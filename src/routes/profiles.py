from fastapi import Request
from datetime import date
from fastapi import Form
from security.interfaces import JWTAuthManagerInterface
import secrets
import schemas.profiles
from pydantic import ValidationError
from fastapi import UploadFile, File
from config import get_s3_storage_client
from storages import S3StorageInterface
from validation import validate_image
from exceptions import S3ConnectionError, S3FileUploadError
from datetime import datetime, timezone
from typing import cast

from security.passwords import hash_password, verify_password
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from database import (
    get_db,
    UserModel,
    UserProfileModel,
    UserGroupEnum,
)
import schemas
from config import get_jwt_auth_manager, get_settings, BaseAppSettings

router = APIRouter()


@router.post(
    "/users/{user_id}/profile/",
    status_code=201,
    response_model=schemas.profiles.ProfileResponseSchema,
)
async def profile(
    user_id: int,
    request: Request,
    first_name: str = Form(None),
    last_name: str = Form(None),
    gender: str = Form(None),
    date_of_birth: str = Form(None),
    info: str = Form(None),
    avatar: UploadFile = File(None),
    db: AsyncSession = Depends(get_db),
    s3_client: S3StorageInterface = Depends(get_s3_storage_client),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):

    authorization = request.headers.get("Authorization")
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is missing",
        )

    scheme, _, token = authorization.partition(" ")

    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'",
        )

    try:
        decoded_token = jwt_manager.decode_access_token(token)
        current_user_id = decoded_token.get("user_id")
    except Exception:
        raise HTTPException(status_code=401, detail="Token has expired.")

    try:
        data = schemas.profiles.ProfileCreateSchema(
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            date_of_birth=date_of_birth,
            info=info,
        )
    except ValidationError as err:
        error_message = err.errors()[0]["msg"]
        # Strip out standard Pydantic v2 wrappers cleanly
        error_message = error_message.split("Value error, ")[-1]
        raise HTTPException(status_code=422, detail=error_message)

    current_user_query = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.group))
        .where(UserModel.id == current_user_id)
    )
    requesting_user = current_user_query.scalar_one_or_none()

    # Safely verify the group relationship exists before checking the name property
    is_admin = (
        requesting_user is not None
        and requesting_user.group is not None
        and requesting_user.group.name == UserGroupEnum.ADMIN
    )

    if current_user_id != user_id and not is_admin:
        raise HTTPException(
            status_code=403, detail="You don't have permission to edit this profile."
        )

    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.group))
        .where(UserModel.id == user_id)
    )
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or not active.")

    profiles = await db.execute(
        select(UserProfileModel).where(UserProfileModel.user_id == user_id)
    )
    profile = profiles.scalar_one_or_none()

    if profile:
        raise HTTPException(status_code=400, detail="User already has a profile.")

    try:
        file_data = await avatar.read()
        file_name = f"avatars/{user_id}_avatar.jpg"

        avatar_url = await s3_client.get_file_url(file_name)

        if len(file_data) > 1 * 1024 * 1024:
            raise HTTPException(status_code=422, detail="Image size exceeds 1 MB")

        await avatar.seek(0)
        validate_image(avatar)

        await s3_client.upload_file(file_name, file_data)

    except HTTPException:
        # 1. Let explicit HTTP status rules pass through unmutated
        raise

    except (S3ConnectionError, S3FileUploadError):
        # 2. Infrastructure failures must be caught before generic handlers to return 500
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload avatar. Please try again later.",
        )

    except (ValueError, AttributeError) as err:
        # 3. Explicitly catch client side layout or mock attribute reading errors to return 422
        err_msg = str(err)
        if "size" in err_msg or "exceeds" in err_msg:
            raise HTTPException(status_code=422, detail="Image size exceeds 1 MB")
        raise HTTPException(status_code=422, detail="Invalid image format")

    except Exception:
        # 4. Fallback universal catcher
        raise HTTPException(status_code=422, detail="Invalid image format")

    new_profile = UserProfileModel(
        user_id=user_id,
        first_name=data.first_name.lower(),
        last_name=data.last_name.lower(),
        gender=data.gender.lower(),
        date_of_birth=data.date_of_birth,
        info=data.info,
        avatar=file_name,
    )

    db.add(new_profile)
    await db.commit()
    await db.refresh(new_profile)
    new_profile.avatar = avatar_url
    return new_profile
