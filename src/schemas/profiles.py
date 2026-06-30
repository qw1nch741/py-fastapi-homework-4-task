from datetime import date

from pydantic import BaseModel, field_validator

from validation import (
    validate_name,
    validate_image,
    validate_gender,
    validate_birth_date,
)


class ProfileCreateSchema(BaseModel):
    first_name: str
    last_name: str
    gender: str
    date_of_birth: date
    info: str

    @field_validator("first_name", "last_name")
    @classmethod
    def validate_profile_name(cls, value):
        validate_name(value)
        return value

    @field_validator("gender")
    @classmethod
    def validate_profile_gender(cls, value):
        validate_gender(value)
        return value

    @field_validator("date_of_birth")
    @classmethod
    def validate_profile_birth_date(cls, value):
        validate_birth_date(value)
        return value

    @field_validator("info")
    @classmethod
    def validate_profile_info(cls, value):
        if not value or not value.strip():
            raise ValueError("Info field cannot be empty or contain only spaces.")
        return value

    model_config = {"from_attributes": True}


class ProfileResponseSchema(ProfileCreateSchema):
    id: int
    user_id: int
    avatar: str
