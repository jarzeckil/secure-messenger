import re

import nh3
from pydantic import BaseModel, Field, field_validator
from zxcvbn import zxcvbn


class UserRegisterModel(BaseModel):
    username: str = Field(..., description='Unique username', min_length=5)
    password: str = Field(..., description='Strong password', min_length=8)

    @field_validator('password')
    @classmethod
    def validate_password(cls, password: str) -> str:
        results = zxcvbn(password)

        score = results.get('score')

        if score < 3:
            suggestions = results.get('feedback', {}).get('suggestions', None)
            warning = results.get('feedback').get('warning', 'Password too weak')

            raise ValueError(
                f'Password score: {score}/4. '
                f'Warning! {warning}. '
                f'Suggestions: {suggestions}'
            )

        return password

    @field_validator('username')
    @classmethod
    def sanitize_username(cls, username: str) -> str:
        return nh3.clean(username)

    @field_validator('username')
    @classmethod
    def validate_username_characters(cls, username: str) -> str:
        pattern = '^[a-zA-Z0-9_]+$'

        if not re.match(pattern, username):
            raise ValueError('Username may contain only a-z, A-Z, 0-9 and _')

        return username


class UserLoginModel(BaseModel):
    username: str = Field(..., description='Username')
    password: str = Field(..., description='Password')


class UserPasswordModel(BaseModel):
    password: str = Field(..., description='Password')


class UserOtpModel(BaseModel):
    code: str = Field(..., description='OTP code')
