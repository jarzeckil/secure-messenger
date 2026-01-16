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


class UserLoginModel(BaseModel):
    username: str = Field(..., description='Username')
    password: str = Field(..., description='Password')


class UserPasswordModel(BaseModel):
    password: str = Field(..., description='Password')


class UserOtpModel(BaseModel):
    code: str = Field(..., description='OTP code')
