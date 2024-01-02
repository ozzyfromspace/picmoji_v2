from typing import cast

from django.contrib.auth.models import User
from django.db import IntegrityError
from marshmallow import Schema, fields
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from auth_jwt.serializers import UserSerializer


class RegistrationSerializer(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    confirm_password = fields.Str(required=True)

    def valid_password(self, password: str, confirm_password: str):
        if password != confirm_password:
            return False
        if len(password) < 3:
            return False
        return True


class RegisterUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request: Request):
        registration_serializer = RegistrationSerializer()
        data = request.data

        if not isinstance(data, dict):
            return Response(
                {"message": "no payload"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        payload_errors = registration_serializer.validate(data)

        if payload_errors:
            return Response(
                {"errors": payload_errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        username = data.get("username")

        password = cast(str, data.get("password"))
        confirm_password = cast(str, data.get("confirm_password"))
        if not RegistrationSerializer().valid_password(password, confirm_password):
            return Response(
                {
                    "message": "passwords do not match",
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        new_user = User(username=username)
        new_user.set_password(password)

        try:
            new_user.save()
        except IntegrityError as e:
            return Response(
                {
                    "message": "invalid payload",
                    "error": e.__str__(),
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        except Exception:
            return Response(
                {"message": "something went wrong"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        user_serializer = UserSerializer(instance=new_user)
        return Response(
            {
                "message": "user registered",
                "user": user_serializer.data,
            },
            status=status.HTTP_201_CREATED,
        )
