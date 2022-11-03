from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated

from .serializers import (UserRegistrationSerializers,
    ActivationSerializer,
    LoginSerializer,
    PasswordChangeSerializer,
    ForgottenPasswordSerializer,
    SetNewPasswordSerializer
    )


class RegistrationView(APIView):
    def post(self, request: Request):
        serializer = UserRegistrationSerializers(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                data='спасибо за регистрацию! Вам было выслано письмо с ключом активации',
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AccountActivationView(APIView):
    def post(self, request: Request):
        serializer = ActivationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.activate_account()
            return Response(
                'Аккаунт активирован!',
                status=status.HTTP_200_OK
            )

class LoginView(ObtainAuthToken):
    serializer_class = LoginSerializer


class logoutView(APIView):
    permission_classes = [IsAuthenticated] # позволяет получать доступ к этой вьюшке только

    def delete(self, request: Request):
        user  = request.user 
        Token.objects.filter(user=user).delete()
        return Response(
            'До свидания! Вы успешно вышли',
            status=status.HTTP_200_OK
        )

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Response):
        serialalizer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serialalizer.is_valid(raise_exception=True):
            serialalizer.set_new_password()
            return Response(
                'Пароль успешно изменен',
                status=status.HTTP_200_OK
            )


class ChangeForgottenPasswordView(APIView):
    def post(self, request: Response):
        serializer = ForgottenPasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.send_code()
            return Response(
                'Вам выслан код для востановления пароля'
            )

class ChangeForgottenPasswordCompleteView(APIView):
    def post(self, request: Response):
        serializer = SetNewPasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.set_new_password()
            return Response(
                'Пароль упешно востановлен',
                status=status.HTTP_200_OK
            )