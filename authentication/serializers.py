
import email
from pkg_resources import require
from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.core.mail import send_mail
from django.conf import settings

User = get_user_model()


class UserRegistrationSerializers(serializers.Serializer):
    username = serializers.CharField(max_length=100, required=True)
    email = serializers.EmailField(max_length=200, required=True)
    password = serializers.CharField(max_length=128, required=True)
    password_confirm = serializers.CharField(max_length=128, required=True)

    def validate_username(self, username):
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError(
                'Этот ник уже занят выберите другой'
            )
        return username

    def validate_email(self, email):
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                'Этот почтовый адрес уже занят ипользуйте другой'
            )
        return email

    def validate(self, attrs: dict):
        password = attrs.get('password')
        print('*' * 20, attrs)
        password_confirmation = attrs.pop('password_confirm')
        if password != password_confirmation:
            raise serializers.ValidationError(
                'Пароль не совпал'
            )
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        user.create_activation_code()
        user.send_activation_code()
        return  user


class ActivationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(min_length=1, max_length=10, required=True)

    def validate_email(self,email):
        if User.objects.filter(email=email).exists():
            return email
        raise serializers.ValidationError('Пользователь не найден')

    def valdate_code(self, code):
        if not User.objects.filter(activation_code=code).exists():
            raise serializers.ValidationError('Неверный код')
        return code

    def validate(self, attrs: dict):
        email = attrs.get('email')
        code = attrs.get('code')
        if not User.objects.filter(email=email, activation_code=code).exists():
            raise serializers.ValidationError('Пользователь не найден')
        return attrs

    def activate_account(self):
        """ Метод для активации аккаунта """
        email = self.validated_data.get('email')
        user = User.objects.get(email=email)
        user.is_active = True
        user.activation_code = ''
        user.save()


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length=128)

    def validate_username(self, username):
        if not User.objects.filter(username=username).exists():
            raise serializers.ValidationError(
                'Пльзователя с указанным ником не существует'
            )
        return username
    
    def validate(self, attrs):
        print('*' * 20, self.context)
        request = self.context.get('request')
        username = attrs.get('username')
        password = attrs.get('password')
        if username and password:
            user = authenticate(
                username=username,
                password=password,
                request=request
            )
            if not user:
                raise serializers.ValidationError('Неправельный Username или пароль')
        else:
            raise serializers.ValidationError('Заполните все поля')
        attrs['user'] = user
        return attrs

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128, required=True)
    new_password = serializers.CharField(max_length=128, required=True)
    old_password_confirm = serializers.CharField(max_length=128, required=True)

    def validate_old_password(self, old_password):
        user = self.context.get('request').user
        if not user.check_password(old_password):
            raise serializers.ValidationError('Неверный пароль')
        return old_password

    def validate(self, attrs: dict):
        pass1 = attrs.get('new_password')
        pass2 = attrs.get('new_password_confirm')
        if pass1 != pass2:
            raise serializers.Serializer('Пароли не совпадают')
        return attrs

    def set_new_password(self):
        user = self.context.get('request').user
        password = self.validated_data.get('new_password')
        user.set_password(password)
        user.save()


class ForgottenPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=200)

    def validate_email(self, email):
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                'Пользователь с такой почтой не существует'
            )
        return email

    def send_code(self):
        email = self.validated_data.get('email')
        user = User.objects.get(email=email)
        user.create_activation_code()
        send_mail(
            'Востановления пароля',
            f'Ваш код для смены пароля: {user.activation_code}',
            settings.EMAIL_HOST_USER,
            [email]
        )

class SetNewPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(min_length=1, max_length=10, required=True)
    new_password = serializers.CharField(max_length=128, required=True)
    new_password_confirm = serializers.CharField(max_length=128, required=True)

    def validate(self, email):
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError('Пользователь не существует')
        return email

    def validate_code(self, code):
        if not User.objects.filter(activation_code=code).exists():
            raise serializers.ValidationError('Неверный код')
        return code

    def validate(self, attrs):
        new_password = attrs.get('new_password')
        pass_confirm = attrs.get('new_password_confirm')
        if new_password != pass_confirm:
            raise serializers.ValidationError('Пароли не совпадают')
        return attrs

    def set_new_password(self):
        email = self.validated_data.get('email')
        user = User.objects.get(email=email)
        new_pass = self.validated_data.get('new_password')
        user.set_password(new_pass)
        user.activation_code = ''
        user.save()






