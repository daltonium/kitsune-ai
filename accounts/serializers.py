from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        max_length=128,
    )
    password_confirm = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        max_length=128,
    )

    class Meta:
        model = User
        fields = ["username", "email", "password", "password_confirm"]

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError({
                "non_field_errors": ["Request body must be a JSON object."]
            })
        unknown = set(data) - set(self.fields)
        if unknown:
            raise serializers.ValidationError({
                "non_field_errors": ["Unexpected registration fields."]
            })
        return super().to_internal_value(data)

    def validate_email(self, value):
        value = value.strip().lower()
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError(
                "An account with this email already exists."
            )
        return value

    def validate(self, attrs):
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError({
                "password_confirm": ["Passwords do not match."]
            })

        candidate = User(
            username=attrs["username"],
            email=attrs["email"],
        )
        try:
            validate_password(attrs["password"], user=candidate)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({
                "password": list(exc.messages)
            })
        return attrs

    def create(self, validated_data):
        validated_data.pop("password_confirm")
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        max_length=128,
    )