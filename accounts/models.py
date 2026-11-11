from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """Custom user model. Extended in Phase 2."""

    def __str__(self):
        return self.username