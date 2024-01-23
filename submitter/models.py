from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractUser
from django.core.exceptions import ValidationError


def validate_substring(value):
    if "@uwaterloo.ca" not in value and "@wlu.ca" not in value:
        raise ValidationError("Must be UWaterloo or ULaurier email")

class UserManager(BaseUserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)

class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(max_length=254, unique=True, validators=[validate_substring])
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.email


class Listing(models.Model):
    creator = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    name = models.CharField(max_length = 200)


class Question(models.Model):
    question_text = models.CharField(max_length=200)
    def __str__(self):
        return self.question_text


class Answer(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    answer_text = models.CharField(max_length=200)
    def __str__(self):
        return self.answer_text

class ListingResponse(models.Model):
    responder = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    listing = models.ForeignKey(Listing, on_delete=models.CASCADE)
    is_shortlisted = models.BooleanField(default = False)

class Response(models.Model):
    # This is the user that submitted the question
    listing_response = models.ForeignKey(ListingResponse, on_delete=models.CASCADE)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    answer =  models.ForeignKey(Answer, on_delete=models.CASCADE)
