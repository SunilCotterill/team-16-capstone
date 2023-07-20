from django.urls import path

from . import views


app_name = "submitter"
urlpatterns = [
    path("", views.index, name="index"),
    path("<int:listing_id>/submission", views.submission, name="submission"),
    path("<int:listing_id>/submit/", views.submit, name="submit"),
    path("<int:listing_id>/results", views.results, name="results"),
    path("<int:listing_id>/results/<int:user_id>", views.result, name="result"),
]