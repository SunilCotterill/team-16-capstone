from django.urls import path

from . import views
from django.contrib.auth import views as auth_views


app_name = "submitter"
urlpatterns = [
    path("", views.index, name="index"),
    path("<int:listing_id>/submission", views.submission, name="submission"),
    path("<int:listing_id>/submit/", views.submit, name="submit"),
    path("<int:listing_id>/results", views.results, name="results"),
    path("<int:listing_id>/results/<str:email>", views.result, name="result"),
    path("<int:listing_id>/submission_complete", views.submission_complete, name ="submission_complete"),

    path('register/', views.registerPage, name = "register"),
    path('login/', views.loginPage, name = "login"),

    path('home/', views.homePage, name = "home"),
    path('new_listing/', views.new_listing, name = "new_listing"),
    path('logout/', views.logout_view, name = "logout"),
]
