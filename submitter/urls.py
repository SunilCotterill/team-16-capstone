from django.urls import path, re_path, reverse_lazy
from django.shortcuts import redirect

from . import views
from django.contrib.auth import views as auth_views
from django.views.generic import RedirectView
from submitter.views import ResetPasswordView


app_name = "submitter"
urlpatterns = [
    path("", views.index, name="index", ),
    path("<int:listing_id>/submission", views.submission, name="submission"),
    path("<int:listing_id>/submit/", views.submit, name="submit"),
    path("<int:listing_id>/results", views.results, name="results"),
    path("<int:listing_id>/results/<str:email>", views.result, name="result"),
    path('<int:listing_id>/results/switch_shortlist/<int:listing_response_id>/', views.update_shortlist, name='update_shortlist'),
    path("<int:listing_id>/submission_complete", views.submission_complete, name ="submission_complete"),

    path('register/', views.registerPage, name = "register"),
    path('login/', views.loginPage, name = "login"),

    path('home/', views.homePage, name = "home"),
    path('new_listing/', views.new_listing, name = "new_listing"),
    path('logout/', views.logout_view, name = "logout"),
    path('signup/', views.registerPage, name='signup'),

    path('verify-email/', views.verify_email, name='verify-email'),
    path('verify-email/done/', views.verify_email_done, name='verify-email-done'),
    path('verify-email-confirm/<uidb64>/<token>/', views.verify_email_confirm, name='verify-email-confirm'),
    path('verify-email/complete/', views.verify_email_complete, name='verify-email-complete'),

    path('change-password', views.change_password, name='change-password'),

    path('password-reset/', ResetPasswordView.as_view(), name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(template_name='submitter/password_reset_confirm.html', success_url=reverse_lazy('submitter:password_reset_complete')),
         name='password_reset_confirm'),
    path('password-reset-complete/',
         auth_views.PasswordResetCompleteView.as_view(template_name='submitter/password_reset_complete.html'),
         name='password_reset_complete'),


    # Catch all for unknown links
    re_path(r'^.*$', RedirectView.as_view(url='/'), name='redirect-to-home'),
]
