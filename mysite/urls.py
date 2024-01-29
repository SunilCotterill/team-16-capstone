from django.contrib import admin
from django.urls import include, path, re_path

urlpatterns = [
    path("submitter/", include("submitter.urls")),
    path("admin/", admin.site.urls),
    re_path(r'^.*$', include('submitter.urls')),
]
