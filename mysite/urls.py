from django.contrib import admin
from django.urls import include, path, re_path
from django.contrib.staticfiles.storage import staticfiles_storage
from django.views.generic import RedirectView

favicon_view = RedirectView.as_view(url=staticfiles_storage.url('favicon.ico'))

urlpatterns = [
    path("favicon.ico", favicon_view),
    path("apartmate/", include("submitter.urls")),
    path("admin/", admin.site.urls),
    re_path(r'^.*$', include('submitter.urls')),
]