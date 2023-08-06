from django.contrib import admin

from django.contrib import admin

from .models import CustomUser, Listing, Question, Answer, Response

admin.site.register(CustomUser)
admin.site.register(Listing)
admin.site.register(Question)
admin.site.register(Answer)
admin.site.register(Response)