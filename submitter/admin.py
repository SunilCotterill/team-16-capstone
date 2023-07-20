from django.contrib import admin

from django.contrib import admin

from .models import User, Listing, Question, Answer, Response

admin.site.register(User)
admin.site.register(Listing)
admin.site.register(Question)
admin.site.register(Answer)
admin.site.register(Response)