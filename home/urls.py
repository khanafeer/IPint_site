from django.contrib import admin
from django.urls import path
from . import views
from .views import index
urlpatterns = [
    path('search/',views.Home.as_view()),
    path('search/comment/',views.Comment.as_view()),
    path('', index)
]