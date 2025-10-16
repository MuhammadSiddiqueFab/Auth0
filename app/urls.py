from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login, name='login'),
    path('auth/callback/', views.callback, name='callback'),
    path('logout/', views.logout, name='logout'),
    path('api/user/', views.UserView.as_view(), name='user'),
]