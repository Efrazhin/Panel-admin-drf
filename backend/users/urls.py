from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import *

urlpatterns = [
    path('login-page/', login_page, name='login-page'),  # HTML (GET)
    path('login/', login_api, name='login'),             # API (POST)
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegisterView.as_view(), name='auth_register'),
    path('change-password/', ChangePasswordView.as_view(), name='auth_change_password'),
    path('me/', UserDetailView.as_view(), name='user-detail'),
    path('mis-permisos/', mis_permisos, name='mis_permisos'),
]