from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import *

urlpatterns = [
    path('login-page/', login_page, name='login-page'),  
    path('login/', login_api, name='login'),             
    path('logout/', logout_view, name='logout'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegisterView.as_view(), name='auth_register'),
    path('me/', UserDetailView.as_view(), name='user-detail'),
    path('mis-permisos/', mis_permisos, name='mis_permisos'),
]