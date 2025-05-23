from django.urls import path
from .views import DashboardUserInfoAPIView, DashboardDataAPIView

urlpatterns = [
    path('panel-data/', DashboardDataAPIView.as_view(), name='dashboard-data'),
    path('user-info/', DashboardUserInfoAPIView.as_view(), name='dashboard_user_info'),
]
