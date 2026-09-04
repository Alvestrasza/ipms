from django.urls import path

from .views import (
    TenantUserDetailView,
    TenantUserListCreateView,
    login_view,
    logout_view,
    session_view,
)


app_name = "tenancy"

urlpatterns = [
    path("session/", session_view, name="session"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("users/", TenantUserListCreateView.as_view(), name="user-list"),
    path("users/<uuid:pk>/", TenantUserDetailView.as_view(), name="user-detail"),
]
