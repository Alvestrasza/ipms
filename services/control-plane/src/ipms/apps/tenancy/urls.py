from django.urls import path

from .views import (
    TenantUserDetailView,
    TenantUserListCreateView,
    login_view,
    logout_view,
    session_view,
)
from .identity_views import (
    AccountView,
    AccountRenameView,
    AccountPasswordView,
    TenantUserRenameView,
    TenantUserPasswordView,
)

app_name = "tenancy"

urlpatterns = [
    path("session/", session_view, name="session"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("account/", AccountView.as_view(), name="account"),
    path("account/rename/", AccountRenameView.as_view(), name="account-rename"),
    path("account/password/", AccountPasswordView.as_view(), name="account-password"),
    path("users/", TenantUserListCreateView.as_view(), name="user-list"),
    path("users/<uuid:pk>/", TenantUserDetailView.as_view(), name="user-detail"),
    path("users/<uuid:pk>/rename/", TenantUserRenameView.as_view(), name="user-rename"),
    path(
        "users/<uuid:pk>/password/",
        TenantUserPasswordView.as_view(),
        name="user-password",
    ),
]
