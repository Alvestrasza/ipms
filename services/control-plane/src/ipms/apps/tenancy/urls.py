from django.urls import path

from .views import login_view, logout_view, session_view


app_name = "tenancy"

urlpatterns = [
    path("session/", session_view, name="session"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
]
