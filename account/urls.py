from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView
urlpatterns = [
    path('',views.home,name='home'),
    path('login/',views.login_view,name='login'),
    path('register/',views.register_view,name='register'),
    path('password_reset/',views.password_reset_view,name='password_reset'),
    path('password_reset_confirm/<uidb64>/<token>/',views.password_reset_confirm_view,name='password_reset_confirm'),
    path('activate/<str:uidb64>/<str:token>',views.activate_account,name='activate'),
    path('logout/', LogoutView.as_view(), name='logout'),
]