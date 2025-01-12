from django.urls import path
from . import views
urlpatterns = [
    path('dashboard',views.customer_dashboard_view,name="customer_dashboard"),
    path('password-change',views.password_change_view,name="password_change")
]
