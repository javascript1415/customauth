from django.urls import path
from . import views
urlpatterns = [
    path('dashboard',views.seller_dashboard_view,name="seller_dashboard"),
]
