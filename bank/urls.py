from django.contrib import admin
from django.urls import path, include
from django.views.generic.base import TemplateView  
from django.shortcuts import redirect
from . import views



urlpatterns = [
    # path('admin/', admin.site.urls),

    path("", views.index, name="index"),
    path("register/", views.register, name="register"),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('transfer/', views.transfer_funds, name='transfer_funds'),
    path('market/', views.market, name='market'),
    path('cheque/', views.deposit_cheque, name='deposit_cheque'),

    path('admin/', views.admin_login, name='admin_login'),

    # Secret question page after password verification
    path('secret-question/', views.secret_question, name='secret_question'),

    # Admin dashboard where they can view and delete users
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),

    # Page to transfer funds before account deletion
    path('transfer-funds-before-deletion/<int:user_id>/', views.transfer_funds_before_deletion, name='transfer_funds_before_deletion'),

    path('dashboard/', views.dashboard, name='dashboard'),
]
