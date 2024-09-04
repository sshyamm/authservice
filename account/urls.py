from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from . import views

urlpatterns = [
    path('token/', views.CustomTokenObtainPairView.as_view(), name='custom_token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', views.LogoutView.as_view(), name='auth_logout'),
    path('password-reset/', views.PasswordResetView.as_view(), name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('signup/', views.SignUpView.as_view(), name='signup'),
    path('invite/', views.InviteMemberView.as_view(), name='invite_member'),
    path('accept-invite/', views.AcceptInviteView.as_view(), name='accept_invite'),
    path('member/<int:pk>/delete/', views.DeleteMemberView.as_view(), name='delete-member'),
    path('member/<int:pk>/update-role/', views.UpdateMemberRoleView.as_view(), name='update-member-role'),
    path('role-wise-user-count/', views.RoleWiseUserCountView.as_view(), name='role-wise-user-count'),
    path('organization-wise-member-count/', views.OrganizationWiseMemberCountView.as_view(), name='organization-wise-member-count'),
    path('organization-role-wise-user-count/', views.OrganizationRoleWiseUserCountView.as_view(), name='organization-role-wise-user-count'),
    path('password-change/', views.PasswordChangeView.as_view(), name='password_change'),
]
