from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import *
from account.serializers import *
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.db.models import Count, Q
from django.utils.dateparse import parse_datetime
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import get_user_model

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        # Validate user credentials and generate JWT token
        data = super().validate(attrs)

        # Add custom data, such as user information
        data.update({'user_id': self.user.id, 'email': self.user.email})

        # Send login alert email
        self.send_login_alert_email(self.user)

        return data

    def send_login_alert_email(self, user):
        subject = 'Login Alert'
        message = (
            f'Hello {user.email},\n\n'
            'We noticed a login to your account. If this was you, you can disregard this message. '
            'If you did not log in, please contact support immediately.\n\n'
            'Best regards,\nThe Team'
        )
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({"detail": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"detail": "Failed to log out."}, status=status.HTTP_400_BAD_REQUEST)
        

class PasswordResetView(APIView):
    def post(self, request):
        email = request.data.get('email')
        User = get_user_model()

        if email is None:
            return Response({'detail': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        reset_url = request.build_absolute_uri(
            reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
        )

        message = render_to_string('password_reset_email.html', {'reset_url': reset_url, 'user': user})
        send_mail(
            'Password Reset Request',
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

        return Response({'detail': 'Password reset link sent.'}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        User = get_user_model()
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            new_password = request.data.get('new_password')
            if new_password:
                user.set_password(new_password)
                user.save()
                return Response({'detail': 'Password has been reset.'}, status=status.HTTP_200_OK)
            return Response({'detail': 'Password not provided.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'detail': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)
    

class SignUpView(APIView):
    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered successfully and invitation email sent!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class InviteMemberView(APIView):
    def post(self, request):
        serializer = InviteMemberSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Invitation sent successfully!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class AcceptInviteView(APIView):
    def post(self, request):
        serializer = AcceptInviteSerializer(data=request.data)
        if serializer.is_valid():
            # Data is validated and member instance is obtained
            user = serializer.save()
            return Response({"message": "Invitation accepted and user registered successfully!"}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class DeleteMemberView(APIView):
    def delete(self, request, *args, **kwargs):
        member_id = kwargs.get('pk')
        
        try:
            member = Member.objects.get(pk=member_id)
            member.delete()
            return Response({"message": "Member deleted successfully!"}, status=status.HTTP_204_NO_CONTENT)
        except Member.DoesNotExist:
            return Response({"error": "Member not found"}, status=status.HTTP_404_NOT_FOUND)
        
class UpdateMemberRoleView(APIView):
    def put(self, request, *args, **kwargs):
        member_id = kwargs.get('pk')
        try:
            member = Member.objects.get(pk=member_id)
        except Member.DoesNotExist:
            return Response({"error": "Member not found"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UpdateMemberRoleSerializer(member, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Member role updated successfully!"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class RoleWiseUserCountView(APIView):
    def get(self, request, *args, **kwargs):
        # Aggregate the number of users per role
        role_counts = Member.objects.values('role__name').annotate(user_count=Count('user')).order_by('role__name')
        
        # Prepare response data
        data = [
            {
                'role': role['role__name'],
                'user_count': role['user_count']
            }
            for role in role_counts
        ]
        
        return Response(data, status=status.HTTP_200_OK)
    
class OrganizationWiseMemberCountView(APIView):
    def get(self, request, *args, **kwargs):
        # Aggregate the number of members per organization
        organization_counts = Member.objects.values('org__name').annotate(member_count=Count('user')).order_by('org__name')
        
        # Prepare response data
        data = [
            {
                'organization': org['org__name'],
                'member_count': org['member_count']
            }
            for org in organization_counts
        ]
        
        return Response(data, status=status.HTTP_200_OK)
    
class OrganizationRoleWiseUserCountView(APIView):
    def get(self, request, *args, **kwargs):
        # Aggregate the number of users per role within each organization
        org_role_counts = Member.objects.values('org__name', 'role__name').annotate(user_count=Count('user')).order_by('org__name', 'role__name')
        
        # Prepare response data
        data = {}
        for item in org_role_counts:
            org_name = item['org__name']
            role_name = item['role__name']
            user_count = item['user_count']
            
            if org_name not in data:
                data[org_name] = []
            
            data[org_name].append({
                'role': role_name,
                'user_count': user_count
            })
        
        # Convert to list of dictionaries for response
        response_data = [{'organization': org, 'roles': roles} for org, roles in data.items()]
        
        return Response(response_data, status=status.HTTP_200_OK)
    
class OrganizationRoleWiseUserCountView(APIView):
    def get(self, request, *args, **kwargs):
        # Parse filter parameters
        from_date = request.query_params.get('from', None)
        to_date = request.query_params.get('to', None)
        status_filter = request.query_params.get('status', None)
        
        # Convert dates to datetime objects
        from_date = parse_datetime(from_date) if from_date else None
        to_date = parse_datetime(to_date) if to_date else None
        
        # Build query filters
        filter_conditions = Q()
        if from_date:
            filter_conditions &= Q(created_at__gte=from_date)
        if to_date:
            filter_conditions &= Q(created_at__lte=to_date)
        if status_filter is not None:
            filter_conditions &= Q(status=status_filter)
        
        # Aggregate the number of users per role within each organization
        org_role_counts = Member.objects.filter(filter_conditions).values('org__name', 'role__name').annotate(user_count=Count('user')).order_by('org__name', 'role__name')
        
        # Prepare response data
        data = {}
        for item in org_role_counts:
            org_name = item['org__name']
            role_name = item['role__name']
            user_count = item['user_count']
            
            if org_name not in data:
                data[org_name] = []
            
            data[org_name].append({
                'role': role_name,
                'user_count': user_count
            })
        
        # Convert to list of dictionaries for response
        response_data = [{'organization': org, 'roles': roles} for org, roles in data.items()]
        
        return Response(response_data, status=status.HTTP_200_OK)
    
class OrganizationMemberCountView(APIView):
    def get(self, request, *args, **kwargs):
        # Parse filter parameters
        from_date = request.query_params.get('from', None)
        to_date = request.query_params.get('to', None)
        status_filter = request.query_params.get('status', None)
        
        # Convert dates to datetime objects
        from_date = parse_datetime(from_date) if from_date else None
        to_date = parse_datetime(to_date) if to_date else None
        
        # Build query filters
        filter_conditions = Q()
        if from_date:
            filter_conditions &= Q(created_at__gte=from_date)
        if to_date:
            filter_conditions &= Q(created_at__lte=to_date)
        if status_filter is not None:
            filter_conditions &= Q(status=status_filter)
        
        # Aggregate the number of members per organization
        org_member_counts = Member.objects.filter(filter_conditions).values('org__name').annotate(member_count=Count('id')).order_by('org__name')
        
        # Prepare response data
        data = []
        for item in org_member_counts:
            org_name = item['org__name']
            member_count = item['member_count']
            
            data.append({
                'organization': org_name,
                'member_count': member_count
            })
        
        return Response(data, status=status.HTTP_200_OK)
    
class PasswordChangeView(APIView):
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

