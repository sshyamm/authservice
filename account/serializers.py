from rest_framework import serializers
from .models import *
from rest_framework import serializers
from django.contrib.auth.models import User
from account.models import *
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate, update_session_auth_hash

class SignUpSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    organization_name = serializers.CharField(required=True)
    organization_details = serializers.JSONField(required=False)

    def create(self, validated_data):
        # Create User
        user = Customuser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password']
        )

        # Check if the organization already exists
        organization, org_created = Organization.objects.get_or_create(
            name=validated_data['organization_name'],
            defaults={
                'settings': validated_data.get('organization_details', {}),
                'status': 1,  # Active status, change accordingly
            }
        )

        # Check if the role already exists
        owner_role, role_created = Role.objects.get_or_create(
            name='Owner',
            org_id=organization.id,
            defaults={'description': 'Owner of the organization'}
        )

        # Add User as Member with Owner Role
        Member.objects.create(
            user_id=user.id,
            org_id=organization.id,
            role_id=owner_role.id,
            status=1  # Active status, change accordingly
        )

        # Send welcome email
        invite_link = f"{settings.SITE_URL}/accept-invite/?email={user.email}"
        send_mail(
            'Welcome to the Organization!',
            f"Hello {user.email},\n\nYou have been successfully registered and added to the organization {organization.name}. To complete your registration, please visit the following link:\n\n{invite_link}\n\nBest regards,\nThe Team",
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

        return user
    
class InviteMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = ['invite_email', 'org', 'role']

    def create(self, validated_data):
        # Create a Member entry with an invitation
        member = Member.objects.create(
            invite_email=validated_data['invite_email'],
            org=validated_data['org'],
            role=validated_data['role'],
            status=0  # Invited status
        )

        # Send invitation email
        invite_link = f"{self.context['request'].build_absolute_uri('/accept-invite/')}?token={member.invite_token}"
        send_mail(
            'You are invited to join {member.org.name}',
            f"Click the following link to join the organization: {invite_link}",
            'from@example.com',
            [member.invite_email],
            fail_silently=False,
        )

        return member
    
class AcceptInviteSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    token = serializers.UUIDField(required=True) 

    def validate(self, attrs):
        token = attrs.get('token')
        email = attrs.get('email')

        try:
            member = Member.objects.get(invite_token=token, invite_accepted=False, invite_email=email)
        except Member.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired token.")

        if member.invite_email != email:
            raise serializers.ValidationError("Email does not match the invitation.")

        attrs['member'] = member
        return attrs

    def create(self, validated_data):
        member = validated_data['member']
        email = validated_data['email']
        password = validated_data['password']

        # Create the user
        user = Customuser.objects.create_user(email=email, password=password)

        # Update the member instance
        member.user = user
        member.invite_accepted = True
        member.status = 1  # Active status
        member.save()

        return user
    
class UpdateMemberRoleSerializer(serializers.ModelSerializer):
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())
    
    class Meta:
        model = Member
        fields = ['role']
    
    def update(self, instance, validated_data):
        # Update the role of the member
        instance.role = validated_data['role']
        instance.save()
        return instance
    
class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def validate(self, attrs):
        new_password = attrs.get('new_password')
        if len(new_password) < 8:  # Basic length check
            raise serializers.ValidationError("New password must be at least 8 characters long.")
        return attrs

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        update_session_auth_hash(self.context['request'], user)

        # Send notification email
        send_mail(
            'Password Changed Successfully',
            'Your password has been changed successfully. If you did not make this change, please contact support immediately.',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        return user


        

