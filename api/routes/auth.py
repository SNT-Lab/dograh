import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger

from api.constants import PASSWORD_RESET_TOKEN_EXPIRY_HOURS
from api.db import db_client
from api.db.models import UserModel
from api.schemas.auth import (
    AuthResponse,
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    SignupRequest,
    UserResponse,
)
from api.services.auth.depends import create_user_configuration_with_mps_key, get_user
from api.services.email_service import send_password_reset_email
from api.utils.auth import create_jwt_token, hash_password, verify_password

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


@router.post("/signup", response_model=AuthResponse)
async def signup(request: SignupRequest):
    # Check if email is already taken
    existing_user = await db_client.get_user_by_email(request.email)
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already registered")

    # Hash password and create user
    hashed = hash_password(request.password)
    user = await db_client.create_user_with_email(
        email=request.email,
        password_hash=hashed,
        name=request.name,
    )

    # Create organization for the user
    org_provider_id = f"org_{user.provider_id}"
    organization, _ = await db_client.get_or_create_organization_by_provider_id(
        org_provider_id=org_provider_id, user_id=user.id
    )

    # Link user to organization
    await db_client.add_user_to_organization(user.id, organization.id)
    await db_client.update_user_selected_organization(user.id, organization.id)

    # Create default service configuration
    try:
        mps_config = await create_user_configuration_with_mps_key(
            user.id, organization.id, user.provider_id
        )
        if mps_config:
            await db_client.update_user_configuration(user.id, mps_config)
    except Exception:
        logger.warning(
            "Failed to create default configuration for OSS user", exc_info=True
        )

    # Create JWT token
    token = create_jwt_token(user.id, request.email)

    return AuthResponse(
        token=token,
        user=UserResponse(
            id=user.id,
            email=user.email,
            name=request.name,
            organization_id=organization.id,
        ),
    )


@router.post("/login", response_model=AuthResponse)
async def login(request: LoginRequest):
    # Look up user by email
    user = await db_client.get_user_by_email(request.email)
    if not user or not user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Verify password
    if not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Create JWT token
    token = create_jwt_token(user.id, user.email)

    return AuthResponse(
        token=token,
        user=UserResponse(
            id=user.id,
            email=user.email,
            organization_id=user.selected_organization_id,
        ),
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user(user: UserModel = Depends(get_user)):
    return UserResponse(
        id=user.id,
        email=user.email,
        organization_id=user.selected_organization_id,
    )


@router.post("/forgot-password", status_code=200)
async def forgot_password(request: ForgotPasswordRequest):
    """Initiate a password reset. Always returns 200 to avoid leaking registered emails."""
    user = await db_client.get_user_by_email(request.email)
    if not user or not user.password_hash:
        # Return success regardless so attackers cannot enumerate accounts
        return {"message": "If that email is registered, a reset link has been sent."}

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=PASSWORD_RESET_TOKEN_EXPIRY_HOURS)

    await db_client.create_password_reset_token(user.id, token_hash, expires_at)

    try:
        await send_password_reset_email(user.email, raw_token)
    except Exception:
        logger.exception("Failed to send password-reset email for user %s", user.id)
        raise HTTPException(status_code=500, detail="Failed to send reset email. Please try again.")

    return {"message": "If that email is registered, a reset link has been sent."}


@router.post("/reset-password", status_code=200)
async def reset_password(request: ResetPasswordRequest):
    """Validate a reset token and update the user's password."""
    token_hash = hashlib.sha256(request.token.encode()).hexdigest()
    token_record = await db_client.get_password_reset_token(token_hash)

    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link.")

    if token_record.used_at is not None:
        raise HTTPException(status_code=400, detail="This reset link has already been used.")

    if datetime.now(timezone.utc) > token_record.expires_at:
        raise HTTPException(status_code=400, detail="This reset link has expired.")

    new_hash = hash_password(request.password)
    await db_client.update_user_password_hash(token_record.user_id, new_hash)
    await db_client.consume_password_reset_token(token_record.id)

    return {"message": "Password updated successfully."}
