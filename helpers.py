import hashlib
from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt, get_jwt_identity
from bson.objectid import ObjectId
from connector import db, redis_client


# Ensure the refresh token is not invoked
def not_invoked_token(endpoint):
    @wraps(endpoint)
    def wrapper(*args, **kwargs):
        jwt_data = get_jwt()
        if redis_client.exists(jwt_data["jti"]):
            return jsonify({"message": "Refresh token is revoked !"}), 400

        return endpoint(*args, **kwargs)

    return wrapper


# Ensure:
# 1- accessed organization exists.
# 2- organization-guests and non-members have read-only access to that organization.
def manage_organization_access(endpoint):
    @wraps(endpoint)
    def wrapper(*args, **kwargs):
        organization_id = kwargs.get("organization_id")
        organization = db.organization.find_one({"_id": ObjectId(organization_id)})
        if not organization:
            return jsonify({"message": "Organization doesn't exist"}), 400

        user_email = get_jwt_identity()
        is_member = any(
            member["email"] == user_email
            for member in organization["organization_members"]
        )

        is_guest_member = any(
            member["email"] == user_email and member["access_level"] == "guest"
            for member in organization["organization_members"]
        )

        # user is not a member OR is a guest member of this organization.
        if not is_member or is_guest_member:
            return (
                jsonify(
                    {
                        "message": "invited users and non-members have read-only access to this organization"
                    }
                ),
                403,
            )
        return endpoint(*args, **kwargs)

    return wrapper


def password_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()
