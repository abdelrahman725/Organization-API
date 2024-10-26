from datetime import timedelta
from dotenv import load_dotenv
from flask import Flask, jsonify, request, render_template, make_response
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from bson.objectid import ObjectId
from helpers import not_invoked_token, manage_organization_access, password_hash
from connector import db, redis_client

load_dotenv()

app = Flask(__name__)

# secret key is safe to be public, since this is just a demo project
app.config["JWT_SECRET_KEY"] = (
    "708690e485ee8cd98827682ee1a4e32114a4367d6b5cff38ab15799d6b32d6ea"
)
jwt = JWTManager(app)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["POST"])
def sign_up():
    name = request.json.get("name")
    email = request.json.get("email")
    password = request.json.get("password")

    if not name or not email or not password:
        return (
            jsonify(
                {
                    "message": "missing credentials",
                }
            ),
            400,
        )
    # ensure email is unique:
    if db.user.find_one({"email": email}):
        return (
            jsonify(
                {
                    "message": "email already exists",
                }
            ),
            400,
        )

    # create a new user
    db.user.insert_one(
        {"name": name, "email": email, "password": password_hash(password)}
    )

    return jsonify({"message": f"user with email {email} created successfully"}), 201


@app.route("/signin", methods=["POST"])
def sign_in():
    email = request.json.get("email")
    password = request.json.get("password")

    if not email or not password:
        return (
            jsonify(
                {
                    "message": "missing credentials",
                }
            ),
            400,
        )

    user = db.user.find_one({"email": email})
    if user and password_hash(password) == user["password"]:
        access_token = create_access_token(
            identity=email, expires_delta=timedelta(hours=1)
        )
        refresh_token = create_refresh_token(
            identity=email, expires_delta=timedelta(days=1)
        )

        response = make_response(
            jsonify(
                {
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                }
            ),
            200,
        )
        response.headers["Authorization"] = f"Bearer {access_token}"
        return response

    return jsonify({"message": "User doesn't exist"}), 401


@app.route("/refresh-token", methods=["POST"])
@jwt_required(refresh=True)  # this ensures refresh-token is valid and not expired
@not_invoked_token  # thie ensures refresh-token wasn't invoked
def refresh_token():
    user_email = get_jwt_identity()
    new_access_token = create_access_token(
        identity=user_email, expires_delta=timedelta(hours=1)
    )
    new_refresh_token = create_refresh_token(
        identity=user_email, expires_delta=timedelta(days=1)
    )

    response = make_response(
        jsonify(
            {
                "message": "Login successful",
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
            }
        ),
        200,
    )
    response.headers["Authorization"] = f"Bearer {new_access_token}"
    return response


@app.route("/revoke-refresh-token", methods=["POST"])
@jwt_required(refresh=True)  # requires only refresh-token
def revoke_refresh_token():
    jwt_data = get_jwt()

    # save JWT ID in redis, so we know it's a permanent revoked token.
    redis_client.set(jwt_data["jti"], "revoked")

    return jsonify(
        {
            "message": "refresh token is revoked successfully",
        }
    )


@app.route("/organization", methods=["POST"])
@jwt_required()
def create_organization():
    user_email = get_jwt_identity()
    organization_name = request.json.get("name")
    organization_description = request.json.get("description")

    if not organization_name or not organization_description:
        return (
            jsonify(
                {
                    "message": "organization name or description is missing",
                }
            ),
            400,
        )

    user = db.user.find_one({"email": user_email})

    if not user:
        return jsonify({"message": "user doesn't exist"})

    created_organization = db.organization.insert_one(
        {
            "name": organization_name,
            "description": organization_description,
            "organization_members": [
                {
                    "name": user["name"],
                    "email": user["email"],
                    "access_level": "owner",
                },
            ],
        }
    )

    return (
        jsonify(
            {
                "organization_id": str(created_organization.inserted_id),
            }
        ),
        201,
    )


@app.route("/organization/<string:organization_id>", methods=["GET"])
@jwt_required()
def get_organization(organization_id: str):
    organization = db.organization.find_one({"_id": ObjectId(organization_id)})
    if not organization:
        return (
            jsonify(
                {
                    "message": "Organization not found",
                }
            ),
            404,
        )

    organization["organization_id"] = str(organization["_id"])
    organization.pop("_id")
    return jsonify(organization)


@app.route("/organization", methods=["GET"])
@jwt_required()
def get_all_organizations():
    all_organizations = db.organization.find()
    result = []
    for organization in all_organizations:
        result.append(
            {
                "organization_id": str(organization["_id"]),
                "name": organization["name"],
                "description": organization["description"],
                "organization_members": organization["organization_members"],
            }
        )

    return jsonify(result)


@app.route("/organization/<string:organization_id>", methods=["PUT"])
@jwt_required()
@manage_organization_access
def update_organiztion(organization_id: str):
    new_organization_name = request.json.get("name")
    new_organization_description = request.json.get("description")

    result = db.organization.update_one(
        {"_id": ObjectId(organization_id)},
        {
            "$set": {
                "name": new_organization_name,
                "description": new_organization_description,
            }
        },
    )
    if result.modified_count == 1:
        return jsonify(
            {
                "organization_id": organization_id,
                "name": new_organization_name,
                "description": new_organization_description,
            }
        )
    return jsonify(
        {
            "message": "organization didn't change",
        }
    )


@app.route("/organization/<string:organization_id>", methods=["DELETE"])
@jwt_required()
@manage_organization_access
def delete_organization(organization_id: str):
    db.organization.delete_one({"_id": ObjectId(organization_id)})

    return jsonify(
        {
            "message": "organization deleted successfully",
        }
    )


@app.route("/organization/<string:organization_id>/invite", methods=["POST"])
@jwt_required()
@manage_organization_access
def invite_user(organization_id: str):
    user_email_to_invite = request.json.get("user_email")
    user = db.user.find_one({"email": user_email_to_invite})

    # check if user exists
    if not user:
        return (
            jsonify(
                {
                    "message": "user with this email doesn't exist",
                }
            ),
            404,
        )

    # invite the user to this org
    db.organization.update_one(
        {"_id": ObjectId(organization_id)},
        {
            "$push": {
                "organization_members": {
                    "name": user["name"],
                    "email": user_email_to_invite,
                    "access_level": "guest",
                }
            }
        },
    )
    return (
        jsonify(
            {
                "message": f"{user_email_to_invite} has been invited successfully to the organization !",
            }
        ),
        201,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
