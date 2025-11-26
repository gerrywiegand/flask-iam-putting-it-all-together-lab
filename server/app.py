#!/usr/bin/env python3

from config import api, app, db
from flask import request, session
from flask_restful import Resource
from models import *
from sqlalchemy.exc import IntegrityError


class Signup(Resource):
    def post(self):
        data = request.get_json()

        try:
            new_user = User(
                username=data.get("username"),
                image_url=data.get("image_url"),
                bio=data.get("bio"),
            )
            new_user.password_hash = data.get("password")

            db.session.add(new_user)
            db.session.commit()

            session["user_id"] = new_user.id
            user_schema = UserSchema()
            return user_schema.dump(new_user), 201

        except (ValueError, IntegrityError):
            db.session.rollback()
            return {"error": "User fields not valid"}, 422


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401
        user = User.query.get(user_id)
        if not user:
            return {"error": "Unauthorized"}, 401
        user_schema = UserSchema()
        return user_schema.dump(user), 200


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session["user_id"] = user.id
            user_schema = UserSchema()
            return user_schema.dump(user), 200
        else:
            return {"error": "Invalid username or password"}, 401


class Logout(Resource):
    def delete(self):
        user_id = session.get("user_id")

        if user_id is not None:
            session.pop("user_id", None)
            return {}, 204
        else:
            return {"error": "No active session"}, 401


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Unauthorized"}, 401

        recipes = Recipe.query.all()  # or filter_by(user_id=user_id) if spec says so
        recipe_schema = RecipeSchema(many=True)
        return recipe_schema.dump(recipes), 200

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()
        user_id = session["user_id"]

        try:
            new_recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id,
            )

            db.session.add(new_recipe)
            db.session.commit()

            recipe_schema = RecipeSchema()
            return recipe_schema.dump(new_recipe), 201

        except ValueError:
            db.session.rollback()
            return {"error": "Recipe fields not valid"}, 422


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
