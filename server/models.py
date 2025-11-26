from config import bcrypt, db
from marshmallow import Schema, fields
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    _password_hash = db.Column("password_hash", db.String(128))
    image_url = db.Column(db.String, nullable=True)
    bio = db.Column(db.String(250), nullable=True)

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        hash_bytes = bcrypt.generate_password_hash(password.encode("utf-8"))
        self._password_hash = hash_bytes.decode("utf-8")

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode("utf-8"))

    @validates("username")
    def validate_username(self, key, username):
        if len(username) < 3 or len(username) > 20:
            raise ValueError("Username must be between 3 and 20 characters long.")
        return username

    recipes = db.relationship(
        "Recipe", back_populates="user", cascade="all, delete-orphan"
    )


class Recipe(db.Model):
    __tablename__ = "recipes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    minutes_to_complete = db.Column(db.Integer, nullable=False)

    @validates("instructions")
    def validate_instructions(self, key, instructions):
        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions

    user = db.relationship("User", back_populates="recipes")


class UserSchema(Schema):
    id = fields.Integer()
    username = fields.String()
    bio = fields.String()


class RecipeSchema(Schema):
    id = fields.Integer()
    title = fields.String()
    instructions = fields.String()
    user_id = fields.Integer()
    minutes_to_complete = fields.Integer()
