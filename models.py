from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt

mongo = PyMongo()
bcrypt = Bcrypt()

# Your User model and other models go here

class User:
    def __init__(self, username, password, _id=None):
        self.username = username
        self.password = password
        self._id = _id

    @staticmethod
    def find_by_username(username):
        user_data = mongo.db.users.find_one({"username": username})
        if user_data:
            return User(
                username=user_data['username'],
                password=user_data['password'],
                _id=user_data['_id']
            )
        return None

    def save(self):
        user_id = mongo.db.users.insert_one({
            "username": self.username,
            "password": self.password
        }).inserted_id
        self._id = user_id
        return user_id

    @staticmethod
    def validate_password(stored_password, provided_password):
        return bcrypt.check_password_hash(stored_password, provided_password)
