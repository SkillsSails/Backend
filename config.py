import os
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt

class Config:
    MONGO_URI = "mongodb://localhost:27017/myDatabase"
    SECRET_KEY = "your_secret_key_here"
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or '/tmp'

    @staticmethod
    def init_app(app):
        app.config['MONGO_URI'] = Config.MONGO_URI
        app.config['SECRET_KEY'] = Config.SECRET_KEY
        app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER

    # Initialize extensions
    mongo = PyMongo()
    bcrypt = Bcrypt()
