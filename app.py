from flask import Flask
from config import Config
from models import mongo, bcrypt
from routes.auth_routes import auth

app = Flask(__name__)
app.config.from_object(Config)

mongo.init_app(app)
bcrypt.init_app(app)

app.register_blueprint(auth, url_prefix='/auth')

if __name__ == '__main__':
    app.run(debug=True)
