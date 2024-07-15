from flask import Flask
from config import Config
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from flask_session import Session
from routes.auth_routes import auth
from flask_pymongo import PyMongo

def create_app():
    # Initialize Flask app
    app = Flask(__name__)
    # Flask-Mail configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USERNAME'] = 'mrdjebbi@gmail.com'
    app.config['MAIL_PASSWORD'] = 'piaj agrh sasa ksdy'  # Use your app password here
    app.config['MAIL_DEFAULT_SENDER'] = 'mrdjebbi@gmail.com'
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    Config.init_app(app)

    # Initialize Flask-Mail
    mail = Mail(app)

    # Initialize MongoDB and bcrypt
    Config.mongo.init_app(app)
    bcrypt = Bcrypt(app)
    
    # Session configuration
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_KEY_PREFIX'] = 'session:'
    Session(app)

    # Register blueprints
    app.register_blueprint(auth, url_prefix='/auth')

    @app.route('/')
    def index():
        return "Welcome to your Flask app!"

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
