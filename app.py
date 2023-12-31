import os
from flask import Flask
from flask_smorest import Api
from flask_jwt_extended import JWTManager
from db import db
import models
from resources.store import blp as StoreBlueprint
from resources.items import blp as ItemBlueprint
from resources.user import blp as UserBlueprint
from datetime import timedelta


def create_app(db_url=None):
    app = Flask(__name__)
    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.config["API_TITLE"] = "Store REST API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or os.getenv("DATABASE_URL", "sqlite:///database.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    api = Api(app)

    @app.before_first_request
    def create_tables():
        db.create_all()

    app.config["JWT_SECRET_KEY"] = "ivyleague"
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=3)
    jwt = JWTManager(app)

    api.register_blueprint(StoreBlueprint)
    api.register_blueprint(ItemBlueprint)
    api.register_blueprint(UserBlueprint)

    return app