from flask import Flask
from extensions import db
from flask_migrate import Migrate
from auth.models import Usuario, Passagem, MeioPagamento
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL") or "sqlite:///concefSA.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or "dev"

db.init_app(app)
migrate = Migrate(app, db)

if __name__ == "__main__":
    app.run(debug=True)
