from extensions import db
from auth.models import Usuario, MeioPagamento, Passagem
from flask import Flask
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL") or "sqlite:///concefSA.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or "dev"

db.init_app(app)

with app.app_context():
    try:
        usuarios = Usuario.query.all()
        meios = MeioPagamento.query.all()
        passagens = Passagem.query.all()
        print(f"Conexão bem-sucedida! Usuários: {usuarios}")
        print(f"Meios de Pagamento: {meios}")
        print(f"Passagens: {passagens}")
        if not usuarios and not meios and not passagens:
            print("Banco conectado, mas nenhum dado encontrado.")
    except Exception as e:
        print(f"Erro ao conectar ou consultar o banco: {e}")
