from app import app
from extensions import db
from auth.models import Usuario, MeioPagamento, Passagem

with app.app_context():
    db.create_all()
    print("Banco de dados e tabelas criados com sucesso!")
