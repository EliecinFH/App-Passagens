import os
from flask import Flask
from extensions import db
from auth.models import Passagem, Usuario

instance_path = os.path.join(os.path.dirname(__file__), 'instance')
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(instance_path, 'concefSA.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    print('--- PASSAGENS ---')
    for p in Passagem.query.all():
        print(f"ID: {p.id}, Registro: {p.numero_registro}, Placa: {p.placa_veiculo}, Valor: {p.valor}, Pago: {p.pago}, Tipo: {p.tipo}, Usuário: {p.usuario_id}")
    print('\n--- USUÁRIOS ---')
    for u in Usuario.query.all():
        print(f"ID: {u.id}, Nome: {u.nome} {u.sobrenome}, Email: {u.email}, CPF: {u.cpf}")
