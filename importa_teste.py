import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from extensions import db, bcrypt
from auth.models import Usuario, Passagem
from flask import Flask
from datetime import datetime

app = Flask(__name__)
instance_path = os.path.join(os.path.dirname(__file__), 'instance')
os.makedirs(instance_path, exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL") or f"sqlite:///{os.path.join(instance_path, 'concefSA.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or "dev"

db.init_app(app)

with app.app_context():
    # Criar usuário admin
    if not Usuario.query.filter_by(email="admin@concefsa.com").first():
        admin = Usuario(
            nome="Admin",
            sobrenome="ConcefSA",
            email="admin@concefsa.com",
            senha="admin123",
            cpf="00000000000",
            telefone="(00)00000-0000",
            endereco="Rua Admin, 1",
            cidade="AdminCity",
            estado="AD",
            cep="00000-000"
        )
        db.session.add(admin)
        db.session.commit()
        print("Usuário admin criado com sucesso!")
    else:
        print("Usuário admin já existe.")

    # Importar passagens do Excel
    try:
        df = pd.read_excel("passagens.xlsx")
        for _, row in df.iterrows():
            passagem = Passagem(
                numero_registro=str(row.get('numero_registro', '')),
                placa_veiculo=str(row.get('placa_veiculo', '')),
                data=row.get('data', datetime.utcnow()),
                hora=str(row.get('hora', '')),
                valor=float(row.get('valor', 0)),
                tipo=str(row.get('tipo', 'credito')),
                pago=bool(row.get('pago', False)),
                usuario_id=1  # Associa ao admin
            )
            db.session.add(passagem)
        db.session.commit()
        print("Passagens importadas com sucesso!")
    except Exception as e:
        print(f"Erro ao importar passagens: {e}")
