from extensions import db, bcrypt
from flask_login import UserMixin
from extensions import db
from flask_bcrypt import bcrypt
from datetime import datetime

class Usuario(db.Model, UserMixin):
    """
    Modelo de usúario
    Representa um usuário do app
    """
    __tablename__ = 'usuario'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    sobrenome = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    senha = db.Column(db.String(100), nullable=False)
    cpf = db.Column(db.String(14), nullable=False, unique=True)
    telefone = db.Column(db.String(15), nullable=True)
    endereco = db.Column(db.String(100), nullable=True)
    cidade = db.Column(db.String(50), nullable=True)
    estado = db.Column(db.String(50), nullable=True)
    cep = db.Column(db.String(9), nullable=True)
    saldo = db.Column(db.Float, default=0.0)
    conta_bloqueada = db.Column(db.Boolean, default=False)
    tentativas_login = db.Column(db.Integer, default=0)
    ultimo_acesso = db.Column(db.DateTime)
    autenticacao_dois_fatores = db.Column(db.Boolean, default=False)
    chave_secreta_2fa = db.Column(db.String(32), nullable=True)
    data_bloqueio = db.Column(db.DateTime, nullable=True)
    senha_temporaria = db.Column(db.String(100), nullable=True)
    data_senha_temporaria = db.Column(db.DateTime, nullable=True)

    def __init__(self, nome, email, senha, cpf, telefone=None, endereco=None, cidade=None, estado=None, cep=None, sobrenome=None):
        self.nome = nome
        self.sobrenome = sobrenome
        self.email = email
        self.senha = senha  # Não faz hash aqui, já vem hasheada do cadastro
        self.cpf = cpf
        self.telefone = telefone
        self.endereco = endereco
        self.cidade = cidade
        self.estado = estado
        self.cep = cep

    def verificar_senha(self, senha):
        return bcrypt.check_password_hash(self.senha, senha)

    def gerar_senha_temporaria(self):
        import secrets
        from datetime import datetime, timedelta
        senha_temp = secrets.token_urlsafe(8)
        self.senha_temporaria = bcrypt.generate_password_hash(senha_temp).decode('utf-8')
        self.data_senha_temporaria = datetime.utcnow()
        return senha_temp

    def verificar_senha_temporaria(self, senha):
        from datetime import datetime, timedelta
        if self.senha_temporaria and self.data_senha_temporaria:
            if datetime.utcnow() - self.data_senha_temporaria < timedelta(hours=24):
                return bcrypt.check_password_hash(self.senha_temporaria, senha)
        return False

    def desbloquear_conta(self):
        self.conta_bloqueada = False
        self.tentativas_login = 0
        self.senha_temporaria = None
        self.data_senha_temporaria = None
        self.data_bloqueio = None

    def get_id(self):
        return str(self.id)

class MeioPagamento(db.Model):
    """
    Modelo de meio de pagamento
    Representa um meio de pagamento do app
    """
    __tablename__ = 'meio_pagamento'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=True)
    tipo = db.Column(db.String(50), nullable=False)  # 'pix', 'cartao', etc
    numero = db.Column(db.String(50), nullable=True)
    descricao = db.Column(db.String(100), nullable=True)
    ativo = db.Column(db.Boolean, default=True)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)

class Passagem(db.Model):
    """
    Modelo de passagem
    Representa a consulta de uma passagem no app
    """
    id = db.Column(db.Integer, primary_key=True)
    numero_registro = db.Column(db.String(50), nullable=False)
    placa_veiculo = db.Column(db.String(50), nullable=False)
    data = db.Column(db.DateTime, nullable=False)
    hora = db.Column(db.String(5), nullable=True)
    valor = db.Column(db.Float, nullable=True)
    tipo = db.Column(db.String(20), nullable=True)  # 'credito' ou 'debito'
    pago = db.Column(db.Boolean, default=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"))
    usuario = db.relationship('Usuario', backref=db.backref('passagens', lazy=True))

    def __init__(self, numero_registro, placa_veiculo, data, hora, valor, usuario_id=None, tipo=None, pago=None):
        self.numero_registro = numero_registro
        self.placa_veiculo = placa_veiculo
        self.data = data
        self.hora = hora
        self.valor = valor
        self.tipo = tipo
        self.pago = pago if pago is not None else False
        self.usuario_id = usuario_id

class Veiculo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    placa = db.Column(db.String(10), nullable=False, unique=True)
    modelo = db.Column(db.String(50), nullable=False)
    cor = db.Column(db.String(30), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    usuario = db.relationship('Usuario', backref=db.backref('veiculos', lazy=True))
