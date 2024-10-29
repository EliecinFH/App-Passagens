from flask_login import UserMixin
from extensions import db
from flask_bcrypt import bcrypt

class Usuario(db.Model, UserMixin):
    """
    Modelo de usúario
    Representa um usuário do app
    """
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    senha = db.Column(db.String(100), nullable=False)
    cpf = db.Column(db.String(14), nullable=True)
    telefone = db.Column(db.String(15), nullable=True)
    endereco = db.Column(db.String(100), nullable=True)
    cidade = db.Column(db.String(50), nullable=True)
    estado = db.Column(db.String(50), nullable=True)
    cep = db.Column(db.String(9), nullable=True)
    saldo = db.Column(db.Float, default=0.0)

    def __init__(self, nome, email, senha, cpf, telefone, endereco, cidade, estado, cep):
        self.nome = nome
        self.email = email
        self.senha = bcrypt.generate_password_hash(senha).decode("utf-8")
        self.cpf = cpf
        self.telefone = telefone
        self.endereco = endereco
        self.cidade = cidade
        self.estado = estado
        self.cep = cep

class MeioPagamento(db.Model):
    """
    Modelo de meio de pagamento
    Representa um meio de pagamento do app
    """
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"))
    tipo = db.Column(db.String(50), nullable=False)
    numero = db.Column(db.String(50), nullable=False)

class Passagem(db.Model):
    """
    Modelo de passagem
    Representa a consulta de uma passagem no app
    """
    id = db.Column(db.Integer, primary_key=True)
    numero_registro = db.Column(db.String(50), nullable=False)
    placa_veiculo = db.Column(db.String(50), nullable=False)
    data = db.Column(db.DateTime, nullable=False)
    hora = db.Column(db.String(5), nullable=False)
    valor = db.Column(db.Float, nullable=False)
    pago = db.Column(db.Boolean, default=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"))
    usuario = db.relationship('Usuario', backref=db.backref('passagens', lazy=True))

    def __init__(self, numero_registro, placa_veiculo, data, hora, valor, usuario_id=usuario_id):
        self.numero_registro = numero_registro
        self.placa_veiculo = placa_veiculo
        self.data = data
        self.hora = hora
        self.valor = valor
        self.pago = False
        self.usuario = Usuario
        self.usuario_id = usuario_id
        