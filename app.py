"""
App concef
Este é o código fonte do app .
"""
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import secrets
import email_validator
import logging
from logging.handlers import RotatingFileHandler
from logging import getLogger, ERROR

# from flash_babel import gettext as _

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///.db"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(16)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Inicializar o banco de dados
with app.app_context():
    db.create_all()

if not app.debug:
    # Criar arquivo de log
    log_file = 'concefSA.log'
    log_handler = RotatingFileHandler('error.log', maxBytes=100000, backupCount=1)
    log_handler.setLevel(ERROR)
    app.logger.addHandler(log_handler)
    # Definir níveis de registro
    app.logger.setLevel(logging.INFO)
    getLogger("werkzeug").setLevel(logging.INFO)

# Configuração do flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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

def validate_email(email):
    """
    Valide um endereço de e-mail usado a biblioteca do validador de e-mail
    :para email: Endereço de email valido
    :return: Endereço de e-mail validado ou nenhuma se for inválido
    """
    from email_validator import validate_email
    try:
        validate_email(email)
        return True
    except email_validator.EmailNotValidError:
        return False
    
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

@app.route("/")
@login_required
def index():
    try:
        return render_template("index.html")
    except Exception as e:
        logging.error(f"Error in index funtion: {e}")
        return "Erro interno do servidor", 500
    

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Você saiu da sua conta.", "info")
    return redirect(url_for("login"))

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Rote de login
    Verifica se o usúario está logado e redireciona para a pagian inicial.
    """
    if request.method == "POST":
        nome = request.form["email"]
        senha = request.form["senha"]
        usuario = Usuario.query.filter_by(nome=nome).first()
        if usuario and bcrypt.check_password_hash(usuario.senha, senha):
            login_user(usuario)
            flash("login realizado com sucesso!", "success")
            return redirect(url_for("index"))
        else:
            flash("E-mail ou senha incorretos.", "danger")
    return render_template("login.html")

# Rota para página de cadastro
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    """
    Modelo de cadastro de usúario
    Rota represnta o cadastro de usuario no app.
    """
    if request.method == "POST":
        # Pegar os dados do formulário
        nome = request.form["nome"]
        email = request.form["email"]
        senha = request.form["senha"]

        # Validar o e-mail
        try:
            email_validator.validate_email(email)
        except email_validator.EmailNotValidError:
            flash('Nome e senha são obrigatórios')
            return redirect(url_for('cadastro'))
        
        # Salvar os dados no banco de dados
        user = Usuario(nome=nome, email=email, senha=bcrypt.generate_password_hash('secret', senha, 10).decode('utf-8'),
                       cpf=request.form['cpf'], telefone=request.form['telefone'], endereco=request.form['endereco'],
                       cidade=request.form['cidade'], estado=request.form['estado'], cep=request.form['cep'])
        db.session.add(user)
        db.session.commit()
        flash('Usuário cadastrado com sucesso!', 'uccess')
        return redirect(url_for('index'))
    return render_template('cadastro.html')

# Rota para a pagina de meio de pagamento
@app.route("/meio_pagamento")
def meio_pagamento():
    """
    Rota de meios de pagamento
    Retorna a lista de meios de pagamento
    """
    meio_pagamento = MeioPagamento.query.all()
    return render_template("meios_pagamento.html", meio_pagamento=meio_pagamento)

@app.route("/saldo")
def saldo():
    try:
        current_user = Usuario.query.get(1)
        if current_user is None:
            flash("Usuário não encontrado.")
            return redirect(url_for("index"))
        # Calcule saldo aqui
        saldo = current_user.saldo 
        return render_template("saldo.html", saldo=saldo)
    except Exception as e:
        logging.error(f"Error getting user saldo: {e}")
        flash("Erro ao calcular saldo. Tente novamente.")
        return redirect(url_for("index"))

# Rota consulta de passagem para quitação
# e encaminha para efetuar o pagamento.
@app.route("/pagamento-passagem", methods=["GET", "POST"])
def pagamento_passagem():
    """
    Lidar com o pagamento de uma passagem

    :return: Redireciona para página de pagamento ou mensagem de erro
    """
    if request.method == "POST":
        numero_registro = request.form["numero_registro"]
        placa_veiculo = request.form["placa_veiculo"]
        data = request.form["data"]
        usuario = Usuario.query.get(current_user.id) # Obtenha o usuário atual
        passagem = Passagem(numero_registro=numero_registro, placa_veiculo=placa_veiculo, data=data, usuario=usuario)
        db.session.add(passagem)
        db.session.commit()
        return redirect(url_for("index"))
    return render_template("pagamento_passagem.html")

    '''try:
        if request.method == "POST":
            numero_registro = request.form["numero_registro"]
            placa_veiculo = request.form["placa_veiculo"]
            data = request.form["data"]
            #Consulta passagem por numero_registro, placa_veiculo e dados
            passagem = Passagem.query.filter_by(numero_registro=numero_registro, placa_veiculo=placa_veiculo, data=data).first()
            if passagem:
                # Verifica se a passagem foi quitada
                if passagem.pago:
                    flash("Passagem já paga.")
                    return redirect(url_for("index"))
                else:
                    # Renderiza página de pagamento com detalhes da passagem
                    return render_template("pagamento_passagem.html", passagem=passagem)
            else:
                flash("Passagem não encontrada.")
                return redirect(url_for("index"))
            # Renderizar págian de consulta
        return render_template("consulta_passagem.html")
    except Exception as e:
        logging.error(f"Error ao processar pagamento: {e}")
        flash("Erro ao processar pagamento.")
        return redirect(url_for("index"))'''

if __name__ == "__main__":
    app.run(debug=True)
