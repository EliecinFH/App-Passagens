"""
App concef
Este é o código fonte do app ConcefSA.
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session
from extensions import db
from auth.models import Usuario, Passagem
# from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import secrets
import logging
from logging.handlers import RotatingFileHandler
from logging import getLogger, ERROR

# Importe os blueprints
from auth.auth import auth
from payment.payment import payment
from auth.passage import passage


# Inicializar o aplicatico Flask
app = Flask(__name__)


# Configuração do banco de dados
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///concefSA.db"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# Inicializar extensões
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Registrando o blueprints
app.register_blueprint(auth, url_prefix='/auth')
app.register_blueprint(payment, url_prefix='/payment')
app.register_blueprint(passage, url_prefix='/passage')

# Inicializar o banco de dados
with app.app_context():
    db.create_all()

# Configuração de logging
if not app.debug:
    log_handler = RotatingFileHandler('error.log', maxBytes=100000, backupCount=1)
    log_handler.setLevel(ERROR)
    app.logger.addHandler(log_handler)
    app.logger.setLevel(logging.INFO)
    getLogger("werkzeug").setLevel(logging.INFO)

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

@app.route("/")
@login_required
def index():
    """"
    Rota principal da aplicação.
    Renderiza a página inicial.
    """
    try:
        return render_template("index.html")
    except Exception as e:
        logging.error(f"Error in index funtion: {e}")
        return "Erro interno do servidor", 500
    
@app.route("/logout")
@login_required
def logout():
    """
    Rota para logout do usuário.
    Redireciona para a página de login após logout.
    """
    logout_user()
    flash("Você saiu da sua conta.", "info")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Rota de login
    Verifica se o usúario está logado e redireciona para a pagian inicial.
    """
    if request.method == "POST":
        # Pegar os dados do formulario
        nome = request.form["email"]
        senha = request.form["senha"]
        usuario = Usuario.query.filter_by(email=nome).first()
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
        cpf = request.form["cpf"]
        telefone = request.form["telefone"]
        endereco = request.form["endereco"]
        cidade = request.form["cidade"]
        estado = request.form["estado"]
        cep = request.form["cep"]
        
        # Verificar se o usuário já existe
        existing_user = Usuario.query.filter_by(email=email).first()
        if existing_user:
            flash('E-mail já cadastrado.', 'danger')
            return redirect(url_for('cadastro'))
        
        # Hash da senha antes de salvar
        hashed_senha = bcrypt.generate_password_hash(senha).decode('utf-8')

        # Salvar os dados no banco de dados
        user = Usuario(nome=nome, email=email, senha=hashed_senha, cpf=cpf, telefone=telefone, endereco=endereco,
                       cidade=cidade, estado=estado, cep=cep)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Usuário cadastrado com sucesso!', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Erro ao cadastrar o usuário. Tente novamente.', 'danger')
            return redirect(url_for('cadastro'))
    return render_template('cadastro.html')
    
# Rota para a pagina de meio de pagamento
@app.route("/meio_pagamento")
@login_required
def meio_pagamento():
    """
    Rota de meios de pagamento
    Retorna a lista de meios de pagamento
   """
    try:
        meios_pagamento = MeioPagamento.query.all()
        return render_template("meios_pagamento.html", meio_pagamento=meios_pagamento)
    except Exception as e:
        logging.error(f"Error fetching payment methods: {e}")
        flash("Erro ao carregar meios de pagamento. Tente novamente.")
        return redirect(url_for("index"))

@app.route("/saldo")
@login_required
def saldo():
    """
    Rota para visualizar o saldo do usuário.
    Calcula o saldo com base nas passagens registradas.
    """
    try:
        if current_user is None:
            flash("Usuário não encontrado.")
            return redirect(url_for("index"))
        # Calcule saldo aqui
        passagem = Passagem.query.filter_by(usuario_id=current_user.id).all()
        saldo = sum(t.valor if t.tipo == 'credito' else -t.valor for t in passagem)

        # Atualizar o saldo no objeto do usuário
        current_user.saldo = saldo
        db.session.commit()

        return render_template("saldo.html", saldo=saldo)
    except Exception as e:
        logging.error(f"Error getting user saldo: {e}")
        flash("Erro ao calcular saldo. Tente novamente.")
        return redirect(url_for("index"))

# Rota consulta de passagem para quitação
# e encaminha para efetuar o pagamento.
@app.route("/pagamento-passagem", methods=["GET", "POST"])
@login_required
def pagamento_passagem():
    """
    Lidar com o pagamento de uma passagem
    """
    if request.method == "POST":
        numero_registro = request.form["numero_registro"]
        placa_veiculo = request.form["placa_veiculo"]
        data = request.form["data"]

        # Validação básica dos dados
        if not all([numero_registro or not placa_veiculo or not data]):
            flash("Todos os campos são obrigatórios.", "danger")
            return redirect(url_for("pagamento_passagem"))

        usuario = Usuario.query.get(current_user.id) # Obtenha o usuário atual
        passagem = Passagem(numero_registro=numero_registro, placa_veiculo=placa_veiculo, data=data, usuario=usuario)

        
        try:
            db.session.add(passagem)
            db.session.commit()
            flash("Pagamento registrado com sucesso!", "success")
            return redirect(url_for("index"))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error registering passage: {e}")
            flash("Erro ao registrar pagamento. tente novamente.", "danger")
            return redirect(url_for("pagamento_passagem"))
        
    return render_template("pagamento_passagem.html")

if __name__ == "__main__":
    app.run(debug=True)
