from flask import Blueprint, request, redirect, url_for, render_template, flash
from .models import Usuario, db
from .validation import validate_email
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError


auth = Blueprint('auth', __name__)
bcrypt = Bcrypt()

# Configuração do flask-login
login_manager = LoginManager()
login_manager.init_app(auth)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

@auth.route("/login", methods=["GET", "POST"])
def login():
    """"
    Rota de login
    Verifica se o usuário está logado e redireciona para a pagina inicial.
    """
    if request.method == "POST":
        email = request.form["email"]
        senha = request.form["senha"]
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario and bcrypt.check_password_hash(usuario.senha, senha):
            login_user(usuario)
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("index"))
        else:
            flash("E-mail ou senha incorretos!", "danger")
    return render_template("login.html")

@auth.route("/cadastro", methods=['GET', 'POST'])
def cadastro():
    """
    Modelo de cadastro de usuário
    Rota representa o cadastro de usuário no app.
    """
    if request.method == "POST":
        # Pegar os dados do Formulário
        nome = request.form["nome"]
        email = request.form["email"]
        senha = request.form["senha"]
        cpf = request.form["cpf"]
        telefone = request.form["telefone"]
        endereco = request.form["endereco"]
        cidade = request.form["cidade"]
        estado = request.form["estado"]
        cep = request.form["cep"]

        # Validador o e-mail
        if not validate_email(email):
            flash('E-mail inválido.', 'danger')
            return redirect(url_for('auth.cadastro'))
        
        # Verificar se o usuário já existe
        existing_user = Usuario.query.filter_by(email=email).first()
        if existing_user:
            flash('E-mail já cadastrado.', 'danger')
            return redirect(url_for('auth.cadastro'))
        
        # Salvar os dados no banco de dados
        user = Usuario(nome=nome, email=email, senha=bcrypt.generate_password_hash(senha).decode("utf-8"), cpf=cpf, telefone=telefone,
                        endereco=endereco, cidade=cidade, estado=estado, cep=cep)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Usuário cadastrado com sucesso', 'success')
            return redirect(url_for('auth.login'))
        except IntegrityError:
            db.session.rollback()
            flash('Erro ao cadastrar usuário. Tente novamente.', 'danger')
            return redirect(url_for('auth.cadastro'))
    
    return render_template('cadastro.html')
    
@auth.route("/logout")
@login_required
def logout():
    """ Rota para logout do usuário."""
    logout_user()
    flash("Você saiu da sua conta.", "info")
    return redirect(url_for("auth.login"))