from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from .models import Usuario, db

auth = Blueprint('auth', __name__)
bcrypt = Bcrypt()

# Configuração do flask-login
login_manager = LoginManager()
login_manager.init_app(auth)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

@auth.rout("/login", methods=["GET", "POST"])
def login():
    """"
    Rota de login
    Verifica se o usuário está logado e redireciona para a pagina unicial.
    """
    if request.method =="POST":
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

@auth.rout("/cadastro", methods=['GET', 'POST'])
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
            flash('E-mail já cadastrado.', 'denger')
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
        flash('Erro ao cadastrar usuário.', 'danger')
        return redirect(url_for('auth.cadastro'))
    
    return render_template('cadastro.html')

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Você sau da sua conta.", "info")
    return redirect(url_for("auth.login"))