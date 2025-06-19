"""
App concef
Este é o código fonte do app ConcefSA.
"""
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from datetime import datetime
import secrets
import logging
from logging.handlers import RotatingFileHandler
from logging import getLogger, ERROR
from extensions import db, bcrypt

# Inicializar o aplicatico Flask
app = Flask(__name__)

# Configuração do flask para produção
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///concefSA.db")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(16)

# Configurações de email para produção
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# Inicializar extensões
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)
mail = Mail(app)

# Importe os blueprints
from auth.auth import auth
from payment.payment import payment
from auth.passage import passage
from auth.models import Usuario, Passagem, Veiculo

app.register_blueprint(auth, url_prefix='/auth')
app.register_blueprint(payment, url_prefix='/payment')
app.register_blueprint(passage, url_prefix='/passage')

# Inicializar o banco de dados
with app.app_context():
    db.create_all()

# Configuração de logging para produção
if not app.debug:
    # Criar arquivo de log
    log_file = 'concefSA.log'
    log_handler = RotatingFileHandler('error.log', maxBytes=100000, backupCount=1)
    log_handler.setLevel(ERROR)
    app.logger.addHandler(log_handler)
    # Definir níveis de registro
    app.logger.setLevel(logging.INFO)
    getLogger("werkzeug").setLevel(logging.INFO)

@login_manager.user_loader
def load_user(user_id):
    print(f"[DEBUG] load_user chamado para id={user_id}")
    app.logger.info(f"[LOGIN_MANAGER] load_user chamado para id={user_id}")
    usuario = Usuario.query.get(int(user_id))
    app.logger.info(f"[LOGIN_MANAGER] load_user chamado para id={user_id}, usuario={usuario}")
    return usuario


@app.route("/")
@login_required
def index():
    try:
        return render_template("home.html")
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
    Verifica se o usuário está logado e redireciona para a página inicial.
    Aceita login com email ou CPF.
    """
    import traceback
    if request.method == "POST":
        identificador = request.form["identificador"]  # Pode ser email ou CPF
        senha = request.form["senha"]
        app.logger.info(
            f"[LOGIN] Tentando login com identificador: {identificador}"
        )
        usuario = None
        if '@' in identificador:
            usuario = Usuario.query.filter_by(email=identificador).first()
        else:
            usuario = Usuario.query.filter_by(cpf=identificador).first()
        app.logger.info(f"[LOGIN] Usuário encontrado: {usuario}")
        if usuario:
            app.logger.info(
                f"[LOGIN] usuario.is_active: {usuario.is_active}"
            )
            app.logger.info(
                f"[LOGIN] usuario.is_authenticated: {usuario.is_authenticated}"
            )
        if usuario and usuario.verificar_senha(senha):
            app.logger.info(
                f"[LOGIN] Senha correta para usuário: "
                f"{usuario.email if usuario else None}"
            )
            if usuario.conta_bloqueada:
                app.logger.warning(
                    f"[LOGIN] Conta bloqueada para usuário: "
                    f"{usuario.email if usuario else None}"
                )
                flash(
                    "Sua conta está bloqueada. "
                    "Verifique seu email para a senha temporária.",
                    "danger"
                )
                return redirect(url_for("login"))
            if usuario.autenticacao_dois_fatores:
                session['temp_user_id'] = usuario.id
                app.logger.info(
                    f"[LOGIN] Usuário requer 2FA: "
                    f"{usuario.email if usuario else None}"
                )
                return redirect(url_for('verificar_2fa'))
            try:
                login_user(usuario)
                app.logger.info(
                    f"[LOGIN] login_user chamado para: {usuario.email}, id: {usuario.get_id()}"
                )
            except Exception as e:
                app.logger.error(
                    f"[LOGIN] Erro ao chamar login_user: {e}\n"
                    f"{traceback.format_exc()}"
                )
                flash("Erro interno ao autenticar usuário.", "danger")
                return redirect(url_for("login"))
            usuario.ultimo_acesso = datetime.utcnow()
            usuario.tentativas_login = 0
            db.session.commit()
            login_user(current_user)
            app.logger.info(
                f"[LOGIN] Login realizado com sucesso para usuário: "
                f"{usuario.email if usuario else None}"
            )
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("index"))
        else:
            if usuario:
                usuario.tentativas_login += 1
                app.logger.warning(
                    f"[LOGIN] Senha incorreta para usuário: "
                    f"{usuario.email if usuario else None}"
                )
                if usuario.tentativas_login >= 5:
                    usuario.conta_bloqueada = True
                    usuario.data_bloqueio = datetime.utcnow()
                    senha_temp = usuario.gerar_senha_temporaria()
                    db.session.commit()
                    login_user(current_user)
                    msg = Message(
                        'Senha Temporária - Desbloqueio de Conta',
                        recipients=[usuario.email]
                    )
                    msg.body = (
                        f'Olá {usuario.nome},\n\n'
                        'Sua conta foi bloqueada devido a múltiplas tentativas de '
                        'login incorretas.\nPara desbloquear sua conta, use a '
                        f'seguinte senha temporária:\n\n{senha_temp}\n\nEsta senha expira em 24 horas.\n'
                        'Por favor, altere sua senha após fazer login.\n\nAtenciosamente,\nEquipe ConcefSA'
                    )
                    mail.send(msg)
            app.logger.warning(
                '[LOGIN] Identificador ou senha incorretos para identificador: '
                f'{identificador}'
            )
            flash("Identificador ou senha incorretos.", "danger")
    return render_template("login.html")


@app.route("/verificar-2fa", methods=["GET", "POST"])
def verificar_2fa():
    """Rota para verificação de autenticação de dois fatores"""
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    usuario = Usuario.query.get(session['temp_user_id'])
    if not usuario or not usuario.autenticacao_dois_fatores:
        return redirect(url_for('login'))
    if request.method == "POST":
        codigo = request.form.get('codigo')
        if usuario.verificar_codigo_2fa(codigo):
            login_user(usuario)
            usuario.ultimo_acesso = datetime.utcnow()
            usuario.tentativas_login = 0
            db.session.commit()
            login_user(current_user)
            session.pop('temp_user_id', None)
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("index"))
        else:
            flash("Código inválido.", "danger")
    return render_template("verificar_2fa.html")


@app.route("/desbloquear-conta", methods=["GET", "POST"])
def desbloquear_conta():
    """Rota para desbloqueio de conta usando senha temporária"""
    if request.method == "POST":
        email = request.form.get('email')
        senha_temp = request.form.get('senha_temp')
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario and usuario.verificar_senha_temporaria(senha_temp):
            usuario.desbloquear_conta()
            db.session.commit()
            login_user(current_user)
            flash(
                "Conta desbloqueada com sucesso! "
                "Faça login com sua senha normal.", "success"
            )
            return redirect(url_for("login"))
        else:
            flash("Email ou senha temporária inválidos.", "danger")
    return render_template("desbloquear_conta.html")


@app.route("/configurar-2fa", methods=["GET", "POST"])
@login_required
def configurar_2fa():
    """Rota para configurar autenticação de dois fatores"""
    if request.method == "POST":
        acao = request.form.get('acao')
        if acao == 'ativar':
            chave = current_user.configurar_2fa()
            db.session.commit()
            login_user(current_user)
            # Gerar QR Code
            totp = pyotp.TOTP(chave)
            provisioning_uri = totp.provisioning_uri(
                current_user.email,
                issuer_name="ConcefSA"
            )
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            qr_code = base64.b64encode(buffered.getvalue()).decode()
            return render_template(
                "configurar_2fa.html", qr_code=qr_code, chave=chave
            )
        elif acao == 'confirmar':
            codigo = request.form.get('codigo')
            if current_user.verificar_codigo_2fa(codigo):
                current_user.autenticacao_dois_fatores = True
                db.session.commit()
                login_user(current_user)
                flash(
                    "Autenticação de dois fatores ativada com sucesso!",
                    "success"
                )
                return redirect(url_for("index"))
            else:
                flash("Código inválido.", "danger")
        elif acao == 'desativar':
            current_user.autenticacao_dois_fatores = False
            current_user.chave_secreta_2fa = None
            db.session.commit()
            login_user(current_user)
            flash(
                "Autenticação de dois fatores desativada.", "success"
            )
            return redirect(url_for("index"))
    return render_template("configurar_2fa.html")


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    """
    Rota de cadastro de usuário
    Permite cadastro com nome, sobrenome, email, CPF e senha.
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

        # Salvar os dados no banco de dados
        user = Usuario(nome=nome, email=email, senha=senha, cpf=cpf, telefone=telefone, endereco=endereco, cidade=cidade, estado=estado, cep=cep)
        db.session.add(user)
        try:
            db.session.commit()
            app.logger.info(f"Usuário cadastrado com sucesso: {email}")
            flash('Usuário cadastrado com sucesso!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            return redirect(url_for('cadastro'))
    return render_template('cadastro.html')
        
    # Salvar os dados no banco de dados
    user = Usuario(nome=nome, email=email, senha=bcrypt.generate_password_hash('secret', senha, 10).decode('utf-8'),
                    cpf=request.form['cpf'], telefone=request.form['telefone'], endereco=request.form['endereco'],
                    cidade=request.form['cidade'], estado=request.form['estado'], cep=request.form['cep'])
    db.session.add(user)
    db.session.commit()
    flash('Usuário cadastrado com sucesso!', 'uccess')
    return redirect(url_for('index'))


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
@login_required
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
    """
    if request.method == "POST":
        numero_registro = request.form["numero_registro"]
        placa_veiculo = request.form["placa_veiculo"]
        data = request.form["data"]
        usuario = Usuario.query.get(current_user.id) # Obtenha o usuário atual
        passagem = Passagem(numero_registro=numero_registro, placa_veiculo=placa_veiculo, data=data, usuario=usuario)
        db.session.add(passagem)
        try:
            db.session.commit()
            flash("Passagem registrada com sucesso!", "success")
            return redirect(url_for("index"))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error registering passage: {e}")
            flash("Erro ao registrar pagamento. tente novamente.", "danger")
            return redirect(url_for("pagamento_passagem"))
        
    return render_template("pagamento_passagem.html")


@app.route("/recuperar-senha", methods=["GET", "POST"])
def recuperar_senha():
    """
    Rota para recuperação de senha.
    Usuário informa o e-mail, recebe uma senha temporária
    (exibida na tela para teste).
    """
    senha_temporaria = None
    if request.method == "POST":
        email = request.form.get("email")
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario:
            senha_temporaria = usuario.gerar_senha_temporaria()
            db.session.commit()
            login_user(current_user)
            flash(
                "Senha temporária gerada! (Aparece na tela para teste)",
                "info"
            )
        else:
            flash("E-mail não encontrado.", "danger")
    return render_template(
        "recuperar_senha.html", senha_temporaria=senha_temporaria
    )


@app.route('/debug_db')
def debug_db():
    try:
        usuarios = Usuario.query.all()
        return f"Usuários encontrados: {len(usuarios)}<br>Primeiro usuário: {usuarios[0].email if usuarios else 'Nenhum'}"
    except Exception as e:
        return f"Erro ao acessar banco: {e}"


if __name__ == "__main__":
    db.init_app(app)
    app.run(debug=True)
