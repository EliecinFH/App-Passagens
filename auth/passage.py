from flask import Blueprint, request, redirect, url_for, flash, render_template
from flask_login import login_required, current_user
from auth.models import Usuario, Passagem, db
from auth.validation import validate_email
from flask_bcrypt import bcrypt

passage = Blueprint('passage', __name__)

@passage.route("/historico")
@login_required
def historico():
    """"
    Rota para exibir o histórico da passagem do usuário
    """
    passagens = Passagem.query.filter_by(usuario_id=current_user.id).all()
    return render_template("historico.html", passagens=passagens)
