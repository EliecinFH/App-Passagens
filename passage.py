from flask import Blueprint, render_template, request, redirect, url_for, flash
from .models import Passagem, db # Importe o modelo Passagem
from .auth import login_required # Importe a função login_required

passage = Blueprint('passage', __name__)

@passage.route("/historico")
@login_required
def historico():
    """"
    Rota para exibir o histórico da passagem do usuário
    """
    passagens = Passagem.query.filter_by(usuario_id=current_user.id).all()
    return render_template("historico.html", passagens=passagens)
