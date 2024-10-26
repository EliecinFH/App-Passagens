from flask import Blueprint, render_template, request, redirect, url_for, flash
from .models import Usuario, Passagem, db # Importe os modulos do banco de dados
from .auth import login_required # Importe a função login_required
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from falsk import Blueprint, render_template, request, redirect, url_for, flash
from flash_sqlalchemy import SQLAlchemy
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

payment = Blueprint('payment', __name__)

@payment.route("/saldo")
@login_required
def saldo():
    try:
        current_user = Usuario.query.get(current_user.id)
        if current_user is None:
            flash("Usuário não encontrado.")
            return redirect(url_for("index"))
        return render_template("saldo.html", saldo=current_user.saldo)
    except Exception as e:
        logging.error(f"Error getting user saldo: {e}")
        flash("Erro ao calcular saldo. Tente novamente.")
        return redirect(url_for("index"))
    
@payment.route("/pagamento-passagem", methods=["GET", "POST"])
@login_required
def pagamento_passagem():
    """"
    Lidar com o pagamento de passagem
    return: Redireciona para página de pagamento ou mengem de erro
    """
    if request.method == "POST":
        numero_registro = request.form["numero_registro"]
        placa_veiculo = request.form["placa_veiculo"]
        data = request.form["data"]
        valor = float(request.form["valor"]) # Obter o valor da passagem
        usuario = Usuario.query.get(current_user.id) # Obtenha o usuário atual

        # Verifique se o usuário tem saldo suficiente
        if usuario.saldo >= valor:
            # Crie a passagem e atualize o saldo
            passagem = Passagem(numero_registro=numero_registro, placa_veiculo=placa_veiculo, data=data, valor=valor, usuario=usuario)
            db.session.add(passagem)
            usuario.saldo -= valor # Debite o valor da passagem
            db.session.commit()
            flash("Passagem paga com sucesso!", "seccess")
            return redirect(url_for("index"))
        else:
            flash("Saldo insuficiente.", "danger")
            return redirect(url_for("payment.pagamento_passagem"))
    return render_template("pagamento_passagem.html")

@payment.route("/recaga", methods=["GET", "POST"])
@login_requerid
def recarga():
    """"
    Rota para recarregar o saldo do usuário
    """
    if request.method == "POST":
        valor_recarga = float(request.form["valor_recarga"])
        current_user = Usuario.query.get(current_user.id)
        if current_user is None:
            flash("Usuário não encontrado.")
            return redirect(url_for("index"))
        current_user.saldo += valor_recarga # Adicione o valor de recarga ao saldo
        db.session.commit()
        flas("Saldo recarregado com sucesso!", "success")
        return redirect(url_for("payment.saldo"))
    return render_template("recarga.html")