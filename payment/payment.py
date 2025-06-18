import logging
from flask import Blueprint, request, redirect, url_for, flash, render_template
from flask_login import login_required, current_user, login_user
from auth.models import Usuario, Passagem
from extensions import db

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
    

@payment.route("/recarga", methods=["GET", "POST"])
@login_required
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
        
        # Verifique se o saldo é suficiente para a recarga
        if valor_recarga <= 0:
            flash("Valor de recarga inválido.", "danger")
            return redirect(url_for("payment.recarga"))
        
        current_user.saldo += valor_recarga # Adicione o valor de recarga ao saldo
        db.session.commit()
        login_user(current_user)
        flash("Saldo recarregado com sucesso!", "success")
        return redirect(url_for("payment.saldo"))
    
    return render_template("recarga.html")
