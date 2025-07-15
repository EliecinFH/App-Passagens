from flask import Blueprint, request, redirect, url_for, flash, render_template
from flask_login import login_required, current_user, login_user
from auth.models import Usuario, Passagem
from extensions import db
from auth.validation import validate_email
from flask_bcrypt import bcrypt

passage = Blueprint('passage', __name__)

@passage.route("/historico")
@login_required
def historico():
    """
    Rota para exibir o histórico da passagem do usuário
    Exibe apenas passagens pagas, ordenadas por data decrescente
    """
    passagens = Passagem.query.filter_by(
        usuario_id=current_user.id, pago=True
    ).order_by(Passagem.data.desc()).all()
    return render_template("historico.html", passagens=passagens)

@passage.route("/pagamento_passagem", methods=["GET", "POST"])
@login_required
def pagamento_passagem():
    """Lidar com o pagamento de passagem e exibir passagens pendentes por placa"""
    passagens_pendentes = None
    if request.method == "GET" and request.args.get("placa_busca"):
        placa_busca = request.args.get("placa_busca").strip().upper()
        passagens_pendentes = Passagem.query.filter_by(placa_veiculo=placa_busca, pago=False).order_by(Passagem.data.desc()).all()
        return render_template("pagamento_passagem.html", passagens_pendentes=passagens_pendentes)
    if request.method == "POST":
        numero_registro = request.form["numero_registro"]
        placa_veiculo = request.form["placa_veiculo"]
        data = request.form["data"]
        valor = float(request.form["valor"])
        usuario = Usuario.query.get(current_user.id)
        if valor <= 0:
            flash("Valor da passagem inválido.", "danger")
            return redirect(url_for("pagamento_passagem"))
        if usuario.saldo >= valor:
            # Atualiza passagem existente se for pendente
            passagem = Passagem.query.filter_by(numero_registro=numero_registro, placa_veiculo=placa_veiculo, pago=False).first()
            if passagem:
                passagem.pago = True
                passagem.usuario_id = usuario.id
                passagem.valor = valor
                db.session.commit()
                login_user(current_user)
                flash("Passagem paga com sucesso!", "success")
                return redirect(url_for("home"))
            else:
                flash("Nenhuma passagem pendente encontrada para os dados informados.", "danger")
                return redirect(url_for("pagamento_passagem"))
        else:
            flash("Saldo insuficiente.", "danger")
            return redirect(url_for("pagamento_passagem"))
    return render_template("pagamento_passagem.html")
