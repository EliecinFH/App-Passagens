from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user, login_user
from auth.models import Usuario, Passagem, Veiculo
from extensions import db

veiculo = Blueprint('veiculo', __name__)

def get_historico_veiculo(placa, usuario_id):
    return Passagem.query.filter_by(placa_veiculo=placa, usuario_id=usuario_id).order_by(Passagem.data.desc()).all()

@veiculo.route('/veiculos', methods=['GET', 'POST'])
@login_required
def cadastrar_veiculo():
    if request.method == 'POST':
        placa = request.form['placa'].strip().upper()
        modelo = request.form['modelo']
        cor = request.form['cor']
        if not placa or not modelo or not cor:
            flash('Preencha todos os campos!', 'danger')
        elif Veiculo.query.filter_by(placa=placa).first():
            flash('Placa já cadastrada!', 'danger')
        else:
            veiculo = Veiculo(placa=placa, modelo=modelo, cor=cor, usuario_id=current_user.id)
            db.session.add(veiculo)
            db.session.commit()
            db.session.refresh(current_user)
            login_user(current_user)
            flash('Veículo cadastrado com sucesso!', 'success')
            return redirect(url_for('veiculo.cadastrar_veiculo'))
    veiculos = Veiculo.query.filter_by(usuario_id=current_user.id).all()
    historicos = {v.placa: get_historico_veiculo(v.placa, current_user.id) for v in veiculos}
    return render_template('veiculos.html', veiculos=veiculos, historicos=historicos)

@veiculo.route('/filtrar_placa', methods=['GET'])
@login_required
def filtrar_placa():
    placa = request.args.get('placa', '').strip().upper()
    passagens = []
    if placa:
        passagens = Passagem.query.filter_by(placa_veiculo=placa).order_by(Passagem.data.desc()).all()
    return render_template('filtro_placa.html', passagens=passagens, placa=placa)
