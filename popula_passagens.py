import pandas as pd
from auth.models import Passagem, Usuario
from extensions import db
from datetime import datetime
from app_passagens.app import app

# Caminho do arquivo Excel
CAMINHO_ARQUIVO = 'app_passagens/passagens.xlsx'

with app.app_context():
    # Deleta todas as passagens
    print('Deletando todas as passagens...')
    Passagem.query.delete()
    db.session.commit()
    print('Passagens deletadas.')

    # Lê o arquivo Excel
    df = pd.read_excel(CAMINHO_ARQUIVO)

    # Ajuste os nomes das colunas conforme o arquivo Excel
    for _, row in df.iterrows():
        if pd.isna(row['Placa']) or not str(row['Placa']).strip():
            continue  # pula linhas sem placa
        usuario = Usuario.query.first()  # Ajuste para associar ao usuário correto se necessário
        datahora = datetime.strptime(str(row['Data/hora']), '%Y-%m-%d %H:%M:%S') if 'Data/hora' in row else datetime.now()
        hora = datahora.strftime('%H:%M')
        passagem = Passagem(
            numero_registro=str(row['Seq Trans']) if 'Seq Trans' in row else '',
            placa_veiculo=row['Placa'],
            data=datahora,
            hora=hora,
            valor=float(str(row['Valor']).replace('R$', '').replace(',', '.')) if 'Valor' in row else 0.0,
            tipo='debito',  # Ajuste se houver coluna de tipo
            pago=(row['Anomalia'] == 'Nenhuma') if 'Anomalia' in row else True,
            usuario_id=usuario.id if usuario else None
        )
        db.session.add(passagem)
    db.session.commit()
    print('Passagens populadas com sucesso!')
