from extensions import db, bcrypt
from auth.models import Usuario
from app_passagens.app import app

with app.app_context():
    nome = 'Usuário Teste'
    sobrenome = 'Teste'
    email = 'usuario@teste.com'
    senha = '123456'  # Lembre-se de hashear a senha se necessário
    cpf = '000.000.000-00'
    telefone = '11999999999'
    endereco = 'Rua Exemplo, 123'
    cidade = 'Cidade'
    estado = 'UF'
    cep = '00000-000'
    senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

    if not Usuario.query.filter_by(email=email).first():
        usuario = Usuario(
            nome=nome,
            sobrenome=sobrenome,
            email=email,
            senha=senha_hash,
            cpf=cpf,
            telefone=telefone,
            endereco=endereco,
            cidade=cidade,
            estado=estado,
            cep=cep
        )
        db.session.add(usuario)
        db.session.commit()
        print('Usuário criado com sucesso!')
    else:
        print('Usuário já existe.')
