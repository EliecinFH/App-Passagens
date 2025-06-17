from extensions import db
from app_passagens.app import app
from sqlalchemy import text

sql = '''
CREATE TABLE IF NOT EXISTS veiculo (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    placa VARCHAR(10) NOT NULL UNIQUE,
    modelo VARCHAR(50) NOT NULL,
    cor VARCHAR(30) NOT NULL,
    usuario_id INTEGER,
    FOREIGN KEY(usuario_id) REFERENCES usuario(id)
);
'''

with app.app_context():
    with db.engine.connect() as conn:
        conn.execute(text(sql))
        print('Tabela veiculo criada com sucesso!')
