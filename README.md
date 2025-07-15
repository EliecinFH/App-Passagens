# App-Passagens

Projeto de app de pagamento de transações pós-passagem.

Este aplicativo é para clientes que passam na praça de pedágio sem meios de pagamento físico e querem pagar a passagem posteriormente!

## 🚀 Como rodar localmente

1. Clone o repositório:
   ```bash
   git clone https://github.com/EliecinFH/App-Passagens.git
   cd App-Passagens
   ```
2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
3. Execute a aplicação:
   ```bash
   flask run
   # ou
   python app.py
   ```
4. Acesse em [http://localhost:5000](http://localhost:5000)

## 🌐 Deploy no Render

- O deploy é feito automaticamente a cada push na branch `auteração-templates`.
- O serviço utiliza Gunicorn e Python 3.10+.
- Variáveis de ambiente devem ser configuradas no painel do Render.
- Veja o arquivo `DEPLOY.md` para um passo a passo completo.

## 🔑 Variáveis de ambiente principais
- `SECRET_KEY`
- `FLASK_ENV=production`
- `DATABASE_URL=BANCO_DE_DADOS`
- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USERNAME`, `MAIL_PASSWORD`

## 📄 Principais rotas do sistema
- `/` - Home (requer login)
- `/login` - Login de usuário
- `/logout` - Logout
- `/cadastro` - Cadastro de usuário
- `/meio_pagamento` - Gerenciar meios de pagamento
- `/saldo` - Visualizar saldo
- `/pagamento-passagem` - Pagar passagem
- `/recuperar-senha` - Recuperar senha
- `/configurar-2fa` - Configurar autenticação de dois fatores
- `/desbloquear-conta` - Desbloquear conta
- `/verificar-2fa` - Verificar código 2FA

## 🛠️ Estrutura do projeto
- `app.py` - Arquivo principal da aplicação Flask
- `auth/` - Autenticação, modelos e validações
- `payment/` - Blueprint de pagamento e saldo
- `templates/` - Templates HTML
- `static/` - Arquivos estáticos (CSS, imagens)

## 📚 Mais informações
- Veja o arquivo `DEPLOY.md` para detalhes de deploy.
- Veja o arquivo `.gitignore` para arquivos ignorados no versionamento.

# Banco de Dados PostgreSQL

Configure a variável de ambiente DATABASE_URL no seguinte formato:

    postgresql://USUARIO:SENHA@HOST:PORT/DATABASE

Exemplo para Render:

    postgresql://admin:SENHA@dpg-d1amnhbe5dus73ep9h60-a:5432/postgre_con

Substitua SENHA pela senha do seu banco.

---

Desenvolvido por EliecinFH.
