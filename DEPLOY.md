# Guia de Deploy no Render

## 📋 Pré-requisitos

1. Conta no [Render](https://render.com)
2. Repositório no GitHub (já configurado)
3. Projeto preparado para produção

## 🚀 Passos para Deploy

### 1. Acesse o Render Dashboard
- Vá para [https://dashboard.render.com/web/new](https://dashboard.render.com/web/new)
- Faça login na sua conta

### 2. Conecte seu Repositório
- Clique em "Connect a repository"
- Selecione o repositório: `EliecinFH/App-Passagens`
- Escolha a branch: `auteração-templates`

### 3. Configure o Serviço Web

**Nome do Serviço:** `app-passagens-concef`

**Configurações:**
- **Environment:** Python 3
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT`

### 4. Configure as Variáveis de Ambiente

Adicione as seguintes variáveis de ambiente:

| Variável | Valor | Descrição |
|----------|-------|-----------|
| `SECRET_KEY` | (deixe vazio para gerar automaticamente) | Chave secreta do Flask |
| `FLASK_ENV` | `production` | Ambiente de produção |
| `DATABASE_URL` | `sqlite:///concefSA.db` | URL do banco de dados |
| `MAIL_SERVER` | `smtp.gmail.com` | Servidor de email |
| `MAIL_PORT` | `587` | Porta do servidor de email |
| `MAIL_USE_TLS` | `true` | Usar TLS para email |
| `MAIL_USERNAME` | `seu-email@gmail.com` | Email para envio |
| `MAIL_PASSWORD` | `sua-senha-app` | Senha do app do Gmail |

### 5. Configurações de Email (Opcional)

Para configurar o envio de emails:

1. **Gmail App Password:**
   - Vá para configurações da conta Google
   - Ative a verificação em duas etapas
   - Gere uma senha de app
   - Use essa senha em `MAIL_PASSWORD`

2. **Ou use um serviço de email:**
   - SendGrid
   - Mailgun
   - Amazon SES

### 6. Deploy

- Clique em "Create Web Service"
- Aguarde o build e deploy (pode levar alguns minutos)
- O Render fornecerá uma URL para acessar sua aplicação

## 🔧 Arquivos de Configuração Criados

### `requirements.txt`
- Dependências do Python com versões específicas
- Inclui Gunicorn para produção

### `Procfile`
- Configuração para o servidor WSGI
- Define como executar a aplicação

### `runtime.txt`
- Especifica a versão do Python (3.9.16)

### `render.yaml`
- Configuração automática do deploy
- Define variáveis de ambiente

### `gunicorn.conf.py`
- Configurações do servidor Gunicorn
- Otimizações para produção

## 🌐 Acesso à Aplicação

Após o deploy, sua aplicação estará disponível em:
```
https://app-passagens-concef.onrender.com
```

## 📊 Monitoramento

- **Logs:** Acesse os logs no dashboard do Render
- **Métricas:** Monitore o uso de recursos
- **Deploy:** Configure deploy automático a cada push

## 🔄 Deploy Automático

O Render fará deploy automático sempre que você fizer push para a branch `auteração-templates`.

## 🛠️ Troubleshooting

### Problemas Comuns:

1. **Erro de Build:**
   - Verifique se todas as dependências estão no `requirements.txt`
   - Confirme se a versão do Python está correta

2. **Erro de Runtime:**
   - Verifique os logs no dashboard do Render
   - Confirme se as variáveis de ambiente estão configuradas

3. **Erro de Banco de Dados:**
   - O SQLite será criado automaticamente
   - Para PostgreSQL, configure `DATABASE_URL` adequadamente

## 📝 Notas Importantes

- O plano gratuito do Render tem limitações
- A aplicação pode "dormir" após 15 minutos de inatividade
- Considere upgrade para planos pagos para produção

## 🔗 Links Úteis

- [Documentação do Render](https://render.com/docs)
- [Guia de Deploy Python](https://render.com/docs/deploy-python-app)
- [Configuração de Variáveis de Ambiente](https://render.com/docs/environment-variables) 