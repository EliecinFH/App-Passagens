from flask import redirect, url_for, session, request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build  # Corrigido: 'bluild' -> 'build'
from google.oauth2 import service_account
import requests

# Configurações da API do google Login
CLIENT_SECRETS_FILE = 'client_secret_10710864237-f7pgmhvvmrfs6vgoqeoo6501cgntl2fo.apps.googleusercontent.com.json'
SCOPES = ['profile', 'email']
REDIRECT_URI = 'http://localhost:5000/login/google/callback'  # Corrigido: REDIRECT -> REDIRECT_URI

# Configuração da API Pix (ajustar para carteira digital)
PIX_API_URL = 'https://api.pix.com.br/v1/pagamentos'
PIX_API_KEY = 'Chave API'

def google_login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

def google_login_callback():
    state = session.pop('state', None)
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=state
    )
    flow.fetch_token(authorization_response=request.url)  # Corrigido: 'fletch_token' -> 'fetch_token'
    credentials = flow.credentials
    # Obtém informações do usuário do Google
    user_info = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()  # Corrigido: 'auth2' -> 'oauth2', 'user_infor' -> 'user_info'
    # Crie um usuário ou faça login (implementar essa lógica)
    return redirect(url_for('home'))

def realizar_pagamento_pix(valor, chave_pix):
    url = PIX_API_URL
    headers = {'Authorization': f'Bearer {PIX_API_KEY}'}
    payload = {
        'valor': valor,
        'chave': chave_pix,
    }
    response = requests.post(url, headers=headers, json=payload)  # Corrigido: 'headres' -> 'headers'
    # Verifique a resposta da API
    if response.status_code == 200:  # Corrigido: 'state_code' -> 'status_code'
        # Processa o pagamento com sucesso
        return True
    else:
        # Tratar erros de pagamento
        return False