import requests

# Altere para o endereço local do seu app Flask
BASE_URL = "http://127.0.0.1:5000"

rotas = [
    "/",
    "/login",
    "/logout",
    "/cadastro",
    "/meio_pagamento",
    "/saldo",
    "/pagamento-passagem",
    "/recuperar-senha",
    "/configurar-2fa",
    "/desbloquear-conta",
    "/verificar-2fa",
    "/debug_db"
]

for rota in rotas:
    url = BASE_URL + rota
    try:
        resp = requests.get(url, allow_redirects=False)
        print(f"{rota:25} -> {resp.status_code}")
    except Exception as e:
        print(f"{rota:25} -> ERRO: {e}")
