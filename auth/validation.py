from email_validator import validate_email as ev_validate_email, EmailNotValidError

# Validação de email
def validate_email(email: str) -> bool:
    """
    Valide um endereço de e-mail usado a biblioteca do validador de e-mail
    :para email: Endereço de email valido
    :return: Endereço de e-mail validado ou nenhuma se for inválido
    """
    try:
        ev_validate_email(email)
        return True
    except EmailNotValidError:
        return False