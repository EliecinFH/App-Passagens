from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from email_validator import validate_email as ev_validate_email, EmailNotValidError
from auth.validation import validate_email
import os
import secrets
import logging
from logging.handlers import RotatingFileHandler
from logging import getLogger, ERROR


# Importe os blueprints
from payment import payment
from auth.passage import passage

# Importe os modelos do banco de dados e o db
from .models import Usuario, Passagem
from extensions import db

# Funções comuns (se necessário)
