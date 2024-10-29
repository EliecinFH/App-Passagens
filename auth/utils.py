from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from email_validator import EmailNotValidError
from auth.validation import validate_email
import os
import secrets
import logging
from logging.handlers import RotatingFileHandler
from logging import getLogger, ERROR


# Importe os blueprints
from payment import payment
from auth.passage import passage

# Importe os modelos do banco de dados
from .models import Usuario, Passagem, db

# Funções comuns (se necessário)
