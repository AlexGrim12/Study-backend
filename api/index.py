import os
from datetime import datetime

from flask import Flask, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from functools import (
    wraps,
)  # Importar wraps para preservar el nombre de la función original

# env
from dotenv import load_dotenv

# Configuración de Flask
app = Flask(__name__)
# env
load_dotenv()
# Configuración de la base de datos
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = os.urandom(
    24
)  # Clave secreta para la sesión (genera una clave segura en producción)
db = SQLAlchemy(app)


# Modelos

# Creacion de las tablas si no estan hechas

#Rutas


# Ruta de bienvenida pagina html
@app.route("/")
def index():
    return redirect(url_for("static", filename="index.html"))