import os
from datetime import datetime

from flask import Flask, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    Boolean,
    ForeignKey,
)
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
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
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# Modelos
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(120), nullable=False)
    school = Column(String(120))
    courses = Column(
        String
    )  # Podrías cambiar esto a una relación muchos a muchos más adelante si es necesario
    friends = Column(
        String
    )  # Similarmente, esto podría ser una relación muchos a muchos
    summaries = relationship("Summary", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Summary(db.Model):
    __tablename__ = "summaries"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(120), nullable=False)
    notion_url = Column(String, nullable=False)
    course_id = Column(Integer, ForeignKey("courses.id"), nullable=False)


class Course(db.Model):
    __tablename__ = "courses"
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    school = Column(String(120))
    summaries = relationship("Summary", backref="course", lazy=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Creacion de las tablas si no estan hechas
with app.app_context():
    db.create_all()

# Rutas


# Ruta de bienvenida pagina html
@app.route("/")
def index():
    return redirect(url_for("static", filename="index.html"))


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    name = data.get("name")
    school = data.get("school")
    password = data.get("password")

    if not username or not name or not password:
        return jsonify({"error": "Faltan datos"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "El usuario ya existe"}), 400

    new_user = User(username=username, name=name, school=school)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Usuario registrado exitosamente"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()

    if user is None or not user.check_password(password):
        return jsonify({"error": "Credenciales inválidas"}), 401

    login_user(user)
    return jsonify({"message": "Inicio de sesión exitoso"}), 200


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Sesión cerrada exitosamente"}), 200


@app.route("/friends", methods=["GET"])
@login_required
def get_friends():
    try:
        # Obtener amigos del usuario autenticado
        user = current_user
        friends_usernames = user.friends.split(",") if user.friends else []
        friends_list = []

        for username in friends_usernames:
            friend = User.query.filter_by(username=username).first()
            if friend:
                friends_list.append(
                    {
                        "UID": friend.id,
                        "name": friend.name,
                        "description": "Estudiante",  # Puedes cambiar esto para obtener una descripción más precisa si está disponible
                        "university": friend.school,
                    }
                )

        return jsonify(friends_list), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/upload_template", methods=["POST"])
@login_required
def upload_template():
    data = request.get_json()
    name = data.get("name")
    notion_url = data.get("notion_url")
    course_id = data.get("course_id")

    if not name or not notion_url or not course_id:
        return jsonify({"error": "Faltan datos"}), 400

    new_summary = Summary(
        user_id=current_user.id, name=name, notion_url=notion_url, course_id=course_id
    )
    db.session.add(new_summary)
    db.session.commit()

    return jsonify({"message": "Template subido exitosamente"}), 201


if __name__ == "__main__":
    app.run(debug=True)
