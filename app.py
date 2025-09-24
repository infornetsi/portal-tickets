import os
import datetime as dt
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup, escape

# -------------------- Configuración --------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cambia-esto-en-render")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///tickets.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

ROLES = ["admin", "supervisor", "tecnico", "usuario"]
ESTADOS = ["abierto", "en_progreso", "resuelto", "cerrado"]

# Filtro: convierte saltos de línea en <br>
@app.template_filter('nl2br')
def nl2br_filter(s):
    if not s:
        return ""
    return Markup("<br>".join(escape(s).splitlines()))

# -------------------- Modelos --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="usuario")

    tickets_creados = db.relationship(
        "Ticket", backref="creator", foreign_keys="Ticket.created_by", lazy=True
    )
    tickets_asignados = db.relationship(
        "Ticket", backref="technician", foreign_keys="Ticket.assigned_to", lazy=True
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="abierto")
    priority = db.Column(db.String(20), nullable=False, default="media")
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=dt.datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, nullable=False, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow
    )


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# -------------------- Utilidades --------------------
def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


def init_app():
    with app.app_context():
        db.create_all()
        # Crear admin inicial si hay variables de entorno
        admin_email = os.environ.get("ADMIN_EMAIL")
        admin_pass = os.environ.get("ADMIN_PASSWORD")
        admin_name = os.environ.get("ADMIN_NAME", "Administrador")
        if admin_email and admin_pass:
            existing = db.session.execute(
                db.select(User).filter_by(email=admin_email)
            ).scalar_one_or_none()
            if not existing:
                admin = User(name=admin_name, email=admin_email, role="admin")
                admin.set_password(admin_pass)
                db.session.add(admin)
                db.session.commit()


init_app()

# -------------------- Rutas públicas --------------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("list_tickets"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("list_tickets"))
        flash("Credenciales incorrectas", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    # Registro abierto solo para rol 'usuario'
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        exists = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
        if exists:
            flash("Ese correo ya está registrado.", "warning")
        elif not name or not email or not password:
            flash("Completa todos los campos.", "warning")
        else:
            u = User(name=name, email=email, role="usuario")
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("Cuenta creada. Ya puedes iniciar sesión.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


# -------------------- Tickets --------------------
@app.route("/tickets")
@login_required
def list_tickets():
    stmt = db.select(Ticket).order_by(Ticket.created_at.desc())
    if current_user.role in ("admin", "supervisor"):
        pass  # ven todo
    elif current_user.role == "tecnico":
        stmt = stmt.filter(Ticket.assigned_to == current_user.id)
    else:  # usuario
        stmt = stmt.filter(Ticket.created_by == current_user.id)

    tickets = db.session.execute(stmt).scalars().all()
    return render_template("tickets.html", tickets=tickets, ESTADOS=ESTADOS)


@app.route("/tickets/nuevo", methods=["GET", "POST"])
@login_required
def new_ticket():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        priority = request.form.get("priority", "media")
        if not title or not description:
            flash("Título y descripción son obligatorios.", "warning")
        else:
            t = Ticket(title=title, description=description, priority=priority, created_by=current_user.id)
            db.session.add(t)
            db.session.commit()
            flash("Ticket creado.", "success")
            return redirect(url_for("list_tickets"))
    return render_template("ticket_detail.html", ticket=None, ESTADOS=ESTADOS, tecnicos=_tecnicos())


@app.route("/tickets/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket:
        abort(404)
    if not _puede_ver(ticket):
        abort(403)
    return render_template("ticket_detail.html", ticket=ticket, ESTADOS=ESTADOS, tecnicos=_tecnicos())


@app.route("/tickets/<int:ticket_id>/asignar", methods=["POST"])
@login_required
@roles_required("admin", "supervisor")
def assign_ticket(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket:
        abort(404)
    tech_id = request.form.get("assigned_to")
    if tech_id:
        user = db.session.get(User, int(tech_id))
        if not user or user.role != "tecnico":
            flash("Debes asignar a un usuario con rol técnico.", "warning")
        else:
            ticket.assigned_to = user.id
            db.session.commit()
            flash("Ticket asignado.", "success")
    return redirect(url_for("ticket_detail", ticket_id=ticket.id))


@app.route("/tickets/<int:ticket_id>/estado", methods=["POST"])
@login_required
def change_status(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket:
        abort(404)
    new_status = request.form.get("status")
    if new_status not in ESTADOS:
        flash("Estado no válido.", "warning")
        return redirect(url_for("ticket_detail", ticket_id=ticket.id))

    # Permisos: admin/supervisor siempre; técnico solo si está asignado; usuario no puede.
    if current_user.role in ("admin", "supervisor") or (
        current_user.role == "tecnico" and ticket.assigned_to == current_user.id
    ):
        ticket.status = new_status
        db.session.commit()
        flash("Estado actualizado.", "success")
    else:
        abort(403)

    return redirect(url_for("ticket_detail", ticket_id=ticket.id))


@app.route("/tickets/<int:ticket_id>/eliminar", methods=["POST"])
@login_required
@roles_required("admin")
def delete_ticket(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket:
        abort(404)
    db.session.delete(ticket)
    db.session.commit()
    flash("Ticket eliminado.", "success")
    return redirect(url_for("list_tickets"))


# -------------------- Administración --------------------
@app.route("/admin/usuarios", methods=["GET", "POST"])
@login_required
@roles_required("admin")
def manage_users():
    if request.method == "POST":
        user_id = int(request.form.get("user_id"))
        new_role = request.form.get("role")
        if new_role not in ROLES:
            flash("Rol no válido.", "warning")
        else:
            user = db.session.get(User, user_id)
            if user:
                user.role = new_role
                db.session.commit()
                flash("Rol actualizado.", "success")
    users = db.session.execute(db.select(User).order_by(User.name)).scalars().all()
    return render_template("users.html", users=users, ROLES=ROLES)


# -------------------- Helpers --------------------
def _tecnicos():
    return db.session.execute(db.select(User).filter_by(role="tecnico").order_by(User.name)).scalars().all()


def _puede_ver(ticket: Ticket) -> bool:
    if current_user.role in ("admin", "supervisor"):
        return True
    if current_user.role == "tecnico":
        return ticket.assigned_to == current_user.id
    # usuario
    return ticket.created_by == current_user.id


# -------------------- Entrada WSGI --------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
