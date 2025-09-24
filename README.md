# Portal de Tickets — v2 (Flask + PostgreSQL + Email)

Incluye:
- `closed_at` (fecha de cierre) con actualización automática al cambiar a *resuelto/cerrado*.
- Notificaciones por email al crear ticket y al cambiar de estado (Flask-Mail).
- Dashboard básico (`/dashboard`) para admin/supervisor.
- Logotipo personalizable en `static/img/logo.png`.
- Normalización de `DATABASE_URL` y *binding* de Gunicorn a `$PORT` para Render.

## Despliegue (Blueprint en Render)

1. Sube este proyecto a un repo de **GitHub**.
2. En **Render → Blueprints → New Blueprint Instance**, elige tu repo.
3. Rellena las variables que te pida (especialmente `ADMIN_EMAIL` y `ADMIN_PASSWORD`). Para email, añade:
   - `MAIL_SERVER` (p. ej. `smtp.gmail.com`)
   - `MAIL_PORT` (`587` si TLS o `465` si SSL)
   - `MAIL_USERNAME`
   - `MAIL_PASSWORD`
   - `MAIL_DEFAULT_SENDER` (opcional, si no igual a `MAIL_USERNAME`)
   - `MAIL_USE_TLS=true` y `MAIL_USE_SSL=false` (o al revés si usas 465)
4. Abre la URL cuando el servicio esté **Live** y entra con el admin.

## Logo
Sustituye `static/img/logo.png` por tu logotipo con el mismo nombre.

## Notas
- Si cambias dependencias, usa **Manual Deploy → Clear build cache & deploy** en Render.
