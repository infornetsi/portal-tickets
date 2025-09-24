# Portal de Tickets (Flask + PostgreSQL en Render)

Despliegue automático con **Render Blueprints**. Requisitos: cuenta en GitHub y Render.

## Pasos
1. Sube este proyecto a un repositorio de **GitHub**.
2. En **Render → Blueprints → New Blueprint Instance**, elige tu repo y confirma.
3. Introduce `ADMIN_EMAIL` y `ADMIN_PASSWORD` cuando te los pida.
4. Espera a que aparezca **Live** y abre la URL pública.
5. Entra con el usuario admin que definiste y empieza a usarlo.

La base de datos es **PostgreSQL** y la URL se inyecta vía `DATABASE_URL` automáticamente.
