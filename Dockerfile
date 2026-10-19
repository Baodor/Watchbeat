FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Install dependencies into a virtualenv owned by the runtime user.
# This avoids root-owned /usr/local/site-packages permissions breaking Uvicorn.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /home/app --create-home app \
    && python -m venv "$VIRTUAL_ENV" \
    && chown -R app:app "$VIRTUAL_ENV"

COPY --chown=app:app requirements.txt ./
USER app
RUN pip install --no-cache-dir -r requirements.txt \
    && python -c "import uvicorn, fastapi, sqlalchemy, psycopg; print('Dependencies import successfully as the app user')"

COPY --chown=app:app server ./server
COPY --chown=app:app web ./web

EXPOSE 8080
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
