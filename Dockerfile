FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 app

# Some build environments install dependencies with restrictive filesystem modes.
# Grant only read/traverse permissions before switching to the unprivileged user.
RUN chmod -R a+rX /usr/local/lib/python3.12/site-packages /usr/local/bin

COPY --chown=app:app server ./server
COPY --chown=app:app web ./web
USER app
# Fail the image build instead of starting a container that immediately restarts.
RUN python -c "import os, uvicorn, fastapi, sqlalchemy, psycopg; assert os.geteuid() == 10001; print('Non-root Python imports OK')"

EXPOSE 8080
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
