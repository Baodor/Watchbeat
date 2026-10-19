FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 app

# Some build environments install dependencies with restrictive filesystem modes.
# Grant only read/traverse permissions before switching to the unprivileged user.
RUN chmod -R a+rX /usr/local/lib/python3.12/site-packages /usr/local/bin

COPY --chown=app:app server /app/server
COPY --chown=app:app web /app/web

# Make the application root and package traversable/readable for the non-root user.
# Keep the source package importable independently of the launcher working directory.
RUN chown app:app /app && chmod 755 /app && chmod -R a+rX /app/server /app/web
USER app
# Catch missing app modules and broken imports before the image is deployed.
RUN python -c "import os; from server.main import app; assert os.geteuid() == 10001; print('Watchbeat application import OK')"

EXPOSE 8080
CMD ["python", "-m", "uvicorn", "server.main:app", "--app-dir", "/app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
