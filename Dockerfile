# Broom365: one container, Gunicorn, SQL Server through DATABASE_URL (SQLite when it is not set).
#
# The default base is a public Python image; the Microsoft ODBC Driver 18 for SQL Server is installed from Microsoft's
# package repository when the base does not already have it. Building the image therefore accepts Microsoft's licence
# terms for that driver. To start from your own base (it must provide Python 3.11+, the driver and unixODBC):
#   docker build --build-arg BASE_IMAGE=registry.example/python-odbc:latest -t broom365 .
ARG BASE_IMAGE=python:3.11-slim-bookworm
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/app/instance

RUN set -eux; \
    if [ ! -d /opt/microsoft/msodbcsql18 ]; then \
        apt-get update; \
        apt-get install -y --no-install-recommends curl gnupg ca-certificates; \
        curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg; \
        echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
            > /etc/apt/sources.list.d/mssql-release.list; \
        apt-get update; \
        ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 unixodbc; \
        apt-get purge -y --auto-remove curl gnupg; \
        rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY broom365 ./broom365
COPY run.py .

# Sessions and the optional SQLite fallback live in /app/instance; the app runs as an unprivileged user.
RUN useradd --system --no-create-home --uid 10001 broom \
    && mkdir -p /app/instance \
    && chown -R broom /app/instance
USER broom

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=4).status == 200 else 1)"

# One worker: a sync job runs in-process, one at a time. Threads serve the pages while it runs.
ENTRYPOINT []
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "8", "--timeout", "120", "--access-logfile", "-", "broom365:create_app()"]
