FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install --no-install-recommends -y nmap && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 scanpod
COPY pyproject.toml ./
RUN pip install --no-cache-dir .
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
RUN pip install --no-cache-dir .
USER 10001
CMD ["uvicorn", "scanpod_enterprise.main:app", "--host", "0.0.0.0", "--port", "8080"]
