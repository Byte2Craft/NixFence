FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && groupadd --gid 10001 nixfence \
    && useradd --system --uid 10001 --gid 10001 --no-create-home nixfence \
    && install -d -o 10001 -g 10001 -m 0700 /data
COPY web ./web
RUN chmod -R a+rX /app/web
USER 10001:10001
EXPOSE 8080
CMD ["uvicorn", "nixfence.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
