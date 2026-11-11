FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --system --uid 10001 --no-create-home nixfence
COPY web ./web
USER 10001
EXPOSE 8080
CMD ["uvicorn", "nixfence.api:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
