# syntax=docker/dockerfile:1
# Keep build and runtime on the same current Python/Alpine line.
# Check upstream security updates, rebuild with --pull and rescan before publication.
ARG PYTHON_IMAGE=python:3.12.16-alpine3.24

FROM ${PYTHON_IMAGE} AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
RUN apk upgrade --no-cache \
    && python -m venv /opt/nixfence-venv
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN /opt/nixfence-venv/bin/python -m pip install --no-cache-dir --upgrade pip \
    && /opt/nixfence-venv/bin/python -m pip install --no-cache-dir . \
    && /opt/nixfence-venv/bin/python -m pip uninstall -y pip setuptools wheel

FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/nixfence-venv/bin:$PATH \
    HOME=/home/nixfence
# Do not install openssh-client-krb5: the default OpenSSH client does not
# require the vulnerable krb5 libraries found in Debian's SSH dependencies.
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates openssh-client-default \
    && ! apk info -e krb5-libs \
    && python -m pip uninstall -y pip setuptools wheel \
    && addgroup -S -g 10001 nixfence \
    && adduser -S -D -H -h /home/nixfence -u 10001 -G nixfence nixfence \
    && mkdir -p /data /home/nixfence \
    && chown -R 10001:10001 /data /home/nixfence \
    && chmod 0700 /data /home/nixfence
WORKDIR /app
COPY --from=builder /opt/nixfence-venv /opt/nixfence-venv
COPY --chown=10001:10001 web /app/web
USER 10001:10001
EXPOSE 8080
CMD ["uvicorn", "nixfence.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
