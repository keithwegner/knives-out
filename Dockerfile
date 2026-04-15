# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS frontend-build

WORKDIR /build/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    KNIVES_OUT_API_DATA_DIR=/var/lib/knives-out \
    KNIVES_OUT_FRONTEND_DIR=/opt/knives-out/frontend/dist

WORKDIR /opt/knives-out

RUN addgroup --system knivesout \
    && adduser --system --ingroup knivesout --home /opt/knives-out knivesout

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --upgrade pip \
    && python -m pip install .

COPY --from=frontend-build /build/frontend/dist /opt/knives-out/frontend/dist

RUN mkdir -p /var/lib/knives-out /opt/knives-out/frontend \
    && chown -R knivesout:knivesout /opt/knives-out /var/lib/knives-out

USER knivesout

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz').read()" || exit 1

CMD ["python", "-m", "uvicorn", "knives_out.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8787"]
