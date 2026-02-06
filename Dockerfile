FROM python:3.14-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install uv

WORKDIR /app

COPY pyproject.toml pyproject-client.toml ./
COPY src/ src/
COPY database/ database/
COPY wsgi.py Makefile ./

RUN uv pip install --system -e . --extra dev

EXPOSE 5100

ENV GATEKEEPER_DB=/data/gatekeeper.sqlite3

CMD ["gatekeeper-web", "--host", "0.0.0.0", "--port", "5100"]
