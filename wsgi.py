"""WSGI entry point for Gatekeeper (gunicorn wsgi:app)."""

from gatekeeper import create_app

app = create_app()
