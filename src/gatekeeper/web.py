"""Web server entry point for gatekeeper-web."""

import click


@click.command()
@click.option("--host", default=None, help="Bind address (overrides config)")
@click.option("--port", default=None, type=int, help="Port (overrides config)")
@click.option("--workers", default=2, help="Number of gunicorn workers")
@click.option("--dev", is_flag=True, help="Run Flask development server with debug mode")
def main(host: str | None, port: int | None, workers: int, dev: bool):
    """Start the Gatekeeper web server."""
    from gatekeeper import create_app

    app = create_app()

    if dev:
        run_host = host or app.config.get("DEV_HOST", "127.0.0.1")
        run_port = port or app.config.get("DEV_PORT", 5100)
        app.run(debug=True, host=run_host, port=run_port)
    else:
        run_host = host or app.config.get("HOST", "0.0.0.0")
        run_port = port or app.config.get("PORT", 5100)

        import gunicorn.app.base

        class GatekeeperApp(gunicorn.app.base.BaseApplication):
            def load_config(self):
                self.cfg.set("bind", f"{run_host}:{run_port}")
                self.cfg.set("workers", str(workers))
                self.cfg.set("preload_app", True)

            def load(self):
                return app

        GatekeeperApp().run()
