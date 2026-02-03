"""WSGI entry point for Gatekeeper."""

import sys

from gatekeeper import create_app

app = create_app()

if __name__ == "__main__":
    dev_mode = "--dev" in sys.argv
    if dev_mode:
        host = app.config["DEV_HOST"]
        port = app.config["DEV_PORT"]
        debug = True
    else:
        host = app.config["HOST"]
        port = app.config["PORT"]
        debug = app.config.get("DEBUG", False)

    app.run(debug=debug, host=host, port=port)
