import os

from broom365 import create_app

app = create_app()

if __name__ == "__main__":
    # Debug (auto-reload, interactive debugger) only when explicitly requested: FLASK_DEBUG=1.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
