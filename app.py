import identity
import identity.web
import requests
from flask import Flask, redirect, render_template, request, session, url_for
from flask_session import Session

import base64
import json

import app_config

app = Flask(__name__)
app.config.from_object(app_config)
Session(app)

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy.
# See also https://flask.palletsprojects.com/en/2.2.x/deploying/proxy_fix/
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

auth = identity.web.Auth(
    session=session,
    authority=app.config.get("AUTHORITY"),
    client_id=app.config["CLIENT_ID"],
    client_credential=app.config["CLIENT_SECRET"],
)


@app.route("/login")
def login():
    redirect_url = url_for("auth_response", _external=True)
    if(app.config.get("REDIRECT_ROOT_URL") is not None):
        redirect_url = f"{app.config.get('REDIRECT_ROOT_URL').strip('/')}/{app.config.get('REDIRECT_PATH').strip('/')}"
    print(auth.log_in(
        scopes=app_config.SCOPE, # Have user consent to scopes during log-in
        redirect_uri=redirect_url, # Optional. If present, this absolute URL must match your app's redirect_uri registered in Azure Portal
    ))
    return render_template("login.html", version=identity.__version__, **auth.log_in(
        scopes=app_config.SCOPE, # Have user consent to scopes during log-in
        redirect_uri=redirect_url, # Optional. If present, this absolute URL must match your app's redirect_uri registered in Azure Portal
        ))


@app.route(app_config.REDIRECT_PATH)
def auth_response():

    token = auth.get_token_for_user(app_config.SCOPE)
    token_parts = token['access_token'].split('.')
    decoded_payload = base64.urlsafe_b64decode(token_parts[1] + '==')
    parsed_payload = json.loads(decoded_payload)

    result = auth.complete_log_in(request.args)
    if "error" in result:
        return render_template("auth_error.html", result=result)
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    return redirect(auth.log_out(url_for("index", _external=True)))


@app.route("/")
def index():
    if not (app.config["CLIENT_ID"] and app.config["CLIENT_SECRET"]):
        # This check is not strictly necessary.
        # You can remove this check from your production code.
        return render_template('config_error.html')
    if not auth.get_user():
        return redirect(url_for("login"))
    return render_template('index.html', user=auth.get_user(), version=identity.__version__)


@app.route("/call_downstream_api")
def call_downstream_api():
    token = auth.get_token_for_user(app_config.SCOPE)
    if "error" in token:
        return redirect(url_for("login"))
    # Use access token to call downstream api
    api_result = requests.get(
        app_config.ENDPOINT,
        headers={'Authorization': 'Bearer ' + token['access_token']},
        timeout=30,
    ).json()

    print(f"Authorization: Bearer {token['access_token']}")

    # Decode the JWT token
    token_parts = token['access_token'].split('.')
    decoded_payload = base64.urlsafe_b64decode(token_parts[1] + '==')
    parsed_payload = json.loads(decoded_payload)

    # Pretty print the JSON
    # pretty_json = json.dumps(parsed_payload, indent=4)
    # print(pretty_json)

    return render_template('display.html', result=parsed_payload)


if __name__ == "__main__":
    app.run(port=5173, ssl_context=('ssl/cert.crt', 'ssl/key.key'))
