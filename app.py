"""Intentionally vulnerable cmd-injection target for mordred RCE-chain validation.

DO NOT deploy outside an ephemeral sandbox. The /ping endpoint passes the
`host` query parameter into a shell unsanitized — a textbook OS command
injection (CWE-78). mordred's apifuzz emits a cmd_injection_probe when its
`; echo MORDRED-CMD-<x>` canary reflects, the nuclei DAST cmdi prove pass
confirms it, and the HTTPRCEVector post-exploit runs recon (id/env/passwd).
"""
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.get("/openapi.json")
def openapi():
    # Advertised so mordred's apifuzz discovers /ping + its `host` param.
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "cmdi-target", "version": "1.0.0"},
        "paths": {
            "/ping": {
                "get": {
                    "parameters": [{
                        "name": "host", "in": "query", "required": True,
                        "schema": {"type": "string", "example": "127.0.0.1"},
                    }],
                    "responses": {"200": {"description": "ping output"}},
                }
            },
            "/echo": {
                "get": {
                    "parameters": [{
                        "name": "msg", "in": "query", "required": True,
                        "schema": {"type": "string", "example": "hello"},
                    }],
                    "responses": {"200": {"description": "echoed html"}},
                }
            },
        },
    })


@app.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE BY DESIGN: unsanitized shell interpolation.
    out = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=15
    )
    return (out.stdout or "") + (out.stderr or ""), 200, {"Content-Type": "text/plain"}


@app.get("/echo")
def echo():
    # VULNERABLE BY DESIGN: reflects `msg` into HTML unescaped — a textbook
    # server-side reflected XSS (CWE-79) that nuclei's DAST xss templates
    # confirm (no headless browser needed, unlike DOM XSS).
    msg = request.args.get("msg", "hi")
    return f"<html><body><div>{msg}</div></body></html>", 200, {"Content-Type": "text/html"}


@app.get("/")
def index():
    return '<a href="/ping?host=127.0.0.1">ping</a> · <a href="/openapi.json">openapi</a>', 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
