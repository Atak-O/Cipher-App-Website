"""Flask application entry point for CipherLab Web Edition."""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request

from ai_assistant import run_cipher_ai_analysis
from cipher_methods import process_cipher

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cipherlab-local-development-secret")


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/cipher")
def cipher_api():
    payload = request.get_json(silent=True) or {}
    cipher_type = payload.get("cipher")
    mode = payload.get("mode", "encrypt")
    text = payload.get("text", "")
    params = payload.get("params", {})

    if not text.strip():
        return jsonify({"ok": False, "error": "Input text cannot be empty."}), 400
    if mode not in {"encrypt", "decrypt"}:
        return jsonify({"ok": False, "error": "Invalid mode."}), 400

    try:
        result = process_cipher(cipher_type, mode, text, params)
    except (TypeError, ValueError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    return jsonify({"ok": True, "result": result})


@app.post("/api/analyze")
def analyze_api():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    if not text.strip():
        return jsonify({"ok": False, "error": "Encrypted text cannot be empty."}), 400

    results = run_cipher_ai_analysis(text)
    best = results[0] if results else None
    return jsonify({"ok": True, "best": best, "results": results})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(debug=debug, port=port, use_reloader=debug)
