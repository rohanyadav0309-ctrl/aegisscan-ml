"""
web_app.py - Web Dashboard Server for AegisScan-ML
Run via: python web_app.py
Access at: http://127.0.0.1:8000
"""
import os
import sys
from flask import Flask, render_template, request, jsonify

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from core.scanner import execute_scan

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "web", "templates")
)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        data = request.get_json(force=True) or {}
        target_url = data.get("url")
        crawl_depth = int(data.get("depth", 2))

        if not target_url:
            return jsonify({"error": "Target URL is required"}), 400

        print(f"[*] Web UI Triggered Scan against: {target_url} (depth={crawl_depth})")
        report = execute_scan(target_url=target_url, crawl_depth=crawl_depth)
        return jsonify(report)
    except Exception as exc:
        print(f"[!] Scan error: {exc}")
        return jsonify({"error": str(exc)}), 500

@app.route("/api/status", methods=["GET"])
def api_status():
    model_exists = os.path.exists(os.path.join(os.path.dirname(__file__), "ml", "model.pkl"))
    return jsonify({
        "status": "online",
        "engine": "AegisScan-ML Hybrid DAST",
        "model_loaded": model_exists
    })

if __name__ == "__main__":
    port = 8000
    print("\n" + "=" * 60)
    print(" 🛡️  AEGISSCAN-ML INTERACTIVE WEB DASHBOARD")
    print(f" 🌐  Dashboard URL: http://127.0.0.1:{port}")
    print("=" * 60 + "\n")
    app.run(host="127.0.0.1", port=port, debug=False)
