"""AEGIS community server — standalone, self-contained, sim-tier.

This is the open-source "demo" entry point: `python -m aegis.serve` (or `docker compose up`)
serves the PreFlight UI and the pipeline in SIMULATOR mode — no LLM, no containerlab, no
external anything. It proves the whole loop (intent/config-import -> verdict -> sealed,
framework-mapped, examiner-ready evidence bundle) on any machine, fully offline.

Live mode (real Qwen3 + containerlab twin) lives in the integrated deployment
(DCN_Network_Tool / the air-gapped product), not in the community core.

    python -m aegis.serve            # then open http://localhost:8088/preflight
    AEGIS_PORT=9000 python -m aegis.serve
"""
from __future__ import annotations
import os
import re

from flask import Flask, Response, jsonify, request

from aegis.core.orchestrator.pipeline import run_preflight, PreflightError
from aegis.core.backends.simulator import SimulatorBackend
from aegis.evidence.pdf import render_pdf

_UI = os.path.join(os.path.dirname(__file__), "ui", "preflight_screen.html")

# Content-Security-Policy shared by the response header and the UI <meta> tag.
# default-src 'self' locks origins down; 'unsafe-inline' is required because the
# PreFlight UI ships inline <style>, inline event handlers and one inline <script>
# (no external assets, no eval). connect-src allows the same-origin API plus the
# localhost fallback the UI uses when opened over http on a dev box.
_CSP = ("default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' http://localhost:5757; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'")

app = Flask(__name__)
# Reject oversized request bodies before they are parsed (sim tier has no auth).
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB


@app.after_request
def _security_headers(resp: Response) -> Response:
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/")
def root():
    return Response('<meta http-equiv="refresh" content="0; url=/preflight">',
                    mimetype="text/html")


@app.get("/preflight")
def ui():
    with open(_UI, encoding="utf-8") as fh:
        return Response(fh.read(), mimetype="text/html")


@app.post("/api/preflight/run")
def preflight_run():
    data = request.get_json(silent=True) or {}
    if (data.get("mode") or "sim") == "live":
        return jsonify({"error": "live mode is not available in the community tier",
                        "stage": "guard", "mode": "live"}), 501

    source = (data.get("source") or "nl_intent").strip()
    imported = None
    if source == "config_import":
        if data.get("configs"):
            imported = data["configs"]
        elif (data.get("config") or "").strip():
            imported = [{"device": data.get("device") or "device-1",
                         "vendor": data.get("vendor") or "frr",
                         "config": data["config"]}]
        else:
            return jsonify({"error": "config_import requires 'config' or 'configs'",
                            "stage": "guard"}), 400
    try:
        bundle = run_preflight(
            (data.get("intent") or "").strip(), backend=SimulatorBackend(),
            lab=(data.get("lab") or "clos-evpn").strip(),
            frameworks=data.get("frameworks") or ["pci_dss_v4"],
            operator=(data.get("operator") or "community").strip(),
            approver=data.get("approver") or None,
            source=source, imported_configs=imported)
    except PreflightError as e:
        return jsonify({"error": str(e), "stage": "guard"}), 400
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"{type(e).__name__}: {e}", "stage": "pipeline"}), 502
    return jsonify(bundle)


@app.post("/api/preflight/evidence/pdf")
def evidence_pdf():
    bundle = request.get_json(silent=True) or {}
    if not bundle.get("integrity", {}).get("sha256"):
        return jsonify({"error": "valid evidence bundle required"}), 400
    try:
        pdf = render_pdf(bundle)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500
    # run_id is client-supplied; sanitize before it lands in the Content-Disposition
    # header. Legit run_ids are uuid4().hex (lowercase hex), so stripping to [a-f0-9]
    # is lossless for them while blocking quote/breakout header-injection abuse.
    run = re.sub(r"[^a-f0-9]", "", str(bundle.get("run_id", "bundle")))[:12] or "bundle"
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="aegis-evidence-{run}.pdf"'})


def main():
    port = int(os.environ.get("AEGIS_PORT", "8088"))
    # Bind loopback by default; require an explicit AEGIS_HOST=0.0.0.0 to expose it.
    host = os.environ.get("AEGIS_HOST", "127.0.0.1")
    print(f"AEGIS community server (sim tier) — http://localhost:{port}/preflight")
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
