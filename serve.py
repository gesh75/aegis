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

from flask import Flask, Response, jsonify, request

from aegis.core.orchestrator.pipeline import run_preflight, PreflightError
from aegis.core.backends.simulator import SimulatorBackend
from aegis.evidence.pdf import render_pdf

_UI = os.path.join(os.path.dirname(__file__), "ui", "preflight_screen.html")

app = Flask(__name__)


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
    run = bundle.get("run_id", "bundle")[:12]
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="aegis-evidence-{run}.pdf"'})


def main():
    port = int(os.environ.get("AEGIS_PORT", "8088"))
    print(f"AEGIS community server (sim tier) — http://localhost:{port}/preflight")
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
