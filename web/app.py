"""Flask web dashboard — upload a pcap, watch progress, browse/download results."""

import datetime
import io
import json
import os
import zipfile

from flask import (
    Flask, abort, jsonify, redirect, render_template, request,
    send_file, url_for,
)
from werkzeug.utils import secure_filename

from pcap_tool.demo.scenario import build_demo_pcap, build_demo_wifi_pcap

from . import jobs
from .jobs import UPLOAD_DIR, OUTPUT_DIR

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_UPLOAD_MB = int(os.environ.get("PCAP_TOOL_MAX_UPLOAD_MB", "500"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)


@app.template_filter("datetimeformat")
def datetimeformat(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


@app.route("/")
def index():
    return render_template("upload.html")


@app.route("/demo.pcap")
def demo_pcap():
    return send_file(io.BytesIO(build_demo_pcap()), as_attachment=True,
                      download_name="demo.pcap", mimetype="application/vnd.tcpdump.pcap")


@app.route("/demo_wifi.pcapng")
def demo_wifi_pcap():
    return send_file(io.BytesIO(build_demo_wifi_pcap()), as_attachment=True,
                      download_name="demo_wifi.pcapng", mimetype="application/x-pcapng")


@app.route("/jobs")
def jobs_list():
    return render_template("jobs_list.html", jobs=jobs.list_jobs())


@app.route("/jobs/<job_id>/delete", methods=["POST"])
def job_delete(job_id):
    jobs.delete_job(job_id)
    return redirect(url_for("jobs_list"))


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("pcap")
    if not f or not f.filename:
        return render_template("upload.html", error="Please choose a .pcap/.pcapng file."), 400

    filename = secure_filename(f.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return render_template(
            "upload.html",
            error=f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        ), 400

    job = jobs.create_job(filename)
    job_dir = os.path.join(UPLOAD_DIR, job["id"])
    os.makedirs(job_dir, exist_ok=True)
    pcap_path = os.path.join(job_dir, filename)
    f.save(pcap_path)

    internal_networks = request.form.get("internal_networks", "").split()

    options = {
        "min_packets": int(request.form.get("min_packets") or 1),
        "collapse_external": bool(request.form.get("collapse_external")),
        "title": request.form.get("title") or "Network Diagram",
        "internal_networks": internal_networks or None,
        "hostname_file": None,
    }

    hf = request.files.get("hostname_file")
    if hf and hf.filename:
        hf_path = os.path.join(job_dir, secure_filename(hf.filename))
        hf.save(hf_path)
        options["hostname_file"] = hf_path

    jobs.start_job(job["id"], pcap_path, options)
    return redirect(url_for("job_status_page", job_id=job["id"]))


@app.route("/jobs/<job_id>")
def job_status_page(job_id):
    job = jobs.get_job(job_id)
    if not job:
        abort(404)
    if job["state"] == "done":
        return redirect(url_for("job_results", job_id=job_id))
    return render_template("status.html", job=job)


@app.route("/jobs/<job_id>/status")
def job_status(job_id):
    job = jobs.get_job(job_id)
    if not job:
        abort(404)
    resp = jsonify({
        "state": job["state"],
        "progress": job["progress"],
        "progress_pct": job["progress_pct"],
        "current_stage": job["current_stage"],
        "error": job["error"],
        "done": job["state"] in ("done", "error"),
    })
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/jobs/<job_id>/results")
def job_results(job_id):
    job = jobs.get_job(job_id)
    if not job:
        abort(404)
    if job["state"] != "done":
        return redirect(url_for("job_status_page", job_id=job_id))
    return render_template("results.html", job=job, result=job["result"])


_ARTIFACTS = {
    "xlsx":      ("report.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "drawio_l3": ("diagram_l3.drawio", "application/xml"),
    "drawio_l2": ("diagram_l2.drawio", "application/xml"),
    "vsdx":      ("diagram.vsdx", "application/vnd.ms-visio.drawing"),
}


@app.route("/jobs/<job_id>/download/<artifact>")
def job_download(job_id, artifact):
    job = jobs.get_job(job_id)
    if not job or job["state"] != "done":
        abort(404)
    if artifact not in _ARTIFACTS:
        abort(404)
    download_name, mimetype = _ARTIFACTS[artifact]
    path = job["paths"].get(artifact)
    if not path or not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=download_name, mimetype=mimetype)


@app.route("/jobs/<job_id>/download/cert/<fingerprint>")
def job_download_cert(job_id, fingerprint):
    job = jobs.get_job(job_id)
    if not job or job["state"] != "done":
        abort(404)
    certs_dir = job["paths"].get("certs_dir")
    if not certs_dir or not os.path.isdir(certs_dir):
        abort(404)
    fp8 = fingerprint[:8]
    for fn in os.listdir(certs_dir):
        if fp8 in fn and fn.endswith(".pem"):
            return send_file(os.path.join(certs_dir, fn), as_attachment=True, download_name=fn,
                              mimetype="application/x-pem-file")
    abort(404)


@app.route("/jobs/<job_id>/download/certs.zip")
def job_download_certs_zip(job_id):
    job = jobs.get_job(job_id)
    if not job or job["state"] != "done":
        abort(404)
    certs_dir = job["paths"].get("certs_dir")
    if not certs_dir or not os.path.isdir(certs_dir):
        abort(404)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fn in sorted(os.listdir(certs_dir)):
            zf.write(os.path.join(certs_dir, fn), arcname=fn)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="certs.zip", mimetype="application/zip")


@app.route("/jobs/<job_id>/download/all.zip")
def job_download_all_zip(job_id):
    job = jobs.get_job(job_id)
    if not job or job["state"] != "done":
        abort(404)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for key, arcname in (("xlsx", "report.xlsx"),
                              ("drawio_l3", "diagram_l3.drawio"),
                              ("drawio_l2", "diagram_l2.drawio"),
                              ("vsdx", "diagram.vsdx")):
            p = job["paths"].get(key)
            if p and os.path.isfile(p):
                zf.write(p, arcname=arcname)
        certs_dir = job["paths"].get("certs_dir")
        if certs_dir and os.path.isdir(certs_dir):
            for fn in sorted(os.listdir(certs_dir)):
                zf.write(os.path.join(certs_dir, fn), arcname=f"certs/{fn}")
        zf.writestr("findings.json", json.dumps(job["result"]["findings"], indent=2))
    buf.seek(0)
    return send_file(buf, as_attachment=True,
                      download_name=f"{job_id}_bundle.zip", mimetype="application/zip")


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=8000)
