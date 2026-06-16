"""In-memory job tracking + background pipeline execution for the web dashboard.

JOBS is a plain dict shared across requests: `{job_id: {...}}`. This only
works correctly when the app is run as a *single process* with a shared
in-memory dict — e.g. `gunicorn -w 1 --threads 4`. Multiple worker
*processes* would each have their own JOBS dict and jobs created on one
worker would be invisible to another. If this needs to scale beyond one
process, replace JOBS with a shared store (Redis, a database, etc).
"""

import json
import os
import shutil
import threading
import time
import traceback
import uuid

from pcap_tool.cli import run_pipeline, write_certs_to_dir
from pcap_tool.excel.workbook import generate_xlsx

from .serialize import prepare_result

UPLOAD_DIR = os.environ.get("PCAP_TOOL_UPLOAD_DIR", "/tmp/pcap_tool_uploads")
OUTPUT_DIR = os.environ.get("PCAP_TOOL_OUTPUT_DIR", "/tmp/pcap_tool_outputs")

JOBS = {}
_JOBS_LOCK = threading.Lock()


def _job_json_path(job_id):
    return os.path.join(OUTPUT_DIR, job_id, "job.json")


def _persist_job(job):
    """Write a finished job's record to disk so it survives a process
    restart (the in-memory JOBS dict otherwise loses all jobs, breaking
    download links and the job history page after every restart)."""
    path = _job_json_path(job["id"])
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(job, f)
    except OSError:
        pass


def _load_persisted_jobs():
    """Rehydrate JOBS from job.json files written before a previous restart."""
    if not os.path.isdir(OUTPUT_DIR):
        return
    for job_id in os.listdir(OUTPUT_DIR):
        path = _job_json_path(job_id)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                job = json.load(f)
        except (OSError, ValueError):
            continue
        JOBS.setdefault(job["id"], job)


_load_persisted_jobs()


def create_job(filename):
    job_id = uuid.uuid4().hex
    job = {
        "id": job_id,
        "filename": filename,
        "state": "queued",
        "progress": [],
        "progress_pct": 0,
        "current_stage": "",
        "error": None,
        "result": None,
        "paths": {},
        "created_at": time.time(),
    }
    with _JOBS_LOCK:
        JOBS[job_id] = job
    return job


def get_job(job_id):
    return JOBS.get(job_id)


def _dir_size(path):
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for fn in filenames:
            total += os.path.getsize(os.path.join(dirpath, fn))
    return total


def list_jobs():
    """Return all jobs, newest first, each annotated with on-disk size_bytes."""
    with _JOBS_LOCK:
        snapshot = list(JOBS.values())
    jobs_with_size = []
    for job in sorted(snapshot, key=lambda j: j["created_at"], reverse=True):
        job = dict(job)
        size = _dir_size(os.path.join(UPLOAD_DIR, job["id"])) + _dir_size(os.path.join(OUTPUT_DIR, job["id"]))
        job["size_bytes"] = size
        jobs_with_size.append(job)
    return jobs_with_size


def delete_job(job_id):
    """Remove a job's in-memory record and on-disk upload/output data."""
    with _JOBS_LOCK:
        existed = JOBS.pop(job_id, None) is not None
    shutil.rmtree(os.path.join(UPLOAD_DIR, job_id), ignore_errors=True)
    shutil.rmtree(os.path.join(OUTPUT_DIR, job_id), ignore_errors=True)
    return existed


def start_job(job_id, pcap_path, options):
    """Spawn a background thread running the pipeline for this job."""
    t = threading.Thread(target=_run_job, args=(job_id, pcap_path, options), daemon=True)
    t.start()


def _run_job(job_id, pcap_path, options):
    job = JOBS[job_id]
    job["state"] = "running"

    out_dir = os.path.join(OUTPUT_DIR, job_id)
    os.makedirs(out_dir, exist_ok=True)
    certs_dir = os.path.join(out_dir, "certs")

    def progress_cb(msg, pct=None, stage=None):
        job["progress"].append(msg)
        if pct is not None:
            job["progress_pct"] = pct
            job["current_stage"] = stage

    try:
        result = run_pipeline(
            pcap_path,
            min_packets=options.get("min_packets", 1),
            collapse_external=options.get("collapse_external", False),
            hostname_file=options.get("hostname_file"),
            internal_networks=options.get("internal_networks"),
            title=options.get("title", "Network Diagram"),
            certs_dir=certs_dir,
            progress_cb=progress_cb,
        )

        # Write downloadable artifacts to disk
        xlsx_path = os.path.join(out_dir, "report.xlsx")
        generate_xlsx(result["rows"], result["nodes"], result["edges"], result["findings"],
                       result["cleartext_hits"], result["banner_hits"], result["tls_sessions"],
                       result["dns_events"], result["wifi_data"], xlsx_path,
                       certificates=result["certificates"])

        l3_path = os.path.join(out_dir, "diagram_l3.drawio")
        with open(l3_path, "w", encoding="utf-8") as f:
            f.write(result["drawio_l3_xml"])

        l2_path = os.path.join(out_dir, "diagram_l2.drawio")
        with open(l2_path, "w", encoding="utf-8") as f:
            f.write(result["drawio_l2_xml"])

        vsdx_path = os.path.join(out_dir, "diagram.vsdx")
        with open(vsdx_path, "wb") as f:
            f.write(result["vsdx_bytes"])

        svg_path = os.path.join(out_dir, "topology.svg")
        with open(svg_path, "w", encoding="utf-8") as f:
            f.write(result["topology_svg"])

        job["paths"] = {
            "xlsx": xlsx_path,
            "drawio_l3": l3_path,
            "drawio_l2": l2_path,
            "vsdx": vsdx_path,
            "topology_svg": svg_path,
            "certs_dir": certs_dir if os.path.isdir(certs_dir) else None,
        }

        job["result"] = prepare_result(result)
        job["progress_pct"] = 100
        job["current_stage"] = "Done"
        job["state"] = "done"

    except Exception as e:
        job["error"] = str(e)
        job["progress"].append(f"[!] Error: {e}")
        job["progress"].append(traceback.format_exc())
        job["state"] = "error"

    _persist_job(job)
