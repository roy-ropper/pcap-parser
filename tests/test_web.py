"""Tests for the Flask web dashboard (web.app), run synchronously via
jobs._run_job() so no background thread / polling is needed."""

import io
import json
import os
import zipfile

import pytest

from web import jobs
from web.app import app
from web.jobs import _run_job

from .conftest import eth_ip_tcp, write_pcap


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


def _make_pcap(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 80, b"GET / HTTP/1.1\r\n\r\n")
    return write_pcap(tmp_path / "web.pcap", [frame])


def _run_to_completion(tmp_path, pcap_path):
    job = jobs.create_job("web.pcap")
    options = {"min_packets": 1, "collapse_external": False, "title": "Test", "internal_networks": None, "hostname_file": None}
    _run_job(job["id"], pcap_path, options)
    assert job["state"] == "done", job.get("error")
    return job


def test_upload_page(client):
    resp = client.get("/")
    assert resp.status_code == 200


def test_missing_job_404(client):
    assert client.get("/jobs/doesnotexist").status_code == 404
    assert client.get("/jobs/doesnotexist/status").status_code == 404
    assert client.get("/jobs/doesnotexist/results").status_code == 404


def test_bad_extension_upload(client):
    data = {"pcap": (io.BytesIO(b"not a pcap"), "evil.exe")}
    resp = client.post("/upload", data=data, content_type="multipart/form-data")
    assert resp.status_code == 400


def test_full_pipeline_and_downloads(tmp_path, client):
    pcap_path = _make_pcap(tmp_path)
    job = _run_to_completion(tmp_path, pcap_path)
    job_id = job["id"]

    resp = client.get(f"/jobs/{job_id}/results")
    assert resp.status_code == 200

    status = client.get(f"/jobs/{job_id}/status")
    assert status.status_code == 200
    assert status.get_json()["state"] == "done"

    for artifact in ("xlsx", "drawio_l3", "drawio_l2", "vsdx"):
        resp = client.get(f"/jobs/{job_id}/download/{artifact}")
        assert resp.status_code == 200, artifact
        assert len(resp.data) > 0


def test_job_persists_across_restart(tmp_path, client):
    pcap_path = _make_pcap(tmp_path)
    job = _run_to_completion(tmp_path, pcap_path)
    job_id = job["id"]

    # Simulate the in-memory JOBS dict being wiped by a process restart, then
    # reloaded from the job.json written on completion.
    jobs.JOBS.pop(job_id)
    jobs._load_persisted_jobs()

    assert jobs.get_job(job_id) is not None

    resp = client.get(f"/jobs/{job_id}/results")
    assert resp.status_code == 200

    resp = client.get(f"/jobs/{job_id}/download/xlsx")
    assert resp.status_code == 200
    assert len(resp.data) > 0


def test_demo_pcap_download(client):
    resp = client.get("/demo.pcap")
    assert resp.status_code == 200
    assert resp.mimetype == "application/vnd.tcpdump.pcap"
    assert len(resp.data) > 0


def test_demo_wifi_pcap_download(client):
    resp = client.get("/demo_wifi.pcapng")
    assert resp.status_code == 200
    assert resp.mimetype == "application/x-pcapng"
    assert len(resp.data) > 0


def test_jobs_list_page(tmp_path, client):
    pcap_path = _make_pcap(tmp_path)
    job = _run_to_completion(tmp_path, pcap_path)

    resp = client.get("/jobs")
    assert resp.status_code == 200
    assert job["filename"].encode() in resp.data


def test_job_delete_removes_data(tmp_path, client):
    pcap_path = _make_pcap(tmp_path)
    job = _run_to_completion(tmp_path, pcap_path)
    job_id = job["id"]

    output_dir = os.path.join(jobs.OUTPUT_DIR, job_id)
    assert os.path.isdir(output_dir)

    resp = client.post(f"/jobs/{job_id}/delete")
    assert resp.status_code == 302

    assert jobs.get_job(job_id) is None
    assert not os.path.exists(output_dir)

    resp = client.get("/jobs")
    assert job_id.encode() not in resp.data


def test_topology_svg_preview(tmp_path, client):
    pcap_path = _make_pcap(tmp_path)
    job = _run_to_completion(tmp_path, pcap_path)
    resp = client.get(f"/jobs/{job['id']}/preview/topology.svg")
    assert resp.status_code == 200
    assert resp.mimetype == "image/svg+xml"
    assert b"<svg" in resp.data or resp.data.startswith(b"<?xml")


def test_topology_svg_preview_not_done(client):
    job = jobs.create_job("pending.pcap")
    resp = client.get(f"/jobs/{job['id']}/preview/topology.svg")
    assert resp.status_code == 404


def test_download_all_zip(tmp_path, client):
    pcap_path = _make_pcap(tmp_path)
    job = _run_to_completion(tmp_path, pcap_path)
    job_id = job["id"]

    resp = client.get(f"/jobs/{job_id}/download/all.zip")
    assert resp.status_code == 200
    assert resp.mimetype == "application/zip"

    with zipfile.ZipFile(io.BytesIO(resp.data)) as zf:
        names = set(zf.namelist())
        for expected in ("report.xlsx", "diagram_l3.drawio", "diagram_l2.drawio",
                          "diagram.vsdx", "findings.json"):
            assert expected in names, expected
        findings = json.loads(zf.read("findings.json"))
        assert isinstance(findings, list)
