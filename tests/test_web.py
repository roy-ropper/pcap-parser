"""Tests for the Flask web dashboard (web.app), run synchronously via
jobs._run_job() so no background thread / polling is needed."""

import io

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
