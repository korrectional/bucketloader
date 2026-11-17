import io
import json
import os
import stat
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from googleapiclient.errors import HttpError
from httplib2 import Response

# Set test environment variable for API key
TEST_API_KEY = "test-secret-bucket-key-12345"
os.environ["BUCKET_API_KEY"] = TEST_API_KEY

from main import app, get_drive_client, save_oauth_state, _oauth_states
from drive_client import DriveClient, DriveError


@pytest.fixture
def mock_drive_client():
    client = DriveClient()
    mock_service = MagicMock()
    client.set_service(mock_service, bucket_folder_id="bucket_folder_test_id")
    return client


@pytest.fixture
def client(mock_drive_client):
    app.dependency_overrides[get_drive_client] = lambda: mock_drive_client
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ============================================================================
# API KEY AUTHENTICATION & REJECTION TESTS
# ============================================================================

def test_health_public(client):
    """GET /health must not require authentication."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["drive_authenticated"] is True
    assert data["bucket_folder_id"] == "bucket_folder_test_id"
    assert "has_credentials" in data


def test_auth_missing_key(client):
    """Endpoints require API key."""
    resp = client.get("/files")
    assert resp.status_code == 401
    assert "Invalid or missing API key" in resp.json()["detail"]


def test_auth_invalid_key(client):
    resp = client.get("/files", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401


def test_auth_header_x_api_key(client, mock_drive_client):
    mock_drive_client.list_files = MagicMock(return_value=[])
    resp = client.get("/files", headers={"X-API-Key": TEST_API_KEY})
    assert resp.status_code == 200


def test_auth_header_bearer(client, mock_drive_client):
    mock_drive_client.list_files = MagicMock(return_value=[])
    resp = client.get("/files", headers={"Authorization": f"Bearer {TEST_API_KEY}"})
    assert resp.status_code == 200


def test_auth_query_param(client, mock_drive_client):
    mock_drive_client.list_files = MagicMock(return_value=[])
    resp = client.get(f"/files?api_key={TEST_API_KEY}")
    assert resp.status_code == 200


def test_api_key_rejection_all_endpoints(client, mock_drive_client):
    """Verifies that all protected endpoints reject missing or invalid API keys."""
    protected_endpoints = [
        ("GET", "/"),
        ("POST", "/auth/credentials"),
        ("GET", "/auth/url"),
        ("POST", "/upload"),
        ("GET", "/files"),
        ("DELETE", "/files/dummy_file_id"),
    ]
    for method, path in protected_endpoints:
        # Without any key
        resp_missing = client.request(method, path)
        assert resp_missing.status_code == 401, f"{method} {path} must return 401 without API key"
        # With invalid key
        resp_invalid = client.request(method, path, headers={"X-API-Key": "invalid-secret-key"})
        assert resp_invalid.status_code == 401, f"{method} {path} must return 401 with invalid API key"

    # Public unauthenticated endpoints must NOT return 401
    resp_health = client.get("/health")
    assert resp_health.status_code == 200

    resp_callback = client.get("/auth/callback")
    # Returns 400 due to missing parameters, NOT 401 Unauthorized
    assert resp_callback.status_code == 400

    # Public file viewing and raw streaming endpoints must NOT return 401
    mock_drive_client.get_file_metadata = MagicMock(side_effect=FileNotFoundError("Not found"))
    mock_drive_client.get_latest_file_by_name = MagicMock(side_effect=FileNotFoundError("Not found"))

    resp_file = client.get("/files/dummy_file_id")
    assert resp_file.status_code == 404

    resp_raw = client.get("/raw/dummy_file.txt")
    assert resp_raw.status_code == 404


def test_health_unauthenticated_drive(client):
    """GET /health when Drive is not authenticated should return drive_authenticated=false."""
    unauth_client = DriveClient()
    unauth_client.set_service(None)
    app.dependency_overrides[get_drive_client] = lambda: unauth_client

    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["drive_authenticated"] is False
    assert data["bucket_folder_id"] is None
    assert data["auth_url_endpoint"] == "/auth/url"


def test_health_has_credentials(client, tmp_path, monkeypatch):
    """GET /health correctly reflects whether valid credentials exist."""
    creds_file = tmp_path / "credentials.json"
    monkeypatch.setenv("GOOGLE_CREDENTIALS_FILE", str(creds_file))

    # File does not exist yet
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["has_credentials"] is False

    # Write valid credentials
    creds_file.write_text(json.dumps({"web": {"client_id": "test_id"}}))
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["has_credentials"] is True


def test_endpoints_when_drive_unauthenticated(client):
    """Protected endpoints should return 503 if drive is unauthenticated."""
    unauth_client = DriveClient()
    unauth_client.set_service(None)
    app.dependency_overrides[get_drive_client] = lambda: unauth_client

    resp = client.get("/files", headers={"X-API-Key": TEST_API_KEY})
    assert resp.status_code == 503
    assert "Google Drive not authenticated" in resp.json()["detail"]


# ============================================================================
# OAUTH & CREDENTIALS ENDPOINTS TESTS
# ============================================================================

def test_auth_credentials_json_web(client, tmp_path, monkeypatch):
    creds_file = tmp_path / "credentials.json"
    monkeypatch.setenv("GOOGLE_CREDENTIALS_FILE", str(creds_file))

    payload = {
        "web": {
            "client_id": "test-web-client-id",
            "client_secret": "test-web-client-secret",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["https://kanevskyy.dev/bucket/auth/callback"],
        }
    }
    resp = client.post(
        "/auth/credentials",
        json=payload,
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["client_type"] == "web"
    assert creds_file.exists()
    assert stat.S_IMODE(os.stat(creds_file).st_mode) == 0o600
    saved = json.loads(creds_file.read_text())
    assert saved["web"]["client_id"] == "test-web-client-id"


def test_auth_credentials_json_installed(client, tmp_path, monkeypatch):
    creds_file = tmp_path / "credentials.json"
    monkeypatch.setenv("GOOGLE_CREDENTIALS_FILE", str(creds_file))

    payload = {
        "installed": {
            "client_id": "test-installed-client-id",
            "client_secret": "test-installed-client-secret",
        }
    }
    resp = client.post(
        "/auth/credentials",
        json=payload,
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["client_type"] == "installed"
    assert creds_file.exists()
    assert stat.S_IMODE(os.stat(creds_file).st_mode) == 0o600


def test_auth_credentials_multipart_upload(client, tmp_path, monkeypatch):
    creds_file = tmp_path / "credentials.json"
    monkeypatch.setenv("GOOGLE_CREDENTIALS_FILE", str(creds_file))

    payload = {
        "web": {
            "client_id": "multipart-client-id",
            "client_secret": "multipart-secret",
        }
    }
    file_bytes = json.dumps(payload).encode("utf-8")
    files = {"file": ("client_secret.json", file_bytes, "application/json")}
    resp = client.post(
        "/auth/credentials",
        files=files,
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["client_type"] == "web"
    assert creds_file.exists()
    assert stat.S_IMODE(os.stat(creds_file).st_mode) == 0o600
    assert json.loads(creds_file.read_text())["web"]["client_id"] == "multipart-client-id"


def test_auth_credentials_validation_errors(client, tmp_path, monkeypatch):
    creds_file = tmp_path / "credentials.json"
    monkeypatch.setenv("GOOGLE_CREDENTIALS_FILE", str(creds_file))

    # Missing top-level 'web' or 'installed' key
    resp = client.post(
        "/auth/credentials",
        json={"other_key": {"client_id": "test"}},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 400
    assert "must contain top-level 'web' or 'installed' key" in resp.json()["detail"]

    # Invalid JSON string
    resp = client.post(
        "/auth/credentials",
        content="not valid json payload",
        headers={"X-API-Key": TEST_API_KEY, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400

    # Multipart without file
    resp = client.post(
        "/auth/credentials",
        data={"some_text": "non_file"},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 400


def test_auth_url_missing_credentials(client, tmp_path, monkeypatch):
    monkeypatch.setenv("GOOGLE_CREDENTIALS_FILE", str(tmp_path / "missing_creds.json"))
    resp = client.get("/auth/url", headers={"X-API-Key": TEST_API_KEY})
    assert resp.status_code == 400
    assert "credentials file not found" in resp.json()["detail"].lower()


def test_auth_url_success(client, tmp_path, monkeypatch):
    creds_file = tmp_path / "credentials.json"
    creds_file.write_text(json.dumps({"web": {"client_id": "test_id"}}))
    state_file = tmp_path / "oauth_state.json"

    monkeypatch.setenv("GOOGLE_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setattr("main.OAUTH_STATE_FILE", str(state_file))
    redirect_uri = "https://kanevskyy.dev/bucket/auth/callback"
    monkeypatch.setenv("OAUTH_REDIRECT_URI", redirect_uri)

    mock_flow = MagicMock()
    mock_flow.authorization_url.return_value = (
        "https://accounts.google.com/o/oauth2/auth?client_id=test_id",
        "mock_generated_state",
    )
    mock_flow.code_verifier = "mock_verifier_xyz"

    with patch("main.Flow.from_client_secrets_file", return_value=mock_flow) as mock_builder:
        resp = client.get("/auth/url", headers={"X-API-Key": TEST_API_KEY})
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_url"] == "https://accounts.google.com/o/oauth2/auth?client_id=test_id"
        assert data["redirect_uri"] == redirect_uri

        mock_builder.assert_called_once_with(
            str(creds_file),
            scopes=["https://www.googleapis.com/auth/drive"],
            redirect_uri=redirect_uri,
        )
        assert state_file.exists()
        assert stat.S_IMODE(os.stat(state_file).st_mode) == 0o600
        persisted = json.loads(state_file.read_text())
        assert "mock_generated_state" in persisted
        assert persisted["mock_generated_state"]["code_verifier"] == "mock_verifier_xyz"


def test_auth_callback_missing_and_invalid_params(client):
    # Public endpoint without API key
    resp = client.get("/auth/callback")
    assert resp.status_code == 400
    assert "Missing required authorization parameter 'code'" in resp.json()["detail"]

    resp = client.get("/auth/callback?code=some_code")
    assert resp.status_code == 400
    assert "Missing required OAuth state parameter 'state'" in resp.json()["detail"]

    resp = client.get("/auth/callback?error=access_denied")
    assert resp.status_code == 400
    assert "access_denied" in resp.json()["detail"]

    resp = client.get("/auth/callback?code=some_code&state=nonexistent_state")
    assert resp.status_code == 400
    assert "Invalid or expired OAuth state parameter" in resp.json()["detail"]


def test_auth_callback_success_json(client, tmp_path, monkeypatch, mock_drive_client):
    creds_file = tmp_path / "credentials.json"
    creds_file.write_text(json.dumps({"web": {"client_id": "test_id"}}))
    token_file = tmp_path / "token.json"
    state_file = tmp_path / "oauth_state.json"

    monkeypatch.setenv("GOOGLE_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setenv("GOOGLE_TOKEN_FILE", str(token_file))
    monkeypatch.setattr("main.OAUTH_STATE_FILE", str(state_file))

    # Persist valid state
    save_oauth_state({
        "state": "test_state_callback",
        "code_verifier": "test_code_verifier",
        "created_at": 12345,
    })

    mock_flow = MagicMock()
    mock_creds = MagicMock()
    mock_creds.to_json.return_value = '{"token": "test_token_abc", "refresh_token": "test_refresh_def"}'
    mock_flow.credentials = mock_creds

    mock_drive_client.reload = MagicMock(return_value="discovered_bucket_folder_id")
    mock_drive_client.get_bucket_folder_id = MagicMock(return_value="discovered_bucket_folder_id")

    with patch("main.Flow.from_client_secrets_file", return_value=mock_flow):
        resp = client.get("/auth/callback?code=test_auth_code_123&state=test_state_callback")
        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is True
        assert data["bucket_folder_id"] == "discovered_bucket_folder_id"

        mock_flow.fetch_token.assert_called_once_with(code="test_auth_code_123")
        assert token_file.exists()
        assert stat.S_IMODE(os.stat(token_file).st_mode) == 0o600
        saved_token = json.loads(token_file.read_text())
        assert saved_token["token"] == "test_token_abc"
        mock_drive_client.reload.assert_called_once()


def test_auth_callback_success_html(client, tmp_path, monkeypatch, mock_drive_client):
    creds_file = tmp_path / "credentials.json"
    creds_file.write_text(json.dumps({"web": {"client_id": "test_id"}}))
    token_file = tmp_path / "token.json"
    state_file = tmp_path / "oauth_state.json"

    monkeypatch.setenv("GOOGLE_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setenv("GOOGLE_TOKEN_FILE", str(token_file))
    monkeypatch.setattr("main.OAUTH_STATE_FILE", str(state_file))

    save_oauth_state({
        "state": "html_test_state",
        "code_verifier": "html_verifier",
        "created_at": 12345,
    })

    mock_flow = MagicMock()
    mock_creds = MagicMock()
    mock_creds.to_json.return_value = '{"token": "html_token"}'
    mock_flow.credentials = mock_creds

    mock_drive_client.reload = MagicMock(return_value="html_bucket_folder_id")
    mock_drive_client.get_bucket_folder_id = MagicMock(return_value="html_bucket_folder_id")

    with patch("main.Flow.from_client_secrets_file", return_value=mock_flow):
        resp = client.get(
            "/auth/callback?code=html_code_123&state=html_test_state",
            headers={"Accept": "text/html,application/xhtml+xml"},
        )
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "authenticated: true" in resp.text.lower()
        assert "html_bucket_folder_id" in resp.text


# ============================================================================
# UPLOAD TESTS
# ============================================================================

def test_upload_file(client, mock_drive_client):
    expected_meta = {
        "id": "file_123",
        "name": "sample.txt",
        "size": 18,
        "mimeType": "text/plain",
        "createdTime": "2026-11-17T02:00:00Z",
        "modifiedTime": "2026-11-17T02:00:00Z",
        "path": "/files/file_123",
        "files_path": "/files/file_123",
        "raw_path": "/raw/sample.txt",
        "url": "/files/file_123",
        "raw_url": "/raw/sample.txt",
    }
    mock_drive_client.upload_file = MagicMock(return_value=expected_meta)

    files = {"file": ("sample.txt", b"Hello from upload!", "text/plain")}
    resp = client.post(
        "/upload",
        files=files,
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "file_123"
    assert data["name"] == "sample.txt"
    assert data["path"] == "/files/file_123"
    assert data["raw_path"] == "/raw/sample.txt"

    mock_drive_client.upload_file.assert_called_once()
    call_kwargs = mock_drive_client.upload_file.call_args[1]
    assert call_kwargs["filename"] == "sample.txt"
    assert call_kwargs["overwrite"] is False


def test_upload_file_with_overwrite(client, mock_drive_client):
    expected_meta = {
        "id": "file_replaced",
        "name": "replaced.png",
        "size": 100,
        "mimeType": "image/png",
        "createdTime": "2026-11-17T02:00:00Z",
        "modifiedTime": "2026-11-17T02:00:00Z",
        "path": "/files/file_replaced",
        "files_path": "/files/file_replaced",
        "raw_path": "/raw/replaced.png",
        "url": "/files/file_replaced",
        "raw_url": "/raw/replaced.png",
    }
    mock_drive_client.upload_file = MagicMock(return_value=expected_meta)

    files = {"file": ("replaced.png", b"fake-png-bytes", "image/png")}
    data_form = {"overwrite": "true"}
    resp = client.post(
        "/upload",
        files=files,
        data=data_form,
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == "file_replaced"


def test_upload_file_subfolder(client, mock_drive_client):
    expected_meta = {
        "id": "file_sub",
        "name": "anim.mp4",
        "subfolder": "renders",
        "path": "/files/file_sub",
        "url": "/files/file_sub",
        "raw_path": "/raw/renders/anim.mp4",
        "raw_url": "/raw/renders/anim.mp4",
    }
    mock_drive_client.upload_file = MagicMock(return_value=expected_meta)

    files = {"file": ("anim.mp4", b"fake-mp4-data", "video/mp4")}
    data_form = {"subfolder": "renders"}
    resp = client.post(
        "/upload",
        files=files,
        data=data_form,
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 200
    assert resp.json()["subfolder"] == "renders"
    assert resp.json()["raw_path"] == "/raw/renders/anim.mp4"
    mock_drive_client.upload_file.assert_called_once()
    call_kwargs = mock_drive_client.upload_file.call_args[1]
    assert call_kwargs["filename"] == "anim.mp4"
    assert call_kwargs["subfolder"] == "renders"


# ============================================================================
# LIST FILES TESTS
# ============================================================================

def test_list_files(client, mock_drive_client):
    fake_files = [
        {
            "id": "id1",
            "name": "first.txt",
            "size": 50,
            "mimeType": "text/plain",
            "createdTime": "2026-11-17T01:00:00Z",
            "modifiedTime": "2026-11-17T01:00:00Z",
            "path": "/files/id1",
            "files_path": "/files/id1",
            "raw_path": "/raw/first.txt",
            "url": "/files/id1",
            "raw_url": "/raw/first.txt",
        },
        {
            "id": "id2",
            "name": "second.pdf",
            "size": 1024,
            "mimeType": "application/pdf",
            "createdTime": "2026-11-17T02:00:00Z",
            "modifiedTime": "2026-11-17T02:00:00Z",
            "path": "/files/id2",
            "files_path": "/files/id2",
            "raw_path": "/raw/second.pdf",
            "url": "/files/id2",
            "raw_url": "/raw/second.pdf",
        },
    ]
    mock_drive_client.list_files = MagicMock(return_value=fake_files)

    resp = client.get("/files", headers={"X-API-Key": TEST_API_KEY})
    assert resp.status_code == 200
    files = resp.json()
    assert len(files) == 2
    assert files[0]["name"] == "first.txt"
    assert files[1]["name"] == "second.pdf"


# ============================================================================
# DOWNLOAD STREAMING TESTS (BY ID & BY FILENAME)
# ============================================================================

def test_download_by_id_success(client, mock_drive_client):
    mock_drive_client.get_file_metadata = MagicMock(
        return_value={
            "id": "file_id_999",
            "name": "photo.jpg",
            "size": 12,
            "mimeType": "image/jpeg",
            "path": "/files/file_id_999",
            "raw_path": "/raw/photo.jpg",
        }
    )
    mock_drive_client.stream_file = MagicMock(return_value=iter([b"fake-jpeg-data"]))

    # Test without API key (public access)
    resp = client.get("/files/file_id_999")
    assert resp.status_code == 200
    assert resp.content == b"fake-jpeg-data"
    assert resp.headers["content-type"] == "image/jpeg"
    assert "photo.jpg" in resp.headers["content-disposition"]
    assert resp.headers["content-length"] == "12"
    assert resp.headers["accept-ranges"] == "bytes"

    # Test with API key also works
    resp_auth = client.get("/files/file_id_999", headers={"X-API-Key": TEST_API_KEY})
    assert resp_auth.status_code == 200


def test_download_by_id_range_request(client, mock_drive_client):
    mock_drive_client.get_file_metadata = MagicMock(
        return_value={
            "id": "vid_1",
            "name": "sample.mp4",
            "size": 1000,
            "mimeType": "video/mp4",
            "path": "/files/vid_1",
            "raw_path": "/raw/sample.mp4",
        }
    )
    mock_drive_client.stream_file = MagicMock(return_value=iter([b"partial-mp4-data"]))

    resp = client.get("/files/vid_1", headers={"Range": "bytes=0-99"})
    assert resp.status_code == 206
    assert resp.headers["content-type"] == "video/mp4"
    assert resp.headers["content-range"] == "bytes 0-99/1000"
    assert resp.headers["content-length"] == "100"
    assert resp.headers["accept-ranges"] == "bytes"


def test_download_by_id_range_unsatisfiable(client, mock_drive_client):
    mock_drive_client.get_file_metadata = MagicMock(
        return_value={
            "id": "vid_1",
            "name": "sample.mp4",
            "size": 1000,
            "mimeType": "video/mp4",
            "path": "/files/vid_1",
            "raw_path": "/raw/sample.mp4",
        }
    )
    resp = client.get("/files/vid_1", headers={"Range": "bytes=2000-"})
    assert resp.status_code == 416
    assert resp.headers["content-range"] == "bytes */1000"


def test_download_by_id_html_viewer(client, mock_drive_client):
    mock_drive_client.get_file_metadata = MagicMock(
        return_value={
            "id": "vid_1",
            "name": "sample.mp4",
            "size": 1000,
            "mimeType": "video/mp4",
            "path": "/files/vid_1",
            "raw_path": "/raw/sample.mp4",
        }
    )
    resp = client.get("/files/vid_1?view=html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "sample.mp4" in resp.text
    assert "<video" in resp.text
    assert "Download File" in resp.text


def test_download_by_id_attachment(client, mock_drive_client):
    mock_drive_client.get_file_metadata = MagicMock(
        return_value={
            "id": "vid_1",
            "name": "sample.mp4",
            "size": 1000,
            "mimeType": "video/mp4",
            "path": "/files/vid_1",
            "raw_path": "/raw/sample.mp4",
        }
    )
    mock_drive_client.stream_file = MagicMock(return_value=iter([b"data"]))
    resp = client.get("/files/vid_1?download=1")
    assert resp.status_code == 200
    assert "attachment; filename=\"sample.mp4\"" in resp.headers["content-disposition"]


def test_download_by_id_not_found(client, mock_drive_client):
    mock_drive_client.get_file_metadata = MagicMock(
        side_effect=FileNotFoundError("Not found")
    )

    resp = client.get("/files/nonexistent", headers={"X-API-Key": TEST_API_KEY})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "File not found"


def test_download_by_filename_success(client, mock_drive_client):
    mock_drive_client.get_latest_file_by_name = MagicMock(
        return_value={
            "id": "file_id_latest",
            "name": "report.pdf",
            "size": 15,
            "mimeType": "application/pdf",
            "path": "/files/file_id_latest",
            "raw_path": "/raw/report.pdf",
        }
    )
    mock_drive_client.stream_file = MagicMock(return_value=iter([b"pdf-stream-data"]))

    # Public access without API key
    resp = client.get("/raw/report.pdf")
    assert resp.status_code == 200
    assert resp.content == b"pdf-stream-data"
    assert resp.headers["content-type"] == "application/pdf"
    assert "report.pdf" in resp.headers["content-disposition"]
    assert resp.headers["content-length"] == "15"
    assert resp.headers["accept-ranges"] == "bytes"


def test_download_by_filename_nested_subfolder(client, mock_drive_client):
    mock_drive_client.get_latest_file_by_name = MagicMock(
        return_value={
            "id": "vid_nested",
            "name": "kinetic_telemetry_waveform.mp4",
            "subfolder": "renders",
            "size": 1053654,
            "mimeType": "video/mp4",
            "path": "/files/vid_nested",
            "raw_path": "/raw/renders/kinetic_telemetry_waveform.mp4",
        }
    )
    mock_drive_client.stream_file = MagicMock(return_value=iter([b"video-bytes"]))

    resp = client.get("/raw/renders/kinetic_telemetry_waveform.mp4")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "video/mp4"
    assert resp.headers["content-length"] == "1053654"
    assert resp.headers["accept-ranges"] == "bytes"
    mock_drive_client.get_latest_file_by_name.assert_called_with("renders/kinetic_telemetry_waveform.mp4")


def test_download_by_filename_range_request(client, mock_drive_client):
    mock_drive_client.get_latest_file_by_name = MagicMock(
        return_value={
            "id": "vid_nested",
            "name": "kinetic_telemetry_waveform.mp4",
            "subfolder": "renders",
            "size": 1053654,
            "mimeType": "video/mp4",
            "path": "/files/vid_nested",
            "raw_path": "/raw/renders/kinetic_telemetry_waveform.mp4",
        }
    )
    mock_drive_client.stream_file = MagicMock(return_value=iter([b"video-bytes-chunk"]))

    resp = client.get(
        "/raw/renders/kinetic_telemetry_waveform.mp4",
        headers={"Range": "bytes=0-1023"},
    )
    assert resp.status_code == 206
    assert resp.headers["content-type"] == "video/mp4"
    assert resp.headers["content-range"] == "bytes 0-1023/1053654"
    assert resp.headers["content-length"] == "1024"
    assert resp.headers["accept-ranges"] == "bytes"


def test_download_by_filename_open_ended_range(client, mock_drive_client):
    mock_drive_client.get_latest_file_by_name = MagicMock(
        return_value={
            "id": "vid_nested",
            "name": "clip.mp4",
            "size": 1000,
            "mimeType": "video/mp4",
            "path": "/files/vid_nested",
            "raw_path": "/raw/clip.mp4",
        }
    )
    mock_drive_client.stream_file = MagicMock(return_value=iter([b"chunk"]))
    resp = client.get("/raw/clip.mp4", headers={"Range": "bytes=500-"})
    assert resp.status_code == 206
    assert resp.headers["content-range"] == "bytes 500-999/1000"
    assert resp.headers["content-length"] == "500"


def test_download_by_filename_suffix_range(client, mock_drive_client):
    mock_drive_client.get_latest_file_by_name = MagicMock(
        return_value={
            "id": "vid_nested",
            "name": "clip.mp4",
            "size": 1000,
            "mimeType": "video/mp4",
            "path": "/files/vid_nested",
            "raw_path": "/raw/clip.mp4",
        }
    )
    mock_drive_client.stream_file = MagicMock(return_value=iter([b"chunk"]))
    resp = client.get("/raw/clip.mp4", headers={"Range": "bytes=-200"})
    assert resp.status_code == 206
    assert resp.headers["content-range"] == "bytes 800-999/1000"
    assert resp.headers["content-length"] == "200"


def test_head_request_support(client, mock_drive_client):
    mock_drive_client.get_file_metadata = MagicMock(
        return_value={
            "id": "vid_head",
            "name": "video.mp4",
            "size": 5000,
            "mimeType": "video/mp4",
            "path": "/files/vid_head",
            "raw_path": "/raw/video.mp4",
        }
    )
    resp = client.head("/files/vid_head")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "video/mp4"
    assert resp.headers["content-length"] == "5000"
    assert resp.headers["accept-ranges"] == "bytes"
    assert resp.content == b""


def test_fallback_known_file_id(client, mock_drive_client):
    mock_drive_client.get_file_metadata = MagicMock(
        side_effect=FileNotFoundError("Not found")
    )
    mock_drive_client.get_latest_file_by_name = MagicMock(
        return_value={
            "id": "1wVyeJd86TUemNUQny2kZTxIWGWhAaGb_",
            "name": "kinetic_telemetry_waveform.mp4",
            "size": 1160039,
            "mimeType": "video/mp4",
            "path": "/files/1wVyeJd86TUemNUQny2kZTxIWGWhAaGb_",
            "raw_path": "/raw/renders/kinetic_telemetry_waveform.mp4",
        }
    )
    mock_drive_client.stream_file = MagicMock(return_value=iter([b"waveform-data"]))
    resp = client.get("/files/1FZSLLIdyMF0DwE9NQtpH-OjrJLR5ks1Q")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "video/mp4"
    assert resp.content == b"waveform-data"


def test_download_by_filename_not_found(client, mock_drive_client):
    mock_drive_client.get_latest_file_by_name = MagicMock(
        side_effect=FileNotFoundError("Not found")
    )

    resp = client.get("/raw/missing.pdf", headers={"X-API-Key": TEST_API_KEY})
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


# ============================================================================
# DELETE TESTS
# ============================================================================

def test_delete_file_success(client, mock_drive_client):
    mock_drive_client.delete_file = MagicMock(return_value=True)

    resp = client.delete("/files/file_to_delete", headers={"X-API-Key": TEST_API_KEY})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "deleted"
    assert data["file_id"] == "file_to_delete"
    mock_drive_client.delete_file.assert_called_once_with("file_to_delete")


def test_delete_file_not_found(client, mock_drive_client):
    mock_drive_client.delete_file = MagicMock(
        side_effect=FileNotFoundError("File not found")
    )

    resp = client.delete("/files/file_not_exists", headers={"X-API-Key": TEST_API_KEY})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "File not found"


# ============================================================================
# DRIVE CLIENT UNIT TESTS (MOCKING GOOGLE API CLIENT)
# ============================================================================

def test_drive_client_discover_or_create_folder():
    client = DriveClient()
    mock_service = MagicMock()
    client.set_service(mock_service)

    # 1. Folder exists
    mock_service.files().list().execute.return_value = {
        "files": [{"id": "existing_folder_id", "name": "bucket"}]
    }
    folder_id = client.get_bucket_folder_id()
    assert folder_id == "existing_folder_id"

    # Reset cache and test folder creation if not exists
    client._bucket_folder_id = None
    mock_service.files().list().execute.return_value = {"files": []}
    mock_service.files().create().execute.return_value = {
        "id": "newly_created_folder_id"
    }

    new_id = client.get_bucket_folder_id()
    assert new_id == "newly_created_folder_id"
    mock_service.files().create.assert_called()


def test_drive_client_reload():
    client = DriveClient()
    mock_service = MagicMock()
    with patch.object(client, "_init_service", return_value=mock_service):
        mock_service.files().list().execute.return_value = {
            "files": [{"id": "reloaded_id", "name": "bucket"}]
        }
        res = client.reload()
        assert res == "reloaded_id"
        assert client.is_authenticated() is True


def test_drive_client_upload_with_overwrite():
    client = DriveClient()
    mock_service = MagicMock()
    client.set_service(mock_service, bucket_folder_id="bucket_123")

    # Mock finding existing file with same name
    mock_service.files().list().execute.return_value = {
        "files": [{"id": "old_file_id"}]
    }
    mock_create_req = MagicMock()
    mock_create_req.next_chunk.return_value = (
        None,
        {
            "id": "new_file_id",
            "name": "test.txt",
            "size": 12,
            "mimeType": "text/plain",
            "createdTime": "2026-11-17T02:00:00Z",
            "modifiedTime": "2026-11-17T02:00:00Z",
        },
    )
    mock_service.files().create.return_value = mock_create_req

    import tempfile

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("test content")
        tmp_name = f.name

    try:
        res = client.upload_file(tmp_name, "test.txt", "text/plain", overwrite=True)
        assert res["id"] == "new_file_id"
        assert res["name"] == "test.txt"
        assert res["path"] == "/files/new_file_id"
        # Verify old file was deleted
        mock_service.files().delete.assert_called_with(fileId="old_file_id")
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def test_drive_client_delete_file_not_found():
    client = DriveClient()
    mock_service = MagicMock()
    client.set_service(mock_service, bucket_folder_id="bucket_123")

    # Simulate 404 from Google Drive API
    resp = Response({"status": 404})
    mock_service.files().get().execute.side_effect = HttpError(resp, b"File not found")

    with pytest.raises(FileNotFoundError):
        client.delete_file("missing_id")


def test_drive_client_stream_file():
    client = DriveClient()
    mock_service = MagicMock()
    client.set_service(mock_service, bucket_folder_id="bucket_123")

    mock_req = MagicMock()
    mock_req.http = None  # Force fallback
    mock_req.execute.return_value = b"direct-file-content"
    mock_service.files().get_media.return_value = mock_req

    chunks = list(client.stream_file("sample_id"))
    assert b"".join(chunks) == b"direct-file-content"
