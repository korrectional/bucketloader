import io
import json
import os
import tempfile
import pytest
from unittest.mock import MagicMock, patch
import auth_setup


def test_auth_setup_missing_credentials(capsys):
    with pytest.raises(SystemExit) as exc:
        auth_setup.run_auth_flow("non_existent_creds.json", "token.json")
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Credentials file not found" in captured.out


def test_auth_setup_successful_flow(monkeypatch, tmp_path):
    creds_file = tmp_path / "credentials.json"
    token_file = tmp_path / "token.json"

    creds_content = {
        "installed": {
            "client_id": "fake_client_id",
            "client_secret": "fake_client_secret",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost"],
        }
    }
    creds_file.write_text(json.dumps(creds_content))

    mock_flow = MagicMock()
    mock_flow.authorization_url.return_value = ("https://accounts.google.com/test-auth-url", "test-state")
    mock_creds = MagicMock()
    mock_creds.to_json.return_value = '{"token": "test_access_token", "refresh_token": "test_refresh_token"}'
    mock_flow.credentials = mock_creds

    # Simulate user pasting redirected URL
    redirect_url = "http://localhost/?state=xyz&code=4/0Abc123CodeValue&scope=drive"
    monkeypatch.setattr("builtins.input", lambda prompt="": redirect_url)

    with patch("auth_setup.InstalledAppFlow.from_client_secrets_file", return_value=mock_flow):
        auth_setup.run_auth_flow(str(creds_file), str(token_file))

    # Check fetch_token called with extracted code
    mock_flow.fetch_token.assert_called_once_with(code="4/0Abc123CodeValue")
    assert token_file.exists()
    assert "test_access_token" in token_file.read_text()


def test_auth_setup_raw_code(monkeypatch, tmp_path):
    creds_file = tmp_path / "credentials.json"
    token_file = tmp_path / "token.json"

    creds_content = {
        "installed": {
            "client_id": "fake_client_id",
            "client_secret": "fake_client_secret",
            "redirect_uris": ["http://localhost"],
        }
    }
    creds_file.write_text(json.dumps(creds_content))

    mock_flow = MagicMock()
    mock_flow.authorization_url.return_value = ("https://accounts.google.com/test-auth-url", "test-state")
    mock_creds = MagicMock()
    mock_creds.to_json.return_value = '{"token": "raw_code_token"}'
    mock_flow.credentials = mock_creds

    # Simulate user pasting raw code directly
    monkeypatch.setattr("builtins.input", lambda prompt="": "my-raw-auth-code-xyz")

    with patch("auth_setup.InstalledAppFlow.from_client_secrets_file", return_value=mock_flow):
        auth_setup.run_auth_flow(str(creds_file), str(token_file))

    mock_flow.fetch_token.assert_called_once_with(code="my-raw-auth-code-xyz")
    assert token_file.exists()
    assert "raw_code_token" in token_file.read_text()
