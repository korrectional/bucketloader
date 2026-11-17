# Bucketloader

Headless Google Drive storage backend and file serving service built with FastAPI and Google Drive API v3. Bucketloader provides an automated web OAuth setup, auto-discovers or creates a dedicated root `bucket` folder in Google Drive, and serves files via both direct file IDs and vanity filenames.

The service runs locally on port `8090` and is exposed via `kroute` at `https://kanevskyy.dev/bucket/` with Nginx `strip_prefix` enabled.

---

## Features

- **Automated Web OAuth Setup**: No manual SSH or copy-pasting required. Upload OAuth client credentials via API, generate authorization URL, and authorize via browser redirect.
- **Root Folder Discovery**: Auto-discovers or creates a root folder named `bucket` in Google Drive (`mimeType='application/vnd.google-apps.folder'` and `name='bucket'` and `'root' in parents` and `trashed=false`).
- **Resumable Uploads**: Upload files using multipart form data with optional overwrite support.
- **Direct & Vanity Streaming**: Stream stored files directly via `/files/{file_id}` or vanity filename `/raw/{filename}`.
- **Unified API Key Authentication**: Protects all sensitive endpoints via `X-API-Key` header, `Authorization: Bearer <key>`, or `?api_key=` query parameter.
- **Seamless DriveClient In-Memory Reload**: DriveClient reloads dynamically upon OAuth token generation without requiring server restart.

---

## Configuration (`.env`)

```ini
# API authentication key (required for upload, list, download, delete, auth endpoints)
BUCKET_API_KEY=your-secure-random-api-key-here

# Server binding
HOST=127.0.0.1
PORT=8090

# Google Drive credentials & token paths
GOOGLE_CREDENTIALS_FILE=credentials.json
GOOGLE_TOKEN_FILE=token.json

# OAuth 2.0 Web redirect URI (configured in Google Cloud Console OAuth Client)
OAUTH_REDIRECT_URI=https://kanevskyy.dev/bucket/auth/callback

# Name of the root folder in Google Drive
BUCKET_FOLDER_NAME=bucket
```

---

## API Endpoints

### 1. Health & OAuth Setup

#### `GET /health` (Public, Unauthenticated)
Returns the service health status, whether Google Drive is authenticated, whether client credentials are saved, and the root bucket folder ID.
- **Response when authenticated**:
  ```json
  {
    "status": "ok",
    "drive_authenticated": true,
    "has_credentials": true,
    "bucket_folder_id": "1xyz..."
  }
  ```
- **Response when unauthenticated**:
  ```json
  {
    "status": "ok",
    "drive_authenticated": false,
    "has_credentials": false,
    "bucket_folder_id": null,
    "auth_url_endpoint": "/auth/url"
  }
  ```

#### `POST /auth/credentials` (Protected by `BUCKET_API_KEY`)
Uploads Google Cloud OAuth client credentials JSON. Accepts either raw JSON body (`{"web": {...}}` or `{"installed": {...}}`) or multipart file upload (`client_secret.json`). Saves credentials to `credentials.json` with file permissions `0600`.
- **Headers**: `X-API-Key: <BUCKET_API_KEY>`
- **Response**:
  ```json
  {
    "status": "success",
    "saved": true,
    "client_type": "web",
    "credentials_path": "/home/azureadmin/bucketloader/credentials.json",
    "message": "Successfully saved Google OAuth credentials (web)."
  }
  ```

#### `GET /auth/url` (Protected by `BUCKET_API_KEY`)
Reads credentials file, builds a Google OAuth 2.0 Flow with scope `https://www.googleapis.com/auth/drive`, `access_type='offline'`, `prompt='consent'`, and redirect URI pointing to `OAUTH_REDIRECT_URI`. Persists state token to disk and memory.
- **Headers**: `X-API-Key: <BUCKET_API_KEY>`
- **Response**:
  ```json
  {
    "auth_url": "https://accounts.google.com/o/oauth2/auth?...",
    "redirect_uri": "https://kanevskyy.dev/bucket/auth/callback"
  }
  ```

#### `GET /auth/callback` (Public, Unauthenticated)
Callback endpoint for Google's OAuth browser redirect. Validates the state parameter, exchanges code for access & refresh tokens, saves `token.json` (`0600`), reloads active `DriveClient` in memory, and discovers or creates the root `bucket` folder.
- **Query Parameters**: `code`, `state`
- Returns confirmation as JSON or HTML (when requested via browser).

---

### 2. File Operations (Protected by `BUCKET_API_KEY`)

#### `POST /upload`
Uploads a file to the root `bucket` folder in Google Drive.
- **Form Data**:
  - `file`: Multipart file upload
  - `overwrite`: Optional boolean (`true`/`false`)
- **Headers**: `X-API-Key: <BUCKET_API_KEY>`
- **Response**:
  ```json
  {
    "id": "1abc...",
    "name": "document.pdf",
    "size": 1024,
    "mimeType": "application/pdf",
    "createdTime": "2026-11-17T02:00:00Z",
    "modifiedTime": "2026-11-17T02:00:00Z",
    "path": "/files/1abc...",
    "files_path": "/files/1abc...",
    "raw_path": "/raw/document.pdf",
    "url": "/files/1abc...",
    "raw_url": "/raw/document.pdf"
  }
  ```

#### `GET /files`
Lists all non-trashed files stored inside the `bucket` folder.
- **Headers**: `X-API-Key: <BUCKET_API_KEY>`

#### `GET /files/{file_id}`
Streams file binary content by Google Drive file ID.
- **Headers**: `X-API-Key: <BUCKET_API_KEY>`

#### `GET /raw/{filename}`
Streams the most recently modified file matching the specified filename.
- **Headers**: `X-API-Key: <BUCKET_API_KEY>`

#### `DELETE /files/{file_id}`
Permanently deletes a file from Google Drive.
- **Headers**: `X-API-Key: <BUCKET_API_KEY>`

---

## Service Management

Bucketloader runs under systemd as `bucketloader.service`:

```bash
# Check service status
sudo systemctl status bucketloader.service

# Restart service
sudo systemctl restart bucketloader.service

# View live logs
sudo journalctl -u bucketloader.service -f
```

---

## Running Tests

All unit and integration tests run with mocked Google Drive and OAuth flows:

```bash
source .venv/bin/activate
pytest -v
```
