import json
import mimetypes
import os
import secrets
import tempfile
import time
from typing import Optional
from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Header,
    Query,
    Form,
    File,
    UploadFile,
    Request,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse, Response
from google_auth_oauthlib.flow import Flow
from drive_client import DriveClient, DriveError

load_dotenv()

app = FastAPI(
    title="Bucketloader",
    description="Headless Google Drive storage backend and file serving service",
    version="1.0.0",
)

drive_client = DriveClient()

OAUTH_STATE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "oauth_state.json"
)
_oauth_states: dict[str, dict] = {}


def get_drive_client() -> DriveClient:
    return drive_client


def get_api_key_from_env() -> str:
    key = os.getenv("BUCKET_API_KEY", "")
    return key.strip()


def get_credentials_path() -> str:
    path = os.getenv("GOOGLE_CREDENTIALS_PATH") or os.getenv(
        "GOOGLE_CREDENTIALS_FILE", "credentials.json"
    )
    if not os.path.isabs(path):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    return path


def get_token_path() -> str:
    path = os.getenv("GOOGLE_TOKEN_PATH") or os.getenv(
        "GOOGLE_TOKEN_FILE", "token.json"
    )
    if not os.path.isabs(path):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    return path


def check_has_credentials() -> bool:
    creds_path = get_credentials_path()
    if not os.path.exists(creds_path):
        return False
    try:
        with open(creds_path, "r") as f:
            data = json.load(f)
        return isinstance(data, dict) and ("web" in data or "installed" in data)
    except Exception:
        return False


def save_oauth_state(state_data: dict) -> None:
    state = state_data["state"]
    _oauth_states[state] = state_data
    try:
        states = {}
        if os.path.exists(OAUTH_STATE_FILE):
            try:
                with open(OAUTH_STATE_FILE, "r") as f:
                    states = json.load(f)
                    if not isinstance(states, dict):
                        states = {}
            except Exception:
                states = {}
        states[state] = state_data
        with open(OAUTH_STATE_FILE, "w") as f:
            json.dump(states, f)
        os.chmod(OAUTH_STATE_FILE, 0o600)
    except Exception:
        pass


def validate_and_consume_state(state: str) -> Optional[dict]:
    state_info = _oauth_states.pop(state, None)
    if os.path.exists(OAUTH_STATE_FILE):
        try:
            with open(OAUTH_STATE_FILE, "r") as f:
                states = json.load(f)
            if isinstance(states, dict) and state in states:
                if state_info is None:
                    state_info = states[state]
                del states[state]
                with open(OAUTH_STATE_FILE, "w") as f:
                    json.dump(states, f)
                os.chmod(OAUTH_STATE_FILE, 0o600)
        except Exception:
            pass
    return state_info


def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    api_key_query: Optional[str] = Query(None, alias="api_key"),
) -> str:
    token = None
    if x_api_key:
        token = x_api_key.strip()
    elif authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
        elif len(parts) == 1:
            token = parts[0].strip()
    elif api_key_query:
        token = api_key_query.strip()

    expected = get_api_key_from_env()
    if not expected or not token or not secrets.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


def ensure_drive_authenticated(client: DriveClient):
    if not client.is_authenticated():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google Drive not authenticated. Please complete OAuth setup via /auth/url or auth_setup.py.",
        )


@app.get("/")
def index(_: str = Depends(verify_api_key)):
    return {
        "service": "bucketloader",
        "health": "/health",
        "docs": "/docs",
    }


@app.get("/health")
def health(client: DriveClient = Depends(get_drive_client)):
    """Health check endpoint. Publicly accessible."""
    is_auth = client.is_authenticated()
    has_creds = check_has_credentials()
    folder_id = None
    if is_auth:
        try:
            folder_id = client.get_bucket_folder_id()
        except Exception:
            folder_id = None

    response_data = {
        "status": "ok",
        "drive_authenticated": is_auth,
        "has_credentials": has_creds,
        "bucket_folder_id": folder_id,
    }
    if not is_auth:
        response_data["auth_url_endpoint"] = "/auth/url"

    return response_data


@app.post("/auth/credentials")
async def save_credentials(
    request: Request,
    _: str = Depends(verify_api_key),
):
    """
    Accepts raw JSON body or multipart file upload of Google Cloud OAuth client credentials,
    validating top-level 'web' or 'installed' key, saves it to credentials.json (chmod 600),
    and returns confirmation.
    """
    content_type = request.headers.get("content-type", "")
    data = None

    if "multipart/form-data" in content_type:
        form = await request.form()
        for _, value in form.items():
            if hasattr(value, "read"):
                file_bytes = await value.read()
                try:
                    data = json.loads(file_bytes.decode("utf-8"))
                except Exception:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Uploaded file is not valid JSON",
                    )
                break
            elif isinstance(value, str) and value.strip().startswith("{"):
                try:
                    data = json.loads(value)
                    break
                except Exception:
                    pass
        if data is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No client credentials file or JSON found in multipart form data",
            )
    else:
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON payload",
            )

    if not isinstance(data, dict) or ("web" not in data and "installed" not in data):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credentials JSON must contain top-level 'web' or 'installed' key",
        )

    creds_path = get_credentials_path()
    try:
        with open(creds_path, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(creds_path, 0o600)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to write credentials file: {e}",
        )

    client_type = "web" if "web" in data else "installed"
    return {
        "status": "success",
        "saved": True,
        "client_type": client_type,
        "credentials_path": creds_path,
        "message": f"Successfully saved Google OAuth credentials ({client_type}).",
    }


@app.get("/auth/url")
def get_auth_url(
    _: str = Depends(verify_api_key),
):
    """
    Reads credentials.json (or GOOGLE_CREDENTIALS_PATH), builds a Google OAuth 2.0 Flow
    with scope https://www.googleapis.com/auth/drive, access_type='offline', prompt='consent',
    and redirect URI pointing to the /bucket/auth/callback endpoint on kanevskyy.dev
    (configured via OAUTH_REDIRECT_URI in .env), persists the OAuth state token, and
    returns JSON with auth_url and redirect_uri.
    """
    creds_path = get_credentials_path()
    if not os.path.exists(creds_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth credentials file not found at '{creds_path}'. Upload credentials via POST /auth/credentials first.",
        )

    redirect_uri = os.getenv(
        "OAUTH_REDIRECT_URI", "https://kanevskyy.dev/bucket/auth/callback"
    )
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    try:
        flow = Flow.from_client_secrets_file(
            creds_path,
            scopes=["https://www.googleapis.com/auth/drive"],
            redirect_uri=redirect_uri,
        )
        auth_url, state = flow.authorization_url(
            access_type="offline",
            prompt="consent",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initialize OAuth flow: {e}",
        )

    state_data = {
        "state": state,
        "code_verifier": getattr(flow, "code_verifier", None),
        "created_at": time.time(),
    }
    save_oauth_state(state_data)

    return {
        "auth_url": auth_url,
        "redirect_uri": redirect_uri,
    }


@app.get("/auth/callback")
def auth_callback(
    request: Request,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    format: Optional[str] = Query(None),
    client: DriveClient = Depends(get_drive_client),
):
    """
    Unauthenticated public endpoint for Google's OAuth browser redirect.
    Validates state, exchanges the query param 'code' for access and refresh tokens,
    writes token.json (chmod 600), reloads the active DriveClient in memory without
    requiring a server restart, discovers/creates the root 'bucket' folder in Google Drive,
    and returns JSON/HTML confirming authenticated=true and bucket_folder_id.
    """
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google OAuth authorization error: {error}",
        )

    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required authorization parameter 'code'",
        )

    if not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required OAuth state parameter 'state'",
        )

    state_info = validate_and_consume_state(state)
    if not state_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state parameter",
        )

    creds_path = get_credentials_path()
    if not os.path.exists(creds_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth credentials file not found. Upload credentials first.",
        )

    redirect_uri = os.getenv(
        "OAUTH_REDIRECT_URI", "https://kanevskyy.dev/bucket/auth/callback"
    )
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    try:
        flow = Flow.from_client_secrets_file(
            creds_path,
            scopes=["https://www.googleapis.com/auth/drive"],
            redirect_uri=redirect_uri,
            state=state,
        )
        if state_info.get("code_verifier"):
            flow.code_verifier = state_info["code_verifier"]

        flow.fetch_token(code=code)
        creds = flow.credentials
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to exchange code for tokens: {e}",
        )

    token_path = get_token_path()
    try:
        with open(token_path, "w") as f:
            f.write(creds.to_json())
        os.chmod(token_path, 0o600)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save token file: {e}",
        )

    # Reload the active DriveClient in memory without requiring a server restart
    client.reload()

    # Discover/create root 'bucket' folder
    bucket_folder_id = None
    try:
        bucket_folder_id = client.get_bucket_folder_id()
    except Exception:
        pass

    accept = request.headers.get("accept", "")
    want_html = (
        format == "html"
        or (
            "text/html" in accept
            and "application/json" not in accept
            and not accept.startswith("*/*")
        )
    )

    if want_html:
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Bucketloader - Authenticated</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; color: #202124; background: #f8f9fa; }}
        .card {{ background: white; border-radius: 8px; border: 1px solid #dadce0; padding: 32px; box-shadow: 0 1px 3px rgba(60,64,67,0.15); }}
        h1 {{ color: #1e8e3e; font-size: 24px; margin-top: 0; }}
        .item {{ margin: 12px 0; font-size: 15px; }}
        code {{ background: #f1f3f4; padding: 3px 8px; border-radius: 4px; font-family: monospace; font-size: 14px; }}
        .badge {{ display: inline-block; background: #e6f4ea; color: #137333; padding: 4px 10px; border-radius: 12px; font-weight: 500; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Google Drive Authenticated</h1>
        <div class="item"><span class="badge">authenticated: true</span></div>
        <div class="item"><strong>Bucket Folder ID:</strong> <code>{bucket_folder_id or "discovered"}</code></div>
        <div class="item">Token saved and DriveClient reloaded successfully. You may close this tab.</div>
    </div>
</body>
</html>"""
        return HTMLResponse(content=html, status_code=status.HTTP_200_OK)

    return {
        "authenticated": True,
        "bucket_folder_id": bucket_folder_id,
        "status": "authenticated",
        "message": "Google Drive authenticated successfully and DriveClient reloaded.",
    }


@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    overwrite: bool = Form(False),
    subfolder: Optional[str] = Form(None),
    _: str = Depends(verify_api_key),
    client: DriveClient = Depends(get_drive_client),
):
    """
    Accepts multipart/form-data file and optional overwrite flag.
    Uploads to Google Drive bucket folder and returns JSON metadata.
    """
    ensure_drive_authenticated(client)

    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_path = temp_file.name
    try:
        temp_file.close()
        with open(temp_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                f.write(chunk)

        filename = file.filename or "unnamed_file"
        file_meta = client.upload_file(
            file_path=temp_path,
            filename=filename,
            mime_type=file.content_type,
            overwrite=overwrite,
            subfolder=subfolder,
        )
        return file_meta
    except DriveError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
    finally:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


@app.get("/files")
def list_files(
    subfolder: Optional[str] = Query(None),
    _: str = Depends(verify_api_key),
    client: DriveClient = Depends(get_drive_client),
):
    """Lists all stored files in the bucket folder."""
    ensure_drive_authenticated(client)
    try:
        files = client.list_files(subfolder=subfolder)
        return files
    except DriveError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


def parse_range_header(
    range_header: Optional[str], file_size: int
) -> Optional[tuple[int, int]]:
    """
    Parses HTTP Range header (RFC 7233).
    Returns (start, end) as 0-indexed inclusive integers, or None if no Range header or invalid.
    Raises HTTPException(416) if range is unsatisfiable.
    """
    if not range_header or not range_header.startswith("bytes="):
        return None

    range_val = range_header.replace("bytes=", "").strip()
    if "," in range_val:
        range_val = range_val.split(",")[0].strip()

    parts = range_val.split("-")
    if len(parts) != 2:
        return None

    start_str, end_str = parts[0].strip(), parts[1].strip()

    if file_size <= 0:
        return None

    if start_str and end_str:
        try:
            start = int(start_str)
            end = int(end_str)
        except ValueError:
            return None
        if start > end or start >= file_size or start < 0:
            raise HTTPException(
                status_code=status.HTTP_416_RANGE_NOT_SATISFIABLE,
                detail="Range Not Satisfiable",
                headers={"Content-Range": f"bytes */{file_size}"},
            )
        end = min(end, file_size - 1)
        return (start, end)

    elif start_str and not end_str:
        try:
            start = int(start_str)
        except ValueError:
            return None
        if start >= file_size or start < 0:
            raise HTTPException(
                status_code=status.HTTP_416_RANGE_NOT_SATISFIABLE,
                detail="Range Not Satisfiable",
                headers={"Content-Range": f"bytes */{file_size}"},
            )
        return (start, file_size - 1)

    elif not start_str and end_str:
        try:
            suffix = int(end_str)
        except ValueError:
            return None
        if suffix <= 0:
            raise HTTPException(
                status_code=status.HTTP_416_RANGE_NOT_SATISFIABLE,
                detail="Range Not Satisfiable",
                headers={"Content-Range": f"bytes */{file_size}"},
            )
        suffix = min(suffix, file_size)
        return (file_size - suffix, file_size - 1)

    return None


def format_file_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def render_html_viewer(meta: dict, stream_url: str, download_url: str) -> HTMLResponse:
    safe_name = meta.get("name", "File")
    file_id = meta.get("id", "")
    size = int(meta.get("size", 0)) if meta.get("size") is not None else 0
    size_str = format_file_size(size)
    mime_type = meta.get("mimeType") or "application/octet-stream"
    modified = meta.get("modifiedTime") or meta.get("createdTime") or ""
    subfolder = meta.get("subfolder") or ""

    if mime_type.startswith("video/"):
        media_preview = f"""
        <div class="media-container">
            <video controls autoplay playsinline preload="metadata">
                <source src="{stream_url}" type="{mime_type}">
                Your browser does not support the video tag.
            </video>
        </div>
        """
    elif mime_type.startswith("audio/"):
        media_preview = f"""
        <div class="media-container">
            <audio controls preload="metadata">
                <source src="{stream_url}" type="{mime_type}">
                Your browser does not support the audio tag.
            </audio>
        </div>
        """
    elif mime_type.startswith("image/"):
        media_preview = f"""
        <div class="media-container">
            <img src="{stream_url}" alt="{safe_name}">
        </div>
        """
    elif mime_type == "application/pdf":
        media_preview = f"""
        <div class="media-container" style="height: 70vh;">
            <iframe src="{stream_url}" style="width: 100%; height: 100%; border: none;"></iframe>
        </div>
        """
    else:
        media_preview = f"""
        <div class="media-placeholder">
            <div class="file-icon">&#128196;</div>
            <p>Direct preview is not available for this file type ({mime_type}).</p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{safe_name} - Bucketloader</title>
    <style>
        body {{
            margin: 0;
            padding: 30px 15px;
            background: #0f172a;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            justify-content: center;
        }}
        .card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            max-width: 960px;
            width: 100%;
            overflow: hidden;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            padding: 20px 24px;
            border-bottom: 1px solid #334155;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 18px;
            font-weight: 600;
            color: #f8fafc;
            word-break: break-all;
        }}
        .badge {{
            background: #0284c7;
            color: #ffffff;
            font-size: 12px;
            padding: 3px 10px;
            border-radius: 9999px;
            font-weight: 500;
        }}
        .media-container {{
            background: #020617;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        video, audio, img {{
            max-width: 100%;
            border-radius: 8px;
        }}
        video {{
            max-height: 70vh;
            width: 100%;
        }}
        .media-placeholder {{
            background: #020617;
            padding: 60px 20px;
            text-align: center;
            color: #94a3b8;
        }}
        .file-icon {{
            font-size: 48px;
            margin-bottom: 12px;
        }}
        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            padding: 20px 24px;
            border-top: 1px solid #334155;
            background: #1e293b;
            font-size: 14px;
        }}
        .metadata-item {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        .metadata-label {{
            color: #94a3b8;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .metadata-val {{
            color: #e2e8f0;
            font-family: monospace;
            word-break: break-all;
        }}
        .actions {{
            padding: 16px 24px;
            background: #0f172a;
            border-top: 1px solid #334155;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .btn {{
            display: inline-flex;
            align-items: center;
            padding: 8px 18px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.15s ease;
        }}
        .btn-primary {{
            background: #2563eb;
            color: white;
        }}
        .btn-primary:hover {{
            background: #1d4ed8;
        }}
        .btn-secondary {{
            background: #334155;
            color: #cbd5e1;
        }}
        .btn-secondary:hover {{
            background: #475569;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h1>{safe_name}</h1>
            <span class="badge">{mime_type}</span>
        </div>
        {media_preview}
        <div class="metadata-grid">
            <div class="metadata-item">
                <span class="metadata-label">File Size</span>
                <span class="metadata-val">{size_str} ({size:,} bytes)</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">File ID</span>
                <span class="metadata-val">{file_id}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Subfolder</span>
                <span class="metadata-val">{subfolder or "/"}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Modified Time</span>
                <span class="metadata-val">{modified or "N/A"}</span>
            </div>
        </div>
        <div class="actions">
            <a href="{download_url}" class="btn btn-primary" download>Download File</a>
            <a href="{stream_url}" class="btn btn-secondary">Direct Stream / Raw</a>
        </div>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=status.HTTP_200_OK)


def build_stream_response(
    meta: dict,
    client: DriveClient,
    range_header: Optional[str] = None,
    download: bool = False,
    view_mode: Optional[str] = None,
    request: Optional[Request] = None,
) -> StreamingResponse | HTMLResponse:
    file_id = str(meta.get("id", ""))
    filename = str(meta.get("name", "file"))
    size_raw = meta.get("size")
    try:
        file_size = int(size_raw) if size_raw is not None else 0
    except (TypeError, ValueError):
        file_size = 0

    # Determine accurate MIME type
    raw_mime = meta.get("mimeType")
    media_type = str(raw_mime) if raw_mime else "application/octet-stream"
    if not media_type or media_type == "application/octet-stream":
        guessed, _ = mimetypes.guess_type(filename)
        if guessed:
            media_type = str(guessed)

    # If HTML viewer explicitly requested
    if view_mode and view_mode.lower() in ("html", "viewer"):
        stream_url = meta.get("files_path", f"/files/{file_id}")
        raw_url = meta.get("raw_path")
        active_stream = raw_url if raw_url else stream_url
        download_url = f"{stream_url}?download=1"
        return render_html_viewer(meta, stream_url=active_stream, download_url=download_url)

    safe_name = filename.replace('"', '\\"')
    disposition = "attachment" if download else "inline"

    headers = {
        "Content-Type": media_type,
        "Content-Disposition": f'{disposition}; filename="{safe_name}"',
        "Accept-Ranges": "bytes",
    }

    if range_header and file_size > 0:
        parsed_range = parse_range_header(range_header, file_size)
        if parsed_range:
            start, end = parsed_range
            content_length = end - start + 1
            headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
            headers["Content-Length"] = str(content_length)
            if request and request.method == "HEAD":
                return Response(
                    content=b"",
                    status_code=status.HTTP_206_PARTIAL_CONTENT,
                    media_type=media_type,
                    headers=headers,
                )
            return StreamingResponse(
                client.stream_file(file_id, range_start=start, range_end=end),
                status_code=status.HTTP_206_PARTIAL_CONTENT,
                media_type=media_type,
                headers=headers,
            )

    if file_size > 0:
        headers["Content-Length"] = str(file_size)

    if request and request.method == "HEAD":
        return Response(
            content=b"",
            status_code=status.HTTP_200_OK,
            media_type=media_type,
            headers=headers,
        )

    return StreamingResponse(
        client.stream_file(file_id),
        status_code=status.HTTP_200_OK,
        media_type=media_type,
        headers=headers,
    )


@app.api_route("/files/{file_id}", methods=["GET", "HEAD"])
def get_file_by_id(
    file_id: str,
    request: Request,
    range: Optional[str] = Header(None, alias="Range"),
    download: Optional[str] = Query(None),
    view: Optional[str] = Query(None),
    format: Optional[str] = Query(None),
    client: DriveClient = Depends(get_drive_client),
):
    """Streams the file directly from Google Drive by file ID. Publicly accessible."""
    ensure_drive_authenticated(client)
    try:
        meta = client.get_file_metadata(file_id)
    except FileNotFoundError:
        # Graceful fallback for replaced/overwritten files (e.g. kinetic waveform video)
        if file_id == "1FZSLLIdyMF0DwE9NQtpH-OjrJLR5ks1Q":
            try:
                meta = client.get_latest_file_by_name("renders/kinetic_telemetry_waveform.mp4")
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
            )
    except DriveError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )

    is_download = bool(download and download.lower() in ("1", "true", "yes"))
    return build_stream_response(
        meta=meta,
        client=client,
        range_header=range,
        download=is_download,
        view_mode=view or format,
        request=request,
    )


@app.api_route("/raw/{filepath:path}", methods=["GET", "HEAD"])
def get_raw_file(
    filepath: str,
    request: Request,
    range: Optional[str] = Header(None, alias="Range"),
    download: Optional[str] = Query(None),
    view: Optional[str] = Query(None),
    format: Optional[str] = Query(None),
    client: DriveClient = Depends(get_drive_client),
):
    """Looks up the most recent file matching filepath in the bucket folder and streams it. Publicly accessible."""
    ensure_drive_authenticated(client)
    try:
        meta = client.get_latest_file_by_name(filepath)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{filepath}' not found",
        )
    except DriveError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )

    is_download = bool(download and download.lower() in ("1", "true", "yes"))
    return build_stream_response(
        meta=meta,
        client=client,
        range_header=range,
        download=is_download,
        view_mode=view or format,
        request=request,
    )


@app.delete("/files/{file_id}")
def delete_file(
    file_id: str,
    _: str = Depends(verify_api_key),
    client: DriveClient = Depends(get_drive_client),
):
    """Deletes/trashes a file by file ID in Google Drive."""
    ensure_drive_authenticated(client)
    try:
        client.delete_file(file_id)
        return {"status": "deleted", "file_id": file_id}
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
        )
    except DriveError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
