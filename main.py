import json
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
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse
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
    _: str = Depends(verify_api_key),
    client: DriveClient = Depends(get_drive_client),
):
    """Lists all stored files in the bucket folder."""
    ensure_drive_authenticated(client)
    try:
        files = client.list_files()
        return files
    except DriveError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@app.get("/files/{file_id}")
def get_file_by_id(
    file_id: str,
    _: str = Depends(verify_api_key),
    client: DriveClient = Depends(get_drive_client),
):
    """Streams the file directly from Google Drive by file ID."""
    ensure_drive_authenticated(client)
    try:
        meta = client.get_file_metadata(file_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
        )
    except DriveError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )

    safe_name = meta["name"].replace('"', '\\"')
    headers = {
        "Content-Disposition": f'inline; filename="{safe_name}"',
    }
    if meta.get("size") and meta["size"] > 0:
        headers["Content-Length"] = str(meta["size"])

    media_type = meta.get("mimeType") or "application/octet-stream"
    return StreamingResponse(
        client.stream_file(file_id),
        media_type=media_type,
        headers=headers,
    )


@app.get("/raw/{filename:path}")
def get_raw_file(
    filename: str,
    _: str = Depends(verify_api_key),
    client: DriveClient = Depends(get_drive_client),
):
    """Looks up the most recent file matching filename in the bucket folder and streams it."""
    ensure_drive_authenticated(client)
    try:
        meta = client.get_latest_file_by_name(filename)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{filename}' not found",
        )
    except DriveError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )

    safe_name = meta["name"].replace('"', '\\"')
    headers = {
        "Content-Disposition": f'inline; filename="{safe_name}"',
    }
    if meta.get("size") and meta["size"] > 0:
        headers["Content-Length"] = str(meta["size"])

    media_type = meta.get("mimeType") or "application/octet-stream"
    return StreamingResponse(
        client.stream_file(meta["id"]),
        media_type=media_type,
        headers=headers,
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
