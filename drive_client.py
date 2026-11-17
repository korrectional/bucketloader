import io
import os
import sys
import tempfile
from typing import Optional, Generator
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError
from dotenv import load_dotenv

load_dotenv()

SCOPES = ["https://www.googleapis.com/auth/drive"]


class DriveError(Exception):
    """Custom exception for Google Drive operations."""
    pass


class DriveClient:
    def __init__(
        self,
        credentials_path: Optional[str] = None,
        token_path: Optional[str] = None,
        folder_name: Optional[str] = None,
        service=None,
    ):
        self.credentials_path = credentials_path or os.getenv(
            "GOOGLE_CREDENTIALS_PATH"
        ) or os.getenv(
            "GOOGLE_CREDENTIALS_FILE", "credentials.json"
        )
        self.token_path = token_path or os.getenv(
            "GOOGLE_TOKEN_PATH"
        ) or os.getenv(
            "GOOGLE_TOKEN_FILE", "token.json"
        )
        self.folder_name = folder_name or os.getenv("BUCKET_FOLDER_NAME", "bucket")
        self._service = service
        self._bucket_folder_id: Optional[str] = None

    def set_service(self, service, bucket_folder_id: Optional[str] = None):
        """Used for testing or manual injection of Google Drive service."""
        self._service = service
        if bucket_folder_id is not None:
            self._bucket_folder_id = bucket_folder_id

    def reload(self) -> Optional[str]:
        """Reloads the active DriveClient in memory without requiring a server restart."""
        self._service = None
        self._bucket_folder_id = None
        if self.service is not None:
            try:
                return self.get_bucket_folder_id()
            except Exception:
                return None
        return None

    @property
    def service(self):
        if self._service is None:
            self._service = self._init_service()
        return self._service

    def _init_service(self):
        """Initializes Google Drive v3 service from token.json if valid."""
        if not os.path.isabs(self.token_path):
            token_file = os.path.join(os.path.dirname(__file__), self.token_path)
            if not os.path.exists(token_file):
                token_file = self.token_path
        else:
            token_file = self.token_path

        if not os.path.exists(token_file):
            return None

        try:
            creds = Credentials.from_authorized_user_file(token_file, SCOPES)
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    with open(token_file, "w") as f:
                        f.write(creds.to_json())
                    os.chmod(token_file, 0o600)
                except Exception:
                    return None

            if creds and creds.valid:
                return build("drive", "v3", credentials=creds, cache_discovery=False)
        except Exception:
            return None
        return None

    def is_authenticated(self) -> bool:
        """Returns True if Google Drive service is available and valid."""
        try:
            return self.service is not None
        except Exception:
            return False

    def get_bucket_folder_id(self) -> str:
        """
        Auto-discover or create the folder named 'bucket' at the root of Google Drive.
        Caches its folder_id.
        """
        if self._bucket_folder_id:
            return self._bucket_folder_id

        if not self.is_authenticated():
            raise DriveError("Google Drive is not authenticated.")

        query = (
            f"mimeType = 'application/vnd.google-apps.folder' and "
            f"name = '{self.folder_name}' and 'root' in parents and trashed = false"
        )
        try:
            results = (
                self.service.files()
                .list(q=query, spaces="drive", fields="files(id, name)")
                .execute()
            )
            files = results.get("files", [])
            if files:
                self._bucket_folder_id = files[0]["id"]
                return self._bucket_folder_id

            # Create the folder if not found
            metadata = {
                "name": self.folder_name,
                "mimeType": "application/vnd.google-apps.folder",
                "parents": ["root"],
            }
            folder = (
                self.service.files()
                .create(body=metadata, fields="id")
                .execute()
            )
            self._bucket_folder_id = folder.get("id")
            return self._bucket_folder_id
        except HttpError as e:
            raise DriveError(f"Failed to discover/create bucket folder: {e}")

    def _format_file_info(self, file_dict: dict) -> dict:
        file_id = file_dict.get("id")
        name = file_dict.get("name", "")
        size = int(file_dict.get("size", 0)) if file_dict.get("size") is not None else 0
        mime_type = file_dict.get("mimeType", "application/octet-stream")
        created_time = file_dict.get("createdTime")
        modified_time = file_dict.get("modifiedTime")

        return {
            "id": file_id,
            "name": name,
            "size": size,
            "mimeType": mime_type,
            "createdTime": created_time,
            "modifiedTime": modified_time,
            "path": f"/files/{file_id}",
            "files_path": f"/files/{file_id}",
            "raw_path": f"/raw/{name}",
            "url": f"/files/{file_id}",
            "raw_url": f"/raw/{name}",
        }

    def upload_file(
        self,
        file_path: str,
        filename: str,
        mime_type: Optional[str] = None,
        overwrite: bool = False,
    ) -> dict:
        """
        Uploads a file to the bucket folder using resumable upload.
        If overwrite is True, deletes existing files with the same name first.
        """
        folder_id = self.get_bucket_folder_id()
        if not folder_id:
            raise DriveError("Google Drive bucket folder not accessible.")

        safe_filename = filename.replace("\\", "\\\\").replace("'", "\\'")

        if overwrite:
            query = f"'{folder_id}' in parents and name = '{safe_filename}' and trashed = false"
            try:
                existing = (
                    self.service.files()
                    .list(q=query, spaces="drive", fields="files(id)")
                    .execute()
                    .get("files", [])
                )
                for f in existing:
                    self.service.files().delete(fileId=f["id"]).execute()
            except HttpError as e:
                raise DriveError(f"Failed to check/delete existing files: {e}")

        media = MediaFileUpload(
            file_path,
            mimetype=mime_type or "application/octet-stream",
            resumable=True,
        )
        metadata = {
            "name": filename,
            "parents": [folder_id],
        }

        request = self.service.files().create(
            body=metadata,
            media_body=media,
            fields="id, name, size, mimeType, createdTime, modifiedTime",
        )

        response = None
        # Handle resumable upload chunks or direct execute in mocks
        if hasattr(request, "next_chunk"):
            try:
                while response is None:
                    status, response = request.next_chunk()
            except (AttributeError, TypeError):
                response = request.execute()
        else:
            response = request.execute()

        # If size is not present in response, get it from local file
        if response and "size" not in response:
            try:
                response["size"] = os.path.getsize(file_path)
            except OSError:
                response["size"] = 0

        return self._format_file_info(response)

    def list_files(self) -> list[dict]:
        """Lists all non-trashed files inside the bucket folder."""
        folder_id = self.get_bucket_folder_id()
        if not folder_id:
            raise DriveError("Google Drive bucket folder not accessible.")

        query = f"'{folder_id}' in parents and trashed = false"
        files = []
        page_token = None

        while True:
            resp = (
                self.service.files()
                .list(
                    q=query,
                    spaces="drive",
                    fields="nextPageToken, files(id, name, size, mimeType, createdTime, modifiedTime)",
                    pageToken=page_token,
                    pageSize=1000,
                )
                .execute()
            )
            for item in resp.get("files", []):
                files.append(self._format_file_info(item))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break

        return files

    def get_file_metadata(self, file_id: str) -> dict:
        """Retrieves metadata of a non-trashed file inside the bucket folder."""
        folder_id = self.get_bucket_folder_id()
        try:
            file_info = (
                self.service.files()
                .get(
                    fileId=file_id,
                    fields="id, name, size, mimeType, parents, trashed, createdTime, modifiedTime",
                )
                .execute()
            )
        except HttpError as e:
            if e.resp.status == 404:
                raise FileNotFoundError(f"File {file_id} not found.")
            raise DriveError(f"Failed to fetch file metadata: {e}")

        if file_info.get("trashed"):
            raise FileNotFoundError(f"File {file_id} is in trash.")
        if folder_id and folder_id not in file_info.get("parents", []):
            raise FileNotFoundError(f"File {file_id} not in bucket folder.")

        return self._format_file_info(file_info)

    def get_latest_file_by_name(self, filename: str) -> dict:
        """Retrieves the latest non-trashed file matching filename in the bucket folder."""
        folder_id = self.get_bucket_folder_id()
        safe_filename = filename.replace("\\", "\\\\").replace("'", "\\'")
        query = f"'{folder_id}' in parents and name = '{safe_filename}' and trashed = false"

        try:
            resp = (
                self.service.files()
                .list(
                    q=query,
                    spaces="drive",
                    orderBy="createdTime desc, modifiedTime desc",
                    fields="files(id, name, size, mimeType, createdTime, modifiedTime)",
                    pageSize=1,
                )
                .execute()
            )
        except HttpError as e:
            raise DriveError(f"Error querying file by name: {e}")

        files = resp.get("files", [])
        if not files:
            raise FileNotFoundError(f"File '{filename}' not found.")

        return self._format_file_info(files[0])

    def stream_file(self, file_id: str, chunk_size: int = 1024 * 1024) -> Generator[bytes, None, None]:
        """Streams file content chunks from Google Drive."""
        request = self.service.files().get_media(fileId=file_id)

        # Attempt MediaIoBaseDownload
        try:
            if hasattr(request, "http") and request.http is not None:
                buf = io.BytesIO()
                downloader = MediaIoBaseDownload(buf, request, chunksize=chunk_size)
                done = False
                while not done:
                    buf.seek(0)
                    buf.truncate(0)
                    status, done = downloader.next_chunk()
                    yield buf.getvalue()
                return
        except Exception:
            pass

        # Fallback for mocks or direct execute
        content = request.execute()
        if isinstance(content, (bytes, bytearray)):
            yield bytes(content)
        elif hasattr(content, "read"):
            while chunk := content.read(chunk_size):
                yield chunk
        else:
            yield str(content).encode("utf-8")

    def delete_file(self, file_id: str) -> bool:
        """Deletes/trashes a file by file_id."""
        folder_id = self.get_bucket_folder_id()
        try:
            file_info = (
                self.service.files()
                .get(fileId=file_id, fields="id, parents, trashed")
                .execute()
            )
        except HttpError as e:
            if e.resp.status == 404:
                raise FileNotFoundError(f"File {file_id} not found.")
            raise DriveError(f"Failed to check file before deletion: {e}")

        if file_info.get("trashed"):
            raise FileNotFoundError(f"File {file_id} not found or already trashed.")
        if folder_id and folder_id not in file_info.get("parents", []):
            raise FileNotFoundError(f"File {file_id} not in bucket folder.")

        try:
            self.service.files().delete(fileId=file_id).execute()
            return True
        except HttpError as e:
            if e.resp.status == 404:
                raise FileNotFoundError(f"File {file_id} not found.")
            raise DriveError(f"Failed to delete file: {e}")
