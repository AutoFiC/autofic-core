import os
import requests
from pydantic import BaseModel, Field
from typing import Optional
from autofic_core.errors import FileDownloadError

class FileInfo(BaseModel):
    path: str
    download_url: str

class DownloadResult(BaseModel):
    path: str
    status: str
    error: Optional[str] = None

class FileDownloader(BaseModel):
    save_dir: str = Field(default="downloaded_repo")

    def download_file(self, file: FileInfo) -> DownloadResult:
        local_path = os.path.join(self.save_dir, file.path)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        if os.path.exists(local_path):
            return DownloadResult(path=file.path, status="skipped")

        try:
            res = requests.get(file.download_url)
            res.raise_for_status()
            with open(local_path, "wb") as f:
                f.write(res.content)
            return DownloadResult(path=file.path, status="success")
    
        except Exception as e:
            return DownloadResult(path=file.path, status="fail", error=str(FileDownloadError(file.path, str(e))))