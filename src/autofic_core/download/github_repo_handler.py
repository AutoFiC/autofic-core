# =============================================================================
# Copyright 2025 AutoFiC Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# =============================================================================

import os
import requests 
import subprocess
import shutil
from github import Github
from github.Repository import Repository
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator
from autofic_core.errors import GitHubTokenMissingError, RepoAccessError, RepoURLFormatError, ForkFailedError

class GitHubRepoConfig(BaseModel):
    repo_url: str
    token: str = Field(default_factory=lambda: os.getenv("GITHUB_TOKEN"))

    @field_validator("token")
    def validate_token(cls, v):
        if not v:
            raise GitHubTokenMissingError()
        return v

    def get_owner_and_name(self) -> tuple[str, str]:
        try:
            path = urlparse(self.repo_url).path.strip("/")
            owner, repo = path.split("/")[:2]
            return owner, repo.removesuffix(".git")
        except Exception:
            raise RepoURLFormatError(self.repo_url)


class GitHubRepoHandler():
    def __init__(self, repo_url: str):
        self.repo_url = repo_url
        self.config = GitHubRepoConfig(repo_url=repo_url)
        self.token = self.config.token

        if not self.token or self.token.strip() == "":
            raise GitHubTokenMissingError()
        
        self.github = Github(self.token)
        self._owner, self._name = self.config.get_owner_and_name()

        try:
            self._current_user = self.github.get_user().login
        except Exception as e:
            raise GitHubTokenMissingError()

        self.needs_fork = self._owner != self._current_user     # Determine whether you need a fork
    
    @staticmethod
    def _parse_repo_url(url: str) -> tuple[str, str]:
        try:
            path = urlparse(url).path.strip("/")
            owner, repo = path.split("/")[:2]
            return owner, repo.removesuffix(".git")
        except Exception:
            raise RepoURLFormatError(url)
        
    def fetch_repo(self) -> Repository:
        repo_name = f"{self._current_user}/{self._name}"
        try:
            return self.github.get_repo(repo_name)
        except Exception as e:
            raise RepoAccessError(f"{repo_name}: {e}")

    def fork(self) -> bool:
        api_url = f"https://api.github.com/repos/{self._owner}/{self._name}/forks"
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github+json"
        }
        response = requests.post(api_url, headers=headers)
        if response.status_code == 202:
            return True
        elif response.status_code == 401:
            raise GitHubTokenMissingError("GITHUB_TOKEN is not set in the environment.")
        elif response.status_code == 404:
            raise RepoURLFormatError("Repository not found (404 Not Found).")
        elif response.status_code == 403:
            raise RepoAccessError("Access forbidden to the repository (403 Forbidden).")
        elif response.status_code != 202:
            raise ForkFailedError(response.status_code, response.text)


    def clone_repo(self, save_dir: str, use_forked: bool = False) -> str:
        save_dir = os.path.abspath(save_dir)            # custom root directory
        repo_path = os.path.join(save_dir, "repo")      # Specify repo subfolder
    
        if os.path.exists(repo_path):
            if os.path.isdir(repo_path):
                shutil.rmtree(repo_path)
            else:
                raise ValueError(f"The specified path is not a directory : {repo_path}")

        clone_url = f"https://github.com/{self._current_user}/{self._name}.git"

        try:
            subprocess.run(['git', 'clone', clone_url, repo_path], check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True)
        except subprocess.CalledProcessError as e:
            raise RepoAccessError(e)
        
        return repo_path