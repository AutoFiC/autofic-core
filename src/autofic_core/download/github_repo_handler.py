import os
import requests 
import subprocess
import shutil
from github import Github
from github.Repository import Repository
from urllib.parse import urlparse
from autofic_core.errors import GitHubTokenMissingError, RepoAccessError, RepoURLFormatError, ForkFailedError

class GitHubRepoHandler():
    """GitHub 저장소 URL과 토큰을 이용해 인증하고, 
    필요한 경우 Fork를 수행한 뒤, 저장소 객체를 반환하는 클래스"""
    def __init__(self, repo_url: str):
        self.repo_url = repo_url
        self.token = os.getenv("GITHUB_TOKEN")
        if not self.token:
            raise GitHubTokenMissingError()
        
        self.github = Github(self.token)
        self._owner, self._name = self._parse_repo_url(repo_url)
        self._current_user = self.github.get_user().login

        self.needs_fork = self._owner != self._current_user     # 포크 필요 여부 판단
    
    @staticmethod
    # URL에서 owner와 name 추출
    def _parse_repo_url(url: str) -> tuple[str, str]:
        try:
            path = urlparse(url).path.strip("/")
            owner, repo = path.split("/")[:2]
            return owner, repo.removesuffix(".git")
        except Exception:
            raise RepoURLFormatError(url)
    
    # 저장소 객체 반환 (Fork 여부에 따라 소유자 변경)
    def fetch_repo(self) -> Repository:
        repo_name = f"{self._current_user}/{self._name}"
        try:
            return self.github.get_repo(repo_name)
        except Exception as e:
            raise RepoAccessError(f"{repo_name}: {e}")

    # 저장소를 현재 사용자 계정으로 Fork. 성공 여부 반환
    def fork(self) -> bool:
        api_url = f"https://api.github.com/repos/{self._owner}/{self._name}/forks"
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github+json"
        }
        response = requests.post(api_url, headers=headers)
        if response.status_code == 202:
            return True
        else:
            raise ForkFailedError(response.status_code, response.text)
    
    # 지정된 경로에 저장소 클론. fork 여부에 따라 다른 저장소 URL 사용.
    def clone_repo(self, save_dir: str, use_forked: bool = False) -> str:
        save_dir = os.path.abspath(save_dir)            # 사용자 지정 루트 디렉토리
        repo_path = os.path.join(save_dir, "repo")      # repo 하위 폴더 지정
    
        # 기존 repo 디렉토리가 있다면 삭제
        if os.path.exists(repo_path):
            if os.path.isdir(repo_path):
                shutil.rmtree(repo_path)
            else:
                raise ValueError(f"지정한 경로가 디렉토리가 아닙니다 : {repo_path}")

        clone_url = f"https://github.com/{self._current_user}/{self._name}.git"
        subprocess.run(['git', 'clone', clone_url, repo_path], check=True)
        return repo_path