# autofic_core/github_handler.py

import os
from github import Github
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()  # .env 파일에서 환경 변수 로드

def parse_repo_url(repo_url):
    """URL에서 사용자명/저장소명을 추출"""
    path = urlparse(repo_url).path.strip("/")
    owner, repo_name = path.split("/")[:2]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    return owner, repo_name

def get_repo_files(repo_url, file_extensions=(".js", ".mjs", ".jsx", ".ts"), silent=False):
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN이 .env에 없습니다.")

    print("GitHub API 인증 시도 중")

    try:
        g = Github(token)
        user = g.get_user()
        print(f"인증 성공! 연결된 계정: {user.login}")
    except Exception as e:
        print("GitHub 인증 실패:", e)
        return []

    try:
        owner, repo_name = parse_repo_url(repo_url)
        repo = g.get_repo(f"{owner}/{repo_name}")
        print(f"저장소: {repo.full_name} (기본 브랜치: {repo.default_branch})")
    except Exception as e:
        print("저장소 불러오기 실패:", e)
        return []
    
    target_exts = (".js", ".mjs", ".jsx", ".ts")

    js_files = []
    contents = repo.get_contents("")

    print("탐색 중입니다.")

    while contents:
        file_content = contents.pop(0)
        if not silent:
            print(f"탐색 중: {file_content.path} ({file_content.type})")
        if file_content.type == "dir":
            contents.extend(repo.get_contents(file_content.path))
        elif file_content.name.endswith(file_extensions) and file_content.download_url:
            js_files.append({
                "path": file_content.path,
                "download_url": file_content.download_url
            })
            if not silent:
                print(f"발견: {file_content.path}")
                
    print(f"JS 파일 {len(js_files)}개를 찾았습니다:")

    return js_files
