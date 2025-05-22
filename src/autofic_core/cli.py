import click
import argparse
from autofic_core.github_handler import get_repo_files

@click.command()
@click.option('--repo', help='GitHub repository URL')
@click.option('--silent', is_flag=True, help="결과 출력 없이 조용히 실행")
def main(repo, silent):
    click.echo(f"Analyzing repo: {repo}")

    parser = argparse.ArgumentParser(description="AutoFiC CLI")
    parser.add_argument("--repo", type=str, required=True, help="GitHub 저장소 URL 입력")
    parser.add_argument("--silent", action="store_true", help="결과 출력 없이 추출만 수행")  # ✅ 이 줄 추가!

    args = parser.parse_args()

    files = get_repo_files(args.repo, silent=args.silent)

    # 파일 목록 출력 예시
    if not files:
        print("JS 파일을 찾지 못했습니다. 저장소 구조 또는 필터 조건을 확인하세요.")
    elif not args.silent:
        print(f"JS 파일 {len(files)}개를 찾았습니다:")
        for file in files:
            print(f"{file['path']} -> {file['download_url']}")

if __name__ == '__main__':
    main()