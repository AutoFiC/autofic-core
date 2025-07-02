from pathlib import Path
import re

class DiffGenerator:
    def __init__(self, repo_dir: Path, diff_dir: Path):
        self.repo_dir = repo_dir    # repo_dir : 원본 코드 저장소 최상위 경로
        self.diff_dir = diff_dir    # diff_dir : diff 파일들이 저장된 경로


    # flatten 된 파일명을 repo 내 상대경로 변환
    # 예: 'core_appHandler.js' -> Path('core/appHandler.js')
    def flatten_to_relative_path(self, flat_name: str) -> Path:
        parts = flat_name.split("_")
        return Path(*parts[:-1]) / parts[-1] 


    # '003_core_appHandler.js' -> start_line: 3 (int) / flatten_file_name: 'core_appHandler.js' (str) 추출
    def parse_diff_filename(self, diff_filename: str) -> tuple[int, str]:
        m = re.match(r"(\d{3})_(.+)$", diff_filename)
        if not m:
            raise ValueError(f"[ ERROR ] 잘못된 diff 파일명 형식: {diff_filename}")

        start_line = int(m.group(1))
        flatten_name = m.group(2)
        return start_line, flatten_name     # 반환 : (start_line, flatten_file_name)


    # diff_dir 내 모든 js 파일 리스트 반환
    def get_diff_files(self):
        return list(self.diff_dir.glob("*.js"))


    # 원본 repo 내 경로 매칭 후 diff 내용과 함께 리스트로 반환 (파일 읽기)
    def load_diffs(self):
        diff_files = self.get_diff_files()
        diffs = []

        for diff_file in diff_files:
            try:
                start_line, flat_filename = self.parse_diff_filename(diff_file.name)
                source_path = self.repo_dir / self.flatten_to_relative_path(flat_filename)

                if not source_path.exists():
                    print(f"[ WARN ] 원본 파일이 없습니다: {source_path}")
                    continue

                diff_content = diff_file.read_text(encoding="utf-8")

                diffs.append({
                    "start_line": start_line,
                    "flat_filename": flat_filename,
                    "source_path": source_path,
                    "diff_content": diff_content,
                })
            except Exception as e:
                print(f"[ ERROR ] diff 파일 처리 실패: {diff_file} - {e}")

        return diffs