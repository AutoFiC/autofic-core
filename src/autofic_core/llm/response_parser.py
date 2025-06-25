from pathlib import Path
import re

class ResponseParser:
    def __init__(self, md_dir: Path, diff_dir: Path, lang: str = "js"):
        self.md_dir = md_dir
        self.diff_dir = diff_dir
        self.lang = lang
        self.diff_dir.mkdir(parents=True, exist_ok=True)

    def extract_code_blocks(self, md_text: str) -> list[str]:
        """
        md 텍스트에서 js 또는 javascript 코드블럭만 추출
        """
        lang_pattern = r"js|javascript"
        pattern = re.compile(rf"```({lang_pattern})\s+(.*?)```", re.DOTALL)
        matches = pattern.findall(md_text)
        return [code.strip() for lang, code in matches]

    def parse_filename(self, md_file: Path):
        """
        md 파일명에서 start_line, 원본 파일명 파싱
        예: response_foo.py_3.md → ('foo.py', 3)
        """
        stem = md_file.stem
        if not stem.startswith("response_"):
            raise ValueError(f"예상하지 못한 md 파일명 형식입니다: {md_file.name}")

        rest = stem[len("response_"):]
        idx = rest.rfind("_")
        if idx == -1:
            raise ValueError(f"파일명에서 start_line 구분자를 찾을 수 없습니다: {md_file.name}")

        filename = rest[:idx]
        start_line_str = rest[idx+1:]

        try:
            start_line = int(start_line_str)
        except ValueError:
            raise ValueError(f"start_line 정수 변환에 실패했습니다: {md_file.name}")

        return filename, start_line

    def extract_and_save_all(self) -> bool:
        """
        md_dir 내 모든 .md 파일을 처리해서 diff_dir에 저장
        성공하면 True, 실패나 경고 있으면 False 리턴
        """
        success = True
        for md_file in self.md_dir.glob("*.md"):
            try:
                filename, start_line = self.parse_filename(md_file)
            except ValueError as e:
                print(f"[Warning] {e}")
                success = False
                continue

            md_text = md_file.read_text(encoding="utf-8")
            code_blocks = self.extract_code_blocks(md_text)

            if not code_blocks:
                print(f"[Warning] 코드 블럭을 찾지 못했습니다: {md_file.name}")
                success = False
                continue

            diff_path = self.diff_dir / f"{start_line:03d}_{filename}"

            try:
                with diff_path.open("w", encoding="utf-8") as f:
                    for block in code_blocks:
                        f.write(block + "\n\n")
                print(f"[Info] diff 파일 생성 완료: {diff_path}")
            except Exception as e:
                print(f"[Error] diff 파일 생성 실패 ({diff_path}): {e}")
                success = False

        return success