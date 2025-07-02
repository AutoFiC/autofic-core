from pathlib import Path
from typing import List, Dict
from collections import defaultdict
import shutil

class DiffMerger:
    def __init__(self, diffs: List[dict], clone_path: Path, result_path: Path):
        self.diffs = diffs
        self.clone_path = clone_path
        self.result_path = result_path


    # 파일명 기준 diff 그룹핑, 그룹 내에서는 start_line 기준으로 내림차순 정렬
    def group_and_sort_diffs(self) -> Dict[str, List[dict]]:
        grouped = defaultdict(list)
        for diff in self.diffs:
            grouped[diff["flat_filename"]].append(diff)

        for filename in grouped:
            grouped[filename].sort(key=lambda d: d["start_line"], reverse=True)
        return grouped


    # 원본 파일들을 결과 경로에 복사하여 병합 준비
    def prepare_target_files(self, grouped_diffs: Dict[str, List[dict]]) -> Dict[str, Path]:
        filename_to_target_path = {}

        for filename, diffs in grouped_diffs.items():
            source_path = diffs[0]["source_path"]
            relative_path = source_path.relative_to(self.clone_path)
            target_path = self.result_path / relative_path

            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, target_path)

            filename_to_target_path[filename] = target_path

        return filename_to_target_path


    # 특정 파일의 특정 라인 범위를 새로운 코드로 덮어쓰기
    def merge_diff_to_file(self, file_path: Path, start_line: int, new_code: str, end_line: int = None) -> None:
        lines = file_path.read_text(encoding="utf-8").splitlines()
        new_code_lines = new_code.splitlines()

        if end_line is None:
            end_line = start_line + len(new_code_lines) - 1

        merged_lines = lines[:start_line - 1] + new_code_lines + lines[end_line:]
        file_path.write_text("\n".join(merged_lines), encoding="utf-8")


    # 위 3단계를 차례로 실행해 전체 diff 병합 완료
    def merge_all(self) -> None:
        grouped = self.group_and_sort_diffs()
        target_paths = self.prepare_target_files(grouped)

        for filename, diffs in grouped.items():
            target_path = target_paths[filename]
            for diff in diffs:
                self.merge_diff_to_file(
                    file_path=target_path,
                    start_line=diff["start_line"],
                    new_code=diff["diff_content"]
                )