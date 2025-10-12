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
import click
from pathlib import Path
from openai import OpenAI
from typing import Any
from dotenv import load_dotenv
from autofic_core.errors import LLMExecutionError
from autofic_core.sast.merger import merge_snippets_by_file
from autofic_core.llm.prompt_generator import PromptGenerator

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class LLMRunner:
    """
    Run LLM with a given prompt.
    """
    def __init__(self, model="gpt-4o"):
        self.model = model

    def run(self, prompt: str) -> str:
        """
        Run prompt and return response.
        Raises:
            LLMExecutionError: On OpenAI error
        """
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security code fixer."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise LLMExecutionError(str(e))


def save_md_response(content: str, prompt_obj: Any, output_dir: Path) -> str:
    """
    Save response to a markdown file.
    Returns:
        Path: Saved file path
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        path = Path(prompt_obj.snippet.path if hasattr(prompt_obj, "snippet") else prompt_obj.path)
    except Exception as e:
        raise RuntimeError(f"[ERROR] Failed to resolve output path: {e}")

    parts = [p for p in path.parts if p not in ("artifacts", "downloaded_repo")]
    flat_path = "_".join(parts)
    output_path = output_dir / f"response_{flat_path}.md"

    output_path.write_text(content, encoding="utf-8")
    return output_path


def run_llm_for_semgrep_results(
    semgrep_json_path: str,
    output_dir: Path,
    tool: str = "semgrep",
    model: str = "gpt-4o",
) -> None:
    """
    Run LLM for all prompts from a SAST result.
    """
    if tool == "semgrep":
        from autofic_core.sast.semgrep.preprocessor import SemgrepPreprocessor as Preprocessor
    elif tool == "codeql":
        from autofic_core.sast.codeql.preprocessor import CodeQLPreprocessor as Preprocessor
    elif tool == "snykcode":
        from autofic_core.sast.snykcode.preprocessor import SnykCodePreprocessor as Preprocessor
    else:
        raise ValueError(f"Unsupported SAST tool: {tool}")

    raw_snippets = Preprocessor.preprocess(semgrep_json_path)
    merged_snippets = merge_snippets_by_file(raw_snippets)
    prompts = PromptGenerator().generate_prompts(merged_snippets)
    runner = LLMRunner(model=model)

    for prompt in prompts:
        try:
            result = runner.run(prompt.prompt)
            save_md_response(result, prompt, output_dir)
        except LLMExecutionError:
            continue