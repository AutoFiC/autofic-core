import subprocess
from pydantic import BaseModel  

class SemgrepResult(BaseModel):
    stdout: str
    stderr: str
    returncode: int

class SemgrepRunner(BaseModel):
    repo_path: str
    rule: str

    def run_semgrep(self) -> SemgrepResult: 
        cmd = [
            "semgrep",
            "--config", self.rule,
            "--json",
            "--include", "*.js", 
            "--include", "*.jsx", 
            "--include", "*.mjs",
            self.repo_path
        ]
    
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', check=True)
            return SemgrepResult(stdout=completed.stdout, stderr=completed.stderr, returncode=completed.returncode)
        except subprocess.CalledProcessError as err:
            return SemgrepResult(stdout=err.stdout, stderr=err.stderr, returncode=err.returncode)