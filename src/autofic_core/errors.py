class AutoficError(Exception):
    """Base class for all custom errors"""
    pass

# github_handler.py 

class GitHubTokenMissingError(AutoficError):
    def __init__(self):
        message = f"[ ERROR ] GitHub token is missing or invalid: Please ensure that the GITHUB_TOKEN environment variable is set correctly and contains a valid token."
        super().__init__(message)

class RepoURLFormatError(AutoficError):
    def __init__(self, repo_url):
        message = f"[ ERROR ] Invalid GitHub repository URL format: {repo_url}"
        super().__init__(message)

class RepoAccessError(AutoficError):
    def __init__(self, original_error):
        message = f"[ ERROR ] Cannot access repository: {original_error}"
        super().__init__(message)
        self.original_error = original_error

class ForkFailedError(AutoficError):
    def __init__(self, status_code, msg):
        message = f"[ ERROR ] Failed to fork repository (HTTP {status_code}) - {msg}"
        super().__init__(message)
        
class AccessDeniedError(AutoficError):
    def __init__(self, path, original_error):
        message = (
            f"[ ERROR ] Access to the path '{path}' was denied. "
            "Please close any applications or terminals using the directory and try again."
        )
        super().__init__(message)
        self.original_error = original_error

# downloader.py

class FileDownloadError(AutoficError):
    def __init__(self, path, original_error):
        message = f"{path} Failed to download file: {original_error}"
        super().__init__(message)
        self.path = path
        self.original_error = original_error

# semgrep_runner.py

class SemgrepExecutionError(AutoficError):
    def __init__(self, returncode, stdout=None, stderr=None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        message = f"Semgrep execution failed (return code:{returncode})"
        super().__init__(message)

# snykcode_runner.py

class SnykCodeErrorMessages:
    TOKEN_MISSING = "[ ERROR ] SNYK_TOKEN environment variable not set."
    NO_JS_FILES_FOUND = "[ ERROR ] No JavaScript/TypeScript files found to analyze."
    CLI_NOT_FOUND = "[ ERROR ] Unable to locate Snyk CLI. Please install or set SNYK_CMD_PATH."

# prompt_generator.py

class PromptGeneratorErrorCodes:
    EMPTY_SNIPPET = "EMPTY_SNIPPET"
    TEMPLATE_RENDER_ERROR = "TEMPLATE_RENDER_ERROR"
    INVALID_SNIPPET_LIST = "INVALID_SNIPPET_LIST"

class PromptGeneratorErrorMessages:
    EMPTY_SNIPPET = "The provided code snippet is empty."
    TEMPLATE_RENDER_ERROR = "An error occurred while rendering the prompt template."
    INVALID_SNIPPET_LIST = "The input must be a list of SemgrepSnippet objects."

class PromptGenerationException(AutoficError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"[ ERROR ] Prompt generation failed ({code}): {message}")

# response_parser.py

class ResponseParseError(AutoficError):
    def __init__(self, filename: str, reason: str):
        message = f"[ ERROR ] Failed to parse {filename}: {reason}"
        super().__init__(message)
        self.filename = filename
        self.reason = reason

# llm_runner.py

class LLMExecutionError(AutoficError):
    def __init__(self, message: str):
        super().__init__(f"[ ERROR ] LLM execution failed: {message}")
        self.message = message

class CodeQLExecutionError(Exception):
    """Raised when CodeQL execution fails."""
    def __init__(self):
        super().__init__("[ERROR] CodeQL execution failed. Please check the log file for details.")
        
# retry_prompt_generator.py   

class RetryPromptGenerationError(AutoficError):
    def __init__(self, path: str, reason: str):
        message = f"[ ERROR ] Failed to generate retry prompt for {path}: {reason}"
        super().__init__(message)
        self.path = path
        self.reason = reason

# diff_generator.py

class DiffWarningMessages:
    ORIGINAL_FILE_NOT_FOUND = "[ WARN ] Original file not found: {}"

class DiffGenerationError(AutoficError):
    def __init__(self, filename: str, reason: str):
        message = f"[ ERROR ] Failed to generate diff: {filename} - {reason}"
        super().__init__(message)
        self.filename = filename
        self.reason = reason
        

# apply_patch.py

class PatchWarningMessages:
    NO_DIFF_FILES = "[ WARN ] No .diff files found in {}"
    PARSED_FILE_NOT_FOUND = "[ WARN ] Could not find matching file in parsed directory: {}"
    RELATIVE_PATH_EXTRACTION_FAILED = "[ WARN ] Failed to extract relative path: {}"
    ORIGINAL_FILE_MISSING = "[ WARN ] Original file does not exist: {}"
    OVERWRITE_FILE_MISSING = "[ WARN ] Original file does not exist in repo: {}"

class PatchErrorMessages:
    PATCH_EXCEPTION = "[ ERROR ] Exception while applying {}: {}"
    FALLBACK_DIFF_FAILED = "[ ERROR ] Failed to generate fallback diff: {}"
    OVERWRITE_FAILED = "[ ERROR ] Failed to overwrite repo file: {}"

class PatchFailMessages:
    PATCH_FAILED = "[ FAIL ] Patch failed: {}"
    FALLBACK_APPLY_FAILED = "[ FAIL ] Fallback diff failed: {}"

# # cli.py

# class PermissionDeniedError(AutoficError):
#     def __init__(self, original_exception: Exception):
#         message = (
#             f"{original_exception}\n"
#             "Please close any editors or terminals using the folder and try again."
#         )
#         super().__init__(message)

# class UnexpectedAutoficError(AutoficError):
#     def __init__(self, original_exception: Exception):
#         super().__init__("An unexpected error occurred: {original_exception}\n")

# class SASTExecutionError(AutoficError):
#     def __init__(self, tool: str, original_exception: Exception):
#         super().__init__("SAST tool [{tool}] failed to execute: {original_exception}\n")
#         self.tool = tool
#         self.original_exception = original_exception

# class UnknownSnippetTypeError(AutoficError):
#     def __init__(self, obj):
#         super().__init__("Unknown snippet type encountere.")

# class MergedSnippetsLoadError(AutoficError):
#     def __init__(self, original_exception: Exception):
#         super().__init__("Failed to load merged snippets from your path.\n")