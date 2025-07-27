import os
import sys
import time
import traceback
from pathlib import Path
from rich.console import Console

from autofic_core.errors import *
from autofic_core.utils.ui_utils import print_help_message, print_divider
from autofic_core.pipeline import AutoFiCPipeline
from autofic_core.log.log_writer import LogManager
from autofic_core.log.log_generator import LogGenerator

from autofic_core.pr_auto.create_yml import AboutYml
from autofic_core.pr_auto.env_encrypt import EnvEncrypy
from autofic_core.pr_auto.pr_procedure import PRProcedure

console = Console()

class AutoFiCApp:
    def __init__(self, explain, repo, save_dir, sast, llm, llm_retry, patch, pr):
        self.explain = explain
        self.repo = repo
        self.save_dir = save_dir
        self.sast = sast
        self.llm = llm
        self.llm_retry = llm_retry
        self.patch = patch
        self.pr = pr
        self.log_manager = LogManager()
        self.log_gen = LogGenerator()

    def run(self):
        try:
            self.validate_options()
            if self.explain:
                print_help_message()
                return

            llm_flag = self.llm or self.llm_retry
            pipeline = AutoFiCPipeline(
                repo_url=self.repo,
                save_dir=Path(self.save_dir),
                sast=self.sast,
                sast_tool=self.sast.lower() if self.sast else None,
                llm=llm_flag,
                llm_retry=self.llm_retry,
                patch=self.patch,
                pr=self.pr
            )
            pipeline.run()

            if self.pr:
                self.run_pr()

        except AutoficError as e:
            console.print(str(e), style="red")
            sys.exit(1)

        except Exception as e:
            console.print(f"[ UNEXPECTED ERROR ] {str(e)}", style="red")
            console.print(traceback.format_exc(), style="red")
            sys.exit(1)

    def validate_options(self):
        if not self.repo:
            raise NoRepositoryError()
        if not self.save_dir:
            raise NoSaveDirError()
        if self.llm and self.llm_retry:
            raise LLMRetryOptionError()
        if not self.sast and (self.llm or self.llm_retry):
            raise LLMWithoutSastError()
        if not (self.llm or self.llm_retry) and self.patch:
            raise PatchWithoutLLMError()
        if not self.patch and self.pr:
            raise PRWithoutPatchError()

    def run_pr(self):
        try:
            print_divider("PR Automation Stage")

            pr_procedure = self.initialize_pr_procedure()

            console.print("[1] Initializing PR process & checking branches...\n", style="bold cyan")
            time.sleep(0.5)
            pr_procedure.post_init()
            pr_procedure.mv_workdir()
            pr_procedure.check_branch_exists()

            console.print("\n[2] Notifying webhooks...\n", style="bold cyan")
            time.sleep(0.5)
            self.notify_webhooks(pr_procedure)

            console.print("\n[3] Creating and pushing PR workflow YAML...\n", style="bold cyan")
            time.sleep(0.5)
            self.handle_pr_yml(pr_procedure)

            console.print("\n[4] Changing files for the pull request...\n", style="bold cyan")
            time.sleep(0.5)
            pr_procedure.change_files()

            console.print("\n[5] Updating branch and creating Pull Request...\n", style="bold cyan")
            time.sleep(0.5)
            pr_procedure.current_main_branch()
            pr_procedure.generate_pr()
            pr_number = pr_procedure.create_pr()

            console.print(f"\n[ SUCCESS ] Pull Request created successfully!\n", style="bold green")
            time.sleep(0.5)

            self.finalize_logging(pr_procedure, pr_number)

        except Exception as e:
            console.print(f"[ PR ERROR ] {e}", style="bold red")
            console.print(traceback.format_exc(), style="red")
            raise

    def initialize_pr_procedure(self):
        base_branch = 'main'
        save_dir = Path(self.save_dir).joinpath('repo')
        repo_url = self.repo.rstrip('/').replace('.git', '')
        json_path = str(Path(self.save_dir).joinpath("sast") / "before.json")
        token = os.getenv('GITHUB_TOKEN')
        user_name = os.getenv('USER_NAME')
        tool = self.sast.lower() if self.sast else None

        return PRProcedure(
            base_branch=base_branch,
            repo_name="UNKNOWN",
            upstream_owner="UNKNOWN",
            save_dir=save_dir,
            repo_url=repo_url,
            token=token,
            user_name=user_name,
            json_path=json_path,
            tool=tool
        )

    def notify_webhooks(self, pr_procedure):
        secret_discord = os.getenv('DISCORD_WEBHOOK_URL')
        secret_slack = os.getenv('SLACK_WEBHOOK_URL')

        user_name = pr_procedure.user_name
        repo_name = pr_procedure.repo_name
        token = pr_procedure.token

        EnvEncrypy(user_name, repo_name, token).webhook_secret_notifier('DISCORD_WEBHOOK_URL', secret_discord)
        EnvEncrypy(user_name, repo_name, token).webhook_secret_notifier('SLACK_WEBHOOK_URL', secret_slack)

    def handle_pr_yml(self, pr_procedure):
        user_name = pr_procedure.user_name
        repo_name = pr_procedure.repo_name
        token = pr_procedure.token
        branch_name = pr_procedure.branch_name

        yml_handler = AboutYml()
        yml_handler.create_pr_yml()
        yml_handler.push_pr_yml(user_name, repo_name, token, branch_name)

    def finalize_logging(self, pr_procedure, pr_number):
        tool = self.sast.lower() if self.sast else None
        repo_url = self.repo.rstrip('/').replace('.git', '')

        repo_data = self.log_gen.generate_repo_log(
            save_dir=Path(self.save_dir),
            name=pr_procedure.repo_name,
            owner=pr_procedure.upstream_owner,
            repo_url=repo_url,
            sastTool=tool,
            rerun=self.llm_retry
        )

        pr_log_data = self.log_gen.generate_pr_log(
            owner=pr_procedure.upstream_owner,
            repo=pr_procedure.repo_name,
            user_name=pr_procedure.user_name,
            repo_url=repo_url,
            repo_hash=repo_data["repo_hash"],
            pr_number=pr_number
        )

        self.log_manager.add_pr_log(pr_log_data)
        self.log_manager.add_repo_status(repo_data)