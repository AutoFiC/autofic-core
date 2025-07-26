import os
import sys
from pathlib import Path
import traceback

from rich.console import Console
from autofic_core.errors import *
from autofic_core.utils.ui_utils import print_help_message
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
            self._validate_options()
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
                self._run_pr(pipeline)

        except AutoficError as e:
            console.print(str(e), style="red")
            sys.exit(1)

        except Exception as e:
            console.print(f"[ UNEXPECTED ERROR ] {str(e)}", style="red")
            console.print(traceback.format_exc(), style="red")
            sys.exit(1)

    def _validate_options(self):
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

    def _run_pr(self, pipeline):
        # PR automation
        branch_num = 1
        base_branch = 'main'
        branch_name = "UNKNOWN"
        repo_name = "UNKOWN"
        upstream_owner = "UNKOWN"
        save_dir = Path(self.save_dir).joinpath('repo')
        repo_url = self.repo.rstrip('/').replace('.git', '')
        secret_discord = os.getenv('DISCORD_WEBHOOK_URL')
        secret_slack = os.getenv('SLACK_WEBHOOK_URL')
        token = os.getenv('GITHUB_TOKEN')
        user_name = os.getenv('USER_NAME')

        # Define PRProcedure class
        json_path = str(Path(self.save_dir).joinpath("sast") / "before.json")
        tool = self.sast.lower() if self.sast else None
        pr_procedure = PRProcedure(
            base_branch, repo_name, upstream_owner,
            save_dir, repo_url, token, user_name, json_path, tool
        )
        # Chapter 1
        pr_procedure.post_init()
        repo_name = pr_procedure.repo_name
        upstream_owner = pr_procedure.upstream_owner
        # Chaper 2
        pr_procedure.mv_workdir()
        # Chapter 3
        pr_procedure.check_branch_exists()
        branch_name = pr_procedure.branch_name
        # Chapter 4
        EnvEncrypy(user_name, repo_name, token).webhook_secret_notifier('DISCORD_WEBHOOK_URL', secret_discord)
        EnvEncrypy(user_name, repo_name, token).webhook_secret_notifier('SLACK_WEBHOOK_URL', secret_slack)
        # Chapter 5
        AboutYml().create_pr_yml()
        AboutYml().push_pr_yml(user_name, repo_name, token, branch_name)
        # Chapter 6
        pr_procedure.change_files()
        # Chapter 7
        pr_procedure.current_main_branch()
        # Chapter 8,9
        pr_procedure.generate_pr()
        pr_number = pr_procedure.create_pr()

        # for log
        if(pr_number):
            repo_data = self.log_gen.generate_repo_log(save_dir=Path(self.save_dir), name=repo_name, owner=upstream_owner,
                                                       repo_url=repo_url, sastTool=tool, rerun=self.llm_retry)
            pr_log_data = self.log_gen.generate_pr_log(owner=upstream_owner, repo=repo_name, user_name=user_name,
                                                       repo_url=repo_url, repo_hash=repo_data["repo_hash"], pr_number=pr_number)
            self.log_manager.add_pr_log(pr_log_data)
            self.log_manager.add_repo_status(repo_data)