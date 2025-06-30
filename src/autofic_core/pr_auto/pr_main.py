# Copyright 2025 Autofic Authors. All Rights Reserved.
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

"""Contains their functional aliases."""

import os
from .create_yml import AboutYml
from .env_encrypt import EnvEncrypy
from .pr_procedure import PRProcedure

class BranchPRAutomation:
    """
    High-level automation for pull request (PR) creation, including:
    - Repository initialization
    - Branch setup
    - Workflow file management
    - GitHub Actions secret registration (Discord/Slack webhooks)
    - File change/commit/push
    - PR creation (fork and upstream)
    - Status/result tracking

    Each step's result is recorded in the 'self.result' dictionary.
    """

    def __init__(self, repo_url: str, save_dir: str):
        """
        Initialize automation with repository URL and local save directory.
        Loads all required environment variables for authentication and webhooks.

        :param repo_url: URL of the GitHub repository
        :param save_dir: Local directory for repository operations
        """
        self.result = {
            "post_init": False,
            "mv_workdir": False,
            "check_branch": False,
            "discordwebhook": False,
            "slackwebhook": False,
            "create_yml": False,
            "push_yml": False,
            "change_files": False,
            "get_main_branch": False,
            "generate_pr": False,
            "create_upstream_pr": False,
            "error_msg": None,
        }
        self.branch_num = 1
        self.base_branch = 'main'
        self.branch_name = "UNKNOWN"
        self.repo_name = "UNKOWN"
        self.upstream_owner = "UNKOWN"
        self.save_dir = save_dir + '/repo'
        self.repo_url = repo_url.rstrip('/').replace('.git', '')
        self.secret_discord = os.getenv('DISCORD_WEBHOOK_URL')
        self.secret_slack = os.getenv('SLACK_WEBHOOK_URL')
        self.token = os.getenv('GITHUB_TOKEN')
        self.user_name = os.getenv('USER_NAME')
        self.slack_webhook = os.environ.get('SLACK_WEBHOOK_URL')
        self.discord_webhook = os.environ.get('DISCORD_WEBHOOK_URL')

    def run(self):
        """
        Orchestrates the entire PR automation workflow, step-by-step:
        1. Initializes repository and branch info
        2. Moves to the working directory
        3. Checks/creates working branch
        4. Registers Discord and Slack webhooks as GitHub Actions secrets
        5. Creates and pushes the workflow YAML file
        6. Makes file changes and commits/pushes
        7. Determines the main branch name
        8. Creates a pull request on the fork
        9. Creates a PR to the upstream repository
        Returns a dictionary summarizing the status of each step.
        """
        
        # Define PRProcedure class
        pr_procedure = PRProcedure(
            self.base_branch, self.repo_name,
            self.upstream_owner, self.save_dir, self.repo_url,
            self.token, self.user_name
        )
        # Chapter 1
        pr_procedure.post_init()
        self.repo_name = pr_procedure.repo_name
        self.upstream_owner = pr_procedure.upstream_owner
        self.result["post_init"] = True
        # Chaper 2
        pr_procedure.mv_workdir()
        self.result["mv_workdir"] = True
        # Chapter 3
        pr_procedure.check_branch_exists()
        self.branch_name = pr_procedure.branch_name
        self.result["check_branch"] = True
        # Chapter 4
        EnvEncrypy(self.user_name, self.repo_name, self.token).webhook_secret_notifier('DISCORD_WEBHOOK_URL', self.secret_discord)
        self.result["discordwebhook"] = True
        EnvEncrypy(self.user_name, self.repo_name, self.token).webhook_secret_notifier('SLACK_WEBHOOK_URL', self.secret_slack)
        self.result["slackwebhook"] = True
        # Chapter 5
        AboutYml().create_pr_yml()
        self.result["create_yml"] = True
        AboutYml().push_pr_yml(self.user_name, self.repo_name, self.token, self.branch_name)
        self.result["push_yml"] = True
        # Chapter 6
        pr_procedure.change_files()
        self.result["change_files"] = True
        # Chapter 7
        pr_procedure.current_main_branch()
        self.result["get_main_branch"] = True
        # Chapter 8,9
        pr_procedure.generate_pr()
        self.result["generate_pr"] = True
        pr_procedure.create_pr()
        self.result["create_upstream_pr"] = True
        # END
        return self.result