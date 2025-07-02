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

"""Contains their functional aliases.
"""
import os
import subprocess
import click

# Handles creation and git operations for GitHub Actions workflow YAML files
class AboutYml:
    """
    Class for managing GitHub Actions workflow YAML files.
    Provides methods to create workflow files and push them to a repository.
    """
    def __init__(self, start_dir="."):
        """
        Initialize with the starting directory (default: current directory).
        :param start_dir: Base directory for workflow file operations.
        """
        self.start_dir = start_dir
        
    def create_pr_yml(self):
        """
        Create the 'pr_notify.yml' GitHub Actions workflow file.
        This workflow sends notifications to Discord and Slack when a pull request is opened, reopened, or closed.
        """
        workflow_dir = os.path.join(self.start_dir, ".github", "workflows")
        os.makedirs(workflow_dir, exist_ok=True)

        pr_notify_yml_path = os.path.join(workflow_dir, "pr_notify.yml")
        pr_notify_yml_content = """name: PR Notifier

on:
  pull_request:
    types: [opened, reopened, closed]

jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - name: Notify Discord
        env:
          DISCORD_WEBHOOK_URL: ${{ secrets.DISCORD_WEBHOOK_URL }}
        run: |
          curl -H "Content-Type: application/json" \
          -d '{"content": "🔔 Pull Request [${{ github.event.pull_request.title }}](${{ github.event.pull_request.html_url }}) by ${{ github.event.pull_request.user.login }} - ${{ github.event.action }}"}' \
          $DISCORD_WEBHOOK_URL
      - name: Notify Slack
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
        run: |
          curl -H "Content-Type: application/json" \
          -d '{"text": ":bell: Pull Request <${{ github.event.pull_request.html_url }}|${{ github.event.pull_request.title }}> by ${{ github.event.pull_request.user.login }} - ${{ github.event.action }}"}' \
          $SLACK_WEBHOOK_URL
"""
        with open(pr_notify_yml_path, "w", encoding="utf-8") as f:
            f.write(pr_notify_yml_content)
            
    def push_pr_yml(self, user_name, repo_name, token, branch_name):
        """
        Adds, commits, and pushes the created workflow YAML file to the specified git branch.
        The remote URL is set to use the provided GitHub token for authentication. (Needed!)

        :param user_name: GitHub username (repository owner)
        :param repo_name: Name of the repository
        :param token: GitHub access token (for authentication)
        :param branch_name: Name of the branch to push to
        """
        repo_url = f'https://x-access-token:{token}@github.com/{user_name}/{repo_name}.git'
        subprocess.run(['git', 'remote', 'set-url', 'origin', repo_url], check=True)
        click.secho("[ INFO ] Pushing the generated .github/workflows/pr_notify.yml.", fg="yellow")
        subprocess.run(['git', 'add', '.github/workflows/pr_notify.yml'], check=True)
        subprocess.run(['git', 'commit', '-m', "[Autofic] Create package.json and CI workflow"], check=True)
        subprocess.run(['git', 'push', 'origin', branch_name], check=True)
