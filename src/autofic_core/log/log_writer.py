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

import requests
import os

class LogManager:
    def __init__(self):
        self.api_base_url = (os.getenv('LOG_API_URL')).rstrip('/')

    def add_pr_log(self, pr_data):
        url = f"{self.api_base_url}/add_pr"
        response = requests.post(url, json=pr_data)
        response.raise_for_status()
        return response.json()

    def add_repo_status(self, repo_data):
        url = f"{self.api_base_url}/add_repo_status"
        response = requests.post(url, json=repo_data)
        response.raise_for_status()
        return response.json()
