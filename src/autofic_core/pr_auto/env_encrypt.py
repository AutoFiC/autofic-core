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

import base64
import requests
from nacl import public, encoding
from rich.console import Console

console = Console()

class EnvEncrypy:
    def __init__(self, user_name, repo_name, token):
        self.user_name = user_name
        self.repo_name = repo_name
        self.token = token
        
    def webhook_secret_notifier(self, secret_name: str, webhook_url: str):
        url = f'https://api.github.com/repos/{self.user_name}/{self.repo_name}/actions/secrets/public-key'
        headers = {'Authorization': f'token {self.token}'}
        resp = requests.get(url, headers=headers)
        pubkey_info = resp.json()

        if 'key_id' not in pubkey_info or 'key' not in pubkey_info:
            console.print(f"[ ERROR ] Invalid public key info: {pubkey_info}", style="red")
            return

        key_id = pubkey_info['key_id']
        encrypted_value = self.encrypt(pubkey_info['key'], webhook_url)

        url2 = f'https://api.github.com/repos/{self.user_name}/{self.repo_name}/actions/secrets/{secret_name}'
        payload = {
            "encrypted_value": encrypted_value,
            "key_id": key_id
        }
        resp2 = requests.put(url2, headers={**headers, 'Content-Type': 'application/json'}, json=payload)
        console.print(f"[ INFO ] Secret registered: {secret_name}, {resp2.status_code}, {resp2.text}", style="white")

    def encrypt(self, public_key: str, secret_value: str) -> str:
        public_key = public.PublicKey(public_key, encoding.Base64Encoder())
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")