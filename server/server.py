import os
import json
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

class FlaskProcedure:
    """
    A class to manage logging of pull requests and repository statuses.

    This class provides methods to read from, write to, and modify a JSON file
    that acts as a simple log database. It is designed to separate data management
    logic from the Flask routes for better modularity and testability.

    Attributes:
        log_path (str): The absolute path to the log.json file.
    """
    def __init__(self, log_path):
        self.log_path = log_path
        if not os.path.exists(self.log_path):
            self.save_log({"prs": [], "repos": []})

    def load_log(self):
        with open(self.log_path, encoding='utf-8') as f:
            return json.load(f)

    def save_log(self, data):
        with open(self.log_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def reset_log(self):
        empty_log = {"prs": [], "repos": []}
        self.save_log(empty_log)

    def is_same_repo_entry(self, existing, new):
        return all(
            existing.get(k) == new.get(k)
            for k in [
                "name", "owner", "repo_url",
                "vulnerabilities", "byClass",
                "sastTool", "rerun", "analysis"
            ]
        )

    def add_pr(self, new_pr):
        data = self.load_log()
        data.setdefault("prs", []).append(new_pr)
        self.save_log(data)
        return new_pr

    def add_repo_status(self, new_repo):
        data = self.load_log()
        repos = data.setdefault("repos", [])
        data["repos"] = [r for r in repos if not self.is_same_repo_entry(r, new_repo)]
        data["repos"].append(new_repo)
        self.save_log(data)
        return new_repo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, 'log.json')
flask_manager = FlaskProcedure(LOG_PATH)

@app.route('/log.json', methods=['GET'])
def get_log():
    return send_file(flask_manager.log_path)

@app.route('/log.json', methods=['PUT'])
def put_log():
    data = request.get_json()
    flask_manager.save_log(data)
    return jsonify({"status": "ok"})

@app.route('/reset_log', methods=['POST'])
def reset_log():
    flask_manager.reset_log()
    return jsonify({"status": "reset"})

@app.route('/add_pr', methods=['POST'])
def add_pr():
    new_pr = request.get_json()
    added_pr = flask_manager.add_pr(new_pr)
    return jsonify({"status": "added", "pr": added_pr})

@app.route('/add_repo_status', methods=['POST'])
def add_repo_status():
    new_repo = request.get_json()
    added_repo = flask_manager.add_repo_status(new_repo)
    return jsonify({"status": "added", "repo": added_repo})

@app.route('/update_approval', methods=['POST'])
def update_approval():
    data = request.get_json()
    pr_number = data.get("pr_number")
    approved = data.get("approved")
    opened = data.get("opened")
    repo_url = data.get("repo_url")

    if pr_number is None:
        return jsonify({"error": "pr_number is required"}), 400

    log_data = flask_manager.load_log()
    updated = False

    for pr in log_data.get("prs", []):
        if pr.get("pr_number") == pr_number and pr.get("repo_url") ==repo_url:
            pr["approved"] = approved
            pr["opened"] =  opened
            updated = True

    if updated:
        flask_manager.save_log(log_data)
        return jsonify({"status": "updated", "pr_number": pr_number})
    else:
        return jsonify({"error": "PR not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
