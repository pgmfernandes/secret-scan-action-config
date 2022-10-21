import base64
import requests
import urllib3


class CyberConfigRepositoryManager:
    config_org_name = "pgmfernandes"
    config_repo_name = "config-files-examples"
    config_branch_name = "main"

    def __init__(self, github_auth):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'Authorization': f"Bearer {github_auth}",
            "Content-Type": "application/json",
            'Accept': "application/vnd.github+json"
        })
        urllib3.disable_warnings()

    def get_config_json(self, owner_and_repo_name):
        config = self.get_config(owner_and_repo_name)
        if config is not None:
            decoded = base64.b64decode(config['content'])
            original_str = decoded.decode('utf-8')
            return original_str
        return None

    def get_config(self, owner_and_repo_name):
        url = f"https://api.github.com/repos/{CyberConfigRepositoryManager.config_org_name}/{CyberConfigRepositoryManager.config_repo_name}/contents/{owner_and_repo_name}.json"
        print(f"URL: {url}")
        response = self.session.get(url)
        if response.status_code == 200:
            print(f"::debug::Config file for {owner_and_repo_name} was found it.")
            config = response.json()
            return config
        elif response.status_code == 401:
            print("::debug::Github did not authorized this request. You probably set a  not valid Github PAT.")
        elif response.status_code == 404:
            print("::debug::Repository not found.")
        return None
