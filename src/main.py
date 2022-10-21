import os
import sys

from controller import ConfigRepositoryController

GH_TOKEN_STR = "GH_TOKEN"
GITHUB_REPOSITORY_STR = "GITHUB_REPOSITORY"
SECURE_PIPELINE_TASK = "SECURE_PIPELINE_TASK"

def init():
    if GH_TOKEN_STR not in os.environ:
        raise Exception(f"Environment variable {GH_TOKEN_STR} not defined")
    if GITHUB_REPOSITORY_STR not in os.environ:
        raise Exception(f"Environment variable {GITHUB_REPOSITORY_STR} not defined")
    auth = os.environ[GH_TOKEN_STR]
    github_repository = os.environ[GITHUB_REPOSITORY_STR]
    c = ConfigRepositoryController(github_auth=auth, github_reposiroty=github_repository)
    c.execute_configuration()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        os.environ[GH_TOKEN_STR] = sys.argv[1]
        os.environ[GITHUB_REPOSITORY_STR] = "pgmfernandes/using-custom-python-action"
        os.environ[SECURE_PIPELINE_TASK] = "sast_snyk"
    try:
        init()
    except Exception as err:
        print("::error file=main.py::" + err.__str__())