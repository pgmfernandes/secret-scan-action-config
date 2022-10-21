import json

from utility import get_json_property
from utility import get_json_property


class SecretConfig:
    def __init__(self, custom_obj):
        self.enabled = get_json_property(custom_obj, "enabled")
        self.custom_payload = get_json_property(custom_obj, "custom_payload")
        self.exception = get_json_property(custom_obj, "exception")


class ConfigPipeline:

    SECRET_SCAN_CONFIG_GITLEKAS = "secret_scan_gitleaks"
    SECRET_SCAN_CONFIG_SEMGREP = "secret_scan_semgrep"
    SECRET_SCAN_CONFIG_TRIVY = "secret_scan_trivy"
    REPOSITORY_LBL = 'repository'
    ORGANIZATION_LBL = 'organization'
    NAME_LBL = 'name'
    HISTORY_LBL = 'history'
    CONFIG_LBL = 'config'

    def __init__(self, json_obj):
        repository = json_obj[ConfigPipeline.REPOSITORY_LBL]
        self.org = repository[ConfigPipeline.ORGANIZATION_LBL]
        self.name = repository[ConfigPipeline.NAME_LBL]
        self.history = json_obj[ConfigPipeline.HISTORY_LBL]
        self.config = json_obj[ConfigPipeline.CONFIG_LBL]
        self.gitleaks = None
        self.semgrep = None
        self.trivy = None
        if self.config is not None:
            if ConfigPipeline.SECRET_SCAN_CONFIG_GITLEKAS in self.config:
                self.gitleaks = SecretConfig(self.config[ConfigPipeline.SECRET_SCAN_CONFIG_GITLEKAS])
            if ConfigPipeline.SECRET_SCAN_CONFIG_SEMGREP in self.config:
                self.semgrep = SecretConfig(self.config[ConfigPipeline.SECRET_SCAN_CONFIG_SEMGREP])
            if ConfigPipeline.SECRET_SCAN_CONFIG_TRIVY in self.config:
                self.trivy = SecretConfig(self.config[ConfigPipeline.SECRET_SCAN_CONFIG_TRIVY])

    @staticmethod
    def create_default():
        json_obj = {
            ConfigPipeline.REPOSITORY_LBL: {
                ConfigPipeline.ORGANIZATION_LBL: ConfigPipeline.UNDEFINED,
                ConfigPipeline.NAME_LBL: ConfigPipeline.UNDEFINED,
                ConfigPipeline.HISTORY_LBL: None,
                ConfigPipeline.CONFIG_LBL: None,
            }
        }
        default_object = ConfigPipeline(json_obj=json_obj)
        return default_object


class ConfigPipelineHelper:
    @staticmethod
    def parse_config_pipeline_from_json(json_content) -> ConfigPipeline:
        resultDict = json.loads(json_content)
        obj = ConfigPipeline(resultDict)
        return obj
