"""
Configuration management: YAML config + CLI args + environment variables.
"""

import os
import yaml
from typing import Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class GitHubConfig(BaseModel):
    tokens: list[str] = Field(default_factory=list)
    tokens_file: Optional[str] = None
    graphql_enabled: bool = True


class ScanningConfig(BaseModel):
    parallel_jobs: int = 8
    clone_depth: int = 1
    max_repo_size_mb: int = 500
    scan_branches: bool = True
    scan_tags: bool = True
    scan_prs: bool = False
    scan_actions: bool = True
    skip_forks: bool = True
    skip_archived: bool = True
    filter_languages: list[str] = Field(default_factory=list)
    min_stars: int = 0
    max_repos: int = 0
    last_push_within_days: int = 0
    priority_languages: list[str] = Field(
        default_factory=lambda: ["Python", "JavaScript", "Go", "TypeScript", "Java", "Ruby"]
    )


class StealthConfig(BaseModel):
    enabled: bool = False
    proxy_list: Optional[str] = None
    min_delay: float = 3.0
    max_delay: float = 15.0
    user_agents: list[str] = Field(default_factory=lambda: [
        "git/2.39.1", "git/2.39.2", "git/2.40.0", "git/2.40.1",
        "git/2.41.0", "git/2.42.0", "git/2.43.0", "git/2.44.0",
    ])


class ValidationConfig(BaseModel):
    enabled: bool = True
    validate_aws: bool = True
    validate_github: bool = True
    validate_slack: bool = True
    validate_stripe: bool = True
    validate_google: bool = True
    validate_openai: bool = True
    timeout: int = 15


class OutputConfig(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["json", "markdown", "csv"])
    directory: str = "./scans"
    database: str = "ghrecon.db"
    no_store_secrets: bool = False
    keep_repos: bool = False
    encryption_key: Optional[str] = None


class GHReconConfig(BaseModel):
    """Master configuration for GHRecon."""
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    stealth: StealthConfig = Field(default_factory=StealthConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    @classmethod
    def from_yaml(cls, path: str) -> "GHReconConfig":
        """Load config from a YAML file."""
        if not os.path.exists(path):
            return cls()
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)

    @classmethod
    def from_env(cls) -> "GHReconConfig":
        """Build config from environment variables."""
        config = cls()
        if os.environ.get("GITHUB_TOKEN"):
            config.github.tokens = [os.environ["GITHUB_TOKEN"]]
        if os.environ.get("GITHUB_TOKENS"):
            config.github.tokens = [
                t.strip() for t in os.environ["GITHUB_TOKENS"].split(",") if t.strip()
            ]
        if os.environ.get("GHRECON_PARALLEL"):
            config.scanning.parallel_jobs = int(os.environ["GHRECON_PARALLEL"])
        if os.environ.get("GHRECON_STEALTH"):
            config.stealth.enabled = os.environ["GHRECON_STEALTH"].lower() in ("1", "true", "yes")
        if os.environ.get("GHRECON_OUTPUT_DIR"):
            config.output.directory = os.environ["GHRECON_OUTPUT_DIR"]
        if os.environ.get("GHRECON_ENCRYPTION_KEY"):
            config.output.encryption_key = os.environ["GHRECON_ENCRYPTION_KEY"]
        return config

    def merge_cli_args(self, **kwargs) -> "GHReconConfig":
        """Merge CLI arguments into the config (CLI takes precedence)."""
        if kwargs.get("tokens_file"):
            self.github.tokens_file = kwargs["tokens_file"]
            with open(kwargs["tokens_file"]) as f:
                self.github.tokens = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if kwargs.get("parallel"):
            self.scanning.parallel_jobs = kwargs["parallel"]
        if kwargs.get("depth"):
            depth_map = {"shallow": 1, "medium": 50, "full": 0}
            self.scanning.clone_depth = depth_map.get(kwargs["depth"], 1)
        if kwargs.get("max_size"):
            self.scanning.max_repo_size_mb = kwargs["max_size"]
        if kwargs.get("skip_forks") is not None:
            self.scanning.skip_forks = kwargs["skip_forks"]
        if kwargs.get("skip_archived") is not None:
            self.scanning.skip_archived = kwargs["skip_archived"]
        if kwargs.get("scan_branches") is not None:
            self.scanning.scan_branches = kwargs["scan_branches"]
        if kwargs.get("scan_prs") is not None:
            self.scanning.scan_prs = kwargs["scan_prs"]
        if kwargs.get("scan_actions") is not None:
            self.scanning.scan_actions = kwargs["scan_actions"]
        if kwargs.get("stealth"):
            self.stealth.enabled = True
        if kwargs.get("proxy_list"):
            self.stealth.proxy_list = kwargs["proxy_list"]
            self.stealth.enabled = True
        if kwargs.get("validate_secrets") is not None:
            self.validation.enabled = kwargs["validate_secrets"]
        if kwargs.get("output_format"):
            self.output.formats = [f.strip() for f in kwargs["output_format"].split(",")]
        if kwargs.get("output_dir"):
            self.output.directory = kwargs["output_dir"]
        if kwargs.get("no_store_secrets"):
            self.output.no_store_secrets = True
        if kwargs.get("keep_repos"):
            self.output.keep_repos = True
        if kwargs.get("max_repos"):
            self.scanning.max_repos = kwargs["max_repos"]
        return self


def load_config(config_path: Optional[str] = None, **cli_args) -> GHReconConfig:
    """Load configuration with precedence: CLI > YAML > ENV > defaults."""
    # Start with defaults
    config = GHReconConfig()

    # Layer environment variables
    env_config = GHReconConfig.from_env()
    if env_config.github.tokens:
        config.github.tokens = env_config.github.tokens
    if env_config.stealth.enabled:
        config.stealth.enabled = True

    # Layer YAML config
    yaml_path = config_path or "config.yaml"
    if os.path.exists(yaml_path):
        config = GHReconConfig.from_yaml(yaml_path)
        # Re-apply env overrides
        if env_config.github.tokens and not config.github.tokens:
            config.github.tokens = env_config.github.tokens

    # Layer CLI arguments (highest precedence)
    config.merge_cli_args(**cli_args)

    return config
