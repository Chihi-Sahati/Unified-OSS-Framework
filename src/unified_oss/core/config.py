"""
Configuration management for Unified OSS Framework.

Provides centralized configuration loading and access.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import os


@dataclass
class DatabaseConfig:
    """Database connection configuration."""
    
    host: str = "localhost"
    port: int = 5432
    database: str = "unified_oss"
    username: str = "postgres"
    password: str = ""
    pool_size: int = 10
    max_overflow: int = 20
    
    @property
    def connection_string(self) -> str:
        """Generate PostgreSQL connection string."""
        return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"


@dataclass
class RedisConfig:
    """Redis cache configuration."""
    
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    ttl_seconds: int = 3600


@dataclass
class KafkaConfig:
    """Kafka streaming configuration."""
    
    bootstrap_servers: str = "localhost:9092"
    consumer_group: str = "unified-oss-consumer"
    auto_offset_reset: str = "earliest"
    enable_auto_commit: bool = False


@dataclass
class NetconfConfig:
    """NETCONF connection configuration."""
    
    default_port: int = 830
    default_timeout: int = 30
    max_sessions: int = 10
    keepalive_interval: int = 60


@dataclass
class SecurityConfig:
    """Security and authentication configuration."""
    
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    token_expiry_hours: int = 24
    mfa_enabled: bool = False
    zero_trust_enabled: bool = True


@dataclass
class Config:
    """
    Main configuration container for Unified OSS Framework.
    
    Provides centralized access to all configuration settings
    including database, cache, messaging, and security.
    """
    
    app_name: str = "Unified OSS Framework"
    version: str = "1.0.0"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"
    
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    kafka: KafkaConfig = field(default_factory=KafkaConfig)
    netconf: NetconfConfig = field(default_factory=NetconfConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    vendor_endpoints: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    @classmethod
    def from_env(cls) -> "Config":
        """
        Load configuration from environment variables.
        
        Returns:
            Config instance populated from environment.
        """
        config = cls()
        
        # Database configuration
        config.database.host = os.getenv("DB_HOST", config.database.host)
        config.database.port = int(os.getenv("DB_PORT", config.database.port))
        config.database.database = os.getenv("DB_NAME", config.database.database)
        config.database.username = os.getenv("DB_USER", config.database.username)
        config.database.password = os.getenv("DB_PASSWORD", "")
        
        # Redis configuration
        config.redis.host = os.getenv("REDIS_HOST", config.redis.host)
        config.redis.port = int(os.getenv("REDIS_PORT", config.redis.port))
        
        # Kafka configuration
        config.kafka.bootstrap_servers = os.getenv(
            "KAFKA_BOOTSTRAP_SERVERS", 
            config.kafka.bootstrap_servers
        )
        
        # Security configuration
        config.security.jwt_secret = os.getenv(
            "JWT_SECRET", 
            config.security.jwt_secret
        )
        
        # Environment
        config.environment = os.getenv("ENVIRONMENT", config.environment)
        config.debug = os.getenv("DEBUG", "false").lower() == "true"
        config.log_level = os.getenv("LOG_LEVEL", config.log_level)
        
        return config
    
    @classmethod
    def from_file(cls, path: str) -> "Config":
        """
        Load configuration from JSON file.
        
        Args:
            path: Path to configuration file.
            
        Returns:
            Config instance populated from file.
        """
        file_path = Path(path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        
        with open(file_path, "r") as f:
            data = json.load(f)
        
        config = cls()
        
        # Load main config
        config.app_name = data.get("app_name", config.app_name)
        config.version = data.get("version", config.version)
        config.environment = data.get("environment", config.environment)
        config.debug = data.get("debug", config.debug)
        config.log_level = data.get("log_level", config.log_level)
        
        # Load database config
        if "database" in data:
            db_data = data["database"]
            config.database = DatabaseConfig(**db_data)
        
        # Load redis config
        if "redis" in data:
            redis_data = data["redis"]
            config.redis = RedisConfig(**redis_data)
        
        # Load kafka config
        if "kafka" in data:
            kafka_data = data["kafka"]
            config.kafka = KafkaConfig(**kafka_data)
        
        # Load netconf config
        if "netconf" in data:
            netconf_data = data["netconf"]
            config.netconf = NetconfConfig(**netconf_data)
        
        # Load security config
        if "security" in data:
            security_data = data["security"]
            config.security = SecurityConfig(**security_data)
        
        # Load vendor endpoints
        config.vendor_endpoints = data.get("vendor_endpoints", {})
        
        return config


class ConfigLoader:
    """
    Configuration loader with support for multiple sources.
    
    Supports loading configuration from:
    - Environment variables
    - JSON/YAML files
    - Default values
    """
    
    _instance: Optional["ConfigLoader"] = None
    _config: Optional[Config] = None
    
    def __new__(cls) -> "ConfigLoader":
        """Singleton pattern for configuration loader."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def load(self, config_path: Optional[str] = None) -> Config:
        """
        Load configuration from available sources.
        
        Priority order:
        1. Environment variables (highest)
        2. Configuration file (if provided)
        3. Default values (lowest)
        
        Args:
            config_path: Optional path to configuration file.
            
        Returns:
            Loaded configuration instance.
        """
        # Start with defaults
        config = Config()
        
        # Load from file if provided
        if config_path:
            config = Config.from_file(config_path)
        
        # Override with environment variables
        env_config = Config.from_env()
        
        # Merge environment overrides
        if os.getenv("DB_HOST"):
            config.database.host = env_config.database.host
        if os.getenv("DB_PORT"):
            config.database.port = env_config.database.port
        if os.getenv("DB_USER"):
            config.database.username = env_config.database.username
        if os.getenv("DB_PASSWORD"):
            config.database.password = env_config.database.password
        if os.getenv("REDIS_HOST"):
            config.redis.host = env_config.redis.host
        if os.getenv("KAFKA_BOOTSTRAP_SERVERS"):
            config.kafka.bootstrap_servers = env_config.kafka.bootstrap_servers
        if os.getenv("JWT_SECRET"):
            config.security.jwt_secret = env_config.security.jwt_secret
        if os.getenv("ENVIRONMENT"):
            config.environment = env_config.environment
        if os.getenv("DEBUG"):
            config.debug = env_config.debug
        if os.getenv("LOG_LEVEL"):
            config.log_level = env_config.log_level
        
        self._config = config
        return config
    
    @property
    def config(self) -> Config:
        """
        Get current configuration.
        
        Returns:
            Current configuration instance.
            
        Raises:
            RuntimeError: If configuration has not been loaded.
        """
        if self._config is None:
            raise RuntimeError("Configuration not loaded. Call load() first.")
        return self._config
    
    def reload(self, config_path: Optional[str] = None) -> Config:
        """
        Reload configuration from sources.
        
        Args:
            config_path: Optional path to configuration file.
            
        Returns:
            Reloaded configuration instance.
        """
        self._config = None
        return self.load(config_path)
