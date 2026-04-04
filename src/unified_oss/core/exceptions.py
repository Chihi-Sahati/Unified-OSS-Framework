"""
Custom exceptions for Unified OSS Framework.

Provides a hierarchy of exceptions for different error scenarios.
"""

from typing import Any, Dict, Optional


class UnifiedOSSError(Exception):
    """
    Base exception for all Unified OSS Framework errors.
    
    Provides common functionality for error handling including
    error codes, details, and serialization.
    """
    
    error_code: str = "UNIFIED_OSS_ERROR"
    http_status: int = 500
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize exception.
        
        Args:
            message: Human-readable error message.
            error_code: Optional specific error code.
            details: Optional dictionary with additional error details.
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.error_code
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for API responses.
        
        Returns:
            Dictionary representation of the error.
        """
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details,
        }
    
    def __str__(self) -> str:
        """Return string representation of error."""
        if self.details:
            return f"[{self.error_code}] {self.message} - {self.details}"
        return f"[{self.error_code}] {self.message}"


class ConnectionError(UnifiedOSSError):
    """
    Network connection error.
    
    Raised when connection to a network element or service fails.
    """
    
    error_code = "CONNECTION_ERROR"
    http_status = 503
    
    def __init__(
        self,
        message: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
        **kwargs,
    ):
        """
        Initialize connection error.
        
        Args:
            message: Error message.
            host: Target host that failed to connect.
            port: Target port.
            **kwargs: Additional details.
        """
        details = kwargs.get("details", {})
        if host:
            details["host"] = host
        if port:
            details["port"] = port
        kwargs["details"] = details
        super().__init__(message, **kwargs)


class ValidationError(UnifiedOSSError):
    """
    Data validation error.
    
    Raised when data fails validation checks.
    """
    
    error_code = "VALIDATION_ERROR"
    http_status = 400
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        constraint: Optional[str] = None,
        **kwargs,
    ):
        """
        Initialize validation error.
        
        Args:
            message: Error message.
            field: Field that failed validation.
            value: Invalid value.
            constraint: Validation constraint that was violated.
            **kwargs: Additional details.
        """
        details = kwargs.get("details", {})
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)
        if constraint:
            details["constraint"] = constraint
        kwargs["details"] = details
        super().__init__(message, **kwargs)


class ConfigurationError(UnifiedOSSError):
    """
    Configuration error.
    
    Raised when configuration is invalid or missing.
    """
    
    error_code = "CONFIGURATION_ERROR"
    http_status = 500
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        **kwargs,
    ):
        """
        Initialize configuration error.
        
        Args:
            message: Error message.
            config_key: Configuration key that is problematic.
            **kwargs: Additional details.
        """
        details = kwargs.get("details", {})
        if config_key:
            details["config_key"] = config_key
        kwargs["details"] = details
        super().__init__(message, **kwargs)


class TimeoutError(UnifiedOSSError):
    """
    Operation timeout error.
    
    Raised when an operation exceeds its time limit.
    """
    
    error_code = "TIMEOUT_ERROR"
    http_status = 504
    
    def __init__(
        self,
        message: str,
        timeout_seconds: Optional[float] = None,
        operation: Optional[str] = None,
        **kwargs,
    ):
        """
        Initialize timeout error.
        
        Args:
            message: Error message.
            timeout_seconds: Timeout duration that was exceeded.
            operation: Operation that timed out.
            **kwargs: Additional details.
        """
        details = kwargs.get("details", {})
        if timeout_seconds:
            details["timeout_seconds"] = timeout_seconds
        if operation:
            details["operation"] = operation
        kwargs["details"] = details
        super().__init__(message, **kwargs)


class AuthenticationError(UnifiedOSSError):
    """
    Authentication error.
    
    Raised when authentication fails.
    """
    
    error_code = "AUTHENTICATION_ERROR"
    http_status = 401


class AuthorizationError(UnifiedOSSError):
    """
    Authorization error.
    
    Raised when user lacks permission for an operation.
    """
    
    error_code = "AUTHORIZATION_ERROR"
    http_status = 403
    
    def __init__(
        self,
        message: str,
        user: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        **kwargs,
    ):
        """
        Initialize authorization error.
        
        Args:
            message: Error message.
            user: User that was denied access.
            resource: Resource that was accessed.
            action: Action that was attempted.
            **kwargs: Additional details.
        """
        details = kwargs.get("details", {})
        if user:
            details["user"] = user
        if resource:
            details["resource"] = resource
        if action:
            details["action"] = action
        kwargs["details"] = details
        super().__init__(message, **kwargs)


class NotFoundError(UnifiedOSSError):
    """
    Resource not found error.
    
    Raised when a requested resource does not exist.
    """
    
    error_code = "NOT_FOUND_ERROR"
    http_status = 404
    
    def __init__(
        self,
        message: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        **kwargs,
    ):
        """
        Initialize not found error.
        
        Args:
            message: Error message.
            resource_type: Type of resource not found.
            resource_id: ID of resource not found.
            **kwargs: Additional details.
        """
        details = kwargs.get("details", {})
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id:
            details["resource_id"] = resource_id
        kwargs["details"] = details
        super().__init__(message, **kwargs)


class ConflictError(UnifiedOSSError):
    """
    Resource conflict error.
    
    Raised when an operation conflicts with existing state.
    """
    
    error_code = "CONFLICT_ERROR"
    http_status = 409


class RateLimitError(UnifiedOSSError):
    """
    Rate limit exceeded error.
    
    Raised when too many requests are made.
    """
    
    error_code = "RATE_LIMIT_ERROR"
    http_status = 429
    
    def __init__(
        self,
        message: str,
        retry_after: Optional[int] = None,
        **kwargs,
    ):
        """
        Initialize rate limit error.
        
        Args:
            message: Error message.
            retry_after: Seconds until rate limit resets.
            **kwargs: Additional details.
        """
        details = kwargs.get("details", {})
        if retry_after:
            details["retry_after"] = retry_after
        kwargs["details"] = details
        super().__init__(message, **kwargs)


class AlarmProcessingError(UnifiedOSSError):
    """
    Alarm processing error.
    
    Raised when alarm processing fails.
    """
    
    error_code = "ALARM_PROCESSING_ERROR"
    http_status = 500


class ConfigDeploymentError(UnifiedOSSError):
    """
    Configuration deployment error.
    
    Raised when configuration deployment fails.
    """
    
    error_code = "CONFIG_DEPLOYMENT_ERROR"
    http_status = 500
    
    def __init__(
        self,
        message: str,
        ne_id: Optional[str] = None,
        config_version: Optional[str] = None,
        rollback_performed: bool = False,
        **kwargs,
    ):
        """
        Initialize configuration deployment error.
        
        Args:
            message: Error message.
            ne_id: Network element ID.
            config_version: Configuration version.
            rollback_performed: Whether rollback was performed.
            **kwargs: Additional details.
        """
        details = kwargs.get("details", {})
        if ne_id:
            details["ne_id"] = ne_id
        if config_version:
            details["config_version"] = config_version
        details["rollback_performed"] = rollback_performed
        kwargs["details"] = details
        super().__init__(message, **kwargs)


class MappingError(UnifiedOSSError):
    """
    Data mapping error.
    
    Raised when data transformation/mapping fails.
    """
    
    error_code = "MAPPING_ERROR"
    http_status = 500
    
    def __init__(
        self,
        message: str,
        source_path: Optional[str] = None,
        target_path: Optional[str] = None,
        **kwargs,
    ):
        """
        Initialize mapping error.
        
        Args:
            message: Error message.
            source_path: Source data path.
            target_path: Target data path.
            **kwargs: Additional details.
        """
        details = kwargs.get("details", {})
        if source_path:
            details["source_path"] = source_path
        if target_path:
            details["target_path"] = target_path
        kwargs["details"] = details
        super().__init__(message, **kwargs)
