"""
Mapping Engine Module for YAML-based mapping rule loading and transformation.

This module provides comprehensive functionality for loading mapping rules from YAML
files and performing bidirectional transformations between vendor-specific formats
and the Common Information Model (CIM).

The module supports:
- YAML parsing for mapping rules
- O(1) lookup indices for forward and reverse mapping
- Severity mapping (Ericsson string → CIM enum, Huawei int → CIM)
- Counter mapping with unit conversion
- Timestamp normalization (multiple vendor formats → ISO 8601)
- Bidirectional transformation (vendor→CIM and CIM→vendor)
- Transformation types: DIRECT, ENUMERATION, AGGREGATION, CONDITIONAL, UNIT_CONVERSION

Example:
    >>> from mapping_engine import MappingRuleLoader, TransformationEngine
    >>> loader = MappingRuleLoader()
    >>> rules = loader.load_from_file('mappings/severity.yaml')
    >>> engine = TransformationEngine(rules)
    >>> cim_severity = engine.transform_alarm('severity', 'critical', 'ericsson')
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import yaml

# Configure module-level logger
logger = logging.getLogger(__name__)


class TransformationType(Enum):
    """Enumeration of supported transformation types.
    
    Attributes:
        DIRECT: Direct 1:1 mapping without transformation.
        ENUMERATION: Mapping between enumeration values.
        AGGREGATION: Combining multiple values into one.
        CONDITIONAL: Conditional mapping based on conditions.
        UNIT_CONVERSION: Converting units (e.g., bytes to megabytes).
    """
    DIRECT = "DIRECT"
    ENUMERATION = "ENUMERATION"
    AGGREGATION = "AGGREGATION"
    CONDITIONAL = "CONDITIONAL"
    UNIT_CONVERSION = "UNIT_CONVERSION"


class MappingError(Exception):
    """Base exception for mapping-related errors."""
    pass


class YAMLParseError(MappingError):
    """Exception raised when YAML parsing fails."""
    pass


class RuleNotFoundError(MappingError):
    """Exception raised when a mapping rule cannot be found."""
    pass


class TypeConversionError(MappingError):
    """Exception raised when type conversion fails."""
    pass


class TransformationError(MappingError):
    """Exception raised when transformation fails."""
    pass


@dataclass
class MappingRule:
    """Dataclass representing a single mapping rule.
    
    Attributes:
        source_path: Path to the source field in vendor format.
        target_path: Path to the target field in CIM format.
        transform: Type of transformation to apply.
        transform_config: Configuration for the transformation.
        vendor: Vendor identifier (e.g., 'ericsson', 'huawei').
        domain: Domain identifier (e.g., 'alarm', 'performance', 'config').
        description: Human-readable description of the mapping.
        tags: Optional tags for categorization and filtering.
        priority: Priority for rule resolution (higher = more important).
        enabled: Whether the rule is active.
    """
    source_path: str
    target_path: str
    transform: TransformationType
    transform_config: Dict[str, Any] = field(default_factory=dict)
    vendor: str = ""
    domain: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True

    def __post_init__(self) -> None:
        """Validate and transform fields after initialization."""
        if isinstance(self.transform, str):
            try:
                self.transform = TransformationType(self.transform.upper())
            except ValueError:
                logger.warning(f"Unknown transformation type: {self.transform}, defaulting to DIRECT")
                self.transform = TransformationType.DIRECT

    def get_source_key(self) -> str:
        """Generate a unique key for the source mapping.
        
        Returns:
            A composite key combining vendor, domain, and source path.
        """
        return f"{self.vendor}:{self.domain}:{self.source_path}"

    def get_target_key(self) -> str:
        """Generate a unique key for the target mapping.
        
        Returns:
            A composite key combining domain and target path.
        """
        return f"{self.domain}:{self.target_path}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert the mapping rule to a dictionary representation.
        
        Returns:
            Dictionary containing all rule attributes.
        """
        return {
            "source_path": self.source_path,
            "target_path": self.target_path,
            "transform": self.transform.value,
            "transform_config": self.transform_config,
            "vendor": self.vendor,
            "domain": self.domain,
            "description": self.description,
            "tags": self.tags,
            "priority": self.priority,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MappingRule":
        """Create a MappingRule instance from a dictionary.
        
        Args:
            data: Dictionary containing rule attributes.
            
        Returns:
            A new MappingRule instance.
        """
        return cls(
            source_path=data.get("source_path", ""),
            target_path=data.get("target_path", ""),
            transform=data.get("transform", TransformationType.DIRECT),
            transform_config=data.get("transform_config", {}),
            vendor=data.get("vendor", ""),
            domain=data.get("domain", ""),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            priority=data.get("priority", 0),
            enabled=data.get("enabled", True),
        )


class TransformationRule:
    """Rule for applying and reversing transformations.
    
    This class encapsulates a single transformation logic that can be
    applied in both forward (vendor→CIM) and reverse (CIM→vendor) directions.
    
    Attributes:
        name: Human-readable name for the transformation.
        transform_type: Type of transformation from TransformationType enum.
        config: Configuration parameters for the transformation.
    """

    def __init__(
        self,
        name: str,
        transform_type: TransformationType,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize a TransformationRule.
        
        Args:
            name: Human-readable name for the transformation.
            transform_type: Type of transformation.
            config: Configuration parameters for the transformation.
        """
        self.name = name
        self.transform_type = transform_type
        self.config = config or {}
        self._forward_map: Dict[Any, Any] = {}
        self._reverse_map: Dict[Any, Any] = {}
        self._initialize_maps()

    def _initialize_maps(self) -> None:
        """Initialize forward and reverse mapping dictionaries."""
        if self.transform_type == TransformationType.ENUMERATION:
            mappings = self.config.get("mappings", {})
            self._forward_map = mappings.copy()
            self._reverse_map = {v: k for k, v in mappings.items()}

    def apply(self, value: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """Apply the transformation to a value.
        
        Args:
            value: The input value to transform.
            context: Optional context information for conditional transformations.
            
        Returns:
            The transformed value.
            
        Raises:
            TransformationError: If the transformation fails.
        """
        context = context or {}

        try:
            if self.transform_type == TransformationType.DIRECT:
                return self._apply_direct(value)
            elif self.transform_type == TransformationType.ENUMERATION:
                return self._apply_enumeration(value)
            elif self.transform_type == TransformationType.AGGREGATION:
                return self._apply_aggregation(value, context)
            elif self.transform_type == TransformationType.CONDITIONAL:
                return self._apply_conditional(value, context)
            elif self.transform_type == TransformationType.UNIT_CONVERSION:
                return self._apply_unit_conversion(value)
            else:
                logger.warning(f"Unknown transformation type: {self.transform_type}")
                return value
        except Exception as e:
            logger.error(f"Transformation failed for rule '{self.name}': {e}")
            raise TransformationError(f"Failed to apply transformation '{self.name}': {e}") from e

    def reverse(self, value: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """Reverse the transformation to get the original value.
        
        Args:
            value: The transformed value to reverse.
            context: Optional context information for conditional transformations.
            
        Returns:
            The original value before transformation.
            
        Raises:
            TransformationError: If the reverse transformation fails.
        """
        context = context or {}

        try:
            if self.transform_type == TransformationType.DIRECT:
                return self._reverse_direct(value)
            elif self.transform_type == TransformationType.ENUMERATION:
                return self._reverse_enumeration(value)
            elif self.transform_type == TransformationType.AGGREGATION:
                return self._reverse_aggregation(value, context)
            elif self.transform_type == TransformationType.CONDITIONAL:
                return self._reverse_conditional(value, context)
            elif self.transform_type == TransformationType.UNIT_CONVERSION:
                return self._reverse_unit_conversion(value)
            else:
                logger.warning(f"Unknown transformation type: {self.transform_type}")
                return value
        except Exception as e:
            logger.error(f"Reverse transformation failed for rule '{self.name}': {e}")
            raise TransformationError(f"Failed to reverse transformation '{self.name}': {e}") from e

    def _apply_direct(self, value: Any) -> Any:
        """Apply direct transformation (identity or simple mapping)."""
        if self._forward_map and value in self._forward_map:
            return self._forward_map[value]
        return value

    def _reverse_direct(self, value: Any) -> Any:
        """Reverse direct transformation."""
        if self._reverse_map and value in self._reverse_map:
            return self._reverse_map[value]
        return value

    def _apply_enumeration(self, value: Any) -> Any:
        """Apply enumeration mapping transformation."""
        if value in self._forward_map:
            return self._forward_map[value]
        
        # Handle default value
        default = self.config.get("default")
        if default is not None:
            logger.debug(f"Using default value '{default}' for unmapped enumeration: {value}")
            return default
        
        # Log warning and return original value
        logger.warning(f"No enumeration mapping found for value: {value}")
        return value

    def _reverse_enumeration(self, value: Any) -> Any:
        """Reverse enumeration mapping transformation."""
        if value in self._reverse_map:
            return self._reverse_map[value]
        
        default = self.config.get("reverse_default")
        if default is not None:
            logger.debug(f"Using reverse default value '{default}' for unmapped enumeration: {value}")
            return default
        
        logger.warning(f"No reverse enumeration mapping found for value: {value}")
        return value

    def _apply_aggregation(self, value: Any, context: Dict[str, Any]) -> Any:
        """Apply aggregation transformation."""
        if not isinstance(value, (list, tuple)):
            return value

        aggregation_type = self.config.get("aggregation_type", "sum")
        values = list(value)

        if aggregation_type == "sum":
            return sum(v for v in values if isinstance(v, (int, float)))
        elif aggregation_type == "avg":
            numeric_values = [v for v in values if isinstance(v, (int, float))]
            return sum(numeric_values) / len(numeric_values) if numeric_values else 0
        elif aggregation_type == "max":
            return max(values) if values else None
        elif aggregation_type == "min":
            return min(values) if values else None
        elif aggregation_type == "count":
            return len(values)
        elif aggregation_type == "join":
            separator = self.config.get("separator", ",")
            return separator.join(str(v) for v in values)
        else:
            logger.warning(f"Unknown aggregation type: {aggregation_type}")
            return value

    def _reverse_aggregation(self, value: Any, context: Dict[str, Any]) -> Any:
        """Reverse aggregation transformation (limited support)."""
        # Aggregation is generally not reversible without additional context
        logger.warning("Aggregation transformation is not fully reversible")
        return value

    def _apply_conditional(self, value: Any, context: Dict[str, Any]) -> Any:
        """Apply conditional transformation based on conditions."""
        conditions = self.config.get("conditions", [])

        for condition in conditions:
            if self._evaluate_condition(condition, value, context):
                return self._apply_condition_result(condition, value)

        # Apply default if no conditions match
        default = self.config.get("default")
        if default is not None:
            return default

        return value

    def _reverse_conditional(self, value: Any, context: Dict[str, Any]) -> Any:
        """Reverse conditional transformation."""
        reverse_conditions = self.config.get("reverse_conditions", [])
        
        for condition in reverse_conditions:
            if self._evaluate_condition(condition, value, context):
                return self._apply_condition_result(condition, value)

        default = self.config.get("reverse_default")
        if default is not None:
            return default

        return value

    def _evaluate_condition(
        self, condition: Dict[str, Any], value: Any, context: Dict[str, Any]
    ) -> bool:
        """Evaluate a condition against a value and context."""
        condition_type = condition.get("type", "equals")
        condition_value = condition.get("value")

        if condition_type == "equals":
            return value == condition_value
        elif condition_type == "not_equals":
            return value != condition_value
        elif condition_type == "greater_than":
            return isinstance(value, (int, float)) and value > condition_value
        elif condition_type == "less_than":
            return isinstance(value, (int, float)) and value < condition_value
        elif condition_type == "contains":
            return isinstance(value, str) and condition_value in value
        elif condition_type == "regex":
            return isinstance(value, str) and bool(re.match(condition_value, value))
        elif condition_type == "in":
            return value in condition_value if isinstance(condition_value, list) else False
        elif condition_type == "context_equals":
            context_key = condition.get("context_key", "")
            return context.get(context_key) == condition_value
        else:
            logger.warning(f"Unknown condition type: {condition_type}")
            return False

    def _apply_condition_result(self, condition: Dict[str, Any], value: Any) -> Any:
        """Apply the result of a matched condition."""
        result_type = condition.get("result_type", "value")
        result_value = condition.get("result_value")

        if result_type == "value":
            return result_value
        elif result_type == "multiply":
            return value * result_value if isinstance(value, (int, float)) else value
        elif result_type == "add":
            return value + result_value if isinstance(value, (int, float)) else value
        elif result_type == "format":
            return result_value.format(value=value)
        else:
            return value

    def _apply_unit_conversion(self, value: Any) -> Any:
        """Apply unit conversion transformation."""
        if not isinstance(value, (int, float)):
            try:
                value = float(value)
            except (TypeError, ValueError):
                logger.warning(f"Cannot convert value to number: {value}")
                return value

        source_unit = self.config.get("source_unit", "")
        target_unit = self.config.get("target_unit", "")
        conversion_factor = self.config.get("conversion_factor", 1.0)
        offset = self.config.get("offset", 0.0)

        # Apply conversion
        result = (value * conversion_factor) + offset

        # Handle precision
        precision = self.config.get("precision")
        if precision is not None:
            result = round(result, precision)

        logger.debug(f"Unit conversion: {value} {source_unit} -> {result} {target_unit}")
        return result

    def _reverse_unit_conversion(self, value: Any) -> Any:
        """Reverse unit conversion transformation."""
        if not isinstance(value, (int, float)):
            try:
                value = float(value)
            except (TypeError, ValueError):
                logger.warning(f"Cannot convert value to number: {value}")
                return value

        conversion_factor = self.config.get("conversion_factor", 1.0)
        offset = self.config.get("offset", 0.0)

        # Reverse the conversion
        result = (value - offset) / conversion_factor

        precision = self.config.get("source_precision")
        if precision is not None:
            result = round(result, precision)

        return result


class BidirectionalMappingIndex:
    """Index for O(1) lookup of mapping rules in both directions.
    
    This class maintains two dictionaries for fast forward and reverse
    lookups of mapping rules. Forward lookup maps vendor-specific paths
    to CIM paths, while reverse lookup maps CIM paths back to vendor paths.
    
    Attributes:
        name: Name identifier for this index.
        rules: List of all mapping rules in this index.
    """

    def __init__(self, name: str = "default") -> None:
        """Initialize the bidirectional mapping index.
        
        Args:
            name: Name identifier for this index.
        """
        self.name = name
        self.rules: List[MappingRule] = []
        self._forward_index: Dict[str, List[MappingRule]] = {}
        self._reverse_index: Dict[str, List[MappingRule]] = {}
        self._transformation_cache: Dict[str, TransformationRule] = {}

    def add_rule(self, rule: MappingRule) -> None:
        """Add a mapping rule to the index.
        
        Args:
            rule: The mapping rule to add.
        """
        if not rule.enabled:
            logger.debug(f"Skipping disabled rule: {rule.source_path}")
            return

        self.rules.append(rule)

        # Add to forward index
        forward_key = rule.get_source_key()
        if forward_key not in self._forward_index:
            self._forward_index[forward_key] = []
        self._forward_index[forward_key].append(rule)

        # Add to reverse index
        reverse_key = rule.get_target_key()
        if reverse_key not in self._reverse_index:
            self._reverse_index[reverse_key] = []
        self._reverse_index[reverse_key].append(rule)

        # Create and cache transformation rule
        transform_key = f"{forward_key}:{rule.target_path}"
        self._transformation_cache[transform_key] = TransformationRule(
            name=f"{rule.source_path}->{rule.target_path}",
            transform_type=rule.transform,
            config=rule.transform_config,
        )

        logger.debug(f"Added rule to index: {forward_key}")

    def remove_rule(self, rule: MappingRule) -> bool:
        """Remove a mapping rule from the index.
        
        Args:
            rule: The mapping rule to remove.
            
        Returns:
            True if the rule was removed, False if not found.
        """
        try:
            self.rules.remove(rule)
        except ValueError:
            return False

        # Remove from forward index
        forward_key = rule.get_source_key()
        if forward_key in self._forward_index:
            self._forward_index[forward_key] = [
                r for r in self._forward_index[forward_key] if r != rule
            ]
            if not self._forward_index[forward_key]:
                del self._forward_index[forward_key]

        # Remove from reverse index
        reverse_key = rule.get_target_key()
        if reverse_key in self._reverse_index:
            self._reverse_index[reverse_key] = [
                r for r in self._reverse_index[reverse_key] if r != rule
            ]
            if not self._reverse_index[reverse_key]:
                del self._reverse_index[reverse_key]

        return True

    def lookup_forward(
        self,
        source_path: str,
        vendor: str = "",
        domain: str = "",
    ) -> Optional[MappingRule]:
        """Look up a mapping rule by source path (vendor→CIM direction).
        
        Args:
            source_path: The source path to look up.
            vendor: Optional vendor filter.
            domain: Optional domain filter.
            
        Returns:
            The matching MappingRule or None if not found.
        """
        # Try exact match first
        exact_key = f"{vendor}:{domain}:{source_path}"
        if exact_key in self._forward_index:
            rules = self._forward_index[exact_key]
            return self._select_best_rule(rules)

        # Try with wildcards
        patterns = [
            f"{vendor}:{domain}:{source_path}",
            f"{vendor}::{source_path}",
            f":{domain}:{source_path}",
            f"::{source_path}",
        ]

        for pattern in patterns:
            if pattern in self._forward_index:
                rules = self._forward_index[pattern]
                return self._select_best_rule(rules)

        logger.debug(f"No forward mapping found for: {source_path}")
        return None

    def lookup_reverse(
        self,
        target_path: str,
        vendor: str = "",
        domain: str = "",
    ) -> Optional[MappingRule]:
        """Look up a mapping rule by target path (CIM→vendor direction).
        
        Args:
            target_path: The target path to look up.
            vendor: Optional vendor filter.
            domain: Optional domain filter.
            
        Returns:
            The matching MappingRule or None if not found.
        """
        # Try exact match first
        exact_key = f"{domain}:{target_path}"
        if exact_key in self._reverse_index:
            rules = self._reverse_index[exact_key]
            filtered = [r for r in rules if not vendor or r.vendor == vendor]
            if filtered:
                return self._select_best_rule(filtered)

        # Try with wildcard domain
        wildcard_key = f":{target_path}"
        if wildcard_key in self._reverse_index:
            rules = self._reverse_index[wildcard_key]
            filtered = [r for r in rules if not vendor or r.vendor == vendor]
            if filtered:
                return self._select_best_rule(filtered)

        logger.debug(f"No reverse mapping found for: {target_path}")
        return None

    def _select_best_rule(self, rules: List[MappingRule]) -> Optional[MappingRule]:
        """Select the best rule from a list based on priority.
        
        Args:
            rules: List of matching rules.
            
        Returns:
            The highest priority rule or None if list is empty.
        """
        if not rules:
            return None

        return max(rules, key=lambda r: r.priority)

    def get_transformation_rule(self, mapping_rule: MappingRule) -> TransformationRule:
        """Get the TransformationRule for a MappingRule.
        
        Args:
            mapping_rule: The mapping rule to get transformation for.
            
        Returns:
            The cached TransformationRule.
        """
        transform_key = f"{mapping_rule.get_source_key()}:{mapping_rule.target_path}"
        
        if transform_key in self._transformation_cache:
            return self._transformation_cache[transform_key]

        # Create new transformation rule if not cached
        transform_rule = TransformationRule(
            name=f"{mapping_rule.source_path}->{mapping_rule.target_path}",
            transform_type=mapping_rule.transform,
            config=mapping_rule.transform_config,
        )
        self._transformation_cache[transform_key] = transform_rule
        return transform_rule

    def clear(self) -> None:
        """Clear all rules from the index."""
        self.rules.clear()
        self._forward_index.clear()
        self._reverse_index.clear()
        self._transformation_cache.clear()
        logger.debug("Index cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the index.
        
        Returns:
            Dictionary containing index statistics.
        """
        return {
            "name": self.name,
            "total_rules": len(self.rules),
            "forward_index_size": len(self._forward_index),
            "reverse_index_size": len(self._reverse_index),
            "transformation_cache_size": len(self._transformation_cache),
        }


class MappingRuleLoader:
    """Loader for mapping rules from YAML files and directories.
    
    This class handles loading, parsing, and validating mapping rules
    from YAML configuration files.
    
    Example:
        >>> loader = MappingRuleLoader()
        >>> rules = loader.load_from_directory('/path/to/mappings')
        >>> print(f"Loaded {len(rules)} rules")
    """

    def __init__(self, strict: bool = False) -> None:
        """Initialize the mapping rule loader.
        
        Args:
            strict: If True, raise exceptions on parse errors.
                   If False, log warnings and continue.
        """
        self.strict = strict
        self._loaded_files: Dict[str, datetime] = {}

    def load_from_file(
        self,
        file_path: Union[str, Path],
        vendor: str = "",
        domain: str = "",
    ) -> List[MappingRule]:
        """Load mapping rules from a single YAML file.
        
        Args:
            file_path: Path to the YAML file.
            vendor: Default vendor if not specified in file.
            domain: Default domain if not specified in file.
            
        Returns:
            List of loaded MappingRule instances.
            
        Raises:
            YAMLParseError: If YAML parsing fails (in strict mode).
        """
        file_path = Path(file_path)

        if not file_path.exists():
            error_msg = f"Mapping file not found: {file_path}"
            logger.error(error_msg)
            if self.strict:
                raise YAMLParseError(error_msg)
            return []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
        except yaml.YAMLError as e:
            error_msg = f"YAML parse error in {file_path}: {e}"
            logger.error(error_msg)
            if self.strict:
                raise YAMLParseError(error_msg) from e
            return []
        except Exception as e:
            error_msg = f"Error reading file {file_path}: {e}"
            logger.error(error_msg)
            if self.strict:
                raise YAMLParseError(error_msg) from e
            return []

        if content is None:
            logger.warning(f"Empty YAML file: {file_path}")
            return []

        # Track loaded file
        self._loaded_files[str(file_path)] = datetime.now(timezone.utc)

        # Parse rules from content
        return self._parse_rules(content, file_path, vendor, domain)

    def load_from_directory(
        self,
        directory_path: Union[str, Path],
        recursive: bool = True,
        vendor: str = "",
        domain: str = "",
    ) -> List[MappingRule]:
        """Load mapping rules from all YAML files in a directory.
        
        Args:
            directory_path: Path to the directory.
            recursive: Whether to search subdirectories.
            vendor: Default vendor if not specified in file.
            domain: Default domain if not specified in file.
            
        Returns:
            List of loaded MappingRule instances.
        """
        directory_path = Path(directory_path)

        if not directory_path.exists():
            logger.error(f"Directory not found: {directory_path}")
            return []

        if not directory_path.is_dir():
            logger.error(f"Path is not a directory: {directory_path}")
            return []

        all_rules: List[MappingRule] = []
        pattern = "**/*.yaml" if recursive else "*.yaml"

        for file_path in directory_path.glob(pattern):
            if file_path.is_file():
                rules = self.load_from_file(file_path, vendor, domain)
                all_rules.extend(rules)

        logger.info(f"Loaded {len(all_rules)} rules from {directory_path}")
        return all_rules

    def _parse_rules(
        self,
        content: Any,
        file_path: Path,
        default_vendor: str,
        default_domain: str,
    ) -> List[MappingRule]:
        """Parse mapping rules from YAML content.
        
        Args:
            content: Parsed YAML content.
            file_path: Path to the source file.
            default_vendor: Default vendor identifier.
            default_domain: Default domain identifier.
            
        Returns:
            List of parsed MappingRule instances.
        """
        rules: List[MappingRule] = []

        # Handle different content structures
        if isinstance(content, dict):
            # Check for rules key
            if "rules" in content:
                rule_list = content["rules"]
            elif "mappings" in content:
                rule_list = content["mappings"]
            else:
                # Treat entire dict as a single rule or list of rules
                rule_list = [content] if self._is_rule_dict(content) else []
            
            if isinstance(rule_list, list):
                for i, rule_data in enumerate(rule_list):
                    try:
                        rule = self._create_rule(
                            rule_data,
                            file_path,
                            default_vendor,
                            default_domain,
                        )
                        if rule:
                            rules.append(rule)
                    except Exception as e:
                        logger.error(f"Error parsing rule {i} in {file_path}: {e}")

        elif isinstance(content, list):
            for i, rule_data in enumerate(content):
                try:
                    rule = self._create_rule(
                        rule_data,
                        file_path,
                        default_vendor,
                        default_domain,
                    )
                    if rule:
                        rules.append(rule)
                except Exception as e:
                    logger.error(f"Error parsing rule {i} in {file_path}: {e}")

        return rules

    def _is_rule_dict(self, data: Dict[str, Any]) -> bool:
        """Check if a dictionary represents a valid rule.
        
        Args:
            data: Dictionary to check.
            
        Returns:
            True if the dictionary has required rule fields.
        """
        return "source_path" in data or "target_path" in data

    def _create_rule(
        self,
        data: Dict[str, Any],
        file_path: Path,
        default_vendor: str,
        default_domain: str,
    ) -> Optional[MappingRule]:
        """Create a MappingRule from parsed data.
        
        Args:
            data: Rule data dictionary.
            file_path: Source file path.
            default_vendor: Default vendor if not specified.
            default_domain: Default domain if not specified.
            
        Returns:
            Created MappingRule or None if data is invalid.
        """
        if not isinstance(data, dict):
            logger.warning(f"Invalid rule data type: {type(data)}")
            return None

        # Extract fields with defaults
        source_path = data.get("source_path", data.get("source", ""))
        target_path = data.get("target_path", data.get("target", ""))

        if not source_path or not target_path:
            logger.warning(f"Rule missing source_path or target_path in {file_path}")
            return None

        # Get transform type
        transform_str = data.get("transform", data.get("transformation", "DIRECT"))
        try:
            transform = TransformationType(transform_str.upper())
        except ValueError:
            logger.warning(f"Invalid transform type: {transform_str}, using DIRECT")
            transform = TransformationType.DIRECT

        return MappingRule(
            source_path=source_path,
            target_path=target_path,
            transform=transform,
            transform_config=data.get("transform_config", data.get("config", {})),
            vendor=data.get("vendor", default_vendor),
            domain=data.get("domain", default_domain),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            priority=data.get("priority", 0),
            enabled=data.get("enabled", True),
        )

    def get_loaded_files(self) -> Dict[str, datetime]:
        """Get dictionary of loaded files with their timestamps.
        
        Returns:
            Dictionary mapping file paths to load timestamps.
        """
        return self._loaded_files.copy()


class TransformationEngine:
    """Engine for applying transformations to various data types.
    
    This class provides methods for transforming alarm, performance,
    and configuration data between vendor-specific formats and CIM.
    
    Example:
        >>> loader = MappingRuleLoader()
        >>> rules = loader.load_from_file('mappings.yaml')
        >>> index = BidirectionalMappingIndex()
        >>> for rule in rules:
        ...     index.add_rule(rule)
        >>> engine = TransformationEngine(index)
        >>> result = engine.transform_alarm({'severity': 'critical'}, 'ericsson')
    """

    # Vendor-specific severity mappings
    ERICSSON_SEVERITY_MAP: Dict[str, str] = {
        "critical": "CRITICAL",
        "major": "HIGH",
        "minor": "MEDIUM",
        "warning": "LOW",
        "indeterminate": "INDETERMINATE",
        "cleared": "CLEARED",
    }

    HUAWEI_SEVERITY_MAP: Dict[int, str] = {
        1: "CRITICAL",
        2: "HIGH",
        3: "MEDIUM",
        4: "LOW",
        5: "INDETERMINATE",
        6: "CLEARED",
    }

    # Vendor-specific timestamp formats
    TIMESTAMP_FORMATS: Dict[str, List[str]] = {
        "ericsson": [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ],
        "huawei": [
            "%Y-%m-%d %H:%M:%S",
            "%Y%m%d%H%M%S",
            "%Y%m%d%H%M%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
        ],
        "nokia": [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%d-%m-%Y %H:%M:%S",
        ],
        "default": [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
        ],
    }

    def __init__(
        self,
        index: Optional[BidirectionalMappingIndex] = None,
        fallback_enabled: bool = True,
    ) -> None:
        """Initialize the transformation engine.
        
        Args:
            index: Optional pre-populated mapping index.
            fallback_enabled: Whether to enable fallback behavior for missing rules.
        """
        self.index = index or BidirectionalMappingIndex()
        self.fallback_enabled = fallback_enabled
        self._init_builtin_mappings()

    def _init_builtin_mappings(self) -> None:
        """Initialize built-in mapping rules for common transformations."""
        # Add Ericsson severity mappings
        for source, target in self.ERICSSON_SEVERITY_MAP.items():
            rule = MappingRule(
                source_path="severity",
                target_path="alarmSeverity",
                transform=TransformationType.ENUMERATION,
                transform_config={"mappings": {source: target}},
                vendor="ericsson",
                domain="alarm",
                description=f"Ericsson severity mapping: {source} -> {target}",
            )
            self.index.add_rule(rule)

        # Add Huawei severity mappings
        for source, target in self.HUAWEI_SEVERITY_MAP.items():
            rule = MappingRule(
                source_path="severity",
                target_path="alarmSeverity",
                transform=TransformationType.ENUMERATION,
                transform_config={"mappings": {source: target}},
                vendor="huawei",
                domain="alarm",
                description=f"Huawei severity mapping: {source} -> {target}",
            )
            self.index.add_rule(rule)

    def transform_alarm(
        self,
        data: Dict[str, Any],
        vendor: str,
        direction: str = "forward",
    ) -> Dict[str, Any]:
        """Transform alarm data between vendor and CIM formats.
        
        Args:
            data: Alarm data dictionary to transform.
            vendor: Vendor identifier (e.g., 'ericsson', 'huawei').
            direction: 'forward' for vendor→CIM, 'reverse' for CIM→vendor.
            
        Returns:
            Transformed alarm data dictionary.
            
        Raises:
            TransformationError: If transformation fails.
        """
        result: Dict[str, Any] = {}

        for source_key, source_value in data.items():
            try:
                if direction == "forward":
                    rule = self.index.lookup_forward(source_key, vendor, "alarm")
                    if rule:
                        transform_rule = self.index.get_transformation_rule(rule)
                        target_value = transform_rule.apply(source_value)
                        result[rule.target_path] = target_value
                    elif self.fallback_enabled:
                        result[source_key] = source_value
                        logger.debug(f"No mapping found for alarm field: {source_key}")
                    else:
                        raise RuleNotFoundError(f"No mapping rule found for: {source_key}")
                else:
                    rule = self.index.lookup_reverse(source_key, vendor, "alarm")
                    if rule:
                        transform_rule = self.index.get_transformation_rule(rule)
                        target_value = transform_rule.reverse(source_value)
                        result[rule.source_path] = target_value
                    elif self.fallback_enabled:
                        result[source_key] = source_value
                    else:
                        raise RuleNotFoundError(f"No reverse mapping found for: {source_key}")
            except RuleNotFoundError:
                raise
            except Exception as e:
                logger.error(f"Error transforming alarm field {source_key}: {e}")
                if self.fallback_enabled:
                    result[source_key] = source_value
                else:
                    raise TransformationError(f"Failed to transform {source_key}: {e}") from e

        # Normalize timestamp if present
        if "eventTime" in result or "timestamp" in data:
            result["eventTime"] = self.normalize_timestamp(
                data.get("eventTime", data.get("timestamp", "")),
                vendor,
            )

        return result

    def transform_performance(
        self,
        data: Dict[str, Any],
        vendor: str,
        direction: str = "forward",
    ) -> Dict[str, Any]:
        """Transform performance data between vendor and CIM formats.
        
        Args:
            data: Performance data dictionary to transform.
            vendor: Vendor identifier.
            direction: 'forward' for vendor→CIM, 'reverse' for CIM→vendor.
            
        Returns:
            Transformed performance data dictionary.
        """
        result: Dict[str, Any] = {}

        for source_key, source_value in data.items():
            try:
                if direction == "forward":
                    rule = self.index.lookup_forward(source_key, vendor, "performance")
                    if rule:
                        transform_rule = self.index.get_transformation_rule(rule)
                        target_value = transform_rule.apply(source_value)
                        result[rule.target_path] = target_value
                    elif self.fallback_enabled:
                        result[source_key] = source_value
                        logger.debug(f"No mapping found for performance field: {source_key}")
                    else:
                        raise RuleNotFoundError(f"No mapping rule found for: {source_key}")
                else:
                    rule = self.index.lookup_reverse(source_key, vendor, "performance")
                    if rule:
                        transform_rule = self.index.get_transformation_rule(rule)
                        target_value = transform_rule.reverse(source_value)
                        result[rule.source_path] = target_value
                    elif self.fallback_enabled:
                        result[source_key] = source_value
                    else:
                        raise RuleNotFoundError(f"No reverse mapping found for: {source_key}")
            except RuleNotFoundError:
                raise
            except Exception as e:
                logger.error(f"Error transforming performance field {source_key}: {e}")
                if self.fallback_enabled:
                    result[source_key] = source_value
                else:
                    raise TransformationError(f"Failed to transform {source_key}: {e}") from e

        # Normalize timestamp
        if "timestamp" in data or "measurementTime" in data:
            result["measurementTime"] = self.normalize_timestamp(
                data.get("measurementTime", data.get("timestamp", "")),
                vendor,
            )

        return result

    def transform_config(
        self,
        data: Dict[str, Any],
        vendor: str,
        direction: str = "forward",
    ) -> Dict[str, Any]:
        """Transform configuration data between vendor and CIM formats.
        
        Args:
            data: Configuration data dictionary to transform.
            vendor: Vendor identifier.
            direction: 'forward' for vendor→CIM, 'reverse' for CIM→vendor.
            
        Returns:
            Transformed configuration data dictionary.
        """
        result: Dict[str, Any] = {}

        for source_key, source_value in data.items():
            try:
                if direction == "forward":
                    rule = self.index.lookup_forward(source_key, vendor, "config")
                    if rule:
                        transform_rule = self.index.get_transformation_rule(rule)
                        target_value = transform_rule.apply(source_value)
                        result[rule.target_path] = target_value
                    elif self.fallback_enabled:
                        result[source_key] = source_value
                        logger.debug(f"No mapping found for config field: {source_key}")
                    else:
                        raise RuleNotFoundError(f"No mapping rule found for: {source_key}")
                else:
                    rule = self.index.lookup_reverse(source_key, vendor, "config")
                    if rule:
                        transform_rule = self.index.get_transformation_rule(rule)
                        target_value = transform_rule.reverse(source_value)
                        result[rule.source_path] = target_value
                    elif self.fallback_enabled:
                        result[source_key] = source_value
                    else:
                        raise RuleNotFoundError(f"No reverse mapping found for: {source_key}")
            except RuleNotFoundError:
                raise
            except Exception as e:
                logger.error(f"Error transforming config field {source_key}: {e}")
                if self.fallback_enabled:
                    result[source_key] = source_value
                else:
                    raise TransformationError(f"Failed to transform {source_key}: {e}") from e

        return result

    def normalize_timestamp(
        self,
        timestamp: Any,
        vendor: str = "default",
    ) -> str:
        """Normalize a vendor-specific timestamp to ISO 8601 format.
        
        Args:
            timestamp: The timestamp value to normalize.
            vendor: Vendor identifier for format detection.
            
        Returns:
            ISO 8601 formatted timestamp string.
        """
        if not timestamp:
            return datetime.now(timezone.utc).isoformat()

        # If already ISO 8601, return as-is
        if isinstance(timestamp, str):
            iso_pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
            if re.match(iso_pattern, timestamp):
                # Ensure timezone info
                if not timestamp.endswith(("Z", "+", "-")):
                    timestamp += "Z"
                return timestamp

        # Get formats for vendor
        formats = self.TIMESTAMP_FORMATS.get(vendor, self.TIMESTAMP_FORMATS["default"])

        # Try parsing with each format
        for fmt in formats:
            try:
                if isinstance(timestamp, (int, float)):
                    # Unix timestamp
                    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                else:
                    dt = datetime.strptime(str(timestamp), fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except (ValueError, TypeError):
                continue

        # Try ISO format directly
        try:
            dt = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            return dt.isoformat()
        except ValueError:
            pass

        # Fallback to current time
        logger.warning(f"Could not parse timestamp: {timestamp}, using current time")
        return datetime.now(timezone.utc).isoformat()

    def add_rule(self, rule: MappingRule) -> None:
        """Add a mapping rule to the engine's index.
        
        Args:
            rule: The mapping rule to add.
        """
        self.index.add_rule(rule)

    def add_rules(self, rules: List[MappingRule]) -> None:
        """Add multiple mapping rules to the engine's index.
        
        Args:
            rules: List of mapping rules to add.
        """
        for rule in rules:
            self.index.add_rule(rule)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the transformation engine.
        
        Returns:
            Dictionary containing engine statistics.
        """
        return {
            "index_stats": self.index.get_stats(),
            "fallback_enabled": self.fallback_enabled,
            "builtin_severity_mappings": {
                "ericsson": len(self.ERICSSON_SEVERITY_MAP),
                "huawei": len(self.HUAWEI_SEVERITY_MAP),
            },
        }


def create_severity_mapping_rule(
    vendor: str,
    source_severity: Union[str, int],
    target_severity: str,
) -> MappingRule:
    """Factory function to create a severity mapping rule.
    
    Args:
        vendor: Vendor identifier.
        source_severity: Source severity value.
        target_severity: Target CIM severity value.
        
    Returns:
        A configured MappingRule for severity mapping.
    """
    return MappingRule(
        source_path="severity",
        target_path="alarmSeverity",
        transform=TransformationType.ENUMERATION,
        transform_config={"mappings": {source_severity: target_severity}},
        vendor=vendor,
        domain="alarm",
        description=f"{vendor.capitalize()} severity mapping: {source_severity} -> {target_severity}",
    )


def create_counter_mapping_rule(
    vendor: str,
    source_path: str,
    target_path: str,
    conversion_factor: float = 1.0,
    offset: float = 0.0,
    unit_from: str = "",
    unit_to: str = "",
    precision: Optional[int] = None,
) -> MappingRule:
    """Factory function to create a counter mapping rule with unit conversion.
    
    Args:
        vendor: Vendor identifier.
        source_path: Source counter path.
        target_path: Target counter path.
        conversion_factor: Factor to multiply by for conversion.
        offset: Offset to add after conversion.
        unit_from: Source unit name.
        unit_to: Target unit name.
        precision: Number of decimal places for result.
        
    Returns:
        A configured MappingRule for counter mapping.
    """
    return MappingRule(
        source_path=source_path,
        target_path=target_path,
        transform=TransformationType.UNIT_CONVERSION,
        transform_config={
            "conversion_factor": conversion_factor,
            "offset": offset,
            "source_unit": unit_from,
            "target_unit": unit_to,
            "precision": precision,
        },
        vendor=vendor,
        domain="performance",
        description=f"Counter mapping: {source_path} ({unit_from}) -> {target_path} ({unit_to})",
    )


def load_mapping_engine(
    config_path: Union[str, Path],
    vendor: str = "",
    domain: str = "",
) -> TransformationEngine:
    """Convenience function to create a fully configured transformation engine.
    
    Args:
        config_path: Path to mapping configuration file or directory.
        vendor: Default vendor identifier.
        domain: Default domain identifier.
        
    Returns:
        A configured TransformationEngine instance.
    """
    config_path = Path(config_path)
    
    loader = MappingRuleLoader()
    index = BidirectionalMappingIndex()
    
    if config_path.is_dir():
        rules = loader.load_from_directory(config_path, vendor=vendor, domain=domain)
    else:
        rules = loader.load_from_file(config_path, vendor=vendor, domain=domain)
    
    for rule in rules:
        index.add_rule(rule)
    
    return TransformationEngine(index)


# Module-level convenience exports
__all__ = [
    "TransformationType",
    "MappingError",
    "YAMLParseError",
    "RuleNotFoundError",
    "TypeConversionError",
    "TransformationError",
    "MappingRule",
    "TransformationRule",
    "BidirectionalMappingIndex",
    "MappingRuleLoader",
    "TransformationEngine",
    "create_severity_mapping_rule",
    "create_counter_mapping_rule",
    "load_mapping_engine",
]
