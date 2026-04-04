#!/usr/bin/env python3
"""
YANG Tree Generator for Unified OSS Framework.

Generates visual tree representations from YANG modules using regex-based
parsing, with support for both text and HTML output formats.

Usage:
    python generate_yang_tree.py --format text --output tree.txt
    python generate_yang_tree.py --format html --output tree.html
    python generate_yang_tree.py --format json --output tree.json
    python generate_yang_tree.py --modules all --format html --output full_tree.html
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
YANG_MODULES_DIR = PROJECT_ROOT / "yang-modules"


# ---------------------------------------------------------------------------
# Data model for YANG tree nodes
# ---------------------------------------------------------------------------

@dataclass
class YangNode:
    """Represents a single node in the YANG tree."""

    name: str
    node_type: str  # container, list, leaf, leaf-list, grouping, rpc, notification, augment, choice, anyxml, anydata
    module: str = ""
    namespace: str = ""
    description: str = ""
    type_info: str = ""
    config: Optional[bool] = None  # None means not specified
    children: List["YangNode"] = field(default_factory=list)
    line_number: int = 0
    keys: List[str] = field(default_factory=list)
    if_feature: str = ""
    mandatory: bool = False
    status: str = ""  # current, deprecated, obsolete
    units: str = ""
    default: str = ""
    reference: str = ""
    uses: str = ""  # grouping reference
    augment_target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the node and its descendants to a plain dict."""
        d: Dict[str, Any] = {
            "name": self.name,
            "type": self.node_type,
        }
        if self.module:
            d["module"] = self.module
        if self.description:
            d["description"] = self.description
        if self.type_info:
            d["type_info"] = self.type_info
        if self.config is not None:
            d["config"] = self.config
        if self.keys:
            d["keys"] = self.keys
        if self.if_feature:
            d["if_feature"] = self.if_feature
        if self.mandatory:
            d["mandatory"] = self.mandatory
        if self.status:
            d["status"] = self.status
        if self.units:
            d["units"] = self.units
        if self.default:
            d["default"] = self.default
        if self.uses:
            d["uses"] = self.uses
        if self.augment_target:
            d["augment_target"] = self.augment_target
        if self.children:
            d["children"] = [child.to_dict() for child in self.children]
        return d


# ---------------------------------------------------------------------------
# Regex-based YANG parser
# ---------------------------------------------------------------------------

# Keywords that open a brace-delimited block in YANG
_BLOCK_KEYWORDS = re.compile(
    r"^\s*(container|list|leaf-list|grouping|rpc|notification|augment|"
    r"choice|case|anyxml|anydata|input|output)\s+"
)

# Keywords that are leaf-like (no nested block of children)
_LEAF_KEYWORDS = re.compile(r"^\s*leaf\s+")

# Statement keywords that have a sub-block but we don't recurse into for tree
_SKIP_BLOCK_KEYWORDS = re.compile(
    r"^\s*(typedef|identity|type|enum|feature|if-feature|import|module|"
    r"submodule|revision|extension|deviation|belongs-to|rpc|notification)\b"
)

# Simple leaf-like statements (single value, no block)
_SIMPLE_STATEMENTS = re.compile(
    r"^\s*(prefix|namespace|yang-version|organization|contact|description|"
    r"reference|base|units|default|config|mandatory|status|ordered-by|"
    r"fraction-digits|range|length|pattern|path|require-instance|"
    r"error-message|error-app-tag|must|when|presence|key|min-elements|"
    r"max-elements|value|bit)\s+"
)

# uses statement
_USES_RE = re.compile(r"^\s*uses\s+([\w\-]+)\s*;")

# key statement inside list
_KEY_RE = re.compile(r"^\s*key\s+\"?([^\";]+)\"?\s*;")


class YangTreeParser:
    """Parses YANG files and builds tree structures using regex."""

    def __init__(self, modules_dir: Path = YANG_MODULES_DIR):
        self.modules_dir = modules_dir
        self.modules: Dict[str, Dict] = {}
        self.parsed_trees: Dict[str, YangNode] = {}
        self._groupings: Dict[str, List[YangNode]] = {}  # module -> groupings

    # ------------------------------------------------------------------
    # Module discovery
    # ------------------------------------------------------------------

    def discover_modules(self) -> List[Path]:
        """Find all .yang files in the modules directory."""
        if not self.modules_dir.is_dir():
            print(f"Warning: modules directory not found: {self.modules_dir}",
                  file=sys.stderr)
            return []
        return sorted(self.modules_dir.glob("*.yang"))

    # ------------------------------------------------------------------
    # Low-level parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_comments(text: str) -> str:
        """Remove // and /* */ comments, respecting strings."""
        result: List[str] = []
        i = 0
        in_string = False
        string_char = ""
        in_block_comment = False
        line_start = True

        while i < len(text):
            ch = text[i]

            # Handle block comments
            if in_block_comment:
                if ch == "*" and i + 1 < len(text) and text[i + 1] == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

            # Handle string literals
            if in_string:
                result.append(ch)
                if ch == "\\" and i + 1 < len(text):
                    result.append(text[i + 1])
                    i += 2
                    continue
                if ch == string_char:
                    in_string = False
                i += 1
                continue

            # Check for comment start
            if ch == "/" and i + 1 < len(text):
                if text[i + 1] == "/":
                    # Line comment – skip to end of line
                    while i < len(text) and text[i] != "\n":
                        i += 1
                    continue
                elif text[i + 1] == "*":
                    in_block_comment = True
                    i += 2
                    continue

            # Detect string start
            if ch in ('"', "'"):
                in_string = True
                string_char = ch
                result.append(ch)
                i += 1
                continue

            result.append(ch)
            i += 1

        return "".join(result)

    @staticmethod
    def _extract_block_body(text: str, start: int) -> Tuple[str, int]:
        """Given that text[start] == '{', return the body and index after '}'.

        Handles nested braces.
        """
        assert text[start] == "{"
        depth = 0
        i = start
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[start + 1:i], i + 1
            i += 1
        # Unmatched brace
        return text[start + 1:], len(text)

    @staticmethod
    def _find_matching_brace(text: str, start: int) -> int:
        """Return index of matching '}' for '{' at text[start]."""
        depth = 0
        i = start
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        return len(text)

    @staticmethod
    def _extract_string_arg(text: str) -> Optional[Tuple[str, int]]:
        """Extract a quoted string argument from position 0.

        Returns (string_value, index_after) or None.
        """
        text = text.lstrip()
        if not text:
            return None
        if text[0] == '"':
            end = text.index('"', 1) if '"' in text[1:] else len(text)
            return text[1:end], end + 1
        if text[0] == "'":
            end = text.index("'", 1) if "'" in text[1:] else len(text)
            return text[1:end], end + 1
        # Bare identifier (e.g. for uses, base, key, etc.)
        m = re.match(r'([\w\-:.]+)', text)
        if m:
            return m.group(1), m.end()
        return None

    @staticmethod
    def _strip_nested_blocks(block: str) -> str:
        """Remove all nested {…} blocks, keeping only top-level statements.

        This is used to correctly extract if-feature, config, description,
        etc. that belong to the current node rather than a child node.
        """
        result: List[str] = []
        i = 0
        depth = 0
        while i < len(block):
            if block[i] == '{':
                if depth == 0:
                    # We entered a nested block – skip it entirely
                    depth = 1
                else:
                    depth += 1
            elif block[i] == '}':
                depth -= 1
                if depth == 0:
                    # Returned to top level after nested block
                    pass
            elif depth == 0:
                result.append(block[i])
            # When depth > 0 we're inside a nested block – skip characters
            i += 1
        return ''.join(result)

    def _extract_description(self, block: str) -> str:
        """Extract the description sub-statement from a block."""
        # description "..." ;   or   description\n  "..." ;
        m = re.search(r'description\s+"((?:[^"\\]|\\.)*)"', block, re.DOTALL)
        if m:
            desc = m.group(1).strip()
            # Collapse whitespace
            desc = re.sub(r'\s+', ' ', desc)
            # Truncate long descriptions for tree display
            if len(desc) > 120:
                desc = desc[:117] + "..."
            return desc
        return ""

    def _extract_type_info(self, block: str) -> str:
        """Extract type information from a leaf or leaf-list block."""
        m = re.search(r'type\s+([\w\-:.]+)\s*(?:\{([^}]*)\}\s*;?|;)', block)
        if m:
            type_name = m.group(1)
            constraints = m.group(2) or ""
            # If the type is identityref, extract the base
            if type_name == "identityref" and constraints:
                base_m = re.search(r'base\s+([\w\-:.]+)', constraints)
                if base_m:
                    return f"identityref[{base_m.group(1)}]"
            parts = [type_name]
            # Extract range, length, pattern, fraction-digits
            for kw in ("range", "length", "pattern", "fraction-digits"):
                cm = re.search(kw + r'\s+"?([^";]+)"?\s*;', constraints)
                if cm:
                    parts.append(f"{kw}={cm.group(1).strip()}")
            return " ".join(parts)
        # identityref (fallback – type block not matched by generic regex)
        m = re.search(r'type\s+identityref\s*\{([^}]*)\}', block)
        if m:
            base_m = re.search(r'base\s+([\w\-:.]+)', m.group(1))
            if base_m:
                return f"identityref[{base_m.group(1)}]"
        # enumeration inline
        m = re.search(r'type\s+enumeration\s*\{', block)
        if m:
            start = m.end() - 1
            end = self._find_matching_brace(block, start)
            enum_body = block[start + 1:end]
            enums = re.findall(r'enum\s+([\w]+)', enum_body)
            if enums:
                return f"enum{{{','.join(enums[:5])}{'...' if len(enums) > 5 else ''}}}"
        return ""

    def _extract_key(self, block: str) -> List[str]:
        """Extract list key names."""
        m = _KEY_RE.search(block)
        if m:
            return [k.strip() for k in m.group(1).split()]
        return []

    # ------------------------------------------------------------------
    # Parse a single YANG module
    # ------------------------------------------------------------------

    def parse_module(self, file_path: Path) -> Dict[str, Any]:
        """Parse a single YANG file and extract module metadata + tree."""
        content = file_path.read_text(encoding="utf-8", errors="replace")
        clean = self._strip_comments(content)

        # Module header
        module_m = re.search(r'module\s+([\w\-]+)\s*\{', clean)
        if not module_m:
            submodule_m = re.search(r'submodule\s+([\w\-]+)\s*\{', clean)
            if submodule_m:
                name = submodule_m.group(1)
            else:
                return {"name": file_path.stem, "error": "Cannot parse module header"}
        else:
            name = module_m.group(1)

        # Namespace
        ns_m = re.search(r'namespace\s+"([^"]+)"', clean)
        namespace = ns_m.group(1) if ns_m else ""

        # Prefix
        prefix_m = re.search(r'prefix\s+"?([\w\-]+)"?\s*;', clean)
        prefix = prefix_m.group(1) if prefix_m else ""

        # Imports
        imports = re.findall(r'import\s+([\w\-]+)\s*\{', clean)

        # Revision
        rev_m = re.search(r'revision\s+([\d\-]+)\s*\{', clean)
        revision = rev_m.group(1) if rev_m else ""

        # Organization
        org_m = re.search(r'organization\s+"([^"]+)"', clean)
        organization = org_m.group(1) if org_m else ""

        # Description (top-level)
        top_desc_m = re.search(
            r'(?:^|\n)\s*description\s+"((?:[^"\\]|\\.)*)"\s*;', clean, re.DOTALL
        )
        description = ""
        if top_desc_m:
            description = re.sub(r'\s+', ' ', top_desc_m.group(1)).strip()
            if len(description) > 300:
                description = description[:297] + "..."

        meta = {
            "name": name,
            "namespace": namespace,
            "prefix": prefix,
            "imports": imports,
            "revision": revision,
            "organization": organization,
            "description": description,
            "file": str(file_path),
        }

        # Parse the tree from the module body
        if module_m or submodule_m:
            brace_start = (module_m or submodule_m).end() - 1
            body, _ = self._extract_block_body(clean, brace_start)
            meta["tree"] = self._parse_block(body, name, namespace, 0)
            meta["groupings"] = self._extract_groupings(body, name)

        return meta

    def _extract_groupings(self, body: str, module: str) -> Dict[str, List[YangNode]]:
        """Extract grouping definitions (we store them for uses expansion)."""
        groupings: Dict[str, List[YangNode]] = {}
        for m in re.finditer(
            r'grouping\s+([\w\-]+)\s*\{', body
        ):
            gname = m.group(1)
            gstart = m.end() - 1
            gbody, _ = self._extract_block_body(body, gstart)
            children = self._parse_block(gbody, module, "", m.start())
            groupings[gname] = children
        return groupings

    def _parse_block(self, block: str, module: str, namespace: str,
                     base_line: int) -> List[YangNode]:
        """Parse a YANG block body into a list of YangNode children."""
        nodes: List[YangNode] = []
        i = 0
        block_len = len(block)

        while i < block_len:
            # Skip whitespace
            while i < block_len and block[i] in " \t\n\r":
                i += 1
            if i >= block_len:
                break

            rest = block[i:]

            # Try to match container, list, choice, etc.
            block_m = re.match(
                r'(container|list|grouping|choice|case|anyxml|anydata|augment|notification)\s+'
                r'([\w\-]+)\s*',
                rest,
            )
            if block_m:
                keyword = block_m.group(1)
                name = block_m.group(2)
                start_in_block = i + block_m.end()

                # Skip to opening brace
                brace_idx = block.index("{", start_in_block)
                inner_body, after = self._extract_block_body(block, brace_idx)

                if keyword == "grouping":
                    # Skip groupings at this level (extracted separately)
                    i = after
                    continue

                # Check for key inside the inner body (before we recurse)
                keys = []
                if keyword == "list":
                    keys = self._extract_key(inner_body)

                # Extract properties from inner body
                desc = self._extract_description(inner_body)

                # config (only top-level)
                top_level = self._strip_nested_blocks(inner_body)
                config_val = None
                config_m = re.search(r'\bconfig\s+(true|false)\s*;', top_level)
                if config_m:
                    config_val = config_m.group(1) == "true"

                # if-feature (only top-level)
                if_feat_m = re.search(r'if-feature\s+([\w\-]+)\s*;', top_level)
                if_feature = if_feat_m.group(1) if if_feat_m else ""

                # status (only top-level)
                status_m = re.search(r'\bstatus\s+(current|deprecated|obsolete)\s*;', top_level)
                status = status_m.group(1) if status_m else ""

                # presence
                presence_m = re.search(r'presence\s+"([^"]*)"\s*;', inner_body)

                # uses statements
                uses_nodes: List[YangNode] = []
                for um in re.finditer(r'uses\s+([\w\-]+)\s*;', inner_body):
                    gname = um.group(1)
                    if gname in self._groupings.get(module, []):
                        uses_nodes = self._groupings[module][gname]

                # Determine the effective node type for tree rendering
                node_type = keyword
                if keyword == "augment":
                    # Parse augment target path
                    target_m = re.match(r'augment\s+"([^"]+)"', rest)
                    if not target_m:
                        target_m = re.match(r'augment\s+([\w\-:/]+)', rest)
                    augment_target = target_m.group(1) if target_m else ""
                    # Parse children of augment block
                    children = self._parse_block(inner_body, module, namespace, i)
                    node = YangNode(
                        name=name,
                        node_type="augment",
                        module=module,
                        namespace=namespace,
                        description=desc,
                        config=config_val,
                        children=children,
                        augment_target=augment_target,
                    )
                    nodes.append(node)
                    i = after
                    continue

                children = self._parse_block(inner_body, module, namespace, i)

                node = YangNode(
                    name=name,
                    node_type=node_type,
                    module=module,
                    namespace=namespace,
                    description=desc,
                    config=config_val,
                    children=children + uses_nodes,
                    keys=keys,
                    if_feature=if_feature,
                    status=status,
                )
                nodes.append(node)
                i = after
                continue

            # Try leaf
            leaf_m = re.match(r'leaf\s+([\w\-]+)\s*\{', rest)
            if leaf_m:
                name = leaf_m.group(1)
                brace_idx = block.index("{", i + leaf_m.start())
                inner_body, after = self._extract_block_body(block, brace_idx)
                desc = self._extract_description(inner_body)
                type_info = self._extract_type_info(inner_body)
                top_level = self._strip_nested_blocks(inner_body)
                config_val = None
                config_m = re.search(r'\bconfig\s+(true|false)\s*;', top_level)
                if config_m:
                    config_val = config_m.group(1) == "true"
                mandatory_m = re.search(r'\bmandatory\s+true\s*;', top_level)
                mandatory = mandatory_m is not None
                default_m = re.search(r'\bdefault\s+"([^"]+)"\s*;', top_level)
                default = default_m.group(1) if default_m else ""
                units_m = re.search(r'\bunits\s+"([^"]+)"\s*;', top_level)
                units = units_m.group(1) if units_m else ""
                status_m = re.search(r'\bstatus\s+(current|deprecated|obsolete)\s*;', top_level)
                status = status_m.group(1) if status_m else ""
                if_feat_m = re.search(r'if-feature\s+([\w\-]+)\s*;', top_level)
                if_feature = if_feat_m.group(1) if if_feat_m else ""

                node = YangNode(
                    name=name,
                    node_type="leaf",
                    module=module,
                    namespace=namespace,
                    description=desc,
                    type_info=type_info,
                    config=config_val,
                    mandatory=mandatory,
                    default=default,
                    units=units,
                    status=status,
                    if_feature=if_feature,
                )
                nodes.append(node)
                i = after
                continue

            # Try leaf-list
            leaflist_m = re.match(r'leaf-list\s+([\w\-]+)\s*\{', rest)
            if leaflist_m:
                name = leaflist_m.group(1)
                brace_idx = block.index("{", i + leaflist_m.start())
                inner_body, after = self._extract_block_body(block, brace_idx)
                desc = self._extract_description(inner_body)
                type_info = self._extract_type_info(inner_body)
                top_level = self._strip_nested_blocks(inner_body)
                config_val = None
                config_m = re.search(r'\bconfig\s+(true|false)\s*;', top_level)
                if config_m:
                    config_val = config_m.group(1) == "true"
                min_el = re.search(r'min-elements\s+(\d+)\s*;', top_level)
                max_el = re.search(r'max-elements\s+(\d+|unbounded)\s*;', top_level)
                ordered_m = re.search(r'ordered-by\s+(\w+)\s*;', top_level)
                units_m = re.search(r'\bunits\s+"([^"]+)"\s*;', top_level)
                units = units_m.group(1) if units_m else ""

                type_label = type_info or "string"
                extras = []
                if min_el:
                    extras.append(f"min={min_el.group(1)}")
                if max_el:
                    extras.append(f"max={max_el.group(1)}")
                if ordered_m:
                    extras.append(ordered_m.group(1))
                if units:
                    extras.append(units)
                full_type = type_label
                if extras:
                    full_type += " [" + ", ".join(extras) + "]"

                node = YangNode(
                    name=name,
                    node_type="leaf-list",
                    module=module,
                    namespace=namespace,
                    description=desc,
                    type_info=full_type,
                    config=config_val,
                )
                nodes.append(node)
                i = after
                continue

            # Try rpc
            rpc_m = re.match(r'rpc\s+([\w\-]+)\s*\{', rest)
            if rpc_m:
                name = rpc_m.group(1)
                brace_idx = block.index("{", i + rpc_m.start())
                inner_body, after = self._extract_block_body(block, brace_idx)
                desc = self._extract_description(inner_body)
                children = self._parse_block(inner_body, module, namespace, i)
                node = YangNode(
                    name=name,
                    node_type="rpc",
                    module=module,
                    namespace=namespace,
                    description=desc,
                    children=children,
                )
                nodes.append(node)
                i = after
                continue

            # Try uses (top-level uses)
            uses_m = _USES_RE.match(rest)
            if uses_m:
                gname = uses_m.group(1)
                uses_children = self._groupings.get(module, {}).get(gname, [])
                nodes.extend(uses_children)
                i += uses_m.end()
                continue

            # Skip any other statement (typedef, feature, identity, etc.)
            # Find the end of this statement
            semi = block.find(";", i)
            brace = block.find("{", i)
            if semi == -1 and brace == -1:
                break
            if brace != -1 and (semi == -1 or brace < semi):
                # Block statement we don't care about – skip it
                end = self._find_matching_brace(block, brace) + 1
            else:
                end = semi + 1
            i = end

        return nodes

    # ------------------------------------------------------------------
    # Parse all modules
    # ------------------------------------------------------------------

    def parse_all_modules(self) -> Dict[str, Dict]:
        """Parse all YANG modules in the directory."""
        self._groupings.clear()
        paths = self.discover_modules()
        if not paths:
            print("No YANG modules found.", file=sys.stderr)
            return {}

        for p in paths:
            try:
                meta = self.parse_module(p)
                self.modules[meta["name"]] = meta
                # Store groupings for uses resolution
                if "groupings" in meta:
                    self._groupings[meta["name"]] = meta["groupings"]
            except Exception as exc:
                print(f"Error parsing {p}: {exc}", file=sys.stderr)

        return self.modules

    # ------------------------------------------------------------------
    # Build trees
    # ------------------------------------------------------------------

    def build_tree(self, module_name: str) -> YangNode:
        """Build a tree structure from a parsed module."""
        if module_name not in self.modules:
            raise ValueError(f"Module '{module_name}' not found. "
                             f"Available: {list(self.modules.keys())}")
        meta = self.modules[module_name]
        children = meta.get("tree", [])
        return YangNode(
            name=module_name,
            node_type="module",
            module=module_name,
            namespace=meta.get("namespace", ""),
            description=meta.get("description", ""),
            children=children,
        )

    def build_unified_tree(self) -> YangNode:
        """Build the unified tree from the tree-model module."""
        # Try unified-oss-tree-model first, fall back to any module
        candidates = [
            "unified-oss-tree-model",
            "unified-oss-core-nrm",
        ]
        for name in candidates:
            if name in self.modules:
                return self.build_tree(name)
        # Fall back to first available module
        if self.modules:
            first = next(iter(self.modules))
            return self.build_tree(first)
        return YangNode(name="empty", node_type="module")

    def build_combined_tree(self) -> YangNode:
        """Build a combined tree from all parsed modules."""
        root = YangNode(
            name="unified-oss-framework",
            node_type="module",
            description="Combined YANG tree from all Unified OSS Framework modules",
        )
        for mod_name, meta in sorted(self.modules.items()):
            mod_node = YangNode(
                name=mod_name,
                node_type="container",
                module=mod_name,
                namespace=meta.get("namespace", ""),
                description=meta.get("description", "")[:100],
                children=meta.get("tree", []),
            )
            root.children.append(mod_node)
        return root


# ---------------------------------------------------------------------------
# Text renderer (pyang-style)
# ---------------------------------------------------------------------------

class TextTreeRenderer:
    """Renders YANG tree as text with box-drawing characters."""

    BRANCH = "├── "
    LAST_BRANCH = "└── "
    VERTICAL = "│   "
    SPACE = "    "

    def render(self, root: YangNode, max_depth: int = 10) -> str:
        """Render tree as text with box-drawing characters."""
        lines: List[str] = []
        self._render_node(root, "", True, 0, max_depth, lines)
        return "\n".join(lines)

    def _format_label(self, node: YangNode) -> str:
        """Format a single node's label like pyang does."""
        name = node.name
        type_map = {
            "container": "",
            "list": "",
            "leaf": "",
            "leaf-list": "",
            "grouping": "",
            "rpc": "",
            "notification": "",
            "augment": "",
            "choice": "",
            "case": "",
            "anyxml": "",
            "anydata": "",
            "module": "",
        }
        suffix = ""
        if node.node_type == "container":
            if node.if_feature:
                suffix = f"?  [if-feature {node.if_feature}]"
        elif node.node_type == "list":
            key_str = " ".join(node.keys)
            suffix = f"  [key: {key_str}]" if node.keys else ""
            if node.if_feature:
                suffix += f"  [if-feature {node.if_feature}]"
        elif node.node_type == "leaf":
            type_part = node.type_info or "string"
            config_part = ""
            if node.config is False:
                config_part = "  {ro}"
            elif node.mandatory:
                config_part = "  {mand}"
            default_part = f'  default="{node.default}"' if node.default else ""
            status_part = f"  [{node.status}]" if node.status else ""
            suffix = f"  {type_part}{config_part}{default_part}{status_part}"
        elif node.node_type == "leaf-list":
            suffix = f"  [{node.type_info or 'string'}]"
        elif node.node_type == "rpc":
            suffix = "  {rpc}"
        elif node.node_type == "notification":
            suffix = "  {notification}"
        elif node.node_type == "augment":
            suffix = f"  [augment: {node.augment_target}]"
        elif node.node_type == "choice":
            suffix = "  {choice}"
        elif node.node_type == "case":
            suffix = "  {case}"

        return f"{name}{suffix}"

    def _render_node(self, node: YangNode, prefix: str, is_last: bool,
                     depth: int, max_depth: int, lines: List[str]) -> None:
        if depth > max_depth:
            return
        connector = self.LAST_BRANCH if is_last else self.BRANCH
        if prefix == "" and depth == 0:
            # Root node
            lines.append(self._format_label(node))
        else:
            lines.append(f"{prefix}{connector}{self._format_label(node)}")

        if not node.children:
            return
        child_prefix = prefix
        if depth > 0 or prefix != "":
            child_prefix = prefix + (self.SPACE if is_last else self.VERTICAL)
        else:
            child_prefix = prefix + self.SPACE

        for idx, child in enumerate(node.children):
            is_last_child = (idx == len(node.children) - 1)
            self._render_node(child, child_prefix, is_last_child,
                              depth + 1, max_depth, lines)


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

class HtmlTreeRenderer:
    """Renders YANG tree as interactive HTML with collapsible nodes."""

    def render(self, root: YangNode,
               title: str = "Unified OSS YANG Tree Model") -> str:
        """Generate a complete HTML page with an interactive tree."""
        stats = self._collect_stats(root)
        body_nodes = self._render_node_html(root, 0)
        modules_info = self._build_modules_info()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
/* ===== BASE STYLES ===== */
:root {{
    --bg: #0f1117;
    --surface: #1a1d27;
    --surface2: #242836;
    --border: #2e3348;
    --text: #e1e4ed;
    --text-muted: #8b90a5;
    --accent: #6c8cff;
    --container-color: #5b9bd5;
    --list-color: #70ad47;
    --leaf-color: #9e9e9e;
    --rpc-color: #b07cd8;
    --notification-color: #e8a838;
    --augment-color: #4ecdc4;
    --choice-color: #f06292;
    --module-color: #6c8cff;
    --radius: 6px;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 0;
}}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

/* ===== LAYOUT ===== */
.header {{
    background: linear-gradient(135deg, #1a1d27 0%, #242836 100%);
    border-bottom: 1px solid var(--border);
    padding: 20px 24px;
    position: sticky;
    top: 0;
    z-index: 100;
}}
.header h1 {{
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 4px;
}}
.header .subtitle {{
    color: var(--text-muted);
    font-size: 0.85rem;
}}
.container {{
    display: flex;
    height: calc(100vh - 90px);
}}

/* ===== SIDEBAR ===== */
.sidebar {{
    width: 300px;
    min-width: 300px;
    background: var(--surface);
    border-right: 1px solid var(--border);
    overflow-y: auto;
    padding: 16px;
}}
.sidebar h2 {{
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin-bottom: 12px;
}}
.stat-card {{
    background: var(--surface2);
    border-radius: var(--radius);
    padding: 12px;
    margin-bottom: 8px;
}}
.stat-card .stat-value {{
    font-size: 1.6rem;
    font-weight: 700;
}}
.stat-card .stat-label {{
    font-size: 0.78rem;
    color: var(--text-muted);
}}
.legend {{
    margin-top: 20px;
}}
.legend-item {{
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 0;
    font-size: 0.82rem;
}}
.legend-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
}}
.module-list {{ margin-top: 16px; }}
.module-item {{
    padding: 6px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    cursor: pointer;
    transition: background 0.15s;
}}
.module-item:hover {{
    background: var(--surface2);
}}

/* ===== SEARCH BAR ===== */
.search-bar {{
    padding: 12px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
}}
.search-bar input {{
    width: 100%;
    padding: 8px 12px;
    border-radius: var(--radius);
    border: 1px solid var(--border);
    background: var(--surface2);
    color: var(--text);
    font-size: 0.9rem;
    outline: none;
    transition: border-color 0.2s;
}}
.search-bar input:focus {{
    border-color: var(--accent);
}}
.search-bar input::placeholder {{
    color: var(--text-muted);
}}
.toolbar {{
    display: flex;
    gap: 8px;
    padding: 8px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    font-size: 0.8rem;
}}
.toolbar button {{
    padding: 4px 10px;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--surface2);
    color: var(--text);
    cursor: pointer;
    font-size: 0.78rem;
    transition: background 0.15s;
}}
.toolbar button:hover {{
    background: var(--border);
}}

/* ===== TREE AREA ===== */
.tree-area {{
    flex: 1;
    overflow: auto;
    padding: 16px;
}}

/* ===== TREE NODES ===== */
.tree-node {{
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 0.82rem;
    line-height: 1.8;
    white-space: nowrap;
}}
.tree-node .node-row {{
    display: flex;
    align-items: flex-start;
    padding: 1px 4px;
    border-radius: 3px;
    cursor: default;
}}
.tree-node .node-row:hover {{
    background: var(--surface2);
}}
.tree-node .toggle {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    cursor: pointer;
    user-select: none;
    color: var(--text-muted);
    font-size: 0.7rem;
    border-radius: 3px;
    transition: background 0.15s;
    flex-shrink: 0;
    margin-right: 2px;
}}
.tree-node .toggle:hover {{
    background: var(--border);
    color: var(--text);
}}
.tree-node .toggle-placeholder {{
    width: 18px;
    display: inline-block;
    flex-shrink: 0;
    margin-right: 2px;
}}
.tree-node .node-name {{
    font-weight: 600;
    margin-right: 4px;
}}
.tree-node .node-type-badge {{
    font-size: 0.65rem;
    padding: 1px 5px;
    border-radius: 3px;
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: 0.03em;
    margin-right: 4px;
}}
.tree-node .type-container .node-name {{ color: var(--container-color); }}
.tree-node .type-container .node-type-badge {{ background: rgba(91,155,213,0.15); color: var(--container-color); }}
.tree-node .type-list .node-name {{ color: var(--list-color); }}
.tree-node .type-list .node-type-badge {{ background: rgba(112,173,71,0.15); color: var(--list-color); }}
.tree-node .type-leaf .node-name {{ color: var(--leaf-color); font-weight: 400; }}
.tree-node .type-leaf .node-type-badge {{ background: rgba(158,158,158,0.1); color: var(--leaf-color); }}
.tree-node .type-leaf-list .node-name {{ color: var(--leaf-color); font-style: italic; }}
.tree-node .type-leaf-list .node-type-badge {{ background: rgba(158,158,158,0.1); color: var(--leaf-color); }}
.tree-node .type-rpc .node-name {{ color: var(--rpc-color); }}
.tree-node .type-rpc .node-type-badge {{ background: rgba(176,124,216,0.15); color: var(--rpc-color); }}
.tree-node .type-notification .node-name {{ color: var(--notification-color); }}
.tree-node .type-notification .node-type-badge {{ background: rgba(232,168,56,0.15); color: var(--notification-color); }}
.tree-node .type-augment .node-name {{ color: var(--augment-color); }}
.tree-node .type-augment .node-type-badge {{ background: rgba(78,205,196,0.15); color: var(--augment-color); }}
.tree-node .type-choice .node-name {{ color: var(--choice-color); }}
.tree-node .type-choice .node-type-badge {{ background: rgba(240,98,146,0.15); color: var(--choice-color); }}
.tree-node .type-module .node-name {{ color: var(--module-color); }}
.tree-node .type-module .node-type-badge {{ background: rgba(108,140,255,0.15); color: var(--module-color); }}

.tree-node .node-meta {{
    color: var(--text-muted);
    font-size: 0.75rem;
}}
.tree-node .node-desc {{
    color: var(--text-muted);
    font-size: 0.72rem;
    font-style: italic;
    margin-left: 8px;
    max-width: 400px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}}
.tree-node .children {{
    padding-left: 20px;
    overflow: hidden;
    transition: max-height 0.25s ease;
}}
.tree-node .children.collapsed {{
    max-height: 0 !important;
    overflow: hidden;
}}
.tree-node .node-row.search-match {{
    background: rgba(108,140,255,0.2);
    outline: 1px solid var(--accent);
}}
.tree-node .node-row.search-hidden {{
    display: none;
}}

/* ===== NO RESULTS ===== */
.no-results {{
    text-align: center;
    color: var(--text-muted);
    padding: 40px;
    font-size: 0.9rem;
}}

/* ===== PRINT STYLES ===== */
@media print {{
    body {{ background: #fff; color: #000; }}
    .header {{ background: #fff; border-bottom: 2px solid #ccc; position: static; }}
    .sidebar, .search-bar, .toolbar {{ display: none; }}
    .container {{ height: auto; }}
    .tree-area {{ padding: 0; }}
    .tree-node .node-row:hover {{ background: transparent; }}
    .tree-node .children.collapsed {{ max-height: none !important; overflow: visible; }}
    .tree-node .node-name {{ color: #000 !important; }}
}}

/* ===== RESPONSIVE ===== */
@media (max-width: 768px) {{
    .sidebar {{ display: none; }}
    .container {{ height: calc(100vh - 90px); }}
}}
</style>
</head>
<body>

<div class="header">
    <h1>🌳 {title}</h1>
    <div class="subtitle">Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | {stats['total_nodes']} nodes | {stats['total_modules']} modules</div>
</div>

<div class="search-bar">
    <input type="text" id="searchInput" placeholder="🔍 Search nodes... (Ctrl+K)" autocomplete="off">
</div>

<div class="toolbar">
    <button onclick="expandAll()">Expand All</button>
    <button onclick="collapseAll()">Collapse All</button>
    <button onclick="expandLevel(2)">Expand 2 Levels</button>
    <button onclick="expandLevel(4)">Expand 4 Levels</button>
</div>

<div class="container">
    <div class="sidebar">
        <h2>📊 Statistics</h2>
        <div class="stat-card">
            <div class="stat-value">{stats['total_nodes']}</div>
            <div class="stat-label">Total Nodes</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats['containers']}</div>
            <div class="stat-label" style="color:var(--container-color)">Containers</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats['lists']}</div>
            <div class="stat-label" style="color:var(--list-color)">Lists</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats['leaves']}</div>
            <div class="stat-label" style="color:var(--leaf-color)">Leaves</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats['leaf_lists']}</div>
            <div class="stat-label">Leaf-lists</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats['rpcs']}</div>
            <div class="stat-label" style="color:var(--rpc-color)">RPCs</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats['notifications']}</div>
            <div class="stat-label" style="color:var(--notification-color)">Notifications</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats['max_depth']}</div>
            <div class="stat-label">Max Depth</div>
        </div>

        <div class="legend">
            <h2>Legend</h2>
            <div class="legend-item"><span class="legend-dot" style="background:var(--container-color)"></span>Container</div>
            <div class="legend-item"><span class="legend-dot" style="background:var(--list-color)"></span>List</div>
            <div class="legend-item"><span class="legend-dot" style="background:var(--leaf-color)"></span>Leaf</div>
            <div class="legend-item"><span class="legend-dot" style="background:var(--rpc-color)"></span>RPC</div>
            <div class="legend-item"><span class="legend-dot" style="background:var(--notification-color)"></span>Notification</div>
            <div class="legend-item"><span class="legend-dot" style="background:var(--augment-color)"></span>Augment</div>
            <div class="legend-item"><span class="legend-dot" style="background:var(--choice-color)"></span>Choice</div>
        </div>

        <div class="module-list">
            <h2>📦 Modules ({stats['total_modules']})</h2>
            {modules_info}
        </div>
    </div>

    <div class="tree-area" id="treeArea">
        {body_nodes}
        <div class="no-results" id="noResults" style="display:none;">
            No nodes match your search query.
        </div>
    </div>
</div>

<script>
// ===== SEARCH FUNCTIONALITY =====
const searchInput = document.getElementById('searchInput');
const noResults = document.getElementById('noResults');
let debounceTimer;

searchInput.addEventListener('input', function() {{
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => searchTree(this.value), 200);
}});

document.addEventListener('keydown', function(e) {{
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {{
        e.preventDefault();
        searchInput.focus();
        searchInput.select();
    }}
    if (e.key === 'Escape') {{
        searchInput.value = '';
        searchTree('');
        searchInput.blur();
    }}
}});

function searchTree(query) {{
    const q = query.toLowerCase().trim();
    const allRows = document.querySelectorAll('.tree-node .node-row');
    const allChildren = document.querySelectorAll('.tree-node .children');
    let matchCount = 0;

    if (!q) {{
        allRows.forEach(r => {{
            r.classList.remove('search-match', 'search-hidden');
        }});
        allChildren.forEach(c => {{
            c.classList.remove('collapsed');
        }});
        noResults.style.display = 'none';
        return;
    }}

    // First, hide all
    allRows.forEach(r => {{
        r.classList.add('search-hidden');
        r.classList.remove('search-match');
    }});

    // Find matches and show them + their ancestors
    allRows.forEach(r => {{
        const name = r.getAttribute('data-node-name') || '';
        const type = r.getAttribute('data-node-type') || '';
        const meta = r.getAttribute('data-node-meta') || '';
        if (name.includes(q) || type.includes(q) || meta.includes(q)) {{
            r.classList.remove('search-hidden');
            r.classList.add('search-match');
            matchCount++;
            // Show parent nodes
            let parent = r.parentElement;
            while (parent) {{
                if (parent.classList && parent.classList.contains('children')) {{
                    parent.classList.remove('collapsed');
                }}
                if (parent.classList && parent.classList.contains('node-row')) {{
                    parent.classList.remove('search-hidden');
                }}
                parent = parent.parentElement;
            }}
        }}
    }});

    noResults.style.display = matchCount === 0 ? 'block' : 'none';
}}

// ===== EXPAND / COLLAPSE =====
function toggleNode(el) {{
    const children = el.parentElement.querySelector(':scope > .children');
    if (!children) return;
    const icon = el.querySelector('.toggle');
    if (children.classList.contains('collapsed')) {{
        children.classList.remove('collapsed');
        if (icon) icon.textContent = '▼';
    }} else {{
        children.classList.add('collapsed');
        if (icon) icon.textContent = '▶';
    }}
}}

function expandAll() {{
    document.querySelectorAll('.tree-node .children.collapsed').forEach(c => {{
        c.classList.remove('collapsed');
    }});
    document.querySelectorAll('.tree-node .toggle').forEach(t => {{
        t.textContent = '▼';
    }});
}}

function collapseAll() {{
    document.querySelectorAll('.tree-node .children').forEach(c => {{
        c.classList.add('collapsed');
    }});
    document.querySelectorAll('.tree-node .toggle').forEach(t => {{
        t.textContent = '▶';
    }});
}}

function expandLevel(targetDepth) {{
    document.querySelectorAll('.tree-node').forEach(node => {{
        const depth = parseInt(node.getAttribute('data-depth') || '0');
        const children = node.querySelector(':scope > .children');
        const toggle = node.querySelector(':scope > .node-row .toggle');
        if (!children) return;
        if (depth < targetDepth) {{
            children.classList.remove('collapsed');
            if (toggle) toggle.textContent = '▼';
        }} else {{
            children.classList.add('collapsed');
            if (toggle) toggle.textContent = '▶';
        }}
    }});
}}

// Auto-collapse all on load
document.addEventListener('DOMContentLoaded', function() {{
    expandLevel(2);
}});
</script>

</body>
</html>"""
        return html

    def _collect_stats(self, root: YangNode) -> Dict[str, int]:
        """Collect statistics from the tree."""
        stats = {
            "containers": 0,
            "lists": 0,
            "leaves": 0,
            "leaf_lists": 0,
            "rpcs": 0,
            "notifications": 0,
            "augments": 0,
            "total_nodes": 0,
            "max_depth": 0,
            "total_modules": 0,
        }

        def _walk(node: YangNode, depth: int) -> None:
            stats["total_nodes"] += 1
            if depth > stats["max_depth"]:
                stats["max_depth"] = depth
            t = node.node_type
            if t == "container":
                stats["containers"] += 1
            elif t == "list":
                stats["lists"] += 1
            elif t == "leaf":
                stats["leaves"] += 1
            elif t == "leaf-list":
                stats["leaf_lists"] += 1
            elif t == "rpc":
                stats["rpcs"] += 1
            elif t == "notification":
                stats["notifications"] += 1
            elif t == "augment":
                stats["augments"] += 1
            elif t == "module":
                stats["total_modules"] += 1
            for child in node.children:
                _walk(child, depth + 1)

        _walk(root, 0)
        return stats

    def _render_node_html(self, node: YangNode, depth: int) -> str:
        """Render a single node and its children as HTML."""
        has_children = len(node.children) > 0
        node_type_css = f"type-{node.node_type}" if node.node_type else ""
        node_id = re.sub(r'[^a-zA-Z0-9_-]', '_', node.name)

        # Build meta string for search
        meta_parts = []
        if node.type_info:
            meta_parts.append(node.type_info)
        if node.description:
            meta_parts.append(node.description)
        if node.if_feature:
            meta_parts.append(f"if-feature {node.if_feature}")
        if node.keys:
            meta_parts.append(f"key {' '.join(node.keys)}")
        if node.uses:
            meta_parts.append(f"uses {node.uses}")
        meta_str = " | ".join(meta_parts)
        # Escape for HTML attribute
        meta_str_escaped = (
            meta_str.replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;")
        )

        # Description text (escaped)
        desc_escaped = ""
        if node.description:
            desc_escaped = (
                node.description.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;")
            )

        # Toggle button
        if has_children:
            toggle = '<span class="toggle" onclick="toggleNode(this)">▼</span>'
        else:
            toggle = '<span class="toggle-placeholder"></span>'

        # Type badge
        badge = f'<span class="node-type-badge">{node.node_type}</span>'

        # Meta info after name
        meta_html = ""
        if node.node_type == "list" and node.keys:
            meta_html = f'<span class="node-meta">[key: {" ".join(node.keys)}]</span>'
        elif node.node_type == "leaf" and node.type_info:
            cfg = ""
            if node.config is False:
                cfg = " {ro}"
            elif node.mandatory:
                cfg = " {mand}"
            def_ = f' default="{node.default}"' if node.default else ""
            meta_html = f'<span class="node-meta">{node.type_info}{cfg}{def_}</span>'
        elif node.node_type == "leaf-list" and node.type_info:
            meta_html = f'<span class="node-meta">[{node.type_info}]</span>'
        elif node.node_type == "rpc":
            meta_html = '<span class="node-meta">{rpc}</span>'
        elif node.node_type == "notification":
            meta_html = '<span class="node-meta">{{notification}}</span>'
        elif node.node_type == "augment" and node.augment_target:
            meta_html = f'<span class="node-meta">[augment: {node.augment_target}]</span>'
        elif node.node_type == "choice":
            meta_html = '<span class="node-meta">{choice}</span>'
        elif node.if_feature:
            meta_html = f'<span class="node-meta">[if-feature {node.if_feature}]</span>'

        desc_html = f'<span class="node-desc" title="{desc_escaped}">{desc_escaped}</span>' if desc_escaped else ""

        children_html = ""
        if has_children:
            children_inner = "\n".join(
                self._render_node_html(c, depth + 1) for c in node.children
            )
            children_html = f'<div class="children">{children_inner}\n</div>'

        return (
            f'<div class="tree-node {node_type_css}" data-depth="{depth}">\n'
            f'  <div class="node-row" '
            f'data-node-name="{node.name}" '
            f'data-node-type="{node.node_type}" '
            f'data-node-meta="{meta_str_escaped}">\n'
            f'    {toggle}\n'
            f'    <span class="node-name">{node.name}</span>\n'
            f'    {badge}\n'
            f'    {meta_html}\n'
            f'    {desc_html}\n'
            f'  </div>\n'
            f'  {children_html}\n'
            f'</div>'
        )

    def _build_modules_info(self) -> str:
        """Build sidebar module list HTML from parsed modules."""
        items: List[str] = []
        for name, meta in sorted(self.modules.items()):
            items.append(
                f'<div class="module-item" title="{meta.get("description", "")[:80]}">'
                f"📦 {name}</div>"
            )
        return "\n".join(items)


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------

class JsonTreeRenderer:
    """Renders YANG tree as JSON for API consumption."""

    def render(self, root: YangNode) -> Dict[str, Any]:
        """Return the tree as a JSON-serialisable dict."""
        return root.to_dict()

    def render_with_metadata(self, root: YangNode, title: str = "") -> Dict[str, Any]:
        """Return JSON with wrapper metadata."""
        stats = self._stats(root)
        return {
            "metadata": {
                "title": title,
                "generated": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "generator": "Unified OSS Framework YANG Tree Generator",
                **stats,
            },
            "tree": root.to_dict(),
        }

    @staticmethod
    def _stats(root: YangNode) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        total = [0]

        def walk(node: YangNode) -> None:
            total[0] += 1
            t = node.node_type
            counts[t] = counts.get(t, 0) + 1
            for c in node.children:
                walk(c)

        walk(root)
        return {"total_nodes": total[0], **counts}


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class YangTreeGenerator:
    """Main generator orchestrating parsing and rendering."""

    def __init__(self, modules_dir: Path = YANG_MODULES_DIR):
        self.parser = YangTreeParser(modules_dir)
        self.text_renderer = TextTreeRenderer()
        self.html_renderer = HtmlTreeRenderer()
        self.json_renderer = JsonTreeRenderer()

    def generate(self, fmt: str = "text", modules: str = "unified",
                 output: str = None, max_depth: int = 10,
                 title: str = "Unified OSS Framework - YANG Tree Model") -> str:
        """Generate tree in the specified format.

        Parameters
        ----------
        fmt : str
            One of 'text', 'html', 'json'.
        modules : str
            Module name, 'all', or 'unified'.
        output : str or None
            Output file path. If None, result is printed.
        max_depth : int
            Maximum tree depth for text output.
        title : str
            Title for HTML output.
        """
        # Parse modules
        self.parser.parse_all_modules()

        # Select the tree
        if modules == "all":
            root = self.parser.build_combined_tree()
        elif modules == "unified":
            root = self.parser.build_unified_tree()
        else:
            root = self.parser.build_tree(modules)

        # Render
        if fmt == "text":
            result = self.text_renderer.render(root, max_depth)
        elif fmt == "html":
            self.html_renderer.modules = self.parser.modules
            result = self.html_renderer.render(root, title=title)
        elif fmt == "json":
            result = json.dumps(
                self.json_renderer.render_with_metadata(root, title=title),
                indent=2, default=str,
            )
        else:
            raise ValueError(f"Unknown format: {fmt}")

        # Write or print
        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(result, encoding="utf-8")
            print(f"Tree written to {output}")
        else:
            print(result)

        return result

    def generate_all_formats(self, output_dir: Path) -> None:
        """Generate all formats (text, html, json) to output directory."""
        self.parser.parse_all_modules()
        root = self.parser.build_unified_tree()

        output_dir.mkdir(parents=True, exist_ok=True)

        # Text
        text = self.text_renderer.render(root)
        (output_dir / "yang-tree.txt").write_text(text, encoding="utf-8")
        print(f"Text tree written to {output_dir / 'yang-tree.txt'}")

        # HTML
        self.html_renderer.modules = self.parser.modules
        html = self.html_renderer.render(root)
        (output_dir / "yang-tree.html").write_text(html, encoding="utf-8")
        print(f"HTML tree written to {output_dir / 'yang-tree.html'}")

        # JSON
        json_data = self.json_renderer.render_with_metadata(root)
        (output_dir / "yang-tree.json").write_text(
            json.dumps(json_data, indent=2, default=str), encoding="utf-8"
        )
        print(f"JSON tree written to {output_dir / 'yang-tree.json'}")


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate YANG tree visualizations for the Unified OSS Framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Text tree to stdout
  python generate_yang_tree.py --format text

  # HTML tree to file
  python generate_yang_tree.py --format html --output tree.html

  # JSON tree
  python generate_yang_tree.py --format json --output tree.json

  # All modules combined
  python generate_yang_tree.py --modules all --format html --output full.html

  # All output formats
  python generate_yang_tree.py --all-formats --output-dir output/

  # Specific module with limited depth
  python generate_yang_tree.py --modules unified-oss-core-nrm --max-depth 5
""",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "html", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--modules", "-m",
        default="unified",
        help="Module to visualize: 'unified', 'all', or a specific module name (default: unified)",
    )
    parser.add_argument(
        "--modules-dir",
        default=str(YANG_MODULES_DIR),
        help=f"Directory containing YANG modules (default: {YANG_MODULES_DIR})",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum tree depth for text output (default: 10)",
    )
    parser.add_argument(
        "--title",
        default="Unified OSS Framework - YANG Tree Model",
        help="Title for HTML output",
    )
    parser.add_argument(
        "--all-formats",
        action="store_true",
        help="Generate text, html, and json formats into the output directory",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(PROJECT_ROOT / "output"),
        help="Output directory when --all-formats is used",
    )

    args = parser.parse_args()

    generator = YangTreeGenerator(Path(args.modules_dir))

    try:
        if args.all_formats:
            generator.generate_all_formats(Path(args.output_dir))
        else:
            generator.generate(
                fmt=args.format,
                modules=args.modules,
                output=args.output,
                max_depth=args.max_depth,
                title=args.title,
            )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
