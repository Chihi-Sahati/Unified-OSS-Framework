"""
YANG Tree Model API Routes.

REST API endpoints for accessing the unified YANG tree model,
browsing module schemas, and retrieving tree visualizations.

This module provides real-time parsing of YANG files from the project's
yang-modules/ directory, builds hierarchical tree structures, and exposes
them through REST API endpoints for browsing, searching, and visualization.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import defaultdict

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
import structlog
import re

logger = structlog.get_logger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Path to the YANG modules directory
# ---------------------------------------------------------------------------
YANG_MODULES_DIR = Path(__file__).resolve().parents[5] / "yang-modules"


# ============================================================
# Response Models (Pydantic)
# ============================================================

class YangModuleInfo(BaseModel):
    """Information about a single YANG module."""
    name: str
    namespace: str
    prefix: str
    revision: str
    description: str
    imports: List[str]
    container_count: int
    list_count: int
    rpc_count: int
    notification_count: int
    file_size: int
    status: str  # loaded, error, pending


class YangTreeNode(BaseModel):
    """A node in the YANG tree."""
    name: str
    node_type: str  # container, list, leaf, leaf-list, rpc, notification
    module: str
    description: Optional[str] = None
    type_info: Optional[str] = None
    config: bool = True
    keys: Optional[List[str]] = None
    children_count: int = 0
    path: str  # full path from root


class YangTreeResponse(BaseModel):
    """Complete YANG tree response."""
    root: YangTreeNode
    total_nodes: int
    total_containers: int
    total_leaves: int
    total_lists: int
    depth: int
    modules_included: List[str]
    generated_at: str


class ModuleListResponse(BaseModel):
    """List of all YANG modules."""
    modules: List[YangModuleInfo]
    total: int
    loaded_at: str


class SchemaMapping(BaseModel):
    """Schema mapping between modules."""
    source_module: str
    target_module: str
    mapping_type: str  # augment, uses, import, extension
    mapped_nodes: List[str]
    description: str


# ============================================================
# YANG Parsing Utilities
# ============================================================

class YangParser:
    """
    Lightweight YANG file parser that extracts structural information
    using regex-based tokenization.  This avoids a heavy dependency on
    ``pyang`` while still providing accurate counts of containers, lists,
    leaves, RPCs, notifications, imports, and hierarchical tree data.
    """

    # Top-level YANG statement keywords (at module scope)
    TOP_LEVEL_KEYWORDS = frozenset({
        "container", "list", "leaf", "leaf-list", "rpc", "notification",
        "grouping", "typedef", "identity", "feature", "augment", "choice",
        "anyxml", "anydata",
    })

    def __init__(self, yang_dir: Path):
        self.yang_dir = yang_dir
        self._parsed_modules: Dict[str, Dict[str, Any]] = {}
        self._parse_all()

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_all_modules(self) -> Dict[str, Dict[str, Any]]:
        """Return the full dict of parsed module metadata."""
        return self._parsed_modules

    def get_module_names(self) -> List[str]:
        """Return sorted list of module names."""
        return sorted(self._parsed_modules.keys())

    def build_unified_tree(
        self,
        module_filter: Optional[str] = None,
        max_depth: int = 10,
        include_descriptions: bool = True,
    ) -> Dict[str, Any]:
        """
        Build a hierarchical YANG tree from the parsed modules.

        Returns a dict with keys: root, total_nodes, total_containers,
        total_leaves, total_lists, depth, modules_included.
        """
        modules = self._parsed_modules
        if module_filter and module_filter != "all" and module_filter != "unified":
            if module_filter in modules:
                modules = {module_filter: modules[module_filter]}
            else:
                modules = {}

        # Build children recursively
        root_children = []
        for mod_name, mod_data in modules.items():
            mod_root = self._build_subtree(
                mod_data["statements"],
                parent_path=f"/unified-oss",
                module_name=mod_name,
                max_depth=max_depth,
                current_depth=1,
                include_descriptions=include_descriptions,
            )
            if mod_root:
                root_children.append(mod_root)

        total_nodes, total_containers, total_leaves, total_lists, tree_depth = (
            self._count_tree(root_children)
        )

        root_node = YangTreeNode(
            name="unified-oss",
            node_type="container",
            module="unified-oss-tree-model",
            description=(
                "Root container for the Unified OSS Framework YANG tree model. "
                "Provides a single entry point to access all managed network resources, "
                "FCAPS data, and vendor-specific extensions."
            ),
            config=True,
            children_count=len(root_children),
            path="/unified-oss",
        )

        return {
            "root": root_node,
            "root_children": root_children,
            "total_nodes": total_nodes,
            "total_containers": total_containers,
            "total_leaves": total_leaves,
            "total_lists": total_lists,
            "depth": tree_depth,
            "modules_included": list(modules.keys()),
        }

    def search_nodes(
        self,
        query: str,
        node_type: Optional[str] = None,
        module: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search across all parsed YANG tree nodes for matching query strings.
        """
        results = []
        q_lower = query.lower()
        for mod_name, mod_data in self._parsed_modules.items():
            if module and module != mod_name:
                continue
            for stmt in mod_data["statements"]:
                found = self._search_statements(
                    stmt, q_lower, node_type, mod_name, "/unified-oss", results
                )
        return results

    def get_node_at_path(self, path: str) -> Optional[Dict[str, Any]]:
        """Resolve a slash-separated path to a node, if it exists."""
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            return None

        # Try to find the node in any module
        target_name = parts[-1]
        for mod_name, mod_data in self._parsed_modules.items():
            node = self._find_node_recursive(
                mod_data["statements"], parts, 0, mod_name
            )
            if node is not None:
                return node
        return None

    def get_schema_mappings(self) -> List[Dict[str, Any]]:
        """
        Derive schema mapping relationships between modules based on
        import statements and augment targets.
        """
        mappings: List[Dict[str, Any]] = []
        for mod_name, mod_data in self._parsed_modules.items():
            for imp in mod_data.get("imports", []):
                if imp in self._parsed_modules:
                    mappings.append({
                        "source_module": mod_name,
                        "target_module": imp,
                        "mapping_type": "import",
                        "mapped_nodes": [],
                        "description": f"{mod_name} imports {imp}",
                    })
            for stmt in mod_data["statements"]:
                if stmt.get("keyword") == "augment":
                    target = stmt.get("argument", "")
                    # Try to determine which module the augment targets
                    target_module = self._resolve_augment_target(target)
                    if target_module and target_module != mod_name:
                        mappings.append({
                            "source_module": mod_name,
                            "target_module": target_module,
                            "mapping_type": "augment",
                            "mapped_nodes": [target],
                            "description": f"{mod_name} augments {target}",
                        })
        return mappings

    def get_statistics(self) -> Dict[str, Any]:
        """Return comprehensive statistics about the YANG tree model."""
        stats: Dict[str, Any] = {
            "total_modules": 0,
            "total_containers": 0,
            "total_lists": 0,
            "total_leaves": 0,
            "total_leaf_lists": 0,
            "total_rpcs": 0,
            "total_notifications": 0,
            "total_imports": 0,
            "total_groupings": 0,
            "total_typedefs": 0,
            "total_identities": 0,
            "total_features": 0,
            "total_file_size_bytes": 0,
            "modules": {},
            "by_category": defaultdict(lambda: 0),
        }
        for mod_name, mod_data in self._parsed_modules.items():
            stats["total_modules"] += 1
            stats["total_containers"] += mod_data["container_count"]
            stats["total_lists"] += mod_data["list_count"]
            stats["total_leaves"] += mod_data["leaf_count"]
            stats["total_leaf_lists"] += mod_data["leaf_list_count"]
            stats["total_rpcs"] += mod_data["rpc_count"]
            stats["total_notifications"] += mod_data["notification_count"]
            stats["total_imports"] += len(mod_data["imports"])
            stats["total_groupings"] += mod_data["grouping_count"]
            stats["total_typedefs"] += mod_data["typedef_count"]
            stats["total_identities"] += mod_data["identity_count"]
            stats["total_features"] += mod_data["feature_count"]
            stats["total_file_size_bytes"] += mod_data["file_size"]

            stats["modules"][mod_name] = {
                "containers": mod_data["container_count"],
                "lists": mod_data["list_count"],
                "leaves": mod_data["leaf_count"],
                "leaf_lists": mod_data["leaf_list_count"],
                "rpcs": mod_data["rpc_count"],
                "notifications": mod_data["notification_count"],
                "imports": len(mod_data["imports"]),
                "file_size": mod_data["file_size"],
                "revision": mod_data["revision"],
            }

            category = self._classify_module(mod_name)
            stats["by_category"][category] += 1

        stats["by_category"] = dict(stats["by_category"])
        return stats

    def validate_modules(self) -> Dict[str, Any]:
        """
        Validate all YANG modules for basic consistency.

        Checks:
        - Module has a name
        - Module has a namespace
        - Module has a prefix
        - Imports reference existing modules
        - File is parseable
        """
        results: Dict[str, Any] = {
            "valid": [],
            "warnings": [],
            "errors": [],
            "total": 0,
            "valid_count": 0,
            "warning_count": 0,
            "error_count": 0,
        }
        all_names = set(self._parsed_modules.keys())

        for mod_name, mod_data in self._parsed_modules.items():
            results["total"] += 1
            mod_issues = []

            if not mod_data["namespace"]:
                mod_issues.append(("error", "Missing namespace"))
            if not mod_data["prefix"]:
                mod_issues.append(("error", "Missing prefix"))
            if not mod_data["revision"]:
                mod_issues.append(("warning", "Missing revision"))

            for imp in mod_data["imports"]:
                if imp not in all_names and not imp.startswith("ietf-"):
                    mod_issues.append((
                        "warning",
                        f"Import '{imp}' not found in local modules (may be external)",
                    ))

            if mod_data["container_count"] == 0 and mod_data["list_count"] == 0:
                mod_issues.append(("warning", "No containers or lists defined"))

            if any(level == "error" for level, _ in mod_issues):
                results["errors"].append({
                    "module": mod_name,
                    "issues": [{"level": l, "message": m} for l, m in mod_issues],
                })
                results["error_count"] += 1
            elif mod_issues:
                results["warnings"].append({
                    "module": mod_name,
                    "issues": [{"level": l, "message": m} for l, m in mod_issues],
                })
                results["warning_count"] += 1
            else:
                results["valid"].append(mod_name)
                results["valid_count"] += 1

        return results

    def generate_text_tree(
        self,
        module_filter: Optional[str] = None,
        max_depth: int = 10,
    ) -> str:
        """Generate a text-based YANG tree representation (RFC 8340 style)."""
        tree = self.build_unified_tree(
            module_filter=module_filter, max_depth=max_depth,
            include_descriptions=False,
        )
        lines = []
        self._render_text_node(tree["root"], tree.get("root_children", []), lines, "", True, max_depth)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal parsing
    # ------------------------------------------------------------------

    def _parse_all(self) -> None:
        """Parse every .yang file in the modules directory."""
        if not self.yang_dir.is_dir():
            logger.warning("YANG modules directory not found", path=str(self.yang_dir))
            return

        for yang_file in sorted(self.yang_dir.glob("*.yang")):
            try:
                parsed = self._parse_file(yang_file)
                self._parsed_modules[parsed["name"]] = parsed
            except Exception as exc:
                logger.error("Failed to parse YANG file", file=yang_file.name, error=str(exc))
                self._parsed_modules[yang_file.stem] = {
                    "name": yang_file.stem,
                    "namespace": "",
                    "prefix": "",
                    "revision": "",
                    "description": f"Error parsing: {exc}",
                    "imports": [],
                    "container_count": 0,
                    "list_count": 0,
                    "leaf_count": 0,
                    "leaf_list_count": 0,
                    "rpc_count": 0,
                    "notification_count": 0,
                    "grouping_count": 0,
                    "typedef_count": 0,
                    "identity_count": 0,
                    "feature_count": 0,
                    "file_size": yang_file.stat().st_size,
                    "statements": [],
                    "status": "error",
                    "filepath": str(yang_file),
                }

    def _parse_file(self, path: Path) -> Dict[str, Any]:
        """Parse a single YANG file and return structured metadata."""
        content = path.read_text(encoding="utf-8")
        file_size = path.stat().st_size

        # Extract module name
        module_match = re.search(r"module\s+([A-Za-z0-9_-]+)", content)
        name = module_match.group(1) if module_match else path.stem

        # Extract namespace
        ns_match = re.search(r'namespace\s+"([^"]+)"', content)
        namespace = ns_match.group(1) if ns_match else ""

        # Extract prefix
        prefix_match = re.search(r'prefix\s+"([^"]+)"', content)
        prefix = prefix_match.group(1) if prefix_match else ""

        # Extract revision
        rev_match = re.search(r"revision\s+(\d{4}-\d{2}-\d{2})", content)
        revision = rev_match.group(1) if rev_match else ""

        # Extract top-level description
        desc_match = re.search(
            r'description\s+"([^"]{1,500})"', content
        ) or re.search(
            r'description\s*\n\s*"([^"]{1,500})"', content
        )
        description = desc_match.group(1).strip() if desc_match else ""

        # Extract imports
        imports = re.findall(r"import\s+([A-Za-z0-9_-]+)", content)

        # Count structural elements
        container_count = len(re.findall(r"^\s+container\s+", content, re.MULTILINE))
        list_count = len(re.findall(r"^\s+list\s+", content, re.MULTILINE))
        leaf_count = len(re.findall(r"^\s+leaf\s+", content, re.MULTILINE))
        leaf_list_count = len(re.findall(r"^\s+leaf-list\s+", content, re.MULTILINE))
        rpc_count = len(re.findall(r"^\s*rpc\s+", content, re.MULTILINE))
        notification_count = len(re.findall(r"^\s*notification\s+", content, re.MULTILINE))
        grouping_count = len(re.findall(r"^\s*grouping\s+", content, re.MULTILINE))
        typedef_count = len(re.findall(r"^\s*typedef\s+", content, re.MULTILINE))
        identity_count = len(re.findall(r"^\s*identity\s+", content, re.MULTILINE))
        feature_count = len(re.findall(r"^\s*feature\s+", content, re.MULTILINE))

        # Parse hierarchical statements for tree building
        statements = self._parse_statements(content, 0, len(content))

        return {
            "name": name,
            "namespace": namespace,
            "prefix": prefix,
            "revision": revision,
            "description": description,
            "imports": imports,
            "container_count": container_count,
            "list_count": list_count,
            "leaf_count": leaf_count,
            "leaf_list_count": leaf_list_count,
            "rpc_count": rpc_count,
            "notification_count": notification_count,
            "grouping_count": grouping_count,
            "typedef_count": typedef_count,
            "identity_count": identity_count,
            "feature_count": feature_count,
            "file_size": file_size,
            "statements": statements,
            "status": "loaded",
            "filepath": str(path),
        }

    def _parse_statements(
        self, content: str, start: int, end: int
    ) -> List[Dict[str, Any]]:
        """
        Parse YANG statements within a text region into a list of dicts.
        Each dict has: keyword, argument, description, children, start, end.
        """
        statements = []
        i = start
        length = len(content)

        while i < end:
            # Skip whitespace and comments
            while i < end:
                if content[i] in " \t\n\r":
                    i += 1
                elif content[i:i+2] == "//":
                    nl = content.find("\n", i)
                    i = nl + 1 if nl != -1 else end
                elif content[i:i+2] == "/*":
                    close = content.find("*/", i + 2)
                    i = close + 2 if close != -1 else end
                else:
                    break

            if i >= end:
                break

            # Read keyword
            kw_start = i
            while i < end and content[i] not in " \t\n\r{;":
                i += 1
            keyword = content[kw_start:i].strip()

            if not keyword:
                i += 1
                continue

            # Skip to argument (may not exist, e.g., for 'container x {')
            while i < end and content[i] in " \t":
                i += 1

            argument = None
            if i < end and content[i] not in "{;":
                # Read argument (possibly quoted)
                if content[i] == '"':
                    i += 1
                    arg_start = i
                    while i < end and content[i] != '"':
                        if content[i] == "\\":
                            i += 1  # skip escaped char
                        i += 1
                    argument = content[arg_start:i]
                    if i < end:
                        i += 1  # skip closing quote
                else:
                    arg_start = i
                    while i < end and content[i] not in " \t\n\r{;":
                        i += 1
                    argument = content[arg_start:i].strip()

            # Skip whitespace
            while i < end and content[i] in " \t\n\r":
                i += 1

            # Look for description sub-statement within braces
            description = None
            children: List[Dict[str, Any]] = []

            if i < end and content[i] == "{":
                # Sub-statement block
                brace_start = i + 1
                brace_depth = 1
                i += 1
                while i < end and brace_depth > 0:
                    if content[i] == "{":
                        brace_depth += 1
                    elif content[i] == "}":
                        brace_depth -= 1
                    i += 1
                block_end = i - 1  # position of closing }

                # Extract description if present in this block
                desc_match = re.search(
                    r'description\s+"([^"]*)"',
                    content[brace_start:block_end],
                )
                if desc_match:
                    description = desc_match.group(1).strip()

                # Parse child statements (one level deep for performance)
                children = self._parse_statements(content, brace_start, block_end)
            elif i < end and content[i] == ";":
                i += 1
                # Check for description before semicolon context (rare at this level)

            stmt: Dict[str, Any] = {
                "keyword": keyword,
                "argument": argument,
                "description": description,
                "children": children,
            }

            # Extract keys for list nodes
            if keyword == "list":
                keys_match = re.search(
                    r'key\s+"([^"]+)"',
                    content[stmt.get("start", start):i] if "start" in stmt else "",
                )
                if not keys_match and children:
                    for child in children:
                        if child["keyword"] == "key" and child["argument"]:
                            stmt["keys"] = [k.strip() for k in child["argument"].split()]
                            break

            # Extract type info for leaf nodes
            if keyword == "leaf" and argument:
                for child in children:
                    if child["keyword"] == "type" and child["argument"]:
                        stmt["type_info"] = child["argument"]
                        break

            statements.append(stmt)

        return statements

    # ------------------------------------------------------------------
    # Tree building helpers
    # ------------------------------------------------------------------

    def _build_subtree(
        self,
        statements: List[Dict[str, Any]],
        parent_path: str,
        module_name: str,
        max_depth: int,
        current_depth: int,
        include_descriptions: bool,
    ) -> Optional[YangTreeNode]:
        """Recursively build YangTreeNode objects from parsed statements."""
        if current_depth > max_depth or not statements:
            return None

        # For module-level, aggregate top-level containers / lists / rpcs
        top_stmts = [s for s in statements if s["keyword"] in self.TOP_LEVEL_KEYWORDS]
        if not top_stmts:
            return None

        # Return the first top-level node as representative
        stmt = top_stmts[0]
        node_name = stmt["argument"] or stmt["keyword"]
        node_type = stmt["keyword"]
        full_path = f"{parent_path}/{node_name}"

        desc = stmt.get("description")
        if not include_descriptions:
            desc = None

        type_info = stmt.get("type_info")
        keys = stmt.get("keys")

        children_count = len(stmt.get("children", []))

        return YangTreeNode(
            name=node_name,
            node_type=node_type,
            module=module_name,
            description=desc,
            type_info=type_info,
            config=True,
            keys=keys,
            children_count=children_count,
            path=full_path,
        )

    def _count_tree(
        self, nodes: List[Any]
    ) -> tuple:
        """Count total nodes, containers, leaves, lists, and max depth."""
        total = 0
        containers = 0
        leaves = 0
        lists = 0
        max_depth = 0

        def _walk(n, depth):
            nonlocal total, containers, leaves, lists, max_depth
            if depth > max_depth:
                max_depth = depth
            total += 1
            nt = n.node_type if isinstance(n, YangTreeNode) else n.get("node_type", "")
            if nt == "container":
                containers += 1
            elif nt == "list":
                lists += 1
            elif nt in ("leaf", "leaf-list"):
                leaves += 1
            # children_count represents actual children; for deeper counting
            # we would recurse, but the top-level count is sufficient.

        for node in nodes:
            _walk(node, 1)

        return total, containers, leaves, lists, max_depth

    # ------------------------------------------------------------------
    # Search helpers
    # ------------------------------------------------------------------

    def _search_statements(
        self,
        stmt: Dict[str, Any],
        query: str,
        node_type_filter: Optional[str],
        module_name: str,
        parent_path: str,
        results: List[Dict[str, Any]],
    ) -> bool:
        """Recursively search statements for matching query."""
        found = False
        keyword = stmt["keyword"]
        argument = stmt.get("argument", "")
        description = stmt.get("description", "") or ""

        # Only search structural nodes
        if keyword in self.TOP_LEVEL_KEYWORDS or keyword in (
            "container", "list", "leaf", "leaf-list", "rpc", "notification",
            "grouping", "typedef", "identity", "feature", "augment",
        ):
            node_name = argument or keyword
            search_text = f"{node_name} {description}".lower()

            if query in search_text:
                if node_type_filter is None or node_type_filter == keyword:
                    full_path = f"{parent_path}/{node_name}"
                    results.append({
                        "name": node_name,
                        "node_type": keyword,
                        "module": module_name,
                        "description": description,
                        "path": full_path,
                    })
                    found = True

            # Recurse into children
            for child in stmt.get("children", []):
                self._search_statements(
                    child, query, node_type_filter, module_name,
                    f"{parent_path}/{node_name}", results,
                )

        return found

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def _find_node_recursive(
        self,
        statements: List[Dict[str, Any]],
        path_parts: List[str],
        index: int,
        module_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Recursively resolve a path to a statement node."""
        if index >= len(path_parts):
            return None

        target = path_parts[index]
        for stmt in statements:
            keyword = stmt["keyword"]
            argument = stmt.get("argument", "")
            node_name = argument or keyword

            if node_name == target:
                if index == len(path_parts) - 1:
                    return {
                        "name": node_name,
                        "node_type": keyword,
                        "module": module_name,
                        "description": stmt.get("description"),
                        "type_info": stmt.get("type_info"),
                        "children": [
                            {
                                "name": c.get("argument") or c["keyword"],
                                "node_type": c["keyword"],
                            }
                            for c in stmt.get("children", [])
                            if c["keyword"] in self.TOP_LEVEL_KEYWORDS
                        ],
                    }
                # Continue deeper
                return self._find_node_recursive(
                    stmt.get("children", []), path_parts, index + 1, module_name
                )

        return None

    # ------------------------------------------------------------------
    # Augment target resolution
    # ------------------------------------------------------------------

    def _resolve_augment_target(self, target_path: str) -> Optional[str]:
        """Try to resolve the target module of an augment statement."""
        # Augment targets look like: /prefix:path/prefix:path/...
        # Extract the first prefix
        match = re.search(r"/([A-Za-z0-9_-]+):", target_path)
        if match:
            prefix = match.group(1)
            # Look up which module uses this prefix
            for mod_name, mod_data in self._parsed_modules.items():
                if mod_data["prefix"] == prefix:
                    return mod_name
        return None

    # ------------------------------------------------------------------
    # Module classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_module(name: str) -> str:
        """Classify a module into a category."""
        name_lower = name.lower()
        if "core-nrm" in name_lower or "tree-model" in name_lower:
            return "Core"
        if "fault" in name_lower:
            return "FCAPS-Fault"
        if "configuration" in name_lower or "config" in name_lower:
            return "FCAPS-Configuration"
        if "performance" in name_lower or "perf" in name_lower:
            return "FCAPS-Performance"
        if "security" in name_lower or "sec" in name_lower:
            return "FCAPS-Security"
        if "accounting" in name_lower or "acct" in name_lower:
            return "FCAPS-Accounting"
        if "5g" in name_lower or "nsa" in name_lower:
            return "5G-NSA"
        if "ericsson" in name_lower:
            return "Vendor-Ericsson"
        if "huawei" in name_lower:
            return "Vendor-Huawei"
        if "ims" in name_lower or "volte" in name_lower:
            return "IMS-VoLTE"
        return "Other"

    # ------------------------------------------------------------------
    # Text tree rendering (RFC 8340 style)
    # ------------------------------------------------------------------

    def _render_text_node(
        self,
        node: YangTreeNode,
        children: List[Any],
        lines: List[str],
        prefix: str,
        is_last: bool,
        max_depth: int,
        current_depth: int = 1,
    ) -> None:
        """Render a YangTreeNode and its children as text."""
        connector = "`-- " if is_last else "+-- "
        suffix = ""

        if node.node_type == "container":
            suffix = ""
        elif node.node_type == "list":
            keys_str = f" [{', '.join(node.keys)}]" if node.keys else ""
            suffix = f"{keys_str}"
        elif node.node_type == "leaf":
            type_str = f" <{node.type_info}>" if node.type_info else ""
            suffix = f"{type_str}"
        elif node.node_type in ("rpc", "notification"):
            suffix = f" {{{node.node_type}}}"

        lines.append(f"{prefix}{connector}{node.name}{suffix}")

        child_prefix = prefix + ("    " if is_last else "|   ")
        if node.node_type in ("container", "list") and current_depth < max_depth:
            for idx, child in enumerate(children):
                self._render_text_node(
                    child,
                    [],
                    lines,
                    child_prefix,
                    idx == len(children) - 1,
                    max_depth,
                    current_depth + 1,
                )


# ============================================================
# Module-level parser instance (lazy-initialized)
# ============================================================

_parser_instance: Optional[YangParser] = None


def get_parser() -> YangParser:
    """Get or create the singleton YangParser instance."""
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = YangParser(YANG_MODULES_DIR)
        logger.info(
            "YANG parser initialized",
            modules_loaded=len(_parser_instance.get_all_modules()),
            yang_dir=str(YANG_MODULES_DIR),
        )
    return _parser_instance


# ============================================================
# Endpoints
# ============================================================

@router.get("/yang-tree", response_model=YangTreeResponse)
async def get_yang_tree(
    request: Request,
    format: str = Query("json", description="Output format: json, text, html"),
    module: str = Query("unified", description="Module name or 'all' or 'unified'"),
    max_depth: int = Query(10, ge=1, le=50),
    include_descriptions: bool = Query(True),
):
    """
    Get the unified YANG tree model.

    Returns a hierarchical tree structure of all YANG modules,
    with options for filtering and formatting.
    """
    parser = get_parser()

    if format == "text":
        text_tree = parser.generate_text_tree(
            module_filter=module, max_depth=max_depth,
        )
        return PlainTextResponse(content=text_tree, media_type="text/plain")

    tree_data = parser.build_unified_tree(
        module_filter=module,
        max_depth=max_depth,
        include_descriptions=include_descriptions,
    )

    return YangTreeResponse(
        root=tree_data["root"],
        total_nodes=tree_data["total_nodes"],
        total_containers=tree_data["total_containers"],
        total_leaves=tree_data["total_leaves"],
        total_lists=tree_data["total_lists"],
        depth=tree_data["depth"],
        modules_included=tree_data["modules_included"],
        generated_at=datetime.utcnow().isoformat() + "Z",
    )


@router.get("/yang-tree/modules", response_model=ModuleListResponse)
async def list_yang_modules(request: Request):
    """List all loaded YANG modules with metadata."""
    parser = get_parser()
    modules = parser.get_all_modules()

    module_infos = []
    for name in parser.get_module_names():
        mod = modules[name]
        module_infos.append(YangModuleInfo(
            name=mod["name"],
            namespace=mod["namespace"],
            prefix=mod["prefix"],
            revision=mod["revision"],
            description=mod["description"],
            imports=mod["imports"],
            container_count=mod["container_count"],
            list_count=mod["list_count"],
            rpc_count=mod["rpc_count"],
            notification_count=mod["notification_count"],
            file_size=mod["file_size"],
            status=mod["status"],
        ))

    return ModuleListResponse(
        modules=module_infos,
        total=len(module_infos),
        loaded_at=datetime.utcnow().isoformat() + "Z",
    )


@router.get("/yang-tree/modules/{module_name}")
async def get_module_details(request: Request, module_name: str):
    """
    Get detailed information about a specific YANG module.

    Returns metadata, structural counts, top-level statements,
    and import relationships.
    """
    parser = get_parser()
    modules = parser.get_all_modules()

    if module_name not in modules:
        raise HTTPException(
            status_code=404,
            detail=f"YANG module '{module_name}' not found. "
                   f"Available modules: {', '.join(parser.get_module_names())}",
        )

    mod = modules[module_name]

    # Collect top-level structural statements
    top_level = []
    for stmt in mod["statements"]:
        if stmt["keyword"] in YangParser.TOP_LEVEL_KEYWORDS:
            top_level.append({
                "name": stmt.get("argument") or stmt["keyword"],
                "type": stmt["keyword"],
                "description": stmt.get("description"),
                "children_count": len(stmt.get("children", [])),
            })

    return {
        "name": mod["name"],
        "namespace": mod["namespace"],
        "prefix": mod["prefix"],
        "revision": mod["revision"],
        "description": mod["description"],
        "yang_version": "1.1",
        "status": mod["status"],
        "filepath": mod["filepath"],
        "file_size": mod["file_size"],
        "imports": mod["imports"],
        "statistics": {
            "containers": mod["container_count"],
            "lists": mod["list_count"],
            "leaves": mod["leaf_count"],
            "leaf_lists": mod["leaf_list_count"],
            "rpcs": mod["rpc_count"],
            "notifications": mod["notification_count"],
            "groupings": mod["grouping_count"],
            "typedefs": mod["typedef_count"],
            "identities": mod["identity_count"],
            "features": mod["feature_count"],
        },
        "category": YangParser._classify_module(module_name),
        "top_level_statements": top_level,
    }


@router.get("/yang-tree/search")
async def search_yang_tree(
    request: Request,
    query: str = Query(..., min_length=1, description="Search query"),
    node_type: Optional[str] = Query(None, description="Filter by node type"),
    module: Optional[str] = Query(None, description="Filter by module"),
):
    """
    Search across all YANG tree nodes.

    Matches against node names and descriptions.  Results can be
    filtered by node type (container, list, leaf, rpc, notification)
    and/or source module.
    """
    parser = get_parser()

    valid_types = {"container", "list", "leaf", "leaf-list", "rpc", "notification",
                   "grouping", "typedef", "identity", "feature", "augment"}
    if node_type and node_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid node_type '{node_type}'. "
                   f"Valid types: {', '.join(sorted(valid_types))}",
        )

    if module:
        modules = parser.get_all_modules()
        if module not in modules:
            raise HTTPException(
                status_code=404,
                detail=f"Module '{module}' not found.",
            )

    results = parser.search_nodes(query=query, node_type=node_type, module=module)

    return {
        "query": query,
        "filters": {"node_type": node_type, "module": module},
        "total_results": len(results),
        "results": results[:100],  # cap at 100 results
    }


@router.get("/yang-tree/schema-mapping")
async def get_schema_mapping(request: Request):
    """
    Get schema mapping relationships between modules.

    Returns import and augment relationships derived from the
    YANG module source files.
    """
    parser = get_parser()
    mappings = parser.get_schema_mappings()

    return {
        "total_mappings": len(mappings),
        "mappings": [SchemaMapping(**m) for m in mappings],
    }


@router.get("/yang-tree/node/{path:path}")
async def get_node_at_path(request: Request, path: str):
    """
    Get a specific node by its path in the YANG tree.

    The path should be a slash-separated path such as:
    ``unified-oss/fcaps/fault-management`` or
    ``unified-oss/network-inventory/core-network-inventory``.
    """
    parser = get_parser()

    # Normalise the path
    normalized = path.strip("/")
    if not normalized:
        raise HTTPException(
            status_code=400,
            detail="Path cannot be empty. Provide a node path like 'unified-oss/fcaps'.",
        )

    node = parser.get_node_at_path(normalized)
    if node is None:
        raise HTTPException(
            status_code=404,
            detail=f"Node at path '/{normalized}' not found.",
        )

    return node


@router.get("/yang-tree/visualization")
async def get_visualization(
    request: Request,
    format: str = Query("html", description="Visualization format: html, svg, dot"),
    module: Optional[str] = Query(None),
):
    """
    Get YANG tree visualization data for frontend rendering.

    Returns data suitable for rendering a tree diagram.  Supports
    HTML (nested divs), SVG (basic tree graph), and DOT (Graphviz)
    output formats.
    """
    parser = get_parser()

    if format == "dot":
        dot_lines = [
            "digraph unified_oss_yang_tree {",
            '  rankdir=TB;',
            '  node [shape=record, fontname="Helvetica", fontsize=10];',
            '  edge [fontname="Helvetica", fontsize=8];',
            '  root [label="unified-oss|Root Container" style=filled fillcolor=lightblue];',
        ]

        modules = parser.get_all_modules()
        for mod_name in parser.get_module_names():
            if module and mod_name != module:
                continue
            mod = modules[mod_name]
            safe_name = mod_name.replace("-", "_")
            containers = mod["container_count"]
            lists = mod["list_count"]
            leaves = mod["leaf_count"]
            label = (
                f"{mod_name}|C:{containers} L:{lists} F:{leaves}|"
                f"{mod['prefix']}"
            )
            dot_lines.append(
                f'  {safe_name} [label="{label}" style=filled '
                f'fillcolor=lightyellow];'
            )
            dot_lines.append(f"  root -> {safe_name};")

        dot_lines.append("}")
        return PlainTextResponse(
            content="\n".join(dot_lines), media_type="text/plain",
        )

    if format == "svg":
        # Basic SVG tree visualization
        modules = parser.get_all_modules()
        mod_names = parser.get_module_names()
        if module:
            mod_names = [m for m in mod_names if m == module]

        width = 800
        height = max(200, len(mod_names) * 50 + 100)

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}">',
            '<style>',
            '  .root { fill: #4a90d9; }',
            '  .module { fill: #f5a623; }',
            '  .edge { stroke: #666; stroke-width: 1.5; }',
            '  text { font-family: Helvetica, sans-serif; font-size: 12px; }',
            '</style>',
        ]

        # Root node
        rx = width // 2
        ry = 30
        svg_parts.append(
            f'<rect x="{rx - 50}" y="10" width="100" height="30" '
            f'rx="5" class="root"/>'
        )
        svg_parts.append(
            f'<text x="{rx}" y="30" text-anchor="middle" '
            f'fill="white">unified-oss</text>'
        )

        # Module nodes
        cols = min(len(mod_names), 5)
        col_width = width / max(cols, 1)
        for idx, mod_name in enumerate(mod_names):
            row = idx // cols
            col = idx % cols
            mx = int(col * col_width + col_width / 2)
            my = 80 + row * 50
            mod = modules[mod_name]

            svg_parts.append(f'<line x1="{rx}" y1="40" x2="{mx}" y2="{my}" class="edge"/>')
            short_name = mod_name[:25] + ("..." if len(mod_name) > 25 else "")
            svg_parts.append(
                f'<rect x="{mx - 60}" y="{my - 12}" width="120" height="24" '
                f'rx="4" class="module"/>'
            )
            svg_parts.append(
                f'<text x="{mx}" y="{my + 4}" text-anchor="middle" '
                f'fill="white" font-size="9">{short_name}</text>'
            )

        svg_parts.append("</svg>")
        return Response(
            content="\n".join(svg_parts), media_type="image/svg+xml",
        )

    # Default: HTML
    modules = parser.get_all_modules()
    mod_names = parser.get_module_names()
    if module:
        mod_names = [m for m in mod_names if m == module]

    html_parts = [
        "<!DOCTYPE html>",
        "<html><head><title>YANG Tree Visualization</title>",
        "<style>",
        "  body { font-family: 'Segoe UI', Helvetica, sans-serif; margin: 20px; }",
        "  .tree { padding-left: 20px; }",
        "  .node-container { color: #2c5282; font-weight: bold; }",
        "  .node-list { color: #2b6cb0; font-style: italic; }",
        "  .node-leaf { color: #4a5568; }",
        "  .node-rpc { color: #9b2c2c; }",
        "  .node-notification { color: #744210; }",
        "  .module-badge { display: inline-block; background: #edf2f7; "
        "    border-radius: 4px; padding: 2px 8px; font-size: 11px; "
        "    color: #4a5568; margin-right: 6px; }",
        "  .module-section { margin-bottom: 16px; border-left: 3px solid #4299e1; "
        "    padding-left: 12px; }",
        "  h1 { color: #2d3748; }",
        "  h2 { color: #4a5568; font-size: 16px; margin-bottom: 4px; }",
        "  .stats { color: #718096; font-size: 13px; }",
        "</style>",
        "</head><body>",
        f"<h1>Unified OSS YANG Tree Model</h1>",
        f"<p class='stats'>{len(mod_names)} modules loaded | "
        f"{sum(m['container_count'] for m in modules.values())} containers | "
        f"{sum(m['list_count'] for m in modules.values())} lists | "
        f"{sum(m['leaf_count'] for m in modules.values())} leaves</p>",
        "<div class='tree'>",
    ]

    for mod_name in mod_names:
        mod = modules[mod_name]
        category = YangParser._classify_module(mod_name)
        html_parts.append(
            f"<div class='module-section'>"
            f"<span class='module-badge'>{category}</span>"
            f"<h2>{mod_name}</h2>"
            f"<p class='stats'>prefix: {mod['prefix']} | "
            f"revision: {mod['revision']} | "
            f"C:{mod['container_count']} L:{mod['list_count']} "
            f"F:{mod['leaf_count']} R:{mod['rpc_count']} "
            f"N:{mod['notification_count']}</p>"
        )

        for stmt in mod["statements"]:
            if stmt["keyword"] in YangParser.TOP_LEVEL_KEYWORDS:
                css_class = f"node-{stmt['keyword']}"
                node_label = stmt.get("argument") or stmt["keyword"]
                desc = stmt.get("description", "")
                if desc and len(desc) > 120:
                    desc = desc[:117] + "..."
                desc_attr = f' title="{desc}"' if desc else ""
                child_count = len(stmt.get("children", []))
                extra = f" ({child_count} children)" if child_count else ""
                html_parts.append(
                    f'<div class="{css_class}"{desc_attr}>'
                    f'{stmt["keyword"]}: {node_label}{extra}</div>'
                )

        html_parts.append("</div>")

    html_parts.append("</div></body></html>")
    return Response(content="\n".join(html_parts), media_type="text/html")


@router.get("/yang-tree/export")
async def export_yang_tree(
    request: Request,
    format: str = Query("json", description="Export format: json, yaml, xml"),
    module: Optional[str] = Query(None),
):
    """
    Export YANG tree in various formats.

    Supports JSON (default), YAML-style text, and XML representations
    of the parsed module metadata and tree structure.
    """
    parser = get_parser()
    modules = parser.get_all_modules()
    mod_names = parser.get_module_names()

    if module:
        if module not in modules:
            raise HTTPException(
                status_code=404, detail=f"Module '{module}' not found.",
            )
        mod_names = [module]

    if format == "yaml":
        lines = ["# Unified OSS Framework - YANG Tree Model Export",
                 f"# Generated: {datetime.utcnow().isoformat()}Z",
                 f"# Total modules: {len(mod_names)}", ""]

        for mod_name in mod_names:
            mod = modules[mod_name]
            lines.append(f"module: {mod_name}")
            lines.append(f"  namespace: {mod['namespace']}")
            lines.append(f"  prefix: {mod['prefix']}")
            lines.append(f"  revision: {mod['revision']}")
            lines.append(f"  description: >")
            for desc_line in (mod["description"] or "N/A").split(". "):
                if desc_line.strip():
                    lines.append(f"    {desc_line.strip()}.")
            lines.append(f"  imports:")
            for imp in mod["imports"]:
                lines.append(f"    - {imp}")
            lines.append(f"  statistics:")
            lines.append(f"    containers: {mod['container_count']}")
            lines.append(f"    lists: {mod['list_count']}")
            lines.append(f"    leaves: {mod['leaf_count']}")
            lines.append(f"    leaf_lists: {mod['leaf_list_count']}")
            lines.append(f"    rpcs: {mod['rpc_count']}")
            lines.append(f"    notifications: {mod['notification_count']}")
            lines.append(f"    groupings: {mod['grouping_count']}")
            lines.append(f"    typedefs: {mod['typedef_count']}")
            lines.append(f"    identities: {mod['identity_count']}")
            lines.append(f"    features: {mod['feature_count']}")
            lines.append(f"    file_size: {mod['file_size']}")
            lines.append(f"  top_level_statements:")
            for stmt in mod["statements"]:
                if stmt["keyword"] in YangParser.TOP_LEVEL_KEYWORDS:
                    name = stmt.get("argument") or stmt["keyword"]
                    lines.append(f"    - {{name: {name}, type: {stmt['keyword']}}}")
            lines.append("")

        return PlainTextResponse(content="\n".join(lines), media_type="text/plain")

    if format == "xml":
        xml_parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<yang-tree-model generated="{datetime.utcnow().isoformat()}Z" '
            f'total-modules="{len(mod_names)}">',
        ]
        for mod_name in mod_names:
            mod = modules[mod_name]
            xml_parts.append(f'  <module name="{mod_name}">')
            xml_parts.append(f'    <namespace>{mod["namespace"]}</namespace>')
            xml_parts.append(f'    <prefix>{mod["prefix"]}</prefix>')
            xml_parts.append(f'    <revision>{mod["revision"]}</revision>')
            xml_parts.append(f'    <description><![CDATA[{mod["description"]}]]></description>')
            xml_parts.append(f'    <imports>')
            for imp in mod["imports"]:
                xml_parts.append(f'      <import>{imp}</import>')
            xml_parts.append(f'    </imports>')
            xml_parts.append(f'    <statistics')
            xml_parts.append(f'      containers="{mod["container_count"]}"')
            xml_parts.append(f'      lists="{mod["list_count"]}"')
            xml_parts.append(f'      leaves="{mod["leaf_count"]}"')
            xml_parts.append(f'      leaf-lists="{mod["leaf_list_count"]}"')
            xml_parts.append(f'      rpcs="{mod["rpc_count"]}"')
            xml_parts.append(f'      notifications="{mod["notification_count"]}"')
            xml_parts.append(f'      groupings="{mod["grouping_count"]}"')
            xml_parts.append(f'      typedefs="{mod["typedef_count"]}"')
            xml_parts.append(f'      identities="{mod["identity_count"]}"')
            xml_parts.append(f'      features="{mod["feature_count"]}"')
            xml_parts.append(f'      file-size="{mod["file_size"]}"')
            xml_parts.append(f'    />')
            xml_parts.append(f'  </module>')
        xml_parts.append('</yang-tree-model>')

        return Response(
            content="\n".join(xml_parts), media_type="application/xml",
        )

    # Default: JSON
    export_data = {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "total_modules": len(mod_names),
        "modules": {},
    }
    for mod_name in mod_names:
        mod = modules[mod_name]
        export_data["modules"][mod_name] = {
            "namespace": mod["namespace"],
            "prefix": mod["prefix"],
            "revision": mod["revision"],
            "description": mod["description"],
            "imports": mod["imports"],
            "statistics": {
                "containers": mod["container_count"],
                "lists": mod["list_count"],
                "leaves": mod["leaf_count"],
                "leaf_lists": mod["leaf_list_count"],
                "rpcs": mod["rpc_count"],
                "notifications": mod["notification_count"],
                "groupings": mod["grouping_count"],
                "typedefs": mod["typedef_count"],
                "identities": mod["identity_count"],
                "features": mod["feature_count"],
                "file_size": mod["file_size"],
            },
            "top_level_statements": [
                {
                    "name": s.get("argument") or s["keyword"],
                    "type": s["keyword"],
                    "description": s.get("description"),
                    "children_count": len(s.get("children", [])),
                }
                for s in mod["statements"]
                if s["keyword"] in YangParser.TOP_LEVEL_KEYWORDS
            ],
        }

    return export_data


@router.get("/yang-tree/statistics")
async def get_tree_statistics(request: Request):
    """
    Get comprehensive statistics about the YANG tree model.

    Returns per-module counts of containers, lists, leaves, RPCs,
    notifications, groupings, typedefs, identities, and features.
    Also includes aggregate totals and module categorization.
    """
    parser = get_parser()
    stats = parser.get_statistics()
    stats["generated_at"] = datetime.utcnow().isoformat() + "Z"
    return stats


@router.get("/yang-tree/validate")
async def validate_yang_modules(request: Request):
    """
    Validate all YANG modules for consistency.

    Checks for missing namespaces, prefixes, revisions, unresolvable
    imports, and modules with no structural definitions.
    """
    parser = get_parser()
    results = parser.validate_modules()
    results["validated_at"] = datetime.utcnow().isoformat() + "Z"
    return results
