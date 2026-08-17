"""Tree-sitter AST parser for code structure analysis.

Parses source code into AST (Abstract Syntax Tree) for:
- Language detection and technical stack identification
- Module dependency graph construction (import analysis)
- Deprecated API pattern matching (for migration assessment)

MVP: Python only (tree-sitter-python).
v0.2+: JavaScript/TypeScript support.

Tree-sitter grammar packages are loaded from pip-installed packages:
- tree-sitter-python (bundled with tree-sitter)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.core.constants import MAX_FILE_SIZE_BYTES, SKIP_BINARY_EXTENSIONS
from src.core.errors import ASTParseFailedError

# Attempt to import tree-sitter; fail gracefully if not installed
try:
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False


def detect_language(file_path: str | Path) -> str | None:
    """Detect programming language from file extension.

    Returns:
        Language string ('python', 'javascript', etc.) or None if unknown/binary.
    """
    ext = Path(file_path).suffix.lower()

    language_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".toml": "toml",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".md": "markdown",
        ".sql": "sql",
        ".sh": "shell",
        ".bash": "shell",
        ".dockerfile": "dockerfile",
        ".cfg": "ini",
        ".ini": "ini",
        ".env": "env",
    }

    # Check for special filenames
    filename = Path(file_path).name.lower()
    if filename == "dockerfile":
        return "dockerfile"
    if filename == "makefile":
        return "makefile"

    return language_map.get(ext)


def is_parseable_file(file_path: str | Path) -> bool:
    """Check if a file should be analyzed.

    Skips: binary files, files over size limit, known non-code extensions.
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    if ext in SKIP_BINARY_EXTENSIONS:
        return False

    # Skip if too large
    try:
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return False
    except OSError:
        pass  # File may not exist yet; defer to caller

    return detect_language(file_path) is not None


def parse_file_ast(
    file_path: str | Path,
    content: str | None = None,
) -> dict[str, Any] | None:
    """Parse a single file into AST.

    Args:
        file_path: Path to the source file.
        content: File content. If None, reads from disk.

    Returns:
        AST dict with keys: language, tree (raw CST), imports, functions, classes.
        Returns None if parsing fails or language is unsupported.

    Raises:
        ASTParseFailedError: If tree-sitter is not installed and parsing is attempted.
    """
    if not HAS_TREE_SITTER:
        return None  # Graceful degradation: no AST available

    lang = detect_language(file_path)
    if lang != "python":
        return None  # MVP: Python only

    if content is None:
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            return None

    try:
        parser = Parser()
        parser.set_language(Language(tspython.language()))
        tree = parser.parse(bytes(content, "utf-8"))
        root = tree.root_node

        return {
            "language": lang,
            "imports": _extract_imports(root, content),
            "functions": _extract_functions(root, content),
            "classes": _extract_classes(root, content),
            "decorators": _extract_decorators(root, content),
            "node_count": _count_nodes(root),
        }
    except Exception as e:
        raise ASTParseFailedError(
            f"AST parse failed for {file_path}: {str(e)}"
        ) from e


def parse_files_batch(
    repo_path: str | Path,
    file_paths: list[str],
) -> dict[str, dict[str, Any]]:
    """Parse multiple files into ASTs.

    Returns:
        Dict mapping file_path -> AST dict.
        Files that fail to parse are omitted from results (non-fatal).
    """
    results: dict[str, dict[str, Any]] = {}
    base = Path(repo_path)

    for fpath in file_paths:
        full_path = base / fpath
        if not full_path.exists() or not is_parseable_file(full_path):
            continue

        try:
            ast = parse_file_ast(full_path)
            if ast is not None:
                results[fpath] = ast
        except ASTParseFailedError:
            continue  # Skip files that fail to parse

    return results


def build_dependency_graph(
    ast_results: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    """Build a module dependency graph from parsed ASTs.

    Returns:
        Adjacency list: {module_path: [imported_module_path, ...]}
    """
    graph: dict[str, list[str]] = {}

    for file_path, ast in ast_results.items():
        imports = ast.get("imports", [])
        imported_modules = []
        for imp in imports:
            module = imp.get("module", "")
            if module:
                imported_modules.append(module)
        graph[file_path] = imported_modules

    return graph


# ------------------------------------------------------------------
# AST extraction helpers (Python only for MVP)
# ------------------------------------------------------------------

def _extract_imports(root: Any, source: str) -> list[dict[str, str]]:
    """Extract import statements from Python AST."""
    imports = []
    _walk_node(root, source, imports, "import_statement")
    _walk_node(root, source, imports, "import_from_statement")
    return imports


def _extract_functions(root: Any, source: str) -> list[dict[str, Any]]:
    """Extract function definitions from Python AST."""
    funcs = []
    _walk_node(root, source, funcs, "function_definition")
    return funcs


def _extract_classes(root: Any, source: str) -> list[dict[str, Any]]:
    """Extract class definitions from Python AST."""
    classes = []
    _walk_node(root, source, classes, "class_definition")
    return classes


def _extract_decorators(root: Any, source: str) -> list[dict[str, Any]]:
    """Extract decorator usages from Python AST."""
    decorators = []
    _walk_node(root, source, decorators, "decorator")
    return decorators


def _walk_node(
    node: Any, source: str, results: list[dict[str, Any]], node_type: str
) -> None:
    """Recursively walk AST and collect nodes of a given type."""
    if node.type == node_type:
        start = node.start_byte
        end = node.end_byte
        snippet = source[start:end].split("\n")[0][:120] if start < len(source) else ""
        results.append({
            "type": node.type,
            "name": _extract_name(node, source),
            "line": node.start_point[0] + 1,
            "snippet": snippet,
        })

    for child in node.children:
        _walk_node(child, source, results, node_type)


def _extract_name(node: Any, source: str) -> str:
    """Try to extract a name from a named node (function name, class name, etc.)."""
    for child in node.children:
        if child.type == "identifier":
            start = child.start_byte
            end = child.end_byte
            return source[start:end] if start < len(source) else "unknown"
    return "unknown"


def _count_nodes(root: Any) -> int:
    """Count total AST nodes (for complexity estimation)."""
    count = 1
    for child in root.children:
        count += _count_nodes(child)
    return count
