"""SQL_Validator: strict, allowlist-based, read-only validation of LLM-generated SQL.

The validator parses SQL into an abstract syntax tree with sqlglot and applies the
checks of Requirement 2 in a fixed precedence order:

    parse_error, stacked_query, non_select_statement, forbidden_operation,
    forbidden_function, system_catalog_access, non_allowlisted_table,
    non_allowlisted_column

On success it returns the comment-free, LIMIT-bounded, normalized SQL. Only that
normalized SQL may be executed. Every unexpected internal failure maps to a
"blocked" decision (fail closed).
"""

from __future__ import annotations

from typing import Iterable, Optional

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from src.config import ALLOWLISTED_SCHEMA
from src.models import Decision, GuardrailDecision, SqlValidationResult

GUARD_NAME = "sql_validator"
MAX_SQL_LENGTH = 10_000
DEFAULT_LIMIT = 100
MAX_LIMIT = 500

# Reason codes in precedence order (Requirement 2.15).
REASON_PRECEDENCE: tuple[str, ...] = (
    "parse_error",
    "stacked_query",
    "non_select_statement",
    "forbidden_operation",
    "forbidden_function",
    "system_catalog_access",
    "non_allowlisted_table",
    "non_allowlisted_column",
)

# Node classes that must never appear at any depth. Resolved by name so that the set
# adapts to the pinned sqlglot version (a unit test verifies the names exist).
FORBIDDEN_NODE_NAMES: tuple[str, ...] = (
    "Drop",
    "Delete",
    "Update",
    "Insert",
    "Alter",
    "Create",
    "TruncateTable",
    "Merge",
    "Attach",
    "Detach",
    "Copy",
    "Pragma",
    "Set",
    "SetItem",
    "Command",
    "Install",
    "Use",
    "LoadData",
    "Into",
    "Lock",
    "Export",
    "Grant",
    "Revoke",
    "Transaction",
    "Commit",
    "Rollback",
    "Analyze",
    "Kill",
)
FORBIDDEN_NODES: tuple[type, ...] = tuple(
    getattr(exp, name) for name in FORBIDDEN_NODE_NAMES if hasattr(exp, name)
)

FORBIDDEN_FUNCTIONS: frozenset[str] = frozenset(
    {
        "read_csv",
        "read_csv_auto",
        "read_parquet",
        "read_json",
        "read_json_auto",
        "read_json_objects",
        "read_ndjson",
        "read_ndjson_auto",
        "read_ndjson_objects",
        "read_text",
        "read_blob",
        "read_xlsx",
        "parquet_scan",
        "parquet_metadata",
        "parquet_schema",
        "parquet_file_metadata",
        "parquet_kv_metadata",
        "scan_parquet",
        "csv_scan",
        "sniff_csv",
        "iceberg_scan",
        "delta_scan",
        "sqlite_scan",
        "postgres_scan",
        "mysql_scan",
        "glob",
        "query",
        "query_table",
        "getenv",
        "current_setting",
        "which_secret",
        "load_extension",
        "duckdb_tables",
    }
)
FORBIDDEN_FUNCTION_PREFIXES: tuple[str, ...] = ("duckdb_", "sqlite_", "pragma_")

SYSTEM_CATALOG_SCHEMAS: frozenset[str] = frozenset(
    {"information_schema", "pg_catalog", "sqlite_master", "sqlite_schema", "sqlite_temp_master", "system"}
)
SYSTEM_TABLE_PREFIXES: tuple[str, ...] = ("duckdb_", "sqlite_", "pg_", "information_schema")


class _Blocked(Exception):
    """Internal control-flow exception carrying a reason code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _blocked(reason: str) -> SqlValidationResult:
    return SqlValidationResult(
        decision=GuardrailDecision(guard=GUARD_NAME, decision=Decision.blocked, reason_code=reason),
        sql=None,
    )


def _allowed(sql: str) -> SqlValidationResult:
    return SqlValidationResult(
        decision=GuardrailDecision(guard=GUARD_NAME, decision=Decision.allowed, reason_code=None),
        sql=sql,
    )


def _lower_schema(schema: dict[str, Iterable[str]]) -> dict[str, set[str]]:
    return {str(t).lower(): {str(c).lower() for c in cols} for t, cols in schema.items()}


def _ident(value: object) -> str:
    """Lower-cased name of an identifier-like argument ('' when absent)."""
    if value is None:
        return ""
    if isinstance(value, exp.Expression):
        return value.name.lower()
    return str(value).lower()


def _function_name(node: exp.Func) -> str:
    if isinstance(node, exp.Anonymous):
        return str(node.name).lower()
    return str(node.sql_name()).lower()


def _is_forbidden_function_name(name: str) -> bool:
    return name in FORBIDDEN_FUNCTIONS or name.startswith(FORBIDDEN_FUNCTION_PREFIXES)


def _parse_statements(sql: str, dialect: str) -> list[exp.Expression]:
    """Check 1 and 2: parse and require exactly one statement."""
    if not isinstance(sql, str) or not sql.strip() or len(sql) > MAX_SQL_LENGTH:
        raise _Blocked("parse_error")
    try:
        parsed = sqlglot.parse(sql, read=dialect)
    except (SqlglotError, ValueError, RecursionError):
        raise _Blocked("parse_error") from None
    statements = [s for s in parsed if s is not None]
    if not statements:
        raise _Blocked("parse_error")
    if len(statements) > 1:
        raise _Blocked("stacked_query")
    return statements


def _check_root_is_select(root: exp.Expression) -> None:
    if type(root) is not exp.Select:
        raise _Blocked("non_select_statement")


def _check_forbidden_operations(root: exp.Expression) -> None:
    for node in root.walk():
        if isinstance(node, FORBIDDEN_NODES):
            raise _Blocked("forbidden_operation")


def _check_forbidden_functions(root: exp.Expression) -> None:
    for node in root.walk():
        if isinstance(node, exp.Func) and _is_forbidden_function_name(_function_name(node)):
            raise _Blocked("forbidden_function")
        # Table-valued functions and non-table sources in FROM/JOIN position.
        if isinstance(node, exp.Table) and not isinstance(node.this, exp.Identifier):
            raise _Blocked("forbidden_function")
        if isinstance(node, (exp.Unnest, exp.Lateral, exp.TableFromRows)) and isinstance(
            node.parent, (exp.From, exp.Join, exp.Lateral)
        ):
            raise _Blocked("forbidden_function")


def _is_system_table(table: exp.Table) -> bool:
    name = _ident(table.this)
    db = _ident(table.args.get("db"))
    catalog = _ident(table.args.get("catalog"))
    if db in SYSTEM_CATALOG_SCHEMAS or catalog in SYSTEM_CATALOG_SCHEMAS:
        return True
    if name in SYSTEM_CATALOG_SCHEMAS:
        return True
    return name.startswith(SYSTEM_TABLE_PREFIXES)


def _check_system_catalogs(root: exp.Expression) -> None:
    for table in root.find_all(exp.Table):
        if _is_system_table(table):
            raise _Blocked("system_catalog_access")


def _collect_cte_names(root: exp.Expression) -> set[str]:
    names: set[str] = set()
    for cte in root.find_all(exp.CTE):
        alias = cte.alias
        if alias:
            names.add(str(alias).lower())
    return names


def _check_tables(root: exp.Expression, allowed: dict[str, set[str]]) -> tuple[dict[str, str], set[str]]:
    """Check 7. Returns (alias map for allowlisted tables, derived/CTE qualifier names)."""
    cte_names = _collect_cte_names(root)
    alias_map: dict[str, str] = {}
    derived: set[str] = set(cte_names)
    for table in root.find_all(exp.Table):
        name = _ident(table.this)
        db = _ident(table.args.get("db"))
        catalog = _ident(table.args.get("catalog"))
        alias = _ident(table.alias) or name
        if not db and not catalog and name in cte_names and name not in allowed:
            derived.add(alias)
            continue
        if catalog or (db and db != "main") or name not in allowed:
            raise _Blocked("non_allowlisted_table")
        alias_map[alias] = name
    for sub in root.find_all(exp.Subquery):
        alias = _ident(sub.alias)
        if alias:
            derived.add(alias)
    return alias_map, derived


def _collect_output_names(root: exp.Expression) -> set[str]:
    """Names introduced by select aliases and derived-table column lists."""
    names: set[str] = set()
    for alias in root.find_all(exp.Alias):
        n = _ident(alias.args.get("alias"))
        if n:
            names.add(n)
    for ta in root.find_all(exp.TableAlias):
        for col in ta.args.get("columns") or []:
            n = _ident(col)
            if n:
                names.add(n)
    return names


def _check_wildcards(
    root: exp.Expression,
    schema: dict[str, set[str]],
    alias_map: dict[str, str],
) -> None:
    """Reject a wildcard that would expand to columns outside the passed schema."""
    reference = _lower_schema(ALLOWLISTED_SCHEMA)
    tables_in_scope = set(alias_map.values())
    for node in list(root.find_all(exp.Star)) + list(root.find_all(exp.Columns)):
        if isinstance(node, exp.Star) and isinstance(node.parent, exp.Func):
            continue  # count(*) does not expand columns
        if isinstance(node, exp.Star) and isinstance(node.parent, exp.Columns):
            continue  # handled through the Columns node itself
        targets: set[str] = tables_in_scope
        parent = node.parent
        if isinstance(node, exp.Star) and isinstance(parent, exp.Column):
            qualifier = _ident(parent.args.get("table"))
            if qualifier in alias_map:
                targets = {alias_map[qualifier]}
        for table in targets:
            full = reference.get(table, schema[table])
            if full - schema[table]:
                raise _Blocked("non_allowlisted_column")


def _check_columns(
    root: exp.Expression,
    schema: dict[str, set[str]],
    alias_map: dict[str, str],
    derived: set[str],
) -> None:
    """Check 8: every column reference must be allowlisted for its table."""
    _check_wildcards(root, schema, alias_map)
    union_columns: set[str] = set()
    for table in set(alias_map.values()):
        union_columns |= schema[table]
    output_names = _collect_output_names(root)
    for column in root.find_all(exp.Column):
        if isinstance(column.this, exp.Star):
            continue  # qualified wildcard handled above
        name = _ident(column.this)
        if column.args.get("db") or column.args.get("catalog"):
            raise _Blocked("non_allowlisted_column")
        qualifier = _ident(column.args.get("table"))
        if qualifier:
            if qualifier in alias_map:
                if name not in schema[alias_map[qualifier]]:
                    raise _Blocked("non_allowlisted_column")
            elif qualifier in derived:
                if name not in union_columns and name not in output_names:
                    raise _Blocked("non_allowlisted_column")
            else:
                raise _Blocked("non_allowlisted_column")
        else:
            if name not in union_columns and name not in output_names:
                raise _Blocked("non_allowlisted_column")


def _strip_comments(root: exp.Expression) -> None:
    for node in root.walk():
        if node.comments:
            node.comments = None


def _apply_limit(root: exp.Select) -> None:
    """Missing or non-literal LIMIT gives 100; a literal over 500 gives 500."""
    limit = root.args.get("limit")
    value: Optional[int] = None
    if isinstance(limit, exp.Limit):
        expr = limit.args.get("expression")
        if isinstance(expr, exp.Literal) and not expr.is_string and expr.is_int:
            value = int(expr.this)
    if value is None:
        root.set("limit", exp.Limit(expression=exp.Literal.number(DEFAULT_LIMIT)))
    elif value > MAX_LIMIT:
        root.set("limit", exp.Limit(expression=exp.Literal.number(MAX_LIMIT)))


def _run_checks(root: exp.Expression, schema: dict[str, set[str]]) -> None:
    _check_root_is_select(root)
    _check_forbidden_operations(root)
    _check_forbidden_functions(root)
    _check_system_catalogs(root)
    alias_map, derived = _check_tables(root, schema)
    _check_columns(root, schema, alias_map, derived)


def _validate(sql: str, schema: dict[str, set[str]], dialect: str) -> str:
    (root,) = _parse_statements(sql, dialect)
    _run_checks(root, schema)
    assert isinstance(root, exp.Select)
    _strip_comments(root)
    _apply_limit(root)
    normalized = root.sql(dialect=dialect, comments=False)

    # Re-parse the generated SQL once: it must still be a single allowed SELECT.
    (reparsed,) = _parse_statements(normalized, dialect)
    _run_checks(reparsed, schema)
    return normalized


def validate_sql(
    sql: str,
    schema: dict[str, list[str]] = ALLOWLISTED_SCHEMA,
    dialect: str = "duckdb",
) -> SqlValidationResult:
    """Validate LLM-generated SQL against the read-only allowlist.

    Returns an "allowed" decision with the normalized SQL (comments removed, LIMIT
    applied), or a "blocked" decision with the reason code of the first failed
    check and no SQL. Any unexpected internal error is a blocked decision.
    """
    try:
        allowed_schema = _lower_schema(schema)
        return _allowed(_validate(sql, allowed_schema, dialect))
    except _Blocked as blocked:
        return _blocked(blocked.reason)
    except Exception:  # noqa: BLE001 - fail closed on any internal error
        return _blocked("parse_error")
