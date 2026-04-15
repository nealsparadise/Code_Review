from pathlib import Path

import pyodbc


def read_sql_file(path: str) -> str:
    sql_path = Path(path)
    if not sql_path.exists():
        raise FileNotFoundError(f"SQL file not found: {sql_path}")
    return sql_path.read_text(encoding="utf-8")


def build_connection(connection_string: str) -> pyodbc.Connection:
    return pyodbc.connect(connection_string, autocommit=True)


def fetch_peoplecode_rows(connection_string: str, source_sql: str) -> list[pyodbc.Row]:
    with build_connection(connection_string) as connection:
        cursor = connection.cursor()
        return cursor.execute(source_sql).fetchall()
