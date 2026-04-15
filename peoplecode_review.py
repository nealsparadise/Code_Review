import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pyodbc

from db_connection import fetch_peoplecode_rows, read_sql_file
from sql_queries import DEFAULT_PEOPLECODE_SQL


@dataclass
class Rule:
    rule_id: str
    rule_name: str
    severity: str
    pattern: str
    description: str
    is_regex: bool


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    description: str
    object_path: str
    progseq: int
    snippet: str


REQUIRED_RULE_FIELDS = {
    "rule_id",
    "rule_name",
    "severity",
    "pattern",
    "description",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Review PeopleCode from a PeopleSoft SQL Server database."
    )
    parser.add_argument(
        "connection_string",
        help="ODBC connection string passed from PeopleSoft.",
    )
    parser.add_argument(
        "--rules",
        default="rules/review_rules.json",
        help="JSON file that contains review rules.",
    )
    parser.add_argument(
        "--output",
        default="review_results.csv",
        help="CSV file to write findings to.",
    )
    parser.add_argument(
        "--source-sql",
        default=None,
        help="Optional SQL file to override the default PeopleCode extraction query.",
    )
    parser.add_argument(
        "--fail-on-severity",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit with code 2 when at least one finding meets or exceeds this severity.",
    )
    return parser.parse_args()


def read_json_file(path: str) -> list[dict]:
    json_path = Path(path)
    if not json_path.exists():
        raise FileNotFoundError(f"JSON file not found: {json_path}")
    with json_path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError("Rules JSON must contain a list of rule objects.")
    return payload


def parse_is_regex(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    if value is None:
        return True
    raise ValueError("Rule field 'is_regex' must be a boolean.")


def load_rules(rule_items: list[dict]) -> list[Rule]:
    rules: list[Rule] = []
    for index, item in enumerate(rule_items, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Rule #{index} must be a JSON object.")
        missing_fields = sorted(REQUIRED_RULE_FIELDS - set(item))
        if missing_fields:
            raise ValueError(
                f"Rule #{index} is missing required fields: {', '.join(missing_fields)}"
            )
        rules.append(
            Rule(
                rule_id=str(item["rule_id"]),
                rule_name=str(item["rule_name"]),
                severity=str(item["severity"]).lower(),
                pattern=str(item["pattern"]),
                description=str(item["description"]),
                is_regex=parse_is_regex(item.get("is_regex", True)),
            )
        )
    return rules


def object_path(row: pyodbc.Row) -> str:
    parts = []
    for index in range(1, 8):
        object_id = getattr(row, f"OBJECTID{index}", None)
        object_value = getattr(row, f"OBJECTVALUE{index}", None)
        if object_id is None and object_value is None:
            continue
        if object_value in (None, ""):
            continue
        parts.append(f"{object_id}:{object_value}")
    return " > ".join(parts)


def extract_snippet(text: str, match: re.Match[str], window: int = 80) -> str:
    start = max(match.start() - window, 0)
    end = min(match.end() + window, len(text))
    return " ".join(text[start:end].split())


def review_peoplecode(rows: Iterable[pyodbc.Row], rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    for row in rows:
        source_text = str(row.PCTEXT or "")
        if not source_text.strip():
            continue

        for rule in rules:
            pattern = rule.pattern if rule.is_regex else re.escape(rule.pattern)
            matches = re.finditer(pattern, source_text, flags=re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        rule_name=rule.rule_name,
                        severity=rule.severity,
                        description=rule.description,
                        object_path=object_path(row),
                        progseq=int(getattr(row, "PROGSEQ", 0) or 0),
                        snippet=extract_snippet(source_text, match),
                    )
                )
    return findings


def write_findings_csv(findings: list[Finding], output_path: str) -> None:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "rule_id",
                "rule_name",
                "severity",
                "description",
                "object_path",
                "progseq",
                "snippet",
            ]
        )
        for finding in findings:
            writer.writerow(
                [
                    finding.rule_id,
                    finding.rule_name,
                    finding.severity,
                    finding.description,
                    finding.object_path,
                    finding.progseq,
                    finding.snippet,
                ]
            )


def severity_rank(severity: str) -> int:
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(severity.lower(), 0)


def should_fail(findings: list[Finding], threshold: str | None) -> bool:
    if not threshold:
        return False
    target_rank = severity_rank(threshold)
    return any(severity_rank(finding.severity) >= target_rank for finding in findings)


def main() -> int:
    args = parse_args()

    try:
        rule_items = read_json_file(args.rules)
        source_sql = (
            read_sql_file(args.source_sql) if args.source_sql else DEFAULT_PEOPLECODE_SQL
        )
        rules = load_rules(rule_items)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    try:
        rows = fetch_peoplecode_rows(args.connection_string, source_sql)
    except pyodbc.Error as exc:
        print(f"Database error: {exc}", file=sys.stderr)
        return 1

    findings = review_peoplecode(rows, rules)
    write_findings_csv(findings, args.output)

    print(f"Rules loaded: {len(rules)}")
    print(f"PeopleCode rows scanned: {len(rows)}")
    print(f"Findings written to: {args.output}")
    print(f"Finding count: {len(findings)}")

    if should_fail(findings, args.fail_on_severity):
        print(
            f"At least one finding met the fail threshold: {args.fail_on_severity}",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
