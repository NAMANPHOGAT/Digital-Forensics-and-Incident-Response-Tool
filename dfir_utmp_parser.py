#!/usr/bin/env python3
"""DFIR parser for Linux utmp/wtmp/btmp and Windows Security EVTX logs."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from typing import Any

# Linux utmp struct on common glibc systems (384 bytes), little-endian explicit.
UTMP_STRUCT = struct.Struct("<hi32s4s32s256shhiii4I20s")

UT_TYPE_MAP = {
    0: "EMPTY",
    1: "RUN_LVL",
    2: "BOOT_TIME",
    3: "NEW_TIME",
    4: "OLD_TIME",
    5: "INIT_PROCESS",
    6: "LOGIN_PROCESS",
    7: "USER_PROCESS",
    8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}


def _decode(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()


def _safe_datetime(ts: float | int | None) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


def _ip_from_ut_addr_v6(addr_v6: tuple[int, int, int, int]) -> str:
    if all(part == 0 for part in addr_v6):
        return ""

    # Common case for IPv4 in first 32-bit word.
    if addr_v6[1] == addr_v6[2] == addr_v6[3] == 0:
        try:
            packed = struct.pack("<I", addr_v6[0])
            return str(ipaddress.IPv4Address(packed))
        except ipaddress.AddressValueError:
            pass

    try:
        packed_v6 = struct.pack("<4I", *addr_v6)
        return str(ipaddress.IPv6Address(packed_v6))
    except ipaddress.AddressValueError:
        return ""


def parse_linux_utmp_file(path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(UTMP_STRUCT.size)
            if not chunk:
                break
            if len(chunk) < UTMP_STRUCT.size:
                break

            unpacked = UTMP_STRUCT.unpack(chunk)
            ut_type, ut_pid, ut_line, _ut_id, ut_user, ut_host, _exit_t, _session, tv_sec, tv_usec, a, b, c, d, _unused = unpacked

            if ut_type == 0 and ut_pid == 0 and not any((ut_line, ut_user, ut_host)):
                continue

            ts = None
            if tv_sec > 0:
                ts = float(tv_sec) + (float(tv_usec) / 1_000_000)

            record = {
                "platform": "linux",
                "type": UT_TYPE_MAP.get(ut_type, f"UNKNOWN_{ut_type}"),
                "type_id": ut_type,
                "user": _decode(ut_user),
                "pid": ut_pid,
                "terminal": _decode(ut_line),
                "host": _decode(ut_host),
                "ip": _ip_from_ut_addr_v6((a, b, c, d)),
                "timestamp": ts,
                "time_readable": _safe_datetime(ts),
            }
            records.append(record)

    return records


def _extract_ip(text: str) -> str:
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return ""


def parse_windows_evtx_file(path: str) -> list[dict[str, Any]]:
    """Parse Security EVTX events related to logons.

    Requires the optional `python-evtx` package.
    """
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "Windows EVTX parsing requires python-evtx. Install with: pip install python-evtx"
        ) from exc

    login_event_ids = {4624: "USER_PROCESS", 4625: "FAILED_LOGIN"}
    records: list[dict[str, Any]] = []

    with Evtx(path) as log:
        for event in log.records():
            xml_text = event.xml()
            root = ET.fromstring(xml_text)

            system = root.find(".//{*}System")
            if system is None:
                continue

            event_id_node = system.find("{*}EventID")
            if event_id_node is None or not event_id_node.text:
                continue
            try:
                event_id = int(event_id_node.text)
            except ValueError:
                continue

            if event_id not in login_event_ids:
                continue

            time_node = system.find(".//{*}TimeCreated")
            ts_iso = ""
            ts = None
            if time_node is not None:
                raw = time_node.attrib.get("SystemTime", "")
                if raw:
                    ts_iso = raw
                    try:
                        ts = datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
                    except ValueError:
                        ts = None

            user = ""
            host = ""
            ip = _extract_ip(xml_text)
            data_nodes = root.findall(".//{*}EventData/{*}Data")
            for node in data_nodes:
                name = (node.attrib.get("Name") or "").lower()
                value = node.text or ""
                if name in {"targetusername", "subjectusername"} and value and value != "-":
                    user = value
                elif name in {"workstationname", "targetdomainname"} and value and value != "-":
                    host = value
                elif name in {"ipaddress", "sourceip", "source network address"} and value and value != "-":
                    ip = value

            records.append(
                {
                    "platform": "windows",
                    "type": login_event_ids[event_id],
                    "type_id": event_id,
                    "user": user,
                    "pid": None,
                    "terminal": "N/A",
                    "host": host,
                    "ip": ip,
                    "timestamp": ts,
                    "time_readable": ts_iso or _safe_datetime(ts),
                }
            )

    return records


def detect_anomalies(records: list[dict[str, Any]], source_name: str) -> list[dict[str, Any]]:
    failed_counts: Counter[tuple[str, str]] = Counter()

    for record in records:
        record_type = (record.get("type") or "").upper()
        if source_name.endswith("btmp") or record_type == "FAILED_LOGIN":
            if record.get("user"):
                failed_counts[(record.get("user", ""), record.get("ip", ""))] += 1

    for record in records:
        reasons: list[str] = []

        ip_text = record.get("ip") or ""
        if ip_text:
            try:
                ip_obj = ipaddress.ip_address(ip_text)
                if not (ip_obj.is_private or ip_obj.is_loopback):
                    reasons.append("suspicious_public_ip")
            except ValueError:
                reasons.append("malformed_ip")

        if record.get("type") in {"USER_PROCESS", "LOGIN_PROCESS"} and record.get("timestamp") is not None:
            hour = datetime.fromtimestamp(float(record["timestamp"])).hour
            if hour < 6 or hour >= 22:
                reasons.append("off_hours_login")

        key = (record.get("user", ""), record.get("ip", ""))
        if failed_counts.get(key, 0) >= 5 and key[0]:
            reasons.append("repeated_failed_logins")

        record["anomalies"] = sorted(set(reasons))
        record["is_suspicious"] = bool(reasons)

    return records


def write_csv(records: list[dict[str, Any]], out_path: str) -> None:
    fields = [
        "platform",
        "type",
        "type_id",
        "user",
        "pid",
        "terminal",
        "host",
        "ip",
        "timestamp",
        "time_readable",
        "is_suspicious",
        "anomalies",
    ]

    with open(out_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in records:
            row = dict(record)
            row["anomalies"] = ";".join(record.get("anomalies", []))
            writer.writerow(row)


def write_json(records: list[dict[str, Any]], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2, ensure_ascii=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse Linux utmp/wtmp/btmp or Windows Security EVTX logs into CSV/JSON.",
    )
    parser.add_argument("--input", required=True, help="Path to input file (.utmp/.wtmp/.btmp or .evtx)")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--format", choices=("csv", "json"), required=True, help="Output format")
    parser.add_argument(
        "--source-type",
        choices=("linux", "windows", "auto"),
        default="auto",
        help="Input source type. auto picks by extension (.evtx => windows, else linux).",
    )
    parser.add_argument(
        "--anomaly-detection",
        action="store_true",
        help="Enable simple anomaly detection (IP, off-hours, repeated failures)",
    )
    return parser.parse_args()


def _detect_source_type(input_path: str, source_type: str) -> str:
    if source_type != "auto":
        return source_type
    if input_path.lower().endswith(".evtx"):
        return "windows"
    return "linux"


def main() -> int:
    args = parse_args()

    if not os.path.exists(args.input):
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 1

    source_type = _detect_source_type(args.input, args.source_type)

    try:
        if source_type == "windows":
            records = parse_windows_evtx_file(args.input)
        else:
            records = parse_linux_utmp_file(args.input)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.anomaly_detection:
        records = detect_anomalies(records, os.path.basename(args.input).lower())
    else:
        for record in records:
            record["anomalies"] = []
            record["is_suspicious"] = False

    if args.format == "csv":
        write_csv(records, args.output)
    else:
        write_json(records, args.output)

    print(f"Parsed {len(records)} records ({source_type}) -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
