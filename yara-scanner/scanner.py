"""
YARA Scanner Service

Flask REST API for file-based and log-based YARA scanning.
Results are indexed into OpenSearch for correlation with DeTTECT coverage.
"""

import json
import os
import glob
import logging
from datetime import datetime, timezone

import yara
from flask import Flask, jsonify, request
from opensearchpy import OpenSearch

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200")
RULES_DIR = os.environ.get("RULES_DIR", "/app/rules")
SAMPLES_DIR = os.environ.get("SAMPLES_DIR", "/app/samples")
LOGS_DIR = os.environ.get("LOGS_DIR", "/app/logs")

# Text fields to extract from JSON log events for YARA matching
LOG_TEXT_FIELDS = [
    "CommandLine",
    "ParentCommandLine",
    "ScriptBlockText",
    "ParentImage",
    "Image",
    "TargetFilename",
    "SourceHostname",
    "DestinationHostname",
    "User",
    "ProcessName",
    "Message",
]

os_client = None
file_rules = None
log_rules = None


def get_opensearch_client():
    global os_client
    if os_client is None:
        host = OPENSEARCH_URL.replace("http://", "").replace("https://", "")
        hostname, port = host.split(":")
        os_client = OpenSearch(
            hosts=[{"host": hostname, "port": int(port)}],
            use_ssl=False,
            verify_certs=False,
        )
    return os_client


def compile_rules(rules_subdir):
    """Compile all .yar/.yara files in a subdirectory."""
    rule_files = {}
    patterns = [
        os.path.join(RULES_DIR, rules_subdir, "*.yar"),
        os.path.join(RULES_DIR, rules_subdir, "*.yara"),
    ]
    for pattern in patterns:
        for filepath in glob.glob(pattern):
            namespace = os.path.splitext(os.path.basename(filepath))[0]
            rule_files[namespace] = filepath

    if not rule_files:
        logger.warning("No YARA rules found in %s/%s", RULES_DIR, rules_subdir)
        return None

    try:
        compiled = yara.compile(filepaths=rule_files)
        logger.info(
            "Compiled %d rule file(s) from %s", len(rule_files), rules_subdir
        )
        return compiled
    except yara.SyntaxError as e:
        logger.error("YARA syntax error in %s: %s", rules_subdir, e)
        return None


def init_rules():
    global file_rules, log_rules
    file_rules = compile_rules("file-rules")
    log_rules = compile_rules("log-rules")


def format_match(match, filepath, scan_type):
    """Format a YARA match into a result dict."""
    matched_strings = []
    for string_match in match.strings:
        for instance in string_match.instances:
            matched_strings.append(
                {
                    "identifier": string_match.identifier,
                    "offset": instance.offset,
                    "data": instance.matched_data.decode("utf-8", errors="replace")[:200],
                }
            )

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "rule_name": match.rule,
        "matched_file": filepath,
        "matched_strings": matched_strings,
        "tags": list(match.tags),
        "technique_id": match.meta.get("technique_id", "unknown"),
        "description": match.meta.get("description", ""),
        "severity": match.meta.get("severity", "info"),
        "scan_type": scan_type,
    }


def index_result(result):
    """Index a scan result into OpenSearch."""
    try:
        client = get_opensearch_client()
        client.index(index="yara-results", body=result)
    except Exception as e:
        logger.error("Failed to index result: %s", e)


@app.route("/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "file_rules_loaded": file_rules is not None,
            "log_rules_loaded": log_rules is not None,
        }
    )


@app.route("/scan/files", methods=["POST"])
def scan_files():
    """Scan all files in the samples directory against file YARA rules."""
    if file_rules is None:
        return jsonify({"error": "No file rules loaded"}), 500

    results = []
    scanned = 0

    for root, _, files in os.walk(SAMPLES_DIR):
        for filename in files:
            if filename.startswith("."):
                continue
            filepath = os.path.join(root, filename)
            scanned += 1
            try:
                matches = file_rules.match(filepath)
                for match in matches:
                    result = format_match(match, filepath, "file")
                    results.append(result)
                    index_result(result)
            except Exception as e:
                logger.error("Error scanning %s: %s", filepath, e)

    return jsonify(
        {
            "scan_type": "file",
            "files_scanned": scanned,
            "matches_found": len(results),
            "results": results,
        }
    )


@app.route("/scan/logs", methods=["POST"])
def scan_logs():
    """Scan JSON log files against log YARA rules.

    For each JSON event, extracts text fields and runs YARA pattern matching
    against the concatenated text buffer.
    """
    if log_rules is None:
        return jsonify({"error": "No log rules loaded"}), 500

    results = []
    events_scanned = 0

    json_files = glob.glob(os.path.join(LOGS_DIR, "*.json"))
    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    events_scanned += 1

                    # Extract text fields and concatenate for YARA matching
                    text_parts = []
                    for field in LOG_TEXT_FIELDS:
                        value = event.get(field, "")
                        if value:
                            text_parts.append(f"{field}={value}")
                    text_buffer = "\n".join(text_parts)

                    if not text_buffer:
                        continue

                    matches = log_rules.match(data=text_buffer.encode("utf-8"))
                    for match in matches:
                        source_info = f"{os.path.basename(json_file)}:L{line_num}"
                        result = format_match(match, source_info, "log")
                        result["source_event"] = {
                            "file": os.path.basename(json_file),
                            "line": line_num,
                            "EventID": event.get("EventID", ""),
                            "CommandLine": event.get("CommandLine", "")[:300],
                        }
                        results.append(result)
                        index_result(result)

        except Exception as e:
            logger.error("Error processing %s: %s", json_file, e)

    return jsonify(
        {
            "scan_type": "log",
            "events_scanned": events_scanned,
            "matches_found": len(results),
            "results": results,
        }
    )


@app.route("/scan/file", methods=["POST"])
def scan_single_file():
    """Upload and scan a single file."""
    if file_rules is None:
        return jsonify({"error": "No file rules loaded"}), 500

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded = request.files["file"]
    data = uploaded.read()
    matches = file_rules.match(data=data)

    results = []
    for match in matches:
        result = format_match(match, uploaded.filename, "file")
        results.append(result)
        index_result(result)

    return jsonify(
        {
            "filename": uploaded.filename,
            "matches_found": len(results),
            "results": results,
        }
    )


@app.route("/results", methods=["GET"])
def get_results():
    """Query YARA scan results from OpenSearch."""
    try:
        client = get_opensearch_client()
        size = request.args.get("size", 100, type=int)
        response = client.search(
            index="yara-results",
            body={
                "query": {"match_all": {}},
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": size,
            },
        )
        hits = [hit["_source"] for hit in response["hits"]["hits"]]
        return jsonify({"total": response["hits"]["total"]["value"], "results": hits})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rules/reload", methods=["POST"])
def reload_rules():
    """Reload YARA rules from disk."""
    init_rules()
    return jsonify(
        {
            "status": "reloaded",
            "file_rules_loaded": file_rules is not None,
            "log_rules_loaded": log_rules is not None,
        }
    )


if __name__ == "__main__":
    init_rules()
    app.run(host="0.0.0.0", port=8081, debug=False)
