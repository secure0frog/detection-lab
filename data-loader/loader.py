"""
Data Loader for Detection Lab

Creates OpenSearch index templates and bulk-loads sample log data.
Runs once as an init container, then exits.
"""

import json
import os
import glob
import sys
import time
import logging

from opensearchpy import OpenSearch, helpers

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200")
LOGS_DIR = os.environ.get("LOGS_DIR", "/app/logs")

MORDOR_INDEX = "mordor-events"
YARA_INDEX = "yara-results"

MORDOR_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "EventID": {"type": "integer"},
            "CommandLine": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
            "ParentCommandLine": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
            "ParentImage": {"type": "keyword"},
            "Image": {"type": "keyword"},
            "User": {"type": "keyword"},
            "SourceHostname": {"type": "keyword"},
            "DestinationHostname": {"type": "keyword"},
            "DestinationIp": {"type": "keyword"},
            "DestinationPort": {"type": "integer"},
            "ProcessId": {"type": "integer"},
            "ProcessName": {"type": "keyword"},
            "TargetFilename": {"type": "keyword"},
            "ScriptBlockText": {"type": "text"},
            "technique_id": {"type": "keyword"},
            "Message": {"type": "text"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
}

YARA_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "rule_name": {"type": "keyword"},
            "matched_file": {"type": "keyword"},
            "matched_strings": {"type": "nested", "properties": {
                "identifier": {"type": "keyword"},
                "offset": {"type": "integer"},
                "data": {"type": "text"},
            }},
            "tags": {"type": "keyword"},
            "technique_id": {"type": "keyword"},
            "description": {"type": "text"},
            "severity": {"type": "keyword"},
            "scan_type": {"type": "keyword"},
            "source_event": {"type": "object", "properties": {
                "file": {"type": "keyword"},
                "line": {"type": "integer"},
                "EventID": {"type": "integer"},
                "CommandLine": {"type": "text"},
            }},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
}


def get_client():
    host = OPENSEARCH_URL.replace("http://", "").replace("https://", "")
    hostname, port = host.split(":")
    return OpenSearch(
        hosts=[{"host": hostname, "port": int(port)}],
        use_ssl=False,
        verify_certs=False,
    )


def wait_for_opensearch(client, max_retries=30):
    """Wait for OpenSearch to be ready."""
    for i in range(max_retries):
        try:
            health = client.cluster.health()
            status = health.get("status", "red")
            if status in ("green", "yellow"):
                logger.info("OpenSearch is ready (status: %s)", status)
                return True
        except Exception:
            pass
        logger.info("Waiting for OpenSearch... (%d/%d)", i + 1, max_retries)
        time.sleep(5)
    return False


def create_indices(client):
    """Create index templates if they don't exist."""
    for index_name, mapping in [(MORDOR_INDEX, MORDOR_MAPPING), (YARA_INDEX, YARA_MAPPING)]:
        if not client.indices.exists(index=index_name):
            client.indices.create(index=index_name, body=mapping)
            logger.info("Created index: %s", index_name)
        else:
            logger.info("Index already exists: %s", index_name)


def load_json_files(client):
    """Load all JSON files from the logs directory into OpenSearch."""
    json_files = glob.glob(os.path.join(LOGS_DIR, "*.json"))
    if not json_files:
        logger.warning("No JSON files found in %s", LOGS_DIR)
        return 0

    total_docs = 0

    for json_file in json_files:
        filename = os.path.basename(json_file)
        logger.info("Processing: %s", filename)

        actions = []
        line_count = 0

        try:
            with open(json_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        doc = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    line_count += 1

                    # Map Timestamp field to @timestamp if present
                    if "Timestamp" in doc and "@timestamp" not in doc:
                        doc["@timestamp"] = doc.pop("Timestamp")

                    doc["_source_file"] = filename

                    actions.append({
                        "_index": MORDOR_INDEX,
                        "_source": doc,
                    })

            if actions:
                success, errors = helpers.bulk(client, actions, chunk_size=500, raise_on_error=False)
                total_docs += success
                if errors:
                    logger.warning("  %d errors indexing %s", len(errors), filename)
                logger.info("  Indexed %d/%d documents from %s", success, line_count, filename)
            else:
                logger.info("  No valid documents in %s", filename)

        except Exception as e:
            logger.error("  Error processing %s: %s", filename, e)

    return total_docs


def main():
    client = get_client()

    if not wait_for_opensearch(client):
        logger.error("OpenSearch is not available. Exiting.")
        sys.exit(1)

    create_indices(client)
    total = load_json_files(client)

    logger.info("=== Data loading complete ===")
    logger.info("Total documents indexed: %d", total)

    # Print index stats
    for index_name in [MORDOR_INDEX, YARA_INDEX]:
        try:
            count = client.count(index=index_name)
            logger.info("Index %s: %d documents", index_name, count["count"])
        except Exception:
            pass


if __name__ == "__main__":
    main()
