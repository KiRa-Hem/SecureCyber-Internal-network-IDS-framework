import os
import sys

import pytest

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.db import DatabaseClient

try:
    from bson import ObjectId
except Exception:  # pragma: no cover
    ObjectId = None


class FakeMongo:
    def __init__(self):
        self.connected = True
        self.find_result = []
        self.insert_calls = []

    def ensure_connection(self):
        return self.connected

    def find(self, _collection, _query=None, _limit=0):
        return list(self.find_result)

    def insert_one(self, collection_name, document):
        self.insert_calls.append((collection_name, document))
        return True

    def close(self):
        self.connected = False


def test_store_audit_writes_to_audit_collection():
    mongo = FakeMongo()
    client = DatabaseClient(mongo)

    client.store_audit({"event_type": "block_ip", "actor": "admin"})

    assert len(mongo.insert_calls) == 1
    assert mongo.insert_calls[0][0] == DatabaseClient.AUDIT_COLLECTION


def test_store_feedback_does_not_write_to_audit_collection():
    mongo = FakeMongo()
    client = DatabaseClient(mongo)

    client.store_feedback({"alert_id": "a1", "label": "false_positive"})

    assert len(mongo.insert_calls) == 1
    assert mongo.insert_calls[0][0] == DatabaseClient.FEEDBACK_COLLECTION


@pytest.mark.skipif(ObjectId is None, reason="bson.ObjectId unavailable")
def test_get_blocklist_serializes_object_ids():
    mongo = FakeMongo()
    mongo.find_result = [{"_id": ObjectId(), "ip": "192.0.2.5"}]
    client = DatabaseClient(mongo)

    rows = client.get_blocklist()

    assert rows
    assert isinstance(rows[0]["_id"], str)


@pytest.mark.skipif(ObjectId is None, reason="bson.ObjectId unavailable")
def test_get_isolated_nodes_serializes_object_ids():
    mongo = FakeMongo()
    mongo.find_result = [{"_id": ObjectId(), "node_id": "db-01"}]
    client = DatabaseClient(mongo)

    rows = client.get_isolated_nodes()

    assert rows
    assert isinstance(rows[0]["_id"], str)
