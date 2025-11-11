import logging
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

from app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MongoDB:
    """Lightweight wrapper around the Mongo client with helper methods."""

    def __init__(self):
        self.client = None
        self.db = None
        self.connect()

    def connect(self):
        try:
            self.client = MongoClient(settings.MONGO_URI_COMPUTED)
            self.db = self.client[settings.MONGO_DB]
            self.client.admin.command("ping")
            logger.info("Connected to MongoDB: %s", settings.MONGO_CLUSTER)
        except ConnectionFailure as exc:
            logger.error("Failed to connect to MongoDB: %s", exc)
            raise

    def close(self):
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")

    def get_collection(self, collection_name: str):
        return self.db[collection_name]

    def insert_one(self, collection_name: str, document: Dict[str, Any]):
        return self.get_collection(collection_name).insert_one(document)

    def insert_many(self, collection_name: str, documents: List[Dict[str, Any]]):
        return self.get_collection(collection_name).insert_many(documents)

    def find(self, collection_name: str, query: Optional[Dict[str, Any]] = None, limit: int = 0):
        cursor = self.get_collection(collection_name).find(query or {})
        if limit > 0:
            cursor = cursor.limit(limit)
        return list(cursor)

    def find_one(self, collection_name: str, query: Dict[str, Any]):
        return self.get_collection(collection_name).find_one(query)

    def update_one(self, collection_name: str, query: Dict[str, Any], update: Dict[str, Any], **kwargs):
        return self.get_collection(collection_name).update_one(query, update, **kwargs)

    def delete_one(self, collection_name: str, query: Dict[str, Any]):
        return self.get_collection(collection_name).delete_one(query)

    def count_documents(self, collection_name: str, query: Optional[Dict[str, Any]] = None):
        return self.get_collection(collection_name).count_documents(query or {})


mongodb = MongoDB()


class DatabaseClient:
    """Higher-level helper that exposes the legacy db.* API expected by other modules."""

    ALERTS_COLLECTION = "alerts"
    BLOCKLIST_COLLECTION = "blocklist"
    ISOLATION_COLLECTION = "isolated_nodes"

    def __init__(self, mongo: MongoDB):
        self.mongo = mongo

    def store_alert(self, alert: Dict[str, Any]):
        document = alert.copy()
        document.setdefault("timestamp", int(time.time()))
        self.mongo.insert_one(self.ALERTS_COLLECTION, document)

    def add_to_blocklist(self, ip: str, reason: str, ttl_seconds: int):
        expires = int(time.time()) + ttl_seconds
        document = {
            "ip": ip,
            "reason": reason,
            "timestamp": int(time.time()),
            "expires_at": expires,
        }
        self.mongo.update_one(
            self.BLOCKLIST_COLLECTION,
            {"ip": ip},
            {"$set": document},
            upsert=True,
        )

    def remove_from_blocklist(self, ip: str):
        self.mongo.delete_one(self.BLOCKLIST_COLLECTION, {"ip": ip})

    def is_blocked(self, ip: str) -> bool:
        record = self.mongo.find_one(self.BLOCKLIST_COLLECTION, {"ip": ip})
        if not record:
            return False
        if record.get("expires_at", 0) < int(time.time()):
            self.remove_from_blocklist(ip)
            return False
        return True

    def get_blocklist(self) -> List[Dict[str, Any]]:
        return self.mongo.find(self.BLOCKLIST_COLLECTION)

    def isolate_node(self, node_id: str, reason: str, ttl_seconds: int):
        expires = int(time.time()) + ttl_seconds
        document = {
            "node_id": node_id,
            "reason": reason,
            "timestamp": int(time.time()),
            "expires_at": expires,
        }
        self.mongo.update_one(
            self.ISOLATION_COLLECTION,
            {"node_id": node_id},
            {"$set": document},
            upsert=True,
        )

    def remove_isolation(self, node_id: str):
        self.mongo.delete_one(self.ISOLATION_COLLECTION, {"node_id": node_id})

    def is_isolated(self, node_id: str) -> bool:
        record = self.mongo.find_one(self.ISOLATION_COLLECTION, {"node_id": node_id})
        if not record:
            return False
        if record.get("expires_at", 0) < int(time.time()):
            self.remove_isolation(node_id)
            return False
        return True

    def get_isolated_nodes(self) -> List[Dict[str, Any]]:
        return self.mongo.find(self.ISOLATION_COLLECTION)


db = DatabaseClient(mongodb)


@contextmanager
def get_mongodb_collection(collection_name: str):
    try:
        yield mongodb.get_collection(collection_name)
    except Exception as exc:
        logger.error("Error accessing MongoDB collection %s: %s", collection_name, exc)
        raise


def init_db():
    """Create the indexes we rely on for lookups."""
    try:
        alerts_collection = mongodb.get_collection(DatabaseClient.ALERTS_COLLECTION)
        alerts_collection.create_index([("timestamp", -1)])
        alerts_collection.create_index([("source_ip", 1)])
        alerts_collection.create_index([("attack_types", 1)])

        packets_collection = mongodb.get_collection("packets")
        packets_collection.create_index([("timestamp", -1)])
        packets_collection.create_index([("source_ip", 1)])
        packets_collection.create_index([("dest_ip", 1)])

        blocklist_collection = mongodb.get_collection(DatabaseClient.BLOCKLIST_COLLECTION)
        blocklist_collection.create_index("ip", unique=True)
        blocklist_collection.create_index("expires_at")

        isolation_collection = mongodb.get_collection(DatabaseClient.ISOLATION_COLLECTION)
        isolation_collection.create_index("node_id", unique=True)
        isolation_collection.create_index("expires_at")

        logger.info("Database initialized successfully")
    except Exception as exc:
        logger.error("Error initializing database: %s", exc)
        raise
