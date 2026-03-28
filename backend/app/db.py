import logging
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from pymongo import MongoClient
try:
    from bson import ObjectId
except Exception:  # pragma: no cover - optional dependency
    ObjectId = None
from pymongo.errors import ConnectionFailure

from app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MongoDB:
    """Lightweight wrapper around the Mongo client with helper methods."""

    def __init__(self):
        self.client = None
        self.db = None
        self.connected = False
        self.connect()

    def connect(self):
        try:
            self.client = MongoClient(
                settings.MONGO_URI_COMPUTED,
                serverSelectionTimeoutMS=3000,
            )
            self.db = self.client[settings.MONGO_DB]
            self.client.admin.command("ping")
            logger.info("Connected to MongoDB: %s", settings.MONGO_CLUSTER)
            self.connected = True
        except Exception as exc:
            logger.warning("MongoDB unavailable (%s). Falling back to in-memory storage.", exc)
            self.client = None
            self.db = None
            self.connected = False
        return self.connected

    def ensure_connection(self) -> bool:
        if not self.connected:
            return self.connect()
        if self.client is None:
            return self.connect()
        try:
            self.client.admin.command("ping")
            return True
        except Exception as exc:
            logger.warning("Lost MongoDB connection (%s). Falling back to in-memory storage.", exc)
            self.close()
            return False

    def close(self):
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")
        self.connected = False

    def get_collection(self, collection_name: str):
        if not self.connected or self.db is None:
            raise RuntimeError("MongoDB is not connected.")
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
    AUDIT_COLLECTION = "audit_logs"
    FEEDBACK_COLLECTION = "alert_feedback"

    def __init__(self, mongo: MongoDB):
        self.mongo = mongo
        self._memory_alerts: List[Dict[str, Any]] = []
        self._memory_blocklist: Dict[str, Dict[str, Any]] = {}
        self._memory_isolated: Dict[str, Dict[str, Any]] = {}
        self._memory_audit: List[Dict[str, Any]] = []
        self._memory_feedback: List[Dict[str, Any]] = []

    def _use_memory(self) -> bool:
        return not self.mongo.ensure_connection()

    def store_alert(self, alert: Dict[str, Any]):
        document = alert.copy()
        document.setdefault("timestamp", int(time.time()))
        if self._use_memory():
            self._memory_alerts.append(document)
            return
        try:
            self.mongo.insert_one(self.ALERTS_COLLECTION, document)
        except Exception as exc:
            logger.warning("MongoDB insert failed (%s). Using in-memory alert storage.", exc)
            self.mongo.close()
            self._memory_alerts.append(document)

    def store_audit(self, entry: Dict[str, Any]):
        document = entry.copy()
        document.setdefault("timestamp", int(time.time()))
        if self._use_memory():
            self._memory_audit.append(document)
            return
        try:
            self.mongo.insert_one(self.AUDIT_COLLECTION, document)
        except Exception as exc:
            logger.warning("MongoDB audit insert failed (%s). Using in-memory audit.", exc)
            self.mongo.close()
            self._memory_audit.append(document)

    def store_feedback(self, entry: Dict[str, Any]):
        document = entry.copy()
        document.setdefault("timestamp", int(time.time()))
        if self._use_memory():
            self._memory_feedback.append(document)
            return
        try:
            self.mongo.insert_one(self.FEEDBACK_COLLECTION, document)
        except Exception as exc:
            logger.warning("MongoDB feedback insert failed (%s). Using in-memory feedback.", exc)
            self.mongo.close()
            self._memory_feedback.append(document)

    def add_to_blocklist(self, ip: str, reason: str, ttl_seconds: int):
        expires = int(time.time()) + ttl_seconds
        document = {
            "ip": ip,
            "reason": reason,
            "timestamp": int(time.time()),
            "expires_at": expires,
        }
        if self._use_memory():
            self._memory_blocklist[ip] = document
            return
        try:
            self.mongo.update_one(
                self.BLOCKLIST_COLLECTION,
                {"ip": ip},
                {"$set": document},
                upsert=True,
            )
        except Exception as exc:
            logger.warning("MongoDB blocklist update failed (%s). Using in-memory blocklist.", exc)
            self.mongo.close()
            self._memory_blocklist[ip] = document

    def remove_from_blocklist(self, ip: str):
        if self._use_memory():
            self._memory_blocklist.pop(ip, None)
            return
        try:
            self.mongo.delete_one(self.BLOCKLIST_COLLECTION, {"ip": ip})
        except Exception as exc:
            logger.warning("MongoDB blocklist delete failed (%s).", exc)
            self.mongo.close()

    def is_blocked(self, ip: str) -> bool:
        if self._use_memory():
            record = self._memory_blocklist.get(ip)
        else:
            try:
                record = self.mongo.find_one(self.BLOCKLIST_COLLECTION, {"ip": ip})
            except Exception as exc:
                logger.warning("MongoDB blocklist lookup failed (%s). Using in-memory blocklist.", exc)
                self.mongo.close()
                record = self._memory_blocklist.get(ip)
        if not record:
            return False
        if record.get("expires_at", 0) < int(time.time()):
            self.remove_from_blocklist(ip)
            return False
        return True

    def get_blocklist(self) -> List[Dict[str, Any]]:
        if self._use_memory():
            return [self._serialize_document(item) for item in self._memory_blocklist.values()]
        try:
            return [self._serialize_document(item) for item in self.mongo.find(self.BLOCKLIST_COLLECTION)]
        except Exception as exc:
            logger.warning("MongoDB blocklist fetch failed (%s). Using in-memory blocklist.", exc)
            self.mongo.close()
            return [self._serialize_document(item) for item in self._memory_blocklist.values()]

    def isolate_node(self, node_id: str, reason: str, ttl_seconds: int):
        expires = int(time.time()) + ttl_seconds
        document = {
            "node_id": node_id,
            "reason": reason,
            "timestamp": int(time.time()),
            "expires_at": expires,
        }
        if self._use_memory():
            self._memory_isolated[node_id] = document
            return
        try:
            self.mongo.update_one(
                self.ISOLATION_COLLECTION,
                {"node_id": node_id},
                {"$set": document},
                upsert=True,
            )
        except Exception as exc:
            logger.warning("MongoDB isolation update failed (%s). Using in-memory isolation.", exc)
            self.mongo.close()
            self._memory_isolated[node_id] = document

    def remove_isolation(self, node_id: str):
        if self._use_memory():
            self._memory_isolated.pop(node_id, None)
            return
        try:
            self.mongo.delete_one(self.ISOLATION_COLLECTION, {"node_id": node_id})
        except Exception as exc:
            logger.warning("MongoDB isolation delete failed (%s).", exc)
            self.mongo.close()

    def is_isolated(self, node_id: str) -> bool:
        if self._use_memory():
            record = self._memory_isolated.get(node_id)
        else:
            try:
                record = self.mongo.find_one(self.ISOLATION_COLLECTION, {"node_id": node_id})
            except Exception as exc:
                logger.warning("MongoDB isolation lookup failed (%s). Using in-memory isolation.", exc)
                self.mongo.close()
                record = self._memory_isolated.get(node_id)
        if not record:
            return False
        if record.get("expires_at", 0) < int(time.time()):
            self.remove_isolation(node_id)
            return False
        return True

    def get_isolated_nodes(self) -> List[Dict[str, Any]]:
        if self._use_memory():
            return [self._serialize_document(item) for item in self._memory_isolated.values()]
        try:
            return [self._serialize_document(item) for item in self.mongo.find(self.ISOLATION_COLLECTION)]
        except Exception as exc:
            logger.warning("MongoDB isolation fetch failed (%s). Using in-memory isolation.", exc)
            self.mongo.close()
            return [self._serialize_document(item) for item in self._memory_isolated.values()]

    def get_alerts(self, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        if self._use_memory():
            alerts = sorted(
                self._memory_alerts,
                key=lambda entry: entry.get("timestamp", 0),
                reverse=True,
            )
            return [self._serialize_document(alert) for alert in alerts[offset:offset + limit]]
        try:
            collection = self.mongo.get_collection(self.ALERTS_COLLECTION)
            cursor = collection.find({}, sort=[("timestamp", -1)], skip=offset, limit=limit)
            return [self._serialize_document(alert) for alert in cursor]
        except Exception as exc:
            logger.warning("MongoDB alert fetch failed (%s). Using in-memory alerts.", exc)
            self.mongo.close()
            alerts = sorted(
                self._memory_alerts,
                key=lambda entry: entry.get("timestamp", 0),
                reverse=True,
            )
            return [self._serialize_document(alert) for alert in alerts[offset:offset + limit]]

    def count_alerts(self) -> int:
        if self._use_memory():
            return len(self._memory_alerts)
        try:
            return self.mongo.count_documents(self.ALERTS_COLLECTION)
        except Exception as exc:
            logger.warning("MongoDB alert count failed (%s). Using in-memory alerts.", exc)
            self.mongo.close()
            return len(self._memory_alerts)

    def _serialize_document(self, value: Any) -> Any:
        if ObjectId is not None and isinstance(value, ObjectId):
            return str(value)
        if isinstance(value, dict):
            return {key: self._serialize_document(val) for key, val in value.items()}
        if isinstance(value, list):
            return [self._serialize_document(item) for item in value]
        return value


db = DatabaseClient(mongodb)


@contextmanager
def get_mongodb_collection(collection_name: str):
    try:
        if not mongodb.ensure_connection():
            raise RuntimeError("MongoDB is not available.")
        yield mongodb.get_collection(collection_name)
    except Exception as exc:
        logger.error("Error accessing MongoDB collection %s: %s", collection_name, exc)
        raise


def init_db():
    """Create the indexes we rely on for lookups."""
    try:
        if not mongodb.ensure_connection():
            logger.warning("Skipping index setup because MongoDB is unavailable.")
            return False
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

        audit_collection = mongodb.get_collection(DatabaseClient.AUDIT_COLLECTION)
        audit_collection.create_index([("timestamp", -1)])
        audit_collection.create_index([("event_type", 1)])

        feedback_collection = mongodb.get_collection(DatabaseClient.FEEDBACK_COLLECTION)
        feedback_collection.create_index([("timestamp", -1)])
        feedback_collection.create_index([("alert_id", 1)])

        logger.info("Database initialized successfully")
        return True
    except Exception as exc:
        logger.error("Error initializing database: %s", exc)
        return False
