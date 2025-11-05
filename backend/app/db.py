import os
import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from typing import Optional, Dict, List, Any
from datetime import datetime
from contextlib import contextmanager

from app.config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB setup
class MongoDB:
    def __init__(self):
        self.client = None
        self.db = None
        self.connect()
    
    def connect(self):
        try:
            self.client = MongoClient(settings.MONGO_URI_COMPUTED)
            self.db = self.client[settings.MONGO_DB]
            # Test connection
            self.client.admin.command('ping')
            logger.info(f'Connected to MongoDB: {settings.MONGO_CLUSTER}')
        except ConnectionFailure as e:
            logger.error(f'Failed to connect to MongoDB: {e}')
            raise
    
    def close(self):
        if self.client:
            self.client.close()
            logger.info('Disconnected from MongoDB')
    
    def get_collection(self, collection_name: str):
        return self.db[collection_name]
    
    def insert_one(self, collection_name: str, document: Dict[str, Any]):
        collection = self.get_collection(collection_name)
        return collection.insert_one(document)
    
    def insert_many(self, collection_name: str, documents: List[Dict[str, Any]]):
        collection = self.get_collection(collection_name)
        return collection.insert_many(documents)
    
    def find(self, collection_name: str, query: Dict[str, Any] = None, limit: int = 0):
        collection = self.get_collection(collection_name)
        if query is None:
            query = {}
        cursor = collection.find(query)
        if limit > 0:
            cursor = cursor.limit(limit)
        return list(cursor)
    
    def find_one(self, collection_name: str, query: Dict[str, Any]):
        collection = self.get_collection(collection_name)
        return collection.find_one(query)
    
    def update_one(self, collection_name: str, query: Dict[str, Any], update: Dict[str, Any]):
        collection = self.get_collection(collection_name)
        return collection.update_one(query, update)
    
    def delete_one(self, collection_name: str, query: Dict[str, Any]):
        collection = self.get_collection(collection_name)
        return collection.delete_one(query)
    
    def count_documents(self, collection_name: str, query: Dict[str, Any] = None):
        collection = self.get_collection(collection_name)
        if query is None:
            query = {}
        return collection.count_documents(query)

# Create MongoDB instance
mongodb = MongoDB()

# Context manager for MongoDB operations
@contextmanager
def get_mongodb_collection(collection_name: str):
    try:
        collection = mongodb.get_collection(collection_name)
        yield collection
    except Exception as e:
        logger.error(f'Error accessing MongoDB collection {collection_name}: {e}')
        raise

# Initialize database
def init_db():
    # Create indexes in MongoDB
    try:
        # Alerts collection indexes
        alerts_collection = mongodb.get_collection('alerts')
        alerts_collection.create_index([('timestamp', -1)])
        alerts_collection.create_index([('source_ip', 1)])
        alerts_collection.create_index([('attack_types', 1)])
        
        # Packets collection indexes
        packets_collection = mongodb.get_collection('packets')
        packets_collection.create_index([('timestamp', -1)])
        packets_collection.create_index([('source_ip', 1)])
        packets_collection.create_index([('dest_ip', 1)])
        
        logger.info('Database initialized successfully')
    except Exception as e:
        logger.error(f'Error initializing database: {e}')
        raise