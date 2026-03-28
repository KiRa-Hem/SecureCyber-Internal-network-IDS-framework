#!/usr/bin/env python3
"""
SQLite to MongoDB Migration Script
This script migrates data from SQLite to MongoDB for the Enhanced IDS/IPS System.
"""

import os
import sys
import sqlite3
import pymongo
from datetime import datetime
from pymongo import MongoClient
from typing import Dict, List, Any
import logging

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SQLiteToMongoMigrator:
    def __init__(self, sqlite_path: str, mongo_uri: str, db_name: str):
        """
        Initialize the migrator.
        
        Args:
            sqlite_path: Path to the SQLite database file
            mongo_uri: MongoDB connection URI
            db_name: MongoDB database name
        """
        self.sqlite_path = sqlite_path
        self.mongo_uri = mongo_uri
        self.db_name = db_name
        self.mongo_client = None
        self.sqlite_conn = None
        
    def connect(self):
        """Connect to both SQLite and MongoDB."""
        # Connect to SQLite
        try:
            self.sqlite_conn = sqlite3.connect(self.sqlite_path)
            logger.info(f"Connected to SQLite database: {self.sqlite_path}")
        except sqlite3.Error as e:
            logger.error(f"Error connecting to SQLite: {e}")
            raise
            
        # Connect to MongoDB
        try:
            self.mongo_client = MongoClient(self.mongo_uri)
            db = self.mongo_client[self.db_name]
            # Test connection
            db.command('ping')
            logger.info(f"Connected to MongoDB: {settings.MONGO_CLUSTER}")
        except pymongo.errors.ConnectionFailure as e:
            logger.error(f"Error connecting to MongoDB: {e}")
            raise
            
    def disconnect(self):
        """Disconnect from both databases."""
        if self.sqlite_conn:
            self.sqlite_conn.close()
            logger.info("Disconnected from SQLite")
            
        if self.mongo_client:
            self.mongo_client.close()
            logger.info("Disconnected from MongoDB")
            
    def get_tables(self) -> List[str]:
        """Get a list of all tables in the SQLite database."""
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        return tables
        
    def get_table_schema(self, table_name: str) -> List[Dict[str, Any]]:
        """
        Get the schema of a table.
        
        Args:
            table_name: Name of the table
            
        Returns:
            List of dictionaries with column information
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = []
        for row in cursor.fetchall():
            columns.append({
                'name': row[1],
                'type': row[2],
                'not_null': bool(row[3]),
                'default_value': row[4],
                'primary_key': bool(row[5])
            })
        return columns
        
    def get_table_data(self, table_name: str) -> List[Dict[str, Any]]:
        """
        Get all data from a table.
        
        Args:
            table_name: Name of the table
            
        Returns:
            List of dictionaries with row data
        """
        cursor = self.sqlite_conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name}")
        columns = [description[0] for description in cursor.description]
        
        data = []
        for row in cursor.fetchall():
            row_dict = {}
            for i, value in enumerate(row):
                # Convert SQLite types to Python types
                if isinstance(value, bytes):
                    # Handle binary data
                    row_dict[columns[i]] = value.hex()
                else:
                    row_dict[columns[i]] = value
            data.append(row_dict)
            
        return data
        
    def migrate_table(self, table_name: str):
        """
        Migrate a single table from SQLite to MongoDB.
        
        Args:
            table_name: Name of the table to migrate
        """
        logger.info(f"Migrating table: {table_name}")
        
        # Get table schema
        schema = self.get_table_schema(table_name)
        logger.debug(f"Table schema: {schema}")
        
        # Get table data
        data = self.get_table_data(table_name)
        logger.info(f"Found {len(data)} records in table {table_name}")
        
        if not data:
            logger.warning(f"No data found in table {table_name}, skipping")
            return
            
        # Get MongoDB collection
        db = self.mongo_client[self.db_name]
        collection = db[table_name]
        
        # Insert data into MongoDB
        try:
            if data:
                result = collection.insert_many(data)
                logger.info(f"Inserted {len(result.inserted_ids)} documents into {table_name}")
            else:
                logger.info(f"No data to insert for table {table_name}")
        except pymongo.errors.BulkWriteError as e:
            logger.error(f"Error inserting data into {table_name}: {e.details}")
            raise
            
    def migrate_all_tables(self):
        """Migrate all tables from SQLite to MongoDB."""
        tables = self.get_tables()
        logger.info(f"Found {len(tables)} tables to migrate")
        
        for table in tables:
            # Skip SQLite internal tables
            if table.startswith('sqlite_'):
                continue
                
            self.migrate_table(table)
            
    def create_indexes(self):
        """Create indexes in MongoDB for better performance."""
        db = self.mongo_client[self.db_name]
        
        # Create indexes for users collection
        if 'users' in db.list_collection_names():
            db.users.create_index([("username", pymongo.ASCENDING)], unique=True)
            db.users.create_index([("email", pymongo.ASCENDING)], unique=True)
            logger.info("Created indexes for users collection")
            
        # Create indexes for alerts collection
        if 'alerts' in db.list_collection_names():
            db.alerts.create_index([("timestamp", pymongo.DESCENDING)])
            db.alerts.create_index([("source_ip", pymongo.ASCENDING)])
            db.alerts.create_index([("attack_types", pymongo.ASCENDING)])
            logger.info("Created indexes for alerts collection")
            
        # Create indexes for packets collection
        if 'packets' in db.list_collection_names():
            db.packets.create_index([("timestamp", pymongo.DESCENDING)])
            db.packets.create_index([("source_ip", pymongo.ASCENDING)])
            db.packets.create_index([("dest_ip", pymongo.ASCENDING)])
            logger.info("Created indexes for packets collection")

def main():
    """Main function to run the migration."""
    # Get configuration
    sqlite_path = os.path.join(os.path.dirname(__file__), '..', 'backend', 'data', 'ids.db')
    mongo_uri = settings.MONGO_URI_COMPUTED
    db_name = settings.MONGO_DB
    
    # Check if SQLite database exists
    if not os.path.exists(sqlite_path):
        logger.error(f"SQLite database not found: {sqlite_path}")
        return 1
        
    # Create migrator
    migrator = SQLiteToMongoMigrator(sqlite_path, mongo_uri, db_name)
    
    try:
        # Connect to databases
        migrator.connect()
        
        # Migrate all tables
        migrator.migrate_all_tables()
        
        # Create indexes
        migrator.create_indexes()
        
        logger.info("Migration completed successfully")
        return 0
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return 1
    finally:
        # Disconnect from databases
        migrator.disconnect()

if __name__ == "__main__":
    sys.exit(main())
