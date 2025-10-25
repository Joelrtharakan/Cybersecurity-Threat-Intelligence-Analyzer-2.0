"""
realtime.py
Listens for new inserts using MongoDB Change Streams.
"""

from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cyber_intel"
COLL_NAME = "urls"

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
col = db[COLL_NAME]

def main():
    print("Listening for changes...")
    with col.watch() as stream:
        for change in stream:
            print("New document inserted:", change['fullDocument']['url'])

if __name__ == '__main__':
    main()