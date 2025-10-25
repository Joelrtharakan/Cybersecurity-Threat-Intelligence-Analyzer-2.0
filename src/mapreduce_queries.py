"""
mapreduce_queries.py
Runs several aggregation jobs on cyber_intel.urls and writes outputs into collections.
Outputs:
 - counts_by_type
 - mal_domains
 - malicious_tld_counts
 - url_length_by_type
"""

from pymongo import MongoClient
import pprint
import pycountry

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cyber_intel"
COLL_NAME = "urls"

def get_country_code(country_name):
    if not country_name or country_name == "Unknown":
        return None
    try:
        country = pycountry.countries.search_fuzzy(country_name)[0]
        return country.alpha_3
    except LookupError:
        return None

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
col = db[COLL_NAME]

def mr_counts_by_type():
    pipeline = [
        {"$group": {"_id": "$type", "value": {"$sum": 1}}}
    ]
    results = list(col.aggregate(pipeline))
    # Insert into collection
    db['counts_by_type'].drop()  # Clear previous
    if results:
        db['counts_by_type'].insert_many(results)
    print("Top types:")
    for doc in db['counts_by_type'].find().sort('value', -1).limit(20):
        pprint.pprint(doc)

def mr_malicious_domains():
    pipeline = [
        {"$match": {"type": {"$ne": "benign"}}},
        {"$group": {"_id": "$domain", "value": {"$sum": 1}}}
    ]
    results = list(col.aggregate(pipeline))
    db['mal_domains'].drop()
    if results:
        db['mal_domains'].insert_many(results)
    print("Top malicious domains:")
    for doc in db['mal_domains'].find().sort('value', -1).limit(20):
        pprint.pprint(doc)

def mr_malicious_tld_counts():
    pipeline = [
        {"$match": {"type": {"$ne": "benign"}}},
        {"$group": {"_id": {"$ifNull": ["$tld", "unknown"]}, "value": {"$sum": 1}}}
    ]
    results = list(col.aggregate(pipeline))
    db['malicious_tld_counts'].drop()
    if results:
        db['malicious_tld_counts'].insert_many(results)
    for doc in db['malicious_tld_counts'].find().sort('value', -1).limit(50):
        pprint.pprint(doc)

def mr_threat_scores():
    pipeline = [
        {"$group": {"_id": "$type", "avg_threat_score": {"$avg": "$threat_score"}, "max_threat_score": {"$max": "$threat_score"}}}
    ]
    results = list(col.aggregate(pipeline))
    db['threat_scores'].drop()
    if results:
        db['threat_scores'].insert_many(results)
    print("Threat scores by type:")
    for doc in db['threat_scores'].find():
        pprint.pprint(doc)

def mr_country_counts():
    # First, get the raw country counts
    pipeline = [
        {"$match": {"type": {"$ne": "benign"}}},
        {"$group": {"_id": "$country", "count": {"$sum": 1}}}
    ]
    results = list(col.aggregate(pipeline))
    
    # Convert country names to ISO-3 codes and aggregate counts
    country_data = []
    other_count = 0
    
    for result in results:
        country_name = result['_id']
        count = result['count']
        
        if country_name and country_name != "Unknown" and country_name != "":
            try:
                country = pycountry.countries.search_fuzzy(country_name)[0]
                country_data.append({
                    "_id": country.alpha_3,
                    "country_name": country_name,
                    "count": count
                })
            except LookupError:
                other_count += count
        else:
            other_count += count
    
    # Add the "Other/Unknown" category if there are any unmapped countries
    if other_count > 0:
        country_data.append({
            "_id": "OTHER",
            "country_name": "Other/Unknown",
            "count": other_count
        })
    
    # Update the database
    db['country_counts'].drop()
    if country_data:
        db['country_counts'].insert_many(country_data)
    
    print("Malicious URLs by country:")
    for doc in db['country_counts'].find().sort('count', -1).limit(10):
        pprint.pprint(doc)

def mr_url_length_by_type():
    pipeline = [
        {"$project": {
            "type": {"$ifNull": ["$type", "unknown"]},
            "url_length": {"$ifNull": ["$url_length", 0]}
        }},
        {"$project": {
            "type": 1,
            "bucket": {
                "$concat": [
                    {"$toString": {"$multiply": [{"$floor": {"$divide": ["$url_length", 50]}}, 50]}},
                    "-",
                    {"$toString": {"$add": [{"$multiply": [{"$floor": {"$divide": ["$url_length", 50]}}, 50]}, 49]}}
                ]
            }
        }},
        {"$group": {"_id": {"type": "$type", "bucket": "$bucket"}, "value": {"$sum": 1}}}
    ]
    results = list(col.aggregate(pipeline))
    db['url_length_by_type'].drop()
    if results:
        db['url_length_by_type'].insert_many(results)
    print("Sample url_length_by_type:")
    for doc in db['url_length_by_type'].find().limit(30):
        pprint.pprint(doc)

def main():
    mr_counts_by_type()
    mr_malicious_domains()
    mr_malicious_tld_counts()
    mr_url_length_by_type()
    mr_threat_scores()
    mr_country_counts()
    print("All aggregation jobs completed.")

if __name__ == '__main__':
    main()
