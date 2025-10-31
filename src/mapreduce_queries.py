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

SAMPLE_SIZE = 100000 
sampled_ids = [doc['_id'] for doc in col.aggregate([{'$sample': {'size': SAMPLE_SIZE}}, {'$project': {'_id': 1}}])]
sampled_col = col.find({'_id': {'$in': sampled_ids}})
col.create_index('type')
col.create_index('domain')
col.create_index('tld')
col.create_index('country')
col.create_index('url_length')

def mr_counts_by_type():

    map_func = "function() { emit(this.type, 1); }"
    reduce_func = "function(key, values) { return Array.sum(values); }"
    db['counts_by_type'].drop()
    result = col.map_reduce(map_func, reduce_func, out='counts_by_type', query={'_id': {'$in': sampled_ids}})
    print("Top types:")
    for doc in db['counts_by_type'].find().sort('value', -1).limit(20):
        pprint.pprint(doc)

def mr_malicious_domains():
    map_func = "function() { if (this.type !== 'benign') { emit(this.domain, 1); } }"
    reduce_func = "function(key, values) { return Array.sum(values); }"
    db['mal_domains'].drop()
    result = col.map_reduce(map_func, reduce_func, out='mal_domains', query={'_id': {'$in': sampled_ids}})
    print("Top malicious domains:")
    for doc in db['mal_domains'].find().sort('value', -1).limit(20):
        pprint.pprint(doc)

def mr_malicious_tld_counts():
    map_func = "function() { if (this.type !== 'benign') { emit(this.tld ? this.tld : 'unknown', 1); } }"
    reduce_func = "function(key, values) { return Array.sum(values); }"
    db['malicious_tld_counts'].drop()
    result = col.map_reduce(map_func, reduce_func, out='malicious_tld_counts', query={'_id': {'$in': sampled_ids}})
    for doc in db['malicious_tld_counts'].find().sort('value', -1).limit(50):
        pprint.pprint(doc)

def mr_threat_scores():
    map_func = "function() { if (typeof this.threat_score === 'number') { emit(this.type, {sum: this.threat_score, max: this.threat_score, count: 1}); } }"
    reduce_func = "function(key, values) { var result = {sum: 0, max: -Infinity, count: 0}; values.forEach(function(v) { result.sum += v.sum; if (v.max > result.max) result.max = v.max; result.count += v.count; }); return result; }"
    finalize_func = "function(key, value) { value.avg = value.count > 0 ? value.sum / value.count : 0; return value; }"
    db['threat_scores'].drop()
    result = col.map_reduce(map_func, reduce_func, out='threat_scores', finalize=finalize_func, query={'_id': {'$in': sampled_ids}})
    print("Threat scores by type:")
    for doc in db['threat_scores'].find():
        pprint.pprint(doc)

def mr_country_counts():
    map_func = "function() { if (this.type !== 'benign') { emit(this.country ? this.country : 'Unknown', 1); } }"
    reduce_func = "function(key, values) { return Array.sum(values); }"
    db['country_counts'].drop()
    result = col.map_reduce(map_func, reduce_func, out='country_counts', query={'_id': {'$in': sampled_ids}})
    country_data = []
    other_count = 0
    for result in db['country_counts'].find():
        country_name = result['_id']
        count = result['value']
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
    if other_count > 0:
        country_data.append({
            "_id": "OTHER",
            "country_name": "Other/Unknown",
            "count": other_count
        })
    db['country_counts'].drop()
    if country_data:
        db['country_counts'].insert_many(country_data)
    print("Malicious URLs by country:")
    for doc in db['country_counts'].find().sort('count', -1).limit(10):
        pprint.pprint(doc)

def mr_url_length_by_type():
    map_func = "function() { var type = this.type ? this.type : 'unknown'; var url_length = this.url_length ? this.url_length : 0; var bucket_start = Math.floor(url_length / 50) * 50; var bucket_end = bucket_start + 49; var bucket = bucket_start + '-' + bucket_end; emit({type: type, bucket: bucket}, 1); }"
    reduce_func = "function(key, values) { return Array.sum(values); }"
    db['url_length_by_type'].drop()
    result = col.map_reduce(map_func, reduce_func, out='url_length_by_type', query={'_id': {'$in': sampled_ids}})
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
