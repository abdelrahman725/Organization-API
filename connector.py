# This file is used only to connecct to MongDb and Redis and creates a client for those connection

from pymongo import MongoClient
from redis import Redis

# connect to MongoDB
client = MongoClient("mongodb://mongo:27017/")
db = client["mydatabase"]

redis_client = Redis(host="redis", port=6379, db=0)