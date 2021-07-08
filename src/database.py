
import pymongo
class DB(object):
     URI = "mongodb://127.0.0.1:27017"
     
     @staticmethod
     def init():
         client = pymongo.MongoClient(DB.URI)
         DB.DATABASE = client['list-name']

     @staticmethod
     def insertName(collection, data):
         DB.DATABASE[collection].insert(data)

     @staticmethod
     def listName(collection, query):
         return DB.DATABASE[collection].find()