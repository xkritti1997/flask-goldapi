# from flask import Flask, json, jsonify, request, make_response
import jwt
import datetime
from functools import wraps

# # for make and decode secretkey
# from base64 import b64encode
# from os import urandom
# random_byte = urandom(16)
# secret_key = b64encode(random_byte).decode('utf-8')


# app = Flask(__name__)


# def token_requried(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = request.args.get('token')

#         if not token:
#             return jsonify({'mesage': 'Token is missing!'}), 403

#         try:
#             data = jwt.decode(
#                 token, app.config['SECRET_KEY'], algorithms=["HS256"])

#         except:
#             return jsonify({'message': 'Token is invalid!'}), 403

#         return f(*args, **kwargs)
#     return decorated


# @app.route("/")
# def hello_world():
#     return "<p>Hello, World!</p>"


# @app.route("/login")
# def login():
#     auth = request.authorization

#     if auth and auth.password == 'o':
#         token = jwt.encode({'user': auth.username, 'exp': datetime.datetime.utcnow(
#         )+datetime.timedelta(seconds=30)}, app.config['SECRET_KEY'], algorithm='HS256')
#         print(token)
#         return jsonify({"token": token})

#     return make_response('Could verify!', 401, {'WWW-Authenticate': 'Basic realm = "Login Required"'})


# @app.route("/register",methods =['POST'])
# def register():
#     return "<p>Hello, register!</p>"


# @app.route('/user')
# @token_requried
# def user():
#     return jsonify({'messgae': 'This is only avalible for people'})


# if __name__ == '__main__':
#     app.run(debug=True)

# import os
# from flask import Flask , render_template
# from src.database import DB
# from src.routes import route

# project_root = os.path.dirname(__file__)
# template_path = os.path.join(project_root, 'src/templates')

# app = Flask(__name__,template_folder=template_path)

# DB.init()

# app.register_blueprint(route.get_blueprint())

# if __name__ == "__main__":
#     app.run(debug="true")

from logging import error
import flask
from flask import json, request, jsonify, session
from pymongo.errors import BulkWriteError
from pymongo import MongoClient
from bson.json_util import dumps
from markupsafe import escape
from base64 import b64encode, encode
from os import urandom
import hashlib
from flask_cors import CORS

app = flask.Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'secret_key'

client = MongoClient('localhost', 27017)
db_rider = client.rider
db_user = client.user
collection_rider = db_rider['info']
collection_user = db_user['info']

user_data = [

]

rider_data = [
    {'_id': 0, 'email': "rider0@example.com", 'password': "rider0example"}
]


@app.route('/')
def main():
    # json_data = flask.request.json
    # value = json_dataz
    return flask.jsonify(message="Hello this is api")


@app.route("/all")
def home():
    # connect to mongodb
    # temp_rider = dumps(collection_rider.find())
    # temp_user = dumps(collection_user.find())
    # # return "rider data : " + temp_rider + '\n'+'user data : '+temp_user

    temp_rider = user_data
    temp_user = rider_data
    print(temp_rider)
    print(temp_user)
    return flask.jsonify(message="Show all data success", rider=temp_rider, user=temp_user)


@app.route("/user_register", methods=['POST'])
def user_register():
    json_data = flask.request.json
    email = json_data["email"]
    password = json_data["password"]
    username = json_data['username']
    print("password", password)
    if request.method == 'POST':
        # collection_user.insert_one({'email': 'dummy', 'password': 'password'})
        # return flask.jsonify(message="User register success")
        i = len(user_data)
        j = str(i)
        random_byte = urandom(8)
        salt = b64encode(random_byte).decode('utf-8')
        pwhws = hashlib.sha256(password.encode()+salt.encode())
        token = jwt.encode({'user': username, 'exp': datetime.datetime.utcnow(
        )+datetime.timedelta(seconds=30)}, app.config['SECRET_KEY'], algorithm='HS256')
        user_data.append(
            {'_id': i, "token": token, "username": username, 'email': email, 'password': pwhws.hexdigest(), "salt": salt})
        return flask.jsonify(token=token)
    else:
        return 'methods POST only'


@app.route("/rider_register", methods=['POST'])
def rider_register():
    if request.method == 'POST':
        # collection_rider.insert_one({'email': 'dummy', 'password': 'password'})
        # return flask.jsonify(message="Rider register success")
        i = len(rider_data)
        j = str(i)
        rider_data.append({'_id': i, 'email': "rider"+j +
                           "@example.com", 'password': ".........."})
        return flask.jsonify(message="rider register success")

    else:
        return 'methods POST only'


@app.route('/login/<string:member>', methods=['POST'])
def login(member):
    register_status = False
    if member == 'user':
        json_data = flask.request.json
        email = json_data["email"]
        password = json_data["password"]

        # return flask.jsonify(json_data)
        try:
            i = 0
            temp = len(user_data)
            while(i < temp):
                print(i)
                temp_data = user_data[i]
                if email == temp_data['email']:
                    register_status = True
                    req_password = hashlib.sha256(
                        password.encode() + temp_data['salt'].encode())
                    print(req_password.hexdigest())
                    print(temp_data['password'])
                    if req_password.hexdigest() == temp_data['password']:
                        print('yess')
                        return flask.jsonify(message="login sucess")
                i += 1
            if register_status == True:
                return flask.jsonify(message="Wrong Password")
            if register_status == False:
                return flask.jsonify(message="Not Register")

        except:
            print(error)
        print(json_data)
        return 'userlogin : '+str(json_data["email"])

    # elif member == 'rider':
    #     return 'riderlogin'
    else:
        return "Wrong api route call !"


@app.route("/del_all/<string:title>")
def del_all(title):
    myquery = {"email": title}
    collection_rider.delete_one(myquery)
    collection_user.delete_one(myquery)

    return flask.jsonify(message="Delete all success")


@app.route("/add_many")
def add_many():
    try:
        todo_many = db.todos.insert_many([
            {'_id': 1, 'title': "todo title one ", 'body': "todo body one "},
            {'_id': 8, 'title': "todo title two", 'body': "todo body two"},
            {'_id': 2, 'title': "todo title three", 'body': "todo body three"},
            {'_id': 9, 'title': "todo title four", 'body': "todo body four"},
            {'_id': 10, 'title': "todo title five", 'body': "todo body five"},
            {'_id': 5, 'title': "todo title six", 'body': "todo body six"},
        ], ordered=False)
    except BulkWriteError as e:
        return flask.jsonify(message="duplicates encountered and ignored",
                             details=e.details,
                             inserted=e.details['nInserted'],
                             duplicates=[x['op'] for x in e.details['writeErrors']])

    return flask.jsonify(message="success", insertedIds=todo_many.inserted_ids)


if __name__ == "__main__":
    app.run(debug="true")
