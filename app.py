import re
from flask import Flask, jsonify, make_response, request
from pymongo import MongoClient
from bson import ObjectId
from bson import json_util
from flask_cors import CORS
import math
import datetime
from functools import wraps
import json
from os import environ as env
from typing import Dict
from flask_cors import cross_origin
import jwt
import json
from os import environ as env
import bcrypt
from bson import json_util
import os
from flask_cors import CORS
import base64





from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, render_template, session, url_for



app = Flask(__name__)
CORS(app)

allowed_origins = ['http://localhost:4200','http://localhost:50083' ]
CORS(app, origins=allowed_origins)



app.config['SECRET_KEY'] = 'my secret'

def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        print(request.headers)  # print headers
        if not token:
            return jsonify( {'message' : 'Token is missing'} ), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except: 
            return jsonify( {'message' : 'Token is invalid'}), 401
        
        bl_token = blacklist.find_one( {"token":token} )
        if bl_token is not None:
            return make_response( jsonify( {'message' : 'Token has been cancelled'} ), 401)
        return func(*args, **kwargs)
    return jwt_required_wrapper 


def admin_required(func):
    @wraps(func)
    def admin_required_wrapper(*args, **kwargs):
        token = request.headers['x-access-token']
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if data["admin"]:
            return func(*args, **kwargs)
        else:
            return make_response(jsonify( {'message' : 'Admin access required'}), 401)
    return admin_required_wrapper


client = MongoClient( "mongodb://127.0.0.1:27017" )
db = client.HikingApp # select the database
trails = db.trails # select the collection
events = db.events
users = db.users
blacklist = db.blacklist
wishlist = db.wishlist

@app.route("/api/v1.0/admin-required", methods=["GET"])
def admin_required_():
    token = request.headers['x-access-token']
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    if data["admin"]:
        response = {'success': True}
    else:
        response = make_response(jsonify({'message': 'Admin access required'}), 401)

    return jsonify(response)




@app.route("/api/v1.0/trails/pages", methods=["GET"])
def fetch_trail_pages_count():
    search = request.args.get('search')
    location = request.args.get('location')
    rating = request.args.get('rating')

    trailFilters = {}

    if (search):
        trailFilters['name'] = {'$regex' : search}
    if (location):
        trailFilters['formatted_address'] = {'$regex' : location}
    if (rating and rating != 'all'):
        trailFilters['rating'] = rating

    trailsCount = trails.count_documents(trailFilters)

    return make_response( jsonify({'totalPages': math.ceil(trailsCount / 10)}), 200 )


@app.route("/api/v1.0/trails", methods=["GET"])


def show_all_trails():

    search = request.args.get('search')
    location = request.args.get('location')
    rating = request.args.get('rating')


    trailFilters = {}

    if (search):
        trailFilters['name'] = {'$regex' : search} 
    if (location):
        trailFilters['formatted_address'] = {'$regex' : location}
    if (rating and rating != 'all'):
        trailFilters['rating'] = rating

    print(trailFilters)


    page_num, page_size = 1, 10
    if request.args.get("pn"):
        page_num = int(request.args.get('pn'))
    if request.args.get("ps"):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))
    
    data_to_return = []
    for trail in trails.find(trailFilters).skip(page_start).limit(page_size):
        trail["_id"] = str(trail["_id"])
        for review in trail["reviews"]:
            review["_id"] = str(review["_id"])
        data_to_return.append(trail) 

    return make_response( jsonify( data_to_return), 200 )


@app.route("/api/v1.0/trails/<string:id>", methods=["GET"])

def show_one_trail(id):
    
    trail = trails.find_one( {"_id" : ObjectId(id) } )
    if trail is not None:
        trail["_id"] = str(trail["_id"])
        for review in trail["reviews"]:
            review["_id"] = str(review["_id"])
        return make_response( jsonify( [trail] ), 200 )
    else: 
        return make_response( jsonify(  { "error" : "Invalid trail ID" } ), 404 )

@app.route("/api/v1.0/trails", methods = ["POST"])
@jwt_required
@admin_required
def add_new_trail():

    # if requires_scope("add:trail"):
            
    

        if "name" in request.form and "formatted_address" in request.form and "rating" in request.form:
            new_trail = {
                "name": request.form["name"],
                "formatted_address": request.form["formatted_address"],
                "rating":request.form["rating"],
                "place_id":request.form["place_id"],
                "geometry": {
                    "location": {
                        "lat": request.form["lat"],
                        "lng": request.form["lng"]
                    }
                },
                "reviews": [],
                "photos": [
                    {
                    "html_attributions": [
                        request.form["html_attributions"]
                    ]
                    }
                ]

            }
            new_trail_id = trails.insert_one(new_trail)
            new_trail_link = "http://localhost:5000/api/v1.0/trails/" \
    +          str(new_trail_id.inserted_id)
            return make_response( jsonify(  { "url" : new_trail_link } ), 201 )
        else:
            return make_response( jsonify( { "error" : "Missing form data" } ), 404 )
    # raise AuthError({
    #     "code": "Unauthorized",
    #     "description": "You don't have access to this resource"
    # }, 403)
        



@app.route("/api/v1.0/trails/<string:id>", methods = ["PUT"])
@jwt_required
@admin_required
def edit_trail(id):

    if "name" in request.form and "formatted_address" in request.form and "rating" in request.form:
        result = trails.update_one(
            { "_id" : ObjectId(id) }, 
            {
                "$set" : { 
                     "name": request.form["name"],
                     "formatted_address": request.form["formatted_address"],
                     "rating":request.form["rating"],
                     "place_id":request.form["place_id"],
                     "geometry": {
                        "location": {
                            "lat": request.form["lat"],
                            "lng": request.form["lng"]
                        }
                    },
                    "photos": [
                        {
                        "html_attributions": [
                            request.form["html_attributions"]
                        ]
                        }
                    ]
                }
            } 
        )
        if result.matched_count == 1:
            edited_trail_link = "http://localhost:5000/api/v1.0/trails/" + id
            return make_response( jsonify( { "url":edited_trail_link } ), 200)
        else: 
            return make_response( jsonify( { "error":"Invalid trail ID" } ), 404 )
    else:
        return make_response( jsonify( { "error" : "Missing form data" } ), 404 )

@app.route("/api/v1.0/trails/<string:id>", methods= ["DELETE"])
@jwt_required
@admin_required
def delete_trail(id):
    result = trails.delete_one( { "_id" : ObjectId(id) } )
    if result.deleted_count == 1:
        return make_response( jsonify( {} ), 204 )
    else:
         return make_response( jsonify( { "error" : "Invalid trail ID" } ), 404 )

@app.route("/api/v1.0/trails/<string:id>/reviews", methods = ["POST"])
@jwt_required
def add_new_review(id):
    new_review = {
        "_id" : ObjectId(),
        "username" : request.form["username"],
        "comment" : request.form["comment"],
        "stars" : request.form["stars"]
    }
    trails.update_one( 
        { "_id" : ObjectId(id) }, 
        { 
            "$push": { "reviews" : new_review }
        }
    )
    new_review_link = "http://localhost:5000/api/v1.0/trails/" + id + \
        "/reviews/" + str(new_review['_id'])
    return make_response( jsonify( { "url" : new_review_link } ), 201 )

@app.route("/api/v1.0/trails/<string:id>/reviews", methods = ["GET"])
def fetch_all_reviews(id):
    search = request.args.get('search')

    print(search)

    reviewsFilters = {"_id" : ObjectId(id)}

    page_num, page_size = 1, 10
    if request.args.get("pn"):
        page_num = int(request.args.get('pn'))
    if request.args.get("ps"):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))
    

    data_to_return = []
    trail = trails.find_one(
        reviewsFilters, { "reviews" : 1, "_id" : 0 } 
    )
    if (trail):
        for review in trail["reviews"]:
            review["_id"] = str(review["_id"])
            if (search):
                if (re.search(search, review['comment'])):    
                    data_to_return.append(review)
            else:
                data_to_return.append(review)
    return make_response( jsonify( data_to_return ), 200 )

@app.route("/api/v1.0/trails/<string:id>/reviews/<string:review_id>", methods = ["GET"])
def fetch_one_review(id, review_id):
    trail = trails.find_one(
        { "reviews._id" : ObjectId(review_id) }, 
        { "_id" : 0, "reviews.$" : 1} 
    )
    if trail is None:
        return make_response( jsonify( { "error" : "Invalid trail ID or review ID" } ), 404 )
    else: 
        trail["reviews"][0]["_id"] = str(trail["reviews"][0]["_id"])
        return make_response( jsonify( trail["reviews"][0] ), 200 )

@app.route("/api/v1.0/trails/<string:id>/reviews/<string:review_id>", methods = ["PUT"])
@admin_required
@jwt_required
def edit_review(id, review_id):
    edited_review = {
        "reviews.$.username" : request.form["username"],
        "reviews.$.comment" : request.form["comment"],
        "reviews.$.stars" : request.form['stars']
    }
    trails.update_one(
        { "reviews._id" : ObjectId(review_id) },
        { "$set" : edited_review }
    )
    edit_review_url = "http://localhost:5000/api/v1.0/trails/" + id + \
        "/reviews/" + review_id
    return make_response( jsonify( { "url" : edit_review_url } ), 200)    

@app.route("/api/v1.0/trails/<string:id>/reviews/<string:review_id>", methods = ["DELETE"])
@jwt_required
@admin_required
def delete_review(id, review_id):
    trails.update_one(
        { "_id" : ObjectId(id) },
        { "$pull" : { "reviews" : { "_id" : ObjectId(review_id) } } }
    )
    return make_response( jsonify( {} ), 204)


@app.route("/api/v1.0/events", methods = ["POST"])
@jwt_required
@admin_required
def add_new_event():
    if "event_name" in request.form and "formatted_address" in request.form and "description" in request.form and "event_date" in request.form and "event_time" in request.form and "event_difficulty" in request.form and "event_duration" in request.form:
        new_event = {
            "event_name": request.form["event_name"],
            "description": request.form["description"],
            "formatted_address": request.form["formatted_address"],
            "event_date":request.form["event_date"],
            "event_time":request.form["event_time"],
            "event_difficulty":request.form["event_difficulty"],
            "event_duration":request.form["event_duration"],
            "dog_friendly":request.form["dog_friendly"],
            'image':request.form["image"],
            "discussions": []


        }
        new_event_id = events.insert_one(new_event)
        new_event_link = "http://localhost:5000/api/v1.0/events/" \
 +          str(new_event_id.inserted_id)
        return make_response( jsonify(  { "url" : new_event_link } ), 201 )
    else:
        return make_response( jsonify( { "error" : "Missing form data" } ), 404 )


@app.route("/api/v1.0/events/pages", methods=["GET"])
def fetch_events_pages_count():
    search = request.args.get('search')
    location = request.args.get('location')
    difficulty = request.args.get('difficulty')

    eventFilters = {}

    if (search):
        eventFilters['event_name'] = {'$regex' : search}
    if (location):
        eventFilters['formatted_address'] = {'$regex' : location}
    if (difficulty and difficulty != 'all'):
        eventFilters['event_difficulty'] = difficulty

    eventsCount = events.count_documents(eventFilters)

    return make_response( jsonify({'totalPages': math.ceil(eventsCount / 10)}), 200 )


@app.route("/api/v1.0/events", methods=["GET"])
def show_all_events():
    search = request.args.get('search')
    location = request.args.get('location')
    difficulty = request.args.get('difficulty')

    eventFilters = {}

    if (search):
        eventFilters['event_name'] = {'$regex' : search}
    if (location):
        eventFilters['formatted_address'] = {'$regex' : location}
    if (difficulty and difficulty != 'all'):
        eventFilters['event_difficulty'] = difficulty

    print(eventFilters)

    page_num, page_size = 1, 10
    if request.args.get("pn"):
        page_num = int(request.args.get('pn'))
    if request.args.get("ps"):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))
    
    data_to_return = []
    for event in events.find(eventFilters).skip(page_start).limit(page_size):
        event["_id"] = str(event["_id"])
        for discussion in event["discussions"]:
            discussion["_id"] = str(discussion["_id"])
            for reply in discussion["replies"]:
                reply["_rid"] = str(reply["_rid"])
        data_to_return.append(event) 

    return make_response( jsonify( data_to_return), 200 )


@app.route("/api/v1.0/events/<string:id>", methods=["GET"])
def show_one_event(id):
    event = events.find_one( {"_id" : ObjectId(id) } )
    if event is not None:
        event["_id"] = str(event["_id"])
        for discussion in event["discussions"]:
            discussion["_id"] = str(discussion["_id"])
            for reply in discussion["replies"]:
                reply["_rid"] = str(reply["_rid"])
        return make_response( jsonify( [event] ), 200 )
    else: 
        return make_response( jsonify(  { "error" : "Invalid event ID" } ), 404 )

@app.route("/api/v1.0/events/<string:id>", methods = ["PUT"])
@admin_required
@jwt_required
def edit_event(id):
    if "event_name" in request.form and "formatted_address" in request.form and "description" in request.form and "event_date" in request.form and "event_time" in request.form and "event_difficulty" in request.form and "event_duration" in request.form:
        result = events.update_one(
            { "_id" : ObjectId(id) }, 
            {
                "$set" : { 
                    "event_name": request.form["event_name"],
                    "description": request.form["description"],
                    "formatted_address": request.form["formatted_address"],
                    "event_date":request.form["event_date"],
                    "event_time":request.form["event_time"],
                    "event_difficulty":request.form["event_difficulty"],
                    "event_duration":request.form["event_duration"],
                    "dog_friendly":request.form["event_duration"],
                    'image':request.form["image"],
                }
            } 
        )
        if result.matched_count == 1:
            edited_event_link = "http://localhost:5000/api/v1.0/events/" + id
            return make_response( jsonify( { "url":edited_event_link } ), 200)
        else: 
            return make_response( jsonify( { "error":"Invalid event ID" } ), 404 )
    else: 
        return make_response( jsonify( { "error" : "Missing form data" } ), 404 )

@app.route("/api/v1.0/events/<string:id>/event_admin", methods= ["DELETE"])
@jwt_required
@admin_required
def delete_event(id):
    result = events.delete_one( { "_id" : ObjectId(id) } )
    if result.deleted_count == 1:
        return make_response( jsonify( {} ), 204 )
    else:
         return make_response( jsonify( { "error" : "Invalid event ID" } ), 404 )

@app.route("/api/v1.0/events/<string:id>/discussions", methods = ["POST"])
@jwt_required
def add_new_discussion(id):
    new_discussion = {
        "_id" : ObjectId(),
        "username" : request.form["username"],
        "comment" : request.form["comment"],
        "replies": []

    }
    events.update_one( 
        { "_id" : ObjectId(id) }, 
        { 
            "$push": { "discussions" : new_discussion }
        }
    )
    new_discussion_link = "http://localhost:5000/api/v1.0/events/" + id + \
        "/discussions/" + str(new_discussion['_id'])
    return make_response( jsonify( { "url" : new_discussion_link } ), 201 )





@app.route("/api/v1.0/events/<string:id>/discussions", methods = ["GET"])
def fetch_all_discussions(id):
    postorpre = request.args.get('postorpre')

    print(postorpre)

    discussionsFilters = {"_id" : ObjectId(id)}

    page_num, page_size = 1, 10
    if request.args.get("pn"):
        page_num = int(request.args.get('pn'))
    if request.args.get("ps"):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))
    

    data_to_return = []
    event = events.find_one(
        discussionsFilters, { "discussions" : 1, "_id" : 0 } 
    )
    if (event):
        for discussion in event["discussions"]:
            discussion["_id"] = str(discussion["_id"])
            for reply in discussion["replies"]:
                reply["_rid"] = str(reply["_rid"])
            if (postorpre):
                if (re.search(postorpre, discussion['comment'])):    
                    data_to_return.append(discussion)
            else:
                data_to_return.append(discussion)
    return make_response( jsonify( data_to_return ), 200 )

@app.route("/api/v1.0/events/<string:id>/discussions/<string:discussion_id>", methods = ["GET"])
def fetch_one_discussion(id, discussion_id):
    
    
    event = events.find_one(
        
        { "discussions._id" : ObjectId(discussion_id) }, 
        { "_id" : 0, "discussions.$" : 1} 
    )
    if (event):
        for discussion in event["discussions"]:
            discussion["_id"] = str(discussion["_id"])
            for reply in discussion["replies"]:
                reply["_rid"] = str(reply["_rid"])
    if event is None:
        return make_response( jsonify( { "error" : "Invalid event ID or discussions ID" } ), 404 )
    else: 
        event["discussions"][0]["_id"] = str(event["discussions"][0]["_id"])
        return make_response( jsonify( event[["discussions"][0]] ), 200 )

@app.route("/api/v1.0/events/<string:id>/discussions/<string:discussion_id>", methods = ["PUT"])
@admin_required
@jwt_required
def edit_discussion(id, discussion_id):
    edited_discussion = {
        "discussions.$.username" : request.form["username"],
        "discussions.$.comment" : request.form["comment"],
        

    }
    events.update_one(
        { "discussions._id" : ObjectId(discussion_id) },
        { "$set" : edited_discussion }
    )
    edit_discussion_url = "http://localhost:5000/api/v1.0/events/" + id + \
        "/discussions/" + discussion_id
    return make_response( jsonify( { "url" : edit_discussion_url } ), 200)    

@app.route("/api/v1.0/events/<string:id>/discussions/<string:discussion_id>", methods = ["DELETE"])
@jwt_required
@admin_required
def delete_discussion(id, discussion_id):
    events.update_one(
        { "_id" : ObjectId(id) },
        { "$pull" : { "discussions" : { "_id" : ObjectId(discussion_id) } } }
    )
    return make_response( jsonify( {} ), 204)

@app.route("/api/v1.0/events/<string:id>/discussions/<string:discussion_id>/replies", methods = ["POST"])
@jwt_required
def add_new_reply(id, discussion_id):
    new_reply = {
        "_rid" : ObjectId(),
        "username" : request.form["username"],
        "comment" : request.form["comment"]
        

    }
    events.update_one( 
        { "discussions._id" : ObjectId(discussion_id)
        }, 
        
        { 
            "$push": {  "discussions.$.replies" : new_reply }
        }
    )
    new_reply_link = "http://localhost:5000/api/v1.0/events/" + id + \
        "/discussions/" + discussion_id + "/replies/" + str(new_reply['_rid'])
    return make_response( jsonify( { "url" : new_reply_link } ), 201 )


@app.route("/api/v1.0/events/<string:id>/discussions/<string:discussion_id>/replies", methods=["GET"])
def fetch_all_replies(id, discussion_id):
    event = events.find_one({"_id": ObjectId(id)})
    if event:
        for discussion in event["discussions"]:
            if discussion["_id"] == ObjectId(discussion_id):
                discussion["_id"] = str(discussion["_id"])
                for reply in discussion["replies"]:
                    reply["_rid"] = str(reply["_rid"])
                return make_response(jsonify(discussion["replies"]), 200)
        return make_response(jsonify({"message": "Discussion not found"}), 404)
    return make_response(jsonify({"message": "Event not found"}), 404)




@app.route("/api/v1.0/login", methods=["GET"])
def login():
    auth = request.authorization
    if auth:
        user = users.find_one( {'username':auth.username } )
        if user is not None:
            if bcrypt.checkpw( bytes( auth.password, 'UTF-8'), user["password"] ):
                token = jwt.encode( {
                        'username' : auth.username,
                        'admin' : user["admin"],
                        'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=100)
                }, app.config['SECRET_KEY'])
                print(token )
                
                return make_response( jsonify ( { 'token': token} ), 200)
            else:
                return make_response( jsonify( {'message':'Bad password'} ), 401)
        else:
            return make_response( jsonify( {'message':'username'} ), 401)

    return make_response( jsonify( {'message':'Authentication required'} ), 401) 





   


@app.route('/api/v1.0/logout', methods=["GET"])
@jwt_required

def logout():
    token = request.headers['x-access-token']
    blacklist.insert_one( {"token":token} )
    return make_response(jsonify( {'message' : 'Logout successful'} ), 200)

@app.route("/api/v1.0/register", methods = ["POST"])

def add_new_user():
    
    password = request.form.get("password")
    username = request.form.get('username')
    if not is_username_unique(username):
        return "Username already exists"

    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    if "name" in request.form and "username" in request.form and password:
        new_user = {
            'name': request.form["name"],
            'username': username,
            'password': hashed_password,
            'admin': False,
            'favorites': [],
            'fav_events': []
        }
        new_user_id = users.insert_one(new_user)
        new_user_link = "http://localhost:5000/api/v1.0/users/" \
    + str(new_user_id.inserted_id)
        return make_response( jsonify( {"url": new_user_link} ), 201)
    else:
        return make_response( jsonify({"error": "Missing form data"}), 404)
    

@app.route("/api/v1.0/is_username_unique", methods = ["GET"])
def is_username_unique(requested_username):
    requested_username = request.form.get('username')

    user = users.find_one({'username': requested_username})
    if user:
        return False  # username already exists
    else:
        return True



def logout():
    token = request.headers['x-access-token']
    blacklist.insert_one( {"token":token} )
    return make_response(jsonify( {'message' : 'Logout successful'} ), 200)
    

@app.route("/api/v1.0/users/favorites/trails", methods=["POST"])
@jwt_required
def add_favorite_trail():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    print(request.headers)  # print headers
    if not token:
        return jsonify( {'message' : 'Token is missing'} ), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: 
        return jsonify( {'message' : 'Token is invalid'}), 401

    user = users.find_one({'username': data['username']})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)

    trail_id = request.form.get('trail_id')
    if not trail_id:
        return make_response(jsonify({'message': 'Trail ID missing'}), 400)

    if trail_id in user.get('favorites', []):
        return make_response(jsonify({'message': 'Trail already in favorites'}), 400)

    user['favorites'] = user.get('favorites', []) + [trail_id]
    users.replace_one({'_id': user['_id']}, user)

    return make_response(jsonify({'message': 'Trail added to favorites'}), 200)

@app.route("/api/v1.0/users/favorites/trails/<string:trail_id>", methods=["DELETE"])
@jwt_required
def delete_favorite_trail(trail_id):
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    print(request.headers)  # print headers
    if not token:
        return jsonify( {'message' : 'Token is missing'} ), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: 
        return jsonify( {'message' : 'Token is invalid'}), 401

    user = users.find_one({'username': data['username']})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)

   
    if not trail_id:
        return make_response(jsonify({'message': 'Trail ID missing'}), 400)

    favorites = user.get('favorites', [])
    if trail_id not in favorites:
        return make_response(jsonify({'message': 'Trail not found in favorites'}), 400)

    favorites.remove(trail_id)
    user['favorites'] = favorites
    users.replace_one({'_id': user['_id']}, user)

    return make_response(jsonify({'message': 'Trail removed favorites'}), 200)



    

@app.route("/api/v1.0/users/favorites/trails", methods=['OPTIONS'])
def options_favorites():

    headers = {
        'Access-Control-Allow-Origin': 'http://localhost:4200',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }

    return '', 204, headers



@app.route("/api/v1.0/users/favorites/trails", methods=["GET"])
def get_favorite_trail():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    print(request.headers)  # print headers
    if not token:
        return jsonify( {'message' : 'Token is missing'} ), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: 
        return jsonify( {'message' : 'Token is invalid'}), 401

    user = users.find_one({'username': data['username']})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)
    
    favorites = user['favorites']
    if not favorites:
        return make_response(jsonify({'message': 'favorites is empty'}), 400)

    trail_list = []
    for trail_id in favorites:
        if not trail_id:
            continue

        trail = trails.find_one({'_id': ObjectId(trail_id)})
        if not trail:
            continue

        trail['_id'] = str(trail['_id'])
        for review in trail.get('reviews', []):
            review['_id'] = str(review['_id'])
        trail_list.append(trail)

    return make_response(jsonify(trail_list), 200)







@app.route("/api/v1.0/profile", methods=["GET"])
def get_user():
    # Get the access token from the header
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token'] 
    decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    
    username = (decoded_token['username'])
    user = users.find_one ( {'username': username } )
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)
    
    jsonified_user = json_util.dumps([user])
  

    return make_response(jsonified_user, 200)

@app.route("/api/v1.0/users/favorites/events", methods=["POST"])
@jwt_required
def add_favorite_event():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    print(request.headers)  # print headers
    if not token:
        return jsonify( {'message' : 'Token is missing'} ), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: 
        return jsonify( {'message' : 'Token is invalid'}), 401

    user = users.find_one({'username': data['username']})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)

    event_id = request.form.get('event_id')
    if not event_id:
        return make_response(jsonify({'message': 'Event ID missing'}), 400)

    if event_id in user.get('fav_events', []):
        return make_response(jsonify({'message': 'Event already in favorites'}), 400)

    user['fav_events'] = user.get('fav_events', []) + [event_id]
    users.replace_one({'_id': user['_id']}, user)

    return make_response(jsonify({'message': 'Event added to favorites'}), 200)

@app.route("/api/v1.0/users/favorites/events/<string:event_id>", methods=["DELETE"])

def delete_favorite_event(event_id):

    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    print(request.headers)  # print headers
    if not token:
        return jsonify( {'message' : 'Token is missing'} ), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: 
        return jsonify( {'message' : 'Token is invalid'}), 401

    user = users.find_one({'username': data['username']})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)

    
    if not event_id:
        return make_response(jsonify({'message': 'Event ID missing'}), 400)

    fav_events = user.get('fav_events', [])
    if event_id not in fav_events:
        return make_response(jsonify({'message': 'Event not found in favorites'}), 400)

    fav_events.remove(event_id)
    user['fav_events'] = fav_events
    users.replace_one({'_id': user['_id']}, user)

    return make_response(jsonify({'message': 'Event removed favorites'}), 200)



@app.route("/api/v1.0/users/favorites/events", methods=["GET"])
def get_favorite_event():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    print(request.headers)  # print headers
    if not token:
        return jsonify( {'message' : 'Token is missing'} ), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: 
        return jsonify( {'message' : 'Token is invalid'}), 401

    user = users.find_one({'username': data['username']})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)
    
    favorites = user['fav_events']
    if not favorites:
        return make_response(jsonify({'message': 'favorites is empty'}), 400)

    event_list = []
    for event_id in favorites:
        if not event_id:
            continue

        event = events.find_one({'_id': ObjectId(event_id)})
        if not event:
            continue

        event['_id'] = str(event['_id'])
        for discussion in event["discussions"]:
            discussion["_id"] = str(discussion["_id"])
            for reply in discussion["replies"]:
                reply["_rid"] = str(reply["_rid"])
        event_list.append(event)

    return make_response(jsonify(event_list), 200)


@app.route("/api/v1.0/users/steps", methods=["POST"])
@jwt_required
def post_steps():
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    print(request.headers)  # print headers
    if not token:
        return jsonify( {'message' : 'Token is missing'} ), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: 
        return jsonify( {'message' : 'Token is invalid'}), 401

    user = users.find_one({'username': data['username']})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)

    total_steps = user.get('total_steps', 0)

    print(request.form)
    new_steps = int(request.form.get('steps', 0))

    print (new_steps)
    total_steps += new_steps



    users.update_one({'username': data['username']}, {'$set': {'total_steps': total_steps}})


    
    print(f'Successfully updated user: {data["username"]}. Total steps: { total_steps}')

    return make_response(jsonify({'message': 'Steps added successfully', 'total_steps': total_steps}), 200)






@app.route("/api/v1.0/users/weeklysteps", methods=["GET"])
@jwt_required
def get_weekly_steps():
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    print(request.headers)  # print headers
    if not token:
        return jsonify( {'message' : 'Token is missing'} ), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: 
        return jsonify( {'message' : 'Token is invalid'}), 401

    user = users.find_one({'username': data['username']})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)
    
    now = datetime.datetime.now()
    monday_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0) - datetime.timedelta(days=now.weekday())
    if now == monday_midnight:
        users.update_one({'username': data['username']}, {'$set': {'total_steps': 0}})
        user['total_steps'] = 0

    return jsonify([{'username': data['username'], 'total_steps': user['total_steps']}]), 200

    



    

@app.route("/api/v1.0/users", methods=["GET"])
def get_users():
    search = request.args.get('search')


    userFilters = {}

    if (search):
        userFilters['username'] = {'$regex' : search}
    
    print(userFilters)

    page_num, page_size = 1, 10
    if request.args.get("pn"):
        page_num = int(request.args.get('pn'))
    if request.args.get("ps"):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))
    
    data_to_return = []
    for user in users.find(userFilters).skip(page_start).limit(page_size):
        user["_id"] = str(user["_id"])
        if 'password' in user:
            user['password'] = base64.b64encode(user['password']).decode('utf-8')
        data_to_return.append(user) 

    return make_response( jsonify( data_to_return), 200 )

@app.route("/api/v1.0/users/pages", methods=["GET"])
def fetch_users_pages_count():
    search = request.args.get('search')


    userFilters = {}

    if (search):
        userFilters['username'] = {'$regex' : search}
   

    usersCount = users.count_documents(userFilters)

    return make_response( jsonify({'totalPages': math.ceil(usersCount / 10)}), 200 )

@app.route("/api/v1.0/users/<string:id>", methods=["GET"])
def get_single_user(id):
    user = users.find_one( {"_id" : ObjectId(id) } )
    if user is not None:
        user["_id"] = str(user["_id"])
        if 'password' in user:
            user['password'] = base64.b64encode(user['password']).decode('utf-8')
        
        return make_response( jsonify( [user] ), 200 )
    else: 
        return make_response( jsonify(  { "error" : "Invalid event ID" } ), 404 )


@app.route("/api/v1.0/users/<string:id>/favs", methods=["GET"])
def get_user_favs(id):
    user = users.find_one({'_id': ObjectId(id)})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)
    
    favorites = user['fav_events']
    if not favorites:
        return make_response(jsonify({'message': 'favorites is empty'}), 400)

    event_list = []
    for event_id in favorites:
        if not event_id:
            continue

        event = events.find_one({'_id': ObjectId(event_id)})
        if not event:
            continue

        event['_id'] = str(event['_id'])
        for discussion in event["discussions"]:
            discussion["_id"] = str(discussion["_id"])
            for reply in discussion["replies"]:
                reply["_rid"] = str(reply["_rid"])
        event_list.append(event)

    return make_response(jsonify(event_list), 200)

@app.route("/api/v1.0/users/<string:id>/favorites", methods=["GET"])
def get_user_favorites(id):
    user = users.find_one({'_id': ObjectId(id)})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)
    
    favorites = user['favorites']
    if not favorites:
        return make_response(jsonify({'message': 'favorites is empty'}), 400)

    trail_list = []
    for trail_id in favorites:
        if not trail_id:
            continue

        trail = trails.find_one({'_id': ObjectId(trail_id)})
        if not trail:
            continue

        trail['_id'] = str(trail['_id'])
        for review in trail.get('reviews', []):
            review['_id'] = str(review['_id'])
        trail_list.append(trail)

    return make_response(jsonify(trail_list), 200)

@app.route("/api/v1.0/users/<string:id>", methods= ["DELETE"])
@jwt_required
@admin_required
def delete_user(id):
    result = users.delete_one( { "_id" : ObjectId(id) } )
    if result.deleted_count == 1:
        return make_response( jsonify( {} ), 204 )
    else:
         return make_response( jsonify( { "error" : "Invalid User ID" } ), 404 )
    

@app.route("/api/v1.0/users/<string:id>", methods = ["PUT"])

def edit_user(id):

    username = request.form.get('username')
    if not is_username_unique(username):
        return "Username already exists"

    if "name" in request.form and "username" in request.form:
        result = users.update_one(
            { "_id" : ObjectId(id) }, 
            {
                "$set" : { 
                     "name": request.form["name"],
                     "username": request.form["username"],
                     

                     
                    },
                    
                    
                
            } 
        )
        if result.matched_count == 1:
            edited_user_link = "http://localhost:5000/api/v1.0/trails/" + id
            return make_response( jsonify( { "url":edited_user_link } ), 200)
        else: 
            return make_response( jsonify( { "error":"Invalid user ID" } ), 404 )
    else:
        return make_response( jsonify( { "error" : "Missing form data" } ), 404 )
    

@app.route("/api/v1.0/profile/reset-password", methods=["POST"])
@jwt_required
def reset_password():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    print(request.headers)  # print headers
    if not token:
        return jsonify( {'message' : 'Token is missing'} ), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: 
        return jsonify( {'message' : 'Token is invalid'}), 401

    user = users.find_one({'username': data['username']})
    if not user:
        return make_response(jsonify({'message': 'User not found'}), 404)
    
    updated_password = request.form.get('updated_password')
    if not updated_password:
        return make_response(jsonify({'message': 'updated password missing'}), 400)
    
    updated_password_hash = bcrypt.hashpw(bytes(updated_password, 'utf-8'), bcrypt.gensalt())
    sucess = users.update_one({'_id': user['_id']}, {'$set': {'password': updated_password_hash}})
    
    if sucess.modified_count == 1:
        response = {'success': True, 'message': 'Password updated successfully'}
        return jsonify(response), 20
    else: 
        return make_response(jsonify({'message': 'Password not updated'}), 400)
    