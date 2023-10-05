import re
from flask import Flask, jsonify, make_response, request
from pymongo import MongoClient
from bson import ObjectId
from bson import json_util
from flask_cors import CORS
import math


app = Flask(__name__)
CORS(app)



client = MongoClient( "mongodb://127.0.0.1:27017" )
db = client.HikingApp # select the database
trails = db.trails # select the collection

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
def add_new_trail():
    if "name" in request.form and "formatted_address" in request.form and "rating" in request.form:
        new_trail = {
            "name": request.form["name"],
            "formatted_address": request.form["formatted_address"],
            "rating":request.form["rating"],
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


@app.route("/api/v1.0/trails/<string:id>", methods = ["PUT"])
def edit_trail(id):
    if "name" in request.form and "formatted_address" in request.form and "rating" in request.form:
        result = trails.update_one(
            { "_id" : ObjectId(id) }, 
            {
                "$set" : { 
                     "name": request.form["name"],
                     "formatted_address": request.form["formatted_address"],
                     "rating":request.form["rating"],
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

def delete_trail(id):
    result = trails.delete_one( { "_id" : ObjectId(id) } )
    if result.deleted_count == 1:
        return make_response( jsonify( {} ), 204 )
    else:
         return make_response( jsonify( { "error" : "Invalid trail ID" } ), 404 )

@app.route("/api/v1.0/trails/<string:id>/reviews", methods = ["POST"])
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
def delete_review(id, review_id):
    trails.update_one(
        { "_id" : ObjectId(id) },
        { "$pull" : { "reviews" : { "_id" : ObjectId(review_id) } } }
    )
    return make_response( jsonify( {} ), 204)

if __name__ == "__main__":
    app.run(debug=True)