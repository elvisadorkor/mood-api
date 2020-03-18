#!flask/bin/python
from flask import Flask, request, jsonify, make_response
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import uuid
import datetime
import jwt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/the-elvatron/Documents/Github/mood-api/mood_rating.db'

db = SQLAlchemy(app)

# create database for users
class User(db.Model):

    id = db.Column(db.Integer, primary_key = True)
    # unique user id to identify each user
    public_id = db.Column(db.String(50), unique=True)
    # name of user
    name = db.Column(db.String(20))
    # user password
    password = db.Column(db.String(20))
    admin = db.Column(db.Boolean)

#create database for user mood ratings
class MoodRating(db.Model):
    id=db.Column(db.Integer, primary_key = True)
    # mood rating
    value=db.Column(db.Integer)
    # time of mood rating to keep track of days on which mood was added to keep track of streak
    time=db.Column(db.Date)
    #id of user who submitted mood rating
    user_id=db.Column(db.Integer)


#create decorator
def require_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        #create empty token
        token = None
        #check if x-access-token header exists
        if 'x-access-token' in request.headers:
            #pass token to variable
            token = request.headers['x-access-token']
        #if token does not exist pass back unauthorized error
        if not token:
            return jsonify({'message' : 'Missing token'}), 401
        #try using json web token to decode token
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            curr_auth_user = User.query.filter_by(public_id=data['public_id']).first()
        #if not successful pass back unauthorized error
        except:
            return jsonify({'message' : 'Token required'}), 401

        return func(curr_auth_user, *args, **kwargs)

    return wrapped


# handle routes for users and add decorator to all routes

# get all users
@app.route('/user', methods = ['GET'])
@require_token
def get_all_users(curr_auth_user):
    #allow only if user is admin
    if curr_auth_user.admin != True:
        return jsonify({'message' : 'Need to be an admin to perform function!'})
    # query users table
    users = User.query.all()
    user_list = []
    for user in users:
        #  create new dictionary to store user information
        user_info = {}
        user_info['name'] = user.name
        user_info['admin'] =  user.admin
        user_info['public_id'] = user.public_id
        #add each user to the list of users
        user_list.append(user_info)
    return jsonify({'users' : user_list})

# get one user
@app.route('/user/<public_id>', methods = ['GET'])
@require_token
def get_user(curr_auth_user, public_id):
    #allow only if user is admin
    if curr_auth_user.admin != True:
        return jsonify({'message' : 'Need to be an admin to perform function!'})
    #find specific user by their unique id
    user = User.query.filter_by(public_id=public_id).first()
    #if user was not found
    if not user:
        return jsonify({'message' : 'This user was not found'})
    #create new dictionary to store user information
    user_info = {}
    user_info['public_id'] = user.public_id
    user_info['name'] = user.name
    user_info['admin'] =  user.admin
    return jsonify({'user' : user_info})


# add new user
@app.route('/user', methods = ['POST'])
@require_token
def new_user(curr_auth_user):
    #allow only if user is admin
    if curr_auth_user.admin != True:
        return jsonify({'message' : 'Need to be an admin to perform function!'})
    # create user whenever data is passed in
    data = request.get_json()
    # create new user
    new_user = User(name = data['name'], password = data['password'], public_id=str(uuid.uuid4()), admin = False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'new user has been created'})


#allow admin to set other admins
@app.route('/user/<public_id>', methods=['PUT'])
@require_token
def update_user(curr_auth_user, public_id):
    #allow only if user is admin
    if not curr_auth_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()
    #if user does not exist
    if not user:
        return jsonify({'message' : 'No user found!'})

    #set admin field to true
    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user admin status has been updated!'})

#function to handle login credentials
#takes username and password of user and uses http basic authentication to generate a token
@app.route('/login')
def login():
    details = request.authorization
    # pass back login if user does not specify needed info
    if not details or not details.username or not details.password:
        return make_response('Could not verify user', 401, {'WWW_Authenticate' : 'Basic realm="Login required"'})

    user = User.query.filter_by(name = details.username).first()
    # pass back login if user not in database
    if not user:
        return make_response('Could not verify user', 401, {'WWW_Authenticate' : 'Basic realm="Login required"'})

    # if user enters the right password:
    if user.password == details.password:
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes = 60)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})

    # pass back login if password incorrect
    return make_response('Could not verify user', 401, {'WWW_Authenticate' : 'Basic realm="Login required"'})


# handle route for mood
@app.route('/mood', methods = ['POST'])
# function to add a new mood rating submitted by a user
def add_mood_rating():
    data = request.get_json()
    new_mood_rating = MoodRating(value=data['value'], time=datetime.datetime.now(), user_id=str(uuid.uuid4()))
    db.session.add(new_mood_rating)
    db.session.commit()
    return jsonify({'message': 'new mood rating has been created'})

if __name__ == '__main__':
    app.run(debug=True)
