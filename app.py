#!flask/bin/python
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import uuid
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/the-elvatron/Documents/Github/mood-api/mood_rating.db'

db = SQLAlchemy(app)

#create database for user mood ratings
class MoodRating(db.Model):
    id=db.Column(db.Integer, primary_key = True)
    # mood rating
    value=db.Column(db.Integer)
    # time of mood rating to keep track of days on which mood was added to keep track of streak
    time=db.Column(db.Date)
    #id of user who submitted mood rating
    user_id=db.Column(db.Integer)


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
