from flask import Flask, jsonify, request, session
from flask_mysqldb import MySQL,MySQLdb
from datetime import timedelta
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import model
from functools import wraps
import mysql.connector
from mysql.connector import Error
import bcrypt


import hashlib, binascii, os
 

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'eya-project'
connection = mysql.connector.connect(host='localhost',
                                         database='testingdb',
                                         user='root',
                                         password='')
                                   


app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=10)



@app.route('/chat',methods=['POST'])
def index():
    user_input = request.json['user_input']
    return jsonify({'msg':str(model.chatbot_response(user_input))})





def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')
 
def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password
 

@app.route('/register', methods=['POST'])
def create_user():
    data = request.get_json()
    password = data['password']
    hashed_password = hash_password(password)
    cur = connection.cursor()
    name = data['name']
    email = data['email']
    cur.execute("INSERT INTO users (name, email, password) VALUES (%s,%s,%s)",(name,email,hashed_password,))
    connection.commit()
    return jsonify({'message' : 'New user created!'})

@app.route('/login', methods=['POST'])
def login():
    json = request.json
    email = json['email']
    password = json['password']
    #print(password)
    # validate the received values
    if email and password:
        #check user exists          
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s",(email,))
        row = cursor.fetchone()
        email = row[2]
        #print(email)
        password1 = row[3]
        
        if row:
            if verify_password(password1, password):
                session['email'] = email
                cursor.close()
                return jsonify({'message' : 'You are logged in successfully'})
            else:
                resp = jsonify({'message' : 'Bad Request - invalid password'})
                resp.status_code = 400
                return resp
    else:
        resp = jsonify({'message' : 'Bad Request - invalid credendtials'})
        resp.status_code = 400
        return resp
         
@app.route('/logout', methods=['GET'])
def logout():
    if 'email' in session:
        session.pop('email', None)
    return jsonify({'message' : 'You successfully logged out'})




if __name__ == '__main__':
  app.run(host='127.0.0.1', port=8000, debug=True)
 