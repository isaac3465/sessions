from sqlite3 import IntegrityError

from flask import Flask, flash, session, render_template, redirect
import cgi, os
from flask import Flask, render_template, url_for, redirect, request
from flask import session as login_session
from flask_login import LoginManager, login_user, logout_user, login_required
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
import sqlite3
from flask_admin import Admin, form
from flask import Flask, flash, request, redirect, url_for
import requests

import json
import os

#from cs50 import SQL
from flask import Flask, flash, json, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from datetime import datetime
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
#from helpers import apology, passwordValid
#from flask_login import login_required, passwordValid
from flask_login import login_required
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
#import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps



app = Flask(__name__, static_folder='static')
app.secret_key = 'any random string'


login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
login_manager.init_app(app)


UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

connect = sqlite3.connect(r'C:\Users\741093.NEWCOLLEGE\Downloads\SQLiteDatabaseBrowserPortable\\database.db', check_same_thread=False)



connect.execute(
    'CREATE TABLE IF NOT EXISTS user (id INTEGER NOT NULL PRIMARY KEY autoincrement, username VARCHAR NOT NULL UNIQUE, \
firstname TEXT, lastname TEXT, email NOT NULL UNIQUE, password TEXT, regDateTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')


@app.route('/')
@app.route('/home')
def home():
    cur = connect.cursor()

    return render_template("home.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user_entered = request.form['password']
        cur = connect.cursor()
        cur.execute(f"SELECT id, username, password from user WHERE username='{username}'")
        if cur is not None:
            # Get Stored hashed and salted password - Need to change fetch one to only return the one username
            #login_user(user)
            data = cur.fetchone()
            print(data)
            id = data[0]
            password = data[2]

            print("user id is ",id)
            print(password)
            print(type(password))
            # Compare Password with hashed password- Bcrypt
            if bcrypt.check_password_hash(password, user_entered):
                session['logged_in'] = True
                session['username'] = username
                session['id'] = id

                flash('You are now logged in', 'success')
                return redirect(url_for('welcome'))
                # Close Connection
                cursor.close()

            else:
                error = 'Invalid Username or Password'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password_hash = request.form['password']

        hashed_password = bcrypt.generate_password_hash(
            password_hash).decode('utf-8')
        try:
            cur = connect.cursor()
            cur.execute(
                "INSERT INTO user(username,firstname, lastname, email, password) VALUES (?,?, ?, ?, ?)", (username, firstname, lastname, email, hashed_password))
        except IntegrityError:
            session.rollback()
        else:
            connect.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/welcome')
def welcome():
    return render_template("welcome.html")
if __name__ == "__main__":

    app.run(debug=True)
