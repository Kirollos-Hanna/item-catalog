#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, make_response
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())[
    'web']['client_id']

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Modularize code by using lots of functions and comments

def createUser(login_session):
    newUser = User(email = login_session['email'], picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None


@app.route('/')
@app.route('/catalog')
def showCatalog():
    categories = session.query(Category)
    items = session.query(Item)
    return render_template('catalog.html', categories=categories, items=items)


@app.route('/catalog/<categoryName>/')
@app.route('/catalog/<categoryName>/items')
def showCategory(categoryName):
    categories = session.query(Category)
    category = categories.filter_by(name=categoryName).one()

    items = session.query(Item).filter_by(category_id=category.id)
    itemsList = [item for item in items]
    # catName = category.name[0].upper() + category.name[1:]

    return render_template('items.html', categories=categories, categoryName=categoryName, items=itemsList, itemsLength=len(itemsList))


@app.route('/catalog/<categoryName>/<itemName>')
def showItem(categoryName, itemName):
    item = session.query(Item).filter_by(name=itemName).one()
    user = getUserInfo(item.user_id)
    
    if 'email' not in login_session or login_session['email'] == user.email:
        return render_template('item.html', item=item)
    else:
        return render_template('public-item.html', item=item)



@app.route('/catalog/<categoryName>/new', methods=['GET', 'POST'])
@app.route('/catalog/<categoryName>/items/new', methods=['GET', 'POST'])
def newItem(categoryName):
    if 'email' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = session.query(Category).filter_by(
            name=request.form['category']).one()
        newItem = Item(name=request.form['name'],
                       description=request.form['desc'],
                       category_id=category.id,
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        return redirect(url_for('showCategory', categoryName=categoryName))
    else:
        return render_template('new-item.html', categoryName=categoryName)


@app.route('/catalog/<categoryName>/<itemName>/edit', methods=['GET', 'POST'])
def editItem(categoryName, itemName):
    if 'email' not in login_session:
        return redirect('/login')
    
    item = session.query(Item).filter_by(name=itemName).one()
    user = getUserInfo(item.user_id)
    if 'email' not in login_session or login_session['email'] == user.email:
        return redirect('/')

    if request.method == 'POST':
        category = session.query(Category).filter_by(
            name=request.form['category']).one()
        item.name = request.form['name']
        item.description = request.form['desc']
        item.category_id = category.id
        session.add(item)
        session.commit()
        return redirect(url_for('showItem', categoryName=category.name, itemName=item.name))
    else:
        return render_template('edit-item.html', categoryName=categoryName, itemName=itemName)


@app.route('/catalog/<categoryName>/<itemName>/delete', methods=['GET', 'POST'])
def deleteItem(categoryName, itemName):
    if 'email' not in login_session:
        return redirect('/login')

    item = session.query(Item).filter_by(name=itemName).one()
    user = getUserInfo(item.user_id)
    if 'email' not in login_session or login_session['email'] == user.email:
        return redirect('/')
    
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template('delete-item.html', categoryName=categoryName, itemName=itemName)


@app.route('/catalog.json')
def catalogJSON():
    categories = session.query(Category)
    items = session.query(Item)

    categoriesJSON = [category.serialize for category in categories]
    itemsJSON = [item.serialize for item in items]

    return jsonify(Category=categoriesJSON, Items=itemsJSON)


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            "Token's user ID doesn't mathc givern user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            "Token's client ID doesn't match app's."), 401)
        print("Token's client ID does not mathc app's.")
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)
    print(data)
    # login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    # output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style="width: 300px; height: 300px; border-radius: 150px; -webkit-border-radius: 150px; -moz-border-radius: 150px;"> '
    # flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        del login_session['credentials']
        del login_session['gplus_id']
        # del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for giver user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


if __name__ == '__main__':
    app.secret_key = "super-secret-key"
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
