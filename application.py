#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask import make_response, session as login_session
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database_setup import Base, Category, Item, User
import random
import string
import json
import requests
import httplib2

app = Flask(__name__)

# Create a connection to the database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

# Create a session
DBSession = sessionmaker(bind=engine)
session = DBSession()

# HELPER FUNCTIONS


def createUser(login_session):
    """
    createUser returns the user id of a newly created user.

    createUser takes a secure cookie session as a parameter,
    creates a new user
    and commits him/her to the database and returns the resulting user id.
    args:
    login_session - a secure cookie session
    that stores key, value pairs when a user logs in.

    returns:
    The id of a user object.
    """
    newUser = User(
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
    getUserInfo returns a user object.

    getUserInfo takes a user id as a parameter,
    fetches the user from the database and returns the resulting user object.
    args:
    user_id - a number that helps identify a particular
    user object in the database.

    returns:
    The user object with the same id as the input argument.
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """
    getUserID returns a user id if it exists
    and returns nothing if a user ID doesn't exist.

    getUserID takes an email as a parameter,
    fetches the user from the database
    and returns the resulting user's id.
    args:
    email - an email string that helps
    identify a particular user object in the database.

    returns:
    The user id with the same email as the input argument.
    Or, none if the user related to that email doesn't exist.
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except NoResultFound:
        return None


def pictureExists():
    """
    pictureExists returns a picture URL string
    if it exists and returns an empty string if it doesn't exist.

    pictureExists assigns the picture key's value
    in the login session object to a picture string variable if it exists.

    returns:
    A string of the picture URL if it exists
    and an empty string if the URL doesn't exist.
    """

    picture = ''
    if 'picture' in login_session:
        picture = login_session['picture']

    return picture


def notLoggedIn():
    """
    notLoggedIn returns a boolean value.

    notLoggedIn checks if an email key exists in the login session object.

    returns:
    True if no user is logged in, False otherwise.
    """
    return 'email' not in login_session


def isPostRequest():
    """
    isPostRequest returns a boolean value.

    isPostRequest checks if the method in the request object is equal to POST.

    returns:
    True if a request method is a post request, False otherwise.
    """
    return request.method == 'POST'


def makeResponse(responseString, responseCode):
    """
    makeResponse returns a response object.

    makeResponse takes a string and code as parameters
    and formulates a response object that gets returned to the client.
    args:
    responseString - a string that shows a helpful message to the client.
    responseCode - an integer that specifies
    the type of message that is being sent.

    returns:
    The response object with the string and code of the input arguments.
    """
    response = make_response(json.dumps(responseString), responseCode)
    response.headers['Content-Type'] = 'application/json'
    return response


def checkUserRequest():
    """
    checkUserRequest returns a 401 response if the token that
    the client sent to the server doesn't match the token
    that the server sent to the client.

    checkUserRequest helps ensure that the user is making
    the request and not a malicious script.

    returns:
    A 401 response if tokens from client and server don't match.
    Nothing otherwise.
    """
    if request.args.get('state') != login_session['state']:
        return makeResponse('Invalid state parameter', 401)


def createJSONRequest(url, requestType, index):
    """
    createJSONRequest returns a result of a request made to the specified URL.

    createJSONRequest takes a url, request type and an index as parameters
    and sends an http request to the url with the specified request type
    and brings the desired data through the index number.
    args:
    url - a string that allows us to access a specific website on the internet.
    requestType - a string that specifies the type of http request we want.
    index - an integer that specifies the particular data
    we want returned from the http request

    returns:
    A specific result from an http request
    """
    h = httplib2.Http()
    return h.request(url, requestType)[index]


def serveOutput():
    """
    serveOutput returns an HTML string to be output
    in case of a successful login.

    serveOutput creates a string to inform the user of a successful login.

    returns:
    An HTML string.
    """
    output = ''
    output += '<h1>Welcome!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '''
    " style="width:300px;
            height:300px;
            border-radius:150px;
            -webkit-border-radius:150px;
            -moz-border-radius:150px;"
        >
    '''
    return output


def itemBelongsToOtherUser(item):
    """
    itemBelongsToOtherUser returns a boolean value of True
    if the current user isn't the one who created the provided item.

    args:
    item - a dictionary of an item in the database.

    returns:
    True if the item doesn't belong to the user and False otherwise.
    """
    user = getUserInfo(item.user_id)
    return login_session['email'] != user.email


def getSpecificItem(itemName):
    """
    getSpecificItem returns an item from the database
    that includes the same name as the provided item name parameter.

    args:
    itemName - a string that can identify a particular item in the database.

    returns:
    An item dictionary from the database.
    """
    return session.query(Item).filter_by(name=itemName).one()


# ROUTES

@app.route('/')
@app.route('/catalog')
def showCatalog():
    # Query all categories and the latest 10 items
    # and render them on the catalog page
    categories = session.query(Category)
    items = session.query(Item).order_by(desc(Item.id)).limit(10)
    picture = pictureExists()
    return render_template(
        'catalog.html',
        categories=categories,
        items=items,
        hasLogin='email' in login_session,
        picture=picture
    )


@app.route('/catalog/<categoryName>/')
@app.route('/catalog/<categoryName>/items')
def showCategory(categoryName):
    # Query all categories and items
    # from the specified category name and render them on the page
    categories = session.query(Category)
    category = categories.filter_by(name=categoryName).one()

    items = session.query(Item).filter_by(category_id=category.id)
    itemsList = [item for item in items]
    picture = pictureExists()

    return render_template(
        'items.html',
        categories=categories,
        categoryName=categoryName,
        items=itemsList,
        itemsLength=len(itemsList),
        hasLogin='email' in login_session,
        picture=picture
    )


@app.route('/catalog/<categoryName>/<itemName>')
def showItem(categoryName, itemName):
    try:
        item = getSpecificItem(itemName)
    except NoResultFound:
        return redirect('/')

    picture = pictureExists()
    if notLoggedIn() or itemBelongsToOtherUser(item):
        return render_template(
            'public-item.html',
            item=item,
            hasLogin='email' in login_session,
            picture=picture
        )
    else:
        return render_template(
            'item.html',
            item=item,
            hasLogin='email' in login_session,
            picture=picture
        )


@app.route(
    '/catalog/<categoryName>/new',
    methods=['GET', 'POST']
)
@app.route(
    '/catalog/<categoryName>/items/new',
    methods=['GET', 'POST']
)
def newItem(categoryName):
    if notLoggedIn():
        return redirect('/login')

    if isPostRequest():
        # Create a new item with all the data provided from the form
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
        # Render the new item page form
        return render_template(
            'new-item.html',
            categoryName=categoryName,
            hasLogin='email' in login_session,
            picture=login_session['picture']
        )


@app.route(
    '/catalog/<categoryName>/<itemName>/edit',
    methods=['GET', 'POST']
)
def editItem(categoryName, itemName):
    if notLoggedIn():
        return redirect('/login')

    item = getSpecificItem(itemName)

    if itemBelongsToOtherUser(item):
        return redirect('/')

    if isPostRequest():
        # Edit all data belonging to item
        # with the new data returned from the form
        category = session.query(Category).filter_by(
            name=request.form['category']).one()
        item.name = request.form['name']
        item.description = request.form['desc']
        item.category_id = category.id
        session.add(item)
        session.commit()
        return redirect(
            url_for(
                'showItem',
                categoryName=category.name,
                itemName=item.name
            )
        )
    else:
        # Render the edit item page form
        return render_template(
            'edit-item.html',
            categoryName=categoryName,
            itemName=itemName,
            hasLogin='email' in login_session,
            picture=login_session['picture']
        )


@app.route(
    '/catalog/<categoryName>/<itemName>/delete',
    methods=['GET', 'POST']
)
def deleteItem(categoryName, itemName):
    if notLoggedIn():
        return redirect('/login')

    item = getSpecificItem(itemName)

    if itemBelongsToOtherUser(item):
        return redirect('/')

    if isPostRequest():
        # Delete the specified item from the database
        session.delete(item)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        # Render the delete item page form
        return render_template(
            'delete-item.html',
            categoryName=categoryName,
            itemName=itemName,
            hasLogin='email' in login_session,
            picture=login_session['picture']
        )


@app.route('/catalog.json')
def catalogJSON():
    # The API endpoint of the application
    # where all the data about categories and items are stored.
    categories = session.query(Category)
    items = session.query(Item)

    categoriesJSON = [category.serialize for category in categories]
    itemsJSON = [item.serialize for item in items]

    return jsonify(Category=categoriesJSON, Items=itemsJSON)


@app.route('/login')
def showLogin():
    if notLoggedIn():
        # Create an anti forgery state token and add it to login session
        state = ''.join(
            random.choice(
                string.ascii_uppercase + string.digits
            ) for x in xrange(32)
        )
        login_session['state'] = state
        return render_template('login.html', STATE=state)
    else:
        return redirect('/')


@app.route('/gconnect', methods=['POST'])
def gconnect():
    checkUserRequest()

    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        return makeResponse('Failed to upgrade the authorization code.', 401)

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    # Create json GET request containing url
    # and access token and store result of request in variable called result
    result = json.loads(createJSONRequest(url, 'GET', 1))

    if result.get('error') is not None:
        return makeResponse(result.get('error'), 500)

    gplus_id = credentials.id_token['sub']

    if result['user_id'] != gplus_id:
        return makeResponse(
            "Token's user ID doesn't match given user ID.",
            401
        )

    client_id = json.loads(
        open('client_secrets.json', 'r').read()
    )['web']['client_id']

    if result['issued_to'] != client_id:
        return makeResponse("Token's client ID doesn't match app's.", 401)

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_credentials is not None and gplus_id == stored_gplus_id:
        return makeResponse('Current user is already connected.', 200)

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = json.loads(answer.text)
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = serveOutput()

    return output


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    checkUserRequest()

    access_token = request.data

    app_id = json.loads(
        open('fb_client_secrets.json', 'r').read()
    )['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read()
    )['web']['app_secret']
    url = '''
    https://graph.facebook.com/oauth/access_token?
    grant_type=fb_exchange_token
    &client_id=%s
    &client_secret=%s
    &fb_exchange_token=%s
    ''' % (app_id, app_secret, access_token)
    result = createJSONRequest(url, 'GET', 1)

    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = '''
    https://graph.facebook.com/v2.8/me?
    access_token=%s
    &fields=id,email
    ''' % token
    result = createJSONRequest(url, 'GET', 1)
    data = json.loads(result)
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    login_session['provider'] = 'facebook'
    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = '''
    https://graph.facebook.com/v2.8/me/picture?
    access_token=%s
    &redirect=0
    &height=200
    &width=200
    ''' % token
    result = createJSONRequest(url, 'GET', 1)
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = serveOutput()

    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    access_token = login_session['access_token']
    if access_token is None:
        return makeResponse('Current user not connected.', 401)

    facebook_id = login_session['facebook_id']

    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    result = createJSONRequest(url, 'DELETE', 1)
    if result[0]:
        return makeResponse('Successfully disconnected.', 200)
    else:
        return makeResponse('Failed to revoke token for giver user.', 400)


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        return makeResponse('Current user not connected.', 401)

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    result = createJSONRequest(url, 'GET', 0)

    if result['status'] == '200':
        return makeResponse('Successfully disconnected.', 200)
    else:
        return makeResponse('Failed to revoke token for giver user.', 400)


@app.route('/disconnect')
def disconnect():
    # Check which provider the user is logged in from
    # and delete all the necessary information from the login session
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        elif login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        del login_session['provider']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['access_token']

        return redirect(url_for('showCatalog'))


if __name__ == '__main__':
    app.secret_key = "super-secret-key"
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
