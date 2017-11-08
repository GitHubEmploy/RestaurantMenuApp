from flask import Flask,render_template,url_for,request,redirect,flash,jsonify

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pg_database_setup import Base,Restaurant,MenuItem, User
#from database_setup import Base,Restaurant,MenuItem, User

# New imports for the login implementation
from flask import session as login_session
import random,string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import psycopg2
import os
from urllib import parse
import logging

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

PG_URL = parse.urlparse(os.environ["DATABASE_URL"])
PG_DATABASE = PG_URL.path[1:]
PG_USER = PG_URL.username
PG_PASSWD = PG_URL.password
PG_HOST = PG_URL.hostname
PG_PORT = PG_URL.port
PG_CONN = 'postgresql+psycopg2://'+PG_USER+':'+PG_PASSWD+'@'+PG_HOST+':'+str(PG_PORT)+'/'+PG_DATABASE
logging.warning("Postgres DATABASE_URL : ")
logging.warning(os.environ["DATABASE_URL"])
logging.warning("Postgres Conn string : "+PG_CONN)

#Create a DB connection and connect to DB
engine = create_engine(PG_CONN)
#engine = create_engine('sqlite:///restaurantmenuwithusers.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a state token to prevent request forgery.
# Store it in the session for latter validation.
@app.route('/login')
def showLogin():
	# Random string or rather salt 
	#state = ''.join(random.choice(string.letters) for x in xrange(32))   #--Python 2.x
    state = ''.join(random.choice(string.ascii_letters) for x in range(32))    #--Python 3.x
    login_session['state']=state
	#return "the current state is %s" % login_session['state']
    return render_template('login.html',STATE=state)

@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('restaurantList'))
    else:
        flash("You were not logged in")
        return redirect(url_for('restaurantList'))

# START FACEBOOK SIGN IN 
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data.decode()
    print("access token received %s " % access_token)


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.decode().split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print("url sent for API access:%s"% url)
    # print("API JSON result: %s" % result)
    data = json.loads(result.decode())
    logging.error(data)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result.decode())

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    # Only disconnect a connected user.
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)

    # url = 'https://graph.facebook.com/XXXXXX/permissions?access_token=EAAcPdwtESfUBAIImCgDZCGjFSxFsD6Y8TFkO3hNak9ZB566lxFohnaLQcM8ZCDvp3z6iRCvhmzmGZCdLeGRPFDYqRDIuBaNy7so9ADp1z7rOG0gxJPZA3x84k6ijx1QgTkZAojMbIYMm16zgtRrjEJWo9YMGs9ug8wYHDOuMv61QZDZD'
    
    h = httplib2.Http()
    result = h.request(url, 'DELETE')
    logging.warning('FB DELETE %s' % result[0])
    if result[0]['status'] == '200':
        clearLoginSession()
        del login_session['facebook_id']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response            

    return "you have been logged out"

# END FACEBOOK SIGN IN 
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    # check also if access token is valid or expired, if expired then resrore the access token
    stored_url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % stored_access_token)
    stored_h = httplib2.Http()
    stored_result = json.loads(stored_h.request(stored_url, 'GET')[1])
    
    if stored_access_token is not None and gplus_id == stored_gplus_id and stored_result.get('error') is None:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
    	user_id=createUser(login_session)    	
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 160px; height: 160px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print("done!")
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session

@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print("Access Token is None")
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print("In gdisconnect access token is %s" % access_token)
    print("User name is: ")
    print(login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print("result is")
    print(result)

    if result['status'] == '200':
        del login_session['gplus_id']
        del login_session['access_token']
        clearLoginSession()
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# Making an API endpoint for Restaurant List(GET Request)
@app.route('/restaurant/JSON')
def restaurantsJSON():
	restaurants = session.query(Restaurant).all()
	listRestaurant=[]
	j=0
	for i in restaurants:
		if i.serializeRestaurant !=[]:
			listRestaurant.append(i.serializeRestaurant)
		j=j+1
	return jsonify(Restaurants=listRestaurant)

# Making an API endpoint for Restaurant Menu(GET Request)
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	menuItems = session.query(MenuItem).filter_by(restaurant_id=restaurant.id).all()
	listMenuItems=[]
	j=0
	for i in menuItems:
		if i.serialize !=[]:
			listMenuItems.append(i.serialize)
		j=j+1
	return jsonify(MenuItems=listMenuItems)

# Making and API endpoint for a single MenuItem(GET Request)
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id,menu_id):
	menuItem = session.query(MenuItem).filter_by(id=menu_id,restaurant_id=restaurant_id).one()
	return jsonify(MenuItem=menuItem.serialize)

# Task 1: Create route for Restaurant function here
@app.route('/')
@app.route('/restaurant/')
def restaurantList():
	restaurants = session.query(Restaurant).all()
	#Below code show how to use HTML Template to achieve the same dynamically
	#checkAccessToken checks and clears the login_session if the token is expired
	#if 'username' in login_session :
	if 'username' in login_session and checkAccessToken():	
		return render_template('restaurant.html',restaurants=restaurants,session=login_session)
	else:
		return render_template('publicrestaurant.html',restaurants=restaurants,session=login_session)	

# Task 1: Create route for newRestaurant function here
@app.route('/restaurant/new/',methods=['GET','POST'])	
def newRestaurant():
	if 'username' not in login_session:
		return redirect('/login');
	if request.method == 'POST':
		newRestaurant = Restaurant(name=request.form['restaurantname'],user_id = login_session['user_id'])
		session.add(newRestaurant)
		session.commit()
		flash('New Restaurant created')
		return	redirect(url_for('restaurantList'))
	else:
		return render_template('newrestaurant.html')
	

# Task 2: Create route for editRestaurant function here
@app.route('/restaurant/<int:restaurant_id>/edit/',methods=['GET','POST'])		
def editRestaurant(restaurant_id):
	if 'username' not in login_session:
		return redirect('/login');	
	editedRestaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if request.method == 'POST':
		if editedRestaurant !=[]:
			editedRestaurant.name=request.form['restaurantname']
			session.add(editedRestaurant)
			session.commit()
			flash('Restaurant "'+editedRestaurant.name+'" updated successfully')
		return	redirect(url_for('restaurantList',restaurant_id=restaurant_id))

	else:
		return render_template('editrestaurant.html',restaurant_id=restaurant_id,editedRestaurant=editedRestaurant)

# Task 3: Create route for deleteRestaurant function here
@app.route('/restaurant/<int:restaurant_id>/delete/',methods=['GET','POST'])		
def deleteRestaurant(restaurant_id):	
    if 'username' not in login_session:
    	return redirect('/login');	
    deletedRestaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':		
        if deletedRestaurant !=[]:
            try:
                session.delete(deletedRestaurant)
                session.commit()
                flash('Restaurant "'+deletedRestaurant.name+'" deleted successfully')
            except:
                session.rollback()
                flash('Restaurant was not deleted.\nDelete all menuitems before deleting restaurant')
        return	redirect(url_for('restaurantList',restaurant_id=restaurant_id))
    else:
        return render_template('deleterestaurant.html',restaurant_id=restaurant_id,deletedRestaurant=deletedRestaurant)

# Task 5: Create route for newMenuItem function here
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def restaurantMenu(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	menuItems = session.query(MenuItem).filter_by(restaurant_id=restaurant.id).all()

	menuUser = getUserInfo(restaurant.user_id)
	if 'username' not in login_session or menuUser.id != login_session['user_id']:
	#Below code show how to use HTML Template to achieve the same dynamically
		return render_template('publicmenu.html',restaurant=restaurant,menuItems=menuItems,creator = menuUser)
	else:
		return render_template('menu.html',restaurant=restaurant,menuItems=menuItems, creator = menuUser)

# Task 6: Create route for newMenuItem function here
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])	
def newMenuItem(restaurant_id):
	if 'username' not in login_session:
		return redirect('/login');	
	if request.method == 'POST':		
		newMenu = MenuItem(name=request.form['newmenu'],price=request.form['price'],description=request.form['description'],restaurant_id=restaurant_id
			,user_id = login_session['user_id'])
		session.add(newMenu)
		session.commit()
		flash('New menu item created')
		return	redirect(url_for('restaurantMenu',restaurant_id=restaurant_id))
	else:
		return render_template('newmenuitem.html',restaurant_id=restaurant_id)
	

# Task 7: Create route for editMenuItem function here
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit/',methods=['GET','POST'])		
def editMenuItem(restaurant_id,menu_id):
	if 'username' not in login_session:
		return redirect('/login');	
	editedMenu = session.query(MenuItem).filter_by(id=menu_id).one()
	if request.method == 'POST':
		if editedMenu !=[]:
			editedMenu.name=request.form['editmenu']
			session.add(editedMenu)
			session.commit()
			flash('MenuItem "'+editedMenu.name+'" updated successfully')
		return	redirect(url_for('restaurantMenu',restaurant_id=restaurant_id))

	else:
		return render_template('editmenuitem.html',restaurant_id=restaurant_id,menu_id=menu_id,placeHolderMenu=editedMenu)

# Task 8: Create route for deleteMenuItem function here
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete/',methods=['GET','POST'])		
def deleteMenuItem(restaurant_id,menu_id):	
	if 'username' not in login_session:
		return redirect('/login');	
	deletedMenu = session.query(MenuItem).filter_by(id=menu_id).one()
	if request.method == 'POST':		
		if deletedMenu !=[]:
			session.delete(deletedMenu)
			session.commit()
			flash('Menu "'+deletedMenu.name+'" deleted successfully')
		return	redirect(url_for('restaurantMenu',restaurant_id=restaurant_id))

	else:
		return render_template('deletemenuitem.html',restaurant_id=restaurant_id,menu_id=menu_id,deleteItemMenu=deletedMenu)

# check also if access token is valid or expired, if expired then resrore the access token
def checkAccessToken():
    stored_access_token = login_session.get('access_token')
    if stored_access_token:
        h = httplib2.Http()
        if login_session.get('gplus_id') is not None:
            url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
                   % stored_access_token)
            result = json.loads(h.request(url, 'GET')[1])
        if login_session.get('facebook_id') is not None:
            url = ('https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' 
                   % stored_access_token)                               
            result = json.loads(h.request(url, 'GET')[1].decode())
        if result.get('error') is not None:
            flash('Seesion expired- You are being logged out')
            if login_session.get('gplus_id'):
                del login_session['gplus_id']
            if login_session.get('facebook_id'):            
                del login_session['facebook_id']
            del login_session['access_token']
            clearLoginSession()
            return False
    return True

def clearLoginSession():
    del login_session['user_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']	

def createUser(login_session):
	newUser = User(name=login_session['username'],email=login_session['email'],picture=login_session['picture'])
	session.add(newUser)
	session.commit()
	user = session.query(User).filter_by(email=login_session['email']).one()
	return user.id

def getUserInfo(user_id):
	try:
		user = session.query(User).filter_by(id=user_id).one()
		return user
	except Exception as e:
		return None

def getUserID(email):
	try:
		user = session.query(User).filter_by(email=email).one()
		return user.id	
	except Exception as e:
		return None

if __name__ == '__main__':    
    app.secret_key = 'Super-Secret-Key'
    app.debug=True
    PORT = int(os.environ.get('PORT'))
    app.run(host='0.0.0.0',port=PORT)
