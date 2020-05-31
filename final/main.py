'''
    Author: Matthew Egan
    CS493 Fall 2019
    Final project
    Date last modified: December 6, 2019
'''


from google.cloud import datastore
from flask import Flask, request, render_template, redirect, session
import json
import string
import random
import requests
from requests_oauthlib import OAuth2Session
from google.oauth2 import id_token
from google.auth.transport import requests
import google.auth.transport.requests
import constants
#import boats
#import loads



clientID = "794202550632-ho036n1q3pl8iu8hevlc3214k0m7rklj.apps.googleusercontent.com"
clientSecret = "0UvTVSi6lG1ZXqVPR_4sqHT6"

oauthURL = "https://accounts.google.com/o/oauth2/v2/auth"

redirect_URI = "http://http://127.0.0.1:8080/oauth"

scope = ['https://www.googleapis.com/auth/userinfo.email',
             'https://www.googleapis.com/auth/userinfo.profile', 'openid']
oauth = OAuth2Session(clientID, redirect_uri=redirect_URI,
                          scope=scope)


#Function to generate a random value for the state, found on https://pythontips.com/2013/07/28/generating-a-random-string/
def generateState(length = 30, chars=string.ascii_letters + string.digits):
	return "".join(random.choice(chars) for x in range(length))



app = Flask(__name__)
#app.register_blueprint(boats.bp)
#app.register_blueprint(loads.bp)
app.secret_key = b'9)*^aj12L'
client = datastore.Client()

@app.route('/')
def startPage():
	#generate state variable and set it for the session
	state = generateState()
	session['state'] = state

	#prepare URI for redirect for user to give consent and login
	linkURL = oauthURL + "?response_type=code&client_id=" + clientID + "&redirect_uri=" + request.url + "oauth" + "&scope=profile email&state=" + state
	return render_template('startpage.html', startURL = linkURL)

@app.route('/oauth')
def oauthPage():
	code = request.args.get('code')
	state = request.args.get('state')

	#check to make sure state google sends back matches state set at start of session
	if state != session['state']:
		error = {'Error': "States do not match"}
		return(json.dumps(error), 401)

	header = {
		'Content-Type': 'application/x-www-form-urlencoded'
	}
	data1 = {
		'code': code,
		'client_id': clientID,
		'client_secret': clientSecret,
		'redirect_uri': request.base_url,
		'grant_type': 'authorization_code'
	}

	#make a POST request in order to retrieve a token from google
	r = requests.Request()
	results = r.__call__("https://oauth2.googleapis.com/token", method = 'POST', body=data1, headers=header)
	
	getToken = json.loads(results.data)

	#extract JWT from response from google
	jwt_token = getToken['id_token']

	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']
	except:
		error = {"Error": "Invalid JWT.  Try logging in again"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#get list of all user entities
	query = client.query(kind=constants.users)
	results = list(query.fetch())

	#check if user was already created, and if so, just return JWT
	for e in results:
		if e['user_id'] == userID:
			return render_template('success.html', id_token = jwt_token)
	
	#if user has not been added to the database, create a new user with sub property from JWT as unique property of user
	new_user = datastore.entity.Entity(key=client.key(constants.users))
	new_user.update({'user_id': userID, 'email': idinfo['email'], 'name': idinfo['name'], 'boats': []})
	client.put(new_user)
	print(new_user)

	
	#display JWT for user
	return render_template('success.html', id_token = jwt_token)


@app.route('/boats', methods=['POST'])
def create_boats_post():

	#response can only be in json, so if request sets accept MIMEtype to anything but json, sends error message
	if ('application/json' not in request.accept_mimetypes):
		error = {'Error': "The requested MIMEtype is not allowed"}
		return(json.dumps(error), 406, {'Content-Type': 'application/json'})

	#sends 401 status if JWT missing from request
	if 'Authorization' not in request.headers:
		error = {"Error": "JWT missing.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#if there is no body provided, sends error message
	if not request.data:
		error = {'Error': "The body of the request is missing"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})
	content = request.get_json(force=True)

	#extracting the JWT from the authorization header
	jwt_token = request.headers['Authorization'].replace('Bearer ', '')


	#try to verify the JWT sent as valid, if not, sends error message and 401 status code
	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']
	except ValueError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except TypeError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#check to see if userID matches any user_id in users database
	query = client.query(kind=constants.users)
	results = list(query.fetch())
	if not any (d['user_id'] == userID for d in results):
		error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	
	content = request.get_json(force=True)

	#if request body is missing any required attributes, sends error message
	if "name" not in content or "type" not in content or "length" not in content:
		error = {"Error": "The request object is missing at least one of the required attributes"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})
	
	#if there is no body provided, sends error message
	if not request.data:
		error = {"Error": "The body of the request is missing"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})

	#creating new entry for boat in datastore
	new_boat = datastore.entity.Entity(key=client.key(constants.boats))
	new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"], "owner": userID, "loads": []})
	client.put(new_boat)
	boat_url = request.url + "/" + str(new_boat.key.id)
	new_boat["self"] = boat_url
	new_boat["id"] = new_boat.key.id
	newBoat = json.dumps(new_boat)

	return (newBoat, 201, {'Content-Type': 'application/json'})

'''
	Method for getting all boats
'''
@app.route('/boats', methods=['GET'])
def view_all_boats_get():
	#response can only be in json, so if request sets accept MIMEtype to anything but json, sends error message
	if ('application/json' not in request.accept_mimetypes):
		error = {'Error': "The requested MIMEtype is not allowed"}
		return(json.dumps(error), 406, {'Content-Type': 'application/json'})  
	
	if 'Authorization' not in request.headers:
		boat_url = request.url
		query = client.query(kind=constants.boats)
		total_boats = list(query.fetch())
		num_boats = len(total_boats)
		query = client.query(kind=constants.boats)
		q_limit = int(request.args.get('limit', '5'))
		q_offset = int(request.args.get('offset', '0'))
		l_iterator = query.fetch(limit= q_limit, offset=q_offset)
		pages = l_iterator.pages
		results = list(next(pages))
		if l_iterator.next_page_token:
			next_offset = q_offset + q_limit
			next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
		else:
			next_url = None
		for e in results:
			e["id"] = e.key.id
			e["self"] = boat_url + "/" + str(e.key.id)
		output = {"boats": results}
		output['total number of boats'] = num_boats
		if next_url:
			output["next"] = next_url
		return (json.dumps(output), 200, {'Content-Type': 'application/json'})
	else:
		#extracting the JWT from the authorization header
		jwt_token = request.headers['Authorization'].replace('Bearer ', '')

		#try to verify the JWT sent as valid, if not, sends error message and 401 status code
		try:
			idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
			userID = idinfo['sub']

		except ValueError:
			error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
			return(json.dumps(error), 401, {'Content-Type': 'application/json'})
		except TypeError:
			error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
			return(json.dumps(error), 401, {'Content-Type': 'application/json'})
		except:
			error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
			return(json.dumps(error), 401, {'Content-Type': 'application/json'})
		
		#get list of all user entities
		query = client.query(kind=constants.users)
		results = list(query.fetch())
		if not any (d['user_id'] == userID for d in results):
			error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
			return(json.dumps(error), 401, {'Content-Type': 'application/json'})
		#fetch all of the boats
		query = client.query(kind=constants.boats)
		query.add_filter('owner', '=', userID)
		user_boats = list(query.fetch())
		return(json.dumps(user_boats), 200, {'Content-Type': 'application/json'})




'''
	Method for viewing a single boat
'''
@app.route('/boats/<boat_id>', methods=['GET'])
def view_boat_get(boat_id):
	#response can only be in json, so if request sets accept MIMEtype to anything but json, sends error message
	if ('application/json' not in request.accept_mimetypes):
		error = {'Error': "The requested MIMEtype is not allowed"}
		return(json.dumps(error), 406, {'Content-Type': 'application/json'})   
	
	
	boat_key = client.key(constants.boats, int(boat_id))
	boat = client.get(boat_key)

	if not boat:
		error = {"Error": "No boat with this boat_id exists"}
		return(json.dumps(error), 404, {'Content-Type': 'application/json'})
	
	boat_url = request.url
	boat["self"] = boat_url
	boat["id"] = boat.key.id
	getBoat = json.dumps(boat)
	
	return (getBoat,200, {'Content-Type': 'application/json'})




@app.route('/boats/<boat_id>', methods=['PUT'])
def edit_boat_put(boat_id):

	#sends 401 status if JWT missing from request
	if 'Authorization' not in request.headers:
		error = {"Error": "JWT missing.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#extracting the JWT from the authorization header
	jwt_token = request.headers['Authorization'].replace('Bearer ', '')

	#try to verify the JWT sent as valid, if not, sends error message and 401 status code
	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']
	except ValueError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except TypeError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#check to see if userID matches any user_id in users database
	query = client.query(kind=constants.users)
	results = list(query.fetch())
	if not any (d['user_id'] == userID for d in results):
		error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})


	boat_key = client.key(constants.boats, int(boat_id))
	boat = client.get(key=boat_key)

	#checks if boat id provided in url is valid, sends error messgae if not
	if not boat:
		error = {"Error": "No boat with this boat_id exists"}
		return (json.dumps(error), 404, {'Content-Type': 'application/json'})

	#if JWT valid but boat from request is owned by a different user, returns error message and 403 status code
	if userID != boat["owner"]:
		error = {"Error": "The boat you selected is owned by someone else.  You are not authorized to make that request"}
		return(json.dumps(error), 403, {'Content-Type': 'application/json'})    
	

	#if there is no body provided, sends error message
	if not request.data:
		error = {"Error": "The body of the request is missing"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})

	content = request.get_json(force=True)

	
	
	#if request body is missing any required attributes, sends error message
	if "name" not in content or "type" not in content or "length" not in content:
		error = {"Error": "The request object is missing at least one of the required attributes"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})

	
	boat.update({"name": content["name"], "type": content["type"],
		"length": content["length"]})
	
	client.put(boat)

	return ('', 200, {'Content-Type': 'application/json'})


'''
	Method for editing a boat
'''
@app.route('/boats/<boat_id>', methods=['PATCH'])
def edit_boat_patch(boat_id):

	#sends 401 status if JWT missing from request
	if 'Authorization' not in request.headers:
		error = {"Error": "JWT missing.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#response can only be in json, so if request sets accept MIMEtype to anything but json, sends error message
	if ('application/json' not in request.accept_mimetypes):
		error = {'Error': "The requested MIMEtype is not allowed"}
		return(json.dumps(error), 406, {'Content-Type': 'application/json'}) 

	#extracting the JWT from the authorization header
	jwt_token = request.headers['Authorization'].replace('Bearer ', '')

	#try to verify the JWT sent as valid, if not, sends error message and 401 status code
	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']
	except ValueError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except TypeError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#check to see if userID matches any user_id in users database
	query = client.query(kind=constants.users)
	results = list(query.fetch())
	if not any (d['user_id'] == userID for d in results):
		error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	
	boat_key = client.key(constants.boats, int(boat_id))
	boat = client.get(key=boat_key)


	#checks if boat id provided in url is valid, sends error messgae if not
	if not boat:
		error = {"Error": "No boat with this boat_id exists"}
		return (json.dumps(error), 404, {'Content-Type': 'application/json'})

	
	#if JWT valid but boat from request is owned by a different user, returns error message and 403 status code
	if userID != boat["owner"]:
		error = {"Error": "The boat you selected is owned by someone else.  You are not authorized to make that request"}
		return(json.dumps(error), 403, {'Content-Type': 'application/json'})


	#if there is no body provided, sends error message
	if not request.data:
		error = {"Error": "The body of the request is missing"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})
	content = request.get_json(force=True)


		

	#checks if name is provided in request body and either updates the name or send error if name is not unique
	if 'name' in content.keys():
		boat.update({"name": content["name"]})

	#checks if type is included in request body, and updates boat entity with new type
	if 'type' in content.keys():
		boat.update({"type": content["type"]})

	#checks if length is included in request body, and updates boat entity with new type
	if 'length' in content.keys():
		boat.update({"length": content["length"]})
	
	client.put(boat)

	boat["self"] = request.url
	boat["id"] = boat.key.id

	updated_boat = json.dumps(boat)

	return(updated_boat, 200, {'Content-Type': 'application/json'})
	


'''
	Method for deleting a single boat
'''  
@app.route('/boats/<boat_id>', methods=['DELETE'])
def delete_boat(boat_id):
	#sends 401 status if JWT missing from request
	if 'Authorization' not in request.headers:
		error = {"Error": "JWT missing.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#extracting the JWT from the authorization header
	jwt_token = request.headers['Authorization'].replace('Bearer ', '')

	#try to verify the JWT sent as valid, if not, sends error message and 401 status code
	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']
	except ValueError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except TypeError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#check to see if userID matches any user_id in users database
	query = client.query(kind=constants.users)
	results = list(query.fetch())
	if not any (d['user_id'] == userID for d in results):
		error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	
	#retrieve boat requested from datastore
	boat_key = client.key(constants.boats, int(boat_id))
	boat = client.get(key=boat_key)

	#if JWT is valid, but boat in request does not exist, returns error message and 403 status code
	if not boat:
		error = {"Error": "No boat with this boat_id exists"}
		return(json.dumps(error), 404, {'Content-Type': 'application/json'})

	#if JWT valid but boat from request is owned by a different user, returns error message and 403 status code
	if userID != boat["owner"]:
		error = {"Error": "The boat you selected is owned by someone else.  You are not authorized to make that request"}
		return(json.dumps(error), 403, {'Content-Type': 'application/json'})
	
	#updating any loads that were assigned to this boat
	query = client.query(kind=constants.loads)
	results = list(query.fetch())
	for e in results:
		if e["carrier"] == boat.key.id:
			e["carrier"] = None
	client.put_multi(results)

	#if JWT valid and user in JWT matches owner of boat, deletes boat and returns 204 status code
	client.delete(boat_key)
	return("", 204)


'''
	Method for putting a load on a boat
'''
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT'])
def assign_load_boat(boat_id,load_id):

	#sends 401 status if JWT missing from request
	if 'Authorization' not in request.headers:
		error = {"Error": "JWT missing.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#extracting the JWT from the authorization header
	jwt_token = request.headers['Authorization'].replace('Bearer ', '')

	#try to verify the JWT sent as valid, if not, sends error message and 401 status code
	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']

	except ValueError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except TypeError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#check to see if userID matches any user_id in users database
	query = client.query(kind=constants.users)
	results = list(query.fetch())
	if not any (d['user_id'] == userID for d in results):
		error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#get boat entity requested
	boat_key = client.key(constants.boats, int(boat_id))
	boat = client.get(key=boat_key)

	#if no boat with that that boat_id exists, send error message
	if not boat:
		error = {"Error": "No boat with that boat_id exists"}
		return (json.dumps(error), 404, {'Content-Type': 'application/json'})

	#if JWT valid but boat from request is owned by a different user, returns error message and 403 status code
	if userID != boat["owner"]:
		error = {"Error": "The boat you selected is owned by someone else.  You are not authorized to make that request"}
		return(json.dumps(error), 403, {'Content-Type': 'application/json'})

	
	#get load entity requested
	load_key = client.key(constants.loads, int(load_id))
	load = client.get(key=load_key)

	#if no load with that that load_id exists, send error message
	if not load:
		error = {"Error": "No load with that load_id exists"}
		return (json.dumps(error), 404, {'Content-Type': 'application/json'})
	
	#if the load is already assigned to a boat, send an error message
	if load["carrier"] is not None:
		error = {"Error": "A load with that load_id is already assigned to another boat"}
		return (json.dumps(error), 403, {'Content-Type': 'application/json'})
		
	#assign boat id as foreign key in carrier property in load entity
	load["carrier"] = boat.key.id
	client.put(load)

	#assign load id as foreign key in loads array for the boat
	if 'loads' in boat.keys():
		boat['loads'].append(load.key.id)
	client.put(boat)

	return('',204)


'''
	Method for viewing all loads on a boat
'''
@app.route('/boats/<boat_id>/loads', methods=['GET'])
def get_loads_for_boat(boat_id):

	#response can only be in json, so if request sets accept MIMEtype to anything but json, sends error message
	if ('application/json' not in request.accept_mimetypes):
		error = {'Error': "The requested MIMEtype is not allowed"}
		return(json.dumps(error), 406, {'Content-Type': 'application/json'}) 

	boat_key = client.key(constants.boats, int(boat_id))
	boat = client.get(key=boat_key)

	if not boat:
			error = {"Error": "No boat with that boat_id exists"}
			return (json.dumps(error), 404, {'Content-Type': 'application/json'})

	load_list  = []
	if 'loads' in boat.keys():
		for lid in boat["loads"]:
			load_key = client.key(constants.loads, int(lid))
			load_list.append(load_key)
		results = client.get_multi(load_list)

		for e in results:
			e["id"] = e.key.id
			e["self"] = request.url_root + "loads/" + str(e.key.id)
		output = {"loads": results}
		return ((json.dumps(output)), 200, {'Content-Type': 'application/json'})
	else:
		return json.dumps([])

'''
	Method for removing a load from a boat, but not completely deleting the load
'''
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['DELETE'])
def remove_load_boat(boat_id,load_id):
	
	#sends 401 status if JWT missing from request
	if 'Authorization' not in request.headers:
		error = {"Error": "JWT missing.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#extracting the JWT from the authorization header
	jwt_token = request.headers['Authorization'].replace('Bearer ', '')

	#try to verify the JWT sent as valid, if not, sends error message and 401 status code
	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']
	except ValueError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except TypeError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#check to see if userID matches any user_id in users database
	query = client.query(kind=constants.users)
	results = list(query.fetch())
	if not any (d['user_id'] == userID for d in results):
		error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	
	#retrieve boat requested from datastore
	boat_key = client.key(constants.boats, int(boat_id))
	boat = client.get(key=boat_key)
	
	#if JWT is valid, but boat in request does not exist, returns error message and 404 status code
	if not boat:
		error = {"Error": "No boat with this boat_id exists"}
		return(json.dumps(error), 404, {'Content-Type': 'application/json'})


	#if JWT valid but boat from request is owned by a different user, returns error message and 403 status code
	if userID != boat["owner"]:
		error = {"Error": "The boat you selected is owned by someone else.  You are not authorized to make that request"}
		return(json.dumps(error), 403, {'Content-Type': 'application/json'})


	#retrieve load requested from datastore
	load_key = client.key(constants.loads, int(load_id))
	load = client.get(key=load_key)

	#if JWT is valid, but load in request does not exist, returns error message and 404 status code
	if not load:
		error = {"Error": "No load with that load_id exists"}
		return (json.dumps(error), 404, {'Content-Type': 'application/json'})
	
	if load['carrier'] == boat.key.id:
		load['carrier'] = None
		client.put(load)
		if 'loads' in boat.keys():
			boat['loads'].remove(int(load_id))
			client.put(boat)
		return ('', 204)
	else:
		error = {"Error": "No load with this load_id is on the boat with this boat_id"}
		return(json.dumps(error), 404, {'Content-Type': 'application/json'})


'''
	Method for creating a new load
'''
@app.route('/loads', methods=['POST'])
def create_loads_post():
	#sends 401 status if JWT missing from request
	if 'Authorization' not in request.headers:
		error = {"Error": "JWT missing.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#response can only be in json, so if request sets accept MIMEtype to anything but json, sends error message
	if ('application/json' not in request.accept_mimetypes):
		error = {'Error': "The requested MIMEtype is not allowed"}
		return(json.dumps(error), 406, {'Content-Type': 'application/json'})

	#extracting the JWT from the authorization header
	jwt_token = request.headers['Authorization'].replace('Bearer ', '')
	
	#try to verify the JWT sent as valid, if not, sends error message and 401 status code
	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']
	except ValueError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except TypeError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#check to see if userID matches any user_id in users database
	query = client.query(kind=constants.users)
	results = list(query.fetch())
	if not any (d['user_id'] == userID for d in results):
		error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	
	content = request.get_json()

	#if request body is missing any required attributes, sends error message
	if "weight" not in content or "content" not in content or "destination" not in content:
		error = {"Error": "The request object is missing at least one of the required attributes"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})
	
	#if there is no body provided, sends error message
	if not request.data:
		error = {"Error": "The body of the request is missing"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})

	#creating new entry for load in datastore
	new_load = datastore.entity.Entity(key=client.key(constants.loads))
	new_load.update({"weight": content["weight"], "content": content["content"], "destination": content["destination"], "carrier": None})
	client.put(new_load)
	load_url = request.url + "/" + str(new_load.key.id)
	new_load["self"] = load_url
	new_load["id"] = new_load.key.id
	newLoad = json.dumps(new_load)
	
	return (newLoad, 201, {'Content-Type': 'application/json'})


'''
	Method for viewing all loads
'''
@app.route('/loads', methods=['GET'])
def view_all_loads_get():

	#response can only be in json, so if request sets accept MIMEtype to anything but json, sends error message
	if ('application/json' not in request.accept_mimetypes):
		error = {'Error': "The requested MIMEtype is not allowed"}
		return(json.dumps(error), 406, {'Content-Type': 'application/json'})

	load_url = request.url
	query = client.query(kind=constants.loads)
	total_loads = list(query.fetch())
	num_loads = len(total_loads)

	query = client.query(kind=constants.loads)
	q_limit = int(request.args.get('limit', '5'))
	q_offset = int(request.args.get('offset', '0'))
	g_iterator = query.fetch(limit= q_limit, offset=q_offset)
	pages = g_iterator.pages
	results = list(next(pages))
	if g_iterator.next_page_token:
		next_offset = q_offset + q_limit
		next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
	else:
		next_url = None
	for e in results:
		e["id"] = e.key.id
		e["self"] = load_url + "/" + str(e.key.id)
	output = {"loads": results}
	output["total number of loads"] = num_loads
	if next_url:
		output["next"] = next_url
	return (json.dumps(output), 200, {'Content-Type': 'application/json'})
		


'''
	Method for viewing a single load
'''
@app.route('/loads/<load_id>', methods=['GET'])
def view_load_get(load_id):
	#response can only be in json, so if request sets accept MIMEtype to anything but json, sends error message
	if ('application/json' not in request.accept_mimetypes):
		error = {'Error': "The requested MIMEtype is not allowed"}
		return(json.dumps(error), 406, {'Content-Type': 'application/json'})
		
	load_key = client.key(constants.loads, int(load_id))
	load = client.get(load_key)

	#if no load with the load_id provided exists, sends error message and 404 status code
	if not load:
		error = {"Error": "No load with this load_id exists"}
		return(json.dumps(error), 404, {'Content-Type': 'application/json'})
	load_url = request.url
		
	load["self"] = load_url
	load["id"] = load.key.id
	getLoad = json.dumps(load)
		
	return (getLoad,200, {'Content-Type': 'application/json'})


'''
	Method to edit a load with PUT
'''
@app.route('/loads/<load_id>', methods=['PUT'])
def edit_load_put(load_id):

	#sends 401 status if JWT missing from request
	if 'Authorization' not in request.headers:
		error = {"Error": "JWT missing.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#extracting the JWT from the authorization header
	jwt_token = request.headers['Authorization'].replace('Bearer ', '')

	#try to verify the JWT sent as valid, if not, sends error message and 401 status code
	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']
	except ValueError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except TypeError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#check to see if userID matches any user_id in users database
	query = client.query(kind=constants.users)
	results = list(query.fetch())
	if not any (d['user_id'] == userID for d in results):
		error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})


	load_key = client.key(constants.loads, int(load_id))
	load = client.get(key=load_key)	

	#if there is no body provided, sends error message
	if not request.data:
		error = {"Error": "The body of the request is missing"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})

	content = request.get_json(force=True)

	#checks if load id provided in url is valid, sends error messgae if not
	if not load:
		error = {"Error": "No load with this load_id exists"}
		return (json.dumps(error), 404, {'Content-Type': 'application/json'})
	
	#if request body is missing any required attributes, sends error message
	if "weight" not in content or "content" not in content or "destination" not in content:
		error = {"Error": "The request object is missing at least one of the required attributes"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})

	
	load.update({"weight": content["weight"], "content": content["content"],
		"destination": content["destination"]})
	
	client.put(load)

	return ('', 200, {'Content-Type': 'application/json'})


'''
	Method for editing a load with PATCH
'''
@app.route('/loads/<load_id>', methods=['PATCH'])
def edit_load_patch(load_id):

	#sends 401 status if JWT missing from request
	if 'Authorization' not in request.headers:
		error = {"Error": "JWT missing.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#response can only be in json, so if request sets accept MIMEtype to anything but json, sends error message
	if ('application/json' not in request.accept_mimetypes):
		error = {'Error': "The requested MIMEtype is not allowed"}
		return(json.dumps(error), 406, {'Content-Type': 'application/json'}) 

	#extracting the JWT from the authorization header
	jwt_token = request.headers['Authorization'].replace('Bearer ', '')

	#try to verify the JWT sent as valid, if not, sends error message and 401 status code
	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']
	except ValueError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except TypeError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#check to see if userID matches any user_id in users database
	query = client.query(kind=constants.users)
	results = list(query.fetch())
	if not any (d['user_id'] == userID for d in results):
		error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	
	load_key = client.key(constants.loads, int(load_id))
	load = client.get(key=load_key)

	#if there is no body provided, sends error message
	if not request.data:
		error = {"Error": "The body of the request is missing"}
		return(json.dumps(error) , 400, {'Content-Type': 'application/json'})
	content = request.get_json(force=True)

	#checks if load id provided in url is valid, sends error messgae if not
	if not load:
		error = {"Error": "No load with this load_id exists"}
		return (json.dumps(error), 404, {'Content-Type': 'application/json'})
		

	#checks if name is provided in request body and either updates the name or send error if name is not unique
	if 'weight' in content.keys():
		load.update({"weight": content["weight"]})

	#checks if type is included in request body, and updates boat entity with new type
	if 'content' in content.keys():
		load.update({"content": content["content"]})

	#checks if length is included in request body, and updates boat entity with new type
	if 'destination' in content.keys():
		load.update({"destination": content["destination"]})
	
	client.put(load)

	load["self"] = request.url
	load["id"] = load.key.id

	updated_load = json.dumps(load)

	return(updated_load, 200, {'Content-Type': 'application/json'})


'''
	Method for deleting a single load
'''
@app.route('/loads/<load_id>', methods=['DELETE'])
def loads_delete(load_id):
	#sends 401 status if JWT missing from request
	if 'Authorization' not in request.headers:
		error = {"Error": "JWT missing.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#response can only be in json, so if request sets accept MIMEtype to anything but json, sends error message
	if ('application/json' not in request.accept_mimetypes):
		error = {'Error': "The requested MIMEtype is not allowed"}
		return(json.dumps(error), 406, {'Content-Type': 'application/json'}) 

	#extracting the JWT from the authorization header
	jwt_token = request.headers['Authorization'].replace('Bearer ', '')

	#try to verify the JWT sent as valid, if not, sends error message and 401 status code
	try:
		idinfo = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
		userID = idinfo['sub']
	except ValueError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except TypeError:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	except:
		error = {"Error": "Invalid JWT.  You are not authorized to make that request"}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})

	#check to see if userID matches any user_id in users database
	query = client.query(kind=constants.users)
	results = list(query.fetch())
	if not any (d['user_id'] == userID for d in results):
		error = {'Error': 'Invalid user.  You are not in the database.  Please visit homepage to login'}
		return(json.dumps(error), 401, {'Content-Type': 'application/json'})
	
	load_key = client.key(constants.loads, int(load_id))
	load = client.get(load_key)

	if not load:
		error = {"Error": "No load with this load_id exists"}
		return(json.dumps(error), 404, {'Content-Type': 'application/json'})

	if load["carrier"] is not None:
		boat_id = load["carrier"]
		boat_key = client.key(constants.boats, boat_id)
		boat = client.get(boat_key)
		if "loads" in boat.keys():
			boat["loads"].remove(int(id))
			client.put(boat)
	client.delete(load_key)
	return ('',204)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)