import json
import base64
from cs50 import SQL
from functools import wraps
from flask import redirect, session
from requests import post, get

# Client ID
client_id = '1aa24b731ad145908c9956bee2ee4f63'

# Client secret
client_secret = '2dd4df43f57f4a678899fe2d6000ba11'

# Make sure the user is logged in to access certain routes
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return func(*args, **kwargs)
    return wrapper

# Get user authentication URL
def get_user_auth_url():
    url = "https://accounts.spotify.com/authorize?"
    query = f"client_id={client_id}&response_type=code&redirect_uri=http://127.0.0.1:5000/callback&scope=playlist-read-private%20playlist-read-collaborative%20playlist-modify-private%20playlist-modify-public%20user-read-private"

    return f'{url}{query}' 


# Get access token
def get_access_token():

    # Prepare headers
    auth_string = client_id + ":" + client_secret
    auth_bytes = auth_string.encode("utf-8")
    auth_base64 = str(base64.b64encode(auth_bytes), "utf-8")

    # URL to send request to
    url = 'https://accounts.spotify.com/api/token'

    # Body parameters
    if session.get('refresh_token'):
        data = {
            'grant_type' : 'refresh_token',
            'refresh_token' :  session['refresh_token'],
        }

    else:
        data = {
            'grant_type' : 'authorization_code',
            'code' :  session['code'],
            'redirect_uri' : 'http://127.0.0.1:5000/callback'
        }

    # Headers
    headers = {
        'Authorization' : 'Basic ' + auth_base64,
        'Content-Type' : 'application/x-www-form-urlencoded'
    }

    # Send request
    jsonResponse = post(url=url, headers=headers, data=data)

    # Convert json to dict
    response = json.loads(jsonResponse.content)

    # remember refresh_token
    try:
        session['refresh_token'] = response['refresh_token']
    except KeyError:
        pass

    # Return access token
    return response['access_token']

# Get authorization header
def get_auth_header():
    return {"Authorization" : "Bearer " + session.get('access_token')}

# Get current user's profile
def get_user_information():

    # Current user api endpoint
    url = 'https://api.spotify.com/v1/me'

    # Header
    headers = get_auth_header()

    # Send request 
    jsonResponse = get(url=url, headers=headers)

    # Return None if invalid access token
    if jsonResponse.status_code == 401:
        session['access_token'] = get_access_token()
        return None

    # Convert json into dict
    response = json.loads(jsonResponse.content)

    # User information
    user = {
        'id' : response['id'],
        'country' : response['country'],
        'username' : response['display_name'],
        'followers' : response['followers']['total']
    }

    return user

# Get another user's information
def get_user_information_with_id(user_spotify_id):
    
    # User profile api endpoint
    url = f'https://api.spotify.com/v1/users/{user_spotify_id}'

    # Header 
    headers = get_auth_header()

    session['access_token'] = get_access_token()

    # Send request
    jsonResponse = get(url=url, headers=headers)

    response = json.loads(jsonResponse.content)

    user = {
        'id' : response['id'],
        'username' : response['display_name'],
        'followers' : response['followers']['total'],
        'link' : response['href']
    }
        
    return user

# Get user's playlist ids
def get_user_playlist_ids(id):

    # Current user playlist api endpoint
    url = f'https://api.spotify.com/v1/users/{id}/playlists'

    # Header
    headers = get_auth_header()

    # Send request
    jsonResponse = get(url=url, headers=headers)

    # Return None if invalid access token
    if jsonResponse.status_code == 401:
        session['access_token'] = get_access_token()
        return None

    # Convert json into dict
    response = json.loads(jsonResponse.content)

    playlists = response["items"]

    user_playlists = []

    for playlist in playlists:
        if playlist['owner']['id'] == id:
            user_playlists.append({
                'id' : playlist['id'],
                'name' : playlist['name'],
                'public' : playlist['public'],
                'tracks' : playlist['href']
            })

    return user_playlists

def get_playlist_info(id):

    session['access_token'] = get_access_token()
        
    url = f'https://api.spotify.com/v1/playlists/{id}?market=US'

    headers = get_auth_header()

    jsonResponse = get(url=url, headers=headers)

    response = json.loads(jsonResponse.content)

    return {
        'name' : response['name'],
        'public' : response['public']
    }

def get_user_playlist(id):

    session['access_token'] = get_access_token()
    
    url = f'https://api.spotify.com/v1/playlists/{id}?market=US'

    headers = get_auth_header()

    jsonResponse = get(url=url, headers=headers)

    # Return None if invalid access token
    if jsonResponse.status_code == 401:
        session['access_token'] = get_access_token()
        return None
    
    response = json.loads(jsonResponse.content)
    songs = response['tracks']['items']

    tracks = []

    for x in range(10):
        tracks.append(songs[x]['track']['id'])
    
    return tracks

def get_songs_from_album(track_ids):

    url = f'https://api.spotify.com/v1/tracks?market=US&ids={",".join(track_ids)}'

    headers = get_auth_header()

    jsonResponse = get(url=url, headers=headers)

    response = json.loads(jsonResponse.content)['tracks']

    tracks = [{
        'album' : track['album']['name'],
        'artist' : track['artists'][0]['name'],
        'name' : track['name']
    } for track in response]

    return tracks

def search_items(type, name):

    session['access_token'] = get_access_token()
    
    url = f'https://api.spotify.com/v1/search?q={name}&type={type}&market=ES&limit=10'

    headers = get_auth_header()

    jsonResponse = get(url=url, headers=headers)

    if type == 'track':
        response = json.loads(jsonResponse.content)['tracks']
        results = [{
            'name' : song['name'],
            'id' : song['id'],
            'image' : song['album']['images'][0]['url'],
            'artists' : [artist['name'] for artist in song['artists']]
        }for song in response['items']]

    else:
        response = json.loads(jsonResponse.content)['albums']
        results = [{
            'name' : song['name'],
            'id' : song['id'],
            'image' : song['images'][0]['url'],
            'artists' : [artist['name'] for artist in song['artists']]
        }for song in response['items']]

    return results

