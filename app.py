import os
import ast

from flask import Flask, render_template, request, session, redirect, url_for
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from re import match
from cs50 import SQL
from helpers import *

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 library to use sqlite
db = SQL("sqlite:///groove50.db")

@app.route("/", methods = ['GET', 'POST'])
@login_required
def index():

    if request.method == 'POST':
        comment = request.form.get('comment')
        post_id = request.form.get('post_id')
        group_id = request.form.get('group_id')
        db.execute('INSERT INTO comments (post_id, comment, user_id, group_id) VALUES(?, ?, ?, ?)', post_id, comment, session['user_id'], group_id)

    group_names = db.execute('SELECT * FROM groups WHERE id IN (SELECT group_id FROM group_members WHERE user_id = ?) ORDER BY time DESC',session['user_id'] )

    posts = db.execute('SELECT * FROM posts WHERE group_id IN (SELECT group_id FROM group_members WHERE user_id = ?) ORDER BY timestamp DESC',session['user_id'] )

    comments = db.execute('SELECT * FROM comments WHERE post_id IN (SELECT post_id FROM posts WHERE group_id IN (SELECT group_id FROM group_members WHERE user_id = ?)) ORDER BY time DESC',session['user_id'])

    users = db.execute('SELECT * FROM users ORDER BY timestamp DESC' )

    return render_template("index.html", group_names = group_names, posts = posts, comments = comments, users = users)

@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    # Handles logging in (POST)
    if request.method == "POST":

        # Get username input from request
        username = request.form.get("username")

        # Get password input from request
        password = request.form.get("password")

        # Query database
        user = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure the user typed in correct username and password
        if not user or not check_password_hash(pwhash=user[0]["hash"], password=password):
            return render_template("login.html", incorrect="Incorrect credentials!")

        # Store user_id in session object
        session["user_id"] = user[0]["id"]

        url = get_user_auth_url()

        # Redirect user to spotify authentication page
        return redirect(url)

    # GET
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    # POST
    if request.method == "POST":

        # Get username from request
        username = request.form.get("username")

        # Get password from request
        password = request.form.get("password")

        # Get confirm_password from request
        confirm_password = request.form.get("confirmPassword")

        # Query database for username
        check_username = db.execute(
            "SELECT * FROM users WHERE username = ?", username)

        # Ensure the username is available
        if check_username:
            return render_template("register.html", incorrect="Username isn't available!")

        # Ensure passwords have both letters and numbers and length of eight and above
        if not match("^(?=.*[A-Za-z])(?=.*\d).{8,}$", password):
            return render_template("register.html", incorrect="The password must be at least 8 characters long and contain both letters and numbers")

        # Ensure passwords match
        if password != confirm_password:
            return render_template("register.html", incorrect="Passwords don't match")

        # Insert new user into database
        id = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                        username, generate_password_hash(password))

        # Remember user
        session["user_id"] = id

        url = get_user_auth_url()

        # Redirect user to spotify authentication page
        return redirect(url)

    # GET
    return render_template("register.html")


@app.route("/profile/me")
@login_required
def profile():

    # Get user information
    user = get_user_information()

    # If invalid access token
    if user is None:
        return redirect('/profile/me')

    # Get username from database
    username = db.execute(
        'SELECT * FROM users WHERE id = ?', session.get('user_id'))

    # Get id of the playlist user displays on profile
    playlist = db.execute(
        'SELECT * FROM profile_playlist_id WHERE user_id = ?', session['user_id'])

    # If the playlist exists
    if len(playlist) > 0:

        user_playlists = get_user_playlist_ids(user['id'])

        playlist_id = playlist[0]['playlist_id']

        # iterate over user playlists
        for user_playlist in user_playlists:

            # Check if the playlist user displays on the profile is public
            if playlist_id == user_playlist['id']:

                if user_playlist['public']:

                    track_ids = get_user_playlist(playlist_id)

                    tracks = get_songs_from_album(track_ids)

                    return render_template("profile.html", user=user, username=username[0]['username'], tracks=tracks, playlist_id=playlist[0]['playlist_id'])

                break

    return render_template("profile.html", user=user, username=username[0]['username'])


@app.route("/callback")
def callback():

    # Auth code
    session['code'] = request.args.get("code")

    # Pass in auth code to get access token
    access_token = get_access_token()

    session["access_token"] = access_token

    spotify_id = get_user_information()['id']

    db.execute('UPDATE users SET spotify_id = ? WHERE id = ?',
               spotify_id, session['user_id'])

    return redirect("/")


@app.route("/profile/me/edit", methods=['GET', 'POST'])
@login_required
def edit_profile():

    # POST
    if request.method == 'POST':

        # Get new username
        username = request.form.get('username')

        # If the user entered a new username
        if username:

            # Query database for existing usernames
            user = db.execute(
                'SELECT * FROM users WHERE username = ?', username)

            # Ensure username is available
            if user:
                return render_template("edit-profile.html", username="Username isn't available")

            # Update username in the database
            db.execute('UPDATE users SET username = ? WHERE id = ?',
                       username, session['user_id'])

        # Get current password
        password = request.form.get('currentPassword')

        # Get new password
        newPassword = request.form.get('newPassword')

        # If the user typed in his/her password
        if password:

            # Query database for current password
            userPassword = db.execute(
                'SELECT * FROM users WHERE id = ?', session['user_id'])

            # Ensure user typed in the correct current password
            if not check_password_hash(password=password, pwhash=userPassword[0]['hash']):
                return render_template("edit-profile.html", password="Wrong password")

            # Ensure user typed in valid new password
            if not match("^(?=.*[A-Za-z])(?=.*\d).{8,}$", newPassword):
                return render_template("edit-profile.html", invalidPassword="The password must be at least 8 characters long and contain both letters and numbers")

            # Update new password in the database
            db.execute('UPDATE users SET hash = ? WHERE id = ?',
                       generate_password_hash(newPassword), session['user_id'])

        # Get list of playlist ids
        playlist_id = request.form.get('playlist')

        # Check if user checked a playlist or not
        if playlist_id is not None:

            id = db.execute(
                'SELECT * FROM profile_playlist_id WHERE user_id = ?', session['user_id'])

            if len(id) == 0:
                db.execute('INSERT INTO profile_playlist_id(user_id, playlist_id) VALUES (?, ?)',
                           session['user_id'], playlist_id)

            elif id[0]['playlist_id'] != playlist_id:
                db.execute(
                    'UPDATE profile_playlist_id SET playlist_id = ?', playlist_id)

        # Redirect to the profile route
        return redirect("/profile/me")

    # GET

    # Get user infos
    user = get_user_information()

    if user is None:
        return redirect('/profile/me/edit')

    # Get user playlists
    playlists = get_user_playlist_ids(user['id'])

    if playlists is None:
        return redirect('/profile/me/edit')

    # Filter out public playlists
    public_playlists = []
    for playlist in playlists:
        if playlist['public'] == True:
            public_playlists.append(playlist)

    return render_template("edit-profile.html", playlists=public_playlists)


@app.route("/search")
@login_required
def search():

    username = request.args.get('username', None)
    group = request.args.get('group', None)

    if username:
        return redirect(url_for('username', username=username))

    if group:
        return redirect(url_for('group', group=group))

    return render_template('search.html')


@app.route("/search/users/results_for_<username>")
@login_required
def username(username):

    session['access_token'] = get_access_token()

    # Query database for users that match
    users = db.execute(
        'SELECT * FROM users WHERE username LIKE ?', username + '%')

    return render_template('username_results.html', spotify=[
        get_user_information_with_id(user['spotify_id'])
        for user in users], users=users)


@app.route("/profile/<username>")
@login_required
def visit_profile(username):

    session['access_token'] = get_access_token()

    user = db.execute('SELECT * FROM users WHERE username = ?', username)

    spotify = get_user_information_with_id(user[0]['spotify_id'])

    profile_playlist_id = db.execute(
        'SELECT * FROM profile_playlist_id WHERE user_id = ?', user[0]['id'])

    if len(profile_playlist_id) > 0 and get_playlist_info(profile_playlist_id[0]['playlist_id'])['public']:

        track_ids = get_user_playlist(profile_playlist_id[0]['playlist_id'])

        if track_ids:

            tracks = get_songs_from_album(track_ids)
            
            return render_template('profile.html', user=spotify, username=user[0]['username'], tracks=tracks, playlist_id = profile_playlist_id[0]['playlist_id'])

    return render_template('profile.html', user=spotify, username=user[0]['username'])


@app.route("/search/groups/results_for_<group>")
@login_required
def group(group):

    session['access_token'] = get_access_token()

    groups = db.execute('SELECT * FROM groups WHERE name LIKE ?', group + '%')

    return render_template('group_results.html', groups = [group['name'] for group in groups])


@app.route("/groups", methods = ['POST', 'GET'])
@login_required
def groups():

    if request.method == 'POST':

        new_group = request.form.get('group_create', None)

        if new_group:

            group_name_check = db.execute('SELECT * FROM groups WHERE name = ?', new_group)

            if group_name_check:
                return redirect('/groups')
            
            id = db.execute('INSERT INTO groups(name) VALUES(?)', new_group)

            db.execute('INSERT INTO group_members(user_id, group_id) VALUES(?, ?)', session['user_id'], id)

    group_ids = db.execute('SELECT * FROM group_members WHERE user_id = ?', session['user_id'])

    if not group_ids:

        return render_template('groups.html')
    
    groups = [db.execute('SELECT * FROM groups WHERE id = ?', group_id['group_id'])[0]['name'] for group_id in group_ids]

    return render_template('groups.html', groups = groups)

@app.route("/groups/<group_name>", methods = ['POST', 'GET'])
def group_visit(group_name):

    group = db.execute('SELECT * FROM groups WHERE name = ?', group_name)

    if request.method == 'POST':

        if request.form.get('action') == 'join':

            db.execute('INSERT INTO group_members (user_id, group_id) VALUES(?, ?)', session['user_id'], group[0]['id'])

        elif request.form.get('action') == 'leave':

            db.execute('DELETE FROM group_members WHERE user_id = ? AND group_id = ?', session['user_id'], group[0]['id'])

            return redirect('/groups')
        
        elif request.form.get('action') == 'post':

            return redirect(f'/groups/{group_name}/post')
        
        elif request.form.get('comment'):

            comment = request.form.get('comment')

            db.execute('INSERT INTO comments (post_id, comment, user_id, group_id) VALUES(?, ?, ?, ?)', request.form.get('post_id'), comment, session['user_id'], group[0]['id'])
        
        else:

            if request.form.get('track'):

                post = ast.literal_eval(request.form.get('track'))
                caption = request.form.get('caption')

                db.execute('INSERT INTO posts (user_id, group_id, type, name, id, image, artist, caption) VALUES(?, ?, ?, ?, ?, ?, ?, ?)',session['user_id'],group[0]['id'],'track',post['name'], post['id'], post['image'], post['artists'], caption)

            else:

                post = ast.literal_eval(request.form.get('album'))
                caption = request.form.get('caption')

                db.execute('INSERT INTO posts (user_id, group_id, type, name, id, image, artist, caption) VALUES(?, ?, ?, ?, ?, ?, ?, ?)',session['user_id'],group[0]['id'],'album',post['name'], post['id'], post['image'], post['artists'], caption)

    posts = db.execute('SELECT * FROM posts WHERE group_id = ? ORDER BY timestamp DESC', group[0]['id'])

    comments = db.execute('SELECT * FROM comments WHERE group_id = ? ORDER BY time DESC', group[0]['id'])

    user = db.execute('SELECT * FROM users WHERE id IN (SELECT user_id FROM group_members WHERE group_id = ?)', group[0]['id'])

    member_count = db.execute('SELECT COUNT(*) FROM group_members WHERE group_id = ?', group[0]['id'])[0]['COUNT(*)']

    member_check = db.execute('SELECT * FROM group_members WHERE user_id = ? and group_id = ?', session['user_id'], group[0]['id'])

    if member_check:
        
        return render_template('group.html', group = group, member_count = member_count, button = 'leave', posts = posts, user = user, comments = comments)

    return render_template('group.html', group = group, member_count = member_count, button = 'join', posts = posts, user=user, comments = comments)

@app.route("/groups/<group_name>/post", methods = ['GET', 'POST'])
def post(group_name):
    session['access_token'] = get_access_token()

    if request.method == 'POST':
        song = request.form.get('song', None)
        album = request.form.get('album', None)

        if song:
            tracks = search_items(type='track', name=song)
            return render_template('post.html', group_name = group_name, type = 'track', results = tracks)
        
        elif album:
            albums = search_items(type='album', name=album)
            return render_template('post.html', group_name = group_name, type = 'album', results = albums)


    return render_template('post.html', group_name = group_name)

@app.route("/logout")
def logout():

    # Clear session
    session.clear()

    # Redirects user to login page
    return redirect("/")