from flask import render_template, request, session, jsonify, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, ValidationError, EqualTo
from flask import Flask, request, abort, send_file
from flask import redirect
from app import app, db
from models import User, Message, ChatRoom, cipher_suite, GroupInvite
import uuid
from datetime import datetime, timedelta
import logging
import os
import re
import time
from flask_cors import CORS
import sqlite3
import json
import secrets
#to make sure that jinja doesnt give out error nightmares :)
@app.context_processor
def inject_blocking_utils():
    return dict(is_blocked=is_blocked)


#for render :)
@app.route('/idkwhattonamethis')
def idkwhatoputhereeither():
    return 'OK', 200


#sussy code
BLOCKED_USERS_FILE = "blocked_users.json"

# load the people the user doesnt like
def load_blocked_users():
    if not os.path.exists(BLOCKED_USERS_FILE):
        return {}
    with open(BLOCKED_USERS_FILE, "r") as f:
        return json.load(f)

# save blocked users if user hates more people
def save_blocked_users(data):
    with open(BLOCKED_USERS_FILE, "w") as f:
        json.dump(data, f)

# do some funky stuff
def is_blocked(viewer_id, sender_id):
    data = load_blocked_users()
    blocked_list = data.get(str(viewer_id), [])
    return str(sender_id) in blocked_list

@app.before_request
def redirect_to_custom_domain():
    if request.host == "socialtap-webapp.onrender.com":
        return redirect("https://socialtap.social/updateapp", code=301)



@app.before_request
def countdown_check():
    if current_user.is_authenticated and current_user.is_admin():
        return

    # Define pages that everyone should be able to access
    allowed_endpoints = [
        'login',
        'static',     
        'countdown',    
        'idkwhatoputhereeither' 
    ]

    # 3. If the requested page is not in the allowed list, redirect to the countdown.
    if request.endpoint not in allowed_endpoints:
        return redirect(url_for('countdown'))


@app.before_request
def check_if_banned():
    if current_user.is_authenticated and current_user.is_banned:
        # Allow access to logout or banned page itself to avoid redirect loops
        allowed_paths = [url_for('logout'), url_for('banned')]
        if request.path in allowed_paths or request.path.startswith('/static/'):
            return None
        
        if request.path.startswith('/api/'):
            return "You are banned.", 403
        
        return redirect(url_for('banned'))
# Block a user
def block_user(viewer_id, sender_id):
    data = load_blocked_users()
    if str(viewer_id) not in data:
        data[str(viewer_id)] = []
    if str(sender_id) not in data[str(viewer_id)]:
        data[str(viewer_id)].append(str(sender_id))
        save_blocked_users(data)

# Unblock a user
def unblock_user(viewer_id, sender_id):
    data = load_blocked_users()
    if str(viewer_id) in data and str(sender_id) in data[str(viewer_id)]:
        data[str(viewer_id)].remove(str(sender_id))
        save_blocked_users(data)

logging.basicConfig(level=logging.DEBUG)

CORS(app)
DB_PATH = "/data/app.db"


#These WP bots thinking I'm using WP are getting pretty annoying
@app.before_request
def block_bad_paths():
    if request.path.startswith('/wp-admin/'):
        print(f"[INFO] Bot attempt blocked from IP: {request.remote_addr}, User-Agent: {request.user_agent.string}")
        time.sleep(5)
        return '', 204

@app.route('/userinvite')
def user_invite():
    inviter = request.args.get('from', 'Someone')
    return render_template('invite.html', inviter=inviter)


# Load blacklist words
BLACKLIST_WORDS = set()
try:
    if os.path.exists('blacklist.txt'):
        with open('blacklist.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    BLACKLIST_WORDS.add(line.lower())
        logging.info(f"Loaded {len(BLACKLIST_WORDS)} words to blacklist")
except Exception as e:
    logging.error(f"Failed to load blacklist: {str(e)}")

def contains_blacklisted_words(text):
    """Check if text contains any blacklisted words"""
    if not text:
        return False, []
    
    text_lower = text.lower()
    found_words = []
    
    # Check for exact matches (with word boundaries)
    for word in BLACKLIST_WORDS:
        pattern = r'\b' + re.escape(word) + r'\b'
        if re.search(pattern, text_lower):
            found_words.append(word)
    
    return bool(found_words), found_words

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=15)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(min=3, max=70)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=30)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken.')

    def validate_email(self, email):
        try:
            # Check if any user already has this email
            user = User.query.filter_by(_email=cipher_suite.encrypt(email.data.encode()).decode()).first()
            if user:
                raise ValidationError('Email already registered.')
        except Exception as e:
            logging.error(f"Error validating email: {str(e)}")
            raise ValidationError('Error validating email. Please try again.')
            
class DeleteAccountForm(FlaskForm):
    confirm_delete = BooleanField('I understand this action cannot be undone', validators=[DataRequired()])
    submit = SubmitField('Delete Account')

# MODIFIED: Changed route to a specific path
@app.route("/countdown")
def countdown():
    return render_template("thisisacountdown.html")

# REMOVED: This route blocked all pages, including login, and is replaced by the new `countdown_check` function.
# @app.route("/<path:subpath>")
# def redirect_to_countdown(subpath):
#     return redirect("/")

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Update last seen timestamp
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Get all chat rooms the user is part of
    chat_rooms = current_user.chats.all()
    
    return render_template('index.html', 
                          username=current_user.username, 
                          chat_rooms=chat_rooms,
                          active_chat_id=None,
                          current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        try:
            # Get all users and compare decrypted emails
            users = User.query.all()
            user = next((u for u in users if u.email == form.email.data), None)

            if user and user.check_password(form.password.data):
                login_user(user)
                return redirect(url_for('index'))
                logging.info(f"User {user.username} logged in successfully")
                return redirect(url_for('index'))
            flash('Invalid email or password')
            logging.warning(f"Failed login attempt for email: {form.email.data}")
        except Exception as e:
            logging.error(f"Login error: {str(e)}", exc_info=True)
            flash('An error occurred during login. Please try again.')
    return render_template('login.html', form=form)

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or request.form  # supports JSON or form-encoded
    email = data.get('username') or data.get('email') 
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    try:
        users = User.query.all()
        user = next((u for u in users if u.email == email), None)

        if user and user.check_password(password):
            login_user(user)
            return jsonify({'success': True, 'username': user.username})
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logging.error(f"/api/login error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Server error'}), 500


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data

        # Max length check
        if len(username) > 15:
            logging.warning(f"Blocked registration attempt (too long): {username}")
            return redirect('https://socialtap.social/regreq')

        # Invalid character check (only a-z, A-Z, 0-9, _)
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            logging.warning(f"Blocked registration attempt (invalid characters): {username}")
            return redirect('https://socialtap.social/regreq')

        # Blacklist check (case insensitive)
        lower_username = username.lower()
        for word in BLACKLIST_WORDS:
            if word in lower_username:
                logging.warning(f"Blocked registration attempt (blacklisted word): {username}")
                return redirect('https://socialtap.social/regreq')

        try:
            user = User(username=username)
            user.email = form.email.data  
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            logging.info(f"User registered successfully: {user.username}")
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            logging.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.')

    return render_template('register.html', form=form)

#regend
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat/<int:chat_id>')
@login_required
def view_chat(chat_id):
    chat_room = ChatRoom.query.get_or_404(chat_id)
    
    # Check if user is a participant in this chat
    if current_user not in chat_room.participants:
        flash('You do not have access to this chat room.')
        return redirect(url_for('index'))
    
    # Update last seen timestamp
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Get all chat rooms the user is part of
    chat_rooms = current_user.chats.all()
    
    return render_template('index.html', 
                          username=current_user.username, 
                          chat_rooms=chat_rooms,
                          active_chat_id=chat_id,
                          current_user=current_user)

@app.route('/messages')
@login_required
def get_messages():
    chat_id = request.args.get('chat_id', type=int)
    fetch_all = request.args.get('fetchall', default="false").lower() == "true"

    if chat_id:
        # Get messages for a specific chat room
        chat_room = ChatRoom.query.get_or_404(chat_id)
        if current_user not in chat_room.participants:
            return jsonify({'error': 'Access denied'}), 403
            
        base_query = Message.query.filter_by(chat_room_id=chat_id)
    else:
        # Get messages for the global chat (messages without a chat_room_id)
        base_query = Message.query.filter_by(chat_room_id=None)

    if fetch_all:
        messages = base_query.order_by(Message.timestamp.asc()).all()
    else:
        # last 178, but still sorted ascending
        subquery = base_query.order_by(Message.timestamp.desc()).limit(178).subquery()
        messages = Message.query.from_statement(
            db.select(subquery).order_by(subquery.c.timestamp.asc())
        ).all()

    return jsonify([{
    'id': msg.id,
    'content': msg.content,
    'username': msg.author.username,
    'timestamp': msg.timestamp.strftime('%H:%M'),
    'badges': msg.author.badges or []
} for msg in messages])

    return jsonify([{
    'id': msg.id,
    'content': msg.content,
    'username': msg.author.username,
    'timestamp': msg.timestamp.strftime('%H:%M'),
    'badges': msg.author.badges or []
} for msg in messages])


@app.route('/send', methods=['POST'])
@login_required
def send_message():
    content = request.form.get('message', '').strip()
    chat_id = request.form.get('chat_id', type=int)
    
    if not content:
        return jsonify({'error': 'Message cannot be empty'}), 400
        
    # Check cooldown
    now = datetime.utcnow()
    last_message = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp.desc()).first()
    if last_message and (now - last_message.timestamp).total_seconds() < 2:
        return jsonify({'error': 'Please wait 2 seconds between messages'}), 429
    
    # Check for blacklisted words
    has_blacklisted, found_words = contains_blacklisted_words(content)
    if has_blacklisted:
        logging.warning(f"User {current_user.username} attempted to send message with blacklisted words: {', '.join(found_words)}")
        return jsonify({
            'error': 'Your message contains inappropriate language',
            'blacklisted_words': found_words
        }), 400
        
        content = request.form["message"]
    if len(content) > 500:
        return "Message too long (max 500 characters)", 400
    # Update user's last seen timestamp
    current_user.last_seen = datetime.utcnow()
    
    if chat_id:
        # Check if user has access to this chat room
        chat_room = ChatRoom.query.get_or_404(chat_id)
        if current_user not in chat_room.participants:
            return jsonify({'error': 'Access denied'}), 403
            
        message = Message(content=content, author=current_user, chat_room=chat_room)
    else:
        # Send to global chat
        message = Message(content=content, author=current_user)
    
    db.session.add(message)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': {
            'id': message.id,
            'content': message.content,
            'username': current_user.username,
            'timestamp': message.timestamp.strftime('%H:%M')
        }
    })

@app.route('/api/users')
@login_required
def get_users():
    # Update user's last seen timestamp
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Get all users except current user
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(
        User.id != current_user.id,
        User.last_seen >= five_minutes_ago
    ).all()
    
    return jsonify([{
    'id': user.id,
    'username': user.username,
    'badges': user.badges or []
} for user in online_users])

@app.route('/api/chats')
@login_required
def get_chats():
    # Update user's last seen timestamp
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Get all chat rooms the user is part of
    chat_rooms = current_user.chats.all()
    
    return jsonify([chat.to_dict() for chat in chat_rooms])

@app.route('/api/chats/create', methods=['POST'])
@login_required
def create_chat():
    data = request.get_json()
    user_ids = data.get('user_ids')  # list of user IDs
    chat_name = data.get('name', '').strip()

    if not user_ids or not isinstance(user_ids, list):
        return jsonify({'error': 'User IDs are required'}), 400

    # cu
    if current_user.id not in user_ids:
        user_ids.append(current_user.id)

    # all users must be alive
    users = User.query.filter(User.id.in_(user_ids)).all()
    if len(users) != len(user_ids):
        return jsonify({'error': 'One or more user IDs are invalid'}), 400

    # dm stuff
    if len(user_ids) == 2:
        other_user_id = next(uid for uid in user_ids if uid != current_user.id)
        existing_chats = current_user.chats.all()
        for chat in existing_chats:
            if other_user_id in [u.id for u in chat.participants] and len(list(chat.participants)) == 2:
                return jsonify({'success': True, 'chat': chat.to_dict()})

        # No existing DM chat found — create one
        other_user = User.query.get(other_user_id)
        dm_name = f"Chat with {other_user.username}"
        chat_room = ChatRoom(name=dm_name, is_private=True)
        chat_room.participants.extend(users)
        db.session.add(chat_room)
        db.session.commit()
        return jsonify({'success': True, 'chat': chat_room.to_dict()})

    # Handle group chat
    if not chat_name:
        return jsonify({'error': 'Group chat name is required'}), 400

    chat_room = ChatRoom(name=chat_name, is_private=False) 
    chat_room.participants.extend(users)

    db.session.add(chat_room)
    db.session.commit()

    return jsonify({'success': True, 'chat': chat_room.to_dict()})  
    db.session.commit()
    
    return jsonify({
        'success': True,
        'chat': chat_room.to_dict()
    })

@app.route('/api/user/offline', methods=['POST'])
@login_required
def set_user_offline():
    # Set the user's last_seen time to a time in the past (more than 5 minutes ago)
    current_user.last_seen = datetime.utcnow() - timedelta(minutes=10)
    db.session.commit()
    
    return '', 204  # Return empty response with HTTP 204 (No Content)

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    # Update last seen timestamp
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    delete_form = DeleteAccountForm()
    
    return render_template('profile.html', user=current_user, delete_form=delete_form)
    
@app.route('/confirm-google-delete')
@login_required
def confirm_google_delete():
    if not current_user.is_google_user:
        flash('This action is only available for Google-authenticated users.', 'danger')
        return redirect(url_for('profile'))
        
    # Create a simple confirmation form
    class ConfirmGoogleDeleteForm(FlaskForm):
        confirm_delete = BooleanField('I understand this action cannot be undone', validators=[DataRequired()])
        submit = SubmitField('Delete My Account')
        
    form = ConfirmGoogleDeleteForm()
    
    return render_template('confirm_google_delete.html', form=form, user=current_user)
    
@app.route('/execute-google-delete', methods=['POST'])
@login_required
def execute_google_delete():
    if not current_user.is_google_user:
        flash('This action is only available for Google-authenticated users.', 'danger')
        return redirect(url_for('profile'))
        
    # Create a simple confirmation form
    class ConfirmGoogleDeleteForm(FlaskForm):
        confirm_delete = BooleanField('I understand this action cannot be undone', validators=[DataRequired()])
        submit = SubmitField('Delete My Account')
        
    form = ConfirmGoogleDeleteForm()
    
    if form.validate_on_submit():
        user_id = current_user.id
        user_username = current_user.username
        
        try:
            # Remove user from all chat participants
            for chat in current_user.chats:
                # If this is a private chat and only 2 participants, delete the entire chat
                if chat.is_private and chat.participants.count() <= 2:
                    # Delete all messages in
