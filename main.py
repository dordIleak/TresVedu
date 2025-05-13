from flask import Flask, request, render_template, redirect, session, jsonify, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import hashlib
import re
from g4f.client import Client
from datetime import datetime, timedelta
from eventlet import lock
import eventlet
import uuid
from collections import defaultdict, deque
import random
from threading import Lock, Thread
import threading
import time
import string
import logging
import json
import redis
from flask_session import Session

eventlet.monkey_patch()

app = Flask(__name__)
app.secret_key = 'f1c3b8e4c5e0a2b7d6f1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8g9h0i1j2k3'

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='eventlet',
    transports=['websocket'],  # Только WebSocket
    logger=True,
    engineio_logger=True,
    ping_interval=15,
    ping_timeout=30,
    max_http_buffer_size=1e6,
    allow_upgrades=False,
    message_queue='redis://localhost:6379/0'# Запрет смены транспортов
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///qqqqqq.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_NAME'] = 'flask_socketio_session'
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6379/1')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 3600,
}
Session(app)
db = SQLAlchemy(app)


def init_db():
    # Rooms database
    conn = sqlite3.connect('rooms.sqlite')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS rooms
                (id INTEGER PRIMARY KEY, 
                 player1 INTEGER,  
                 player2 INTEGER,
                 status TEXT,
                 player1_progress INTEGER,
                 player2_progress INTEGER,
                 player1_current_problem INTEGER,
                 player2_current_problem INTEGER)''')

    # Создаем 1000 комнат
    c.execute('SELECT COUNT(*) FROM rooms')
    if c.fetchone()[0] < 1000:
        for i in range(1, 1001):
            c.execute('INSERT OR IGNORE INTO rooms (id, status) VALUES (?, "free")', (i,))

    # Queue database остается без изменений
    conn = sqlite3.connect('queue.sqlite')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS queue
                (non_id INTEGER PRIMARY KEY,
                 player_id INTEGER)''')
    conn.commit()
    conn.close()

init_db()

r = redis.Redis(host='localhost', port=6379, db=0)
r1 = redis.Redis(host='localhost', port=6379, db=1)
# Модель для хранения сообщений
class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

    def __repr__(self):
        return f'<Message {self.id} from user {self.user_id}>'

# Создание таблиц

class User(UserMixin):

    def __init__(self, id):
        self.id = id

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Системный промпт
SYSTEM_PROMPTS = {
    "bookchr": {
        "role": "system",
        "content": "Think about non-obvious random russian book character. You are him. Your task is to respond to the player's questions and comments as your character, without revealing your name until the player correctly guesses who you are. Respond to all questions and comments in the voice of your character, using their personality and style of communication. If the player asks a question in the format 'how would you react if...', answer it by describing your character's reaction and feelings. When the player correctly guesses who you are, acknowledge it and add '12345' at the end of your response. If the player gives up - write '54321' at the end of your next message. Write the name of this character at the end of your first response in curly brackets. Don't break character no matter what the player asks. Answer all questions only on behalf of your character, if the character couldn't know this or that information, answer on behalf of the character that you don't know."
    },
    "poet": {
        "role": "system",
        "content": "Think about random russian poet except Pushkin. You are him. Your task is to respond to the player's questions and comments as your character, without revealing your name until the player correctly guesses who you are. Respond to all questions and comments in the voice of your character, using their personality and style of communication. If the player asks a question in the format 'how would you react if...', answer it by describing your character's reaction and feelings. When the player correctly guesses who you are, acknowledge it and add '12345' at the end of your response. If the player gives up - write '54321' at the end of your next message. Write the name of this poet at the end of your first response in curly brackets. Don't break character no matter what the player asks. Answer all questions only on behalf of your character, if the character couldn't know this or that information, answer on behalf of the character that you don't know."
    },
    "historical": {
        "role": "system",
        "content": "Think about random russian historical figure (czar, scientist, military leader etc) except Petr The First, Lenin, Stalin and Suvorov. You are them. Your task is to respond to the player's questions and comments as your character, without revealing your name until the player correctly guesses who you are. Respond to all questions and comments in the voice of your character, using their personality and style of communication. If the player asks a question in the format 'how would you react if...', answer it by describing your character's reaction and feelings. When the player correctly guesses who you are, acknowledge it and add '12345' at the end of your response. If the player gives up - write '54321' at the end of your next message. Write the name of this historical figure at the end of your first response in curly brackets. Don't break character no matter what the player asks. Answer all questions only on behalf of your character, if the character couldn't know this or that information, answer on behalf of the character that you don't know."
    }
}
client = Client()
dialog_start = "НОВЫЙ ДИАЛОГ"
login = None

@app.route('/math_main')
def math_main():
    return render_template('math_main.html')


questions_per_game = 5


@socketio.on('connect')
def handle_connect():
    # Восстанавливаем сессию из куки
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if session_id:
        # Создаем новую сессию на основе полученного ID
        session.new = True
        session.permanent = True
        session.sid = session_id
    # Сохраняем ID подключения в Redis
    r.setex(f"socket:{request.sid}", 3600, 'connected')
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    try:
        user_id = current_user.id
        player_id = request.sid
        print(f"Player disconnected: {player_id}")

        Message.query.filter_by(user_id=user_id, role='system').delete()
        db.session.commit()

        # Удаляем из очереди матчмейкинга
        with r.pipeline() as pipe:
            pipe.lrem('matchmaking_queue', 0, player_id)
            pipe.execute()

    except Exception as e:
        print(f"Disconnect error: {str(e)}")

def manage_rooms(player_id):
    try:
        with r.pipeline() as pipe:
            while True:
                try:
                    pipe.watch('matchmaking_queue')
                    queued = pipe.lrange('matchmaking_queue', -1, -1)

                    if queued:
                        other_player = queued[0].decode()
                        pipe.multi()
                        pipe.rpop('matchmaking_queue')
                        room_id = f"room_{pipe.incr('room_counter')}"
                        response = pipe.execute()
                        room_id = f"room_{response[1]}"
                        return room_id, other_player
                    else:
                        pipe.multi()
                        pipe.lpush('matchmaking_queue', player_id)
                        pipe.execute()
                        return None, None
                except redis.WatchError:
                    continue
    except Exception as e:
        print(f"Error in matchmaking: {str(e)}")
        raise


def create_room(room_id, players):
    try:
        problems = generate_math_problems()
        room_data = {
            'players': json.dumps(players),
            'problems': json.dumps(problems),
            'progress': json.dumps({p: 0 for p in players})
        }
        r.hset(f'room:{room_id}', mapping=room_data)
        print(f"Created room {room_id} with players {players}")
    except Exception as e:
        print(f"Failed to create room: {str(e)}")

        with r.pipeline() as pipe:
            pipe.lpush('matchmaking_queue', players[0])
            if len(players) > 1:
                pipe.lpush('matchmaking_queue', players[1])
            pipe.execute()
        raise


@socketio.on('join_queue')
def handle_join_queue():
    try:
        print(f"Player {request.sid} joining queue")
        session['player_id'] = request.sid
        session['room_id'] = None
        session.modified = True

        room_id, other_player = manage_rooms(request.sid)

        if other_player:
            print(f"Match found: {request.sid} vs {other_player}")
            session['room_id'] = room_id
            session.modified = True
            join_room(room_id)

            try:
                create_room(room_id, [request.sid, other_player])
                send_game_start(room_id, [request.sid, other_player])
            except:
                session['room_id'] = None
                emit('error', {'message': 'Failed to create game'})
        else:
            print(f"Player {request.sid} added to queue")
            emit('waiting')

    except Exception as e:
        print(f"Join queue error: {str(e)}")
        emit('error', {'message': 'Matchmaking failed. Try again.'})

def send_game_start(room_id, players):
    room_key = f'room:{room_id}'
    problems = json.loads(r.hget(room_key, 'problems'))

    for pid in players:
        emit('game_start', {
            'problem': problems[0]['question'],
            'room_id': room_id,
            'problem_number': 1
        }, room=pid)


@socketio.on('submit_answer')
def handle_answer(data):
    try:
        player_id = request.sid
        room_id = data.get('room_id')

        # Валидация комнаты
        if not room_id or not r.exists(f'room:{room_id}'):
            return emit('error', {'message': 'Invalid room'})

        process_answer(player_id, room_id, data['answer'])

    except Exception as e:
        emit('error', {'message': 'Answer processing error'})


def process_answer(player_id, room_id, answer):
    try:
        room_key = f'room:{room_id}'
        if not r.exists(room_key):
            emit('error', {'message': 'Игра завершена'})
            return

        with r.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(room_key)


                    room_data = {k.decode(): v.decode() for k, v in pipe.hgetall(room_key).items()}

                    problems = json.loads(room_data['problems'])
                    progress = json.loads(room_data['progress'])
                    players = json.loads(room_data['players'])

                    current = progress.get(player_id, 0)

                    if current >= len(problems):
                        return

                    if int(answer) == problems[current]['answer']:
                        new_progress = current + 1
                        progress[player_id] = new_progress

                        pipe.multi()
                        pipe.hset(room_key, 'progress', json.dumps(progress))
                        pipe.execute()

                        if new_progress >= len(problems):
                            handle_game_completion(room_key, player_id, players)
                        else:
                            send_next_problem(player_id, problems, new_progress)
                            update_opponent(players, player_id, new_progress)

                    break

                except redis.WatchError:
                    continue
                except KeyError as e:
                    emit('error', {'message': 'Ошибка данных игры'})
                    break

    except Exception as e:
        logger.error(f"Ошибка обработки ответа: {str(e)}")
        emit('error', {'message': 'Ошибка сервера'})


def handle_game_completion(room_key, player_id, players):
    try:
        room_data = r.hgetall(room_key)
        progress = json.loads(room_data[b'progress'])
        problems = json.loads(room_data[b'problems'])

        all_players = json.loads(room_data[b'players'])
        total_questions = len(problems)

        for p in all_players:
            if r.exists(f"socket:{p}"):
                player_progress = progress.get(p, 0)
                opponent_progress = max(progress.get(op, 0) for op in all_players if op != p)

                result = 'win' if player_progress > opponent_progress else 'lose'
                if player_progress == opponent_progress:
                    result = 'draw'

                emit('game_result', {
                    'result': result,
                    'your_score': player_progress,
                    'opponent_score': opponent_progress,
                    'total_questions': total_questions
                }, room=p)

        r.delete(room_key)
        logger.info(f"Игра завершена в комнате {room_key}")

    except Exception as e:
        logger.error(f"Ошибка завершения игры: {str(e)}")

def generate_math_problems():
    try:
        problems = []
        for _ in range(questions_per_game):
            x1 = random.randint(-10, 10)
            x2 = random.randint(1, 10)
            znak_before_a = None
            znak_before_b = None
            b = -(x1 + x2)
            a = x1 * x2
            if x1 <= 0:
                znak_before_a = "-"
            else:
                znak_before_a = "+"
            if x1<x2:
                znak_before_b = "+"
            else:
                znak_before_b = "-"
            problem = f"x²{znak_before_b}{abs(b)}x{znak_before_a}{abs(a)}=0" if b != 0 else f"x²{znak_before_a}{abs(a)}=0"
            if x1 > x2:
                answer = x1
            else:
                answer = x2
            problems.append({'question': problem, 'answer': answer})
        return problems
    except:
        logger.error("Problem generation failed")
        raise

def send_next_problem(player_id, problems, new_progress):
    try:
        emit('next_problem', {
            'problem': problems[new_progress]['question'],
            'problem_number': new_progress + 1
        }, room=player_id)
    except IndexError:
        logger.error("Попытка получить несуществующий вопрос")

def handle_progress_update(room_id, player_id, progress):
    room_key = f'room:{room_id}'
    room_data = r.hgetall(room_key)
    players = json.loads(room_data[b'players'])

    emit('next_problem', {
        'problem': json.loads(room_data[b'problems'])[progress[player_id]]['question'],
        'problem_number': progress[player_id] + 1
    }, room=player_id)

    opponents = [p for p in players if p != player_id]
    for op in opponents:
        if r.exists(f"socket:{op}"):
            emit('opponent_progress', {'progress': progress[player_id]}, room=op)


@app.route('/tresVguess')
def home():
    return render_template('home.html')

@app.route('/')
def home_main():
    return render_template('home_main.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/about_guess')
def about_guess():
    return render_template('about_guess.html')

@app.route('/about_math')
def about_math():
    return render_template('about_math.html')

@app.route('/help')
def help():
    return render_template('catalog.html')
# ---------------------------------------------------------------------------------------------



#----------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    global login
    error_message_nosuchuser = None
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        # Хеширование пароля для проверки
        password_bytes = password.encode('utf-8')
        hash_object = hashlib.sha256()
        hash_object.update(password_bytes)
        password_hex = hash_object.hexdigest()

        connect = sqlite3.connect('ucheniki.sqlite', check_same_thread=False)
        cursor = connect.cursor()

        user_data = cursor.execute('SELECT * FROM ucheniki WHERE login=? AND password=?',
                                   (login, password_hex)).fetchone()
        connect.commit()

        if user_data:
            user_id = user_data[0]
            user = User(user_id)
            login_user(user, remember=False)

            return redirect('/')
        else:
            error_message_nosuchuser = "Такого пользователя не существует"
    return render_template('login.html', error = error_message_nosuchuser)

@app.route('/profile')
@login_required
def profile():
    error_message_unknown = None
    global login
    connect = sqlite3.connect('ucheniki.sqlite', check_same_thread=False)
    cursor = connect.cursor()

    user_id = current_user.id

    user_data = cursor.execute('SELECT * FROM ucheniki WHERE id=?', (user_id, )).fetchone()
    nameik = user_data[1]
    colvoq = user_data[3]
    connect.commit()

    return render_template('admin.html', name=nameik,  colvo=colvoq)

@app.route('/profile_ugadan')
@login_required
def profile_ugadan():
    error_message_unknown = None
    global login
    connect = sqlite3.connect('ucheniki.sqlite', check_same_thread=False)
    cursor = connect.cursor()

    user_id = current_user.id

    user_data = cursor.execute('SELECT * FROM ucheniki WHERE id=?', (user_id,)).fetchone()
    nameik = user_data[1]
    colvoq = user_data[3]
    connect.commit()

    return render_template('profile_done.html', name=nameik,  colvo=(colvoq-1))

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    global login
    error_message = None
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        password_bytes = password.encode('utf-8')

        hash_object = hashlib.sha256()
        hash_object.update(password_bytes)
        password_hex = hash_object.hexdigest()

        connect = sqlite3.connect('ucheniki.sqlite', check_same_thread=False)
        cursor = connect.cursor()
        check = cursor.execute('SELECT * FROM ucheniki WHERE login=?', (login,)).fetchone()
        if check is None:
            cursor.execute('INSERT INTO ucheniki (login, password, ugadannye_schetchik) VALUES (?, ?, ?)', (login, password_hex, 0))
            connect.commit()
        else:
            error_message = ("Такой логин уже занят!")
        if not error_message:
            return render_template('zakaz_done.html')
    return render_template('zakaz.html', error = error_message)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect('/')

@socketio.on('send_message')
def handle_send_message(data):
    try:
        if not current_user.is_authenticated:
            emit('error', {'message': 'Not authenticated'})
            return

        user_id = current_user.id
        message_content = data['message']
        character_type = data.get ('character_type', 'poet')

        existing_system = Message.query.filter_by(user_id=user_id, role='system').first()
        if existing_system:
            if (character_type == 'poet' and 'historical figure' in existing_system.content) or \
                    (character_type == 'historical' and 'poet' in existing_system.content) or \
                    (character_type == 'bookchr' and 'book character' not in existing_system.content):
                Message.query.filter_by(user_id=user_id, role='system').delete()
                db.session.commit()

        SYSTEM_PROMPT = SYSTEM_PROMPTS[character_type]

        print(f"User {user_id} sent message: {message_content}")

        user_message = Message(user_id=user_id, role='user', content=message_content)
        db.session.add(user_message)

        if not Message.query.filter_by(user_id=user_id, role='system').first():
            system_message = Message(user_id=user_id, role='system', content=SYSTEM_PROMPT['content'])
            print(f"Using prompt: {SYSTEM_PROMPT['content']}")
            db.session.add(system_message)

        db.session.commit()

        messages = Message.query.filter_by(user_id=user_id).order_by(Message.timestamp.asc()).all()
        dialogue = [{"role": msg.role, "content": msg.content} for msg in messages]

        emit('typing_started', {}, room=request.sid)
        response_content = get_assistant_response(dialogue)
        snd_to_usr = re.sub(r'\{.*?\}', '', response_content)

        assistant_message = Message(user_id=user_id, role='assistant', content=response_content)
        db.session.add(assistant_message)
        db.session.commit()

        if "12345" in response_content:
            try:
                conn = sqlite3.connect('ucheniki.sqlite')
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE ucheniki SET ugadannye_schetchik = ugadannye_schetchik + 1 WHERE id = ?',
                    (user_id,))
                conn.commit()
                conn.close()

                Message.query.filter_by(user_id=user_id).delete()
                db.session.commit()

                emit('redirect', {'url': '/profile_ugadan'}, room=request.sid)
                return
            except Exception as e:
                print(f"Database error: {str(e)}")
                emit('error', {'message': 'Database error'})
        if "54321" in response_content:
            try:
                Message.query.filter_by(user_id=user_id).delete()
                db.session.commit()
                emit('redirect', {'url': '/tresVguess'}, room=request.sid)
                return
            except Exception as e:
                print(f"Database error: {str(e)}")
                emit('error', {'message': 'Database error'})

        emit('receive_response', {
            'user_id': 'Сервер',
            'message': snd_to_usr
        }, room=request.sid)

    except Exception as e:
        print(f"Error in handle_send_message: {str(e)}")
        emit('error', {'message': str(e)})


def get_assistant_response(dialogue):
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=dialogue,
            temperature=0.7,
        )

        print(f"API response: {response}")  # Логируем ответ

        if not response.choices:
            return "API вернул пустой ответ."

        return response.choices[0].message.content
    except Exception as e:
        print(f"Error in get_assistant_response: {str(e)}")
        return "Извините, произошла ошибка при обработке вашего запроса."

@socketio.on('clear_chat')
def handle_clear_chat():
    if not current_user.is_authenticated:
        return

    user_id = current_user.id
    try:
        Message.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        emit('chat_cleared', {}, room=request.sid)
    except Exception as e:
        print(f"Error clearing chat: {str(e)}")
        emit('error', {'message': 'Ошибка очистки чата'})



if __name__ == "__main__":
    socketio.run(app, allow_unsafe_werkzeug=True)