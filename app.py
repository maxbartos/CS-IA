from flask import Flask, render_template, request, redirect, flash, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import random


app = Flask(__name__)
app.secret_key = 'MYSECRETKEY'
DATABASE = 'TripleOutDatabase.db'

# Create users table if it doesn't exist
def create_users_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            tournament_wins INTEGER DEFAULT 0,
            total_points_scored INTEGER DEFAULT 0,
            total_darts_thrown INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

# Create tournaments table if it doesn't exist
def create_tournaments_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tournaments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            style TEXT NOT NULL,
            game_mode TEXT NOT NULL,
            status TEXT DEFAULT "Not Started",
            code TEXT UNIQUE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

# Create playing tournaments table if it doesn't exist
def create_playing_tournaments_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS playing_tournaments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            tournament_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (tournament_id) REFERENCES tournaments (id)
        )
    ''')
    conn.commit()
    conn.close()

def create_matches_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tournament_id INTEGER NOT NULL,
            round INTEGER NOT NULL,
            match_number INTEGER NOT NULL,
            player1 TEXT NOT NULL,
            player2 TEXT NOT NULL,
            result TEXT DEFAULT NULL,
            FOREIGN KEY (tournament_id) REFERENCES tournaments (id)
        )
    ''')
    conn.commit()
    conn.close()

create_matches_table()
create_playing_tournaments_table()
create_users_table()
create_tournaments_table()

# Login required decorator
def login_required(f):
    def wrap(*args, **kwargs): #Ensures that certain preconditions are met --> user logged in 
        if 'user_id' not in session:
            flash("You need to log in first.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__ #Renaming the name of the function to match the logged in user
    return wrap

def update_user_stats(user_id, points_scored, darts_thrown):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users
        SET total_points_scored = total_points_scored + ?, 
            total_darts_thrown = total_darts_thrown + ?
        WHERE id = ?
    ''', (points_scored, darts_thrown, user_id))
    conn.commit()
    conn.close()

@app.route('/update_stats', methods=['POST'])
@login_required
def update_stats():
    data = request.get_json()
    points_scored = data.get('points_scored', 0)
    darts_thrown = data.get('darts_thrown', 0)
    user_id = session['user_id']  # Assuming the logged-in user's ID is stored in the session

    update_user_stats(user_id, points_scored, darts_thrown)
    return jsonify({"success": True, "message": "Stats updated successfully"}) #converts python dictionaries into JSON-formatted HTTP responses

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)

        conn = sqlite3.connect(DATABASE)
        try:
            conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', 
                         (username, email, password_hash))
            conn.commit()
            flash('Account created successfully', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                flash('Username already taken', 'danger')
            elif 'email' in str(e):
                flash('Email already taken', 'danger')
            return redirect(url_for('signup'))
        finally:
            conn.close()
    return render_template('signup.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect(DATABASE)
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user is None:
            flash('Email not found', 'danger')
            return redirect(url_for('login'))
        
        if check_password_hash(user[3], password):
            session['user_id'] = user[0]
            flash('Logged in successfully', 'success')
            return redirect(url_for('home'))
        else:
            flash('Incorrect password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

# Home route with login required
@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# Profile route with login required
@app.route('/profile')
@login_required
def profile():
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('SELECT username, email, tournament_wins, total_points_scored, total_darts_thrown FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        username, email, tournament_wins, total_points, total_darts = user
        avg_points_per_dart = round(total_points / total_darts, 2) if total_darts > 0 else 0
        avg_points_per_three_darts = round(avg_points_per_dart * 3, 2) if total_darts > 0 else 0
        return render_template(
            'profile.html',
            username=username,
            email=email,
            tournament_wins=tournament_wins,
            avg_points_per_dart=avg_points_per_dart,
            avg_points_per_three_darts=avg_points_per_three_darts
        )
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('home'))

# Unified Game Page route
@app.route('/game', methods=['GET', 'POST'])
@login_required
def game():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Fetch all usernames
    cursor.execute('SELECT username FROM users')
    usernames = [row[0] for row in cursor.fetchall()]

    conn.close()
    return render_template('game.html', usernames=usernames)

# Tournaments page route
@app.route('/tournaments', methods=['GET', 'POST'])
@login_required
def tournaments():
    user_id = session['user_id']
    
    # Connect to the database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get tournaments the user is playing in
    cursor.execute('''
        SELECT t.id, t.name, t.style, t.game_mode, t.status, t.code
        FROM tournaments t
        JOIN playing_tournaments pt ON t.id = pt.tournament_id
        WHERE pt.user_id = ?
    ''', (user_id,))
    playing_tournaments = cursor.fetchall()

    # Get tournaments the user is hosting
    cursor.execute('''
        SELECT id, name, style, game_mode, status, code
        FROM tournaments
        WHERE user_id = ?
    ''', (user_id,))
    hosting_tournaments = cursor.fetchall()

    conn.close()

    return render_template(
        'tournaments.html',
        playing_tournaments=playing_tournaments,
        hosting_tournaments=hosting_tournaments
    )

# Create Tournament route
@app.route('/create_tournament', methods=['POST'])
@login_required
def create_tournament():
    user_id = session['user_id']
    name = request.form.get('name')
    style = request.form.get('style')
    game_mode = request.form.get('game_mode')

    # Generate a unique 6-digit code
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    code = None
    while True:
        code = f"{random.randint(100000, 999999)}"
        cursor.execute('SELECT * FROM tournaments WHERE code = ?', (code,))
        if cursor.fetchone() is None:
            break

    # Insert tournament into the database
    cursor.execute('''
        INSERT INTO tournaments (user_id, name, style, game_mode, code)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, name, style, game_mode, code))
    conn.commit()
    conn.close()

    flash(f"Tournament '{name}' created successfully with code {code}.", "success")
    return redirect(url_for('tournaments'))

# Tournament Details route
@app.route('/tournament_details/<int:tournament_id>')
def tournament_details(tournament_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Fetch tournament details
    cursor.execute('SELECT name, style, game_mode, status, code, id FROM tournaments WHERE id = ?', (tournament_id,))
    tournament = cursor.fetchone()

    # Ensure the tournament exists
    if not tournament:
        flash("Tournament not found.", "danger")
        return redirect(url_for('tournaments'))

    # Fetch participants
    cursor.execute('''
        SELECT u.username, u.email
        FROM playing_tournaments pt
        JOIN users u ON pt.user_id = u.id
        WHERE pt.tournament_id = ?
    ''', (tournament_id,))
    participants = cursor.fetchall()

    # Fetch matches
    cursor.execute('''
        SELECT round, match_number, player1, player2
        FROM matches
        WHERE tournament_id = ?
        ORDER BY round, match_number
    ''', (tournament_id,))
    matches = cursor.fetchall()

    conn.close()

    return render_template(
        'tournament_details.html',
        tournament=tournament,
        participants=participants,
        matches=matches,
        tournament_id=tournament_id
    )
    
@app.route('/delete_tournament/<int:tournament_id>', methods=['POST'])
@login_required
def delete_tournament(tournament_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Fetch the tournament details
    cursor.execute('SELECT name FROM tournaments WHERE id = ?', (tournament_id,))
    tournament = cursor.fetchone()

    if not tournament:
        flash("Tournament not found.", "danger")
        conn.close()
        return redirect(url_for('tournaments'))

    # Fetch the winner from the form data
    winner = request.form.get('winner')
    if not winner:
        cursor.execute('DELETE FROM tournaments WHERE id = ?', (tournament_id,))
        conn.commit()
        conn.close()
        return redirect(url_for('tournaments'))

    # Increment the winner's tournament_wins
    cursor.execute('SELECT id FROM users WHERE username = ?', (winner,))
    user = cursor.fetchone()

    if not user:
        flash("Winner not found in the system.", "danger")
        conn.close()
        return redirect(url_for('tournament_details', tournament_id=tournament_id))

    winner_id = user[0]
    cursor.execute('''
        UPDATE users
        SET tournament_wins = tournament_wins + 1
        WHERE id = ?
    ''', (winner_id,))

    # Delete the tournament
    cursor.execute('DELETE FROM tournaments WHERE id = ?', (tournament_id,))
    conn.commit()
    conn.close()

    flash(f"Tournament '{tournament[0]}' finished and deleted. Winner: {winner}.", "success")
    return redirect(url_for('tournaments'))

@app.route('/join_tournament', methods=['POST'])
@login_required
def join_tournament():
    user_id = session['user_id']
    tournament_code = request.form['tournament_code']

    # Check if a tournament with the given code exists
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tournaments WHERE code = ?', (tournament_code,))
    tournament = cursor.fetchone()

    if tournament:
        # Check if the user is already playing in this tournament
        cursor.execute('SELECT * FROM playing_tournaments WHERE user_id = ? AND tournament_id = ?', (user_id, tournament[0]))
        already_joined = cursor.fetchone()

        if not already_joined:
            # Add the user to the playing_tournaments table
            cursor.execute('INSERT INTO playing_tournaments (user_id, tournament_id) VALUES (?, ?)', (user_id, tournament[0]))
            conn.commit()
            flash('Successfully joined the tournament!', 'success')
        else:
            flash('You are already playing in this tournament.', 'info')
    else:
        flash('No tournament found with the given code.', 'danger')

    conn.close()
    return redirect(url_for('tournaments'))

@app.route('/start_tournament/<int:tournament_id>', methods=['POST'])
@login_required
def start_tournament(tournament_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Fetch the tournament details
    cursor.execute('SELECT style FROM tournaments WHERE id = ?', (tournament_id,))
    tournament = cursor.fetchone()

    if not tournament:
        flash("Tournament not found.", "danger")
        conn.close()
        return redirect(url_for('tournaments'))

    style = tournament[0]

    # Fetch participants
    cursor.execute('''
        SELECT users.username
        FROM playing_tournaments
        JOIN users ON playing_tournaments.user_id = users.id
        WHERE playing_tournaments.tournament_id = ?
    ''', (tournament_id,))
    participants = [row[0] for row in cursor.fetchall()]

    participant_count = len(participants)

    # Prevent tournament start with fewer than 2 participants
    if participant_count < 2:
        flash("A tournament requires at least two participants to start.", "warning")
        conn.close()
        return redirect(url_for('tournaments'))

    matches = []

    if style == 'knockout':
        # Calculate the next power of 2 greater than or equal to participant_count
        num_rounds = 1
        while 2**num_rounds < participant_count:
            num_rounds += 1
        total_slots = 2**num_rounds

        # Add "byes" for participants who advance automatically
        participants += ["Bye"] * (total_slots - participant_count)

        # Generate matches for the first round
        current_round = 1
        match_number = 1
        current_matches = [(participants[i], participants[i+1]) for i in range(0, len(participants), 2)]

        while current_matches:
            next_matches = []
            for player1, player2 in current_matches:
                matches.append((current_round, match_number, player1, player2))
                if player1 != "Bye" and player2 != "Bye":
                    next_matches.append((f"Match {match_number}", f"Match {match_number + 1}"))
                elif player1 != "Bye":
                    next_matches.append((player1, f"Match {match_number + 1}"))
                elif player2 != "Bye":
                    next_matches.append((player2, f"Match {match_number + 1}"))
                match_number += 1
            current_round += 1
            current_matches = next_matches[:len(next_matches) // 2]

    elif style == 'league':
        # League format: round-robin
        match_number = 1
        for i in range(len(participants)):
            for j in range(i + 1, len(participants)):
                matches.append((1, match_number, participants[i], participants[j]))
                match_number += 1

    # Insert matches into the database
    for match in matches:
        cursor.execute('''
            INSERT INTO matches (tournament_id, round, match_number, player1, player2)
            VALUES (?, ?, ?, ?, ?)
        ''', (tournament_id, match[0], match[1], match[2], match[3]))

    # Update tournament status and code
    cursor.execute('''
        UPDATE tournaments
        SET status = "Ongoing", code = ?
        WHERE id = ?
    ''', (''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=6)), tournament_id))
    conn.commit()
    conn.close()

    flash("Tournament started successfully!", "success")
    return redirect(url_for('tournament_details', tournament_id=tournament_id))

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
