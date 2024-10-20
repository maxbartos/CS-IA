from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import random 
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MnvDrTyu765$34567890oijHBVcdE$567897654EWsdfghjMk'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    player2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    player1_score = db.Column(db.Integer, default=0)
    player2_score = db.Column(db.Integer, default=0)

class Tournament(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    participants = db.relationship('User', secondary='tournament_participants')

class TournamentParticipants(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def generate_tournament_code(length=6):
    characters = string.ascii_uppercase + string.digits
    return "".join(random.choice(characters) for _ in range(length))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    print("Reached the signup route")  # Debug statement
    if request.method == 'POST':
        print("Processing POST request")  # Debug statement
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            print('b')
            flash('Email already in use. Please log in.', 'danger')
            print("b2")
            return redirect(url_for('login'))

        if User.query.filter_by(username=username).first():
            print('a')
            flash('Username already taken. Please choose a different username.', 'danger')
            return redirect(url_for('signup'))

        if len(password) < 6:
            print('c')
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('signup'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can log in now.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=request.form.get('remember'))
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your email and password or create an account.', 'danger')
            print("d2")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/home")
@login_required
def home():
    return render_template('home.html')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
