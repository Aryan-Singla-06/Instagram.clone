from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from datetime import timedelta
import bcrypt
import time

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///Insta.db"
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)

db = SQLAlchemy(app)

class Insta(db.Model):
    sno = db.Column(db.Integer , primary_key=True)
    username = db.Column(db.String(200) , nullable=False)
    fullname = db.Column(db.String(200) , nullable=False)
    email = db.Column(db.String(500) , nullable=False)
    password = db.Column(db.String(200) , nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    fullname = StringField('fullname', validators=[DataRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')
   
    def validate_username(self, username):
        user = Insta.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')

    def validate_email(self, email):
        user = Insta.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different one.')

@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = Insta(username=username,fullname=fullname, email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration Successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', time=int(time.time()))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if email:
            user = Insta.query.filter_by(email=email).first()
        else:
            user = None
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            session.permanent = True  # Make session permanent
            session['user_id'] = user.sno  # Store user ID in session
            session['username'] = user.username  # Store username in session

            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('')
    return render_template('login.html', time=int(time.time()))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
      flash('Session expired! Please log in again.', 'danger')
      return redirect(url_for('login'))

    return render_template('dashboard.html')

if __name__=="__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True) 
