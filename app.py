from enum import unique
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy



app = Flask(__name__)
app.config['SECRET_KEY'] = '3jdnsniiosecrert'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)

db = SQLAlchemy(app)


#user info table for database
#created using db.create_all() from terminal
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique = True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

class LoginForm(FlaskForm):
    username = StringField('Username',validators=[InputRequired(), Length(min=3,max=50)])
    password = PasswordField('Password', validators=[InputRequired(),Length(min=8)])
    remember = BooleanField('Remember me')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4)])
    email = StringField('Email', validators=[InputRequired(), Email(message='invalid Email'),Length(max=100)])
    password = PasswordField('Password', validators=[InputRequired(),Length(min=8,max=100)])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods= ['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(username= form.username.data).first()
        if (user and (user.password == form.password.data)):
            print(form.password.data)
            return redirect(url_for('dashboard'))
        else:
            return "<h1>Invalid Username or Password!</h1>"       


    return render_template('login.html', form= form)

@app.route('/signup', methods= ['GET','POST'])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        new_user = Users(username= form.username.data, email= form.email.data, password= form.password.data)
        db.session.add(new_user)
        db.session.commit()
        return render_template('index.html')

    return render_template('signup.html', form = form)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)