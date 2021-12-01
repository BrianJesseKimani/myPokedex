
from flask import Flask, render_template, redirect, url_for
from flask.wrappers import Response
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from werkzeug.wrappers import response
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sassutils.wsgi import SassMiddleware
import requests


app = Flask(__name__)
app.config['SECRET_KEY'] = '3jdnsniiosecrert'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.wsgi_app = SassMiddleware(app.wsgi_app, {
    'app': ('static/sass', 'static/css', '/static/css')
})
arr = []
response = requests.get("https://pokeapi.co/api/v2/pokemon?limit=300")
response_json = response.json()
resp_array = response_json['results']
for i in resp_array:
    response = requests.get(i['url'])
    res = response.json()
    arr.append(res)



#user info table for database
#created using db.create_all() from terminal
class Users(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique = True, nullable = False)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80), nullable = False)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username',validators=[InputRequired(), Length(min=3,max=15)])
    password = PasswordField('Password', validators=[InputRequired(),Length(min=8, max=80)])
    remember = BooleanField('Remember me')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4)])
    email = StringField('Email', validators=[InputRequired(), Email(message='invalid Email'),Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(),Length(min=8,max=80)])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods= ['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(username= form.username.data).first()
        if (user and (check_password_hash(user.password,form.password.data))):
            print(form.password.data)
            login_user(user, remember = form.remember.data)
            return redirect(url_for('dashboard'))
        else:
            return "<h1>Invalid Username or Password!</h1>"       


    return render_template('login.html', form= form)

    

@app.route('/signup', methods= ['GET','POST'])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        hashed_password =generate_password_hash(form.password.data, method= 'sha256')
        new_user = Users(username= form.username.data, email= form.email.data, password= hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('index.html')

    return render_template('signup.html', form = form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name = current_user.username)

@app.route('/deck')
@login_required
def deck():
    return render_template('deck.html', name = current_user.username, pokedata = arr)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)