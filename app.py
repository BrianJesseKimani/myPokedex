
from os import name
from flask import Flask, render_template, redirect, url_for, request
from flask.helpers import flash    
from flask.wrappers import Response
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from sqlalchemy.orm import backref
from werkzeug.wrappers import response
from wtforms import StringField, PasswordField, BooleanField
from wtforms.fields.simple import SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sassutils.wsgi import SassMiddleware
from flask_migrate import Migrate, migrate
import requests


app = Flask(__name__)
app.config['SECRET_KEY'] = '3jdnsniiosecrert'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']  = False
Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app,db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.wsgi_app = SassMiddleware(app.wsgi_app, {
    'app': ('static/sass', 'static/css', '/static/css')
})
arr = {}
response = requests.get("https://pokeapi.co/api/v2/pokemon?limit=3")
response_json = response.json()
resp_array = response_json['results']

# for i in resp_array:
#     response = requests.get(i['url'])
#     res = response.json()
#     arr.append(res)


for i in resp_array:
    response = requests.get(i['url'])
    res = response.json()
    arr[res['name']] = response.json()




#user info table for database
#created using db.create_all() from terminal




class Users(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique = True, nullable = False)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80), nullable = False)
    coins = db.Column(db.Integer, default= 1000)
    pokemon = db.relationship('Pokemon', backref='owner')


class Pokemon(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(15), nullable = False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))

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

class BuyForm(FlaskForm):
    pokemon_name = StringField("PokemonName  ",validators=[InputRequired()])
    submit1 = SubmitField("BUY! (-50 coins)")

class SellForm(FlaskForm):
    pokemon_name = StringField("PokemonName ",validators=[InputRequired()])
    submit2 = SubmitField("SELL! (+50 coins)")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods= ['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(username= form.username.data).first()
        if (user and (check_password_hash(user.password,form.password.data))):
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
        new_user = Users(username= form.username.data, email= form.email.data, password= hashed_password, coins=10000)
        db.session.add(new_user)
        db.session.commit()
        return render_template('index.html')

    return render_template('signup.html', form = form)

@app.route('/dashboard', methods= ['GET','POST'])
@login_required
def dashboard():
    Buyform = BuyForm()
    Sellform = SellForm()
    all_user_pokemon = Pokemon.query.filter_by(owner_id = current_user.id)

    if (request.method == "POST" and Buyform.submit1.data and Buyform.validate()):
        if current_user.coins >= 50:
            exists = Pokemon.query.filter_by(name=Buyform.pokemon_name.data, owner_id = current_user.id).first() is not None
            if (exists):
                return '<h1> You already Own this Pokemon!</h1>'
            current_user.coins = current_user.coins - 50
            new_pokemon = Pokemon(name=Buyform.pokemon_name.data, owner=current_user)
            db.session.add(new_pokemon)
            db.session.commit()
            all_user_pokemon = Pokemon.query.filter_by(owner_id = current_user.id)
        else:
            return '<h1> Enter valid Pokemon Name or Buy more Coins</h1>'

    elif (request.method == "POST" and Sellform.submit2.data and Sellform.validate()):
        exists = Pokemon.query.filter_by(name=Sellform.pokemon_name.data, owner_id = current_user.id).first() is not None
        if not exists:
            return "<h1> Name Invalid or You Don\'t Own this Pokemon!</h1>"
        pokemon = Pokemon.query.filter_by(name=Sellform.pokemon_name.data).first()
        if pokemon.owner == current_user:
            current_user.coins = current_user.coins + 50
            db.session.delete(pokemon)
            db.session.commit()
            all_user_pokemon = Pokemon.query.filter_by(owner_id = current_user.id)
        else:
            return '<h1> You Don\'t Own this Pokemon!</h1>'
        

        
    return render_template('dashboard.html', name = current_user.username, coins = current_user.coins, my_pokemon = all_user_pokemon, pokedata=arr)

@app.route('/deck')
@login_required
def deck():
    Buyform = BuyForm()
    Sellform = SellForm()
    return render_template('deck.html', name = current_user.username, pokedata = arr, coins = current_user.coins, buyform = Buyform, sellform = Sellform)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)