from flask import render_template, url_for, flash, redirect
from flask_blog import app, db, bcrypt, login_manager
from flask_blog.forms import RegistrationForm, LoginForm
from flask_blog.models import User, Post
from flask_login import login_user, current_user, logout_user

posts = [
    {
        "name": "Devansh",
        'age': 22,
        'Comment': 'Hello, wfh is really great.'
    },
    {
        'name': "Sid",
        'age': 21,
        'Comment': 'I am on the dark side'
    },
    {
        'name': "Archu",
        'age': 22,
        'Comment': 'I like anime. I am the anime dealer'
    },
    {
        'name': "Aakash",
        'age': 22,
        'Comment': 'I need money. A lot of money.'
    }
]


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.htm', posts=posts)


@app.route('/about')
def about():
    return render_template('about.htm', title='About')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.htm', title='Register Now', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
       user = User.query.filter_by(username=form.username.data).first()
       if user and bcrypt.check_password_hash(user.password, form.password.data):
           login_user(user)
           return redirect(url_for('home'))
       else:
            flash('Invalid credentials', 'danger')
    return render_template('login.htm', title='Log in', form=form)


@app.route('/logout', methods=['GET','POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))
