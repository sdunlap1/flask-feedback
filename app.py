from flask import Flask, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, Email
from email_validator import validate_email, EmailNotValidError
from models import db, User, bcrypt, Feedback

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'supersecretkey'
db.init_app(app)

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(max=20)])
    password = PasswordField('Password', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=50)])
    first_name = StringField('First Name', validators=[InputRequired(), Length(max=30)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(max=30)])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(max=20)])
    password = PasswordField('Password', validators=[InputRequired()])

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('user_profile', username=session['username']))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, password=form.password.data, email=form.email.data, first_name=form.first_name.data, last_name=form.last_name.data)
        db.session.add(user)
        db.session.commit()
        session['username'] = user.username
        return redirect(url_for('user_profile', username=user.username))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('user_profile', username=session['username']))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            session['username'] = user.username
            return redirect(url_for('user_profile', username=user.username))
        flash('Invalid credentials, please try again.')
    return render_template('login.html', form=form)

@app.route('/secret')
def secret():
    if 'username' not in session:
        flash('You must be logged in to view this page.')
        return redirect(url_for('login'))
    return render_template('secret.html')

@app.route('/users/<username>')
def user_profile(username):
    if 'username' not in session or session['username'] != username:
        flash('You are not authorized to view this page.')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first_or_404()
    feedbacks = Feedback.query.filter_by(username=username).all()
    return render_template('user.html', user=user, feedbacks=feedbacks)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

class FeedbackForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(max=100)])
    content = StringField('Content', validators=[InputRequired()])

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    if 'username' not in session or session['username'] != username:
        flash('You are not authorized to view this page.')
        return redirect(url_for('login'))
    
    form = FeedbackForm()
    if form.validate_on_submit():
        feedback = Feedback(title=form.title.data, content=form.content.data, username=username)
        db.session.add(feedback)
        db.session.commit()
        return redirect(url_for('user_profile', username=username))
    
    return render_template('feedback_form.html', form=form, feedback=None)

@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' not in session or session['username'] != feedback.username:
        flash('You are not authorized to view this page.')
        return redirect(url_for('login'))
    
    form = FeedbackForm()
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        return redirect(url_for('user_profile', username=feedback.username))
    
    return render_template('feedback_form.html', form=form, feedback=feedback)

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' not in session or session['username'] != feedback.username:
        flash('You are not authorized to perform this action.')
        return redirect(url_for('login'))
    
    db.session.delete(feedback)
    db.session.commit()
    return redirect(url_for('user_profile', username=feedback.username))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='10.0.4.23', port=5000, debug=True)
