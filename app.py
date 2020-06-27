import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
#from flask_mail import Mail, Message 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
#import datetime as dt
#import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'os.getenv("APP_KEY")'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/USER/Desktop/Web Programming With Python And JAVA Script/Lecture 4 - ORMs And APIs/project1/project1/venv/Users.db'
app.config['USER_APP_NAME'] = 'My App!'
app.config['USER_AFTER_REGISTER_ENDPOINT'] = 'login'
#app.config.from_pyfile('config.cfg')
bootstrap = Bootstrap(app)
#mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

s = URLSafeTimedSerializer('os.getenv("APP_KEY")')

#s = URLSafeTimedSerializer('os.getenv("APP_KEY")')

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(35))
    username = db.Column(db.String(30), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    confirmed = db.Column(db.DateTime())

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class LogInForm(FlaskForm):
	username = StringField('Username', validators=[InputRequired(), Length(min=4, max=30)])
	password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
	remember = BooleanField('Remember Me')

class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=4, max=30)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=4, max=35)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=30)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords Must Match')])
    accept = BooleanField('I have read and agreed to the <a href="#">Terms And Condtions</a>', validators=[InputRequired(message='This is required')])

class RequestPasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=50)])

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords Must Match')])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LogInForm()

	if form.validate_on_submit():
		users = Users.query.filter_by(username=form.username.data).first()
		if users:
			if check_password_hash(users.password, form.password.data):
				login_user(users, remember=form.remember.data)
				return redirect(url_for('dashboard'))

		return '<h1>Invalid Username Or Password</h1>'
		#return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

	return render_template('login.html', form=form)

@app.route('/signup', methods=['GET','POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():

        users = Users.query.filter_by(username=form.username.data).first()
        if users:
            raise ValidationError('The username name is not available. Please choose a different username.')

        users = Users.query.filter_by(email=form.email.data).first()
        if users:
            raise ValidationError('The email address you entered is currently associated with an account. Please enter a valid email address.')

        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = Users(first_name=form.first_name.data, last_name=form.last_name.data, username=form.username.data, email=form.email.data, password=hashed_password)

        email = request.form['email']
        token = s.dumps(email, salt='confirm-email')

        msg = MIMEMultipart()
        msg['From'] = "os.getenv(""DO_NOT_REPLY"")"
        msg['To'] = "email"
        password = "os.getenv(""MAIL_APP_PASS"")"
        msg['Subject'] = "Confirm Email"
        #msg['Date'] = formatdate(self.date, localtime=True)

        link = url_for('confirm_email', token=token, _external=True)

        body = 'Confirm your account here {}'.format(link)
        msg.attach(MIMEText(body, 'html'))
        print(msg)

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(os.getenv("DO_NOT_REPLY"), os.getenv("MAIL_APP_PASS"))
        server.sendmail(os.getenv("DO_NOT_REPLY"), email, msg.as_string())
        server.quit()

        #message = "Confirm email"
        #server = smtplib.SMTP("smtp.gmail.com", 587)
        #server.starttls()
        #server.login(os.getenv("DO_NOT_REPLY"), os.getenv("MAIL_APP_PASS"))
        #server.sendmail(os.getenv("DO_NOT_REPLY"), email, message)

        db.session.add(new_user)
        db.session.commit()

        #return '<h1>Your email is {}. The token is {}</h1>'.format(email, token)

        return '<h1>Success! Check your inbox for the confirmation link</h1>'

        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():

    form = RequestPasswordResetForm()

    if form.validate_on_submit():
        users = Users.query.filter_by(email=form.email.data).first()
        if users is None:
            raise ValidationError('The email address you entered is not associated with any account. Please register first.')
        
        email = request.form['email']
        token = s.dumps(email, salt='reset-password')

        msg = MIMEMultipart()
        msg['From'] = "os.getenv(""DO_NOT_REPLY"")"
        msg['To'] = "email"
        password = "os.getenv(""MAIL_APP_PASS"")"
        msg['Subject'] = "Reset Your Password"
        #msg['Date'] = formatdate(self.date, localtime=True)

        link = url_for('reset_password', token=token, _external=True)

        body = 'Click here to reset your password {}'.format(link)
        msg.attach(MIMEText(body, 'html'))
        print(msg)

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(os.getenv("DO_NOT_REPLY"), os.getenv("MAIL_APP_PASS"))
        server.sendmail(os.getenv("DO_NOT_REPLY"), email, msg.as_string())
        server.quit()

        #return '<h1>Invalid Username Or Password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

        return '<h1>Success! Check your inbox for the reset link</h1>'

    return render_template('request_password_reset.html', form=form)

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='confirm-email', max_age=600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    #return '<h1>The token works!</h1>'
    return redirect(url_for('login'))

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):

    form = ResetPasswordForm()

    try:
        email = s.loads(token, salt='reset-password', max_age=600) #10mins
    except SignatureExpired:
        return '<h1>The token is expired or invalid!</h1>'
    return render_template('reset_password.html', form=form)

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        
        user = Users.query.filter_by(email=email).first()  
        
        users.password = hashed_password
        db.session.commit()
        return '<h1>Success! Your account has been updated.</h1>'
        #return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

# To activate: Scripts\activate