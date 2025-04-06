from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
import mysql.connector
import MySQLdb.cursors
import re
app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Kunal@8438'
app.config['MYSQL_DB'] = 'registrationdata'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)

class RegisterForm(FlaskForm):
    name= StringField("Name",validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = StringField("Password",validators=[DataRequired()])
    submit =SubmitField("Register")

@app.route('/')
def hello_world():
    return render_template('index.html')
    #return 'Hello, World!'

"""@app.route('/register')
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())

        #store data into database 
        cursor = mysql.connection,cursor()
        cursor.execute("INSERT INTO users (name,email,password) VALUES(%s,%s,%s)",(name,email,password))
        mysql.connect.commit()
        cursor.close()

        return redirect(url_for('login'))
    
    
    
    return render_template('register.html')"""

@app.route('/login', methods=['GET','POST'])
def login():
    msg = ''
    """if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
    
     username = request.form['username']
     password = request.form['password']
     cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
     cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username,password))   
     account = cursor.fetchone()
    if account:
       session['loggedin'] =True
       session['id'] = account['id']
       session['username'] = account['username']
       return render_template('index.html', 
        msg='Logged in successfully!')
    else: msg ='Incorrect username/password!'"""
    return render_template('login.html', msg=msg)

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))

        account = cursor.fetchone()
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only letters and numbers!'
        elif not username or not password or not email:  
            msg = 'Please fill out the form!'
        else:
            cursor.execute('INSERT INTO accounts (username, password, email) VALUES("%s", "%s", "%s")', (username, password, email))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
        
    return render_template('register.html', msg=msg)        

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')












if __name__ == "__main__":
    app.run(debug=True)