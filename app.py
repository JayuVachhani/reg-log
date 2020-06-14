import re
from flask import Flask, render_template, request, redirect, url_for, flash,session
from datetime import datetime
from flaskext.mysql import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import Form, StringField, PasswordField,SelectField
from wtforms.validators import InputRequired, Length, ValidationError


# create instance of the Flask class
# here parameter of Flask constructor is give current module's name
app = Flask(__name__)

mysql = MySQL()
app.config['SECRET_KEY'] = 'a really really really really long secret key'
# MySQL configurations
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = '1232587'
app.config['MYSQL_DATABASE_DB'] = 'casestudy'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

class RegistrationForm(Form):    
    username = StringField('Username', validators=[InputRequired(message="Username required"), Length(min=4, max=25, message="Username must be between 4 and 25 characters")])
    password = PasswordField('password', validators=[InputRequired(message="Password required"), Length(min=8, max=15, message="Password must be between 8 and 15 characters")])
    role_id = SelectField("Role",choices=[('executive'),('cashier')])


@app.route("/")
def reg():
    # passing reference of date variable
    return render_template("register.html")


# register page
@app.route("/register/",methods=['GET',"POST"])
def register():
    try:
        error = None        
    # check if request is post or not
        form = RegistrationForm(request.form)
        if request.method == "POST" and form.validate():
            print('username {0} password {1} role {2}'.format(username,password,role_id))   
        # store the user-data in variables coming from form
            username = form.username.data        
            password = form.password.data
            role_id = form.role_id.data
            print('username {0} password {1} role {2}'.format(username,password,role_id))      

            # create connection with the database
            conn = mysql.connect()
            # create cursor for connection
            cursor = conn.cursor()

            # Check if account exists in database or not
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))

            # fetch that particular user
            account = cursor.fetchone()


            # If account exists show error and validation checks
            if account:

                error = 'Account already exists!'
                return render_template('register.html',error = error,form=form)

            # regular expression        
            elif not re.match(r'[A-Za-z]+', username):
                error = 'Username must contain only characters!'
                return render_template('register.html',error = error,form=form)

            else:
            # create hashed password
                password = generate_password_hash(password)
                print('username {0}'.format(username))
                # Account doesnt exists and the form data is valid, now insert new account into accounts table
                cursor.execute('INSERT INTO users VALUES (null,%s, %s, %s)', (username,password,role))

                # commit all changes
                conn.commit()
                # after close all actions
                conn.close()
                cursor.close()
                flash('You have successfully registered!')
                return redirect(url_for('login'))
        return render_template('register.html',error = error,form=form)
    except Exception as e:
        return (str(e))
    return render_template('register.html',error = error,form=form)

@app.route("/login/",methods=['GET','POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        userpass = request.form['password']
        conn = mysql.connect()
        cursor = conn.cursor()
        result = cursor.execute("SELECT * FROM users WHERE username = %s",[username])
        # Fetch one record and return result

        if result > 0:
            data = cursor.fetchone()
            # retrieve password from database
            password = data[2]
            # retrieve id
            id_num = data[0]

            # match both hased and user password
            if sha256_crypt.verify(userpass, password):

                # if true session will be started
                session['loggedin'] = True
                session['admin'] = False

                # store user in session
                session['username'] = username
                session['id'] = id_num
                msg='Logged In Successfully!!!', 'success'
                return redirect(url_for('home'))
            else:
                msg = 'Invalid Login'
                return render_template('login.html',msg=msg)
        else:
            msg='User not found'
            return render_template('login.html',msg=msg)

    return render_template('login.html',msg=msg)


@app.route("/home/")
def home():
    # first check if user is logged in or not
    if 'loggedin' in session:
        # if true it render the request to particular destination
        return render_template("home.html")
    # if not logged in redirect to login page
    return redirect(url_for('login'))

if __name__ == "__main__":
    #we need to run our flask app using .run funtion
    #if we don't want run everytime pass the debug = True
    # it will refresh everytime whenever changes is done
    app.secret_key = 'SECRET KEY'
    
    app.run(debug=True)

