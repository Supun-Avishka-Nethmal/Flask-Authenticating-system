from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import DataRequired, Email, ValidationError,EqualTo
import bcrypt
from flask_mysqldb import MySQL
from datetime import timedelta

app=Flask(__name__)

app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']=''
app.config['MYSQL_DB']='blog_post'
app.secret_key='my_name'
app.config["PERMENENT_SESSION_LIFETIME"]=timedelta(minutes=30)
app.permanent_session_lifetime=timedelta(minutes=30)

mysql= MySQL(app)

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password1 = PasswordField("Password", validators=[DataRequired()])
    password2 = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password1', message='Passwords must match')])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")    

@app.route('/')

@app.route('/login',methods=["GET","POST"])
def login():
   form = LoginForm()
   if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
     
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM users WHERE email=%s",(email,))
            user=cursor.fetchone()
            cursor.close()

            if user and bcrypt.checkpw(password.encode('utf-8'),user[3].encode('utf-8')):
                        session['user_id']=user[0]
                        return redirect(url_for("home"))
            else:
              flash("Invalid Email Or Password Please Check Email Or Password Again.")
              return redirect(url_for("login"))

   return render_template("login.html",form=form)

@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
            name = form.name.data
            email = form.email.data
            password1 = form.password1.data

            hash_password=bcrypt.hashpw(password1.encode('utf-8'),bcrypt.gensalt())
            
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hash_password))
            mysql.connection.commit()  
            cursor.close()

            return redirect(url_for("login"))
 
    return render_template("register.html",form=form)
@app.route('/home')
def home():
    if 'user_id' in session:
        user_id=session["user_id"]
        cursor=mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s",(user_id,))
        user=cursor.fetchone()
        cursor.execute("SELECT * FROM products")  
        products=cursor.fetchall() 

        cursor.close()
       
        if user and products:
          return render_template('home.html',user=user,products=products)
        
    
     

    return redirect(url_for('login'))
    
@app.route('/logout')    
def logout():
     session.pop('user_id',None)
     return redirect('login')

@app.route('/contactus')
def contactus():
    if 'user_id' in session:
        user_id=session["user_id"]
        cursor=mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s",(user_id,))
        user=cursor.fetchone()
        cursor.close()
        if user:
          return render_template('contactus.html')
     

    return redirect(url_for('login'))


if __name__=="__main__":
    app.run(debug=True)
