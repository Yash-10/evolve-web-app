import os
from flask import Flask, render_template, request, redirect, session, flash
from flask_session import Session
from cs50 import SQL
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from helpers import login_required
import datetime

# Setup the Flask app
app = Flask(__name__)

# Ensure templates are reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem instead of signed cookies
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db_user = os.environ.get('DB_USER')
db = SQL(db_user)

@app.route("/login", methods=["GET", "POST"])
def login():
    """ Log user in """

    # Forget any user_id
    session.clear()

    if request.method == "GET":
        return render_template("login.html")
    else:
        name_login = request.form.get("name_login")
        email_login = request.form.get("email_login")
        password_login = request.form.get("password_login")

        rows = db.execute("SELECT * FROM users WHERE name=:username AND email=:email", username=name_login, email=email_login)

        # Error checking
        if len(rows) != 1:
            flash("User doesn't exist!", "danger")
            return redirect("/home")

        elif not check_password_hash(rows[0]["hash"], password_login):
            flash("Wrong password entered!", "danger")
            return redirect("/home")

        # If no errors, log in the user
        else:
            session["user_id"] = rows[0]["id"] # Remember which user has logged in

            flash("Succesfully Logged in!", "success")

            return redirect("/")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """ Log user out """

    # Forget any user_id
    session.clear()

    flash("Successfully Logged out!", "success")

    return redirect("/home")

# Create list's to store data
my_post = []
my_title = []
my_time = []
my_likes = []

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """ Show only current logged in user's posts """

    if request.method == "GET":
        row_index = db.execute("SELECT names, text, title, time, like FROM blogs WHERE id=:userid AND text IS NOT NULL ORDER BY time DESC", userid=session["user_id"])

        name_nav = db.execute("SELECT names FROM blogs WHERE id=:userid", userid=session["user_id"])

        #print(row_index)
        length_of_my_blogs = len(row_index)

        # Store the name of the current user who is logged in
        session["username"] = name_nav[0]["names"]

        if length_of_my_blogs == 0:
            # Tracking a boolean 'show' if no posts by the current user and show a message
            show = False
            return render_template("index.html", row_index=row_index, show=show, length_of_my_blogs=length_of_my_blogs)
        else:
            # If atleast one post by the user, show all the posts
            show = True
            my_name = row_index[0]["names"]

            for i in range(length_of_my_blogs):
                my_post.append(row_index[i]["text"])
                my_title.append(row_index[i]["title"])
                my_time.append(row_index[i]["time"])
                my_likes.append(row_index[i]["like"])

            return render_template("index.html", row_index=row_index, show=show, length_of_my_blogs=length_of_my_blogs)

    else:

        # Handle deletion of post
        blog_to_delete = request.form.get("to_delete")

        db.execute("DELETE FROM blogs WHERE text=:blog_delete AND id=:userid", blog_delete=blog_to_delete, userid=session["user_id"])

        flash("Your message is successfully deleted", "success")

        return redirect("/")


@app.route("/home")
def home():
    """ Show the homepage """
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """ Register user """

    if request.method == "GET":
        return render_template("register.html")
    else:
        name = request.form.get("name_register")
        email = request.form.get("email_register")
        password = request.form.get("password_register")
        confirm_password = request.form.get("confirm_password")
        question = request.form.get("question_register")

        # Hash the password using the 'pbkdf2:sha256' method
        hash_pw = generate_password_hash(password, method='pbkdf2:sha256')

        # Error checking
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect("/register")

        rows1 = db.execute("SELECT * FROM users WHERE name=:username", username=name)
        rows2 = db.execute("SELECT * FROM users WHERE email=:email", email=email)
        rows3 = db.execute("SELECT hash FROM users WHERE hash=:hash_password", hash_password=hash_pw)
        rows4 = db.execute("SELECT * FROM users WHERE question=:question", question=question)

        query = db.execute("SELECT hash FROM users")

        # Error checking
        for i in range(len(query)):
            if len(rows3) == 0 and check_password_hash(query[i]["hash"], password):
                flash("User already exists - Password same!", "danger")
                return redirect("/register")

        if len(rows1) != 0 or len(rows2) != 0:
            flash("User already exists!", "danger")
            return redirect("/register")

        elif len(rows4) != 0:
            flash("Answer to the identity question is already taken. Please choose a different answer!", "danger")
            return redirect("/register")

        # If no error, register the user
        else:

            db.execute("INSERT INTO users (name, email, hash, question) VALUES (:name, :email, :hash_pw, :question)", name=name, email=email, hash_pw=hash_pw, question=question)
            ids = db.execute("SELECT id FROM users WHERE name=:name", name=name)
            ids = ids[0]["id"]

            db.execute("INSERT INTO blogs (id, names, email) VALUES (:ids, :name, :email)", ids=ids, name=name, email=email)

            flash("Successfully Registered!", "success")
            return redirect("/")


@app.route("/create_post", methods=["GET", "POST"])
@login_required
def create_post():
    """ Allow the user to create a post """

    if request.method == "GET":
        return render_template("post.html")
    else:
        title_of_post = request.form.get("title_post")
        content_of_post = request.form.get("content_post")

        # Error checking
        if not title_of_post or not content_of_post:
            flash("Title or/and Content not specified!", "danger")
            return redirect("/create_post")

        # If no error, create the post successfully
        else:
            id_user = session["user_id"]

            name = db.execute("SELECT name FROM users WHERE id=:ids", ids=id_user)
            name = name[0]["name"]

            times = datetime.datetime.now()
            string_time = str(times)
            date_ = string_time[8:10]
            month_ = string_time[5:7]

            year_ = string_time[0:4]
            final_time = datetime(f"{date_} {month_} {year_}")

            db.execute("INSERT INTO blogs (names, id, text, title, time) VALUES (:name, :user_id, :texts, :titles, :time)", name=name, user_id=session["user_id"], texts=content_of_post, titles=title_of_post, time=times)

            return redirect("/display_posts")

# Store data in lists
likes_list = []
texts = []
title = []
usernames = []
time_of_post = []
date_of_post = []

@app.route("/display_posts", methods=["GET", "POST"])
@login_required
def display_posts():
    """ Display everyone's posts """

    if request.method == "GET":
        posts = db.execute("SELECT names, text, title, like, time FROM blogs WHERE text IS NOT NULL ORDER BY time DESC")
        posts_noposts = db.execute("SELECT names, text, title, like, time FROM blogs")
        is_current_user = db.execute("SELECT names FROM blogs WHERE id=:userid", userid=session["user_id"])

        length_of_all_posts = len(posts)

        for i in range(len(posts)):
            texts.append(posts[i]["text"])
            title.append(posts[i]["title"])
            usernames.append(posts[i]["names"])
            time_of_post.append(posts[i]["time"])
            likes_list.append(posts[i]["like"])

        return render_template("show_posts.html", posts=posts, texts=texts, title=title, length_of_all_posts=length_of_all_posts, usernames=usernames, time_of_post=time_of_post, likes_list=likes_list)

    else:
        # Handle the logic of liking a post

        like_blog = request.form.get("to_like")
        like_for_one = request.form.get("to_like_blog")
        like_for_one1 = request.form.get("to_like_blog_title")

        db.execute("UPDATE blogs SET like = like + 1 WHERE text=:blog_one AND title=:title", blog_one=like_for_one, title=like_for_one1)

        select = db.execute("SELECT * FROM blogs WHERE text=:blog_one AND title=:title", blog_one=like_for_one, title=like_for_one1)

        is_my_name = db.execute("SELECT names FROM blogs WHERE id=:userid", userid=session["user_id"])

        name = select[0]["names"]

        # Display message after liking the post
        # If liked other posts...
        if name != is_my_name[0]["names"]:
            flash("You liked a blog by {}!".format(name), "success")

        # If liked my own posts...
        else:
            flash("You liked your own blog!", "success")

        return redirect("/display_posts")


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """ Allow user to change password """

    if request.method == "GET":
        return render_template("change_password.html")
    else:
        pass1 = request.form.get("password_change")
        pass2 = request.form.get("confirm_password_change")
        email_user = request.form.get("email_field")
        question_verify = request.form.get("question_field")

        row_email = db.execute("SELECT email FROM users WHERE email=:email_user", email_user=email_user)
        row_name = db.execute("SELECT name FROM users WHERE email=:email_user", email_user=email_user)
        row_hash = db.execute("SELECT hash FROM users WHERE email=:email_user", email_user=email_user)
        row_question = db.execute("SELECT question FROM users WHERE question=:question", question=question_verify)

        # Error checking
        if len(row_email) != 1 or len(row_name) != 1 or len(row_hash) != 1:
            flash("User does not exist!!", "danger")
            return redirect("/change_password")

        elif not pass1 == pass2:
            flash("Passwords do not match!", "danger")
            return redirect("/change_password")

        elif not len(row_question) == 1:
            flash("Incorrect response to the identity question!", "danger")
            return redirect("/change_password")

        # If no error, update the password successfully
        else:
            db.execute("UPDATE users SET hash=:hash_password WHERE email=:email_user", hash_password=generate_password_hash(pass1, method='pbkdf2:sha256'), email_user=email_user)

            flash("Password Successfully changed!", "success")

            return redirect("/change_password")


@app.route("/delete_account", methods=["POST"])
@login_required
def delete_acc():
    """ Delete account """

    db.execute("DELETE FROM users WHERE id=:userid", userid=session["user_id"])
    db.execute("DELETE FROM blogs WHERE id=:userid", userid=session["user_id"])

    # Forget any user_id
    session.clear()

    flash("Your account was successfully deleted!", "success")

    return redirect("/home")
