from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateSignupForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

## CONFIGURE TABLES


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")


class User(db.Model, UserMixin):
    # __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="user")
    comments = relationship("Comment", back_populates="user")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comments")


db.create_all()


def add_user(form_object: CreateSignupForm) -> User:
    """Adds new user record to the table user from the data in the parameter form_object
    :returns: Class Object: User class
    :param form_object: Class Object"""
    new_user_record = User(email=form_object.email.data,
                           password=generate_password_hash(password=form_object.password.data, method="pbkdf2:sha256",
                                                           salt_length=8),
                           name=form_object.name.data)
    db.session.add(new_user_record)
    db.session.commit()
    return new_user_record


def create_comment(form_object: CommentForm, post_id: int) -> None:
    """Creates new comment record to the table comments from the data in the parameter form_object and post_id
    :returns: None
    :param form_object: Class Object
    :param post_id: Integer"""
    new_comment = Comment(text=form_object.comment.data,
                          user_id=current_user.id,
                          post_id=post_id
                          )
    db.session.add(new_comment)
    db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(function):
    @wraps(function)
    def wrapper_func(**kwargs):
        if not current_user.is_anonymous and current_user.id == 1:
            return function(**kwargs)
        else:
            abort(403)
    return wrapper_func


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = CreateSignupForm()
    if form.validate_on_submit():
        if not User.query.filter_by(email=form.email.data).first():
            new_user = add_user(form)
            login_user(new_user)
            flash(message="Congratulations, You have been successfully registered!")
            return redirect(url_for("get_all_posts"))
        else:
            flash(message="You have already registered with that email. Login instead!")
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_to_login: User = User.query.filter_by(email=form.email.data).first()
        if user_to_login:
            if check_password_hash(pwhash=user_to_login.password, password=form.password.data):
                login_user(user_to_login)
                flash(message="Successfully, Logged In!")
                return redirect(url_for("get_all_posts"))
            else:
                flash(message="Incorrect, Password!")
        else:
            flash(message="No user registered for given E-mail. Please register!")
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash(message="You need to login or register to comment!")
            return redirect(url_for("login"))
        create_comment(form, post_id)
    comments_of_post = Comment.query.filter_by(post_id=post_id).all()
    return render_template("post.html", post=requested_post, current_user=current_user, form=form,
                           comments=comments_of_post)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            user_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(port=5000, debug=True)
