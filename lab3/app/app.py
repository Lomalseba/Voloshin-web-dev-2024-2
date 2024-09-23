import random
from flask import Flask, render_template, request, session, redirect, url_for, make_response
from faker import Faker
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os
from models.user import db, User

load_dotenv()

fake = Faker()

app = Flask(__name__)
application = app

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

app.secret_key = os.getenv('SECRET_KEY')

images_ids = ['7d4e9175-95ea-4c5f-8be5-92a6b708bb3c',
              '2d2ab7df-cdbc-48a8-a936-35bba702def5',
              '6e12f3de-d5fd-4ebb-855b-8cbc485278b7',
              'afc2cfe7-5cac-4b80-9b9a-d5c65ef0c728',
              'cab5b7f2-774e-4884-a200-0c0180fa777f']

def generate_comments(replies=True):
    comments = []
    for i in range(random.randint(1, 3)):
        comment = { 'author': fake.name(), 'text': fake.text() }
        if replies:
            comment['replies'] = generate_comments(replies=False)
        comments.append(comment)
    return comments

def generate_post(i):
    return {
        'title': fake.sentence(nb_words=6),
        'text': fake.paragraph(nb_sentences=100),
        'author': fake.name(),
        'date': fake.date_time_between(start_date='-2y', end_date='now'),
        'image_id': f'{images_ids[i]}.jpg',
        'comments': generate_comments()
    }

posts_list = sorted([generate_post(i) for i in range(5)], key=lambda p: p['date'], reverse=True)

@app.route('/posts')
def posts():
    return render_template('posts.html', title='Посты', posts=posts_list)

@app.route('/posts/<int:index>')
def post(index):
    p = posts_list[index]
    return render_template('post.html', title=p['title'], post=p)

@app.route('/about')
def about():
    return render_template('about.html', title='Об авторе')

@app.route('/post')
def post_for_lab():
    random_post_index = random.randint(0, len(posts_list) - 1)
    post_data = posts_list[random_post_index]
    return render_template('post.html', title='post', post=post_data)

@app.route('/info', methods=['GET', 'POST'])
def info():
    url_parameters = request.args.to_dict()
    headers = dict(request.headers)
    cookies = request.cookies.to_dict()
    form_data = request.form.to_dict() if request.method == 'POST' else {}

    form_submitted = False
    number_correct = True
    error_message = ""
    number = ""

    if request.method == 'POST':
        form_submitted = True
        number = form_data['number']
        only_num = [num for num in number if num.isdigit()]

        if len(only_num) not in [10, 11]:
            error_message = "Недопустимый ввод. Неверное количество цифр."
            number_correct = False
        for i, num in enumerate(form_data['number']):
            if num not in ['1','2','3','4','5','6','7','8','9','.',' ','(',')','-','+']:
                number_correct = False
                error_message = "Недопустимый ввод. В номере телефона встречаются недопустимые символы."

        if len(only_num) == 10:
            only_num = ["8"] + only_num
        if len(only_num) == 11:
            only_num[0] = "8"
            number = "".join(only_num)
            number = f"{number[:1]}-{number[1:4]}-{number[4:7]}-{number[7:9]}-{number[9:]}"
        else:
            number_correct = False



    return render_template('info.html', title='info', url_parameters=url_parameters, headers=headers,
                               cookies=cookies, form_data=form_data, form_submitted=form_submitted,
                               number_correct=number_correct, number=number, error_message=error_message)

@app.context_processor
def inject_user():
    return {'logged_in': 'user_id' in session}

@app.route("/", methods=["POST", "GET"])
def auth():
    if "visit_count" not in session:
        session["visit_count"] = 0

    session["visit_count"] += 1
    error_message = None

    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = username

            resp = make_response(redirect(url_for('info')))

            if remember:
                expires = datetime.now() + timedelta(days=7)
                resp.set_cookie('user.id', str(user.id), expires=expires)
                resp.set_cookie('username',username,  expires=expires)
            else:
                resp.set_cookie('user.id','1', expires=0)
                resp.set_cookie('username', '1', expires=0)

            return resp
        else:
            error_message = 'Invalid username or password!'

    return render_template("authorization.html", visit_count=session["visit_count"],
                           error_message=error_message)

@app.route("/logout")
def logout():
    session.pop("user_id", 0)
    session.pop("username", 0)
    return redirect(url_for("auth"))

@app.route("/srcrute)")
def security():
    if 'user_id' in session:
        return render_template("security.html")
    else:
        error_message = "need to auth"
        redirect(url_for('auth'), error_message=error_message)