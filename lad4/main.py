from flask import Flask, render_template, redirect, url_for, request, make_response, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from my_sqldb import MyDb
import mysql.connector

app = Flask(__name__)

app.config.from_pyfile('config.py')

db = MyDb(app)

login_manager = LoginManager();

login_manager.init_app(app);

login_manager.login_view = 'login'
login_manager.login_message = 'Доступ к данной странице есть только у авторизованных пользователей '
login_manager.login_message_category = 'warning'

def get_roles():
    with db.connect().cursor(named_tuple=True) as cursor:
            query = ('SELECT * FROM roles')
            cursor.execute(query)
            roles = cursor.fetchall()
    return roles

class User(UserMixin):
    def __init__(self,user_id,user_login):
        self.id = user_id
        self.login = user_login
        

@login_manager.user_loader
def load_user(user_id):
    cursor= db.connect().cursor(named_tuple=True)
    query = ('SELECT * FROM users WHERE id=%s')
    cursor.execute(query,(user_id,))
    user = cursor.fetchone()
    cursor.close()
    if user:
       return User(user.id,user.login)
    return None

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/list_users')
def list_users():
    with db.connect().cursor(named_tuple=True) as cursor:
            query = '''
                    SELECT users.*, roles.name as role_name 
                    FROM users 
                    LEFT JOIN roles ON users.role_id = roles.id
                    '''
            cursor.execute(query)
            users = cursor.fetchall()
    return render_template('list_users.html', users = users)


def check_login(login):
    white_list = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    error = ""
    if len(login) < 5:
        error += "Логин должен содержать не менее 5 символов, "

    for char in login:
        if char not in white_list:
            error += "Логин должен состоять только из латинских букв и цифр, "
            break

    if error:
        return error[:-2]
    return True


def check_password(password):
    white_list = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    white_list_num = "1234567890"
    white_list_sign = "~!?@#$%^&*_-+()[]{}></|'.,:;"

    error = ""
    if len(password) < 8:
        error += "не менее 8 символов, "
    if len(password) > 128:
        error += "не более 128 символов, "

    flag_up = False
    flag_down = False
    flag_num = False
    flag_alf = True
    flag_spase = True

    for let in password:
        if let in white_list:
            if let.isupper():
                flag_up = True
            elif let.islower():
                flag_down = True
        elif let in white_list_num:
            flag_num = True
        elif let in white_list_sign:
            pass
        elif let == " ":
            flag_spase = False
        else:
            flag_alf = False

    if not flag_up:
        error += "как минимум одна заглавная буква, "
    if not flag_down:
        error += "как минимум одна строчная буква, "
    if not flag_num:
        error += "как минимум одна цифра, "
    if not flag_alf:
        error += "только латинские или кириллические буквы, "
    if not flag_spase:
        error += "без пробелов, "
    if error:
        return error[:-2]
    return True



@app.route('/create_user', methods=['GET', 'POST'])
# @login_required
def create_user():
    errors = {}
    roles = get_roles()
    user_data = {}

    if request.method == "POST":
        first_name = request.form.get('name')
        second_name = request.form.get('lastname')
        middle_name = request.form.get('middlename')
        login = request.form.get('login')
        password = request.form.get('password')
        role_id = request.form.get('role')


        user_data['first_name'] = first_name
        user_data['second_name'] = second_name
        user_data['middle_name'] = middle_name
        user_data['login'] = login
        user_data['password_hash'] = password

        if not first_name:
            errors["first_name_error"] = "Имя обязательно для заполнения"
        if not second_name:
            errors["second_name_error"] = "Фамилия обязательна для заполнения"
        if not login:
            errors['login_error'] = 'Логин обязателен для заполнения'
        elif check_login(login) != 1:
            errors['login_error'] = check_login(login)
        if not password:
            errors['password_error'] = 'Пароль обязателен для заполнения'
        elif check_password(password) != 1:
            errors['password_error'] = check_password(password)

        if errors:
            return render_template('create_user.html', roles=roles, errors=errors, user=user_data)


        try:
            with db.connect().cursor(named_tuple=True) as cursor:
                query = (
                    'INSERT INTO users (login, password_hash, first_name, second_name, middle_name, role_id) values(%s, SHA2(%s,256), %s, %s, %s, %s)'
                )
                cursor.execute(query, (login, password, first_name, second_name, middle_name, role_id))
                db.connect().commit()
                flash('Вы успешно зарегестировали пользователя', 'success')
                return redirect(url_for('list_users'))
        except mysql.connector.errors.DatabaseError:
            db.connect().rollback()
            flash('Ошибка при регистрации', 'danger')

    return render_template('create_user.html', roles=roles, errors=errors, user=user_data)


def update_password(login, new_password):
    try:
        with db.connect().cursor(named_tuple=True) as cursor:
            print("update database")
            query = 'UPDATE users SET password_hash=SHA2(%s,256) WHERE login=%s'
            cursor.execute(query, (new_password, login))
            db.connect().commit()
            return True
    except mysql.connector.errors.DatabaseError:
        db.connect().rollback()
        return False


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == "POST":
        login = request.form.get('login')
        password = request.form.get('password')
        print(login, password)
        remember = request.form.get('remember')
        with db.connect().cursor(named_tuple=True) as cursor:
            query = ('SELECT * FROM users WHERE login=%s and password_hash=SHA2(%s,256) ')
            cursor.execute(query,(login, password))
            user_data = cursor.fetchone()
            if user_data:
                    login_user(User(user_data.id,user_data.login),remember=remember)
                    flash('Вы успешно прошли аутентификацию', 'success')
                    return redirect(url_for('index'))
        flash('Неверные логин или пароль', 'danger')
    return render_template('login.html')




@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    errors = {}
    password_data = {}

    if request.method == 'POST':
        password = request.form.get('oldpassword')
        new_password = request.form.get('newpassword')
        confirm_new_password = request.form.get('confirmnewpassword')

        password_data['old_password'] = password
        password_data['new_password'] = new_password
        password_data['confirm_new_password'] = confirm_new_password

        login = current_user.login
        try:
            with db.connect().cursor(named_tuple=True) as cursor:
                query = 'SELECT * FROM users WHERE login=%s and password_hash=SHA2(%s,256)'
                cursor.execute(query, (login, password))
                user_data = cursor.fetchone()

                if not user_data:
                    flash('Старый пароль введен неправильно', 'danger')
                elif new_password == confirm_new_password:
                    if check_password(new_password) != 1:
                        flash(check_password(new_password), 'danger')
                    else:
                        query = 'UPDATE users SET password_hash=SHA2(%s,256) WHERE login=%s'
                        cursor.execute(query, (new_password, login))
                        db.connect().commit()
                        flash('Вы успешно сменили пароль', 'success')
                        return redirect(url_for('index'))
                else:
                    flash('Новый пароль и подтверждение не совпадают', 'danger')

        except Exception as e:
            flash(f'Произошла ошибка: {str(e)}, пароль не сменился', 'danger')

    # В случае GET-запроса или если произошла ошибка, вернем форму с возможными ошибками
    return render_template('change_password.html', errors=errors, password_data=password_data)


@app.route('/show_user/<int:user_id>')
# @login_required
def show_user(user_id):
    with db.connect().cursor(named_tuple=True) as cursor:
        query = '''
                SELECT users.*, roles.name as role_name
                FROM users
                LEFT JOIN roles ON users.role_id = roles.id 
                WHERE users.id = %s
                '''
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
    return render_template('show_user.html', user = user )


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    errors = {}  # Инициализируем пустой словарь для ошибок

    # Получаем данные пользователя
    with db.connect().cursor(named_tuple=True) as cursor:
        query = ('SELECT users.*, roles.name as role_name FROM users '
                 'LEFT JOIN roles ON users.role_id = roles.id WHERE users.id = %s')
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()

    if request.method == "POST":
        first_name = request.form.get('name')
        second_name = request.form.get('lastname')
        middle_name = request.form.get('middlename')

        # Проверка корректности данных
        if not first_name:
            errors['first_name_error'] = 'Имя обязательно для заполнения.'
        if not second_name:
            errors['second_name_error'] = 'Фамилия обязательна для заполнения.'

        if not errors:  # Если нет ошибок, обновляем данные
            try:
                with db.connect().cursor(named_tuple=True) as cursor:
                    query = ('UPDATE users SET first_name=%s, second_name=%s, middle_name=%s WHERE id=%s;')
                    cursor.execute(query, (first_name, second_name, middle_name, user_id))
                    db.connect().commit()
                    flash('Вы успешно обновили пользователя', 'success')
                    return redirect(url_for('list_users'))
            except mysql.connector.errors.DatabaseError:
                db.connect().rollback()
                flash('Ошибка при обновлении', 'danger')
        else:
            flash('Произошла ошибка при проверке данных', 'danger')

    # Возвращаем шаблон с данными пользователя и ошибками
    return render_template('edit_user.html', user=user, errors=errors)

@app.route('/delete_user/<int:user_id>', methods=["POST"])
@login_required
def delete_user(user_id): 
    with db.connect().cursor(named_tuple=True) as cursor:
        try:
            query = ('DELETE FROM users WHERE id=%s')
            cursor.execute(query, (user_id,))
            db.connect().commit()
            flash('Удаление успешно', 'success')
        except:
            db.connect().rollback()
            flash('Ошибка при удалении пользователя', 'danger')
    return redirect(url_for('list_users'))


if __name__ == "__main__":
    app.run(debug=True, port=5000)