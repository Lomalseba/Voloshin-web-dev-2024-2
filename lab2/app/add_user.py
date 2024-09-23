import os
from werkzeug.security import generate_password_hash
from app import app, db, User


def add_user(username, password):
    with app.app_context():
        # Создание нового пользователя
        user = User(username=username)
        user.set_password(password)

        # Добавление пользователя в базу данных
        db.session.add(user)
        db.session.commit()

        print(f'User {username} added successfully!')


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python add_user.py <username> <password>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]

    add_user(username, password)