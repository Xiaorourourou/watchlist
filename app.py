import os
import sys

import click
from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  

db = SQLAlchemy(app)
login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    return user


login_manager.login_view = 'login'


@app.cli.command()   
@click.option('--drop', is_flag=True, help='Create after drop.')   
def initdb(drop):
    """Initialize the database."""
    if drop:   
        db.drop_all()
    db.create_all()
    click.echo('Initialized database.')   

@app.cli.command()
def forge():
      """Generate fake data."""
      db.create_all()

      name = 'Xiaorourourou'
      movies = [
              {'title': '战狼2', 'year': '2017'},
              {'title': '哪吒之魔童降世', 'year': '2019'},
              {'title': '流浪地球', 'year': '2019'},
              {'title': '复仇者联盟4', 'year': '2019'},
              {'title': '红海行动', 'year': '2018'},
              {'title': '唐人街探案2', 'year': '2018'},
              {'title': '我不是药神', 'year': '2018'},
              {'title': '中国机长', 'year': '2019'},
              {'title': '速度与激情8', 'year': '2017'},
              {'title': '西红柿首富', 'year': '2018'},
              {'title': '复仇者联盟3', 'year': '2018'},
              {'title': '捉妖记2', 'year': '2018'},
              {'title': '八佰', 'year': '2020'},
              {'title': '姜子牙', 'year': '2020'},
              {'title': '我和我的家乡', 'year': '2020'},
              {'title': '你好，李焕英', 'year': '2021'},
              {'title': '长津湖', 'year': '2021'},
              {'title': '速度与激情9', 'year': '2021'},
      ]

      user = User(name=name)
      db.session.add(user)
      for m in movies:
           movie = Movie(title=m['title'], year=m['year'])
           db.session.add(movie)

      db.session.commit()
      click.echo('Done.')

@app.cli.command()
@click.option('--username', prompt=True, help='The username used to login.')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='The password used to login.')
def admin(username, password):
    """Create user."""
    db.create_all()

    user = User.query.first()
    if user is not None:
        click.echo('Updating user...')
        user.username = username
        user.set_password(password)
    else:
        click.echo('Creating user...')
        user = User(username=username, name='Admin')
        user.set_password(password)
        db.session.add(user)

    db.session.commit()
    click.echo('Done.')


class User(db.Model, UserMixin): 
    id = db.Column(db.Integer, primary_key=True)   
    name = db.Column(db.String(20))   
    username = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def validate_password(self, password):
        return check_password_hash(self.password_hash, password)


class Movie(db.Model):   
    id = db.Column(db.Integer, primary_key=True)   
    title = db.Column(db.String(60))   
    year = db.Column(db.String(4))   


@app.context_processor
def inject_user():
    user = User.query.first()
    return dict(user=user)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            return redirect(url_for('index'))

        title = request.form['title']
        year = request.form['year']

        if not title or not year or len(year) > 4 or len(title) > 60:
            flash('Invalid input.')
            return redirect(url_for('index'))
        movie = Movie(title=title, year=year)
        db.session.add(movie)
        db.session.commit()
        flash('Item created.')
        return redirect(url_for('index'))
    movies = Movie.query.all()
    return render_template('index.html', movies=movies)

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        query = request.form['query']
        results = Movie.query.filter(Movie.title.ilike(f'%{query}%')).all()
        return render_template('search_results.html', results=results, query=query)
    return render_template('search.html')


@app.route('/movie/edit/<int:movie_id>', methods=['GET', 'POST'])
@login_required
def edit(movie_id):
    movie = Movie.query.get_or_404(movie_id)

    if request.method == 'POST':
        title = request.form['title']
        year = request.form['year']

        if not title or not year or len(year) > 4 or len(title) > 60:
            flash('Invalid input.')
            return redirect(url_for('edit', movie_id=movie_id))

        movie.title = title
        movie.year = year
        db.session.commit()
        flash('Item updated.')
        return redirect(url_for('index'))

    return render_template('edit.html', movie=movie)


@app.route('/movie/delete/<int:movie_id>', methods=['POST'])
@login_required
def delete(movie_id):
    movie = Movie.query.get_or_404(movie_id)
    db.session.delete(movie)
    db.session.commit()
    flash('Item deleted.')
    return redirect(url_for('index'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        name = request.form['name']

        if not name or len(name) > 20:
            flash('Invalid input.')
            return redirect(url_for('settings'))

        user = User.query.first()
        user.name = name
        db.session.commit()
        flash('Settings updated.')
        return redirect(url_for('index'))

    return render_template('settings.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Invalid input.')
            return redirect(url_for('login'))

        user = User.query.first()

        if username == user.username and user.validate_password(password):
            login_user(user)
            flash('Login success.')
            return redirect(url_for('index'))

        flash('Invalid username or password.')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Goodbye.')
    return redirect(url_for('index'))




