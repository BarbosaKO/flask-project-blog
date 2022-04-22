import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

#******* Funções de Configuração e rotas de redirecionamento para outras Views *******

#Função chamada antes da requisição de Auth e suas rotas
#Verifica se já existe uma sessão ativa e loga automáticamente
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

#Logout do app
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

#Verifica nas demais páginas se existe uma sessão ativa, senão redireciona para login
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

#******************************************************************************************


#*********************** Views ***************************
#************ auth = /register ************
@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':

        #Chamar um model aqui, algo como: 
        # newUser = User(request.form['username'], request.form['password'])
        username = request.form['username']
        password = request.form['password']

        db = get_db() #função da db.py
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                #É melhor não executar esse comando aqui, crie um repository chamado user e chame db.py lá
                #Então chame aqui o repository e rode algo como: 
                #'user.create(newUser.dado1, newUser.dado2)'
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

#************ auth = /login ************
@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        db = get_db()
        error = None
        #Podemos mudar aqui de forma que a db.py retornar um objeto user
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (request.form['username'],)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], request.form['password']):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            #Criar variáveis de sessão, como: ids, nickname, role...
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')
