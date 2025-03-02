from flask import Flask, render_template, url_for, redirect
from fakePinterest import app, bcrypt, database, login_manager
from flask_login import login_required, login_user, logout_user, current_user
from fakePinterest.forms import FormLogin, FormCriarConta, FormFoto
from fakePinterest.models import Usuario, Foto
from werkzeug.utils import secure_filename
import os


@app.route('/', methods=['GET', 'POST'])
def homepage():
    form_login = FormLogin()
    if form_login.validate_on_submit():
        usuario = Usuario.query.filter_by(email=form_login.email.data).first()
        if usuario and bcrypt.check_password_hash(usuario.senha, form_login.senha.data):
            login_user(usuario)
            return redirect(url_for('perfil', id_usuario=usuario.id))
    return render_template('homepage.html', form=form_login)


@app.route('/criar_conta', methods=['GET', 'POST'])
def criar_conta():
    formcriar_conta = FormCriarConta()
    if formcriar_conta.validate_on_submit():
        senha_cript = bcrypt.generate_password_hash(formcriar_conta.senha.data)
        usuario = Usuario(username=formcriar_conta.username.data, email=formcriar_conta.email.data, senha=senha_cript)
        database.session.add(usuario)
        database.session.commit()
        login_user(usuario, remember=True)
        return redirect(url_for('perfil', id_usuario=usuario.id))
    return render_template('criar_conta.html', form=formcriar_conta)


@app.route('/perfil/<int:id_usuario>',  methods=['GET', 'POST'])
@login_required
def perfil(id_usuario):
    if int(id_usuario) == int(current_user.id):
        form_foto = FormFoto()
        if form_foto.validate_on_submit():
            arquivo = form_foto.foto.data
            nome_seguro = secure_filename(arquivo.filename)
            caminho = os.path.join(os.path.abspath(os.path.dirname(__file__)), app.config['OPLOAD_FOLDER'], nome_seguro)
            arquivo.save(caminho)
            foto = Foto(imagem=nome_seguro, id_usuario=current_user.id)
            database.session.add(foto)
            database.session.commit()
        return render_template('perfil.html', usuario=current_user, form=form_foto)
    else:
        usuario = Usuario.query.get(int(id_usuario))
    return render_template('perfil.html', usuario=usuario, form=None)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('homepage'))


@app.route('/feed')
@login_required
def feed():
    fotos= Foto.query.order_by(Foto.data_criacao.desc()).all()
    return render_template('feed.html', fotos=fotos)






