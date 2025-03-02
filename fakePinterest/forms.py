from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError,Length
from fakePinterest.models import Usuario


class FormLogin(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    botao_confirmacao = SubmitField('Fazer Login')

    def validate_email(self, email):
        usuario = Usuario.query.filter_by(email=email.data).first()
        if not usuario:
            raise ValidationError('Usuário inexistente, crie uma conta')


class FormCriarConta(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    username = StringField('Nome', validators=[DataRequired()])
    senha = PasswordField('Senha', validators=[DataRequired(), Length(6, 20)])
    confirmacao_senha = PasswordField('Confirmação de senha', validators=[DataRequired(), EqualTo('senha')])
    botao_confirmacao = SubmitField('Criar Conta')

    def validate_email(self, email):
        usuario = Usuario.query.filter_by(email=email.data).first()
        if usuario:
            raise ValidationError('E-mail ja cadastrado, faça login para continuar')


class FormFoto(FlaskForm):
    foto = FileField('Foto', validators=[DataRequired()])
    botao_confirmacao = SubmitField('Enviar')


