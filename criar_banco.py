from fakePinterest import app, database
from fakePinterest.models import Usuario,Foto

with app.app_context():
    database.create_all()
