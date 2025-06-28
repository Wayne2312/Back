from flask import Flask
from models import db
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

with app.app_context():
    db.init_app(app)
    db.create_all()
    print("Database tables created successfully")