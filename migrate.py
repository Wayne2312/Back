import logging
from flask import Flask
from flask_migrate import Migrate, upgrade
from models import db
from config import Config
import os
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

  # Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

  # Test database connection
try:
    engine = create_engine(os.getenv('DATABASE_URL'))
    with engine.connect() as conn:
          logger.info("Database connection successful")
except OperationalError as e:
      logger.error(f"Database connection failed: {e}")
      exit(1)

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)

with app.app_context():
    try:
        upgrade()  # Apply migrations
        logger.info("Database migrations applied successfully")
    except Exception as e:
        logger.error(f"Failed to apply migrations: {e}")
        exit(1)
