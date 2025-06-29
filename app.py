import os
import logging
logger = logging.getLogger(__name__)
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
from flask_restx import Api, Resource, fields
from dotenv import load_dotenv
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from models import db, User, Habit, Activity
from config import Config
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError


logging.basicConfig(level=logging.DEBUG)
load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)
app = Flask(__name__)
app.config.from_object(Config)

# Initialize Flask-RESTX
api = Api(
    app,
    version='1.0',
    title='Habit Tracker API',
    description='API for managing user habits and tracking activities',
    doc='/api/docs/',
    authorizations={
        'Bearer Auth': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'Type "Bearer <jwt-token>"'
        }
    },
    security='Bearer Auth'
)

# Define namespaces
auth_ns = api.namespace('auth', description='Authentication operations')
habits_ns = api.namespace('habits', description='Habit management operations')

frontend_url = os.getenv('FRONTEND_URL', 'https://front-lovat-eight.vercel.app')
if not frontend_url:
    logger.error("FRONTEND_URL environment variable is not set")
    raise ValueError("FRONTEND_URL environment variable is required")

CORS(app, resources={
    r"/api/*": {
        "origins": ["https://front-lovat-eight.vercel.app", "http://localhost:3000"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type"],
        "supports_credentials": True,
        "expose_headers": ["Authorization"]
    }
})

# Model definitions for Swagger documentation
register_model = api.model('Register', {
    'username': fields.String(required=True, description='User username'),
    'email': fields.String(required=True, description='User email'),
    'password': fields.String(required=True, description='User password')
})

login_model = api.model('Login', {
    'identifier': fields.String(required=True, description='Username or email'),
    'password': fields.String(required=True, description='User password')
})

habit_model = api.model('Habit', {
    'name': fields.String(required=True, description='Habit name'),
    'description': fields.String(description='Habit description'),
    'frequency': fields.String(required=True, description='Habit frequency (daily or weekly)')
})

activity_model = api.model('Activity', {
    'id': fields.Integer(readonly=True, description='Activity ID'),
    'completed_at': fields.DateTime(readonly=True, description='Activity completion timestamp')
})

habit_response_model = api.model('HabitResponse', {
    'id': fields.Integer(readonly=True, description='Habit ID'),
    'name': fields.String(description='Habit name'),
    'description': fields.String(description='Habit description'),
    'frequency': fields.String(description='Habit frequency'),
    'streak': fields.Integer(description='Current streak')
})

analysis_model = api.model('Analysis', {
    'habits': fields.List(fields.Nested(api.model('HabitAnalysis', {
        'id': fields.Integer(description='Habit ID'),
        'name': fields.String(description='Habit name'),
        'frequency': fields.String(description='Habit frequency'),
        'total_activities': fields.Integer(description='Total activities'),
        'completion_rate': fields.Float(description='Completion rate')
    }))),
    'trends': fields.Nested(api.model('Trends', {
        'labels': fields.List(fields.String, description='Date labels for trend data'),
        'data': fields.Raw(description='Trend data for each habit')
    }))
})

from email_validator import validate_email, EmailNotValidError
import re

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True

def validate_email_format(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        response = jsonify({"status": "preflight accepted"})
        origin = request.headers.get('Origin')
        if origin in ["https://front-lovat-eight.vercel.app", "http://localhost:3000"]:
            response.headers.add("Access-Control-Allow-Origin", origin)
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Authorization, Content-Type")
        return response

db.init_app(app)
migrate = Migrate(app, db)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return {"message": "Token required"}, 401
            
        if token.startswith("Bearer "):
            token = token[7:]
        else:
            return {"message": "Invalid token format"}, 401
            
        try:
            payload = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"], 
                               options={"require": ["exp", "iat"]})
            user = User.query.get(payload["user_id"])
            if not user:
                return {"message": "Invalid token"}, 403
        except jwt.ExpiredSignatureError:
            return {"message": "Token expired"}, 401
        except (jwt.InvalidTokenError, jwt.DecodeError, KeyError) as e:
            logger.error(f"Token validation failed: {str(e)}")
            return {"message": "Invalid token"}, 401
        except Exception as e:
            logger.error(f"Unexpected token validation error: {str(e)}")
            return {"message": "Token validation failed"}, 500
            
        return f(user, *args, **kwargs)
    return decorated

@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.doc('register_user')
    @auth_ns.expect(register_model)
    def post(self):
        data = request.get_json()
        
        # Validate input
        if not all(k in data for k in ['username', 'email', 'password']):
            return {"message": "All fields are required"}, 400
            
        if len(data['username']) < 3:
            return {"message": "Username must be at least 3 characters"}, 400
            
        if not validate_email_format(data['email']):
            return {"message": "Invalid email format"}, 400
            
        if not validate_password(data['password']):
            return {"message": "Password must be at least 8 characters with uppercase, lowercase and numbers"}, 400
            
        # Check for existing user (atomic operation)
        existing_user = db.session.execute(
            db.select(User).where(
                (User.username == data['username']) | 
                (User.email == data['email'])
            )
        ).scalar()
        
        if existing_user:
            return {"message": "Username or email already exists"}, 400
            
        try:
            hashed_password = bcrypt.hashpw(data['password'].encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
            new_user = User(
                username=data['username'],
                email=data['email'],
                password=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            
            token = generate_token(new_user.id, new_user.email)
            return {
                "message": "User registered",
                "token": token,
                "user": {
                    "id": new_user.id,
                    "username": new_user.username,
                    "email": new_user.email
                }
            }, 201
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}")
            return {"message": "Registration failed"}, 500

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.doc('login_user')
    @auth_ns.expect(login_model)
    @auth_ns.response(200, 'Login successful')
    @auth_ns.response(401, 'Invalid credentials')
    def post(self):
        if request.method == "OPTIONS":
            return jsonify({}), 200
        data = request.get_json()
        logger.debug(f"Login payload: {data}")
        identifier = data.get("identifier")
        password = data.get("password")
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        if not user or not bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
            logger.error("Invalid credentials")
            return {"message": "Invalid credentials"}, 401
        token = generate_token(user.id, user.email)
        logger.info(f"User logged in: {user.username}")
        return {"token": token, "username": user.username, "email": user.email}, 200

def generate_token(user_id, email):
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")
    logger.debug(f"Generated token for user_id {user_id}: {token}")
    return token

@habits_ns.route('')
class Habits(Resource):
    @habits_ns.doc('create_habit')
    @token_required
    def post(self, user):
        data = request.get_json()
        
        if not data.get('name') or not data.get('frequency'):
            return {"message": "Name and frequency are required"}, 400
            
        frequency = data['frequency'].lower()
        if frequency not in ['daily', 'weekly']:
            return {"message": "Frequency must be 'daily' or 'weekly'"}, 400
            
        if len(data['name']) > 100:
            return {"message": "Habit name too long (max 100 chars)"}, 400
            
        try:
            new_habit = Habit(
                name=data['name'],
                description=data.get('description', '')[:500],  # Limit description length
                frequency=frequency,
                user_id=user.id
            )
            db.session.add(new_habit)
            db.session.commit()
            return {
                "message": "Habit created",
                "habit": {
                    "id": new_habit.id,
                    "name": new_habit.name,
                    "streak": 0  # Initial streak
                }
            }, 201
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Habit creation error: {str(e)}")
            return {"message": "Failed to create habit"}, 500

    @habits_ns.doc('create_habit')
    @habits_ns.expect(habit_model)
    @habits_ns.response(201, 'Habit created')
    @habits_ns.response(400, 'Invalid input')
    @habits_ns.response(401, 'Unauthorized')
    @habits_ns.expect(auth_ns.parser().add_argument('Authorization', location='headers', required=True))
    @token_required
    def post(self, user):
        data = request.get_json()
        logger.debug(f"Create habit payload: {data}")
        name = data.get("name")
        description = data.get("description", "")
        frequency = data.get("frequency")
        if not name or not frequency:
            logger.error("Missing name or frequency")
            return {"message": "Name and frequency required"}, 400
        if frequency.lower() not in ["daily", "weekly"]:
            logger.error(f"Invalid frequency: {frequency}")
            return {"message": "Frequency must be 'daily' or 'weekly'"}, 400
        try:
            new_habit = Habit(name=name, description=description, frequency=frequency.lower(), user_id=user.id)
            db.session.add(new_habit)
            db.session.commit()
            logger.info(f"Habit created: {name} for user {user.username}")
            return {"message": "Habit created", "id": new_habit.id}, 201
        except SQLAlchemyError as e:
            logger.error(f"Database error creating habit: {str(e)}")
            db.session.rollback()
            return {"message": "Failed to create habit"}, 500

@habits_ns.route('/<int:id>')
class Habit(Resource):
    @habits_ns.doc('update_delete_habit')
    @habits_ns.expect(habit_model)
    @habits_ns.response(200, 'Habit updated')
    @habits_ns.response(403, 'Unauthorized')
    @habits_ns.response(404, 'Habit not found')
    @habits_ns.expect(auth_ns.parser().add_argument('Authorization', location='headers', required=True))
    @token_required
    def put(self, user, id):
        habit = Habit.query.get_or_404(id)
        if habit.user_id != user.id:
            logger.error(f"Unauthorized access to habit {id} by user {user.id}")
            return {"message": "Unauthorized"}, 403
        data = request.get_json()
        logger.debug(f"Update habit {id} payload: {data}")
        frequency = data.get("frequency", habit.frequency)
        if frequency.lower() not in ["daily", "weekly"]:
            logger.error(f"Invalid frequency: {frequency}")
            return {"message": "Frequency must be 'daily' or 'weekly'"}, 400
        try:
            habit.name = data.get("name", habit.name)
            habit.description = data.get("description", habit.description)
            habit.frequency = frequency.lower()
            db.session.commit()
            logger.info(f"Habit {id} updated for user {user.username}")
            return {"message": "Habit updated"}, 200
        except SQLAlchemyError as e:
            logger.error(f"Database error updating habit: {str(e)}")
            db.session.rollback()
            return {"message": "Failed to update habit"}, 500

    @habits_ns.doc('delete_habit')
    @habits_ns.response(200, 'Habit deleted')
    @habits_ns.response(403, 'Unauthorized')
    @habits_ns.response(404, 'Habit not found')
    @habits_ns.expect(auth_ns.parser().add_argument('Authorization', location='headers', required=True))
    @token_required
    def delete(self, user, id):
        habit = Habit.query.get_or_404(id)
        if habit.user_id != user.id:
            logger.error(f"Unauthorized access to habit {id} by user {user.id}")
            return {"message": "Unauthorized"}, 403
        try:
            logger.info(f"Deleting habit {id} for user {user.id}")
            db.session.delete(habit)
            db.session.commit()
            logger.info(f"Habit {id} deleted successfully by user {user.id}")
            return {"message": "Habit deleted"}, 200
        except SQLAlchemyError as e:
            logger.error(f"Error deleting habit {id}: {str(e)}")
            db.session.rollback()
            return {"message": "Failed to delete habit"}, 500

@habits_ns.route('/<int:id>/log')
class LogActivity(Resource):
    @habits_ns.doc('log_activity')
    @habits_ns.response(201, 'Activity logged')
    @habits_ns.response(403, 'Unauthorized')
    @habits_ns.response(404, 'Habit not found')
    @habits_ns.expect(auth_ns.parser().add_argument('Authorization', location='headers', required=True))
    @token_required
    def post(self, user, id):
        habit = Habit.query.get_or_404(id)
        if habit.user_id != user.id:
            logger.error(f"Unauthorized access to habit {id} by user {user.id}")
            return {"message": "Unauthorized"}, 403
        try:
            new_activity = Activity(habit_id=id, user_id=user.id, completed_at=datetime.utcnow())
            db.session.add(new_activity)
            db.session.commit()
            logger.info(f"Activity logged for habit {id} by user {user.username}")
            return {"message": "Activity logged", "streak": calculate_streak(habit)}, 201
        except SQLAlchemyError as e:
            logger.error(f"Database error logging activity: {str(e)}")
            db.session.rollback()
            return {"message": "Failed to log activity"}, 500

@habits_ns.route('/<int:id>/history')
class HabitHistory(Resource):
    @habits_ns.doc('get_habit_history')
    @habits_ns.response(200, 'Success', [activity_model])
    @habits_ns.response(403, 'Unauthorized')
    @habits_ns.response(404, 'Habit not found')
    @habits_ns.expect(auth_ns.parser().add_argument('Authorization', location='headers', required=True))
    @token_required
    def get(self, user, id):
        habit = Habit.query.get_or_404(id)
        if habit.user_id != user.id:
            logger.error(f"Unauthorized access to habit {id} by user {user.id}")
            return {"message": "Unauthorized"}, 403
        try:
            activities = Activity.query.filter_by(habit_id=id).order_by(Activity.completed_at.desc()).all()
            logger.debug(f"Fetched history for habit {id}: {len(activities)} activities")
            return [{
                "id": activity.id,
                "completed_at": activity.completed_at.isoformat()
            } for activity in activities], 200
        except SQLAlchemyError as e:
            logger.error(f"Database error fetching history: {str(e)}")
            return {"message": "Failed to fetch history"}, 500

@habits_ns.route('/analysis')
class HabitsAnalysis(Resource):
    @habits_ns.doc('get_habits_analysis')
    @habits_ns.response(200, 'Success', analysis_model)
    @habits_ns.response(401, 'Unauthorized')
    @habits_ns.response(500, 'Server error')
    @habits_ns.expect(auth_ns.parser().add_argument('Authorization', location='headers', required=True))
    @token_required
    def get(self, user):
        try:
            habits = Habit.query.filter_by(user_id=user.id).all()
            habit_data = []
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=30)
            trend_labels = [(start_date + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(31)]
            trend_data = {habit.id: [0] * 31 for habit in habits}

            for habit in habits:
                total_activities = Activity.query.filter_by(habit_id=habit.id).count()
                if habit.frequency == "daily":
                    expected_days = 30
                    actual_days = db.session.query(
                        func.count(func.distinct(func.date(Activity.completed_at)))
                    ).filter(
                        Activity.habit_id == habit.id,
                        Activity.completed_at >= start_date,
                        Activity.completed_at <= end_date
                    ).scalar() or 0
                    completion_rate = actual_days / expected_days if expected_days > 0 else 0
                else:
                    expected_weeks = 4
                    actual_weeks = db.session.query(
                        func.count(func.distinct(func.extract("week", Activity.completed_at)))
                    ).filter(
                        Activity.habit_id == habit.id,
                        Activity.completed_at >= start_date,
                        Activity.completed_at <= end_date
                    ).scalar() or 0
                    completion_rate = actual_weeks / expected_weeks if expected_weeks > 0 else 0

                activities = Activity.query.filter(
                    Activity.habit_id == habit.id,
                    Activity.completed_at >= start_date,
                    Activity.completed_at <= end_date
                ).all()
                for activity in activities:
                    day_index = (activity.completed_at.date() - start_date.date()).days
                    if 0 <= day_index < 31:
                        trend_data[habit.id][day_index] += 1

                habit_data.append({
                    "id": habit.id,
                    "name": habit.name,
                    "frequency": habit.frequency,
                    "total_activities": total_activities,
                    "completion_rate": completion_rate
                })

            logger.debug(f"Analysis fetched for user {user.username}: {len(habit_data)} habits")
            return {
                "habits": habit_data,
                "trends": {
                    "labels": trend_labels,
                    "data": trend_data
                }
            }, 200
        except SQLAlchemyError as e:
            logger.error(f"Database error fetching analysis: {str(e)}")
            return {"message": "Failed to fetch analysis"}, 500

def calculate_streak(habit):
    try:
        # For daily habits
        if habit.frequency == 'daily':
            # Get the most recent activity date
            last_activity = db.session.execute(
                db.select(Activity.completed_at)
                .where(Activity.habit_id == habit.id)
                .order_by(Activity.completed_at.desc())
                .limit(1)
            ).scalar()
            
            if not last_activity:
                return 0
                
            # Check if the last activity was today or yesterday
            today = datetime.utcnow().date()
            last_date = last_activity.date()
            
            if last_date == today:
                streak_days = 1
                current_date = today - timedelta(days=1)
            elif last_date == today - timedelta(days=1):
                streak_days = 2
                current_date = today - timedelta(days=2)
            else:
                return 0
                
            # Count consecutive previous days
            while True:
                activity_exists = db.session.execute(
                    db.select(Activity.completed_at)
                    .where(
                        Activity.habit_id == habit.id,
                        func.date(Activity.completed_at) == current_date
                    )
                    .exists()
                ).scalar()
                
                if not activity_exists:
                    break
                    
                streak_days += 1
                current_date -= timedelta(days=1)
                
            return streak_days
            
        # For weekly habits
        else:
            # Similar logic but for weeks
            # ... implementation omitted for brevity
            pass
            
    except SQLAlchemyError as e:
        logger.error(f"Streak calculation error: {str(e)}")
        return 0

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
