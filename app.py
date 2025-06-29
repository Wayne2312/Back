import os
import logging
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
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Flask-RESTX
api = Api(app, 
    version='1.0', 
    title='Habit Tracker API',
    description='API for managing user habits and tracking activities',
    doc='/api/docs/'
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

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        response = jsonify({"status": "preflight accepted"})
        response.headers.add("Access-Control-Allow-Origin", "https://front-lovat-eight.vercel.app")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Authorization, Content-Type")
        return response

db.init_app(app)
migrate = Migrate(app, db)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        logger.debug(f"Received Authorization header: {token}")
        if not token:
            logger.error("Token missing in request")
            return jsonify({"message": "Token required"}), 401
        if token.startswith("Bearer "):
            token = token[7:]
        else:
            logger.error("Invalid Authorization header format")
            return jsonify({"message": "Token required (Bearer expected)"}), 401
        try:
            payload = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"], options={"require": ["exp", "iat"]})
            user = User.query.get(payload["user_id"])
            if not user:
                logger.error("User not found for token")
                return jsonify({"message": "Invalid token"}), 403
            logger.debug(f"Token valid for user: {user.username}")
        except jwt.ExpiredSignatureError:
            logger.error("Token expired")
            return jsonify({"message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            logger.error("Invalid token")
            return jsonify({"message": "Invalid token"}), 401
        return f(user, *args, **kwargs)
    return decorated

@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.doc('register_user')
    @auth_ns.expect(register_model)
    @auth_ns.response(201, 'User registered successfully')
    @auth_ns.response(400, 'Invalid input')
    @auth_ns.response(500, 'Server error')
    def post(self):
        if request.method == "OPTIONS":
            return jsonify({}), 200
        data = request.get_json()
        logger.debug(f"Register payload: {data}")
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        if not username or not email or not password:
            logger.error("Missing username, email, or password")
            return {"message": "Username, email, and password required"}, 400
        if User.query.filter_by(username=username).first():
            logger.error(f"Username already exists: {username}")
            return {"message": "Username already exists"}, 400
        if User.query.filter_by(email=email).first():
            logger.error(f"Email already exists: {email}")
            return {"message": "Email already exists"}, 400
        try:
            hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
            new_user = User(
                username=username,
                email=email,
                password=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            token = generate_token(new_user.id, new_user.email)
            logger.info(f"User registered: {username}")
            return {"message": "User registered", "token": token}, 201
        except SQLAlchemyError as e:
            logger.error(f"Database error during registration: {str(e)}")
            db.session.rollback()
            return {"message": "Failed to register user"}, 500

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
    @habits_ns.doc('list_create_habits')
    @habits_ns.response(200, 'Success', [habit_response_model])
    @habits_ns.response(401, 'Unauthorized')
    @habits_ns.response(500, 'Server error')
    @habits_ns.expect(auth_ns.parser().add_argument('Authorization', location='headers', required=True))
    @token_required
    def get(self, user):
        try:
            habits = Habit.query.filter_by(user_id=user.id).all()
            logger.debug(f"Fetched {len(habits)} habits for user {user.username}")
            return [{
                "id": habit.id,
                "name": habit.name,
                "description": habit.description,
                "frequency": habit.frequency,
                "streak": calculate_streak(habit)
            } for habit in habits], 200
        except SQLAlchemyError as e:
            logger.error(f"Database error fetching habits: {str(e)}")
            return {"message": "Failed to fetch habits"}, 500

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

    @habits_ns madrugada_doc('delete_habit')
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
        activities = Activity.query.filter_by(habit_id=habit.id).order_by(Activity.completed_at.desc()).all()
        if not activities:
            return 0
        streak = 0
        today = datetime.utcnow().date()
        for i, activity in enumerate(activities):
            activity_date = activity.completed_at.date()
            if i == 0 and activity_date < today:
                return streak
            if i > 0 and (activities[i-1].completed_at.date() - activity_date).days > 1:
                break
            streak += 1
        return streak
    except SQLAlchemyError as e:
        logger.error(f"Database error calculating streak: {str(e)}")
        return 0

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
