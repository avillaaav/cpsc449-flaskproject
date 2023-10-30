from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

app.config['PROPAGATE_EXCEPTIONS'] = True  # Enable propagating exceptions to get detailed error messages
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'cpsc449key'  # Replace with a secure secret key

# Replace with your actual database URL with the correct MySQL driver (mysql://)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:CPSC449!@localhost/mysql'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# curl -X POST http://127.0.0.1:5000/login -H "Content-Type: application/json" -d '{"username":"cpsc449username","password":"cpsc449pass!"}'
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    # Check if the username and password are correct (you'll need to implement this logic)
    if username == 'cpsc449username' and password == 'cpsc449pass!':
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# curl -X GET http://127.0.0.1:5000/protected -H "Authorization: Bearer <access_token_here>"
@app.route('/protected')
@jwt_required()
def protected_route():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/')
def hello_world():
    return 'Hello, World!! - CPSC 449'

# Custom error handlers

# 404 - Not Found
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not Found', 'message': 'The requested resource was not found'}), 404

# 400 - Bad Request
@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({'error': 'Bad Request', 'message': 'The request was malformed or invalid'}), 400

# 401 - Unauthorized
@app.errorhandler(401)
def unauthorized_error(error):
    return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401

# Generic error handler for uncaught exceptions
@app.errorhandler(Exception)
def generic_error(error):
    print(error)  # Print the error to the console for debugging
    return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    app.run()
