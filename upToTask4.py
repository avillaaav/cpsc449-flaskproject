from flask import Flask, jsonify, request, send_from_directory, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename  # Import secure_filename
import os

app = Flask(__name__)

app.config['PROPAGATE_EXCEPTIONS'] = True  # Enable propagating exceptions to get detailed error messages
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'cpsc449key'  # Replace with a secure secret key

# Replace with your actual database URL with the correct MySQL driver (mysql://)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:CPSC449!@localhost/mysql'

# Define the folder for storing uploaded files
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Registration route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()  # Assuming you are sending JSON data

    # Extract username and password from the request
    username = data.get('username')
    password = data.get('password')

    # Check if the user already exists (you may want to add additional checks here)
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400

    # Create a new user
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201  # Return a 201 status code for successful creation

# curl -X POST -H "Content-Type: application/json" -d '{"username":"cpsc449username","password":"cpsc449pass!"}' http://127.0.0.1:5000/login
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

# curl -X POST -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY5ODYyMjY5MCwianRpIjoiNDIyNWQ5MGItZDI5Ni00MDAxLWE0NzYtMDZiZGRhMDE4NWQwIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImNwc2M0NDl1c2VybmFtZSIsIm5iZiI6MTY5ODYyMjY5MCwiZXhwIjoxNjk4NjIzNTkwfQ.MB5ja4wZ_Rpv_tQwIP1G1sQsPPhz5E4qHkfDgfuDSoM" -F "file=@/Users/angelvilla/Desktop/CPSC449/picture.jpg" http://127.0.0.1:5000/upload
@app.route('/protected')
@jwt_required()  # Requires authentication to access this route
def protected_route():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Upload route
@app.route('/upload', methods=['POST'])
@jwt_required()  # Requires authentication to upload files
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        if file.content_length > current_app.config['MAX_CONTENT_LENGTH']:
            return jsonify({'message': 'File size exceeds the maximum allowed size'}), 400
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File uploaded successfully'}), 200
    else:
        return jsonify({'message': 'Invalid file type or size'}), 400

# Serve uploaded files
@app.route('/uploads/<filename>')
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
