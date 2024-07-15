import traceback
from flask import Blueprint, request, jsonify, current_app, session
from models import User, bcrypt
from twilio.rest import Client
from flask_mail import Mail, Message
import random
import re
import os
import fitz
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask import Flask, jsonify, request, session
from bson import ObjectId  # Import ObjectId from bson package
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Required for session management
app.config['MONGO_URI'] = 'mongodb://localhost:27017/myDatabase'

auth = Blueprint('auth', __name__)  # Define blueprint after necessary imports

# Twilio configuration
TWILIO_ACCOUNT_SID = 'AC64a0e8f2d4cb5742e2e9066ae86ef03e'
TWILIO_AUTH_TOKEN = '52c70879d1547a04dbf875cecd5d564a'
TWILIO_PHONE_NUMBER = '+15736484216'
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
otp_storage = {}
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}  # Define the set of allowed file extensions
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
# Function to generate OTP
# Function to generate OTP
def generate_otp():
    return random.randint(100000, 999999)

def send_otp_phone(phone_number, otp):
    if twilio_client:
        message = twilio_client.messages.create(
            body=f'Your OTP is {otp}',
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        return message.sid
    else:
        return None

# Function to send OTP to email

# Function to send OTP to email
def send_otp_email(email, otp):
    try:
        mail = current_app.extensions['mail']
        msg = Message('Your OTP Code', sender=current_app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your OTP is {otp}'
        mail.send(msg)
        print(f"OTP email sent to {email}")
    except Exception as e:
        print(f"Error sending OTP email: {e}")
        raise e

# Function to validate phone number format
def is_valid_phone_number(input_str):
    return re.fullmatch(r'^\d{8}$', input_str) is not None

# Function to validate email format
def is_valid_email(input_str):
    return re.fullmatch(r'[^@]+@[^@]+\.[^@]+', input_str) is not None

# Function to send OTP based on contact info type (phone or email)
def send_otp(contact_info, otp):
    if is_valid_phone_number(contact_info):
        send_otp_phone(f'+216{contact_info}', otp)
    elif is_valid_email(contact_info):
        send_otp_email(contact_info, otp)
    session[contact_info] = otp
    session.modified = True  # Ensure the session is saved
    print(f"OTP sent to {contact_info}: {otp}")


def validate_otp(contact_info, otp_attempt):
    stored_otp = session.get(contact_info)
    print(f"Validating OTP for {contact_info}. Stored OTP: {stored_otp}, OTP Attempt: {otp_attempt}")  # Debug print
    if stored_otp and str(stored_otp) == str(otp_attempt):
        session.pop(contact_info, None)  # Remove OTP from session after successful validation
        session.modified = True  # Ensure the session is saved
        return True
    return False
# Function to extract text from PDF
def extract_information_from_pdf(pdf_file):
    doc = fitz.open(pdf_file)
    text = ""
    for page_num in range(len(doc)):
        page = doc.load_page(page_num)
        text += page.get_text()
    return text

# Function to extract information from text and populate a User object
def extract_information(text):
    extracted_info = User()

    # Extract email using regular expression
    email_pattern = re.compile(r"Email:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", re.IGNORECASE)
    email_match = re.search(email_pattern, text)
    if email_match:
        extracted_info.email = email_match.group(1)

    # Extract phone number using regular expression
    phone_pattern = re.compile(r"Phone:\s*\((\d{3})\)\s*(\d{3})-(\d{4})", re.IGNORECASE)
    phone_match = re.search(phone_pattern, text)
    if phone_match:
        extracted_info.phone_number = f"({phone_match.group(1)}) {phone_match.group(2)}-{phone_match.group(3)}"

    # Extract GitHub using regular expression
    github_pattern = re.compile(r"GitHub:\s*(https://github.com/\S+)", re.IGNORECASE)
    github_match = re.search(github_pattern, text)
    if github_match:
        extracted_info.github = github_match.group(1)

    # Extract LinkedIn using regular expression
    linkedin_pattern = re.compile(r"LinkedIn:\s*(https://www.linkedin.com/in/\S+)", re.IGNORECASE)
    linkedin_match = re.search(linkedin_pattern, text)
    if linkedin_match:
        extracted_info.linkedin = linkedin_match.group(1)

    # Extract technical skills using regular expression
    technical_skills_pattern = re.compile(r"Technical Skills:(.*?)Professional Skills:", re.DOTALL)
    technical_skills_match = re.search(technical_skills_pattern, text)
    if technical_skills_match:
        technical_skills_text = technical_skills_match.group(1).strip()
        extracted_info.technical_skills = [skill.strip() for skill in technical_skills_text.split(",")]

    # Extract professional skills using regular expression
    professional_skills_pattern = re.compile(r"Professional Skills:(.*?)Certifications:", re.DOTALL)
    professional_skills_match = re.search(professional_skills_pattern, text)
    if professional_skills_match:
        professional_skills_text = professional_skills_match.group(1).strip()
        extracted_info.professional_skills = [skill.strip() for skill in professional_skills_text.split(",")]

    # Extract certification information using regular expression
    certification_pattern = re.compile(r"Certifications:.*?Organization:\s*(.*?)\s*Name:\s*(.*?)\s*Year:\s*(\d{4})", re.DOTALL)
    certification_match = re.search(certification_pattern, text)
    if certification_match:
        extracted_info.certification["organization"] = certification_match.group(1).strip()
        extracted_info.certification["name"] = certification_match.group(2).strip()
        extracted_info.certification["year"] = certification_match.group(3).strip()

    return extracted_info


@auth.route('/forgot_password/send_otp', methods=['POST'])
def send_otp_route():
    data = request.get_json()
    contact_info = data.get('contact_info')
    
    if not contact_info:
        return jsonify({'error': 'Contact information is required'}), 400
    
    try:
        user = User.find_by_contact_info(contact_info)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate OTP
        otp = random.randint(100000, 999999)
        
        # Send OTP
        send_otp(contact_info, otp)
        
        # Save OTP and user info in session
        session['forgot_password_contact_info'] = contact_info
        session['forgot_password_user_id'] = user._id
        session['forgot_password_otp'] = otp
        
        return jsonify({'message': 'OTP sent successfully', 'user_id': user._id}), 200
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return jsonify({'error': 'Failed to send OTP'}), 500


# Route to send OTP
@auth.route('/signup', methods=['POST'])
def signup():
    try:
        # Extract form data from request
        username = request.form.get('username')
        password = request.form.get('password')
        pdf_file = request.files.get('pdf_file')

        # Debug output to check form data
        print(f"Username: {username}, Password: {password}")

        if not username or not password or not pdf_file:
            return jsonify({"error": "Username, password, and PDF file are required"}), 400

        if User.find_by_username(username):
            return jsonify({"error": "Username already exists"}), 400

        # Ensure the file is not None before processing
        if pdf_file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        # Save the uploaded file securely
        filename = secure_filename(pdf_file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        pdf_file.save(filepath)

        try:
            # Extract information from the PDF
            text = extract_information_from_pdf(filepath)
            extracted_info = extract_information(text)

            # Use extracted information for user registration
            email = extracted_info.email
            phone_number = extracted_info.phone_number

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(
                username=username,
                password=hashed_password,
                email=email,
                phone_number=phone_number,
                github=extracted_info.github,
                linkedin=extracted_info.linkedin,
                technical_skills=extracted_info.technical_skills,
                professional_skills=extracted_info.professional_skills,
                certification=extracted_info.certification
            )
            user_id = user.save()

            if not user_id:
                return jsonify({"error": "Failed to create user"}), 500

            return jsonify({
                "message": "User created successfully",
                "_id": str(user_id),
                "username": user.username
            }), 201

        except Exception as e:
            return jsonify({"error": f"Error processing PDF: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@auth.route('/forgot_password/change_password', methods=['POST'])
def forgot_password_change_password():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid input"}), 400

    new_password = data.get('new_password')
    email = data.get('email')

    if not new_password or not email:
        return jsonify({"error": "Email and new password are required"}), 400

    try:
        # Print the new password before hashing (for debugging purposes)
        print(f"New password before hashing: {new_password}")

        # Find user by email (which acts as the username)
        user = User.find_by_email(email)

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Hash the new password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Update user's password in the database
        user.change_password(email, new_password)  # This method saves the updated password

        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        app.logger.error(f"Error changing password: {e}")
        return jsonify({"error": "Failed to change password"}), 500




@auth.route('/forgot_password/validate_otp', methods=['POST'])
def validate_otp_route():
    data = request.get_json()
    contact_info = data.get('contact_info')
    otp_attempt = data.get('otp')
    
    if not contact_info or not otp_attempt:
        return jsonify({'error': 'Contact information and OTP are required'}), 400
    
    # Retrieve stored OTP and user info from session
    stored_user_id = session.get('forgot_password_user_id')
  
    

    
    # If OTP is valid, you can proceed with the password reset or any further steps
    # For example, you can set a session flag to indicate OTP validation success
    session['otp_validated'] = True
    
    return jsonify({'message': 'OTP validated successfully', 'user_id': stored_user_id,'contact_info':contact_info}), 200


  
@auth.route('/signin', methods=['POST'])
def signin():
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Invalid input"}), 400

        username = data['username']
        password = data['password']

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        user = User.find_by_username(username)
        if not user:
            return jsonify({"error": "User not found"}), 404

        if not bcrypt.check_password_hash(user.password, password):
            return jsonify({"error": "Invalid password"}), 401

        return jsonify({
            "message": "Sign-in successful",
            "_id": str(user._id),
            "username": user.username
        }), 200
    except Exception as e:
        print(f"Exception in signin route: {e}")
        return jsonify({"error": "Internal server error"}), 500
@auth.route('/profile/<user_id>', methods=['GET'])
def get_user_profile(user_id):
    try:
        print(f"Received user_id: {user_id}")

        # Check if user_id is a valid ObjectId
        if not ObjectId.is_valid(user_id):
            return jsonify({"error": "Invalid user ID format"}), 400

        # Find user by ID
        user = User.find_by_id(user_id)
        
        if not user:
            print(f"User with id {user_id} not found in the database")
            return jsonify({"error": "User not found"}), 404

        # Convert user object to dictionary
        user_data = user.to_dict()
        print(f"User data: {user_data}")

        return jsonify(user_data), 200

    except Exception as e:
        print(f"Error retrieving user profile: {e}")
        return jsonify({"error": str(e)}), 500


@auth.route('/profile/update/<user_id>', methods=['PUT'])
def update_user_profile(user_id):
    try:
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Extract updated profile data from request
        data = request.get_json()
        new_data = {
            "email": data.get("email", user.email),
            "phone_number": data.get("phone_number", user.phone_number),
            "github": data.get("github", user.github),
            "linkedin": data.get("linkedin", user.linkedin)
        }

        # Update user profile
        user.update_profile(new_data)

        return jsonify({"message": "Profile updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
