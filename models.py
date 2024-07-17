from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from bson import ObjectId
from flask import session
from pymongo import ReturnDocument  # Import session from Flask
from config import Config  # Import Config class from config.py

mongo = PyMongo()
bcrypt = Bcrypt()

class User:
    def __init__(self,
                 id=None,
                 username=None,
                 password=None,
                 email=None,
                 phone_number=None,
                 github=None,
                 linkedin=None,
                 technical_skills=None,
                 professional_skills=None,
                 certification=None,
                 role=None,  # Add role attribute
                 _id=None):
            
        self.id = id
        self.username = username
        self.password = password
        self.email = email
        self.phone_number = phone_number
        self.github = github
        self.linkedin = linkedin
        self.technical_skills = technical_skills or []
        self.professional_skills = professional_skills or []
        self.certification = certification or {
            "organization": None,
            "name": None,
            "year": None
        }
        self.role = role  # Initialize role
        self._id = _id

    def to_dict(self):
        # Convert object attributes to dictionary
        return {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "phone_number": self.phone_number,
            "github": self.github,
            "linkedin": self.linkedin,
            "technical_skills": self.technical_skills,
            "professional_skills": self.professional_skills,
            "certification": self.certification,
            "role": self.role  # Add role to dictionary

        }
    def __str__(self):
        return f"User(_id={self._id}username={self.username}, email={self.email}, phone_number={self.phone_number}, _id={self._id})"

    def find_by_username(username):
        user_data = Config.mongo.db.users.find_one({"username": username})
        if user_data:
            return User(
                id=user_data["_id"],
                username=user_data['username'],
                password=user_data['password'],
                email=user_data.get('email'),
                phone_number=user_data.get('phone_number'),
                github=user_data.get('github'),
                linkedin=user_data.get('linkedin'),
                technical_skills=user_data.get('technical_skills', []),
                professional_skills=user_data.get('professional_skills', []),
                certification=user_data.get('certification', {
                    "organization": None,
                    "name": None,
                    "year": None
                }),
                role=user_data.get("role"),  # Fix role attribute access
                _id=str(user_data['_id'])  # Convert ObjectId to string
            )
        return None
    def update_profile(self, new_data):
        try:
            # Convert self.id to ObjectId if it's not already
            if not isinstance(self.id, ObjectId):
                self.id = ObjectId(self.id)

            update_query = {
                "$set": {
                    "email": new_data.get("email", self.email),
                    "phone_number": new_data.get("phone_number", self.phone_number),
                    "github": new_data.get("github", self.github),
                    "linkedin": new_data.get("linkedin", self.linkedin),
                    "technical_skills": new_data.get("technical_skills", self.technical_skills),
                    "professional_skills": new_data.get("professional_skills", self.professional_skills),
                    "certification": new_data.get("certification", self.certification)
                }
            }

            # Update user in MongoDB
            result = Config.mongo.db.users.update_one(
                {"_id": self.id},
                update_query
            )

            if result.modified_count > 0:
                # Update self attributes from new_data
                self.email = new_data.get("email", self.email)
                self.phone_number = new_data.get("phone_number", self.phone_number)
                self.github = new_data.get("github", self.github)
                self.linkedin = new_data.get("linkedin", self.linkedin)
                self.technical_skills = new_data.get("technical_skills", self.technical_skills)
                self.professional_skills = new_data.get("professional_skills", self.professional_skills)
                self.certification = new_data.get("certification", self.certification)

                print(f"User profile updated: {new_data}")

                return True
            else:
                print(f"User with _id {self.id} not found in the database or no modifications were made.")
                return False

        except Exception as e:
            print(f"Error updating user profile: {e}")
            return False
    def find_by_contact_info(contact_info):
            user_data = Config.mongo.db.users.find_one({
                "$or": [
                    {"email": contact_info},
                    {"phone_number": contact_info}
                ]
            })
            if user_data:
                user = User(
                    username=user_data['username'],
                    password=user_data['password'],
                    email=user_data.get('email'),
                    phone_number=user_data.get('phone_number'),
                    github=user_data.get('github'),
                    linkedin=user_data.get('linkedin'),
                    technical_skills=user_data.get('technical_skills', []),
                    professional_skills=user_data.get('professional_skills', []),
                    certification=user_data.get('certification', {
                        "organization": None,
                        "name": None,
                        "year": None
                    }),
                     role=user_data.get("role"),  # Fix role attribute access
                    _id=str(user_data['_id'])  # Convert ObjectId to string
                )
                print(f"User data: {user.__dict__}")  # Print user data
                return user
            return None
    def save(self):
        user_data = {
            "username": self.username,
            "email": self.email,
            "phone_number": self.phone_number,
            "github": self.github,
            "linkedin": self.linkedin,
            "technical_skills": self.technical_skills,
            "professional_skills": self.professional_skills,
            "certification": self.certification,
             "role": self.role  # Add role to user data

        }

        try:
            if self._id:
                # Update existing user document
                try:
                    obj_id = ObjectId(self._id)
                except Exception as e:
                    raise ValueError(f"Invalid _id format: {self._id}. Error: {e}")

                # Retrieve current user data from MongoDB
                current_user = Config.mongo.db.users.find_one({"_id": obj_id})
                if current_user is None:
                    raise Exception(f"User with _id {self._id} not found in the database")

                # Update password if it has changed
                if self.password and self.password != current_user.get('password'):
                    user_data["password"] = bcrypt.generate_password_hash(self.password).decode('utf-8')

                # Check if there are actual changes (excluding password)
                if any(current_user.get(field) != user_data.get(field) for field in user_data if field != "password"):
                    result = Config.mongo.db.users.update_one({"_id": obj_id}, {"$set": user_data})

                    if result.modified_count == 1:
                        # Update the session with the user ID
                        session['user_id'] = self._id
                        return self._id
                    else:
                        raise Exception("Failed to update user: Document not modified")
                else:
                    print("No changes detected, skipping update.")
                    # No update needed, return existing _id
                    return self._id

            else:
                # Insert new user document
                user_data["password"] = bcrypt.generate_password_hash(self.password).decode('utf-8')
                user_id = Config.mongo.db.users.insert_one(user_data).inserted_id
                self._id = str(user_id)

                # Update the session with the new user ID
                session['user_id'] = self._id
                return self._id

        except Exception as e:
            print(f"Error saving user: {e}")
            return None

    @staticmethod
    def change_password(email, new_password):
        try:
            # Print the new password before hashing (for debugging purposes)
            print(f"New password before hashing: {new_password}")

            # Find user by email
            user_data = Config.mongo.db.users.find_one({"email": email})

            if user_data:
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                result = Config.mongo.db.users.update_one({"email": email}, {"$set": {"password": hashed_password}})

                if result.modified_count == 1:
                    return True
                else:
                    raise Exception("Failed to update password: Document not modified")
            else:
                print(f"No user found with email {email}")
                return False
        except Exception as e:
            print(f"Error changing password: {e}")
            return False




    @staticmethod
    def validate_password(stored_password, provided_password):
        return bcrypt.check_password_hash(stored_password, provided_password)

    def find_by_id(user_id):
        try:
            # Try to find the user with _id as ObjectId
            user_data = Config.mongo.db.users.find_one({"_id": ObjectId(user_id)})
            
            if not user_data:
                # If not found as ObjectId, try to find as string
                user_data = Config.mongo.db.users.find_one({"_id": user_id})
            
            if user_data:
                # Ensure _id is always a string for consistency
                _id = str(user_data['_id'])
                
                return User(
                    id=_id,  # Convert ObjectId to string if necessary
                    username=user_data['username'],
                    password=user_data['password'],
                    email=user_data.get('email'),
                    phone_number=user_data.get('phone_number'),
                    github=user_data.get('github'),
                    linkedin=user_data.get('linkedin'),
                    technical_skills=user_data.get('technical_skills', []),
                    professional_skills=user_data.get('professional_skills', []),
                    certification=user_data.get('certification', {
                        "organization": None,
                        "name": None,
                        "year": None
                    }),
                     role=user_data.get("role"),  # Fix role attribute access
                    _id=_id  # Ensure _id is always a string
                )
            else:
                print(f"No user found with id {user_id}")
                return None
        except Exception as e:
            print(f"Error finding user by id: {e}")
            return None