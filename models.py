from datetime import datetime
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
                 role=None,
                 jobs=None,
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
        self.role = role
        self.jobs = jobs or []
        self._id = _id

    def to_dict(self):
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
            "role": self.role,
            "jobs": [str(job_id) for job_id in self.jobs]
        }

    def __str__(self):
        return f"User(_id={self._id}, username={self.username}, email={self.email}, phone_number={self.phone_number}, _id={self._id})"

    @staticmethod
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
                role=user_data.get("role"),
                jobs=user_data.get("jobs", []),
                _id=str(user_data['_id'])
            )
        return None

    def update_profile(self, new_data):
        try:
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

            result = Config.mongo.db.users.update_one(
                {"_id": self.id},
                update_query
            )

            if result.modified_count > 0:
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

    @staticmethod
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
                role=user_data.get("role"),
                jobs=user_data.get("jobs", []),
                _id=str(user_data['_id'])
            )
            print(f"User data: {user.__dict__}")
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
            "role": self.role,
            "jobs": self.jobs
        }

        try:
            if self._id:
                try:
                    obj_id = ObjectId(self._id)
                except Exception as e:
                    raise ValueError(f"Invalid _id format: {self._id}. Error: {e}")

                current_user = Config.mongo.db.users.find_one({"_id": obj_id})
                if current_user is None:
                    raise Exception(f"User with _id {self._id} not found in the database")

                if self.password and self.password != current_user.get('password'):
                    user_data["password"] = bcrypt.generate_password_hash(self.password).decode('utf-8')

                if any(current_user.get(field) != user_data.get(field) for field in user_data if field != "password"):
                    result = Config.mongo.db.users.update_one({"_id": obj_id}, {"$set": user_data})

                    if result.modified_count == 1:
                        session['user_id'] = self._id
                        return self._id
                    else:
                        raise Exception("Failed to update user: Document not modified")
                else:
                    print("No changes detected, skipping update.")
                    return self._id

            else:
                user_data["password"] = bcrypt.generate_password_hash(self.password).decode('utf-8')
                user_id = Config.mongo.db.users.insert_one(user_data).inserted_id
                self._id = str(user_id)

                session['user_id'] = self._id
                return self._id

        except Exception as e:
            print(f"Error saving user: {e}")
            return None

    @staticmethod
    def change_password(email, new_password):
        try:
            print(f"New password before hashing: {new_password}")

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

    @staticmethod
    def find_by_id(user_id):
        try:
            user_data = Config.mongo.db.users.find_one({"_id": ObjectId(user_id)})
            
            if not user_data:
                user_data = Config.mongo.db.users.find_one({"_id": user_id})
            
            if user_data:
                _id = str(user_data['_id'])
                
                return User(
                    id=_id,
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
                    role=user_data.get("role"),
                    jobs=user_data.get("jobs", []),
                    _id=_id
                )
            return None
        except Exception as e:
            print(f"Error finding user by ID: {e}")
            return None

    def get_user_jobs(self):
        try:
            user_id = self._id
            job_data = Config.mongo.db.jobs.find({"user_id": ObjectId(user_id)})
            jobs = [Job(
                title=job["title"],
                description=job["description"],
                date_posted=job["date_posted"],
                salary=job["salary"],
                requirements=job["requirements"],
                location=job["location"],
                user_id=job["user_id"],
                _id=str(job["_id"])
            ) for job in job_data]
            return jobs
        except Exception as e:
            print(f"Error getting user jobs: {e}")
            return []

    @staticmethod
    def find_user_by_id(user_id):
        try:
            user_data = Config.mongo.db.users.find_one({"_id": ObjectId(user_id)})
            if user_data:
                return User(
                    id=user_data['_id'],
                    username=user_data['username'],
                    email=user_data['email'],
                    phone_number=user_data['phone_number'],
                    github=user_data['github'],
                    linkedin=user_data['linkedin'],
                    technical_skills=user_data['technical_skills'],
                    professional_skills=user_data['professional_skills'],
                    certification=user_data['certification'],
                    role=user_data['role'],
                    jobs=user_data['jobs'],
                    _id=user_data['_id']
                )
            return None
        except Exception as e:
            print(f"Error finding user by ID: {e}")
            return None

class Job:
    def __init__(self, title=None, description=None, date_posted=None, salary=None, requirements=None, location=None, user_id=None, _id=None):
        self.title = title
        self.description = description
        self.date_posted = date_posted if date_posted else datetime.utcnow()
        self.salary = salary
        self.requirements = requirements or []
        self.location = location
        self.user_id = user_id
        self._id = _id

    def to_dict(self):
        return {
            "title": self.title,
            "description": self.description,
            "date_posted": self.date_posted,
            "salary": self.salary,
            "requirements": self.requirements,
            "location": self.location,
            "user_id": str(self.user_id),
            "_id": str(self._id)
        }

    def save(self):
        job_data = {
            "title": self.title,
            "description": self.description,
            "date_posted": self.date_posted,
            "salary": self.salary,
            "requirements": self.requirements,
            "location": self.location,
            "user_id": ObjectId(self.user_id)
        }

        try:
            if self._id:
                job_id = ObjectId(self._id)
                result = Config.mongo.db.jobs.update_one(
                    {"_id": job_id},
                    {"$set": job_data}
                )
                if result.modified_count == 1:
                    return str(job_id)
                else:
                    raise Exception("Failed to update job: Document not modified")
            else:
                job_id = Config.mongo.db.jobs.insert_one(job_data).inserted_id
                self._id = str(job_id)

                # Add the job ID to the user's job list
                user = User.find_by_id(self.user_id)
                if user:
                    user.jobs.append(job_id)
                    Config.mongo.db.users.update_one(
                        {"_id": ObjectId(self.user_id)},
                        {"$addToSet": {"jobs": job_id}}
                    )
                    return str(job_id)
                else:
                    raise Exception("Failed to find user to associate with the job")
        except Exception as e:
            print(f"Error saving job: {e}")
            return None

    @staticmethod
    def find_by_user_id(user_id):
        jobs = Config.mongo.db.jobs.find({"user_id": ObjectId(user_id)})
        return [Job(
            title=job["title"],
            description=job["description"],
            date_posted=job["date_posted"],
            salary=job["salary"],
            requirements=job["requirements"],
            location=job["location"],
            user_id=job["user_id"],
            _id=str(job["_id"])
        ) for job in jobs]

    @staticmethod
    def find_by_id(job_id):
        job_data = Config.mongo.db.jobs.find_one({"_id": ObjectId(job_id)})
        if job_data:
            return Job(
                title=job_data["title"],
                description=job_data["description"],
                date_posted=job_data["date_posted"],
                salary=job_data["salary"],
                requirements=job_data["requirements"],
                location=job_data["location"],
                user_id=job_data["user_id"],
                _id=str(job_data["_id"])
            )
        return None
