from datetime import datetime
from bs4 import BeautifulSoup
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from bson import ObjectId
from flask import Flask, app, session
from pymongo import MongoClient, ReturnDocument
import requests  # Import session from Flask
from config import Config  # Import Config class from config.py
from flask import jsonify

mongo = PyMongo()
bcrypt = Bcrypt()
app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/myDatabase'
client = MongoClient(app.config['MONGO_URI'])
db = client.get_database()

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
                 github_info_id=None,  # Add github_info_id attribute
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
        self.github_info_id = github_info_id  # Add github_info_id attribute
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
            "jobs": [str(job_id) for job_id in self.jobs],
            "github_info_id": str(self.github_info_id) if self.github_info_id else None  # Add github_info_id to dict

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
                github_info_id=user_data.get("github_info_id"),  # Get github_info_id from database
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
                    "certification": new_data.get("certification", self.certification),
                    "github_info_id": new_data.get("github_info_id", self.github_info_id)  # Update github_info_id

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
                self.github_info_id = new_data.get("github_info_id", self.github_info_id)  # Update github_info_id in instance

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
        self.title = title if title is not None else "No title"
        self.description = description if description is not None else "No description"
        self.date_posted = date_posted if date_posted else datetime.utcnow()
        self.salary = salary if salary is not None else "Not specified"
        self.requirements = requirements if requirements is not None else []
        self.location = location if location is not None else "No location"
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
    def find_by_id(job_id):
        job_data = Config.mongo.db.jobs.find_one({"_id": ObjectId(job_id)})
        if job_data:
            return Job(
                title=job_data.get("title", "No title"),
                description=job_data.get("description", "No description"),
                date_posted=Job.parse_date(job_data.get("date_posted")),
                salary=job_data.get("salary", "Not specified"),
                requirements=job_data.get("requirements", []),
                location=job_data.get("location", "No location"),
                user_id=job_data.get("user_id"),
                _id=str(job_data["_id"])
            )
        return None

    @staticmethod
    def find(filter=None):
        jobs = Config.mongo.db.jobs.find(filter or {})
        return [Job(
            title=job.get("title", "No title"),
            description=job.get("description", "No description"),
            date_posted=Job.parse_date(job.get("date_posted")),
            salary=job.get("salary", "Not specified"),
            requirements=job.get("requirements", []),
            location=job.get("location", "No location"),
            user_id=job.get("user_id"),
            _id=str(job["_id"])
        ) for job in jobs]

    @staticmethod
    def parse_date(date_value):
        if isinstance(date_value, datetime):
            return date_value
        try:
            return datetime.strptime(date_value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except (ValueError, TypeError):
            return datetime.utcnow()
        
class Review:
    def __init__(self, job_id=None, user_id=None, rating=None, comment=None, date=None, _id=None):
        self.job_id = job_id
        self.user_id = user_id
        self.rating = rating
        self.comment = comment
        self.date = date if date else datetime.utcnow()
        self._id = _id

    def to_dict(self):
        return {
            "job_id": str(self.job_id),
            "user_id": str(self.user_id),
            "rating": self.rating,
            "comment": self.comment,
            "date": self.date,
            "_id": str(self._id)
        }

    def save(self):
        github_info_data = self.to_dict()
        review_data = {
            "job_id": ObjectId(self.job_id),
            "user_id": ObjectId(self.user_id),
            "rating": self.rating,
            "comment": self.comment,
            "date": self.date
        }

        try:
            if self._id:
                review_id = ObjectId(self._id)
                result = Config.mongo.db.reviews.update_one(
                    {"_id": review_id},
                    {"$set": review_data}
                )
                if result.modified_count == 1:
                    return str(review_id)
                else:
                    raise Exception("Failed to update review: Document not modified")
            else:
                self._id = str(review_id)
                return str(review_id)
        except Exception as e:
            print(f"Error saving review: {e}")
            return None

    @staticmethod
    def find_by_job_id(job_id):
        reviews = Config.mongo.db.reviews.find({"job_id": ObjectId(job_id)})
        return [Review(
            job_id=review.get("job_id"),
            user_id=review.get("user_id"),
            rating=review.get("rating"),
            comment=review.get("comment"),
            date=review.get("date"),
            _id=str(review["_id"])
        ) for review in reviews]

    @staticmethod
    def find_by_user_id(user_id):
        reviews = Config.mongo.db.reviews.find({"user_id": ObjectId(user_id)})
        return [Review(
            job_id=review.get("job_id"),
            user_id=review.get("user_id"),
            rating=review.get("rating"),
            comment=review.get("comment"),
            date=review.get("date"),
            _id=str(review["_id"])
        ) for review in reviews]

    @staticmethod
    def find_by_id(review_id):
        review_data = Config.mongo.db.reviews.find_one({"_id": ObjectId(review_id)})
        if review_data:
            return Review(
                job_id=review_data.get("job_id"),
                user_id=review_data.get("user_id"),
                rating=review_data.get("rating"),
                comment=review_data.get("comment"),
                date=review_data.get("date"),
                _id=str(review_data["_id"])
            )
        return None
    @staticmethod
    def find_top_rated():
        reviews = Config.mongo.db.reviews.find().sort("rating", -1)
        return [Review(
            job_id=review.get("job_id"),
            user_id=review.get("user_id"),
            rating=review.get("rating"),
            comment=review.get("comment"),
            date=review.get("date"),
            _id=str(review["_id"])
        ) for review in reviews]
    
from bson.objectid import ObjectId

class GithubInfo:
    def __init__(self,
                 user_id=None,
                 username=None,
                 user_url=None,
                 repositories=None,
                 followers=None,
                 following=None,
                 starred_repos=None,
                 _id=None):
        self.user_id = user_id
        self.username = username
        self.user_url = user_url
        self.repositories = repositories or []
        self.followers = followers or 0
        self.following = following or 0
        self.starred_repos = starred_repos or []

        self._id = _id
        self.client = MongoClient('mongodb://localhost:27017/')
        self.db = self.client['myDatabase']
        self.collection = self.db['github_info']

    def save_info(self):
        info = {
            "user_id": ObjectId(self.user_id),
            "username": self.username,
            "user_url": self.user_url,
            "repositories": self.repositories,
            "followers": self.followers,
            "following": self.following,
            "starred_repos": self.starred_repos
        }
        if self._id:
            self.collection.update_one({"_id": self._id}, {"$set": info}, upsert=True)
        else:
            self.collection.insert_one(info)

    def to_dict(self):
        return {
            "user_id": str(self.user_id),
            "username": self.username,
            "user_url": self.user_url,
            "repositories": self.repositories,
            "followers": self.followers,
            "following": self.following,
            "starred_repos": self.starred_repos
        }

    @staticmethod
    def find_by_user_id(user_id):
        try:
            client = MongoClient('mongodb://localhost:27017/')
            db = client['myDatabase']
            github_info_data = db.github_info.find_one({"user_id": ObjectId(user_id)})
            if github_info_data:
                return GithubInfo(
                    user_id=github_info_data['user_id'],
                    username=github_info_data.get('username'),
                    user_url=github_info_data.get('user_url'),
                    repositories=github_info_data.get('repositories', []),
                    followers=github_info_data.get('followers', 0),
                    following=github_info_data.get('following', 0),
                    starred_repos=github_info_data.get('starred_repos', []),
                    _id=str(github_info_data['_id'])
                )
            return None
        except Exception as e:
            print(f"Error finding GitHub info by user ID: {e}")
            return None

    def scrape_github(self):
        user = User.find_by_id(self.user_id)
        if not user:
            print(f"No user found with ID {self.user_id}")
            return

        self.github_url = user.github  # Fetching github URL from the User class
        if not self.github_url:
            print("No GitHub URL found for the user.")
            return

        response = requests.get(self.github_url)
        if response.status_code != 200:
            print(f"Failed to fetch GitHub page for user {self.username}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')

        # Assuming you have logic here to extract repositories, followers, following, etc.
        # Here's a placeholder for setting these values
        self.username = user.username
        repo = f'https://api.github.com/users/{self.username}/repos'
        self.user_url = repo
        self.repositories = self.extract_repositories()
        self.followers = self.extract_followers()
        self.following = self.extract_following()
        self.starred_repos = self.extract_starred_repos()

        self.save_info()

    def extract_repositories(self):
        # Fetch repositories from GitHub API
        repos_url = f'https://api.github.com/users/{self.username}/repos'
        response = requests.get(repos_url)
        if response.status_code == 200:
            repos_data = response.json()
            return [repo['name'] for repo in repos_data]
        return []

    def extract_followers(self):
        # Fetch followers count from GitHub API
        user_url = f'https://api.github.com/users/{self.username}'
        response = requests.get(user_url)
        if response.status_code == 200:
            user_data = response.json()
            return user_data.get('followers', 0)
        return 0

    def extract_following(self):
        # Fetch following count from GitHub API
        user_url = f'https://api.github.com/users/{self.username}'
        response = requests.get(user_url)
        if response.status_code == 200:
            user_data = response.json()
            return user_data.get('following', 0)
        return 0

    def extract_starred_repos(self):
        # Fetch starred repositories from GitHub API
        stars_url = f'https://api.github.com/users/{self.username}/starred'
        response = requests.get(stars_url)
        if response.status_code == 200:
            stars_data = response.json()
            return [repo['name'] for repo in stars_data]
        return []
