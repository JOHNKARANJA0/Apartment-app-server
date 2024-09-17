#!/usr/bin/env python3
import os
from datetime import timedelta,datetime
import cloudinary
from cloudinary.uploader import upload as cloudinary_upload
import pyotp
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
from flask_restful import Api, Resource
from flask_cors import CORS
from models import Apartment, db, User, Lease, LeaseHistory, bcrypt
from utils import generate_totp_secret, generate_totp_token, send_email



app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]}})

app.config['SQLALCHEMY_DATABASE_URI'] =os.environ.get('DATABASE_URI') #'sqlite:///app.db' 
app.config["JWT_SECRET_KEY"] = "your_jwt_secret_key"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "your_secret_key"  

app.json.compact = False
jwt = JWTManager(app)       

migrate = Migrate(app, db)
db.init_app(app)
bcrypt.init_app(app)
api = Api(app)

cloudinary.config(
    cloud_name=os.environ.get('CLOUD_NAME'),
    api_key=os.environ.get('API_KEY'),
    api_secret=os.environ.get('API_SECRET')
)


@app.route("/")
def index():
    return "<h1>Apartment App</h1>"

class Login(Resource):
    def post(self):
        request_json = request.get_json()
        email = request_json.get('email', None)
        password = request_json.get('password', None)

        user = User.query.filter_by(email=email).first()

        if user and user.authenticate(password):
            user.is_active = True
            db.session.commit()
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}
        else:
            return {"message": "Invalid email or password"}, 401

class CheckSession(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if user:
            user.is_active = True
            db.session.commit()
            apartments = [hse.to_dict() for hse in user.apartments]
            leases = [leased.to_dict() for leased in user.leases]
            return {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "image": user.image,
                "phone": user.phone,
                "apartment": apartments,
                "lease": leases,
                "token_verified": user.token_verified,
                "is_active": user.is_active,
            }, 200
        else:
            return {"error": "User not found"}, 404

BLACKLIST = set()
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, decrypted_token):
    return decrypted_token['jti'] in BLACKLIST

class Logout(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if user:
            user.is_active = False
            db.session.commit()
        jti = get_jwt()["jti"]
        BLACKLIST.add(jti)
        return {"success": "Successfully logged out"}, 200

class VerifyToken(Resource):
    def post(self):
        data = request.get_json()
        email = data['email']
        token_from_request = data['token']

        user = User.query.filter_by(email=email).first()

        if user:
            totp = pyotp.TOTP(user.token, interval=200) 

            is_valid = totp.verify(token_from_request, valid_window=1)

            if is_valid:
                user.token_verified = True
                db.session.commit()
                return {"message": "Token verified successfully."}, 200
            else:
                return {"message": "Invalid token or email."}, 400
        else:
            return {"message": "User not found."}, 404
class Users(Resource):
    def get(self):
        users = User.query.all()
        return [user.to_dict(only=('id', 'name', 'phone', 'email', 'image', 'token', 'token_verified', 'is_active')) for user in users], 200

    def post(self):
        data = request.get_json()
        password = data['password']
        try:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            totp_secret = generate_totp_secret()
            totp_token = generate_totp_token(totp_secret)
            new_user = User(
                name=data['name'],
                phone=data['phone'],
                email=data['email'],
                _password_hash=password_hash,
                token=totp_secret
            )
            db.session.add(new_user)
            db.session.commit()
            # Send the token to user's email
            email_sent = send_email(
                to_email=data['email'],
                subject="Your Verification Token",
                body=f"""Hello, {data['name']}.\n Welcome to the Mugumo App.\nYour verification token is: {totp_token}. \n\nThank you,\nAPARTMENT MANAGEMENT"""
            )
            if email_sent:
                return {"success": "User created successfully! Verification token sent to email.", "user": new_user.to_dict()}, 201
            else:
                return {"success": "User created successfully! Failed to send verification token.", "user": new_user.to_dict()}, 201
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

class UserResource(Resource):
    @jwt_required()
    def patch(self, id):
        current_user = get_jwt_identity()
        if current_user != id:
            return {"error": "Unauthorized"}, 403

        user = User.query.get_or_404(id)
        data = request.form
        image = request.files.get('image')

        try:
            if image:
                upload_result = cloudinary_upload(image, resource_type="image", transformation=[
                    {"width": 200, "height": 200, "crop": "fill", "gravity": "auto"},
                    {"fetch_format": "auto", "quality": "auto"}
                ])
                user.image = upload_result['secure_url']
            if 'name' in data:
                user.name = data['name']
            if 'email' in data:
                user.email = data['email']
            if 'password' in data:
                old_password = data.get('old_password')
                new_password = data.get('password')
                if not user.authenticate(old_password):
                    return {"error": "Incorrect current password"}, 400
                user.password_hash = new_password

            db.session.commit()
            return {"message": "User profile updated successfully"}, 200
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

    def delete(self, id):
        user = User.query.get_or_404(id)
        db.session.delete(user)
        db.session.commit()
        return {"message": "User deleted successfully"}, 204

class Apartments(Resource):
    def get(self):
        apartments = Apartment.query.all()
        return [apartment.to_dict(only=('id', 'house_no', 'water_bill', 'electric_bill', 'trash_bill', 'security_bill', 'rent', 'created_at', 'user_id', 'report', 'status_report')) for apartment in apartments], 200

    def post(self):
        data = request.get_json()
        try:
            new_apartment = Apartment(
                house_no=data['house_no'],
                water_bill=data.get('water_bill', 0),
                electric_bill=data.get('electric_bill', 0),
                trash_bill=data.get('trash_bill', 0),
                security_bill=data.get('security_bill', 0),
                rent=data.get('rent', 0),
                report=data['report'],
                user_id=data['user_id'],
                status_report=data.get('status_report', 'Vacant')
            )
            db.session.add(new_apartment)
            db.session.commit()
            return {"success": "Apartment created successfully!", "apartment": new_apartment.to_dict()}, 201
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

class ApartmentResource(Resource):
    def get(self, id):
        apartment = Apartment.query.get_or_404(id)
        return apartment.to_dict(only=('id', 'house_no', 'water_bill', 'electric_bill', 'trash_bill', 'security_bill', 'rent', 'created_at', 'user_id', 'report', 'status_report')), 200

    def patch(self, id):
        apartment = Apartment.query.get_or_404(id)
        data = request.get_json()

        try:
            for key in ['house_no', 'water_bill', 'electric_bill', 'trash_bill', 'security_bill', 'rent', 'report', 'status_report']:
                if key in data:
                    setattr(apartment, key, data[key])

            db.session.commit()
            return {"message": "Apartment updated successfully", "apartment": apartment.to_dict()}, 200
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

    def delete(self, id):
        apartment = Apartment.query.get_or_404(id)
        db.session.delete(apartment)
        db.session.commit()
        return {"message": "Apartment deleted successfully"}, 204
class Leases(Resource):
    def get(self):
        leases = Lease.query.all()
        return [lease.to_dict(only=('id', 'user_id', 'apartment_id', 'start_date', 'end_date', 'status')) for lease in leases], 200

    def post(self):
        data = request.get_json()
        try:
            new_lease = Lease(
                user_id=data['user_id'],
                apartment_id=data['apartment_id'],
                start_date=datetime.strptime(data['start_date'], '%d/%m/%Y').date(),
                end_date=datetime.strptime(data['end_date'], '%d/%m/%Y').date(),
                status=data.get('status', 'Pending')
            )
            db.session.add(new_lease)
            db.session.commit()
            return {"success": "Lease created successfully!", "lease": new_lease.to_dict()}, 201
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

class LeaseResource(Resource):
    def get(self, id):
        lease = Lease.query.get_or_404(id)
        return lease.to_dict(only=('id', 'user_id', 'apartment_id', 'start_date', 'end_date', 'status')), 200

    def patch(self, id):
        lease = Lease.query.get_or_404(id)
        data = request.get_json()

        try:
            for key in ['user_id', 'apartment_id', 'start_date', 'end_date', 'status']:
                if key in data:
                    setattr(lease, key, data[key])

            db.session.commit()
            return {"message": "Lease updated successfully", "lease": lease.to_dict()}, 200
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

    def delete(self, id):
        lease = Lease.query.get_or_404(id)
        db.session.delete(lease)
        db.session.commit()
        return {"message": "Lease deleted successfully"}, 204
class LeaseHistories(Resource):
    def get(self):
        lease_histories = LeaseHistory.query.all()
        return [history.to_dict(only=('id', 'user_id', 'apartment_id', 'start_date', 'end_date', 'status')) for history in lease_histories], 200

    def post(self):
        data = request.get_json()
        try:
            new_history = LeaseHistory(
                user_id=data['user_id'],
                apartment_id=data['apartment_id'],
                start_date=datetime.strptime(data['start_date'], '%d/%m/%Y').date(),
                end_date=datetime.strptime(data['end_date'], '%d/%m/%Y').date(),
                status=data.get('status')
            )
            db.session.add(new_history)
            db.session.commit()
            return {"success": "Lease history created successfully!", "history": new_history.to_dict()}, 201
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

class LeaseHistoryResource(Resource):
    def get(self, id):
        history = LeaseHistory.query.get_or_404(id)
        return history.to_dict(only=('id', 'user_id', 'apartment_id', 'start_date', 'end_date', 'status')), 200

    def patch(self, id):
        history = LeaseHistory.query.get_or_404(id)
        data = request.get_json()

        try:
            for key in ['user_id', 'apartment_id', 'start_date', 'end_date', 'status']:
                if key in data:
                    setattr(history, key, data[key])

            db.session.commit()
            return {"message": "Lease history updated successfully", "history": history.to_dict()}, 200
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

    def delete(self, id):
        history = LeaseHistory.query.get_or_404(id)
        db.session.delete(history)
        db.session.commit()
        return {"message": "Lease history deleted successfully"}, 204
    
    
api.add_resource(Login, '/login')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Logout, '/logout')
api.add_resource(VerifyToken, '/verify_token')
api.add_resource(Users, '/users')
api.add_resource(UserResource, '/users/<int:id>')
api.add_resource(Apartments, '/apartments')
api.add_resource(ApartmentResource, '/apartments/<int:id>')
api.add_resource(Leases, '/leases')
api.add_resource(LeaseResource, '/leases/<int:id>')
api.add_resource(LeaseHistories, '/lease_histories')
api.add_resource(LeaseHistoryResource, '/lease_histories/<int:id>')
if __name__ == '__main__':
    app.run(port=5555, debug=True)
    