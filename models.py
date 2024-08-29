#!/usr/bin/env python3

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from flask_bcrypt import Bcrypt
from datetime import datetime

bcrypt = Bcrypt()

metadata = MetaData(
    naming_convention={
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)
db = SQLAlchemy(metadata=metadata)

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)  # Changed to String to handle leading zeros
    email = db.Column(db.String(100), unique=True, nullable=False)
    image = db.Column(db.String, nullable=True)
    _password_hash = db.Column('password_hash', db.String(128), nullable=False)
    token = db.Column(db.String(32), nullable=True)
    token_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # Relationships
    apartments = db.relationship('Apartment', backref='user', lazy=True, cascade='all, delete-orphan')
    leases = db.relationship('Lease', backref='user', lazy=True, cascade='all, delete-orphan')
    
    # Serialization rules
    serialize_rules = ('-apartments.user', '-_password_hash', '-leases.user')
    
    @validates('email')
    def validate_email(self, key, value):
        assert '@' in value, "Invalid Email provided"
        return value
    
    @hybrid_property    
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')
    
    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')
    
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))


class Apartment(db.Model, SerializerMixin):
    __tablename__ = 'apartments'
    
    id = db.Column(db.Integer, primary_key=True)
    house_no = db.Column(db.String, nullable=False)
    water_bill = db.Column(db.Integer, default=0)
    electric_bill = db.Column(db.Integer, default=0)
    trash_bill = db.Column(db.Integer, default=0)
    security_bill = db.Column(db.Integer, default=0)
    rent = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    report = db.Column(db.String, nullable=False)
    status_report = db.Column(db.String(50), nullable=False, default='Vacant') 
    
    # Relationships
    leases = db.relationship('Lease', backref='apartment', lazy=True)
    
    # Serialization rules
    serialize_rules = ('-user.apartments',)
    
    @validates('status_report')
    def update_lease_dates(self, key, value):
        if value == "Occupied":
            # Update start_date for the active lease
            active_lease = Lease.query.filter_by(apartment_id=self.id, status='Pending').first()
            if active_lease:
                active_lease.start_date = datetime.now()
        elif value == "Vacant":
            # Update end_date for the last lease
            last_lease = Lease.query.filter_by(apartment_id=self.id, status='Approved').order_by(Lease.start_date.desc()).first()
            if last_lease:
                last_lease.end_date = datetime.now()
                last_lease.status = 'Terminated'
                # Move to LeaseHistory
                lease_history = LeaseHistory(
                    user_id=last_lease.user_id,
                    apartment_id=last_lease.apartment_id,
                    start_date=last_lease.start_date,
                    end_date=last_lease.end_date,
                    status=last_lease.status
                )
                db.session.add(lease_history)
                db.session.commit()
        return value


class Lease(db.Model, SerializerMixin):
    __tablename__ = 'leases'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    apartment_id = db.Column(db.Integer, db.ForeignKey('apartments.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='Pending')  # 'Pending', 'Approved', 'Rejected', 'Terminated'

    # Relationships
    user = db.relationship('User', back_populates='leases')
    apartment = db.relationship('Apartment', back_populates='leases')

    # Serialization rules 
    serialize_rules = ('-user.leases', '-apartment.leases')
    
class LeaseHistory(db.Model, SerializerMixin):
    __tablename__ = 'lease_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    apartment_id = db.Column(db.Integer, db.ForeignKey('apartments.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), nullable=False)

    # Relationships
    user = db.relationship('User')
    apartment = db.relationship('Apartment')

    # Serialization rules 
    serialize_rules = ('-user.leases', '-apartment.leases')