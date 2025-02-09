import random

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Column, Integer, String, Date, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
import uuid
from datetime import date
import smtplib
import json
import os

from dotenv import load_dotenv
load_dotenv()

smtp_server = "smtp.gmail.com"
smtp_port = 587
sender_email = os.getenv("SENDER_EMAIL")
password = os.getenv("SENDER_PASSWORD")

verification_db = {}


def send_verification_code(email: str, code: int) -> None:
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, email, f"Subject: Verification Code\n\nYour code: {code}")
            print("Email sent successfully!")
    except Exception as e:
        print("Error:", e)


app = FastAPI()
Base = declarative_base()
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

encryptor = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Database Model
class UserDB(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    surname = Column(String, nullable=True)
    nickname = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    date_of_birth = Column(Date, nullable=False)
    hashed_password = Column(String, nullable=False)
    contacts = Column(String, nullable=False, default="[]")  # Store contacts as JSON


# Pydantic Model for Request/Response
class UserCreate(BaseModel):
    name: str = Field(..., min_length=1)
    surname: str | None = None
    nickname: str = Field(..., min_length=3)
    email: EmailStr
    date_of_birth: date
    password: str = Field(..., min_length=6)


class UserResponse(BaseModel):
    id: str
    name: str
    surname: str | None
    nickname: str
    email: EmailStr
    date_of_birth: date

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    nickname: str
    password: str


class VerifyUser(BaseModel):
    user_id: str
    verification_code: int


# Dependency for DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class Message(BaseModel):
    sender: str
    text: str
    send_date: date


# Create tables
Base.metadata.create_all(bind=engine)


@app.post("/register/")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.nickname == user.nickname).first():
        raise HTTPException(status_code=400, detail="Nickname already in use")
    if db.query(UserDB).filter(UserDB.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already in use")

    hashed_password = encryptor.hash(user.password)
    new_user = UserDB(
        name=user.name,
        surname=user.surname,
        nickname=user.nickname,
        email=user.email,
        date_of_birth=user.date_of_birth,
        hashed_password=hashed_password,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    verification_db[new_user.id] = random.randint(100000, 999999)
    send_verification_code(new_user.email, verification_db[new_user.id])
    return {"user_id": new_user.id}


@app.post("/login/")
def login_user(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.nickname == user.nickname).first()
    if not db_user or not encryptor.verify(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid nickname or password")

    return {"user_id": db_user.id}


@app.post("/verify/")
def verify_user(verify_data: VerifyUser):
    if verify_data.user_id not in verification_db:
        raise HTTPException(status_code=400, detail="Invalid user ID")
    if verification_db[verify_data.user_id] != verify_data.verification_code:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    del verification_db[verify_data.user_id]
    return {"message": "Verification successful"}


@app.delete("/delete/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()
    return {"message": "User deleted successfully"}


@app.post("/addcontact/{user_id}/{contact_nickname}")
def add_contact(user_id: str, contact_nickname: str, db: Session = Depends(get_db)):
    # Find the user adding the contact
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Find the contact user by their nickname
    contact_user = db.query(UserDB).filter(UserDB.nickname == contact_nickname).first()
    if not contact_user:
        raise HTTPException(status_code=404, detail="Contact user not found")

    # Prevent adding self as a contact
    if user.nickname == contact_nickname:
        raise HTTPException(status_code=400, detail="You cannot add yourself as a contact")

    # Update user's contacts
    user_contacts = json.loads(user.contacts)
    if contact_nickname not in user_contacts:
        user_contacts.append(contact_nickname)
        user.contacts = json.dumps(user_contacts)

    # Update contact's contacts (add the user)
    contact_user_contacts = json.loads(contact_user.contacts)
    if user.nickname not in contact_user_contacts:
        contact_user_contacts.append(user.nickname)
        contact_user.contacts = json.dumps(contact_user_contacts)

    # Commit the changes
    db.commit()
    
    return {"message": "Contact added successfully to both users"}



@app.post("/sendMessage/{user_id}/{contact_nickname}")
def send_message(user_id: str, contact_nickname: str, message: Message, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    contacts = json.loads(user.contacts)
    if contact_nickname not in contacts:
        raise HTTPException(status_code=400, detail="Contact not found")

    file_path = f"conversations/{user.nickname}_{contact_nickname}.json"
    os.makedirs("conversations", exist_ok=True)

    conversation = []
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            conversation = json.load(f)

    conversation.append({
        "sender": message.sender,
        "text": message.text,
        "send_date": message.send_date.isoformat()
    })

    with open(file_path, "w") as f:
        json.dump(conversation, f, indent=4)

    return {"message": "Message sent successfully"}


@app.get("/profile_info/{user_id}")
def get_profile_info(user_id: str, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/search/{user_id}/{search_string}")
def search_users(user_id: str, search_string: str, db: Session = Depends(get_db)):
    # Retrieve the current user
    current_user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Load contacts from the JSON field (list of nicknames)
    try:
        contacts_list = json.loads(current_user.contacts)
    except json.JSONDecodeError:
        contacts_list = []

    # Filter contacts whose nicknames contain the search string (case-insensitive)
    matched_contacts = [
        contact for contact in contacts_list
        if search_string.lower() in contact.lower()
    ]

    # Query for other users whose nickname starts with the search string (case-insensitive)
    # and who are not the current user and not already in contacts.
    other_users_query = db.query(UserDB).filter(
        UserDB.nickname.ilike(f"{search_string}%"),
        UserDB.id != user_id
    )
    # Exclude users that are already in the contacts list.
    if contacts_list:
        other_users_query = other_users_query.filter(~UserDB.nickname.in_(contacts_list))
    matched_other_users = other_users_query.all()

    # Use the Pydantic model for serialization (UserResponse)
    return {
        "matched_contacts": matched_contacts,
        "matched_other_users": matched_other_users
    }

@app.get("/getContactInfo/{user_id}/{nickname}")
def get_contact_info(user_id: str, nickname: str, db: Session = Depends(get_db)):
    current_user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = db.query(UserDB).filter(UserDB.nickname == nickname).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"name": user.name, "surname": user.surname, "nickname": user.nickname}
