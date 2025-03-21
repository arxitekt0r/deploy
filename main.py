import random
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Column, Integer, String, Date, create_engine, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from PIL import Image
import uuid
from datetime import date
import time
import smtplib
import json
import os
import io
from typing import Optional, Dict, List
import base64
from dotenv import load_dotenv

load_dotenv()

smtp_server = "smtp.gmail.com"
smtp_port = 587
sender_email = os.getenv("SENDER_EMAIL")
password = os.getenv("SENDER_PASSWORD")

pending_users = {}
verification_db = {}


app = FastAPI()




Base = declarative_base()
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

encryptor = CryptContext(schemes=["bcrypt"], deprecated="auto")


def send_verification_code(email: str, code: int) -> None:
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, email, f"Subject: Verification Code\n\nYour code: {code}")
            print("Email sent successfully!")
    except Exception as e:
        print("Error:", e)



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
    profile_photo = Column(LargeBinary, nullable=True)  # Store image in binary format


class MessageDB(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, nullable=False)
    recipient = Column(String, nullable=False)
    text = Column(String, nullable=False)
    timestamp = Column(String, nullable=False, default=str(time.time()))


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

def cleanup_expired_pending_users(expiration_seconds=3600):  # 1-hour expiration
    current_time = time.time()
    expired_users = [uid for uid, data in pending_users.items() if current_time - data["timestamp"] > expiration_seconds]

    for uid in expired_users:
        pending_users.pop(uid, None)
        verification_db.pop(uid, None)


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.message_storage = {}  # Store undelivered messages

    async def connect(self, username: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[username] = websocket

        # Deliver any stored messages
        if username in self.message_storage:
            for message in self.message_storage[username]:
                await websocket.send_json(message)
            del self.message_storage[username]

    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]

    async def send_message(self, recipient: str, message: dict):
        if recipient in self.active_connections:
            await self.active_connections[recipient].send_json(message)
        else:
            # Store undelivered message
            if recipient not in self.message_storage:
                self.message_storage[recipient] = []
            self.message_storage[recipient].append(message)

manager = ConnectionManager()

@app.websocket("/ws/{username}")
async def websocket_endpoint(username: str, websocket: WebSocket, db: Session = Depends(get_db)):
    await manager.connect(username, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            recipient = data["recipient"]
            message_text = data["message"]
            timestamp = str(time.time())

            # Save message in DB
            db_message = MessageDB(sender=username, recipient=recipient, text=message_text, timestamp=timestamp)
            db.add(db_message)
            db.commit()

            # Construct the message payload
            message = {
                "sender": username,
                "recipient": recipient,
                "message": message_text,
                "timestamp": timestamp
            }

            # Send the message
            await manager.send_message(recipient, message)

    except WebSocketDisconnect:
        manager.disconnect(username)

@app.post("/register/")
def request_verification(user: UserCreate, db: Session = Depends(get_db)):
    cleanup_expired_pending_users()  # Clean up old unverified users

    # Check if nickname is pending but expired
    for uid, data in pending_users.items():
        if data["nickname"] == user.nickname:
            del pending_users[uid]
            del verification_db[uid]
            break

    # Check if user exists in the database
    existing_user = db.query(UserDB).filter(
        (UserDB.nickname == user.nickname) | (UserDB.email == user.email)
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Nickname or email already in use")

    # Generate verification code and user ID
    verification_code = random.randint(100000, 999999)
    user_id = str(uuid.uuid4())

    # Store user data temporarily
    pending_users[user_id] = {
        "name": user.name,
        "surname": user.surname,
        "nickname": user.nickname,
        "email": user.email,
        "date_of_birth": str(user.date_of_birth),
        "password": encryptor.hash(user.password),
        "timestamp": time.time()  # Store registration time
    }

    # Store verification code
    verification_db[user_id] = verification_code
    send_verification_code(user.email, verification_code)

    return {"message": "Verification code sent. Please verify to complete registration.", "user_id": user_id}

@app.post("/login/")
def login_user(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.nickname == user.nickname).first()
    if not db_user or not encryptor.verify(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid nickname or password")

    return {"user_id": db_user.id}


@app.post("/verify/")
def verify_user(verify_data: VerifyUser, db: Session = Depends(get_db)):
    user_id = verify_data.user_id

    if user_id not in verification_db:
        raise HTTPException(status_code=400, detail="Invalid or expired verification request")
    if verification_db[user_id] != verify_data.verification_code:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # Retrieve user data from pending storage
    user_data = pending_users.pop(user_id, None)
    if not user_data:
        raise HTTPException(status_code=400, detail="User data not found")

    # Create and save user in the database
    new_user = UserDB(
        id=user_id,
        name=user_data["name"],
        surname=user_data["surname"],
        nickname=user_data["nickname"],
        email=user_data["email"],
        date_of_birth=date.fromisoformat(user_data["date_of_birth"]),
        hashed_password=user_data["password"],
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Remove from verification DB after successful verification
    del verification_db[user_id]

    return {"message": "Verification successful"}


@app.delete("/delete/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()
    return {"message": "User deleted successfully"}


class AddContactRequest(BaseModel):
    user_id: str
    contact_nickname: str

@app.post("/addcontact/")
def add_contact(request: AddContactRequest, db: Session = Depends(get_db)):
    user_id = request.user_id
    contact_nickname = request.contact_nickname
    
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

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    surname: Optional[str] = None
    nickname: Optional[str] = None
    profile_photo: Optional[str] = None  # Base64 string

@app.put("/edit_profile/{user_id}")
async def edit_profile(
    user_id: str,
    update_data: ProfileUpdate,
    db: Session = Depends(get_db),
):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Handle nickname change
    if update_data.nickname and update_data.nickname != user.nickname:
        existing_user = db.query(UserDB).filter(UserDB.nickname == update_data.nickname).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Nickname already in use")
        user.nickname = update_data.nickname

    # Update other fields
    if update_data.name and update_data.name != user.name:
        user.name = update_data.name
    if update_data.surname is not None and update_data.surname != user.surname:
        user.surname = update_data.surname

    # Handle profile photo
    if update_data.profile_photo:
        try:
            img_data = base64.b64decode(update_data.profile_photo)
            image = Image.open(io.BytesIO(img_data))
            image = image.convert("RGB")
            img_bytes_io = io.BytesIO()
            image.save(img_bytes_io, format="JPEG")
            user.profile_photo = img_bytes_io.getvalue()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid image data: {str(e)}")

    db.commit()
    db.refresh(user)

    return {"message": "Profile updated successfully", "user": user}

@app.get("/profile_info/{user_id}")
def get_profile_info(user_id: str, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    profile_photo_base64 = None
    if user.profile_photo:
        profile_photo_base64 = base64.b64encode(user.profile_photo).decode("utf-8")

    # Load contacts from the JSON field
    try:
        contacts_list = json.loads(user.contacts)  # List of nicknames
    except json.JSONDecodeError:
        contacts_list = []

    # Retrieve full contact details
    contacts_query = db.query(UserDB.nickname, UserDB.name, UserDB.surname).filter(UserDB.nickname.in_(contacts_list))
    contacts = [
        {"nickname": contact.nickname, "name": contact.name, "surname": contact.surname}
        for contact in contacts_query.all()
    ]

    return {
        "id": user.id,
        "name": user.name,
        "surname": user.surname,
        "nickname": user.nickname,
        "email": user.email,
        "date_of_birth": user.date_of_birth,
        "profile_photo": profile_photo_base64,  # Return Base64 encoded photo
        "contacts": contacts  # List of contacts with details
    }


@app.get("/search/{user_id}/{search_string}")
def search_users(user_id: str, search_string: str, db: Session = Depends(get_db)):
    # Retrieve the current user
    current_user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Load contacts from the JSON field (list of nicknames)
    try:
        contacts_list = json.loads(current_user.contacts)  # Assuming contacts store nicknames
    except json.JSONDecodeError:
        contacts_list = []

    def serialize_user(user):
        """Helper function to serialize user data including profile photo"""
        profile_photo_base64 = None
        if user.profile_photo:
            profile_photo_base64 = base64.b64encode(user.profile_photo).decode("utf-8")
        return {
            "nickname": user.nickname,
            "name": user.name,
            "surname": user.surname,
            "profile_photo": profile_photo_base64
        }

    # Query database to get full details of matched contacts
    matched_contacts_query = db.query(UserDB).filter(
        UserDB.nickname.in_(contacts_list),
        UserDB.nickname.ilike(f"%{search_string}%")  # Search for substring match
    )
    matched_contacts = [serialize_user(user) for user in matched_contacts_query.all()]

    # Query for other users whose nickname starts with the search string (case-insensitive)
    other_users_query = db.query(UserDB).filter(
        UserDB.nickname.ilike(f"{search_string}%"),
        UserDB.id != user_id
    )

    # Exclude users that are already in the contacts list
    if contacts_list:
        other_users_query = other_users_query.filter(~UserDB.nickname.in_(contacts_list))

    matched_other_users = [serialize_user(user) for user in other_users_query.all()]

    return {
        "matched_contacts": matched_contacts,       # Now contains profile_photo
        "matched_other_users": matched_other_users  # Now contains profile_photo
    }


@app.get("/getContactInfo/{user_id}/{nickname}")
def get_contact_info(user_id: str, nickname: str, db: Session = Depends(get_db)):
    current_user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    user = db.query(UserDB).filter(UserDB.nickname == nickname).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    profile_photo_base64 = None
    if user.profile_photo:
        profile_photo_base64 = base64.b64encode(user.profile_photo).decode("utf-8")

    return {
        "name": user.name,
        "surname": user.surname,
        "nickname": user.nickname,
        "profile_photo": profile_photo_base64
    }


@app.get("/getMessageHistory/{user_id}/{contact_nickname}")
def get_message_history(user_id: str, contact_nickname: str, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Retrieve messages between the user and the contact
    messages = db.query(MessageDB).filter(
        ((MessageDB.sender == user.nickname) & (MessageDB.recipient == contact_nickname)) |
        ((MessageDB.sender == contact_nickname) & (MessageDB.recipient == user.nickname))
    ).order_by(MessageDB.timestamp).all()

    # Serialize messages
    return [
        {"sender": msg.sender, "recipient": msg.recipient, "message": msg.text, "timestamp": msg.timestamp}
        for msg in messages
    ]



@app.get("/check_nickname/{nickname}")
def check_nickname(nickname: str, db: Session = Depends(get_db)):
    existing_user = db.query(UserDB).filter(UserDB.nickname == nickname).first()
    if existing_user:
        return {"message": "Nickname already in use"}
    return {"message": "Nickname is free"}



