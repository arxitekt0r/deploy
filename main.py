import random
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Column, Integer, String, Date, create_engine, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from PIL import Image
import uuid
from datetime import date
import smtplib
import json
import os
import io
import base64

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


pending_users = {}

@app.post("/register/")
def request_verification(user: UserCreate):
    if user.nickname in [u["nickname"] for u in pending_users.values()]:
        raise HTTPException(status_code=400, detail="Nickname already in use")
    if user.email in [u["email"] for u in pending_users.values()]:
        raise HTTPException(status_code=400, detail="Email already in use")

    verification_code = random.randint(100000, 999999)
    user_id = str(uuid.uuid4())  # Generate a temporary user ID

    # Store user data temporarily
    pending_users[user_id] = {
        "name": user.name,
        "surname": user.surname,
        "nickname": user.nickname,
        "email": user.email,
        "date_of_birth": str(user.date_of_birth),  # Convert date to string for storage
        "password": encryptor.hash(user.password),
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

    # Retrieve user data from temporary storage
    user_data = pending_users.pop(user_id, None)
    if not user_data:
        raise HTTPException(status_code=400, detail="User data not found")

    # Create and save the user in the database
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

@app.post("/sendMessage/{user_id}/{contact_nickname}")
def send_message(user_id: str, contact_nickname: str, message: Message, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    contacts = json.loads(user.contacts)
    if contact_nickname not in contacts:
        raise HTTPException(status_code=400, detail="Contact not found")

    a, b = sorted([user.nickname, contact_nickname])

    file_path = f"conversations/{a}_{b}.json"
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

class EditProfileRequest(BaseModel):
    name: str | None = None
    surname: str | None = None
    nickname: str | None = None

@app.put("/edit_profile/{user_id}")
async def edit_profile(
    user_id: str,
    name: str | None = None,
    surname: str | None = None,
    nickname: str | None = None,
    profile_photo: UploadFile = File(None),
    db: Session = Depends(get_db),
):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Handle nickname change
    if nickname and nickname != user.nickname:
        existing_user = db.query(UserDB).filter(UserDB.nickname == nickname).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Nickname already in use")
        user.nickname = nickname

    # Update other fields
    if name:
        user.name = name
    if surname is not None:
        user.surname = surname

    # Handle profile photo
    if profile_photo:
        image = Image.open(profile_photo.file)
        image = image.convert("RGB")  # Ensure it's in RGB format
        img_bytes = io.BytesIO()
        image.save(img_bytes, format="JPEG")
        user.profile_photo = img_bytes.getvalue()

    db.commit()
    db.refresh(user)
    return {"message": "Profile updated successfully"}

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
    # Retrieve the current user from the database
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        contacts_list = json.loads(user.contacts)
    except json.JSONDecodeError:
        contacts_list = []
    if contact_nickname not in contacts_list:
        raise HTTPException(status_code=400, detail="Contact not found in your contacts")

    a, b = sorted([user.nickname, contact_nickname])
    file_path = f"conversations/{a}_{b}.json"
    os.makedirs("conversations", exist_ok=True)

    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            conversation = json.load(f)
    else:
        conversation = []

    return {"conversation": conversation}
