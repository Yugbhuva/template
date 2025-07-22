from fastapi import FastAPI, HTTPException, Depends, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, Mapped, mapped_column
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
from typing import Optional, TYPE_CHECKING
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import os
from dotenv import load_dotenv
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.requests import Request as StarletteRequest
import db_interface
from models import User, Base

# Load environment variables
load_dotenv()
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://template-dhcd.onrender.com")

# App configuration
app = FastAPI(title="Simple Auth System")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Database setup
DATABASE_URL = "sqlite:///./auth.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# Base = declarative_base() # This line is removed as per the edit hint.

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# User Model
# class User(Base): # This class is removed as per the edit hint.
#     __tablename__ = "users"

#     id: Mapped[int] = mapped_column(primary_key=True, index=True)
#     email: Mapped[str] = mapped_column(String, unique=True, index=True)
#     password_hash: Mapped[str] = mapped_column(String)
#     full_name: Mapped[str] = mapped_column(String)
#     is_active: Mapped[bool] = mapped_column(Boolean, default=True)
#     is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
#     created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
#     reset_token: Mapped[Optional[str]] = mapped_column(String, nullable=True)
#     reset_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

# Create tables
Base.metadata.create_all(bind=engine)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        return email
    except jwt.PyJWTError:
        return None

DB_BACKEND = os.getenv("DB_BACKEND", "sqlite")

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    
    email = verify_token(token)
    if not email:
        return None
    
    if DB_BACKEND == "sqlite":
        user = db_interface.get_user_by_email(db, email)
    else:
        import asyncio
        user = asyncio.run(db_interface.get_user_by_email(email))

    if not user or not bool(user.is_active if DB_BACKEND == "sqlite" else user.get("is_active", True)):
        return None
    
    return user

def send_email(to_email: str, subject: str, body: str):
    """Simple email sending function"""
    try:
        # Configure these in your .env file
        smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        sender_email = os.getenv("SENDER_EMAIL", "ybhuva817@gmail.com")
        sender_password = os.getenv("SENDER_PASSWORD", "kkvt vyqt dvxj vikp")
        
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = to_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
        
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

# OAuth setup
config = Config('.env')
oauth = OAuth(config)
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)
if oauth.google is None:
    raise RuntimeError("Google OAuth is not configured properly. Check your .env file.")
oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("home.html", {"request": request, "user": user})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    db: Session = Depends(get_db)
):
    if DB_BACKEND == "sqlite":
        if db_interface.get_user_by_email(db, email):
            return templates.TemplateResponse("register.html", {"request": request, "error": "Email already registered"})
        is_first_user = db.query(User).count() == 0
        hashed_password = get_password_hash(password)
        user_data = {
            "email": email,
            "password_hash": hashed_password,
            "full_name": full_name,
            "is_admin": is_first_user
        }
        db_interface.create_user(db, user_data)
    else:
        user = await db_interface.get_user_by_email(email)
        if user:
            return templates.TemplateResponse("register.html", {"request": request, "error": "Email already registered"})
        is_first_user = (await db_interface.get_all_users()).__len__() == 0
        hashed_password = get_password_hash(password)
        user_data = {
            "email": email,
            "password_hash": hashed_password,
            "full_name": full_name,
            "is_admin": is_first_user,
            "is_active": True,
            "created_at": datetime.utcnow()
        }
        await db_interface.create_user(user_data)
    return templates.TemplateResponse("register.html", {"request": request, "success": "Registration successful! Please login."})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    if DB_BACKEND == "sqlite":
        user = db_interface.get_user_by_email(db, email)
        if not user or not verify_password(password, user.password_hash):
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password"})
    else:
        user = await db_interface.get_user_by_email(email)
        if not user or not verify_password(password, user["password_hash"]):
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email if DB_BACKEND == "sqlite" else user["email"]}, expires_delta=access_token_expires)
    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get('/login/google')
async def login_google(request: Request):
    redirect_uri = request.url_for('auth_google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.route('/auth/google/callback')
async def auth_google_callback(request: StarletteRequest, db: Session = Depends(get_db)):
    token = await oauth.google.authorize_access_token(request)
    user_info = await oauth.google.parse_id_token(request, token)
    email = user_info.get('email')
    full_name = user_info.get('name')
    if not email:
        return RedirectResponse(url='/login')
    if DB_BACKEND == "sqlite":
        user = db_interface.get_user_by_email(db, email)
    else:
        user = await db_interface.get_user_by_email(email)
    if not user:
        user_data = {
            "email": email,
            "full_name": full_name,
            "password_hash": "",
            "is_active": True
        }
        if DB_BACKEND == "sqlite":
            db_interface.create_user(db, user_data)
        else:
            await db_interface.create_user(user_data)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={'sub': user.email if DB_BACKEND == "sqlite" else user["email"]}, expires_delta=access_token_expires)
    response = RedirectResponse(url='/dashboard', status_code=302)
    response.set_cookie(key='access_token', value=access_token, httponly=True)
    return response

@app.get('/login/github')
async def login_github(request: Request):
    redirect_uri = request.url_for('auth_github_callback')
    return await oauth.github.authorize_redirect(request, redirect_uri)

@app.route('/auth/github/callback')
async def auth_github_callback(request: StarletteRequest, db: Session = Depends(get_db)):
    token = await oauth.github.authorize_access_token(request)
    resp = await oauth.github.get('user', token=token)
    profile = resp.json()
    email = profile.get('email')
    if not email:
        # Fallback: fetch primary email
        emails_resp = await oauth.github.get('user/emails', token=token)
        emails = emails_resp.json()
        for e in emails:
            if e.get('primary') and e.get('verified'):
                email = e.get('email')
                break
    full_name = profile.get('name') or profile.get('login')
    if not email:
        return RedirectResponse(url='/login')
    if DB_BACKEND == "sqlite":
        user = db_interface.get_user_by_email(db, email)
    else:
        user = await db_interface.get_user_by_email(email)
    if not user:
        user_data = {
            "email": email,
            "full_name": full_name,
            "password_hash": "",
            "is_active": True
        }
        if DB_BACKEND == "sqlite":
            db_interface.create_user(db, user_data)
        else:
            await db_interface.create_user(user_data)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={'sub': user.email if DB_BACKEND == "sqlite" else user["email"]}, expires_delta=access_token_expires)
    response = RedirectResponse(url='/dashboard', status_code=302)
    response.set_cookie(key='access_token', value=access_token, httponly=True)
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login")
    
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie(key="access_token")
    return response

@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request):
    return templates.TemplateResponse("reset_password.html", {"request": request})

@app.post("/reset-password")
async def reset_password(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    if DB_BACKEND == "sqlite":
        user = db_interface.get_user_by_email(db, email)
    else:
        user = await db_interface.get_user_by_email(email)
    
    if user:
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        user_data = {
            "reset_token": reset_token,
            "reset_token_expires": datetime.utcnow() + timedelta(hours=1)
        }
        if DB_BACKEND == "sqlite":
            db_interface.update_user(db, email, user_data)
        else:
            await db_interface.update_user(email, user_data)
        
        # Send reset email
        reset_url = f"{FRONTEND_URL}/reset-confirm?token={reset_token}"
        email_body = f"""
        Hello {user.full_name},
        
        You requested a password reset. Click the link below to reset your password:
        {reset_url}
        
        This link will expire in 1 hour.
        
        If you didn't request this, please ignore this email.
        """
        
        send_email(str(user.email), "Password Reset Request", email_body)  # type: ignore
    
    return templates.TemplateResponse("reset_password.html", {
        "request": request, 
        "success": "If your email exists, you'll receive a reset link."
    })

@app.get("/reset-confirm", response_class=HTMLResponse)
async def reset_confirm_page(request: Request, token: str):
    return templates.TemplateResponse("reset_confirm.html", {"request": request, "token": token})

@app.post("/reset-confirm")
async def reset_confirm(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db)
):
    if DB_BACKEND == "sqlite":
        user = db_interface.get_user_by_reset_token(db, token)
    else:
        user = await db_interface.get_user_by_reset_token(token)
    
    if not user:
        return templates.TemplateResponse("reset_confirm.html", {
            "request": request, 
            "token": token,
            "error": "Invalid or expired reset token"
        })
    
    # Update password
    user_data = {
        "password_hash": get_password_hash(new_password),
        "reset_token": None,
        "reset_token_expires": None
    }
    if DB_BACKEND == "sqlite":
        db_interface.update_user(db, user.email, user_data)
    else:
        await db_interface.update_user(user["email"], user_data)
    
    return templates.TemplateResponse("reset_confirm.html", {
        "request": request, 
        "success": "Password reset successful! You can now login."
    })

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login")
    
    return templates.TemplateResponse("profile.html", {"request": request, "user": user})

@app.post("/profile")
async def update_profile(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login")
    
    # Check if email is already taken by another user
    if DB_BACKEND == "sqlite":
        existing_user = db_interface.get_user_by_email(db, email)
    else:
        existing_user = await db_interface.get_user_by_email(email)

    if existing_user and existing_user.id != user.id:
        return templates.TemplateResponse("profile.html", {
            "request": request, 
            "user": user,
            "error": "Email already in use"
        })
    
    # Update user
    user_data = {
        "full_name": full_name,
        "email": email
    }
    if DB_BACKEND == "sqlite":
        db_interface.update_user(db, user.email, user_data)
    else:
        await db_interface.update_user(user["email"], user_data)
    
    return templates.TemplateResponse("profile.html", {
        "request": request, 
        "user": user,
        "success": "Profile updated successfully!"
    })

@app.post("/delete-account")
async def delete_account(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login")
    if DB_BACKEND == "sqlite":
        db_interface.delete_user(db, user.email)
    else:
        await db_interface.delete_user(user["email"])
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(key="access_token")
    return response

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not bool(user.is_admin if DB_BACKEND == "sqlite" else user.get("is_admin", False)):
        return RedirectResponse(url="/login", status_code=302)
    if DB_BACKEND == "sqlite":
        users = db_interface.get_all_users(db)
    else:
        users = await db_interface.get_all_users()
    return templates.TemplateResponse("admin_dashboard.html", {"request": request, "user": user, "users": users})

@app.post("/admin/delete-user")
async def admin_delete_user(request: Request, user_id: int = Form(...), db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    if not admin or not bool(admin.is_admin if DB_BACKEND == "sqlite" else admin.get("is_admin", False)):
        return RedirectResponse(url="/login", status_code=302)
    if DB_BACKEND == "sqlite":
        user = db_interface.get_user_by_id(db, user_id)
    else:
        user = await db_interface.get_user_by_id(user_id)
    if not user or user.id == admin.id:
        return RedirectResponse(url="/admin", status_code=302)
    if DB_BACKEND == "sqlite":
        db_interface.delete_user(db, user.email)
    else:
        await db_interface.delete_user(user["email"])
    return RedirectResponse(url="/admin", status_code=302)

@app.get("/admin/edit-user", response_class=HTMLResponse)
async def admin_edit_user_page(request: Request, user_id: int, db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    if not admin or not bool(admin.is_admin if DB_BACKEND == "sqlite" else admin.get("is_admin", False)):
        return RedirectResponse(url="/login", status_code=302)
    if DB_BACKEND == "sqlite":
        user = db_interface.get_user_by_id(db, user_id)
    else:
        user = await db_interface.get_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/admin", status_code=302)
    return templates.TemplateResponse("admin_edit_user.html", {"request": request, "admin": admin, "edit_user": user})

@app.post("/admin/edit-user", response_class=HTMLResponse)
async def admin_edit_user(request: Request, user_id: int = Form(...), full_name: str = Form(...), email: str = Form(...), is_admin: Optional[bool] = Form(False), db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    if not admin or not bool(admin.is_admin if DB_BACKEND == "sqlite" else admin.get("is_admin", False)):
        return RedirectResponse(url="/login", status_code=302)
    if DB_BACKEND == "sqlite":
        user = db_interface.get_user_by_id(db, user_id)
    else:
        user = await db_interface.get_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/admin", status_code=302)
    user_data = {
        "full_name": full_name,
        "email": email,
        "is_admin": bool(is_admin)
    }
    if DB_BACKEND == "sqlite":
        db_interface.update_user(db, user.email, user_data)
    else:
        await db_interface.update_user(user["email"], user_data)
    return RedirectResponse(url="/admin", status_code=302)

@app.get("/admin/add-user", response_class=HTMLResponse)
async def admin_add_user_page(request: Request, db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    if not admin or not bool(admin.is_admin if DB_BACKEND == "sqlite" else admin.get("is_admin", False)):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("admin_add_user.html", {"request": request, "admin": admin})

@app.post("/admin/add-user", response_class=HTMLResponse)
async def admin_add_user(request: Request, full_name: str = Form(...), email: str = Form(...), password: str = Form(...), is_admin: Optional[bool] = Form(False), db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    if not admin or not bool(admin.is_admin if DB_BACKEND == "sqlite" else admin.get("is_admin", False)):
        return RedirectResponse(url="/login", status_code=302)
    if DB_BACKEND == "sqlite":
        if db_interface.get_user_by_email(db, email):
            return templates.TemplateResponse("admin_add_user.html", {"request": request, "admin": admin, "error": "Email already registered"})
        hashed_password = get_password_hash(password)
        user_data = {
            "email": email,
            "password_hash": hashed_password,
            "full_name": full_name,
            "is_admin": bool(is_admin),
            "is_active": True,
            "created_at": datetime.utcnow()
        }
        db_interface.create_user(db, user_data)
    else:
        user = await db_interface.get_user_by_email(email)
        if user:
            return templates.TemplateResponse("admin_add_user.html", {"request": request, "admin": admin, "error": "Email already registered"})
        hashed_password = get_password_hash(password)
        user_data = {
            "email": email,
            "password_hash": hashed_password,
            "full_name": full_name,
            "is_admin": bool(is_admin),
            "is_active": True,
            "created_at": datetime.utcnow()
        }
        await db_interface.create_user(user_data)
    return RedirectResponse(url="/admin", status_code=302)