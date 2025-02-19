from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer
import sqlite3
import jwt, os
import datetime
import logging
import bcrypt
from typing import Dict
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load AI Models Locally
from Models.medbert import medbert  # Ensure correct import path
from Models.biogpt import biogpt  # Ensure correct import path

# Initialize FastAPI app
app = FastAPI()

# Database and Security Configurations
DATABASE = "health_chatbot.db"
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")  # Default for testing
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Pydantic Model
class LoginRequest(BaseModel):
    username: str
    password: str

# Initialize Database
def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn, conn.cursor()

def init_db():
    conn, cursor = get_db()
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        query TEXT NOT NULL,
        response TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)
    conn.commit()
    conn.close()

init_db()

# Token Functions
def create_access_token(username: str) -> str:
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {"sub": username, "exp": expiration}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# User Authentication
@app.post("/auth/register")
async def register_user(user: LoginRequest):
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode("utf-8")
    conn, cursor = get_db()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()
    return {"message": "User registered successfully"}

@app.post("/auth/login")
async def login_user(request: LoginRequest):
    conn, cursor = get_db()
    cursor.execute("SELECT * FROM users WHERE username = ?", (request.username,))
    user = cursor.fetchone()
    conn.close()
    if not user or not bcrypt.checkpw(request.password.encode('utf-8'), user[2].encode('utf-8')):
        raise HTTPException(status_code=422, detail="Invalid username or password")
    return {"token": create_access_token(username=request.username)}

# AI Chatbot Endpoint
@app.post("/healthbot")
async def healthbot_response(request: Request, data: Dict[str, str]):
    auth_header = request.headers.get("Authorization")
    username = "Guest" if (auth_header and auth_header.startswith("Bearer guest")) else verify_token(await oauth2_scheme(request))
    
    query = data.get("query")
    if not query:
        raise HTTPException(status_code=400, detail="Query is required")
    
    classification_result = medbert.classify_text(query)
    bot_response = biogpt.generate_response(query)
    
    if username != "Guest":
        conn, cursor = get_db()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user:
            cursor.execute("INSERT INTO chat_history (user_id, query, response) VALUES (?, ?, ?)", (user[0], query, bot_response))
            conn.commit()
        conn.close()
    
    return {"classification": classification_result.tolist(), "response": bot_response}

# Retrieve Chat History
@app.get("/chat_history/")
async def get_chat_history(token: str = Depends(oauth2_scheme)):
    username = verify_token(token)
    conn, cursor = get_db()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user_id = user[0]
    cursor.execute("SELECT id, query, response, timestamp FROM chat_history WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
    history = [{"id": r[0], "query": r[1], "response": r[2], "timestamp": r[3]} for r in cursor.fetchall()]
    conn.close()
    return {"history": history}

# Delete Chat History
@app.delete("/chat_history/delete/")
async def delete_chat_history(token: str = Depends(oauth2_scheme)):
    username = verify_token(token)
    conn, cursor = get_db()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    cursor.execute("DELETE FROM chat_history WHERE user_id = ?", (user[0],))
    conn.commit()
    conn.close()
    return {"message": "Chat history deleted successfully"}
