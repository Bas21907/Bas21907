from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime
import hashlib
import bcrypt
import re
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Thread pool for CPU-intensive hash operations
thread_pool = ThreadPoolExecutor(max_workers=4)

# Common wordlists for dictionary attacks
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "qwerty", "letmein", "welcome",
    "monkey", "dragon", "master", "shadow", "football", "baseball", "sunshine",
    "iloveyou", "trustno1", "hello", "freedom", "whatever", "princess", "maggie",
    "jordan", "summer", "sophie", "hellow", "michelle", "daniel", "starwars",
    "computer", "michelle", "tiger", "1234", "a1b2c3", "foobar", "buster",
    "thomas", "robert", "batman", "abcdef", "ncc1701", "coffee", "scooter",
    "charlie", "orange", "apple", "yankee", "braves", "newyork", "jackson",
    "florida", "sarah", "pepsi", "nicholas", "1qaz2wsx", "zxcvbnm", "asdfgh"
]

# Extended wordlist with common variations
EXTENDED_WORDLIST = []
for password in COMMON_PASSWORDS:
    EXTENDED_WORDLIST.extend([
        password,
        password.upper(),
        password.capitalize(),
        password + "1",
        password + "123",
        password + "!",
        password + "@",
        "1" + password,
        "123" + password,
        password + "2024",
        password + "2023",
        password + "2025"
    ])

# Define Models
class HashAnalysisRequest(BaseModel):
    hashes: List[str] = Field(..., description="List of hashes to analyze")
    attack_type: str = Field(default="dictionary", description="Type of attack: dictionary, brute_force")
    custom_wordlist: Optional[List[str]] = Field(None, description="Custom wordlist for dictionary attack")
    max_length: Optional[int] = Field(8, description="Maximum length for brute force attack")

class HashResult(BaseModel):
    hash_value: str
    hash_type: str
    cracked: bool
    plaintext: Optional[str] = None
    strength_score: int
    time_taken: float
    attempts: int

class HashAnalysisResponse(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    results: List[HashResult]
    total_cracked: int
    total_time: float
    summary: str

class HashAnalysisHistory(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    results: List[HashResult]
    total_cracked: int
    total_time: float
    summary: str

def identify_hash_type(hash_value: str) -> str:
    """Identify the type of hash based on its characteristics"""
    hash_value = hash_value.strip()
    
    # Check for common hash patterns
    if len(hash_value) == 32 and re.match(r'^[a-f0-9]+$', hash_value, re.IGNORECASE):
        return "MD5"
    elif len(hash_value) == 40 and re.match(r'^[a-f0-9]+$', hash_value, re.IGNORECASE):
        return "SHA-1"
    elif len(hash_value) == 64 and re.match(r'^[a-f0-9]+$', hash_value, re.IGNORECASE):
        return "SHA-256"
    elif len(hash_value) == 128 and re.match(r'^[a-f0-9]+$', hash_value, re.IGNORECASE):
        return "SHA-512"
    elif hash_value.startswith('$2b$') or hash_value.startswith('$2a$') or hash_value.startswith('$2y$'):
        return "bcrypt"
    elif hash_value.startswith('$6$'):
        return "SHA-512 (Unix)"
    elif hash_value.startswith('$5$'):
        return "SHA-256 (Unix)"
    elif hash_value.startswith('$1$'):
        return "MD5 (Unix)"
    elif len(hash_value) == 13 and re.match(r'^[a-zA-Z0-9./]+$', hash_value):
        return "DES (Unix)"
    else:
        return "Unknown"

def calculate_strength_score(hash_type: str, plaintext: Optional[str] = None) -> int:
    """Calculate strength score based on hash type and plaintext complexity"""
    base_scores = {
        "MD5": 1,
        "SHA-1": 2,
        "SHA-256": 5,
        "SHA-512": 6,
        "bcrypt": 8,
        "SHA-512 (Unix)": 7,
        "SHA-256 (Unix)": 6,
        "MD5 (Unix)": 3,
        "DES (Unix)": 1,
        "Unknown": 0
    }
    
    score = base_scores.get(hash_type, 0)
    
    if plaintext:
        # Reduce score based on plaintext weakness
        if len(plaintext) < 6:
            score = max(1, score - 3)
        elif len(plaintext) < 8:
            score = max(1, score - 2)
        elif plaintext.lower() in [p.lower() for p in COMMON_PASSWORDS]:
            score = max(1, score - 2)
        elif not any(c.isupper() for c in plaintext):
            score = max(1, score - 1)
        elif not any(c.isdigit() for c in plaintext):
            score = max(1, score - 1)
    
    return min(10, max(1, score))

def hash_password(password: str, hash_type: str) -> str:
    """Hash a password using the specified algorithm"""
    if hash_type == "MD5":
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == "SHA-1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_type == "SHA-256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type == "SHA-512":
        return hashlib.sha512(password.encode()).hexdigest()
    return ""

def crack_hash_dictionary(hash_value: str, hash_type: str, wordlist: List[str]) -> tuple[bool, Optional[str], int]:
    """Attempt to crack a hash using dictionary attack"""
    attempts = 0
    
    for password in wordlist:
        attempts += 1
        
        if hash_type == "bcrypt":
            try:
                if bcrypt.checkpw(password.encode(), hash_value.encode()):
                    return True, password, attempts
            except:
                continue
        else:
            hashed = hash_password(password, hash_type)
            if hashed.lower() == hash_value.lower():
                return True, password, attempts
    
    return False, None, attempts

async def analyze_single_hash(hash_value: str, attack_type: str, custom_wordlist: Optional[List[str]]) -> HashResult:
    """Analyze a single hash"""
    start_time = time.time()
    
    # Identify hash type
    hash_type = identify_hash_type(hash_value)
    
    # Choose wordlist
    wordlist = custom_wordlist if custom_wordlist else EXTENDED_WORDLIST
    
    # Attempt to crack
    cracked = False
    plaintext = None
    attempts = 0
    
    if attack_type == "dictionary":
        # Run dictionary attack in thread pool
        loop = asyncio.get_event_loop()
        cracked, plaintext, attempts = await loop.run_in_executor(
            thread_pool, crack_hash_dictionary, hash_value, hash_type, wordlist
        )
    
    # Calculate metrics
    time_taken = time.time() - start_time
    strength_score = calculate_strength_score(hash_type, plaintext)
    
    return HashResult(
        hash_value=hash_value,
        hash_type=hash_type,
        cracked=cracked,
        plaintext=plaintext,
        strength_score=strength_score,
        time_taken=time_taken,
        attempts=attempts
    )

# API Routes
@api_router.post("/analyze-hashes", response_model=HashAnalysisResponse)
async def analyze_hashes(request: HashAnalysisRequest):
    """Analyze multiple password hashes"""
    try:
        start_time = time.time()
        
        # Validate input
        if not request.hashes:
            raise HTTPException(status_code=400, detail="No hashes provided")
        
        # Analyze each hash
        results = []
        for hash_value in request.hashes:
            result = await analyze_single_hash(hash_value, request.attack_type, request.custom_wordlist)
            results.append(result)
        
        # Calculate summary statistics
        total_time = time.time() - start_time
        total_cracked = sum(1 for r in results if r.cracked)
        crack_rate = (total_cracked / len(results)) * 100 if results else 0
        
        # Generate summary
        summary = f"Analyzed {len(results)} hashes in {total_time:.2f}s. "
        summary += f"Cracked {total_cracked} ({crack_rate:.1f}%). "
        summary += f"Average strength score: {sum(r.strength_score for r in results) / len(results):.1f}/10"
        
        # Create response
        response = HashAnalysisResponse(
            results=results,
            total_cracked=total_cracked,
            total_time=total_time,
            summary=summary
        )
        
        # Save to database
        await db.hash_analysis.insert_one(response.dict())
        
        return response
        
    except Exception as e:
        logging.error(f"Error analyzing hashes: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@api_router.get("/analysis-history", response_model=List[HashAnalysisHistory])
async def get_analysis_history(limit: int = 10):
    """Get hash analysis history"""
    try:
        history = await db.hash_analysis.find().sort("timestamp", -1).limit(limit).to_list(limit)
        return [HashAnalysisHistory(**item) for item in history]
    except Exception as e:
        logging.error(f"Error fetching history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch history")

@api_router.get("/hash-stats")
async def get_hash_stats():
    """Get overall hash analysis statistics"""
    try:
        total_analyses = await db.hash_analysis.count_documents({})
        
        # Get recent analyses for stats
        recent_analyses = await db.hash_analysis.find().sort("timestamp", -1).limit(100).to_list(100)
        
        if not recent_analyses:
            return {
                "total_analyses": 0,
                "total_hashes_analyzed": 0,
                "average_crack_rate": 0,
                "most_common_hash_types": [],
                "weakest_passwords": []
            }
        
        # Calculate statistics
        total_hashes = sum(len(analysis.get("results", [])) for analysis in recent_analyses)
        total_cracked = sum(analysis.get("total_cracked", 0) for analysis in recent_analyses)
        avg_crack_rate = (total_cracked / total_hashes * 100) if total_hashes > 0 else 0
        
        # Get hash type distribution
        hash_types = {}
        weak_passwords = []
        
        for analysis in recent_analyses:
            for result in analysis.get("results", []):
                hash_type = result.get("hash_type", "Unknown")
                hash_types[hash_type] = hash_types.get(hash_type, 0) + 1
                
                if result.get("cracked") and result.get("plaintext"):
                    weak_passwords.append(result["plaintext"])
        
        most_common_types = sorted(hash_types.items(), key=lambda x: x[1], reverse=True)[:5]
        most_common_weak = list(set(weak_passwords))[:10]
        
        return {
            "total_analyses": total_analyses,
            "total_hashes_analyzed": total_hashes,
            "average_crack_rate": round(avg_crack_rate, 1),
            "most_common_hash_types": most_common_types,
            "weakest_passwords": most_common_weak
        }
        
    except Exception as e:
        logging.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get statistics")

@api_router.get("/")
async def root():
    return {"message": "CyberSec Pro - Password Hash Analysis Engine"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()