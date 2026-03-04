from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import sqlite3, hashlib, jwt, os, json

SECRET_KEY     = os.getenv("SECRET_KEY", "change-this-secret-in-production")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin1234")
ALGORITHM      = "HS256"
TOKEN_EXPIRE_HOURS = 24

app = FastAPI(title="Revaldo Store Backend", version="2.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

security = HTTPBearer()

def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    try: yield conn
    finally: conn.close()

def init_db():
    conn = sqlite3.connect("database.db")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
        description TEXT, price REAL NOT NULL, emoji TEXT DEFAULT '📦',
        image_url TEXT DEFAULT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, user_name TEXT, user_email TEXT,
        customer_name TEXT, customer_phone TEXT, customer_address TEXT,
        items TEXT, total_price REAL, status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    for col in [("products","image_url TEXT"), ("orders","customer_name TEXT"),
                ("orders","customer_phone TEXT"), ("orders","customer_address TEXT"),
                ("orders","items TEXT"), ("orders","total_price REAL")]:
        try: conn.execute(f"ALTER TABLE {col[0]} ADD COLUMN {col[1]}")
        except: pass
    conn.commit()
    conn.close()

init_db()

def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()
def create_token(uid, email):
    return jwt.encode({"user_id":uid,"email":email,"exp":datetime.utcnow()+timedelta(hours=TOKEN_EXPIRE_HOURS)}, SECRET_KEY, algorithm=ALGORITHM)
def verify_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    try: return jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError: raise HTTPException(401, "انتهت صلاحية الـ Token")
    except: raise HTTPException(401, "Token غير صالح")

class RegisterRequest(BaseModel): name:str; email:str; password:str
class LoginRequest(BaseModel): email:str; password:str
class AdminLoginRequest(BaseModel): password:str
class ProductCreate(BaseModel):
    name:str; description:Optional[str]=None; price:float
    emoji:Optional[str]="📦"; image_url:Optional[str]=None
class OrderCreate(BaseModel):
    customer_name:str; customer_phone:str; customer_address:str
    items:List[dict]; total_price:float
class OrderStatusUpdate(BaseModel): status:str

@app.get("/")
def root(): return {"message":"🚀 Revaldo Store Backend شغال!"}

@app.post("/auth/register", status_code=201)
def register(data: RegisterRequest, db=Depends(get_db)):
    try:
        db.execute("INSERT INTO users (name,email,password) VALUES (?,?,?)", (data.name,data.email,hash_password(data.password)))
        db.commit()
        user = db.execute("SELECT * FROM users WHERE email=?", (data.email,)).fetchone()
        return {"message":"تم إنشاء الحساب ✅","token":create_token(user["id"],user["email"]),"name":user["name"]}
    except sqlite3.IntegrityError: raise HTTPException(400,"الإيميل مستخدم بالفعل")

@app.post("/auth/login")
def login(data: LoginRequest, db=Depends(get_db)):
    user = db.execute("SELECT * FROM users WHERE email=? AND password=?", (data.email,hash_password(data.password))).fetchone()
    if not user: raise HTTPException(401,"إيميل أو كلمة مرور خاطئة")
    return {"token":create_token(user["id"],user["email"]),"user_id":user["id"],"name":user["name"],"email":user["email"]}

@app.post("/admin/login")
def admin_login(data: AdminLoginRequest):
    if data.password != ADMIN_PASSWORD: raise HTTPException(401,"باسورد الأدمين غلط")
    return {"message":"مرحباً يا أدمين ✅","admin":True}

@app.get("/products")
def get_products(db=Depends(get_db)):
    return [dict(p) for p in db.execute("SELECT * FROM products ORDER BY created_at DESC").fetchall()]

@app.post("/admin/products", status_code=201)
def add_product(data: ProductCreate, db=Depends(get_db)):
    cursor = db.execute("INSERT INTO products (name,description,price,emoji,image_url) VALUES (?,?,?,?,?)",
                        (data.name,data.description,data.price,data.emoji,data.image_url))
    db.commit()
    return {"message":"تم إضافة المنتج ✅","id":cursor.lastrowid}

@app.delete("/admin/products/{pid}")
def delete_product(pid:int, db=Depends(get_db)):
    db.execute("DELETE FROM products WHERE id=?", (pid,)); db.commit()
    return {"message":"تم حذف المنتج ✅"}

@app.post("/orders", status_code=201)
def create_order(data: OrderCreate, payload=Depends(verify_token), db=Depends(get_db)):
    user = db.execute("SELECT * FROM users WHERE id=?", (payload["user_id"],)).fetchone()
    db.execute("INSERT INTO orders (user_id,user_name,user_email,customer_name,customer_phone,customer_address,items,total_price) VALUES (?,?,?,?,?,?,?,?)",
               (payload["user_id"],user["name"],user["email"],data.customer_name,data.customer_phone,data.customer_address,json.dumps(data.items,ensure_ascii=False),data.total_price))
    db.commit()
    return {"message":"تم إرسال الأوردر ✅"}

@app.get("/admin/orders")
def get_orders(db=Depends(get_db)):
    return [dict(o) for o in db.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()]

@app.put("/admin/orders/{oid}")
def update_order(oid:int, data:OrderStatusUpdate, db=Depends(get_db)):
    db.execute("UPDATE orders SET status=? WHERE id=?", (data.status,oid)); db.commit()
    return {"message":"تم تحديث الأوردر ✅"}
