# database.py

# 1️⃣ استيراد المكتبات اللازمة
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

# 2️⃣ تحميل ملف البيئة (.env)
load_dotenv()

# 3️⃣ جلب رابط قاعدة البيانات من البيئة
DATABASE_URL = os.getenv("DATABASE_URL")

# 4️⃣ إنشاء محرك الاتصال مع القاعدة
engine = create_engine(DATABASE_URL)

# 5️⃣ إنشاء Session (جلسة تواصل مع القاعدة)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 6️⃣ إنشاء Base (هي القاعدة التي سنبني الجداول منها)
Base = declarative_base()
