# models.py

from sqlalchemy import Column, DateTime, Integer, String, func
from database import Base

# 1️⃣ تعريف جدول الشهادات
class Certificate(Base):
    __tablename__ = "certificates"  # اسم الجدول داخل قاعدة البيانات

    # 2️⃣ الأعمدة (الحقول) داخل الجدول
    id = Column(Integer, primary_key=True, index=True)
    firstname = Column(String, nullable=False)
    lastname = Column(String, nullable=False)
    birthdate = Column(String, nullable=False)
    certificate_name = Column(String, nullable=False)
    serial_number = Column(String, nullable=False, unique=True)
    random_code = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())