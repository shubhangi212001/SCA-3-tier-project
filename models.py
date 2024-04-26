#models.py
# create domain_banner table in database
from sqlalchemy import Integer,VARCHAR,Column
from db import Base
try:  
    class SCA(Base):
        __tablename__ = 'sca'
        id = Column(Integer, primary_key=True, index=True)
        cwe_id	 = Column(Integer)
        name = Column(VARCHAR)
        
except Exception as e:
    print (e)
    
