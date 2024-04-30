#db.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
# from models.response import Response


    
host = "172.16.22.122:3306" 
username = "root" 
password = "support#123" 
database = "CSV_DB" 
SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{username}:{password}@{host}/{database}?charset=utf8" 

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
    


# database session
def get_db():
    try:
        db = SessionLocal()
        yield db
    except Exception as e:
        return e
    finally:
        db.close()
