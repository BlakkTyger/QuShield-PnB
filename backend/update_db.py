from app.core.database import engine
from sqlalchemy import text

def modify_db():
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE assets ADD COLUMN third_party_vendor VARCHAR(255);"))
    except Exception as e:
        print("third_party_vendor errored or existed:", e)
    
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE assets ADD COLUMN auth_mechanisms VARCHAR(255);"))
    except Exception as e:
        print("auth_mechanisms errored or existed:", e)
        
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE assets ADD COLUMN jwt_algorithm VARCHAR(50);"))
    except Exception as e:
        print("jwt_algorithm errored or existed:", e)

if __name__ == "__main__":
    modify_db()
    print("Execution complete.")
