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
            print("jwt_algorithm added successfully.")
    except Exception as e:
        print("jwt_algorithm errored or existed:", e)

    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE assets ADD COLUMN is_third_party BOOLEAN DEFAULT FALSE;"))
            print("is_third_party added successfully.")
    except Exception as e:
        print("is_third_party errored or existed:", e)

    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE assets ADD COLUMN fingerprint_hash VARCHAR(64);"))
            print("fingerprint_hash added successfully.")
    except Exception as e:
        print("fingerprint_hash errored or existed:", e)
        
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN user_id UUID;"))
            print("user_id column added successfully.")
    except Exception as e:
        print("user_id errored or existed:", e)

    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN scan_type VARCHAR(10) DEFAULT 'deep' NOT NULL;"))
            print("Added scan_type column to scan_jobs successfully.")
    except Exception as e:
        print("scan_type errored or existed:", e)
        
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE certificates DROP CONSTRAINT certificates_sha256_fingerprint_key;"))
            print("Dropped unique constraint on certificates successfully.")
    except Exception as e:
        print("certificates_sha256_fingerprint_key constraint errored or already dropped:", e)

    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN deployment_mode VARCHAR(20) DEFAULT 'secure';"))
            conn.execute(text("ALTER TABLE users ADD COLUMN ai_tier VARCHAR(20) DEFAULT 'free';"))
            conn.execute(text("ALTER TABLE users ADD COLUMN cloud_api_keys JSON;"))
            print("AI tier columns added successfully.")
    except Exception as e:
        print("AI tier columns errored or existed:", e)
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN result_data JSON;"))
            print("result_data column added successfully.")
    except Exception as e:
        print("result_data errored or existed:", e)

if __name__ == "__main__":
    modify_db()
    print("Execution complete.")
