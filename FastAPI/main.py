import sqlite3
from scanner.misc import secrets
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import APIKeyHeader
import os

app = FastAPI()

api_key_header = APIKeyHeader(name="api_key")

# List of valid API tokens
valid_tokens = [os.environ["FASTAPI_DEV_KEY"]]

async def authenticate(api_key: str = Depends(api_key_header)):
    if api_key not in valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return api_key


@app.get("/domain/search/{domain_name}")
def search_domain(domain_name: str, api_key: str = Depends(authenticate)):
    db_path = "/var/csirt/source/scanner/db.sqlite3"  # Replace with your actual path

    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    query = f"SELECT * FROM nessus_okdomains WHERE domain = ?"
    cursor.execute(query, (domain_name,))

    domain_data = cursor.fetchone()
    connection.close()

    if domain_data:
        columns = [column[0] for column in cursor.description]
        domain_dict = dict(zip(columns, domain_data))
        return domain_dict
    else:
        return {"error": "Domain not found"}

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)