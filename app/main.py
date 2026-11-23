from fastapi import FastAPI, HTTPException
app = FastAPI(title="devsecops-pipeline")
ITEMS = {1: {"id": 1, "name": "sensor"}, 2: {"id": 2, "name": "gateway"}}

@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
@app.get("/items/{item_id}")
def read_item(item_id: int) -> dict:
    item = ITEMS.get(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item
import subprocess
@app.get("/ping")
def ping(host: str) -> dict:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": result.stdout}
