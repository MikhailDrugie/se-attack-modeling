from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Attack Modelling MVP",
    version="0.1"
)

@app.get("/")
def read_root():
    return {"message": "Backend жив, заебато!"}

@app.get("/status")
def status():
    return JSONResponse(content={"status": "ok", "db_alive": False})
