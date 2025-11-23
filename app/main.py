from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from config import cur_lang
from enums import Lang


app = FastAPI(
    title="Attack Modeling MVP",
    version="0.1"
)


@app.middleware("http")
async def set_lang_middleware(request: Request, call_next):
    lang_header = request.headers.get("Accept-Language", "ru")
    new_lang = Lang.ENG if "en" in lang_header else Lang.RU    
    token = cur_lang.set(new_lang)
    try:
        response = await call_next(request)
        return response
    finally:
        cur_lang.reset(token)


@app.get("/")
def read_root():
    return {"message": "Backend жив, заебато!"}

@app.get("/status")
def status():
    return JSONResponse(content={"status": "ok", "db_alive": False})
