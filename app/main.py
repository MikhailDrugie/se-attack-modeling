from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from config import cur_lang
from enums import Lang
from routers import auth, users, scans, cwe
from utils.logging import app_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP 
    app_logger.info("[STARTUP] Application starting...")
    app_logger.info(f'[STARTUP] Version: {app.version}')
    yield
    # SHUTDOWN
    app_logger.info("[SHUTDOWN] Application shutting down...")
    app_logger.info("[SHUTDOWN] Cleanup completed")


app = FastAPI(
    title="Attack Modeling API",
    version="1.0",
    lifespan=lifespan
)

# TODO: do we really need CORS for frontend?
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(scans.router)
app.include_router(cwe.router)

@app.get("/")
def read_root():
    app_logger.info("[API] Root endpoint accessed")
    return {"message": app.title, "version": app.version, "status": "running"}
