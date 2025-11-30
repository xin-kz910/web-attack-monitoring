# logging/test_app.py
from fastapi import FastAPI
from .router import router as logging_router

app = FastAPI()
app.include_router(logging_router)
