from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes.auth import router as auth_router
from routes.payments import router as payments_router

app = FastAPI(title="Beevolve API", version="1.0.0")

origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(payments_router)

@app.get("/")
async def root():
    return {"message": "Beevolve API is running"}

@app.get("/api/health")
async def health():
    return {"status": "ok"}
