from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app import models
from app.database import engine
from app.router import users, admin
from fastapi.staticfiles import StaticFiles


def get_application():
    _app = FastAPI(title=settings.PROJECT_NAME)

    _app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return _app


app = get_application()
app.mount("/static", StaticFiles(directory="static"), name="static")


# Create database tables
models.Base.metadata.create_all(bind=engine)

# Include Routers
app.include_router(users.router, prefix="/api")
app.include_router(admin.router, prefix="/api")


@app.get("/")
async def root():
    return {"message": "Hello Root!"}


@app.get("/root2")
async def root2():
    return {"message": "Hello Root2!"}
