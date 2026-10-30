"""Alembic env: URL comes from settings; metadata from models."""

from alembic import context
from sqlalchemy import create_engine

from security_agent.config import get_settings
from security_agent.db.models import Base

config = context.config
engine = create_engine(get_settings().database_url, pool_pre_ping=True)

with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()
