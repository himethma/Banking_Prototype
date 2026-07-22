from __future__ import annotations

import uuid
from pydantic import BaseModel, Field, field_validator


class TransferPrepareRequest(BaseModel):
    source_account_id: uuid.UUID
    destination_account_number: str = Field(min_length=10, max_length=18, pattern=r"^[0-9]+$")
    amount_minor: int = Field(gt=0)
    currency: str = Field(default="LKR", pattern=r"^LKR$")
    description: str = Field(default="", max_length=140)

    @field_validator("description")
    @classmethod
    def clean_description(cls, value: str) -> str:
        return " ".join(value.split())


class TransferCommitRequest(BaseModel):
    preparation_id: uuid.UUID

