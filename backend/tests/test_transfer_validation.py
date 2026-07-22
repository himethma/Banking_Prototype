import uuid

import pytest
from pydantic import ValidationError

from app.schemas import TransferPrepareRequest


def valid_request(**changes):
    values = {
        "source_account_id": uuid.uuid4(),
        "destination_account_number": "100000000002",
        "amount_minor": 10_000,
        "currency": "LKR",
        "description": "  Rent   payment  ",
    }
    values.update(changes)
    return TransferPrepareRequest(**values)


def test_transfer_uses_integer_minor_units_and_normalizes_description():
    request = valid_request()
    assert request.amount_minor == 10_000
    assert request.description == "Rent payment"


@pytest.mark.parametrize("amount", [0, -1])
def test_non_positive_amount_is_rejected(amount):
    with pytest.raises(ValidationError):
        valid_request(amount_minor=amount)


def test_unsupported_currency_is_rejected():
    with pytest.raises(ValidationError):
        valid_request(currency="USD")


def test_non_numeric_destination_is_rejected():
    with pytest.raises(ValidationError):
        valid_request(destination_account_number="account-two")

