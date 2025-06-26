# tests/test_main.py

import pytest
from aphelion.main import get_greeting

def test_get_greeting():
    """
    Tests the get_greeting function from main.py.
    """
    assert get_greeting() == "Hello from Aphelion!"

def test_placeholder_true():
    """
    A placeholder test that always passes.
    Can be removed or replaced as actual tests are added.
    """
    assert True is True
