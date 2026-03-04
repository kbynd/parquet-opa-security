import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pandas as pd
from pipeline.characterize import characterize
from registry.characterization import bit_mask, decode

def make_row(**kwargs):
    return pd.DataFrame([{"customer_id": "X", "name": "Test", **kwargs}])


def test_pii_bit_set_when_email_present():
    df = make_row(email="test@example.com", region="APAC")
    result = characterize(df)
    pii_lo, _ = bit_mask("pii")
    assert result.iloc[0]["_sec_lo"] & pii_lo != 0, "PII bit should be set"


def test_phi_bit_set_when_health_condition_present():
    df = make_row(email="test@example.com", region="APAC", health_condition="Diabetes")
    result = characterize(df)
    phi_lo, _ = bit_mask("phi")
    assert result.iloc[0]["_sec_lo"] & phi_lo != 0, "PHI bit should be set"


def test_region_apac_bit():
    df = make_row(email="x@x.com", region="APAC")
    result = characterize(df)
    apac_lo, _ = bit_mask("region_apac")
    assert result.iloc[0]["_sec_lo"] & apac_lo != 0


def test_region_emea_bit():
    df = make_row(email="x@x.com", region="EMEA")
    result = characterize(df)
    emea_lo, _ = bit_mask("region_emea")
    assert result.iloc[0]["_sec_lo"] & emea_lo != 0


def test_no_double_application():
    """Running characterize twice should give same result (idempotent)."""
    df = make_row(email="x@x.com", region="APAC", annual_salary=100000)
    result1 = characterize(df)
    # Strip _sec_lo/_sec_hi and re-run
    stripped = result1.drop(columns=["_sec_lo", "_sec_hi"])
    result2 = characterize(stripped)
    assert result1.iloc[0]["_sec_lo"] == result2.iloc[0]["_sec_lo"]


def test_decode_roundtrip():
    df = make_row(email="x@x.com", region="APAC", health_condition="Flu", annual_salary=50000)
    result = characterize(df)
    lo = result.iloc[0]["_sec_lo"]
    dims = decode(lo, 0)
    assert "pii" in dims
    assert "phi" in dims
    assert "region_apac" in dims
    assert "financial" in dims
