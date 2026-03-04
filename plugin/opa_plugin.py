"""
Installs a transparent security filter on spark.read().

Usage:
    from plugin.opa_plugin import install_opa_plugin, set_user_context

    spark = SparkSession.builder.appName("app").getOrCreate()
    install_opa_plugin(spark)

    set_user_context("kalyan@co.com", ["analyst", "apac_reader"], "IN")

    df = spark.read.parquet("path/to/secured/")   # ← unchanged
    df.show()                                      # ← only permitted rows
"""

import requests
import threading
import logging
from functools import wraps
from typing import Optional
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F

logger = logging.getLogger(__name__)

# Thread-local user context — safe for concurrent notebook kernels / threads
_ctx = threading.local()


class OpaError(Exception):
    pass


class OpaClient:
    def __init__(self, url: str, timeout: int = 5):
        self.url = url.rstrip("/")
        self.timeout = timeout

    def get_permitted_mask(self, user_id: str, roles: list, jurisdiction: str = "") -> tuple[int, int]:
        payload = {
            "input": {
                "user": {
                    "id": user_id,
                    "roles": roles,
                    "jurisdiction": jurisdiction,
                }
            }
        }
        try:
            resp = requests.post(
                f"{self.url}/v1/data/lakehouse/access/result",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            lo = result.get("permitted_lo", 0)
            hi = result.get("permitted_hi", 0)
            logger.debug(f"OPA permitted mask: lo={hex(lo)}, hi={hex(hi)}, "
                        f"dims={result.get('active_dimensions', [])}")
            return lo, hi
        except requests.RequestException as e:
            raise OpaError(f"OPA unreachable: {e}") from e


def set_user_context(user_id: str, roles: list, jurisdiction: str = ""):
    """Call once per session/request to establish who is reading data."""
    _ctx.user_id     = user_id
    _ctx.roles       = roles
    _ctx.jurisdiction = jurisdiction


def _current_user() -> dict:
    return {
        "user_id":      getattr(_ctx, "user_id", "anonymous"),
        "roles":        getattr(_ctx, "roles", []),
        "jurisdiction": getattr(_ctx, "jurisdiction", ""),
    }


def _apply_security_filter(df: DataFrame, opa_client: OpaClient, fail_open: bool) -> DataFrame:
    """
    Core enforcement logic.
    Called once per read — OPA called once, filter baked into plan.
    """
    # If table has no security columns, it's an unsecured table — pass through
    if "_sec_lo" not in df.columns:
        logger.debug("Table has no _sec_lo column — passing through unsecured")
        return df

    user = _current_user()

    try:
        permitted_lo, permitted_hi = opa_client.get_permitted_mask(
            user["user_id"], user["roles"], user["jurisdiction"]
        )
    except OpaError as e:
        if fail_open:
            logger.error(f"OPA error, failing open (INSECURE): {e}")
            return df.drop("_sec_lo", "_sec_hi")
        else:
            logger.error(f"OPA error, failing closed: {e}")
            # Return empty DataFrame with correct schema
            return df.filter(F.lit(False)).drop("_sec_lo", "_sec_hi")

    # forbidden_lo: bits that are set in the doc but NOT in permitted mask
    # A row is visible iff it has no forbidden bits
    # (_sec_lo & ~permitted_lo) == 0
    # Python int → Spark Long: mask to 63 bits (Spark Long is signed 64-bit)
    forbidden_lo = (~permitted_lo) & 0x7FFF_FFFF_FFFF_FFFF
    forbidden_hi = (~permitted_hi) & 0x7FFF_FFFF_FFFF_FFFF

    cond = F.col("_sec_lo").bitwiseAND(F.lit(forbidden_lo)) == F.lit(0)

    if "_sec_hi" in df.columns:
        cond = cond & (F.col("_sec_hi").bitwiseAND(F.lit(forbidden_hi)) == F.lit(0))

    return df.filter(cond).drop("_sec_lo", "_sec_hi")


def install_opa_plugin(
    spark: SparkSession,
    opa_url: str = "http://localhost:8181",
    fail_open: bool = False,
):
    """
    Monkey-patches DataFrameReader so that:
      spark.read.parquet(path)
      spark.read.load(path)
      spark.read.format(...).load(path)
      spark.table(name)
    all automatically apply OPA security filtering.

    fail_open=False (default, recommended): if OPA is unreachable, return empty DataFrame
    fail_open=True: if OPA is unreachable, return unfiltered data (INSECURE, dev only)
    """
    from pyspark.sql.readwriter import DataFrameReader

    client = OpaClient(opa_url)

    original_parquet = DataFrameReader.parquet
    original_load    = DataFrameReader.load
    original_table   = SparkSession.table

    @wraps(original_parquet)
    def secured_parquet(self, *paths, **options):
        df = original_parquet(self, *paths, **options)
        return _apply_security_filter(df, client, fail_open)

    @wraps(original_load)
    def secured_load(self, path=None, format=None, schema=None, **options):
        df = original_load(self, path=path, format=format, schema=schema, **options)
        return _apply_security_filter(df, client, fail_open)

    @wraps(original_table)
    def secured_table(self, tableName):
        df = original_table(self, tableName)
        return _apply_security_filter(df, client, fail_open)

    DataFrameReader.parquet = secured_parquet
    DataFrameReader.load    = secured_load
    SparkSession.table      = secured_table

    print(f"✓ OPA security plugin installed")
    print(f"  Policy endpoint : {opa_url}")
    print(f"  Fail mode       : {'open (INSECURE)' if fail_open else 'closed (safe)'}")
