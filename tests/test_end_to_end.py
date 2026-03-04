"""
Requires: OPA running at localhost:8181 AND PySpark.
Run after: docker-compose up -d && python pipeline/characterize.py data/sample_raw.csv /tmp/test_secured.parquet
"""
import os
import pytest

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
PARQUET_PATH = "/tmp/test_secured.parquet"


@pytest.fixture(scope="module")
def spark():
    from pyspark.sql import SparkSession
    return SparkSession.builder.master("local[2]").appName("test").getOrCreate()


@pytest.fixture(scope="module")
def secured_parquet(spark):
    """Run characterization pipeline first."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    import pandas as pd
    from pipeline.characterize import characterize
    import pyarrow as pa
    import pyarrow.parquet as pq

    df = pd.read_csv("data/sample_raw.csv")
    characterized = characterize(df)
    table = pa.Table.from_pandas(characterized)
    pq.write_table(table, PARQUET_PATH)
    return PARQUET_PATH


def test_apac_reader_sees_only_apac(spark, secured_parquet):
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    from plugin.opa_plugin import install_opa_plugin, set_user_context
    install_opa_plugin(spark, opa_url=OPA_URL, fail_open=False)
    set_user_context("analyst@co.com", ["analyst", "apac_reader"], "IN")

    df = spark.read.parquet(secured_parquet)
    rows = df.collect()

    regions = {r["region"] for r in rows}
    assert regions == {"APAC"}, f"Expected only APAC rows, got: {regions}"


def test_phi_unauthorized_sees_no_health_records(spark, secured_parquet):
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    from plugin.opa_plugin import install_opa_plugin, set_user_context
    install_opa_plugin(spark, opa_url=OPA_URL, fail_open=False)
    set_user_context("analyst@co.com", ["analyst", "apac_reader"], "IN")

    df = spark.read.parquet(secured_parquet)
    rows = df.collect()

    # Rows with health_condition should be excluded (phi bit set, not in permitted mask)
    health_rows = [r for r in rows if r["health_condition"] is not None and r["health_condition"] != ""]
    assert len(health_rows) == 0, "PHI rows should not be visible to unauthorized user"


def test_phi_authorized_sees_health_records(spark, secured_parquet):
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    from plugin.opa_plugin import install_opa_plugin, set_user_context
    set_user_context("doctor@co.com", ["analyst", "phi_authorized", "apac_reader"], "IN")

    df = spark.read.parquet(secured_parquet)
    rows = df.collect()

    health_rows = [r for r in rows if r["health_condition"] is not None and r["health_condition"] != ""]
    assert len(health_rows) > 0, "PHI-authorized user should see health records"


def test_opa_unreachable_fails_closed(spark, secured_parquet):
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    from plugin.opa_plugin import install_opa_plugin, set_user_context
    install_opa_plugin(spark, opa_url="http://localhost:9999", fail_open=False)
    set_user_context("analyst@co.com", ["analyst"], "IN")

    df = spark.read.parquet(secured_parquet)
    assert df.count() == 0, "Unreachable OPA with fail_open=False should return no rows"
