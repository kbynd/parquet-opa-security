#!/usr/bin/env python3
"""
Example: Using Secured Parquet Reader with PySpark

This script demonstrates how to use the secured Parquet format with PySpark.

Prerequisites:
1. OPA server running: docker-compose up -d
2. Secured Parquet files with _sec_lo and _sec_hi columns
3. Parquet security JARs in Spark classpath

Usage:
    python example_spark_usage.py
"""

from pyspark.sql import SparkSession

def create_secured_spark_session(user_id, roles, jurisdiction="US"):
    """
    Create a Spark session with secured Parquet reading enabled.

    Args:
        user_id: User identifier (e.g., "analyst@co.com")
        roles: Comma-separated roles (e.g., "analyst,apac_reader")
        jurisdiction: User's jurisdiction code (optional)

    Returns:
        SparkSession configured for secured reading
    """
    return SparkSession.builder \
        .appName("Secured Parquet Demo") \
        .master("local[2]") \
        .config("spark.jars", "target/parquet-security-spark-0.1.0-SNAPSHOT.jar,../parquet-security-core/target/parquet-security-core-0.1.0-SNAPSHOT.jar") \
        .config("spark.sql.sources.default", "secured-parquet") \
        .config("spark.security.opa.url", "http://localhost:8181") \
        .config("spark.security.user.id", user_id) \
        .config("spark.security.user.roles", roles) \
        .config("spark.security.user.jurisdiction", jurisdiction) \
        .config("spark.security.fail_open", "false") \
        .getOrCreate()


def example_1_admin_user():
    """Example 1: Admin user sees all records"""
    print("\n=== Example 1: Admin User (sees all) ===")

    spark = create_secured_spark_session(
        user_id="admin@co.com",
        roles="admin"
    )

    df = spark.read.parquet("/tmp/secured/customers.parquet")

    print(f"Total records visible: {df.count()}")
    df.select("name", "region", "_sec_lo").show(truncate=False)

    spark.stop()


def example_2_apac_analyst():
    """Example 2: APAC analyst sees only APAC records"""
    print("\n=== Example 2: APAC Analyst (sees only APAC) ===")

    spark = create_secured_spark_session(
        user_id="apac-analyst@co.com",
        roles="analyst,apac_reader",
        jurisdiction="IN"
    )

    df = spark.read.parquet("/tmp/secured/customers.parquet")

    print(f"Total records visible: {df.count()}")
    df.select("name", "region", "_sec_lo").show(truncate=False)

    spark.stop()


def example_3_emea_analyst():
    """Example 3: EMEA analyst sees only EMEA records"""
    print("\n=== Example 3: EMEA Analyst (sees only EMEA) ===")

    spark = create_secured_spark_session(
        user_id="emea-analyst@co.com",
        roles="analyst,emea_reader",
        jurisdiction="DE"
    )

    df = spark.read.parquet("/tmp/secured/customers.parquet")

    print(f"Total records visible: {df.count()}")
    df.select("name", "region", "_sec_lo").show(truncate=False)

    spark.stop()


def example_4_explicit_format():
    """Example 4: Explicitly specify secured-parquet format"""
    print("\n=== Example 4: Explicit Format Specification ===")

    spark = SparkSession.builder \
        .appName("Secured Parquet Demo") \
        .master("local[2]") \
        .config("spark.jars", "target/parquet-security-spark-0.1.0-SNAPSHOT.jar,../parquet-security-core/target/parquet-security-core-0.1.0-SNAPSHOT.jar") \
        .config("spark.security.opa.url", "http://localhost:8181") \
        .config("spark.security.user.id", "analyst@co.com") \
        .config("spark.security.user.roles", "analyst,apac_reader") \
        .getOrCreate()

    # Explicitly use secured-parquet format
    df = spark.read \
        .format("secured-parquet") \
        .load("/tmp/secured/customers.parquet")

    print(f"Total records visible: {df.count()}")
    df.select("name", "region", "_sec_lo").show(truncate=False)

    spark.stop()


def example_5_disable_security():
    """Example 5: Disable security filtering (debug mode)"""
    print("\n=== Example 5: Security Disabled (debug mode) ===")

    spark = SparkSession.builder \
        .appName("Secured Parquet Demo") \
        .master("local[2]") \
        .config("spark.jars", "target/parquet-security-spark-0.1.0-SNAPSHOT.jar,../parquet-security-core/target/parquet-security-core-0.1.0-SNAPSHOT.jar") \
        .config("spark.sql.sources.default", "secured-parquet") \
        .config("spark.security.enabled", "false") \
        .getOrCreate()

    df = spark.read.parquet("/tmp/secured/customers.parquet")

    print(f"Total records visible (security disabled): {df.count()}")
    df.select("name", "region", "_sec_lo").show(truncate=False)

    spark.stop()


def example_6_sql_queries():
    """Example 6: Use Spark SQL with secured tables"""
    print("\n=== Example 6: Spark SQL Queries ===")

    spark = create_secured_spark_session(
        user_id="analyst@co.com",
        roles="analyst,apac_reader",
        jurisdiction="IN"
    )

    # Register as temporary view
    df = spark.read.parquet("/tmp/secured/customers.parquet")
    df.createOrReplaceTempView("customers")

    # Run SQL queries - security filter applied transparently
    result = spark.sql("""
        SELECT region, COUNT(*) as count
        FROM customers
        GROUP BY region
        ORDER BY count DESC
    """)

    print("Region distribution (filtered by security):")
    result.show()

    spark.stop()


if __name__ == "__main__":
    print("""
    Secured Parquet Reader - Spark Integration Examples
    ===================================================

    These examples demonstrate different usage patterns for the
    secured Parquet reader with Spark.

    Prerequisites:
    1. Run: docker-compose up -d (start OPA)
    2. Run: mvn clean install (build JARs)
    3. Create secured test data (see README)
    """)

    try:
        # Run examples
        example_1_admin_user()
        example_2_apac_analyst()
        example_3_emea_analyst()
        example_4_explicit_format()
        example_5_disable_security()
        example_6_sql_queries()

        print("\n✅ All examples completed successfully!")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        print("\nCommon issues:")
        print("- OPA server not running: docker-compose up -d")
        print("- JARs not built: mvn clean install")
        print("- Test data not created: see README for characterization pipeline")
        raise
