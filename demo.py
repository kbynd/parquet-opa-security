#!/usr/bin/env python3
"""
Interactive demo of the OPA-Parquet security system.
Run after: docker-compose up -d
"""

import sys
import os
from pyspark.sql import SparkSession
from plugin.opa_plugin import install_opa_plugin, set_user_context

def main():
    print("=" * 70)
    print("OPA-Parquet Security Demo")
    print("=" * 70)

    # Step 1: Characterize the sample data
    print("\n[Step 1] Characterizing sample data...")
    from pipeline.characterize import run

    secured_path = "/tmp/secured/customers.parquet"
    os.makedirs("/tmp/secured", exist_ok=True)

    run("data/sample_raw.csv", secured_path)

    # Step 2: Inspect the characterized data
    print("\n[Step 2] Inspecting characterized data...")
    import pyarrow.parquet as pq
    from registry.characterization import decode

    table = pq.read_table(secured_path)
    df = table.to_pandas()

    print("\nCharacterized rows:")
    print("-" * 100)
    for _, row in df.iterrows():
        dims = decode(row['_sec_lo'], row['_sec_hi'])
        print(f"{row['name']:20s} | {row['region']:5s} | _sec_lo={hex(row['_sec_lo']):12s} | {dims}")

    # Step 3: Test access control with different user contexts
    print("\n[Step 3] Testing access control with Spark...")

    spark = SparkSession.builder.master('local[2]').appName('demo').getOrCreate()
    spark.sparkContext.setLogLevel("ERROR")  # Reduce Spark logging noise

    install_opa_plugin(spark)

    # Test 1: APAC analyst (no PHI access)
    print("\n" + "=" * 70)
    print("Test 1: APAC analyst (sees only APAC, no PHI)")
    print("=" * 70)
    set_user_context('kalyan@co.com', ['analyst', 'apac_reader'], 'IN')
    df1 = spark.read.parquet(secured_path)
    print(f"\nRows visible: {df1.count()}")
    df1.select("name", "region", "email", "annual_salary", "health_condition", "department").show(truncate=False)

    # Test 2: Global finance reader (financial data, all regions, no PHI)
    print("\n" + "=" * 70)
    print("Test 2: Global finance reader (sees financial data, all regions, no PHI)")
    print("=" * 70)
    set_user_context('finance@co.com', ['analyst', 'finance_reader', 'global_reader'], 'IN')
    df2 = spark.read.parquet(secured_path)
    print(f"\nRows visible: {df2.count()}")
    df2.select("name", "region", "email", "annual_salary", "health_condition", "department").show(truncate=False)

    # Test 3: PHI-authorized APAC analyst
    print("\n" + "=" * 70)
    print("Test 3: PHI-authorized APAC analyst (sees APAC + health records)")
    print("=" * 70)
    set_user_context('doctor@co.com', ['analyst', 'phi_authorized', 'apac_reader'], 'IN')
    df3 = spark.read.parquet(secured_path)
    print(f"\nRows visible: {df3.count()}")
    df3.select("name", "region", "email", "annual_salary", "health_condition", "department").show(truncate=False)

    # Test 4: Admin (sees everything)
    print("\n" + "=" * 70)
    print("Test 4: Admin (sees everything)")
    print("=" * 70)
    set_user_context('admin@co.com', ['admin'], 'IN')
    df4 = spark.read.parquet(secured_path)
    print(f"\nRows visible: {df4.count()}")
    df4.select("name", "region", "email", "annual_salary", "health_condition", "department").show(truncate=False)

    print("\n" + "=" * 70)
    print("Demo complete!")
    print("=" * 70)

    spark.stop()


if __name__ == "__main__":
    main()
