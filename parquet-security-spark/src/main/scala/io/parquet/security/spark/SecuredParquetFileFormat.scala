package io.parquet.security.spark

import org.apache.hadoop.conf.Configuration
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.catalyst.InternalRow
import org.apache.spark.sql.execution.datasources.{OutputWriterFactory, PartitionedFile}
import org.apache.spark.sql.execution.datasources.parquet.ParquetFileFormat
import org.apache.spark.sql.sources.Filter
import org.apache.spark.sql.types.StructType
import org.apache.spark.util.SerializableConfiguration
import io.parquet.security._
import io.parquet.security.opa.OpaSecurityPolicyProvider
import org.slf4j.LoggerFactory

import scala.collection.JavaConverters._

/**
 * Spark-aware Parquet format that reads Spark config and applies security filtering.
 *
 * This is NOT an "adapter" - it's Spark application code that knows how to read
 * Spark's configuration and call OPA to get the permitted mask.
 *
 * Configuration keys:
 * - spark.security.opa.url: OPA server URL (required)
 * - spark.security.user.id: User ID (required)
 * - spark.security.user.roles: Comma-separated roles (required)
 * - spark.security.user.jurisdiction: User jurisdiction (optional)
 * - spark.security.fail_open: Whether to allow access on OPA failure (default: false)
 * - spark.security.enabled: Enable/disable security filtering (default: true)
 *
 * Usage:
 * {{{
 * val spark = SparkSession.builder()
 *   .config("spark.sql.sources.default", "secured-parquet")
 *   .config("spark.security.opa.url", "http://localhost:8181")
 *   .config("spark.security.user.id", "analyst@co.com")
 *   .config("spark.security.user.roles", "analyst,apac_reader")
 *   .config("spark.security.user.jurisdiction", "IN")
 *   .getOrCreate()
 *
 * // Completely transparent - no code changes needed
 * val df = spark.read.parquet("/tmp/secured/customers.parquet")
 * df.show()
 * }}}
 */
class SecuredParquetFileFormat extends ParquetFileFormat {

  private val logger = LoggerFactory.getLogger(classOf[SecuredParquetFileFormat])

  /**
   * Override buildReaderWithPartitionValues to inject security filtering.
   *
   * This method:
   * 1. Reads Spark configuration
   * 2. Creates OPA policy provider and user context
   * 3. Fetches permitted mask from OPA (once per query)
   * 4. Wraps base reader with filtering logic
   */
  override def buildReaderWithPartitionValues(
      sparkSession: SparkSession,
      dataSchema: StructType,
      partitionSchema: StructType,
      requiredSchema: StructType,
      filters: Seq[Filter],
      options: Map[String, String],
      hadoopConf: Configuration
  ): PartitionedFile => Iterator[InternalRow] = {

    // Check if security is enabled
    val securityEnabled = sparkSession.conf.get("spark.security.enabled", "true").toBoolean

    if (!securityEnabled) {
      logger.info("Security filtering is disabled")
      return super.buildReaderWithPartitionValues(
        sparkSession, dataSchema, partitionSchema, requiredSchema, filters, options, hadoopConf
      )
    }

    // Read Spark configuration
    val opaUrl = sparkSession.conf.getOption("spark.security.opa.url") match {
      case Some(url) => url
      case None =>
        logger.error("spark.security.opa.url is not configured")
        throw new IllegalArgumentException("spark.security.opa.url must be configured for secured Parquet reading")
    }

    val userId = sparkSession.conf.getOption("spark.security.user.id") match {
      case Some(id) => id
      case None =>
        logger.error("spark.security.user.id is not configured")
        throw new IllegalArgumentException("spark.security.user.id must be configured for secured Parquet reading")
    }

    val rolesStr = sparkSession.conf.getOption("spark.security.user.roles") match {
      case Some(roles) => roles
      case None =>
        logger.error("spark.security.user.roles is not configured")
        throw new IllegalArgumentException("spark.security.user.roles must be configured for secured Parquet reading")
    }

    val jurisdiction = sparkSession.conf.getOption("spark.security.user.jurisdiction").orNull
    val failOpen = sparkSession.conf.get("spark.security.fail_open", "false").toBoolean

    val roles = rolesStr.split(",").map(_.trim).toList.asJava

    logger.info(s"Configuring secured Parquet reader for user=$userId, roles=$rolesStr, jurisdiction=$jurisdiction")

    // Create policy provider and user context
    val policyProvider = new OpaSecurityPolicyProvider(opaUrl, failOpen)
    val userContext = new UserContext(userId, roles, jurisdiction, null)

    // Fetch permitted mask once (OPA called once per spark.read())
    val permittedMask = try {
      policyProvider.getPermittedMask(userContext)
    } catch {
      case e: SecurityException =>
        logger.error(s"Failed to fetch permitted mask from OPA: ${e.getMessage}")
        throw e
    }

    logger.info(s"Fetched permitted mask: permittedLo=${permittedMask.permittedLo}, permittedHi=${permittedMask.permittedHi}")

    // Get base reader
    val baseReader = super.buildReaderWithPartitionValues(
      sparkSession, dataSchema, partitionSchema, requiredSchema, filters, options, hadoopConf
    )

    // Find _sec_lo and _sec_hi column positions
    val secLoIdx = try {
      dataSchema.fieldIndex("_sec_lo")
    } catch {
      case _: IllegalArgumentException =>
        logger.warn("_sec_lo column not found in schema - security filtering will be skipped for this file")
        -1
    }

    val secHiIdx = try {
      dataSchema.fieldIndex("_sec_hi")
    } catch {
      case _: IllegalArgumentException =>
        logger.warn("_sec_hi column not found in schema - security filtering will be skipped for this file")
        -1
    }

    // If security columns are missing, either fail or skip filtering
    if (secLoIdx < 0 || secHiIdx < 0) {
      if (!failOpen) {
        throw new SecurityException("Security columns (_sec_lo, _sec_hi) not found in file schema")
      }
      logger.warn("Security columns not found and fail_open=true - allowing all rows")
      return baseReader
    }

    // Wrap with security filtering
    (file: PartitionedFile) => {
      val baseIterator = baseReader(file)

      // Compute forbidden masks
      val forbiddenLo = (~permittedMask.permittedLo) & 0x7FFFFFFFFFFFFFFFL
      val forbiddenHi = (~permittedMask.permittedHi) & 0x7FFFFFFFFFFFFFFFL

      var totalRows = 0L
      var filteredRows = 0L

      // Apply filtering
      val filteredIterator = baseIterator.filter { row =>
        totalRows += 1

        val secLo = row.getLong(secLoIdx)
        val secHi = row.getLong(secHiIdx)

        val isPermitted = ((secLo & forbiddenLo) == 0) && ((secHi & forbiddenHi) == 0)

        if (!isPermitted) {
          filteredRows += 1
        }

        isPermitted
      }

      // Log statistics when iterator is exhausted
      new Iterator[InternalRow] {
        var exhausted = false

        override def hasNext: Boolean = {
          val hasMore = filteredIterator.hasNext
          if (!hasMore && !exhausted) {
            exhausted = true
            logger.info(s"Filtered ${filteredRows} of ${totalRows} rows from file ${file.filePath}")
          }
          hasMore
        }

        override def next(): InternalRow = filteredIterator.next()
      }
    }
  }

  /**
   * Override prepareWrite to prevent writing to secured Parquet files.
   * Writing is not supported in this version.
   */
  override def prepareWrite(
      sparkSession: SparkSession,
      job: org.apache.hadoop.mapreduce.Job,
      options: Map[String, String],
      dataSchema: StructType
  ): OutputWriterFactory = {
    throw new UnsupportedOperationException(
      "Writing to secured Parquet files is not yet supported. " +
      "Use the characterization pipeline to create secured files."
    )
  }
}
