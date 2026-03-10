package io.parquet.security.spark

import org.apache.spark.sql.execution.datasources.FileFormat
import org.apache.spark.sql.execution.datasources.parquet.ParquetFileFormat
import org.apache.spark.sql.sources.DataSourceRegister

/**
 * Default source for Spark data source registration.
 *
 * This allows users to reference the secured Parquet format as:
 * - .format("secured-parquet")
 * - .format("io.parquet.security.spark")
 *
 * Usage:
 * {{{
 * spark.read
 *   .format("secured-parquet")
 *   .load("/path/to/data.parquet")
 * }}}
 *
 * Or register as default:
 * {{{
 * spark.conf.set("spark.sql.sources.default", "secured-parquet")
 * spark.read.parquet("/path/to/data.parquet")  // Uses secured format
 * }}}
 */
class DefaultSource extends SecuredParquetFileFormat with DataSourceRegister {

  /**
   * Short name for this data source.
   * Allows users to use .format("secured-parquet")
   */
  override def shortName(): String = "secured-parquet"
}
