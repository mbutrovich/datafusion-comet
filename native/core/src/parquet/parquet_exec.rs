// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use crate::execution::operators::ExecutionError;
use crate::parquet::parquet_support::SparkParquetOptions;
use crate::parquet::schema_adapter::SparkSchemaAdapterFactory;
use arrow::datatypes::{Field, SchemaRef};
use base64::Engine;
use datafusion::common::{extensions_options, HashSet};
use datafusion::config::{EncryptionFactoryOptions, TableParquetOptions};
use datafusion::datasource::listing::PartitionedFile;
use datafusion::datasource::physical_plan::{
    FileGroup, FileScanConfigBuilder, FileSource, ParquetSource,
};
use datafusion::datasource::source::DataSourceExec;
use datafusion::error::DataFusionError;
use datafusion::execution::object_store::ObjectStoreUrl;
use datafusion::execution::parquet_encryption::EncryptionFactory;
use datafusion::physical_expr::expressions::BinaryExpr;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::scalar::ScalarValue;
use datafusion_comet_spark_expr::EvalMode;
use itertools::Itertools;
use object_store::path::Path;
use parquet::encryption::decrypt::{FileDecryptionProperties, KeyRetriever};
use parquet::encryption::encrypt::FileEncryptionProperties;
use rand::rand_core::OsRng;
use rand::TryRngCore;
use std::collections::HashMap;
use std::io;
use std::io::Write;
use std::sync::Arc;

/// Initializes a DataSourceExec plan with a ParquetSource. This may be used by either the
/// `native_datafusion` scan or the `native_iceberg_compat` scan.
///
///   `required_schema`: Schema to be projected by the scan.
///
///   `data_schema`: Schema of the underlying data. It is optional and, if provided, is used
/// instead of `required_schema` to initialize the file scan
///
///   `partition_schema` and `partition_fields` are optional. If `partition_schema` is specified,
/// then `partition_fields` must also be specified
///
///   `object_store_url`: Url to read data from
///
///   `file_groups`: A collection of groups of `PartitionedFiles` that are to be read by the scan
///
///   `projection_vector`: A vector of the indexes in the schema of the fields to be projected
///
///   `data_filters`: Any predicate that must be applied to the data returned by the scan. If
/// specified, then `data_schema` must also be specified.
#[allow(clippy::too_many_arguments)]
pub(crate) fn init_datasource_exec(
    required_schema: SchemaRef,
    data_schema: Option<SchemaRef>,
    partition_schema: Option<SchemaRef>,
    partition_fields: Option<Vec<Field>>,
    object_store_url: ObjectStoreUrl,
    file_groups: Vec<Vec<PartitionedFile>>,
    projection_vector: Option<Vec<usize>>,
    data_filters: Option<Vec<Arc<dyn PhysicalExpr>>>,
    default_values: Option<HashMap<usize, ScalarValue>>,
    session_timezone: &str,
    case_sensitive: bool,
) -> Result<Arc<DataSourceExec>, ExecutionError> {
    println!("init_datasource_exec");
    io::stdout().flush().expect("Failed to flush stdout");
    let (table_parquet_options, spark_parquet_options) =
        get_options(session_timezone, case_sensitive);
    let mut parquet_source = ParquetSource::new(table_parquet_options);

    println!("init_datasource_exec2");
    io::stdout().flush().expect("Failed to flush stdout");

    // Create a conjunctive form of the vector because ParquetExecBuilder takes
    // a single expression
    if let Some(data_filters) = data_filters {
        let cnf_data_filters = data_filters.clone().into_iter().reduce(|left, right| {
            Arc::new(BinaryExpr::new(
                left,
                datafusion::logical_expr::Operator::And,
                right,
            ))
        });

        if let Some(filter) = cnf_data_filters {
            parquet_source = parquet_source.with_predicate(filter);
        }
    }

    println!("init_datasource_exec3");
    io::stdout().flush().expect("Failed to flush stdout");

    let file_source = parquet_source.with_schema_adapter_factory(Arc::new(
        SparkSchemaAdapterFactory::new(spark_parquet_options, default_values),
    ))?;

    let file_groups = file_groups
        .iter()
        .map(|files| FileGroup::new(files.clone()))
        .collect();

    println!("init_datasource_exec4");
    io::stdout().flush().expect("Failed to flush stdout");

    let file_scan_config = match (data_schema, projection_vector, partition_fields) {
        (Some(data_schema), Some(projection_vector), Some(partition_fields)) => {
            get_file_config_builder(
                data_schema,
                partition_schema,
                file_groups,
                object_store_url,
                file_source,
            )
            .with_projection(Some(projection_vector))
            .with_table_partition_cols(partition_fields)
            .build()
        }
        _ => get_file_config_builder(
            required_schema,
            partition_schema,
            file_groups,
            object_store_url,
            file_source,
        )
        .build(),
    };

    println!("init_datasource_exec5");
    io::stdout().flush().expect("Failed to flush stdout");

    println!("file_scan_config: {:#?}", file_scan_config);
    io::stdout().flush().expect("Failed to flush stdout");

    Ok(Arc::new(DataSourceExec::new(Arc::new(file_scan_config))))
}

// struct CustomKeyRetriever {
//     keys: Mutex<HashMap<String, Vec<u8>>>,
// }
//
// impl KeyRetriever for CustomKeyRetriever {
//     fn retrieve_key(&self, key_metadata: &[u8]) -> parquet::errors::Result<Vec<u8>> {
//         // Metadata is bytes, so convert it to a string identifier
//         let key_metadata = std::str::from_utf8(key_metadata).map_err(|e| {
//             ParquetError::General(format!("Could not convert key metadata to string: {e}"))
//         })?;
//         println!("retrieve_key: {:?}", key_metadata);
//         // Lookup the key
//         let keys = self.keys.lock().unwrap();
//         match keys.get(key_metadata) {
//             Some(key) => Ok(key.clone()),
//             None => Err(ParquetError::General(format!(
//                 "Could not retrieve key for metadata {key_metadata:?}"
//             ))),
//         }
//     }
// }

pub const ENCRYPTION_FACTORY_ID: &str = "example.mock_kms_encryption";

// Options used to configure our example encryption factory
extensions_options! {
    struct EncryptionConfig {
        /// Comma-separated list of columns to encrypt
        pub encrypted_columns: String, default = "".to_owned()
    }
}

/// Mock implementation of an `EncryptionFactory` that stores encryption keys
/// base64 encoded in the Parquet encryption metadata.
/// For production use, integrating with a key-management service to encrypt
/// data encryption keys is recommended.
#[derive(Default, Debug)]
pub struct TestEncryptionFactory {}

/// `EncryptionFactory` is a DataFusion trait for types that generate
/// file encryption and decryption properties.
impl EncryptionFactory for TestEncryptionFactory {
    /// Generate file encryption properties to use when writing a Parquet file.
    /// The `schema` is provided so that it may be used to dynamically configure
    /// per-column encryption keys.
    /// The file path is also available. We don't use the path in this example,
    /// but other implementations may want to use this to compute an
    /// AAD prefix for the file, or to allow use of external key material
    /// (where key metadata is stored in a JSON file alongside Parquet files).
    fn get_file_encryption_properties(
        &self,
        options: &EncryptionFactoryOptions,
        schema: &SchemaRef,
        _file_path: &Path,
    ) -> Result<Option<FileEncryptionProperties>, DataFusionError> {
        println!("get_file_encryption_properties");
        io::stdout().flush().expect("Failed to flush stdout");
        let config: EncryptionConfig = options.to_extension_options()?;

        // Generate a random encryption key for this file.
        let mut key = vec![0u8; 16];
        OsRng.try_fill_bytes(&mut key).unwrap();

        // Generate the key metadata that allows retrieving the key when reading the file.
        let key_metadata = wrap_key(&key);

        let mut builder = FileEncryptionProperties::builder(key.to_vec())
            .with_footer_key_metadata(key_metadata.clone());

        let encrypted_columns: HashSet<&str> = config.encrypted_columns.split(",").collect();
        if !encrypted_columns.is_empty() {
            // Set up per-column encryption.
            for field in schema.fields().iter() {
                if encrypted_columns.contains(field.name().as_str()) {
                    // Here we re-use the same key for all encrypted columns,
                    // but new keys could also be generated per column.
                    builder = builder.with_column_key_and_metadata(
                        field.name().as_str(),
                        key.clone(),
                        key_metadata.clone(),
                    );
                }
            }
        }

        let encryption_properties = builder.build()?;

        Ok(Some(encryption_properties))
    }

    /// Generate file decryption properties to use when reading a Parquet file.
    /// Rather than provide the AES keys directly for decryption, we set a `KeyRetriever`
    /// that can determine the keys using the encryption metadata.
    fn get_file_decryption_properties(
        &self,
        _options: &EncryptionFactoryOptions,
        _file_path: &Path,
    ) -> Result<Option<FileDecryptionProperties>, DataFusionError> {
        println!("get_file_decryption_properties");
        io::stdout().flush().expect("Failed to flush stdout");
        let decryption_properties =
            FileDecryptionProperties::with_key_retriever(Arc::new(TestKeyRetriever {})).build()?;
        Ok(Some(decryption_properties))
    }
}

/// Mock implementation of encrypting a key that simply base64 encodes the key.
/// Note that this is not a secure way to store encryption keys,
/// and for production use keys should be encrypted with a KMS.
fn wrap_key(key: &[u8]) -> Vec<u8> {
    println!("wrap_key");
    io::stdout().flush().expect("Failed to flush stdout");
    base64::prelude::BASE64_STANDARD
        .encode(key)
        .as_bytes()
        .to_vec()
}

struct TestKeyRetriever {}

impl KeyRetriever for TestKeyRetriever {
    /// Get a data encryption key using the metadata stored in the Parquet file.
    fn retrieve_key(&self, key_metadata: &[u8]) -> datafusion::parquet::errors::Result<Vec<u8>> {
        println!("retrieve_key");
        io::stdout().flush().expect("Failed to flush stdout");
        let key_metadata = std::str::from_utf8(key_metadata)?;
        let key = base64::prelude::BASE64_STANDARD
            .decode(key_metadata)
            .unwrap();
        Ok(key)
    }
}

fn get_options(
    session_timezone: &str,
    case_sensitive: bool,
) -> (TableParquetOptions, SparkParquetOptions) {
    println!("get_options");
    io::stdout().flush().expect("Failed to flush stdout");
    let mut table_parquet_options = TableParquetOptions::new();
    table_parquet_options.global.pushdown_filters = true;
    table_parquet_options.global.reorder_filters = true;
    table_parquet_options.global.coerce_int96 = Some("us".to_string());
    let mut spark_parquet_options =
        SparkParquetOptions::new(EvalMode::Legacy, session_timezone, false);
    spark_parquet_options.allow_cast_unsigned_ints = true;
    spark_parquet_options.case_sensitive = case_sensitive;

    // let mut keys = HashMap::new();
    // keys.insert("kf".to_owned(), b"0123456789012345".to_vec());
    // keys.insert("kc1".to_owned(), b"1234567890123450".to_vec());
    // keys.insert("kc2".to_owned(), b"1234567890123451".to_vec());
    //
    // let key_retriever = Arc::new(CustomKeyRetriever {
    //     keys: Mutex::new(keys),
    // });

    // let decryption_properties =
    //     FileDecryptionProperties::with_key_retriever(key_retriever)
    //         .build()
    //         .unwrap();

    // table_parquet_options.crypto.file_decryption =
    //     Some(ConfigFileDecryptionProperties::from(&decryption_properties));

    table_parquet_options
        .crypto
        .configure_factory(ENCRYPTION_FACTORY_ID, &EncryptionConfig::default());

    (table_parquet_options, spark_parquet_options)
}

fn get_file_config_builder(
    schema: SchemaRef,
    partition_schema: Option<SchemaRef>,
    file_groups: Vec<FileGroup>,
    object_store_url: ObjectStoreUrl,
    file_source: Arc<dyn FileSource>,
) -> FileScanConfigBuilder {
    match partition_schema {
        Some(partition_schema) => {
            let partition_fields: Vec<Field> = partition_schema
                .fields()
                .iter()
                .map(|field| {
                    Field::new(field.name(), field.data_type().clone(), field.is_nullable())
                })
                .collect_vec();
            FileScanConfigBuilder::new(object_store_url, Arc::clone(&schema), file_source)
                .with_file_groups(file_groups)
                .with_table_partition_cols(partition_fields)
        }
        _ => FileScanConfigBuilder::new(object_store_url, Arc::clone(&schema), file_source)
            .with_file_groups(file_groups),
    }
}
