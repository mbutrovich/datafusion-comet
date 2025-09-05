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
use crate::jvm_bridge::JVMClasses;
use crate::parquet::parquet_support::SparkParquetOptions;
use crate::parquet::schema_adapter::SparkSchemaAdapterFactory;
use arrow::datatypes::{Field, SchemaRef};
use datafusion::common::extensions_options;
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
use datafusion::prelude::SessionContext;
use datafusion::scalar::ScalarValue;
use datafusion_comet_spark_expr::EvalMode;
use itertools::Itertools;
use object_store::path::Path;
use parquet::encryption::decrypt::{FileDecryptionProperties, KeyRetriever};
use parquet::encryption::encrypt::FileEncryptionProperties;
use parquet::errors::ParquetError;
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub is_footer_key: bool,
    pub kms_instance_id: Option<String>,
    pub kms_instance_url: Option<String>,
    pub master_key_id: String,
    pub is_double_wrapped: bool,
    pub kek_id: Option<String>,
    pub encoded_wrapped_kek: Option<String>,
    pub encoded_wrapped_dek: String,
}

impl KeyMaterial {
    pub fn parse(json_str: &str) -> Result<Self, ParquetError> {
        let map: HashMap<String, serde_json::Value> =
            serde_json::from_str(json_str).map_err(|e| {
                ParquetError::General(format!("Failed to parse key material JSON: {}", e))
            })?;
        println!("map {:?}", map);
        Self::parse_from_map(&map)
    }

    pub fn parse_from_map(map: &HashMap<String, serde_json::Value>) -> Result<Self, ParquetError> {
        let get_string = |key: &str| -> Result<String, ParquetError> {
            map.get(key)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| ParquetError::General(format!("Missing or invalid field: {}", key)))
        };

        let get_optional_string = |key: &str| -> Option<String> {
            map.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
        };

        let get_bool =
            |key: &str| -> bool { map.get(key).and_then(|v| v.as_bool()).unwrap_or(false) };

        let is_footer_key = get_bool("isFooterKey");
        let kms_instance_id = get_optional_string("kmsInstanceID");
        let kms_instance_url = get_optional_string("kmsInstanceURL");
        let master_key_id = get_string("masterKeyID")?;
        let is_double_wrapped = get_bool("doubleWrapping");
        let kek_id = get_optional_string("keyEncryptionKeyID");
        let encoded_wrapped_kek = get_optional_string("wrappedKEK");
        let encoded_wrapped_dek = get_string("wrappedDEK")?;

        if is_double_wrapped && (kek_id.is_none() || encoded_wrapped_kek.is_none()) {
            return Err(ParquetError::General(
                "Double wrapped key material requires keyEncryptionKeyID and wrappedKEK"
                    .to_string(),
            ));
        }

        Ok(KeyMaterial {
            is_footer_key,
            kms_instance_id,
            kms_instance_url,
            master_key_id,
            is_double_wrapped,
            kek_id,
            encoded_wrapped_kek,
            encoded_wrapped_dek,
        })
    }
}

#[derive(Debug)]
pub struct KeyMetadata {
    pub is_internal_storage: bool,
    pub key_reference: Option<String>,
    pub key_material: Option<KeyMaterial>,
}

impl KeyMetadata {
    fn new(
        is_internal_storage: bool,
        key_reference: Option<String>,
        key_material: Option<KeyMaterial>,
    ) -> Self {
        if is_internal_storage {
            assert!(key_material.is_some() && key_reference.is_none());
        } else {
            assert!(key_material.is_none() && key_reference.is_some());
        }
        KeyMetadata {
            is_internal_storage,
            key_reference,
            key_material,
        }
    }

    pub fn parse(key_metadata_bytes: &[u8]) -> Result<Self, ParquetError> {
        let metadata_str = std::str::from_utf8(key_metadata_bytes)
            .map_err(|e| ParquetError::General(format!("Invalid UTF-8 in key metadata: {}", e)))?;

        let map: HashMap<String, serde_json::Value> =
            serde_json::from_str(metadata_str).map_err(|e| {
                ParquetError::General(format!("Failed to parse key metadata JSON: {}", e))
            })?;

        let get_bool =
            |key: &str| -> bool { map.get(key).and_then(|v| v.as_bool()).unwrap_or(false) };

        let get_optional_string = |key: &str| -> Option<String> {
            map.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
        };

        let is_internal_storage = get_bool("internalStorage");

        if is_internal_storage {
            let key_material = KeyMaterial::parse_from_map(&map)?;
            Ok(KeyMetadata::new(true, None, Some(key_material)))
        } else {
            let key_reference = get_optional_string("keyReference");
            Ok(KeyMetadata::new(false, key_reference, None))
        }
    }

    pub fn get_key_material(&self) -> Option<&KeyMaterial> {
        self.key_material.as_ref()
    }
}

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
    session_ctx: &Arc<SessionContext>,
) -> Result<Arc<DataSourceExec>, ExecutionError> {
    let (table_parquet_options, spark_parquet_options) =
        get_options(session_timezone, case_sensitive);

    let mut parquet_source = ParquetSource::new(table_parquet_options);

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

    parquet_source = parquet_source.with_encryption_factory(
        session_ctx
            .runtime_env()
            .parquet_encryption_factory(ENCRYPTION_FACTORY_ID)?,
    );

    let file_source = parquet_source.with_schema_adapter_factory(Arc::new(
        SparkSchemaAdapterFactory::new(spark_parquet_options, default_values),
    ))?;

    let file_groups = file_groups
        .iter()
        .map(|files| FileGroup::new(files.clone()))
        .collect();

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

    Ok(Arc::new(DataSourceExec::new(Arc::new(file_scan_config))))
}

pub const ENCRYPTION_FACTORY_ID: &str = "comet.jni_kms_encryption";

// Options used to configure our example encryption factory
extensions_options! {
    struct CometParquetEncryptionConfig {
    }
}
#[derive(Default, Debug)]
pub struct TestEncryptionFactory {}

/// `EncryptionFactory` is a DataFusion trait for types that generate
/// file encryption and decryption properties.
impl EncryptionFactory for TestEncryptionFactory {
    fn get_file_encryption_properties(
        &self,
        _options: &EncryptionFactoryOptions,
        _schema: &SchemaRef,
        _file_path: &Path,
    ) -> Result<Option<FileEncryptionProperties>, DataFusionError> {
        Err(DataFusionError::NotImplemented(
            "Comet does not support Parquet encryption yet."
                .parse()
                .unwrap(),
        ))
    }

    /// Generate file decryption properties to use when reading a Parquet file.
    /// Rather than provide the AES keys directly for decryption, we set a `KeyRetriever`
    /// that can determine the keys using the encryption metadata.
    fn get_file_decryption_properties(
        &self,
        _options: &EncryptionFactoryOptions,
        file_path: &Path,
    ) -> Result<Option<FileDecryptionProperties>, DataFusionError> {
        let decryption_properties =
            FileDecryptionProperties::with_key_retriever(Arc::new(TestKeyRetriever {
                file_path: file_path.to_string(),
            }))
            .build()?;
        Ok(Some(decryption_properties))
    }
}

struct TestKeyRetriever {
    file_path: String,
}

impl KeyRetriever for TestKeyRetriever {
    /// Get a data encryption key using the metadata stored in the Parquet file.
    fn retrieve_key(&self, key_metadata: &[u8]) -> datafusion::parquet::errors::Result<Vec<u8>> {
        // Get JNI environment
        let mut env = JVMClasses::get_env().unwrap();

        // Convert key_metadata to JByteArray
        let key_metadata_array = env.byte_array_from_slice(key_metadata).unwrap();

        // Convert file_path to JString
        let file_path_jstring = env.new_string(&self.file_path).unwrap();

        // Get the CometFileKeyUnwrapper class and method
        let jvm_classes = JVMClasses::get();
        let file_key_unwrapper = &jvm_classes.file_key_unwrapper;

        // Call static method CometFileKeyUnwrapper.getKey(byte[], String) -> byte[]
        let result = unsafe {
            env.call_static_method_unchecked(
                &file_key_unwrapper.class,
                file_key_unwrapper.method_get_key,
                file_key_unwrapper.method_get_key_ret.clone(),
                &[
                    jni::objects::JValue::from(&key_metadata_array).as_jni(),
                    jni::objects::JValue::from(&file_path_jstring).as_jni(),
                ],
            )
        };

        let result = result.unwrap();

        // Extract the byte array from the result
        let result_array = result.l().unwrap();

        // Convert JObject to JByteArray and then to Vec<u8>
        let byte_array: jni::objects::JByteArray = result_array.into();

        let result_vec = env.convert_byte_array(&byte_array).unwrap();
        Ok(result_vec)
    }
}

fn get_options(
    session_timezone: &str,
    case_sensitive: bool,
) -> (TableParquetOptions, SparkParquetOptions) {
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

    table_parquet_options.crypto.configure_factory(
        ENCRYPTION_FACTORY_ID,
        &CometParquetEncryptionConfig::default(),
    );

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
