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

//! Instrumented wrapper for ParquetFileReaderFactory. Logs every
//! create_reader / get_metadata / get_bytes / get_byte_ranges call to stdout
//! with file path, byte counts, ranges, timing, and page index presence.
//!
//! Each log line is prefixed with [COMET-INSTRUMENT] for easy grepping in
//! Spark executor stdout. A per-reader sequence number lets you tie multiple
//! calls back to the same reader instance.

use bytes::Bytes;
use datafusion::common::Result as DataFusionResult;
use datafusion::datasource::physical_plan::parquet::ParquetFileReaderFactory;
use datafusion::physical_plan::metrics::ExecutionPlanMetricsSet;
use datafusion_datasource::PartitionedFile;
use futures::future::BoxFuture;
use futures::FutureExt;
use object_store::path::Path;
use parquet::arrow::arrow_reader::ArrowReaderOptions;
use parquet::arrow::async_reader::AsyncFileReader;
use parquet::file::metadata::ParquetMetaData;
use std::fmt::Debug;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

static READER_SEQ: AtomicU64 = AtomicU64::new(0);
static FACTORY_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct InstrumentedReaderFactory {
    inner: Arc<dyn ParquetFileReaderFactory>,
    factory_id: u64,
}

impl InstrumentedReaderFactory {
    pub fn new(inner: Arc<dyn ParquetFileReaderFactory>) -> Self {
        let factory_id = FACTORY_SEQ.fetch_add(1, Ordering::Relaxed);
        println!("[COMET-INSTRUMENT] factory_create id={factory_id}");
        Self { inner, factory_id }
    }
}

impl ParquetFileReaderFactory for InstrumentedReaderFactory {
    fn create_reader(
        &self,
        partition_index: usize,
        partitioned_file: PartitionedFile,
        metadata_size_hint: Option<usize>,
        metrics: &ExecutionPlanMetricsSet,
    ) -> DataFusionResult<Box<dyn AsyncFileReader + Send>> {
        let reader_id = READER_SEQ.fetch_add(1, Ordering::Relaxed);
        let location = partitioned_file.object_meta.location.clone();
        let size = partitioned_file.object_meta.size;
        let range = partitioned_file.range.clone();
        println!(
            "[COMET-INSTRUMENT] create_reader reader_id={} factory_id={} partition={} file={} size={} range={:?} hint={:?}",
            reader_id,
            self.factory_id,
            partition_index,
            location,
            size,
            range,
            metadata_size_hint,
        );
        let inner_reader = self.inner.create_reader(
            partition_index,
            partitioned_file,
            metadata_size_hint,
            metrics,
        )?;
        Ok(Box::new(InstrumentedReader {
            inner: inner_reader,
            location,
            reader_id,
            partition_index,
            get_bytes_calls: 0,
            get_byte_ranges_calls: 0,
            get_metadata_calls: 0,
            total_bytes: 0,
            total_ranges: 0,
            created_at: Instant::now(),
        }))
    }
}

struct InstrumentedReader {
    inner: Box<dyn AsyncFileReader + Send>,
    location: Path,
    reader_id: u64,
    partition_index: usize,
    get_bytes_calls: u64,
    get_byte_ranges_calls: u64,
    get_metadata_calls: u64,
    total_bytes: u64,
    total_ranges: u64,
    created_at: Instant,
}

impl Drop for InstrumentedReader {
    fn drop(&mut self) {
        println!(
            "[COMET-INSTRUMENT] reader_drop reader_id={} partition={} file={} lifetime={:?} get_bytes_calls={} get_byte_ranges_calls={} get_metadata_calls={} total_bytes={} total_ranges={}",
            self.reader_id,
            self.partition_index,
            self.location,
            self.created_at.elapsed(),
            self.get_bytes_calls,
            self.get_byte_ranges_calls,
            self.get_metadata_calls,
            self.total_bytes,
            self.total_ranges,
        );
    }
}

impl AsyncFileReader for InstrumentedReader {
    fn get_bytes(&mut self, range: Range<u64>) -> BoxFuture<'_, parquet::errors::Result<Bytes>> {
        let len = range.end - range.start;
        self.get_bytes_calls += 1;
        self.total_bytes += len;
        self.total_ranges += 1;
        let reader_id = self.reader_id;
        let partition_index = self.partition_index;
        let location = self.location.clone();
        let range_clone = range.clone();
        async move {
            let start = Instant::now();
            let result = self.inner.get_bytes(range_clone.clone()).await;
            let elapsed = start.elapsed();
            println!(
                "[COMET-INSTRUMENT] get_bytes reader_id={} partition={} file={} range={}..{} len={} elapsed={:?} ok={}",
                reader_id,
                partition_index,
                location,
                range_clone.start,
                range_clone.end,
                len,
                elapsed,
                result.is_ok(),
            );
            result
        }
        .boxed()
    }

    fn get_byte_ranges(
        &mut self,
        ranges: Vec<Range<u64>>,
    ) -> BoxFuture<'_, parquet::errors::Result<Vec<Bytes>>>
    where
        Self: Send,
    {
        let total: u64 = ranges.iter().map(|r| r.end - r.start).sum();
        let num_ranges = ranges.len();
        self.get_byte_ranges_calls += 1;
        self.total_bytes += total;
        self.total_ranges += num_ranges as u64;
        let reader_id = self.reader_id;
        let partition_index = self.partition_index;
        let location = self.location.clone();
        // Capture min/max range size for diagnostic
        let min_range = ranges.iter().map(|r| r.end - r.start).min().unwrap_or(0);
        let max_range = ranges.iter().map(|r| r.end - r.start).max().unwrap_or(0);
        // Detect non-contiguous ranges (gaps between consecutive sorted ranges)
        let mut sorted = ranges.clone();
        sorted.sort_by_key(|r| r.start);
        let mut max_gap: u64 = 0;
        let mut total_gap: u64 = 0;
        for w in sorted.windows(2) {
            if w[1].start > w[0].end {
                let g = w[1].start - w[0].end;
                max_gap = max_gap.max(g);
                total_gap += g;
            }
        }
        async move {
            let start = Instant::now();
            let result = self.inner.get_byte_ranges(ranges).await;
            let elapsed = start.elapsed();
            println!(
                "[COMET-INSTRUMENT] get_byte_ranges reader_id={} partition={} file={} num_ranges={} total_bytes={} min_range={} max_range={} total_gap={} max_gap={} elapsed={:?} ok={}",
                reader_id,
                partition_index,
                location,
                num_ranges,
                total,
                min_range,
                max_range,
                total_gap,
                max_gap,
                elapsed,
                result.is_ok(),
            );
            result
        }
        .boxed()
    }

    fn get_metadata<'a>(
        &'a mut self,
        options: Option<&'a ArrowReaderOptions>,
    ) -> BoxFuture<'a, parquet::errors::Result<Arc<ParquetMetaData>>> {
        self.get_metadata_calls += 1;
        let reader_id = self.reader_id;
        let partition_index = self.partition_index;
        let location = self.location.clone();
        async move {
            let start = Instant::now();
            let result = self.inner.get_metadata(options).await;
            let elapsed = start.elapsed();
            match &result {
                Ok(metadata) => {
                    let has_column_index = metadata.column_index().is_some();
                    let has_offset_index = metadata.offset_index().is_some();
                    let num_row_groups = metadata.num_row_groups();
                    let num_columns = metadata
                        .file_metadata()
                        .schema_descr()
                        .num_columns();
                    let total_compressed: i64 = metadata
                        .row_groups()
                        .iter()
                        .map(|rg| rg.compressed_size())
                        .sum();
                    println!(
                        "[COMET-INSTRUMENT] get_metadata reader_id={} partition={} file={} elapsed={:?} num_row_groups={} num_columns={} has_column_index={} has_offset_index={} total_compressed={}",
                        reader_id,
                        partition_index,
                        location,
                        elapsed,
                        num_row_groups,
                        num_columns,
                        has_column_index,
                        has_offset_index,
                        total_compressed,
                    );
                }
                Err(e) => {
                    println!(
                        "[COMET-INSTRUMENT] get_metadata reader_id={} partition={} file={} elapsed={:?} error={}",
                        reader_id,
                        partition_index,
                        location,
                        elapsed,
                        e,
                    );
                }
            }
            result
        }
        .boxed()
    }
}
