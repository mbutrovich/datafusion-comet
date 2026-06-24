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

//! Instrumented ObjectStore wrapper. Logs every get_opts / get_ranges call below
//! the reader layer with byte counts, range counts, latency, and a per-call
//! sequence number. Lines prefixed [COMET-OS] for grepping.
//!
//! This catches the metadata-loading I/O path that bypasses the AsyncFileReader
//! wrapper (DFParquetMetadata::fetch_metadata reads via ObjectStore::get_ranges
//! directly).

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMultipartOpts, PutOptions, PutPayload, PutResult, Result,
};
use std::fmt::{Debug, Display, Formatter};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

static OS_CALL_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct InstrumentedObjectStore {
    inner: Arc<dyn ObjectStore>,
}

impl InstrumentedObjectStore {
    pub fn new(inner: Arc<dyn ObjectStore>) -> Self {
        Self { inner }
    }
}

impl Display for InstrumentedObjectStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "InstrumentedObjectStore({})", self.inner)
    }
}

#[async_trait]
impl ObjectStore for InstrumentedObjectStore {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> Result<PutResult> {
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOpts,
    ) -> Result<Box<dyn MultipartUpload>> {
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> Result<GetResult> {
        let call_id = OS_CALL_SEQ.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        let range = options.range.clone();
        let result = self.inner.get_opts(location, options).await;
        let elapsed = start.elapsed();
        let (ok, len) = match &result {
            Ok(r) => (true, Some(r.meta.size)),
            Err(_) => (false, None),
        };
        println!(
            "[COMET-OS] get_opts call_id={} file={} range={:?} elapsed={:?} ok={} reported_len={:?}",
            call_id, location, range, elapsed, ok, len,
        );
        result
    }

    async fn get_ranges(&self, location: &Path, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        let call_id = OS_CALL_SEQ.fetch_add(1, Ordering::Relaxed);
        let num_ranges = ranges.len();
        let total: u64 = ranges.iter().map(|r| r.end - r.start).sum();
        let min_range = ranges.iter().map(|r| r.end - r.start).min().unwrap_or(0);
        let max_range = ranges.iter().map(|r| r.end - r.start).max().unwrap_or(0);
        let mut sorted: Vec<Range<u64>> = ranges.to_vec();
        sorted.sort_by_key(|r| r.start);
        let mut total_gap: u64 = 0;
        let mut max_gap: u64 = 0;
        for w in sorted.windows(2) {
            if w[1].start > w[0].end {
                let g = w[1].start - w[0].end;
                total_gap += g;
                max_gap = max_gap.max(g);
            }
        }
        let start = Instant::now();
        let result = self.inner.get_ranges(location, ranges).await;
        let elapsed = start.elapsed();
        println!(
            "[COMET-OS] get_ranges call_id={} file={} num_ranges={} total_bytes={} min_range={} max_range={} total_gap={} max_gap={} elapsed={:?} ok={}",
            call_id,
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

    fn delete_stream(
        &self,
        locations: BoxStream<'static, Result<Path>>,
    ) -> BoxStream<'static, Result<Path>> {
        self.inner.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, Result<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> Result<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(&self, from: &Path, to: &Path, options: CopyOptions) -> Result<()> {
        self.inner.copy_opts(from, to, options).await
    }
}
