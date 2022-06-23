// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use super::Node;
use crate::metrics::{NODE_CACHE_HIT, NODE_CACHE_TOTAL};
use aptos_infallible::Mutex;
use aptos_jellyfish_merkle::node_type::NodeKey;
use aptos_types::{nibble::nibble_path::NibblePath, transaction::Version};
use cpu_time::ThreadTime;
use lru::LruCache;
use std::time::Instant;

use once_cell::sync::Lazy;

use aptos_metrics_core::{register_histogram, Histogram};

const NUM_SHARDS: usize = 256;

pub static READ_LOCK_TIME: Lazy<Histogram> =
    Lazy::new(|| register_histogram!("jmt_lru_read_lock_time", "JMT lru read lock time.").unwrap());
pub static READ_CACHE_TIME: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!("jmt_lru_read_cache_time", "JMT lru read cache time.").unwrap()
});
pub static READ_CACHE_CPU_TIME: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "jmt_lru_read_cache_cpu_time",
        "JMT lru read cache cpu time."
    )
    .unwrap()
});
pub static WRITE_LOCK_TIME: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!("jmt_lru_write_lock_time", "JMT lru write lock time.").unwrap()
});

#[derive(Debug)]
pub(crate) struct LruNodeCache {
    shards: [Mutex<LruCache<NibblePath, (Version, Node)>>; NUM_SHARDS],
}

impl LruNodeCache {
    pub fn new(max_nodes_per_shard: usize) -> Self {
        Self {
            // `arr!()` doesn't allow a const in place of the integer literal
            shards: arr_macro::arr![Mutex::new(LruCache::new(max_nodes_per_shard)); 256],
        }
    }

    fn shard(nibble_path: &NibblePath) -> u8 {
        let path_bytes = nibble_path.bytes();
        if path_bytes.is_empty() {
            0
        } else {
            path_bytes[0]
        }
    }

    pub fn get(&self, node_key: &NodeKey) -> Option<Node> {
        let mut t = Instant::now();
        //NODE_CACHE_TOTAL.with_label_values(&["position_lru"]).inc();
        let mut r = self.shards[Self::shard(node_key.nibble_path()) as usize].lock();
        READ_LOCK_TIME.observe(t.elapsed().as_secs_f64() * 1000000000.0);
        if READ_LOCK_TIME.get_sample_count().checked_rem(65536) == Some(0) {
            println!(
                "read_lock: {}, write_lock: {}, cache_latency: {}, cache_cpu_time: {}, len: {}",
                READ_LOCK_TIME.get_sample_sum() / READ_LOCK_TIME.get_sample_count() as f64,
                WRITE_LOCK_TIME.get_sample_sum() / WRITE_LOCK_TIME.get_sample_count() as f64,
                READ_CACHE_TIME.get_sample_sum() / READ_CACHE_TIME.get_sample_count() as f64,
                READ_CACHE_CPU_TIME.get_sample_sum()
                    / READ_CACHE_CPU_TIME.get_sample_count() as f64,
                r.len(),
            );
        }
        t = Instant::now();
        let tt = ThreadTime::now();
        let ret = r.get(node_key.nibble_path()).and_then(|(version, node)| {
            if *version == node_key.version() {
                //NODE_CACHE_HIT.with_label_values(&["position_lru"]).inc();
                Some(node.clone())
            } else {
                None
            }
        });
        READ_CACHE_TIME.observe(t.elapsed().as_secs_f64() * 1000000000.0);
        READ_CACHE_CPU_TIME.observe(tt.elapsed().as_secs_f64() * 1000000000.0);
        ret
    }

    pub fn put(&self, node_key: NodeKey, node: Node) {
        let t = Instant::now();
        let (version, nibble_path) = node_key.unpack();
        let mut w = self.shards[Self::shard(&nibble_path) as usize].lock();
        WRITE_LOCK_TIME.observe(t.elapsed().as_secs_f64() * 1000000000.0);
        let value = (version, node);
        w.put(nibble_path, value);
    }
}
