use core::ops::Deref as _;
use std_shims::{vec, vec::Vec, collections::HashMap};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use ahash::RandomState;

#[cfg(feature = "compile-time-generators")]
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
#[cfg(not(feature = "compile-time-generators"))]
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as ED25519_BASEPOINT_TABLE;

use monero_oxide::{
  ed25519::{Commitment, CompressedPoint, Point, Scalar},
  transaction::{Pruned, Timelock, Transaction},
};
use monero_interface::ScannableBlock;
use crate::{
  address::SubaddressIndex, output::*, Extra, GuaranteedViewPair, PaymentId, SharedKeyDerivations,
  ViewPair,
};

#[cfg(feature = "scanner-microprof")]
/// Snapshot of scanner micro-profiler counters/timers.
///
/// This is intended for performance diagnostics of wallet scanning. All values are best-effort and
/// are aggregated across the process.
///
/// Units:
/// - counters are raw event counts
/// - `ns_*` fields are elapsed nanoseconds accumulated across calls
#[derive(Clone, Copy, Debug, Default)]
pub struct ScannerMicroprofSnapshot {
  /// Number of `ScannableBlock`s scanned.
  pub blocks: u64,
  /// Number of v2 transactions passed through `scan_transaction` (i.e., "actually scanned").
  pub txs_scanned: u64,
  /// Number of outputs iterated over (visited) during scanning.
  pub outputs_visited: u64,
  /// Number of ECDH derivations attempted (per output, per candidate tx key).
  pub ecdh_derivations: u64,
  /// Number of view-tag mismatches encountered (early reject path).
  pub viewtag_mismatch: u64,
  /// Number of commitment verification attempts performed.
  pub commitment_verify_attempts: u64,
  /// Number of commitment verification failures (mismatches).
  pub commitment_verify_fail: u64,
  /// Number of outputs matched to this wallet.
  pub outputs_matched: u64,
  /// Number of failures to parse the transaction `extra` field.
  pub extra_parse_fail: u64,
  /// Number of transactions where no tx keys were found in `extra`.
  pub tx_keys_missing: u64,
  /// Number of ECDH cache hits (ECDH was reused from the per-tx cache).
  pub ecdh_cache_hits: u64,
  /// Number of ECDH cache misses (ECDH had to be computed and inserted into the per-tx cache).
  pub ecdh_cache_misses: u64,
  /// Accumulated nanoseconds spent in per-block setup (tx list construction, basic checks).
  pub ns_block_setup: u64,
  /// Accumulated nanoseconds spent inside `scan_transaction` (all work within it).
  pub ns_scan_transaction: u64,
  /// Accumulated nanoseconds spent in commitment verification work.
  pub ns_commitment_verify: u64,
  /// Accumulated nanoseconds spent computing ECDH (view_scalar * tx_pub_key) scalar mul.
  pub ns_ecdh_mul: u64,
  /// Accumulated nanoseconds spent doing HashMap lookup for the ECDH cache on cache hits.
  pub ns_ecdh_cache_lookup_hit: u64,
  /// Accumulated nanoseconds spent doing HashMap lookup + insertion bookkeeping for the ECDH cache on cache misses.
  /// This does *not* include the scalar multiplication time tracked by `ns_ecdh_mul`.
  pub ns_ecdh_cache_lookup_miss: u64,
  /// Accumulated nanoseconds spent computing `SharedKeyDerivations::output_derivations(...)`.
  pub ns_output_derivations: u64,
  /// Accumulated nanoseconds spent computing the subaddress spend key and performing the map lookup.
  pub ns_subaddress_lookup: u64,
}

#[cfg(feature = "scanner-microprof")]
/// Return a snapshot of scanner micro-profiler counters/timers.
///
/// This API is only compiled when the `scanner-microprof` feature is enabled.
///
/// The profiler is additionally gated at runtime by the `MONERO_WALLET_SCANNER_MICROPROF` env var:
/// - if the env var is not set to a non-zero value, this returns `None`.
///
/// If `reset` is `true`, counters are atomically reset to `0` as part of snapshotting.
pub fn scanner_microprof_snapshot(reset: bool) -> Option<ScannerMicroprofSnapshot> {
  if !microprof_enabled() {
    return None;
  }

  let take = |a: &AtomicU64| -> u64 {
    if reset {
      a.swap(0, Ordering::Relaxed)
    } else {
      a.load(Ordering::Relaxed)
    }
  };

  Some(ScannerMicroprofSnapshot {
    blocks: take(&MP_BLOCKS),
    txs_scanned: take(&MP_TXS_SCANNED),
    outputs_visited: take(&MP_OUTPUTS_VISITED),
    ecdh_derivations: take(&MP_ECDH_DERIVATIONS),
    viewtag_mismatch: take(&MP_VIEWTAG_MISMATCH),
    commitment_verify_attempts: take(&MP_COMMITMENT_VERIFY_ATTEMPTS),
    commitment_verify_fail: take(&MP_COMMITMENT_VERIFY_FAIL),
    outputs_matched: take(&MP_OUTPUTS_MATCHED),
    extra_parse_fail: take(&MP_EXTRA_PARSE_FAIL),
    tx_keys_missing: take(&MP_TX_KEYS_MISSING),
    ecdh_cache_hits: take(&MP_ECDH_CACHE_HITS),
    ecdh_cache_misses: take(&MP_ECDH_CACHE_MISSES),
    ns_block_setup: take(&MP_NS_BLOCK_SETUP),
    ns_scan_transaction: take(&MP_NS_SCAN_TRANSACTION),
    ns_commitment_verify: take(&MP_NS_COMMITMENT_VERIFY),
    ns_ecdh_mul: take(&MP_NS_ECDH_MUL),
    ns_ecdh_cache_lookup_hit: take(&MP_NS_ECDH_CACHE_LOOKUP_HIT),
    ns_ecdh_cache_lookup_miss: take(&MP_NS_ECDH_CACHE_LOOKUP_MISS),
    ns_output_derivations: take(&MP_NS_OUTPUT_DERIVATIONS),
    ns_subaddress_lookup: take(&MP_NS_SUBADDRESS_LOOKUP),
  })
}

#[cfg(feature = "scanner-microprof")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(feature = "scanner-microprof")]
use once_cell::sync::Lazy;

#[cfg(feature = "scanner-microprof")]
static SCANNER_MICROPROF_ENABLED: Lazy<AtomicBool> = Lazy::new(|| {
  let enabled = std::env::var("MONERO_WALLET_SCANNER_MICROPROF")
    .ok()
    .and_then(|s| s.parse::<u8>().ok())
    .map(|v| v != 0)
    .unwrap_or(false);
  AtomicBool::new(enabled)
});

#[cfg(feature = "scanner-microprof")]
#[inline(always)]
fn microprof_enabled() -> bool {
  SCANNER_MICROPROF_ENABLED.load(Ordering::Relaxed)
}

#[cfg(feature = "scanner-microprof")]
static MP_BLOCKS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_TXS_SCANNED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_OUTPUTS_VISITED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_ECDH_DERIVATIONS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_VIEWTAG_MISMATCH: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_COMMITMENT_VERIFY_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_COMMITMENT_VERIFY_FAIL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_OUTPUTS_MATCHED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_EXTRA_PARSE_FAIL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_TX_KEYS_MISSING: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_ECDH_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_ECDH_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "scanner-microprof")]
static MP_NS_BLOCK_SETUP: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_NS_SCAN_TRANSACTION: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_NS_COMMITMENT_VERIFY: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_NS_ECDH_MUL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_NS_ECDH_CACHE_LOOKUP_HIT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_NS_ECDH_CACHE_LOOKUP_MISS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_NS_OUTPUT_DERIVATIONS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "scanner-microprof")]
static MP_NS_SUBADDRESS_LOOKUP: AtomicU64 = AtomicU64::new(0);

/// A collection of potentially additionally timelocked outputs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Timelocked(Vec<WalletOutput>);

impl Timelocked {
  /// Return the outputs which aren't subject to an additional timelock.
  #[must_use]
  pub fn not_additionally_locked(self) -> Vec<WalletOutput> {
    let mut res = vec![];
    for output in &self.0 {
      if output.additional_timelock() == Timelock::None {
        res.push(output.clone());
      }
    }
    res
  }

  /// Return the outputs whose additional timelock unlocks by the specified block/time.
  ///
  /// Additional timelocks are almost never used outside of miner transactions, and are
  /// increasingly planned for removal. Ignoring non-miner additionally-timelocked outputs is
  /// recommended.
  ///
  /// `block` is the block number of the block the additional timelock must be satsified by.
  ///
  /// `time` is represented in seconds since the epoch and is in terms of Monero's on-chain clock.
  /// That means outputs whose additional timelocks are statisfied by `Instant::now()` (the time
  /// according to the local system clock) may still be locked due to variance with Monero's clock.
  #[must_use]
  pub fn additional_timelock_satisfied_by(self, block: usize, time: u64) -> Vec<WalletOutput> {
    let mut res = vec![];
    for output in &self.0 {
      if (output.additional_timelock() <= Timelock::Block(block))
        || (output.additional_timelock() <= Timelock::Time(time))
      {
        res.push(output.clone());
      }
    }
    res
  }

  /// Ignore the timelocks and return all outputs within this container.
  #[must_use]
  pub fn ignore_additional_timelock(mut self) -> Vec<WalletOutput> {
    let mut res = vec![];
    core::mem::swap(&mut self.0, &mut res);
    res
  }
}

/// Errors when scanning a block.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ScanError {
  /// The block was for an unsupported protocol version.
  #[error("unsupported protocol version ({0})")]
  UnsupportedProtocol(u8),
  /// The ScannableBlock was invalid.
  #[error("invalid scannable block ({0})")]
  InvalidScannableBlock(&'static str),
}

#[derive(Clone)]
struct InternalScanner {
  pair: ViewPair,
  guaranteed: bool,
  subaddresses: HashMap<CompressedPoint, Option<SubaddressIndex>>,
}

impl Zeroize for InternalScanner {
  #[expect(clippy::iter_over_hash_type)]
  fn zeroize(&mut self) {
    self.pair.zeroize();
    self.guaranteed.zeroize();

    // This may not be effective, unfortunately
    for (mut key, mut value) in self.subaddresses.drain() {
      key.zeroize();
      value.zeroize();
    }
  }
}
impl Drop for InternalScanner {
  fn drop(&mut self) {
    self.zeroize();
  }
}
impl ZeroizeOnDrop for InternalScanner {}

impl InternalScanner {
  fn new(pair: ViewPair, guaranteed: bool) -> Self {
    let mut subaddresses = HashMap::new();
    subaddresses.insert(pair.spend().compress(), None);
    Self { pair, guaranteed, subaddresses }
  }

  fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
    let (spend, _) = self.pair.subaddress_keys(subaddress);
    self.subaddresses.insert(spend.compress(), Some(subaddress));
  }

  fn scan_transaction(
    &self,
    output_index_for_first_ringct_output: u64,
    tx_hash: [u8; 32],
    tx: &Transaction<Pruned>,
  ) -> Result<Timelocked, ScanError> {
    #[cfg(feature = "scanner-microprof")]
    let t0_scan_tx = std::time::Instant::now();

    // Only scan TXs creating RingCT outputs
    // For the full details on why this check is equivalent, please see the documentation in `scan`
    if tx.version() != 2 {
      #[cfg(feature = "scanner-microprof")]
      {
        if microprof_enabled() {
          // still count it as "tx seen", but not "tx scanned"
          MP_NS_SCAN_TRANSACTION
            .fetch_add(t0_scan_tx.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
      }
      return Ok(Timelocked(vec![]));
    }

    #[cfg(feature = "scanner-microprof")]
    {
      if microprof_enabled() {
        MP_TXS_SCANNED.fetch_add(1, Ordering::Relaxed);
      }
    }

    // Hoist invariants out of the inner loops:
    // - view scalar conversion (used for ECDH)
    // - uniqueness (guaranteed scanner mode) derived from tx inputs
    let dalek_view = Zeroizing::new((*self.pair.view).into());
    let uniqueness = if self.guaranteed {
      Some(SharedKeyDerivations::uniqueness(&tx.prefix().inputs))
    } else {
      None
    };

    // Cache ECDH per tx key:
    // ECDH = view_scalar * tx_pub_key is independent of output index, so compute once per key.
    #[allow(clippy::type_complexity)]
    let mut ecdh_cache: HashMap<CompressedPoint, Zeroizing<Point>, RandomState> =
      HashMap::with_hasher(RandomState::new());

    // Read the extra field
    let Ok(extra) = Extra::read(&mut tx.prefix().extra.as_slice()) else {
      #[cfg(feature = "scanner-microprof")]
      {
        if microprof_enabled() {
          MP_EXTRA_PARSE_FAIL.fetch_add(1, Ordering::Relaxed);
          MP_NS_SCAN_TRANSACTION
            .fetch_add(t0_scan_tx.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
      }
      return Ok(Timelocked(vec![]));
    };

    let Some((tx_keys, additional)) = extra.keys() else {
      #[cfg(feature = "scanner-microprof")]
      {
        if microprof_enabled() {
          MP_TX_KEYS_MISSING.fetch_add(1, Ordering::Relaxed);
          MP_NS_SCAN_TRANSACTION
            .fetch_add(t0_scan_tx.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
      }
      return Ok(Timelocked(vec![]));
    };
    let payment_id = extra.payment_id();

    let mut res = vec![];
    for (o, output) in tx.prefix().outputs.iter().enumerate() {
      #[cfg(feature = "scanner-microprof")]
      {
        if microprof_enabled() {
          MP_OUTPUTS_VISITED.fetch_add(1, Ordering::Relaxed);
        }
      }

      /*
        Explicitly skip keys which are the identity.

        These are theoretically able to be scanned (with negligible probability except for a
        recipient who chooses their keys as to cause this), but are unspendable due to restrictions
        the key image isn't the identity point (in place since the RingCT upgrade).
      */
      if output.key == CompressedPoint::IDENTITY {
        continue;
      }

      let Some(output_key) = output.key.decompress() else { continue };

      // Monero checks with each TX key and with the additional key for this output
      // See notes in original code for Monero's behavior.
      let additional = additional.as_ref().and_then(|additional| additional.get(o));

      for key in tx_keys.iter().map(Some).chain(core::iter::once(additional)).flatten().copied() {
        #[cfg(feature = "scanner-microprof")]
        {
          if microprof_enabled() {
            MP_ECDH_DERIVATIONS.fetch_add(1, Ordering::Relaxed);
          }
        }

        // Calculate (or reuse cached) ECDH = view_scalar * key.
        // Cache key is the compressed tx pubkey.
        let key_comp: CompressedPoint = key.compress();

        #[cfg(feature = "scanner-microprof")]
        let t0_cache_lookup = std::time::Instant::now();

        let ecdh: &Zeroizing<Point> = match ecdh_cache.entry(key_comp) {
          std_shims::collections::hash_map::Entry::Occupied(e) => {
            #[cfg(feature = "scanner-microprof")]
            {
              if microprof_enabled() {
                MP_ECDH_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
                MP_NS_ECDH_CACHE_LOOKUP_HIT
                  .fetch_add(t0_cache_lookup.elapsed().as_nanos() as u64, Ordering::Relaxed);
              }
            }
            e.into_mut()
          }
          std_shims::collections::hash_map::Entry::Vacant(e) => {
            #[cfg(feature = "scanner-microprof")]
            {
              if microprof_enabled() {
                MP_ECDH_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
                // Attribute time spent up to this point as "lookup miss overhead"
                // (hashing + table probe + entry setup), excluding the scalar mul itself.
                MP_NS_ECDH_CACHE_LOOKUP_MISS
                  .fetch_add(t0_cache_lookup.elapsed().as_nanos() as u64, Ordering::Relaxed);
              }
            }

            #[cfg(feature = "scanner-microprof")]
            let t0_ecdh = std::time::Instant::now();

            let computed = Zeroizing::new(Point::from(dalek_view.deref() * key.into()));

            #[cfg(feature = "scanner-microprof")]
            {
              if microprof_enabled() {
                MP_NS_ECDH_MUL.fetch_add(t0_ecdh.elapsed().as_nanos() as u64, Ordering::Relaxed);
              }
            }

            e.insert(computed)
          }
        };

        // Derive view tag + shared key. We can avoid computing shared key for view-tag mismatches.
        let output_derivations = if let Some(actual_view_tag) = output.view_tag {
          #[cfg(feature = "scanner-microprof")]
          let t0_deriv = std::time::Instant::now();

          // Fast path: compute only the expected view tag first.
          let expected_view_tag = SharedKeyDerivations::output_view_tag(&*ecdh, o);

          #[cfg(feature = "scanner-microprof")]
          {
            if microprof_enabled() {
              MP_NS_OUTPUT_DERIVATIONS
                .fetch_add(t0_deriv.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
          }

          if actual_view_tag != expected_view_tag {
            #[cfg(feature = "scanner-microprof")]
            {
              if microprof_enabled() {
                MP_VIEWTAG_MISMATCH.fetch_add(1, Ordering::Relaxed);
              }
            }
            continue;
          }

          // Only compute shared_key once the view tag matches.
          #[cfg(feature = "scanner-microprof")]
          let t0_deriv2 = std::time::Instant::now();
          let shared_key = SharedKeyDerivations::output_shared_key(uniqueness, &*ecdh, o);
          #[cfg(feature = "scanner-microprof")]
          {
            if microprof_enabled() {
              MP_NS_OUTPUT_DERIVATIONS
                .fetch_add(t0_deriv2.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
          }

          SharedKeyDerivations { view_tag: expected_view_tag, shared_key }
        } else {
          // No view tag available: fall back to deriving both values in one pass.
          #[cfg(feature = "scanner-microprof")]
          let t0_deriv = std::time::Instant::now();
          let output_derivations = SharedKeyDerivations::output_derivations(uniqueness, &*ecdh, o);
          #[cfg(feature = "scanner-microprof")]
          {
            if microprof_enabled() {
              MP_NS_OUTPUT_DERIVATIONS
                .fetch_add(t0_deriv.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
          }
          // Avoid moving out of Zeroizing; just read fields through Deref.
          SharedKeyDerivations {
            view_tag: output_derivations.view_tag,
            shared_key: output_derivations.shared_key,
          }
        };

        // Calculate (or reuse cached) ECDH = view_scalar * key.
        // Cache key is the compressed tx pubkey.
        let key_comp: CompressedPoint = key.compress();

        #[cfg(feature = "scanner-microprof")]
        let t0_cache_lookup = std::time::Instant::now();

        let ecdh: &Zeroizing<Point> = match ecdh_cache.entry(key_comp) {
          std_shims::collections::hash_map::Entry::Occupied(e) => {
            #[cfg(feature = "scanner-microprof")]
            {
              if microprof_enabled() {
                MP_ECDH_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
                MP_NS_ECDH_CACHE_LOOKUP_HIT
                  .fetch_add(t0_cache_lookup.elapsed().as_nanos() as u64, Ordering::Relaxed);
              }
            }
            e.into_mut()
          }
          std_shims::collections::hash_map::Entry::Vacant(e) => {
            #[cfg(feature = "scanner-microprof")]
            {
              if microprof_enabled() {
                MP_ECDH_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
                // Attribute time spent up to this point as "lookup miss overhead"
                // (hashing + table probe + entry setup), excluding the scalar mul itself.
                MP_NS_ECDH_CACHE_LOOKUP_MISS
                  .fetch_add(t0_cache_lookup.elapsed().as_nanos() as u64, Ordering::Relaxed);
              }
            }

            #[cfg(feature = "scanner-microprof")]
            let t0_ecdh = std::time::Instant::now();

            let computed = Zeroizing::new(Point::from(dalek_view.deref() * key.into()));

            #[cfg(feature = "scanner-microprof")]
            {
              if microprof_enabled() {
                MP_NS_ECDH_MUL.fetch_add(t0_ecdh.elapsed().as_nanos() as u64, Ordering::Relaxed);
              }
            }

            e.insert(computed)
          }
        };

        // Derive view tag + shared key. We can avoid computing shared key for view-tag mismatches.
        let output_derivations = if let Some(actual_view_tag) = output.view_tag {
          #[cfg(feature = "scanner-microprof")]
          let t0_deriv = std::time::Instant::now();

          // Fast path: compute only the expected view tag first.
          let expected_view_tag = SharedKeyDerivations::output_view_tag(&*ecdh, o);

          #[cfg(feature = "scanner-microprof")]
          {
            if microprof_enabled() {
              MP_NS_OUTPUT_DERIVATIONS
                .fetch_add(t0_deriv.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
          }

          if actual_view_tag != expected_view_tag {
            #[cfg(feature = "scanner-microprof")]
            {
              if microprof_enabled() {
                MP_VIEWTAG_MISMATCH.fetch_add(1, Ordering::Relaxed);
              }
            }
            continue;
          }

          // Only compute shared_key once the view tag matches.
          #[cfg(feature = "scanner-microprof")]
          let t0_deriv2 = std::time::Instant::now();
          let shared_key = SharedKeyDerivations::output_shared_key(uniqueness, &*ecdh, o);
          #[cfg(feature = "scanner-microprof")]
          {
            if microprof_enabled() {
              MP_NS_OUTPUT_DERIVATIONS
                .fetch_add(t0_deriv2.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
          }

          SharedKeyDerivations { view_tag: expected_view_tag, shared_key }
        } else {
          // No view tag available: fall back to deriving both values in one pass.
          #[cfg(feature = "scanner-microprof")]
          let t0_deriv = std::time::Instant::now();
          let output_derivations = SharedKeyDerivations::output_derivations(uniqueness, &*ecdh, o);
          #[cfg(feature = "scanner-microprof")]
          {
            if microprof_enabled() {
              MP_NS_OUTPUT_DERIVATIONS
                .fetch_add(t0_deriv.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
          }
          // Avoid moving out of Zeroizing; just read fields through Deref.
          SharedKeyDerivations {
            view_tag: output_derivations.view_tag,
            shared_key: output_derivations.shared_key,
          }
        };

        // P - shared == spend
        #[cfg(feature = "scanner-microprof")]
        let t0_lookup = std::time::Instant::now();

        let subaddress_opt = {
          // The output key may be of torsion [0, 8)
          // Our subtracting of a prime-order element means any torsion will be preserved
          // If someone wanted to malleate output keys with distinct torsions, only one will be
          // scanned accordingly (the one which has matching torsion of the spend key)
          let subaddress_spend_key =
            output_key.into() - (&output_derivations.shared_key.into() * ED25519_BASEPOINT_TABLE);
          self
            .subaddresses
            .get::<CompressedPoint>(&subaddress_spend_key.compress().to_bytes().into())
        };

        #[cfg(feature = "scanner-microprof")]
        {
          if microprof_enabled() {
            MP_NS_SUBADDRESS_LOOKUP
              .fetch_add(t0_lookup.elapsed().as_nanos() as u64, Ordering::Relaxed);
          }
        }

        let Some(subaddress) = subaddress_opt else {
          continue;
        };
        let subaddress = *subaddress;

        // The key offset is this shared key
        let mut key_offset = output_derivations.shared_key.into();
        if let Some(subaddress) = subaddress {
          // And if this was to a subaddress, it's additionally the offset from subaddress spend
          // key to the normal spend key
          key_offset += self.pair.subaddress_derivation(subaddress).into();
        }
        // Since we've found an output to us, get its amount
        let mut commitment = Commitment::zero();

        // Miner transaction
        if let Some(amount) = output.amount {
          commitment.amount = amount;
        // Regular transaction
        } else {
          let Transaction::V2 { proofs: Some(ref proofs), .. } = &tx else {
            // Invalid transaction, as of consensus rules at the time of writing this code
            Err(ScanError::InvalidScannableBlock("non-miner v2 transaction without RCT proofs"))?
          };

          commitment = match proofs.base.encrypted_amounts.get(o) {
            Some(amount) => output_derivations.decrypt(amount),
            // Invalid transaction, as of consensus rules at the time of writing this code
            None => Err(ScanError::InvalidScannableBlock(
              "RCT proofs without an encrypted amount per output",
            ))?,
          };

          // Rebuild the commitment to verify it
          #[cfg(feature = "scanner-microprof")]
          let t0_verify = std::time::Instant::now();

          #[cfg(feature = "scanner-microprof")]
          {
            if microprof_enabled() {
              MP_COMMITMENT_VERIFY_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            }
          }

          let ok = Some(&commitment.commit().compress()) == proofs.base.commitments.get(o);

          #[cfg(feature = "scanner-microprof")]
          {
            if microprof_enabled() {
              MP_NS_COMMITMENT_VERIFY
                .fetch_add(t0_verify.elapsed().as_nanos() as u64, Ordering::Relaxed);
              if !ok {
                MP_COMMITMENT_VERIFY_FAIL.fetch_add(1, Ordering::Relaxed);
              }
            }
          }

          if !ok {
            continue;
          }
        }

        // Decrypt the payment ID
        let payment_id =
          payment_id.map(|id| id ^ SharedKeyDerivations::payment_id_xor(ecdh.clone()));

        let o = u64::try_from(o).expect("couldn't convert output index (usize) to u64");

        #[cfg(feature = "scanner-microprof")]
        {
          if microprof_enabled() {
            MP_OUTPUTS_MATCHED.fetch_add(1, Ordering::Relaxed);
          }
        }

        res.push(WalletOutput {
          absolute_id: AbsoluteId { transaction: tx_hash, index_in_transaction: o },
          relative_id: RelativeId {
            index_on_blockchain: output_index_for_first_ringct_output.checked_add(o).ok_or(
              ScanError::InvalidScannableBlock(
                "transaction's output's index isn't representable as a u64",
              ),
            )?,
          },
          data: OutputData { key: output_key, key_offset: Scalar::from(key_offset), commitment },
          metadata: Metadata {
            additional_timelock: tx.prefix().additional_timelock,
            subaddress,
            payment_id,
            arbitrary_data: extra.arbitrary_data(),
          },
        });

        // Break to prevent public keys from being included multiple times, triggering multiple
        // inclusions of the same output
        break;
      }
    }

    #[cfg(feature = "scanner-microprof")]
    {
      if microprof_enabled() {
        MP_NS_SCAN_TRANSACTION.fetch_add(t0_scan_tx.elapsed().as_nanos() as u64, Ordering::Relaxed);
      }
    }

    Ok(Timelocked(res))
  }

  fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
    #[cfg(feature = "scanner-microprof")]
    let t0_setup = std::time::Instant::now();

    // This is the output index for the first RingCT output within the block
    // We mutate it to be the output index for the first RingCT for each transaction
    let ScannableBlock { block, transactions, output_index_for_first_ringct_output } = block;
    if block.transactions.len() != transactions.len() {
      Err(ScanError::InvalidScannableBlock(
        "scanning a ScannableBlock with more/less transactions than it should have",
      ))?;
    }
    let Some(mut output_index_for_first_ringct_output) = output_index_for_first_ringct_output
    else {
      #[cfg(feature = "scanner-microprof")]
      {
        if microprof_enabled() {
          MP_NS_BLOCK_SETUP.fetch_add(t0_setup.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
      }
      return Ok(Timelocked(vec![]));
    };

    if block.header.hardfork_version > 16 {
      Err(ScanError::UnsupportedProtocol(block.header.hardfork_version))?;
    }

    // We obtain all TXs in full
    let mut txs_with_hashes = vec![(
      block.miner_transaction().hash(),
      Transaction::<Pruned>::from(block.miner_transaction().clone()),
    )];
    for (hash, tx) in block.transactions.iter().zip(transactions) {
      txs_with_hashes.push((*hash, tx));
    }

    #[cfg(feature = "scanner-microprof")]
    {
      if microprof_enabled() {
        MP_BLOCKS.fetch_add(1, Ordering::Relaxed);
        MP_NS_BLOCK_SETUP.fetch_add(t0_setup.elapsed().as_nanos() as u64, Ordering::Relaxed);
      }
    }

    let mut res = Timelocked(vec![]);
    for (hash, tx) in txs_with_hashes {
      // Push all outputs into our result
      {
        let mut this_txs_outputs = vec![];
        core::mem::swap(
          &mut self.scan_transaction(output_index_for_first_ringct_output, hash, &tx)?.0,
          &mut this_txs_outputs,
        );
        res.0.extend(this_txs_outputs);
      }

      // Update the RingCT starting index for the next TX
      if matches!(tx, Transaction::V2 { .. }) {
        output_index_for_first_ringct_output = output_index_for_first_ringct_output
          .checked_add(
            u64::try_from(tx.prefix().outputs.len())
              .expect("couldn't convert amount of outputs (usize) to u64"),
          )
          .ok_or(ScanError::InvalidScannableBlock("RingCT output indexes exceeded u64::MAX"))?;
      }
    }

    // If the block's version is >= 12, drop all unencrypted payment IDs
    // https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
    //   src/wallet/wallet2.cpp#L2739-L2744
    if block.header.hardfork_version >= 12 {
      for output in &mut res.0 {
        if matches!(output.metadata.payment_id, Some(PaymentId::Unencrypted(_))) {
          output.metadata.payment_id = None;
        }
      }
    }

    Ok(res)
  }
}

/// A transaction scanner to find outputs received.
///
/// When an output is successfully scanned, the output key MUST be checked against the local
/// database for lack of prior observation. If it was prior observed, that output is an instance
/// of the
/// [burning bug](https://web.getmonero.org/2018/09/25/a-post-mortum-of-the-burning-bug.html) and
/// MAY be unspendable. Only the prior received output(s) or the newly received output will be
/// spendable (as spending one will burn all of them).
///
/// Once checked, the output key MUST be saved to the local database so future checks can be
/// performed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Scanner(InternalScanner);

impl Scanner {
  /// Create a Scanner from a ViewPair.
  pub fn new(pair: ViewPair) -> Self {
    Self(InternalScanner::new(pair, false))
  }

  /// Register a subaddress to scan for.
  ///
  /// Subaddresses must be explicitly registered ahead of time in order to be successfully scanned.
  ///
  /// This function runs in variable time, notably with regards to the distribution of subaddress
  /// derivations (which should be reasonably uniform) and the amount of subaddresses registered.
  pub fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
    self.0.register_subaddress(subaddress);
  }

  /// Scan a block.
  ///
  /// This function runs in variable time, notably with regards to how the private view key relates
  /// to outputs present within the block (such as if it can successfully scan outputs present).
  pub fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
    self.0.scan(block)
  }
}

/// A transaction scanner to find outputs received which are guaranteed to be spendable.
///
/// 'Guaranteed' outputs, or transactions outputs to the burning bug, are not officially specified
/// by the Monero project. They should only be used if necessary. No support outside of
/// monero-wallet is promised.
///
/// "guaranteed to be spendable" assumes satisfaction of any timelocks in effect.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GuaranteedScanner(InternalScanner);

impl GuaranteedScanner {
  /// Create a GuaranteedScanner from a GuaranteedViewPair.
  pub fn new(pair: GuaranteedViewPair) -> Self {
    Self(InternalScanner::new(pair.0, true))
  }

  /// Register a subaddress to scan for.
  ///
  /// Subaddresses must be explicitly registered ahead of time in order to be successfully scanned.
  ///
  /// This function runs in variable time, notably with regards to the distribution of subaddress
  /// derivations (which should be reasonably uniform) and the amount of subaddresses registered.
  pub fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
    self.0.register_subaddress(subaddress);
  }

  /// Scan a block.
  ///
  /// This function runs in variable time, notably with regards to how the private view key relates
  /// to outputs present within the block (such as if it can successfully scan outputs present).
  pub fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
    self.0.scan(block)
  }
}
