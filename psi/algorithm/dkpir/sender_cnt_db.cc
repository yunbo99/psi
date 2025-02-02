// Copyright 2024 Zhongyun Lin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "psi/algorithm/dkpir/sender_cnt_db.h"

#include <algorithm>
#include <future>
#include <sstream>
#include <thread>
#include <vector>

#include "apsi/oprf/oprf_common.h"
#include "apsi/thread_pool_mgr.h"
#include "apsi/util/stopwatch.h"
#include "apsi/util/utils.h"
#include "kuku/locfunc.h"
#include "spdlog/spdlog.h"
#include "yacl/base/exception.h"

#include "psi/algorithm/dkpir/sender_cnt_db.pb.h"

namespace psi::dkpir {

namespace {
/**
Creates and returns the vector of hash functions similarly to how Kuku 2.x sets
them internally.
*/
std::vector<kuku::LocFunc> hash_functions(const PSIParams& params) {
  std::vector<kuku::LocFunc> result;
  for (uint32_t i = 0; i < params.table_params().hash_func_count; ++i) {
    result.emplace_back(params.table_params().table_size,
                        kuku::make_item(i, 0));
  }

  return result;
}

/**
Computes all cuckoo hash table locations for a given item.
*/
std::unordered_set<kuku::location_type> all_locations(
    const std::vector<kuku::LocFunc>& hash_funcs, const HashedItem& item) {
  std::unordered_set<kuku::location_type> result;
  for (auto& hf : hash_funcs) {
    result.emplace(hf(item.get_as<kuku::item_type>().front()));
  }

  return result;
}

/**
Compute the label size in multiples of item-size chunks.
*/
size_t compute_label_size(size_t label_byte_count, const PSIParams& params) {
  return (label_byte_count * 8 + params.item_bit_count() - 1) /
         params.item_bit_count();
}

/**
Unpacks a cuckoo idx into its bin and bundle indices
*/
std::pair<size_t, size_t> unpack_cuckoo_idx(size_t cuckoo_idx,
                                            size_t bins_per_bundle) {
  // Recall that bin indices are relative to the bundle index. That is, the
  // first bin index of a bundle at bundle index 5 is 0. A cuckoo index is
  // similar, except it is not relative to the bundle index. It just keeps
  // counting past bundle boundaries. So in order to get the bin index from the
  // cuckoo index, just compute cuckoo_idx (mod bins_per_bundle).
  size_t bin_idx = cuckoo_idx % bins_per_bundle;

  // Compute which bundle index this cuckoo index belongs to
  size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;

  return {bin_idx, bundle_idx};
}

/**
Converts each given Item-Label pair in between the given iterators into its
algebraic form, i.e., a sequence of felt-felt pairs. Also computes each Item's
cuckoo index.
*/
std::vector<std::pair<::apsi::util::AlgItemLabel, size_t>>
preprocess_labeled_data(
    const std::vector<std::pair<HashedItem, EncryptedLabel>>::const_iterator
        begin,
    const std::vector<std::pair<HashedItem, EncryptedLabel>>::const_iterator
        end,
    const PSIParams& params) {
  STOPWATCH(sender_stopwatch, "preprocess_labeled_data");
  SPDLOG_DEBUG("Start preprocessing {} labeled items", distance(begin, end));

  // Some variables we'll need
  size_t bins_per_item = params.item_params().felts_per_item;
  size_t item_bit_count = params.item_bit_count();

  // Set up Kuku hash functions
  auto hash_funcs = hash_functions(params);

  // Calculate the cuckoo indices for each item. Store every pair of
  // (item-label, cuckoo_idx) in a vector. Later, we're gonna sort this vector
  // by cuckoo_idx and use the result to parallelize the work of inserting the
  // items into BinBundles.
  std::vector<std::pair<::apsi::util::AlgItemLabel, size_t>> data_with_indices;
  for (auto it = begin; it != end; it++) {
    const std::pair<HashedItem, EncryptedLabel>& item_label_pair = *it;

    // Serialize the data into field elements
    const HashedItem& item = item_label_pair.first;
    const EncryptedLabel& label = item_label_pair.second;
    AlgItemLabel alg_item_label = algebraize_item_label(
        item, label, item_bit_count, params.seal_params().plain_modulus());

    // Get the cuckoo table locations for this item and add to data_with_indices
    for (auto location : all_locations(hash_funcs, item)) {
      // The current hash value is an index into a table of Items. In reality
      // our BinBundles are tables of bins, which contain chunks of items. How
      // many chunks? bins_per_item many chunks
      size_t bin_idx = location * bins_per_item;

      // Store the data along with its index
      data_with_indices.push_back(make_pair(alg_item_label, bin_idx));
    }
  }

  SPDLOG_DEBUG("Finished preprocessing {} labeled items", distance(begin, end));
  return data_with_indices;
}

/**
Converts each given Item into its algebraic form, i.e., a sequence of
felt-monostate pairs. Also computes each Item's cuckoo index.
*/
std::vector<std::pair<::apsi::util::AlgItem, size_t>> preprocess_unlabeled_data(
    const std::vector<HashedItem>::const_iterator begin,
    const std::vector<HashedItem>::const_iterator end,
    const PSIParams& params) {
  STOPWATCH(sender_stopwatch, "preprocess_unlabeled_data");
  SPDLOG_DEBUG("Start preprocessing {} unlabeled items", distance(begin, end));

  // Some variables we'll need
  size_t bins_per_item = params.item_params().felts_per_item;
  size_t item_bit_count = params.item_bit_count();

  // Set up Kuku hash functions
  auto hash_funcs = hash_functions(params);

  // Calculate the cuckoo indices for each item. Store every pair of
  // (item-label, cuckoo_idx) in a vector. Later, we're gonna sort this vector
  // by cuckoo_idx and use the result to parallelize the work of inserting the
  // items into BinBundles.
  std::vector<std::pair<::apsi::util::AlgItem, size_t>> data_with_indices;
  for (auto it = begin; it != end; ++it) {
    const HashedItem& item = *it;

    // Serialize the data into field elements
    ::apsi::util::AlgItem alg_item = algebraize_item(
        item, item_bit_count, params.seal_params().plain_modulus());

    // Get the cuckoo table locations for this item and add to data_with_indices
    for (auto location : all_locations(hash_funcs, item)) {
      // The current hash value is an index into a table of Items. In reality
      // our BinBundles are tables of bins, which contain chunks of items. How
      // many chunks? bins_per_item many chunks
      size_t bin_idx = location * bins_per_item;

      // Store the data along with its index
      data_with_indices.emplace_back(make_pair(alg_item, bin_idx));
    }
  }

  SPDLOG_DEBUG("Finished preprocessing {} unlabeled items",
               distance(begin, end));

  return data_with_indices;
}

/**
Converts given Item into its algebraic form, i.e., a sequence of felt-monostate
pairs. Also computes the Item's cuckoo index.
*/
std::vector<std::pair<::apsi::util::AlgItem, size_t>> preprocess_unlabeled_data(
    const HashedItem& item, const PSIParams& params) {
  std::vector<HashedItem> item_singleton{item};
  return preprocess_unlabeled_data(item_singleton.begin(), item_singleton.end(),
                                   params);
}

/**
Inserts the given items and corresponding labels into bin_bundles at their
respective cuckoo indices. It will only insert the data with bundle index in the
half-open range range indicated by work_range. If inserting into a BinBundle
would make the number of items in a bin larger than max_bin_size, this function
will create and insert a new BinBundle. If overwrite is set, this will overwrite
the labels if it finds an AlgItemLabel that matches the input perfectly.
*/
template <typename T>
void insert_or_assign_worker(
    const std::vector<std::pair<T, size_t>>& data_with_indices,
    std::vector<std::vector<BinBundle>>& bin_bundles,
    const CryptoContext& crypto_context, uint32_t bundle_index,
    uint32_t bins_per_bundle, size_t label_size, size_t max_bin_size,
    size_t ps_low_degree, bool overwrite, bool compressed) {
  STOPWATCH(sender_stopwatch, "insert_or_assign_worker");
  SPDLOG_DEBUG(
      "Insert-or-Assign worker for bundle index {}; mode of operation: {}",
      bundle_index, overwrite ? "overwriting existing" : "inserting new");

  // Iteratively insert each item-label pair at the given cuckoo index
  for (auto& data_with_idx : data_with_indices) {
    const T& data = data_with_idx.first;

    // Get the bundle index
    size_t cuckoo_idx = data_with_idx.second;
    size_t bin_idx, bundle_idx;
    std::tie(bin_idx, bundle_idx) =
        unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

    // If the bundle_idx isn't in the prescribed range, don't try to insert this
    // data
    if (bundle_idx != bundle_index) {
      // Dealing with this bundle index is not our job
      continue;
    }

    // Get the bundle set at the given bundle index
    std::vector<BinBundle>& bundle_set = bin_bundles[bundle_idx];

    // Try to insert or overwrite these field elements in an existing BinBundle
    // at this bundle index. Keep track of whether or not we succeed.
    bool written = false;
    for (auto bundle_it = bundle_set.rbegin(); bundle_it != bundle_set.rend();
         ++bundle_it) {
      // If we're supposed to overwrite, try to overwrite. One of these
      // BinBundles has to have the data we're trying to overwrite.
      if (overwrite) {
        // If we successfully overwrote, we're done with this bundle
        written = bundle_it->try_multi_overwrite(data, bin_idx);
        if (written) {
          break;
        }
      }

      // Do a dry-run insertion and see if the new largest bin size in the range
      // exceeds the limit
      int32_t new_largest_bin_size =
          bundle_it->multi_insert_dry_run(data, bin_idx);

      // Check if inserting would violate the max bin size constraint
      if (new_largest_bin_size > 0 &&
          seal::util::safe_cast<size_t>(new_largest_bin_size) < max_bin_size) {
        // All good
        bundle_it->multi_insert_for_real(data, bin_idx);
        written = true;
        break;
      }
    }

    // We tried to overwrite an item that doesn't exist. This should never
    // happen
    if (overwrite && !written) {
      SPDLOG_ERROR(
          "Insert-or-Assign worker: "
          "failed to overwrite item at bundle index {} because the item was "
          "not found",
          bundle_idx);
      YACL_THROW("tried to overwrite non-existent item");
    }

    // If we had conflicts everywhere when trying to insert, then we need to
    // make a new BinBundle and insert the data there
    if (!written) {
      // Make a fresh BinBundle and insert
      BinBundle new_bin_bundle(crypto_context, label_size, max_bin_size,
                               ps_low_degree, bins_per_bundle, compressed,
                               false);
      int res = new_bin_bundle.multi_insert_for_real(data, bin_idx);

      // If even that failed, I don't know what could've happened
      if (res < 0) {
        SPDLOG_ERROR(
            "Insert-or-Assign worker: "
            "failed to insert item into a new BinBundle at bundle index {}",
            bundle_idx);
        YACL_THROW("failed to insert item into a new BinBundle");
      }

      // Push a new BinBundle to the set of BinBundles at this bundle index
      bundle_set.push_back(std::move(new_bin_bundle));
    }
  }

  SPDLOG_DEBUG("Insert-or-Assign worker: finished processing bundle index {}",
               bundle_index);
}

/**
Takes algebraized data to be inserted, splits it up, and distributes it so that
thread_count many threads can all insert in parallel. If overwrite is set, this
will overwrite the labels if it finds an AlgItemLabel that matches the input
perfectly.
*/
template <typename T>
void dispatch_insert_or_assign(
    const std::vector<std::pair<T, size_t>>& data_with_indices,
    std::vector<std::vector<BinBundle>>& bin_bundles,
    const CryptoContext& crypto_context, uint32_t bins_per_bundle,
    size_t label_size, uint32_t max_bin_size, uint32_t ps_low_degree,
    bool overwrite, bool compressed) {
  ::apsi::ThreadPoolMgr tpm;

  // Collect the bundle indices and partition them into thread_count many
  // partitions. By some uniformity assumption, the number of things to insert
  // per partition should be roughly the same. Note that the contents of
  // bundle_indices is always sorted (increasing order).
  std::set<size_t> bundle_indices_set;
  for (auto& data_with_idx : data_with_indices) {
    size_t cuckoo_idx = data_with_idx.second;
    size_t bin_idx, bundle_idx;
    std::tie(bin_idx, bundle_idx) =
        unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);
    bundle_indices_set.insert(bundle_idx);
  }

  // Copy the set of indices into a vector and sort so each thread processes a
  // range of indices
  std::vector<size_t> bundle_indices;
  bundle_indices.reserve(bundle_indices_set.size());
  copy(bundle_indices_set.begin(), bundle_indices_set.end(),
       back_inserter(bundle_indices));
  std::sort(bundle_indices.begin(), bundle_indices.end());

  // Run the threads on the partitions
  std::vector<std::future<void>> futures(bundle_indices.size());
  SPDLOG_INFO("Launching {} insert-or-assign worker tasks",
              bundle_indices.size());
  size_t future_idx = 0;
  for (auto& bundle_idx : bundle_indices) {
    futures[future_idx++] = tpm.thread_pool().enqueue([&, bundle_idx]() {
      insert_or_assign_worker(data_with_indices, bin_bundles, crypto_context,
                              static_cast<uint32_t>(bundle_idx),
                              bins_per_bundle, label_size, max_bin_size,
                              ps_low_degree, overwrite, compressed);
    });
  }

  // Wait for the tasks to finish
  for (auto& f : futures) {
    f.get();
  }

  SPDLOG_INFO("Finished insert-or-assign worker tasks");
}

HashedItem GetItemHash(const Item& item, const OPRFKey& oprf_key) {
  // Create an elliptic curve point from the item
  ::apsi::oprf::ECPoint ecpt(item.get_as<const unsigned char>());
  // Multiply with key
  ecpt.scalar_multiply(oprf_key.key_span(), true);

  // Extract the item hash and the label encryption key
  std::array<unsigned char, ::apsi::oprf::ECPoint::hash_size>
      item_hash_and_label_key;
  ecpt.extract_hash(item_hash_and_label_key);

  // The first 128 bits represent the item hash
  HashedItem result;
  copy_bytes(item_hash_and_label_key.data(), ::apsi::oprf::oprf_hash_size,
             result.value().data());

  return result;
}

std::vector<HashedItem> ComputeHashes(const gsl::span<const Item>& oprf_items,
                                      const OPRFKey& oprf_key) {
  STOPWATCH(sender_stopwatch, "OPRFSender::ComputeHashes (unlabeled)");
  SPDLOG_DEBUG("Start computing OPRF hashes for {} items", oprf_items.size());

  ::apsi::ThreadPoolMgr tpm;
  std::vector<HashedItem> oprf_hashes(oprf_items.size());
  size_t task_count = std::min<size_t>(::apsi::ThreadPoolMgr::GetThreadCount(),
                                       oprf_items.size());
  std::vector<std::future<void>> futures(task_count);

  auto ComputeHashesLambda = [&](size_t start_idx, size_t step) {
    for (size_t idx = start_idx; idx < oprf_items.size(); idx += step) {
      oprf_hashes[idx] = GetItemHash(oprf_items[idx], oprf_key);
    }
  };

  for (size_t thread_idx = 0; thread_idx < task_count; thread_idx++) {
    futures[thread_idx] =
        tpm.thread_pool().enqueue(ComputeHashesLambda, thread_idx, task_count);
  }

  for (auto& f : futures) {
    f.get();
  }

  SPDLOG_DEBUG("Finished computing OPRF hashes for {} items",
               oprf_items.size());

  return oprf_hashes;
}

std::vector<std::pair<HashedItem, EncryptedLabel>> ComputeHashes(
    const gsl::span<const std::pair<Item, Label>>& oprf_item_labels,
    const OPRFKey& oprf_key, size_t label_byte_count) {
  STOPWATCH(sender_stopwatch, "psi::dkpir::ComputeHashes");

  ::apsi::ThreadPoolMgr tpm;
  std::vector<std::pair<HashedItem, EncryptedLabel>> oprf_hashes(
      oprf_item_labels.size());
  size_t task_count = std::min<size_t>(::apsi::ThreadPoolMgr::GetThreadCount(),
                                       oprf_item_labels.size());
  std::vector<std::future<void>> futures(task_count);

  auto ComputeHashesLambda = [&](size_t start_idx, size_t step) {
    for (size_t idx = start_idx; idx < oprf_item_labels.size(); idx += step) {
      const Item& item = oprf_item_labels[idx].first;
      Label label = oprf_item_labels[idx].second;

      HashedItem hashed_item = GetItemHash(item, oprf_key);

      // The label is not encrypted here because it needs to be used later
      // for homomorphic addition.
      EncryptedLabel encrypted_label(label_byte_count);
      copy_bytes(label.data(), label_byte_count, encrypted_label.data());

      oprf_hashes[idx] = make_pair(hashed_item, std::move(encrypted_label));
    }
  };

  for (size_t thread_idx = 0; thread_idx < task_count; thread_idx++) {
    futures[thread_idx] =
        tpm.thread_pool().enqueue(ComputeHashesLambda, thread_idx, task_count);
  }

  for (auto& f : futures) {
    f.get();
  }

  SPDLOG_INFO("Finished computing OPRF hashes for {} items",
              oprf_item_labels.size());
  return oprf_hashes;
}

/**
Returns a set of DB cache references corresponding to the bundles in the given
set
*/
std::vector<std::reference_wrapper<const ::apsi::sender::BinBundleCache>>
collect_caches(std::vector<BinBundle>& bin_bundles) {
  std::vector<std::reference_wrapper<const ::apsi::sender::BinBundleCache>>
      result;
  for (const auto& bundle : bin_bundles) {
    result.emplace_back(std::cref(bundle.get_cache()));
  }

  return result;
}

}  // namespace

SenderCntDB::SenderCntDB(const PSIParams& params, size_t label_byte_count,
                         bool compressed)
    : params_(params),
      crypto_context_(params_),
      label_byte_count_(label_byte_count),
      compressed_(compressed) {
  // The labels cannot be more than 1 KB.
  if (label_byte_count_ > 1024) {
    SPDLOG_ERROR("Requested label byte count {} exceeds the maximum (1024)",
                 label_byte_count_);

    YACL_THROW("label_byte_count is too large");
  }

  // Set the evaluator. This will be used for BatchedPlaintextPolyn::eval.
  crypto_context_.set_evaluator();

  // Reset the SenderDB data structures
  clear();
}

SenderCntDB::SenderCntDB(const PSIParams& params, const OPRFKey& oprf_key,
                         size_t label_byte_count, bool compressed)
    : SenderCntDB(params, label_byte_count, compressed) {
  // Initialize oprf key with the one given to this constructor
  oprf_key_ = std::move(oprf_key);
}

SenderCntDB::SenderCntDB(SenderCntDB&& source)
    : params_(source.params_),
      crypto_context_(source.crypto_context_),
      label_byte_count_(source.label_byte_count_),
      item_count_(source.item_count_),
      compressed_(source.compressed_),
      stripped_(source.stripped_) {
  // Lock the source before moving stuff over
  auto lock = source.get_writer_lock();

  hashed_items_ = std::move(source.hashed_items_);
  bin_bundles_ = std::move(source.bin_bundles_);
  oprf_key_ = std::move(source.oprf_key_);
  source.oprf_key_ = OPRFKey();

  // Reset the source data structures
  source.clear_internal();
}

SenderCntDB& SenderCntDB::operator=(SenderCntDB&& source) {
  // Do nothing if moving to self
  if (&source == this) {
    return *this;
  }

  // Lock the current SenderCntDB
  auto this_lock = get_writer_lock();

  params_ = source.params_;
  crypto_context_ = source.crypto_context_;
  label_byte_count_ = source.label_byte_count_;
  item_count_ = source.item_count_;
  compressed_ = source.compressed_;
  stripped_ = source.stripped_;

  // Lock the source before moving stuff over
  auto source_lock = source.get_writer_lock();

  hashed_items_ = std::move(source.hashed_items_);
  bin_bundles_ = std::move(source.bin_bundles_);
  oprf_key_ = std::move(source.oprf_key_);
  source.oprf_key_ = OPRFKey();

  // Reset the source data structures
  source.clear_internal();

  return *this;
}

size_t SenderCntDB::get_bin_bundle_count(uint32_t bundle_idx) const {
  // Lock the database for reading
  auto lock = get_reader_lock();

  return bin_bundles_.at(::seal::util::safe_cast<size_t>(bundle_idx)).size();
}

size_t SenderCntDB::get_bin_bundle_count() const {
  // Lock the database for reading
  auto lock = get_reader_lock();

  // Compute the total number of BinBundles
  return accumulate(bin_bundles_.cbegin(), bin_bundles_.cend(), size_t(0),
                    [&](auto& a, auto& b) { return a + b.size(); });
}

double SenderCntDB::get_packing_rate() const {
  // Lock the database for reading
  auto lock = get_reader_lock();

  uint64_t item_count = seal::util::mul_safe(
      static_cast<uint64_t>(get_item_count()),
      static_cast<uint64_t>(params_.table_params().hash_func_count));
  uint64_t max_item_count = seal::util::mul_safe(
      static_cast<uint64_t>(get_bin_bundle_count()),
      static_cast<uint64_t>(params_.items_per_bundle()),
      static_cast<uint64_t>(params_.table_params().max_items_per_bin));

  return max_item_count ? static_cast<double>(item_count) /
                              static_cast<double>(max_item_count)
                        : 0.0;
}

void SenderCntDB::clear_internal() {
  // Assume the SenderDB is already locked for writing

  // Clear the set of inserted items
  hashed_items_.clear();
  item_count_ = 0;

  // Clear the BinBundles
  bin_bundles_.clear();
  bin_bundles_.resize(params_.bundle_idx_count());

  // Reset the stripped_ flag
  stripped_ = false;
}

void SenderCntDB::clear() {
  if (hashed_items_.size()) {
    SPDLOG_INFO("Removing {} items pairs from SenderDB", hashed_items_.size());
  }

  // Lock the database for writing
  auto lock = get_writer_lock();

  clear_internal();
}

void SenderCntDB::generate_caches() {
  STOPWATCH(sender_stopwatch, "SenderDB::generate_caches");
  SPDLOG_INFO("Start generating bin bundle caches");

  for (auto& bundle_idx : bin_bundles_) {
    for (auto& bb : bundle_idx) {
      bb.regen_cache();
    }
  }

  SPDLOG_INFO("Finished generating bin bundle caches");
}

std::vector<std::reference_wrapper<const ::apsi::sender::BinBundleCache>>
SenderCntDB::get_cache_at(uint32_t bundle_idx) {
  return collect_caches(
      bin_bundles_.at(::seal::util::safe_cast<size_t>(bundle_idx)));
}

OPRFKey SenderCntDB::strip() {
  // Lock the database for writing
  auto lock = get_writer_lock();

  stripped_ = true;

  OPRFKey oprf_key_copy = std::move(oprf_key_);
  oprf_key_.clear();
  hashed_items_.clear();

  ::apsi::ThreadPoolMgr tpm;

  std::vector<std::future<void>> futures;
  for (auto& bundle_idx : bin_bundles_) {
    for (auto& bb : bundle_idx) {
      futures.push_back(tpm.thread_pool().enqueue([&bb]() { bb.strip(); }));
    }
  }

  // Wait for the tasks to finish
  for (auto& f : futures) {
    f.get();
  }

  SPDLOG_INFO("SenderDB has been stripped");

  return oprf_key_copy;
}

OPRFKey SenderCntDB::get_oprf_key() const {
  if (stripped_) {
    SPDLOG_ERROR("Cannot return the OPRF key from a stripped SenderDB");
    YACL_THROW("failed to return OPRF key");
  }
  return oprf_key_;
}

void SenderCntDB::insert_or_assign(
    const std::vector<std::pair<Item, Label>>& data) {
  if (stripped_) {
    SPDLOG_ERROR("Cannot insert data to a stripped SenderCntDB");
    YACL_THROW("failed to insert data");
  }

  STOPWATCH(sender_stopwatch, "SenderCntDB::insert_or_assign");
  SPDLOG_INFO("Start inserting {} items in SenderCntDB", data.size());

  // First compute the hashes for the input data
  auto hashed_data = ComputeHashes(data, oprf_key_, label_byte_count_);

  // Lock the database for writing
  auto lock = get_writer_lock();

  // We need to know which items are new and which are old, since we have to
  // tell dispatch_insert_or_assign when to have an overwrite-on-collision
  // versus add-binbundle-on-collision policy.
  auto new_data_end = remove_if(
      hashed_data.begin(), hashed_data.end(), [&](const auto& item_label_pair) {
        bool found =
            hashed_items_.find(item_label_pair.first) != hashed_items_.end();
        if (!found) {
          // Add to hashed_items_ already at this point!
          hashed_items_.insert(item_label_pair.first);
          item_count_++;
        }

        // Remove those that were found
        return found;
      });

  // Dispatch the insertion, first for the new data, then for the data we're
  // gonna overwrite
  uint32_t bins_per_bundle = params_.bins_per_bundle();
  uint32_t max_bin_size = params_.table_params().max_items_per_bin;
  uint32_t ps_low_degree = params_.query_params().ps_low_degree;

  // Compute the label size; this ceil(effective_label_bit_count /
  // item_bit_count)
  size_t label_size = compute_label_size(label_byte_count_, params_);

  auto new_item_count = distance(hashed_data.begin(), new_data_end);
  auto existing_item_count = distance(new_data_end, hashed_data.end());

  if (existing_item_count != 0) {
    SPDLOG_INFO("Found {} existing items to replace in SenderDB",
                existing_item_count);

    // Break the data into field element representation. Also compute the items'
    // cuckoo indices.
    std::vector<std::pair<::apsi::util::AlgItemLabel, size_t>>
        data_with_indices =
            preprocess_labeled_data(new_data_end, hashed_data.end(), params_);

    dispatch_insert_or_assign(data_with_indices, bin_bundles_, crypto_context_,
                              bins_per_bundle, label_size, max_bin_size,
                              ps_low_degree, true, /* overwrite items */
                              compressed_);

    // Release memory that is no longer needed
    hashed_data.erase(new_data_end, hashed_data.end());
  }

  if (new_item_count != 0) {
    SPDLOG_INFO("Found {} new items to insert in SenderCntDB", new_item_count);

    // Process and add the new data. Break the data into field element
    // representation. Also compute the items' cuckoo indices.
    std::vector<std::pair<::apsi::util::AlgItemLabel, size_t>>
        data_with_indices = preprocess_labeled_data(hashed_data.begin(),
                                                    hashed_data.end(), params_);

    dispatch_insert_or_assign(data_with_indices, bin_bundles_, crypto_context_,
                              bins_per_bundle, label_size, max_bin_size,
                              ps_low_degree, false, /* don't overwrite items */
                              compressed_);
  }

  // Generate the BinBundle caches
  generate_caches();

  SPDLOG_INFO("Finished inserting {} items in SenderDB", data.size());
}

bool SenderCntDB::has_item(const Item& item) const {
  if (stripped_) {
    SPDLOG_ERROR(
        "Cannot retrieve the presence of an item from a stripped SenderDB");
    YACL_THROW("failed to retrieve the presence of item");
  }

  // First compute the hash for the input item
  auto hashed_item = ComputeHashes({&item, 1}, oprf_key_)[0];

  // Lock the database for reading
  auto lock = get_reader_lock();

  return hashed_items_.find(hashed_item) != hashed_items_.end();
}

Label SenderCntDB::get_label(const Item& item) const {
  if (stripped_) {
    SPDLOG_ERROR("Cannot retrieve a label from a stripped SenderDB");
    YACL_THROW("failed to retrieve label");
  }

  // First compute the hash for the input item
  HashedItem hashed_item;

  hashed_item = GetItemHash(item, oprf_key_);

  // Lock the database for reading
  auto lock = get_reader_lock();

  // Check if this item is in the DB. If not, throw an exception
  if (hashed_items_.find(hashed_item) == hashed_items_.end()) {
    SPDLOG_ERROR(
        "Cannot retrieve label for an item that is not in the SenderDB");
    YACL_THROW("failed to retrieve label");
  }

  uint32_t bins_per_bundle = params_.bins_per_bundle();

  // Preprocess a single element. This algebraizes the item and gives back its
  // field element representation as well as its cuckoo hash. We only read one
  // of the locations because the labels are the same in each location.
  AlgItem alg_item;
  size_t cuckoo_idx;
  std::tie(alg_item, cuckoo_idx) =
      preprocess_unlabeled_data(hashed_item, params_)[0];

  // Now figure out where to look to get the label
  size_t bin_idx, bundle_idx;
  std::tie(bin_idx, bundle_idx) =
      unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

  // Retrieve the algebraic labels from one of the BinBundles at this index
  const std::vector<BinBundle>& bundle_set = bin_bundles_[bundle_idx];
  std::vector<::apsi::util::felt_t> alg_label;
  bool got_labels = false;
  for (const BinBundle& bundle : bundle_set) {
    // Try to retrieve the contiguous labels from this BinBundle
    if (bundle.try_get_multi_label(alg_item, bin_idx, alg_label)) {
      got_labels = true;
      break;
    }
  }

  // It shouldn't be possible to have items in your set but be unable to
  // retrieve the associated label. Throw an exception because something is
  // terribly wrong.
  if (!got_labels) {
    SPDLOG_ERROR(
        "Failed to retrieve label for an item that was supposed to be in the "
        "SenderDB");
    YACL_THROW("failed to retrieve label");
  }

  // All good. Now just reconstruct the big label from its split-up parts
  EncryptedLabel encrypted_label = dealgebraize_label(
      alg_label,
      alg_label.size() * static_cast<size_t>(params_.item_bit_count_per_felt()),
      params_.seal_params().plain_modulus());

  Label result(label_byte_count_);
  copy_bytes(encrypted_label.data(), label_byte_count_, result.data());

  // Decrypt the label
  return result;
}

size_t SenderCntDB::save(std::ostream& info_out, std::ostream& bin_out) const {
  // Lock the database for reading
  auto lock = get_reader_lock();

  STOPWATCH(sender_stopwatch, "SenderCntDB::save");
  SPDLOG_DEBUG("Start saving SenderDB");

  // First save the PSIParam
  std::stringstream ss;
  params_.save(ss);
  std::string params_str = ss.str();

  psi::dkpir::SenderCntDBProto sender_cnt_db_proto;
  sender_cnt_db_proto.set_params(params_str);

  sender_cnt_db_proto.set_label_byte_count(
      ::seal::util::safe_cast<uint32_t>(label_byte_count_));
  sender_cnt_db_proto.set_item_count(
      ::seal::util::safe_cast<uint32_t>(item_count_));
  sender_cnt_db_proto.set_compressed(compressed_);
  sender_cnt_db_proto.set_stripped(stripped_);

  auto oprf_key_span = oprf_key_.key_span();
  sender_cnt_db_proto.set_oprf_key(oprf_key_span.data(), oprf_key_span.size());

  sender_cnt_db_proto.set_bin_bundle_count(
      ::seal::util::safe_cast<uint32_t>(get_bin_bundle_count()));

  // Serialize to output stream
  if (!sender_cnt_db_proto.SerializeToOstream(&info_out)) {
    YACL_THROW("Failed to serialize SenderCntDB");
  }

  size_t total_size = sender_cnt_db_proto.ByteSizeLong();

  // Write the BinBundles
  size_t bin_bundle_data_size = 0;
  for (size_t bundle_idx = 0; bundle_idx < bin_bundles_.size(); bundle_idx++) {
    for (auto& bb : bin_bundles_[bundle_idx]) {
      auto size = bb.save(bin_out, static_cast<uint32_t>(bundle_idx));
      SPDLOG_DEBUG("Saved BinBundle at bundle index {} ({} bytes)", bundle_idx,
                   size);
      bin_bundle_data_size += size;
    }
  }

  total_size += bin_bundle_data_size;

  SPDLOG_DEBUG("Saved SenderDB with {} items ({} bytes)", get_item_count(),
               bin_bundle_data_size);

  SPDLOG_DEBUG("Finished saving SenderDB");

  return total_size;
}

std::pair<SenderCntDB, size_t> SenderCntDB::Load(std::istream& info_in,
                                                 std::istream& bin_in) {
  STOPWATCH(sender_stopwatch, "SenderCntDB::Load");
  SPDLOG_DEBUG("Start loading SenderCntDB");

  psi::dkpir::SenderCntDBProto sender_cnt_db_proto;

  if (!sender_cnt_db_proto.ParsePartialFromIstream(&info_in)) {
    SPDLOG_ERROR("Failed to load SenderDB: the buffer is invalid");
    YACL_THROW("failed to load SenderDB");
  }

  std::unique_ptr<PSIParams> params;

  try {
    ::seal::util::ArrayGetBuffer agbuf(
        sender_cnt_db_proto.params().data(),
        static_cast<std::streamsize>(sender_cnt_db_proto.params().size()));
    std::istream params_stream(&agbuf);
    params = std::make_unique<PSIParams>(PSIParams::Load(params_stream).first);
  } catch (const std::runtime_error& ex) {
    SPDLOG_ERROR("APSI threw an exception creating PSIParams: {}", ex.what());
    YACL_THROW("failed to load SenderDB");
  }

  // Load the info so we know what kind of SenderDB to create
  size_t item_count = static_cast<size_t>(sender_cnt_db_proto.item_count());
  size_t label_byte_count =
      static_cast<size_t>(sender_cnt_db_proto.label_byte_count());

  bool compressed = sender_cnt_db_proto.compressed();
  bool stripped = sender_cnt_db_proto.stripped();

  SPDLOG_DEBUG(
      "Loaded SenderDB properties: "
      "item_count: {}; "
      "label_byte_count: {}; "
      "compressed: {}; "
      "stripped: {}",
      item_count, label_byte_count, std::boolalpha << compressed,
      std::boolalpha << stripped);

  // Create the correct kind of SenderDB
  std::unique_ptr<SenderCntDB> sender_cnt_db;

  try {
    sender_cnt_db =
        std::make_unique<SenderCntDB>(*params, label_byte_count, compressed);
    sender_cnt_db->stripped_ = stripped;
    sender_cnt_db->item_count_ = item_count;
  } catch (const std::invalid_argument& ex) {
    SPDLOG_ERROR("APSI threw an exception creating SenderDB: ", ex.what());
    YACL_THROW("failed to load SenderDB");
  }

  // Check that the OPRF key size is correct
  size_t loaded_oprf_key_size = sender_cnt_db_proto.oprf_key().size();
  if (loaded_oprf_key_size != ::apsi::oprf::oprf_key_size) {
    SPDLOG_ERROR(
        "The loaded OPRF key has invalid size ({} bytes; expected {} bytes)",
        loaded_oprf_key_size, ::apsi::oprf::oprf_key_size);
    YACL_THROW("failed to load SenderDB");
  }

  // Copy over the OPRF key
  sender_cnt_db->oprf_key_.load(::apsi::oprf::oprf_key_span_const_type(
      reinterpret_cast<const unsigned char*>(
          sender_cnt_db_proto.oprf_key().data()),
      ::apsi::oprf::oprf_key_size));

  uint32_t bin_bundle_count = sender_cnt_db_proto.bin_bundle_count();
  size_t bin_bundle_data_size = 0;
  uint32_t max_bin_size = params->table_params().max_items_per_bin;
  uint32_t ps_low_degree = params->query_params().ps_low_degree;
  uint32_t bins_per_bundle = params->bins_per_bundle();
  size_t label_size = compute_label_size(label_byte_count, *params);

  // Load all BinBundle data
  std::vector<std::vector<unsigned char>> bin_bundle_data;
  bin_bundle_data.reserve(bin_bundle_count);
  while (bin_bundle_count--) {
    bin_bundle_data.push_back(::apsi::util::read_from_stream(bin_in));
  }

  // Use multiple threads to recreate the BinBundles
  ::apsi::ThreadPoolMgr tpm;

  std::vector<std::mutex> bundle_idx_mtxs(sender_cnt_db->bin_bundles_.size());
  std::mutex bin_bundle_data_size_mtx;
  std::vector<std::future<void>> futures;
  for (size_t i = 0; i < bin_bundle_data.size(); i++) {
    futures.push_back(tpm.thread_pool().enqueue([&, i]() {
      BinBundle bb(sender_cnt_db->crypto_context_, label_size, max_bin_size,
                   ps_low_degree, bins_per_bundle, compressed, stripped);
      auto bb_data = bb.load(bin_bundle_data[i]);

      // Clear the data buffer since we have now loaded the BinBundle
      bin_bundle_data[i].clear();

      // Check that the loaded bundle index is not out of range
      if (bb_data.first >= sender_cnt_db->bin_bundles_.size()) {
        SPDLOG_ERROR(
            "The bundle index of the loaded BinBundle ({}) exceeds the maximum "
            "({})",
            bb_data.first, params->bundle_idx_count() - 1);
        YACL_THROW("failed to load SenderDB");
      }

      // Add the loaded BinBundle to the correct location in bin_bundles_
      bundle_idx_mtxs[bb_data.first].lock();
      sender_cnt_db->bin_bundles_[bb_data.first].push_back(std::move(bb));
      bundle_idx_mtxs[bb_data.first].unlock();

      SPDLOG_DEBUG("Loaded BinBundle at bundle index {} ({} bytes)",
                   bb_data.first, bb_data.second);

      std::lock_guard<std::mutex> bin_bundle_data_size_lock(
          bin_bundle_data_size_mtx);
      bin_bundle_data_size += bb_data.second;
    }));
  }

  // Wait for the tasks to finish
  for (auto& f : futures) {
    f.get();
  }

  size_t total_size = sender_cnt_db_proto.ByteSizeLong() + bin_bundle_data_size;
  SPDLOG_DEBUG("Loaded SenderDB with {} items ({} bytes)",
               sender_cnt_db->get_item_count(), total_size);

  // Make sure the BinBundle caches are valid
  sender_cnt_db->generate_caches();

  SPDLOG_DEBUG("Finished loading SenderDB");

  return {std::move(*sender_cnt_db), total_size};
}

}  // namespace psi::dkpir