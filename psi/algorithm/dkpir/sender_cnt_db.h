// Copyright 2024 Zhongyun Lin, Meituan
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

#pragma once
#include <vector>

#include "apsi/bin_bundle.h"
#include "apsi/crypto_context.h"
#include "apsi/item.h"
#include "apsi/oprf/oprf_sender.h"
#include "apsi/psi_params.h"
#include "seal/util/locks.h"

namespace psi::dkpir {

using PSIParams = ::apsi::PSIParams;
using OPRFKey = ::apsi::oprf::OPRFKey;
using CryptoContext = ::apsi::CryptoContext;
using BinBundle = ::apsi::sender::BinBundle;

using Item = ::apsi::Item;
using Label = ::apsi::Label;
using HashedItem = ::apsi::HashedItem;
using EncryptedLabel = ::apsi::EncryptedLabel;

class SenderCntDB {
 public:
  /**
  Creates a new SenderCntDB.
  */
  SenderCntDB(const PSIParams& params, size_t label_byte_count = 0,
              bool compressed = false);

  SenderCntDB(const PSIParams& params, const OPRFKey& oprf_key,
              size_t label_byte_count = 0, bool compressed = false);

  /**
  Creates a new SenderCntDB by moving from an existing one.
  */
  SenderCntDB(SenderCntDB&& source);

  /**
  Moves an existing SenderCntDB to the current one.
  */
  SenderCntDB& operator=(SenderCntDB&& source);

  /**
  Clears the database. Every item and label will be removed. The OPRF key is
  unchanged.
  */
  void clear();

  /**
  Returns the label byte count.
  */
  size_t get_label_byte_count() const { return label_byte_count_; }

  /**
  Indicates whether SEAL plaintexts are compressed in memory.
  */
  bool is_compressed() const { return compressed_; }

  /**
  Indicates whether the SenderCntDB has been stripped of all information not
  needed for serving a query.
  */
  bool is_stripped() const { return stripped_; }

  /**
  Strips the SenderCntDB of all information not needed for serving a query.
  Returns a copy of the OPRF key and clears it from the SenderCntDB. This
  function may not be used in practice.
  */
  OPRFKey strip();

  /**
  Returns a copy of the OPRF key.
  */
  OPRFKey get_oprf_key() const;

  /**
  Inserts the given data into the database. This function can be used only on a
  labeled SenderCntDB instance. If an item already exists in the database, its
  label is overwritten with the new label.
  */
  void insert_or_assign(const std::vector<std::pair<Item, Label>>& data);

  /**
  Clears the database and inserts the given data. This function can be used only
  on a labeled SenderDB instance.
  */
  void set_data(const std::vector<std::pair<Item, Label>>& data) {
    clear();
    insert_or_assign(data);
  }

  /**
  Returns whether the given item has been inserted in the SenderCntDB.
  */
  bool has_item(const Item& item) const;

  /**
  Returns the label associated to the given item in the database. Throws
  std::invalid_argument if the item does not appear in the database.
  */
  Label get_label(const Item& item) const;

  /**
  Returns a set of cache references corresponding to the bundles at the given
  bundle index. Even though this function returns a vector, the order has no
  significance. This function is meant for internal use.
  */
  auto get_cache_at(std::uint32_t bundle_idx)
      -> std::vector<
          std::reference_wrapper<const ::apsi::sender::BinBundleCache>>;

  /**
  Returns a reference to the PSI parameters for this SenderCntDB.
  */
  const PSIParams& get_params() const { return params_; }

  /**
  Returns a reference to the CryptoContext for this SenderCntDB.
  */
  const CryptoContext& get_crypto_context() const { return crypto_context_; }

  /**
  Returns a reference to the SEALContext for this SenderCntDB.
  */
  std::shared_ptr<seal::SEALContext> get_seal_context() const {
    return crypto_context_.seal_context();
  }

  /**
  Returns a reference to a set of item hashes already existing in the
  SenderCntDB.
  */
  const std::unordered_set<HashedItem>& get_hashed_items() const {
    return hashed_items_;
  }

  /**
  Returns the number of items in this SenderCntDB.
  */
  size_t get_item_count() const { return item_count_; }

  /**
  Returns the total number of bin bundles at a specific bundle index.
  */
  std::size_t get_bin_bundle_count(std::uint32_t bundle_idx) const;

  /**
  Returns the total number of bin bundles.
  */
  std::size_t get_bin_bundle_count() const;

  /**
  Returns how efficiently the SenderCntDB is packaged. A higher rate indicates
  better performance and a lower communication cost in a query execution.
  */
  double get_packing_rate() const;

  /**
  Obtains a scoped lock preventing the SenderCntDB from being changed.
  */
  seal::util::ReaderLock get_reader_lock() const {
    return db_lock_.acquire_read();
  }

  /**
  Writes the SenderCntDB to two streams, one for the meta info and the other
  for BinBundle.
  */
  std::size_t save(std::ostream& info_out, std::ostream& bin_out) const;

  /**
  Reads the SenderCntDB from two streams, one for the meta info and the other
  for BinBundle.
  */
  static std::pair<SenderCntDB, size_t> Load(std::istream& info_in,
                                             std::istream& bin_in);

 private:
  seal::util::WriterLock get_writer_lock() { return db_lock_.acquire_write(); }

  void clear_internal();

  void generate_caches();

  /**
  The set of all items that have been inserted into the database
  */
  std::unordered_set<HashedItem> hashed_items_;

  /**
  The PSI parameters define the SEAL parameters, base field, item size, table
  size, etc.
  */
  PSIParams params_;

  /**
  Necessary for evaluating polynomials of Plaintexts.
  */
  CryptoContext crypto_context_;

  /**
  A read-write lock to protect the database from modification while in use.
  */
  mutable seal::util::ReaderWriterLocker db_lock_;

  /**
  Indicates the size of the label in bytes. A zero value indicates an unlabeled
  SenderCntDB.
  */
  size_t label_byte_count_;

  /**
  The number of items currently in the SenderDB.
  */
  size_t item_count_;

  /**
  Indicates whether SEAL plaintexts are compressed in memory.
  */
  bool compressed_;

  /**
  Indicates whether the SenderDB has been stripped of all information not needed
  for serving a query.
  */
  bool stripped_;

  /**
  All the BinBundles in the database, indexed by bundle index. The set
  (represented by a vector internally) at bundle index i contains all the
  BinBundles with bundle index i.
  */
  std::vector<std::vector<BinBundle>> bin_bundles_;

  /**
  Holds the OPRF key for this SenderDB.
  */
  OPRFKey oprf_key_;
};
}  // namespace psi::dkpir