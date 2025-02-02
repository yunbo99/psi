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

#include "psi/algorithm/dkpir/dk_pir.h"

#include <thread>

namespace psi::dkpir {

void DkPirSender::RunQuery(const psi::dkpir::DkPirQuery &query,
                           psi::apsi_wrapper::YaclChannel &chl,
                           const std::vector<uint64_t> &poly_matrix1,
                           const std::vector<uint64_t> &poly_matrix2) {
  if (!query) {
    APSI_LOG_ERROR("Failed to process query request: query is invalid");
    throw std::invalid_argument("query is invalid");
  }

  // We use a custom SEAL memory that is freed after the query is done
  auto pool = ::seal::MemoryManager::GetPool(::seal::mm_force_new);

  ::apsi::ThreadPoolMgr tpm;

  auto sender_cnt_db = query.sender_cnt_db();
  auto sender_cnt_db_lock = sender_cnt_db->get_reader_lock();

  STOPWATCH(::apsi::util::sender_stopwatch, "DkPirSender::RunQuery");
  APSI_LOG_INFO("Start processing query request on database with "
                << sender_cnt_db->get_item_count() << " items");

  // Copy over the CryptoContext from psi::dkpir::SenderCntDB; set the
  // Evaluator for this local instance. Relinearization keys may not have been
  // included in the query. In that case query.relin_keys() simply holds an
  // empty seal::RelinKeys instance. There is no problem with the below call to
  // CryptoContext::set_evaluator.
  ::apsi::CryptoContext crypto_context(sender_cnt_db->get_crypto_context());
  crypto_context.set_evaluator(query.relin_keys());

  // Get the PSIParams
  ::apsi::PSIParams params(sender_cnt_db->get_params());

  uint32_t bundle_idx_count = params.bundle_idx_count();
  uint32_t max_items_per_bin = params.table_params().max_items_per_bin;

  // Extract the PowersDag
  ::apsi::PowersDag pd = query.pd();

  // For each bundle index i, we need a vector of powers of the query Qᵢ. We
  // need powers all the way up to Qᵢ^max_items_per_bin. We don't store the
  // zeroth power. If Paterson-Stockmeyer is used, then only a subset of the
  // powers will be populated.
  std::vector<CiphertextPowers> all_powers(bundle_idx_count);

  // Initialize powers
  for (CiphertextPowers &powers : all_powers) {
    // The + 1 is because we index by power. The 0th power is a dummy value. I
    // promise this makes things easier to read.
    size_t powers_size = static_cast<size_t>(max_items_per_bin) + 1;
    powers.reserve(powers_size);
    for (size_t i = 0; i < powers_size; i++) {
      powers.emplace_back(pool);
    }
  }

  // Load inputs provided in the query
  for (auto &q : query.data()) {
    // The exponent of all the query powers we're about to iterate through
    size_t exponent = static_cast<size_t>(q.first);

    // Load Qᵢᵉ for all bundle indices i, where e is the exponent specified
    // above
    for (size_t bundle_idx = 0; bundle_idx < all_powers.size(); bundle_idx++) {
      // Load input^power to all_powers[bundle_idx][exponent]
      APSI_LOG_DEBUG("Extracting query ciphertext power "
                     << exponent << " for bundle index " << bundle_idx);
      all_powers[bundle_idx][exponent] = std::move(q.second[bundle_idx]);
    }
  }

  // Compute query powers for the bundle indexes
  for (size_t bundle_idx = 0; bundle_idx < bundle_idx_count; bundle_idx++) {
    ComputePowers(sender_cnt_db, crypto_context, all_powers, pd,
                  static_cast<uint32_t>(bundle_idx), pool);
  }

  APSI_LOG_DEBUG("Finished computing powers for all bundle indices");
  APSI_LOG_DEBUG("Start processing bin bundle caches");

  std::vector<std::future<void>> futures;

  std::vector<std::vector<::seal::Ciphertext>> count_ciphertexts;
  std::mutex cts_mutex;

  for (size_t bundle_idx = 0; bundle_idx < bundle_idx_count; bundle_idx++) {
    auto bundle_caches =
        sender_cnt_db->get_cache_at(static_cast<uint32_t>(bundle_idx));
    for (auto &cache : bundle_caches) {
      futures.push_back(tpm.thread_pool().enqueue([&, bundle_idx, cache]() {
        ProcessBinBundleCache(sender_cnt_db, crypto_context, cache, all_powers,
                              static_cast<uint32_t>(bundle_idx), pool,
                              cts_mutex, count_ciphertexts);
      }));
    }
  }

  // Wait until all bin bundle caches have been processed
  for (auto &future : futures) {
    future.get();
  }

  APSI_LOG_DEBUG("Finished processing bin bundle caches");
  APSI_LOG_DEBUG("Start computing polynomial");

  // 伪代码

  auto seal_context = crypto_context.seal_context();
  auto evaluator = crypto_context.evaluator();
  ::seal::Ciphertext count(*seal_context, pool);

  APSI_LOG_DEBUG("Start adding all count ciphertexts");

  for (auto &cts : count_ciphertexts) {
    for (auto &ct : cts) {
      evaluator->add_inplace(count, ct);
    }
  }

  APSI_LOG_DEBUG("Finish adding all count ciphertexts");

  auto encoder = crypto_context.encoder();

  ::seal::Plaintext plain_poly_matrix1, plain_poly_matrix2;

  encoder->encode(poly_matrix1, plain_poly_matrix1);
  encoder->encode(poly_matrix2, plain_poly_matrix2);

  // evaluator->multiply_plain_inplace(count, plain_poly_matrix1);
  // evaluator->add_plain_inplace(count, plain_poly_matrix2);

  APSI_LOG_DEBUG("Finish computing polynomial");

  std::stringstream ss;
  count.save(ss, query.compr_mode());
  // count_ciphertexts[0][0].save(ss, query.compr_mode());

  std::shared_ptr<yacl::link::Context> lctx = chl.get_lctx();
  lctx->Send(lctx->NextRank(), ss.str(), "count_ct");
}

void DkPirSender::ComputePowers(
    const std::shared_ptr<psi::dkpir::SenderCntDB> &sender_cnt_db,
    const ::apsi::CryptoContext &crypto_context,
    std::vector<CiphertextPowers> &all_powers, const ::apsi::PowersDag &pd,
    uint32_t bundle_idx, ::seal::MemoryPoolHandle &pool) {
  STOPWATCH(sender_stopwatch, "Sender::ComputePowers");
  auto bundle_caches = sender_cnt_db->get_cache_at(bundle_idx);
  if (!bundle_caches.size()) {
    return;
  }

  // Compute all powers of the query
  APSI_LOG_DEBUG("Computing all query ciphertext powers for bundle index "
                 << bundle_idx);

  auto evaluator = crypto_context.evaluator();
  auto relin_keys = crypto_context.relin_keys();

  CiphertextPowers &powers_at_this_bundle_idx = all_powers[bundle_idx];
  bool relinearize = crypto_context.seal_context()->using_keyswitching();
  pd.parallel_apply([&](const ::apsi::PowersDag::PowersNode &node) {
    if (!node.is_source()) {
      auto parents = node.parents;
      ::seal::Ciphertext prod(pool);
      if (parents.first == parents.second) {
        evaluator->square(powers_at_this_bundle_idx[parents.first], prod, pool);
      } else {
        evaluator->multiply(powers_at_this_bundle_idx[parents.first],
                            powers_at_this_bundle_idx[parents.second], prod,
                            pool);
      }
      if (relinearize) {
        evaluator->relinearize_inplace(prod, *relin_keys, pool);
      }
      powers_at_this_bundle_idx[node.power] = std::move(prod);
    }
  });

  // Now that all powers of the ciphertext have been computed, we need to
  // transform them to NTT form. This will substantially improve the polynomial
  // evaluation, because the plaintext polynomials are already in NTT
  // transformed form, and the ciphertexts are used repeatedly for each bin
  // bundle at this index. This computation is separate from the graph
  // processing above, because the multiplications must all be done before
  // transforming to NTT form. We omit the first ciphertext in the vector,
  // because it corresponds to the zeroth power of the query and is included
  // only for convenience of the indexing; the ciphertext is actually not
  // set or valid for use.

  ::apsi::ThreadPoolMgr tpm;

  // After computing all powers we will modulus switch down to parameters that
  // one more level for low powers than for high powers; same choice must be
  // used when encoding/NTT transforming the ::apsi::sender::SenderDB data.
  auto high_powers_parms_id =
      get_parms_id_for_chain_idx(*crypto_context.seal_context(), 1);
  auto low_powers_parms_id =
      get_parms_id_for_chain_idx(*crypto_context.seal_context(), 2);

  uint32_t ps_low_degree =
      sender_cnt_db->get_params().query_params().ps_low_degree;

  std::vector<std::future<void>> futures;
  for (uint32_t power : pd.target_powers()) {
    futures.push_back(tpm.thread_pool().enqueue([&, power]() {
      if (!ps_low_degree) {
        // Only one ciphertext-plaintext multiplication is needed after this
        evaluator->mod_switch_to_inplace(powers_at_this_bundle_idx[power],
                                         high_powers_parms_id, pool);

        // All powers must be in NTT form
        evaluator->transform_to_ntt_inplace(powers_at_this_bundle_idx[power]);
      } else {
        if (power <= ps_low_degree) {
          // Low powers must be at a higher level than high powers
          evaluator->mod_switch_to_inplace(powers_at_this_bundle_idx[power],
                                           low_powers_parms_id, pool);

          // Low powers must be in NTT form
          evaluator->transform_to_ntt_inplace(powers_at_this_bundle_idx[power]);
        } else {
          // High powers are only modulus switched
          evaluator->mod_switch_to_inplace(powers_at_this_bundle_idx[power],
                                           high_powers_parms_id, pool);
        }
      }
    }));
  }

  for (auto &f : futures) {
    f.get();
  }
}

void DkPirSender::ProcessBinBundleCache(
    const std::shared_ptr<psi::dkpir::SenderCntDB> &sender_cnt_db,
    const ::apsi::CryptoContext &crypto_context,
    std::reference_wrapper<const ::apsi::sender::BinBundleCache> cache,
    std::vector<CiphertextPowers> &all_powers, uint32_t bundle_idx,
    ::seal::MemoryPoolHandle &pool, std::mutex &cts_mutex,
    std::vector<std::vector<::seal::Ciphertext>> &count_ciphertexts) {
  STOPWATCH(sender_stopwatch, "DkPirSender::ProcessBinBundleCache");

  std::vector<::seal::Ciphertext> cts;

  // Determine if we use Paterson-Stockmeyer or not
  uint32_t ps_low_degree =
      sender_cnt_db->get_params().query_params().ps_low_degree;
  uint32_t degree;
  bool using_ps;

  for (const auto &interp_polyn : cache.get().batched_interp_polyns) {
    // Compute the label result and move to rp
    degree =
        ::seal::util::safe_cast<uint32_t>(interp_polyn.batched_coeffs.size()) -
        1;
    using_ps = (ps_low_degree > 1) && (ps_low_degree < degree);
    if (using_ps) {
      cts.push_back(interp_polyn.eval_patstock(
          crypto_context, all_powers[bundle_idx], ps_low_degree, pool));
    } else {
      cts.push_back(interp_polyn.eval(all_powers[bundle_idx], pool));
    }
  }

  std::lock_guard<std::mutex> lock(cts_mutex);
  count_ciphertexts.emplace_back(std::move(cts));
}

::seal::Ciphertext DkPirReceiver::ReceiveCiphertext(
    const std::shared_ptr<yacl::link::Context> &lctx) {
  auto pool = ::seal::MemoryManager::GetPool(::seal::mm_force_new);
  ::seal::Ciphertext count_ct(pool);
  ::apsi::CryptoContext crypto_context = get_crypto_context();
  std::stringstream ss_ct;

  ss_ct << std::string_view(lctx->Recv(lctx->NextRank(), "count_ct"));

  count_ct.load(*crypto_context.seal_context(), ss_ct);

  return count_ct;
}

// 应该先接收来自sender的消息，再进行后续的处理
void DkPirReceiver::SendCount(uint64_t count,
                              const std::shared_ptr<yacl::link::Context> &lctx,
                              ::seal::Ciphertext count_ct) {
  ::apsi::CryptoContext crypto_context = get_crypto_context();

  ::seal::Plaintext result;
  crypto_context.decryptor()->decrypt(count_ct, result);

  std::stringstream ss_pt;
  result.save(ss_pt);
  auto buffer = yacl::Buffer(&count, sizeof(count));

  lctx->Send(lctx->NextRank(), buffer, "count_sum");
  lctx->Send(lctx->NextRank(), ss_pt.str(), "count_sum_pt");
}

}  // namespace psi::dkpir