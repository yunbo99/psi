// Copyright 2022 Ant Group Co., Ltd.
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

#include "psi/algorithm/ecdh/ecdh_psi.h"

#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "spdlog/spdlog.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

#include "psi/cryptor/cryptor_selector.h"
#include "psi/utils/batch_provider_impl.h"

namespace psi::ecdh {

constexpr int kLogBatchInterval = 10;

EcdhPsiContext::EcdhPsiContext(EcdhPsiOptions options)
    : options_(std::move(options)),
      id_(options_.link_ctx->PartyIdByRank(options_.link_ctx->Rank())) {
  YACL_ENFORCE(options_.link_ctx->WorldSize() == 2);

  main_link_ctx_ = options_.link_ctx;
  dual_mask_link_ctx_ = options_.link_ctx->Spawn();
}

void EcdhPsiContext::CheckConfig() {
  // Sanity check: the `target_rank` and 'curve_type' should match.
  std::string my_config =
      fmt::format("target_rank={},curve={}", options_.target_rank,
                  static_cast<int>(options_.ecc_cryptor->GetCurveType()));
  yacl::Buffer my_config_buf(my_config.c_str(), my_config.size());
  auto config_list =
      yacl::link::AllGather(main_link_ctx_, my_config_buf, "ECDHPSI:SANITY");
  auto peer_config = config_list[main_link_ctx_->NextRank()];
  YACL_ENFORCE(my_config_buf == peer_config,
               "EcdhPsiContext Config mismatch, mine={}, peer={}", my_config,
               peer_config.data<const char>());
}

void EcdhPsiContext::MaskSelf(
    const std::shared_ptr<IBasicBatchProvider>& batch_provider,
    uint64_t processed_item_cnt) {
  size_t batch_count = 0;
  size_t item_count = processed_item_cnt;
  bool read_next_batch = true;

  std::vector<std::string> batch_items;
  std::unordered_map<uint32_t, uint32_t> duplicate_item_cnt;
  while (processed_item_cnt > 0) {
    auto [read_batch_items, item_cnt] =
        batch_provider->ReadNextBatchWithDupCnt();

    if (read_batch_items.empty()) {
      YACL_ENFORCE_EQ(processed_item_cnt, 0U);
    }

    if (read_batch_items.size() <= processed_item_cnt) {
      processed_item_cnt -= read_batch_items.size();
    } else {
      read_next_batch = false;
      batch_items = std::vector<std::string>(
          read_batch_items.begin() + processed_item_cnt,
          read_batch_items.end());
      processed_item_cnt = 0;
      for (auto [index, cnt] : item_cnt) {
        if (index >= processed_item_cnt) {
          duplicate_item_cnt[index - processed_item_cnt] = cnt;
        }
      }
    }
  }

  while (true) {
    // NOTE: we still need to send one batch even there is no data.
    // This dummy batch is used to notify peer the end of data stream.
    if (read_next_batch) {
      std::tie(batch_items, duplicate_item_cnt) =
          batch_provider->ReadNextBatchWithDupCnt();
    } else {
      read_next_batch = true;
    }

    std::vector<std::string> masked_items;
    std::vector<std::string> hashed_masked_items;
    auto hashed_points = options_.ecc_cryptor->HashInputs(batch_items);
    auto masked_points = options_.ecc_cryptor->EccMask(hashed_points);
    masked_items = options_.ecc_cryptor->SerializeEcPoints(masked_points);

    // Send x^a.
    const auto tag = fmt::format("ECDHPSI:X^A:{}", batch_count);
    if (PeerCanTouchResults()) {
      if (!duplicate_item_cnt.empty()) {
        SPDLOG_INFO("send extra item cnt: {}", duplicate_item_cnt.size());
      }
      SendBatch(masked_items, duplicate_item_cnt, batch_count, tag);
    } else {
      SendBatch(masked_items, batch_count, tag);
    }

    if (batch_items.empty()) {
      SPDLOG_INFO("MaskSelf:{} --finished, batch_count={}, self_item_count={}",
                  Id(), batch_count, item_count);
      if (options_.statistics) {
        options_.statistics->self_item_count = item_count;
      }
      break;
    }

    if (options_.ecdh_logger) {
      hashed_masked_items =
          options_.ecc_cryptor->SerializeEcPoints(hashed_points);
      options_.ecdh_logger->Log(EcdhStage::MaskSelf,
                                options_.ecc_cryptor->GetPrivateKey(),
                                item_count, hashed_masked_items, masked_items);
    }
    item_count += batch_items.size();
    ++batch_count;

    if (batch_count % kLogBatchInterval == 0) {
      SPDLOG_INFO("MaskSelf:{}, batch_count={}, self_item_count={}", Id(),
                  batch_count, item_count);
    }
  }
}

void EcdhPsiContext::MaskPeer(
    const std::shared_ptr<IEcPointStore>& peer_ec_point_store) {
  size_t batch_count = 0;
  size_t item_count = 0;
  while (true) {
    // Fetch y^b.
    std::vector<std::string> peer_items;
    std::vector<std::string> dual_masked_peers;
    std::unordered_map<uint32_t, uint32_t> duplicate_item_cnt;
    const auto tag = fmt::format("ECDHPSI:Y^B:{}", batch_count);
    RecvBatch(&peer_items, &duplicate_item_cnt, batch_count, tag);
    if (!duplicate_item_cnt.empty()) {
      SPDLOG_INFO("recv extra item cnt: {}", duplicate_item_cnt.size());
    }

    auto peer_points = options_.ecc_cryptor->DeserializeEcPoints(peer_items);

    // Compute (y^b)^a.
    if (!peer_items.empty()) {
      // TODO: avoid mem copy
      const auto& masked_points = options_.ecc_cryptor->EccMask(peer_points);
      for (uint32_t i = 0; i != peer_points.size(); ++i) {
        const auto masked =
            options_.ecc_cryptor->SerializeEcPoint(masked_points[i]);
        // In the final comparison, we only send & compare `kFinalCompareBytes`
        // number of bytes.
        std::string cipher(
            masked.data<char>() + masked.size() - options_.dual_mask_size,
            options_.dual_mask_size);
        if (SelfCanTouchResults()) {
          // Store cipher of peer items for later intersection compute.
          peer_ec_point_store->Save(cipher, duplicate_item_cnt[i]);
        }
        dual_masked_peers.emplace_back(std::move(cipher));
      }

      if (SelfCanTouchResults()) {
        if (options_.recovery_manager) {
          peer_ec_point_store->Flush();
          options_.recovery_manager->UpdateEcdhDualMaskedItemPeerCount(
              peer_ec_point_store->ItemCount());
        }
      }
    }

    auto target_rank_str = [&, this]() {
      return options_.target_rank == yacl::link::kAllRank
                 ? "all"
                 : std::to_string(options_.target_rank);
    };

    // Should send out the dual masked items to peer.
    if (PeerCanTouchResults()) {
      if (batch_count == 0) {
        SPDLOG_INFO("SendDualMaskedItems to peer: {}, batch={}, begin...",
                    target_rank_str(), batch_count);
      }
      const auto tag = fmt::format("ECDHPSI:Y^B^A:{}", batch_count);
      // call non-block to avoid blocking each other with MaskSelf
      SendDualMaskedBatchNonBlock(dual_masked_peers, batch_count, tag);
      SPDLOG_INFO("SendDualMaskedItems to peer: {}, batch={}, end...",
                  target_rank_str(), batch_count);
      if (dual_masked_peers.empty()) {
        SPDLOG_INFO(
            "SendDualMaskedItems to peer: {}, batch_count={}, finished.",
            target_rank_str(), batch_count);
      }
    }

    if (peer_items.empty()) {
      SPDLOG_INFO("MaskPeer:{} --finished, batch_count={}, peer_item_count={}",
                  Id(), batch_count, item_count);
      if (options_.statistics) {
        options_.statistics->peer_item_count = item_count;
      }
      break;
    }
    if (options_.ecdh_logger) {
      options_.ecdh_logger->Log(EcdhStage::MaskPeer,
                                options_.ecc_cryptor->GetPrivateKey(),
                                item_count, peer_items, dual_masked_peers);
    }
    item_count += peer_items.size();
    batch_count++;

    if (batch_count % kLogBatchInterval == 0) {
      SPDLOG_INFO("MaskPeer:{}, batch_count={}, peer_item_count={}", Id(),
                  batch_count, item_count);
    }
  }
}

void EcdhPsiContext::RecvDualMaskedSelf(
    const std::shared_ptr<IEcPointStore>& self_ec_point_store) {
  if (!SelfCanTouchResults()) {
    return;
  }

  size_t item_count = 0;
  // Receive x^a^b.
  size_t batch_count = 0;
  while (true) {
    // TODO: avoid mem copy
    std::vector<std::string> masked_items;
    const auto tag = fmt::format("ECDHPSI:X^A^B:{}", batch_count);
    RecvDualMaskedBatch(&masked_items, batch_count, tag);
    if (options_.ecdh_logger) {
      options_.ecdh_logger->Log(EcdhStage::RecvDualMaskedSelf,
                                options_.ecc_cryptor->GetPrivateKey(),
                                item_count, masked_items);
    }

    self_ec_point_store->Save(masked_items);

    if (masked_items.empty()) {
      SPDLOG_INFO(
          "RecvDualMaskedSelf:{} recv last batch finished, batch_count={}",
          Id(), batch_count);
      break;
    } else {
      if (options_.recovery_manager) {
        self_ec_point_store->Flush();
        options_.recovery_manager->UpdateEcdhDualMaskedItemSelfCount(
            self_ec_point_store->ItemCount());
      }
    }

    item_count += masked_items.size();
    batch_count++;

    // Call the hook.
    if (options_.on_batch_finished) {
      options_.on_batch_finished(batch_count);
    }
  }
}

namespace {

template <typename T>
PsiDataBatch BatchData(
    const std::vector<T>& batch_items,
    const std::unordered_map<uint32_t, uint32_t>& duplicate_item_cnt,
    std::string_view type, int32_t batch_idx) {
  PsiDataBatch batch;
  batch.is_last_batch = batch_items.empty();
  batch.item_num = batch_items.size();
  batch.batch_index = batch_idx;
  batch.type = type;
  if (!batch_items.empty()) {
    batch.flatten_bytes.reserve(batch_items.size() * batch_items[0].size());
    for (const auto& item : batch_items) {
      batch.flatten_bytes.append(item);
    }
    for (const auto& [idx, cnt] : duplicate_item_cnt) {
      batch.duplicate_item_cnt[idx] = cnt;
    }
  }
  return batch;
}

template <typename T>
PsiDataBatch BatchData(const std::vector<T>& batch_items, std::string_view type,
                       int32_t batch_idx) {
  return BatchData(batch_items, std::unordered_map<uint32_t, uint32_t>(), type,
                   batch_idx);
}

template <typename T>
void SendBatchImpl(
    const std::vector<T>& batch_items,
    const std::unordered_map<uint32_t, uint32_t>& duplicate_item_cnt,
    const std::shared_ptr<yacl::link::Context>& link_ctx, std::string_view type,
    int32_t batch_idx, std::string_view tag) {
  auto batch = BatchData<T>(batch_items, duplicate_item_cnt, type, batch_idx);
  link_ctx->SendAsyncThrottled(link_ctx->NextRank(), batch.Serialize(), tag);
}

template <typename T>
void SendBatchImpl(const std::vector<T>& batch_items,
                   const std::shared_ptr<yacl::link::Context>& link_ctx,
                   std::string_view type, int32_t batch_idx,
                   std::string_view tag) {
  SendBatchImpl(batch_items, std::unordered_map<uint32_t, uint32_t>(), link_ctx,
                type, batch_idx, tag);
}

template <typename T>
void SendBatchNonBlockImpl(
    const std::vector<T>& batch_items,
    const std::unordered_map<uint32_t, uint32_t>& duplicate_item_cnt,
    const std::shared_ptr<yacl::link::Context>& link_ctx, std::string_view type,
    int32_t batch_idx, std::string_view tag) {
  auto batch = BatchData<T>(batch_items, duplicate_item_cnt, type, batch_idx);
  link_ctx->SendAsync(link_ctx->NextRank(), batch.Serialize(), tag);
}
template <typename T>
void SendBatchNonBlockImpl(const std::vector<T>& batch_items,
                           const std::shared_ptr<yacl::link::Context>& link_ctx,
                           std::string_view type, int32_t batch_idx,
                           std::string_view tag) {
  SendBatchNonBlockImpl(batch_items, std::unordered_map<uint32_t, uint32_t>(),
                        link_ctx, type, batch_idx, tag);
}

void RecvBatchImpl(const std::shared_ptr<yacl::link::Context>& link_ctx,
                   int32_t batch_idx, std::string_view tag,
                   std::vector<std::string>* items) {
  PsiDataBatch batch =
      PsiDataBatch::Deserialize(link_ctx->Recv(link_ctx->NextRank(), tag));

  YACL_ENFORCE(batch.batch_index == batch_idx, "Expected batch {}, but got {} ",
               batch_idx, batch.batch_index);

  if (batch.item_num > 0) {
    auto item_size = batch.flatten_bytes.size() / batch.item_num;
    for (size_t i = 0; i < batch.item_num; ++i) {
      items->emplace_back(batch.flatten_bytes.substr(i * item_size, item_size));
    }
  }
}

void RecvBatchImpl(const std::shared_ptr<yacl::link::Context>& link_ctx,
                   int32_t batch_idx, std::string_view tag,
                   std::vector<std::string>& items,
                   std::unordered_map<uint32_t, uint32_t>& duplicate_item_cnt) {
  PsiDataBatch batch =
      PsiDataBatch::Deserialize(link_ctx->Recv(link_ctx->NextRank(), tag));

  YACL_ENFORCE(batch.batch_index == batch_idx, "Expected batch {}, but got {} ",
               batch_idx, batch.batch_index);

  if (batch.item_num > 0) {
    auto item_size = batch.flatten_bytes.size() / batch.item_num;
    for (size_t i = 0; i < batch.item_num; ++i) {
      items.emplace_back(batch.flatten_bytes.substr(i * item_size, item_size));
    }
    for (const auto& [idx, cnt] : batch.duplicate_item_cnt) {
      duplicate_item_cnt[idx] = cnt;
    }
  }
}

};  // namespace

void EcdhPsiContext::SendBatch(
    const std::vector<std::string>& batch_items,
    const std::unordered_map<uint32_t, uint32_t>& duplicate_item_cnt,
    int32_t batch_idx, std::string_view tag) {
  SendBatchImpl(batch_items, duplicate_item_cnt, main_link_ctx_, "enc",
                batch_idx, tag);
}
void EcdhPsiContext::SendBatch(const std::vector<std::string>& batch_items,
                               int32_t batch_idx, std::string_view tag) {
  SendBatchImpl(batch_items, main_link_ctx_, "enc", batch_idx, tag);
}

void EcdhPsiContext::SendBatch(
    const std::vector<std::string_view>& batch_items,
    const std::unordered_map<uint32_t, uint32_t>& duplicate_item_cnt,
    int32_t batch_idx, std::string_view tag) {
  SendBatchImpl(batch_items, duplicate_item_cnt, main_link_ctx_, "enc",
                batch_idx, tag);
}
void EcdhPsiContext::SendBatch(const std::vector<std::string_view>& batch_items,
                               int32_t batch_idx, std::string_view tag) {
  SendBatchImpl(batch_items, main_link_ctx_, "enc", batch_idx, tag);
}

void EcdhPsiContext::RecvBatch(
    std::vector<std::string>* items,
    std::unordered_map<uint32_t, uint32_t>* duplicate_item_cnt,
    int32_t batch_idx, std::string_view tag) {
  RecvBatchImpl(main_link_ctx_, batch_idx, tag, *items, *duplicate_item_cnt);
}
void EcdhPsiContext::RecvBatch(std::vector<std::string>* items,
                               int32_t batch_idx, std::string_view tag) {
  RecvBatchImpl(main_link_ctx_, batch_idx, tag, items);
}

void EcdhPsiContext::SendDualMaskedBatch(
    const std::vector<std::string>& batch_items, int32_t batch_idx,
    std::string_view tag) {
  SendBatchImpl(batch_items, dual_mask_link_ctx_, "dual.enc", batch_idx, tag);
}

void EcdhPsiContext::SendDualMaskedBatch(
    const std::vector<std::string_view>& batch_items, int32_t batch_idx,
    std::string_view tag) {
  SendBatchImpl(batch_items, dual_mask_link_ctx_, "dual.enc", batch_idx, tag);
}

void EcdhPsiContext::SendDualMaskedBatchNonBlock(
    const std::vector<std::string>& batch_items, int32_t batch_idx,
    std::string_view tag) {
  SendBatchNonBlockImpl(batch_items, dual_mask_link_ctx_, "dual.enc", batch_idx,
                        tag);
}

void EcdhPsiContext::RecvDualMaskedBatch(std::vector<std::string>* items,
                                         int32_t batch_idx,
                                         std::string_view tag) {
  RecvBatchImpl(dual_mask_link_ctx_, batch_idx, tag, items);
}

void RunEcdhPsi(const EcdhPsiOptions& options,
                const std::shared_ptr<IBasicBatchProvider>& batch_provider,
                const std::shared_ptr<IEcPointStore>& self_ec_point_store,
                const std::shared_ptr<IEcPointStore>& peer_ec_point_store) {
  YACL_ENFORCE(options.link_ctx->WorldSize() == 2);
  YACL_ENFORCE(batch_provider != nullptr && self_ec_point_store != nullptr &&
               peer_ec_point_store != nullptr);

  EcdhPsiContext handler(options);
  handler.CheckConfig();

  uint64_t processed_item_cnt = 0;
  if (options.recovery_manager) {
    if (handler.SelfCanTouchResults() && handler.PeerCanTouchResults()) {
      processed_item_cnt =
          std::min(options.recovery_manager->ecdh_dual_masked_cnt_from_peer(),
                   options.recovery_manager->checkpoint()
                       .ecdh_dual_masked_item_self_count());
    } else if (handler.SelfCanTouchResults() &&
               !handler.PeerCanTouchResults()) {
      processed_item_cnt = options.recovery_manager->checkpoint()
                               .ecdh_dual_masked_item_self_count();
    } else {
      processed_item_cnt =
          options.recovery_manager->ecdh_dual_masked_cnt_from_peer();
    }

    SPDLOG_INFO("processed_item_cnt = {}", processed_item_cnt);
  }

  std::future<void> f_mask_self = std::async([&] {
    SPDLOG_INFO("ID {}: MaskSelf begin...", handler.Id());
    handler.MaskSelf(batch_provider, processed_item_cnt);
    SPDLOG_INFO("ID {}: MaskSelf finished.", handler.Id());
  });
  std::future<void> f_mask_peer = std::async([&] {
    SPDLOG_INFO("ID {}: MaskPeer begin...", handler.Id());
    handler.MaskPeer(peer_ec_point_store);
    SPDLOG_INFO("ID {}: MaskPeer finished.", handler.Id());
  });
  std::future<void> f_recv_peer = std::async([&] {
    SPDLOG_INFO("ID {}: RecvDualMaskedSelf begin...", handler.Id());
    handler.RecvDualMaskedSelf(self_ec_point_store);
    SPDLOG_INFO("ID {}: RecvDualMaskedSelf finished.", handler.Id());
  });

  // Wait for end of logic flows or exceptions.
  // Note: exception_ptr is `shared_ptr` style, hence could be used to prolong
  // the lifetime of pointed exceptions.
  std::exception_ptr mask_self_exptr = nullptr;
  std::exception_ptr mask_peer_exptr = nullptr;
  std::exception_ptr recv_peer_exptr = nullptr;

  try {
    f_mask_self.get();
  } catch (const std::exception& e) {
    mask_self_exptr = std::current_exception();
    SPDLOG_ERROR("ID {}: Error in MaskSelf: {}", handler.Id(), e.what());
  }

  try {
    f_mask_peer.get();
  } catch (const std::exception& e) {
    mask_peer_exptr = std::current_exception();
    SPDLOG_ERROR("ID {}: Error in MaskPeer: {}", handler.Id(), e.what());
  }

  try {
    f_recv_peer.get();
  } catch (const std::exception& e) {
    recv_peer_exptr = std::current_exception();
    SPDLOG_ERROR("ID {}: Error in RecvDualMaskedSelf: {}", handler.Id(),
                 e.what());
  }

  if (mask_self_exptr) {
    std::rethrow_exception(mask_self_exptr);
  }
  if (mask_peer_exptr) {
    std::rethrow_exception(mask_peer_exptr);
  }
  if (recv_peer_exptr) {
    std::rethrow_exception(recv_peer_exptr);
  }
}

std::vector<std::string> RunEcdhPsi(
    const std::shared_ptr<yacl::link::Context>& link_ctx,
    const std::vector<std::string>& items, size_t target_rank, CurveType curve,
    size_t batch_size) {
  EcdhPsiOptions options;
  options.ecc_cryptor = CreateEccCryptor(curve);
  options.link_ctx = link_ctx;
  options.target_rank = target_rank;
  options.batch_size = batch_size;

  auto self_ec_point_store = std::make_shared<MemoryEcPointStore>();
  auto peer_ec_point_store = std::make_shared<MemoryEcPointStore>();
  auto batch_provider =
      std::make_shared<MemoryBatchProvider>(items, batch_size);

  RunEcdhPsi(options, batch_provider, self_ec_point_store, peer_ec_point_store);

  // Originally we should setup a hashset for peer results.
  // But tests show that when items_count > 10,000,000, the performance of
  // |std::unordered_set| or |absl::flat_hash_set| drops significantly.
  // Besides, these hashset containers require more memory.
  // Here we choose the compact data structure and stable find costs.
  std::vector<std::string> ret;
  std::vector<std::string> peer_results(peer_ec_point_store->content());
  std::sort(peer_results.begin(), peer_results.end());
  const auto& self_results = self_ec_point_store->content();
  for (uint32_t index = 0; index < self_results.size(); index++) {
    if (std::binary_search(peer_results.begin(), peer_results.end(),
                           self_results[index])) {
      YACL_ENFORCE(index < items.size());
      ret.push_back(items[index]);
    }
  }
  return ret;
}

}  // namespace psi::ecdh
