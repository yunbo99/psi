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

#include "psi/algorithm/dkpir/entry.h"

#include "psi/algorithm/dkpir/common.h"
#include "psi/algorithm/dkpir/dk_pir.h"
#include "psi/algorithm/dkpir/sender_dispatcher.h"

namespace psi::dkpir {
void SenderOffline(const DkPirSenderOptions &options) {
  ::apsi::oprf::OPRFKey oprf_key;
  std::shared_ptr<::apsi::sender::SenderDB> sender_db;
  std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db;

  // GenerateSenderDB
  sender_db = psi::apsi_wrapper::GenerateSenderDB(
      options.sender_key_value_file, options.params_file,
      options.nonce_byte_count, options.compress, oprf_key);
  YACL_ENFORCE(sender_db != nullptr, "create sender_db from {} failed",
               options.sender_key_value_file);

  sender_cnt_db = psi::dkpir::GenerateSenderCntDB(options.sender_key_count_file,
                                                  options.params_file,
                                                  options.compress, oprf_key);

  YACL_ENFORCE(sender_cnt_db != nullptr, "create sender_db from {} failed",
               options.sender_key_count_file);

  // Try to save the SenderDB if a save file was given
  YACL_ENFORCE(psi::apsi_wrapper::TrySaveSenderDB(options.value_sdb_out_file,
                                                  sender_db, oprf_key),
               "Save sender_db to {} failed.", options.value_sdb_out_file);

  YACL_ENFORCE(psi::dkpir::TrySaveSenderCntDB(options.count_info_file,
                                              options.count_sdb_out_file,
                                              sender_cnt_db, oprf_key),
               "Save sender_cnt_db to {} failed.", options.count_sdb_out_file);
}

void SenderOnline(const DkPirSenderOptions &options,
                  const std::shared_ptr<yacl::link::Context> &lctx) {
  ::apsi::oprf::OPRFKey oprf_key;
  std::shared_ptr<::apsi::sender::SenderDB> sender_db;
  std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db;

  sender_db = psi::apsi_wrapper::TryLoadSenderDB(options.value_sdb_out_file,
                                                 options.params_file, oprf_key);
  YACL_ENFORCE(sender_db != nullptr, "load old sender_db from {} failed",
               options.value_sdb_out_file);

  sender_cnt_db = psi::dkpir::TryLoadSenderCntDB(options.count_info_file,
                                                 options.count_sdb_out_file);

  YACL_ENFORCE(sender_cnt_db != nullptr,
               "load old sender_cnt_db from {} and {} failed",
               options.count_info_file, options.count_sdb_out_file);

  std::atomic<bool> stop = false;

  psi::dkpir::DkPirSenderDispatcher dispatcher(sender_db, sender_cnt_db,
                                               oprf_key);

  lctx->ConnectToMesh();
  dispatcher.run(stop, lctx, options.streaming_result);

  dispatcher.CheckCount(lctx);
}

int ReceiverOnline(const DkPirReceiverOptions &options,
                   const std::shared_ptr<yacl::link::Context> &lctx) {
  std::unique_ptr<::apsi::network::NetworkChannel> channel;

  lctx->ConnectToMesh();
  channel = std::make_unique<psi::apsi_wrapper::YaclChannel>(lctx);

  // reciver must own the same params_file as sender.
  std::unique_ptr<::apsi::PSIParams> params =
      psi::apsi_wrapper::BuildPsiParams(options.params_file);

  ::apsi::ThreadPoolMgr::SetThreadCount(options.threads);
  SPDLOG_INFO("Setting thread count to {}",
              ::apsi::ThreadPoolMgr::GetThreadCount());

  psi::dkpir::DkPirReceiver receiver(*params);

  auto [query_data, orig_items] =
      psi::apsi_wrapper::load_db_with_orig_items(options.tmp_query_file);

  if (!query_data ||
      !std::holds_alternative<psi::apsi_wrapper::UnlabeledData>(*query_data)) {
    // Failed to read query file
    SPDLOG_ERROR("Failed to read query file: terminating");
    return -1;
  }

  auto &items = std::get<psi::apsi_wrapper::UnlabeledData>(*query_data);

  std::vector<::apsi::Item> items_vec(items.begin(), items.end());
  std::vector<::apsi::HashedItem> oprf_items;
  std::vector<::apsi::LabelKey> label_keys;

  try {
    SPDLOG_INFO("Sending OPRF request for {} items ", items_vec.size());
    tie(oprf_items, label_keys) =
        psi::dkpir::DkPirReceiver::RequestOPRF(items_vec, *channel);
    SPDLOG_INFO("Received OPRF response for {} items", items_vec.size());
  } catch (const std::exception &ex) {
    SPDLOG_WARN("OPRF request failed: {}", ex.what());
    return -1;
  }

  std::vector<::apsi::receiver::MatchRecord> query_result;
  try {
    SPDLOG_INFO("Sending APSI query");
    query_result = receiver.request_query(oprf_items, label_keys, *channel,
                                          options.streaming_result);
    SPDLOG_INFO("Received APSI query response");
  } catch (const std::exception &ex) {
    SPDLOG_WARN("Failed sending APSI query: {}", ex.what());
    return -1;
  }

  psi::dkpir::print_intersection_results(orig_items, items_vec, query_result,
                                         options.apsi_output_file);

  ::seal::Ciphertext count_ct = receiver.ReceiveCiphertext(lctx);

  psi::apsi_wrapper::Receiver::RequestOPRF(
      {}, *channel, std::numeric_limits<uint32_t>::max());

  // Receiver convert result file
  psi::apsi_wrapper::ApsiCsvConverter recevier_result_converter(
      options.apsi_output_file, "key", {"value"});

  uint64_t cnt =
      ::seal::util::safe_cast<uint64_t>(recevier_result_converter.ExtractResult(
          options.result_file, options.key, options.labels));

  SPDLOG_INFO("Receiver has received {} rows in total.", cnt);

  // 处理行数的密文 以解密为主
  receiver.SendCount(cnt, lctx, count_ct);

  return 0;
}

}  // namespace psi::dkpir