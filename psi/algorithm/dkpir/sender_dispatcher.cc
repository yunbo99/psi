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

#include "psi/algorithm/dkpir/sender_dispatcher.h"

#include "apsi/requests.h"
#include "spdlog/spdlog.h"
#include "yacl/base/exception.h"

#include "psi/algorithm/dkpir/query.h"


using namespace std::chrono_literals;

namespace psi::dkpir {
DkPirSenderDispatcher::DkPirSenderDispatcher(
    std::shared_ptr<::apsi::sender::SenderDB> sender_db,
    std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db,
    ::apsi::oprf::OPRFKey oprf_key)
    : sender_db_(std::move(sender_db)),
      sender_cnt_db_(std::move(sender_cnt_db)),
      oprf_key_(std::move(oprf_key)) {
  if (!sender_db_ || !sender_cnt_db_) {
    YACL_THROW("sender_db or sender_cnt_db is not set");
  }

  // If SenderDB is not stripped, the OPRF key it holds must be equal to the
  // provided oprf_key
  if (!sender_db_->is_stripped() && oprf_key_ != sender_db_->get_oprf_key()) {
    SPDLOG_ERROR(
        "Failed to create DkPirSenderDispatcher: SenderDB OPRF key differs "
        "from the given OPRF key");
    YACL_THROW("mismatching OPRF keys");
  }

  ::apsi::CryptoContext crypto_context(sender_db_->get_crypto_context());
  auto encoder = crypto_context.encoder();
  uint64_t slot_count = encoder->slot_count();
  poly_matrix1_.resize(slot_count, 2ULL);
  poly_matrix2_.resize(slot_count, 1ULL);
}

void DkPirSenderDispatcher::run(std::atomic<bool> &stop,
                                std::shared_ptr<yacl::link::Context> lctx,
                                bool streaming_result) {
  psi::apsi_wrapper::YaclChannel chl(lctx);

  auto seal_context = sender_db_->get_seal_context();

  bool logged_waiting = false;
  while (!stop) {
    std::unique_ptr<::apsi::network::SenderOperation> sop;
    if (!(sop = chl.receive_operation(seal_context))) {
      if (!logged_waiting) {
        // We want to log 'Waiting' only once, even if we have to wait
        // for several sleeps. And only once after processing a request as
        // well.
        logged_waiting = true;
        APSI_LOG_INFO("Waiting for request from Receiver");
      }

      std::this_thread::sleep_for(50ms);
      continue;
    }

    switch (sop->type()) {
      case ::apsi::network::SenderOperationType::sop_parms:
        APSI_LOG_INFO("Received parameter request");
        dispatch_parms(std::move(sop), chl);
        break;

      case ::apsi::network::SenderOperationType::sop_oprf:
        APSI_LOG_INFO("Received OPRF request");
        dispatch_oprf(std::move(sop), chl, stop);
        break;

      case ::apsi::network::SenderOperationType::sop_query:
        APSI_LOG_INFO("Received query");
        dispatch_query(std::move(sop), chl, streaming_result);
        break;

      default:
        // We should never reach this point
        throw std::runtime_error("invalid operation");
    }

    logged_waiting = false;
  }
}

void DkPirSenderDispatcher::dispatch_parms(
    std::unique_ptr<::apsi::network::SenderOperation> sop,
    psi::apsi_wrapper::YaclChannel &chl) {
  STOPWATCH(sender_stopwatch, "DkPirSenderDispatcher::dispatch_params");

  try {
    // Extract the parameter request
    ::apsi::ParamsRequest params_request =
        ::apsi::to_params_request(std::move(sop));

    psi::dkpir::DkPirSender::RunParams(params_request, sender_db_, chl);
  } catch (const std::exception &ex) {
    APSI_LOG_ERROR(
        "Sender threw an exception while processing parameter request: "
        << ex.what());
  }
}

void DkPirSenderDispatcher::dispatch_oprf(
    std::unique_ptr<::apsi::network::SenderOperation> sop,
    psi::apsi_wrapper::YaclChannel &chl, std::atomic<bool> &stop) {
  STOPWATCH(sender_stopwatch, "DkPirSenderDispatcher::dispatch_oprf");

  try {
    // Extract the OPRF request
    ::apsi::OPRFRequest oprf_request = ::apsi::to_oprf_request(std::move(sop));

    // NOTE(junfeng): This is a hack, empty request with max bucket_idx is a
    // signal of stop.
    
    if (oprf_request->data.empty() &&
        oprf_request->bucket_idx == std::numeric_limits<uint32_t>::max()) {
      stop = true;
      return;
    }

    // SetBucketIdx(oprf_request->bucket_idx);

    DkPirSender::RunOPRF(oprf_request, oprf_key_, chl);
  } catch (const std::exception &ex) {
    APSI_LOG_ERROR("Sender threw an exception while processing OPRF request: "
                   << ex.what());
  }
}

void DkPirSenderDispatcher::dispatch_query(
    std::unique_ptr<::apsi::network::SenderOperation> sop,
    psi::apsi_wrapper::YaclChannel &chl, bool streaming_result) {
  STOPWATCH(sender_stopwatch, "DkPirSenderDispatcher::dispatch_query");

  try {
    // Create the Query object
    auto query_request = ::apsi::to_query_request(std::move(sop));

    // SetBucketIdx(query_request->bucket_idx);

    auto send_func = DkPirSender::BasicSend<::apsi::Response::element_type>;

    if (sender_db_ == nullptr || sender_cnt_db_ == nullptr) {
      ::apsi::QueryResponse response_query =
          std::make_unique<::apsi::QueryResponse::element_type>();
      response_query->package_count = 0;
      try {
        send_func(chl, std::move(response_query));
      } catch (const std::exception &ex) {
        APSI_LOG_ERROR(
            "Failed to send response to query request; function threw an "
            "exception: "
            << ex.what());
        throw;
      }
      return;
    }

    // Create the Query object
    psi::dkpir::DkPirQuery query(std::move(query_request), sender_db_,
                                 sender_cnt_db_);

    // Query will send result to client in a stream of ResultPackages
    // (ResultParts)
    psi::apsi_wrapper::Sender::RunQuery(query, chl, streaming_result);
    DkPirSender::RunQuery(query, chl, poly_matrix1(), poly_matrix2());
  } catch (const std::exception &ex) {
    APSI_LOG_ERROR(
        "Sender threw an exception while processing query: " << ex.what());
  }
}

bool DkPirSenderDispatcher::CheckCount(
    const std::shared_ptr<yacl::link::Context> &lctx) {
  ::apsi::CryptoContext crypto_context(sender_cnt_db_->get_crypto_context());

  uint64_t count;
  ::seal::Plaintext result;
  std::stringstream ss_ct;

  yacl::Buffer count_buf = lctx->Recv(lctx->NextRank(), "count_sum");
  YACL_ENFORCE(count_buf.size() == sizeof(uint64_t));
  std::memcpy(&count, count_buf.data(), count_buf.size());

  std::stringstream ss_pt;
  ss_pt << std::string_view(lctx->Recv(lctx->NextRank(), "count_sum_pt"));
  auto seal_context = crypto_context.seal_context();
  result.load(*seal_context, ss_pt);

  auto encoder = crypto_context.encoder();
  size_t slot_count = encoder->slot_count();

  std::vector<uint64_t> plain_result(slot_count, 0ULL);
  encoder->decode(result, plain_result);
  
  return true;
}

}  // namespace psi::dkpir