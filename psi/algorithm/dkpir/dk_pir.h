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

#pragma once

#include "psi/algorithm/dkpir/query.h"
#include "psi/wrapper/apsi/receiver.h"
#include "psi/wrapper/apsi/sender.h"
#include "psi/wrapper/apsi/yacl_channel.h"

namespace psi::dkpir {
using CiphertextPowers = std::vector<::seal::Ciphertext>;

class DkPirSender : public psi::apsi_wrapper::Sender {
 public:
  DkPirSender() = delete;
  static void RunQuery(const psi::dkpir::DkPirQuery &query,
                       psi::apsi_wrapper::YaclChannel &chl,
                       const std::vector<uint64_t> &poly_matrix1,
                       const std::vector<uint64_t> &poly_matrix2);

  static void ComputePowers(
      const std::shared_ptr<psi::dkpir::SenderCntDB> &sender_cnt_db,
      const ::apsi::CryptoContext &crypto_context,
      std::vector<CiphertextPowers> &powers, const ::apsi::PowersDag &pd,
      std::uint32_t bundle_idx, ::seal::MemoryPoolHandle &pool);

  static void ProcessBinBundleCache(
      const std::shared_ptr<psi::dkpir::SenderCntDB> &sender_cnt_db,
      const ::apsi::CryptoContext &crypto_context,
      std::reference_wrapper<const ::apsi::sender::BinBundleCache> cache,
      std::vector<CiphertextPowers> &all_powers, uint32_t bundle_idx,
      ::seal::MemoryPoolHandle &pool, std::mutex &cts_mutex,
      std::vector<std::vector<::seal::Ciphertext>> &count_ciphertexts);
};

class DkPirReceiver : public psi::apsi_wrapper::Receiver {
 public:
  DkPirReceiver(::apsi::PSIParams params)
      : psi::apsi_wrapper::Receiver(params) {};

  void SendCount(uint64_t count,
                 const std::shared_ptr<yacl::link::Context> &lctx,
                 ::seal::Ciphertext count_ct);

  ::seal::Ciphertext ReceiveCiphertext(
      const std::shared_ptr<yacl::link::Context> &lctx);
};

}  // namespace psi::dkpir