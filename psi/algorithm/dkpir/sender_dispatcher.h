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

#include <memory>

#include "apsi/oprf/oprf_sender.h"

#include "psi/algorithm/dkpir/dk_pir.h"
#include "psi/wrapper/apsi/yacl_channel.h"

namespace psi::dkpir {
class DkPirSenderDispatcher {
 public:
  DkPirSenderDispatcher() = delete;

  DkPirSenderDispatcher(std::shared_ptr<::apsi::sender::SenderDB> sender_db,
                        std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db,
                        ::apsi::oprf::OPRFKey oprf_key);

  void run(std::atomic<bool> &stop, std::shared_ptr<yacl::link::Context> lctx,
           bool streaming_result = true);

  bool CheckCount(const std::shared_ptr<yacl::link::Context> &lctx);

  const std::vector<uint64_t> &poly_matrix1() const { return poly_matrix1_; }

  const std::vector<uint64_t> &poly_matrix2() const { return poly_matrix2_; }

 private:
  std::shared_ptr<::apsi::sender::SenderDB> sender_db_;
  std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db_;
  std::vector<uint64_t> poly_matrix1_;
  std::vector<uint64_t> poly_matrix2_;

  ::apsi::oprf::OPRFKey oprf_key_;

  void dispatch_parms(std::unique_ptr<::apsi::network::SenderOperation> sop,
                      psi::apsi_wrapper::YaclChannel &channel);

  void dispatch_oprf(std::unique_ptr<::apsi::network::SenderOperation> sop,
                     psi::apsi_wrapper::YaclChannel &channel,
                     std::atomic<bool> &stop);

  void dispatch_query(std::unique_ptr<::apsi::network::SenderOperation> sop,
                      psi::apsi_wrapper::YaclChannel &channel,
                      bool streaming_result = true);
};
}  // namespace psi::dkpir