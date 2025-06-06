// Copyright 2024 Ant Group Co., Ltd.
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
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/link/link.h"

namespace psi::nty {
class ServerAidedTwoPartyPsi {
 public:
  static void ServerAidedPsi(
      const std::vector<uint128_t>& items, size_t self_rank,
      size_t aided_server_rank, size_t helper_rank, size_t receiver_rank,
      const std::vector<std::shared_ptr<yacl::link::Context>>& p2p,
      std::vector<uint128_t>& outputs);

  static void ServerAssist(
      size_t helper_rank, size_t receiver_rank,
      const std::vector<std::shared_ptr<yacl::link::Context>>& p2p);
};

}  // namespace psi::nty
