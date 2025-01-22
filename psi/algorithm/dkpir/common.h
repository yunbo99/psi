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

#include "psi/wrapper/apsi/utils/common.h"
#include "psi/algorithm/dkpir/sender_cnt_db.h"

namespace psi::dkpir {
std::shared_ptr<psi::dkpir::SenderCntDB> GenerateSenderCntDB(
    const std::string& source_file, const std::string& params_file,
    bool compress, ::apsi::oprf::OPRFKey& oprf_key,
    const std::vector<std::string>& keys = {},
    const std::vector<std::string>& labels = {});

std::shared_ptr<psi::dkpir::SenderCntDB> CreateSenderCntDB(
    const psi::apsi_wrapper::DBData& db_data,
    std::unique_ptr<::apsi::PSIParams> psi_params,
    ::apsi::oprf::OPRFKey& oprf_key, bool compress);

bool TrySaveSenderCntDB(const std::string& info_file,
                        const std::string& sdb_out_file,
                        std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db,
                        const ::apsi::oprf::OPRFKey& oprf_key);

std::shared_ptr<psi::dkpir::SenderCntDB> TryLoadSenderCntDB(
    const std::string& info_file, const std::string& sdb_out_file);

void print_intersection_results(
    const std::vector<std::string> &orig_items,
    const std::vector<::apsi::Item> &items,
    const std::vector<::apsi::receiver::MatchRecord> &intersection,
    const std::string &out_file, bool append_to_outfile = false);

}  // namespace psi::dkpir