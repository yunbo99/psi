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
#include "psi/utils/resource_manager.h"
#include "psi/utils/csv_converter.h"
#include "psi/wrapper/apsi/utils/sender_db.h"

namespace psi::dkpir {
struct DkPirSenderOptions {
  std::size_t nonce_byte_count = 16;
  bool compress = false;
  bool streaming_result = true;

  std::string params_file;
  std::string sender_key_value_file;
  std::string sender_key_count_file;
  std::string value_sdb_out_file;
  std::string count_info_file;
  std::string count_sdb_out_file;
};

struct DkPirReceiverOptions {
  std::size_t threads = 1;
  bool streaming_result = true;
  std::string params_file;

  std::string tmp_query_file;
  std::string apsi_output_file;
  std::string result_file;

  std::string key;
  std::vector<std::string> labels;
};

void SenderOffline(const DkPirSenderOptions &options);

void SenderOnline(const DkPirSenderOptions &options,
                  const std::shared_ptr<yacl::link::Context> &lctx);

int ReceiverOnline(const DkPirReceiverOptions &options,
                   const std::shared_ptr<yacl::link::Context> &lctx);                  

}  // namespace psi::dkpir