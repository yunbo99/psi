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

#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_set>

#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"
#include "gtest/gtest.h"

#include "psi/wrapper/apsi/api/receiver.h"
#include "psi/wrapper/apsi/api/sender.h"
#include "psi/wrapper/apsi/utils/csv_converter.h"

namespace psi::apsi_wrapper {

std::unordered_set<std::string> ReadCsvRow(const std::string& file_path) {
  std::unordered_set<std::string> lines;
  std::ifstream file(file_path);
  std::string line;
  while (std::getline(file, line)) {
    lines.insert(line);
  }
  return lines;
}

TEST(DuplicateKeyTest, Works) {
  std::string sender_db_file = "examples/pir/apsi/data/duplicate_key_db.csv";
  std::string params_file = "examples/pir/apsi/parameters/100-1-300.json";
  size_t nonce_byte_count = 16;
  const size_t bucket_cnt = 10;
  bool compress = false;
  std::string receiver_query_file =
      "examples/pir/apsi/data/duplicate_key_query.csv";

  std::string receiver_target_result_file =
      "examples/pir/apsi/data/duplicate_key_target_result.csv";

  boost::uuids::random_generator uuid_generator;
  auto uuid_str = boost::uuids::to_string(uuid_generator());

  std::filesystem::path tmp_folder{std::filesystem::temp_directory_path() /
                                   uuid_str};
  std::filesystem::create_directories(tmp_folder);

  std::string sender_key_value_file = tmp_folder / "sender_key_value.csv";
  std::string sdb_out_file = tmp_folder / "out_sdb";

  std::string receiver_tmp_query_file = tmp_folder / "receiver_tmp_query.csv";
  std::string receiver_apsi_output_file =
      tmp_folder / "receiver_apsi_output.csv";
  std::string receiver_result_file = tmp_folder / "receiver_result.csv";

  {
    // Sender convert db file
    psi::apsi_wrapper::ApsiCsvConverter sender_db_converter(
        sender_db_file, "id", {"label1", "label2", "label3"});
    sender_db_converter.MergeColumnAndRow(sender_key_value_file);

    // Receiver convert query file
    psi::apsi_wrapper::ApsiCsvConverter receiver_query_converter(
        receiver_query_file, "id");
    receiver_query_converter.ExtractQuery(receiver_tmp_query_file);

    // APSI
    psi::apsi_wrapper::api::Sender::Option sender_option;
    sender_option.source_file = sender_key_value_file;
    sender_option.params_file = params_file;
    sender_option.nonce_byte_count = nonce_byte_count;
    sender_option.compress = compress;
    sender_option.db_path = sdb_out_file;
    sender_option.num_buckets = bucket_cnt;
    sender_option.group_cnt = bucket_cnt;

    psi::apsi_wrapper::api::Sender sender(sender_option);

    sender.GenerateSenderDb();

    std::string params_str = sender.GenerateParams();

    psi::apsi_wrapper::api::Receiver receiver(bucket_cnt);

    receiver.LoadParamsConfig(params_file);
    auto recv_context = receiver.BucketizeItems(receiver_tmp_query_file);

    auto oprf_requst = receiver.RequestOPRF(recv_context);

    auto oprf_response = sender.RunOPRF(oprf_requst);

    auto query_request = receiver.RequestQuery(recv_context, oprf_response);

    auto query_response = sender.RunQuery(query_request);

    auto cnts = receiver.ProcessResult(recv_context, query_response,
                                       receiver_apsi_output_file);

    // Receiver convert result file
    psi::apsi_wrapper::ApsiCsvConverter recevier_result_converter(
        receiver_apsi_output_file, "key", {"value"});
    int cnt = recevier_result_converter.ExtractResult(
        receiver_result_file, "id", {"label1", "label2", "label3"});

    std::unordered_set<std::string> target_data =
        ReadCsvRow(receiver_target_result_file);
    std::unordered_set<std::string> result = ReadCsvRow(receiver_result_file);
    
    // Target_data contains the row with the column names
    EXPECT_EQ(cnt, target_data.size() - 1);
    EXPECT_EQ(result, target_data);
  }
}
}  // namespace psi::apsi_wrapper