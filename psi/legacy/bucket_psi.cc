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

#include "psi/legacy/bucket_psi.h"

#include <omp.h>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <utility>

#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "spdlog/spdlog.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/utils/serialize.h"

#include "psi/algorithm/ecdh/ecdh_psi.h"
#include "psi/cryptor/cryptor_selector.h"
#include "psi/prelude.h"
#include "psi/utils/arrow_csv_batch_provider.h"
#include "psi/utils/bucket.h"
#include "psi/utils/ec_point_store.h"
#include "psi/utils/io.h"
#include "psi/utils/serialize.h"
#include "psi/utils/sync.h"

namespace psi {

namespace {

constexpr size_t kBucketSize = 1 << 20;

class ProgressLoop {
 public:
  // Starts the background thread which will be calling the function
  ProgressLoop(const std::shared_ptr<Progress>& progress,
               ProgressCallbacks function, int64_t interval_ms)
      : progress_(progress),
        function_(function),
        interval_ms_(std::max(static_cast<int64_t>(1), interval_ms)) {
    thread_.reset(new std::thread([this]() { RunLoop(); }));
  }

  ~ProgressLoop() {
    NotifyStop();
    // wait for thread_ to complete and cleanup.
    thread_->join();
    thread_.reset();
  }

 private:
  // Notifies the background thread to stop
  void NotifyStop() {
    if (!stop_event_.HasBeenNotified()) {
      stop_event_.Notify();
    }
  }

  // Loops forever calling `function_` every `interval_ms_`.
  void RunLoop() {
    while (!stop_event_.HasBeenNotified()) {
      const int64_t begin = absl::ToUnixMillis(absl::Now());
      function_(progress_->Get());
      const int64_t end = absl::ToUnixMillis(absl::Now());
      const int64_t deadline = begin + interval_ms_;
      if (deadline > end) {
        if (stop_event_.WaitForNotificationWithTimeout(
                absl::Milliseconds(deadline - end))) {
          // notify end
          break;
        }
      }
    }
    // last progress callback
    function_(progress_->Get());
  }

  const std::shared_ptr<Progress> progress_;
  const ProgressCallbacks function_;
  const int64_t interval_ms_;

  // Protects state below.
  mutable absl::Mutex mutex_;
  absl::Notification stop_event_;

  std::unique_ptr<std::thread> thread_ = nullptr;
};

}  // namespace

void CreateOutputFolder(const std::string& path) {
  // create output folder.
  auto out_dir_path = std::filesystem::path(path).parent_path();
  if (out_dir_path.empty()) {
    return;  // create file under CWD, no need to create parent dir
  }

  std::error_code ec;
  std::filesystem::create_directory(out_dir_path, ec);
  YACL_ENFORCE(ec.value() == 0,
               "failed to create output dir={} for path={}, reason = {}",
               out_dir_path.string(), path, ec.message());
}

size_t FilterFileByIndices(const std::string& input, const std::string& output,
                           const std::vector<uint64_t>& indices,
                           bool output_difference, size_t header_line_count) {
  auto in = io::BuildInputStream(io::FileIoOptions(input));
  auto out = io::BuildOutputStream(io::FileIoOptions(output));

  std::string line;
  size_t idx = 0;
  size_t actual_count = 0;
  auto indices_iter = indices.begin();
  while (in->GetLine(&line)) {
    if (idx < header_line_count) {
      out->Write(line);
      out->Write("\n");
    } else {
      if (!output_difference) {
        if (indices_iter == indices.end()) {
          break;
        }
      }

      if ((indices_iter != indices.end() &&
           *indices_iter == idx - header_line_count) != output_difference) {
        out->Write(line);
        out->Write("\n");
        actual_count++;
      }

      if (indices_iter != indices.end() &&
          *indices_iter == idx - header_line_count) {
        indices_iter++;
      }
    }
    idx++;
  }
  size_t target_count =
      (output_difference ? (idx - header_line_count - indices.size())
                         : indices.size());

  YACL_ENFORCE_EQ(actual_count, target_count,
                  "logstic error, indices.size={}, actual_count={}, "
                  "target_count={}, output_difference={}, please be "
                  "sure the `indices` is sorted",
                  indices.size(), actual_count, target_count,
                  output_difference);

  out->Close();
  in->Close();

  return indices.size();
}

size_t FilterFileByIndices(const std::string& input, const std::string& output,
                           const std::filesystem::path& indices,
                           bool output_difference, size_t header_line_count) {
  auto in = io::BuildInputStream(io::FileIoOptions(input));
  auto out = io::BuildOutputStream(io::FileIoOptions(output));

  std::string line;
  size_t idx = 0;
  size_t actual_count = 0;
  FileIndexReader reader(indices);

  std::optional<uint64_t> intersection_index = reader.GetNext();

  while (in->GetLine(&line)) {
    if (idx < header_line_count) {
      out->Write(line);
      out->Write("\n");
    } else {
      if (!output_difference) {
        if (!intersection_index.has_value()) {
          break;
        }
      }

      if ((intersection_index.has_value() &&
           intersection_index.value() == idx - header_line_count) !=
          output_difference) {
        out->Write(line);
        out->Write("\n");
        actual_count++;
      }

      if (intersection_index.has_value() &&
          intersection_index.value() == idx - header_line_count) {
        intersection_index = reader.GetNext();
      }
    }
    idx++;
  }

  size_t target_count =
      (output_difference ? (idx - header_line_count - reader.read_cnt())
                         : reader.read_cnt());

  YACL_ENFORCE_EQ(
      actual_count, target_count,
      "logstic error, reader.read_cnt={}, actual_count={}, input_path={}, "
      "target_count={}, output_difference={}, please be "
      "sure the `indices` is sorted",
      reader.read_cnt(), actual_count, input, target_count, output_difference);

  out->Close();
  in->Close();

  return reader.read_cnt();
}

std::unique_ptr<CsvChecker> CheckInput(
    std::shared_ptr<yacl::link::Context> lctx, const std::string& input_path,
    const std::vector<std::string>& selected_fields, bool precheck_required) {
  // input dataset pre check
  SPDLOG_INFO("Begin sanity check for input file: {}, precheck_switch:{}",
              input_path, precheck_required);
  std::unique_ptr<CsvChecker> checker;
  auto csv_check_f = [&] {
    checker = std::make_unique<CsvChecker>(input_path, selected_fields,
                                           !precheck_required);
  };
  // keep alive
  SyncWait(lctx, std::move(csv_check_f));
  SPDLOG_INFO("End sanity check for input file: {}, size={}", input_path,
              checker->data_count());

  return checker;
}

BucketPsi::BucketPsi(BucketPsiConfig config,
                     std::shared_ptr<yacl::link::Context> lctx)
    : config_(std::move(config)), lctx_(std::move(lctx)) {
  if (config_.psi_type() != PsiType::ECDH_OPRF_UB_PSI_2PC_GEN_CACHE) {
    Init();
  }

  // prepare fields vec
  selected_fields_.insert(selected_fields_.end(),
                          config_.input_params().select_fields().begin(),
                          config_.input_params().select_fields().end());
}

PsiResultReport BucketPsi::Run(ProgressCallbacks progress_callbacks,
                               int64_t callbacks_interval_ms) {
  // init progress
  auto progress = std::make_shared<Progress>();
  progress->SetWeights({15, 65, 20});

  // begin loop thread
  std::unique_ptr<ProgressLoop> p_loop = nullptr;
  if (progress_callbacks) {
    SPDLOG_INFO("begin progress callback loop thread, interval:{}",
                callbacks_interval_ms);
    p_loop = std::make_unique<ProgressLoop>(progress, progress_callbacks,
                                            callbacks_interval_ms);
  }

  PsiResultReport report;
  std::vector<uint64_t> indices;
  bool digest_equal = false;

  if (config_.psi_type() != PsiType::ECDH_OPRF_UB_PSI_2PC_OFFLINE &&
      config_.psi_type() != PsiType::ECDH_OPRF_UB_PSI_2PC_GEN_CACHE &&
      config_.psi_type() != PsiType::ECDH_OPRF_UB_PSI_2PC_TRANSFER_CACHE &&
      config_.psi_type() != PsiType::ECDH_OPRF_UB_PSI_2PC_ONLINE &&
      config_.psi_type() != PsiType::ECDH_OPRF_UB_PSI_2PC_SHUFFLE_ONLINE) {
    progress->NextSubProgress("Precheck");
    auto checker =
        CheckInput(lctx_, config_.input_params().path(), selected_fields_,
                   config_.input_params().precheck());
    report.set_original_count(checker->data_count());

    // gather others hash digest
    std::vector<yacl::Buffer> digest_buf_list =
        yacl::link::AllGather(lctx_, checker->hash_digest(), "PSI:SYNC_DIGEST");
    digest_equal = HashListEqualTest(digest_buf_list);

    // run psi
    auto psi_progress = progress->NextSubProgress("RunPsi");
    if (!digest_equal) {
      uint64_t items_count = checker->data_count();
      indices = RunPsi(psi_progress, items_count);

    } else {
      SPDLOG_INFO("Skip doing psi, because dataset has been aligned!");
      indices.resize(checker->data_count());
      std::iota(indices.begin(), indices.end(), 0);
    }
    report.set_intersection_count(indices.size());

  } else {
    YACL_THROW(
        "Not support, please use new interface UbPsiConfig in psi_v2.proto.");
  }

  progress->NextSubProgress("ProduceOutput");
  ProduceOutput(digest_equal, indices, report);

  progress->Done();

  return report;
}

void BucketPsi::ProduceOutput(bool digest_equal, std::vector<uint64_t>& indices,
                              PsiResultReport& report) {
  if ((config_.psi_type() == PsiType::ECDH_OPRF_UB_PSI_2PC_OFFLINE) ||
      (config_.psi_type() == PsiType::ECDH_OPRF_UB_PSI_2PC_GEN_CACHE) ||
      (config_.psi_type() == PsiType::ECDH_OPRF_UB_PSI_2PC_TRANSFER_CACHE) ||
      (static_cast<size_t>(config_.receiver_rank()) != lctx_->Rank() &&
       !config_.broadcast_result())) {
    report.set_intersection_count(-1);
    // no generate output file;
    return;
  } else {
    report.set_intersection_count(indices.size());
  }

  // filter dataset
  SPDLOG_INFO("Begin post filtering, indices.size={}, should_sort={}",
              indices.size(), config_.output_params().need_sort());

  std::sort(indices.begin(), indices.end());
  GenerateResult(config_.input_params().path(), config_.output_params().path(),
                 selected_fields_, indices, config_.output_params().need_sort(),
                 digest_equal);

  SPDLOG_INFO("End post filtering, in={}, out={}",
              config_.input_params().path(), config_.output_params().path());
}

void BucketPsi::Init() {
  // TODO: deal input_params data_type

  if (config_.bucket_size() == 0) {
    config_.set_bucket_size(kBucketSize);
  }
  SPDLOG_INFO("bucket size set to {}", config_.bucket_size());

  // Test connection.
  lctx_->ConnectToMesh();

  MemoryPsiConfig config;
  config.set_psi_type(config_.psi_type());
  config.set_curve_type(config_.curve_type());
  config.set_receiver_rank(config_.receiver_rank());
  config.set_broadcast_result(config_.broadcast_result());
  // set dppsi parameters
  if (config_.has_dppsi_params()) {
    DpPsiParams* dppsi_params = config.mutable_dppsi_params();
    dppsi_params->set_bob_sub_sampling(
        config_.dppsi_params().bob_sub_sampling());
    dppsi_params->set_epsilon(config_.dppsi_params().epsilon());
  }
  mem_psi_ = std::make_unique<MemoryPsi>(config, lctx_);

  // create output folder.
  CreateOutputFolder(config_.output_params().path());
}

std::vector<uint64_t> BucketPsi::RunPsi(std::shared_ptr<Progress>& progress,
                                        uint64_t& self_items_count) {
  SPDLOG_INFO("Run psi protocol={}, self_items_count={}", config_.psi_type(),
              self_items_count);

  if ((config_.psi_type() == PsiType::ECDH_OPRF_UB_PSI_2PC_GEN_CACHE) ||
      (config_.psi_type() == PsiType::ECDH_OPRF_UB_PSI_2PC_TRANSFER_CACHE) ||
      (config_.psi_type() == PsiType::ECDH_OPRF_UB_PSI_2PC_SHUFFLE_ONLINE) ||
      (config_.psi_type() == PsiType::ECDH_OPRF_UB_PSI_2PC_OFFLINE) ||
      (config_.psi_type() == PsiType::ECDH_OPRF_UB_PSI_2PC_ONLINE)) {
    YACL_THROW(
        "not support, please use new interface UbPsiConfig in psi_v2.proto.");
  } else {
    return RunBucketPsi(progress, self_items_count);
  }
}

std::vector<uint64_t> BucketPsi::RunBucketPsi(
    std::shared_ptr<Progress>& progress, uint64_t self_items_count) {
  std::vector<uint64_t> ret;

  size_t max_bucket_count = NegotiateBucketNum(
      lctx_, self_items_count, config_.bucket_size(), config_.psi_type());

  // one party item_size is 0, no need to do intersection
  if (max_bucket_count == 0) {
    return ret;
  }

  SPDLOG_INFO("psi protocol={}, bucket_count={}", config_.psi_type(),
              max_bucket_count);

  // hash bucket items
  auto bucket_store = CreateCacheFromCsv(
      config_.input_params().path(), selected_fields_,
      std::filesystem::path(config_.output_params().path()).parent_path(),
      max_bucket_count);
  for (size_t bucket_idx = 0; bucket_idx < bucket_store->BucketNum();
       bucket_idx++) {
    auto bucket_items_list = bucket_store->LoadBucketItems(bucket_idx);

    SPDLOG_INFO("run psi bucket_idx={}, bucket_item_size={} ", bucket_idx,
                bucket_items_list.size());

    std::vector<std::string> item_data_list;
    item_data_list.reserve(bucket_items_list.size());
    for (const auto& item : bucket_items_list) {
      item_data_list.push_back(item.base64_data);
    }

    auto result_list = mem_psi_->Run(item_data_list);

    SPDLOG_INFO("psi protocol={}, result_size={}", config_.psi_type(),
                result_list.size());

    // get result item indices
    GetResultIndices(item_data_list, bucket_items_list, result_list, &ret);

    // count progress
    if (progress) {
      progress->Update(100 * (bucket_idx + 1) / bucket_store->BucketNum());
    }
  }

  return ret;
}

void GetResultIndices(const std::vector<std::string>& item_data_list,
                      const std::vector<HashBucketCache::BucketItem>& item_list,
                      std::vector<std::string>& result_list,
                      std::vector<uint64_t>* indices) {
  indices->reserve(indices->size() + result_list.size());
  if (result_list.empty()) {
    return;
  } else if (result_list.size() == item_list.size()) {
    for (const auto& item : item_list) {
      indices->push_back(item.index);
    }
    return;
  }

  std::sort(result_list.begin(), result_list.end());
  for (size_t i = 0; i < item_data_list.size(); ++i) {
    if (std::binary_search(result_list.begin(), result_list.end(),
                           item_data_list[i])) {
      indices->push_back(item_list[i].index);
    }
  }
}

}  // namespace psi
