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

// perfetto usage is adapted from
// https://github.com/google/perfetto/blob/master/examples/sdk/example.cc

#pragma once

#include "yacl/link/context.h"

#include "psi/apps/psi_launcher/report.h"
#include "psi/config/psi.h"
#include "psi/config/ub_psi.h"
#include "psi/legacy/bucket_psi.h"

#include "psi/proto/pir.pb.h"
#include "psi/proto/psi.pb.h"
#include "psi/proto/psi_v2.pb.h"

namespace psi {

PsiResultReport RunLegacyPsi(const BucketPsiConfig& bucket_psi_config,
                             const std::shared_ptr<yacl::link::Context>& lctx,
                             ProgressCallbacks progress_callbacks = nullptr,
                             int64_t callbacks_interval_ms = 5 * 1000);

PsiResultReport RunPsi(const v2::PsiConfig& psi_config,
                       const std::shared_ptr<yacl::link::Context>& lctx);

PsiResultReport RunUbPsi(const v2::UbPsiConfig& ub_psi_config,
                         const std::shared_ptr<yacl::link::Context>& lctx);

PirResultReport RunPir(const ApsiReceiverConfig& apsi_receiver_config,
                       const std::shared_ptr<yacl::link::Context>& lctx);

PirResultReport RunPir(const ApsiSenderConfig& apsi_sender_config,
                       const std::shared_ptr<yacl::link::Context>& lctx);

PirResultReport RunDkPir(const DkPirReceiverConfig& dk_pir_receiver_config,
                         const std::shared_ptr<yacl::link::Context>& lctx);

PirResultReport RunDkPir(const DkPirSenderConfig& dk_pir_sender_config,
                         const std::shared_ptr<yacl::link::Context>& lctx);

namespace api {

namespace internal {
v2::UbPsiConfig UbExecConfToUbconf(
    const ub::UbPsiExecuteConfig& exec_config,
    const std::shared_ptr<yacl::link::Context>& lctx);
}

struct ProgressParams {
  ProgressCallbacks hook = nullptr;

  uint32_t interval_ms = 5 * 1000;
};

PsiExecuteReport PsiExecute(const PsiExecuteConfig& config,
                            const std::shared_ptr<yacl::link::Context>& lctx,
                            const ProgressParams& progress_params = {});

PsiExecuteReport UbPsiExecute(const ub::UbPsiExecuteConfig& config,
                              const std::shared_ptr<yacl::link::Context>& lctx);

}  // namespace api

}  // namespace psi
