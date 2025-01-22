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