// Copyright 2025
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

#include "psi/algorithm/dkpir/sender_cnt_db.h"

#include "yacl/crypto/rand/rand.h"
#include "yacl/utils/parallel.h"

#include "psi/algorithm/dkpir/common.h"
#include "psi/algorithm/dkpir/phe/encryptor.h"
#include "psi/algorithm/dkpir/phe/key_generator.h"
#include "psi/wrapper/apsi/utils/sender_db.h"

namespace psi::dkpir {
namespace {
// Parse the count from the label, which requires the label to be composed only
// of '0' ~ '9'
uint32_t GetCount(const std::vector<unsigned char> &label) {
  std::string str(label.begin(), label.end());

  try {
    uint32_t count = static_cast<uint32_t>(std::stoi(str));
    return count;
  } catch (const std::exception &ex) {
    SPDLOG_WARN("Row count read error: {}", ex.what());
  }

  return 0;
}

// This function preprocess the row count in the row count table. First, apply a
// random linear function p(x)=ax+b to the row count corresponding to each
// key, and then encrypt the results of the linear function using
// EC-ElGamal. Finally, store the linear function and the private key to a
// local file.
void EncryptCount(psi::apsi_wrapper::LabeledData &data,
                  const std::string &sk_file) {
  std::shared_ptr<yacl::crypto::EcGroup> curve =
      yacl::crypto::EcGroupFactory::Instance().Create(
          "fourq", yacl::ArgLib = "FourQlib");
  uint64_t point_size = curve->GetSerializeLength();

  psi::dkpir::phe::PublicKey public_key;
  psi::dkpir::phe::SecretKey secret_key;
  psi::dkpir::phe::KeyGenerator::GenerateKey(curve, &public_key, &secret_key);
  psi::dkpir::phe::Encryptor encryptor(public_key);

  // Generate a random linear function p(x)=ax+b
  std::vector<uint32_t> polynomial(2);
  polynomial[0] = yacl::crypto::SecureRandU32();
  polynomial[1] = yacl::crypto::SecureRandU32();

  // Replace {(item, count)} with {(item, Enc(p(count)))}
  yacl::parallel_for(0, data.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      uint32_t count = GetCount(data[idx].second);
      yacl::math::MPInt count_poly = psi::dkpir::ComputePoly(polynomial, count);

      data[idx].second.resize(point_size * 2);
      psi::dkpir::phe::Ciphertext ciphertext = encryptor.Encrypt(count_poly);
      ciphertext.SerializeCiphertext(curve, data[idx].second.data(),
                                     point_size * 2);
    }
  });

  std::ofstream out(sk_file, std::ios::binary);
  psi::dkpir::Save(polynomial, secret_key, out);

  SPDLOG_INFO(
      "Complete the encryption of the row count, and store the private key of "
      "phe in {}",
      sk_file);
}
}  // namespace

std::shared_ptr<::apsi::sender::SenderDB> GenerateSenderCntDB(
    const std::string &db_file, const std::string &params_file,
    const std::string &sk_file, size_t nonce_byte_count, bool compress,
    ::apsi::oprf::OPRFKey &oprf_key, const std::vector<std::string> &keys,
    const std::vector<std::string> &labels) {
  std::unique_ptr<::apsi::PSIParams> params =
      psi::apsi_wrapper::BuildPsiParams(params_file);
  if (!params) {
    // We must have valid parameters given
    APSI_LOG_ERROR("Failed to set PSI parameters");
    return nullptr;
  }

  std::unique_ptr<psi::apsi_wrapper::DBData> db_data;
  if (db_file.empty() ||
      !(db_data = psi::apsi_wrapper::load_db(db_file, keys, labels))) {
    // Failed to read db file
    APSI_LOG_DEBUG("Failed to load data from a CSV file");
    return nullptr;
  }

  return CreateSenderCntDB(*db_data, std::move(params), sk_file, oprf_key,
                           nonce_byte_count, compress);
}

std::shared_ptr<::apsi::sender::SenderDB> CreateSenderCntDB(
    const psi::apsi_wrapper::DBData &db_data,
    std::unique_ptr<::apsi::PSIParams> psi_params, const std::string &sk_file,
    ::apsi::oprf::OPRFKey &oprf_key, size_t nonce_byte_count, bool compress) {
  if (!psi_params) {
    APSI_LOG_ERROR("No PSI parameters were given");
    return nullptr;
  }

  std::shared_ptr<::apsi::sender::SenderDB> sender_cnt_db;

  try {
    psi::apsi_wrapper::LabeledData labeled_db_data =
        std::get<psi::apsi_wrapper::LabeledData>(db_data);

    EncryptCount(labeled_db_data, sk_file);

    // Find the longest label and use that as label size
    size_t label_byte_count =
        max_element(
            labeled_db_data.begin(), labeled_db_data.end(),
            [](auto &a, auto &b) { return a.second.size() < b.second.size(); })
            ->second.size();

    sender_cnt_db = std::make_shared<::apsi::sender::SenderDB>(
        *psi_params, oprf_key, label_byte_count, nonce_byte_count, compress);
    sender_cnt_db->set_data(labeled_db_data);
    APSI_LOG_INFO("Created labeled sender_cnt_db with "
                  << sender_cnt_db->get_item_count() << " items and "
                  << label_byte_count << "-byte labels (" << nonce_byte_count
                  << "-byte nonces)");

  } catch (const std::exception &ex) {
    APSI_LOG_ERROR("Failed to create sender_cnt_db: " << ex.what());
    return nullptr;
  }

  if (compress) {
    APSI_LOG_INFO("Using in-memory compression to reduce memory footprint");
  }

  // Read the OPRFKey and strip the sender_cnt_db to
  // reduce memory use
  oprf_key = sender_cnt_db->strip();

  APSI_LOG_INFO(
      "sender_cnt_db packing rate: " << sender_cnt_db->get_packing_rate());

  return sender_cnt_db;
}
}  // namespace psi::dkpir