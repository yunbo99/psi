
#include "psi/algorithm/dkpir/common.h"

#include <fstream>
#include <sstream>

#include "psi/wrapper/apsi/utils/sender_db.h"

namespace psi::dkpir {

struct Colors {
  static const std::string Red;
  static const std::string Green;
  static const std::string RedBold;
  static const std::string GreenBold;
  static const std::string Reset;
};

const std::string Colors::Red = "\033[31m";
const std::string Colors::Green = "\033[32m";
const std::string Colors::RedBold = "\033[1;31m";
const std::string Colors::GreenBold = "\033[1;32m";
const std::string Colors::Reset = "\033[0m";

std::shared_ptr<psi::dkpir::SenderCntDB> CreateSenderCntDB(
    const psi::apsi_wrapper::DBData &db_data,
    std::unique_ptr<::apsi::PSIParams> psi_params,
    ::apsi::oprf::OPRFKey &oprf_key, bool compress) {
  if (!psi_params) {
    APSI_LOG_ERROR("No PSI parameters were given");
    return nullptr;
  }

  std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db;

  try {
    auto &labeled_db_data = std::get<psi::apsi_wrapper::LabeledData>(db_data);

    // Find the longest label and use that as label size
    size_t label_byte_count =
        max_element(
            labeled_db_data.begin(), labeled_db_data.end(),
            [](auto &a, auto &b) { return a.second.size() < b.second.size(); })
            ->second.size();

    sender_cnt_db = std::make_shared<psi::dkpir::SenderCntDB>(
        *psi_params, oprf_key, label_byte_count, compress);
    sender_cnt_db->set_data(labeled_db_data);
    APSI_LOG_INFO("Created labeled SenderDB with "
                  << sender_cnt_db->get_item_count() << " items and "
                  << label_byte_count << "-byte labels");
  } catch (const std::exception &ex) {
    APSI_LOG_ERROR("Failed to create SenderDB: " << ex.what());
    return nullptr;
  }

  APSI_LOG_INFO("SenderDB packing rate: " << sender_cnt_db->get_packing_rate());

  return sender_cnt_db;
}

std::shared_ptr<psi::dkpir::SenderCntDB> GenerateSenderCntDB(
    const std::string &source_file, const std::string &params_file,
    bool compress, ::apsi::oprf::OPRFKey &oprf_key,
    const std::vector<std::string> &keys,
    const std::vector<std::string> &labels) {
  std::unique_ptr<::apsi::PSIParams> params =
      psi::apsi_wrapper::BuildPsiParams(params_file);
  if (!params) {
    // We must have valid parameters given
    APSI_LOG_ERROR("Failed to set PSI parameters");
    return nullptr;
  }

  std::unique_ptr<psi::apsi_wrapper::DBData> db_data;
  if (source_file.empty() ||
      !(db_data = psi::apsi_wrapper::load_db(source_file, keys, labels))) {
    // Failed to read db file
    APSI_LOG_DEBUG("Failed to load data from a CSV file");
    return nullptr;
  }

  return CreateSenderCntDB(*db_data, std::move(params), oprf_key, compress);
}

bool TrySaveSenderCntDB(const std::string &info_file,
                        const std::string &sdb_out_file,
                        std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db,
                        const ::apsi::oprf::OPRFKey &oprf_key) {
  if (!sender_cnt_db) {
    return false;
  }

  std::ofstream info_out(info_file, std::ios::binary);
  std::ofstream sdb_out(sdb_out_file, std::ios::binary);

  try {
    size_t size = sender_cnt_db->save(info_out, sdb_out);
    APSI_LOG_INFO("Saved SenderCntDB (" << size << " bytes) to " << info_file
                                        << " and " << sdb_out_file);

    // Save also the OPRF key (fixed size: oprf_key_size bytes)
    // Note: This operation seems redundant, because in the online phase we will
    // use the oprf_key in SenderDB
    oprf_key.save(sdb_out);
    APSI_LOG_INFO("Saved OPRF key (" << ::apsi::oprf::oprf_key_size
                                     << " bytes) to " << sdb_out_file);

  } catch (const std::exception &e) {
    APSI_LOG_WARNING("Failed to save SenderCntDB: " << e.what());
    return false;
  }

  return true;
}

std::shared_ptr<psi::dkpir::SenderCntDB> TryLoadSenderCntDB(
    const std::string &info_file, const std::string &sdb_file) {
  std::shared_ptr<psi::dkpir::SenderCntDB> result = nullptr;

  std::ifstream info_in(info_file, std::ios::binary);
  std::ifstream sdb_in(sdb_file, std::ios::binary);

  try {
    auto [data, size] = psi::dkpir::SenderCntDB::Load(info_in, sdb_in);
    APSI_LOG_INFO("Loaded SenderCntDB (" << size << " bytes) from " << info_file
                                         << " and " << sdb_file);
    result = std::make_shared<psi::dkpir::SenderCntDB>(std::move(data));
  } catch (const std::exception &e) {
    APSI_LOG_DEBUG("Failed to load SenderCntDB: " << e.what());
  }

  return result;
}

void print_intersection_results(
    const std::vector<std::string> &orig_items,
    const std::vector<::apsi::Item> &items,
    const std::vector<::apsi::receiver::MatchRecord> &intersection,
    const std::string &out_file, bool append_to_outfile) {
  if (orig_items.size() != items.size()) {
    throw std::invalid_argument("orig_items must have same size as items");
  }

  std::stringstream csv_output;
  std::string csv_header = "key,value";
  int match_cnt = 0;
  for (size_t i = 0; i < orig_items.size(); i++) {
    std::stringstream msg;
    if (intersection[i].found) {
      match_cnt++;
      msg << Colors::GreenBold << orig_items[i] << Colors::Reset << "(FOUND) ";
      csv_output << orig_items[i];
      if (intersection[i].label) {
        msg << ": ";
        msg << Colors::GreenBold << intersection[i].label.to_string()
            << Colors::Reset;
        csv_output << "," << intersection[i].label.to_string();
      }
      csv_output << std::endl;
      APSI_LOG_INFO(msg.str());
    } else {
      // msg << Colors::RedBold << orig_items[i] << Colors::Reset << " (NOT
      // FOUND)"; APSI_LOG_INFO(msg.str());
    }
  }

  if (!out_file.empty()) {
    if (append_to_outfile) {
      std::ofstream ofs(out_file, std::ios_base::app);
      ofs << csv_output.str();
    } else {
      std::ofstream ofs(out_file);
      ofs << csv_header << std::endl;
      ofs << csv_output.str();
    }

    APSI_LOG_INFO("Wrote output to " << out_file);
  }
}

}  // namespace psi::dkpir