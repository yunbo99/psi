
#include "psi/algorithm/dkpir/entry.h"
#include "apsi/log.h"

int main() {
  ::apsi::Log::SetConsoleDisabled(false);
  ::apsi::Log::SetLogLevel("all");
  
  // This is hardcode, just for test
  std::string root_dir = "/home/admin/dev/secretflow/psi/";
  std::string sender_data_file =
      root_dir + "examples/pir/apsi/data/duplicate_key_db.csv";
  std::string params_file =
      root_dir + "examples/pir/apsi/parameters/100-1-300.json";
  std::string sender_key_value_file = root_dir + "tmp/sender_key_value.csv";
  std::string sender_key_count_file = root_dir + "tmp/sender_key_count.csv";
  std::string value_sdb_out_file = root_dir + "tmp/sender_value_sdb_out.db";
  std::string count_info_file = root_dir + "tmp/count_info.db";
  std::string count_sdb_out_file = root_dir + "tmp/count_sdb_out.db";

  // std::shared_ptr<yacl::link::Context> lctx = nullptr;
  // std::string party = "sender";

  // yacl::link::ContextDesc link_desc;
  // link_desc.parties.push_back(
  //     yacl::link::ContextDesc::Party("sender", "127.0.0.1:5300"));
  // link_desc.parties.push_back(
  //     yacl::link::ContextDesc::Party("receiver", "127.0.0.1:5400"));

  // auto link_resource =
  //     psi::ResourceManager::GetInstance().AddLinkResource(party, link_desc);
  // lctx = link_resource->GetLinkContext();

  // psi::ApsiCsvConverter sender_db_converter(
  //     sender_data_file, "id", {"label1", "label2", "label3"});

  // sender_db_converter.MergeColumnAndRow(sender_key_value_file,
  //                                       sender_key_count_file);

  psi::dkpir::DkPirSenderOptions options;

  options.params_file = params_file;
  options.sender_key_value_file = sender_key_value_file;
  options.sender_key_count_file = sender_key_count_file;
  options.value_sdb_out_file = value_sdb_out_file;
  options.count_info_file = count_info_file;
  options.count_sdb_out_file = count_sdb_out_file;

  psi::dkpir::SenderOffline(options);
  // psi::dkpir::SenderOnline(options, lctx);

  // psi::ResourceManager::GetInstance().RemoveAllResource();

  return 0;
}