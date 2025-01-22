#include <variant>

#include "psi/algorithm/dkpir/entry.h"
#include "apsi/log.h"

int main() {
  ::apsi::Log::SetConsoleDisabled(false);
  ::apsi::Log::SetLogLevel("all");
  
  // This is hardcode, just for test
  std::string root_dir = "/home/admin/dev/secretflow/psi/";
  std::string params_file =
      root_dir + "examples/pir/apsi/parameters/100-1-300.json";
  std::string query_file =
      root_dir + "examples/pir/apsi/data/duplicate_key_query.csv";
  std::string tmp_query_file = root_dir + "tmp/tmp_query.csv";
  std::string apsi_output_file = root_dir + "tmp/apsi_output.csv";
  std::string result_file = root_dir + "tmp/result.csv";

  std::shared_ptr<yacl::link::Context> lctx = nullptr;
  std::string party = "receiver";

  yacl::link::ContextDesc link_desc;
  link_desc.parties.push_back(
      yacl::link::ContextDesc::Party("sender", "127.0.0.1:5300"));
  link_desc.parties.push_back(
      yacl::link::ContextDesc::Party("receiver", "127.0.0.1:5400"));

  auto link_resource =
      psi::ResourceManager::GetInstance().AddLinkResource(party, link_desc);
  lctx = link_resource->GetLinkContext();

  psi::apsi_wrapper::ApsiCsvConverter receiver_query_converter(query_file,
                                                               "id");
  receiver_query_converter.ExtractQuery(tmp_query_file);

  psi::dkpir::DkPirReceiverOptions options;
  options.params_file = params_file;
  options.tmp_query_file = tmp_query_file;
  options.apsi_output_file = apsi_output_file;
  options.result_file = result_file;
  options.key = "id";
  options.labels = {"label1", "label2", "label3"};

  psi::dkpir::ReceiverOnline(options, lctx);

  psi::ResourceManager::GetInstance().RemoveAllResource();

  return 0;
}