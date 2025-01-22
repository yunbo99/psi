#pragma once
#include <memory>

#include "apsi/query.h"

#include "psi/algorithm/dkpir/sender_cnt_db.h"
namespace psi::dkpir {
using QueryRequest = std::unique_ptr<::apsi::network::SenderOperationQuery>;

// A query request can be used to generate a DkPirQuery, which can be used to
// query both data and count
class DkPirQuery : public ::apsi::sender::Query {
 public:
  DkPirQuery(QueryRequest query_request,
             std::shared_ptr<::apsi::sender::SenderDB> sender_db,
             std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db)
      : ::apsi::sender::Query(std::move(query_request), sender_db),
        sender_cnt_db_(std::move(sender_cnt_db)) {};

  std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db() const noexcept {
    return sender_cnt_db_;
  }

 private:
  std::shared_ptr<psi::dkpir::SenderCntDB> sender_cnt_db_;
};
}  // namespace psi::dkpir