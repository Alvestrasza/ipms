#pragma once

#include "ipms/agent/hyperv_pack.hpp"

#include <optional>
#include <string>
#include <utility>

namespace ipms::agent {

struct console_input_assignment {
  std::string session_id;
  std::string vm_source_id;
  std::string vm_name;
  std::vector<windows::hyperv_console_input> inputs;
};

struct console_input_poll_result {
  bool active{false};
  std::optional<console_input_assignment> assignment;
};

struct console_input_receipt {
  std::string session_id;
  std::vector<std::string> acknowledged_ids;
  std::string failure_code;
};

// One ordered input executor owns this dispatcher. A receipt survives transport
// failure and worker restarts: retry the receipt, never the local VM operation.
class console_input_dispatcher {
 public:
  template <typename Cancelled, typename Poll, typename Apply, typename Deliver,
            typename IdentityCurrent>
  bool cycle(const std::string& identity, Cancelled cancelled, Poll poll,
             Apply apply, Deliver deliver, IdentityCurrent identity_current) {
    if (cancelled()) return false;
    if (pending_) {
      // An enrollment/endpoint change cannot replay another identity's input.
      // The old session remains owned by the old enrollment and expires there.
      if (pending_identity_ != identity) {
        pending_.reset();
      } else {
        const bool active = deliver(*pending_);
        pending_.reset();
        return active;
      }
    }
    const auto polled = poll();
    if (!polled.assignment || cancelled() || !identity_current()) return polled.active;
    const auto& assignment = *polled.assignment;
    // Install a fail-closed receipt before touching the VM. Even an exception
    // after a partially applied batch must not cause the batch to be replayed.
    pending_identity_ = identity;
    pending_ = console_input_receipt{assignment.session_id, {}, "console_input_failed"};
    const auto result = apply(assignment, cancelled);
    pending_->acknowledged_ids = result.acknowledged_input_ids;
    if (result.succeeded) pending_->failure_code.clear();
    if (cancelled()) return polled.active;
    const bool active = deliver(*pending_);
    pending_.reset();
    return active;
  }

 private:
  std::string pending_identity_;
  std::optional<console_input_receipt> pending_;
};

}  // namespace ipms::agent
