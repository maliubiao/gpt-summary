Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the `quic_connection_id_manager.cc` file in the Chromium QUIC stack. Key areas to address are functionality, relevance to JavaScript, logical reasoning (input/output), common errors, and debugging steps.

**2. Initial Scan and High-Level Interpretation:**

First, I quickly read through the code to get a general sense of its purpose. Keywords like "ConnectionId," "NewConnectionIdFrame," "RetireConnectionIdFrame," and the class names `QuicPeerIssuedConnectionIdManager` and `QuicSelfIssuedConnectionIdManager` immediately suggest this code is responsible for managing connection IDs in the QUIC protocol. The presence of alarms (`QuicAlarm`) suggests time-based operations, likely related to connection ID lifecycle management.

**3. Deconstructing the Code - Identifying Key Components and their Responsibilities:**

I then go through the code more systematically, focusing on:

* **Classes:** Identify the main classes and their member variables and methods.
    * `QuicConnectionIdData`:  A simple data structure holding information about a connection ID.
    * `QuicPeerIssuedConnectionIdManager`: Handles connection IDs provided by the *peer* (the remote endpoint).
    * `QuicSelfIssuedConnectionIdManager`: Handles connection IDs generated *locally*.
    * Inner anonymous namespace and alarm classes (`RetirePeerIssuedConnectionIdAlarm`, `RetireSelfIssuedConnectionIdAlarmDelegate`): These are helper structures for time-delayed actions.
* **Key Data Structures:** Note the use of `std::vector` for storing connection ID data and how different vectors represent different states (active, unused, to-be-retired). The `RecentValueBuffer` suggests tracking recently seen sequence numbers.
* **Core Functionality (Methods):**  For each class, I examine the methods and try to understand their role:
    * **`QuicPeerIssuedConnectionIdManager`:**  `OnNewConnectionIdFrame`, `ConsumeOneUnusedConnectionId`, `PrepareToRetireConnectionIdPriorTo`, `PrepareToRetireActiveConnectionId`, `MaybeRetireUnusedConnectionIds`, `IsConnectionIdActive`, `ConsumeToBeRetiredConnectionIdSequenceNumbers`, `ReplaceConnectionId`. These clearly manage peer-provided IDs, including receiving new ones, retiring old ones, and tracking their status.
    * **`QuicSelfIssuedConnectionIdManager`:** `MaybeIssueNewConnectionId`, `OnRetireConnectionIdFrame`, `GetUnretiredConnectionIds`, `RetireConnectionId`, `MaybeSendNewConnectionIds`, `ConsumeOneConnectionId`, `IsConnectionIdInUse`. These handle the generation and management of locally generated IDs.
* **Visitor Pattern:**  Notice the `QuicConnectionIdManagerVisitorInterface`. This indicates a visitor pattern, allowing external components to react to connection ID management events.
* **Flags and Configuration:** The `active_connection_id_limit_` variable and mentions of `QuicFlags` suggest configurable limits and behavior.

**4. Connecting to JavaScript (or Lack Thereof):**

At this stage, I consider if and how this code directly interacts with JavaScript. Since this code resides deep within the network stack, and deals with low-level protocol details like connection ID management, *direct* interaction with JavaScript is unlikely. JavaScript running in a browser interacts with network functionalities through higher-level APIs (like `fetch` or WebSockets). The QUIC implementation, of which this code is a part, operates *underneath* those APIs. Therefore, the connection is *indirect*. JavaScript triggers network requests, which eventually lead to QUIC being used, and this code then manages the underlying connection identifiers.

**5. Logical Reasoning (Input/Output):**

To illustrate the logic, I pick a crucial function from each manager and define hypothetical inputs and expected outputs. This clarifies the method's purpose and behavior. For example, with `OnNewConnectionIdFrame`, I consider the scenarios of a valid new ID, a duplicate ID, and an out-of-order retirement.

**6. Identifying Common Errors:**

Based on my understanding of the code and the QUIC protocol, I think about potential issues a developer or the system might encounter:
    * Exceeding connection ID limits.
    * Retiring IDs too quickly.
    * Receiving out-of-order or duplicate `NEW_CONNECTION_ID` frames.
    * Errors in the `ConnectionIdGeneratorInterface`.

**7. Tracing User Operations (Debugging Clues):**

I imagine a typical user interaction (opening a website) and trace how it might eventually involve this code. This helps in understanding how a developer might arrive at this code during debugging. Key steps involve:

* User initiates a network request.
* Browser resolves the domain and establishes a connection (potentially using QUIC).
* The QUIC handshake happens, which involves connection ID negotiation.
* Subsequent data transfer relies on these connection IDs.
* Errors or connection migrations might trigger changes in connection IDs, leading to this code being executed.

**8. Structuring the Answer:**

Finally, I organize my findings into a clear and structured response, covering each point requested in the prompt: functionality, JavaScript relationship, logical reasoning, common errors, and debugging. I use clear headings and bullet points to make the information easily digestible.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this interacts with JavaScript through some internal Chromium API?
* **Correction:** While there might be internal communication, the core function of this code is purely within the QUIC protocol implementation. The interaction with JavaScript is at a higher, abstracted level.
* **Initial thought:**  Focus on every single method.
* **Refinement:** Focus on the *key* methods that illustrate the core functionalities of each class. No need to exhaustively explain every small helper function.
* **Initial thought:**  Overcomplicate the input/output examples.
* **Refinement:** Keep the input/output examples simple and focused on illustrating the primary logic of the chosen methods.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive answer addressing all aspects of the request.
这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_connection_id_manager.cc` 是 Chromium 网络栈中 QUIC 协议实现的关键部分，负责管理 QUIC 连接的连接标识符 (Connection ID, CID)。其主要功能是：

**核心功能:**

1. **管理对端发起的连接 ID (Peer-Issued Connection IDs):**
   - **存储和跟踪:** 维护由通信对端通过 `NEW_CONNECTION_ID` 帧发送过来的连接 ID 及其相关信息，例如序列号和无状态重置令牌。
   - **防止重用:** 确保新收到的连接 ID 不会与之前使用过的 ID 冲突。
   - **限制数量:** 遵守对端可以提供的活动连接 ID 的数量限制，防止资源耗尽。
   - **按需激活:**  将未使用的连接 ID 移动到活动状态，供连接使用。
   - **按需退休 (Retire):**  根据对端发送的 `RETIRE_CONNECTION_ID` 帧，将不再使用的连接 ID 标记为待退休。
   - **批量退休:**  根据对端指示的 `retire_prior_to` 值，批量退休序列号早于该值的连接 ID。
   - **替换:**  允许在特定情况下替换已有的连接 ID。

2. **管理自身发起的连接 ID (Self-Issued Connection IDs):**
   - **生成新的连接 ID:**  根据配置和策略生成新的连接 ID。
   - **分配序列号:**  为每个新生成的连接 ID 分配唯一的序列号。
   - **生成无状态重置令牌:**  为每个新的连接 ID 生成对应的无状态重置令牌。
   - **存储和跟踪:**  维护自身生成的活动连接 ID 及其序列号。
   - **按需发行 (Issue):**  在需要时（例如为了支持连接迁移）生成并发送 `NEW_CONNECTION_ID` 帧给对端。
   - **处理退休请求:** 接收对端发送的 `RETIRE_CONNECTION_ID` 帧，并将对应的连接 ID 标记为待退休。
   - **延迟退休:**  根据 RTT (Round-Trip Time) 估计延迟连接 ID 的实际退休，以避免过早退休导致的问题。

**与 Javascript 的关系:**

这个文件是 C++ 代码，属于 Chromium 浏览器的底层网络协议实现，**不直接**与 Javascript 代码交互。然而，它的功能对基于 Web 的应用至关重要，因为：

- **QUIC 是 HTTP/3 的基础:**  现代浏览器通常使用 QUIC 协议来优化 HTTP/3 的连接。这个文件负责管理 QUIC 连接的关键部分，确保连接的稳定性和可靠性。
- **连接迁移:** 连接 ID 的管理使得 QUIC 能够支持连接迁移，即在客户端 IP 地址或端口发生变化时，连接可以无缝地迁移到新的网络路径，而不会中断用户的 Web 应用体验。这对于移动设备和网络切换非常重要。
- **更好的性能:** QUIC 协议旨在提供比 TCP 更低的延迟和更好的性能，而连接 ID 的有效管理是实现这些目标的关键因素之一。

**举例说明 (Javascript 如何间接受到影响):**

当用户在浏览器中访问一个支持 HTTP/3 的网站时，浏览器底层会使用 QUIC 协议建立连接。`quic_connection_id_manager.cc` 负责管理这个 QUIC 连接的连接 ID。

例如，当用户的移动设备从 Wi-Fi 网络切换到移动数据网络时，IP 地址可能会发生变化。QUIC 协议会利用连接迁移功能来保持连接不断开。`QuicConnectionIdManager` 会参与这个过程：

1. **Javascript 发起请求:**  用户在网页上点击链接或执行某些操作，导致浏览器发起新的网络请求。
2. **浏览器使用 QUIC:** 浏览器判断可以使用 QUIC 连接，并尝试复用已有的连接或建立新的连接。
3. **连接 ID 管理:**  `QuicConnectionIdManager`  会维护当前连接使用的连接 ID。
4. **IP 地址变化:**  用户设备的网络发生变化，IP 地址改变。
5. **连接迁移:**  QUIC 协议会尝试迁移连接到新的 IP 地址。这可能涉及到使用新的连接 ID，`QuicConnectionIdManager` 会参与新连接 ID 的选择和管理。
6. **用户无感知:**  整个过程对于 Javascript 代码和用户来说是透明的，用户不会因为网络切换而看到连接中断。

**逻辑推理 (假设输入与输出):**

**场景 1: 对端发送新的连接 ID**

* **假设输入:**
    * 已经建立的 QUIC 连接。
    * 接收到对端发送的 `NEW_CONNECTION_ID` 帧，包含：
        * `connection_id`:  `0x12345678`
        * `sequence_number`: `1`
        * `stateless_reset_token`: `0xABCDEF0123456789`
        * `retire_prior_to`: `0`
* **逻辑推理:**
    * `IsConnectionIdNew()` 检查 `0x12345678` 是否为新的 ID。假设是新的。
    * 将连接 ID 数据 `(0x12345678, 1, 0xABCDEF0123456789)` 添加到 `unused_connection_id_data_` 列表中。
* **预期输出:**  新的连接 ID 被成功存储，可以后续被激活使用。

**场景 2:  自身需要生成新的连接 ID**

* **假设输入:**
    *  `active_connection_ids_.size()` 小于 `active_connection_id_limit_`。
    *  `connection_id_generator_` 生成了新的 `connection_id`: `0x98765432`。
* **逻辑推理:**
    * `MaybeIssueNewConnectionId()` 被调用。
    * 生成新的序列号，假设为 `1`（如果这是第一个自发起的 ID）。
    * 生成对应的无状态重置令牌。
    * 创建 `QuicNewConnectionIdFrame`。
    * 将新的连接 ID 添加到 `active_connection_ids_` 列表。
    * 调用 `visitor_->SendNewConnectionId()` 发送 `NEW_CONNECTION_ID` 帧。
* **预期输出:**  成功生成并发送 `NEW_CONNECTION_ID` 帧给对端。

**用户或编程常见的使用错误:**

1. **配置的活动连接 ID 限制过低:**  如果配置的 `active_connection_id_limit_` 太小，可能会导致连接无法充分利用连接迁移的优势，或者在需要更多连接 ID 的情况下出现问题。
   * **错误示例:**  将 `active_connection_id_limit_` 设置为 1，导致无法同时使用多个连接 ID 进行连接迁移或多路复用。
2. **连接 ID 生成器故障:**  如果 `ConnectionIdGeneratorInterface` 的实现存在问题，可能导致生成的连接 ID 冲突或不符合规范，从而导致连接失败。
   * **错误示例:**  `ConnectionIdGeneratorInterface` 生成的连接 ID 不是全局唯一的。
3. **不正确地处理 `NEW_CONNECTION_ID` 帧:**  在接收端，如果没有正确处理对端发送的 `NEW_CONNECTION_ID` 帧，例如没有存储新的连接 ID 或没有更新状态，可能导致后续连接迁移失败或出现状态不一致。
   * **错误示例:**  接收到 `NEW_CONNECTION_ID` 帧后，没有添加到 `unused_connection_id_data_` 列表中。
4. **过早退休连接 ID:**  在发送 `RETIRE_CONNECTION_ID` 帧时，如果退休的连接 ID 仍然被对端使用，会导致连接错误。
   * **错误示例:**  在连接迁移完成之前就发送了退休旧连接 ID 的帧。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在 Chrome 浏览器中访问一个使用 HTTP/3 的网站，并且遇到了连接问题，开发人员可能需要调试 `quic_connection_id_manager.cc` 来查找原因：

1. **用户打开网页:** 用户在地址栏输入 URL 并回车，或者点击一个链接。
2. **DNS 解析:** 浏览器进行 DNS 查询，获取目标服务器的 IP 地址。
3. **QUIC 连接建立:**  浏览器尝试与服务器建立 QUIC 连接。这个过程中会涉及到连接 ID 的协商和初始分配。
4. **接收到 `NEW_CONNECTION_ID`:** 服务器可能会发送 `NEW_CONNECTION_ID` 帧给客户端，客户端的 `QuicPeerIssuedConnectionIdManager::OnNewConnectionIdFrame` 会被调用。
5. **连接迁移 (可能发生):** 如果用户的网络环境发生变化（例如从 Wi-Fi 切换到移动数据），QUIC 可能会尝试进行连接迁移。
   - 客户端可能会生成新的连接 ID 并发送 `NEW_CONNECTION_ID`，触发 `QuicSelfIssuedConnectionIdManager::MaybeIssueNewConnectionId`。
   - 服务器可能会要求客户端退休旧的连接 ID，触发 `QuicSelfIssuedConnectionIdManager::OnRetireConnectionIdFrame`。
6. **数据传输:**  建立连接后，浏览器和服务器之间通过 QUIC 连接传输数据，数据包头中会包含连接 ID。
7. **连接关闭:**  当会话结束时，连接会被关闭。

**调试线索:**

- **网络抓包:** 使用 Wireshark 等工具抓取网络包，查看 `NEW_CONNECTION_ID` 和 `RETIRE_CONNECTION_ID` 帧的发送情况，以及连接 ID 的使用情况。
- **QUIC 事件日志:** Chromium 提供了 QUIC 事件日志，可以记录连接 ID 的分配、退休等事件，帮助追踪连接 ID 的生命周期。
- **断点调试:**  在 `quic_connection_id_manager.cc` 中的关键函数（如 `OnNewConnectionIdFrame`, `MaybeIssueNewConnectionId`, `OnRetireConnectionIdFrame`) 设置断点，查看连接 ID 的状态变化和参数值。
- **查看连接状态:**  Chromium 的内部工具 (如 `chrome://net-internals/#quic`) 可以查看当前 QUIC 连接的状态，包括使用的连接 ID 信息。

通过以上步骤和工具，开发人员可以逐步定位与连接 ID 管理相关的网络问题。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_id_manager.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_connection_id_manager.h"

#include <algorithm>
#include <cstdio>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

QuicConnectionIdData::QuicConnectionIdData(
    const QuicConnectionId& connection_id, uint64_t sequence_number,
    const StatelessResetToken& stateless_reset_token)
    : connection_id(connection_id),
      sequence_number(sequence_number),
      stateless_reset_token(stateless_reset_token) {}

namespace {

class RetirePeerIssuedConnectionIdAlarm
    : public QuicAlarm::DelegateWithContext {
 public:
  explicit RetirePeerIssuedConnectionIdAlarm(
      QuicConnectionIdManagerVisitorInterface* visitor,
      QuicConnectionContext* context)
      : QuicAlarm::DelegateWithContext(context), visitor_(visitor) {}
  RetirePeerIssuedConnectionIdAlarm(const RetirePeerIssuedConnectionIdAlarm&) =
      delete;
  RetirePeerIssuedConnectionIdAlarm& operator=(
      const RetirePeerIssuedConnectionIdAlarm&) = delete;

  void OnAlarm() override { visitor_->OnPeerIssuedConnectionIdRetired(); }

 private:
  QuicConnectionIdManagerVisitorInterface* visitor_;
};

std::vector<QuicConnectionIdData>::const_iterator FindConnectionIdData(
    const std::vector<QuicConnectionIdData>& cid_data_vector,
    const QuicConnectionId& cid) {
  return std::find_if(cid_data_vector.begin(), cid_data_vector.end(),
                      [&cid](const QuicConnectionIdData& cid_data) {
                        return cid == cid_data.connection_id;
                      });
}

std::vector<QuicConnectionIdData>::iterator FindConnectionIdData(
    std::vector<QuicConnectionIdData>* cid_data_vector,
    const QuicConnectionId& cid) {
  return std::find_if(cid_data_vector->begin(), cid_data_vector->end(),
                      [&cid](const QuicConnectionIdData& cid_data) {
                        return cid == cid_data.connection_id;
                      });
}

}  // namespace

QuicPeerIssuedConnectionIdManager::QuicPeerIssuedConnectionIdManager(
    size_t active_connection_id_limit,
    const QuicConnectionId& initial_peer_issued_connection_id,
    const QuicClock* clock, QuicAlarmFactory* alarm_factory,
    QuicConnectionIdManagerVisitorInterface* visitor,
    QuicConnectionContext* context)
    : active_connection_id_limit_(active_connection_id_limit),
      clock_(clock),
      retire_connection_id_alarm_(alarm_factory->CreateAlarm(
          new RetirePeerIssuedConnectionIdAlarm(visitor, context))) {
  QUICHE_DCHECK_GE(active_connection_id_limit_, 2u);
  QUICHE_DCHECK(!initial_peer_issued_connection_id.IsEmpty());
  active_connection_id_data_.emplace_back<const QuicConnectionId&, uint64_t,
                                          const StatelessResetToken&>(
      initial_peer_issued_connection_id,
      /*sequence_number=*/0u, {});
  recent_new_connection_id_sequence_numbers_.Add(0u, 1u);
}

QuicPeerIssuedConnectionIdManager::~QuicPeerIssuedConnectionIdManager() {
  retire_connection_id_alarm_->Cancel();
}

bool QuicPeerIssuedConnectionIdManager::IsConnectionIdNew(
    const QuicNewConnectionIdFrame& frame) {
  auto is_old_connection_id = [&frame](const QuicConnectionIdData& cid_data) {
    return cid_data.connection_id == frame.connection_id;
  };
  if (std::any_of(active_connection_id_data_.begin(),
                  active_connection_id_data_.end(), is_old_connection_id)) {
    return false;
  }
  if (std::any_of(unused_connection_id_data_.begin(),
                  unused_connection_id_data_.end(), is_old_connection_id)) {
    return false;
  }
  if (std::any_of(to_be_retired_connection_id_data_.begin(),
                  to_be_retired_connection_id_data_.end(),
                  is_old_connection_id)) {
    return false;
  }
  return true;
}

void QuicPeerIssuedConnectionIdManager::PrepareToRetireConnectionIdPriorTo(
    uint64_t retire_prior_to,
    std::vector<QuicConnectionIdData>* cid_data_vector) {
  auto it2 = cid_data_vector->begin();
  for (auto it = cid_data_vector->begin(); it != cid_data_vector->end(); ++it) {
    if (it->sequence_number >= retire_prior_to) {
      *it2++ = *it;
    } else {
      to_be_retired_connection_id_data_.push_back(*it);
      if (!retire_connection_id_alarm_->IsSet()) {
        retire_connection_id_alarm_->Set(clock_->ApproximateNow());
      }
    }
  }
  cid_data_vector->erase(it2, cid_data_vector->end());
}

QuicErrorCode QuicPeerIssuedConnectionIdManager::OnNewConnectionIdFrame(
    const QuicNewConnectionIdFrame& frame, std::string* error_detail,
    bool* is_duplicate_frame) {
  if (recent_new_connection_id_sequence_numbers_.Contains(
          frame.sequence_number)) {
    // This frame has a recently seen sequence number. Ignore.
    *is_duplicate_frame = true;
    return QUIC_NO_ERROR;
  }
  if (!IsConnectionIdNew(frame)) {
    *error_detail =
        "Received a NEW_CONNECTION_ID frame that reuses a previously seen Id.";
    return IETF_QUIC_PROTOCOL_VIOLATION;
  }

  recent_new_connection_id_sequence_numbers_.AddOptimizedForAppend(
      frame.sequence_number, frame.sequence_number + 1);

  if (recent_new_connection_id_sequence_numbers_.Size() >
      kMaxNumConnectionIdSequenceNumberIntervals) {
    *error_detail =
        "Too many disjoint connection Id sequence number intervals.";
    return IETF_QUIC_PROTOCOL_VIOLATION;
  }

  // QuicFramer::ProcessNewConnectionIdFrame guarantees that
  // frame.sequence_number >= frame.retire_prior_to, and hence there is no need
  // to check that.
  if (frame.sequence_number < max_new_connection_id_frame_retire_prior_to_) {
    // Later frames have asked for retirement of the current frame.
    to_be_retired_connection_id_data_.emplace_back(frame.connection_id,
                                                   frame.sequence_number,
                                                   frame.stateless_reset_token);
    if (!retire_connection_id_alarm_->IsSet()) {
      retire_connection_id_alarm_->Set(clock_->ApproximateNow());
    }
    return QUIC_NO_ERROR;
  }
  if (frame.retire_prior_to > max_new_connection_id_frame_retire_prior_to_) {
    max_new_connection_id_frame_retire_prior_to_ = frame.retire_prior_to;
    PrepareToRetireConnectionIdPriorTo(frame.retire_prior_to,
                                       &active_connection_id_data_);
    PrepareToRetireConnectionIdPriorTo(frame.retire_prior_to,
                                       &unused_connection_id_data_);
  }

  if (active_connection_id_data_.size() + unused_connection_id_data_.size() >=
      active_connection_id_limit_) {
    *error_detail = "Peer provides more connection IDs than the limit.";
    return QUIC_CONNECTION_ID_LIMIT_ERROR;
  }

  unused_connection_id_data_.emplace_back(
      frame.connection_id, frame.sequence_number, frame.stateless_reset_token);
  return QUIC_NO_ERROR;
}

const QuicConnectionIdData*
QuicPeerIssuedConnectionIdManager::ConsumeOneUnusedConnectionId() {
  if (unused_connection_id_data_.empty()) {
    return nullptr;
  }
  active_connection_id_data_.push_back(unused_connection_id_data_.back());
  unused_connection_id_data_.pop_back();
  return &active_connection_id_data_.back();
}

void QuicPeerIssuedConnectionIdManager::PrepareToRetireActiveConnectionId(
    const QuicConnectionId& cid) {
  auto it = FindConnectionIdData(active_connection_id_data_, cid);
  if (it == active_connection_id_data_.end()) {
    // The cid has already been retired.
    return;
  }
  to_be_retired_connection_id_data_.push_back(*it);
  active_connection_id_data_.erase(it);
  if (!retire_connection_id_alarm_->IsSet()) {
    retire_connection_id_alarm_->Set(clock_->ApproximateNow());
  }
}

void QuicPeerIssuedConnectionIdManager::MaybeRetireUnusedConnectionIds(
    const std::vector<QuicConnectionId>& active_connection_ids_on_path) {
  std::vector<QuicConnectionId> cids_to_retire;
  for (const auto& cid_data : active_connection_id_data_) {
    if (std::find(active_connection_ids_on_path.begin(),
                  active_connection_ids_on_path.end(),
                  cid_data.connection_id) ==
        active_connection_ids_on_path.end()) {
      cids_to_retire.push_back(cid_data.connection_id);
    }
  }
  for (const auto& cid : cids_to_retire) {
    PrepareToRetireActiveConnectionId(cid);
  }
}

bool QuicPeerIssuedConnectionIdManager::IsConnectionIdActive(
    const QuicConnectionId& cid) const {
  return FindConnectionIdData(active_connection_id_data_, cid) !=
         active_connection_id_data_.end();
}

std::vector<uint64_t> QuicPeerIssuedConnectionIdManager::
    ConsumeToBeRetiredConnectionIdSequenceNumbers() {
  std::vector<uint64_t> result;
  for (auto const& cid_data : to_be_retired_connection_id_data_) {
    result.push_back(cid_data.sequence_number);
  }
  to_be_retired_connection_id_data_.clear();
  return result;
}

void QuicPeerIssuedConnectionIdManager::ReplaceConnectionId(
    const QuicConnectionId& old_connection_id,
    const QuicConnectionId& new_connection_id) {
  auto it1 =
      FindConnectionIdData(&active_connection_id_data_, old_connection_id);
  if (it1 != active_connection_id_data_.end()) {
    it1->connection_id = new_connection_id;
    return;
  }
  auto it2 = FindConnectionIdData(&to_be_retired_connection_id_data_,
                                  old_connection_id);
  if (it2 != to_be_retired_connection_id_data_.end()) {
    it2->connection_id = new_connection_id;
  }
}

namespace {

class RetireSelfIssuedConnectionIdAlarmDelegate
    : public QuicAlarm::DelegateWithContext {
 public:
  explicit RetireSelfIssuedConnectionIdAlarmDelegate(
      QuicSelfIssuedConnectionIdManager* connection_id_manager,
      QuicConnectionContext* context)
      : QuicAlarm::DelegateWithContext(context),
        connection_id_manager_(connection_id_manager) {}
  RetireSelfIssuedConnectionIdAlarmDelegate(
      const RetireSelfIssuedConnectionIdAlarmDelegate&) = delete;
  RetireSelfIssuedConnectionIdAlarmDelegate& operator=(
      const RetireSelfIssuedConnectionIdAlarmDelegate&) = delete;

  void OnAlarm() override { connection_id_manager_->RetireConnectionId(); }

 private:
  QuicSelfIssuedConnectionIdManager* connection_id_manager_;
};

}  // namespace

QuicSelfIssuedConnectionIdManager::QuicSelfIssuedConnectionIdManager(
    size_t active_connection_id_limit,
    const QuicConnectionId& initial_connection_id, const QuicClock* clock,
    QuicAlarmFactory* alarm_factory,
    QuicConnectionIdManagerVisitorInterface* visitor,
    QuicConnectionContext* context, ConnectionIdGeneratorInterface& generator)
    : active_connection_id_limit_(active_connection_id_limit),
      clock_(clock),
      visitor_(visitor),
      retire_connection_id_alarm_(alarm_factory->CreateAlarm(
          new RetireSelfIssuedConnectionIdAlarmDelegate(this, context))),
      last_connection_id_(initial_connection_id),
      next_connection_id_sequence_number_(1u),
      last_connection_id_consumed_by_self_sequence_number_(0u),
      connection_id_generator_(generator) {
  active_connection_ids_.emplace_back(initial_connection_id, 0u);
}

QuicSelfIssuedConnectionIdManager::~QuicSelfIssuedConnectionIdManager() {
  retire_connection_id_alarm_->Cancel();
}

std::optional<QuicNewConnectionIdFrame>
QuicSelfIssuedConnectionIdManager::MaybeIssueNewConnectionId() {
  std::optional<QuicConnectionId> new_cid =
      connection_id_generator_.GenerateNextConnectionId(last_connection_id_);
  if (!new_cid.has_value()) {
    return {};
  }
  if (!visitor_->MaybeReserveConnectionId(*new_cid)) {
    return {};
  }
  QuicNewConnectionIdFrame frame;
  frame.connection_id = *new_cid;
  frame.sequence_number = next_connection_id_sequence_number_++;
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  active_connection_ids_.emplace_back(frame.connection_id,
                                      frame.sequence_number);
  frame.retire_prior_to = active_connection_ids_.front().second;
  last_connection_id_ = frame.connection_id;
  return frame;
}

std::optional<QuicNewConnectionIdFrame> QuicSelfIssuedConnectionIdManager::
    MaybeIssueNewConnectionIdForPreferredAddress() {
  std::optional<QuicNewConnectionIdFrame> frame = MaybeIssueNewConnectionId();
  QUICHE_DCHECK(!frame.has_value() || (frame->sequence_number == 1u));
  return frame;
}

QuicErrorCode QuicSelfIssuedConnectionIdManager::OnRetireConnectionIdFrame(
    const QuicRetireConnectionIdFrame& frame, QuicTime::Delta pto_delay,
    std::string* error_detail) {
  QUICHE_DCHECK(!active_connection_ids_.empty());
  if (frame.sequence_number >= next_connection_id_sequence_number_) {
    *error_detail = "To be retired connecton ID is never issued.";
    return IETF_QUIC_PROTOCOL_VIOLATION;
  }

  auto it =
      std::find_if(active_connection_ids_.begin(), active_connection_ids_.end(),
                   [&frame](const std::pair<QuicConnectionId, uint64_t>& p) {
                     return p.second == frame.sequence_number;
                   });
  // The corresponding connection ID has been retired. Ignore.
  if (it == active_connection_ids_.end()) {
    return QUIC_NO_ERROR;
  }

  if (to_be_retired_connection_ids_.size() + active_connection_ids_.size() >=
      kMaxNumConnectonIdsInUse) {
    // Close connection if the number of connection IDs in use will exeed the
    // limit, i.e., peer retires connection ID too fast.
    *error_detail = "There are too many connection IDs in use.";
    return QUIC_TOO_MANY_CONNECTION_ID_WAITING_TO_RETIRE;
  }

  QuicTime retirement_time = clock_->ApproximateNow() + 3 * pto_delay;
  if (!to_be_retired_connection_ids_.empty()) {
    retirement_time =
        std::max(retirement_time, to_be_retired_connection_ids_.back().second);
  }

  to_be_retired_connection_ids_.emplace_back(it->first, retirement_time);
  if (!retire_connection_id_alarm_->IsSet()) {
    retire_connection_id_alarm_->Set(retirement_time);
  }

  active_connection_ids_.erase(it);
  MaybeSendNewConnectionIds();

  return QUIC_NO_ERROR;
}

std::vector<QuicConnectionId>
QuicSelfIssuedConnectionIdManager::GetUnretiredConnectionIds() const {
  std::vector<QuicConnectionId> unretired_ids;
  for (const auto& cid_pair : to_be_retired_connection_ids_) {
    unretired_ids.push_back(cid_pair.first);
  }
  for (const auto& cid_pair : active_connection_ids_) {
    unretired_ids.push_back(cid_pair.first);
  }
  return unretired_ids;
}

QuicConnectionId QuicSelfIssuedConnectionIdManager::GetOneActiveConnectionId()
    const {
  QUICHE_DCHECK(!active_connection_ids_.empty());
  return active_connection_ids_.front().first;
}

void QuicSelfIssuedConnectionIdManager::RetireConnectionId() {
  if (to_be_retired_connection_ids_.empty()) {
    QUIC_BUG(quic_bug_12420_1)
        << "retire_connection_id_alarm fired but there is no connection ID "
           "to be retired.";
    return;
  }
  QuicTime now = clock_->ApproximateNow();
  auto it = to_be_retired_connection_ids_.begin();
  do {
    visitor_->OnSelfIssuedConnectionIdRetired(it->first);
    ++it;
  } while (it != to_be_retired_connection_ids_.end() && it->second <= now);
  to_be_retired_connection_ids_.erase(to_be_retired_connection_ids_.begin(),
                                      it);
  // Set the alarm again if there is another connection ID to be removed.
  if (!to_be_retired_connection_ids_.empty()) {
    retire_connection_id_alarm_->Set(
        to_be_retired_connection_ids_.front().second);
  }
}

void QuicSelfIssuedConnectionIdManager::MaybeSendNewConnectionIds() {
  while (active_connection_ids_.size() < active_connection_id_limit_) {
    std::optional<QuicNewConnectionIdFrame> frame = MaybeIssueNewConnectionId();
    if (!frame.has_value()) {
      break;
    }
    if (!visitor_->SendNewConnectionId(*frame)) {
      break;
    }
  }
}

bool QuicSelfIssuedConnectionIdManager::HasConnectionIdToConsume() const {
  for (const auto& active_cid_data : active_connection_ids_) {
    if (active_cid_data.second >
        last_connection_id_consumed_by_self_sequence_number_) {
      return true;
    }
  }
  return false;
}

std::optional<QuicConnectionId>
QuicSelfIssuedConnectionIdManager::ConsumeOneConnectionId() {
  for (const auto& active_cid_data : active_connection_ids_) {
    if (active_cid_data.second >
        last_connection_id_consumed_by_self_sequence_number_) {
      // Since connection IDs in active_connection_ids_ has monotonically
      // increasing sequence numbers, the returned connection ID has the
      // smallest sequence number among all unconsumed active connection IDs.
      last_connection_id_consumed_by_self_sequence_number_ =
          active_cid_data.second;
      return active_cid_data.first;
    }
  }
  return std::nullopt;
}

bool QuicSelfIssuedConnectionIdManager::IsConnectionIdInUse(
    const QuicConnectionId& cid) const {
  for (const auto& active_cid_data : active_connection_ids_) {
    if (active_cid_data.first == cid) {
      return true;
    }
  }
  for (const auto& to_be_retired_cid_data : to_be_retired_connection_ids_) {
    if (to_be_retired_cid_data.first == cid) {
      return true;
    }
  }
  return false;
}

}  // namespace quic
```