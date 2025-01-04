Response:
Let's break down the thought process for analyzing the `quic_connection_alarms.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relation to JavaScript, logical inferences (with input/output examples), common usage errors, and debugging context.

2. **Initial Scan and Core Concept:** Quickly read through the code, focusing on class names and key function calls. The name `QuicConnectionAlarms` and the various alarm delegates (like `AckAlarmDelegate`, `RetransmissionAlarmDelegate`) immediately suggest this file is responsible for managing timers or scheduled events within a QUIC connection.

3. **Identify Key Classes and Their Roles:**
    * `QuicConnectionAlarms`: The main class, likely responsible for holding and managing the different alarms.
    * `QuicAlarm`: A base class for alarms. The delegates inherit from this, defining the action when the alarm fires.
    * `QuicConnectionAlarmDelegate`:  A base delegate for alarms specifically tied to a `QuicConnectionAlarmsDelegate`.
    * Specific Alarm Delegates (`AckAlarmDelegate`, `RetransmissionAlarmDelegate`, etc.): Each represents a distinct type of scheduled event. Their `OnAlarm()` methods point to corresponding methods in the `QuicConnectionAlarmsDelegate`.
    * `QuicAlarmMultiplexer`: An optional component (controlled by a flag) that seems to manage multiple alarms using fewer underlying system timers. This is an optimization.
    * `QuicConnectionAlarmHolder`: Used when the multiplexer is disabled, it directly holds individual `QuicAlarm` instances.

4. **Determine Functionality by Analyzing Alarm Types:**  Go through each specific alarm delegate and its `OnAlarm()` method. This reveals the core functions:
    * `AckAlarmDelegate` -> `OnAckAlarm()`: Sending acknowledgements.
    * `RetransmissionAlarmDelegate` -> `OnRetransmissionAlarm()`: Retransmitting lost packets.
    * `SendAlarmDelegate` -> `OnSendAlarm()`:  Triggering packet sending (likely after a delay).
    * `MtuDiscoveryAlarmDelegate` -> `OnMtuDiscoveryAlarm()`:  Performing MTU discovery.
    * ... and so on for the other alarms.

5. **Consider the Multiplexer:** Realize that the `QuicAlarmMultiplexer` is an optimization. It doesn't change the *types* of alarms, but how they're scheduled. Its functionality is to consolidate multiple alarms onto fewer underlying timers to improve efficiency. The `FireAlarms()` method iterates through due alarms and triggers them.

6. **JavaScript Relationship:**  Think about how QUIC and the Chromium network stack interact with web browsers (and thus JavaScript). QUIC is a transport protocol. JavaScript in a browser interacts with network protocols via browser APIs (like `fetch` or WebSockets). The connection alarms within QUIC are *under the hood*. JavaScript doesn't directly manipulate these timers. However, the *effects* of these alarms are visible:  faster loading (due to retransmissions), timely acknowledgements, etc. The key is indirect influence, not direct control.

7. **Logical Inferences (Input/Output):**  Choose a specific alarm, like the retransmission alarm. Hypothesize a scenario:
    * **Input:** Packet loss detected (e.g., missing acknowledgements). The retransmission alarm is set.
    * **Output:** When the alarm fires, the lost packets are retransmitted. This demonstrates the alarm's purpose. Similarly, consider the idle detector alarm and what happens when a connection is idle for too long.

8. **Common Usage Errors:** Focus on the developer/programmer perspective within the Chromium codebase. Since this is internal QUIC code, the "user" is a Chromium developer working on the networking stack. Potential errors would involve:
    * Incorrectly setting or canceling alarms.
    * Not handling alarm firings properly.
    * Issues with the multiplexer logic (if enabled). The code itself contains `QUICHE_BUG` checks, which hint at potential internal errors.

9. **Debugging Context (User Operations):** Trace a high-level user action that would involve a QUIC connection:
    * User types a URL and hits Enter.
    * Browser initiates a connection.
    * QUIC is negotiated.
    * Data transfer occurs.
    *  Consider scenarios where specific alarms become relevant: network issues triggering retransmissions, idle connections triggering the idle detector, etc. This helps explain *why* these alarms exist.

10. **Structure and Refine:** Organize the information into the requested categories. Use clear and concise language. Provide specific examples where needed. Ensure the explanation is accurate and reflects the code's functionality. For example, when discussing the multiplexer, highlight that it's an optimization and not a fundamental change in the alarm *types*.

11. **Review and Verify:** Read through the generated explanation to ensure it's comprehensive, accurate, and addresses all parts of the request. Check for any misunderstandings or misinterpretations of the code. For instance, double-check the purpose of each alarm delegate against the code.
这个C++源代码文件 `quic_connection_alarms.cc` 属于 Chromium 的网络栈，更具体地说是 QUIC 协议的实现部分。它的主要功能是**管理 QUIC 连接中各种需要定时触发的事件，即管理连接的各种定时器（Alarms）**。

以下是其更详细的功能列表：

**核心功能：管理 QUIC 连接的定时器**

* **创建和持有各种类型的定时器：**  文件中定义了多个内部类（如 `AckAlarmDelegate`, `RetransmissionAlarmDelegate` 等），每个类对应一种特定的 QUIC 连接定时器。这些定时器用于处理连接生命周期中的不同事件。
* **调度定时器：**  `QuicConnectionAlarms` 类负责创建并持有这些定时器，并根据需要设置它们的触发时间。
* **触发定时器回调：** 当定时器到期时，会调用相应的 `OnAlarm()` 方法，执行预定义的操作。这些操作通常会调用 `QuicConnectionAlarmsDelegate` 接口中定义的方法，将事件通知给 QUIC 连接的更高层逻辑。
* **使用或不使用多路复用器优化定时器管理：**  文件实现了两种管理定时器的方式：
    * **独立定时器：**  每个逻辑定时器都有一个独立的底层系统定时器。
    * **定时器多路复用器 (`QuicAlarmMultiplexer`)：**  将多个逻辑定时器复用到较少的底层系统定时器上，以减少系统调用的开销，提高效率。是否使用多路复用器由 `quic_use_alarm_multiplexer` 这个 Feature Flag 控制。

**各种类型的定时器及其功能：**

文件中定义了以下几种关键的定时器类型：

* **`AckAlarmDelegate` (Ack Alarm):**  用于触发发送确认 (ACK) 包。当接收到新的数据包或者需要延迟确认时会设置此定时器。
* **`RetransmissionAlarmDelegate` (Retransmission Alarm):** 用于检测丢失的数据包并触发重传。当发送数据包后，如果没有及时收到确认，此定时器会触发。
* **`SendAlarmDelegate` (Send Alarm):** 用于在发送队列有待发送数据但由于拥塞控制或其他原因需要延迟发送时，定时检查是否可以发送数据。
* **`MtuDiscoveryAlarmDelegate` (MTU Discovery Alarm):**  用于触发路径最大传输单元 (MTU) 发现过程，以优化数据包大小。
* **`ProcessUndecryptablePacketsAlarmDelegate` (Process Undecryptable Packets Alarm):**  用于延迟处理无法立即解密的包，可能因为密钥尚未就绪。
* **`DiscardPreviousOneRttKeysAlarmDelegate` (Discard Previous One RTT Keys Alarm):**  用于在密钥更新后，定时丢弃旧的 1-RTT 加密密钥。
* **`DiscardZeroRttDecryptionKeysAlarmDelegate` (Discard Zero RTT Decryption Keys Alarm):** 用于在一定时间后丢弃 0-RTT 解密密钥。
* **`MultiPortProbingAlarmDelegate` (Multi-Port Probing Alarm):** 用于触发多端口探测，尝试在不同的网络路径上发送数据。
* **`IdleDetectorAlarmDelegate` (Idle Detector Alarm):** 用于检测连接是否空闲，并在空闲超时后执行相应操作（例如关闭连接）。
* **`NetworkBlackholeDetectorAlarmDelegate` (Network Blackhole Detector Alarm):** 用于检测网络是否出现黑洞（数据包丢失但没有明显拥塞），并采取措施。
* **`PingAlarmDelegate` (Ping Alarm):** 用于发送 PING 帧，以保持连接活跃或进行 RTT 测量。
* **`MultiplexerAlarmDelegate` (用于 `QuicAlarmMultiplexer`):** 当使用多路复用器时，这个定时器用于批量触发到期的逻辑定时器。

**与 JavaScript 的关系：**

这个 C++ 文件本身不直接包含 JavaScript 代码，因此没有直接的 JavaScript 功能。然而，它通过以下方式间接地影响 JavaScript 的功能：

* **网络性能：**  QUIC 协议是现代 Web 浏览器使用的重要网络协议，用于加速 HTTP/3 等应用。这个文件管理的定时器对于 QUIC 连接的稳定性和性能至关重要。例如，重传定时器确保丢失的数据包能够被及时重传，从而避免页面加载卡顿。确认定时器确保及时发送 ACK，维持流量控制和拥塞控制的正常运作。
* **用户体验：**  通过优化网络连接，例如进行 MTU 发现以减少分片，以及检测网络问题并采取措施，这个文件有助于提升用户的网页浏览体验。更快的页面加载速度和更稳定的连接直接影响用户在浏览器中运行的 JavaScript 代码的性能和响应速度。

**举例说明（假设输入与输出）：**

**假设输入（针对 `RetransmissionAlarmDelegate`）：**

1. **发送方发送了数据包 P1, P2, P3。**
2. **发送方设置了重传定时器，例如 100ms 后触发。**
3. **发送方收到了对 P1 和 P3 的 ACK，但没有收到对 P2 的 ACK。**
4. **100ms 时间到，重传定时器触发。**

**输出：**

* `RetransmissionAlarmDelegate::OnAlarm()` 被调用。
* `connection_->OnRetransmissionAlarm()` 被调用。
* QUIC 连接的重传逻辑判断数据包 P2 丢失。
* **发送方重新发送数据包 P2。**

**假设输入（针对 `IdleDetectorAlarmDelegate`）：**

1. **连接建立后，空闲超时时间设置为 30 秒。**
2. **在 30 秒内，没有发送或接收到任何新的数据。**
3. **空闲检测定时器触发。**

**输出：**

* `IdleDetectorAlarmDelegate::OnAlarm()` 被调用。
* `connection_->OnIdleDetectorAlarm()` 被调用。
* QUIC 连接的空闲检测逻辑判断连接已空闲超时。
* **连接被关闭。**

**用户或编程常见的使用错误（C++ 层面）：**

这些错误通常发生在 QUIC 协议的实现层面，而不是最终用户层面：

* **错误地设置或取消定时器：**  如果开发者在代码中错误地设置了定时器的触发时间，或者忘记在某些情况下取消定时器，可能会导致非预期的行为，例如过早或过晚地触发事件。
* **在定时器回调中执行耗时操作：** 定时器回调应该尽可能快地执行，避免阻塞事件循环。如果在回调中执行了耗时操作，可能会导致其他定时器延迟触发，甚至影响整个连接的性能。
* **并发访问问题：** 在多线程环境下，需要确保对定时器状态的访问是线程安全的，避免出现竞态条件。
* **资源泄漏：** 如果定时器对象没有被正确地释放，可能会导致内存泄漏。

**用户操作如何一步步到达这里（调试线索）：**

假设用户在浏览器中访问一个使用 HTTP/3 (基于 QUIC) 的网站，并且遇到了网络问题，例如页面加载缓慢。以下是可能触发到这个文件相关代码的路径：

1. **用户在浏览器地址栏输入 URL 并按下 Enter 键。**
2. **浏览器发起网络请求。**
3. **浏览器与服务器协商使用 QUIC 协议建立连接。**
4. **连接建立后，数据开始传输。**

**调试线索：**

* **网络延迟或丢包：** 如果网络出现延迟或丢包，`RetransmissionAlarmDelegate` 相关的代码会被触发，尝试重传丢失的数据包。调试时可以检查是否有大量的重传事件发生。
* **连接空闲：** 如果用户在页面加载后长时间没有进行任何操作，`IdleDetectorAlarmDelegate` 相关的代码可能会被触发，最终可能导致连接关闭。调试时可以观察连接的空闲状态和空闲超时时间。
* **MTU 问题：** 如果网络路径的 MTU 设置不合理，导致数据包需要分片，`MtuDiscoveryAlarmDelegate` 相关的代码会被触发，尝试发现最佳的 MTU 值。
* **密钥协商或更新问题：** 在 QUIC 连接的密钥协商或更新过程中，`ProcessUndecryptablePacketsAlarmDelegate`，`DiscardPreviousOneRttKeysAlarmDelegate`，`DiscardZeroRttDecryptionKeysAlarmDelegate` 相关的代码可能会被触发。
* **多端口连接尝试：** 如果启用了多端口支持，并且连接遇到问题，`MultiPortProbingAlarmDelegate` 相关的代码可能会被触发，尝试在其他端口上建立连接。
* **Keep-alive 机制：** 为了保持连接活跃，`PingAlarmDelegate` 相关的代码会定期发送 PING 帧。

在 Chromium 的调试工具中（例如 `net-internals`），可以查看 QUIC 连接的详细信息，包括激活的定时器及其触发时间。通过分析这些信息，可以追踪问题的根源，并定位到 `quic_connection_alarms.cc` 文件中相关的逻辑。

总而言之，`quic_connection_alarms.cc` 是 QUIC 协议实现中负责管理关键时间事件的核心组件，它通过调度和触发各种类型的定时器，保证了 QUIC 连接的可靠性、性能和安全性。虽然 JavaScript 不直接操作这些定时器，但这些定时器的工作直接影响着基于 QUIC 的 Web 应用的用户体验。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_alarms.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_connection_alarms.h"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/base/nullability.h"
#include "absl/container/inlined_vector.h"
#include "absl/strings/str_format.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_connection_context.h"
#include "quiche/quic/core/quic_one_block_arena.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

namespace {

// Base class of all alarms owned by a QuicConnection.
class QuicConnectionAlarmDelegate : public QuicAlarm::Delegate {
 public:
  explicit QuicConnectionAlarmDelegate(QuicConnectionAlarmsDelegate* connection)
      : connection_(connection) {}
  QuicConnectionAlarmDelegate(const QuicConnectionAlarmDelegate&) = delete;
  QuicConnectionAlarmDelegate& operator=(const QuicConnectionAlarmDelegate&) =
      delete;

  QuicConnectionContext* GetConnectionContext() override {
    return (connection_ == nullptr) ? nullptr : connection_->context();
  }

 protected:
  QuicConnectionAlarmsDelegate* connection_;
};

// An alarm that is scheduled to send an ack if a timeout occurs.
class AckAlarmDelegate : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  void OnAlarm() override { connection_->OnAckAlarm(); }
};

// This alarm will be scheduled any time a data-bearing packet is sent out.
// When the alarm goes off, the connection checks to see if the oldest packets
// have been acked, and retransmit them if they have not.
class RetransmissionAlarmDelegate : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  void OnAlarm() override { connection_->OnRetransmissionAlarm(); }
};

// An alarm that is scheduled when the SentPacketManager requires a delay
// before sending packets and fires when the packet may be sent.
class SendAlarmDelegate : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  void OnAlarm() override { connection_->OnSendAlarm(); }
};

class MtuDiscoveryAlarmDelegate : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  void OnAlarm() override { connection_->OnMtuDiscoveryAlarm(); }
};

class ProcessUndecryptablePacketsAlarmDelegate
    : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  void OnAlarm() override { connection_->OnProcessUndecryptablePacketsAlarm(); }
};

class DiscardPreviousOneRttKeysAlarmDelegate
    : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  void OnAlarm() override { connection_->OnDiscardPreviousOneRttKeysAlarm(); }
};

class DiscardZeroRttDecryptionKeysAlarmDelegate
    : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  void OnAlarm() override {
    connection_->OnDiscardZeroRttDecryptionKeysAlarm();
  }
};

class MultiPortProbingAlarmDelegate : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  void OnAlarm() override {
    QUIC_DLOG(INFO) << "Alternative path probing alarm fired";
    connection_->MaybeProbeMultiPortPath();
  }
};

class IdleDetectorAlarmDelegate : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  IdleDetectorAlarmDelegate(const IdleDetectorAlarmDelegate&) = delete;
  IdleDetectorAlarmDelegate& operator=(const IdleDetectorAlarmDelegate&) =
      delete;

  void OnAlarm() override { connection_->OnIdleDetectorAlarm(); }
};

class NetworkBlackholeDetectorAlarmDelegate
    : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  NetworkBlackholeDetectorAlarmDelegate(
      const NetworkBlackholeDetectorAlarmDelegate&) = delete;
  NetworkBlackholeDetectorAlarmDelegate& operator=(
      const NetworkBlackholeDetectorAlarmDelegate&) = delete;

  void OnAlarm() override { connection_->OnNetworkBlackholeDetectorAlarm(); }
};

class PingAlarmDelegate : public QuicConnectionAlarmDelegate {
 public:
  using QuicConnectionAlarmDelegate::QuicConnectionAlarmDelegate;

  PingAlarmDelegate(const PingAlarmDelegate&) = delete;
  PingAlarmDelegate& operator=(const PingAlarmDelegate&) = delete;

  void OnAlarm() override { connection_->OnPingAlarm(); }
};

class MultiplexerAlarmDelegate : public QuicAlarm::Delegate {
 public:
  explicit MultiplexerAlarmDelegate(QuicAlarmMultiplexer* multiplexer)
      : multiplexer_(multiplexer) {}
  MultiplexerAlarmDelegate(const QuicConnectionAlarmDelegate&) = delete;
  MultiplexerAlarmDelegate& operator=(const MultiplexerAlarmDelegate&) = delete;

  QuicConnectionContext* GetConnectionContext() override {
    return multiplexer_->delegate()->context();
  }

  void OnAlarm() override { multiplexer_->FireAlarms(); }

 protected:
  QuicAlarmMultiplexer* multiplexer_;
};

}  // namespace

std::string QuicAlarmSlotName(QuicAlarmSlot slot) {
  switch (slot) {
    case QuicAlarmSlot::kAck:
      return "Ack";
    case QuicAlarmSlot::kRetransmission:
      return "Retransmission";
    case QuicAlarmSlot::kSend:
      return "Send";
    case QuicAlarmSlot::kMtuDiscovery:
      return "MtuDiscovery";
    case QuicAlarmSlot::kProcessUndecryptablePackets:
      return "ProcessUndecryptablePackets";
    case QuicAlarmSlot::kDiscardPreviousOneRttKeys:
      return "DiscardPreviousOneRttKeys";
    case QuicAlarmSlot::kDiscardZeroRttDecryptionKeys:
      return "DiscardZeroRttDecryptionKeys";
    case QuicAlarmSlot::kMultiPortProbing:
      return "MultiPortProbing";
    case QuicAlarmSlot::kIdleNetworkDetector:
      return "IdleNetworkDetector";
    case QuicAlarmSlot::kNetworkBlackholeDetector:
      return "NetworkBlackholeDetector";
    case QuicAlarmSlot::kPing:
      return "Ping";
    case QuicAlarmSlot::kSlotCount:
      break;
  }
  return "[unknown]";
}

QuicAlarmMultiplexer::QuicAlarmMultiplexer(
    absl::Nonnull<QuicConnectionAlarmsDelegate*> connection,
    QuicConnectionArena& arena, QuicAlarmFactory& alarm_factory)
    : deadlines_({QuicTime::Zero(), QuicTime::Zero(), QuicTime::Zero(),
                  QuicTime::Zero(), QuicTime::Zero(), QuicTime::Zero(),
                  QuicTime::Zero(), QuicTime::Zero(), QuicTime::Zero(),
                  QuicTime::Zero(), QuicTime::Zero()}),
      now_alarm_(alarm_factory.CreateAlarm(
          arena.New<MultiplexerAlarmDelegate>(this), &arena)),
      later_alarm_(alarm_factory.CreateAlarm(
          arena.New<MultiplexerAlarmDelegate>(this), &arena)),
      connection_(connection),
      underlying_alarm_granularity_(QuicTimeDelta::FromMicroseconds(
          GetQuicFlag(quic_multiplexer_alarm_granularity_us))) {}

void QuicAlarmMultiplexer::Set(QuicAlarmSlot slot, QuicTime new_deadline) {
  QUICHE_DCHECK(!IsSet(slot));
  QUICHE_DCHECK(new_deadline.IsInitialized());
  if (permanently_cancelled_) {
    QUICHE_BUG(quic_alarm_multiplexer_illegal_set)
        << "Set called after alarms are permanently cancelled. new_deadline:"
        << new_deadline;
    return;
  }
  SetDeadlineFor(slot, new_deadline);
  MaybeRescheduleUnderlyingAlarms();
}

void QuicAlarmMultiplexer::Update(QuicAlarmSlot slot, QuicTime new_deadline,
                                  QuicTimeDelta granularity) {
  if (permanently_cancelled_) {
    QUICHE_BUG(quic_alarm_multiplexer_illegal_update)
        << "Update called after alarm is permanently cancelled. new_deadline:"
        << new_deadline << ", granularity:" << granularity;
    return;
  }

  if (!new_deadline.IsInitialized()) {
    Cancel(slot);
    return;
  }
  if (std::abs((new_deadline - GetDeadline(slot)).ToMicroseconds()) <
      granularity.ToMicroseconds()) {
    return;
  }
  SetDeadlineFor(slot, new_deadline);
  MaybeRescheduleUnderlyingAlarms();
}

void QuicAlarmMultiplexer::DeferUnderlyingAlarmScheduling() {
  defer_updates_of_underlying_alarms_ = true;
}

void QuicAlarmMultiplexer::ResumeUnderlyingAlarmScheduling() {
  QUICHE_DCHECK(defer_updates_of_underlying_alarms_);
  defer_updates_of_underlying_alarms_ = false;
  RescheduleUnderlyingAlarms();
}

void QuicAlarmMultiplexer::FireAlarms() {
  if (permanently_cancelled_) {
    QUICHE_BUG(multiplexer_fire_alarms_permanently_cancelled)
        << "FireAlarms() called when all alarms have been permanently "
           "cancelled.";
    return;
  }

  QuicTime now = connection_->clock()->ApproximateNow();

  // Create a fixed list of alarms that are due.
  absl::InlinedVector<QuicAlarmSlot, kNumberOfSlots> scheduled;
  for (size_t slot_number = 0; slot_number < deadlines_.size(); ++slot_number) {
    if (deadlines_[slot_number].IsInitialized() &&
        deadlines_[slot_number] <= now) {
      scheduled.push_back(static_cast<QuicAlarmSlot>(slot_number));
    }
  }

  // Execute them in order of scheduled deadlines.
  absl::c_sort(scheduled, [this](QuicAlarmSlot a, QuicAlarmSlot b) {
    return GetDeadline(a) < GetDeadline(b);
  });
  for (QuicAlarmSlot slot : scheduled) {
    Fire(slot);
  }
  MaybeRescheduleUnderlyingAlarms();
}

void QuicAlarmMultiplexer::RescheduleUnderlyingAlarms() {
  if (permanently_cancelled_) {
    return;
  }

  QuicTime now = connection_->clock()->ApproximateNow();
  bool schedule_now = false;
  QuicTime later_alarm_deadline = QuicTime::Infinite();
  for (const QuicTime& deadline : deadlines_) {
    if (!deadline.IsInitialized()) {
      continue;
    }
    if (deadline <= now) {
      schedule_now = true;
    } else {
      later_alarm_deadline = std::min(later_alarm_deadline, deadline);
    }
  }

  if (schedule_now && !now_alarm_->IsSet()) {
    now_alarm_->Set(now);
  }
  if (!schedule_now && now_alarm_->IsSet()) {
    now_alarm_->Cancel();
  }

  if (later_alarm_deadline != QuicTime::Infinite()) {
    later_alarm_->Update(later_alarm_deadline, underlying_alarm_granularity_);
  } else {
    later_alarm_->Cancel();
  }

  QUICHE_DVLOG(1) << "Rescheduled alarms; now = "
                  << (schedule_now ? "true" : "false")
                  << "; later = " << later_alarm_deadline;
  QUICHE_DVLOG(1) << "Alarms: " << DebugString();
}

void QuicAlarmMultiplexer::Fire(QuicAlarmSlot slot) {
  if (!IsSet(slot)) {
    return;
  }
  SetDeadlineFor(slot, QuicTime::Zero());

  switch (slot) {
    case QuicAlarmSlot::kAck:
      connection_->OnAckAlarm();
      return;
    case QuicAlarmSlot::kRetransmission:
      connection_->OnRetransmissionAlarm();
      return;
    case QuicAlarmSlot::kSend:
      connection_->OnSendAlarm();
      return;
    case QuicAlarmSlot::kMtuDiscovery:
      connection_->OnMtuDiscoveryAlarm();
      return;
    case QuicAlarmSlot::kProcessUndecryptablePackets:
      connection_->OnProcessUndecryptablePacketsAlarm();
      return;
    case QuicAlarmSlot::kDiscardPreviousOneRttKeys:
      connection_->OnDiscardPreviousOneRttKeysAlarm();
      return;
    case QuicAlarmSlot::kDiscardZeroRttDecryptionKeys:
      connection_->OnDiscardZeroRttDecryptionKeysAlarm();
      return;
    case QuicAlarmSlot::kMultiPortProbing:
      connection_->MaybeProbeMultiPortPath();
      return;
    case QuicAlarmSlot::kIdleNetworkDetector:
      connection_->OnIdleDetectorAlarm();
      return;
    case QuicAlarmSlot::kNetworkBlackholeDetector:
      connection_->OnNetworkBlackholeDetectorAlarm();
      return;
    case QuicAlarmSlot::kPing:
      connection_->OnPingAlarm();
      return;
    case QuicAlarmSlot::kSlotCount:
      break;
  }
  QUICHE_NOTREACHED();
}

std::string QuicAlarmMultiplexer::DebugString() {
  std::vector<std::pair<QuicTime, QuicAlarmSlot>> scheduled;
  for (size_t i = 0; i < deadlines_.size(); ++i) {
    if (deadlines_[i].IsInitialized()) {
      scheduled.emplace_back(deadlines_[i], static_cast<QuicAlarmSlot>(i));
    }
  }
  absl::c_sort(scheduled);

  QuicTime now = connection_->clock()->Now();
  std::string result;
  for (const auto& [deadline, slot] : scheduled) {
    QuicTimeDelta relative = deadline - now;
    absl::StrAppendFormat(&result, "        %.1fms --- %s\n",
                          relative.ToMicroseconds() / 1000.f,
                          QuicAlarmSlotName(slot));
  }
  return result;
}

void QuicAlarmMultiplexer::CancelAllAlarms() {
  QUICHE_DVLOG(1) << "Cancelling all QuicConnection alarms.";
  permanently_cancelled_ = true;
  deadlines_.fill(QuicTime::Zero());
  now_alarm_->PermanentCancel();
  later_alarm_->PermanentCancel();
}

QuicConnectionAlarmHolder::QuicConnectionAlarmHolder(
    QuicConnectionAlarmsDelegate* delegate, QuicAlarmFactory& alarm_factory,
    QuicConnectionArena& arena)
    : ack_alarm_(alarm_factory.CreateAlarm(
          arena.New<AckAlarmDelegate>(delegate), &arena)),
      retransmission_alarm_(alarm_factory.CreateAlarm(
          arena.New<RetransmissionAlarmDelegate>(delegate), &arena)),
      send_alarm_(alarm_factory.CreateAlarm(
          arena.New<SendAlarmDelegate>(delegate), &arena)),
      mtu_discovery_alarm_(alarm_factory.CreateAlarm(
          arena.New<MtuDiscoveryAlarmDelegate>(delegate), &arena)),
      process_undecryptable_packets_alarm_(alarm_factory.CreateAlarm(
          arena.New<ProcessUndecryptablePacketsAlarmDelegate>(delegate),
          &arena)),
      discard_previous_one_rtt_keys_alarm_(alarm_factory.CreateAlarm(
          arena.New<DiscardPreviousOneRttKeysAlarmDelegate>(delegate), &arena)),
      discard_zero_rtt_decryption_keys_alarm_(alarm_factory.CreateAlarm(
          arena.New<DiscardZeroRttDecryptionKeysAlarmDelegate>(delegate),
          &arena)),
      multi_port_probing_alarm_(alarm_factory.CreateAlarm(
          arena.New<MultiPortProbingAlarmDelegate>(delegate), &arena)),
      idle_network_detector_alarm_(alarm_factory.CreateAlarm(
          arena.New<IdleDetectorAlarmDelegate>(delegate), &arena)),
      network_blackhole_detector_alarm_(alarm_factory.CreateAlarm(
          arena.New<NetworkBlackholeDetectorAlarmDelegate>(delegate), &arena)),
      ping_alarm_(alarm_factory.CreateAlarm(
          arena.New<PingAlarmDelegate>(delegate), &arena)) {}

QuicConnectionAlarms::QuicConnectionAlarms(
    QuicConnectionAlarmsDelegate* delegate, QuicAlarmFactory& alarm_factory,
    QuicConnectionArena& arena)
    : use_multiplexer_(GetQuicReloadableFlag(quic_use_alarm_multiplexer)) {
  if (use_multiplexer_) {
    multiplexer_.emplace(delegate, arena, alarm_factory);
  } else {
    holder_.emplace(delegate, alarm_factory, arena);
  }
}
}  // namespace quic

"""

```