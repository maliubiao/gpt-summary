Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

**1. Initial Understanding and Purpose:**

The first step is to recognize the file name: `web_transport_write_blocked_list.cc`. This immediately suggests its core function: managing a list of WebTransport streams that are blocked from writing data. The ".cc" extension tells us it's C++ source code. The "chromium/net" path hints at its integration within the Chromium networking stack, specifically within the QUIC implementation.

**2. Core Data Structures:**

Next, I scan the code for the main data structures used to manage the blocked streams. I see:

* `priorities_`: A `std::map` storing the priority of each stream, keyed by `QuicStreamId`. This is crucial for prioritization.
* `main_schedule_`: An instance of `PriorityFifo`, which appears to be the primary scheduler. It manages both HTTP and WebTransport session priorities.
* `web_transport_session_schedulers_`: A `std::map` of `PriorityFifo` instances, keyed by `ScheduleKey`. This handles scheduling *within* individual WebTransport sessions. This hierarchical scheduling is a key design point.
* `ScheduleKey`: A struct to represent keys in the schedulers, distinguishing between HTTP streams and WebTransport sessions.

**3. Key Functionalities (High-Level):**

Based on the data structures and function names, I can infer the primary functionalities:

* **Registration/Unregistration:**  `RegisterStream`, `UnregisterStream` handle adding and removing streams from the tracked lists.
* **Blocking/Unblocking (Scheduling):** `AddStream` adds a stream to the blocked list (scheduler), and `PopFront` retrieves the next stream to unblock.
* **Priority Management:**  `UpdateStreamPriority` allows changing the priority of a stream.
* **Querying State:**  `HasWriteBlockedDataStreams`, `NumBlockedSpecialStreams`, `NumBlockedStreams`, `IsStreamBlocked`, `GetPriorityOfStream`, `ShouldYield` provide information about the current state of the blocked list.

**4. Delving into Specific Functions and Logic:**

Now, I go through each function in more detail, focusing on:

* **Input and Output:** What are the parameters and what does the function return or modify?
* **Logic and Control Flow:** How does the function interact with the data structures? Are there conditional branches or loops?
* **Error Handling (Assertions and QUICHE_BUG):**  The code uses `QUICHE_DCHECK` for internal consistency checks and `QUICHE_BUG` to signal unexpected states, which are important for understanding potential errors.
* **Special Cases:** Are there specific conditions handled differently (e.g., static streams, WebTransport vs. HTTP streams)?

For example, in `RegisterStream`:

* It takes `stream_id`, `is_static_stream`, and `raw_priority`.
* It stores the priority in `priorities_`.
* It registers the stream in `main_schedule_`, using different `ScheduleKey` types for HTTP and WebTransport.
* For WebTransport, it manages a sub-scheduler in `web_transport_session_schedulers_`.
* It registers the *session* in the `main_schedule_` if it's a new session.

**5. Identifying Connections to JavaScript:**

This requires understanding how WebTransport is used in a browser context. WebTransport allows JavaScript to establish connections and exchange data with a server. The C++ code is part of the browser's networking stack that *implements* the WebTransport protocol. Therefore, the connection lies in how JavaScript initiates WebTransport streams, sends data, and the browser's underlying C++ handles the actual data transmission and flow control.

* **JavaScript initiates streams:** When JavaScript opens a WebTransport stream, this C++ code will be involved in managing that stream's write blocking.
* **JavaScript sends data:** When JavaScript attempts to send data, the browser's networking stack might block the write if congestion occurs or other flow control mechanisms are in place. This blocked list is part of that process.
* **Prioritization:** The JavaScript API for WebTransport allows setting priorities on streams. This priority information is used by this C++ code to schedule which blocked stream gets to write next.

**6. Constructing Examples and Scenarios:**

To illustrate the functionality, I create hypothetical scenarios:

* **Basic Blocking/Unblocking:** A stream is registered, data is sent, the stream gets blocked, and later unblocked.
* **Priority:** Two streams are blocked with different priorities, and the higher priority stream is unblocked first.
* **WebTransport Sessions:** Demonstrate how streams within a WebTransport session are grouped and prioritized.

**7. Identifying Potential User and Programming Errors:**

I look for patterns in the `QUICHE_BUG` calls and consider common mistakes developers might make when using WebTransport:

* **Registering the same stream twice:** The code explicitly checks for this.
* **Incorrect priority settings:**  While the C++ code enforces the logic, misconfiguring priorities in JavaScript could lead to unexpected behavior.
* **Not handling backpressure:**  If JavaScript keeps sending data without respecting the flow control, the streams will become blocked.

**8. Tracing User Operations (Debugging Clues):**

This involves thinking about the sequence of actions a user might take that would eventually lead to this code being executed. It starts from the user interaction in the browser (e.g., a website using WebTransport) and traces down to the network stack.

**9. Refining and Organizing the Explanation:**

Finally, I organize the information into logical sections (Functionality, Relation to JavaScript, Examples, Errors, Debugging) to provide a clear and comprehensive explanation. I use formatting (like bullet points and bold text) to improve readability. I also make sure to explain any technical terms (like "static streams" or "urgency").

Throughout this process, I'm constantly referring back to the code, reading comments, and trying to understand the intent behind each piece of logic. The goal is not just to describe *what* the code does, but also *why* it does it and how it fits into the larger WebTransport picture.
这个文件 `net/third_party/quiche/src/quiche/quic/core/web_transport_write_blocked_list.cc` 实现了 Chromium QUIC 协议栈中用于管理被阻塞的 WebTransport 写操作的流的列表。 它的主要功能是：

**1. 追踪被阻塞的 WebTransport 和 HTTP 数据流：**

* 当一个 WebTransport 或 HTTP 数据流因为发送窗口受限而无法写入数据时，它会被添加到这个阻塞列表中。
* 列表会记录每个被阻塞流的 ID 和优先级。

**2. 实现基于优先级的调度：**

*  该列表使用两层调度结构来管理阻塞的流：
    * **主调度器 (`main_schedule_`)**:  管理所有类型的阻塞流（HTTP 和 WebTransport 会话）。对于 WebTransport，它管理的是 WebTransport 会话的优先级。
    * **WebTransport 会话调度器 (`web_transport_session_schedulers_`)**:  每个 WebTransport 会话都有一个独立的调度器，用于管理该会话内部各个数据流的优先级。
* 当有发送窗口可用时，列表会按照优先级顺序选出一个流，允许其继续写入数据。
* HTTP 流直接在主调度器中管理。
* WebTransport 数据流的优先级由其所属的 WebTransport 会话的优先级以及流自身的发送顺序决定。

**3. 动态更新流的优先级：**

*  当流的优先级发生变化时，列表会更新其在调度器中的位置，以确保调度仍然基于最新的优先级。

**4. 提供查询接口：**

*  可以查询当前是否有被阻塞的 WebTransport 数据流。
*  可以查询当前有多少被阻塞的特殊流（例如，控制流）。
*  可以查询当前有多少被阻塞的流。
*  可以判断某个特定的流是否被阻塞。

**与 JavaScript 功能的关系以及举例说明：**

这个 C++ 文件直接位于 Chromium 的网络栈底层，JavaScript 代码无法直接访问或操作它。然而，它对 JavaScript 发起的 WebTransport 连接有着重要的影响。

当 JavaScript 使用 WebTransport API 创建连接和流，并尝试发送数据时，如果底层的 QUIC 连接因为拥塞控制、流量控制或其他原因导致发送窗口受限，那么这些 WebTransport 数据流可能会被添加到 `WebTransportWriteBlockedList` 中。

**举例说明：**

假设一个网页的 JavaScript 代码创建了一个 WebTransport 连接，并在该连接上创建了两个流，分别用于发送视频和音频数据。

```javascript
// JavaScript 代码
const transport = new WebTransport("https://example.com/webtransport");
await transport.ready;

const videoStream = await transport.createUnidirectionalStream();
const videoWriter = videoStream.writable.getWriter();

const audioStream = await transport.createUnidirectionalStream();
const audioWriter = audioStream.writable.getWriter();

// 假设在某个时刻，网络拥塞导致 QUIC 连接的发送窗口受限

// 当 JavaScript 尝试写入数据时，底层的 C++ 代码可能会将流添加到阻塞列表中
videoWriter.write(videoData); // 可能导致 videoStream 被阻塞
audioWriter.write(audioData); // 可能导致 audioStream 被阻塞

// 底层的 C++ 代码 (WebTransportWriteBlockedList) 会根据流的优先级来决定哪个流先被允许发送数据。
// 例如，音频流可能被设置为更高的优先级，因此它可能会在视频流之前被解除阻塞。
```

在这个例子中，`WebTransportWriteBlockedList` 的 C++ 代码会处理将 `videoStream` 和 `audioStream` 添加到阻塞列表，并根据它们的优先级来调度发送。JavaScript 代码无需知道这个阻塞列表的存在，它只需要调用 WebTransport API 进行写入操作，底层的网络栈会处理阻塞和调度。

**逻辑推理和假设输入与输出：**

**假设输入：**

1. 一个新的 WebTransport 连接创建，ID 为 `session_id_123`。
2. 在这个连接上创建了两个单向流，ID 分别为 `stream_id_456` (低优先级) 和 `stream_id_789` (高优先级)。
3. 两个流都有待发送的数据，但 QUIC 连接的发送窗口暂时不足以发送所有数据。
4. `RegisterStream(stream_id_456, false, QuicStreamPriority{/* 低优先级 */});` 被调用。
5. `RegisterStream(stream_id_789, false, QuicStreamPriority{/* 高优先级 */});` 被调用。
6. `AddStream(stream_id_456)` 被调用，因为该流尝试发送数据但被阻塞。
7. `AddStream(stream_id_789)` 被调用，因为该流尝试发送数据但也被阻塞。

**预期输出：**

1. `priorities_` 包含 `stream_id_456` 和其对应的低优先级，以及 `stream_id_789` 和其对应的高优先级。
2. `web_transport_session_schedulers_` 中存在一个以 `session_id_123` 相关的 `ScheduleKey` 为键的 `PriorityFifo` 实例。
3. 该 `PriorityFifo` 实例中同时包含了 `stream_id_456` 和 `stream_id_789`。
4. `main_schedule_` 中存在一个以 `session_id_123` 相关的 `ScheduleKey` 为键的条目，代表该 WebTransport 会话。
5. 当调用 `PopFront()` 时，由于 `stream_id_789` 优先级更高，它应该先被返回。

**用户或编程常见的使用错误：**

由于这个文件是网络栈的内部实现，普通用户不会直接与之交互。编程错误通常发生在网络栈的开发过程中。一些可能的错误包括：

1. **多次注册同一个流：** 代码中使用了 `QUICHE_BUG` 来检测这种情况。如果开发者错误地多次调用 `RegisterStream` 并传入相同的 `stream_id`，会导致断言失败。
    ```c++
    // 错误示例：
    write_blocked_list.RegisterStream(10, false, {});
    write_blocked_list.RegisterStream(10, false, {}); // 触发 QUICHE_BUG
    ```

2. **在未注册的情况下取消注册流：** 如果尝试调用 `UnregisterStream` 来移除一个没有被注册的流，代码会触发 `QUICHE_BUG`。
    ```c++
    // 错误示例：
    write_blocked_list.UnregisterStream(20); // 如果流 20 没有被注册，会触发 QUICHE_BUG
    ```

3. **更新不存在的流的优先级：**  `UpdateStreamPriority` 依赖于流已经被注册。如果尝试更新一个未注册的流的优先级，`GetPriorityOfStream` 会触发 `QUICHE_BUG`。

4. **调度逻辑错误：**  在实现调度逻辑时，可能会出现错误导致优先级高的流没有被优先调度，或者重复调度同一个流。代码中的 `QUICHE_BUG_IF` 语句可以帮助检测这些逻辑错误。

**用户操作如何一步步到达这里作为调试线索：**

当调试 WebTransport 相关的问题时，了解用户操作如何触发代码执行至 `WebTransportWriteBlockedList` 可以帮助定位问题。以下是一个典型的用户操作流程和对应的调试线索：

1. **用户在浏览器中访问一个使用 WebTransport 的网站。**
    *   调试线索：检查浏览器开发者工具的网络标签，查看是否建立了 WebTransport 连接。检查控制台是否有与 WebTransport 相关的错误信息。

2. **网站的 JavaScript 代码创建了一个 WebTransport 连接。**
    *   调试线索：在浏览器进程中设置断点，查看 `WebTransport::Connect` 的调用。

3. **JavaScript 代码在该连接上创建了一个或多个流，并尝试发送数据。**
    *   调试线索：在浏览器进程中设置断点，查看 `WebTransportSession::CreateUnidirectionalStream` 或 `WebTransportSession::CreateBidirectionalStream` 的调用。 检查 JavaScript 代码中 `stream.writable.getWriter().write()` 的调用。

4. **底层的 QUIC 连接因为发送窗口受限，导致数据流被阻塞。**
    *   调试线索：在 QUIC 层设置断点，查看发送窗口的状态。查看 `QuicStreamSequencer` 是否因为接收到 `BLOCKED` 帧而暂停发送。

5. **当流被阻塞时，`WebTransportWriteBlockedList::AddStream` 被调用。**
    *   调试线索：在 `WebTransportWriteBlockedList::AddStream` 设置断点，查看哪个流被添加到阻塞列表。查看调用堆栈，追溯到是哪个 QUIC 或 WebTransport 组件触发了阻塞。

6. **当 QUIC 连接的发送窗口恢复时，`WebTransportWriteBlockedList::PopFront` 被调用，选择下一个要发送数据的流。**
    *   调试线索：在 `WebTransportWriteBlockedList::PopFront` 设置断点，查看哪个流被选中。检查主调度器和会话调度器的状态，确认优先级调度是否正确。

通过以上步骤，可以逐步跟踪用户操作在网络栈中的执行流程，并利用断点和日志来分析 `WebTransportWriteBlockedList` 的状态和行为，从而定位 WebTransport 相关的性能问题或错误。  特别关注 `QUICHE_BUG` 的触发，这通常指示了代码中的意外状态或逻辑错误。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/web_transport_write_blocked_list.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/web_transport_write_blocked_list.h"

#include <cstddef>
#include <optional>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "quiche/quic/core/quic_stream_priority.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

bool WebTransportWriteBlockedList::HasWriteBlockedDataStreams() const {
  return main_schedule_.NumScheduledInPriorityRange(
             std::nullopt, RemapUrgency(HttpStreamPriority::kMaximumUrgency,
                                        /*is_http=*/true)) > 0;
}

size_t WebTransportWriteBlockedList::NumBlockedSpecialStreams() const {
  return main_schedule_.NumScheduledInPriorityRange(
      RemapUrgency(kStaticUrgency, /*is_http=*/false), std::nullopt);
}

size_t WebTransportWriteBlockedList::NumBlockedStreams() const {
  size_t num_streams = main_schedule_.NumScheduled();
  for (const auto& [key, scheduler] : web_transport_session_schedulers_) {
    if (scheduler.HasScheduled()) {
      num_streams += scheduler.NumScheduled();
      // Account for the fact that the group itself has an entry in the main
      // scheduler that does not correspond to any actual stream.
      QUICHE_DCHECK(main_schedule_.IsScheduled(key));
      --num_streams;
    }
  }
  return num_streams;
}

void WebTransportWriteBlockedList::RegisterStream(
    QuicStreamId stream_id, bool is_static_stream,
    const QuicStreamPriority& raw_priority) {
  QuicStreamPriority priority =
      is_static_stream
          ? QuicStreamPriority(HttpStreamPriority{kStaticUrgency, true})
          : raw_priority;
  auto [unused, success] = priorities_.emplace(stream_id, priority);
  if (!success) {
    QUICHE_BUG(WTWriteBlocked_RegisterStream_already_registered)
        << "Tried to register stream " << stream_id
        << " that is already registered";
    return;
  }

  if (priority.type() == QuicPriorityType::kHttp) {
    absl::Status status = main_schedule_.Register(
        ScheduleKey::HttpStream(stream_id),
        RemapUrgency(priority.http().urgency, /*is_http=*/true));
    QUICHE_BUG_IF(WTWriteBlocked_RegisterStream_http_scheduler, !status.ok())
        << status;
    return;
  }

  QUICHE_DCHECK_EQ(priority.type(), QuicPriorityType::kWebTransport);
  ScheduleKey group_key = ScheduleKey::WebTransportSession(priority);
  auto [it, created_new] =
      web_transport_session_schedulers_.try_emplace(group_key);
  absl::Status status =
      it->second.Register(stream_id, priority.web_transport().send_order);
  QUICHE_BUG_IF(WTWriteBlocked_RegisterStream_data_scheduler, !status.ok())
      << status;

  // If the group is new, register it with the main scheduler.
  if (created_new) {
    // The IETF draft requires the priority of data streams associated with an
    // individual session to be equivalent to the priority of the control
    // stream.
    auto session_priority_it =
        priorities_.find(priority.web_transport().session_id);
    // It is possible for a stream to be (re-)registered while the control
    // stream is already gone.
    QUICHE_DLOG_IF(WARNING, session_priority_it == priorities_.end())
        << "Stream " << stream_id << " is associated with session ID "
        << priority.web_transport().session_id
        << ", but the session control stream is not registered; assuming "
           "default urgency.";
    QuicStreamPriority session_priority =
        session_priority_it != priorities_.end() ? session_priority_it->second
                                                 : QuicStreamPriority();

    status = main_schedule_.Register(
        group_key,
        RemapUrgency(session_priority.http().urgency, /*is_http=*/false));
    QUICHE_BUG_IF(WTWriteBlocked_RegisterStream_main_scheduler, !status.ok())
        << status;
  }
}

void WebTransportWriteBlockedList::UnregisterStream(QuicStreamId stream_id) {
  auto map_it = priorities_.find(stream_id);
  if (map_it == priorities_.end()) {
    QUICHE_BUG(WTWriteBlocked_UnregisterStream_not_found)
        << "Stream " << stream_id << " not found";
    return;
  }
  QuicStreamPriority priority = map_it->second;
  priorities_.erase(map_it);

  if (priority.type() != QuicPriorityType::kWebTransport) {
    absl::Status status =
        main_schedule_.Unregister(ScheduleKey::HttpStream(stream_id));
    QUICHE_BUG_IF(WTWriteBlocked_UnregisterStream_http, !status.ok()) << status;
    return;
  }

  ScheduleKey key = ScheduleKey::WebTransportSession(priority);
  auto subscheduler_it = web_transport_session_schedulers_.find(key);
  if (subscheduler_it == web_transport_session_schedulers_.end()) {
    QUICHE_BUG(WTWriteBlocked_UnregisterStream_no_subscheduler)
        << "Stream " << stream_id
        << " is a WebTransport data stream, but has no scheduler for the "
           "associated group";
    return;
  }
  Subscheduler& subscheduler = subscheduler_it->second;
  absl::Status status = subscheduler.Unregister(stream_id);
  QUICHE_BUG_IF(WTWriteBlocked_UnregisterStream_subscheduler_stream_failed,
                !status.ok())
      << status;

  // If this is the last stream associated with the group, remove the group.
  if (!subscheduler.HasRegistered()) {
    status = main_schedule_.Unregister(key);
    QUICHE_BUG_IF(WTWriteBlocked_UnregisterStream_subscheduler_failed,
                  !status.ok())
        << status;

    web_transport_session_schedulers_.erase(subscheduler_it);
  }
}

void WebTransportWriteBlockedList::UpdateStreamPriority(
    QuicStreamId stream_id, const QuicStreamPriority& new_priority) {
  QuicStreamPriority old_priority = GetPriorityOfStream(stream_id);
  if (old_priority == new_priority) {
    return;
  }

  bool was_blocked = IsStreamBlocked(stream_id);
  UnregisterStream(stream_id);
  RegisterStream(stream_id, /*is_static_stream=*/false, new_priority);
  if (was_blocked) {
    AddStream(stream_id);
  }

  if (new_priority.type() == QuicPriorityType::kHttp) {
    for (auto& [key, subscheduler] : web_transport_session_schedulers_) {
      QUICHE_DCHECK(key.has_group());
      if (key.stream() == stream_id) {
        absl::Status status =
            main_schedule_.UpdatePriority(key, new_priority.http().urgency);
        QUICHE_BUG_IF(WTWriteBlocked_UpdateStreamPriority_subscheduler_failed,
                      !status.ok())
            << status;
      }
    }
  }
}

QuicStreamId WebTransportWriteBlockedList::PopFront() {
  absl::StatusOr<ScheduleKey> main_key = main_schedule_.PopFront();
  if (!main_key.ok()) {
    QUICHE_BUG(WTWriteBlocked_PopFront_no_streams)
        << "PopFront() called when no streams scheduled: " << main_key.status();
    return 0;
  }
  if (!main_key->has_group()) {
    return main_key->stream();
  }

  auto it = web_transport_session_schedulers_.find(*main_key);
  if (it == web_transport_session_schedulers_.end()) {
    QUICHE_BUG(WTWriteBlocked_PopFront_no_subscheduler)
        << "Subscheduler for WebTransport group " << main_key->DebugString()
        << " not found";
    return 0;
  }
  Subscheduler& subscheduler = it->second;
  absl::StatusOr<QuicStreamId> result = subscheduler.PopFront();
  if (!result.ok()) {
    QUICHE_BUG(WTWriteBlocked_PopFront_subscheduler_empty)
        << "Subscheduler for group " << main_key->DebugString()
        << " is empty while in the main schedule";
    return 0;
  }
  if (subscheduler.HasScheduled()) {
    absl::Status status = main_schedule_.Schedule(*main_key);
    QUICHE_BUG_IF(WTWriteBlocked_PopFront_reschedule_group, !status.ok())
        << status;
  }
  return *result;
}

void WebTransportWriteBlockedList::AddStream(QuicStreamId stream_id) {
  QuicStreamPriority priority = GetPriorityOfStream(stream_id);
  absl::Status status;
  switch (priority.type()) {
    case QuicPriorityType::kHttp:
      status = main_schedule_.Schedule(ScheduleKey::HttpStream(stream_id));
      QUICHE_BUG_IF(WTWriteBlocked_AddStream_http, !status.ok()) << status;
      break;
    case QuicPriorityType::kWebTransport:
      status =
          main_schedule_.Schedule(ScheduleKey::WebTransportSession(priority));
      QUICHE_BUG_IF(WTWriteBlocked_AddStream_wt_main, !status.ok()) << status;

      auto it = web_transport_session_schedulers_.find(
          ScheduleKey::WebTransportSession(priority));
      if (it == web_transport_session_schedulers_.end()) {
        QUICHE_BUG(WTWriteBlocked_AddStream_no_subscheduler)
            << ScheduleKey::WebTransportSession(priority);
        return;
      }
      Subscheduler& subscheduler = it->second;
      status = subscheduler.Schedule(stream_id);
      QUICHE_BUG_IF(WTWriteBlocked_AddStream_wt_sub, !status.ok()) << status;
      break;
  }
}

bool WebTransportWriteBlockedList::IsStreamBlocked(
    QuicStreamId stream_id) const {
  QuicStreamPriority priority = GetPriorityOfStream(stream_id);
  switch (priority.type()) {
    case QuicPriorityType::kHttp:
      return main_schedule_.IsScheduled(ScheduleKey::HttpStream(stream_id));
    case QuicPriorityType::kWebTransport:
      auto it = web_transport_session_schedulers_.find(
          ScheduleKey::WebTransportSession(priority));
      if (it == web_transport_session_schedulers_.end()) {
        QUICHE_BUG(WTWriteBlocked_IsStreamBlocked_no_subscheduler)
            << ScheduleKey::WebTransportSession(priority);
        return false;
      }
      const Subscheduler& subscheduler = it->second;
      return subscheduler.IsScheduled(stream_id);
  }
  QUICHE_NOTREACHED();
  return false;
}

QuicStreamPriority WebTransportWriteBlockedList::GetPriorityOfStream(
    QuicStreamId id) const {
  auto it = priorities_.find(id);
  if (it == priorities_.end()) {
    QUICHE_BUG(WTWriteBlocked_GetPriorityOfStream_not_found)
        << "Stream " << id << " not found";
    return QuicStreamPriority();
  }
  return it->second;
}

std::string WebTransportWriteBlockedList::ScheduleKey::DebugString() const {
  return absl::StrFormat("(%d, %d)", stream_, group_);
}

bool WebTransportWriteBlockedList::ShouldYield(QuicStreamId id) const {
  QuicStreamPriority priority = GetPriorityOfStream(id);
  if (priority.type() == QuicPriorityType::kHttp) {
    absl::StatusOr<bool> should_yield =
        main_schedule_.ShouldYield(ScheduleKey::HttpStream(id));
    QUICHE_BUG_IF(WTWriteBlocked_ShouldYield_http, !should_yield.ok())
        << should_yield.status();
    return *should_yield;
  }
  QUICHE_DCHECK_EQ(priority.type(), QuicPriorityType::kWebTransport);
  absl::StatusOr<bool> should_yield =
      main_schedule_.ShouldYield(ScheduleKey::WebTransportSession(priority));
  QUICHE_BUG_IF(WTWriteBlocked_ShouldYield_wt_main, !should_yield.ok())
      << should_yield.status();
  if (*should_yield) {
    return true;
  }

  auto it = web_transport_session_schedulers_.find(
      ScheduleKey::WebTransportSession(priority));
  if (it == web_transport_session_schedulers_.end()) {
    QUICHE_BUG(WTWriteBlocked_ShouldYield_subscheduler_not_found)
        << "Subscheduler not found for "
        << ScheduleKey::WebTransportSession(priority);
    return false;
  }
  const Subscheduler& subscheduler = it->second;

  should_yield = subscheduler.ShouldYield(id);
  QUICHE_BUG_IF(WTWriteBlocked_ShouldYield_wt_subscheduler, !should_yield.ok())
      << should_yield.status();
  return *should_yield;
}
}  // namespace quic

"""

```