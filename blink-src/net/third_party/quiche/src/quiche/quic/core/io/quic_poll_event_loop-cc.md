Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Core Functionality:**

The first step is to grasp the main purpose of the `QuicPollEventLoop`. Keywords like "event loop," "poll," "socket," and "alarm" immediately suggest it's about handling asynchronous I/O and timers. Reading the initial comments and the class declaration confirms this. It uses the `poll` system call (or `WSAPoll` on Windows) to monitor file descriptors (sockets) for events.

**2. Deconstructing Key Methods:**

Next, analyze the significant methods and their roles:

* **`RegisterSocket`**: How are sockets added for monitoring?  It stores the file descriptor, event types, and a listener.
* **`UnregisterSocket`**:  How are sockets removed?  It simply erases the entry.
* **`RearmSocket`**: How are the watched events for a socket modified?  It adds *more* events (ORing the masks).
* **`ArtificiallyNotifyEvent`**: This is interesting. It allows forcing an event notification. This suggests a mechanism for testing or internal signaling.
* **`RunEventLoopOnce`**: This is the heart of the loop. It processes alarms and then waits for I/O events.
* **`ComputePollTimeout`**: How does it calculate the timeout for `poll`? It considers both a default timeout and the next alarm. The handling of artificial events is crucial here.
* **`PollWithRetries`**: This handles the `poll` system call, including retries on `EINTR`. This is important for robustness.
* **`ProcessIoEvents`**:  How does it interact with `poll` and dispatch events? It sets up the `pollfd` array, calls `poll`, and then iterates through the results.
* **`DispatchIoEvent`**:  How does it determine which events to notify the listener about? It combines `poll` results with artificially triggered events. The masking logic is key.
* **`RunReadyCallbacks`**: How are the listeners actually notified?  It iterates through the ready list and calls `OnSocketEvent`.
* **`ProcessAlarmsUpTo`**: How are timers handled? It iterates through the sorted alarms and fires those whose deadlines have passed.
* **`AlarmFactory` and `Alarm`**: How are alarms created and managed? They're associated with the event loop.

**3. Identifying Relationships and Data Structures:**

Pay attention to the data structures used:

* `registrations_`: A `std::map` storing socket information (fd, events, listener). The use of `std::shared_ptr` for `Registration` is noteworthy (likely for lifetime management).
* `alarms_`: A `std::multimap` storing alarms, ordered by deadline. The use of `std::weak_ptr` for the alarm handle is important to avoid circular dependencies and allow alarm objects to be destroyed.

**4. Considering JavaScript Relevance:**

Think about how this low-level I/O handling relates to JavaScript in a browser environment. The key connection is the *event loop*. JavaScript is single-threaded and relies on an event loop to handle asynchronous operations (like network requests, timers, user input). While JavaScript itself doesn't directly use `poll`, the underlying browser infrastructure (including the network stack) does. This leads to examples like `setTimeout`, `fetch`, and WebSockets.

**5. Formulating Examples and Scenarios:**

Based on the understanding of the code, create concrete examples:

* **Logical Reasoning:**  Think of a scenario where a socket is registered for read and write, and an alarm is set. How does the `ComputePollTimeout` function behave with different inputs?
* **User/Programming Errors:** Consider common mistakes when working with asynchronous I/O, like forgetting to register a socket or misinterpreting event masks.
* **Debugging Scenario:** Trace a typical user action (e.g., opening a webpage) and how it might lead to the execution of this code.

**6. Structuring the Answer:**

Organize the information logically:

* Start with a high-level summary of the file's purpose.
* Detail the core functionalities by explaining each key method.
* Explain the connection to JavaScript with illustrative examples.
* Provide concrete examples for logical reasoning, potential errors, and debugging.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus only on the `poll` call.
* **Correction:** Realize that the alarm handling is equally important to the event loop's function.
* **Initial thought:**  Directly equate JavaScript events to `poll` events.
* **Correction:** Explain the abstraction layer – JavaScript doesn't use `poll` directly, but relies on the browser's event loop implemented using mechanisms like `poll`.
* **Initial thought:** Briefly mention potential errors.
* **Correction:** Provide specific and actionable examples of common mistakes.

By following this methodical process of understanding, deconstructing, connecting, and illustrating, a comprehensive and accurate answer can be constructed. The emphasis should be on explaining *what* the code does, *how* it does it, and *why* it matters (especially in the context of the user's question about JavaScript).
这个文件 `net/third_party/quiche/src/quiche/quic/core/io/quic_poll_event_loop.cc` 是 Chromium QUIC 库中实现基于 `poll` 系统调用的事件循环的关键组件。它负责监听和处理网络 socket 上的 I/O 事件以及定时器事件（alarms）。

以下是它的功能列表：

**核心功能：**

1. **事件循环管理:**  它实现了一个事件循环，定期检查注册的 socket 是否有可读、可写或错误事件发生。
2. **Socket 监听:** 它允许注册和取消注册文件描述符 (socket fd)，并指定需要监听的事件类型（可读、可写、错误）。
3. **I/O 事件通知:** 当注册的 socket 上发生指定事件时，它会通知相应的监听器 (`QuicSocketEventListener`).
4. **定时器管理:** 它集成了定时器功能，允许设置在特定时间触发的回调（通过 `QuicAlarm`）。
5. **基于 `poll` 系统调用:**  它使用 `poll` (或 Windows 上的 `WSAPoll`) 系统调用来高效地等待多个文件描述符上的事件。
6. **非阻塞 I/O:**  它设计用于非阻塞 I/O，避免在等待事件时阻塞整个线程。
7. **人工事件触发:** 允许人为地触发 socket 事件通知，这主要用于测试目的。

**详细功能分解：**

* **`RegisterSocket(SocketFd fd, QuicSocketEventMask events, QuicSocketEventListener* listener)`:**
    * 功能：将一个 socket 文件描述符 `fd` 注册到事件循环中，以便监听指定的事件 `events` (例如 `kSocketEventReadable`, `kSocketEventWritable`)。
    * `listener`：是一个接口，当 socket 上发生感兴趣的事件时，会调用 `listener->OnSocketEvent` 方法。
* **`UnregisterSocket(SocketFd fd)`:**
    * 功能：从事件循环中移除对指定 socket 文件描述符 `fd` 的监听。
* **`RearmSocket(SocketFd fd, QuicSocketEventMask events)`:**
    * 功能：修改已注册 socket 文件描述符 `fd` 的监听事件，可以添加新的监听事件。
* **`ArtificiallyNotifyEvent(SocketFd fd, QuicSocketEventMask events)`:**
    * 功能：人为地触发指定 socket 文件描述符 `fd` 上的事件 `events`，即使实际的系统调用 `poll` 没有报告这些事件。这通常用于测试或模拟场景。
* **`RunEventLoopOnce(QuicTime::Delta default_timeout)`:**
    * 功能：执行事件循环的单次迭代。
    * 它首先处理到期的定时器（alarms）。
    * 然后调用 `poll` 等待注册的 socket 事件发生，或直到 `default_timeout` 超时。
    * 最后，处理发生的 I/O 事件，并再次处理到期的定时器。
* **`ComputePollTimeout(QuicTime now, QuicTime::Delta default_timeout)`:**
    * 功能：计算 `poll` 系统调用的超时时间。
    * 它会考虑是否有即将到期的定时器，并确保 `poll` 不会阻塞超过下一个定时器到期的时间。
    * 如果有通过 `ArtificiallyNotifyEvent` 设置的人工事件等待触发，则超时时间为 0，立即返回。
* **`PollWithRetries(absl::Span<pollfd> fds, QuicTime start_time, QuicTime::Delta timeout)`:**
    * 功能：执行 `poll` 系统调用，并在遇到 `EINTR` 错误时进行重试，直到超时或发生其他错误。
* **`ProcessIoEvents(QuicTime start_time, QuicTime::Delta timeout)`:**
    * 功能：准备 `pollfd` 结构体数组，调用 `PollWithRetries` 执行 `poll`，并处理返回的事件。
    * 它会遍历 `poll` 返回的结果，并调用对应 socket 的 `QuicSocketEventListener` 的 `OnSocketEvent` 方法。
* **`DispatchIoEvent(std::vector<ReadyListEntry>& ready_list, SocketFd fd, PollMask mask)`:**
    * 功能：根据 `poll` 返回的事件 `mask`，查找对应的 socket 注册信息，并将准备好的事件添加到待处理的列表中。
    * 它还会考虑通过 `ArtificiallyNotifyEvent` 设置的人工事件。
* **`RunReadyCallbacks(std::vector<ReadyListEntry>& ready_list)`:**
    * 功能：遍历待处理的事件列表，并调用每个事件对应的 `QuicSocketEventListener` 的 `OnSocketEvent` 方法。
* **`ProcessAlarmsUpTo(QuicTime time)`:**
    * 功能：处理所有截止时间早于或等于 `time` 的定时器。
    * 它会调用每个到期定时器的 `DoFire` 方法。
* **`CreateAlarmFactory()`:**
    * 功能：创建一个 `QuicAlarmFactory`，用于创建与此事件循环关联的定时器。
* **`Alarm` 类：**
    * 是一个内部类，实现了 `QuicAlarm` 接口，与 `QuicPollEventLoop` 紧密集成。
    * `SetImpl()`：在事件循环中注册定时器。
    * `CancelImpl()`：取消定时器。

**与 JavaScript 的功能关系：**

虽然这段 C++ 代码本身不是 JavaScript，但它在 Chromium 的网络栈中扮演着关键角色，而 Chromium 是 Chrome 浏览器以及 Node.js 等 JavaScript 运行时的基础。

JavaScript 中的异步操作，如网络请求 (`fetch`, `XMLHttpRequest`)、定时器 (`setTimeout`, `setInterval`)、WebSockets 等，底层都依赖于操作系统提供的事件循环机制。  `QuicPollEventLoop` 这样的组件就是 Chromium 实现其网络部分的事件循环的关键。

**举例说明：**

当 JavaScript 代码执行 `fetch('https://example.com')` 时，浏览器底层会发生以下（简化）过程：

1. **JavaScript 引擎** 将这个异步请求传递给浏览器的 **网络模块**。
2. **网络模块** 创建一个 socket 连接到 `example.com` 的服务器。
3. **网络模块** (在 QUIC 的情况下) 可能会使用 `QuicPollEventLoop::RegisterSocket` 来注册这个 socket 的可读事件。
4. **`QuicPollEventLoop::RunEventLoopOnce`** 会周期性地调用 `poll` 来检查这个 socket 是否有数据到达。
5. 当服务器响应数据到达时，`poll` 会返回，并且 `QuicPollEventLoop` 会调用与该 socket 关联的监听器的 `OnSocketEvent` 方法，通知数据已准备好读取。
6. **网络模块** 读取数据，并最终通过回调或 Promise 将结果返回给 **JavaScript 引擎**。

类似地，当 JavaScript 执行 `setTimeout(callback, 1000)` 时：

1. **JavaScript 引擎** 将定时器请求传递给浏览器。
2. 浏览器的定时器管理模块会使用 `QuicPollEventLoop::AlarmFactory::CreateAlarm` 创建一个 `QuicAlarm` 实例。
3. `QuicAlarm::Set` 最终会调用 `QuicPollEventLoop::alarms_` 的插入操作，将定时器注册到事件循环中。
4. 在 `QuicPollEventLoop::RunEventLoopOnce` 的每次迭代中，`ProcessAlarmsUpTo` 会检查是否有到期的定时器。
5. 当定时器到期时，`ProcessAlarmsUpTo` 会执行 `callback`。

**逻辑推理的假设输入与输出：**

**假设输入：**

1. 调用 `RegisterSocket(3, kSocketEventReadable, listener1)` 注册 socket fd 3 监听可读事件。
2. 调用 `RegisterSocket(5, kSocketEventWritable, listener2)` 注册 socket fd 5 监听可写事件。
3. 调用 `ArtificiallyNotifyEvent(3, kSocketEventReadable)` 人为触发 socket fd 3 的可读事件。
4. 调用 `RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100))`。

**输出：**

1. 在 `RunEventLoopOnce` 中，由于 `has_artificial_events_pending_` 为 true，`ComputePollTimeout` 会返回 `QuicTime::Delta::Zero()`。
2. `ProcessIoEvents` 会执行 `poll`，但由于超时为 0，可能会立即返回 (取决于具体实现和系统调度)。
3. `DispatchIoEvent` 会因为人为触发的事件，将 socket fd 3 和 `kSocketEventReadable` 添加到 `ready_list`。
4. `RunReadyCallbacks` 会调用 `listener1->OnSocketEvent(this, 3, kSocketEventReadable)`。
5. 如果实际 socket fd 5 也是可写的，`poll` 可能会返回 socket fd 5 的可写事件，并调用 `listener2->OnSocketEvent(this, 5, kSocketEventWritable)`。

**用户或编程常见的使用错误：**

1. **忘记注册 socket:**  在进行 I/O 操作前，没有先调用 `RegisterSocket` 将 socket 注册到事件循环中，导致事件无法被监控和处理。
    * **例子:**  创建一个 socket 连接后，直接尝试读取数据，而没有先注册 socket 的可读事件。
2. **注册错误的事件类型:**  注册了错误的事件类型，导致程序无法响应实际发生的事件。
    * **例子:**  只注册了 `kSocketEventWritable`，但服务器发送了数据，导致程序无法读取数据。
3. **未正确处理 `OnSocketEvent` 中的逻辑:**  在 `OnSocketEvent` 回调函数中没有正确处理事件，例如没有读取可读 socket 中的数据，或者没有写入可写 socket。
    * **例子:**  在 `OnSocketEvent` 中，当收到可读事件时，没有调用 `recv` 读取数据，导致下次事件循环仍然会收到可读事件，形成忙循环。
4. **忘记取消注册 socket:**  在不再需要监听 socket 事件时，忘记调用 `UnregisterSocket`，可能导致资源泄漏或不必要的事件处理。
    * **例子:**  连接关闭后，没有取消注册 socket，事件循环仍然会尝试处理已关闭的 socket。
5. **在 `OnSocketEvent` 中进行耗时操作:**  在 `OnSocketEvent` 回调函数中执行耗时的同步操作会阻塞事件循环，影响其他事件的处理。
    * **例子:**  在 `OnSocketEvent` 中进行复杂的计算或同步 I/O 操作。

**用户操作如何一步步到达这里，作为调试线索：**

假设用户在 Chrome 浏览器中访问一个使用了 QUIC 协议的网站：

1. **用户在地址栏输入网址并按下回车键。**
2. **浏览器解析 URL 并确定需要建立网络连接。**
3. **Chrome 的网络栈尝试使用 QUIC 协议与服务器建立连接。**
4. **网络栈创建一个 socket 并尝试连接到服务器。**
5. **`QuicPollEventLoop::RegisterSocket`** 被调用，将该 socket 的可读和可写事件注册到事件循环中。
6. **`QuicPollEventLoop::RunEventLoopOnce`** 进入循环，等待 socket 事件或定时器触发。
7. **如果连接成功，或者收到服务器的数据包，底层的 socket 会变得可读或可写。**
8. **`poll` 系统调用返回，指示 socket 上有事件发生。**
9. **`QuicPollEventLoop::ProcessIoEvents`** 处理 `poll` 返回的结果。
10. **`QuicSocketEventListener::OnSocketEvent`** 被调用，通知 QUIC 代码有新的数据到达或连接状态发生变化。
11. **QUIC 代码根据事件类型进行相应的处理，例如解析数据包、发送 ACK 等。**
12. **如果需要发送数据，QUIC 代码可能会再次调用底层的 socket 发送数据，并且依赖事件循环监听 socket 的可写事件。**

**调试线索:**

* 如果网络连接建立失败或数据传输出现问题，可以断点或日志输出在 `RegisterSocket`、`ProcessIoEvents`、`OnSocketEvent` 等关键函数中，查看 socket 的注册情况、`poll` 的返回值、以及事件处理逻辑是否正确。
* 可以检查 `registrations_` 成员变量，查看当前注册的 socket 及其监听的事件。
* 可以使用网络抓包工具 (如 Wireshark) 配合调试，查看实际的网络数据包，与代码中的事件处理逻辑进行对比。
* 如果怀疑是定时器问题，可以在 `ProcessAlarmsUpTo` 中设置断点，查看定时器的触发情况。
* 如果性能出现问题，可以分析 `RunEventLoopOnce` 的执行时间，以及 `poll` 的等待时间，找出瓶颈。

总而言之，`QuicPollEventLoop.cc` 文件是 Chromium QUIC 库中处理底层 I/O 事件和定时器的核心组件，它通过 `poll` 系统调用高效地管理网络连接的生命周期，并为上层 QUIC 协议的实现提供基础。理解它的工作原理对于调试 QUIC 相关的网络问题至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/io/quic_poll_event_loop.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/io/quic_poll_event_loop.h"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <memory>
#include <utility>
#include <vector>

#include "absl/types/span.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"

namespace quic {

namespace {

using PollMask = decltype(::pollfd().events);

PollMask GetPollMask(QuicSocketEventMask event_mask) {
  return ((event_mask & kSocketEventReadable) ? POLLIN : 0) |
         ((event_mask & kSocketEventWritable) ? POLLOUT : 0) |
         ((event_mask & kSocketEventError) ? POLLERR : 0);
}

QuicSocketEventMask GetEventMask(PollMask poll_mask) {
  return ((poll_mask & POLLIN) ? kSocketEventReadable : 0) |
         ((poll_mask & POLLOUT) ? kSocketEventWritable : 0) |
         ((poll_mask & POLLERR) ? kSocketEventError : 0);
}

}  // namespace

QuicPollEventLoop::QuicPollEventLoop(QuicClock* clock) : clock_(clock) {}

bool QuicPollEventLoop::RegisterSocket(SocketFd fd, QuicSocketEventMask events,
                                       QuicSocketEventListener* listener) {
  auto [it, success] =
      registrations_.insert({fd, std::make_shared<Registration>()});
  if (!success) {
    return false;
  }
  Registration& registration = *it->second;
  registration.events = events;
  registration.listener = listener;
  return true;
}

bool QuicPollEventLoop::UnregisterSocket(SocketFd fd) {
  return registrations_.erase(fd);
}

bool QuicPollEventLoop::RearmSocket(SocketFd fd, QuicSocketEventMask events) {
  auto it = registrations_.find(fd);
  if (it == registrations_.end()) {
    return false;
  }
  it->second->events |= events;
  return true;
}

bool QuicPollEventLoop::ArtificiallyNotifyEvent(SocketFd fd,
                                                QuicSocketEventMask events) {
  auto it = registrations_.find(fd);
  if (it == registrations_.end()) {
    return false;
  }
  has_artificial_events_pending_ = true;
  it->second->artificially_notify_at_next_iteration |= events;
  return true;
}

void QuicPollEventLoop::RunEventLoopOnce(QuicTime::Delta default_timeout) {
  const QuicTime start_time = clock_->Now();
  ProcessAlarmsUpTo(start_time);

  QuicTime::Delta timeout = ComputePollTimeout(start_time, default_timeout);
  ProcessIoEvents(start_time, timeout);

  const QuicTime end_time = clock_->Now();
  ProcessAlarmsUpTo(end_time);
}

QuicTime::Delta QuicPollEventLoop::ComputePollTimeout(
    QuicTime now, QuicTime::Delta default_timeout) const {
  default_timeout = std::max(default_timeout, QuicTime::Delta::Zero());
  if (has_artificial_events_pending_) {
    return QuicTime::Delta::Zero();
  }
  if (alarms_.empty()) {
    return default_timeout;
  }
  QuicTime end_time = std::min(now + default_timeout, alarms_.begin()->first);
  if (end_time < now) {
    // We only run a single pass of processing alarm callbacks per
    // RunEventLoopOnce() call.  If an alarm schedules another alarm in the past
    // while in the callback, this will happen.
    return QuicTime::Delta::Zero();
  }
  return end_time - now;
}

int QuicPollEventLoop::PollWithRetries(absl::Span<pollfd> fds,
                                       QuicTime start_time,
                                       QuicTime::Delta timeout) {
  const QuicTime timeout_at = start_time + timeout;
  int poll_result;
  for (;;) {
    float timeout_ms = std::ceil(timeout.ToMicroseconds() / 1000.f);
    poll_result =
        PollSyscall(fds.data(), fds.size(), static_cast<int>(timeout_ms));

    // Stop if there are events or a non-EINTR error.
    bool done = poll_result > 0 || (poll_result < 0 && errno != EINTR);
    if (done) {
      break;
    }
    // Poll until `clock_` shows the timeout was exceeded.
    // PollSyscall uses a system clock internally that may run faster.
    QuicTime now = clock_->Now();
    if (now >= timeout_at) {
      break;
    }
    timeout = timeout_at - now;
  }
  return poll_result;
}

void QuicPollEventLoop::ProcessIoEvents(QuicTime start_time,
                                        QuicTime::Delta timeout) {
  // Set up the pollfd[] array.
  const size_t registration_count = registrations_.size();
  auto pollfds = std::make_unique<pollfd[]>(registration_count);
  size_t i = 0;
  for (auto& [fd, registration] : registrations_) {
    QUICHE_CHECK_LT(
        i, registration_count);  // Crash instead of out-of-bounds access.
    pollfds[i].fd = fd;
    pollfds[i].events = GetPollMask(registration->events);
    pollfds[i].revents = 0;
    ++i;
  }

  // Actually run poll(2).
  int poll_result =
      PollWithRetries(absl::Span<pollfd>(pollfds.get(), registration_count),
                      start_time, timeout);
  if (poll_result == 0 && !has_artificial_events_pending_) {
    return;
  }

  // Prepare the list of all callbacks to be called, while resetting all events,
  // since we're operating in the level-triggered mode.
  std::vector<ReadyListEntry> ready_list;
  ready_list.reserve(registration_count);
  for (i = 0; i < registration_count; i++) {
    DispatchIoEvent(ready_list, pollfds[i].fd, pollfds[i].revents);
  }
  has_artificial_events_pending_ = false;

  // Actually call all of the callbacks.
  RunReadyCallbacks(ready_list);
}

void QuicPollEventLoop::DispatchIoEvent(std::vector<ReadyListEntry>& ready_list,
                                        SocketFd fd, PollMask mask) {
  auto it = registrations_.find(fd);
  if (it == registrations_.end()) {
    QUIC_BUG(poll returned an unregistered fd) << fd;
    return;
  }
  Registration& registration = *it->second;

  mask |= GetPollMask(registration.artificially_notify_at_next_iteration);
  // poll() always returns certain classes of events even if not requested.
  mask &= GetPollMask(registration.events |
                      registration.artificially_notify_at_next_iteration);
  registration.artificially_notify_at_next_iteration = QuicSocketEventMask();
  if (!mask) {
    return;
  }

  ready_list.push_back(ReadyListEntry{fd, it->second, GetEventMask(mask)});
  registration.events &= ~GetEventMask(mask);
}

void QuicPollEventLoop::RunReadyCallbacks(
    std::vector<ReadyListEntry>& ready_list) {
  for (ReadyListEntry& entry : ready_list) {
    std::shared_ptr<Registration> registration = entry.registration.lock();
    if (!registration) {
      // The socket has been unregistered from within one of the callbacks.
      continue;
    }
    registration->listener->OnSocketEvent(this, entry.fd, entry.events);
  }
  ready_list.clear();
}

void QuicPollEventLoop::ProcessAlarmsUpTo(QuicTime time) {
  // Determine which alarm callbacks needs to be run.
  std::vector<std::weak_ptr<Alarm*>> alarms_to_call;
  while (!alarms_.empty() && alarms_.begin()->first <= time) {
    auto& [deadline, schedule_handle_weak] = *alarms_.begin();
    alarms_to_call.push_back(std::move(schedule_handle_weak));
    alarms_.erase(alarms_.begin());
  }
  // Actually run those callbacks.
  for (std::weak_ptr<Alarm*>& schedule_handle_weak : alarms_to_call) {
    std::shared_ptr<Alarm*> schedule_handle = schedule_handle_weak.lock();
    if (!schedule_handle) {
      // The alarm has been cancelled and might not even exist anymore.
      continue;
    }
    (*schedule_handle)->DoFire();
  }
  // Clean up all of the alarms in the front that have been cancelled.
  while (!alarms_.empty()) {
    if (alarms_.begin()->second.expired()) {
      alarms_.erase(alarms_.begin());
    } else {
      break;
    }
  }
}

QuicAlarm* QuicPollEventLoop::AlarmFactory::CreateAlarm(
    QuicAlarm::Delegate* delegate) {
  return new Alarm(loop_, QuicArenaScopedPtr<QuicAlarm::Delegate>(delegate));
}

QuicArenaScopedPtr<QuicAlarm> QuicPollEventLoop::AlarmFactory::CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) {
  if (arena != nullptr) {
    return arena->New<Alarm>(loop_, std::move(delegate));
  }
  return QuicArenaScopedPtr<QuicAlarm>(new Alarm(loop_, std::move(delegate)));
}

QuicPollEventLoop::Alarm::Alarm(
    QuicPollEventLoop* loop, QuicArenaScopedPtr<QuicAlarm::Delegate> delegate)
    : QuicAlarm(std::move(delegate)), loop_(loop) {}

void QuicPollEventLoop::Alarm::SetImpl() {
  current_schedule_handle_ = std::make_shared<Alarm*>(this);
  loop_->alarms_.insert({deadline(), current_schedule_handle_});
}

void QuicPollEventLoop::Alarm::CancelImpl() {
  current_schedule_handle_.reset();
}

std::unique_ptr<QuicAlarmFactory> QuicPollEventLoop::CreateAlarmFactory() {
  return std::make_unique<AlarmFactory>(this);
}

int QuicPollEventLoop::PollSyscall(pollfd* fds, size_t nfds, int timeout) {
#if defined(_WIN32)
  return WSAPoll(fds, nfds, timeout);
#else
  return ::poll(fds, nfds, timeout);
#endif  // defined(_WIN32)
}

}  // namespace quic

"""

```