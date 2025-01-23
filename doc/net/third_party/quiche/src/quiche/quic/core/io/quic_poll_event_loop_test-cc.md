Response:
The user wants to understand the functionality of the `quic_poll_event_loop_test.cc` file in the Chromium network stack. I need to explain what this file does, its relationship to Javascript (if any), provide examples with hypothetical inputs and outputs, discuss common usage errors, and describe how a user might end up triggering this code.

Here's a breakdown of how to address each point:

1. **Functionality:** The core purpose of a `_test.cc` file is to test the functionality of a corresponding source file. In this case, it's testing `quic_poll_event_loop.cc`. This involves setting up various scenarios and using assertions to verify that the `QuicPollEventLoop` class behaves as expected. Key aspects to highlight are socket registration/unregistration, event notifications (read/write), handling timeouts, and managing alarms.

2. **Relationship to Javascript:**  The Chromium network stack, including QUIC, is written in C++. While it underpins the network communication for web browsers, which execute Javascript, there isn't a direct, explicit connection at the *source code* level. I need to explain this indirect relationship. When Javascript makes a network request (e.g., using `fetch`), the browser's networking components (including QUIC) handle the underlying communication.

3. **Hypothetical Inputs and Outputs:**  I can pick some key test cases from the file and explain the setup (input) and the expected outcome (output). For example, the "Readable" test case involves writing to a pipe and expecting a read event. I should simplify the explanation.

4. **Common Usage Errors:** Since this is a test file, it doesn't represent user-facing code. The "users" here are the developers writing code that *uses* `QuicPollEventLoop`. The common errors would involve misusing the API, such as failing to register sockets correctly, misinterpreting event notifications, or not handling timeouts properly. I should also mention potential race conditions in multithreaded environments.

5. **User Operations and Debugging:** To explain how a user action leads to this code, I need to trace a high-level flow. A user initiates a network request in the browser. This triggers the network stack, which might use QUIC, and the `QuicPollEventLoop` manages the underlying socket events. For debugging, developers would use tools like breakpoints and logging within this C++ code.

**Mental Sandbox:**

*   **Functionality:** I'll focus on the core concepts tested: registration, event notification, alarms, timeouts.
*   **Javascript:** I'll clearly state the C++ nature and the indirect link via browser networking.
*   **Inputs/Outputs:** I'll choose a simple case like the "Readable" test. Input: `write()` to a pipe. Output: `OnSocketEvent` with `kSocketEventReadable`.
*   **Usage Errors:** I'll think about typical API misuse patterns. For instance, registering the same socket multiple times.
*   **User Operations/Debugging:** I'll imagine a user clicking a link and how the request flows through the browser to the network stack.

Okay, the planning is complete. I'm ready to generate the response.
这个文件 `net/third_party/quiche/src/quiche/quic/core/io/quic_poll_event_loop_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它的主要功能是**测试 `QuicPollEventLoop` 类的功能是否正常**。

`QuicPollEventLoop` 是一个基于 `poll()` 系统调用的事件循环，用于监听和处理套接字上的事件（例如可读、可写）以及定时器事件。这个测试文件通过模拟各种场景来验证 `QuicPollEventLoop` 的行为是否符合预期。

**主要功能点包括：**

*   **套接字注册与注销:** 测试 `RegisterSocket` 和 `UnregisterSocket` 方法，确保能够正确地添加和移除需要监听的套接字。
*   **事件通知:** 测试当套接字上发生特定事件（例如可读、可写）时，`QuicPollEventLoop` 是否能够正确地通知注册的监听器。
*   **人工事件触发:** 测试 `ArtificiallyNotifyEvent` 方法，该方法允许人为地触发套接字事件，用于模拟某些特殊情况。
*   **重新武装套接字:** 测试 `RearmSocket` 方法，用于在处理事件后重新监听套接字的特定事件。
*   **超时计算:** 测试 `ComputePollTimeout` 方法，该方法用于计算 `poll()` 系统调用的超时时间，考虑了最近的定时器事件。
*   **定时器（Alarm）管理:** 测试 `QuicAlarm` 与 `QuicPollEventLoop` 的集成，验证定时器是否能在预期的时间触发。包括设置定时器、取消定时器以及在定时器回调中取消其他定时器。
*   **处理 `EINTR` 中断:** 测试当 `poll()` 系统调用被信号中断 (`EINTR`) 时，`QuicPollEventLoop` 是否能够正确处理并继续运行。
*   **模拟 `poll()` 提前返回:** 测试当 `poll()` 系统调用在超时之前返回时，`QuicPollEventLoop` 的行为。

**与 Javascript 的关系：**

这个 C++ 文件本身与 Javascript 没有直接的编程接口上的关系。然而，从更高的层面来看，它的功能是支撑 Chromium 浏览器进行网络通信的关键部分。当 Javascript 代码（例如在网页中运行的脚本）发起网络请求时，Chromium 浏览器底层的网络栈（包括 QUIC 协议和 `QuicPollEventLoop`）会负责处理这些请求。

**举例说明:**

当一个网页的 Javascript 代码使用 `fetch()` API 发起一个 HTTPS 请求时，如果浏览器和服务器之间协商使用了 QUIC 协议，那么 `QuicPollEventLoop` 就会在后台工作，监听与该连接相关的套接字事件。

*   **Javascript 发起请求:** `fetch('https://example.com')`
*   **底层处理:** Chromium 的网络栈会创建 QUIC 连接，并使用 `QuicPollEventLoop` 监听连接的套接字是否可读（接收数据）、可写（发送数据）等。
*   **事件通知:** 当服务器返回数据时，底层的套接字变为可读，`QuicPollEventLoop` 会通知相应的 QUIC 组件来处理接收到的数据。
*   **数据传递:** 接收到的数据最终会被传递回 Javascript 代码，`fetch()` API 的 Promise 会 resolve。

**逻辑推理与假设输入输出：**

**场景：测试套接字可读事件**

*   **假设输入:**
    1. 创建一个管道 `read_fd_` 和 `write_fd_`。
    2. 在 `QuicPollEventLoop` 中注册 `read_fd_`，监听可读事件。
    3. 从 `write_fd_` 写入数据 "test"。
*   **预期输出:**
    1. `QuicPollEventLoop` 的 `RunEventLoopOnce` 方法被调用。
    2. 注册到 `read_fd_` 的监听器（`MockQuicSocketEventListener`）的 `OnSocketEvent` 方法会被调用。
    3. `OnSocketEvent` 方法的参数 `events` 包含 `kSocketEventReadable`。

**用户或编程常见的使用错误：**

1. **忘记注册套接字:**  在开始监听套接字事件之前，必须先使用 `RegisterSocket` 将套接字和监听器注册到 `QuicPollEventLoop`。忘记注册会导致事件无法被正确处理。
    *   **错误示例:**  直接向已创建但未注册的套接字写入数据，期望能收到事件通知，但实际上 `QuicPollEventLoop` 并不会监听该套接字。

2. **重复注册套接字:** 尝试使用相同的套接字多次调用 `RegisterSocket`。`QuicPollEventLoop` 通常会阻止这种行为，并返回错误。
    *   **错误示例:**  在已经注册了一个套接字后，再次使用相同的套接字和监听器调用 `RegisterSocket`，可能会导致未定义的行为或断言失败。

3. **在事件处理程序中忘记重新武装套接字:**  某些场景下，处理完一个事件后，可能需要继续监听该套接字的同类事件。如果忘记使用 `RearmSocket` 重新注册监听，后续的事件可能不会被通知。
    *   **错误示例:**  读取了套接字中的部分数据后，希望继续接收更多数据，但忘记调用 `RearmSocket` 重新监听可读事件，导致后续数据到达时没有得到处理。

4. **对已注销的套接字进行操作:**  在调用 `UnregisterSocket` 注销套接字后，继续尝试使用 `RearmSocket` 或 `ArtificiallyNotifyEvent` 操作该套接字会导致错误。
    *   **错误示例:**  在一个事件处理程序中注销了一个套接字，然后在后续的代码中尝试重新武装该套接字。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户在 Chromium 浏览器中访问一个使用 QUIC 协议的网站。** 例如，在地址栏输入 `https://www.google.com` (假设 Google 服务器支持且浏览器协商使用了 QUIC)。

2. **浏览器发起连接。** Chromium 的网络栈开始建立与 Google 服务器的 QUIC 连接。

3. **创建套接字。** 网络栈会创建一个或多个 UDP 套接字用于 QUIC 通信。

4. **`QuicPollEventLoop` 注册套接字。**  与 QUIC 连接相关的套接字会被注册到 `QuicPollEventLoop` 中，以便监听网络事件（例如接收到来自服务器的数据）。

5. **网络事件发生。**  当服务器发送数据包到达客户端时，与该连接关联的套接字变为可读。

6. **`poll()` 系统调用返回。** `QuicPollEventLoop` 内部的 `poll()` 调用会检测到套接字上的可读事件。

7. **事件通知。** `QuicPollEventLoop` 会调用注册到该套接字的监听器的 `OnSocketEvent` 方法，并将 `kSocketEventReadable` 作为参数传递。

8. **QUIC 组件处理数据。** 监听器（通常是 QUIC 协议栈的某个组件）会读取套接字中的数据，并进行 QUIC 协议相关的处理，例如解密、解复用等。

9. **数据传递到上层。**  处理后的数据最终会传递到 Chromium 更高层的网络模块，并最终可能传递到渲染进程，供 Javascript 代码使用。

**调试线索:**

如果在调试 QUIC 连接问题时，怀疑事件循环没有正确工作，可以考虑以下步骤：

*   **设置断点:** 在 `quic_poll_event_loop_test.cc` 或 `quic_poll_event_loop.cc` 的关键位置设置断点，例如 `RegisterSocket`、`UnregisterSocket`、`RunEventLoopOnce`、`PollSyscall` 以及事件处理函数中。
*   **查看套接字注册状态:** 检查哪些套接字被注册到 `QuicPollEventLoop`，以及它们监听的事件类型。
*   **观察 `poll()` 调用:** 查看 `poll()` 系统调用的返回值、超时时间以及返回的事件，确认是否正确地检测到了网络事件。
*   **检查事件处理函数是否被调用:** 确认在网络事件发生后，对应的 `OnSocketEvent` 方法是否被调用，以及传递的事件参数是否正确。
*   **分析定时器行为:** 如果涉及到超时或定时器，检查 `QuicAlarm` 的设置和触发情况，确认定时器是否按预期工作。

通过分析这些信息，可以帮助开发者理解 `QuicPollEventLoop` 的行为，并定位网络连接问题的原因。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/io/quic_poll_event_loop_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/io/quic_poll_event_loop.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"

namespace quic {

class QuicPollEventLoopPeer {
 public:
  static QuicTime::Delta ComputePollTimeout(const QuicPollEventLoop& loop,
                                            QuicTime now,
                                            QuicTime::Delta default_timeout) {
    return loop.ComputePollTimeout(now, default_timeout);
  }
};

}  // namespace quic

namespace quic::test {
namespace {

using testing::_;
using testing::AtMost;
using testing::ElementsAre;

constexpr QuicSocketEventMask kAllEvents =
    kSocketEventReadable | kSocketEventWritable | kSocketEventError;
constexpr QuicTime::Delta kDefaultTimeout = QuicTime::Delta::FromSeconds(100);

class MockQuicSocketEventListener : public QuicSocketEventListener {
 public:
  MOCK_METHOD(void, OnSocketEvent,
              (QuicEventLoop* /*event_loop*/, SocketFd /*fd*/,
               QuicSocketEventMask /*events*/),
              (override));
};

class MockDelegate : public QuicAlarm::Delegate {
 public:
  QuicConnectionContext* GetConnectionContext() override { return nullptr; }
  MOCK_METHOD(void, OnAlarm, (), (override));
};

class QuicPollEventLoopForTest : public QuicPollEventLoop {
 public:
  QuicPollEventLoopForTest(MockClock* clock)
      : QuicPollEventLoop(clock), clock_(clock) {}

  int PollSyscall(pollfd* fds, nfds_t nfds, int timeout) override {
    timeouts_.push_back(timeout);
    if (eintr_after_ != QuicTime::Delta::Infinite()) {
      errno = EINTR;
      clock_->AdvanceTime(eintr_after_);
      eintr_after_ = QuicTime::Delta::Infinite();
      return -1;
    }
    if (poll_return_after_ != QuicTime::Delta::Infinite()) {
      clock_->AdvanceTime(poll_return_after_);
      poll_return_after_ = QuicTime::Delta::Infinite();
    } else {
      clock_->AdvanceTime(QuicTime::Delta::FromMilliseconds(timeout));
    }

    return QuicPollEventLoop::PollSyscall(fds, nfds, timeout);
  }

  void TriggerEintrAfter(QuicTime::Delta time) { eintr_after_ = time; }
  void ReturnFromPollAfter(QuicTime::Delta time) { poll_return_after_ = time; }

  const std::vector<int>& timeouts() const { return timeouts_; }

 private:
  MockClock* clock_;
  QuicTime::Delta eintr_after_ = QuicTime::Delta::Infinite();
  QuicTime::Delta poll_return_after_ = QuicTime::Delta::Infinite();
  std::vector<int> timeouts_;
};

class QuicPollEventLoopTest : public QuicTest {
 public:
  QuicPollEventLoopTest()
      : loop_(&clock_), factory_(loop_.CreateAlarmFactory()) {
    int fds[2];
    int result = ::pipe(fds);
    QUICHE_CHECK(result >= 0) << "Failed to create a pipe, errno: " << errno;
    read_fd_ = fds[0];
    write_fd_ = fds[1];

    QUICHE_CHECK(::fcntl(read_fd_, F_SETFL,
                         ::fcntl(read_fd_, F_GETFL) | O_NONBLOCK) == 0)
        << "Failed to mark pipe FD non-blocking, errno: " << errno;
    QUICHE_CHECK(::fcntl(write_fd_, F_SETFL,
                         ::fcntl(write_fd_, F_GETFL) | O_NONBLOCK) == 0)
        << "Failed to mark pipe FD non-blocking, errno: " << errno;

    clock_.AdvanceTime(10 * kDefaultTimeout);
  }

  ~QuicPollEventLoopTest() {
    close(read_fd_);
    close(write_fd_);
  }

  QuicTime::Delta ComputePollTimeout() {
    return QuicPollEventLoopPeer::ComputePollTimeout(loop_, clock_.Now(),
                                                     kDefaultTimeout);
  }

  std::pair<std::unique_ptr<QuicAlarm>, MockDelegate*> CreateAlarm() {
    auto delegate = std::make_unique<testing::StrictMock<MockDelegate>>();
    MockDelegate* delegate_unowned = delegate.get();
    auto alarm = absl::WrapUnique(factory_->CreateAlarm(delegate.release()));
    return std::make_pair(std::move(alarm), delegate_unowned);
  }

 protected:
  MockClock clock_;
  QuicPollEventLoopForTest loop_;
  std::unique_ptr<QuicAlarmFactory> factory_;
  int read_fd_;
  int write_fd_;
};

TEST_F(QuicPollEventLoopTest, NothingHappens) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  // Attempt double-registration.
  EXPECT_FALSE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(4));
  // Expect no further calls.
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_THAT(loop_.timeouts(), ElementsAre(4, 5));
}

TEST_F(QuicPollEventLoopTest, RearmWriter) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable))
      .Times(2);
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  ASSERT_TRUE(loop_.RearmSocket(write_fd_, kSocketEventWritable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_F(QuicPollEventLoopTest, Readable) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));

  ASSERT_EQ(4, write(write_fd_, "test", 4));
  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  // Expect no further calls.
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_F(QuicPollEventLoopTest, RearmReader) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));

  ASSERT_EQ(4, write(write_fd_, "test", 4));
  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  // Expect no further calls.
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_F(QuicPollEventLoopTest, WriterUnblocked) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));

  int io_result;
  std::string data(2048, 'a');
  do {
    io_result = write(write_fd_, data.data(), data.size());
  } while (io_result > 0);
  ASSERT_EQ(errno, EAGAIN);

  // Rearm and expect no immediate calls.
  ASSERT_TRUE(loop_.RearmSocket(write_fd_, kSocketEventWritable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  do {
    io_result = read(read_fd_, data.data(), data.size());
  } while (io_result > 0);
  ASSERT_EQ(errno, EAGAIN);
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_F(QuicPollEventLoopTest, ArtificialEvent) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);
  ASSERT_TRUE(loop_.ArtificiallyNotifyEvent(read_fd_, kSocketEventReadable));
  EXPECT_EQ(ComputePollTimeout(), QuicTime::Delta::Zero());

  {
    testing::InSequence s;
    EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable));
    EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  }
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);
}

TEST_F(QuicPollEventLoopTest, Unregister) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_.UnregisterSocket(write_fd_));

  // Expect nothing to happen.
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));

  EXPECT_FALSE(loop_.UnregisterSocket(write_fd_));
  EXPECT_FALSE(loop_.RearmSocket(write_fd_, kSocketEventWritable));
  EXPECT_FALSE(loop_.ArtificiallyNotifyEvent(write_fd_, kSocketEventWritable));
}

TEST_F(QuicPollEventLoopTest, UnregisterInsideEventHandler) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable))
      .WillOnce([this]() { ASSERT_TRUE(loop_.UnregisterSocket(write_fd_)); });
  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable))
      .Times(0);
  ASSERT_TRUE(loop_.ArtificiallyNotifyEvent(read_fd_, kSocketEventReadable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_F(QuicPollEventLoopTest, EintrHandler) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));

  loop_.TriggerEintrAfter(QuicTime::Delta::FromMilliseconds(25));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
  EXPECT_THAT(loop_.timeouts(), ElementsAre(100, 75));
}

TEST_F(QuicPollEventLoopTest, PollReturnsEarly) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));

  loop_.ReturnFromPollAfter(QuicTime::Delta::FromMilliseconds(25));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
  EXPECT_THAT(loop_.timeouts(), ElementsAre(100, 75));
}

TEST_F(QuicPollEventLoopTest, AlarmInFuture) {
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm, delegate] = CreateAlarm();
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  alarm->Set(clock_.Now() + kAlarmTimeout);
  EXPECT_EQ(ComputePollTimeout(), kAlarmTimeout);

  EXPECT_CALL(*delegate, OnAlarm());
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);
}

TEST_F(QuicPollEventLoopTest, AlarmsInPast) {
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm1, delegate1] = CreateAlarm();
  auto [alarm2, delegate2] = CreateAlarm();

  alarm1->Set(clock_.Now() - 2 * kAlarmTimeout);
  alarm2->Set(clock_.Now() - kAlarmTimeout);

  {
    testing::InSequence s;
    EXPECT_CALL(*delegate1, OnAlarm());
    EXPECT_CALL(*delegate2, OnAlarm());
  }
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
}

TEST_F(QuicPollEventLoopTest, AlarmCancelled) {
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm, delegate] = CreateAlarm();
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  alarm->Set(clock_.Now() + kAlarmTimeout);
  alarm->Cancel();
  alarm->Set(clock_.Now() + 2 * kAlarmTimeout);
  EXPECT_EQ(ComputePollTimeout(), kAlarmTimeout);

  EXPECT_CALL(*delegate, OnAlarm());
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
  EXPECT_THAT(loop_.timeouts(), ElementsAre(10));
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);
}

TEST_F(QuicPollEventLoopTest, AlarmCancelsAnotherAlarm) {
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm1_ptr, delegate1] = CreateAlarm();
  auto [alarm2_ptr, delegate2] = CreateAlarm();

  QuicAlarm& alarm1 = *alarm1_ptr;
  QuicAlarm& alarm2 = *alarm2_ptr;
  alarm1.Set(clock_.Now() - kAlarmTimeout);
  alarm2.Set(clock_.Now() - kAlarmTimeout);

  int alarms_called = 0;
  // Since the order in which alarms are cancelled is not well-determined, make
  // each one cancel another.
  EXPECT_CALL(*delegate1, OnAlarm()).Times(AtMost(1)).WillOnce([&]() {
    alarm2.Cancel();
    ++alarms_called;
  });
  EXPECT_CALL(*delegate2, OnAlarm()).Times(AtMost(1)).WillOnce([&]() {
    alarm1.Cancel();
    ++alarms_called;
  });
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
  EXPECT_EQ(alarms_called, 1);
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);
}

}  // namespace
}  // namespace quic::test
```