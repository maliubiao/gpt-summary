Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Core Purpose:**

The initial lines are crucial: "A universal test for all event loops supported by the build of QUICHE." This immediately tells us the file is about testing different implementations of event loops within the QUICHE library. The comparison to `QuicPollEventLoopTest` highlights the key differences: real clock usage and support for both level-triggered and edge-triggered events.

**2. Identifying Key Components:**

Scan the `#include` directives and the code structure for important classes and concepts:

*   `QuicEventLoop`: This is the central abstraction being tested.
*   `QuicDefaultEventLoop`:  Likely a concrete implementation of `QuicEventLoop`.
*   `QuicAlarm`:  Used for timing and scheduling events.
*   `QuicAlarmFactory`:  For creating `QuicAlarm` instances.
*   `QuicSocketEventListener`: An interface for receiving socket events.
*   `MockQuicSocketEventListener`, `MockDelegate`:  Test doubles (mocks) to control behavior and verify expectations.
*   `QuicTime`, `QuicDefaultClock`:  Classes related to time.
*   `SocketFd`:  Represents a file descriptor (likely a socket).
*   `QuicSocketEventMask`:  A bitmask for representing socket events (readable, writable, error).
*   `GetAllSupportedEventLoops()`:  A function (likely defined elsewhere) that provides a list of event loop factory implementations.
*   The test fixture `QuicEventLoopFactoryTest`.
*   Individual `TEST_P` test cases.

**3. Analyzing the Test Fixture (`QuicEventLoopFactoryTest`):**

*   **Parametrization:** The `QuicTestWithParam<QuicEventLoopFactory*>` indicates that the tests are run with different `QuicEventLoopFactory` implementations. This reinforces the "universal test" aspect.
*   **Setup (`SetUp`)**:  Creates a `QuicEventLoop`, an `AlarmFactory`, and a pipe (two file descriptors for inter-process communication simulation). The pipe's FDs are set to non-blocking.
*   **Tear Down (`TearDown`)**: Cleans up resources (factory, loop, and closes the file descriptors). The comment about Epoll automatically removing FDs is a hint about potential underlying implementations.
*   **`CreateAlarm()`**:  A helper function to create an alarm and a mock delegate for it.
*   **`RunEventLoopUntil()`**: A utility function to run the event loop until a condition is met or a timeout occurs. This is a common pattern for testing asynchronous operations.

**4. Examining Individual Test Cases:**

For each test case, try to understand its purpose and the assertions it makes:

*   **`NothingHappens`**: Registers sockets, tries double registration (should fail), and runs the loop expecting a write event. This tests basic registration and event triggering.
*   **`RearmWriter`**: Tests rearming a socket for write events. The difference in behavior for edge-triggered vs. level-triggered loops is important here.
*   **`Readable`**:  Writes to a pipe and verifies that a readable event is triggered on the reading end.
*   **`ArtificialNotifyFromCallback`**: Tests the `ArtificiallyNotifyEvent` mechanism, where an event is triggered programmatically within a callback. The handling of edge vs. level triggering is again crucial.
*   **`ArtificialNotifyOncePerIteration`**: Checks that artificial events are processed only once per event loop iteration to prevent infinite loops.
*   **`WriterUnblocked`**: Simulates a blocked write and verifies that a writeable event is triggered when the blockage is removed (by reading from the other end of the pipe).
*   **`ArtificialEvent`**: Directly triggers artificial read and write events.
*   **`Unregister`**: Tests the `UnregisterSocket` functionality.
*   **`UnregisterInsideEventHandler`**:  Checks the behavior of unregistering a socket from within its own event handler.
*   **`UnregisterSelfInsideEventHandler`**:  A specific case of unregistering the socket that triggered the event.
*   **`ReadWriteSocket`**:  Uses a bidirectional socket (`socketpair`) to test both read and write events on the same socket.
*   **Alarm-related tests (`AlarmInFuture`, `AlarmsInPast`, `AlarmCancelled`, etc.)**: These test the functionality of the `QuicAlarm` class, including setting alarms, canceling them, and the timing of alarm callbacks.
*   **Error Handling (`NegativeTimeout`)**: Tests how the event loop handles invalid input (negative timeout).
*   **`ScheduleAlarmInPastFromInsideAlarm`**:  Tests scheduling a new alarm from within an existing alarm's callback.

**5. Identifying Connections to JavaScript (Based on Keywords and Functionality):**

Look for concepts and terms that are common in JavaScript's asynchronous programming model:

*   **Event Loop:**  JavaScript has a central event loop that handles asynchronous operations. The C++ code is explicitly testing different implementations of *an* event loop, which is a fundamental concept in asynchronous programming across different languages.
*   **Callbacks:** The `OnSocketEvent` and `OnAlarm` methods are effectively callbacks that are invoked when events occur. Callbacks are a cornerstone of asynchronous programming in JavaScript.
*   **Timers:** The `QuicAlarm` mechanism is analogous to `setTimeout` and `setInterval` in JavaScript.
*   **Non-blocking I/O:**  The use of `O_NONBLOCK` indicates non-blocking socket operations, which is essential for efficient event-driven programming (like Node.js).
*   **Promises/Async-Await (Indirect):** While not directly present, the event loop is the underlying mechanism that makes Promises and `async`/`await` work in JavaScript. The tests verify the core infrastructure that enables these higher-level abstractions.

**6. Logical Inference (Hypothetical Input/Output):**

For tests involving sockets, consider the flow of data:

*   **`Readable`:**
    *   *Input:*  Data written to `write_fd_`.
    *   *Output:* `OnSocketEvent` called for `read_fd_` with `kSocketEventReadable`.
*   **`WriterUnblocked`:**
    *   *Input:* Initially, writing to `write_fd_` blocks. Then, data is read from `read_fd_`, unblocking the writer.
    *   *Output:* Initially, `OnSocketEvent` with `kSocketEventWritable`. After unblocking, another `OnSocketEvent` with `kSocketEventWritable`.
*   **Alarm Tests:**
    *   *Input:* Setting an alarm with a specific timeout.
    *   *Output:* `OnAlarm` callback invoked after the timeout (or immediately if the timeout is in the past).

**7. Common Usage Errors:**

Think about how a developer might misuse the event loop or related APIs:

*   **Forgetting to Register Sockets:**  Trying to receive events on a socket without registering it with the event loop.
*   **Incorrect Event Masks:**  Registering for the wrong type of event (e.g., only readable when the intention is to handle both readable and writable).
*   **Not Handling `EAGAIN`:** In non-blocking I/O, `read` and `write` can return `-1` with `errno` set to `EAGAIN` when there's no data or the buffer is full. Ignoring this can lead to busy-waiting or lost data. The `ArtificialNotifyFromCallback` test touches on this.
*   **Double Registration:** Trying to register the same socket multiple times (the test explicitly checks for this).
*   **Memory Management:** Incorrectly managing the lifetime of `QuicAlarm` delegates. The test with `DestructorWithPendingAlarm` implicitly checks for proper cleanup.
*   **Deadlocks/Infinite Loops:**  In scenarios with artificial events, continuously triggering new events within a callback without processing data could lead to a loop. The `ArtificialNotifyOncePerIteration` test aims to prevent this.

**8. Debugging Steps (User Operation to Reach the Code):**

Imagine a scenario where a network connection in Chromium (using QUIC) is behaving unexpectedly:

1. **Network Issue Reported:** A user reports slow loading times or connection drops on a website using QUIC.
2. **Developer Investigation:** A network engineer starts investigating the QUIC connection.
3. **Focus on I/O:**  They suspect issues with how the application is handling network events (reading and writing data).
4. **Looking at Event Handling:** They delve into the QUICHE library's I/O layer, where event loops are central.
5. **Examining Event Loop Implementations:** They might look at the different `QuicEventLoop` implementations (poll, epoll, etc.).
6. **Running Tests:** To verify the correctness of the event loop implementations, they would run tests like `quic_all_event_loops_test.cc`.
7. **Specific Test Failure:** If a particular test fails (e.g., related to edge-triggered events or alarm timing), this provides a concrete starting point for debugging the underlying issue in the event loop implementation or how it's being used.
8. **Tracing Execution:** The developer might use debugging tools to step through the code in `quic_all_event_loops_test.cc` and the actual event loop implementation to understand the sequence of events and identify the root cause of the failure.

By following these steps, we can systematically understand the purpose, functionality, and implications of this C++ test file.
This C++ source code file, `quic_all_event_loops_test.cc`, is a comprehensive test suite for different implementations of event loops used within the QUICHE library (a QUIC protocol implementation used in Chromium). Its primary function is to ensure that all supported event loop mechanisms behave correctly according to the QUIC specification and internal requirements.

Here's a breakdown of its functionalities:

**1. Universal Testing of Event Loops:**

*   The core purpose is to test various event loop implementations supported by the QUICHE build. This means it's designed to work with different underlying operating system mechanisms like `epoll`, `poll`, `kqueue`, etc., without needing separate test files for each.
*   It achieves this by using a parameterized test (`QuicTestWithParam`) driven by `GetAllSupportedEventLoops()`, which presumably returns a list of available `QuicEventLoopFactory` objects.

**2. Socket Event Handling:**

*   It tests the ability of the event loop to monitor file descriptors (specifically sockets) for readability, writability, and errors.
*   It uses mock objects (`MockQuicSocketEventListener`) to simulate how a QUIC connection might react to socket events. These mocks allow the test to verify that the event loop correctly notifies listeners when events occur.
*   It tests registration, unregistration, and re-arming of socket event listeners.
*   It distinguishes between level-triggered and edge-triggered event loop behavior and has tests to cover both.

**3. Timer Management (Alarms):**

*   It tests the `QuicAlarm` mechanism, which is used for scheduling events in the future.
*   It verifies that alarms fire at the correct time, can be canceled, and that their cancellation and setting work correctly even within alarm callbacks.
*   It checks the behavior of alarms scheduled in the past.

**4. Edge Case and Error Handling:**

*   It tests scenarios like double-registering a socket (which should fail).
*   It checks how the event loop handles negative timeouts for running a single iteration.
*   It includes tests for unregistering sockets, even from within the event handler itself.

**5. Usage of Real Clock:**

*   Unlike some other tests, this test uses the real system clock because certain event loop implementations might not support the injection of a mock clock. This makes the tests more realistic in certain aspects.

**Relationship to JavaScript and Examples:**

While this is C++ code, the underlying concepts of event loops and asynchronous operations are directly related to how JavaScript works, especially in environments like Node.js or web browsers.

*   **Event Loop:**  JavaScript has a single-threaded event loop that manages asynchronous operations. This C++ code is testing the core mechanism that allows for non-blocking I/O and other asynchronous tasks in QUICHE, which is analogous to JavaScript's event loop.

    *   **Example:** In Node.js, when you perform an asynchronous file read (`fs.readFile`), the event loop monitors the file system. Once the file is read, a callback function is added to the event queue and eventually executed. The C++ code tests the core logic of how such events are monitored and dispatched.

*   **Callbacks:** The `OnSocketEvent` and `OnAlarm` methods in the C++ code are essentially callbacks. They are functions that get invoked when a specific event occurs.

    *   **Example:** In JavaScript, you often use callbacks with asynchronous functions:

        ```javascript
        setTimeout(() => {
          console.log("This will be printed after 1 second");
        }, 1000);
        ```

        The anonymous function passed to `setTimeout` is a callback, similar to the `OnAlarm` method being tested in the C++ code.

*   **Timers:**  `QuicAlarm` is similar to `setTimeout` and `setInterval` in JavaScript.

    *   **Example:** The `AlarmInFuture` test in C++ is analogous to setting a timer in JavaScript:

        ```javascript
        setTimeout(() => {
          // Code that should execute later
        }, 5); // 5 milliseconds
        ```

*   **Non-blocking I/O:** The tests involving socket readability and writability demonstrate the non-blocking nature of the I/O operations managed by the event loop.

    *   **Example:** In Node.js, using `net.createServer` to create a TCP server involves the event loop monitoring sockets for incoming connections and data. This C++ code is testing the foundational mechanisms that make this non-blocking I/O possible.

**Logical Inference (Hypothetical Input and Output):**

Let's take the `Readable` test as an example:

*   **Hypothetical Input:**
    1. A `QuicEventLoopFactoryTest` object is initialized.
    2. A read file descriptor (`read_fd_`) and a write file descriptor (`write_fd_`) are created using `pipe`.
    3. The `read_fd_` is registered with the event loop to listen for readable events.
    4. The string "test" is written to the `write_fd_`.

*   **Logical Process:**
    1. The operating system's pipe mechanism buffers the data written to `write_fd_`.
    2. The event loop, monitoring `read_fd_`, detects that there is data available to be read.
    3. The event loop calls the `OnSocketEvent` method of the `MockQuicSocketEventListener` associated with `read_fd_`.

*   **Hypothetical Output:**
    1. The `EXPECT_CALL` on the mock listener is satisfied. The `OnSocketEvent` method is called with:
        *   The event loop instance.
        *   The `read_fd_`.
        *   A `QuicSocketEventMask` that includes `kSocketEventReadable`.
    2. Subsequent calls to `loop_->RunEventLoopOnce` without further data written to the pipe will not trigger the `OnSocketEvent` again (unless the event loop is level-triggered and the data is still in the pipe).

**User or Programming Common Usage Errors:**

*   **Forgetting to Register Sockets:** A common mistake would be to create a socket and try to read or write to it within a QUIC connection without properly registering it with the event loop. This would lead to the event loop being unaware of any events on that socket, causing the application to hang or not receive data. The tests like `NothingHappens` implicitly test this by showing what happens when no events occur on registered sockets.

*   **Incorrect Event Mask:**  A programmer might register a socket only for `kSocketEventWritable` but then expect to be notified when data is available to read. The tests with specific event masks (like `kAllEvents` or just `kSocketEventReadable`) ensure that the event loop respects the registered interest.

*   **Not Handling `EAGAIN` (or equivalent):** When working with non-blocking sockets (as is the case here), `read` or `write` calls might return an error with `errno` set to `EAGAIN` (or `EWOULDBLOCK`). This indicates that the operation couldn't be completed immediately and the program should try again later. Failing to handle this correctly can lead to busy-waiting or data loss. The `ArtificialNotifyFromCallback` test touches upon scenarios where repeated attempts might be needed.

*   **Double Registration:**  Accidentally registering the same socket with the event loop multiple times could lead to unexpected behavior, such as the event handler being called multiple times for the same event. The `NothingHappens` test explicitly checks that double registration is prevented.

**User Operation to Reach This Code (Debugging Scenario):**

Let's imagine a user is experiencing issues with a website using QUIC in Chrome:

1. **User Reports an Issue:** The user reports slow loading times, connection interruptions, or other network-related problems while browsing a specific website.
2. **Chromium Developers Investigate:** Chromium developers start investigating the issue, suspecting it might be related to the QUIC implementation.
3. **Focus on Event Handling:** They might suspect a problem with how QUIC is handling network events (socket reads, writes, timeouts, etc.).
4. **Examining Event Loop Logic:**  To understand how events are being managed, they might look at the code responsible for handling the event loop in QUICHE. This leads them to files like `quic_all_event_loops_test.cc` to see how the core event loop mechanisms are tested.
5. **Running Tests for Specific Scenarios:**  If they suspect an issue with timer management, they might focus on the alarm-related tests. If the problem seems related to socket I/O, they'd look at tests involving `MockQuicSocketEventListener`.
6. **Debugging Test Failures:** If a test in `quic_all_event_loops_test.cc` fails, it indicates a potential bug in one of the event loop implementations or how QUIC is using them. This failing test provides a concrete starting point for debugging the underlying issue.
7. **Tracing Execution:** Developers would use debugging tools to step through the code of the failing test and the corresponding event loop implementation to pinpoint the source of the bug. They might set breakpoints in the `OnSocketEvent` or `OnAlarm` methods or within the event loop's core logic.

In essence, this test file is a crucial part of ensuring the reliability and correctness of QUIC's network communication within Chromium. It acts as a safety net to catch bugs and verify the fundamental mechanisms that underpin asynchronous operations in the QUIC protocol implementation.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/io/quic_all_event_loops_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A universal test for all event loops supported by the build of QUICHE in
// question.
//
// This test is very similar to QuicPollEventLoopTest, however, there are some
// notable differences:
//   (1) This test uses the real clock, since the event loop implementation may
//       not support accepting a mock clock.
//   (2) This test covers both level-triggered and edge-triggered event loops.

#include <fcntl.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/cleanup/cleanup.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic::test {
namespace {

using testing::_;
using testing::AtMost;

MATCHER_P(HasFlagSet, value, "Checks a flag in a bit mask") {
  return (arg & value) != 0;
}

constexpr QuicSocketEventMask kAllEvents =
    kSocketEventReadable | kSocketEventWritable | kSocketEventError;

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

void SetNonBlocking(int fd) {
  QUICHE_CHECK(::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK) == 0)
      << "Failed to mark FD non-blocking, errno: " << errno;
}

class QuicEventLoopFactoryTest
    : public QuicTestWithParam<QuicEventLoopFactory*> {
 public:
  void SetUp() override {
    loop_ = GetParam()->Create(&clock_);
    factory_ = loop_->CreateAlarmFactory();
    int fds[2];
    int result = ::pipe(fds);
    QUICHE_CHECK(result >= 0) << "Failed to create a pipe, errno: " << errno;
    read_fd_ = fds[0];
    write_fd_ = fds[1];

    SetNonBlocking(read_fd_);
    SetNonBlocking(write_fd_);
  }

  void TearDown() override {
    factory_.reset();
    loop_.reset();
    // Epoll-based event loop automatically removes registered FDs from the
    // Epoll set, which should happen before these FDs are closed.
    close(read_fd_);
    close(write_fd_);
  }

  std::pair<std::unique_ptr<QuicAlarm>, MockDelegate*> CreateAlarm() {
    auto delegate = std::make_unique<testing::StrictMock<MockDelegate>>();
    MockDelegate* delegate_unowned = delegate.get();
    auto alarm = absl::WrapUnique(factory_->CreateAlarm(delegate.release()));
    return std::make_pair(std::move(alarm), delegate_unowned);
  }

  template <typename Condition>
  void RunEventLoopUntil(Condition condition, QuicTime::Delta timeout) {
    const QuicTime end = clock_.Now() + timeout;
    while (!condition() && clock_.Now() < end) {
      loop_->RunEventLoopOnce(end - clock_.Now());
    }
  }

 protected:
  QuicDefaultClock clock_;
  std::unique_ptr<QuicEventLoop> loop_;
  std::unique_ptr<QuicAlarmFactory> factory_;
  int read_fd_;
  int write_fd_;
};

std::string GetTestParamName(
    ::testing::TestParamInfo<QuicEventLoopFactory*> info) {
  return EscapeTestParamName(info.param->GetName());
}

INSTANTIATE_TEST_SUITE_P(QuicEventLoopFactoryTests, QuicEventLoopFactoryTest,
                         ::testing::ValuesIn(GetAllSupportedEventLoops()),
                         GetTestParamName);

TEST_P(QuicEventLoopFactoryTest, NothingHappens) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(read_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_->RegisterSocket(write_fd_, kAllEvents, &listener));

  // Attempt double-registration.
  EXPECT_FALSE(loop_->RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(4));
  // Expect no further calls.
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(5));
}

TEST_P(QuicEventLoopFactoryTest, RearmWriter) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(write_fd_, kAllEvents, &listener));

  if (loop_->SupportsEdgeTriggered()) {
    EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable))
        .Times(1);
    loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
    loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  } else {
    EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable))
        .Times(2);
    loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
    ASSERT_TRUE(loop_->RearmSocket(write_fd_, kSocketEventWritable));
    loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  }
}

TEST_P(QuicEventLoopFactoryTest, Readable) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(read_fd_, kAllEvents, &listener));

  ASSERT_EQ(4, write(write_fd_, "test", 4));
  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable));
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  // Expect no further calls.
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

// A common pattern: read a limited amount of data from an FD, and expect to
// read the remainder on the next operation.
TEST_P(QuicEventLoopFactoryTest, ArtificialNotifyFromCallback) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(read_fd_, kSocketEventReadable, &listener));

  constexpr absl::string_view kData = "test test test test test test test ";
  constexpr size_t kTimes = kData.size() / 5;
  ASSERT_EQ(kData.size(), write(write_fd_, kData.data(), kData.size()));
  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable))
      .Times(loop_->SupportsEdgeTriggered() ? (kTimes + 1) : kTimes)
      .WillRepeatedly([&]() {
        char buf[5];
        int read_result = read(read_fd_, buf, sizeof(buf));
        if (read_result > 0) {
          ASSERT_EQ(read_result, 5);
          if (loop_->SupportsEdgeTriggered()) {
            EXPECT_TRUE(
                loop_->ArtificiallyNotifyEvent(read_fd_, kSocketEventReadable));
          } else {
            EXPECT_TRUE(loop_->RearmSocket(read_fd_, kSocketEventReadable));
          }
        } else {
          EXPECT_EQ(errno, EAGAIN);
        }
      });
  for (size_t i = 0; i < kTimes + 2; i++) {
    loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  }
}

// Verify that artificial events are notified on the next iteration. This is to
// prevent infinite loops in RunEventLoopOnce when the event callback keeps
// adding artificial events.
TEST_P(QuicEventLoopFactoryTest, ArtificialNotifyOncePerIteration) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(read_fd_, kSocketEventReadable, &listener));

  constexpr absl::string_view kData = "test test test test test test test ";
  ASSERT_EQ(kData.size(), write(write_fd_, kData.data(), kData.size()));

  int64_t read_event_count_ = 0;
  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable))
      .WillRepeatedly([&]() {
        read_event_count_++;
        EXPECT_TRUE(
            loop_->ArtificiallyNotifyEvent(read_fd_, kSocketEventReadable));
      });
  for (size_t i = 1; i < 5; i++) {
    loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(10));
    EXPECT_EQ(read_event_count_, i);
  }
}

TEST_P(QuicEventLoopFactoryTest, WriterUnblocked) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));

  int io_result;
  std::string data(2048, 'a');
  do {
    io_result = write(write_fd_, data.data(), data.size());
  } while (io_result > 0);
  ASSERT_EQ(errno, EAGAIN);

  // Rearm if necessary and expect no immediate calls.
  if (!loop_->SupportsEdgeTriggered()) {
    ASSERT_TRUE(loop_->RearmSocket(write_fd_, kSocketEventWritable));
  }
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  do {
    io_result = read(read_fd_, data.data(), data.size());
  } while (io_result > 0);
  ASSERT_EQ(errno, EAGAIN);
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_P(QuicEventLoopFactoryTest, ArtificialEvent) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(read_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_->RegisterSocket(write_fd_, kAllEvents, &listener));

  ASSERT_TRUE(loop_->ArtificiallyNotifyEvent(read_fd_, kSocketEventReadable));

  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable));
  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_P(QuicEventLoopFactoryTest, Unregister) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(write_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_->UnregisterSocket(write_fd_));

  // Expect nothing to happen.
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));

  EXPECT_FALSE(loop_->UnregisterSocket(write_fd_));
  if (!loop_->SupportsEdgeTriggered()) {
    EXPECT_FALSE(loop_->RearmSocket(write_fd_, kSocketEventWritable));
  }
  EXPECT_FALSE(loop_->ArtificiallyNotifyEvent(write_fd_, kSocketEventWritable));
}

TEST_P(QuicEventLoopFactoryTest, UnregisterInsideEventHandler) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(read_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_->RegisterSocket(write_fd_, kAllEvents, &listener));

  // We are not guaranteed the order in which those events will happen, so we
  // try to accommodate both possibilities.
  int total_called = 0;
  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable))
      .Times(AtMost(1))
      .WillOnce([&]() {
        ++total_called;
        ASSERT_TRUE(loop_->UnregisterSocket(write_fd_));
      });
  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable))
      .Times(AtMost(1))
      .WillOnce([&]() {
        ++total_called;
        ASSERT_TRUE(loop_->UnregisterSocket(read_fd_));
      });
  ASSERT_TRUE(loop_->ArtificiallyNotifyEvent(read_fd_, kSocketEventReadable));
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  EXPECT_EQ(total_called, 1);
}

TEST_P(QuicEventLoopFactoryTest, UnregisterSelfInsideEventHandler) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable))
      .WillOnce([&]() { ASSERT_TRUE(loop_->UnregisterSocket(write_fd_)); });
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

// Creates a bidirectional socket and tests its behavior when it's both readable
// and writable.
TEST_P(QuicEventLoopFactoryTest, ReadWriteSocket) {
  int sockets[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
  SetNonBlocking(sockets[0]);
  SetNonBlocking(sockets[1]);

  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_->RegisterSocket(sockets[0], kAllEvents, &listener));
  EXPECT_CALL(listener, OnSocketEvent(_, sockets[0], kSocketEventWritable));
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(4));

  int io_result;
  std::string data(2048, 'a');
  do {
    io_result = write(sockets[0], data.data(), data.size());
  } while (io_result > 0);
  ASSERT_EQ(errno, EAGAIN);

  if (!loop_->SupportsEdgeTriggered()) {
    ASSERT_TRUE(loop_->RearmSocket(sockets[0], kSocketEventWritable));
  }
  // We are not write-blocked, so this should not notify.
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(4));

  EXPECT_GT(write(sockets[1], data.data(), data.size()), 0);
  EXPECT_CALL(listener, OnSocketEvent(_, sockets[0], kSocketEventReadable));
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(4));

  do {
    char buffer[2048];
    io_result = read(sockets[1], buffer, sizeof(buffer));
  } while (io_result > 0);
  ASSERT_EQ(errno, EAGAIN);
  // Here, we can receive either "writable" or "readable and writable"
  // notification depending on the backend in question.
  EXPECT_CALL(listener,
              OnSocketEvent(_, sockets[0], HasFlagSet(kSocketEventWritable)));
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(4));

  EXPECT_TRUE(loop_->UnregisterSocket(sockets[0]));
  close(sockets[0]);
  close(sockets[1]);
}

TEST_P(QuicEventLoopFactoryTest, AlarmInFuture) {
  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm, delegate] = CreateAlarm();

  alarm->Set(clock_.Now() + kAlarmTimeout);

  bool alarm_called = false;
  EXPECT_CALL(*delegate, OnAlarm()).WillOnce([&]() { alarm_called = true; });
  RunEventLoopUntil([&]() { return alarm_called; },
                    QuicTime::Delta::FromMilliseconds(100));
}

TEST_P(QuicEventLoopFactoryTest, AlarmsInPast) {
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
  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
}

TEST_P(QuicEventLoopFactoryTest, AlarmCancelled) {
  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm, delegate] = CreateAlarm();

  alarm->Set(clock_.Now() + kAlarmTimeout);
  alarm->Cancel();

  loop_->RunEventLoopOnce(kAlarmTimeout * 2);
}

TEST_P(QuicEventLoopFactoryTest, AlarmCancelledAndSetAgain) {
  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm, delegate] = CreateAlarm();

  alarm->Set(clock_.Now() + kAlarmTimeout);
  alarm->Cancel();
  alarm->Set(clock_.Now() + 2 * kAlarmTimeout);

  bool alarm_called = false;
  EXPECT_CALL(*delegate, OnAlarm()).WillOnce([&]() { alarm_called = true; });
  RunEventLoopUntil([&]() { return alarm_called; },
                    QuicTime::Delta::FromMilliseconds(100));
}

TEST_P(QuicEventLoopFactoryTest, AlarmCancelsAnotherAlarm) {
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
  // Run event loop twice to ensure the second alarm is not called after two
  // iterations.
  loop_->RunEventLoopOnce(kAlarmTimeout * 2);
  loop_->RunEventLoopOnce(kAlarmTimeout * 2);
  EXPECT_EQ(alarms_called, 1);
}

TEST_P(QuicEventLoopFactoryTest, DestructorWithPendingAlarm) {
  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm1_ptr, delegate1] = CreateAlarm();

  alarm1_ptr->Set(clock_.Now() + kAlarmTimeout);
  // Expect destructor to cleanly unregister itself before the event loop is
  // gone.
}

TEST_P(QuicEventLoopFactoryTest, NegativeTimeout) {
  constexpr auto kAlarmTimeout = QuicTime::Delta::FromSeconds(300);
  auto [alarm1_ptr, delegate1] = CreateAlarm();

  alarm1_ptr->Set(clock_.Now() + kAlarmTimeout);

  loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(-1));
}

TEST_P(QuicEventLoopFactoryTest, ScheduleAlarmInPastFromInsideAlarm) {
  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(20);
  auto [alarm1_ptr, delegate1] = CreateAlarm();
  auto [alarm2_ptr, delegate2] = CreateAlarm();

  alarm1_ptr->Set(clock_.Now() - kAlarmTimeout);
  EXPECT_CALL(*delegate1, OnAlarm())
      .WillOnce([&, alarm2_unowned = alarm2_ptr.get()]() {
        alarm2_unowned->Set(clock_.Now() - 2 * kAlarmTimeout);
      });
  bool fired = false;
  EXPECT_CALL(*delegate2, OnAlarm()).WillOnce([&]() { fired = true; });

  RunEventLoopUntil([&]() { return fired; },
                    QuicTime::Delta::FromMilliseconds(100));
}

}  // namespace
}  // namespace quic::test

"""

```