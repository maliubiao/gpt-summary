Response:
Let's break down the thought process for analyzing this C++ test file for the Chromium networking stack.

**1. Initial Understanding of the Request:**

The core request is to analyze the `net/log/net_log_unittest.cc` file. The analysis should cover its functionality, relationship to JavaScript (if any), logical reasoning (with examples), common usage errors, and how a user's action might lead to this code being executed (as a debugging aid).

**2. Decomposition of the Request and Planning:**

To address all aspects of the request, a structured approach is necessary:

*   **Functionality:**  Read through the code, identify the main classes and functions being tested, and summarize their purpose. Focus on the `NetLog` and related observer classes.
*   **JavaScript Relationship:** This requires knowledge of how Chromium's network stack interacts with the rendering engine (Blink, which handles JavaScript). Look for any obvious signs of interaction or think about the general role of network logging in a browser.
*   **Logical Reasoning:**  Identify specific test cases and analyze the input (setup) and expected output (assertions). Create simplified examples to illustrate the logic.
*   **Common Usage Errors:** Think about how developers might misuse the `NetLog` API based on its design and the tests provided. Look for patterns in the test setup and consider what could go wrong.
*   **User Operation & Debugging:** Connect the low-level logging to high-level user actions. Trace a potential scenario where network logging becomes relevant for debugging.

**3. Detailed Code Analysis (Iterative Process):**

*   **Includes:** Note the included headers (`net/log/net_log.h`, `base/...`, `testing/gtest/...`). These indicate dependencies and the testing framework being used. The `#ifdef UNSAFE_BUFFERS_BUILD` is a conditional compilation directive, likely for specific build configurations. It's worth noting but not central to the core functionality.
*   **Namespaces:**  The code resides in the `net` namespace, which is expected for networking-related code in Chromium.
*   **Constants:**  `kThreads` and `kEvents` suggest the tests involve multithreading and generating multiple log events.
*   **Helper Functions:**  Functions like `CaptureModeToInt`, `CaptureModeToValue`, and `NetCaptureModeParams` are clearly for setting up test data related to `NetLogCaptureMode`.
*   **`BasicGlobalEvents` Test:**  This is the simplest test. It verifies that global events can be added to the `NetLog` and are recorded correctly with timestamps and event types. The assertions check the expected values in the `entries` vector.
*   **`BasicEventsWithSource` Test:** This test introduces `NetLogWithSource`, showing how events can be associated with specific sources (e.g., `URL_REQUEST`, `SOCKET`). The test verifies the source information is correctly recorded along with the event details (begin/end phases).
*   **`CaptureModes` Test:**  This test is crucial for understanding how capture modes affect the data recorded. It iterates through different capture modes and checks if the `capture_mode` parameter is correctly passed to the NetLog callback.
*   **Observer Classes (`CountingObserver`, `LoggingObserver`):** These are custom observers used for testing. `CountingObserver` simply counts events, while `LoggingObserver` stores the logged entries.
*   **Thread-Related Classes (`NetLogTestThread`, `AddEventsTestThread`, `AddRemoveObserverTestThread`):** These classes demonstrate how the `NetLog` works in a multithreaded environment. They test adding events from multiple threads and adding/removing observers concurrently.
*   **`RunTestThreads` Template:** This is a utility function for running multiple threads of a given type.
*   **Multithreading Tests (`NetLogEventThreads`, `NetLogAddRemoveObserver`):** These tests exercise the thread-safety of the `NetLog` implementation.
*   **`NetLogTwoObservers` Test:**  Demonstrates the interaction between multiple observers with different capture modes.
*   **`NetLogEntryToValueEmptyParams` Test:** Checks the serialization behavior when event parameters are empty.

**4. Identifying the JavaScript Connection (and Lack Thereof):**

Review the identified functionalities. The `NetLog` primarily deals with low-level network events. While these events *indirectly* affect JavaScript (e.g., a failed network request will impact a JavaScript application), the `net_log_unittest.cc` itself doesn't contain any direct JavaScript code or interaction with JavaScript APIs. The connection is conceptual and through the broader browser architecture.

**5. Crafting Logical Reasoning Examples:**

For each test case analyzed, create simplified input and output scenarios. Focus on the key aspects being tested. For instance, in `BasicEventsWithSource`, the input is the sequence of `BeginEvent` and `EndEvent` calls, and the output is the expected order and content of the logged entries.

**6. Identifying Common Usage Errors:**

Think about potential mistakes developers might make when using the `NetLog`:

*   Forgetting to add or remove observers, leading to missing logs or memory leaks.
*   Misunderstanding capture modes and not getting the desired level of detail.
*   Incorrectly associating events with sources.

**7. Tracing User Operations and Debugging:**

Consider a common user action like navigating to a website. Connect the dots from this action to the potential involvement of the `NetLog` during debugging. Explain how the recorded logs can help diagnose network issues.

**8. Structuring the Output:**

Organize the analysis into clear sections as requested: Functionality, JavaScript Relation, Logical Reasoning, Common Errors, and User Operations/Debugging. Use code snippets and examples to illustrate the points. Be precise and avoid jargon where possible.

**Self-Correction/Refinement during the Process:**

*   **Initial thought:**  Maybe there's some internal JavaScript testing framework involved.
*   **Correction:**  Upon closer inspection, the tests are purely C++ using Google Test. The interaction with JavaScript is indirect, through the browser's architecture.
*   **Initial thought:** The code directly handles network requests.
*   **Correction:**  The code *logs* network requests and other events. The actual network handling is done elsewhere in the Chromium codebase.
*   **Refinement:**  Provide specific examples in the Logical Reasoning section instead of just general descriptions. Make the Common Usage Errors concrete with scenarios.

By following this iterative process of analysis, decomposition, and refinement, a comprehensive and accurate answer to the request can be generated.
这个文件 `net/log/net_log_unittest.cc` 是 Chromium 网络栈中 `net/log` 组件的单元测试文件。它的主要功能是测试 `net::NetLog` 类的各种功能和行为。

以下是该文件的详细功能列表：

**主要功能:**

1. **测试全局事件记录:**  测试 `NetLog::AddGlobalEntry()` 方法，确保可以记录不属于特定源的全局事件，并验证记录的事件类型、时间戳等信息是否正确。
2. **测试带来源的事件记录:** 测试 `NetLogWithSource` 类以及 `BeginEvent()` 和 `EndEvent()` 方法，确保可以记录与特定源（例如 URL 请求、套接字等）相关的事件，并验证事件的来源信息、阶段（开始/结束）、时间戳等信息是否正确。
3. **测试不同的捕获模式:** 测试 `NetLogCaptureMode` 的不同级别（例如 `kDefault`, `kIncludeSensitive`, `kEverything`）对记录事件参数的影响，确保在不同的捕获模式下，能够正确地记录或省略敏感信息。
4. **测试观察者模式:** 测试 `NetLog` 的观察者模式，包括添加和移除观察者 (`NetLog::AddObserver()`, `NetLog::RemoveObserver()`)，以及观察者接收事件通知的能力。
5. **测试多线程环境下的事件记录:**  创建多个线程并发地向 `NetLog` 添加事件，验证 `NetLog` 在多线程环境下的线程安全性，确保事件能够正确地被记录和分发给所有观察者。
6. **测试添加和移除观察者的并发性:** 创建多个线程并发地添加和移除观察者，验证 `NetLog` 在并发修改观察者列表时的正确性。
7. **测试事件参数的序列化:** 测试 `NetLogEntry::ToDict()` 方法，验证将 `NetLogEntry` 对象序列化为 `base::Value::Dict` 时的行为，特别是对于没有参数的事件。

**与 JavaScript 的关系:**

虽然这个 C++ 测试文件本身不包含 JavaScript 代码，但 `net::NetLog` 组件在 Chromium 中扮演着重要的角色，它可以记录网络请求的各个阶段和相关信息，这些信息对于调试 web 应用的网络问题至关重要。

**举例说明:**

当一个 JavaScript 应用发起一个网络请求（例如使用 `fetch()` API 或 `XMLHttpRequest`）时，Chromium 的网络栈会处理这个请求。在这个过程中，`NetLog` 会记录各种事件，例如：

*   DNS 解析开始和结束
*   建立 TCP 连接
*   发送 HTTP 请求头和数据
*   接收 HTTP 响应头和数据
*   TLS 握手过程

这些被记录的事件可以被导出并用于分析网络性能问题、排查连接错误等。  **Chrome 的开发者工具 (DevTools) 中的 "Network" 面板和 "Network Log" 功能就使用了 `NetLog` 提供的数据。**

因此，虽然这个测试文件是 C++ 代码，但它测试的功能直接支持了开发者在 JavaScript 环境中进行网络调试。

**假设输入与输出 (逻辑推理举例):**

**测试场景:**  测试 `BasicEventsWithSource` 中记录 URL 请求的开始和结束事件。

**假设输入:**

1. 创建一个 `NetLogWithSource` 对象，类型为 `NetLogSourceType::URL_REQUEST`。
2. 调用该对象的 `BeginEvent(NetLogEventType::REQUEST_ALIVE)`。
3. 过一段时间后，调用该对象的 `EndEvent(NetLogEventType::REQUEST_ALIVE)`。

**预期输出 (部分):**

`RecordingNetLogObserver` 应该记录到两个事件：

*   第一个事件:
    *   `type`: `NetLogEventType::REQUEST_ALIVE`
    *   `source.type`: `NetLogSourceType::URL_REQUEST`
    *   `phase`: `NetLogEventPhase::BEGIN`
*   第二个事件:
    *   `type`: `NetLogEventType::REQUEST_ALIVE`
    *   `source.type`: `NetLogSourceType::URL_REQUEST`
    *   `phase`: `NetLogEventPhase::END`
    *   `source.id` 与第一个事件相同

**用户或编程常见的使用错误 (举例说明):**

1. **忘记添加观察者:** 如果用户想要记录网络日志，但忘记将一个 `NetLog::ThreadSafeObserver` 添加到 `NetLog` 中，那么即使有事件发生，也不会被记录下来。

    ```c++
    // 错误示例
    NetLogWithSource source = NetLogWithSource::Make(NetLogSourceType::URL_REQUEST);
    source.BeginEvent(NetLogEventType::REQUEST_START);
    // ... 进行网络操作 ...
    source.EndEvent(NetLogEventType::REQUEST_END);

    // 没有添加观察者，所以日志不会被记录。
    ```

2. **在不合适的时机移除观察者:**  如果观察者在需要记录日志的时间段之前或之中被移除，那么部分或全部的日志信息会丢失。

    ```c++
    RecordingNetLogObserver observer;
    NetLog::Get()->AddObserver(&observer, NetLogCaptureMode::kEverything);

    NetLogWithSource source = NetLogWithSource::Make(NetLogSourceType::URL_REQUEST);
    source.BeginEvent(NetLogEventType::REQUEST_START);

    NetLog::Get()->RemoveObserver(&observer); // 过早移除观察者

    // ... 进行网络操作 ...
    source.EndEvent(NetLogEventType::REQUEST_END);

    // 只有 REQUEST_START 事件可能被记录到， REQUEST_END 不会被记录。
    ```

3. **误解捕获模式:** 用户可能没有选择合适的 `NetLogCaptureMode`，导致敏感信息被意外记录下来，或者需要的详细信息没有被记录。例如，如果选择了 `kDefault` 模式，一些敏感的请求头可能不会被记录。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器时遇到了一个网络问题，例如网页加载缓慢或请求失败。为了调试这个问题，用户可能会：

1. **打开 Chrome 的开发者工具 (DevTools)。**
2. **切换到 "Network" 面板。**
3. **刷新页面或执行导致网络请求的操作。**

在用户执行这些操作的过程中，Chromium 的网络栈会执行相应的代码，包括涉及到 `net::NetLog` 的部分。

**调试线索:**

*   当用户在 "Network" 面板中查看请求的详细信息时，DevTools 会从 `NetLog` 中提取相关的事件数据并展示出来。
*   如果开发者想要更深入地了解网络栈的内部运作，可以使用 `chrome://net-export/` 导出整个网络日志。导出的日志文件包含了 `NetLog` 记录的所有事件，包括与这个测试文件中测试的各种事件类型和来源相关的信息。
*   如果 Chromium 的开发者在排查网络栈自身的 bug，他们可能会运行这个单元测试文件 (`net_log_unittest.cc`) 来验证 `NetLog` 组件的功能是否正常。如果测试失败，就意味着 `NetLog` 的实现存在问题，需要进行修复。

总而言之， `net/log/net_log_unittest.cc` 是一个关键的测试文件，用于确保 Chromium 网络栈的日志记录功能能够正确地工作，这对于网络性能分析、问题排查以及开发者调试都至关重要，并且间接地支持了 JavaScript 开发中的网络调试需求。

### 提示词
```
这是目录为net/log/net_log_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/log/net_log.h"

#include "base/memory/raw_ptr.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/task_environment.h"
#include "base/threading/simple_thread.h"
#include "base/values.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

const int kThreads = 10;
const int kEvents = 100;

int CaptureModeToInt(NetLogCaptureMode capture_mode) {
  return static_cast<int>(capture_mode);
}

base::Value CaptureModeToValue(NetLogCaptureMode capture_mode) {
  return base::Value(CaptureModeToInt(capture_mode));
}

base::Value::Dict NetCaptureModeParams(NetLogCaptureMode capture_mode) {
  base::Value::Dict dict;
  dict.Set("capture_mode", CaptureModeToValue(capture_mode));
  return dict;
}

TEST(NetLogTest, BasicGlobalEvents) {
  base::test::TaskEnvironment task_environment{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  RecordingNetLogObserver net_log_observer;
  auto entries = net_log_observer.GetEntries();
  EXPECT_EQ(0u, entries.size());

  task_environment.FastForwardBy(base::Seconds(1234));
  base::TimeTicks ticks0 = base::TimeTicks::Now();

  NetLog::Get()->AddGlobalEntry(NetLogEventType::CANCELLED);

  task_environment.FastForwardBy(base::Seconds(5678));
  base::TimeTicks ticks1 = base::TimeTicks::Now();
  EXPECT_LE(ticks0, ticks1);

  NetLog::Get()->AddGlobalEntry(NetLogEventType::FAILED);

  task_environment.FastForwardBy(base::Seconds(91011));
  EXPECT_LE(ticks1, base::TimeTicks::Now());

  entries = net_log_observer.GetEntries();
  ASSERT_EQ(2u, entries.size());

  EXPECT_EQ(NetLogEventType::CANCELLED, entries[0].type);
  EXPECT_EQ(NetLogSourceType::NONE, entries[0].source.type);
  EXPECT_NE(NetLogSource::kInvalidId, entries[0].source.id);
  EXPECT_EQ(ticks0, entries[0].source.start_time);
  EXPECT_EQ(NetLogEventPhase::NONE, entries[0].phase);
  EXPECT_EQ(ticks0, entries[0].time);
  EXPECT_FALSE(entries[0].HasParams());

  EXPECT_EQ(NetLogEventType::FAILED, entries[1].type);
  EXPECT_EQ(NetLogSourceType::NONE, entries[1].source.type);
  EXPECT_NE(NetLogSource::kInvalidId, entries[1].source.id);
  EXPECT_LT(entries[0].source.id, entries[1].source.id);
  EXPECT_EQ(ticks1, entries[1].source.start_time);
  EXPECT_EQ(NetLogEventPhase::NONE, entries[1].phase);
  EXPECT_EQ(ticks1, entries[1].time);
  EXPECT_FALSE(entries[1].HasParams());
}

TEST(NetLogTest, BasicEventsWithSource) {
  base::test::TaskEnvironment task_environment{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  RecordingNetLogObserver net_log_observer;
  auto entries = net_log_observer.GetEntries();
  EXPECT_EQ(0u, entries.size());

  task_environment.FastForwardBy(base::Seconds(9876));
  base::TimeTicks source0_start_ticks = base::TimeTicks::Now();

  NetLogWithSource source0 =
      NetLogWithSource::Make(NetLogSourceType::URL_REQUEST);
  task_environment.FastForwardBy(base::Seconds(1));
  base::TimeTicks source0_event0_ticks = base::TimeTicks::Now();
  source0.BeginEvent(NetLogEventType::REQUEST_ALIVE);

  task_environment.FastForwardBy(base::Seconds(5432));
  base::TimeTicks source1_start_ticks = base::TimeTicks::Now();

  NetLogWithSource source1 = NetLogWithSource::Make(NetLogSourceType::SOCKET);
  task_environment.FastForwardBy(base::Seconds(1));
  base::TimeTicks source1_event0_ticks = base::TimeTicks::Now();
  source1.BeginEvent(NetLogEventType::SOCKET_ALIVE);
  task_environment.FastForwardBy(base::Seconds(10));
  base::TimeTicks source1_event1_ticks = base::TimeTicks::Now();
  source1.EndEvent(NetLogEventType::SOCKET_ALIVE);

  task_environment.FastForwardBy(base::Seconds(1));
  base::TimeTicks source0_event1_ticks = base::TimeTicks::Now();
  source0.EndEvent(NetLogEventType::REQUEST_ALIVE);

  task_environment.FastForwardBy(base::Seconds(123));

  entries = net_log_observer.GetEntries();
  ASSERT_EQ(4u, entries.size());

  EXPECT_EQ(NetLogEventType::REQUEST_ALIVE, entries[0].type);
  EXPECT_EQ(NetLogSourceType::URL_REQUEST, entries[0].source.type);
  EXPECT_NE(NetLogSource::kInvalidId, entries[0].source.id);
  EXPECT_EQ(source0_start_ticks, entries[0].source.start_time);
  EXPECT_EQ(NetLogEventPhase::BEGIN, entries[0].phase);
  EXPECT_EQ(source0_event0_ticks, entries[0].time);
  EXPECT_FALSE(entries[0].HasParams());

  EXPECT_EQ(NetLogEventType::SOCKET_ALIVE, entries[1].type);
  EXPECT_EQ(NetLogSourceType::SOCKET, entries[1].source.type);
  EXPECT_NE(NetLogSource::kInvalidId, entries[1].source.id);
  EXPECT_LT(entries[0].source.id, entries[1].source.id);
  EXPECT_EQ(source1_start_ticks, entries[1].source.start_time);
  EXPECT_EQ(NetLogEventPhase::BEGIN, entries[1].phase);
  EXPECT_EQ(source1_event0_ticks, entries[1].time);
  EXPECT_FALSE(entries[1].HasParams());

  EXPECT_EQ(NetLogEventType::SOCKET_ALIVE, entries[2].type);
  EXPECT_EQ(NetLogSourceType::SOCKET, entries[2].source.type);
  EXPECT_EQ(entries[1].source.id, entries[2].source.id);
  EXPECT_EQ(source1_start_ticks, entries[2].source.start_time);
  EXPECT_EQ(NetLogEventPhase::END, entries[2].phase);
  EXPECT_EQ(source1_event1_ticks, entries[2].time);
  EXPECT_FALSE(entries[2].HasParams());

  EXPECT_EQ(NetLogEventType::REQUEST_ALIVE, entries[3].type);
  EXPECT_EQ(NetLogSourceType::URL_REQUEST, entries[3].source.type);
  EXPECT_EQ(entries[0].source.id, entries[3].source.id);
  EXPECT_EQ(source0_start_ticks, entries[3].source.start_time);
  EXPECT_EQ(NetLogEventPhase::END, entries[3].phase);
  EXPECT_EQ(source0_event1_ticks, entries[3].time);
  EXPECT_FALSE(entries[3].HasParams());
}

// Check that the correct CaptureMode is sent to NetLog Value callbacks.
TEST(NetLogTest, CaptureModes) {
  NetLogCaptureMode kModes[] = {
      NetLogCaptureMode::kDefault,
      NetLogCaptureMode::kIncludeSensitive,
      NetLogCaptureMode::kEverything,
  };

  RecordingNetLogObserver net_log_observer;

  for (NetLogCaptureMode mode : kModes) {
    net_log_observer.SetObserverCaptureMode(mode);

    NetLog::Get()->AddGlobalEntry(NetLogEventType::SOCKET_ALIVE,
                                  [&](NetLogCaptureMode capture_mode) {
                                    return NetCaptureModeParams(capture_mode);
                                  });

    auto entries = net_log_observer.GetEntries();

    ASSERT_EQ(1u, entries.size());
    EXPECT_EQ(NetLogEventType::SOCKET_ALIVE, entries[0].type);
    EXPECT_EQ(NetLogSourceType::NONE, entries[0].source.type);
    EXPECT_NE(NetLogSource::kInvalidId, entries[0].source.id);
    EXPECT_GE(base::TimeTicks::Now(), entries[0].source.start_time);
    EXPECT_EQ(NetLogEventPhase::NONE, entries[0].phase);
    EXPECT_GE(base::TimeTicks::Now(), entries[0].time);

    ASSERT_EQ(CaptureModeToInt(mode),
              GetIntegerValueFromParams(entries[0], "capture_mode"));

    net_log_observer.Clear();
  }
}

class CountingObserver : public NetLog::ThreadSafeObserver {
 public:
  CountingObserver() = default;

  ~CountingObserver() override {
    if (net_log())
      net_log()->RemoveObserver(this);
  }

  void OnAddEntry(const NetLogEntry& entry) override { ++count_; }

  int count() const { return count_; }

 private:
  int count_ = 0;
};

class LoggingObserver : public NetLog::ThreadSafeObserver {
 public:
  LoggingObserver() = default;

  ~LoggingObserver() override {
    if (net_log())
      net_log()->RemoveObserver(this);
  }

  void OnAddEntry(const NetLogEntry& entry) override {
    // TODO(crbug.com/40257546): This should be updated to be a
    // base::Value::Dict instead of a std::unique_ptr.
    std::unique_ptr<base::Value::Dict> dict =
        std::make_unique<base::Value::Dict>(entry.ToDict());
    ASSERT_TRUE(dict);
    values_.push_back(std::move(dict));
  }

  size_t GetNumValues() const { return values_.size(); }
  base::Value::Dict* GetDict(size_t index) const {
    return values_[index].get();
  }

 private:
  std::vector<std::unique_ptr<base::Value::Dict>> values_;
};

void AddEvent(NetLog* net_log) {
  net_log->AddGlobalEntry(NetLogEventType::CANCELLED,
                          [&](NetLogCaptureMode capture_mode) {
                            return NetCaptureModeParams(capture_mode);
                          });
}

// A thread that waits until an event has been signalled before calling
// RunTestThread.
class NetLogTestThread : public base::SimpleThread {
 public:
  NetLogTestThread() : base::SimpleThread("NetLogTest") {}

  NetLogTestThread(const NetLogTestThread&) = delete;
  NetLogTestThread& operator=(const NetLogTestThread&) = delete;

  // We'll wait for |start_event| to be triggered before calling a subclass's
  // subclass's RunTestThread() function.
  void Init(NetLog* net_log, base::WaitableEvent* start_event) {
    start_event_ = start_event;
    net_log_ = net_log;
  }

  void Run() override {
    start_event_->Wait();
    RunTestThread();
  }

  // Subclasses must override this with the code they want to run on their
  // thread.
  virtual void RunTestThread() = 0;

 protected:
  raw_ptr<NetLog> net_log_ = nullptr;

 private:
  // Only triggered once all threads have been created, to make it less likely
  // each thread completes before the next one starts.
  raw_ptr<base::WaitableEvent> start_event_ = nullptr;
};

// A thread that adds a bunch of events to the NetLog.
class AddEventsTestThread : public NetLogTestThread {
 public:
  AddEventsTestThread() = default;

  AddEventsTestThread(const AddEventsTestThread&) = delete;
  AddEventsTestThread& operator=(const AddEventsTestThread&) = delete;

  ~AddEventsTestThread() override = default;

 private:
  void RunTestThread() override {
    for (int i = 0; i < kEvents; ++i)
      AddEvent(net_log_);
  }
};

// A thread that adds and removes an observer from the NetLog repeatedly.
class AddRemoveObserverTestThread : public NetLogTestThread {
 public:
  AddRemoveObserverTestThread() = default;

  AddRemoveObserverTestThread(const AddRemoveObserverTestThread&) = delete;
  AddRemoveObserverTestThread& operator=(const AddRemoveObserverTestThread&) =
      delete;

  ~AddRemoveObserverTestThread() override { EXPECT_TRUE(!observer_.net_log()); }

 private:
  void RunTestThread() override {
    for (int i = 0; i < kEvents; ++i) {
      ASSERT_FALSE(observer_.net_log());

      net_log_->AddObserver(&observer_, NetLogCaptureMode::kIncludeSensitive);
      ASSERT_EQ(net_log_, observer_.net_log());
      ASSERT_EQ(NetLogCaptureMode::kIncludeSensitive, observer_.capture_mode());

      net_log_->RemoveObserver(&observer_);
      ASSERT_TRUE(!observer_.net_log());
    }
  }

  CountingObserver observer_;
};

// Creates |kThreads| threads of type |ThreadType| and then runs them all
// to completion.
template <class ThreadType>
void RunTestThreads(NetLog* net_log) {
  // Must outlive `threads`.
  base::WaitableEvent start_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);

  ThreadType threads[kThreads];
  for (size_t i = 0; i < std::size(threads); ++i) {
    threads[i].Init(net_log, &start_event);
    threads[i].Start();
  }

  start_event.Signal();

  for (size_t i = 0; i < std::size(threads); ++i)
    threads[i].Join();
}

// Makes sure that events on multiple threads are dispatched to all observers.
TEST(NetLogTest, NetLogEventThreads) {
  // Attach some observers.  They'll safely detach themselves on destruction.
  CountingObserver observers[3];
  for (auto& observer : observers) {
    NetLog::Get()->AddObserver(&observer, NetLogCaptureMode::kEverything);
  }

  // Run a bunch of threads to completion, each of which will emit events to
  // |net_log|.
  RunTestThreads<AddEventsTestThread>(NetLog::Get());

  // Check that each observer saw the emitted events.
  const int kTotalEvents = kThreads * kEvents;
  for (const auto& observer : observers)
    EXPECT_EQ(kTotalEvents, observer.count());
}

// Test adding and removing a single observer.
TEST(NetLogTest, NetLogAddRemoveObserver) {
  CountingObserver observer;

  AddEvent(NetLog::Get());
  EXPECT_EQ(0, observer.count());
  EXPECT_EQ(nullptr, observer.net_log());
  EXPECT_FALSE(NetLog::Get()->IsCapturing());

  // Add the observer and add an event.
  NetLog::Get()->AddObserver(&observer, NetLogCaptureMode::kIncludeSensitive);
  EXPECT_TRUE(NetLog::Get()->IsCapturing());
  EXPECT_EQ(NetLog::Get(), observer.net_log());
  EXPECT_EQ(NetLogCaptureMode::kIncludeSensitive, observer.capture_mode());
  EXPECT_TRUE(NetLog::Get()->IsCapturing());

  AddEvent(NetLog::Get());
  EXPECT_EQ(1, observer.count());

  AddEvent(NetLog::Get());
  EXPECT_EQ(2, observer.count());

  // Remove observer and add an event.
  NetLog::Get()->RemoveObserver(&observer);
  EXPECT_EQ(nullptr, observer.net_log());
  EXPECT_FALSE(NetLog::Get()->IsCapturing());

  AddEvent(NetLog::Get());
  EXPECT_EQ(2, observer.count());

  // Add the observer a final time, this time with a different capture mdoe, and
  // add an event.
  NetLog::Get()->AddObserver(&observer, NetLogCaptureMode::kEverything);
  EXPECT_EQ(NetLog::Get(), observer.net_log());
  EXPECT_EQ(NetLogCaptureMode::kEverything, observer.capture_mode());
  EXPECT_TRUE(NetLog::Get()->IsCapturing());

  AddEvent(NetLog::Get());
  EXPECT_EQ(3, observer.count());
}

// Test adding and removing two observers at different log levels.
TEST(NetLogTest, NetLogTwoObservers) {
  LoggingObserver observer[2];

  // Add first observer.
  NetLog::Get()->AddObserver(&observer[0],
                             NetLogCaptureMode::kIncludeSensitive);
  EXPECT_EQ(NetLog::Get(), observer[0].net_log());
  EXPECT_EQ(nullptr, observer[1].net_log());
  EXPECT_EQ(NetLogCaptureMode::kIncludeSensitive, observer[0].capture_mode());
  EXPECT_TRUE(NetLog::Get()->IsCapturing());

  // Add second observer observer.
  NetLog::Get()->AddObserver(&observer[1], NetLogCaptureMode::kEverything);
  EXPECT_EQ(NetLog::Get(), observer[0].net_log());
  EXPECT_EQ(NetLog::Get(), observer[1].net_log());
  EXPECT_EQ(NetLogCaptureMode::kIncludeSensitive, observer[0].capture_mode());
  EXPECT_EQ(NetLogCaptureMode::kEverything, observer[1].capture_mode());
  EXPECT_TRUE(NetLog::Get()->IsCapturing());

  // Add event and make sure both observers receive it at their respective log
  // levels.
  std::optional<int> param;
  AddEvent(NetLog::Get());
  ASSERT_EQ(1U, observer[0].GetNumValues());
  param = observer[0].GetDict(0)->FindDict("params")->FindInt("capture_mode");
  ASSERT_TRUE(param);
  EXPECT_EQ(CaptureModeToInt(observer[0].capture_mode()), param.value());
  ASSERT_EQ(1U, observer[1].GetNumValues());
  param = observer[1].GetDict(0)->FindDict("params")->FindInt("capture_mode");
  ASSERT_TRUE(param);
  EXPECT_EQ(CaptureModeToInt(observer[1].capture_mode()), param.value());

  // Remove second observer.
  NetLog::Get()->RemoveObserver(&observer[1]);
  EXPECT_EQ(NetLog::Get(), observer[0].net_log());
  EXPECT_EQ(nullptr, observer[1].net_log());
  EXPECT_EQ(NetLogCaptureMode::kIncludeSensitive, observer[0].capture_mode());
  EXPECT_TRUE(NetLog::Get()->IsCapturing());

  // Add event and make sure only second observer gets it.
  AddEvent(NetLog::Get());
  EXPECT_EQ(2U, observer[0].GetNumValues());
  EXPECT_EQ(1U, observer[1].GetNumValues());

  // Remove first observer.
  NetLog::Get()->RemoveObserver(&observer[0]);
  EXPECT_EQ(nullptr, observer[0].net_log());
  EXPECT_EQ(nullptr, observer[1].net_log());
  EXPECT_FALSE(NetLog::Get()->IsCapturing());

  // Add event and make sure neither observer gets it.
  AddEvent(NetLog::Get());
  EXPECT_EQ(2U, observer[0].GetNumValues());
  EXPECT_EQ(1U, observer[1].GetNumValues());
}

// Makes sure that adding and removing observers simultaneously on different
// threads works.
TEST(NetLogTest, NetLogAddRemoveObserverThreads) {
  // Run a bunch of threads to completion, each of which will repeatedly add
  // and remove an observer, and set its logging level.
  RunTestThreads<AddRemoveObserverTestThread>(NetLog::Get());
}

// Tests that serializing a NetLogEntry with empty parameters omits a value for
// "params".
TEST(NetLogTest, NetLogEntryToValueEmptyParams) {
  // NetLogEntry with no params.
  NetLogEntry entry1(NetLogEventType::REQUEST_ALIVE, NetLogSource(),
                     NetLogEventPhase::BEGIN, base::TimeTicks(),
                     base::Value::Dict());

  ASSERT_TRUE(entry1.params.empty());
  ASSERT_FALSE(entry1.ToDict().Find("params"));
}

}  // namespace

}  // namespace net
```