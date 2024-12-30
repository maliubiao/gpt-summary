Response:
My thought process to analyze the C++ code and generate the comprehensive response involved several steps:

1. **Understand the Goal:** The request asks for a functional description of a C++ test file (`window_manager_test.cc`), its relationship to JavaScript (unlikely but needs consideration), examples of logical reasoning with input/output, common usage errors, and debugging guidance.

2. **Initial Code Scan (High-Level):** I first skimmed the code to identify the main components:
    * Includes: `window_manager.h`, standard library headers, and Quiche-specific testing tools. This immediately suggests the file tests `WindowManager`.
    * Namespace Structure:  `http2::adapter::test`. This confirms it's a unit test within the HTTP/2 adapter component of the Quiche library.
    * Test Fixture: `WindowManagerTest` inheriting from `quiche::test::QuicheTest`. This is the standard way to structure tests in this framework.
    * Test Methods:  Functions starting with `TEST_F` or `TEST`. These are the individual test cases.
    * Helper Class: `WindowManagerPeer`. This is used for accessing private members of `WindowManager`, which is common in testing to verify internal state.

3. **Focus on `WindowManager`'s Role:** The core of the tests revolves around the `WindowManager` class. Based on the names of the test methods (e.g., `DataOnlyBuffered`, `DataBufferedAndFlushed`, `AvoidWindowUnderflow`), I deduced that `WindowManager` is responsible for managing flow control windows in an HTTP/2 connection. Key concepts likely include:
    * Window Size Limit: The maximum amount of data that can be sent without receiving a `WINDOW_UPDATE` frame.
    * Buffered Data: Data that has been prepared to send but not yet flushed.
    * Flushed Data: Data that has been sent.
    * Window Consumption:  Data received by the peer.
    * Notifications: Informing a listener when the window state changes (allowing more data to be sent).

4. **Analyze Individual Test Cases:** I then went through each `TEST_F` and `TEST` method, understanding what specific aspect of `WindowManager` it was testing:
    * **NoOps:** Basic checks that certain calls without data transfer don't trigger notifications.
    * **DataOnlyBuffered/DataBufferedAndFlushed:**  Verifying notifications based on buffering and flushing data.
    * **AvoidWindowUnderflow/AvoidBufferedUnderflow:** Testing for error handling when trying to buffer or flush more data than allowed. The use of `EXPECT_QUICHE_BUG` is a strong indicator of expected error conditions.
    * **WindowConsumed:** Testing notifications when the receiving end consumes data.
    * **ListenerCalledOnSizeUpdate:**  Testing notifications when the window size limit is changed.
    * **WindowUpdateAfterLimitDecreased:**  Testing how the window manager handles a shrinking window size limit.
    * **ZeroWindowNotification:**  Ensuring notifications are sent even when the window reaches zero.
    * **OnWindowSizeLimitChange/NegativeWindowSize/IncreaseWindow:** Testing specific methods for modifying the window size and how buffered data affects these changes.
    * **WindowManagerNoUpdateTest/WindowManagerShouldUpdateTest:** Testing constructor options that modify the notification behavior. These tests highlight customization points in the `WindowManager`.

5. **Identify Key Methods and Their Behavior:**  Based on the test cases, I identified the primary methods of `WindowManager` being tested:
    * `SetWindowSizeLimit()`:  Sets the maximum window size.
    * `MarkDataBuffered()`:  Indicates data has been buffered for sending.
    * `MarkDataFlushed()`: Indicates data has been sent.
    * `MarkWindowConsumed()`: Indicates the receiving end has consumed data.
    * `CurrentWindowSize()`: Returns the current available window size.
    * `WindowSizeLimit()`: Returns the current window size limit.
    * `OnWindowSizeLimitChange()`: Handles updates to the window size limit from the peer.
    * `IncreaseWindow()`:  Explicitly increases the send window.

6. **Address the JavaScript Question:** I explicitly addressed the low likelihood of a direct connection to JavaScript, explaining that this is low-level network code. However, I pointed out the indirect relationship via web browsers and network requests.

7. **Generate Examples (Logical Reasoning):**  For each key method, I created simple "if-then" scenarios with hypothetical inputs and outputs to illustrate the logic. I focused on scenarios that demonstrated the core functionality.

8. **Identify Common Usage Errors:**  By looking at the `EXPECT_QUICHE_BUG` tests, I directly identified the "buffered underflow" error. I generalized this to include other potential mistakes like setting incorrect limits or mismanaging buffered data.

9. **Explain Debugging:**  I described how a developer might arrive at this test file during debugging, focusing on scenarios related to flow control issues in an HTTP/2 implementation. I emphasized the value of the tests themselves as debugging tools.

10. **Structure the Response:** Finally, I organized the information logically with clear headings and bullet points for readability. I started with a general overview, then went into specifics for each aspect of the request. I made sure to address all parts of the prompt.

Throughout this process, I focused on extracting the essential information about the `WindowManager`'s function and how the test file verifies its behavior. I prioritized clarity and provided concrete examples to illustrate the concepts.
这个文件 `net/third_party/quiche/src/quiche/http2/adapter/window_manager_test.cc` 是 Chromium 网络栈中 QUICHE 库的一部分，专门用于测试 `WindowManager` 类的功能。`WindowManager` 类负责管理 HTTP/2 连接的流量控制窗口。

以下是该文件的功能列表：

**核心功能：测试 `WindowManager` 类的各种行为和逻辑**

* **初始化和基本操作测试:** 测试 `WindowManager` 的初始化状态、设置窗口大小限制 (`SetWindowSizeLimit`) 等基本操作是否正确。
* **数据缓冲和刷新测试:**
    * 测试当数据被缓冲 (`MarkDataBuffered`) 但未刷新时，`WindowManager` 是否不会通知监听器。
    * 测试当数据被缓冲并随后刷新 (`MarkDataFlushed`) 时，`WindowManager` 是否会正确地通知监听器。
    * 验证只有在消耗了一定比例的窗口后，才会触发通知。
* **防止窗口下溢和缓冲下溢测试:**
    * 测试 `WindowManager` 是否能正确防止窗口下溢（尝试缓冲超过窗口大小的数据）。
    * 测试 `WindowManager` 是否能正确防止缓冲下溢（尝试刷新比已缓冲数据更多的数据），并使用 `EXPECT_QUICHE_BUG` 宏来断言这种情况会触发错误。
* **窗口消耗测试:** 测试当窗口被消耗 (`MarkWindowConsumed`) 时，`WindowManager` 是否会通知监听器。
* **窗口大小更新测试:** 测试当窗口大小限制被更新 (`SetWindowSizeLimit`) 时，`WindowManager` 是否会通知监听器，并验证通知的值是否正确。
* **限制减小后的窗口更新测试:** 测试当窗口大小限制减小时，`WindowManager` 如何以及何时通知监听器。只有在超出新限制的窗口被消耗后才会触发。
* **零窗口通知测试:** 测试即使没有数据刷新，当窗口完全被消耗时，`WindowManager` 仍然会通知监听器，以避免人为阻塞。
* **`OnWindowSizeLimitChange` 测试:** 测试当接收到来自对端的窗口大小更新时 (`OnWindowSizeLimitChange`)，`WindowManager` 如何更新其内部状态。
* **负窗口大小测试:** 测试在窗口大小变为负数的情况下，`WindowManager` 的行为，例如在窗口大小减小后，已缓冲的数据可能导致负窗口。
* **增加窗口大小测试:** 测试 `IncreaseWindow` 方法，允许在当前限制之外增加窗口大小，并测试后续的窗口消耗如何触发通知。
* **自定义通知行为测试:**
    * 测试在构造 `WindowManager` 时，可以指定是否在通知监听器时更新内部窗口状态。
    * 测试可以提供自定义的函数 (`ShouldWindowUpdateFn`) 来决定何时通知监听器，从而实现更灵活的通知策略。

**与 Javascript 的关系：**

这个 C++ 文件本身与 Javascript 没有直接的功能关系。`WindowManager` 是一个底层的网络流量控制组件，运行在服务器或客户端的网络协议栈中。Javascript 主要用于前端开发，处理用户交互和页面逻辑。

然而，它们之间存在间接关系：

* **网络请求:** 当 Javascript 代码（例如在浏览器中运行的 Web 应用）发起 HTTP/2 请求时，底层的网络栈（包括 `WindowManager`）会参与到请求的处理过程中。`WindowManager` 确保数据以符合流量控制规则的方式发送和接收。
* **浏览器实现:** 浏览器的网络模块是用 C++ 等语言实现的，因此浏览器的 HTTP/2 支持会用到类似 `WindowManager` 的组件。当 Javascript 发起网络请求时，最终会调用到这些底层的 C++ 代码。

**举例说明（间接关系）：**

假设一个 Javascript Web 应用需要从服务器下载一个大文件：

1. **Javascript 发起请求:** Javascript 代码使用 `fetch` API 或 `XMLHttpRequest` 对象向服务器发起 HTTP/2 GET 请求。
2. **浏览器处理请求:** 浏览器接收到 Javascript 的请求，并将其传递给其底层的网络模块。
3. **`WindowManager` 的作用:** 在建立 HTTP/2 连接后，发送端（可能是服务器）的 `WindowManager` 会根据其窗口大小限制来控制发送数据的速率。 接收端（浏览器）的 `WindowManager` 会管理其接收窗口，并可能发送 `WINDOW_UPDATE` 帧来告知发送端可以发送更多数据。
4. **数据传输:** 数据以符合流量控制规则的数据帧的形式在网络上传输。
5. **Javascript 接收数据:** 浏览器接收到数据后，将其传递给 Javascript 代码。

在这个过程中，虽然 Javascript 代码没有直接调用 `WindowManager` 的代码，但 `WindowManager` 的功能确保了网络连接的稳定和效率。

**逻辑推理举例（假设输入与输出）：**

假设 `kDefaultLimit` 为 3072 (3 * 1024)。

**场景 1：数据缓冲和刷新**

* **假设输入:**
    * `wm_.MarkDataBuffered(1024)`
    * `wm_.MarkDataBuffered(1024)`
    * `wm_.MarkDataFlushed(512)`
    * `wm_.MarkDataFlushed(1536)`
* **预期输出:** `call_sequence_` 最终包含一个元素，值为 2048 (1024 + 1024)，因为当刷新了超过窗口大小限制三分之一的数据时会触发通知。

**场景 2：窗口消耗**

* **假设输入:**
    * `wm_.MarkWindowConsumed(512)`
    * `wm_.MarkWindowConsumed(513)`
* **预期输出:** `call_sequence_` 最终包含一个元素，值为 1025 (512 + 513)，因为当消耗的窗口大小超过限制的三分之一时会触发通知。

**用户或编程常见的使用错误举例：**

1. **刷新超过缓冲的数据:** 开发者错误地调用 `MarkDataFlushed` 并传入一个大于当前已缓冲的值。`WindowManager` 会通过 `EXPECT_QUICHE_BUG` 宏捕获这种错误，表明这是一个编程错误，不应该发生。例如：
   ```c++
   wm_.MarkDataBuffered(100);
   wm_.MarkDataFlushed(200); // 错误：尝试刷新 200，但只缓冲了 100
   ```
2. **在高流量下未及时更新窗口:**  如果接收端没有及时发送 `WINDOW_UPDATE` 帧，发送端的 `WindowManager` 可能会因为窗口耗尽而停止发送数据，导致连接停顿。这通常不是 `WindowManager` 本身的错误，而是协议层面的问题。

**用户操作如何一步步到达这里（作为调试线索）：**

假设用户在使用 Chrome 浏览器访问一个网站时遇到了下载速度缓慢的问题。作为一名 Chromium 开发者，你可能会进行以下调试步骤：

1. **怀疑网络层问题:**  下载速度慢可能与网络拥塞、服务器性能或客户端的网络配置有关。但也有可能是 HTTP/2 的流量控制机制出现了问题。
2. **查看 QUICHE 日志:**  QUICHE 库会产生详细的日志，可以查看是否有与流量控制相关的异常或警告。
3. **检查 `WindowManager` 的状态:**  如果日志显示可能与窗口大小或缓冲有关的问题，你可能会想了解 `WindowManager` 的内部状态。
4. **阅读 `window_manager_test.cc`:**  为了理解 `WindowManager` 的正常行为和预期逻辑，你会查看其单元测试文件。这个文件包含了各种测试用例，可以帮助你了解 `WindowManager` 的功能和边界条件。
5. **运行相关的测试:**  你可以运行 `window_manager_test.cc` 中的特定测试用例，以验证 `WindowManager` 在特定场景下的行为是否符合预期。
6. **使用断点调试:**  如果测试未能重现问题，你可能会在 `WindowManager` 的代码中设置断点，并逐步执行浏览器处理网络请求的代码，以观察窗口大小、缓冲数据和刷新过程中的变量值。
7. **分析核心方法:** 你可能会特别关注 `MarkDataBuffered`、`MarkDataFlushed`、`MarkWindowConsumed` 和 `OnWindowSizeLimitChange` 等方法，以及监听器的回调是否被正确触发。

通过阅读和运行 `window_manager_test.cc` 中的测试，开发者可以更好地理解 `WindowManager` 的工作原理，并将其作为调试复杂网络问题的起点。这些测试用例覆盖了 `WindowManager` 的关键功能，有助于验证其在各种场景下的正确性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/window_manager_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "quiche/http2/adapter/window_manager.h"

#include <algorithm>
#include <list>

#include "absl/functional/bind_front.h"
#include "quiche/http2/test_tools/http2_random.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {

// Use the peer to access private vars of WindowManager.
class WindowManagerPeer {
 public:
  explicit WindowManagerPeer(const WindowManager& wm) : wm_(wm) {}

  int64_t buffered() { return wm_.buffered_; }

 private:
  const WindowManager& wm_;
};

namespace {

class WindowManagerTest : public quiche::test::QuicheTest {
 protected:
  WindowManagerTest()
      : wm_(kDefaultLimit, absl::bind_front(&WindowManagerTest::OnCall, this)),
        peer_(wm_) {}

  void OnCall(int64_t s) { call_sequence_.push_back(s); }

  const int64_t kDefaultLimit = 32 * 1024 * 3;
  std::list<int64_t> call_sequence_;
  WindowManager wm_;
  WindowManagerPeer peer_;
  ::http2::test::Http2Random random_;
};

// A few no-op calls.
TEST_F(WindowManagerTest, NoOps) {
  wm_.SetWindowSizeLimit(kDefaultLimit);
  wm_.SetWindowSizeLimit(0);
  wm_.SetWindowSizeLimit(kDefaultLimit);
  wm_.MarkDataBuffered(0);
  wm_.MarkDataFlushed(0);
  EXPECT_TRUE(call_sequence_.empty());
}

// This test verifies that WindowManager does not notify its listener when data
// is only buffered, and never flushed.
TEST_F(WindowManagerTest, DataOnlyBuffered) {
  int64_t total = 0;
  while (total < kDefaultLimit) {
    int64_t s = std::min<int64_t>(kDefaultLimit - total, random_.Uniform(1024));
    total += s;
    wm_.MarkDataBuffered(s);
  }
  EXPECT_THAT(call_sequence_, ::testing::IsEmpty());
}

// This test verifies that WindowManager does notify its listener when data is
// buffered and subsequently flushed.
TEST_F(WindowManagerTest, DataBufferedAndFlushed) {
  int64_t total_buffered = 0;
  int64_t total_flushed = 0;
  while (call_sequence_.empty()) {
    int64_t buffered = std::min<int64_t>(kDefaultLimit - total_buffered,
                                         random_.Uniform(1024));
    wm_.MarkDataBuffered(buffered);
    total_buffered += buffered;
    EXPECT_TRUE(call_sequence_.empty());
    int64_t flushed = (total_buffered - total_flushed) > 0
                          ? random_.Uniform(total_buffered - total_flushed)
                          : 0;
    wm_.MarkDataFlushed(flushed);
    total_flushed += flushed;
  }
  // If WindowManager decided to send an update, at least one third of the
  // window must have been consumed by buffered data.
  EXPECT_GE(total_buffered, kDefaultLimit / 3);
}

// Window manager should avoid window underflow.
TEST_F(WindowManagerTest, AvoidWindowUnderflow) {
  EXPECT_EQ(wm_.CurrentWindowSize(), wm_.WindowSizeLimit());
  // Don't buffer more than the total window!
  wm_.MarkDataBuffered(wm_.WindowSizeLimit() + 1);
  EXPECT_EQ(wm_.CurrentWindowSize(), 0u);
}

// Window manager should GFE_BUG and avoid buffered underflow.
TEST_F(WindowManagerTest, AvoidBufferedUnderflow) {
  EXPECT_EQ(peer_.buffered(), 0u);
  // Don't flush more than has been buffered!
  EXPECT_QUICHE_BUG(wm_.MarkDataFlushed(1), "buffered underflow");
  EXPECT_EQ(peer_.buffered(), 0u);

  wm_.MarkDataBuffered(42);
  EXPECT_EQ(peer_.buffered(), 42u);
  // Don't flush more than has been buffered!
  EXPECT_QUICHE_BUG(
      {
        wm_.MarkDataFlushed(43);
        EXPECT_EQ(peer_.buffered(), 0u);
      },
      "buffered underflow");
}

// This test verifies that WindowManager notifies its listener when window is
// consumed (data is ignored or immediately dropped).
TEST_F(WindowManagerTest, WindowConsumed) {
  int64_t consumed = kDefaultLimit / 3 - 1;
  wm_.MarkWindowConsumed(consumed);
  EXPECT_TRUE(call_sequence_.empty());
  const int64_t extra = 1;
  wm_.MarkWindowConsumed(extra);
  EXPECT_THAT(call_sequence_, testing::ElementsAre(consumed + extra));
}

// This test verifies that WindowManager notifies its listener when the window
// size limit is increased.
TEST_F(WindowManagerTest, ListenerCalledOnSizeUpdate) {
  wm_.SetWindowSizeLimit(kDefaultLimit - 1024);
  EXPECT_TRUE(call_sequence_.empty());
  wm_.SetWindowSizeLimit(kDefaultLimit * 5);
  // Because max(outstanding window, previous limit) is kDefaultLimit, it is
  // only appropriate to increase the window by kDefaultLimit * 4.
  EXPECT_THAT(call_sequence_, testing::ElementsAre(kDefaultLimit * 4));
}

// This test verifies that when data is buffered and then the limit is
// decreased, WindowManager only notifies the listener once any outstanding
// window has been consumed.
TEST_F(WindowManagerTest, WindowUpdateAfterLimitDecreased) {
  wm_.MarkDataBuffered(kDefaultLimit - 1024);
  wm_.SetWindowSizeLimit(kDefaultLimit - 2048);

  // Now there are 2048 bytes of window outstanding beyond the current limit,
  // and we have 1024 bytes of data buffered beyond the current limit. This is
  // intentional, to be sure that WindowManager works properly if the limit is
  // decreased at runtime.

  wm_.MarkDataFlushed(512);
  EXPECT_TRUE(call_sequence_.empty());
  wm_.MarkDataFlushed(512);
  EXPECT_TRUE(call_sequence_.empty());
  wm_.MarkDataFlushed(512);
  EXPECT_TRUE(call_sequence_.empty());
  wm_.MarkDataFlushed(1024);
  EXPECT_THAT(call_sequence_, testing::ElementsAre(512));
}

// For normal behavior, we only call MaybeNotifyListener() when data is
// flushed. But if window runs out entirely, we still need to call
// MaybeNotifyListener() to avoid becoming artificially blocked when data isn't
// being flushed.
TEST_F(WindowManagerTest, ZeroWindowNotification) {
  // Consume a byte of window, but not enough to trigger an update.
  wm_.MarkWindowConsumed(1);

  // Buffer the remaining window.
  wm_.MarkDataBuffered(kDefaultLimit - 1);
  // Listener is notified of the remaining byte of possible window.
  EXPECT_THAT(call_sequence_, testing::ElementsAre(1));
}

TEST_F(WindowManagerTest, OnWindowSizeLimitChange) {
  wm_.MarkDataBuffered(10000);
  EXPECT_EQ(wm_.CurrentWindowSize(), kDefaultLimit - 10000);
  EXPECT_EQ(wm_.WindowSizeLimit(), kDefaultLimit);

  wm_.OnWindowSizeLimitChange(kDefaultLimit + 1000);
  EXPECT_EQ(wm_.CurrentWindowSize(), kDefaultLimit - 9000);
  EXPECT_EQ(wm_.WindowSizeLimit(), kDefaultLimit + 1000);

  wm_.OnWindowSizeLimitChange(kDefaultLimit - 1000);
  EXPECT_EQ(wm_.CurrentWindowSize(), kDefaultLimit - 11000);
  EXPECT_EQ(wm_.WindowSizeLimit(), kDefaultLimit - 1000);
}

TEST_F(WindowManagerTest, NegativeWindowSize) {
  wm_.MarkDataBuffered(80000);
  // 98304 window - 80000 buffered = 18304 available
  EXPECT_EQ(wm_.CurrentWindowSize(), 18304);
  wm_.OnWindowSizeLimitChange(65535);
  // limit decreases by 98304 - 65535 = 32769, window becomes -14465
  EXPECT_EQ(wm_.CurrentWindowSize(), -14465);
  wm_.MarkDataFlushed(70000);
  // Still 10000 bytes buffered, so window manager grants sufficient quota to
  // reach a window of 65535 - 10000.
  EXPECT_EQ(wm_.CurrentWindowSize(), 55535);
  // Desired window minus existing window: 55535 - (-14465) = 70000
  EXPECT_THAT(call_sequence_, testing::ElementsAre(70000));
}

TEST_F(WindowManagerTest, IncreaseWindow) {
  wm_.MarkDataBuffered(1000);
  EXPECT_EQ(wm_.CurrentWindowSize(), kDefaultLimit - 1000);
  EXPECT_EQ(wm_.WindowSizeLimit(), kDefaultLimit);

  // Increasing the window beyond the limit is allowed.
  wm_.IncreaseWindow(5000);
  EXPECT_EQ(wm_.CurrentWindowSize(), kDefaultLimit + 4000);
  EXPECT_EQ(wm_.WindowSizeLimit(), kDefaultLimit);

  // 80000 bytes are buffered, then flushed.
  wm_.MarkWindowConsumed(80000);
  // The window manager replenishes the consumed quota up to the limit.
  EXPECT_THAT(call_sequence_, testing::ElementsAre(75000));
  // The window is the limit, minus buffered data, as expected.
  EXPECT_EQ(wm_.CurrentWindowSize(), kDefaultLimit - 1000);
}

// This test verifies that when the constructor option is specified,
// WindowManager does not update its internal accounting of the flow control
// window when notifying the listener.
TEST(WindowManagerNoUpdateTest, NoWindowUpdateOnListener) {
  const int64_t kDefaultLimit = 65535;

  std::list<int64_t> call_sequence1;
  WindowManager wm1(
      kDefaultLimit,
      [&call_sequence1](int64_t delta) { call_sequence1.push_back(delta); },
      /*should_notify_listener=*/{},
      /*update_window_on_notify=*/true);  // default
  std::list<int64_t> call_sequence2;
  WindowManager wm2(
      kDefaultLimit,
      [&call_sequence2](int64_t delta) { call_sequence2.push_back(delta); },
      /*should_notify_listener=*/{},
      /*update_window_on_notify=*/false);

  const int64_t consumed = kDefaultLimit / 3 - 1;

  wm1.MarkWindowConsumed(consumed);
  EXPECT_TRUE(call_sequence1.empty());
  wm2.MarkWindowConsumed(consumed);
  EXPECT_TRUE(call_sequence2.empty());

  EXPECT_EQ(wm1.CurrentWindowSize(), kDefaultLimit - consumed);
  EXPECT_EQ(wm2.CurrentWindowSize(), kDefaultLimit - consumed);

  const int64_t extra = 1;
  wm1.MarkWindowConsumed(extra);
  EXPECT_THAT(call_sequence1, testing::ElementsAre(consumed + extra));
  // Window size *is* updated after invoking the listener.
  EXPECT_EQ(wm1.CurrentWindowSize(), kDefaultLimit);
  call_sequence1.clear();

  wm2.MarkWindowConsumed(extra);
  EXPECT_THAT(call_sequence2, testing::ElementsAre(consumed + extra));
  // Window size is *not* updated after invoking the listener.
  EXPECT_EQ(wm2.CurrentWindowSize(), kDefaultLimit - (consumed + extra));
  call_sequence2.clear();

  // Manually increase the window by the listener notification amount.
  wm2.IncreaseWindow(consumed + extra);
  EXPECT_EQ(wm2.CurrentWindowSize(), kDefaultLimit);

  wm1.SetWindowSizeLimit(kDefaultLimit * 5);
  EXPECT_THAT(call_sequence1, testing::ElementsAre(kDefaultLimit * 4));
  // *Does* update the window size.
  EXPECT_EQ(wm1.CurrentWindowSize(), kDefaultLimit * 5);

  wm2.SetWindowSizeLimit(kDefaultLimit * 5);
  EXPECT_THAT(call_sequence2, testing::ElementsAre(kDefaultLimit * 4));
  // Does *not* update the window size.
  EXPECT_EQ(wm2.CurrentWindowSize(), kDefaultLimit);
}

// This test verifies that when the constructor option is specified,
// WindowManager uses the provided ShouldWindowUpdateFn to determine when to
// notify the listener.
TEST(WindowManagerShouldUpdateTest, CustomShouldWindowUpdateFn) {
  const int64_t kDefaultLimit = 65535;

  // This window manager should always notify.
  std::list<int64_t> call_sequence1;
  WindowManager wm1(
      kDefaultLimit,
      [&call_sequence1](int64_t delta) { call_sequence1.push_back(delta); },
      [](int64_t /*limit*/, int64_t /*window*/, int64_t /*delta*/) {
        return true;
      });
  // This window manager should never notify.
  std::list<int64_t> call_sequence2;
  WindowManager wm2(
      kDefaultLimit,
      [&call_sequence2](int64_t delta) { call_sequence2.push_back(delta); },
      [](int64_t /*limit*/, int64_t /*window*/, int64_t /*delta*/) {
        return false;
      });
  // This window manager should notify as long as no data is buffered.
  std::list<int64_t> call_sequence3;
  WindowManager wm3(
      kDefaultLimit,
      [&call_sequence3](int64_t delta) { call_sequence3.push_back(delta); },
      [](int64_t limit, int64_t window, int64_t delta) {
        return delta == limit - window;
      });

  const int64_t consumed = kDefaultLimit / 4;

  wm1.MarkWindowConsumed(consumed);
  EXPECT_THAT(call_sequence1, testing::ElementsAre(consumed));
  wm2.MarkWindowConsumed(consumed);
  EXPECT_TRUE(call_sequence2.empty());
  wm3.MarkWindowConsumed(consumed);
  EXPECT_THAT(call_sequence3, testing::ElementsAre(consumed));

  const int64_t buffered = 42;

  wm1.MarkDataBuffered(buffered);
  EXPECT_THAT(call_sequence1, testing::ElementsAre(consumed));
  wm2.MarkDataBuffered(buffered);
  EXPECT_TRUE(call_sequence2.empty());
  wm3.MarkDataBuffered(buffered);
  EXPECT_THAT(call_sequence3, testing::ElementsAre(consumed));

  wm1.MarkDataFlushed(buffered / 3);
  EXPECT_THAT(call_sequence1, testing::ElementsAre(consumed, buffered / 3));
  wm2.MarkDataFlushed(buffered / 3);
  EXPECT_TRUE(call_sequence2.empty());
  wm3.MarkDataFlushed(buffered / 3);
  EXPECT_THAT(call_sequence3, testing::ElementsAre(consumed));

  wm1.MarkDataFlushed(2 * buffered / 3);
  EXPECT_THAT(call_sequence1,
              testing::ElementsAre(consumed, buffered / 3, 2 * buffered / 3));
  wm2.MarkDataFlushed(2 * buffered / 3);
  EXPECT_TRUE(call_sequence2.empty());
  wm3.MarkDataFlushed(2 * buffered / 3);
  EXPECT_THAT(call_sequence3, testing::ElementsAre(consumed, buffered));
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2

"""

```