Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The filename `web_transport_write_blocked_list_test.cc` and the `#include "quiche/quic/core/web_transport_write_blocked_list.h"` immediately tell us the subject is the `WebTransportWriteBlockedList` class. The `_test.cc` suffix signifies this is a unit test file.

2. **Understand the Purpose of Unit Tests:**  Unit tests are designed to verify the functionality of a specific component (the "unit") in isolation. Therefore, the primary goal of this file is to test the methods and behavior of the `WebTransportWriteBlockedList` class.

3. **Analyze the Test Structure:**  The file uses the Google Test framework (`::testing::...`). We see a test fixture `WebTransportWriteBlockedListTest` inheriting from `::quiche::test::QuicheTest`. This sets up a context for running multiple related tests. Each test case is a function starting with `TEST_F(WebTransportWriteBlockedListTest, ...)`

4. **Examine the Helper Methods:**  The test fixture has helper methods like `RegisterStaticStream`, `RegisterHttpStream`, `RegisterWebTransportDataStream`, and `PopAll`. These are crucial for setting up test scenarios in a concise way.

    * **`Register...Stream`:** These methods likely simulate registering different types of streams with the `WebTransportWriteBlockedList`, associating them with a priority. The `is_static_stream` flag suggests a distinction between control streams and data streams.
    * **`PopAll`:** This method iteratively calls a `PopFront` method on the list and collects the results. This is a common pattern for testing queue-like structures.

5. **Go Through Each Test Case:**  The most informative part is analyzing each individual test case. For each one, ask:

    * **What aspect of `WebTransportWriteBlockedList` is being tested?** Look at the test name and the operations performed within the test.
    * **What is the expected behavior?** The `EXPECT_...` and `ASSERT_THAT` macros reveal the expected outcomes.
    * **What are the inputs/setup for the test?**  The `Register...Stream` and `AddStream` calls set up the test conditions.

6. **Categorize Functionality Based on Tests:** As you go through the tests, you can start grouping them by the functionality they are verifying. For example:

    * **Basic Stream Handling:** `BasicHttpStreams`, `RegisterDuplicateStream`, `UnregisterMissingStream`, `GetPriorityMissingStream` test basic registration, addition, and retrieval of streams.
    * **Priority Ordering:** Tests with multiple stream registrations and `PopAll` (like `BasicHttpStreams`, `NestedStreams`, `NestedStreamsWithHigherPriorityGroup`, etc.) verify the priority ordering logic.
    * **Stream Types:** Tests involving `RegisterStaticStream`, `RegisterHttpStream`, and `RegisterWebTransportDataStream` and the interactions between them (e.g., `NestedStreamVsControlStream`).
    * **Blocking/Unblocking:** `HasWriteBlockedDataStreams`, `IsStreamBlocked` test the tracking of blocked streams.
    * **Updates:** `UpdatePriorityHttp`, `UpdatePriorityWebTransport`, `UpdatePriorityControlStream` test the ability to modify stream priorities.
    * **Yielding:** `ShouldYield` likely tests a mechanism for determining if a stream should yield its turn.
    * **Unregistration:** `UnregisterScheduledStreams`, `UnregisterUnscheduledStreams` test removing streams.
    * **Randomized Testing:** `RandomizedTest` provides broader coverage by testing with randomly ordered streams.

7. **Look for Connections to JavaScript (if any):**  WebTransport is a browser API used by JavaScript. Think about how the functionalities being tested in C++ relate to what a JavaScript developer using the WebTransport API would experience.

    * **Stream Priorities:**  JavaScript code can likely influence the priority of streams it creates. The C++ code handles the underlying prioritization logic.
    * **Write Blocking:**  If a stream's write buffer is full, the browser needs a way to manage which streams can write next. The `WebTransportWriteBlockedList` likely plays a role in this.
    * **Stream Creation and Management:** JavaScript uses the WebTransport API to create and manage streams. The C++ code manages the server-side representation of these streams.

8. **Consider Error Scenarios:** The tests with `EXPECT_QUICHE_BUG` are specifically checking for expected errors when the API is used incorrectly (e.g., registering a duplicate stream). This is valuable for identifying common usage errors.

9. **Think About Debugging:** How would a developer end up looking at this C++ code?  Consider scenarios like:

    * **Performance Issues:** If a user reports slow data transfer, a developer might investigate the stream prioritization logic.
    * **Unexpected Blocking:** If streams are getting blocked unexpectedly, this code could be relevant.
    * **WebTransport API Issues:**  If there are bugs or unexpected behavior in the JavaScript WebTransport API, the underlying C++ implementation might be the cause.

10. **Structure the Explanation:** Organize the findings logically, starting with the main purpose and then detailing the specific functionalities, JavaScript connections, error scenarios, and debugging context. Use clear and concise language. Use examples where possible.

By following these steps, you can effectively analyze a C++ test file and extract its key information. The iterative nature of examining each test case and then grouping them by functionality is particularly important for understanding the overall behavior of the tested component.
这个C++ 源文件 `web_transport_write_blocked_list_test.cc` 是 Chromium 网络栈中 QUIC 协议 WebTransport 功能的一部分，它的主要功能是**测试 `WebTransportWriteBlockedList` 类**。

`WebTransportWriteBlockedList` 类的作用是管理由于写入受阻（例如，接收方窗口已满）而无法发送数据的 WebTransport 流。  它维护一个阻塞的流的列表，并根据流的优先级决定哪些流应该被优先唤醒并允许继续发送数据。

以下是该测试文件所测试的主要功能点：

**1. 流的注册和注销 (Registration and Unregistration):**

* **功能:** 测试向 `WebTransportWriteBlockedList` 注册和注销不同类型的流（HTTP 流和 WebTransport 数据流）的能力。
* **假设输入与输出:**
    * **假设输入:** 调用 `RegisterHttpStream(1)` 注册一个 ID 为 1 的 HTTP 流。
    * **预期输出:** 内部数据结构能够正确记录该流的存在和类型。
* **用户/编程常见错误:** 尝试注册已存在的流会导致程序错误 (测试用例 `RegisterDuplicateStream`)。

**2. 流的添加和移除 (Adding and Removing Blocked Streams):**

* **功能:** 测试将流添加到阻塞列表，以及根据优先级从阻塞列表中移除（唤醒）流的功能。
* **假设输入与输出:**
    * **假设输入:** 先注册流 1 和流 2，然后调用 `list_.AddStream(1)` 和 `list_.AddStream(2)` 将它们添加到阻塞列表。
    * **预期输出:** 调用 `PopAll()` 应该按照优先级顺序返回流 ID。例如，如果流 1 优先级高于流 2，则返回顺序为 {1, 2}。
* **用户/编程常见错误:** 尝试从空列表中移除流会导致程序错误 (测试用例 `PopFrontMissing`)。

**3. 流的优先级排序 (Priority Ordering):**

* **功能:** 测试 `WebTransportWriteBlockedList` 如何根据流的优先级（包括 HTTP 流优先级和 WebTransport 流优先级）对阻塞的流进行排序。
* **假设输入与输出:**
    * **假设输入:** 注册具有不同优先级的 HTTP 流和 WebTransport 数据流，并将它们添加到阻塞列表。
    * **预期输出:** `PopAll()` 返回的流 ID 顺序应该反映其优先级。例如，优先级更高的流应该先被返回。 (例如，测试用例 `BasicHttpStreams`, `NestedStreams`, `NestedStreamsWithHigherPriorityGroup`, `NestedStreamsSendOrder`, `NestedStreamsDifferentGroups`, `NestedStreamsDifferentSession`)
* **与 JavaScript 的关系:**  WebTransport 规范允许 JavaScript 代码设置 WebTransport 数据流的优先级。 Chromium 的网络栈需要根据这些优先级来调度数据发送。此测试文件验证了 C++ 端的优先级排序逻辑是否正确。
    * **举例:** 在 JavaScript 中，可以使用 `WebTransportSendStream.priority` 属性来设置流的优先级。  在 C++ 端，`WebTransportWriteBlockedList` 会根据这个优先级来决定哪个流先发送数据。

**4. 判断流是否被阻塞 (Checking if a Stream is Blocked):**

* **功能:** 测试 `IsStreamBlocked()` 方法，用于检查指定的流是否在阻塞列表中。
* **假设输入与输出:**
    * **假设输入:** 将一个流添加到阻塞列表，然后调用 `IsStreamBlocked()` 检查该流。
    * **预期输出:** `IsStreamBlocked()` 应该返回 `true`。
* **用户/编程常见错误:** 在尝试发送数据之前，没有正确检查流是否被阻塞，可能会导致发送失败或数据丢失。

**5. 更新流的优先级 (Updating Stream Priority):**

* **功能:** 测试更新已注册流的优先级的功能，并验证更新后的优先级是否会影响流的排序。
* **假设输入与输出:**
    * **假设输入:** 先注册并阻塞一些流，然后调用 `UpdateStreamPriority()` 修改其中一个流的优先级。
    * **预期输出:** 再次调用 `PopAll()` 时，流的顺序应该反映新的优先级。 (例如，测试用例 `UpdatePriorityHttp`, `UpdatePriorityWebTransport`, `UpdatePriorityControlStream`)
* **与 JavaScript 的关系:**  JavaScript 代码有时可能需要动态地调整 WebTransport 流的优先级。此测试验证了 C++ 端是否能正确处理这些更新。

**6. 判断是否应该让出 (Should Yield):**

* **功能:** 测试 `ShouldYield()` 方法，该方法可能用于判断一个流是否应该让出其发送机会给其他更高优先级的流。
* **假设输入与输出:**
    * **假设输入:**  注册并阻塞具有不同优先级的流。
    * **预期输出:**  对于优先级较低的流，`ShouldYield()` 可能会返回 `true`，表示它应该让出。 (测试用例 `ShouldYield`)

**7. 随机化测试 (Randomized Testing):**

* **功能:** 通过随机排列流的添加顺序，进行更全面的测试，以确保优先级排序逻辑的健壮性。
* **假设输入与输出:**
    * **假设输入:**  随机顺序添加一系列具有不同优先级的流。
    * **预期输出:**  无论添加顺序如何，`PopAll()` 返回的流顺序始终应该符合预期的优先级顺序。 (测试用例 `RandomizedTest`)

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用基于 Chromium 的浏览器访问一个使用了 WebTransport 协议的网站。

1. **用户发起 WebTransport 连接:**  JavaScript 代码使用 `new WebTransport(...)` API 创建一个 WebTransport 连接。
2. **创建和发送 WebTransport 流:**  JavaScript 代码使用 `createSendStream()` 创建一个或多个发送流，并使用 `WritableStream.getWriter().write()` 发送数据。
3. **网络拥塞或接收方窗口受限:**  如果网络出现拥塞，或者接收方的接收窗口已满，某些 WebTransport 流可能会因为无法发送数据而被阻塞。
4. **`WebTransportWriteBlockedList` 的使用:**  在 Chromium 的网络栈中，当 WebTransport 流的写入操作受阻时，该流的 ID 会被添加到 `WebTransportWriteBlockedList` 中。
5. **优先级判断和调度:**  当有新的网络资源可用时 (例如，接收方窗口更新)，Chromium 的网络栈会使用 `WebTransportWriteBlockedList` 来决定哪个被阻塞的流应该被优先唤醒并允许发送数据。这涉及到调用 `PopFront()` 等方法。
6. **调试线索:** 如果开发者在调试 WebTransport 连接的性能问题（例如，某些流的发送延迟很高），他们可能会：
    * **查看网络日志:**  检查哪些流被阻塞以及阻塞的时间。
    * **断点调试 C++ 代码:**  在 `WebTransportWriteBlockedList` 的 `AddStream()`, `PopFront()`, `UpdateStreamPriority()` 等方法上设置断点，以观察流的添加、移除和优先级变化。
    * **检查流的优先级设置:**  确认 JavaScript 代码是否正确设置了流的优先级。
    * **分析 `ShouldYield()` 的行为:**  查看在特定情况下，哪些流被认为应该让出。

**总结:**

`web_transport_write_blocked_list_test.cc` 文件通过一系列单元测试，确保了 `WebTransportWriteBlockedList` 类能够正确地管理和调度被阻塞的 WebTransport 流，并严格按照优先级进行排序。这对于保证 WebTransport 协议的性能和公平性至关重要。  它与 JavaScript 的功能紧密相关，因为 JavaScript 代码可以通过 WebTransport API 设置流的优先级，而 C++ 端的 `WebTransportWriteBlockedList` 则负责执行这些优先级策略。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/web_transport_write_blocked_list_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/web_transport_write_blocked_list.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <vector>

#include "absl/algorithm/container.h"
#include "quiche/quic/core/quic_stream_priority.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace quic::test {
namespace {

using ::testing::ElementsAre;
using ::testing::ElementsAreArray;

class WebTransportWriteBlockedListTest : public ::quiche::test::QuicheTest {
 protected:
  void RegisterStaticStream(QuicStreamId id) {
    list_.RegisterStream(id, /*is_static_stream=*/true, QuicStreamPriority());
  }
  void RegisterHttpStream(QuicStreamId id,
                          int urgency = HttpStreamPriority::kDefaultUrgency) {
    HttpStreamPriority priority;
    priority.urgency = urgency;
    list_.RegisterStream(id, /*is_static_stream=*/false,
                         QuicStreamPriority(priority));
  }
  void RegisterWebTransportDataStream(QuicStreamId id,
                                      WebTransportStreamPriority priority) {
    list_.RegisterStream(id, /*is_static_stream=*/false,
                         QuicStreamPriority(priority));
  }

  std::vector<QuicStreamId> PopAll() {
    std::vector<QuicStreamId> result;
    size_t expected_count = list_.NumBlockedStreams();
    while (list_.NumBlockedStreams() > 0) {
      EXPECT_TRUE(list_.HasWriteBlockedDataStreams() ||
                  list_.HasWriteBlockedSpecialStream());
      result.push_back(list_.PopFront());
      EXPECT_EQ(list_.NumBlockedStreams(), --expected_count);
    }
    return result;
  }

  WebTransportWriteBlockedList list_;
};

TEST_F(WebTransportWriteBlockedListTest, BasicHttpStreams) {
  RegisterHttpStream(1);
  RegisterHttpStream(2);
  RegisterHttpStream(3, HttpStreamPriority::kDefaultUrgency + 1);
  RegisterStaticStream(4);

  EXPECT_EQ(list_.GetPriorityOfStream(1), QuicStreamPriority());
  EXPECT_EQ(list_.GetPriorityOfStream(2), QuicStreamPriority());
  EXPECT_EQ(list_.GetPriorityOfStream(3).http().urgency, 4);

  EXPECT_EQ(list_.NumBlockedStreams(), 0);
  EXPECT_EQ(list_.NumBlockedSpecialStreams(), 0);
  list_.AddStream(1);
  list_.AddStream(2);
  list_.AddStream(3);
  list_.AddStream(4);
  EXPECT_EQ(list_.NumBlockedStreams(), 4);
  EXPECT_EQ(list_.NumBlockedSpecialStreams(), 1);

  EXPECT_THAT(PopAll(), ElementsAre(4, 3, 1, 2));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);
  EXPECT_EQ(list_.NumBlockedSpecialStreams(), 0);

  list_.AddStream(2);
  list_.AddStream(3);
  list_.AddStream(4);
  list_.AddStream(1);
  EXPECT_THAT(PopAll(), ElementsAre(4, 3, 2, 1));
}

TEST_F(WebTransportWriteBlockedListTest, RegisterDuplicateStream) {
  RegisterHttpStream(1);
  EXPECT_QUICHE_BUG(RegisterHttpStream(1), "already registered");
}

TEST_F(WebTransportWriteBlockedListTest, UnregisterMissingStream) {
  EXPECT_QUICHE_BUG(list_.UnregisterStream(1), "not found");
}

TEST_F(WebTransportWriteBlockedListTest, GetPriorityMissingStream) {
  EXPECT_QUICHE_BUG(list_.GetPriorityOfStream(1), "not found");
}

TEST_F(WebTransportWriteBlockedListTest, PopFrontMissing) {
  RegisterHttpStream(1);
  list_.AddStream(1);
  EXPECT_EQ(list_.PopFront(), 1);
  EXPECT_QUICHE_BUG(list_.PopFront(), "no streams scheduled");
}

TEST_F(WebTransportWriteBlockedListTest, HasWriteBlockedDataStreams) {
  RegisterStaticStream(1);
  RegisterHttpStream(2);

  EXPECT_FALSE(list_.HasWriteBlockedDataStreams());
  list_.AddStream(1);
  EXPECT_FALSE(list_.HasWriteBlockedDataStreams());
  list_.AddStream(2);
  EXPECT_TRUE(list_.HasWriteBlockedDataStreams());
  EXPECT_EQ(list_.PopFront(), 1);
  EXPECT_TRUE(list_.HasWriteBlockedDataStreams());
  EXPECT_EQ(list_.PopFront(), 2);
  EXPECT_FALSE(list_.HasWriteBlockedDataStreams());
}

TEST_F(WebTransportWriteBlockedListTest, NestedStreams) {
  RegisterHttpStream(1);
  RegisterHttpStream(2);
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(4, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(5, WebTransportStreamPriority{2, 0, 0});
  RegisterWebTransportDataStream(6, WebTransportStreamPriority{2, 0, 0});
  EXPECT_EQ(list_.NumBlockedStreams(), 0);

  list_.AddStream(3);
  list_.AddStream(5);
  list_.AddStream(4);
  list_.AddStream(6);
  EXPECT_EQ(list_.NumBlockedStreams(), 4);
  EXPECT_THAT(PopAll(), ElementsAre(3, 5, 4, 6));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);

  list_.AddStream(3);
  list_.AddStream(4);
  list_.AddStream(5);
  EXPECT_EQ(list_.NumBlockedStreams(), 3);
  EXPECT_THAT(PopAll(), ElementsAre(3, 5, 4));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);

  list_.AddStream(4);
  list_.AddStream(5);
  list_.AddStream(6);
  EXPECT_EQ(list_.NumBlockedStreams(), 3);
  EXPECT_THAT(PopAll(), ElementsAre(4, 5, 6));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);

  list_.AddStream(6);
  list_.AddStream(3);
  list_.AddStream(4);
  list_.AddStream(5);
  EXPECT_EQ(list_.NumBlockedStreams(), 4);
  EXPECT_THAT(PopAll(), ElementsAre(6, 3, 5, 4));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);

  list_.AddStream(6);
  list_.AddStream(5);
  list_.AddStream(4);
  list_.AddStream(3);
  EXPECT_EQ(list_.NumBlockedStreams(), 4);
  EXPECT_THAT(PopAll(), ElementsAre(6, 4, 5, 3));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);
}

TEST_F(WebTransportWriteBlockedListTest, NestedStreamsWithHigherPriorityGroup) {
  RegisterHttpStream(1, HttpStreamPriority::kDefaultUrgency + 1);
  RegisterHttpStream(2);
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(4, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(5, WebTransportStreamPriority{2, 0, 0});
  RegisterWebTransportDataStream(6, WebTransportStreamPriority{2, 0, 0});
  EXPECT_EQ(list_.NumBlockedStreams(), 0);

  list_.AddStream(3);
  list_.AddStream(5);
  list_.AddStream(4);
  list_.AddStream(6);
  EXPECT_EQ(list_.NumBlockedStreams(), 4);
  EXPECT_THAT(PopAll(), ElementsAre(3, 4, 5, 6));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);

  list_.AddStream(3);
  list_.AddStream(4);
  list_.AddStream(5);
  EXPECT_EQ(list_.NumBlockedStreams(), 3);
  EXPECT_THAT(PopAll(), ElementsAre(3, 4, 5));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);

  list_.AddStream(4);
  list_.AddStream(5);
  list_.AddStream(6);
  EXPECT_EQ(list_.NumBlockedStreams(), 3);
  EXPECT_THAT(PopAll(), ElementsAre(4, 5, 6));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);

  list_.AddStream(6);
  list_.AddStream(3);
  list_.AddStream(4);
  list_.AddStream(5);
  EXPECT_EQ(list_.NumBlockedStreams(), 4);
  EXPECT_THAT(PopAll(), ElementsAre(3, 4, 6, 5));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);

  list_.AddStream(6);
  list_.AddStream(5);
  list_.AddStream(4);
  list_.AddStream(3);
  EXPECT_EQ(list_.NumBlockedStreams(), 4);
  EXPECT_THAT(PopAll(), ElementsAre(4, 3, 6, 5));
  EXPECT_EQ(list_.NumBlockedStreams(), 0);
}

TEST_F(WebTransportWriteBlockedListTest, NestedStreamVsControlStream) {
  RegisterHttpStream(1);
  RegisterWebTransportDataStream(2, WebTransportStreamPriority{1, 0, 0});

  list_.AddStream(2);
  list_.AddStream(1);
  EXPECT_THAT(PopAll(), ElementsAre(1, 2));

  list_.AddStream(1);
  list_.AddStream(2);
  EXPECT_THAT(PopAll(), ElementsAre(1, 2));
}

TEST_F(WebTransportWriteBlockedListTest, NestedStreamsSendOrder) {
  RegisterHttpStream(1);
  RegisterWebTransportDataStream(2, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{1, 0, 100});
  RegisterWebTransportDataStream(4, WebTransportStreamPriority{1, 0, -100});

  list_.AddStream(4);
  list_.AddStream(3);
  list_.AddStream(2);
  list_.AddStream(1);
  EXPECT_THAT(PopAll(), ElementsAre(1, 3, 2, 4));
}

TEST_F(WebTransportWriteBlockedListTest, NestedStreamsDifferentGroups) {
  RegisterHttpStream(1);
  RegisterWebTransportDataStream(2, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{1, 1, 100});
  RegisterWebTransportDataStream(4, WebTransportStreamPriority{1, 7, -100});

  list_.AddStream(4);
  list_.AddStream(3);
  list_.AddStream(2);
  list_.AddStream(1);
  EXPECT_THAT(PopAll(), ElementsAre(1, 4, 3, 2));

  list_.AddStream(1);
  list_.AddStream(2);
  list_.AddStream(3);
  list_.AddStream(4);
  EXPECT_THAT(PopAll(), ElementsAre(1, 2, 3, 4));
}

TEST_F(WebTransportWriteBlockedListTest, NestedStreamsDifferentSession) {
  RegisterWebTransportDataStream(1, WebTransportStreamPriority{10, 0, 0});
  RegisterWebTransportDataStream(2, WebTransportStreamPriority{11, 0, 100});
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{12, 0, -100});

  list_.AddStream(3);
  list_.AddStream(2);
  list_.AddStream(1);
  EXPECT_THAT(PopAll(), ElementsAre(3, 2, 1));

  list_.AddStream(1);
  list_.AddStream(2);
  list_.AddStream(3);
  EXPECT_THAT(PopAll(), ElementsAre(1, 2, 3));
}

TEST_F(WebTransportWriteBlockedListTest, UnregisterScheduledStreams) {
  RegisterHttpStream(1);
  RegisterHttpStream(2);
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(4, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(5, WebTransportStreamPriority{2, 0, 0});
  RegisterWebTransportDataStream(6, WebTransportStreamPriority{2, 0, 0});

  EXPECT_EQ(list_.NumBlockedStreams(), 0);
  for (QuicStreamId id : {1, 2, 3, 4, 5, 6}) {
    list_.AddStream(id);
  }
  EXPECT_EQ(list_.NumBlockedStreams(), 6);

  list_.UnregisterStream(1);
  EXPECT_EQ(list_.NumBlockedStreams(), 5);
  list_.UnregisterStream(3);
  EXPECT_EQ(list_.NumBlockedStreams(), 4);
  list_.UnregisterStream(4);
  EXPECT_EQ(list_.NumBlockedStreams(), 3);
  list_.UnregisterStream(5);
  EXPECT_EQ(list_.NumBlockedStreams(), 2);
  list_.UnregisterStream(6);
  EXPECT_EQ(list_.NumBlockedStreams(), 1);
  list_.UnregisterStream(2);
  EXPECT_EQ(list_.NumBlockedStreams(), 0);
}

TEST_F(WebTransportWriteBlockedListTest, UnregisterUnscheduledStreams) {
  RegisterHttpStream(1);
  RegisterHttpStream(2);
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(4, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(5, WebTransportStreamPriority{2, 0, 0});
  RegisterWebTransportDataStream(6, WebTransportStreamPriority{2, 0, 0});

  EXPECT_EQ(list_.NumRegisteredHttpStreams(), 2);
  EXPECT_EQ(list_.NumRegisteredGroups(), 2);
  list_.UnregisterStream(1);
  EXPECT_EQ(list_.NumRegisteredHttpStreams(), 1);
  EXPECT_EQ(list_.NumRegisteredGroups(), 2);
  list_.UnregisterStream(3);
  EXPECT_EQ(list_.NumRegisteredHttpStreams(), 1);
  EXPECT_EQ(list_.NumRegisteredGroups(), 2);
  list_.UnregisterStream(4);
  EXPECT_EQ(list_.NumRegisteredHttpStreams(), 1);
  EXPECT_EQ(list_.NumRegisteredGroups(), 1);

  list_.UnregisterStream(5);
  EXPECT_EQ(list_.NumRegisteredHttpStreams(), 1);
  EXPECT_EQ(list_.NumRegisteredGroups(), 1);
  list_.UnregisterStream(6);
  EXPECT_EQ(list_.NumRegisteredHttpStreams(), 1);
  EXPECT_EQ(list_.NumRegisteredGroups(), 0);
  list_.UnregisterStream(2);
  EXPECT_EQ(list_.NumRegisteredHttpStreams(), 0);
  EXPECT_EQ(list_.NumRegisteredGroups(), 0);

  RegisterHttpStream(1);
  RegisterHttpStream(2);
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(4, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(5, WebTransportStreamPriority{2, 0, 0});
  RegisterWebTransportDataStream(6, WebTransportStreamPriority{2, 0, 0});
}

TEST_F(WebTransportWriteBlockedListTest, IsStreamBlocked) {
  RegisterHttpStream(1);
  RegisterWebTransportDataStream(2, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{9, 0, 0});

  EXPECT_FALSE(list_.IsStreamBlocked(1));
  EXPECT_FALSE(list_.IsStreamBlocked(2));
  EXPECT_FALSE(list_.IsStreamBlocked(3));

  list_.AddStream(3);
  EXPECT_FALSE(list_.IsStreamBlocked(1));
  EXPECT_FALSE(list_.IsStreamBlocked(2));
  EXPECT_TRUE(list_.IsStreamBlocked(3));

  list_.AddStream(1);
  EXPECT_TRUE(list_.IsStreamBlocked(1));
  EXPECT_FALSE(list_.IsStreamBlocked(2));
  EXPECT_TRUE(list_.IsStreamBlocked(3));

  ASSERT_EQ(list_.PopFront(), 1);
  EXPECT_FALSE(list_.IsStreamBlocked(1));
  EXPECT_FALSE(list_.IsStreamBlocked(2));
  EXPECT_TRUE(list_.IsStreamBlocked(3));
}

TEST_F(WebTransportWriteBlockedListTest, UpdatePriorityHttp) {
  RegisterHttpStream(1);
  RegisterHttpStream(2);
  RegisterHttpStream(3);

  list_.AddStream(1);
  list_.AddStream(2);
  list_.AddStream(3);
  EXPECT_THAT(PopAll(), ElementsAre(1, 2, 3));

  list_.UpdateStreamPriority(
      2, QuicStreamPriority(
             HttpStreamPriority{HttpStreamPriority::kMaximumUrgency, false}));

  list_.AddStream(1);
  list_.AddStream(2);
  list_.AddStream(3);
  EXPECT_THAT(PopAll(), ElementsAre(2, 1, 3));
}

TEST_F(WebTransportWriteBlockedListTest, UpdatePriorityWebTransport) {
  RegisterWebTransportDataStream(1, WebTransportStreamPriority{0, 0, 0});
  RegisterWebTransportDataStream(2, WebTransportStreamPriority{0, 0, 0});
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{0, 0, 0});

  list_.AddStream(1);
  list_.AddStream(2);
  list_.AddStream(3);
  EXPECT_THAT(PopAll(), ElementsAre(1, 2, 3));

  list_.UpdateStreamPriority(
      2, QuicStreamPriority(WebTransportStreamPriority{0, 0, 1}));

  list_.AddStream(1);
  list_.AddStream(2);
  list_.AddStream(3);
  EXPECT_THAT(PopAll(), ElementsAre(2, 1, 3));
}

TEST_F(WebTransportWriteBlockedListTest, UpdatePriorityControlStream) {
  RegisterHttpStream(1);
  RegisterHttpStream(2);
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(4, WebTransportStreamPriority{2, 0, 0});

  list_.AddStream(3);
  list_.AddStream(4);
  EXPECT_THAT(PopAll(), ElementsAre(3, 4));
  list_.AddStream(4);
  list_.AddStream(3);
  EXPECT_THAT(PopAll(), ElementsAre(4, 3));

  list_.UpdateStreamPriority(
      2, QuicStreamPriority(
             HttpStreamPriority{HttpStreamPriority::kMaximumUrgency, false}));

  list_.AddStream(3);
  list_.AddStream(4);
  EXPECT_THAT(PopAll(), ElementsAre(4, 3));
  list_.AddStream(4);
  list_.AddStream(3);
  EXPECT_THAT(PopAll(), ElementsAre(4, 3));
}

TEST_F(WebTransportWriteBlockedListTest, ShouldYield) {
  RegisterHttpStream(1);
  RegisterWebTransportDataStream(2, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(3, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(4, WebTransportStreamPriority{1, 0, 10});

  EXPECT_FALSE(list_.ShouldYield(1));
  EXPECT_FALSE(list_.ShouldYield(2));
  EXPECT_FALSE(list_.ShouldYield(3));
  EXPECT_FALSE(list_.ShouldYield(4));

  list_.AddStream(1);
  EXPECT_FALSE(list_.ShouldYield(1));
  EXPECT_TRUE(list_.ShouldYield(2));
  EXPECT_TRUE(list_.ShouldYield(3));
  EXPECT_TRUE(list_.ShouldYield(4));
  PopAll();

  list_.AddStream(2);
  EXPECT_FALSE(list_.ShouldYield(1));
  EXPECT_FALSE(list_.ShouldYield(2));
  EXPECT_TRUE(list_.ShouldYield(3));
  EXPECT_FALSE(list_.ShouldYield(4));
  PopAll();

  list_.AddStream(4);
  EXPECT_FALSE(list_.ShouldYield(1));
  EXPECT_TRUE(list_.ShouldYield(2));
  EXPECT_TRUE(list_.ShouldYield(3));
  EXPECT_FALSE(list_.ShouldYield(4));
  PopAll();
}

TEST_F(WebTransportWriteBlockedListTest, RandomizedTest) {
  RegisterHttpStream(1);
  RegisterHttpStream(2, HttpStreamPriority::kMinimumUrgency);
  RegisterHttpStream(3, HttpStreamPriority::kMaximumUrgency);
  RegisterWebTransportDataStream(4, WebTransportStreamPriority{1, 0, 0});
  RegisterWebTransportDataStream(5, WebTransportStreamPriority{2, 0, +1});
  RegisterWebTransportDataStream(6, WebTransportStreamPriority{2, 0, -1});
  RegisterWebTransportDataStream(7, WebTransportStreamPriority{3, 8, 0});
  RegisterWebTransportDataStream(8, WebTransportStreamPriority{3, 8, 100});
  RegisterWebTransportDataStream(9, WebTransportStreamPriority{3, 8, 20000});
  RegisterHttpStream(10, HttpStreamPriority::kDefaultUrgency + 1);
  // The priorities of the streams above are arranged so that the priorities of
  // all streams above are strictly ordered (i.e. there are no streams that
  // would be round-robined).
  constexpr std::array<QuicStreamId, 10> order = {3, 9, 8, 7, 10,
                                                  1, 4, 2, 5, 6};

  SimpleRandom random;
  for (int i = 0; i < 1000; ++i) {
    // Shuffle the streams.
    std::vector<QuicStreamId> pushed_streams(order.begin(), order.end());
    for (int j = pushed_streams.size() - 1; j > 0; --j) {
      std::swap(pushed_streams[j],
                pushed_streams[random.RandUint64() % (j + 1)]);
    }

    size_t stream_count = 1 + random.RandUint64() % order.size();
    pushed_streams.resize(stream_count);

    for (QuicStreamId id : pushed_streams) {
      list_.AddStream(id);
    }

    std::vector<QuicStreamId> expected_streams;
    absl::c_copy_if(
        order, std::back_inserter(expected_streams), [&](QuicStreamId id) {
          return absl::c_find(pushed_streams, id) != pushed_streams.end();
        });
    ASSERT_THAT(PopAll(), ElementsAreArray(expected_streams));
  }
}

}  // namespace
}  // namespace quic::test
```