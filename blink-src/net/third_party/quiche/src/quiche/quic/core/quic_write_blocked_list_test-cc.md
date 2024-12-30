Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the C++ test file, its relationship to JavaScript (if any), logical reasoning with input/output, common user/programming errors, and debugging steps to reach this code.

2. **Identify the Core Subject:** The file name `quic_write_blocked_list_test.cc` and the `#include "quiche/quic/core/quic_write_blocked_list.h"` immediately tell us that this file tests the `QuicWriteBlockedList` class. This is the central point of investigation.

3. **Analyze the Test Structure:** The file uses Google Test (`#include "quiche/quic/platform/api/quic_test.h"`) and defines a test fixture `QuicWriteBlockedListTest` that inherits from `QuicTest`. This structure is standard for C++ unit testing. The `SetUp()` method is important as it initializes the `QuicWriteBlockedList`. The various protected methods within the test fixture are helper functions to interact with the `QuicWriteBlockedList` under test.

4. **Deconstruct Individual Tests:**  Go through each `TEST_F` function. Each test focuses on a specific aspect of `QuicWriteBlockedList`'s behavior. Summarize the purpose of each test:

    * `PriorityOrder`:  Verifies streams are prioritized correctly based on static/dynamic and priority values.
    * `SingleStaticStream`: Checks handling of a single static stream.
    * `StaticStreamsComeFirst`: Confirms static streams are processed before non-static ones.
    * `NoDuplicateEntries`: Ensures adding the same stream multiple times doesn't cause issues.
    * `IncrementalStreamsRoundRobin`: Tests the round-robin behavior for incremental streams.
    * `QuicWriteBlockedListParameterizedTest` (and its cases): This is a more complex parameterized test. Note the parameters (`priority_respect_incremental_`, `disable_batch_write_`) and how they affect the tests. Specifically, identify the `BatchingWrites` and `RoundRobin` tests based on the `disable_batch_write_` flag.
    * `NonIncrementalStreamsKeepWriting`:  Verifies that non-incremental streams can continue writing without yielding immediately.
    * `IncrementalAndNonIncrementalStreams`: Tests the interaction between incremental and non-incremental streams.
    * `Ceding`: Checks the `ShouldYield` method, which determines if a stream should yield to others.
    * `UnregisterStream`:  Tests removing streams from the blocked list.
    * `UnregisterNotRegisteredStream`: Verifies behavior when unregistering a non-existent stream (expecting a bug).
    * `UpdateStreamPriority`: Tests changing the priority of a stream.
    * `UpdateStaticStreamPriority`:  Ensures that the priority of static streams cannot be updated (expecting a debug assertion).
    * `UpdateStreamPrioritySameUrgency`: Checks how streams with the same priority are handled after priority updates.

5. **Synthesize Functionality:** Based on the individual test summaries, create a concise description of the `QuicWriteBlockedList`'s functionality. Focus on:

    * Managing write-blocked streams.
    * Prioritization (static vs. dynamic, priority values, incremental).
    * Round-robin behavior (especially for incremental streams).
    * Batching writes (controlled by a flag).
    * The `ShouldYield` method.
    * Registration, unregistration, and priority updates.

6. **Address JavaScript Relationship:**  Think about where this QUIC code might interact with JavaScript in a browser. The key connection is the network stack. JavaScript initiates network requests, and the browser's networking components (including QUIC) handle the underlying communication. The prioritization managed by `QuicWriteBlockedList` directly affects how quickly resources are delivered to the JavaScript code. Provide a concrete example, like prioritizing the main HTML document over images.

7. **Logical Reasoning (Input/Output):** Select a simpler test case (like `PriorityOrder`) and trace the execution mentally. Define the initial state (registered streams, their priorities). Simulate the `AddStream` calls, noting the internal state of the blocked list. Predict the order in which `PopFront` will return the stream IDs based on the prioritization rules.

8. **Common Errors:** Consider common mistakes developers might make when *using* the `QuicWriteBlockedList` (or related QUIC components). Examples include:

    * Not registering streams before adding them.
    * Updating the priority of static streams.
    * Assuming strict FIFO without understanding prioritization.

9. **Debugging Steps:**  Imagine a scenario where a user reports a slow loading page. Outline the steps a developer might take to investigate, eventually leading to examining the `QuicWriteBlockedList`:

    * User reports slow page load.
    * Initial checks (network connectivity, server issues).
    * Examining browser network logs (identifying potential QUIC issues).
    * Diving into QUIC internals (congestion control, stream prioritization).
    * Suspecting issues with write blocking and examining the `QuicWriteBlockedList`.

10. **Review and Refine:** Read through the generated analysis. Ensure it's clear, concise, and addresses all parts of the request. Correct any inaccuracies or areas where more detail might be helpful. For instance, initially, I might just say it handles prioritization, but then I'd refine it to specify *how* the prioritization works (static first, then priority values, then incremental).

This detailed thought process allows for a comprehensive understanding of the test file and its implications within the larger Chromium networking stack.
这个C++源代码文件 `quic_write_blocked_list_test.cc` 是 Chromium 中 QUIC 协议栈的一部分，专门用于测试 `QuicWriteBlockedList` 类的功能。 `QuicWriteBlockedList` 的主要作用是**管理当前由于发送缓冲区已满而被阻塞的 QUIC 数据流和控制流**，并根据优先级决定下一个可以发送数据的流。

以下是 `quic_write_blocked_list_test.cc` 的功能列表：

1. **测试数据流的优先级排序:**  验证 `QuicWriteBlockedList` 是否能正确地根据流的优先级（包括静态流和动态流，以及它们的 urgency 和 incremental 属性）对阻塞的流进行排序。优先级高的流应该先被解除阻塞并允许发送数据。

2. **测试静态流的特殊处理:** 验证静态流（通常是重要的控制流）是否具有更高的优先级，即使它们的优先级值较低，也能优先于动态流被处理。

3. **测试防止重复添加:** 验证 `QuicWriteBlockedList` 不会重复添加同一个阻塞的流。

4. **测试增量流的轮询调度 (Round-Robin):** 对于优先级相同的增量流（incremental streams），验证 `QuicWriteBlockedList` 是否按照轮询的方式调度，以避免某个流一直占用发送机会。

5. **测试批量写入的机制:** (通过参数化测试 `QuicWriteBlockedListParameterizedTest`) 验证当启用批量写入时，一个流在发送一定量的数据后才会让出发送机会给其他流，从而提高效率。

6. **测试非增量流的持续写入:** (通过参数化测试 `QuicWriteBlockedListParameterizedTest`) 验证当启用尊重增量属性的优先级策略时，非增量流可以持续写入数据直到完成或被更高优先级的流抢占。

7. **测试增量流和非增量流的混合处理:** (通过参数化测试 `QuicWriteBlockedListParameterizedTest`) 验证 `QuicWriteBlockedList` 如何处理同时存在增量流和非增量流的情况。

8. **测试 `ShouldYield()` 方法:** 验证 `ShouldYield()` 方法是否能正确判断一个流是否应该让出发送机会给其他更高优先级的流。

9. **测试注销流 (`UnregisterStream`) 功能:** 验证从 `QuicWriteBlockedList` 中正确移除已不再阻塞的流。

10. **测试更新流优先级 (`UpdateStreamPriority`) 功能:** 验证可以动态更新阻塞队列中流的优先级，并影响其后续的调度顺序。

**与 JavaScript 的功能关系：**

`quic_write_blocked_list_test.cc` 本身是用 C++ 编写的测试代码，直接与 JavaScript 没有交互。然而，它测试的 `QuicWriteBlockedList` 类是 Chromium 浏览器网络栈中 QUIC 协议实现的关键部分。当用户在浏览器中使用 JavaScript 发起网络请求时，QUIC 协议负责底层的数据传输。

* **例子：**  假设一个网页同时加载多个资源，例如 HTML 文件、CSS 文件、JavaScript 文件和图片。这些资源对应不同的 QUIC 流。`QuicWriteBlockedList` 负责决定哪些流的数据应该优先发送。例如，可能需要优先发送 HTML 文件，以便更快地渲染页面结构，而图片等资源的优先级可能较低。JavaScript 代码通过浏览器提供的 API (如 `fetch` 或 `XMLHttpRequest`) 发起这些请求，但底层的 QUIC 流管理和优先级控制是由 C++ 代码完成的。

**逻辑推理（假设输入与输出）：**

假设我们有以下场景：

**输入:**

1. 注册了三个非静态流，ID 分别为 10, 12, 14，优先级分别为 Lowest, Medium, Highest。
2. 所有三个流都因为发送缓冲区满而被阻塞，并被添加到 `QuicWriteBlockedList`。

**内部操作:**

`QuicWriteBlockedList` 会根据优先级对这些流进行排序。

**输出 (通过 `PopFront()` 获取解除阻塞的流的顺序):**

1. 流 14 (Highest 优先级)
2. 流 12 (Medium 优先级)
3. 流 10 (Lowest 优先级)

**用户或编程常见的使用错误：**

1. **未注册流就尝试操作:**  在调用 `AddStream`、`UpdateStreamPriority` 或 `UnregisterStream` 之前，必须先通过 `RegisterStream` 注册该流。如果未注册就操作，可能会导致程序崩溃或出现未定义的行为。例如，测试用例 `UnregisterNotRegisteredStream` 就展示了这种情况，预期会触发一个 BUG 断言。

   ```c++
   TEST_F(QuicWriteBlockedListTest, UnregisterNotRegisteredStream) {
     EXPECT_QUICHE_BUG(UnregisterStream(1), "Stream 1 not registered");
     // ...
   }
   ```

2. **尝试更新静态流的优先级:** 静态流的优先级通常是固定的，尝试使用 `UpdateStreamPriority` 修改静态流的优先级是不允许的。测试用例 `UpdateStaticStreamPriority` 演示了这一点，预期会触发一个调试断言。

   ```c++
   TEST_F(QuicWriteBlockedListTest, UpdateStaticStreamPriority) {
     RegisterStream(2, kStatic, {kV3LowestPriority, kNotIncremental});
     EXPECT_QUICHE_DEBUG_DEATH(
         UpdateStreamPriority(2, {kV3HighestPriority, kNotIncremental}),
         "IsRegistered");
   }
   ```

3. **重复添加已经阻塞的流:** 虽然 `QuicWriteBlockedList` 会防止重复添加，但开发者应该避免在知道流已经阻塞的情况下再次添加，这可能表示逻辑上的错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户报告某个网页加载缓慢，尤其是某些资源加载很慢甚至卡住。作为调试线索，我们可以沿着以下步骤追踪到 `QuicWriteBlockedList`：

1. **用户报告网页加载问题:** 用户反馈网页内容加载不全或速度很慢。
2. **开发者开始诊断:** 开发者首先会检查网络连接是否正常，服务器是否响应缓慢等。
3. **检查浏览器网络面板:** 使用 Chrome DevTools 的 Network 面板，开发者可以查看各个资源的加载情况，包括请求头、响应头、加载时间等。可能会发现某些资源的 Status 显示 Pending 或者 Transferring 卡住很长时间。
4. **关注 QUIC 连接:** 如果网页使用了 QUIC 协议（可以通过 Network 面板的 Protocol 列查看），那么问题可能出在 QUIC 连接的某个环节。
5. **深入 QUIC 协议栈调试:** 如果怀疑是 QUIC 的问题，开发者可能需要查看 Chromium 的内部日志或者使用更底层的网络抓包工具 (如 Wireshark) 来分析 QUIC 数据包的交互。
6. **关注流的发送情况:**  如果发现某些 QUIC 流的发送停滞不前，可能是因为发送缓冲区被阻塞。
7. **定位到 `QuicWriteBlockedList`:**  在 QUIC 协议栈的实现中，当一个流的发送缓冲区满时，该流会被添加到 `QuicWriteBlockedList` 中。开发者可能会查看与发送管理相关的代码，最终定位到 `QuicWriteBlockedList` 类，了解当前有哪些流被阻塞以及它们的优先级。
8. **分析优先级和调度:** 开发者会检查 `QuicWriteBlockedList` 的状态，查看阻塞的流的优先级，以及调度算法是否正常工作。例如，如果一个高优先级的流一直没有被发送，可能表明优先级设置或调度逻辑存在问题。
9. **查看相关配置和标志:** 有些行为可能受到配置标志的影响，例如是否启用批量写入。开发者可能需要检查这些标志的设置。例如，`QuicWriteBlockedListParameterizedTest` 就使用了 reloadable flags 来测试不同的行为。

因此，`quic_write_blocked_list_test.cc` 提供的测试用例可以帮助开发者验证 `QuicWriteBlockedList` 的行为是否符合预期，从而排查用户报告的网页加载缓慢等问题。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_write_blocked_list_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_write_blocked_list.h"

#include <optional>
#include <tuple>

#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"

using spdy::kV3HighestPriority;
using spdy::kV3LowestPriority;

namespace quic {
namespace test {
namespace {

constexpr bool kStatic = true;
constexpr bool kNotStatic = false;

constexpr bool kIncremental = true;
constexpr bool kNotIncremental = false;

class QuicWriteBlockedListTest : public QuicTest {
 protected:
  void SetUp() override {
    // Delay construction of QuicWriteBlockedList object to allow constructor of
    // derived test classes to manipulate reloadable flags that are latched in
    // QuicWriteBlockedList constructor.
    write_blocked_list_.emplace();
  }

  bool HasWriteBlockedDataStreams() const {
    return write_blocked_list_->HasWriteBlockedDataStreams();
  }

  bool HasWriteBlockedSpecialStream() const {
    return write_blocked_list_->HasWriteBlockedSpecialStream();
  }

  size_t NumBlockedSpecialStreams() const {
    return write_blocked_list_->NumBlockedSpecialStreams();
  }

  size_t NumBlockedStreams() const {
    return write_blocked_list_->NumBlockedStreams();
  }

  bool ShouldYield(QuicStreamId id) const {
    return write_blocked_list_->ShouldYield(id);
  }

  QuicStreamPriority GetPriorityOfStream(QuicStreamId id) const {
    return write_blocked_list_->GetPriorityOfStream(id);
  }

  QuicStreamId PopFront() { return write_blocked_list_->PopFront(); }

  void RegisterStream(QuicStreamId stream_id, bool is_static_stream,
                      const HttpStreamPriority& priority) {
    write_blocked_list_->RegisterStream(stream_id, is_static_stream,
                                        QuicStreamPriority(priority));
  }

  void UnregisterStream(QuicStreamId stream_id) {
    write_blocked_list_->UnregisterStream(stream_id);
  }

  void UpdateStreamPriority(QuicStreamId stream_id,
                            const HttpStreamPriority& new_priority) {
    write_blocked_list_->UpdateStreamPriority(stream_id,
                                              QuicStreamPriority(new_priority));
  }

  void UpdateBytesForStream(QuicStreamId stream_id, size_t bytes) {
    write_blocked_list_->UpdateBytesForStream(stream_id, bytes);
  }

  void AddStream(QuicStreamId stream_id) {
    write_blocked_list_->AddStream(stream_id);
  }

  bool IsStreamBlocked(QuicStreamId stream_id) const {
    return write_blocked_list_->IsStreamBlocked(stream_id);
  }

 private:
  std::optional<QuicWriteBlockedList> write_blocked_list_;
};

TEST_F(QuicWriteBlockedListTest, PriorityOrder) {
  // Mark streams blocked in roughly reverse priority order, and
  // verify that streams are sorted.
  RegisterStream(40, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(23, kNotStatic, {kV3HighestPriority, kIncremental});
  RegisterStream(17, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(1, kStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(3, kStatic, {kV3HighestPriority, kNotIncremental});

  EXPECT_EQ(kV3LowestPriority, GetPriorityOfStream(40).http().urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityOfStream(40).http().incremental);

  EXPECT_EQ(kV3HighestPriority, GetPriorityOfStream(23).http().urgency);
  EXPECT_EQ(kIncremental, GetPriorityOfStream(23).http().incremental);

  EXPECT_EQ(kV3HighestPriority, GetPriorityOfStream(17).http().urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityOfStream(17).http().incremental);

  AddStream(40);
  EXPECT_TRUE(IsStreamBlocked(40));
  AddStream(23);
  EXPECT_TRUE(IsStreamBlocked(23));
  AddStream(17);
  EXPECT_TRUE(IsStreamBlocked(17));
  AddStream(3);
  EXPECT_TRUE(IsStreamBlocked(3));
  AddStream(1);
  EXPECT_TRUE(IsStreamBlocked(1));

  EXPECT_EQ(5u, NumBlockedStreams());
  EXPECT_TRUE(HasWriteBlockedSpecialStream());
  EXPECT_EQ(2u, NumBlockedSpecialStreams());
  EXPECT_TRUE(HasWriteBlockedDataStreams());

  // Static streams are highest priority, regardless of priority value.
  EXPECT_EQ(1u, PopFront());
  EXPECT_EQ(1u, NumBlockedSpecialStreams());
  EXPECT_FALSE(IsStreamBlocked(1));

  EXPECT_EQ(3u, PopFront());
  EXPECT_EQ(0u, NumBlockedSpecialStreams());
  EXPECT_FALSE(IsStreamBlocked(3));

  // Streams with same priority are popped in the order they were inserted.
  EXPECT_EQ(23u, PopFront());
  EXPECT_FALSE(IsStreamBlocked(23));
  EXPECT_EQ(17u, PopFront());
  EXPECT_FALSE(IsStreamBlocked(17));

  // Low priority stream appears last.
  EXPECT_EQ(40u, PopFront());
  EXPECT_FALSE(IsStreamBlocked(40));

  EXPECT_EQ(0u, NumBlockedStreams());
  EXPECT_FALSE(HasWriteBlockedSpecialStream());
  EXPECT_FALSE(HasWriteBlockedDataStreams());
}

TEST_F(QuicWriteBlockedListTest, SingleStaticStream) {
  RegisterStream(5, kStatic, {kV3HighestPriority, kNotIncremental});
  AddStream(5);

  EXPECT_EQ(1u, NumBlockedStreams());
  EXPECT_TRUE(HasWriteBlockedSpecialStream());
  EXPECT_EQ(5u, PopFront());
  EXPECT_EQ(0u, NumBlockedStreams());
  EXPECT_FALSE(HasWriteBlockedSpecialStream());
}

TEST_F(QuicWriteBlockedListTest, StaticStreamsComeFirst) {
  RegisterStream(5, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(3, kStatic, {kV3LowestPriority, kNotIncremental});
  AddStream(5);
  AddStream(3);

  EXPECT_EQ(2u, NumBlockedStreams());
  EXPECT_TRUE(HasWriteBlockedSpecialStream());
  EXPECT_TRUE(HasWriteBlockedDataStreams());

  EXPECT_EQ(3u, PopFront());
  EXPECT_EQ(5u, PopFront());

  EXPECT_EQ(0u, NumBlockedStreams());
  EXPECT_FALSE(HasWriteBlockedSpecialStream());
  EXPECT_FALSE(HasWriteBlockedDataStreams());
}

TEST_F(QuicWriteBlockedListTest, NoDuplicateEntries) {
  // Test that QuicWriteBlockedList doesn't allow duplicate entries.
  // Try to add a stream to the write blocked list multiple times at the same
  // priority.
  const QuicStreamId kBlockedId = 5;
  RegisterStream(kBlockedId, kNotStatic, {kV3HighestPriority, kNotIncremental});
  AddStream(kBlockedId);
  AddStream(kBlockedId);
  AddStream(kBlockedId);

  // This should only result in one blocked stream being added.
  EXPECT_EQ(1u, NumBlockedStreams());
  EXPECT_TRUE(HasWriteBlockedDataStreams());

  // There should only be one stream to pop off the front.
  EXPECT_EQ(kBlockedId, PopFront());
  EXPECT_EQ(0u, NumBlockedStreams());
  EXPECT_FALSE(HasWriteBlockedDataStreams());
}

TEST_F(QuicWriteBlockedListTest, IncrementalStreamsRoundRobin) {
  const QuicStreamId id1 = 5;
  const QuicStreamId id2 = 7;
  const QuicStreamId id3 = 9;
  RegisterStream(id1, kNotStatic, {kV3LowestPriority, kIncremental});
  RegisterStream(id2, kNotStatic, {kV3LowestPriority, kIncremental});
  RegisterStream(id3, kNotStatic, {kV3LowestPriority, kIncremental});

  AddStream(id1);
  AddStream(id2);
  AddStream(id3);

  EXPECT_EQ(id1, PopFront());
  const size_t kLargeWriteSize = 1000 * 1000 * 1000;
  UpdateBytesForStream(id1, kLargeWriteSize);
  AddStream(id1);

  EXPECT_EQ(id2, PopFront());
  UpdateBytesForStream(id2, kLargeWriteSize);
  EXPECT_EQ(id3, PopFront());
  UpdateBytesForStream(id3, kLargeWriteSize);

  AddStream(id3);
  AddStream(id2);

  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kLargeWriteSize);
  EXPECT_EQ(id3, PopFront());
  UpdateBytesForStream(id3, kLargeWriteSize);
  AddStream(id3);

  EXPECT_EQ(id2, PopFront());
  EXPECT_EQ(id3, PopFront());
}

class QuicWriteBlockedListParameterizedTest
    : public QuicWriteBlockedListTest,
      public ::testing::WithParamInterface<std::tuple<bool, bool>> {
 protected:
  QuicWriteBlockedListParameterizedTest()
      : priority_respect_incremental_(std::get<0>(GetParam())),
        disable_batch_write_(std::get<1>(GetParam())) {
    SetQuicReloadableFlag(quic_priority_respect_incremental,
                          priority_respect_incremental_);
    SetQuicReloadableFlag(quic_disable_batch_write, disable_batch_write_);
  }

  const bool priority_respect_incremental_;
  const bool disable_batch_write_;
};

INSTANTIATE_TEST_SUITE_P(
    BatchWrite, QuicWriteBlockedListParameterizedTest,
    ::testing::Combine(::testing::Bool(), ::testing::Bool()),
    [](const testing::TestParamInfo<
        QuicWriteBlockedListParameterizedTest::ParamType>& info) {
      return absl::StrCat(std::get<0>(info.param) ? "RespectIncrementalTrue"
                                                  : "RespectIncrementalFalse",
                          std::get<1>(info.param) ? "DisableBatchWriteTrue"
                                                  : "DisableBatchWriteFalse");
    });

// If reloadable_flag_quic_disable_batch_write is false, writes are batched.
TEST_P(QuicWriteBlockedListParameterizedTest, BatchingWrites) {
  if (disable_batch_write_) {
    return;
  }

  const QuicStreamId id1 = 5;
  const QuicStreamId id2 = 7;
  const QuicStreamId id3 = 9;
  RegisterStream(id1, kNotStatic, {kV3LowestPriority, kIncremental});
  RegisterStream(id2, kNotStatic, {kV3LowestPriority, kIncremental});
  RegisterStream(id3, kNotStatic, {kV3HighestPriority, kIncremental});

  AddStream(id1);
  AddStream(id2);
  EXPECT_EQ(2u, NumBlockedStreams());

  // The first stream we push back should stay at the front until 16k is
  // written.
  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, 15999);
  AddStream(id1);
  EXPECT_EQ(2u, NumBlockedStreams());
  EXPECT_EQ(id1, PopFront());

  // Once 16k is written the first stream will yield to the next.
  UpdateBytesForStream(id1, 1);
  AddStream(id1);
  EXPECT_EQ(2u, NumBlockedStreams());
  EXPECT_EQ(id2, PopFront());

  // Set the new stream to have written all but one byte.
  UpdateBytesForStream(id2, 15999);
  AddStream(id2);
  EXPECT_EQ(2u, NumBlockedStreams());

  // Ensure higher priority streams are popped first.
  AddStream(id3);
  EXPECT_EQ(id3, PopFront());

  // Higher priority streams will always be popped first, even if using their
  // byte quota
  UpdateBytesForStream(id3, 20000);
  AddStream(id3);
  EXPECT_EQ(id3, PopFront());

  // Once the higher priority stream is out of the way, id2 will resume its 16k
  // write, with only 1 byte remaining of its guaranteed write allocation.
  EXPECT_EQ(id2, PopFront());
  UpdateBytesForStream(id2, 1);
  AddStream(id2);
  EXPECT_EQ(2u, NumBlockedStreams());
  EXPECT_EQ(id1, PopFront());
}

// If reloadable_flag_quic_disable_batch_write is true, writes are performed
// round-robin regardless of how little data is written on each stream.
TEST_P(QuicWriteBlockedListParameterizedTest, RoundRobin) {
  if (!disable_batch_write_) {
    return;
  }

  const QuicStreamId id1 = 5;
  const QuicStreamId id2 = 7;
  const QuicStreamId id3 = 9;
  RegisterStream(id1, kNotStatic, {kV3LowestPriority, kIncremental});
  RegisterStream(id2, kNotStatic, {kV3LowestPriority, kIncremental});
  RegisterStream(id3, kNotStatic, {kV3LowestPriority, kIncremental});

  AddStream(id1);
  AddStream(id2);
  AddStream(id3);

  EXPECT_EQ(id1, PopFront());
  AddStream(id1);

  EXPECT_EQ(id2, PopFront());
  EXPECT_EQ(id3, PopFront());

  AddStream(id3);
  AddStream(id2);

  EXPECT_EQ(id1, PopFront());
  EXPECT_EQ(id3, PopFront());
  AddStream(id3);

  EXPECT_EQ(id2, PopFront());
  EXPECT_EQ(id3, PopFront());
}

TEST_P(QuicWriteBlockedListParameterizedTest,
       NonIncrementalStreamsKeepWriting) {
  if (!priority_respect_incremental_) {
    return;
  }

  const QuicStreamId id1 = 1;
  const QuicStreamId id2 = 2;
  const QuicStreamId id3 = 3;
  const QuicStreamId id4 = 4;
  RegisterStream(id1, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(id2, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(id3, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(id4, kNotStatic, {kV3HighestPriority, kNotIncremental});

  AddStream(id1);
  AddStream(id2);
  AddStream(id3);

  // A non-incremental stream can continue writing as long as it has data.
  EXPECT_EQ(id1, PopFront());
  const size_t kLargeWriteSize = 1000 * 1000 * 1000;
  UpdateBytesForStream(id1, kLargeWriteSize);
  AddStream(id1);

  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kLargeWriteSize);
  AddStream(id1);

  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kLargeWriteSize);
  AddStream(id1);

  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kLargeWriteSize);
  AddStream(id1);

  // A higher priority stream takes precedence.
  AddStream(id4);
  EXPECT_EQ(id4, PopFront());

  // When it is the turn of the lower urgency bucket again, writing of the first
  // stream will continue.
  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kLargeWriteSize);

  // When there is no more data on the first stream, write can start on the
  // second stream.
  EXPECT_EQ(id2, PopFront());
  UpdateBytesForStream(id2, kLargeWriteSize);
  AddStream(id2);

  // Write continues without limit.
  EXPECT_EQ(id2, PopFront());
  UpdateBytesForStream(id2, kLargeWriteSize);
  AddStream(id2);

  // Stream 1 is not the most recently written one, therefore it gets to the end
  // of the dequeue.
  AddStream(id1);

  EXPECT_EQ(id2, PopFront());
  UpdateBytesForStream(id2, kLargeWriteSize);

  EXPECT_EQ(id3, PopFront());
  UpdateBytesForStream(id2, kLargeWriteSize);
  AddStream(id3);

  EXPECT_EQ(id3, PopFront());
  UpdateBytesForStream(id2, kLargeWriteSize);

  // When there is no data to write either on stream 2 or stream 3, stream 1 can
  // resume.
  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kLargeWriteSize);
}

TEST_P(QuicWriteBlockedListParameterizedTest,
       IncrementalAndNonIncrementalStreams) {
  if (!priority_respect_incremental_) {
    return;
  }

  const QuicStreamId id1 = 1;
  const QuicStreamId id2 = 2;
  RegisterStream(id1, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(id2, kNotStatic, {kV3LowestPriority, kIncremental});

  AddStream(id1);
  AddStream(id2);

  // A non-incremental stream can continue writing as long as it has data.
  EXPECT_EQ(id1, PopFront());
  const size_t kSmallWriteSize = 1000;
  UpdateBytesForStream(id1, kSmallWriteSize);
  AddStream(id1);

  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kSmallWriteSize);
  AddStream(id1);

  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kSmallWriteSize);

  EXPECT_EQ(id2, PopFront());
  UpdateBytesForStream(id2, kSmallWriteSize);
  AddStream(id2);
  AddStream(id1);

  if (!disable_batch_write_) {
    // Small writes do not exceed the batch limit.
    // Writes continue even on an incremental stream.
    EXPECT_EQ(id2, PopFront());
    UpdateBytesForStream(id2, kSmallWriteSize);
    AddStream(id2);

    EXPECT_EQ(id2, PopFront());
    UpdateBytesForStream(id2, kSmallWriteSize);
  }

  EXPECT_EQ(id1, PopFront());
  const size_t kLargeWriteSize = 1000 * 1000 * 1000;
  UpdateBytesForStream(id1, kLargeWriteSize);
  AddStream(id1);

  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kLargeWriteSize);
  AddStream(id1);

  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kLargeWriteSize);
  AddStream(id2);
  AddStream(id1);

  // When batch writing is disabled, stream 2 immediately yields to stream 1,
  // which is the non-incremental stream with most recent writes.
  // When batch writing is enabled, stream 2 only yields to stream 1 after
  // exceeding the batching limit.
  if (!disable_batch_write_) {
    EXPECT_EQ(id2, PopFront());
    UpdateBytesForStream(id2, kLargeWriteSize);
    AddStream(id2);
  }

  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, kLargeWriteSize);
}

TEST_F(QuicWriteBlockedListTest, Ceding) {
  RegisterStream(15, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(16, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(5, kNotStatic, {5, kNotIncremental});
  RegisterStream(4, kNotStatic, {5, kNotIncremental});
  RegisterStream(7, kNotStatic, {7, kNotIncremental});
  RegisterStream(1, kStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(3, kStatic, {kV3HighestPriority, kNotIncremental});

  // When nothing is on the list, nothing yields.
  EXPECT_FALSE(ShouldYield(5));

  AddStream(5);
  // 5 should not yield to itself.
  EXPECT_FALSE(ShouldYield(5));
  // 4 and 7 are equal or lower priority and should yield to 5.
  EXPECT_TRUE(ShouldYield(4));
  EXPECT_TRUE(ShouldYield(7));
  // Stream 15 and static streams should preempt 5.
  EXPECT_FALSE(ShouldYield(15));
  EXPECT_FALSE(ShouldYield(3));
  EXPECT_FALSE(ShouldYield(1));

  // Block a high priority stream.
  AddStream(15);
  // 16 should yield (same priority) but static streams will still not.
  EXPECT_TRUE(ShouldYield(16));
  EXPECT_FALSE(ShouldYield(3));
  EXPECT_FALSE(ShouldYield(1));

  // Block a static stream.  All non-static streams should yield.
  AddStream(3);
  EXPECT_TRUE(ShouldYield(16));
  EXPECT_TRUE(ShouldYield(15));
  EXPECT_FALSE(ShouldYield(3));
  EXPECT_FALSE(ShouldYield(1));

  // Block the other static stream.  All other streams should yield.
  AddStream(1);
  EXPECT_TRUE(ShouldYield(16));
  EXPECT_TRUE(ShouldYield(15));
  EXPECT_TRUE(ShouldYield(3));
  EXPECT_FALSE(ShouldYield(1));
}

TEST_F(QuicWriteBlockedListTest, UnregisterStream) {
  RegisterStream(40, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(23, kNotStatic, {6, kNotIncremental});
  RegisterStream(12, kNotStatic, {3, kNotIncremental});
  RegisterStream(17, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(1, kStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(3, kStatic, {kV3HighestPriority, kNotIncremental});

  AddStream(40);
  AddStream(23);
  AddStream(12);
  AddStream(17);
  AddStream(1);
  AddStream(3);

  UnregisterStream(23);
  UnregisterStream(1);

  EXPECT_EQ(3u, PopFront());
  EXPECT_EQ(17u, PopFront());
  EXPECT_EQ(12u, PopFront());
  EXPECT_EQ(40, PopFront());
}

TEST_F(QuicWriteBlockedListTest, UnregisterNotRegisteredStream) {
  EXPECT_QUICHE_BUG(UnregisterStream(1), "Stream 1 not registered");

  RegisterStream(2, kNotStatic, {kV3HighestPriority, kIncremental});
  UnregisterStream(2);
  EXPECT_QUICHE_BUG(UnregisterStream(2), "Stream 2 not registered");
}

TEST_F(QuicWriteBlockedListTest, UpdateStreamPriority) {
  RegisterStream(40, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(23, kNotStatic, {6, kIncremental});
  RegisterStream(17, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(1, kStatic, {2, kNotIncremental});
  RegisterStream(3, kStatic, {kV3HighestPriority, kNotIncremental});

  EXPECT_EQ(kV3LowestPriority, GetPriorityOfStream(40).http().urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityOfStream(40).http().incremental);

  EXPECT_EQ(6, GetPriorityOfStream(23).http().urgency);
  EXPECT_EQ(kIncremental, GetPriorityOfStream(23).http().incremental);

  EXPECT_EQ(kV3HighestPriority, GetPriorityOfStream(17).http().urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityOfStream(17).http().incremental);

  UpdateStreamPriority(40, {3, kIncremental});
  UpdateStreamPriority(23, {kV3HighestPriority, kNotIncremental});
  UpdateStreamPriority(17, {5, kNotIncremental});

  EXPECT_EQ(3, GetPriorityOfStream(40).http().urgency);
  EXPECT_EQ(kIncremental, GetPriorityOfStream(40).http().incremental);

  EXPECT_EQ(kV3HighestPriority, GetPriorityOfStream(23).http().urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityOfStream(23).http().incremental);

  EXPECT_EQ(5, GetPriorityOfStream(17).http().urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityOfStream(17).http().incremental);

  AddStream(40);
  AddStream(23);
  AddStream(17);
  AddStream(1);
  AddStream(3);

  EXPECT_EQ(1u, PopFront());
  EXPECT_EQ(3u, PopFront());
  EXPECT_EQ(23u, PopFront());
  EXPECT_EQ(40u, PopFront());
  EXPECT_EQ(17u, PopFront());
}

// UpdateStreamPriority() must not be called for static streams.
TEST_F(QuicWriteBlockedListTest, UpdateStaticStreamPriority) {
  RegisterStream(2, kStatic, {kV3LowestPriority, kNotIncremental});
  EXPECT_QUICHE_DEBUG_DEATH(
      UpdateStreamPriority(2, {kV3HighestPriority, kNotIncremental}),
      "IsRegistered");
}

TEST_F(QuicWriteBlockedListTest, UpdateStreamPrioritySameUrgency) {
  // Streams with same urgency are returned by PopFront() in the order they were
  // added by AddStream().
  RegisterStream(1, kNotStatic, {6, kNotIncremental});
  RegisterStream(2, kNotStatic, {6, kNotIncremental});

  AddStream(1);
  AddStream(2);

  EXPECT_EQ(1u, PopFront());
  EXPECT_EQ(2u, PopFront());

  // Calling UpdateStreamPriority() on the first stream does not change the
  // order.
  RegisterStream(3, kNotStatic, {6, kNotIncremental});
  RegisterStream(4, kNotStatic, {6, kNotIncremental});

  EXPECT_EQ(6, GetPriorityOfStream(3).http().urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityOfStream(3).http().incremental);

  UpdateStreamPriority(3, {6, kIncremental});

  EXPECT_EQ(6, GetPriorityOfStream(3).http().urgency);
  EXPECT_EQ(kIncremental, GetPriorityOfStream(3).http().incremental);

  AddStream(3);
  AddStream(4);

  EXPECT_EQ(3u, PopFront());
  EXPECT_EQ(4u, PopFront());

  // Calling UpdateStreamPriority() on the second stream does not change the
  // order.
  RegisterStream(5, kNotStatic, {6, kIncremental});
  RegisterStream(6, kNotStatic, {6, kIncremental});

  EXPECT_EQ(6, GetPriorityOfStream(6).http().urgency);
  EXPECT_EQ(kIncremental, GetPriorityOfStream(6).http().incremental);

  UpdateStreamPriority(6, {6, kNotIncremental});

  EXPECT_EQ(6, GetPriorityOfStream(6).http().urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityOfStream(6).http().incremental);

  AddStream(5);
  AddStream(6);

  EXPECT_EQ(5u, PopFront());
  EXPECT_EQ(6u, PopFront());
}

}  // namespace
}  // namespace test
}  // namespace quic

"""

```