Response:
The user wants to understand the functionality of the C++ source code file `moqt_live_relay_queue_test.cc`. They are particularly interested in:

1. **Functionality:** What does this code do?
2. **JavaScript Relation:**  Is there any connection to JavaScript?
3. **Logic Inference:** Can I provide examples of inputs and expected outputs?
4. **Common Errors:** What are typical user or programming errors related to this code?
5. **Debugging Context:** How does a user end up at this point in the code during debugging?

**Plan:**

1. **High-Level Functionality:**  Recognize that this is a test file for `MoqtLiveRelayQueue`. The primary function is to verify the behavior of the queue under different scenarios.
2. **JavaScript Analysis:** Determine if the functionality has any direct ties to JavaScript. Given that it's a C++ networking stack component, the connection is likely indirect, focusing on how the network data is eventually used by JavaScript in a browser.
3. **Input/Output Examples:**  Focus on the test cases. Each `TEST` block sets up specific inputs (adding objects to the queue) and defines expected outputs (calls to mock methods like `PublishObject`, `CloseStreamForGroup`, etc.). I can extract these patterns.
4. **Common Errors:**  Think about what could go wrong when *using* the `MoqtLiveRelayQueue` class (even though this is a test). Errors could involve incorrect object ordering, misuse of status flags, etc.
5. **Debugging Steps:** Imagine a scenario where a developer is investigating issues related to live media streaming or data delivery within the Chromium network stack. How would they narrow down the problem to this specific component?
这个C++源代码文件 `moqt_live_relay_queue_test.cc` 是 Chromium 网络栈中 QUIC 协议的 MoQT (Media over QUIC Transport) 组件的一个测试文件。它的主要功能是 **测试 `MoqtLiveRelayQueue` 类的行为和功能**。

具体来说，这个测试文件通过以下方式来验证 `MoqtLiveRelayQueue` 类的功能：

1. **创建测试用例:**  定义了多个 `TEST` 函数，每个函数针对 `MoqtLiveRelayQueue` 类的特定场景或功能进行测试。
2. **使用 Mock 对象:**  创建了一个名为 `TestMoqtLiveRelayQueue` 的类，它继承自 `MoqtLiveRelayQueue` 并实现了 `MoqtObjectListener` 接口。这个类使用了 Google Mock 框架，允许模拟 `MoqtLiveRelayQueue` 在接收到对象后的行为，例如 `PublishObject`，`CloseStreamForGroup` 等。
3. **模拟对象添加:**  在每个测试用例中，通过 `AddObject` 方法向 `TestMoqtLiveRelayQueue` 对象添加不同状态和内容的媒体对象。
4. **验证方法调用:**  使用 Google Mock 的断言 (`EXPECT_CALL`) 来验证在特定输入下，`MoqtLiveRelayQueue` 是否按照预期调用了模拟的方法，并传递了正确的参数。
5. **覆盖多种场景:**  测试用例覆盖了各种场景，例如：
    * 单个或多个媒体组 (group) 的发布。
    * 在发布过程中标记组结束或流结束。
    * 模拟订阅者回溯订阅 (past subscribe) 的场景，验证如何处理已缓存的对象。
    * 处理对象不存在或组不存在的情况。
    * 处理不同的子组 (subgroup) 的情况。
    * 尝试覆盖已存在的对象。

**它与 JavaScript 的功能关系：**

`MoqtLiveRelayQueue` 本身是用 C++ 实现的，运行在 Chromium 的网络进程中，并不直接与 JavaScript 代码交互。然而，它的功能是为基于 QUIC 的媒体传输提供支持，这最终会影响到网页上的 JavaScript 代码如何接收和处理媒体数据。

**举例说明:**

假设一个网页使用 JavaScript 的 Media Source Extensions (MSE) API 来接收和渲染通过 MoQT 传输的实时视频流。

1. **发布者 (Publisher):**  Chromium 的网络栈中的 MoQT 发布者将视频帧编码后，通过 `MoqtLiveRelayQueue` 进行缓存和管理。
2. **订阅者 (Subscriber):** 当网页上的 JavaScript 代码发起订阅请求时，`MoqtLiveRelayQueue` 会根据订阅窗口 (SubscribeWindow) 将缓存的视频帧（作为 "object"）传递给网络栈的下游组件，最终通过 QUIC 连接发送给客户端。
3. **JavaScript 接收:** 客户端浏览器接收到这些视频帧后，JavaScript 代码会通过 MSE API 将这些帧添加到 `<video>` 元素的缓冲区中，从而实现视频的播放。

在这个过程中，`MoqtLiveRelayQueue` 的功能确保了：

* **有序交付:**  按照正确的顺序缓存和传递媒体对象。
* **回溯订阅支持:**  能够根据订阅者的请求，提供过去已发布的媒体对象。
* **资源管理:**  有效地管理缓存的媒体数据。

**逻辑推理的假设输入与输出：**

**假设输入:**

```c++
TEST(MoqtLiveRelayQueueExample, BasicPublishing) {
  TestMoqtLiveRelayQueue queue;
  // 假设我们向队列添加了三个对象，属于 group 0
  queue.AddObject(FullSequence{0, 0}, "frame1");
  queue.AddObject(FullSequence{0, 1}, "frame2");
  queue.AddObject(FullSequence{0, 2}, "frame3");
  queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup);
}
```

**预期输出 (通过 `EXPECT_CALL` 验证):**

```c++
  EXPECT_CALL(queue, PublishObject(0, 0, "frame1"));
  EXPECT_CALL(queue, PublishObject(0, 1, "frame2"));
  EXPECT_CALL(queue, PublishObject(0, 2, "frame3"));
  EXPECT_CALL(queue, CloseStreamForGroup(0));
```

**解释:**  当添加了三个数据对象和一个组结束标记后，我们期望 `MoqtLiveRelayQueue` 依次调用 `PublishObject` 方法将三个帧发布出去，并在最后调用 `CloseStreamForGroup` 方法表示该组结束。

**涉及用户或者编程常见的使用错误，并举例说明：**

1. **乱序添加对象:** 用户或编程错误可能导致向 `MoqtLiveRelayQueue` 添加对象的顺序不正确，例如：

   ```c++
   queue.AddObject(FullSequence{0, 1}, "frame2"); // 错误：先添加了 object_id 为 1 的对象
   queue.AddObject(FullSequence{0, 0}, "frame1");
   ```

   `MoqtLiveRelayQueue` 可能会根据其内部逻辑处理这种情况，但如果依赖严格的顺序，可能会导致意外的行为。

2. **错误地使用状态标记:**  错误地使用了 `MoqtObjectStatus`，例如在没有发布所有对象的情况下就标记了 `kEndOfGroup`：

   ```c++
   queue.AddObject(FullSequence{0, 0}, "frame1");
   queue.AddObject(FullSequence{0, 1}, MoqtObjectStatus::kEndOfGroup); // 错误：可能还有其他对象没有发布
   queue.AddObject(FullSequence{0, 2}, "frame3"); // 这条数据可能不会被正确处理
   ```

3. **尝试覆盖已发布的对象:**  `MoqtLiveRelayQueue` 通常不允许覆盖已经发布的对象，尝试这样做会导致错误或被忽略：

   ```c++
   queue.AddObject(FullSequence{0, 0}, "frame1");
   queue.AddObject(FullSequence{0, 0}, "frame1_updated"); // 错误：尝试覆盖
   ```

   在测试代码中，可以看到 `TEST(MoqtLiveRelayQueue, OverwriteObject)` 就是用来测试这种情况的。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用一个在线视频会议应用，该应用使用了 Chromium 内核。用户遇到了视频播放卡顿或者回溯播放不正常的问题。作为 Chromium 的开发者，为了调试这个问题，可能会进行以下步骤：

1. **定位网络请求:**  使用 Chromium 的网络调试工具 (chrome://net-internals) 查看与视频流相关的 QUIC 连接。
2. **查看 MoQT 相关日志:**  启用 MoQT 的 debug 日志，查看是否有异常信息，例如对象丢失、乱序等。
3. **追踪代码执行路径:**  如果怀疑是 `MoqtLiveRelayQueue` 的问题，可能会设置断点在 `MoqtLiveRelayQueue` 的 `AddObject`，`PublishObject` 等方法上。
4. **分析调用堆栈:** 当断点触发时，查看调用堆栈，可以追溯到是谁在向 `MoqtLiveRelayQueue` 添加对象，以及添加的对象的状态。
5. **查看测试用例:**  可能会查看 `moqt_live_relay_queue_test.cc` 中的测试用例，特别是那些与回溯订阅 (`CallSubscribeForPast`) 或组结束相关的测试，来理解 `MoqtLiveRelayQueue` 在这些场景下的预期行为。

通过以上步骤，开发者可以逐步缩小问题范围，最终可能定位到 `MoqtLiveRelayQueue` 的具体代码逻辑，并利用测试文件中的用例来验证修复方案。例如，如果发现回溯播放有问题，可能会仔细分析 `TEST(MoqtLiveRelayQueue, ...PastSubscribe...)` 相关的测试用例。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_live_relay_queue_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_live_relay_queue.h"

#include <cstdint>
#include <optional>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_subscribe_windows.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt::test {

namespace {

class TestMoqtLiveRelayQueue : public MoqtLiveRelayQueue,
                               public MoqtObjectListener {
 public:
  TestMoqtLiveRelayQueue()
      : MoqtLiveRelayQueue(FullTrackName{"test", "track"},
                           MoqtForwardingPreference::kSubgroup) {
    AddObjectListener(this);
  }

  void OnNewObjectAvailable(FullSequence sequence) {
    std::optional<PublishedObject> object = GetCachedObject(sequence);
    QUICHE_CHECK(object.has_value());
    switch (object->status) {
      case MoqtObjectStatus::kNormal:
        PublishObject(object->sequence.group, object->sequence.object,
                      object->payload.AsStringView());
        break;
      case MoqtObjectStatus::kObjectDoesNotExist:
        SkipObject(object->sequence.group, object->sequence.object);
        break;
      case MoqtObjectStatus::kGroupDoesNotExist:
        SkipGroup(object->sequence.group);
        break;
      case MoqtObjectStatus::kEndOfGroup:
        CloseStreamForGroup(object->sequence.group);
        break;
      case MoqtObjectStatus::kEndOfTrack:
        CloseTrack();
        break;
      case moqt::MoqtObjectStatus::kEndOfSubgroup:
        CloseStreamForSubgroup(object->sequence.group,
                               object->sequence.subgroup);
        break;
      default:
        EXPECT_TRUE(false);
    }
  }

  void CallSubscribeForPast(const SubscribeWindow& window) {
    std::vector<FullSequence> objects =
        GetCachedObjectsInRange(FullSequence(0, 0), GetLargestSequence());
    for (FullSequence object : objects) {
      if (window.InWindow(object)) {
        OnNewObjectAvailable(object);
      }
    }
  }

  MOCK_METHOD(void, CloseStreamForGroup, (uint64_t group_id), ());
  MOCK_METHOD(void, CloseStreamForSubgroup,
              (uint64_t group_id, uint64_t subgroup_id), ());
  MOCK_METHOD(void, PublishObject,
              (uint64_t group_id, uint64_t object_id,
               absl::string_view payload),
              ());
  MOCK_METHOD(void, SkipObject, (uint64_t group_id, uint64_t object_id), ());
  MOCK_METHOD(void, SkipGroup, (uint64_t group_id), ());
  MOCK_METHOD(void, CloseTrack, (), ());
  MOCK_METHOD(void, OnTrackPublisherGone, (), (override));
};

// Duplicates of MoqtOutgoingQueue test cases.
TEST(MoqtLiveRelayQueue, SingleGroup) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup));
}

TEST(MoqtLiveRelayQueue, SingleGroupPastSubscribeFromZero) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));

    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  queue.CallSubscribeForPast(SubscribeWindow(0, 0));
}

TEST(MoqtLiveRelayQueue, SingleGroupPastSubscribeFromMidGroup) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));

    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  queue.CallSubscribeForPast(SubscribeWindow(0, 1));
}

TEST(MoqtLiveRelayQueue, TwoGroups) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "d"));
    EXPECT_CALL(queue, PublishObject(1, 1, "e"));
    EXPECT_CALL(queue, PublishObject(1, 2, "f"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 0}, "d"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 1}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 2}, "f"));
}

TEST(MoqtLiveRelayQueue, TwoGroupsPastSubscribe) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "d"));
    EXPECT_CALL(queue, PublishObject(1, 1, "e"));
    EXPECT_CALL(queue, PublishObject(1, 2, "f"));

    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "d"));
    EXPECT_CALL(queue, PublishObject(1, 1, "e"));
    EXPECT_CALL(queue, PublishObject(1, 2, "f"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 0}, "d"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 1}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 2}, "f"));
  queue.CallSubscribeForPast(SubscribeWindow(0, 1));
}

TEST(MoqtLiveRelayQueue, FiveGroups) {
  TestMoqtLiveRelayQueue queue;
  ;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "c"));
    EXPECT_CALL(queue, PublishObject(1, 1, "d"));
    EXPECT_CALL(queue, CloseStreamForGroup(1));
    EXPECT_CALL(queue, PublishObject(2, 0, "e"));
    EXPECT_CALL(queue, PublishObject(2, 1, "f"));
    EXPECT_CALL(queue, CloseStreamForGroup(2));
    EXPECT_CALL(queue, PublishObject(3, 0, "g"));
    EXPECT_CALL(queue, PublishObject(3, 1, "h"));
    EXPECT_CALL(queue, CloseStreamForGroup(3));
    EXPECT_CALL(queue, PublishObject(4, 0, "i"));
    EXPECT_CALL(queue, PublishObject(4, 1, "j"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 0}, "c"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 1}, "d"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{1, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 0}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 1}, "f"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{2, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 0}, "g"));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 1}, "h"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{3, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 0}, "i"));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 1}, "j"));
}

TEST(MoqtLiveRelayQueue, FiveGroupsPastSubscribe) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "c"));
    EXPECT_CALL(queue, PublishObject(1, 1, "d"));
    EXPECT_CALL(queue, CloseStreamForGroup(1));
    EXPECT_CALL(queue, PublishObject(2, 0, "e"));
    EXPECT_CALL(queue, PublishObject(2, 1, "f"));
    EXPECT_CALL(queue, CloseStreamForGroup(2));
    EXPECT_CALL(queue, PublishObject(3, 0, "g"));
    EXPECT_CALL(queue, PublishObject(3, 1, "h"));
    EXPECT_CALL(queue, CloseStreamForGroup(3));
    EXPECT_CALL(queue, PublishObject(4, 0, "i"));
    EXPECT_CALL(queue, PublishObject(4, 1, "j"));

    // Past SUBSCRIBE would only get the three most recent groups.
    EXPECT_CALL(queue, PublishObject(2, 0, "e"));
    EXPECT_CALL(queue, PublishObject(2, 1, "f"));
    EXPECT_CALL(queue, CloseStreamForGroup(2));
    EXPECT_CALL(queue, PublishObject(3, 0, "g"));
    EXPECT_CALL(queue, PublishObject(3, 1, "h"));
    EXPECT_CALL(queue, CloseStreamForGroup(3));
    EXPECT_CALL(queue, PublishObject(4, 0, "i"));
    EXPECT_CALL(queue, PublishObject(4, 1, "j"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 0}, "c"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 1}, "d"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{1, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 0}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 1}, "f"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{2, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 0}, "g"));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 1}, "h"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{3, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 0}, "i"));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 1}, "j"));
  queue.CallSubscribeForPast(SubscribeWindow(0, 0));
}

TEST(MoqtLiveRelayQueue, FiveGroupsPastSubscribeFromMidGroup) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(1, 0, "c"));
    EXPECT_CALL(queue, PublishObject(1, 1, "d"));
    EXPECT_CALL(queue, CloseStreamForGroup(1));
    EXPECT_CALL(queue, PublishObject(2, 0, "e"));
    EXPECT_CALL(queue, PublishObject(2, 1, "f"));
    EXPECT_CALL(queue, CloseStreamForGroup(2));
    EXPECT_CALL(queue, PublishObject(3, 0, "g"));
    EXPECT_CALL(queue, PublishObject(3, 1, "h"));
    EXPECT_CALL(queue, CloseStreamForGroup(3));
    EXPECT_CALL(queue, PublishObject(4, 0, "i"));
    EXPECT_CALL(queue, PublishObject(4, 1, "j"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 0}, "c"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 1}, "d"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{1, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 0}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 1}, "f"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{2, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 0}, "g"));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 1}, "h"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{3, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 0}, "i"));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 1}, "j"));
  // This object will be ignored, but this is not an error.
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 2}, MoqtObjectStatus::kEndOfGroup));
}

TEST(MoqtLiveRelayQueue, EndOfTrack) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseTrack());
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_FALSE(
      queue.AddObject(FullSequence{0, 1}, MoqtObjectStatus::kEndOfTrack));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfTrack));
}

TEST(MoqtLiveRelayQueue, EndOfGroup) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_FALSE(
      queue.AddObject(FullSequence{0, 1}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_FALSE(queue.AddObject(FullSequence{0, 4}, "e"));
}

TEST(MoqtLiveRelayQueue, GroupDoesNotExist) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, SkipGroup(0));
  }
  EXPECT_FALSE(queue.AddObject(FullSequence{0, 1},
                               MoqtObjectStatus::kGroupDoesNotExist));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0},
                              MoqtObjectStatus::kGroupDoesNotExist));
}

TEST(MoqtLiveRelayQueue, OverwriteObject) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_FALSE(queue.AddObject(FullSequence{0, 1}, "invalid"));
}

TEST(MoqtLiveRelayQueue, DifferentSubgroups) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 3, "d"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 0));
    EXPECT_CALL(queue, PublishObject(0, 5, "e"));
    EXPECT_CALL(queue, PublishObject(0, 7, "f"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 1));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 2));

    // Serve them back in strict subgroup order.
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 3, "d"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 0));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 5, "e"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 1));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, PublishObject(0, 7, "f"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 2));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0, 3}, "d"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2, 2}, "c"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 0, 4}, MoqtObjectStatus::kEndOfSubgroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1, 5}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2, 7}, "f"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 1, 6}, MoqtObjectStatus::kEndOfSubgroup));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 2, 8}, MoqtObjectStatus::kEndOfSubgroup));
  queue.CallSubscribeForPast(SubscribeWindow(0, 0));
}

TEST(MoqtLiveRelayQueue, EndOfSubgroup) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 0));
    EXPECT_CALL(queue, PublishObject(0, 2, "b")).Times(0);
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0, 0}, "a"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 0, 1}, MoqtObjectStatus::kEndOfSubgroup));
  EXPECT_FALSE(queue.AddObject(FullSequence{0, 0, 2}, "b"));
}

}  // namespace

}  // namespace moqt::test

"""

```