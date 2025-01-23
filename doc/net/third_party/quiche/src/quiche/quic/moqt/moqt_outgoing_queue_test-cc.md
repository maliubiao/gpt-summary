Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `moqt_outgoing_queue_test.cc` immediately suggests it's a test file for the `MoqtOutgoingQueue` class. The presence of `#include "quiche/quic/moqt/moqt_outgoing_queue.h"` confirms this.

2. **Understand the Testing Framework:** The includes reveal that it uses `quiche::test::QuicheTest` and Google Test (`testing::...`). This tells us it's using a standard C++ testing framework with assertions and mocks.

3. **Examine the Test Fixture:** The `TestMoqtOutgoingQueue` class inherits from `MoqtOutgoingQueue` and `MoqtObjectListener`. This indicates it's creating a specialized version of the queue for testing purposes, and it needs to implement the `MoqtObjectListener` interface. The `MOCK_METHOD` declarations are a key indicator of how interactions with other parts of the system are being verified.

4. **Analyze Individual Test Cases:** Go through each `TEST(MoqtOutgoingQueue, ...)` block. For each test:
    * **Identify the Scenario:** What specific behavior or edge case is being tested?  The test names often provide clues (e.g., `FirstObjectNotKeyframe`, `SingleGroup`, `TwoGroupsPastSubscribe`).
    * **Look for Setup:** What actions are performed *before* the main behavior being tested? This often involves creating a `TestMoqtOutgoingQueue` instance and potentially setting expectations on mocked methods.
    * **Identify the Action Under Test:** What method of `MoqtOutgoingQueue` is being invoked?  In most cases, it's `AddObject`. The `CallSubscribeForPast` method is also interesting.
    * **Analyze the Assertions:** What are the `EXPECT_...` and `ASSERT_THAT` statements checking? These define the expected outcomes of the test. Look for interactions with the mocked methods using `EXPECT_CALL`.
    * **Infer the Purpose of Mocked Methods:** The `PublishObject` and `CloseStreamForGroup` mocks are clearly designed to verify that the queue is correctly instructing other components to send data.

5. **Look for Helper Functions:** The `FetchToVector` function stands out. It seems to be a utility for extracting data from a `MoqtFetchTask`. Understanding its purpose is crucial for understanding the `Fetch` related tests.

6. **Consider Javascript Relevance (If Any):** While this is C++ code, think about the *concepts* involved. A "queue" is a fundamental data structure used in many programming contexts, including Javascript (e.g., for handling asynchronous tasks or message passing). The idea of "publishing" and "subscribing" is also relevant to Javascript in the context of event handling or reactive programming libraries. However, the *direct* connection to Javascript code is weak in this specific file.

7. **Infer Logic and Assumptions:**  Based on the test cases, deduce the internal logic of `MoqtOutgoingQueue`. For example:
    * The first object in a group must be a keyframe.
    * The queue manages objects in groups, identified by a group ID.
    * There's a mechanism to "subscribe for past" objects.
    * The `Fetch` method allows retrieving objects with specific criteria.
    * There's a limit on how many past groups are retained.

8. **Identify Potential User Errors:**  Think about how a developer *using* this `MoqtOutgoingQueue` class might misuse it. The "FirstObjectNotKeyframe" test directly points to one such error. Consider other scenarios based on the class's behavior.

9. **Trace User Operations (Debugging Context):** Imagine a bug report related to this code. How would a user's actions lead to this part of the code?  Think about the network stack context. A user might be streaming media or real-time data, and the application might be publishing updates to this queue. Understanding the higher-level MOQT protocol is helpful here.

10. **Structure the Explanation:**  Organize the findings logically. Start with the overall purpose, then dive into specific functionalities, Javascript relevance (if any), logic/assumptions, potential errors, and debugging tips. Use clear and concise language. Provide concrete examples where possible (especially for input/output and user errors).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about queuing data."
* **Correction:** "No, it's more nuanced. It manages objects in *groups*, and the concept of keyframes is important. There's also a 'subscribe for past' mechanism."
* **Initial thought:** "How does this relate to Javascript?"
* **Refinement:** "The *concepts* are similar to asynchronous handling or eventing, but there's no direct code interaction. Focus on the abstract ideas."
* **Initial thought:** "Just list the tests."
* **Refinement:** "Explain *what* each test is testing and *why* it's important."

By following these steps and iteratively refining the understanding, we can arrive at a comprehensive explanation of the C++ test file.
这个C++源代码文件 `moqt_outgoing_queue_test.cc` 是 Chromium 网络栈中 QUIC 协议的 MOQT (Media over QUIC Transport) 组件的一部分。它的主要功能是 **测试 `MoqtOutgoingQueue` 类的各种功能和行为**。

`MoqtOutgoingQueue` 的作用是管理即将通过 QUIC 连接发送出去的媒体对象（例如，音频或视频片段）。它负责以下方面：

* **存储待发送的媒体对象:**  维护一个队列来保存需要发送的数据。
* **管理对象的分组 (Groups):**  将连续的媒体对象组织成逻辑上的组，这对于确保按正确的顺序和上下文发送数据至关重要。
* **处理关键帧 (Keyframes):** 区分关键帧和非关键帧，关键帧是解码后续帧所必需的。
* **支持订阅历史 (Past Subscribe):**  允许新的订阅者请求过去已经发送过的数据。
* **支持按需获取 (Fetch):** 允许接收端请求特定范围内的对象。
* **管理对象的生命周期:**  跟踪哪些对象已被发送，哪些可以被清除。

**与 Javascript 功能的关系：**

虽然这个文件本身是 C++ 代码，但它测试的 `MoqtOutgoingQueue` 类在 Chromium 的网络栈中扮演着重要角色，而 Chromium 是浏览器内核。因此，它间接地与浏览器的 Javascript 功能相关，特别是那些涉及媒体流传输的 API，例如：

* **Media Source Extensions (MSE):**  MSE 允许 Javascript 代码构建用于 `<video>` 或 `<audio>` 元素的媒体流。MOQT 作为一种传输协议，可以被 MSE 用于接收和处理媒体数据。`MoqtOutgoingQueue` 负责将要发送的媒体数据组织好，以便通过网络传输到接收端的 Javascript 代码。
* **WebCodecs API:** WebCodecs 提供了对媒体编解码器的底层访问。Javascript 可以使用 WebCodecs 对接收到的 MOQT 数据进行解码和处理。同样，如果要通过 MOQT 发送媒体，Javascript 可以使用 WebCodecs 编码数据，然后这些数据可能会进入 `MoqtOutgoingQueue` 进行排队和发送。

**举例说明:**

假设一个 Javascript 应用正在使用 MSE 通过 MOQT 向另一个客户端发送实时视频流。

1. **Javascript (发送端):**
   ```javascript
   // 获取视频帧数据 (例如，从 <canvas> 或 MediaStreamTrack)
   const videoFrame = ...;

   // 使用 WebCodecs API 对视频帧进行编码
   const encodedChunk = await encoder.encode(videoFrame);

   // 将编码后的数据发送出去 (这部分逻辑会使用到 Chromium 的网络栈，最终会涉及到 MoqtOutgoingQueue)
   sendMoqtData(encodedChunk.data);
   ```

2. **C++ (Chromium 网络栈):** 当 `sendMoqtData` 被调用时，编码后的数据会经过一系列处理，最终可能会被添加到 `MoqtOutgoingQueue` 中。`MoqtOutgoingQueue` 会根据关键帧信息、分组策略等来组织这些数据，然后通过 QUIC 连接发送出去。

3. **Javascript (接收端):** 接收端会接收到通过 QUIC 和 MOQT 传输的数据，并使用 MSE 或 WebCodecs 将其解码和渲染到页面上。

**逻辑推理与假设输入输出:**

让我们以 `TEST(MoqtOutgoingQueue, SingleGroup)` 这个测试用例为例进行逻辑推理：

**假设输入:**

* 创建一个 `TestMoqtOutgoingQueue` 实例。
* 依次添加三个媒体对象：
    * 内容为 "a"，标记为关键帧 (true)。
    * 内容为 "b"，标记为非关键帧 (false)。
    * 内容为 "c"，标记为非关键帧 (false)。

**预期输出:**

* `PublishObject` 方法会被调用三次，每次对应一个添加的媒体对象：
    * 第一次调用 `PublishObject(0, 0, "a")`：表示将第一个对象（内容 "a"）作为组 0 的第一个对象（ID 0）发布。
    * 第二次调用 `PublishObject(0, 1, "b")`：表示将第二个对象（内容 "b"）作为组 0 的第二个对象（ID 1）发布。
    * 第三次调用 `PublishObject(0, 2, "c")`：表示将第三个对象（内容 "c"）作为组 0 的第三个对象（ID 2）发布。

**解释:**  由于第一个对象是关键帧，它会创建一个新的组（组 ID 0）。后续的非关键帧对象会被添加到同一个组中，并赋予递增的对象 ID。`PublishObject` 方法（在这个测试中是被 mock 的）模拟了将这些对象发送出去的过程。

**用户或编程常见的使用错误:**

1. **第一个对象不是关键帧:**  `TEST(MoqtOutgoingQueue, FirstObjectNotKeyframe)` 测试用例就指出了这个错误。如果尝试将一个非关键帧对象作为新组的第一个对象添加，`MoqtOutgoingQueue` 会触发一个 `QUICHE_BUG` 断言。

   **例子:**

   ```c++
   TestMoqtOutgoingQueue queue;
   // 错误：第一个对象不是关键帧
   queue.AddObject(MemSliceFromString("a"), false);
   ```

   **说明:**  在媒体流中，通常需要一个初始的关键帧来开始解码。如果第一个对象不是关键帧，接收端可能无法正确解码后续的非关键帧。

2. **在没有订阅的情况下期望立即发送数据:** 用户可能错误地认为添加到 `MoqtOutgoingQueue` 的数据会立即发送出去。实际上，`MoqtOutgoingQueue` 只是负责组织和缓存数据。实际的发送还需要依赖于底层的 QUIC 连接和订阅者的需求。

3. **不理解分组的概念:** 用户可能不理解 MOQT 中对象分组的意义，导致数据发送的顺序或上下文出现问题。例如，错误地将属于不同时间段或逻辑单元的媒体对象放在同一个组中。

**用户操作如何一步步到达这里（作为调试线索）：**

假设一个用户在使用一个在线视频会议应用时遇到了视频卡顿或花屏的问题。以下是可能的调试线索，最终可能会指向 `moqt_outgoing_queue_test.cc` 中测试的代码：

1. **用户操作:** 用户加入了视频会议，并开始发送自己的视频流。
2. **Javascript 代码 (发送端):** 浏览器的 Javascript 代码使用 `getUserMedia` 获取用户的摄像头数据，然后使用 WebCodecs 对视频帧进行编码。
3. **Chromium 网络栈 (MOQT):** 编码后的视频帧数据被传递给 Chromium 的网络栈，并由 MOQT 组件处理。
4. **`MoqtOutgoingQueue`:**  这些视频帧数据被添加到 `MoqtOutgoingQueue` 中进行排队，等待通过 QUIC 连接发送。
5. **问题发生:** 由于网络拥塞、编码错误或其他原因，某个关键帧丢失或者发送延迟。
6. **Javascript 代码 (接收端):** 接收端的 Javascript 代码接收到的数据不完整或顺序错误，导致解码失败，出现视频卡顿或花屏。
7. **调试:** 开发人员可能会检查以下方面：
   * **QUIC 连接状态:** 检查连接是否稳定，是否存在丢包。
   * **MOQT 消息:** 检查发送端和接收端之间 MOQT 控制消息的交换，例如 `SUBSCRIBE` 和 `PUBLISH`。
   * **`MoqtOutgoingQueue` 的状态:** 检查发送端 `MoqtOutgoingQueue` 中排队的对象，确认关键帧是否被正确标记和分组。
   * **测试用例:**  如果怀疑是 `MoqtOutgoingQueue` 的逻辑问题，开发人员可能会参考 `moqt_outgoing_queue_test.cc` 中的测试用例，以了解其预期行为，并尝试复现问题。例如，他们可能会想到“如果关键帧没有正确发送会发生什么？” 这就可能让他们关注到 `FirstObjectNotKeyframe` 这样的测试用例。

因此，虽然用户直接操作的是浏览器应用，但当出现网络传输相关的媒体问题时，底层的网络栈组件（如 `MoqtOutgoingQueue`）就成为了潜在的故障点，而其对应的测试代码可以帮助开发人员理解其行为并进行调试。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_outgoing_queue_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/moqt/moqt_outgoing_queue.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_subscribe_windows.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace moqt {
namespace {

using ::quic::test::MemSliceFromString;
using ::quiche::test::IsOkAndHolds;
using ::quiche::test::StatusIs;
using ::testing::AnyOf;
using ::testing::ElementsAre;
using ::testing::IsEmpty;

class TestMoqtOutgoingQueue : public MoqtOutgoingQueue,
                              public MoqtObjectListener {
 public:
  TestMoqtOutgoingQueue()
      : MoqtOutgoingQueue(FullTrackName{"test", "track"},
                          MoqtForwardingPreference::kSubgroup) {
    AddObjectListener(this);
  }

  void OnNewObjectAvailable(FullSequence sequence) override {
    std::optional<PublishedObject> object = GetCachedObject(sequence);
    QUICHE_CHECK(object.has_value());
    ASSERT_THAT(object->status, AnyOf(MoqtObjectStatus::kNormal,
                                      MoqtObjectStatus::kEndOfGroup));
    if (object->status == MoqtObjectStatus::kNormal) {
      PublishObject(object->sequence.group, object->sequence.object,
                    object->payload.AsStringView());
    } else {
      CloseStreamForGroup(object->sequence.group);
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
  MOCK_METHOD(void, PublishObject,
              (uint64_t group_id, uint64_t object_id,
               absl::string_view payload),
              ());
  MOCK_METHOD(void, OnTrackPublisherGone, (), (override));
};

absl::StatusOr<std::vector<std::string>> FetchToVector(
    std::unique_ptr<MoqtFetchTask> fetch) {
  std::vector<std::string> objects;
  for (;;) {
    PublishedObject object;
    MoqtFetchTask::GetNextObjectResult result = fetch->GetNextObject(object);
    switch (result) {
      case MoqtFetchTask::kSuccess:
        if (object.status == MoqtObjectStatus::kNormal) {
          objects.emplace_back(object.payload.AsStringView());
        } else {
          EXPECT_EQ(object.status, MoqtObjectStatus::kEndOfGroup);
        }
        continue;
      case MoqtFetchTask::kPending:
        return absl::InternalError(
            "Unexpected kPending from MoqtOutgoingQueue");
      case MoqtFetchTask::kEof:
        return objects;
      case MoqtFetchTask::kError:
        return fetch->GetStatus();
    }
  }
}

TEST(MoqtOutgoingQueue, FirstObjectNotKeyframe) {
  TestMoqtOutgoingQueue queue;
  EXPECT_QUICHE_BUG(queue.AddObject(MemSliceFromString("a"), false),
                    "The first object");
}

TEST(MoqtOutgoingQueue, SingleGroup) {
  TestMoqtOutgoingQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
  }
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), false);
}

TEST(MoqtOutgoingQueue, SingleGroupPastSubscribeFromZero) {
  TestMoqtOutgoingQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));

    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
  }
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), false);
  queue.CallSubscribeForPast(SubscribeWindow(0, 0));
}

TEST(MoqtOutgoingQueue, SingleGroupPastSubscribeFromMidGroup) {
  TestMoqtOutgoingQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));

    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
  }
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), false);
  queue.CallSubscribeForPast(SubscribeWindow(0, 1));
}

TEST(MoqtOutgoingQueue, TwoGroups) {
  TestMoqtOutgoingQueue queue;
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
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), false);
  queue.AddObject(MemSliceFromString("d"), true);
  queue.AddObject(MemSliceFromString("e"), false);
  queue.AddObject(MemSliceFromString("f"), false);
}

TEST(MoqtOutgoingQueue, TwoGroupsPastSubscribe) {
  TestMoqtOutgoingQueue queue;
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
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), false);
  queue.AddObject(MemSliceFromString("d"), true);
  queue.AddObject(MemSliceFromString("e"), false);
  queue.AddObject(MemSliceFromString("f"), false);
  queue.CallSubscribeForPast(SubscribeWindow(0, 1));
}

TEST(MoqtOutgoingQueue, FiveGroups) {
  TestMoqtOutgoingQueue queue;
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
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), true);
  queue.AddObject(MemSliceFromString("d"), false);
  queue.AddObject(MemSliceFromString("e"), true);
  queue.AddObject(MemSliceFromString("f"), false);
  queue.AddObject(MemSliceFromString("g"), true);
  queue.AddObject(MemSliceFromString("h"), false);
  queue.AddObject(MemSliceFromString("i"), true);
  queue.AddObject(MemSliceFromString("j"), false);
}

TEST(MoqtOutgoingQueue, FiveGroupsPastSubscribe) {
  TestMoqtOutgoingQueue queue;
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
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), true);
  queue.AddObject(MemSliceFromString("d"), false);
  queue.AddObject(MemSliceFromString("e"), true);
  queue.AddObject(MemSliceFromString("f"), false);
  queue.AddObject(MemSliceFromString("g"), true);
  queue.AddObject(MemSliceFromString("h"), false);
  queue.AddObject(MemSliceFromString("i"), true);
  queue.AddObject(MemSliceFromString("j"), false);
  queue.CallSubscribeForPast(SubscribeWindow(0, 0));
}

TEST(MoqtOutgoingQueue, Fetch) {
  TestMoqtOutgoingQueue queue;
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{0, 0}, 2, 0,
                                        MoqtDeliveryOrder::kAscending)),
              StatusIs(absl::StatusCode::kNotFound));

  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), true);
  queue.AddObject(MemSliceFromString("d"), false);
  queue.AddObject(MemSliceFromString("e"), true);

  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{0, 0}, 2, 0,
                                        MoqtDeliveryOrder::kAscending)),
              IsOkAndHolds(ElementsAre("a", "b", "c", "d", "e")));
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{0, 100}, 0, 1000,
                                        MoqtDeliveryOrder::kAscending)),
              IsOkAndHolds(IsEmpty()));
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{0, 0}, 2, 0,
                                        MoqtDeliveryOrder::kDescending)),
              IsOkAndHolds(ElementsAre("e", "c", "d", "a", "b")));
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{0, 0}, 1, 0,
                                        MoqtDeliveryOrder::kAscending)),
              IsOkAndHolds(ElementsAre("a", "b", "c")));
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{0, 0}, 1, 0,
                                        MoqtDeliveryOrder::kAscending)),
              IsOkAndHolds(ElementsAre("a", "b", "c")));
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{1, 0}, 5, std::nullopt,
                                        MoqtDeliveryOrder::kAscending)),
              IsOkAndHolds(ElementsAre("c", "d", "e")));
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{3, 0}, 5, std::nullopt,
                                        MoqtDeliveryOrder::kAscending)),
              StatusIs(absl::StatusCode::kNotFound));

  queue.AddObject(MemSliceFromString("f"), true);
  queue.AddObject(MemSliceFromString("g"), false);
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{0, 0}, 0, 1,
                                        MoqtDeliveryOrder::kAscending)),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{0, 0}, 2, 0,
                                        MoqtDeliveryOrder::kAscending)),
              IsOkAndHolds(ElementsAre("c", "d", "e")));
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{1, 0}, 5, std::nullopt,
                                        MoqtDeliveryOrder::kAscending)),
              IsOkAndHolds(ElementsAre("c", "d", "e", "f", "g")));
  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{3, 0}, 5, std::nullopt,
                                        MoqtDeliveryOrder::kAscending)),
              IsOkAndHolds(ElementsAre("f", "g")));
}

TEST(MoqtOutgoingQueue, ObjectsGoneWhileFetching) {
  TestMoqtOutgoingQueue queue;
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), true);
  queue.AddObject(MemSliceFromString("c"), true);
  queue.AddObject(MemSliceFromString("d"), true);
  queue.AddObject(MemSliceFromString("e"), true);

  EXPECT_THAT(FetchToVector(queue.Fetch(FullSequence{0, 0}, 5, 0,
                                        MoqtDeliveryOrder::kAscending)),
              IsOkAndHolds(ElementsAre("c", "d", "e")));
  std::unique_ptr<MoqtFetchTask> deferred_fetch =
      queue.Fetch(FullSequence{0, 0}, 5, 0, MoqtDeliveryOrder::kAscending);

  queue.AddObject(MemSliceFromString("f"), true);
  queue.AddObject(MemSliceFromString("g"), true);
  queue.AddObject(MemSliceFromString("h"), true);
  queue.AddObject(MemSliceFromString("i"), true);

  EXPECT_THAT(FetchToVector(std::move(deferred_fetch)),
              IsOkAndHolds(IsEmpty()));
}

}  // namespace
}  // namespace moqt
```