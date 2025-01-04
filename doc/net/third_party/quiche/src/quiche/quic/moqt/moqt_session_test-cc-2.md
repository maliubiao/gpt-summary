Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Initial Understanding - Context is Key:**

The prompt provides vital contextual information:

* **File Path:** `net/third_party/quiche/src/quiche/quic/moqt/moqt_session_test.cc`  This immediately tells us it's a C++ *test* file for the `MoqtSession` class within the QUIC implementation (specifically the MOQT protocol). The `.cc` extension confirms C++.
* **Chromium Network Stack:** This reinforces the context of networking and the specific environment.
* **Part 3 of 3:**  This implies previous analysis has been done, and this part likely focuses on specific test cases.

**2. Core Objective - What does this file do?**

The fundamental purpose of any `*_test.cc` file is to verify the correct behavior of the code it's testing (in this case, `MoqtSession`). This means it will contain various test functions that exercise different aspects of `MoqtSession`'s functionality.

**3. Identifying Key Components:**

Scanning the code reveals several crucial elements:

* **`TEST_F(MoqtSessionTest, ...)`:** This is the standard Google Test framework syntax for defining test cases. `MoqtSessionTest` is a test fixture (a class that sets up common test conditions).
* **`EXPECT_CALL(...)`:**  These are calls to the Google Mock framework. This tells us that the tests are interacting with *mocked* dependencies. The presence of `mock_session_`, `mock_stream0`, etc., confirms this. Mocking is used to isolate the unit under test (`MoqtSession`) and control the behavior of its collaborators.
* **`FullTrackName`, `FullSequence`, `MoqtObjectStatus`, `MoqtForwardingPreference`:** These are domain-specific types and enums, hinting at the concepts being tested (tracks, objects, sequences, forwarding preferences).
* **`SetupPublisher()`:** This is a helper function within the test fixture, likely used to create and configure mock `MoqtTrack` objects.
* **`MoqtSessionPeer::...`:** This suggests access to private members or methods of `MoqtSession` for testing purposes. This is common in unit testing to reach internal states.
* **`OnCanCreateNewOutgoingUnidirectionalStream()`, `OnNewObjectAvailable()`, `Writev()`:** These are method names that suggest the core functionalities being tested: stream creation, object availability notifications, and writing data to streams.

**4. Analyzing Individual Test Cases:**

Each `TEST_F` block represents a specific scenario being tested. The `EXPECT_CALL` statements within each test describe the expected interactions with the mocked objects. Let's take a few examples:

* **`StreamGroupedBySubscription`:** This test sets up multiple subscriptions to the same track and expects that when objects are published, new outgoing streams are created, and the correct "group ID" is embedded in the stream data. The "group ID" being the 3rd byte is a detail specific to the MOQT protocol.
* **`StreamQueuedForSubscriptionThatDoesntExist`:**  This test checks how the `MoqtSession` handles the case where a subscription is deleted *after* objects have been queued for delivery. It verifies that no streams are opened in this scenario.
* **`QueuedStreamPriorityChanged`:** This test focuses on the priority mechanism. It shows how changing the priority of subscriptions affects the order in which streams are created and data is sent.

**5. Addressing Specific Prompts:**

* **Functionality:**  Based on the analysis of the test cases, the primary function is clearly *testing* the `MoqtSession` class, specifically focusing on how it handles outgoing data streams related to published objects and subscriptions.
* **JavaScript Relationship:**  This is where we need to think about the broader context. While the *code* is C++, the MOQT protocol itself is relevant to web technologies and could be used in scenarios involving JavaScript. The example given (a media streaming application) is a plausible use case. JavaScript would interact with the browser's WebTransport API, which, on the underlying network stack, could be using MOQT.
* **Logic Inference (Hypothetical Input/Output):** For the `StreamGroupedBySubscription` test, we can infer:
    * **Input:** Publishing objects on a track with multiple subscribers.
    * **Output:**  The creation of multiple unidirectional streams, each with a distinct group ID corresponding to the subscription. The `EXPECT_EQ` calls verify this.
* **User/Programming Errors:** The `StreamQueuedForSubscriptionThatDoesntExist` test highlights a potential scenario where resources might be leaked if not handled correctly. A programmer might accidentally delete a subscription while there are still pending data deliveries.
* **User Operation to Reach the Code:**  This requires thinking about the user's interaction with a web application that uses MOQT. The media streaming example fits well. The steps outline a likely user flow.
* **Overall Function (Part 3):**  This part of the tests focuses on the behavior of the `MoqtSession` in managing outgoing streams when there are multiple subscribers and when subscription priorities change. It builds upon the foundational testing likely covered in parts 1 and 2.

**6. Structuring the Response:**

Finally, the information needs to be organized logically into the sections requested by the prompt: Functionality, JavaScript Relation, Logic Inference, Common Errors, User Steps, and Overall Function. Using clear headings and bullet points makes the response easier to read and understand.

This thought process involves a combination of code analysis, understanding of testing methodologies (unit testing, mocking), and knowledge of the broader context (QUIC, MOQT, web technologies). The iterative process of examining the code, identifying key components, and understanding the purpose of each test case is crucial to arriving at a comprehensive and accurate answer.
这是Chromium网络栈中 `net/third_party/quiche/src/quiche/quic/moqt/moqt_session_test.cc` 文件的第三部分，它主要包含针对 `MoqtSession` 类的单元测试。综合前两部分，我们可以归纳出以下功能：

**整体功能归纳 (结合前两部分):**

该文件全面测试了 `MoqtSession` 类的各项功能，涵盖了 MOQT 协议会话的生命周期和各种状态转换。具体来说，它测试了：

* **会话的创建和销毁：**  测试会话的初始化、资源分配和清理。
* **与底层 QUIC/WebTransport 连接的交互：**  模拟和验证会话如何创建和管理底层流。
* **发布者和订阅者的处理：**  测试添加、删除发布者和订阅者的逻辑，以及它们之间的关联。
* **Track 的管理：**  测试添加、查找、更新和删除 Track 的功能。
* **Object 的发布和接收：**  测试发布者如何发布 Object，以及订阅者如何接收和缓存 Object。
* **Subscription 的管理：**  测试创建、更新和取消订阅的流程，以及订阅状态的管理。
* **消息的编码和解码：**  虽然代码片段中没有直接展示，但测试中使用了模拟的 `MockStream` 和 `Writev`，暗示了对 MOQT 消息的序列化和反序列化过程的测试。
* **流的创建和管理：**  详细测试了控制流和数据流的创建、分配和关闭。
* **优先级管理：**  测试了如何根据订阅者的优先级来调度数据流的发送。
* **错误处理：**  虽然此处代码片段没有直接展示，但通常测试文件中会包含对各种错误场景的处理测试。
* **状态管理：**  测试了会话内部状态的维护和更新，例如 Track 的状态、Object 的状态等。
* **流量控制：**  尽管在此片段中不明显，但通常会测试会话如何处理发送和接收窗口。

**第三部分的功能细述：**

这部分着重测试了 `MoqtSession` 在处理多个订阅者和对象发布时的流创建和优先级管理：

1. **根据订阅分组流 (StreamGroupedBySubscription):**
   - 测试当同一个 Track 有多个订阅者，并且发布了新的 Object 时，`MoqtSession` 是否会为每个订阅者创建一个独立的流。
   - 验证每个流的数据是否包含了正确的 Group ID，用于标识该流属于哪个订阅者。

2. **为不存在的订阅排队流 (StreamQueuedForSubscriptionThatDoesntExist):**
   - 测试当有 Object 需要发送给一个订阅者，但该订阅者随后被删除时，`MoqtSession` 如何处理已排队的流。
   - 验证即使订阅不存在，但当底层流可用时，也不会尝试创建新的流。

3. **已排队流的优先级变更 (QueuedStreamPriorityChanged):**
   - 测试当已排队的流的优先级发生变化时，`MoqtSession` 是否会根据新的优先级来调度流的发送。
   - 模拟了先为两个不同优先级的订阅者排队流，然后提升其中一个订阅者的优先级，验证高优先级的订阅者对应的流是否会被优先创建和发送。

4. **订阅更新关闭订阅 (SubscribeUpdateClosesSubscription) (被注释掉):**
   -  这是一个被注释掉的测试，推测其目的是测试当收到订阅更新消息，指示订阅范围缩减到已经交付的 Object 时，是否会正确关闭该订阅。
   -  这涉及到 MOQT 协议中 `SUBSCRIBE_UPDATE` 消息的处理。

**与 JavaScript 的关系及举例说明：**

MOQT 协议旨在为 Web 应用程序提供高效可靠的媒体传输能力。虽然这段 C++ 代码是网络栈的底层实现，但它直接影响着 JavaScript 在浏览器中通过 WebTransport API 使用 MOQT 的行为。

**举例说明：**

假设一个 JavaScript 编写的实时多人在线游戏，使用了 MOQT 协议来同步游戏状态和媒体数据。

1. **`StreamGroupedBySubscription` 的体现：**  游戏中可能有多个玩家订阅了相同的游戏状态更新 Track。当服务器（作为发布者）更新游戏状态时，`MoqtSession` 需要为每个玩家（订阅者）创建一个独立的 WebTransport 流，确保每个玩家都能收到最新的状态，并且可以根据玩家的权限或视角发送不同的数据（通过 Group ID 区分）。JavaScript 代码可以通过 WebTransport API 接收到这些不同的流数据。

   ```javascript
   // JavaScript (浏览器端)
   const transport = new WebTransport(url);
   await transport.ready;

   const reader1 = transport.createReceiveStream().readable.getReader();
   const reader2 = transport.createReceiveStream().readable.getReader();

   // 假设 reader1 接收的是 Group ID 0 的数据，reader2 接收的是 Group ID 1 的数据
   while (true) {
     const { value, done } = await reader1.read();
     if (done) break;
     console.log("Player 1 update:", value);
   }

   while (true) {
     const { value, done } = await reader2.read();
     if (done) break;
     console.log("Player 2 update:", value);
   }
   ```

2. **`QueuedStreamPriorityChanged` 的体现：**  在视频会议应用中，当用户将某个参与者的视频流置为“焦点”时，JavaScript 可以通知底层网络栈提高该视频流的优先级。`MoqtSession` 的优先级管理机制会确保焦点视频流的数据优先发送，从而提供更好的用户体验。

   ```javascript
   // JavaScript (浏览器端)
   // ... 获取到订阅特定视频流的 ID
   transport.changeStreamPriority(videoStreamId, 'high');
   ```

**逻辑推理的假设输入与输出 (以 `StreamGroupedBySubscription` 为例):**

**假设输入:**

* **Track 名称:** "game-state"
* **Object 数据:**  包含游戏当前状态的二进制数据 (例如, `MemSliceFromString("current_x:10, current_y:20")`)
* **订阅者数量:** 3
* **订阅者 ID:** 0, 1, 2

**预期输出:**

* 创建 3 个新的单向 WebTransport 流。
* 每个流的数据负载的前几个字节（根据 MOQT 协议的定义）将包含：
    * Track Alias (由 `SetupPublisher` 设置)
    * **Group ID:**
        * 流 1 的 Group ID 为 0
        * 流 2 的 Group ID 为 1
        * 流 3 的 Group ID 为 2
    * 其他 MOQT 头部信息
* 每个流的数据负载的剩余部分将包含 Object 的数据。

**涉及用户或编程常见的使用错误及举例说明：**

1. **在订阅不存在后仍然尝试发布 Object:**  如果发布者没有正确跟踪订阅者的状态，可能会在订阅者取消订阅后仍然尝试向其发送数据。`StreamQueuedForSubscriptionThatDoesntExist` 测试就覆盖了这种情况，但在实际应用中，发布者应该避免这种情况，以节省资源。

   ```c++
   // 潜在的错误使用模式 (发布者代码)
   void OnObjectReady() {
     for (auto& subscription : subscriptions_) {
       // 错误：没有检查 subscription 是否仍然有效
       PublishObject(subscription, object_data_);
     }
   }
   ```

2. **优先级设置不当导致重要数据延迟：**  如果开发者在 JavaScript 中错误地设置了流的优先级，可能会导致重要的数据（例如，音频或关键的游戏状态更新）被低优先级的流阻塞。

3. **没有正确处理订阅更新：**  如果订阅者没有正确处理 `SUBSCRIBE_UPDATE` 消息，可能会导致数据接收不完整或出现状态不一致。被注释掉的 `SubscribeUpdateClosesSubscription` 测试就与此相关。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户正在使用一个基于 WebTransport 和 MOQT 的实时协作文档编辑器：

1. **用户 A 和用户 B 打开同一个文档。** 这会在浏览器中建立到服务器的 WebTransport 连接。
2. **用户 A 和用户 B 都订阅了文档内容的更新 Track。**  JavaScript 代码会调用 WebTransport API 发送 SUBSCRIBE 消息。
3. **用户 A 在文档中输入了一些文字。**  JavaScript 代码会将这些更改发送到服务器。
4. **服务器接收到更改，并将其作为新的 Object 发布到文档内容的 Track。**  `MoqtSession` 负责处理这个发布。
5. **`StreamGroupedBySubscription` 测试覆盖的场景:**  `MoqtSession` 会为用户 A 和用户 B 各创建一个独立的流来发送这个新的 Object (文档更新)。 每个流都会携带一个 Group ID，可能用于区分不同用户的上下文或权限（尽管在这个简单的例子中可能相同）。
6. **`QueuedStreamPriorityChanged` 测试覆盖的场景:**  假设用户 B 的网络连接较差，导致其订阅的优先级暂时降低。当文档更新发布时，发送给用户 A 的流可能会比发送给用户 B 的流具有更高的优先级，从而优先发送给用户 A。
7. **开发者在调试时，如果发现某个用户的文档更新延迟较高，可能会查看 `MoqtSession` 的日志，或者运行类似的单元测试来验证优先级管理是否正常工作。**  他们可能会检查 `OnCanCreateNewOutgoingUnidirectionalStream` 的调用顺序，以及 `Writev` 方法被调用的流的 ID，来判断优先级是否生效。

**归纳一下它的功能 (第三部分):**

这部分主要测试 `MoqtSession` 在处理以下关键场景时的行为：

* **多订阅者下的流分组：** 确保为每个订阅者创建独立的流来发送 Object。
* **处理已删除订阅的排队流：**  防止为已不存在的订阅创建不必要的流。
* **根据优先级调度流：**  验证当订阅者的优先级发生变化时，流的创建和发送顺序是否会受到影响。

总而言之，这部分测试聚焦于 `MoqtSession` 在管理多个并发订阅和处理优先级时的流管理和调度逻辑，这对于构建高效且用户体验良好的实时 Web 应用至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
dObject{FullSequence(2, 0), MoqtObjectStatus::kNormal,
                                 127, MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(2, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_stream0, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream1, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream2, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream0, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        // The Group ID is the 3rd byte of the stream.
        EXPECT_EQ(static_cast<const uint8_t>(data[0][2]), 0);
        return absl::OkStatus();
      });
  EXPECT_CALL(mock_stream1, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        // The Group ID is the 3rd byte of the stream.
        EXPECT_EQ(static_cast<const uint8_t>(data[0][2]), 1);
        return absl::OkStatus();
      });
  EXPECT_CALL(mock_stream2, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        // The Group ID is the 3rd byte of the stream.
        EXPECT_EQ(static_cast<const uint8_t>(data[0][2]), 2);
        return absl::OkStatus();
      });
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

TEST_F(MoqtSessionTest, StreamQueuedForSubscriptionThatDoesntExist) {
  FullTrackName ftn("foo", "bar");
  auto track = SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup,
                              FullSequence(0, 0));
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 14, 0, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  subscription->OnNewObjectAvailable(FullSequence(0, 0));

  // Delete the subscription, then grant stream credit.
  MoqtSessionPeer::DeleteSubscription(&session_, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream()).Times(0);
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

TEST_F(MoqtSessionTest, QueuedStreamPriorityChanged) {
  FullTrackName ftn1("foo", "bar");
  auto track1 = SetupPublisher(ftn1, MoqtForwardingPreference::kSubgroup,
                               FullSequence(0, 0));
  FullTrackName ftn2("dead", "beef");
  auto track2 = SetupPublisher(ftn2, MoqtForwardingPreference::kSubgroup,
                               FullSequence(0, 0));
  EXPECT_CALL(*track1, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  EXPECT_CALL(*track2, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  MoqtObjectListener* subscription0 =
      MoqtSessionPeer::AddSubscription(&session_, track1, 0, 14, 0, 0);
  MoqtObjectListener* subscription1 =
      MoqtSessionPeer::AddSubscription(&session_, track2, 1, 15, 0, 0);
  MoqtSessionPeer::UpdateSubscriberPriority(&session_, 0, 1);
  MoqtSessionPeer::UpdateSubscriberPriority(&session_, 1, 2);

  // Two published objects will queue four streams.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false))
      .WillOnce(Return(false))
      .WillOnce(Return(false))
      .WillOnce(Return(false));
  EXPECT_CALL(*track1, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  EXPECT_CALL(*track2, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  subscription0->OnNewObjectAvailable(FullSequence(0, 0));
  subscription1->OnNewObjectAvailable(FullSequence(0, 0));
  subscription0->OnNewObjectAvailable(FullSequence(1, 0));
  subscription1->OnNewObjectAvailable(FullSequence(1, 0));

  // Allow one stream to be opened. It will be group 0, subscription 0.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  webtransport::test::MockStream mock_stream0;
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream0));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor0;
  EXPECT_CALL(mock_stream0, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor0 = std::move(visitor);
      });
  EXPECT_CALL(mock_stream0, GetStreamId()).WillRepeatedly(Return(0));
  EXPECT_CALL(mock_stream0, visitor()).WillOnce([&]() {
    return stream_visitor0.get();
  });
  EXPECT_CALL(*track1, GetCachedObject(FullSequence(0, 0)))
      .WillOnce(
          Return(PublishedObject{FullSequence(0, 0), MoqtObjectStatus::kNormal,
                                 127, MemSliceFromString("foobar")}));
  EXPECT_CALL(*track1, GetCachedObject(FullSequence(0, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_stream0, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream0, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        // Check track alias is 14.
        EXPECT_EQ(static_cast<const uint8_t>(data[0][1]), 14);
        // Check Group ID is 0
        EXPECT_EQ(static_cast<const uint8_t>(data[0][2]), 0);
        return absl::OkStatus();
      });
  session_.OnCanCreateNewOutgoingUnidirectionalStream();

  // Raise the priority of subscription 1 and allow another stream. It will be
  // group 0, subscription 1.
  MoqtSessionPeer::UpdateSubscriberPriority(&session_, 1, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true))
      .WillRepeatedly(Return(false));
  webtransport::test::MockStream mock_stream1;
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream1));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor1;
  EXPECT_CALL(mock_stream1, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor1 = std::move(visitor);
      });
  EXPECT_CALL(mock_stream1, GetStreamId()).WillRepeatedly(Return(1));
  EXPECT_CALL(mock_stream1, visitor()).WillOnce([&]() {
    return stream_visitor1.get();
  });
  EXPECT_CALL(*track2, GetCachedObject(FullSequence(0, 0)))
      .WillOnce(
          Return(PublishedObject{FullSequence(0, 0), MoqtObjectStatus::kNormal,
                                 127, MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track2, GetCachedObject(FullSequence(0, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_stream1, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream1, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        // Check track alias is 15.
        EXPECT_EQ(static_cast<const uint8_t>(data[0][1]), 15);
        // Check Group ID is 0
        EXPECT_EQ(static_cast<const uint8_t>(data[0][2]), 0);
        return absl::OkStatus();
      });
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

// TODO: re-enable this test once this behavior is re-implemented.
#if 0
TEST_F(MoqtSessionTest, SubscribeUpdateClosesSubscription) {
  MoqtSessionPeer::set_peer_role(&session_, MoqtRole::kSubscriber);
  FullTrackName ftn("foo", "bar");
  MockLocalTrackVisitor track_visitor;
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kTrack, &track_visitor);
  MoqtSessionPeer::AddSubscription(&session_, ftn, 0, 2, 5, 0);
  // Get the window, set the maximum delivered.
  LocalTrack* track = MoqtSessionPeer::local_track(&session_, ftn);
  track->GetWindow(0)->OnObjectSent(FullSequence(7, 3),
                                    MoqtObjectStatus::kNormal);
  // Update the end to fall at the last delivered object.
  MoqtSubscribeUpdate update = {
      /*subscribe_id=*/0,
      /*start_group=*/5,
      /*start_object=*/0,
      /*end_group=*/7,
      /*end_object=*/3,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream));
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeDone);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeUpdateMessage(update);
  EXPECT_TRUE(correct_message);
  EXPECT_FALSE(session_.HasSubscribers(ftn));
}
#endif

}  // namespace test

}  // namespace moqt

"""


```