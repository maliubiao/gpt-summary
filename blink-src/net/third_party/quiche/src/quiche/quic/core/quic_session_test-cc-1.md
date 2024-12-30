Response:
The user wants me to analyze a code snippet from a Chromium network stack file related to QUIC session testing.

Here's a breakdown of the thought process to generate the response:

1. **Understand the Core Functionality:** The filename `quic_session_test.cc` and the test fixture names (like `QuicSessionTestServer`) clearly indicate this file contains unit tests for the `QuicSession` class. The tests focus on server-side behavior (`QuicSessionTestServer`).

2. **Analyze Individual Tests:** Go through each `TEST_P` function and determine its purpose. Look for keywords and function calls like:
    * `CheckClosedStreams()`: Verifies that streams are properly closed.
    * `GetOrCreateStream()`: Tests stream creation logic.
    * `max_open_incoming_bidirectional_streams()`, `max_open_incoming_unidirectional_streams()`: Tests limits on the number of open streams.
    * `MaxAvailableBidirectionalStreams()`, `MaxAvailableUnidirectionalStreams()`: Tests exceeding the available stream IDs.
    * `CloseConnection()`: Checks connection closure scenarios based on stream limits and invalid IDs.
    * `MarkConnectionLevelWriteBlocked()`: Tests mechanisms for handling write blocking.
    * `OnCanWrite()`: Tests the scheduling and execution of stream writes.
    * `SendStreamData()`, `SendLargeFakeData()`:  Related to sending data on streams.
    * `SetPriority()`: Tests prioritization of streams.
    * `SendControlFrame()`: Tests sending control frames like `STREAMS_BLOCKED` and `MAX_STREAMS`.
    * `OnStreamFrame()`: Tests handling of incoming stream frames.
    * `SendGoAway()`: Tests sending GOAWAY frames.
    * `OnPacketReceived()`: Tests handling of incoming packets, specifically connectivity probes.
    * `CompleteHandshake()`: Sets up a simulated handshake.

3. **Group Tests by Functionality:**  After analyzing individual tests, group them into logical categories. For this snippet, the main functionalities are:
    * Stream lifecycle management (creation, closing, limits).
    * Handling write blocking and `OnCanWrite` logic.
    * Congestion control interaction.
    * Sending and handling control frames (specifically `STREAMS_BLOCKED`, `MAX_STREAMS`, and `GOAWAY`).
    * Connectivity probing.
    * Handling static stream IDs.
    * Handling invalid stream IDs.

4. **Identify Connections to JavaScript (if any):**  Consider how these server-side QUIC functionalities might relate to JavaScript in a browser context. Key areas of connection are:
    * Opening and closing streams (initiated by JavaScript `fetch` or WebSockets).
    * Receiving data on streams (handled by JavaScript event listeners).
    * Stream limits (impact the number of concurrent requests JavaScript can make).
    * Error handling (JavaScript might receive errors related to exceeding stream limits).

5. **Provide Examples:**  For the JavaScript connections, provide concrete examples using `fetch` and WebSockets to illustrate the relationship.

6. **Infer Logical Reasoning and Scenarios:**  For tests involving logical reasoning (like exceeding stream limits), create hypothetical input and output scenarios. For instance, when too many bidirectional streams are requested, the expected output is a connection closure with a specific error code.

7. **Identify Potential User/Programming Errors:**  Think about common mistakes developers might make when interacting with QUIC concepts. Examples include:
    * Trying to open too many streams.
    * Sending data on a closed stream.
    * Misunderstanding stream limits.

8. **Trace User Actions (Debugging Clues):**  Consider how a user action in a browser could lead to these tests being relevant. Examples include:
    * Opening multiple tabs/making multiple requests.
    * Slow network conditions causing write blocking.
    * Server-side pushing of data.

9. **Summarize the Functionality (as requested in part 2):** Condense the analysis into a concise summary of the code's purpose.

10. **Review and Refine:**  Read through the generated response to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that need further explanation. For example, ensure the connection between the server-side test and the client-side JavaScript is clearly articulated and exemplified.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Focus heavily on the C++ implementation details.
* **Correction:**  Shift focus to explain the *purpose* of the tests and their implications for higher-level concepts, especially the JavaScript interaction requested by the user.
* **Initial thought:**  Only list the test names.
* **Correction:**  Explain what each test *does* and the scenario it covers.
* **Initial thought:**  Provide very technical examples for JavaScript.
* **Correction:** Simplify the JavaScript examples to be more illustrative and accessible.
* **Initial thought:**  Don't explicitly link the tests to debugging scenarios.
* **Correction:** Add a section on how these tests can serve as debugging clues, linking user actions to the tested functionalities.
* **Initial thought:**  The summary might be too verbose or too short.
* **Correction:** Aim for a concise yet comprehensive summary that captures the key aspects of the code snippet.
这是对Chromium网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_session_test.cc` 文件代码片段的分析，主要关注其功能。

**代码片段功能归纳：**

这个代码片段主要测试了 `QuicSession` 类在服务器端的流管理功能，具体包括：

1. **流的关闭和清理:** 测试 `CheckClosedStreams()` 确保已关闭的流被正确地清理。
2. **最大可用的双向和单向流:** 测试在达到最大允许打开的流数量之前，可以成功创建新的双向和单向流。
3. **超出最大可用流数量:** 测试当尝试创建超出最大可用流ID范围的流时，连接会按照 QUIC 版本规范进行处理（IETF QUIC 终止连接并返回 `QUIC_INVALID_STREAM_ID`，其他版本返回 `QUIC_TOO_MANY_AVAILABLE_STREAMS`）。
4. **大量可用流的创建:** 测试在高并发场景下，能够按需创建大量的双向和单向流，并且不会因为创建顺序（先创建大ID的流）而出现问题。同时，测试了双向流和单向流的限制是独立工作的，不会互相干扰。
5. **标记已关闭流为写阻塞的调试断言:** 测试当尝试将一个已关闭的流标记为写阻塞时，会触发一个调试断言（`DCHECK`），以防止潜在的错误操作。
6. **`OnCanWrite()` 方法的行为:** 测试 `QuicSession` 的 `OnCanWrite()` 方法如何调度和执行多个写阻塞的流的写入操作。测试了循环限制，以及在启用批量写入或尊重增量优先级的情况下，同一个流可能在一次 `OnCanWrite()` 调用中多次写入。
7. **批量写入测试:** 测试在启用批量写入的情况下，`OnCanWrite()` 方法如何高效地处理多个流的写入，并测试了流的优先级对写入顺序的影响。
8. **`OnCanWrite()` 捆绑多个流的写入:** 测试 `OnCanWrite()` 方法是否能够将来自不同流的数据捆绑到同一个数据包中发送，以提高效率。
9. **`OnCanWrite()` 受拥塞控制阻塞:** 测试当拥塞控制限制发送时，`OnCanWrite()` 如何处理，以及当拥塞解除后如何继续发送被阻塞的流的数据。
10. **`OnCanWrite()` 受写入器阻塞:** 测试当底层的 `PacketWriter` 阻塞时，`OnCanWrite()` 方法不会调用流的 `OnCanWrite()` 方法，并且会正确处理 application-limited 的状态。
11. **发送 `STREAMS_BLOCKED` 帧:** 测试当尝试打开超过允许的最大外出流数量时，会发送 `STREAMS_BLOCKED` 控制帧。
12. **限制最大流数量和发送 `MAX_STREAMS` 帧:** 测试如何限制最大允许的接收流数量，以及当窗口需要扩展时发送 `MAX_STREAMS` 控制帧。同时测试了对 `MAX_STREAMS` 帧的确认处理。
13. **缓冲握手数据:** 测试在握手完成之前，如果数据流被阻塞，是否能正确检测到握手是否挂起，并且在 `OnCanWrite()` 中优先处理加密流。
14. **`OnCanWrite()` 处理已关闭的流:** 测试 `OnCanWrite()` 方法在处理写阻塞流时，会忽略已经关闭的流。
15. **`OnCanWrite()` 在流控阻塞时的行为:** 测试当连接层面流控被阻塞时，`OnCanWrite()` 方法只允许加密流和头部流写入，数据流会被阻止。
16. **发送 `GOAWAY` 帧:** 测试发送 `GOAWAY` 帧的功能，表明服务器即将关闭连接。测试了不会重复发送 `GOAWAY` 帧。
17. **处理无效的 `GOAWAY` 帧:** 测试接收到无效的 `GOAWAY` 帧时的行为。
18. **服务器回复连接性探测:** 测试服务器在接收到来自新路径的连接性探测包时，会回复一个连接性探测包。
19. **加密握手后增加超时时间:** 测试在完成加密握手后，连接的空闲超时时间会增加。
20. **处理静态流 ID 的 FIN:** 测试接收到静态流 ID 的 FIN 帧时的行为，应该会关闭连接。
21. **处理无效的流 ID 的帧:**  代码片段在此处结束，但根据上下文推测，这里会测试接收到无效流 ID 的帧时的处理行为。

**与 JavaScript 的关系：**

虽然这段代码是 C++ 写的，用于测试 QUIC 协议的服务器端实现，但它与 JavaScript 在 Web 开发中使用的 `fetch` API 和 WebSocket API 有着密切的关系。

* **流的创建和管理:** JavaScript 通过 `fetch` 或 WebSocket 发起请求时，底层会建立 QUIC 流。这段代码测试了服务器如何管理这些来自客户端的流的生命周期，包括限制并发流的数量。如果 JavaScript 代码尝试发起过多并发请求，服务器可能会根据这些限制关闭连接或拒绝创建新的流，这在 JavaScript 中可能会表现为网络错误。
* **数据发送和接收:** `OnCanWrite()` 方法和批量写入测试涉及到数据在 QUIC 流上的发送。JavaScript 通过 `fetch` 发送请求体或通过 WebSocket 发送消息时，最终会触发服务器端的这些数据发送逻辑。
* **连接关闭和错误处理:** 测试中关于超出流限制和接收无效帧导致连接关闭的部分，直接影响到 JavaScript 应用的健壮性。当服务器因为这些原因关闭连接时，JavaScript 代码需要能够捕获并处理这些错误，例如通过 `fetch` 的 `catch` 块或 WebSocket 的 `onerror` 事件。
* **GOAWAY 帧:** 服务器发送 `GOAWAY` 帧通知客户端即将关闭连接。JavaScript 应用接收到这个信号后，应该停止发送新的请求，并优雅地处理已有的连接。

**JavaScript 举例说明:**

假设一个网页使用 `fetch` API 并行请求多个资源：

```javascript
async function fetchData(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      console.error(`请求失败: ${response.status} ${response.statusText}`);
    } else {
      const data = await response.json();
      console.log(`成功获取数据: ${url}`, data);
    }
  } catch (error) {
    console.error(`请求出错: ${url}`, error);
    // 这里可能会捕获到由于服务器流限制或发送 GOAWAY 导致的错误
  }
}

const urls = [
  '/api/resource1',
  '/api/resource2',
  '/api/resource3',
  // ... 更多的 URL
];

urls.map(fetchData);
```

如果 `urls` 数组包含大量的 URL，并且服务器的 `QuicSession` 实例配置了较小的 `max_open_incoming_bidirectional_streams`，那么当 JavaScript 代码尝试并发发起这些请求时，就可能触发 `quic_session_test.cc` 中测试的 "TooManyAvailableBidirectionalStreams" 场景，导致服务器关闭连接。JavaScript 的 `catch` 块就会捕获到相应的网络错误。

**逻辑推理、假设输入与输出:**

**测试用例:** `TEST_P(QuicSessionTestServer, TooManyAvailableBidirectionalStreams)`

**假设输入:**

1. 服务器的 `max_open_incoming_bidirectional_streams` 配置为 `N`。
2. 客户端尝试创建 `N + 2` 个双向流。

**逻辑推理:**

* 前 `N` 个流应该可以成功创建。
* 当尝试创建第 `N + 1` 个流时，如果其 ID 在可用范围内，也可能成功创建。
* 当尝试创建第 `N + 2` 个流时，如果其 ID 超出了当前会话可以接受的范围（基于 `MaxAvailableBidirectionalStreams()` 的计算），则会触发连接关闭。
* 根据 QUIC 版本，关闭连接的原因可能是 `QUIC_INVALID_STREAM_ID` (IETF QUIC) 或 `QUIC_TOO_MANY_AVAILABLE_STREAMS` (其他版本)。

**预期输出:**

* `EXPECT_NE(nullptr, session_.GetOrCreateStream(stream_id1))` 对于前几个流返回非空指针。
* `EXPECT_EQ(nullptr, session_.GetOrCreateStream(stream_id2))` 对于超出范围的流返回空指针。
* `EXPECT_CALL(*connection_, CloseConnection(...))` 会被调用，参数取决于 QUIC 版本。

**用户或编程常见的使用错误举例:**

1. **尝试在连接关闭后发送数据:** 用户操作可能导致连接意外关闭（例如网络不稳定，服务器主动关闭），而 JavaScript 代码没有正确处理连接关闭事件，仍然尝试通过该连接发送数据，这会导致错误。`quic_session_test.cc` 中的测试确保了服务器在这些情况下会进行正确的处理。
2. **不理解 QUIC 的流限制:** 开发者可能不了解 QUIC 对并发流数量的限制，在 JavaScript 中发起了远超服务器处理能力的并发请求，导致服务器触发流限制并关闭连接。测试 "TooManyAvailableBidirectionalStreams" 就是为了验证服务器在这种情况下是否按照预期工作。
3. **错误地管理 WebSocket 连接的生命周期:**  在使用 WebSocket 时，开发者可能没有正确处理连接关闭事件，导致在连接已经断开的情况下仍然尝试发送或接收数据。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **网页中的 JavaScript 代码发起多个 `fetch` 请求或建立 WebSocket 连接。**
3. **如果服务器配置的并发流限制较低，并且网页尝试建立的连接或请求数量超过了这个限制。**
4. **服务器端的 `QuicSession` 实例会尝试创建新的流，但会发现超过了最大允许数量。**
5. **根据 `quic_session_test.cc` 中测试的逻辑，服务器会选择关闭连接并发送相应的错误码。**
6. **在 Chromium 的网络栈中，相关的错误信息会被记录，开发者可以通过 `chrome://net-internals/#quic` 查看 QUIC 连接的详细信息，包括连接关闭的原因。**
7. **调试时，可以查看 `quic_session_test.cc` 中的测试用例，了解服务器在各种流管理场景下的行为，从而定位问题原因。** 例如，如果看到连接被 `QUIC_TOO_MANY_AVAILABLE_STREAMS` 关闭，可以推断是客户端尝试创建了过多的并发流。

总而言之，这个代码片段集中测试了 `QuicSession` 在服务器端处理流创建、管理和关闭的各种场景，包括正常情况和异常情况，确保 QUIC 连接的稳定性和可靠性。这些测试直接关系到基于 QUIC 协议的 Web 应用的性能和健壮性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
 CheckClosedStreams();
}

TEST_P(QuicSessionTestServer, MaximumAvailableOpenedBidirectionalStreams) {
  QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);
  session_.GetOrCreateStream(stream_id);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_NE(nullptr,
            session_.GetOrCreateStream(GetNthClientInitiatedBidirectionalId(
                session_.max_open_incoming_bidirectional_streams() - 1)));
}

TEST_P(QuicSessionTestServer, MaximumAvailableOpenedUnidirectionalStreams) {
  QuicStreamId stream_id = GetNthClientInitiatedUnidirectionalId(0);
  session_.GetOrCreateStream(stream_id);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_NE(nullptr,
            session_.GetOrCreateStream(GetNthClientInitiatedUnidirectionalId(
                session_.max_open_incoming_unidirectional_streams() - 1)));
}

TEST_P(QuicSessionTestServer, TooManyAvailableBidirectionalStreams) {
  QuicStreamId stream_id1 = GetNthClientInitiatedBidirectionalId(0);
  QuicStreamId stream_id2;
  EXPECT_NE(nullptr, session_.GetOrCreateStream(stream_id1));
  // A stream ID which is too large to create.
  stream_id2 = GetNthClientInitiatedBidirectionalId(
      session_.MaxAvailableBidirectionalStreams() + 2);
  if (VersionHasIetfQuicFrames(transport_version())) {
    // IETF QUIC terminates the connection with invalid stream id
    EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_STREAM_ID, _, _));
  } else {
    // other versions terminate the connection with
    // QUIC_TOO_MANY_AVAILABLE_STREAMS.
    EXPECT_CALL(*connection_,
                CloseConnection(QUIC_TOO_MANY_AVAILABLE_STREAMS, _, _));
  }
  EXPECT_EQ(nullptr, session_.GetOrCreateStream(stream_id2));
}

TEST_P(QuicSessionTestServer, TooManyAvailableUnidirectionalStreams) {
  QuicStreamId stream_id1 = GetNthClientInitiatedUnidirectionalId(0);
  QuicStreamId stream_id2;
  EXPECT_NE(nullptr, session_.GetOrCreateStream(stream_id1));
  // A stream ID which is too large to create.
  stream_id2 = GetNthClientInitiatedUnidirectionalId(
      session_.MaxAvailableUnidirectionalStreams() + 2);
  if (VersionHasIetfQuicFrames(transport_version())) {
    // IETF QUIC terminates the connection with invalid stream id
    EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_STREAM_ID, _, _));
  } else {
    // other versions terminate the connection with
    // QUIC_TOO_MANY_AVAILABLE_STREAMS.
    EXPECT_CALL(*connection_,
                CloseConnection(QUIC_TOO_MANY_AVAILABLE_STREAMS, _, _));
  }
  EXPECT_EQ(nullptr, session_.GetOrCreateStream(stream_id2));
}

TEST_P(QuicSessionTestServer, ManyAvailableBidirectionalStreams) {
  // When max_open_streams_ is 200, should be able to create 200 streams
  // out-of-order, that is, creating the one with the largest stream ID first.
  if (VersionHasIetfQuicFrames(transport_version())) {
    QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(&session_, 200);
    // Smaller limit on unidirectional streams to help detect crossed wires.
    QuicSessionPeer::SetMaxOpenIncomingUnidirectionalStreams(&session_, 50);
  } else {
    QuicSessionPeer::SetMaxOpenIncomingStreams(&session_, 200);
  }
  // Create a stream at the start of the range.
  QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);
  EXPECT_NE(nullptr, session_.GetOrCreateStream(stream_id));

  // Create the largest stream ID of a threatened total of 200 streams.
  // GetNth... starts at 0, so for 200 streams, get the 199th.
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_NE(nullptr, session_.GetOrCreateStream(
                         GetNthClientInitiatedBidirectionalId(199)));

  if (VersionHasIetfQuicFrames(transport_version())) {
    // If IETF QUIC, check to make sure that creating bidirectional
    // streams does not mess up the unidirectional streams.
    stream_id = GetNthClientInitiatedUnidirectionalId(0);
    EXPECT_NE(nullptr, session_.GetOrCreateStream(stream_id));
    // Now try to get the last possible unidirectional stream.
    EXPECT_NE(nullptr, session_.GetOrCreateStream(
                           GetNthClientInitiatedUnidirectionalId(49)));
    // and this should fail because it exceeds the unidirectional limit
    // (but not the bi-)
    EXPECT_CALL(
        *connection_,
        CloseConnection(QUIC_INVALID_STREAM_ID,
                        "Stream id 798 would exceed stream count limit 50",
                        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET))
        .Times(1);
    EXPECT_EQ(nullptr, session_.GetOrCreateStream(
                           GetNthClientInitiatedUnidirectionalId(199)));
  }
}

TEST_P(QuicSessionTestServer, ManyAvailableUnidirectionalStreams) {
  // When max_open_streams_ is 200, should be able to create 200 streams
  // out-of-order, that is, creating the one with the largest stream ID first.
  if (VersionHasIetfQuicFrames(transport_version())) {
    QuicSessionPeer::SetMaxOpenIncomingUnidirectionalStreams(&session_, 200);
    // Smaller limit on unidirectional streams to help detect crossed wires.
    QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(&session_, 50);
  } else {
    QuicSessionPeer::SetMaxOpenIncomingStreams(&session_, 200);
  }
  // Create one stream.
  QuicStreamId stream_id = GetNthClientInitiatedUnidirectionalId(0);
  EXPECT_NE(nullptr, session_.GetOrCreateStream(stream_id));

  // Create the largest stream ID of a threatened total of 200 streams.
  // GetNth... starts at 0, so for 200 streams, get the 199th.
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_NE(nullptr, session_.GetOrCreateStream(
                         GetNthClientInitiatedUnidirectionalId(199)));
  if (VersionHasIetfQuicFrames(transport_version())) {
    // If IETF QUIC, check to make sure that creating unidirectional
    // streams does not mess up the bidirectional streams.
    stream_id = GetNthClientInitiatedBidirectionalId(0);
    EXPECT_NE(nullptr, session_.GetOrCreateStream(stream_id));
    // Now try to get the last possible bidirectional stream.
    EXPECT_NE(nullptr, session_.GetOrCreateStream(
                           GetNthClientInitiatedBidirectionalId(49)));
    // and this should fail because it exceeds the bnidirectional limit
    // (but not the uni-)
    std::string error_detail;
    if (QuicVersionUsesCryptoFrames(transport_version())) {
      error_detail = "Stream id 796 would exceed stream count limit 50";
    } else {
      error_detail = "Stream id 800 would exceed stream count limit 50";
    }
    EXPECT_CALL(
        *connection_,
        CloseConnection(QUIC_INVALID_STREAM_ID, error_detail,
                        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET))
        .Times(1);
    EXPECT_EQ(nullptr, session_.GetOrCreateStream(
                           GetNthClientInitiatedBidirectionalId(199)));
  }
}

TEST_P(QuicSessionTestServer, DebugDFatalIfMarkingClosedStreamWriteBlocked) {
  CompleteHandshake();
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  QuicStreamId closed_stream_id = stream2->id();
  // Close the stream.
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(closed_stream_id, _));
  stream2->Reset(QUIC_BAD_APPLICATION_PAYLOAD);
  std::string msg =
      absl::StrCat("Marking unknown stream ", closed_stream_id, " blocked.");
  EXPECT_QUIC_BUG(session_.MarkConnectionLevelWriteBlocked(closed_stream_id),
                  msg);
}

// SpdySession::OnCanWrite() queries QuicWriteBlockedList for the number of
// streams that are marked as connection level write blocked, then queries
// QuicWriteBlockedList that many times for what stream to write data on.  This
// can result in some streams writing multiple times in a single
// SpdySession::OnCanWrite() call while other streams not getting a turn.
TEST_P(QuicSessionTestServer, OnCanWrite) {
  CompleteHandshake();
  session_.set_writev_consumes_all_data(true);
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_.CreateOutgoingBidirectionalStream();

  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream6->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());

  InSequence s;

  // Reregister, to test the loop limit.
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_.SendStreamData(stream2);
    session_.MarkConnectionLevelWriteBlocked(stream2->id());
  }));

  if (!GetQuicReloadableFlag(quic_disable_batch_write) ||
      GetQuicReloadableFlag(quic_priority_respect_incremental)) {
    // If batched writes are enabled, stream 2 will write again. Also, streams
    // are non-incremental by default, so if the incremental flag is respected,
    // then stream 2 will write again. (If it is not respected, then every
    // stream is treated as incremental.)
    EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
      session_.SendStreamData(stream2);
    }));
    EXPECT_CALL(*stream6, OnCanWrite()).WillOnce(Invoke([this, stream6]() {
      session_.SendStreamData(stream6);
    }));
  } else {
    EXPECT_CALL(*stream6, OnCanWrite()).WillOnce(Invoke([this, stream6]() {
      session_.SendStreamData(stream6);
    }));
    EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
      session_.SendStreamData(stream4);
    }));
  }

  // Stream 4 will not get called, as we exceeded the loop limit.
  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, TestBatchedWrites) {
  session_.set_writev_consumes_all_data(true);
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_.CreateOutgoingBidirectionalStream();

  const QuicStreamPriority priority(
      HttpStreamPriority{HttpStreamPriority::kDefaultUrgency,
                         /* incremental = */ true});
  stream2->SetPriority(priority);
  stream4->SetPriority(priority);
  stream6->SetPriority(priority);

  session_.set_writev_consumes_all_data(true);
  // Tell the session that stream2 and stream4 have data to write.
  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());

  // With two sessions blocked, we should get two write calls.
  InSequence s;
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_.SendLargeFakeData(stream2, 6000);
    session_.MarkConnectionLevelWriteBlocked(stream2->id());
  }));
  if (GetQuicReloadableFlag(quic_disable_batch_write)) {
    EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
      session_.SendLargeFakeData(stream4, 6000);
      session_.MarkConnectionLevelWriteBlocked(stream4->id());
    }));
  } else {
    // Since stream2 only wrote 6 kB and marked itself blocked again,
    // the second write happens on the same stream.
    EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
      session_.SendLargeFakeData(stream2, 6000);
      session_.MarkConnectionLevelWriteBlocked(stream2->id());
    }));
  }
  session_.OnCanWrite();

  // If batched write is enabled, stream2 can write a third time in a row.
  // If batched write is disabled, stream2 has a turn again after stream4.
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_.SendLargeFakeData(stream2, 6000);
    session_.MarkConnectionLevelWriteBlocked(stream2->id());
  }));
  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
    session_.SendLargeFakeData(stream4, 6000);
    session_.MarkConnectionLevelWriteBlocked(stream4->id());
  }));
  session_.OnCanWrite();

  // The next write adds a block for stream 6.
  stream6->SetPriority(QuicStreamPriority(HttpStreamPriority{
      kV3HighestPriority, HttpStreamPriority::kDefaultIncremental}));
  if (GetQuicReloadableFlag(quic_disable_batch_write)) {
    EXPECT_CALL(*stream2, OnCanWrite())
        .WillOnce(Invoke([this, stream2, stream6]() {
          session_.SendLargeFakeData(stream2, 6000);
          session_.MarkConnectionLevelWriteBlocked(stream2->id());
          session_.MarkConnectionLevelWriteBlocked(stream6->id());
        }));
  } else {
    EXPECT_CALL(*stream4, OnCanWrite())
        .WillOnce(Invoke([this, stream4, stream6]() {
          session_.SendLargeFakeData(stream4, 6000);
          session_.MarkConnectionLevelWriteBlocked(stream4->id());
          session_.MarkConnectionLevelWriteBlocked(stream6->id());
        }));
  }
  // Stream 6 will write next, because it has higher priority.
  // It does not mark itself as blocked.
  EXPECT_CALL(*stream6, OnCanWrite())
      .WillOnce(Invoke([this, stream4, stream6]() {
        session_.SendStreamData(stream6);
        session_.SendLargeFakeData(stream4, 6000);
      }));
  session_.OnCanWrite();

  // If batched write is enabled, stream4 can continue to write, but will
  // exhaust its write limit, so the last write is on stream2.
  // If batched write is disabled, stream4 has a turn again, then stream2.
  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
    session_.SendLargeFakeData(stream4, 12000);
    session_.MarkConnectionLevelWriteBlocked(stream4->id());
  }));
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_.SendLargeFakeData(stream2, 6000);
    session_.MarkConnectionLevelWriteBlocked(stream2->id());
  }));
  session_.OnCanWrite();
}

TEST_P(QuicSessionTestServer, OnCanWriteBundlesStreams) {
  // Encryption needs to be established before data can be sent.
  CompleteHandshake();
  MockPacketWriter* writer = static_cast<MockPacketWriter*>(
      QuicConnectionPeer::GetWriter(session_.connection()));

  // Drive congestion control manually.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), send_algorithm);

  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_.CreateOutgoingBidirectionalStream();

  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream6->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());

  EXPECT_CALL(*send_algorithm, CanSend(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*send_algorithm, GetCongestionWindow())
      .WillRepeatedly(Return(kMaxOutgoingPacketSize * 10));
  EXPECT_CALL(*send_algorithm, InRecovery()).WillRepeatedly(Return(false));
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_.SendStreamData(stream2);
  }));
  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
    session_.SendStreamData(stream4);
  }));
  EXPECT_CALL(*stream6, OnCanWrite()).WillOnce(Invoke([this, stream6]() {
    session_.SendStreamData(stream6);
  }));

  // Expect that we only send one packet, the writes from different streams
  // should be bundled together.
  EXPECT_CALL(*writer, WritePacket(_, _, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*send_algorithm, OnPacketSent(_, _, _, _, _));
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));
  session_.OnCanWrite();
  EXPECT_FALSE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, OnCanWriteCongestionControlBlocks) {
  CompleteHandshake();
  session_.set_writev_consumes_all_data(true);
  InSequence s;

  // Drive congestion control manually.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), send_algorithm);

  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_.CreateOutgoingBidirectionalStream();

  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream6->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());

  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_.SendStreamData(stream2);
  }));
  EXPECT_CALL(*send_algorithm, GetCongestionWindow()).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream6, OnCanWrite()).WillOnce(Invoke([this, stream6]() {
    session_.SendStreamData(stream6);
  }));
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(false));
  // stream4->OnCanWrite is not called.

  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());

  // Still congestion-control blocked.
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(false));
  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());

  // stream4->OnCanWrite is called once the connection stops being
  // congestion-control blocked.
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
    session_.SendStreamData(stream4);
  }));
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));
  session_.OnCanWrite();
  EXPECT_FALSE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, OnCanWriteWriterBlocks) {
  CompleteHandshake();
  // Drive congestion control manually in order to ensure that
  // application-limited signaling is handled correctly.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), send_algorithm);
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillRepeatedly(Return(true));

  // Drive packet writer manually.
  MockPacketWriter* writer = static_cast<MockPacketWriter*>(
      QuicConnectionPeer::GetWriter(session_.connection()));
  EXPECT_CALL(*writer, IsWriteBlocked()).WillRepeatedly(Return(true));
  EXPECT_CALL(*writer, WritePacket(_, _, _, _, _, _)).Times(0);

  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();

  session_.MarkConnectionLevelWriteBlocked(stream2->id());

  EXPECT_CALL(*stream2, OnCanWrite()).Times(0);
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_)).Times(0);

  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, SendStreamsBlocked) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  CompleteHandshake();
  for (size_t i = 0; i < kDefaultMaxStreamsPerConnection; ++i) {
    ASSERT_TRUE(session_.CanOpenNextOutgoingBidirectionalStream());
    session_.GetNextOutgoingBidirectionalStreamId();
  }
  // Next checking causes STREAMS_BLOCKED to be sent.
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke([](const QuicFrame& frame) {
        EXPECT_FALSE(frame.streams_blocked_frame.unidirectional);
        EXPECT_EQ(kDefaultMaxStreamsPerConnection,
                  frame.streams_blocked_frame.stream_count);
        ClearControlFrame(frame);
        return true;
      }));
  EXPECT_FALSE(session_.CanOpenNextOutgoingBidirectionalStream());

  for (size_t i = 0; i < kDefaultMaxStreamsPerConnection; ++i) {
    ASSERT_TRUE(session_.CanOpenNextOutgoingUnidirectionalStream());
    session_.GetNextOutgoingUnidirectionalStreamId();
  }
  // Next checking causes STREAM_BLOCKED to be sent.
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke([](const QuicFrame& frame) {
        EXPECT_TRUE(frame.streams_blocked_frame.unidirectional);
        EXPECT_EQ(kDefaultMaxStreamsPerConnection,
                  frame.streams_blocked_frame.stream_count);
        ClearControlFrame(frame);
        return true;
      }));
  EXPECT_FALSE(session_.CanOpenNextOutgoingUnidirectionalStream());
}

TEST_P(QuicSessionTestServer, LimitMaxStreams) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  CompleteHandshake();

  const QuicStreamId kMaxStreams = 4;
  QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(&session_,
                                                          kMaxStreams);
  EXPECT_EQ(kMaxStreams, QuicSessionPeer::ietf_streamid_manager(&session_)
                             ->advertised_max_incoming_bidirectional_streams());

  // Open and close the entire max streams window which will result
  // in two MAX_STREAMS frames being sent.
  std::vector<QuicMaxStreamsFrame> max_stream_frames;
  EXPECT_CALL(*connection_, SendControlFrame(IsFrame(MAX_STREAMS_FRAME)))
      .Times(2)
      .WillRepeatedly(Invoke([&max_stream_frames](const QuicFrame& frame) {
        max_stream_frames.push_back(frame.max_streams_frame);
        ClearControlFrame(frame);
        return true;
      }));
  for (size_t i = 0; i < kMaxStreams; ++i) {
    QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(i);
    QuicStreamFrame data1(stream_id, true, 0, absl::string_view("HT"));
    session_.OnStreamFrame(data1);

    CloseStream(stream_id);
  }
  EXPECT_EQ(2 * kMaxStreams,
            QuicSessionPeer::ietf_streamid_manager(&session_)
                ->advertised_max_incoming_bidirectional_streams());

  // Opening and closing the next max streams window should NOT result
  // in any MAX_STREAMS frames being sent.
  QuicAlarm* alarm = QuicSessionPeer::GetStreamCountResetAlarm(&session_);
  if (alarm->IsSet()) {
    alarm_factory_.FireAlarm(alarm);
  }
  for (size_t i = 0; i < kMaxStreams; ++i) {
    QuicStreamId stream_id =
        GetNthClientInitiatedBidirectionalId(i + kMaxStreams);
    QuicStreamFrame data1(stream_id, true, 0, absl::string_view("HT"));
    session_.OnStreamFrame(data1);

    CloseStream(stream_id);
  }

  // Now when the outstanding MAX_STREAMS frame is ACK'd a new one will be sent.
  EXPECT_CALL(*connection_, SendControlFrame(IsFrame(MAX_STREAMS_FRAME)))
      .WillOnce(Invoke(&ClearControlFrame));
  session_.OnFrameAcked(QuicFrame(max_stream_frames[0]),
                        QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(3 * kMaxStreams,
            QuicSessionPeer::ietf_streamid_manager(&session_)
                ->advertised_max_incoming_bidirectional_streams());

  // Open (but do not close) all available streams to consume the full window.
  if (alarm->IsSet()) {
    alarm_factory_.FireAlarm(alarm);
  }
  for (size_t i = 0; i < kMaxStreams; ++i) {
    QuicStreamId stream_id =
        GetNthClientInitiatedBidirectionalId(i + 2 * kMaxStreams);
    QuicStreamFrame data1(stream_id, true, 0, absl::string_view("HT"));
    session_.OnStreamFrame(data1);
  }

  // When the remaining outstanding MAX_STREAMS frame is ACK'd no new one
  // will be sent because the correct limit has already been advertised.
  session_.OnFrameAcked(QuicFrame(max_stream_frames[1]),
                        QuicTime::Delta::Zero(), QuicTime::Zero());
}

TEST_P(QuicSessionTestServer, BufferedHandshake) {
  // This test is testing behavior of crypto stream flow control, but when
  // CRYPTO frames are used, there is no flow control for the crypto handshake.
  if (QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  session_.set_writev_consumes_all_data(true);
  EXPECT_FALSE(session_.HasPendingHandshake());  // Default value.

  // Test that blocking other streams does not change our status.
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  EXPECT_FALSE(session_.HasPendingHandshake());

  TestStream* stream3 = session_.CreateOutgoingBidirectionalStream();
  session_.MarkConnectionLevelWriteBlocked(stream3->id());
  EXPECT_FALSE(session_.HasPendingHandshake());

  // Blocking (due to buffering of) the Crypto stream is detected.
  session_.MarkConnectionLevelWriteBlocked(
      QuicUtils::GetCryptoStreamId(connection_->transport_version()));
  EXPECT_TRUE(session_.HasPendingHandshake());

  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();
  session_.MarkConnectionLevelWriteBlocked(stream4->id());
  EXPECT_TRUE(session_.HasPendingHandshake());

  InSequence s;
  // Force most streams to re-register, which is common scenario when we block
  // the Crypto stream, and only the crypto stream can "really" write.

  // Due to prioritization, we *should* be asked to write the crypto stream
  // first.
  // Don't re-register the crypto stream (which signals complete writing).
  TestCryptoStream* crypto_stream = session_.GetMutableCryptoStream();
  EXPECT_CALL(*crypto_stream, OnCanWrite());

  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_.SendStreamData(stream2);
  }));
  EXPECT_CALL(*stream3, OnCanWrite()).WillOnce(Invoke([this, stream3]() {
    session_.SendStreamData(stream3);
  }));
  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
    session_.SendStreamData(stream4);
    session_.MarkConnectionLevelWriteBlocked(stream4->id());
  }));

  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());
  EXPECT_FALSE(session_.HasPendingHandshake());  // Crypto stream wrote.
}

TEST_P(QuicSessionTestServer, OnCanWriteWithClosedStream) {
  CompleteHandshake();
  session_.set_writev_consumes_all_data(true);
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_.CreateOutgoingBidirectionalStream();

  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream6->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());
  CloseStream(stream6->id());

  InSequence s;
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_.SendStreamData(stream2);
  }));
  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
    session_.SendStreamData(stream4);
  }));
  session_.OnCanWrite();
  EXPECT_FALSE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, OnCanWriteLimitsNumWritesIfFlowControlBlocked) {
  // Drive congestion control manually in order to ensure that
  // application-limited signaling is handled correctly.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), send_algorithm);
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillRepeatedly(Return(true));

  // Ensure connection level flow control blockage.
  QuicFlowControllerPeer::SetSendWindowOffset(session_.flow_controller(), 0);
  EXPECT_TRUE(session_.flow_controller()->IsBlocked());
  EXPECT_TRUE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());

  // Mark the crypto and headers streams as write blocked, we expect them to be
  // allowed to write later.
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    session_.MarkConnectionLevelWriteBlocked(
        QuicUtils::GetCryptoStreamId(connection_->transport_version()));
  }

  // Create a data stream, and although it is write blocked we never expect it
  // to be allowed to write as we are connection level flow control blocked.
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  session_.MarkConnectionLevelWriteBlocked(stream->id());
  EXPECT_CALL(*stream, OnCanWrite()).Times(0);

  // The crypto and headers streams should be called even though we are
  // connection flow control blocked.
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    TestCryptoStream* crypto_stream = session_.GetMutableCryptoStream();
    EXPECT_CALL(*crypto_stream, OnCanWrite());
  }

  // After the crypto and header streams perform a write, the connection will be
  // blocked by the flow control, hence it should become application-limited.
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));

  session_.OnCanWrite();
  EXPECT_FALSE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, SendGoAway) {
  if (VersionHasIetfQuicFrames(transport_version())) {
    // In IETF QUIC, GOAWAY lives up in the HTTP layer.
    return;
  }
  CompleteHandshake();
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  MockPacketWriter* writer = static_cast<MockPacketWriter*>(
      QuicConnectionPeer::GetWriter(session_.connection()));
  EXPECT_CALL(*writer, WritePacket(_, _, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));

  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallySendControlFrame));
  session_.SendGoAway(QUIC_PEER_GOING_AWAY, "Going Away.");
  EXPECT_TRUE(session_.transport_goaway_sent());

  const QuicStreamId kTestStreamId = 5u;
  EXPECT_CALL(*connection_, SendControlFrame(_)).Times(0);
  EXPECT_CALL(*connection_,
              OnStreamReset(kTestStreamId, QUIC_STREAM_PEER_GOING_AWAY))
      .Times(0);
  EXPECT_TRUE(session_.GetOrCreateStream(kTestStreamId));
}

TEST_P(QuicSessionTestServer, DoNotSendGoAwayTwice) {
  CompleteHandshake();
  if (VersionHasIetfQuicFrames(transport_version())) {
    // In IETF QUIC, GOAWAY lives up in the HTTP layer.
    return;
  }
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke(&ClearControlFrame));
  session_.SendGoAway(QUIC_PEER_GOING_AWAY, "Going Away.");
  EXPECT_TRUE(session_.transport_goaway_sent());
  session_.SendGoAway(QUIC_PEER_GOING_AWAY, "Going Away.");
}

TEST_P(QuicSessionTestServer, InvalidGoAway) {
  if (VersionHasIetfQuicFrames(transport_version())) {
    // In IETF QUIC, GOAWAY lives up in the HTTP layer.
    return;
  }
  QuicGoAwayFrame go_away(kInvalidControlFrameId, QUIC_PEER_GOING_AWAY,
                          session_.next_outgoing_bidirectional_stream_id(), "");
  session_.OnGoAway(go_away);
}

// Test that server session will send a connectivity probe in response to a
// connectivity probe on the same path.
TEST_P(QuicSessionTestServer, ServerReplyToConnectivityProbe) {
  if (VersionHasIetfQuicFrames(transport_version()) ||
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    return;
  }
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  QuicSocketAddress old_peer_address =
      QuicSocketAddress(QuicIpAddress::Loopback4(), kTestPort);
  EXPECT_EQ(old_peer_address, session_.peer_address());

  QuicSocketAddress new_peer_address =
      QuicSocketAddress(QuicIpAddress::Loopback4(), kTestPort + 1);

  MockPacketWriter* writer = static_cast<MockPacketWriter*>(
      QuicConnectionPeer::GetWriter(session_.connection()));
  EXPECT_CALL(*writer, WritePacket(_, _, _, new_peer_address, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));

  EXPECT_CALL(*connection_, SendConnectivityProbingPacket(_, _))
      .WillOnce(
          Invoke(connection_,
                 &MockQuicConnection::ReallySendConnectivityProbingPacket));
  session_.OnPacketReceived(session_.self_address(), new_peer_address,
                            /*is_connectivity_probe=*/true);
  EXPECT_EQ(old_peer_address, session_.peer_address());
}

TEST_P(QuicSessionTestServer, IncreasedTimeoutAfterCryptoHandshake) {
  EXPECT_EQ(kInitialIdleTimeoutSecs + 3,
            QuicConnectionPeer::GetNetworkTimeout(connection_).ToSeconds());
  CompleteHandshake();
  EXPECT_EQ(kMaximumIdleTimeoutSecs + 3,
            QuicConnectionPeer::GetNetworkTimeout(connection_).ToSeconds());
}

TEST_P(QuicSessionTestServer, OnStreamFrameFinStaticStreamId) {
  if (VersionUsesHttp3(connection_->transport_version())) {
    // The test relies on headers stream, which no longer exists in IETF QUIC.
    return;
  }
  QuicStreamId headers_stream_id =
      QuicUtils::GetHeadersStreamId(connection_->transport_version());
  std::unique_ptr<TestStream> fake_headers_stream =
      std::make_unique<TestStream>(headers_stream_id, &session_,
                                   /*is_static*/ true, BIDIRECTIONAL);
  QuicSessionPeer::ActivateStream(&session_, std::move(fake_headers_stream));
  // Send two bytes of payload.
  QuicStreamFrame data1(headers_stream_id, true, 0, absl::string_view("HT"));
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_INVALID_STREAM_ID, "Attempt to close a static stream",
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  session_.OnStreamFrame(data1);
}

TEST_P(QuicSessionTestServer, OnStreamFrameInvalidStreamId) {

"""


```