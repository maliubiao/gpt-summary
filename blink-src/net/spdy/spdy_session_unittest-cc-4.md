Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of `net/spdy/spdy_session_unittest.cc`, its relation to JavaScript, examples of logical reasoning, common user errors, debugging steps, and a summary of the functionality within the provided snippet (part 5 of 8).

2. **Identify the Language and Purpose:**  The file extension `.cc` clearly indicates C++ source code. The name `spdy_session_unittest.cc` strongly suggests it contains unit tests for the `SpdySession` class within the Chromium networking stack. The `unittest` part is a dead giveaway. SPDY is a predecessor to HTTP/2, so this code likely tests the core logic of managing SPDY sessions.

3. **High-Level Functionality:**  The primary purpose is to test the `SpdySession` class. Unit tests focus on isolating and verifying specific aspects of a class's behavior. I expect to see tests related to:
    * Stream creation and management.
    * Flow control (send and receive windows).
    * Handling of SPDY frames (SETTINGS, WINDOW_UPDATE, RST_STREAM, DATA, GOAWAY).
    * Error handling.
    * Interactions with the underlying socket.
    * Priority.

4. **Scan the Code for Key Patterns and Keywords:** I'll look for:
    * `TEST_F`: This is the standard Google Test macro for defining test cases within a test fixture. The fixture name (`SpdySessionTest`, `SpdySessionTestWithMockTime`) tells me which aspects are being tested.
    * `EXPECT_...` and `ASSERT_...`: These are Google Test assertion macros, indicating the expected outcomes of the tests.
    * `CreateMockRead`, `CreateMockWrite`: These strongly suggest the use of mock objects for simulating network socket behavior. The tests are controlling the input and expected output.
    * `SequencedSocketData`, `StaticSocketDataProvider`: These are likely classes for setting up mock socket data with predefined read and write sequences.
    * `spdy_util_.ConstructSpdy...`: This indicates the use of utility functions to create SPDY frame objects.
    * `SpdyStream`, `SpdySession`: These are the core classes being tested.
    * Flow control related terms: `send_window_size`, `recv_window_size`, `WINDOW_UPDATE`, `FLOW_CONTROL_ERROR`.
    * Time-related terms (in `SpdySessionTestWithMockTime`): `AdvanceClock`, `kDefaultTimeToBufferSmallWindowUpdates`.

5. **Analyze Individual Test Cases:** I'll go through each `TEST_F` and try to understand what specific scenario it's testing:
    * `UpdateStreamsSendWindowSize`: Checks how the session's send window size is updated by a SETTINGS frame and how it affects newly created streams.
    * `AdjustRecvWindowSize`: Tests the `IncreaseRecvWindowSize` and `DecreaseRecvWindowSize` methods and verifies that WINDOW_UPDATE frames are sent correctly.
    * `FlowControlSlowReads`: Tests time-based buffering of small window updates.
    * `AdjustSendWindowSize`: Tests the `IncreaseSendWindowSize` and `DecreaseSendWindowSize` methods.
    * `SessionFlowControlInactiveStream`: Checks how incoming data for an inactive stream affects session flow control.
    * `SessionFlowControlPadding`: Verifies that padding is included in flow control calculations.
    * `StreamFlowControlTooMuchData`: Tests the case where the peer sends more data than the stream's receive window allows.
    * `SessionFlowControlTooMuchDataTwoDataFrames` and `StreamFlowControlTooMuchDataTwoDataFrames`: Regression tests for bugs related to flow control with multiple data frames.
    * `SessionFlowControlNoReceiveLeaks` and `SessionFlowControlNoSendLeaks`: Tests to ensure that receive and send windows are correctly updated even when data is dropped or not fully sent.
    * `SessionFlowControlEndToEnd`: A comprehensive test of flow control with bidirectional data exchange.
    * `RunResumeAfterUnstallTest` and related tests (`ResumeAfterUnstallSession`, `ResumeAfterUnstallStream`, etc.): Tests scenarios where streams are stalled due to flow control and then resumed.
    * `ResumeByPriorityAfterSendWindowSizeIncrease`: Tests that streams resume in priority order after the send window is increased.

6. **Relate to JavaScript (if applicable):** SPDY and HTTP/2 are transport protocols. JavaScript running in a browser interacts with these protocols through higher-level APIs like `fetch` or `XMLHttpRequest`. JavaScript doesn't directly manipulate SPDY frames. However, the *behavior* tested here (flow control, stream management, error handling) indirectly impacts JavaScript by influencing how quickly and reliably data is transferred between the browser and the server. For instance, flow control issues could lead to delays or errors observed by JavaScript applications.

7. **Identify Logical Reasoning, Assumptions, Inputs, and Outputs:**  Each test case embodies logical reasoning. The *assumption* is that the `SpdySession` class should behave according to the SPDY specification. The *input* is the sequence of mock socket reads and writes. The *output* is verified through the `EXPECT_...` and `ASSERT_...` statements. For example, in `StreamFlowControlTooMuchData`, the input includes sending a data frame larger than the stream's receive window. The expected output is that the stream is reset with a `FLOW_CONTROL_ERROR`.

8. **Pinpoint Common User/Programming Errors:**  While this is *unit test* code, it reveals potential errors in the *implementation* of `SpdySession`. Common errors related to SPDY/HTTP/2 include:
    * **Incorrect flow control management:** Sending more data than the peer's advertised window size. Not correctly processing WINDOW_UPDATE frames.
    * **Stream ID collisions:** Although not directly shown here, this is a potential issue in a real implementation.
    * **Incorrect handling of SPDY frame types or flags.**
    * **State management errors:**  Incorrectly tracking the state of streams (open, closed, half-closed).

9. **Trace User Actions to Reach the Code (Debugging):** A network engineer or developer debugging SPDY issues might end up here in several ways:
    * **Observing network errors:**  Seeing connection resets, timeouts, or slow data transfer in the browser's developer tools.
    * **Analyzing network logs:** Examining `net-internals` logs in Chrome might reveal SPDY-specific errors or unexpected frame sequences.
    * **Reproducing a bug reported by a user:**  If a user reports an issue related to network performance on a site using SPDY/HTTP/2, developers might try to reproduce the issue and then debug the underlying network stack.
    * **Writing or debugging network code:** Developers working on Chromium's networking stack would directly interact with this code.

10. **Summarize Functionality (Part 5):**  Based on the analysis of the provided snippet, the main focus of this section is **testing the flow control mechanisms of the `SpdySession` class**. This includes:
    * Updating session and stream send window sizes based on SETTINGS frames.
    * Adjusting session receive window size and triggering WINDOW_UPDATE frames.
    * Handling flow control when receiving data for inactive streams.
    * Ensuring padding is correctly accounted for in flow control.
    * Testing scenarios where the peer sends more data than allowed by flow control (both session and stream level).
    * Regression tests for specific flow control bugs.
    * Verifying that send and receive windows are managed correctly to prevent "leaks."
    * End-to-end testing of flow control during bidirectional data transfer.
    * Testing the resumption of stalled streams after increasing flow control windows.
    * Ensuring streams resume in priority order.

By following these steps, I can systematically break down the provided code snippet and provide a comprehensive answer to the user's request. The key is to understand the context (unit testing for SPDY), identify the core functionalities being tested, and then analyze each test case in detail.
这是一个Chromium网络栈中 `net/spdy/spdy_session_unittest.cc` 文件的第五部分，主要功能是**测试 `SpdySession` 类的流量控制机制**。

**归纳一下这部分的功能：**

这部分代码专注于测试 `SpdySession` 类在处理流量控制时的各种场景，包括：

* **更新发送窗口大小：** 测试当接收到 `SETTINGS` 帧时，`SpdySession` 如何更新自身的发送窗口大小，以及如何影响后续创建的流的发送窗口大小。
* **调整接收窗口大小：** 测试 `IncreaseRecvWindowSize` 和 `DecreaseRecvWindowSize` 方法是否能正确调整会话的接收窗口大小，以及是否会在合适的时机发送 `WINDOW_UPDATE` 帧。
* **慢速读取时的流量控制：** 测试当接收数据较慢时，如何通过时间延迟来触发 `WINDOW_UPDATE` 帧的发送。
* **调整发送窗口大小 (Spdy 3.1)：**  虽然注释提到 "enable_spdy_31" flag，但实际代码并没有明显的 Spdy 3.1 特性，可能是一个早期版本的测试或注释未更新。这里测试的是基本的发送窗口大小调整。
* **非活跃流的流量控制：** 测试当接收到针对非活跃流的数据时，如何影响会话的接收窗口大小和未确认的接收窗口字节数。
* **Padding 的流量控制：** 测试在流量控制中是否正确计算了 SPDY 数据帧的 padding 部分。
* **超过流级别流量控制窗口的数据：** 测试当对端发送的数据超过流的接收窗口大小时，`SpdySession` 如何处理，通常会导致流被重置 (`RST_STREAM`)。
* **会话级别流量控制中接收过多数据 (两个数据帧)：**  这是对一个特定 bug 的回归测试，该 bug 发生在计算会话级别流量控制时，未发送的 `WINDOW_UPDATE` 的增量被错误地包含在内。测试了接收两个数据帧，第一个没问题，但第二个会导致超过会话接收窗口。
* **流级别流量控制中接收过多数据 (两个数据帧)：** 类似于上面的会话级别测试，但针对的是流级别的流量控制。
* **没有接收泄露的流量控制：** 测试即使接收方丢弃收到的数据，接收窗口也能正确增加，避免 "泄露"。
* **没有发送泄露的流量控制：** 测试当数据帧还未发送到 socket 就关闭流时，发送窗口也能正确增加，避免 "泄露"。
* **端到端流量控制：** 测试双向数据传输时，发送和接收窗口如何正确变化。
* **流量控制阻塞后恢复：** 通过不同的阻塞和恢复方式（会话级别和流级别），测试当流因流量控制被阻塞后，在窗口增加后能否正确恢复发送。
* **优先级恢复：** 测试当多个流因流量控制被阻塞时，当发送窗口增加后，流是否按照优先级顺序恢复发送。

**与 Javascript 的功能关系：**

`spdy_session_unittest.cc` 是 C++ 代码，直接与 Javascript 没有关系。然而，它测试的网络协议 (SPDY，虽然现在更多是 HTTP/2) 是浏览器与服务器通信的基础。

* **间接影响：** Javascript 通过浏览器提供的 Web API (如 `fetch` 或 `XMLHttpRequest`) 发起网络请求。`SpdySession` 的正确运行直接影响这些 API 的性能和可靠性。例如，流量控制机制的正确实现可以防止网络拥塞，提高数据传输效率，从而提升 Javascript 应用的响应速度。
* **调试线索：** 如果前端 Javascript 应用出现网络请求缓慢或失败的问题，后端开发人员或网络工程师可能会检查服务器端和浏览器端的网络栈实现，这时就可能涉及到 `SpdySession` 相关的代码。

**逻辑推理的举例说明：**

例如，在 `TEST_F(SpdySessionTest, StreamFlowControlTooMuchData)` 中：

* **假设输入：**
    * 创建一个流，其初始接收窗口大小设置为 `stream_max_recv_window_size` (例如 1024)。
    * 对端发送一个大小为 `data_frame_size` (例如 2 * 1024) 的数据帧。
* **逻辑推理：** 因为数据帧的大小超过了流的接收窗口大小，所以 `SpdySession` 应该检测到流量控制错误。
* **预期输出：**
    * `SpdySession` 发送一个 `RST_STREAM` 帧来重置该流，错误码为 `FLOW_CONTROL_ERROR`。
    * 该流被关闭。

**用户或编程常见的使用错误举例说明：**

虽然这个文件是单元测试，但它可以帮助理解在实际应用中可能出现的问题：

* **用户操作导致的问题：**
    * **网络环境不稳定：**  虽然不是直接的代码错误，但网络波动可能导致数据包丢失或延迟，从而触发流量控制机制。例如，用户在弱网环境下访问网站，可能会看到请求被延迟或中断。
* **编程错误导致的问题：**
    * **服务器端流量控制配置错误：** 如果服务器端的流量控制参数配置不当，可能会限制客户端的发送速度，导致请求被阻塞。
    * **客户端未正确处理流量控制信号：** 虽然浏览器会自动处理大部分流量控制，但在一些自定义的网络应用中，如果开发者没有正确处理服务器发送的流量控制信号 (例如 `WINDOW_UPDATE` 帧)，可能会导致发送缓冲区溢出或连接被断开。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户在使用 Chrome 浏览器访问一个使用了 HTTP/2 (SPDY 的后继者，原理类似) 的网站时遇到以下问题：

1. **用户访问网站很慢，或者部分资源加载不出来。**
2. **用户打开 Chrome 的开发者工具 (DevTools)，查看 Network 面板。** 他们可能会看到一些请求的状态是 "Stalled" 或 "Pending" 很长时间。
3. **用户或开发者可能会打开 `chrome://net-internals/#http2` 或 `chrome://net-internals/#events` 来查看更详细的网络日志。** 这些日志可能会显示与特定 SPDY 会话相关的错误，例如流量控制错误。
4. **如果需要深入调试 Chromium 源代码，开发人员可能会查看 `net/spdy` 目录下的代码，包括 `spdy_session.cc` 和 `spdy_session_unittest.cc`。** `spdy_session_unittest.cc` 中的测试用例可以帮助理解 `SpdySession` 在各种流量控制场景下的行为，从而定位问题所在。例如，如果日志中显示 "FLOW_CONTROL_ERROR"，开发人员可能会查看 `StreamFlowControlTooMuchData` 或相关的测试用例来理解这种错误是如何产生的。

**这是第5部分，共8部分，请归纳一下它的功能：**

正如前面总结的，这部分 (第 5 部分) 的核心功能是 **测试 `SpdySession` 类的流量控制机制**。它涵盖了发送和接收窗口的调整、Padding 的处理、超过流量控制窗口的处理、避免流量泄露以及流量控制阻塞后的恢复等各种场景。这些测试确保了 `SpdySession` 能够按照 SPDY 协议规范正确地管理数据传输，防止网络拥塞，并保证连接的稳定性和效率。

Prompt: 
```
这是目录为net/spdy/spdy_session_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共8部分，请归纳一下它的功能

"""
t(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_REFUSED_STREAM));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(rst, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), MockRead(ASYNC, 0, 4)  // EOF
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream);
  EXPECT_EQ(0u, spdy_stream->stream_id());

  StreamCreatingDelegate delegate(spdy_stream, session_);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  EXPECT_EQ(0u, spdy_stream->stream_id());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream->stream_id());

  // Cause the stream to be reset, which should cause another stream
  // to be created.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(spdy_stream);
  EXPECT_TRUE(delegate.StreamIsClosed());
  EXPECT_EQ(0u, num_active_streams());
  EXPECT_EQ(1u, num_created_streams());

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, UpdateStreamsSendWindowSize) {
  // Set spdy::SETTINGS_INITIAL_WINDOW_SIZE to a small number so that
  // WINDOW_UPDATE gets sent.
  spdy::SettingsMap new_settings;
  int32_t window_size = 1;
  new_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] = window_size;

  // Set up the socket so we read a SETTINGS frame that sets
  // INITIAL_WINDOW_SIZE.
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(new_settings));
  MockRead reads[] = {
      CreateMockRead(settings_frame, 0), MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 0, 2)  // EOF
  };

  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  MockWrite writes[] = {
      CreateMockWrite(settings_ack, 3),
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();
  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  TestCompletionCallback callback1;
  EXPECT_NE(spdy_stream1->send_window_size(), window_size);

  // Process the SETTINGS frame.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(stream_initial_send_window_size(), window_size);
  EXPECT_EQ(spdy_stream1->send_window_size(), window_size);

  // Release the first one, this will allow the second to be created.
  spdy_stream1->Cancel(ERR_ABORTED);
  EXPECT_FALSE(spdy_stream1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(spdy_stream2->send_window_size(), window_size);
  spdy_stream2->Cancel(ERR_ABORTED);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// SpdySession::{Increase,Decrease}RecvWindowSize should properly
// adjust the session receive window size. In addition,
// SpdySession::IncreaseRecvWindowSize should trigger
// sending a WINDOW_UPDATE frame for a large enough delta.
TEST_F(SpdySessionTest, AdjustRecvWindowSize) {
  const int32_t initial_window_size = kDefaultInitialWindowSize;
  const int32_t delta_window_size = 100;

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), MockRead(ASYNC, 0, 2)  // EOF
  };
  spdy::SpdySerializedFrame window_update(spdy_util_.ConstructSpdyWindowUpdate(
      spdy::kSessionFlowControlStreamId,
      initial_window_size + delta_window_size));
  MockWrite writes[] = {
      CreateMockWrite(window_update, 0),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  IncreaseRecvWindowSize(delta_window_size);
  EXPECT_EQ(initial_window_size + delta_window_size,
            session_recv_window_size());
  EXPECT_EQ(delta_window_size, session_unacked_recv_window_bytes());

  // Should trigger sending a WINDOW_UPDATE frame.
  IncreaseRecvWindowSize(initial_window_size);
  EXPECT_EQ(initial_window_size + delta_window_size + initial_window_size,
            session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  base::RunLoop().RunUntilIdle();

  // DecreaseRecvWindowSize() expects |in_io_loop_| to be true.
  set_in_io_loop(true);
  DecreaseRecvWindowSize(initial_window_size + delta_window_size +
                         initial_window_size);
  set_in_io_loop(false);
  EXPECT_EQ(0, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// SpdySession::{Increase,Decrease}RecvWindowSize should properly
// adjust the session receive window size. In addition,
// SpdySession::IncreaseRecvWindowSize should trigger
// sending a WINDOW_UPDATE frame for a small delta after
// kDefaultTimeToBufferSmallWindowUpdates time has passed.
TEST_F(SpdySessionTestWithMockTime, FlowControlSlowReads) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  CreateNetworkSession();
  session_ = CreateFakeSpdySession(spdy_session_pool_, key_);

  // Re-enable the time-based window update buffering. The test harness
  // disables it by default to prevent flakiness.
  session_->SetTimeToBufferSmallWindowUpdates(
      kDefaultTimeToBufferSmallWindowUpdates);

  const int32_t initial_window_size = kDefaultInitialWindowSize;
  const int32_t delta_window_size = 100;

  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  // Receive data, consuming some of the receive window.
  set_in_io_loop(true);
  DecreaseRecvWindowSize(delta_window_size);
  set_in_io_loop(false);

  EXPECT_EQ(initial_window_size - delta_window_size,
            session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  // Consume the data, returning some of the receive window (locally)
  IncreaseRecvWindowSize(delta_window_size);
  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(delta_window_size, session_unacked_recv_window_bytes());

  // Receive data, consuming some of the receive window.
  set_in_io_loop(true);
  DecreaseRecvWindowSize(delta_window_size);
  set_in_io_loop(false);

  // Window updates after a configured time second should force a WINDOW_UPDATE,
  // draining the unacked window bytes.
  AdvanceClock(kDefaultTimeToBufferSmallWindowUpdates);
  IncreaseRecvWindowSize(delta_window_size);
  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());
}

// SpdySession::{Increase,Decrease}SendWindowSize should properly
// adjust the session send window size when the "enable_spdy_31" flag
// is set.
TEST_F(SpdySessionTest, AdjustSendWindowSize) {
  MockRead reads[] = {
    MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  CreateNetworkSession();
  session_ = CreateFakeSpdySession(spdy_session_pool_, key_);

  const int32_t initial_window_size = kDefaultInitialWindowSize;
  const int32_t delta_window_size = 100;

  EXPECT_EQ(initial_window_size, session_send_window_size());

  IncreaseSendWindowSize(delta_window_size);
  EXPECT_EQ(initial_window_size + delta_window_size,
            session_send_window_size());

  DecreaseSendWindowSize(delta_window_size);
  EXPECT_EQ(initial_window_size, session_send_window_size());
}

// Incoming data for an inactive stream should not cause the session
// receive window size to decrease, but it should cause the unacked
// bytes to increase.
TEST_F(SpdySessionTest, SessionFlowControlInactiveStream) {
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyDataFrame(1, false));
  MockRead reads[] = {
      CreateMockRead(resp, 0), MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 0, 2)  // EOF
  };
  SequencedSocketData data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  EXPECT_EQ(kDefaultInitialWindowSize, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(kDefaultInitialWindowSize, session_recv_window_size());
  EXPECT_EQ(kUploadDataSize, session_unacked_recv_window_bytes());

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// The frame header is not included in flow control, but frame payload
// (including optional pad length and padding) is.
TEST_F(SpdySessionTest, SessionFlowControlPadding) {
  const int padding_length = 42;
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyDataFrame(1, kUploadData, false, padding_length));
  MockRead reads[] = {
      CreateMockRead(resp, 0), MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 0, 2)  // EOF
  };
  SequencedSocketData data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  EXPECT_EQ(kDefaultInitialWindowSize, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(kDefaultInitialWindowSize, session_recv_window_size());
  EXPECT_EQ(kUploadDataSize + padding_length,
            session_unacked_recv_window_bytes());

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Peer sends more data than stream level receiving flow control window.
TEST_F(SpdySessionTest, StreamFlowControlTooMuchData) {
  const int32_t stream_max_recv_window_size = 1024;
  const int32_t data_frame_size = 2 * stream_max_recv_window_size;

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(spdy_util_.ConstructSpdyRstStream(
      1, spdy::ERROR_CODE_FLOW_CONTROL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 4),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  const std::string payload(data_frame_size, 'a');
  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, payload, false));
  MockRead reads[] = {
      CreateMockRead(resp, 1),       MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(data_frame, 3), MockRead(ASYNC, ERR_IO_PENDING, 5),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  session_deps_.http2_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] =
      stream_max_recv_window_size;
  CreateNetworkSession();

  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  EXPECT_EQ(stream_max_recv_window_size, spdy_stream->recv_window_size());

  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, spdy_stream->SendRequestHeaders(
                                std::move(headers), NO_MORE_DATA_TO_SEND));

  // Request and response.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, spdy_stream->stream_id());

  // Too large data frame causes flow control error, should close stream.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream);

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Regression test for a bug that was caused by including unsent WINDOW_UPDATE
// deltas in the receiving window size when checking incoming frames for flow
// control errors at session level.
TEST_F(SpdySessionTest, SessionFlowControlTooMuchDataTwoDataFrames) {
  const int32_t session_max_recv_window_size = 500;
  const int32_t first_data_frame_size = 200;
  const int32_t second_data_frame_size = 400;

  // First data frame should not trigger a WINDOW_UPDATE.
  ASSERT_GT(session_max_recv_window_size / 2, first_data_frame_size);
  // Second data frame would be fine had there been a WINDOW_UPDATE.
  ASSERT_GT(session_max_recv_window_size, second_data_frame_size);
  // But in fact, the two data frames together overflow the receiving window at
  // session level.
  ASSERT_LT(session_max_recv_window_size,
            first_data_frame_size + second_data_frame_size);

  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_FLOW_CONTROL_ERROR,
      "delta_window_size is 400 in DecreaseRecvWindowSize, which is larger "
      "than the receive window size of 300"));
  MockWrite writes[] = {
      CreateMockWrite(goaway, 4),
  };

  const std::string first_data_frame(first_data_frame_size, 'a');
  spdy::SpdySerializedFrame first(
      spdy_util_.ConstructSpdyDataFrame(1, first_data_frame, false));
  const std::string second_data_frame(second_data_frame_size, 'b');
  spdy::SpdySerializedFrame second(
      spdy_util_.ConstructSpdyDataFrame(1, second_data_frame, false));
  MockRead reads[] = {
      CreateMockRead(first, 0), MockRead(ASYNC, ERR_IO_PENDING, 1),
      CreateMockRead(second, 2), MockRead(ASYNC, 0, 3),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();
  // Setting session level receiving window size to smaller than initial is not
  // possible via SpdySessionPoolPeer.
  set_session_recv_window_size(session_max_recv_window_size);

  // First data frame is immediately consumed and does not trigger
  // WINDOW_UPDATE.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(first_data_frame_size, session_unacked_recv_window_bytes());
  EXPECT_EQ(session_max_recv_window_size, session_recv_window_size());
  EXPECT_TRUE(session_->IsAvailable());

  // Second data frame overflows receiving window, causes session to close.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(session_->IsDraining());
}

// Regression test for a bug that was caused by including unsent WINDOW_UPDATE
// deltas in the receiving window size when checking incoming data frames for
// flow control errors at stream level.
TEST_F(SpdySessionTest, StreamFlowControlTooMuchDataTwoDataFrames) {
  const int32_t stream_max_recv_window_size = 500;
  const int32_t first_data_frame_size = 200;
  const int32_t second_data_frame_size = 400;

  // First data frame should not trigger a WINDOW_UPDATE.
  ASSERT_GT(stream_max_recv_window_size / 2, first_data_frame_size);
  // Second data frame would be fine had there been a WINDOW_UPDATE.
  ASSERT_GT(stream_max_recv_window_size, second_data_frame_size);
  // But in fact, they should overflow the receiving window at stream level.
  ASSERT_LT(stream_max_recv_window_size,
            first_data_frame_size + second_data_frame_size);

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(spdy_util_.ConstructSpdyRstStream(
      1, spdy::ERROR_CODE_FLOW_CONTROL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 6),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  const std::string first_data_frame(first_data_frame_size, 'a');
  spdy::SpdySerializedFrame first(
      spdy_util_.ConstructSpdyDataFrame(1, first_data_frame, false));
  const std::string second_data_frame(second_data_frame_size, 'b');
  spdy::SpdySerializedFrame second(
      spdy_util_.ConstructSpdyDataFrame(1, second_data_frame, false));
  MockRead reads[] = {
      CreateMockRead(resp, 1),   MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(first, 3),  MockRead(ASYNC, ERR_IO_PENDING, 4),
      CreateMockRead(second, 5), MockRead(ASYNC, ERR_IO_PENDING, 7),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  session_deps_.http2_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] =
      stream_max_recv_window_size;
  CreateNetworkSession();

  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, spdy_stream->SendRequestHeaders(
                                std::move(headers), NO_MORE_DATA_TO_SEND));

  // Request and response.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(spdy_stream->IsLocallyClosed());
  EXPECT_EQ(stream_max_recv_window_size, spdy_stream->recv_window_size());

  // First data frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(spdy_stream->IsLocallyClosed());
  EXPECT_EQ(stream_max_recv_window_size - first_data_frame_size,
            spdy_stream->recv_window_size());

  // Consume first data frame.  This does not trigger a WINDOW_UPDATE.
  std::string received_data = delegate.TakeReceivedData();
  EXPECT_EQ(static_cast<size_t>(first_data_frame_size), received_data.size());
  EXPECT_EQ(stream_max_recv_window_size, spdy_stream->recv_window_size());

  // Second data frame overflows receiving window, causes the stream to close.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream.get());

  // RST_STREAM
  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// A delegate that drops any received data.
class DropReceivedDataDelegate : public test::StreamDelegateSendImmediate {
 public:
  DropReceivedDataDelegate(const base::WeakPtr<SpdyStream>& stream,
                           std::string_view data)
      : StreamDelegateSendImmediate(stream, data) {}

  ~DropReceivedDataDelegate() override = default;

  // Drop any received data.
  void OnDataReceived(std::unique_ptr<SpdyBuffer> buffer) override {}
};

// Send data back and forth but use a delegate that drops its received
// data. The receive window should still increase to its original
// value, i.e. we shouldn't "leak" receive window bytes.
TEST_F(SpdySessionTest, SessionFlowControlNoReceiveLeaks) {
  const int32_t kMsgDataSize = 100;
  const std::string msg_data(kMsgDataSize, 'a');

  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kMsgDataSize, MEDIUM, nullptr, 0));
  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, msg_data, false));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(msg, 2),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, msg_data, false));
  spdy::SpdySerializedFrame window_update(spdy_util_.ConstructSpdyWindowUpdate(
      spdy::kSessionFlowControlStreamId, kMsgDataSize));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(echo, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), MockRead(ASYNC, 0, 5)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> stream =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(0u, stream->stream_id());

  DropReceivedDataDelegate delegate(stream, msg_data);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kMsgDataSize));
  EXPECT_EQ(ERR_IO_PENDING,
            stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND));

  const int32_t initial_window_size = kDefaultInitialWindowSize;
  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(kMsgDataSize, session_unacked_recv_window_bytes());

  stream->Close();
  EXPECT_FALSE(stream);

  EXPECT_THAT(delegate.WaitForClose(), IsOk());

  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(kMsgDataSize, session_unacked_recv_window_bytes());

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Send data back and forth but close the stream before its data frame
// can be written to the socket. The send window should then increase
// to its original value, i.e. we shouldn't "leak" send window bytes.
TEST_F(SpdySessionTest, SessionFlowControlNoSendLeaks) {
  const int32_t kMsgDataSize = 100;
  const std::string msg_data(kMsgDataSize, 'a');

  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kMsgDataSize, MEDIUM, nullptr, 0));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(resp, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> stream =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(0u, stream->stream_id());

  test::StreamDelegateSendImmediate delegate(stream, msg_data);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kMsgDataSize));
  EXPECT_EQ(ERR_IO_PENDING,
            stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND));

  const int32_t initial_window_size = kDefaultInitialWindowSize;
  EXPECT_EQ(initial_window_size, session_send_window_size());

  // Write request.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(initial_window_size, session_send_window_size());

  // Read response, but do not run the message loop, so that the body is not
  // written to the socket.
  data.Resume();

  EXPECT_EQ(initial_window_size - kMsgDataSize, session_send_window_size());

  // Closing the stream should increase the session's send window.
  stream->Close();
  EXPECT_FALSE(stream);

  EXPECT_EQ(initial_window_size, session_send_window_size());

  EXPECT_THAT(delegate.WaitForClose(), IsOk());

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Send data back and forth; the send and receive windows should
// change appropriately.
TEST_F(SpdySessionTest, SessionFlowControlEndToEnd) {
  const int32_t kMsgDataSize = 100;
  const std::string msg_data(kMsgDataSize, 'a');

  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kMsgDataSize, MEDIUM, nullptr, 0));
  spdy::SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, msg_data, false));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(msg, 2),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, msg_data, false));
  spdy::SpdySerializedFrame window_update(spdy_util_.ConstructSpdyWindowUpdate(
      spdy::kSessionFlowControlStreamId, kMsgDataSize));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(echo, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5),
      CreateMockRead(window_update, 6),
      MockRead(ASYNC, ERR_IO_PENDING, 7),
      MockRead(ASYNC, 0, 8)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> stream =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(0u, stream->stream_id());

  test::StreamDelegateSendImmediate delegate(stream, msg_data);
  stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kMsgDataSize));
  EXPECT_EQ(ERR_IO_PENDING,
            stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND));

  const int32_t initial_window_size = kDefaultInitialWindowSize;
  EXPECT_EQ(initial_window_size, session_send_window_size());
  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  // Send request and message.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(initial_window_size - kMsgDataSize, session_send_window_size());
  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  // Read echo.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(initial_window_size - kMsgDataSize, session_send_window_size());
  EXPECT_EQ(initial_window_size - kMsgDataSize, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  // Read window update.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(initial_window_size, session_send_window_size());
  EXPECT_EQ(initial_window_size - kMsgDataSize, session_recv_window_size());
  EXPECT_EQ(0, session_unacked_recv_window_bytes());

  EXPECT_EQ(msg_data, delegate.TakeReceivedData());

  // Draining the delegate's read queue should increase the session's
  // receive window.
  EXPECT_EQ(initial_window_size, session_send_window_size());
  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(kMsgDataSize, session_unacked_recv_window_bytes());

  stream->Close();
  EXPECT_FALSE(stream);

  EXPECT_THAT(delegate.WaitForClose(), IsOk());

  EXPECT_EQ(initial_window_size, session_send_window_size());
  EXPECT_EQ(initial_window_size, session_recv_window_size());
  EXPECT_EQ(kMsgDataSize, session_unacked_recv_window_bytes());

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Given a stall function and an unstall function, runs a test to make
// sure that a stream resumes after unstall.
void SpdySessionTest::RunResumeAfterUnstallTest(
    base::OnceCallback<void(SpdyStream*)> stall_function,
    base::OnceCallback<void(SpdyStream*, int32_t)> unstall_function) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataStringPiece, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 1),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataStringPiece, false));
  MockRead reads[] = {
      CreateMockRead(resp, 2), MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  test::StreamDelegateWithBody delegate(stream, kBodyDataStringPiece);
  stream->SetDelegate(&delegate);

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING,
            stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream->url().spec());

  std::move(stall_function).Run(stream.get());

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream->send_stalled_by_flow_control());

  std::move(unstall_function).Run(stream.get(), kBodyDataSize);

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate.TakeReceivedData());

  // Run SpdySession::PumpWriteLoop which destroys |session_|.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(session_);
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Run the resume-after-unstall test with all possible stall and
// unstall sequences.

TEST_F(SpdySessionTest, ResumeAfterUnstallSession) {
  RunResumeAfterUnstallTest(base::BindOnce(&SpdySessionTest::StallSessionOnly,
                                           base::Unretained(this)),
                            base::BindOnce(&SpdySessionTest::UnstallSessionOnly,
                                           base::Unretained(this)));
}

// Equivalent to
// SpdyStreamTest.ResumeAfterSendWindowSizeIncrease.
TEST_F(SpdySessionTest, ResumeAfterUnstallStream) {
  RunResumeAfterUnstallTest(
      base::BindOnce(&SpdySessionTest::StallStreamOnly, base::Unretained(this)),
      base::BindOnce(&SpdySessionTest::UnstallStreamOnly,
                     base::Unretained(this)));
}

TEST_F(SpdySessionTest, StallSessionStreamResumeAfterUnstallSessionStream) {
  RunResumeAfterUnstallTest(
      base::BindOnce(&SpdySessionTest::StallSessionStream,
                     base::Unretained(this)),
      base::BindOnce(&SpdySessionTest::UnstallSessionStream,
                     base::Unretained(this)));
}

TEST_F(SpdySessionTest, StallStreamSessionResumeAfterUnstallSessionStream) {
  RunResumeAfterUnstallTest(
      base::BindOnce(&SpdySessionTest::StallStreamSession,
                     base::Unretained(this)),
      base::BindOnce(&SpdySessionTest::UnstallSessionStream,
                     base::Unretained(this)));
}

TEST_F(SpdySessionTest, StallStreamSessionResumeAfterUnstallStreamSession) {
  RunResumeAfterUnstallTest(
      base::BindOnce(&SpdySessionTest::StallStreamSession,
                     base::Unretained(this)),
      base::BindOnce(&SpdySessionTest::UnstallStreamSession,
                     base::Unretained(this)));
}

TEST_F(SpdySessionTest, StallSessionStreamResumeAfterUnstallStreamSession) {
  RunResumeAfterUnstallTest(
      base::BindOnce(&SpdySessionTest::StallSessionStream,
                     base::Unretained(this)),
      base::BindOnce(&SpdySessionTest::UnstallStreamSession,
                     base::Unretained(this)));
}

// Cause a stall by reducing the flow control send window to 0. The
// streams should resume in priority order when that window is then
// increased.
TEST_F(SpdySessionTest, ResumeByPriorityAfterSendWindowSizeIncrease) {
  spdy::SpdySerializedFrame req1(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOWEST, nullptr, 0));
  spdy::SpdyS
"""


```