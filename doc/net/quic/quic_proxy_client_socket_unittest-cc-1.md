Response:
The user wants a summary of the functionality of the provided C++ code, which is the second part of a unit test file for `QuicProxyClientSocket` in Chromium's network stack. The request also asks for connections to JavaScript, logical inferences, common user/programming errors, and debugging information.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The file is a unit test (`*_unittest.cc`) for `QuicProxyClientSocket`. Unit tests verify the correct behavior of a specific class or component in isolation. Therefore, the primary function is to test various aspects of how `QuicProxyClientSocket` interacts with its dependencies (primarily the underlying QUIC session and stream).

2. **Analyze the Test Cases:**  Go through each `TEST_P` function and determine what specific scenario it's testing. Look for the `mock_quic_data_` setup, the actions performed on the `sock_` object (the `QuicProxyClientSocket` instance), and the assertions made.

3. **Group Similar Test Cases:** Notice patterns in the tests. Some tests focus on reading data (successful reads, errors, after FIN), others on writing data (successful writes, errors, when closed/disconnected), and some on the interaction between reads and writes (async scenarios, pending operations). There are also tests for connection establishment (auth/error responses) and lifecycle management (closing, disconnecting).

4. **Look for Specific Functionality Tested:**  Note down the key areas being tested:
    * Handling of authentication and error responses during connection.
    * Asynchronous read and write operations and their interaction.
    * Behavior when the socket is closed or disconnected.
    * Handling of pending read/write operations when the socket is closed or disconnected.
    * NetLog integration.
    * Scenarios where the socket object is deleted during a callback.

5. **Address the Specific Requirements:**

    * **Functionality Listing:**  Summarize the groups of test cases into a list of functionalities. Use descriptive language.

    * **JavaScript Relationship:**  Consider how `QuicProxyClientSocket` might be used in a browser context. Since it handles proxy connections over QUIC, it's likely involved when a web page accessed via a proxy uses QUIC. Think about JavaScript making network requests –  `fetch()` is a good example. Explain how a proxy configured in the browser settings would lead to this code being invoked.

    * **Logical Inferences:** Look for tests that simulate specific sequences of events and assert the outcomes. Choose a test with a clear setup and predictable result. Explain the input (mock data) and the expected output (assertion results).

    * **User/Programming Errors:** Identify tests that expose common mistakes. For example, trying to read or write on a closed socket is a common error. Explain *why* this is an error (resource issues, undefined behavior).

    * **User Steps to Reach the Code:**  Trace back the steps a user might take in a browser to cause this code to be executed. Start with a user action (opening a website), and connect it to the underlying network mechanisms (proxy settings, QUIC protocol).

    * **Debugging Clues:**  Focus on the information the tests provide for debugging. The `mock_quic_data_` setup is crucial, as it shows the expected sequence of QUIC packets. The assertions pinpoint where a failure occurs. The NetLog test shows how to use logging for diagnosis.

    * **Part 2 Summary:**  Combine the functionalities identified in step 4 into a concise summary of the second part of the test file. Emphasize the focus on data transfer and lifecycle management after the initial connection.

6. **Refine and Organize:**  Structure the answer logically, using clear headings and bullet points. Ensure the language is precise and avoids jargon where possible. Review the answer to make sure it addresses all aspects of the prompt. For example, initially, I might have just listed the test case names, but the prompt asks for functionality, requiring a higher-level interpretation. Also, double-check the accuracy of the inferences and examples.
这是 `net/quic/quic_proxy_client_socket_unittest.cc` 文件第二部分的功能归纳：

**主要功能归纳：**

这部分测试用例主要关注 `QuicProxyClientSocket` 在建立连接后的数据读写行为以及连接生命周期管理相关的场景。具体来说，它测试了以下几个方面的功能：

* **读取响应体：** 测试在代理认证请求和代理错误发生时，如何读取服务器的响应体数据。
* **异步读写操作：**  深入测试了异步读取和写入操作，以及它们之间的交互，例如在一个写操作进行时发起读操作，反之亦然，确保操作的正确顺序和阻塞行为。
* **已关闭或断开连接的读写操作：** 验证在 `QuicProxyClientSocket` 已经关闭或断开连接的情况下，进行读写操作会返回预期的错误或状态。
* **连接关闭时的读写行为：**  测试在接收到 FIN 包后以及连接关闭期间的读取行为，确保已接收的数据被正确读取，并且后续的读取返回 0。
* **待处理的读写操作与连接关闭/断开：**  测试当有未完成的读或写操作时，连接被关闭或断开会发生什么情况，例如回调是否会被触发，以及返回的错误码是否正确。
* **连接重置时的读写行为：**  测试当连接被重置（RST）时，待处理的读写操作是否会被回调，以及回调的返回值。
* **NetLog 集成：** 验证 `QuicProxyClientSocket` 的操作是否会产生预期的 NetLog 事件，并且只产生相关的事件（避免 SpdySession 的事件）。
* **回调中删除 Socket 对象：** 测试在一个读操作的回调中删除了 `QuicProxyClientSocket` 对象后，正在等待的写操作的回调是否会被执行，以确保内存安全和避免 double free。

**与 JavaScript 功能的关系：**

`QuicProxyClientSocket` 本身是一个 C++ 的网络底层组件，直接与 JavaScript 功能没有直接的 API 交互。然而，它在浏览器网络栈中扮演着重要的角色，当 JavaScript 发起通过 HTTP 代理服务器的 HTTPS 请求时，并且底层使用了 QUIC 协议，那么 `QuicProxyClientSocket` 就会被使用。

**举例说明：**

假设一个网页中的 JavaScript 代码使用 `fetch()` API 发起一个通过代理服务器的 HTTPS 请求：

```javascript
fetch('https://example.com', {
  mode: 'cors',
  // ... 其他配置
}).then(response => {
  // 处理响应
}).catch(error => {
  // 处理错误
});
```

如果浏览器配置了使用 QUIC 协议的 HTTP 代理服务器，并且这个请求需要通过该代理，那么在网络栈的底层，就会涉及到 `QuicProxyClientSocket` 的使用。

* **连接建立阶段：** 当连接到代理服务器时，`QuicProxyClientSocket` 会处理与代理服务器的 QUIC 连接建立握手，包括发送 CONNECT 请求。这部分在第一部分测试文件中有所体现。
* **数据传输阶段：**  一旦连接建立，`QuicProxyClientSocket` 负责将 JavaScript 发送的请求数据（例如 HTTP Headers，Body）写入到 QUIC 流中，并将从代理服务器接收到的响应数据读取并传递给上层网络模块，最终传递给 JavaScript 的 `fetch()` API。 这就是这部分测试用例主要关注的场景。

**逻辑推理，假设输入与输出：**

**测试用例：`TEST_P(QuicProxyClientSocketTest, AsyncReadAroundWrite)`**

* **假设输入（`mock_quic_data_` 配置）：**
    1. 发送 SETTINGS 包。
    2. 发送 CONNECT 请求包。
    3. 异步接收服务器 CONNECT 响应包。
    4. 暂停读取。
    5. 异步接收服务器数据包 (kMsg1)。
    6. 发送 ACK 包确认收到 kMsg1。
    7. 同步发送数据包 (kMsg2)。
    8. 暂停读取。
    9. 异步接收服务器数据包 (kMsg3)。
    10. 永久暂停读取。
    11. 发送 ACK 和 RST 包。
* **预期输出：**
    1. 连接成功建立 (`AssertConnectSucceeds()`)。
    2. 第一次同步读取成功，读取到 `kMsg1` (`AssertSyncReadEquals(kMsg1, kLen1)`)。
    3. 开始异步读取 `kMsg3` (`AssertReadStarts(kMsg3, kLen3)`)。
    4. 同步写入 `kMsg2` 成功 (`AssertSyncWriteSucceeds(kMsg2, kLen2)`)。
    5. 在写入完成后，异步读取 `kMsg3` 返回 (`AssertReadReturns(kMsg3, kLen3)`)。

**用户或编程常见的使用错误举例：**

* **在连接未建立或已关闭的情况下尝试读写：** 程序员可能会忘记检查连接状态，直接调用 `Read()` 或 `Write()` 方法。测试用例 `ReadOnDisconnectSocketReturnsNotConnected` 和 `WriteOnClosedStream` 就模拟了这种情况，并验证了会返回 `ERR_SOCKET_NOT_CONNECTED` 或 `ERR_QUIC_PROTOCOL_ERROR`。
* **未处理异步操作完成的回调：**  在使用异步 `Read()` 或 `Write()` 时，必须正确处理完成回调。如果忘记处理或者处理逻辑有误，可能会导致数据丢失、程序挂起或者崩溃。测试用例 `PendingReadOnCloseReturnsZero` 和 `WritePendingOnClose` 验证了在连接关闭时，未完成的异步操作会被正确回调。
* **资源管理错误：** 例如，在回调函数中错误地释放了 `QuicProxyClientSocket` 对象，导致后续操作访问了无效内存。 `RstWithReadAndWritePendingDelete` 测试用例模拟了这种情况，确保即使在读回调中删除了 socket，写回调也不会被错误执行。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入一个 HTTPS 网址，该网站的服务器支持 QUIC 协议。**
2. **浏览器检查本地是否有可用的 QUIC 会话。** 如果没有，或者需要新的会话，浏览器会尝试与服务器建立 QUIC 连接。
3. **浏览器发现需要使用 HTTP 代理服务器来访问该网站（可能是在系统设置或浏览器设置中配置了代理）。**
4. **浏览器会尝试与代理服务器建立 QUIC 连接。**
5. **一旦与代理服务器的 QUIC 连接建立，浏览器会创建一个 `QuicProxyClientSocket` 实例。**
6. **`QuicProxyClientSocket` 会向代理服务器发送一个 CONNECT 请求，请求代理服务器转发到目标 HTTPS 网站的连接。** 这部分对应第一部分测试文件。
7. **一旦 CONNECT 请求成功，并且 `QuicProxyClientSocket` 接收到代理服务器的响应，用户开始与目标网站进行数据交互。**
8. **用户在网页上进行操作，例如点击链接、提交表单等，JavaScript 代码会发起新的网络请求。**
9. **这些请求的数据（例如 HTTP 请求头、请求体）会通过 `QuicProxyClientSocket` 的 `Write()` 方法发送给代理服务器。**
10. **代理服务器返回的响应数据会通过 `QuicProxyClientSocket` 的 `Read()` 方法接收。**
11. **如果代理服务器返回了认证请求或者错误响应，这部分的代码（例如 `ReadAuthResponseBody` 和 `ReadErrorResponseBody` 测试用例）会被执行。**
12. **如果在数据传输过程中连接出现问题（例如网络中断、服务器主动关闭连接），相关的关闭、断开或重置逻辑（对应的测试用例）会被触发。**

**调试线索：**

* **NetLog：** `NetLog` 测试用例表明可以通过查看浏览器的 `chrome://net-export/` 导出的网络日志，来跟踪 `QuicProxyClientSocket` 的生命周期和网络事件，例如连接建立、数据发送接收等。
* **Quic 数据包抓包：** 使用 Wireshark 等工具抓取 QUIC 数据包，可以分析实际的网络传输情况，验证测试用例中 `mock_quic_data_` 的配置是否与实际情况一致。
* **断点调试：**  在 Chromium 源码中设置断点，可以逐步跟踪 `QuicProxyClientSocket` 的执行流程，观察其内部状态和变量值，例如连接状态、读写缓冲区等。
* **单元测试代码：** 这些单元测试用例本身就是很好的调试参考。通过阅读测试代码，可以了解 `QuicProxyClientSocket` 的预期行为和各种边界情况的处理方式。

**总结第二部分的功能：**

总而言之，`net/quic/quic_proxy_client_socket_unittest.cc` 的第二部分主要关注 `QuicProxyClientSocket` 在成功建立与代理服务器的 QUIC 连接后，如何可靠地进行数据读写操作，以及在连接生命周期的不同阶段（例如关闭、断开、重置）如何正确处理读写请求和回调，并确保与 NetLog 的集成。它深入测试了异步操作、错误处理和资源管理等关键方面，保障了 `QuicProxyClientSocket` 作为 QUIC 代理客户端的健壮性和正确性。

### 提示词
```
这是目录为net/quic/quic_proxy_client_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
TEST_P(QuicProxyClientSocketTest, ReadAuthResponseBody) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC,
                          ConstructServerConnectAuthReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  std::string header2 = ConstructDataHeader(kLen2);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(3, header2 + std::string(kMsg2, kLen2)));
  mock_quic_data_.AddReadPauseForever();

  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 3, 3));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectFails(ERR_PROXY_AUTH_REQUESTED);

  // The next two reads are consumed and buffered.
  ResumeAndRun();

  AssertSyncReadEquals(kMsg1, kLen1);
  AssertSyncReadEquals(kMsg2, kLen2);
}

TEST_P(QuicProxyClientSocketTest, ReadErrorResponseBody) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC,
                          ConstructServerConnectErrorReplyPacket(1, !kFin));
  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      SYNCHRONOUS,
      ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  std::string header2 = ConstructDataHeader(kLen2);
  mock_quic_data_.AddRead(
      SYNCHRONOUS,
      ConstructServerDataPacket(3, header2 + std::string(kMsg2, kLen2)));
  mock_quic_data_.AddReadPauseForever();

  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 3, 3));
  InitializeSession();
  InitializeClientSocket();

  AssertConnectFails(ERR_TUNNEL_CONNECTION_FAILED);
}

// ----------- Reads and Writes

TEST_P(QuicProxyClientSocketTest, AsyncReadAroundWrite) {
  int write_packet_index = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(write_packet_index++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(write_packet_index++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(write_packet_index++, 2, 1));

  std::string header2 = ConstructDataHeader(kLen2);
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructDataPacket(write_packet_index++,
                                       {header2 + std::string(kMsg2, kLen2)}));

  mock_quic_data_.AddReadPause();

  std::string header3 = ConstructDataHeader(kLen3);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(3, header3 + std::string(kMsg3, kLen3)));
  mock_quic_data_.AddReadPauseForever();

  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(write_packet_index++,
                                            quic::QUIC_STREAM_CANCELLED, 3, 3));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  ResumeAndRun();

  AssertSyncReadEquals(kMsg1, kLen1);

  AssertReadStarts(kMsg3, kLen3);
  // Read should block until after the write succeeds.

  AssertSyncWriteSucceeds(kMsg2, kLen2);

  ASSERT_FALSE(read_callback_.have_result());
  ResumeAndRun();

  // Now the read will return.
  AssertReadReturns(kMsg3, kLen3);
}

TEST_P(QuicProxyClientSocketTest, AsyncWriteAroundReads) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  mock_quic_data_.AddReadPause();

  std::string header2 = ConstructDataHeader(kLen3);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(3, header2 + std::string(kMsg3, kLen3)));
  mock_quic_data_.AddReadPauseForever();

  mock_quic_data_.AddWritePause();

  std::string header3 = ConstructDataHeader(kLen2);
  mock_quic_data_.AddWrite(
      ASYNC, ConstructDataPacket(packet_number++,
                                 {header3 + std::string(kMsg2, kLen2)}));
  mock_quic_data_.AddWrite(
      ASYNC, ConstructAckAndDataPacket(packet_number++, 3, 3,
                                       header3 + std::string(kMsg2, kLen2)));

  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  ResumeAndRun();
  AssertSyncReadEquals(kMsg1, kLen1);

  // Write should block until the next read completes.
  // QuicChromiumClientStream::Handle::WriteStreamData() will only be
  // asynchronous starting with the second time it's called while the UDP socket
  // is write-blocked. Therefore, at least two writes need to be called on
  // |sock_| to get an asynchronous one.
  AssertWriteReturns(kMsg2, kLen2, kLen2);
  AssertWriteReturns(kMsg2, kLen2, ERR_IO_PENDING);

  AssertAsyncReadEquals(kMsg3, kLen3);

  ASSERT_FALSE(write_callback_.have_result());

  // Now the write will complete
  ResumeAndRun();
  EXPECT_EQ(kLen2, write_callback_.WaitForResult());
}

// ----------- Reading/Writing on Closed socket

// Reading from an already closed socket should return 0
TEST_P(QuicProxyClientSocketTest, ReadOnClosedSocketReturnsZero) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();
  mock_quic_data_.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  ResumeAndRun();

  ASSERT_FALSE(sock_->IsConnected());
  ASSERT_EQ(0, sock_->Read(nullptr, 1, CompletionOnceCallback()));
  ASSERT_EQ(0, sock_->Read(nullptr, 1, CompletionOnceCallback()));
  ASSERT_EQ(0, sock_->Read(nullptr, 1, CompletionOnceCallback()));
  ASSERT_FALSE(sock_->IsConnectedAndIdle());
}

// Read pending when socket is closed should return 0
TEST_P(QuicProxyClientSocketTest, PendingReadOnCloseReturnsZero) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();
  mock_quic_data_.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  AssertReadStarts(kMsg1, kLen1);

  ResumeAndRun();

  ASSERT_EQ(0, read_callback_.WaitForResult());
}

// Reading from a disconnected socket is an error
TEST_P(QuicProxyClientSocketTest, ReadOnDisconnectSocketReturnsNotConnected) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 1));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  sock_->Disconnect();

  ASSERT_EQ(ERR_SOCKET_NOT_CONNECTED,
            sock_->Read(nullptr, 1, CompletionOnceCallback()));
}

// Reading data after receiving FIN should return buffered data received before
// FIN, then 0.
TEST_P(QuicProxyClientSocketTest, ReadAfterFinReceivedReturnsBufferedData) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(ASYNC, ConstructServerDataFinPacket(
                                     2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  ResumeAndRun();

  AssertSyncReadEquals(kMsg1, kLen1);
  ASSERT_EQ(0, sock_->Read(nullptr, 1, CompletionOnceCallback()));
  ASSERT_EQ(0, sock_->Read(nullptr, 1, CompletionOnceCallback()));

  sock_->Disconnect();
  ASSERT_EQ(ERR_SOCKET_NOT_CONNECTED,
            sock_->Read(nullptr, 1, CompletionOnceCallback()));
}

// Calling Write() on a closed socket is an error.
TEST_P(QuicProxyClientSocketTest, WriteOnClosedStream) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();
  mock_quic_data_.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  ResumeAndRun();

  AssertWriteReturns(kMsg1, kLen1, ERR_QUIC_PROTOCOL_ERROR);
}

// Calling Write() on a disconnected socket is an error.
TEST_P(QuicProxyClientSocketTest, WriteOnDisconnectedSocket) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 1));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  sock_->Disconnect();

  AssertWriteReturns(kMsg1, kLen1, ERR_SOCKET_NOT_CONNECTED);
}

// If the socket is closed with a pending Write(), the callback should be called
// with the same error the session was closed with.
TEST_P(QuicProxyClientSocketTest, WritePendingOnClose) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(SYNCHRONOUS, ERR_IO_PENDING);

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  // QuicChromiumClientStream::Handle::WriteStreamData() will only be
  // asynchronous starting with the second time it's called while the UDP socket
  // is write-blocked. Therefore, at least two writes need to be called on
  // |sock_| to get an asynchronous one.
  AssertWriteReturns(kMsg1, kLen1, kLen1);

  // This second write will be async. This is the pending write that's being
  // tested.
  AssertWriteReturns(kMsg1, kLen1, ERR_IO_PENDING);

  // Make sure the write actually starts.
  base::RunLoop().RunUntilIdle();

  session_->CloseSessionOnError(ERR_CONNECTION_CLOSED,
                                quic::QUIC_INTERNAL_ERROR,
                                quic::ConnectionCloseBehavior::SILENT_CLOSE);

  EXPECT_THAT(write_callback_.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

TEST_P(QuicProxyClientSocketTest, DisconnectWithWritePending) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(SYNCHRONOUS, ERR_IO_PENDING);

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  // QuicChromiumClientStream::Handle::WriteStreamData() will only be
  // asynchronous starting with the second time it's called while the UDP socket
  // is write-blocked. Therefore, at least two writes need to be called on
  // |sock_| to get an asynchronous one.
  AssertWriteReturns(kMsg1, kLen1, kLen1);

  // This second write will be async. This is the pending write that's being
  // tested.
  AssertWriteReturns(kMsg1, kLen1, ERR_IO_PENDING);

  // Make sure the write actually starts.
  base::RunLoop().RunUntilIdle();

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(sock_->IsConnected());
  EXPECT_FALSE(write_callback_.have_result());
}

// If the socket is Disconnected with a pending Read(), the callback
// should not be called.
TEST_P(QuicProxyClientSocketTest, DisconnectWithReadPending) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 1));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  EXPECT_TRUE(sock_->IsConnected());

  AssertReadStarts(kMsg1, kLen1);

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(sock_->IsConnected());
  EXPECT_FALSE(read_callback_.have_result());
}

// If the socket is Reset when both a read and write are pending,
// both should be called back.
TEST_P(QuicProxyClientSocketTest, RstWithReadAndWritePending) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  mock_quic_data_.AddRead(
      ASYNC, ConstructServerRstPacket(2, quic::QUIC_STREAM_CANCELLED));
  mock_quic_data_.AddReadPauseForever();
  std::string header = ConstructDataHeader(kLen2);
  mock_quic_data_.AddWrite(
      ASYNC, ConstructAckAndDataPacket(packet_number++, 1, 1,
                                       {header + std::string(kMsg2, kLen2)}));
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstOnlyPacket(
                       packet_number++, quic::QUIC_STREAM_CANCELLED, 2, 2));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  EXPECT_TRUE(sock_->IsConnected());

  AssertReadStarts(kMsg1, kLen1);

  // Write should block until the next read completes.
  // QuicChromiumClientStream::Handle::WriteStreamData() will only be
  // asynchronous starting with the second time it's called while the UDP socket
  // is write-blocked. Therefore, at least two writes need to be called on
  // |sock_| to get an asynchronous one.
  AssertWriteReturns(kMsg2, kLen2, kLen2);

  AssertWriteReturns(kMsg2, kLen2, ERR_IO_PENDING);

  ResumeAndRun();

  EXPECT_TRUE(read_callback_.have_result());
  EXPECT_TRUE(write_callback_.have_result());
}

// Makes sure the proxy client socket's source gets the expected NetLog events
// and only the expected NetLog events (No SpdySession events).
TEST_P(QuicProxyClientSocketTest, NetLog) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  ResumeAndRun();
  AssertSyncReadEquals(kMsg1, kLen1);

  NetLogSource sock_source = sock_->NetLog().source();
  sock_.reset();

  auto entry_list = net_log_observer_.GetEntriesForSource(sock_source);

  ASSERT_EQ(entry_list.size(), 10u);
  EXPECT_TRUE(
      LogContainsBeginEvent(entry_list, 0, NetLogEventType::SOCKET_ALIVE));
  EXPECT_TRUE(LogContainsEvent(entry_list, 1,
                               NetLogEventType::HTTP2_PROXY_CLIENT_SESSION,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsBeginEvent(
      entry_list, 2, NetLogEventType::HTTP_TRANSACTION_TUNNEL_SEND_REQUEST));
  EXPECT_TRUE(LogContainsEvent(
      entry_list, 3, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEndEvent(
      entry_list, 4, NetLogEventType::HTTP_TRANSACTION_TUNNEL_SEND_REQUEST));
  EXPECT_TRUE(LogContainsBeginEvent(
      entry_list, 5, NetLogEventType::HTTP_TRANSACTION_TUNNEL_READ_HEADERS));
  EXPECT_TRUE(LogContainsEvent(
      entry_list, 6,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEndEvent(
      entry_list, 7, NetLogEventType::HTTP_TRANSACTION_TUNNEL_READ_HEADERS));
  EXPECT_TRUE(LogContainsEvent(entry_list, 8,
                               NetLogEventType::SOCKET_BYTES_RECEIVED,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(
      LogContainsEndEvent(entry_list, 9, NetLogEventType::SOCKET_ALIVE));
}

// A helper class that will delete |sock| when the callback is invoked.
class DeleteSockCallback : public TestCompletionCallbackBase {
 public:
  explicit DeleteSockCallback(std::unique_ptr<QuicProxyClientSocket>* sock)
      : sock_(sock) {}

  DeleteSockCallback(const DeleteSockCallback&) = delete;
  DeleteSockCallback& operator=(const DeleteSockCallback&) = delete;

  ~DeleteSockCallback() override = default;

  CompletionOnceCallback callback() {
    return base::BindOnce(&DeleteSockCallback::OnComplete,
                          base::Unretained(this));
  }

 private:
  void OnComplete(int result) {
    sock_->reset(nullptr);
    SetResult(result);
  }

  raw_ptr<std::unique_ptr<QuicProxyClientSocket>> sock_;
};

// If the socket is reset when both a read and write are pending, and the
// read callback causes the socket to be deleted, the write callback should
// not be called.
TEST_P(QuicProxyClientSocketTest, RstWithReadAndWritePendingDelete) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  mock_quic_data_.AddRead(
      ASYNC, ConstructServerRstPacket(2, quic::QUIC_STREAM_CANCELLED));
  mock_quic_data_.AddReadPauseForever();
  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddWrite(
      ASYNC, ConstructAckAndDataPacket(packet_number++, 1, 1,
                                       {header + std::string(kMsg1, kLen1)}));
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstOnlyPacket(
                       packet_number++, quic::QUIC_STREAM_CANCELLED, 2, 2));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  EXPECT_TRUE(sock_->IsConnected());

  DeleteSockCallback read_callback(&sock_);
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kLen1);
  ASSERT_EQ(ERR_IO_PENDING,
            sock_->Read(read_buf.get(), kLen1, read_callback.callback()));

  // QuicChromiumClientStream::Handle::WriteStreamData() will only be
  // asynchronous starting with the second time it's called while the UDP socket
  // is write-blocked. Therefore, at least two writes need to be called on
  // |sock_| to get an asynchronous one.
  AssertWriteReturns(kMsg1, kLen1, kLen1);

  AssertWriteReturns(kMsg1, kLen1, ERR_IO_PENDING);

  ResumeAndRun();

  EXPECT_FALSE(sock_.get());

  EXPECT_EQ(0, read_callback.WaitForResult());
  EXPECT_FALSE(write_callback_.have_result());
}

INSTANTIATE_TEST_SUITE_P(VersionIncludeStreamDependencySequence,
                         QuicProxyClientSocketTest,
                         ::testing::ValuesIn(AllSupportedQuicVersions()),
                         ::testing::PrintToStringParamName());

}  // namespace net::test
```