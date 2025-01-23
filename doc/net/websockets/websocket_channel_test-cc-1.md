Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a four-part file. The file `net/websockets/websocket_channel_test.cc` is part of the Chromium network stack and contains unit tests for the `WebSocketChannel` class.

Here's a breakdown of the code's key features:

1. **Test Fixtures:**  The code defines various test fixtures (`WebSocketChannelTest`, `WebSocketChannelEventInterfaceTest`, `WebSocketChannelStreamTest`, `WebSocketChannelSendUtf8Test`, `WebSocketChannelReceiveUtf8Test`). These fixtures set up common test environments and helper functions.

2. **Mocking and Faking:** The code utilizes mock objects (`MockWebSocketEventInterface`, `MockWebSocketStream`) and fake implementations (`FakeWebSocketEventInterface`, `FakeWebSocketStream`, `ReadableFakeWebSocketStream`, `WriteableFakeWebSocketStream`, `UnWriteableFakeWebSocketStream`, `EchoeyFakeWebSocketStream`, `ResetOnWriteFakeWebSocketStream`) to simulate different WebSocket scenarios and isolate the `WebSocketChannel`'s behavior.

3. **Testing Event Interface Interactions:** Many tests focus on verifying that the `WebSocketChannel` correctly interacts with its `WebSocketEventInterface`. This includes testing:
    *   Successful and failed connection attempts.
    *   Passing of subprotocols and extensions.
    *   Handling of data frames received after the handshake.
    *   Proper handling of close frames.
    *   Reporting of errors (like masked frames, unknown opcodes, protocol errors).
    *   Callbacks for opening handshake start and finish.

4. **Testing Stream Interactions:** Some tests verify the interactions between `WebSocketChannel` and the `WebSocketStream`, particularly using mock streams to control the stream's behavior.

5. **Testing UTF-8 Handling:**  Specific fixtures are designed to test the `WebSocketChannel`'s handling of UTF-8 encoded text frames during sending and receiving.

6. **Testing Closing Handshake:** Several tests cover scenarios involving the WebSocket closing handshake, initiated both by the client and the server.

7. **Testing Error Conditions:** A significant portion of the tests focus on verifying how `WebSocketChannel` handles various error conditions, including connection failures, protocol errors, invalid frames, and connection resets.

8. **Asynchronous Operations:** The tests cover asynchronous read and write operations and how `WebSocketChannel` manages them.

**Relationship to JavaScript:**

The `WebSocketChannel` in C++ is the underlying implementation that enables JavaScript's `WebSocket` API in web browsers. JavaScript code uses the `WebSocket` API to establish and manage WebSocket connections. The C++ code being tested here is what handles the low-level details of the WebSocket protocol.

**Examples of Interaction with JavaScript:**

*   **Establishing a connection:** When a JavaScript calls `new WebSocket('ws://example.com')`, the browser's underlying implementation (which involves this C++ code) will initiate the connection. The tests here simulate the various outcomes of that connection attempt (success, failure, different server responses).
*   **Sending data:** When JavaScript calls `websocket.send('Hello')`, the browser's implementation uses the `WebSocketChannel` to send a WebSocket frame containing the data "Hello". The tests here verify how `WebSocketChannel` handles sending frames, including UTF-8 encoding.
*   **Receiving data:** When the server sends data, the `WebSocketChannel` in C++ receives and processes the frames. It then notifies the JavaScript via the `WebSocket` API's `onmessage` event. The tests here simulate receiving different types of frames (text, binary, control frames) and check how `WebSocketChannel` parses and delivers them.
*   **Closing the connection:** When JavaScript calls `websocket.close()`, the browser's implementation uses `WebSocketChannel` to initiate the closing handshake. The tests here verify the correct sequence of events during the closing handshake.
*   **Handling errors:** If the WebSocket connection encounters an error (e.g., connection refused, protocol error), the `WebSocketChannel` in C++ detects this and notifies the JavaScript via the `WebSocket` API's `onerror` event or triggers the `onclose` event with an error code. The tests here simulate these error scenarios.

**Hypothetical Input and Output (Illustrative):**

*   **Input (Test Case: `ConnectSuccessReported`):** A successful connection attempt is simulated in the test.
*   **Output:** The test verifies that the `OnAddChannelResponse` method of the mock `WebSocketEventInterface` is called with an indication of success.

*   **Input (Test Case: `MaskedFramesAreRejected`):** A WebSocket frame with the masked bit set (which is invalid for server-sent frames) is simulated.
*   **Output:** The test verifies that the `OnFailChannel` method of the mock `WebSocketEventInterface` is called with an appropriate error message.

**Common User/Programming Errors:**

*   **Trying to send data on a closed connection:**  JavaScript developers might try to call `websocket.send()` after the connection has been closed. The underlying C++ code would reject this operation.
*   **Incorrect WebSocket URL:** Providing an invalid or non-WebSocket URL (e.g., starting with `http://` instead of `ws://` or `wss://`) in the JavaScript `WebSocket` constructor will be caught by the browser's implementation, possibly leading to an error reported by the C++ code.
*   **Server sending masked frames:** According to the WebSocket protocol, servers should not mask frames sent to clients. If a server mistakenly sends masked frames, the C++ code will detect this and close the connection (as demonstrated in the `MaskedFramesAreRejected` test).
*   **Receiving invalid UTF-8:** If a WebSocket server sends a text frame that is not valid UTF-8, the C++ code needs to handle this appropriately. While not explicitly shown in *this* snippet, other parts of the code or related tests likely cover this.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User opens a web page in a Chromium-based browser.**
2. **The web page's JavaScript code attempts to establish a WebSocket connection using `new WebSocket('ws://example.com')`.**
3. **The browser's network stack takes over the connection establishment process.**
4. **The `WebSocketChannel` class (and the code being tested here) is involved in managing the WebSocket connection.**
5. **If a bug or unexpected behavior occurs during the WebSocket communication (e.g., the server sends an invalid frame), developers might need to debug the network stack.**
6. **To debug, developers might set breakpoints in `net/websockets/websocket_channel.cc` (where `WebSocketChannel` is implemented) and `net/websockets/websocket_channel_test.cc` (to understand the expected behavior and how the tests exercise different scenarios).**
7. **Examining the logs or network inspector can also provide clues about what's happening at the WebSocket level.**

**Summary of Functionality (Part 2):**

This part of the `websocket_channel_test.cc` file primarily defines **test fixtures and numerous unit tests** that focus on verifying the correct behavior of the `WebSocketChannel` class, particularly its interaction with the `WebSocketEventInterface` and how it handles various events and error conditions during the WebSocket handshake and subsequent data transfer. The tests cover successful and failed connections, handling of different frame types (data, control, close), and responses to various server behaviors and protocol violations. These tests ensure the robustness and correctness of the underlying WebSocket implementation in Chromium.

这是 `net/websockets/websocket_channel_test.cc` 文件的第二部分，主要延续了第一部分的内容，继续定义和实现用于测试 `WebSocketChannel` 类的单元测试。 这部分主要关注 `WebSocketChannel` 与 `WebSocketEventInterface` 之间的交互，以及在各种场景下（包括成功连接、连接失败、接收数据、发送数据、关闭连接以及各种错误情况） `WebSocketChannel` 的行为。

**功能归纳:**

1. **测试连接的成功与失败:**  测试了 `WebSocketChannel` 在成功建立连接和连接失败时如何通知 `WebSocketEventInterface`。
2. **测试握手过程中的数据处理:** 验证了在 WebSocket 握手完成后，服务端发送的数据如何被 `WebSocketChannel` 处理并通过 `WebSocketEventInterface` 传递。
3. **测试连接关闭流程:** 涵盖了服务端主动关闭连接、客户端主动关闭连接以及在握手完成前后关闭连接的不同情况，并验证 `WebSocketChannel` 如何通知 `WebSocketEventInterface`。
4. **测试异步数据读取:**  验证了 `WebSocketChannel` 如何处理服务端异步发送的数据帧，以及在读取过程中可能出现的同步读取情况。
5. **测试消息分片与重组:**  测试了当一个 WebSocket 消息被分成多个帧发送时，`WebSocketChannel` 如何将其重组并传递给 `WebSocketEventInterface`。
6. **测试错误处理:**  涵盖了多种 WebSocket 协议错误，例如接收到被掩码的帧、未知操作码、无效的帧头等，并验证 `WebSocketChannel` 如何检测并处理这些错误，并通过 `WebSocketEventInterface` 通知。
7. **测试控制帧的处理:**  验证了 `WebSocketChannel` 如何处理控制帧（如 Ping、Pong）以及控制帧在数据消息中出现的情况。
8. **测试发送数据失败的情况:** 验证了当发送数据帧失败时，`WebSocketChannel` 如何处理并通知 `WebSocketEventInterface`。
9. **测试关闭握手的触发:** 验证了调用 `StartClosingHandshake` 方法后，`WebSocketChannel` 如何启动关闭握手流程并通知 `WebSocketEventInterface`。
10. **测试在连接建立过程中关闭连接:**  验证了在连接尚未完全建立时调用 `StartClosingHandshake` 的行为。
11. **测试服务端发送关闭帧:**  涵盖了服务端发送不同类型的关闭帧（包含状态码和原因、不包含状态码和原因）时，`WebSocketChannel` 如何解析并通知 `WebSocketEventInterface`。
12. **测试协议错误导致的连接失败:** 验证了当底层网络流返回协议错误时，`WebSocketChannel` 如何处理并通知 `WebSocketEventInterface`。
13. **测试握手请求事件:**  验证了 `WebSocketChannel` 何时以及如何通知 `WebSocketEventInterface` 握手请求已经开始。
14. **测试握手完成后立即失败的情况:** 验证了在握手成功后，如果连接立即失败，`WebSocketChannel` 的处理方式。
15. **测试连接关闭后接收到数据帧的情况:** 验证了在 WebSocket 连接关闭后，如果仍然收到数据帧，`WebSocketChannel` 如何处理并标记为错误。
16. **测试无效的关闭帧负载:**  测试了接收到负载长度不正确的关闭帧时，`WebSocketChannel` 如何处理。

**与 JavaScript 功能的关系举例:**

*   **`TEST_F(WebSocketChannelEventInterfaceTest, ConnectSuccessReported)`:**  模拟了 JavaScript 中 `new WebSocket('ws://...')` 成功建立连接的情况。当 JavaScript 代码成功创建 WebSocket 对象后，底层的 C++ `WebSocketChannel` 会通知其 `WebSocketEventInterface`，表明连接已建立。
*   **`TEST_F(WebSocketChannelEventInterfaceTest, DataLeftFromHandshake)`:**  模拟了服务端在 WebSocket 握手响应中携带数据的情况。这对应于 JavaScript 中 `websocket.onmessage` 事件在连接建立后立即被触发，接收到服务端在握手阶段发送的数据。
*   **`TEST_F(WebSocketChannelEventInterfaceTest, AsyncAbnormalClosure)`:**  模拟了服务端意外断开连接，没有发送关闭帧的情况。这对应于 JavaScript 中 `websocket.onerror` 事件被触发，或者 `websocket.onclose` 事件被触发，`wasClean` 属性为 `false`。
*   **`TEST_F(WebSocketChannelEventInterfaceTest, MaskedFramesAreRejected)`:**  模拟了服务端错误地发送了被掩码的数据帧。这在 JavaScript 中通常不会直接暴露出来，因为这是协议层面的错误，会被底层的 C++ 代码处理并关闭连接。开发者可能会在 `websocket.onerror` 或 `websocket.onclose` 事件中观察到连接异常。
*   **`TEST_F(WebSocketChannelEventInterfaceTest, SendCloseDropsChannel)`:**  模拟了 JavaScript 中调用 `websocket.close()` 方法。底层的 C++ `WebSocketChannel` 会启动关闭握手流程，并最终触发 `WebSocketEventInterface` 的 `OnDropChannel` 方法。这对应于 JavaScript 中 `websocket.onclose` 事件被触发。

**逻辑推理的假设输入与输出:**

*   **假设输入 ( `TEST_F(WebSocketChannelEventInterfaceTest, FragmentedMessage)` ):**
    *   服务端分三批发送一个文本消息 "THREE SMALL FRAMES"，每批包含多个数据帧。
    *   第一批包含 "THREE" 和 " " 两个非最终帧。
    *   第二批包含 "SMALL" 一个非最终帧。
    *   第三批包含 " " 和 "FRAMES" 两个帧，其中最后一个是最终帧。
*   **输出:**  `WebSocketEventInterface` 的 `OnDataFrameVector` 方法会被多次调用，每次调用对应接收到的一个数据帧片段。最终，`WebSocketEventInterface` 会接收到一个完整的消息，即 "THREE SMALL FRAMES"。

*   **假设输入 ( `TEST_F(WebSocketChannelEventInterfaceTest, MaskedFramesAreRejected)` ):**
    *   服务端发送一个文本帧，但该帧的掩码位被设置为 1（表示被掩码）。
*   **输出:** `WebSocketEventInterface` 的 `OnFailChannel` 方法会被调用，并带有指示服务端不应发送被掩码帧的错误消息。

**涉及用户或编程常见的使用错误举例:**

*   **错误地认为服务端会掩码发送的帧:** 开发者如果错误地认为服务端发送的帧会被掩码，可能会在客户端尝试解掩码，但这实际上是不必要的，因为 WebSocket 协议规定服务端不应掩码发送给客户端的帧。这个错误会被 `TEST_F(WebSocketChannelEventInterfaceTest, MaskedFramesAreRejected)` 这类测试覆盖。
*   **在连接关闭后尝试发送数据:**  用户操作在 WebSocket 连接已经关闭后（例如用户点击了断开连接按钮），JavaScript 代码可能仍然尝试调用 `websocket.send()` 发送数据。虽然这个测试文件侧重于底层实现，但底层的 `WebSocketChannel` 会拒绝发送并在内部处理这种情况，最终会影响到 JavaScript 的 `onerror` 或 `onclose` 事件。
*   **服务端实现错误导致发送无效帧:**  服务端开发者如果对 WebSocket 协议理解不透彻，可能会实现出发送被掩码帧、使用未知操作码的帧等错误行为。这些错误会被此测试文件中的相应测试用例捕获，帮助 Chromium 开发者确保浏览器能够正确处理这些不合规的服务器行为。

**用户操作如何一步步的到达这里作为调试线索:**

1. **用户在浏览器中访问了一个网页。**
2. **该网页的 JavaScript 代码尝试创建一个 WebSocket 连接到某个服务端 (例如 `new WebSocket('ws://example.com')`)。**
3. **Chromium 浏览器的网络栈开始处理这个连接请求。**
4. **`WebSocketChannel` 类被创建，负责管理这个 WebSocket 连接的生命周期和数据传输。**
5. **在连接建立或数据传输过程中，如果服务端发送了不符合 WebSocket 协议的帧（例如被掩码的帧），或者连接过程中发生了错误（例如连接被拒绝），`WebSocketChannel` 会检测到这些异常。**
6. **为了调试这种问题，Chromium 的开发者可能会运行 `net/websockets/websocket_channel_test.cc` 中的相关测试用例，例如 `MaskedFramesAreRejected` 或 `UnknownOpCodeIsRejected`，来验证 `WebSocketChannel` 是否按照预期处理了这些错误情况。**
7. **开发者可能会在 `WebSocketChannel` 的实现代码中设置断点，并结合测试用例的执行流程，来跟踪问题发生的具体位置和原因。**  例如，当调试服务端发送掩码帧的问题时，开发者可能会在 `WebSocketChannel` 接收数据帧的代码中设置断点，查看掩码位的状态以及触发的错误处理逻辑。

总而言之，这部分测试代码是 Chromium 网络栈中 `WebSocketChannel` 功能的基石，它通过模拟各种正常的和异常的 WebSocket 通信场景，来确保 `WebSocketChannel` 能够可靠、正确地处理 WebSocket 连接，并为上层的 JavaScript `WebSocket` API 提供稳定的支持。

### 提示词
```
这是目录为net/websockets/websocket_channel_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
() {
    return std::make_unique<FakeWebSocketEventInterface>();
  }

  // This method serves no other purpose than to provide a nice syntax for
  // assigning to stream_. class T must be a subclass of WebSocketStream or you
  // will have unpleasant compile errors.
  template <class T>
  void set_stream(std::unique_ptr<T> stream) {
    stream_ = std::move(stream);
  }

  // A struct containing the data that will be used to connect the channel.
  // Grouped for readability.
  struct ConnectData {
    ConnectData()
        : url_request_context(CreateTestURLRequestContextBuilder()->Build()),
          socket_url("ws://ws/"),
          origin(url::Origin::Create(GURL("http://ws"))),
          site_for_cookies(SiteForCookies::FromUrl(GURL("http://ws/"))) {
      this->isolation_info =
          IsolationInfo::Create(IsolationInfo::RequestType::kOther, origin,
                                origin, SiteForCookies::FromOrigin(origin));
    }

    // URLRequestContext object.
    std::unique_ptr<URLRequestContext> url_request_context;

    // URL to (pretend to) connect to.
    GURL socket_url;
    // Requested protocols for the request.
    std::vector<std::string> requested_subprotocols;
    // Origin of the request
    url::Origin origin;
    // First party for cookies for the request.
    net::SiteForCookies site_for_cookies;
    // Whether the calling context has opted into the Storage Access API.
    StorageAccessApiStatus storage_access_api_status =
        StorageAccessApiStatus::kNone;
    // IsolationInfo created from the origin.
    net::IsolationInfo isolation_info;

    WebSocketStreamCreationCallbackArgumentSaver argument_saver;
  };
  ConnectData connect_data_;

  // The channel we are testing. Not initialised until SetChannel() is called.
  std::unique_ptr<WebSocketChannel> channel_;

  // A mock or fake stream for tests that need one.
  std::unique_ptr<WebSocketStream> stream_;

  std::vector<scoped_refptr<IOBuffer>> result_frame_data_;
};

// enum of WebSocketEventInterface calls. These are intended to be or'd together
// in order to instruct WebSocketChannelDeletingTest when it should fail.
enum EventInterfaceCall {
  EVENT_ON_ADD_CHANNEL_RESPONSE = 0x1,
  EVENT_ON_DATA_FRAME = 0x2,
  EVENT_ON_FLOW_CONTROL = 0x4,
  EVENT_ON_CLOSING_HANDSHAKE = 0x8,
  EVENT_ON_FAIL_CHANNEL = 0x10,
  EVENT_ON_DROP_CHANNEL = 0x20,
  EVENT_ON_START_OPENING_HANDSHAKE = 0x40,
  EVENT_ON_FINISH_OPENING_HANDSHAKE = 0x80,
  EVENT_ON_SSL_CERTIFICATE_ERROR = 0x100,
};

// Base class for tests which verify that EventInterface methods are called
// appropriately.
class WebSocketChannelEventInterfaceTest : public WebSocketChannelTest {
 public:
  void SetUp() override {
    EXPECT_CALL(*event_interface_, HasPendingDataFrames()).Times(AnyNumber());
  }

 protected:
  WebSocketChannelEventInterfaceTest()
      : event_interface_(
            std::make_unique<StrictMock<MockWebSocketEventInterface>>()) {
  }

  ~WebSocketChannelEventInterfaceTest() override = default;

  // Tests using this fixture must set expectations on the event_interface_ mock
  // object before calling CreateChannelAndConnect() or
  // CreateChannelAndConnectSuccessfully(). This will only work once per test
  // case, but once should be enough.
  std::unique_ptr<WebSocketEventInterface> CreateEventInterface() override {
    return std::move(event_interface_);
  }

  std::unique_ptr<MockWebSocketEventInterface> event_interface_;
};

// Base class for tests which verify that WebSocketStream methods are called
// appropriately by using a MockWebSocketStream.
class WebSocketChannelStreamTest : public WebSocketChannelEventInterfaceTest {
 public:
  void SetUp() override {
    WebSocketChannelEventInterfaceTest::SetUp();
    // For the purpose of the tests using this fixture, it doesn't matter
    // whether these methods are called or not.
    EXPECT_CALL(*mock_stream_, GetSubProtocol()).Times(AnyNumber());
    EXPECT_CALL(*mock_stream_, GetExtensions()).Times(AnyNumber());
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _))
        .Times(AnyNumber());
    EXPECT_CALL(*event_interface_, OnDataFrameVector(_, _, _))
        .Times(AnyNumber());
    EXPECT_CALL(*event_interface_, OnClosingHandshake()).Times(AnyNumber());
    EXPECT_CALL(*event_interface_, OnSendDataFrameDone()).Times(AnyNumber());
    EXPECT_CALL(*event_interface_, OnFailChannel(_, _, _)).Times(AnyNumber());
    EXPECT_CALL(*event_interface_, OnDropChannel(_, _, _)).Times(AnyNumber());
  }

 protected:
  WebSocketChannelStreamTest()
      : mock_stream_(std::make_unique<StrictMock<MockWebSocketStream>>()) {}

  void CreateChannelAndConnectSuccessfully() override {
    set_stream(std::move(mock_stream_));
    WebSocketChannelTest::CreateChannelAndConnectSuccessfully();
  }

  std::unique_ptr<MockWebSocketStream> mock_stream_;
};

// Fixture for tests which test UTF-8 validation of sent Text frames via the
// EventInterface.
class WebSocketChannelSendUtf8Test
    : public WebSocketChannelEventInterfaceTest {
 public:
  void SetUp() override {
    WebSocketChannelEventInterfaceTest::SetUp();
    set_stream(std::make_unique<WriteableFakeWebSocketStream>());
    // For the purpose of the tests using this fixture, it doesn't matter
    // whether these methods are called or not.
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _))
        .Times(AnyNumber());
    EXPECT_CALL(*event_interface_, OnSendDataFrameDone()).Times(AnyNumber());
  }
};

// Fixture for tests which test UTF-8 validation of received Text frames using a
// mock WebSocketStream.
class WebSocketChannelReceiveUtf8Test : public WebSocketChannelStreamTest {
 public:
  void SetUp() override {
    WebSocketChannelStreamTest::SetUp();
    // For the purpose of the tests using this fixture, it doesn't matter
    // whether these methods are called or not.
  }
};

// Simple test that everything that should be passed to the stream creation
// callback is passed to the argument saver.
TEST_F(WebSocketChannelTest, EverythingIsPassedToTheCreatorFunction) {
  connect_data_.socket_url = GURL("ws://example.com/test");
  connect_data_.origin = url::Origin::Create(GURL("http://example.com"));
  connect_data_.site_for_cookies =
      SiteForCookies::FromUrl(GURL("http://example.com/"));
  connect_data_.isolation_info = net::IsolationInfo::Create(
      IsolationInfo::RequestType::kOther, connect_data_.origin,
      connect_data_.origin, SiteForCookies::FromOrigin(connect_data_.origin));
  connect_data_.requested_subprotocols.push_back("Sinbad");

  CreateChannelAndConnect();

  const WebSocketStreamCreationCallbackArgumentSaver& actual =
      connect_data_.argument_saver;

  EXPECT_EQ(connect_data_.url_request_context.get(),
            actual.url_request_context);

  EXPECT_EQ(connect_data_.socket_url, actual.socket_url);
  EXPECT_EQ(connect_data_.origin.Serialize(), actual.origin.Serialize());
  EXPECT_TRUE(
      connect_data_.site_for_cookies.IsEquivalent(actual.site_for_cookies));
  EXPECT_EQ(connect_data_.storage_access_api_status,
            actual.storage_access_api_status);
  EXPECT_TRUE(
      connect_data_.isolation_info.IsEqualForTesting(actual.isolation_info));
}

TEST_F(WebSocketChannelEventInterfaceTest, ConnectSuccessReported) {
  // false means success.
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, "", ""));

  CreateChannelAndConnect();

  connect_data_.argument_saver.connect_delegate->OnSuccess(
      std::move(stream_), std::make_unique<WebSocketHandshakeResponseInfo>(
                              GURL(), nullptr, IPEndPoint(), base::Time()));
  std::ignore = channel_->ReadFrames();
}

TEST_F(WebSocketChannelEventInterfaceTest, ConnectFailureReported) {
  EXPECT_CALL(*event_interface_, OnFailChannel("hello", ERR_FAILED, _));

  CreateChannelAndConnect();

  connect_data_.argument_saver.connect_delegate->OnFailure("hello", ERR_FAILED,
                                                           std::nullopt);
}

TEST_F(WebSocketChannelEventInterfaceTest, NonWebSocketSchemeRejected) {
  EXPECT_CALL(*event_interface_, OnFailChannel("Invalid scheme", _, _));
  connect_data_.socket_url = GURL("http://www.google.com/");
  CreateChannelAndConnect();
}

TEST_F(WebSocketChannelEventInterfaceTest, ProtocolPassed) {
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, "Bob", ""));

  CreateChannelAndConnect();

  connect_data_.argument_saver.connect_delegate->OnSuccess(
      std::make_unique<FakeWebSocketStream>("Bob", ""),
      std::make_unique<WebSocketHandshakeResponseInfo>(
          GURL(), nullptr, IPEndPoint(), base::Time()));
  std::ignore = channel_->ReadFrames();
}

TEST_F(WebSocketChannelEventInterfaceTest, ExtensionsPassed) {
  EXPECT_CALL(*event_interface_,
              OnAddChannelResponse(_, "", "extension1, extension2"));

  CreateChannelAndConnect();

  connect_data_.argument_saver.connect_delegate->OnSuccess(
      std::make_unique<FakeWebSocketStream>("", "extension1, extension2"),
      std::make_unique<WebSocketHandshakeResponseInfo>(
          GURL(), nullptr, IPEndPoint(), base::Time()));
  std::ignore = channel_->ReadFrames();
}

// The first frames from the server can arrive together with the handshake, in
// which case they will be available as soon as ReadFrames() is called the first
// time.
TEST_F(WebSocketChannelEventInterfaceTest, DataLeftFromHandshake) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "HELLO"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_,
                OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeText,
                                  AsVector("HELLO")));
  }

  CreateChannelAndConnectSuccessfully();
}

// A remote server could accept the handshake, but then immediately send a
// Close frame.
TEST_F(WebSocketChannelEventInterfaceTest, CloseAfterHandshake) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED,  CLOSE_DATA(SERVER_ERROR, "Internal Server Error")}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  stream->PrepareReadFramesError(ReadableFakeWebSocketStream::SYNC,
                                 ERR_CONNECTION_CLOSED);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_, OnClosingHandshake());
    EXPECT_CALL(
        *event_interface_,
        OnDropChannel(
            true, kWebSocketErrorInternalServerError, "Internal Server Error"));
  }

  CreateChannelAndConnectSuccessfully();
}

// Do not close until browser has sent all pending frames.
TEST_F(WebSocketChannelEventInterfaceTest, ShouldCloseWhileNoDataFrames) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, NOT_MASKED,
       CLOSE_DATA(SERVER_ERROR, "Internal Server Error")}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  stream->PrepareReadFramesError(ReadableFakeWebSocketStream::SYNC,
                                 ERR_CONNECTION_CLOSED);
  set_stream(std::move(stream));
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_, HasPendingDataFrames())
        .WillOnce(Return(false))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(checkpoint, Call(1));
#if DCHECK_IS_ON()
    EXPECT_CALL(*event_interface_, HasPendingDataFrames())
        .WillOnce(Return(false));
#endif
    EXPECT_CALL(*event_interface_, OnClosingHandshake());
    EXPECT_CALL(*event_interface_,
                OnDropChannel(true, kWebSocketErrorInternalServerError,
                              "Internal Server Error"));
  }

  CreateChannelAndConnectSuccessfully();
  checkpoint.Call(1);
  ASSERT_EQ(CHANNEL_DELETED, channel_->ReadFrames());
}

// A remote server could close the connection immediately after sending the
// handshake response (most likely a bug in the server).
TEST_F(WebSocketChannelEventInterfaceTest, ConnectionCloseAfterHandshake) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  stream->PrepareReadFramesError(ReadableFakeWebSocketStream::SYNC,
                                 ERR_CONNECTION_CLOSED);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_,
                OnDropChannel(false, kWebSocketErrorAbnormalClosure, _));
  }

  CreateChannelAndConnectSuccessfully();
}

TEST_F(WebSocketChannelEventInterfaceTest, NormalAsyncRead) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "HELLO"}};
  // We use this checkpoint object to verify that the callback isn't called
  // until we expect it to be.
  Checkpoint checkpoint;
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*event_interface_,
                OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeText,
                                  AsVector("HELLO")));
    EXPECT_CALL(checkpoint, Call(2));
  }

  CreateChannelAndConnectSuccessfully();
  checkpoint.Call(1);
  base::RunLoop().RunUntilIdle();
  checkpoint.Call(2);
}

// Extra data can arrive while a read is being processed, resulting in the next
// read completing synchronously.
TEST_F(WebSocketChannelEventInterfaceTest, AsyncThenSyncRead) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames1[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "HELLO"}};
  static const InitFrame frames2[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "WORLD"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames1);
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames2);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_,
                OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeText,
                                  AsVector("HELLO")));
    EXPECT_CALL(*event_interface_,
                OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeText,
                                  AsVector("WORLD")));
  }

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// Data frames are delivered the same regardless of how many reads they arrive
// as.
TEST_F(WebSocketChannelEventInterfaceTest, FragmentedMessage) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  // Here we have one message which arrived in five frames split across three
  // reads. It may have been reframed on arrival, but this class doesn't care
  // about that.
  static const InitFrame frames1[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "THREE"},
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,      " "}};
  static const InitFrame frames2[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,      "SMALL"}};
  static const InitFrame frames3[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,      " "},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,  "FRAMES"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames1);
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames2);
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames3);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_,
                OnDataFrameVector(false, WebSocketFrameHeader::kOpCodeText,
                                  AsVector("THREE")));
    EXPECT_CALL(
        *event_interface_,
        OnDataFrameVector(false, WebSocketFrameHeader::kOpCodeContinuation,
                          AsVector(" ")));
    EXPECT_CALL(
        *event_interface_,
        OnDataFrameVector(false, WebSocketFrameHeader::kOpCodeContinuation,
                          AsVector("SMALL")));
    EXPECT_CALL(
        *event_interface_,
        OnDataFrameVector(false, WebSocketFrameHeader::kOpCodeContinuation,
                          AsVector(" ")));
    EXPECT_CALL(
        *event_interface_,
        OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeContinuation,
                          AsVector("FRAMES")));
  }

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// A message can consist of one frame with null payload.
TEST_F(WebSocketChannelEventInterfaceTest, NullMessage) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, nullptr}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(
      *event_interface_,
      OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeText, AsVector("")));
  CreateChannelAndConnectSuccessfully();
}

// Connection closed by the remote host without a closing handshake.
TEST_F(WebSocketChannelEventInterfaceTest, AsyncAbnormalClosure) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  stream->PrepareReadFramesError(ReadableFakeWebSocketStream::ASYNC,
                                 ERR_CONNECTION_CLOSED);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_,
                OnDropChannel(false, kWebSocketErrorAbnormalClosure, _));
  }

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// A connection reset should produce the same event as an unexpected closure.
TEST_F(WebSocketChannelEventInterfaceTest, ConnectionReset) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  stream->PrepareReadFramesError(ReadableFakeWebSocketStream::ASYNC,
                                 ERR_CONNECTION_RESET);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_,
                OnDropChannel(false, kWebSocketErrorAbnormalClosure, _));
  }

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// RFC6455 5.1 "A client MUST close a connection if it detects a masked frame."
TEST_F(WebSocketChannelEventInterfaceTest, MaskedFramesAreRejected) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "HELLO"}};

  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(
        *event_interface_,
        OnFailChannel(
            "A server must not mask any frames that it sends to the client.", _,
            _));
  }

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// RFC6455 5.2 "If an unknown opcode is received, the receiving endpoint MUST
// _Fail the WebSocket Connection_."
TEST_F(WebSocketChannelEventInterfaceTest, UnknownOpCodeIsRejected) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {{FINAL_FRAME, 4, NOT_MASKED, "HELLO"}};

  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_,
                OnFailChannel("Unrecognized frame opcode: 4", _, _));
  }

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// RFC6455 5.4 "Control frames ... MAY be injected in the middle of a
// fragmented message."
TEST_F(WebSocketChannelEventInterfaceTest, ControlFrameInDataMessage) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  // We have one message of type Text split into two frames. In the middle is a
  // control message of type Pong.
  static const InitFrame frames1[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText,
       NOT_MASKED,      "SPLIT "}};
  static const InitFrame frames2[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePong, NOT_MASKED, ""}};
  static const InitFrame frames3[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeContinuation,
       NOT_MASKED,  "MESSAGE"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames1);
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames2);
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames3);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_,
                OnDataFrameVector(false, WebSocketFrameHeader::kOpCodeText,
                                  AsVector("SPLIT ")));
    EXPECT_CALL(
        *event_interface_,
        OnDataFrameVector(true, WebSocketFrameHeader::kOpCodeContinuation,
                          AsVector("MESSAGE")));
  }

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// It seems redundant to repeat the entirety of the above test, so just test a
// Pong with null data.
TEST_F(WebSocketChannelEventInterfaceTest, PongWithNullData) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodePong, NOT_MASKED, nullptr}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// If a frame has an invalid header, then the connection is closed and
// subsequent frames must not trigger events.
TEST_F(WebSocketChannelEventInterfaceTest, FrameAfterInvalidFrame) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {NOT_FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, MASKED, "HELLO"},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, " WORLD"}};

  stream->PrepareReadFrames(ReadableFakeWebSocketStream::ASYNC, OK, frames);
  set_stream(std::move(stream));
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(
        *event_interface_,
        OnFailChannel(
            "A server must not mask any frames that it sends to the client.", _,
            _));
  }

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

// If a write fails, the channel is dropped.
TEST_F(WebSocketChannelEventInterfaceTest, FailedWrite) {
  set_stream(std::make_unique<UnWriteableFakeWebSocketStream>());
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*event_interface_,
                OnDropChannel(false, kWebSocketErrorAbnormalClosure, _));
    EXPECT_CALL(checkpoint, Call(2));
  }

  CreateChannelAndConnectSuccessfully();
  checkpoint.Call(1);

  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("H"), 1U),
            WebSocketChannel::CHANNEL_DELETED);
  checkpoint.Call(2);
}

// OnDropChannel() is called exactly once when StartClosingHandshake() is used.
TEST_F(WebSocketChannelEventInterfaceTest, SendCloseDropsChannel) {
  set_stream(std::make_unique<EchoeyFakeWebSocketStream>());
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_, OnSendDataFrameDone());
    EXPECT_CALL(*event_interface_,
                OnDropChannel(true, kWebSocketNormalClosure, "Fred"));
  }

  CreateChannelAndConnectSuccessfully();

  ASSERT_EQ(CHANNEL_ALIVE,
            channel_->StartClosingHandshake(kWebSocketNormalClosure, "Fred"));
  base::RunLoop().RunUntilIdle();
}

// StartClosingHandshake() also works before connection completes, and calls
// OnDropChannel.
TEST_F(WebSocketChannelEventInterfaceTest, CloseDuringConnection) {
  EXPECT_CALL(*event_interface_,
              OnDropChannel(false, kWebSocketErrorAbnormalClosure, ""));

  CreateChannelAndConnect();
  ASSERT_EQ(CHANNEL_DELETED,
            channel_->StartClosingHandshake(kWebSocketNormalClosure, "Joe"));
}

// OnDropChannel() is only called once when a write() on the socket triggers a
// connection reset.
TEST_F(WebSocketChannelEventInterfaceTest, OnDropChannelCalledOnce) {
  set_stream(std::make_unique<ResetOnWriteFakeWebSocketStream>());
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));

  EXPECT_CALL(*event_interface_,
              OnDropChannel(false, kWebSocketErrorAbnormalClosure, ""))
      .Times(1);

  CreateChannelAndConnectSuccessfully();

  EXPECT_EQ(channel_->SendFrame(true, WebSocketFrameHeader::kOpCodeText,
                                AsIOBuffer("yt?"), 3U),
            WebSocketChannel::CHANNEL_ALIVE);
  base::RunLoop().RunUntilIdle();
}

// When the remote server sends a Close frame with an empty payload,
// WebSocketChannel should report code 1005, kWebSocketErrorNoStatusReceived.
TEST_F(WebSocketChannelEventInterfaceTest, CloseWithNoPayloadGivesStatus1005) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, NOT_MASKED, ""}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  stream->PrepareReadFramesError(ReadableFakeWebSocketStream::SYNC,
                                 ERR_CONNECTION_CLOSED);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(*event_interface_, OnClosingHandshake());
  EXPECT_CALL(*event_interface_,
              OnDropChannel(true, kWebSocketErrorNoStatusReceived, _));

  CreateChannelAndConnectSuccessfully();
}

// A version of the above test with null payload.
TEST_F(WebSocketChannelEventInterfaceTest,
       CloseWithNullPayloadGivesStatus1005) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, NOT_MASKED, nullptr}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  stream->PrepareReadFramesError(ReadableFakeWebSocketStream::SYNC,
                                 ERR_CONNECTION_CLOSED);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(*event_interface_, OnClosingHandshake());
  EXPECT_CALL(*event_interface_,
              OnDropChannel(true, kWebSocketErrorNoStatusReceived, _));

  CreateChannelAndConnectSuccessfully();
}

// If ReadFrames() returns ERR_WS_PROTOCOL_ERROR, then the connection must be
// failed.
TEST_F(WebSocketChannelEventInterfaceTest, SyncProtocolErrorGivesStatus1002) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  stream->PrepareReadFramesError(ReadableFakeWebSocketStream::SYNC,
                                 ERR_WS_PROTOCOL_ERROR);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));

  EXPECT_CALL(*event_interface_, OnFailChannel("Invalid frame header", _, _));

  CreateChannelAndConnectSuccessfully();
}

// Async version of above test.
TEST_F(WebSocketChannelEventInterfaceTest, AsyncProtocolErrorGivesStatus1002) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  stream->PrepareReadFramesError(ReadableFakeWebSocketStream::ASYNC,
                                 ERR_WS_PROTOCOL_ERROR);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(*event_interface_, OnFailChannel("Invalid frame header", _, _));

  CreateChannelAndConnectSuccessfully();
  base::RunLoop().RunUntilIdle();
}

TEST_F(WebSocketChannelEventInterfaceTest, StartHandshakeRequest) {
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
    EXPECT_CALL(*event_interface_, OnStartOpeningHandshakeCalled());
  }

  CreateChannelAndConnectSuccessfully();

  auto request_info = std::make_unique<WebSocketHandshakeRequestInfo>(
      GURL("ws://www.example.com/"), base::Time());
  connect_data_.argument_saver.connect_delegate->OnStartOpeningHandshake(
      std::move(request_info));

  base::RunLoop().RunUntilIdle();
}

TEST_F(WebSocketChannelEventInterfaceTest, FailJustAfterHandshake) {
  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnStartOpeningHandshakeCalled());
    EXPECT_CALL(*event_interface_, OnFailChannel("bye", _, _));
  }

  CreateChannelAndConnect();

  WebSocketStream::ConnectDelegate* connect_delegate =
      connect_data_.argument_saver.connect_delegate.get();
  GURL url("ws://www.example.com/");
  auto request_info =
      std::make_unique<WebSocketHandshakeRequestInfo>(url, base::Time());
  auto response_headers =
      base::MakeRefCounted<HttpResponseHeaders>("HTTP/1.1 200 OK");
  auto response_info = std::make_unique<WebSocketHandshakeResponseInfo>(
      url, response_headers, IPEndPoint(), base::Time());
  connect_delegate->OnStartOpeningHandshake(std::move(request_info));

  connect_delegate->OnFailure("bye", ERR_FAILED, std::nullopt);
  base::RunLoop().RunUntilIdle();
}

// Any frame after close is invalid. This test uses a Text frame. See also
// test "PingAfterCloseIfRejected".
TEST_F(WebSocketChannelEventInterfaceTest, DataAfterCloseIsRejected) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, NOT_MASKED,
       CLOSE_DATA(NORMAL_CLOSURE, "OK")},
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeText, NOT_MASKED, "Payload"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));

  {
    InSequence s;
    EXPECT_CALL(*event_interface_, OnClosingHandshake());
    EXPECT_CALL(*event_interface_,
                OnFailChannel("Data frame received after close", _, _));
  }

  CreateChannelAndConnectSuccessfully();
}

// A Close frame with a one-byte payload elicits a specific console error
// message.
TEST_F(WebSocketChannelEventInterfaceTest, OneByteClosePayloadMessage) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose, NOT_MASKED, "\x03"}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(
      *event_interface_,
      OnFailChannel(
          "Received a broken close frame with an invalid size of 1 byte.", _,
          _));

  CreateChannelAndConnectSuccessfully();
}

// A Close frame with a reserved status code also elicits a specific console
// error message.
TEST_F(WebSocketChannelEventInterfaceTest, ClosePayloadReservedStatusMessage) {
  auto stream = std::make_unique<ReadableFakeWebSocketStream>();
  static const InitFrame frames[] = {
      {FINAL_FRAME, WebSocketFrameHeader::kOpCodeClose,
       NOT_MASKED,  CLOSE_DATA(ABNORMAL_CLOSURE, "Not valid on wire")}};
  stream->PrepareReadFrames(ReadableFakeWebSocketStream::SYNC, OK, frames);
  set_stream(std::move(stream));
  EXPECT_CALL(*event_interface_, OnAddChannelResponse(_, _, _));
  EXPECT_CALL(
      *event_interface_,
```