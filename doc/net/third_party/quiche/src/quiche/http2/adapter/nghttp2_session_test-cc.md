Response:
Let's break down the thought process for analyzing the C++ test file and generating the response.

**1. Understanding the Core Request:**

The request asks for:

* **Functionality of the file:** What does this code do?
* **Relation to JavaScript:** Are there any connections to JavaScript concepts?
* **Logic and I/O:**  Can we infer input/output based on the tests?
* **Common Errors:** What mistakes might users or programmers make when interacting with this code or the underlying library?
* **Debugging Path:** How would a developer end up looking at this specific file during debugging?

**2. Initial Scan and Identification of Key Components:**

The first step is to quickly read through the code to identify the major parts:

* **Includes:** These point to the libraries and headers being used. `quiche/http2/adapter/nghttp2_session.h` is a central piece. The `test/` includes indicate this is a testing file.
* **Namespaces:** `http2::adapter::test` tells us the context.
* **`NgHttp2SessionTest` Class:** This is the main test fixture, inheriting from `quiche::test::QuicheTest`. This immediately tells us we're dealing with unit tests.
* **`SetUp` and `TearDown`:** Standard testing setup/cleanup functions. They initialize and deallocate `nghttp2_option`.
* **`CreateCallbacks`:** A helper function to create `nghttp2` callbacks.
* **Test Cases (e.g., `ClientConstruction`, `ClientHandlesFrames`, etc.):** These are individual tests focusing on specific aspects of `NgHttp2Session`.
* **`TestVisitor`:** A mock object (`MockHttp2Visitor`) used to observe interactions with the `NgHttp2Session`. This is crucial for verifying the behavior of the session.
* **`TestFrameSequence`:** A utility class for constructing HTTP/2 frame sequences.
* **`ToHeaders` and `GetNghttp2Nvs`:** Helper functions for converting between header representations.
* **`nghttp2_` function calls:**  These indicate interaction with the underlying `nghttp2` library.

**3. Analyzing Individual Test Cases:**

For each test case, the process involves:

* **Identifying the scenario:** What aspect of `NgHttp2Session` is being tested (e.g., client creation, handling frames as a client, handling frames as a server, error conditions)?
* **Following the control flow:**  Read the code line by line to understand the setup, actions performed on the `NgHttp2Session`, and the assertions/expectations.
* **Understanding the expectations:** Pay close attention to the `EXPECT_CALL` statements on the `visitor_`. These define the expected interactions with the mock visitor, indicating what the `NgHttp2Session` *should* do. The arguments to `EXPECT_CALL` are critical for understanding the specifics (frame types, stream IDs, data, etc.).
* **Inferring inputs and outputs:**  Based on the `TestFrameSequence` and the `EXPECT_CALL`s, determine what input is being fed to the session and what output (in terms of callbacks to the visitor) is expected.
* **Identifying relevant `nghttp2` functions:** Understand the role of functions like `nghttp2_session_send`, `nghttp2_submit_request`, `nghttp2_submit_extension`.

**4. Connecting to JavaScript (or Lack Thereof):**

The code is clearly C++. The key is to identify if any of the concepts are mirrored in JavaScript web development:

* **HTTP/2 Protocol:**  JavaScript in browsers uses HTTP/2 for communication with servers. Concepts like streams, headers, data frames are relevant.
* **Client-Server Interaction:**  The test cases for client and server perspectives directly relate to how web applications interact.
* **Error Handling:** The `RST_STREAM` and `GOAWAY` frames, and error codes like `INTERNAL_ERROR`, are important for robust network communication, also applicable to JavaScript.
* **WebSockets (Potential, though not explicitly tested):** While not directly shown, the underlying mechanisms could be related to how WebSockets are implemented, which JavaScript interacts with.

Crucially, the *direct* connection is through the underlying browser implementation. JavaScript doesn't directly manipulate `nghttp2` but uses browser APIs that rely on implementations like this.

**5. Identifying Common Errors:**

By examining the test cases and the nature of the HTTP/2 protocol, we can infer potential errors:

* **Incorrect Frame Sequencing:** HTTP/2 has specific rules about frame ordering. The tests implicitly check for correct handling of sequences.
* **Header Format Errors:** Incorrect or missing required headers.
* **Data Handling Errors:** Incorrect data length, trying to send data after closing a stream.
* **Flow Control Issues:** Although auto window updates are disabled in the tests, misunderstanding flow control is a common error.
* **Callback Failures:** The `NullPayload` test specifically highlights a case where a callback returns an error.

**6. Tracing the Debugging Path:**

Consider scenarios where a developer might need to investigate this code:

* **HTTP/2 Implementation Bugs:** If there's a problem with how Chromium handles HTTP/2, this core adapter layer is a prime suspect.
* **Interoperability Issues:** Problems communicating with servers that have specific HTTP/2 implementations.
* **Performance Problems:**  Understanding how the session manages streams and flow control could be relevant for performance analysis.
* **Investigating Specific Frame Handling:**  If a particular type of frame (e.g., `PUSH_PROMISE`) is causing issues, the code handling that frame would be examined.

**7. Structuring the Response:**

Finally, organize the gathered information into a clear and structured response, addressing each part of the original request. Use clear headings and bullet points to make the information easy to understand. Provide concrete examples where possible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus too much on direct JavaScript code.
* **Correction:** Realize the connection is through the browser's internal implementation and the underlying HTTP/2 concepts. Emphasize the "how a browser using Chromium..." aspect.
* **Initial thought:**  Describe every single line of code in detail.
* **Correction:** Focus on the *purpose* of the tests and the overall functionality rather than a low-level code walkthrough. Highlight the key `EXPECT_CALL`s and the frame sequences.
* **Initial thought:**  Just list potential errors without context.
* **Correction:** Provide specific examples of how these errors might manifest and how the tests might catch them.

By following these steps, combining code analysis with an understanding of HTTP/2 and testing principles, a comprehensive and accurate answer can be generated.
这个C++源代码文件 `nghttp2_session_test.cc` 是 Chromium 网络栈中用于测试 `NgHttp2Session` 类的单元测试文件。`NgHttp2Session` 是一个适配器类，它封装了 `nghttp2` 库的功能，为 Chromium 的 HTTP/2 实现提供了底层支持。

以下是该文件的功能列表：

**核心功能：测试 NgHttp2Session 类的各种行为和功能**

1. **会话生命周期管理:**
   - 测试客户端和服务器端 `NgHttp2Session` 对象的创建和销毁。
   - 验证会话的初始状态（例如，是否期望读/写，初始窗口大小）。

2. **帧处理:**
   - 测试 `NgHttp2Session` 如何处理各种 HTTP/2 帧，包括：
     - `SETTINGS` (设置)
     - `PING` (心跳)
     - `WINDOW_UPDATE` (窗口更新)
     - `HEADERS` (头部)
     - `DATA` (数据)
     - `RST_STREAM` (重置流)
     - `GOAWAY` (关闭连接)
   - 测试客户端和服务器端分别如何发送和接收这些帧。
   - 使用 `TestFrameSequence` 类方便地构造和发送帧序列。
   - 使用 `MockHttp2Visitor` 模拟 HTTP/2 会话的回调，验证 `NgHttp2Session` 在接收到帧时是否正确地调用了相应的回调函数（例如 `OnFrameHeader`, `OnSettingsStart`, `OnDataForStream` 等）。

3. **流管理:**
   - 测试如何创建新的 HTTP/2 流 (`nghttp2_submit_request`)。
   - 验证流 ID 的分配。
   - 测试流的生命周期，包括发送头部、数据，以及流的结束 (FIN)。
   - 测试流的重置 (`RST_STREAM`) 和关闭。

4. **流量控制 (Window Update):**
   - 测试 `NgHttp2Session` 如何处理和更新接收窗口大小。

5. **错误处理:**
   - 测试 `NgHttp2Session` 在遇到错误时的行为，例如接收到无效帧或回调函数返回错误。
   - 模拟 `OnEndStream` 回调返回错误的情况。
   - 测试提交扩展帧时 payload 为空的情况。

6. **客户端和服务器端行为测试:**
   - 区分并测试客户端和服务器端 `NgHttp2Session` 对象的不同行为。例如，客户端发送连接前导 (Client Preface)，服务器端接收连接前导。

**与 JavaScript 的关系:**

该文件是 C++ 代码，直接与 JavaScript 没有关系。但是，它测试的 `NgHttp2Session` 类是 Chromium 网络栈中处理 HTTP/2 协议的关键部分。浏览器中的 JavaScript 代码 (例如，使用 `fetch` API 或 `XMLHttpRequest`) 发起的网络请求，在底层可能会使用到 HTTP/2 协议，而 `NgHttp2Session` 就负责处理这些 HTTP/2 连接的细节。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` API 向服务器请求数据：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当浏览器建立与 `example.com` 的 HTTP/2 连接时，Chromium 的网络栈会使用 `NgHttp2Session` 来管理这个连接。`nghttp2_session_test.cc` 中的测试用例会模拟服务器发送 `HEADERS` 帧和 `DATA` 帧，验证 `NgHttp2Session` 是否正确解析这些帧，并将头部和数据传递给上层。

例如，`ServerHandlesFrames` 测试用例就模拟了服务器接收客户端发送的包含请求头部的 `HEADERS` 帧和包含请求体的 `DATA` 帧，并验证 `NgHttp2Session` 是否正确调用 `OnHeaderForStream` 和 `OnDataForStream` 回调。

**逻辑推理、假设输入与输出:**

**假设输入 (基于 `ClientHandlesFrames` 测试用例):**

```
ServerPreface()  // 服务器连接前导 (空 SETTINGS 帧)
Ping(42)          // PING 帧，opaque_data=42
WindowUpdate(0, 1000) // WINDOW_UPDATE 帧，增加连接级别的窗口大小 1000
```

**预期输出 (对应的 `MockHttp2Visitor` 回调):**

```
OnFrameHeader(0, 0, SETTINGS, 0)
OnSettingsStart()
OnSettingsEnd()
OnFrameHeader(0, 8, PING, 0)
OnPing(42, false)
OnFrameHeader(0, 4, WINDOW_UPDATE, 0)
OnWindowUpdate(0, 1000)
```

**假设输入 (基于 `ServerHandlesFrames` 测试用例):**

```
ClientPreface() // 客户端连接前导 (空 SETTINGS 帧)
Headers(1, {{":method", "POST"}, ...}, false) // HEADERS 帧，用于流 ID 1
WindowUpdate(1, 2000) // WINDOW_UPDATE 帧，增加流 ID 1 的窗口大小 2000
Data(1, "This is the request body.") // DATA 帧，用于流 ID 1
```

**预期输出 (对应的 `MockHttp2Visitor` 回调):**

```
OnFrameHeader(0, 0, SETTINGS, 0)
OnSettingsStart()
OnSettingsEnd()
OnFrameHeader(1, _, HEADERS, 4)
OnBeginHeadersForStream(1)
OnHeaderForStream(1, ":method", "POST")
... // 其他头部
OnEndHeadersForStream(1)
OnFrameHeader(1, 4, WINDOW_UPDATE, 0)
OnWindowUpdate(1, 2000)
OnFrameHeader(1, 25, DATA, 0)
OnBeginDataForStream(1, 25)
OnDataForStream(1, "This is the request body.")
```

**用户或编程常见的使用错误:**

1. **未正确处理 `want_read()` 和 `want_write()`:**  `NgHttp2Session` 使用 `want_read()` 和 `want_write()` 来指示是否期望从底层网络读取数据或向底层网络写入数据。如果用户没有正确轮询这些状态并调用 `ProcessBytes()` 或 `Send()`，会导致数据无法正确发送或接收。

   **例子:**  假设服务器端收到了客户端的请求，但服务器程序忘记检查 `session.want_write()` 并在准备好响应后调用 `nghttp2_session_send()`, 那么响应将不会被发送出去。

2. **在错误的时机发送帧:** HTTP/2 协议有严格的状态机。例如，在连接建立之前发送数据帧是错误的。

   **例子:**  在 `SETTINGS` 交换完成之前，客户端尝试发送 `HEADERS` 帧，`NgHttp2Session` 可能会返回错误或关闭连接。

3. **流量控制窗口管理不当:**  发送方发送的数据量超过接收方的窗口大小时，连接会阻塞。

   **例子:**  客户端的初始窗口大小是 65535 字节。如果服务器发送超过这个大小的数据，而客户端没有发送 `WINDOW_UPDATE` 帧来增加窗口大小，服务器最终会停止发送数据。

4. **不正确的头部信息:**  HTTP/2 的头部信息有特定的格式和要求。例如，`:` 前缀的伪头部字段（如 `:method`, `:path`）是必需的。

   **例子:**  客户端提交请求时，缺少 `:method` 或 `:path` 头部，`NgHttp2Session` 在序列化帧时可能会出错。

5. **回调函数实现错误:**  用户需要实现 `NgHttp2Visitor` 接口的回调函数来处理接收到的帧。如果这些回调函数的实现有错误，可能会导致程序崩溃或行为异常。

   **例子:** `NullPayload` 测试用例就模拟了提交扩展帧时 payload 为空的情况，这会导致 `OnPackExtensionCallback` 回调失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chromium 浏览器访问一个网站时遇到了 HTTP/2 相关的问题，例如：

1. **页面加载缓慢或失败:**  用户访问某个网站，浏览器尝试建立 HTTP/2 连接，但连接建立失败或者数据传输速度很慢。

2. **控制台出现网络错误:**  浏览器的开发者工具的 Network 面板显示 HTTP/2 连接相关的错误信息。

3. **特定资源加载失败:**  网站上的某些图片、脚本或样式表无法加载，提示与 HTTP/2 有关的错误。

作为 Chromium 的开发人员或需要深入调试网络问题的用户，可能会按照以下步骤进行调试，最终可能需要查看 `nghttp2_session_test.cc`：

1. **检查网络日志:**  首先查看 Chrome 的 `net-internals` 工具 (`chrome://net-internals/#http2`)，查看 HTTP/2 连接的详细信息，包括发送和接收的帧。

2. **分析帧序列:**  根据 `net-internals` 的信息，分析是否有异常的帧或帧序列错误。

3. **定位到 `NgHttp2Session`:**  如果怀疑是 HTTP/2 会话管理的问题，可能会查看 `NgHttp2Session` 相关的代码。

4. **查看单元测试:**  为了理解 `NgHttp2Session` 的预期行为和各种帧的处理逻辑，开发人员可能会查看 `nghttp2_session_test.cc` 中的单元测试。这些测试用例覆盖了各种正常的和异常的场景，可以帮助理解 `NgHttp2Session` 的工作原理，并找到潜在的 bug。

5. **针对性调试:**  如果 `net-internals` 显示接收到了一个特定的异常帧 (例如 `RST_STREAM` 或 `GOAWAY`)，开发人员可能会在 `nghttp2_session_test.cc` 中查找处理该帧的测试用例，例如 `ClientHandlesFrames` 中的相关部分，以理解 `NgHttp2Session` 在接收到该帧时的行为。

6. **模拟和重现:**  有时，开发人员可能会尝试编写新的单元测试来重现用户遇到的问题，或者修改现有的测试用例来验证修复方案。

因此，`nghttp2_session_test.cc` 作为 `NgHttp2Session` 的单元测试文件，是理解和调试 Chromium HTTP/2 实现的重要资源。当网络问题指向 HTTP/2 层时，查看和分析这个文件可以提供关键的线索。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/http2/adapter/nghttp2_session.h"

#include <string>
#include <vector>

#include "quiche/http2/adapter/mock_http2_visitor.h"
#include "quiche/http2/adapter/nghttp2_callbacks.h"
#include "quiche/http2/adapter/nghttp2_util.h"
#include "quiche/http2/adapter/test_frame_sequence.h"
#include "quiche/http2/adapter/test_utils.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using testing::_;

enum FrameType {
  DATA,
  HEADERS,
  PRIORITY,
  RST_STREAM,
  SETTINGS,
  PUSH_PROMISE,
  PING,
  GOAWAY,
  WINDOW_UPDATE,
};

class NgHttp2SessionTest : public quiche::test::QuicheTest {
 public:
  void SetUp() override {
    nghttp2_option_new(&options_);
    nghttp2_option_set_no_auto_window_update(options_, 1);
  }

  void TearDown() override { nghttp2_option_del(options_); }

  nghttp2_session_callbacks_unique_ptr CreateCallbacks() {
    nghttp2_session_callbacks_unique_ptr callbacks = callbacks::Create(nullptr);
    return callbacks;
  }

  TestVisitor visitor_;
  nghttp2_option* options_ = nullptr;
};

TEST_F(NgHttp2SessionTest, ClientConstruction) {
  NgHttp2Session session(Perspective::kClient, CreateCallbacks(), options_,
                         &visitor_);
  EXPECT_TRUE(session.want_read());
  EXPECT_FALSE(session.want_write());
  EXPECT_EQ(session.GetRemoteWindowSize(), kInitialFlowControlWindowSize);
  EXPECT_NE(session.raw_ptr(), nullptr);
}

TEST_F(NgHttp2SessionTest, ClientHandlesFrames) {
  NgHttp2Session session(Perspective::kClient, CreateCallbacks(), options_,
                         &visitor_);

  ASSERT_EQ(0, nghttp2_session_send(session.raw_ptr()));
  ASSERT_GT(visitor_.data().size(), 0);

  const std::string initial_frames = TestFrameSequence()
                                         .ServerPreface()
                                         .Ping(42)
                                         .WindowUpdate(0, 1000)
                                         .Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor_, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor_, OnSettingsStart());
  EXPECT_CALL(visitor_, OnSettingsEnd());

  EXPECT_CALL(visitor_, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor_, OnPing(42, false));
  EXPECT_CALL(visitor_, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor_, OnWindowUpdate(0, 1000));

  const int64_t initial_result = session.ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_EQ(session.GetRemoteWindowSize(),
            kInitialFlowControlWindowSize + 1000);

  EXPECT_CALL(visitor_, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor_, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor_, OnBeforeFrameSent(PING, 0, 8, 0x1));
  EXPECT_CALL(visitor_, OnFrameSent(PING, 0, 8, 0x1, 0));

  ASSERT_EQ(0, nghttp2_session_send(session.raw_ptr()));
  // Some bytes should have been serialized.
  absl::string_view serialized = visitor_.data();
  ASSERT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                        spdy::SpdyFrameType::PING}));
  visitor_.Clear();

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const auto nvs1 = GetNghttp2Nvs(headers1);

  const std::vector<Header> headers2 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/two"}});
  const auto nvs2 = GetNghttp2Nvs(headers2);

  const std::vector<Header> headers3 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/three"}});
  const auto nvs3 = GetNghttp2Nvs(headers3);

  const int32_t stream_id1 = nghttp2_submit_request(
      session.raw_ptr(), nullptr, nvs1.data(), nvs1.size(), nullptr, nullptr);
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  const int32_t stream_id2 = nghttp2_submit_request(
      session.raw_ptr(), nullptr, nvs2.data(), nvs2.size(), nullptr, nullptr);
  ASSERT_GT(stream_id2, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id2;

  const int32_t stream_id3 = nghttp2_submit_request(
      session.raw_ptr(), nullptr, nvs3.data(), nvs3.size(), nullptr, nullptr);
  ASSERT_GT(stream_id3, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id3;

  EXPECT_CALL(visitor_, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor_, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor_, OnBeforeFrameSent(HEADERS, 3, _, 0x5));
  EXPECT_CALL(visitor_, OnFrameSent(HEADERS, 3, _, 0x5, 0));
  EXPECT_CALL(visitor_, OnBeforeFrameSent(HEADERS, 5, _, 0x5));
  EXPECT_CALL(visitor_, OnFrameSent(HEADERS, 5, _, 0x5, 0));

  ASSERT_EQ(0, nghttp2_session_send(session.raw_ptr()));
  serialized = visitor_.data();
  EXPECT_THAT(serialized, EqualsFrames({spdy::SpdyFrameType::HEADERS,
                                        spdy::SpdyFrameType::HEADERS,
                                        spdy::SpdyFrameType::HEADERS}));
  visitor_.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.")
          .RstStream(3, Http2ErrorCode::INTERNAL_ERROR)
          .GoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!")
          .Serialize();

  EXPECT_CALL(visitor_, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor_, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor_,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor_, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor_, OnFrameHeader(1, 26, DATA, 0));
  EXPECT_CALL(visitor_, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor_, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor_, OnFrameHeader(3, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor_, OnRstStream(3, Http2ErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(visitor_, OnCloseStream(3, Http2ErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(visitor_, OnFrameHeader(0, 19, GOAWAY, 0));
  EXPECT_CALL(visitor_,
              OnGoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!"));
  const int64_t stream_result = session.ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  // Even though the client recieved a GOAWAY, streams 1 and 5 are still active.
  EXPECT_TRUE(session.want_read());

  EXPECT_CALL(visitor_, OnFrameHeader(1, 0, DATA, 1));
  EXPECT_CALL(visitor_, OnBeginDataForStream(1, 0));
  EXPECT_CALL(visitor_, OnEndStream(1));
  EXPECT_CALL(visitor_, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
  EXPECT_CALL(visitor_, OnFrameHeader(5, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor_, OnRstStream(5, Http2ErrorCode::REFUSED_STREAM));
  EXPECT_CALL(visitor_, OnCloseStream(5, Http2ErrorCode::REFUSED_STREAM));
  session.ProcessBytes(TestFrameSequence()
                           .Data(1, "", true)
                           .RstStream(5, Http2ErrorCode::REFUSED_STREAM)
                           .Serialize());
  // After receiving END_STREAM for 1 and RST_STREAM for 5, the session no
  // longer expects reads.
  EXPECT_FALSE(session.want_read());

  // Client will not have anything else to write.
  EXPECT_FALSE(session.want_write());
  ASSERT_EQ(0, nghttp2_session_send(session.raw_ptr()));
  serialized = visitor_.data();
  EXPECT_EQ(serialized.size(), 0);
}

TEST_F(NgHttp2SessionTest, ServerConstruction) {
  NgHttp2Session session(Perspective::kServer, CreateCallbacks(), options_,
                         &visitor_);
  EXPECT_TRUE(session.want_read());
  EXPECT_FALSE(session.want_write());
  EXPECT_EQ(session.GetRemoteWindowSize(), kInitialFlowControlWindowSize);
  EXPECT_NE(session.raw_ptr(), nullptr);
}

TEST_F(NgHttp2SessionTest, ServerHandlesFrames) {
  NgHttp2Session session(Perspective::kServer, CreateCallbacks(), options_,
                         &visitor_);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Ping(42)
                                 .WindowUpdate(0, 1000)
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .WindowUpdate(1, 2000)
                                 .Data(1, "This is the request body.")
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "http"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/two"}},
                                          /*fin=*/true)
                                 .RstStream(3, Http2ErrorCode::CANCEL)
                                 .Ping(47)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor_, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor_, OnSettingsStart());
  EXPECT_CALL(visitor_, OnSettingsEnd());

  EXPECT_CALL(visitor_, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor_, OnPing(42, false));
  EXPECT_CALL(visitor_, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor_, OnWindowUpdate(0, 1000));
  EXPECT_CALL(visitor_, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor_, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor_, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor_, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor_, OnWindowUpdate(1, 2000));
  EXPECT_CALL(visitor_, OnFrameHeader(1, 25, DATA, 0));
  EXPECT_CALL(visitor_, OnBeginDataForStream(1, 25));
  EXPECT_CALL(visitor_, OnDataForStream(1, "This is the request body."));
  EXPECT_CALL(visitor_, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor_, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor_, OnHeaderForStream(3, ":method", "GET"));
  EXPECT_CALL(visitor_, OnHeaderForStream(3, ":scheme", "http"));
  EXPECT_CALL(visitor_, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor_, OnHeaderForStream(3, ":path", "/this/is/request/two"));
  EXPECT_CALL(visitor_, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor_, OnEndStream(3));
  EXPECT_CALL(visitor_, OnFrameHeader(3, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor_, OnRstStream(3, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor_, OnCloseStream(3, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor_, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor_, OnPing(47, false));

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_EQ(session.GetRemoteWindowSize(),
            kInitialFlowControlWindowSize + 1000);

  EXPECT_CALL(visitor_, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor_, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor_, OnBeforeFrameSent(PING, 0, 8, 0x1));
  EXPECT_CALL(visitor_, OnFrameSent(PING, 0, 8, 0x1, 0));
  EXPECT_CALL(visitor_, OnBeforeFrameSent(PING, 0, 8, 0x1));
  EXPECT_CALL(visitor_, OnFrameSent(PING, 0, 8, 0x1, 0));

  EXPECT_TRUE(session.want_write());
  ASSERT_EQ(0, nghttp2_session_send(session.raw_ptr()));
  // Some bytes should have been serialized.
  absl::string_view serialized = visitor_.data();
  // SETTINGS ack, two PING acks.
  EXPECT_THAT(serialized, EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                        spdy::SpdyFrameType::PING,
                                        spdy::SpdyFrameType::PING}));
}

// Verifies that a null payload is caught by the OnPackExtensionCallback
// implementation.
TEST_F(NgHttp2SessionTest, NullPayload) {
  NgHttp2Session session(Perspective::kClient, CreateCallbacks(), options_,
                         &visitor_);

  void* payload = nullptr;
  const int result = nghttp2_submit_extension(
      session.raw_ptr(), kMetadataFrameType, 0, 1, payload);
  ASSERT_EQ(0, result);
  EXPECT_TRUE(session.want_write());
  int send_result = -1;
  EXPECT_QUICHE_BUG(
      {
        send_result = nghttp2_session_send(session.raw_ptr());
        EXPECT_EQ(NGHTTP2_ERR_CALLBACK_FAILURE, send_result);
      },
      "Extension frame payload for stream 1 is null!");
}

TEST_F(NgHttp2SessionTest, ServerSeesErrorOnEndStream) {
  NgHttp2Session session(Perspective::kServer, CreateCallbacks(), options_,
                         &visitor_);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"}},
                                          /*fin=*/false)
                                 .Data(1, "Request body", true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor_, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor_, OnSettingsStart());
  EXPECT_CALL(visitor_, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor_, OnFrameHeader(1, _, HEADERS, 0x4));
  EXPECT_CALL(visitor_, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":path", "/"));
  EXPECT_CALL(visitor_, OnEndHeadersForStream(1));

  EXPECT_CALL(visitor_, OnFrameHeader(1, _, DATA, 0x1));
  EXPECT_CALL(visitor_, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor_, OnDataForStream(1, "Request body"));
  EXPECT_CALL(visitor_, OnEndStream(1)).WillOnce(testing::Return(false));

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(NGHTTP2_ERR_CALLBACK_FAILURE, result);

  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor_, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor_, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  ASSERT_EQ(0, nghttp2_session_send(session.raw_ptr()));
  EXPECT_THAT(visitor_.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
  visitor_.Clear();

  EXPECT_FALSE(session.want_write());
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
```