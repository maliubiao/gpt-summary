Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `callback_visitor_test.cc` immediately suggests this file tests the `CallbackVisitor` class. The `_test.cc` suffix is a standard convention for unit tests in C++ projects. The "callback" part hints at the interaction with a callback mechanism, likely related to handling HTTP/2 events.

2. **Understand the Context:** The path `net/third_party/quiche/src/quiche/http2/adapter/` tells us this is part of the QUIC implementation within Chromium's networking stack, specifically the HTTP/2 adapter. This adapter likely translates low-level HTTP/2 events into a higher-level interface.

3. **Examine Includes:** The included headers provide valuable clues:
    * `"quiche/http2/adapter/callback_visitor.h"`:  Confirms this file tests `CallbackVisitor`.
    * `<string>`:  Standard string manipulation.
    * `"absl/container/flat_hash_map.h"`: Implies the `CallbackVisitor` likely manages stream-related data, possibly using a hash map.
    * `"quiche/http2/adapter/http2_protocol.h"`: Deals with HTTP/2 protocol constants and structures.
    * `"quiche/http2/adapter/mock_nghttp2_callbacks.h"`:  Crucial for testing. Indicates the `CallbackVisitor` interacts with `nghttp2` (a popular HTTP/2 library) and uses mocks for testing its interactions.
    * `"quiche/http2/adapter/nghttp2_adapter.h"`: The adapter this visitor is part of.
    * `"quiche/http2/adapter/nghttp2_test_utils.h"` and `"quiche/http2/adapter/test_frame_sequence.h"`: Utility classes for constructing and manipulating HTTP/2 frames in tests.
    * `"quiche/http2/adapter/test_utils.h"`: General testing utilities.
    * `"quiche/common/platform/api/quiche_test.h"`: The base class for QUIC tests.

4. **Analyze the Test Structure:** The file uses Google Test (`TEST`, `EXPECT_CALL`, `ASSERT_TRUE`, etc.). Tests are grouped by functionality (e.g., `ConnectionFrames`, `StreamFrames`, `HeadersWithContinuation`). This helps in understanding the different aspects being tested.

5. **Decipher Individual Tests:** For each test case:
    * **Instantiation:**  A `StrictMock<MockNghttp2Callbacks>` is created. This means all expected calls to the mock *must* happen in the specified order. A `CallbackVisitor` is instantiated, taking the perspective (client or server) and the mock callbacks.
    * **`EXPECT_CALL`:** These lines define the expected interactions with the mock `nghttp2` callbacks. They specify the method called (`OnBeginFrame`, `OnFrameRecv`, `OnHeader`, etc.) and the expected arguments (using matchers like `HasFrameHeader`, `IsSettings`, `IsData`). The `testing::InSequence seq;` ensures the calls happen in the defined order within the test.
    * **`visitor.On...`:** These lines simulate the `CallbackVisitor` receiving HTTP/2 frame events. The arguments mimic the data that would be extracted from a real HTTP/2 frame.
    * **Assertions:** `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT` verify the state of the `CallbackVisitor` or the interactions with the mock. For example, checking the `stream_map_size()` or using `UnorderedElementsAre` to verify closed streams.

6. **Identify Key Functionality:** Based on the test names and the mock expectations, the `CallbackVisitor`'s primary functions are:
    * **Receiving and Processing HTTP/2 Frames:**  The `OnFrameHeader` and subsequent `On...` methods handle different frame types.
    * **Forwarding Events to Callbacks:** The `CallbackVisitor` translates low-level frame data into calls to the `nghttp2` callback interface.
    * **Managing Stream State:** The `stream_map_size()` and the tests involving `RST_STREAM` and `GOAWAY` indicate stream management.
    * **Handling Continuations:** Specific tests deal with `CONTINUATION` frames for headers.
    * **Error Handling:** Tests like `ResetAndGoaway` and `MismatchedContentLengthCallbacks` examine how the visitor handles errors and edge cases.

7. **Relate to JavaScript (If Applicable):**  The connection to JavaScript comes through web browsers. When a browser makes an HTTP/2 request, it's the browser's networking stack (which includes code like this) that parses the incoming HTTP/2 responses. The browser's JavaScript engine then receives the parsed data (headers, body) to be used by the web page. The `CallbackVisitor` is a low-level component in this process.

8. **Infer Input/Output:** By looking at the `visitor.On...` calls and the `EXPECT_CALL`s, you can infer the inputs and expected outputs for different scenarios. For example, calling `visitor.OnFrameHeader(1, 23, HEADERS, 4)` followed by `visitor.OnBeginHeadersForStream(1)` is expected to trigger `callbacks.OnBeginHeaders`.

9. **Identify Common Errors:** The tests themselves highlight potential errors:
    * Sending `CONTINUATION` frames without a preceding `HEADERS` frame.
    * Mismatched stream IDs in `CONTINUATION` frames.
    * Receiving frames for already closed streams.
    * Content-Length mismatches.

10. **Trace User Actions:**  Consider how a user's action in a browser leads to this code being executed. For example, a user clicking a link would trigger an HTTP/2 request. The server's response would be processed by a `CallbackVisitor` on the client side.

11. **Iterative Refinement:** After the initial analysis, reread the code and test names carefully. Look for patterns and connections between different tests. This helps refine your understanding and catch any nuances. For instance, noticing the `Perspective::kClient` and `Perspective::kServer` usage highlights the dual nature of the visitor.

By following this structured approach, you can effectively analyze and understand complex C++ test files like this one. The key is to break down the problem into smaller pieces, leverage the available information (filenames, includes, test structure), and connect the code to its broader context.
这个文件 `callback_visitor_test.cc` 是 Chromium 网络栈中 `quiche` 库的一部分，专门用于测试 `CallbackVisitor` 类的功能。`CallbackVisitor` 在 HTTP/2 适配器中扮演着核心角色，它负责接收 HTTP/2 帧解析后的事件通知，并将这些事件转发给实现了 `Nghttp2Callbacks` 接口的对象。

以下是该文件的功能列表：

**主要功能:**

1. **单元测试 `CallbackVisitor` 类:**  该文件通过一系列的单元测试来验证 `CallbackVisitor` 类的各种功能和行为。
2. **模拟 `nghttp2` 回调:** 它使用 `MockNghttp2Callbacks` 来模拟 `nghttp2` 库提供的回调接口，以便在测试环境中验证 `CallbackVisitor` 是否正确地调用了这些回调，并传递了正确的参数。
3. **测试不同类型的 HTTP/2 帧:**  测试覆盖了多种 HTTP/2 帧类型，例如 `SETTINGS`, `PING`, `GOAWAY`, `HEADERS`, `DATA`, `RST_STREAM`, `WINDOW_UPDATE`, `CONTINUATION` 等。
4. **测试客户端和服务端视角:** 测试区分了客户端和服务端两种视角，因为 `CallbackVisitor` 在这两种场景下的行为可能略有不同。
5. **测试连接级别的事件:**  例如 `SETTINGS`, `PING`, `GOAWAY`, `WINDOW_UPDATE` 等影响整个 HTTP/2 连接的帧。
6. **测试流级别的事件:** 例如 `HEADERS`, `DATA`, `RST_STREAM` 等与特定 HTTP 流相关的帧。
7. **测试头部延续帧 (`CONTINUATION`):** 验证 `CallbackVisitor` 是否正确处理需要多个 `CONTINUATION` 帧才能完整接收的头部信息。
8. **测试流的生命周期管理:**  验证 `CallbackVisitor` 如何跟踪和管理 HTTP/2 流的创建、关闭等状态。
9. **测试错误处理:**  例如，测试接收到无效的帧序列或者在处理回调时发生错误的情况。
10. **测试数据帧的填充 (`PADDING`):**  验证 `CallbackVisitor` 对带有填充的数据帧的处理。
11. **测试内容长度不匹配的情况:** 模拟服务端接收到的数据长度与 `Content-Length` 头部不一致的情况，并验证回调行为。
12. **测试在流结束后收到头部的情况:** 验证 `CallbackVisitor` 如何处理在流已经结束 (`FIN` 标志) 后又收到的 `HEADERS` 帧。

**与 JavaScript 功能的关系：**

该文件中的代码是 C++，直接与 JavaScript 没有关联。然而，它所测试的 `CallbackVisitor` 类是 Chromium 网络栈的一部分，负责处理底层的 HTTP/2 协议。当浏览器中的 JavaScript 代码发起 HTTP/2 请求时，Chromium 的网络栈会处理这些请求和响应。`CallbackVisitor` 在这个过程中扮演着重要的角色，将底层的 HTTP/2 事件传递给上层代码。

**举例说明：**

假设一个 JavaScript 代码发起一个 HTTP/2 GET 请求，并且服务器返回一个带有头部和数据的主体。

1. **服务器发送 HEADERS 帧:**  服务器会发送一个包含响应头部的 `HEADERS` 帧。
2. **CallbackVisitor 处理 HEADERS 帧:**  Chromium 的网络栈接收到这个 `HEADERS` 帧后，会调用 `CallbackVisitor` 的 `OnFrameHeader` 和 `OnBeginHeadersForStream` 方法。
3. **CallbackVisitor 通知 nghttp2 回调:**  `CallbackVisitor` 会调用模拟的 `MockNghttp2Callbacks` 的 `OnBeginHeaders` 方法，并将流 ID 和头部信息传递过去。
4. **服务器发送 DATA 帧:**  服务器随后发送包含响应主体数据的 `DATA` 帧。
5. **CallbackVisitor 处理 DATA 帧:**  Chromium 的网络栈接收到 `DATA` 帧后，会调用 `CallbackVisitor` 的 `OnFrameHeader` 和 `OnDataForStream` 方法。
6. **CallbackVisitor 通知 nghttp2 回调:**  `CallbackVisitor` 会调用模拟的 `MockNghttp2Callbacks` 的 `OnDataChunkRecv` 方法，并将数据传递过去。
7. **Chromium 将数据传递给 JavaScript:**  Chromium 的上层网络代码会接收到来自 `CallbackVisitor` 的通知，并将响应头部和数据传递给浏览器的渲染引擎和 JavaScript 环境。

最终，JavaScript 代码可以通过 `fetch` 或 `XMLHttpRequest` 等 API 接收到服务器返回的响应。`CallbackVisitor` 在这个过程中负责底层的 HTTP/2 协议处理。

**逻辑推理 (假设输入与输出):**

**假设输入:** 收到一个 `HEADERS` 帧，流 ID 为 1，包含头部 `:status: 200` 和 `content-type: text/html`。

**模拟 `visitor.OnFrameHeader` 调用:**
```c++
visitor.OnFrameHeader(1, /*length*/ some_length, HEADERS, /*flags*/ 4);
```

**模拟 `visitor.OnBeginHeadersForStream` 调用:**
```c++
visitor.OnBeginHeadersForStream(1);
```

**模拟 `visitor.OnHeaderForStream` 调用 (假设顺序接收到头部):**
```c++
visitor.OnHeaderForStream(1, ":status", "200");
visitor.OnHeaderForStream(1, "content-type", "text/html");
```

**模拟 `visitor.OnEndHeadersForStream` 调用:**
```c++
visitor.OnEndHeadersForStream(1);
```

**预期输出 (通过 `MockNghttp2Callbacks` 的 `EXPECT_CALL` 验证):**

```c++
EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, HEADERS, _)));
EXPECT_CALL(callbacks, OnBeginHeaders(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
EXPECT_CALL(callbacks, OnHeader(_, ":status", "200", _));
EXPECT_CALL(callbacks, OnHeader(_, "content-type", "text/html", _));
EXPECT_CALL(callbacks, OnFrameRecv(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
```

**用户或编程常见的使用错误 (及其测试用例):**

1. **错误：在没有收到 `HEADERS` 帧的情况下收到 `CONTINUATION` 帧。**
   - **测试用例：** `ClientCallbackVisitorUnitTest.ContinuationNoHeaders`
   - **说明：** 用户或程序员可能会错误地构建 HTTP/2 帧序列，导致 `CONTINUATION` 帧在没有关联的 `HEADERS` 帧之前到达。`CallbackVisitor` 应该能够检测到这种情况并采取适当的措施（例如，关闭连接或流）。

2. **错误：`CONTINUATION` 帧的流 ID 与之前的 `HEADERS` 帧不匹配。**
   - **测试用例：** `ClientCallbackVisitorUnitTest.ContinuationWrongStream`
   - **说明：**  当头部信息跨越多个 `CONTINUATION` 帧时，所有帧的流 ID 必须保持一致。如果流 ID 不匹配，则表明帧序列错误。

3. **错误：在流已经关闭后发送 `HEADERS` 帧。**
   - **测试用例：** `ServerCallbackVisitorUnitTest.HeadersAfterFin`
   - **说明：**  一旦流被关闭（发送了带有 `END_STREAM` 标志的帧或收到了 `RST_STREAM` 帧），就不应该再向该流发送新的帧。`CallbackVisitor` 应该能够识别这种情况。

4. **错误：发送的 `DATA` 帧的长度与 `Content-Length` 头部不匹配。**
   - **测试用例：** `ServerCallbackVisitorUnitTest.MismatchedContentLengthCallbacks`
   - **说明：** 当使用了 `Content-Length` 头部时，发送的数据量必须与头部指定的值一致。不匹配会导致错误。

**用户操作如何一步步的到达这里 (作为调试线索):**

假设用户在 Chrome 浏览器中访问一个 HTTPS 网站，并且该网站支持 HTTP/2。

1. **用户在地址栏输入网址并按下回车，或者点击一个链接。**
2. **Chrome 浏览器解析 URL 并确定需要建立 HTTPS 连接。**
3. **Chrome 的网络栈与服务器进行 TCP 握手和 TLS 握手。**
4. **在 TLS 握手期间，通过 ALPN (Application-Layer Protocol Negotiation) 协商使用 HTTP/2 协议。**
5. **Chrome 的 HTTP/2 实现 (基于 quiche 库) 发送 HTTP/2 连接前导 (connection preface)。**
6. **Chrome 的 HTTP/2 实现构造并发送 HTTP/2 `HEADERS` 帧来发起 HTTP 请求。**
7. **当服务器响应时，会发送 HTTP/2 帧 (例如 `SETTINGS`, `HEADERS`, `DATA`)。**
8. **Chromium 的网络栈接收到这些帧，并交给 `NgHttp2Adapter` 进行处理。**
9. **`NgHttp2Adapter` 解析收到的帧，并调用 `CallbackVisitor` 的相应方法，例如 `OnFrameHeader`, `OnBeginHeadersForStream`, `OnHeaderForStream`, `OnDataForStream` 等。**
10. **`CallbackVisitor` 将这些事件转发给实现了 `Nghttp2Callbacks` 接口的对象，这些对象负责处理上层的 HTTP/2 逻辑。**

**调试线索:**

当出现网络问题或者 HTTP/2 通信错误时，开发人员可能会关注以下几点，以便定位到 `CallbackVisitor` 的相关代码：

- **查看网络日志:**  Chromium 提供了 `net-internals` 工具 (`chrome://net-internals/`)，可以查看详细的网络请求和响应信息，包括 HTTP/2 帧的交互。
- **断点调试:** 在 Chromium 的网络栈代码中设置断点，例如在 `CallbackVisitor` 的 `OnFrameHeader` 或其他关键方法中，可以跟踪 HTTP/2 帧的接收和处理过程。
- **查看 quiche 库的日志:**  quiche 库本身也可能提供日志输出，可以帮助理解底层的 HTTP/2 处理过程。
- **分析崩溃堆栈:** 如果程序崩溃，崩溃堆栈信息可能会指向 `CallbackVisitor` 相关的代码。

总之，`callback_visitor_test.cc` 是一个至关重要的测试文件，它确保了 `CallbackVisitor` 类能够正确地处理各种 HTTP/2 事件，是保证 Chromium 网络栈 HTTP/2 功能稳定可靠的关键组成部分。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/callback_visitor_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/http2/adapter/callback_visitor.h"

#include <string>

#include "absl/container/flat_hash_map.h"
#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/mock_nghttp2_callbacks.h"
#include "quiche/http2/adapter/nghttp2_adapter.h"
#include "quiche/http2/adapter/nghttp2_test_utils.h"
#include "quiche/http2/adapter/test_frame_sequence.h"
#include "quiche/http2/adapter/test_utils.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using testing::_;
using testing::IsEmpty;
using testing::Pair;
using testing::UnorderedElementsAre;

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
  CONTINUATION,
};

// Tests connection-level events.
TEST(ClientCallbackVisitorUnitTest, ConnectionFrames) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kClient,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // SETTINGS
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, SETTINGS, _)));
  visitor.OnFrameHeader(0, 0, SETTINGS, 0);

  visitor.OnSettingsStart();
  EXPECT_CALL(callbacks, OnFrameRecv(IsSettings(testing::IsEmpty())));
  visitor.OnSettingsEnd();

  // PING
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, PING, _)));
  visitor.OnFrameHeader(0, 8, PING, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsPing(42)));
  visitor.OnPing(42, false);

  // WINDOW_UPDATE
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, WINDOW_UPDATE, _)));
  visitor.OnFrameHeader(0, 4, WINDOW_UPDATE, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsWindowUpdate(1000)));
  visitor.OnWindowUpdate(0, 1000);

  // PING ack
  EXPECT_CALL(callbacks,
              OnBeginFrame(HasFrameHeader(0, PING, NGHTTP2_FLAG_ACK)));
  visitor.OnFrameHeader(0, 8, PING, 1);

  EXPECT_CALL(callbacks, OnFrameRecv(IsPingAck(247)));
  visitor.OnPing(247, true);

  // GOAWAY
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, GOAWAY, 0)));
  visitor.OnFrameHeader(0, 19, GOAWAY, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsGoAway(5, NGHTTP2_ENHANCE_YOUR_CALM,
                                              "calm down!!")));
  visitor.OnGoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!");

  EXPECT_EQ(visitor.stream_map_size(), 0);
}

TEST(ClientCallbackVisitorUnitTest, StreamFrames) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kClient,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);
  absl::flat_hash_map<Http2StreamId, int> stream_close_counts;
  visitor.set_stream_close_listener(
      [&stream_close_counts](Http2StreamId stream_id) {
        ++stream_close_counts[stream_id];
      });

  testing::InSequence seq;

  EXPECT_EQ(visitor.stream_map_size(), 0);

  // HEADERS on stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, HEADERS, _)));
  visitor.OnFrameHeader(1, 23, HEADERS, 4);

  EXPECT_CALL(callbacks,
              OnBeginHeaders(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
  visitor.OnBeginHeadersForStream(1);

  EXPECT_EQ(visitor.stream_map_size(), 1);

  EXPECT_CALL(callbacks, OnHeader(_, ":status", "200", _));
  visitor.OnHeaderForStream(1, ":status", "200");

  EXPECT_CALL(callbacks, OnHeader(_, "server", "my-fake-server", _));
  visitor.OnHeaderForStream(1, "server", "my-fake-server");

  EXPECT_CALL(callbacks,
              OnHeader(_, "date", "Tue, 6 Apr 2021 12:54:01 GMT", _));
  visitor.OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT");

  EXPECT_CALL(callbacks, OnHeader(_, "trailer", "x-server-status", _));
  visitor.OnHeaderForStream(1, "trailer", "x-server-status");

  EXPECT_CALL(callbacks, OnFrameRecv(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
  visitor.OnEndHeadersForStream(1);

  // DATA for stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, DATA, 0)));
  visitor.OnFrameHeader(1, 26, DATA, 0);

  visitor.OnBeginDataForStream(1, 26);
  EXPECT_CALL(callbacks, OnDataChunkRecv(0, 1, "This is the response body."));
  EXPECT_CALL(callbacks, OnFrameRecv(IsData(1, _, 0)));
  visitor.OnDataForStream(1, "This is the response body.");

  // Trailers for stream 1, with a different nghttp2 "category".
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, HEADERS, _)));
  visitor.OnFrameHeader(1, 23, HEADERS, 4);

  EXPECT_CALL(callbacks, OnBeginHeaders(IsHeaders(1, _, NGHTTP2_HCAT_HEADERS)));
  visitor.OnBeginHeadersForStream(1);

  EXPECT_CALL(callbacks, OnHeader(_, "x-server-status", "OK", _));
  visitor.OnHeaderForStream(1, "x-server-status", "OK");

  EXPECT_CALL(callbacks, OnFrameRecv(IsHeaders(1, _, NGHTTP2_HCAT_HEADERS)));
  visitor.OnEndHeadersForStream(1);

  EXPECT_THAT(stream_close_counts, IsEmpty());

  // RST_STREAM on stream 3
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(3, RST_STREAM, 0)));
  visitor.OnFrameHeader(3, 4, RST_STREAM, 0);

  // No change in stream map size.
  EXPECT_EQ(visitor.stream_map_size(), 1);
  EXPECT_THAT(stream_close_counts, IsEmpty());

  EXPECT_CALL(callbacks, OnFrameRecv(IsRstStream(3, NGHTTP2_INTERNAL_ERROR)));
  visitor.OnRstStream(3, Http2ErrorCode::INTERNAL_ERROR);

  EXPECT_CALL(callbacks, OnStreamClose(3, NGHTTP2_INTERNAL_ERROR));
  visitor.OnCloseStream(3, Http2ErrorCode::INTERNAL_ERROR);

  EXPECT_THAT(stream_close_counts, UnorderedElementsAre(Pair(3, 1)));

  // More stream close events
  EXPECT_CALL(callbacks,
              OnBeginFrame(HasFrameHeader(1, DATA, NGHTTP2_FLAG_END_STREAM)));
  visitor.OnFrameHeader(1, 0, DATA, 1);

  EXPECT_CALL(callbacks, OnFrameRecv(IsData(1, _, NGHTTP2_FLAG_END_STREAM)));
  visitor.OnBeginDataForStream(1, 0);
  EXPECT_TRUE(visitor.OnEndStream(1));

  EXPECT_CALL(callbacks, OnStreamClose(1, NGHTTP2_NO_ERROR));
  visitor.OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR);

  // Stream map is empty again after both streams were closed.
  EXPECT_EQ(visitor.stream_map_size(), 0);
  EXPECT_THAT(stream_close_counts,
              UnorderedElementsAre(Pair(3, 1), Pair(1, 1)));

  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(5, RST_STREAM, _)));
  visitor.OnFrameHeader(5, 4, RST_STREAM, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsRstStream(5, NGHTTP2_REFUSED_STREAM)));
  visitor.OnRstStream(5, Http2ErrorCode::REFUSED_STREAM);

  EXPECT_CALL(callbacks, OnStreamClose(5, NGHTTP2_REFUSED_STREAM));
  visitor.OnCloseStream(5, Http2ErrorCode::REFUSED_STREAM);

  EXPECT_EQ(visitor.stream_map_size(), 0);
  EXPECT_THAT(stream_close_counts,
              UnorderedElementsAre(Pair(3, 1), Pair(1, 1), Pair(5, 1)));
}

TEST(ClientCallbackVisitorUnitTest, HeadersWithContinuation) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kClient,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // HEADERS on stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, HEADERS, 0x0)));
  ASSERT_TRUE(visitor.OnFrameHeader(1, 23, HEADERS, 0x0));

  EXPECT_CALL(callbacks,
              OnBeginHeaders(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
  visitor.OnBeginHeadersForStream(1);

  EXPECT_CALL(callbacks, OnHeader(_, ":status", "200", _));
  visitor.OnHeaderForStream(1, ":status", "200");

  EXPECT_CALL(callbacks, OnHeader(_, "server", "my-fake-server", _));
  visitor.OnHeaderForStream(1, "server", "my-fake-server");

  EXPECT_CALL(callbacks,
              OnBeginFrame(HasFrameHeader(1, CONTINUATION, END_HEADERS_FLAG)));
  ASSERT_TRUE(visitor.OnFrameHeader(1, 23, CONTINUATION, END_HEADERS_FLAG));

  EXPECT_CALL(callbacks,
              OnHeader(_, "date", "Tue, 6 Apr 2021 12:54:01 GMT", _));
  visitor.OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT");

  EXPECT_CALL(callbacks, OnHeader(_, "trailer", "x-server-status", _));
  visitor.OnHeaderForStream(1, "trailer", "x-server-status");

  EXPECT_CALL(callbacks, OnFrameRecv(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
  visitor.OnEndHeadersForStream(1);
}

TEST(ClientCallbackVisitorUnitTest, ContinuationNoHeaders) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kClient,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);
  // Because no stream precedes the CONTINUATION frame, the stream ID does not
  // match, and the method returns false.
  EXPECT_FALSE(visitor.OnFrameHeader(1, 23, CONTINUATION, END_HEADERS_FLAG));
}

TEST(ClientCallbackVisitorUnitTest, ContinuationWrongPrecedingType) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kClient,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, WINDOW_UPDATE, _)));
  visitor.OnFrameHeader(1, 4, WINDOW_UPDATE, 0);

  // Because the CONTINUATION frame does not follow HEADERS, the method returns
  // false.
  EXPECT_FALSE(visitor.OnFrameHeader(1, 23, CONTINUATION, END_HEADERS_FLAG));
}

TEST(ClientCallbackVisitorUnitTest, ContinuationWrongStream) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kClient,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);
  // HEADERS on stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, HEADERS, 0x0)));
  ASSERT_TRUE(visitor.OnFrameHeader(1, 23, HEADERS, 0x0));

  EXPECT_CALL(callbacks,
              OnBeginHeaders(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
  visitor.OnBeginHeadersForStream(1);

  EXPECT_CALL(callbacks, OnHeader(_, ":status", "200", _));
  visitor.OnHeaderForStream(1, ":status", "200");

  EXPECT_CALL(callbacks, OnHeader(_, "server", "my-fake-server", _));
  visitor.OnHeaderForStream(1, "server", "my-fake-server");

  // The CONTINUATION stream ID does not match the one from the HEADERS.
  EXPECT_FALSE(visitor.OnFrameHeader(3, 23, CONTINUATION, END_HEADERS_FLAG));
}

TEST(ClientCallbackVisitorUnitTest, ResetAndGoaway) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kClient,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // RST_STREAM on stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, RST_STREAM, 0x0)));
  EXPECT_TRUE(visitor.OnFrameHeader(1, 13, RST_STREAM, 0x0));

  EXPECT_CALL(callbacks, OnFrameRecv(IsRstStream(1, NGHTTP2_INTERNAL_ERROR)));
  visitor.OnRstStream(1, Http2ErrorCode::INTERNAL_ERROR);

  EXPECT_CALL(callbacks, OnStreamClose(1, NGHTTP2_INTERNAL_ERROR));
  EXPECT_TRUE(visitor.OnCloseStream(1, Http2ErrorCode::INTERNAL_ERROR));

  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, GOAWAY, 0x0)));
  EXPECT_TRUE(visitor.OnFrameHeader(0, 13, GOAWAY, 0x0));

  EXPECT_CALL(callbacks,
              OnFrameRecv(IsGoAway(3, NGHTTP2_ENHANCE_YOUR_CALM, "calma te")));
  EXPECT_TRUE(
      visitor.OnGoAway(3, Http2ErrorCode::ENHANCE_YOUR_CALM, "calma te"));

  EXPECT_CALL(callbacks, OnStreamClose(5, NGHTTP2_STREAM_CLOSED))
      .WillOnce(testing::Return(NGHTTP2_ERR_CALLBACK_FAILURE));
  EXPECT_FALSE(visitor.OnCloseStream(5, Http2ErrorCode::STREAM_CLOSED));
}

TEST(ServerCallbackVisitorUnitTest, ConnectionFrames) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kServer,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // SETTINGS
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, SETTINGS, _)));
  visitor.OnFrameHeader(0, 0, SETTINGS, 0);

  visitor.OnSettingsStart();
  EXPECT_CALL(callbacks, OnFrameRecv(IsSettings(testing::IsEmpty())));
  visitor.OnSettingsEnd();

  // PING
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, PING, _)));
  visitor.OnFrameHeader(0, 8, PING, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsPing(42)));
  visitor.OnPing(42, false);

  // WINDOW_UPDATE
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, WINDOW_UPDATE, _)));
  visitor.OnFrameHeader(0, 4, WINDOW_UPDATE, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsWindowUpdate(1000)));
  visitor.OnWindowUpdate(0, 1000);

  // PING ack
  EXPECT_CALL(callbacks,
              OnBeginFrame(HasFrameHeader(0, PING, NGHTTP2_FLAG_ACK)));
  visitor.OnFrameHeader(0, 8, PING, 1);

  EXPECT_CALL(callbacks, OnFrameRecv(IsPingAck(247)));
  visitor.OnPing(247, true);

  EXPECT_EQ(visitor.stream_map_size(), 0);
}

TEST(ServerCallbackVisitorUnitTest, StreamFrames) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kServer,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // HEADERS on stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(
                             1, HEADERS, NGHTTP2_FLAG_END_HEADERS)));
  visitor.OnFrameHeader(1, 23, HEADERS, 4);

  EXPECT_CALL(callbacks, OnBeginHeaders(IsHeaders(1, NGHTTP2_FLAG_END_HEADERS,
                                                  NGHTTP2_HCAT_REQUEST)));
  visitor.OnBeginHeadersForStream(1);

  EXPECT_EQ(visitor.stream_map_size(), 1);

  EXPECT_CALL(callbacks, OnHeader(_, ":method", "POST", _));
  visitor.OnHeaderForStream(1, ":method", "POST");

  EXPECT_CALL(callbacks, OnHeader(_, ":path", "/example/path", _));
  visitor.OnHeaderForStream(1, ":path", "/example/path");

  EXPECT_CALL(callbacks, OnHeader(_, ":scheme", "https", _));
  visitor.OnHeaderForStream(1, ":scheme", "https");

  EXPECT_CALL(callbacks, OnHeader(_, ":authority", "example.com", _));
  visitor.OnHeaderForStream(1, ":authority", "example.com");

  EXPECT_CALL(callbacks, OnHeader(_, "accept", "text/html", _));
  visitor.OnHeaderForStream(1, "accept", "text/html");

  EXPECT_CALL(callbacks, OnFrameRecv(IsHeaders(1, NGHTTP2_FLAG_END_HEADERS,
                                               NGHTTP2_HCAT_REQUEST)));
  visitor.OnEndHeadersForStream(1);

  // DATA on stream 1
  EXPECT_CALL(callbacks,
              OnBeginFrame(HasFrameHeader(1, DATA, NGHTTP2_FLAG_END_STREAM)));
  visitor.OnFrameHeader(1, 25, DATA, NGHTTP2_FLAG_END_STREAM);

  visitor.OnBeginDataForStream(1, 25);
  EXPECT_CALL(callbacks, OnDataChunkRecv(NGHTTP2_FLAG_END_STREAM, 1,
                                         "This is the request body."));
  EXPECT_CALL(callbacks, OnFrameRecv(IsData(1, _, NGHTTP2_FLAG_END_STREAM)));
  visitor.OnDataForStream(1, "This is the request body.");
  EXPECT_TRUE(visitor.OnEndStream(1));

  EXPECT_CALL(callbacks, OnStreamClose(1, NGHTTP2_NO_ERROR));
  visitor.OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR);

  EXPECT_EQ(visitor.stream_map_size(), 0);

  // RST_STREAM on stream 3
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(3, RST_STREAM, 0)));
  visitor.OnFrameHeader(3, 4, RST_STREAM, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsRstStream(3, NGHTTP2_INTERNAL_ERROR)));
  visitor.OnRstStream(3, Http2ErrorCode::INTERNAL_ERROR);

  EXPECT_CALL(callbacks, OnStreamClose(3, NGHTTP2_INTERNAL_ERROR));
  visitor.OnCloseStream(3, Http2ErrorCode::INTERNAL_ERROR);

  EXPECT_EQ(visitor.stream_map_size(), 0);
}

TEST(ServerCallbackVisitorUnitTest, DataWithPadding) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kServer,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  const size_t kPaddingLength = 39;
  const uint8_t kFlags = NGHTTP2_FLAG_PADDED | NGHTTP2_FLAG_END_STREAM;

  testing::InSequence seq;

  // DATA on stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, DATA, kFlags)));
  EXPECT_TRUE(visitor.OnFrameHeader(1, 25 + kPaddingLength, DATA, kFlags));

  EXPECT_TRUE(visitor.OnBeginDataForStream(1, 25 + kPaddingLength));

  // Padding before data.
  EXPECT_TRUE(visitor.OnDataPaddingLength(1, kPaddingLength));

  EXPECT_CALL(callbacks,
              OnDataChunkRecv(kFlags, 1, "This is the request body."));
  EXPECT_CALL(callbacks, OnFrameRecv(IsData(1, _, kFlags, kPaddingLength)));
  EXPECT_TRUE(visitor.OnDataForStream(1, "This is the request body."));
  EXPECT_TRUE(visitor.OnEndStream(1));

  EXPECT_CALL(callbacks, OnStreamClose(1, NGHTTP2_NO_ERROR));
  visitor.OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR);

  // DATA on stream 3
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(3, DATA, kFlags)));
  EXPECT_TRUE(visitor.OnFrameHeader(3, 25 + kPaddingLength, DATA, kFlags));

  EXPECT_TRUE(visitor.OnBeginDataForStream(3, 25 + kPaddingLength));

  // Data before padding.
  EXPECT_CALL(callbacks,
              OnDataChunkRecv(kFlags, 3, "This is the request body."));
  EXPECT_TRUE(visitor.OnDataForStream(3, "This is the request body."));

  EXPECT_CALL(callbacks, OnFrameRecv(IsData(3, _, kFlags, kPaddingLength)));
  EXPECT_TRUE(visitor.OnDataPaddingLength(3, kPaddingLength));
  EXPECT_TRUE(visitor.OnEndStream(3));

  EXPECT_CALL(callbacks, OnStreamClose(3, NGHTTP2_NO_ERROR));
  visitor.OnCloseStream(3, Http2ErrorCode::HTTP2_NO_ERROR);

  // DATA on stream 5
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(5, DATA, kFlags)));
  EXPECT_TRUE(visitor.OnFrameHeader(5, 25 + kPaddingLength, DATA, kFlags));

  EXPECT_TRUE(visitor.OnBeginDataForStream(5, 25 + kPaddingLength));

  // Error during padding.
  EXPECT_CALL(callbacks,
              OnDataChunkRecv(kFlags, 5, "This is the request body."));
  EXPECT_TRUE(visitor.OnDataForStream(5, "This is the request body."));

  EXPECT_CALL(callbacks, OnFrameRecv(IsData(5, _, kFlags, kPaddingLength)))
      .WillOnce(testing::Return(NGHTTP2_ERR_CALLBACK_FAILURE));
  EXPECT_TRUE(visitor.OnDataPaddingLength(5, kPaddingLength));
  EXPECT_FALSE(visitor.OnEndStream(3));

  EXPECT_CALL(callbacks, OnStreamClose(5, NGHTTP2_NO_ERROR));
  visitor.OnCloseStream(5, Http2ErrorCode::HTTP2_NO_ERROR);
}

// In the case of a Content-Length mismatch where the header value is larger
// than the actual data for the stream, nghttp2 will call
// `on_begin_frame_callback` and `on_data_chunk_recv_callback`, but not the
// `on_frame_recv_callback`.
TEST(ServerCallbackVisitorUnitTest, MismatchedContentLengthCallbacks) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kServer,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);
  auto adapter = NgHttp2Adapter::CreateServerAdapter(visitor);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"},
                                           {"content-length", "50"}},
                                          /*fin=*/false)
                                 .Data(1, "Less than 50 bytes.", true)
                                 .Serialize();

  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, SETTINGS, _)));

  EXPECT_CALL(callbacks, OnFrameRecv(IsSettings(testing::IsEmpty())));

  // HEADERS on stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(
                             1, HEADERS, NGHTTP2_FLAG_END_HEADERS)));

  EXPECT_CALL(callbacks, OnBeginHeaders(IsHeaders(1, NGHTTP2_FLAG_END_HEADERS,
                                                  NGHTTP2_HCAT_REQUEST)));

  EXPECT_CALL(callbacks, OnHeader(_, ":method", "POST", _));
  EXPECT_CALL(callbacks, OnHeader(_, ":path", "/", _));
  EXPECT_CALL(callbacks, OnHeader(_, ":scheme", "https", _));
  EXPECT_CALL(callbacks, OnHeader(_, ":authority", "example.com", _));
  EXPECT_CALL(callbacks, OnHeader(_, "content-length", "50", _));
  EXPECT_CALL(callbacks, OnFrameRecv(IsHeaders(1, NGHTTP2_FLAG_END_HEADERS,
                                               NGHTTP2_HCAT_REQUEST)));

  // DATA on stream 1
  EXPECT_CALL(callbacks,
              OnBeginFrame(HasFrameHeader(1, DATA, NGHTTP2_FLAG_END_STREAM)));

  EXPECT_CALL(callbacks, OnDataChunkRecv(NGHTTP2_FLAG_END_STREAM, 1,
                                         "Less than 50 bytes."));

  // Like nghttp2, CallbackVisitor does not pass on a call to OnFrameRecv in the
  // case of Content-Length mismatch.

  int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);
}

TEST(ServerCallbackVisitorUnitTest, HeadersAfterFin) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kServer,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // HEADERS on stream 1
  EXPECT_CALL(
      callbacks,
      OnBeginFrame(HasFrameHeader(
          1, HEADERS, NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM)));
  visitor.OnFrameHeader(1, 23, HEADERS, 5);

  EXPECT_CALL(callbacks,
              OnBeginHeaders(IsHeaders(
                  1, NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM,
                  NGHTTP2_HCAT_REQUEST)));
  EXPECT_TRUE(visitor.OnBeginHeadersForStream(1));

  EXPECT_EQ(visitor.stream_map_size(), 1);

  EXPECT_CALL(callbacks, OnHeader).Times(5);
  visitor.OnHeaderForStream(1, ":method", "POST");
  visitor.OnHeaderForStream(1, ":path", "/example/path");
  visitor.OnHeaderForStream(1, ":scheme", "https");
  visitor.OnHeaderForStream(1, ":authority", "example.com");
  visitor.OnHeaderForStream(1, "accept", "text/html");

  EXPECT_CALL(callbacks,
              OnFrameRecv(IsHeaders(
                  1, NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM,
                  NGHTTP2_HCAT_REQUEST)));
  visitor.OnEndHeadersForStream(1);

  EXPECT_TRUE(visitor.OnEndStream(1));

  EXPECT_CALL(callbacks, OnStreamClose(1, NGHTTP2_NO_ERROR));
  visitor.OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR);

  EXPECT_EQ(visitor.stream_map_size(), 0);

  // Invalid repeat HEADERS on closed stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(
                             1, HEADERS, NGHTTP2_FLAG_END_HEADERS)));
  visitor.OnFrameHeader(1, 23, HEADERS, 4);

  EXPECT_CALL(callbacks, OnBeginHeaders(IsHeaders(1, NGHTTP2_FLAG_END_HEADERS,
                                                  NGHTTP2_HCAT_HEADERS)));
  EXPECT_TRUE(visitor.OnBeginHeadersForStream(1));

  // The visitor should not revive streams that have already been closed.
  EXPECT_EQ(visitor.stream_map_size(), 0);
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
```