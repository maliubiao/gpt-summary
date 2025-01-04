Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the file's functionality, its relationship to JavaScript (if any), logical reasoning examples, common usage errors, and debugging steps. Essentially, it's about understanding the purpose and context of this specific test file within the larger Chromium networking stack.

2. **Initial Scan and Keyword Identification:**  Read through the code, looking for important keywords and patterns:
    * `#include`:  Identifies dependencies. Notice `quiche/http2/adapter/...`, `quiche/common/...`, and standard C++ libraries. This immediately suggests it's related to HTTP/2 adaptation in the QUIC implementation.
    * `namespace http2::adapter::test`:  Confirms this is a test file within the HTTP/2 adapter component.
    * `TEST(OgHttp2AdapterTest, ...)` and `TEST_P(MetadataApiTest, ...)`:  Indicates this file contains unit tests using the Google Test framework. The names of the test cases (e.g., `ClientHandlesMetadata`, `ClientSendsMetadataAfterFlowControlBlock`) strongly suggest the core functionality being tested.
    * `OgHttp2Adapter`:  This is the central class being tested.
    * `TestVisitor`, `MockHttp2Visitor`:  These are mock objects used to simulate the behavior of the underlying HTTP/2 implementation and observe the adapter's interactions.
    * `SubmitRequest`, `SubmitResponse`, `SubmitMetadata`, `SubmitTrailer`: These are methods of the `OgHttp2Adapter` that are being exercised.
    * `OnBeforeFrameSent`, `OnFrameSent`, `OnFrameHeader`, `OnBeginHeadersForStream`, etc.: These are methods of the `Http2VisitorInterface` that the mock object is expected to be called on. These represent the adapter's interaction with the lower-level HTTP/2 handling.
    * `Metadata`: The repeated appearance of "Metadata" in test names and code clearly indicates a primary focus on handling HTTP/2 metadata frames.
    * `Serialize`, `EqualsFrames`: These utility functions from the test framework are used to construct and compare HTTP/2 frame sequences.
    * `Perspective::kClient`, `Perspective::kServer`:  Indicates tests for both client and server roles of the adapter.

3. **Identify Core Functionality:** Based on the test names and the interactions with the mock visitor, the primary function of this file is to test the `OgHttp2Adapter`'s ability to correctly handle HTTP/2 METADATA frames. This includes:
    * **Sending metadata:** From both client and server perspectives.
    * **Receiving metadata:** And correctly parsing it.
    * **Handling metadata in different scenarios:**  Empty payloads, errors during processing, interaction with flow control, and continuation frames.
    * **Interaction with other frame types:** Ensuring metadata doesn't disrupt the handling of HEADERS, DATA, and SETTINGS frames.
    * **Queuing and ordering:**  Verifying that metadata and trailers are sent in the correct order.

4. **JavaScript Relationship:**  Consider how HTTP/2 metadata relates to web development and JavaScript. HTTP headers are exposed to JavaScript through APIs like `fetch` and `XMLHttpRequest`. While this specific C++ code doesn't *directly* execute JavaScript, it's part of the browser's network stack that *enables* JavaScript to interact with HTTP/2 servers that send and receive metadata. The connection is indirect but crucial.

5. **Logical Reasoning Examples (Input/Output):** Select a simple test case and trace its execution:
    * Choose `ClientHandlesMetadata`.
    * **Input:** The client submits a request with headers. The server sends back a preface, connection metadata, headers, stream metadata, and data.
    * **Output:** The test expects a specific sequence of calls to the `TestVisitor`'s methods, confirming that the adapter correctly parses and interprets the incoming frames and generates the correct outgoing frames. The `EXPECT_CALL` statements define these expected interactions.

6. **Common Usage Errors:** Think about how a developer might misuse the `OgHttp2Adapter` or the related APIs:
    * **Incorrect metadata submission:** Submitting metadata for a non-existent stream, or submitting too much metadata before flow control allows.
    * **Visitor implementation errors:** The `Http2VisitorInterface` is a contract. A faulty implementation of the visitor could lead to crashes or incorrect behavior. The tests in this file help catch such errors in the adapter itself.
    * **Assuming immediate sending:**  Forgetting that `Send()` needs to be called to actually transmit data.

7. **Debugging Steps:**  Imagine a scenario where metadata isn't being handled correctly. How would a developer reach this code?
    * Start with a network request in the browser.
    * Examine network logs to see the raw HTTP/2 frames.
    * If metadata is involved, look for METADATA frames.
    * If there's an issue, a developer might step through the Chromium networking code, eventually reaching the `OgHttp2Adapter` and potentially these test files to understand how metadata processing *should* work. The test file serves as a reference and can be run in isolation to debug specific metadata handling scenarios.

8. **Structure the Answer:** Organize the findings into the requested categories: Functionality, JavaScript relationship, logical reasoning, usage errors, and debugging. Use clear and concise language, and provide specific examples from the code where relevant. Use formatting (like bullet points) to improve readability.

9. **Review and Refine:** Read through the answer to ensure accuracy, completeness, and clarity. Check for any logical inconsistencies or areas that could be explained better. For instance, explicitly mentioning the role of `kMetadataFrameType` enhances understanding.

This iterative process of scanning, identifying, connecting, and exemplifying allows for a comprehensive understanding of the test file's role and its context within the larger project.
这个C++文件 `oghttp2_adapter_metadata_test.cc` 是 Chromium 网络栈中 QUIC 库的一部分，专门用于测试 `OgHttp2Adapter` 类在处理 HTTP/2 **元数据 (Metadata)** 方面的功能。 `OgHttp2Adapter` 是一个将 Chromium 的 HTTP/2 实现 (spdy) 适配到通用 HTTP/2 适配器接口的类。

**主要功能:**

1. **测试客户端如何处理接收到的元数据帧:**  测试客户端在接收到服务器发送的元数据帧时的行为，包括连接级别的元数据和流级别的元数据。它验证了 `OgHttp2Adapter` 能否正确地解析和回调访问者 (visitor) 接口来处理这些元数据。
2. **测试客户端发送元数据帧的能力:**  测试客户端在发送请求后，能否根据需要发送元数据帧。这包括在流启动后、数据发送前或发送后发送元数据。
3. **测试服务器如何处理接收到的元数据帧:** 虽然文件中大部分测试是针对客户端的，但也有测试用例模拟服务器接收客户端发送的元数据帧。
4. **测试元数据帧的各种场景:**  包括带有有效负载的元数据帧、空负载的元数据帧、以及处理过程中发生错误的情况。
5. **测试元数据帧与流量控制的交互:**  测试在流量控制阻塞的情况下，元数据帧的发送是否受到影响，以及在流量控制解除后是否能正常发送。
6. **测试元数据帧和延续帧 (CONTINUATION) 的配合使用:**  测试当元数据负载较大，需要分割成多个帧发送时，`OgHttp2Adapter` 是否能正确处理。
7. **测试元数据和尾部 (Trailers) 的发送顺序:**  验证服务器在发送完主体数据后，能先发送元数据，再发送尾部。
8. **使用 Mock 对象进行隔离测试:**  使用 `MockHttp2Visitor` 模拟底层的 HTTP/2 处理逻辑，使得测试可以集中在 `OgHttp2Adapter` 的行为上。

**与 JavaScript 的关系:**

该 C++ 代码本身不包含 JavaScript 代码，但它所测试的功能直接影响到浏览器中 JavaScript 代码的网络行为。

**举例说明:**

假设一个网站使用了 HTTP/2 的元数据功能，在服务器响应中携带了一些额外的非标准的元数据，例如 `X-Custom-Debug-Info: some-value`。

1. **服务器发送元数据:**  服务器在发送 HTTP 响应头之后，但在响应体之前，发送一个包含 `X-Custom-Debug-Info: some-value` 的元数据帧。
2. **C++ 代码的作用:**  `oghttp2_adapter_metadata_test.cc` 中的测试用例 (例如 `ClientHandlesMetadata`) 确保 `OgHttp2Adapter` 能正确接收并解析这个元数据帧，并将其传递给 `Http2VisitorInterface` 的实现。
3. **JavaScript 的影响:**  虽然 JavaScript 无法直接访问 HTTP/2 的元数据帧 (目前标准的浏览器 API 并不直接暴露)，但这些元数据可以被底层的网络栈使用，例如用于调试、监控或进行一些性能优化。在未来，可能会有浏览器 API 允许 JavaScript 访问这些元数据。

**逻辑推理 (假设输入与输出):**

**假设输入:**  服务器发送以下 HTTP/2 帧序列：

```
HEADERS (stream_id=1)  // 响应头
:status: 200
content-type: text/plain

METADATA (stream_id=1) // 元数据帧
X-Custom-Info: debug

DATA (stream_id=1)     // 响应体
Hello, world!
```

**预期输出 (基于 `ClientHandlesMetadata` 测试用例):**

`TestVisitor` 模拟对象的预期回调顺序：

```
OnFrameHeader(1, _, HEADERS, 4)
OnBeginHeadersForStream(1)
OnHeaderForStream(1, ":status", "200")
OnHeaderForStream(1, "content-type", "text/plain")
OnEndHeadersForStream(1)
OnFrameHeader(1, _, kMetadataFrameType, 4)
OnBeginMetadataForStream(1, _)
OnMetadataForStream(1, "X-Custom-Info: debug") // 假设 metadata 以键值对形式回调
OnMetadataEndForStream(1)
OnFrameHeader(1, 13, DATA, 0)
OnBeginDataForStream(1, 13)
OnDataForStream(1, "Hello, world!")
```

**用户或编程常见的使用错误:**

1. **服务端未正确实现元数据发送:**  服务端可能没有按照 HTTP/2 规范发送元数据帧，例如帧头格式错误，或者在不应该发送元数据的时候发送。这会导致客户端的 `OgHttp2Adapter` 解析失败，可能触发连接错误。
   * **示例:** 服务端错误地将元数据帧的类型标识为 DATA 帧。客户端接收到后，会按照 DATA 帧处理，导致数据解析错误。测试用例 `ClientHandlesMetadataWithPayloadError` 和 `ClientHandlesMetadataWithCompletionError` 模拟了这种错误情况，并验证了 `OgHttp2Adapter` 能否正确处理并上报错误。
2. **客户端访问者 (visitor) 实现不正确:**  如果客户端的 `Http2VisitorInterface` 实现没有正确处理 `OnBeginMetadataForStream` 和 `OnMetadataForStream` 等回调，元数据信息可能会丢失或处理不当。
   * **示例:** 客户端的访问者在 `OnMetadataForStream` 回调中直接返回 `false`，表示处理失败。测试用例 `ClientHandlesMetadataWithPayloadError` 和 `ClientHandlesMetadataWithCompletionError` 验证了这种情况下的行为，`OgHttp2Adapter` 会终止处理后续的帧并发送 GOAWAY 帧。
3. **在不合适的时间发送元数据:**  虽然 HTTP/2 允许在 HEADERS 和 DATA 帧之间发送元数据，但过早或过晚发送可能会导致某些实现出现问题。测试用例通过各种帧序列来验证 `OgHttp2Adapter` 的鲁棒性。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器访问一个支持 HTTP/2 元数据的网站时遇到了问题，浏览器没有正确显示某些预期的信息。

1. **用户访问网站:** 用户在 Chrome 浏览器的地址栏输入网址并回车。
2. **浏览器发起 HTTP/2 连接:** Chrome 的网络栈会尝试与服务器建立 HTTP/2 连接。
3. **服务器发送包含元数据的响应:** 服务器在响应中包含了元数据帧。
4. **Chrome 网络栈接收并处理帧:**  接收到的 HTTP/2 帧会经过 Chromium 的网络栈处理，其中就包括 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter.cc` 中的 `OgHttp2Adapter` 类。
5. **`OgHttp2Adapter` 处理元数据帧:**  当接收到元数据帧时，`OgHttp2Adapter` 会调用其内部的逻辑来解析这个帧，并回调事先注册的 `Http2VisitorInterface` 的实现。
6. **如果出现问题:**  如果在元数据处理的任何阶段出现错误 (例如，帧格式错误、访问者实现错误)，开发者可能会需要调试 `OgHttp2Adapter` 的代码。
7. **调试线索:** 开发者可以使用以下步骤进行调试：
   * **查看网络日志:**  使用 Chrome 的 `chrome://net-export/` 功能导出网络日志，查看接收到的原始 HTTP/2 帧，确认是否存在元数据帧以及其内容是否正确。
   * **断点调试:**  在 `OgHttp2Adapter::ProcessBytes` 函数以及与元数据处理相关的回调函数中设置断点，例如 `OnFrameHeader`，`OnBeginMetadataForStream`，`OnMetadataForStream`，观察代码的执行流程和变量的值。
   * **查看 `oghttp2_adapter_metadata_test.cc`:**  阅读这个测试文件，了解 `OgHttp2Adapter` 在处理元数据时的预期行为。可以尝试运行相关的测试用例，看看是否能复现问题，或者修改测试用例来模拟出错的情况。
   * **检查 `Http2VisitorInterface` 的实现:**  确认 Chrome 内部实现的 `Http2VisitorInterface` 是否正确处理了元数据的回调。

总而言之，`oghttp2_adapter_metadata_test.cc` 是确保 Chromium 的 HTTP/2 适配器能正确处理元数据的关键组成部分，它通过大量的测试用例覆盖了各种场景，帮助开发者发现和修复与元数据处理相关的 Bug，从而保证用户能够正常体验使用 HTTP/2 元数据功能的网站。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_metadata_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_join.h"
#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/http2_visitor_interface.h"
#include "quiche/http2/adapter/mock_http2_visitor.h"
#include "quiche/http2/adapter/oghttp2_adapter.h"
#include "quiche/http2/adapter/oghttp2_util.h"
#include "quiche/http2/adapter/test_frame_sequence.h"
#include "quiche/http2/adapter/test_utils.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using ConnectionError = Http2VisitorInterface::ConnectionError;

using spdy::SpdyFrameType;
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
  CONTINUATION,
};

TEST(OgHttp2AdapterTest, ClientHandlesMetadata) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const int32_t stream_id1 = adapter->SubmitRequest(
      headers1, nullptr, true, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Metadata(0, "Example connection metadata")
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Metadata(1, "Example stream metadata")
          .Data(1, "This is the response body.", true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(0));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 26, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterTest, ClientHandlesMetadataWithEmptyPayload) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id =
      adapter->SubmitRequest(headers1, nullptr, true, nullptr);
  ASSERT_GT(stream_id, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Metadata(1, "")
          .Data(1, "This is the response body.", true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(3);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));
}

TEST(OgHttp2AdapterTest, ClientHandlesMetadataWithPayloadError) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  ASSERT_GT(stream_id, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Metadata(0, "Example connection metadata")
          .Headers(stream_id,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Metadata(stream_id, "Example stream metadata")
          .Data(stream_id, "This is the response body.", true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(0));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, _, _)).Times(3);
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(stream_id, _));
  EXPECT_CALL(visitor, OnMetadataForStream(stream_id, _))
      .WillOnce(testing::Return(false));
  // Remaining frames are not processed due to the error.
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  // Negative integer returned to indicate an error.
  EXPECT_LT(stream_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  EXPECT_FALSE(adapter->want_read());
  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterTest, ClientHandlesMetadataWithCompletionError) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id =
      adapter->SubmitRequest(headers, nullptr, true, nullptr);
  ASSERT_GT(stream_id, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Metadata(0, "Example connection metadata")
          .Headers(stream_id,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Metadata(stream_id, "Example stream metadata")
          .Data(stream_id, "This is the response body.", true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(0));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, _, _)).Times(3);
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(stream_id, _));
  EXPECT_CALL(visitor, OnMetadataForStream(stream_id, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(stream_id))
      .WillOnce(testing::Return(false));
  // Remaining frames are not processed due to the error.
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  // Negative integer returned to indicate an error.
  EXPECT_LT(stream_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  EXPECT_FALSE(adapter->want_read());
  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::GOAWAY}));
}

class MetadataApiTest : public quiche::test::QuicheTestWithParam<bool> {};

INSTANTIATE_TEST_SUITE_P(WithAndWithoutNewApi, MetadataApiTest,
                         testing::Bool());

TEST_P(MetadataApiTest, ClientSendsMetadataAfterFlowControlBlock) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const std::string kBody = std::string(100 * 1024, 'a');
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, false);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);

  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, std::move(body1), false, nullptr);
  ASSERT_EQ(stream_id1, 1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x4, 0));
  // 4 DATA frames should saturate the default 64kB stream/connection flow
  // control window.
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id1, _, 0x0, 0)).Times(4);

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_FALSE(adapter->want_write());
  EXPECT_EQ(0, adapter->GetSendWindowSize());

  const quiche::HttpHeaderBlock block = ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(stream_id1, block);
    adapter->SubmitMetadata(stream_id1, 1);
  } else {
    auto source = std::make_unique<TestMetadataSource>(block);
    adapter->SubmitMetadata(1, 16384u, std::move(source));
  }
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
}

TEST(OgHttp2AdapterTest, ClientSendsMetadataWithContinuation) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Metadata(0, "Example connection metadata in multiple frames", true)
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/false,
                   /*add_continuation=*/true)
          .Metadata(1,
                    "Some stream metadata that's also sent in multiple frames",
                    true)
          .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Metadata on stream 0
  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 0));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(0));

  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, CONTINUATION, 4));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  // Metadata on stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 0));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
  EXPECT_EQ("Example connection metadata in multiple frames",
            absl::StrJoin(visitor.GetMetadata(0), ""));
  EXPECT_EQ("Some stream metadata that's also sent in multiple frames",
            absl::StrJoin(visitor.GetMetadata(1), ""));
}

TEST_P(MetadataApiTest, SubmitMetadata) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const quiche::HttpHeaderBlock block = ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(1, block);
    adapter->SubmitMetadata(1, 1);
  } else {
    auto source = std::make_unique<TestMetadataSource>(block);
    adapter->SubmitMetadata(1, 16384u, std::move(source));
  }
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS,
                            static_cast<SpdyFrameType>(kMetadataFrameType)}));
  EXPECT_FALSE(adapter->want_write());
}

size_t DivRoundUp(size_t numerator, size_t denominator) {
  return numerator / denominator + (numerator % denominator == 0 ? 0 : 1);
}

TEST_P(MetadataApiTest, SubmitMetadataMultipleFrames) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const auto kLargeValue = std::string(63 * 1024, 'a');
  const quiche::HttpHeaderBlock block =
      ToHeaderBlock(ToHeaders({{"large-value", kLargeValue}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(1, block);
    adapter->SubmitMetadata(1, DivRoundUp(kLargeValue.size(), 16384u));
  } else {
    auto source = std::make_unique<TestMetadataSource>(block);
    adapter->SubmitMetadata(1, 16384u, std::move(source));
  }
  EXPECT_TRUE(adapter->want_write());

  testing::InSequence seq;
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS,
                            static_cast<SpdyFrameType>(kMetadataFrameType),
                            static_cast<SpdyFrameType>(kMetadataFrameType),
                            static_cast<SpdyFrameType>(kMetadataFrameType),
                            static_cast<SpdyFrameType>(kMetadataFrameType)}));
  EXPECT_FALSE(adapter->want_write());
}

TEST_P(MetadataApiTest, SubmitConnectionMetadata) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const quiche::HttpHeaderBlock block = ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(0, block);
    adapter->SubmitMetadata(0, 1);
  } else {
    auto source = std::make_unique<TestMetadataSource>(block);
    adapter->SubmitMetadata(0, 16384u, std::move(source));
  }
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 0, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 0, _, 0x4, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS,
                            static_cast<SpdyFrameType>(kMetadataFrameType)}));
  EXPECT_FALSE(adapter->want_write());
}

TEST_P(MetadataApiTest, ServerQueuesMetadataThenTrailers) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  const absl::string_view kBody = "This is an example response body.";

  // The body source must indicate that the end of the body is not the end of
  // the stream.
  visitor.AppendPayloadForStream(1, kBody);
  visitor.SetEndData(1, false);
  auto body1 = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result = adapter->SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      std::move(body1), false);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_THAT(visitor.data(), testing::HasSubstr(kBody));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  const quiche::HttpHeaderBlock block =
      ToHeaderBlock(ToHeaders({{"key", "wild value!"}}));
  if (GetParam()) {
    visitor.AppendMetadataForStream(1, block);
    adapter->SubmitMetadata(1, 1);
  } else {
    adapter->SubmitMetadata(
        1, 16384u, std::make_unique<TestMetadataSource>(std::move(block)));
  }

  int trailer_result =
      adapter->SubmitTrailer(1, ToHeaders({{":final-status", "a-ok"}}));
  ASSERT_EQ(trailer_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _,
                                         END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _,
                                   END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({static_cast<SpdyFrameType>(kMetadataFrameType),
                            SpdyFrameType::HEADERS}));
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2

"""

```