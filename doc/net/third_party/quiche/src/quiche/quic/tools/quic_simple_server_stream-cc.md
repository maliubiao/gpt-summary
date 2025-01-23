Response:
My thinking process to answer the request about `quic_simple_server_stream.cc` involved the following steps:

1. **Understand the Core Request:** The request asks for the functionalities of the given C++ source code file, its relationship with JavaScript, examples of logical reasoning (input/output), common usage errors, and debugging guidance.

2. **Initial Code Scan (Keywords and Structure):** I first scanned the code for prominent keywords and the overall structure. Keywords like `Server`, `Stream`, `Headers`, `Body`, `Response`, `Connect`, `WebTransport`, and function names like `OnInitialHeadersComplete`, `OnBodyAvailable`, `SendResponse` immediately gave me a high-level understanding of its purpose. The inheritance from `QuicSpdyServerStreamBase` and the presence of `QuicSimpleServerBackend` suggested this is a server-side component handling incoming QUIC stream requests.

3. **Deconstruct Functionality by Analyzing Key Methods:** I then focused on the core methods to understand their roles:

    * **Constructor(s):**  Initialization, especially the association with `QuicSimpleServerBackend`.
    * **`OnInitialHeadersComplete`:** Processing incoming request headers. Key actions include validation, handling CONNECT requests (including WebTransport), and potentially sending error responses.
    * **`OnBodyAvailable`:**  Handling incoming request body data, including checks for content length and handling CONNECT data.
    * **`SendResponse`:** Orchestrating the sending of the server's response based on the request headers and body. This includes logic for WebTransport, fetching responses from the backend, and handling different response types (normal, error, not found, etc.).
    * **`HandleRequestConnectData`:** Specific logic for processing data within a CONNECT request.
    * **`Respond`:**  The central point for actually sending the response after fetching it from the backend. It deals with delayed responses, Early Hints, special response types (close connection, ignore request, backend error), and finally sending headers, body, and trailers.
    * **`SendStreamData`:**  A method for sending data in chunks, potentially closing the stream.
    * **`TerminateStreamWithError`:** Forcefully closing the stream due to an error.
    * **`WriteGeneratedBytes`:**  A special case for generating a large response body.
    * **`SendNotFoundResponse` / `SendErrorResponse`:** Sending standard error responses.
    * **`SendIncompleteResponse` / `SendHeadersAndBody` / `SendHeadersAndBodyAndTrailers`:**  Methods for constructing and sending different parts of the HTTP response.
    * **`IsConnectRequest`:**  A helper to determine if the request is a CONNECT request.

4. **Identify Relationships with JavaScript:**  I considered how server-side code like this interacts with the client-side (where JavaScript typically resides). The key connection is through the HTTP protocol (or HTTP/3 in this case, over QUIC). JavaScript code running in a browser or Node.js makes HTTP requests. This server code *handles* those requests and sends back HTTP responses that JavaScript then processes. I focused on scenarios like fetching data, submitting forms, and the special case of WebTransport, which enables more direct bidirectional communication.

5. **Construct Logical Reasoning Examples (Input/Output):**  Based on the functionality, I created simple scenarios demonstrating the flow of data and the server's response. I chose examples involving basic GET and POST requests and a CONNECT request. The key was to show how request headers and body influence the server's output.

6. **Identify Common Usage Errors:** I thought about common mistakes developers might make when interacting with or configuring a server like this. Examples included incorrect content length, missing headers, requesting non-existent resources, and server-side errors in handling requests.

7. **Trace User Actions for Debugging:** I considered a simple user interaction (clicking a link) and traced the likely path through the network stack, highlighting where this specific server-side code would be invoked. The goal was to provide context for debugging.

8. **Structure the Answer:** I organized the information into clear sections based on the request's prompts: functionalities, relationship with JavaScript, logical reasoning, usage errors, and debugging. Within each section, I used bullet points and clear language to explain the concepts.

9. **Refine and Elaborate:** I reviewed my initial draft and added more detail and explanation where necessary. For example, I elaborated on the significance of `QuicSimpleServerBackend` and the different response types. I made sure the JavaScript examples were concrete and relatable.

10. **Address Specific Requirements:** I made sure to explicitly address all parts of the original request, including providing concrete examples for each point. For instance, when discussing JavaScript, I provided code snippets. For logical reasoning, I presented specific input and output.

By following these steps, I could systematically analyze the provided C++ code and generate a comprehensive and informative answer that addressed all aspects of the user's request. The process involves understanding the code's purpose, dissecting its functionality, connecting it to relevant client-side technologies, and considering practical aspects like error handling and debugging.
这个文件 `net/third_party/quiche/src/quiche/quic/tools/quic_simple_server_stream.cc` 是 Chromium QUIC 简单服务器实现中用于处理单个 QUIC 流（stream）的类 `QuicSimpleServerStream` 的源代码。它的主要功能是：

**核心功能：处理客户端的 HTTP/QUIC 请求并生成响应。**

更具体地说，它负责：

1. **接收和解析客户端请求：**
   - 接收客户端发送的 HTTP 请求头（通过 `OnInitialHeadersComplete`）。
   - 验证请求头，例如检查必要的 `:authority` 和 `:path` 字段。
   - 接收客户端发送的请求体（通过 `OnBodyAvailable`）。
   - 处理 `CONNECT` 方法的特殊请求，用于建立隧道。
   - 支持 WebTransport 协议，处理相关的请求和数据。

2. **与后端交互获取响应：**
   - 将接收到的请求信息（头和体）传递给 `QuicSimpleServerBackend`，由后端逻辑处理请求并生成响应。
   - 对于 `CONNECT` 请求，调用 `QuicSimpleServerBackend::HandleConnectHeaders` 和 `QuicSimpleServerBackend::HandleConnectData`。
   - 对于普通 HTTP 请求，调用 `QuicSimpleServerBackend::FetchResponseFromBackend`。

3. **发送服务器响应：**
   - 接收 `QuicSimpleServerBackend` 返回的响应信息（头、体、尾部）。
   - 发送 HTTP 响应头（通过 `WriteHeaders`）。
   - 发送 HTTP 响应体（通过 `WriteOrBufferBody`）。
   - 发送 HTTP 响应尾部（通过 `WriteTrailers`）。
   - 支持发送 Early Hints。
   - 可以发送错误响应（例如 404 Not Found, 500 Internal Server Error）和自定义状态码的错误响应。
   - 可以发送不完整的响应，不带 FIN 标志，用于流式传输数据。
   - 特殊情况下，可以指示服务器关闭连接。
   - 可以生成指定长度的响应体数据（用于测试目的）。

4. **处理连接和流的生命周期：**
   - 跟踪请求是否已处理并发送响应。
   - 在流完成时通知后端 (`CloseBackendResponseStream`)。
   - 可以主动终止流并发送错误码。

**与 JavaScript 的关系：**

该 C++ 文件本身不包含 JavaScript 代码，但它在服务器端处理客户端（通常是运行在浏览器中的 JavaScript 代码）发出的 HTTP/QUIC 请求。关系体现在：

* **JavaScript 发起请求：** 浏览器中的 JavaScript 代码可以使用 `fetch` API 或 `XMLHttpRequest` 等方法发起 HTTP 请求。当使用 QUIC 协议时，这些请求最终会到达这个 C++ 代码处理。
* **服务器响应 JavaScript：**  `QuicSimpleServerStream` 生成的 HTTP 响应（包括状态码、头部和响应体）会被发送回客户端，JavaScript 代码可以接收并处理这些响应数据。

**举例说明：**

假设 JavaScript 代码发起一个简单的 GET 请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个场景下：

1. 浏览器会创建一个 QUIC 连接到 `example.com` 的服务器。
2. JavaScript 的 `fetch` 调用会生成一个 HTTP/3 请求，包含类似以下的头部：
   ```
   :method: GET
   :scheme: https
   :authority: example.com
   :path: /data.json
   // ... 其他头部
   ```
3. 这个请求会被编码并通过 QUIC 连接发送到服务器。
4. 服务器端的 `QuicSimpleServerStream` 实例会接收到这个请求，并调用 `OnInitialHeadersComplete` 解析这些头部。
5. `QuicSimpleServerStream` 会将请求信息传递给 `QuicSimpleServerBackend`。
6. `QuicSimpleServerBackend` 可能会从文件系统、缓存或其他数据源获取 `data.json` 的内容，并构建一个 HTTP 响应，例如：
   ```
   :status: 200
   content-type: application/json
   content-length: ...
   // ... 其他头部

   {"key": "value"}
   ```
7. `QuicSimpleServerStream` 会接收到这个响应，并使用 `WriteHeaders` 和 `WriteOrBufferBody` 将响应头和响应体通过 QUIC 连接发送回客户端。
8. 浏览器接收到响应后，JavaScript 的 `response.json()` 会解析 JSON 数据，最终 `console.log(data)` 会输出 `{"key": "value"}`。

**逻辑推理的假设输入与输出：**

**假设输入：**

* **请求头 (传入 `OnInitialHeadersComplete`)：**
  ```
  :method: POST
  :scheme: https
  :authority: example.com
  :path: /submit
  content-type: application/x-www-form-urlencoded
  content-length: 13
  ```
* **请求体 (传入 `OnBodyAvailable`)：**
  ```
  name=John&age=30
  ```

**逻辑推理：**

1. `OnInitialHeadersComplete` 会解析头部，提取 `:method`, `:path`, `content-length` 等信息。
2. 由于 `:method` 是 `POST`，并且有 `content-length`，`QuicSimpleServerStream` 会继续接收请求体。
3. `OnBodyAvailable` 会将接收到的请求体数据 `name=John&age=30` 存储起来。
4. 当请求完成（收到 FIN 标志）后，`SendResponse` 会被调用。
5. `SendResponse` 会将请求头和体传递给 `QuicSimpleServerBackend`。
6. `QuicSimpleServerBackend` 可能会根据请求的路径 `/submit` 和请求体中的数据进行处理。

**假设输出（取决于 `QuicSimpleServerBackend` 的实现）：**

* **成功处理：**
  * **响应头 (发送到客户端)：**
    ```
    :status: 200
    content-type: text/plain
    content-length: 18
    ```
  * **响应体 (发送到客户端)：**
    ```
    Data received: OK
    ```
* **处理失败（例如缺少必要字段）：**
  * **响应头 (发送到客户端)：**
    ```
    :status: 400
    content-type: text/plain
    content-length: 21
    ```
  * **响应体 (发送到客户端)：**
    ```
    Missing required field
    ```

**用户或编程常见的使用错误：**

1. **Content-Length 不匹配实际 Body 大小：**
   - **错误场景：** 客户端发送的 `content-length` 头部值与实际发送的请求体大小不一致。
   - **`QuicSimpleServerStream` 的处理：** 会在 `OnBodyAvailable` 中检测到 `body_.size() > static_cast<uint64_t>(content_length_)` 并调用 `SendErrorResponse()`。
   - **示例：** JavaScript 代码设置了错误的 `content-length`，或者在发送过程中部分数据丢失。
   ```javascript
   fetch('/upload', {
     method: 'POST',
     headers: {
       'Content-Type': 'text/plain',
       'Content-Length': '5' // 错误地声明长度为 5
     },
     body: 'This is more than 5 bytes'
   });
   ```

2. **缺少必要的请求头 (例如 `:authority`, `:path`)：**
   - **错误场景：** 客户端发送的请求头中缺少 `:authority` 或 `:path` 字段。
   - **`QuicSimpleServerStream` 的处理：** 在 `SendResponse` 中会检查这些头部是否存在，如果缺少会调用 `SendErrorResponse()`。
   - **示例：** 客户端代码没有正确构造 HTTP 请求头。

3. **尝试在 CONNECT 请求中发送 Body：**
   - **错误场景：**  客户端使用 `CONNECT` 方法，但尝试在初始请求中发送数据体（通常 `CONNECT` 请求不应有请求体）。
   - **`QuicSimpleServerStream` 的处理：** 虽然会接收数据，但 `CONNECT` 的处理逻辑主要在建立连接之后的数据帧中。如果后端不期望初始请求有 body，可能会导致处理错误。
   - **示例：** 误解了 `CONNECT` 方法的用途。

4. **后端返回非法的响应状态码：**
   - **错误场景：** `QuicSimpleServerBackend` 返回的响应头中 `:status` 字段不是合法的 HTTP 状态码（例如非数字）。
   - **`QuicSimpleServerStream` 的处理：** 在 `Respond` 函数中会尝试解析状态码，如果解析失败会调用 `SendErrorResponse()`。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问 `https://example.com/resource`：

1. **用户在浏览器地址栏输入 URL 并按下回车，或者点击了一个指向该 URL 的链接。**
2. **浏览器解析 URL，确定协议为 HTTPS，主机为 example.com，路径为 /resource。**
3. **浏览器查找与 example.com 的 QUIC 连接。** 如果没有，则会建立一个新的 QUIC 连接。
4. **浏览器构造一个 HTTP/3 请求。** 请求头可能如下：
   ```
   :method: GET
   :scheme: https
   :authority: example.com
   :path: /resource
   user-agent: ...
   accept: ...
   // ... 其他浏览器添加的头部
   ```
5. **浏览器将请求头（编码后）通过 QUIC 连接发送到服务器。**
6. **服务器的 QUIC 实现接收到新的流的数据，并创建一个 `QuicSimpleServerStream` 实例来处理这个流。**
7. **`QuicSimpleServerStream` 的 `OnInitialHeadersComplete` 方法被调用，参数包含接收到的请求头。**  这是代码执行的第一个入口点。
8. **`OnInitialHeadersComplete` 内部会进行头部的验证和解析。**
9. **如果请求包含请求体（例如 POST 请求），后续的数据包会导致 `OnBodyAvailable` 方法被调用。**
10. **最终，`SendResponse` 方法会被调用，负责从后端获取响应并发送回客户端。**

**调试线索：**

* **查看服务器日志：** 服务器通常会记录接收到的请求头、发送的响应头以及可能发生的错误。
* **使用 QUIC 调试工具：** 例如 `qvis` 可以可视化 QUIC 连接的详细信息，包括发送和接收的数据包、头部等。
* **在 `QuicSimpleServerStream` 的关键方法中添加日志输出：**  例如在 `OnInitialHeadersComplete`, `OnBodyAvailable`, `SendResponse`, `Respond` 等方法中打印接收到的数据和执行的逻辑，可以帮助跟踪请求的处理过程。
* **检查 `QuicSimpleServerBackend` 的实现：** 确认后端是否正确处理了请求并返回了预期的响应。
* **使用浏览器开发者工具的网络面板：** 可以查看浏览器发送的请求头和接收到的响应头，以及请求的状态和时间线，有助于定位客户端或服务器端的问题。

理解 `QuicSimpleServerStream` 的功能和它在请求处理流程中的位置，结合调试工具和日志，可以有效地诊断基于 QUIC 的网络应用程序的问题。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/tools/quic_simple_server_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quic_simple_server_stream.h"

#include <algorithm>
#include <cstdint>
#include <list>
#include <optional>
#include <string>
#include <utility>

#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/quic/core/http/quic_spdy_stream.h"
#include "quiche/quic/core/http/spdy_utils.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/tools/quic_simple_server_session.h"

using quiche::HttpHeaderBlock;

namespace quic {

QuicSimpleServerStream::QuicSimpleServerStream(
    QuicStreamId id, QuicSpdySession* session, StreamType type,
    QuicSimpleServerBackend* quic_simple_server_backend)
    : QuicSpdyServerStreamBase(id, session, type),
      content_length_(-1),
      generate_bytes_length_(0),
      quic_simple_server_backend_(quic_simple_server_backend) {
  QUICHE_DCHECK(quic_simple_server_backend_);
}

QuicSimpleServerStream::QuicSimpleServerStream(
    PendingStream* pending, QuicSpdySession* session,
    QuicSimpleServerBackend* quic_simple_server_backend)
    : QuicSpdyServerStreamBase(pending, session),
      content_length_(-1),
      generate_bytes_length_(0),
      quic_simple_server_backend_(quic_simple_server_backend) {
  QUICHE_DCHECK(quic_simple_server_backend_);
}

QuicSimpleServerStream::~QuicSimpleServerStream() {
  quic_simple_server_backend_->CloseBackendResponseStream(this);
}

void QuicSimpleServerStream::OnInitialHeadersComplete(
    bool fin, size_t frame_len, const QuicHeaderList& header_list) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len, header_list);
  // QuicSpdyStream::OnInitialHeadersComplete() may have already sent error
  // response.
  if (!response_sent_ &&
      !SpdyUtils::CopyAndValidateHeaders(header_list, &content_length_,
                                         &request_headers_)) {
    QUIC_DVLOG(1) << "Invalid headers";
    SendErrorResponse();
  }
  ConsumeHeaderList();

  // CONNECT requests do not carry any message content but carry data after the
  // headers, so they require sending the response right after parsing the
  // headers even though the FIN bit has not been received on the request
  // stream.
  if (!fin && !response_sent_ && IsConnectRequest()) {
    if (quic_simple_server_backend_ == nullptr) {
      QUIC_DVLOG(1) << "Backend is missing on CONNECT headers.";
      SendErrorResponse();
      return;
    }

    if (web_transport() != nullptr) {
      QuicSimpleServerBackend::WebTransportResponse response =
          quic_simple_server_backend_->ProcessWebTransportRequest(
              request_headers_, web_transport());
      if (response.response_headers[":status"] == "200") {
        WriteHeaders(std::move(response.response_headers), false, nullptr);
        if (response.visitor != nullptr) {
          web_transport()->SetVisitor(std::move(response.visitor));
        }
        web_transport()->HeadersReceived(request_headers_);
      } else {
        WriteHeaders(std::move(response.response_headers), true, nullptr);
      }
      return;
    }

    quic_simple_server_backend_->HandleConnectHeaders(request_headers_,
                                                      /*request_handler=*/this);
  }
}

void QuicSimpleServerStream::OnBodyAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    QUIC_DVLOG(1) << "Stream " << id() << " processed " << iov.iov_len
                  << " bytes.";
    body_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    if (content_length_ >= 0 &&
        body_.size() > static_cast<uint64_t>(content_length_)) {
      QUIC_DVLOG(1) << "Body size (" << body_.size() << ") > content length ("
                    << content_length_ << ").";
      SendErrorResponse();
      return;
    }
    MarkConsumed(iov.iov_len);
  }

  if (!sequencer()->IsClosed()) {
    if (IsConnectRequest()) {
      HandleRequestConnectData(/*fin_received=*/false);
    }
    sequencer()->SetUnblocked();
    return;
  }

  // If the sequencer is closed, then all the body, including the fin, has been
  // consumed.
  OnFinRead();

  if (write_side_closed() || fin_buffered()) {
    return;
  }

  if (IsConnectRequest()) {
    HandleRequestConnectData(/*fin_received=*/true);
  } else {
    SendResponse();
  }
}

void QuicSimpleServerStream::HandleRequestConnectData(bool fin_received) {
  QUICHE_DCHECK(IsConnectRequest());

  if (quic_simple_server_backend_ == nullptr) {
    QUIC_DVLOG(1) << "Backend is missing on CONNECT data.";
    ResetWriteSide(
        QuicResetStreamError::FromInternal(QUIC_STREAM_CONNECT_ERROR));
    return;
  }

  // Clear `body_`, so only new data is sent to the backend next time.
  std::string data = std::move(body_);
  body_.clear();

  quic_simple_server_backend_->HandleConnectData(data,
                                                 /*data_complete=*/fin_received,
                                                 this);
}

void QuicSimpleServerStream::SendResponse() {
  QUICHE_DCHECK(!IsConnectRequest());

  if (request_headers_.empty()) {
    QUIC_DVLOG(1) << "Request headers empty.";
    SendErrorResponse();
    return;
  }

  if (content_length_ > 0 &&
      static_cast<uint64_t>(content_length_) != body_.size()) {
    QUIC_DVLOG(1) << "Content length (" << content_length_ << ") != body size ("
                  << body_.size() << ").";
    SendErrorResponse();
    return;
  }

  if (!request_headers_.contains(":authority")) {
    QUIC_DVLOG(1) << "Request headers do not contain :authority.";
    SendErrorResponse();
    return;
  }

  if (!request_headers_.contains(":path")) {
    QUIC_DVLOG(1) << "Request headers do not contain :path.";
    SendErrorResponse();
    return;
  }

  if (quic_simple_server_backend_ == nullptr) {
    QUIC_DVLOG(1) << "Backend is missing in SendResponse().";
    SendErrorResponse();
    return;
  }

  if (web_transport() != nullptr) {
    QuicSimpleServerBackend::WebTransportResponse response =
        quic_simple_server_backend_->ProcessWebTransportRequest(
            request_headers_, web_transport());
    if (response.response_headers[":status"] == "200") {
      WriteHeaders(std::move(response.response_headers), false, nullptr);
      if (response.visitor != nullptr) {
        web_transport()->SetVisitor(std::move(response.visitor));
      }
      web_transport()->HeadersReceived(request_headers_);
    } else {
      WriteHeaders(std::move(response.response_headers), true, nullptr);
    }
    return;
  }

  // Fetch the response from the backend interface and wait for callback once
  // response is ready
  quic_simple_server_backend_->FetchResponseFromBackend(request_headers_, body_,
                                                        this);
}

QuicConnectionId QuicSimpleServerStream::connection_id() const {
  return spdy_session()->connection_id();
}

QuicStreamId QuicSimpleServerStream::stream_id() const { return id(); }

std::string QuicSimpleServerStream::peer_host() const {
  return spdy_session()->peer_address().host().ToString();
}

QuicSpdyStream* QuicSimpleServerStream::GetStream() { return this; }

namespace {

class DelayedResponseAlarm : public QuicAlarm::DelegateWithContext {
 public:
  DelayedResponseAlarm(QuicSimpleServerStream* stream,
                       const QuicBackendResponse* response)
      : QuicAlarm::DelegateWithContext(
            stream->spdy_session()->connection()->context()),
        stream_(stream),
        response_(response) {
    stream_ = stream;
    response_ = response;
  }

  ~DelayedResponseAlarm() override = default;

  void OnAlarm() override { stream_->Respond(response_); }

 private:
  QuicSimpleServerStream* stream_;
  const QuicBackendResponse* response_;
};

}  // namespace

void QuicSimpleServerStream::OnResponseBackendComplete(
    const QuicBackendResponse* response) {
  if (response == nullptr) {
    QUIC_DVLOG(1) << "Response not found in cache.";
    SendNotFoundResponse();
    return;
  }

  auto delay = response->delay();
  if (delay.IsZero()) {
    Respond(response);
    return;
  }

  auto* connection = session()->connection();
  delayed_response_alarm_.reset(connection->alarm_factory()->CreateAlarm(
      new DelayedResponseAlarm(this, response)));
  delayed_response_alarm_->Set(connection->clock()->Now() + delay);
}

void QuicSimpleServerStream::Respond(const QuicBackendResponse* response) {
  // Send Early Hints first.
  for (const auto& headers : response->early_hints()) {
    QUIC_DVLOG(1) << "Stream " << id() << " sending an Early Hints response: "
                  << headers.DebugString();
    WriteHeaders(headers.Clone(), false, nullptr);
  }

  if (response->response_type() == QuicBackendResponse::CLOSE_CONNECTION) {
    QUIC_DVLOG(1) << "Special response: closing connection.";
    OnUnrecoverableError(QUIC_NO_ERROR, "Toy server forcing close");
    return;
  }

  if (response->response_type() == QuicBackendResponse::IGNORE_REQUEST) {
    QUIC_DVLOG(1) << "Special response: ignoring request.";
    return;
  }

  if (response->response_type() == QuicBackendResponse::BACKEND_ERR_RESPONSE) {
    QUIC_DVLOG(1) << "Quic Proxy: Backend connection error.";
    /*502 Bad Gateway
      The server was acting as a gateway or proxy and received an
      invalid response from the upstream server.*/
    SendErrorResponse(502);
    return;
  }

  // Examing response status, if it was not pure integer as typical h2
  // response status, send error response. Notice that
  // QuicHttpResponseCache push urls are strictly authority + path only,
  // scheme is not included (see |QuicHttpResponseCache::GetKey()|).
  std::string request_url = request_headers_[":authority"].as_string() +
                            request_headers_[":path"].as_string();
  int response_code;
  const HttpHeaderBlock& response_headers = response->headers();
  if (!ParseHeaderStatusCode(response_headers, &response_code)) {
    auto status = response_headers.find(":status");
    if (status == response_headers.end()) {
      QUIC_LOG(WARNING)
          << ":status not present in response from cache for request "
          << request_url;
    } else {
      QUIC_LOG(WARNING) << "Illegal (non-integer) response :status from cache: "
                        << status->second << " for request " << request_url;
    }
    SendErrorResponse();
    return;
  }

  if (response->response_type() == QuicBackendResponse::INCOMPLETE_RESPONSE) {
    QUIC_DVLOG(1)
        << "Stream " << id()
        << " sending an incomplete response, i.e. no trailer, no fin.";
    SendIncompleteResponse(response->headers().Clone(), response->body());
    return;
  }

  if (response->response_type() == QuicBackendResponse::GENERATE_BYTES) {
    QUIC_DVLOG(1) << "Stream " << id() << " sending a generate bytes response.";
    std::string path = request_headers_[":path"].as_string().substr(1);
    if (!absl::SimpleAtoi(path, &generate_bytes_length_)) {
      QUIC_LOG(ERROR) << "Path is not a number.";
      SendNotFoundResponse();
      return;
    }
    HttpHeaderBlock headers = response->headers().Clone();
    headers["content-length"] = absl::StrCat(generate_bytes_length_);

    WriteHeaders(std::move(headers), false, nullptr);
    QUICHE_DCHECK(!response_sent_);
    response_sent_ = true;

    WriteGeneratedBytes();

    return;
  }

  QUIC_DVLOG(1) << "Stream " << id() << " sending response.";
  SendHeadersAndBodyAndTrailers(response->headers().Clone(), response->body(),
                                response->trailers().Clone());
}

void QuicSimpleServerStream::SendStreamData(absl::string_view data,
                                            bool close_stream) {
  // Doesn't make sense to call this without data or `close_stream`.
  QUICHE_DCHECK(!data.empty() || close_stream);

  if (close_stream) {
    SendHeadersAndBodyAndTrailers(
        /*response_headers=*/std::nullopt, data,
        /*response_trailers=*/quiche::HttpHeaderBlock());
  } else {
    SendIncompleteResponse(/*response_headers=*/std::nullopt, data);
  }
}

void QuicSimpleServerStream::TerminateStreamWithError(
    QuicResetStreamError error) {
  QUIC_DVLOG(1) << "Stream " << id() << " abruptly terminating with error "
                << error.internal_code();
  ResetWriteSide(error);
}

void QuicSimpleServerStream::OnCanWrite() {
  QuicSpdyStream::OnCanWrite();
  WriteGeneratedBytes();
}

void QuicSimpleServerStream::WriteGeneratedBytes() {
  static size_t kChunkSize = 1024;
  while (!HasBufferedData() && generate_bytes_length_ > 0) {
    size_t len = std::min<size_t>(kChunkSize, generate_bytes_length_);
    std::string data(len, 'a');
    generate_bytes_length_ -= len;
    bool fin = generate_bytes_length_ == 0;
    WriteOrBufferBody(data, fin);
  }
}

void QuicSimpleServerStream::SendNotFoundResponse() {
  QUIC_DVLOG(1) << "Stream " << id() << " sending not found response.";
  HttpHeaderBlock headers;
  headers[":status"] = "404";
  headers["content-length"] = absl::StrCat(strlen(kNotFoundResponseBody));
  SendHeadersAndBody(std::move(headers), kNotFoundResponseBody);
}

void QuicSimpleServerStream::SendErrorResponse() { SendErrorResponse(0); }

void QuicSimpleServerStream::SendErrorResponse(int resp_code) {
  QUIC_DVLOG(1) << "Stream " << id() << " sending error response.";
  if (!reading_stopped()) {
    StopReading();
  }
  HttpHeaderBlock headers;
  if (resp_code <= 0) {
    headers[":status"] = "500";
  } else {
    headers[":status"] = absl::StrCat(resp_code);
  }
  headers["content-length"] = absl::StrCat(strlen(kErrorResponseBody));
  SendHeadersAndBody(std::move(headers), kErrorResponseBody);
}

void QuicSimpleServerStream::SendIncompleteResponse(
    std::optional<HttpHeaderBlock> response_headers, absl::string_view body) {
  // Headers should be sent iff not sent in a previous response.
  QUICHE_DCHECK_NE(response_headers.has_value(), response_sent_);

  if (response_headers.has_value()) {
    QUIC_DLOG(INFO) << "Stream " << id() << " writing headers (fin = false) : "
                    << response_headers.value().DebugString();
    // Do not mark response sent for early 100 continue response.
    int response_code;
    if (!ParseHeaderStatusCode(*response_headers, &response_code) ||
        response_code != 100) {
      response_sent_ = true;
    }
    WriteHeaders(std::move(response_headers).value(), /*fin=*/false, nullptr);
  }

  QUIC_DLOG(INFO) << "Stream " << id()
                  << " writing body (fin = false) with size: " << body.size();
  if (!body.empty()) {
    WriteOrBufferBody(body, /*fin=*/false);
  }
}

void QuicSimpleServerStream::SendHeadersAndBody(
    HttpHeaderBlock response_headers, absl::string_view body) {
  SendHeadersAndBodyAndTrailers(std::move(response_headers), body,
                                HttpHeaderBlock());
}

void QuicSimpleServerStream::SendHeadersAndBodyAndTrailers(
    std::optional<HttpHeaderBlock> response_headers, absl::string_view body,
    HttpHeaderBlock response_trailers) {
  // Headers should be sent iff not sent in a previous response.
  QUICHE_DCHECK_NE(response_headers.has_value(), response_sent_);

  if (response_headers.has_value()) {
    // Send the headers, with a FIN if there's nothing else to send.
    bool send_fin = (body.empty() && response_trailers.empty());
    QUIC_DLOG(INFO) << "Stream " << id()
                    << " writing headers (fin = " << send_fin
                    << ") : " << response_headers.value().DebugString();
    WriteHeaders(std::move(response_headers).value(), send_fin, nullptr);
    response_sent_ = true;
    if (send_fin) {
      // Nothing else to send.
      return;
    }
  }

  // Send the body, with a FIN if there's no trailers to send.
  bool send_fin = response_trailers.empty();
  QUIC_DLOG(INFO) << "Stream " << id() << " writing body (fin = " << send_fin
                  << ") with size: " << body.size();
  if (!body.empty() || send_fin) {
    WriteOrBufferBody(body, send_fin);
  }
  if (send_fin) {
    // Nothing else to send.
    return;
  }

  // Send the trailers. A FIN is always sent with trailers.
  QUIC_DLOG(INFO) << "Stream " << id() << " writing trailers (fin = true): "
                  << response_trailers.DebugString();
  WriteTrailers(std::move(response_trailers), nullptr);
}

bool QuicSimpleServerStream::IsConnectRequest() const {
  auto method_it = request_headers_.find(":method");
  return method_it != request_headers_.end() && method_it->second == "CONNECT";
}

void QuicSimpleServerStream::OnInvalidHeaders() {
  QUIC_DVLOG(1) << "Invalid headers";
  SendErrorResponse(400);
}

const char* const QuicSimpleServerStream::kErrorResponseBody = "bad";
const char* const QuicSimpleServerStream::kNotFoundResponseBody =
    "file not found";

}  // namespace quic
```