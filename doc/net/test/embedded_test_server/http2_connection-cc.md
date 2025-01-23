Response:
Let's break down the thought process for analyzing this C++ code.

**1. Initial Scan and Identification of Core Purpose:**

* **Keywords:**  "net/test/embedded_test_server", "http2_connection". These immediately suggest a testing component for HTTP/2 within Chromium's networking stack. The filename strongly hints at managing an HTTP/2 connection on the server-side.
* **Includes:**  The included headers (`#include ...`) provide further clues: `net/http/http_response_headers.h`, `net/http/http_status_code.h`, `net/socket/stream_socket.h`, `net/ssl/ssl_info.h`,  `net/test/embedded_test_server/embedded_test_server.h`, and importantly, something related to HTTP/2 (`http2/adapter/...`). This reinforces the HTTP/2 server connection management role.

**2. Deconstructing the Class Structure (Http2Connection):**

* **Key Members:**
    * `std::unique_ptr<StreamSocket> socket_`:  Manages the underlying network socket.
    * `EmbeddedTestServerConnectionListener* connection_listener_`: Likely for reporting connection events.
    * `EmbeddedTestServer* embedded_test_server_`:  A backpointer to the overall test server.
    * `http2::adapter::OgHttp2Adapter adapter_`:  The core HTTP/2 library integration. This is the heart of the HTTP/2 handling.
    * `std::map<StreamId, std::unique_ptr<HttpRequest>> request_map_`: Stores incoming HTTP requests, keyed by stream ID.
    * `std::map<StreamId, std::unique_ptr<ResponseDelegate>> response_map_`: Manages responses for each stream.
    * `std::queue<StreamId> ready_streams_`:  A queue to indicate which streams have received complete headers.
    * `DataFrameSource`: A nested class for handling data frame sending.
    * `ResponseDelegate`: A nested class for managing responses for a specific stream.

* **Key Methods:**
    * `Http2Connection(std::unique_ptr<StreamSocket> socket, ...)`: Constructor - sets up the connection.
    * `OnSocketReady()`:  Called when the socket is ready for I/O.
    * `ReadData()`/`OnDataRead()`/`HandleData()`:  Handles incoming data from the socket, passing it to the HTTP/2 adapter.
    * `OnHeaderForStream()`/`OnEndHeadersForStream()`/`OnEndStream()`: HTTP/2 visitor methods that process incoming headers and signal the end of the header section for a stream.
    * `OnDataForStream()`: Processes incoming data for a specific stream.
    * `OnReadyToSend()`:  Called by the `DataFrameSource` to send data over the socket.
    * `SendInternal()`/`OnSendInternalDone()`:  Handles the actual writing of data to the socket.
    * `ResponseDelegate::SendResponseHeaders()`, `ResponseDelegate::SendContents()`, `ResponseDelegate::FinishResponse()`:  Methods within the `ResponseDelegate` to construct and send HTTP responses.

**3. Identifying Functionality:**

Based on the members and methods, the core functionalities emerge:

* **Receiving and Parsing HTTP/2 Requests:** The `Http2Connection` class acts as an HTTP/2 server endpoint, receiving raw bytes from the socket, parsing the HTTP/2 frames (using the `OgHttp2Adapter`), and extracting headers and data.
* **Handling Multiple Streams:** The use of `stream_id` and the `request_map_`/`response_map_` clearly indicate support for multiplexing multiple requests and responses over a single HTTP/2 connection.
* **Generating and Sending HTTP/2 Responses:** The `ResponseDelegate` is responsible for constructing and sending responses. It handles headers, data, and the final FIN frame.
* **Integration with the Embedded Test Server:** The class interacts with `EmbeddedTestServer` to dispatch requests to appropriate handlers.
* **Flow Control:** The `blocked_streams_` and the logic in `OnReadyToSend` and `OnSendInternalDone` suggest basic handling of write blocking, a form of flow control.

**4. Connecting to JavaScript:**

* **Web Browser as the Client:** The most obvious connection is through a web browser. A browser would initiate an HTTP/2 connection to the `EmbeddedTestServer`.
* **JavaScript's Role:** JavaScript code running in the browser would trigger the HTTP request (e.g., using `fetch()` or `XMLHttpRequest`). The browser handles the underlying HTTP/2 protocol details. This C++ code is the *server-side* component that receives and responds to those requests.
* **Example:** A JavaScript `fetch('/data')` would lead to the `Http2Connection` receiving the headers for a new stream, the `EmbeddedTestServer` finding a handler for `/data`, and the `ResponseDelegate` sending back the data to the browser, which the JavaScript would then access.

**5. Logical Reasoning (Input/Output):**

* **Simplified Scenario:** Focus on a basic request/response cycle.
* **Input:** Raw HTTP/2 frames arriving on the socket, representing a GET request for `/example`.
* **Processing:**
    * `HandleData()` receives the bytes.
    * `adapter_->ProcessBytes()` parses the HEADERS frame.
    * `OnHeaderForStream()` and `OnEndHeadersForStream()` populate the `request_map_`.
    * `OnEndStream()` adds the `stream_id` to `ready_streams_`.
    * The main loop in `HandleData()` dispatches the request to the `EmbeddedTestServer`.
    * A handler (not shown in this code) for `/example` is invoked.
    * The handler uses the `ResponseDelegate` to send headers and data.
    * `SendResponseHeaders()` and `SendContents()` call into the `adapter_` to generate HTTP/2 response frames.
    * `OnReadyToSend()` and `SendInternal()` write the response frames to the socket.
* **Output:** Raw HTTP/2 frames sent back on the socket, representing the response (headers and potentially data).

**6. Common Usage Errors:**

* **Incorrect Header Formatting:**  The code explicitly checks for "Connection" headers, highlighting that including prohibited headers is an error.
* **Sending Data Before Headers:** The check in `OnDataForStream()` prevents processing data if headers haven't arrived, indicating a protocol violation.
* **Not Calling `FinishResponse()`:** If the `FinishResponse()` method isn't called, the client might wait indefinitely for more data, leading to a stalled connection.

**7. Debugging Scenario:**

* **Starting Point:** A user reports that a specific page on the test server isn't loading correctly.
* **Tracing the Request:**
    1. **Browser Network Tab:** The developer inspects the browser's network tab and sees the request stuck or failing with an HTTP/2 error.
    2. **Server-Side Logging:**  They might add logging in the `EmbeddedTestServer` or within the request handlers to see if the request is even reaching the server.
    3. **Breakpoint in `Http2Connection::HandleData()`:** If the request *is* reaching the server, a breakpoint here allows inspection of the raw incoming data.
    4. **Stepping Through HTTP/2 Parsing:**  Step through the calls to `adapter_->ProcessBytes()` and the visitor methods (`OnHeaderForStream`, `OnDataForStream`, etc.) to see how the request is being parsed.
    5. **Inspecting `request_map_`:** Check if the request headers and content are being populated correctly.
    6. **Breakpoint in `ResponseDelegate` Methods:**  Examine the response headers and data being sent back.
    7. **Socket-Level Inspection:**  In more complex scenarios, tools that capture raw socket traffic (like Wireshark) can be used to examine the actual HTTP/2 frames being exchanged.

This detailed breakdown illustrates how one can approach analyzing unfamiliar code by focusing on keywords, structure, functionality, and then relating it to broader contexts and potential issues.这个 C++ 文件 `http2_connection.cc` 是 Chromium 网络栈中 `net::test_server` 命名空间下的一个组件，其主要功能是 **模拟一个 HTTP/2 服务器连接**，用于集成测试和单元测试。

以下是它的详细功能点：

**核心功能:**

1. **处理 HTTP/2 连接:**
   - 接收并解析来自客户端的 HTTP/2 请求。
   - 管理 HTTP/2 的流 (streams)。
   - 生成并发送 HTTP/2 响应。

2. **作为测试服务器的一部分:**
   - 与 `EmbeddedTestServer` 类协同工作，接收由 `EmbeddedTestServer` 路由的请求。
   - 提供发送响应的能力，包括设置状态码、响应头和响应体。

3. **模拟 HTTP/2 协议细节:**
   - 使用 `http2::adapter::OgHttp2Adapter` 库来处理底层的 HTTP/2 帧的解析和生成。
   - 实现 `http2::adapter::Http2VisitorInterface` 接口，以便在 HTTP/2 适配器解析到特定事件时得到通知 (例如，接收到头部、数据等)。

4. **支持异步操作:**
   - 使用 `base::OnceClosure` 和 `base::BindOnce` 来处理异步发送数据完成的回调。
   - 使用 `net::StreamSocket` 进行非阻塞的 socket I/O 操作。

5. **提供方便的 API 用于发送响应:**
   - `ResponseDelegate` 类封装了发送 HTTP 响应的逻辑，使得测试代码可以更简洁地构建响应。
   - 支持发送头部、内容，以及一次性发送头部、内容并结束响应。

**与 JavaScript 功能的关系:**

`http2_connection.cc` 本身是用 C++ 编写的，不直接包含 JavaScript 代码。但是，它模拟的 HTTP/2 服务器连接是 **JavaScript 代码在浏览器中发起网络请求的后端**。

**举例说明:**

假设你在一个 Chromium 的测试环境中，有一个网页运行着以下 JavaScript 代码：

```javascript
fetch('/data')
  .then(response => response.text())
  .then(data => console.log(data));
```

当这段 JavaScript 代码执行时，浏览器会：

1. **发起一个 HTTP/2 请求** 到测试服务器 (由 `EmbeddedTestServer` 启动)。
2. 这个请求会被 `Http2Connection` 实例接收。
3. `Http2Connection` 会解析请求头 (例如，`:path` 为 `/data`)。
4. `Http2Connection` 将请求转发给 `EmbeddedTestServer` 的请求处理器。
5. 测试代码中注册的请求处理器会生成一个 HTTP/2 响应，并使用 `ResponseDelegate` 将响应发送回浏览器。
6. 浏览器接收到响应，JavaScript 的 `then` 回调函数会被调用，最终将响应内容打印到控制台。

**逻辑推理 (假设输入与输出):**

**假设输入:** 客户端发送一个带有以下头部的 HTTP/2 请求帧到 `Http2Connection`:

```
:method: GET
:path: /resource
:authority: test.example.com
user-agent: Chrome/Test
```

**处理过程:**

1. `Http2Connection::HandleData` 接收到数据。
2. `adapter_->ProcessBytes` 解析 HTTP/2 帧。
3. `Http2Connection::OnHeaderForStream` 被多次调用，解析每个头部。
4. `Http2Connection::OnEndHeadersForStream` 被调用，创建一个 `HttpRequest` 对象，其中包含解析出的头部信息，并存储在 `request_map_` 中。
   - **假设输入数据完整且符合 HTTP/2 协议。**
5. `Http2Connection::OnEndStream` 被调用，将流 ID 添加到 `ready_streams_`。
6. 在 `HandleData` 的后续处理中，从 `ready_streams_` 中取出流 ID，并使用对应的 `HttpRequest` 调用 `embedded_test_server_->HandleRequest`。

**假设输出 (取决于 `EmbeddedTestServer` 的处理结果):**

如果 `EmbeddedTestServer` 的处理器返回一个状态码为 200，头部 `Content-Type: text/plain`，内容为 "Hello, world!" 的响应，那么 `Http2Connection` 将会发送以下 HTTP/2 响应帧：

```
:status: 200
content-type: text/plain

Hello, world!
```

**用户或编程常见的使用错误:**

1. **在测试代码中忘记调用 `FinishResponse()`:** 如果在 `ResponseDelegate` 中发送了头部和部分内容后，忘记调用 `FinishResponse()`，那么 HTTP/2 流将不会被标记为结束，客户端可能会一直等待更多数据。这会导致请求hang住。

   ```c++
   // 错误示例：忘记调用 FinishResponse()
   response_delegate->SendResponseHeaders(net::HttpStatusCode::HTTP_OK, "", {});
   response_delegate->SendContents("Partial content");
   // 缺少 response_delegate->FinishResponse();
   ```

2. **发送不合法的 HTTP 头部:**  `Http2Connection` 中会忽略 `Connection` 相关的头部。如果在测试代码中尝试发送这些头部，它们将被忽略，但如果客户端严格要求这些头部，可能会导致行为不符合预期。

   ```c++
   // 可能被忽略的头部
   base::StringPairs headers = {{"Connection", "close"}};
   response_delegate->SendResponseHeaders(net::HttpStatusCode::HTTP_OK, "", headers);
   ```

3. **没有正确处理异步发送完成的回调:**  `SendContents` 方法使用回调来通知数据发送完成。如果测试代码没有正确处理这些回调，可能会导致资源泄漏或者逻辑错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者正在调试一个与 HTTP/2 相关的网络问题，他们可能会进行以下操作，最终涉及到 `http2_connection.cc`：

1. **编写或运行一个使用 `EmbeddedTestServer` 的 Chromium 网络栈的测试用例。** 这个测试用例可能模拟一个客户端向服务器发送 HTTP/2 请求。
2. **设置断点在 `http2_connection.cc` 的关键函数上，例如 `HandleData`, `OnHeaderForStream`, `OnDataForStream`, `ResponseDelegate::SendResponseHeaders`, `ResponseDelegate::SendContents`。**
3. **运行测试用例。** 当测试用例执行到设置的断点时，调试器会暂停，允许开发者检查当前的状态。
4. **观察 `Http2Connection` 接收到的原始数据 (`read_buf_`)。** 开发者可以查看接收到的 HTTP/2 帧的内容，以确认客户端发送的数据是否正确。
5. **单步执行 `adapter_->ProcessBytes`，观察 HTTP/2 适配器如何解析帧。** 开发者可以了解请求是如何被分解成头部和数据的。
6. **检查 `request_map_` 的内容，查看解析出的 HTTP 请求头信息。**  确认头部是否被正确解析。
7. **观察 `ResponseDelegate` 如何构建响应。** 开发者可以检查将要发送的响应头和响应体是否符合预期。
8. **单步执行数据发送过程 (`OnReadyToSend`, `SendInternal`)。** 开发者可以查看数据是如何通过 socket 发送出去的。
9. **使用网络抓包工具 (如 Wireshark) 捕获客户端和服务器之间的网络流量。**  这可以提供更底层的视角，查看实际发送和接收的 HTTP/2 帧。

通过以上步骤，开发者可以深入了解 HTTP/2 连接的处理过程，定位问题所在，例如客户端请求格式错误、服务器响应生成错误、或者底层的 HTTP/2 协议交互问题。 `http2_connection.cc` 作为一个模拟 HTTP/2 服务器连接的核心组件，是调试这类问题的关键入口点之一。

### 提示词
```
这是目录为net/test/embedded_test_server/http2_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/embedded_test_server/http2_connection.h"

#include <memory>
#include <string_view>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/raw_ref.h"
#include "base/strings/strcat.h"
#include "base/task/sequenced_task_runner.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_status_code.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/ssl_info.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"

namespace net {

namespace {

std::vector<http2::adapter::Header> GenerateHeaders(HttpStatusCode status,
                                                    base::StringPairs headers) {
  std::vector<http2::adapter::Header> response_vector;
  response_vector.emplace_back(
      http2::adapter::HeaderRep(std::string(":status")),
      http2::adapter::HeaderRep(base::NumberToString(status)));
  for (const auto& header : headers) {
    // Connection (and related) headers are considered malformed and will
    // result in a client error
    if (base::EqualsCaseInsensitiveASCII(header.first, "connection"))
      continue;
    response_vector.emplace_back(
        http2::adapter::HeaderRep(base::ToLowerASCII(header.first)),
        http2::adapter::HeaderRep(header.second));
  }

  return response_vector;
}

}  // namespace

namespace test_server {

class Http2Connection::DataFrameSource
    : public http2::adapter::DataFrameSource {
 public:
  explicit DataFrameSource(Http2Connection* connection,
                           const StreamId& stream_id)
      : connection_(connection), stream_id_(stream_id) {}
  ~DataFrameSource() override = default;
  DataFrameSource(const DataFrameSource&) = delete;
  DataFrameSource& operator=(const DataFrameSource&) = delete;

  std::pair<int64_t, bool> SelectPayloadLength(size_t max_length) override {
    if (chunks_.empty())
      return {kBlocked, last_frame_};

    bool finished = (chunks_.size() <= 1) &&
                    (chunks_.front().size() <= max_length) && last_frame_;

    return {std::min(chunks_.front().size(), max_length), finished};
  }

  bool Send(std::string_view frame_header, size_t payload_length) override {
    std::string concatenated =
        base::StrCat({frame_header, chunks_.front().substr(0, payload_length)});
    const int64_t result = connection_->OnReadyToSend(concatenated);
    // Write encountered error.
    if (result < 0) {
      connection_->OnConnectionError(ConnectionError::kSendError);
      return false;
    }

    // Write blocked.
    if (result == 0) {
      connection_->blocked_streams_.insert(*stream_id_);
      return false;
    }

    if (static_cast<const size_t>(result) < concatenated.size()) {
      // Probably need to handle this better within this test class.
      QUICHE_LOG(DFATAL)
          << "DATA frame not fully flushed. Connection will be corrupt!";
      connection_->OnConnectionError(ConnectionError::kSendError);
      return false;
    }

    chunks_.front().erase(0, payload_length);

    if (chunks_.front().empty())
      chunks_.pop();

    if (chunks_.empty() && send_completion_callback_) {
      std::move(send_completion_callback_).Run();
    }

    return true;
  }

  bool send_fin() const override { return true; }

  void AddChunk(std::string chunk) { chunks_.push(std::move(chunk)); }
  void set_last_frame(bool last_frame) { last_frame_ = last_frame; }
  void SetSendCompletionCallback(base::OnceClosure callback) {
    send_completion_callback_ = std::move(callback);
  }

 private:
  const raw_ptr<Http2Connection> connection_;
  const raw_ref<const StreamId, DanglingUntriaged> stream_id_;
  std::queue<std::string> chunks_;
  bool last_frame_ = false;
  base::OnceClosure send_completion_callback_;
};

// Corresponds to an HTTP/2 stream
class Http2Connection::ResponseDelegate : public HttpResponseDelegate {
 public:
  ResponseDelegate(Http2Connection* connection, StreamId stream_id)
      : stream_id_(stream_id), connection_(connection) {}
  ~ResponseDelegate() override = default;
  ResponseDelegate(const ResponseDelegate&) = delete;
  ResponseDelegate& operator=(const ResponseDelegate&) = delete;

  void AddResponse(std::unique_ptr<HttpResponse> response) override {
    responses_.push_back(std::move(response));
  }

  void SendResponseHeaders(HttpStatusCode status,
                           const std::string& status_reason,
                           const base::StringPairs& headers) override {
    std::unique_ptr<DataFrameSource> data_frame =
        std::make_unique<DataFrameSource>(connection_, stream_id_);
    data_frame_ = data_frame.get();
    connection_->adapter()->SubmitResponse(
        stream_id_, GenerateHeaders(status, headers), std::move(data_frame),
        /*end_stream=*/false);
    connection_->SendIfNotProcessing();
  }

  void SendRawResponseHeaders(const std::string& headers) override {
    scoped_refptr<HttpResponseHeaders> parsed_headers =
        HttpResponseHeaders::TryToCreate(headers);
    if (parsed_headers->response_code() == 0) {
      connection_->OnConnectionError(ConnectionError::kParseError);
      LOG(ERROR) << "raw headers could not be parsed";
    }
    base::StringPairs header_pairs;
    size_t iter = 0;
    std::string key, value;
    while (parsed_headers->EnumerateHeaderLines(&iter, &key, &value))
      header_pairs.emplace_back(key, value);
    SendResponseHeaders(
        static_cast<HttpStatusCode>(parsed_headers->response_code()),
        /*status_reason=*/"", header_pairs);
  }

  void SendContents(const std::string& contents,
                    base::OnceClosure callback) override {
    DCHECK(data_frame_);
    data_frame_->AddChunk(contents);
    data_frame_->SetSendCompletionCallback(std::move(callback));
    connection_->adapter()->ResumeStream(stream_id_);
    connection_->SendIfNotProcessing();
  }

  void FinishResponse() override {
    data_frame_->set_last_frame(true);
    connection_->adapter()->ResumeStream(stream_id_);
    connection_->SendIfNotProcessing();
  }

  void SendContentsAndFinish(const std::string& contents) override {
    data_frame_->set_last_frame(true);
    SendContents(contents, base::DoNothing());
  }

  void SendHeadersContentAndFinish(HttpStatusCode status,
                                   const std::string& status_reason,
                                   const base::StringPairs& headers,
                                   const std::string& contents) override {
    std::unique_ptr<DataFrameSource> data_frame =
        std::make_unique<DataFrameSource>(connection_, stream_id_);
    data_frame->AddChunk(contents);
    data_frame->set_last_frame(true);
    connection_->adapter()->SubmitResponse(
        stream_id_, GenerateHeaders(status, headers), std::move(data_frame),
        /*end_stream=*/false);
    connection_->SendIfNotProcessing();
  }
  base::WeakPtr<ResponseDelegate> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

 private:
  std::vector<std::unique_ptr<HttpResponse>> responses_;
  StreamId stream_id_;
  const raw_ptr<Http2Connection> connection_;
  raw_ptr<DataFrameSource, DanglingUntriaged> data_frame_;
  base::WeakPtrFactory<ResponseDelegate> weak_factory_{this};
};

Http2Connection::Http2Connection(
    std::unique_ptr<StreamSocket> socket,
    EmbeddedTestServerConnectionListener* connection_listener,
    EmbeddedTestServer* embedded_test_server)
    : socket_(std::move(socket)),
      connection_listener_(connection_listener),
      embedded_test_server_(embedded_test_server),
      read_buf_(base::MakeRefCounted<IOBufferWithSize>(4096)) {
  http2::adapter::OgHttp2Adapter::Options options;
  options.perspective = http2::adapter::Perspective::kServer;
  adapter_ = http2::adapter::OgHttp2Adapter::Create(*this, options);
}

Http2Connection::~Http2Connection() = default;

void Http2Connection::OnSocketReady() {
  ReadData();
}

void Http2Connection::ReadData() {
  while (true) {
    int rv = socket_->Read(
        read_buf_.get(), read_buf_->size(),
        base::BindOnce(&Http2Connection::OnDataRead, base::Unretained(this)));
    if (rv == ERR_IO_PENDING)
      return;
    if (!HandleData(rv))
      return;
  }
}

void Http2Connection::OnDataRead(int rv) {
  if (HandleData(rv))
    ReadData();
}

bool Http2Connection::HandleData(int rv) {
  if (rv <= 0) {
    embedded_test_server_->RemoveConnection(this);
    return false;
  }

  if (connection_listener_)
    connection_listener_->ReadFromSocket(*socket_, rv);

  std::string_view remaining_buffer(read_buf_->data(), rv);
  while (!remaining_buffer.empty()) {
    int result = adapter_->ProcessBytes(remaining_buffer);
    if (result < 0)
      return false;
    remaining_buffer = remaining_buffer.substr(result);
  }

  // Any frames and data sources will be queued up and sent all at once below
  DCHECK(!processing_responses_);
  processing_responses_ = true;
  while (!ready_streams_.empty()) {
    StreamId stream_id = ready_streams_.front();
    ready_streams_.pop();
    auto delegate = std::make_unique<ResponseDelegate>(this, stream_id);
    ResponseDelegate* delegate_ptr = delegate.get();
    response_map_[stream_id] = std::move(delegate);
    embedded_test_server_->HandleRequest(delegate_ptr->GetWeakPtr(),
                                         std::move(request_map_[stream_id]),
                                         socket_.get());
    request_map_.erase(stream_id);
  }
  adapter_->Send();
  processing_responses_ = false;
  return true;
}

StreamSocket* Http2Connection::Socket() {
  return socket_.get();
}

std::unique_ptr<StreamSocket> Http2Connection::TakeSocket() {
  return std::move(socket_);
}

base::WeakPtr<HttpConnection> Http2Connection::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

int64_t Http2Connection::OnReadyToSend(std::string_view serialized) {
  if (write_buf_)
    return kSendBlocked;

  write_buf_ = base::MakeRefCounted<DrainableIOBuffer>(
      base::MakeRefCounted<StringIOBuffer>(std::string(serialized)),
      serialized.size());
  SendInternal();
  return serialized.size();
}

bool Http2Connection::OnCloseStream(StreamId stream_id,
                                    http2::adapter::Http2ErrorCode error_code) {
  response_map_.erase(stream_id);
  return true;
}

void Http2Connection::SendInternal() {
  DCHECK(socket_);
  DCHECK(write_buf_);
  while (write_buf_->BytesRemaining() > 0) {
    int rv = socket_->Write(write_buf_.get(), write_buf_->BytesRemaining(),
                            base::BindOnce(&Http2Connection::OnSendInternalDone,
                                           base::Unretained(this)),
                            TRAFFIC_ANNOTATION_FOR_TESTS);
    if (rv == ERR_IO_PENDING)
      return;

    if (rv < 0) {
      embedded_test_server_->RemoveConnection(this);
      break;
    }

    write_buf_->DidConsume(rv);
  }
  write_buf_ = nullptr;
}

void Http2Connection::OnSendInternalDone(int rv) {
  DCHECK(write_buf_);
  if (rv < 0) {
    embedded_test_server_->RemoveConnection(this);
    write_buf_ = nullptr;
    return;
  }
  write_buf_->DidConsume(rv);

  SendInternal();

  if (!write_buf_) {
    // Now that writing is no longer blocked, any blocked streams can be
    // resumed.
    for (const auto& stream_id : blocked_streams_)
      adapter_->ResumeStream(stream_id);

    if (adapter_->want_write()) {
      base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&Http2Connection::SendIfNotProcessing,
                                    weak_factory_.GetWeakPtr()));
    }
  }
}

void Http2Connection::SendIfNotProcessing() {
  if (!processing_responses_) {
    processing_responses_ = true;
    adapter_->Send();
    processing_responses_ = false;
  }
}

http2::adapter::Http2VisitorInterface::OnHeaderResult
Http2Connection::OnHeaderForStream(http2::adapter::Http2StreamId stream_id,
                                   std::string_view key,
                                   std::string_view value) {
  header_map_[stream_id][std::string(key)] = std::string(value);
  return http2::adapter::Http2VisitorInterface::HEADER_OK;
}

bool Http2Connection::OnEndHeadersForStream(
    http2::adapter::Http2StreamId stream_id) {
  HttpRequest::HeaderMap header_map = header_map_[stream_id];
  auto request = std::make_unique<HttpRequest>();
  // TODO(crbug.com/40242862): Handle proxy cases.
  request->relative_url = header_map[":path"];
  request->base_url = GURL(header_map[":authority"]);
  request->method_string = header_map[":method"];
  request->method = HttpRequestParser::GetMethodType(request->method_string);
  request->headers = header_map;

  request->has_content = false;

  SSLInfo ssl_info;
  DCHECK(socket_->GetSSLInfo(&ssl_info));
  request->ssl_info = ssl_info;
  request_map_[stream_id] = std::move(request);

  return true;
}

bool Http2Connection::OnEndStream(http2::adapter::Http2StreamId stream_id) {
  ready_streams_.push(stream_id);
  return true;
}

bool Http2Connection::OnFrameHeader(StreamId /*stream_id*/,
                                    size_t /*length*/,
                                    uint8_t /*type*/,
                                    uint8_t /*flags*/) {
  return true;
}

bool Http2Connection::OnBeginHeadersForStream(StreamId stream_id) {
  return true;
}

bool Http2Connection::OnBeginDataForStream(StreamId stream_id,
                                           size_t payload_length) {
  return true;
}

bool Http2Connection::OnDataForStream(StreamId stream_id,
                                      std::string_view data) {
  auto request = request_map_.find(stream_id);
  if (request == request_map_.end()) {
    // We should not receive data before receiving headers.
    return false;
  }

  request->second->has_content = true;
  request->second->content.append(data);
  adapter_->MarkDataConsumedForStream(stream_id, data.size());
  return true;
}

bool Http2Connection::OnDataPaddingLength(StreamId stream_id,
                                          size_t padding_length) {
  adapter_->MarkDataConsumedForStream(stream_id, padding_length);
  return true;
}

bool Http2Connection::OnGoAway(StreamId last_accepted_stream_id,
                               http2::adapter::Http2ErrorCode error_code,
                               std::string_view opaque_data) {
  return true;
}

int Http2Connection::OnBeforeFrameSent(uint8_t frame_type,
                                       StreamId stream_id,
                                       size_t length,
                                       uint8_t flags) {
  return 0;
}

int Http2Connection::OnFrameSent(uint8_t frame_type,
                                 StreamId stream_id,
                                 size_t length,
                                 uint8_t flags,
                                 uint32_t error_code) {
  return 0;
}

bool Http2Connection::OnInvalidFrame(StreamId stream_id,
                                     InvalidFrameError error) {
  return true;
}

bool Http2Connection::OnMetadataForStream(StreamId stream_id,
                                          std::string_view metadata) {
  return true;
}

bool Http2Connection::OnMetadataEndForStream(StreamId stream_id) {
  return true;
}

}  // namespace test_server

}  // namespace net
```