Response:
My thinking process to address the prompt about `net/http/http_stream_parser.cc` goes like this:

1. **Understand the Core Function:** The filename and the initial comments clearly indicate this file is responsible for parsing HTTP streams. This means it handles the raw bytes coming from a network connection and interprets them as HTTP headers and body.

2. **Break Down Functionality by Examining the Code (First Pass):**  I'd quickly scan the code, looking for key classes, methods, and member variables. This gives a high-level understanding of what the parser *does*. I'd notice things like:
    * `SendRequest`:  Handles sending the HTTP request.
    * `ReadResponseHeaders`:  Handles reading and parsing the response headers.
    * `ReadResponseBody`: Handles reading the response body.
    * State machine (`io_state_`):  Manages the different stages of the parsing process.
    * Buffers (`read_buf_`, `request_headers_`, `request_body_send_buf_`): Used to store and manipulate data.
    * Handling of chunked encoding (`HttpChunkedDecoder`).
    * Handling of content length.
    * Error handling.
    * Logging (`NetLog`).

3. **Categorize Functionality:**  Based on the code scan, I'd group the functionalities into logical categories:
    * **Sending Requests:**  Formatting and sending headers and bodies.
    * **Receiving Responses:**  Reading and parsing headers, decoding the body (chunked, content-length).
    * **State Management:**  Keeping track of the parsing progress.
    * **Buffering:** Managing the incoming and outgoing data.
    * **Error Handling:**  Dealing with network and parsing errors.
    * **Logging:** Recording events for debugging and analysis.

4. **Address Specific Prompt Questions:** Now I'd go through each part of the prompt:

    * **List the functions:**  This is mostly done in step 2. I'd list the key public methods and some important internal ones.

    * **Relationship to JavaScript:** This requires understanding how the network stack interacts with the browser's rendering engine. JavaScript makes network requests (e.g., using `fetch` or `XMLHttpRequest`). The browser's networking code (including this parser) handles the actual low-level communication. I'd focus on how the parsed information (headers, body) is ultimately used by JavaScript.

    * **Logical Reasoning (Input/Output):** I'd choose a simple scenario (like a basic GET request) and trace the data flow. I'd consider:
        * **Input:** Raw bytes from the socket.
        * **Processing:** Parsing the status line, headers, and body based on headers.
        * **Output:**  Parsed headers (key-value pairs), the response body (as a stream of bytes).

    * **User/Programming Errors:**  I'd think about common mistakes that could lead to issues in this part of the code. Examples:
        * **Server-side errors:** Incorrect headers, broken chunked encoding.
        * **Client-side errors (less direct):**  While the user doesn't directly interact with this code, their actions (e.g., requesting a large file on a slow connection) can expose issues. A programmer might misinterpret error codes returned by this parser.

    * **User Operation as Debugging Clue:** I'd illustrate how a user action (like clicking a link) triggers a series of events that eventually lead to this code being executed. This emphasizes the role of this parser in the overall browser workflow.

    * **Summarize Functionality (Part 1):** This is essentially a concise version of the categorized functionalities from step 3, focusing on the aspects covered in the provided code snippet (which is primarily about sending requests).

5. **Refine and Elaborate:** After the initial pass, I'd review my answers, adding more detail, concrete examples, and clearer explanations. I'd make sure the language is precise and avoids jargon where possible. I would refer back to the code snippet to ensure my understanding is grounded in the provided source. For instance, noticing the merging of headers and body would be a key detail to include.

6. **Structure the Answer:** I'd organize the information logically, using headings and bullet points to make it easy to read and understand. I'd address each part of the prompt explicitly.

By following these steps, I aim to provide a comprehensive and accurate answer that addresses all aspects of the prompt, drawing directly from the provided code and my understanding of the Chromium networking stack.
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_parser.h"

#include <algorithm>
#include <memory>
#include <string_view>
#include <utility>

#include "base/check.h"
#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/containers/span_writer.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/clamped_math.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/upload_data_stream.h"
#include "net/http/http_chunked_decoder.h"
#include "net/http/http_connection_info.h"
#include "net/http/http_log_util.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/http/http_util.h"
#include "net/log/net_log_event_type.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_info.h"
#include "url/gurl.h"
#include "url/url_canon.h"

namespace net {

namespace {

const uint64_t kMaxMergedHeaderAndBodySize = 1400;
const size_t kRequestBodyBufferSize = 1 << 14;  // 16KB

std::string GetResponseHeaderLines(const HttpResponseHeaders& headers) {
  std::string cr_separated_headers;
  base::StringTokenizer tokenizer(headers.raw_headers(), std::string(1, '\0'));
  while (tokenizer.GetNext()) {
    base::StrAppend(&cr_separated_headers, {tokenizer.token_piece(), "\n"});
  }
  return cr_separated_headers;
}

base::Value::Dict NetLogSendRequestBodyParams(uint64_t length,
                                              bool is_chunked,
                                              bool did_merge) {
  base::Value::Dict dict;
  dict.Set("length", static_cast<int>(length));
  dict.Set("is_chunked", is_chunked);
  dict.Set("did_merge", did_merge);
  return dict;
}

void NetLogSendRequestBody(const NetLogWithSource& net_log,
                           uint64_t length,
                           bool is_chunked,
                           bool did_merge) {
  net_log.AddEvent(NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST_BODY, [&] {
    return NetLogSendRequestBodyParams(length, is_chunked, did_merge);
  });
}

// Returns true if |error_code| is an error for which we give the server a
// chance to send a body containing error information, if the error was received
// while trying to upload a request body.
bool ShouldTryReadingOnUploadError(int error_code) {
  return (error_code == ERR_CONNECTION_RESET);
}

}  // namespace

// Similar to DrainableIOBuffer(), but this version comes with its own
// storage. The motivation is to avoid repeated allocations of
// DrainableIOBuffer.
//
// Example:
//
// scoped_refptr<SeekableIOBuffer> buf =
//     base::MakeRefCounted<SeekableIOBuffer>(1024);
// // capacity() == 1024. size() == BytesRemaining() == BytesConsumed() == 0.
// // data() points to the beginning of the buffer.
//
// // Read() takes an IOBuffer.
// int bytes_read = some_reader->Read(buf, buf->capacity());
// buf->DidAppend(bytes_read);
// // size() == BytesRemaining() == bytes_read. data() is unaffected.
//
// while (buf->BytesRemaining() > 0) {
//   // Write() takes an IOBuffer. If it takes const char*, we could
///  // simply use the regular IOBuffer like buf->data() + offset.
//   int bytes_written = Write(buf, buf->BytesRemaining());
//   buf->DidConsume(bytes_written);
// }
// // BytesRemaining() == 0. BytesConsumed() == size().
// // data() points to the end of the consumed bytes (exclusive).
//
// // If you want to reuse the buffer, be sure to clear the buffer.
// buf->Clear();
// // size() == BytesRemaining() == BytesConsumed() == 0.
// // data() points to the beginning of the buffer.
//
class HttpStreamParser::SeekableIOBuffer : public IOBufferWithSize {
 public:
  explicit SeekableIOBuffer(int capacity)
      : IOBufferWithSize(capacity), real_data_(data_), capacity_(capacity) {}

  // DidConsume() changes the |data_| pointer so that |data_| always points
  // to the first unconsumed byte.
  void DidConsume(int bytes) {
    SetOffset(used_ + bytes);
  }

  // Returns the number of unconsumed bytes.
  int BytesRemaining() const {
    return size_ - used_;
  }

  // Seeks to an arbitrary point in the buffer. The notion of bytes consumed
  // and remaining are updated appropriately.
  void SetOffset(int bytes) {
    DCHECK_GE(bytes, 0);
    DCHECK_LE(bytes, size_);
    used_ = bytes;
    data_ = real_data_ + used_;
  }

  // Called after data is added to the buffer. Adds |bytes| added to
  // |size_|. data() is unaffected.
  void DidAppend(int bytes) {
    DCHECK_GE(bytes, 0);
    DCHECK_GE(size_ + bytes, 0);
    DCHECK_LE(size_ + bytes, capacity_);
    size_ += bytes;
  }

  // Changes the logical size to 0, and the offset to 0.
  void Clear() {
    size_ = 0;
    SetOffset(0);
  }

  // Returns the logical size of the buffer (i.e the number of bytes of data
  // in the buffer).
  int size() const { return size_; }

  // Returns the capacity of the buffer. The capacity is the size used when
  // the object is created.
  int capacity() const { return capacity_; }

 private:
  ~SeekableIOBuffer() override {
    // data_ will be deleted in IOBuffer::~IOBuffer().
    data_ = real_data_;
  }

  raw_ptr<char, AllowPtrArithmetic> real_data_;
  const int capacity_;
  int size_ = 0;
  int used_ = 0;
};

// 2 CRLFs + max of 8 hex chars.
const size_t HttpStreamParser::kChunkHeaderFooterSize = 12;

HttpStreamParser::HttpStreamParser(StreamSocket* stream_socket,
                                   bool connection_is_reused,
                                   const GURL& url,
                                   const std::string& method,
                                   UploadDataStream* upload_data_stream,
                                   GrowableIOBuffer* read_buffer,
                                   const NetLogWithSource& net_log)
    : url_(url),
      method_(method),
      upload_data_stream_(upload_data_stream),
      read_buf_(read_buffer),
      response_header_start_offset_(std::string::npos),
      stream_socket_(stream_socket),
      connection_is_reused_(connection_is_reused),
      net_log_(net_log),
      truncate_to_content_length_enabled_(base::FeatureList::IsEnabled(
          features::kTruncateBodyToContentLength)) {
  io_callback_ = base::BindRepeating(&HttpStreamParser::OnIOComplete,
                                     weak_ptr_factory_.GetWeakPtr());
}

HttpStreamParser::~HttpStreamParser() = default;

int HttpStreamParser::SendRequest(
    const std::string& request_line,
    const HttpRequestHeaders& headers,
    const NetworkTrafficAnnotationTag& traffic_annotation,
    HttpResponseInfo* response,
    CompletionOnceCallback callback) {
  DCHECK_EQ(STATE_NONE, io_state_);
  DCHECK(callback_.is_null());
  DCHECK(!callback.is_null());
  DCHECK(response);

  NetLogRequestHeaders(net_log_,
                       NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST_HEADERS,
                       request_line, &headers);

  DVLOG(1) << __func__ << "() request_line = \"" << request_line << "\""
           << " headers = \"" << headers.ToString() << "\"";
  traffic_annotation_ = MutableNetworkTrafficAnnotationTag(traffic_annotation);
  response_ = response;

  // Put the peer's IP address and port into the response.
  IPEndPoint ip_endpoint;
  int result = stream_socket_->GetPeerAddress(&ip_endpoint);
  if (result != OK)
    return result;
  response_->remote_endpoint = ip_endpoint;

  std::string request = request_line + headers.ToString();
  request_headers_length_ = request.size();

  if (upload_data_stream_) {
    request_body_send_buf_ =
        base::MakeRefCounted<SeekableIOBuffer>(kRequestBodyBufferSize);
    if (upload_data_stream_->is_chunked()) {
      // Read buffer is adjusted to guarantee that |request_body_send_buf_| is
      // large enough to hold the encoded chunk.
      request_body_read_buf_ = base::MakeRefCounted<SeekableIOBuffer>(
          kRequestBodyBufferSize - kChunkHeaderFooterSize);
    } else {
      // No need to encode request body, just send the raw data.
      request_body_read_buf_ = request_body_send_buf_;
    }
  }

  io_state_ = STATE_SEND_HEADERS;

  // If we have a small request body, then we'll merge with the headers into a
  // single write.
  bool did_merge = false;
  if (ShouldMergeRequestHeadersAndBody(request, upload_data_stream_)) {
    int merged_size =
        static_cast<int>(request_headers_length_ + upload_data_stream_->size());
    auto merged_request_headers_and_body =
        base::MakeRefCounted<IOBufferWithSize>(merged_size);
    // We'll repurpose |request_headers_| to store the merged headers and
    // body.
    request_headers_ = base::MakeRefCounted<DrainableIOBuffer>(
        merged_request_headers_and_body, merged_size);

    memcpy(request_headers_->data(), request.data(), request_headers_length_);
    request_headers_->DidConsume(request_headers_length_);

    uint64_t todo = upload_data_stream_->size();
    while (todo) {
      int consumed = upload_data_stream_->Read(request_headers_.get(),
                                               static_cast<int>(todo),
                                               CompletionOnceCallback());
      // Read() must succeed synchronously if not chunked and in memory.
      DCHECK_GT(consumed, 0);
      request_headers_->DidConsume(consumed);
      todo -= consumed;
    }
    DCHECK(upload_data_stream_->IsEOF());
    // Reset the offset, so the buffer can be read from the beginning.
    request_headers_->SetOffset(0);
    did_merge = true;

    NetLogSendRequestBody(net_log_, upload_data_stream_->size(),
                          false, /* not chunked */
                          true /* merged */);
  }

  if (!did_merge) {
    // If we didn't merge the body with the headers, then |request_headers_|
    // contains just the HTTP headers.
    size_t request_size = request.size();
    scoped_refptr<StringIOBuffer> headers_io_buf =
        base::MakeRefCounted<StringIOBuffer>(std::move(request));
    request_headers_ = base::MakeRefCounted<DrainableIOBuffer>(
        std::move(headers_io_buf), request_size);
  }

  result = DoLoop(OK);
  if (result == ERR_IO_PENDING)
    callback_ = std::move(callback);

  return result > 0 ? OK : result;
}

int HttpStreamParser::ConfirmHandshake(CompletionOnceCallback callback) {
  // This function is not covered in the provided part 1.
  return ERR_NOT_IMPLEMENTED;
}

int HttpStreamParser::ReadResponseHeaders(CompletionOnceCallback callback) {
  // This function is not covered in the provided part 1.
  return ERR_NOT_IMPLEMENTED;
}

int HttpStreamParser::ReadResponseBody(IOBuffer* buf,
                                       int buf_len,
                                       CompletionOnceCallback callback) {
  // This function is not covered in the provided part 1.
  return ERR_NOT_IMPLEMENTED;
}

void HttpStreamParser::OnIOComplete(int result) {
  // This function is not fully covered in the provided part 1, but the basic mechanism is present.
  result = DoLoop(result);

  // The client callback can do anything, including destroying this class,
  // so any pending callback must be issued after everything else is done.
  if (result != ERR_IO_PENDING && !callback_.is_null()) {
    std::move(callback_).Run(result);
  }
}

int HttpStreamParser::DoLoop(int result) {
  do {
    DCHECK_NE(ERR_IO_PENDING, result);
    DCHECK_NE(STATE_DONE, io_state_);
    DCHECK_NE(STATE_NONE, io_state_);
    State state = io_state_;
    io_state_ = STATE_NONE;
    switch (state) {
      case STATE_SEND_HEADERS:
        DCHECK_EQ(OK, result);
        result = DoSendHeaders();
        DCHECK_NE(STATE_NONE, io_state_);
        break;
      case STATE_SEND_HEADERS_COMPLETE:
        result = DoSendHeadersComplete(result);
        DCHECK_NE(STATE_NONE, io_state_);
        break;
      case STATE_SEND_BODY:
        DCHECK_EQ(OK, result);
        result = DoSendBody();
        DCHECK_NE(STATE_NONE, io_state_);
        break;
      case STATE_SEND_BODY_COMPLETE:
        result = DoSendBodyComplete(result);
        DCHECK_NE(STATE_NONE, io_state_);
        break;
      case STATE_SEND_REQUEST_READ_BODY_COMPLETE:
        result = DoSendRequestReadBodyComplete(result);
        DCHECK_NE(STATE_NONE, io_state_);
        break;
      case STATE_SEND_REQUEST_COMPLETE:
        result = DoSendRequestComplete(result);
        break;
      case STATE_READ_HEADERS:
      case STATE_READ_HEADERS_COMPLETE:
      case STATE_READ_BODY:
      case STATE_READ_BODY_COMPLETE:
        // These states are not covered in part 1.
        NOTREACHED();
        break;
      default:
        NOTREACHED();
    }
  } while (result != ERR_IO_PENDING &&
           (io_state_ != STATE_DONE && io_state_ != STATE_NONE));

  return result;
}

int HttpStreamParser::DoSendHeaders() {
  int bytes_remaining = request_headers_->BytesRemaining();
  DCHECK_GT(bytes_remaining, 0);

  // Record our best estimate of the 'request time' as the time when we send
  // out the first bytes of the request headers.
  if (bytes_remaining == request_headers_->size())
    response_->request_time = base::Time::Now();

  io_state_ = STATE_SEND_HEADERS_COMPLETE;
  return stream_socket_->Write(
      request_headers_.get(), bytes_remaining, io_callback_,
      NetworkTrafficAnnotationTag(traffic_annotation_));
}

int HttpStreamParser::DoSendHeadersComplete(int result) {
  if (result < 0) {
    // In the unlikely case that the headers and body were merged, all the
    // the headers were sent, but not all of the body way, and |result| is
    // an error that this should try reading after, stash the error for now and
    // act like the request was successfully sent.
    io_state_ = STATE_SEND_REQUEST_COMPLETE;
    if (request_headers_->BytesConsumed() >= request_headers_length_ &&
        ShouldTryReadingOnUploadError(result)) {
      upload_error_ = result;
      return OK;
    }
    return result;
  }

  sent_bytes_ += result;
  request_headers_->DidConsume(result);
  if (request_headers_->BytesRemaining() > 0) {
    io_state_ = STATE_SEND_HEADERS;
    return OK;
  }

  if (upload_data_stream_ &&
      (upload_data_stream_->is_chunked() ||
       // !IsEOF() indicates that the body wasn't merged.
       (upload_data_stream_->size() > 0 && !upload_data_stream_->IsEOF()))) {
    NetLogSendRequestBody(net_log_, upload_data_stream_->size(),
                          upload_data_stream_->is_chunked(),
                          false /* not merged */);
    io_state_ = STATE_SEND_BODY;
    return OK;
  }

  // Finished sending the request.
  io_state_ = STATE_SEND_REQUEST_COMPLETE;
  return OK;
}

int HttpStreamParser::DoSendBody() {
  if (request_body_send_buf_->BytesRemaining() > 0) {
    io_state_ = STATE_SEND_BODY_COMPLETE;
    return stream_socket_->Write(
        request_body_send_buf_.get(), request_body_send_buf_->BytesRemaining(),
        io_callback_, NetworkTrafficAnnotationTag(traffic_annotation_));
  }

  if (upload_data_stream_->is_chunked() && sent_last_chunk_) {
    // Finished sending the request.
    io_state_ = STATE_SEND_REQUEST_COMPLETE;
    return OK;
  }

  request_body_read_buf_->Clear();
  io_state_ = STATE_SEND_REQUEST_READ_BODY_COMPLETE;
  return upload_data_stream_->Read(
      request_body_read_buf_.get(), request_body_read_buf_->capacity(),
      base::BindOnce(&HttpStreamParser::OnIOComplete,
                     weak_ptr_factory_.GetWeakPtr()));
}

int HttpStreamParser::DoSendBodyComplete(int result) {
  if (result < 0) {
    // If |result| is an error that this should try reading after, stash the
    // error for now and act like the request was successfully sent.
    io_state_ = STATE_SEND_REQUEST_COMPLETE;
    if (ShouldTryReadingOnUploadError(result)) {
      upload_error_ = result;
      return OK;
    }
    return result;
  }

  sent_bytes_ += result;
  request_body_send_buf_->DidConsume(result);

  io_state_ = STATE_SEND_BODY;
  return OK;
}

int HttpStreamParser::DoSendRequestReadBodyComplete(int result) {
  // |result| is the result of read from the request body from the last call to
  // DoSendBody().
  if (result < 0) {
    io_state_ = STATE_SEND_REQUEST_COMPLETE;
    return result;
  }

  // Chunked data needs to be encoded.
  if (upload_data_stream_->is_chunked()) {
    if (result == 0) {  // Reached the end.
      DCHECK(upload_data_stream_->IsEOF());
      sent_last_chunk_ = true;
    }
    // Encode the buffer as 1 chunk.
    const std::string_view payload(request_body_read_buf_->data(), result);
    request_body_send_buf_->Clear();
    // Note: EncodeChunk implementation is not in this snippet.
    // Assuming it encodes the payload into the send buffer.
    // Placeholder for actual encoding logic.
    if (payload.size() > 0) {
      std::string chunk_header = base::StringPrintf("%zx\r\n", payload.size());
      memcpy(request_body_send_buf_->data(), chunk_header.data(), chunk_header.size());
      request_body_send_buf_->DidAppend(chunk_header.size());
      memcpy(request_body_send_buf_->data() + request_body_send_buf_->size(), payload.data(), payload.size());
      request_body_send_buf_->DidAppend(payload.size());
      memcpy(request_body_send_buf_->data() + request_body_send_buf_->size(), "\r\n", 2);
      request_body_send_buf_->DidAppend(2);
    }
  }

  if (result == 0) {  // Reached the end.
    // Reaching EOF means we can finish sending request body unless the data is
    // chunked. (i.e. No need to send the terminal chunk.)
    DCHECK(upload_data_stream_->IsEOF());
    DCHECK(!upload_data_stream_->is_chunked());
    // Finished sending the request.
    io_state_ = STATE_SEND_REQUEST_COMPLETE;
  } else if (result > 0) {
    request_body_send_buf_->DidAppend(result);
    result = 0;
    io_state_ = STATE_SEND_BODY;
  } else {
    // Handle encoding error if EncodeChunk failed (not shown in snippet)
  }
  return result;
}

int HttpStreamParser::DoSendRequestComplete(int result) {
  DCHECK_NE(result, ERR_IO_PENDING);
  request_headers_ = nullptr;
  upload_data_stream_ = nullptr;
  request_body_send_buf_ = nullptr;
  request_body_read_buf_ = nullptr;

  return result;
}

int HttpStreamParser::DoReadHeaders() {
  // This function is not covered in the provided part 1.
  return ERR_NOT_IMPLEMENTED;
}

int HttpStreamParser::DoReadHeadersComplete(int result) {
  // This function is not covered in the provided part 1.
  return ERR_NOT_IMPLEMENTED;
}

int HttpStreamParser::DoReadBody() {
  // This function is not covered in the provided part 1.
  return ERR_NOT_IMPLEMENTED;
}

int HttpStreamParser::DoReadBodyComplete(int result) {
  // This function is not covered in the provided part 1.
  return ERR_NOT_IMPLEMENTED;
}

int HttpStreamParser::HandleReadHeaderResult(int result) {
  // This function is not covered in the provided part 1.
  return ERR_NOT_IMPLEMENTED;
}

}  // namespace net
```

## 功能列举 (基于提供的第一部分代码)

`net/http/http_stream_parser.cc` 的主要功能是**构建并发送 HTTP 请求**。 它负责将请求头和请求体数据通过底层的 `StreamSocket` 发送到服务器。

更具体地说，从提供的代码来看，它执行以下操作：

1. **管理请求发送状态:** 使用状态机 (`io_state_`) 来跟踪请求发送的不同阶段，例如发送头部、发送主体等。
2. **构建请求头:** 接收请求行和 `HttpRequestHeaders` 对象，并将它们组合成要发送的字符串。
3. **处理请求体:**
    * 接收 `UploadDataStream` 对象，该对象提供要发送的请求体数据。
    * 支持发送分块编码 (chunked) 的请求体。
    * 可以将小的请求体与请求头合并到一个写入操作中以提高效率。
4. **使用 SeekableIOBuffer:** 自定义了一个 `SeekableIOBuffer` 类，用于高效地管理和操作请求体数据。这个 buffer 允许在 buffer 中“seek”，避免重复分配内存。
5. **网络写入:** 使用底层的 `StreamSocket` 的 `Write` 方法将请求头和请求体数据发送到服务器。
6. **合并请求头和请求体:**  对于小的请求体，代码尝试将请求头和请求体合并成一个单一的写操作，以减少系统调用和提高性能。
7. **记录网络日志:** 使用 `NetLog` 记录请求发送的相关信息，例如请求体长度、是否分块、是否合并等，用于调试和监控。
8. **处理发送错误:**  在发送请求的过程中如果发生错误，会进行相应的处理。对于某些特定的错误 (例如 `ERR_CONNECTION_RESET`)，会尝试读取服务器可能返回的错误信息。

## 与 JavaScript 功能的关系及举例

`net/http/http_stream_parser.cc` 位于 Chromium 的网络栈中，它处理浏览器与服务器之间的底层 HTTP 通信。JavaScript 代码（在浏览器中运行）通过 Web API (例如 `fetch` 或 `XMLHttpRequest`) 发起网络请求。

**关系：**

当 JavaScript 代码执行 `fetch` 或 `XMLHttpRequest` 发起一个 HTTP 请求时，浏览器内核会将该请求传递到网络栈。`HttpStreamParser` 就是网络栈中负责实际发送请求的关键组件之一。

**举例说明：**

假设以下 JavaScript 代码发起一个 POST 请求：

```javascript
fetch('https://example.com/api/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ key: 'value' })
});
```

**用户操作如何到达这里：**

1. **用户在浏览器中执行了 JavaScript 代码**，例如，通过访问一个包含上述代码的网页，或在浏览器的开发者工具控制台中运行代码。
2. **JavaScript 代码调用 `fetch` API**，并指定了请求方法、URL、头部和请求体。
3. **浏览器内核接收到这个请求信息**，并开始构建底层的 HTTP 请求。
4. **网络栈被调用来处理这个请求。**
5. **`HttpStreamParser` 被创建或复用**，并接收请求的 URL、方法、头部以及请求体数据（封装在 `UploadDataStream` 中）。
6. **`SendRequest` 方法被调用**，开始执行发送请求的流程，包括构建请求头、处理请求体，并通过 `StreamSocket` 发送到服务器。

**`HttpStreamParser` 在此过程中的作用：**

* 它会根据 JavaScript 提供的 `headers` 对象构建 `HttpRequestHeaders`。
* 它会将 `JSON.stringify({ key: 'value' })` 的结果作为请求体，并通过 `UploadDataStream` 提供。
* 如果请求体很小，`HttpStreamParser` 可能会选择将请求头和请求体合并发送，这在 `ShouldMergeRequestHeadersAndBody` 函数中判断。
* 它会使用 `StreamSocket` 将构建好的 HTTP 请求发送到 `example.com` 的服务器。
* 它会使用 `NetLog` 记录请求发送的详细信息，方便开发者调试。

## 逻辑推理、假设输入与输出

**假设输入：**

* `request_line`:  "POST /api/data HTTP/1.1\r\n"
* `headers`:  一个 `HttpRequestHeaders` 对象，包含 "Content-Type: application/json\r\n" 和 "Host: example.com\r\n" 等头部。
* `upload_data_stream`: 一个 `UploadDataStream` 对象，提供请求体数据 `{"key": "value"}`。假设这个请求体很小，可以被合并。
* `stream_socket_`: 一个已经连接到 `example.com` 服务器的 `StreamSocket` 对象。

**逻辑推理：**

1. `SendRequest` 方法被调用。
2. `ShouldMergeRequestHeadersAndBody` 函数返回 true，因为请求体很小。
3. 创建一个足够大的 `IOBufferWithSize` 来容纳合并后的请求头和请求体。
4. 将请求头字符串复制到 `request_headers_` (一个 `DrainableIOBuffer`)。
5. 从 `upload_data_stream` 中同步读取请求体数据并追加到 `request_headers_`。
6. 调用 `stream_socket_->Write` 方法，将合并后的请求头和请求体数据一次性发送出去。

**假设输出（通过 `stream_socket_->Write` 发送的数据）：**

```
POST /api/data HTTP/1.1\r\n
Content-Type: application/json\r\n
Host: example.com\r\n
\r\n
{"key": "value"}
```

## 用户或编程常见的使用错误

虽然用户不直接操作 `HttpStreamParser`，但编程错误可能导致其行为异常。

**举例说明：**

1. **服务器端错误导致解析失败:**  如果服务器返回的响应头部格式不正确（例如缺少必要的冒号或换行符），后续的响应解析器（在提供的代码片段之外）可能会出错。但这部分代码主要关注请求的发送。

2. **编程错误导致 `UploadDataStream` 状态不正确:** 如果程序员在使用 `UploadDataStream` 时没有正确处理其状态（例如，在发送前就标记为 EOF），`HttpStreamParser` 可能会发送空的请求体，或者进入错误的状态。

3. **网络连接问题:** 底层的 `StreamSocket` 可能会遇到连接中断或其他网络错误。`HttpStreamParser` 需要正确处理 `stream_socket_->Write` 返回的错误码。例如，如果连接在发送请求的过程中被重
### 提示词
```
这是目录为net/http/http_stream_parser.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_parser.h"

#include <algorithm>
#include <memory>
#include <string_view>
#include <utility>

#include "base/check.h"
#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/containers/span_writer.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/clamped_math.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/upload_data_stream.h"
#include "net/http/http_chunked_decoder.h"
#include "net/http/http_connection_info.h"
#include "net/http/http_log_util.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/http/http_util.h"
#include "net/log/net_log_event_type.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_info.h"
#include "url/gurl.h"
#include "url/url_canon.h"

namespace net {

namespace {

const uint64_t kMaxMergedHeaderAndBodySize = 1400;
const size_t kRequestBodyBufferSize = 1 << 14;  // 16KB

std::string GetResponseHeaderLines(const HttpResponseHeaders& headers) {
  std::string cr_separated_headers;
  base::StringTokenizer tokenizer(headers.raw_headers(), std::string(1, '\0'));
  while (tokenizer.GetNext()) {
    base::StrAppend(&cr_separated_headers, {tokenizer.token_piece(), "\n"});
  }
  return cr_separated_headers;
}

base::Value::Dict NetLogSendRequestBodyParams(uint64_t length,
                                              bool is_chunked,
                                              bool did_merge) {
  base::Value::Dict dict;
  dict.Set("length", static_cast<int>(length));
  dict.Set("is_chunked", is_chunked);
  dict.Set("did_merge", did_merge);
  return dict;
}

void NetLogSendRequestBody(const NetLogWithSource& net_log,
                           uint64_t length,
                           bool is_chunked,
                           bool did_merge) {
  net_log.AddEvent(NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST_BODY, [&] {
    return NetLogSendRequestBodyParams(length, is_chunked, did_merge);
  });
}

// Returns true if |error_code| is an error for which we give the server a
// chance to send a body containing error information, if the error was received
// while trying to upload a request body.
bool ShouldTryReadingOnUploadError(int error_code) {
  return (error_code == ERR_CONNECTION_RESET);
}

}  // namespace

// Similar to DrainableIOBuffer(), but this version comes with its own
// storage. The motivation is to avoid repeated allocations of
// DrainableIOBuffer.
//
// Example:
//
// scoped_refptr<SeekableIOBuffer> buf =
//     base::MakeRefCounted<SeekableIOBuffer>(1024);
// // capacity() == 1024. size() == BytesRemaining() == BytesConsumed() == 0.
// // data() points to the beginning of the buffer.
//
// // Read() takes an IOBuffer.
// int bytes_read = some_reader->Read(buf, buf->capacity());
// buf->DidAppend(bytes_read);
// // size() == BytesRemaining() == bytes_read. data() is unaffected.
//
// while (buf->BytesRemaining() > 0) {
//   // Write() takes an IOBuffer. If it takes const char*, we could
///  // simply use the regular IOBuffer like buf->data() + offset.
//   int bytes_written = Write(buf, buf->BytesRemaining());
//   buf->DidConsume(bytes_written);
// }
// // BytesRemaining() == 0. BytesConsumed() == size().
// // data() points to the end of the consumed bytes (exclusive).
//
// // If you want to reuse the buffer, be sure to clear the buffer.
// buf->Clear();
// // size() == BytesRemaining() == BytesConsumed() == 0.
// // data() points to the beginning of the buffer.
//
class HttpStreamParser::SeekableIOBuffer : public IOBufferWithSize {
 public:
  explicit SeekableIOBuffer(int capacity)
      : IOBufferWithSize(capacity), real_data_(data_), capacity_(capacity) {}

  // DidConsume() changes the |data_| pointer so that |data_| always points
  // to the first unconsumed byte.
  void DidConsume(int bytes) {
    SetOffset(used_ + bytes);
  }

  // Returns the number of unconsumed bytes.
  int BytesRemaining() const {
    return size_ - used_;
  }

  // Seeks to an arbitrary point in the buffer. The notion of bytes consumed
  // and remaining are updated appropriately.
  void SetOffset(int bytes) {
    DCHECK_GE(bytes, 0);
    DCHECK_LE(bytes, size_);
    used_ = bytes;
    data_ = real_data_ + used_;
  }

  // Called after data is added to the buffer. Adds |bytes| added to
  // |size_|. data() is unaffected.
  void DidAppend(int bytes) {
    DCHECK_GE(bytes, 0);
    DCHECK_GE(size_ + bytes, 0);
    DCHECK_LE(size_ + bytes, capacity_);
    size_ += bytes;
  }

  // Changes the logical size to 0, and the offset to 0.
  void Clear() {
    size_ = 0;
    SetOffset(0);
  }

  // Returns the logical size of the buffer (i.e the number of bytes of data
  // in the buffer).
  int size() const { return size_; }

  // Returns the capacity of the buffer. The capacity is the size used when
  // the object is created.
  int capacity() const { return capacity_; }

 private:
  ~SeekableIOBuffer() override {
    // data_ will be deleted in IOBuffer::~IOBuffer().
    data_ = real_data_;
  }

  raw_ptr<char, AllowPtrArithmetic> real_data_;
  const int capacity_;
  int size_ = 0;
  int used_ = 0;
};

// 2 CRLFs + max of 8 hex chars.
const size_t HttpStreamParser::kChunkHeaderFooterSize = 12;

HttpStreamParser::HttpStreamParser(StreamSocket* stream_socket,
                                   bool connection_is_reused,
                                   const GURL& url,
                                   const std::string& method,
                                   UploadDataStream* upload_data_stream,
                                   GrowableIOBuffer* read_buffer,
                                   const NetLogWithSource& net_log)
    : url_(url),
      method_(method),
      upload_data_stream_(upload_data_stream),
      read_buf_(read_buffer),
      response_header_start_offset_(std::string::npos),
      stream_socket_(stream_socket),
      connection_is_reused_(connection_is_reused),
      net_log_(net_log),
      truncate_to_content_length_enabled_(base::FeatureList::IsEnabled(
          features::kTruncateBodyToContentLength)) {
  io_callback_ = base::BindRepeating(&HttpStreamParser::OnIOComplete,
                                     weak_ptr_factory_.GetWeakPtr());
}

HttpStreamParser::~HttpStreamParser() = default;

int HttpStreamParser::SendRequest(
    const std::string& request_line,
    const HttpRequestHeaders& headers,
    const NetworkTrafficAnnotationTag& traffic_annotation,
    HttpResponseInfo* response,
    CompletionOnceCallback callback) {
  DCHECK_EQ(STATE_NONE, io_state_);
  DCHECK(callback_.is_null());
  DCHECK(!callback.is_null());
  DCHECK(response);

  NetLogRequestHeaders(net_log_,
                       NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST_HEADERS,
                       request_line, &headers);

  DVLOG(1) << __func__ << "() request_line = \"" << request_line << "\""
           << " headers = \"" << headers.ToString() << "\"";
  traffic_annotation_ = MutableNetworkTrafficAnnotationTag(traffic_annotation);
  response_ = response;

  // Put the peer's IP address and port into the response.
  IPEndPoint ip_endpoint;
  int result = stream_socket_->GetPeerAddress(&ip_endpoint);
  if (result != OK)
    return result;
  response_->remote_endpoint = ip_endpoint;

  std::string request = request_line + headers.ToString();
  request_headers_length_ = request.size();

  if (upload_data_stream_) {
    request_body_send_buf_ =
        base::MakeRefCounted<SeekableIOBuffer>(kRequestBodyBufferSize);
    if (upload_data_stream_->is_chunked()) {
      // Read buffer is adjusted to guarantee that |request_body_send_buf_| is
      // large enough to hold the encoded chunk.
      request_body_read_buf_ = base::MakeRefCounted<SeekableIOBuffer>(
          kRequestBodyBufferSize - kChunkHeaderFooterSize);
    } else {
      // No need to encode request body, just send the raw data.
      request_body_read_buf_ = request_body_send_buf_;
    }
  }

  io_state_ = STATE_SEND_HEADERS;

  // If we have a small request body, then we'll merge with the headers into a
  // single write.
  bool did_merge = false;
  if (ShouldMergeRequestHeadersAndBody(request, upload_data_stream_)) {
    int merged_size =
        static_cast<int>(request_headers_length_ + upload_data_stream_->size());
    auto merged_request_headers_and_body =
        base::MakeRefCounted<IOBufferWithSize>(merged_size);
    // We'll repurpose |request_headers_| to store the merged headers and
    // body.
    request_headers_ = base::MakeRefCounted<DrainableIOBuffer>(
        merged_request_headers_and_body, merged_size);

    memcpy(request_headers_->data(), request.data(), request_headers_length_);
    request_headers_->DidConsume(request_headers_length_);

    uint64_t todo = upload_data_stream_->size();
    while (todo) {
      int consumed = upload_data_stream_->Read(request_headers_.get(),
                                               static_cast<int>(todo),
                                               CompletionOnceCallback());
      // Read() must succeed synchronously if not chunked and in memory.
      DCHECK_GT(consumed, 0);
      request_headers_->DidConsume(consumed);
      todo -= consumed;
    }
    DCHECK(upload_data_stream_->IsEOF());
    // Reset the offset, so the buffer can be read from the beginning.
    request_headers_->SetOffset(0);
    did_merge = true;

    NetLogSendRequestBody(net_log_, upload_data_stream_->size(),
                          false, /* not chunked */
                          true /* merged */);
  }

  if (!did_merge) {
    // If we didn't merge the body with the headers, then |request_headers_|
    // contains just the HTTP headers.
    size_t request_size = request.size();
    scoped_refptr<StringIOBuffer> headers_io_buf =
        base::MakeRefCounted<StringIOBuffer>(std::move(request));
    request_headers_ = base::MakeRefCounted<DrainableIOBuffer>(
        std::move(headers_io_buf), request_size);
  }

  result = DoLoop(OK);
  if (result == ERR_IO_PENDING)
    callback_ = std::move(callback);

  return result > 0 ? OK : result;
}

int HttpStreamParser::ConfirmHandshake(CompletionOnceCallback callback) {
  int ret = stream_socket_->ConfirmHandshake(
      base::BindOnce(&HttpStreamParser::RunConfirmHandshakeCallback,
                     weak_ptr_factory_.GetWeakPtr()));
  if (ret == ERR_IO_PENDING)
    confirm_handshake_callback_ = std::move(callback);
  return ret;
}

int HttpStreamParser::ReadResponseHeaders(CompletionOnceCallback callback) {
  DCHECK(io_state_ == STATE_NONE || io_state_ == STATE_DONE);
  DCHECK(callback_.is_null());
  DCHECK(!callback.is_null());
  DCHECK_EQ(0u, read_buf_unused_offset_);
  DCHECK(SendRequestBuffersEmpty());

  // This function can be called with io_state_ == STATE_DONE if the
  // connection is closed after seeing just a 1xx response code.
  if (io_state_ == STATE_DONE)
    return ERR_CONNECTION_CLOSED;

  int result = OK;
  io_state_ = STATE_READ_HEADERS;

  if (read_buf_->offset() > 0) {
    // Simulate the state where the data was just read from the socket.
    result = read_buf_->offset();
    read_buf_->set_offset(0);
  }
  if (result > 0)
    io_state_ = STATE_READ_HEADERS_COMPLETE;

  result = DoLoop(result);
  if (result == ERR_IO_PENDING)
    callback_ = std::move(callback);

  return result > 0 ? OK : result;
}

int HttpStreamParser::ReadResponseBody(IOBuffer* buf,
                                       int buf_len,
                                       CompletionOnceCallback callback) {
  DCHECK(io_state_ == STATE_NONE || io_state_ == STATE_DONE);
  DCHECK(callback_.is_null());
  DCHECK(!callback.is_null());
  DCHECK_LE(buf_len, kMaxBufSize);
  DCHECK(SendRequestBuffersEmpty());
  // Added to investigate crbug.com/499663.
  CHECK(buf);

  if (io_state_ == STATE_DONE)
    return OK;

  user_read_buf_ = buf;
  user_read_buf_len_ = base::checked_cast<size_t>(buf_len);
  io_state_ = STATE_READ_BODY;

  int result = DoLoop(OK);
  if (result == ERR_IO_PENDING)
    callback_ = std::move(callback);

  return result;
}

void HttpStreamParser::OnIOComplete(int result) {
  result = DoLoop(result);

  // The client callback can do anything, including destroying this class,
  // so any pending callback must be issued after everything else is done.
  if (result != ERR_IO_PENDING && !callback_.is_null()) {
    std::move(callback_).Run(result);
  }
}

int HttpStreamParser::DoLoop(int result) {
  do {
    DCHECK_NE(ERR_IO_PENDING, result);
    DCHECK_NE(STATE_DONE, io_state_);
    DCHECK_NE(STATE_NONE, io_state_);
    State state = io_state_;
    io_state_ = STATE_NONE;
    switch (state) {
      case STATE_SEND_HEADERS:
        DCHECK_EQ(OK, result);
        result = DoSendHeaders();
        DCHECK_NE(STATE_NONE, io_state_);
        break;
      case STATE_SEND_HEADERS_COMPLETE:
        result = DoSendHeadersComplete(result);
        DCHECK_NE(STATE_NONE, io_state_);
        break;
      case STATE_SEND_BODY:
        DCHECK_EQ(OK, result);
        result = DoSendBody();
        DCHECK_NE(STATE_NONE, io_state_);
        break;
      case STATE_SEND_BODY_COMPLETE:
        result = DoSendBodyComplete(result);
        DCHECK_NE(STATE_NONE, io_state_);
        break;
      case STATE_SEND_REQUEST_READ_BODY_COMPLETE:
        result = DoSendRequestReadBodyComplete(result);
        DCHECK_NE(STATE_NONE, io_state_);
        break;
      case STATE_SEND_REQUEST_COMPLETE:
        result = DoSendRequestComplete(result);
        break;
      case STATE_READ_HEADERS:
        net_log_.BeginEvent(NetLogEventType::HTTP_STREAM_PARSER_READ_HEADERS);
        DCHECK_GE(result, 0);
        result = DoReadHeaders();
        break;
      case STATE_READ_HEADERS_COMPLETE:
        result = DoReadHeadersComplete(result);
        net_log_.EndEventWithNetErrorCode(
            NetLogEventType::HTTP_STREAM_PARSER_READ_HEADERS, result);
        break;
      case STATE_READ_BODY:
        DCHECK_GE(result, 0);
        result = DoReadBody();
        break;
      case STATE_READ_BODY_COMPLETE:
        result = DoReadBodyComplete(result);
        break;
      default:
        NOTREACHED();
    }
  } while (result != ERR_IO_PENDING &&
           (io_state_ != STATE_DONE && io_state_ != STATE_NONE));

  return result;
}

int HttpStreamParser::DoSendHeaders() {
  int bytes_remaining = request_headers_->BytesRemaining();
  DCHECK_GT(bytes_remaining, 0);

  // Record our best estimate of the 'request time' as the time when we send
  // out the first bytes of the request headers.
  if (bytes_remaining == request_headers_->size())
    response_->request_time = base::Time::Now();

  io_state_ = STATE_SEND_HEADERS_COMPLETE;
  return stream_socket_->Write(
      request_headers_.get(), bytes_remaining, io_callback_,
      NetworkTrafficAnnotationTag(traffic_annotation_));
}

int HttpStreamParser::DoSendHeadersComplete(int result) {
  if (result < 0) {
    // In the unlikely case that the headers and body were merged, all the
    // the headers were sent, but not all of the body way, and |result| is
    // an error that this should try reading after, stash the error for now and
    // act like the request was successfully sent.
    io_state_ = STATE_SEND_REQUEST_COMPLETE;
    if (request_headers_->BytesConsumed() >= request_headers_length_ &&
        ShouldTryReadingOnUploadError(result)) {
      upload_error_ = result;
      return OK;
    }
    return result;
  }

  sent_bytes_ += result;
  request_headers_->DidConsume(result);
  if (request_headers_->BytesRemaining() > 0) {
    io_state_ = STATE_SEND_HEADERS;
    return OK;
  }

  if (upload_data_stream_ &&
      (upload_data_stream_->is_chunked() ||
       // !IsEOF() indicates that the body wasn't merged.
       (upload_data_stream_->size() > 0 && !upload_data_stream_->IsEOF()))) {
    NetLogSendRequestBody(net_log_, upload_data_stream_->size(),
                          upload_data_stream_->is_chunked(),
                          false /* not merged */);
    io_state_ = STATE_SEND_BODY;
    return OK;
  }

  // Finished sending the request.
  io_state_ = STATE_SEND_REQUEST_COMPLETE;
  return OK;
}

int HttpStreamParser::DoSendBody() {
  if (request_body_send_buf_->BytesRemaining() > 0) {
    io_state_ = STATE_SEND_BODY_COMPLETE;
    return stream_socket_->Write(
        request_body_send_buf_.get(), request_body_send_buf_->BytesRemaining(),
        io_callback_, NetworkTrafficAnnotationTag(traffic_annotation_));
  }

  if (upload_data_stream_->is_chunked() && sent_last_chunk_) {
    // Finished sending the request.
    io_state_ = STATE_SEND_REQUEST_COMPLETE;
    return OK;
  }

  request_body_read_buf_->Clear();
  io_state_ = STATE_SEND_REQUEST_READ_BODY_COMPLETE;
  return upload_data_stream_->Read(
      request_body_read_buf_.get(), request_body_read_buf_->capacity(),
      base::BindOnce(&HttpStreamParser::OnIOComplete,
                     weak_ptr_factory_.GetWeakPtr()));
}

int HttpStreamParser::DoSendBodyComplete(int result) {
  if (result < 0) {
    // If |result| is an error that this should try reading after, stash the
    // error for now and act like the request was successfully sent.
    io_state_ = STATE_SEND_REQUEST_COMPLETE;
    if (ShouldTryReadingOnUploadError(result)) {
      upload_error_ = result;
      return OK;
    }
    return result;
  }

  sent_bytes_ += result;
  request_body_send_buf_->DidConsume(result);

  io_state_ = STATE_SEND_BODY;
  return OK;
}

int HttpStreamParser::DoSendRequestReadBodyComplete(int result) {
  // |result| is the result of read from the request body from the last call to
  // DoSendBody().
  if (result < 0) {
    io_state_ = STATE_SEND_REQUEST_COMPLETE;
    return result;
  }

  // Chunked data needs to be encoded.
  if (upload_data_stream_->is_chunked()) {
    if (result == 0) {  // Reached the end.
      DCHECK(upload_data_stream_->IsEOF());
      sent_last_chunk_ = true;
    }
    // Encode the buffer as 1 chunk.
    const std::string_view payload(request_body_read_buf_->data(), result);
    request_body_send_buf_->Clear();
    result = EncodeChunk(payload, request_body_send_buf_->span());
  }

  if (result == 0) {  // Reached the end.
    // Reaching EOF means we can finish sending request body unless the data is
    // chunked. (i.e. No need to send the terminal chunk.)
    DCHECK(upload_data_stream_->IsEOF());
    DCHECK(!upload_data_stream_->is_chunked());
    // Finished sending the request.
    io_state_ = STATE_SEND_REQUEST_COMPLETE;
  } else if (result > 0) {
    request_body_send_buf_->DidAppend(result);
    result = 0;
    io_state_ = STATE_SEND_BODY;
  }
  return result;
}

int HttpStreamParser::DoSendRequestComplete(int result) {
  DCHECK_NE(result, ERR_IO_PENDING);
  request_headers_ = nullptr;
  upload_data_stream_ = nullptr;
  request_body_send_buf_ = nullptr;
  request_body_read_buf_ = nullptr;

  return result;
}

int HttpStreamParser::DoReadHeaders() {
  io_state_ = STATE_READ_HEADERS_COMPLETE;

  // Grow the read buffer if necessary.
  if (read_buf_->RemainingCapacity() == 0)
    read_buf_->SetCapacity(read_buf_->capacity() + kHeaderBufInitialSize);

  // http://crbug.com/16371: We're seeing |user_buf_->data()| return NULL.
  // See if the user is passing in an IOBuffer with a NULL |data_|.
  CHECK(read_buf_->data());

  return stream_socket_->Read(read_buf_.get(), read_buf_->RemainingCapacity(),
                              io_callback_);
}

int HttpStreamParser::DoReadHeadersComplete(int result) {
  // DoReadHeadersComplete is called with the result of Socket::Read, which is a
  // (byte_count | error), and returns (error | OK).

  result = HandleReadHeaderResult(result);

  // If still reading the headers, just return the result.
  if (io_state_ == STATE_READ_HEADERS) {
    return result;
  }

  // If the result is ERR_IO_PENDING, |io_state_| should be STATE_READ_HEADERS.
  DCHECK_NE(ERR_IO_PENDING, result);

  // TODO(mmenke):  The code below is ugly and hacky.  A much better and more
  // flexible long term solution would be to separate out the read and write
  // loops, though this would involve significant changes, both here and
  // elsewhere (WebSockets, for instance).

  // If there was an error uploading the request body, may need to adjust the
  // result.
  if (upload_error_ != OK) {
    // On errors, use the original error received when sending the request.
    // The main cases where these are different is when there's a header-related
    // error code, or when there's an ERR_CONNECTION_CLOSED, which can result in
    // special handling of partial responses and HTTP/0.9 responses.
    if (result < 0) {
      // Nothing else to do.  In the HTTP/0.9 or only partial headers received
      // cases, can normally go to other states after an error reading headers.
      io_state_ = STATE_DONE;
      // Don't let caller see the headers.
      response_->headers = nullptr;
      result = upload_error_;
    } else {
      // Skip over 1xx responses as usual, and allow 4xx/5xx error responses to
      // override the error received while uploading the body. For other status
      // codes, return the original error received when trying to upload the
      // request body, to make sure the consumer has some indication there was
      // an error.
      int response_code_class = response_->headers->response_code() / 100;
      if (response_code_class != 1 && response_code_class != 4 &&
          response_code_class != 5) {
        // Nothing else to do.
        io_state_ = STATE_DONE;
        // Don't let caller see the headers.
        response_->headers = nullptr;
        result = upload_error_;
      }
    }
  }

  // If there will be no more header reads, clear the request and response
  // pointers, as they're no longer needed, and in some cases the body may
  // be read after the parent class destroyed the underlying objects (See
  // HttpResponseBodyDrainer).
  //
  // This is the last header read if HttpStreamParser is done, no response
  // headers were received, or if the response code is not in the 1xx range.
  if (io_state_ == STATE_DONE || !response_->headers ||
      response_->headers->response_code() / 100 != 1) {
    response_ = nullptr;
  }

  return result;
}

int HttpStreamParser::DoReadBody() {
  io_state_ = STATE_READ_BODY_COMPLETE;

  // Added to investigate crbug.com/499663.
  CHECK(user_read_buf_.get());

  // There may be additional data after the end of the body waiting in
  // the socket, but in order to find out, we need to read as much as possible.
  // If there is additional data, discard it and close the connection later.
  uint64_t remaining_read_len = user_read_buf_len_;
  uint64_t remaining_body = 0;
  if (truncate_to_content_length_enabled_ && !chunked_decoder_.get() &&
      response_body_length_ >= 0) {
    remaining_body = base::checked_cast<uint64_t>(response_body_length_ -
                                                  response_body_read_);
    remaining_read_len = std::min(remaining_read_len, remaining_body);
  }

  // There may be some data left over from reading the response headers.
  if (read_buf_->offset()) {
    const auto read_offset_s = base::checked_cast<size_t>(read_buf_->offset());
    CHECK_GE(read_offset_s, read_buf_unused_offset_);
    const size_t available = read_offset_s - read_buf_unused_offset_;
    if (available) {
      const auto bytes_from_buffer = static_cast<size_t>(
          std::min(uint64_t{available}, remaining_read_len));
      user_read_buf_->span().copy_prefix_from(read_buf_->everything().subspan(
          read_buf_unused_offset_, bytes_from_buffer));
      read_buf_unused_offset_ += bytes_from_buffer;
      // Clear out the remaining data if we've reached the end of the body.
      if (truncate_to_content_length_enabled_ &&
          (remaining_body == bytes_from_buffer) &&
          (available > bytes_from_buffer)) {
        read_buf_->SetCapacity(0);
        read_buf_unused_offset_ = 0;
        discarded_extra_data_ = true;
      } else if (bytes_from_buffer == available) {
        read_buf_->SetCapacity(0);
        read_buf_unused_offset_ = 0;
      }
      return bytes_from_buffer;
    }
    read_buf_->SetCapacity(0);
    read_buf_unused_offset_ = 0;
  }

  // Check to see if we're done reading.
  if (IsResponseBodyComplete())
    return 0;

  // DoReadBodyComplete will truncate the amount read if necessary whether the
  // read completes synchronously or asynchronously.
  DCHECK_EQ(0, read_buf_->offset());
  return stream_socket_->Read(user_read_buf_.get(),
                              base::checked_cast<int>(user_read_buf_len_),
                              io_callback_);
}

int HttpStreamParser::DoReadBodyComplete(int result) {
  // Check to see if we've read too much and need to discard data before we
  // increment received_bytes_ and response_body_read_ or otherwise start
  // processing the data.
  if (truncate_to_content_length_enabled_ && !chunked_decoder_.get() &&
      response_body_length_ >= 0) {
    // Calculate how much we should have been allowed to read to not go beyond
    // the Content-Length.
    const auto remaining_body = base::checked_cast<uint64_t>(
        response_body_length_ - response_body_read_);
    uint64_t remaining_read_len =
        std::min(uint64_t{user_read_buf_len_}, remaining_body);
    if (result > 0 && static_cast<uint64_t>(result) > remaining_read_len) {
      // Truncate to only what is in the body.
      result = base::checked_cast<int>(remaining_read_len);
      discarded_extra_data_ = true;
    }
  }

  // When the connection is closed, there are numerous ways to interpret it.
  //
  //  - If a Content-Length header is present and the body contains exactly that
  //    number of bytes at connection close, the response is successful.
  //
  //  - If a Content-Length header is present and the body contains fewer bytes
  //    than promised by the header at connection close, it may indicate that
  //    the connection was closed prematurely, or it may indicate that the
  //    server sent an invalid Content-Length header. Unfortunately, the invalid
  //    Content-Length header case does occur in practice and other browsers are
  //    tolerant of it. We choose to treat it as an error for now, but the
  //    download system treats it as a non-error, and URLRequestHttpJob also
  //    treats it as OK if the Content-Length is the post-decoded body content
  //    length.
  //
  //  - If chunked encoding is used and the terminating chunk has been processed
  //    when the connection is closed, the response is successful.
  //
  //  - If chunked encoding is used and the terminating chunk has not been
  //    processed when the connection is closed, it may indicate that the
  //    connection was closed prematurely or it may indicate that the server
  //    sent an invalid chunked encoding. We choose to treat it as
  //    an invalid chunked encoding.
  //
  //  - If a Content-Length is not present and chunked encoding is not used,
  //    connection close is the only way to signal that the response is
  //    complete. Unfortunately, this also means that there is no way to detect
  //    early close of a connection. No error is returned.
  if (result == 0 && !IsResponseBodyComplete() && CanFindEndOfResponse()) {
    if (chunked_decoder_.get())
      result = ERR_INCOMPLETE_CHUNKED_ENCODING;
    else
      result = ERR_CONTENT_LENGTH_MISMATCH;
  }

  if (result > 0)
    received_bytes_ += result;

  // Filter incoming data if appropriate.  FilterBuf may return an error.
  if (result > 0 && chunked_decoder_.get()) {
    result = chunked_decoder_->FilterBuf(
        user_read_buf_->span().first(static_cast<size_t>(result)));
    if (result == 0 && !chunked_decoder_->reached_eof()) {
      // Don't signal completion of the Read call yet or else it'll look like
      // we received end-of-file.  Wait for more data.
      io_state_ = STATE_READ_BODY;
      return OK;
    }
  }

  if (result > 0)
    response_body_read_ += result;

  if (result <= 0 || IsResponseBodyComplete()) {
    io_state_ = STATE_DONE;

    // Save the overflow data, which can be in two places.  There may be
    // some left over in |user_read_buf_|, plus there may be more
    // in |read_buf_|.  But the part left over in |user_read_buf_| must have
    // come from the |read_buf_|, so there's room to put it back at the
    // start first.
    const auto read_offset_s = base::checked_cast<size_t>(read_buf_->offset());
    CHECK_GE(read_offset_s, read_buf_unused_offset_);
    const size_t additional_save_amount =
        read_offset_s - read_buf_unused_offset_;
    int save_amount = 0;
    if (chunked_decoder_.get()) {
      save_amount = chunked_decoder_->bytes_after_eof();
    } else if (response_body_length_ >= 0) {
      int64_t extra_data_read = response_body_read_ - response_body_length_;
      if (extra_data_read > 0) {
        save_amount = static_cast<int>(extra_data_read);
        if (result > 0)
          result -= save_amount;
      }
    }

    const auto new_capacity =
        base::checked_cast<int>(save_amount + additional_save_amount);
    CHECK_LE(new_capacity, kMaxBufSize);
    if (read_buf_->capacity() < new_capacity) {
      read_buf_->SetCapacity(new_capacity);
    }

    if (save_amount) {
      received_bytes_ -= save_amount;
      read_buf_->everything().copy_prefix_from(user_read_buf_->span().subspan(
          base::checked_cast<size_t>(result),
          base::checked_cast<size_t>(save_amount)));
    }
    read_buf_->set_offset(save_amount);
    if (additional_save_amount) {
      read_buf_->span().copy_prefix_from(read_buf_->everything().subspan(
          read_buf_unused_offset_, additional_save_amount));
      read_buf_->set_offset(new_capacity);
    }
    read_buf_unused_offset_ = 0;
  } else {
    // Now waiting for more of the body to be read.
    user_read_buf_ = nullptr;
    user_read_buf_len_ = 0;
  }

  return result;
}

int HttpStreamParser::HandleReadHeaderResult(int result) {
  DCHECK_EQ(0u, read_buf_unused_offset_);

  if (result == 0)
    result = ERR_CONNECTION_CLOSED;

  if (result == ERR_CONNECTION_CLOSED) {
    // The connection closed without getting any more data.
    if (read_buf_->offset() == 0) {
      io_state_ = STATE_DONE;
      // If the connection has not been reused, it may have been a 0-length
      // HTTP/0.9 responses, but it was most likely an error, so just return
      // ERR_EMPTY_RESPONSE instead. If the connection was reused, just pass
      // on the original connection close error, as rather than being an
      // empty HTTP/0.9 response it's much more likely the server closed the
      // socket before it received the request.
      if (!connection_is_reused_)
        return ERR_EMPTY_RESPONSE;
      return result;
    }

    // Accepting truncated headers over HTTPS is a potential security
    // vulnerability, so just return an error in that case.
    //
    // If response_header_start_offset_ is std::string::npos, this may be a < 8
    // byte HTTP/0.9 response. However, accepting such a response over HTTPS
    // would allow a MITM to truncate an HTTP/1.x status line to look like a
    // short HTTP/0.9 response if the peer put a record boundary at the first 8
    // bytes. To ensure that all response headers received over HTTPS are
    // pristine, treat such responses as errors.
    //
    // TODO(mmenke):  Returning ERR_RESPONSE_HEADERS_TRUNCATED when a response
    // looks like an HTTP/0.9 response is weird.  Should either come up with
    // another error code, or, better, disable HTTP/0.9 over HTTPS (and give
    // that a new error code).
    if (url_.SchemeIsCryptographic()) {
      io_state_ = STATE_DONE;
      return ERR_RESPONSE_HEADERS_TRUNCATED;
    }

    // Parse things as well as we can and let the caller decide what to do.
    int end_offset;
    if (response_header_start_offset_ != std::string::npos) {
      // The response looks to be a truncated set of HTTP headers.
      io_state_ = STATE_READ_BODY_COMPLETE;
      end_offset = read_buf_->offset();
    } else {
      // The response is apparently using HTTP
```