Response:
My thinking process to answer the request goes through these stages:

1. **Understanding the Request:** I first break down the prompt to identify the key tasks:
    * Describe the functionality of `balsa_frame.cc`.
    * Explain its relationship to JavaScript.
    * Provide examples of logical inference (input/output).
    * Illustrate common user/programming errors.
    * Outline the user actions leading to this code.
    * Summarize the functionality in part 2.

2. **Initial Code Scan (Skimming for Keywords and Structure):** I quickly scan the provided code, looking for important keywords, data structures, and general flow:
    * **Class Name:** `BalsaFrame` – This suggests it deals with framing of some sort. "Balsa" hints at a lightweight structure.
    * **Includes:**  `quiche`, network-related headers (implicitly through `quiche/common_`). This confirms it's part of a networking stack.
    * **Member Variables:** `parse_state_`, `headers_`, `visitor_`, `chunk_length_remaining_`, `content_length_remaining_`, etc. These strongly indicate it's involved in parsing and processing network messages (likely HTTP).
    * **Methods:** `ProcessInput`, `ProcessHeaders`, `BytesSafeToSplice`, `BytesSpliced`, `HandleError`, `HandleWarning`. These are action-oriented and relate to processing data and managing state.
    * **Enums:** `BalsaFrameEnums`, `BalsaHeadersEnums`. These define the states and status codes the class operates with.
    * **Header Processing:**  Lots of logic around processing headers, including chunked encoding and content length.
    * **Body Processing:**  Code sections dealing with chunk data and content.
    * **Error Handling:**  `HandleError` suggests robust error management.
    * **Visitor Pattern:** The `visitor_` member suggests a delegation pattern for handling events.

3. **Inferring Core Functionality (Based on Code Clues):** Based on the initial scan, I start forming a hypothesis about the core functionality:  `BalsaFrame` is likely responsible for parsing and processing HTTP messages (requests and responses) at a low level. It manages the state of parsing (headers, body, chunking), interacts with a separate header parsing component (`BalsaHeaders`), and notifies a "visitor" about parsing events.

4. **Addressing Specific Questions:** Now, I go through each part of the request systematically:

    * **Functionality Listing:** I summarize the inferred functionality in bullet points, using the keywords and concepts identified in the code. I focus on the responsibilities of the class.

    * **Relationship to JavaScript:** I consider how this server-side C++ code interacts with client-side JavaScript. The key interaction is through the HTTP protocol. JavaScript uses APIs like `fetch` or `XMLHttpRequest` to send requests and receive responses. `BalsaFrame` is responsible for parsing these raw HTTP messages *on the server*. I provide examples of how JavaScript initiates requests and how the server-side processing relates.

    * **Logical Inference (Input/Output):** I look for conditional logic in the code and devise simple scenarios:
        * **Chunked Encoding:** Inputting a chunked message and predicting the state transitions and visitor callbacks.
        * **Content Length:**  Inputting a message with a content length and predicting the body processing.
        * **Error Cases:**  Inputting malformed headers or invalid chunk lengths and observing the error handling.

    * **User/Programming Errors:** I think about common mistakes developers make when dealing with HTTP:
        * Incorrect content length.
        * Mismatched chunk sizes.
        * Missing content length for POST/PUT requests.
        * Exceeding header limits.

    * **User Actions as Debugging Clues:** I trace back how a user action on a website (e.g., clicking a link, submitting a form) translates to network requests that eventually reach this code. I emphasize the steps involved from the browser to the server.

    * **Summarizing Part 2:** I reread the provided code snippet and identify the key actions within it. This involves handling different parsing states based on the presence of `Transfer-Encoding: chunked` or `Content-Length`, and the logic for transitioning between these states.

5. **Refinement and Clarity:**  Finally, I review my answers to ensure they are clear, concise, and accurate. I use proper terminology and explain the concepts in a way that is understandable to someone familiar with networking concepts. I try to connect the low-level C++ code to the higher-level interactions that developers are more familiar with (like JavaScript and HTTP requests).

Essentially, I use a combination of code analysis, domain knowledge (HTTP protocol), and logical reasoning to understand the purpose and behavior of the code and to answer the specific questions in the prompt. The process is iterative, where initial assumptions are refined based on further code examination.
这是 `net/third_party/quiche/src/quiche/balsa/balsa_frame.cc` 文件第二部分的功能归纳：

**核心功能：HTTP 消息体的解析和处理**

这部分代码主要负责 `BalsaFrame` 类处理 HTTP 消息体（body）的逻辑，包括：

* **处理分块传输编码 (Chunked Transfer Encoding):**
    * **读取块长度 (`READING_CHUNK_LENGTH` 状态):**  解析消息体中的块长度信息，支持十六进制表示，并处理空格、制表符、分号后的参数等。会对无效的块长度格式进行错误处理。
    * **读取块扩展 (`READING_CHUNK_EXTENSION` 状态):**  读取块长度后的可选扩展信息。
    * **读取块数据 (`READING_CHUNK_DATA` 状态):**  读取指定长度的块数据，并通过 `visitor_` 回调通知接收到的数据。
    * **读取块终止符 (`READING_CHUNK_TERM` 状态):**  验证每个数据块后的 `\r\n` 终止符。
    * **读取最后一个块的终止符 (`READING_LAST_CHUNK_TERM` 状态):** 处理最后一个大小为 0 的块后的终止符，并检测是否存在 Trailer Headers。

* **处理 Content-Length 指定的消息体 (`READING_CONTENT` 状态):**
    * 读取指定 `Content-Length` 大小的消息体数据。
    * 通过 `visitor_` 回调通知接收到的数据。
    * 当接收到所有数据后，将状态设置为 `MESSAGE_FULLY_READ` 并调用 `visitor_->MessageDone()`。

* **处理无 Content-Length 和 Transfer-Encoding 的消息体 (`READING_UNTIL_CLOSE` 状态):**
    * 对于某些请求方法（非 POST 和 PUT，或者配置允许），假设消息体持续到连接关闭。
    * 将接收到的所有数据都视为消息体，并通过 `visitor_` 回调通知。

* **处理 Trailer Headers (`READING_TRAILER` 状态):**
    * 在分块传输编码中，最后一个大小为 0 的块后可以跟 Trailer Headers。
    * 解析 Trailer Headers，并将其存储在 `trailers_` 中。
    * 通过 `visitor_->OnTrailers()` 回调通知 Trailer Headers。

* **错误处理:**
    * 在解析消息体过程中遇到错误（例如，无效的块长度、块长度溢出、Trailer 过长等），会调用 `HandleError()` 并切换到 `ERROR` 状态。

* **限制:**
    * 对 Trailer Headers 的长度进行限制，防止恶意请求消耗过多资源。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它在网络栈中扮演着关键角色，与 JavaScript 的交互是通过 HTTP 协议进行的。

* **发送请求：** 当 JavaScript 代码（例如，使用 `fetch` 或 `XMLHttpRequest`) 发送一个带有消息体的 HTTP 请求时，`BalsaFrame` 负责在服务器端解析这个请求的消息体。例如，如果 JavaScript 发送一个 `POST` 请求，请求体中包含 JSON 数据，`BalsaFrame` 会解析这个 JSON 数据。

* **接收响应：** 同样，当服务器发送一个带有消息体的 HTTP 响应时（例如，返回 JSON 数据），`BalsaFrame` 负责在客户端（Chromium 浏览器）解析这个响应的消息体。

**举例说明：**

**假设输入（服务器接收到的数据流）：**

```
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
\r\n
4\r\n
abcd\r\n
0\r\n
Trailer-Name: Trailer-Value\r\n
\r\n
```

**逻辑推理和输出：**

1. **初始状态:** `parse_state_` 为 `READING_CHUNK_LENGTH`。
2. **读取 "4\r\n":** `chunk_length_remaining_` 被设置为 4，`parse_state_` 变为 `READING_CHUNK_DATA`。`visitor_->OnChunkLength(4)` 被调用。
3. **读取 "abcd":**  `visitor_->OnBodyChunkInput("abcd")` 被调用。`chunk_length_remaining_` 变为 0，`parse_state_` 变为 `READING_CHUNK_TERM`。
4. **读取 "\r\n":** `parse_state_` 变为 `READING_CHUNK_LENGTH`。
5. **读取 "0\r\n":** `chunk_length_remaining_` 被设置为 0，`parse_state_` 变为 `READING_LAST_CHUNK_TERM`。`visitor_->OnChunkLength(0)` 被调用。
6. **读取 "Trailer-Name: Trailer-Value\r\n\r\n":**  `parse_state_` 变为 `READING_TRAILER`。`trailers_` 存储了 Trailer Header。`visitor_->OnTrailers(trailers_)` 被调用。 `parse_state_` 变为 `MESSAGE_FULLY_READ`，`visitor_->MessageDone()` 被调用。

**用户或编程常见的使用错误：**

* **Content-Length 与实际内容不符：** 如果服务器声明了 `Content-Length`，但发送的数据量与声明的不一致，会导致解析错误。例如，声明 `Content-Length: 10`，但只发送了 5 个字节。
* **分块传输编码格式错误：**
    * **无效的块长度：** 块长度不是有效的十六进制数字，或者包含非法字符。
    * **缺少块终止符：**  每个数据块后没有 `\r\n`。
    * **Trailer 格式错误：** Trailer Headers 的格式不符合 HTTP Header 的规范。
* **POST/PUT 请求缺少 Content-Length：**  对于 `POST` 和 `PUT` 请求，通常需要指定 `Content-Length`，否则可能导致解析错误或服务器行为不确定。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中执行操作：** 用户在网页上点击链接、提交表单、上传文件等操作，导致浏览器发起 HTTP 请求。
2. **浏览器构建 HTTP 请求：** 浏览器根据用户操作和网页内容，构建 HTTP 请求报文，包括请求头和请求体。
3. **请求发送到服务器：** 浏览器将 HTTP 请求报文发送到目标服务器。
4. **服务器接收请求：** 服务器接收到浏览器的 HTTP 请求。
5. **Chromium 网络栈处理请求：** 如果服务器是基于 Chromium 网络栈构建的（或者客户端是 Chromium 浏览器），接收到的请求数据会传递到网络栈的相关模块。
6. **`BalsaFrame` 解析消息体：**  `BalsaFrame` 类负责解析 HTTP 请求或响应的消息体部分。它会根据请求头（例如 `Transfer-Encoding` 或 `Content-Length`）来决定如何解析消息体数据。
7. **触发 `ProcessInput`：**  当有新的消息体数据到达时，`BalsaFrame::ProcessInput()` 方法会被调用，逐步解析数据。

**调试线索：**

* **抓包工具 (e.g., Wireshark):**  可以抓取网络数据包，查看实际发送和接收的 HTTP 报文内容，包括请求头、响应头和消息体，从而确定是否存在格式错误。
* **服务器日志：** 服务器端的日志可能会记录请求处理过程中的错误信息，例如解析消息体失败等。
* **浏览器开发者工具：**  浏览器的开发者工具（Network 面板）可以查看请求和响应的详细信息，包括 Header 和 Preview，有助于发现问题。
* **断点调试：** 在 `BalsaFrame::ProcessInput()` 等关键方法中设置断点，可以逐步跟踪消息体解析的过程，查看状态变化和变量值，帮助定位问题。

总而言之，这部分 `balsa_frame.cc` 代码专注于解析和处理 HTTP 消息体，是 Chromium 网络栈中处理 HTTP 通信的核心组件之一。它通过状态机的方式处理不同类型的消息体编码，并提供回调机制将解析结果通知给上层模块。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_frame.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
e is no body.
    return;
  }

  if (headers_->transfer_encoding_is_chunked_) {
    // Note that
    // if ( Transfer-Encoding: chunked &&  Content-length: )
    // then Transfer-Encoding: chunked trumps.
    // This is as specified in the spec.
    // rfc2616 section 4.4.3
    parse_state_ = BalsaFrameEnums::READING_CHUNK_LENGTH;
    return;
  }

  // Errors parsing content-length definitely can cause
  // protocol errors/warnings
  switch (headers_->content_length_status_) {
    // If we have a content-length, and it is parsed
    // properly, there are two options.
    // 1) zero content, in which case the message is done, and
    // 2) nonzero content, in which case we have to
    //    consume the body.
    case BalsaHeadersEnums::VALID_CONTENT_LENGTH:
      if (headers_->content_length_ == 0) {
        parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
      } else {
        parse_state_ = BalsaFrameEnums::READING_CONTENT;
      }
      break;
    case BalsaHeadersEnums::CONTENT_LENGTH_OVERFLOW:
    case BalsaHeadersEnums::INVALID_CONTENT_LENGTH:
      // If there were characters left-over after parsing the
      // content length, we should flag an error and stop.
      HandleError(BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH);
      break;
      // We can have: no transfer-encoding, no content length, and no
      // connection: close...
      // Unfortunately, this case doesn't seem to be covered in the spec.
      // We'll assume that the safest thing to do here is what the google
      // binaries before 2008 already do, which is to assume that
      // everything until the connection is closed is body.
    case BalsaHeadersEnums::NO_CONTENT_LENGTH:
      if (is_request_) {
        const absl::string_view method = headers_->request_method();
        // POSTs and PUTs should have a detectable body length.  If they
        // do not we consider it an error.
        if ((method != "POST" && method != "PUT") ||
            !http_validation_policy().require_content_length_if_body_required) {
          parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
          break;
        } else if (!allow_reading_until_close_for_request_) {
          HandleError(BalsaFrameEnums::REQUIRED_BODY_BUT_NO_CONTENT_LENGTH);
          break;
        }
      }
      parse_state_ = BalsaFrameEnums::READING_UNTIL_CLOSE;
      HandleWarning(BalsaFrameEnums::MAYBE_BODY_BUT_NO_CONTENT_LENGTH);
      break;
      // The COV_NF_... statements here provide hints to the apparatus
      // which computes coverage reports/ratios that this code is never
      // intended to be executed, and should technically be impossible.
      // COV_NF_START
    default:
      QUICHE_LOG(FATAL) << "Saw a content_length_status: "
                        << headers_->content_length_status_
                        << " which is unknown.";
      // COV_NF_END
  }
}

size_t BalsaFrame::ProcessHeaders(const char* message_start,
                                  size_t message_length) {
  const char* const original_message_start = message_start;
  const char* const message_end = message_start + message_length;
  const char* message_current = message_start;
  const char* checkpoint = message_start;

  if (message_length == 0) {
    return message_current - original_message_start;
  }

  while (message_current < message_end) {
    size_t base_idx = headers_->GetReadableBytesFromHeaderStream();

    // Yes, we could use strchr (assuming null termination), or
    // memchr, but as it turns out that is slower than this tight loop
    // for the input that we see.
    if (!saw_non_newline_char_) {
      do {
        const char c = *message_current;
        if (c != '\r' && c != '\n') {
          if (CHAR_LE(c, ' ')) {
            HandleError(BalsaFrameEnums::NO_REQUEST_LINE_IN_REQUEST);
            return message_current - original_message_start;
          }
          break;
        }
        ++message_current;
        if (message_current == message_end) {
          return message_current - original_message_start;
        }
      } while (true);
      saw_non_newline_char_ = true;
      message_start = message_current;
      checkpoint = message_current;
    }
    while (message_current < message_end) {
      if (*message_current != '\n') {
        ++message_current;
        continue;
      }
      const size_t relative_idx = message_current - message_start;
      const size_t message_current_idx = 1 + base_idx + relative_idx;
      lines_.push_back(std::make_pair(last_slash_n_idx_, message_current_idx));
      if (lines_.size() == 1) {
        headers_->WriteFromFramer(checkpoint, 1 + message_current - checkpoint);
        checkpoint = message_current + 1;
        char* begin = headers_->OriginalHeaderStreamBegin();

        QUICHE_DVLOG(1) << "First line "
                        << std::string(begin, lines_[0].second);
        QUICHE_DVLOG(1) << "is_request_: " << is_request_;
        ProcessFirstLine(begin, begin + lines_[0].second);
        if (parse_state_ == BalsaFrameEnums::MESSAGE_FULLY_READ) {
          break;
        }

        if (parse_state_ == BalsaFrameEnums::ERROR) {
          return message_current - original_message_start;
        }
      }
      const size_t chars_since_last_slash_n =
          (message_current_idx - last_slash_n_idx_);
      last_slash_n_idx_ = message_current_idx;
      if (chars_since_last_slash_n > 2) {
        // false positive.
        ++message_current;
        continue;
      }
      if ((chars_since_last_slash_n == 1) ||
          (((message_current > message_start) &&
            (*(message_current - 1) == '\r')) ||
           (last_char_was_slash_r_))) {
        break;
      }
      ++message_current;
    }

    if (message_current == message_end) {
      continue;
    }

    ++message_current;
    QUICHE_DCHECK(message_current >= message_start);
    if (message_current > message_start) {
      headers_->WriteFromFramer(checkpoint, message_current - checkpoint);
    }

    // Check if we have exceeded maximum headers length
    // Although we check for this limit before and after we call this function
    // we check it here as well to make sure that in case the visitor changed
    // the max_header_length_ (for example after processing the first line)
    // we handle it gracefully.
    if (headers_->GetReadableBytesFromHeaderStream() > max_header_length_) {
      HandleHeadersTooLongError();
      return message_current - original_message_start;
    }

    // Since we know that we won't be writing any more bytes of the header,
    // we tell that to the headers object. The headers object may make
    // more efficient allocation decisions when this is signaled.
    headers_->DoneWritingFromFramer();
    visitor_->OnHeaderInput(headers_->GetReadablePtrFromHeaderStream());

    // Ok, now that we've written everything into our header buffer, it is
    // time to process the header lines (extract proper values for headers
    // which are important for framing).
    ProcessHeaderLines(lines_, false /*is_trailer*/, headers_);
    if (parse_state_ == BalsaFrameEnums::ERROR) {
      return message_current - original_message_start;
    }

    if (use_interim_headers_callback_ &&
        IsInterimResponse(headers_->parsed_response_code()) &&
        headers_->parsed_response_code() != kSwitchingProtocolsStatusCode) {
      // Deliver headers from this interim response but reset everything else to
      // prepare for the next set of headers. Skip 101 Switching Protocols
      // because these are considered final headers for the current protocol.
      visitor_->OnInterimHeaders(
          std::make_unique<BalsaHeaders>(std::move(*headers_)));
      Reset();
      checkpoint = message_start = message_current;
      continue;
    }
    if (continue_headers_ != nullptr &&
        headers_->parsed_response_code_ == kContinueStatusCode) {
      // Save the headers from this 100 Continue response but reset everything
      // else to prepare for the next set of headers.
      BalsaHeaders saved_continue_headers = std::move(*headers_);
      Reset();
      *continue_headers_ = std::move(saved_continue_headers);
      visitor_->ContinueHeaderDone();
      checkpoint = message_start = message_current;
      continue;
    }
    AssignParseStateAfterHeadersHaveBeenParsed();
    if (parse_state_ == BalsaFrameEnums::ERROR) {
      return message_current - original_message_start;
    }
    visitor_->ProcessHeaders(*headers_);
    visitor_->HeaderDone();
    if (parse_state_ == BalsaFrameEnums::MESSAGE_FULLY_READ) {
      visitor_->MessageDone();
    }
    return message_current - original_message_start;
  }
  // If we've gotten to here, it means that we've consumed all of the
  // available input. We need to record whether or not the last character we
  // saw was a '\r' so that a subsequent call to ProcessInput correctly finds
  // a header framing that is split across the two calls.
  last_char_was_slash_r_ = (*(message_end - 1) == '\r');
  QUICHE_DCHECK(message_current >= message_start);
  if (message_current > message_start) {
    headers_->WriteFromFramer(checkpoint, message_current - checkpoint);
  }
  return message_current - original_message_start;
}

size_t BalsaFrame::BytesSafeToSplice() const {
  switch (parse_state_) {
    case BalsaFrameEnums::READING_CHUNK_DATA:
      return chunk_length_remaining_;
    case BalsaFrameEnums::READING_UNTIL_CLOSE:
      return std::numeric_limits<size_t>::max();
    case BalsaFrameEnums::READING_CONTENT:
      return content_length_remaining_;
    default:
      return 0;
  }
}

void BalsaFrame::BytesSpliced(size_t bytes_spliced) {
  switch (parse_state_) {
    case BalsaFrameEnums::READING_CHUNK_DATA:
      if (chunk_length_remaining_ < bytes_spliced) {
        HandleError(BalsaFrameEnums::
                        CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT);
        return;
      }
      chunk_length_remaining_ -= bytes_spliced;
      if (chunk_length_remaining_ == 0) {
        parse_state_ = BalsaFrameEnums::READING_CHUNK_TERM;
      }
      return;

    case BalsaFrameEnums::READING_UNTIL_CLOSE:
      return;

    case BalsaFrameEnums::READING_CONTENT:
      if (content_length_remaining_ < bytes_spliced) {
        HandleError(BalsaFrameEnums::
                        CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT);
        return;
      }
      content_length_remaining_ -= bytes_spliced;
      if (content_length_remaining_ == 0) {
        parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
        visitor_->MessageDone();
      }
      return;

    default:
      HandleError(BalsaFrameEnums::CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO);
      return;
  }
}

size_t BalsaFrame::ProcessInput(const char* input, size_t size) {
  const char* current = input;
  const char* on_entry = current;
  const char* end = current + size;

  QUICHE_DCHECK(headers_ != nullptr);
  if (headers_ == nullptr) {
    return 0;
  }

  if (parse_state_ == BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE) {
    const size_t header_length = headers_->GetReadableBytesFromHeaderStream();
    // Yes, we still have to check this here as the user can change the
    // max_header_length amount!
    // Also it is possible that we have reached the maximum allowed header size,
    // and we have more to consume (remember we are still inside
    // READING_HEADER_AND_FIRSTLINE) in which case we directly declare an error.
    if (header_length > max_header_length_ ||
        (header_length == max_header_length_ && size > 0)) {
      HandleHeadersTooLongError();
      return current - input;
    }
    const size_t bytes_to_process =
        std::min(max_header_length_ - header_length, size);
    current += ProcessHeaders(input, bytes_to_process);
    // If we are still reading headers check if we have crossed the headers
    // limit. Note that we check for >= as opposed to >. This is because if
    // header_length_after equals max_header_length_ and we are still in the
    // parse_state_  BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE we know for
    // sure that the headers limit will be crossed later on
    if (parse_state_ == BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE) {
      // Note that headers_ is valid only if we are still reading headers.
      const size_t header_length_after =
          headers_->GetReadableBytesFromHeaderStream();
      if (header_length_after >= max_header_length_) {
        HandleHeadersTooLongError();
      }
    }
    return current - input;
  }

  if (parse_state_ == BalsaFrameEnums::MESSAGE_FULLY_READ ||
      parse_state_ == BalsaFrameEnums::ERROR) {
    // Can do nothing more 'till we're reset.
    return current - input;
  }

  QUICHE_DCHECK_LE(current, end);
  if (current == end) {
    return current - input;
  }

  while (true) {
    switch (parse_state_) {
      case BalsaFrameEnums::READING_CHUNK_LENGTH:
        // In this state we read the chunk length.
        // Note that once we hit a character which is not in:
        // [0-9;A-Fa-f\n], we transition to a different state.
        //
        QUICHE_DCHECK_LE(current, end);
        while (true) {
          if (current == end) {
            visitor_->OnRawBodyInput(
                absl::string_view(on_entry, current - on_entry));
            return current - input;
          }

          const char c = *current;
          ++current;

          static const signed char kBad = -1;
          static const signed char kDelimiter = -2;

          // valid cases:
          //  "09123\n"                      // -> 09123
          //  "09123\r\n"                    // -> 09123
          //  "09123  \n"                    // -> 09123
          //  "09123  \r\n"                  // -> 09123
          //  "09123  12312\n"               // -> 09123
          //  "09123  12312\r\n"             // -> 09123
          //  "09123; foo=bar\n"             // -> 09123
          //  "09123; foo=bar\r\n"           // -> 09123
          //  "FFFFFFFFFFFFFFFF\r\n"         // -> FFFFFFFFFFFFFFFF
          //  "FFFFFFFFFFFFFFFF 22\r\n"      // -> FFFFFFFFFFFFFFFF
          // invalid cases:
          // "[ \t]+[^\n]*\n"
          // "FFFFFFFFFFFFFFFFF\r\n"  (would overflow)
          // "\r\n"
          // "\n"
          signed char addition = kBad;
          // clang-format off
          switch (c) {
            case '0': addition = 0; break;
            case '1': addition = 1; break;
            case '2': addition = 2; break;
            case '3': addition = 3; break;
            case '4': addition = 4; break;
            case '5': addition = 5; break;
            case '6': addition = 6; break;
            case '7': addition = 7; break;
            case '8': addition = 8; break;
            case '9': addition = 9; break;
            case 'a': addition = 0xA; break;
            case 'b': addition = 0xB; break;
            case 'c': addition = 0xC; break;
            case 'd': addition = 0xD; break;
            case 'e': addition = 0xE; break;
            case 'f': addition = 0xF; break;
            case 'A': addition = 0xA; break;
            case 'B': addition = 0xB; break;
            case 'C': addition = 0xC; break;
            case 'D': addition = 0xD; break;
            case 'E': addition = 0xE; break;
            case 'F': addition = 0xF; break;
            case '\t':
            case '\n':
            case '\r':
            case ' ':
            case ';':
              addition = kDelimiter;
              break;
            default:
              // Leave addition == kBad
              break;
          }
          // clang-format on
          if (addition >= 0) {
            chunk_length_character_extracted_ = true;
            size_t length_x_16 = chunk_length_remaining_ * 16;
            const size_t kMaxDiv16 = std::numeric_limits<size_t>::max() / 16;
            if ((chunk_length_remaining_ > kMaxDiv16) ||
                (std::numeric_limits<size_t>::max() - length_x_16) <
                    static_cast<size_t>(addition)) {
              // overflow -- asked for a chunk-length greater than 2^64 - 1!!
              visitor_->OnRawBodyInput(
                  absl::string_view(on_entry, current - on_entry));
              HandleError(BalsaFrameEnums::CHUNK_LENGTH_OVERFLOW);
              return current - input;
            }
            chunk_length_remaining_ = length_x_16 + addition;
            continue;
          }

          if (!chunk_length_character_extracted_ || addition == kBad) {
            // ^[0-9;A-Fa-f][ \t\n] -- was not matched, either because no
            // characters were converted, or an unexpected character was
            // seen.
            visitor_->OnRawBodyInput(
                absl::string_view(on_entry, current - on_entry));
            HandleError(BalsaFrameEnums::INVALID_CHUNK_LENGTH);
            return current - input;
          }

          break;
        }

        --current;
        parse_state_ = BalsaFrameEnums::READING_CHUNK_EXTENSION;
        last_char_was_slash_r_ = false;
        visitor_->OnChunkLength(chunk_length_remaining_);
        continue;

      case BalsaFrameEnums::READING_CHUNK_EXTENSION: {
        // TODO(phython): Convert this scanning to be 16 bytes at a time if
        // there is data to be read.
        const char* extensions_start = current;
        size_t extensions_length = 0;
        QUICHE_DCHECK_LE(current, end);
        while (true) {
          if (current == end) {
            visitor_->OnChunkExtensionInput(
                absl::string_view(extensions_start, extensions_length));
            visitor_->OnRawBodyInput(
                absl::string_view(on_entry, current - on_entry));
            return current - input;
          }
          const char c = *current;
          if (http_validation_policy_.disallow_lone_cr_in_chunk_extension) {
            // This is a CR character and the next one is not LF.
            const bool cr_followed_by_non_lf =
                c == '\r' && current + 1 < end && *(current + 1) != '\n';
            // The last character processed by the last ProcessInput() call was
            // CR, this is the first character of the current ProcessInput()
            // call, and it is not LF.
            const bool previous_cr_followed_by_non_lf =
                last_char_was_slash_r_ && current == input && c != '\n';
            if (cr_followed_by_non_lf || previous_cr_followed_by_non_lf) {
              HandleError(BalsaFrameEnums::INVALID_CHUNK_EXTENSION);
              return current - input;
            }
            if (current + 1 == end) {
              last_char_was_slash_r_ = c == '\r';
            }
          }
          if (c == '\r' || c == '\n') {
            extensions_length = (extensions_start == current)
                                    ? 0
                                    : current - extensions_start - 1;
          }

          ++current;
          if (c == '\n') {
            break;
          }
        }

        chunk_length_character_extracted_ = false;
        visitor_->OnChunkExtensionInput(
            absl::string_view(extensions_start, extensions_length));

        if (chunk_length_remaining_ != 0) {
          parse_state_ = BalsaFrameEnums::READING_CHUNK_DATA;
          continue;
        }

        HeaderFramingFound('\n');
        parse_state_ = BalsaFrameEnums::READING_LAST_CHUNK_TERM;
        continue;
      }

      case BalsaFrameEnums::READING_CHUNK_DATA:
        while (current < end) {
          if (chunk_length_remaining_ == 0) {
            break;
          }
          // read in the chunk
          size_t bytes_remaining = end - current;
          size_t consumed_bytes = (chunk_length_remaining_ < bytes_remaining)
                                      ? chunk_length_remaining_
                                      : bytes_remaining;
          const char* tmp_current = current + consumed_bytes;
          visitor_->OnRawBodyInput(
              absl::string_view(on_entry, tmp_current - on_entry));
          visitor_->OnBodyChunkInput(
              absl::string_view(current, consumed_bytes));
          on_entry = current = tmp_current;
          chunk_length_remaining_ -= consumed_bytes;
        }

        if (chunk_length_remaining_ == 0) {
          parse_state_ = BalsaFrameEnums::READING_CHUNK_TERM;
          continue;
        }

        visitor_->OnRawBodyInput(
            absl::string_view(on_entry, current - on_entry));
        return current - input;

      case BalsaFrameEnums::READING_CHUNK_TERM:
        QUICHE_DCHECK_LE(current, end);
        while (true) {
          if (current == end) {
            visitor_->OnRawBodyInput(
                absl::string_view(on_entry, current - on_entry));
            return current - input;
          }

          const char c = *current;
          ++current;

          if (c == '\n') {
            break;
          }
        }
        parse_state_ = BalsaFrameEnums::READING_CHUNK_LENGTH;
        continue;

      case BalsaFrameEnums::READING_LAST_CHUNK_TERM:
        QUICHE_DCHECK_LE(current, end);
        while (true) {
          if (current == end) {
            visitor_->OnRawBodyInput(
                absl::string_view(on_entry, current - on_entry));
            return current - input;
          }

          const char c = *current;
          if (HeaderFramingFound(c) != 0) {
            // If we've found a "\r\n\r\n", then the message
            // is done.
            ++current;
            parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
            visitor_->OnRawBodyInput(
                absl::string_view(on_entry, current - on_entry));
            visitor_->MessageDone();
            return current - input;
          }

          // If not, however, since the spec only suggests that the
          // client SHOULD indicate the presence of trailers, we get to
          // *test* that they did or didn't.
          // If all of the bytes we've seen since:
          //   OPTIONAL_WS 0 OPTIONAL_STUFF CRLF
          // are either '\r', or '\n', then we can assume that we don't yet
          // know if we need to parse headers, or if the next byte will make
          // the HeaderFramingFound condition (above) true.
          if (!HeaderFramingMayBeFound()) {
            break;
          }

          // If HeaderFramingMayBeFound(), then we have seen only characters
          // '\r' or '\n'.
          ++current;

          // Lets try again! There is no state change here.
        }

        // If (!HeaderFramingMayBeFound()), then we know that we must be
        // reading the first non CRLF character of a trailer.
        parse_state_ = BalsaFrameEnums::READING_TRAILER;
        visitor_->OnRawBodyInput(
            absl::string_view(on_entry, current - on_entry));
        on_entry = current;
        continue;

      // TODO(yongfa): No leading whitespace is allowed before field-name per
      // RFC2616. Leading whitespace will cause header parsing error too.
      case BalsaFrameEnums::READING_TRAILER:
        while (current < end) {
          const char c = *current;
          ++current;
          ++trailer_length_;
          if (trailers_ != nullptr) {
            // Reuse the header length limit for trailer, which is just a bunch
            // of headers.
            if (trailer_length_ > max_header_length_) {
              --current;
              HandleError(BalsaFrameEnums::TRAILER_TOO_LONG);
              return current - input;
            }
            if (LineFramingFound(c)) {
              trailer_lines_.push_back(
                  std::make_pair(start_of_trailer_line_, trailer_length_));
              start_of_trailer_line_ = trailer_length_;
            }
          }
          if (HeaderFramingFound(c) != 0) {
            parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
            if (trailers_ != nullptr) {
              trailers_->WriteFromFramer(on_entry, current - on_entry);
              trailers_->DoneWritingFromFramer();
              ProcessHeaderLines(trailer_lines_, true /*is_trailer*/,
                                 trailers_.get());
              if (parse_state_ == BalsaFrameEnums::ERROR) {
                return current - input;
              }
              visitor_->OnTrailers(std::move(trailers_));

              // Allows trailers to be delivered without another call to
              // EnableTrailers() in case the framer is Reset().
              trailers_ = std::make_unique<BalsaHeaders>();
            }
            visitor_->OnTrailerInput(
                absl::string_view(on_entry, current - on_entry));
            visitor_->MessageDone();
            return current - input;
          }
        }
        if (trailers_ != nullptr) {
          trailers_->WriteFromFramer(on_entry, current - on_entry);
        }
        visitor_->OnTrailerInput(
            absl::string_view(on_entry, current - on_entry));
        return current - input;

      case BalsaFrameEnums::READING_UNTIL_CLOSE: {
        const size_t bytes_remaining = end - current;
        if (bytes_remaining > 0) {
          visitor_->OnRawBodyInput(absl::string_view(current, bytes_remaining));
          visitor_->OnBodyChunkInput(
              absl::string_view(current, bytes_remaining));
          current += bytes_remaining;
        }
        return current - input;
      }

      case BalsaFrameEnums::READING_CONTENT:
        while ((content_length_remaining_ != 0u) && current < end) {
          // read in the content
          const size_t bytes_remaining = end - current;
          const size_t consumed_bytes =
              (content_length_remaining_ < bytes_remaining)
                  ? content_length_remaining_
                  : bytes_remaining;
          visitor_->OnRawBodyInput(absl::string_view(current, consumed_bytes));
          visitor_->OnBodyChunkInput(
              absl::string_view(current, consumed_bytes));
          current += consumed_bytes;
          content_length_remaining_ -= consumed_bytes;
        }
        if (content_length_remaining_ == 0) {
          parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
          visitor_->MessageDone();
        }
        return current - input;

      default:
        // The state-machine should never be in a state that isn't handled
        // above.  This is a glaring logic error, and we should do something
        // drastic to ensure that this gets looked-at and fixed.
        QUICHE_LOG(FATAL) << "Unknown state: " << parse_state_  // COV_NF_LINE
                          << " memory corruption?!";            // COV_NF_LINE
    }
  }
}

void BalsaFrame::HandleHeadersTooLongError() {
  if (parse_truncated_headers_even_when_headers_too_long_) {
    const size_t len = headers_->GetReadableBytesFromHeaderStream();
    const char* stream_begin = headers_->OriginalHeaderStreamBegin();

    if (last_slash_n_idx_ < len && stream_begin[last_slash_n_idx_] != '\r') {
      // We write an end to the truncated line, and a blank line to end the
      // headers, to end up with something that will parse.
      static const absl::string_view kTwoLineEnds = "\r\n\r\n";
      headers_->WriteFromFramer(kTwoLineEnds.data(), kTwoLineEnds.size());

      // This is the last, truncated line.
      lines_.push_back(std::make_pair(last_slash_n_idx_, len + 2));
      // A blank line to end the headers.
      lines_.push_back(std::make_pair(len + 2, len + 4));
    }

    ProcessHeaderLines(lines_, /*is_trailer=*/false, headers_);
  }

  HandleError(BalsaFrameEnums::HEADERS_TOO_LONG);
}

const int32_t BalsaFrame::kValidTerm1;
const int32_t BalsaFrame::kValidTerm1Mask;
const int32_t BalsaFrame::kValidTerm2;
const int32_t BalsaFrame::kValidTerm2Mask;

}  // namespace quiche

#undef CHAR_LT
#undef CHAR_LE
#undef CHAR_GT
#undef CHAR_GE
#undef QUICHE_DCHECK_CHAR_GE
```