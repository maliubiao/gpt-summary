Response:
Let's break down the thought process for analyzing the `multipart_parser.cc` file.

1. **Understand the Core Purpose:** The file name `multipart_parser.cc` immediately suggests its primary function: parsing multipart data. The `blink/renderer/core/fetch` path hints that this is related to fetching resources over the network within the Blink rendering engine (part of Chromium). Multipart data is often used for forms with file uploads or when a single response contains multiple independent data entities.

2. **Identify Key Classes/Structures:**  Skimming the code reveals the central class: `MultipartParser`. Within this class, there's a nested `Matcher` class. The presence of an `enum State` is a strong indicator of a state machine implementation, which is common for parsing tasks. The `Client` interface suggests a delegate pattern for notifying the user of parsing events.

3. **Decipher the State Machine:** The `enum State` is crucial. Reading through its members (`kParsingPreamble`, `kParsingDelimiterSuffix`, `kParsingPartHeaderFields`, etc.) gives a high-level overview of the parsing process. It starts with a preamble, then parses delimiters, header fields, part data, and eventually an epilogue. The "close delimiter" state indicates support for ending the multipart stream.

4. **Analyze the `Matcher` Class:**  The `Matcher` class is responsible for finding specific byte sequences (like delimiters). Its `Match()` method and `num_matched_bytes_` member indicate incremental matching. This is efficient for streaming data where the entire input might not be available at once.

5. **Examine the `MultipartParser` Methods:**

    * **Constructor:**  The constructor takes the `boundary` string and a `Client` pointer. The manipulation of the `delimiter_` (adding `\r\n--`) is important for understanding the structure of a multipart message.
    * **`AppendData()`:** This is the core method for feeding data to the parser. The `while (!bytes.empty())` loop and the `switch (state_)` suggest a state-driven processing of the input data. Each case corresponds to a different parsing stage.
    * **`Cancel()` and `Finish()`:** These methods provide control over the parsing process, allowing for early termination or finalization.
    * **Helper Methods (e.g., `ParseDelimiter`, `ParseHeaderFields`, `ParseTransportPadding`):**  These break down the parsing logic into smaller, more manageable units. `ParseHeaderFields` calls out to another parsing function (`ParseMultipartFormHeadersFromBody`), indicating a dependency on existing header parsing logic.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**

    * **HTML Forms (`<form>`):** The most direct connection is to HTML forms with `enctype="multipart/form-data"`. When such a form is submitted, the browser encodes the data (including file uploads) as a multipart message. This parser would be responsible for processing the *response* to such a form submission if the server sends back multipart data (which is less common for form responses but possible).
    * **`fetch()` API (JavaScript):** The `fetch()` API can be used to send or receive multipart data. The `multipart_parser.cc` would be involved in handling the response if the `Content-Type` header indicates a multipart format.
    * **Server-Sent Events (SSE):**  While less direct, some SSE implementations might use multipart as a way to transmit multiple events in a single stream. This parser *could* potentially be involved in such scenarios, though SSE has its own simpler format. *Initial thought might be too broad here, need to focus on direct relevance.*  The file's location (`blink/renderer/core/fetch`) strengthens the connection to network requests and responses.

7. **Consider Logic and Assumptions:**

    * **Delimiter Matching:** The parser relies heavily on finding the boundary delimiter to separate parts. The assumptions about the delimiter format (`\r\n--<boundary>`) are crucial.
    * **State Transitions:**  The parsing logic depends on correctly transitioning between states based on the matched data.
    * **Error Handling (Implicit):**  While there isn't explicit error *reporting* in this code snippet, the state machine implicitly handles situations where the input doesn't match the expected format by staying in a particular state or returning `false` from `AppendData()`. The `Cancel()` method provides a way to handle unrecoverable errors.

8. **Identify Potential User/Programming Errors:**

    * **Incorrect Boundary:**  The most obvious error is a mismatch between the boundary specified in the `Content-Type` header and the actual boundary used in the message body.
    * **Malformed Multipart Message:**  Missing delimiters, incorrect ordering of headers and data, or extra characters can all confuse the parser.
    * **Premature Termination:**  Canceling the parsing prematurely could lead to incomplete data processing.

9. **Debug Scenario:**  Think about how a developer might end up looking at this code during debugging. A common scenario would be investigating issues with file uploads or responses containing multipart data. The steps involve setting breakpoints within `AppendData()` and stepping through the state transitions to see if the parser is behaving as expected given the input data. Network inspection tools would be used to examine the raw HTTP request and response.

10. **Refine and Organize:**  Finally, structure the analysis logically, starting with the core functionality and then expanding to related concepts, examples, and potential issues. Use clear headings and bullet points for readability. Double-check the accuracy of the connections to web technologies. For example, initially, I might have thought about general network parsing, but the specific location of the file within Blink's `fetch` module points to its role in handling HTTP responses.
好的，我们来分析一下 `blink/renderer/core/fetch/multipart_parser.cc` 这个文件的功能及其与前端技术的关系，并探讨可能的使用错误和调试线索。

**文件功能：**

`multipart_parser.cc` 文件实现了 **multipart 数据的解析器**。Multipart 是一种用于在单个 HTTP 消息体中组合多个不同类型数据的格式。它常用于：

1. **HTML 表单提交包含文件上传的情况 (`enctype="multipart/form-data"`)**:  浏览器会将表单数据和文件内容封装成 multipart 消息发送给服务器。
2. **服务器推送多个独立资源**:  虽然不常见，但服务器可以使用 multipart 格式来一次性推送多个独立的资源给客户端。
3. **某些 API 的数据传输**: 有些 API 可能采用 multipart 格式传输数据。

**具体来说，`MultipartParser` 类的功能是：**

* **解析 multipart 消息体的结构**:  它识别消息中的边界 (boundary)，分隔不同的 part。
* **提取每个 part 的头部信息 (header fields)**:  例如 `Content-Type`, `Content-Disposition` 等。
* **提取每个 part 的实际数据 (body)**.
* **处理 preamble 和 epilogue**:  Multipart 消息可以有前导 (preamble) 和尾部 (epilogue) 数据，解析器需要识别并跳过它们。
* **支持取消解析**: 提供 `Cancel()` 方法来提前终止解析过程。
* **支持完成解析**: 提供 `Finish()` 方法来处理解析完成后的状态。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **HTML 和 JavaScript (通过 `fetch` 或 `XMLHttpRequest`)**:
   - **场景**:  一个包含文件上传的 HTML 表单被提交。
   - **用户操作**: 用户在 `<input type="file">` 元素中选择文件，并点击提交按钮。
   - **浏览器行为**: 浏览器将表单数据（包括文件名和文件内容）编码成 `multipart/form-data` 格式的 HTTP 请求体。
   - **`MultipartParser` 的作用**: 当服务器返回一个 `Content-Type` 为 `multipart/*` 的响应时，Blink 引擎会使用 `MultipartParser` 来解析响应体，提取各个 part 的数据（例如，可能包含服务器处理结果或上传文件的元数据）。
   - **假设输入与输出**:
     - **假设输入 (响应体片段)**:
       ```
       --boundary123
       Content-Disposition: form-data; name="status"

       success
       --boundary123
       Content-Disposition: form-data; name="uploaded_file"; filename="image.png"
       Content-Type: image/png

       <PNG 文件二进制数据>
       --boundary123--\r\n
       ```
     - **输出 (通过 `Client` 接口回调)**:
       - `PartHeaderFieldsInMultipartReceived`:  收到 `status` part 的头部信息 `Content-Disposition: form-data; name="status"`。
       - `PartDataInMultipartReceived`: 收到 `status` part 的数据 `success`。
       - `PartHeaderFieldsInMultipartReceived`: 收到 `uploaded_file` part 的头部信息 `Content-Disposition: form-data; name="uploaded_file"; filename="image.png"` 和 `Content-Type: image/png`。
       - `PartDataInMultipartReceived`: 收到 `uploaded_file` part 的 PNG 文件二进制数据。
       - `PartDataInMultipartFullyReceived`:  `uploaded_file` part 的数据接收完成。

2. **JavaScript `fetch` API 处理 multipart 响应**:
   - **场景**:  JavaScript 使用 `fetch` API 发起请求，服务器返回一个 `multipart/mixed` 类型的响应，包含多个 JSON 对象。
   - **用户操作**:  用户可能触发某个 JavaScript 事件导致 `fetch` 请求的发送。
   - **`MultipartParser` 的作用**:  `MultipartParser` 用于解析响应体，将不同的 JSON 对象提取出来，并通过 `Client` 接口回调给上层，最终这些数据可能被 JavaScript 代码处理。
   - **假设输入与输出**:
     - **假设输入 (响应体片段)**:
       ```
       --another_boundary
       Content-Type: application/json

       {"id": 1, "name": "Item 1"}
       --another_boundary
       Content-Type: application/json

       {"id": 2, "name": "Item 2"}
       --another_boundary--\r\n
       ```
     - **输出 (通过 `Client` 接口回调)**:
       - `PartHeaderFieldsInMultipartReceived`: 收到第一个 JSON part 的头部信息 `Content-Type: application/json`。
       - `PartDataInMultipartReceived`: 收到第一个 JSON part 的数据 `{"id": 1, "name": "Item 1"}`。
       - `PartDataInMultipartFullyReceived`:  第一个 JSON part 的数据接收完成。
       - `PartHeaderFieldsInMultipartReceived`: 收到第二个 JSON part 的头部信息 `Content-Type: application/json`。
       - `PartDataInMultipartReceived`: 收到第二个 JSON part 的数据 `{"id": 2, "name": "Item 2"}`。
       - `PartDataInMultipartFullyReceived`:  第二个 JSON part 的数据接收完成。

3. **CSS**:  CSS 本身不直接涉及 multipart 数据的生成或解析。然而，如果通过 JavaScript 发起请求获取 multipart 响应，并且响应中的某些 part 包含 CSS 数据，那么 `MultipartParser` 会负责解析这些 CSS 数据部分，JavaScript 可以进一步处理这些 CSS。

**用户或编程常见的使用错误：**

1. **服务端返回的 `Content-Type` 声明与实际数据不符**:  如果服务端声明是 `multipart/form-data`，但实际发送的格式不符合规范，会导致解析失败。
2. **边界 (boundary) 设置错误或不一致**:  `Content-Type` 头部会指定 boundary，如果实际消息体中使用的 boundary 与声明的不一致，解析器将无法正确分隔 parts。
   - **举例**: 服务端 `Content-Type` 设置为 `multipart/mixed; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW`，但实际消息体中使用了 `--my_custom_boundary`。
3. **缺少必要的头部信息**:  每个 part 通常需要包含 `Content-Disposition` 头部，尤其是在表单提交时。缺少这些头部可能导致解析错误。
4. **提前关闭连接或发送不完整的 multipart 消息**: 如果在所有 part 发送完毕前关闭连接，`MultipartParser` 可能会停留在某个状态，导致解析不完整。
5. **在客户端错误地构造 multipart 请求**: 如果开发者手动构建 multipart 请求（例如，使用 `fetch` API），可能会错误地添加额外的空格、换行符，或者错误地编码数据。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户正在使用一个包含文件上传功能的网页：

1. **用户打开网页**: 浏览器加载 HTML, CSS 和 JavaScript。
2. **用户填写表单**: 用户在表单的输入框中输入文本。
3. **用户选择文件**: 用户点击 `<input type="file">` 元素，并从文件系统中选择一个或多个文件。
4. **用户点击提交按钮**: 浏览器开始构建 HTTP 请求。
5. **浏览器设置请求头**:  浏览器根据表单的 `enctype="multipart/form-data"` 设置 `Content-Type` 头部，并生成一个唯一的 boundary。
6. **浏览器编码请求体**: 浏览器将表单数据和文件内容按照 multipart 格式编码到请求体中。
7. **请求发送到服务器**: 浏览器将请求发送到服务器。
8. **服务器处理请求并返回响应**: 服务器接收请求，处理上传的文件和表单数据，并生成一个 HTTP 响应。
9. **响应头指示 multipart 内容**: 服务器在响应头中设置 `Content-Type` 为 `multipart/related; boundary=...` 或其他 `multipart/*` 类型。
10. **Blink 引擎接收响应**: 浏览器的网络层接收到响应数据。
11. **触发 `MultipartParser`**:  由于响应头的 `Content-Type` 指示了 multipart 内容，Blink 引擎会创建 `MultipartParser` 的实例，并将响应体的数据逐步传递给 `AppendData()` 方法进行解析。
12. **解析过程**: `MultipartParser` 根据 boundary 识别不同的 part，提取每个 part 的头部信息和数据。
13. **通过 `Client` 接口通知上层**:  解析器将解析出的信息（头部信息，数据）通过 `Client` 接口回调给上层模块，例如负责处理网络响应的模块。
14. **JavaScript 获取数据**:  上层模块可能将解析出的数据传递给 JavaScript 代码，例如，通过 `fetch` API 的 `then()` 回调函数。

**调试线索**:

如果在文件上传或处理 multipart 响应时遇到问题，可以按照以下步骤进行调试：

1. **检查请求头和响应头**: 使用浏览器的开发者工具 (Network 面板) 查看 HTTP 请求和响应的头部信息，特别是 `Content-Type` 和 `boundary` 的值，确保它们是正确的。
2. **检查请求体和响应体**:  查看请求和响应的原始数据，确认 multipart 消息的格式是否符合规范，boundary 是否正确使用，是否存在额外的空格或换行符。
3. **断点调试 `multipart_parser.cc`**:  在 Chromium 的源代码中设置断点，例如在 `AppendData()` 方法的入口，以及状态机切换的地方，逐步跟踪解析过程，查看数据是如何被解析的，以及状态是如何变化的。
4. **查看 `Client` 接口的实现**:  了解 `MultipartParser` 如何将解析结果通知给上层，查看 `Client` 接口的具体实现，确认数据是否被正确传递。
5. **对比预期输入输出**:  根据 multipart 格式的规范，手动构造一些简单的测试用例，并与实际的输入输出进行对比，找出差异。

总之，`multipart_parser.cc` 在处理涉及多部分数据的网络通信中扮演着关键角色，特别是在 Web 开发中常见的表单文件上传场景。理解其工作原理对于调试相关问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/fetch/multipart_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/multipart_parser.h"

#include <algorithm>
#include <utility>

#include "base/containers/span.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

namespace {

constexpr char kCloseDelimiterSuffix[] = "--\r\n";
constexpr size_t kDashBoundaryOffset = 2u;  // The length of "\r\n".
constexpr char kDelimiterSuffix[] = "\r\n";

}  // namespace

MultipartParser::Matcher::Matcher() = default;

MultipartParser::Matcher::Matcher(base::span<const char> match_data,
                                  size_t num_matched_bytes)
    : match_data_(match_data), num_matched_bytes_(num_matched_bytes) {}

bool MultipartParser::Matcher::Match(base::span<const char> data) {
  for (const char c : data) {
    if (!Match(c)) {
      return false;
    }
  }
  return true;
}

void MultipartParser::Matcher::SetNumMatchedBytes(size_t num_matched_bytes) {
  DCHECK_LE(num_matched_bytes, match_data_.size());
  num_matched_bytes_ = num_matched_bytes;
}

MultipartParser::MultipartParser(Vector<char> boundary, Client* client)
    : client_(client),
      delimiter_(std::move(boundary)),
      state_(State::kParsingPreamble) {
  // The delimiter consists of "\r\n" and a dash boundary which consists of
  // "--" and a boundary.
  delimiter_.push_front("\r\n--", 4u);
  matcher_ = DelimiterMatcher(kDashBoundaryOffset);
}

bool MultipartParser::AppendData(base::span<const char> bytes) {
  DCHECK_NE(State::kFinished, state_);
  DCHECK_NE(State::kCancelled, state_);

  while (!bytes.empty()) {
    switch (state_) {
      case State::kParsingPreamble:
        // Parse either a preamble and a delimiter or a dash boundary.
        ParseDelimiter(bytes);
        if (!matcher_.IsMatchComplete() && !bytes.empty()) {
          // Parse a preamble data (by ignoring it) and then a delimiter.
          matcher_.SetNumMatchedBytes(0u);
          ParseDataAndDelimiter(bytes);
        }
        if (matcher_.IsMatchComplete()) {
          // Prepare for a delimiter suffix.
          matcher_ = DelimiterSuffixMatcher();
          state_ = State::kParsingDelimiterSuffix;
        }
        break;

      case State::kParsingDelimiterSuffix:
        // Parse transport padding and "\r\n" after a delimiter.
        // This state can be reached after either a preamble or part
        // octets are parsed.
        if (matcher_.NumMatchedBytes() == 0u) {
          ParseTransportPadding(bytes);
        }
        while (!bytes.empty()) {
          if (!matcher_.Match(bytes.front())) {
            return false;
          }
          bytes = bytes.subspan(1u);
          if (matcher_.IsMatchComplete()) {
            // Prepare for part header fields.
            state_ = State::kParsingPartHeaderFields;
            break;
          }
        }
        break;

      case State::kParsingPartHeaderFields: {
        // Parse part header fields (which ends with "\r\n") and an empty
        // line (which also ends with "\r\n").
        // This state can be reached after a delimiter and a delimiter
        // suffix after either a preamble or part octets are parsed.
        HTTPHeaderMap header_fields;
        if (ParseHeaderFields(bytes, &header_fields)) {
          // Prepare for part octets.
          matcher_ = DelimiterMatcher();
          state_ = State::kParsingPartOctets;
          client_->PartHeaderFieldsInMultipartReceived(header_fields);
        }
        break;
      }

      case State::kParsingPartOctets: {
        // Parse part octets and a delimiter.
        // This state can be reached only after part header fields are
        // parsed.
        const size_t num_initially_matched_bytes = matcher_.NumMatchedBytes();
        auto bytes_before = bytes;
        ParseDelimiter(bytes);
        if (!matcher_.IsMatchComplete() && !bytes.empty()) {
          if (matcher_.NumMatchedBytes() >= num_initially_matched_bytes &&
              num_initially_matched_bytes > 0u) {
            // Since the matched bytes did not form a complete
            // delimiter, the matched bytes turned out to be octet
            // bytes instead of being delimiter bytes. Additionally,
            // some of the matched bytes are from the previous call and
            // are therefore not in the `bytes_before` span.
            client_->PartDataInMultipartReceived(matcher_.MatchedData());
            if (state_ != State::kParsingPartOctets)
              break;
            bytes_before = bytes;
          }
          matcher_.SetNumMatchedBytes(0u);
          ParseDataAndDelimiter(bytes);

          const size_t skipped_size = bytes_before.size() - bytes.size();
          if (skipped_size > matcher_.NumMatchedBytes()) {
            size_t payload_size = skipped_size - matcher_.NumMatchedBytes();
            auto payload = bytes_before.first(payload_size);
            client_->PartDataInMultipartReceived(payload);
            if (state_ != State::kParsingPartOctets)
              break;
          }
        }
        if (matcher_.IsMatchComplete()) {
          state_ = State::kParsingDelimiterOrCloseDelimiterSuffix;
          client_->PartDataInMultipartFullyReceived();
        }
        break;
      }

      case State::kParsingDelimiterOrCloseDelimiterSuffix:
        // Determine whether this is a delimiter suffix or a close
        // delimiter suffix.
        // This state can be reached only after part octets are parsed.
        if (bytes.front() == '-') {
          // Prepare for a close delimiter suffix.
          matcher_ = CloseDelimiterSuffixMatcher();
          state_ = State::kParsingCloseDelimiterSuffix;
        } else {
          // Prepare for a delimiter suffix.
          matcher_ = DelimiterSuffixMatcher();
          state_ = State::kParsingDelimiterSuffix;
        }
        break;

      case State::kParsingCloseDelimiterSuffix:
        // Parse "--", transport padding and "\r\n" after a delimiter
        // (a delimiter and "--" constitute a close delimiter).
        // This state can be reached only after part octets are parsed.
        for (;;) {
          if (matcher_.NumMatchedBytes() == 2u) {
            ParseTransportPadding(bytes);
          }
          if (bytes.empty()) {
            break;
          }
          if (!matcher_.Match(bytes.front())) {
            return false;
          }
          bytes = bytes.subspan(1u);
          if (matcher_.IsMatchComplete()) {
            // Prepare for an epilogue.
            state_ = State::kParsingEpilogue;
            break;
          }
        }
        break;

      case State::kParsingEpilogue:
        // Parse an epilogue (by ignoring it).
        // This state can be reached only after a delimiter and a close
        // delimiter suffix after part octets are parsed.
        return true;

      case State::kCancelled:
      case State::kFinished:
        // The client changed the state.
        return false;
    }
  }

  DCHECK(bytes.empty());
  return true;
}

void MultipartParser::Cancel() {
  state_ = State::kCancelled;
}

bool MultipartParser::Finish() {
  DCHECK_NE(State::kCancelled, state_);
  DCHECK_NE(State::kFinished, state_);

  const State initial_state = state_;
  state_ = State::kFinished;

  switch (initial_state) {
    case State::kParsingPartOctets:
      if (matcher_.NumMatchedBytes() > 0u) {
        // Since the matched bytes did not form a complete delimiter,
        // the matched bytes turned out to be octet bytes instead of being
        // delimiter bytes.
        client_->PartDataInMultipartReceived(matcher_.MatchedData());
      }
      return false;
    case State::kParsingCloseDelimiterSuffix:
      // Require a full close delimiter consisting of a delimiter and "--"
      // but ignore missing or partial "\r\n" after that.
      return matcher_.NumMatchedBytes() >= 2u;
    case State::kParsingEpilogue:
      return true;
    default:
      return false;
  }
}

MultipartParser::Matcher MultipartParser::CloseDelimiterSuffixMatcher() const {
  return Matcher(base::span_from_cstring(kCloseDelimiterSuffix), 0u);
}

MultipartParser::Matcher MultipartParser::DelimiterMatcher(
    size_t num_already_matched_bytes) const {
  return Matcher(delimiter_, num_already_matched_bytes);
}

MultipartParser::Matcher MultipartParser::DelimiterSuffixMatcher() const {
  return Matcher(base::span_from_cstring(kDelimiterSuffix), 0u);
}

void MultipartParser::ParseDataAndDelimiter(base::span<const char>& bytes) {
  DCHECK_EQ(0u, matcher_.NumMatchedBytes());

  // Search for a complete delimiter within the bytes.
  auto delimiter_begin = base::ranges::search(bytes, delimiter_);
  if (delimiter_begin != bytes.end()) {
    // A complete delimiter was found. The bytes before that are octet
    // bytes.
    auto delimiter_and_rest =
        bytes.subspan(static_cast<size_t>(delimiter_begin - bytes.begin()));
    auto [delimiter, rest] = delimiter_and_rest.split_at(delimiter_.size());
    const bool matched = matcher_.Match(delimiter);
    DCHECK(matched);
    DCHECK(matcher_.IsMatchComplete());
    bytes = rest;
  } else {
    // Search for a partial delimiter in the end of the bytes.
    auto maybe_delimiter_span = bytes.last(
        std::min(static_cast<size_t>(delimiter_.size() - 1u), bytes.size()));
    while (!maybe_delimiter_span.empty()) {
      if (matcher_.Match(maybe_delimiter_span)) {
        break;
      }
      maybe_delimiter_span = maybe_delimiter_span.subspan(1u);
      matcher_.SetNumMatchedBytes(0u);
    }
    // If a partial delimiter was found in the end of bytes, the bytes
    // before the partial delimiter are definitely octets bytes and
    // the partial delimiter bytes are buffered for now.
    // If a partial delimiter was not found in the end of bytes, all bytes
    // are definitely octets bytes.
    // In all cases, all bytes are parsed now.
    bytes = {};
  }

  DCHECK(matcher_.IsMatchComplete() || bytes.empty());
}

void MultipartParser::ParseDelimiter(base::span<const char>& bytes) {
  DCHECK(!matcher_.IsMatchComplete());
  size_t matched = 0;
  while (matched < bytes.size() && matcher_.Match(bytes[matched])) {
    ++matched;
    if (matcher_.IsMatchComplete())
      break;
  }
  bytes = bytes.subspan(matched);
}

bool MultipartParser::ParseHeaderFields(base::span<const char>& bytes,
                                        HTTPHeaderMap* header_fields) {
  // Combine the current bytes with buffered header bytes if needed.
  if (bytes.size() > std::numeric_limits<wtf_size_t>::max()) {
    return false;
  }

  auto header_bytes = bytes;
  if (!buffered_header_bytes_.empty()) {
    buffered_header_bytes_.Append(
        header_bytes.data(),
        base::checked_cast<wtf_size_t>(header_bytes.size()));
    header_bytes = buffered_header_bytes_;
  }

  wtf_size_t end = 0u;
  if (!ParseMultipartFormHeadersFromBody(base::as_bytes(header_bytes),
                                         header_fields, &end)) {
    // Store the current header bytes for the next call unless that has
    // already been done.
    if (buffered_header_bytes_.empty()) {
      buffered_header_bytes_.Append(
          header_bytes.data(),
          base::checked_cast<wtf_size_t>(header_bytes.size()));
    }
    bytes = {};
    return false;
  }
  buffered_header_bytes_.clear();
  bytes = bytes.last(header_bytes.size() - end);
  return true;
}

void MultipartParser::ParseTransportPadding(
    base::span<const char>& bytes) const {
  size_t matched = 0;
  while (matched < bytes.size() &&
         (bytes[matched] == '\t' || bytes[matched] == ' ')) {
    ++matched;
  }
  bytes = bytes.subspan(matched);
}

void MultipartParser::Trace(Visitor* visitor) const {
  visitor->Trace(client_);
}

}  // namespace blink
```