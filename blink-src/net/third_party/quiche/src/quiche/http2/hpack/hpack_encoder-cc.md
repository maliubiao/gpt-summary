Response:
Let's break down the thought process for analyzing the `hpack_encoder.cc` file.

**1. Initial Understanding - The "What":**

The first step is to understand the file's purpose within the larger Chromium networking stack. The path `net/third_party/quiche/src/quiche/http2/hpack/hpack_encoder.cc` is a strong indicator. Keywords like "http2," "hpack," and "encoder" immediately point to HTTP/2 header compression. The copyright notice confirms it's part of Chromium.

**2. Core Functionality - The "How":**

Now, we need to dive into the code to understand *how* it performs header compression. Reading through the class and function names gives a high-level overview:

* `HpackEncoder`: The main class responsible for encoding.
* `EncodeHeaderBlock`: Takes a `HttpHeaderBlock` (likely a map of header name-value pairs) and returns an encoded string. This is the primary entry point for basic encoding.
* `ApplyHeaderTableSizeSetting`:  Handles dynamic table size updates.
* `EncodeRepresentations`: A more internal function likely used by `EncodeHeaderBlock` and progressive encoding.
* `EmitIndex`, `EmitIndexedLiteral`, `EmitNonIndexedLiteral`:  These suggest the different encoding strategies HPACK uses.
* `EmitString`: Handles encoding individual header name or value strings, potentially using Huffman coding.
* `MaybeEmitTableSize`:  Deals with signaling table size changes.
* `CookieToCrumbs`:  A specific function for optimizing cookie header compression.
* `DecomposeRepresentation`:  Handles multi-value headers.
* `Encoderator`:  Implements progressive encoding, useful for large header blocks.

**3. Identifying Key Concepts - The "Why":**

Understanding the "how" naturally leads to identifying the core HPACK concepts implemented:

* **Header Table:** The dynamic table for storing frequently used headers. Functions like `header_table_.GetByNameAndValue`, `header_table_.TryAddEntry` confirm its usage.
* **Indexing:** Encoding by referencing an entry in the header table (`EmitIndex`).
* **Literal Encoding:** Encoding the header name and value directly.
* **Huffman Coding:**  A lossless compression technique for strings (`EmitString`, `HuffmanEncode`, `HuffmanSize`).
* **Dynamic Table Size Updates:**  The ability to change the size of the header table (`ApplyHeaderTableSizeSetting`, `MaybeEmitTableSize`).
* **Cookie Crumbling:**  A specific optimization for the `Cookie` header.
* **Progressive Encoding:**  The ability to encode headers in chunks, useful for large header blocks.

**4. Relationship to JavaScript - The "Where":**

This is where we connect the C++ implementation to its usage in a browser environment. HTTP/2 is the transport protocol, and JavaScript in the browser interacts with it through APIs like `fetch` or `XMLHttpRequest`. The browser's networking stack (where this C++ code resides) handles the actual HTTP/2 communication, including HPACK encoding. Therefore, any `fetch` request with headers will eventually go through this HPACK encoder.

**5. Logic and Examples -  Illustrating the "How":**

To solidify understanding, concrete examples are essential. We need to demonstrate different encoding scenarios:

* **Indexed Header:** A common header already in the table.
* **Literal with Indexing:** A new header added to the table.
* **Literal without Indexing:** A header not added to the table.
* **Cookie Crumbling:**  Showing how a single `Cookie` header is split.
* **Table Size Update:**  Demonstrating the signaling of table size changes.

For each example, providing the assumed input and the likely output helps clarify the encoding process.

**6. Common User/Programming Errors - The "Gotchas":**

Thinking about potential misuse helps provide practical value. Common errors related to HPACK encoding include:

* **Incorrect Header Order:** While HPACK doesn't strictly require a specific order, the encoder *processes* headers in a certain order (pseudo-headers first). This could theoretically impact the efficiency of dynamic table usage if an application aggressively sets and then overrides pseudo-headers.
* **Excessive Table Size Updates:** Repeatedly changing the table size can lead to overhead.
* **Very Large Headers:** While HPACK compresses, extremely large individual headers might still be inefficient.

**7. Debugging and User Operations - Tracing the Path:**

To understand how a user's action leads to this code, we trace a request:

1. User action in the browser (e.g., clicking a link, submitting a form).
2. JavaScript `fetch` or `XMLHttpRequest` API is used.
3. The browser's networking stack constructs the HTTP request, including headers.
4. The `HpackEncoder` is invoked to encode these headers.

This provides context for debugging network issues related to header compression. If a problem arises, a developer might examine network logs, looking for anomalies in the encoded headers.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus too much on the low-level bit manipulation. **Correction:** Shift focus to the higher-level HPACK concepts and how the code implements them.
* **Initial thought:**  Overlook the JavaScript connection. **Correction:** Emphasize the role of this code within the browser's networking stack and how JavaScript APIs trigger its execution.
* **Initial thought:**  Provide overly complex examples. **Correction:** Simplify examples to focus on the core encoding mechanisms.
* **Initial thought:** Not explicitly mentioning the HTTP/2 context. **Correction:** Ensure the explanation clearly states that HPACK is a compression mechanism for HTTP/2.

By following these steps, we can systematically analyze the C++ code and provide a comprehensive explanation of its functionality, relevance to JavaScript, logic, potential errors, and its place in the user's interaction with the web.
这个`hpack_encoder.cc`文件是Chromium网络栈中负责HTTP/2 HPACK（Header Compression for HTTP）编码的核心组件。它的主要功能是将HTTP头部字段（header fields）转换成一种压缩的二进制格式，以便在HTTP/2连接中高效地传输。

以下是该文件的详细功能列表：

**核心功能:**

1. **HTTP头部字段压缩:**  这是最核心的功能。它接收一组HTTP头部字段（name-value对），并使用HPACK算法将其压缩成二进制数据流。
2. **静态表和动态表的使用:** HPACK利用静态表（预定义的常用头部字段）和动态表（最近使用的头部字段）来减少需要传输的数据量。`HpackEncoder`负责查找并利用这些表中的条目。
3. **索引表示 (Indexed Representation):** 如果头部字段在静态表或动态表中存在，编码器会使用其索引来表示该头部字段，大大减少数据量。
4. **字面表示 (Literal Representation):**  如果头部字段不在表中，编码器会将头部名称和值以字面形式编码。
5. **带索引的字面表示 (Literal Representation with Indexing):**  对于不在表中但可能在后续请求中重复出现的头部字段，编码器可以将其添加到动态表中并编码。
6. **不带索引的字面表示 (Literal Representation without Indexing):** 对于不需要索引的头部字段，编码器会将其直接编码而不添加到动态表。
7. **Huffman编码:**  为了进一步减小数据量，编码器可以选择对头部名称和值进行Huffman编码。
8. **动态表大小更新:**  编码器可以发出指令来更新解码器端的动态表大小，以适应不同的网络环境和头部模式。
9. **Cookie头部字段的特殊处理 (Cookie Crumbling):**  为了提高压缩效率，`HpackEncoder`可以将单个`Cookie`头部字段拆分成多个独立的头部字段进行编码。
10. **逐步编码 (Progressive Encoding):**  `Encoderator`类提供了逐步编码的功能，允许将大型头部块分块编码，适用于需要控制编码过程的情况。

**与JavaScript功能的关联:**

JavaScript在浏览器中通过Fetch API或XMLHttpRequest API发起HTTP请求。当JavaScript代码设置请求头时，这些头部信息最终会被传递到Chromium的网络栈进行处理，其中就包括`hpack_encoder.cc`负责的HPACK编码。

**举例说明:**

假设一个JavaScript应用使用Fetch API发送一个GET请求：

```javascript
fetch('https://example.com/data', {
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer my_token_123',
    'Custom-Header': 'some_value'
  }
});
```

当这个请求发送出去时，Chromium的网络栈会调用`HpackEncoder`来编码这些头部字段。

* **假设输入:**  `quiche::HttpHeaderBlock` 包含了以下键值对：
    ```
    {
      {"content-type", "application/json"},
      {"authorization", "Bearer my_token_123"},
      {"custom-header", "some_value"}
    }
    ```

* **逻辑推理与假设输出:**
    1. **`content-type`:**  可能在静态表中，如果存在，则输出可能是表示该索引的二进制数据。例如，假设`content-type: application/json` 在静态表中的索引是 `60`，则输出可能是一个以 `1` 开头的字节，后跟编码后的索引值（根据 HPACK 规范）。
    2. **`authorization`:** 不太可能在静态表中，可能被编码为字面量。编码器可能会选择是否将其添加到动态表。如果决定不添加到动态表，则输出可能是以 `0000` 开头的字节，后跟编码后的 "authorization" 字符串和 "Bearer my_token_123" 字符串。字符串可能使用 Huffman 编码。
    3. **`custom-header`:**  类似 `authorization`，也会被编码为字面量。

* **假设输出 (部分，二进制表示):**
    ```
    10111100  //  表示索引 60 (假设)
    00001000  //  字面量，不带索引
    ...        //  编码后的 "authorization" 字符串 (可能使用 Huffman)
    ...        //  编码后的 "Bearer my_token_123" 字符串 (可能使用 Huffman)
    00001000  //  字面量，不带索引
    ...        //  编码后的 "custom-header" 字符串 (可能使用 Huffman)
    ...        //  编码后的 "some_value" 字符串 (可能使用 Huffman)
    ```

**用户或编程常见的使用错误:**

1. **误解头部字段的顺序重要性:** 虽然HPACK编码器内部会处理头部字段的顺序，但HTTP/2协议本身并没有强制要求特定的头部字段顺序。 然而，编码器的实现方式（例如，先处理伪头部）可能会影响压缩效率。  用户不应该依赖特定的编码顺序。

2. **发送过多的自定义头部字段:**  虽然HPACK可以压缩头部，但发送大量独特的自定义头部字段可能会降低压缩效率，因为这些字段不太可能在动态表中找到匹配项。  开发者应该考虑是否真的需要发送那么多独特的头部。

3. **频繁更改头部字段的值:** 如果一个头部字段的名称相同，但值频繁变化，HPACK的动态表可能无法有效地利用，因为每次变化都可能需要添加新的条目。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中发起网络请求:**  例如，用户在地址栏输入URL并回车，点击链接，或者JavaScript代码发起 `fetch` 或 `XMLHttpRequest` 请求。

2. **浏览器构建HTTP请求:**  浏览器根据用户的操作或JavaScript代码的指示，构建需要发送的HTTP请求，包括请求方法、URL和头部字段。

3. **网络栈处理请求:**  Chromium的网络栈接收到构建好的HTTP请求。

4. **选择HTTP/2协议:** 如果服务器支持HTTP/2，浏览器会与服务器协商使用HTTP/2协议。

5. **HPACK编码:** 在HTTP/2连接建立后，当需要发送HTTP头部时，网络栈会调用`HpackEncoder::EncodeHeaderBlock`（或其他相关方法）将头部字段压缩成HPACK格式。

6. **发送压缩后的头部:** 压缩后的头部数据会作为HTTP/2帧的一部分发送到服务器。

**调试线索:**

* **网络抓包:** 使用如Wireshark等工具抓取网络包，可以查看发送的HTTP/2帧，包括头部帧。解码这些帧可以分析HPACK编码的结果。
* **Chrome DevTools:**  Chrome开发者工具的Network标签可以查看请求的Headers信息。虽然显示的是解码后的头部，但可以帮助理解哪些头部被发送，从而推断编码器可能做了什么。
* **Chromium 内部日志:**  在Chromium的开发版本中，可以启用网络相关的日志（例如使用 `--enable-logging --v=1` 启动 Chrome），查看更详细的HPACK编码过程信息。  `QUICHE_DVLOG(2)` 这样的日志语句会在这种调试模式下输出信息。
* **断点调试:** 如果有Chromium的源代码和调试环境，可以在 `hpack_encoder.cc` 中设置断点，逐步跟踪头部编码的过程，查看动态表的状态、Huffman编码的应用等。

总而言之，`hpack_encoder.cc` 在Chromium网络栈中扮演着至关重要的角色，它负责将HTTP头部字段高效地压缩，从而提升HTTP/2的性能。理解其功能有助于我们更好地理解HTTP/2协议和浏览器的网络工作原理。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/hpack/hpack_encoder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/hpack/hpack_encoder.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/hpack/hpack_constants.h"
#include "quiche/http2/hpack/hpack_header_table.h"
#include "quiche/http2/hpack/hpack_output_stream.h"
#include "quiche/http2/hpack/huffman/hpack_huffman_encoder.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace spdy {

class HpackEncoder::RepresentationIterator {
 public:
  // |pseudo_headers| and |regular_headers| must outlive the iterator.
  RepresentationIterator(const Representations& pseudo_headers,
                         const Representations& regular_headers)
      : pseudo_begin_(pseudo_headers.begin()),
        pseudo_end_(pseudo_headers.end()),
        regular_begin_(regular_headers.begin()),
        regular_end_(regular_headers.end()) {}

  // |headers| must outlive the iterator.
  explicit RepresentationIterator(const Representations& headers)
      : pseudo_begin_(headers.begin()),
        pseudo_end_(headers.end()),
        regular_begin_(headers.end()),
        regular_end_(headers.end()) {}

  bool HasNext() {
    return pseudo_begin_ != pseudo_end_ || regular_begin_ != regular_end_;
  }

  const Representation Next() {
    if (pseudo_begin_ != pseudo_end_) {
      return *pseudo_begin_++;
    } else {
      return *regular_begin_++;
    }
  }

 private:
  Representations::const_iterator pseudo_begin_;
  Representations::const_iterator pseudo_end_;
  Representations::const_iterator regular_begin_;
  Representations::const_iterator regular_end_;
};

namespace {

// The default header listener.
void NoOpListener(absl::string_view /*name*/, absl::string_view /*value*/) {}

// The default HPACK indexing policy.
bool DefaultPolicy(absl::string_view name, absl::string_view /* value */) {
  if (name.empty()) {
    return false;
  }
  // :authority is always present and rarely changes, and has moderate
  // length, therefore it makes a lot of sense to index (insert in the
  // dynamic table).
  if (name[0] == kPseudoHeaderPrefix) {
    return name == ":authority";
  }
  return true;
}

}  // namespace

HpackEncoder::HpackEncoder()
    : output_stream_(),
      min_table_size_setting_received_(std::numeric_limits<size_t>::max()),
      listener_(NoOpListener),
      should_index_(DefaultPolicy),
      enable_compression_(true),
      should_emit_table_size_(false),
      crumble_cookies_(true) {}

HpackEncoder::~HpackEncoder() = default;

std::string HpackEncoder::EncodeHeaderBlock(
    const quiche::HttpHeaderBlock& header_set) {
  // Separate header set into pseudo-headers and regular headers.
  Representations pseudo_headers;
  Representations regular_headers;
  bool found_cookie = false;
  for (const auto& header : header_set) {
    if (!found_cookie && header.first == "cookie") {
      // Note that there can only be one "cookie" header, because header_set is
      // a map.
      found_cookie = true;
      if (crumble_cookies_) {
        CookieToCrumbs(header, &regular_headers);
      } else {
        DecomposeRepresentation(header, &regular_headers);
      }
    } else if (!header.first.empty() &&
               header.first[0] == kPseudoHeaderPrefix) {
      DecomposeRepresentation(header, &pseudo_headers);
    } else {
      DecomposeRepresentation(header, &regular_headers);
    }
  }

  RepresentationIterator iter(pseudo_headers, regular_headers);
  return EncodeRepresentations(&iter);
}

void HpackEncoder::ApplyHeaderTableSizeSetting(size_t size_setting) {
  if (size_setting == header_table_.settings_size_bound()) {
    return;
  }
  if (size_setting < header_table_.settings_size_bound()) {
    min_table_size_setting_received_ =
        std::min(size_setting, min_table_size_setting_received_);
  }
  header_table_.SetSettingsHeaderTableSize(size_setting);
  should_emit_table_size_ = true;
}

std::string HpackEncoder::EncodeRepresentations(RepresentationIterator* iter) {
  MaybeEmitTableSize();
  while (iter->HasNext()) {
    const auto header = iter->Next();
    listener_(header.first, header.second);
    if (enable_compression_) {
      size_t index =
          header_table_.GetByNameAndValue(header.first, header.second);
      if (index != kHpackEntryNotFound) {
        EmitIndex(index);
      } else if (should_index_(header.first, header.second)) {
        EmitIndexedLiteral(header);
      } else {
        EmitNonIndexedLiteral(header, enable_compression_);
      }
    } else {
      EmitNonIndexedLiteral(header, enable_compression_);
    }
  }

  return output_stream_.TakeString();
}

void HpackEncoder::EmitIndex(size_t index) {
  QUICHE_DVLOG(2) << "Emitting index " << index;
  output_stream_.AppendPrefix(kIndexedOpcode);
  output_stream_.AppendUint32(index);
}

void HpackEncoder::EmitIndexedLiteral(const Representation& representation) {
  QUICHE_DVLOG(2) << "Emitting indexed literal: (" << representation.first
                  << ", " << representation.second << ")";
  output_stream_.AppendPrefix(kLiteralIncrementalIndexOpcode);
  EmitLiteral(representation);
  header_table_.TryAddEntry(representation.first, representation.second);
}

void HpackEncoder::EmitNonIndexedLiteral(const Representation& representation,
                                         bool enable_compression) {
  QUICHE_DVLOG(2) << "Emitting nonindexed literal: (" << representation.first
                  << ", " << representation.second << ")";
  output_stream_.AppendPrefix(kLiteralNoIndexOpcode);
  size_t name_index = header_table_.GetByName(representation.first);
  if (enable_compression && name_index != kHpackEntryNotFound) {
    output_stream_.AppendUint32(name_index);
  } else {
    output_stream_.AppendUint32(0);
    EmitString(representation.first);
  }
  EmitString(representation.second);
}

void HpackEncoder::EmitLiteral(const Representation& representation) {
  size_t name_index = header_table_.GetByName(representation.first);
  if (name_index != kHpackEntryNotFound) {
    output_stream_.AppendUint32(name_index);
  } else {
    output_stream_.AppendUint32(0);
    EmitString(representation.first);
  }
  EmitString(representation.second);
}

void HpackEncoder::EmitString(absl::string_view str) {
  size_t encoded_size =
      enable_compression_ ? http2::HuffmanSize(str) : str.size();
  if (encoded_size < str.size()) {
    QUICHE_DVLOG(2) << "Emitted Huffman-encoded string of length "
                    << encoded_size;
    output_stream_.AppendPrefix(kStringLiteralHuffmanEncoded);
    output_stream_.AppendUint32(encoded_size);
    http2::HuffmanEncode(str, encoded_size, output_stream_.MutableString());
  } else {
    QUICHE_DVLOG(2) << "Emitted literal string of length " << str.size();
    output_stream_.AppendPrefix(kStringLiteralIdentityEncoded);
    output_stream_.AppendUint32(str.size());
    output_stream_.AppendBytes(str);
  }
}

void HpackEncoder::MaybeEmitTableSize() {
  if (!should_emit_table_size_) {
    return;
  }
  const size_t current_size = CurrentHeaderTableSizeSetting();
  QUICHE_DVLOG(1) << "MaybeEmitTableSize current_size=" << current_size;
  QUICHE_DVLOG(1) << "MaybeEmitTableSize min_table_size_setting_received_="
                  << min_table_size_setting_received_;
  if (min_table_size_setting_received_ < current_size) {
    output_stream_.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream_.AppendUint32(min_table_size_setting_received_);
  }
  output_stream_.AppendPrefix(kHeaderTableSizeUpdateOpcode);
  output_stream_.AppendUint32(current_size);
  min_table_size_setting_received_ = std::numeric_limits<size_t>::max();
  should_emit_table_size_ = false;
}

// static
void HpackEncoder::CookieToCrumbs(const Representation& cookie,
                                  Representations* out) {
  // See Section 8.1.2.5. "Compressing the Cookie Header Field" in the HTTP/2
  // specification at https://tools.ietf.org/html/draft-ietf-httpbis-http2-14.
  // Cookie values are split into individually-encoded HPACK representations.
  absl::string_view cookie_value = cookie.second;
  // Consume leading and trailing whitespace if present.
  absl::string_view::size_type first = cookie_value.find_first_not_of(" \t");
  absl::string_view::size_type last = cookie_value.find_last_not_of(" \t");
  if (first == absl::string_view::npos) {
    cookie_value = absl::string_view();
  } else {
    cookie_value = cookie_value.substr(first, (last - first) + 1);
  }
  for (size_t pos = 0;;) {
    size_t end = cookie_value.find(';', pos);

    if (end == absl::string_view::npos) {
      out->push_back(std::make_pair(cookie.first, cookie_value.substr(pos)));
      break;
    }
    out->push_back(
        std::make_pair(cookie.first, cookie_value.substr(pos, end - pos)));

    // Consume next space if present.
    pos = end + 1;
    if (pos != cookie_value.size() && cookie_value[pos] == ' ') {
      pos++;
    }
  }
}

// static
void HpackEncoder::DecomposeRepresentation(const Representation& header_field,
                                           Representations* out) {
  std::vector<absl::string_view> pieces =
      absl::StrSplit(header_field.second, '\0');
  out->reserve(pieces.size());
  for (absl::string_view piece : pieces) {
    out->push_back(std::make_pair(header_field.first, piece));
  }
}

// Iteratively encodes a quiche::HttpHeaderBlock.
class HpackEncoder::Encoderator : public ProgressiveEncoder {
 public:
  Encoderator(const quiche::HttpHeaderBlock& header_set, HpackEncoder* encoder);
  Encoderator(const Representations& representations, HpackEncoder* encoder);

  // Encoderator is neither copyable nor movable.
  Encoderator(const Encoderator&) = delete;
  Encoderator& operator=(const Encoderator&) = delete;

  // Returns true iff more remains to encode.
  bool HasNext() const override { return has_next_; }

  // Encodes and returns up to max_encoded_bytes of the current header block.
  std::string Next(size_t max_encoded_bytes) override;

 private:
  HpackEncoder* encoder_;
  std::unique_ptr<RepresentationIterator> header_it_;
  Representations pseudo_headers_;
  Representations regular_headers_;
  bool has_next_;
};

HpackEncoder::Encoderator::Encoderator(
    const quiche::HttpHeaderBlock& header_set, HpackEncoder* encoder)
    : encoder_(encoder), has_next_(true) {
  // Separate header set into pseudo-headers and regular headers.
  bool found_cookie = false;
  for (const auto& header : header_set) {
    if (!found_cookie && header.first == "cookie") {
      // Note that there can only be one "cookie" header, because header_set
      // is a map.
      found_cookie = true;
      if (encoder_->crumble_cookies_) {
        CookieToCrumbs(header, &regular_headers_);
      } else {
        DecomposeRepresentation(header, &regular_headers_);
      }
    } else if (!header.first.empty() &&
               header.first[0] == kPseudoHeaderPrefix) {
      DecomposeRepresentation(header, &pseudo_headers_);
    } else {
      DecomposeRepresentation(header, &regular_headers_);
    }
  }
  header_it_ = std::make_unique<RepresentationIterator>(pseudo_headers_,
                                                        regular_headers_);

  encoder_->MaybeEmitTableSize();
}

HpackEncoder::Encoderator::Encoderator(const Representations& representations,
                                       HpackEncoder* encoder)
    : encoder_(encoder), has_next_(true) {
  for (const auto& header : representations) {
    if (header.first == "cookie") {
      if (encoder_->crumble_cookies_) {
        CookieToCrumbs(header, &regular_headers_);
      } else {
        DecomposeRepresentation(header, &regular_headers_);
      }
    } else if (!header.first.empty() &&
               header.first[0] == kPseudoHeaderPrefix) {
      pseudo_headers_.push_back(header);
    } else {
      regular_headers_.push_back(header);
    }
  }
  header_it_ = std::make_unique<RepresentationIterator>(pseudo_headers_,
                                                        regular_headers_);

  encoder_->MaybeEmitTableSize();
}

std::string HpackEncoder::Encoderator::Next(size_t max_encoded_bytes) {
  QUICHE_BUG_IF(spdy_bug_61_1, !has_next_)
      << "Encoderator::Next called with nothing left to encode.";
  const bool enable_compression = encoder_->enable_compression_;

  // Encode up to max_encoded_bytes of headers.
  while (header_it_->HasNext() &&
         encoder_->output_stream_.size() <= max_encoded_bytes) {
    const Representation header = header_it_->Next();
    encoder_->listener_(header.first, header.second);
    if (enable_compression) {
      size_t index = encoder_->header_table_.GetByNameAndValue(header.first,
                                                               header.second);
      if (index != kHpackEntryNotFound) {
        encoder_->EmitIndex(index);
      } else if (encoder_->should_index_(header.first, header.second)) {
        encoder_->EmitIndexedLiteral(header);
      } else {
        encoder_->EmitNonIndexedLiteral(header, enable_compression);
      }
    } else {
      encoder_->EmitNonIndexedLiteral(header, enable_compression);
    }
  }

  has_next_ = encoder_->output_stream_.size() > max_encoded_bytes;
  return encoder_->output_stream_.BoundedTakeString(max_encoded_bytes);
}

std::unique_ptr<HpackEncoder::ProgressiveEncoder> HpackEncoder::EncodeHeaderSet(
    const quiche::HttpHeaderBlock& header_set) {
  return std::make_unique<Encoderator>(header_set, this);
}

std::unique_ptr<HpackEncoder::ProgressiveEncoder>
HpackEncoder::EncodeRepresentations(const Representations& representations) {
  return std::make_unique<Encoderator>(representations, this);
}

}  // namespace spdy

"""

```