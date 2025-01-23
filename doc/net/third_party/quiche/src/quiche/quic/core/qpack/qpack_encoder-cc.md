Response:
Let's break down the thought process for analyzing the `qpack_encoder.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the `QpackEncoder` class, its relationship to JavaScript, example inputs/outputs for logical reasoning, common usage errors, and how a user action leads to this code.

2. **Initial Code Scan (Keywords and Structure):**  Quickly scan the code for important keywords and structural elements. This includes:
    * Class name: `QpackEncoder`
    * Includes:  Headers related to QUIC, QPACK, strings, and algorithms. This immediately signals that this is part of a QUIC implementation and deals with header compression.
    * Constructor/Destructor:  Indicates initialization and cleanup.
    * Key methods: `EncodeIndexedHeaderField`, `EncodeLiteralHeaderFieldWithNameReference`, `EncodeLiteralHeaderField`, `FirstPassEncode`, `SecondPassEncode`, `EncodeHeaderList`, `SetMaximumDynamicTableCapacity`, `SetDynamicTableCapacity`, `SetMaximumBlockedStreams`, `OnInsertCountIncrement`, `OnHeaderAcknowledgement`, `OnStreamCancellation`, `OnErrorDetected`. These method names give strong hints about the functionality.
    * Member variables: `huffman_encoding_`, `cookie_crumbling_`, `decoder_stream_error_delegate_`, `decoder_stream_receiver_`, `encoder_stream_sender_`, `maximum_blocked_streams_`, `header_list_count_`, `header_table_`, `blocking_manager_`. These reveal the core components and state managed by the encoder.
    * Namespaces: `quic` and anonymous namespaces.

3. **Focus on Core Functionality (The "Encode" Methods):** The most prominent methods are related to encoding. `EncodeHeaderList` seems like the main entry point. `FirstPassEncode` and `SecondPassEncode` suggest a two-stage process. The other `Encode...` methods appear to be helper functions for constructing different types of header field representations.

4. **Deciphering the Two-Pass Encoding:**
    * **`FirstPassEncode`:**  This method iterates through the `header_list`. It tries to find matches in the `header_table_` (both static and dynamic). Based on matches and available space/blocking constraints, it decides *how* to represent each header field (indexed, literal with name reference, or literal). Crucially, it interacts with the `encoder_stream_sender_` to send dynamic table updates (insertions, duplicates) and the `blocking_manager_` to track dependencies.
    * **`SecondPassEncode`:** This method takes the representations generated in the first pass and the `required_insert_count`. It formats the header block prefix and then encodes each header field representation into the final byte string. The key here is the transformation of absolute indices to request-stream-relative indices.

5. **Understanding Dynamic Table Interactions:** The code heavily interacts with `header_table_`. This suggests that the encoder maintains a dynamic table of recently used headers to improve compression. Methods like `SetMaximumDynamicTableCapacity` and `SetDynamicTableCapacity` directly control this table. The concept of a "draining index" is also important for understanding how entries are aged out.

6. **Analyzing Blocking Management:** The `blocking_manager_` and related methods (`OnInsertCountIncrement`, `OnHeaderAcknowledgement`, `OnStreamCancellation`) are crucial for handling dependencies between the encoder and decoder dynamic tables. The encoder needs to know if the decoder has received certain updates before it can safely refer to those entries.

7. **Identifying JavaScript Relevance (or Lack Thereof):**  Given that this is low-level network stack code within Chromium, the direct relationship with JavaScript is likely minimal. JavaScript interacts with HTTP through higher-level browser APIs. The connection would be that this code *enables* efficient HTTP/3 (which uses QPACK) communication that JavaScript applications ultimately benefit from. Think of it as the engine under the hood.

8. **Constructing Examples (Logical Reasoning):**  Choose simple scenarios to illustrate the two-pass encoding. Focus on the key decisions:
    * Indexed header: Show how a known header is represented concisely.
    * Literal with name reference: Show how a known header name combined with a new value is encoded.
    * Literal: Show how completely new headers are encoded.
    * Dynamic table insertion: Show how a new header can be added to the dynamic table.

9. **Identifying Common Usage Errors:**  Think about the responsibilities of the code and what could go wrong from an external perspective (even though it's internal Chromium code). Errors often relate to incorrect usage of the API, such as setting conflicting capacities or mismanaging acknowledgements.

10. **Tracing User Actions (Debugging):**  Think about the user's journey and how their actions translate into network requests. Focus on the point where headers are generated (browser making a request) and how those headers would be passed to the QPACK encoder for transmission.

11. **Review and Refine:** Read through the generated explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained more effectively. Ensure the examples are easy to understand and directly relate to the code's behavior. For instance, initially, I might not have emphasized the two-pass nature as clearly, so a review would prompt me to strengthen that explanation. Similarly, clarifying the indirect nature of the JavaScript relationship is important.
这个文件 `net/third_party/quiche/src/quiche/quic/core/qpack/qpack_encoder.cc` 实现了 Chromium QUIC 协议栈中 QPACK (QPACK: HTTP/3 Header Compression) 编码器的功能。  它负责将 HTTP 头部信息压缩成 QPACK 格式，以便在网络上传输。

以下是该文件的主要功能：

**核心功能：HTTP 头部压缩编码**

1. **将 HTTP 头部列表编码成 QPACK 表示形式:**  这是该文件的核心职责。它接收一个 `quiche::HttpHeaderBlock` (表示 HTTP 头部键值对的列表)，并将其转换为 QPACK 编码的字节流。

2. **静态表和动态表的使用:**  QPACK 使用静态表（预定义的常用头部）和动态表（最近使用的头部）来提高压缩效率。`QpackEncoder` 类内部维护着一个动态表 (`header_table_`)，并利用它来编码头部。

3. **索引头部字段:**  如果一个头部字段（名称和值）存在于静态表或动态表中，编码器会使用其索引进行编码，从而大大减小数据量。

4. **带名称引用的文字头部字段:** 如果头部名称存在于静态表或动态表中，但值不同，编码器可以引用已知的名称，并以字面值的形式发送新的值。

5. **文字头部字段:**  如果头部字段的名称和值都不在表中，编码器会将它们以字面值的形式发送。

6. **动态表更新:**  编码器可以向解码器发送指令，以更新其动态表。这包括插入新的头部字段或复制现有字段。这些指令通过 `encoder_stream_sender_` 发送到单独的编码器流。

7. **阻塞处理:** QPACK 引入了“阻塞”的概念。如果编码器引用了动态表中尚未被解码器确认接收的条目，则该头部块可能会被标记为阻塞。`QpackEncoder` 包含 `blocking_manager_` 来管理这些阻塞情况，并根据解码器的确认信息来决定如何编码。

8. **Required Insert Count (RIC):**  编码器会计算解码器需要接收的最少插入数（RIC），以便能够正确解码当前发送的头部块。这个信息会包含在编码后的头部块前缀中。

9. **两种编码Pass:**  编码过程通常分为两个 pass：
    * **First Pass (`FirstPassEncode`):**  决定如何表示每个头部字段（索引、带名称引用、字面值），并确定是否需要更新动态表。
    * **Second Pass (`SecondPassEncode`):** 将第一 pass 生成的表示形式转换为实际的 QPACK 编码字节流。

**辅助功能：**

1. **管理动态表容量:**  `SetMaximumDynamicTableCapacity` 和 `SetDynamicTableCapacity` 方法允许设置动态表的最大容量和当前容量。

2. **管理阻塞流的数量:** `SetMaximumBlockedStreams` 方法设置允许的最大阻塞流数量。

3. **处理解码器流的事件:**  `OnInsertCountIncrement`、`OnHeaderAcknowledgement`、`OnStreamCancellation` 方法处理来自解码器流的指令，例如动态表插入计数增加、头部确认和流取消。

4. **错误处理:** `OnErrorDetected` 方法用于处理 QPACK 编码过程中检测到的错误，并将错误通知给 `decoder_stream_error_delegate_`。

**与 JavaScript 的关系：**

`QpackEncoder` 本身是用 C++ 实现的，直接与 JavaScript 没有代码级别的交互。 然而，它在浏览器网络栈中扮演着关键角色，最终会影响到 JavaScript 发起的网络请求的性能。

* **间接影响:** 当 JavaScript 代码使用 Fetch API 或 XMLHttpRequest 发起 HTTP/3 请求时，Chromium 的网络栈会使用 `QpackEncoder` 来压缩请求和响应的头部。 压缩后的头部数据更小，传输更快，从而提高了网页加载速度和应用性能。 这对 JavaScript 编写的前端应用是有益的。

**举例说明：**

假设一个 JavaScript 应用发起一个 HTTP/3 GET 请求，请求头包含以下信息：

```
{
  "Content-Type": "application/json",
  "Accept-Language": "en-US,en;q=0.9",
  "Custom-Header": "some-value"
}
```

**假设输入：**  `quiche::HttpHeaderBlock` 对象，包含上述头部信息。

**逻辑推理和输出：**

1. **First Pass:**
   * "Content-Type": "application/json"  可能在静态表中，`FirstPassEncode` 会查找匹配项。 假设找到了，它会生成一个 "索引头部字段" 的表示形式，例如 `Representation::IndexedHeaderField(true, /* static table index */)`。
   * "Accept-Language": "en-US,en;q=0.9" 也可能在静态表中。
   * "Custom-Header": "some-value"  可能不在静态表或动态表中。`FirstPassEncode` 可能会生成一个 "文字头部字段" 的表示形式，例如 `Representation::LiteralHeaderField("Custom-Header", "some-value")`。如果动态表允许插入，并且编码器决定插入，它可能会发送一个动态表插入指令，并在后续的请求中使用索引。

2. **Second Pass:**
   * `SecondPassEncode` 会将第一 pass 生成的 `Representation` 对象编码成实际的字节流。索引头部字段会被编码为较小的整数，而文字头部字段会被编码为其原始字符串（可能经过 Huffman 编码）。
   * 输出将是一个包含 QPACK 编码头部信息的 `std::string`。

**用户或编程常见的使用错误：**

虽然开发者通常不会直接与 `QpackEncoder` 交互，但其配置不当或解码器实现存在问题可能会导致错误。

1. **动态表容量设置不当:**  如果编码器和解码器对动态表的最大容量有不同的理解，可能会导致编码和解码不一致。 Chromium 内部会进行协调以避免这种情况。

2. **假设解码器已接收到某些更新:** 编码器不能随意引用动态表中的条目，它必须考虑解码器是否已经收到了插入或复制这些条目的指令。 如果编码器错误地认为解码器已知某个条目，可能会导致解码失败。 `blocking_manager_` 的作用就是为了避免这种情况。

3. **尝试发送过大的头部:**  虽然 QPACK 本身没有严格的头部大小限制，但传输层（如 HTTP/3）或应用层可能会有。 这不是 `QpackEncoder` 本身的错误，但会影响到使用它的场景。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中输入网址并访问一个 HTTP/3 网站。**
2. **浏览器（Chromium）的网络栈开始建立与服务器的 QUIC 连接。**
3. **当浏览器需要发送 HTTP 请求时（例如，获取网页的 HTML），它会构建 HTTP 头部。**
4. **这些 HTTP 头部会被传递到 `QpackEncoder::EncodeHeaderList` 方法。**
5. **`EncodeHeaderList` 内部会调用 `FirstPassEncode` 和 `SecondPassEncode` 来将头部压缩成 QPACK 格式。**
6. **编码后的 QPACK 头部数据会作为 QUIC 数据包的一部分发送到服务器。**

**调试线索:** 如果在网络请求中发现头部压缩相关的问题，例如头部丢失或解析错误，开发人员可能会：

* **查看 QUIC 连接的日志，** 检查 QPACK 编码器发送的动态表更新指令和编码后的头部块。
* **使用网络抓包工具（如 Wireshark）** 查看 QUIC 数据包的内容，分析 QPACK 头部的结构。
* **在 Chromium 源码中设置断点，**  跟踪 `QpackEncoder` 的执行流程，查看其如何处理特定的头部字段。
* **检查 `blocking_manager_` 的状态，**  了解是否有头部块因为依赖未确认的动态表条目而被阻塞。

总而言之，`qpack_encoder.cc` 是 Chromium 网络栈中负责高效压缩 HTTP 头部信息的关键组件，它直接影响着基于 HTTP/3 的网络应用的性能。虽然 JavaScript 开发者不会直接调用这个 C++ 类，但其功能对他们构建的应用至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/qpack/qpack_encoder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/qpack/qpack_encoder.h"

#include <algorithm>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/qpack/qpack_index_conversions.h"
#include "quiche/quic/core/qpack/qpack_instruction_encoder.h"
#include "quiche/quic/core/qpack/qpack_required_insert_count.h"
#include "quiche/quic/core/qpack/value_splitting_header_list.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

namespace {

// Fraction to calculate draining index.  The oldest |kDrainingFraction| entries
// will not be referenced in header blocks.  A new entry (duplicate or literal
// with name reference) will be added to the dynamic table instead.  This allows
// the number of references to the draining entry to go to zero faster, so that
// it can be evicted.  See
// https://rfc-editor.org/rfc/rfc9204.html#section-2.1.1.1.
// TODO(bnc): Fine tune.
const float kDrainingFraction = 0.25;

}  // anonymous namespace

QpackEncoder::QpackEncoder(
    DecoderStreamErrorDelegate* decoder_stream_error_delegate,
    HuffmanEncoding huffman_encoding, CookieCrumbling cookie_crumbling)
    : huffman_encoding_(huffman_encoding),
      cookie_crumbling_(cookie_crumbling),
      decoder_stream_error_delegate_(decoder_stream_error_delegate),
      decoder_stream_receiver_(this),
      encoder_stream_sender_(huffman_encoding),
      maximum_blocked_streams_(0),
      header_list_count_(0) {
  QUICHE_DCHECK(decoder_stream_error_delegate_);
}

QpackEncoder::~QpackEncoder() {}

// static
QpackEncoder::Representation QpackEncoder::EncodeIndexedHeaderField(
    bool is_static, uint64_t index,
    QpackBlockingManagerShim::IndexSet* referred_indices) {
  // Add |index| to |*referred_indices| only if entry is in the dynamic table.
  if (!is_static) {
    referred_indices->insert(index);
  }
  return Representation::IndexedHeaderField(is_static, index);
}

// static
QpackEncoder::Representation
QpackEncoder::EncodeLiteralHeaderFieldWithNameReference(
    bool is_static, uint64_t index, absl::string_view value,
    QpackBlockingManagerShim::IndexSet* referred_indices) {
  // Add |index| to |*referred_indices| only if entry is in the dynamic table.
  if (!is_static) {
    referred_indices->insert(index);
  }
  return Representation::LiteralHeaderFieldNameReference(is_static, index,
                                                         value);
}

// static
QpackEncoder::Representation QpackEncoder::EncodeLiteralHeaderField(
    absl::string_view name, absl::string_view value) {
  return Representation::LiteralHeaderField(name, value);
}

QpackEncoder::Representations QpackEncoder::FirstPassEncode(
    QuicStreamId stream_id, const quiche::HttpHeaderBlock& header_list,
    QpackBlockingManagerShim::IndexSet* referred_indices,
    QuicByteCount* encoder_stream_sent_byte_count) {
  // If previous instructions are buffered in |encoder_stream_sender_|,
  // do not count them towards the current header block.
  const QuicByteCount initial_encoder_stream_buffered_byte_count =
      encoder_stream_sender_.BufferedByteCount();

  const bool can_write_to_encoder_stream = encoder_stream_sender_.CanWrite();

  Representations representations;
  representations.reserve(header_list.size());

  // Entries with index larger than or equal to |known_received_count| are
  // blocking.
  const uint64_t known_received_count =
      blocking_manager_.known_received_count();

  // The index of the oldest entry that must not be evicted. Blocking entries
  // must not be evicted. Also, unacknowledged entries must not be evicted,
  // even if they have no outstanding references (see https://crbug.com/1441880
  // for more context).
  uint64_t smallest_non_evictable_index = std::min(
      blocking_manager_.smallest_blocking_index(), known_received_count);

  // Only entries with index greater than or equal to |draining_index| are
  // allowed to be referenced.
  const uint64_t draining_index =
      header_table_.draining_index(kDrainingFraction);
  // Blocking references are allowed if the number of blocked streams is less
  // than the limit.
  const bool blocking_allowed = blocking_manager_.blocking_allowed_on_stream(
      stream_id, maximum_blocked_streams_);

  // Track events for histograms.
  bool dynamic_table_insertion_blocked = false;
  bool blocked_stream_limit_exhausted = false;

  for (const auto& header :
       ValueSplittingHeaderList(&header_list, cookie_crumbling_)) {
    // These strings are owned by |header_list|.
    absl::string_view name = header.first;
    absl::string_view value = header.second;

    QpackEncoderHeaderTable::MatchResult match_result =
        header_table_.FindHeaderField(name, value);

    switch (match_result.match_type) {
      case QpackEncoderHeaderTable::MatchType::kNameAndValue: {
        if (match_result.is_static) {
          // Refer to entry directly.
          representations.push_back(EncodeIndexedHeaderField(
              match_result.is_static, match_result.index, referred_indices));

          break;
        }

        if (match_result.index >= draining_index) {
          if (!blocking_allowed && match_result.index >= known_received_count) {
            blocked_stream_limit_exhausted = true;
          } else {
            // Refer to entry directly.
            representations.push_back(EncodeIndexedHeaderField(
                match_result.is_static, match_result.index, referred_indices));
            smallest_non_evictable_index =
                std::min(smallest_non_evictable_index, match_result.index);
            header_table_.set_dynamic_table_entry_referenced();

            break;
          }
        } else {
          // No new references should be added for entry to allow it to drain.
          // Duplicate entry instead if possible.
          if (!blocking_allowed) {
            blocked_stream_limit_exhausted = true;
          } else if (QpackEntry::Size(name, value) >
                     header_table_.MaxInsertSizeWithoutEvictingGivenEntry(
                         std::min(smallest_non_evictable_index,
                                  match_result.index))) {
            dynamic_table_insertion_blocked = true;
          } else {
            if (can_write_to_encoder_stream) {
              encoder_stream_sender_.SendDuplicate(
                  QpackAbsoluteIndexToEncoderStreamRelativeIndex(
                      match_result.index,
                      header_table_.inserted_entry_count()));
              uint64_t new_index = header_table_.InsertEntry(name, value);
              representations.push_back(EncodeIndexedHeaderField(
                  match_result.is_static, new_index, referred_indices));
              smallest_non_evictable_index =
                  std::min(smallest_non_evictable_index, match_result.index);
              header_table_.set_dynamic_table_entry_referenced();

              break;
            }
          }
        }

        // Match cannot be used.

        QpackEncoderHeaderTable::MatchResult match_result_name_only =
            header_table_.FindHeaderName(name);

        // If no name match found, or if the matching entry is the same as the
        // previous one (which could not be used), then encode header line as
        // string literals.
        if (match_result_name_only.match_type !=
                QpackEncoderHeaderTable::MatchType::kName ||
            (match_result_name_only.is_static == match_result.is_static &&
             match_result_name_only.index == match_result.index)) {
          representations.push_back(EncodeLiteralHeaderField(name, value));
          break;
        }

        match_result = match_result_name_only;

        ABSL_FALLTHROUGH_INTENDED;
      }

      case QpackEncoderHeaderTable::MatchType::kName: {
        if (match_result.is_static) {
          if (blocking_allowed &&
              QpackEntry::Size(name, value) <=
                  header_table_.MaxInsertSizeWithoutEvictingGivenEntry(
                      smallest_non_evictable_index)) {
            // If allowed, insert entry into dynamic table and refer to it.
            if (can_write_to_encoder_stream) {
              encoder_stream_sender_.SendInsertWithNameReference(
                  match_result.is_static, match_result.index, value);
              uint64_t new_index = header_table_.InsertEntry(name, value);
              representations.push_back(EncodeIndexedHeaderField(
                  /* is_static = */ false, new_index, referred_indices));
              smallest_non_evictable_index =
                  std::min<uint64_t>(smallest_non_evictable_index, new_index);

              break;
            }
          }

          // Emit literal field with name reference.
          representations.push_back(EncodeLiteralHeaderFieldWithNameReference(
              match_result.is_static, match_result.index, value,
              referred_indices));

          break;
        }

        if (!blocking_allowed) {
          blocked_stream_limit_exhausted = true;
        } else if (QpackEntry::Size(name, value) >
                   header_table_.MaxInsertSizeWithoutEvictingGivenEntry(
                       std::min(smallest_non_evictable_index,
                                match_result.index))) {
          dynamic_table_insertion_blocked = true;
        } else {
          // If allowed, insert entry with name reference and refer to it.
          if (can_write_to_encoder_stream) {
            encoder_stream_sender_.SendInsertWithNameReference(
                match_result.is_static,
                QpackAbsoluteIndexToEncoderStreamRelativeIndex(
                    match_result.index, header_table_.inserted_entry_count()),
                value);
            uint64_t new_index = header_table_.InsertEntry(name, value);
            representations.push_back(EncodeIndexedHeaderField(
                match_result.is_static, new_index, referred_indices));
            smallest_non_evictable_index =
                std::min(smallest_non_evictable_index, match_result.index);
            header_table_.set_dynamic_table_entry_referenced();

            break;
          }
        }

        if ((blocking_allowed || match_result.index < known_received_count) &&
            match_result.index >= draining_index) {
          // If allowed, refer to entry name directly, with literal value.
          representations.push_back(EncodeLiteralHeaderFieldWithNameReference(
              match_result.is_static, match_result.index, value,
              referred_indices));
          smallest_non_evictable_index =
              std::min(smallest_non_evictable_index, match_result.index);
          header_table_.set_dynamic_table_entry_referenced();

          break;
        }

        representations.push_back(EncodeLiteralHeaderField(name, value));

        break;
      }

      case QpackEncoderHeaderTable::MatchType::kNoMatch: {
        // If allowed, insert entry and refer to it.
        if (!blocking_allowed) {
          blocked_stream_limit_exhausted = true;
        } else if (QpackEntry::Size(name, value) >
                   header_table_.MaxInsertSizeWithoutEvictingGivenEntry(
                       smallest_non_evictable_index)) {
          dynamic_table_insertion_blocked = true;
        } else {
          if (can_write_to_encoder_stream) {
            encoder_stream_sender_.SendInsertWithoutNameReference(name, value);
            uint64_t new_index = header_table_.InsertEntry(name, value);
            representations.push_back(EncodeIndexedHeaderField(
                /* is_static = */ false, new_index, referred_indices));
            smallest_non_evictable_index =
                std::min<uint64_t>(smallest_non_evictable_index, new_index);

            break;
          }
        }

        // Encode entry as string literals.
        // TODO(b/112770235): Consider also adding to dynamic table to improve
        // compression ratio for subsequent header blocks with peers that do not
        // allow any blocked streams.
        representations.push_back(EncodeLiteralHeaderField(name, value));

        break;
      }
    }
  }

  const QuicByteCount encoder_stream_buffered_byte_count =
      encoder_stream_sender_.BufferedByteCount();
  QUICHE_DCHECK_GE(encoder_stream_buffered_byte_count,
                   initial_encoder_stream_buffered_byte_count);

  if (encoder_stream_sent_byte_count) {
    *encoder_stream_sent_byte_count =
        encoder_stream_buffered_byte_count -
        initial_encoder_stream_buffered_byte_count;
  }
  if (can_write_to_encoder_stream) {
    encoder_stream_sender_.Flush();
  } else {
    QUICHE_DCHECK_EQ(encoder_stream_buffered_byte_count,
                     initial_encoder_stream_buffered_byte_count);
  }

  ++header_list_count_;

  if (dynamic_table_insertion_blocked) {
    QUIC_HISTOGRAM_COUNTS(
        "QuicSession.Qpack.HeaderListCountWhenInsertionBlocked",
        header_list_count_, /* min = */ 1, /* max = */ 1000,
        /* bucket_count = */ 50,
        "The ordinality of a header list within a connection during the "
        "encoding of which at least one dynamic table insertion was "
        "blocked.");
  } else {
    QUIC_HISTOGRAM_COUNTS(
        "QuicSession.Qpack.HeaderListCountWhenInsertionNotBlocked",
        header_list_count_, /* min = */ 1, /* max = */ 1000,
        /* bucket_count = */ 50,
        "The ordinality of a header list within a connection during the "
        "encoding of which no dynamic table insertion was blocked.");
  }

  if (blocked_stream_limit_exhausted) {
    QUIC_HISTOGRAM_COUNTS(
        "QuicSession.Qpack.HeaderListCountWhenBlockedStreamLimited",
        header_list_count_, /* min = */ 1, /* max = */ 1000,
        /* bucket_count = */ 50,
        "The ordinality of a header list within a connection during the "
        "encoding of which unacknowledged dynamic table entries could not be "
        "referenced due to the limit on the number of blocked streams.");
  } else {
    QUIC_HISTOGRAM_COUNTS(
        "QuicSession.Qpack.HeaderListCountWhenNotBlockedStreamLimited",
        header_list_count_, /* min = */ 1, /* max = */ 1000,
        /* bucket_count = */ 50,
        "The ordinality of a header list within a connection during the "
        "encoding of which the limit on the number of blocked streams did "
        "not "
        "prevent referencing unacknowledged dynamic table entries.");
  }

  return representations;
}

std::string QpackEncoder::SecondPassEncode(
    QpackEncoder::Representations representations,
    uint64_t required_insert_count) const {
  QpackInstructionEncoder instruction_encoder(huffman_encoding_);
  std::string encoded_headers;

  // Header block prefix.
  instruction_encoder.Encode(
      Representation::Prefix(QpackEncodeRequiredInsertCount(
          required_insert_count, header_table_.max_entries())),
      &encoded_headers);

  const uint64_t base = required_insert_count;

  for (auto& representation : representations) {
    // Dynamic table references must be transformed from absolute to relative
    // indices.
    if ((representation.instruction() == QpackIndexedHeaderFieldInstruction() ||
         representation.instruction() ==
             QpackLiteralHeaderFieldNameReferenceInstruction()) &&
        !representation.s_bit()) {
      representation.set_varint(QpackAbsoluteIndexToRequestStreamRelativeIndex(
          representation.varint(), base));
    }
    instruction_encoder.Encode(representation, &encoded_headers);
  }

  return encoded_headers;
}

std::string QpackEncoder::EncodeHeaderList(
    QuicStreamId stream_id, const quiche::HttpHeaderBlock& header_list,
    QuicByteCount* encoder_stream_sent_byte_count) {
  // Keep track of all dynamic table indices that this header block refers to so
  // that it can be passed to QpackBlockingManager.
  QpackBlockingManagerShim::IndexSet referred_indices;

  // First pass: encode into |representations|.
  Representations representations =
      FirstPassEncode(stream_id, header_list, &referred_indices,
                      encoder_stream_sent_byte_count);

  const uint64_t required_insert_count =
      referred_indices.empty()
          ? 0
          : QpackBlockingManagerShim::RequiredInsertCount(referred_indices);
  if (!referred_indices.empty()) {
    blocking_manager_.OnHeaderBlockSent(stream_id, std::move(referred_indices),
                                        required_insert_count);
  }

  // Second pass.
  return SecondPassEncode(std::move(representations), required_insert_count);
}

bool QpackEncoder::SetMaximumDynamicTableCapacity(
    uint64_t maximum_dynamic_table_capacity) {
  return header_table_.SetMaximumDynamicTableCapacity(
      maximum_dynamic_table_capacity);
}

void QpackEncoder::SetDynamicTableCapacity(uint64_t dynamic_table_capacity) {
  encoder_stream_sender_.SendSetDynamicTableCapacity(dynamic_table_capacity);
  // Do not flush encoder stream.  This write can safely be delayed until more
  // instructions are written.

  bool success = header_table_.SetDynamicTableCapacity(dynamic_table_capacity);
  QUICHE_DCHECK(success);
}

bool QpackEncoder::SetMaximumBlockedStreams(uint64_t maximum_blocked_streams) {
  if (maximum_blocked_streams < maximum_blocked_streams_) {
    return false;
  }
  maximum_blocked_streams_ = maximum_blocked_streams;
  return true;
}

void QpackEncoder::OnInsertCountIncrement(uint64_t increment) {
  if (increment == 0) {
    OnErrorDetected(QUIC_QPACK_DECODER_STREAM_INVALID_ZERO_INCREMENT,
                    "Invalid increment value 0.");
    return;
  }

  if (!blocking_manager_.OnInsertCountIncrement(increment)) {
    OnErrorDetected(QUIC_QPACK_DECODER_STREAM_INCREMENT_OVERFLOW,
                    "Insert Count Increment instruction causes overflow.");
  }

  if (blocking_manager_.known_received_count() >
      header_table_.inserted_entry_count()) {
    OnErrorDetected(QUIC_QPACK_DECODER_STREAM_IMPOSSIBLE_INSERT_COUNT,
                    absl::StrCat("Increment value ", increment,
                                 " raises known received count to ",
                                 blocking_manager_.known_received_count(),
                                 " exceeding inserted entry count ",
                                 header_table_.inserted_entry_count()));
  }
}

void QpackEncoder::OnHeaderAcknowledgement(QuicStreamId stream_id) {
  if (!blocking_manager_.OnHeaderAcknowledgement(stream_id)) {
    OnErrorDetected(
        QUIC_QPACK_DECODER_STREAM_INCORRECT_ACKNOWLEDGEMENT,
        absl::StrCat("Header Acknowledgement received for stream ", stream_id,
                     " with no outstanding header blocks."));
  }
}

void QpackEncoder::OnStreamCancellation(QuicStreamId stream_id) {
  blocking_manager_.OnStreamCancellation(stream_id);
}

void QpackEncoder::OnErrorDetected(QuicErrorCode error_code,
                                   absl::string_view error_message) {
  decoder_stream_error_delegate_->OnDecoderStreamError(error_code,
                                                       error_message);
}

}  // namespace quic
```