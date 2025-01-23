Response:
Let's break down the thought process for analyzing the C++ code and fulfilling the request.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of `QpackProgressiveDecoder.cc` within the Chromium network stack. This involves:

* **Describing its purpose:** What does this class *do*?
* **Identifying JavaScript relevance:** Does it interact with JavaScript, and how?
* **Illustrating logic with examples:**  Show how it works with hypothetical inputs and outputs.
* **Pointing out potential user errors:** What mistakes can developers make when using or interacting with this code (even indirectly)?
* **Tracing user actions to reach this code:** How does a user's interaction on the web eventually lead to the execution of this code?

**2. Initial Code Scan and Keyword Recognition:**

I'd start by quickly skimming the code for keywords and structural elements:

* **Class Name:** `QpackProgressiveDecoder`. "Decoder" strongly suggests it's responsible for converting encoded data back into its original form. "Progressive" implies it handles data in chunks. "Qpack" is a known protocol, likely related to HTTP/3 headers.
* **Includes:**  Headers like `<string>`, `<utility>`, `absl/strings/string_view`, and especially those containing "quiche/quic/core/qpack" are clues. They indicate dependencies on QUIC and QPACK specific components.
* **Member Variables:**  Variables like `stream_id_`, `prefix_decoder_`, `instruction_decoder_`, `header_table_`, `handler_`, `required_insert_count_`, `base_`, `blocked_`, `buffer_` provide hints about its internal state and operations. "Blocked" is a key concept in flow control.
* **Methods:**  `Decode()`, `EndHeaderBlock()`, `OnInstructionDecoded()`, `OnHeaderDecoded()`, `OnError()`, `Cancel()` are critical for understanding the class's interface and lifecycle. "Decode" is the central function.
* **Namespaces:**  `quic` confirms its place within the QUIC implementation.
* **Comments:**  The initial copyright and license are standard, but any specific comments within the code are valuable.

**3. Deeper Dive into Functionality:**

Now I would examine the methods in more detail:

* **Constructor:**  Initializes member variables, setting up the decoding process. Note the `prefix_decoder_` and `instruction_decoder_`, suggesting a two-stage decoding process.
* **`Decode(absl::string_view data)`:** This is the core decoding loop. It first handles a prefix and then, if not blocked, decodes instructions. The buffering logic when blocked is important.
* **`EndHeaderBlock()`:** Signals the end of the header block.
* **`OnInstructionDecoded(const QpackInstruction* instruction)`:** This is a crucial dispatcher, handling different types of QPACK instructions. The `if` statements checking the instruction type are key to understanding the different decoding paths.
* **`OnHeaderDecoded(...)`:**  Passes the decoded header name and value to a `handler_`. This is likely where the decoded information is made available to higher layers.
* **`OnError(...)`:** Handles decoding errors.
* **`Do...Instruction()` methods:** These methods implement the logic for specific QPACK instructions (e.g., indexed header field, literal header field). They interact with the `header_table_`.
* **`DoPrefixInstruction()`:** Decodes the initial prefix, including the `required_insert_count_` and `base_`. The blocking mechanism is initiated here.

**4. Connecting to JavaScript:**

This requires understanding the overall architecture of a web browser:

* **Network Stack:**  The C++ code resides in the browser's network stack, responsible for handling network protocols like HTTP/3 (which uses QPACK).
* **Renderer Process:**  JavaScript runs in the renderer process.
* **Inter-Process Communication (IPC):**  The network stack and the renderer process communicate via IPC.

The connection isn't direct. The `QpackProgressiveDecoder` decodes HTTP headers. These headers contain information used by the browser and eventually exposed to JavaScript. Key headers relevant to JavaScript include:

* **`content-type`:**  Determines how the browser interprets the response body (e.g., `text/html`, `application/javascript`).
* **`content-encoding`:**  Indicates if the response is compressed (e.g., `gzip`, `br`).
* **Cookies (using `set-cookie` and `cookie` headers):** Directly accessible and manipulated by JavaScript.
* **Cache-related headers:**  Control browser caching behavior.

**5. Crafting Examples and Scenarios:**

* **Input/Output:** Create simple scenarios demonstrating the decoding of basic indexed and literal headers.
* **User Errors:** Think about common mistakes related to web development, like incorrect header formats or relying on specific header behavior.
* **Debugging:**  Trace a typical user action (e.g., clicking a link) through the network request process to show how the decoder is involved.

**6. Structuring the Response:**

Organize the information logically using the headings provided in the prompt:

* **功能 (Functionality):** Provide a concise summary of the class's purpose and key responsibilities.
* **与 JavaScript 的关系 (Relationship with JavaScript):** Explain the indirect connection via HTTP headers and provide concrete examples of relevant headers.
* **逻辑推理 (Logical Reasoning):** Present the input/output examples, clearly outlining the assumptions and the decoding steps.
* **用户或编程常见的使用错误 (Common User or Programming Errors):**  Focus on mistakes that can lead to decoding issues or unexpected behavior.
* **用户操作如何一步步的到达这里 (How User Operations Lead Here):**  Provide a step-by-step walkthrough of a typical user interaction and the path of the network request.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on the low-level bit manipulation. *Correction:*  Shift the focus to the overall purpose and how it fits into the bigger picture.
* **Vague JavaScript connection:**  Simply stating "it's used for HTTP headers." *Correction:* Provide specific examples of headers relevant to JavaScript and their impact.
* **Too technical examples:**  Using complex QPACK encoding details. *Correction:* Simplify the examples to illustrate the core concepts.
* **Overlooking user errors:**  Focusing only on internal decoding errors. *Correction:* Consider developer errors related to header usage.

By following these steps, combining code analysis with an understanding of web browser architecture, and refining the explanation through examples and scenarios, we can generate a comprehensive and informative answer to the request.好的，让我们来分析一下 `net/third_party/quiche/src/quiche/quic/core/qpack/qpack_progressive_decoder.cc` 文件的功能。

**功能 (Functionality):**

`QpackProgressiveDecoder` 类是 Chromium 网络栈中 QUIC 协议的 QPACK (QPACK: Header Compression for HTTP/3) 实现的一部分。它的主要功能是**逐步解码 HTTP/3 的头部数据块 (header block)**。

更具体地说，它执行以下任务：

1. **处理 QPACK 指令 (Instructions):**  QPACK 使用一系列指令来表示头部字段。`QpackProgressiveDecoder` 负责解析这些指令，这些指令可能指示：
    *  索引头部字段（引用静态表或动态表中的条目）。
    *  使用字面量表示头部字段（直接提供名称和值）。
    *  指示动态表的更新（尽管此解码器本身不执行更新，但它需要理解更新计数）。

2. **管理解码状态:**  该类维护解码的进度状态，包括：
    * **`required_insert_count_`:**  解码所需的动态表插入计数。这用于处理依赖于动态表条目的头部字段。
    * **`base_`:**  用于计算相对索引的基准值。
    * **`blocked_`:**  指示解码器是否因等待动态表更新而被阻塞。
    * **`buffer_`:**  在解码器被阻塞时缓冲接收到的数据。

3. **处理头部块前缀 (Header Block Prefix):**  每个头部块都以一个前缀开始，其中包含解码所需的动态表插入计数和基准值。

4. **与头部表交互 (Interaction with Header Table):**  解码器与 `QpackDecoderHeaderTable` 类交互，以查找索引的头部字段。

5. **通知解码结果 (Notifying Decoding Results):**  一旦头部字段被成功解码，解码器会通过 `HeadersHandlerInterface` 将解码后的头部字段（名称和值）传递给上层。当整个头部块解码完成时，它会通知 `DecodingCompletedVisitor`。

6. **处理错误 (Error Handling):**  如果解码过程中发生错误（例如，无效的指令、索引超出范围），解码器会报告错误并通过 `HeadersHandlerInterface` 通知上层。

7. **处理阻塞 (Handling Blocking):**  如果解码的头部字段依赖于尚未插入到动态表中的条目，解码器会进入阻塞状态，直到所需的条目被插入。它使用 `BlockedStreamLimitEnforcer` 来限制被阻塞的流的数量。

**与 JavaScript 的关系 (Relationship with JavaScript):**

`QpackProgressiveDecoder` 本身是用 C++ 编写的，并不直接包含 JavaScript 代码。然而，它在 Web 浏览器中扮演着关键角色，最终影响着 JavaScript 可以访问的信息。

当用户在浏览器中发起 HTTP/3 请求时，服务器返回的 HTTP 头部信息会被编码成 QPACK 格式。`QpackProgressiveDecoder` 的任务就是将这些编码的头部信息解码成 JavaScript 可以理解的键值对。

**举例说明:**

假设一个网站的服务器发送了以下编码的 QPACK 头部块：

```
// 假设这是一个简化的 QPACK 编码
Prefix:  ... (指示 required_insert_count 和 base)
Instruction:  Indexed Header Field (静态表索引，例如 "content-type")
Instruction:  Literal Header Field With Name Reference (动态表索引，例如 "custom-header", "custom-value")
```

1. `QpackProgressiveDecoder` 首先解码前缀，获取 `required_insert_count` 和 `base`。
2. 然后，它解析第一个指令 "Indexed Header Field"。假设该指令引用了静态表中 `content-type: text/html` 这个条目。解码器会调用 `handler_->OnHeaderDecoded("content-type", "text/html")`。
3. 接着，它解析第二个指令 "Literal Header Field With Name Reference"。假设该指令引用了动态表中的一个条目，其名称为 "custom-header"，并且指令中包含了值 "custom-value"。解码器会调用 `handler_->OnHeaderDecoded("custom-header", "custom-value")`。

最终，JavaScript 代码可以通过浏览器的 API (例如，`fetch` API 的响应对象的 `headers` 属性) 访问到解码后的头部信息：

```javascript
fetch('https://example.com')
  .then(response => {
    console.log(response.headers.get('content-type')); // 输出: "text/html"
    console.log(response.headers.get('custom-header')); // 输出: "custom-value"
  });
```

**逻辑推理 (Logical Reasoning):**

**假设输入:**

* **编码的头部块数据:**  `\x00\x82\x41\x88Example-Value` (这是一个非常简化的假设，实际的 QPACK 编码会更复杂)
    * `\x00`:  Required Insert Count = 0
    * `\x82`:  Indexed Header Field, 静态表索引 2 (假设 "content-type: application/json")
    * `\x41`:  Literal Header Field With Name Reference, 静态表索引 1 (假设 "cache-control")
    * `\x88Example-Value`: 字面量值 "Example-Value"

* **初始状态:**  动态表为空。

**输出:**

1. **解码后的头部字段:**
   * `content-type: application/json`
   * `cache-control: Example-Value`

**推理步骤:**

1. **解码前缀:**  `\x00` 被解码，`required_insert_count_` 为 0，`base_` 被计算出来（此处假设为 0）。
2. **解码第一个指令:** `\x82` 表示索引头部字段，引用静态表索引 2。解码器查找静态表，找到 "content-type: application/json"，并调用 `OnHeaderDecoded("content-type", "application/json")`。
3. **解码第二个指令:** `\x41` 表示带有名称引用的字面量头部字段，引用静态表索引 1 ("cache-control")，并带有字面量值 "Example-Value"。解码器调用 `OnHeaderDecoded("cache-control", "Example-Value")`。

**用户或编程常见的使用错误 (Common User or Programming Errors):**

虽然用户或程序员通常不会直接与 `QpackProgressiveDecoder` 交互，但与 HTTP 头部相关的错误可能会导致解码问题，从而影响应用程序的行为。以下是一些例子：

1. **服务器发送的 QPACK 编码数据无效:**  如果服务器的 QPACK 编码器存在 bug，发送了格式错误的指令或前缀，`QpackProgressiveDecoder` 会检测到错误并报告 `QUIC_QPACK_DECOMPRESSION_FAILED`。这可能导致浏览器无法正确加载网页或资源。

2. **依赖于动态表中不存在的条目:** 如果服务器发送的头部字段索引引用了尚未插入到动态表中的条目（`absolute_index >= required_insert_count_`），解码器会报错。这通常是由于客户端和服务器之间的动态表同步问题导致的。

3. **头部字段名称或值过大:** 虽然 `QpackProgressiveDecoder` 本身可能不会直接限制头部字段的大小，但上层可能会有这样的限制。如果解码后的头部字段过大，可能会导致内存问题或处理错误。

4. **客户端和服务端对静态表的理解不一致:**  尽管不太可能，但如果客户端和服务端使用的静态表版本不同，可能会导致索引错误的头部字段。

**用户操作是如何一步步的到达这里，作为调试线索 (How User Operations Lead Here as Debugging Clues):**

假设用户在浏览器中访问 `https://example.com/page.html`。以下是可能触发 `QpackProgressiveDecoder` 的步骤：

1. **用户在浏览器地址栏输入 URL 并按下回车，或点击一个链接。**
2. **浏览器解析 URL 并确定需要建立与 `example.com` 的连接。**
3. **如果浏览器和服务器支持 HTTP/3，它们会尝试建立 QUIC 连接。**  QUIC 连接的建立涉及到握手过程。
4. **连接建立后，浏览器会发送一个 HTTP/3 请求到服务器，请求 `/page.html`。**  这个请求的头部信息会被编码并发送。
5. **服务器接收到请求，处理后生成 HTTP/3 响应，包括响应头部信息。**  这些头部信息会被 QPACK 编码。
6. **服务器通过 QUIC 连接将编码后的响应头部块发送回浏览器。**
7. **浏览器接收到这些编码后的头部块数据。**
8. **`QpackProgressiveDecoder` 类被实例化，用于解码接收到的头部块数据。**  `Decode()` 方法会被调用，传入接收到的数据。
9. **`QpackProgressiveDecoder` 逐步解析 QPACK 指令，并与 `QpackDecoderHeaderTable` 交互。**
10. **解码后的头部字段通过 `HeadersHandlerInterface` 传递给上层处理模块。**
11. **最终，解码后的头部信息被用于渲染网页，或者通过 JavaScript API 暴露给网页脚本。**

**调试线索:**

当调试网络问题时，如果怀疑 QPACK 解码出现问题，可以关注以下方面：

* **网络抓包:** 使用 Wireshark 或 Chrome 的网络面板抓取网络数据包，查看 QUIC 连接中的 QPACK 编码数据。
* **QUIC 事件日志:** Chromium 通常会记录 QUIC 相关的事件，包括 QPACK 解码的错误信息。查看这些日志可以帮助定位问题。
* **条件断点:** 在 `QpackProgressiveDecoder` 的关键方法（如 `Decode()`, `OnInstructionDecoded()`, `OnError()`）设置断点，检查解码过程中的状态和数据。
* **检查动态表状态:**  如果怀疑是动态表同步问题，可以查看客户端和服务器的动态表状态。
* **对比客户端和服务端 QPACK 实现:** 确保客户端和服务端使用的 QPACK 实现版本兼容。

总而言之，`QpackProgressiveDecoder` 是 QUIC 协议中处理 HTTP/3 头部压缩的关键组件，它负责将服务器发送的编码后的头部信息解码成浏览器可以理解的格式，最终影响着网页的加载和 JavaScript 可以访问的 HTTP 头部信息。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/qpack/qpack_progressive_decoder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/qpack/qpack_progressive_decoder.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/qpack/qpack_index_conversions.h"
#include "quiche/quic/core/qpack/qpack_instructions.h"
#include "quiche/quic/core/qpack/qpack_required_insert_count.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

namespace {

// The value argument passed to OnHeaderDecoded() is from an entry in the static
// table.
constexpr bool kValueFromStaticTable = true;

}  // anonymous namespace

QpackProgressiveDecoder::QpackProgressiveDecoder(
    QuicStreamId stream_id, BlockedStreamLimitEnforcer* enforcer,
    DecodingCompletedVisitor* visitor, QpackDecoderHeaderTable* header_table,
    HeadersHandlerInterface* handler)
    : stream_id_(stream_id),
      prefix_decoder_(std::make_unique<QpackInstructionDecoder>(
          QpackPrefixLanguage(), this)),
      instruction_decoder_(QpackRequestStreamLanguage(), this),
      enforcer_(enforcer),
      visitor_(visitor),
      header_table_(header_table),
      handler_(handler),
      required_insert_count_(0),
      base_(0),
      required_insert_count_so_far_(0),
      prefix_decoded_(false),
      blocked_(false),
      decoding_(true),
      error_detected_(false),
      cancelled_(false) {}

QpackProgressiveDecoder::~QpackProgressiveDecoder() {
  if (blocked_ && !cancelled_) {
    header_table_->UnregisterObserver(required_insert_count_, this);
  }
}

void QpackProgressiveDecoder::Decode(absl::string_view data) {
  QUICHE_DCHECK(decoding_);

  if (data.empty() || error_detected_) {
    return;
  }

  // Decode prefix byte by byte until the first (and only) instruction is
  // decoded.
  while (!prefix_decoded_) {
    QUICHE_DCHECK(!blocked_);

    if (!prefix_decoder_->Decode(data.substr(0, 1))) {
      return;
    }

    // |prefix_decoder_->Decode()| must return false if an error is detected.
    QUICHE_DCHECK(!error_detected_);

    data = data.substr(1);
    if (data.empty()) {
      return;
    }
  }

  if (blocked_) {
    buffer_.append(data.data(), data.size());
  } else {
    QUICHE_DCHECK(buffer_.empty());

    instruction_decoder_.Decode(data);
  }
}

void QpackProgressiveDecoder::EndHeaderBlock() {
  QUICHE_DCHECK(decoding_);
  decoding_ = false;

  if (!blocked_) {
    FinishDecoding();
  }
}

bool QpackProgressiveDecoder::OnInstructionDecoded(
    const QpackInstruction* instruction) {
  if (instruction == QpackPrefixInstruction()) {
    return DoPrefixInstruction();
  }

  QUICHE_DCHECK(prefix_decoded_);
  QUICHE_DCHECK_LE(required_insert_count_,
                   header_table_->inserted_entry_count());

  if (instruction == QpackIndexedHeaderFieldInstruction()) {
    return DoIndexedHeaderFieldInstruction();
  }
  if (instruction == QpackIndexedHeaderFieldPostBaseInstruction()) {
    return DoIndexedHeaderFieldPostBaseInstruction();
  }
  if (instruction == QpackLiteralHeaderFieldNameReferenceInstruction()) {
    return DoLiteralHeaderFieldNameReferenceInstruction();
  }
  if (instruction == QpackLiteralHeaderFieldPostBaseInstruction()) {
    return DoLiteralHeaderFieldPostBaseInstruction();
  }
  QUICHE_DCHECK_EQ(instruction, QpackLiteralHeaderFieldInstruction());
  return DoLiteralHeaderFieldInstruction();
}

void QpackProgressiveDecoder::OnInstructionDecodingError(
    QpackInstructionDecoder::ErrorCode /* error_code */,
    absl::string_view error_message) {
  // Ignore |error_code| and always use QUIC_QPACK_DECOMPRESSION_FAILED to avoid
  // having to define a new QuicErrorCode for every instruction decoder error.
  OnError(QUIC_QPACK_DECOMPRESSION_FAILED, error_message);
}

void QpackProgressiveDecoder::OnInsertCountReachedThreshold() {
  QUICHE_DCHECK(blocked_);

  // Clear |blocked_| before calling instruction_decoder_.Decode() below,
  // because that might destroy |this| and ~QpackProgressiveDecoder() needs to
  // know not to call UnregisterObserver().
  blocked_ = false;
  enforcer_->OnStreamUnblocked(stream_id_);

  if (!buffer_.empty()) {
    std::string buffer(std::move(buffer_));
    buffer_.clear();
    if (!instruction_decoder_.Decode(buffer)) {
      // |this| might be destroyed.
      return;
    }
  }

  if (!decoding_) {
    FinishDecoding();
  }
}

void QpackProgressiveDecoder::Cancel() { cancelled_ = true; }

bool QpackProgressiveDecoder::DoIndexedHeaderFieldInstruction() {
  if (!instruction_decoder_.s_bit()) {
    uint64_t absolute_index;
    if (!QpackRequestStreamRelativeIndexToAbsoluteIndex(
            instruction_decoder_.varint(), base_, &absolute_index)) {
      OnError(QUIC_QPACK_DECOMPRESSION_FAILED, "Invalid relative index.");
      return false;
    }

    if (absolute_index >= required_insert_count_) {
      OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
              "Absolute Index must be smaller than Required Insert Count.");
      return false;
    }

    QUICHE_DCHECK_LT(absolute_index, std::numeric_limits<uint64_t>::max());
    required_insert_count_so_far_ =
        std::max(required_insert_count_so_far_, absolute_index + 1);

    auto entry =
        header_table_->LookupEntry(/* is_static = */ false, absolute_index);
    if (!entry) {
      OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
              "Dynamic table entry already evicted.");
      return false;
    }

    header_table_->set_dynamic_table_entry_referenced();
    return OnHeaderDecoded(!kValueFromStaticTable, entry->name(),
                           entry->value());
  }

  auto entry = header_table_->LookupEntry(/* is_static = */ true,
                                          instruction_decoder_.varint());
  if (!entry) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED, "Static table entry not found.");
    return false;
  }

  return OnHeaderDecoded(kValueFromStaticTable, entry->name(), entry->value());
}

bool QpackProgressiveDecoder::DoIndexedHeaderFieldPostBaseInstruction() {
  uint64_t absolute_index;
  if (!QpackPostBaseIndexToAbsoluteIndex(instruction_decoder_.varint(), base_,
                                         &absolute_index)) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED, "Invalid post-base index.");
    return false;
  }

  if (absolute_index >= required_insert_count_) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
            "Absolute Index must be smaller than Required Insert Count.");
    return false;
  }

  QUICHE_DCHECK_LT(absolute_index, std::numeric_limits<uint64_t>::max());
  required_insert_count_so_far_ =
      std::max(required_insert_count_so_far_, absolute_index + 1);

  auto entry =
      header_table_->LookupEntry(/* is_static = */ false, absolute_index);
  if (!entry) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
            "Dynamic table entry already evicted.");
    return false;
  }

  header_table_->set_dynamic_table_entry_referenced();
  return OnHeaderDecoded(!kValueFromStaticTable, entry->name(), entry->value());
}

bool QpackProgressiveDecoder::DoLiteralHeaderFieldNameReferenceInstruction() {
  if (!instruction_decoder_.s_bit()) {
    uint64_t absolute_index;
    if (!QpackRequestStreamRelativeIndexToAbsoluteIndex(
            instruction_decoder_.varint(), base_, &absolute_index)) {
      OnError(QUIC_QPACK_DECOMPRESSION_FAILED, "Invalid relative index.");
      return false;
    }

    if (absolute_index >= required_insert_count_) {
      OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
              "Absolute Index must be smaller than Required Insert Count.");
      return false;
    }

    QUICHE_DCHECK_LT(absolute_index, std::numeric_limits<uint64_t>::max());
    required_insert_count_so_far_ =
        std::max(required_insert_count_so_far_, absolute_index + 1);

    auto entry =
        header_table_->LookupEntry(/* is_static = */ false, absolute_index);
    if (!entry) {
      OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
              "Dynamic table entry already evicted.");
      return false;
    }

    header_table_->set_dynamic_table_entry_referenced();
    return OnHeaderDecoded(!kValueFromStaticTable, entry->name(),
                           instruction_decoder_.value());
  }

  auto entry = header_table_->LookupEntry(/* is_static = */ true,
                                          instruction_decoder_.varint());
  if (!entry) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED, "Static table entry not found.");
    return false;
  }

  return OnHeaderDecoded(kValueFromStaticTable, entry->name(),
                         instruction_decoder_.value());
}

bool QpackProgressiveDecoder::DoLiteralHeaderFieldPostBaseInstruction() {
  uint64_t absolute_index;
  if (!QpackPostBaseIndexToAbsoluteIndex(instruction_decoder_.varint(), base_,
                                         &absolute_index)) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED, "Invalid post-base index.");
    return false;
  }

  if (absolute_index >= required_insert_count_) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
            "Absolute Index must be smaller than Required Insert Count.");
    return false;
  }

  QUICHE_DCHECK_LT(absolute_index, std::numeric_limits<uint64_t>::max());
  required_insert_count_so_far_ =
      std::max(required_insert_count_so_far_, absolute_index + 1);

  auto entry =
      header_table_->LookupEntry(/* is_static = */ false, absolute_index);
  if (!entry) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
            "Dynamic table entry already evicted.");
    return false;
  }

  header_table_->set_dynamic_table_entry_referenced();
  return OnHeaderDecoded(!kValueFromStaticTable, entry->name(),
                         instruction_decoder_.value());
}

bool QpackProgressiveDecoder::DoLiteralHeaderFieldInstruction() {
  return OnHeaderDecoded(!kValueFromStaticTable, instruction_decoder_.name(),
                         instruction_decoder_.value());
}

bool QpackProgressiveDecoder::DoPrefixInstruction() {
  QUICHE_DCHECK(!prefix_decoded_);

  if (!QpackDecodeRequiredInsertCount(
          prefix_decoder_->varint(), header_table_->max_entries(),
          header_table_->inserted_entry_count(), &required_insert_count_)) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
            "Error decoding Required Insert Count.");
    return false;
  }

  const bool sign = prefix_decoder_->s_bit();
  const uint64_t delta_base = prefix_decoder_->varint2();
  if (!DeltaBaseToBase(sign, delta_base, &base_)) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED, "Error calculating Base.");
    return false;
  }

  prefix_decoded_ = true;

  if (required_insert_count_ > header_table_->inserted_entry_count()) {
    if (!enforcer_->OnStreamBlocked(stream_id_)) {
      OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
              "Limit on number of blocked streams exceeded.");
      return false;
    }
    blocked_ = true;
    header_table_->RegisterObserver(required_insert_count_, this);
  }

  return true;
}

bool QpackProgressiveDecoder::OnHeaderDecoded(bool /*value_from_static_table*/,
                                              absl::string_view name,
                                              absl::string_view value) {
  handler_->OnHeaderDecoded(name, value);
  return true;
}

void QpackProgressiveDecoder::FinishDecoding() {
  QUICHE_DCHECK(buffer_.empty());
  QUICHE_DCHECK(!blocked_);
  QUICHE_DCHECK(!decoding_);

  if (error_detected_) {
    return;
  }

  if (!instruction_decoder_.AtInstructionBoundary()) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED, "Incomplete header block.");
    return;
  }

  if (!prefix_decoded_) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED, "Incomplete header data prefix.");
    return;
  }

  if (required_insert_count_ != required_insert_count_so_far_) {
    OnError(QUIC_QPACK_DECOMPRESSION_FAILED,
            "Required Insert Count too large.");
    return;
  }

  visitor_->OnDecodingCompleted(stream_id_, required_insert_count_);
  handler_->OnDecodingCompleted();
}

void QpackProgressiveDecoder::OnError(QuicErrorCode error_code,
                                      absl::string_view error_message) {
  QUICHE_DCHECK(!error_detected_);

  error_detected_ = true;
  // Might destroy |this|.
  handler_->OnDecodingErrorDetected(error_code, error_message);
}

bool QpackProgressiveDecoder::DeltaBaseToBase(bool sign, uint64_t delta_base,
                                              uint64_t* base) {
  if (sign) {
    if (delta_base == std::numeric_limits<uint64_t>::max() ||
        required_insert_count_ < delta_base + 1) {
      return false;
    }
    *base = required_insert_count_ - delta_base - 1;
    return true;
  }

  if (delta_base >
      std::numeric_limits<uint64_t>::max() - required_insert_count_) {
    return false;
  }
  *base = required_insert_count_ + delta_base;
  return true;
}

}  // namespace quic
```