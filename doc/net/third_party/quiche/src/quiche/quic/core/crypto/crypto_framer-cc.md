Response:
Let's break down the thought process for analyzing this `crypto_framer.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the `CryptoFramer`, its relationship to JavaScript, logical reasoning with examples, common user errors, and debugging steps.

2. **Initial Skim and Identify Key Components:**  I'll first read through the code quickly, looking for class names, important functions, and any obvious data structures. I see `CryptoFramer`, `CryptoHandshakeMessage`, `CryptoFramerVisitorInterface`, `ParseMessage`, `ConstructHandshakeMessage`, `ProcessInput`, and mentions of `QuicTag`. This immediately tells me it's involved in processing and creating cryptographic handshake messages.

3. **Analyze Core Functionality - `CryptoFramer`:**

   * **Purpose:** The name "framer" suggests it's involved in taking raw data and structuring it into meaningful units (frames/messages) and vice-versa. The "crypto" prefix implies this structuring relates to cryptographic handshake processes within the QUIC protocol.
   * **Key Methods:**
      * `ParseMessage`:  This static method clearly takes raw input and attempts to parse a `CryptoHandshakeMessage` from it. It uses a `OneShotVisitor` internally, which hints at a visitor pattern for handling the parsed message.
      * `ProcessInput`:  This is the core processing function. It takes raw input, buffers it, and attempts to parse handshake messages incrementally. It maintains internal state (`state_`) to handle the parsing process.
      * `ConstructHandshakeMessage`: This static method does the opposite of `ParseMessage`. It takes a `CryptoHandshakeMessage` and serializes it into a raw byte stream.
      * `HasTag`:  Checks if a specific tag exists in the currently parsed message.
      * `ForceHandshake`:  Seems to force the completion of a handshake message parsing, even if not all data is available.
      * `Clear`: Resets the internal state of the framer.
   * **State Management:** The `state_` enum (`STATE_READING_TAG`, `STATE_READING_NUM_ENTRIES`, etc.) indicates a state machine for parsing. This is crucial for handling potentially fragmented input.
   * **Error Handling:** The `error_` member and `OnError` method in the visitor suggest error reporting during the parsing process.

4. **Analyze Related Classes:**

   * `CryptoHandshakeMessage`:  This likely represents the structured form of the cryptographic handshake message. It probably contains key-value pairs (tags and their associated data). The methods like `set_tag` and the use of a `tag_value_map` confirm this.
   * `CryptoFramerVisitorInterface`: This interface defines how the `CryptoFramer` communicates parsed messages and errors to its client. The `OnHandshakeMessage` and `OnError` methods are the core of this communication.
   * `OneShotVisitor`: A simple implementation of the visitor interface used for the `ParseMessage` static method.

5. **JavaScript Relationship:**  Consider where QUIC is used in a browser. JavaScript interacts with web servers. QUIC is a transport protocol used by Chromium for fetching web resources. Therefore, the *result* of this code's execution (creating and parsing handshake messages) *indirectly* affects the establishment of secure QUIC connections, which then allows JavaScript code to load web pages. However, there's *no direct JavaScript API* that calls this specific C++ code. The connection is that it's a foundational component of the browser's network stack that makes QUIC (and therefore faster/more reliable web browsing for JavaScript) possible.

6. **Logical Reasoning with Examples:**

   * **Construction:** Imagine a simple handshake message with a "client version" tag and a version number. Show how `ConstructHandshakeMessage` would serialize this.
   * **Parsing:**  Take the output of the construction example and show how `ProcessInput` would parse it, highlighting the state transitions and the role of tags and lengths.

7. **Common User Errors:** Think about how *developers* using the QUIC library might misuse this `CryptoFramer`.

   * **Incomplete Input:**  Not providing enough data for a complete message.
   * **Incorrect Message Format:** Trying to construct messages with duplicate tags or out-of-order tags.
   * **Exceeding Limits:** Sending messages with too many entries.

8. **Debugging Steps:** How would a developer track down an issue related to this code?

   * **Network Sniffing:**  Capture the raw network packets to see the actual bytes being exchanged.
   * **Logging:**  The code uses `QUIC_LOG`. Adding more logging statements around state transitions and data processing would be helpful.
   * **Breakpoints:**  Set breakpoints within `ProcessInput` to step through the parsing logic and inspect variables.

9. **Structure and Refine:** Organize the findings into the requested categories (functionality, JavaScript relation, logical reasoning, errors, debugging). Use clear and concise language. Ensure the examples are easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe there's a direct JavaScript API for QUIC. **Correction:**  While there are evolving browser APIs related to networking, there isn't a direct low-level API that exposes the `CryptoFramer`. The relationship is more at the level of the browser's internal implementation.
* **Considering error examples:**  Focus not on *end-user* errors, but on *developer* errors who are working with the QUIC library.
* **Debugging:**  Initially, I might just say "use a debugger." **Refinement:**  Be more specific about what to log and where to set breakpoints.

By following this structured approach, combining code analysis with knowledge of network protocols and browser architecture, I can generate a comprehensive and accurate answer to the prompt.
这个 `crypto_framer.cc` 文件是 Chromium QUIC 协议栈中负责**构建和解析加密握手消息**的关键组件。 它的主要功能是处理 QUIC 连接建立阶段的密钥交换和参数协商。

**功能列表:**

1. **解析加密握手消息 (`ParseMessage`)**:
   - 接收一个包含加密数据的字符串 ( `absl::string_view in` )。
   - 使用内部状态机逐步解析数据，提取消息类型（`QuicTag`）以及包含的各个字段（由 `QuicTag` 标识）。
   - 将解析后的消息存储在 `CryptoHandshakeMessage` 对象中。
   - 使用 `CryptoFramerVisitorInterface` 通知外部组件解析结果（成功或失败）。

2. **构建加密握手消息 (`ConstructHandshakeMessage`)**:
   - 接收一个 `CryptoHandshakeMessage` 对象，其中包含了要发送的握手信息。
   - 将消息序列化为字节流，包括消息类型标签、字段数量、填充以及各个字段的标签和值。
   - 返回一个包含序列化后数据的 `QuicData` 对象，可以用于网络传输。
   - 负责根据消息大小添加必要的填充，以满足协议的最小大小要求。

3. **处理输入数据流 (`ProcessInput`)**:
   - 接收一段可能包含部分或完整握手消息的字节流 ( `absl::string_view input` )。
   - 将输入数据追加到内部缓冲区。
   - 根据当前解析状态 (`state_`) 读取缓冲区中的数据，并尝试解析握手消息的各个部分（消息标签、字段数量、字段标签和长度、字段值）。
   - 处理消息的截断情况（当 `process_truncated_messages_` 为 true 时）。

4. **维护解析状态**:
   - 使用状态机 (`state_`) 跟踪当前的解析进度，例如正在读取消息标签、字段数量、字段标签和长度、字段值等。
   - 确保按照正确的顺序解析握手消息的各个部分。

5. **错误处理**:
   - 检测并记录解析过程中遇到的错误，例如字段数量过多、标签重复、标签顺序错误、结束偏移量错误等。
   - 将错误信息存储在 `error_detail_` 中，并将错误码设置到 `error_`。
   - 通过 `CryptoFramerVisitorInterface` 的 `OnError` 方法通知外部组件发生了错误。

6. **检查标签是否存在 (`HasTag`)**:
   - 允许检查当前已解析的消息中是否存在特定的 `QuicTag`。

7. **强制完成握手消息解析 (`ForceHandshake`)**:
   - 允许在数据不完整的情况下，尽力解析已接收到的部分数据。

8. **内部数据管理**:
   - 使用 `buffer_` 存储接收到的输入数据。
   - 使用 `tags_and_lengths_` 存储已解析的字段标签及其长度。
   - 使用 `message_` 存储正在解析或已构建的 `CryptoHandshakeMessage` 对象。

**与 JavaScript 的关系:**

`crypto_framer.cc` 是 Chromium 网络栈的 C++ 代码，**与 JavaScript 没有直接的调用关系**。JavaScript 代码运行在浏览器的主进程或渲染进程中，并通过 Chromium 提供的网络 API (如 `fetch`, `XMLHttpRequest`, WebSockets) 与服务器进行交互。

然而，`crypto_framer.cc` 的功能对于建立安全的 QUIC 连接至关重要，而 QUIC 连接可以被浏览器用于加载 JavaScript 代码和进行其他网络通信。 因此，**JavaScript 的网络请求最终会依赖于 QUIC 连接的建立，而 `crypto_framer.cc` 在这个过程中扮演了关键角色。**

**举例说明:**

假设一个使用 `fetch` API 的 JavaScript 代码向一个支持 QUIC 的服务器发起 HTTPS 请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当浏览器执行这个 `fetch` 请求时，底层的 Chromium 网络栈会尝试与 `example.com` 建立 QUIC 连接。 在连接建立的握手阶段，`crypto_framer.cc` 会参与以下过程：

1. **客户端发送 ClientHello 消息:** Chromium 的 QUIC 代码会使用 `ConstructHandshakeMessage` 构建一个包含客户端支持的加密套件、版本等信息的 ClientHello 消息。
2. **服务器接收 ClientHello 消息:** 服务器的 QUIC 实现会解析这个消息。
3. **服务器发送 ServerHello 消息:** 服务器会构建一个包含其选择的加密参数、证书等信息的 ServerHello 消息，并发送给客户端。
4. **客户端接收 ServerHello 消息:**  `crypto_framer.cc` 中的 `ProcessInput` 和 `ParseMessage` 会被用来解析接收到的 ServerHello 消息，提取服务器的加密参数和证书。
5. **后续密钥交换和参数协商:**  `crypto_framer.cc` 会继续处理后续的握手消息，例如 Certificate、CertificateVerify、Finished 等，直到安全连接建立完成。

**逻辑推理 (假设输入与输出):**

**假设输入 (构建消息):**

```c++
CryptoHandshakeMessage message;
message.set_tag(kCHLO); // ClientHello
message.SetValue(kVER, "Q050"); // QUIC 版本
message.SetValue(kSNI, "example.com"); // 服务器名称指示
```

**输出 (构建消息):**

`ConstructHandshakeMessage(message)` 将会返回一个 `QuicData` 对象，其内部包含类似以下的字节序列（简化表示，实际内容会更复杂）：

```
[kCHLO][字段数量][填充][kVER][偏移量1][kSNI][偏移量2][Q050][example.com]
```

**假设输入 (解析消息):**

假设接收到以下服务器发送的 ServerHello 消息的字节序列：

```
[kSHLO][字段数量][填充][kVER][偏移量1][kSCID][偏移量2][Q050][服务器连接ID]
```

**输出 (解析消息):**

调用 `ProcessInput` 并最终传递给 `ParseMessage` 后，`CryptoFramer` 会将解析结果存储在内部的 `message_` 对象中：

```c++
message_.tag() == kSHLO;
message_.GetStringPiece(kVER) == "Q050";
message_.GetStringPiece(kSCID) == "服务器连接ID";
```

**用户或编程常见的使用错误 (以 QUIC 库开发者角度):**

1. **构建消息时字段顺序错误:**  QUIC 握手消息的字段通常有特定的顺序要求。如果开发者在构建 `CryptoHandshakeMessage` 时不按照规范添加字段，`ConstructHandshakeMessage` 可能会生成无效的消息，导致握手失败。
   - **例子:**  在 ClientHello 中，版本信息 (`kVER`) 通常需要在其他字段之前。

2. **解析消息时未处理所有可能的标签:** 在实现 QUIC 终端时，开发者需要能够解析握手消息中可能出现的各种标签。如果代码中缺少对某些标签的处理逻辑，可能会导致解析错误或功能缺失。
   - **例子:**  忽略对 `kSREJ` (拒绝连接) 消息的处理，导致客户端无法处理服务器的拒绝连接。

3. **错误地设置或读取填充:** QUIC 握手消息可能包含填充字节。开发者在构建和解析消息时需要正确处理填充，避免因填充错误导致消息解析失败。
   - **例子:**  在构建消息时，填充长度计算错误，导致消息总长度不符合预期。

4. **未处理消息截断的情况:**  网络传输过程中，握手消息可能会被分片。开发者需要确保 `CryptoFramer` 能够正确处理接收到的部分消息，并在接收到完整消息后再进行解析。
   - **例子:**  `process_truncated_messages_` 设置为 `false` 时，如果接收到部分消息就尝试解析，会导致错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一个用户操作导致代码执行到 `crypto_framer.cc` 的一个典型场景：

1. **用户在 Chrome 浏览器中输入一个 HTTPS URL 并访问，例如 `https://www.example.com`。**
2. **Chrome 浏览器首先会进行 DNS 查询，解析 `www.example.com` 的 IP 地址。**
3. **浏览器发现目标服务器支持 QUIC 协议 (例如，通过 ALPN 协商或 HTTP/3 指示)。**
4. **Chromium 的网络栈开始尝试与服务器建立 QUIC 连接。**
5. **连接建立的第一步是密钥交换和参数协商，这涉及到加密握手消息的交互。**
6. **客户端 (浏览器) 构建 ClientHello 消息。** 这时，`crypto_framer.cc` 中的 `ConstructHandshakeMessage` 函数会被调用，将客户端的握手信息打包成字节流。
7. **客户端将 ClientHello 消息发送给服务器。**
8. **服务器接收到 ClientHello 消息后，会发送 ServerHello 消息。**
9. **客户端接收到 ServerHello 消息。** 这时，`crypto_framer.cc` 中的 `ProcessInput` 函数会被调用，接收并缓存 ServerHello 消息的字节流。
10. **`ProcessInput` 函数会逐步解析接收到的数据，最终调用到 `ParseMessage` 函数。**
11. **`ParseMessage` 函数会根据 ServerHello 消息的格式，提取其中的各种参数，例如服务器选择的 QUIC 版本、连接 ID、加密参数等。**
12. **如果解析过程中出现错误，例如消息格式不符合预期，`CryptoFramer` 会设置错误状态，并通过 Visitor 接口通知上层模块。**

**调试线索:**

当需要调试与 `crypto_framer.cc` 相关的 QUIC 握手问题时，可以采取以下步骤：

1. **启用 QUIC 的详细日志:** Chromium 提供了命令行参数或内部设置来启用 QUIC 的详细日志输出。这些日志会记录握手消息的构建和解析过程，包括每个字段的值。
2. **使用网络抓包工具 (如 Wireshark):**  抓取客户端和服务器之间的网络数据包，可以查看实际传输的握手消息的原始字节流，对比预期格式，找出差异。
3. **在 `crypto_framer.cc` 中设置断点:**  在关键函数如 `ProcessInput`, `ParseMessage`, `ConstructHandshakeMessage` 中设置断点，可以单步执行代码，查看变量的值，了解消息解析或构建的详细过程。
4. **检查 `CryptoFramerVisitorInterface` 的实现:**  查看使用 `CryptoFramer` 的上层模块如何处理解析结果和错误，可以帮助理解握手过程中的控制流程。
5. **关注错误信息:**  `CryptoFramer` 中记录的错误信息 (`error_` 和 `error_detail_`) 是定位问题的关键线索。
6. **对比 QUIC 规范:**  对照 QUIC 的 RFC 文档，理解握手消息的格式和字段的含义，有助于判断解析或构建过程是否符合规范。

通过以上分析，可以更深入地理解 `net/third_party/quiche/src/quiche/quic/core/crypto/crypto_framer.cc` 文件的作用以及它在 QUIC 协议中的重要性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/crypto_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/crypto/crypto_framer.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/quiche_endian.h"

namespace quic {

namespace {

const size_t kQuicTagSize = sizeof(QuicTag);
const size_t kCryptoEndOffsetSize = sizeof(uint32_t);
const size_t kNumEntriesSize = sizeof(uint16_t);

// OneShotVisitor is a framer visitor that records a single handshake message.
class OneShotVisitor : public CryptoFramerVisitorInterface {
 public:
  OneShotVisitor() : error_(false) {}

  void OnError(CryptoFramer* /*framer*/) override { error_ = true; }

  void OnHandshakeMessage(const CryptoHandshakeMessage& message) override {
    out_ = std::make_unique<CryptoHandshakeMessage>(message);
  }

  bool error() const { return error_; }

  std::unique_ptr<CryptoHandshakeMessage> release() { return std::move(out_); }

 private:
  std::unique_ptr<CryptoHandshakeMessage> out_;
  bool error_;
};

}  // namespace

CryptoFramer::CryptoFramer()
    : visitor_(nullptr),
      error_detail_(""),
      num_entries_(0),
      values_len_(0),
      process_truncated_messages_(false) {
  Clear();
}

CryptoFramer::~CryptoFramer() {}

// static
std::unique_ptr<CryptoHandshakeMessage> CryptoFramer::ParseMessage(
    absl::string_view in) {
  OneShotVisitor visitor;
  CryptoFramer framer;

  framer.set_visitor(&visitor);
  if (!framer.ProcessInput(in) || visitor.error() ||
      framer.InputBytesRemaining()) {
    return nullptr;
  }

  return visitor.release();
}

QuicErrorCode CryptoFramer::error() const { return error_; }

const std::string& CryptoFramer::error_detail() const { return error_detail_; }

bool CryptoFramer::ProcessInput(absl::string_view input,
                                EncryptionLevel /*level*/) {
  return ProcessInput(input);
}

bool CryptoFramer::ProcessInput(absl::string_view input) {
  QUICHE_DCHECK_EQ(QUIC_NO_ERROR, error_);
  if (error_ != QUIC_NO_ERROR) {
    return false;
  }
  error_ = Process(input);
  if (error_ != QUIC_NO_ERROR) {
    QUICHE_DCHECK(!error_detail_.empty());
    visitor_->OnError(this);
    return false;
  }

  return true;
}

size_t CryptoFramer::InputBytesRemaining() const { return buffer_.length(); }

bool CryptoFramer::HasTag(QuicTag tag) const {
  if (state_ != STATE_READING_VALUES) {
    return false;
  }
  for (const auto& it : tags_and_lengths_) {
    if (it.first == tag) {
      return true;
    }
  }
  return false;
}

void CryptoFramer::ForceHandshake() {
  QuicDataReader reader(buffer_.data(), buffer_.length(),
                        quiche::HOST_BYTE_ORDER);
  for (const std::pair<QuicTag, size_t>& item : tags_and_lengths_) {
    absl::string_view value;
    if (reader.BytesRemaining() < item.second) {
      break;
    }
    reader.ReadStringPiece(&value, item.second);
    message_.SetStringPiece(item.first, value);
  }
  visitor_->OnHandshakeMessage(message_);
}

// static
std::unique_ptr<QuicData> CryptoFramer::ConstructHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  size_t num_entries = message.tag_value_map().size();
  size_t pad_length = 0;
  bool need_pad_tag = false;
  bool need_pad_value = false;

  size_t len = message.size();
  if (len < message.minimum_size()) {
    need_pad_tag = true;
    need_pad_value = true;
    num_entries++;

    size_t delta = message.minimum_size() - len;
    const size_t overhead = kQuicTagSize + kCryptoEndOffsetSize;
    if (delta > overhead) {
      pad_length = delta - overhead;
    }
    len += overhead + pad_length;
  }

  if (num_entries > kMaxEntries) {
    return nullptr;
  }

  std::unique_ptr<char[]> buffer(new char[len]);
  QuicDataWriter writer(len, buffer.get(), quiche::HOST_BYTE_ORDER);
  if (!writer.WriteTag(message.tag())) {
    QUICHE_DCHECK(false) << "Failed to write message tag.";
    return nullptr;
  }
  if (!writer.WriteUInt16(static_cast<uint16_t>(num_entries))) {
    QUICHE_DCHECK(false) << "Failed to write size.";
    return nullptr;
  }
  if (!writer.WriteUInt16(0)) {
    QUICHE_DCHECK(false) << "Failed to write padding.";
    return nullptr;
  }

  uint32_t end_offset = 0;
  // Tags and offsets
  for (auto it = message.tag_value_map().begin();
       it != message.tag_value_map().end(); ++it) {
    if (it->first == kPAD && need_pad_tag) {
      // Existing PAD tags are only checked when padding needs to be added
      // because parts of the code may need to reserialize received messages
      // and those messages may, legitimately include padding.
      QUICHE_DCHECK(false)
          << "Message needed padding but already contained a PAD tag";
      return nullptr;
    }

    if (it->first > kPAD && need_pad_tag) {
      need_pad_tag = false;
      if (!WritePadTag(&writer, pad_length, &end_offset)) {
        return nullptr;
      }
    }

    if (!writer.WriteTag(it->first)) {
      QUICHE_DCHECK(false) << "Failed to write tag.";
      return nullptr;
    }
    end_offset += it->second.length();
    if (!writer.WriteUInt32(end_offset)) {
      QUICHE_DCHECK(false) << "Failed to write end offset.";
      return nullptr;
    }
  }

  if (need_pad_tag) {
    if (!WritePadTag(&writer, pad_length, &end_offset)) {
      return nullptr;
    }
  }

  // Values
  for (auto it = message.tag_value_map().begin();
       it != message.tag_value_map().end(); ++it) {
    if (it->first > kPAD && need_pad_value) {
      need_pad_value = false;
      if (!writer.WriteRepeatedByte('-', pad_length)) {
        QUICHE_DCHECK(false) << "Failed to write padding.";
        return nullptr;
      }
    }

    if (!writer.WriteBytes(it->second.data(), it->second.length())) {
      QUICHE_DCHECK(false) << "Failed to write value.";
      return nullptr;
    }
  }

  if (need_pad_value) {
    if (!writer.WriteRepeatedByte('-', pad_length)) {
      QUICHE_DCHECK(false) << "Failed to write padding.";
      return nullptr;
    }
  }

  return std::make_unique<QuicData>(buffer.release(), len, true);
}

void CryptoFramer::Clear() {
  message_.Clear();
  tags_and_lengths_.clear();
  error_ = QUIC_NO_ERROR;
  error_detail_ = "";
  state_ = STATE_READING_TAG;
}

QuicErrorCode CryptoFramer::Process(absl::string_view input) {
  // Add this data to the buffer.
  buffer_.append(input.data(), input.length());
  QuicDataReader reader(buffer_.data(), buffer_.length(),
                        quiche::HOST_BYTE_ORDER);

  switch (state_) {
    case STATE_READING_TAG:
      if (reader.BytesRemaining() < kQuicTagSize) {
        break;
      }
      QuicTag message_tag;
      reader.ReadTag(&message_tag);
      message_.set_tag(message_tag);
      state_ = STATE_READING_NUM_ENTRIES;
      ABSL_FALLTHROUGH_INTENDED;
    case STATE_READING_NUM_ENTRIES:
      if (reader.BytesRemaining() < kNumEntriesSize + sizeof(uint16_t)) {
        break;
      }
      reader.ReadUInt16(&num_entries_);
      if (num_entries_ > kMaxEntries) {
        error_detail_ = absl::StrCat(num_entries_, " entries");
        return QUIC_CRYPTO_TOO_MANY_ENTRIES;
      }
      uint16_t padding;
      reader.ReadUInt16(&padding);

      tags_and_lengths_.reserve(num_entries_);
      state_ = STATE_READING_TAGS_AND_LENGTHS;
      values_len_ = 0;
      ABSL_FALLTHROUGH_INTENDED;
    case STATE_READING_TAGS_AND_LENGTHS: {
      if (reader.BytesRemaining() <
          num_entries_ * (kQuicTagSize + kCryptoEndOffsetSize)) {
        break;
      }

      uint32_t last_end_offset = 0;
      for (unsigned i = 0; i < num_entries_; ++i) {
        QuicTag tag;
        reader.ReadTag(&tag);
        if (i > 0 && tag <= tags_and_lengths_[i - 1].first) {
          if (tag == tags_and_lengths_[i - 1].first) {
            error_detail_ = absl::StrCat("Duplicate tag:", tag);
            return QUIC_CRYPTO_DUPLICATE_TAG;
          }
          error_detail_ = absl::StrCat("Tag ", tag, " out of order");
          return QUIC_CRYPTO_TAGS_OUT_OF_ORDER;
        }

        uint32_t end_offset;
        reader.ReadUInt32(&end_offset);

        if (end_offset < last_end_offset) {
          error_detail_ =
              absl::StrCat("End offset: ", end_offset, " vs ", last_end_offset);
          return QUIC_CRYPTO_TAGS_OUT_OF_ORDER;
        }
        tags_and_lengths_.push_back(std::make_pair(
            tag, static_cast<size_t>(end_offset - last_end_offset)));
        last_end_offset = end_offset;
      }
      values_len_ = last_end_offset;
      state_ = STATE_READING_VALUES;
      ABSL_FALLTHROUGH_INTENDED;
    }
    case STATE_READING_VALUES:
      if (reader.BytesRemaining() < values_len_) {
        if (!process_truncated_messages_) {
          break;
        }
        QUIC_LOG(ERROR) << "Trunacted message. Missing "
                        << values_len_ - reader.BytesRemaining() << " bytes.";
      }
      for (const std::pair<QuicTag, size_t>& item : tags_and_lengths_) {
        absl::string_view value;
        if (!reader.ReadStringPiece(&value, item.second)) {
          QUICHE_DCHECK(process_truncated_messages_);
          // Store an empty value.
          message_.SetStringPiece(item.first, "");
          continue;
        }
        message_.SetStringPiece(item.first, value);
      }
      visitor_->OnHandshakeMessage(message_);
      Clear();
      state_ = STATE_READING_TAG;
      break;
  }
  // Save any remaining data.
  buffer_ = std::string(reader.PeekRemainingPayload());
  return QUIC_NO_ERROR;
}

// static
bool CryptoFramer::WritePadTag(QuicDataWriter* writer, size_t pad_length,
                               uint32_t* end_offset) {
  if (!writer->WriteTag(kPAD)) {
    QUICHE_DCHECK(false) << "Failed to write tag.";
    return false;
  }
  *end_offset += pad_length;
  if (!writer->WriteUInt32(*end_offset)) {
    QUICHE_DCHECK(false) << "Failed to write end offset.";
    return false;
  }
  return true;
}

}  // namespace quic
```