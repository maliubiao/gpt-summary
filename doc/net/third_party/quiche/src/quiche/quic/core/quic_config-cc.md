Response:
The user wants to understand the functionality of the `quic_config.cc` file in the Chromium network stack. They are particularly interested in:

1. **Functionality Overview:** What does this file do?
2. **JavaScript Relationship:** Does it interact with JavaScript, and if so, how?
3. **Logical Inference:**  Examples of logical deductions within the code, with hypothetical inputs and outputs.
4. **Common Usage Errors:** Mistakes users or programmers might make when using this code.
5. **Debugging Context:** How does a user's action lead to this code being executed, aiding in debugging?
6. **Summary of Functionality (Part 1):** A concise summary of the functionality presented in the provided code snippet.

**Plan:**

1. **Analyze the Code:** Carefully examine the provided C++ code to understand its purpose and the data structures it defines.
2. **Identify Core Functionality:** Determine the main tasks performed by this file. It seems to be related to configuring and managing QUIC connection parameters.
3. **JavaScript Relationship:**  Consider how QUIC configuration might indirectly affect JavaScript through network requests initiated by web pages.
4. **Logical Inference Examples:** Look for conditional logic or data transformations within the code. Create simple input scenarios and trace the expected output.
5. **Common Usage Errors:** Think about how developers might misuse the configuration options or the provided API.
6. **Debugging Scenario:**  Imagine a typical user interaction that involves a QUIC connection and how that might lead to this configuration code being involved.
7. **Summarize Part 1:**  Condense the understanding of the code into a brief overview of its purpose.
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_config.cc的chromium 网络栈的源代码文件， 请列举一下它的功能,
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

**`net/third_party/quiche/src/quiche/quic/core/quic_config.cc` 的功能 (第 1 部分):**

该文件定义了 QUIC 协议连接的配置类 `QuicConfig` 及其相关的辅助类，用于管理和协商 QUIC 连接的各种参数。  主要功能可以归纳为：

1. **定义和管理连接配置参数:**
   - 该文件定义了 `QuicConfig` 类，该类存储了 QUIC 连接的各种配置选项，例如最大双向流数量、最大空闲超时时间、初始拥塞窗口大小等。
   - 它使用 `QuicFixedUint32`, `QuicFixedUint62`, `QuicFixedStatelessResetToken`, `QuicFixedTagVector`, `QuicFixedSocketAddress` 等辅助类来表示不同类型的配置参数。这些辅助类负责存储和管理单个配置项的发送值和接收值，以及在握手消息中的序列化和反序列化。

2. **处理握手消息中的配置参数:**
   - 代码提供了将配置参数添加到握手消息 (`CryptoHandshakeMessage`) 和从握手消息中读取配置参数的功能。
   - `ToHandshakeMessage` 方法将本地配置参数添加到要发送的握手消息中。
   - `ProcessPeerHello` 方法从接收到的对等方的握手消息中提取配置参数。
   - `ReadUint32` 辅助函数用于从握手消息中读取 uint32 类型的参数，并处理参数缺失或格式错误的情况。

3. **区分发送和接收的配置值:**
   - 对于每个配置参数，都有独立的“发送值”和“接收值”。
   - 发送值是本地希望使用的值，用于发送给对等方。
   - 接收值是从对等方接收到的值，表示对等方使用的配置。

4. **支持可选和必需的配置参数:**
   - `QuicConfigPresence` 枚举定义了配置参数是必需的 (`PRESENCE_REQUIRED`) 还是可选的 (`PRESENCE_OPTIONAL`)。
   - 在读取握手消息时，如果必需的参数缺失，则会返回错误。

5. **提供设置和获取配置参数的接口:**
   - `QuicConfig` 类提供了各种 `Set...ToSend` 方法来设置要发送给对等方的配置参数值。
   - 提供了 `Get...ToSend` 和 `Received...` 方法来获取发送和接收到的配置参数值。

**与 JavaScript 的关系举例说明:**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它所配置的 QUIC 连接是 Web 浏览器进行网络通信的基础。JavaScript 通过浏览器提供的 Web API (例如 `fetch`, `XMLHttpRequest`, `WebSocket`) 发起网络请求，这些请求可能会使用 QUIC 协议。

**举例:**

假设一个网页上的 JavaScript 代码使用 `fetch` API 发起一个 HTTPS 请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，浏览器底层的网络栈可能会使用 QUIC 协议来建立与 `example.com` 服务器的连接。`QuicConfig` 类在这个连接建立过程中起作用：

- **配置连接选项:** JavaScript 代码发起请求时，浏览器可能会根据自身的配置（例如，通过 Chrome 的设置或实验性功能）设置一些 QUIC 连接选项。这些选项会被设置到 `QuicConfig` 对象中，并在握手阶段发送给服务器。
- **服务器配置:** 服务器也会有自己的 `QuicConfig` 对象，并将其配置发送给浏览器。
- **协商参数:**  浏览器和服务器通过交换握手消息，根据各自的 `QuicConfig` 对象来协商最终的连接参数，例如最大流数量、拥塞控制算法等。这些协商的结果会影响到 JavaScript 发起的请求的性能，例如，更多的流数量可能允许浏览器并行下载更多的资源。

**逻辑推理的假设输入与输出:**

考虑 `ReadUint32` 函数：

**假设输入:**

- `msg`: 一个 `CryptoHandshakeMessage` 对象，其中包含键值对，例如 `{{kMIBS, 100}, {kCFCW, 65535}}` (表示最大双向流数为 100，连接级流量控制窗口为 65535 字节)。
- `tag`: `kMIBS` (代表最大双向流数)。
- `presence`: `PRESENCE_REQUIRED`.
- `default_value`: 0 (这里不影响，因为参数存在).
- `out`: 一个指向 `uint32_t` 变量的指针。
- `error_details`: 一个指向 `std::string` 变量的指针。

**输出:**

- 返回值: `QUIC_NO_ERROR`.
- `*out`: 100.
- `*error_details`: "" (空字符串，表示没有错误).

**假设输入 (参数缺失):**

- `msg`: 一个 `CryptoHandshakeMessage` 对象，其中包含键值对，例如 `{{kCFCW, 65535}}` (缺少 `kMIBS` 参数)。
- `tag`: `kMIBS`.
- `presence`: `PRESENCE_REQUIRED`.
- `default_value`: 0.
- `out`: 一个指向 `uint32_t` 变量的指针。
- `error_details`: 一个指向 `std::string` 变量的指针。

**输出:**

- 返回值: `QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND`.
- `*out`: 值不确定，取决于 `out` 指向的变量的初始值.
- `*error_details`: "Missing MIBS".

**假设输入 (可选参数缺失):**

- `msg`: 一个 `CryptoHandshakeMessage` 对象，其中包含键值对，例如 `{{kCFCW, 65535}}` (缺少 `kMIUS` 参数，假设 `kMIUS` 是可选的)。
- `tag`: `kMIUS`.
- `presence`: `PRESENCE_OPTIONAL`.
- `default_value`: 5.
- `out`: 一个指向 `uint32_t` 变量的指针。
- `error_details`: 一个指向 `std::string` 变量的指针。

**输出:**

- 返回值: `QUIC_NO_ERROR`.
- `*out`: 5 (设置为 `default_value`).
- `*error_details`: "" (空字符串，表示没有错误).

**用户或编程常见的使用错误举例说明:**

1. **尝试在握手完成后修改已协商的参数:** 一旦 QUIC 连接建立，某些参数就不能再更改。如果在握手完成后尝试修改这些参数的发送值，可能不会生效，或者会导致连接出现意外行为。
   ```c++
   QuicConfig config;
   // ... 进行握手 ...
   config.SetMaxBidirectionalStreamsToSend(200); // 错误：握手完成后修改参数
   ```

2. **错误地设置必需参数的 `presence` 为 `PRESENCE_OPTIONAL`:** 如果某个参数在协议中是必需的，但代码中将其定义为可选的，可能会导致在接收到不包含该参数的握手消息时，程序不会报错，而是使用默认值，这可能导致连接行为不符合预期。

3. **在发送握手消息前忘记设置必需的参数:** 如果某个配置参数被标记为 `PRESENCE_REQUIRED`，但在发送握手消息之前没有为其设置发送值，对等方可能会因为缺少必需的参数而拒绝连接。

4. **混淆发送值和接收值:** 开发者可能会错误地使用 `Get...ToSend()` 来获取对等方的配置，或者使用 `Set...ToSend()` 来设置本地的接收配置。

**用户操作如何一步步到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个使用 QUIC 协议的网站时遇到连接问题。以下是可能到达 `quic_config.cc` 的调试线索：

1. **用户在浏览器地址栏输入 URL 并按下回车。**
2. **浏览器解析 URL，确定需要建立 HTTPS 连接。**
3. **浏览器网络栈尝试与服务器建立连接，并选择使用 QUIC 协议（如果可用且配置允许）。**
4. **QUIC 连接建立过程涉及 TLS 握手，其中包含 QUIC 特有的握手消息。**
5. **在握手过程中，`QuicConfig` 对象会被创建和使用，用于管理本地和对等方的配置参数。**
6. **如果握手失败，或者连接出现异常行为，开发者可能会查看 Chrome 的内部日志（例如 `net-internals`），这些日志可能会显示与 QUIC 配置相关的错误信息，例如缺少必需的参数，或者参数值不一致。**
7. **为了更深入地调试，开发者可能会查看 Chromium 的源代码，并断点到 `quic_config.cc` 中的 `ProcessPeerHello` 等函数，以检查接收到的配置参数是否正确，以及本地的配置是否按预期发送。**
8. **用户可能启用了 Chrome 的实验性 QUIC 功能，或者通过命令行参数修改了 QUIC 相关的配置。这些配置最终会影响到 `QuicConfig` 对象的状态。**

**归纳一下它的功能 (第 1 部分):**

`quic_config.cc` 文件的主要功能是**定义和管理 QUIC 连接的配置参数，负责在握手阶段序列化和反序列化这些参数，并区分本地发送的配置和从对等方接收的配置。** 它为 QUIC 连接的建立和运行提供了必要的配置基础。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_config.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_config.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/crypto_handshake_message.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_socket_address_coder.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quic {

// Reads the value corresponding to |name_| from |msg| into |out|. If the
// |name_| is absent in |msg| and |presence| is set to OPTIONAL |out| is set
// to |default_value|.
QuicErrorCode ReadUint32(const CryptoHandshakeMessage& msg, QuicTag tag,
                         QuicConfigPresence presence, uint32_t default_value,
                         uint32_t* out, std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);
  QuicErrorCode error = msg.GetUint32(tag, out);
  switch (error) {
    case QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND:
      if (presence == PRESENCE_REQUIRED) {
        *error_details = "Missing " + QuicTagToString(tag);
        break;
      }
      error = QUIC_NO_ERROR;
      *out = default_value;
      break;
    case QUIC_NO_ERROR:
      break;
    default:
      *error_details = "Bad " + QuicTagToString(tag);
      break;
  }
  return error;
}

QuicConfigValue::QuicConfigValue(QuicTag tag, QuicConfigPresence presence)
    : tag_(tag), presence_(presence) {}
QuicConfigValue::~QuicConfigValue() {}

QuicFixedUint32::QuicFixedUint32(QuicTag tag, QuicConfigPresence presence)
    : QuicConfigValue(tag, presence),
      has_send_value_(false),
      has_receive_value_(false) {}
QuicFixedUint32::~QuicFixedUint32() {}

bool QuicFixedUint32::HasSendValue() const { return has_send_value_; }

uint32_t QuicFixedUint32::GetSendValue() const {
  QUIC_BUG_IF(quic_bug_12743_1, !has_send_value_)
      << "No send value to get for tag:" << QuicTagToString(tag_);
  return send_value_;
}

void QuicFixedUint32::SetSendValue(uint32_t value) {
  has_send_value_ = true;
  send_value_ = value;
}

bool QuicFixedUint32::HasReceivedValue() const { return has_receive_value_; }

uint32_t QuicFixedUint32::GetReceivedValue() const {
  QUIC_BUG_IF(quic_bug_12743_2, !has_receive_value_)
      << "No receive value to get for tag:" << QuicTagToString(tag_);
  return receive_value_;
}

void QuicFixedUint32::SetReceivedValue(uint32_t value) {
  has_receive_value_ = true;
  receive_value_ = value;
}

void QuicFixedUint32::ToHandshakeMessage(CryptoHandshakeMessage* out) const {
  if (tag_ == 0) {
    QUIC_BUG(quic_bug_12743_3)
        << "This parameter does not support writing to CryptoHandshakeMessage";
    return;
  }
  if (has_send_value_) {
    out->SetValue(tag_, send_value_);
  }
}

QuicErrorCode QuicFixedUint32::ProcessPeerHello(
    const CryptoHandshakeMessage& peer_hello, HelloType /*hello_type*/,
    std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);
  if (tag_ == 0) {
    *error_details =
        "This parameter does not support reading from CryptoHandshakeMessage";
    QUIC_BUG(quic_bug_10575_1) << *error_details;
    return QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND;
  }
  QuicErrorCode error = peer_hello.GetUint32(tag_, &receive_value_);
  switch (error) {
    case QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND:
      if (presence_ == PRESENCE_OPTIONAL) {
        return QUIC_NO_ERROR;
      }
      *error_details = "Missing " + QuicTagToString(tag_);
      break;
    case QUIC_NO_ERROR:
      has_receive_value_ = true;
      break;
    default:
      *error_details = "Bad " + QuicTagToString(tag_);
      break;
  }
  return error;
}

QuicFixedUint62::QuicFixedUint62(QuicTag name, QuicConfigPresence presence)
    : QuicConfigValue(name, presence),
      has_send_value_(false),
      has_receive_value_(false) {}

QuicFixedUint62::~QuicFixedUint62() {}

bool QuicFixedUint62::HasSendValue() const { return has_send_value_; }

uint64_t QuicFixedUint62::GetSendValue() const {
  if (!has_send_value_) {
    QUIC_BUG(quic_bug_10575_2)
        << "No send value to get for tag:" << QuicTagToString(tag_);
    return 0;
  }
  return send_value_;
}

void QuicFixedUint62::SetSendValue(uint64_t value) {
  if (value > quiche::kVarInt62MaxValue) {
    QUIC_BUG(quic_bug_10575_3) << "QuicFixedUint62 invalid value " << value;
    value = quiche::kVarInt62MaxValue;
  }
  has_send_value_ = true;
  send_value_ = value;
}

bool QuicFixedUint62::HasReceivedValue() const { return has_receive_value_; }

uint64_t QuicFixedUint62::GetReceivedValue() const {
  if (!has_receive_value_) {
    QUIC_BUG(quic_bug_10575_4)
        << "No receive value to get for tag:" << QuicTagToString(tag_);
    return 0;
  }
  return receive_value_;
}

void QuicFixedUint62::SetReceivedValue(uint64_t value) {
  has_receive_value_ = true;
  receive_value_ = value;
}

void QuicFixedUint62::ToHandshakeMessage(CryptoHandshakeMessage* out) const {
  if (!has_send_value_) {
    return;
  }
  uint32_t send_value32;
  if (send_value_ > std::numeric_limits<uint32_t>::max()) {
    QUIC_BUG(quic_bug_10575_5) << "Attempting to send " << send_value_
                               << " for tag:" << QuicTagToString(tag_);
    send_value32 = std::numeric_limits<uint32_t>::max();
  } else {
    send_value32 = static_cast<uint32_t>(send_value_);
  }
  out->SetValue(tag_, send_value32);
}

QuicErrorCode QuicFixedUint62::ProcessPeerHello(
    const CryptoHandshakeMessage& peer_hello, HelloType /*hello_type*/,
    std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);
  uint32_t receive_value32;
  QuicErrorCode error = peer_hello.GetUint32(tag_, &receive_value32);
  // GetUint32 is guaranteed to always initialize receive_value32.
  receive_value_ = receive_value32;
  switch (error) {
    case QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND:
      if (presence_ == PRESENCE_OPTIONAL) {
        return QUIC_NO_ERROR;
      }
      *error_details = "Missing " + QuicTagToString(tag_);
      break;
    case QUIC_NO_ERROR:
      has_receive_value_ = true;
      break;
    default:
      *error_details = "Bad " + QuicTagToString(tag_);
      break;
  }
  return error;
}

QuicFixedStatelessResetToken::QuicFixedStatelessResetToken(
    QuicTag tag, QuicConfigPresence presence)
    : QuicConfigValue(tag, presence),
      has_send_value_(false),
      has_receive_value_(false) {}
QuicFixedStatelessResetToken::~QuicFixedStatelessResetToken() {}

bool QuicFixedStatelessResetToken::HasSendValue() const {
  return has_send_value_;
}

const StatelessResetToken& QuicFixedStatelessResetToken::GetSendValue() const {
  QUIC_BUG_IF(quic_bug_12743_4, !has_send_value_)
      << "No send value to get for tag:" << QuicTagToString(tag_);
  return send_value_;
}

void QuicFixedStatelessResetToken::SetSendValue(
    const StatelessResetToken& value) {
  has_send_value_ = true;
  send_value_ = value;
}

bool QuicFixedStatelessResetToken::HasReceivedValue() const {
  return has_receive_value_;
}

const StatelessResetToken& QuicFixedStatelessResetToken::GetReceivedValue()
    const {
  QUIC_BUG_IF(quic_bug_12743_5, !has_receive_value_)
      << "No receive value to get for tag:" << QuicTagToString(tag_);
  return receive_value_;
}

void QuicFixedStatelessResetToken::SetReceivedValue(
    const StatelessResetToken& value) {
  has_receive_value_ = true;
  receive_value_ = value;
}

void QuicFixedStatelessResetToken::ToHandshakeMessage(
    CryptoHandshakeMessage* out) const {
  if (has_send_value_) {
    out->SetValue(tag_, send_value_);
  }
}

QuicErrorCode QuicFixedStatelessResetToken::ProcessPeerHello(
    const CryptoHandshakeMessage& peer_hello, HelloType /*hello_type*/,
    std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);
  QuicErrorCode error =
      peer_hello.GetStatelessResetToken(tag_, &receive_value_);
  switch (error) {
    case QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND:
      if (presence_ == PRESENCE_OPTIONAL) {
        return QUIC_NO_ERROR;
      }
      *error_details = "Missing " + QuicTagToString(tag_);
      break;
    case QUIC_NO_ERROR:
      has_receive_value_ = true;
      break;
    default:
      *error_details = "Bad " + QuicTagToString(tag_);
      break;
  }
  return error;
}

QuicFixedTagVector::QuicFixedTagVector(QuicTag name,
                                       QuicConfigPresence presence)
    : QuicConfigValue(name, presence),
      has_send_values_(false),
      has_receive_values_(false) {}

QuicFixedTagVector::QuicFixedTagVector(const QuicFixedTagVector& other) =
    default;

QuicFixedTagVector::~QuicFixedTagVector() {}

bool QuicFixedTagVector::HasSendValues() const { return has_send_values_; }

const QuicTagVector& QuicFixedTagVector::GetSendValues() const {
  QUIC_BUG_IF(quic_bug_12743_6, !has_send_values_)
      << "No send values to get for tag:" << QuicTagToString(tag_);
  return send_values_;
}

void QuicFixedTagVector::SetSendValues(const QuicTagVector& values) {
  has_send_values_ = true;
  send_values_ = values;
}

bool QuicFixedTagVector::HasReceivedValues() const {
  return has_receive_values_;
}

const QuicTagVector& QuicFixedTagVector::GetReceivedValues() const {
  QUIC_BUG_IF(quic_bug_12743_7, !has_receive_values_)
      << "No receive value to get for tag:" << QuicTagToString(tag_);
  return receive_values_;
}

void QuicFixedTagVector::SetReceivedValues(const QuicTagVector& values) {
  has_receive_values_ = true;
  receive_values_ = values;
}

void QuicFixedTagVector::ToHandshakeMessage(CryptoHandshakeMessage* out) const {
  if (has_send_values_) {
    out->SetVector(tag_, send_values_);
  }
}

QuicErrorCode QuicFixedTagVector::ProcessPeerHello(
    const CryptoHandshakeMessage& peer_hello, HelloType /*hello_type*/,
    std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);
  QuicTagVector values;
  QuicErrorCode error = peer_hello.GetTaglist(tag_, &values);
  switch (error) {
    case QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND:
      if (presence_ == PRESENCE_OPTIONAL) {
        return QUIC_NO_ERROR;
      }
      *error_details = "Missing " + QuicTagToString(tag_);
      break;
    case QUIC_NO_ERROR:
      QUIC_DVLOG(1) << "Received Connection Option tags from receiver.";
      has_receive_values_ = true;
      receive_values_.insert(receive_values_.end(), values.begin(),
                             values.end());
      break;
    default:
      *error_details = "Bad " + QuicTagToString(tag_);
      break;
  }
  return error;
}

QuicFixedSocketAddress::QuicFixedSocketAddress(QuicTag tag,
                                               QuicConfigPresence presence)
    : QuicConfigValue(tag, presence),
      has_send_value_(false),
      has_receive_value_(false) {}

QuicFixedSocketAddress::~QuicFixedSocketAddress() {}

bool QuicFixedSocketAddress::HasSendValue() const { return has_send_value_; }

const QuicSocketAddress& QuicFixedSocketAddress::GetSendValue() const {
  QUIC_BUG_IF(quic_bug_12743_8, !has_send_value_)
      << "No send value to get for tag:" << QuicTagToString(tag_);
  return send_value_;
}

void QuicFixedSocketAddress::SetSendValue(const QuicSocketAddress& value) {
  has_send_value_ = true;
  send_value_ = value;
}

void QuicFixedSocketAddress::ClearSendValue() {
  has_send_value_ = false;
  send_value_ = QuicSocketAddress();
}

bool QuicFixedSocketAddress::HasReceivedValue() const {
  return has_receive_value_;
}

const QuicSocketAddress& QuicFixedSocketAddress::GetReceivedValue() const {
  QUIC_BUG_IF(quic_bug_12743_9, !has_receive_value_)
      << "No receive value to get for tag:" << QuicTagToString(tag_);
  return receive_value_;
}

void QuicFixedSocketAddress::SetReceivedValue(const QuicSocketAddress& value) {
  has_receive_value_ = true;
  receive_value_ = value;
}

void QuicFixedSocketAddress::ToHandshakeMessage(
    CryptoHandshakeMessage* out) const {
  if (has_send_value_) {
    QuicSocketAddressCoder address_coder(send_value_);
    out->SetStringPiece(tag_, address_coder.Encode());
  }
}

QuicErrorCode QuicFixedSocketAddress::ProcessPeerHello(
    const CryptoHandshakeMessage& peer_hello, HelloType /*hello_type*/,
    std::string* error_details) {
  absl::string_view address;
  if (!peer_hello.GetStringPiece(tag_, &address)) {
    if (presence_ == PRESENCE_REQUIRED) {
      *error_details = "Missing " + QuicTagToString(tag_);
      return QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND;
    }
  } else {
    QuicSocketAddressCoder address_coder;
    if (address_coder.Decode(address.data(), address.length())) {
      SetReceivedValue(
          QuicSocketAddress(address_coder.ip(), address_coder.port()));
    }
  }
  return QUIC_NO_ERROR;
}

QuicConfig::QuicConfig()
    : negotiated_(false),
      max_time_before_crypto_handshake_(QuicTime::Delta::Zero()),
      max_idle_time_before_crypto_handshake_(QuicTime::Delta::Zero()),
      max_undecryptable_packets_(0),
      connection_options_(kCOPT, PRESENCE_OPTIONAL),
      client_connection_options_(kCLOP, PRESENCE_OPTIONAL),
      max_idle_timeout_to_send_(QuicTime::Delta::Infinite()),
      max_bidirectional_streams_(kMIBS, PRESENCE_REQUIRED),
      max_unidirectional_streams_(kMIUS, PRESENCE_OPTIONAL),
      bytes_for_connection_id_(kTCID, PRESENCE_OPTIONAL),
      initial_round_trip_time_us_(kIRTT, PRESENCE_OPTIONAL),
      initial_max_stream_data_bytes_incoming_bidirectional_(0,
                                                            PRESENCE_OPTIONAL),
      initial_max_stream_data_bytes_outgoing_bidirectional_(0,
                                                            PRESENCE_OPTIONAL),
      initial_max_stream_data_bytes_unidirectional_(0, PRESENCE_OPTIONAL),
      initial_stream_flow_control_window_bytes_(kSFCW, PRESENCE_OPTIONAL),
      initial_session_flow_control_window_bytes_(kCFCW, PRESENCE_OPTIONAL),
      connection_migration_disabled_(kNCMR, PRESENCE_OPTIONAL),
      alternate_server_address_ipv6_(kASAD, PRESENCE_OPTIONAL),
      alternate_server_address_ipv4_(kASAD, PRESENCE_OPTIONAL),
      stateless_reset_token_(kSRST, PRESENCE_OPTIONAL),
      max_ack_delay_ms_(kMAD, PRESENCE_OPTIONAL),
      min_ack_delay_ms_(0, PRESENCE_OPTIONAL),
      ack_delay_exponent_(kADE, PRESENCE_OPTIONAL),
      max_udp_payload_size_(0, PRESENCE_OPTIONAL),
      max_datagram_frame_size_(0, PRESENCE_OPTIONAL),
      active_connection_id_limit_(0, PRESENCE_OPTIONAL) {
  SetDefaults();
}

QuicConfig::QuicConfig(const QuicConfig& other) = default;

QuicConfig::~QuicConfig() {}

bool QuicConfig::SetInitialReceivedConnectionOptions(
    const QuicTagVector& tags) {
  if (HasReceivedConnectionOptions()) {
    // If we have already received connection options (via handshake or due to
    // a previous call), don't re-initialize.
    return false;
  }
  connection_options_.SetReceivedValues(tags);
  return true;
}

void QuicConfig::SetConnectionOptionsToSend(
    const QuicTagVector& connection_options) {
  connection_options_.SetSendValues(connection_options);
}

void QuicConfig::AddConnectionOptionsToSend(
    const QuicTagVector& connection_options) {
  if (!connection_options_.HasSendValues()) {
    SetConnectionOptionsToSend(connection_options);
    return;
  }
  const QuicTagVector& existing_connection_options = SendConnectionOptions();
  QuicTagVector connection_options_to_send;
  connection_options_to_send.reserve(existing_connection_options.size() +
                                     connection_options.size());
  connection_options_to_send.assign(existing_connection_options.begin(),
                                    existing_connection_options.end());
  connection_options_to_send.insert(connection_options_to_send.end(),
                                    connection_options.begin(),
                                    connection_options.end());
  SetConnectionOptionsToSend(connection_options_to_send);
}

void QuicConfig::SetGoogleHandshakeMessageToSend(std::string message) {
  google_handshake_message_to_send_ = std::move(message);
}

const std::optional<std::string>&
QuicConfig::GetReceivedGoogleHandshakeMessage() const {
  return received_google_handshake_message_;
}

void QuicConfig::SetDiscardLengthToSend(int32_t discard_length) {
  discard_length_to_send_ = discard_length;
}

bool QuicConfig::HasReceivedConnectionOptions() const {
  return connection_options_.HasReceivedValues();
}

const QuicTagVector& QuicConfig::ReceivedConnectionOptions() const {
  return connection_options_.GetReceivedValues();
}

bool QuicConfig::HasSendConnectionOptions() const {
  return connection_options_.HasSendValues();
}

const QuicTagVector& QuicConfig::SendConnectionOptions() const {
  return connection_options_.GetSendValues();
}

bool QuicConfig::HasClientSentConnectionOption(QuicTag tag,
                                               Perspective perspective) const {
  if (perspective == Perspective::IS_SERVER) {
    if (HasReceivedConnectionOptions() &&
        ContainsQuicTag(ReceivedConnectionOptions(), tag)) {
      return true;
    }
  } else if (HasSendConnectionOptions() &&
             ContainsQuicTag(SendConnectionOptions(), tag)) {
    return true;
  }
  return false;
}

void QuicConfig::SetClientConnectionOptions(
    const QuicTagVector& client_connection_options) {
  client_connection_options_.SetSendValues(client_connection_options);
}

bool QuicConfig::HasClientRequestedIndependentOption(
    QuicTag tag, Perspective perspective) const {
  if (perspective == Perspective::IS_SERVER) {
    return (HasReceivedConnectionOptions() &&
            ContainsQuicTag(ReceivedConnectionOptions(), tag));
  }

  return (client_connection_options_.HasSendValues() &&
          ContainsQuicTag(client_connection_options_.GetSendValues(), tag));
}

const QuicTagVector& QuicConfig::ClientRequestedIndependentOptions(
    Perspective perspective) const {
  static const QuicTagVector* no_options = new QuicTagVector;
  if (perspective == Perspective::IS_SERVER) {
    return HasReceivedConnectionOptions() ? ReceivedConnectionOptions()
                                          : *no_options;
  }

  return client_connection_options_.HasSendValues()
             ? client_connection_options_.GetSendValues()
             : *no_options;
}

void QuicConfig::SetIdleNetworkTimeout(QuicTime::Delta idle_network_timeout) {
  if (idle_network_timeout.ToMicroseconds() <= 0) {
    QUIC_BUG(quic_bug_10575_6)
        << "Invalid idle network timeout " << idle_network_timeout;
    return;
  }
  max_idle_timeout_to_send_ = idle_network_timeout;
}

QuicTime::Delta QuicConfig::IdleNetworkTimeout() const {
  // TODO(b/152032210) add a QUIC_BUG to ensure that is not called before we've
  // received the peer's values. This is true in production code but not in all
  // of our tests that use a fake QuicConfig.
  if (!received_max_idle_timeout_.has_value()) {
    return max_idle_timeout_to_send_;
  }
  return *received_max_idle_timeout_;
}

void QuicConfig::SetMaxBidirectionalStreamsToSend(uint32_t max_streams) {
  max_bidirectional_streams_.SetSendValue(max_streams);
}

uint32_t QuicConfig::GetMaxBidirectionalStreamsToSend() const {
  return max_bidirectional_streams_.GetSendValue();
}

bool QuicConfig::HasReceivedMaxBidirectionalStreams() const {
  return max_bidirectional_streams_.HasReceivedValue();
}

uint32_t QuicConfig::ReceivedMaxBidirectionalStreams() const {
  return max_bidirectional_streams_.GetReceivedValue();
}

void QuicConfig::SetMaxUnidirectionalStreamsToSend(uint32_t max_streams) {
  max_unidirectional_streams_.SetSendValue(max_streams);
}

uint32_t QuicConfig::GetMaxUnidirectionalStreamsToSend() const {
  return max_unidirectional_streams_.GetSendValue();
}

bool QuicConfig::HasReceivedMaxUnidirectionalStreams() const {
  return max_unidirectional_streams_.HasReceivedValue();
}

uint32_t QuicConfig::ReceivedMaxUnidirectionalStreams() const {
  return max_unidirectional_streams_.GetReceivedValue();
}

void QuicConfig::SetMaxAckDelayToSendMs(uint32_t max_ack_delay_ms) {
  max_ack_delay_ms_.SetSendValue(max_ack_delay_ms);
}

uint32_t QuicConfig::GetMaxAckDelayToSendMs() const {
  return max_ack_delay_ms_.GetSendValue();
}

bool QuicConfig::HasReceivedMaxAckDelayMs() const {
  return max_ack_delay_ms_.HasReceivedValue();
}

uint32_t QuicConfig::ReceivedMaxAckDelayMs() const {
  return max_ack_delay_ms_.GetReceivedValue();
}

void QuicConfig::SetMinAckDelayMs(uint32_t min_ack_delay_ms) {
  min_ack_delay_ms_.SetSendValue(min_ack_delay_ms);
}

uint32_t QuicConfig::GetMinAckDelayToSendMs() const {
  return min_ack_delay_ms_.GetSendValue();
}

bool QuicConfig::HasReceivedMinAckDelayMs() const {
  return min_ack_delay_ms_.HasReceivedValue();
}

uint32_t QuicConfig::ReceivedMinAckDelayMs() const {
  return min_ack_delay_ms_.GetReceivedValue();
}

void QuicConfig::SetAckDelayExponentToSend(uint32_t exponent) {
  ack_delay_exponent_.SetSendValue(exponent);
}

uint32_t QuicConfig::GetAckDelayExponentToSend() const {
  return ack_delay_exponent_.GetSendValue();
}

bool QuicConfig::HasReceivedAckDelayExponent() const {
  return ack_delay_exponent_.HasReceivedValue();
}

uint32_t QuicConfig::ReceivedAckDelayExponent() const {
  return ack_delay_exponent_.GetReceivedValue();
}

void QuicConfig::SetMaxPacketSizeToSend(uint64_t max_udp_payload_size) {
  max_udp_payload_size_.SetSendValue(max_udp_payload_size);
}

uint64_t QuicConfig::GetMaxPacketSizeToSend() const {
  return max_udp_payload_size_.GetSendValue();
}

bool QuicConfig::HasReceivedMaxPacketSize() const {
  return max_udp_payload_size_.HasReceivedValue();
}

uint64_t QuicConfig::ReceivedMaxPacketSize() const {
  return max_udp_payload_size_.GetReceivedValue();
}

void QuicConfig::SetMaxDatagramFrameSizeToSend(
    uint64_t max_datagram_frame_size) {
  max_datagram_frame_size_.SetSendValue(max_datagram_frame_size);
}

uint64_t QuicConfig::GetMaxDatagramFrameSizeToSend() const {
  return max_datagram_frame_size_.GetSendValue();
}

bool QuicConfig::HasReceivedMaxDatagramFrameSize() const {
  return max_datagram_frame_size_.HasReceivedValue();
}

uint64_t QuicConfig::ReceivedMaxDatagramFrameSize() const {
  return max_datagram_frame_size_.GetReceivedValue();
}

void QuicConfig::SetActiveConnectionIdLimitToSend(
    uint64_t active_connection_id_limit) {
  active_connection_id_limit_.SetSendValue(active_connection_id_limit);
}

uint64_t QuicConfig::GetActiveConnectionIdLimitToSend() const {
  return active_connection_id_limit_.GetSendValue();
}

bool QuicConfig::HasReceivedActiveConnectionIdLimit() const {
  return active_connection_id_limit_.HasReceivedValue();
}

uint64_t QuicConfig::ReceivedActiveConnectionIdLimit() const {
  return active_connection_id_limit_.GetReceivedValue();
}

bool QuicConfig::HasSetBytesForConnectionIdToSend() const {
  return bytes_for_connection_id_.HasSendValue();
}

void QuicConfig::SetBytesForConnectionIdToSend(uint32_t bytes) {
  bytes_for_connection_id_.SetSendValue(bytes);
}

bool QuicConfig::HasReceivedBytesForConnectionId() const {
  return bytes_for_connection_id_.HasReceivedValue();
}

uint32_t QuicConfig::ReceivedBytesForConnectionId() const {
  return bytes_for_connection_id_.GetReceivedValue();
}

void QuicConfig::SetInitialRoundTripTimeUsToSend(uint64_t rtt) {
  initial_round_trip_time_us_.SetSendValue(rtt);
}

bool QuicConfig::HasReceivedInitialRoundTripTimeUs() const {
  return initial_round_trip_time_us_.HasReceivedValue();
}

uint64_t QuicConfig::ReceivedInitialRoundTripTimeUs() const {
  return initial_round_trip_time_us_.GetReceivedValue();
}

bool QuicConfig::HasInitialRoundTripTimeUsToSend() const {
  return initial_round_trip_time_us_.HasSendValue();
}

uint64_t QuicConfig::GetInitialRoundTripTimeUsToSend() const {
  return initial_round_trip_time_us_.GetSendValue();
}

void QuicConfig::SetInitialStreamFlowControlWindowToSend(
    uint64_t window_bytes) {
  if (window_bytes < kMinimumFlowControlSendWindow) {
    QUIC_BUG(quic_bug_10575_7)
        << "Initial stream flow control receive window (" << window_bytes
        << ") cannot be set lower than minimum ("
        << kMinimumFlowControlSendWindow << ").";
    window_bytes = kMinimumFlowControlSendWindow;
  }
  initial_stream_flow_control_window_bytes_.SetSendValue(window_bytes);
}

uint64_t QuicConfig::GetInitialStreamFlowControlWindowToSend() const {
  return initial_stream_flow_control_window_bytes_.GetSendValue();
}

bool QuicConfig::HasReceivedInitialStreamFlowControlWindowBytes() const {
  return initial_stream_flow_control_window_bytes_.HasReceivedValue();
}

uint64_t QuicConfig::ReceivedInitialStreamFlowControlWindowBytes() const {
  return initial_stream_flow_control_window_bytes_.GetReceivedValue();
}

void QuicConfig::SetInitialMaxStreamDataBytesIncomingBidirectionalToSend(
    uint64_t window_bytes) {
  initial_max_stream_data_bytes_incoming_bidirectional_.SetSendValue(
      window_bytes);
}

uint64_t QuicConfig::GetInitialMaxStreamDataBytesIncomingBidirectionalToSend()
    const {
  if (initial_max_stream_data_bytes_incoming_bidirectional_.HasSendValue()) {
    return initial_max_stream_data_bytes_incoming_bidirectional_.GetSendValue();
  }
  return initial_stream_flow_control_window_bytes_.GetSendValue();
}

bool QuicConfig::HasReceivedInitialMaxStreamDataBytesIncomingBidirectional()
    const {
  return initial_max_stream_data_bytes_incoming_bidirectional_
      .HasReceivedValue();
}

uint64_t QuicConfig::ReceivedInitialMaxStreamDataBytesIncomingBidirectional()
    const {
  return initial_max_stream_data_bytes_incoming_bidirectional_
      .GetReceivedValue();
}

void QuicConfig::SetInitialMaxStreamDataBytesOutgoingBidirectionalToSend(
    uint64_t window_bytes) {
  initial_max_stream_data_bytes_outgoing_bidirectional_.SetSendValue(
      window_bytes);
}

uint64_t QuicConfig::GetInitialMaxStreamDataBytesOutgoingBidirectionalToSend()
    const {
  if (initial_max_stream_data_bytes_outgoing_bidirectional_.HasSendValue()) {
    return initial_max_stream_data_bytes_outgoing_bidirectional_.GetSendValue();
  }
  return initial_stream_flow_control_window_bytes_.GetSendValue();
}

bool QuicConfig::HasReceivedInitialMaxStreamDataBytesOutgoingBidirectional()
    const {
  return initial_max_stream_data_bytes_outgoing_bidirectional_
      .HasReceivedValue();
}

uint64_t QuicConfig::ReceivedInitialMaxStreamDataBytesOutgoingBidirectional()
    const {
  return initial_max_stream_data_bytes_outgoing_bidirectional_
      .GetReceivedValue();
}

void QuicConfig::SetInitialMaxStreamDataBytesUnidirectionalToSend(
    uint64_t window_bytes) {
  initial_max_stream_data_bytes_unidirectional_.SetSendValue(window_bytes);
}

uint64_t QuicConfig::GetInitialMaxStreamDataBytesUnidirectionalToSend() const {
  if (initial_max_stream_data_bytes_unidirectional_.HasSendValue()) {
    return initial_max_stream_data_bytes_unidirectional_.GetSendValue();
  }
  return initial_stream_flow_control_window_bytes_.GetSendValue();
}

bool QuicConfig::HasReceivedInitialMaxStreamDataBytesUnidirectional() const {
  return initial_max_stream_data_bytes_unidirectional_.HasReceivedValue();
}

uint64_t QuicConfig::ReceivedInitialMaxStreamDataBytesUnidirectional() const {
  return initial_max_stream_data_bytes_unidirectional_.GetReceivedValue();
}

void QuicConfig::SetInitialSessionFlowControlWindowToSend(
    uint64_t window_bytes) {
  if (window_bytes < kMinimumFlowControlSendWindow) {
    QUIC_BUG(quic_bug_10575_8)
        << "Initial session flow control receive window (" << window_bytes
        << ") cannot be set lower than default ("
        << kMinimumFlowControlSendWindow << ").";
    window_bytes = kMinimumFlowControlSendWindow;
  }
  initial_session_flow_control_window_bytes_.SetSendValue(window_bytes);
}

uint64_t QuicConfig::GetInitialSessionFlowControlWindowToSend() const {
  return initial_session_flow_control_window_bytes_.GetSendValue();
}

bool QuicConfig::HasReceivedInitialSessionFlowControlWindowBytes() const {
  return initial_session_flow_control_window_bytes_.HasReceivedValue();
}

uint64_t QuicConfig::ReceivedInitialSessionFlowControlWindowBytes() const {
  return initial_session_flow_control_window_bytes_.GetReceivedValue();
}

void QuicConfig::SetDisableConnectionMigration() {
  connection_migration_disabled_.SetSendValue(1);
}

bool QuicConfig::DisableConnectionMigration() const {
  return connection_migration_disabled_.HasReceivedValue();
}

void QuicConfig::SetIPv6AlternateServerAddressToSend(
    const QuicSocketAddress& alternate_server_address_ipv6) {
  if (!alternate_server_address_ipv6.Normalized().host().IsIPv6()) {
    QUIC_BUG(quic_bug_10575_9)
        << "Cannot use SetIPv6AlternateServerAddressToSend with "
        << alternate_server_address_ipv6;
    return;
  }
  alternate_server_address_ipv6_.SetSendValue(alternate_server_address_ipv6);
}

bool QuicConfig::HasReceivedIPv6AlternateServerAddress() const {
  return alternate_server_address_ipv6_.HasReceivedValue();
}

const QuicSocketAddress& QuicConfig::ReceivedIPv6AlternateServerAddress()
    const {
  return alternate_server_address_ipv6_.GetReceivedValue();
}

void QuicConfig::SetIPv4AlternateServerAddressToSend(
    const QuicSocketAddress& alternate_server_address_ipv4) {
  if (!alternate_server_address_ipv4.host().IsIPv4()) {
    QUIC_BUG(quic_bug_10575_11)
        << "Cannot use SetIPv4AlternateServerAddressToSend with "
        << alternate_server_address_ipv4;
    return;
  }
  alternate_server_address_ipv4_.SetSendValue(alternate_server_address_ipv4);
}

bool QuicConfig::HasReceivedIPv4AlternateServerAddress() const {
  return alternate_server_address_ipv4_.HasReceivedValue();
}

const QuicSocketAddress& QuicConfig::ReceivedIPv4AlternateServerAddress()
    const {
  return alternate_server_address_ipv4_.GetReceivedValue();
}

void QuicConfig::SetPreferredAddressConnectionIdAndTokenToSend(
    const QuicConnectionId& connection_id,
    const StatelessResetToken& stateless_reset_token) {
  if ((!alternate_server_address_ipv4_.HasSendValue() &&
       !alternate_server_address_ipv6_.HasSendValue()) ||
      preferred_address_connection_id_and_token_.has_value()) {
    QUIC_BUG(quic_bug_10575_17)
        << "Can not send connection ID and token for preferred address";
    return;
  }
  preferred_address_connection_id_and_token_ =
      std::make_pair(connection_id, stateless_reset_token);
}

bool QuicConfig::HasReceivedPreferredAddressConnectionIdAndToken() const {
  return (HasReceivedIPv6AlternateServerAddress() ||
          HasReceivedIPv4AlternateServerAddress()) &&
         preferred_address_connection_id_and_token_.has_value();
}

const std::pair<QuicConnectionId, StatelessResetToken>&
QuicConfig::ReceivedPreferredAddressConnectionIdAndToken() const {
  QUICHE_DCHECK(HasReceivedPreferredAddressConnectionIdAndToken());
  return *preferred_address_connection_id_and_token_;
}

void QuicConfig::SetOriginalConnectionIdToSend(
    const QuicConnectionId& original_destination_connection_id) {
  original_destination_connection_id_to_send_ =
      original_destination_connection_id;
}

bool QuicConfig::HasReceivedOriginalConnectionId() const {
  return received_original_destination_connection_id_.has_value();
}

QuicConnectionId QuicConfig::ReceivedOriginalConnectionId() const {
  if (!HasReceivedOriginalConnectionId()) {
    QUIC_BUG(quic_bug_10575_13) << "No received original connection ID";
    return EmptyQuicConnectionId();
  }
  return *received_original_destination_connection_id_;
}

void QuicConfig::SetInitialSourceConnectionIdToSend(
    const QuicConnectionId& initial_source_connection_id) {
  initial_source_connection_id_to_send_ = initial_source_connection_id;
}

bool QuicConfig::HasReceivedInitialSourceConnectionId() const {
  return received_initial_source_connection_id_.has_value();
}

QuicConnectionId QuicConfig::ReceivedInitialSourceConnectionId() const {
  if (!HasReceivedInitialSourceConnectionId()) {
    QUIC_BUG(quic_bug_10575_14) << "No received initial source connection ID";
    return EmptyQuicConnectionId();
  }
  return *received_initial_source_connection_id_;
}

void QuicConfig::SetRetrySourceConnectionIdToSend(
    const QuicConnectionId& retry_source_connection_id) {
  retry_source_connection_id_to_se
```