Response:
The user wants a summary of the functionality of the C++ source code file `transport_parameters.cc`. I need to identify the key responsibilities of this file. Specifically, I should look for:

1. **Data Structures:**  What kind of data is being managed?  The file name hints at "transport parameters".
2. **Encoding/Decoding:** How are these parameters represented in a binary format for transmission? Look for `Write` and `Read` operations.
3. **Validation:** How are the parameters checked for correctness? Look for `IsValid` functions.
4. **Relationship to JavaScript:** Does this file expose any functionality that directly interacts with JavaScript? This is unlikely given it's a core networking component.
5. **Logic and Assumptions:** Are there any logical operations or decisions being made based on the parameters? Look for conditional statements and default values.
6. **Potential User Errors:** What mistakes could developers or users make when using this code?
7. **Debugging Context:** How would a user end up interacting with this code?  What user actions would lead to these parameters being used?

**High-Level Plan:**

1. Analyze the included headers to understand the dependencies.
2. Examine the `TransportParameters` class definition and its members.
3. Identify the methods responsible for serialization, deserialization, and validation.
4. Look for specific parameter IDs and their associated data types.
5. Address the JavaScript interaction question (likely negative).
6. Formulate assumptions for input/output examples related to serialization/deserialization.
7. Identify common usage errors, especially around setting invalid parameter values.
8. Describe a typical user interaction flow that involves transport parameters.
9. Summarize the overall functionality for part 1.
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/transport_parameters.cc的chromium 网络栈的源代码文件， 请列举一下它的功能,
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

**该文件的功能：**

该 C++ 文件 `transport_parameters.cc` 定义了 QUIC 协议中传输参数的结构和处理逻辑。其核心功能可以归纳为以下几点：

1. **定义传输参数的结构：**  它定义了 `TransportParameters` 类，该类包含了 QUIC 连接建立时协商的各种参数，例如：
    * 连接ID (`original_destination_connection_id`, `initial_source_connection_id`, `retry_source_connection_id`)
    * 超时设置 (`max_idle_timeout_ms`)
    * 最大数据量 (`initial_max_data`, `initial_max_stream_data_bidi_local`, `initial_max_stream_data_bidi_remote`, `initial_max_stream_data_uni`)
    * 最大流数量 (`initial_max_streams_bidi`, `initial_max_streams_uni`)
    * ACK 延迟相关参数 (`ack_delay_exponent`, `max_ack_delay`, `min_ack_delay_us`)
    * 是否禁用主动迁移 (`disable_active_migration`)
    * 首选地址 (`preferred_address`)
    * 活动连接ID限制 (`active_connection_id_limit`)
    * 最大数据报帧大小 (`max_datagram_frame_size`)
    * 丢弃参数 (`discard`)
    * Google 握手消息 (`google_handshake_message`)
    * 初始往返时间 (`initial_round_trip_time_us`)
    * Google 连接选项 (`google_connection_options`)
    * QUIC 版本信息 (`version_information`, `legacy_version_information`)
    * 可靠流重置 (`reliable_stream_reset`)
    * 自定义参数 (`custom_parameters`)

2. **传输参数的编码和解码：** 提供了将 `TransportParameters` 对象序列化为字节流 (用于网络传输) 以及从字节流反序列化为 `TransportParameters` 对象的功能。这通过 `SerializeTransportParameters` 和 `ParseTransportParameters` 函数（在后续部分）实现。

3. **传输参数的验证：**  定义了 `AreValid` 方法，用于检查 `TransportParameters` 对象中的参数是否有效，例如，检查参数值是否在允许的范围内，以及客户端和服务器发送的参数是否符合协议规范。

4. **辅助功能：** 提供了将传输参数 ID 转换为字符串表示 (`TransportParameterIdToString`) 以及判断参数 ID 是否已知 (`TransportParameterIdIsKnown`) 的辅助函数，主要用于调试和日志记录。

**与 JavaScript 的关系：**

该文件是 Chromium 网络栈的 C++ 代码，直接与 JavaScript 没有直接关系。JavaScript 在浏览器中通过 Web API (如 `fetch`, `XMLHttpRequest`, `WebSockets`) 与网络进行交互。当 JavaScript 发起一个使用 QUIC 协议的网络请求时，底层的 Chromium 网络栈会处理 QUIC 连接的建立和管理，其中包括使用这里的 `TransportParameters` 来协商连接参数。

**举例说明:**

假设一个网页使用 `fetch` API 发起一个 HTTPS 请求，底层使用了 QUIC 协议。

* **JavaScript 操作:**
  ```javascript
  fetch('https://example.com/data')
    .then(response => response.text())
    .then(data => console.log(data));
  ```

* **底层过程:**
    1. 当浏览器与 `example.com` 服务器建立 QUIC 连接时，客户端和服务器会交换包含传输参数的 Handshake 消息。
    2. `transport_parameters.cc` 文件中的代码负责编码客户端提议的传输参数，并解码服务器返回的传输参数。
    3. 例如，JavaScript 并不知道 `initial_max_data` 的值，但底层的 C++ 代码会处理这个参数的协商。客户端可能会建议一个值，服务器可能会接受或提出一个不同的值。
    4. 协商成功后，连接的后续数据传输会受到这些协商好的参数的约束。例如，`initial_max_data` 限制了客户端或服务器在收到确认之前可以发送的数据量。

**逻辑推理：**

**假设输入 (客户端提议的传输参数):**

* `max_idle_timeout_ms`: 30000 (30 秒)
* `initial_max_data`: 1048576 (1MB)
* `initial_max_streams_bidi`: 100

**预期输出 (序列化后的字节流片段，仅为示例，实际编码更复杂):**

`01 02 75 30 04 03 10 00 00 08 01 64`

* `01`: `kMaxIdleTimeout` 的参数 ID
* `02`: `max_idle_timeout_ms` 值的长度 (2 字节)
* `75 30`: `30000` 的 VarInt 编码
* `04`: `kInitialMaxData` 的参数 ID
* `03`: `initial_max_data` 值的长度 (3 字节)
* `10 00 00`: `1048576` 的 VarInt 编码
* `08`: `kInitialMaxStreamsBidi` 的参数 ID
* `01`: `initial_max_streams_bidi` 值的长度 (1 字节)
* `64`: `100` 的 VarInt 编码

**用户或编程常见的使用错误：**

1. **设置超出范围的参数值：** 例如，尝试将 `max_udp_payload_size` 设置为小于 `kMinMaxPacketSizeTransportParam` (1200) 的值。`AreValid` 方法会检测到这个错误。

   ```c++
   TransportParameters params;
   params.max_udp_payload_size.set_value(1000);
   std::string error_details;
   if (!params.AreValid(&error_details)) {
     // error_details 将包含 "Invalid transport parameters ..."
   }
   ```

2. **客户端发送服务器专属参数：**  例如，客户端尝试设置 `stateless_reset_token`。`AreValid` 方法会报告此错误。

   ```c++
   TransportParameters client_params;
   client_params.perspective = Perspective::IS_CLIENT;
   client_params.stateless_reset_token = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
   std::string error_details;
   if (!client_params.AreValid(&error_details)) {
     // error_details 将包含 "Client cannot send stateless reset token"
   }
   ```

3. **自定义参数 ID 与已知参数冲突：**  开发者尝试使用一个已定义的传输参数 ID 作为自定义参数的 ID。

   ```c++
   TransportParameters params;
   params.custom_parameters[TransportParameters::kMaxIdleTimeout] = "some value";
   std::string error_details;
   if (!params.AreValid(&error_details)) {
     // error_details 将包含 "Using custom_parameters with known ID ..."
   }
   ```

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器中输入网址或点击链接:** 例如，用户访问 `https://example.com`。
2. **浏览器尝试与服务器建立连接:** 浏览器会根据协议和缓存信息决定是否需要建立新的 QUIC 连接。
3. **QUIC 连接握手开始:** 如果决定建立 QUIC 连接，客户端会发送一个 `ClientHello` 消息，其中包含客户端提议的传输参数。
4. **`TransportParameters` 对象被创建并填充:** Chromium 网络栈的代码会创建一个 `TransportParameters` 对象，并根据客户端的配置和默认值填充相应的参数。
5. **`SerializeTransportParameters` 被调用:**  该函数会将 `TransportParameters` 对象编码成字节流，以便发送给服务器。
6. **服务器收到 `ClientHello` 并解析传输参数:** 服务器端的 QUIC 实现会接收到字节流，并使用相应的解码逻辑 (在服务器端的 `transport_parameters.cc` 或类似文件中) 将其解析回 `TransportParameters` 对象。
7. **服务器发送 `ServerHello` 消息:**  服务器会根据自己的配置和客户端的提议，生成包含服务器传输参数的 `ServerHello` 消息。
8. **客户端收到 `ServerHello` 并解析传输参数:** 客户端的 QUIC 实现会解码服务器返回的传输参数。
9. **在调试过程中，开发者可能会在以下位置设置断点来检查 `transport_parameters.cc` 的行为:**
    * `SerializeTransportParameters` 函数：查看客户端发送的传输参数。
    * `ParseTransportParameters` 函数 (在后续部分)：查看客户端或服务器接收到的传输参数。
    * `TransportParameters::AreValid` 函数：检查传输参数的有效性。
    * `TransportParameters` 类的构造函数或成员设置函数：查看参数的初始值或被修改的值。

**归纳一下它的功能 (第 1 部分):**

该文件的主要功能是**定义和管理 QUIC 协议中使用的传输参数**。它提供了存储、编码、解码和验证这些参数的结构和方法，是 QUIC 连接建立和运行的关键组成部分。它定义了哪些参数可以协商，它们的类型、默认值和有效范围，并确保在连接建立时双方对这些参数达成一致。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/transport_parameters.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/transport_parameters.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <forward_list>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/digest.h"
#include "openssl/sha.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_ip_address.h"

namespace quic {

// Values of the TransportParameterId enum as defined in the
// "Transport Parameter Encoding" section of draft-ietf-quic-transport.
// When parameters are encoded, one of these enum values is used to indicate
// which parameter is encoded. The supported draft version is noted in
// transport_parameters.h.
enum TransportParameters::TransportParameterId : uint64_t {
  kOriginalDestinationConnectionId = 0,
  kMaxIdleTimeout = 1,
  kStatelessResetToken = 2,
  kMaxPacketSize = 3,
  kInitialMaxData = 4,
  kInitialMaxStreamDataBidiLocal = 5,
  kInitialMaxStreamDataBidiRemote = 6,
  kInitialMaxStreamDataUni = 7,
  kInitialMaxStreamsBidi = 8,
  kInitialMaxStreamsUni = 9,
  kAckDelayExponent = 0xa,
  kMaxAckDelay = 0xb,
  kDisableActiveMigration = 0xc,
  kPreferredAddress = 0xd,
  kActiveConnectionIdLimit = 0xe,
  kInitialSourceConnectionId = 0xf,
  kRetrySourceConnectionId = 0x10,

  kMaxDatagramFrameSize = 0x20,

  // https://github.com/quicwg/base-drafts/wiki/Quantum-Readiness-test
  kDiscard = 0x173E,

  kGoogleHandshakeMessage = 0x26ab,

  kInitialRoundTripTime = 0x3127,
  kGoogleConnectionOptions = 0x3128,
  // 0x3129 was used to convey the user agent string.
  // 0x312A was used only in T050 to indicate support for HANDSHAKE_DONE.
  // 0x312B was used to indicate that QUIC+TLS key updates were not supported.
  // 0x4751 was used for non-standard Google-specific parameters encoded as a
  // Google QUIC_CRYPTO CHLO, it has been replaced by individual parameters.
  kGoogleQuicVersion =
      0x4752,  // Used to transmit version and supported_versions.

  kMinAckDelay = 0xDE1A,           // draft-iyengar-quic-delayed-ack.
  kVersionInformation = 0xFF73DB,  // draft-ietf-quic-version-negotiation.

  // draft-ietf-quic-reliable-stream-reset.
  kReliableStreamReset = 0x17F7586D2CB571,
};

namespace {

constexpr QuicVersionLabel kReservedVersionMask = 0x0f0f0f0f;
constexpr QuicVersionLabel kReservedVersionBits = 0x0a0a0a0a;

// The following constants define minimum and maximum allowed values for some of
// the parameters. These come from the "Transport Parameter Definitions"
// section of draft-ietf-quic-transport.
constexpr uint64_t kMinMaxPacketSizeTransportParam = 1200;
constexpr uint64_t kMaxAckDelayExponentTransportParam = 20;
constexpr uint64_t kDefaultAckDelayExponentTransportParam = 3;
constexpr uint64_t kMaxMaxAckDelayTransportParam = 16383;
constexpr uint64_t kDefaultMaxAckDelayTransportParam = 25;
constexpr uint64_t kMinActiveConnectionIdLimitTransportParam = 2;
constexpr uint64_t kDefaultActiveConnectionIdLimitTransportParam = 2;

std::string TransportParameterIdToString(
    TransportParameters::TransportParameterId param_id) {
  switch (param_id) {
    case TransportParameters::kOriginalDestinationConnectionId:
      return "original_destination_connection_id";
    case TransportParameters::kMaxIdleTimeout:
      return "max_idle_timeout";
    case TransportParameters::kStatelessResetToken:
      return "stateless_reset_token";
    case TransportParameters::kMaxPacketSize:
      return "max_udp_payload_size";
    case TransportParameters::kInitialMaxData:
      return "initial_max_data";
    case TransportParameters::kInitialMaxStreamDataBidiLocal:
      return "initial_max_stream_data_bidi_local";
    case TransportParameters::kInitialMaxStreamDataBidiRemote:
      return "initial_max_stream_data_bidi_remote";
    case TransportParameters::kInitialMaxStreamDataUni:
      return "initial_max_stream_data_uni";
    case TransportParameters::kInitialMaxStreamsBidi:
      return "initial_max_streams_bidi";
    case TransportParameters::kInitialMaxStreamsUni:
      return "initial_max_streams_uni";
    case TransportParameters::kAckDelayExponent:
      return "ack_delay_exponent";
    case TransportParameters::kMaxAckDelay:
      return "max_ack_delay";
    case TransportParameters::kDisableActiveMigration:
      return "disable_active_migration";
    case TransportParameters::kPreferredAddress:
      return "preferred_address";
    case TransportParameters::kActiveConnectionIdLimit:
      return "active_connection_id_limit";
    case TransportParameters::kInitialSourceConnectionId:
      return "initial_source_connection_id";
    case TransportParameters::kRetrySourceConnectionId:
      return "retry_source_connection_id";
    case TransportParameters::kMaxDatagramFrameSize:
      return "max_datagram_frame_size";
    case TransportParameters::kDiscard:
      return "discard";
    case TransportParameters::kGoogleHandshakeMessage:
      return "google_handshake_message";
    case TransportParameters::kInitialRoundTripTime:
      return "initial_round_trip_time";
    case TransportParameters::kGoogleConnectionOptions:
      return "google_connection_options";
    case TransportParameters::kGoogleQuicVersion:
      return "google-version";
    case TransportParameters::kMinAckDelay:
      return "min_ack_delay_us";
    case TransportParameters::kVersionInformation:
      return "version_information";
    case TransportParameters::kReliableStreamReset:
      return "reliable_stream_reset";
  }
  return absl::StrCat("Unknown(", param_id, ")");
}

bool TransportParameterIdIsKnown(
    TransportParameters::TransportParameterId param_id) {
  switch (param_id) {
    case TransportParameters::kOriginalDestinationConnectionId:
    case TransportParameters::kMaxIdleTimeout:
    case TransportParameters::kStatelessResetToken:
    case TransportParameters::kMaxPacketSize:
    case TransportParameters::kInitialMaxData:
    case TransportParameters::kInitialMaxStreamDataBidiLocal:
    case TransportParameters::kInitialMaxStreamDataBidiRemote:
    case TransportParameters::kInitialMaxStreamDataUni:
    case TransportParameters::kInitialMaxStreamsBidi:
    case TransportParameters::kInitialMaxStreamsUni:
    case TransportParameters::kAckDelayExponent:
    case TransportParameters::kMaxAckDelay:
    case TransportParameters::kDisableActiveMigration:
    case TransportParameters::kPreferredAddress:
    case TransportParameters::kActiveConnectionIdLimit:
    case TransportParameters::kInitialSourceConnectionId:
    case TransportParameters::kRetrySourceConnectionId:
    case TransportParameters::kMaxDatagramFrameSize:
    case TransportParameters::kDiscard:
    case TransportParameters::kGoogleHandshakeMessage:
    case TransportParameters::kInitialRoundTripTime:
    case TransportParameters::kGoogleConnectionOptions:
    case TransportParameters::kGoogleQuicVersion:
    case TransportParameters::kMinAckDelay:
    case TransportParameters::kVersionInformation:
    case TransportParameters::kReliableStreamReset:
      return true;
  }
  return false;
}

}  // namespace

TransportParameters::IntegerParameter::IntegerParameter(
    TransportParameters::TransportParameterId param_id, uint64_t default_value,
    uint64_t min_value, uint64_t max_value)
    : param_id_(param_id),
      value_(default_value),
      default_value_(default_value),
      min_value_(min_value),
      max_value_(max_value),
      has_been_read_(false) {
  QUICHE_DCHECK_LE(min_value, default_value);
  QUICHE_DCHECK_LE(default_value, max_value);
  QUICHE_DCHECK_LE(max_value, quiche::kVarInt62MaxValue);
}

TransportParameters::IntegerParameter::IntegerParameter(
    TransportParameters::TransportParameterId param_id)
    : TransportParameters::IntegerParameter::IntegerParameter(
          param_id, 0, 0, quiche::kVarInt62MaxValue) {}

void TransportParameters::IntegerParameter::set_value(uint64_t value) {
  value_ = value;
}

uint64_t TransportParameters::IntegerParameter::value() const { return value_; }

bool TransportParameters::IntegerParameter::IsValid() const {
  return min_value_ <= value_ && value_ <= max_value_;
}

bool TransportParameters::IntegerParameter::Write(
    QuicDataWriter* writer) const {
  QUICHE_DCHECK(IsValid());
  if (value_ == default_value_) {
    // Do not write if the value is default.
    return true;
  }
  if (!writer->WriteVarInt62(param_id_)) {
    QUIC_BUG(quic_bug_10743_1) << "Failed to write param_id for " << *this;
    return false;
  }
  const quiche::QuicheVariableLengthIntegerLength value_length =
      QuicDataWriter::GetVarInt62Len(value_);
  if (!writer->WriteVarInt62(value_length)) {
    QUIC_BUG(quic_bug_10743_2) << "Failed to write value_length for " << *this;
    return false;
  }
  if (!writer->WriteVarInt62WithForcedLength(value_, value_length)) {
    QUIC_BUG(quic_bug_10743_3) << "Failed to write value for " << *this;
    return false;
  }
  return true;
}

bool TransportParameters::IntegerParameter::Read(QuicDataReader* reader,
                                                 std::string* error_details) {
  if (has_been_read_) {
    *error_details =
        "Received a second " + TransportParameterIdToString(param_id_);
    return false;
  }
  has_been_read_ = true;

  if (!reader->ReadVarInt62(&value_)) {
    *error_details =
        "Failed to parse value for " + TransportParameterIdToString(param_id_);
    return false;
  }
  if (!reader->IsDoneReading()) {
    *error_details =
        absl::StrCat("Received unexpected ", reader->BytesRemaining(),
                     " bytes after parsing ", this->ToString(false));
    return false;
  }
  return true;
}

std::string TransportParameters::IntegerParameter::ToString(
    bool for_use_in_list) const {
  if (for_use_in_list && value_ == default_value_) {
    return "";
  }
  std::string rv = for_use_in_list ? " " : "";
  absl::StrAppend(&rv, TransportParameterIdToString(param_id_), " ", value_);
  if (!IsValid()) {
    rv += " (Invalid)";
  }
  return rv;
}

std::ostream& operator<<(std::ostream& os,
                         const TransportParameters::IntegerParameter& param) {
  os << param.ToString(/*for_use_in_list=*/false);
  return os;
}

TransportParameters::PreferredAddress::PreferredAddress()
    : ipv4_socket_address(QuicIpAddress::Any4(), 0),
      ipv6_socket_address(QuicIpAddress::Any6(), 0),
      connection_id(EmptyQuicConnectionId()),
      stateless_reset_token(kStatelessResetTokenLength, 0) {}

TransportParameters::PreferredAddress::~PreferredAddress() {}

bool TransportParameters::PreferredAddress::operator==(
    const PreferredAddress& rhs) const {
  return ipv4_socket_address == rhs.ipv4_socket_address &&
         ipv6_socket_address == rhs.ipv6_socket_address &&
         connection_id == rhs.connection_id &&
         stateless_reset_token == rhs.stateless_reset_token;
}

bool TransportParameters::PreferredAddress::operator!=(
    const PreferredAddress& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(
    std::ostream& os,
    const TransportParameters::PreferredAddress& preferred_address) {
  os << preferred_address.ToString();
  return os;
}

std::string TransportParameters::PreferredAddress::ToString() const {
  return "[" + ipv4_socket_address.ToString() + " " +
         ipv6_socket_address.ToString() + " connection_id " +
         connection_id.ToString() + " stateless_reset_token " +
         absl::BytesToHexString(absl::string_view(
             reinterpret_cast<const char*>(stateless_reset_token.data()),
             stateless_reset_token.size())) +
         "]";
}

TransportParameters::LegacyVersionInformation::LegacyVersionInformation()
    : version(0) {}

bool TransportParameters::LegacyVersionInformation::operator==(
    const LegacyVersionInformation& rhs) const {
  return version == rhs.version && supported_versions == rhs.supported_versions;
}

bool TransportParameters::LegacyVersionInformation::operator!=(
    const LegacyVersionInformation& rhs) const {
  return !(*this == rhs);
}

std::string TransportParameters::LegacyVersionInformation::ToString() const {
  std::string rv =
      absl::StrCat("legacy[version ", QuicVersionLabelToString(version));
  if (!supported_versions.empty()) {
    absl::StrAppend(&rv,
                    " supported_versions " +
                        QuicVersionLabelVectorToString(supported_versions));
  }
  absl::StrAppend(&rv, "]");
  return rv;
}

std::ostream& operator<<(std::ostream& os,
                         const TransportParameters::LegacyVersionInformation&
                             legacy_version_information) {
  os << legacy_version_information.ToString();
  return os;
}

TransportParameters::VersionInformation::VersionInformation()
    : chosen_version(0) {}

bool TransportParameters::VersionInformation::operator==(
    const VersionInformation& rhs) const {
  return chosen_version == rhs.chosen_version &&
         other_versions == rhs.other_versions;
}

bool TransportParameters::VersionInformation::operator!=(
    const VersionInformation& rhs) const {
  return !(*this == rhs);
}

std::string TransportParameters::VersionInformation::ToString() const {
  std::string rv = absl::StrCat("[chosen_version ",
                                QuicVersionLabelToString(chosen_version));
  if (!other_versions.empty()) {
    absl::StrAppend(&rv, " other_versions " +
                             QuicVersionLabelVectorToString(other_versions));
  }
  absl::StrAppend(&rv, "]");
  return rv;
}

std::ostream& operator<<(
    std::ostream& os,
    const TransportParameters::VersionInformation& version_information) {
  os << version_information.ToString();
  return os;
}

std::ostream& operator<<(std::ostream& os, const TransportParameters& params) {
  os << params.ToString();
  return os;
}

std::string TransportParameters::ToString() const {
  std::string rv = "[";
  if (perspective == Perspective::IS_SERVER) {
    rv += "Server";
  } else {
    rv += "Client";
  }
  if (legacy_version_information.has_value()) {
    rv += " " + legacy_version_information->ToString();
  }
  if (version_information.has_value()) {
    rv += " " + version_information->ToString();
  }
  if (original_destination_connection_id.has_value()) {
    rv += " " + TransportParameterIdToString(kOriginalDestinationConnectionId) +
          " " + original_destination_connection_id->ToString();
  }
  rv += max_idle_timeout_ms.ToString(/*for_use_in_list=*/true);
  if (!stateless_reset_token.empty()) {
    rv += " " + TransportParameterIdToString(kStatelessResetToken) + " " +
          absl::BytesToHexString(absl::string_view(
              reinterpret_cast<const char*>(stateless_reset_token.data()),
              stateless_reset_token.size()));
  }
  rv += max_udp_payload_size.ToString(/*for_use_in_list=*/true);
  rv += initial_max_data.ToString(/*for_use_in_list=*/true);
  rv += initial_max_stream_data_bidi_local.ToString(/*for_use_in_list=*/true);
  rv += initial_max_stream_data_bidi_remote.ToString(/*for_use_in_list=*/true);
  rv += initial_max_stream_data_uni.ToString(/*for_use_in_list=*/true);
  rv += initial_max_streams_bidi.ToString(/*for_use_in_list=*/true);
  rv += initial_max_streams_uni.ToString(/*for_use_in_list=*/true);
  rv += ack_delay_exponent.ToString(/*for_use_in_list=*/true);
  rv += max_ack_delay.ToString(/*for_use_in_list=*/true);
  rv += min_ack_delay_us.ToString(/*for_use_in_list=*/true);
  if (disable_active_migration) {
    rv += " " + TransportParameterIdToString(kDisableActiveMigration);
  }
  if (reliable_stream_reset) {
    rv += " " + TransportParameterIdToString(kReliableStreamReset);
  }
  if (preferred_address) {
    rv += " " + TransportParameterIdToString(kPreferredAddress) + " " +
          preferred_address->ToString();
  }
  rv += active_connection_id_limit.ToString(/*for_use_in_list=*/true);
  if (initial_source_connection_id.has_value()) {
    rv += " " + TransportParameterIdToString(kInitialSourceConnectionId) + " " +
          initial_source_connection_id->ToString();
  }
  if (retry_source_connection_id.has_value()) {
    rv += " " + TransportParameterIdToString(kRetrySourceConnectionId) + " " +
          retry_source_connection_id->ToString();
  }
  rv += max_datagram_frame_size.ToString(/*for_use_in_list=*/true);
  if (discard_length >= 0) {
    absl::StrAppend(&rv, " ", TransportParameterIdToString(kDiscard),
                    " length: ", discard_length);
  }
  if (google_handshake_message.has_value()) {
    absl::StrAppend(&rv, " ",
                    TransportParameterIdToString(kGoogleHandshakeMessage),
                    " length: ", google_handshake_message->length());
  }
  rv += initial_round_trip_time_us.ToString(/*for_use_in_list=*/true);
  if (google_connection_options.has_value()) {
    rv += " " + TransportParameterIdToString(kGoogleConnectionOptions) + " ";
    bool first = true;
    for (const QuicTag& connection_option : *google_connection_options) {
      if (first) {
        first = false;
      } else {
        rv += ",";
      }
      rv += QuicTagToString(connection_option);
    }
  }
  for (const auto& kv : custom_parameters) {
    absl::StrAppend(&rv, " 0x", absl::Hex(static_cast<uint32_t>(kv.first)),
                    "=");
    static constexpr size_t kMaxPrintableLength = 32;
    if (kv.second.length() <= kMaxPrintableLength) {
      rv += absl::BytesToHexString(kv.second);
    } else {
      absl::string_view truncated(kv.second.data(), kMaxPrintableLength);
      rv += absl::StrCat(absl::BytesToHexString(truncated), "...(length ",
                         kv.second.length(), ")");
    }
  }
  rv += "]";
  return rv;
}

TransportParameters::TransportParameters()
    : max_idle_timeout_ms(kMaxIdleTimeout),
      max_udp_payload_size(kMaxPacketSize, kDefaultMaxPacketSizeTransportParam,
                           kMinMaxPacketSizeTransportParam,
                           quiche::kVarInt62MaxValue),
      initial_max_data(kInitialMaxData),
      initial_max_stream_data_bidi_local(kInitialMaxStreamDataBidiLocal),
      initial_max_stream_data_bidi_remote(kInitialMaxStreamDataBidiRemote),
      initial_max_stream_data_uni(kInitialMaxStreamDataUni),
      initial_max_streams_bidi(kInitialMaxStreamsBidi),
      initial_max_streams_uni(kInitialMaxStreamsUni),
      ack_delay_exponent(kAckDelayExponent,
                         kDefaultAckDelayExponentTransportParam, 0,
                         kMaxAckDelayExponentTransportParam),
      max_ack_delay(kMaxAckDelay, kDefaultMaxAckDelayTransportParam, 0,
                    kMaxMaxAckDelayTransportParam),
      min_ack_delay_us(kMinAckDelay, 0, 0,
                       kMaxMaxAckDelayTransportParam * kNumMicrosPerMilli),
      disable_active_migration(false),
      active_connection_id_limit(kActiveConnectionIdLimit,
                                 kDefaultActiveConnectionIdLimitTransportParam,
                                 kMinActiveConnectionIdLimitTransportParam,
                                 quiche::kVarInt62MaxValue),
      max_datagram_frame_size(kMaxDatagramFrameSize),
      reliable_stream_reset(false),
      initial_round_trip_time_us(kInitialRoundTripTime)
// Important note: any new transport parameters must be added
// to TransportParameters::AreValid, SerializeTransportParameters and
// ParseTransportParameters, TransportParameters's custom copy constructor, the
// operator==, and TransportParametersTest.Comparator.
{}

TransportParameters::TransportParameters(const TransportParameters& other)
    : perspective(other.perspective),
      legacy_version_information(other.legacy_version_information),
      version_information(other.version_information),
      original_destination_connection_id(
          other.original_destination_connection_id),
      max_idle_timeout_ms(other.max_idle_timeout_ms),
      stateless_reset_token(other.stateless_reset_token),
      max_udp_payload_size(other.max_udp_payload_size),
      initial_max_data(other.initial_max_data),
      initial_max_stream_data_bidi_local(
          other.initial_max_stream_data_bidi_local),
      initial_max_stream_data_bidi_remote(
          other.initial_max_stream_data_bidi_remote),
      initial_max_stream_data_uni(other.initial_max_stream_data_uni),
      initial_max_streams_bidi(other.initial_max_streams_bidi),
      initial_max_streams_uni(other.initial_max_streams_uni),
      ack_delay_exponent(other.ack_delay_exponent),
      max_ack_delay(other.max_ack_delay),
      min_ack_delay_us(other.min_ack_delay_us),
      disable_active_migration(other.disable_active_migration),
      active_connection_id_limit(other.active_connection_id_limit),
      initial_source_connection_id(other.initial_source_connection_id),
      retry_source_connection_id(other.retry_source_connection_id),
      max_datagram_frame_size(other.max_datagram_frame_size),
      reliable_stream_reset(other.reliable_stream_reset),
      initial_round_trip_time_us(other.initial_round_trip_time_us),
      discard_length(other.discard_length),
      google_handshake_message(other.google_handshake_message),
      google_connection_options(other.google_connection_options),
      custom_parameters(other.custom_parameters) {
  if (other.preferred_address) {
    preferred_address = std::make_unique<TransportParameters::PreferredAddress>(
        *other.preferred_address);
  }
}

bool TransportParameters::operator==(const TransportParameters& rhs) const {
  if (!(perspective == rhs.perspective &&
        legacy_version_information == rhs.legacy_version_information &&
        version_information == rhs.version_information &&
        original_destination_connection_id ==
            rhs.original_destination_connection_id &&
        max_idle_timeout_ms.value() == rhs.max_idle_timeout_ms.value() &&
        stateless_reset_token == rhs.stateless_reset_token &&
        max_udp_payload_size.value() == rhs.max_udp_payload_size.value() &&
        initial_max_data.value() == rhs.initial_max_data.value() &&
        initial_max_stream_data_bidi_local.value() ==
            rhs.initial_max_stream_data_bidi_local.value() &&
        initial_max_stream_data_bidi_remote.value() ==
            rhs.initial_max_stream_data_bidi_remote.value() &&
        initial_max_stream_data_uni.value() ==
            rhs.initial_max_stream_data_uni.value() &&
        initial_max_streams_bidi.value() ==
            rhs.initial_max_streams_bidi.value() &&
        initial_max_streams_uni.value() ==
            rhs.initial_max_streams_uni.value() &&
        ack_delay_exponent.value() == rhs.ack_delay_exponent.value() &&
        max_ack_delay.value() == rhs.max_ack_delay.value() &&
        min_ack_delay_us.value() == rhs.min_ack_delay_us.value() &&
        disable_active_migration == rhs.disable_active_migration &&
        active_connection_id_limit.value() ==
            rhs.active_connection_id_limit.value() &&
        initial_source_connection_id == rhs.initial_source_connection_id &&
        retry_source_connection_id == rhs.retry_source_connection_id &&
        max_datagram_frame_size.value() ==
            rhs.max_datagram_frame_size.value() &&
        reliable_stream_reset == rhs.reliable_stream_reset &&
        initial_round_trip_time_us.value() ==
            rhs.initial_round_trip_time_us.value() &&
        discard_length == rhs.discard_length &&
        google_handshake_message == rhs.google_handshake_message &&
        google_connection_options == rhs.google_connection_options &&
        custom_parameters == rhs.custom_parameters)) {
    return false;
  }

  if ((!preferred_address && rhs.preferred_address) ||
      (preferred_address && !rhs.preferred_address)) {
    return false;
  }
  if (preferred_address && rhs.preferred_address &&
      *preferred_address != *rhs.preferred_address) {
    return false;
  }

  return true;
}

bool TransportParameters::operator!=(const TransportParameters& rhs) const {
  return !(*this == rhs);
}

bool TransportParameters::AreValid(std::string* error_details) const {
  QUICHE_DCHECK(perspective == Perspective::IS_CLIENT ||
                perspective == Perspective::IS_SERVER);
  if (perspective == Perspective::IS_CLIENT && !stateless_reset_token.empty()) {
    *error_details = "Client cannot send stateless reset token";
    return false;
  }
  if (perspective == Perspective::IS_CLIENT &&
      original_destination_connection_id.has_value()) {
    *error_details = "Client cannot send original_destination_connection_id";
    return false;
  }
  if (!stateless_reset_token.empty() &&
      stateless_reset_token.size() != kStatelessResetTokenLength) {
    *error_details = absl::StrCat("Stateless reset token has bad length ",
                                  stateless_reset_token.size());
    return false;
  }
  if (perspective == Perspective::IS_CLIENT && preferred_address) {
    *error_details = "Client cannot send preferred address";
    return false;
  }
  if (preferred_address && preferred_address->stateless_reset_token.size() !=
                               kStatelessResetTokenLength) {
    *error_details =
        absl::StrCat("Preferred address stateless reset token has bad length ",
                     preferred_address->stateless_reset_token.size());
    return false;
  }
  if (preferred_address &&
      (!preferred_address->ipv4_socket_address.host().IsIPv4() ||
       !preferred_address->ipv6_socket_address.host().IsIPv6())) {
    QUIC_BUG(quic_bug_10743_4) << "Preferred address family failure";
    *error_details = "Internal preferred address family failure";
    return false;
  }
  if (perspective == Perspective::IS_CLIENT &&
      retry_source_connection_id.has_value()) {
    *error_details = "Client cannot send retry_source_connection_id";
    return false;
  }
  for (const auto& kv : custom_parameters) {
    if (TransportParameterIdIsKnown(kv.first)) {
      *error_details = absl::StrCat("Using custom_parameters with known ID ",
                                    TransportParameterIdToString(kv.first),
                                    " is not allowed");
      return false;
    }
  }
  if (perspective == Perspective::IS_SERVER &&
      google_handshake_message.has_value()) {
    *error_details = "Server cannot send google_handshake_message";
    return false;
  }
  if (perspective == Perspective::IS_SERVER &&
      initial_round_trip_time_us.value() > 0) {
    *error_details = "Server cannot send initial round trip time";
    return false;
  }
  if (version_information.has_value()) {
    const QuicVersionLabel& chosen_version =
        version_information->chosen_version;
    const QuicVersionLabelVector& other_versions =
        version_information->other_versions;
    if (chosen_version == 0) {
      *error_details = "Invalid chosen version";
      return false;
    }
    if (perspective == Perspective::IS_CLIENT &&
        std::find(other_versions.begin(), other_versions.end(),
                  chosen_version) == other_versions.end()) {
      // When sent by the client, chosen_version needs to be present in
      // other_versions because other_versions lists the compatible versions and
      // the chosen version is part of that list. When sent by the server,
      // other_version contains the list of fully-deployed versions which is
      // generally equal to the list of supported versions but can slightly
      // differ during removal of versions across a server fleet. See
      // draft-ietf-quic-version-negotiation for details.
      *error_details = "Client chosen version not in other versions";
      return false;
    }
  }
  const bool ok =
      max_idle_timeout_ms.IsValid() && max_udp_payload_size.IsValid() &&
      initial_max_data.IsValid() &&
      initial_max_stream_data_bidi_local.IsValid() &&
      initial_max_stream_data_bidi_remote.IsValid() &&
      initial_max_stream_data_uni.IsValid() &&
      initial_max_streams_bidi.IsValid() && initial_max_streams_uni.IsValid() &&
      ack_delay_exponent.IsValid() && max_ack_delay.IsValid() &&
      min_ack_delay_us.IsValid() && active_connection_id_limit.IsValid() &&
      max_datagram_frame_size.IsValid() && initial_round_trip_time_us.IsValid();
  if (!ok) {
    *error_details = "Invalid transport parameters " + this->ToString();
  }
  return ok;
}

TransportParameters::~TransportParameters() = default;

bool SerializeTransportParameters(const TransportParameters& in,
                                  std::vector<uint8_t>* out) {
  std::string error_details;
  if (!in.AreValid(&error_details)) {
    QUIC_BUG(invalid transport parameters)
        << "Not serializing invalid transport parameters: " << error_details;
    return false;
  }
  if (!in.legacy_version_information.has_value() ||
      in.legacy_version_information->version == 0 ||
      (in.perspective == Perspective::IS_SERVER &&
       in.legacy_version_information->supported_versions.empty())) {
    QUIC_BUG(missing versions) << "Refusing to serialize without versions";
    return false;
  }
  TransportParameters::ParameterMap custom_parameters = in.custom_parameters;
  for (const auto& kv : custom_parameters) {
    if (kv.first % 31 == 27) {
      // See the "Reserved Transport Parameters" section of RFC 9000.
      QUIC_BUG(custom_parameters with GREASE)
          << "Serializing custom_parameters with GREASE ID " << kv.first
          << " is not allowed";
      return false;
    }
  }

  // Maximum length of the GREASE transport parameter (see below).
  static constexpr size_t kMaxGreaseLength = 16;

  // Empirically transport parameters generally fit within 128 bytes, but we
  // need to allocate the size up front. Integer transport parameters
  // have a maximum encoded length of 24 bytes (3 variable length integers),
  // other transport parameters have a length of 16 + the maximum value length.
  static constexpr size_t kTypeAndValueLength = 2 * sizeof(uint64_t);
  static constexpr size_t kIntegerParameterLength =
      kTypeAndValueLength + sizeof(uint64_t);
  static constexpr size_t kStatelessResetParameterLength =
      kTypeAndValueLength + 16 /* stateless reset token length */;
  static constexpr size_t kConnectionIdParameterLength =
      kTypeAndValueLength + 255 /* maximum connection ID length */;
  static constexpr size_t kPreferredAddressParameterLength =
      kTypeAndValueLength + 4 /*IPv4 address */ + 2 /* IPv4 port */ +
      16 /* IPv6 address */ + 1 /* Connection ID length */ +
      255 /* maximum connection ID length */ + 16 /* stateless reset token */;
  static constexpr size_t kKnownTransportParamLength =
      kConnectionIdParameterLength +      // original_destination_connection_id
      kIntegerParameterLength +           // max_idle_timeout
      kStatelessResetParameterLength +    // stateless_reset_token
      kIntegerParameterLength +           // max_udp_payload_size
      kIntegerParameterLength +           // initial_max_data
      kIntegerParameterLength +           // initial_max_stream_data_bidi_local
      kIntegerParameterLength +           // initial_max_stream_data_bidi_remote
      kIntegerParameterLength +           // initial_max_stream_data_uni
      kIntegerParameterLength +           // initial_max_streams_bidi
      kIntegerParameterLength +           // initial_max_streams_uni
      kIntegerParameterLength +           // ack_delay_exponent
      kIntegerParameterLength +           // max_ack_delay
      kIntegerParameterLength +           // min_ack_delay_us
      kTypeAndValueLength +               // disable_active_migration
      kPreferredAddressParameterLength +  // preferred_address
      kIntegerParameterLength +           // active_connection_id_limit
      kConnectionIdParameterLength +      // initial_source_connection_id
      kConnectionIdParameterLength +      // retry_source_connection_id
      kIntegerParameterLength +           // max_datagram_frame_size
      kTypeAndValueLength +               // reliable_stream_reset
      kIntegerParameterLength +           // initial_round_trip_time_us
      kTypeAndValueLength +               // discard
      kTypeAndValueLength +               // google_handshake_message
      kTypeAndValueLength +               //
```