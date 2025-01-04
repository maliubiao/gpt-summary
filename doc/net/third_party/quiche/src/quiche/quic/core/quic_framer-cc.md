Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is the beginning of `quic_framer.cc`, a crucial part of the Chromium QUIC implementation. It's responsible for handling the serialization and deserialization of QUIC packets and frames.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the core responsibility:** The filename `quic_framer.cc` and the included headers (`quic_packets.h`, `quic_frames.h`, `crypto/*.h`) strongly suggest that this code deals with the structure and processing of QUIC packets. The term "framer" also hints at the act of constructing and interpreting frames.

2. **Scan the included headers:** The headers provide clues about the functionalities. Headers like `quic_packets.h` indicate handling of entire packets, while `quic_stream_frame.h`, `quic_ack_frame.h`, etc., point to the management of individual frame types. The `crypto/` headers suggest involvement in encryption and decryption.

3. **Analyze the class definition:** The `QuicFramer` class is the central entity. Its member functions and data members will define its capabilities.

4. **Look for key methods and data members:**  Methods like `BuildDataPacket`, `AppendIetfPacketHeader`, and the various `GetMin...Size` functions clearly indicate serialization and size calculation logic. Data members like `supported_versions_`, `decrypter_level_`, and `perspective_` reveal the framer's state and configuration.

5. **Focus on the provided code blocks:**  The initial portion of the file defines constants and helper functions related to frame types, header structures, and error handling. These are fundamental to the core functionality. The `QuicFramer` constructor initializes important parameters.

6. **Infer relationships and interactions:** The framer needs to interact with encryption/decryption modules (evident from `crypto/*.h`) and with a "visitor" (the `visitor_` member) to notify about parsed frames and errors.

7. **Relate to Javascript (if applicable):**  QUIC is a transport protocol that underlies HTTP/3. Javascript running in a browser interacts with QUIC indirectly through the browser's network stack. The framer is a low-level component, but its role in correctly handling packets is essential for the reliable data transfer that Javascript applications rely on. Examples could involve fetching resources or establishing WebSockets connections.

8. **Consider debugging scenarios:**  The framer is a critical component, so errors here can lead to connection failures. Understanding how user actions (like visiting a website) lead to packet processing by the framer is important for debugging.

9. **Address the specific constraints:** The prompt asks for a list of functionalities, mentioning relationships with Javascript, logical reasoning with input/output examples, common user errors, debugging steps, and a summary of the current part.

10. **Structure the answer:** Organize the findings into clear categories like core functionality, detailed breakdown, Javascript connection, logical reasoning, user errors, debugging, and the summary of part 1. Use bullet points and clear language.

11. **Refine and review:** Ensure that the summary is accurate, comprehensive given the provided snippet, and addresses all aspects of the prompt. For instance, the logical reasoning part can be exemplified by the size calculation functions, where specific inputs (frame type, data length) lead to a calculated output (frame size). Common user errors are less direct with this low-level code, but misconfiguration (like incorrect version negotiation) is a possible high-level issue that would manifest here.

By following this thought process, the generated answer accurately describes the functionality of the `quic_framer.cc` code, relates it to Javascript, provides illustrative examples, and addresses the specific constraints of the prompt.
这个 `quic_framer.cc` 文件的第 1 部分主要负责定义 `QuicFramer` 类的基本结构、常量、辅助函数和构造函数。  其核心功能是作为 QUIC 协议数据包的构造器和解析器，负责将 QUIC 数据结构（如帧）序列化成字节流，以及将接收到的字节流反序列化成 QUIC 数据结构。

**以下是其功能的详细列举：**

* **定义 QUIC 帧类型和标志位:**  定义了各种 QUIC 帧类型的常量（例如 `PADDING`, `RESET_STREAM`, `CONNECTION_CLOSE`, `STREAM`, `ACK` 等），以及用于解析和构建这些帧的标志位和掩码。 这包括区分常规帧类型和特殊帧类型（如 Stream 和 Ack）。
* **定义数据包头部结构相关的常量和函数:**  定义了用于处理 QUIC 数据包头部（尤其是 IETF QUIC 头部）的常量和函数，例如连接 ID 长度的编码和解码、数据包编号长度的编码和解码、长包头类型的编码和解码等。
* **提供辅助函数用于处理字节序和数据长度:**  定义了一些辅助函数，如 `Delta`（计算差值），`ClosestTo`（找到最接近的值），以及用于读取和写入不同长度的数据（例如，数据包编号长度）。
* **提供辅助函数用于确定数据包类型和加密级别:**  定义了 `GetPacketNumberSpace` 和 `GetEncryptionLevel` 函数，用于根据数据包头部信息推断数据包所属的包编号空间和当前的加密级别。
* **定义错误处理相关的常量和函数:**  定义了最大错误字符串长度的常量 `kMaxErrorStringLength`，以及用于截断过长错误字符串的函数 `TruncateErrorString` 和 `TruncatedErrorStringSize`。还包括生成带错误码的错误字符串的函数 `GenerateErrorString`。
* **定义 `QuicFramer` 类:**
    * **成员变量:** 定义了 `QuicFramer` 类的一些核心成员变量，包括：
        * `visitor_`:  一个指向 `QuicFramerVisitor` 的指针，用于在解析完成帧或发生错误时通知上层模块。
        * `error_`:  记录最近一次发生的错误码。
        * `last_serialized_server_connection_id_`:  记录最后一次序列化的服务器连接 ID。
        * `version_`:  当前使用的 QUIC 版本。
        * `supported_versions_`:  支持的 QUIC 版本列表。
        * `decrypter_level_` 和 `alternative_decrypter_level_`:  当前的解密级别和备用解密级别。
        * `perspective_`:  表示当前是客户端还是服务端视角。
        * `validate_flags_`:  指示是否需要验证标志位。
        * `process_timestamps_`:  指示是否需要处理时间戳。
        * 以及其他与帧处理、连接 ID、加密等相关的配置项。
    * **构造函数:**  定义了 `QuicFramer` 的构造函数，用于初始化其成员变量，例如支持的 QUIC 版本、创建时间、视角等。

**与 Javascript 的关系：**

`quic_framer.cc` 本身是 C++ 代码，Javascript 代码无法直接访问或调用它。但是，它在浏览器网络栈中扮演着关键角色，最终影响着 Javascript 的网络请求行为。

**举例说明：**

假设一个 Javascript 应用程序发起一个 HTTP/3 请求（HTTP/3 基于 QUIC 协议）。

1. **用户操作:**  用户在浏览器中点击一个链接或 Javascript 代码发起一个 `fetch()` 请求。
2. **浏览器网络栈:**  浏览器网络栈会开始建立与服务器的 QUIC 连接。
3. **数据包构造 (序列化):** 当浏览器需要向服务器发送数据（例如，HTTP 请求头），`QuicFramer` 会被用来将这些数据封装成 QUIC 数据包。`QuicFramer` 的相关方法会将 HTTP 请求头等信息组织成 QUIC 帧，并根据协议规范将这些帧序列化成字节流。
4. **数据包解析 (反序列化):**  当浏览器接收到来自服务器的 QUIC 数据包时，`QuicFramer` 会被用来解析这些数据包。它会读取字节流，识别不同的 QUIC 帧，并将它们反序列化成浏览器可以理解的数据结构。 例如，解析出服务器发送的 HTTP 响应头或数据。
5. **Javascript 收到响应:**  最终，解析后的 HTTP 响应数据会被传递给 Javascript 代码，完成 `fetch()` 请求的处理。

**逻辑推理的假设输入与输出：**

**假设输入:**  一个表示 `RESET_STREAM` 帧的 C++ 数据结构，其中包含流 ID 和错误码。

**输出:**  `QuicFramer` 的序列化方法会将这个数据结构转换成一段字节流，其格式符合 QUIC 协议关于 `RESET_STREAM` 帧的定义。 这段字节流将包含帧类型标识符 (对应 `RESET_STREAM`)，流 ID 的编码，以及错误码的编码。

**用户或编程常见的使用错误：**

由于 `QuicFramer` 是网络栈内部的组件，用户或一般的 Javascript 开发者不会直接与其交互。  编程错误通常发生在 QUIC 协议的实现层面，例如：

* **错误地设置帧的标志位:**  在构建帧时，如果开发者错误地设置了某个标志位，例如 Stream 帧的 FIN 位，会导致接收方 `QuicFramer` 解析出错。
* **提供的缓冲区大小不足:**  在序列化帧到缓冲区时，如果提供的缓冲区大小小于帧实际需要的空间，会导致内存溢出或其他错误。
* **尝试解析不支持的 QUIC 版本的数据包:** 如果 `QuicFramer` 配置的支持版本列表中不包含接收到的数据包的版本，解析会失败。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中输入网址并访问网页。**
2. **浏览器开始解析域名，建立 TCP 连接（如果是 HTTP/1.1 或 HTTP/2）或尝试建立 QUIC 连接（如果是 HTTP/3）。**
3. **如果是 QUIC 连接:**
    * **客户端发送 ClientHello 消息，其中可能包含支持的 QUIC 版本信息。**
    * **服务端接收到 ClientHello 消息，`QuicFramer` 会解析这个消息。**
    * **如果连接成功建立，后续的数据传输都会通过 `QuicFramer` 进行数据包的构建和解析。**
4. **当网页需要加载资源时，Javascript 代码发起 `fetch()` 请求。**
5. **浏览器网络栈将 `fetch()` 请求的数据通过 `QuicFramer` 封装成 QUIC 数据包发送给服务器。**
6. **服务器响应的数据包被浏览器接收，并由 `QuicFramer` 解析，最终将数据传递给 Javascript。**

**作为调试线索，如果网络请求出现问题，例如连接失败、数据传输错误等，开发者可能会查看网络日志或使用网络抓包工具，分析底层的 QUIC 数据包。 了解 `QuicFramer` 的工作原理有助于理解这些数据包的结构，定位问题所在。**

**归纳一下第 1 部分的功能:**

第 1 部分主要定义了 `QuicFramer` 类的基础结构和用于处理 QUIC 帧和数据包头部的基本常量和辅助函数。 它为后续的帧的序列化、反序列化和错误处理奠定了基础。  简单来说，它定义了 QUIC 协议数据包的基本组成元素和解析规则。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共9部分，请归纳一下它的功能

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_framer.h"

#include <sys/types.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/macros.h"
#include "absl/base/optimization.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/crypto_framer.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/crypto_handshake_message.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/null_decrypter.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/frames/quic_ack_frequency_frame.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_socket_address_coder.h"
#include "quiche/quic/core/quic_stream_frame_data_producer.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_client_stats.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_ip_address_family.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_stack_trace.h"
#include "quiche/common/quiche_text_utils.h"
#include "quiche/common/wire_serialization.h"

namespace quic {

namespace {

#define ENDPOINT \
  (perspective_ == Perspective::IS_SERVER ? "Server: " : "Client: ")

// There are two interpretations for the Frame Type byte in the QUIC protocol,
// resulting in two Frame Types: Special Frame Types and Regular Frame Types.
//
// Regular Frame Types use the Frame Type byte simply. Currently defined
// Regular Frame Types are:
// Padding            : 0b 00000000 (0x00)
// ResetStream        : 0b 00000001 (0x01)
// ConnectionClose    : 0b 00000010 (0x02)
// GoAway             : 0b 00000011 (0x03)
// WindowUpdate       : 0b 00000100 (0x04)
// Blocked            : 0b 00000101 (0x05)
//
// Special Frame Types encode both a Frame Type and corresponding flags
// all in the Frame Type byte. Currently defined Special Frame Types
// are:
// Stream             : 0b 1xxxxxxx
// Ack                : 0b 01xxxxxx
//
// Semantics of the flag bits above (the x bits) depends on the frame type.

// Masks to determine if the frame type is a special use
// and for specific special frame types.
const uint8_t kQuicFrameTypeSpecialMask = 0xC0;  // 0b 11000000
const uint8_t kQuicFrameTypeStreamMask = 0x80;
const uint8_t kQuicFrameTypeAckMask = 0x40;
static_assert(kQuicFrameTypeSpecialMask ==
                  (kQuicFrameTypeStreamMask | kQuicFrameTypeAckMask),
              "Invalid kQuicFrameTypeSpecialMask");

// The stream type format is 1FDOOOSS, where
//    F is the fin bit.
//    D is the data length bit (0 or 2 bytes).
//    OO/OOO are the size of the offset.
//    SS is the size of the stream ID.
// Note that the stream encoding can not be determined by inspection. It can
// be determined only by knowing the QUIC Version.
// Stream frame relative shifts and masks for interpreting the stream flags.
// StreamID may be 1, 2, 3, or 4 bytes.
const uint8_t kQuicStreamIdShift = 2;
const uint8_t kQuicStreamIDLengthMask = 0x03;

// Offset may be 0, 2, 4, or 8 bytes.
const uint8_t kQuicStreamShift = 3;
const uint8_t kQuicStreamOffsetMask = 0x07;

// Data length may be 0 or 2 bytes.
const uint8_t kQuicStreamDataLengthShift = 1;
const uint8_t kQuicStreamDataLengthMask = 0x01;

// Fin bit may be set or not.
const uint8_t kQuicStreamFinShift = 1;
const uint8_t kQuicStreamFinMask = 0x01;

// The format is 01M0LLOO, where
//   M if set, there are multiple ack blocks in the frame.
//  LL is the size of the largest ack field.
//  OO is the size of the ack blocks offset field.
// packet number size shift used in AckFrames.
const uint8_t kQuicSequenceNumberLengthNumBits = 2;
const uint8_t kActBlockLengthOffset = 0;
const uint8_t kLargestAckedOffset = 2;

// Acks may have only one ack block.
const uint8_t kQuicHasMultipleAckBlocksOffset = 5;

// Timestamps are 4 bytes followed by 2 bytes.
const uint8_t kQuicNumTimestampsLength = 1;
const uint8_t kQuicFirstTimestampLength = 4;
const uint8_t kQuicTimestampLength = 2;
// Gaps between packet numbers are 1 byte.
const uint8_t kQuicTimestampPacketNumberGapLength = 1;

// Maximum length of encoded error strings.
const int kMaxErrorStringLength = 256;

const uint8_t kConnectionIdLengthAdjustment = 3;
const uint8_t kDestinationConnectionIdLengthMask = 0xF0;
const uint8_t kSourceConnectionIdLengthMask = 0x0F;

// Returns the absolute value of the difference between |a| and |b|.
uint64_t Delta(uint64_t a, uint64_t b) {
  // Since these are unsigned numbers, we can't just return abs(a - b)
  if (a < b) {
    return b - a;
  }
  return a - b;
}

uint64_t ClosestTo(uint64_t target, uint64_t a, uint64_t b) {
  return (Delta(target, a) < Delta(target, b)) ? a : b;
}

QuicPacketNumberLength ReadAckPacketNumberLength(uint8_t flags) {
  switch (flags & PACKET_FLAGS_8BYTE_PACKET) {
    case PACKET_FLAGS_8BYTE_PACKET:
      return PACKET_6BYTE_PACKET_NUMBER;
    case PACKET_FLAGS_4BYTE_PACKET:
      return PACKET_4BYTE_PACKET_NUMBER;
    case PACKET_FLAGS_2BYTE_PACKET:
      return PACKET_2BYTE_PACKET_NUMBER;
    case PACKET_FLAGS_1BYTE_PACKET:
      return PACKET_1BYTE_PACKET_NUMBER;
    default:
      QUIC_BUG(quic_bug_10850_2) << "Unreachable case statement.";
      return PACKET_6BYTE_PACKET_NUMBER;
  }
}

uint8_t PacketNumberLengthToOnWireValue(
    QuicPacketNumberLength packet_number_length) {
  return packet_number_length - 1;
}

QuicPacketNumberLength GetShortHeaderPacketNumberLength(uint8_t type) {
  QUICHE_DCHECK(!(type & FLAGS_LONG_HEADER));
  return static_cast<QuicPacketNumberLength>((type & 0x03) + 1);
}

uint8_t LongHeaderTypeToOnWireValue(QuicLongHeaderType type,
                                    const ParsedQuicVersion& version) {
  switch (type) {
    case INITIAL:
      return version.UsesV2PacketTypes() ? (1 << 4) : 0;
    case ZERO_RTT_PROTECTED:
      return version.UsesV2PacketTypes() ? (2 << 4) : (1 << 4);
    case HANDSHAKE:
      return version.UsesV2PacketTypes() ? (3 << 4) : (2 << 4);
    case RETRY:
      return version.UsesV2PacketTypes() ? 0 : (3 << 4);
    case VERSION_NEGOTIATION:
      return 0xF0;  // Value does not matter
    default:
      QUIC_BUG(quic_bug_10850_3) << "Invalid long header type: " << type;
      return 0xFF;
  }
}

QuicLongHeaderType GetLongHeaderType(uint8_t type,
                                     const ParsedQuicVersion& version) {
  QUICHE_DCHECK((type & FLAGS_LONG_HEADER));
  switch ((type & 0x30) >> 4) {
    case 0:
      return version.UsesV2PacketTypes() ? RETRY : INITIAL;
    case 1:
      return version.UsesV2PacketTypes() ? INITIAL : ZERO_RTT_PROTECTED;
    case 2:
      return version.UsesV2PacketTypes() ? ZERO_RTT_PROTECTED : HANDSHAKE;
    case 3:
      return version.UsesV2PacketTypes() ? HANDSHAKE : RETRY;
    default:
      QUIC_BUG(quic_bug_10850_4) << "Unreachable statement";
      return INVALID_PACKET_TYPE;
  }
}

QuicPacketNumberLength GetLongHeaderPacketNumberLength(uint8_t type) {
  return static_cast<QuicPacketNumberLength>((type & 0x03) + 1);
}

// Used to get packet number space before packet gets decrypted.
PacketNumberSpace GetPacketNumberSpace(const QuicPacketHeader& header) {
  switch (header.form) {
    case GOOGLE_QUIC_PACKET:
      QUIC_BUG(quic_bug_10850_5)
          << "Try to get packet number space of Google QUIC packet";
      break;
    case IETF_QUIC_SHORT_HEADER_PACKET:
      return APPLICATION_DATA;
    case IETF_QUIC_LONG_HEADER_PACKET:
      switch (header.long_packet_type) {
        case INITIAL:
          return INITIAL_DATA;
        case HANDSHAKE:
          return HANDSHAKE_DATA;
        case ZERO_RTT_PROTECTED:
          return APPLICATION_DATA;
        case VERSION_NEGOTIATION:
        case RETRY:
        case INVALID_PACKET_TYPE:
          QUIC_BUG(quic_bug_10850_6)
              << "Try to get packet number space of long header type: "
              << QuicUtils::QuicLongHeaderTypetoString(header.long_packet_type);
          break;
      }
  }

  return NUM_PACKET_NUMBER_SPACES;
}

EncryptionLevel GetEncryptionLevel(const QuicPacketHeader& header) {
  switch (header.form) {
    case GOOGLE_QUIC_PACKET:
      QUIC_BUG(quic_bug_10850_7)
          << "Cannot determine EncryptionLevel from Google QUIC header";
      break;
    case IETF_QUIC_SHORT_HEADER_PACKET:
      return ENCRYPTION_FORWARD_SECURE;
    case IETF_QUIC_LONG_HEADER_PACKET:
      switch (header.long_packet_type) {
        case INITIAL:
          return ENCRYPTION_INITIAL;
        case HANDSHAKE:
          return ENCRYPTION_HANDSHAKE;
        case ZERO_RTT_PROTECTED:
          return ENCRYPTION_ZERO_RTT;
        case VERSION_NEGOTIATION:
        case RETRY:
        case INVALID_PACKET_TYPE:
          QUIC_BUG(quic_bug_10850_8)
              << "No encryption used with type "
              << QuicUtils::QuicLongHeaderTypetoString(header.long_packet_type);
      }
  }
  return NUM_ENCRYPTION_LEVELS;
}

absl::string_view TruncateErrorString(absl::string_view error) {
  if (error.length() <= kMaxErrorStringLength) {
    return error;
  }
  return absl::string_view(error.data(), kMaxErrorStringLength);
}

size_t TruncatedErrorStringSize(const absl::string_view& error) {
  if (error.length() < kMaxErrorStringLength) {
    return error.length();
  }
  return kMaxErrorStringLength;
}

uint8_t GetConnectionIdLengthValue(uint8_t length) {
  if (length == 0) {
    return 0;
  }
  return static_cast<uint8_t>(length - kConnectionIdLengthAdjustment);
}

bool IsValidPacketNumberLength(QuicPacketNumberLength packet_number_length) {
  size_t length = packet_number_length;
  return length == 1 || length == 2 || length == 4 || length == 6 ||
         length == 8;
}

bool IsValidFullPacketNumber(uint64_t full_packet_number,
                             ParsedQuicVersion version) {
  return full_packet_number > 0 || version.HasIetfQuicFrames();
}

bool AppendIetfConnectionIds(bool version_flag, bool use_length_prefix,
                             QuicConnectionId destination_connection_id,
                             QuicConnectionId source_connection_id,
                             QuicDataWriter* writer) {
  if (!version_flag) {
    return writer->WriteConnectionId(destination_connection_id);
  }

  if (use_length_prefix) {
    return writer->WriteLengthPrefixedConnectionId(destination_connection_id) &&
           writer->WriteLengthPrefixedConnectionId(source_connection_id);
  }

  // Compute connection ID length byte.
  uint8_t dcil = GetConnectionIdLengthValue(destination_connection_id.length());
  uint8_t scil = GetConnectionIdLengthValue(source_connection_id.length());
  uint8_t connection_id_length = dcil << 4 | scil;

  return writer->WriteUInt8(connection_id_length) &&
         writer->WriteConnectionId(destination_connection_id) &&
         writer->WriteConnectionId(source_connection_id);
}

enum class DroppedPacketReason {
  // General errors
  INVALID_PUBLIC_HEADER,
  VERSION_MISMATCH,
  // Version negotiation packet errors
  INVALID_VERSION_NEGOTIATION_PACKET,
  // Public reset packet errors, pre-v44
  INVALID_PUBLIC_RESET_PACKET,
  // Data packet errors
  INVALID_PACKET_NUMBER,
  INVALID_DIVERSIFICATION_NONCE,
  DECRYPTION_FAILURE,
  NUM_REASONS,
};

void RecordDroppedPacketReason(DroppedPacketReason reason) {
  QUIC_CLIENT_HISTOGRAM_ENUM("QuicDroppedPacketReason", reason,
                             DroppedPacketReason::NUM_REASONS,
                             "The reason a packet was not processed. Recorded "
                             "each time such a packet is dropped");
}

PacketHeaderFormat GetIetfPacketHeaderFormat(uint8_t type_byte) {
  return type_byte & FLAGS_LONG_HEADER ? IETF_QUIC_LONG_HEADER_PACKET
                                       : IETF_QUIC_SHORT_HEADER_PACKET;
}

std::string GenerateErrorString(std::string initial_error_string,
                                QuicErrorCode quic_error_code) {
  if (quic_error_code == QUIC_IETF_GQUIC_ERROR_MISSING) {
    // QUIC_IETF_GQUIC_ERROR_MISSING is special -- it means not to encode
    // the error value in the string.
    return initial_error_string;
  }
  return absl::StrCat(std::to_string(static_cast<unsigned>(quic_error_code)),
                      ":", initial_error_string);
}

// Return the minimum size of the ECN fields in an ACK frame
size_t AckEcnCountSize(const QuicAckFrame& ack_frame) {
  if (!ack_frame.ecn_counters.has_value()) {
    return 0;
  }
  return (QuicDataWriter::GetVarInt62Len(ack_frame.ecn_counters->ect0) +
          QuicDataWriter::GetVarInt62Len(ack_frame.ecn_counters->ect1) +
          QuicDataWriter::GetVarInt62Len(ack_frame.ecn_counters->ce));
}

}  // namespace

QuicFramer::QuicFramer(const ParsedQuicVersionVector& supported_versions,
                       QuicTime creation_time, Perspective perspective,
                       uint8_t expected_server_connection_id_length)
    : visitor_(nullptr),
      error_(QUIC_NO_ERROR),
      last_serialized_server_connection_id_(EmptyQuicConnectionId()),
      version_(ParsedQuicVersion::Unsupported()),
      supported_versions_(supported_versions),
      decrypter_level_(ENCRYPTION_INITIAL),
      alternative_decrypter_level_(NUM_ENCRYPTION_LEVELS),
      alternative_decrypter_latch_(false),
      perspective_(perspective),
      validate_flags_(true),
      process_timestamps_(false),
      max_receive_timestamps_per_ack_(std::numeric_limits<uint32_t>::max()),
      receive_timestamps_exponent_(0),
      process_reset_stream_at_(false),
      creation_time_(creation_time),
      last_timestamp_(QuicTime::Delta::Zero()),
      support_key_update_for_connection_(false),
      current_key_phase_bit_(false),
      potential_peer_key_update_attempt_count_(0),
      first_sending_packet_number_(FirstSendingPacketNumber()),
      data_producer_(nullptr),
      expected_server_connection_id_length_(
          expected_server_connection_id_length),
      expected_client_connection_id_length_(0),
      supports_multiple_packet_number_spaces_(false),
      last_written_packet_number_length_(0),
      peer_ack_delay_exponent_(kDefaultAckDelayExponent),
      local_ack_delay_exponent_(kDefaultAckDelayExponent),
      current_received_frame_type_(0),
      previously_received_frame_type_(0) {
  QUICHE_DCHECK(!supported_versions.empty());
  version_ = supported_versions_[0];
  QUICHE_DCHECK(version_.IsKnown())
      << ParsedQuicVersionVectorToString(supported_versions_);
}

QuicFramer::~QuicFramer() {}

// static
size_t QuicFramer::GetMinStreamFrameSize(QuicTransportVersion version,
                                         QuicStreamId stream_id,
                                         QuicStreamOffset offset,
                                         bool last_frame_in_packet,
                                         size_t data_length) {
  if (VersionHasIetfQuicFrames(version)) {
    return kQuicFrameTypeSize + QuicDataWriter::GetVarInt62Len(stream_id) +
           (last_frame_in_packet
                ? 0
                : QuicDataWriter::GetVarInt62Len(data_length)) +
           (offset != 0 ? QuicDataWriter::GetVarInt62Len(offset) : 0);
  }
  return kQuicFrameTypeSize + GetStreamIdSize(stream_id) +
         GetStreamOffsetSize(offset) +
         (last_frame_in_packet ? 0 : kQuicStreamPayloadLengthSize);
}

// static
size_t QuicFramer::GetMinCryptoFrameSize(QuicStreamOffset offset,
                                         QuicPacketLength data_length) {
  return kQuicFrameTypeSize + QuicDataWriter::GetVarInt62Len(offset) +
         QuicDataWriter::GetVarInt62Len(data_length);
}

// static
size_t QuicFramer::GetMessageFrameSize(bool last_frame_in_packet,
                                       QuicByteCount length) {
  return kQuicFrameTypeSize +
         (last_frame_in_packet ? 0 : QuicDataWriter::GetVarInt62Len(length)) +
         length;
}

// static
size_t QuicFramer::GetMinAckFrameSize(
    QuicTransportVersion version, const QuicAckFrame& ack_frame,
    uint32_t local_ack_delay_exponent,
    bool use_ietf_ack_with_receive_timestamp) {
  if (VersionHasIetfQuicFrames(version)) {
    // The minimal ack frame consists of the following fields: Largest
    // Acknowledged, ACK Delay, 0 ACK Block Count, First ACK Block and either 0
    // Timestamp Range Count or ECN counts.
    // Type byte + largest acked.
    size_t min_size =
        kQuicFrameTypeSize +
        QuicDataWriter::GetVarInt62Len(LargestAcked(ack_frame).ToUint64());
    // Ack delay.
    min_size += QuicDataWriter::GetVarInt62Len(
        ack_frame.ack_delay_time.ToMicroseconds() >> local_ack_delay_exponent);
    // 0 ack block count.
    min_size += QuicDataWriter::GetVarInt62Len(0);
    // First ack block.
    min_size += QuicDataWriter::GetVarInt62Len(
        ack_frame.packets.Empty() ? 0
                                  : ack_frame.packets.rbegin()->Length() - 1);

    if (use_ietf_ack_with_receive_timestamp) {
      // 0 Timestamp Range Count.
      min_size += QuicDataWriter::GetVarInt62Len(0);
    } else {
      min_size += AckEcnCountSize(ack_frame);
    }
    return min_size;
  }
  return kQuicFrameTypeSize +
         GetMinPacketNumberLength(LargestAcked(ack_frame)) +
         kQuicDeltaTimeLargestObservedSize + kQuicNumTimestampsSize;
}

// static
size_t QuicFramer::GetStopWaitingFrameSize(
    QuicPacketNumberLength packet_number_length) {
  size_t min_size = kQuicFrameTypeSize + packet_number_length;
  return min_size;
}

// static
size_t QuicFramer::GetRstStreamFrameSize(QuicTransportVersion version,
                                         const QuicRstStreamFrame& frame) {
  if (VersionHasIetfQuicFrames(version)) {
    return QuicDataWriter::GetVarInt62Len(frame.stream_id) +
           QuicDataWriter::GetVarInt62Len(frame.byte_offset) +
           kQuicFrameTypeSize +
           QuicDataWriter::GetVarInt62Len(frame.ietf_error_code);
  }
  return kQuicFrameTypeSize + kQuicMaxStreamIdSize + kQuicMaxStreamOffsetSize +
         kQuicErrorCodeSize;
}

// static
size_t QuicFramer::GetConnectionCloseFrameSize(
    QuicTransportVersion version, const QuicConnectionCloseFrame& frame) {
  if (!VersionHasIetfQuicFrames(version)) {
    // Not IETF QUIC, return Google QUIC CONNECTION CLOSE frame size.
    return kQuicFrameTypeSize + kQuicErrorCodeSize +
           kQuicErrorDetailsLengthSize +
           TruncatedErrorStringSize(frame.error_details);
  }

  // Prepend the extra error information to the string and get the result's
  // length.
  const size_t truncated_error_string_size = TruncatedErrorStringSize(
      GenerateErrorString(frame.error_details, frame.quic_error_code));

  const size_t frame_size =
      truncated_error_string_size +
      QuicDataWriter::GetVarInt62Len(truncated_error_string_size) +
      kQuicFrameTypeSize +
      QuicDataWriter::GetVarInt62Len(frame.wire_error_code);
  if (frame.close_type == IETF_QUIC_APPLICATION_CONNECTION_CLOSE) {
    return frame_size;
  }
  // The Transport close frame has the transport_close_frame_type, so include
  // its length.
  return frame_size +
         QuicDataWriter::GetVarInt62Len(frame.transport_close_frame_type);
}

// static
size_t QuicFramer::GetMinGoAwayFrameSize() {
  return kQuicFrameTypeSize + kQuicErrorCodeSize + kQuicErrorDetailsLengthSize +
         kQuicMaxStreamIdSize;
}

// static
size_t QuicFramer::GetWindowUpdateFrameSize(
    QuicTransportVersion version, const QuicWindowUpdateFrame& frame) {
  if (!VersionHasIetfQuicFrames(version)) {
    return kQuicFrameTypeSize + kQuicMaxStreamIdSize + kQuicMaxStreamOffsetSize;
  }
  if (frame.stream_id == QuicUtils::GetInvalidStreamId(version)) {
    // Frame would be a MAX DATA frame, which has only a Maximum Data field.
    return kQuicFrameTypeSize + QuicDataWriter::GetVarInt62Len(frame.max_data);
  }
  // Frame would be MAX STREAM DATA, has Maximum Stream Data and Stream ID
  // fields.
  return kQuicFrameTypeSize + QuicDataWriter::GetVarInt62Len(frame.max_data) +
         QuicDataWriter::GetVarInt62Len(frame.stream_id);
}

// static
size_t QuicFramer::GetMaxStreamsFrameSize(QuicTransportVersion version,
                                          const QuicMaxStreamsFrame& frame) {
  if (!VersionHasIetfQuicFrames(version)) {
    QUIC_BUG(quic_bug_10850_9)
        << "In version " << version
        << ", which does not support IETF Frames, and tried to serialize "
           "MaxStreams Frame.";
  }
  return kQuicFrameTypeSize +
         QuicDataWriter::GetVarInt62Len(frame.stream_count);
}

// static
size_t QuicFramer::GetStreamsBlockedFrameSize(
    QuicTransportVersion version, const QuicStreamsBlockedFrame& frame) {
  if (!VersionHasIetfQuicFrames(version)) {
    QUIC_BUG(quic_bug_10850_10)
        << "In version " << version
        << ", which does not support IETF frames, and tried to serialize "
           "StreamsBlocked Frame.";
  }

  return kQuicFrameTypeSize +
         QuicDataWriter::GetVarInt62Len(frame.stream_count);
}

// static
size_t QuicFramer::GetBlockedFrameSize(QuicTransportVersion version,
                                       const QuicBlockedFrame& frame) {
  if (!VersionHasIetfQuicFrames(version)) {
    return kQuicFrameTypeSize + kQuicMaxStreamIdSize;
  }
  if (frame.stream_id == QuicUtils::GetInvalidStreamId(version)) {
    // return size of IETF QUIC Blocked frame
    return kQuicFrameTypeSize + QuicDataWriter::GetVarInt62Len(frame.offset);
  }
  // return size of IETF QUIC Stream Blocked frame.
  return kQuicFrameTypeSize + QuicDataWriter::GetVarInt62Len(frame.offset) +
         QuicDataWriter::GetVarInt62Len(frame.stream_id);
}

// static
size_t QuicFramer::GetStopSendingFrameSize(const QuicStopSendingFrame& frame) {
  return kQuicFrameTypeSize + QuicDataWriter::GetVarInt62Len(frame.stream_id) +
         QuicDataWriter::GetVarInt62Len(frame.ietf_error_code);
}

// static
size_t QuicFramer::GetAckFrequencyFrameSize(
    const QuicAckFrequencyFrame& frame) {
  return QuicDataWriter::GetVarInt62Len(IETF_ACK_FREQUENCY) +
         QuicDataWriter::GetVarInt62Len(frame.sequence_number) +
         QuicDataWriter::GetVarInt62Len(frame.packet_tolerance) +
         QuicDataWriter::GetVarInt62Len(frame.max_ack_delay.ToMicroseconds()) +
         // One byte for encoding boolean
         1;
}

// static
size_t QuicFramer::GetResetStreamAtFrameSize(
    const QuicResetStreamAtFrame& frame) {
  return QuicDataWriter::GetVarInt62Len(IETF_RESET_STREAM_AT) +
         QuicDataWriter::GetVarInt62Len(frame.stream_id) +
         QuicDataWriter::GetVarInt62Len(frame.error) +
         QuicDataWriter::GetVarInt62Len(frame.final_offset) +
         QuicDataWriter::GetVarInt62Len(frame.reliable_offset);
}

// static
size_t QuicFramer::GetPathChallengeFrameSize(
    const QuicPathChallengeFrame& frame) {
  return kQuicFrameTypeSize + sizeof(frame.data_buffer);
}

// static
size_t QuicFramer::GetPathResponseFrameSize(
    const QuicPathResponseFrame& frame) {
  return kQuicFrameTypeSize + sizeof(frame.data_buffer);
}

// static
size_t QuicFramer::GetRetransmittableControlFrameSize(
    QuicTransportVersion version, const QuicFrame& frame) {
  switch (frame.type) {
    case PING_FRAME:
      // Ping has no payload.
      return kQuicFrameTypeSize;
    case RST_STREAM_FRAME:
      return GetRstStreamFrameSize(version, *frame.rst_stream_frame);
    case CONNECTION_CLOSE_FRAME:
      return GetConnectionCloseFrameSize(version,
                                         *frame.connection_close_frame);
    case GOAWAY_FRAME:
      return GetMinGoAwayFrameSize() +
             TruncatedErrorStringSize(frame.goaway_frame->reason_phrase);
    case WINDOW_UPDATE_FRAME:
      // For IETF QUIC, this could be either a MAX DATA or MAX STREAM DATA.
      // GetWindowUpdateFrameSize figures this out and returns the correct
      // length.
      return GetWindowUpdateFrameSize(version, frame.window_update_frame);
    case BLOCKED_FRAME:
      return GetBlockedFrameSize(version, frame.blocked_frame);
    case NEW_CONNECTION_ID_FRAME:
      return GetNewConnectionIdFrameSize(*frame.new_connection_id_frame);
    case RETIRE_CONNECTION_ID_FRAME:
      return GetRetireConnectionIdFrameSize(*frame.retire_connection_id_frame);
    case NEW_TOKEN_FRAME:
      return GetNewTokenFrameSize(*frame.new_token_frame);
    case MAX_STREAMS_FRAME:
      return GetMaxStreamsFrameSize(version, frame.max_streams_frame);
    case STREAMS_BLOCKED_FRAME:
      return GetStreamsBlockedFrameSize(version, frame.streams_blocked_frame);
    case PATH_RESPONSE_FRAME:
      return GetPathResponseFrameSize(frame.path_response_frame);
    case PATH_CHALLENGE_FRAME:
      return GetPathChallengeFrameSize(frame.path_challenge_frame);
    case STOP_SENDING_FRAME:
      return GetStopSendingFrameSize(frame.stop_sending_frame);
    case HANDSHAKE_DONE_FRAME:
      // HANDSHAKE_DONE has no payload.
      return kQuicFrameTypeSize;
    case ACK_FREQUENCY_FRAME:
      return GetAckFrequencyFrameSize(*frame.ack_frequency_frame);
    case RESET_STREAM_AT_FRAME:
      return GetResetStreamAtFrameSize(*frame.reset_stream_at_frame);
    case STREAM_FRAME:
    case ACK_FRAME:
    case STOP_WAITING_FRAME:
    case MTU_DISCOVERY_FRAME:
    case PADDING_FRAME:
    case MESSAGE_FRAME:
    case CRYPTO_FRAME:
    case NUM_FRAME_TYPES:
      QUICHE_DCHECK(false);
      return 0;
  }

  // Not reachable, but some Chrome compilers can't figure that out.  *sigh*
  QUICHE_DCHECK(false);
  return 0;
}

// static
size_t QuicFramer::GetStreamIdSize(QuicStreamId stream_id) {
  // Sizes are 1 through 4 bytes.
  for (int i = 1; i <= 4; ++i) {
    stream_id >>= 8;
    if (stream_id == 0) {
      return i;
    }
  }
  QUIC_BUG(quic_bug_10850_11) << "Failed to determine StreamIDSize.";
  return 4;
}

// static
size_t QuicFramer::GetStreamOffsetSize(QuicStreamOffset offset) {
  // 0 is a special case.
  if (offset == 0) {
    return 0;
  }
  // 2 through 8 are the remaining sizes.
  offset >>= 8;
  for (int i = 2; i <= 8; ++i) {
    offset >>= 8;
    if (offset == 0) {
      return i;
    }
  }
  QUIC_BUG(quic_bug_10850_12) << "Failed to determine StreamOffsetSize.";
  return 8;
}

// static
size_t QuicFramer::GetNewConnectionIdFrameSize(
    const QuicNewConnectionIdFrame& frame) {
  return kQuicFrameTypeSize +
         QuicDataWriter::GetVarInt62Len(frame.sequence_number) +
         QuicDataWriter::GetVarInt62Len(frame.retire_prior_to) +
         kConnectionIdLengthSize + frame.connection_id.length() +
         sizeof(frame.stateless_reset_token);
}

// static
size_t QuicFramer::GetRetireConnectionIdFrameSize(
    const QuicRetireConnectionIdFrame& frame) {
  return kQuicFrameTypeSize +
         QuicDataWriter::GetVarInt62Len(frame.sequence_number);
}

// static
size_t QuicFramer::GetNewTokenFrameSize(const QuicNewTokenFrame& frame) {
  return kQuicFrameTypeSize +
         QuicDataWriter::GetVarInt62Len(frame.token.length()) +
         frame.token.length();
}

bool QuicFramer::IsSupportedVersion(const ParsedQuicVersion version) const {
  for (const ParsedQuicVersion& supported_version : supported_versions_) {
    if (version == supported_version) {
      return true;
    }
  }
  return false;
}

size_t QuicFramer::GetSerializedFrameLength(
    const QuicFrame& frame, size_t free_bytes, bool first_frame,
    bool last_frame, QuicPacketNumberLength packet_number_length) {
  // Prevent a rare crash reported in b/19458523.
  if (frame.type == ACK_FRAME && frame.ack_frame == nullptr) {
    QUIC_BUG(quic_bug_10850_13)
        << "Cannot compute the length of a null ack frame. free_bytes:"
        << free_bytes << " first_frame:" << first_frame
        << " last_frame:" << last_frame
        << " seq num length:" << packet_number_length;
    set_error(QUIC_INTERNAL_ERROR);
    visitor_->OnError(this);
    return 0;
  }
  if (frame.type == PADDING_FRAME) {
    if (frame.padding_frame.num_padding_bytes == -1) {
      // Full padding to the end of the packet.
      return free_bytes;
    } else {
      // Lite padding.
      return free_bytes <
                     static_cast<size_t>(frame.padding_frame.num_padding_bytes)
                 ? free_bytes
                 : frame.padding_frame.num_padding_bytes;
    }
  }

  size_t frame_len =
      ComputeFrameLength(frame, last_frame, packet_number_length);
  if (frame_len <= free_bytes) {
    // Frame fits within packet. Note that acks may be truncated.
    return frame_len;
  }
  // Only truncate the first frame in a packet, so if subsequent ones go
  // over, stop including more frames.
  if (!first_frame) {
    return 0;
  }
  bool can_truncate =
      frame.type == ACK_FRAME &&
      free_bytes >=
          GetMinAckFrameSize(version_.transport_version, *frame.ack_frame,
                             local_ack_delay_exponent_,
                             UseIetfAckWithReceiveTimestamp(*frame.ack_frame));
  if (can_truncate) {
    // Truncate the frame so the packet will not exceed kMaxOutgoingPacketSize.
    // Note that we may not use every byte of the writer in this case.
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Truncating large frame, free bytes: " << free_bytes;
    return free_bytes;
  }
  return 0;
}

QuicFramer::AckFrameInfo::AckFrameInfo()
    : max_block_length(0), first_block_length(0), num_ack_blocks(0) {}

QuicFramer::AckFrameInfo::AckFrameInfo(const AckFrameInfo& other) = default;

QuicFramer::AckFrameInfo::~AckFrameInfo() {}

bool QuicFramer::WriteIetfLongHeaderLength(const QuicPacketHeader& header,
                                           QuicDataWriter* writer,
                                           size_t length_field_offset,
                                           EncryptionLevel level) {
  if (!QuicVersionHasLongHeaderLengths(transport_version()) ||
      !header.version_flag || length_field_offset == 0) {
    return true;
  }
  if (writer->length() < length_field_offset ||
      writer->length() - length_field_offset <
          quiche::kQuicheDefaultLongHeaderLengthLength) {
    set_detailed_error("Invalid length_field_offset.");
    QUIC_BUG(quic_bug_10850_14) << "Invalid length_field_offset.";
    return false;
  }
  size_t length_to_write = writer->length() - length_field_offset -
                           quiche::kQuicheDefaultLongHeaderLengthLength;
  // Add length of auth tag.
  length_to_write = GetCiphertextSize(level, length_to_write);

  QuicDataWriter length_writer(writer->length() - length_field_offset,
                               writer->data() + length_field_offset);
  if (!length_writer.WriteVarInt62WithForcedLength(
          length_to_write, quiche::kQuicheDefaultLongHeaderLengthLength)) {
    set_detailed_error("Failed to overwrite long header length.");
    QUIC_BUG(quic_bug_10850_15) << "Failed to overwrite long header length.";
    return false;
  }
  return true;
}

size_t QuicFramer::BuildDataPacket(const QuicPacketHeader& header,
                                   const QuicFrames& frames, char* buffer,
                                   size_t packet_length,
                                   EncryptionLevel level) {
  QUIC_BUG_IF(quic_bug_12975_2, header.version_flag &&
                                    header.long_packet_type == RETRY &&
                                    !frames.empty())
      << "IETF RETRY packets cannot contain frames " << header;
  QuicDataWriter writer(packet_length, buffer);
  size_t length_field_offset = 0;
  if (!AppendIetfPacketHeader(header, &writer, &length_field_offset)) {
    QUIC_BUG(quic_bug_10850_16) << "AppendPacketHeader failed";
    return 
"""


```