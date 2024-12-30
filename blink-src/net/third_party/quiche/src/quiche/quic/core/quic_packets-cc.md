Response:
Let's break down the thought process for analyzing the `quic_packets.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to JavaScript, examples of logic, common errors, and a debugging trace. This requires a comprehensive understanding of the code.

2. **Initial Scan and High-Level Overview:**  Read through the file, paying attention to includes, namespaces, and the major data structures (classes and structs). Identify the core purpose. In this case, the file clearly deals with representing and manipulating QUIC packets.

3. **Deconstruct the File by Sections:**  Group related code blocks together. The file naturally falls into these categories:
    * **Connection ID Helpers:** Functions like `GetServerConnectionIdAsRecipient`, etc., clearly deal with extracting connection IDs based on perspective.
    * **Packet Header Size Calculation:**  `GetPacketHeaderSize` functions are central to understanding packet layout.
    * **Data Structure Definitions:**  The `QuicPacketHeader`, `QuicPublicResetPacket`, `QuicVersionNegotiationPacket`, `QuicData`, `QuicPacket`, `QuicEncryptedPacket`, `QuicReceivedPacket`, `SerializedPacket`, and `ReceivedPacketInfo` classes and structs define how packets and related metadata are stored.
    * **Helper Functions for Data Structures:** Constructors, destructors, copy operators, and output stream operators (`operator<<`) for the data structures.
    * **Packet Manipulation Functions:** `AssociatedData`, `Plaintext`, `CopySerializedPacket`, `CopyBuffer`.

4. **Analyze Each Section in Detail:**

    * **Connection ID Helpers:**  Observe the pattern. These functions are about getting the correct connection ID (source or destination) based on whether the current entity is the client or the server. Note the `Perspective` enum.

    * **Packet Header Size Calculation:** This is crucial. Notice the distinction between long and short headers based on `include_version`. Pay attention to the different length fields (connection IDs, packet number, retry token, length itself). The `QUICHE_DCHECK` macro suggests internal consistency checks.

    * **Data Structures:** For each class/struct:
        * Identify the member variables and their types. What information does each structure hold?
        * Understand the purpose of each structure. `QuicPacketHeader` holds metadata, `QuicData` and its derivatives hold the raw packet data, `SerializedPacket` represents a packet ready for sending, and `ReceivedPacketInfo` holds metadata about a received packet.

    * **Helper Functions:**
        * **Constructors/Destructors:** Understand how objects are initialized and cleaned up. Pay attention to memory management (`owns_buffer_`).
        * **Copy Operators:**  How are objects copied?  Are they deep copies or shallow copies?
        * **Output Stream Operators:**  How are these objects represented in text for debugging?

    * **Packet Manipulation:**  Understand how to access different parts of a packet (header, associated data, plaintext). The `SerializedPacket` and its copying mechanism are important for understanding packet lifecycle during sending.

5. **Address Specific Questions in the Request:**

    * **Functionality:** Summarize the purpose of each major component and the overall goal of the file.

    * **Relationship to JavaScript:**  This is a C++ file in the network stack. JavaScript interacts with the network through browser APIs. Think about how JavaScript might *indirectly* be affected. The connection establishment, data transfer, and error handling managed by this code ultimately enable the functionality JavaScript developers rely on. Provide concrete examples of network operations in JavaScript that are underpinned by this code.

    * **Logic and Assumptions:** Look for conditional logic (if/else). For the connection ID helpers, make explicit the assumptions about the `Perspective`. For header size calculation, demonstrate how the size changes based on header fields.

    * **Common Errors:** Consider scenarios where developers might misuse the provided functions or misinterpret packet structures. Examples include incorrect `Perspective` values leading to wrong connection ID selection, or miscalculating packet sizes.

    * **User Operations and Debugging:** Think about the chain of events that leads to packet processing within the Chromium browser. Start with a user action (typing a URL, clicking a link) and trace it through the network stack, eventually reaching the point where this C++ code is involved in handling QUIC packets. This helps provide context for debugging.

6. **Review and Refine:**  Read through the analysis, ensuring clarity, accuracy, and completeness. Check for any logical inconsistencies or missing details. Make sure the examples are relevant and easy to understand. For instance, initially, I might have focused too much on the low-level details of bit manipulation within the packet header. Refining the answer involves focusing on the higher-level concepts and how they relate to user actions and JavaScript.

7. **Self-Correction Example During Analysis:**  Initially, I might have overlooked the significance of the `SerializedPacket` and its role in the sending process. Upon closer examination, the presence of `retransmittable_frames` and `nonretransmittable_frames` suggests its use in preparing packets for transmission and handling retransmissions. Recognizing this detail adds significant value to the understanding of the file's functionality. Similarly, understanding the `owns_buffer_` flag in `QuicData` is crucial for grasping memory management. If I initially missed this, I'd go back and incorporate it.
这个C++源代码文件 `net/third_party/quiche/src/quiche/quic/core/quic_packets.cc` 定义了 Chromium QUIC 协议栈中用于表示和操作 QUIC 数据包的各种数据结构和辅助函数。它的主要功能可以概括为：

**核心功能:**

1. **定义 QUIC 数据包结构体:**  定义了表示不同类型 QUIC 数据包的 C++ 结构体，例如：
   - `QuicPacketHeader`:  表示 QUIC 数据包头部信息，包括连接ID、包序号、版本信息等。
   - `QuicPublicResetPacket`: 表示公共重置包。
   - `QuicVersionNegotiationPacket`: 表示版本协商包。
   - `QuicIetfStatelessResetPacket`: 表示 IETF 标准的无状态重置包。
   - `QuicData`:  表示原始的字节数据。
   - `QuicPacket`: 表示包含头部信息的 QUIC 数据包。
   - `QuicEncryptedPacket`: 表示加密后的 QUIC 数据包。
   - `QuicReceivedPacket`: 表示接收到的 QUIC 数据包，包含接收时间和可能的头部信息。
   - `SerializedPacket`:  表示准备好发送的 QUIC 数据包，包含加密后的数据和相关的元数据。
   - `ReceivedPacketInfo`:  表示接收到的数据包的详细信息，包括源地址、目的地址等。

2. **提供访问和操作数据包信息的函数:** 提供了各种辅助函数，用于获取和操作数据包结构体中的信息，例如：
   - `GetServerConnectionIdAsRecipient`, `GetClientConnectionIdAsRecipient`, `GetServerConnectionIdAsSender`, `GetClientConnectionIdAsSender`:  根据视角（客户端或服务端）获取相应的连接ID。
   - `GetIncludedDestinationConnectionIdLength`, `GetIncludedSourceConnectionIdLength`: 获取包含的连接ID的长度。
   - `GetPacketHeaderSize`:  计算数据包头部的大小。
   - `GetStartOfEncryptedData`: 计算加密数据开始的位置。
   - `AssociatedData`:  获取用于加密的关联数据。
   - `Plaintext`: 获取数据包的明文部分。

3. **实现数据包的创建、复制和销毁:** 提供了构造函数、拷贝构造函数、移动构造函数、析构函数以及 `Clone()` 方法，用于创建、复制和销毁数据包对象，并管理内存。

4. **提供数据包信息的格式化输出:**  重载了 `operator<<` 运算符，使得可以将数据包对象以易读的格式输出到流中，方便调试。

**与 JavaScript 的关系:**

这个 C++ 文件是 Chromium 浏览器网络栈的底层实现，直接与 JavaScript 没有直接的源代码级别的关系。然而，它对 JavaScript 的网络功能至关重要。

当 JavaScript 代码发起网络请求（例如，使用 `fetch` API 或 `XMLHttpRequest`）并且协议协商选择了 QUIC 时，Chromium 浏览器底层的网络栈会使用这个文件中定义的结构体和函数来构建、解析和处理 QUIC 数据包。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch` API 向服务器发起一个 HTTPS 请求，而该连接使用了 QUIC 协议。

1. **JavaScript 发起请求:** JavaScript 代码调用 `fetch('https://example.com')`。
2. **浏览器网络栈处理:**  Chromium 的网络栈开始处理这个请求。如果决定使用 QUIC，它会创建 QUIC 连接。
3. **构建 QUIC 数据包:** 当需要发送数据（例如，HTTP 请求头）到服务器时，网络栈会使用 `QuicPacketHeader` 等结构体来构建 QUIC 数据包的头部，设置连接ID、包序号等信息。数据负载会被放入 `QuicData` 或 `QuicPacket` 对象中。
4. **加密数据包:** 数据会被加密，生成 `QuicEncryptedPacket`。
5. **发送数据包:** 加密后的数据包通过网络发送出去。
6. **接收 QUIC 数据包:** 当收到来自服务器的 QUIC 数据包时，网络栈会使用这个文件中的结构体来解析数据包的头部，获取连接ID、包序号等信息。
7. **解密数据包:**  数据包会被解密。
8. **传递给 JavaScript:** 解密后的数据（例如，HTTP 响应）会被传递回 JavaScript 代码，`fetch` API 的 Promise 会 resolve。

**逻辑推理和假设输入/输出:**

以 `GetServerConnectionIdAsRecipient` 函数为例：

**假设输入:**

- `header`: 一个 `QuicPacketHeader` 对象，假设其 `destination_connection_id` 为 `0x12345678`，`source_connection_id` 为 `0x9ABCDEF0`。
- `perspective`: 一个 `Perspective` 枚举值，可以是 `Perspective::IS_SERVER` 或 `Perspective::IS_CLIENT`。

**逻辑推理:**

- 如果 `perspective` 是 `Perspective::IS_SERVER`，则接收者是服务器，服务器应该使用数据包头部的 `destination_connection_id` 作为其连接ID。
- 如果 `perspective` 是 `Perspective::IS_CLIENT`，则接收者是客户端，客户端应该使用数据包头部的 `source_connection_id` 作为其连接ID。

**输出:**

- 如果 `perspective` 是 `Perspective::IS_SERVER`，则输出 `QuicConnectionId(0x12345678)`。
- 如果 `perspective` 是 `Perspective::IS_CLIENT`，则输出 `QuicConnectionId(0x9ABCDEF0)`。

**用户或编程常见的使用错误:**

1. **错误地理解 Perspective:** 在调用获取连接ID的函数时，如果传递了错误的 `Perspective` 参数，可能会导致获取错误的连接ID。例如，在服务器端处理接收到的数据包时，如果误将 `perspective` 设置为 `Perspective::IS_CLIENT`，则会错误地使用源连接ID作为服务器的连接ID。

   ```c++
   // 错误示例：在服务端处理接收到的数据包时
   QuicConnectionId server_cid = GetServerConnectionIdAsRecipient(header, Perspective::IS_CLIENT);
   // server_cid 将会是 header.source_connection_id，这是错误的。
   ```

2. **不正确的头部大小计算:** 在手动构建或解析 QUIC 数据包时，如果使用 `GetPacketHeaderSize` 计算头部大小出错，可能会导致数据包解析失败或发送错误。例如，忘记考虑某些头部字段（如版本信息或Nonce）的存在。

   ```c++
   // 错误示例：假设版本协商标志位被设置，但计算头部大小时没有考虑版本号的长度
   size_t header_size = kPacketHeaderTypeSize + GetIncludedDestinationConnectionIdLength(header) +
                        GetIncludedSourceConnectionIdLength(header) + header.packet_number_length;
   if (header.version_flag) {
       // 忘记加上 kQuicVersionSize
   }
   ```

3. **内存管理错误:**  在处理 `QuicData` 和 `QuicPacket` 时，如果所有权 (`owns_buffer_`) 管理不当，可能会导致内存泄漏或 double free。例如，在 `QuicData` 对象析构时，如果 `owns_buffer_` 为 true，则会尝试释放 `buffer_` 指向的内存，如果该内存已经被释放过，则会出错。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。**
2. **浏览器解析 URL，确定目标服务器的地址和端口。**
3. **浏览器网络栈检查是否已经存在与目标服务器的 QUIC 连接。**
4. **如果不存在 QUIC 连接，网络栈会尝试与服务器建立 QUIC 连接。** 这涉及到发送 ClientHello 数据包，其中会使用 `QuicPacketHeader` 等结构体构建初始数据包。
5. **如果存在 QUIC 连接，浏览器开始发送 HTTP 请求。** 这时，请求数据会被封装成 QUIC 数据包，`quic_packets.cc` 中定义的结构体和函数会被用来构建这些数据包。
6. **当收到来自服务器的响应数据时，网络栈会使用 `QuicReceivedPacket` 等结构体来表示接收到的数据包，并解析其头部信息。**
7. **在连接的生命周期中，可能会涉及到发送和接收各种类型的 QUIC 控制帧和数据帧，这些都会涉及到 `quic_packets.cc` 中定义的结构体和函数。**
8. **如果发生错误，例如连接超时或对端发送重置包，网络栈会创建和处理相应的 QUIC 控制包，例如 `QuicPublicResetPacket` 或 `QuicIetfStatelessResetPacket`。**

**调试线索:**

当在 Chromium 网络栈中调试 QUIC 相关问题时，可以关注以下几点：

- **查看 `QuicPacketHeader` 中的字段值:**  例如，检查连接ID是否正确，包序号是否按预期递增，版本信息是否匹配等。
- **检查 `GetPacketHeaderSize` 的返回值:** 确保计算出的头部大小与实际数据包的布局一致。
- **跟踪 `QuicData` 和 `QuicPacket` 的创建和销毁:**  验证内存管理是否正确。
- **在发送和接收数据包的关键路径上设置断点:**  例如，在构建数据包、加密数据包、解密数据包等环节设置断点，查看相关变量的值。
- **使用网络抓包工具 (如 Wireshark) 结合 QUIC 解码器:**  分析实际的网络数据包，与代码中的数据结构进行对比。

总而言之，`net/third_party/quiche/src/quiche/quic/core/quic_packets.cc` 是 Chromium QUIC 协议栈中至关重要的基础组件，它定义了 QUIC 数据包的表示方式和操作方法，为 QUIC 协议的实现提供了核心的数据结构和工具函数。虽然 JavaScript 开发者不会直接操作这个文件中的代码，但其功能直接影响着基于 QUIC 的网络连接的建立、数据传输和错误处理，从而间接地影响着 JavaScript 应用的网络性能和稳定性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_packets.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_packets.h"

#include <algorithm>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_flags.h"

namespace quic {

QuicConnectionId GetServerConnectionIdAsRecipient(
    const QuicPacketHeader& header, Perspective perspective) {
  if (perspective == Perspective::IS_SERVER) {
    return header.destination_connection_id;
  }
  return header.source_connection_id;
}

QuicConnectionId GetClientConnectionIdAsRecipient(
    const QuicPacketHeader& header, Perspective perspective) {
  if (perspective == Perspective::IS_CLIENT) {
    return header.destination_connection_id;
  }
  return header.source_connection_id;
}

QuicConnectionId GetServerConnectionIdAsSender(const QuicPacketHeader& header,
                                               Perspective perspective) {
  if (perspective == Perspective::IS_CLIENT) {
    return header.destination_connection_id;
  }
  return header.source_connection_id;
}

QuicConnectionIdIncluded GetServerConnectionIdIncludedAsSender(
    const QuicPacketHeader& header, Perspective perspective) {
  if (perspective == Perspective::IS_CLIENT) {
    return header.destination_connection_id_included;
  }
  return header.source_connection_id_included;
}

QuicConnectionId GetClientConnectionIdAsSender(const QuicPacketHeader& header,
                                               Perspective perspective) {
  if (perspective == Perspective::IS_CLIENT) {
    return header.source_connection_id;
  }
  return header.destination_connection_id;
}

QuicConnectionIdIncluded GetClientConnectionIdIncludedAsSender(
    const QuicPacketHeader& header, Perspective perspective) {
  if (perspective == Perspective::IS_CLIENT) {
    return header.source_connection_id_included;
  }
  return header.destination_connection_id_included;
}

uint8_t GetIncludedConnectionIdLength(
    QuicConnectionId connection_id,
    QuicConnectionIdIncluded connection_id_included) {
  QUICHE_DCHECK(connection_id_included == CONNECTION_ID_PRESENT ||
                connection_id_included == CONNECTION_ID_ABSENT);
  return connection_id_included == CONNECTION_ID_PRESENT
             ? connection_id.length()
             : 0;
}

uint8_t GetIncludedDestinationConnectionIdLength(
    const QuicPacketHeader& header) {
  return GetIncludedConnectionIdLength(
      header.destination_connection_id,
      header.destination_connection_id_included);
}

uint8_t GetIncludedSourceConnectionIdLength(const QuicPacketHeader& header) {
  return GetIncludedConnectionIdLength(header.source_connection_id,
                                       header.source_connection_id_included);
}

size_t GetPacketHeaderSize(QuicTransportVersion version,
                           const QuicPacketHeader& header) {
  return GetPacketHeaderSize(
      version, GetIncludedDestinationConnectionIdLength(header),
      GetIncludedSourceConnectionIdLength(header), header.version_flag,
      header.nonce != nullptr, header.packet_number_length,
      header.retry_token_length_length, header.retry_token.length(),
      header.length_length);
}

size_t GetPacketHeaderSize(
    QuicTransportVersion version, uint8_t destination_connection_id_length,
    uint8_t source_connection_id_length, bool include_version,
    bool include_diversification_nonce,
    QuicPacketNumberLength packet_number_length,
    quiche::QuicheVariableLengthIntegerLength retry_token_length_length,
    QuicByteCount retry_token_length,
    quiche::QuicheVariableLengthIntegerLength length_length) {
  if (include_version) {
    // Long header.
    size_t size = kPacketHeaderTypeSize + kConnectionIdLengthSize +
                  destination_connection_id_length +
                  source_connection_id_length + packet_number_length +
                  kQuicVersionSize;
    if (include_diversification_nonce) {
      size += kDiversificationNonceSize;
    }
    if (VersionHasLengthPrefixedConnectionIds(version)) {
      size += kConnectionIdLengthSize;
    }
    QUICHE_DCHECK(
        QuicVersionHasLongHeaderLengths(version) ||
        retry_token_length_length + retry_token_length + length_length == 0);
    if (QuicVersionHasLongHeaderLengths(version)) {
      size += retry_token_length_length + retry_token_length + length_length;
    }
    return size;
  }
  // Short header.
  return kPacketHeaderTypeSize + destination_connection_id_length +
         packet_number_length;
}

size_t GetStartOfEncryptedData(QuicTransportVersion version,
                               const QuicPacketHeader& header) {
  return GetPacketHeaderSize(version, header);
}

size_t GetStartOfEncryptedData(
    QuicTransportVersion version, uint8_t destination_connection_id_length,
    uint8_t source_connection_id_length, bool include_version,
    bool include_diversification_nonce,
    QuicPacketNumberLength packet_number_length,
    quiche::QuicheVariableLengthIntegerLength retry_token_length_length,
    QuicByteCount retry_token_length,
    quiche::QuicheVariableLengthIntegerLength length_length) {
  // Encryption starts before private flags.
  return GetPacketHeaderSize(
      version, destination_connection_id_length, source_connection_id_length,
      include_version, include_diversification_nonce, packet_number_length,
      retry_token_length_length, retry_token_length, length_length);
}

QuicPacketHeader::QuicPacketHeader()
    : destination_connection_id(EmptyQuicConnectionId()),
      destination_connection_id_included(CONNECTION_ID_PRESENT),
      source_connection_id(EmptyQuicConnectionId()),
      source_connection_id_included(CONNECTION_ID_ABSENT),
      reset_flag(false),
      version_flag(false),
      has_possible_stateless_reset_token(false),
      packet_number_length(PACKET_4BYTE_PACKET_NUMBER),
      type_byte(0),
      version(UnsupportedQuicVersion()),
      nonce(nullptr),
      form(GOOGLE_QUIC_PACKET),
      long_packet_type(INITIAL),
      possible_stateless_reset_token({}),
      retry_token_length_length(quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0),
      retry_token(absl::string_view()),
      length_length(quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0),
      remaining_packet_length(0) {}

QuicPacketHeader::QuicPacketHeader(const QuicPacketHeader& other) = default;

QuicPacketHeader::~QuicPacketHeader() {}

QuicPacketHeader& QuicPacketHeader::operator=(const QuicPacketHeader& other) =
    default;

QuicPublicResetPacket::QuicPublicResetPacket()
    : connection_id(EmptyQuicConnectionId()), nonce_proof(0) {}

QuicPublicResetPacket::QuicPublicResetPacket(QuicConnectionId connection_id)
    : connection_id(connection_id), nonce_proof(0) {}

QuicVersionNegotiationPacket::QuicVersionNegotiationPacket()
    : connection_id(EmptyQuicConnectionId()) {}

QuicVersionNegotiationPacket::QuicVersionNegotiationPacket(
    QuicConnectionId connection_id)
    : connection_id(connection_id) {}

QuicVersionNegotiationPacket::QuicVersionNegotiationPacket(
    const QuicVersionNegotiationPacket& other) = default;

QuicVersionNegotiationPacket::~QuicVersionNegotiationPacket() {}

QuicIetfStatelessResetPacket::QuicIetfStatelessResetPacket()
    : stateless_reset_token({}) {}

QuicIetfStatelessResetPacket::QuicIetfStatelessResetPacket(
    const QuicPacketHeader& header, StatelessResetToken token)
    : header(header), stateless_reset_token(token) {}

QuicIetfStatelessResetPacket::QuicIetfStatelessResetPacket(
    const QuicIetfStatelessResetPacket& other) = default;

QuicIetfStatelessResetPacket::~QuicIetfStatelessResetPacket() {}

std::ostream& operator<<(std::ostream& os, const QuicPacketHeader& header) {
  os << "{ destination_connection_id: " << header.destination_connection_id
     << " ("
     << (header.destination_connection_id_included == CONNECTION_ID_PRESENT
             ? "present"
             : "absent")
     << "), source_connection_id: " << header.source_connection_id << " ("
     << (header.source_connection_id_included == CONNECTION_ID_PRESENT
             ? "present"
             : "absent")
     << "), packet_number_length: "
     << static_cast<int>(header.packet_number_length)
     << ", reset_flag: " << header.reset_flag
     << ", version_flag: " << header.version_flag;
  if (header.version_flag) {
    os << ", version: " << ParsedQuicVersionToString(header.version);
    if (header.long_packet_type != INVALID_PACKET_TYPE) {
      os << ", long_packet_type: "
         << QuicUtils::QuicLongHeaderTypetoString(header.long_packet_type);
    }
    if (header.retry_token_length_length !=
        quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0) {
      os << ", retry_token_length_length: "
         << static_cast<int>(header.retry_token_length_length);
    }
    if (header.retry_token.length() != 0) {
      os << ", retry_token_length: " << header.retry_token.length();
    }
    if (header.length_length != quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0) {
      os << ", length_length: " << static_cast<int>(header.length_length);
    }
    if (header.remaining_packet_length != 0) {
      os << ", remaining_packet_length: " << header.remaining_packet_length;
    }
  }
  if (header.nonce != nullptr) {
    os << ", diversification_nonce: "
       << absl::BytesToHexString(
              absl::string_view(header.nonce->data(), header.nonce->size()));
  }
  os << ", packet_number: " << header.packet_number << " }\n";
  return os;
}

QuicData::QuicData(const char* buffer, size_t length)
    : buffer_(buffer), length_(length), owns_buffer_(false) {}

QuicData::QuicData(const char* buffer, size_t length, bool owns_buffer)
    : buffer_(buffer), length_(length), owns_buffer_(owns_buffer) {}

QuicData::QuicData(absl::string_view packet_data)
    : buffer_(packet_data.data()),
      length_(packet_data.length()),
      owns_buffer_(false) {}

QuicData::~QuicData() {
  if (owns_buffer_) {
    delete[] const_cast<char*>(buffer_);
  }
}

QuicPacket::QuicPacket(
    char* buffer, size_t length, bool owns_buffer,
    uint8_t destination_connection_id_length,
    uint8_t source_connection_id_length, bool includes_version,
    bool includes_diversification_nonce,
    QuicPacketNumberLength packet_number_length,
    quiche::QuicheVariableLengthIntegerLength retry_token_length_length,
    QuicByteCount retry_token_length,
    quiche::QuicheVariableLengthIntegerLength length_length)
    : QuicData(buffer, length, owns_buffer),
      buffer_(buffer),
      destination_connection_id_length_(destination_connection_id_length),
      source_connection_id_length_(source_connection_id_length),
      includes_version_(includes_version),
      includes_diversification_nonce_(includes_diversification_nonce),
      packet_number_length_(packet_number_length),
      retry_token_length_length_(retry_token_length_length),
      retry_token_length_(retry_token_length),
      length_length_(length_length) {}

QuicPacket::QuicPacket(QuicTransportVersion /*version*/, char* buffer,
                       size_t length, bool owns_buffer,
                       const QuicPacketHeader& header)
    : QuicPacket(buffer, length, owns_buffer,
                 GetIncludedDestinationConnectionIdLength(header),
                 GetIncludedSourceConnectionIdLength(header),
                 header.version_flag, header.nonce != nullptr,
                 header.packet_number_length, header.retry_token_length_length,
                 header.retry_token.length(), header.length_length) {}

QuicEncryptedPacket::QuicEncryptedPacket(const char* buffer, size_t length)
    : QuicData(buffer, length) {}

QuicEncryptedPacket::QuicEncryptedPacket(const char* buffer, size_t length,
                                         bool owns_buffer)
    : QuicData(buffer, length, owns_buffer) {}

QuicEncryptedPacket::QuicEncryptedPacket(absl::string_view data)
    : QuicData(data) {}

std::unique_ptr<QuicEncryptedPacket> QuicEncryptedPacket::Clone() const {
  char* buffer = new char[this->length()];
  std::copy(this->data(), this->data() + this->length(), buffer);
  return std::make_unique<QuicEncryptedPacket>(buffer, this->length(), true);
}

std::ostream& operator<<(std::ostream& os, const QuicEncryptedPacket& s) {
  os << s.length() << "-byte data";
  return os;
}

QuicReceivedPacket::QuicReceivedPacket(const char* buffer, size_t length,
                                       QuicTime receipt_time)
    : QuicReceivedPacket(buffer, length, receipt_time,
                         false /* owns_buffer */) {}

QuicReceivedPacket::QuicReceivedPacket(const char* buffer, size_t length,
                                       QuicTime receipt_time, bool owns_buffer)
    : QuicReceivedPacket(buffer, length, receipt_time, owns_buffer, 0 /* ttl */,
                         true /* ttl_valid */) {}

QuicReceivedPacket::QuicReceivedPacket(const char* buffer, size_t length,
                                       QuicTime receipt_time, bool owns_buffer,
                                       int ttl, bool ttl_valid)
    : quic::QuicReceivedPacket(buffer, length, receipt_time, owns_buffer, ttl,
                               ttl_valid, nullptr /* packet_headers */,
                               0 /* headers_length */,
                               false /* owns_header_buffer */, ECN_NOT_ECT) {}

QuicReceivedPacket::QuicReceivedPacket(const char* buffer, size_t length,
                                       QuicTime receipt_time, bool owns_buffer,
                                       int ttl, bool ttl_valid,
                                       char* packet_headers,
                                       size_t headers_length,
                                       bool owns_header_buffer)
    : quic::QuicReceivedPacket(buffer, length, receipt_time, owns_buffer, ttl,
                               ttl_valid, packet_headers, headers_length,
                               owns_header_buffer, ECN_NOT_ECT) {}

QuicReceivedPacket::QuicReceivedPacket(
    const char* buffer, size_t length, QuicTime receipt_time, bool owns_buffer,
    int ttl, bool ttl_valid, char* packet_headers, size_t headers_length,
    bool owns_header_buffer, QuicEcnCodepoint ecn_codepoint)
    : quic::QuicReceivedPacket(buffer, length, receipt_time, owns_buffer, ttl,
                               ttl_valid, packet_headers, headers_length,
                               owns_header_buffer, ecn_codepoint,
                               /*ipv6_flow_label=*/0) {}

QuicReceivedPacket::QuicReceivedPacket(
    const char* buffer, size_t length, QuicTime receipt_time, bool owns_buffer,
    int ttl, bool ttl_valid, char* packet_headers, size_t headers_length,
    bool owns_header_buffer, QuicEcnCodepoint ecn_codepoint,
    uint32_t ipv6_flow_label)
    : QuicEncryptedPacket(buffer, length, owns_buffer),
      receipt_time_(receipt_time),
      ttl_(ttl_valid ? ttl : -1),
      packet_headers_(packet_headers),
      headers_length_(headers_length),
      owns_header_buffer_(owns_header_buffer),
      ecn_codepoint_(ecn_codepoint),
      ipv6_flow_label_(ipv6_flow_label) {}

QuicReceivedPacket::~QuicReceivedPacket() {
  if (owns_header_buffer_) {
    delete[] static_cast<char*>(packet_headers_);
  }
}

std::unique_ptr<QuicReceivedPacket> QuicReceivedPacket::Clone() const {
  char* buffer = new char[this->length()];
  memcpy(buffer, this->data(), this->length());
  if (this->packet_headers()) {
    char* headers_buffer = new char[this->headers_length()];
    memcpy(headers_buffer, this->packet_headers(), this->headers_length());
    return std::make_unique<QuicReceivedPacket>(
        buffer, this->length(), receipt_time(), true, ttl(), ttl() >= 0,
        headers_buffer, this->headers_length(), true, this->ecn_codepoint());
  }

  return std::make_unique<QuicReceivedPacket>(
      buffer, this->length(), receipt_time(), true, ttl(), ttl() >= 0, nullptr,
      0, false, this->ecn_codepoint());
}

std::ostream& operator<<(std::ostream& os, const QuicReceivedPacket& s) {
  os << s.length() << "-byte data";
  return os;
}

absl::string_view QuicPacket::AssociatedData(
    QuicTransportVersion version) const {
  return absl::string_view(
      data(),
      GetStartOfEncryptedData(version, destination_connection_id_length_,
                              source_connection_id_length_, includes_version_,
                              includes_diversification_nonce_,
                              packet_number_length_, retry_token_length_length_,
                              retry_token_length_, length_length_));
}

absl::string_view QuicPacket::Plaintext(QuicTransportVersion version) const {
  const size_t start_of_encrypted_data = GetStartOfEncryptedData(
      version, destination_connection_id_length_, source_connection_id_length_,
      includes_version_, includes_diversification_nonce_, packet_number_length_,
      retry_token_length_length_, retry_token_length_, length_length_);
  return absl::string_view(data() + start_of_encrypted_data,
                           length() - start_of_encrypted_data);
}

SerializedPacket::SerializedPacket(QuicPacketNumber packet_number,
                                   QuicPacketNumberLength packet_number_length,
                                   const char* encrypted_buffer,
                                   QuicPacketLength encrypted_length,
                                   bool has_ack, bool has_stop_waiting)
    : encrypted_buffer(encrypted_buffer),
      encrypted_length(encrypted_length),
      has_crypto_handshake(NOT_HANDSHAKE),
      packet_number(packet_number),
      packet_number_length(packet_number_length),
      encryption_level(ENCRYPTION_INITIAL),
      has_ack(has_ack),
      has_stop_waiting(has_stop_waiting),
      transmission_type(NOT_RETRANSMISSION),
      has_ack_frame_copy(false),
      has_ack_frequency(false),
      has_message(false),
      fate(SEND_TO_WRITER) {}

SerializedPacket::SerializedPacket(SerializedPacket&& other)
    : has_crypto_handshake(other.has_crypto_handshake),
      packet_number(other.packet_number),
      packet_number_length(other.packet_number_length),
      encryption_level(other.encryption_level),
      has_ack(other.has_ack),
      has_stop_waiting(other.has_stop_waiting),
      has_ack_ecn(other.has_ack_ecn),
      transmission_type(other.transmission_type),
      largest_acked(other.largest_acked),
      has_ack_frame_copy(other.has_ack_frame_copy),
      has_ack_frequency(other.has_ack_frequency),
      has_message(other.has_message),
      fate(other.fate),
      peer_address(other.peer_address),
      bytes_not_retransmitted(other.bytes_not_retransmitted),
      initial_header(other.initial_header) {
  if (this != &other) {
    if (release_encrypted_buffer && encrypted_buffer != nullptr) {
      release_encrypted_buffer(encrypted_buffer);
    }
    encrypted_buffer = other.encrypted_buffer;
    encrypted_length = other.encrypted_length;
    release_encrypted_buffer = std::move(other.release_encrypted_buffer);
    other.release_encrypted_buffer = nullptr;

    retransmittable_frames.swap(other.retransmittable_frames);
    nonretransmittable_frames.swap(other.nonretransmittable_frames);
  }
}

SerializedPacket::~SerializedPacket() {
  if (release_encrypted_buffer && encrypted_buffer != nullptr) {
    release_encrypted_buffer(encrypted_buffer);
  }

  if (!retransmittable_frames.empty()) {
    DeleteFrames(&retransmittable_frames);
  }
  for (auto& frame : nonretransmittable_frames) {
    if (!has_ack_frame_copy && frame.type == ACK_FRAME) {
      // Do not delete ack frame if the packet does not own a copy of it.
      continue;
    }
    DeleteFrame(&frame);
  }
}

SerializedPacket* CopySerializedPacket(const SerializedPacket& serialized,
                                       quiche::QuicheBufferAllocator* allocator,
                                       bool copy_buffer) {
  SerializedPacket* copy = new SerializedPacket(
      serialized.packet_number, serialized.packet_number_length,
      serialized.encrypted_buffer, serialized.encrypted_length,
      serialized.has_ack, serialized.has_stop_waiting);
  copy->has_crypto_handshake = serialized.has_crypto_handshake;
  copy->encryption_level = serialized.encryption_level;
  copy->transmission_type = serialized.transmission_type;
  copy->largest_acked = serialized.largest_acked;
  copy->has_ack_frequency = serialized.has_ack_frequency;
  copy->has_message = serialized.has_message;
  copy->fate = serialized.fate;
  copy->peer_address = serialized.peer_address;
  copy->bytes_not_retransmitted = serialized.bytes_not_retransmitted;
  copy->initial_header = serialized.initial_header;
  copy->has_ack_ecn = serialized.has_ack_ecn;

  if (copy_buffer) {
    copy->encrypted_buffer = CopyBuffer(serialized);
    copy->release_encrypted_buffer = [](const char* p) { delete[] p; };
  }
  // Copy underlying frames.
  copy->retransmittable_frames =
      CopyQuicFrames(allocator, serialized.retransmittable_frames);
  QUICHE_DCHECK(copy->nonretransmittable_frames.empty());
  for (const auto& frame : serialized.nonretransmittable_frames) {
    if (frame.type == ACK_FRAME) {
      copy->has_ack_frame_copy = true;
    }
    copy->nonretransmittable_frames.push_back(CopyQuicFrame(allocator, frame));
  }
  return copy;
}

char* CopyBuffer(const SerializedPacket& packet) {
  return CopyBuffer(packet.encrypted_buffer, packet.encrypted_length);
}

char* CopyBuffer(const char* encrypted_buffer,
                 QuicPacketLength encrypted_length) {
  char* dst_buffer = new char[encrypted_length];
  memcpy(dst_buffer, encrypted_buffer, encrypted_length);
  return dst_buffer;
}

ReceivedPacketInfo::ReceivedPacketInfo(const QuicSocketAddress& self_address,
                                       const QuicSocketAddress& peer_address,
                                       const QuicReceivedPacket& packet)
    : self_address(self_address),
      peer_address(peer_address),
      packet(packet),
      form(GOOGLE_QUIC_PACKET),
      long_packet_type(INVALID_PACKET_TYPE),
      version_flag(false),
      use_length_prefix(false),
      version_label(0),
      version(ParsedQuicVersion::Unsupported()),
      destination_connection_id(EmptyQuicConnectionId()),
      source_connection_id(EmptyQuicConnectionId()) {}

ReceivedPacketInfo::~ReceivedPacketInfo() {}

std::string ReceivedPacketInfo::ToString() const {
  std::string output =
      absl::StrCat("{ self_address: ", self_address.ToString(),
                   ", peer_address: ", peer_address.ToString(),
                   ", packet_length: ", packet.length(),
                   ", header_format: ", form, ", version_flag: ", version_flag);
  if (version_flag) {
    absl::StrAppend(&output, ", version: ", ParsedQuicVersionToString(version));
  }
  absl::StrAppend(
      &output,
      ", destination_connection_id: ", destination_connection_id.ToString(),
      ", source_connection_id: ", source_connection_id.ToString(), " }\n");
  return output;
}

std::ostream& operator<<(std::ostream& os,
                         const ReceivedPacketInfo& packet_info) {
  os << packet_info.ToString();
  return os;
}

bool QuicPacketHeader::operator==(const QuicPacketHeader& other) const {
  return destination_connection_id == other.destination_connection_id &&
         destination_connection_id_included ==
             other.destination_connection_id_included &&
         source_connection_id == other.source_connection_id &&
         source_connection_id_included == other.source_connection_id_included &&
         reset_flag == other.reset_flag && version_flag == other.version_flag &&
         has_possible_stateless_reset_token ==
             other.has_possible_stateless_reset_token &&
         packet_number_length == other.packet_number_length &&
         type_byte == other.type_byte && version == other.version &&
         nonce == other.nonce &&
         ((!packet_number.IsInitialized() &&
           !other.packet_number.IsInitialized()) ||
          (packet_number.IsInitialized() &&
           other.packet_number.IsInitialized() &&
           packet_number == other.packet_number)) &&
         form == other.form && long_packet_type == other.long_packet_type &&
         possible_stateless_reset_token ==
             other.possible_stateless_reset_token &&
         retry_token_length_length == other.retry_token_length_length &&
         retry_token == other.retry_token &&
         length_length == other.length_length &&
         remaining_packet_length == other.remaining_packet_length;
}

bool QuicPacketHeader::operator!=(const QuicPacketHeader& other) const {
  return !operator==(other);
}

}  // namespace quic

"""

```