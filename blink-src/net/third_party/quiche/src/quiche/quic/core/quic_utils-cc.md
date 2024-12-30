Response:
Let's break down the thought process for analyzing this C++ file and answering the user's request.

**1. Understanding the Request:**

The user wants to know the functionalities of the `quic_utils.cc` file in Chromium's QUIC implementation. They are also interested in:

* **Relationship to JavaScript:**  Since it's in a browser context, this is a relevant question.
* **Logical Reasoning:**  This usually means identifying functions that perform transformations or decisions based on input. The request asks for hypothetical inputs and outputs.
* **Common Usage Errors:**  Points where developers might misuse the functions.
* **Debugging Context:** How a user action in a browser could lead to this code being executed.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code and look for key elements:

* **Includes:**  These tell us the dependencies and give hints about the functionalities (e.g., `<string>`, `<algorithm>`, `openssl/sha.h`, and importantly, other `quic/core` headers).
* **Namespace:** `namespace quic` confirms its role within the QUIC library.
* **Helper Macros/Functions:**  `QUIC_UTIL_HAS_UINT128`, `IncrementalHashFast`, `IncrementalHashSlow`, `IncrementalHash` – these suggest hashing functionalities.
* **Public Static Functions:** These are the primary interface of the utility class. Listing them out helps organize the functionalities: `FNV1a_64_Hash`, `FNV1a_128_Hash`, `SerializeUint128Short`, `AddressChangeTypeToString`, `SentPacketStateToString`, `QuicLongHeaderTypetoString`, `AckResultToString`, `DetermineAddressChangeType`, `IsAckable`, `IsRetransmittableFrame`, `IsHandshakeFrame`, `ContainsFrameType`, `RetransmissionTypeToPacketState`, `IsIetfPacketHeader`, `IsIetfPacketShortHeader`, `GetInvalidStreamId`, `GetCryptoStreamId`, `IsCryptoStreamId`, `GetHeadersStreamId`, `IsClientInitiatedStreamId`, `IsServerInitiatedStreamId`, `IsOutgoingStreamId`, `IsBidirectionalStreamId`, `GetStreamType`, `StreamIdDelta`, `GetFirstBidirectionalStreamId`, `GetFirstUnidirectionalStreamId`, `GetMaxClientInitiatedBidirectionalStreamId`, `CreateRandomConnectionId`, `CreateZeroConnectionId`, `IsConnectionIdLengthValidForVersion`, `IsConnectionIdValidForVersion`, `GenerateStatelessResetToken`, `GetMaxStreamCount`, `GetPacketNumberSpace`, `GetEncryptionLevelToSendAckofSpace`, `IsProbingFrame`, `IsAckElicitingFrame`, `AreStatelessResetTokensEqual`, `IsValidWebTransportSessionId`, `MemSliceSpanTotalSize`, `PosixBasename`, `RawSha256`.
* **Enums:** `AddressChangeType`, `SentPacketState`, `QuicLongHeaderType`, `AckResult` – these define categories and their string representation functions are present.
* **Constants:**  `kOffset`, `kPrime` in hashing, and others like `kQuicDefaultConnectionIdLength`.

**3. Categorizing Functionalities:**

Based on the identified functions, we can group them into logical categories:

* **Hashing:**  `FNV1a_64_Hash`, `FNV1a_128_Hash`, `IncrementalHash`.
* **Serialization:** `SerializeUint128Short`.
* **String Conversion (for Debugging/Logging):** Functions like `AddressChangeTypeToString`, `SentPacketStateToString`, etc.
* **Address Management:** `DetermineAddressChangeType`.
* **Packet and Frame Type Checks:** `IsAckable`, `IsRetransmittableFrame`, `IsHandshakeFrame`, `ContainsFrameType`, `IsIetfPacketHeader`, `IsIetfPacketShortHeader`, `IsProbingFrame`, `IsAckElicitingFrame`.
* **Stream ID Management:**  `GetInvalidStreamId`, `GetCryptoStreamId`, `IsCryptoStreamId`, `GetHeadersStreamId`, `IsClientInitiatedStreamId`, `IsServerInitiatedStreamId`, `IsOutgoingStreamId`, `IsBidirectionalStreamId`, `GetStreamType`, `StreamIdDelta`, `GetFirstBidirectionalStreamId`, `GetFirstUnidirectionalStreamId`, `GetMaxClientInitiatedBidirectionalStreamId`, `IsValidWebTransportSessionId`.
* **Connection ID Management:** `CreateRandomConnectionId`, `CreateZeroConnectionId`, `IsConnectionIdLengthValidForVersion`, `IsConnectionIdValidForVersion`, `GenerateStatelessResetToken`.
* **Packet Number Space Management:** `GetPacketNumberSpace`, `GetEncryptionLevelToSendAckofSpace`.
* **Other Utilities:** `GetMaxStreamCount`, `AreStatelessResetTokensEqual`, `MemSliceSpanTotalSize`, `PosixBasename`, `RawSha256`.

**4. Addressing the JavaScript Relationship:**

The key is to understand the *role* of this C++ code in the browser. It's part of the *network stack*. JavaScript in a web page doesn't directly call these C++ functions. Instead, it uses higher-level Web APIs (like `fetch` or WebSockets). The browser's internal implementation of these APIs will eventually interact with the QUIC stack. Therefore, the connection is *indirect*. Focus on *what* QUIC does for the browser that JavaScript utilizes.

**5. Logical Reasoning - Hypothetical Inputs and Outputs:**

Choose a few representative functions and devise simple scenarios. For example, for `DetermineAddressChangeType`, pick different IP address and port combinations to illustrate the logic. For stream ID functions, consider client vs. server perspectives and different versions of QUIC.

**6. Common Usage Errors:**

Think about how a developer working on the QUIC implementation (or a related network component) might misuse these utilities. Focus on:

* **Incorrect assumptions about stream IDs:**  Especially with different QUIC versions.
* **Mismatched connection ID lengths:**  Forcing incompatible lengths.
* **Incorrectly interpreting return values:**  Like assuming a function always returns a valid stream ID.

**7. Debugging Context - User Actions:**

Trace a simple user action (like visiting a website) down to the QUIC layer. Consider:

* **DNS lookup:**  How the browser finds the server's IP address.
* **Establishing a QUIC connection:**  The handshake process.
* **Data transfer:**  Requesting web resources.
* **Potential network changes:** Leading to address migration scenarios.

**8. Structuring the Answer:**

Organize the findings into clear sections as requested by the user. Use bullet points and examples to make the information easy to understand. Start with a high-level overview of the file's purpose.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe JavaScript directly calls these functions via some binding mechanism. **Correction:**  Realized the interaction is through higher-level browser APIs.
* **Initial focus on technical details of hashing:** **Refinement:**  Broadened the explanation to cover the *purpose* of hashing in QUIC (like generating reset tokens).
* **Overly complex hypothetical scenarios:** **Simplification:**  Used easier-to-understand examples for inputs and outputs.
* **Vague examples of user errors:** **Specificity:**  Provided concrete examples like using the wrong stream ID for a specific QUIC version.

By following these steps, iterating through the code, and thinking about the context, a comprehensive and accurate answer can be constructed.
这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_utils.cc` 是 Chromium 网络栈中 QUIC 协议实现的核心工具类，它提供了一系列静态实用函数，用于处理 QUIC 协议中的各种通用任务和数据转换。

**主要功能列举:**

1. **哈希计算:**
   - 提供 FNV-1a 64 位和 128 位哈希函数的实现，用于快速计算数据的哈希值。
   - 提供增量哈希函数 `IncrementalHash`，可以逐步计算数据的哈希值，避免一次性加载所有数据。

2. **数据序列化/反序列化:**
   - 提供 `SerializeUint128Short` 函数，用于将 128 位无符号整数序列化为字节数组。

3. **字符串转换:**
   - 提供将枚举类型转换为字符串的函数，方便调试和日志记录，例如：
     - `AddressChangeTypeToString`: 将 `AddressChangeType` 枚举值转换为字符串表示。
     - `SentPacketStateToString`: 将 `SentPacketState` 枚举值转换为字符串表示。
     - `QuicLongHeaderTypetoString`: 将 `QuicLongHeaderType` 枚举值转换为字符串表示。
     - `AckResultToString`: 将 `AckResult` 枚举值转换为字符串表示。

4. **地址变更检测:**
   - 提供 `DetermineAddressChangeType` 函数，用于比较两个 `QuicSocketAddress` 对象，判断地址变更的类型 (例如：端口变更、IPv4 子网变更、IPv4 到 IPv6 的变更等)。

5. **数据包状态判断:**
   - 提供 `IsAckable` 函数，判断给定的 `SentPacketState` 是否是可被 ACK 的状态。
   - 提供 `IsRetransmittableFrame` 函数，判断给定的 `QuicFrameType` 是否是需要重传的帧类型。
   - 提供 `IsHandshakeFrame` 函数，判断给定的 `QuicFrame` 是否是握手帧。

6. **帧类型判断:**
   - 提供 `ContainsFrameType` 函数，检查 `QuicFrames` 列表中是否包含指定类型的帧。
   - 提供 `IsProbingFrame` 函数，判断给定的 `QuicFrameType` 是否是探测帧。
   - 提供 `IsAckElicitingFrame` 函数，判断给定的 `QuicFrameType` 是否是需要应答的帧。

7. **数据包重传类型转换:**
   - 提供 `RetransmissionTypeToPacketState` 函数，将 `TransmissionType` (重传类型) 转换为相应的 `SentPacketState`。

8. **IETF QUIC 数据包头部判断:**
   - 提供 `IsIetfPacketHeader` 和 `IsIetfPacketShortHeader` 函数，判断数据包头部是否符合 IETF QUIC 标准。

9. **流 ID 管理:**
   - 提供获取特定用途的流 ID 的函数，例如：
     - `GetInvalidStreamId`: 获取无效的流 ID。
     - `GetCryptoStreamId`: 获取加密流的流 ID。
     - `GetHeadersStreamId`: 获取 HTTP 头部流的流 ID。
   - 提供判断流 ID 类型的函数，例如：
     - `IsClientInitiatedStreamId`: 判断流 ID 是否由客户端发起。
     - `IsServerInitiatedStreamId`: 判断流 ID 是否由服务端发起。
     - `IsOutgoingStreamId`: 判断流 ID 是否是本地端发起的流。
     - `IsBidirectionalStreamId`: 判断流 ID 是否是双向流。
   - 提供获取流类型的函数 `GetStreamType`。
   - 提供计算流 ID 增量的函数 `StreamIdDelta`。
   - 提供获取第一个双向流和单向流 ID 的函数 (`GetFirstBidirectionalStreamId`, `GetFirstUnidirectionalStreamId`)。
   - 提供获取客户端可以发起的最大双向流 ID 的函数 `GetMaxClientInitiatedBidirectionalStreamId`。
   - 提供判断 WebTransport 会话 ID 是否有效的函数 `IsValidWebTransportSessionId`。

10. **连接 ID 管理:**
    - 提供创建随机连接 ID 的函数 (`CreateRandomConnectionId`)。
    - 提供创建全零连接 ID 的函数 `CreateZeroConnectionId`。
    - 提供校验连接 ID 长度是否对给定 QUIC 版本有效的函数 (`IsConnectionIdLengthValidForVersion`, `IsConnectionIdValidForVersion`)。
    - 提供生成无状态重置 Token 的函数 `GenerateStatelessResetToken`。
    - 提供比较两个无状态重置 Token 是否相等的函数 `AreStatelessResetTokensEqual`。

11. **流数量管理:**
    - 提供获取最大流数量的函数 `GetMaxStreamCount`。

12. **数据包编号空间管理:**
    - 提供根据加密级别获取数据包编号空间的函数 `GetPacketNumberSpace`。
    - 提供根据数据包编号空间获取发送 ACK 所需加密级别的函数 `GetEncryptionLevelToSendAckofSpace`。

13. **内存切片操作:**
    - 提供计算一组内存切片总大小的函数 `MemSliceSpanTotalSize`。

14. **路径操作:**
    - 提供获取路径basename的函数 `PosixBasename`。

15. **SHA-256 哈希:**
    - 提供计算字符串 SHA-256 哈希值的函数 `RawSha256`。

**与 JavaScript 的关系:**

这个 C++ 文件本身并不直接与 JavaScript 代码交互。然而，它作为 Chromium 网络栈的一部分，为浏览器提供底层的 QUIC 协议支持。当 JavaScript 代码通过 Web API (例如 `fetch`, WebSockets) 发起网络请求时，如果协议协商结果是 QUIC，那么底层的 C++ QUIC 实现（包括 `quic_utils.cc` 中的函数）会被调用来处理 QUIC 连接的建立、数据传输、错误处理等。

**举例说明:**

当 JavaScript 代码使用 `fetch` API 请求一个使用 HTTPS/QUIC 的资源时，浏览器内部会经过以下步骤，可能涉及到 `quic_utils.cc` 中的功能：

1. **协议协商:** 浏览器会尝试与服务器协商使用 QUIC 协议。
2. **连接建立:** 如果协商成功，QUIC 连接建立过程会用到 `CreateRandomConnectionId` 生成连接 ID。
3. **数据包发送:** 当发送 HTTP 请求时，数据会被封装成 QUIC 数据包，可能需要使用哈希函数（如 `FNV1a_64_Hash`）来做一些完整性校验或者内部索引。
4. **数据包接收:** 接收到服务器的 QUIC 数据包后，需要解析数据包头部，可能用到 `IsIetfPacketHeader` 来判断头部格式。
5. **流管理:**  请求和响应的数据会通过 QUIC 流进行传输，需要使用 `IsClientInitiatedStreamId` 或 `IsServerInitiatedStreamId` 来判断流的来源。
6. **地址迁移:** 如果客户端的网络地址发生变化，`DetermineAddressChangeType` 会被用来判断地址变更的类型。
7. **错误处理:** 如果连接出现问题，可能会用到 `SentPacketStateToString` 等函数来记录和调试错误信息。

**逻辑推理 - 假设输入与输出:**

**例子 1: `DetermineAddressChangeType`**

* **假设输入:**
    * `old_address`:  IPv4 地址 "192.168.1.100:12345"
    * `new_address`:  IPv4 地址 "192.168.1.100:54321"
* **输出:** `PORT_CHANGE`

* **假设输入:**
    * `old_address`:  IPv4 地址 "192.168.1.100:12345"
    * `new_address`:  IPv4 地址 "192.168.2.100:12345"
* **输出:** `IPV4_TO_IPV4_CHANGE`

* **假设输入:**
    * `old_address`:  IPv4 地址 "192.168.1.100:12345"
    * `new_address`:  IPv6 地址 "[2001:db8::1]:12345"
* **输出:** `IPV4_TO_IPV6_CHANGE`

**例子 2: `IsClientInitiatedStreamId` (假设使用 IETF QUIC)**

* **假设输入:**
    * `version`:  支持 IETF QUIC 的版本 (例如 `QUIC_VERSION_T059`)
    * `id`:  流 ID `0`
* **输出:** `true` (偶数 ID 由客户端发起)

* **假设输入:**
    * `version`:  支持 IETF QUIC 的版本
    * `id`:  流 ID `1`
* **输出:** `false` (奇数 ID 由服务端发起)

**常见使用错误举例:**

1. **错误地假设流 ID 的来源:**  在处理 QUIC 流时，开发者可能错误地假设所有偶数 ID 都是客户端发起的，而忽略了 QUIC 版本之间的差异。例如，在早期的 Google QUIC 版本中，客户端发起的双向流 ID 是奇数。

   ```c++
   // 错误示例：假设所有偶数 ID 都是客户端发起的
   bool is_client_stream(QuicStreamId id) {
     return id % 2 == 0; // 对于旧版本 QUIC 是错误的
   }

   // 正确做法：使用 QuicUtils 提供的函数
   bool is_client_stream_correct(ParsedQuicVersion version, QuicStreamId id) {
     return QuicUtils::IsClientInitiatedStreamId(version.transport_version, id);
   }
   ```

2. **使用不兼容的连接 ID 长度:**  开发者可能在创建连接时使用了与当前 QUIC 版本不兼容的连接 ID 长度。早期的 QUIC 版本只支持固定长度的连接 ID，而 IETF QUIC 允许可变长度。

   ```c++
   // 错误示例：在旧版本 QUIC 中使用非 8 字节的连接 ID
   QuicConnectionId cid;
   cid.set_length(10); // 对于不支持可变长度的版本是错误的

   // 正确做法：使用 QuicUtils 检查连接 ID 长度的有效性
   uint8_t desired_length = 10;
   QuicTransportVersion version = QUIC_VERSION_46; // 假设是旧版本
   if (QuicUtils::IsConnectionIdLengthValidForVersion(desired_length, version)) {
     // 创建连接 ID
   } else {
     // 处理错误
   }
   ```

**用户操作如何一步步到达这里 (调试线索):**

假设用户在 Chrome 浏览器中访问一个使用了 QUIC 协议的网站 (例如，YouTube 或 Google 搜索)。

1. **用户在地址栏输入网址并按下回车，或者点击一个链接。**
2. **Chrome 浏览器首先会进行 DNS 查询，获取服务器的 IP 地址。**
3. **浏览器会尝试与服务器建立连接，并进行协议协商，看是否支持 QUIC。**
4. **如果协商成功，浏览器会尝试建立 QUIC 连接。**  在这个过程中，`quic_utils.cc` 中的 `CreateRandomConnectionId` 可能会被调用来生成客户端的连接 ID。
5. **浏览器发送初始的 QUIC 握手数据包。**  在这个过程中，可能需要使用哈希函数来计算某些校验值。
6. **服务器响应握手数据包。**  浏览器接收到数据包后，会使用 `IsIetfPacketHeader` 等函数来解析数据包头部。
7. **连接建立完成后，浏览器开始发送 HTTP 请求。** 请求数据会被封装成 QUIC 数据帧，并分配相应的流 ID。`IsClientInitiatedStreamId` 会被用来确定流 ID 的性质。
8. **如果用户的网络环境发生变化，例如从 Wi-Fi 切换到移动网络，或者 NAT 设备进行了端口映射的改变。**  QUIC 连接可能会尝试进行地址迁移，此时 `DetermineAddressChangeType` 会被调用来判断地址变更的类型。
9. **在整个连接过程中，如果发生丢包或者需要重传数据包。**  `IsRetransmittableFrame` 会判断帧是否需要重传，`RetransmissionTypeToPacketState` 会将重传类型转换为数据包状态。
10. **如果连接出现错误，或者服务器发送了连接关闭帧。**  `SentPacketStateToString` 等函数可能会被用于生成调试信息。

因此，几乎所有与 QUIC 协议相关的网络操作，从连接建立到数据传输再到连接关闭，都有可能间接地调用到 `quic_utils.cc` 中提供的实用函数。在调试 QUIC 相关问题时，理解这些工具函数的功能非常有帮助。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_utils.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_utils.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>

#include "absl/base/macros.h"
#include "absl/base/optimization.h"
#include "absl/numeric/int128.h"
#include "absl/strings/string_view.h"
#include "openssl/sha.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/quiche_endian.h"

namespace quic {
namespace {

// We know that >= GCC 4.8 and Clang have a __uint128_t intrinsic. Other
// compilers don't necessarily, notably MSVC.
#if defined(__x86_64__) &&                                         \
    ((defined(__GNUC__) &&                                         \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8))) || \
     defined(__clang__))
#define QUIC_UTIL_HAS_UINT128 1
#endif

#ifdef QUIC_UTIL_HAS_UINT128
absl::uint128 IncrementalHashFast(absl::uint128 uhash, absl::string_view data) {
  // This code ends up faster than the naive implementation for 2 reasons:
  // 1. absl::uint128 is sufficiently complicated that the compiler
  //    cannot transform the multiplication by kPrime into a shift-multiply-add;
  //    it has go through all of the instructions for a 128-bit multiply.
  // 2. Because there are so fewer instructions (around 13), the hot loop fits
  //    nicely in the instruction queue of many Intel CPUs.
  // kPrime = 309485009821345068724781371
  static const absl::uint128 kPrime =
      (static_cast<absl::uint128>(16777216) << 64) + 315;
  auto hi = absl::Uint128High64(uhash);
  auto lo = absl::Uint128Low64(uhash);
  absl::uint128 xhash = (static_cast<absl::uint128>(hi) << 64) + lo;
  const uint8_t* octets = reinterpret_cast<const uint8_t*>(data.data());
  for (size_t i = 0; i < data.length(); ++i) {
    xhash = (xhash ^ static_cast<uint32_t>(octets[i])) * kPrime;
  }
  return absl::MakeUint128(absl::Uint128High64(xhash),
                           absl::Uint128Low64(xhash));
}
#endif

#ifndef QUIC_UTIL_HAS_UINT128
// Slow implementation of IncrementalHash. In practice, only used by Chromium.
absl::uint128 IncrementalHashSlow(absl::uint128 hash, absl::string_view data) {
  // kPrime = 309485009821345068724781371
  static const absl::uint128 kPrime = absl::MakeUint128(16777216, 315);
  const uint8_t* octets = reinterpret_cast<const uint8_t*>(data.data());
  for (size_t i = 0; i < data.length(); ++i) {
    hash = hash ^ absl::MakeUint128(0, octets[i]);
    hash = hash * kPrime;
  }
  return hash;
}
#endif

absl::uint128 IncrementalHash(absl::uint128 hash, absl::string_view data) {
#ifdef QUIC_UTIL_HAS_UINT128
  return IncrementalHashFast(hash, data);
#else
  return IncrementalHashSlow(hash, data);
#endif
}

}  // namespace

// static
uint64_t QuicUtils::FNV1a_64_Hash(absl::string_view data) {
  static const uint64_t kOffset = UINT64_C(14695981039346656037);
  static const uint64_t kPrime = UINT64_C(1099511628211);

  const uint8_t* octets = reinterpret_cast<const uint8_t*>(data.data());

  uint64_t hash = kOffset;

  for (size_t i = 0; i < data.length(); ++i) {
    hash = hash ^ octets[i];
    hash = hash * kPrime;
  }

  return hash;
}

// static
absl::uint128 QuicUtils::FNV1a_128_Hash(absl::string_view data) {
  return FNV1a_128_Hash_Three(data, absl::string_view(), absl::string_view());
}

// static
absl::uint128 QuicUtils::FNV1a_128_Hash_Two(absl::string_view data1,
                                            absl::string_view data2) {
  return FNV1a_128_Hash_Three(data1, data2, absl::string_view());
}

// static
absl::uint128 QuicUtils::FNV1a_128_Hash_Three(absl::string_view data1,
                                              absl::string_view data2,
                                              absl::string_view data3) {
  // The two constants are defined as part of the hash algorithm.
  // see http://www.isthe.com/chongo/tech/comp/fnv/
  // kOffset = 144066263297769815596495629667062367629
  const absl::uint128 kOffset = absl::MakeUint128(
      UINT64_C(7809847782465536322), UINT64_C(7113472399480571277));

  absl::uint128 hash = IncrementalHash(kOffset, data1);
  if (data2.empty()) {
    return hash;
  }

  hash = IncrementalHash(hash, data2);
  if (data3.empty()) {
    return hash;
  }
  return IncrementalHash(hash, data3);
}

// static
void QuicUtils::SerializeUint128Short(absl::uint128 v, uint8_t* out) {
  const uint64_t lo = absl::Uint128Low64(v);
  const uint64_t hi = absl::Uint128High64(v);
  // This assumes that the system is little-endian.
  memcpy(out, &lo, sizeof(lo));
  memcpy(out + sizeof(lo), &hi, sizeof(hi) / 2);
}

#define RETURN_STRING_LITERAL(x) \
  case x:                        \
    return #x;

std::string QuicUtils::AddressChangeTypeToString(AddressChangeType type) {
  switch (type) {
    RETURN_STRING_LITERAL(NO_CHANGE);
    RETURN_STRING_LITERAL(PORT_CHANGE);
    RETURN_STRING_LITERAL(IPV4_SUBNET_CHANGE);
    RETURN_STRING_LITERAL(IPV4_TO_IPV6_CHANGE);
    RETURN_STRING_LITERAL(IPV6_TO_IPV4_CHANGE);
    RETURN_STRING_LITERAL(IPV6_TO_IPV6_CHANGE);
    RETURN_STRING_LITERAL(IPV4_TO_IPV4_CHANGE);
  }
  return "INVALID_ADDRESS_CHANGE_TYPE";
}

const char* QuicUtils::SentPacketStateToString(SentPacketState state) {
  switch (state) {
    RETURN_STRING_LITERAL(OUTSTANDING);
    RETURN_STRING_LITERAL(NEVER_SENT);
    RETURN_STRING_LITERAL(ACKED);
    RETURN_STRING_LITERAL(UNACKABLE);
    RETURN_STRING_LITERAL(NEUTERED);
    RETURN_STRING_LITERAL(HANDSHAKE_RETRANSMITTED);
    RETURN_STRING_LITERAL(LOST);
    RETURN_STRING_LITERAL(PTO_RETRANSMITTED);
    RETURN_STRING_LITERAL(NOT_CONTRIBUTING_RTT);
  }
  return "INVALID_SENT_PACKET_STATE";
}

// static
const char* QuicUtils::QuicLongHeaderTypetoString(QuicLongHeaderType type) {
  switch (type) {
    RETURN_STRING_LITERAL(VERSION_NEGOTIATION);
    RETURN_STRING_LITERAL(INITIAL);
    RETURN_STRING_LITERAL(RETRY);
    RETURN_STRING_LITERAL(HANDSHAKE);
    RETURN_STRING_LITERAL(ZERO_RTT_PROTECTED);
    default:
      return "INVALID_PACKET_TYPE";
  }
}

// static
const char* QuicUtils::AckResultToString(AckResult result) {
  switch (result) {
    RETURN_STRING_LITERAL(PACKETS_NEWLY_ACKED);
    RETURN_STRING_LITERAL(NO_PACKETS_NEWLY_ACKED);
    RETURN_STRING_LITERAL(UNSENT_PACKETS_ACKED);
    RETURN_STRING_LITERAL(UNACKABLE_PACKETS_ACKED);
    RETURN_STRING_LITERAL(PACKETS_ACKED_IN_WRONG_PACKET_NUMBER_SPACE);
  }
  return "INVALID_ACK_RESULT";
}

// static
AddressChangeType QuicUtils::DetermineAddressChangeType(
    const QuicSocketAddress& old_address,
    const QuicSocketAddress& new_address) {
  if (!old_address.IsInitialized() || !new_address.IsInitialized() ||
      old_address == new_address) {
    return NO_CHANGE;
  }

  if (old_address.host() == new_address.host()) {
    return PORT_CHANGE;
  }

  bool old_ip_is_ipv4 = old_address.host().IsIPv4() ? true : false;
  bool migrating_ip_is_ipv4 = new_address.host().IsIPv4() ? true : false;
  if (old_ip_is_ipv4 && !migrating_ip_is_ipv4) {
    return IPV4_TO_IPV6_CHANGE;
  }

  if (!old_ip_is_ipv4) {
    return migrating_ip_is_ipv4 ? IPV6_TO_IPV4_CHANGE : IPV6_TO_IPV6_CHANGE;
  }

  const int kSubnetMaskLength = 24;
  if (old_address.host().InSameSubnet(new_address.host(), kSubnetMaskLength)) {
    // Subnet part does not change (here, we use /24), which is considered to be
    // caused by NATs.
    return IPV4_SUBNET_CHANGE;
  }

  return IPV4_TO_IPV4_CHANGE;
}

// static
bool QuicUtils::IsAckable(SentPacketState state) {
  return state != NEVER_SENT && state != ACKED && state != UNACKABLE;
}

// static
bool QuicUtils::IsRetransmittableFrame(QuicFrameType type) {
  switch (type) {
    case ACK_FRAME:
    case PADDING_FRAME:
    case STOP_WAITING_FRAME:
    case MTU_DISCOVERY_FRAME:
    case PATH_CHALLENGE_FRAME:
    case PATH_RESPONSE_FRAME:
      return false;
    default:
      return true;
  }
}

// static
bool QuicUtils::IsHandshakeFrame(const QuicFrame& frame,
                                 QuicTransportVersion transport_version) {
  if (!QuicVersionUsesCryptoFrames(transport_version)) {
    return frame.type == STREAM_FRAME &&
           frame.stream_frame.stream_id == GetCryptoStreamId(transport_version);
  } else {
    return frame.type == CRYPTO_FRAME;
  }
}

// static
bool QuicUtils::ContainsFrameType(const QuicFrames& frames,
                                  QuicFrameType type) {
  for (const QuicFrame& frame : frames) {
    if (frame.type == type) {
      return true;
    }
  }
  return false;
}

// static
SentPacketState QuicUtils::RetransmissionTypeToPacketState(
    TransmissionType retransmission_type) {
  switch (retransmission_type) {
    case ALL_ZERO_RTT_RETRANSMISSION:
      return UNACKABLE;
    case HANDSHAKE_RETRANSMISSION:
      return HANDSHAKE_RETRANSMITTED;
    case LOSS_RETRANSMISSION:
      return LOST;
    case PTO_RETRANSMISSION:
      return PTO_RETRANSMITTED;
    case PATH_RETRANSMISSION:
      return NOT_CONTRIBUTING_RTT;
    case ALL_INITIAL_RETRANSMISSION:
      return UNACKABLE;
    default:
      QUIC_BUG(quic_bug_10839_2)
          << retransmission_type << " is not a retransmission_type";
      return UNACKABLE;
  }
}

// static
bool QuicUtils::IsIetfPacketHeader(uint8_t first_byte) {
  return (first_byte & FLAGS_LONG_HEADER) || (first_byte & FLAGS_FIXED_BIT) ||
         !(first_byte & FLAGS_DEMULTIPLEXING_BIT);
}

// static
bool QuicUtils::IsIetfPacketShortHeader(uint8_t first_byte) {
  return IsIetfPacketHeader(first_byte) && !(first_byte & FLAGS_LONG_HEADER);
}

// static
QuicStreamId QuicUtils::GetInvalidStreamId(QuicTransportVersion version) {
  return VersionHasIetfQuicFrames(version)
             ? std::numeric_limits<QuicStreamId>::max()
             : 0;
}

// static
QuicStreamId QuicUtils::GetCryptoStreamId(QuicTransportVersion version) {
  QUIC_BUG_IF(quic_bug_12982_1, QuicVersionUsesCryptoFrames(version))
      << "CRYPTO data aren't in stream frames; they have no stream ID.";
  return QuicVersionUsesCryptoFrames(version) ? GetInvalidStreamId(version) : 1;
}

// static
bool QuicUtils::IsCryptoStreamId(QuicTransportVersion version,
                                 QuicStreamId stream_id) {
  if (QuicVersionUsesCryptoFrames(version)) {
    return false;
  }
  return stream_id == GetCryptoStreamId(version);
}

// static
QuicStreamId QuicUtils::GetHeadersStreamId(QuicTransportVersion version) {
  QUICHE_DCHECK(!VersionUsesHttp3(version));
  return GetFirstBidirectionalStreamId(version, Perspective::IS_CLIENT);
}

// static
bool QuicUtils::IsClientInitiatedStreamId(QuicTransportVersion version,
                                          QuicStreamId id) {
  if (id == GetInvalidStreamId(version)) {
    return false;
  }
  return VersionHasIetfQuicFrames(version) ? id % 2 == 0 : id % 2 != 0;
}

// static
bool QuicUtils::IsServerInitiatedStreamId(QuicTransportVersion version,
                                          QuicStreamId id) {
  if (id == GetInvalidStreamId(version)) {
    return false;
  }
  return VersionHasIetfQuicFrames(version) ? id % 2 != 0 : id % 2 == 0;
}

// static
bool QuicUtils::IsOutgoingStreamId(ParsedQuicVersion version, QuicStreamId id,
                                   Perspective perspective) {
  // Streams are outgoing streams, iff:
  // - we are the server and the stream is server-initiated
  // - we are the client and the stream is client-initiated.
  const bool perspective_is_server = perspective == Perspective::IS_SERVER;
  const bool stream_is_server =
      QuicUtils::IsServerInitiatedStreamId(version.transport_version, id);
  return perspective_is_server == stream_is_server;
}

// static
bool QuicUtils::IsBidirectionalStreamId(QuicStreamId id,
                                        ParsedQuicVersion version) {
  QUICHE_DCHECK(version.HasIetfQuicFrames());
  return id % 4 < 2;
}

// static
StreamType QuicUtils::GetStreamType(QuicStreamId id, Perspective perspective,
                                    bool peer_initiated,
                                    ParsedQuicVersion version) {
  QUICHE_DCHECK(version.HasIetfQuicFrames());
  if (IsBidirectionalStreamId(id, version)) {
    return BIDIRECTIONAL;
  }

  if (peer_initiated) {
    if (perspective == Perspective::IS_SERVER) {
      QUICHE_DCHECK_EQ(2u, id % 4);
    } else {
      QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective);
      QUICHE_DCHECK_EQ(3u, id % 4);
    }
    return READ_UNIDIRECTIONAL;
  }

  if (perspective == Perspective::IS_SERVER) {
    QUICHE_DCHECK_EQ(3u, id % 4);
  } else {
    QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, perspective);
    QUICHE_DCHECK_EQ(2u, id % 4);
  }
  return WRITE_UNIDIRECTIONAL;
}

// static
QuicStreamId QuicUtils::StreamIdDelta(QuicTransportVersion version) {
  return VersionHasIetfQuicFrames(version) ? 4 : 2;
}

// static
QuicStreamId QuicUtils::GetFirstBidirectionalStreamId(
    QuicTransportVersion version, Perspective perspective) {
  if (VersionHasIetfQuicFrames(version)) {
    return perspective == Perspective::IS_CLIENT ? 0 : 1;
  } else if (QuicVersionUsesCryptoFrames(version)) {
    return perspective == Perspective::IS_CLIENT ? 1 : 2;
  }
  return perspective == Perspective::IS_CLIENT ? 3 : 2;
}

// static
QuicStreamId QuicUtils::GetFirstUnidirectionalStreamId(
    QuicTransportVersion version, Perspective perspective) {
  if (VersionHasIetfQuicFrames(version)) {
    return perspective == Perspective::IS_CLIENT ? 2 : 3;
  } else if (QuicVersionUsesCryptoFrames(version)) {
    return perspective == Perspective::IS_CLIENT ? 1 : 2;
  }
  return perspective == Perspective::IS_CLIENT ? 3 : 2;
}

// static
QuicStreamId QuicUtils::GetMaxClientInitiatedBidirectionalStreamId(
    QuicTransportVersion version) {
  if (VersionHasIetfQuicFrames(version)) {
    // Client initiated bidirectional streams have stream IDs divisible by 4.
    return std::numeric_limits<QuicStreamId>::max() - 3;
  }

  // Client initiated bidirectional streams have odd stream IDs.
  return std::numeric_limits<QuicStreamId>::max();
}

// static
QuicConnectionId QuicUtils::CreateRandomConnectionId() {
  return CreateRandomConnectionId(kQuicDefaultConnectionIdLength,
                                  QuicRandom::GetInstance());
}

// static
QuicConnectionId QuicUtils::CreateRandomConnectionId(QuicRandom* random) {
  return CreateRandomConnectionId(kQuicDefaultConnectionIdLength, random);
}
// static
QuicConnectionId QuicUtils::CreateRandomConnectionId(
    uint8_t connection_id_length) {
  return CreateRandomConnectionId(connection_id_length,
                                  QuicRandom::GetInstance());
}

// static
QuicConnectionId QuicUtils::CreateRandomConnectionId(
    uint8_t connection_id_length, QuicRandom* random) {
  QuicConnectionId connection_id;
  connection_id.set_length(connection_id_length);
  if (connection_id.length() > 0) {
    random->RandBytes(connection_id.mutable_data(), connection_id.length());
  }
  return connection_id;
}

// static
QuicConnectionId QuicUtils::CreateZeroConnectionId(
    QuicTransportVersion version) {
  if (!VersionAllowsVariableLengthConnectionIds(version)) {
    char connection_id_bytes[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    return QuicConnectionId(static_cast<char*>(connection_id_bytes),
                            ABSL_ARRAYSIZE(connection_id_bytes));
  }
  return EmptyQuicConnectionId();
}

// static
bool QuicUtils::IsConnectionIdLengthValidForVersion(
    size_t connection_id_length, QuicTransportVersion transport_version) {
  // No version of QUIC can support lengths that do not fit in an uint8_t.
  if (connection_id_length >
      static_cast<size_t>(std::numeric_limits<uint8_t>::max())) {
    return false;
  }

  if (transport_version == QUIC_VERSION_UNSUPPORTED ||
      transport_version == QUIC_VERSION_RESERVED_FOR_NEGOTIATION) {
    // Unknown versions could allow connection ID lengths up to 255.
    return true;
  }

  const uint8_t connection_id_length8 =
      static_cast<uint8_t>(connection_id_length);
  // Versions that do not support variable lengths only support length 8.
  if (!VersionAllowsVariableLengthConnectionIds(transport_version)) {
    return connection_id_length8 == kQuicDefaultConnectionIdLength;
  }
  return connection_id_length8 <= kQuicMaxConnectionIdWithLengthPrefixLength;
}

// static
bool QuicUtils::IsConnectionIdValidForVersion(
    QuicConnectionId connection_id, QuicTransportVersion transport_version) {
  return IsConnectionIdLengthValidForVersion(connection_id.length(),
                                             transport_version);
}

StatelessResetToken QuicUtils::GenerateStatelessResetToken(
    QuicConnectionId connection_id) {
  static_assert(sizeof(absl::uint128) == sizeof(StatelessResetToken),
                "bad size");
  static_assert(alignof(absl::uint128) >= alignof(StatelessResetToken),
                "bad alignment");
  absl::uint128 hash = FNV1a_128_Hash(
      absl::string_view(connection_id.data(), connection_id.length()));
  return *reinterpret_cast<StatelessResetToken*>(&hash);
}

// static
QuicStreamCount QuicUtils::GetMaxStreamCount() {
  return (kMaxQuicStreamCount >> 2) + 1;
}

// static
PacketNumberSpace QuicUtils::GetPacketNumberSpace(
    EncryptionLevel encryption_level) {
  switch (encryption_level) {
    case ENCRYPTION_INITIAL:
      return INITIAL_DATA;
    case ENCRYPTION_HANDSHAKE:
      return HANDSHAKE_DATA;
    case ENCRYPTION_ZERO_RTT:
    case ENCRYPTION_FORWARD_SECURE:
      return APPLICATION_DATA;
    default:
      QUIC_BUG(quic_bug_10839_3)
          << "Try to get packet number space of encryption level: "
          << encryption_level;
      return NUM_PACKET_NUMBER_SPACES;
  }
}

// static
EncryptionLevel QuicUtils::GetEncryptionLevelToSendAckofSpace(
    PacketNumberSpace packet_number_space) {
  switch (packet_number_space) {
    case INITIAL_DATA:
      return ENCRYPTION_INITIAL;
    case HANDSHAKE_DATA:
      return ENCRYPTION_HANDSHAKE;
    case APPLICATION_DATA:
      return ENCRYPTION_FORWARD_SECURE;
    default:
      QUICHE_DCHECK(false);
      return NUM_ENCRYPTION_LEVELS;
  }
}

// static
bool QuicUtils::IsProbingFrame(QuicFrameType type) {
  switch (type) {
    case PATH_CHALLENGE_FRAME:
    case PATH_RESPONSE_FRAME:
    case NEW_CONNECTION_ID_FRAME:
    case PADDING_FRAME:
      return true;
    default:
      return false;
  }
}

// static
bool QuicUtils::IsAckElicitingFrame(QuicFrameType type) {
  switch (type) {
    case PADDING_FRAME:
    case STOP_WAITING_FRAME:
    case ACK_FRAME:
    case CONNECTION_CLOSE_FRAME:
      return false;
    default:
      return true;
  }
}

// static
bool QuicUtils::AreStatelessResetTokensEqual(
    const StatelessResetToken& token1, const StatelessResetToken& token2) {
  char byte = 0;
  for (size_t i = 0; i < kStatelessResetTokenLength; i++) {
    // This avoids compiler optimizations that could make us stop comparing
    // after we find a byte that doesn't match.
    byte |= (token1[i] ^ token2[i]);
  }
  return byte == 0;
}

bool IsValidWebTransportSessionId(WebTransportSessionId id,
                                  ParsedQuicVersion version) {
  QUICHE_DCHECK(version.UsesHttp3());
  return (id <= std::numeric_limits<QuicStreamId>::max()) &&
         QuicUtils::IsBidirectionalStreamId(id, version) &&
         QuicUtils::IsClientInitiatedStreamId(version.transport_version, id);
}

QuicByteCount MemSliceSpanTotalSize(absl::Span<quiche::QuicheMemSlice> span) {
  QuicByteCount total = 0;
  for (const quiche::QuicheMemSlice& slice : span) {
    total += slice.length();
  }
  return total;
}

absl::string_view PosixBasename(absl::string_view path) {
  constexpr char kPathSeparator = '/';
  size_t pos = path.find_last_of(kPathSeparator);

  // Handle the case with no `kPathSeparator` in `path`.
  if (pos == absl::string_view::npos) {
    return path;
  }

  // Handle the case with a single leading `kPathSeparator` in `path`.
  if (pos == 0) {
    return absl::ClippedSubstr(path, 1);
  }

  return absl::ClippedSubstr(path, pos + 1);
}

std::string RawSha256(absl::string_view input) {
  std::string raw_hash;
  raw_hash.resize(SHA256_DIGEST_LENGTH);
  SHA256(reinterpret_cast<const uint8_t*>(input.data()), input.size(),
         reinterpret_cast<uint8_t*>(&raw_hash[0]));
  return raw_hash;
}

#undef RETURN_STRING_LITERAL  // undef for jumbo builds
}  // namespace quic

"""

```