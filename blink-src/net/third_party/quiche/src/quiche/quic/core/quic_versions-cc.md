Response:
Let's break down the thought process for analyzing this C++ file and addressing the prompt's questions.

**1. Understanding the Core Functionality:**

The filename `quic_versions.cc` immediately suggests that this file deals with managing and manipulating different versions of the QUIC protocol. Reading through the code confirms this. Key elements that stand out:

* **`ParsedQuicVersion`:**  A central structure representing a specific QUIC version, encapsulating both the transport version and the handshake protocol.
* **`QuicTransportVersion` and `HandshakeProtocol`:** Enums defining the possible values for these components.
* **Version Negotiation:** Functions like `CreateRandomVersionLabelForNegotiation` and the handling of `QUIC_VERSION_RESERVED_FOR_NEGOTIATION` hint at the mechanism for agreeing on a version during connection establishment.
* **Feature Flags:** The use of `GetQuicReloadableFlag` and `SetQuicReloadableFlag` indicates that the availability of certain versions can be controlled at runtime.
* **Version Lists:**  Functions like `AllSupportedVersions`, `CurrentSupportedVersions`, and `FilterSupportedVersions` manage collections of supported versions.
* **String Conversion:**  Functions to convert between `ParsedQuicVersion`, `QuicVersionLabel`, `QuicTransportVersion`, and their string representations are essential for debugging and logging.
* **Version-Specific Features:** Numerous boolean functions (e.g., `HasHeaderProtection`, `SupportsRetry`) determine if a given version supports particular QUIC features.

**2. Identifying Key Functions and Their Purpose:**

I would then mentally (or on scratch paper) categorize the functions based on their roles:

* **Version Representation:** `ParsedQuicVersion`, `QuicTransportVersion`, `HandshakeProtocol`.
* **Version Creation/Parsing:** `MakeVersionLabel`, `CreateQuicVersionLabel`, `ParseQuicVersionLabel`, `ParseQuicVersionString`, `ParseQuicVersionLabelString`.
* **Version Lists & Filtering:** `AllSupportedVersions`, `CurrentSupportedVersions`, `FilterSupportedVersions`, `ObsoleteSupportedVersions`.
* **Version Feature Checks:**  All the `bool ParsedQuicVersion::...()` methods (e.g., `UsesHttp3`, `SupportsRetry`).
* **Version Negotiation Support:** `CreateRandomVersionLabelForNegotiation`, `QuicVersionReservedForNegotiation`.
* **String Conversion:** `ParsedQuicVersionToString`, `QuicVersionToString`, `QuicVersionLabelToString`, etc.
* **ALPN Mapping:** `AlpnForVersion`.
* **Feature Flag Management:** `SetVersionFlag`, `QuicEnableVersion`, `QuicDisableVersion`, `QuicVersionIsEnabled`.

**3. Addressing the Prompt's Specific Questions:**

* **Functionality:** This becomes a summary of the identified key functions and their purposes, as described above. Emphasis should be placed on the core idea of managing and distinguishing between different QUIC versions.

* **Relationship to JavaScript:**  This requires thinking about where QUIC fits in a web browser context. JavaScript running in a browser interacts with the network stack to make HTTP requests (including HTTP/3, which uses QUIC). Therefore, JavaScript *indirectly* relies on the functionality in this file because it influences which QUIC version the browser and server will negotiate. An example scenario involves a browser supporting the latest QUIC version and a server only supporting an older version. This file's logic helps determine the mutually supported version.

* **Logical Reasoning (Hypothetical Input/Output):** Focus on functions that transform data. `ParseQuicVersionString` is a good example. Provide clear inputs (version strings) and the expected output (`ParsedQuicVersion` objects or `UnsupportedQuicVersion`).

* **User/Programming Errors:** Think about common mistakes developers might make when interacting with versioning. Trying to enable an unsupported version, inconsistencies between client and server configurations, or misunderstanding the meaning of different version strings are all possibilities.

* **User Operation to Reach Here (Debugging Clues):** This requires imagining a user experiencing a QUIC-related issue. The steps involve the user initiating a network request, the browser attempting to establish a QUIC connection, and a potential mismatch or failure occurring during version negotiation. This file becomes relevant when debugging such issues because it contains the core logic for version handling.

**4. Structuring the Answer:**

Organize the information logically. Start with a concise summary of the file's purpose. Then, address each of the prompt's questions in a separate section with clear headings. Use code examples where appropriate (especially for the JavaScript and error sections). For the hypothetical input/output, present it as a table or clear input/output pairs.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just lists the QUIC versions."  **Correction:**  It's more than just a list; it actively manages, parses, filters, and determines the capabilities of different versions.
* **Initial thought about JavaScript:** "JavaScript doesn't directly call this C++ code." **Refinement:**  While not a direct call, JavaScript's network requests rely on the underlying QUIC implementation, making this file indirectly relevant.
* **Ensuring clarity:**  Use precise language to describe the different QUIC concepts (transport version, handshake protocol, version labels, ALPN).
* **Double-checking examples:** Verify the accuracy of the hypothetical inputs and outputs, and the user/programming error scenarios.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive and accurate response to the prompt's questions.
这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_versions.cc` 在 Chromium 的网络栈中扮演着至关重要的角色，它的主要功能是**管理和定义 QUIC 协议的不同版本**。  它提供了处理和操作 QUIC 版本信息的各种方法，确保客户端和服务器能够协商并使用兼容的 QUIC 版本进行通信。

以下是该文件的详细功能列表：

1. **定义 QUIC 版本常量:**  定义了各种 QUIC 协议的版本常量，例如 `QUIC_VERSION_46`，`QUIC_VERSION_IETF_DRAFT_29`，`QUIC_VERSION_IETF_RFC_V1`，`QUIC_VERSION_IETF_RFC_V2` 等。 这些常量标识了不同 QUIC 协议规范的特定迭代。

2. **表示和操作 QUIC 版本:** 提供了 `ParsedQuicVersion` 结构体，用于更精细地表示一个 QUIC 版本，包括其传输层版本 (`transport_version`) 和握手协议 (`handshake_protocol`)，例如 `PROTOCOL_QUIC_CRYPTO` 或 `PROTOCOL_TLS1_3`。  该文件包含了许多方法来操作 `ParsedQuicVersion` 对象，例如：
    * 判断版本是否已知 (`IsKnown`)
    * 判断版本是否使用特定的特性，例如头部保护 (`HasHeaderProtection`)、Retry 机制 (`SupportsRetry`)、HTTP/3 (`UsesHttp3`)、TLS 握手 (`UsesTls`) 等。
    * 判断版本是否支持可变长度连接 ID (`AllowsVariableLengthConnectionIds`)

3. **版本协商支持:**  包含用于版本协商的逻辑，例如：
    * 生成用于版本协商的随机版本标签 (`CreateRandomVersionLabelForNegotiation`)。
    * 将 `ParsedQuicVersion` 转换为用于网络传输的版本标签 (`CreateQuicVersionLabel`)。
    * 将版本标签解析回 `ParsedQuicVersion` (`ParseQuicVersionLabel`)。
    * 解析版本标签字符串 (`ParseQuicVersionLabelString`)。

4. **支持的 QUIC 版本管理:**  提供了管理当前支持和所有支持的 QUIC 版本列表的功能：
    * `AllSupportedVersions()`: 返回所有支持的 QUIC 版本列表。
    * `CurrentSupportedVersions()`: 返回当前启用的 QUIC 版本列表（可能受标志位控制）。
    * `FilterSupportedVersions()`:  根据标志位过滤提供的版本列表。
    * `ObsoleteSupportedVersions()`: 返回已过时的 QUIC 版本列表。

5. **字符串表示和解析:**  提供了在不同 QUIC 版本表示形式之间进行转换的功能，方便日志记录和调试：
    * `QuicVersionToString()`: 将 `QuicTransportVersion` 转换为字符串表示。
    * `HandshakeProtocolToString()`: 将 `HandshakeProtocol` 转换为字符串表示。
    * `ParsedQuicVersionToString()`: 将 `ParsedQuicVersion` 转换为字符串表示。
    * `QuicVersionLabelToString()`: 将 `QuicVersionLabel` 转换为字符串表示。
    * `ParseQuicVersionString()`: 将版本字符串解析为 `ParsedQuicVersion`。
    * `ParsedQuicVersionVectorToString()`: 将版本向量转换为字符串表示。

6. **版本特性查询:** 提供了一系列函数来查询特定传输层版本是否支持某些特性，例如 `VersionAllowsVariableLengthConnectionIds()`，`VersionSupportsGoogleAltSvcFormat()` 等。

7. **通过 Feature Flag 控制版本:**  使用 Chromium 的 feature flag 机制 (`SetQuicReloadableFlag`) 来启用或禁用特定的 QUIC 版本。这允许在运行时动态调整支持的 QUIC 版本。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所管理的 QUIC 版本信息对于 JavaScript 在 Web 浏览器中的网络通信至关重要。  当 JavaScript 发起一个网络请求 (例如使用 `fetch` API) 时，如果协议是 `https://`，浏览器会尝试使用 HTTP/3 over QUIC。

1. **版本协商:**  浏览器内部的网络栈（由 C++ 实现）会使用此文件中定义的版本信息来与服务器进行 QUIC 版本协商。浏览器会发送一个包含其支持的 QUIC 版本列表的 Initial 包。服务器会选择一个它也支持的版本，并在其响应中指明。这个过程直接依赖于 `quic_versions.cc` 中定义的版本常量和协商逻辑。

2. **Feature 支持:** JavaScript 无法直接感知底层的 QUIC 版本，但 QUIC 版本的选择会影响可用的网络特性。 例如，如果协商使用了较旧的 QUIC 版本，可能不支持头部保护或某些拥塞控制算法。这会间接影响 JavaScript 发起的网络请求的性能和安全性。

**举例说明:**

假设一个浏览器支持最新的 QUIC v2 版本 (`RFCv2`) 和一个旧版本 (`Q046`)。 一个服务器只支持 `Q046`。

* **假设输入（JavaScript 发起请求）:**  JavaScript 代码执行 `fetch('https://example.com')`。
* **逻辑推理（C++ 代码处理版本协商）:**
    * 浏览器会读取 `CurrentSupportedVersions()`，其中包含 `RFCv2` 和 `Q046`。
    * 浏览器会生成一个包含 `RFCv2` 和 `Q046` 对应的 `QuicVersionLabel` 的 ClientHello 包。
    * 服务器收到 ClientHello，发现它只支持 `Q046`。
    * 服务器会在 Version Negotiation 包中或者在 ServerHello 中选择 `Q046`。
* **输出（最终协商的版本）:** 最终客户端和服务器会协商使用 `Q046` 进行通信。

**用户或编程常见的使用错误:**

1. **配置不一致:**  服务器和客户端配置了不同的支持 QUIC 版本列表，导致无法找到共同支持的版本，连接失败。
    * **示例:** 服务器管理员错误地禁用了最新的 QUIC 版本，而客户端默认尝试使用最新版本。
    * **错误信息:**  可能会看到类似 "No acceptable QUIC version found" 的错误信息。

2. **强制使用不支持的版本:** 尝试强制连接到只支持特定旧版本 QUIC 的服务器，但客户端已禁用了该版本。
    * **示例:**  一个应用程序尝试连接到一个旧的 QUIC 服务，但该应用程序运行环境的 QUIC 配置禁用了该旧版本。

3. **误解版本字符串:**  在配置或日志中错误地理解 QUIC 版本字符串的含义，例如混淆传输层版本号和版本标签。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问一个网站或应用程序:** 用户在浏览器中输入网址或打开一个使用网络连接的应用程序。

2. **浏览器/应用程序尝试建立 HTTPS 连接:**  浏览器或应用程序尝试与服务器建立安全连接。

3. **尝试 QUIC 连接:**  如果服务器支持 QUIC，并且客户端也启用了 QUIC，客户端会尝试建立 QUIC 连接。

4. **版本协商失败或遇到版本相关的错误:**  在 QUIC 连接建立的早期阶段，客户端和服务器会进行版本协商。如果协商失败（例如没有共同支持的版本），或者在通信过程中遇到版本相关的错误（例如使用了旧版本不支持的特性），网络栈的代码会涉及到 `quic_versions.cc` 中的逻辑。

5. **调试信息/日志记录:**  当出现 QUIC 连接问题时，开发者或系统管理员可能会查看网络日志或 Chromium 的内部日志。这些日志通常会包含 QUIC 版本信息，例如客户端发送的版本列表，服务器选择的版本等。`quic_versions.cc` 中的字符串转换函数 (`ParsedQuicVersionToString`, `QuicVersionLabelToString` 等) 在生成这些日志信息时会被调用。

6. **代码断点/性能分析:**  在开发或调试 QUIC 相关功能时，开发者可能会在 `quic_versions.cc` 中的关键函数设置断点，以查看版本协商的流程，或者分析与版本相关的性能问题。

总而言之，`net/third_party/quiche/src/quiche/quic/core/quic_versions.cc` 是 Chromium 网络栈中管理 QUIC 协议版本的核心文件，它直接影响着浏览器与服务器之间 QUIC 连接的建立和功能特性。 虽然 JavaScript 开发者不会直接操作这个文件中的代码，但理解其功能对于理解基于 QUIC 的网络通信至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_versions.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_versions.h"

#include <algorithm>
#include <ostream>
#include <string>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_tag.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/quiche_endian.h"
#include "quiche/common/quiche_text_utils.h"

namespace quic {
namespace {

QuicVersionLabel CreateRandomVersionLabelForNegotiation() {
  QuicVersionLabel result;
  if (!GetQuicFlag(quic_disable_version_negotiation_grease_randomness)) {
    QuicRandom::GetInstance()->RandBytes(&result, sizeof(result));
  } else {
    result = MakeVersionLabel(0xd1, 0x57, 0x38, 0x3f);
  }
  result &= 0xf0f0f0f0;
  result |= 0x0a0a0a0a;
  return result;
}

void SetVersionFlag(const ParsedQuicVersion& version, bool should_enable) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  const bool enable = should_enable;
  const bool disable = !should_enable;
  if (version == ParsedQuicVersion::RFCv2()) {
    SetQuicReloadableFlag(quic_enable_version_rfcv2, enable);
  } else if (version == ParsedQuicVersion::RFCv1()) {
    SetQuicReloadableFlag(quic_disable_version_rfcv1, disable);
  } else if (version == ParsedQuicVersion::Draft29()) {
    SetQuicReloadableFlag(quic_disable_version_draft_29, disable);
  } else if (version == ParsedQuicVersion::Q046()) {
    SetQuicReloadableFlag(quic_disable_version_q046, disable);
  } else {
    QUIC_BUG(quic_bug_10589_1)
        << "Cannot " << (enable ? "en" : "dis") << "able version " << version;
  }
}

}  // namespace

bool ParsedQuicVersion::IsKnown() const {
  QUICHE_DCHECK(ParsedQuicVersionIsValid(handshake_protocol, transport_version))
      << QuicVersionToString(transport_version) << " "
      << HandshakeProtocolToString(handshake_protocol);
  return transport_version != QUIC_VERSION_UNSUPPORTED;
}

bool ParsedQuicVersion::KnowsWhichDecrypterToUse() const {
  QUICHE_DCHECK(IsKnown());
  return transport_version > QUIC_VERSION_46;
}

bool ParsedQuicVersion::UsesInitialObfuscators() const {
  QUICHE_DCHECK(IsKnown());
  // Initial obfuscators were added in version 50.
  return transport_version > QUIC_VERSION_46;
}

bool ParsedQuicVersion::AllowsLowFlowControlLimits() const {
  QUICHE_DCHECK(IsKnown());
  // Low flow-control limits are used for all IETF versions.
  return UsesHttp3();
}

bool ParsedQuicVersion::HasHeaderProtection() const {
  QUICHE_DCHECK(IsKnown());
  // Header protection was added in version 50.
  return transport_version > QUIC_VERSION_46;
}

bool ParsedQuicVersion::SupportsRetry() const {
  QUICHE_DCHECK(IsKnown());
  // Retry was added in version 47.
  return transport_version > QUIC_VERSION_46;
}

bool ParsedQuicVersion::SendsVariableLengthPacketNumberInLongHeader() const {
  QUICHE_DCHECK(IsKnown());
  return transport_version > QUIC_VERSION_46;
}

bool ParsedQuicVersion::AllowsVariableLengthConnectionIds() const {
  QUICHE_DCHECK(IsKnown());
  return VersionAllowsVariableLengthConnectionIds(transport_version);
}

bool ParsedQuicVersion::SupportsClientConnectionIds() const {
  QUICHE_DCHECK(IsKnown());
  // Client connection IDs were added in version 49.
  return transport_version > QUIC_VERSION_46;
}

bool ParsedQuicVersion::HasLengthPrefixedConnectionIds() const {
  QUICHE_DCHECK(IsKnown());
  return VersionHasLengthPrefixedConnectionIds(transport_version);
}

bool ParsedQuicVersion::SupportsAntiAmplificationLimit() const {
  QUICHE_DCHECK(IsKnown());
  // The anti-amplification limit is used for all IETF versions.
  return UsesHttp3();
}

bool ParsedQuicVersion::CanSendCoalescedPackets() const {
  QUICHE_DCHECK(IsKnown());
  return HasLongHeaderLengths() && UsesTls();
}

bool ParsedQuicVersion::SupportsGoogleAltSvcFormat() const {
  QUICHE_DCHECK(IsKnown());
  return VersionSupportsGoogleAltSvcFormat(transport_version);
}

bool ParsedQuicVersion::UsesHttp3() const {
  QUICHE_DCHECK(IsKnown());
  return VersionUsesHttp3(transport_version);
}

bool ParsedQuicVersion::HasLongHeaderLengths() const {
  QUICHE_DCHECK(IsKnown());
  return QuicVersionHasLongHeaderLengths(transport_version);
}

bool ParsedQuicVersion::UsesCryptoFrames() const {
  QUICHE_DCHECK(IsKnown());
  return QuicVersionUsesCryptoFrames(transport_version);
}

bool ParsedQuicVersion::HasIetfQuicFrames() const {
  QUICHE_DCHECK(IsKnown());
  return VersionHasIetfQuicFrames(transport_version);
}

bool ParsedQuicVersion::UsesLegacyTlsExtension() const {
  QUICHE_DCHECK(IsKnown());
  return UsesTls() && transport_version <= QUIC_VERSION_IETF_DRAFT_29;
}

bool ParsedQuicVersion::UsesTls() const {
  QUICHE_DCHECK(IsKnown());
  return handshake_protocol == PROTOCOL_TLS1_3;
}

bool ParsedQuicVersion::UsesQuicCrypto() const {
  QUICHE_DCHECK(IsKnown());
  return handshake_protocol == PROTOCOL_QUIC_CRYPTO;
}

bool ParsedQuicVersion::UsesV2PacketTypes() const {
  QUICHE_DCHECK(IsKnown());
  return transport_version == QUIC_VERSION_IETF_RFC_V2;
}

bool ParsedQuicVersion::AlpnDeferToRFCv1() const {
  QUICHE_DCHECK(IsKnown());
  return transport_version == QUIC_VERSION_IETF_RFC_V2;
}

bool VersionHasLengthPrefixedConnectionIds(
    QuicTransportVersion transport_version) {
  QUICHE_DCHECK(transport_version != QUIC_VERSION_UNSUPPORTED);
  // Length-prefixed connection IDs were added in version 49.
  return transport_version > QUIC_VERSION_46;
}

std::ostream& operator<<(std::ostream& os, const ParsedQuicVersion& version) {
  os << ParsedQuicVersionToString(version);
  return os;
}

std::ostream& operator<<(std::ostream& os,
                         const ParsedQuicVersionVector& versions) {
  os << ParsedQuicVersionVectorToString(versions);
  return os;
}

QuicVersionLabel MakeVersionLabel(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return MakeQuicTag(d, c, b, a);
}

std::ostream& operator<<(std::ostream& os,
                         const QuicVersionLabelVector& version_labels) {
  os << QuicVersionLabelVectorToString(version_labels);
  return os;
}

std::ostream& operator<<(std::ostream& os,
                         const QuicTransportVersionVector& transport_versions) {
  os << QuicTransportVersionVectorToString(transport_versions);
  return os;
}

QuicVersionLabel CreateQuicVersionLabel(ParsedQuicVersion parsed_version) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  if (parsed_version == ParsedQuicVersion::RFCv2()) {
    return MakeVersionLabel(0x6b, 0x33, 0x43, 0xcf);
  } else if (parsed_version == ParsedQuicVersion::RFCv1()) {
    return MakeVersionLabel(0x00, 0x00, 0x00, 0x01);
  } else if (parsed_version == ParsedQuicVersion::Draft29()) {
    return MakeVersionLabel(0xff, 0x00, 0x00, 29);
  } else if (parsed_version == ParsedQuicVersion::Q046()) {
    return MakeVersionLabel('Q', '0', '4', '6');
  } else if (parsed_version == ParsedQuicVersion::ReservedForNegotiation()) {
    return CreateRandomVersionLabelForNegotiation();
  }
  QUIC_BUG(quic_bug_10589_2)
      << "Unsupported version "
      << QuicVersionToString(parsed_version.transport_version) << " "
      << HandshakeProtocolToString(parsed_version.handshake_protocol);
  return 0;
}

QuicVersionLabelVector CreateQuicVersionLabelVector(
    const ParsedQuicVersionVector& versions) {
  QuicVersionLabelVector out;
  out.reserve(versions.size());
  for (const auto& version : versions) {
    out.push_back(CreateQuicVersionLabel(version));
  }
  return out;
}

ParsedQuicVersionVector AllSupportedVersionsWithQuicCrypto() {
  ParsedQuicVersionVector versions;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    if (version.handshake_protocol == PROTOCOL_QUIC_CRYPTO) {
      versions.push_back(version);
    }
  }
  QUIC_BUG_IF(quic_bug_10589_3, versions.empty())
      << "No version with QUIC crypto found.";
  return versions;
}

ParsedQuicVersionVector CurrentSupportedVersionsWithQuicCrypto() {
  ParsedQuicVersionVector versions;
  for (const ParsedQuicVersion& version : CurrentSupportedVersions()) {
    if (version.handshake_protocol == PROTOCOL_QUIC_CRYPTO) {
      versions.push_back(version);
    }
  }
  QUIC_BUG_IF(quic_bug_10589_4, versions.empty())
      << "No version with QUIC crypto found.";
  return versions;
}

ParsedQuicVersionVector AllSupportedVersionsWithTls() {
  ParsedQuicVersionVector versions;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    if (version.UsesTls()) {
      versions.push_back(version);
    }
  }
  QUIC_BUG_IF(quic_bug_10589_5, versions.empty())
      << "No version with TLS handshake found.";
  return versions;
}

ParsedQuicVersionVector CurrentSupportedVersionsWithTls() {
  ParsedQuicVersionVector versions;
  for (const ParsedQuicVersion& version : CurrentSupportedVersions()) {
    if (version.UsesTls()) {
      versions.push_back(version);
    }
  }
  QUIC_BUG_IF(quic_bug_10589_6, versions.empty())
      << "No version with TLS handshake found.";
  return versions;
}

ParsedQuicVersionVector ObsoleteSupportedVersions() {
  return ParsedQuicVersionVector{quic::ParsedQuicVersion::Q046(),
                                 quic::ParsedQuicVersion::Draft29()};
}

bool IsObsoleteSupportedVersion(ParsedQuicVersion version) {
  static const ParsedQuicVersionVector obsolete_versions =
      ObsoleteSupportedVersions();
  for (const ParsedQuicVersion& obsolete_version : obsolete_versions) {
    if (version == obsolete_version) {
      return true;
    }
  }
  return false;
}

ParsedQuicVersionVector CurrentSupportedVersionsForClients() {
  ParsedQuicVersionVector versions;
  for (const ParsedQuicVersion& version : CurrentSupportedVersionsWithTls()) {
    QUICHE_DCHECK_EQ(version.handshake_protocol, PROTOCOL_TLS1_3);
    if (version.transport_version >= QUIC_VERSION_IETF_RFC_V1) {
      versions.push_back(version);
    }
  }
  QUIC_BUG_IF(quic_bug_10589_8, versions.empty())
      << "No supported client versions found.";
  return versions;
}

ParsedQuicVersionVector CurrentSupportedHttp3Versions() {
  ParsedQuicVersionVector versions;
  for (const ParsedQuicVersion& version : CurrentSupportedVersions()) {
    if (version.UsesHttp3()) {
      versions.push_back(version);
    }
  }
  QUIC_BUG_IF(no_version_uses_http3, versions.empty())
      << "No version speaking Http3 found.";
  return versions;
}

ParsedQuicVersion ParseQuicVersionLabel(QuicVersionLabel version_label) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    if (version_label == CreateQuicVersionLabel(version)) {
      return version;
    }
  }
  // Reading from the client so this should not be considered an ERROR.
  QUIC_DLOG(INFO) << "Unsupported QuicVersionLabel version: "
                  << QuicVersionLabelToString(version_label);
  return UnsupportedQuicVersion();
}

ParsedQuicVersionVector ParseQuicVersionLabelVector(
    const QuicVersionLabelVector& version_labels) {
  ParsedQuicVersionVector parsed_versions;
  for (const QuicVersionLabel& version_label : version_labels) {
    ParsedQuicVersion parsed_version = ParseQuicVersionLabel(version_label);
    if (parsed_version.IsKnown()) {
      parsed_versions.push_back(parsed_version);
    }
  }
  return parsed_versions;
}

ParsedQuicVersion ParseQuicVersionString(absl::string_view version_string) {
  if (version_string.empty()) {
    return UnsupportedQuicVersion();
  }
  const ParsedQuicVersionVector supported_versions = AllSupportedVersions();
  for (const ParsedQuicVersion& version : supported_versions) {
    if (version_string == ParsedQuicVersionToString(version) ||
        (version_string == AlpnForVersion(version) &&
         !version.AlpnDeferToRFCv1()) ||
        (version.handshake_protocol == PROTOCOL_QUIC_CRYPTO &&
         version_string == QuicVersionToString(version.transport_version))) {
      return version;
    }
  }
  for (const ParsedQuicVersion& version : supported_versions) {
    if (version.UsesHttp3() &&
        version_string ==
            QuicVersionLabelToString(CreateQuicVersionLabel(version))) {
      return version;
    }
  }
  int quic_version_number = 0;
  if (absl::SimpleAtoi(version_string, &quic_version_number) &&
      quic_version_number > 0) {
    QuicTransportVersion transport_version =
        static_cast<QuicTransportVersion>(quic_version_number);
    if (!ParsedQuicVersionIsValid(PROTOCOL_QUIC_CRYPTO, transport_version)) {
      return UnsupportedQuicVersion();
    }
    ParsedQuicVersion version(PROTOCOL_QUIC_CRYPTO, transport_version);
    if (std::find(supported_versions.begin(), supported_versions.end(),
                  version) != supported_versions.end()) {
      return version;
    }
    return UnsupportedQuicVersion();
  }
  // Reading from the client so this should not be considered an ERROR.
  QUIC_DLOG(INFO) << "Unsupported QUIC version string: \"" << version_string
                  << "\".";
  return UnsupportedQuicVersion();
}

ParsedQuicVersionVector ParseQuicVersionVectorString(
    absl::string_view versions_string) {
  ParsedQuicVersionVector versions;
  std::vector<absl::string_view> version_strings =
      absl::StrSplit(versions_string, ',');
  for (absl::string_view version_string : version_strings) {
    quiche::QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(
        &version_string);
    ParsedQuicVersion version = ParseQuicVersionString(version_string);
    if (!version.IsKnown() || std::find(versions.begin(), versions.end(),
                                        version) != versions.end()) {
      continue;
    }
    versions.push_back(version);
  }
  return versions;
}

QuicTransportVersionVector AllSupportedTransportVersions() {
  QuicTransportVersionVector transport_versions;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    if (std::find(transport_versions.begin(), transport_versions.end(),
                  version.transport_version) == transport_versions.end()) {
      transport_versions.push_back(version.transport_version);
    }
  }
  return transport_versions;
}

ParsedQuicVersionVector AllSupportedVersions() {
  constexpr auto supported_versions = SupportedVersions();
  return ParsedQuicVersionVector(supported_versions.begin(),
                                 supported_versions.end());
}

ParsedQuicVersionVector CurrentSupportedVersions() {
  return FilterSupportedVersions(AllSupportedVersions());
}

ParsedQuicVersionVector FilterSupportedVersions(
    ParsedQuicVersionVector versions) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  ParsedQuicVersionVector filtered_versions;
  filtered_versions.reserve(versions.size());
  for (const ParsedQuicVersion& version : versions) {
    if (version == ParsedQuicVersion::RFCv2()) {
      if (GetQuicReloadableFlag(quic_enable_version_rfcv2)) {
        filtered_versions.push_back(version);
      }
    } else if (version == ParsedQuicVersion::RFCv1()) {
      if (!GetQuicReloadableFlag(quic_disable_version_rfcv1)) {
        filtered_versions.push_back(version);
      }
    } else if (version == ParsedQuicVersion::Draft29()) {
      if (!GetQuicReloadableFlag(quic_disable_version_draft_29)) {
        filtered_versions.push_back(version);
      }
    } else if (version == ParsedQuicVersion::Q046()) {
      if (!GetQuicReloadableFlag(quic_disable_version_q046)) {
        filtered_versions.push_back(version);
      }
    } else {
      QUIC_BUG(quic_bug_10589_7)
          << "QUIC version " << version << " has no flag protection";
      filtered_versions.push_back(version);
    }
  }
  return filtered_versions;
}

ParsedQuicVersionVector ParsedVersionOfIndex(
    const ParsedQuicVersionVector& versions, int index) {
  ParsedQuicVersionVector version;
  int version_count = versions.size();
  if (index >= 0 && index < version_count) {
    version.push_back(versions[index]);
  } else {
    version.push_back(UnsupportedQuicVersion());
  }
  return version;
}

std::string QuicVersionLabelToString(QuicVersionLabel version_label) {
  return QuicTagToString(quiche::QuicheEndian::HostToNet32(version_label));
}

ParsedQuicVersion ParseQuicVersionLabelString(
    absl::string_view version_label_string) {
  const ParsedQuicVersionVector supported_versions = AllSupportedVersions();
  for (const ParsedQuicVersion& version : supported_versions) {
    if (version_label_string ==
        QuicVersionLabelToString(CreateQuicVersionLabel(version))) {
      return version;
    }
  }
  return UnsupportedQuicVersion();
}

std::string QuicVersionLabelVectorToString(
    const QuicVersionLabelVector& version_labels, const std::string& separator,
    size_t skip_after_nth_version) {
  std::string result;
  for (size_t i = 0; i < version_labels.size(); ++i) {
    if (i != 0) {
      result.append(separator);
    }

    if (i > skip_after_nth_version) {
      result.append("...");
      break;
    }
    result.append(QuicVersionLabelToString(version_labels[i]));
  }
  return result;
}

#define RETURN_STRING_LITERAL(x) \
  case x:                        \
    return #x

std::string QuicVersionToString(QuicTransportVersion transport_version) {
  switch (transport_version) {
    RETURN_STRING_LITERAL(QUIC_VERSION_46);
    RETURN_STRING_LITERAL(QUIC_VERSION_IETF_DRAFT_29);
    RETURN_STRING_LITERAL(QUIC_VERSION_IETF_RFC_V1);
    RETURN_STRING_LITERAL(QUIC_VERSION_IETF_RFC_V2);
    RETURN_STRING_LITERAL(QUIC_VERSION_UNSUPPORTED);
    RETURN_STRING_LITERAL(QUIC_VERSION_RESERVED_FOR_NEGOTIATION);
  }
  return absl::StrCat("QUIC_VERSION_UNKNOWN(",
                      static_cast<int>(transport_version), ")");
}

std::string HandshakeProtocolToString(HandshakeProtocol handshake_protocol) {
  switch (handshake_protocol) {
    RETURN_STRING_LITERAL(PROTOCOL_UNSUPPORTED);
    RETURN_STRING_LITERAL(PROTOCOL_QUIC_CRYPTO);
    RETURN_STRING_LITERAL(PROTOCOL_TLS1_3);
  }
  return absl::StrCat("PROTOCOL_UNKNOWN(", static_cast<int>(handshake_protocol),
                      ")");
}

std::string ParsedQuicVersionToString(ParsedQuicVersion version) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  if (version == UnsupportedQuicVersion()) {
    return "0";
  } else if (version == ParsedQuicVersion::RFCv2()) {
    QUICHE_DCHECK(version.UsesHttp3());
    return "RFCv2";
  } else if (version == ParsedQuicVersion::RFCv1()) {
    QUICHE_DCHECK(version.UsesHttp3());
    return "RFCv1";
  } else if (version == ParsedQuicVersion::Draft29()) {
    QUICHE_DCHECK(version.UsesHttp3());
    return "draft29";
  }

  return QuicVersionLabelToString(CreateQuicVersionLabel(version));
}

std::string QuicTransportVersionVectorToString(
    const QuicTransportVersionVector& versions) {
  std::string result = "";
  for (size_t i = 0; i < versions.size(); ++i) {
    if (i != 0) {
      result.append(",");
    }
    result.append(QuicVersionToString(versions[i]));
  }
  return result;
}

std::string ParsedQuicVersionVectorToString(
    const ParsedQuicVersionVector& versions, const std::string& separator,
    size_t skip_after_nth_version) {
  std::string result;
  for (size_t i = 0; i < versions.size(); ++i) {
    if (i != 0) {
      result.append(separator);
    }
    if (i > skip_after_nth_version) {
      result.append("...");
      break;
    }
    result.append(ParsedQuicVersionToString(versions[i]));
  }
  return result;
}

bool VersionSupportsGoogleAltSvcFormat(QuicTransportVersion transport_version) {
  return transport_version <= QUIC_VERSION_46;
}

bool VersionAllowsVariableLengthConnectionIds(
    QuicTransportVersion transport_version) {
  QUICHE_DCHECK_NE(transport_version, QUIC_VERSION_UNSUPPORTED);
  return transport_version > QUIC_VERSION_46;
}

bool QuicVersionLabelUses4BitConnectionIdLength(
    QuicVersionLabel version_label) {
  // As we deprecate old versions, we still need the ability to send valid
  // version negotiation packets for those versions. This function keeps track
  // of the versions that ever supported the 4bit connection ID length encoding
  // that we know about. Google QUIC 43 and earlier used a different encoding,
  // and Google QUIC 49 and later use the new length prefixed encoding.
  // Similarly, only IETF drafts 11 to 21 used this encoding.

  // Check Q043, Q044, Q045, Q046, Q047 and Q048.
  for (uint8_t c = '3'; c <= '8'; ++c) {
    if (version_label == MakeVersionLabel('Q', '0', '4', c)) {
      return true;
    }
  }
  // Check T048.
  if (version_label == MakeVersionLabel('T', '0', '4', '8')) {
    return true;
  }
  // Check IETF draft versions in [11,21].
  for (uint8_t draft_number = 11; draft_number <= 21; ++draft_number) {
    if (version_label == MakeVersionLabel(0xff, 0x00, 0x00, draft_number)) {
      return true;
    }
  }
  return false;
}

ParsedQuicVersion UnsupportedQuicVersion() {
  return ParsedQuicVersion::Unsupported();
}

ParsedQuicVersion QuicVersionReservedForNegotiation() {
  return ParsedQuicVersion::ReservedForNegotiation();
}

std::string AlpnForVersion(ParsedQuicVersion parsed_version) {
  if (parsed_version == ParsedQuicVersion::RFCv2()) {
    return "h3";
  } else if (parsed_version == ParsedQuicVersion::RFCv1()) {
    return "h3";
  } else if (parsed_version == ParsedQuicVersion::Draft29()) {
    return "h3-29";
  }
  return "h3-" + ParsedQuicVersionToString(parsed_version);
}

void QuicEnableVersion(const ParsedQuicVersion& version) {
  SetVersionFlag(version, /*should_enable=*/true);
}

void QuicDisableVersion(const ParsedQuicVersion& version) {
  SetVersionFlag(version, /*should_enable=*/false);
}

bool QuicVersionIsEnabled(const ParsedQuicVersion& version) {
  ParsedQuicVersionVector current = CurrentSupportedVersions();
  return std::find(current.begin(), current.end(), version) != current.end();
}

#undef RETURN_STRING_LITERAL  // undef for jumbo builds
}  // namespace quic

"""

```