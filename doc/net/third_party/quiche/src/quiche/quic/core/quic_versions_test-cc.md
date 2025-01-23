Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Identify the Core Purpose:** The filename `quic_versions_test.cc` immediately suggests this file is about testing the functionality related to QUIC versions. Keywords like "versions," "supported," "parse," and "create" are likely to appear frequently.

2. **Understand the Testing Framework:**  The presence of `#include "quiche/quic/platform/api/quic_test.h"` strongly indicates this uses a custom testing framework within the QUIC library. The `TEST()` macros confirm this.

3. **Analyze Individual Test Cases (Mental Walkthrough):** Go through each `TEST()` block and try to understand what it's testing. Look for:
    * **Setup:** What data is being prepared? (e.g., specific version values, strings)
    * **Action:** What function is being called? (e.g., `CreateQuicVersionLabel`, `ParseQuicVersionString`)
    * **Assertion:** What is being checked? (e.g., `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`)

4. **Categorize Functionality:** As you analyze the tests, group them by the functionalities they are testing. This will help structure the "功能" section. For example:
    * Creating version labels
    * Parsing version labels (from different formats)
    * Checking version validity
    * Examining version features
    * Converting between version representations (string, label, internal types)
    * Filtering and manipulating version lists
    * Enabling/disabling versions
    * Checking for obsolete versions

5. **Look for Javascript Connections (and note the absence):**  Actively search for concepts or keywords related to Javascript or web development where this code might interact with a Javascript environment. In this specific case, there are no direct mentions or obvious connections within the *test file itself*. It's crucial to note this lack of direct connection. The broader context of QUIC being used in web browsers is relevant, but the *test file* doesn't directly demonstrate that.

6. **Identify Logic and Assumptions:** Pinpoint specific tests that involve logical reasoning about version properties. For example, the `Features` test directly asserts the presence or absence of certain features for different QUIC versions. For "假设输入与输出," choose a representative test and detail the specific input and expected output based on the assertions.

7. **Consider Potential User/Programming Errors:** Think about how developers might misuse the version handling functions. Examples include:
    * Passing invalid version strings.
    * Using unsupported or deprecated versions.
    * Incorrectly assuming feature availability based on a version.
    * Not handling version negotiation correctly.

8. **Trace Debugging Steps:** Imagine you're a developer and this test fails. How would you get here?  This leads to the "用户操作是如何一步步的到达这里，作为调试线索" section. Think about the general steps involved in developing and testing network code:
    * Code changes related to QUIC versions.
    * Running unit tests to verify those changes.
    * A specific test case failing.
    * Investigating the failure by examining the test code and potentially the underlying implementation.

9. **Refine and Organize:** Review your findings and structure them logically. Use clear headings and bullet points to enhance readability. Ensure that each point is well-supported by the analysis of the test code. Pay attention to the specific wording of the prompt and address each part.

**Self-Correction/Refinement during the process:**

* **Initial Thought:** "Maybe some of the string parsing relates to Javascript's handling of strings."  **Correction:**  While Javascript *also* deals with strings, the C++ code is operating at a much lower level, manipulating byte representations of version identifiers. The connection is more conceptual (both deal with representing information as strings) than directly functional.
* **Initial Thought:** "The `Features` test just lists properties." **Refinement:** Recognize that this test *is* a form of logic – it's asserting specific logical properties of different QUIC versions.
* **Initial Thought:** Focus only on the positive tests. **Correction:**  Include tests that check for error conditions (like `CreateQuicVersionLabelUnsupported`) and the handling of invalid input (in parsing tests).

By following these steps, and continually refining the analysis, you can generate a comprehensive and accurate description of the test file's functionality and its implications.
这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_versions_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它的主要功能是**测试 QUIC 协议版本相关的各种功能**。

具体来说，这个测试文件涵盖了以下几个方面的功能：

**1. 定义和管理 QUIC 版本:**

* **测试版本常量的定义:**  验证预定义的 QUIC 版本常量（例如 `QUIC_VERSION_46`, `QUIC_VERSION_IETF_DRAFT_29` 等）是否正确。
* **测试版本信息的存储和访问:**  测试如何存储和访问每个版本的详细信息，例如握手协议 (handshake protocol) 和传输版本 (transport version)。
* **测试支持的版本列表:** 验证当前支持的 QUIC 版本列表是否正确。

**2. 版本标签 (Version Label) 的创建和解析:**

* **创建版本标签:** 测试将内部的 `ParsedQuicVersion` 结构转换为用于网络传输的 4 字节版本标签 (Version Label) 的功能。例如，`CreateQuicVersionLabel(ParsedQuicVersion::Q046())` 应该生成 `0x51303436u`。
* **解析版本标签:** 测试将接收到的 4 字节版本标签解析回内部的 `ParsedQuicVersion` 结构的功能。例如，`ParseQuicVersionLabel(MakeVersionLabel('Q', '0', '4', '6'))` 应该返回 `ParsedQuicVersion::Q046()`。
* **测试不支持版本的处理:** 验证尝试创建不支持版本的标签时是否会触发预期的错误断言 (`EXPECT_QUIC_BUG`)。

**3. 版本字符串的解析和生成:**

* **解析版本字符串:** 测试将各种表示 QUIC 版本的字符串（例如 "QUIC_VERSION_46", "46", "Q046", "ff00001d", "draft29", "h3"）解析成 `ParsedQuicVersion` 的功能。
* **生成版本字符串:** 测试将 `ParsedQuicVersion` 结构转换回字符串表示的功能。
* **测试版本向量字符串的解析:** 测试将逗号分隔的版本字符串列表解析成 `ParsedQuicVersionVector` 的功能。

**4. 版本特性 (Features) 的检查:**

* **测试不同版本的特性支持:** 针对不同的 QUIC 版本，测试其是否支持特定的功能，例如头部保护 (Header Protection)、重试 (Retry)、可变长度连接ID (Variable Length Connection IDs)、HTTP/3 等。

**5. 版本过滤和使能/禁用:**

* **测试过滤支持的版本:** 测试根据当前启用的版本列表过滤给定版本列表的功能。
* **测试版本的使能和禁用:** 测试动态地启用和禁用特定 QUIC 版本的功能。

**6. 版本兼容性和演进:**

* **测试废弃版本:** 识别和测试被认为是废弃的 QUIC 版本。
* **测试当前支持的版本:** 区分当前推荐使用的 QUIC 版本。

**与 JavaScript 的关系:**

这个 C++ 文件本身**不直接与 JavaScript 代码交互**。然而，它所测试的 QUIC 协议版本协商和特性支持对于基于浏览器的 JavaScript 应用使用 QUIC 连接至关重要。

例如：

* **版本协商:** 当浏览器（运行 JavaScript 应用）尝试与服务器建立 QUIC 连接时，它需要与服务器协商双方都支持的 QUIC 版本。这个 C++ 文件中测试的版本解析和创建功能直接影响到这个协商过程。浏览器会发送一个包含其支持版本列表的版本标签，服务器会选择一个共同支持的版本。
* **特性支持:** 不同的 QUIC 版本支持不同的特性。JavaScript 应用可能会依赖某些 QUIC 特性来优化性能或实现特定功能。这个 C++ 文件中测试的版本特性检查确保了 QUIC 库能够正确地处理不同版本的功能差异。

**举例说明 JavaScript 的关系:**

假设一个 JavaScript 应用使用 `fetch` API 或 WebSocket over QUIC 与服务器通信。

1. **版本协商:**  当建立连接时，浏览器底层会使用类似于这个 C++ 文件中测试的逻辑来生成包含浏览器支持的 QUIC 版本标签的列表。
2. **特性使用:**  如果 JavaScript 应用的代码依赖于某个特定的 QUIC 特性（例如 0-RTT 连接），浏览器底层的 QUIC 实现会根据协商的版本来判断该特性是否可用。如果协商的版本不支持该特性，则会回退到其他机制或报告错误。

**逻辑推理的假设输入与输出:**

**假设输入:**  一个表示版本标签的 4 字节整数 `0x51303436u`。

**测试函数:** `ParseQuicVersionLabel()`

**预期输出:**  一个 `ParsedQuicVersion` 对象，其内部表示等同于 `ParsedQuicVersion::Q046()`。这包括其握手协议为 `PROTOCOL_QUIC_CRYPTO`，传输版本为 `QUIC_VERSION_46`。

**假设输入:**  一个版本字符串 `"h3-29"`。

**测试函数:** `ParseQuicVersionString()`

**预期输出:**  一个 `ParsedQuicVersion` 对象，其内部表示等同于 `ParsedQuicVersion::Draft29()`。这包括其握手协议为 `PROTOCOL_TLS1_3`，传输版本为 `QUIC_VERSION_IETF_DRAFT_29`。

**用户或编程常见的使用错误:**

1. **传递无效的版本字符串进行解析:** 用户可能错误地传递一个格式不正确的版本字符串给 `ParseQuicVersionString()`，例如 `"Q 46"` 或 `"99"`。这将导致解析失败，并返回 `UnsupportedQuicVersion()`。
   * **例子:**  一个配置系统允许用户手动指定 QUIC 版本，用户错误地输入了 "Q 46"。

2. **假设所有版本都支持特定特性:** 程序员可能错误地假设所有 QUIC 版本都支持某个特定的特性，例如 0-RTT 连接，而没有根据协商的版本进行检查。这可能导致在旧版本上运行时出现错误。
   * **例子:**  代码直接使用了某个只有较新 QUIC 版本才支持的 API，而没有进行版本判断。

3. **错误地创建或比较版本标签:**  程序员可能手动构建版本标签时出现错误，或者在比较版本标签时使用错误的比较方法。
   * **例子:**  在实现自定义的版本协商逻辑时，错误地使用了位运算来生成版本标签。

**用户操作到达这里的调试线索:**

要到达这个测试文件的执行，通常需要以下步骤：

1. **开发者修改了 QUIC 协议版本相关的代码:**  例如，添加了对新 QUIC 版本的支持，修改了现有版本的特性，或者修复了与版本处理相关的 bug。

2. **开发者运行了 QUIC 相关的单元测试:**  为了验证他们的修改是否正确，开发者会运行与 QUIC 协议相关的单元测试。这通常是通过 Chromium 的构建系统（例如 `gn` 和 `ninja`) 执行特定的测试目标来完成的。

3. **特定的测试用例失败:**  例如，`QuicVersionsTest.ParseQuicVersionLabel` 测试用例在解析一个新添加的版本标签时失败。

4. **开发者开始调试:**
   * **查看测试失败的日志:** 开发者会查看测试失败的详细日志，了解哪个断言失败了以及失败的原因。
   * **定位到测试文件和失败的测试用例:**  根据日志信息，开发者会找到 `net/third_party/quiche/src/quiche/quic/core/quic_versions_test.cc` 文件以及导致失败的具体测试用例。
   * **查看测试代码:** 开发者会仔细检查测试用例的输入、预期输出以及相关的 QUIC 版本处理代码，以找出问题所在。
   * **设置断点并单步执行:**  为了更深入地了解代码的执行流程，开发者可能会在测试代码或相关的 QUIC 版本处理函数中设置断点，并使用调试器单步执行代码，观察变量的值和程序的执行路径。
   * **分析 core dump (如果崩溃):**  如果测试导致程序崩溃，开发者可能会分析 core dump 文件，以了解崩溃时的程序状态和调用堆栈。

总而言之，这个测试文件是 QUIC 协议实现中至关重要的一部分，它确保了 QUIC 版本处理逻辑的正确性，这对于 QUIC 协议的稳定性和互操作性至关重要。 虽然它本身是用 C++ 编写的，但其测试的功能直接影响到浏览器和 JavaScript 应用如何使用 QUIC 进行网络通信。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_versions_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/quic_versions.h"

#include <cstddef>
#include <sstream>

#include "absl/algorithm/container.h"
#include "absl/base/macros.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {
namespace test {
namespace {

using ::testing::ElementsAre;
using ::testing::IsEmpty;

TEST(QuicVersionsTest, CreateQuicVersionLabelUnsupported) {
  EXPECT_QUIC_BUG(
      CreateQuicVersionLabel(UnsupportedQuicVersion()),
      "Unsupported version QUIC_VERSION_UNSUPPORTED PROTOCOL_UNSUPPORTED");
}

TEST(QuicVersionsTest, KnownAndValid) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_TRUE(version.IsKnown());
    EXPECT_TRUE(ParsedQuicVersionIsValid(version.handshake_protocol,
                                         version.transport_version));
  }
  ParsedQuicVersion unsupported = UnsupportedQuicVersion();
  EXPECT_FALSE(unsupported.IsKnown());
  EXPECT_TRUE(ParsedQuicVersionIsValid(unsupported.handshake_protocol,
                                       unsupported.transport_version));
  ParsedQuicVersion reserved = QuicVersionReservedForNegotiation();
  EXPECT_TRUE(reserved.IsKnown());
  EXPECT_TRUE(ParsedQuicVersionIsValid(reserved.handshake_protocol,
                                       reserved.transport_version));
  // Check that invalid combinations are not valid.
  EXPECT_FALSE(ParsedQuicVersionIsValid(PROTOCOL_TLS1_3, QUIC_VERSION_46));
  EXPECT_FALSE(ParsedQuicVersionIsValid(PROTOCOL_QUIC_CRYPTO,
                                        QUIC_VERSION_IETF_DRAFT_29));
  // Check that deprecated versions are not valid.
  EXPECT_FALSE(ParsedQuicVersionIsValid(PROTOCOL_QUIC_CRYPTO,
                                        static_cast<QuicTransportVersion>(33)));
  EXPECT_FALSE(ParsedQuicVersionIsValid(PROTOCOL_QUIC_CRYPTO,
                                        static_cast<QuicTransportVersion>(99)));
  EXPECT_FALSE(ParsedQuicVersionIsValid(PROTOCOL_TLS1_3,
                                        static_cast<QuicTransportVersion>(99)));
}

TEST(QuicVersionsTest, Features) {
  ParsedQuicVersion parsed_version_q046 = ParsedQuicVersion::Q046();
  ParsedQuicVersion parsed_version_draft_29 = ParsedQuicVersion::Draft29();

  EXPECT_TRUE(parsed_version_q046.IsKnown());
  EXPECT_FALSE(parsed_version_q046.KnowsWhichDecrypterToUse());
  EXPECT_FALSE(parsed_version_q046.UsesInitialObfuscators());
  EXPECT_FALSE(parsed_version_q046.AllowsLowFlowControlLimits());
  EXPECT_FALSE(parsed_version_q046.HasHeaderProtection());
  EXPECT_FALSE(parsed_version_q046.SupportsRetry());
  EXPECT_FALSE(
      parsed_version_q046.SendsVariableLengthPacketNumberInLongHeader());
  EXPECT_FALSE(parsed_version_q046.AllowsVariableLengthConnectionIds());
  EXPECT_FALSE(parsed_version_q046.SupportsClientConnectionIds());
  EXPECT_FALSE(parsed_version_q046.HasLengthPrefixedConnectionIds());
  EXPECT_FALSE(parsed_version_q046.SupportsAntiAmplificationLimit());
  EXPECT_FALSE(parsed_version_q046.CanSendCoalescedPackets());
  EXPECT_TRUE(parsed_version_q046.SupportsGoogleAltSvcFormat());
  EXPECT_FALSE(parsed_version_q046.UsesHttp3());
  EXPECT_FALSE(parsed_version_q046.HasLongHeaderLengths());
  EXPECT_FALSE(parsed_version_q046.UsesCryptoFrames());
  EXPECT_FALSE(parsed_version_q046.HasIetfQuicFrames());
  EXPECT_FALSE(parsed_version_q046.UsesTls());
  EXPECT_TRUE(parsed_version_q046.UsesQuicCrypto());

  EXPECT_TRUE(parsed_version_draft_29.IsKnown());
  EXPECT_TRUE(parsed_version_draft_29.KnowsWhichDecrypterToUse());
  EXPECT_TRUE(parsed_version_draft_29.UsesInitialObfuscators());
  EXPECT_TRUE(parsed_version_draft_29.AllowsLowFlowControlLimits());
  EXPECT_TRUE(parsed_version_draft_29.HasHeaderProtection());
  EXPECT_TRUE(parsed_version_draft_29.SupportsRetry());
  EXPECT_TRUE(
      parsed_version_draft_29.SendsVariableLengthPacketNumberInLongHeader());
  EXPECT_TRUE(parsed_version_draft_29.AllowsVariableLengthConnectionIds());
  EXPECT_TRUE(parsed_version_draft_29.SupportsClientConnectionIds());
  EXPECT_TRUE(parsed_version_draft_29.HasLengthPrefixedConnectionIds());
  EXPECT_TRUE(parsed_version_draft_29.SupportsAntiAmplificationLimit());
  EXPECT_TRUE(parsed_version_draft_29.CanSendCoalescedPackets());
  EXPECT_FALSE(parsed_version_draft_29.SupportsGoogleAltSvcFormat());
  EXPECT_TRUE(parsed_version_draft_29.UsesHttp3());
  EXPECT_TRUE(parsed_version_draft_29.HasLongHeaderLengths());
  EXPECT_TRUE(parsed_version_draft_29.UsesCryptoFrames());
  EXPECT_TRUE(parsed_version_draft_29.HasIetfQuicFrames());
  EXPECT_TRUE(parsed_version_draft_29.UsesTls());
  EXPECT_FALSE(parsed_version_draft_29.UsesQuicCrypto());
}

TEST(QuicVersionsTest, ParseQuicVersionLabel) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  EXPECT_EQ(ParsedQuicVersion::Q046(),
            ParseQuicVersionLabel(MakeVersionLabel('Q', '0', '4', '6')));
  EXPECT_EQ(ParsedQuicVersion::Draft29(),
            ParseQuicVersionLabel(MakeVersionLabel(0xff, 0x00, 0x00, 0x1d)));
  EXPECT_EQ(ParsedQuicVersion::RFCv1(),
            ParseQuicVersionLabel(MakeVersionLabel(0x00, 0x00, 0x00, 0x01)));
  EXPECT_EQ(ParsedQuicVersion::RFCv2(),
            ParseQuicVersionLabel(MakeVersionLabel(0x6b, 0x33, 0x43, 0xcf)));
  EXPECT_EQ((ParsedQuicVersionVector{ParsedQuicVersion::RFCv2(),
                                     ParsedQuicVersion::RFCv1(),
                                     ParsedQuicVersion::Draft29()}),
            ParseQuicVersionLabelVector(QuicVersionLabelVector{
                MakeVersionLabel(0x6b, 0x33, 0x43, 0xcf),
                MakeVersionLabel(0x00, 0x00, 0x00, 0x01),
                MakeVersionLabel(0xaa, 0xaa, 0xaa, 0xaa),
                MakeVersionLabel(0xff, 0x00, 0x00, 0x1d)}));

  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_EQ(version, ParseQuicVersionLabel(CreateQuicVersionLabel(version)));
  }
}

TEST(QuicVersionsTest, ParseQuicVersionString) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  EXPECT_EQ(ParsedQuicVersion::Q046(),
            ParseQuicVersionString("QUIC_VERSION_46"));
  EXPECT_EQ(ParsedQuicVersion::Q046(), ParseQuicVersionString("46"));
  EXPECT_EQ(ParsedQuicVersion::Q046(), ParseQuicVersionString("Q046"));

  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionString(""));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionString("Q 46"));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionString("Q046 "));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionString("99"));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionString("70"));

  EXPECT_EQ(ParsedQuicVersion::Draft29(), ParseQuicVersionString("ff00001d"));
  EXPECT_EQ(ParsedQuicVersion::Draft29(), ParseQuicVersionString("draft29"));
  EXPECT_EQ(ParsedQuicVersion::Draft29(), ParseQuicVersionString("h3-29"));

  EXPECT_EQ(ParsedQuicVersion::RFCv1(), ParseQuicVersionString("00000001"));
  EXPECT_EQ(ParsedQuicVersion::RFCv1(), ParseQuicVersionString("h3"));

  // QUICv2 will never be the result for "h3".

  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_EQ(version,
              ParseQuicVersionString(ParsedQuicVersionToString(version)));
    EXPECT_EQ(version, ParseQuicVersionString(QuicVersionLabelToString(
                           CreateQuicVersionLabel(version))));
    if (!version.AlpnDeferToRFCv1()) {
      EXPECT_EQ(version, ParseQuicVersionString(AlpnForVersion(version)));
    }
  }
}

TEST(QuicVersionsTest, ParseQuicVersionVectorString) {
  ParsedQuicVersion version_q046 = ParsedQuicVersion::Q046();
  ParsedQuicVersion version_draft_29 = ParsedQuicVersion::Draft29();

  EXPECT_THAT(ParseQuicVersionVectorString(""), IsEmpty());

  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_46"),
              ElementsAre(version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-Q046"),
              ElementsAre(version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-Q046, h3-29"),
              ElementsAre(version_q046, version_draft_29));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-29,h3-Q046,h3-29"),
              ElementsAre(version_draft_29, version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-29, h3-Q046"),
              ElementsAre(version_draft_29, version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_46,h3-29"),
              ElementsAre(version_q046, version_draft_29));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-29,QUIC_VERSION_46"),
              ElementsAre(version_draft_29, version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_46, h3-29"),
              ElementsAre(version_q046, version_draft_29));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-29, QUIC_VERSION_46"),
              ElementsAre(version_draft_29, version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-29,QUIC_VERSION_46"),
              ElementsAre(version_draft_29, version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_46,h3-29"),
              ElementsAre(version_q046, version_draft_29));

  // Regression test for https://crbug.com/1044952.
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_46, QUIC_VERSION_46"),
              ElementsAre(version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-Q046, h3-Q046"),
              ElementsAre(version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-Q046, QUIC_VERSION_46"),
              ElementsAre(version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString(
                  "QUIC_VERSION_46, h3-Q046, QUIC_VERSION_46, h3-Q046"),
              ElementsAre(version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_46, h3-29, h3-Q046"),
              ElementsAre(version_q046, version_draft_29));

  EXPECT_THAT(ParseQuicVersionVectorString("99"), IsEmpty());
  EXPECT_THAT(ParseQuicVersionVectorString("70"), IsEmpty());
  EXPECT_THAT(ParseQuicVersionVectorString("h3-01"), IsEmpty());
  EXPECT_THAT(ParseQuicVersionVectorString("h3-01,h3-29"),
              ElementsAre(version_draft_29));
}

// Do not use MakeVersionLabel() to generate expectations, because
// CreateQuicVersionLabel() uses MakeVersionLabel() internally,
// in case it has a bug.
TEST(QuicVersionsTest, CreateQuicVersionLabel) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  EXPECT_EQ(0x51303436u, CreateQuicVersionLabel(ParsedQuicVersion::Q046()));
  EXPECT_EQ(0xff00001du, CreateQuicVersionLabel(ParsedQuicVersion::Draft29()));
  EXPECT_EQ(0x00000001u, CreateQuicVersionLabel(ParsedQuicVersion::RFCv1()));
  EXPECT_EQ(0x6b3343cfu, CreateQuicVersionLabel(ParsedQuicVersion::RFCv2()));

  // Make sure the negotiation reserved version is in the IETF reserved space.
  EXPECT_EQ(
      0xda5a3a3au & 0x0f0f0f0f,
      CreateQuicVersionLabel(ParsedQuicVersion::ReservedForNegotiation()) &
          0x0f0f0f0f);

  // Make sure that disabling randomness works.
  SetQuicFlag(quic_disable_version_negotiation_grease_randomness, true);
  EXPECT_EQ(0xda5a3a3au, CreateQuicVersionLabel(
                             ParsedQuicVersion::ReservedForNegotiation()));
}

TEST(QuicVersionsTest, QuicVersionLabelToString) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  EXPECT_EQ("Q046", QuicVersionLabelToString(
                        CreateQuicVersionLabel(ParsedQuicVersion::Q046())));
  EXPECT_EQ("ff00001d", QuicVersionLabelToString(CreateQuicVersionLabel(
                            ParsedQuicVersion::Draft29())));
  EXPECT_EQ("00000001", QuicVersionLabelToString(CreateQuicVersionLabel(
                            ParsedQuicVersion::RFCv1())));
  EXPECT_EQ("6b3343cf", QuicVersionLabelToString(CreateQuicVersionLabel(
                            ParsedQuicVersion::RFCv2())));

  QuicVersionLabelVector version_labels = {
      MakeVersionLabel('Q', '0', '3', '5'),
      MakeVersionLabel('T', '0', '3', '8'),
      MakeVersionLabel(0xff, 0, 0, 7),
  };

  EXPECT_EQ("Q035", QuicVersionLabelToString(version_labels[0]));
  EXPECT_EQ("T038", QuicVersionLabelToString(version_labels[1]));
  EXPECT_EQ("ff000007", QuicVersionLabelToString(version_labels[2]));

  EXPECT_EQ("Q035,T038,ff000007",
            QuicVersionLabelVectorToString(version_labels));
  EXPECT_EQ("Q035:T038:ff000007",
            QuicVersionLabelVectorToString(version_labels, ":", 2));
  EXPECT_EQ("Q035|T038|...",
            QuicVersionLabelVectorToString(version_labels, "|", 1));

  std::ostringstream os;
  os << version_labels;
  EXPECT_EQ("Q035,T038,ff000007", os.str());
}

TEST(QuicVersionsTest, ParseQuicVersionLabelString) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  // Explicitly test known QUIC version label strings.
  EXPECT_EQ(ParsedQuicVersion::Q046(), ParseQuicVersionLabelString("Q046"));
  EXPECT_EQ(ParsedQuicVersion::Draft29(),
            ParseQuicVersionLabelString("ff00001d"));
  EXPECT_EQ(ParsedQuicVersion::RFCv1(),
            ParseQuicVersionLabelString("00000001"));
  EXPECT_EQ(ParsedQuicVersion::RFCv2(),
            ParseQuicVersionLabelString("6b3343cf"));

  // Sanity check that a variety of other serialization formats are ignored.
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionLabelString("1"));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionLabelString("46"));
  EXPECT_EQ(UnsupportedQuicVersion(),
            ParseQuicVersionLabelString("QUIC_VERSION_46"));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionLabelString("h3"));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionLabelString("h3-29"));

  // Test round-trips between QuicVersionLabelToString and
  // ParseQuicVersionLabelString.
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_EQ(version, ParseQuicVersionLabelString(QuicVersionLabelToString(
                           CreateQuicVersionLabel(version))));
  }
}

TEST(QuicVersionsTest, QuicVersionToString) {
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED",
            QuicVersionToString(QUIC_VERSION_UNSUPPORTED));

  QuicTransportVersion single_version[] = {QUIC_VERSION_46};
  QuicTransportVersionVector versions_vector;
  for (size_t i = 0; i < ABSL_ARRAYSIZE(single_version); ++i) {
    versions_vector.push_back(single_version[i]);
  }
  EXPECT_EQ("QUIC_VERSION_46",
            QuicTransportVersionVectorToString(versions_vector));

  QuicTransportVersion multiple_versions[] = {QUIC_VERSION_UNSUPPORTED,
                                              QUIC_VERSION_46};
  versions_vector.clear();
  for (size_t i = 0; i < ABSL_ARRAYSIZE(multiple_versions); ++i) {
    versions_vector.push_back(multiple_versions[i]);
  }
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED,QUIC_VERSION_46",
            QuicTransportVersionVectorToString(versions_vector));

  // Make sure that all supported versions are present in QuicVersionToString.
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_NE("QUIC_VERSION_UNSUPPORTED",
              QuicVersionToString(version.transport_version));
  }

  std::ostringstream os;
  os << versions_vector;
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED,QUIC_VERSION_46", os.str());
}

TEST(QuicVersionsTest, ParsedQuicVersionToString) {
  EXPECT_EQ("0", ParsedQuicVersionToString(ParsedQuicVersion::Unsupported()));
  EXPECT_EQ("Q046", ParsedQuicVersionToString(ParsedQuicVersion::Q046()));
  EXPECT_EQ("draft29", ParsedQuicVersionToString(ParsedQuicVersion::Draft29()));
  EXPECT_EQ("RFCv1", ParsedQuicVersionToString(ParsedQuicVersion::RFCv1()));
  EXPECT_EQ("RFCv2", ParsedQuicVersionToString(ParsedQuicVersion::RFCv2()));

  ParsedQuicVersionVector versions_vector = {ParsedQuicVersion::Q046()};
  EXPECT_EQ("Q046", ParsedQuicVersionVectorToString(versions_vector));

  versions_vector = {ParsedQuicVersion::Unsupported(),
                     ParsedQuicVersion::Q046()};
  EXPECT_EQ("0,Q046", ParsedQuicVersionVectorToString(versions_vector));
  EXPECT_EQ("0:Q046", ParsedQuicVersionVectorToString(versions_vector, ":",
                                                      versions_vector.size()));
  EXPECT_EQ("0|...", ParsedQuicVersionVectorToString(versions_vector, "|", 0));

  // Make sure that all supported versions are present in
  // ParsedQuicVersionToString.
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_NE("0", ParsedQuicVersionToString(version));
  }

  std::ostringstream os;
  os << versions_vector;
  EXPECT_EQ("0,Q046", os.str());
}

TEST(QuicVersionsTest, FilterSupportedVersionsAllVersions) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    QuicEnableVersion(version);
  }
  ParsedQuicVersionVector expected_parsed_versions;
  for (const ParsedQuicVersion& version : SupportedVersions()) {
    expected_parsed_versions.push_back(version);
  }
  EXPECT_EQ(expected_parsed_versions,
            FilterSupportedVersions(AllSupportedVersions()));
  EXPECT_EQ(expected_parsed_versions, AllSupportedVersions());
}

TEST(QuicVersionsTest, FilterSupportedVersionsWithoutFirstVersion) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    QuicEnableVersion(version);
  }
  QuicDisableVersion(AllSupportedVersions().front());
  ParsedQuicVersionVector expected_parsed_versions;
  for (const ParsedQuicVersion& version : SupportedVersions()) {
    expected_parsed_versions.push_back(version);
  }
  expected_parsed_versions.erase(expected_parsed_versions.begin());
  EXPECT_EQ(expected_parsed_versions,
            FilterSupportedVersions(AllSupportedVersions()));
}

TEST(QuicVersionsTest, LookUpParsedVersionByIndex) {
  ParsedQuicVersionVector all_versions = AllSupportedVersions();
  int version_count = all_versions.size();
  for (int i = -5; i <= version_count + 1; ++i) {
    ParsedQuicVersionVector index = ParsedVersionOfIndex(all_versions, i);
    if (i >= 0 && i < version_count) {
      EXPECT_EQ(all_versions[i], index[0]);
    } else {
      EXPECT_EQ(UnsupportedQuicVersion(), index[0]);
    }
  }
}

// This test may appear to be so simplistic as to be unnecessary,
// yet a typo was made in doing the #defines and it was caught
// only in some test far removed from here... Better safe than sorry.
TEST(QuicVersionsTest, CheckTransportVersionNumbersForTypos) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  EXPECT_EQ(QUIC_VERSION_46, 46);
  EXPECT_EQ(QUIC_VERSION_IETF_DRAFT_29, 73);
  EXPECT_EQ(QUIC_VERSION_IETF_RFC_V1, 80);
  EXPECT_EQ(QUIC_VERSION_IETF_RFC_V2, 82);
}

TEST(QuicVersionsTest, AlpnForVersion) {
  static_assert(SupportedVersions().size() == 4u,
                "Supported versions out of sync");
  EXPECT_EQ("h3-Q046", AlpnForVersion(ParsedQuicVersion::Q046()));
  EXPECT_EQ("h3-29", AlpnForVersion(ParsedQuicVersion::Draft29()));
  EXPECT_EQ("h3", AlpnForVersion(ParsedQuicVersion::RFCv1()));
  EXPECT_EQ("h3", AlpnForVersion(ParsedQuicVersion::RFCv2()));
}

TEST(QuicVersionsTest, QuicVersionEnabling) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    QuicFlagSaver flag_saver;
    QuicDisableVersion(version);
    EXPECT_FALSE(QuicVersionIsEnabled(version));
    QuicEnableVersion(version);
    EXPECT_TRUE(QuicVersionIsEnabled(version));
  }
}

TEST(QuicVersionsTest, ReservedForNegotiation) {
  EXPECT_EQ(QUIC_VERSION_RESERVED_FOR_NEGOTIATION,
            QuicVersionReservedForNegotiation().transport_version);
  // QUIC_VERSION_RESERVED_FOR_NEGOTIATION MUST NOT be supported.
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_NE(QUIC_VERSION_RESERVED_FOR_NEGOTIATION, version.transport_version);
  }
}

TEST(QuicVersionsTest, SupportedVersionsHasCorrectList) {
  size_t index = 0;
  for (HandshakeProtocol handshake_protocol : SupportedHandshakeProtocols()) {
    for (int trans_vers = 255; trans_vers > 0; trans_vers--) {
      QuicTransportVersion transport_version =
          static_cast<QuicTransportVersion>(trans_vers);
      SCOPED_TRACE(index);
      if (ParsedQuicVersionIsValid(handshake_protocol, transport_version)) {
        ParsedQuicVersion version = SupportedVersions()[index];
        EXPECT_EQ(version,
                  ParsedQuicVersion(handshake_protocol, transport_version));
        index++;
      }
    }
  }
  EXPECT_EQ(SupportedVersions().size(), index);
}

TEST(QuicVersionsTest, SupportedVersionsAllDistinct) {
  for (size_t index1 = 0; index1 < SupportedVersions().size(); ++index1) {
    ParsedQuicVersion version1 = SupportedVersions()[index1];
    for (size_t index2 = index1 + 1; index2 < SupportedVersions().size();
         ++index2) {
      ParsedQuicVersion version2 = SupportedVersions()[index2];
      EXPECT_NE(version1, version2) << version1 << " " << version2;
      EXPECT_NE(CreateQuicVersionLabel(version1),
                CreateQuicVersionLabel(version2))
          << version1 << " " << version2;
      // The one pair where ALPNs are the same.
      if ((version1 != ParsedQuicVersion::RFCv2()) &&
          (version2 != ParsedQuicVersion::RFCv1())) {
        EXPECT_NE(AlpnForVersion(version1), AlpnForVersion(version2))
            << version1 << " " << version2;
      }
    }
  }
}

TEST(QuicVersionsTest, CurrentSupportedHttp3Versions) {
  ParsedQuicVersionVector h3_versions = CurrentSupportedHttp3Versions();
  ParsedQuicVersionVector all_current_supported_versions =
      CurrentSupportedVersions();
  for (auto& version : all_current_supported_versions) {
    bool version_is_h3 = false;
    for (auto& h3_version : h3_versions) {
      if (version == h3_version) {
        EXPECT_TRUE(version.UsesHttp3());
        version_is_h3 = true;
        break;
      }
    }
    if (!version_is_h3) {
      EXPECT_FALSE(version.UsesHttp3());
    }
  }
}

TEST(QuicVersionsTest, ObsoleteSupportedVersions) {
  ParsedQuicVersionVector obsolete_versions = ObsoleteSupportedVersions();
  EXPECT_EQ(quic::ParsedQuicVersion::Q046(), obsolete_versions[0]);
  EXPECT_EQ(quic::ParsedQuicVersion::Draft29(), obsolete_versions[1]);
}

TEST(QuicVersionsTest, IsObsoleteSupportedVersion) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    bool is_obsolete = version.handshake_protocol != PROTOCOL_TLS1_3 ||
                       version.transport_version < QUIC_VERSION_IETF_RFC_V1;
    EXPECT_EQ(is_obsolete, IsObsoleteSupportedVersion(version));
  }
}

TEST(QuicVersionsTest, CurrentSupportedVersionsForClients) {
  ParsedQuicVersionVector supported_versions = CurrentSupportedVersions();
  ParsedQuicVersionVector client_versions =
      CurrentSupportedVersionsForClients();
  for (auto& version : supported_versions) {
    const bool is_obsolete = IsObsoleteSupportedVersion(version);
    const bool is_supported =
        absl::c_find(client_versions, version) != client_versions.end();
    // Every supported version which is not obsolete should be a supported
    // client version.
    EXPECT_EQ(!is_obsolete, is_supported);
  }
  // Every client version should be a supported version, of course.
  for (auto& version : client_versions) {
    EXPECT_TRUE(absl::c_find(supported_versions, version) !=
                supported_versions.end());
  }
}

}  // namespace
}  // namespace test
}  // namespace quic
```