Response:
The user wants to understand the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_config_test.cc`. I need to analyze the code and explain its purpose, especially in the context of the Chromium network stack. I should also address the relationship with Javascript (if any), provide examples of logical reasoning with input and output, discuss common usage errors, and explain how a user might end up at this code during debugging. Finally, I need to summarize the overall function of this first part of the file.

Here's a breakdown of the code and how to address the user's request:

1. **Overall Purpose:** The file `quic_config_test.cc` contains unit tests for the `QuicConfig` class. This class likely manages the configuration parameters for a QUIC connection.

2. **Functionality Listing:** I will iterate through the test cases (`TEST_P`) and describe what each test is verifying. These tests cover setting default values, automatic configuration, and handling handshake messages (QUIC Crypto and Transport Parameters).

3. **Relationship with Javascript:**  QUIC is a transport layer protocol, and this specific C++ code deals with low-level configuration. There's no direct relationship with Javascript. However, I can explain that Javascript running in a browser might *use* the QUIC protocol (implemented in C++) for network communication. I'll provide an example of a browser making a fetch request and how the underlying network stack might use QUIC with certain configurations.

4. **Logical Reasoning (Input/Output):**  For specific test cases, I can create scenarios with hypothetical input values and the expected output based on the test's logic. For example, for `SetInitialStreamFlowControlWindowToSend`, if the input is `100000`, the output (as verified by the test) is that `GetInitialStreamFlowControlWindowToSend` returns `100000`.

5. **Common Usage Errors:**  I'll look for test cases that explicitly check for errors or boundary conditions. For example, the test for `InvalidFlowControlWindow` demonstrates a common mistake of setting a flow control window that is too small. I can also mention that incorrect configuration settings could lead to performance issues or connection failures.

6. **User Operation and Debugging:** I'll explain a typical scenario where a user's action in a web browser might involve the QUIC protocol and how a developer might end up debugging `QuicConfig`. For example, if a website loads slowly, a developer might inspect the network traffic and realize there are issues with the QUIC connection setup, leading them to investigate the configuration.

7. **Summary of Part 1:** I will synthesize the functionalities observed in the provided code snippet, highlighting that it focuses on testing various aspects of the `QuicConfig` class, primarily its behavior related to default values and the QUIC Crypto handshake.

**Mental Sandbox Simulation:**

* **Scanning the code:** I see a lot of `TEST_P` macros, indicating parameterized tests. The tests cover setting various configuration options and processing handshake messages.
* **Javascript connection:** I'll emphasize the indirect relationship – Javascript uses QUIC, but doesn't directly interact with this C++ code.
* **Input/Output:**  I can use the `SetInitialStreamFlowControlWindowToSend` test as a simple example.
* **Usage errors:** The `InvalidFlowControlWindow` test is a clear example. I can also think of scenarios where developers might misconfigure timeouts or flow control.
* **Debugging path:** A web developer noticing slow loading times is a good starting point. They might use browser developer tools to inspect network traffic and see QUIC connection details.
* **Part 1 summary:** The focus is clearly on basic configuration and QUIC Crypto handshake processing. Transport Parameters are introduced but not the primary focus of this section.

Strategizing complete. I will now generate the response based on the above analysis.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_config_test.cc` 文件的第一部分，其主要功能是 **测试 `QuicConfig` 类的各种功能**。`QuicConfig` 类负责管理 QUIC 连接的配置参数。

以下是该文件第一部分功能的详细列举：

1. **测试 `QuicConfig` 类的默认值设置:**
   - `TEST_P(QuicConfigTest, SetDefaults)` 验证了 `QuicConfig` 对象在创建后是否正确设置了默认的流控窗口大小、最大数据包大小等参数。
   - **假设输入:** 创建一个 `QuicConfig` 对象。
   - **预期输出:**  `GetInitialStreamFlowControlWindowToSend()` 等方法返回 `kMinimumFlowControlSendWindow`，`GetMaxPacketSizeToSend()` 返回 `kMaxIncomingPacketSize`，并且相关的 `HasReceived...` 方法返回 `false`。

2. **测试自动设置 IETF 流控参数:**
   - `TEST_P(QuicConfigTest, AutoSetIetfFlowControl)` 验证了当设置初始流控窗口时，是否会自动更新其他相关的 IETF QUIC 流控参数 (例如，双向和单向流的最大数据量)。
   - **假设输入:**  先调用 `SetInitialStreamFlowControlWindowToSend()` 设置一个值，然后调用 `SetInitialMaxStreamDataBytesIncomingBidirectionalToSend()` 设置另一个不同的值。
   - **预期输出:**  调用 `GetInitial...` 相关方法会返回之前设置的对应值。

3. **测试将 `QuicConfig` 转换为握手消息 (仅限 QUIC Crypto):**
   - `TEST_P(QuicConfigTest, ToHandshakeMessage)` 验证了可以将 `QuicConfig` 中的配置信息转换为 `CryptoHandshakeMessage` 对象，用于 QUIC Crypto 握手。 这部分代码只在非 TLS 版本的 QUIC 中执行。
   - **假设输入:**  设置流控窗口大小、空闲超时时间等配置，然后调用 `ToHandshakeMessage()`。
   - **预期输出:**  生成的 `CryptoHandshakeMessage` 对象中包含了对应配置项的标签和值 (例如，`kICSL` 对应空闲超时时间，`kSFCW` 对应流控窗口大小)。

4. **测试处理客户端 Hello 消息 (仅限 QUIC Crypto):**
   - `TEST_P(QuicConfigTest, ProcessClientHello)` 模拟服务器接收到客户端的 Hello 消息 (`CryptoHandshakeMessage`) 并处理其中的配置信息。这部分代码只在非 TLS 版本的 QUIC 中执行。
   - **假设输入:**  创建一个包含客户端配置信息的 `CryptoHandshakeMessage`，例如初始流控窗口大小、连接选项等。
   - **预期输出:**  `QuicConfig` 对象能够正确解析并存储客户端发送的配置信息，例如 `IdleNetworkTimeout()` 返回客户端设置的超时时间，`ReceivedConnectionOptions()` 包含客户端发送的连接选项。

5. **测试处理服务器 Hello 消息 (仅限 QUIC Crypto):**
   - `TEST_P(QuicConfigTest, ProcessServerHello)` 模拟客户端接收到服务器的 Hello 消息 (`CryptoHandshakeMessage`) 并处理其中的配置信息。这部分代码只在非 TLS 版本的 QUIC 中执行。
   - **假设输入:**  创建一个包含服务器配置信息的 `CryptoHandshakeMessage`，例如初始流控窗口大小、备用服务器地址、无状态重置令牌等。
   - **预期输出:**  `QuicConfig` 对象能够正确解析并存储服务器发送的配置信息，例如 `IdleNetworkTimeout()` 返回服务器设置的超时时间，`ReceivedIPv4AlternateServerAddress()` 返回服务器的备用 IPv4 地址。

6. **测试处理 Hello 消息中缺少可选值的情况 (仅限 QUIC Crypto):**
   - `TEST_P(QuicConfigTest, MissingOptionalValuesInCHLO)` 和 `TEST_P(QuicConfigTest, MissingOptionalValuesInSHLO)` 验证了在接收到客户端或服务器的 Hello 消息时，如果缺少某些可选的配置项，是否能够正常处理而不会报错。这部分代码只在非 TLS 版本的 QUIC 中执行。
   - **假设输入:**  创建一个 `CryptoHandshakeMessage`，其中缺少一些非必须的配置项。
   - **预期输出:**  `ProcessPeerHello()` 方法返回 `IsQuicNoError()`，表示处理成功。

7. **测试处理 Hello 消息中缺少必要值的情况 (仅限 QUIC Crypto):**
   - `TEST_P(QuicConfigTest, MissingValueInCHLO)` 和 `TEST_P(QuicConfigTest, MissingValueInSHLO)` 验证了在接收到客户端或服务器的 Hello 消息时，如果缺少必要的配置项，是否会返回相应的错误。这部分代码只在非 TLS 版本的 QUIC 中执行。
   - **假设输入:**  创建一个 `CryptoHandshakeMessage`，其中缺少一个必须的配置项 (例如 `kICSL`)。
   - **预期输出:**  `ProcessPeerHello()` 方法返回相应的错误码 `QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND`。

8. **测试处理超出范围的服务器 Hello 消息 (仅限 QUIC Crypto):**
   - `TEST_P(QuicConfigTest, OutOfBoundSHLO)` 验证了当服务器发送的某些配置值超出客户端允许的范围时，是否会返回相应的错误。这部分代码只在非 TLS 版本的 QUIC 中执行。
   - **假设输入:**  创建一个服务器 `QuicConfig`，设置一个超出客户端预期范围的空闲超时时间，并将其转换为 Hello 消息。
   - **预期输出:**  客户端的 `ProcessPeerHello()` 方法返回 `QUIC_INVALID_NEGOTIATED_VALUE` 错误。

9. **测试设置无效的流控窗口大小:**
   - `TEST_P(QuicConfigTest, InvalidFlowControlWindow)` 验证了 `QuicConfig` 是否会拒绝设置小于最小允许值的流控窗口大小。
   - **假设输入:**  尝试调用 `SetInitialStreamFlowControlWindowToSend()` 并传入一个小于 `kMinimumFlowControlSendWindow` 的值。
   - **预期输出:**  程序会触发 `EXPECT_QUIC_BUG` 断言，并且实际的流控窗口值不会被修改。

10. **测试检查客户端是否发送了特定的连接选项 (仅限 QUIC Crypto):**
    - `TEST_P(QuicConfigTest, HasClientSentConnectionOption)` 验证了可以判断客户端是否在 Hello 消息中发送了特定的连接选项。这部分代码只在非 TLS 版本的 QUIC 中执行。
    - **假设输入:**  创建一个客户端 `QuicConfig`，设置要发送的连接选项，然后将其转换为 Hello 消息并由服务器处理。
    - **预期输出:**  服务器的 `config_.HasClientSentConnectionOption()` 方法对于客户端发送的选项返回 `true`。

11. **测试不发送客户端连接选项 (仅限 QUIC Crypto):**
    - `TEST_P(QuicConfigTest, DontSendClientConnectionOptions)` 验证了使用 `SetClientConnectionOptions()` 设置的选项不会被发送到对端。这部分代码只在非 TLS 版本的 QUIC 中执行。
    - **假设输入:**  创建一个客户端 `QuicConfig`，使用 `SetClientConnectionOptions()` 设置一些选项，然后将其转换为 Hello 消息并由服务器处理。
    - **预期输出:**  服务器的 `config_.HasReceivedConnectionOptions()` 返回 `false`。

12. **测试检查客户端是否请求了独立的选项 (仅限 QUIC Crypto):**
    - `TEST_P(QuicConfigTest, HasClientRequestedIndependentOption)` 验证了可以区分客户端明确请求的选项和为了兼容性而发送的选项。这部分代码只在非 TLS 版本的 QUIC 中执行。
    - **假设输入:**  创建一个客户端 `QuicConfig`，使用 `SetClientConnectionOptions()` 设置一些选项，使用 `SetConnectionOptionsToSend()` 设置另一些选项，然后将其转换为 Hello 消息并由服务器处理。
    - **预期输出:**  服务器的 `config_.HasClientRequestedIndependentOption()` 方法能够正确判断哪些是独立请求的选项。

13. **测试处理过大的空闲超时时间传输参数 (仅限 QUIC TLS):**
    - `TEST_P(QuicConfigTest, IncomingLargeIdleTimeoutTransportParameter)` 验证了当接收到对端发送的超出本地配置的空闲超时时间时，会使用本地配置的值。这部分代码只在 TLS 版本的 QUIC 中执行。
    - **假设输入:**  本地配置一个较小的空闲超时时间，接收到的传输参数中包含一个较大的空闲超时时间。
    - **预期输出:**  `config_.IdleNetworkTimeout()` 返回本地配置的较小值。

14. **测试接收到无效的最小 ACK 延迟传输参数 (仅限 QUIC TLS):**
    - `TEST_P(QuicConfigTest, ReceivedInvalidMinAckDelayInTransportParameter)` 验证了当接收到的最小 ACK 延迟大于最大 ACK 延迟时，会返回错误。这部分代码只在 TLS 版本的 QUIC 中执行。
    - **假设输入:**  接收到的传输参数中，`min_ack_delay_us` 的值大于 `max_ack_delay` 的值。
    - **预期输出:**  `ProcessTransportParameters()` 返回 `IETF_QUIC_PROTOCOL_VIOLATION` 错误。

15. **测试填充传输参数 (仅限 QUIC TLS):**
    - `TEST_P(QuicConfigTest, FillTransportParams)` 验证了可以将 `QuicConfig` 中的配置信息填充到 `TransportParameters` 对象中，用于 QUIC TLS 握手。这部分代码只在 TLS 版本的 QUIC 中执行。
    - **假设输入:**  设置各种配置项，例如流控窗口大小、最大数据包大小、备用服务器地址等。
    - **预期输出:**  生成的 `TransportParameters` 对象中包含了对应的配置值。

16. **测试 DNAT 场景下的首选地址:**
    - `TEST_P(QuicConfigTest, DNATPreferredAddress)` 验证了在进行网络地址转换 (DNAT) 的情况下，能够正确设置和获取首选服务器地址和映射后的备用服务器地址。
    - **假设输入:**  设置用于 DNAT 的 IPv4 和 IPv6 的原始服务器地址和预期地址。
    - **预期输出:**  `GetPreferredAddressToSend()` 返回原始地址，`GetMappedAlternativeServerAddress()` 返回预期地址。

17. **测试不填充 IPv4 首选地址的情况 (仅限 QUIC TLS):**
    - `TEST_P(QuicConfigTest, FillTransportParamsNoV4PreferredAddress)` 验证了当不设置 IPv4 备用地址时，填充的传输参数中 IPv4 首选地址会被设置为通配符地址。这部分代码只在 TLS 版本的 QUIC 中执行。
    - **假设输入:**  只设置 IPv6 备用地址，不设置 IPv4 备用地址。
    - **预期输出:**  填充的 `TransportParameters` 中，IPv4 首选地址为 `0.0.0.0:0`。

18. **测试是否支持服务器首选地址:**
    - `TEST_P(QuicConfigTest, SupportsServerPreferredAddress)` 验证了在不同情况下（通过 flag 或者连接选项），客户端和服务器是否支持服务器首选地址功能。

19. **测试添加要发送的连接选项:**
    - `TEST_P(QuicConfigTest, AddConnectionOptionsToSend)` 验证了可以向 `QuicConfig` 对象添加要发送的连接选项。

20. **测试处理服务器发送的传输参数 (仅限 QUIC TLS):**
    - `TEST_P(QuicConfigTest, ProcessTransportParametersServer)` 验证了当服务器处理接收到的客户端传输参数时，能够正确解析并存储其中的配置信息。这部分代码只在 TLS 版本的 QUIC 中执行。
    - **假设输入:**  创建一个包含客户端配置信息的 `TransportParameters` 对象，例如流控窗口大小、最大数据包大小等。
    - **预期输出:**  `QuicConfig` 对象能够正确解析并存储客户端发送的配置信息，例如 `ReceivedInitialMaxStreamDataBytesIncomingBidirectional()` 返回客户端设置的流控窗口大小。同时，测试了在连接恢复的情况下，某些参数不会被处理。

**它与 Javascript 的功能关系：**

该 C++ 代码直接处理 QUIC 协议的底层配置，与 Javascript 没有直接的功能关系。然而，Javascript 在浏览器环境中可以通过 `fetch` API 或 WebSocket 等技术发起网络请求，这些请求底层可能会使用 QUIC 协议进行传输。

**举例说明:**

假设一个用户在 Chrome 浏览器中访问一个支持 QUIC 的网站。

1. **用户操作:** 用户在地址栏输入网址 `https://example.com` 并按下回车。
2. **浏览器行为:** Chrome 浏览器会尝试与 `example.com` 的服务器建立连接。
3. **QUIC 连接建立:** 如果服务器支持 QUIC，浏览器可能会尝试使用 QUIC 协议建立连接。
4. **`QuicConfig` 的作用:**  在 QUIC 连接建立的过程中，客户端和服务器会交换配置信息。`QuicConfig` 类在客户端和服务器端分别负责管理各自的配置参数。例如，客户端的 `QuicConfig` 可能会设置初始流控窗口大小，并将其包含在 Client Hello 消息中发送给服务器。服务器收到后，会使用其 `QuicConfig` 对象来解析并处理这些信息。

**用户或编程常见的使用错误举例说明:**

1. **设置过小的流控窗口:** 开发者可能会错误地将初始流控窗口大小设置为一个非常小的值，导致连接吞吐量受限，性能下降。`TEST_P(QuicConfigTest, InvalidFlowControlWindow)`  就测试了这种情况，防止设置无效的值。
2. **配置不匹配:** 客户端和服务器的某些配置参数必须兼容。例如，如果客户端请求了一个服务器不支持的连接选项，可能会导致连接建立失败。虽然这个测试文件没有直接测试配置不匹配的情况，但 `ProcessPeerHello` 系列的测试隐含地检查了对端发送的配置是否有效。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设一个网络应用的开发者发现用户在使用他们的应用时，QUIC 连接的性能非常差，或者经常出现连接失败的情况。

1. **问题报告:** 用户报告应用加载缓慢或出现网络错误。
2. **开发者排查:** 开发者开始检查应用的后台服务和客户端的网络连接。
3. **抓包分析:** 开发者可能会使用 Wireshark 等抓包工具捕获网络数据包，发现连接使用的是 QUIC 协议。
4. **QUIC 连接细节分析:** 开发者可能会深入分析 QUIC 握手过程中的数据包，查看客户端和服务器交换的配置信息 (例如，通过查看 Client Hello 和 Server Hello 消息)。
5. **怀疑配置问题:** 如果开发者发现握手消息中的某些配置参数异常 (例如，流控窗口过小，或者协商的连接选项不合理)，他们可能会怀疑是 `QuicConfig` 的配置出现了问题。
6. **代码调试:** 开发者可能会查看 Chromium 的 QUIC 源代码，特别是 `quic_config.cc` 和 `quic_config_test.cc`，来理解 `QuicConfig` 的工作原理，以及如何正确设置和处理配置参数。`quic_config_test.cc` 中的测试用例可以帮助开发者理解各种配置场景和可能出现的错误。
7. **定位问题:** 通过分析测试用例和实际的网络数据包，开发者可能会找到导致性能问题的配置错误，例如在代码中错误地设置了初始流控窗口大小。
8. **修复代码:** 开发者会修改代码，确保 `QuicConfig` 对象被正确初始化和配置。

**归纳一下它的功能:**

总而言之，`net/third_party/quiche/src/quiche/quic/core/quic_config_test.cc` 的第一部分主要功能是 **全面地测试 `QuicConfig` 类的各种功能，包括默认值设置、自动配置、与 QUIC Crypto 握手消息的转换和处理，以及对无效配置的处理。** 这些测试确保了 `QuicConfig` 类能够正确地管理 QUIC 连接的配置参数，并在各种场景下都能正常工作，从而保证 QUIC 连接的稳定性和性能。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_config_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "quiche/quic/core/crypto/crypto_handshake_message.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace test {
namespace {

class QuicConfigTest : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  QuicConfigTest() : version_(GetParam()) {}

 protected:
  ParsedQuicVersion version_;
  QuicConfig config_;
};

// Run all tests with all versions of QUIC.
INSTANTIATE_TEST_SUITE_P(QuicConfigTests, QuicConfigTest,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicConfigTest, SetDefaults) {
  EXPECT_EQ(kMinimumFlowControlSendWindow,
            config_.GetInitialStreamFlowControlWindowToSend());
  EXPECT_EQ(kMinimumFlowControlSendWindow,
            config_.GetInitialMaxStreamDataBytesIncomingBidirectionalToSend());
  EXPECT_EQ(kMinimumFlowControlSendWindow,
            config_.GetInitialMaxStreamDataBytesOutgoingBidirectionalToSend());
  EXPECT_EQ(kMinimumFlowControlSendWindow,
            config_.GetInitialMaxStreamDataBytesUnidirectionalToSend());
  EXPECT_FALSE(config_.HasReceivedInitialStreamFlowControlWindowBytes());
  EXPECT_FALSE(
      config_.HasReceivedInitialMaxStreamDataBytesIncomingBidirectional());
  EXPECT_FALSE(
      config_.HasReceivedInitialMaxStreamDataBytesOutgoingBidirectional());
  EXPECT_FALSE(config_.HasReceivedInitialMaxStreamDataBytesUnidirectional());
  EXPECT_EQ(kMaxIncomingPacketSize, config_.GetMaxPacketSizeToSend());
  EXPECT_FALSE(config_.HasReceivedMaxPacketSize());
}

TEST_P(QuicConfigTest, AutoSetIetfFlowControl) {
  EXPECT_EQ(kMinimumFlowControlSendWindow,
            config_.GetInitialStreamFlowControlWindowToSend());
  EXPECT_EQ(kMinimumFlowControlSendWindow,
            config_.GetInitialMaxStreamDataBytesIncomingBidirectionalToSend());
  EXPECT_EQ(kMinimumFlowControlSendWindow,
            config_.GetInitialMaxStreamDataBytesOutgoingBidirectionalToSend());
  EXPECT_EQ(kMinimumFlowControlSendWindow,
            config_.GetInitialMaxStreamDataBytesUnidirectionalToSend());
  static const uint32_t kTestWindowSize = 1234567;
  config_.SetInitialStreamFlowControlWindowToSend(kTestWindowSize);
  EXPECT_EQ(kTestWindowSize, config_.GetInitialStreamFlowControlWindowToSend());
  EXPECT_EQ(kTestWindowSize,
            config_.GetInitialMaxStreamDataBytesIncomingBidirectionalToSend());
  EXPECT_EQ(kTestWindowSize,
            config_.GetInitialMaxStreamDataBytesOutgoingBidirectionalToSend());
  EXPECT_EQ(kTestWindowSize,
            config_.GetInitialMaxStreamDataBytesUnidirectionalToSend());
  static const uint32_t kTestWindowSizeTwo = 2345678;
  config_.SetInitialMaxStreamDataBytesIncomingBidirectionalToSend(
      kTestWindowSizeTwo);
  EXPECT_EQ(kTestWindowSize, config_.GetInitialStreamFlowControlWindowToSend());
  EXPECT_EQ(kTestWindowSizeTwo,
            config_.GetInitialMaxStreamDataBytesIncomingBidirectionalToSend());
  EXPECT_EQ(kTestWindowSize,
            config_.GetInitialMaxStreamDataBytesOutgoingBidirectionalToSend());
  EXPECT_EQ(kTestWindowSize,
            config_.GetInitialMaxStreamDataBytesUnidirectionalToSend());
}

TEST_P(QuicConfigTest, ToHandshakeMessage) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  config_.SetInitialStreamFlowControlWindowToSend(
      kInitialStreamFlowControlWindowForTest);
  config_.SetInitialSessionFlowControlWindowToSend(
      kInitialSessionFlowControlWindowForTest);
  config_.SetIdleNetworkTimeout(QuicTime::Delta::FromSeconds(5));
  CryptoHandshakeMessage msg;
  config_.ToHandshakeMessage(&msg, version_.transport_version);

  uint32_t value;
  QuicErrorCode error = msg.GetUint32(kICSL, &value);
  EXPECT_THAT(error, IsQuicNoError());
  EXPECT_EQ(5u, value);

  error = msg.GetUint32(kSFCW, &value);
  EXPECT_THAT(error, IsQuicNoError());
  EXPECT_EQ(kInitialStreamFlowControlWindowForTest, value);

  error = msg.GetUint32(kCFCW, &value);
  EXPECT_THAT(error, IsQuicNoError());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest, value);
}

TEST_P(QuicConfigTest, ProcessClientHello) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  const uint32_t kTestMaxAckDelayMs =
      static_cast<uint32_t>(GetDefaultDelayedAckTimeMs() + 1);
  QuicConfig client_config;
  QuicTagVector cgst;
  cgst.push_back(kQBIC);
  client_config.SetIdleNetworkTimeout(
      QuicTime::Delta::FromSeconds(2 * kMaximumIdleTimeoutSecs));
  client_config.SetInitialRoundTripTimeUsToSend(10 * kNumMicrosPerMilli);
  client_config.SetInitialStreamFlowControlWindowToSend(
      2 * kInitialStreamFlowControlWindowForTest);
  client_config.SetInitialSessionFlowControlWindowToSend(
      2 * kInitialSessionFlowControlWindowForTest);
  QuicTagVector copt;
  copt.push_back(kTBBR);
  client_config.SetConnectionOptionsToSend(copt);
  client_config.SetMaxAckDelayToSendMs(kTestMaxAckDelayMs);
  CryptoHandshakeMessage msg;
  client_config.ToHandshakeMessage(&msg, version_.transport_version);

  std::string error_details;
  QuicTagVector initial_received_options;
  initial_received_options.push_back(kIW50);
  EXPECT_TRUE(
      config_.SetInitialReceivedConnectionOptions(initial_received_options));
  EXPECT_FALSE(
      config_.SetInitialReceivedConnectionOptions(initial_received_options))
      << "You can only set initial options once.";
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_FALSE(
      config_.SetInitialReceivedConnectionOptions(initial_received_options))
      << "You cannot set initial options after the hello.";
  EXPECT_THAT(error, IsQuicNoError());
  EXPECT_TRUE(config_.negotiated());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs),
            config_.IdleNetworkTimeout());
  EXPECT_EQ(10 * kNumMicrosPerMilli, config_.ReceivedInitialRoundTripTimeUs());
  EXPECT_TRUE(config_.HasReceivedConnectionOptions());
  EXPECT_EQ(2u, config_.ReceivedConnectionOptions().size());
  EXPECT_EQ(config_.ReceivedConnectionOptions()[0], kIW50);
  EXPECT_EQ(config_.ReceivedConnectionOptions()[1], kTBBR);
  EXPECT_EQ(config_.ReceivedInitialStreamFlowControlWindowBytes(),
            2 * kInitialStreamFlowControlWindowForTest);
  EXPECT_EQ(config_.ReceivedInitialSessionFlowControlWindowBytes(),
            2 * kInitialSessionFlowControlWindowForTest);
  EXPECT_TRUE(config_.HasReceivedMaxAckDelayMs());
  EXPECT_EQ(kTestMaxAckDelayMs, config_.ReceivedMaxAckDelayMs());

  // IETF QUIC stream limits should not be received in QUIC crypto messages.
  EXPECT_FALSE(
      config_.HasReceivedInitialMaxStreamDataBytesIncomingBidirectional());
  EXPECT_FALSE(
      config_.HasReceivedInitialMaxStreamDataBytesOutgoingBidirectional());
  EXPECT_FALSE(config_.HasReceivedInitialMaxStreamDataBytesUnidirectional());
}

TEST_P(QuicConfigTest, ProcessServerHello) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  QuicIpAddress host;
  host.FromString("127.0.3.1");
  const QuicSocketAddress kTestServerAddress = QuicSocketAddress(host, 1234);
  const StatelessResetToken kTestStatelessResetToken{
      0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
      0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};
  const uint32_t kTestMaxAckDelayMs =
      static_cast<uint32_t>(GetDefaultDelayedAckTimeMs() + 1);
  QuicConfig server_config;
  QuicTagVector cgst;
  cgst.push_back(kQBIC);
  server_config.SetIdleNetworkTimeout(
      QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs / 2));
  server_config.SetInitialRoundTripTimeUsToSend(10 * kNumMicrosPerMilli);
  server_config.SetInitialStreamFlowControlWindowToSend(
      2 * kInitialStreamFlowControlWindowForTest);
  server_config.SetInitialSessionFlowControlWindowToSend(
      2 * kInitialSessionFlowControlWindowForTest);
  server_config.SetIPv4AlternateServerAddressToSend(kTestServerAddress);
  server_config.SetStatelessResetTokenToSend(kTestStatelessResetToken);
  server_config.SetMaxAckDelayToSendMs(kTestMaxAckDelayMs);
  CryptoHandshakeMessage msg;
  server_config.ToHandshakeMessage(&msg, version_.transport_version);
  std::string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, SERVER, &error_details);
  EXPECT_THAT(error, IsQuicNoError());
  EXPECT_TRUE(config_.negotiated());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs / 2),
            config_.IdleNetworkTimeout());
  EXPECT_EQ(10 * kNumMicrosPerMilli, config_.ReceivedInitialRoundTripTimeUs());
  EXPECT_EQ(config_.ReceivedInitialStreamFlowControlWindowBytes(),
            2 * kInitialStreamFlowControlWindowForTest);
  EXPECT_EQ(config_.ReceivedInitialSessionFlowControlWindowBytes(),
            2 * kInitialSessionFlowControlWindowForTest);
  EXPECT_TRUE(config_.HasReceivedIPv4AlternateServerAddress());
  EXPECT_EQ(kTestServerAddress, config_.ReceivedIPv4AlternateServerAddress());
  EXPECT_FALSE(config_.HasReceivedIPv6AlternateServerAddress());
  EXPECT_TRUE(config_.HasReceivedStatelessResetToken());
  EXPECT_EQ(kTestStatelessResetToken, config_.ReceivedStatelessResetToken());
  EXPECT_TRUE(config_.HasReceivedMaxAckDelayMs());
  EXPECT_EQ(kTestMaxAckDelayMs, config_.ReceivedMaxAckDelayMs());

  // IETF QUIC stream limits should not be received in QUIC crypto messages.
  EXPECT_FALSE(
      config_.HasReceivedInitialMaxStreamDataBytesIncomingBidirectional());
  EXPECT_FALSE(
      config_.HasReceivedInitialMaxStreamDataBytesOutgoingBidirectional());
  EXPECT_FALSE(config_.HasReceivedInitialMaxStreamDataBytesUnidirectional());
}

TEST_P(QuicConfigTest, MissingOptionalValuesInCHLO) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  CryptoHandshakeMessage msg;
  msg.SetValue(kICSL, 1);

  // Set all REQUIRED tags.
  msg.SetValue(kICSL, 1);
  msg.SetValue(kMIBS, 1);

  // No error, as rest are optional.
  std::string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_THAT(error, IsQuicNoError());
  EXPECT_TRUE(config_.negotiated());
}

TEST_P(QuicConfigTest, MissingOptionalValuesInSHLO) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  CryptoHandshakeMessage msg;

  // Set all REQUIRED tags.
  msg.SetValue(kICSL, 1);
  msg.SetValue(kMIBS, 1);

  // No error, as rest are optional.
  std::string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, SERVER, &error_details);
  EXPECT_THAT(error, IsQuicNoError());
  EXPECT_TRUE(config_.negotiated());
}

TEST_P(QuicConfigTest, MissingValueInCHLO) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  // Server receives CHLO with missing kICSL.
  CryptoHandshakeMessage msg;
  std::string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_THAT(error, IsError(QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND));
}

TEST_P(QuicConfigTest, MissingValueInSHLO) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  // Client receives SHLO with missing kICSL.
  CryptoHandshakeMessage msg;
  std::string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, SERVER, &error_details);
  EXPECT_THAT(error, IsError(QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND));
}

TEST_P(QuicConfigTest, OutOfBoundSHLO) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  QuicConfig server_config;
  server_config.SetIdleNetworkTimeout(
      QuicTime::Delta::FromSeconds(2 * kMaximumIdleTimeoutSecs));

  CryptoHandshakeMessage msg;
  server_config.ToHandshakeMessage(&msg, version_.transport_version);
  std::string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, SERVER, &error_details);
  EXPECT_THAT(error, IsError(QUIC_INVALID_NEGOTIATED_VALUE));
}

TEST_P(QuicConfigTest, InvalidFlowControlWindow) {
  // QuicConfig should not accept an invalid flow control window to send to the
  // peer: the receive window must be at least the default of 16 Kb.
  QuicConfig config;
  const uint64_t kInvalidWindow = kMinimumFlowControlSendWindow - 1;
  EXPECT_QUIC_BUG(
      config.SetInitialStreamFlowControlWindowToSend(kInvalidWindow),
      "Initial stream flow control receive window");

  EXPECT_EQ(kMinimumFlowControlSendWindow,
            config.GetInitialStreamFlowControlWindowToSend());
}

TEST_P(QuicConfigTest, HasClientSentConnectionOption) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  QuicConfig client_config;
  QuicTagVector copt;
  copt.push_back(kTBBR);
  copt.push_back(kPRGC);
  client_config.SetConnectionOptionsToSend(copt);
  EXPECT_TRUE(client_config.HasClientSentConnectionOption(
      kTBBR, Perspective::IS_CLIENT));
  EXPECT_TRUE(client_config.HasClientSentConnectionOption(
      kPRGC, Perspective::IS_CLIENT));

  CryptoHandshakeMessage msg;
  client_config.ToHandshakeMessage(&msg, version_.transport_version);

  std::string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_THAT(error, IsQuicNoError());
  EXPECT_TRUE(config_.negotiated());

  EXPECT_TRUE(config_.HasReceivedConnectionOptions());
  EXPECT_EQ(2u, config_.ReceivedConnectionOptions().size());
  EXPECT_TRUE(
      config_.HasClientSentConnectionOption(kTBBR, Perspective::IS_SERVER));
  EXPECT_TRUE(
      config_.HasClientSentConnectionOption(kPRGC, Perspective::IS_SERVER));
}

TEST_P(QuicConfigTest, DontSendClientConnectionOptions) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  QuicConfig client_config;
  QuicTagVector copt;
  copt.push_back(kTBBR);
  client_config.SetClientConnectionOptions(copt);

  CryptoHandshakeMessage msg;
  client_config.ToHandshakeMessage(&msg, version_.transport_version);

  std::string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_THAT(error, IsQuicNoError());
  EXPECT_TRUE(config_.negotiated());

  EXPECT_FALSE(config_.HasReceivedConnectionOptions());
}

TEST_P(QuicConfigTest, HasClientRequestedIndependentOption) {
  if (version_.UsesTls()) {
    // CryptoHandshakeMessage is only used for QUIC_CRYPTO.
    return;
  }
  QuicConfig client_config;
  QuicTagVector client_opt;
  client_opt.push_back(kRENO);
  QuicTagVector copt;
  copt.push_back(kTBBR);
  client_config.SetClientConnectionOptions(client_opt);
  client_config.SetConnectionOptionsToSend(copt);
  EXPECT_TRUE(client_config.HasClientSentConnectionOption(
      kTBBR, Perspective::IS_CLIENT));
  EXPECT_TRUE(client_config.HasClientRequestedIndependentOption(
      kRENO, Perspective::IS_CLIENT));
  EXPECT_FALSE(client_config.HasClientRequestedIndependentOption(
      kTBBR, Perspective::IS_CLIENT));

  CryptoHandshakeMessage msg;
  client_config.ToHandshakeMessage(&msg, version_.transport_version);

  std::string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_THAT(error, IsQuicNoError());
  EXPECT_TRUE(config_.negotiated());

  EXPECT_TRUE(config_.HasReceivedConnectionOptions());
  EXPECT_EQ(1u, config_.ReceivedConnectionOptions().size());
  EXPECT_FALSE(config_.HasClientRequestedIndependentOption(
      kRENO, Perspective::IS_SERVER));
  EXPECT_TRUE(config_.HasClientRequestedIndependentOption(
      kTBBR, Perspective::IS_SERVER));
}

TEST_P(QuicConfigTest, IncomingLargeIdleTimeoutTransportParameter) {
  if (!version_.UsesTls()) {
    // TransportParameters are only used for QUIC+TLS.
    return;
  }
  // Configure our idle timeout to 60s, then receive 120s from peer.
  // Since the received value is above ours, we should then use ours.
  config_.SetIdleNetworkTimeout(quic::QuicTime::Delta::FromSeconds(60));
  TransportParameters params;
  params.max_idle_timeout_ms.set_value(120000);

  std::string error_details = "foobar";
  EXPECT_THAT(config_.ProcessTransportParameters(
                  params, /* is_resumption = */ false, &error_details),
              IsQuicNoError());
  EXPECT_EQ("", error_details);
  EXPECT_EQ(quic::QuicTime::Delta::FromSeconds(60),
            config_.IdleNetworkTimeout());
}

TEST_P(QuicConfigTest, ReceivedInvalidMinAckDelayInTransportParameter) {
  if (!version_.UsesTls()) {
    // TransportParameters are only used for QUIC+TLS.
    return;
  }
  TransportParameters params;

  params.max_ack_delay.set_value(25 /*ms*/);
  params.min_ack_delay_us.set_value(25 * kNumMicrosPerMilli + 1);
  std::string error_details = "foobar";
  EXPECT_THAT(config_.ProcessTransportParameters(
                  params, /* is_resumption = */ false, &error_details),
              IsError(IETF_QUIC_PROTOCOL_VIOLATION));
  EXPECT_EQ("MinAckDelay is greater than MaxAckDelay.", error_details);

  params.max_ack_delay.set_value(25 /*ms*/);
  params.min_ack_delay_us.set_value(25 * kNumMicrosPerMilli);
  EXPECT_THAT(config_.ProcessTransportParameters(
                  params, /* is_resumption = */ false, &error_details),
              IsQuicNoError());
  EXPECT_TRUE(error_details.empty());
}

TEST_P(QuicConfigTest, FillTransportParams) {
  if (!version_.UsesTls()) {
    // TransportParameters are only used for QUIC+TLS.
    return;
  }
  const std::string kFakeGoogleHandshakeMessage = "Fake handshake message";
  const int32_t kDiscardLength = 2000;
  config_.SetInitialMaxStreamDataBytesIncomingBidirectionalToSend(
      2 * kMinimumFlowControlSendWindow);
  config_.SetInitialMaxStreamDataBytesOutgoingBidirectionalToSend(
      3 * kMinimumFlowControlSendWindow);
  config_.SetInitialMaxStreamDataBytesUnidirectionalToSend(
      4 * kMinimumFlowControlSendWindow);
  config_.SetMaxPacketSizeToSend(kMaxPacketSizeForTest);
  config_.SetMaxDatagramFrameSizeToSend(kMaxDatagramFrameSizeForTest);
  config_.SetActiveConnectionIdLimitToSend(kActiveConnectionIdLimitForTest);

  config_.SetOriginalConnectionIdToSend(TestConnectionId(0x1111));
  config_.SetInitialSourceConnectionIdToSend(TestConnectionId(0x2222));
  config_.SetRetrySourceConnectionIdToSend(TestConnectionId(0x3333));
  config_.SetMinAckDelayMs(kDefaultMinAckDelayTimeMs);
  config_.SetDiscardLengthToSend(kDiscardLength);
  config_.SetGoogleHandshakeMessageToSend(kFakeGoogleHandshakeMessage);
  config_.SetReliableStreamReset(true);

  QuicIpAddress host;
  host.FromString("127.0.3.1");
  QuicSocketAddress kTestServerAddress = QuicSocketAddress(host, 1234);
  QuicConnectionId new_connection_id = TestConnectionId(5);
  StatelessResetToken new_stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(new_connection_id);
  config_.SetIPv4AlternateServerAddressToSend(kTestServerAddress);
  QuicSocketAddress kTestServerAddressV6 =
      QuicSocketAddress(QuicIpAddress::Any6(), 1234);
  config_.SetIPv6AlternateServerAddressToSend(kTestServerAddressV6);
  config_.SetPreferredAddressConnectionIdAndTokenToSend(
      new_connection_id, new_stateless_reset_token);
  config_.ClearAlternateServerAddressToSend(quiche::IpAddressFamily::IP_V6);
  EXPECT_TRUE(config_.GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V4)
                  .has_value());
  EXPECT_FALSE(config_.GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V6)
                   .has_value());

  TransportParameters params;
  config_.FillTransportParameters(&params);

  EXPECT_EQ(2 * kMinimumFlowControlSendWindow,
            params.initial_max_stream_data_bidi_remote.value());
  EXPECT_EQ(3 * kMinimumFlowControlSendWindow,
            params.initial_max_stream_data_bidi_local.value());
  EXPECT_EQ(4 * kMinimumFlowControlSendWindow,
            params.initial_max_stream_data_uni.value());

  EXPECT_EQ(static_cast<uint64_t>(kMaximumIdleTimeoutSecs * 1000),
            params.max_idle_timeout_ms.value());

  EXPECT_EQ(kMaxPacketSizeForTest, params.max_udp_payload_size.value());
  EXPECT_EQ(kMaxDatagramFrameSizeForTest,
            params.max_datagram_frame_size.value());
  EXPECT_EQ(kActiveConnectionIdLimitForTest,
            params.active_connection_id_limit.value());

  ASSERT_TRUE(params.original_destination_connection_id.has_value());
  EXPECT_EQ(TestConnectionId(0x1111),
            params.original_destination_connection_id.value());
  ASSERT_TRUE(params.initial_source_connection_id.has_value());
  EXPECT_EQ(TestConnectionId(0x2222),
            params.initial_source_connection_id.value());
  ASSERT_TRUE(params.retry_source_connection_id.has_value());
  EXPECT_EQ(TestConnectionId(0x3333),
            params.retry_source_connection_id.value());

  EXPECT_EQ(
      static_cast<uint64_t>(kDefaultMinAckDelayTimeMs) * kNumMicrosPerMilli,
      params.min_ack_delay_us.value());

  EXPECT_EQ(params.preferred_address->ipv4_socket_address, kTestServerAddress);
  EXPECT_EQ(params.preferred_address->ipv6_socket_address,
            QuicSocketAddress(QuicIpAddress::Any6(), 0));

  EXPECT_EQ(*reinterpret_cast<StatelessResetToken*>(
                &params.preferred_address->stateless_reset_token.front()),
            new_stateless_reset_token);
  EXPECT_EQ(kDiscardLength, params.discard_length);
  EXPECT_EQ(kFakeGoogleHandshakeMessage, params.google_handshake_message);

  EXPECT_TRUE(params.reliable_stream_reset);
}

TEST_P(QuicConfigTest, DNATPreferredAddress) {
  QuicIpAddress host_v4;
  host_v4.FromString("127.0.3.1");
  QuicSocketAddress server_address_v4 = QuicSocketAddress(host_v4, 1234);
  QuicSocketAddress expected_server_address_v4 =
      QuicSocketAddress(host_v4, 1235);

  QuicIpAddress host_v6;
  host_v6.FromString("2001:db8:0::1");
  QuicSocketAddress server_address_v6 = QuicSocketAddress(host_v6, 1234);
  QuicSocketAddress expected_server_address_v6 =
      QuicSocketAddress(host_v6, 1235);

  config_.SetIPv4AlternateServerAddressForDNat(server_address_v4,
                                               expected_server_address_v4);
  config_.SetIPv6AlternateServerAddressForDNat(server_address_v6,
                                               expected_server_address_v6);

  EXPECT_EQ(server_address_v4,
            config_.GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V4));
  EXPECT_EQ(server_address_v6,
            config_.GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V6));

  EXPECT_EQ(expected_server_address_v4,
            config_.GetMappedAlternativeServerAddress(
                quiche::IpAddressFamily::IP_V4));
  EXPECT_EQ(expected_server_address_v6,
            config_.GetMappedAlternativeServerAddress(
                quiche::IpAddressFamily::IP_V6));
}

TEST_P(QuicConfigTest, FillTransportParamsNoV4PreferredAddress) {
  if (!version_.UsesTls()) {
    // TransportParameters are only used for QUIC+TLS.
    return;
  }

  QuicIpAddress host;
  host.FromString("127.0.3.1");
  QuicSocketAddress kTestServerAddress = QuicSocketAddress(host, 1234);
  QuicConnectionId new_connection_id = TestConnectionId(5);
  StatelessResetToken new_stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(new_connection_id);
  config_.SetIPv4AlternateServerAddressToSend(kTestServerAddress);
  QuicSocketAddress kTestServerAddressV6 =
      QuicSocketAddress(QuicIpAddress::Any6(), 1234);
  config_.SetIPv6AlternateServerAddressToSend(kTestServerAddressV6);
  config_.SetPreferredAddressConnectionIdAndTokenToSend(
      new_connection_id, new_stateless_reset_token);
  config_.ClearAlternateServerAddressToSend(quiche::IpAddressFamily::IP_V4);
  EXPECT_FALSE(config_.GetPreferredAddressToSend(quiche::IpAddressFamily::IP_V4)
                   .has_value());
  config_.ClearAlternateServerAddressToSend(quiche::IpAddressFamily::IP_V4);

  TransportParameters params;
  config_.FillTransportParameters(&params);
  EXPECT_EQ(params.preferred_address->ipv4_socket_address,
            QuicSocketAddress(QuicIpAddress::Any4(), 0));
  EXPECT_EQ(params.preferred_address->ipv6_socket_address,
            kTestServerAddressV6);
}

TEST_P(QuicConfigTest, SupportsServerPreferredAddress) {
  SetQuicFlag(quic_always_support_server_preferred_address, true);
  EXPECT_TRUE(config_.SupportsServerPreferredAddress(Perspective::IS_CLIENT));
  EXPECT_TRUE(config_.SupportsServerPreferredAddress(Perspective::IS_SERVER));

  SetQuicFlag(quic_always_support_server_preferred_address, false);
  EXPECT_TRUE(config_.SupportsServerPreferredAddress(Perspective::IS_CLIENT));
  EXPECT_FALSE(config_.SupportsServerPreferredAddress(Perspective::IS_SERVER));

  QuicTagVector copt;
  copt.push_back(kSPAD);
  config_.SetConnectionOptionsToSend(copt);
  EXPECT_TRUE(config_.SupportsServerPreferredAddress(Perspective::IS_CLIENT));
  EXPECT_FALSE(config_.SupportsServerPreferredAddress(Perspective::IS_SERVER));

  config_.SetInitialReceivedConnectionOptions(copt);
  EXPECT_TRUE(config_.SupportsServerPreferredAddress(Perspective::IS_CLIENT));
  EXPECT_TRUE(config_.SupportsServerPreferredAddress(Perspective::IS_SERVER));
}

TEST_P(QuicConfigTest, AddConnectionOptionsToSend) {
  QuicTagVector copt;
  copt.push_back(kNOIP);
  copt.push_back(kFPPE);
  config_.AddConnectionOptionsToSend(copt);
  ASSERT_TRUE(config_.HasSendConnectionOptions());
  EXPECT_TRUE(quic::ContainsQuicTag(config_.SendConnectionOptions(), kNOIP));
  EXPECT_TRUE(quic::ContainsQuicTag(config_.SendConnectionOptions(), kFPPE));

  copt.clear();
  copt.push_back(kSPAD);
  copt.push_back(kSPA2);
  config_.AddConnectionOptionsToSend(copt);
  ASSERT_EQ(4, config_.SendConnectionOptions().size());
  EXPECT_TRUE(quic::ContainsQuicTag(config_.SendConnectionOptions(), kNOIP));
  EXPECT_TRUE(quic::ContainsQuicTag(config_.SendConnectionOptions(), kFPPE));
  EXPECT_TRUE(quic::ContainsQuicTag(config_.SendConnectionOptions(), kSPAD));
  EXPECT_TRUE(quic::ContainsQuicTag(config_.SendConnectionOptions(), kSPA2));
}

TEST_P(QuicConfigTest, ProcessTransportParametersServer) {
  if (!version_.UsesTls()) {
    // TransportParameters are only used for QUIC+TLS.
    return;
  }
  const std::string kFakeGoogleHandshakeMessage = "Fake handshake message";
  const int32_t kDiscardLength = 2000;
  TransportParameters params;

  params.initial_max_stream_data_bidi_local.set_value(
      2 * kMinimumFlowControlSendWindow);
  params.initial_max_stream_data_bidi_remote.set_value(
      3 * kMinimumFlowControlSendWindow);
  params.initial_max_stream_data_uni.set_value(4 *
                                               kMinimumFlowControlSendWindow);
  params.max_udp_payload_size.set_value(kMaxPacketSizeForTest);
  params.max_datagram_frame_size.set_value(kMaxDatagramFrameSizeForTest);
  params.initial_max_streams_bidi.set_value(kDefaultMaxStreamsPerConnection);
  params.stateless_reset_token = CreateStatelessResetTokenForTest();
  params.max_ack_delay.set_value(kMaxAckDelayForTest);
  params.min_ack_delay_us.set_value(kMinAckDelayUsForTest);
  params.ack_delay_exponent.set_value(kAckDelayExponentForTest);
  params.active_connection_id_limit.set_value(kActiveConnectionIdLimitForTest);
  params.original_destination_connection_id = TestConnectionId(0x1111);
  params.initial_source_connection_id = TestConnectionId(0x2222);
  params.retry_source_connection_id = TestConnectionId(0x3333);
  params.discard_length = kDiscardLength;
  params.google_handshake_message = kFakeGoogleHandshakeMessage;

  std::string error_details;
  EXPECT_THAT(config_.ProcessTransportParameters(
                  params, /* is_resumption = */ true, &error_details),
              IsQuicNoError())
      << error_details;

  EXPECT_FALSE(config_.negotiated());

  ASSERT_TRUE(
      config_.HasReceivedInitialMaxStreamDataBytesIncomingBidirectional());
  EXPECT_EQ(2 * kMinimumFlowControlSendWindow,
            config_.ReceivedInitialMaxStreamDataBytesIncomingBidirectional());

  ASSERT_TRUE(
      config_.HasReceivedInitialMaxStreamDataBytesOutgoingBidirectional());
  EXPECT_EQ(3 * kMinimumFlowControlSendWindow,
            config_.ReceivedInitialMaxStreamDataBytesOutgoingBidirectional());

  ASSERT_TRUE(config_.HasReceivedInitialMaxStreamDataBytesUnidirectional());
  EXPECT_EQ(4 * kMinimumFlowControlSendWindow,
            config_.ReceivedInitialMaxStreamDataBytesUnidirectional());

  ASSERT_TRUE(config_.HasReceivedMaxPacketSize());
  EXPECT_EQ(kMaxPacketSizeForTest, config_.ReceivedMaxPacketSize());

  ASSERT_TRUE(config_.HasReceivedMaxDatagramFrameSize());
  EXPECT_EQ(kMaxDatagramFrameSizeForTest,
            config_.ReceivedMaxDatagramFrameSize());

  ASSERT_TRUE(config_.HasReceivedMaxBidirectionalStreams());
  EXPECT_EQ(kDefaultMaxStreamsPerConnection,
            config_.ReceivedMaxBidirectionalStreams());

  EXPECT_FALSE(config_.DisableConnectionMigration());

  // The following config shouldn't be processed because of resumption.
  EXPECT_FALSE(config_.HasReceivedStatelessResetToken());
  EXPECT_FALSE(config_.HasReceivedMaxAckDelayMs());
  EXPECT_FALSE(config_.HasReceivedAckDelayExponent());
  EXPECT_FALSE(config_.HasReceivedMinAckDelayMs());
  EXPECT_FALSE(config_.HasReceivedOriginalConnectionId());
  EXPECT_FALSE(config_.HasReceivedInitialSourceConnectionId());
  EXPECT_FALSE(config_.HasReceivedRetrySourceConnectionId());

  // Let the config process another slightly tweaked transport paramters.
  // Note that the values for flow control and stream limit cannot be smaller
  // than before. This rule is enforced in QuicSession::OnConfigNegotiated().
  params.initial_max_stream_data_bidi_local.set_value(
      2 * kMinimumFlowControlSendWindow + 1);
  params.initial_max_stream_data_bidi_remote.set_value(
      4 * kMinimumFlowControlSendWindow);
  params.initial_max_stream_data_uni.set_value(5 *
                                               kMinimumFlowControlSendWindow);
  params.max_udp_payload_size.set_value(2 * kMaxPacketSizeForTest);
  params.max_datagram_frame_size.set_value(2 * kMaxDatagramFrameSizeForTest);
  params.initial_max_streams_bidi.set_value(2 *
                                            kDefaultMaxStreamsPerConnection);
  params.disable_active_migration = true;

  EXPECT_THAT(config_.ProcessTransportParameters(
                  params, /* is_resumption = */ false, &error_details),
              IsQuicNoError())
      << error_details;

  EXPECT_TRUE(config_.negotiated());

  ASSERT_TRUE(
      config_.HasReceivedInitialMaxStreamDataBytesIncomingBidirectional());
  EXPECT_EQ(2 * kMinimumFlowControlSendWindow + 1,
            config_.ReceivedInitialMaxStreamDataBytesIncomingBidirectional());

  ASSERT_TRUE(
      config_.HasReceivedInitialMaxStreamDataBytesOutgoingBidirectional());
  EXPECT_EQ(4 * kMinimumFlowControlSendWindow,
            config_.ReceivedInitialMaxStreamDataBytesOutgoingBidirectional());

  ASSERT_TRUE(config_.HasReceivedInitialMaxStreamDataBytesUnidirectional());
  EXPECT_EQ(5 * kMinimumFlowControlSendWindow,
            config_.ReceivedInitialMaxStreamDataBytesUnidirectional());

  ASSERT_TRUE(config_.HasReceivedMaxPacketSize());
  EXPECT_EQ(2 * kMaxPacketSizeForTest, config_.ReceivedMaxPacketSize());

  ASSERT_TRUE(config_.HasReceivedMaxDatagramFrameSize());
  EXPECT_EQ(2 * kMaxDatagramFrameSizeForTest,
            config_.ReceivedMaxDatagramFrameSize());

  ASSERT_TRUE(config_.HasReceivedMaxBidirectionalStreams());
  EXPECT_EQ(2 * kDefaultMaxStreamsPerConnection,
            config_.ReceivedMaxBidirectionalStreams());

  EXPECT_TRUE(config_.DisableConnectionMigration());

  ASSERT_TRUE(config_.HasReceivedStatelessResetToken());

  ASSERT_TRUE(config_.HasReceivedMaxAckDelayMs());
  EXPECT_EQ(config_.ReceivedMaxAckDelayMs(), kMaxAckDelayForTest);

  ASSERT_TRUE(config_.HasReceivedMinAckDelayMs());
  EXPECT_EQ(config_.ReceivedMinAckDelayMs(),
            kMinAckDelayUsForTest / kNumMicrosPerMilli);

  ASSERT_TRUE(config_.HasReceivedAckDelayExponent());
```