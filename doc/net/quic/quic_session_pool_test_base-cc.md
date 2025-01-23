Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core request is to analyze the C++ source file `net/quic/quic_session_pool_test_base.cc`. This means understanding its purpose, how it's used, and any potential connections to other technologies (like JavaScript in this case).

2. **Identify Key Components:**  The first step is to scan the file for prominent structures and keywords. Looking at the `#include` directives gives a good overview of the dependencies:
    * **Core C++:** Standard library headers (`memory`, `ostream`, `string`, etc.).
    * **Base Library:**  `base/` headers (like `functional/bind.h`, `run_loop.h`, `test/`). This strongly suggests the code is part of a larger Chromium project.
    * **Net Library:** `net/` headers (like `base/features.h`, `base/host_port_pair.h`, `quic/`, `http/`, `socket/`). This confirms it's related to networking within Chromium, specifically the QUIC protocol.
    * **Quiche:** `third_party/quiche/` headers. Quiche is Google's open-source QUIC implementation, confirming the file interacts with the QUIC protocol.
    * **Testing Frameworks:** `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`. This immediately tells us this is a *test* file.

3. **Focus on the Class Name:**  The primary class defined is `QuicSessionPoolTestBase`. The "TestBase" suffix is a strong indicator that this class provides common infrastructure and helper functions for other test classes.

4. **Analyze the Class Members (Public and Private):**  Examine the members declared within `QuicSessionPoolTestBase`. This helps understand the data the class manages and the tools it provides:
    * **Networking Components:**  `MockHostResolver`, `MockClientSocketFactory`, `HttpServerProperties`, `MockCertVerifier`, `TransportSecurityState`, `QuicContext`. These are all fundamental components of a network stack, especially for handling connection establishment and security.
    * **QUIC Specific Components:** `QuicSessionPool`, `MockCryptoClientStreamFactory`, `QuicTestPacketMaker`. These clearly indicate interaction with QUIC.
    * **Testing Utilities:** `MockClock`, `MockRandom`, `ScopedFeatureList`, `TestTaskRunner`, `MockQuicData`. These are common testing utilities for controlling time, randomness, and simulating network behavior.
    * **Request Building:** The nested `RequestBuilder` class is for constructing and sending QUIC requests in tests.
    * **Helper Functions:**  Methods like `CreateStream`, `HasActiveSession`, `GetActiveSession`, `Construct...Packet`. These provide convenient ways to interact with the `QuicSessionPool` and create test scenarios.

5. **Determine the Core Functionality:** Based on the class members and methods, the core functionality is clear: **to provide a base class for testing the `QuicSessionPool`**. This involves:
    * Setting up common test infrastructure (mock resolvers, socket factories, etc.).
    * Creating and managing `QuicSessionPool` instances.
    * Providing helper functions to create requests, check session states, and construct QUIC packets.

6. **Address Specific Questions:** Now, systematically address each part of the prompt:

    * **Functionality Listing:** Summarize the findings from the previous steps into a list of key functionalities.

    * **Relationship to JavaScript:** This requires understanding how the Chromium network stack interacts with the browser's rendering engine and JavaScript. The key is recognizing that JavaScript in a browser triggers network requests. These requests, when using HTTPS, can potentially use QUIC. The `QuicSessionPool` is responsible for managing these QUIC connections. Provide concrete examples of how a JavaScript `fetch()` or `XMLHttpRequest` could lead to the `QuicSessionPool` being used. Emphasize that the *test file itself* doesn't directly execute JavaScript but *tests the component that supports JavaScript network requests*.

    * **Logical Reasoning (Input/Output):** Select a representative function, like `HasActiveSession`. Define a clear input (a `SchemeHostPort`, `PrivacyMode`, etc.) and the expected output (true/false) based on whether a matching active session exists. Make a clear *assumption* about the state of the `QuicSessionPool` for the reasoning to work.

    * **Common Usage Errors:**  Think about how developers using the `QuicSessionPool` *incorrectly* might lead to issues. Examples include incorrect configuration, not handling errors properly, or misuse of the pooling mechanism. Connect these potential errors to what the test base is designed to verify (e.g., testing correct session reuse).

    * **User Operations as Debugging Clues:** Trace a user action (e.g., clicking a link) through the browser's network stack. Explain how the request gets to the point where the `QuicSessionPool` is consulted. This involves mentioning the URL, DNS resolution, connection establishment, and the potential use of QUIC. This helps illustrate how the code under test fits into the larger user experience.

7. **Refine and Organize:**  Review the generated explanations for clarity, accuracy, and completeness. Organize the information logically under the headings provided in the prompt. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. For example, initially, I might have just listed "manages QUIC sessions."  Refinement would lead to a more descriptive statement like "Manages a pool of active and idle QUIC sessions to optimize connection reuse and reduce latency for subsequent requests to the same server."

This systematic approach, moving from high-level understanding to detailed analysis and then addressing the specific prompt questions, allows for a comprehensive and accurate explanation of the C++ test file.
这个C++源代码文件 `net/quic/quic_session_pool_test_base.cc` 是 Chromium 网络栈中 QUIC 协议相关的一个基础测试类。它的主要功能是**为 QUIC 会话池 (QuicSessionPool) 的单元测试提供一个共享的、可配置的环境和辅助方法。**  它本身并不直接参与实际的网络请求或数据传输，而是作为测试框架的一部分，简化了编写针对 `QuicSessionPool` 各个方面的测试用例。

以下是该文件提供的核心功能：

**1. 提供测试基础架构:**

*   **SetUp和TearDown:**  虽然文件中没有显式的 `SetUp` 和 `TearDown` 方法，但 `QuicSessionPoolTestBase` 的构造函数和析构函数起到了类似的作用。构造函数初始化了测试所需的各种模拟对象，如主机解析器 (`MockHostResolver`)、套接字工厂 (`MockClientSocketFactory`)、HTTP 服务器属性 (`HttpServerProperties`)、证书验证器 (`MockCertVerifier`) 等。析构函数负责清理资源。
*   **共享的模拟对象:**  该类包含了用于模拟网络环境的各种 mock 对象，例如：
    *   `MockHostResolver`: 用于模拟 DNS 解析。
    *   `MockClientSocketFactory`: 用于模拟创建客户端套接字。
    *   `MockCertVerifier`: 用于模拟证书验证过程。
    *   `MockCryptoClientStreamFactory`: 用于模拟 QUIC 加密客户端流的创建。
    *   `MockQuicContext`: 提供 QUIC 上下文信息，例如时钟和随机数生成器。
    *   `MockQuicData`:  用于模拟网络数据的发送和接收。
*   **配置选项:**  允许测试用例配置 QUIC 版本 (`version_`)，启用/禁用特定的 QUIC 功能（通过 `scoped_feature_list_`）。
*   **辅助的构建器 (`RequestBuilder`):**  提供了一个方便的类来构建 `QuicSessionRequest` 对象，用于请求 QUIC 会话。

**2. 提供用于测试的辅助方法:**

*   **会话管理检查:**
    *   `HasActiveSession()`: 检查是否存在指定目标地址的活动 QUIC 会话。
    *   `HasActiveJob()`: 检查是否存在正在建立到指定目标地址的 QUIC 会话的 job。
    *   `GetPendingSession()`: 获取正在等待激活的 QUIC 会话。
    *   `GetActiveSession()`: 获取指定目标地址的活动 QUIC 会话。
*   **会话创建和释放:**
    *   `CreateStream()`: 从 `QuicSessionRequest` 创建一个 `HttpStream` 对象。
*   **数据包构造:**  提供了大量辅助方法用于构造各种 QUIC 数据包，方便测试用例模拟不同的网络场景，例如：
    *   `ConstructServerConnectionClosePacket()`: 构造服务器关闭连接的数据包。
    *   `ConstructClientRstPacket()`: 构造客户端 RST 流的数据包。
    *   `ConstructGetRequestPacket()`: 构造 GET 请求数据包。
    *   `ConstructOkResponsePacket()`: 构造成功的响应数据包。
    *   `ConstructInitialSettingsPacket()`: 构造初始设置数据包。
    *   `ConstructAckPacket()`: 构造 ACK 确认数据包。
    *   `ConstructServerDataPacket()`: 构造服务器发送数据的数据包。
    *   `ConstructClientH3DatagramPacket()` / `ConstructServerH3Datagram()`: 构造 HTTP/3 Datagram 数据包。
*   **其他实用方法:**
    *   `DefaultProofVerifyDetails()`:  返回默认的证书验证细节。
    *   `NotifyIPAddressChanged()`: 模拟 IP 地址变更的通知。
    *   `GetSourcePortForNewSessionAndGoAway()`: 用于测试在收到 GOAWAY 帧后新会话的端口分配。
    *   获取特定类型的流 ID (`GetNthClientInitiatedBidirectionalStreamId`, `GetQpackDecoderStreamId`, `GetNthServerInitiatedUnidirectionalStreamId`).
    *   构造 QPACK 解码器取消指令 (`StreamCancellationQpackDecoderInstruction`).

**3. 与 Javascript 的关系:**

该文件本身 **不直接** 与 Javascript 代码交互。然而，它测试的网络栈组件 `QuicSessionPool` 在 Chromium 浏览器中扮演着重要的角色，支持浏览器发起的网络请求，包括那些由 Javascript 发起的请求。

**举例说明:**

假设一个网页中的 Javascript 代码使用 `fetch()` API 发起一个 HTTPS 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

1. 当这段 Javascript 代码执行时，浏览器内核的网络栈会处理这个请求。
2. 如果浏览器和 `example.com` 之间支持 QUIC 协议，并且 `QuicSessionPool` 中没有可复用的现有会话，网络栈会尝试创建一个新的 QUIC 会话。
3. `QuicSessionPool` 负责管理这些 QUIC 会话的生命周期，包括创建、复用、关闭等。
4. `net/quic/quic_session_pool_test_base.cc` 中定义的测试用例会模拟各种场景，例如：
    *   测试 `QuicSessionPool` 是否正确地为新的请求创建 QUIC 会话。
    *   测试 `QuicSessionPool` 是否能在合适的时机复用已有的 QUIC 会话，避免重复握手。
    *   测试 `QuicSessionPool` 在网络条件变化（例如 IP 地址变更）时的行为。
    *   测试 `QuicSessionPool` 如何处理服务器发送的 GOAWAY 帧。

**总结： Javascript 通过浏览器提供的 API 发起网络请求，而 `QuicSessionPool` 是 Chromium 网络栈中处理 QUIC 协议会话的关键组件。  `quic_session_pool_test_base.cc`  的目的就是确保 `QuicSessionPool` 的功能正确无误，从而间接地保障了 Javascript 发起的基于 QUIC 的网络请求能够正常工作。**

**4. 逻辑推理 (假设输入与输出):**

**假设输入：**

*   调用 `HasActiveSession(url::SchemeHostPort("example.com", 443), PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(), ProxyChain::Direct(), SESSION_USAGE_NORMAL, false)`。
*   此时，`QuicSessionPool` 中 **存在一个** 连接到 `example.com:443` 的 **活动** QUIC 会话，并且该会话的 `PrivacyMode` 是 `PRIVACY_MODE_DISABLED`，`NetworkAnonymizationKey` 为空，使用直连代理，`SessionUsage` 是 `SESSION_USAGE_NORMAL`，且 `require_dns_https_alpn` 为 `false`。

**输出：**

*   `HasActiveSession` 函数将返回 `true`。

**逻辑推理：** `HasActiveSession` 函数会遍历 `QuicSessionPool` 中维护的活动会话列表，检查是否存在与输入参数完全匹配的会话（主机、端口、隐私模式等）。由于假设存在一个匹配的活动会话，所以函数返回 `true`。

**假设输入：**

*   调用 `GetActiveSession(url::SchemeHostPort("notexist.com", 443), PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(), ProxyChain::Direct(), SESSION_USAGE_NORMAL, false)`。
*   此时，`QuicSessionPool` 中 **不存在** 连接到 `notexist.com:443` 的活动 QUIC 会话。

**输出：**

*   `GetActiveSession` 函数将返回 `nullptr`。

**逻辑推理：** `GetActiveSession` 函数与 `HasActiveSession` 类似，会查找匹配的活动会话。由于假设不存在匹配的会话，所以函数返回空指针。

**5. 涉及用户或者编程常见的使用错误 (举例说明):**

*   **错误配置代理:** 用户可能配置了错误的 HTTP 代理服务器，导致 QUIC 连接尝试通过不支持 QUIC 的代理，或者代理的配置与预期不符。这会导致 `QuicSessionPool` 无法建立连接或建立错误的连接。测试用例可能会模拟这种情况，验证 `QuicSessionPool` 是否能正确处理代理相关的错误。
*   **证书问题:**  服务器的 SSL/TLS 证书可能存在问题（过期、域名不匹配等），导致 QUIC 握手失败。`QuicSessionPool` 需要能够检测并处理这些证书错误。测试用例会使用 `MockCertVerifier` 模拟各种证书验证场景，确保 `QuicSessionPool` 的行为符合预期。
*   **网络中断或不稳定:**  用户网络环境不稳定可能导致 QUIC 连接中断。开发者在使用 `QuicSessionPool` 的代码中需要正确处理连接中断的情况，例如重试请求或通知用户。测试用例会模拟网络中断，验证 `QuicSessionPool` 的恢复能力和错误处理机制。
*   **QUIC 功能的错误假设:** 开发者可能错误地假设某些 QUIC 功能始终可用或以某种方式工作。测试用例可以验证在特定功能被禁用或以非预期方式工作时，`QuicSessionPool` 的行为是否正确。
*   **资源泄漏:** 如果 `QuicSessionPool` 没有正确管理会话的生命周期，可能会导致资源泄漏，例如打开的套接字没有被及时关闭。测试用例会检查会话的创建和销毁，确保没有资源泄漏。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在 Chromium 浏览器中访问 `https://www.example.com`：

1. **用户在地址栏输入 URL 或点击链接。**
2. **浏览器解析 URL，确定协议为 HTTPS。**
3. **浏览器查找与 `www.example.com` 相关的缓存信息，包括是否已经存在活动的 QUIC 会话。**  `QuicSessionPool` 会被查询。
4. **如果 `QuicSessionPool` 中存在可复用的活动会话 (与目标主机、端口、代理等匹配)，则直接复用该会话，进行数据传输。**  此时，`QuicSessionPool::GetActiveSession()` 等方法会被调用。
5. **如果 `QuicSessionPool` 中没有可复用的活动会话，浏览器会尝试建立新的 QUIC 连接。**
    *   **DNS 解析:**  浏览器首先进行 DNS 查询，将 `www.example.com` 解析为 IP 地址。 `MockHostResolver` 在测试环境中模拟了这个过程。
    *   **连接尝试:** 浏览器使用解析到的 IP 地址和端口，通过 `MockClientSocketFactory` 创建一个 UDP 套接字，并尝试与服务器建立 QUIC 连接。
    *   **QUIC 握手:**  客户端和服务器之间进行 QUIC 握手，协商加密参数等。`MockCryptoClientStreamFactory` 模拟了客户端的加密流创建过程。
    *   **会话创建:**  如果握手成功，`QuicSessionPool` 中会创建一个新的 QUIC 会话。
6. **进行 HTTP 请求:**  一旦 QUIC 会话建立，浏览器会通过该会话发送 HTTP 请求。
7. **接收和处理响应:**  服务器通过 QUIC 会话发送 HTTP 响应，浏览器接收并处理。

**作为调试线索:**

当开发者调试与 QUIC 连接相关的问题时，例如连接建立失败、连接被意外关闭、性能问题等，`net/quic/quic_session_pool_test_base.cc` 中测试用例可以作为重要的参考：

*   **复现问题场景:** 开发者可以参考或修改现有的测试用例，来复现用户遇到的问题场景，例如模拟特定的网络条件、服务器行为、代理配置等。
*   **验证修复方案:** 在修复了代码中的缺陷后，可以编写新的测试用例或修改现有用例，验证修复方案是否有效，以及是否引入了新的问题。
*   **理解 QUIC 连接流程:**  阅读测试用例可以帮助开发者更深入地理解 QUIC 连接的建立、会话管理、错误处理等流程，从而更好地定位问题。
*   **检查特定功能的行为:**  如果怀疑某个特定的 QUIC 功能（例如连接迁移、0-RTT 连接）存在问题，可以查找或编写针对该功能的测试用例，来验证其行为是否符合预期。

总而言之，`net/quic/quic_session_pool_test_base.cc` 是理解和调试 Chromium QUIC 连接机制的关键入口点之一，它通过提供一个可控的测试环境，帮助开发者验证 `QuicSessionPool` 的正确性和健壮性。

### 提示词
```
这是目录为net/quic/quic_session_pool_test_base.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_session_pool_test_base.h"

#include <sys/types.h>

#include <memory>
#include <ostream>
#include <set>
#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/time/time.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/http_user_agent_settings.h"
#include "net/base/load_flags.h"
#include "net/base/mock_network_change_notifier.h"
#include "net/base/net_error_details.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/schemeful_site.h"
#include "net/base/session_usage.h"
#include "net/base/test_proxy_delegate.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/host_resolver_source.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_util.h"
#include "net/http/transport_security_state.h"
#include "net/http/transport_security_state_test_util.h"
#include "net/quic/address_utils.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/mock_quic_context.h"
#include "net/quic/mock_quic_data.h"
#include "net/quic/properties_based_quic_server_info.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_chromium_client_session_peer.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_http_stream.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_server_info.h"
#include "net/quic/quic_session_key.h"
#include "net/quic/quic_session_pool_peer.h"
#include "net/quic/quic_test_packet_maker.h"
#include "net/quic/quic_test_packet_printer.h"
#include "net/quic/test_task_runner.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_session_test_util.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/test_ssl_config_service.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/common/quiche_data_writer.h"
#include "net/third_party/quiche/src/quiche/http2/test_tools/spdy_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/crypto_handshake.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_decrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_encrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_constants.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_clock.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_random.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_config_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_connection_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_path_validator_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_session_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

using std::string;

namespace net::test {

QuicSessionPoolTestBase::RequestBuilder::RequestBuilder(
    QuicSessionPoolTestBase* test,
    QuicSessionPool* pool)
    : quic_version(test->version_),
      net_log(test->net_log_),
      failed_on_default_network_callback(
          test->failed_on_default_network_callback_),
      callback(test->callback_.callback()),
      request(pool) {}
QuicSessionPoolTestBase::RequestBuilder::RequestBuilder(
    QuicSessionPoolTestBase* test)
    : RequestBuilder(test, test->factory_.get()) {}
QuicSessionPoolTestBase::RequestBuilder::~RequestBuilder() = default;

int QuicSessionPoolTestBase::RequestBuilder::CallRequest() {
  return request.Request(
      std::move(destination), quic_version, proxy_chain,
      std::move(proxy_annotation_tag), http_user_agent_settings, session_usage,
      privacy_mode, priority, socket_tag, network_anonymization_key,
      secure_dns_policy, require_dns_https_alpn, cert_verify_flags, url,
      net_log, &net_error_details,
      MultiplexedSessionCreationInitiator::kUnknown,
      std::move(failed_on_default_network_callback), std::move(callback));
}
QuicSessionPoolTestBase::QuicSessionPoolTestBase(
    quic::ParsedQuicVersion version,
    std::vector<base::test::FeatureRef> enabled_features,
    std::vector<base::test::FeatureRef> disabled_features)
    : host_resolver_(std::make_unique<MockHostResolver>(
          /*default_result=*/MockHostResolverBase::RuleResolver::
              GetLocalhostResult())),
      socket_factory_(std::make_unique<MockClientSocketFactory>()),
      version_(version),
      client_maker_(version_,
                    quic::QuicUtils::CreateRandomConnectionId(
                        context_.random_generator()),
                    context_.clock(),
                    kDefaultServerHostName,
                    quic::Perspective::IS_CLIENT,
                    /*client_priority_uses_incremental=*/true,
                    /*use_priority_header=*/true),
      server_maker_(version_,
                    quic::QuicUtils::CreateRandomConnectionId(
                        context_.random_generator()),
                    context_.clock(),
                    kDefaultServerHostName,
                    quic::Perspective::IS_SERVER,
                    /*client_priority_uses_incremental=*/false,
                    /*use_priority_header=*/false),
      http_server_properties_(std::make_unique<HttpServerProperties>()),
      cert_verifier_(std::make_unique<MockCertVerifier>()),
      net_log_(NetLogWithSource::Make(NetLog::Get(),
                                      NetLogSourceType::QUIC_SESSION_POOL)),
      failed_on_default_network_callback_(base::BindRepeating(
          &QuicSessionPoolTestBase::OnFailedOnDefaultNetwork,
          base::Unretained(this))),
      quic_params_(context_.params()) {
  enabled_features.push_back(features::kAsyncQuicSession);
  scoped_feature_list_.InitWithFeatures(enabled_features, disabled_features);
  FLAGS_quic_enable_http3_grease_randomness = false;
  context_.AdvanceTime(quic::QuicTime::Delta::FromSeconds(1));

  // It's important that different proxies have different IPs, to avoid
  // pooling them together.
  host_resolver_->rules()->AddRule(kProxy1HostName, "127.0.1.1");
  host_resolver_->rules()->AddRule(kProxy2HostName, "127.0.1.2");
}

QuicSessionPoolTestBase::~QuicSessionPoolTestBase() = default;
void QuicSessionPoolTestBase::Initialize() {
  DCHECK(!factory_);
  factory_ = std::make_unique<QuicSessionPool>(
      net_log_.net_log(), host_resolver_.get(), &ssl_config_service_,
      socket_factory_.get(), http_server_properties_.get(),
      cert_verifier_.get(), &transport_security_state_, proxy_delegate_.get(),
      /*sct_auditing_delegate=*/nullptr,
      /*SocketPerformanceWatcherFactory*/ nullptr,
      &crypto_client_stream_factory_, &context_);
}

void QuicSessionPoolTestBase::MaybeMakeNewConnectionIdAvailableToSession(
    const quic::QuicConnectionId& new_cid,
    quic::QuicSession* session,
    uint64_t sequence_number) {
  quic::QuicNewConnectionIdFrame new_cid_frame;
  new_cid_frame.connection_id = new_cid;
  new_cid_frame.sequence_number = sequence_number;
  new_cid_frame.retire_prior_to = 0u;
  new_cid_frame.stateless_reset_token =
      quic::QuicUtils::GenerateStatelessResetToken(new_cid_frame.connection_id);
  session->connection()->OnNewConnectionIdFrame(new_cid_frame);
}

std::unique_ptr<HttpStream> QuicSessionPoolTestBase::CreateStream(
    QuicSessionRequest* request) {
  std::unique_ptr<QuicChromiumClientSession::Handle> session =
      request->ReleaseSessionHandle();
  if (!session || !session->IsConnected()) {
    return nullptr;
  }

  std::set<std::string> dns_aliases =
      session->GetDnsAliasesForSessionKey(request->session_key());
  return std::make_unique<QuicHttpStream>(std::move(session),
                                          std::move(dns_aliases));
}

bool QuicSessionPoolTestBase::HasActiveSession(
    const url::SchemeHostPort& scheme_host_port,
    PrivacyMode privacy_mode,
    const NetworkAnonymizationKey& network_anonymization_key,
    const ProxyChain& proxy_chain,
    SessionUsage session_usage,
    bool require_dns_https_alpn) {
  quic::QuicServerId server_id(scheme_host_port.host(),
                               scheme_host_port.port());
  return QuicSessionPoolPeer::HasActiveSession(
      factory_.get(), server_id, privacy_mode, network_anonymization_key,
      proxy_chain, session_usage, require_dns_https_alpn);
}

bool QuicSessionPoolTestBase::HasActiveJob(
    const url::SchemeHostPort& scheme_host_port,
    const PrivacyMode privacy_mode,
    bool require_dns_https_alpn) {
  quic::QuicServerId server_id(scheme_host_port.host(),
                               scheme_host_port.port());
  return QuicSessionPoolPeer::HasActiveJob(
      factory_.get(), server_id, privacy_mode, require_dns_https_alpn);
}

// Get the pending, not activated session, if there is only one session alive.
QuicChromiumClientSession* QuicSessionPoolTestBase::GetPendingSession(
    const url::SchemeHostPort& scheme_host_port) {
  quic::QuicServerId server_id(scheme_host_port.host(),
                               scheme_host_port.port());
  return QuicSessionPoolPeer::GetPendingSession(
      factory_.get(), server_id, PRIVACY_MODE_DISABLED, scheme_host_port);
}

QuicChromiumClientSession* QuicSessionPoolTestBase::GetActiveSession(
    const url::SchemeHostPort& scheme_host_port,
    PrivacyMode privacy_mode,
    const NetworkAnonymizationKey& network_anonymization_key,
    const ProxyChain& proxy_chain,
    SessionUsage session_usage,
    bool require_dns_https_alpn) {
  quic::QuicServerId server_id(scheme_host_port.host(),
                               scheme_host_port.port());
  return QuicSessionPoolPeer::GetActiveSession(
      factory_.get(), server_id, privacy_mode, network_anonymization_key,
      proxy_chain, session_usage, require_dns_https_alpn);
}

int QuicSessionPoolTestBase::GetSourcePortForNewSessionAndGoAway(
    const url::SchemeHostPort& destination) {
  return GetSourcePortForNewSessionInner(destination, true);
}

int QuicSessionPoolTestBase::GetSourcePortForNewSessionInner(
    const url::SchemeHostPort& destination,
    bool goaway_received) {
  // Should only be called if there is no active session for this destination.
  EXPECT_FALSE(HasActiveSession(destination));
  size_t socket_count = socket_factory_->udp_client_socket_ports().size();

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  GURL url("https://" + destination.host() + "/");
  RequestBuilder builder(this);
  builder.destination = destination;
  builder.url = url;

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());
  stream.reset();

  QuicChromiumClientSession* session = GetActiveSession(destination);

  if (socket_count + 1 != socket_factory_->udp_client_socket_ports().size()) {
    ADD_FAILURE();
    return 0;
  }

  if (goaway_received) {
    quic::QuicGoAwayFrame goaway(quic::kInvalidControlFrameId,
                                 quic::QUIC_NO_ERROR, 1, "");
    session->connection()->OnGoAwayFrame(goaway);
  }

  factory_->OnSessionClosed(session);
  EXPECT_FALSE(HasActiveSession(destination));
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  return socket_factory_->udp_client_socket_ports()[socket_count];
}

ProofVerifyDetailsChromium
QuicSessionPoolTestBase::DefaultProofVerifyDetails() {
  // Load a certificate that is valid for *.example.org
  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  EXPECT_TRUE(test_cert.get());
  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = test_cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  return verify_details;
}

void QuicSessionPoolTestBase::NotifyIPAddressChanged() {
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  // Spin the message loop so the notification is delivered.
  base::RunLoop().RunUntilIdle();
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructServerConnectionClosePacket(uint64_t num) {
  return server_maker_.Packet(num)
      .AddConnectionCloseFrame(quic::QUIC_CRYPTO_VERSION_NOT_SUPPORTED,
                               "Time to panic!")
      .Build();
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructClientRstPacket(
    uint64_t packet_number,
    quic::QuicRstStreamErrorCode error_code) {
  quic::QuicStreamId stream_id = GetNthClientInitiatedBidirectionalStreamId(0);
  return client_maker_.Packet(packet_number)
      .AddStopSendingFrame(stream_id, error_code)
      .AddRstStreamFrame(stream_id, error_code)
      .Build();
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructGetRequestPacket(uint64_t packet_number,
                                                   quic::QuicStreamId stream_id,
                                                   bool fin) {
  quiche::HttpHeaderBlock headers =
      client_maker_.GetRequestHeaders("GET", "https", "/");
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
  size_t spdy_headers_frame_len;
  return client_maker_.MakeRequestHeadersPacket(packet_number, stream_id, fin,
                                                priority, std::move(headers),
                                                &spdy_headers_frame_len);
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructConnectUdpRequestPacket(
    uint64_t packet_number,
    quic::QuicStreamId stream_id,
    std::string authority,
    std::string path,
    bool fin) {
  return ConstructConnectUdpRequestPacket(client_maker_, packet_number,
                                          stream_id, authority, path, fin);
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructConnectUdpRequestPacket(
    QuicTestPacketMaker& packet_maker,
    uint64_t packet_number,
    quic::QuicStreamId stream_id,
    std::string authority,
    std::string path,
    bool fin) {
  quiche::HttpHeaderBlock headers;
  headers[":scheme"] = "https";
  headers[":path"] = path;
  headers[":protocol"] = "connect-udp";
  headers[":method"] = "CONNECT";
  headers[":authority"] = authority;
  headers["user-agent"] = "test-ua";
  headers["capsule-protocol"] = "?1";
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
  size_t spdy_headers_frame_len;
  auto rv = packet_maker.MakeRequestHeadersPacket(
      packet_number, stream_id, fin, priority, std::move(headers),
      &spdy_headers_frame_len, /*should_include_priority_frame=*/false);
  return rv;
}

std::string QuicSessionPoolTestBase::ConstructClientH3DatagramFrame(
    uint64_t quarter_stream_id,
    uint64_t context_id,
    std::unique_ptr<quic::QuicEncryptedPacket> inner) {
  std::string data;
  // Allow enough space for payload and two varint-62's.
  data.resize(inner->length() + 2 * 8);
  quiche::QuicheDataWriter writer(data.capacity(), data.data());
  CHECK(writer.WriteVarInt62(quarter_stream_id));
  CHECK(writer.WriteVarInt62(context_id));
  CHECK(writer.WriteBytes(inner->data(), inner->length()));
  data.resize(writer.length());
  return data;
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructClientH3DatagramPacket(
    uint64_t packet_number,
    uint64_t quarter_stream_id,
    uint64_t context_id,
    std::unique_ptr<quic::QuicEncryptedPacket> inner) {
  std::string data = ConstructClientH3DatagramFrame(
      quarter_stream_id, context_id, std::move(inner));
  return client_maker_.Packet(packet_number).AddMessageFrame(data).Build();
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructOkResponsePacket(uint64_t packet_number,
                                                   quic::QuicStreamId stream_id,
                                                   bool fin) {
  return ConstructOkResponsePacket(server_maker_, packet_number, stream_id,
                                   fin);
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructOkResponsePacket(
    QuicTestPacketMaker& packet_maker,
    uint64_t packet_number,
    quic::QuicStreamId stream_id,
    bool fin) {
  quiche::HttpHeaderBlock headers = packet_maker.GetResponseHeaders("200");
  size_t spdy_headers_frame_len;
  return packet_maker.MakeResponseHeadersPacket(packet_number, stream_id, fin,
                                                std::move(headers),
                                                &spdy_headers_frame_len);
}

std::unique_ptr<quic::QuicReceivedPacket>
QuicSessionPoolTestBase::ConstructInitialSettingsPacket() {
  return client_maker_.MakeInitialSettingsPacket(1);
}

std::unique_ptr<quic::QuicReceivedPacket>
QuicSessionPoolTestBase::ConstructInitialSettingsPacket(
    uint64_t packet_number) {
  return client_maker_.MakeInitialSettingsPacket(packet_number);
}

std::unique_ptr<quic::QuicReceivedPacket>
QuicSessionPoolTestBase::ConstructInitialSettingsPacket(
    QuicTestPacketMaker& packet_maker,
    uint64_t packet_number) {
  return packet_maker.MakeInitialSettingsPacket(packet_number);
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructServerSettingsPacket(uint64_t packet_number) {
  return server_maker_.MakeInitialSettingsPacket(packet_number);
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructAckPacket(
    test::QuicTestPacketMaker& packet_maker,
    uint64_t packet_number,
    uint64_t packet_num_received,
    uint64_t smallest_received,
    uint64_t largest_received) {
  return packet_maker.Packet(packet_number)
      .AddAckFrame(packet_num_received, smallest_received, largest_received)
      .Build();
}

std::string QuicSessionPoolTestBase::ConstructDataHeader(size_t body_len) {
  quiche::QuicheBuffer buffer = quic::HttpEncoder::SerializeDataFrameHeader(
      body_len, quiche::SimpleBufferAllocator::Get());
  return std::string(buffer.data(), buffer.size());
}

std::unique_ptr<quic::QuicEncryptedPacket>
QuicSessionPoolTestBase::ConstructServerDataPacket(uint64_t packet_number,
                                                   quic::QuicStreamId stream_id,
                                                   bool fin,
                                                   std::string_view data) {
  return server_maker_.Packet(packet_number)
      .AddStreamFrame(stream_id, fin, data)
      .Build();
}

std::string QuicSessionPoolTestBase::ConstructH3Datagram(
    uint64_t stream_id,
    uint64_t context_id,
    std::unique_ptr<quic::QuicEncryptedPacket> packet) {
  std::string data;
  // Allow enough space for payload and two varint-62's.
  data.resize(packet->length() + 2 * 8);
  quiche::QuicheDataWriter writer(data.capacity(), data.data());
  CHECK(writer.WriteVarInt62(stream_id >> 2));
  CHECK(writer.WriteVarInt62(context_id));
  CHECK(writer.WriteBytes(packet->data(), packet->length()));
  data.resize(writer.length());
  return data;
}

quic::QuicStreamId
QuicSessionPoolTestBase::GetNthClientInitiatedBidirectionalStreamId(
    int n) const {
  return quic::test::GetNthClientInitiatedBidirectionalStreamId(
      version_.transport_version, n);
}

quic::QuicStreamId QuicSessionPoolTestBase::GetQpackDecoderStreamId() const {
  return quic::test::GetNthClientInitiatedUnidirectionalStreamId(
      version_.transport_version, 1);
}

std::string QuicSessionPoolTestBase::StreamCancellationQpackDecoderInstruction(
    int n) const {
  return StreamCancellationQpackDecoderInstruction(n, true);
}

std::string QuicSessionPoolTestBase::StreamCancellationQpackDecoderInstruction(
    int n,
    bool create_stream) const {
  const quic::QuicStreamId cancelled_stream_id =
      GetNthClientInitiatedBidirectionalStreamId(n);
  EXPECT_LT(cancelled_stream_id, 63u);

  const char opcode = 0x40;
  if (create_stream) {
    return {0x03, static_cast<char>(opcode | cancelled_stream_id)};
  } else {
    return {static_cast<char>(opcode | cancelled_stream_id)};
  }
}

quic::QuicStreamId
QuicSessionPoolTestBase::GetNthServerInitiatedUnidirectionalStreamId(int n) {
  return quic::test::GetNthServerInitiatedUnidirectionalStreamId(
      version_.transport_version, n);
}

void QuicSessionPoolTestBase::OnFailedOnDefaultNetwork(int rv) {
  failed_on_default_network_ = true;
}

}  // namespace net::test
```