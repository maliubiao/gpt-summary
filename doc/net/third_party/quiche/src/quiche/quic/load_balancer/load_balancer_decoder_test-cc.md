Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `load_balancer_decoder_test.cc` immediately suggests this is a test file for something called `LoadBalancerDecoder`. The presence of `#include "quiche/quic/load_balancer/load_balancer_decoder.h"` confirms this. Therefore, the primary goal is to understand how the `LoadBalancerDecoder` is being tested.

2. **Scan for Key Classes and Functions:** Look for class definitions and important function calls within the tests. We see `LoadBalancerDecoder`, `LoadBalancerConfig`, `LoadBalancerServerId`, and `QuicConnectionId`. The test methods themselves (e.g., `UnencryptedConnectionIdTestVectors`, `DecoderTestVectors`) provide hints about the functionalities being tested. The `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_EQ` macros signal assertions within the tests. `AddConfig` and `GetServerId` appear to be central methods of `LoadBalancerDecoder`.

3. **Understand the Test Structure:** Notice the `LoadBalancerDecoderTest` class inheriting from `QuicTest`. This is a common pattern for structuring tests. Each `TEST_F` macro defines an individual test case. The tests generally follow a pattern:
    * Set up test data (often using structs like `LoadBalancerDecoderTestCase`).
    * Create a `LoadBalancerDecoder` object.
    * Add configurations using `AddConfig`.
    * Call the method under test (`GetServerId`).
    * Assert the results using `EXPECT_*`.

4. **Analyze Individual Test Cases:**  Go through each `TEST_F` and decipher its intent:
    * `UnencryptedConnectionIdTestVectors`: Tests decoding with unencrypted connection IDs. The `CreateUnencrypted` method suggests this.
    * `DecoderTestVectors`: Likely tests the standard, encrypted case based on the presence of `kKey` and the comment about draft-ietf-quic-load-balancers-19.
    * `InvalidConfigId`, `UnroutableCodepoint`, `ConnectionIdTooShort`, `ConnectionIdTooLongIsOK`: These test error conditions and boundary cases related to connection ID structure and configuration.
    * `DeleteConfigBadId`, `DeleteConfigGoodId`: Test the functionality of removing configurations and how the decoder behaves afterward. The `EXPECT_QUIC_BUG` is noteworthy.
    * `TwoServerIds`: Tests the ability to decode different server IDs based on different connection IDs.
    * `GetConfigId`: Tests a static helper function for extracting the configuration ID.
    * `GetConfig`: Tests retrieving the configuration object itself.
    * `OnePassIgnoreAdditionalBytes`: Tests a specific scenario where extra bytes in the connection ID are ignored.

5. **Look for Patterns and Relationships:** Notice how `LoadBalancerConfig` is used to configure the decoder. Observe how `QuicConnectionId` acts as the input, and `LoadBalancerServerId` is the expected output of the decoding process.

6. **Consider Potential JavaScript Relevance (If Any):**  Since this is Chromium code, think about where load balancing might intersect with web browsers and JavaScript. While this specific low-level decoding logic likely isn't directly exposed to JavaScript, the *outcomes* of this process are important. The browser needs to connect to the correct server, and load balancing helps achieve that. So, the *result* of this decoding (which server to connect to) influences network requests initiated by JavaScript. It's an indirect relationship.

7. **Infer Logic and Assumptions:**  Based on the test names and assertions, infer the underlying logic of the `LoadBalancerDecoder`. It seems to:
    * Use a configuration ID embedded in the connection ID.
    * Extract a server ID from the connection ID based on the configuration.
    * Handle both encrypted and unencrypted connection IDs.
    * Have specific length requirements for server IDs and nonces.
    * Have a mechanism to delete configurations.

8. **Think About User and Programming Errors:** Consider how a developer might misuse this code or how a user's actions could lead to these code paths being executed. Incorrectly configuring the `LoadBalancerDecoder` or generating malformed connection IDs are potential errors. User actions like clicking links or entering URLs eventually trigger network requests that utilize this load balancing mechanism.

9. **Trace the User Path (Debugging Context):**  Imagine a scenario where a connection fails. How might one end up debugging this code? The flow could be:
    * User reports a connection issue.
    * Network logs might show connections being attempted with specific connection IDs.
    * Developers might suspect load balancing issues.
    * They'd look at the server's load balancer configuration.
    * They might examine the connection ID being used.
    * They'd then step through the `LoadBalancerDecoder` code to see if the server ID is being extracted correctly.

10. **Review and Refine:**  Go back through the analysis, ensuring clarity and accuracy. Organize the information logically into the requested categories (functionality, JavaScript relevance, logic, errors, user path).

This systematic approach, starting with the big picture and then diving into the details of each test case, helps in understanding the purpose and functionality of the code under examination.
这个文件 `net/third_party/quiche/src/quiche/quic/load_balancer/load_balancer_decoder_test.cc` 是 Chromium QUIC 协议栈中用于测试 `LoadBalancerDecoder` 类的单元测试文件。 `LoadBalancerDecoder` 的作用是从 QUIC 连接 ID 中解码出负载均衡的服务器 ID。

以下是该文件的功能点的详细说明：

**1. 测试 `LoadBalancerDecoder` 的核心功能：解码服务器 ID**

*   该文件包含了多个测试用例，用于验证 `LoadBalancerDecoder` 是否能正确地从 `QuicConnectionId` 中提取 `LoadBalancerServerId`。
*   测试用例覆盖了不同的负载均衡配置 (`LoadBalancerConfig`)，包括加密和非加密的连接 ID。
*   测试用例使用了预定义的连接 ID 和期望的服务器 ID，来验证解码结果的正确性。

**2. 测试不同的负载均衡配置**

*   **非加密连接 ID (`UnencryptedConnectionIdTestVectors`)**:  测试了在未加密连接 ID 的情况下，`LoadBalancerDecoder` 能否根据配置正确提取服务器 ID。配置信息直接嵌入在连接 ID 中。
*   **加密连接 ID (`DecoderTestVectors`)**: 测试了使用密钥加密的连接 ID 的解码过程。这些测试用例参考了 QUIC 负载均衡草案 (draft-ietf-quic-load-balancers-19) 的附录 B 中的测试向量。覆盖了不同长度的服务器 ID 和 nonce 的情况。

**3. 测试错误处理和边界情况**

*   **无效的配置 ID (`InvalidConfigId`)**:  测试了当连接 ID 中包含的配置 ID 与已添加的配置不匹配时，解码器是否返回错误。
*   **不可路由的码点 (`UnroutableCodepoint`, `UnroutableCodepointAnyLength`)**: QUIC 连接 ID 的首字节可能包含一些保留或特殊用途的码点。这些测试用例验证了当遇到不可路由的码点时，解码器是否正确处理（通常是返回失败）。
*   **连接 ID 过短 (`ConnectionIdTooShort`)**:  测试了当连接 ID 的长度不足以包含完整的服务器 ID 时，解码器是否返回错误。
*   **连接 ID 过长 (`ConnectionIdTooLongIsOK`)**:  测试了当连接 ID 比需要的长时，解码器是否仍然能够正确解码，忽略额外的字节。

**4. 测试配置的添加和删除**

*   **删除错误的配置 ID (`DeleteConfigBadId`)**: 测试了尝试删除不存在的配置 ID 时，解码器是否会触发断言 (QUIC_BUG)。这表明这是一个编程错误。
*   **删除正确的配置 ID (`DeleteConfigGoodId`)**: 测试了成功删除配置后，使用该配置的连接 ID 进行解码会失败。

**5. 测试同时存在多个配置**

*   **多个服务器 ID (`TwoServerIds`)**:  测试了当添加了多个负载均衡配置时，解码器能否根据连接 ID 中的配置 ID 选择正确的配置并解码出对应的服务器 ID。

**6. 测试辅助方法**

*   **获取配置 ID (`GetConfigId`)**: 测试了静态方法 `GetConfigId`，该方法从连接 ID 中提取负载均衡配置的 ID。
*   **获取配置 (`GetConfig`)**: 测试了根据配置 ID 获取 `LoadBalancerConfig` 对象的方法。

**与 JavaScript 功能的关系**

这个 C++ 文件本身与 JavaScript 没有直接的功能关系。它是 Chromium 网络栈的底层实现，负责处理 QUIC 协议的负载均衡。然而，它所完成的工作会间接地影响到 JavaScript 的网络请求行为：

*   **透明的负载均衡**:  当用户在浏览器中通过 JavaScript 发起网络请求时，底层的 QUIC 协议栈可能会使用负载均衡来选择最佳的服务器。`LoadBalancerDecoder` 确保了连接被路由到正确的后端服务器。这个过程对 JavaScript 是透明的。
*   **性能和可靠性**:  有效的负载均衡可以提高网络连接的性能和可靠性。虽然 JavaScript 代码本身不直接调用 `LoadBalancerDecoder`，但用户体验会因为底层的负载均衡而受益。

**逻辑推理、假设输入与输出**

以下是一个 `DecoderTestVectors` 中的一个测试用例的逻辑推理：

**假设输入:**

*   **`LoadBalancerConfig`**:  `config_id = 0`, `server_id_len = 3`, `nonce_len = 4`, `key = kKey` (一个 16 字节的密钥)。
*   **`QuicConnectionId`**: `{0x07, 0x20, 0xb1, 0xd0, 0x7b, 0x35, 0x9d, 0x3c}`

**逻辑推理 (基于 QUIC 负载均衡草案的理解):**

1. **提取配置 ID**: 连接 ID 的第一个字节 `0x07`，右移 `kConnectionIdLengthBits` (通常是 4 或 2，取决于实现) 位后得到配置 ID `0`。
2. **提取加密数据**:  连接 ID 的剩余部分 (减去配置 ID 的长度) 是加密后的数据。
3. **解密过程**:  根据配置的密钥、nonce 长度和服务器 ID 长度，对加密数据进行多轮解密操作。具体的解密算法和轮数在 `LoadBalancerDecoder` 的实现中。
4. **提取服务器 ID**: 解密后的数据包含 nonce 和服务器 ID。根据配置的 `server_id_len`，提取出服务器 ID。

**预期输出:**

*   **`LoadBalancerServerId`**: `{0xed, 0x79, 0x3a}` (对应 `MakeServerId(kServerId, 3)`)

**用户或编程常见的使用错误**

*   **编程错误**:
    *   **配置不匹配**:  服务端和客户端使用的负载均衡配置不一致（例如，密钥不同，服务器 ID 或 nonce 长度不同）。这会导致 `LoadBalancerDecoder` 无法正确解码连接 ID。
    *   **错误的连接 ID 格式**:  如果客户端生成的连接 ID 格式不符合负载均衡配置的要求（例如，配置 ID 部分错误），解码将会失败。
    *   **在没有配置的情况下尝试解码**:  在 `LoadBalancerDecoder` 中没有添加任何配置就尝试解码连接 ID。
    *   **删除正在使用的配置**:  删除仍然有连接在使用的负载均衡配置可能会导致后续使用该连接的解码失败。

*   **用户操作导致的间接影响**:
    *   **网络配置错误**:  用户的网络环境可能存在问题，导致连接无法建立或被错误路由，但这通常不是 `LoadBalancerDecoder` 直接负责的。
    *   **服务器端配置错误**:  服务器端的负载均衡器配置错误，例如密钥不匹配，会导致客户端无法连接。虽然 `LoadBalancerDecoder` 在客户端，但服务端配置错误会体现在客户端的连接失败上。

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户遇到连接问题，开发者需要调试 `LoadBalancerDecoder` 的行为：

1. **用户尝试访问网站**: 用户在浏览器地址栏输入网址或点击链接，浏览器发起网络请求。
2. **QUIC 连接协商**: 如果网站支持 QUIC，浏览器会尝试与服务器建立 QUIC 连接。这可能涉及到发送包含负载均衡信息的初始连接 ID。
3. **连接 ID 的生成和发送**: 客户端根据负载均衡配置生成包含服务器 ID 的连接 ID，并发送给服务器。
4. **服务器端解码**: 服务器端的负载均衡器（可能对应于 `LoadBalancerDecoder` 的服务端实现）接收到连接 ID 并尝试解码以确定目标后端服务器。
5. **请求路由**: 服务器根据解码出的服务器 ID 将请求路由到相应的后端服务实例。
6. **调试线索**: 如果连接失败，开发者可能会：
    *   **检查客户端的 QUIC 连接日志**: 查看客户端发送的连接 ID 是否符合预期。
    *   **检查服务器端的负载均衡器日志**:  查看服务器端是否成功解码了连接 ID，以及解码出的服务器 ID 是什么。
    *   **检查客户端的负载均衡配置**:  确认客户端使用的配置与服务器端是否一致。
    *   **单步调试 `LoadBalancerDecoder` 代码**: 如果怀疑是客户端解码错误，可以在客户端代码中设置断点，查看 `LoadBalancerDecoder::GetServerId` 的输入和输出，以及中间的解密过程。
    *   **分析网络抓包**:  捕获客户端和服务器之间的网络数据包，分析 QUIC 连接的握手过程和连接 ID 的传输。

通过以上步骤，开发者可以逐步缩小问题范围，最终定位到是否是 `LoadBalancerDecoder` 导致的连接问题。例如，如果客户端发送的连接 ID 格式不正确，或者服务器端无法使用配置的密钥成功解密，那么问题可能就出在 `LoadBalancerDecoder` 或相关的配置上。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/load_balancer/load_balancer_decoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/load_balancer/load_balancer_decoder.h"

#include <cstdint>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/load_balancer/load_balancer_config.h"
#include "quiche/quic/load_balancer/load_balancer_server_id.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {

namespace test {

namespace {

class LoadBalancerDecoderTest : public QuicTest {};

// Convenience function to shorten the code. Does not check if |array| is long
// enough or |length| is valid for a server ID.
inline LoadBalancerServerId MakeServerId(const uint8_t array[],
                                         const uint8_t length) {
  return LoadBalancerServerId(absl::Span<const uint8_t>(array, length));
}

constexpr char kRawKey[] = {0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
                            0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f};
constexpr absl::string_view kKey(kRawKey, kLoadBalancerKeyLen);
constexpr uint8_t kServerId[] = {0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f,
                                 0xab, 0x65, 0xba, 0x04, 0xc3, 0x33, 0x0a};

struct LoadBalancerDecoderTestCase {
  LoadBalancerConfig config;
  QuicConnectionId connection_id;
  LoadBalancerServerId server_id;
};

TEST_F(LoadBalancerDecoderTest, UnencryptedConnectionIdTestVectors) {
  const struct LoadBalancerDecoderTestCase test_vectors[2] = {
      {
          *LoadBalancerConfig::CreateUnencrypted(0, 3, 4),
          QuicConnectionId({0x07, 0xed, 0x79, 0x3a, 0x80, 0x49, 0x71, 0x8a}),
          MakeServerId(kServerId, 3),
      },
      {
          *LoadBalancerConfig::CreateUnencrypted(1, 8, 5),
          QuicConnectionId({0x2d, 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f,
                            0x5f, 0xee, 0x15, 0xda, 0x27, 0xc4}),
          MakeServerId(kServerId, 8),
      }};
  for (const auto& test : test_vectors) {
    LoadBalancerDecoder decoder;
    LoadBalancerServerId answer;
    EXPECT_TRUE(decoder.AddConfig(test.config));
    EXPECT_TRUE(decoder.GetServerId(test.connection_id, answer));
    EXPECT_EQ(answer, test.server_id);
  }
}

// Compare test vectors from Appendix B of draft-ietf-quic-load-balancers-19.
TEST_F(LoadBalancerDecoderTest, DecoderTestVectors) {
  // Try (1) the "standard" CID length of 8
  // (2) server_id_len > nonce_len, so there is a fourth decryption pass
  // (3) the single-pass encryption case
  // (4) An even total length.
  const struct LoadBalancerDecoderTestCase test_vectors[4] = {
      {
          *LoadBalancerConfig::Create(0, 3, 4, kKey),
          QuicConnectionId({0x07, 0x20, 0xb1, 0xd0, 0x7b, 0x35, 0x9d, 0x3c}),
          MakeServerId(kServerId, 3),
      },
      {
          *LoadBalancerConfig::Create(1, 10, 5, kKey),
          QuicConnectionId({0x2f, 0xcc, 0x38, 0x1b, 0xc7, 0x4c, 0xb4, 0xfb,
                            0xad, 0x28, 0x23, 0xa3, 0xd1, 0xf8, 0xfe, 0xd2}),
          MakeServerId(kServerId, 10),
      },
      {
          *LoadBalancerConfig::Create(2, 8, 8, kKey),
          QuicConnectionId({0x50, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9,
                            0xb2, 0xb9, 0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c,
                            0xc3}),
          MakeServerId(kServerId, 8),
      },
      {
          *LoadBalancerConfig::Create(0, 9, 9, kKey),
          QuicConnectionId({0x12, 0x57, 0x79, 0xc9, 0xcc, 0x86, 0xbe, 0xb3,
                            0xa3, 0xa4, 0xa3, 0xca, 0x96, 0xfc, 0xe4, 0xbf,
                            0xe0, 0xcd, 0xbc}),
          MakeServerId(kServerId, 9),
      },
  };
  for (const auto& test : test_vectors) {
    LoadBalancerDecoder decoder;
    EXPECT_TRUE(decoder.AddConfig(test.config));
    LoadBalancerServerId answer;
    EXPECT_TRUE(decoder.GetServerId(test.connection_id, answer));
    EXPECT_EQ(answer, test.server_id);
  }
}

TEST_F(LoadBalancerDecoderTest, InvalidConfigId) {
  LoadBalancerServerId server_id({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id.IsValid());
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(1, 3, 4)));
  QuicConnectionId wrong_config_id(
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
  LoadBalancerServerId answer;
  EXPECT_FALSE(decoder.GetServerId(
      QuicConnectionId({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
      answer));
}

TEST_F(LoadBalancerDecoderTest, UnroutableCodepoint) {
  LoadBalancerServerId server_id({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id.IsValid());
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(1, 3, 4)));
  LoadBalancerServerId answer;
  EXPECT_FALSE(decoder.GetServerId(
      QuicConnectionId({0xe0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
      answer));
}

TEST_F(LoadBalancerDecoderTest, UnroutableCodepointAnyLength) {
  LoadBalancerServerId server_id({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id.IsValid());
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(1, 3, 4)));
  LoadBalancerServerId answer;
  EXPECT_FALSE(decoder.GetServerId(QuicConnectionId({0xff}), answer));
}

TEST_F(LoadBalancerDecoderTest, ConnectionIdTooShort) {
  LoadBalancerServerId server_id({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id.IsValid());
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(0, 3, 4)));
  LoadBalancerServerId answer;
  EXPECT_FALSE(decoder.GetServerId(
      QuicConnectionId({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}), answer));
}

TEST_F(LoadBalancerDecoderTest, ConnectionIdTooLongIsOK) {
  LoadBalancerServerId server_id({0x01, 0x02, 0x03});
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(0, 3, 4)));
  LoadBalancerServerId answer;
  EXPECT_TRUE(decoder.GetServerId(
      QuicConnectionId({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}),
      answer));
  EXPECT_EQ(answer, server_id);
}

TEST_F(LoadBalancerDecoderTest, DeleteConfigBadId) {
  LoadBalancerDecoder decoder;
  decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(2, 3, 4));
  decoder.DeleteConfig(0);
  EXPECT_QUIC_BUG(decoder.DeleteConfig(7),
                  "Decoder deleting config with invalid config_id 7");
  LoadBalancerServerId answer;
  EXPECT_TRUE(decoder.GetServerId(
      QuicConnectionId({0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
      answer));
}

TEST_F(LoadBalancerDecoderTest, DeleteConfigGoodId) {
  LoadBalancerDecoder decoder;
  decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(2, 3, 4));
  decoder.DeleteConfig(2);
  LoadBalancerServerId answer;
  EXPECT_FALSE(decoder.GetServerId(
      QuicConnectionId({0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
      answer));
}

// Create two server IDs and make sure the decoder decodes the correct one.
TEST_F(LoadBalancerDecoderTest, TwoServerIds) {
  LoadBalancerServerId server_id1({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id1.IsValid());
  LoadBalancerServerId server_id2({0x04, 0x05, 0x06});
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(0, 3, 4)));
  LoadBalancerServerId answer;
  EXPECT_TRUE(decoder.GetServerId(
      QuicConnectionId({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
      answer));
  EXPECT_EQ(answer, server_id1);
  EXPECT_TRUE(decoder.GetServerId(
      QuicConnectionId({0x00, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}),
      answer));
  EXPECT_EQ(answer, server_id2);
}

TEST_F(LoadBalancerDecoderTest, GetConfigId) {
  EXPECT_FALSE(
      LoadBalancerDecoder::GetConfigId(QuicConnectionId()).has_value());
  for (uint8_t i = 0; i < kNumLoadBalancerConfigs; i++) {
    const QuicConnectionId connection_id(
        {static_cast<unsigned char>(i << kConnectionIdLengthBits)});
    auto config_id = LoadBalancerDecoder::GetConfigId(connection_id);
    EXPECT_EQ(config_id,
              LoadBalancerDecoder::GetConfigId(connection_id.data()[0]));
    EXPECT_TRUE(config_id.has_value());
    EXPECT_EQ(*config_id, i);
  }
  EXPECT_FALSE(
      LoadBalancerDecoder::GetConfigId(QuicConnectionId({0xe0})).has_value());
}

TEST_F(LoadBalancerDecoderTest, GetConfig) {
  LoadBalancerDecoder decoder;
  decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(2, 3, 4));

  EXPECT_EQ(decoder.GetConfig(0), nullptr);
  EXPECT_EQ(decoder.GetConfig(1), nullptr);
  EXPECT_EQ(decoder.GetConfig(3), nullptr);
  EXPECT_EQ(decoder.GetConfig(4), nullptr);

  const LoadBalancerConfig* config = decoder.GetConfig(2);
  ASSERT_NE(config, nullptr);
  EXPECT_EQ(config->server_id_len(), 3);
  EXPECT_EQ(config->nonce_len(), 4);
  EXPECT_FALSE(config->IsEncrypted());
}

TEST_F(LoadBalancerDecoderTest, OnePassIgnoreAdditionalBytes) {
  uint8_t ptext[] = {0x00, 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f, 0xee,
                     0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5, 0xda, 0x41};
  uint8_t ctext[] = {0x00, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9, 0xb2, 0xb9,
                     0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c, 0xc3, 0xda, 0x41};
  LoadBalancerDecoder decoder;
  decoder.AddConfig(
      *LoadBalancerConfig::Create(0, 8, 8, absl::string_view(kRawKey, 16)));
  LoadBalancerServerId original_server_id(absl::Span<uint8_t>(&ptext[1], 8));
  QuicConnectionId cid(absl::Span<uint8_t>(ctext, sizeof(ctext)));
  LoadBalancerServerId answer;
  EXPECT_TRUE(decoder.GetServerId(cid, answer));
  EXPECT_EQ(answer, original_server_id);
}

}  // namespace

}  // namespace test

}  // namespace quic
```