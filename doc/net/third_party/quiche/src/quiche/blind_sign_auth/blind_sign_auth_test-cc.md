Response:
Let's break down the thought process for analyzing the C++ test file.

**1. Initial Understanding of the File's Purpose:**

The file path `net/third_party/quiche/src/quiche/blind_sign_auth/blind_sign_auth_test.cc` immediately suggests this is a test file for the `blind_sign_auth` component within the QUIC implementation (Quiche). The `_test.cc` suffix is a strong indicator of a test file in C++ projects.

**2. Examining the Includes:**

The included headers provide crucial clues about the functionalities being tested:

* `"quiche/blind_sign_auth/blind_sign_auth.h"`:  This is the header file for the class being tested.
* Standard C++ headers (`<cstdint>`, `<memory>`, `<string>`, etc.): Indicate basic C++ usage.
* `"absl/...`":  Usage of the Abseil libraries, particularly for status handling (`absl/status/...`), string manipulation (`absl/strings/...`), and time operations (`absl/time/...`).
* `"anonymous_tokens/cpp/...`":  This points to the anonymous tokens library, suggesting the `BlindSignAuth` component is related to privacy-preserving authentication. The specific includes (crypto, token encodings, testing utils) give more context.
* `"openssl/base.h"`, `"openssl/digest.h"`: Indicate the use of OpenSSL for cryptographic operations.
* `"quiche/blind_sign_auth/...`": Includes related to the `blind_sign_auth` module, such as interfaces and protocol buffers.
* `"quiche/common/platform/api/...`":  Quiche's platform abstraction layer, indicating testing constructs.
* `"quiche/common/test_tools/...`": Quiche's testing utilities.

**3. Identifying the Test Fixture:**

The `class BlindSignAuthTest : public QuicheTest` defines the test fixture. This means all the test cases within this class will inherit the setup and teardown logic defined in `SetUp()` and `TearDown()`.

**4. Analyzing `SetUp()`:**

This method is crucial for understanding the test environment:

* **Key Pair Generation:** The code generates an RSA key pair using `anonymous_tokens::GetStrongTestRsaKeyPair2048()`. This immediately suggests that the blind signing mechanism uses RSA cryptography. The subsequent code populates `rsa_public_key_` and `rsa_private_key_` with these keys.
* **Protobuf Population:** The code populates `public_key_proto_` with details about the public key, including key version, use case, hash type, etc. This shows that configuration and key information are likely exchanged using protocol buffers.
* **Request/Response Mocking:** The creation of `expected_get_initial_data_request_` and `fake_get_initial_data_response_` indicates that the tests will involve mocking network requests and responses. The specific fields in these protos reveal the nature of the initial data exchange.
* **Privacy Pass Data:** The code constructs `privacy_pass_data`, which includes a `token_key_id_` (derived from the public key) and serialized extensions. This strongly suggests the involvement of Privacy Pass or a similar mechanism.
* **Extension Creation:** The code creates various extensions (expiration timestamp, geo hint, service type, debug mode, proxy layer) and serializes them. This hints at the metadata being associated with the blind signatures.
* **BlindSignAuth Instantiation:**  Finally, `blind_sign_auth_` is instantiated with a mock message interface and options enabling Privacy Pass. This confirms that the tests will use a mock object for network interactions.

**5. Analyzing Helper Functions (`CreateSignResponse`, `ValidatePrivacyPassTokensOutput`):**

These functions are designed to simplify test setup and verification:

* **`CreateSignResponse`:** This function takes a request body and generates a simulated sign response. It validates the incoming request, extracts the blinded token, and simulates signing it using the private key. The conditional logic for `use_privacy_pass` is important, showing how the signing process differs with and without Privacy Pass.
* **`ValidatePrivacyPassTokensOutput`:** This function inspects the output tokens, verifying their internal structure (token and encoded extensions) and the presence of specific metadata like the geo hint.

**6. Examining Individual Test Cases:**

Each `TEST_F` block represents a specific test scenario:

* **Error Handling Tests:** Tests like `TestGetTokensFailedNetworkError`, `TestGetTokensFailedBadGetInitialDataResponse`, and `TestGetTokensFailedBadAuthAndSignResponse` focus on how the `BlindSignAuth` class handles various error conditions during the token acquisition process. They use `EXPECT_CALL` to set expectations on the mock message interface.
* **Success Case:** `TestPrivacyPassGetTokensSucceeds` tests the successful acquisition of tokens when Privacy Pass is enabled. It verifies the output tokens using `ValidatePrivacyPassTokensOutput`.
* **Negative Privacy Pass Test:** `TestPrivacyPassGetTokensFailsWithBadExtensions` tests a scenario where the Privacy Pass extensions are invalid.

**7. Connecting to JavaScript (if applicable):**

The core logic here is C++. The connection to JavaScript would primarily be through network interactions. If a website or web application uses this blind signing functionality:

* **JavaScript initiates the token request:** JavaScript code would make an HTTP request to a server endpoint that triggers the C++ `BlindSignAuth::GetTokens` call.
* **JavaScript receives the tokens:** The server would then return the acquired blind sign tokens to the JavaScript code, likely in a JSON format.
* **JavaScript uses the tokens:** The JavaScript code might then include these tokens in subsequent requests to authenticate the user or prove something about their identity without revealing personal information.

**8. Logical Reasoning and Input/Output:**

For tests like `TestPrivacyPassGetTokensSucceeds`:

* **Hypothetical Input:** An OAuth token, a request for 1 token, Proxy Layer A, and the Chrome IP Blinding service type.
* **Expected Output:** A successful status and an array/span containing one `BlindSignToken`. This token's internal structure (when decoded) would contain the signed blinded value and encoded extensions (including the geo hint). The `ValidatePrivacyPassTokensOutput` function verifies the specifics.

**9. Common Usage Errors:**

* **Incorrect OAuth Token:** Providing an invalid or expired OAuth token will likely lead to authentication failures on the server-side.
* **Incorrect Number of Tokens Requested:**  Requesting a negative or zero number of tokens might lead to undefined behavior or errors.
* **Mismatched Service Type:** Specifying the wrong `BlindSignAuthServiceType` could result in the server rejecting the request.
* **Network Connectivity Issues:**  The device running the code needs network access to communicate with the blind signing service.

**10. User Operation Steps as Debugging Clues:**

Imagine a user trying to access a website that uses Privacy Pass with Chrome IP Blinding:

1. **User opens a website:** The user navigates to a website that requires a Privacy Pass token for access (or to get better service).
2. **Website triggers token request:** The website's JavaScript (or the browser itself) detects the need for a token and initiates a request to the Chrome IP Blinding service.
3. **Browser (or extension) obtains OAuth token:**  Chrome or a related extension handles the OAuth authentication flow to get a valid OAuth token.
4. **`BlindSignAuth::GetTokens` is called:** The network stack in Chromium calls the `BlindSignAuth::GetTokens` function with the OAuth token and other parameters. This is where the code in the test file is relevant.
5. **Network requests are made:** The `MockBlindSignMessageInterface` (in tests) or the actual network interface makes requests to the blind signing service.
6. **Tokens are received:** The blind signing service returns signed tokens.
7. **Tokens are used by the website:** The browser sends these tokens to the website to prove the user has a valid token.

By understanding this user flow, developers can trace potential issues. For example, if a user cannot access the website, debugging might involve inspecting:

* **Network requests:** Are the requests to the blind signing service being made correctly? Are there any network errors?
* **OAuth token validity:** Is the user's OAuth token valid?
* **Server-side logs:** What is the blind signing service's response to the token request?
* **Local state:** Is the browser or extension configured correctly for Privacy Pass?

This systematic approach helps in dissecting the code, understanding its purpose, and identifying potential issues and connections to broader systems.
这个C++源代码文件 `blind_sign_auth_test.cc` 是 Chromium 网络栈中 QUIC 库的 `blind_sign_auth` 组件的单元测试文件。它的主要功能是测试 `BlindSignAuth` 类的各种功能，确保其按照预期工作。

以下是该文件的详细功能分解：

**1. 测试 `BlindSignAuth` 类的核心功能:**

* **获取盲签名 Token (GetTokens):**  测试 `BlindSignAuth::GetTokens` 方法，该方法负责与后端服务通信，获取用于匿名身份验证的盲签名 Token。测试包括成功获取 Token 的情况，以及各种错误情况，例如网络错误、后端服务返回错误响应、无效的响应数据等。
* **Privacy Pass 集成:** 重点测试了与 Privacy Pass 的集成。Privacy Pass 是一种匿名凭证系统，`BlindSignAuth` 可以使用它来获取 Token。测试涵盖了启用 Privacy Pass 和禁用 Privacy Pass 的不同场景，以及在启用 Privacy Pass 时处理公共元数据扩展的情况。
* **错误处理:** 测试了各种错误场景下的行为，例如后端服务返回错误状态码、响应数据格式不正确、网络连接失败等。
* **请求参数构建:** 验证了 `BlindSignAuth` 在与后端服务通信时，构建的请求参数是否正确，例如服务类型、代理层、公钥信息等。
* **响应数据解析:** 测试了 `BlindSignAuth` 正确解析后端服务返回的响应数据，包括公钥信息、签名信息等。

**2. 模拟后端服务交互:**

* **使用 Mock 对象:**  该测试文件使用了 `MockBlindSignMessageInterface` 来模拟与后端盲签名服务的通信。这使得测试可以在不依赖真实后端服务的情况下进行，提高了测试的效率和可靠性。
* **设置 Mock 行为:**  通过 `EXPECT_CALL` 宏，可以预先设定 Mock 对象的行为，例如当调用 `DoRequest` 方法时，返回特定的状态码或响应数据。

**3. 辅助测试功能:**

* **密钥生成和管理:** 在 `SetUp()` 方法中，生成了用于测试的 RSA 公钥和私钥，并将其转换为相应的 Protocol Buffer 格式。
* **构造测试请求和响应:**  `SetUp()` 方法还构造了预期的 `GetInitialDataRequest` 和伪造的 `GetInitialDataResponse`，用于模拟初始数据获取阶段的交互。
* **辅助函数:** 提供了 `CreateSignResponse` 函数来根据请求内容创建模拟的签名响应，以及 `ValidatePrivacyPassTokensOutput` 函数来验证 Privacy Pass Token 的输出格式和内容。

**与 Javascript 的关系 (如果存在):**

虽然该文件是 C++ 代码，但 `BlindSignAuth` 组件最终会服务于浏览器中的 Javascript 代码。以下是一些可能的关联和举例：

* **Javascript 发起 Token 请求:**  在浏览器中，当网站需要获取盲签名 Token 时，通常会通过 Javascript 代码调用浏览器提供的 API (例如 Chrome 的 Privacy Pass API 或 Network API) 来触发 Token 获取流程。这个流程最终会调用到 C++ 的 `BlindSignAuth::GetTokens` 方法。
    * **举例:**  一个使用了 Privacy Pass 的网站可能会使用如下 Javascript 代码片段来请求 Token:
      ```javascript
      navigator.privacyPass.requestToken({
          count: 1,
          // 其他可能的参数
      }).then(token => {
          // 将获取到的 token 发送给网站的后端服务器
          console.log("Got Privacy Pass token:", token);
      }).catch(error => {
          console.error("Failed to get Privacy Pass token:", error);
      });
      ```
* **Token 的使用:**  Javascript 代码获取到 Token 后，通常会将其添加到后续发送给网站服务器的请求头中，作为匿名身份验证的凭据。
    * **举例:**  可以将 Token 添加到 `Authorization` 请求头中:
      ```javascript
      fetch('/protected-resource', {
          headers: {
              'Authorization': `PrivacyPass ${token}`
          }
      });
      ```

**逻辑推理 (假设输入与输出):**

考虑 `TEST_F(BlindSignAuthTest, TestPrivacyPassGetTokensSucceeds)` 这个测试用例：

* **假设输入:**
    * `oauth_token_` (一个有效的 OAuth 令牌，用于与后端服务进行身份验证)
    * `num_tokens = 1` (请求获取一个 Token)
    * `ProxyLayer::kProxyA` (指定使用的代理层)
    * `BlindSignAuthServiceType::kChromeIpBlinding` (指定服务类型为 Chrome IP Blinding)
    * Mock 消息接口被配置为：
        * 首次调用 `DoRequest` (用于获取初始数据) 返回成功的响应，包含预先设定的公钥信息和 Privacy Pass 数据。
        * 第二次调用 `DoRequest` (用于签名 Token) 返回成功的响应，包含使用私钥签名的 Token。
* **预期输出:**
    * `GetTokens` 方法成功执行，返回一个 `absl::Span<BlindSignToken>`，其中包含一个 `BlindSignToken` 对象。
    * 该 `BlindSignToken` 的 `token` 字段包含一个 Privacy Pass Token 的序列化数据。
    * 该 `BlindSignToken` 的 `geo_hint` 字段包含预期的地理位置信息 ("US,US-AL,ALABASTER")。

**用户或编程常见的使用错误:**

* **错误的 OAuth 令牌:** 用户可能配置了错误的或过期的 OAuth 令牌，导致无法成功与后端服务进行身份验证。
* **请求的 Token 数量不合理:** 请求过多或过少的 Token 可能会导致性能问题或服务拒绝。
* **服务类型不匹配:**  在调用 `GetTokens` 时，指定了错误的服务类型，导致后端服务无法正确处理请求。
* **网络连接问题:**  用户的设备没有网络连接，或者连接不稳定，导致无法与后端服务通信。
* **Privacy Pass 配置错误:** 如果用户或程序没有正确配置 Privacy Pass 扩展或设置，可能会导致无法获取 Token。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器访问一个使用了 Privacy Pass 的网站，并且该网站的服务类型是 Chrome IP Blinding：

1. **用户打开网站:** 用户在 Chrome 浏览器中输入网址或点击链接访问该网站。
2. **网站触发 Privacy Pass 流程:** 网站的 Javascript 代码检测到需要 Privacy Pass Token，并调用浏览器的 Privacy Pass API (`navigator.privacyPass.requestToken`).
3. **浏览器发起 Token 请求:** Chrome 浏览器接收到 Javascript 的请求，开始进行 Token 获取流程。
4. **调用 C++ `BlindSignAuth::GetTokens`:**  浏览器内部的网络栈代码会根据配置和服务类型，调用到 `net/third_party/quiche/src/quiche/blind_sign_auth/blind_sign_auth.cc` 文件中的 `BlindSignAuth::GetTokens` 方法。
5. **与后端服务通信:** `BlindSignAuth::GetTokens` 方法会使用 `BlindSignMessageInterface` 与后端盲签名服务进行通信，首先获取初始数据（包括公钥），然后发送盲化的 Token 请求签名。
6. **接收签名后的 Token:** 后端服务返回签名后的 Token。
7. **将 Token 返回给 Javascript:** `BlindSignAuth::GetTokens` 方法将获取到的 Token 返回给浏览器，最终通过 Privacy Pass API 的 Promise 将 Token 传递给网站的 Javascript 代码。

**调试线索:**

如果在上述过程中出现问题，可以从以下几个方面进行调试：

* **Network 面板:** 查看浏览器 Network 面板，检查与盲签名服务相关的网络请求（例如 `/initial-data`, `/auth-and-sign`）的状态码、请求头、响应头和响应体，确认请求是否发送成功，以及后端服务是否返回了错误。
* **Chrome 内部日志:**  Chrome 提供了内部日志功能（可以通过 `chrome://net-export/` 导出），可以查看更详细的网络请求和响应信息，以及 Privacy Pass 组件的运行状态。
* **断点调试:**  可以在 `blind_sign_auth.cc` 和 `blind_sign_auth_test.cc` 中设置断点，跟踪代码执行流程，查看变量的值，例如请求参数、响应数据等。
* **Privacy Pass 扩展状态:** 检查浏览器中 Privacy Pass 扩展的状态，确认是否已启用，以及是否有可用的 Token。
* **后端服务日志:**  如果可以访问后端服务的日志，可以查看服务端的请求处理情况，是否有错误发生。

总而言之，`blind_sign_auth_test.cc` 是一个至关重要的测试文件，它确保了 `BlindSignAuth` 组件的正确性和可靠性，而 `BlindSignAuth` 组件在 Chromium 中负责处理盲签名 Token 的获取，为用户提供匿名身份验证的功能。理解这个测试文件的功能有助于理解整个盲签名流程以及如何进行调试。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/blind_sign_auth/blind_sign_auth_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/blind_sign_auth/blind_sign_auth.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "anonymous_tokens/cpp/privacy_pass/token_encodings.h"
#include "anonymous_tokens/cpp/testing/utils.h"
#include "openssl/base.h"
#include "openssl/digest.h"
#include "quiche/blind_sign_auth/blind_sign_auth_interface.h"
#include "quiche/blind_sign_auth/blind_sign_auth_protos.h"
#include "quiche/blind_sign_auth/blind_sign_message_interface.h"
#include "quiche/blind_sign_auth/blind_sign_message_response.h"
#include "quiche/blind_sign_auth/test_tools/mock_blind_sign_message_interface.h"
#include "quiche/common/platform/api/quiche_mutex.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace quiche {
namespace test {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::StartsWith;
using ::testing::Unused;

class BlindSignAuthTest : public QuicheTest {
 protected:
  void SetUp() override {
    // Create keypair and populate protos.
    auto [test_rsa_public_key, test_rsa_private_key] =
        anonymous_tokens::GetStrongTestRsaKeyPair2048();
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        rsa_public_key_,
        anonymous_tokens::CreatePublicKeyRSA(
            test_rsa_public_key.n, test_rsa_public_key.e));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        rsa_private_key_,
        anonymous_tokens::CreatePrivateKeyRSA(
            test_rsa_private_key.n, test_rsa_private_key.e,
            test_rsa_private_key.d, test_rsa_private_key.p,
            test_rsa_private_key.q, test_rsa_private_key.dp,
            test_rsa_private_key.dq, test_rsa_private_key.crt));

    anonymous_tokens::RSAPublicKey public_key;
    public_key.set_n(test_rsa_public_key.n);
    public_key.set_e(test_rsa_public_key.e);

    public_key_proto_.set_key_version(1);
    public_key_proto_.set_use_case("TEST_USE_CASE");
    public_key_proto_.set_serialized_public_key(public_key.SerializeAsString());
    public_key_proto_.set_sig_hash_type(
        anonymous_tokens::AT_HASH_TYPE_SHA384);
    public_key_proto_.set_mask_gen_function(
        anonymous_tokens::AT_MGF_SHA384);
    public_key_proto_.set_salt_length(48);
    public_key_proto_.set_key_size(256);
    public_key_proto_.set_message_mask_type(
        anonymous_tokens::AT_MESSAGE_MASK_NO_MASK);
    public_key_proto_.set_message_mask_size(0);

    // Create expected GetInitialDataRequest.
    expected_get_initial_data_request_.set_use_attestation(false);
    expected_get_initial_data_request_.set_service_type("chromeipblinding");
    expected_get_initial_data_request_.set_location_granularity(
        privacy::ppn::GetInitialDataRequest_LocationGranularity_CITY_GEOS);
    expected_get_initial_data_request_.set_validation_version(2);
    expected_get_initial_data_request_.set_proxy_layer(privacy::ppn::PROXY_A);

    // Create fake GetInitialDataResponse.
    privacy::ppn::GetInitialDataResponse fake_get_initial_data_response;
    *fake_get_initial_data_response.mutable_at_public_metadata_public_key() =
        public_key_proto_;
    fake_get_initial_data_response_ = fake_get_initial_data_response;

    // Create PrivacyPassData.
    privacy::ppn::GetInitialDataResponse::PrivacyPassData privacy_pass_data;
    // token_key_id is derived from public key.
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        std::string public_key_der,
        anonymous_tokens::RsaSsaPssPublicKeyToDerEncoding(
            rsa_public_key_.get()));
    const EVP_MD* sha256 = EVP_sha256();
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        token_key_id_, anonymous_tokens::ComputeHash(
                           public_key_der, *sha256));

    // Create and serialize fake extensions.
    anonymous_tokens::ExpirationTimestamp
        expiration_timestamp;
    int64_t one_hour_away = absl::ToUnixSeconds(absl::Now() + absl::Hours(1));
    expiration_timestamp.timestamp = one_hour_away - (one_hour_away % 900);
    expiration_timestamp.timestamp_precision = 900;
    absl::StatusOr<anonymous_tokens::Extension>
        expiration_extension = expiration_timestamp.AsExtension();
    QUICHE_EXPECT_OK(expiration_extension);
    extensions_.extensions.push_back(*expiration_extension);

    anonymous_tokens::GeoHint geo_hint;
    geo_hint.geo_hint = "US,US-AL,ALABASTER";
    absl::StatusOr<anonymous_tokens::Extension>
        geo_hint_extension = geo_hint.AsExtension();
    QUICHE_EXPECT_OK(geo_hint_extension);
    extensions_.extensions.push_back(*geo_hint_extension);

    anonymous_tokens::ServiceType service_type;
    service_type.service_type_id =
        anonymous_tokens::ServiceType::kChromeIpBlinding;
    absl::StatusOr<anonymous_tokens::Extension>
        service_type_extension = service_type.AsExtension();
    QUICHE_EXPECT_OK(service_type_extension);
    extensions_.extensions.push_back(*service_type_extension);

    anonymous_tokens::DebugMode debug_mode;
    debug_mode.mode = anonymous_tokens::DebugMode::kDebug;
    absl::StatusOr<anonymous_tokens::Extension>
        debug_mode_extension = debug_mode.AsExtension();
    QUICHE_EXPECT_OK(debug_mode_extension);
    extensions_.extensions.push_back(*debug_mode_extension);

    anonymous_tokens::ProxyLayer proxy_layer;
    proxy_layer.layer =
        anonymous_tokens::ProxyLayer::kProxyA;
    absl::StatusOr<anonymous_tokens::Extension>
        proxy_layer_extension = proxy_layer.AsExtension();
    QUICHE_EXPECT_OK(proxy_layer_extension);
    extensions_.extensions.push_back(*proxy_layer_extension);

    absl::StatusOr<std::string> serialized_extensions =
        anonymous_tokens::EncodeExtensions(extensions_);
    QUICHE_EXPECT_OK(serialized_extensions);

    privacy_pass_data.set_token_key_id(token_key_id_);
    privacy_pass_data.set_public_metadata_extensions(*serialized_extensions);

    *fake_get_initial_data_response.mutable_public_metadata_info() =
        public_metadata_info_;
    *fake_get_initial_data_response.mutable_privacy_pass_data() =
        privacy_pass_data;
    fake_get_initial_data_response_ = fake_get_initial_data_response;

    // Create BlindSignAuthOptions.
    privacy::ppn::BlindSignAuthOptions options;
    options.set_enable_privacy_pass(true);

    blind_sign_auth_ =
        std::make_unique<BlindSignAuth>(&mock_message_interface_, options);
  }

  void TearDown() override { blind_sign_auth_.reset(nullptr); }

 public:
  void CreateSignResponse(const std::string& body, bool use_privacy_pass) {
    privacy::ppn::AuthAndSignRequest request;
    ASSERT_TRUE(request.ParseFromString(body));

    // Validate AuthAndSignRequest.
    EXPECT_EQ(request.service_type(), "chromeipblinding");
    // Phosphor does not need the public key hash if the KeyType is
    // privacy::ppn::AT_PUBLIC_METADATA_KEY_TYPE.
    EXPECT_EQ(request.key_type(), privacy::ppn::AT_PUBLIC_METADATA_KEY_TYPE);
    EXPECT_EQ(request.public_key_hash(), "");
    EXPECT_EQ(request.key_version(), public_key_proto_.key_version());
    EXPECT_EQ(request.do_not_use_rsa_public_exponent(), true);
    EXPECT_NE(request.blinded_token().size(), 0);

    if (use_privacy_pass) {
      EXPECT_EQ(request.public_metadata_extensions(),
                fake_get_initial_data_response_.privacy_pass_data()
                    .public_metadata_extensions());
    } else {
      EXPECT_EQ(request.public_metadata_info().SerializeAsString(),
                public_metadata_info_.SerializeAsString());
    }

    // Construct AuthAndSignResponse.
    privacy::ppn::AuthAndSignResponse response;
    for (const auto& request_token : request.blinded_token()) {
      std::string decoded_blinded_token;
      ASSERT_TRUE(absl::Base64Unescape(request_token, &decoded_blinded_token));
      if (use_privacy_pass) {
        absl::StatusOr<std::string> signature =
            anonymous_tokens::TestSignWithPublicMetadata(
                decoded_blinded_token, request.public_metadata_extensions(),
                *rsa_private_key_, false);
        QUICHE_EXPECT_OK(signature);
        response.add_blinded_token_signature(absl::Base64Escape(*signature));
      } else {
        absl::StatusOr<std::string> serialized_token =
            anonymous_tokens::TestSign(
                decoded_blinded_token, rsa_private_key_.get());
        // TestSignWithPublicMetadata for privacy pass
        QUICHE_EXPECT_OK(serialized_token);
        response.add_blinded_token_signature(
            absl::Base64Escape(*serialized_token));
      }
    }
    sign_response_ = response;
  }

  void ValidatePrivacyPassTokensOutput(absl::Span<BlindSignToken> tokens) {
    for (const auto& token : tokens) {
      privacy::ppn::PrivacyPassTokenData privacy_pass_token_data;
      ASSERT_TRUE(privacy_pass_token_data.ParseFromString(token.token));
      // Validate token structure.
      std::string decoded_token;
      ASSERT_TRUE(absl::WebSafeBase64Unescape(privacy_pass_token_data.token(),
                                              &decoded_token));
      // Extensions should be padded and web-safe.
      EXPECT_EQ(privacy_pass_token_data.encoded_extensions().back(), '=');
      std::string decoded_extensions;
      ASSERT_TRUE(absl::WebSafeBase64Unescape(
          privacy_pass_token_data.encoded_extensions(), &decoded_extensions));
      // Validate GeoHint in BlindSignToken.
      EXPECT_EQ(token.geo_hint.geo_hint, "US,US-AL,ALABASTER");
      EXPECT_EQ(token.geo_hint.country_code, "US");
      EXPECT_EQ(token.geo_hint.region, "US-AL");
      EXPECT_EQ(token.geo_hint.city, "ALABASTER");
    }
  }

  MockBlindSignMessageInterface mock_message_interface_;
  std::unique_ptr<BlindSignAuth> blind_sign_auth_;
  anonymous_tokens::RSABlindSignaturePublicKey
      public_key_proto_;
  bssl::UniquePtr<RSA> rsa_public_key_;
  bssl::UniquePtr<RSA> rsa_private_key_;
  std::string token_key_id_;
  anonymous_tokens::Extensions extensions_;
  privacy::ppn::PublicMetadataInfo public_metadata_info_;
  privacy::ppn::AuthAndSignResponse sign_response_;
  privacy::ppn::GetInitialDataResponse fake_get_initial_data_response_;
  std::string oauth_token_ = "oauth_token";
  privacy::ppn::GetInitialDataRequest expected_get_initial_data_request_;
};

TEST_F(BlindSignAuthTest, TestGetTokensFailedNetworkError) {
  EXPECT_CALL(mock_message_interface_,
              DoRequest(Eq(BlindSignMessageRequestType::kGetInitialData),
                        Eq(oauth_token_), _, _))
      .Times(1)
      .WillOnce([=](auto&&, auto&&, auto&&, auto get_initial_data_cb) {
        std::move(get_initial_data_cb)(
            absl::InternalError("Failed to create socket"));
      });

  EXPECT_CALL(mock_message_interface_,
              DoRequest(Eq(BlindSignMessageRequestType::kAuthAndSign), _, _, _))
      .Times(0);

  int num_tokens = 1;
  QuicheNotification done;
  SignedTokenCallback callback =
      [&done](absl::StatusOr<absl::Span<BlindSignToken>> tokens) {
        EXPECT_THAT(tokens.status().code(), absl::StatusCode::kInvalidArgument);
        done.Notify();
      };
  blind_sign_auth_->GetTokens(oauth_token_, num_tokens, ProxyLayer::kProxyA,
                              BlindSignAuthServiceType::kChromeIpBlinding,
                              std::move(callback));
  done.WaitForNotification();
}

TEST_F(BlindSignAuthTest, TestGetTokensFailedBadGetInitialDataResponse) {
  *fake_get_initial_data_response_.mutable_at_public_metadata_public_key()
       ->mutable_use_case() = "SPAM";

  BlindSignMessageResponse fake_public_key_response(
      absl::StatusCode::kOk,
      fake_get_initial_data_response_.SerializeAsString());

  EXPECT_CALL(
      mock_message_interface_,
      DoRequest(Eq(BlindSignMessageRequestType::kGetInitialData),
                Eq(oauth_token_),
                Eq(expected_get_initial_data_request_.SerializeAsString()), _))
      .Times(1)
      .WillOnce([=](auto&&, auto&&, auto&&, auto get_initial_data_cb) {
        std::move(get_initial_data_cb)(fake_public_key_response);
      });

  EXPECT_CALL(mock_message_interface_,
              DoRequest(Eq(BlindSignMessageRequestType::kAuthAndSign), _, _, _))
      .Times(0);

  int num_tokens = 1;
  QuicheNotification done;
  SignedTokenCallback callback =
      [&done](absl::StatusOr<absl::Span<BlindSignToken>> tokens) {
        EXPECT_THAT(tokens.status().code(), absl::StatusCode::kInvalidArgument);
        done.Notify();
      };
  blind_sign_auth_->GetTokens(oauth_token_, num_tokens, ProxyLayer::kProxyA,
                              BlindSignAuthServiceType::kChromeIpBlinding,
                              std::move(callback));
  done.WaitForNotification();
}

TEST_F(BlindSignAuthTest, TestGetTokensFailedBadAuthAndSignResponse) {
  BlindSignMessageResponse fake_public_key_response(
      absl::StatusCode::kOk,
      fake_get_initial_data_response_.SerializeAsString());
  {
    InSequence seq;

    EXPECT_CALL(
        mock_message_interface_,
        DoRequest(
            Eq(BlindSignMessageRequestType::kGetInitialData), Eq(oauth_token_),
            Eq(expected_get_initial_data_request_.SerializeAsString()), _))
        .Times(1)
        .WillOnce([=](auto&&, auto&&, auto&&, auto get_initial_data_cb) {
          std::move(get_initial_data_cb)(fake_public_key_response);
        });

    EXPECT_CALL(mock_message_interface_,
                DoRequest(Eq(BlindSignMessageRequestType::kAuthAndSign),
                          Eq(oauth_token_), _, _))
        .Times(1)
        .WillOnce(Invoke([this](Unused, Unused, const std::string& body,
                                BlindSignMessageCallback callback) {
          CreateSignResponse(body, false);
          // Add an invalid signature that can't be Base64 decoded.
          sign_response_.add_blinded_token_signature("invalid_signature%");
          BlindSignMessageResponse response(absl::StatusCode::kOk,
                                            sign_response_.SerializeAsString());
          std::move(callback)(response);
        }));
  }

  int num_tokens = 1;
  QuicheNotification done;
  SignedTokenCallback callback =
      [&done](absl::StatusOr<absl::Span<BlindSignToken>> tokens) {
        EXPECT_THAT(tokens.status().code(), absl::StatusCode::kInternal);
        done.Notify();
      };
  blind_sign_auth_->GetTokens(oauth_token_, num_tokens, ProxyLayer::kProxyA,
                              BlindSignAuthServiceType::kChromeIpBlinding,
                              std::move(callback));
  done.WaitForNotification();
}

TEST_F(BlindSignAuthTest, TestPrivacyPassGetTokensSucceeds) {
  BlindSignMessageResponse fake_public_key_response(
      absl::StatusCode::kOk,
      fake_get_initial_data_response_.SerializeAsString());
  {
    InSequence seq;

    EXPECT_CALL(
        mock_message_interface_,
        DoRequest(
            Eq(BlindSignMessageRequestType::kGetInitialData), Eq(oauth_token_),
            Eq(expected_get_initial_data_request_.SerializeAsString()), _))
        .Times(1)
        .WillOnce([=](auto&&, auto&&, auto&&, auto get_initial_data_cb) {
          std::move(get_initial_data_cb)(fake_public_key_response);
        });

    EXPECT_CALL(mock_message_interface_,
                DoRequest(Eq(BlindSignMessageRequestType::kAuthAndSign),
                          Eq(oauth_token_), _, _))
        .Times(1)
        .WillOnce(Invoke([this](Unused, Unused, const std::string& body,
                                BlindSignMessageCallback callback) {
          CreateSignResponse(body, /*use_privacy_pass=*/true);
          BlindSignMessageResponse response(absl::StatusCode::kOk,
                                            sign_response_.SerializeAsString());
          std::move(callback)(response);
        }));
  }

  int num_tokens = 1;
  QuicheNotification done;
  SignedTokenCallback callback =
      [this, &done](absl::StatusOr<absl::Span<BlindSignToken>> tokens) {
        QUICHE_EXPECT_OK(tokens);
        ValidatePrivacyPassTokensOutput(*tokens);
        done.Notify();
      };
  blind_sign_auth_->GetTokens(oauth_token_, num_tokens, ProxyLayer::kProxyA,
                              BlindSignAuthServiceType::kChromeIpBlinding,
                              std::move(callback));
  done.WaitForNotification();
}

TEST_F(BlindSignAuthTest, TestPrivacyPassGetTokensFailsWithBadExtensions) {
  privacy::ppn::BlindSignAuthOptions options;
  options.set_enable_privacy_pass(true);
  blind_sign_auth_ =
      std::make_unique<BlindSignAuth>(&mock_message_interface_, options);

  public_key_proto_.set_message_mask_type(
      anonymous_tokens::AT_MESSAGE_MASK_NO_MASK);
  public_key_proto_.set_message_mask_size(0);
  *fake_get_initial_data_response_.mutable_at_public_metadata_public_key() =
      public_key_proto_;
  fake_get_initial_data_response_.mutable_privacy_pass_data()
      ->set_public_metadata_extensions("spam");
  BlindSignMessageResponse fake_public_key_response(
      absl::StatusCode::kOk,
      fake_get_initial_data_response_.SerializeAsString());

  EXPECT_CALL(
      mock_message_interface_,
      DoRequest(Eq(BlindSignMessageRequestType::kGetInitialData),
                Eq(oauth_token_),
                Eq(expected_get_initial_data_request_.SerializeAsString()), _))
      .Times(1)
      .WillOnce([=](auto&&, auto&&, auto&&, auto get_initial_data_cb) {
        std::move(get_initial_data_cb)(fake_public_key_response);
      });

  int num_tokens = 1;
  QuicheNotification done;
  SignedTokenCallback callback =
      [&done](absl::StatusOr<absl::Span<BlindSignToken>> tokens) {
        EXPECT_THAT(tokens.status().code(), absl::StatusCode::kInvalidArgument);
        done.Notify();
      };
  blind_sign_auth_->GetTokens(oauth_token_, num_tokens, ProxyLayer::kProxyA,
                              BlindSignAuthServiceType::kChromeIpBlinding,
                              std::move(callback));
  done.WaitForNotification();
}

}  // namespace
}  // namespace test
}  // namespace quiche
```