Response:
Let's break down the thought process for analyzing this C++ code and addressing the prompt's requirements.

**1. Understanding the Core Functionality:**

The first step is to read through the code and identify its main purpose. The class name `BlindSignAuth` and the function `GetTokens` immediately suggest an authentication or authorization mechanism using blind signatures. Keywords like "Privacy Pass," "RSA," "tokens," and the various protobuf message types (`GetInitialDataRequest`, `AuthAndSignRequest`, etc.) confirm this. The directory path `net/third_party/quiche/src/quiche/blind_sign_auth` indicates it's part of the QUIC implementation within Chromium, likely for privacy-preserving authentication in network requests.

**Key Functionality Identified:**

* **Token Acquisition:** The primary goal is to obtain signed tokens.
* **Blind Signatures:**  The code utilizes blind signature techniques, specifically Privacy Pass, for issuing tokens. This means the client can request a signed token without revealing the exact content being signed to the issuer beforehand.
* **Public Metadata:** The code interacts with a server that provides public metadata (like expiration times and geographic hints) associated with the tokens.
* **Proxy Layer Support:**  The `ProxyLayer` enum and related logic suggest the system can be used in conjunction with different proxy configurations.
* **Service Type Differentiation:** The `BlindSignAuthServiceType` enum hints at different use cases for the token issuance.
* **Callbacks:** Asynchronous operations using callbacks are evident.

**2. Tracing the `GetTokens` Flow:**

To understand the execution flow, trace the `GetTokens` function:

* It initiates a `GetInitialDataRequest`.
* The response to this request is handled by `GetInitialDataCallback`.
* Based on the response, it either uses Privacy Pass (`GeneratePrivacyPassTokens`) or indicates that non-Privacy Pass tokens are no longer supported.
* `GeneratePrivacyPassTokens` creates blind token requests and sends an `AuthAndSignRequest`.
* The server's signature response is processed in `PrivacyPassAuthAndSignCallback` to finalize the tokens.

**3. Identifying Potential Relationships with JavaScript:**

Since this is Chromium code, its purpose is to facilitate network operations within the browser. JavaScript in a web page would interact with this functionality *indirectly* through the browser's network stack.

* **Hypothesis:** This code likely provides the underlying mechanism for features like Privacy Pass in Chrome. When a user visits a website that uses Privacy Pass, the browser (using this C++ code) interacts with the Privacy Pass issuer to obtain tokens. These tokens are then sent with subsequent requests to prove the user has "spent" a token and isn't a bot or abusive client.

* **Example:** A website might implement a CAPTCHA alternative using Privacy Pass. When the user solves the CAPTCHA, the browser could obtain a Privacy Pass token using this C++ code and store it. Later, when the user performs an action on the website, the browser automatically includes this token in the request headers. The website's server can then verify the token.

**4. Logical Inference with Hypothetical Inputs and Outputs:**

Focus on the core functions:

* **`GetTokens` Input:** `oauth_token` (optional), `num_tokens`, `proxy_layer`, `service_type`, `callback`.
* **`GetTokens` Output (through callback):** `absl::Span<BlindSignToken>` (on success) or an error status.

* **`GeneratePrivacyPassTokens` Input:** `initial_data_response`, `oauth_token`, `num_tokens`, `proxy_layer`, `service_type`, `callback`.
* **`GeneratePrivacyPassTokens` Output (through callback):**  The same as `GetTokens`.

* **`PrivacyPassAuthAndSignCallback` Input:**  Various parameters related to the process, including the response from the server.
* **`PrivacyPassAuthAndSignCallback` Output (through callback):**  The final `BlindSignToken` objects.

**Hypothetical Scenario:**

* **Input (to `GetTokens`):** `num_tokens = 2`, `proxy_layer = ProxyLayer::kProxyA`, `service_type = BlindSignAuthServiceType::kChromeIpBlinding`.
* **Assumptions:**  The `GetInitialData` request succeeds, and the Privacy Pass flow is used. The server successfully signs the blind tokens.
* **Output (through callback):** A span containing two `BlindSignToken` objects. Each `BlindSignToken` would contain:
    * A serialized `PrivacyPassTokenData` protobuf.
    * A `public_key_expiry_time`.
    * A `geo_hint`.

**5. Identifying Common User/Programming Errors:**

Think about how the code could fail or be misused:

* **Invalid Server Response:** The code handles cases where `GetInitialData` or `AuthAndSign` fail or return non-OK status codes. A common error would be the server being down or returning malformed data.
* **Incorrect Protobuf Parsing:**  Failures to parse protobuf messages (`ParseFromString`) are checked. A programming error could be providing incorrect or corrupted data.
* **Mismatched Number of Signatures:** The code validates that the number of returned signatures matches the number of requested tokens. A server-side error could cause this.
* **Base64 Encoding/Decoding Issues:** Errors during base64 encoding/decoding are handled. Incorrect implementation or data corruption could lead to these errors.
* **Privacy Pass Client Errors:** Failures to create or use the `PrivacyPassRsaBssaPublicMetadataClient` are checked. This could indicate issues with the public key or other parameters.
* **Extension Validation:** The code validates the order and values of extensions. Incorrect server configuration or data could cause validation failures.

**6. Tracing User Actions to Reach the Code (Debugging Clues):**

Consider a scenario where a developer might be debugging this code:

1. **User Action:** A user attempts to access a website that utilizes Privacy Pass or a similar blind signature-based authentication mechanism (e.g., for IP Blinding).
2. **Browser Initiates Request:** The browser's network stack detects the need for a Privacy Pass token.
3. **`BlindSignAuth::GetTokens` is Called:**  The browser's networking code calls this function, likely with parameters indicating the desired number of tokens and the target service.
4. **Network Requests:**  `GetTokens` initiates a `GetInitialDataRequest` to the issuer.
5. **Callback Execution:**  The `GetInitialDataCallback` is executed upon receiving the response.
6. **Privacy Pass Flow:** If the response indicates Privacy Pass is to be used, `GeneratePrivacyPassTokens` is called.
7. **More Network Requests:** `GeneratePrivacyPassTokens` initiates an `AuthAndSignRequest`.
8. **Final Callback:** `PrivacyPassAuthAndSignCallback` is executed after receiving the signed tokens.
9. **Token Usage:** The obtained tokens are then used in subsequent network requests to the target website.

**Debugging Scenario:** If a user reports issues accessing a website and the logs show errors within `BlindSignAuth::PrivacyPassAuthAndSignCallback` related to signature validation, a developer could investigate the following:

* **Server-Side Issues:** Is the Privacy Pass issuer functioning correctly? Are the signatures being generated correctly?
* **Network Issues:** Are there network problems preventing the browser from reaching the issuer or the target website?
* **Configuration Errors:** Is the browser's Privacy Pass configuration correct? Are the correct issuer URLs being used?
* **Code Bugs:** Is there a bug in the C++ code itself that is causing incorrect token generation or validation?

By following these steps, we can systematically analyze the code, understand its function, and address all the points raised in the prompt. The key is to start with the big picture and then progressively delve into the details, making connections between different parts of the code and its interaction with the broader system (like JavaScript and network requests).
好的，我们来详细分析一下 `net/third_party/quiche/src/quiche/blind_sign_auth/blind_sign_auth.cc` 这个 Chromium 网络栈的源代码文件。

**文件功能概述:**

这个 C++ 文件 `blind_sign_auth.cc` 的主要功能是实现**盲签名认证 (Blind Sign Authentication)** 机制。更具体地说，它实现了 **Privacy Pass** 协议的客户端部分，用于获取匿名凭证 (tokens)。这些凭证可以用于证明用户执行了某些操作（例如，通过了 CAPTCHA），而无需透露用户的身份。

主要功能可以概括为：

1. **获取初始数据 (Get Initial Data):**  与认证服务器通信，获取进行盲签名所需的初始信息，例如服务器的公钥、元数据扩展等。这通过 `GetTokens` 方法发起，并使用 `GetInitialDataCallback` 处理响应。
2. **生成 Privacy Pass Tokens (Generate Privacy Pass Tokens):**  使用从服务器获取的公钥和元数据，以及本地生成的随机数，创建盲化的 token 请求。这个过程涉及到与 `anonymous_tokens` 库的交互，该库提供了 Privacy Pass 协议的底层实现。
3. **认证和签名请求 (Auth and Sign Request):** 将盲化的 token 请求发送到认证服务器进行签名。这通过 `PrivacyPassAuthAndSignCallback` 处理服务器的签名响应。
4. **完成 Token (Finalize Token):**  使用服务器返回的签名，结合本地的盲化信息，完成 Privacy Pass token 的生成。
5. **管理 Token 的生命周期:**  虽然代码本身没有显式地管理 token 的存储和使用，但其目的是生成可用于后续请求的 token。

**与 JavaScript 功能的关系及举例说明:**

这个 C++ 代码本身不直接包含 JavaScript 代码，但它提供的功能与浏览器中的 JavaScript 代码有密切关系。当用户在浏览器中与需要 Privacy Pass 认证的网站交互时，浏览器会使用这个 C++ 代码来获取必要的 token，然后将这些 token 嵌入到 HTTP 请求头中。

**举例说明:**

假设一个网站使用了 Privacy Pass 来防止机器人攻击。当用户访问这个网站时，可能会发生以下流程：

1. **JavaScript 触发:** 网站的 JavaScript 代码检测到用户需要提供 Privacy Pass 凭证。
2. **浏览器请求 Token:**  JavaScript 代码会通知浏览器的底层网络栈，需要获取 Privacy Pass token。
3. **C++ 代码介入:**  Chromium 的网络栈会调用 `BlindSignAuth::GetTokens` 函数，根据需要生成指定数量的 token。
4. **网络请求:** `BlindSignAuth` 类会发起与 Privacy Pass 认证服务器的通信（通过 `BlindSignMessageInterface`）。
5. **Token 返回:**  服务器返回签名后的 token。
6. **JavaScript 使用 Token:**  `BlindSignAuth` 类将生成的 token 返回给浏览器的网络栈，然后 JavaScript 代码可以将这些 token 添加到后续发送给网站的 HTTP 请求头中（例如，作为 `Sec-Privacy-Pass-Token` 头）。
7. **网站验证:** 网站的服务器会验证请求头中的 Privacy Pass token，以确认用户已通过验证。

**逻辑推理、假设输入与输出:**

**假设输入 (针对 `GeneratePrivacyPassTokens` 函数):**

* `initial_data_response`: 一个 `privacy::ppn::GetInitialDataResponse` 类型的对象，包含从认证服务器获取的公钥、元数据扩展等信息。
* `oauth_token`: 可选的 OAuth 令牌，用于身份验证。
* `num_tokens`: 需要生成的 token 数量，例如 `2`。
* `proxy_layer`:  指定使用的代理层，例如 `ProxyLayer::kProxyA`。
* `service_type`: 指定服务类型，例如 `BlindSignAuthServiceType::kChromeIpBlinding`。
* `callback`: 一个回调函数，用于处理生成的 token 或错误。

**逻辑推理过程:**

1. **解析公钥:** 从 `initial_data_response` 中解析 RSA 公钥。
2. **解析扩展:** 从 `initial_data_response` 中解析公共元数据扩展。
3. **创建 Token Challenge:**  创建一个用于生成 token 请求的 challenge。
4. **循环生成请求:**  循环 `num_tokens` 次：
   - 创建 `PrivacyPassRsaBssaPublicMetadataClient` 实例。
   - 生成随机数作为 nonce。
   - 调用客户端的 `CreateTokenRequest` 方法，创建盲化的 token 请求。
   - 将盲化的 token 添加到 `sign_request` 中。
5. **发送认证和签名请求:** 创建 `privacy::ppn::AuthAndSignRequest`，包含盲化的 token 和其他信息，并发送到认证服务器。
6. **处理签名响应:** 在 `PrivacyPassAuthAndSignCallback` 中接收服务器的签名。
7. **完成 Token:** 使用服务器的签名和本地信息，调用客户端的 `FinalizeToken` 方法，完成 token 的生成。
8. **调用回调:** 将生成的 `BlindSignToken` 对象传递给回调函数。

**假设输出 (通过 `callback` 返回):**

一个 `absl::Span<BlindSignToken>`，其中包含了 `num_tokens` 个 `BlindSignToken` 对象。每个 `BlindSignToken` 对象可能包含：

* 一个序列化的 `privacy::ppn::PrivacyPassTokenData` protobuf，其中包含最终的 token 和编码后的扩展信息。
* `public_key_expiry_time`: 公钥的过期时间。
* `geo_hint`: 地理位置提示信息。

**涉及用户或编程常见的使用错误及举例说明:**

1. **网络连接问题:** 用户的网络连接不稳定或无法连接到 Privacy Pass 认证服务器，导致无法获取初始数据或签名。
   * **例子:** 用户在网络环境差的地方浏览网页，导致 `GetInitialDataRequest` 或后续的 `AuthAndSignRequest` 超时或失败。

2. **服务器端错误:** Privacy Pass 认证服务器出现故障或返回错误响应，导致 token 生成失败。
   * **例子:** 认证服务器的公钥发生更改，但客户端没有及时更新，导致签名验证失败。

3. **OAuth 令牌无效或过期 (如果需要):**  如果获取 token 需要 OAuth 令牌，则提供无效或过期的令牌会导致认证失败。
   * **例子:** 用户的 Google 账号会话过期，导致提供的 OAuth 令牌无效。

4. **代码集成错误 (针对开发者):**  在集成 `BlindSignAuth` 类时，传递了错误的参数或没有正确处理回调函数。
   * **例子:** 开发者在调用 `GetTokens` 时，传递了错误的 `num_tokens` 值，或者没有正确处理回调函数返回的错误状态。

5. **依赖库版本不兼容:**  `BlindSignAuth` 依赖于其他库（如 `anonymous_tokens`），如果这些库的版本不兼容，可能会导致编译或运行时错误。
   * **例子:**  `anonymous_tokens` 库的 API 发生更改，但 `BlindSignAuth` 代码没有及时更新。

**用户操作如何一步步到达这里，作为调试线索:**

当开发者需要调试 `BlindSignAuth` 的相关功能时，可以通过以下用户操作来触发代码的执行：

1. **用户访问需要 Privacy Pass 的网站:** 这是最常见的触发场景。当用户访问一个集成了 Privacy Pass 的网站时，浏览器会自动尝试获取必要的 token。
2. **用户执行需要 Privacy Pass 验证的操作:**  例如，点击一个需要 Privacy Pass 验证的按钮，或者尝试访问受 Privacy Pass 保护的内容。
3. **开发者手动触发 (用于测试):** 开发者可以编写测试代码或使用特定的工具来模拟需要 Privacy Pass 的场景，从而直接调用 `BlindSignAuth` 的方法。

**作为调试线索:**

当出现与 Privacy Pass 相关的问题时，开发者可以关注以下线索：

* **网络请求日志:** 查看浏览器发出的网络请求，确认是否成功发起了与 Privacy Pass 认证服务器的连接，以及请求和响应的内容是否符合预期。重点关注 `GetInitialData` 和 `AuthAndSign` 相关的请求。
* **控制台输出 (Chromium 的内部日志):**  `QUICHE_LOG` 宏会输出日志信息，开发者可以通过配置 Chromium 的日志级别来查看 `BlindSignAuth` 相关的日志，了解代码的执行流程和遇到的错误。
* **断点调试:**  在 `BlindSignAuth` 的关键函数（例如 `GetTokens`, `GetInitialDataCallback`, `GeneratePrivacyPassTokens`, `PrivacyPassAuthAndSignCallback`）设置断点，逐步跟踪代码的执行，查看变量的值，分析问题的原因。
* **检查 Privacy Pass 的配置:**  确认浏览器中 Privacy Pass 的设置是否正确，例如是否启用了 Privacy Pass，以及相关的域名是否被允许使用 Privacy Pass。
* **错误回调:**  检查传递给 `GetTokens` 的回调函数是否被正确调用，以及回调函数接收到的错误信息，这些信息可以提供关于失败原因的线索。

总而言之，`net/third_party/quiche/src/quiche/blind_sign_auth/blind_sign_auth.cc` 文件是 Chromium 中实现 Privacy Pass 客户端功能的核心部分，它负责与认证服务器通信，生成和管理匿名凭证，以增强用户的隐私和安全性。理解其功能和可能的错误场景对于调试网络相关问题至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/blind_sign_auth/blind_sign_auth.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/blind_sign_auth/blind_sign_auth.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/functional/bind_front.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "anonymous_tokens/cpp/privacy_pass/rsa_bssa_public_metadata_client.h"
#include "anonymous_tokens/cpp/privacy_pass/token_encodings.h"
#include "anonymous_tokens/cpp/shared/proto_utils.h"
#include "quiche/blind_sign_auth/blind_sign_auth_interface.h"
#include "quiche/blind_sign_auth/blind_sign_auth_protos.h"
#include "quiche/blind_sign_auth/blind_sign_message_interface.h"
#include "quiche/blind_sign_auth/blind_sign_message_response.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_random.h"

namespace quiche {
namespace {

template <typename T>
std::string OmitDefault(T value) {
  return value == 0 ? "" : absl::StrCat(value);
}

constexpr absl::string_view kIssuerHostname =
    "https://ipprotection-ppissuer.googleapis.com";

}  // namespace

void BlindSignAuth::GetTokens(std::optional<std::string> oauth_token,
                              int num_tokens, ProxyLayer proxy_layer,
                              BlindSignAuthServiceType service_type,
                              SignedTokenCallback callback) {
  // Create GetInitialData RPC.
  privacy::ppn::GetInitialDataRequest request;
  request.set_use_attestation(false);
  request.set_service_type(BlindSignAuthServiceTypeToString(service_type));
  request.set_location_granularity(
      privacy::ppn::GetInitialDataRequest_LocationGranularity_CITY_GEOS);
  // Validation version must be 2 to use ProxyLayer.
  request.set_validation_version(2);
  request.set_proxy_layer(QuicheProxyLayerToPpnProxyLayer(proxy_layer));

  // Call GetInitialData on the BlindSignMessageInterface Fetcher.
  std::string body = request.SerializeAsString();
  BlindSignMessageCallback initial_data_callback = absl::bind_front(
      &BlindSignAuth::GetInitialDataCallback, this, oauth_token, num_tokens,
      proxy_layer, service_type, std::move(callback));
  fetcher_->DoRequest(BlindSignMessageRequestType::kGetInitialData, oauth_token,
                      body, std::move(initial_data_callback));
}

void BlindSignAuth::GetInitialDataCallback(
    std::optional<std::string> oauth_token, int num_tokens,
    ProxyLayer proxy_layer, BlindSignAuthServiceType service_type,
    SignedTokenCallback callback,
    absl::StatusOr<BlindSignMessageResponse> response) {
  if (!response.ok()) {
    QUICHE_LOG(WARNING) << "GetInitialDataRequest failed: "
                        << response.status();
    std::move(callback)(absl::InvalidArgumentError(
        "GetInitialDataRequest failed: invalid response"));
    return;
  }
  absl::StatusCode code = response->status_code();
  if (code != absl::StatusCode::kOk) {
    std::string message =
        absl::StrCat("GetInitialDataRequest failed with code: ", code);
    QUICHE_LOG(WARNING) << message;
    std::move(callback)(
        absl::InvalidArgumentError("GetInitialDataRequest failed"));
    return;
  }
  // Parse GetInitialDataResponse.
  privacy::ppn::GetInitialDataResponse initial_data_response;
  if (!initial_data_response.ParseFromString(response->body())) {
    QUICHE_LOG(WARNING) << "Failed to parse GetInitialDataResponse";
    std::move(callback)(
        absl::InternalError("Failed to parse GetInitialDataResponse"));
    return;
  }

  // Create token signing requests.
  bool use_privacy_pass_client =
      initial_data_response.has_privacy_pass_data() &&
      auth_options_.enable_privacy_pass();

  if (use_privacy_pass_client) {
    QUICHE_DVLOG(1) << "Using Privacy Pass client";
    GeneratePrivacyPassTokens(initial_data_response, std::move(oauth_token),
                              num_tokens, proxy_layer, service_type,
                              std::move(callback));
  } else {
    QUICHE_LOG(ERROR) << "Non-Privacy Pass tokens are no longer supported";
    std::move(callback)(absl::UnimplementedError(
        "Non-Privacy Pass tokens are no longer supported"));
  }
}

void BlindSignAuth::GeneratePrivacyPassTokens(
    privacy::ppn::GetInitialDataResponse initial_data_response,
    std::optional<std::string> oauth_token, int num_tokens,
    ProxyLayer proxy_layer, BlindSignAuthServiceType service_type,
    SignedTokenCallback callback) {
  // Set up values used in the token generation loop.
  anonymous_tokens::RSAPublicKey public_key_proto;
  if (!public_key_proto.ParseFromString(
          initial_data_response.at_public_metadata_public_key()
              .serialized_public_key())) {
    std::move(callback)(
        absl::InvalidArgumentError("Failed to parse Privacy Pass public key"));
    return;
  }
  absl::StatusOr<bssl::UniquePtr<RSA>> bssl_rsa_key =
      anonymous_tokens::CreatePublicKeyRSA(
          public_key_proto.n(), public_key_proto.e());
  if (!bssl_rsa_key.ok()) {
    QUICHE_LOG(ERROR) << "Failed to create RSA public key: "
                      << bssl_rsa_key.status();
    std::move(callback)(absl::InternalError("Failed to create RSA public key"));
    return;
  }
  absl::StatusOr<anonymous_tokens::Extensions> extensions =
      anonymous_tokens::DecodeExtensions(
          initial_data_response.privacy_pass_data()
              .public_metadata_extensions());
  if (!extensions.ok()) {
    QUICHE_LOG(WARNING) << "Failed to decode extensions: "
                        << extensions.status();
    std::move(callback)(
        absl::InvalidArgumentError("Failed to decode extensions"));
    return;
  }
  std::vector<uint16_t> kExpectedExtensionTypes = {
      /*ExpirationTimestamp=*/0x0001, /*GeoHint=*/0x0002,
      /*ServiceType=*/0xF001, /*DebugMode=*/0xF002, /*ProxyLayer=*/0xF003};
  // TODO(b/345801768): Improve the API of
  // `anonymous_tokens::ValidateExtensionsOrderAndValues` to
  // avoid any possible TOCTOU problems.
  absl::Status result =
      anonymous_tokens::ValidateExtensionsOrderAndValues(
          *extensions, absl::MakeSpan(kExpectedExtensionTypes), absl::Now());
  if (!result.ok()) {
    QUICHE_LOG(WARNING) << "Failed to validate extensions: " << result;
    std::move(callback)(
        absl::InvalidArgumentError("Failed to validate extensions"));
    return;
  }
  absl::StatusOr<anonymous_tokens::ExpirationTimestamp>
      expiration_timestamp = anonymous_tokens::
          ExpirationTimestamp::FromExtension(extensions->extensions.at(0));
  if (!expiration_timestamp.ok()) {
    QUICHE_LOG(WARNING) << "Failed to parse expiration timestamp: "
                        << expiration_timestamp.status();
    std::move(callback)(
        absl::InvalidArgumentError("Failed to parse expiration timestamp"));
    return;
  }
  absl::Time public_metadata_expiry_time =
      absl::FromUnixSeconds(expiration_timestamp->timestamp);

  absl::StatusOr<anonymous_tokens::GeoHint> geo_hint =
      anonymous_tokens::GeoHint::FromExtension(
          extensions->extensions.at(1));
  QUICHE_CHECK(geo_hint.ok());

  // Create token challenge.
  anonymous_tokens::TokenChallenge challenge;
  challenge.issuer_name = kIssuerHostname;
  absl::StatusOr<std::string> token_challenge =
      anonymous_tokens::MarshalTokenChallenge(challenge);
  if (!token_challenge.ok()) {
    QUICHE_LOG(WARNING) << "Failed to marshal token challenge: "
                        << token_challenge.status();
    std::move(callback)(
        absl::InvalidArgumentError("Failed to marshal token challenge"));
    return;
  }

  QuicheRandom* random = QuicheRandom::GetInstance();
  // Create vector of Privacy Pass clients, one for each token.
  std::vector<anonymous_tokens::ExtendedTokenRequest>
      extended_token_requests;
  std::vector<std::unique_ptr<anonymous_tokens::
                                  PrivacyPassRsaBssaPublicMetadataClient>>
      privacy_pass_clients;
  std::vector<std::string> privacy_pass_blinded_tokens;

  for (int i = 0; i < num_tokens; i++) {
    // Create client.
    auto client = anonymous_tokens::
        PrivacyPassRsaBssaPublicMetadataClient::Create(*bssl_rsa_key.value());
    if (!client.ok()) {
      QUICHE_LOG(WARNING) << "Failed to create Privacy Pass client: "
                          << client.status();
      std::move(callback)(
          absl::InternalError("Failed to create Privacy Pass client"));
      return;
    }

    // Create nonce.
    std::string nonce_rand(32, '\0');
    random->RandBytes(nonce_rand.data(), nonce_rand.size());

    // Create token request.
    absl::StatusOr<anonymous_tokens::ExtendedTokenRequest>
        extended_token_request = client.value()->CreateTokenRequest(
            *token_challenge, nonce_rand,
            initial_data_response.privacy_pass_data().token_key_id(),
            *extensions);
    if (!extended_token_request.ok()) {
      QUICHE_LOG(WARNING) << "Failed to create ExtendedTokenRequest: "
                          << extended_token_request.status();
      std::move(callback)(
          absl::InternalError("Failed to create ExtendedTokenRequest"));
      return;
    }
    privacy_pass_clients.push_back(*std::move(client));
    extended_token_requests.push_back(*extended_token_request);
    privacy_pass_blinded_tokens.push_back(absl::Base64Escape(
        extended_token_request->request.blinded_token_request));
  }

  privacy::ppn::AuthAndSignRequest sign_request;
  sign_request.set_service_type(BlindSignAuthServiceTypeToString(service_type));
  sign_request.set_key_type(privacy::ppn::AT_PUBLIC_METADATA_KEY_TYPE);
  sign_request.set_key_version(
      initial_data_response.at_public_metadata_public_key().key_version());
  sign_request.mutable_blinded_token()->Assign(
      privacy_pass_blinded_tokens.begin(), privacy_pass_blinded_tokens.end());
  sign_request.mutable_public_metadata_extensions()->assign(
      initial_data_response.privacy_pass_data().public_metadata_extensions());
  // TODO(b/295924807): deprecate this option after AT server defaults to it
  sign_request.set_do_not_use_rsa_public_exponent(true);
  sign_request.set_proxy_layer(QuicheProxyLayerToPpnProxyLayer(proxy_layer));

  absl::StatusOr<anonymous_tokens::AnonymousTokensUseCase>
      use_case = anonymous_tokens::ParseUseCase(
          initial_data_response.at_public_metadata_public_key().use_case());
  if (!use_case.ok()) {
    QUICHE_LOG(WARNING) << "Failed to parse use case: " << use_case.status();
    std::move(callback)(absl::InvalidArgumentError("Failed to parse use case"));
    return;
  }

  BlindSignMessageCallback auth_and_sign_callback =
      absl::bind_front(&BlindSignAuth::PrivacyPassAuthAndSignCallback, this,
                       std::move(initial_data_response.privacy_pass_data()
                                     .public_metadata_extensions()),
                       public_metadata_expiry_time, *geo_hint, *use_case,
                       std::move(privacy_pass_clients), std::move(callback));
  // TODO(b/304811277): remove other usages of string.data()
  fetcher_->DoRequest(BlindSignMessageRequestType::kAuthAndSign, oauth_token,
                      sign_request.SerializeAsString(),
                      std::move(auth_and_sign_callback));
}

void BlindSignAuth::PrivacyPassAuthAndSignCallback(
    std::string encoded_extensions, absl::Time public_key_expiry_time,
    anonymous_tokens::GeoHint geo_hint,
    anonymous_tokens::AnonymousTokensUseCase use_case,
    std::vector<std::unique_ptr<anonymous_tokens::
                                    PrivacyPassRsaBssaPublicMetadataClient>>
        privacy_pass_clients,
    SignedTokenCallback callback,
    absl::StatusOr<BlindSignMessageResponse> response) {
  // Validate response.
  if (!response.ok()) {
    QUICHE_LOG(WARNING) << "AuthAndSign failed: " << response.status();
    std::move(callback)(
        absl::InvalidArgumentError("AuthAndSign failed: invalid response"));
    return;
  }
  absl::StatusCode code = response->status_code();
  if (code != absl::StatusCode::kOk) {
    std::string message = absl::StrCat("AuthAndSign failed with code: ", code);
    QUICHE_LOG(WARNING) << message;
    std::move(callback)(absl::InvalidArgumentError("AuthAndSign failed"));
    return;
  }

  // Decode AuthAndSignResponse.
  privacy::ppn::AuthAndSignResponse sign_response;
  if (!sign_response.ParseFromString(response->body())) {
    QUICHE_LOG(WARNING) << "Failed to parse AuthAndSignResponse";
    std::move(callback)(
        absl::InternalError("Failed to parse AuthAndSignResponse"));
    return;
  }
  if (static_cast<size_t>(sign_response.blinded_token_signature_size()) !=
      privacy_pass_clients.size()) {
    QUICHE_LOG(WARNING) << "Number of signatures does not equal number of "
                           "Privacy Pass tokens sent";
    std::move(callback)(
        absl::InternalError("Number of signatures does not equal number of "
                            "Privacy Pass tokens sent"));
    return;
  }

  // Create tokens using blinded signatures.
  std::vector<BlindSignToken> tokens_vec;
  for (int i = 0; i < sign_response.blinded_token_signature_size(); i++) {
    std::string unescaped_blinded_sig;
    if (!absl::Base64Unescape(sign_response.blinded_token_signature()[i],
                              &unescaped_blinded_sig)) {
      QUICHE_LOG(WARNING) << "Failed to unescape blinded signature";
      std::move(callback)(
          absl::InternalError("Failed to unescape blinded signature"));
      return;
    }

    absl::StatusOr<anonymous_tokens::Token> token =
        privacy_pass_clients[i]->FinalizeToken(unescaped_blinded_sig);
    if (!token.ok()) {
      QUICHE_LOG(WARNING) << "Failed to finalize token: " << token.status();
      std::move(callback)(absl::InternalError("Failed to finalize token"));
      return;
    }

    absl::StatusOr<std::string> marshaled_token =
        anonymous_tokens::MarshalToken(*token);
    if (!marshaled_token.ok()) {
      QUICHE_LOG(WARNING) << "Failed to marshal token: "
                          << marshaled_token.status();
      std::move(callback)(absl::InternalError("Failed to marshal token"));
      return;
    }

    privacy::ppn::PrivacyPassTokenData privacy_pass_token_data;
    privacy_pass_token_data.mutable_token()->assign(
        ConvertBase64ToWebSafeBase64(absl::Base64Escape(*marshaled_token)));
    privacy_pass_token_data.mutable_encoded_extensions()->assign(
        ConvertBase64ToWebSafeBase64(absl::Base64Escape(encoded_extensions)));
    privacy_pass_token_data.set_use_case_override(use_case);
    tokens_vec.push_back(
        BlindSignToken{privacy_pass_token_data.SerializeAsString(),
                       public_key_expiry_time, geo_hint});
  }

  std::move(callback)(absl::Span<BlindSignToken>(tokens_vec));
}

privacy::ppn::ProxyLayer BlindSignAuth::QuicheProxyLayerToPpnProxyLayer(
    quiche::ProxyLayer proxy_layer) {
  switch (proxy_layer) {
    case ProxyLayer::kProxyA: {
      return privacy::ppn::ProxyLayer::PROXY_A;
    }
    case ProxyLayer::kProxyB: {
      return privacy::ppn::ProxyLayer::PROXY_B;
    }
  }
}

std::string BlindSignAuth::ConvertBase64ToWebSafeBase64(
    std::string base64_string) {
  absl::c_replace(base64_string, /*old_value=*/'+', /*new_value=*/'-');
  absl::c_replace(base64_string, /*old_value=*/'/', /*new_value=*/'_');
  return base64_string;
}

std::string BlindSignAuthServiceTypeToString(
    quiche::BlindSignAuthServiceType service_type) {
  switch (service_type) {
    case BlindSignAuthServiceType::kChromeIpBlinding: {
      return "chromeipblinding";
    }
    case BlindSignAuthServiceType::kCronetIpBlinding: {
      return "cronetipblinding";
    }
    case BlindSignAuthServiceType::kWebviewIpBlinding: {
      // Currently WebView uses the same service type as Chrome.
      // TODO(b/280621504): Change this once we have a more specific service
      // type.
      return "chromeipblinding";
    }
  }
}

}  // namespace quiche

"""

```