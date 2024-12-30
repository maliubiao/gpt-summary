Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Goal:**

The user wants to understand the functionality of `registration_fetcher.cc`, specifically within the context of Chromium's networking stack. They are also interested in its relationship with JavaScript, potential logic, common errors, and how a user's action might lead to this code being executed.

**2. Initial Code Scan and Identification of Key Components:**

My first step is to quickly scan the code to identify the main players and their roles. I look for:

* **Class Names:** `RegistrationFetcher`, `RegistrationFetcherImpl`, `RegistrationCompleteParams`
* **Key Functions:** `StartCreateTokenAndFetch`, `StartFetchWithExistingKey`, `Start`, `OnResponseStarted`, `OnReadCompleted`, `OnChallengeNeeded`, `OnRegistrationTokenCreated`
* **Data Structures:** `RegistrationFetcherParam`, `SessionParams`, `RegistrationTokenResult`, `SessionChallengeParam`
* **Network Related Elements:** `URLRequest`, `URLRequestContext`, `IsolationInfo`, `HttpResponseHeaders`, `NetworkTrafficAnnotationTag`
* **Cryptographic Elements:** `unexportable_keys::UnexportableKeyService`, `crypto::SignatureVerifier`
* **Constants:** Header names (`Sec-Session-Id`, `Sec-Session-Response`), buffer size, task priority
* **Namespaces:** `net::device_bound_sessions`

This initial scan gives me a high-level overview of the code's purpose. It's clearly involved in fetching something related to "device-bound sessions" and uses cryptographic keys.

**3. Deconstructing the Workflow (The "Happy Path"):**

Next, I try to piece together the normal execution flow of the code. I focus on the main entry points and how the data flows.

* **`StartCreateTokenAndFetch`:** This looks like the primary entry point. It takes parameters, including supported cryptographic algorithms, and calls `key_service.GenerateSigningKeySlowlyAsync`. This suggests it's starting the process by either creating a new key or using an existing one.
* **`StartFetchWithExistingKey`:** This function is called after the key generation (or if an existing key is used). It creates a `RegistrationFetcherImpl` object.
* **`RegistrationFetcherImpl::Start`:** This function initiates the network request. It can either start a request to get a challenge or, if a challenge is already provided, it signs the challenge and then starts the request.
* **Network Request Flow (`RegistrationFetcherImpl` as `URLRequest::Delegate`):**  The standard `URLRequest` delegate methods (`OnReceivedRedirect`, `OnResponseStarted`, `OnReadCompleted`) handle the network communication.
* **Challenge Handling (`OnChallengeNeeded`):**  If the server responds with a 401 and a `Sec-Session-Registration` header, `OnChallengeNeeded` is called. It extracts the challenge, signs it, and retries the request.
* **Response Processing (`OnResponseCompleted`):** When the response is fully received, the code parses the JSON data (`ParseSessionInstructionJson`) and calls the final callback.

**4. Identifying Key Responsibilities:**

Based on the workflow, I can now identify the key responsibilities of this code:

* **Initiating and managing network requests:** Fetching data from a specified endpoint.
* **Handling server challenges:**  Responding to 401 Unauthorized responses with a signed challenge.
* **Generating and using cryptographic keys:** Interacting with the `unexportable_keys` service to sign data.
* **Parsing server responses:** Processing the JSON payload from the server.
* **Invoking a callback:** Notifying the caller about the success or failure of the registration process.

**5. Addressing Specific Questions from the User:**

Now, I go through the user's specific questions and relate them to the code I've analyzed:

* **Functionality:** I summarize the core responsibilities identified in the previous step.
* **JavaScript Relationship:** I look for interactions with web standards or browser APIs that might be exposed to JavaScript. The "Device Bound Session Credentials API" mentioned in the traffic annotation is a strong clue. I explain how JavaScript could trigger this flow (e.g., a website sending a `Sec-Session-Registration` header).
* **Logic and Input/Output:** I devise a simplified scenario (no initial session ID, server sends a challenge) and trace the execution flow, outlining the key input and output at each step.
* **User/Programming Errors:** I consider common pitfalls, such as incorrect server configuration (missing headers, wrong responses), and errors related to the `unexportable_keys` service.
* **User Actions and Debugging:** I describe the user actions that would lead to this code being executed (visiting a website, the server initiating the DBSC flow). I suggest debugging techniques like network inspection and looking for specific headers.

**6. Refining and Organizing the Answer:**

Finally, I structure the answer logically, using clear headings and bullet points. I ensure the language is accessible and avoids overly technical jargon where possible. I double-check that I've addressed all aspects of the user's request.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `RegistrationFetcher` directly makes the network request.
* **Correction:** Realized that `RegistrationFetcherImpl` is the actual `URLRequest::Delegate`, handling the network interaction.
* **Initial thought:** The key generation might happen synchronously.
* **Correction:** Noticed the use of `...SlowlyAsync`, indicating asynchronous key operations. This is important for understanding the non-blocking nature of the process.
* **Double-checking assumptions:**  Ensured I correctly interpreted the meaning of the header names and the purpose of the traffic annotation.

By following this systematic approach, I can effectively analyze the code and provide a comprehensive and informative answer to the user's request. The process involves understanding the overall purpose, dissecting the workflow, identifying key components, and then specifically addressing the user's questions with relevant examples and explanations.
这个文件 `net/device_bound_sessions/registration_fetcher.cc` 是 Chromium 网络栈中负责**获取设备绑定会话凭据注册令牌**的核心组件。 它的主要功能是：

1. **发起网络请求以完成设备绑定会话凭据的注册流程。**  当服务器通过 `Sec-Session-Registration` 响应头指示需要进行设备绑定会话注册时，浏览器会使用这个组件与服务器进行通信。
2. **处理服务器的质询 (Challenge)。** 如果服务器返回 401 状态码并提供质询，`RegistrationFetcher` 负责使用本地设备上的密钥对质询进行签名。
3. **与 `unexportable_keys::UnexportableKeyService` 交互。** 它利用 `UnexportableKeyService` 来生成新的非导出密钥，或者使用已有的密钥来签署质询。这些密钥与特定的设备绑定会话相关联。
4. **构建并发送带有注册信息的请求。**  它会构建包含会话 ID 和签名后的质询的 HTTP 请求头 (`Sec-Session-Id`, `Sec-Session-Response`) 发送到服务器。
5. **解析服务器的响应。**  一旦注册成功，它会解析服务器返回的 JSON 格式的会话参数 (`SessionParams`)。
6. **管理网络请求的生命周期。** 它作为 `URLRequest::Delegate` 处理网络请求的各个阶段，包括重定向、错误处理和数据读取。

**与 JavaScript 功能的关系：**

`registration_fetcher.cc` 本身是用 C++ 编写的，直接与 JavaScript 没有代码层面的交互。然而，它的功能是响应来自 Web 内容（通过 JavaScript 发起的网络请求）的服务器指示。

**举例说明：**

1. **服务器发送 `Sec-Session-Registration` 头：**  当用户访问一个支持设备绑定会话的网站时，服务器可能会在响应某个 JavaScript 发起的请求时包含 `Sec-Session-Registration` 响应头。这个头会指示浏览器需要进行设备绑定会话的注册。
2. **浏览器内部触发：** 浏览器解析到这个响应头后，会触发网络栈的相应逻辑，最终导致 `RegistrationFetcher::StartCreateTokenAndFetch` 或 `RegistrationFetcher::StartFetchWithExistingKey` 被调用。
3. **无需直接 JavaScript 调用：**  JavaScript 代码本身通常不需要直接调用或知道 `registration_fetcher.cc` 的存在。它的作用是发起网络请求，服务器的响应会间接地触发 C++ 层的逻辑。

**逻辑推理 (假设输入与输出)：**

**假设输入：**

* **注册端点 URL：** `https://example.com/register-session`
* **支持的算法：**  `[ECDSA_SHA256, RSA_PKCS1_SHA256]`
* **服务器返回的 `Sec-Session-Registration` 头包含一个质询：**  `challenge_value`
* **已有的会话 ID (可选):** `existing_session_id`

**输出：**

1. **如果注册成功：**
   * `RegistrationCompleteCallback` 会被调用，参数 `params` 包含：
     * `SessionParams`：从服务器响应中解析出的会话参数（例如，会话过期时间等）。
     * `key_id`：用于此会话的非导出密钥的 ID。
     * `url`：注册端点的 URL。
     * `referral_session_identifier` (可选)：如果注册是基于现有会话进行的。
2. **如果注册失败：**
   * `RegistrationCompleteCallback` 会被调用，参数 `params` 为 `std::nullopt`。

**用户或编程常见的使用错误：**

1. **服务器配置错误：**
   * **缺少 `Sec-Session-Registration` 头：** 服务器应该在需要注册时发送此头，否则浏览器不会尝试进行注册。
   * **错误的质询格式：**  如果服务器提供的质询格式不符合预期，解析会失败。
   * **注册端点不可访问或返回错误状态码：**  例如，返回 404 或 500 错误，导致注册失败。
   * **服务器没有正确验证签名后的质询：**  如果服务器期望的签名方式或内容与浏览器发送的不同，注册会失败。
2. **`unexportable_keys::UnexportableKeyService` 的问题：**
   * **密钥生成失败：**  在某些情况下，密钥服务可能无法生成新的密钥。
   * **密钥签名失败：**  密钥服务可能无法使用指定的密钥签署质询。
3. **网络问题：**
   * **网络连接中断：**  导致请求无法发送或接收。
   * **DNS 解析失败：**  无法找到注册端点的 IP 地址。
   * **SSL/TLS 错误：**  无法建立安全的连接。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户访问一个网站：** 用户在浏览器中输入网址或点击链接，访问一个可能使用设备绑定会话的网站。
2. **网站的服务器响应包含 `Sec-Session-Registration` 头：**  网站的服务器在响应用户请求（例如，加载页面资源或执行 API 调用）时，可能会在 HTTP 响应头中包含 `Sec-Session-Registration`。这通常发生在服务器决定需要为用户的当前设备创建一个绑定的会话时。
3. **浏览器网络栈解析响应头：** Chromium 的网络栈接收到服务器的响应，并解析 HTTP 响应头。
4. **发现 `Sec-Session-Registration` 头：** 网络栈的代码检测到 `Sec-Session-Registration` 头，并识别出需要进行设备绑定会话的注册。
5. **创建 `RegistrationFetcher` 实例：**  网络栈会创建 `RegistrationFetcher` 的实例，并传入必要的参数，例如注册端点的 URL 和支持的签名算法。
6. **`StartCreateTokenAndFetch` 或 `StartFetchWithExistingKey` 被调用：**  根据是否需要生成新的密钥，相应的启动函数会被调用。
7. **如果需要质询，发起初始请求：**  如果 `Sec-Session-Registration` 头中包含质询，或者需要先从服务器获取质询，`RegistrationFetcherImpl` 会创建一个 `URLRequest` 并发送到注册端点。
8. **处理服务器的响应 (包括 401 和质询)：**  `RegistrationFetcherImpl` 作为 `URLRequest::Delegate` 接收服务器的响应。如果收到 401 状态码和质询，它会使用 `unexportable_keys::UnexportableKeyService` 对质询进行签名。
9. **发送带有签名质询的请求：**  创建一个新的 `URLRequest`，并在请求头中包含签名后的质询 (`Sec-Session-Response`) 和可能的会话 ID (`Sec-Session-Id`)。
10. **接收成功响应并解析会话参数：**  如果服务器验证了签名并成功注册了会话，它会返回 2xx 状态码和包含会话参数的 JSON 数据。`RegistrationFetcherImpl` 解析这些数据。
11. **调用 `RegistrationCompleteCallback`：**  最终，无论注册成功还是失败，都会调用事先注册的回调函数，将结果传递给调用者。

**调试线索：**

* **抓包分析：** 使用 Wireshark 或 Chrome 的开发者工具 (Network 选项卡) 检查与注册端点的 HTTP 请求和响应头。查看是否存在 `Sec-Session-Registration`，`Sec-Session-Id`，`Sec-Session-Response` 等头信息，以及请求和响应的内容。
* **Chrome 内部日志：**  启用 Chromium 的网络日志 (可以通过 `chrome://net-export/` 或命令行参数) 可以查看更详细的网络请求过程，包括错误信息。
* **断点调试：** 如果有 Chromium 的调试构建，可以在 `registration_fetcher.cc` 中设置断点，跟踪代码的执行流程，查看变量的值，例如质询内容、签名结果等。
* **检查 `unexportable_keys` 服务：**  如果怀疑密钥生成或签名有问题，可以查看与 `unexportable_keys::UnexportableKeyService` 相关的日志或进行断点调试。

总而言之，`registration_fetcher.cc` 在 Chromium 的设备绑定会话机制中扮演着关键的角色，它负责与服务器进行注册流程的交互，利用本地密钥进行身份验证，并最终获取用于后续会话的凭据。它虽然不直接被 JavaScript 调用，但其功能是响应 Web 内容发起的请求，是 Web 安全特性的一部分。

Prompt: 
```
这是目录为net/device_bound_sessions/registration_fetcher.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/device_bound_sessions/registration_fetcher.h"

#include <memory>
#include <utility>
#include <vector>

#include "components/unexportable_keys/background_task_priority.h"
#include "components/unexportable_keys/unexportable_key_service.h"
#include "net/base/io_buffer.h"
#include "net/device_bound_sessions/registration_request_param.h"
#include "net/device_bound_sessions/session_binding_utils.h"
#include "net/device_bound_sessions/session_challenge_param.h"
#include "net/device_bound_sessions/session_json_utils.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"

namespace net::device_bound_sessions {

namespace {

constexpr char kSessionIdHeaderName[] = "Sec-Session-Id";
constexpr char kJwtSessionHeaderName[] = "Sec-Session-Response";
constexpr net::NetworkTrafficAnnotationTag kRegistrationTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("dbsc_registration", R"(
        semantics {
          sender: "Device Bound Session Credentials API"
          description:
            "Device Bound Session Credentials (DBSC) let a server create a "
            "session with the local device. For more info see "
            "https://github.com/WICG/dbsc."
          trigger:
            "Server sending a response with a Sec-Session-Registration header."
          data: "A signed JWT with the new key created for this session."
          destination: WEBSITE
          last_reviewed: "2024-04-10"
          user_data {
            type: ACCESS_TOKEN
          }
          internal {
            contacts {
              email: "kristianm@chromium.org"
            }
            contacts {
              email: "chrome-counter-abuse-alerts@google.com"
            }
          }
        }
        policy {
          cookies_allowed: YES
          cookies_store: "user"
          setting: "There is no separate setting for this feature, but it will "
            "follow the cookie settings."
          policy_exception_justification: "Not implemented."
        })");

constexpr int kBufferSize = 4096;

// New session registration doesn't block the user and can be done with a delay.
constexpr unexportable_keys::BackgroundTaskPriority kTaskPriority =
    unexportable_keys::BackgroundTaskPriority::kBestEffort;

void OnDataSigned(
    crypto::SignatureVerifier::SignatureAlgorithm algorithm,
    unexportable_keys::UnexportableKeyService& unexportable_key_service,
    std::string header_and_payload,
    unexportable_keys::UnexportableKeyId key_id,
    base::OnceCallback<void(
        std::optional<RegistrationFetcher::RegistrationTokenResult>)> callback,
    unexportable_keys::ServiceErrorOr<std::vector<uint8_t>> result) {
  if (!result.has_value()) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  const std::vector<uint8_t>& signature = result.value();
  std::optional<std::string> registration_token =
      AppendSignatureToHeaderAndPayload(header_and_payload, algorithm,
                                        signature);
  if (!registration_token.has_value()) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  std::move(callback).Run(RegistrationFetcher::RegistrationTokenResult(
      registration_token.value(), key_id));
}

void SignChallengeWithKey(
    unexportable_keys::UnexportableKeyService& unexportable_key_service,
    unexportable_keys::UnexportableKeyId& key_id,
    const GURL& registration_url,
    std::string_view challenge,
    std::optional<std::string> authorization,
    base::OnceCallback<
        void(std::optional<RegistrationFetcher::RegistrationTokenResult>)>
        callback) {
  auto expected_algorithm = unexportable_key_service.GetAlgorithm(key_id);
  auto expected_public_key =
      unexportable_key_service.GetSubjectPublicKeyInfo(key_id);
  if (!expected_algorithm.has_value() || !expected_public_key.has_value()) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  std::optional<std::string> optional_header_and_payload =
      CreateKeyRegistrationHeaderAndPayload(
          challenge, registration_url, expected_algorithm.value(),
          expected_public_key.value(), base::Time::Now(),
          std::move(authorization));

  if (!optional_header_and_payload.has_value()) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  std::string header_and_payload =
      std::move(optional_header_and_payload.value());
  unexportable_key_service.SignSlowlyAsync(
      key_id, base::as_bytes(base::make_span(header_and_payload)),
      kTaskPriority,
      base::BindOnce(&OnDataSigned, expected_algorithm.value(),
                     std::ref(unexportable_key_service),
                     std::move(header_and_payload), key_id,
                     std::move(callback)));
}

class RegistrationFetcherImpl : public URLRequest::Delegate {
 public:
  // URLRequest::Delegate

  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override {
    if (!redirect_info.new_url.SchemeIsCryptographic()) {
      request->Cancel();
      OnResponseCompleted();
      // *this is deleted here
    }
  }

  // TODO(kristianm): Look into if OnAuthRequired might need to be customize
  // for DBSC

  // TODO(kristianm): Think about what to do for DBSC with
  // OnCertificateRequested, leaning towards not supporting it but not sure.

  // Always cancel requests on SSL errors, this is the default implementation
  // of OnSSLCertificateError.

  // This is always called unless the request is deleted before it is called.
  void OnResponseStarted(URLRequest* request, int net_error) override {
    if (net_error != OK) {
      OnResponseCompleted();
      // *this is deleted here
      return;
    }

    HttpResponseHeaders* headers = request->response_headers();
    const int response_code = headers ? headers->response_code() : 0;

    if (response_code == 401) {
      auto challenge_params =
          device_bound_sessions::SessionChallengeParam::CreateIfValid(
              fetcher_endpoint_, headers);
      OnChallengeNeeded(std::move(challenge_params));
      // *this is preserved here.
      return;
    }

    if (response_code < 200 || response_code >= 300) {
      OnResponseCompleted();
      // *this is deleted here
      return;
    }

    // Initiate the first read.
    int bytes_read = request->Read(buf_.get(), kBufferSize);
    if (bytes_read >= 0) {
      OnReadCompleted(request, bytes_read);
    } else if (bytes_read != ERR_IO_PENDING) {
      OnResponseCompleted();
      // *this is deleted here
    }
  }

  void OnReadCompleted(URLRequest* request, int bytes_read) override {
    data_received_.append(buf_->data(), bytes_read);
    while (bytes_read > 0) {
      bytes_read = request->Read(buf_.get(), kBufferSize);
      if (bytes_read > 0) {
        data_received_.append(buf_->data(), bytes_read);
      }
    }

    if (bytes_read != ERR_IO_PENDING) {
      OnResponseCompleted();
      // *this is deleted here
    }
  }

  RegistrationFetcherImpl(
      const GURL& fetcher_endpoint,
      std::optional<std::string> session_identifier,
      unexportable_keys::UnexportableKeyService& key_service,
      const unexportable_keys::UnexportableKeyId& key_id,
      const URLRequestContext* context,
      const IsolationInfo& isolation_info,
      RegistrationFetcher::RegistrationCompleteCallback callback)
      : fetcher_endpoint_(fetcher_endpoint),
        session_identifier_(std::move(session_identifier)),
        key_service_(key_service),
        key_id_(key_id),
        context_(context),
        isolation_info_(isolation_info),
        callback_(std::move(callback)),
        buf_(base::MakeRefCounted<IOBufferWithSize>(kBufferSize)) {}

  ~RegistrationFetcherImpl() override { CHECK(!callback_); }

  void Start(std::optional<std::string> challenge,
             std::optional<std::string> authorization) {
    if (challenge.has_value()) {
      SignChallengeWithKey(
          *key_service_, key_id_, fetcher_endpoint_, *challenge,
          std::move(authorization),
          base::BindOnce(&RegistrationFetcherImpl::OnRegistrationTokenCreated,
                         base::Unretained(this)));
      return;
    }

    // Start a request to get a challenge with the session identifier.
    // `RegistrationRequestParam::Create` guarantees `session_identifier_` is
    // set when `challenge_` is missing.
    if (session_identifier_.has_value()) {
      request_ = CreateBaseRequest();
      request_->Start();
    }
  }

 private:
  void OnRegistrationTokenCreated(
      std::optional<RegistrationFetcher::RegistrationTokenResult> result) {
    if (!result) {
      RunCallbackAndDeleteSelf(std::nullopt);
      return;
    }

    request_ = CreateBaseRequest();
    request_->SetExtraRequestHeaderByName(
        kJwtSessionHeaderName, result->registration_token, /*overwrite*/ true);
    request_->Start();
  }

  std::unique_ptr<net::URLRequest> CreateBaseRequest() {
    std::unique_ptr<net::URLRequest> request = context_->CreateRequest(
        fetcher_endpoint_, IDLE, this, kRegistrationTrafficAnnotation);
    request->set_method("POST");
    request->SetLoadFlags(LOAD_DISABLE_CACHE);
    request->set_allow_credentials(true);

    request->set_site_for_cookies(isolation_info_.site_for_cookies());
    // TODO(kristianm): Set initiator to the URL of the registration header.
    request->set_initiator(url::Origin());
    request->set_isolation_info(isolation_info_);

    if (session_identifier_.has_value()) {
      request->SetExtraRequestHeaderByName(
          kSessionIdHeaderName, *session_identifier_, /*overwrite*/ true);
    }

    return request;
  }

  void OnChallengeNeeded(
      std::optional<std::vector<SessionChallengeParam>> challenge_params) {
    if (!challenge_params || challenge_params->empty()) {
      RunCallbackAndDeleteSelf(std::nullopt);
      return;
    }

    // TODO(kristianm): Log if there is more than one challenge
    // TODO(kristianm): Handle if session identifiers don't match
    const std::string& challenge = (*challenge_params)[0].challenge();
    Start(challenge, std::nullopt);
  }

  void OnResponseCompleted() {
    if (!data_received_.empty()) {
      std::optional<SessionParams> params =
          ParseSessionInstructionJson(data_received_);
      if (params) {
        RunCallbackAndDeleteSelf(
            std::make_optional<RegistrationFetcher::RegistrationCompleteParams>(
                std::move(*params), key_id_, request_->url(),
                std::move(session_identifier_)));
        return;
      }
    }

    RunCallbackAndDeleteSelf(std::nullopt);
  }

  // Running callback when fetching is complete or on error.
  // Deletes `this` afterwards.
  void RunCallbackAndDeleteSelf(
      std::optional<RegistrationFetcher::RegistrationCompleteParams> params) {
    std::move(callback_).Run(std::move(params));
    delete this;
  }

  // State passed in to constructor
  GURL fetcher_endpoint_;
  std::optional<std::string> session_identifier_;
  const raw_ref<unexportable_keys::UnexportableKeyService> key_service_;
  unexportable_keys::UnexportableKeyId key_id_;
  raw_ptr<const URLRequestContext> context_;
  IsolationInfo isolation_info_;
  RegistrationFetcher::RegistrationCompleteCallback callback_;

  // Created to fetch data
  std::unique_ptr<URLRequest> request_;
  scoped_refptr<IOBuffer> buf_;
  std::string data_received_;
};

std::optional<RegistrationFetcher::RegistrationCompleteParams> (
    *g_mock_fetcher)() = nullptr;

}  // namespace

RegistrationFetcher::RegistrationCompleteParams::RegistrationCompleteParams(
    SessionParams params,
    unexportable_keys::UnexportableKeyId key_id,
    const GURL& url,
    std::optional<std::string> referral_session_identifier)
    : params(std::move(params)),
      key_id(std::move(key_id)),
      url(url),
      referral_session_identifier(std::move(referral_session_identifier)) {}

RegistrationFetcher::RegistrationCompleteParams::RegistrationCompleteParams(
    RegistrationFetcher::RegistrationCompleteParams&& other) noexcept = default;
RegistrationFetcher::RegistrationCompleteParams&
RegistrationFetcher::RegistrationCompleteParams::operator=(
    RegistrationFetcher::RegistrationCompleteParams&& other) noexcept = default;

RegistrationFetcher::RegistrationCompleteParams::~RegistrationCompleteParams() =
    default;

// static
void RegistrationFetcher::StartCreateTokenAndFetch(
    RegistrationFetcherParam registration_params,
    unexportable_keys::UnexportableKeyService& key_service,
    // TODO(kristianm): Check the lifetime of context and make sure this use
    // is safe.
    const URLRequestContext* context,
    const IsolationInfo& isolation_info,
    RegistrationCompleteCallback callback) {
  // Using mock fetcher for testing
  if (g_mock_fetcher) {
    std::move(callback).Run(g_mock_fetcher());
    return;
  }

  const auto supported_algos = registration_params.supported_algos();
  auto request_params =
      RegistrationRequestParam::Create(std::move(registration_params));
  // `key_service` is created along with `SessionService` and will be valid
  // until the browser ends, hence `std::ref` is safe here.
  key_service.GenerateSigningKeySlowlyAsync(
      supported_algos, kTaskPriority,
      base::BindOnce(&RegistrationFetcher::StartFetchWithExistingKey,
                     std::move(request_params), std::ref(key_service), context,
                     isolation_info, std::move(callback)));
}

// static
void RegistrationFetcher::StartFetchWithExistingKey(
    RegistrationRequestParam request_params,
    unexportable_keys::UnexportableKeyService& unexportable_key_service,
    const URLRequestContext* context,
    const IsolationInfo& isolation_info,
    RegistrationFetcher::RegistrationCompleteCallback callback,
    unexportable_keys::ServiceErrorOr<unexportable_keys::UnexportableKeyId>
        key_id) {
  // Using mock fetcher for testing.
  if (g_mock_fetcher) {
    std::move(callback).Run(g_mock_fetcher());
    return;
  }

  if (!key_id.has_value()) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  // RegistrationFetcherImpl manages its own lifetime.
  RegistrationFetcherImpl* fetcher = new RegistrationFetcherImpl(
      request_params.TakeRegistrationEndpoint(),
      request_params.TakeSessionIdentifier(), unexportable_key_service,
      key_id.value(), context, isolation_info, std::move(callback));

  fetcher->Start(request_params.TakeChallenge(),
                 request_params.TakeAuthorization());
}

void RegistrationFetcher::SetFetcherForTesting(FetcherType func) {
  if (g_mock_fetcher) {
    CHECK(!func);
    g_mock_fetcher = nullptr;
  } else {
    g_mock_fetcher = func;
  }
}

void RegistrationFetcher::CreateTokenAsyncForTesting(
    unexportable_keys::UnexportableKeyService& unexportable_key_service,
    std::string challenge,
    const GURL& registration_url,
    std::optional<std::string> authorization,
    base::OnceCallback<
        void(std::optional<RegistrationFetcher::RegistrationTokenResult>)>
        callback) {
  static constexpr crypto::SignatureVerifier::SignatureAlgorithm
      kSupportedAlgos[] = {crypto::SignatureVerifier::ECDSA_SHA256,
                           crypto::SignatureVerifier::RSA_PKCS1_SHA256};
  unexportable_key_service.GenerateSigningKeySlowlyAsync(
      kSupportedAlgos, kTaskPriority,
      base::BindOnce(
          [](unexportable_keys::UnexportableKeyService& key_service,
             const GURL& registration_url, const std::string& challenge,
             std::optional<std::string>&& authorization,
             base::OnceCallback<void(
                 std::optional<RegistrationFetcher::RegistrationTokenResult>)>
                 callback,
             unexportable_keys::ServiceErrorOr<
                 unexportable_keys::UnexportableKeyId> key_result) {
            if (!key_result.has_value()) {
              std::move(callback).Run(std::nullopt);
              return;
            }

            SignChallengeWithKey(key_service, key_result.value(),
                                 registration_url, challenge,
                                 std::move(authorization), std::move(callback));
          },
          std::ref(unexportable_key_service), registration_url,
          std::move(challenge), std::move(authorization), std::move(callback)));
}

}  // namespace net::device_bound_sessions

"""

```