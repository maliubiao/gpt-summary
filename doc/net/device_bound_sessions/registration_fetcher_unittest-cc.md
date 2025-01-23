Response:
The user wants to understand the functionality of the C++ source code file `registration_fetcher_unittest.cc`. They are interested in:
1. **Functionality of the code:** A general overview of what the code does.
2. **Relationship to Javascript:** If and how the code interacts with Javascript.
3. **Logical reasoning with examples:** Providing hypothetical inputs and expected outputs.
4. **Common user/programming errors:** Identifying potential mistakes when using the code.
5. **User journey for debugging:** Describing how a user might reach this code during operation.

This is the first part of the analysis, so I need to focus on summarizing the functionality based on the provided code.

**Code Analysis:**

The code is a unit test file (`_unittest.cc`) for a class named `RegistrationFetcher`. It uses the Google Test framework (`testing/gtest/include/gtest/gtest.h`).

The tests focus on verifying the behavior of `RegistrationFetcher` in various scenarios, including:

- Successful registration with different valid JSON responses.
- Handling invalid or missing fields in the JSON response (e.g., missing scope, session identifier, invalid scope specifications, invalid credential types).
- Handling network errors (e.g., server shutdown, invalid HTTP response).
- Handling server-side errors (e.g., 500 Internal Server Error).
- Handling authentication challenges (401 Unauthorized).
- Handling HTTP redirects (both HTTPS and HTTP).
- Handling SSL certificate errors.
- Fetching registration with an existing cryptographic key.
- Handling scenarios where the server requires a challenge for an existing key.

The tests utilize an `EmbeddedTestServer` to simulate server responses and mock the `UnexportableKeyService`.

**Summary of Functionality for Part 1:**

The primary function of `registration_fetcher_unittest.cc` is to **thoroughly test the `RegistrationFetcher` class**. It aims to ensure that `RegistrationFetcher` correctly handles various successful and error scenarios when fetching registration data from a server, especially in the context of device-bound sessions and cryptographic key management.这是对 Chromium 网络栈中 `net/device_bound_sessions/registration_fetcher_unittest.cc` 文件的功能进行的归纳：

**功能归纳：**

`registration_fetcher_unittest.cc` 文件的主要功能是 **对 `RegistrationFetcher` 类进行单元测试**。这个测试套件旨在验证 `RegistrationFetcher` 在各种场景下的行为，包括：

1. **成功获取注册信息:** 测试在收到各种有效 JSON 响应时，`RegistrationFetcher` 是否能正确解析并提取出会话标识符、作用域和凭据信息。
2. **处理无效的 JSON 响应:** 测试当服务器返回格式错误的 JSON 数据、缺少必要字段（如会话标识符、作用域）、或作用域规范不正确时，`RegistrationFetcher` 是否能正确处理并给出预期的结果（通常是失败）。
3. **处理不同类型的凭据:**  测试当服务器返回不同类型的凭据信息时，`RegistrationFetcher` 是否能正确识别并提取出 `cookie` 类型的凭据。
4. **处理网络错误:** 测试当发生网络错误（如服务器关闭、返回无效的 HTTP 响应）时，`RegistrationFetcher` 是否能正确处理并通知调用方。
5. **处理服务器错误:** 测试当服务器返回错误状态码（如 500 Internal Server Error）时，`RegistrationFetcher` 是否能正确处理。
6. **处理授权质询 (401 Unauthorized):** 测试 `RegistrationFetcher` 是否能处理服务器返回的 401 状态码，并从中提取质询信息。
7. **处理 HTTP 重定向:** 测试 `RegistrationFetcher` 是否能跟随 HTTPS 重定向，但拒绝跟随 HTTP 重定向。
8. **处理 SSL 错误:** 测试当遇到 SSL 证书错误（如证书过期）时，`RegistrationFetcher` 是否能正确处理。
9. **使用现有密钥获取注册信息:** 测试 `RegistrationFetcher` 在已知密钥的情况下，是否能成功向服务器请求注册信息。
10. **处理需要质询的现有密钥:** 测试 `RegistrationFetcher` 在使用现有密钥请求注册信息时，如果服务器返回质询，是否能正确处理并完成注册流程。

**与 JavaScript 的关系：**

从提供的代码片段来看，该文件是 C++ 代码，主要负责网络请求和数据解析，**没有直接的 JavaScript 代码或交互**。它的功能是为 Chromium 浏览器内部的网络栈提供支持。

然而，从更高层次来看，`RegistrationFetcher` 获取的会话信息（包括作用域和凭据）最终可能会被用于浏览器处理来自网页的请求，而网页通常会包含 JavaScript 代码。例如：

* **作用域 (Scope):**  服务器返回的作用域信息可能会限制哪些网站或路径可以使用设备绑定的会话。浏览器可能会在 JavaScript 发起网络请求时，检查这些作用域限制。
* **凭据 (Credentials):** 服务器返回的 cookie 信息可能会被存储在浏览器的 cookie 存储中，JavaScript 可以通过 `document.cookie` 等 API 来访问这些 cookie。

**举例说明:**

假设服务器返回的 JSON 响应中包含以下凭据信息：

```json
  "credentials": [{
    "type": "cookie",
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
  }]
```

1. **`RegistrationFetcher` (C++)** 会解析这段 JSON，提取出 cookie 的名称 (`auth_cookie`) 和属性 (`Domain=example.com; Path=/; Secure; SameSite=None`)。
2. **Chromium 浏览器** 会将这个 cookie 存储起来。
3. **网页中的 JavaScript** (运行在 `example.com` 域名下) 可以通过 `document.cookie` 访问到名为 `auth_cookie` 的 cookie，并可能将其用于后续的网络请求的身份验证。

**逻辑推理，假设输入与输出：**

**假设输入:**

* **服务器 URL:** `https://www.example.test/startsession`
* **服务器返回的 JSON:**  `{"session_identifier": "test_session", "scope": {"include_site": true}, "credentials": []}`

**预期输出:**

* `RegistrationFetcher` 成功解析 JSON。
* `RegistrationCompleteParams` 结构体中的 `params.session_id` 为 "test_session"。
* `params.scope.include_site` 为 `true`。
* `params.credentials` 为空。

**涉及用户或编程常见的使用错误：**

* **服务器端错误配置:** 服务器返回的 JSON 格式不正确或缺少必要的字段，会导致 `RegistrationFetcher` 解析失败。例如，忘记包含 `session_identifier` 字段。
* **URL 配置错误:**  传递给 `RegistrationFetcher` 的注册 URL 不正确，导致网络请求失败。
* **误解作用域配置:**  开发者可能不理解服务器返回的作用域信息的含义，导致在使用设备绑定会话时出现意外的行为。例如，错误地认为某个子域名也包含在作用域内。
* **凭据类型处理错误:**  服务器可能返回多种类型的凭据，但客户端可能只处理了 `cookie` 类型，导致其他类型的凭据被忽略。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试访问一个需要设备绑定会话的网站或功能。**
2. **浏览器检测到需要进行设备绑定会话的注册或刷新。**
3. **浏览器网络栈会创建 `RegistrationFetcher` 实例。**
4. **`RegistrationFetcher` 根据配置的 URL 向服务器发送注册请求。**
5. **服务器返回注册信息 (JSON)。**
6. **`RegistrationFetcher` 解析服务器的响应。**

如果在调试过程中发现设备绑定会话无法正常工作，开发者可能会查看网络日志，确认注册请求是否成功，以及服务器返回的响应内容是否正确。如果怀疑是客户端解析响应的问题，就可能会查看 `RegistrationFetcher` 相关的代码和日志。`registration_fetcher_unittest.cc` 中的测试用例可以帮助开发者理解 `RegistrationFetcher` 在各种情况下的预期行为，从而更容易定位问题。 例如，如果服务器返回的 JSON 结构发生了变化，导致与客户端的解析逻辑不匹配，那么开发者可能会参考测试用例来更新解析代码。

### 提示词
```
这是目录为net/device_bound_sessions/registration_fetcher_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/device_bound_sessions/registration_fetcher.h"

#include <memory>
#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/run_loop.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/test_future.h"
#include "components/unexportable_keys/unexportable_key_service.h"
#include "components/unexportable_keys/unexportable_key_service_impl.h"
#include "components/unexportable_keys/unexportable_key_task_manager.h"
#include "crypto/scoped_mock_unexportable_key_provider.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/cookies/cookie_access_result.h"
#include "net/cookies/cookie_store.h"
#include "net/cookies/cookie_store_test_callbacks.h"
#include "net/device_bound_sessions/registration_request_param.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_status_code.h"
#include "net/socket/socket_test_util.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/test_with_task_environment.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net::device_bound_sessions {

namespace {

using ::testing::ElementsAre;

constexpr char kBasicValidJson[] =
    R"({
  "session_identifier": "session_id",
  "scope": {
    "include_site": true,
    "scope_specification" : [
      {
        "type": "include",
        "domain": "trusted.example.com",
        "path": "/only_trusted_path"
      }
    ]
  },
  "credentials": [{
    "type": "cookie",
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
  }]
})";

constexpr char kSessionIdentifier[] = "session_id";
constexpr char kRedirectPath[] = "/redirect";
constexpr char kChallenge[] = "test_challenge";
const GURL kRegistrationUrl = GURL("https://www.example.test/startsession");
constexpr unexportable_keys::BackgroundTaskPriority kTaskPriority =
    unexportable_keys::BackgroundTaskPriority::kBestEffort;
std::vector<crypto::SignatureVerifier::SignatureAlgorithm> CreateAlgArray() {
  return {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256,
          crypto::SignatureVerifier::SignatureAlgorithm::RSA_PKCS1_SHA256};
}

class RegistrationTest : public TestWithTaskEnvironment {
 protected:
  RegistrationTest()
      : server_(test_server::EmbeddedTestServer::TYPE_HTTPS),
        context_(CreateTestURLRequestContextBuilder()->Build()),
        unexportable_key_service_(task_manager_) {}

  unexportable_keys::UnexportableKeyService& unexportable_key_service() {
    return unexportable_key_service_;
  }

  RegistrationFetcherParam GetBasicParam(
      std::optional<GURL> url = std::nullopt) {
    if (!url) {
      url = server_.GetURL("/");
    }

    return RegistrationFetcherParam::CreateInstanceForTesting(
        *url, CreateAlgArray(), std::string(kChallenge),
        /*authorization=*/std::nullopt);
  }

  void CreateKeyAndRunCallback(
      base::OnceCallback<void(unexportable_keys::ServiceErrorOr<
                              unexportable_keys::UnexportableKeyId>)>
          callback) {
    unexportable_key_service_.GenerateSigningKeySlowlyAsync(
        CreateAlgArray(), kTaskPriority, std::move(callback));
  }

  test_server::EmbeddedTestServer server_;
  std::unique_ptr<URLRequestContext> context_;

  const url::Origin kOrigin = url::Origin::Create(GURL("https://origin/"));
  unexportable_keys::UnexportableKeyTaskManager task_manager_{
      crypto::UnexportableKeyProvider::Config()};
  unexportable_keys::UnexportableKeyServiceImpl unexportable_key_service_;
};

class TestRegistrationCallback {
 public:
  TestRegistrationCallback() = default;

  RegistrationFetcher::RegistrationCompleteCallback callback() {
    return base::BindOnce(&TestRegistrationCallback::OnRegistrationComplete,
                          base::Unretained(this));
  }

  void WaitForCall() {
    if (called_) {
      return;
    }

    base::RunLoop run_loop;

    waiting_ = true;
    closure_ = run_loop.QuitClosure();
    run_loop.Run();
  }

  std::optional<RegistrationFetcher::RegistrationCompleteParams> outcome() {
    EXPECT_TRUE(called_);
    return std::move(outcome_);
  }

 private:
  void OnRegistrationComplete(
      std::optional<RegistrationFetcher::RegistrationCompleteParams> params) {
    EXPECT_FALSE(called_);

    called_ = true;
    outcome_ = std::move(params);

    if (waiting_) {
      waiting_ = false;
      std::move(closure_).Run();
    }
  }

  bool called_ = false;
  std::optional<RegistrationFetcher::RegistrationCompleteParams> outcome_ =
      std::nullopt;

  bool waiting_ = false;
  base::OnceClosure closure_;
};

std::unique_ptr<test_server::HttpResponse> ReturnResponse(
    HttpStatusCode code,
    std::string_view response_text,
    const test_server::HttpRequest& request) {
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_code(code);
  response->set_content_type("application/json");
  response->set_content(response_text);
  return response;
}

std::unique_ptr<test_server::HttpResponse> ReturnUnauthorized(
    const test_server::HttpRequest& request) {
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_code(HTTP_UNAUTHORIZED);
  response->AddCustomHeader("Sec-Session-Challenge", R"("challenge")");
  return response;
}

std::unique_ptr<test_server::HttpResponse> ReturnTextResponse(
    const test_server::HttpRequest& request) {
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_code(HTTP_OK);
  response->set_content_type("text/plain");
  response->set_content("some content");
  return response;
}

std::unique_ptr<test_server::HttpResponse> ReturnInvalidResponse(
    const test_server::HttpRequest& request) {
  return std::make_unique<test_server::RawHttpResponse>(
      "", "Not a valid HTTP response.");
}

class UnauthorizedThenSuccessResponseContainer {
 public:
  UnauthorizedThenSuccessResponseContainer(int unauthorize_response_times)
      : run_times(0), error_respose_times(unauthorize_response_times) {}

  std::unique_ptr<test_server::HttpResponse> Return(
      const test_server::HttpRequest& request) {
    if (run_times++ < error_respose_times) {
      return ReturnUnauthorized(request);
    }
    return ReturnResponse(HTTP_OK, kBasicValidJson, request);
  }

 private:
  int run_times;
  int error_respose_times;
};

TEST_F(RegistrationTest, BasicSuccess) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kBasicValidJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_TRUE(out_params->params.scope.include_site);
  EXPECT_THAT(out_params->params.scope.specifications,
              ElementsAre(SessionParams::Scope::Specification(
                  SessionParams::Scope::Specification::Type::kInclude,
                  "trusted.example.com", "/only_trusted_path")));
  EXPECT_THAT(
      out_params->params.credentials,
      ElementsAre(SessionParams::Credential(
          "auth_cookie", "Domain=example.com; Path=/; Secure; SameSite=None")));
}

TEST_F(RegistrationTest, NoScopeJson) {
  constexpr char kTestingJson[] =
      R"({
  "session_identifier": "session_id",
  "credentials": [{
    "type": "cookie",
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
  }]
})";
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kTestingJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_FALSE(out_params->params.scope.include_site);
  EXPECT_TRUE(out_params->params.scope.specifications.empty());
  EXPECT_THAT(
      out_params->params.credentials,
      ElementsAre(SessionParams::Credential(
          "auth_cookie", "Domain=example.com; Path=/; Secure; SameSite=None")));
}

TEST_F(RegistrationTest, NoSessionIdJson) {
  constexpr char kTestingJson[] =
      R"({
  "credentials": [{
    "type": "cookie",
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
  }]
})";
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kTestingJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_FALSE(out_params);
}

TEST_F(RegistrationTest, SpecificationNotDictJson) {
  constexpr char kTestingJson[] =
      R"({
  "session_identifier": "session_id",
  "scope": {
    "include_site": true,
    "scope_specification" : [
      "type", "domain", "path"
    ]
  },
  "credentials": [{
    "type": "cookie",
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
  }]
})";

  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kTestingJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_TRUE(out_params->params.scope.include_site);
  EXPECT_TRUE(out_params->params.scope.specifications.empty());
  EXPECT_THAT(
      out_params->params.credentials,
      ElementsAre(SessionParams::Credential(
          "auth_cookie", "Domain=example.com; Path=/; Secure; SameSite=None")));
}

TEST_F(RegistrationTest, OneMissingPath) {
  constexpr char kTestingJson[] =
      R"({
  "session_identifier": "session_id",
  "scope": {
    "include_site": true,
    "scope_specification" : [
      {
        "type": "include",
        "domain": "trusted.example.com"
      },
      {
        "type": "exclude",
        "domain": "new.example.com",
        "path": "/only_trusted_path"
      }
    ]
  },
  "credentials": [{
    "type": "cookie",
    "name": "other_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
  }]
})";

  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kTestingJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_TRUE(out_params->params.scope.include_site);

  EXPECT_THAT(out_params->params.scope.specifications,
              ElementsAre(SessionParams::Scope::Specification(
                  SessionParams::Scope::Specification::Type::kExclude,
                  "new.example.com", "/only_trusted_path")));

  EXPECT_THAT(out_params->params.credentials,
              ElementsAre(SessionParams::Credential(
                  "other_cookie",
                  "Domain=example.com; Path=/; Secure; SameSite=None")));
}

TEST_F(RegistrationTest, OneSpecTypeInvalid) {
  constexpr char kTestingJson[] =
      R"({
  "session_identifier": "session_id",
  "scope": {
    "include_site": true,
    "scope_specification" : [
      {
        "type": "invalid",
        "domain": "trusted.example.com",
        "path": "/only_trusted_path"
      },
      {
        "type": "exclude",
        "domain": "new.example.com",
        "path": "/only_trusted_path"
      }
    ]
  },
  "credentials": [{
    "type": "cookie",
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
  }]
})";

  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kTestingJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_TRUE(out_params->params.scope.include_site);

  EXPECT_THAT(out_params->params.scope.specifications,
              ElementsAre(SessionParams::Scope::Specification(
                  SessionParams::Scope::Specification::Type::kExclude,
                  "new.example.com", "/only_trusted_path")));

  EXPECT_THAT(
      out_params->params.credentials,
      ElementsAre(SessionParams::Credential(
          "auth_cookie", "Domain=example.com; Path=/; Secure; SameSite=None")));
}

TEST_F(RegistrationTest, InvalidTypeSpecList) {
  constexpr char kTestingJson[] =
      R"({
  "session_identifier": "session_id",
  "scope": {
    "include_site": true,
    "scope_specification" : "missing"
  },
  "credentials": [{
    "type": "cookie",
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
  }]
})";

  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kTestingJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_TRUE(out_params->params.scope.include_site);
  EXPECT_TRUE(out_params->params.scope.specifications.empty());
}

TEST_F(RegistrationTest, TypeIsNotCookie) {
  constexpr char kTestingJson[] =
      R"({
  "session_identifier": "session_id",
  "credentials": [{
    "type": "sync auth",
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
  }]
})";

  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kTestingJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  EXPECT_EQ(callback.outcome(), std::nullopt);
}

TEST_F(RegistrationTest, TwoTypesCookie_NotCookie) {
  constexpr char kTestingJson[] =
      R"({
  "session_identifier": "session_id",
  "credentials": [
    {
      "type": "cookie",
      "name": "auth_cookie",
      "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
    },
    {
      "type": "sync auth",
      "name": "auth_cookie",
      "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
    }
  ]
})";

  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kTestingJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_THAT(
      out_params->params.credentials,
      ElementsAre(SessionParams::Credential(
          "auth_cookie", "Domain=example.com; Path=/; Secure; SameSite=None")));
}

TEST_F(RegistrationTest, TwoTypesNotCookie_Cookie) {
  constexpr char kTestingJson[] =
      R"({
  "session_identifier": "session_id",
  "credentials": [
    {
      "type": "sync auth",
      "name": "auth_cookie",
      "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
    },
    {
      "type": "cookie",
      "name": "auth_cookie",
      "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
    }
  ]
})";

  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kTestingJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_THAT(
      out_params->params.credentials,
      ElementsAre(SessionParams::Credential(
          "auth_cookie", "Domain=example.com; Path=/; Secure; SameSite=None")));
}

TEST_F(RegistrationTest, CredEntryWithoutDict) {
  constexpr char kTestingJson[] =
      R"({
  "session_identifier": "session_id",
  "credentials": [{
    "type": "cookie",
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; SameSite=None"
  },
  "test"]
})";

  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kTestingJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcher::StartCreateTokenAndFetch(
      GetBasicParam(), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_THAT(
      out_params->params.credentials,
      ElementsAre(SessionParams::Credential(
          "auth_cookie", "Domain=example.com; Path=/; Secure; SameSite=None")));
}

TEST_F(RegistrationTest, ReturnTextFile) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnTextResponse));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcherParam params = GetBasicParam();
  RegistrationFetcher::StartCreateTokenAndFetch(
      std::move(params), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  EXPECT_EQ(callback.outcome(), std::nullopt);
}

TEST_F(RegistrationTest, ReturnInvalidJson) {
  std::string invalid_json = "*{}";
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, invalid_json));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcherParam params = GetBasicParam();
  RegistrationFetcher::StartCreateTokenAndFetch(
      std::move(params), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  EXPECT_EQ(callback.outcome(), std::nullopt);
}

TEST_F(RegistrationTest, ReturnEmptyJson) {
  std::string empty_json = "{}";
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, empty_json));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcherParam params = GetBasicParam();
  RegistrationFetcher::StartCreateTokenAndFetch(
      std::move(params), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();
  EXPECT_EQ(callback.outcome(), std::nullopt);
}

TEST_F(RegistrationTest, NetworkErrorServerShutdown) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  ASSERT_TRUE(server_.Start());
  GURL url = server_.GetURL("/");
  ASSERT_TRUE(server_.ShutdownAndWaitUntilComplete());

  TestRegistrationCallback callback;
  RegistrationFetcherParam params = GetBasicParam(url);
  RegistrationFetcher::StartCreateTokenAndFetch(
      std::move(params), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(callback.outcome(), std::nullopt);
}

TEST_F(RegistrationTest, NetworkErrorInvalidResponse) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnInvalidResponse));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcherParam params = GetBasicParam();
  RegistrationFetcher::StartCreateTokenAndFetch(
      std::move(params), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(callback.outcome(), std::nullopt);
}

TEST_F(RegistrationTest, ServerError500) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(base::BindRepeating(
      &ReturnResponse, HTTP_INTERNAL_SERVER_ERROR, kBasicValidJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcherParam params = GetBasicParam();
  RegistrationFetcher::StartCreateTokenAndFetch(
      std::move(params), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(callback.outcome(), std::nullopt);
}

TEST_F(RegistrationTest, ServerErrorReturnOne401ThenSuccess) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;

  auto* container = new UnauthorizedThenSuccessResponseContainer(1);
  server_.RegisterRequestHandler(
      base::BindRepeating(&UnauthorizedThenSuccessResponseContainer::Return,
                          base::Owned(container)));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcherParam params = GetBasicParam();
  RegistrationFetcher::StartCreateTokenAndFetch(
      std::move(params), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();

  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_TRUE(out_params->params.scope.include_site);
  EXPECT_THAT(out_params->params.scope.specifications,
              ElementsAre(SessionParams::Scope::Specification(
                  SessionParams::Scope::Specification::Type::kInclude,
                  "trusted.example.com", "/only_trusted_path")));
  EXPECT_THAT(
      out_params->params.credentials,
      ElementsAre(SessionParams::Credential(
          "auth_cookie", "Domain=example.com; Path=/; Secure; SameSite=None")));
}

std::unique_ptr<test_server::HttpResponse> ReturnRedirect(
    const std::string& location,
    const test_server::HttpRequest& request) {
  if (request.relative_url != "/") {
    return nullptr;
  }

  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_code(HTTP_FOUND);
  response->AddCustomHeader("Location", location);
  response->set_content("Redirected");
  response->set_content_type("text/plain");
  return std::move(response);
}

std::unique_ptr<test_server::HttpResponse> CheckRedirect(
    bool* redirect_followed_out,
    const test_server::HttpRequest& request) {
  if (request.relative_url != kRedirectPath) {
    return nullptr;
  }

  *redirect_followed_out = true;
  return ReturnResponse(HTTP_OK, kBasicValidJson, request);
}

TEST_F(RegistrationTest, FollowHttpsRedirect) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  bool followed = false;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnRedirect, kRedirectPath));
  server_.RegisterRequestHandler(
      base::BindRepeating(&CheckRedirect, &followed));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcherParam params = GetBasicParam();
  RegistrationFetcher::StartCreateTokenAndFetch(
      std::move(params), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();

  EXPECT_TRUE(followed);
  EXPECT_NE(callback.outcome(), std::nullopt);
}

TEST_F(RegistrationTest, DontFollowHttpRedirect) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  bool followed = false;
  test_server::EmbeddedTestServer http_server_;
  ASSERT_TRUE(http_server_.Start());
  const GURL target = http_server_.GetURL(kRedirectPath);

  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnRedirect, target.spec()));
  server_.RegisterRequestHandler(
      base::BindRepeating(&CheckRedirect, &followed));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcherParam params = GetBasicParam();
  RegistrationFetcher::StartCreateTokenAndFetch(
      std::move(params), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());
  callback.WaitForCall();

  EXPECT_FALSE(followed);
  EXPECT_EQ(callback.outcome(), std::nullopt);
}

TEST_F(RegistrationTest, FailOnSslErrorExpired) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kBasicValidJson));
  server_.SetSSLConfig(net::EmbeddedTestServer::CERT_EXPIRED);
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  RegistrationFetcherParam params = GetBasicParam();
  RegistrationFetcher::StartCreateTokenAndFetch(
      std::move(params), unexportable_key_service(), context_.get(),
      IsolationInfo::CreateTransient(), callback.callback());

  callback.WaitForCall();
  EXPECT_EQ(callback.outcome(), std::nullopt);
}

std::unique_ptr<test_server::HttpResponse> ReturnResponseForRefreshRequest(
    const test_server::HttpRequest& request) {
  auto response = std::make_unique<test_server::BasicHttpResponse>();

  auto resp_iter = request.headers.find("Sec-Session-Response");
  std::string session_response =
      resp_iter != request.headers.end() ? resp_iter->second : "";
  if (session_response.empty()) {
    const auto session_iter = request.headers.find("Sec-Session-Id");
    EXPECT_TRUE(session_iter != request.headers.end() &&
                !session_iter->second.empty());

    response->set_code(HTTP_UNAUTHORIZED);
    response->AddCustomHeader("Sec-Session-Challenge",
                              R"("test_challenge";id="session_id")");
    return response;
  }

  response->set_code(HTTP_OK);
  response->set_content_type("application/json");
  response->set_content(kBasicValidJson);
  return response;
}

TEST_F(RegistrationTest, BasicSuccessForExistingKey) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_OK, kBasicValidJson));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  auto isolation_info = IsolationInfo::CreateTransient();
  auto request_param = RegistrationRequestParam::CreateForTesting(
      server_.base_url(), kSessionIdentifier, kChallenge);
  CreateKeyAndRunCallback(base::BindOnce(
      &RegistrationFetcher::StartFetchWithExistingKey, std::move(request_param),
      std::ref(unexportable_key_service()), context_.get(),
      std::ref(isolation_info), callback.callback()));

  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_TRUE(out_params->params.scope.include_site);
  EXPECT_THAT(out_params->params.scope.specifications,
              ElementsAre(SessionParams::Scope::Specification(
                  SessionParams::Scope::Specification::Type::kInclude,
                  "trusted.example.com", "/only_trusted_path")));
  EXPECT_THAT(
      out_params->params.credentials,
      ElementsAre(SessionParams::Credential(
          "auth_cookie", "Domain=example.com; Path=/; Secure; SameSite=None")));
}

TEST_F(RegistrationTest, FetchRegistrationWithCachedChallenge) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponseForRefreshRequest));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  auto request_param = RegistrationRequestParam::CreateForTesting(
      server_.base_url(), kSessionIdentifier, kChallenge);
  auto isolation_info = IsolationInfo::CreateTransient();
  CreateKeyAndRunCallback(base::BindOnce(
      &RegistrationFetcher::StartFetchWithExistingKey, std::move(request_param),
      std::ref(unexportable_key_service()), context_.get(),
      std::ref(isolation_info), callback.callback()));

  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_TRUE(out_params->params.scope.include_site);
  EXPECT_THAT(out_params->params.scope.specifications,
              ElementsAre(SessionParams::Scope::Specification(
                  SessionParams::Scope::Specification::Type::kInclude,
                  "trusted.example.com", "/only_trusted_path")));
  EXPECT_THAT(
      out_params->params.credentials,
      ElementsAre(SessionParams::Credential(
          "auth_cookie", "Domain=example.com; Path=/; Secure; SameSite=None")));
}

TEST_F(RegistrationTest, FetchRegitrationAndChallengeRequired) {
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponseForRefreshRequest));
  ASSERT_TRUE(server_.Start());

  TestRegistrationCallback callback;
  auto request_param = RegistrationRequestParam::CreateForTesting(
      server_.base_url(), kSessionIdentifier, std::nullopt);
  auto isolation_info = IsolationInfo::CreateTransient();
  CreateKeyAndRunCallback(base::BindOnce(
      &RegistrationFetcher::StartFetchWithExistingKey, std::move(request_param),
      std::ref(unexportable_key_service()), context_.get(),
      std::ref(isolation_info), callback.callback()));

  callback.WaitForCall();
  std::optional<RegistrationFetcher::RegistrationCompleteParams> out_params =
      callback.outcome();
  ASSERT_TRUE(out_params);
  EXPECT_TRUE(out_params->params.scope.include_site);
  EXPECT_THAT(out_params->params.scope.specifications,
              ElementsA
```