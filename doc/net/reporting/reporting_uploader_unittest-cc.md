Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The primary goal is to understand what this specific file (`reporting_uploader_unittest.cc`) tests. It's a *unittest*, so it's designed to test the functionality of a specific component in isolation. The name "reporting_uploader" is a strong clue.

2. **Identify the Target Class:**  The `#include "net/reporting/reporting_uploader.h"` line immediately tells us the main class under test is `ReportingUploader`. Everything in the file will likely revolve around exercising its methods and verifying its behavior.

3. **Analyze the Test Structure:**  The file uses the Google Test framework (`TEST_F`). This means each `TEST_F` block is an individual test case. The class `ReportingUploaderTest` inherits from `TestWithTaskEnvironment`, providing necessary setup and teardown.

4. **Examine Setup and Helper Functions:**
    * The `ReportingUploaderTest` constructor sets up an `EmbeddedTestServer` and a `URLRequestContext`. This suggests network interaction is involved.
    * Helper functions like `CheckUpload`, `AllowPreflight`, `ReturnResponse`, `ReturnInvalidResponse`, etc., are defined. These strongly hint at the various scenarios being tested – successful uploads, different server responses, preflight requests, etc.
    * The `TestUploadCallback` class is a utility to handle asynchronous callbacks, essential for testing network operations.

5. **Iterate Through Test Cases (Mental Walkthrough):**  Go through each `TEST_F` individually and try to understand its purpose:
    * `Upload`:  Verifies the basic upload process, including correct headers and body.
    * `Success`: Checks for a successful upload outcome.
    * `NetworkError1`, `NetworkError2`: Tests scenarios where network errors occur (server down, invalid response).
    * `ServerError`: Tests a 500 Internal Server Error.
    * `VerifyPreflight`, `SkipPreflightForSameOrigin`: Focus on CORS preflight requests.
    * `FailedCorsPreflight`, `CorsPreflightWithoutOrigin`, etc.: Test various scenarios of failed or malformed CORS preflight responses.
    * `RemoveEndpoint`: Tests how the uploader handles a 410 Gone response.
    * `FollowHttpsRedirect`, `DontFollowHttpRedirect`: Tests redirect behavior (HTTPS allowed, HTTP blocked).
    * `DontSendCookies`, `DontSaveCookies`: Tests that reporting uploads don't involve cookie handling.
    * `DontCacheResponse`:  Verifies that responses are not cached.
    * `RespectsNetworkAnonymizationKey`: A more complex test verifying that requests with different network keys use separate sockets.

6. **Identify Key Functionality Being Tested:** Based on the test cases, create a concise summary of the `ReportingUploader`'s functionality:
    * Initiating POST requests for reporting.
    * Handling successful server responses.
    * Handling various network errors and server errors.
    * Performing CORS preflight checks (when needed).
    * Handling different CORS preflight response scenarios (success, failure, missing headers).
    * Handling "gone" responses.
    * Following HTTPS redirects, but not HTTP redirects.
    * Specifically *not* sending or saving cookies.
    * Specifically *not* caching responses.
    * Respecting `NetworkAnonymizationKey` for connection partitioning.

7. **Consider JavaScript Relevance:**  Think about where these network reporting mechanisms might be used in a browser context. JavaScript, running in web pages, is often the source of these reports (e.g., using the Network Error Logging API or similar).

8. **Develop JavaScript Examples:**  Create simple JavaScript snippets that would trigger the `ReportingUploader`'s functionality. This involves understanding how JavaScript interacts with browser APIs that generate network reports.

9. **Reason About Inputs and Outputs:** For a few key test cases, think about the specific inputs (URLs, data, server responses) and the expected outputs (the `Outcome` enum values). This helps solidify understanding of the test logic.

10. **Identify Potential User/Programming Errors:**  Consider how a developer using the reporting APIs or a user encountering network issues might lead to these test scenarios. This connects the technical details to practical use cases.

11. **Trace User Actions (Debugging Perspective):** Imagine a user experiencing a problem and how a developer might use these unittests as a starting point for debugging. Think about the sequence of user actions and the corresponding network events.

12. **Structure the Explanation:**  Organize the findings into a clear and logical structure, covering functionality, JavaScript relevance, logical reasoning, user errors, and debugging. Use clear headings and bullet points for readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just sends reports."  **Correction:**  It's more nuanced. It handles CORS, redirects, cookies, caching – it's a full-fledged network request handler for reporting.
* **Initial thought (JavaScript):** "Maybe `fetch()`?" **Correction:**  While `fetch()` can trigger network requests, the context here is *specifically* about *reporting* mechanisms, like NEL, which have dedicated browser implementations that might leverage this `ReportingUploader`.
* **Overly focused on code details:**  **Correction:**  Balance the technical analysis with the higher-level understanding of *why* these tests exist and what user scenarios they cover.

By following this kind of methodical process, moving from the general to the specific, and continually refining understanding, one can effectively analyze even complex code files like this unittest.
这个文件 `net/reporting/reporting_uploader_unittest.cc` 是 Chromium 网络栈中 `ReportingUploader` 类的单元测试文件。它的主要功能是 **测试 `ReportingUploader` 类的各种功能和行为**。

以下是它的具体功能分解：

**1. 功能概述:**

* **上传报告:** 测试 `ReportingUploader` 能否成功地将报告数据上传到指定的 URL。
* **处理成功和失败:** 测试上传成功和各种失败场景（例如网络错误、服务器错误、CORS 预检失败等）的处理。
* **CORS 预检:** 测试 `ReportingUploader` 是否正确执行 CORS 预检请求，并根据预检结果决定是否进行实际的报告上传。
* **HTTPS 重定向:** 测试 `ReportingUploader` 是否遵循 HTTPS 重定向，但不遵循 HTTP 重定向。
* **Cookie 处理:** 测试 `ReportingUploader` 在上传报告时是否正确地不发送和不保存 Cookie。
* **缓存控制:** 测试 `ReportingUploader` 在上传报告时不缓存服务器的响应。
* **NetworkAnonymizationKey:** 测试 `ReportingUploader` 是否尊重 `NetworkAnonymizationKey`，确保具有相同 Key 的请求可以共享 socket 连接。
* **处理“已移除”的端点:** 测试 `ReportingUploader` 如何处理服务器返回 410 Gone 状态码的情况。

**2. 与 JavaScript 的关系 (间接关系):**

`ReportingUploader` 本身是用 C++ 实现的，直接与 JavaScript 没有代码层面的交互。然而，它所承担的功能是 JavaScript API (如 Network Error Logging, Crash Reporting 等) 的底层实现支撑。

* **举例说明:**
    * 当网页中的 JavaScript 代码通过 `navigator.sendBeacon()` 或其他 Reporting API 发送网络错误报告时，Chromium 浏览器会将这些报告数据传递给网络栈。
    * `ReportingUploader` 负责接收这些报告数据，并将其通过 HTTP POST 请求上传到配置的报告接收端点。
    * **假设输入（JavaScript）:**  网页 JavaScript 代码调用 `navigator.sendBeacon('https://example.com/report', JSON.stringify({ "type": "network-error", "message": "Failed to load resource" }))`。
    * **对应的 `ReportingUploader` 行为:**  `ReportingUploader` 会接收到目标 URL (`https://example.com/report`) 和报告数据 (`{"type": "network-error", "message": "Failed to load resource"}`). 它会构造一个 HTTP POST 请求，将数据作为请求体发送出去。

**3. 逻辑推理 (假设输入与输出):**

* **测试用例: `TEST_F(ReportingUploaderTest, Success)`**
    * **假设输入:**
        * `kOrigin`: `https://origin/`
        * `server_.GetURL("/")`:  假设服务器运行在 `https://localhost:PORT/`
        * `kUploadBody`: "{}"
        * 服务器配置为允许 CORS 预检 (返回 `Access-Control-Allow-Origin`)，并对 POST 请求返回 HTTP 200 OK。
    * **预期输出:** `callback.outcome()` 的值为 `ReportingUploader::Outcome::SUCCESS`。

* **测试用例: `TEST_F(ReportingUploaderTest, NetworkError1)`**
    * **假设输入:**
        * `kOrigin`: `https://origin/`
        * `url`: 一个服务器已经关闭的 URL。
        * `kUploadBody`: "{}"
    * **预期输出:** `callback.outcome()` 的值为 `ReportingUploader::Outcome::FAILURE`。

* **测试用例: `TEST_F(ReportingUploaderTest, FailedCorsPreflight)`**
    * **假设输入:**
        * `kOrigin`: `https://origin/`
        * `server_.GetURL("/")`:  假设服务器运行在 `https://localhost:PORT/`
        * `kUploadBody`: "{}"
        * 服务器对 OPTIONS 预检请求返回 HTTP 403 Forbidden。
    * **预期输出:** `callback.outcome()` 的值为 `ReportingUploader::Outcome::FAILURE`。

**4. 用户或编程常见的使用错误 (作为调试线索):**

* **配置错误的报告端点:**
    * **错误:** 用户（开发者）在配置报告接收端点时，可能输入了错误的 URL，例如拼写错误、使用了 HTTP 而不是 HTTPS (可能导致安全问题)，或者端点根本不存在。
    * **对应测试:** `TEST_F(ReportingUploaderTest, NetworkError1)` 模拟了服务器不可达的情况，可以帮助调试此类问题。
* **CORS 配置错误:**
    * **错误:**  报告接收端点的服务器没有正确配置 CORS 头部 (例如缺少 `Access-Control-Allow-Origin`)，导致浏览器阻止跨域请求。
    * **对应测试:** 多个测试用例，例如 `TEST_F(ReportingUploaderTest, FailedCorsPreflight)`、`TEST_F(ReportingUploaderTest, CorsPreflightWithoutOrigin)` 等，专门测试了各种 CORS 预检失败的情况，可以帮助诊断 CORS 配置问题。
* **服务器端错误:**
    * **错误:** 报告接收端点的服务器内部出现错误 (例如数据库连接失败、代码 bug)，返回 5xx 错误码。
    * **对应测试:** `TEST_F(ReportingUploaderTest, ServerError)` 测试了服务器返回 500 错误的情况。
* **重定向问题:**
    * **错误:**  报告接收端点配置了 HTTP 重定向，而 `ReportingUploader` 不会跟随 HTTP 重定向。
    * **对应测试:** `TEST_F(ReportingUploaderTest, DontFollowHttpRedirect)` 可以帮助验证是否因为 HTTP 重定向导致报告上传失败。

**5. 用户操作如何一步步到达这里 (作为调试线索):**

假设用户遇到了一个网络错误，并且这个错误被 JavaScript 的 Network Error Logging API 捕获并尝试报告：

1. **用户操作:** 用户在浏览器中访问一个网页。
2. **网络错误发生:** 网页尝试加载某个资源 (例如图片、脚本)，但由于网络问题 (例如 DNS 解析失败、连接超时、服务器返回 404) 导致加载失败。
3. **JavaScript 捕获错误:** 网页的 JavaScript 代码使用了 Network Error Logging API，浏览器内核会记录这个网络错误。
4. **报告生成:**  浏览器内核根据配置，决定将这个网络错误生成一个报告。
5. **`ReportingUploader` 启动:** 当需要上传报告时，网络栈会创建 `ReportingUploader` 实例。
6. **构造请求:** `ReportingUploader` 会根据报告数据和配置的报告端点 URL，构造一个 HTTP POST 请求。
7. **发送预检请求 (如果需要):** 如果是跨域请求，并且需要进行 CORS 预检，`ReportingUploader` 会先发送 OPTIONS 请求。
8. **处理预检响应:** 根据预检响应的结果，决定是否发送实际的报告上传请求。
9. **发送上传请求:** 发送包含报告数据的 HTTP POST 请求。
10. **处理服务器响应:**  `ReportingUploader` 接收并处理服务器的响应，例如成功 (200 OK)、失败 (4xx, 5xx)、重定向等。
11. **回调通知:**  `ReportingUploader` 通过回调通知上层模块上传结果。

**作为调试线索:** 当开发者发现网络报告没有成功上传时，他们可能会查看 Chromium 的网络日志 (net-internals)。如果日志显示与报告上传相关的请求失败，他们可能会深入研究 `ReportingUploader` 的代码和相关的单元测试，例如本文件，来理解可能的原因：

* **如果看到 CORS 错误:** 会查看与 CORS 预检相关的测试用例。
* **如果看到连接错误:** 会查看与网络错误处理相关的测试用例。
* **如果怀疑重定向问题:** 会查看与重定向处理相关的测试用例。

总而言之，`net/reporting/reporting_uploader_unittest.cc` 是确保 `ReportingUploader` 类功能正确性和健壮性的重要组成部分，它涵盖了各种正常和异常情况，为网络报告功能的稳定运行提供了保障。它与 JavaScript 的联系在于它是 JavaScript Reporting API 的底层实现。

### 提示词
```
这是目录为net/reporting/reporting_uploader_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_uploader.h"

#include <memory>
#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/run_loop.h"
#include "base/test/scoped_feature_list.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/cookies/cookie_access_result.h"
#include "net/cookies/cookie_store.h"
#include "net/cookies/cookie_store_test_callbacks.h"
#include "net/http/http_status_code.h"
#include "net/socket/socket_test_util.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/test_with_task_environment.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

class ReportingUploaderTest : public TestWithTaskEnvironment {
 protected:
  ReportingUploaderTest()
      : server_(test_server::EmbeddedTestServer::TYPE_HTTPS),
        context_(CreateTestURLRequestContextBuilder()->Build()),
        uploader_(ReportingUploader::Create(context_.get())) {}

  test_server::EmbeddedTestServer server_;
  std::unique_ptr<URLRequestContext> context_;
  std::unique_ptr<ReportingUploader> uploader_;

  const url::Origin kOrigin = url::Origin::Create(GURL("https://origin/"));
};

const char kUploadBody[] = "{}";

void CheckUpload(const test_server::HttpRequest& request) {
  if (request.method_string != "POST") {
    return;
  }
  auto it = request.headers.find("Content-Type");
  EXPECT_TRUE(it != request.headers.end());
  EXPECT_EQ("application/reports+json", it->second);
  EXPECT_TRUE(request.has_content);
  EXPECT_EQ(kUploadBody, request.content);
}

std::unique_ptr<test_server::HttpResponse> AllowPreflight(
    const test_server::HttpRequest& request) {
  if (request.method_string != "OPTIONS") {
    return nullptr;
  }
  auto it = request.headers.find("Origin");
  EXPECT_TRUE(it != request.headers.end());
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->AddCustomHeader("Access-Control-Allow-Origin", it->second);
  response->AddCustomHeader("Access-Control-Allow-Methods", "POST");
  response->AddCustomHeader("Access-Control-Allow-Headers", "Content-Type");
  response->set_code(HTTP_OK);
  response->set_content("");
  response->set_content_type("text/plain");
  return std::move(response);
}

std::unique_ptr<test_server::HttpResponse> ReturnResponse(
    HttpStatusCode code,
    const test_server::HttpRequest& request) {
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_code(code);
  response->set_content("");
  response->set_content_type("text/plain");
  return std::move(response);
}

std::unique_ptr<test_server::HttpResponse> ReturnInvalidResponse(
    const test_server::HttpRequest& request) {
  return std::make_unique<test_server::RawHttpResponse>(
      "", "Not a valid HTTP response.");
}

class TestUploadCallback {
 public:
  TestUploadCallback() = default;

  ReportingUploader::UploadCallback callback() {
    return base::BindOnce(&TestUploadCallback::OnUploadComplete,
                          base::Unretained(this));
  }

  void WaitForCall() {
    if (called_)
      return;

    base::RunLoop run_loop;

    waiting_ = true;
    closure_ = run_loop.QuitClosure();
    run_loop.Run();
  }

  ReportingUploader::Outcome outcome() const { return outcome_; }

 private:
  void OnUploadComplete(ReportingUploader::Outcome outcome) {
    EXPECT_FALSE(called_);

    called_ = true;
    outcome_ = outcome;

    if (waiting_) {
      waiting_ = false;
      std::move(closure_).Run();
    }
  }

  bool called_ = false;
  ReportingUploader::Outcome outcome_;

  bool waiting_ = false;
  base::OnceClosure closure_;
};

TEST_F(ReportingUploaderTest, Upload) {
  server_.RegisterRequestMonitor(base::BindRepeating(&CheckUpload));
  server_.RegisterRequestHandler(base::BindRepeating(&AllowPreflight));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();
}

TEST_F(ReportingUploaderTest, Success) {
  server_.RegisterRequestHandler(base::BindRepeating(&AllowPreflight));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::SUCCESS, callback.outcome());
}

TEST_F(ReportingUploaderTest, NetworkError1) {
  ASSERT_TRUE(server_.Start());
  GURL url = server_.GetURL("/");
  ASSERT_TRUE(server_.ShutdownAndWaitUntilComplete());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, url, IsolationInfo::CreateTransient(),
                         kUploadBody, 0, false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::FAILURE, callback.outcome());
}

TEST_F(ReportingUploaderTest, NetworkError2) {
  server_.RegisterRequestHandler(base::BindRepeating(&AllowPreflight));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnInvalidResponse));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::FAILURE, callback.outcome());
}

TEST_F(ReportingUploaderTest, ServerError) {
  server_.RegisterRequestHandler(base::BindRepeating(&AllowPreflight));
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_INTERNAL_SERVER_ERROR));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::FAILURE, callback.outcome());
}

std::unique_ptr<test_server::HttpResponse> VerifyPreflight(
    bool* preflight_received_out,
    const test_server::HttpRequest& request) {
  if (request.method_string != "OPTIONS") {
    return nullptr;
  }
  *preflight_received_out = true;
  return AllowPreflight(request);
}

TEST_F(ReportingUploaderTest, VerifyPreflight) {
  bool preflight_received = false;
  server_.RegisterRequestHandler(
      base::BindRepeating(&VerifyPreflight, &preflight_received));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_TRUE(preflight_received);
  EXPECT_EQ(ReportingUploader::Outcome::SUCCESS, callback.outcome());
}

TEST_F(ReportingUploaderTest, SkipPreflightForSameOrigin) {
  bool preflight_received = false;
  server_.RegisterRequestHandler(
      base::BindRepeating(&VerifyPreflight, &preflight_received));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  auto server_origin = url::Origin::Create(server_.base_url());
  uploader_->StartUpload(server_origin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_FALSE(preflight_received);
  EXPECT_EQ(ReportingUploader::Outcome::SUCCESS, callback.outcome());
}

std::unique_ptr<test_server::HttpResponse> ReturnPreflightError(
    const test_server::HttpRequest& request) {
  if (request.method_string != "OPTIONS") {
    return nullptr;
  }
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_code(HTTP_FORBIDDEN);
  response->set_content("");
  response->set_content_type("text/plain");
  return std::move(response);
}

TEST_F(ReportingUploaderTest, FailedCorsPreflight) {
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnPreflightError));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::FAILURE, callback.outcome());
}

std::unique_ptr<test_server::HttpResponse> ReturnPreflightWithoutOrigin(
    const test_server::HttpRequest& request) {
  if (request.method_string != "OPTIONS") {
    return nullptr;
  }
  auto it = request.headers.find("Origin");
  EXPECT_TRUE(it != request.headers.end());
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->AddCustomHeader("Access-Control-Allow-Methods", "POST");
  response->AddCustomHeader("Access-Control-Allow-Headers", "Content-Type");
  response->set_code(HTTP_OK);
  response->set_content("");
  response->set_content_type("text/plain");
  return std::move(response);
}

TEST_F(ReportingUploaderTest, CorsPreflightWithoutOrigin) {
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnPreflightWithoutOrigin));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::FAILURE, callback.outcome());
}

std::unique_ptr<test_server::HttpResponse> ReturnPreflightWithoutMethods(
    const test_server::HttpRequest& request) {
  if (request.method_string != "OPTIONS") {
    return nullptr;
  }
  auto it = request.headers.find("Origin");
  EXPECT_TRUE(it != request.headers.end());
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->AddCustomHeader("Access-Control-Allow-Origin", it->second);
  response->AddCustomHeader("Access-Control-Allow-Headers", "Content-Type");
  response->set_code(HTTP_OK);
  response->set_content("");
  response->set_content_type("text/plain");
  return std::move(response);
}

TEST_F(ReportingUploaderTest, CorsPreflightWithoutMethods) {
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnPreflightWithoutMethods));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::SUCCESS, callback.outcome());
}

std::unique_ptr<test_server::HttpResponse> ReturnPreflightWithWildcardMethods(
    const test_server::HttpRequest& request) {
  if (request.method_string != "OPTIONS") {
    return nullptr;
  }
  auto it = request.headers.find("Origin");
  EXPECT_TRUE(it != request.headers.end());
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->AddCustomHeader("Access-Control-Allow-Origin", it->second);
  response->AddCustomHeader("Access-Control-Allow-Headers", "Content-Type");
  response->AddCustomHeader("Access-Control-Allow-Methods", "*");
  response->set_code(HTTP_OK);
  response->set_content("");
  response->set_content_type("text/plain");
  return std::move(response);
}

TEST_F(ReportingUploaderTest, CorsPreflightWildcardMethods) {
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnPreflightWithWildcardMethods));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::SUCCESS, callback.outcome());
}

std::unique_ptr<test_server::HttpResponse> ReturnPreflightWithoutHeaders(
    const test_server::HttpRequest& request) {
  if (request.method_string != "OPTIONS") {
    return nullptr;
  }
  auto it = request.headers.find("Origin");
  EXPECT_TRUE(it != request.headers.end());
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->AddCustomHeader("Access-Control-Allow-Origin", it->second);
  response->AddCustomHeader("Access-Control-Allow-Methods", "POST");
  response->set_code(HTTP_OK);
  response->set_content("");
  response->set_content_type("text/plain");
  return std::move(response);
}

TEST_F(ReportingUploaderTest, CorsPreflightWithoutHeaders) {
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnPreflightWithoutHeaders));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::FAILURE, callback.outcome());
}

std::unique_ptr<test_server::HttpResponse> ReturnPreflightWithWildcardHeaders(
    const test_server::HttpRequest& request) {
  if (request.method_string != "OPTIONS") {
    return nullptr;
  }
  auto it = request.headers.find("Origin");
  EXPECT_TRUE(it != request.headers.end());
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->AddCustomHeader("Access-Control-Allow-Origin", it->second);
  response->AddCustomHeader("Access-Control-Allow-Headers", "*");
  response->AddCustomHeader("Access-Control-Allow-Methods", "POST");
  response->set_code(HTTP_OK);
  response->set_content("");
  response->set_content_type("text/plain");
  return std::move(response);
}

TEST_F(ReportingUploaderTest, CorsPreflightWildcardHeaders) {
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnPreflightWithWildcardHeaders));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::SUCCESS, callback.outcome());
}

TEST_F(ReportingUploaderTest, RemoveEndpoint) {
  server_.RegisterRequestHandler(base::BindRepeating(&AllowPreflight));
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnResponse, HTTP_GONE));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_EQ(ReportingUploader::Outcome::REMOVE_ENDPOINT, callback.outcome());
}

const char kRedirectPath[] = "/redirect";

std::unique_ptr<test_server::HttpResponse> ReturnRedirect(
    const std::string& location,
    const test_server::HttpRequest& request) {
  if (request.relative_url != "/")
    return nullptr;

  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_code(HTTP_FOUND);
  response->AddCustomHeader("Location", location);
  response->set_content(
      "Thank you, Mario! But our Princess is in another castle.");
  response->set_content_type("text/plain");
  return std::move(response);
}

std::unique_ptr<test_server::HttpResponse> CheckRedirect(
    bool* redirect_followed_out,
    const test_server::HttpRequest& request) {
  if (request.relative_url != kRedirectPath)
    return nullptr;

  *redirect_followed_out = true;
  return ReturnResponse(HTTP_OK, request);
}

TEST_F(ReportingUploaderTest, FollowHttpsRedirect) {
  bool followed = false;
  server_.RegisterRequestHandler(base::BindRepeating(&AllowPreflight));
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnRedirect, kRedirectPath));
  server_.RegisterRequestHandler(
      base::BindRepeating(&CheckRedirect, &followed));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_TRUE(followed);
  EXPECT_EQ(ReportingUploader::Outcome::SUCCESS, callback.outcome());
}

TEST_F(ReportingUploaderTest, DontFollowHttpRedirect) {
  bool followed = false;

  test_server::EmbeddedTestServer http_server_;
  http_server_.RegisterRequestHandler(
      base::BindRepeating(&CheckRedirect, &followed));
  ASSERT_TRUE(http_server_.Start());

  const GURL target = http_server_.GetURL(kRedirectPath);
  server_.RegisterRequestHandler(base::BindRepeating(&AllowPreflight));
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnRedirect, target.spec()));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, callback.callback());
  callback.WaitForCall();

  EXPECT_FALSE(followed);
  EXPECT_EQ(ReportingUploader::Outcome::FAILURE, callback.outcome());
}

void CheckNoCookie(const test_server::HttpRequest& request) {
  auto it = request.headers.find("Cookie");
  EXPECT_TRUE(it == request.headers.end());
}

TEST_F(ReportingUploaderTest, DontSendCookies) {
  server_.RegisterRequestMonitor(base::BindRepeating(&CheckNoCookie));
  server_.RegisterRequestHandler(base::BindRepeating(&AllowPreflight));
  server_.RegisterRequestHandler(base::BindRepeating(&ReturnResponse, HTTP_OK));
  ASSERT_TRUE(server_.Start());

  ResultSavingCookieCallback<CookieAccessResult> cookie_callback;
  GURL url = server_.GetURL("/");
  auto cookie =
      CanonicalCookie::CreateForTesting(url, "foo=bar", base::Time::Now());
  context_->cookie_store()->SetCanonicalCookieAsync(
      std::move(cookie), url, CookieOptions::MakeAllInclusive(),
      cookie_callback.MakeCallback());
  cookie_callback.WaitUntilDone();
  ASSERT_TRUE(cookie_callback.result().status.IsInclude());

  TestUploadCallback upload_callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, upload_callback.callback());
  upload_callback.WaitForCall();
}

std::unique_ptr<test_server::HttpResponse> SendCookie(
    const test_server::HttpRequest& request) {
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_code(HTTP_OK);
  response->AddCustomHeader("Set-Cookie", "foo=bar");
  response->set_content("");
  response->set_content_type("text/plain");
  return std::move(response);
}

TEST_F(ReportingUploaderTest, DontSaveCookies) {
  server_.RegisterRequestHandler(base::BindRepeating(&AllowPreflight));
  server_.RegisterRequestHandler(base::BindRepeating(&SendCookie));
  ASSERT_TRUE(server_.Start());

  TestUploadCallback upload_callback;
  uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                         IsolationInfo::CreateTransient(), kUploadBody, 0,
                         false, upload_callback.callback());
  upload_callback.WaitForCall();

  GetCookieListCallback cookie_callback;
  context_->cookie_store()->GetCookieListWithOptionsAsync(
      server_.GetURL("/"), CookieOptions::MakeAllInclusive(),
      CookiePartitionKeyCollection(),
      base::BindOnce(&GetCookieListCallback::Run,
                     base::Unretained(&cookie_callback)));
  cookie_callback.WaitUntilDone();

  EXPECT_TRUE(cookie_callback.cookies().empty());
}

std::unique_ptr<test_server::HttpResponse> ReturnCacheableResponse(
    int* request_count_out,
    const test_server::HttpRequest& request) {
  ++*request_count_out;
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_code(HTTP_OK);
  response->AddCustomHeader("Cache-Control", "max-age=86400");
  response->set_content("");
  response->set_content_type("text/plain");
  return std::move(response);
}

// TODO(juliatuttle): This passes even if the uploader doesn't set
// LOAD_DISABLE_CACHE. Maybe that's okay -- Chromium might not cache POST
// responses ever -- but this test should either not exist or be sure that it is
// testing actual functionality, not a default.
TEST_F(ReportingUploaderTest, DontCacheResponse) {
  int request_count = 0;
  server_.RegisterRequestHandler(base::BindRepeating(&AllowPreflight));
  server_.RegisterRequestHandler(
      base::BindRepeating(&ReturnCacheableResponse, &request_count));
  ASSERT_TRUE(server_.Start());

  {
    TestUploadCallback callback;
    uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                           IsolationInfo::CreateTransient(), kUploadBody, 0,
                           false, callback.callback());
    callback.WaitForCall();
  }
  EXPECT_EQ(1, request_count);

  {
    TestUploadCallback callback;
    uploader_->StartUpload(kOrigin, server_.GetURL("/"),
                           IsolationInfo::CreateTransient(), kUploadBody, 0,
                           false, callback.callback());
    callback.WaitForCall();
  }
  EXPECT_EQ(2, request_count);
}

// Create two requests with the same NetworkAnonymizationKey, and one request
// with a different one, and make sure only the requests with the same
// NetworkAnonymizationKey share a socket.
TEST_F(ReportingUploaderTest, RespectsNetworkAnonymizationKey) {
  // While network state partitioning is not needed for reporting code to
  // respect NetworkAnonymizationKey, this test works by ensuring that
  // Reporting's NetworkAnonymizationKey makes it to the socket pool layer and
  // is respected there, so this test needs to enable
  // network state partitioning.
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  const SchemefulSite kSite1 = SchemefulSite(kOrigin);
  const SchemefulSite kSite2(GURL("https://origin2/"));
  ASSERT_NE(kSite1, kSite2);
  const url::Origin kSiteOrigin1 = url::Origin::Create(kSite1.GetURL());
  const url::Origin kSiteOrigin2 = url::Origin::Create(kSite2.GetURL());
  const IsolationInfo kIsolationInfo1 =
      IsolationInfo::Create(net::IsolationInfo::RequestType::kOther,
                            kSiteOrigin1, kSiteOrigin1, net::SiteForCookies());
  const IsolationInfo kIsolationInfo2 =
      IsolationInfo::Create(net::IsolationInfo::RequestType::kOther,
                            kSiteOrigin2, kSiteOrigin2, net::SiteForCookies());

  MockClientSocketFactory socket_factory;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_client_socket_factory_for_testing(&socket_factory);
  auto context = context_builder->Build();

  // First socket handles first and third requests.
  MockWrite writes1[] = {
      MockWrite(SYNCHRONOUS, 0,
                "POST /1 HTTP/1.1\r\n"
                "Host: origin\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 2\r\n"
                "Content-Type: application/reports+json\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n\r\n"),
      MockWrite(SYNCHRONOUS, 1, kUploadBody),
      MockWrite(SYNCHRONOUS, 3,
                "POST /3 HTTP/1.1\r\n"
                "Host: origin\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 2\r\n"
                "Content-Type: application/reports+json\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n\r\n"),
      MockWrite(SYNCHRONOUS, 4, kUploadBody),
  };
  MockRead reads1[] = {
      MockRead(SYNCHRONOUS, 2,
               "HTTP/1.1 200 OK\r\n"
               "Connection: Keep-Alive\r\n"
               "Content-Length: 0\r\n\r\n"),
      MockRead(SYNCHRONOUS, 5,
               "HTTP/1.1 200 OK\r\n"
               "Connection: Keep-Alive\r\n"
               "Content-Length: 0\r\n\r\n"),
  };
  SequencedSocketData data1(reads1, writes1);
  socket_factory.AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl_data1(ASYNC, OK);
  socket_factory.AddSSLSocketDataProvider(&ssl_data1);

  // Second socket handles second request.
  MockWrite writes2[] = {
      MockWrite(SYNCHRONOUS, 0,
                "POST /2 HTTP/1.1\r\n"
                "Host: origin\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 2\r\n"
                "Content-Type: application/reports+json\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n\r\n"),
      MockWrite(SYNCHRONOUS, 1, kUploadBody),
  };
  MockRead reads2[] = {
      MockRead(SYNCHRONOUS, 2,
               "HTTP/1.1 200 OK\r\n"
               "Connection: Keep-Alive\r\n"
               "Content-Length: 0\r\n\r\n"),
  };
  SequencedSocketData data2(reads2, writes2);
  socket_factory.AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl_data2(ASYNC, OK);
  socket_factory.AddSSLSocketDataProvider(&ssl_data2);

  TestUploadCallback callback1;
  std::unique_ptr<ReportingUploader> uploader1 =
      ReportingUploader::Create(context.get());
  uploader1->StartUpload(kOrigin, GURL("https://origin/1"), kIsolationInfo1,
                         kUploadBody, 0, false, callback1.callback());
  callback1.WaitForCall();
  EXPECT_EQ(ReportingUploader::Outcome::SUCCESS, callback1.outcome());

  // Start two more requests in parallel. The first started uses a different
  // NetworkAnonymizationKey, so should create a new socket, while the second
  // one gets the other socket. Start in parallel to make sure that a new socket
  // isn't created just because the first is returned to the socket pool
  // asynchronously.
  TestUploadCallback callback2;
  std::unique_ptr<ReportingUploader> uploader2 =
      ReportingUploader::Create(context.get());
  uploader2->StartUpload(kOrigin, GURL("https://origin/2"), kIsolationInfo2,
                         kUploadBody, 0, false, callback2.callback());
  TestUploadCallback callback3;
  std::unique_ptr<ReportingUploader> uploader3 =
      ReportingUploader::Create(context.get());
  uploader3->StartUpload(kOrigin, GURL("https://origin/3"), kIsolationInfo1,
                         kUploadBody, 0, false, callback3.callback());

  callback2.WaitForCall();
  EXPECT_EQ(ReportingUploader::Outcome::SUCCESS, callback2.outcome());

  callback3.WaitForCall();
  EXPECT_EQ(ReportingUploader::Outcome::SUCCESS, callback3.outcome());
}

}  // namespace
}  // namespace net
```