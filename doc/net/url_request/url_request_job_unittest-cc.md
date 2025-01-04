Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `url_request_job_unittest.cc` file within the Chromium networking stack. This means identifying what aspects of `URLRequestJob` are being tested. Additionally, we need to determine if there are any connections to JavaScript, potential user errors, and how a user's actions might lead to this code being executed.

2. **Initial Scan and Identification of Key Components:**  A quick read-through reveals several important things:
    * **`#include` statements:** These indicate the dependencies and what the code interacts with. We see `url_request/url_request_job.h`, various testing utilities (`gtest`, `gmock`, `test_with_task_environment`), and network-related headers (`net/base`, `net/http`, `net/url_request`). This immediately tells us it's a unit test file for the `URLRequestJob` class.
    * **Test Fixtures (`URLRequestJobTest`):** This signifies that the code is structured using Google Test. The tests within this fixture will interact with and test `URLRequestJob` functionality.
    * **`TEST_F` macros:** Each of these defines an individual test case.
    * **`MockTransaction` and related setup:** The presence of `MockTransaction` suggests that the tests are using mock objects to simulate network responses, rather than making actual network requests. This is a common practice in unit testing network code.
    * **Assertions (`EXPECT_...`):**  These are used to verify the expected behavior of the code under test.
    * **Specific test names (e.g., `TransactionNoFilter`, `TransactionNotifiedWhenDone`, `RedirectTransaction...`, `SlowFilterRead`):** These names give strong hints about what aspects of `URLRequestJob` are being tested (e.g., handling of redirects, content encoding, slow responses).

3. **Categorize the Functionality Based on Tests:**  As we go through the `TEST_F` blocks, we can start grouping the functionality being tested:
    * **Basic Request/Response Handling:**  Tests like `TransactionNoFilter`, `TransactionNotifiedWhenDone`, `SyncTransactionNotifiedWhenDone` verify the basic flow of making a request and receiving a response, both synchronously and asynchronously.
    * **Content Encoding (gzip, Brotli):**  Tests like `GZipTransaction`, `SyncSlowTransaction`, `SlowFilterRead`, `SlowBrotliRead`, `InvalidContentGZipTransaction` focus on how `URLRequestJob` handles compressed content using different encoding schemes. This includes testing error conditions (invalid gzip).
    * **Redirection:** Tests like `RedirectTransactionNotifiedWhenDone`, `RedirectTransactionWithReferrerPolicyHeader`, `TransactionNotCachedWhenNetworkDelegateRedirects` specifically target how `URLRequestJob` manages HTTP redirects, including referrer policy and interaction with `NetworkDelegate`.
    * **Empty Body Handling:** `EmptyBodySkipFilter` tests the scenario of a response with no content but with a content encoding.
    * **Referrer Policy:** The `URLRequestJobComputeReferrer` tests form a separate block focusing on the logic for computing the referrer URL based on various policies and destination URLs.

4. **Identify Connections to JavaScript (or Lack Thereof):**  While `URLRequestJob` is a core part of the networking stack that *supports* web browsing and thus JavaScript execution, the *unit tests themselves* don't directly execute or interact with JavaScript. The tests simulate HTTP requests and responses at a lower level. The connection is *indirect*. JavaScript running in a browser will trigger network requests that eventually involve `URLRequestJob`.

5. **Analyze Logic and Create Input/Output Examples:** For each test case, we can deduce the intended logic and create hypothetical inputs and outputs. This helps solidify understanding:
    * **Example (TransactionNoFilter):**
        * **Input (Simulated):** A request to "http://www.google.com/gzyp" with a "200 OK" response and "hello" as the body. The `Content-Length` header is intentionally incorrect.
        * **Output (Expected):**  The request completes successfully, the received data is "hello", and the `GetExpectedContentSize()` reflects the provided (incorrect) value.
    * **Example (GZipTransaction):**
        * **Input (Simulated):** A request to "http://www.google.com/gzyp" with "Content-Encoding: gzip" and an intentionally wrong `Content-Length`. The mock server returns compressed data.
        * **Output (Expected):** The request completes successfully, the data is decompressed (though in this test, it's empty as per the `GZipServer` function), and the `GetExpectedContentSize()` is -1 because content encoding is present.
    * **Example (RedirectTransactionWithReferrerPolicyHeader):**
        * **Input (Simulated):** A request to a URL that redirects with a "Referrer-Policy: no-referrer" header.
        * **Output (Expected):** After the redirect, the `URLRequest`'s `referrer_policy()` is updated to `NO_REFERRER`, and the `referrer()` is empty.

6. **Identify Potential User Errors:**  User errors don't directly cause `URLRequestJob` to fail in the context of these *unit tests*. However, we can infer how user actions *could* lead to scenarios tested here:
    * **Visiting a site with invalid gzip encoding:** This could trigger the `InvalidContentGZipTransaction` scenario.
    * **Following a redirect that sets a specific referrer policy:** This relates to the `RedirectTransactionWithReferrerPolicyHeader` test.
    * **Experiencing slow network conditions:** While not a direct error, tests like `SlowFilterRead` and `SlowBrotliRead` demonstrate how `URLRequestJob` handles such situations.

7. **Trace User Actions to Code Execution (Debugging Clues):** This is about understanding how a user's interaction might lead to this specific code being involved:
    * **Typing a URL or clicking a link:** This initiates a navigation, and the browser needs to fetch the resource.
    * **The browser encounters a resource requiring decompression (gzip, Brotli):** The `URLRequestJob` will use decompression logic, which is tested here.
    * **The browser encounters an HTTP redirect:** The redirect handling logic in `URLRequestJob`, which is tested here, comes into play.
    * **A website sets a `Referrer-Policy` header:** This header affects how the browser sends referrer information on subsequent requests, and the tests for `URLRequestJobComputeReferrer` and the redirect referrer policy test are relevant.

8. **Refine and Structure the Output:** Finally, organize the gathered information into a clear and structured format, addressing each part of the original request (functionality, JavaScript relation, logic examples, user errors, debugging). Use clear language and provide specific examples from the code.这个C++源代码文件 `net/url_request/url_request_job_unittest.cc` 是 Chromium 网络栈的一部分，专门用于**测试 `URLRequestJob` 类的功能**。 `URLRequestJob` 是 Chromium 中处理 URL 请求的核心类之一。

以下是该文件的功能详细列表：

**核心功能：测试 `URLRequestJob` 的各种行为和场景**

* **基本的请求和响应处理:**
    * 测试在没有内容编码过滤器的情况下，`URLRequestJob` 如何处理 HTTP 响应（`TransactionNoFilter`， `TransactionNoFilterWithInvalidLength`）。
    * 测试请求完成时是否正确通知观察者（`TransactionNotifiedWhenDone`， `SyncTransactionNotifiedWhenDone`， `RedirectTransactionNotifiedWhenDone`）。
    * 测试同步请求的处理流程（`SyncTransactionNotifiedWhenDone`， `SyncSlowTransaction`）。
* **内容编码处理 (gzip, Brotli):**
    * 测试 `URLRequestJob` 如何处理 gzip 编码的响应（`GZipTransaction`， `SyncSlowTransaction`， `SlowFilterRead`， `EmptyBodySkipFilter`， `InvalidContentGZipTransaction`）。
    * 测试 `URLRequestJob` 如何处理 Brotli 编码的响应（`SlowBrotliRead`）。
    * 测试处理大型 gzip 头部的情况（`SyncSlowTransaction`）。
    * 测试处理无效的 gzip 内容的情况（`InvalidContentGZipTransaction`）。
    * 测试跳过内容解码过滤器的情况（`EmptyBodySkipFilter`）。
* **重定向处理:**
    * 测试 `URLRequestJob` 如何处理 HTTP 重定向（`RedirectTransactionNotifiedWhenDone`）。
    * 测试重定向过程中 `Referrer-Policy` 头部的影响（`RedirectTransactionWithReferrerPolicyHeader`）。
    * 测试当 `NetworkDelegate` 触发重定向时，请求是否被缓存（`TransactionNotCachedWhenNetworkDelegateRedirects`）。
* **Referrer Policy 计算:**
    * 提供了一系列独立的测试用例 (`URLRequestJobComputeReferrer`)，用于验证 `URLRequestJob::ComputeReferrerForPolicy` 函数在不同 Referrer Policy 和源/目标 URL 下的 referrer 计算逻辑。这包括：
        * 同源和跨域情况下的计算。
        * 处理 `nullptr` 输入。
        * 文件系统 URL 作为目标 URL 的情况。
        * 截断过长的 referrer。
        * 处理无效的 referrer scheme。
        * 启用 `kCapReferrerToOriginOnCrossOrigin` Feature 后的行为。

**与 JavaScript 的关系：间接相关**

`URLRequestJob` 本身是用 C++ 实现的，与 JavaScript 没有直接的代码级别的交互。然而，它在浏览器中扮演着关键角色，负责处理由 JavaScript 发起的网络请求。

**举例说明:**

1. **`fetch()` API:** 当 JavaScript 代码中使用 `fetch()` API 发起一个网络请求时，Chromium 的渲染进程会将这个请求传递给网络进程。网络进程会创建一个 `URLRequest` 对象，并由相应的 `URLRequestJob` 子类来处理这个请求。`URLRequestJob` 负责与网络层交互，获取响应数据，并最终将数据返回给渲染进程，供 JavaScript 使用。
2. **`XMLHttpRequest` (XHR):**  类似于 `fetch()`，当 JavaScript 使用 `XMLHttpRequest` 对象发起请求时，底层也会使用 `URLRequest` 和 `URLRequestJob` 来处理网络通信。
3. **图片加载和资源请求:**  浏览器加载网页时，JavaScript 可能会动态创建 `<img>` 标签或使用其他方式请求图片、CSS、JavaScript 文件等资源。这些资源请求同样会经过 `URLRequestJob` 进行处理。

**逻辑推理的假设输入与输出 (以 `TransactionNoFilter` 为例):**

**假设输入:**

* **URL:** `http://www.google.com/gzyp`
* **HTTP 方法:** `GET`
* **模拟的 HTTP 响应头:**
    ```
    HTTP/1.1 200 OK
    Cache-Control: max-age=10000
    Content-Length: 30
    ```
* **模拟的 HTTP 响应体:** `hello`

**预期输出:**

* `d.request_failed()` 为 `false` (请求未失败)。
* `req->GetResponseCode()` 为 `200` (HTTP 状态码为 200)。
* `d.data_received()` 为 `"hello"` (接收到的数据为 "hello")。
* `req->GetExpectedContentSize()` 为 `30` (期望的内容大小为 30，即使实际接收到的数据长度不同)。

**用户或编程常见的使用错误举例说明:**

虽然这个单元测试文件本身不涉及用户操作的错误，但它测试的 `URLRequestJob` 类在实际使用中可能会遇到以下错误，这些错误可能源于用户的操作或编程错误：

1. **内容编码错误:** 用户访问的网站返回了错误的 gzip 或 Brotli 编码数据，导致 `URLRequestJob` 解码失败，从而可能触发类似 `InvalidContentGZipTransaction` 测试中验证的错误。这可能是网站服务器配置错误或内容生成错误导致。
2. **重定向循环:** 用户访问的 URL 导致一系列的重定向，最终形成一个循环。`URLRequestJob` 需要能够检测并阻止这种无限循环，避免资源耗尽。虽然此文件没有直接测试重定向循环，但 `URLRequestJob` 具有处理此类情况的机制。
3. **不正确的 Referrer Policy 设置:**  网站开发者可能会设置错误的 `Referrer-Policy` 头部，导致浏览器在发送请求时传递了不期望的 referrer 信息，这与 `RedirectTransactionWithReferrerPolicyHeader` 和 `URLRequestJobComputeReferrer` 测试的场景相关。
4. **请求被拦截或重定向:**  用户的网络环境或浏览器扩展可能会拦截或重定向某些请求。 `TransactionNotCachedWhenNetworkDelegateRedirects` 测试了 `NetworkDelegate` 干预请求的情况。

**用户操作如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中访问了一个 URL，例如 `http://www.example.com/resource.gz`，并且该资源使用了 gzip 编码。

1. **用户在地址栏输入 URL 或点击链接。**
2. **浏览器渲染进程发起网络请求。**
3. **网络进程接收到请求，创建一个 `URLRequest` 对象。**
4. **网络进程根据 URL 的 scheme 和其他信息，选择合适的 `URLRequestJob` 子类来处理这个请求，例如 `HttpStreamJob`。**
5. **`HttpStreamJob` 与服务器建立连接，发送请求。**
6. **服务器返回 HTTP 响应，包含 `Content-Encoding: gzip` 头部。**
7. **`HttpStreamJob` 检测到 gzip 编码，会创建一个解压过滤器 (例如 `GzipDecompressor`)。**
8. **`URLRequestJob` (更具体地说是 `HttpStreamJob`) 在读取响应体时，会将原始数据通过解压过滤器进行处理。**
9. **如果解压过程中发生错误 (例如，数据损坏)，`URLRequestJob` 会将错误通知给 `URLRequest` 的委托对象 (通常是渲染进程)。**
10. **在开发或调试阶段，如果怀疑 `URLRequestJob` 的行为有问题，开发者可能会编写或运行 `net/url_request/url_request_job_unittest.cc` 中的相关测试用例，例如 `InvalidContentGZipTransaction`，来验证 `URLRequestJob` 在处理无效 gzip 数据时的行为是否符合预期。**

因此，`net/url_request/url_request_job_unittest.cc` 文件中的测试用例模拟了各种网络场景和响应，帮助开发者确保 `URLRequestJob` 在实际用户操作中能够正确、稳定地工作，并能处理各种异常情况。当用户遇到网络请求相关的问题时，理解 `URLRequestJob` 的工作原理和相应的测试可以帮助开发者缩小问题范围，定位 bug。

Prompt: 
```
这是目录为net/url_request/url_request_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_job.h"

#include <memory>
#include <optional>

#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "net/base/features.h"
#include "net/base/request_priority.h"
#include "net/http/http_transaction_test_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/referrer_policy.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/url_util.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

// Data encoded in kBrotliHelloData.
const char kHelloData[] = "hello, world!\n";
// kHelloData encoded with brotli.
const char kBrotliHelloData[] =
    "\033\015\0\0\244\024\102\152\020\111\152\072\235\126\034";

// This is a header that signals the end of the data.
const char kGzipData[] = "\x1f\x08b\x08\0\0\0\0\0\0\3\3\0\0\0\0\0\0\0\0";
const char kGzipDataWithName[] =
    "\x1f\x08b\x08\x08\0\0\0\0\0\0name\0\3\0\0\0\0\0\0\0\0";
// kHelloData encoded with gzip.
const char kGzipHelloData[] =
    "\x1f\x8b\x08\x08\x46\x7d\x4e\x56\x00\x03\x67\x7a\x69\x70\x2e\x74\x78\x74"
    "\x00\xcb\x48\xcd\xc9\xc9\xe7\x02\x00\x20\x30\x3a\x36\x06\x00\x00\x00";

void GZipServer(const HttpRequestInfo* request,
                std::string* response_status,
                std::string* response_headers,
                std::string* response_data) {
  response_data->assign(kGzipData, sizeof(kGzipData));
}

void GZipHelloServer(const HttpRequestInfo* request,
                     std::string* response_status,
                     std::string* response_headers,
                     std::string* response_data) {
  response_data->assign(kGzipHelloData, sizeof(kGzipHelloData) - 1);
}

void BigGZipServer(const HttpRequestInfo* request,
                   std::string* response_status,
                   std::string* response_headers,
                   std::string* response_data) {
  response_data->assign(kGzipDataWithName, sizeof(kGzipDataWithName));
  response_data->insert(10, 64 * 1024, 'a');
}

void BrotliHelloServer(const HttpRequestInfo* request,
                       std::string* response_status,
                       std::string* response_headers,
                       std::string* response_data) {
  response_data->assign(kBrotliHelloData, sizeof(kBrotliHelloData) - 1);
}

void MakeMockReferrerPolicyTransaction(const char* referer_header,
                                       const char* response_headers,
                                       MockTransaction* transaction) {
  transaction->method = "GET";
  transaction->request_time = base::Time();
  transaction->request_headers = referer_header;
  transaction->load_flags = LOAD_NORMAL;
  transaction->status = "HTTP/1.1 302 Found";
  transaction->response_headers = response_headers;
  transaction->response_time = base::Time();
  transaction->data = "hello";
  transaction->dns_aliases = {};
  transaction->test_mode = TEST_MODE_NORMAL;
  transaction->handler = MockTransactionHandler();
  transaction->read_handler = MockTransactionReadHandler();
  if (GURL(transaction->url).SchemeIsCryptographic()) {
    transaction->cert =
        net::ImportCertFromFile(net::GetTestCertsDirectory(), "ok_cert.pem");
  } else {
    transaction->cert = nullptr;
  }
  transaction->cert_status = 0;
  transaction->ssl_connection_status = 0;
  transaction->start_return_code = OK;
}

const MockTransaction kNoFilterTransaction = {
    "http://www.google.com/gzyp",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n"
    "Content-Length: 30\n",  // Intentionally wrong.
    base::Time(),
    "hello",
    {},
    std::nullopt,
    std::nullopt,
    TEST_MODE_NORMAL,
    MockTransactionHandler(),
    MockTransactionReadHandler(),
    nullptr,
    0,
    OK,
    OK,
};

const MockTransaction kNoFilterTransactionWithInvalidLength = {
    "http://www.google.com/gzyp",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n"
    "Content-Length: +30\n",  // Invalid
    base::Time(),
    "hello",
    {},
    std::nullopt,
    std::nullopt,
    TEST_MODE_NORMAL,
    MockTransactionHandler(),
    MockTransactionReadHandler(),
    nullptr,
    0,
    OK,
    OK,
};

const MockTransaction kGZipTransaction = {
    "http://www.google.com/gzyp",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n"
    "Content-Encoding: gzip\n"
    "Content-Length: 30\n",  // Intentionally wrong.
    base::Time(),
    "",
    {},
    std::nullopt,
    std::nullopt,
    TEST_MODE_NORMAL,
    base::BindRepeating(&GZipServer),
    MockTransactionReadHandler(),
    nullptr,
    0,
    0,
    OK,
    OK,
};

const MockTransaction kGzipSlowTransaction = {
    "http://www.google.com/gzyp",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n"
    "Content-Encoding: gzip\n",
    base::Time(),
    "",
    {},
    std::nullopt,
    std::nullopt,
    TEST_MODE_SLOW_READ,
    base::BindRepeating(&GZipHelloServer),
    MockTransactionReadHandler(),
    nullptr,
    0,
    0,
    OK,
    OK,
};

const MockTransaction kRedirectTransaction = {
    "http://www.google.com/redirect",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 302 Found",
    "Cache-Control: max-age=10000\n"
    "Location: http://www.google.com/destination\n"
    "Content-Length: 5\n",
    base::Time(),
    "hello",
    {},
    std::nullopt,
    std::nullopt,
    TEST_MODE_NORMAL,
    MockTransactionHandler(),
    MockTransactionReadHandler(),
    nullptr,
    0,
    0,
    OK,
    OK,
};

const MockTransaction kEmptyBodyGzipTransaction = {
    "http://www.google.com/empty_body",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Content-Encoding: gzip\n",
    base::Time(),
    "",
    {},
    std::nullopt,
    std::nullopt,
    TEST_MODE_NORMAL,
    MockTransactionHandler(),
    MockTransactionReadHandler(),
    nullptr,
    0,
    0,
    OK,
    OK,
};

const MockTransaction kInvalidContentGZipTransaction = {
    "http://www.google.com/gzyp",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Content-Encoding: gzip\n"
    "Content-Length: 21\n",
    base::Time(),
    "not a valid gzip body",
    {},
    std::nullopt,
    std::nullopt,
    TEST_MODE_NORMAL,
    MockTransactionHandler(),
    MockTransactionReadHandler(),
    nullptr,
    0,
    0,
    OK,
    OK,
};

const MockTransaction kBrotliSlowTransaction = {
    "http://www.google.com/brotli",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n"
    "Content-Encoding: br\n"
    "Content-Length: 230\n",  // Intentionally wrong.
    base::Time(),
    "",
    {},
    std::nullopt,
    std::nullopt,
    TEST_MODE_SLOW_READ,
    base::BindRepeating(&BrotliHelloServer),
    MockTransactionReadHandler(),
    nullptr,
    0,
    0,
    OK,
    OK,
};

}  // namespace

using URLRequestJobTest = TestWithTaskEnvironment;

TEST_F(URLRequestJobTest, TransactionNoFilter) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  context_builder->DisableHttpCache();
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kNoFilterTransaction);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  EXPECT_FALSE(d.request_failed());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ("hello", d.data_received());
  EXPECT_TRUE(network_layer->done_reading_called());
  // When there's no filter and a Content-Length, expected content size should
  // be available.
  EXPECT_EQ(30, req->GetExpectedContentSize());
}

TEST_F(URLRequestJobTest, TransactionNoFilterWithInvalidLength) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  context_builder->DisableHttpCache();
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kNoFilterTransactionWithInvalidLength);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  EXPECT_FALSE(d.request_failed());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ("hello", d.data_received());
  EXPECT_TRUE(network_layer->done_reading_called());
  // Invalid Content-Lengths that start with a + should not be reported.
  EXPECT_EQ(-1, req->GetExpectedContentSize());
}

TEST_F(URLRequestJobTest, TransactionNotifiedWhenDone) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  context_builder->DisableHttpCache();
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kGZipTransaction);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  EXPECT_TRUE(d.response_completed());
  EXPECT_EQ(OK, d.request_status());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ("", d.data_received());
  EXPECT_TRUE(network_layer->done_reading_called());
  // When there's a filter and a Content-Length, expected content size should
  // not be available.
  EXPECT_EQ(-1, req->GetExpectedContentSize());
}

TEST_F(URLRequestJobTest, SyncTransactionNotifiedWhenDone) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  context_builder->DisableHttpCache();
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kGZipTransaction);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(kGZipTransaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));
  transaction.test_mode = TEST_MODE_SYNC_ALL;

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  EXPECT_TRUE(d.response_completed());
  EXPECT_EQ(OK, d.request_status());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ("", d.data_received());
  EXPECT_TRUE(network_layer->done_reading_called());
  // When there's a filter and a Content-Length, expected content size should
  // not be available.
  EXPECT_EQ(-1, req->GetExpectedContentSize());
}

// Tests processing a large gzip header one byte at a time.
TEST_F(URLRequestJobTest, SyncSlowTransaction) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  context_builder->DisableHttpCache();
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kGZipTransaction);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));
  transaction.test_mode = TEST_MODE_SYNC_ALL | TEST_MODE_SLOW_READ;
  transaction.handler = base::BindRepeating(&BigGZipServer);

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  EXPECT_TRUE(d.response_completed());
  EXPECT_EQ(OK, d.request_status());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ("", d.data_received());
  EXPECT_TRUE(network_layer->done_reading_called());
  EXPECT_EQ(-1, req->GetExpectedContentSize());
}

TEST_F(URLRequestJobTest, RedirectTransactionNotifiedWhenDone) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  context_builder->DisableHttpCache();
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kRedirectTransaction);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  EXPECT_TRUE(network_layer->done_reading_called());
}

TEST_F(URLRequestJobTest, RedirectTransactionWithReferrerPolicyHeader) {
  struct TestCase {
    const char* original_url;
    const char* original_referrer;
    const char* response_headers;
    ReferrerPolicy original_referrer_policy;
    ReferrerPolicy expected_final_referrer_policy;
    const char* expected_final_referrer;
  };

  // Note: There are more thorough test cases in RedirectInfoTest.
  const TestCase kTests[] = {
      // If a redirect serves 'Referrer-Policy: no-referrer', then the referrer
      // should be cleared.
      {"http://foo.test/one" /* original url */,
       "http://foo.test/one" /* original referrer */,
       "Location: http://foo.test/test\n"
       "Referrer-Policy: no-referrer\n",
       // original policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       ReferrerPolicy::NO_REFERRER /* expected final policy */,
       "" /* expected final referrer */},

      // A redirect response without Referrer-Policy header should not affect
      // the policy and the referrer.
      {"http://foo.test/one" /* original url */,
       "http://foo.test/one" /* original referrer */,
       "Location: http://foo.test/test\n",
       // original policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       // expected final policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "http://foo.test/one" /* expected final referrer */},
  };

  for (const auto& test : kTests) {
    ScopedMockTransaction transaction(test.original_url);
    std::string request_headers =
        "Referer: " + std::string(test.original_referrer) + "\n";
    MakeMockReferrerPolicyTransaction(request_headers.c_str(),
                                      test.response_headers, &transaction);

    auto context_builder = CreateTestURLRequestContextBuilder();
    auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
        std::make_unique<MockNetworkLayer>());
    context_builder->DisableHttpCache();
    auto context = context_builder->Build();

    TestDelegate d;
    std::unique_ptr<URLRequest> req(
        context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                               TRAFFIC_ANNOTATION_FOR_TESTS));

    req->set_referrer_policy(test.original_referrer_policy);
    req->SetReferrer(test.original_referrer);

    req->set_method("GET");
    req->Start();

    d.RunUntilComplete();

    EXPECT_TRUE(network_layer->done_reading_called());

    // Test that the referrer policy and referrer were set correctly
    // according to the header received during the redirect.
    EXPECT_EQ(test.expected_final_referrer_policy, req->referrer_policy());
    EXPECT_EQ(test.expected_final_referrer, req->referrer());
  }
}

TEST_F(URLRequestJobTest, TransactionNotCachedWhenNetworkDelegateRedirects) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  auto network_delegate = std::make_unique<TestNetworkDelegate>();
  network_delegate->set_redirect_on_headers_received_url(GURL("http://foo"));
  context_builder->DisableHttpCache();
  context_builder->set_network_delegate(std::move(network_delegate));
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kGZipTransaction);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  EXPECT_TRUE(network_layer->stop_caching_called());
}

// Makes sure that ReadRawDataComplete correctly updates request status before
// calling ReadFilteredData.
// Regression test for crbug.com/553300.
TEST_F(URLRequestJobTest, EmptyBodySkipFilter) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  context_builder->DisableHttpCache();
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kEmptyBodyGzipTransaction);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  EXPECT_FALSE(d.request_failed());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_TRUE(d.data_received().empty());
  EXPECT_TRUE(network_layer->done_reading_called());
}

// Regression test for crbug.com/575213.
TEST_F(URLRequestJobTest, InvalidContentGZipTransaction) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  context_builder->DisableHttpCache();
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kInvalidContentGZipTransaction);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  // Request failed indicates the request failed before headers were received,
  // so should be false.
  EXPECT_FALSE(d.request_failed());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, d.request_status());
  EXPECT_TRUE(d.data_received().empty());
  EXPECT_FALSE(network_layer->done_reading_called());
}

// Regression test for crbug.com/553300.
TEST_F(URLRequestJobTest, SlowFilterRead) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  context_builder->DisableHttpCache();
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kGzipSlowTransaction);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  EXPECT_FALSE(d.request_failed());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ("hello\n", d.data_received());
  EXPECT_TRUE(network_layer->done_reading_called());
}

TEST_F(URLRequestJobTest, SlowBrotliRead) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto* network_layer = context_builder->SetHttpTransactionFactoryForTesting(
      std::make_unique<MockNetworkLayer>());
  context_builder->DisableHttpCache();
  auto context = context_builder->Build();

  ScopedMockTransaction transaction(kBrotliSlowTransaction);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL(transaction.url), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  req->set_method("GET");
  req->Start();

  d.RunUntilComplete();

  EXPECT_FALSE(d.request_failed());
  EXPECT_EQ(200, req->GetResponseCode());
  EXPECT_EQ(kHelloData, d.data_received());
  EXPECT_TRUE(network_layer->done_reading_called());
  // When there's a filter and a Content-Length, expected content size should
  // not be available.
  EXPECT_EQ(-1, req->GetExpectedContentSize());
}

TEST(URLRequestJobComputeReferrer, SetsSameOriginForMetricsOnSameOrigin) {
  bool same_origin = false;
  URLRequestJob::ComputeReferrerForPolicy(
      ReferrerPolicy(),
      /*original_referrer=*/GURL("http://google.com"),
      /*destination=*/GURL("http://google.com"), &same_origin);
  EXPECT_TRUE(same_origin);
}

TEST(URLRequestJobComputeReferrer, SetsSameOriginForMetricsOnCrossOrigin) {
  bool same_origin = true;
  URLRequestJob::ComputeReferrerForPolicy(
      ReferrerPolicy(),
      /*original_referrer=*/GURL("http://google.com"),
      /*destination=*/GURL("http://boggle.com"), &same_origin);
  EXPECT_FALSE(same_origin);
}

TEST(URLRequestJobComputeReferrer, AcceptsNullptrInput) {
  // Shouldn't segfault.
  URLRequestJob::ComputeReferrerForPolicy(ReferrerPolicy(), GURL(), GURL(),
                                          nullptr);
}

TEST(URLRequestJobComputeReferrer, FilesystemDestination) {
  EXPECT_EQ(URLRequestJob::ComputeReferrerForPolicy(
                ReferrerPolicy::NEVER_CLEAR, GURL("https://referrer.example"),
                GURL("filesystem:https://destination.example"), nullptr),
            GURL("https://referrer.example"));
}

TEST(URLRequestJobComputeReferrer, TruncatesLongReferrer) {
  std::string original_spec = "https://referrer.example/";
  original_spec.resize(4097, 'a');
  const GURL kOriginalReferrer(original_spec);

  EXPECT_EQ(URLRequestJob::ComputeReferrerForPolicy(ReferrerPolicy::NEVER_CLEAR,
                                                    kOriginalReferrer,
                                                    GURL("https://google.com")),
            GURL("https://referrer.example/"));
}

TEST(URLRequestJobComputeReferrer, DoesntTruncateShortReferrer) {
  std::string original_spec = "https://referrer.example/";
  original_spec.resize(4096, 'a');
  const GURL kOriginalReferrer(original_spec);

  EXPECT_EQ(URLRequestJob::ComputeReferrerForPolicy(ReferrerPolicy::NEVER_CLEAR,
                                                    kOriginalReferrer,
                                                    GURL("https://google.com")),
            kOriginalReferrer);
}

TEST(URLRequestJobComputeReferrer, DoesntTruncateEvenShorterReferrer) {
  std::string original_spec = "https://referrer.example/";
  original_spec.resize(4095, 'a');
  const GURL kOriginalReferrer(original_spec);

  EXPECT_EQ(URLRequestJob::ComputeReferrerForPolicy(ReferrerPolicy::NEVER_CLEAR,
                                                    kOriginalReferrer,
                                                    GURL("https://google.com")),
            kOriginalReferrer);
}

TEST(URLRequestJobComputeReferrer, DoesntTruncateReferrerWithLongRef) {
  // Because the "is the length greater than 4096?" check comes *after*
  // stripping the ref in the Referrer Policy spec, a URL that is short except
  // for having a very long ref should not be stripped to an origin by the "if
  // the length is too long, strip to the origin" check.
  EXPECT_EQ(URLRequestJob::ComputeReferrerForPolicy(
                ReferrerPolicy::NEVER_CLEAR,
                GURL(std::string("https://referrer.example/path#") +
                     std::string(5000, 'a')),
                GURL("https://google.com")),
            GURL("https://referrer.example/path"));
}

TEST(URLRequestJobComputeReferrer, InvalidSchemeReferrer) {
  const GURL kOriginalReferrer("about:blank");
  ASSERT_FALSE(url::IsReferrerScheme(
      kOriginalReferrer.spec().data(),
      kOriginalReferrer.parsed_for_possibly_invalid_spec().scheme));

  EXPECT_EQ(URLRequestJob::ComputeReferrerForPolicy(ReferrerPolicy::NEVER_CLEAR,
                                                    kOriginalReferrer,
                                                    GURL("https://google.com")),
            GURL());

  EXPECT_EQ(URLRequestJob::ComputeReferrerForPolicy(ReferrerPolicy::ORIGIN,
                                                    kOriginalReferrer,
                                                    GURL("https://google.com")),
            GURL());
}

TEST(URLRequestJobComputeReferrer, CapReferrerOnCrossOrigin) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kCapReferrerToOriginOnCrossOrigin);

  const GURL kOriginalReferrer("https://boggle.com/path");

  EXPECT_EQ(URLRequestJob::ComputeReferrerForPolicy(ReferrerPolicy::NEVER_CLEAR,
                                                    kOriginalReferrer,
                                                    GURL("https://google.com")),
            GURL("https://boggle.com/"));
}

TEST(URLRequestJobComputeReferrer,
     CapReferrerOnCrossOriginRespectsStricterPolicy) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kCapReferrerToOriginOnCrossOrigin);

  const GURL kOriginalReferrer("https://boggle.com/path");

  EXPECT_EQ(URLRequestJob::ComputeReferrerForPolicy(ReferrerPolicy::NO_REFERRER,
                                                    kOriginalReferrer,
                                                    GURL("https://google.com")),
            GURL());
}

TEST(URLRequestJobComputeReferrer,
     CapReferrerOnCrossOriginDoesntCapOnSameOrigin) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kCapReferrerToOriginOnCrossOrigin);

  const GURL kOriginalReferrer("https://boggle.com/path");

  EXPECT_EQ(URLRequestJob::ComputeReferrerForPolicy(ReferrerPolicy::NEVER_CLEAR,
                                                    kOriginalReferrer,
                                                    GURL("https://boggle.com")),
            kOriginalReferrer);
}

}  // namespace net

"""

```