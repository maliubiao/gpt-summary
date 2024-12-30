Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The core request is to analyze the provided C++ code (`http_transaction_test_util.cc`) and explain its purpose, its relationship to JavaScript (if any), and potential usage errors, along with debugging tips.

**2. Initial Code Scan & Identifying Key Structures:**

The first step is to quickly scan the code for prominent keywords and structures. This reveals:

* **Includes:**  Headers like `<algorithm>`, `<unordered_map>`, `<utility>`, `base/`, `net/`, `testing/gtest/include/gtest/gtest.h`, and `url/gurl.h`. This immediately signals that the code is part of a larger project (Chromium), deals with networking (`net/`), and is heavily involved in testing (`testing/gtest`).
* **Namespaces:** The code is within the `net` namespace.
* **`MockTransaction` struct:** This is a central data structure holding information about simulated HTTP transactions (URL, method, headers, body, etc.). The presence of `kSimpleGET_Transaction`, `kSimplePOST_Transaction`, etc., confirms this is test data.
* **`FindMockTransaction` function:** This function searches for a `MockTransaction` based on a URL. This is a crucial component for simulating server responses.
* **`ScopedMockTransaction` class:** This class manages the lifetime of a `MockTransaction`, adding and removing it from a global registry. This hints at a mechanism for setting up and tearing down test scenarios.
* **`TestTransactionConsumer` class:** This class seems to be a test utility for initiating and running HTTP transactions using a `HttpTransaction` interface. It handles the asynchronous nature of network requests.
* **`MockNetworkTransaction` class:**  This is the core of the mocking logic. It implements the `HttpTransaction` interface and uses the `MockTransaction` data to simulate server behavior. It handles starting requests, reading responses, and simulating different network conditions (e.g., slow reads).
* **`MockNetworkLayer` class:** This class acts as a factory for creating `MockNetworkTransaction` objects. It simulates the network layer in a testing environment.
* **Helper functions:** `ReadTransaction` simplifies reading the entire response body.

**3. Determining the Primary Functionality:**

Based on the identified structures, it becomes clear that the primary purpose of this file is to provide utilities for *testing* the HTTP transaction logic in Chromium's network stack. It allows developers to simulate various HTTP requests and server responses without needing a real network server.

**4. Analyzing the Relationship with JavaScript:**

The prompt specifically asks about the connection to JavaScript. The crucial link here is the browser context. JavaScript running in a web page makes HTTP requests. While this C++ code doesn't *directly* execute JavaScript or vice-versa, it's a fundamental part of the browser (Chromium) that *handles* those HTTP requests initiated by JavaScript.

* **Example:** A JavaScript `fetch()` call or an `XMLHttpRequest` will eventually be processed by Chromium's network stack, and during testing, components like `MockNetworkTransaction` can be used to simulate the server's response to that JavaScript-initiated request.

**5. Logical Inference and Examples:**

The next step is to demonstrate how the mocking mechanism works with examples. This involves:

* **Identifying the input:** The input to the system being tested is a `HttpRequestInfo` object (constructed from a JavaScript request, for instance).
* **Identifying the matching logic:** `FindMockTransaction` is the key to matching an incoming request with a predefined `MockTransaction`. The URL is the primary matching criterion.
* **Determining the output:** The output is a simulated `HttpResponseInfo` and response body.

**Hypothetical Input/Output Example:**

This example showcases the flow: a request comes in, it's matched to a `MockTransaction`, and the mock response is generated.

**6. Identifying Potential Usage Errors:**

Thinking about how developers might misuse these utilities leads to common errors:

* **Forgetting to register a `MockTransaction`:** If a test makes a request for which no mock is defined, the `FindMockTransaction` will return `nullptr`, leading to an error.
* **Incorrect mock data:** If the mock data doesn't accurately represent the expected server response, tests might fail unexpectedly.

**7. Debugging Guidance - Tracing User Actions:**

The prompt also asks how user actions lead to this code. This involves understanding the browser's request lifecycle:

* **User Action -> JavaScript Request:**  A user clicks a link, submits a form, or JavaScript code initiates a network request.
* **Browser Processes Request:** The browser's rendering engine or JavaScript engine creates a request object.
* **Network Stack Involvement:**  The request is passed to the network stack.
* **Testing with Mocks:** During testing, instead of going to a real network, the `MockNetworkLayer` intercepts the request.
* **`FindMockTransaction`:** The URL of the request is used to find a matching `MockTransaction`.
* **Simulated Response:** The data from the `MockTransaction` is used to create a simulated response.
* **Response Back to JavaScript:** The simulated response is returned to the JavaScript code, completing the cycle.

**8. Structuring the Answer:**

Finally, the information needs to be structured clearly and logically, addressing each part of the prompt:

* **Functionality:**  Clearly state the main purpose of the file.
* **JavaScript Relationship:** Explain the indirect connection through browser-initiated requests.
* **Logical Inference:** Provide the hypothetical input/output example.
* **Usage Errors:**  Give concrete examples of common mistakes.
* **Debugging:** Explain the user action flow leading to this code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this code directly interacts with JavaScript APIs.
* **Correction:** Realization that it's more about simulating the *server-side* of requests initiated by JavaScript.
* **Initial thought:** Focus heavily on the C++ implementation details.
* **Correction:** Shift focus to the *purpose* and *usage* of the utilities from a testing perspective.
* **Ensuring clarity:** Use clear and concise language, avoiding jargon where possible.

By following these steps, including the crucial step of understanding the broader context within the Chromium project and the role of testing, a comprehensive and accurate answer can be constructed.
这个文件 `net/http/http_transaction_test_util.cc` 是 Chromium 网络栈的一部分，它的主要功能是提供 **用于测试 `net::HttpTransaction` 及其相关组件的实用工具和模拟对象**。  简单来说，它帮助开发者在测试环境下模拟各种 HTTP 交互场景，而无需实际的网络连接。

以下是它的具体功能点：

**1. 模拟 HTTP 事务 (Mock Transactions):**

*   **`MockTransaction` 结构体:**  定义了一个用于描述模拟 HTTP 事务的数据结构。它包含了请求的 URL、方法、请求头、预期的响应状态码、响应头、响应体等信息。
*   **预定义的模拟事务 (Built-in Mock Transactions):**  文件中定义了一些常用的模拟事务，例如 `kSimpleGET_Transaction`， `kSimplePOST_Transaction` 等，方便快速使用。
*   **动态添加和查找模拟事务:**  提供了 `AddMockTransaction` 和 `FindMockTransaction` 函数，允许在测试中动态地注册和查找与特定 URL 匹配的模拟事务。这使得测试能够针对特定的 URL 返回预定义的响应。
*   **`ScopedMockTransaction` 类:**  一个 RAII 风格的类，用于方便地在作用域内注册和注销模拟事务，避免手动管理。

**2. 模拟 HTTP 请求 (Mock HTTP Request):**

*   **`MockHttpRequest` 类:**  根据 `MockTransaction` 的信息创建一个模拟的 `HttpRequestInfo` 对象。这用于模拟实际的 HTTP 请求对象，并可以生成缓存键。

**3. 测试 HTTP 事务消费者 (Test Transaction Consumer):**

*   **`TestTransactionConsumer` 类:**  一个用于发起和执行 HTTP 事务的测试工具。它使用 `HttpTransactionFactory` 创建 `HttpTransaction` 对象，并模拟了启动、读取响应等操作。它通过 `RunLoop` 来处理异步操作。

**4. 模拟网络事务 (Mock Network Transaction):**

*   **`MockNetworkTransaction` 类:**  这是模拟 HTTP 事务的核心实现。它继承自 `HttpTransaction`，但不进行实际的网络操作。相反，它查找与请求 URL 匹配的 `MockTransaction`，并根据其配置模拟响应。
*   **模拟各种场景:**  它可以模拟同步和异步的请求开始和数据读取，延迟读取，返回特定的错误码等。
*   **模拟认证:**  支持模拟需要认证的场景，可以根据请求头中的 `X-Require-Mock-Auth` 字段和预定义的响应状态码来触发认证流程。
*   **模拟连接信息:**  可以设置模拟的传输层信息（例如，连接类型、IP 地址、端口）。
*   **模拟重定向 (虽然代码中没有直接体现，但可以通过 `MockTransactionHandler` 回调来实现)。**

**5. 模拟网络层 (Mock Network Layer):**

*   **`MockNetworkLayer` 类:**  一个模拟的网络层工厂，用于创建 `MockNetworkTransaction` 对象。它实现了 `HttpTransactionFactory` 接口。
*   **控制事务行为:**  可以跟踪创建的事务数量，模拟停止缓存等操作。

**与 JavaScript 的关系：**

这个 C++ 文件本身不包含 JavaScript 代码，但它直接服务于测试那些与 JavaScript 交互的网络功能。

*   **举例说明：** 假设你在测试一个 JavaScript 功能，该功能使用 `fetch()` API 从 `http://www.google.com/` 获取数据。在你的 C++ 测试代码中，你可以使用 `ScopedMockTransaction` 注册一个针对 `http://www.google.com/` 的模拟事务 `kSimpleGET_Transaction`。当 JavaScript 代码在测试环境下执行 `fetch()` 时，Chromium 的网络栈会被引导到使用 `MockNetworkLayer` 创建的 `MockNetworkTransaction`。这个模拟事务会返回预定义的 `kSimpleGET_Transaction` 中的响应数据（"<html><body>Google Blah Blah</body></html>"），而不会真正发送网络请求。这样，你可以独立地测试 JavaScript 代码的网络交互逻辑，而无需依赖真实的 Google 服务器。

**逻辑推理，假设输入与输出：**

**假设输入：**

1. 一个 `HttpRequestInfo` 对象，其 `url` 为 `http://www.example.com/~foo/bar.html`，`method` 为 "GET"。
2. 当前已通过 `ScopedMockTransaction` 注册了 `kTypicalGET_Transaction`。
3. 使用 `MockNetworkLayer` 创建了一个 `MockNetworkTransaction` 来处理这个请求。

**逻辑推理过程：**

1. `MockNetworkTransaction::StartInternal` 被调用，传入 `HttpRequestInfo`。
2. `FindMockTransaction` 函数会被调用，使用请求的 URL (`http://www.example.com/~foo/bar.html`) 在已注册的模拟事务中查找匹配项。
3. 由于 `kTypicalGET_Transaction` 的 URL 与请求 URL 匹配，`FindMockTransaction` 返回指向 `kTypicalGET_Transaction` 的指针。
4. `MockNetworkTransaction` 会使用 `kTypicalGET_Transaction` 中的数据来模拟响应。
5. 当测试代码调用 `MockNetworkTransaction::Read` 时，它会返回 `kTypicalGET_Transaction` 中 `data` 字段的内容："<html><body>Google Blah Blah</body></html>"。
6. `MockNetworkTransaction::GetResponseInfo` 会返回一个 `HttpResponseInfo` 对象，其中包含了 `kTypicalGET_Transaction` 中的状态码 ("HTTP/1.1 200 OK") 和响应头 ("Date: Wed, 28 Nov 2007 09:40:09 GMT\nLast-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n")。

**假设输出：**

*   `MockNetworkTransaction::Read` 返回 `OK`，并将 "<html><body>Google Blah Blah</body></html>" 写入提供的缓冲区。
*   `MockNetworkTransaction::GetResponseInfo` 返回的 `HttpResponseInfo` 对象包含以下信息：
    *   状态码: "HTTP/1.1 200 OK"
    *   响应头:
        ```
        Date: Wed, 28 Nov 2007 09:40:09 GMT
        Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT
        ```
    *   `was_cached` 为 `false` (因为是模拟的网络请求)。

**用户或编程常见的使用错误：**

1. **忘记注册 `MockTransaction`:**  测试代码尝试发起一个请求，但没有预先注册针对该 URL 的 `MockTransaction`。这将导致 `FindMockTransaction` 返回 `nullptr`，`MockNetworkTransaction` 无法模拟响应，可能导致测试失败或崩溃。
    *   **例子：** 测试代码尝试请求 `http://example.test/api/data`，但没有使用 `ScopedMockTransaction` 添加相应的模拟事务。

2. **`MockTransaction` 数据配置错误:**  `MockTransaction` 中的响应状态码、响应头或响应体与测试期望的不一致。这会导致测试验证失败。
    *   **例子：**  测试期望服务器返回 404 错误，但 `MockTransaction` 配置的是 200 OK。

3. **在异步测试中没有正确处理 `ERR_IO_PENDING`:**  `MockNetworkTransaction` 可以模拟异步操作，如果测试代码没有正确处理 `Start` 或 `Read` 方法返回的 `ERR_IO_PENDING`，可能会导致测试提前结束或无法获取到模拟的响应。
    *   **例子：**  测试代码调用 `MockNetworkTransaction::Read` 后，没有等待回调完成就继续执行后续的断言。

4. **`MockTransaction` 的 URL 匹配错误:**  `FindMockTransaction` 使用 URL 的字符串进行匹配，如果注册的 `MockTransaction` 的 URL 与实际请求的 URL 不完全一致（例如，缺少或多余的斜杠，参数顺序不同），则无法找到匹配的模拟事务。
    *   **例子：**  注册了 `http://example.com/data` 的模拟事务，但测试代码请求的是 `http://example.com/data/`。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设一个开发者正在调试一个与网页加载缓慢相关的问题，该网页包含通过 JavaScript 发起的 `fetch()` 请求。

1. **用户在浏览器中访问网页:**  用户在 Chrome 浏览器中输入网址或点击链接，触发网页加载。
2. **JavaScript 发起 `fetch()` 请求:**  网页加载后，JavaScript 代码执行，调用 `fetch()` API 向服务器请求数据。
3. **Chromium 网络栈处理请求:**  浏览器内核接收到 `fetch()` 请求，并将其传递给网络栈进行处理。
4. **调试期间可能使用 Mock 进行本地测试:**  开发者可能为了隔离问题，在本地搭建了一个测试环境，并配置了使用 `MockNetworkLayer` 来模拟服务器行为。
5. **断点或日志输出:**  开发者可能会在 `MockNetworkTransaction::StartInternal` 或 `FindMockTransaction` 等关键函数设置断点，或者添加日志输出，以便观察请求是如何被路由到模拟事务的，以及匹配了哪个 `MockTransaction`。
6. **检查 `MockTransaction` 配置:**  如果发现请求匹配到了错误的 `MockTransaction`，或者没有找到匹配的 `MockTransaction`，开发者会检查测试代码中 `ScopedMockTransaction` 的使用情况，以及 `MockTransaction` 的 URL 和其他配置是否正确。
7. **分析异步操作:**  如果怀疑是异步操作处理不当导致的问题，开发者会检查 `TestTransactionConsumer` 或类似的测试工具中是否正确使用了 `RunLoop` 或其他机制来等待异步操作完成。
8. **查看 NetLog:**  Chromium 的 NetLog 可以记录网络事件的详细信息，包括请求的 URL、头信息、是否使用了缓存、连接信息等。开发者可以通过查看 NetLog 来追踪请求的整个生命周期，并判断是否按预期使用了模拟事务。

总而言之，`net/http/http_transaction_test_util.cc` 提供了一套强大的工具，使得 Chromium 的开发者能够有效地测试网络栈的各个组件，特别是 `HttpTransaction` 的行为，模拟各种网络场景，并隔离和调试网络相关的问题，而无需依赖真实的外部服务器。它在单元测试和集成测试中都扮演着重要的角色。

Prompt: 
```
这是目录为net/http/http_transaction_test_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_transaction_test_util.h"

#include <algorithm>
#include <unordered_map>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/clock.h"
#include "base/time/time.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/load_flags.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_errors.h"
#include "net/base/network_isolation_key.h"
#include "net/base/proxy_chain.h"
#include "net/base/schemeful_site.h"
#include "net/cert/x509_certificate.h"
#include "net/disk_cache/disk_cache.h"
#include "net/http/http_cache.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/http/http_transaction.h"
#include "net/log/net_log.h"
#include "net/log/net_log_source.h"
#include "net/ssl/ssl_private_key.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {
using MockTransactionMap =
    std::unordered_map<std::string, const MockTransaction*>;
static MockTransactionMap mock_transactions;

void AddMockTransaction(const MockTransaction* trans) {
  auto result =
      mock_transactions.insert(std::make_pair(GURL(trans->url).spec(), trans));
  CHECK(result.second) << "Transaction already exists: " << trans->url;
}

void RemoveMockTransaction(const MockTransaction* trans) {
  mock_transactions.erase(GURL(trans->url).spec());
}

}  // namespace

TransportInfo DefaultTransportInfo() {
  return TransportInfo(TransportType::kDirect,
                       IPEndPoint(IPAddress::IPv4Localhost(), 80),
                       /*accept_ch_frame_arg=*/"",
                       /*cert_is_issued_by_known_root=*/false, kProtoUnknown);
}

//-----------------------------------------------------------------------------
// mock transaction data

const MockTransaction kSimpleGET_Transaction = {
    "http://www.google.com/",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n",
    base::Time(),
    "<html><body>Google Blah Blah</body></html>",
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

const MockTransaction kSimplePOST_Transaction = {
    "http://bugdatabase.com/edit",
    "POST",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "",
    base::Time(),
    "<html><body>Google Blah Blah</body></html>",
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

const MockTransaction kTypicalGET_Transaction = {
    "http://www.example.com/~foo/bar.html",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
    "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n",
    base::Time(),
    "<html><body>Google Blah Blah</body></html>",
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

const MockTransaction kETagGET_Transaction = {
    "http://www.google.com/foopy",
    "GET",
    base::Time(),
    "",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n"
    "Etag: \"foopy\"\n",
    base::Time(),
    "<html><body>Google Blah Blah</body></html>",
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

const MockTransaction kRangeGET_Transaction = {
    "http://www.google.com/",
    "GET",
    base::Time(),
    "Range: 0-100\r\n",
    LOAD_NORMAL,
    DefaultTransportInfo(),
    "HTTP/1.1 200 OK",
    "Cache-Control: max-age=10000\n",
    base::Time(),
    "<html><body>Google Blah Blah</body></html>",
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

static const MockTransaction* const kBuiltinMockTransactions[] = {
  &kSimpleGET_Transaction,
  &kSimplePOST_Transaction,
  &kTypicalGET_Transaction,
  &kETagGET_Transaction,
  &kRangeGET_Transaction
};

const MockTransaction* FindMockTransaction(const GURL& url) {
  // look for overrides:
  MockTransactionMap::const_iterator it = mock_transactions.find(url.spec());
  if (it != mock_transactions.end())
    return it->second;

  // look for builtins:
  for (const auto* transaction : kBuiltinMockTransactions) {
    if (url == GURL(transaction->url))
      return transaction;
  }
  return nullptr;
}

ScopedMockTransaction::ScopedMockTransaction(const char* url)
    : MockTransaction({nullptr}) {
  CHECK(url);
  this->url = url;
  AddMockTransaction(this);
}

ScopedMockTransaction::ScopedMockTransaction(const MockTransaction& t,
                                             const char* url)
    : MockTransaction(t) {
  if (url) {
    this->url = url;
  }
  AddMockTransaction(this);
}

ScopedMockTransaction::~ScopedMockTransaction() {
  RemoveMockTransaction(this);
}

MockHttpRequest::MockHttpRequest(const MockTransaction& t) {
  url = GURL(t.url);
  method = t.method;
  extra_headers.AddHeadersFromString(t.request_headers);
  load_flags = t.load_flags;
  SchemefulSite site(url);
  network_isolation_key = NetworkIsolationKey(site, site);
  network_anonymization_key = NetworkAnonymizationKey::CreateSameSite(site);
  frame_origin = url::Origin::Create(url);
  fps_cache_filter = t.fps_cache_filter;
  browser_run_id = t.browser_run_id;
}

std::string MockHttpRequest::CacheKey() {
  return *HttpCache::GenerateCacheKeyForRequest(this);
}

//-----------------------------------------------------------------------------

TestTransactionConsumer::TestTransactionConsumer(
    RequestPriority priority,
    HttpTransactionFactory* factory) {
  // Disregard the error code.
  factory->CreateTransaction(priority, &trans_);
}

TestTransactionConsumer::~TestTransactionConsumer() = default;

void TestTransactionConsumer::Start(const HttpRequestInfo* request,
                                    const NetLogWithSource& net_log) {
  state_ = State::kStarting;
  int result =
      trans_->Start(request,
                    base::BindOnce(&TestTransactionConsumer::OnIOComplete,
                                   base::Unretained(this)),
                    net_log);
  if (result != ERR_IO_PENDING)
    DidStart(result);

  base::RunLoop loop;
  quit_closure_ = loop.QuitClosure();
  loop.Run();
}

void TestTransactionConsumer::DidStart(int result) {
  if (result != OK) {
    DidFinish(result);
  } else {
    Read();
  }
}

void TestTransactionConsumer::DidRead(int result) {
  if (result <= 0) {
    DidFinish(result);
  } else {
    content_.append(read_buf_->data(), result);
    Read();
  }
}

void TestTransactionConsumer::DidFinish(int result) {
  state_ = State::kDone;
  error_ = result;
  if (!quit_closure_.is_null()) {
    std::move(quit_closure_).Run();
  }
}

void TestTransactionConsumer::Read() {
  state_ = State::kReading;
  read_buf_ = base::MakeRefCounted<IOBufferWithSize>(1024);
  int result =
      trans_->Read(read_buf_.get(), 1024,
                   base::BindOnce(&TestTransactionConsumer::OnIOComplete,
                                  base::Unretained(this)));
  if (result != ERR_IO_PENDING)
    DidRead(result);
}

void TestTransactionConsumer::OnIOComplete(int result) {
  switch (state_) {
    case State::kStarting:
      DidStart(result);
      break;
    case State::kReading:
      DidRead(result);
      break;
    default:
      NOTREACHED();
  }
}

MockNetworkTransaction::MockNetworkTransaction(RequestPriority priority,
                                               MockNetworkLayer* factory)
    : priority_(priority), transaction_factory_(factory->AsWeakPtr()) {}

MockNetworkTransaction::~MockNetworkTransaction() {
  // Use `original_request_ptr_` as in ~HttpNetworkTransaction to make sure its
  // valid and not already freed by the consumer. Only check till Read is
  // invoked since HttpNetworkTransaction sets request_ to nullptr when Read is
  // invoked. See crbug.com/734037.
  if (original_request_ptr_ && !reading_) {
    DCHECK(original_request_ptr_->load_flags >= 0);
  }
}

int MockNetworkTransaction::Start(const HttpRequestInfo* request,
                                  CompletionOnceCallback callback,
                                  const NetLogWithSource& net_log) {
  net_log_ = net_log;
  CHECK(!original_request_ptr_);
  original_request_ptr_ = request;
  return StartInternal(*request, std::move(callback));
}

int MockNetworkTransaction::RestartIgnoringLastError(
    CompletionOnceCallback callback) {
  return ERR_FAILED;
}

int MockNetworkTransaction::RestartWithCertificate(
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> client_private_key,
    CompletionOnceCallback callback) {
  return ERR_FAILED;
}

int MockNetworkTransaction::RestartWithAuth(const AuthCredentials& credentials,
                                            CompletionOnceCallback callback) {
  if (!IsReadyToRestartForAuth())
    return ERR_FAILED;

  HttpRequestInfo auth_request_info = *original_request_ptr_;
  auth_request_info.extra_headers.SetHeader("Authorization", "Bar");

  // Let the MockTransactionHandler worry about this: the only way for this
  // test to succeed is by using an explicit handler for the transaction so
  // that server behavior can be simulated.
  return StartInternal(std::move(auth_request_info), std::move(callback));
}

void MockNetworkTransaction::PopulateNetErrorDetails(
    NetErrorDetails* /*details*/) const {
  NOTIMPLEMENTED();
}

bool MockNetworkTransaction::IsReadyToRestartForAuth() {
  CHECK(original_request_ptr_);
  if (!original_request_ptr_->extra_headers.HasHeader("X-Require-Mock-Auth")) {
    return false;
  }

  // Allow the mock server to decide whether authentication is required or not.
  std::string status_line = response_.headers->GetStatusLine();
  return status_line.find(" 401 ") != std::string::npos ||
      status_line.find(" 407 ") != std::string::npos;
}

int MockNetworkTransaction::Read(IOBuffer* buf,
                                 int buf_len,
                                 CompletionOnceCallback callback) {
  const MockTransaction* t = FindMockTransaction(current_request_.url);
  DCHECK(t);

  CHECK(!done_reading_called_);
  reading_ = true;

  int num = t->read_return_code;

  if (OK == num) {
    if (t->read_handler) {
      num = t->read_handler.Run(content_length_, data_cursor_, buf, buf_len);
      data_cursor_ += num;
    } else {
      int data_len = static_cast<int>(data_.size());
      num = std::min(static_cast<int64_t>(buf_len), data_len - data_cursor_);
      if (test_mode_ & TEST_MODE_SLOW_READ)
        num = std::min(num, 1);
      if (num) {
        memcpy(buf->data(), data_.data() + data_cursor_, num);
        data_cursor_ += num;
      }
    }
  }

  if (test_mode_ & TEST_MODE_SYNC_NET_READ)
    return num;

  CallbackLater(std::move(callback), num);
  return ERR_IO_PENDING;
}

void MockNetworkTransaction::StopCaching() {
  if (transaction_factory_.get())
    transaction_factory_->TransactionStopCaching();
}

int64_t MockNetworkTransaction::GetTotalReceivedBytes() const {
  return received_bytes_;
}

int64_t MockNetworkTransaction::GetTotalSentBytes() const {
  return sent_bytes_;
}

int64_t MockNetworkTransaction::GetReceivedBodyBytes() const {
  return received_body_bytes_;
}

void MockNetworkTransaction::DoneReading() {
  CHECK(!done_reading_called_);
  done_reading_called_ = true;
  if (transaction_factory_.get())
    transaction_factory_->TransactionDoneReading();
}

const HttpResponseInfo* MockNetworkTransaction::GetResponseInfo() const {
  return &response_;
}

LoadState MockNetworkTransaction::GetLoadState() const {
  if (data_cursor_)
    return LOAD_STATE_READING_RESPONSE;
  return LOAD_STATE_IDLE;
}

void MockNetworkTransaction::SetQuicServerInfo(
    QuicServerInfo* quic_server_info) {
}

bool MockNetworkTransaction::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  if (socket_log_id_ != NetLogSource::kInvalidId) {
    // The minimal set of times for a request that gets a response, assuming it
    // gets a new socket.
    load_timing_info->socket_reused = false;
    load_timing_info->socket_log_id = socket_log_id_;
    load_timing_info->connect_timing.connect_start = base::TimeTicks::Now();
    load_timing_info->connect_timing.connect_end = base::TimeTicks::Now();
    load_timing_info->send_start = base::TimeTicks::Now();
    load_timing_info->send_end = base::TimeTicks::Now();
  } else {
    // If there's no valid socket ID, just use the generic socket reused values.
    // No tests currently depend on this, just should not match the values set
    // by a cache hit.
    load_timing_info->socket_reused = true;
    load_timing_info->send_start = base::TimeTicks::Now();
    load_timing_info->send_end = base::TimeTicks::Now();
  }
  return true;
}

bool MockNetworkTransaction::GetRemoteEndpoint(IPEndPoint* endpoint) const {
  *endpoint = IPEndPoint(IPAddress(127, 0, 0, 1), 80);
  return true;
}

void MockNetworkTransaction::SetPriority(RequestPriority priority) {
  priority_ = priority;
}

void MockNetworkTransaction::SetWebSocketHandshakeStreamCreateHelper(
    WebSocketHandshakeStreamBase::CreateHelper* create_helper) {
  websocket_handshake_stream_create_helper_ = create_helper;
}

// static
const int64_t MockNetworkTransaction::kTotalReceivedBytes = 1000;

// static
const int64_t MockNetworkTransaction::kTotalSentBytes = 100;

// static
const int64_t MockNetworkTransaction::kReceivedBodyBytes = 500;

int MockNetworkTransaction::StartInternal(HttpRequestInfo request,
                                          CompletionOnceCallback callback) {
  current_request_ = std::move(request);
  const MockTransaction* t = FindMockTransaction(current_request_.url);
  if (!t) {
    return ERR_FAILED;
  }
  test_mode_ = t->test_mode;

  // Return immediately if we're returning an error.
  if (OK != t->start_return_code) {
    if (test_mode_ & TEST_MODE_SYNC_NET_START) {
      return t->start_return_code;
    }
    CallbackLater(std::move(callback), t->start_return_code);
    return ERR_IO_PENDING;
  }

  next_state_ = State::NOTIFY_BEFORE_CREATE_STREAM;
  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING) {
    callback_ = std::move(callback);
  }
  return rv;
}

int MockNetworkTransaction::DoNotifyBeforeCreateStream() {
  next_state_ = State::CREATE_STREAM;
  bool defer = false;
  if (!before_network_start_callback_.is_null()) {
    std::move(before_network_start_callback_).Run(&defer);
  }
  if (!defer) {
    return OK;
  }
  return ERR_IO_PENDING;
}

int MockNetworkTransaction::DoCreateStream() {
  next_state_ = State::CREATE_STREAM_COMPLETE;
  if (test_mode_ & TEST_MODE_SYNC_NET_START) {
    return OK;
  }
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&MockNetworkTransaction::OnIOComplete,
                                weak_factory_.GetWeakPtr(), OK));
  return ERR_IO_PENDING;
}

int MockNetworkTransaction::DoCreateStreamComplete(int result) {
  // We don't have a logic which simulate stream creation
  CHECK_EQ(OK, result);
  next_state_ = State::CONNECTED_CALLBACK;
  return OK;
}

int MockNetworkTransaction::DoConnectedCallback() {
  next_state_ = State::CONNECTED_CALLBACK_COMPLETE;
  if (connected_callback_.is_null()) {
    return OK;
  }

  const MockTransaction* t = FindMockTransaction(current_request_.url);
  CHECK(t);
  return connected_callback_.Run(
      t->transport_info, base::BindOnce(&MockNetworkTransaction::OnIOComplete,
                                        weak_factory_.GetWeakPtr()));
}

int MockNetworkTransaction::DoConnectedCallbackComplete(int result) {
  if (result != OK) {
    return result;
  }
  next_state_ = State::BUILD_REQUEST;
  return OK;
}

int MockNetworkTransaction::DoBuildRequest() {
  next_state_ = State::BUILD_REQUEST_COMPLETE;
  if (modify_request_headers_callback_) {
    modify_request_headers_callback_.Run(&current_request_.extra_headers);
  }
  return OK;
}

int MockNetworkTransaction::DoBuildRequestComplete(int result) {
  CHECK_EQ(OK, result);
  next_state_ = State::SEND_REQUEST;
  return OK;
}

int MockNetworkTransaction::DoSendRequest() {
  next_state_ = State::SEND_REQUEST_COMPLETE;

  sent_bytes_ = kTotalSentBytes;
  received_bytes_ = kTotalReceivedBytes;
  received_body_bytes_ = kReceivedBodyBytes;

  const MockTransaction* t = FindMockTransaction(current_request_.url);
  CHECK(t);

  std::string resp_status = t->status;
  std::string resp_headers = t->response_headers;
  std::string resp_data = t->data;

  if (t->handler) {
    t->handler.Run(&current_request_, &resp_status, &resp_headers, &resp_data);
  }
  std::string header_data =
      base::StringPrintf("%s\n%s\n", resp_status.c_str(), resp_headers.c_str());
  std::replace(header_data.begin(), header_data.end(), '\n', '\0');

  response_.request_time = transaction_factory_->Now();
  if (!t->request_time.is_null())
    response_.request_time = t->request_time;

  response_.was_cached = false;
  response_.network_accessed = true;
  response_.remote_endpoint = t->transport_info.endpoint;
  if (t->transport_info.type == TransportType::kDirect) {
    response_.proxy_chain = ProxyChain::Direct();
  } else if (t->transport_info.type == TransportType::kProxied) {
    response_.proxy_chain = ProxyChain::FromSchemeHostAndPort(
        ProxyServer::SCHEME_HTTP,
        t->transport_info.endpoint.ToStringWithoutPort(),
        t->transport_info.endpoint.port());
  }

  response_.response_time = transaction_factory_->Now();
  if (!t->response_time.is_null()) {
    response_.response_time = t->response_time;
    response_.original_response_time = t->response_time;
  }

  response_.headers = base::MakeRefCounted<HttpResponseHeaders>(header_data);
  response_.ssl_info.cert = t->cert;
  response_.ssl_info.cert_status = t->cert_status;
  response_.ssl_info.connection_status = t->ssl_connection_status;
  response_.dns_aliases = t->dns_aliases;
  data_ = resp_data;
  content_length_ = response_.headers->GetContentLength();

  if (net_log_.net_log()) {
    socket_log_id_ = net_log_.net_log()->NextID();
  }

  if (current_request_.load_flags & LOAD_PREFETCH) {
    response_.unused_since_prefetch = true;
  }

  if (current_request_.load_flags & LOAD_RESTRICTED_PREFETCH_FOR_MAIN_FRAME) {
    DCHECK(response_.unused_since_prefetch);
    response_.restricted_prefetch = true;
  }
  return OK;
}

int MockNetworkTransaction::DoSendRequestComplete(int result) {
  CHECK_EQ(OK, result);
  next_state_ = State::READ_HEADERS;
  return OK;
}

int MockNetworkTransaction::DoReadHeaders() {
  next_state_ = State::READ_HEADERS_COMPLETE;
  return OK;
}

int MockNetworkTransaction::DoReadHeadersComplete(int result) {
  CHECK_EQ(OK, result);
  return OK;
}

int MockNetworkTransaction::DoLoop(int result) {
  CHECK(next_state_ != State::NONE);

  int rv = result;
  do {
    State state = next_state_;
    next_state_ = State::NONE;
    switch (state) {
      case State::NOTIFY_BEFORE_CREATE_STREAM:
        CHECK_EQ(OK, rv);
        rv = DoNotifyBeforeCreateStream();
        break;
      case State::CREATE_STREAM:
        CHECK_EQ(OK, rv);
        rv = DoCreateStream();
        break;
      case State::CREATE_STREAM_COMPLETE:
        rv = DoCreateStreamComplete(rv);
        break;
      case State::CONNECTED_CALLBACK:
        rv = DoConnectedCallback();
        break;
      case State::CONNECTED_CALLBACK_COMPLETE:
        rv = DoConnectedCallbackComplete(rv);
        break;
      case State::BUILD_REQUEST:
        CHECK_EQ(OK, rv);
        rv = DoBuildRequest();
        break;
      case State::BUILD_REQUEST_COMPLETE:
        rv = DoBuildRequestComplete(rv);
        break;
      case State::SEND_REQUEST:
        CHECK_EQ(OK, rv);
        rv = DoSendRequest();
        break;
      case State::SEND_REQUEST_COMPLETE:
        rv = DoSendRequestComplete(rv);
        break;
      case State::READ_HEADERS:
        CHECK_EQ(OK, rv);
        rv = DoReadHeaders();
        break;
      case State::READ_HEADERS_COMPLETE:
        rv = DoReadHeadersComplete(rv);
        break;
      default:
        NOTREACHED() << "bad state";
    }
  } while (rv != ERR_IO_PENDING && next_state_ != State::NONE);

  return rv;
}

void MockNetworkTransaction::OnIOComplete(int result) {
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    CHECK(callback_);
    std::move(callback_).Run(rv);
  }
}

void MockNetworkTransaction::SetBeforeNetworkStartCallback(
    BeforeNetworkStartCallback callback) {
  before_network_start_callback_ = std::move(callback);
}

void MockNetworkTransaction::SetModifyRequestHeadersCallback(
    base::RepeatingCallback<void(HttpRequestHeaders*)> callback) {
  modify_request_headers_callback_ = std::move(callback);
}

void MockNetworkTransaction::SetConnectedCallback(
    const ConnectedCallback& callback) {
  connected_callback_ = callback;
}

int MockNetworkTransaction::ResumeNetworkStart() {
  CHECK_EQ(next_state_, State::CREATE_STREAM);
  return DoLoop(OK);
}

ConnectionAttempts MockNetworkTransaction::GetConnectionAttempts() const {
  // TODO(ricea): Replace this with a proper implementation if needed.
  return {};
}

void MockNetworkTransaction::CloseConnectionOnDestruction() {
  NOTIMPLEMENTED();
}

bool MockNetworkTransaction::IsMdlMatchForMetrics() const {
  return false;
}

void MockNetworkTransaction::CallbackLater(CompletionOnceCallback callback,
                                           int result) {
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&MockNetworkTransaction::RunCallback,
                     weak_factory_.GetWeakPtr(), std::move(callback), result));
}

void MockNetworkTransaction::RunCallback(CompletionOnceCallback callback,
                                         int result) {
  std::move(callback).Run(result);
}

MockNetworkLayer::MockNetworkLayer() = default;

MockNetworkLayer::~MockNetworkLayer() = default;

void MockNetworkLayer::TransactionDoneReading() {
  CHECK(!done_reading_called_);
  done_reading_called_ = true;
}

void MockNetworkLayer::TransactionStopCaching() {
  stop_caching_called_ = true;
}

void MockNetworkLayer::ResetTransactionCount() {
  transaction_count_ = 0;
}

int MockNetworkLayer::CreateTransaction(
    RequestPriority priority,
    std::unique_ptr<HttpTransaction>* trans) {
  transaction_count_++;
  last_create_transaction_priority_ = priority;
  auto mock_transaction =
      std::make_unique<MockNetworkTransaction>(priority, this);
  last_transaction_ = mock_transaction->AsWeakPtr();
  *trans = std::move(mock_transaction);
  return OK;
}

HttpCache* MockNetworkLayer::GetCache() {
  return nullptr;
}

HttpNetworkSession* MockNetworkLayer::GetSession() {
  return nullptr;
}

void MockNetworkLayer::SetClock(base::Clock* clock) {
  DCHECK(!clock_);
  clock_ = clock;
}

base::Time MockNetworkLayer::Now() {
  if (clock_)
    return clock_->Now();
  return base::Time::Now();
}

//-----------------------------------------------------------------------------
// helpers

int ReadTransaction(HttpTransaction* trans, std::string* result) {
  int rv;

  std::string content;
  do {
    TestCompletionCallback callback;
    auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
    rv = trans->Read(buf.get(), 256, callback.callback());
    if (rv == ERR_IO_PENDING) {
      rv = callback.WaitForResult();
      base::RunLoop().RunUntilIdle();
    }

    if (rv > 0)
      content.append(buf->data(), rv);
    else if (rv < 0)
      return rv;
  } while (rv > 0);

  result->swap(content);
  return OK;
}

//-----------------------------------------------------------------------------
// connected callback handler

ConnectedHandler::ConnectedHandler() = default;
ConnectedHandler::~ConnectedHandler() = default;

ConnectedHandler::ConnectedHandler(const ConnectedHandler&) = default;
ConnectedHandler& ConnectedHandler::operator=(const ConnectedHandler&) =
    default;
ConnectedHandler::ConnectedHandler(ConnectedHandler&&) = default;
ConnectedHandler& ConnectedHandler::operator=(ConnectedHandler&&) = default;

int ConnectedHandler::OnConnected(const TransportInfo& info,
                                  CompletionOnceCallback callback) {
  transports_.push_back(info);
  if (run_callback_) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(callback), result_));
    return ERR_IO_PENDING;
  }
  return result_;
}

}  // namespace net

"""

```