Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Core Request:**

The user wants to understand the functionality of `url_request_test_util.cc` within the Chromium networking stack. They also want to know about:

* **Relationship to JavaScript:** How does this low-level C++ code interact with the higher-level JavaScript used in web browsers?
* **Logical Reasoning (Input/Output):** What are some typical use cases and the expected outcomes?
* **Common User/Programming Errors:** How might a developer misuse these utility functions?
* **Debugging Context:** How does one end up interacting with this code during debugging?

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for key terms and patterns. I'm looking for:

* **Test-related keywords:** `Test`, `Mock`, `EXPECT`, `RunUntil`, `Filtering`. This immediately suggests the file's purpose is testing.
* **Networking concepts:** `URLRequest`, `NetworkDelegate`, `Cookie`, `Proxy`, `SSL`, `Redirect`, `Headers`, `Http`. These indicate the domain the code operates in.
* **Chromium-specific classes:** `URLRequestContextBuilder`, `URLRequestFilter`.
* **Data structures:** `std::unique_ptr`, `scoped_refptr`, `base::RunLoop`.
* **Delegation pattern:** The presence of `NetworkDelegate` and methods like `OnBeforeURLRequest`, `OnResponseStarted` etc., strongly suggest a delegation pattern is being used for intercepting and observing network requests.

**3. Identifying Key Classes and Their Roles:**

Based on the keywords and structure, I start to identify the core classes and their responsibilities:

* **`TestDelegate`:**  A simple `URLRequest::Delegate` implementation for testing. It provides basic event handling and allows waiting for request completion, redirects, or authentication.
* **`TestNetworkDelegate`:** A more comprehensive `NetworkDelegate` implementation for testing. Crucially, it tracks the order of network events (`next_states_`, `event_order_`), allows simulating errors and redirects, and provides fine-grained control over cookies.
* **`TestURLRequestContextGetter`:**  A way to create and manage `URLRequestContext` instances for testing, often with mocked or controlled dependencies.
* **`TestScopedURLInterceptor`:** A mechanism to intercept specific URL requests and inject a custom `URLRequestJob`, effectively mocking the network response for those requests.
* **Helper functions:** `CreateTestURLRequestContextBuilder`.

**4. Analyzing Functionality and Grouping:**

Now, I systematically go through the code, grouping related functionalities:

* **Request Lifecycle Observation:** `TestNetworkDelegate`'s event tracking (`OnBeforeURLRequest`, `OnResponseStarted`, `OnCompleted`, etc.).
* **Controlling Request Behavior:**  `TestNetworkDelegate`'s flags like `cancel_in_rr_`, `redirect_on_headers_received_url_`, and methods to set credentials or allow certificate errors.
* **Cookie Manipulation:** `TestNetworkDelegate`'s methods like `OnCanSetCookie`, `OnAnnotateAndMoveUserBlockedCookies`, and `FilteringTestNetworkDelegate`.
* **Request Interception and Mocking:** `TestScopedURLInterceptor`.
* **Context Creation:** `TestURLRequestContextGetter` and `CreateTestURLRequestContextBuilder`.

**5. Addressing JavaScript Interaction:**

This is a crucial part of the request. The key insight is that this C++ code *directly* doesn't run JavaScript. However, it *enables* testing of the networking layer that JavaScript relies on. I need to explain the indirect relationship:

* JavaScript (in a browser or Node.js using Chromium's networking) makes network requests.
* The Chromium networking stack (written in C++) handles these requests.
* `url_request_test_util.cc` provides tools to *simulate* and *observe* the behavior of this C++ networking stack in a controlled environment.
* This allows testing how the C++ networking code behaves in scenarios that JavaScript might trigger (e.g., redirects, cookie setting, authentication).

**6. Crafting Examples and Scenarios (Logical Reasoning):**

For input/output examples, I focus on demonstrating the core functionalities:

* **Redirects:**  Show how `TestDelegate` and `TestNetworkDelegate` can be used to simulate and observe redirects.
* **Request Cancellation:** Demonstrate how to cancel a request at different stages.
* **Cookie Blocking:** Illustrate how `TestNetworkDelegate` can be used to block cookies.
* **Request Interception:**  Show how `TestScopedURLInterceptor` can provide a mocked response.

**7. Identifying Common Errors:**

I think about how a developer using these utilities might make mistakes:

* **Incorrect Event Order Assumptions:**  Not understanding or mishandling the expected sequence of `NetworkDelegate` events.
* **Forgetting `RunUntilComplete()`:**  Not waiting for asynchronous operations to finish.
* **Misconfiguring Interceptors:**  Setting up interceptors that don't match the intended requests.
* **Not Cleaning Up Resources:**  Although RAII helps, being mindful of the lifetime of test objects is important.

**8. Constructing the Debugging Narrative:**

The goal here is to connect the low-level C++ to user actions:

* Start with a user action in the browser (typing a URL, clicking a link).
* Trace the journey through JavaScript APIs, browser processes, and finally down to the C++ networking stack.
* Explain how, during debugging, a developer might set breakpoints in `url_request_test_util.cc` when investigating network-related issues, especially during automated testing or when examining specific network delegate behavior.

**9. Structuring the Answer:**

Finally, I organize the information logically, using headings and bullet points for clarity. I address each part of the user's request explicitly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file has some direct JavaScript binding. **Correction:** After closer examination, it's clear the interaction is indirect, through testing the underlying C++ networking layer.
* **Initial thought:** Focus only on individual functions. **Correction:** Emphasize the interaction between different classes (e.g., `TestDelegate` and `TestNetworkDelegate`).
* **Initial thought:** Provide very technical details of every function. **Correction:**  Focus on the *purpose* and common use cases of the key classes and methods, rather than an exhaustive API description.

By following this systematic approach, I can thoroughly analyze the code and provide a comprehensive and helpful answer to the user's request.
这个文件 `net/url_request/url_request_test_util.cc` 是 Chromium 网络栈中专门用于 **测试** `URLRequest` 及其相关功能的工具库。它提供了一系列辅助类和函数，使得编写针对网络请求的单元测试变得更加方便和可靠。

以下是它的主要功能：

**1. 模拟和控制网络请求行为:**

* **`TestDelegate`:**  一个简单的 `URLRequest::Delegate` 的实现，用于在测试中接收 `URLRequest` 的回调事件。它可以用来验证请求是否完成、是否发生了重定向、是否需要认证，以及接收响应数据等。
* **`TestNetworkDelegate`:** 一个更强大的 `NetworkDelegate` 实现，允许对网络请求的各个阶段进行细粒度的控制和观察。它可以用来模拟网络错误、强制重定向、检查请求头和响应头、控制 cookie 的设置和获取等。
* **`FilteringTestNetworkDelegate`:** 继承自 `TestNetworkDelegate`，增加了基于规则过滤 cookie 的功能，方便测试 cookie 相关的策略。
* **`TestScopedURLInterceptor`:**  允许你拦截特定的 URL 请求，并用预先定义的 `URLRequestJob` 来响应，从而模拟特定的服务器行为，例如返回特定的响应或错误。

**2. 创建测试用的 `URLRequestContext`:**

* **`CreateTestURLRequestContextBuilder()`:**  创建一个 `URLRequestContextBuilder` 对象，并预先配置了一些常用的测试设置，例如使用 `MockCachingHostResolver` (模拟 DNS 解析)、禁用代理等。
* **`TestURLRequestContextGetter`:**  提供一个方便的方式来获取测试用的 `URLRequestContext`。

**3. 辅助测试的工具函数和常量:**

* 定义了一些常量，例如 `kBufferSize` (用于读取响应数据的缓冲区大小) 和用于标识 `TestNetworkDelegate` 中请求 ID 的键值。

**与 JavaScript 功能的关系:**

这个 C++ 文件本身不直接运行 JavaScript 代码。然而，它为测试 Chromium 网络栈提供了基础，而这个网络栈是 JavaScript 发起网络请求的基础。

**举例说明:**

假设一段 JavaScript 代码尝试发起一个跨域请求，并且预期浏览器会阻止发送 cookie。我们可以使用 `url_request_test_util.cc` 中的类来编写测试：

```cpp
TEST(CrossOriginCookieTest, BlockedByUserPreferences) {
  // 创建一个测试用的 URLRequestContext
  std::unique_ptr<URLRequestContextGetter> context_getter =
      CreateTestURLRequestContextGetter();
  URLRequestContext* context = context_getter->GetURLRequestContext();

  // 创建一个 TestNetworkDelegate，并设置阻止 cookie 的选项
  TestNetworkDelegate network_delegate;
  network_delegate.set_cookie_options_bit_mask(
      TestNetworkDelegate::NO_GET_COOKIES | TestNetworkDelegate::NO_SET_COOKIE);
  context->set_network_delegate(&network_delegate);

  // 创建一个 URLRequest
  GURL url("https://example.com/api");
  std::unique_ptr<URLRequest> request =
      context->CreateRequest(url, net::RequestPriority::HIGHEST, nullptr);

  // 设置 cookie
  StaticCookiePolicy::SetGlobalCookiePolicy(
      StaticCookiePolicy::ALLOW_ALL_COOKIES);
  context->cookie_manager()->SetCanonicalCookie(
      CanonicalCookie::CreateUnsafeCookieForTesting(
          "cookie_name", "cookie_value", "example.com", "/", base::Time::Now(),
          base::Time::Max(), base::Time::Now(), false, false,
          CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT, false),
      url, url, CookieOptions::MakeAllInclusive());

  // 发起请求
  TestDelegate delegate;
  request->set_delegate(&delegate);
  request->Start();
  delegate.RunUntilComplete();

  // 断言 cookie 没有被发送或设置 (通过检查 TestNetworkDelegate 的状态)
  EXPECT_EQ(0, network_delegate.blocked_annotate_cookies_count());
  EXPECT_EQ(0, network_delegate.blocked_set_cookie_count());
}
```

在这个例子中，我们使用了 `TestNetworkDelegate` 来模拟浏览器阻止 cookie 的行为，并验证了 JavaScript 发起的请求确实受到了这个策略的影响。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. 使用 `TestScopedURLInterceptor` 拦截对 `https://test.example/data` 的请求。
2. 拦截器配置返回一个状态码为 `404 Not Found` 的响应，内容为 `"Not found"`.
3. 使用 `URLRequest::CreateRequest` 创建一个请求到 `https://test.example/data`。
4. 使用 `TestDelegate` 作为请求的 delegate。

**预期输出:**

* `TestDelegate::OnResponseStarted` 会被调用，并且 `net_error` 参数为 `net::ERR_HTTP_RESPONSE_CODE_FAILURE`。
* `TestDelegate::received_bytes_count_` 会等于 `"Not found"` 的长度。
* `TestDelegate::data_received_` 会包含 `"Not found"` 字符串。
* `TestDelegate::request_status_` 会是 `net::OK` (因为数据已成功读取)。
* `TestDelegate::OnCompleted` 会被调用，`net_error` 参数为 `net::ERR_HTTP_RESPONSE_CODE_FAILURE`.

**用户或编程常见的使用错误:**

1. **忘记运行 RunUntilComplete:**  `URLRequest` 的操作是异步的。如果用户在发起请求后没有调用 `TestDelegate::RunUntilComplete()` 或其他类似的等待方法，就直接检查结果，可能会得到不完整或错误的结果。
   ```cpp
   // 错误示例
   TestDelegate delegate;
   request->set_delegate(&delegate);
   request->Start();
   // 忘记调用 delegate.RunUntilComplete();
   EXPECT_TRUE(delegate.response_completed()); // 可能会得到错误的结果
   ```

2. **在错误的 NetworkDelegate 回调中做出假设:** 用户可能会在某些 `NetworkDelegate` 回调中假设请求已经完成了特定的步骤，但实际上可能还没有。例如，在 `OnBeforeRedirect` 中假设已经收到了所有的响应头信息是不安全的。

3. **误用 TestScopedURLInterceptor:**  如果用户注册了一个 `TestScopedURLInterceptor`，但请求的 URL 与拦截器配置的不匹配，那么拦截器将不会生效，可能会导致测试用例的行为与预期不符。

4. **没有正确清理测试环境:**  例如，在测试结束后没有移除注册的 `URLRequestFilter` 或恢复全局的 cookie 策略，可能会影响后续的测试用例。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个开发者，当你遇到 Chromium 网络栈相关的 bug 或需要测试新的网络功能时，你可能会编写使用 `url_request_test_util.cc` 的单元测试。以下是一些可能到达这里的场景：

1. **编写新的网络功能测试:** 当你开发了一个新的网络特性（例如，一个新的协议支持、一个优化的缓存机制、或者一个新的安全策略），你需要编写单元测试来验证它的正确性。这些测试很可能会使用 `TestDelegate` 和 `TestNetworkDelegate` 来模拟各种网络场景，并验证你的代码的行为是否符合预期。

2. **调试网络请求相关的 bug:** 当用户报告了一个与网络请求相关的 bug，而你怀疑是 Chromium 网络栈本身的问题时，你可能会尝试编写一个单元测试来重现这个 bug。在这种情况下，你可能会使用 `TestScopedURLInterceptor` 来模拟导致 bug 的服务器行为，并使用 `TestDelegate` 或 `TestNetworkDelegate` 来观察请求过程中的错误。

3. **分析现有的网络测试用例:** 为了理解 Chromium 网络栈的特定行为，或者为了修改或扩展现有的测试用例，你可能会需要查看和理解 `url_request_test_util.cc` 中提供的工具类是如何被使用的。

4. **在 NetworkDelegate 的回调中设置断点:** 当你怀疑是某个 `NetworkDelegate` 的实现有问题时，你可能会在 `TestNetworkDelegate` 的某个回调函数中设置断点，来观察请求的状态和数据流。

**总结:**

`net/url_request/url_request_test_util.cc` 是 Chromium 网络栈中至关重要的测试工具库。它提供了一系列灵活且强大的工具，允许开发者模拟各种网络场景，并对 `URLRequest` 及其相关的组件进行彻底的测试。理解这个文件的功能对于编写可靠的网络测试和调试网络问题至关重要。

### 提示词
```
这是目录为net/url_request/url_request_test_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_test_util.h"

#include <memory>
#include <utility>

#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/run_loop.h"
#include "base/supports_user_data.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cookies/cookie_setting_override.h"
#include "net/cookies/cookie_util.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_network_session.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_server_properties.h"
#include "net/http/transport_security_state.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_retry_info.h"
#include "net/quic/quic_context.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_filter.h"
#include "net/url_request/url_request_job.h"
#include "net/url_request/url_request_job_factory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// These constants put the NetworkDelegate events of TestNetworkDelegate
// into an order. They are used in conjunction with
// |TestNetworkDelegate::next_states_| to check that we do not send
// events in the wrong order.
const int kStageBeforeURLRequest = 1 << 0;
const int kStageBeforeStartTransaction = 1 << 1;
const int kStageHeadersReceived = 1 << 2;
const int kStageBeforeRedirect = 1 << 3;
const int kStageBeforeRetry = 1 << 4;
const int kStageResponseStarted = 1 << 5;
const int kStageCompletedSuccess = 1 << 6;
const int kStageCompletedError = 1 << 7;
const int kStageURLRequestDestroyed = 1 << 8;
const int kStageDestruction = 1 << 9;

const char kTestNetworkDelegateRequestIdKey[] =
    "TestNetworkDelegateRequestIdKey";

class TestRequestId : public base::SupportsUserData::Data {
 public:
  explicit TestRequestId(int id) : id_(id) {}
  ~TestRequestId() override = default;

  int id() const { return id_; }

 private:
  const int id_;
};

}  // namespace

std::unique_ptr<URLRequestContextBuilder> CreateTestURLRequestContextBuilder() {
  auto builder = std::make_unique<URLRequestContextBuilder>();
  builder->set_host_resolver(std::make_unique<MockCachingHostResolver>(
      /*cache_invalidation_num=*/0,
      /*default_result=*/MockHostResolverBase::RuleResolver::
          GetLocalhostResult()));
  builder->set_proxy_resolution_service(
      ConfiguredProxyResolutionService::CreateDirect());
  builder->SetCertVerifier(
      CertVerifier::CreateDefault(/*cert_net_fetcher=*/nullptr));
  builder->set_ssl_config_service(std::make_unique<SSLConfigServiceDefaults>());
  builder->SetHttpAuthHandlerFactory(HttpAuthHandlerFactory::CreateDefault());
  builder->SetHttpServerProperties(std::make_unique<HttpServerProperties>());
  builder->set_quic_context(std::make_unique<QuicContext>());
  builder->SetCookieStore(std::make_unique<CookieMonster>(/*store=*/nullptr,
                                                          /*netlog=*/nullptr));
  builder->set_http_user_agent_settings(
      std::make_unique<StaticHttpUserAgentSettings>("en-us,fr", std::string()));
  return builder;
}

TestURLRequestContextGetter::TestURLRequestContextGetter(
    const scoped_refptr<base::SingleThreadTaskRunner>& network_task_runner)
    : network_task_runner_(network_task_runner) {
  DCHECK(network_task_runner_.get());
}

TestURLRequestContextGetter::TestURLRequestContextGetter(
    const scoped_refptr<base::SingleThreadTaskRunner>& network_task_runner,
    std::unique_ptr<URLRequestContext> context)
    : network_task_runner_(network_task_runner), context_(std::move(context)) {
  DCHECK(network_task_runner_.get());
}

TestURLRequestContextGetter::~TestURLRequestContextGetter() = default;

URLRequestContext* TestURLRequestContextGetter::GetURLRequestContext() {
  if (is_shut_down_)
    return nullptr;

  if (!context_.get())
    context_ = CreateTestURLRequestContextBuilder()->Build();
  return context_.get();
}

void TestURLRequestContextGetter::NotifyContextShuttingDown() {
  // This should happen before call to base NotifyContextShuttingDown() per that
  // method's doc comments.
  is_shut_down_ = true;

  URLRequestContextGetter::NotifyContextShuttingDown();
  context_ = nullptr;
}

scoped_refptr<base::SingleThreadTaskRunner>
TestURLRequestContextGetter::GetNetworkTaskRunner() const {
  return network_task_runner_;
}

const int TestDelegate::kBufferSize;

TestDelegate::TestDelegate()
    : buf_(base::MakeRefCounted<IOBufferWithSize>(kBufferSize)) {}

TestDelegate::~TestDelegate() = default;

void TestDelegate::RunUntilComplete() {
  base::RunLoop run_loop;
  on_complete_ = run_loop.QuitClosure();
  run_loop.Run();
}

void TestDelegate::RunUntilRedirect() {
  base::RunLoop run_loop;
  on_redirect_ = run_loop.QuitClosure();
  run_loop.Run();
}

void TestDelegate::RunUntilAuthRequired() {
  base::RunLoop run_loop;
  on_auth_required_ = run_loop.QuitClosure();
  run_loop.Run();
}

int TestDelegate::OnConnected(URLRequest* request,
                              const TransportInfo& info,
                              CompletionOnceCallback callback) {
  transports_.push_back(info);

  if (on_connected_run_callback_) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(callback), on_connected_result_));
    return net::ERR_IO_PENDING;
  }

  return on_connected_result_;
}

void TestDelegate::OnReceivedRedirect(URLRequest* request,
                                      const RedirectInfo& redirect_info,
                                      bool* defer_redirect) {
  EXPECT_TRUE(request->is_redirecting());

  redirect_info_ = redirect_info;

  received_redirect_count_++;
  if (on_redirect_) {
    *defer_redirect = true;
    std::move(on_redirect_).Run();
  } else if (cancel_in_rr_) {
    request->Cancel();
  }
}

void TestDelegate::OnAuthRequired(URLRequest* request,
                                  const AuthChallengeInfo& auth_info) {
  auth_required_ = true;
  if (on_auth_required_) {
    std::move(on_auth_required_).Run();
    return;
  }
  if (!credentials_.Empty()) {
    request->SetAuth(credentials_);
  } else {
    request->CancelAuth();
  }
}

void TestDelegate::OnSSLCertificateError(URLRequest* request,
                                         int net_error,
                                         const SSLInfo& ssl_info,
                                         bool fatal) {
  // The caller can control whether it needs all SSL requests to go through,
  // independent of any possible errors, or whether it wants SSL errors to
  // cancel the request.
  have_certificate_errors_ = true;
  certificate_errors_are_fatal_ = fatal;
  certificate_net_error_ = net_error;
  if (allow_certificate_errors_)
    request->ContinueDespiteLastError();
  else
    request->Cancel();
}

void TestDelegate::OnResponseStarted(URLRequest* request, int net_error) {
  // It doesn't make sense for the request to have IO pending at this point.
  DCHECK_NE(ERR_IO_PENDING, net_error);
  EXPECT_FALSE(request->is_redirecting());

  response_started_count_++;
  request_status_ = net_error;
  if (cancel_in_rs_) {
    request_status_ = request->Cancel();
    // Canceling |request| will cause OnResponseCompleted() to be called.
  } else if (net_error != OK) {
    request_failed_ = true;
    OnResponseCompleted(request);
  } else {
    // Initiate the first read.
    int bytes_read = request->Read(buf_.get(), kBufferSize);
    if (bytes_read >= 0)
      OnReadCompleted(request, bytes_read);
    else if (bytes_read != ERR_IO_PENDING)
      OnResponseCompleted(request);
  }
}

void TestDelegate::OnReadCompleted(URLRequest* request, int bytes_read) {
  // It doesn't make sense for the request to have IO pending at this point.
  DCHECK_NE(bytes_read, ERR_IO_PENDING);

  // If you've reached this, you've either called "RunUntilComplete"
  // If this DCHECK fails, that probably  means you've run
  // "RunUntilRedirect" or "RunUntilAuthRequired" and haven't
  // redirected/auth-challenged
  DCHECK(on_complete_);

  // If the request was cancelled in a redirect, it should not signal
  // OnReadCompleted. Note that |cancel_in_rs_| may be true due to
  // https://crbug.com/564848.
  EXPECT_FALSE(cancel_in_rr_);

  if (response_started_count_ == 0)
    received_data_before_response_ = true;

  if (bytes_read >= 0) {
    // There is data to read.
    received_bytes_count_ += bytes_read;

    // Consume the data.
    data_received_.append(buf_->data(), bytes_read);

    if (cancel_in_rd_) {
      request_status_ = request->Cancel();
      // If bytes_read is 0, won't get a notification on cancelation.
      if (bytes_read == 0) {
          std::move(on_complete_).Run();
      }
      return;
    }
  }

  // If it was not end of stream, request to read more.
  while (bytes_read > 0) {
    bytes_read = request->Read(buf_.get(), kBufferSize);
    if (bytes_read > 0) {
      data_received_.append(buf_->data(), bytes_read);
      received_bytes_count_ += bytes_read;
    }
  }

  request_status_ = bytes_read;
  if (request_status_ != ERR_IO_PENDING)
    OnResponseCompleted(request);
  else if (cancel_in_rd_pending_)
    request_status_ = request->Cancel();
}

void TestDelegate::OnResponseCompleted(URLRequest* request) {
  response_completed_ = true;
  std::move(on_complete_).Run();
}

TestNetworkDelegate::TestNetworkDelegate() = default;

TestNetworkDelegate::~TestNetworkDelegate() {
  for (auto i = next_states_.begin(); i != next_states_.end(); ++i) {
    event_order_[i->first] += "~TestNetworkDelegate\n";
    EXPECT_TRUE(i->second & kStageDestruction) << event_order_[i->first];
  }
}

bool TestNetworkDelegate::GetLoadTimingInfoBeforeRedirect(
    LoadTimingInfo* load_timing_info_before_redirect) const {
  *load_timing_info_before_redirect = load_timing_info_before_redirect_;
  return has_load_timing_info_before_redirect_;
}

void TestNetworkDelegate::InitRequestStatesIfNew(int request_id) {
  if (next_states_.find(request_id) == next_states_.end()) {
    // TODO(davidben): Although the URLRequest documentation does not allow
    // calling Cancel() before Start(), the ResourceLoader does so. URLRequest's
    // destructor also calls Cancel. Either officially support this or fix the
    // ResourceLoader code.
    next_states_[request_id] = kStageBeforeURLRequest | kStageCompletedError;
    event_order_[request_id] = "";
  }
}

int TestNetworkDelegate::OnBeforeURLRequest(URLRequest* request,
                                            CompletionOnceCallback callback,
                                            GURL* new_url) {
  int req_id = GetRequestId(request);
  InitRequestStatesIfNew(req_id);
  event_order_[req_id] += "OnBeforeURLRequest\n";
  EXPECT_TRUE(next_states_[req_id] & kStageBeforeURLRequest) <<
      event_order_[req_id];
  next_states_[req_id] =
      kStageBeforeStartTransaction |
      kStageResponseStarted |  // data: URLs do not trigger sending headers
      kStageBeforeRedirect |   // a delegate can trigger a redirection
      kStageCompletedError;    // request canceled by delegate
  created_requests_++;
  return OK;
}

int TestNetworkDelegate::OnBeforeStartTransaction(
    URLRequest* request,
    const HttpRequestHeaders& headers,
    OnBeforeStartTransactionCallback callback) {
  if (before_start_transaction_fails_)
    return ERR_FAILED;

  int req_id = GetRequestId(request);
  InitRequestStatesIfNew(req_id);
  event_order_[req_id] += "OnBeforeStartTransaction\n";
  EXPECT_TRUE(next_states_[req_id] & kStageBeforeStartTransaction)
      << event_order_[req_id];
  next_states_[req_id] =
      kStageHeadersReceived | kStageCompletedError | kStageBeforeRedirect;
  before_start_transaction_count_++;
  return OK;
}

int TestNetworkDelegate::OnHeadersReceived(
    URLRequest* request,
    CompletionOnceCallback callback,
    const HttpResponseHeaders* original_response_headers,
    scoped_refptr<HttpResponseHeaders>* override_response_headers,
    const IPEndPoint& endpoint,
    std::optional<GURL>* preserve_fragment_on_redirect_url) {
  EXPECT_FALSE(preserve_fragment_on_redirect_url->has_value());
  int req_id = GetRequestId(request);
  bool is_first_response =
      event_order_[req_id].find("OnHeadersReceived\n") == std::string::npos;
  event_order_[req_id] += "OnHeadersReceived\n";
  InitRequestStatesIfNew(req_id);
  EXPECT_TRUE(next_states_[req_id] & kStageHeadersReceived) <<
      event_order_[req_id];
  next_states_[req_id] = kStageBeforeRedirect | kStageBeforeRetry |
                         kStageResponseStarted |
                         kStageCompletedError;  // e.g. proxy resolution problem

  // Basic authentication sends a second request from the URLRequestHttpJob
  // layer before the URLRequest reports that a response has started.
  next_states_[req_id] |= kStageBeforeStartTransaction;

  if (!redirect_on_headers_received_url_.is_empty()) {
    *override_response_headers = base::MakeRefCounted<HttpResponseHeaders>(
        original_response_headers->raw_headers());
    (*override_response_headers)->ReplaceStatusLine("HTTP/1.1 302 Found");
    (*override_response_headers)->RemoveHeader("Location");
    (*override_response_headers)
        ->AddHeader("Location", redirect_on_headers_received_url_.spec());

    redirect_on_headers_received_url_ = GURL();

    // Since both values are std::optionals, can just copy this over.
    *preserve_fragment_on_redirect_url = preserve_fragment_on_redirect_url_;
  } else if (add_header_to_first_response_ && is_first_response) {
    *override_response_headers = base::MakeRefCounted<HttpResponseHeaders>(
        original_response_headers->raw_headers());
    (*override_response_headers)
        ->AddHeader("X-Network-Delegate", "Greetings, planet");
  }

  headers_received_count_++;
  return OK;
}

void TestNetworkDelegate::OnBeforeRedirect(URLRequest* request,
                                           const GURL& new_location) {
  load_timing_info_before_redirect_ = LoadTimingInfo();
  request->GetLoadTimingInfo(&load_timing_info_before_redirect_);
  has_load_timing_info_before_redirect_ = true;
  EXPECT_FALSE(load_timing_info_before_redirect_.request_start_time.is_null());
  EXPECT_FALSE(load_timing_info_before_redirect_.request_start.is_null());

  int req_id = GetRequestId(request);
  InitRequestStatesIfNew(req_id);
  event_order_[req_id] += "OnBeforeRedirect\n";
  EXPECT_TRUE(next_states_[req_id] & kStageBeforeRedirect) <<
      event_order_[req_id];
  next_states_[req_id] =
      kStageBeforeURLRequest |        // HTTP redirects trigger this.
      kStageBeforeStartTransaction |  // Redirects from the network delegate do
                                      // not
                                      // trigger onBeforeURLRequest.
      kStageCompletedError;

  // A redirect can lead to a file or a data URL. In this case, we do not send
  // headers.
  next_states_[req_id] |= kStageResponseStarted;
}

void TestNetworkDelegate::OnBeforeRetry(URLRequest* request) {
  int req_id = GetRequestId(request);
  InitRequestStatesIfNew(req_id);
  event_order_[req_id] += "OnBeforeRetry\n";
  EXPECT_TRUE(next_states_[req_id] & kStageBeforeRetry) << event_order_[req_id];
  next_states_[req_id] = kStageBeforeURLRequest;
}

void TestNetworkDelegate::OnResponseStarted(URLRequest* request,
                                            int net_error) {
  DCHECK_NE(ERR_IO_PENDING, net_error);

  LoadTimingInfo load_timing_info;
  request->GetLoadTimingInfo(&load_timing_info);
  EXPECT_FALSE(load_timing_info.request_start_time.is_null());
  EXPECT_FALSE(load_timing_info.request_start.is_null());

  int req_id = GetRequestId(request);
  InitRequestStatesIfNew(req_id);
  event_order_[req_id] += "OnResponseStarted\n";
  EXPECT_TRUE(next_states_[req_id] & kStageResponseStarted)
      << event_order_[req_id];
  next_states_[req_id] = kStageCompletedSuccess | kStageCompletedError;
  if (net_error == ERR_ABORTED)
    return;

  if (net_error != OK) {
    error_count_++;
    last_error_ = net_error;
  }
}

void TestNetworkDelegate::OnCompleted(URLRequest* request,
                                      bool started,
                                      int net_error) {
  DCHECK_NE(net_error, net::ERR_IO_PENDING);

  int req_id = GetRequestId(request);
  InitRequestStatesIfNew(req_id);
  event_order_[req_id] += "OnCompleted\n";
  // Expect "Success -> (next_states_ & kStageCompletedSuccess)"
  // is logically identical to
  // Expect "!(Success) || (next_states_ & kStageCompletedSuccess)"
  EXPECT_TRUE(net_error != OK ||
              (next_states_[req_id] & kStageCompletedSuccess))
      << event_order_[req_id];
  EXPECT_TRUE(net_error == OK || (next_states_[req_id] & kStageCompletedError))
      << event_order_[req_id];
  next_states_[req_id] = kStageURLRequestDestroyed;
  completed_requests_++;
  if (net_error == ERR_ABORTED) {
    canceled_requests_++;
  } else if (net_error != OK) {
    error_count_++;
    last_error_ = net_error;
  } else {
    DCHECK_EQ(OK, net_error);
  }
}

void TestNetworkDelegate::OnURLRequestDestroyed(URLRequest* request) {
  int req_id = GetRequestId(request);
  InitRequestStatesIfNew(req_id);
  event_order_[req_id] += "OnURLRequestDestroyed\n";
  EXPECT_TRUE(next_states_[req_id] & kStageURLRequestDestroyed) <<
      event_order_[req_id];
  next_states_[req_id] = kStageDestruction;
  destroyed_requests_++;
}

bool TestNetworkDelegate::OnAnnotateAndMoveUserBlockedCookies(
    const URLRequest& request,
    const net::FirstPartySetMetadata& first_party_set_metadata,
    net::CookieAccessResultList& maybe_included_cookies,
    net::CookieAccessResultList& excluded_cookies) {
  RecordCookieSettingOverrides(request.cookie_setting_overrides());
  bool allow = true;
  if (cookie_options_bit_mask_ & NO_GET_COOKIES)
    allow = false;

  if (!allow) {
    blocked_annotate_cookies_count_++;
    ExcludeAllCookies(CookieInclusionStatus::EXCLUDE_USER_PREFERENCES,
                      maybe_included_cookies, excluded_cookies);
  }

  return allow;
}

NetworkDelegate::PrivacySetting TestNetworkDelegate::OnForcePrivacyMode(
    const URLRequest& request) const {
  RecordCookieSettingOverrides(request.cookie_setting_overrides());
  return NetworkDelegate::PrivacySetting::kStateAllowed;
}

bool TestNetworkDelegate::OnCanSetCookie(
    const URLRequest& request,
    const net::CanonicalCookie& cookie,
    CookieOptions* options,
    const net::FirstPartySetMetadata& first_party_set_metadata,
    CookieInclusionStatus* inclusion_status) {
  RecordCookieSettingOverrides(request.cookie_setting_overrides());
  bool allow = true;
  if (cookie_options_bit_mask_ & NO_SET_COOKIE)
    allow = false;

  if (!allow) {
    blocked_set_cookie_count_++;
  } else {
    set_cookie_count_++;
  }

  return allow;
}

bool TestNetworkDelegate::OnCancelURLRequestWithPolicyViolatingReferrerHeader(
    const URLRequest& request,
    const GURL& target_url,
    const GURL& referrer_url) const {
  return cancel_request_with_policy_violating_referrer_;
}

int TestNetworkDelegate::GetRequestId(URLRequest* request) {
  TestRequestId* test_request_id = reinterpret_cast<TestRequestId*>(
      request->GetUserData(kTestNetworkDelegateRequestIdKey));
  if (test_request_id)
    return test_request_id->id();
  int id = next_request_id_++;
  request->SetUserData(kTestNetworkDelegateRequestIdKey,
                       std::make_unique<TestRequestId>(id));
  return id;
}

std::optional<cookie_util::StorageAccessStatus>
TestNetworkDelegate::OnGetStorageAccessStatus(
    const URLRequest& request,
    base::optional_ref<const RedirectInfo> redirect_info) const {
  return storage_access_status_;
}

bool TestNetworkDelegate::OnIsStorageAccessHeaderEnabled(
    const url::Origin* top_frame_origin,
    const GURL& url) const {
  return is_storage_access_header_enabled_;
}

FilteringTestNetworkDelegate::FilteringTestNetworkDelegate() = default;
FilteringTestNetworkDelegate::~FilteringTestNetworkDelegate() = default;

bool FilteringTestNetworkDelegate::OnCanSetCookie(
    const URLRequest& request,
    const net::CanonicalCookie& cookie,
    CookieOptions* options,
    const net::FirstPartySetMetadata& first_party_set_metadata,
    CookieInclusionStatus* inclusion_status) {
  // Filter out cookies with the same name as |cookie_name_filter_| and
  // combine with |allowed_from_caller|.
  bool allowed = cookie.Name() != cookie_name_filter_;

  ++set_cookie_called_count_;

  if (!allowed)
    ++blocked_set_cookie_count_;

  // Call the nested delegate's method first to avoid a short circuit.
  return TestNetworkDelegate::OnCanSetCookie(request, cookie, options,
                                             first_party_set_metadata,
                                             inclusion_status) &&
         allowed;
}

NetworkDelegate::PrivacySetting
FilteringTestNetworkDelegate::OnForcePrivacyMode(
    const URLRequest& request) const {
  if (force_privacy_mode_) {
    return partitioned_state_allowed_
               ? NetworkDelegate::PrivacySetting::kPartitionedStateAllowedOnly
               : NetworkDelegate::PrivacySetting::kStateDisallowed;
  }

  return TestNetworkDelegate::OnForcePrivacyMode(request);
}

bool FilteringTestNetworkDelegate::OnAnnotateAndMoveUserBlockedCookies(
    const URLRequest& request,
    const net::FirstPartySetMetadata& first_party_set_metadata,
    net::CookieAccessResultList& maybe_included_cookies,
    net::CookieAccessResultList& excluded_cookies) {
  // Filter out cookies if |block_annotate_cookies_| is set and
  // combine with |allowed_from_caller|.
  bool allowed = !block_annotate_cookies_;

  ++annotate_cookies_called_count_;

  if (!allowed) {
    ++blocked_annotate_cookies_count_;
    ExcludeAllCookies(net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES,
                      maybe_included_cookies, excluded_cookies);
  }

  if (allowed && block_get_cookies_by_name_ && !cookie_name_filter_.empty()) {
    for (auto& cookie : maybe_included_cookies) {
      if (cookie.cookie.Name().find(cookie_name_filter_) != std::string::npos) {
        cookie.access_result.status.AddExclusionReason(
            net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES);
      }
    }
    for (auto& cookie : excluded_cookies) {
      if (cookie.cookie.Name().find(cookie_name_filter_) != std::string::npos) {
        cookie.access_result.status.AddExclusionReason(
            net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES);
      }
    }

    MoveExcludedCookies(maybe_included_cookies, excluded_cookies);
  }

  // Call the nested delegate's method first to avoid a short circuit.
  return TestNetworkDelegate::OnAnnotateAndMoveUserBlockedCookies(
             request, first_party_set_metadata, maybe_included_cookies,
             excluded_cookies) &&
         allowed;
}

// URLRequestInterceptor that intercepts only the first request it sees,
// returning the provided URLRequestJob.
class TestScopedURLInterceptor::TestRequestInterceptor
    : public URLRequestInterceptor {
 public:
  explicit TestRequestInterceptor(std::unique_ptr<URLRequestJob> intercept_job)
      : intercept_job_(std::move(intercept_job)) {}

  ~TestRequestInterceptor() override { CHECK(safe_to_delete_); }

  std::unique_ptr<URLRequestJob> MaybeInterceptRequest(
      URLRequest* request) const override {
    return std::move(intercept_job_);
  }

  bool job_used() const { return intercept_job_.get() == nullptr; }
  void set_safe_to_delete() { safe_to_delete_ = true; }

 private:
  mutable std::unique_ptr<URLRequestJob> intercept_job_;
  // This is used to catch chases where the TestRequestInterceptor is destroyed
  // before the TestScopedURLInterceptor.
  bool safe_to_delete_ = false;
};

TestScopedURLInterceptor::TestScopedURLInterceptor(
    const GURL& url,
    std::unique_ptr<URLRequestJob> intercept_job)
    : url_(url) {
  std::unique_ptr<TestRequestInterceptor> interceptor =
      std::make_unique<TestRequestInterceptor>(std::move(intercept_job));
  interceptor_ = interceptor.get();
  URLRequestFilter::GetInstance()->AddUrlInterceptor(url_,
                                                     std::move(interceptor));
}

TestScopedURLInterceptor::~TestScopedURLInterceptor() {
  DCHECK(interceptor_->job_used());
  interceptor_->set_safe_to_delete();
  interceptor_ = nullptr;
  URLRequestFilter::GetInstance()->RemoveUrlHandler(url_);
}

}  // namespace net
```