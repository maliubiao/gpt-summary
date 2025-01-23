Response: Let's break down the thought process to analyze the provided C++ unittest file.

1. **Understand the Goal:** The request asks for the functionality of the file `throttling_url_loader_unittest.cc`, its relation to web technologies (JavaScript, HTML, CSS), logical reasoning examples, and common usage errors.

2. **Identify the Core Subject:** The filename itself is a strong clue: `throttling_url_loader_unittest.cc`. This immediately tells us the file is testing something called `ThrottlingURLLoader`. The `unittest.cc` suffix confirms it's a unit test file.

3. **Scan for Key Classes/Namespaces:**  Quickly scan the code for prominent class names and namespaces. We see:
    * `blink` namespace (suggests Blink rendering engine)
    * `network::mojom` (Mojo interfaces related to networking)
    * `URLLoader`, `URLLoaderFactory`, `URLLoaderClient` (core networking concepts)
    * `URLLoaderThrottle` (the throttling mechanism being tested)
    * `ThrottlingURLLoader` (the class under test)
    * Test classes like `TestURLLoaderFactory`, `TestURLLoaderClient`, `TestURLLoaderThrottle` (mock implementations for testing)
    * Google Test macros (`TEST_F`, `EXPECT_EQ`, etc.)

4. **Infer the Purpose of `ThrottlingURLLoader`:** Based on the name, we can infer that `ThrottlingURLLoader` likely manages and controls the loading of URLs, potentially with the ability to introduce delays or modifications (throttling).

5. **Analyze the Test Structure:** Observe the structure of the test cases (`TEST_F` blocks). Each test case seems to focus on a specific interaction or scenario involving `ThrottlingURLLoader` and its related components. Common patterns emerge:
    * Setting up mock objects (`TestURLLoaderFactory`, `TestURLLoaderClient`, custom `TestURLLoaderThrottle`).
    * Configuring the behavior of the mock throttle (e.g., deferring, canceling, modifying requests).
    * Creating and starting the `ThrottlingURLLoader`.
    * Simulating events (e.g., redirects, responses, completions).
    * Using `base::RunLoop` for asynchronous testing.
    * Assertions (`EXPECT_EQ`, `EXPECT_TRUE`, etc.) to verify expected behavior.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):** Now, think about how URL loading relates to web content. JavaScript, HTML, and CSS all rely on fetching resources via URLs.
    * **JavaScript:**  `fetch()`, `XMLHttpRequest`, dynamically loaded scripts (`<script src="...">`), images (`<img src="...">`), etc.
    * **HTML:**  Links (`<a href="...">`), images (`<img>`), iframes (`<iframe>`), scripts (`<script>`), stylesheets (`<link rel="stylesheet">`), form submissions.
    * **CSS:**  `url()` function in properties like `background-image`, `@import`.

    The `ThrottlingURLLoader` is a low-level component within the browser engine. It's responsible for *how* these URLs are loaded. Throttling could affect things like:
    * **JavaScript execution:** If a script load is throttled, the script might take longer to execute, potentially delaying page interactivity.
    * **HTML rendering:**  If images or other resources are throttled, the page might render incompletely or slowly.
    * **CSS styling:** If stylesheets are throttled, the page might initially render without styles (FOUT - Flash of Unstyled Content).

7. **Identify Logical Reasoning Examples:** Look for test cases that demonstrate different control flow scenarios and how the `ThrottlingURLLoader` reacts. Focus on the interaction with the `URLLoaderThrottle`:
    * **Cancellation:** Tests like `CancelBeforeStart`, `CancelBeforeRedirect`, `CancelBeforeResponse` show how a throttle can abort the loading process at different stages. *Hypothetical Input:* A network request is initiated. A throttle decides to cancel it. *Hypothetical Output:* The `URLLoaderClient` receives an error notification, and the actual network request might not even be initiated.
    * **Deferral (Pausing):** Tests like `DeferBeforeStart`, `DeferBeforeRedirect`, `DeferBeforeResponse` illustrate how a throttle can temporarily pause the loading process. *Hypothetical Input:* A network request starts. A throttle defers it. *Hypothetical Output:* The network request is paused. The throttle can later resume it.
    * **Modification:** The `ModifyURLBeforeStart` and `ModifyHeadersBeforeRedirect` tests show how a throttle can alter the request. *Hypothetical Input:* A request for `http://example.org`. A throttle changes it to `http://example.org/foo`. *Hypothetical Output:* The underlying network request is made to the modified URL.
    * **Restarting:** The `RestartWithURLReset` tests demonstrate a more complex scenario where the loading process can be restarted with the original URL.

8. **Spot Common Usage Errors:**  Think about how developers using or interacting with URL loading might make mistakes, and see if the tests cover related scenarios:
    * **Canceling/Deleting at Incorrect Times:** Tests like `DeleteBeforeStart`, `DeleteBeforeRedirect`, `DeleteBeforeResponse`, `DestroyingThrottlingURLLoaderInDelegateCall_Response`, and `DestroyingThrottlingURLLoaderInDelegateCall_Redirect` highlight the importance of managing the lifecycle of the loader and avoiding premature destruction, especially within callback contexts.
    * **Incorrectly Resuming:** The `ResumeNoOpIfNotDeferred` test shows that calling `Resume()` when the loader isn't deferred has no effect, which might be a point of confusion for developers.
    * **Redundant Cancellation:** The `CancelNoOpIfAlreadyCanceled` test demonstrates that canceling multiple times doesn't cause issues but is unnecessary.

9. **Structure the Answer:** Organize the findings into clear sections based on the request:
    * Functionality of the file.
    * Relationship to JavaScript, HTML, CSS with examples.
    * Logical reasoning examples with hypothetical inputs/outputs.
    * Common usage errors with explanations.

10. **Refine and Review:** Go through the generated answer, ensuring clarity, accuracy, and completeness. Double-check the examples and explanations. For instance, ensure the connection between throttling and the user experience (e.g., page load times, perceived performance) is clearly stated.

This systematic approach, starting with the high-level purpose and gradually diving into details, helps to thoroughly analyze the code and address all aspects of the request.
这个文件 `throttling_url_loader_unittest.cc` 是 Chromium Blink 引擎中 `ThrottlingURLLoader` 类的单元测试文件。它的主要功能是 **验证 `ThrottlingURLLoader` 类的行为是否符合预期**。 `ThrottlingURLLoader` 的作用是在 URL 加载过程中应用一系列的 `URLLoaderThrottle`，这些 throttle 可以拦截、修改或取消请求。

更具体地说，这个单元测试文件通过创建各种场景来测试 `ThrottlingURLLoader` 的以下方面：

**主要功能点:**

1. **生命周期管理:**
   - 测试在请求开始前、重定向时、响应时等不同阶段取消 `ThrottlingURLLoader` 的行为。
   - 测试在不同阶段删除 `ThrottlingURLLoader` 的行为，确保没有内存泄漏或崩溃。

2. **Throttle 的执行和控制:**
   - 测试 `URLLoaderThrottle` 的 `WillStartRequest`、`WillRedirectRequest`、`WillProcessResponse` 和 `BeforeWillProcessResponse` 等方法的调用时机和效果。
   - 测试 `URLLoaderThrottle` 如何使用 `URLLoaderThrottle::Delegate` 来控制请求，例如取消请求、延迟请求、修改请求 URL 和 header。
   - 测试多个 `URLLoaderThrottle` 协同工作的情况，包括它们的执行顺序和互相影响。

3. **请求的修改和重定向:**
   - 测试 `URLLoaderThrottle` 如何修改请求的 URL。
   - 测试 `URLLoaderThrottle` 如何修改和移除重定向请求的 header。
   - 测试 `ThrottlingURLLoader` 如何处理跨域重定向和 `IsolationInfo`。

4. **异步处理:**
   - 使用 `base::RunLoop` 来处理异步操作，例如 throttle 延迟请求。

5. **错误处理:**
   - 测试在不同阶段取消请求时，`URLLoaderClient` 收到的错误码是否正确。
   - 测试网络连接中断（pipe closure）时的行为。

6. **重启请求:**
   - 测试 `URLLoaderThrottle` 如何使用 `RestartWithURLReset` 来重启请求，包括在 `BeforeWillProcessResponse` 和 `BeforeWillRedirectRequest` 阶段。
   - 测试多个 throttle 同时请求重启时的行为。

**与 JavaScript, HTML, CSS 的关系：**

`ThrottlingURLLoader` 本身并不直接处理 JavaScript, HTML, 或 CSS 的解析或执行。但是，它在 URL 加载管道中扮演着关键角色，而这些 Web 技术都依赖于 URL 加载来获取资源。 因此，`ThrottlingURLLoader` 的行为会间接地影响这些技术的功能。

**举例说明:**

* **JavaScript:**
    * 假设一个 JavaScript 脚本尝试使用 `fetch()` API 加载一个外部脚本文件。一个 `URLLoaderThrottle` 可以被配置为延迟这个请求。测试用例会验证在这种情况下，`ThrottlingURLLoader` 正确地暂停了请求，直到 throttle 允许它继续。 这会直接影响 JavaScript 的执行时机，如果脚本加载被延迟，那么依赖该脚本的功能可能也会延迟执行。
    * **假设输入:** JavaScript 代码 `fetch('https://example.com/script.js')`。一个 `TestURLLoaderThrottle` 被配置为在 `WillStartRequest` 中调用 `delegate->Defer()`.
    * **预期输出:**  `fetch()` 请求不会立即发送到网络层，直到 throttle 调用 `delegate->Resume()`。

* **HTML:**
    * HTML 文件中可能包含 `<img>` 标签引用图片资源。一个 `URLLoaderThrottle` 可以被配置为阻止加载某些特定的图片 URL。测试用例会验证在这种情况下，`ThrottlingURLLoader` 能正确地取消对该图片 URL 的请求。 这会导致 HTML 页面无法显示该图片。
    * **假设输入:** HTML 代码 `<img src="https://example.com/image.png">`。一个 `TestURLLoaderThrottle` 被配置为在 `WillStartRequest` 中检查 URL，如果匹配 `https://example.com/image.png` 则调用 `delegate->CancelWithError(net::ERR_BLOCKED_BY_CLIENT)`.
    * **预期输出:** 图片资源加载被取消，浏览器不会显示该图片，并且可能在开发者工具中显示一个网络错误。

* **CSS:**
    * CSS 文件可以使用 `@import` 规则或 `url()` 函数引用其他 CSS 文件或图片资源。一个 `URLLoaderThrottle` 可以被配置为修改请求的 CSS 资源的 header。测试用例会验证在这种情况下，`ThrottlingURLLoader` 能正确地修改请求的 header。 例如，可以添加一个自定义的 header 用于服务器端的特殊处理。
    * **假设输入:** CSS 代码 `@import url("style2.css");`。一个 `TestURLLoaderThrottle` 被配置为在 `WillStartRequest` 中，如果请求的 URL 包含 `style2.css`，则修改请求的 header，例如添加 `X-Custom-Header: test-value`.
    * **预期输出:** 当请求 `style2.css` 时，网络请求中会包含 `X-Custom-Header: test-value` 这个 header。

**逻辑推理的假设输入与输出:**

* **场景:** 测试 `URLLoaderThrottle` 在 `WillRedirectRequest` 中修改重定向请求的 header。
    * **假设输入:**
        1. 初始请求 URL: `http://example.org`
        2. 服务器返回重定向到 `http://example.com` 的响应。
        3. 一个 `TestURLLoaderThrottle` 被配置为在 `WillRedirectRequest` 中添加 header `X-Throttle-Header: modified`.
    * **预期输出:**
        1. `TestURLLoaderFactory` 的 `FollowRedirect` 方法被调用。
        2. `factory_.headers_modified_on_redirect()` 将包含 header `X-Throttle-Header: modified`.

* **场景:** 测试 `URLLoaderThrottle` 在 `BeforeWillProcessResponse` 中使用 `RestartWithURLReset`。
    * **假设输入:**
        1. 请求 URL: `http://example.org`
        2. 一个 `TestURLLoaderThrottle` 被配置为在 `BeforeWillProcessResponse` 中调用 `delegate->RestartWithURLReset(true)`.
    * **预期输出:**
        1. `factory_.create_loader_and_start_called()` 的次数会增加，因为请求被重启了。
        2. 新的请求将使用原始的 URL `http://example.org`，即使之前的请求可能经历了内部重定向或修改。

**用户或编程常见的使用错误：**

* **在 Throttle 的回调中错误地管理 ThrottlingURLLoader 的生命周期:**
    * **错误示例:** 在 `TestURLLoaderThrottle` 的 `WillStartRequest` 回调中，直接 `delete loader();`。
    * **后果:**  可能导致 use-after-free 错误，因为 `ThrottlingURLLoader` 可能还在被其他部分引用。测试用例 `DestroyingThrottlingURLLoaderInDelegateCall_Response` 和 `DestroyingThrottlingURLLoaderInDelegateCall_Redirect` 就是为了验证这种情况下的安全性。
    * **正确做法:** 应该避免在 throttle 的回调中直接管理 `ThrottlingURLLoader` 的生命周期。如果需要停止加载，应该使用 `delegate->CancelWithError()`。

* **不理解 Throttle 的执行顺序:**
    * **错误示例:** 假设有两个 throttle，都尝试修改同一个 header，但是开发者没有考虑到它们的执行顺序，导致最终的 header 值不是预期的。
    * **后果:**  请求的行为可能与预期不符。
    * **正确做法:**  理解不同 throttle 回调的执行顺序，例如 `WillStartRequest` 在所有 throttle 中按添加顺序执行。

* **在没有 defer 的情况下调用 Resume:**
    * **错误示例:**  在一个没有调用 `delegate->Defer()` 的 throttle 回调中，错误地调用了 `delegate->Resume()`。
    * **后果:**  `Resume()` 方法在这种情况下是空操作，不会产生实际效果，可能导致代码逻辑混乱。测试用例 `ResumeNoOpIfNotDeferred` 就是为了验证这一点。

* **多次调用 CancelWithError:**
    * **错误示例:** 在一个 throttle 回调中，多次调用 `delegate->CancelWithError()`，并传入不同的错误码。
    * **后果:**  只有第一次 `CancelWithError()` 调用有效，后续调用会被忽略。测试用例 `CancelNoOpIfAlreadyCanceled` 验证了这一点。

总而言之，`throttling_url_loader_unittest.cc` 是一个非常重要的测试文件，它确保了 `ThrottlingURLLoader` 及其相关的 throttle 机制能够正确可靠地工作，这对于 Chromium 浏览器正确加载和处理各种 Web 资源至关重要。

### 提示词
```
这是目录为blink/common/loader/throttling_url_loader_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/loader/throttling_url_loader.h"

#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/weak_wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/early_hints.mojom.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/loader/url_loader_throttle.h"

namespace blink {
namespace {

GURL request_url = GURL("http://example.org");
GURL redirect_url = GURL("http://example.com");
using RestartWithURLReset = URLLoaderThrottle::RestartWithURLReset;

class TestURLLoaderFactory : public network::mojom::URLLoaderFactory,
                             public network::mojom::URLLoader {
 public:
  TestURLLoaderFactory() {
    receiver_.Bind(factory_remote_.BindNewPipeAndPassReceiver());
    shared_factory_ =
        base::MakeRefCounted<network::WeakWrapperSharedURLLoaderFactory>(
            factory_remote_.get());
  }
  TestURLLoaderFactory(const TestURLLoaderFactory&) = delete;
  TestURLLoaderFactory& operator=(const TestURLLoaderFactory&) = delete;

  ~TestURLLoaderFactory() override { shared_factory_->Detach(); }

  mojo::Remote<network::mojom::URLLoaderFactory>& factory_remote() {
    return factory_remote_;
  }
  mojo::Receiver<network::mojom::URLLoader>& url_loader_receiver() {
    return url_loader_receiver_;
  }
  scoped_refptr<network::SharedURLLoaderFactory> shared_factory() {
    return shared_factory_;
  }

  size_t create_loader_and_start_called() const {
    return create_loader_and_start_called_;
  }

  const std::vector<std::string>& headers_removed_on_redirect() const {
    return headers_removed_on_redirect_;
  }

  const net::HttpRequestHeaders& headers_modified_on_redirect() const {
    return headers_modified_on_redirect_;
  }

  const net::HttpRequestHeaders& cors_exempt_headers_modified_on_redirect()
      const {
    return cors_exempt_headers_modified_on_redirect_;
  }

  void NotifyClientOnReceiveResponse() {
    client_remote_->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                                      mojo::ScopedDataPipeConsumerHandle(),
                                      std::nullopt);
  }

  void NotifyClientOnReceiveRedirect() {
    net::RedirectInfo info;
    info.new_url = redirect_url;
    client_remote_->OnReceiveRedirect(info,
                                      network::mojom::URLResponseHead::New());
  }

  void NotifyClientOnComplete(int error_code) {
    network::URLLoaderCompletionStatus data;
    data.error_code = error_code;
    client_remote_->OnComplete(data);
  }

  void CloseClientPipe() { client_remote_.reset(); }

  using OnCreateLoaderAndStartCallback = base::RepeatingCallback<void(
      const network::ResourceRequest& url_request)>;
  void set_on_create_loader_and_start(
      const OnCreateLoaderAndStartCallback& callback) {
    on_create_loader_and_start_callback_ = callback;
  }

 private:
  // network::mojom::URLLoaderFactory implementation.
  void CreateLoaderAndStart(
      mojo::PendingReceiver<network::mojom::URLLoader> receiver,
      int32_t request_id,
      uint32_t options,
      const network::ResourceRequest& url_request,
      mojo::PendingRemote<network::mojom::URLLoaderClient> client,
      const net::MutableNetworkTrafficAnnotationTag& traffic_annotation)
      override {
    create_loader_and_start_called_++;

    url_loader_receiver_.reset();
    url_loader_receiver_.Bind(std::move(receiver));
    client_remote_.reset();
    client_remote_.Bind(std::move(client));

    if (on_create_loader_and_start_callback_)
      on_create_loader_and_start_callback_.Run(url_request);
  }

  void Clone(mojo::PendingReceiver<network::mojom::URLLoaderFactory> receiver)
      override {
    NOTREACHED();
  }

  // network::mojom::URLLoader implementation.
  void FollowRedirect(
      const std::vector<std::string>& removed_headers,
      const net::HttpRequestHeaders& modified_headers,
      const net::HttpRequestHeaders& modified_cors_exempt_headers,
      const std::optional<GURL>& new_url) override {
    headers_removed_on_redirect_ = removed_headers;
    headers_modified_on_redirect_ = modified_headers;
    cors_exempt_headers_modified_on_redirect_ = modified_cors_exempt_headers;
  }

  void SetPriority(net::RequestPriority priority,
                   int32_t intra_priority_value) override {}

  void PauseReadingBodyFromNet() override {}
  void ResumeReadingBodyFromNet() override {}

  size_t create_loader_and_start_called_ = 0;
  std::vector<std::string> headers_removed_on_redirect_;
  net::HttpRequestHeaders headers_modified_on_redirect_;
  net::HttpRequestHeaders cors_exempt_headers_modified_on_redirect_;

  mojo::Receiver<network::mojom::URLLoaderFactory> receiver_{this};
  mojo::Receiver<network::mojom::URLLoader> url_loader_receiver_{this};
  mojo::Remote<network::mojom::URLLoaderFactory> factory_remote_;
  mojo::Remote<network::mojom::URLLoaderClient> client_remote_;
  scoped_refptr<network::WeakWrapperSharedURLLoaderFactory> shared_factory_;
  OnCreateLoaderAndStartCallback on_create_loader_and_start_callback_;
};

class TestURLLoaderClient : public network::mojom::URLLoaderClient {
 public:
  TestURLLoaderClient() = default;
  TestURLLoaderClient(const TestURLLoaderClient&) = delete;
  TestURLLoaderClient& operator=(const TestURLLoaderClient&) = delete;

  size_t on_received_response_called() const {
    return on_received_response_called_;
  }

  size_t on_received_redirect_called() const {
    return on_received_redirect_called_;
  }

  size_t on_complete_called() const { return on_complete_called_; }

  void set_on_received_redirect_callback(
      const base::RepeatingClosure& callback) {
    on_received_redirect_callback_ = callback;
  }

  void set_on_received_response_callback(base::OnceClosure callback) {
    on_received_response_callback_ = std::move(callback);
  }

  using OnCompleteCallback = base::OnceCallback<void(int error_code)>;
  void set_on_complete_callback(OnCompleteCallback callback) {
    on_complete_callback_ = std::move(callback);
  }

 private:
  // network::mojom::URLLoaderClient implementation:
  void OnReceiveEarlyHints(network::mojom::EarlyHintsPtr early_hints) override {
  }

  void OnReceiveResponse(
      network::mojom::URLResponseHeadPtr response_head,
      mojo::ScopedDataPipeConsumerHandle body,
      std::optional<mojo_base::BigBuffer> cached_metadata) override {
    on_received_response_called_++;
    if (on_received_response_callback_)
      std::move(on_received_response_callback_).Run();
  }
  void OnReceiveRedirect(
      const net::RedirectInfo& redirect_info,
      network::mojom::URLResponseHeadPtr response_head) override {
    on_received_redirect_called_++;
    if (on_received_redirect_callback_)
      on_received_redirect_callback_.Run();
  }
  void OnUploadProgress(int64_t current_position,
                        int64_t total_size,
                        OnUploadProgressCallback ack_callback) override {}
  void OnTransferSizeUpdated(int32_t transfer_size_diff) override {}
  void OnComplete(const network::URLLoaderCompletionStatus& status) override {
    on_complete_called_++;
    if (on_complete_callback_)
      std::move(on_complete_callback_).Run(status.error_code);
  }

  size_t on_received_response_called_ = 0;
  size_t on_received_redirect_called_ = 0;
  size_t on_complete_called_ = 0;

  base::RepeatingClosure on_received_redirect_callback_;
  base::OnceClosure on_received_response_callback_;
  OnCompleteCallback on_complete_callback_;
};

class TestURLLoaderThrottle : public blink::URLLoaderThrottle {
 public:
  TestURLLoaderThrottle() = default;
  explicit TestURLLoaderThrottle(base::OnceClosure destruction_notifier)
      : destruction_notifier_(std::move(destruction_notifier)) {}

  TestURLLoaderThrottle(const TestURLLoaderThrottle&) = delete;
  TestURLLoaderThrottle& operator=(const TestURLLoaderThrottle&) = delete;

  ~TestURLLoaderThrottle() override {
    if (destruction_notifier_)
      std::move(destruction_notifier_).Run();
  }

  using ThrottleCallback =
      base::RepeatingCallback<void(URLLoaderThrottle::Delegate* delegate,
                                   bool* defer)>;
  using ThrottleRedirectCallback = base::OnceCallback<void(
      blink::URLLoaderThrottle::Delegate* delegate,
      bool* defer,
      std::vector<std::string>* removed_headers,
      net::HttpRequestHeaders* modified_headers,
      net::HttpRequestHeaders* modified_cors_exempt_headers)>;

  using BeforeThrottleCallback = base::RepeatingCallback<void(
      URLLoaderThrottle::Delegate* delegate,
      RestartWithURLReset* restart_with_url_reset)>;
  using BeforeThrottleRedirectCallback = base::OnceCallback<void(
      blink::URLLoaderThrottle::Delegate* delegate,
      RestartWithURLReset* restart_with_url_reset,
      std::vector<std::string>* removed_headers,
      net::HttpRequestHeaders* modified_headers,
      net::HttpRequestHeaders* modified_cors_exempt_headers)>;

  size_t will_start_request_called() const {
    return will_start_request_called_;
  }
  size_t will_redirect_request_called() const {
    return will_redirect_request_called_;
  }
  size_t will_process_response_called() const {
    return will_process_response_called_;
  }
  size_t before_will_process_response_called() const {
    return before_will_process_response_called_;
  }

  size_t before_will_redirect_request_called() const {
    return before_will_redirect_request_called_;
  }

  GURL observed_response_url() const { return *response_url_; }

  void set_will_start_request_callback(const ThrottleCallback& callback) {
    will_start_request_callback_ = callback;
  }

  void set_will_redirect_request_callback(ThrottleRedirectCallback callback) {
    will_redirect_request_callback_ = std::move(callback);
  }

  void set_will_process_response_callback(const ThrottleCallback& callback) {
    will_process_response_callback_ = callback;
  }

  void set_before_will_process_response_callback(
      const BeforeThrottleCallback& callback) {
    before_will_process_response_callback_ = callback;
  }

  void set_before_will_redirect_request_callback(
      BeforeThrottleRedirectCallback callback) {
    before_will_redirect_request_callback_ = std::move(callback);
  }

  void set_modify_url_in_will_start(const GURL& url) {
    modify_url_in_will_start_ = url;
  }

  Delegate* delegate() const { return delegate_; }

 private:
  // blink::URLLoaderThrottle implementation.
  void WillStartRequest(network::ResourceRequest* request,
                        bool* defer) override {
    will_start_request_called_++;
    if (!modify_url_in_will_start_.is_empty())
      request->url = modify_url_in_will_start_;

    if (will_start_request_callback_)
      will_start_request_callback_.Run(delegate_.get(), defer);
  }

  void WillRedirectRequest(
      net::RedirectInfo* redirect_info,
      const network::mojom::URLResponseHead& response_head,
      bool* defer,
      std::vector<std::string>* removed_headers,
      net::HttpRequestHeaders* modified_headers,
      net::HttpRequestHeaders* modified_cors_exempt_headers) override {
    will_redirect_request_called_++;
    if (will_redirect_request_callback_) {
      std::move(will_redirect_request_callback_)
          .Run(delegate_.get(), defer, removed_headers, modified_headers,
               modified_cors_exempt_headers);
    }
  }

  void WillProcessResponse(const GURL& response_url,
                           network::mojom::URLResponseHead* response_head,
                           bool* defer) override {
    will_process_response_called_++;
    response_url_ = response_url;
    if (will_process_response_callback_)
      will_process_response_callback_.Run(delegate_.get(), defer);
  }

  void BeforeWillProcessResponse(
      const GURL& response_url,
      const network::mojom::URLResponseHead& response_head,
      RestartWithURLReset* restart_with_url_reset) override {
    before_will_process_response_called_++;
    if (before_will_process_response_callback_) {
      before_will_process_response_callback_.Run(delegate_.get(),
                                                 restart_with_url_reset);
    }
  }

  void BeforeWillRedirectRequest(
      net::RedirectInfo* redirect_info,
      const network::mojom::URLResponseHead& response_head,
      RestartWithURLReset* restart_with_url_reset,
      std::vector<std::string>* removed_headers,
      net::HttpRequestHeaders* modified_headers,
      net::HttpRequestHeaders* modified_cors_exempt_headers) override {
    before_will_redirect_request_called_++;
    if (before_will_redirect_request_callback_) {
      std::move(before_will_redirect_request_callback_)
          .Run(delegate_.get(), restart_with_url_reset, removed_headers,
               modified_headers, modified_cors_exempt_headers);
    }
  }

  size_t will_start_request_called_ = 0;
  size_t will_redirect_request_called_ = 0;
  size_t will_process_response_called_ = 0;
  size_t before_will_process_response_called_ = 0;
  size_t before_will_redirect_request_called_ = 0;

  std::optional<GURL> response_url_;

  ThrottleCallback will_start_request_callback_;
  ThrottleRedirectCallback will_redirect_request_callback_;
  ThrottleCallback will_process_response_callback_;
  BeforeThrottleCallback before_will_process_response_callback_;
  BeforeThrottleRedirectCallback before_will_redirect_request_callback_;

  GURL modify_url_in_will_start_;

  base::OnceClosure destruction_notifier_;
};

class ThrottlingURLLoaderTest : public testing::Test {
 public:
  ThrottlingURLLoaderTest() = default;
  ThrottlingURLLoaderTest(const ThrottlingURLLoaderTest&) = delete;
  ThrottlingURLLoaderTest& operator=(const ThrottlingURLLoaderTest&) = delete;

  std::unique_ptr<ThrottlingURLLoader>& loader() { return loader_; }
  TestURLLoaderThrottle* throttle() const { return throttle_; }

 protected:
  // testing::Test implementation.
  void SetUp() override {
    auto throttle = std::make_unique<TestURLLoaderThrottle>(
        base::BindOnce(&ThrottlingURLLoaderTest::ResetThrottleRawPointer,
                       weak_factory_.GetWeakPtr()));

    throttle_ = throttle.get();

    throttles_.push_back(std::move(throttle));
  }

  void CreateLoaderAndStart(
      std::optional<network::ResourceRequest::TrustedParams> trusted_params =
          std::nullopt) {
    network::ResourceRequest request;
    request.url = request_url;
    request.trusted_params = std::move(trusted_params);
    loader_ = ThrottlingURLLoader::CreateLoaderAndStart(
        factory_.shared_factory(), std::move(throttles_), /*request_id=*/0,
        /*options=*/0, &request, &client_, TRAFFIC_ANNOTATION_FOR_TESTS,
        base::SingleThreadTaskRunner::GetCurrentDefault());
    factory_.factory_remote().FlushForTesting();
  }

  void ResetLoader() {
    ResetThrottleRawPointer();
    loader_.reset();
  }

  void ResetThrottleRawPointer() { throttle_ = nullptr; }

  // Be the first member so it is destroyed last.
  base::test::TaskEnvironment task_environment_;

  std::unique_ptr<ThrottlingURLLoader> loader_;
  std::vector<std::unique_ptr<blink::URLLoaderThrottle>> throttles_;

  TestURLLoaderFactory factory_;
  TestURLLoaderClient client_;

  // Owned by |throttles_| or |loader_|.
  raw_ptr<TestURLLoaderThrottle> throttle_ = nullptr;

  base::WeakPtrFactory<ThrottlingURLLoaderTest> weak_factory_{this};
};

TEST_F(ThrottlingURLLoaderTest, CancelBeforeStart) {
  throttle_->set_will_start_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        delegate->CancelWithError(net::ERR_ACCESS_DENIED);
      }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();
  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeleteBeforeStart) {
  base::RunLoop run_loop;
  throttle_->set_will_start_request_callback(base::BindLambdaForTesting(
      [this, &run_loop](blink::URLLoaderThrottle::Delegate* delegate,
                        bool* defer) {
        ResetLoader();
        run_loop.Quit();
      }));

  CreateLoaderAndStart();
  run_loop.Run();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeferBeforeStart) {
  throttle_->set_will_start_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
      }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::OK, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());

  throttle_->delegate()->Resume();
  factory_.factory_remote().FlushForTesting();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());

  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(1u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, ModifyURLBeforeStart) {
  throttle_->set_modify_url_in_will_start(GURL("http://example.org/foo"));

  CreateLoaderAndStart();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
}

TEST_F(ThrottlingURLLoaderTest,
       CrossOriginRedirectBeforeStartWithIsolationInfo) {
  const GURL modified_url = GURL("https://example.org");

  throttle_->set_modify_url_in_will_start(modified_url);

  network::ResourceRequest::TrustedParams trusted_params;
  trusted_params.isolation_info = net::IsolationInfo::Create(
      net::IsolationInfo::RequestType::kMainFrame,
      url::Origin::Create(request_url), url::Origin::Create(request_url),
      net::SiteForCookies());

  const auto expected_redirected_isolation_info =
      trusted_params.isolation_info.CreateForRedirect(
          url::Origin::Create(modified_url));
  ASSERT_FALSE(trusted_params.isolation_info.IsEqualForTesting(
      expected_redirected_isolation_info));

  CreateLoaderAndStart(std::move(trusted_params));

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  base::RunLoop run_loop;
  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&](const network::ResourceRequest& url_request) {
        run_loop.Quit();

        ASSERT_TRUE(url_request.trusted_params);
        EXPECT_TRUE(
            url_request.trusted_params->isolation_info.IsEqualForTesting(
                expected_redirected_isolation_info));
      }));

  loader_->FollowRedirect({}, {}, {});

  run_loop.Run();
}

// Regression test for crbug.com/933538
TEST_F(ThrottlingURLLoaderTest, ModifyURLAndDeferRedirect) {
  throttle_->set_modify_url_in_will_start(GURL("http://example.org/foo"));
  throttle_->set_will_start_request_callback(
      base::BindRepeating([](blink::URLLoaderThrottle::Delegate* /* delegate */,
                             bool* defer) { *defer = true; }));
  base::RunLoop run_loop;
  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [&](blink::URLLoaderThrottle::Delegate* /* delegate */, bool* defer,
          std::vector<std::string>* /* removed_headers */,
          net::HttpRequestHeaders* /* modified_headers */,
          net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        *defer = true;
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());

  throttle_->delegate()->Resume();
  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());

  throttle_->delegate()->Resume();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());
  EXPECT_EQ(0u, factory_.create_loader_and_start_called());
  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(1u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());
}

// Regression test for crbug.com/1053700.
TEST_F(ThrottlingURLLoaderTest,
       RedirectCallbackShouldNotBeCalledAfterDestruction) {
  throttle_->set_modify_url_in_will_start(GURL("http://example.org/foo"));
  base::RunLoop run_loop;
  bool called = false;
  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [&](blink::URLLoaderThrottle::Delegate* /* delegate */, bool* defer,
          std::vector<std::string>* /* removed_headers */,
          net::HttpRequestHeaders* /* modified_headers */,
          net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        *defer = true;
        called = true;
      }));

  // We don't use CreateLoaderAndStart because we don't want to call
  // FlushForTesting().
  network::ResourceRequest request;
  request.url = request_url;
  loader_ = ThrottlingURLLoader::CreateLoaderAndStart(
      factory_.shared_factory(), std::move(throttles_), 0, 0, &request,
      &client_, TRAFFIC_ANNOTATION_FOR_TESTS,
      base::SingleThreadTaskRunner::GetCurrentDefault());

  loader_ = nullptr;

  run_loop.RunUntilIdle();
  EXPECT_FALSE(called);
}

TEST_F(ThrottlingURLLoaderTest, CancelBeforeRedirect) {
  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* /* defer */,
         std::vector<std::string>* /* removed_headers */,
         net::HttpRequestHeaders* /* modified_headers */,
         net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        delegate->CancelWithError(net::ERR_ACCESS_DENIED);
      }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveRedirect();

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeleteBeforeRedirect) {
  base::RunLoop run_loop;
  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [this, &run_loop](
          blink::URLLoaderThrottle::Delegate* delegate, bool* /* defer */,
          std::vector<std::string>* /* removed_headers */,
          net::HttpRequestHeaders* /* modified_headers */,
          net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        ResetLoader();
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveRedirect();

  run_loop.Run();

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, CancelBeforeWillRedirect) {
  throttle_->set_before_will_redirect_request_callback(
      base::BindLambdaForTesting(
          [](blink::URLLoaderThrottle::Delegate* delegate,
             RestartWithURLReset* restart_with_url_reset,
             std::vector<std::string>* /* removed_headers */,
             net::HttpRequestHeaders* /* modified_headers */,
             net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
            delegate->CancelWithError(net::ERR_ACCESS_DENIED);
          }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveRedirect();

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeleteBeforeWillRedirect) {
  base::RunLoop run_loop;
  throttle_->set_before_will_redirect_request_callback(
      base::BindLambdaForTesting(
          [this, &run_loop](
              blink::URLLoaderThrottle::Delegate* delegate,
              RestartWithURLReset* restart_with_url_reset,
              std::vector<std::string>* /* removed_headers */,
              net::HttpRequestHeaders* /* modified_headers */,
              net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
            ResetLoader();
            run_loop.Quit();
          }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveRedirect();

  run_loop.Run();

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeferBeforeRedirect) {
  base::RunLoop run_loop1;
  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [&run_loop1](
          blink::URLLoaderThrottle::Delegate* delegate, bool* defer,
          std::vector<std::string>* /* removed_headers */,
          net::HttpRequestHeaders* /* modified_headers */,
          net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        *defer = true;
        run_loop1.Quit();
      }));

  base::RunLoop run_loop2;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop2](int error) {
        EXPECT_EQ(net::ERR_UNEXPECTED, error);
        run_loop2.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveRedirect();

  run_loop1.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  factory_.NotifyClientOnComplete(net::ERR_UNEXPECTED);

  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());

  throttle_->delegate()->Resume();
  run_loop2.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(1u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, ModifyHeadersBeforeRedirect) {
  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* /* defer */,
         std::vector<std::string>* removed_headers,
         net::HttpRequestHeaders* modified_headers,
         net::HttpRequestHeaders* modified_cors_exempt_headers) {
        removed_headers->push_back("X-Test-Header-1");
        modified_headers->SetHeader("X-Test-Header-2", "Foo");
        modified_headers->SetHeader("X-Test-Header-3", "Throttle Value");
        modified_cors_exempt_headers->SetHeader("X-Test-Cors-Exempt-Header-1",
                                                "Bubble");
      }));

  client_.set_on_received_redirect_callback(base::BindLambdaForTesting([&]() {
    net::HttpRequestHeaders modified_headers;
    modified_headers.SetHeader("X-Test-Header-3", "Client Value");
    modified_headers.SetHeader("X-Test-Header-4", "Bar");
    net::HttpRequestHeaders modified_cors_exempt_headers;
    modified_cors_exempt_headers.SetHeader("X-Test-Cors-Exempt-Header-1",
                                           "Bobble");
    loader_->FollowRedirect({} /* removed_headers */,
                            std::move(modified_headers),
                            std::move(modified_cors_exempt_headers));
  }));

  CreateLoaderAndStart();
  factory_.NotifyClientOnReceiveRedirect();
  base::RunLoop().RunUntilIdle();

  ASSERT_FALSE(factory_.headers_removed_on_redirect().empty());
  EXPECT_THAT(factory_.headers_removed_on_redirect(),
              testing::ElementsAre("X-Test-Header-1"));
  ASSERT_FALSE(factory_.headers_modified_on_redirect().IsEmpty());
  EXPECT_EQ(
      "X-Test-Header-2: Foo\r\n"
      "X-Test-Header-3: Client Value\r\n"
      "X-Test-Header-4: Bar\r\n\r\n",
      factory_.headers_modified_on_redirect().ToString());
  ASSERT_FALSE(factory_.cors_exempt_headers_modified_on_redirect().IsEmpty());
  EXPECT_EQ("X-Test-Cors-Exempt-Header-1: Bobble\r\n\r\n",
            factory_.cors_exempt_headers_modified_on_redirect().ToString());
}

TEST_F(ThrottlingURLLoaderTest, MultipleThrottlesModifyHeadersBeforeRedirect) {
  auto* throttle2 = new TestURLLoaderThrottle();
  throttles_.push_back(base::WrapUnique(throttle2));

  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* /* defer */,
         std::vector<std::string>* removed_headers,
         net::HttpRequestHeaders* modified_headers,
         net::HttpRequestHeaders* modified_cors_exempt_headers) {
        removed_headers->push_back("X-Test-Header-0");
        removed_headers->push_back("X-Test-Header-1");
        modified_headers->SetHeader("X-Test-Header-3", "Foo");
        modified_headers->SetHeader("X-Test-Header-4", "Throttle1");
      }));

  throttle2->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* /* defer */,
         std::vector<std::string>* removed_headers,
         net::HttpRequestHeaders* modified_headers,
         net::HttpRequestHeaders* modified_cors_exempt_headers) {
        removed_headers->push_back("X-Test-Header-1");
        removed_headers->push_back("X-Test-Header-2");
        modified_headers->SetHeader("X-Test-Header-4", "Throttle2");
      }));

  client_.set_on_received_redirect_callback(base::BindLambdaForTesting(
      [&]() { loader_->FollowRedirect({}, {}, {}); }));

  CreateLoaderAndStart();
  factory_.NotifyClientOnReceiveRedirect();
  base::RunLoop().RunUntilIdle();

  ASSERT_FALSE(factory_.headers_removed_on_redirect().empty());
  EXPECT_THAT(factory_.headers_removed_on_redirect(),
              testing::ElementsAre("X-Test-Header-0", "X-Test-Header-1",
                                   "X-Test-Header-2"));
  ASSERT_FALSE(factory_.headers_modified_on_redirect().IsEmpty());
  EXPECT_EQ(
      "X-Test-Header-3: Foo\r\n"
      "X-Test-Header-4: Throttle2\r\n\r\n",
      factory_.headers_modified_on_redirect().ToString());
}

TEST_F(ThrottlingURLLoaderTest, CancelBeforeResponse) {
  throttle_->set_will_process_response_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        delegate->CancelWithError(net::ERR_ACCESS_DENIED);
      }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeleteBeforeResponse) {
  base::RunLoop run_loop;
  throttle_->set_will_process_response_callback(base::BindLambdaForTesting(
      [this, &run_loop](blink::URLLoaderThrottle::Delegate* delegate,
                        bool* defer) {
        ResetLoader();
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop.Run();

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, CancelBeforeWillProcessResponse) {
  throttle_->set_before_will_process_response_callback(
      base::BindLambdaForTesting(
          [](blink::URLLoaderThrottle::Delegate* delegate,
             RestartWithURLReset* restart_with_url_reset) {
            delegate->CancelWithError(net::ERR_ACCESS_DENIED);
          }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());
  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeleteBeforeWillProcessResponse) {
  base::RunLoop run_loop;
  throttle_->set_before_will_process_response_callback(
      base::BindLambdaForTesting(
          [this, &run_loop](blink::URLLoaderThrottle::Delegate* delegate,
                            RestartWithURLReset* restart_with_url_reset) {
            ResetLoader();
            run_loop.Quit();
          }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop.Run();

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeferBeforeResponse) {
  base::RunLoop run_loop1;
  throttle_->set_will_process_response_callback(base::BindRepeating(
      [](const base::RepeatingClosure& quit_closure,
         blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
        quit_closure.Run();
      },
      run_loop1.QuitClosure()));

  base::RunLoop run_loop2;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop2](int error) {
        EXPECT_EQ(net::ERR_UNEXPECTED, error);
        run_loop2.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop1.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  factory_.NotifyClientOnComplete(net::ERR_UNEXPECTED);

  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());

  throttle_->delegate()->Resume();
  run_loop2.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(1u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, PipeClosure) {
  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ABORTED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.CloseClientPipe();

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, ResumeNoOpIfNotDeferred) {
  auto resume_callback = base::BindRepeating(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* /* defer */) {
        delegate->Resume();
        delegate->Resume();
      });
  throttle_->set_will_start_request_callback(resume_callback);
  throttle_->set_will_process_response_callback(std::move(resume_callback));
  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* /* defer */,
         std::vector<std::string>* /* removed_headers */,
         net::HttpRequestHeaders* /* modified_headers */,
         net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        delegate->Resume();
        delegate->Resume();
      }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::OK, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();
  factory_.NotifyClientOnReceiveRedirect();
  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(redirect_url));

  EXPECT_EQ(1u, client_.on_received_response_called());
  EXPECT_EQ(1u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, CancelNoOpIfAlreadyCanceled) {
  throttle_->set_will_start_request_callback(base::BindRepeating(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        delegate->CancelWithError(net::ERR_ACCESS_DENIED);
        delegate->CancelWithError(net::ERR_UNEXPECTED);
      }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();
  throttle_->delegate()->CancelWithError(net::ERR_INVALID_ARGUMENT);
  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, ResumeNoOpIfAlreadyCanceled) {
  throttle_->set_will_process_response_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        delegate->CancelWithError(net::ERR_ACCESS_DENIED);
        delegate->Resume();
      }));

  base::RunLoop run_loop1;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop1](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop1.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop1.Run();

  throttle_->delegate()->Resume();

  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, MultipleThrottlesBasicSupport) {
  throttles_.emplace_back(std::make_unique<TestURLLoaderThrottle>());
  auto* throttle2 =
      static_cast<TestURLLoaderThrottle*>(throttles_.back().get());
  CreateLoaderAndStart();
  factory_.NotifyClientOnReceiveResponse();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle2->will_start_request_called());
}

TEST_F(ThrottlingURLLoaderTest, BlockWithOneOfMultipleThrottles) {
  throttles_.emplace_back(std::make_unique<TestURLLoaderThrottle>());
  auto* throttle2 =
      static_cast<TestURLLoaderThrottle*>(throttles_.back().get());
  throttle2->set_will_start_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
      }));

  base::RunLoop loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&loop](int error) {
        EXPECT_EQ(net::OK, error);
        loop.Quit();
      }));

  CreateLoaderAndStart();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle2->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle2->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle2->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());
  EXPECT_EQ(0u, throttle2->will_process_response_called());

  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());

  throttle2->delegate()->Resume();
  factory_.factory_remote().FlushForTesting();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());

  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle2->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle2->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle2->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());
  EXPECT_EQ(1u, throttle2->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));
  EXPECT_TRUE(
      throttle2->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(1u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, BlockWithMultipleThrottles) {
  throttles_.emplace_back(std::make_unique<TestURLLoaderThrottle>());
  auto* throttle2 =
      static_cast<TestURLLoaderThrottle*>(throttles_.back().get());

  // Defers a request on both throttles.
  throttle_->set_will_start_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
      }));
  throttle2->set_will_start_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
      }));

  base::RunLoop loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&loop](int error) {
        EXPECT_EQ(net::OK, error);
        loop.Quit();
      }));

  CreateLoaderAndStart();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle2->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle2->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle2->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());
  EXPECT_EQ(0u, throttle2->will_process_response_called());

  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());

  throttle_->delegate()->Resume();

  // Should still not have started because there's |throttle2| is still blocking
  // the request.
  factory_.factory_remote().FlushForTesting();
  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  throttle2->delegate()->Resume();

  // Now it should have started.
  factory_.factory_remote().FlushForTesting();
  EXPECT_EQ(1u, factory_.create_loader_and_start_called());

  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle2->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle2->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle2->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());
  EXPECT_EQ(1u, throttle2->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));
  EXPECT_TRUE(
      throttle2->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(1u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest,
       DestroyingThrottlingURLLoaderInDelegateCall_Response) {
  base::RunLoop run_loop1;
  throttle_->set_will_process_response_callback(base::BindLambdaForTesting(
      [&run_loop1](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
        run_loop1.Quit();
      }));

  base::RunLoop run_loop2;
  client_.set_on_received_response_callback(base::BindLambdaForTesting([&]() {
    // Destroy the ThrottlingURLLoader while inside a delegate call from a
    // throttle.
    loader().reset();

    // The throttle should stay alive.
    EXPECT_NE(nullptr, throttle());

    run_loop2.Quit();
  }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop1.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  throttle_->delegate()->Resume();
  run_loop2.Run();

  // The ThrottlingURLLoader should be gone.
  EXPECT_EQ(nullptr, loader_);
  // The throttle should stay alive and destroyed later.
  EXPECT_NE(nullptr, throttle_);

  task_environment_.RunUntilIdle();
  EXPECT_EQ(nullptr, throttle_.get());
}

// Regression test for crbug.com/833292.
TEST_F(ThrottlingURLLoaderTest,
       DestroyingThrottlingURLLoaderInDelegateCall_Redirect) {
  base::RunLoop run_loop1;
  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [&run_loop1](
          blink::URLLoaderThrottle::Delegate* delegate, bool* defer,
          std::vector<std::string>* /* removed_headers */,
          net::HttpRequestHeaders* /* modified_headers */,
          net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        *defer = true;
        run_loop1.Quit();
      }));

  base::RunLoop run_loop2;
  client_.set_on_received_redirect_callback(base::BindRepeating(
      [](ThrottlingURLLoaderTest* test,
         const base::RepeatingClosure& quit_closure) {
        // Destroy the ThrottlingURLLoader while inside a delegate call from a
        // throttle.
        test->loader().reset();

        // The throttle should stay alive.
        EXPECT_NE(nullptr, test->throttle());

        quit_closure.Run();
      },
      base::Unretained(this), run_loop2.QuitClosure()));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveRedirect();

  run_loop1.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  throttle_->delegate()->Resume();
  run_loop2.Run();

  // The ThrottlingURLLoader should be gone.
  EXPECT_EQ(nullptr, loader_);
  // The throttle should stay alive and destroyed later.
  EXPECT_NE(nullptr, throttle_);

  task_environment_.RunUntilIdle();
  EXPECT_EQ(nullptr, throttle_.get());
}

// Call RestartWithURLReset() from a single throttle while processing
// BeforeWillProcessResponse(), and verify that it restarts with the original
// URL.
TEST_F(ThrottlingURLLoaderTest, RestartWithURLReset) {
  base::RunLoop run_loop1;
  base::RunLoop run_loop2;
  base::RunLoop run_loop3;

  // URL for internal redirect.
  const GURL modified_url = GURL("http://www.example.uk.com");
  throttle_->set_modify_url_in_will_start(modified_url);

  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&run_loop1](const network::ResourceRequest& url_request) {
        run_loop1.Quit();
      }));

  // Set the client to actually follow redirects to allow URL resetting to
  // occur.
  client_.set_on_received_redirect_callback(
      base::BindLambdaForTesting([this]() {
        net::HttpRequestHeaders modified_headers;
        loader_->FollowRedirect({} /* removed_headers */,
                                std::move(modified_headers),
                                {} /* modified_cors_exempt_headers */);
      }));

  CreateLoaderAndStart();
  run_loop1.Run();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());
  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  // Restart the request with URL reset when processing
  // BeforeWillProcessResponse().
  throttle_->set_before_will_process_response_callback(
      base::BindRepeating([](blink::URLLoaderThrottle::Delegate* delegate,
                             RestartWithURLReset* restart_with_url_reset) {
        *restart_with_url_reset = RestartWithURLReset(true);
      }));

  // The next time we intercept CreateLoaderAndStart() should be for the
  // restarted request.
  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&run_loop2](const network::ResourceRequest& url_request) {
        run_loop2.Quit();
      }));

  factory_.NotifyClientOnReceiveResponse();
  run_loop2.Run();

  EXPECT_EQ(2u, factory_.create_loader_and_start_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  // Now that the restarted request has been made, clear
  // BeforeWillProcessResponse() so it doesn't restart the request yet again.
  throttle_->set_before_will_process_response_callback(
      TestURLLoaderThrottle::BeforeThrottleCallback());

  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop3](int error) {
        EXPECT_EQ(net::OK, error);
        run_loop3.Quit();
      }));

  // Complete the response.
  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  run_loop3.Run();

  EXPECT_EQ(2u, factory_.create_loader_and_start_called());
  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(2u, throttle_->will_redirect_request_called());
  EXPECT_EQ(2u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());
  EXPECT_EQ(throttle_->observed_response_url(), request_url);
}

// Call RestartWithURLReset() from multiple throttles while processing
// BeforeWillProcessResponse(). Ensures that the request is restarted exactly
// once with the original URL.
TEST_F(ThrottlingURLLoaderTest, MultipleRestartWithURLReset) {
  // Create two additional TestURLLoaderThrottles for a total of 3, and keep
  // local unowned pointers to them in |throttles|.
  std::vector<TestURLLoaderThrottle*> throttles;
  ASSERT_EQ(1u, throttles_.size());
  throttles.push_back(throttle_);
  for (size_t i = 0; i < 2u; ++i) {
    auto throttle = std::make_unique<TestURLLoaderThrottle>();
    throttles.push_back(throttle.get());
    throttles_.push_back(std::move(throttle));
  }
  ASSERT_EQ(3u, throttles_.size());
  ASSERT_EQ(3u, throttles.size());

  base::RunLoop run_loop1;
  base::RunLoop run_loop2;
  base::RunLoop run_loop3;

  // URL for internal redirect.
  const GURL modified_url = GURL("http://www.example.uk.com");
  throttle_->set_modify_url_in_will_start(modified_url);

  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&run_loop1](const network::ResourceRequest& url_request) {
        run_loop1.Quit();
      }));

  // Set the client to actually follow redirects to allow URL resetting to
  // occur.
  client_.set_on_received_redirect_callback(
      base::BindLambdaForTesting([this]() {
        net::HttpRequestHeaders modified_headers;
        loader_->FollowRedirect({} /* removed_headers */,
                                std::move(modified_headers),
                                {} /* modified_cors_exempt_headers */);
      }));

  CreateLoaderAndStart();
  run_loop1.Run();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());
  for (const auto* throttle : throttles) {
    EXPECT_EQ(1u, throttle->will_start_request_called());
    EXPECT_EQ(1u, throttle->will_redirect_request_called());
    EXPECT_EQ(0u, throttle->before_will_process_response_called());
    EXPECT_EQ(0u, throttle->will_process_response_called());
  }

  // Have two of the three throttles restart with URL reset when processing
  // BeforeWillProcessResponse().
  for (auto* throttle : {throttles[0], throttles[2]}) {
    throttle->set_before_will_process_response_callback(
        base::BindRepeating([](blink::URLLoaderThrottle::Delegate* delegate,
                               RestartWithURLReset* restart_with_url_reset) {
          *restart_with_url_reset = RestartWithURLReset(true);
        }));
  }

  // The next time we intercept CreateLoaderAndStart() should be for the
  // restarted request.
  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&run_loop2](const network::ResourceRequest& url_request) {
        run_loop2.Quit();
      }));

  factory_.NotifyClientOnReceiveResponse();
  run_loop2.Run();

  EXPECT_EQ(2u, factory_.create_loader_and_start_called());
  for (const auto* throttle : {throttles[0], throttles[2]}) {
    EXPECT_EQ(1u, throttle->before_will_process_response_called());
    EXPECT_EQ(0u, throttle->will_process_response_called());
  }

  // Now that the restarted request has been made, clear
  // BeforeWillProcessResponse() so it doesn't restart the request yet again.
  for (auto* throttle : throttles) {
    throttle->set_before_will_process_response_callback(
        TestURLLoaderThrottle::BeforeThrottleCallback());
  }

  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop3](int error) {
        EXPECT_EQ(net::OK, error);
        run_loop3.Quit();
      }));

  // Complete the response.
  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  run_loop3.Run();

  EXPECT_EQ(2u, factory_.create_loader_and_start_called());
  for (auto* throttle : throttles) {
    EXPECT_EQ(1u, throttle->will_start_request_called());
    EXPECT_EQ(2u, throttle->will_redirect_request_called());
    EXPECT_EQ(2u, throttle->before_will_process_response_called());
    EXPECT_EQ(1u, throttle->will_process_response_called());
    EXPECT_EQ(throttle_->observed_response_url(), request_url);
  }
}

// Test restarts from "BeforeWillRedirectRequest".
TEST_F(ThrottlingURLLoaderTest, RestartWithURLResetBeforeWillRedirectRequest) {
  base::RunLoop run_loop1;
  base::RunLoop run_loop2;

  // URL for internal redirect.
  GURL modified_url = GURL("http://www.example.uk.com");
  throttle_->set_modify_url_in_will_start(modified_url);

  // When we intercept CreateLoaderAndStart() it is for the restarted request
  // already.
  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&run_loop1](const network::ResourceRequest& url_request) {
        run_loop1.Quit();
      }));

  // Set the client to actually follow redirects to allow URL resetting to
  // occur.
  client_.set_on_received_redirect_callback(
      base::BindLambdaForTesting([this]() {
        net::HttpRequestHeaders modified_headers;
        loader_->FollowRedirect({} /* removed_headers */,
                                std::move(modified_headers),
                                {} /* modified_cors_exempt_headers */);
      }));

  // Restart the request with URL reset when processing
  // BeforeWillRedirectRequest().
  throttle_->set_before_will_redirect_request_callback(base::BindRepeating(
      [](blink::URLLoaderThrottle::Delegate* delegate,
         RestartWithURLReset* restart_with_url_reset,
         std::vector<std::string>* /* removed_headers */,
         net::HttpRequestHeaders* /* modified_headers */,
         net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        *restart_with_url_reset = RestartWithURLReset(true);
      }));

  CreateLoaderAndStart();
  run_loop1.Run();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());
  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(2u, throttle_->before_will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop2](int error) {
        EXPECT_EQ(net::OK, error);
        run_loop2.Quit();
      }));

  // Complete the response.
  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  run_loop2.Run();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());
  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(2u, throttle_->before_will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());
  EXPECT_EQ(throttle_->observed_response_url(), request_url);
}

}  // namespace
}  // namespace blink
```