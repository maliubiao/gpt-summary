Response:
Let's break down the thought process to analyze the provided C++ unittest file.

**1. Understanding the Goal:**

The primary goal is to analyze `url_loader_unittest.cc` and describe its functionalities, its relation to web technologies (JavaScript, HTML, CSS), and identify potential usage errors.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for prominent keywords and structures. This gives a high-level understanding. Keywords that immediately jump out are:

* `unittest.cc`, `TEST_F`, `EXPECT_TRUE`, `EXPECT_FALSE`, `ASSERT_EQ`: These clearly indicate this is a unit testing file using Google Test.
* `URLLoader`, `URLLoaderClient`, `ResourceRequestSender`:  These suggest the file is testing the functionality of a `URLLoader`, likely involving sending network requests.
* `network::ResourceRequest`, `network::mojom::URLResponseHead`, `WebURLResponse`, `WebURLError`:  These are data structures related to network requests and responses in the Chromium environment.
* `SyncLoadResponse`:  Indicates testing of synchronous loading scenarios.
* `Redirect`, `Response`, `Failure`: Likely represent different test scenarios for network requests.
* `DeleteOn...`:  Suggests testing scenarios where objects are deleted at specific points during the loading process, possibly to check for memory leaks or crashes.
* `LoaderFreezeMode`: Indicates a feature to pause or control the loading process.
* `SSLInfo`, `AuthChallengeInfo`: Suggests tests related to secure connections and authentication.
* `encoded_body_length`, `encoded_data_length`:  Relate to performance metrics and data transfer sizes.

**3. Identifying Core Functionality through Test Cases:**

The `TEST_F` macros define individual test cases. By examining these test case names and their internal logic, we can deduce the core functionalities being tested:

* **`Success`:** Tests a successful network request and response.
* **`Redirect`:** Tests handling of HTTP redirects.
* **`Failure`:** Tests handling of failed network requests.
* **`DeleteOnReceiveRedirect`, `DeleteOnReceiveResponse`, `DeleteOnFinish`, `DeleteOnFail`:** These test the robustness of the `URLLoader` and its clients when the client object is deleted during various stages of the loading process. This is a common practice in Chromium to prevent use-after-free errors.
* **`DefersLoadingBeforeStart`:** Tests the `Freeze` functionality, ensuring the loader can be paused before a request is started.
* **`ResponseIPEndpoint`, `ResponseAddressSpace`, `ClientAddressSpace`:** These test that the `WebURLResponse` correctly captures IP address and address space information from the underlying network response.
* **`SSLInfo`:** Tests that SSL connection information is correctly captured and available in the `WebURLResponse`.
* **`SyncLengths`:**  Specifically tests the accuracy of length fields (`encoded_body_length`, `encoded_data_length`) in synchronous loading scenarios, which are important for performance metrics.
* **`AuthChallengeInfo`:** Tests that authentication challenge information is correctly passed through to the `WebURLResponse`.

**4. Relating to Web Technologies (JavaScript, HTML, CSS):**

This is where we connect the low-level testing to the high-level web platform.

* **Fetching Resources (Core):** The `URLLoader` is fundamental to how browsers fetch resources like HTML, CSS, JavaScript, images, etc. Every time a browser needs to load something from a URL, the `URLLoader` (or a similar component) is involved.
* **JavaScript `fetch()` API:** The `URLLoader` is a backend component that implements the underlying network operations for the JavaScript `fetch()` API. The tests for successful requests, redirects, and failures directly reflect the behavior a JavaScript developer would observe when using `fetch()`.
* **Loading HTML Documents:** When a user navigates to a URL, the browser uses a `URLLoader` to fetch the initial HTML document. The redirect tests are relevant here as many web applications use redirects.
* **Loading CSS Stylesheets:**  When the browser parses an HTML document and encounters a `<link>` tag for a CSS file, a `URLLoader` is used to fetch that CSS file.
* **Loading JavaScript Files:** Similar to CSS, `<script>` tags trigger the use of `URLLoader` to fetch JavaScript files.
* **Error Handling:** The "Failure" tests and the `WebURLError` directly relate to how the browser handles network errors when loading resources, which might be surfaced to the user or handled by JavaScript error handlers.
* **Security (SSL):** The `SSLInfo` test directly relates to the security of HTTPS connections, which is crucial for protecting user data and ensuring website authenticity.
* **Authentication:** The `AuthChallengeInfo` test is relevant to scenarios where a server requires authentication (e.g., a 401 or 407 HTTP status code).
* **Performance:** The `SyncLengths` test highlights the importance of accurate length reporting for performance monitoring, which can be exposed in browser developer tools and used by web performance APIs.

**5. Logical Inference (Assumptions, Inputs, Outputs):**

For each test case, we can infer the assumptions, inputs, and expected outputs:

* **Assumption:** The `MockResourceRequestSender` correctly simulates the network layer's behavior.
* **Input:** A `network::ResourceRequest` object containing the URL and other request parameters.
* **Output:**  The expected sequence of calls to the `URLLoaderClient` methods (`WillFollowRedirect`, `DidReceiveResponse`, `DidFinishLoading`, `DidFail`). The state of the `TestURLLoaderClient` (e.g., `did_receive_response_`, `did_finish_`, `error_`).

**6. Common Usage Errors:**

* **Deleting the `URLLoaderClient` prematurely:** The "DeleteOn..." tests highlight a critical pattern in Chromium where objects might be deleted during callbacks. Failing to handle this correctly can lead to crashes. A common mistake might be a poorly designed object lifecycle management where a client object is destroyed while the loader is still active.
* **Incorrectly handling redirects:**  Failing to follow redirects correctly or getting into redirect loops are common web development issues. The redirect tests ensure the underlying `URLLoader` handles these cases properly.
* **Not handling network errors:**  Web developers need to gracefully handle network errors. The "Failure" test highlights the importance of the `URLLoader` providing accurate error information.

**7. Structuring the Output:**

Finally, organize the findings into a clear and structured format, as demonstrated in the initial good answer. Use headings and bullet points to improve readability. Provide concrete examples to illustrate the connections to web technologies.
这个C++代码文件 `url_loader_unittest.cc` 是 Chromium Blink 引擎中 `URLLoader` 类的单元测试。它的主要功能是验证 `URLLoader` 类的各种行为和功能是否符合预期。

**核心功能列举:**

1. **异步请求的生命周期测试:**  测试 `URLLoader` 发起异步请求、接收重定向、接收响应头、接收响应体、请求成功完成和请求失败的各种场景。
2. **同步请求的生命周期测试:** 测试 `URLLoader` 发起同步请求并获取响应的场景。
3. **取消请求测试:**  虽然代码中没有显式的取消请求的测试用例，但 `MockResourceRequestSender` 的 `Cancel` 方法被调用并验证，表明测试覆盖了取消请求的机制。
4. **客户端删除时的处理:** 测试在 `URLLoader` 的不同生命周期阶段（接收重定向、接收响应、完成、失败）客户端被删除时，`URLLoader` 能否正确处理，防止崩溃。
5. **延迟加载测试:** 测试 `URLLoader` 的 `Freeze` 功能，验证其可以在启动请求前被冻结，并且只有在解冻后才真正发送请求。
6. **响应信息的正确性验证:**
    - **IP Endpoint:** 验证 `WebURLResponse` 能否正确获取并反映服务器的 IP 地址和端口信息。
    - **地址空间:** 验证 `WebURLResponse` 能否正确获取并反映服务器和客户端的地址空间信息（公网、私网等）。
    - **SSL 信息:** 验证对于 HTTPS 请求，`WebURLResponse` 能否正确获取并反映 SSL 连接的详细信息，如证书信息。
    - **长度信息:** 验证对于同步请求，`WebURLResponse` 能否正确获取并反映编码后的 body 长度和总数据长度，这对于性能指标（PerformanceResourceTiming API）非常重要。
    - **认证挑战信息:** 验证 `WebURLResponse` 能否正确传递认证挑战信息 (AuthChallengeInfo)。
7. **与 `ResourceRequestSender` 的交互测试:** 通过 `MockResourceRequestSender` 模拟网络层的行为，验证 `URLLoader` 在不同场景下如何调用 `ResourceRequestSender` 的方法。

**与 JavaScript, HTML, CSS 功能的关系及举例说明:**

`URLLoader` 是浏览器网络请求的核心组件，它负责从网络上获取各种资源，包括 JavaScript, HTML, CSS 文件以及图片、音视频等其他资源。

* **JavaScript `fetch()` API 和 XMLHttpRequest:** 当 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起网络请求时，Blink 引擎底层会使用 `URLLoader` 来执行这些请求。
    * **假设输入:**  JavaScript 代码 `fetch('http://example.com/data.json')`。
    * **逻辑推理:**  `URLLoader` 会根据这个 URL 创建一个 `network::ResourceRequest`，并发送给网络层。如果请求成功，`URLLoaderClient` 的 `DidReceiveResponse` 方法会被调用，并将响应数据传递给 JavaScript 的 Promise 或回调函数。
    * **测试用例关联:**  `URLLoaderTest::Success` 测试用例模拟了这种成功获取资源的场景。
* **加载 HTML 文档:** 当浏览器导航到一个新的 URL 时，Blink 引擎会使用 `URLLoader` 来下载 HTML 文档。
    * **假设输入:** 用户在地址栏输入 `http://example.com` 并回车。
    * **逻辑推理:** `URLLoader` 会请求 `http://example.com` 的 HTML 文档。如果服务器返回 302 重定向，`URLLoaderClient` 的 `WillFollowRedirect` 方法会被调用，决定是否跟随重定向。
    * **测试用例关联:** `URLLoaderTest::Redirect` 测试用例模拟了重定向的场景。
* **加载 CSS 样式表:** 当 HTML 解析器遇到 `<link rel="stylesheet" href="style.css">` 标签时，Blink 引擎会使用 `URLLoader` 来下载 `style.css` 文件。
    * **假设输入:** HTML 文档包含 `<link rel="stylesheet" href="style.css">`。
    * **逻辑推理:**  `URLLoader` 会请求 `style.css`。如果请求失败（例如 404 错误），`URLLoaderClient` 的 `DidFail` 方法会被调用，浏览器会采取相应的错误处理措施。
    * **测试用例关联:** `URLLoaderTest::Failure` 测试用例模拟了请求失败的场景。
* **加载 JavaScript 脚本:** 当 HTML 解析器遇到 `<script src="script.js"></script>` 标签时，Blink 引擎会使用 `URLLoader` 下载 `script.js` 文件。
* **处理资源加载错误:** 当网络请求失败时，`URLLoader` 会通知 `URLLoaderClient`，并将错误信息封装在 `WebURLError` 对象中。这些错误信息最终可能会被暴露给 JavaScript 的错误处理机制。

**逻辑推理的假设输入与输出:**

* **假设输入 (针对 `URLLoaderTest::Success`):**
    * 创建一个 `URLLoader` 实例。
    * 创建一个 `network::ResourceRequest` 对象，URL 为 "http://foo"。
    * `MockResourceRequestSender` 模拟网络层返回一个成功的响应。
* **输出:**
    * `TestURLLoaderClient::did_receive_response()` 返回 `true`。
    * `TestURLLoaderClient::did_finish()` 返回 `true`。
    * `TestURLLoaderClient::error()` 为空（没有错误）。
    * `MockResourceRequestSender::canceled()` 返回 `false` (请求没有被取消)。
    * `TestURLLoaderClient::did_receive_response_body()` 返回 `true`。

* **假设输入 (针对 `URLLoaderTest::Redirect`):**
    * 创建一个 `URLLoader` 实例。
    * 创建一个 `network::ResourceRequest` 对象，URL 为 "http://foo"。
    * `MockResourceRequestSender` 模拟网络层返回一个 302 重定向响应，然后返回最终资源的成功响应。
* **输出:**
    * `TestURLLoaderClient::did_receive_redirect()` 返回 `true`。
    * `TestURLLoaderClient::did_receive_response()` 返回 `true`。
    * `TestURLLoaderClient::did_finish()` 返回 `true`。
    * `TestURLLoaderClient::error()` 为空。
    * `MockResourceRequestSender::canceled()` 返回 `false`.
    * `TestURLLoaderClient::did_receive_response_body()` 返回 `true`.

* **假设输入 (针对 `URLLoaderTest::Failure`):**
    * 创建一个 `URLLoader` 实例。
    * 创建一个 `network::ResourceRequest` 对象，URL 为 "http://foo"。
    * `MockResourceRequestSender` 模拟网络层返回一个失败的响应。
* **输出:**
    * `TestURLLoaderClient::did_receive_response()` 返回 `true` (即使失败，也可能接收到响应头)。
    * `TestURLLoaderClient::did_finish()` 返回 `false`。
    * `TestURLLoaderClient::error()` 不为空，其 `reason()` 属性为 `net::ERR_FAILED`。
    * `MockResourceRequestSender::canceled()` 返回 `false`.

**涉及用户或者编程常见的使用错误:**

* **过早释放 `URLLoaderClient`:**  在 `URLLoader` 完成请求之前，如果持有 `URLLoaderClient` 的对象被销毁，可能会导致 use-after-free 错误。
    * **举例:** 一个 JavaScript Promise 绑定了一个资源加载操作，但 Promise 的生命周期管理不当，在请求完成前就被回收，可能导致相关的 C++ 对象被过早释放。测试用例 `DeleteOnReceiveRedirect`, `DeleteOnReceiveResponse`, `DeleteOnFinish`, `DeleteOnFail` 就是为了验证这种情况下的安全性。
* **没有正确处理网络错误:**  开发者在处理 `fetch()` 或 `XMLHttpRequest` 的响应时，没有检查请求是否成功，直接访问响应数据，可能会导致程序崩溃或行为异常。
    * **举例:**  JavaScript 代码没有 `catch` `fetch()` 返回的 Promise 的 rejection，当网络请求失败时，可能会抛出未捕获的异常。
* **同步请求的滥用:**  在主线程中使用同步请求会阻塞浏览器渲染，导致页面卡顿，用户体验差。
    * **举例:**  JavaScript 代码中使用 `XMLHttpRequest` 并将 `async` 设置为 `false`，会在请求返回前阻塞 JavaScript 的执行。
* **不正确的 CORS 配置:**  当 JavaScript 代码尝试从不同的域加载资源时，如果服务器没有正确配置 CORS 头，`URLLoader` 会阻止请求，导致资源加载失败。
    * **举例:**  一个网页部署在 `example.com`，JavaScript 代码尝试 `fetch('http://api.another-domain.com/data')`，但 `api.another-domain.com` 的服务器没有设置 `Access-Control-Allow-Origin` 头，请求会被阻止。
* **资源 URL 错误:**  请求一个不存在的资源或错误的 URL 会导致 404 错误，开发者需要在代码中处理这种情况。

总而言之，`url_loader_unittest.cc` 通过大量的单元测试用例，确保 `URLLoader` 作为一个核心的网络请求组件，在各种场景下都能稳定可靠地工作，这对于保证 Chromium 浏览器的功能正确性和用户体验至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/url_loader_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader.h"

#include <stdint.h>
#include <string.h>

#include <string_view>
#include <utility>
#include <vector>

#include "base/command_line.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/task_environment.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/cert/x509_util.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/test/cert_test_util.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/weak_wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/encoded_body_length.mojom-forward.h"
#include "services/network/public/mojom/encoded_body_length.mojom.h"
#include "services/network/public/mojom/fetch_api.mojom-shared.h"
#include "services/network/public/mojom/url_loader_completion_status.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_url_request_extra_data.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/renderer/platform/loader/fetch/loader_freeze_mode.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_sender.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/sync_load_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_client.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace blink {
namespace {

const char kTestURL[] = "http://foo";
const char kTestData[] = "blah!";

class MockResourceRequestSender : public ResourceRequestSender {
 public:
  MockResourceRequestSender() = default;
  MockResourceRequestSender(const MockResourceRequestSender&) = delete;
  MockResourceRequestSender& operator=(const MockResourceRequestSender&) =
      delete;
  ~MockResourceRequestSender() override = default;

  // ResourceRequestSender implementation:
  void SendSync(
      std::unique_ptr<network::ResourceRequest> request,
      const net::NetworkTrafficAnnotationTag& traffic_annotation,
      uint32_t loader_options,
      SyncLoadResponse* response,
      scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
      WebVector<std::unique_ptr<URLLoaderThrottle>> throttles,
      base::TimeDelta timeout,
      const Vector<String>& cors_exempt_header_list,
      base::WaitableEvent* terminate_sync_load_event,
      mojo::PendingRemote<mojom::blink::BlobRegistry> download_to_blob_registry,
      scoped_refptr<ResourceRequestClient> resource_request_client,
      std::unique_ptr<ResourceLoadInfoNotifierWrapper>
          resource_load_info_notifier_wrapper) override {
    *response = std::move(sync_load_response_);
  }

  int SendAsync(
      std::unique_ptr<network::ResourceRequest> request,
      scoped_refptr<base::SequencedTaskRunner> loading_task_runner,
      const net::NetworkTrafficAnnotationTag& traffic_annotation,
      uint32_t loader_options,
      const Vector<String>& cors_exempt_header_list,
      scoped_refptr<ResourceRequestClient> resource_request_client,
      scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
      WebVector<std::unique_ptr<URLLoaderThrottle>> throttles,
      std::unique_ptr<ResourceLoadInfoNotifierWrapper>
          resource_load_info_notifier_wrapper,
      CodeCacheHost* code_cache_host,
      base::OnceCallback<void(mojom::blink::RendererEvictionReason)>
          evict_from_bfcache_callback,
      base::RepeatingCallback<void(size_t)>
          did_buffer_load_while_in_bfcache_callback) override {
    EXPECT_FALSE(resource_request_client_);
    if (sync_load_response_.head->encoded_body_length) {
      EXPECT_TRUE(loader_options & network::mojom::kURLLoadOptionSynchronous);
    }
    resource_request_client_ = std::move(resource_request_client);
    return 1;
  }

  void Cancel(scoped_refptr<base::SequencedTaskRunner> task_runner) override {
    EXPECT_FALSE(canceled_);
    canceled_ = true;

    task_runner->ReleaseSoon(FROM_HERE, std::move(resource_request_client_));
  }

  ResourceRequestClient* resource_request_client() {
    return resource_request_client_.get();
  }

  bool canceled() { return canceled_; }

  void Freeze(LoaderFreezeMode mode) override { freeze_mode_ = mode; }
  LoaderFreezeMode freeze_mode() const { return freeze_mode_; }

  void set_sync_load_response(SyncLoadResponse&& sync_load_response) {
    sync_load_response_ = std::move(sync_load_response);
  }

 private:
  scoped_refptr<ResourceRequestClient> resource_request_client_;
  bool canceled_ = false;
  LoaderFreezeMode freeze_mode_ = LoaderFreezeMode::kNone;
  SyncLoadResponse sync_load_response_;
};

class FakeURLLoaderFactory final : public network::mojom::URLLoaderFactory {
 public:
  FakeURLLoaderFactory() = default;
  FakeURLLoaderFactory(const FakeURLLoaderFactory&) = delete;
  FakeURLLoaderFactory& operator=(const FakeURLLoaderFactory&) = delete;
  ~FakeURLLoaderFactory() override = default;
  void CreateLoaderAndStart(
      mojo::PendingReceiver<network::mojom::URLLoader> receiver,
      int32_t request_id,
      uint32_t options,
      const network::ResourceRequest& url_request,
      mojo::PendingRemote<network::mojom::URLLoaderClient> client,
      const net::MutableNetworkTrafficAnnotationTag& traffic_annotation)
      override {
    NOTREACHED();
  }

  void Clone(mojo::PendingReceiver<network::mojom::URLLoaderFactory> receiver)
      override {
    NOTREACHED();
  }
};

class TestURLLoaderClient : public URLLoaderClient {
 public:
  TestURLLoaderClient()
      : loader_(new URLLoader(
            /*cors_exempt_header_list=*/Vector<String>(),
            /*terminate_sync_load_event=*/nullptr,
            scheduler::GetSingleThreadTaskRunnerForTesting(),
            scheduler::GetSingleThreadTaskRunnerForTesting(),
            base::MakeRefCounted<network::WeakWrapperSharedURLLoaderFactory>(
                &fake_url_loader_factory_),
            /*keep_alive_handle=*/mojo::NullRemote(),
            /*back_forward_cache_loader_helper=*/nullptr,
            /*throttles=*/{})),
        delete_on_receive_redirect_(false),
        delete_on_receive_response_(false),
        delete_on_receive_data_(false),
        delete_on_finish_(false),
        delete_on_fail_(false),
        did_receive_redirect_(false),
        did_receive_response_(false),
        did_finish_(false) {}

  TestURLLoaderClient(const TestURLLoaderClient&) = delete;
  TestURLLoaderClient& operator=(const TestURLLoaderClient&) = delete;

  ~TestURLLoaderClient() override {
    // During the deconstruction of the `loader_`, the request context will be
    // released asynchronously and we must ensure that the request context has
    // been deleted practically before the test quits, thus, memory leak will
    // not be reported on the ASAN build. So, we call 'reset()' to trigger the
    // deconstruction, and then execute `RunUntilIdle()` to empty the task queue
    // to achieve that.
    if (loader_) {
      loader_.reset();
    }
    base::RunLoop().RunUntilIdle();
  }

  // URLLoaderClient implementation:
  bool WillFollowRedirect(const WebURL& new_url,
                          const net::SiteForCookies& new_site_for_cookies,
                          const WebString& new_referrer,
                          network::mojom::ReferrerPolicy new_referrer_policy,
                          const WebString& new_method,
                          const WebURLResponse& passed_redirect_response,
                          bool& report_raw_headers,
                          std::vector<std::string>*,
                          net::HttpRequestHeaders&,
                          bool insecure_scheme_was_upgraded) override {
    EXPECT_TRUE(loader_);

    // No test currently simulates mutiple redirects.
    EXPECT_FALSE(did_receive_redirect_);
    did_receive_redirect_ = true;

    if (delete_on_receive_redirect_) {
      loader_.reset();
    }

    return true;
  }

  void DidSendData(uint64_t bytesSent, uint64_t totalBytesToBeSent) override {
    EXPECT_TRUE(loader_);
  }

  void DidReceiveResponse(
      const WebURLResponse& response,
      absl::variant<mojo::ScopedDataPipeConsumerHandle, SegmentedBuffer> body,
      std::optional<mojo_base::BigBuffer> cached_metadata) override {
    EXPECT_TRUE(loader_);
    EXPECT_FALSE(did_receive_response_);

    did_receive_response_ = true;
    response_ = response;
    if (delete_on_receive_response_) {
      loader_.reset();
      return;
    }
    DCHECK(!response_body_);
    // SegmentedBuffer is used only for BackgroundUrlLoader.
    CHECK(absl::holds_alternative<mojo::ScopedDataPipeConsumerHandle>(body));
    mojo::ScopedDataPipeConsumerHandle body_handle =
        std::move(absl::get<mojo::ScopedDataPipeConsumerHandle>(body));
    if (body_handle) {
      response_body_ = std::move(body_handle);
    }
  }

  void DidFinishLoading(base::TimeTicks finishTime,
                        int64_t totalEncodedDataLength,
                        uint64_t totalEncodedBodyLength,
                        int64_t totalDecodedBodyLength) override {
    EXPECT_TRUE(loader_);
    EXPECT_TRUE(did_receive_response_);
    EXPECT_FALSE(did_finish_);
    did_finish_ = true;

    if (delete_on_finish_) {
      loader_.reset();
    }
  }

  void DidFail(const WebURLError& error,
               base::TimeTicks finishTime,
               int64_t totalEncodedDataLength,
               uint64_t totalEncodedBodyLength,
               int64_t totalDecodedBodyLength) override {
    EXPECT_TRUE(loader_);
    EXPECT_FALSE(did_finish_);
    error_ = error;

    if (delete_on_fail_) {
      loader_.reset();
    }
  }

  URLLoader* loader() { return loader_.get(); }
  void DeleteLoader() { loader_.reset(); }

  void set_delete_on_receive_redirect() { delete_on_receive_redirect_ = true; }
  void set_delete_on_receive_response() { delete_on_receive_response_ = true; }
  void set_delete_on_receive_data() { delete_on_receive_data_ = true; }
  void set_delete_on_finish() { delete_on_finish_ = true; }
  void set_delete_on_fail() { delete_on_fail_ = true; }

  bool did_receive_redirect() const { return did_receive_redirect_; }
  bool did_receive_response() const { return did_receive_response_; }
  bool did_receive_response_body() const { return !!response_body_; }
  bool did_finish() const { return did_finish_; }
  const std::optional<WebURLError>& error() const { return error_; }
  const WebURLResponse& response() const { return response_; }

 private:
  FakeURLLoaderFactory fake_url_loader_factory_;
  std::unique_ptr<URLLoader> loader_;

  bool delete_on_receive_redirect_;
  bool delete_on_receive_response_;
  bool delete_on_receive_data_;
  bool delete_on_finish_;
  bool delete_on_fail_;

  bool did_receive_redirect_;
  bool did_receive_response_;
  mojo::ScopedDataPipeConsumerHandle response_body_;
  bool did_finish_;
  std::optional<WebURLError> error_;
  WebURLResponse response_;
};

class URLLoaderTest : public testing::Test {
 public:
  URLLoaderTest() : client_(std::make_unique<TestURLLoaderClient>()) {
    auto sender = std::make_unique<MockResourceRequestSender>();
    sender_ = sender.get();
    client_->loader()->SetResourceRequestSenderForTesting(std::move(sender));
  }

  ~URLLoaderTest() override = default;

  void DoStartAsyncRequest() {
    auto request = std::make_unique<network::ResourceRequest>();
    request->url = GURL(kTestURL);
    request->destination = network::mojom::RequestDestination::kEmpty;
    request->priority = net::IDLE;
    client()->loader()->LoadAsynchronously(
        std::move(request), /*url_request_extra_data=*/nullptr,
        /*no_mime_sniffing=*/false,
        std::make_unique<ResourceLoadInfoNotifierWrapper>(
            /*resource_load_info_notifier=*/nullptr),
        /*code_cache_host=*/nullptr, client());
    ASSERT_TRUE(resource_request_client());
  }

  void DoReceiveRedirect() {
    EXPECT_FALSE(client()->did_receive_redirect());
    net::RedirectInfo redirect_info;
    redirect_info.status_code = 302;
    redirect_info.new_method = "GET";
    redirect_info.new_url = GURL(kTestURL);
    redirect_info.new_site_for_cookies =
        net::SiteForCookies::FromUrl(GURL(kTestURL));
    std::vector<std::string> removed_headers;
    bool callback_called = false;
    resource_request_client()->OnReceivedRedirect(
        redirect_info, network::mojom::URLResponseHead::New(),
        /*follow_redirect_callback=*/
        WTF::BindOnce(
            [](bool* callback_called, std::vector<std::string> removed_headers,
               net::HttpRequestHeaders modified_headers) {
              *callback_called = true;
            },
            WTF::Unretained(&callback_called)));
    DCHECK(callback_called);
    EXPECT_TRUE(client()->did_receive_redirect());
  }

  void DoReceiveResponse() {
    EXPECT_FALSE(client()->did_receive_response());

    mojo::ScopedDataPipeConsumerHandle handle_to_pass;
    MojoResult rv = mojo::CreateDataPipe(nullptr, body_handle_, handle_to_pass);
    ASSERT_EQ(MOJO_RESULT_OK, rv);

    resource_request_client()->OnReceivedResponse(
        network::mojom::URLResponseHead::New(), std::move(handle_to_pass),
        /*cached_metadata=*/std::nullopt);
    EXPECT_TRUE(client()->did_receive_response());
  }

  void DoCompleteRequest() {
    EXPECT_FALSE(client()->did_finish());
    DCHECK(body_handle_);
    body_handle_.reset();
    base::RunLoop().RunUntilIdle();
    network::URLLoaderCompletionStatus status(net::OK);
    status.encoded_data_length = std::size(kTestData);
    status.encoded_body_length = std::size(kTestData);
    status.decoded_body_length = std::size(kTestData);
    resource_request_client()->OnCompletedRequest(status);
    EXPECT_TRUE(client()->did_finish());
    // There should be no error.
    EXPECT_FALSE(client()->error());
  }

  void DoFailRequest() {
    EXPECT_FALSE(client()->did_finish());
    DCHECK(body_handle_);
    body_handle_.reset();
    base::RunLoop().RunUntilIdle();
    network::URLLoaderCompletionStatus status(net::ERR_FAILED);
    status.encoded_data_length = std::size(kTestData);
    status.encoded_body_length = std::size(kTestData);
    status.decoded_body_length = std::size(kTestData);
    resource_request_client()->OnCompletedRequest(status);
    EXPECT_FALSE(client()->did_finish());
    ASSERT_TRUE(client()->error());
    EXPECT_EQ(net::ERR_FAILED, client()->error()->reason());
  }

  TestURLLoaderClient* client() { return client_.get(); }
  MockResourceRequestSender* sender() { return sender_; }
  ResourceRequestClient* resource_request_client() {
    return sender_->resource_request_client();
  }

 private:
  base::test::SingleThreadTaskEnvironment task_environment_;
  mojo::ScopedDataPipeProducerHandle body_handle_;
  std::unique_ptr<TestURLLoaderClient> client_;
  raw_ptr<MockResourceRequestSender> sender_ = nullptr;
};

TEST_F(URLLoaderTest, Success) {
  DoStartAsyncRequest();
  DoReceiveResponse();
  DoCompleteRequest();
  EXPECT_FALSE(sender()->canceled());
  EXPECT_TRUE(client()->did_receive_response_body());
}

TEST_F(URLLoaderTest, Redirect) {
  DoStartAsyncRequest();
  DoReceiveRedirect();
  DoReceiveResponse();
  DoCompleteRequest();
  EXPECT_FALSE(sender()->canceled());
  EXPECT_TRUE(client()->did_receive_response_body());
}

TEST_F(URLLoaderTest, Failure) {
  DoStartAsyncRequest();
  DoReceiveResponse();
  DoFailRequest();
  EXPECT_FALSE(sender()->canceled());
}

// The client may delete the URLLoader during any callback from the loader.
// These tests make sure that doesn't result in a crash.
TEST_F(URLLoaderTest, DeleteOnReceiveRedirect) {
  client()->set_delete_on_receive_redirect();
  DoStartAsyncRequest();
  DoReceiveRedirect();
}

TEST_F(URLLoaderTest, DeleteOnReceiveResponse) {
  client()->set_delete_on_receive_response();
  DoStartAsyncRequest();
  DoReceiveResponse();
}

TEST_F(URLLoaderTest, DeleteOnFinish) {
  client()->set_delete_on_finish();
  DoStartAsyncRequest();
  DoReceiveResponse();
  DoCompleteRequest();
}

TEST_F(URLLoaderTest, DeleteOnFail) {
  client()->set_delete_on_fail();
  DoStartAsyncRequest();
  DoReceiveResponse();
  DoFailRequest();
}

TEST_F(URLLoaderTest, DefersLoadingBeforeStart) {
  client()->loader()->Freeze(LoaderFreezeMode::kStrict);
  EXPECT_EQ(sender()->freeze_mode(), LoaderFreezeMode::kNone);
  DoStartAsyncRequest();
  EXPECT_EQ(sender()->freeze_mode(), LoaderFreezeMode::kStrict);
}

TEST_F(URLLoaderTest, ResponseIPEndpoint) {
  KURL url("http://example.test/");

  struct TestCase {
    const char* ip;
    uint16_t port;
  } cases[] = {
      {"127.0.0.1", 443},
      {"123.123.123.123", 80},
      {"::1", 22},
      {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", 1337},
      {"2001:db8:85a3:0:0:8a2e:370:7334", 12345},
      {"2001:db8:85a3::8a2e:370:7334", 8080},
      {"::ffff:192.0.2.128", 8443},
  };

  for (const auto& test : cases) {
    SCOPED_TRACE(test.ip);

    net::IPAddress address;
    ASSERT_TRUE(address.AssignFromIPLiteral(test.ip));

    network::mojom::URLResponseHead head;
    head.remote_endpoint = net::IPEndPoint(address, test.port);

    WebURLResponse response = WebURLResponse::Create(url, head, true, -1);
    EXPECT_EQ(head.remote_endpoint, response.RemoteIPEndpoint());
  };
}

TEST_F(URLLoaderTest, ResponseAddressSpace) {
  KURL url("http://foo.example");

  network::mojom::URLResponseHead head;
  head.response_address_space = network::mojom::IPAddressSpace::kPrivate;

  WebURLResponse response = WebURLResponse::Create(url, head, true, -1);

  EXPECT_EQ(network::mojom::IPAddressSpace::kPrivate, response.AddressSpace());
}

TEST_F(URLLoaderTest, ClientAddressSpace) {
  KURL url("http://foo.example");

  network::mojom::URLResponseHead head;
  head.client_address_space = network::mojom::IPAddressSpace::kPublic;

  WebURLResponse response = WebURLResponse::Create(url, head, true, -1);

  EXPECT_EQ(network::mojom::IPAddressSpace::kPublic,
            response.ClientAddressSpace());
}

TEST_F(URLLoaderTest, SSLInfo) {
  KURL url("https://test.example/");

  net::CertificateList certs;
  ASSERT_TRUE(net::LoadCertificateFiles(
      {"subjectAltName_sanity_check.pem", "root_ca_cert.pem"}, &certs));
  ASSERT_EQ(2U, certs.size());

  std::string_view cert0_der =
      net::x509_util::CryptoBufferAsStringPiece(certs[0]->cert_buffer());
  std::string_view cert1_der =
      net::x509_util::CryptoBufferAsStringPiece(certs[1]->cert_buffer());

  net::SSLInfo ssl_info;
  ssl_info.cert =
      net::X509Certificate::CreateFromDERCertChain({cert0_der, cert1_der});
  net::SSLConnectionStatusSetVersion(net::SSL_CONNECTION_VERSION_TLS1_2,
                                     &ssl_info.connection_status);

  network::mojom::URLResponseHead head;
  head.ssl_info = ssl_info;
  WebURLResponse web_url_response = WebURLResponse::Create(url, head, true, -1);

  const std::optional<net::SSLInfo>& got_ssl_info =
      web_url_response.ToResourceResponse().GetSSLInfo();
  ASSERT_TRUE(got_ssl_info.has_value());
  EXPECT_EQ(ssl_info.connection_status, got_ssl_info->connection_status);
  EXPECT_TRUE(ssl_info.cert->EqualsIncludingChain(got_ssl_info->cert.get()));
}

// Verifies that the lengths used by the PerformanceResourceTiming API are
// correctly assigned for sync XHR.
TEST_F(URLLoaderTest, SyncLengths) {
  static const char kBodyData[] = "Today is Thursday";
  const uint64_t kEncodedBodyLength = 30;
  const int kEncodedDataLength = 130;
  const KURL url(kTestURL);

  auto request = std::make_unique<network::ResourceRequest>();
  request->url = GURL(url);
  request->destination = network::mojom::RequestDestination::kEmpty;
  request->priority = net::HIGHEST;

  // Prepare a mock response
  SyncLoadResponse sync_load_response;
  sync_load_response.error_code = net::OK;
  sync_load_response.url = GURL(url);
  sync_load_response.data =
      SharedBuffer::Create(kBodyData, sizeof(kBodyData) - 1);
  ASSERT_EQ(17u, sync_load_response.data->size());
  sync_load_response.head->encoded_body_length =
      network::mojom::EncodedBodyLength::New(kEncodedBodyLength);
  sync_load_response.head->encoded_data_length = kEncodedDataLength;
  sender()->set_sync_load_response(std::move(sync_load_response));

  WebURLResponse response;
  std::optional<WebURLError> error;
  scoped_refptr<SharedBuffer> data;
  int64_t encoded_data_length = 0;
  uint64_t encoded_body_length = 0;
  scoped_refptr<BlobDataHandle> downloaded_blob;

  client()->loader()->LoadSynchronously(
      std::move(request), /*top_frame_origin=*/nullptr,
      /*download_to_blob=*/false,
      /*no_mime_sniffing=*/false, base::TimeDelta(), nullptr, response, error,
      data, encoded_data_length, encoded_body_length, downloaded_blob,
      std::make_unique<ResourceLoadInfoNotifierWrapper>(
          /*resource_load_info_notifier=*/nullptr));

  EXPECT_EQ(kEncodedBodyLength, encoded_body_length);
  EXPECT_EQ(kEncodedDataLength, encoded_data_length);
}

// Verifies that WebURLResponse::Create() copies AuthChallengeInfo to the
// response.
TEST_F(URLLoaderTest, AuthChallengeInfo) {
  network::mojom::URLResponseHead head;
  net::AuthChallengeInfo auth_challenge_info;
  auth_challenge_info.is_proxy = true;
  auth_challenge_info.challenge = "foobar";
  head.auth_challenge_info = auth_challenge_info;

  blink::WebURLResponse response =
      WebURLResponse::Create(KURL(), head, true, -1);
  ASSERT_TRUE(response.AuthChallengeInfo().has_value());
  EXPECT_TRUE(response.AuthChallengeInfo()->is_proxy);
  EXPECT_EQ("foobar", response.AuthChallengeInfo()->challenge);
}

}  // namespace
}  // namespace blink

"""

```