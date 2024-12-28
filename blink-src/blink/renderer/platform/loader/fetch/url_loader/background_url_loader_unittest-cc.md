Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's Blink engine. The file is `background_url_loader_unittest.cc`. It is a unit test file, so its primary function is to test the `BackgroundURLLoader` class.

Here's a breakdown of the requested information:

1. **Functionality:**  Describe what the code does.
2. **Relation to Web Technologies:** Explain if and how it relates to JavaScript, HTML, and CSS.
3. **Logical Reasoning (with examples):**  If the tests involve logical steps, provide example inputs and expected outputs.
4. **Common Usage Errors:**  Identify potential mistakes users or developers might make.
5. **Summary:**  Concisely summarize the file's purpose.

Let's go through the code and address each point.
这是 `blink/renderer/platform/loader/fetch/url_loader/background_url_loader_unittest.cc` 文件的第 1 部分，主要功能是**测试 `BackgroundURLLoader` 类的功能**。

`BackgroundURLLoader` 是 Blink 渲染引擎中用于在后台执行 URL 加载的类。这个单元测试文件通过模拟各种场景来验证 `BackgroundURLLoader` 的行为是否符合预期。

**与 JavaScript, HTML, CSS 的关系：**

`BackgroundURLLoader`  直接与浏览器加载网络资源的过程相关，而这些资源通常包括 JavaScript、HTML 和 CSS 文件。

* **JavaScript:** 当网页中的 JavaScript 代码发起网络请求（例如使用 `fetch` API 或 `XMLHttpRequest`），Blink 引擎可能会使用 `BackgroundURLLoader` 来在后台下载 JavaScript 文件。这个测试文件会验证 `BackgroundURLLoader` 能否正确处理对 JavaScript 资源的请求，包括处理重定向、错误以及接收响应数据。
* **HTML:**  浏览器加载 HTML 页面时，同样会使用 URL 加载器来获取 HTML 内容。`BackgroundURLLoader` 可以用于预加载或后台更新 HTML 内容。测试中模拟的简单的 "text/html" 响应就与 HTML 加载相关。
* **CSS:**  与 JavaScript 类似，当浏览器解析 HTML 遇到 `<link>` 标签引用 CSS 文件时，`BackgroundURLLoader` 可以用于下载 CSS 文件。测试中对于资源请求和响应的处理逻辑也适用于 CSS 文件的加载。

**举例说明:**

假设一个网页使用 JavaScript 的 `fetch` API 在后台请求一个名为 `data.json` 的 JSON 文件：

```javascript
fetch('data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个场景下，Blink 引擎可能会使用 `BackgroundURLLoader` 来处理对 `data.json` 的请求。`background_url_loader_unittest.cc` 中的测试会模拟以下情况：

* **假设输入：**
    *  一个指向 `data.json` 的 URL 请求。
    *  一个模拟的网络响应，包含 JSON 数据。
* **预期输出：**
    *  `BackgroundURLLoader` 成功接收到响应数据。
    *  如果发生重定向，`BackgroundURLLoader` 能正确处理。
    *  如果请求失败，`BackgroundURLLoader` 能通知客户端请求失败。

测试代码中，`CreateTestRequest()` 创建了一个简单的请求，`CreateTestResponse()` 创建了一个模拟的响应头，`CreateTestBody()` 创建了模拟的响应体。这些可以看作是对上述 `data.json` 请求和响应的简化模拟。

**逻辑推理 (假设输入与输出):**

* **测试重定向场景：**
    * **假设输入：** 一个请求到一个会返回 HTTP 重定向状态码（如 302）的 URL。
    * **预期输出：** `BackgroundURLLoader` 能够识别重定向，并且如果客户端允许，会发起对新 URL 的请求。测试代码中的 `TEST_F(BackgroundResourceFecherTest, Redirect)` 就是在测试这个场景，它模拟了服务器返回重定向响应，并验证 `BackgroundURLLoader` 是否调用了 `FollowRedirect`。

* **测试请求失败场景：**
    * **假设输入：** 一个请求到一个不存在的 URL 或者网络连接断开。
    * **预期输出：** `BackgroundURLLoader` 会通知客户端请求失败，并提供相应的错误信息。测试代码中的 `TEST_F(BackgroundResourceFecherTest, FailedRequest)`  模拟了接收到 `net::ERR_FAILED` 错误码，并验证客户端是否收到了错误通知。

**涉及用户或者编程常见的使用错误：**

虽然这个文件是单元测试，主要面向开发者，但它覆盖的场景可以帮助理解 `BackgroundURLLoader` 的行为，从而避免一些使用错误。

* **错误地假设后台加载总是成功：**  开发者需要处理网络请求失败的情况。测试中的 `FailedRequest` 可以提醒开发者需要有相应的错误处理机制。
* **没有正确处理重定向：**  有些后台加载的场景可能需要开发者显式地处理重定向。测试中的 `Redirect` 和 `RedirectDoNotFollow`  可以帮助开发者理解 `BackgroundURLLoader` 的重定向处理流程，以及如何控制是否跟随重定向。
* **在请求过程中过早释放资源：** 测试中的 `CancelSoonAfterStart` 和 `CancelAfterStart`  模拟了在请求的不同阶段取消请求的情况，这可以帮助开发者理解在后台加载过程中管理资源生命周期的重要性，避免出现悬空指针等问题。

**功能归纳 (第 1 部分):**

这部分 `background_url_loader_unittest.cc` 文件的主要功能是：

1. **测试 `BackgroundURLLoader` 的基本请求-响应流程：** 验证 `BackgroundURLLoader` 能否正确发起请求，接收响应头、响应体和缓存元数据，并通知客户端。
2. **测试 `BackgroundURLLoader` 对网络错误的处理：** 验证 `BackgroundURLLoader` 能否正确地将网络错误传递给客户端。
3. **测试 `BackgroundURLLoader` 对 HTTP 重定向的处理：** 验证 `BackgroundURLLoader` 能否识别并处理重定向，并允许客户端决定是否跟随重定向。
4. **测试在请求生命周期内取消 `BackgroundURLLoader` 的行为：** 验证在请求的不同阶段取消请求是否会导致崩溃或其他非预期行为，并确保资源得到正确清理。
5. **为 `BackgroundURLLoader` 的开发和维护提供保障：** 通过自动化测试确保代码的正确性和稳定性，防止引入 bug。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/background_url_loader_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/background_url_loader.h"

#include "base/check.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/notreached.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/threading/thread_restrictions.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "net/base/net_errors.h"
#include "net/http/http_response_headers.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/navigation/renderer_eviction_reason.mojom-blink.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/web_background_resource_fetch_assets.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/platform/back_forward_cache_buffer_limit_tracker.h"
#include "third_party/blink/renderer/platform/loader/fetch/back_forward_cache_loader_helper.h"
#include "third_party/blink/renderer/platform/loader/fetch/background_code_cache_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/background_response_processor.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_client.h"
#include "third_party/blink/renderer/platform/loader/testing/fake_background_resource_fetch_assets.h"
#include "third_party/blink/renderer/platform/loader/testing/fake_url_loader_factory_for_background_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "url/gurl.h"

namespace WTF {

template <>
struct CrossThreadCopier<network::mojom::URLResponseHeadPtr> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = network::mojom::URLResponseHeadPtr;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<std::optional<mojo_base::BigBuffer>> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = std::optional<mojo_base::BigBuffer>;
  static Type Copy(Type&& value) { return std::move(value); }
};

}  // namespace WTF

namespace blink {
namespace {

constexpr char kTestURL[] = "http://example.com/";
constexpr char kRedirectedURL[] = "http://example.com/redirected";
constexpr int kMaxBufferedBytesPerProcess = 1000;
constexpr std::string kTestBodyString = "test data.";

using MaybeStartFunction =
    CrossThreadOnceFunction<bool(network::mojom::URLResponseHeadPtr&,
                                 mojo::ScopedDataPipeConsumerHandle&,
                                 std::optional<mojo_base::BigBuffer>&,
                                 scoped_refptr<base::SingleThreadTaskRunner>,
                                 scoped_refptr<base::SequencedTaskRunner>,
                                 BackgroundResponseProcessor::Client*)>;

class BackgroundResponseProcessorTestUtil
    : public WTF::ThreadSafeRefCounted<BackgroundResponseProcessorTestUtil> {
 public:
  BackgroundResponseProcessorTestUtil() = default;

  BackgroundResponseProcessorTestUtil(
      const BackgroundResponseProcessorTestUtil&) = delete;
  BackgroundResponseProcessorTestUtil& operator=(
      const BackgroundResponseProcessorTestUtil&) = delete;

  void SetSyncReturnFalse() {
    result_of_maybe_start_processing_response_ = false;
  }
  void SetExpectNotReached() {
    expect_maybe_start_processing_response_not_called_ = true;
  }

  std::unique_ptr<BackgroundResponseProcessorFactory> CreateProcessorFactory() {
    return std::make_unique<DummyProcessorFactory>(this);
  }
  bool MaybeStartProcessingResponse(
      network::mojom::URLResponseHeadPtr& head,
      mojo::ScopedDataPipeConsumerHandle& body,
      std::optional<mojo_base::BigBuffer>& cached_metadata_buffer,
      scoped_refptr<base::SequencedTaskRunner> background_task_runner,
      BackgroundResponseProcessor::Client* client) {
    CHECK(!expect_maybe_start_processing_response_not_called_);
    response_received_ = true;
    if (result_of_maybe_start_processing_response_) {
      head_ = std::move(head);
      body_ = std::move(body);
      cached_metadata_buffer_ = std::move(cached_metadata_buffer);
      background_task_runner_ = std::move(background_task_runner);
      client_ = std::move(client);
    }
    run_loop_.Quit();
    return result_of_maybe_start_processing_response_;
  }
  void OnProcessorDeleted() {
    client_ = nullptr;
    if (background_task_runner_) {
      CHECK(background_task_runner_->RunsTasksInCurrentSequence());
    }
    processor_deleted_ = true;
  }

  void WaitUntilMaybeStartProcessingResponse() { run_loop_.Run(); }

  bool response_received() const { return response_received_; }
  network::mojom::URLResponseHeadPtr& head() { return head_; }
  mojo::ScopedDataPipeConsumerHandle& body() { return body_; }
  std::optional<mojo_base::BigBuffer>& cached_metadata_buffer() {
    return cached_metadata_buffer_;
  }
  scoped_refptr<base::SequencedTaskRunner>& background_task_runner() {
    return background_task_runner_;
  }
  BackgroundResponseProcessor::Client* client() { return client_; }
  bool processor_deleted() const { return processor_deleted_; }

 private:
  class DummyProcessor final : public BackgroundResponseProcessor {
   public:
    explicit DummyProcessor(
        scoped_refptr<BackgroundResponseProcessorTestUtil> test_util)
        : test_util_(std::move(test_util)) {}

    DummyProcessor(const DummyProcessor&) = delete;
    DummyProcessor& operator=(const DummyProcessor&) = delete;
    ~DummyProcessor() override { test_util_->OnProcessorDeleted(); }

    bool MaybeStartProcessingResponse(
        network::mojom::URLResponseHeadPtr& head,
        mojo::ScopedDataPipeConsumerHandle& body,
        std::optional<mojo_base::BigBuffer>& cached_metadata_buffer,
        scoped_refptr<base::SequencedTaskRunner> background_task_runner,
        Client* client) override {
      return test_util_->MaybeStartProcessingResponse(
          head, body, cached_metadata_buffer, background_task_runner, client);
    }

   private:
    scoped_refptr<BackgroundResponseProcessorTestUtil> test_util_;
  };

  class DummyProcessorFactory final
      : public BackgroundResponseProcessorFactory {
   public:
    explicit DummyProcessorFactory(
        scoped_refptr<BackgroundResponseProcessorTestUtil> test_util)
        : test_util_(std::move(test_util)) {}

    DummyProcessorFactory(const DummyProcessorFactory&) = delete;
    DummyProcessorFactory& operator=(const DummyProcessorFactory&) = delete;
    ~DummyProcessorFactory() override = default;

    std::unique_ptr<BackgroundResponseProcessor> Create() && override {
      return std::make_unique<DummyProcessor>(std::move(test_util_));
    }
    scoped_refptr<BackgroundResponseProcessorTestUtil> test_util_;
  };

  friend class WTF::ThreadSafeRefCounted<BackgroundResponseProcessorTestUtil>;
  ~BackgroundResponseProcessorTestUtil() = default;

  bool result_of_maybe_start_processing_response_ = true;
  bool expect_maybe_start_processing_response_not_called_ = false;

  network::mojom::URLResponseHeadPtr head_;
  mojo::ScopedDataPipeConsumerHandle body_;
  std::optional<mojo_base::BigBuffer> cached_metadata_buffer_;
  scoped_refptr<base::SequencedTaskRunner> background_task_runner_;
  raw_ptr<BackgroundResponseProcessor::Client> client_;
  bool response_received_ = false;
  bool processor_deleted_ = false;

  base::RunLoop run_loop_;
};

mojo::ScopedDataPipeConsumerHandle CreateDataPipeConsumerHandleFilledWithString(
    const std::string& string) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  CHECK_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
           MOJO_RESULT_OK);
  CHECK(mojo::BlockingCopyFromString(string, producer_handle));
  return consumer_handle;
}

mojo::ScopedDataPipeConsumerHandle CreateTestBody() {
  return CreateDataPipeConsumerHandleFilledWithString(kTestBodyString);
}

SegmentedBuffer CreateTestBodyRawData() {
  SegmentedBuffer result;
  result.Append(kTestBodyString);
  return result;
}

mojo_base::BigBuffer CreateTestCachedMetaData() {
  return mojo_base::BigBuffer(std::vector<uint8_t>({1, 2, 3, 4, 5}));
}

std::unique_ptr<network::ResourceRequest> CreateTestRequest() {
  auto request = std::make_unique<network::ResourceRequest>();
  request->url = GURL(kTestURL);
  return request;
}

network::mojom::URLResponseHeadPtr CreateTestResponse() {
  auto response = network::mojom::URLResponseHead::New();
  response->headers =
      base::MakeRefCounted<net::HttpResponseHeaders>("HTTP/1.1 200 OK");
  response->mime_type = "text/html";
  return response;
}

class FakeBackForwardCacheLoaderHelper final
    : public BackForwardCacheLoaderHelper {
 public:
  FakeBackForwardCacheLoaderHelper() = default;
  ~FakeBackForwardCacheLoaderHelper() = default;

  void EvictFromBackForwardCache(
      mojom::blink::RendererEvictionReason reason) override {
    evicted_reason_ = reason;
  }
  void DidBufferLoadWhileInBackForwardCache(bool update_process_wide_count,
                                            size_t num_bytes) override {
    if (update_process_wide_count) {
      process_wide_count_updated_ = true;
      BackForwardCacheBufferLimitTracker::Get().DidBufferBytes(num_bytes);
    }
    total_bytes_buffered_ += num_bytes;
  }
  void Detach() override {}
  void Trace(Visitor* visitor) const override {
    BackForwardCacheLoaderHelper::Trace(visitor);
  }

  const std::optional<mojom::blink::RendererEvictionReason>& evicted_reason()
      const {
    return evicted_reason_;
  }
  size_t total_bytes_buffered() const { return total_bytes_buffered_; }
  bool process_wide_count_updated() const {
    return process_wide_count_updated_;
  }

 private:
  std::optional<mojom::blink::RendererEvictionReason> evicted_reason_;
  size_t total_bytes_buffered_ = 0;
  bool process_wide_count_updated_ = false;
};

class FakeURLLoaderClient : public URLLoaderClient {
 public:
  explicit FakeURLLoaderClient(
      scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner)
      : unfreezable_task_runner_(std::move(unfreezable_task_runner)) {}

  FakeURLLoaderClient(const FakeURLLoaderClient&) = delete;
  FakeURLLoaderClient& operator=(const FakeURLLoaderClient&) = delete;

  ~FakeURLLoaderClient() override = default;

  using WillFollowRedirectCallback =
      base::OnceCallback<bool(const WebURL& new_url)>;
  void AddWillFollowRedirectCallback(
      WillFollowRedirectCallback will_follow_callback) {
    will_follow_callbacks_.push_back(std::move(will_follow_callback));
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
    DCHECK(unfreezable_task_runner_->BelongsToCurrentThread());
    DCHECK(!will_follow_callbacks_.empty());
    WillFollowRedirectCallback will_follow_callback =
        std::move(will_follow_callbacks_.front());
    will_follow_callbacks_.pop_front();
    return std::move(will_follow_callback).Run(new_url);
  }
  void DidSendData(uint64_t bytesSent, uint64_t totalBytesToBeSent) override {
    NOTREACHED();
  }
  void DidReceiveResponse(
      const WebURLResponse& response,
      absl::variant<mojo::ScopedDataPipeConsumerHandle, SegmentedBuffer> body,
      std::optional<mojo_base::BigBuffer> cached_metadata) override {
    DCHECK(unfreezable_task_runner_->BelongsToCurrentThread());
    DCHECK(!response_);
    DCHECK(!response_body_handle_);
    CHECK(response_body_buffer_.empty());
    response_ = response;
    cached_metadata_ = std::move(cached_metadata);
    if (absl::holds_alternative<mojo::ScopedDataPipeConsumerHandle>(body)) {
      response_body_handle_ =
          std::move(absl::get<mojo::ScopedDataPipeConsumerHandle>(body));
    } else {
      response_body_buffer_ = std::move(absl::get<SegmentedBuffer>(body));
    }
  }
  void DidReceiveTransferSizeUpdate(int transfer_size_diff) override {
    DCHECK(unfreezable_task_runner_->BelongsToCurrentThread());
    transfer_size_diffs_.push_back(transfer_size_diff);
  }
  void DidFinishLoading(base::TimeTicks finishTime,
                        int64_t totalEncodedDataLength,
                        uint64_t totalEncodedBodyLength,
                        int64_t totalDecodedBodyLength) override {
    DCHECK(unfreezable_task_runner_->BelongsToCurrentThread());
    did_finish_ = true;
  }
  void DidFail(const WebURLError& error,
               base::TimeTicks finishTime,
               int64_t totalEncodedDataLength,
               uint64_t totalEncodedBodyLength,
               int64_t totalDecodedBodyLength) override {
    DCHECK(unfreezable_task_runner_->BelongsToCurrentThread());
    EXPECT_FALSE(did_finish_);
    error_ = error;
  }

  const std::optional<WebURLResponse>& response() const { return response_; }
  const std::optional<mojo_base::BigBuffer>& cached_metadata() const {
    return cached_metadata_;
  }
  const mojo::ScopedDataPipeConsumerHandle& response_body_handle() const {
    return response_body_handle_;
  }
  const SegmentedBuffer& response_body_buffer() const {
    return response_body_buffer_;
  }
  const std::vector<int>& transfer_size_diffs() const {
    return transfer_size_diffs_;
  }
  bool did_finish() const { return did_finish_; }
  const std::optional<WebURLError>& error() const { return error_; }

 private:
  scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner_;

  std::deque<WillFollowRedirectCallback> will_follow_callbacks_;

  std::optional<WebURLResponse> response_;
  std::optional<mojo_base::BigBuffer> cached_metadata_;
  mojo::ScopedDataPipeConsumerHandle response_body_handle_;
  SegmentedBuffer response_body_buffer_;
  std::vector<int> transfer_size_diffs_;
  bool did_finish_ = false;
  std::optional<WebURLError> error_;
};

struct PriorityInfo {
  net::RequestPriority priority;
  int32_t intra_priority_value;
};

class FakeURLLoader : public network::mojom::URLLoader {
 public:
  explicit FakeURLLoader(
      mojo::PendingReceiver<network::mojom::URLLoader> pending_receiver)
      : receiver_(this, std::move(pending_receiver)) {}
  FakeURLLoader(const FakeURLLoader&) = delete;
  FakeURLLoader& operator=(const FakeURLLoader&) = delete;
  ~FakeURLLoader() override = default;

  // network::mojom::URLLoader implementation:
  void FollowRedirect(
      const std::vector<std::string>& removed_headers,
      const net::HttpRequestHeaders& modified_headers,
      const net::HttpRequestHeaders& modified_cors_exempt_headers,
      const std::optional<GURL>& new_url) override {
    follow_redirect_called_ = true;
  }
  void SetPriority(net::RequestPriority priority,
                   int32_t intra_priority_value) override {
    set_priority_log_.push_back(PriorityInfo{
        .priority = priority, .intra_priority_value = intra_priority_value});
  }
  void PauseReadingBodyFromNet() override {}
  void ResumeReadingBodyFromNet() override {}

  bool follow_redirect_called() const { return follow_redirect_called_; }
  const std::vector<PriorityInfo>& set_priority_log() const {
    return set_priority_log_;
  }

  void set_disconnect_handler(base::OnceClosure handler) {
    receiver_.set_disconnect_handler(std::move(handler));
  }

 private:
  bool follow_redirect_called_ = false;
  std::vector<PriorityInfo> set_priority_log_;
  mojo::Receiver<network::mojom::URLLoader> receiver_;
};

// Sets up the message sender override for the unit test.
class BackgroundResourceFecherTest : public testing::Test {
 public:
  explicit BackgroundResourceFecherTest()
      : unfreezable_task_runner_(
            base::MakeRefCounted<scheduler::FakeTaskRunner>()) {}

  BackgroundResourceFecherTest(const BackgroundResourceFecherTest&) = delete;
  BackgroundResourceFecherTest& operator=(const BackgroundResourceFecherTest&) =
      delete;
  ~BackgroundResourceFecherTest() override = default;

  // testing::Test implementation:
  void SetUp() override {
    background_task_runner_ =
        base::ThreadPool::CreateSingleThreadTaskRunner({});
    WebRuntimeFeatures::EnableBackForwardCache(true);
    feature_list_.InitWithFeaturesAndParameters(
        {{blink::features::kLoadingTasksUnfreezable,
          {{"max_buffered_bytes_per_process",
            base::NumberToString(kMaxBufferedBytesPerProcess)}}}},
        {});
    bfcache_loader_helper_ =
        MakeGarbageCollected<FakeBackForwardCacheLoaderHelper>();
  }
  void TearDown() override {
    // Need to run tasks to avoid memory leak.
    task_environment_.RunUntilIdle();
    unfreezable_task_runner_->RunUntilIdle();
  }

 protected:
  std::unique_ptr<BackgroundURLLoader> CreateBackgroundURLLoaderAndStart(
      std::unique_ptr<network::ResourceRequest> request,
      URLLoaderClient* url_loader_client,
      std::unique_ptr<BackgroundResponseProcessorFactory>
          background_processor_factory = nullptr) {
    base::RunLoop run_loop;
    scoped_refptr<WebBackgroundResourceFetchAssets>
        background_resource_fetch_assets =
            base::MakeRefCounted<FakeBackgroundResourceFetchAssets>(
                background_task_runner_,
                base::BindLambdaForTesting(
                    [&](mojo::PendingReceiver<network::mojom::URLLoader> loader,
                        mojo::PendingRemote<network::mojom::URLLoaderClient>
                            client) {
                      DCHECK(background_task_runner_
                                 ->RunsTasksInCurrentSequence());
                      loader_pending_receiver_ = std::move(loader);
                      loader_client_pending_remote_ = std::move(client);
                      run_loop.Quit();
                    }));
    std::unique_ptr<BackgroundURLLoader> background_url_loader =
        std::make_unique<BackgroundURLLoader>(
            std::move(background_resource_fetch_assets),
            /*cors_exempt_header_list=*/Vector<String>(),
            unfreezable_task_runner_, bfcache_loader_helper_,
            /*background_code_cache_host=*/nullptr);

    CHECK(background_url_loader->CanHandleResponseOnBackground());
    if (background_processor_factory) {
      background_url_loader->SetBackgroundResponseProcessorFactory(
          std::move(background_processor_factory));
    }
    background_url_loader->LoadAsynchronously(
        std::move(request), SecurityOrigin::Create(KURL(kTestURL)),
        /*no_mime_sniffing=*/false,
        std::make_unique<ResourceLoadInfoNotifierWrapper>(
            /*resource_load_info_notifier=*/nullptr),
        /*code_cache_host=*/nullptr, url_loader_client);
    run_loop.Run();
    return background_url_loader;
  }

  mojo::PendingReceiver<network::mojom::URLLoader> loader_pending_receiver_;
  mojo::PendingRemote<network::mojom::URLLoaderClient>
      loader_client_pending_remote_;

  scoped_refptr<base::SequencedTaskRunner> background_task_runner_;
  scoped_refptr<scheduler::FakeTaskRunner> unfreezable_task_runner_;
  base::test::TaskEnvironment task_environment_;
  Persistent<FakeBackForwardCacheLoaderHelper> bfcache_loader_helper_;

 private:
  class TestPlatformForRedirects final : public TestingPlatformSupport {
   public:
    bool IsRedirectSafe(const GURL& from_url, const GURL& to_url) override {
      return true;
    }
  };

  ScopedTestingPlatformSupport<TestPlatformForRedirects> platform_;
  base::test::ScopedFeatureList feature_list_;
};

TEST_F(BackgroundResourceFecherTest, SimpleRequest) {
  FakeURLLoaderClient client(unfreezable_task_runner_);
  auto background_url_loader =
      CreateBackgroundURLLoaderAndStart(CreateTestRequest(), &client);

  mojo::Remote<network::mojom::URLLoaderClient> loader_client_remote(
      std::move(loader_client_pending_remote_));
  loader_client_remote->OnReceiveResponse(
      CreateTestResponse(), CreateTestBody(), CreateTestCachedMetaData());

  // Call RunUntilIdle() to receive Mojo IPC.
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(client.response());
  EXPECT_FALSE(client.cached_metadata());
  EXPECT_FALSE(client.response_body_handle());
  unfreezable_task_runner_->RunUntilIdle();
  EXPECT_TRUE(client.response());
  EXPECT_TRUE(client.cached_metadata());
  EXPECT_TRUE(client.response_body_handle());

  loader_client_remote->OnTransferSizeUpdated(10);
  // Call RunUntilIdle() to receive Mojo IPC.
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(client.transfer_size_diffs().empty());
  unfreezable_task_runner_->RunUntilIdle();
  EXPECT_THAT(client.transfer_size_diffs(), testing::ElementsAreArray({10}));

  loader_client_remote->OnComplete(network::URLLoaderCompletionStatus(net::OK));

  // Call RunUntilIdle() to receive Mojo IPC.
  task_environment_.RunUntilIdle();
  EXPECT_FALSE(client.did_finish());
  unfreezable_task_runner_->RunUntilIdle();
  EXPECT_TRUE(client.did_finish());

  EXPECT_FALSE(client.error());
}

TEST_F(BackgroundResourceFecherTest, FailedRequest) {
  FakeURLLoaderClient client(unfreezable_task_runner_);
  auto background_url_loader =
      CreateBackgroundURLLoaderAndStart(CreateTestRequest(), &client);

  mojo::Remote<network::mojom::URLLoaderClient> loader_client_remote(
      std::move(loader_client_pending_remote_));

  loader_client_remote->OnComplete(
      network::URLLoaderCompletionStatus(net::ERR_FAILED));

  // Call RunUntilIdle() to receive Mojo IPC.
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(client.error());
  unfreezable_task_runner_->RunUntilIdle();
  EXPECT_TRUE(client.error());
}

TEST_F(BackgroundResourceFecherTest, Redirect) {
  FakeURLLoaderClient client(unfreezable_task_runner_);
  KURL redirected_url;
  client.AddWillFollowRedirectCallback(
      base::BindLambdaForTesting([&](const WebURL& new_url) {
        redirected_url = new_url;
        return true;
      }));
  auto background_url_loader =
      CreateBackgroundURLLoaderAndStart(CreateTestRequest(), &client);

  mojo::Remote<network::mojom::URLLoaderClient> loader_client_remote(
      std::move(loader_client_pending_remote_));
  FakeURLLoader loader(std::move(loader_pending_receiver_));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedURL);

  loader_client_remote->OnReceiveRedirect(
      redirect_info, network::mojom::URLResponseHead::New());

  // Call RunUntilIdle() to receive Mojo IPC.
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(redirected_url.IsEmpty());
  unfreezable_task_runner_->RunUntilIdle();
  EXPECT_EQ(KURL(kRedirectedURL), redirected_url);

  // Call RunUntilIdle() to receive Mojo IPC.
  task_environment_.RunUntilIdle();
  EXPECT_TRUE(loader.follow_redirect_called());

  loader_client_remote->OnReceiveResponse(CreateTestResponse(),
                                          CreateTestBody(),
                                          /*cached_metadata=*/std::nullopt);
  loader_client_remote->OnComplete(network::URLLoaderCompletionStatus(net::OK));
  task_environment_.RunUntilIdle();
  unfreezable_task_runner_->RunUntilIdle();
  EXPECT_TRUE(client.response());
  EXPECT_TRUE(client.did_finish());
}

TEST_F(BackgroundResourceFecherTest, RedirectDoNotFollow) {
  FakeURLLoaderClient client(unfreezable_task_runner_);
  KURL redirected_url;
  auto background_url_loader =
      CreateBackgroundURLLoaderAndStart(CreateTestRequest(), &client);

  client.AddWillFollowRedirectCallback(
      base::BindLambdaForTesting([&](const WebURL& new_url) {
        redirected_url = new_url;
        background_url_loader.reset();
        return false;
      }));

  mojo::Remote<network::mojom::URLLoaderClient> loader_client_remote(
      std::move(loader_client_pending_remote_));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedURL);

  loader_client_remote->OnReceiveRedirect(
      redirect_info, network::mojom::URLResponseHead::New());

  // Call RunUntilIdle() to receive Mojo IPC.
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(redirected_url.IsEmpty());
  unfreezable_task_runner_->RunUntilIdle();
  EXPECT_EQ(KURL(kRedirectedURL), redirected_url);
}

TEST_F(BackgroundResourceFecherTest, RedirectAndCancelDoNotCrash) {
  FakeURLLoaderClient client(unfreezable_task_runner_);
  KURL redirected_url;
  client.AddWillFollowRedirectCallback(
      base::BindLambdaForTesting([&](const WebURL& new_url) {
        redirected_url = new_url;
        return true;
      }));
  auto background_url_loader =
      CreateBackgroundURLLoaderAndStart(CreateTestRequest(), &client);

  mojo::Remote<network::mojom::URLLoaderClient> loader_client_remote(
      std::move(loader_client_pending_remote_));
  FakeURLLoader loader(std::move(loader_pending_receiver_));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedURL);

  loader_client_remote->OnReceiveRedirect(
      redirect_info, network::mojom::URLResponseHead::New());

  // Call RunUntilIdle() to receive Mojo IPC.
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(redirected_url.IsEmpty());
  // Cancel the request before Context::OnReceivedRedirect() is called in
  // `unfreezable_task_runner_`.
  background_url_loader.reset();
  unfreezable_task_runner_->RunUntilIdle();
  EXPECT_TRUE(redirected_url.IsEmpty());
}

TEST_F(BackgroundResourceFecherTest, AbortWhileHandlingRedirectDoNotCrash) {
  FakeURLLoaderClient client(unfreezable_task_runner_);
  KURL redirected_url;
  client.AddWillFollowRedirectCallback(
      base::BindLambdaForTesting([&](const WebURL& new_url) {
        redirected_url = new_url;
        return true;
      }));
  auto background_url_loader =
      CreateBackgroundURLLoaderAndStart(CreateTestRequest(), &client);

  mojo::Remote<network::mojom::URLLoaderClient> loader_client_remote(
      std::move(loader_client_pending_remote_));
  FakeURLLoader loader(std::move(loader_pending_receiver_));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedURL);

  loader_client_remote->OnReceiveRedirect(
      redirect_info, network::mojom::URLResponseHead::New());
  loader_client_remote->OnComplete(
      network::URLLoaderCompletionStatus(net::ERR_FAILED));

  // Call RunUntilIdle() to receive Mojo IPC.
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(redirected_url.IsEmpty());
  unfreezable_task_runner_->RunUntilIdle();
  EXPECT_FALSE(redirected_url.IsEmpty());
  task_environment_.RunUntilIdle();
}

TEST_F(BackgroundResourceFecherTest, CancelSoonAfterStart) {
  base::WaitableEvent waitable_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  background_task_runner_->PostTask(
      FROM_HERE, base::BindLambdaForTesting([&]() {
        base::ScopedAllowBaseSyncPrimitivesForTesting allow_wait;
        waitable_event.Wait();
      }));

  scoped_refptr<WebBackgroundResourceFetchAssets>
      background_resource_fetch_assets =
          base::MakeRefCounted<FakeBackgroundResourceFetchAssets>(
              background_task_runner_,
              base::BindLambdaForTesting(
                  [&](mojo::PendingReceiver<network::mojom::URLLoader> loader,
                      mojo::PendingRemote<network::mojom::URLLoaderClient>
                          client) {
                    // CreateLoaderAndStart should not be called.
                    CHECK(false);
                  }));
  std::unique_ptr<BackgroundURLLoader> background_url_loader =
      std::make_unique<BackgroundURLLoader>(
          std::move(background_resource_fetch_assets),
          /*cors_exempt_header_list=*/Vector<String>(),
          unfreezable_task_runner_,
          /*back_forward_cache_loader_helper=*/nullptr,
          /*background_code_cache_host*/ nullptr);
  FakeURLLoaderClient client(unfreezable_task_runner_);
  background_url_loader->LoadAsynchronously(
      CreateTestRequest(), SecurityOrigin::Create(KURL(kTestURL)),
      /*no_mime_sniffing=*/false,
      std::make_unique<ResourceLoadInfoNotifierWrapper>(
          /*resource_load_info_notifier=*/nullptr),
      /*code_cache_host=*/nullptr, &client);

  background_url_loader.reset();
  waitable_event.Signal();
  task_environment_.RunUntilIdle();
}

TEST_F(BackgroundResourceFecherTest, CancelAfterStart) {
  FakeURLLoaderClient client(unfreezable_task_runner_);
  auto background_url_loader =
      CreateBackgroundURLLoaderAndStart(CreateTestRequest(), &client);

  mojo::Remote<network::mojom::URLLoaderClient> loader_client_remote(
      std::move(loader_client_pending_remote_));
  FakeURLLoader loader(std::move(loader_pending_receiver_));

  bool url_loader_client_dissconnected = false;
  bool url_loader_dissconnected = false;
  loader_client_remote.set_disconnect_handler(base::BindLambdaForTesting(
      [&]() { url_loader_client_dissconnected = true; }));
  loader.set_disconnect_handler(
      base::BindLambdaForTesting([&]() { url_loader_dissconnected = true; }));

  background_url_loader.reset();

  // Call RunUntilIdle() to call Mojo's disconnect handler.
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(url_loader_client_dissconnected);
  EXPECT_TRUE(url_loader_dissconnected);
}

TEST_F(BackgroundResourceFecherTest, CancelAfterReceiveResponse) {
  FakeURLLoaderClient client(unfreezable_task_runner_);
  auto background_url_loader =
      CreateBackgroundURLLoaderAndStart(CreateTestRequest(), &client);

  mojo::Remote<network::mojom::URLLoaderClient> loader_client_remote(
      std::move(loader_client_pending_remote_));
  FakeURLLoader loader(std::move(loader_pending_receiver_));

  bool url_loader_client_dissconnected = false;
  bool url_loader_dissconnected = false;
  loader_client_remote.set_disconnect_handler(base::BindLambdaForTesting(
      [&]() { url_loader_client_dissconnected = true; }));
  loader.set_disconnect_handler(
      base::BindLambdaForTesting([&]() { url_loader_dissconnected = true; }));

  loader_client_remote->OnReceiveResponse(CreateTestResponse(),
                                          CreateTestBody(),
                                          /*cached_metadata=*/std::nullopt);

  // Call RunUntilIdle() to call Mojo's disconnect handler.
  task_environment_.RunUntilIdle();

  background_url_loader.reset();

  // Call RunUntilIdle() to call Mojo's disconnect handler.
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(url_loader_client_dissconnected);
  EXPECT_TRUE(url_loader_dissconnected);

  // Flush all tasks posted to avoid memory lea
"""


```