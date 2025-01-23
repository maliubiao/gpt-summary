Response:
Let's break down the thought process for analyzing the C++ unittest file.

**1. Understanding the Goal:**

The core request is to understand the purpose of the `worker_main_script_loader_unittest.cc` file within the Chromium Blink engine. This involves identifying its functionalities, relating it to web technologies (JavaScript, HTML, CSS), and considering potential errors.

**2. Initial Scan for Keywords and Structure:**

The first step is to quickly scan the code for important keywords and structural elements. This helps in forming a high-level understanding:

* **Headers:**  `#include` directives point to the main class being tested (`worker_main_script_loader.h`) and testing frameworks (`gtest`, `gmock`). Other includes like `mojom` suggest interaction with the Chromium Mojo system for inter-process communication.
* **Namespaces:** The code resides within the `blink` namespace, indicating its belonging to the Blink rendering engine.
* **Test Fixture:** The `WorkerMainScriptLoaderTest` class inherits from `testing::Test`, clearly marking this as a unit test file.
* **Test Cases:**  `TEST_F` macros define individual test cases like `ResponseWithSucessThenOnComplete`, `ResponseWithFailureThenOnComplete`, etc. These names provide hints about the scenarios being tested.
* **Mocking:** The presence of `MockResourceLoadObserver` and the usage of `EXPECT_CALL` indicate that the tests involve mocking dependencies to isolate the `WorkerMainScriptLoader`'s behavior.
* **Data Pipes:** Mentions of `mojo::ScopedDataPipeProducerHandle` and `mojo::CreateDataPipe` suggest testing the handling of data streams.
* **Assertions:** `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ` are standard testing assertions used to verify expected outcomes.

**3. Identifying the Core Class Under Test:**

The inclusion of `worker_main_script_loader.h` and the test fixture name directly point to `WorkerMainScriptLoader` as the class being tested.

**4. Deciphering Test Case Names and Logic:**

Now, delve into each test case to understand its purpose:

* **`ResponseWithSucessThenOnComplete`:**  This clearly tests the scenario where the worker script is loaded successfully. The `kHeader` suggests a successful HTTP response (200 OK). The assertions check if loading finished, if data was received, and if the correct URL and encoding were used.
* **`ResponseWithFailureThenOnComplete`:** This tests a failed loading scenario. `kFailHeader` indicates an HTTP error (404 Not Found). Assertions verify that loading did *not* finish successfully and that it failed.
* **`DisconnectBeforeOnComplete`:** This tests the robustness of the loader when the connection is unexpectedly closed. The `loader_client_.reset()` simulates this disconnection.
* **`OnCompleteWithError`:** This tests the scenario where the server sends a valid response but the underlying network has an error (`net::ERR_FAILED`).

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Based on the class name and the test scenarios, the connection to web technologies becomes apparent:

* **JavaScript:** The "worker main script" refers to the primary JavaScript file that a web worker executes. The test case `ResponseWithSucessThenOnComplete` downloads and verifies the content of such a script. The `kTopLevelScript = "fetch(\"empty.html\");"` example directly involves a JavaScript API.
* **HTML:** While the test doesn't directly parse HTML, the example JavaScript code `fetch("empty.html")` demonstrates how a worker script might interact with HTML resources (even if `empty.html` isn't loaded in the test itself). The `Content-Type: text/javascript` header is crucial for the browser to interpret the downloaded content as JavaScript.
* **CSS:**  Less direct, but it's worth noting that worker scripts *could* theoretically fetch CSS files (though less common for main worker scripts). The loading mechanism tested here is general enough to handle different content types.

**6. Logic Inference (Hypothetical Inputs and Outputs):**

Consider a specific test case like `ResponseWithSucessThenOnComplete`:

* **Hypothetical Input:**
    * A successful HTTP response (200 OK) with the `Content-Type: text/javascript` header.
    * The JavaScript code: `fetch("empty.html");` being sent in the response body.
    * The network connection completes successfully (`net::OK`).
* **Expected Output:**
    * `client_->LoadingIsFinished()` is true.
    * `client_->LoadingIsFailed()` is false.
    * The downloaded script content (`fetch("empty.html");`) is stored in `client_->Data()`.
    * The MIME type is correctly identified as `text/javascript`.

**7. Identifying Potential User/Programming Errors:**

Think about how a developer might misuse or encounter errors related to this loading process:

* **Incorrect `Content-Type`:**  If the server sends the JavaScript file with an incorrect `Content-Type` header (e.g., `text/plain`), the browser might not execute it as JavaScript, leading to errors.
* **Network Errors:**  General network issues (DNS resolution failure, connection timeouts, etc.) will prevent the script from loading. The test cases with `net::ERR_FAILED` cover this.
* **CORS Issues:** If the worker script attempts to fetch resources from a different origin without proper CORS headers, the fetch will fail. While not explicitly tested in this unit test, it's a common web development error related to resource loading.
* **Script Errors:**  Once the script is loaded, JavaScript errors within the script itself can cause the worker to malfunction. This unit test focuses on the *loading* process, not the execution, but it's a related concern.
* **Mismatched Promises/Async Operations:** If the worker script relies on asynchronous operations (like `fetch`) without proper error handling, it can lead to unhandled rejections or unexpected behavior.

**8. Refinement and Structure:**

Finally, organize the findings into a clear and structured response, addressing each part of the original request. Use clear headings and bullet points for readability. Provide specific code examples from the test file to illustrate the points.

This systematic approach, starting with a high-level overview and progressively drilling down into the details of the code and its context, allows for a comprehensive understanding of the unittest file's purpose and its relevance to web technologies.
这个文件 `worker_main_script_loader_unittest.cc` 是 Chromium Blink 引擎中用于测试 `WorkerMainScriptLoader` 类的单元测试。`WorkerMainScriptLoader` 的职责是**加载 Web Worker 的主脚本**。

让我们分解一下它的功能以及与 JavaScript, HTML, CSS 的关系：

**文件功能概览:**

1. **测试 `WorkerMainScriptLoader` 的成功加载场景:** 验证当服务器返回成功的 HTTP 响应 (200 OK) 和正确的 JavaScript 内容时，`WorkerMainScriptLoader` 能否正确下载、解析并通知客户端。
2. **测试 `WorkerMainScriptLoader` 的失败加载场景:** 验证当服务器返回错误的 HTTP 响应 (例如 404 Not Found) 或者网络连接失败时，`WorkerMainScriptLoader` 能否正确处理错误并通知客户端。
3. **测试加载过程中的中断:** 验证当加载过程中连接断开时，`WorkerMainScriptLoader` 的行为。
4. **使用 Mock 对象进行隔离测试:**  使用 `MockResourceLoadObserver` 和 `FakeResourceLoadInfoNotifier` 来模拟依赖项的行为，以便更专注于测试 `WorkerMainScriptLoader` 自身的逻辑。
5. **使用 Mojo 进行进程间通信测试:**  由于 Web Worker 运行在独立的进程中，加载过程涉及到与浏览器主进程的通信，这个文件使用了 Mojo 数据管道 (`mojo::ScopedDataPipeProducerHandle`) 来模拟数据传输。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `WorkerMainScriptLoader` 的核心功能就是加载 JavaScript 文件，这个文件是 Web Worker 的入口点。
    * **举例:**  测试用例 `ResponseWithSucessThenOnComplete` 中，`kTopLevelScript` 变量包含了 JavaScript 代码 `fetch("empty.html");`。这个测试验证了 `WorkerMainScriptLoader` 能够成功加载包含 `fetch` API 调用的 JavaScript 代码。
    * **假设输入与输出:** 假设服务器返回的 JavaScript 文件内容为 `console.log("Worker started");`。  `WorkerMainScriptLoader` 的输出（通过 `TestClient` 的 `Data()` 方法获取）应该包含这段字符串。

* **HTML:** 虽然 `WorkerMainScriptLoader` 直接加载的是 JavaScript 文件，但 Web Worker 脚本通常会与 HTML 页面交互，或者通过 `importScripts` 加载其他 JavaScript 模块。
    * **举例:** `kTopLevelScript = "fetch(\"empty.html\");"` 这个例子展示了 Worker 脚本可能发起网络请求去获取 HTML 文件或其他资源。虽然这个单元测试没有实际去加载 `empty.html` 的逻辑，但它体现了 Worker 脚本与 HTML 资源之间的潜在联系。
    * **假设输入与输出:**  无直接输入输出关系，但可以认为如果 `WorkerMainScriptLoader` 成功加载包含 `fetch('index.html')` 的脚本，那么后续 Worker 可能会尝试获取并处理 HTML 内容。

* **CSS:**  Web Worker 主要用于在后台执行 JavaScript 代码，通常不直接处理 CSS。 但是，Worker 中加载的 JavaScript 可以通过 Fetch API 获取 CSS 文件，或者操作文档（如果 Worker 可以访问文档，例如 Service Worker）。
    * **举例:** Worker 脚本可能包含 `fetch("style.css").then(response => response.text()).then(css => console.log(css));` 这样的代码。
    * **假设输入与输出:**  假设服务器返回的 CSS 文件内容为 `body { background-color: red; }`。如果 Worker 脚本包含上述代码且加载成功，虽然 `WorkerMainScriptLoader` 不直接输出 CSS，但 Worker 的控制台输出会包含这段 CSS 内容。

**逻辑推理与假设输入输出：**

考虑 `ResponseWithSucessThenOnComplete` 测试用例：

* **假设输入:**
    * 服务器返回 HTTP 状态码 200 OK。
    * `Content-Type` 头部设置为 `text/javascript`。
    * 响应体包含 JavaScript 代码 `const message = "Hello from worker"; console.log(message);`。
    * 网络连接正常完成。
* **预期输出:**
    * `client_->LoadingIsFinished()` 为 `true`。
    * `client_->LoadingIsFailed()` 为 `false`。
    * `client_->Data()` 返回的 `SharedBuffer` 内容与输入的 JavaScript 代码一致。
    * `fake_resource_load_info_notifier.GetMimeType()` 返回 `"text/javascript"`。

考虑 `ResponseWithFailureThenOnComplete` 测试用例：

* **假设输入:**
    * 服务器返回 HTTP 状态码 404 Not Found。
    * 响应体可能包含错误信息 "Page Not Found"。
    * 网络连接正常完成。
* **预期输出:**
    * `client_->LoadingIsFinished()` 为 `false`。
    * `client_->LoadingIsFailed()` 为 `true`。

**用户或编程常见的使用错误：**

1. **服务器返回错误的 `Content-Type`:** 如果服务器返回的 JavaScript 文件，但 `Content-Type` 设置为 `text/plain` 或其他不正确的类型，浏览器可能不会将其作为 JavaScript 执行，导致 Worker 启动失败或行为异常。`WorkerMainScriptLoader` 需要能够处理这种情况。
    * **举例:** 开发者配置服务器时错误地将 `.js` 文件的 MIME 类型设置为 `text/plain`。

2. **网络连接问题:** 由于网络不稳定或者服务器故障，导致 Worker 主脚本加载失败。`WorkerMainScriptLoader` 需要能够优雅地处理这些网络错误。
    * **举例:** 用户在网络环境不佳的情况下尝试创建 Web Worker。

3. **CORS (跨域资源共享) 问题:** 如果 Worker 脚本位于一个域，尝试加载另一个域的脚本，而服务器没有设置正确的 CORS 头部，加载将会失败。
    * **举例:**  HTML 页面在 `example.com` 域，尝试创建一个 Worker，其主脚本位于 `cdn.another.com` 域，但 `cdn.another.com` 没有设置允许 `example.com` 跨域访问的 CORS 头部。

4. **脚本内容错误:** 虽然 `WorkerMainScriptLoader` 主要关注加载过程，但加载的脚本本身可能包含语法错误或其他运行时错误，导致 Worker 无法正常启动或执行。这不属于 `WorkerMainScriptLoader` 的直接责任，但开发者需要注意脚本内容的正确性。
    * **举例:** Worker 脚本中存在拼写错误的变量名或使用了未定义的函数。

5. **Mojo 通信错误:**  在 Chromium 的多进程架构中，Worker 加载涉及到 Mojo 消息传递。如果 Mojo 通信链路出现问题，加载过程也会失败。虽然开发者不太可能直接操作 Mojo，但理解其重要性有助于排查更底层的错误。

总而言之，`worker_main_script_loader_unittest.cc` 通过各种测试用例，确保 `WorkerMainScriptLoader` 能够可靠地加载 Web Worker 的主脚本，并正确处理成功、失败以及中断等各种场景，这是 Web Worker 功能正常运行的基础。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/worker_main_script_loader_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/worker_main_script_loader.h"

#include "base/containers/span.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "build/build_config.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "net/http/http_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/resource_load_info_notifier.mojom.h"
#include "third_party/blink/public/mojom/navigation/renderer_eviction_reason.mojom-blink.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_observer.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/worker_main_script_loader_client.h"
#include "third_party/blink/renderer/platform/loader/testing/fake_resource_load_info_notifier.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_fetch_context.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"

namespace blink {

namespace {

using ::testing::_;

const char kTopLevelScriptURL[] = "https://example.com/worker.js";
const char kHeader[] =
    "HTTP/1.1 200 OK\n"
    "Content-Type: text/javascript\n\n";
const char kFailHeader[] = "HTTP/1.1 404 Not Found\n\n";
const std::string kTopLevelScript = "fetch(\"empty.html\");";

class WorkerMainScriptLoaderTest : public testing::Test {
 public:
  WorkerMainScriptLoaderTest()
      : fake_loader_(pending_remote_loader_.InitWithNewPipeAndPassReceiver()),
        client_(MakeGarbageCollected<TestClient>()) {
    scoped_feature_list_.InitWithFeatureState(
        blink::features::kPlzDedicatedWorker, true);
  }
  ~WorkerMainScriptLoaderTest() override {
    // Forced GC in order to finalize objects depending on MockResourceObserver,
    // see details https://crbug.com/1132634.
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

 protected:
  class TestClient final : public GarbageCollected<TestClient>,
                           public WorkerMainScriptLoaderClient {

   public:
    // Implements WorkerMainScriptLoaderClient.
    void DidReceiveDataWorkerMainScript(base::span<const char> data) override {
      if (!data_)
        data_ = SharedBuffer::Create(data.data(), data.size());
      else
        data_->Append(data.data(), data.size());
    }
    void OnFinishedLoadingWorkerMainScript() override { finished_ = true; }
    void OnFailedLoadingWorkerMainScript() override { failed_ = true; }

    bool LoadingIsFinished() const { return finished_; }
    bool LoadingIsFailed() const { return failed_; }

    SharedBuffer* Data() const { return data_.get(); }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(worker_main_script_loader_);
    }

   private:
    Member<WorkerMainScriptLoader> worker_main_script_loader_;
    scoped_refptr<SharedBuffer> data_;
    bool finished_ = false;
    bool failed_ = false;
  };

  class FakeURLLoader final : public network::mojom::URLLoader {
   public:
    explicit FakeURLLoader(
        mojo::PendingReceiver<network::mojom::URLLoader> url_loader_receiver)
        : receiver_(this, std::move(url_loader_receiver)) {}
    ~FakeURLLoader() override = default;

    FakeURLLoader(const FakeURLLoader&) = delete;
    FakeURLLoader& operator=(const FakeURLLoader&) = delete;

    // network::mojom::URLLoader overrides.
    void FollowRedirect(const std::vector<std::string>&,
                        const net::HttpRequestHeaders&,
                        const net::HttpRequestHeaders&,
                        const std::optional<GURL>&) override {}
    void SetPriority(net::RequestPriority priority,
                     int32_t intra_priority_value) override {}
    void PauseReadingBodyFromNet() override {}
    void ResumeReadingBodyFromNet() override {}

   private:
    mojo::Receiver<network::mojom::URLLoader> receiver_;
  };

  class MockResourceLoadObserver : public ResourceLoadObserver {
   public:
    MOCK_METHOD2(DidStartRequest, void(const FetchParameters&, ResourceType));
    MOCK_METHOD6(WillSendRequest,
                 void(const ResourceRequest&,
                      const ResourceResponse& redirect_response,
                      ResourceType,
                      const ResourceLoaderOptions&,
                      RenderBlockingBehavior,
                      const Resource*));
    MOCK_METHOD3(DidChangePriority,
                 void(uint64_t identifier,
                      ResourceLoadPriority,
                      int intra_priority_value));
    MOCK_METHOD5(DidReceiveResponse,
                 void(uint64_t identifier,
                      const ResourceRequest& request,
                      const ResourceResponse& response,
                      const Resource* resource,
                      ResponseSource));
    MOCK_METHOD2(DidReceiveData,
                 void(uint64_t identifier, base::SpanOrSize<const char> chunk));
    MOCK_METHOD2(DidReceiveTransferSizeUpdate,
                 void(uint64_t identifier, int transfer_size_diff));
    MOCK_METHOD2(DidDownloadToBlob, void(uint64_t identifier, BlobDataHandle*));
    MOCK_METHOD4(DidFinishLoading,
                 void(uint64_t identifier,
                      base::TimeTicks finish_time,
                      int64_t encoded_data_length,
                      int64_t decoded_body_length));
    MOCK_METHOD5(DidFailLoading,
                 void(const KURL&,
                      uint64_t identifier,
                      const ResourceError&,
                      int64_t encoded_data_length,
                      IsInternalRequest));
    MOCK_METHOD2(DidChangeRenderBlockingBehavior,
                 void(Resource* resource, const FetchParameters& params));
    MOCK_METHOD0(InterestedInAllRequests, bool());
    MOCK_METHOD1(EvictFromBackForwardCache,
                 void(mojom::blink::RendererEvictionReason));
  };

  MojoCreateDataPipeOptions CreateDataPipeOptions() {
    MojoCreateDataPipeOptions options;
    options.struct_size = sizeof(MojoCreateDataPipeOptions);
    options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
    options.element_num_bytes = 1;
    options.capacity_num_bytes = 1024;
    return options;
  }

  std::unique_ptr<WorkerMainScriptLoadParameters> CreateMainScriptLoaderParams(
      const char* header,
      mojo::ScopedDataPipeProducerHandle* body_producer) {
    auto head = network::mojom::URLResponseHead::New();
    head->headers = base::MakeRefCounted<net::HttpResponseHeaders>(
        net::HttpUtil::AssembleRawHeaders(header));
    head->headers->GetMimeType(&head->mime_type);
    network::mojom::URLLoaderClientEndpointsPtr endpoints =
        network::mojom::URLLoaderClientEndpoints::New(
            std::move(pending_remote_loader_),
            loader_client_.BindNewPipeAndPassReceiver());

    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params =
            std::make_unique<WorkerMainScriptLoadParameters>();
    worker_main_script_load_params->response_head = std::move(head);
    worker_main_script_load_params->url_loader_client_endpoints =
        std::move(endpoints);
    mojo::ScopedDataPipeConsumerHandle body_consumer;
    MojoCreateDataPipeOptions options = CreateDataPipeOptions();
    EXPECT_EQ(MOJO_RESULT_OK,
              mojo::CreateDataPipe(&options, *body_producer, body_consumer));
    worker_main_script_load_params->response_body = std::move(body_consumer);

    return worker_main_script_load_params;
  }

  WorkerMainScriptLoader* CreateWorkerMainScriptLoaderAndStartLoading(
      std::unique_ptr<WorkerMainScriptLoadParameters>
          worker_main_script_load_params,
      ResourceLoadObserver* observer,
      mojom::ResourceLoadInfoNotifier* resource_load_info_notifier) {
    ResourceRequest request(kTopLevelScriptURL);
    request.SetRequestContext(mojom::blink::RequestContextType::SHARED_WORKER);
    request.SetRequestDestination(
        network::mojom::RequestDestination::kSharedWorker);
    FetchParameters fetch_params(std::move(request),
                                 ResourceLoaderOptions(nullptr /* world */));
    WorkerMainScriptLoader* worker_main_script_loader =
        MakeGarbageCollected<WorkerMainScriptLoader>();
    MockFetchContext* fetch_context = MakeGarbageCollected<MockFetchContext>();
    fetch_context->SetResourceLoadInfoNotifier(resource_load_info_notifier);
    worker_main_script_loader->Start(fetch_params,
                                     std::move(worker_main_script_load_params),
                                     fetch_context, observer, client_);
    return worker_main_script_loader;
  }

  void Complete(int net_error) {
    loader_client_->OnComplete(network::URLLoaderCompletionStatus(net_error));
    base::RunLoop().RunUntilIdle();
  }

 protected:
  base::test::TaskEnvironment task_environment_;

  mojo::PendingRemote<network::mojom::URLLoader> pending_remote_loader_;
  mojo::Remote<network::mojom::URLLoaderClient> loader_client_;
  FakeURLLoader fake_loader_;

  Persistent<TestClient> client_;
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(WorkerMainScriptLoaderTest, ResponseWithSucessThenOnComplete) {
  mojo::ScopedDataPipeProducerHandle body_producer;
  std::unique_ptr<WorkerMainScriptLoadParameters>
      worker_main_script_load_params =
          CreateMainScriptLoaderParams(kHeader, &body_producer);
  MockResourceLoadObserver* mock_observer =
      MakeGarbageCollected<MockResourceLoadObserver>();
  FakeResourceLoadInfoNotifier fake_resource_load_info_notifier;
  EXPECT_CALL(*mock_observer, DidReceiveResponse(_, _, _, _, _));
  EXPECT_CALL(*mock_observer, DidReceiveData(_, _));
  EXPECT_CALL(*mock_observer, DidFinishLoading(_, _, _, _));
  EXPECT_CALL(*mock_observer, DidFailLoading(_, _, _, _, _)).Times(0);
  Persistent<WorkerMainScriptLoader> worker_main_script_loader =
      CreateWorkerMainScriptLoaderAndStartLoading(
          std::move(worker_main_script_load_params), mock_observer,
          &fake_resource_load_info_notifier);
  mojo::BlockingCopyFromString(kTopLevelScript, body_producer);
  body_producer.reset();
  Complete(net::OK);

  EXPECT_TRUE(client_->LoadingIsFinished());
  EXPECT_FALSE(client_->LoadingIsFailed());
  EXPECT_EQ(KURL(kTopLevelScriptURL),
            worker_main_script_loader->GetRequestURL());
  EXPECT_EQ(UTF8Encoding(), worker_main_script_loader->GetScriptEncoding());
  auto flatten_data = client_->Data()->CopyAs<Vector<char>>();
  EXPECT_EQ(kTopLevelScript, std::string(base::as_string_view(flatten_data)));
  EXPECT_EQ("text/javascript", fake_resource_load_info_notifier.GetMimeType());
}

TEST_F(WorkerMainScriptLoaderTest, ResponseWithFailureThenOnComplete) {
  mojo::ScopedDataPipeProducerHandle body_producer;
  std::unique_ptr<WorkerMainScriptLoadParameters>
      worker_main_script_load_params =
          CreateMainScriptLoaderParams(kFailHeader, &body_producer);
  MockResourceLoadObserver* mock_observer =
      MakeGarbageCollected<MockResourceLoadObserver>();
  FakeResourceLoadInfoNotifier fake_resource_load_info_notifier;
  EXPECT_CALL(*mock_observer, DidReceiveResponse(_, _, _, _, _));
  EXPECT_CALL(*mock_observer, DidFinishLoading(_, _, _, _)).Times(0);
  EXPECT_CALL(*mock_observer, DidFailLoading(_, _, _, _, _));
  Persistent<WorkerMainScriptLoader> worker_main_script_loader =
      CreateWorkerMainScriptLoaderAndStartLoading(
          std::move(worker_main_script_load_params), mock_observer,
          &fake_resource_load_info_notifier);
  mojo::BlockingCopyFromString("PAGE NOT FOUND\n", body_producer);
  Complete(net::OK);
  body_producer.reset();

  EXPECT_FALSE(client_->LoadingIsFinished());
  EXPECT_TRUE(client_->LoadingIsFailed());
}

TEST_F(WorkerMainScriptLoaderTest, DisconnectBeforeOnComplete) {
  mojo::ScopedDataPipeProducerHandle body_producer;
  std::unique_ptr<WorkerMainScriptLoadParameters>
      worker_main_script_load_params =
          CreateMainScriptLoaderParams(kHeader, &body_producer);
  MockResourceLoadObserver* mock_observer =
      MakeGarbageCollected<MockResourceLoadObserver>();
  FakeResourceLoadInfoNotifier fake_resource_load_info_notifier;
  EXPECT_CALL(*mock_observer, DidReceiveResponse(_, _, _, _, _));
  EXPECT_CALL(*mock_observer, DidFinishLoading(_, _, _, _)).Times(0);
  EXPECT_CALL(*mock_observer, DidFailLoading(_, _, _, _, _));
  Persistent<WorkerMainScriptLoader> worker_main_script_loader =
      CreateWorkerMainScriptLoaderAndStartLoading(
          std::move(worker_main_script_load_params), mock_observer,
          &fake_resource_load_info_notifier);
  loader_client_.reset();
  body_producer.reset();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(client_->LoadingIsFinished());
  EXPECT_TRUE(client_->LoadingIsFailed());
}

TEST_F(WorkerMainScriptLoaderTest, OnCompleteWithError) {
  mojo::ScopedDataPipeProducerHandle body_producer;
  std::unique_ptr<WorkerMainScriptLoadParameters>
      worker_main_script_load_params =
          CreateMainScriptLoaderParams(kHeader, &body_producer);
  MockResourceLoadObserver* mock_observer =
      MakeGarbageCollected<MockResourceLoadObserver>();
  FakeResourceLoadInfoNotifier fake_resource_load_info_notifier;
  EXPECT_CALL(*mock_observer, DidReceiveResponse(_, _, _, _, _));
  EXPECT_CALL(*mock_observer, DidReceiveData(_, _));
  EXPECT_CALL(*mock_observer, DidFinishLoading(_, _, _, _)).Times(0);
  EXPECT_CALL(*mock_observer, DidFailLoading(_, _, _, _, _));
  Persistent<WorkerMainScriptLoader> worker_main_script_loader =
      CreateWorkerMainScriptLoaderAndStartLoading(
          std::move(worker_main_script_load_params), mock_observer,
          &fake_resource_load_info_notifier);
  mojo::BlockingCopyFromString(kTopLevelScript, body_producer);
  Complete(net::ERR_FAILED);
  body_producer.reset();

  EXPECT_FALSE(client_->LoadingIsFinished());
  EXPECT_TRUE(client_->LoadingIsFailed());
}

}  // namespace

}  // namespace blink
```