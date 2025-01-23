Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `web_embedded_worker_impl_test.cc` immediately suggests this is a testing file for the `WebEmbeddedWorkerImpl` class. The `_test.cc` suffix is a standard convention.

2. **Understand the Context:** The directory `blink/renderer/modules/service_worker/` tells us this is related to Service Workers within the Blink rendering engine (Chromium's rendering engine).

3. **Examine Includes:** The included headers provide significant clues about the file's functionality and dependencies. Look for keywords like `test`, `mock`, and the specific Blink and Chromium components:
    * **Testing Frameworks:** `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h` indicate the use of Google Test and Google Mock for unit testing.
    * **Service Worker Specific:** Headers with "service_worker" in their path (`third_party/blink/public/mojom/service_worker/...`, `third_party/blink/public/web/modules/service_worker/...`) confirm the focus on Service Worker functionality.
    * **Mojo:** Headers with "mojo" (`mojo/public/cpp/bindings/...`) indicate the use of Mojo IPC for communication between processes (in this case, likely between the renderer and the browser process).
    * **Networking:** Headers related to `network` (`services/network/public/cpp/...`, `services/network/public/mojom/...`) show interaction with network requests and responses.
    * **Blink Core:** Headers from `third_party/blink/renderer/core/...` point to interaction with the core rendering engine.
    * **Platform Abstraction:** Headers from `third_party/blink/public/platform/...` and `third_party/blink/renderer/platform/...`  represent platform-agnostic interfaces and implementations.

4. **Analyze the Test Fixture:** The `WebEmbeddedWorkerImplTest` class inherits from `testing::Test`. This sets up the test environment. The `SetUp` and `TearDown` methods indicate initialization and cleanup procedures. The instantiation of `MockServiceWorkerContextClient` and `WebEmbeddedWorkerImpl` within `SetUp` is crucial.

5. **Deconstruct Individual Tests:**  Each `TEST_F` macro defines a specific test case. Analyze each test method:
    * **`TerminateSoonAfterStart`:** Creates a worker and immediately terminates it. Focuses on basic lifecycle management.
    * **`TerminateWhileWaitingForDebugger`:** Starts a worker with debugging enabled and terminates it. Tests handling termination during a specific state.
    * **`ScriptNotFound`:** Simulates a scenario where the Service Worker script cannot be loaded (404 error). Checks if the worker handles this error correctly.
    * **`GCOnWorkerThreadShouldNotCauseUploadFail`:** This test is more complex. It involves:
        * Starting a worker.
        * Dispatching a fetch event with an upload body.
        * Triggering garbage collection on the worker thread.
        * Verifying that the upload continues to function correctly after garbage collection. This points to memory management concerns when interacting between threads.

6. **Identify Mock Objects and Fake Implementations:** Notice the use of `MockServiceWorkerContextClient`, `FakeURLLoader`, and `FakeURLLoaderFactory`. These are used to isolate the component under test (`WebEmbeddedWorkerImpl`) and control the behavior of its dependencies. The fake implementations allow simulating specific network conditions or worker behaviors.

7. **Look for Interactions with JavaScript/HTML/CSS:** While the test is in C++, it tests aspects of Service Workers that directly relate to web development:
    * **Script Loading:** Tests like `ScriptNotFound` directly address how the worker handles the loading of its JavaScript file (the Service Worker script).
    * **Fetch API:** The `GCOnWorkerThreadShouldNotCauseUploadFail` test uses `DispatchFetchEventForSubresource` which is a core part of the Service Worker's fetch interception capabilities. This relates to how a Service Worker can intercept and modify network requests made by the web page.
    * **Lifecycle:** Tests involving `StartWorkerContext` and `TerminateWorkerContext` are about the fundamental lifecycle management of a Service Worker, which developers need to understand.

8. **Analyze Helper Classes:**  Classes like `FakeURLLoader`, `FakeURLLoaderFactory`, `FakeWebServiceWorkerFetchContext`, `OnFallbackReceiver`, `MojoHandleWatcher`, `TestDataUploader`, and `TestDataPipeReader` are utilities created specifically for testing. Understanding their purpose helps in understanding the test scenarios. For example, `TestDataUploader` and `TestDataPipeReader` are used to simulate and verify the transfer of data through Mojo pipes.

9. **Infer Logic and Assumptions:**  Consider the purpose of each test and what conditions it's trying to verify. For example, the `GCOnWorkerThreadShouldNotCauseUploadFail` test assumes that garbage collection on the worker thread shouldn't unexpectedly interrupt ongoing operations like data uploads.

10. **Consider User/Developer Errors:**  Think about common mistakes developers might make when working with Service Workers. The `ScriptNotFound` test directly relates to a common error: providing an incorrect path to the Service Worker script. Other tests, while more internal, touch upon potential internal errors that could manifest as unexpected behavior for developers.

11. **Trace User Operations (Debugging Clues):** Imagine a user interacting with a web page that uses Service Workers. How might the code in this test be relevant to debugging?  For example:
    * If a user reports that their Service Worker isn't starting, the tests around `StartWorkerContext` and potential script loading failures (`ScriptNotFound`) become relevant.
    * If a user experiences issues with network requests being intercepted by the Service Worker (e.g., uploads failing), the `GCOnWorkerThreadShouldNotCauseUploadFail` test provides insight into potential race conditions or memory management issues within the Service Worker's implementation.

By following these steps, you can systematically analyze a complex C++ test file and understand its purpose, how it relates to the larger system, and how it can be used for debugging. The key is to start with the obvious clues (file name, directory), then delve into the details of the code, focusing on the interactions between different components and the specific scenarios being tested.
这个文件 `web_embedded_worker_impl_test.cc` 是 Chromium Blink 引擎中用于测试 `WebEmbeddedWorkerImpl` 类的单元测试文件。`WebEmbeddedWorkerImpl` 是 Blink 渲染引擎中用于管理嵌入式 Worker（通常指 Service Worker）的实现类。

以下是该文件的功能分解和相关说明：

**核心功能:**

1. **测试 `WebEmbeddedWorkerImpl` 的生命周期管理:**
   - 测试启动 (`StartWorkerContext`) 和终止 (`TerminateWorkerContext`) Worker 的过程。
   - 测试在 Worker 启动后立即终止的情况。
   - 测试在 Worker 等待调试器时终止的情况。

2. **测试 Worker 脚本加载失败的情况:**
   - 模拟 Worker 脚本 HTTP 状态码为 404 (Not Found) 的情况，验证 `WebEmbeddedWorkerImpl` 是否能正确处理。

3. **测试 Worker 线程的垃圾回收与资源上传:**
   - 测试在 Worker 线程进行垃圾回收时，是否会影响正在进行的资源上传操作。这涉及到 Mojo 管道的连接性和数据的完整性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

尽管这个文件本身是用 C++ 编写的，但它测试的 `WebEmbeddedWorkerImpl` 类是 Service Worker 功能的核心，而 Service Worker 与 JavaScript、HTML 有着密切的关系：

* **JavaScript:** Service Worker 本质上是用 JavaScript 编写的脚本。测试文件中的场景，例如脚本加载失败，直接关系到 JavaScript 脚本的执行。
    * **例子:** `kNotFoundScriptURL` 常量定义了一个模拟 404 错误的 JavaScript 文件 URL。测试用例 `ScriptNotFound` 验证了当 Service Worker 的 JavaScript 脚本无法加载时，`WebEmbeddedWorkerImpl` 的行为。

* **HTML:**  HTML 页面通过 `<script>` 标签或者在 JavaScript 中使用 `navigator.serviceWorker.register()` 方法来注册和使用 Service Worker。`WebEmbeddedWorkerImpl` 负责管理这些注册的 Service Worker 的生命周期。
    * **例子:**  虽然测试代码中没有直接涉及 HTML，但可以想象，一个 HTML 页面尝试注册一个 URL 为 `kNotFoundScriptURL` 的 Service Worker，就会触发 `ScriptNotFound` 测试用例所模拟的情况。

* **CSS:**  Service Worker 可以拦截网络请求，包括 CSS 文件的请求，并进行缓存或修改。虽然这个测试文件没有直接测试 CSS 相关的功能，但 `WebEmbeddedWorkerImpl` 的能力会影响到 CSS 资源的加载和处理。
    * **例子:**  假设一个 Service Worker 拦截了一个 CSS 文件的请求，但由于某种原因（例如 Worker 崩溃或网络问题），无法返回有效的响应，那么页面的样式可能会出现问题。这个测试文件确保了 `WebEmbeddedWorkerImpl` 的基本稳定性，从而间接保证了 Service Worker 处理 CSS 等资源的能力。

**逻辑推理、假设输入与输出:**

**测试用例: `ScriptNotFound`**

* **假设输入:**
    * `WebEmbeddedWorkerStartData` 对象，其中 `script_url` 设置为 `kNotFoundScriptURL` (`https://a.test/sw-404.js`)。
    * 模拟的网络环境，当请求 `kNotFoundScriptURL` 时返回 HTTP 404 状态码。
* **逻辑推理:**  `WebEmbeddedWorkerImpl` 尝试加载指定的 Service Worker 脚本。由于网络返回 404，加载会失败。`WebEmbeddedWorkerImpl` 应该通知其客户端（`MockServiceWorkerContextClient`）加载失败。
* **预期输出:**
    * `MockServiceWorkerContextClient::FailedToFetchClassicScript()` 方法被调用。
    * Worker 最终被终止。

**测试用例: `GCOnWorkerThreadShouldNotCauseUploadFail`**

* **假设输入:**
    * 启动一个 Service Worker。
    * 通过 `DispatchFetchEventForSubresource` 发起一个子资源请求，其中包含一个上传的数据流（"foobarbaz"）。
    * 在数据上传过程中，触发 Worker 线程的垃圾回收。
* **逻辑推理:** Worker 线程的垃圾回收不应该中断或影响正在进行的 Mojo 管道数据传输。数据上传应该能够完整地完成。
* **预期输出:**
    * 通过 Mojo 管道读取上传的数据，应该能够按顺序读取到 "foo", "bar", "baz"。
    * 垃圾回收后，Mojo 管道的连接仍然有效，直到数据传输完成。

**用户或编程常见的使用错误:**

* **脚本路径错误:** 用户在注册 Service Worker 时，提供的 JavaScript 脚本路径不正确，导致 HTTP 404 错误。`ScriptNotFound` 测试用例模拟了这种情况，提醒开发者需要仔细检查脚本路径。

* **Mojo 管道使用不当:** 在涉及到跨线程或跨进程通信时，如果 Mojo 管道的使用不当，可能会导致数据丢失或程序崩溃。`GCOnWorkerThreadShouldNotCauseUploadFail` 测试用例隐含地测试了 Mojo 管道在垃圾回收场景下的稳定性，可以帮助发现潜在的 Mojo 使用问题。

* **Worker 生命周期管理错误:**  开发者可能没有正确地管理 Service Worker 的生命周期，导致 Worker 意外终止或无法启动。测试用例如 `TerminateSoonAfterStart` 和 `TerminateWhileWaitingForDebugger` 覆盖了这些场景。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在使用一个使用了 Service Worker 的网页，并且遇到了与 Service Worker 启动或网络请求相关的问题，开发者可能会进行以下调试：

1. **检查 Service Worker 注册:** 开发者会检查 HTML 或 JavaScript 代码中是否正确地注册了 Service Worker，并确认脚本路径是否正确。如果路径错误，可能会遇到类似 `ScriptNotFound` 测试用例模拟的情况。

2. **查看开发者工具:**
   - **Application 面板 -> Service Workers:** 开发者可以查看已注册的 Service Worker 的状态、作用域、更新状态等。如果 Service Worker 注册失败，这里会显示错误信息。
   - **Network 面板:** 开发者可以查看网络请求，确认 Service Worker 是否拦截了请求，以及请求的响应状态码。如果发现请求返回 404，可能与 `ScriptNotFound` 测试用例相关。
   - **Console 面板:**  Service Worker 的错误信息和 `console.log` 输出会显示在这里。

3. **模拟网络状况:** 开发者可以使用 Chrome 开发者工具中的 "Network conditions" 来模拟不同的网络状况，例如离线状态或慢速网络，以测试 Service Worker 的缓存和离线能力。

4. **断点调试 Service Worker 代码:** 开发者可以在 Service Worker 的 JavaScript 代码中设置断点，逐步执行代码，查看变量的值和执行流程。

5. **Blink 引擎源码调试 (深入):** 如果问题涉及到 Blink 引擎内部的 Service Worker 管理，开发者可能会需要查看 `WebEmbeddedWorkerImpl` 的实现和相关的测试用例。
   - **定位 `WebEmbeddedWorkerImpl`:** 通过 Service Worker 的错误信息或行为，开发者可能会追踪到 Blink 引擎中负责管理 Service Worker 的类，即 `WebEmbeddedWorkerImpl`。
   - **查看 `web_embedded_worker_impl_test.cc`:**  开发者会查看这个测试文件，了解 `WebEmbeddedWorkerImpl` 的基本功能和已知的边界情况。例如，如果怀疑是 Worker 启动失败，可能会关注 `TerminateSoonAfterStart` 和 `ScriptNotFound` 这类测试用例。
   - **单步调试 C++ 代码:**  如果需要更深入的调试，开发者可能会在 Blink 引擎的 C++ 代码中设置断点，例如在 `WebEmbeddedWorkerImpl::StartWorkerContext` 或 `WebEmbeddedWorkerImpl::TerminateWorkerContext` 方法中，来理解 Worker 的启动和终止过程。

总而言之，`web_embedded_worker_impl_test.cc` 是一个重要的测试文件，它验证了 Blink 引擎中 Service Worker 管理核心类的基本功能和错误处理能力。通过分析这个文件，开发者可以更好地理解 Service Worker 的内部工作原理，并为调试 Service Worker 相关问题提供线索。

### 提示词
```
这是目录为blink/renderer/modules/service_worker/web_embedded_worker_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/exported/web_embedded_worker_impl.h"

#include <memory>

#include "base/feature_list.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/network/public/cpp/cross_origin_embedder_policy.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/mojom/chunked_data_pipe_getter.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/messaging/message_port_channel.h"
#include "third_party/blink/public/mojom/browser_interface_broker.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_response.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/controller_service_worker.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/controller_service_worker_mode.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/dispatch_fetch_event_params.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_fetch_response_callback.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_object.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_registration.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_stream_handle.mojom-blink.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_error.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_policy_container.h"
#include "third_party/blink/public/platform/web_url_request_extra_data.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/web/modules/service_worker/web_service_worker_context_client.h"
#include "third_party/blink/public/web/modules/service_worker/web_service_worker_context_proxy.h"
#include "third_party/blink/public/web/web_embedded_worker_start_data.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_factory.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {
namespace {

const std::string kServer = "https://a.test";
const std::string kNotFoundScriptURL = kServer + "/sw-404.js";
const std::string kTimedOutURL = kServer + "/timedout.js";
const std::string kEmptyURL = kServer + "/empty.js";

// A fake URLLoader which is used for off-main-thread script fetch tests.
class FakeURLLoader final : public URLLoader {
 public:
  FakeURLLoader() = default;
  ~FakeURLLoader() override = default;

  void LoadSynchronously(std::unique_ptr<network::ResourceRequest> request,
                         scoped_refptr<const SecurityOrigin> top_frame_origin,
                         bool download_to_blob,
                         bool no_mime_sniffing,
                         base::TimeDelta timeout_interval,
                         URLLoaderClient*,
                         WebURLResponse&,
                         std::optional<WebURLError>&,
                         scoped_refptr<SharedBuffer>&,
                         int64_t& encoded_data_length,
                         uint64_t& encoded_body_length,
                         scoped_refptr<BlobDataHandle>& downloaded_blob,
                         std::unique_ptr<blink::ResourceLoadInfoNotifierWrapper>
                             resource_load_info_notifier_wrapper) override {
    NOTREACHED();
  }

  void LoadAsynchronously(
      std::unique_ptr<network::ResourceRequest> request,
      scoped_refptr<const SecurityOrigin> top_frame_origin,
      bool no_mime_sniffing,
      std::unique_ptr<blink::ResourceLoadInfoNotifierWrapper>
          resource_load_info_notifier_wrapper,
      CodeCacheHost* code_cache_host,
      URLLoaderClient* client) override {
    const std::string url = request->url.spec();
    if (url == kNotFoundScriptURL) {
      WebURLResponse response;
      response.SetMimeType("text/javascript");
      response.SetHttpStatusCode(404);
      client->DidReceiveResponse(response,
                                 /*body=*/mojo::ScopedDataPipeConsumerHandle(),
                                 /*cached_metadata=*/std::nullopt);
      client->DidFinishLoading(base::TimeTicks(), 0, 0, 0);
      return;
    }
    if (url == kEmptyURL) {
      WebURLResponse response;
      response.SetMimeType("text/javascript");
      response.SetHttpHeaderField(http_names::kContentType, "text/javascript");
      response.SetCurrentRequestUrl(url_test_helpers::ToKURL(kEmptyURL));
      response.SetHttpStatusCode(200);
      client->DidReceiveResponse(response,
                                 /*body=*/mojo::ScopedDataPipeConsumerHandle(),
                                 /*cached_metadata=*/std::nullopt);
      client->DidFinishLoading(base::TimeTicks(), 0, 0, 0);
      return;
    }
    if (url == kTimedOutURL) {
      // Don't handle other requests intentionally to emulate ongoing load.
      return;
    }
    NOTREACHED();
  }

  void Freeze(LoaderFreezeMode) override {}
  void DidChangePriority(WebURLRequest::Priority, int) override {}
  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunnerForBodyLoader()
      override {
    return base::MakeRefCounted<scheduler::FakeTaskRunner>();
  }
};

// A fake URLLoaderFactory which is used for off-main-thread script fetch tests.
class FakeURLLoaderFactory final : public URLLoaderFactory {
 public:
  std::unique_ptr<URLLoader> CreateURLLoader(
      const network::ResourceRequest&,
      scoped_refptr<base::SingleThreadTaskRunner>,
      scoped_refptr<base::SingleThreadTaskRunner>,
      mojo::PendingRemote<mojom::blink::KeepAliveHandle>,
      BackForwardCacheLoaderHelper*,
      Vector<std::unique_ptr<URLLoaderThrottle>> throttles) override {
    return std::make_unique<FakeURLLoader>();
  }
};

// A fake WebServiceWorkerFetchContext which is used for off-main-thread script
// fetch tests.
class FakeWebServiceWorkerFetchContext final
    : public WebServiceWorkerFetchContext {
 public:
  void SetTerminateSyncLoadEvent(base::WaitableEvent*) override {}
  void InitializeOnWorkerThread(AcceptLanguagesWatcher*) override {}
  URLLoaderFactory* GetURLLoaderFactory() override {
    return &fake_url_loader_factory_;
  }
  std::unique_ptr<URLLoaderFactory> WrapURLLoaderFactory(
      CrossVariantMojoRemote<network::mojom::URLLoaderFactoryInterfaceBase>
          url_loader_factory) override {
    return nullptr;
  }
  void FinalizeRequest(WebURLRequest&) override {}
  WebVector<std::unique_ptr<URLLoaderThrottle>> CreateThrottles(
      const network::ResourceRequest& request) override {
    return {};
  }

  mojom::ControllerServiceWorkerMode GetControllerServiceWorkerMode()
      const override {
    return mojom::ControllerServiceWorkerMode::kNoController;
  }
  net::SiteForCookies SiteForCookies() const override {
    return net::SiteForCookies();
  }
  std::optional<WebSecurityOrigin> TopFrameOrigin() const override {
    return std::optional<WebSecurityOrigin>();
  }
  WebString GetAcceptLanguages() const override { return WebString(); }
  void SetIsOfflineMode(bool is_offline_mode) override {}

 private:
  FakeURLLoaderFactory fake_url_loader_factory_;
};

class FakeBrowserInterfaceBroker final
    : public mojom::blink::BrowserInterfaceBroker {
 public:
  FakeBrowserInterfaceBroker() = default;
  ~FakeBrowserInterfaceBroker() override = default;

  void GetInterface(mojo::GenericPendingReceiver) override {}

  mojo::PendingRemote<mojom::blink::BrowserInterfaceBroker>
  BindNewPipeAndPassRemote() {
    return receiver_.BindNewPipeAndPassRemote();
  }

 private:
  mojo::Receiver<mojom::blink::BrowserInterfaceBroker> receiver_{this};
};

class OnFallbackReceiver
    : public mojom::blink::ServiceWorkerFetchResponseCallback {
 public:
  mojo::PendingRemote<mojom::blink::ServiceWorkerFetchResponseCallback>
  BindNewPipeAndPassRemote() {
    return response_callback_receiver_.BindNewPipeAndPassRemote();
  }

  std::optional<network::DataElementChunkedDataPipe> WaitFallbackRequestBody() {
    run_loop_.Run();
    CHECK(fallback_request_body_);
    return std::move(*fallback_request_body_);
  }

 private:
  // mojom::blink::ServiceWorkerFetchResponseCallback overrides:
  void OnResponse(
      mojom::blink::FetchAPIResponsePtr response,
      mojom::blink::ServiceWorkerFetchEventTimingPtr timing) override {
    NOTREACHED();
  }
  void OnResponseStream(
      mojom::blink::FetchAPIResponsePtr response,
      mojom::blink::ServiceWorkerStreamHandlePtr body_as_stream,
      mojom::blink::ServiceWorkerFetchEventTimingPtr timing) override {
    NOTREACHED();
  }
  void OnFallback(
      std::optional<network::DataElementChunkedDataPipe> request_body,
      mojom::blink::ServiceWorkerFetchEventTimingPtr timing) override {
    fallback_request_body_ = std::move(request_body);
    response_callback_receiver_.reset();
    run_loop_.Quit();
  }

  mojo::Receiver<mojom::blink::ServiceWorkerFetchResponseCallback>
      response_callback_receiver_{this};
  base::RunLoop run_loop_;
  std::optional<std::optional<network::DataElementChunkedDataPipe>>
      fallback_request_body_;
};

class MojoHandleWatcher {
 public:
  explicit MojoHandleWatcher(mojo::Handle handle)
      : handle_watcher_(FROM_HERE,
                        mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                        base::SequencedTaskRunner::GetCurrentDefault()) {
    handle_watcher_.Watch(handle,
                          MOJO_HANDLE_SIGNAL_READABLE |
                              MOJO_HANDLE_SIGNAL_WRITABLE |
                              MOJO_HANDLE_SIGNAL_PEER_CLOSED,
                          base::BindRepeating(&MojoHandleWatcher::OnReady,
                                              base::Unretained(this)));
  }

  void Wait() {
    run_loop_ = std::make_unique<base::RunLoop>();
    handle_watcher_.ArmOrNotify();
    run_loop_->Run();
  }

  typedef base::OnceCallback<void(void)> DoneCallBack;
  void WaitAsync(DoneCallBack callback) {
    done_callback_ = std::move(callback);
    handle_watcher_.ArmOrNotify();
  }

 private:
  void OnReady(MojoResult result) {
    CHECK_EQ(result, MOJO_RESULT_OK);
    if (done_callback_) {
      std::move(done_callback_).Run();
      return;
    }
    run_loop_->Quit();
  }

  std::unique_ptr<base::RunLoop> run_loop_;
  mojo::SimpleWatcher handle_watcher_;
  DoneCallBack done_callback_;
};

class TestDataUploader : public network::mojom::blink::ChunkedDataPipeGetter {
 public:
  explicit TestDataUploader(const std::string& upload_contents)
      : upload_contents_(upload_contents) {}

  mojo::PendingRemote<network::mojom::blink::ChunkedDataPipeGetter>
  BindNewPipeAndPassRemote() {
    auto pending_remote = receiver_.BindNewPipeAndPassRemote();
    receiver_.set_disconnect_with_reason_handler(base::BindLambdaForTesting(
        [&](uint32_t reason, const std::string& description) {
          LOG(INFO) << "TestDataUploader Mojo closed reason" << reason
                    << ", desc=" << description;
        }));
    return pending_remote;
  }

  void CallGetSizeCallback() {
    std::move(get_size_callback_).Run(0, upload_contents_.size());
  }

 private:
  // network::mojom::blink::ChunkedDataPipeGetter implementation:
  void GetSize(GetSizeCallback get_size_callback) override {
    get_size_callback_ = std::move(get_size_callback);
  }
  void StartReading(mojo::ScopedDataPipeProducerHandle producer) override {
    producer_ = std::move(producer);

    handle_watcher_ = std::make_unique<MojoHandleWatcher>(producer_.get());
    handle_watcher_->WaitAsync(
        base::BindOnce(&TestDataUploader::OnMojoReady, base::Unretained(this)));
  }

  void OnMojoReady() {
    size_t bytes_written = 0;
    CHECK_EQ(MOJO_RESULT_OK,
             producer_->WriteData(base::as_byte_span(upload_contents_)
                                      .subspan(0u, upload_contents_.size()),
                                  MOJO_WRITE_DATA_FLAG_NONE, bytes_written));
    CHECK_EQ(upload_contents_.size(), bytes_written);
  }

  const std::string upload_contents_;
  mojo::ScopedDataPipeProducerHandle producer_;
  std::unique_ptr<MojoHandleWatcher> handle_watcher_;
  mojo::Receiver<network::mojom::blink::ChunkedDataPipeGetter> receiver_{this};
  GetSizeCallback get_size_callback_;
};

class TestDataPipeReader {
 public:
  explicit TestDataPipeReader(
      mojo::PendingRemote<network::mojom::ChunkedDataPipeGetter>
          chunked_data_pipe_getter,
      uint32_t capacity_read_pipe_size)
      : chunked_data_pipe_getter_(std::move(chunked_data_pipe_getter)) {
    CHECK_EQ(MOJO_RESULT_OK, mojo::CreateDataPipe(capacity_read_pipe_size,
                                                  producer_, consumer_));
    handle_watcher_ = std::make_unique<MojoHandleWatcher>(consumer_.get());

    chunked_data_pipe_getter_.set_disconnect_with_reason_handler(
        base::BindLambdaForTesting(
            [&](uint32_t reason, const std::string& description) {
              LOG(INFO) << "TestDataPipeReader Mojo closed reason" << reason
                        << ", desc=" << description;
            }));

    chunked_data_pipe_getter_->GetSize(
        base::BindLambdaForTesting([](int32_t status, uint64_t size) {}));
    chunked_data_pipe_getter_->StartReading(std::move(producer_));
  }
  TestDataPipeReader(TestDataPipeReader&&) = default;

  std::string Read() {
    handle_watcher_->Wait();
    std::string buffer(20u, '\0');
    size_t actually_read_bytes = 0;
    CHECK_EQ(MOJO_RESULT_OK,
             consumer_->ReadData(MOJO_READ_DATA_FLAG_NONE,
                                 base::as_writable_byte_span(buffer),
                                 actually_read_bytes));
    return buffer.substr(0, actually_read_bytes);
  }

  bool IsConnected() const { return chunked_data_pipe_getter_.is_connected(); }

 private:
  mojo::ScopedDataPipeProducerHandle producer_;
  mojo::ScopedDataPipeConsumerHandle consumer_;
  std::unique_ptr<MojoHandleWatcher> handle_watcher_;

  mojo::Remote<network::mojom::ChunkedDataPipeGetter> chunked_data_pipe_getter_;
};

class MockServiceWorkerContextClient final
    : public WebServiceWorkerContextClient {
 public:
  MockServiceWorkerContextClient() = default;
  ~MockServiceWorkerContextClient() override = default;

  MOCK_METHOD2(
      WorkerReadyForInspectionOnInitiatorThread,
      void(CrossVariantMojoRemote<mojom::DevToolsAgentInterfaceBase>
               devtools_agent_remote,
           CrossVariantMojoReceiver<mojom::DevToolsAgentHostInterfaceBase>));

  void SetWebPolicyContainer(WebPolicyContainer* web_policy_container) {
    web_policy_container_ = web_policy_container;
  }

  void WorkerContextStarted(
      WebServiceWorkerContextProxy* proxy,
      scoped_refptr<base::SequencedTaskRunner> worker_task_runner) override {
    worker_task_runner_ = std::move(worker_task_runner);
    mojo::PendingAssociatedRemote<mojom::blink::ServiceWorkerHost> host_remote;
    auto host_receiver = host_remote.InitWithNewEndpointAndPassReceiver();

    mojo::PendingAssociatedRemote<
        mojom::blink::ServiceWorkerRegistrationObjectHost>
        registration_object_host;
    auto registration_object_host_receiver =
        registration_object_host.InitWithNewEndpointAndPassReceiver();
    mojo::PendingAssociatedRemote<mojom::blink::ServiceWorkerRegistrationObject>
        registration_object;

    mojo::PendingAssociatedRemote<mojom::blink::ServiceWorkerObjectHost>
        service_worker_object_host;
    auto service_worker_object_host_receiver =
        service_worker_object_host.InitWithNewEndpointAndPassReceiver();
    mojo::PendingAssociatedRemote<mojom::blink::ServiceWorkerObject>
        service_worker_object;

    mojo::PendingAssociatedRemote<mojom::blink::AssociatedInterfaceProvider>
        associated_interfaces_remote_from_browser;
    auto associated_interfaces_recevier_from_browser =
        associated_interfaces_remote_from_browser
            .InitWithNewEndpointAndPassReceiver();

    mojo::PendingAssociatedRemote<mojom::blink::AssociatedInterfaceProvider>
        associated_interfaces_remote_to_browser;
    auto associated_interfaces_recevier_to_browser =
        associated_interfaces_remote_to_browser
            .InitWithNewEndpointAndPassReceiver();

    // Simulates calling blink.mojom.ServiceWorker.InitializeGlobalScope() to
    // unblock the service worker script evaluation.
    mojo::Remote<mojom::blink::ServiceWorker> service_worker;
    proxy->BindServiceWorker(service_worker.BindNewPipeAndPassReceiver());
    service_worker->InitializeGlobalScope(
        std::move(host_remote),
        std::move(associated_interfaces_remote_from_browser),
        std::move(associated_interfaces_recevier_to_browser),
        mojom::blink::ServiceWorkerRegistrationObjectInfo::New(
            2 /* registration_id */, KURL("https://example.com"),
            mojom::blink::ServiceWorkerUpdateViaCache::kImports,
            std::move(registration_object_host),
            registration_object.InitWithNewEndpointAndPassReceiver(), nullptr,
            nullptr, nullptr),
        mojom::blink::ServiceWorkerObjectInfo::New(
            1 /* service_worker_version_id */,
            mojom::blink::ServiceWorkerState::kParsed,
            KURL("https://example.com"), std::move(service_worker_object_host),
            service_worker_object.InitWithNewEndpointAndPassReceiver()),
        mojom::blink::FetchHandlerExistence::EXISTS,
        /*reporting_observer_receiver=*/mojo::NullReceiver(),
        /*ancestor_frame_type=*/mojom::blink::AncestorFrameType::kNormalFrame,
        blink::BlinkStorageKey());

    MockPolicyContainerHost mock_policy_container_host;
    web_policy_container_->remote =
        mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote();
    web_policy_container_ = nullptr;

    // ControllerServiceWorker requires Clone to ensure
    // CrossOriginResourcePolicyChecker. See
    // ServiceWorkerGlobalScope::DispatchFetchEventForSubresource().
    mojo::Remote<mojom::blink::ControllerServiceWorker>
        stub_controller_service_worker;
    proxy->BindControllerServiceWorker(
        stub_controller_service_worker.BindNewPipeAndPassReceiver());
    stub_controller_service_worker->Clone(
        controller_service_worker_.BindNewPipeAndPassReceiver(),
        network::CrossOriginEmbedderPolicy(), mojo::NullRemote());

    // To make the other side callable.
    host_receiver.EnableUnassociatedUsage();
    associated_interfaces_recevier_from_browser.EnableUnassociatedUsage();
    associated_interfaces_remote_to_browser.EnableUnassociatedUsage();
    registration_object_host_receiver.EnableUnassociatedUsage();
    service_worker_object_host_receiver.EnableUnassociatedUsage();
  }

  void FailedToFetchClassicScript() override {
    classic_script_load_failure_event_.Signal();
  }

  void DidEvaluateScript(bool /* success */) override {
    script_evaluated_event_.Signal();
  }

  scoped_refptr<WebServiceWorkerFetchContext>
  CreateWorkerFetchContextOnInitiatorThread() override {
    return base::MakeRefCounted<FakeWebServiceWorkerFetchContext>();
  }

  void OnNavigationPreloadResponse(
      int fetch_event_id,
      std::unique_ptr<WebURLResponse> response,
      mojo::ScopedDataPipeConsumerHandle data_pipe) override {}

  void OnNavigationPreloadComplete(int fetch_event_id,
                                   base::TimeTicks completion_time,
                                   int64_t encoded_data_length,
                                   int64_t encoded_body_length,
                                   int64_t decoded_body_length) override {}

  void OnNavigationPreloadError(
      int fetch_event_id,
      std::unique_ptr<WebServiceWorkerError> error) override {}

  TestDataPipeReader DispatchFetchEventForSubresourceAndCreateReader(
      const std::string& upload_contents,
      uint32_t capacity_read_pipe_size) {
    OnFallbackReceiver on_fallback_receiver;
    worker_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&MockServiceWorkerContextClient::
                           DispatchFetchEventForSubresourceonWorkerThread,
                       base::Unretained(this),
                       base::Unretained(&on_fallback_receiver),
                       upload_contents));
    auto fallback_request_body = on_fallback_receiver.WaitFallbackRequestBody();
    return TestDataPipeReader(
        fallback_request_body->ReleaseChunkedDataPipeGetter(),
        capacity_read_pipe_size);
  }

  void DispatchFetchEventForSubresourceonWorkerThread(
      OnFallbackReceiver* on_fallback_receiver,
      const std::string& upload_contents) {
    auto request = mojom::blink::FetchAPIRequest::New();
    request->url = url_test_helpers::ToKURL(kServer);
    request->method = "POST";
    request->is_main_resource_load = false;

    test_data_uploader_ = std::make_unique<TestDataUploader>(upload_contents);
    ResourceRequestBody src(test_data_uploader_->BindNewPipeAndPassRemote());
    request->body = std::move(src);
    auto params = mojom::blink::DispatchFetchEventParams::New();
    params->request = std::move(request);
    params->client_id = "foo";
    params->resulting_client_id = "bar";

    controller_service_worker_->DispatchFetchEventForSubresource(
        std::move(params), on_fallback_receiver->BindNewPipeAndPassRemote(),
        base::DoNothing());
  }

  void CollectAllGarbageOnWorkerThread() {
    base::RunLoop run_loop;
    worker_task_runner_->PostTask(
        FROM_HERE, base::BindLambdaForTesting([&]() {
          blink::WebHeap::CollectAllGarbageForTesting();
          run_loop.Quit();
        }));
    run_loop.Run();
  }

  void CallUploaderGetSizeCallback() {
    base::RunLoop run_loop;
    worker_task_runner_->PostTask(FROM_HERE, base::BindLambdaForTesting([&]() {
                                    test_data_uploader_->CallGetSizeCallback();
                                    run_loop.Quit();
                                  }));
    run_loop.Run();
  }

  void WorkerContextDestroyed() override {
    test_data_uploader_.reset();
    controller_service_worker_.reset();
    termination_event_.Signal();
  }

  // These methods must be called on the main thread.
  void WaitUntilScriptEvaluated() { script_evaluated_event_.Wait(); }
  void WaitUntilThreadTermination() { termination_event_.Wait(); }
  void WaitUntilFailedToLoadClassicScript() {
    classic_script_load_failure_event_.Wait();
  }

 private:
  base::WaitableEvent script_evaluated_event_;
  base::WaitableEvent termination_event_;
  base::WaitableEvent classic_script_load_failure_event_;

  scoped_refptr<base::SequencedTaskRunner> worker_task_runner_;
  mojo::Remote<mojom::blink::ControllerServiceWorker>
      controller_service_worker_;
  std::unique_ptr<TestDataUploader> test_data_uploader_;
  raw_ptr<WebPolicyContainer> web_policy_container_;
};

class WebEmbeddedWorkerImplTest : public testing::Test {
 protected:
  void SetUp() override {
    mock_client_ = std::make_unique<MockServiceWorkerContextClient>();
    worker_ = std::make_unique<WebEmbeddedWorkerImpl>(mock_client_.get());
  }

  std::unique_ptr<WebEmbeddedWorkerStartData> CreateStartData() {
    const WebURL script_url = url_test_helpers::ToKURL(kTimedOutURL);
    WebFetchClientSettingsObject outside_settings_object(
        network::mojom::ReferrerPolicy::kDefault,
        /*outgoing_referrer=*/script_url,
        blink::mojom::InsecureRequestsPolicy::kDoNotUpgrade);
    auto start_data = std::make_unique<WebEmbeddedWorkerStartData>(
        std::move(outside_settings_object));
    start_data->script_url = script_url;
    start_data->user_agent = WebString("dummy user agent");
    start_data->script_type = mojom::blink::ScriptType::kClassic;
    start_data->wait_for_debugger_mode =
        WebEmbeddedWorkerStartData::kDontWaitForDebugger;
    start_data->policy_container = std::make_unique<WebPolicyContainer>();
    mock_client_->SetWebPolicyContainer(start_data->policy_container.get());
    return start_data;
  }

  void TearDown() override {
    // Drain queued tasks posted from the worker thread in order to avoid tasks
    // bound with unretained objects from running after tear down. Worker
    // termination may post such tasks (see https://crbug,com/1007616).
    // TODO(nhiroki): Stop using synchronous WaitableEvent, and instead use
    // QuitClosure to wait until all the tasks run before test completion.
    test::RunPendingTasks();

    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<MockServiceWorkerContextClient> mock_client_;
  std::unique_ptr<WebEmbeddedWorkerImpl> worker_;
};

}  // namespace

TEST_F(WebEmbeddedWorkerImplTest, TerminateSoonAfterStart) {
  FakeBrowserInterfaceBroker browser_interface_broker;
  worker_->StartWorkerContext(
      CreateStartData(),
      /*installed_scripts_manager_params=*/nullptr,
      /*content_settings_proxy=*/mojo::NullRemote(),
      /*cache_storage_remote=*/mojo::NullRemote(),
      browser_interface_broker.BindNewPipeAndPassRemote(),
      InterfaceRegistry::GetEmptyInterfaceRegistry(),
      scheduler::GetSingleThreadTaskRunnerForTesting());
  testing::Mock::VerifyAndClearExpectations(mock_client_.get());

  // Terminate the worker immediately after start.
  worker_->TerminateWorkerContext();
  worker_->WaitForShutdownForTesting();
}

TEST_F(WebEmbeddedWorkerImplTest, TerminateWhileWaitingForDebugger) {
  std::unique_ptr<WebEmbeddedWorkerStartData> start_data = CreateStartData();
  start_data->wait_for_debugger_mode =
      WebEmbeddedWorkerStartData::kWaitForDebugger;
  FakeBrowserInterfaceBroker browser_interface_broker;
  worker_->StartWorkerContext(
      std::move(start_data),
      /*installed_scripts_manager_params=*/nullptr,
      /*content_settings_proxy=*/mojo::NullRemote(),
      /*cache_storage_remote=*/mojo::NullRemote(),
      browser_interface_broker.BindNewPipeAndPassRemote(),
      InterfaceRegistry::GetEmptyInterfaceRegistry(),
      scheduler::GetSingleThreadTaskRunnerForTesting());
  testing::Mock::VerifyAndClearExpectations(mock_client_.get());

  // Terminate the worker while waiting for the debugger.
  worker_->TerminateWorkerContext();
  worker_->WaitForShutdownForTesting();
}

TEST_F(WebEmbeddedWorkerImplTest, ScriptNotFound) {
  WebURL script_url = url_test_helpers::ToKURL(kNotFoundScriptURL);
  url_test_helpers::RegisterMockedErrorURLLoad(script_url);
  std::unique_ptr<WebEmbeddedWorkerStartData> start_data = CreateStartData();
  start_data->script_url = script_url;
  FakeBrowserInterfaceBroker browser_interface_broker;

  // Start worker and load the script.
  worker_->StartWorkerContext(
      std::move(start_data),
      /*installed_scripts_manager_params=*/nullptr,
      /*content_settings_proxy=*/mojo::NullRemote(),
      /*cache_storage_remote=*/mojo::NullRemote(),
      browser_interface_broker.BindNewPipeAndPassRemote(),
      InterfaceRegistry::GetEmptyInterfaceRegistry(),
      scheduler::GetSingleThreadTaskRunnerForTesting());
  testing::Mock::VerifyAndClearExpectations(mock_client_.get());

  mock_client_->WaitUntilFailedToLoadClassicScript();

  // Terminate the worker for cleanup.
  worker_->TerminateWorkerContext();
  worker_->WaitForShutdownForTesting();
}

TEST_F(WebEmbeddedWorkerImplTest, GCOnWorkerThreadShouldNotCauseUploadFail) {
  std::unique_ptr<WebEmbeddedWorkerStartData> start_data = CreateStartData();
  start_data->script_url = url_test_helpers::ToKURL(kEmptyURL);
  FakeBrowserInterfaceBroker browser_interface_broker;
  worker_->StartWorkerContext(
      std::move(start_data),
      // CreateStartData(),
      /*installed_scripts_manager_params=*/nullptr,
      /*content_settings_proxy=*/mojo::NullRemote(),
      /*cache_storage_remote=*/mojo::NullRemote(),
      browser_interface_broker.BindNewPipeAndPassRemote(),
      InterfaceRegistry::GetEmptyInterfaceRegistry(),
      scheduler::GetSingleThreadTaskRunnerForTesting());
  mock_client_->WaitUntilScriptEvaluated();

  // We need to fulfill mojo pipe to let BytesUploader await it and
  // not to have Oilpan references. See the loop in
  // BytesUploader::WriteDataOnPipe().
  TestDataPipeReader reader =
      mock_client_->DispatchFetchEventForSubresourceAndCreateReader(
          /*upload_contents=*/"foobarbaz",
          /*capacity_read_pipe_size=*/3u);
  // Confirm mojo piping is connected.
  EXPECT_EQ("foo", reader.Read());

  mock_client_->CollectAllGarbageOnWorkerThread();
  EXPECT_TRUE(reader.IsConnected());

  EXPECT_EQ("bar", reader.Read());
  EXPECT_EQ("baz", reader.Read());
  mock_client_->CallUploaderGetSizeCallback();
  mock_client_->CollectAllGarbageOnWorkerThread();
  EXPECT_FALSE(reader.IsConnected());

  // Terminate the worker for cleanup.
  worker_->TerminateWorkerContext();
  worker_->WaitForShutdownForTesting();
}

}  // namespace blink
```