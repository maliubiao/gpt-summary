Response:
The user wants a summary of the functionality of the C++ source code file `script_streamer_test.cc`.

Here's a breakdown of how to arrive at the summary:

1. **Identify the Core Purpose:** The filename itself, `script_streamer_test.cc`, strongly suggests that this file contains tests for the `ScriptStreamer` class.

2. **Examine Includes:** The included headers provide clues about the functionalities being tested. Key includes are:
    * `script_streamer.h`: The class under test.
    * Headers related to V8 (`v8.h`, `v8_binding_for_core.h`, etc.):  Indicates interaction with the V8 JavaScript engine.
    * Headers related to resource loading (`resource_loader.h`, `resource_fetcher.h`, etc.): Shows testing of how scripts are loaded.
    * Headers related to Mojo (`mojo/public/cpp/...`): Suggests asynchronous data transfer.
    * Testing-related headers (`gtest/gtest.h`, `testing/gmock/gmock.h`, `base/test/bind.h`, etc.):  Confirms this is a test file.

3. **Analyze Test Cases:**  The `TEST_F` macros define individual test cases. The names of these test cases are very descriptive and reveal the specific functionalities being tested:
    * `CompilingStreamedScript`: Tests successful compilation of a streamed script.
    * `CompilingStreamedScriptWithParseError`:  Tests handling of parse errors during streaming.
    * `CancellingStreaming`: Tests cancellation of the streaming process.
    * `DataAfterCancelling`: Tests handling of data received after cancellation.
    * `SuppressingStreaming`: Tests scenarios where streaming is intentionally disabled (e.g., due to code cache).
    * `ConsumeLocalCompileHints`: Tests using locally cached compile hints.
    * `EmptyScripts`: Tests streaming of empty scripts.
    * `SmallScripts`: Tests the behavior for small scripts (which might not be streamed).
    * `ScriptsWithSmallFirstChunk`: Tests streaming when the initial data chunk is small.
    * `EncodingChanges`: Tests handling of encoding changes during streaming.
    * `EncodingFromBOM`: Tests handling of Byte Order Marks (BOMs).
    * `GarbageCollectDuringStreaming`: Tests garbage collection during streaming.
    * `ResourceSetRevalidatingRequest`: Tests behavior when a resource is being revalidated.
    * `InlineScript`: Tests streaming of inline scripts.
    * `ProduceLocalCompileHintsForStreamedScript`: Tests generation of local compile hints.
    * `NullCacheHandler`: Tests scenarios where there is no cache handler.

4. **Identify Supporting Classes and Functions:**  The code defines helper classes and functions like `TestResourceClient`, `NoopLoaderFactory`, and `AppendDataToDataPipe`. These are used to simulate network behavior and manage the testing environment.

5. **Infer Relationships to Web Technologies:** Based on the interaction with V8 and resource loading, it's clear that this code relates to how JavaScript is fetched and processed in a web browser. The tests cover aspects relevant to HTML `<script>` tags and how the browser optimizes the loading and compilation of JavaScript.

6. **Formulate the Summary:** Combine the information gathered above into a concise description of the file's purpose.

7. **Address Specific Requirements:** Review the initial prompt to ensure all specific points are covered (relationship to JavaScript, HTML, CSS; logical reasoning with input/output; common user/programming errors; user operation leading to this code).

    * **JavaScript:** The file directly tests the streaming and compilation of JavaScript code.
    * **HTML:** The loading of external JavaScript files is triggered by `<script src="...">` tags in HTML.
    * **CSS:** While not directly related, the fetching mechanism for scripts is similar to CSS, and the underlying resource loading infrastructure is shared.
    * **Logical Reasoning:** Many tests have implicit assumptions about input and expected output. For example, providing valid JavaScript should result in successful compilation. Providing invalid JavaScript should result in a compilation error.
    * **User/Programming Errors:** Incorrect script syntax would lead to parse errors tested in the file. Network issues or incorrect server configurations could lead to interrupted loading, which the tests also cover implicitly.
    * **User Operations:**  A user navigating to a webpage with `<script>` tags initiates the script loading process, eventually leading to the execution of this code.

8. **Structure the Response:** Organize the summary into clear points covering the different aspects of the file's functionality.
这是 `blink/renderer/bindings/core/v8/script_streamer_test.cc` 文件的第一部分，它主要用于测试 Blink 引擎中 `ScriptStreamer` 类的功能。`ScriptStreamer` 的作用是在 JavaScript 脚本下载的过程中逐步解析和编译脚本，从而提高页面加载速度。

以下是对其功能的归纳：

**主要功能:**

1. **测试脚本流式编译:**  该文件中的测试用例验证了 `ScriptStreamer` 是否能够正确地在脚本下载的同时进行编译。这允许在脚本完全下载完成之前就开始执行，从而优化性能。
2. **测试流式编译的各种场景:**  测试涵盖了成功编译、编译出错、取消流式传输等多种情况，确保 `ScriptStreamer` 在不同场景下都能正常工作。
3. **模拟网络加载:**  测试用例通过 `mojo::ScopedDataPipe` 模拟网络数据传输，可以控制数据传输的速度和内容，方便测试 `ScriptStreamer` 在不同网络环境下的行为。
4. **验证代码缓存和编译提示:**  部分测试用例涉及到代码缓存和编译提示，验证 `ScriptStreamer` 与这些优化机制的交互是否正确。
5. **测试内联脚本的流式处理:**  除了外部脚本，测试还覆盖了内联脚本的流式处理。
6. **测试编码处理:**  验证 `ScriptStreamer` 是否能正确处理不同的字符编码，包括 BOM (Byte Order Mark)。
7. **测试与 V8 引擎的集成:**  测试用例直接与 V8 JavaScript 引擎交互，例如编译脚本、运行脚本等，确保 `ScriptStreamer` 与 V8 的集成是正确的。

**与 JavaScript, HTML, CSS 的关系 (及举例说明):**

* **JavaScript:**  `ScriptStreamer` 的核心功能是处理 JavaScript 脚本。该文件中的所有测试都围绕着 JavaScript 代码的加载和编译展开。
    * **示例:** 测试用例中包含了 JavaScript 代码片段，例如 `function foo() { return 5; }`，用于验证流式编译的功能。
* **HTML:**  HTML 中的 `<script>` 标签会触发 JavaScript 脚本的加载。`ScriptStreamer` 正是处理这些通过 `<script>` 标签引入的外部 JavaScript 文件或内联脚本。
    * **示例:** 当浏览器解析到 `<script src="my_script.js"></script>` 时，会发起对 `my_script.js` 的网络请求，`ScriptStreamer` 负责处理下载过程中的数据。
* **CSS:**  虽然 `ScriptStreamer` 主要处理 JavaScript，但资源加载的基本原理是相似的。例如，CSS 文件的加载也涉及到网络请求和数据处理。测试中使用的 `ResourceRequest` 和 `ResourceResponse` 等概念在 CSS 加载中也适用。
    * **关联性:**  网络加载框架是通用的，`ScriptStreamer` 使用的底层机制与其他资源（如 CSS）的加载类似。

**逻辑推理 (假设输入与输出):**

* **假设输入:** 一段合法的 JavaScript 代码片段，通过 `AppendData` 方法逐步提供给 `ScriptStreamer`。
* **预期输出:**  `ScriptStreamer` 能够逐步解析并最终成功编译该代码，`resource_client_->Finished()` 将返回 `true`，表示资源加载完成。可以进一步使用 `V8ScriptRunner::CompileScript` 编译该脚本并运行。

* **假设输入:** 一段包含语法错误的 JavaScript 代码片段。
* **预期输出:** `ScriptStreamer` 在解析到错误时会停止解析，`V8ScriptRunner::CompileScript` 编译脚本会失败，并且 `try_catch.HasCaught()` 会返回 `true`，表明捕获到了异常。

**用户或编程常见的使用错误 (及举例说明):**

* **网络问题导致下载中断:**  用户网络不稳定或服务器出现问题可能导致脚本下载中断。测试中的 `Cancel()` 方法模拟了这种情况，验证 `ScriptStreamer` 能否优雅地处理。
* **服务器返回错误的 Content-Type:** 如果服务器返回的 `Content-Type` 不正确，浏览器可能无法识别这是一个 JavaScript 文件，`ScriptStreamer` 可能不会被调用。但这更多是上层处理的问题，`ScriptStreamer` 假设接收到的是 JavaScript 数据流。
* **脚本包含语法错误:**  这是最常见的错误，测试用例 `CompilingStreamedScriptWithParseError` 专门测试了这种情况。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中输入网址或点击链接，导航到一个包含 JavaScript 脚本的网页。**
2. **浏览器解析 HTML 文档，遇到 `<script>` 标签。**
3. **浏览器发起对脚本 URL 的网络请求。**
4. **网络层接收到响应数据，Blink 的网络模块开始处理响应。**
5. **如果这是一个外部 JavaScript 文件，且满足流式编译的条件（例如，文件大小超过一定阈值），`ScriptResource` 会创建一个 `ScriptStreamer` 对象。**
6. **接收到的脚本数据会通过 `mojo::DataPipe` 传递给 `ScriptStreamer`。**
7. **`ScriptStreamer` 在后台线程逐步解析和编译接收到的数据块。**
8. **测试文件 `script_streamer_test.cc` 中的代码模拟了步骤 5-7，通过创建 `ScriptResource` 和 `ScriptStreamer`，并使用 `AppendData` 模拟网络数据接收。**
9. **如果需要调试 `ScriptStreamer` 的行为，可以设置断点在这个文件中的相关代码处，例如 `AppendDataToDataPipe` 方法或 `ScriptStreamer` 的内部处理逻辑中。**

**功能归纳:**

总而言之，`blink/renderer/bindings/core/v8/script_streamer_test.cc` 的第一部分主要负责测试 Blink 引擎中 `ScriptStreamer` 类的核心功能，即在 JavaScript 脚本下载过程中进行流式编译，并验证其在各种正常和异常情况下的行为，包括处理编译错误、取消、代码缓存和不同的字符编码等。它通过模拟网络数据传输和直接与 V8 引擎交互来实现测试。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/script_streamer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/script_streamer.h"

#include <memory>
#include <utility>

#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/threading/thread_restrictions.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_url_request_extra_data.h"
#include "third_party/blink/renderer/bindings/core/v8/referrer_script_info.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_code_cache.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_consumer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_local_compile_hints_consumer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_local_compile_hints_producer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/script/mock_script_element_base.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/cross_origin_attribute_value.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/response_body_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_fetch_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_fetch_context.h"
#include "third_party/blink/renderer/platform/loader/testing/test_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/testing/mock_context_lifecycle_notifier.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

class TestResourceClient final : public GarbageCollected<TestResourceClient>,
                                 public ResourceClient {
 public:
  explicit TestResourceClient(base::OnceClosure finish_closure)
      : finish_closure_(std::move(finish_closure)) {}

  bool Finished() const { return finished_; }

  bool ErrorOccurred() const { return error_occurred_; }

  void NotifyFinished(Resource* resource) override {
    finished_ = true;
    error_occurred_ = resource->ErrorOccurred();
    std::move(finish_closure_).Run();
  }

  // Name for debugging, e.g. shown in memory-infra.
  String DebugName() const override { return "TestResourceClient"; }

 private:
  bool finished_ = false;
  bool error_occurred_ = false;
  base::OnceClosure finish_closure_;
};

// TODO(leszeks): This class has a similar class in resource_loader_test.cc,
// the two should probably share the same class.
class NoopLoaderFactory final : public ResourceFetcher::LoaderFactory {
  std::unique_ptr<URLLoader> CreateURLLoader(
      const network::ResourceRequest& request,
      const ResourceLoaderOptions& options,
      scoped_refptr<base::SingleThreadTaskRunner> freezable_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner,
      BackForwardCacheLoaderHelper*,
      const std::optional<base::UnguessableToken>&
          service_worker_race_network_request_token,
      bool is_from_origin_dirty_style_sheet) override {
    return std::make_unique<NoopURLLoader>(std::move(freezable_task_runner));
  }
  CodeCacheHost* GetCodeCacheHost() override { return nullptr; }

  class NoopURLLoader final : public URLLoader {
   public:
    explicit NoopURLLoader(
        scoped_refptr<base::SingleThreadTaskRunner> task_runner)
        : task_runner_(std::move(task_runner)) {}
    ~NoopURLLoader() override = default;
    void LoadSynchronously(
        std::unique_ptr<network::ResourceRequest> request,
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
        URLLoaderClient*) override {}
    void Freeze(LoaderFreezeMode) override {}
    void DidChangePriority(WebURLRequest::Priority, int) override {
      NOTREACHED();
    }
    scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunnerForBodyLoader()
        override {
      return task_runner_;
    }
    scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  };
};

void AppendDataToDataPipe(std::string_view data,
                          mojo::ScopedDataPipeProducerHandle& producer_handle) {
  MojoResult result = producer_handle->WriteAllData(base::as_byte_span(data));
  EXPECT_EQ(result, MOJO_RESULT_OK);

  // In case the mojo datapipe is being read on the main thread, we need to
  // spin the event loop to allow the watcher to post its "data received"
  // callback back to the main thread.
  //
  // Note that this uses a nested RunLoop -- this is to prevent it from being
  // affected by the QuitClosure of the outer RunLoop.
  base::RunLoop().RunUntilIdle();

  // Yield control to the background thread, so that V8 gets a chance to
  // process the data before the main thread adds more. Note that we
  // cannot fully control in what kind of chunks the data is passed to V8
  // (if V8 is not requesting more data between two AppendDataToDataPipecalls,
  // it will get both chunks together).
  test::YieldCurrentThread();
}

const uint32_t kDataPipeSize = 1024;

}  // namespace

class ScriptStreamingTest : public testing::Test {
 public:
  ScriptStreamingTest()
      : url_(String("http://streaming-test.example.com/foo" +
                    base::NumberToString(url_counter_++))) {}

  void Init(v8::Isolate* isolate, bool use_response_http_scheme = true) {
    auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
    FetchContext* context = MakeGarbageCollected<MockFetchContext>();
    scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        scheduler::GetSingleThreadTaskRunnerForTesting();
    auto* fetcher = MakeGarbageCollected<ResourceFetcher>(ResourceFetcherInit(
        properties->MakeDetachable(), context, task_runner, task_runner,
        MakeGarbageCollected<NoopLoaderFactory>(),
        MakeGarbageCollected<MockContextLifecycleNotifier>(),
        nullptr /* back_forward_cache_loader_helper */));

    EXPECT_EQ(
        mojo::CreateDataPipe(kDataPipeSize, producer_handle_, consumer_handle_),
        MOJO_RESULT_OK);

    ResourceRequest request(url_);
    request.SetRequestContext(mojom::blink::RequestContextType::SCRIPT);

    resource_client_ =
        MakeGarbageCollected<TestResourceClient>(run_loop_.QuitClosure());
    FetchParameters params = FetchParameters::CreateForTest(std::move(request));
    constexpr v8_compile_hints::V8CrowdsourcedCompileHintsProducer*
        kNoCompileHintsProducer = nullptr;
    constexpr v8_compile_hints::V8CrowdsourcedCompileHintsConsumer*
        kNoCompileHintsConsumer = nullptr;
    resource_ = ScriptResource::Fetch(
        params, fetcher, resource_client_, isolate,
        ScriptResource::kAllowStreaming, kNoCompileHintsProducer,
        kNoCompileHintsConsumer, v8_compile_hints::MagicCommentMode::kNever);
    resource_->AddClient(resource_client_, task_runner.get());

    ResourceResponse response(url_);
    response.SetHttpStatusCode(200);

    if (!use_response_http_scheme) {
      response.SetCurrentRequestUrl(KURL("file:///something"));
    }
    resource_->SetResponse(response);

    resource_->Loader()->DidReceiveResponse(WrappedResourceResponse(response),
                                            std::move(consumer_handle_),
                                            /*cached_metadata=*/std::nullopt);
  }

  ClassicScript* CreateClassicScript() const {
    return ClassicScript::CreateFromResource(resource_, ScriptFetchOptions());
  }

 protected:
  void AppendData(std::string_view data) {
    AppendDataToDataPipe(data, producer_handle_);
  }

  void Finish() {
    resource_->Loader()->DidFinishLoading(base::TimeTicks(), 0, 0, 0);
    producer_handle_.reset();
    resource_->SetStatus(ResourceStatus::kCached);
  }

  void Cancel() { resource_->Loader()->Cancel(); }

  void RunUntilResourceLoaded() { run_loop_.Run(); }

  static int url_counter_;

  test::TaskEnvironment task_environment_;
  KURL url_;

  base::RunLoop run_loop_;
  Persistent<TestResourceClient> resource_client_;
  Persistent<ScriptResource> resource_;
  mojo::ScopedDataPipeProducerHandle producer_handle_;
  mojo::ScopedDataPipeConsumerHandle consumer_handle_;
};

int ScriptStreamingTest::url_counter_ = 0;

TEST_F(ScriptStreamingTest, CompilingStreamedScript) {
  // Test that we can successfully compile a streamed script.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  AppendData("function foo() {");
  AppendData("return 5; }");
  AppendData("foo();");
  EXPECT_FALSE(resource_client_->Finished());
  Finish();

  // Process tasks on the main thread until the resource has notified that it
  // has finished loading.
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());
  ClassicScript* classic_script = CreateClassicScript();
  EXPECT_TRUE(classic_script->Streamer());
  v8::TryCatch try_catch(scope.GetIsolate());
  v8::Local<v8::Script> script;
  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_TRUE(V8ScriptRunner::CompileScript(
                  scope.GetScriptState(), *classic_script,
                  classic_script->CreateScriptOrigin(scope.GetIsolate()),
                  compile_options, no_cache_reason)
                  .ToLocal(&script));
  EXPECT_FALSE(try_catch.HasCaught());
}

TEST_F(ScriptStreamingTest, CompilingStreamedScriptWithParseError) {
  // Test that scripts with parse errors are handled properly. In those cases,
  // V8 stops reading the network stream: make sure we handle it gracefully.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  AppendData("function foo() {");
  AppendData("this is the part which will be a parse error");
  EXPECT_FALSE(resource_client_->Finished());
  Finish();

  // Process tasks on the main thread until the resource has notified that it
  // has finished loading.
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());
  ClassicScript* classic_script = CreateClassicScript();
  EXPECT_TRUE(classic_script->Streamer());
  v8::TryCatch try_catch(scope.GetIsolate());
  v8::Local<v8::Script> script;
  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_FALSE(V8ScriptRunner::CompileScript(
                   scope.GetScriptState(), *classic_script,
                   classic_script->CreateScriptOrigin(scope.GetIsolate()),
                   compile_options, no_cache_reason)
                   .ToLocal(&script));
  EXPECT_TRUE(try_catch.HasCaught());
}

TEST_F(ScriptStreamingTest, CancellingStreaming) {
  // Test that the upper layers (PendingScript and up) can be ramped down
  // while streaming is ongoing, and ScriptStreamer handles it gracefully.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  AppendData("function foo() {");

  // In general, we cannot control what the background thread is doing
  // (whether it's parsing or waiting for more data). In this test, we have
  // given it so little data that it's surely waiting for more.

  // Simulate cancelling the network load (e.g., because the user navigated
  // away).
  EXPECT_FALSE(resource_client_->Finished());
  Cancel();

  // The V8 side will complete too. This should not crash. We don't receive
  // any results from the streaming and the resource client should finish with
  // an error.
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());
  EXPECT_TRUE(resource_client_->ErrorOccurred());
  EXPECT_FALSE(resource_->HasStreamer());
}

TEST_F(ScriptStreamingTest, DataAfterCancelling) {
  // Test that the upper layers (PendingScript and up) can be ramped down
  // before streaming is started, and ScriptStreamer handles it gracefully.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  // In general, we cannot control what the background thread is doing
  // (whether it's parsing or waiting for more data). In this test, we have
  // given it so little data that it's surely waiting for more.

  EXPECT_FALSE(resource_client_->Finished());

  // Simulate cancelling the network load (e.g., because the user navigated
  // away).
  Cancel();

  // Append data to the streamer's data pipe.
  AppendData("function foo() {");

  // The V8 side will complete too. This should not crash. We don't receive
  // any results from the streaming and the resource client should finish with
  // an error.
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());
  EXPECT_TRUE(resource_client_->ErrorOccurred());
  EXPECT_FALSE(resource_->HasStreamer());
}

TEST_F(ScriptStreamingTest, SuppressingStreaming) {
  // If we notice before streaming that there is a code cache, streaming
  // is suppressed (V8 doesn't parse while the script is loading), and the
  // upper layer (ScriptResourceClient) should get a notification when the
  // script is loaded.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  CachedMetadataHandler* cache_handler = resource_->CacheHandler();
  EXPECT_TRUE(cache_handler);
  cache_handler->DisableSendToPlatformForTesting();
  // CodeCacheHost can be nullptr since we disabled sending data to
  // GeneratedCodeCacheHost for testing.
  cache_handler->SetCachedMetadata(/*code_cache_host*/ nullptr,
                                   V8CodeCache::TagForCodeCache(cache_handler),
                                   reinterpret_cast<const uint8_t*>("X"), 1);

  AppendData("function foo() {");
  Finish();
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());

  ClassicScript* classic_script = CreateClassicScript();
  // ClassicScript doesn't refer to the streamer, since we have suppressed
  // the streaming and resumed the non-streaming code path for script
  // compilation.
  EXPECT_FALSE(classic_script->Streamer());
}

TEST_F(ScriptStreamingTest, ConsumeLocalCompileHints) {
  // If we notice before streaming that there is a compile hints cache, we use
  // it for eager compilation.

  // Disable features::kProduceCompileHints2 forcefully, because local compile
  // hints are not used when producing crowdsourced compile hints.
  base::test::ScopedFeatureList features;
  features.InitWithFeatureStates({{features::kLocalCompileHints, true},
                                  {features::kProduceCompileHints2, false}});

  V8TestingScope scope;
  Init(scope.GetIsolate());

  CachedMetadataHandler* cache_handler = resource_->CacheHandler();
  EXPECT_TRUE(cache_handler);
  cache_handler->DisableSendToPlatformForTesting();
  // CodeCacheHost can be nullptr since we disabled sending data to
  // GeneratedCodeCacheHost for testing.

  // Create fake compile hints (what the real compile hints are is internal to
  // v8).
  std::vector<int> compile_hints = {200, 230};
  uint64_t timestamp = V8CodeCache::GetTimestamp();

  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data(
      v8_compile_hints::V8LocalCompileHintsProducer::
          CreateCompileHintsCachedDataForScript(compile_hints, timestamp));

  cache_handler->SetCachedMetadata(
      /*code_cache_host*/ nullptr,
      V8CodeCache::TagForCompileHints(cache_handler), cached_data->data,
      cached_data->length);

  // Checks for debugging failures in this test.
  EXPECT_TRUE(V8CodeCache::HasCompileHints(
      cache_handler, CachedMetadataHandler::kAllowUnchecked));
  EXPECT_TRUE(V8CodeCache::HasHotTimestamp(cache_handler));

  AppendData("/*this doesn't matter*/");
  Finish();
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());

  ScriptStreamer* script_streamer = std::get<0>(
      ScriptStreamer::TakeFrom(resource_, mojom::blink::ScriptType::kClassic));
  ResourceScriptStreamer* resource_script_streamer =
      reinterpret_cast<ResourceScriptStreamer*>(script_streamer);
  EXPECT_TRUE(resource_script_streamer);

  v8_compile_hints::V8LocalCompileHintsConsumer* local_compile_hints_consumer =
      resource_script_streamer->GetV8LocalCompileHintsConsumerForTest();
  EXPECT_TRUE(local_compile_hints_consumer);

  EXPECT_TRUE(local_compile_hints_consumer->GetCompileHint(200));
  EXPECT_FALSE(local_compile_hints_consumer->GetCompileHint(210));
  EXPECT_TRUE(local_compile_hints_consumer->GetCompileHint(230));
  EXPECT_FALSE(local_compile_hints_consumer->GetCompileHint(240));
}

TEST_F(ScriptStreamingTest, EmptyScripts) {
  // Empty scripts should also be streamed properly, that is, the upper layer
  // (ScriptResourceClient) should be notified when an empty script has been
  // loaded.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  // Finish the script without sending any data.
  Finish();
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());

  ClassicScript* classic_script = CreateClassicScript();
  EXPECT_FALSE(classic_script->Streamer());
}

TEST_F(ScriptStreamingTest, SmallScripts) {
  // Small scripts shouldn't be streamed.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  // This is the data chunk is small enough to not start streaming (it is less
  // than 4 bytes, so smaller than a UTF-8 BOM).
  AppendData("{}");
  EXPECT_TRUE(resource_->HasStreamer());
  EXPECT_FALSE(resource_->HasRunningStreamer());

  Finish();
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());

  ClassicScript* classic_script = CreateClassicScript();
  EXPECT_FALSE(classic_script->Streamer());
}

TEST_F(ScriptStreamingTest, ScriptsWithSmallFirstChunk) {
  // If a script is long enough, if should be streamed, even if the first data
  // chunk is small.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  // This is the first data chunk which is small enough to not start streaming
  // (it is less than 4 bytes, so smaller than a UTF-8 BOM).
  AppendData("{}");
  EXPECT_TRUE(resource_->HasStreamer());
  EXPECT_FALSE(resource_->HasRunningStreamer());

  // Now add more data so that streaming does start.
  AppendData("/*------*/");
  EXPECT_TRUE(resource_->HasRunningStreamer());

  Finish();
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());
  ClassicScript* classic_script = CreateClassicScript();
  EXPECT_TRUE(classic_script->Streamer());
  v8::TryCatch try_catch(scope.GetIsolate());
  v8::Local<v8::Script> script;
  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_TRUE(V8ScriptRunner::CompileScript(
                  scope.GetScriptState(), *classic_script,
                  classic_script->CreateScriptOrigin(scope.GetIsolate()),
                  compile_options, no_cache_reason)
                  .ToLocal(&script));
  EXPECT_FALSE(try_catch.HasCaught());
}

TEST_F(ScriptStreamingTest, EncodingChanges) {
  // It's possible that the encoding of the Resource changes after we start
  // loading it.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  resource_->SetEncodingForTest("windows-1252");

  resource_->SetEncodingForTest("UTF-8");
  // \xec\x92\x81 are the raw bytes for \uc481.
  AppendData(
      "function foo() { var foob\xec\x92\x81r = 13; return foob\xec\x92\x81r; "
      "} foo();");

  Finish();

  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());
  ClassicScript* classic_script = CreateClassicScript();
  EXPECT_TRUE(classic_script->Streamer());
  v8::TryCatch try_catch(scope.GetIsolate());
  v8::Local<v8::Script> script;
  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_TRUE(V8ScriptRunner::CompileScript(
                  scope.GetScriptState(), *classic_script,
                  classic_script->CreateScriptOrigin(scope.GetIsolate()),
                  compile_options, no_cache_reason)
                  .ToLocal(&script));
  EXPECT_FALSE(try_catch.HasCaught());
}

TEST_F(ScriptStreamingTest, EncodingFromBOM) {
  // Byte order marks should be removed before giving the data to V8. They
  // will also affect encoding detection.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  // This encoding is wrong on purpose.
  resource_->SetEncodingForTest("windows-1252");

  // \xef\xbb\xbf is the UTF-8 byte order mark. \xec\x92\x81 are the raw bytes
  // for \uc481.
  AppendData(
      "\xef\xbb\xbf function foo() { var foob\xec\x92\x81r = 13; return "
      "foob\xec\x92\x81r; } foo();");

  Finish();
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());
  ClassicScript* classic_script = CreateClassicScript();
  EXPECT_TRUE(classic_script->Streamer());
  v8::TryCatch try_catch(scope.GetIsolate());
  v8::Local<v8::Script> script;
  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_TRUE(V8ScriptRunner::CompileScript(
                  scope.GetScriptState(), *classic_script,
                  classic_script->CreateScriptOrigin(scope.GetIsolate()),
                  compile_options, no_cache_reason)
                  .ToLocal(&script));
  EXPECT_FALSE(try_catch.HasCaught());
}

// A test for crbug.com/711703. Should not crash.
TEST_F(ScriptStreamingTest, GarbageCollectDuringStreaming) {
  V8TestingScope scope;
  Init(scope.GetIsolate());

  EXPECT_FALSE(resource_client_->Finished());

  resource_ = nullptr;
  ThreadState::Current()->CollectAllGarbageForTesting(
      ThreadState::StackState::kNoHeapPointers);
}

TEST_F(ScriptStreamingTest, ResourceSetRevalidatingRequest) {
  V8TestingScope scope;
  Init(scope.GetIsolate());

  // Kick the streaming off.
  AppendData("function foo() {");
  AppendData("}");
  Finish();
  RunUntilResourceLoaded();

  // Should be done streaming by now.
  EXPECT_TRUE(resource_->HasFinishedStreamer());

  ResourceRequest request(resource_->Url());
  resource_->SetRevalidatingRequest(request);

  // Now there shouldn't be a streamer at all, and the reason should be
  // "kRevalidate".
  EXPECT_FALSE(resource_->HasStreamer());
  EXPECT_EQ(resource_->NoStreamerReason(),
            ScriptStreamer::NotStreamingReason::kRevalidate);
}

class InlineScriptStreamingTest
    : public ScriptStreamingTest,
      public ::testing::WithParamInterface<
          std::pair<bool /* 16 bit source */,
                    v8::ScriptCompiler::CompileOptions>> {};

TEST_P(InlineScriptStreamingTest, InlineScript) {
  // Test that we can successfully compile an inline script.
  V8TestingScope scope;
  Init(scope.GetIsolate());

  String source = "function foo() {return 5;} foo();";
  if (GetParam().first)
    source.Ensure16Bit();
  auto streamer = base::MakeRefCounted<BackgroundInlineScriptStreamer>(
      scope.GetIsolate(), source, GetParam().second);
  worker_pool::PostTask(
      FROM_HERE, {},
      CrossThreadBindOnce(&BackgroundInlineScriptStreamer::Run, streamer));

  ClassicScript* classic_script = ClassicScript::Create(
      source, KURL(), KURL(), ScriptFetchOptions(),
      ScriptSourceLocationType::kUnknown, SanitizeScriptErrors::kSanitize,
      nullptr, TextPosition::MinimumPosition(),
      ScriptStreamer::NotStreamingReason::kInvalid,
      InlineScriptStreamer::From(streamer));

  DummyPageHolder holder;
  ScriptEvaluationResult result = classic_script->RunScriptAndReturnValue(
      holder.GetFrame().DomWindow(),
      ExecuteScriptPolicy::kExecuteScriptWhenScriptsDisabled);
  EXPECT_EQ(result.GetResultType(),
            ScriptEvaluationResult::ResultType::kSuccess);
  EXPECT_EQ(
      5, result.GetSuccessValue()->Int32Value(scope.GetContext()).FromJust());
}

TEST_F(ScriptStreamingTest, ProduceLocalCompileHintsForStreamedScript) {
  // Test that we can produce local compile hints when a script is streamed.
  base::test::ScopedFeatureList flag_on(features::kLocalCompileHints);
  V8TestingScope scope;
  Init(scope.GetIsolate());

  AppendData("function foo() { return 5; }");
  AppendData("foo();");
  EXPECT_FALSE(resource_client_->Finished());
  Finish();

  // Process tasks on the main thread until the resource has notified that it
  // has finished loading.
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());
  ClassicScript* classic_script = CreateClassicScript();
  EXPECT_TRUE(classic_script->Streamer());
  v8::TryCatch try_catch(scope.GetIsolate());
  v8::Local<v8::Script> script;
  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_TRUE(V8ScriptRunner::CompileScript(
                  scope.GetScriptState(), *classic_script,
                  classic_script->CreateScriptOrigin(scope.GetIsolate()),
                  compile_options, no_cache_reason)
                  .ToLocal(&script));
  EXPECT_FALSE(try_catch.HasCaught());

  v8::Local<v8::Value> return_value;
  EXPECT_TRUE(script->Run(scope.GetContext()).ToLocal(&return_value));

  // Expect that we got a compile hint for the function which was run. Don't
  // assert what it is (that's internal to V8).
  std::vector<int> compile_hints = script->GetProducedCompileHints();
  EXPECT_EQ(1UL, compile_hints.size());
}

TEST_F(ScriptStreamingTest, NullCacheHandler) {
  V8TestingScope scope;
  // Use setting the responses URL to something else than HTTP(S) to trigger the
  // "streaming but no cache handler" corner case.
  Init(scope.GetIsolate(), /*use_response_http_scheme=*/false);
  EXPECT_FALSE(resource_->CacheHandler());

  AppendData("/*this doesn't matter*/");
  Finish();
  RunUntilResourceLoaded();
  EXPECT_TRUE(resource_client_->Finished());

  ScriptStreamer* script_streamer = std::get<0>(
      ScriptStreamer::TakeFrom(resource_, mojom::blink::ScriptType::kClassic));
  ResourceScriptStreamer* resource_script_streamer =
      reinterpret_cast<ResourceScriptStreamer*>(script_streamer);
  EXPECT_TRUE(resource_script_streamer);
}

INSTANTIATE_TEST_SUITE_P(
    All,
    InlineScriptStreamingTest,
    testing::ValuesIn(
        {std::make_pair(true,
                        v8::ScriptCompiler::CompileOptions::kNoCompileOptions),
         std::make_pair(false,
                        v8::ScriptCompiler::CompileOptions::kNoCompileOptions),
         std::make_pair(true,
                        v8::ScriptCompiler::CompileOptions::kEagerCompile),
         std::make_pair(false,
                        v8::ScriptCompiler::CompileOptions::kEagerCompile)}));

namespace {

// This is small enough to not start streaming (it is less　than 4 bytes, so
// smaller than a UTF-8 BOM).
const char kTooSmallScript[] = "//";
// This script is large enough to start streaming (it is larger than 4 bytes, so
// larger than a UTF-8 BOM).
const char kLargeEnoughScript[] = "function foo() { return 5; }";

// \xef\xbb\xbf is the UTF-8 byte order mark. \xec\x92\x81 are the raw bytes
// for \uc481.
const char kScriptWithBOM[] =
    "\xef\xbb\xbf function foo() { var foob\xec\x92\x81r = 13; return "
    "foob\xec\x92\x81r; } foo();";

class DummyLoaderFactory final : public ResourceFetcher::LoaderFactory {
 public:
  DummyLoaderFactory() = default;
  ~DummyLoaderFactory() override = default;

  // ResourceFetcher::LoaderFactory implementation:
  std::unique_ptr<URLLoader> CreateURLLoader(
      const network::ResourceRequest& request,
      const ResourceLoaderOptions& options,
      scoped_refptr<base::SingleThreadTaskRunner> freezable_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner,
      BackForwardCacheLoaderHelper*,
      const std::optional<base::UnguessableToken>&
          service_worker_race_network_request_token,
      bool is_from_origin_dirty_style_sheet) override {
    return std::make_unique<DummyURLLoader>(this,
                                            std::move(freezable_task_runner));
  }
  CodeCacheHost* GetCodeCacheHost() override { return nullptr; }

  bool load_started() const {
"""


```