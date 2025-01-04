Response:
Let's break down the thought process for analyzing the C++ test file and generating the detailed explanation.

**1. Initial Scan and Purpose Identification:**

* **Keywords:**  `test`, `V8ScriptRunner`, `bindings`, `core`, `v8`. These immediately suggest the file is a test suite for the `V8ScriptRunner` component within the Blink rendering engine.
* **Includes:**  The included headers (`v8_script_runner.h`, `testing/gtest/include/gtest/gtest.h`, various `blink` headers) confirm this is a C++ unit test using Google Test. The `blink` headers indicate the functionalities being tested relate to JavaScript execution, resource loading, and caching within the Blink engine.

**2. Dissecting the Test Fixture (`V8ScriptRunnerTest`):**

* **`SetUp()`:**  The presence of `SetUp()` and the `counter_` variable suggests a mechanism to ensure each test runs in a slightly different context, likely to bypass caching or other optimizations that could interfere with individual test execution.
* **`Code()`, `DifferentCode()`, `Url()`:** These methods generate simple JavaScript code snippets and URLs. The comments about tricking the V8 code cache are crucial for understanding the test's focus.
* **`TagForCodeCache()`, `TagForTimeStamp()`, `SetCacheTimeStamp()`:** These point directly to the file's primary concern: testing the V8 code caching mechanism.
* **`CompileScript()` (multiple overloads):** This is the core action being tested. It takes a script, compiles it, and potentially interacts with the code cache. The different overloads suggest variations in how caching options are handled.
* **`CreateEmptyResource()`, `CreateResource()`, `CreateScript()`:** These utility functions are for setting up test scenarios by creating mock script resources with different properties (code, cached data, URLs, encodings).
* **`CreateCachedData()`:** This function simulates a scenario where code has already been cached, preparing data for tests that check cache consumption.
* **`RunLoopUntilQuit()`:**  This suggests the tests might involve asynchronous operations or message passing, requiring a run loop to wait for completion.

**3. Analyzing Individual Tests (Examples):**

* **`resourcelessShouldPass`:**  Tests compiling a script without an associated resource. This is a basic sanity check.
* **`emptyResourceDoesNotHaveCacheHandler`:** Checks a fundamental assumption about empty resources and caching.
* **`codeOption`:** Tests the specific case where only code caching is enabled. It verifies that the cache is created and associated with the correct encoding.
* **`consumeCodeOption`:** Focuses on consuming an existing code cache. It sets up a scenario where the cache exists and then attempts to compile the same script, expecting the cached version to be used.
* **`produceAndConsumeCodeOption`:** Tests the full cycle: cold run (timestamp), warm run (code cache), hot run (consume).
* **`successfulCodeCacheWithHashing` and `codeCacheWithFailedHashCheck`:** These tests deal with a more sophisticated caching mechanism involving hash checks, likely for security or integrity. They test both successful caching and scenarios where the hash doesn't match, leading to cache invalidation.
* **`successfulOffThreadCodeCache`, `discardOffThreadCodeCacheWithDifferentSource`, `discardOffThreadCodeCacheWithBitCorruption`:** These tests introduce asynchronous code cache consumption on a separate thread. They cover successful off-thread caching and scenarios where the cache is discarded due to source code changes or data corruption.

**4. Identifying Relationships to Web Technologies:**

* **JavaScript:** The core function is compiling and running JavaScript. The test manipulates JavaScript code directly in the `Code()` and `DifferentCode()` methods.
* **HTML:** While not directly manipulating HTML, the tests implicitly relate to how `<script>` tags in HTML are processed. The caching mechanisms being tested are crucial for optimizing page load times when the browser encounters the same script again.
* **CSS:** Less direct, but if JavaScript interacts with CSS (e.g., through the DOM), the performance of that JavaScript is affected by the caching mechanisms being tested.

**5. Inferring Logic and Assumptions:**

* **Caching Logic:** The tests reveal the different states of the cache (none, timestamp, code cache) and the transitions between them based on caching options and the presence of cached data.
* **Hashing:** The tests with "hashing" in their names demonstrate a mechanism to ensure the integrity of cached code by verifying a hash against the script content.
* **Off-threading:** The "OffThreadCodeCache" tests highlight an optimization where code cache consumption can happen in the background, improving main thread responsiveness.

**6. Identifying Potential User/Programming Errors:**

* **Cache Inconsistency:** If a developer modifies a JavaScript file on the server but the browser uses a cached version, this can lead to unexpected behavior. The tests around hash checking are relevant to this.
* **Incorrect Caching Headers:** While the tests don't directly manipulate HTTP headers, the underlying caching logic is influenced by them. Incorrect cache-control headers could prevent effective caching.
* **Assumptions about Cache Validity:** Developers might assume a cached script is always the latest version, which isn't always true.

**7. Tracing User Operations (Debugging Clues):**

* **Initial Page Load:**  The tests for cold runs and timestamp caching simulate the first time a user visits a page with a specific script.
* **Subsequent Page Loads:** The warm and hot run tests simulate revisiting a page, where the browser attempts to use the cached script.
* **Script Updates:** The tests with different code simulate scenarios where a website developer has changed a JavaScript file.
* **Network Issues/Corruption:** The bit corruption test hints at how the browser handles situations where downloaded or cached data might be corrupted.

**8. Structuring the Explanation:**

The final step is to organize the findings logically, using clear headings and examples. This involves:

* **Summarizing the file's purpose.**
* **Explaining the core functionality being tested (V8 script compilation and caching).**
* **Providing specific examples of how the tests relate to JavaScript, HTML, and CSS.**
* **Illustrating logical reasoning with input/output examples.**
* **Highlighting potential user/programming errors.**
* **Providing debugging clues by tracing user actions.**

This systematic approach, starting with a high-level overview and drilling down into the details of the code and individual tests, allows for a comprehensive understanding of the `v8_script_runner_test.cc` file and its significance within the Blink rendering engine.
这个文件 `v8_script_runner_test.cc` 是 Chromium Blink 引擎中用于测试 `V8ScriptRunner` 类的单元测试文件。 `V8ScriptRunner` 的主要职责是在 Blink 渲染引擎中执行 JavaScript 代码。因此，这个测试文件的功能是验证 `V8ScriptRunner` 及其相关的代码在各种场景下的行为是否正确。

以下是更详细的功能列表和相关的解释：

**主要功能:**

1. **测试 JavaScript 代码的编译和执行:**
   - 验证 `V8ScriptRunner::CompileScript` 函数在不同情况下是否能正确编译 JavaScript 代码。
   - 模拟各种编译选项 (例如是否启用代码缓存)。
   - 测试无关联资源 (resourceless) 的脚本编译。

2. **测试 V8 代码缓存 (Code Cache) 的生成和使用:**
   - 测试在不同的缓存选项 (`kNone`, `kCode`, `kDefault`) 下，代码缓存的生成和检索。
   - 验证代码缓存是否与脚本的 URL 和内容正确关联。
   - 测试在哈希校验 (hashing) 开启的情况下，代码缓存的生成和校验逻辑。
   - 模拟代码缓存的冷启动 (cold run)、暖启动 (warm run) 和热启动 (hot run) 场景。
   - 验证当脚本内容发生变化时，代码缓存是否能正确失效。

3. **测试异步的离线线程代码缓存消费 (Off-Thread Code Cache Consumption):**
   - 验证代码缓存的消费可以发生在独立的线程上，提高主线程的响应性。
   - 测试在离线线程消费代码缓存成功和失败的情况 (例如，当缓存数据损坏或与当前脚本不匹配时)。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**  `V8ScriptRunner` 的核心功能就是执行 JavaScript 代码。测试用例中会创建包含 JavaScript 代码的字符串，并使用 `V8ScriptRunner` 进行编译。
   * **例子:** `Code()` 函数返回一个简单的 JavaScript 函数定义 `a = function() { 1 + 1; }`。测试用例会用这个代码来验证编译和缓存逻辑。
   * **例子:**  `DifferentCode()` 函数返回不同的 JavaScript 代码 `a = function() { 1 + 12; }`，用于测试当脚本内容变化时，缓存机制是否能正确识别并失效。

* **HTML:**  当浏览器解析 HTML 页面时，遇到 `<script>` 标签，就会触发 JavaScript 代码的加载和执行。 `V8ScriptRunner` 负责执行这些脚本。
   * **例子:** 虽然测试代码没有直接创建 HTML，但它模拟了 `<script>` 标签加载外部 JavaScript 文件的场景。`CreateResource` 函数会创建一个 `ScriptResource` 对象，这代表了一个外部脚本资源。代码缓存的目的是加速后续加载相同脚本的过程，这在用户多次访问同一个页面或多个页面共享同一个 JavaScript 文件时非常有用。

* **CSS:**  JavaScript 可以操作 CSS，例如通过 DOM API 修改元素的样式。 `V8ScriptRunner` 负责执行这些操作 CSS 的 JavaScript 代码。
   * **例子:**  虽然测试用例没有直接涉及到 CSS 操作，但如果一段 JavaScript 代码中包含了修改元素样式的逻辑，`V8ScriptRunner` 也会负责执行这部分代码。 代码缓存的优化同样能提升包含 CSS 操作的 JavaScript 代码的执行效率。

**逻辑推理 (假设输入与输出):**

假设输入一个包含以下 JavaScript 代码的字符串:

```javascript
function add(a, b) {
  return a + b;
}
```

并且设置 `mojom::blink::V8CacheOptions::kCode` 选项进行编译。

**假设输入:**

* `classic_script.SourceText()`:  `"function add(a, b) {\n  return a + b;\n}"`
* `mojom::blink::V8CacheOptions::kCode`

**预期输出:**

* `CompileScript` 函数成功返回 (返回一个 `v8::MaybeLocal<v8::Script>`)。
* 如果是第一次编译 (冷启动)，则会生成代码缓存数据。
* 如果是后续编译 (暖启动或热启动)，并且脚本内容和 URL 没有变化，则会尝试使用已有的代码缓存，从而加速编译过程。
* `cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler))` 返回非空值，表示成功获取到代码缓存。

**用户或编程常见的使用错误举例:**

* **不正确的缓存控制头 (Cache-Control Headers):** 如果服务器返回的 HTTP 响应头中包含不当的 `Cache-Control` 指令，可能会导致浏览器无法有效地缓存 JavaScript 文件，即使 Blink 内部的 `V8ScriptRunner` 试图利用代码缓存。
    * **例子:**  服务器设置了 `Cache-Control: no-cache` 或 `Cache-Control: max-age=0`，浏览器每次请求都会重新下载脚本，代码缓存机制无法发挥作用。

* **假设代码缓存总是有效:** 开发者可能会假设一旦脚本被缓存，后续加载都会使用缓存。但如果脚本内容更新了，或者缓存策略发生了变化，缓存可能会失效。
    * **例子:** 开发者修改了 JavaScript 文件并部署到服务器，但用户的浏览器仍然使用了旧的缓存版本，导致页面行为不一致。

* **在开发环境频繁修改脚本但不清理缓存:** 在开发过程中，开发者可能会频繁修改 JavaScript 代码。如果不清理浏览器缓存，可能会导致浏览器仍然使用旧的代码，影响调试效率。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接，导航到一个网页。**
2. **浏览器开始解析 HTML 页面。**
3. **当解析到 `<script>` 标签时，浏览器发起对脚本资源的请求。**
4. **如果脚本资源是外部文件，浏览器会下载该文件。**
5. **下载完成后，Blink 渲染引擎会将脚本内容传递给 `V8ScriptRunner`。**
6. **`V8ScriptRunner` 会根据当前的缓存策略和资源状态，决定是否尝试使用或生成代码缓存。**
7. **`V8ScriptRunner::CompileScript` 函数会被调用，进行脚本的编译。**
8. **在编译过程中，会涉及到与 `V8CodeCache` 相关的逻辑，判断是否可以使用缓存，或者生成新的缓存。**
9. **如果启用了离线线程代码缓存消费，相关的任务会被派发到独立的线程执行。**

当开发者在调试 JavaScript 执行或代码缓存相关的问题时，可能会需要在 Blink 引擎的源代码中查找 `V8ScriptRunner` 和 `V8CodeCache` 的相关代码。`v8_script_runner_test.cc` 文件可以作为理解这些组件工作原理的重要参考，因为它包含了各种场景下的测试用例。通过阅读这些测试用例，开发者可以更好地理解 `V8ScriptRunner` 的行为，以及可能出现问题的地方。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/v8_script_runner_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"

#include "base/location.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/bindings/core/v8/referrer_script_info.h"
#include "third_party/blink/renderer/bindings/core/v8/script_cache_consumer_client.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_code_cache.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/loader/resource/script_resource.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

class V8ScriptRunnerTest : public testing::Test {
 public:
  V8ScriptRunnerTest() = default;
  ~V8ScriptRunnerTest() override = default;

  void SetUp() override {
    // To trick various layers of caching, increment a counter for each
    // test and use it in Code() and Url().
    counter_++;
  }

  WTF::String Code() const {
    // Simple function for testing. Note:
    // - Add counter to trick V8 code cache.
    // - Pad counter to 1000 digits, to trick minimal cacheability threshold.
    return WTF::String::Format("a = function() { 1 + 1; } // %01000d\n",
                               counter_);
  }
  WTF::String DifferentCode() const {
    return WTF::String::Format("a = function() { 1 + 12; } // %01000d\n",
                               counter_);
  }
  KURL Url() const {
    return KURL(WTF::String::Format(code_cache_with_hashing_scheme_
                                        ? "codecachewithhashing://bla.com/bla%d"
                                        : "http://bla.com/bla%d",
                                    counter_));
  }
  unsigned TagForCodeCache(CachedMetadataHandler* cache_handler) const {
    return V8CodeCache::TagForCodeCache(cache_handler);
  }
  unsigned TagForTimeStamp(CachedMetadataHandler* cache_handler) const {
    return V8CodeCache::TagForTimeStamp(cache_handler);
  }
  void SetCacheTimeStamp(CodeCacheHost* code_cache_host,
                         CachedMetadataHandler* cache_handler) {
    V8CodeCache::SetCacheTimeStamp(code_cache_host, cache_handler);
  }

  bool CompileScript(v8::Isolate* isolate,
                     ScriptState* script_state,
                     const ClassicScript& classic_script,
                     mojom::blink::V8CacheOptions cache_options) {
    ExecutionContext* execution_context = ExecutionContext::From(script_state);
    if (classic_script.CacheHandler()) {
      classic_script.CacheHandler()->Check(
          ExecutionContext::GetCodeCacheHostFromContext(execution_context),
          classic_script.SourceText());
    }
    v8::ScriptCompiler::CompileOptions compile_options;
    V8CodeCache::ProduceCacheOptions produce_cache_options;
    v8::ScriptCompiler::NoCacheReason no_cache_reason;
    std::tie(compile_options, produce_cache_options, no_cache_reason) =
        V8CodeCache::GetCompileOptions(cache_options, classic_script);
    v8::MaybeLocal<v8::Script> compiled_script = V8ScriptRunner::CompileScript(
        script_state, classic_script,
        classic_script.CreateScriptOrigin(isolate), compile_options,
        no_cache_reason);
    if (compiled_script.IsEmpty()) {
      return false;
    }
    V8CodeCache::ProduceCache(
        isolate,
        ExecutionContext::GetCodeCacheHostFromContext(execution_context),
        compiled_script.ToLocalChecked(), classic_script.CacheHandler(),
        classic_script.SourceText().length(), classic_script.SourceUrl(),
        classic_script.StartPosition(), produce_cache_options);
    return true;
  }

  bool CompileScript(v8::Isolate* isolate,
                     ScriptState* script_state,
                     const ClassicScript& classic_script,
                     v8::ScriptCompiler::CompileOptions compile_options,
                     v8::ScriptCompiler::NoCacheReason no_cache_reason,
                     V8CodeCache::ProduceCacheOptions produce_cache_options) {
    ExecutionContext* execution_context = ExecutionContext::From(script_state);
    if (classic_script.CacheHandler()) {
      classic_script.CacheHandler()->Check(
          ExecutionContext::GetCodeCacheHostFromContext(execution_context),
          classic_script.SourceText());
    }
    v8::MaybeLocal<v8::Script> compiled_script = V8ScriptRunner::CompileScript(
        script_state, classic_script,
        classic_script.CreateScriptOrigin(isolate), compile_options,
        no_cache_reason);
    if (compiled_script.IsEmpty()) {
      return false;
    }
    V8CodeCache::ProduceCache(
        isolate,
        ExecutionContext::GetCodeCacheHostFromContext(execution_context),
        compiled_script.ToLocalChecked(), classic_script.CacheHandler(),
        classic_script.SourceText().length(), classic_script.SourceUrl(),
        classic_script.StartPosition(), produce_cache_options);
    return true;
  }

  ScriptResource* CreateEmptyResource(v8::Isolate* isolate) {
    ScriptResource* resource =
        ScriptResource::CreateForTest(isolate, NullURL(), UTF8Encoding());
    return resource;
  }

  ScriptResource* CreateResource(v8::Isolate* isolate,
                                 const WTF::TextEncoding& encoding,
                                 Vector<uint8_t> serialized_metadata,
                                 std::optional<String> code = {}) {
    return CreateResource(isolate, encoding,
                          base::make_span(serialized_metadata), code);
  }

  ScriptResource* CreateResource(
      v8::Isolate* isolate,
      const WTF::TextEncoding& encoding,
      base::span<const uint8_t> serialized_metadata = {},
      std::optional<String> code = {}) {
    ScriptResource* resource =
        ScriptResource::CreateForTest(isolate, Url(), encoding);
    if (!code)
      code = Code();
    ResourceResponse response(Url());
    response.SetHttpStatusCode(200);
    resource->ResponseReceived(response);
    if (serialized_metadata.size() != 0) {
      resource->SetSerializedCachedMetadata(serialized_metadata);
    }
    StringUTF8Adaptor code_utf8(code.value());
    resource->AppendData(code_utf8);
    resource->FinishForTest();

    return resource;
  }

  ClassicScript* CreateScript(ScriptResource* resource) {
    return ClassicScript::CreateFromResource(resource, ScriptFetchOptions());
  }

  Vector<uint8_t> CreateCachedData() {
    V8TestingScope scope;
    ClassicScript* classic_script =
        CreateScript(CreateResource(scope.GetIsolate(), UTF8Encoding()));
    // Set timestamp to simulate a warm run.
    ScriptCachedMetadataHandler* cache_handler =
        static_cast<ScriptCachedMetadataHandler*>(
            classic_script->CacheHandler());
    ExecutionContext* execution_context =
        ExecutionContext::From(scope.GetScriptState());
    SetCacheTimeStamp(
        ExecutionContext::GetCodeCacheHostFromContext(execution_context),
        cache_handler);

    // Warm run - should produce code cache.
    EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                              *classic_script,
                              mojom::blink::V8CacheOptions::kCode));

    // Check the produced cache is for code cache.
    scoped_refptr<CachedMetadata> cached_metadata =
        cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler));

    // Copy the serialized data to return it at an independent vector.
    base::span<const uint8_t> serialized_data_view =
        cached_metadata->SerializedData();
    Vector<uint8_t> ret;
    ret.AppendRange(serialized_data_view.begin(), serialized_data_view.end());
    return ret;
  }

  // TODO(leszeks): Change this from needing an explicit quit callback to
  // manually flushing the thread pool.
  void RunLoopUntilQuit(base::Location location = base::Location::Current()) {
    run_loop_.Run(location);
  }

 protected:
  static int counter_;
  test::TaskEnvironment task_environment_;
  bool code_cache_with_hashing_scheme_ = false;
  base::test::ScopedFeatureList feature_list_;
  base::RunLoop run_loop_;
};

int V8ScriptRunnerTest::counter_ = 0;

TEST_F(V8ScriptRunnerTest, resourcelessShouldPass) {
  V8TestingScope scope;
  ClassicScript* classic_script =
      ClassicScript::Create(Code(), Url(), Url(), ScriptFetchOptions(),
                            ScriptSourceLocationType::kInternal);
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script,
                            mojom::blink::V8CacheOptions::kNone));
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script,
                            mojom::blink::V8CacheOptions::kCode));
}

TEST_F(V8ScriptRunnerTest, emptyResourceDoesNotHaveCacheHandler) {
  V8TestingScope scope;
  ScriptResource* resource = CreateEmptyResource(scope.GetIsolate());
  EXPECT_FALSE(resource->CacheHandler());
}

TEST_F(V8ScriptRunnerTest, codeOption) {
  V8TestingScope scope;
  ClassicScript* classic_script =
      CreateScript(CreateResource(scope.GetIsolate(), UTF8Encoding()));
  CachedMetadataHandler* cache_handler = classic_script->CacheHandler();
  ExecutionContext* execution_context =
      ExecutionContext::From(scope.GetScriptState());
  SetCacheTimeStamp(
      ExecutionContext::GetCodeCacheHostFromContext(execution_context),
      cache_handler);

  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script,
                            mojom::blink::V8CacheOptions::kCode));

  EXPECT_TRUE(cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler)));
  // The cached data is associated with the encoding.
  ScriptResource* another_resource =
      CreateResource(scope.GetIsolate(), UTF16LittleEndianEncoding());
  EXPECT_FALSE(cache_handler->GetCachedMetadata(
      TagForCodeCache(another_resource->CacheHandler())));
}

TEST_F(V8ScriptRunnerTest, consumeCodeOption) {
  V8TestingScope scope;
  ClassicScript* classic_script =
      CreateScript(CreateResource(scope.GetIsolate(), UTF8Encoding()));
  // Set timestamp to simulate a warm run.
  CachedMetadataHandler* cache_handler = classic_script->CacheHandler();
  ExecutionContext* execution_context =
      ExecutionContext::From(scope.GetScriptState());
  SetCacheTimeStamp(
      ExecutionContext::GetCodeCacheHostFromContext(execution_context),
      cache_handler);

  // Warm run - should produce code cache.
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script,
                            mojom::blink::V8CacheOptions::kCode));

  // Check the produced cache is for code cache.
  EXPECT_TRUE(cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler)));

  // Hot run - should consume code cache.
  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_EQ(produce_cache_options,
            V8CodeCache::ProduceCacheOptions::kNoProduceCache);
  EXPECT_EQ(compile_options,
            v8::ScriptCompiler::CompileOptions::kConsumeCodeCache);
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script, compile_options, no_cache_reason,
                            produce_cache_options));
  EXPECT_TRUE(cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler)));
}

TEST_F(V8ScriptRunnerTest, produceAndConsumeCodeOption) {
  V8TestingScope scope;
  ClassicScript* classic_script =
      CreateScript(CreateResource(scope.GetIsolate(), UTF8Encoding()));
  CachedMetadataHandler* cache_handler = classic_script->CacheHandler();

  // Cold run - should set the timestamp.
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script,
                            mojom::blink::V8CacheOptions::kDefault));
  EXPECT_TRUE(cache_handler->GetCachedMetadata(TagForTimeStamp(cache_handler)));
  EXPECT_FALSE(
      cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler)));

  // Warm run - should produce code cache.
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script,
                            mojom::blink::V8CacheOptions::kDefault));
  EXPECT_TRUE(cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler)));

  // Hot run - should consume code cache.
  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_EQ(produce_cache_options,
            V8CodeCache::ProduceCacheOptions::kNoProduceCache);
  EXPECT_EQ(compile_options,
            v8::ScriptCompiler::CompileOptions::kConsumeCodeCache);
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script, compile_options, no_cache_reason,
                            produce_cache_options));
  EXPECT_TRUE(cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler)));
}

TEST_F(V8ScriptRunnerTest, cacheDataTypeMismatch) {
  V8TestingScope scope;
  ClassicScript* classic_script =
      CreateScript(CreateResource(scope.GetIsolate(), UTF8Encoding()));
  CachedMetadataHandler* cache_handler = classic_script->CacheHandler();
  EXPECT_FALSE(
      cache_handler->GetCachedMetadata(TagForTimeStamp(cache_handler)));
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script,
                            mojom::blink::V8CacheOptions::kDefault));
  EXPECT_TRUE(cache_handler->GetCachedMetadata(TagForTimeStamp(cache_handler)));
  EXPECT_FALSE(
      cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler)));
}

TEST_F(V8ScriptRunnerTest, successfulCodeCacheWithHashing) {
  V8TestingScope scope;
#if DCHECK_IS_ON()
  // TODO(crbug.com/1329535): Remove if threaded preload scanner doesn't launch.
  // This is needed because the preload scanner creates a thread when loading a
  // page.
  WTF::SetIsBeforeThreadCreatedForTest();
#endif
  SchemeRegistry::RegisterURLSchemeAsCodeCacheWithHashing(
      "codecachewithhashing");
  code_cache_with_hashing_scheme_ = true;
  ClassicScript* classic_script =
      CreateScript(CreateResource(scope.GetIsolate(), UTF8Encoding()));
  CachedMetadataHandler* cache_handler = classic_script->CacheHandler();
  EXPECT_TRUE(cache_handler->HashRequired());

  // Cold run - should set the timestamp.
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script,
                            mojom::blink::V8CacheOptions::kDefault));
  EXPECT_TRUE(cache_handler->GetCachedMetadata(TagForTimeStamp(cache_handler)));
  EXPECT_FALSE(
      cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler)));

  // Warm run - should produce code cache.
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script,
                            mojom::blink::V8CacheOptions::kDefault));
  EXPECT_TRUE(cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler)));

  // Hot run - should consume code cache.
  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_EQ(produce_cache_options,
            V8CodeCache::ProduceCacheOptions::kNoProduceCache);
  EXPECT_EQ(compile_options,
            v8::ScriptCompiler::CompileOptions::kConsumeCodeCache);
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script, compile_options, no_cache_reason,
                            produce_cache_options));
  EXPECT_TRUE(cache_handler->GetCachedMetadata(TagForCodeCache(cache_handler)));
}

TEST_F(V8ScriptRunnerTest, codeCacheWithFailedHashCheck) {
  V8TestingScope scope;
#if DCHECK_IS_ON()
  // TODO(crbug.com/1329535): Remove if threaded preload scanner doesn't launch.
  // This is needed because the preload scanner creates a thread when loading a
  // page.
  WTF::SetIsBeforeThreadCreatedForTest();
#endif
  SchemeRegistry::RegisterURLSchemeAsCodeCacheWithHashing(
      "codecachewithhashing");
  code_cache_with_hashing_scheme_ = true;

  ClassicScript* classic_script_1 =
      CreateScript(CreateResource(scope.GetIsolate(), UTF8Encoding()));
  ScriptCachedMetadataHandlerWithHashing* cache_handler_1 =
      static_cast<ScriptCachedMetadataHandlerWithHashing*>(
          classic_script_1->CacheHandler());
  EXPECT_TRUE(cache_handler_1->HashRequired());

  // Cold run - should set the timestamp.
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script_1,
                            mojom::blink::V8CacheOptions::kDefault));
  EXPECT_TRUE(
      cache_handler_1->GetCachedMetadata(TagForTimeStamp(cache_handler_1)));
  EXPECT_FALSE(
      cache_handler_1->GetCachedMetadata(TagForCodeCache(cache_handler_1)));

  // A second script with matching script text, using the state of
  // the ScriptCachedMetadataHandler from the first script.
  ClassicScript* classic_script_2 = CreateScript(
      CreateResource(scope.GetIsolate(), UTF8Encoding(),
                     cache_handler_1->GetSerializedCachedMetadata()));
  ScriptCachedMetadataHandlerWithHashing* cache_handler_2 =
      static_cast<ScriptCachedMetadataHandlerWithHashing*>(
          classic_script_2->CacheHandler());
  EXPECT_TRUE(cache_handler_2->HashRequired());

  // Warm run - should produce code cache.
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script_2,
                            mojom::blink::V8CacheOptions::kDefault));
  EXPECT_TRUE(
      cache_handler_2->GetCachedMetadata(TagForCodeCache(cache_handler_2)));

  // A third script with different script text, using the state of
  // the ScriptCachedMetadataHandler from the second script.
  ClassicScript* classic_script_3 = CreateScript(CreateResource(
      scope.GetIsolate(), UTF8Encoding(),
      cache_handler_2->GetSerializedCachedMetadata(), DifferentCode()));
  ScriptCachedMetadataHandlerWithHashing* cache_handler_3 =
      static_cast<ScriptCachedMetadataHandlerWithHashing*>(
          classic_script_3->CacheHandler());
  EXPECT_TRUE(cache_handler_3->HashRequired());

  // Since the third script's text doesn't match the first two, the hash check
  // should reject the existing code cache data and the cache entry should
  // be updated back to a timestamp like it would during a cold run.
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script_3,
                            mojom::blink::V8CacheOptions::kDefault));
  EXPECT_TRUE(
      cache_handler_3->GetCachedMetadata(TagForTimeStamp(cache_handler_3)));
  EXPECT_FALSE(
      cache_handler_3->GetCachedMetadata(TagForCodeCache(cache_handler_3)));

  // A fourth script with matching script text, using the state of
  // the ScriptCachedMetadataHandler from the third script.
  ClassicScript* classic_script_4 = CreateScript(
      CreateResource(scope.GetIsolate(), UTF8Encoding(),
                     cache_handler_3->GetSerializedCachedMetadata()));
  ScriptCachedMetadataHandlerWithHashing* cache_handler_4 =
      static_cast<ScriptCachedMetadataHandlerWithHashing*>(
          classic_script_4->CacheHandler());
  EXPECT_TRUE(cache_handler_4->HashRequired());

  // Running the original script again once again sets the timestamp since the
  // content has changed again.
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script_4,
                            mojom::blink::V8CacheOptions::kDefault));
  EXPECT_TRUE(
      cache_handler_4->GetCachedMetadata(TagForTimeStamp(cache_handler_4)));
  EXPECT_FALSE(
      cache_handler_4->GetCachedMetadata(TagForCodeCache(cache_handler_4)));
}

namespace {

class StubScriptCacheConsumerClient final
    : public GarbageCollected<StubScriptCacheConsumerClient>,
      public ScriptCacheConsumerClient {
 public:
  explicit StubScriptCacheConsumerClient(base::OnceClosure finish_closure)
      : finish_closure_(std::move(finish_closure)) {}

  void NotifyCacheConsumeFinished() override {
    cache_consume_finished_ = true;
    std::move(finish_closure_).Run();
  }

  bool cache_consume_finished() { return cache_consume_finished_; }

 private:
  base::OnceClosure finish_closure_;
  bool cache_consume_finished_ = false;
};

}  // namespace

TEST_F(V8ScriptRunnerTest, successfulOffThreadCodeCache) {
  feature_list_.InitAndEnableFeature(
      blink::features::kConsumeCodeCacheOffThread);

  Vector<uint8_t> cached_data = CreateCachedData();
  EXPECT_GT(cached_data.size(), 0u);

  V8TestingScope scope;

  // Hot run - should start an off-thread code cache consumption.
  ScriptResource* resource =
      CreateResource(scope.GetIsolate(), UTF8Encoding(), cached_data);
  EXPECT_TRUE(V8CodeCache::HasCodeCache(resource->CacheHandler()));
  ClassicScript* classic_script = CreateScript(resource);
  EXPECT_NE(classic_script->CacheConsumer(), nullptr);
  auto* consumer_client = MakeGarbageCollected<StubScriptCacheConsumerClient>(
      run_loop_.QuitClosure());
  classic_script->CacheConsumer()->NotifyClientWaiting(
      consumer_client, classic_script,
      scheduler::GetSingleThreadTaskRunnerForTesting());

  // Wait until the ScriptCacheConsumer completes. ScriptCacheConsumer will
  // post a task for the client to signal that it has completed, which will
  // post a QuitClosure to this RunLoop.
  RunLoopUntilQuit();

  EXPECT_TRUE(consumer_client->cache_consume_finished());

  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script, compile_options, no_cache_reason,
                            produce_cache_options));
}

TEST_F(V8ScriptRunnerTest, discardOffThreadCodeCacheWithDifferentSource) {
  feature_list_.InitAndEnableFeature(
      blink::features::kConsumeCodeCacheOffThread);

  Vector<uint8_t> cached_data = CreateCachedData();
  EXPECT_GT(cached_data.size(), 0u);

  V8TestingScope scope;

  // Hot run - should start an off-thread code cache consumption.
  ScriptResource* resource = CreateResource(scope.GetIsolate(), UTF8Encoding(),
                                            cached_data, DifferentCode());
  ClassicScript* classic_script = CreateScript(resource);
  EXPECT_NE(classic_script->CacheConsumer(), nullptr);
  auto* consumer_client = MakeGarbageCollected<StubScriptCacheConsumerClient>(
      run_loop_.QuitClosure());
  classic_script->CacheConsumer()->NotifyClientWaiting(
      consumer_client, classic_script,
      scheduler::GetSingleThreadTaskRunnerForTesting());

  // Wait until the ScriptCacheConsumer completes. ScriptCacheConsumer will
  // post a task for the client to signal that it has completed, which will
  // post a QuitClosure to this RunLoop.
  RunLoopUntilQuit();

  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_EQ(produce_cache_options,
            V8CodeCache::ProduceCacheOptions::kNoProduceCache);
  EXPECT_EQ(compile_options,
            v8::ScriptCompiler::CompileOptions::kConsumeCodeCache);
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script, compile_options, no_cache_reason,
                            produce_cache_options));
  // Code cache should have been cleared after being rejected.
  EXPECT_FALSE(V8CodeCache::HasCodeCache(resource->CacheHandler()));
}

TEST_F(V8ScriptRunnerTest, discardOffThreadCodeCacheWithBitCorruption) {
  feature_list_.InitAndEnableFeature(
      blink::features::kConsumeCodeCacheOffThread);

  Vector<uint8_t> cached_data = CreateCachedData();
  EXPECT_GT(cached_data.size(), 0u);

  V8TestingScope scope;

  // Corrupt the cached data.
  Vector<uint8_t> corrupted_data = cached_data;
  corrupted_data[sizeof(CachedMetadataHeader) + 2] ^= 0x1;

  // Hot run - should start an off-thread code cache consumption.
  ScriptResource* resource =
      CreateResource(scope.GetIsolate(), UTF8Encoding(), corrupted_data);
  ClassicScript* classic_script = CreateScript(resource);
  EXPECT_NE(classic_script->CacheConsumer(), nullptr);
  auto* consumer_client = MakeGarbageCollected<StubScriptCacheConsumerClient>(
      run_loop_.QuitClosure());
  classic_script->CacheConsumer()->NotifyClientWaiting(
      consumer_client, classic_script,
      scheduler::GetSingleThreadTaskRunnerForTesting());

  // Wait until the ScriptCacheConsumer completes. ScriptCacheConsumer will
  // post a task for the client to signal that it has completed, which will
  // post a QuitClosure to this RunLoop.
  RunLoopUntilQuit();

  v8::ScriptCompiler::CompileOptions compile_options;
  V8CodeCache::ProduceCacheOptions produce_cache_options;
  v8::ScriptCompiler::NoCacheReason no_cache_reason;
  std::tie(compile_options, produce_cache_options, no_cache_reason) =
      V8CodeCache::GetCompileOptions(mojom::blink::V8CacheOptions::kDefault,
                                     *classic_script);
  EXPECT_EQ(produce_cache_options,
            V8CodeCache::ProduceCacheOptions::kNoProduceCache);
  EXPECT_EQ(compile_options,
            v8::ScriptCompiler::CompileOptions::kConsumeCodeCache);
  EXPECT_TRUE(CompileScript(scope.GetIsolate(), scope.GetScriptState(),
                            *classic_script, compile_options, no_cache_reason,
                            produce_cache_options));
  // Code cache should have been cleared after being rejected.
  EXPECT_FALSE(V8CodeCache::HasCodeCache(resource->CacheHandler()));
}

}  // namespace

}  // namespace blink

"""

```