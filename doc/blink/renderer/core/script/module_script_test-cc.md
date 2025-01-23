Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the *functionality* of the test file, its relation to web technologies, logic, common errors, and debugging hints. This means we need to understand *what* the code is testing and *why*.

2. **Identify the Core Subject:** The filename `module_script_test.cc` and the inclusion of `<module_script.h>` immediately tell us the tests are focused on the `ModuleScript` class. The `namespace blink` further confirms this is part of the Blink rendering engine.

3. **Scan for Key Classes and Methods:** Quickly look through the code for important class names and methods being tested. We see:
    * `ModuleScript` (the main subject)
    * `JSModuleScript` (a specific type of `ModuleScript`)
    * `ValueWrapperSyntheticModuleScript` (another type)
    * `ClassicScript` (used for comparison and setup)
    * `CachedMetadataHandler`, `ScriptCachedMetadataHandler`, `ScriptCachedMetadataHandlerWithHashing` (related to caching)
    * `V8CodeCache` (explicitly mentioned and tested)
    * `ModuleRecord::Instantiate` and `RunScriptOnScriptStateAndReturnValue` (related to module execution)
    * `ProduceCache` (the core caching method being tested)
    * Test fixtures like `ModuleScriptTest` and `ModuleTestBase`.

4. **Analyze Individual Test Cases:** Go through each `TEST_F` function. Understand the *setup*, the *actions*, and the *assertions*.
    * **`V8CodeCache`:**  This test iterates through loading a module script multiple times. The assertions check the behavior of `V8CodeCache` in different scenarios (cold load, warm load, hot load) by examining the `CachedMetadataHandler` and the calls to the `MockCachedMetadataSender`. It also tests the interaction between module scripts and classic scripts regarding code caching.
    * **`ValueWrapperSyntheticModuleScript`:** This test seems simpler, focusing on the creation of a `ValueWrapperSyntheticModuleScript`. The assertion checks if a `V8Module` was successfully created.
    * **`V8CodeCacheWithHashChecking`:** This test is similar to the first one but specifically focuses on how content hashing affects V8 code caching. It deliberately changes the source code between loads to simulate cache invalidation.

5. **Connect to Web Technologies:**  Think about how these C++ classes and tests relate to JavaScript, HTML, and CSS.
    * **JavaScript:** `ModuleScript` directly relates to JavaScript modules (`<script type="module">`). The tests involve executing JavaScript code.
    * **HTML:** The loading of module scripts is triggered by `<script type="module">` tags in HTML. The `KURL` used in the tests represent URLs that would appear in HTML.
    * **CSS:** While not directly tested here, CSS can be loaded via modules using `@import` statements, so there's an indirect relationship.

6. **Identify Logical Reasoning and Assumptions:**  Pay attention to the flow of logic within the tests.
    * **Caching Logic:** The tests assume V8's code caching mechanism works in a specific way (timestamping, code cache generation, consumption). The different `nth_load` scenarios represent different states of the cache.
    * **Hashing Logic:** The `V8CodeCacheWithHashChecking` test explicitly reasons about how changing the source code affects the cache based on content hashing.

7. **Consider User/Programming Errors:** Think about common mistakes developers make when working with JavaScript modules and how these tests might catch them.
    * **Cache Invalidation:** Incorrect caching configurations or changes in module content without proper cache busting can lead to errors. The hash checking test directly addresses this.
    * **Module Loading Errors:** While not explicitly demonstrated in *this* test file, other tests might cover syntax errors or import/export issues.

8. **Trace User Actions (Debugging Clues):** Imagine a user interacting with a web page and how that leads to the execution of module scripts.
    * **Initial Page Load:** The browser parses HTML, encounters `<script type="module">`, and initiates the loading process.
    * **Navigation:**  Navigating to a page with module scripts triggers the loading process.
    * **Service Workers:**  Service workers can intercept requests for module scripts, potentially affecting caching.
    * **Developer Tools:** Developers might use the "Network" tab to inspect how module scripts are loaded and cached.

9. **Structure the Answer:** Organize the information logically, starting with a general overview and then diving into specifics. Use headings and bullet points for clarity. Provide concrete examples and code snippets where possible.

10. **Refine and Review:** Read through the answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might not have explicitly linked CSS `@import` to modules, but on review, it's a relevant connection to make.

By following these steps, we can systematically analyze the C++ test file and extract the requested information, creating a comprehensive and helpful explanation.
这个文件 `module_script_test.cc` 是 Chromium Blink 引擎中用于测试 `ModuleScript` 及其相关功能的单元测试文件。它的主要目的是确保 `ModuleScript` 类在各种场景下的行为符合预期。

下面我将详细列举它的功能，并解释它与 JavaScript、HTML、CSS 的关系，以及可能的逻辑推理、用户错误和调试线索。

**1. 功能列举:**

* **测试 `ModuleScript` 的创建和销毁:**  验证 `ModuleScript` 对象能否被正确创建和释放。
* **测试不同类型的 `ModuleScript`:**  测试 `JSModuleScript` (用于 JavaScript 模块) 和 `ValueWrapperSyntheticModuleScript` (用于包装值的合成模块) 的行为。
* **测试 JavaScript 模块的执行:**  验证 JavaScript 模块代码能否被正确地实例化和执行。这涉及到 `ModuleRecord::Instantiate` 和 `RunScriptOnScriptStateAndReturnValue` 等方法。
* **测试 V8 代码缓存 (V8 Code Cache):**  这是该文件测试的重点。它测试了 `ModuleScript` 如何利用 V8 的代码缓存机制来提高性能。具体包括：
    * **首次加载:** 测试首次加载模块脚本时，如何生成时间戳 (timestamp) 用于后续缓存。
    * **二次加载:** 测试基于时间戳，如何生成代码缓存 (code cache)。
    * **后续加载:** 测试如何使用已有的代码缓存，避免重复编译。
    * **缓存失效:** 测试当模块脚本内容发生变化时，如何检测并使缓存失效。
    * **不同脚本类型间的缓存交互:** 测试模块脚本生成的缓存是否会影响经典脚本的执行，以及反之。
* **测试带哈希校验的代码缓存:**  测试 `ScriptCachedMetadataHandlerWithHashing` 类，验证基于内容哈希的代码缓存机制的正确性。这能更可靠地防止缓存污染。
* **使用 Mock 对象进行测试:** 使用 `MockCachedMetadataSender` 模拟缓存元数据的发送，以便更好地控制和断言缓存行为。
* **提供测试辅助函数:**  提供 `CreateJSModuleScript`、`CreateValueWrapperSyntheticModuleScript`、`CreateClassicScript` 等函数来简化测试对象的创建。

**2. 与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:** `ModuleScript` 的核心功能就是处理 JavaScript 模块。
    * **举例:**  `CreateJSModuleScript` 函数模拟了浏览器加载一个 `<script type="module">` 标签时创建 `JSModuleScript` 的过程。测试用例中的 `LargeSourceText` 可以看作是模块脚本的内容。`ModuleRecord::Instantiate` 和 `RunScriptOnScriptStateAndReturnValue` 则模拟了 JavaScript 引擎执行模块代码。
    * **假设输入与输出:**
        * **输入 (JavaScript 模块代码):**  `export function foo() { return 1; }`
        * **输出 (执行结果):**  通过测试代码，可以验证 `foo()` 函数是否被正确定义和调用。
* **HTML:**  HTML 中的 `<script type="module">` 标签触发了模块脚本的加载和解析。
    * **举例:** 当浏览器解析到 `<script type="module" src="my_module.js"></script>` 时，Blink 引擎会创建一个 `ModuleScript` 对象来处理 `my_module.js` 的加载和执行。测试代码中的 `KURL("https://fox.url/script.js")` 模拟了模块脚本的 URL。
    * **用户操作:** 用户在浏览器地址栏输入 URL 或点击链接，浏览器加载 HTML 页面，解析 HTML 时遇到 `<script type="module">`。
* **CSS:**  虽然 `ModuleScript` 主要处理 JavaScript，但 JavaScript 模块可以动态地加载和操作 CSS。
    * **举例:** 一个 JavaScript 模块可以使用 `import` 语句引入 CSS 模块 (虽然不是所有浏览器都原生支持)，或者动态地创建 `<link>` 标签来加载 CSS。`ModuleScript` 负责执行这个 JavaScript 模块，从而间接地影响 CSS 的加载。
    * **假设输入与输出:**
        * **输入 (JavaScript 模块代码):** `import styles from './styles.css'; document.body.classList.add(styles.main);`
        * **输出 (页面效果):** 页面 body 元素的 class 列表中会添加 `styles.main` 对应的 CSS 类，从而改变页面的样式。

**3. 逻辑推理及假设输入与输出:**

测试用例中涉及到大量的逻辑推理，主要是关于 V8 代码缓存的行为。以 `TEST_F(ModuleScriptTest, V8CodeCache)` 为例：

* **假设输入:**  一个较长的 JavaScript 模块脚本 (`LargeSourceText`)。
* **逻辑推理:**
    * **首次加载 (nth_load = 0):** 缓存中没有数据，`ProduceCache` 应该生成时间戳。
    * **二次加载 (nth_load = 1):** 缓存中有时间戳，`ProduceCache` 应该生成代码缓存。
    * **三次加载 (nth_load = 2):** 缓存中既有时间戳又有代码缓存，`ProduceCache` 应该直接使用缓存，不进行额外操作。
    * **与经典脚本交互:** 当模块脚本缓存存在时，运行一个内容相同的经典脚本，由于类型不匹配，应该导致缓存失效。
* **输出 (通过断言验证):**
    * 检查 `cache_handler` 中是否存储了时间戳和代码缓存。
    * 检查 `GetProduceCacheOptions` 返回的枚举值是否符合预期。
    * 检查 `MockCachedMetadataSender` 的 `Send` 方法是否被调用，以及调用次数是否正确。

在 `TEST_F(ModuleScriptTest, V8CodeCacheWithHashChecking)` 中，逻辑推理更进一步，考虑了脚本内容变化对缓存的影响。

**4. 涉及的用户或编程常见的使用错误及举例:**

虽然这个文件是测试代码，但它可以帮助理解在实际开发中可能出现的问题：

* **缓存失效问题:** 用户可能会错误地认为修改了 JavaScript 模块后，浏览器会自动加载最新版本，但如果缓存机制没有正确处理，可能仍然使用旧的缓存版本。`V8CodeCacheWithHashChecking` 测试就模拟了这种情况，并验证了 Blink 如何通过哈希校验来避免这个问题。
    * **用户操作:** 开发者修改了 `my_module.js` 文件，但没有清理浏览器缓存或使用版本号等机制，导致用户加载页面时仍然使用旧版本的模块。
* **代码缓存的意外失效:**  某些操作可能会导致代码缓存失效，例如浏览器配置的更改或缓存策略的调整。测试用例验证了在不同场景下缓存是否按预期工作，帮助开发者理解哪些因素可能影响缓存。
* **混合使用模块脚本和经典脚本时的缓存问题:**  虽然不常见，但如果开发者错误地假设模块脚本的缓存能直接用于执行相同内容的经典脚本，可能会导致意外行为。测试用例 `TEST_F(ModuleScriptTest, V8CodeCache)` 验证了这种假设是不成立的。
    * **编程错误:** 开发者可能在某些场景下使用 `<script>` 标签加载模块脚本的内容，期望能利用模块脚本的缓存。

**5. 用户操作如何一步步的到达这里，作为调试线索:**

假设一个用户遇到了与 JavaScript 模块加载相关的问题，例如模块没有按预期执行，或者性能很差。作为开发者，可以进行以下调试：

1. **用户在浏览器地址栏输入 URL 或点击链接:**  这是访问网页的起点。
2. **浏览器加载 HTML 页面:** 浏览器开始解析 HTML。
3. **浏览器解析到 `<script type="module">` 标签:**  Blink 引擎会创建 `ModuleScript` 对象来处理这个模块。
4. **Blink 引擎发起网络请求获取模块脚本内容:** 如果是外部模块，会进行网络请求。
5. **`ModuleScript` 对象使用 `CachedMetadataHandler` 检查是否有可用的缓存:**  这对应了测试用例中对 `cache_handler->GetCachedMetadata()` 的检查。
6. **如果缓存存在且有效，V8 引擎可能会直接使用缓存的代码:** 这对应了测试用例中 `V8CodeCache::ProduceCacheOptions::kNoProduceCache` 的情况。
7. **如果缓存不存在或失效，V8 引擎会编译模块脚本:**  这对应了测试用例中生成时间戳和代码缓存的过程。
8. **`ModuleRecord::Instantiate` 和 `RunScriptOnScriptStateAndReturnValue` 被调用执行模块代码:**  如果执行出错，可以在这里设置断点进行调试。
9. **如果开启了代码缓存，`ModuleScript::ProduceCache()` 会被调用，将编译结果或时间戳存储到缓存:**  这对应了测试用例中 `module_script->ProduceCache()` 的调用。

**调试线索:**

* **查看浏览器开发者工具的 "Network" 标签:**  检查模块脚本的加载状态，是否使用了缓存 (from disk cache 或 from memory cache)。
* **查看 "Performance" 标签:**  分析脚本的编译和执行时间，判断是否存在性能瓶颈。
* **在 Blink 源码中设置断点:**  如果怀疑是 Blink 引擎的问题，可以在 `ModuleScript::ProduceCache`、`ModuleRecord::Instantiate` 等关键函数设置断点，跟踪代码的执行流程。
* **检查浏览器缓存配置:**  确认浏览器是否启用了缓存，以及缓存策略是否正确。
* **使用 `--enable-blink-features=V8CodeCache` 等命令行参数:**  可以控制 Blink 的特定功能，以便进行更细致的测试和调试。

总而言之，`module_script_test.cc` 是 Blink 引擎中一个非常重要的测试文件，它专注于验证 JavaScript 模块的加载、执行和缓存机制的正确性，这对于保证 Web 应用的性能和稳定性至关重要。通过分析这个文件，我们可以更深入地理解 Blink 引擎的工作原理，并为日常的 Web 开发和调试提供有价值的参考。

### 提示词
```
这是目录为blink/renderer/core/script/module_script_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/script/module_script.h"

#include "base/test/scoped_feature_list.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/script/js_module_script.h"
#include "third_party/blink/renderer/core/script/value_wrapper_synthetic_module_script.h"
#include "third_party/blink/renderer/core/testing/dummy_modulator.h"
#include "third_party/blink/renderer/core/testing/module_test_base.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

using ::testing::_;

namespace blink {

namespace {

class ModuleScriptTestModulator final : public DummyModulator {
 public:
  explicit ModuleScriptTestModulator(ScriptState* script_state)
      : script_state_(script_state) {}
  ~ModuleScriptTestModulator() override = default;

  void Trace(Visitor* visitor) const override {
    visitor->Trace(script_state_);
    DummyModulator::Trace(visitor);
  }

 private:
  ScriptState* GetScriptState() override { return script_state_.Get(); }

  Member<ScriptState> script_state_;
};

class MockCachedMetadataSender : public CachedMetadataSender {
 public:
  MockCachedMetadataSender() = default;

  MOCK_METHOD2(Send, void(CodeCacheHost*, base::span<const uint8_t>));
  bool IsServedFromCacheStorage() override { return false; }
};

ClassicScript* CreateClassicScript(const String& source_text,
                                   CachedMetadataHandler* cache_handler) {
  return ClassicScript::Create(source_text, KURL(), KURL(),
                               ScriptFetchOptions(),
                               ScriptSourceLocationType::kInternal,
                               SanitizeScriptErrors::kSanitize, cache_handler);
}

static const int kScriptRepeatLength = 500;

}  // namespace

class ModuleScriptTest : public ::testing::Test, public ModuleTestBase {
 protected:
  static String LargeSourceText(const char* suffix = nullptr) {
    StringBuilder builder;
    // Returns a sufficiently long script that is eligible for V8 code cache.
    builder.Append(String("window.foo = "));
    for (int i = 0; i < kScriptRepeatLength; ++i) {
      builder.Append(String("1 + "));
    }
    builder.Append(String("0;"));
    if (suffix)
      builder.Append(String(suffix));
    return builder.ToString();
  }

  static JSModuleScript* CreateJSModuleScript(
      Modulator* modulator,
      const String& source_text,
      CachedMetadataHandler* cache_handler) {
    ModuleScriptCreationParams params(
        KURL("https://fox.url/script.js"), KURL("https://fox.url/"),
        ScriptSourceLocationType::kInline, ModuleType::kJavaScript,
        ParkableString(source_text.Impl()->IsolatedCopy()), cache_handler,
        network::mojom::ReferrerPolicy::kDefault);
    return JSModuleScript::Create(params, modulator, ScriptFetchOptions());
  }

  static ValueWrapperSyntheticModuleScript*
  CreateValueWrapperSyntheticModuleScript(Modulator* modulator,
                                          v8::Local<v8::Value> local_value) {
    return ValueWrapperSyntheticModuleScript::CreateWithDefaultExport(
        local_value, modulator, KURL("https://fox.url/script.js"),
        KURL("https://fox.url/"), ScriptFetchOptions());
  }

  // Tests |window.foo| is set correctly, and reset |window.foo| for the next
  // test.
  static void TestFoo(V8TestingScope& scope) {
    v8::Local<v8::Value> value =
        ClassicScript::CreateUnspecifiedScript("window.foo")
            ->RunScriptAndReturnValue(&scope.GetWindow())
            .GetSuccessValueOrEmpty();
    EXPECT_TRUE(value->IsNumber());
    EXPECT_EQ(kScriptRepeatLength,
              value->NumberValue(scope.GetContext()).ToChecked());

    ClassicScript::CreateUnspecifiedScript("window.foo = undefined;")
        ->RunScript(&scope.GetWindow());
  }

  // Accessors for ModuleScript private members.
  static V8CodeCache::ProduceCacheOptions GetProduceCacheOptions(
      const JSModuleScript* module_script) {
    return module_script->produce_cache_data_->GetProduceCacheOptions();
  }

  static bool HandlerCachedMetadataWasDiscarded(
      CachedMetadataHandler* cache_handler) {
    auto* handler = static_cast<ScriptCachedMetadataHandler*>(cache_handler);
    if (!handler)
      return false;
    return handler->cached_metadata_discarded_;
  }

  void SetUp() override { ModuleTestBase::SetUp(); }

  void TearDown() override {
    feature_list_.Reset();
    ModuleTestBase::TearDown();
  }

  test::TaskEnvironment task_environment_;
  base::test::ScopedFeatureList feature_list_;
};

// Test expectations depends on heuristics in V8CodeCache and therefore these
// tests should be updated if necessary when V8CodeCache is modified.
TEST_F(ModuleScriptTest, V8CodeCache) {
  using Checkpoint = testing::StrictMock<testing::MockFunction<void(int)>>;

  V8TestingScope scope;
  Modulator* modulator =
      MakeGarbageCollected<ModuleScriptTestModulator>(scope.GetScriptState());
  Modulator::SetModulator(scope.GetScriptState(), modulator);

  auto sender = std::make_unique<MockCachedMetadataSender>();
  MockCachedMetadataSender* sender_ptr = sender.get();
  CachedMetadataHandler* cache_handler =
      MakeGarbageCollected<ScriptCachedMetadataHandler>(UTF8Encoding(),
                                                        std::move(sender));
  const uint32_t kTimeStampTag = V8CodeCache::TagForTimeStamp(cache_handler);
  const uint32_t kCodeTag = V8CodeCache::TagForCodeCache(cache_handler);

  // Tests the main code path: simply produce and consume code cache.
  for (int nth_load = 0; nth_load < 3; ++nth_load) {
    // Compile a module script.
    JSModuleScript* module_script =
        CreateJSModuleScript(modulator, LargeSourceText(), cache_handler);
    ASSERT_TRUE(module_script);

    // Check that the module script is instantiated/evaluated correctly.
    ASSERT_TRUE(ModuleRecord::Instantiate(scope.GetScriptState(),
                                          module_script->V8Module(),
                                          module_script->SourceUrl())
                    .IsEmpty());
    ASSERT_EQ(module_script
                  ->RunScriptOnScriptStateAndReturnValue(scope.GetScriptState())
                  .GetResultType(),
              ScriptEvaluationResult::ResultType::kSuccess);
    TestFoo(scope);

    Checkpoint checkpoint;
    ::testing::InSequence s;

    switch (nth_load) {
      case 0:
        // For the first time, the cache handler doesn't contain any data, and
        // we'll set timestamp in ProduceCache() below.
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_EQ(V8CodeCache::ProduceCacheOptions::kSetTimeStamp,
                  GetProduceCacheOptions(module_script));
        EXPECT_CALL(*sender_ptr, Send(_, _));
        break;

      case 1:
        // For the second time, as timestamp is already set, we'll produce code
        // cache in ProduceCache() below.
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_EQ(V8CodeCache::ProduceCacheOptions::kProduceCodeCache,
                  GetProduceCacheOptions(module_script));
        EXPECT_CALL(*sender_ptr, Send(_, _));
        break;

      case 2:
        // For the third time, the code cache is already there and we've
        // consumed the code cache and won't do anything in ProduceCache().
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_EQ(V8CodeCache::ProduceCacheOptions::kNoProduceCache,
                  GetProduceCacheOptions(module_script));
        break;
    }

    EXPECT_CALL(checkpoint, Call(3));

    module_script->ProduceCache();

    checkpoint.Call(3);

    switch (nth_load) {
      case 0:
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        break;

      case 1:
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kCodeTag));
        break;

      case 2:
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kCodeTag));
        break;
    }
  }

  // Tests anything wrong doesn't occur when module script code cache is
  // consumed by a classic script.

  Checkpoint checkpoint;
  ::testing::InSequence s;

  // As code cache is mismatched and rejected by V8, the CachedMetadata are
  // cleared and notified to Platform.
  EXPECT_CALL(*sender_ptr, Send(_, _));
  EXPECT_CALL(checkpoint, Call(4));

  CreateClassicScript(LargeSourceText(), cache_handler)
      ->RunScript(&scope.GetWindow());

  checkpoint.Call(4);

  TestFoo(scope);

  // The CachedMetadata are cleared.
  EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
  EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
}

TEST_F(ModuleScriptTest, ValueWrapperSyntheticModuleScript) {
  V8TestingScope scope;
  v8::Local<v8::Value> local_value(v8::Number::New(scope.GetIsolate(), 1234));
  Modulator* modulator =
      MakeGarbageCollected<ModuleScriptTestModulator>(scope.GetScriptState());
  ValueWrapperSyntheticModuleScript* module_script =
      CreateValueWrapperSyntheticModuleScript(modulator, local_value);
  ASSERT_FALSE(module_script->V8Module().IsEmpty());
}

TEST_F(ModuleScriptTest, V8CodeCacheWithHashChecking) {
  using Checkpoint = testing::StrictMock<testing::MockFunction<void(int)>>;

  V8TestingScope scope;
  Modulator* modulator =
      MakeGarbageCollected<ModuleScriptTestModulator>(scope.GetScriptState());
  Modulator::SetModulator(scope.GetScriptState(), modulator);

  auto sender = std::make_unique<MockCachedMetadataSender>();
  MockCachedMetadataSender* sender_ptr = sender.get();
  ScriptCachedMetadataHandlerWithHashing* cache_handler =
      MakeGarbageCollected<ScriptCachedMetadataHandlerWithHashing>(
          UTF8Encoding(), std::move(sender));
  const uint32_t kTimeStampTag = V8CodeCache::TagForTimeStamp(cache_handler);
  const uint32_t kCodeTag = V8CodeCache::TagForCodeCache(cache_handler);

  // Six loads:
  // 0: cold, should produce timestamp
  // 1: source text changed, should produce timestamp
  // 2: warm, should produce code cache
  // 3: source text changed again, should produce timestamp
  // 4: warm, should produce code cache
  // 5: hot, should consume code cache
  for (int nth_load = 0; nth_load < 6; ++nth_load) {
    // Running the module script immediately clears the code cache contents if
    // it detects a hash mismatch. Thus, some checks must occur before it is
    // called.
    switch (nth_load) {
      case 1:
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_CALL(*sender_ptr, Send(_, _));
        break;

      case 3:
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_CALL(*sender_ptr, Send(_, _));
        break;
    }

    // Compile a module script.
    String source =
        LargeSourceText((nth_load == 1 || nth_load == 2) ? " " : nullptr);
    cache_handler->ResetForTesting();
    JSModuleScript* module_script =
        CreateJSModuleScript(modulator, source, cache_handler);
    ASSERT_TRUE(module_script);

    // Check that the module script is instantiated/evaluated correctly.
    ASSERT_TRUE(ModuleRecord::Instantiate(scope.GetScriptState(),
                                          module_script->V8Module(),
                                          module_script->SourceUrl())
                    .IsEmpty());
    ASSERT_EQ(module_script
                  ->RunScriptOnScriptStateAndReturnValue(scope.GetScriptState())
                  .GetResultType(),
              ScriptEvaluationResult::ResultType::kSuccess);
    TestFoo(scope);

    Checkpoint checkpoint;
    ::testing::InSequence s;

    switch (nth_load) {
      case 0:
        // For the first time, the cache handler doesn't contain any data, and
        // we'll set timestamp in ProduceCache() below.
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_EQ(V8CodeCache::ProduceCacheOptions::kSetTimeStamp,
                  GetProduceCacheOptions(module_script));
        EXPECT_CALL(*sender_ptr, Send(_, _));
        break;

      case 1:
        // For the second time, the timestamp has been cleared and will be
        // replaced by another timestamp because the content didn't match.
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_EQ(V8CodeCache::ProduceCacheOptions::kSetTimeStamp,
                  GetProduceCacheOptions(module_script));
        EXPECT_CALL(*sender_ptr, Send(_, _));
        break;

      case 2:
        // For the third time, as timestamp is already set, we'll produce code
        // cache in ProduceCache() below.
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_EQ(V8CodeCache::ProduceCacheOptions::kProduceCodeCache,
                  GetProduceCacheOptions(module_script));
        EXPECT_CALL(*sender_ptr, Send(_, _));
        break;

      case 3:
        // For the fourth time, the code cache has been cleared and will get
        // replaced with a timestamp in ProduceCache() due to a content
        // mismatch.
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_EQ(V8CodeCache::ProduceCacheOptions::kSetTimeStamp,
                  GetProduceCacheOptions(module_script));
        EXPECT_CALL(*sender_ptr, Send(_, _));
        break;

      case 4:
        // For the fifth time, as timestamp is already set, we'll produce code
        // cache in ProduceCache() below.
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_EQ(V8CodeCache::ProduceCacheOptions::kProduceCodeCache,
                  GetProduceCacheOptions(module_script));
        EXPECT_CALL(*sender_ptr, Send(_, _));
        break;

      case 5:
        // For the sixth time, the code cache is already there and we've
        // consumed the code cache and won't do anything in ProduceCache().
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kCodeTag));
        EXPECT_EQ(V8CodeCache::ProduceCacheOptions::kNoProduceCache,
                  GetProduceCacheOptions(module_script));
        break;
    }

    EXPECT_CALL(checkpoint, Call(3));

    module_script->ProduceCache();

    checkpoint.Call(3);

    switch (nth_load) {
      case 0:
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        break;

      case 1:
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        break;

      case 2:
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kCodeTag));
        break;

      case 3:
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kCodeTag));
        break;

      case 4:
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kCodeTag));
        break;

      case 5:
        EXPECT_FALSE(cache_handler->GetCachedMetadata(kTimeStampTag));
        EXPECT_TRUE(cache_handler->GetCachedMetadata(kCodeTag));
        break;
    }
  }
}

}  // namespace blink
```