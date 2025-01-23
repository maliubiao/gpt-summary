Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Identify the Core Purpose:** The file name `module_script_loader_test.cc` strongly suggests this is a test file. The `_test.cc` convention is common in C++ projects. The "module_script_loader" part points to the class being tested: `ModuleScriptLoader`. So, the primary function is to test the functionality of the `ModuleScriptLoader` class.

2. **Scan for Key Test Structures:** Look for standard testing frameworks. The presence of `#include "testing/gtest/include/gtest/gtest.h"` immediately signals that Google Test is being used. This means we should expect to see `TEST_F` macros defining individual test cases.

3. **Analyze Test Case Names:**  Examine the names of the `TEST_F` functions. They usually provide a high-level idea of what's being tested. Examples from the file:
    * `FetchDataURL`:  Likely tests loading modules from `data:` URLs.
    * `FetchDataURLJSONModule`:  Specifically tests loading JSON modules from `data:` URLs.
    * `FetchInvalidURL`: Tests handling of invalid URLs.
    * `FetchURL`: Tests loading modules from regular HTTP(S) URLs.
    * The `_OnWorklet` suffix indicates versions of the tests that run in the context of a Worklet.

4. **Examine the Setup and Teardown:**  The `SetUp` and `TearDown` methods are crucial for understanding the test environment.
    * `SetUp`:  Calls `PageTestBase::SetUp`. This hints that the tests run within a simulated browser page environment.
    * `TearDown`:  Deals with `global_scope_`, which relates to Worklets. This confirms that the tests cover both document and Worklet contexts.

5. **Look for Helper Classes and Methods:** Identify custom classes used for testing. In this case, `TestModuleScriptLoaderClient` is a mock client to observe the behavior of `ModuleScriptLoader`. `ModuleScriptLoaderTestModulator` appears to be a mock modulator used for dependency injection. The helper methods like `TestFetchDataURL`, `TestFetchInvalidURL`, etc., encapsulate common test setup and execution.

6. **Focus on the `ModuleScriptLoader::Fetch` Call:** This is the central point of interaction with the class under test. Note the arguments:
    * `ModuleScriptFetchRequest`: Represents the request to fetch a module.
    * `fetcher_`:  A `ResourceFetcher` (likely mocked or faked).
    * `ModuleGraphLevel`:  Indicates the context of the fetch.
    * `GetModulator()`: Provides the mock modulator.
    * `custom_fetch_type`: Distinguishes between document and Worklet module fetches.
    * `registry`:  A `ModuleScriptLoaderRegistry`.
    * `client`: The mock client.

7. **Trace Data Flow (Mentally):**  Imagine the steps involved when `ModuleScriptLoader::Fetch` is called:
    * A request is created.
    * The `ResourceFetcher` attempts to fetch the resource (potentially using mocked network responses).
    * The `Modulator` likely resolves module specifiers.
    * The `ModuleScriptLoader` processes the fetched content.
    * The `ModuleScriptLoaderClient` is notified of the result.

8. **Connect to Web Concepts:** Now, relate the code to JavaScript, HTML, and CSS:
    * **JavaScript:** The core subject. Module loading is a fundamental JavaScript feature. The tests specifically deal with JavaScript modules (`ModuleType::kJavaScript`).
    * **HTML:**  Module scripts are often loaded via `<script type="module">` tags in HTML. While not directly tested in *this* file, the underlying loader functionality is crucial for that HTML feature.
    * **CSS:** While less direct, CSS can be imported within JavaScript modules using `@import`. This file likely doesn't test *CSS* loading itself, but the module loader needs to handle such imports correctly, potentially triggering further resource fetches.

9. **Infer Logic and Scenarios:** Based on the test names and the structure, deduce the logic being tested:
    * **Success Cases:** Loading valid JavaScript and JSON modules from various sources (`data:` URLs, regular URLs).
    * **Error Handling:**  Dealing with invalid URLs, invalid module specifiers, and invalid JSON.
    * **Worklet Context:** Ensuring the loader works correctly within the isolated environment of a Worklet.
    * **Caching (Implied):** The "Try to fetch the same URL again..." comments in the Worklet tests suggest testing the `WorkletModuleResponsesMap` for caching.

10. **Consider User Errors and Debugging:**  Think about how developers might encounter issues related to module loading:
    * Incorrect module specifiers (leading to `InvalidSpecifier` tests).
    * Network errors or invalid URLs (leading to `FetchInvalidURL` tests).
    * Syntax errors in modules (implicitly tested by checking for parse errors).
    * Issues specific to Worklets (hence the `_OnWorklet` tests).

11. **Relate to User Actions:** Imagine the user actions that would trigger module loading:
    * Opening an HTML page containing `<script type="module">`.
    * A JavaScript module using `import` statements.
    * A Service Worker or Shared Worker loading module scripts.
    * A Worklet (like an Animation Worklet or Paint Worklet) loading its module.

12. **Construct Explanations and Examples:** Finally, organize the findings into a clear and structured explanation, providing concrete examples of JavaScript code, potential errors, and the user actions leading to the tested code. Use the identified test cases to support the explanations.

This systematic approach allows you to dissect a complex test file, understand its purpose, and connect it to broader web development concepts. The key is to start with the high-level purpose and gradually zoom in on the details, always trying to relate the code back to the user experience and common development scenarios.
这个文件 `module_script_loader_test.cc` 是 Chromium Blink 引擎中 `ModuleScriptLoader` 类的单元测试文件。它的主要功能是 **验证 `ModuleScriptLoader` 类的各种功能是否正常工作**。

以下是该文件的详细功能分解，并关联到 JavaScript, HTML, CSS 的关系，以及逻辑推理、常见错误和调试线索：

**1. 功能概述:**

* **测试模块脚本的加载:**  `ModuleScriptLoader` 的核心职责是从不同的来源（例如，通过网络、`data:` URL）加载 ECMAScript 模块。这个测试文件涵盖了各种加载场景。
* **测试不同模块类型的加载:**  不仅测试 JavaScript 模块 (`ModuleType::kJavaScript`)，还测试 JSON 模块 (`ModuleType::kJSON`).
* **测试在不同上下文中的加载:**  区分了在主文档上下文和在 Worklet 上下文中的模块加载。Worklet 是 Web Worker 的一种，用于执行轻量级的任务。
* **测试加载成功和失败的情况:**  包括了加载有效模块和无效模块（例如，包含语法错误、无效的模块标识符）的场景。
* **测试异步加载:**  模块加载通常是异步的，测试确保异步完成的机制正常工作。
* **使用 Mock 对象进行隔离测试:**  使用了 Mock 对象（例如 `MockFetchContext`, `TestLoaderFactory`) 来模拟网络请求和其他依赖项的行为，以便更专注于测试 `ModuleScriptLoader` 的逻辑。
* **测试缓存机制 (针对 Worklet):**  在 Worklet 上下文中，测试了 `WorkletModuleResponsesMap` 是否能正确缓存模块，避免重复加载。

**2. 与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  这是测试的核心。`ModuleScriptLoader` 负责加载和处理 JavaScript 模块，这是现代 JavaScript 开发的关键特性。测试用例验证了 `import` 和 `export` 等模块语法的支持，以及模块的解析和执行。
    * **例子:** 测试用例 `FetchDataURL` 加载一个简单的 JavaScript 模块，该模块导出一个名为 'grapes' 的字符串。这模拟了 HTML 中 `<script type="module">` 标签加载外部 JavaScript 模块的行为。
* **HTML:** 虽然这个文件本身不直接操作 HTML，但 `ModuleScriptLoader` 是浏览器加载 HTML 中 `<script type="module">` 标签所指向的模块的关键组件。测试保证了当 HTML 中引用模块时，Blink 引擎能正确加载和处理它们。
    * **例子:** 当用户在 HTML 中写下 `<script type="module" src="my-module.js"></script>` 时，Blink 会使用 `ModuleScriptLoader` 来加载 `my-module.js` 的内容。
* **CSS:**  虽然此文件主要关注 JavaScript 模块，但 JavaScript 模块可以导入 CSS 模块 (通过提案中的 CSS Modules)。`ModuleScriptLoader` 的机制也可能间接涉及到 CSS 模块的加载（虽然这个测试文件没有直接测试 CSS 模块加载）。
    * **例子:**  一个 JavaScript 模块可能包含 `import styles from './styles.css';` 这样的语句。`ModuleScriptLoader` 需要能够处理这种导入，并可能委托给其他组件来加载 CSS 文件。

**3. 逻辑推理 (假设输入与输出):**

* **假设输入 (针对 `FetchDataURL`):**
    * `ModuleScriptFetchRequest`:  包含一个 `data:` URL，例如 `"data:text/javascript,export default 'grapes';"`, 和 `ModuleType::kJavaScript`。
    * `fetcher_`: 一个模拟的 `ResourceFetcher`，能处理 `data:` URL 请求。
    * `GetModulator()`: 提供模块标识符解析和 `ModuleScriptFetcher` 创建的能力。
    * `client`: `TestModuleScriptLoaderClient`，用于接收加载完成的通知。
* **预期输出 (针对 `FetchDataURL`):**
    * `client->WasNotifyFinished()` 返回 `true`，表示加载已完成。
    * `client->GetModuleScript()` 返回一个非空的 `ModuleScript` 对象。
    * `client->GetModuleScript()->HasEmptyRecord()` 返回 `false`，表示模块已成功解析。
    * `client->GetModuleScript()->HasParseError()` 返回 `false`，表示没有解析错误。

* **假设输入 (针对 `FetchInvalidURL`):**
    * `ModuleScriptFetchRequest`: 包含一个无效的 URL。
* **预期输出 (针对 `FetchInvalidURL`):**
    * `client->WasNotifyFinished()` 返回 `true`。
    * `client->GetModuleScript()` 返回 `nullptr` 或一个表示加载失败的特殊状态。

**4. 涉及用户或编程常见的使用错误:**

* **无效的模块标识符 (Specifier):**  开发者在 `import` 语句中使用了无法解析的路径或名称。
    * **例子 (对应 `InvalidSpecifier` 测试):**  JavaScript 代码 `import 'invalid';`  中的 `'invalid'` 是一个无法解析的模块标识符。`ModuleScriptLoader` 需要能够检测并报告这类错误。
* **网络错误或无效的 URL:**  `<script type="module" src="...">` 中的 `src` 指向一个不存在的资源或一个无效的 URL。
    * **例子 (对应 `FetchInvalidURL` 测试):**  尝试加载一个空 URL，模拟网络请求失败的情况。
* **模块语法错误:**  JavaScript 模块中存在语法错误，导致解析失败。
    * **例子:**  一个模块包含 `export defalt` (typo) 而不是 `export default`。`ModuleScriptLoader` 应该能够检测到这些错误。
* **JSON 模块内容错误:**  当加载 JSON 模块时，如果内容不是有效的 JSON 格式，会导致解析错误。
    * **例子 (对应 `FetchDataURLInvalidJSONModule` 测试):**  加载 `data:application/json,{{{`，这是一个无效的 JSON 字符串。
* **在 Worklet 中重复添加相同模块的错误 (可能隐含在测试中):**  虽然测试覆盖了 Worklet 的缓存机制，但错误地多次尝试将相同的模块添加到 Worklet 中可能会导致问题。

**5. 用户操作如何一步步的到达这里 (作为调试线索):**

假设用户在浏览器中访问了一个包含模块脚本的网页：

1. **用户访问网页:** 用户在浏览器地址栏输入 URL 或点击一个链接。
2. **HTML 解析:** 浏览器开始解析 HTML 文档。
3. **遇到 `<script type="module">` 标签:** 解析器遇到一个带有 `type="module"` 的 `<script>` 标签。
4. **创建 ModuleScriptLoader:** Blink 引擎会创建一个 `ModuleScriptLoader` 对象（或使用现有的）。
5. **创建 ModuleScriptFetchRequest:** 根据 `<script>` 标签的 `src` 属性（或内联脚本的内容），创建一个 `ModuleScriptFetchRequest` 对象，包含要加载的模块的 URL 和类型。
6. **调用 `ModuleScriptLoader::Fetch`:**  Blink 引擎调用 `ModuleScriptLoader::Fetch` 方法，传入 `ModuleScriptFetchRequest` 和其他必要的上下文信息（例如，`ResourceFetcher`, `Modulator`, `client`）。
7. **网络请求 (如果需要):** 如果是外部模块，`ResourceFetcher` 会发起网络请求去获取模块内容。Mock 测试中会模拟这个过程。
8. **内容接收和处理:**  `ModuleScriptLoader` 接收到模块内容。
9. **模块解析:**  `ModuleScriptLoader` 调用相应的解析器（例如，JavaScript 或 JSON 解析器）来解析模块内容。
10. **通知 Client:**  加载完成后，`ModuleScriptLoader` 通过 `ModuleScriptLoaderClient` 接口通知相关的组件（例如，文档的脚本控制器）。
11. **模块执行:**  如果模块加载成功且没有错误，浏览器会执行模块中的代码。

**在 Worklet 上下文中:**

1. **JavaScript 代码创建 Worklet:**  网页中的 JavaScript 代码使用 `new Worklet(...)` 或类似 API 创建一个 Worklet 实例。
2. **Worklet 加载模块:**  Worklet 的脚本控制器会使用 `ModuleScriptLoader` 来加载 Worklet 需要执行的模块。这可以通过 `worklet.addModule(...)` 方法触发。
3. **后续步骤类似:**  创建 `ModuleScriptFetchRequest`，调用 `ModuleScriptLoader::Fetch`，网络请求（如果需要），内容处理，模块解析，最终通知 Worklet 的脚本控制器。

**调试线索:**

当模块加载出现问题时，开发者可以关注以下几点：

* **浏览器开发者工具的 "Network" 标签:**  检查模块的 URL 是否正确，请求是否成功，响应状态码是否为 200 OK。
* **浏览器开发者工具的 "Console" 标签:**  查看是否有 JavaScript 错误，例如 "Uncaught SyntaxError: Cannot use import statement outside a module"。
* **检查 `<script type="module">` 标签的 `src` 属性是否正确。**
* **检查模块文件的 MIME 类型是否正确 (对于网络加载)。**
* **如果是在 Worklet 中加载模块，检查 Worklet 的创建和 `addModule` 调用是否正确。**
* **使用断点调试 Blink 引擎的代码:**  如果开发者有 Blink 引擎的开发环境，可以在 `ModuleScriptLoader::Fetch` 或相关的代码中设置断点，逐步跟踪模块加载的过程，查看每一步的状态和数据。

总而言之，`module_script_loader_test.cc` 是一个至关重要的测试文件，它确保了 Chromium Blink 引擎能够可靠地加载和处理 JavaScript 和 JSON 模块，这是现代 Web 开发的基础。通过各种测试用例，它覆盖了模块加载的不同场景，帮助开发者避免常见的错误，并为调试模块加载问题提供了重要的线索。

### 提示词
```
这是目录为blink/renderer/core/loader/modulescript/module_script_loader_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/modulescript/module_script_loader.h"

#include "base/test/scoped_feature_list.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/modulescript/document_module_script_fetcher.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_fetch_request.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_loader_client.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_loader_registry.h"
#include "third_party/blink/renderer/core/loader/modulescript/worklet_module_script_fetcher.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/script/module_script.h"
#include "third_party/blink/renderer/core/script/script.h"
#include "third_party/blink/renderer/core/testing/dummy_modulator.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/worker_thread_test_helper.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope_test_helper.h"
#include "third_party/blink/renderer/core/workers/worklet_module_responses_map.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object_snapshot.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/testing/fetch_testing_platform_support.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_fetch_context.h"
#include "third_party/blink/renderer/platform/loader/testing/test_loader_factory.h"
#include "third_party/blink/renderer/platform/loader/testing/test_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/testing/mock_context_lifecycle_notifier.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {

namespace {

class TestModuleScriptLoaderClient final
    : public GarbageCollected<TestModuleScriptLoaderClient>,
      public ModuleScriptLoaderClient {
 public:
  TestModuleScriptLoaderClient() = default;
  ~TestModuleScriptLoaderClient() override = default;

  void Trace(Visitor* visitor) const override {
    visitor->Trace(module_script_);
  }

  void NotifyNewSingleModuleFinished(ModuleScript* module_script) override {
    was_notify_finished_ = true;
    module_script_ = module_script;
  }

  bool WasNotifyFinished() const { return was_notify_finished_; }
  ModuleScript* GetModuleScript() { return module_script_.Get(); }

 private:
  bool was_notify_finished_ = false;
  Member<ModuleScript> module_script_;
};

class ModuleScriptLoaderTestModulator final : public DummyModulator {
 public:
  explicit ModuleScriptLoaderTestModulator(ScriptState* script_state)
      : script_state_(script_state) {}

  ~ModuleScriptLoaderTestModulator() override = default;

  KURL ResolveModuleSpecifier(const String& module_request,
                              const KURL& base_url,
                              String* failure_reason) final {
    return KURL(base_url, module_request);
  }

  ScriptState* GetScriptState() override { return script_state_.Get(); }

  ModuleScriptFetcher* CreateModuleScriptFetcher(
      ModuleScriptCustomFetchType custom_fetch_type,
      base::PassKey<ModuleScriptLoader> pass_key) override {
    auto* execution_context = ExecutionContext::From(script_state_);
    if (auto* scope = DynamicTo<WorkletGlobalScope>(execution_context)) {
      EXPECT_EQ(ModuleScriptCustomFetchType::kWorkletAddModule,
                custom_fetch_type);
      return MakeGarbageCollected<WorkletModuleScriptFetcher>(scope, pass_key);
    }
    EXPECT_EQ(ModuleScriptCustomFetchType::kNone, custom_fetch_type);
    return MakeGarbageCollected<DocumentModuleScriptFetcher>(execution_context,
                                                             pass_key);
  }

  void Trace(Visitor*) const override;

 private:
  Member<ScriptState> script_state_;
};

void ModuleScriptLoaderTestModulator::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  DummyModulator::Trace(visitor);
}

}  // namespace

class ModuleScriptLoaderTest : public PageTestBase {
 public:
  ModuleScriptLoaderTest();
  ModuleScriptLoaderTest(const ModuleScriptLoaderTest&) = delete;
  ModuleScriptLoaderTest& operator=(const ModuleScriptLoaderTest&) = delete;
  void SetUp() override;
  void TearDown() override;

  void InitializeForDocument();
  void InitializeForWorklet();

  void TestFetchDataURL(ModuleScriptCustomFetchType,
                        TestModuleScriptLoaderClient*);
  void TestInvalidSpecifier(ModuleScriptCustomFetchType,
                            TestModuleScriptLoaderClient*);
  void TestFetchInvalidURL(ModuleScriptCustomFetchType,
                           TestModuleScriptLoaderClient*);
  void TestFetchURL(ModuleScriptCustomFetchType, TestModuleScriptLoaderClient*);
  void TestFetchDataURLJSONModule(ModuleScriptCustomFetchType custom_fetch_type,
                                  TestModuleScriptLoaderClient* client);
  void TestFetchDataURLInvalidJSONModule(
      ModuleScriptCustomFetchType custom_fetch_type,
      TestModuleScriptLoaderClient* client);

  ModuleScriptLoaderTestModulator* GetModulator() { return modulator_.Get(); }

  void RunUntilIdle() {
    static_cast<scheduler::FakeTaskRunner*>(fetcher_->GetTaskRunner().get())
        ->RunUntilIdle();
  }

  const base::TickClock* GetTickClock() override {
    return PageTestBase::GetTickClock();
  }

 protected:
  const KURL url_;
  const scoped_refptr<const SecurityOrigin> security_origin_;

  Persistent<ResourceFetcher> fetcher_;

  ScopedTestingPlatformSupport<FetchTestingPlatformSupport> platform_;
  std::unique_ptr<MockWorkerReportingProxy> reporting_proxy_;
  Persistent<ModuleScriptLoaderTestModulator> modulator_;
  Persistent<WorkletGlobalScope> global_scope_;
};

void ModuleScriptLoaderTest::SetUp() {
  PageTestBase::SetUp(gfx::Size(500, 500));
}

void ModuleScriptLoaderTest::TearDown() {
  if (global_scope_) {
    global_scope_->Dispose();
    global_scope_->NotifyContextDestroyed();
  }
}

ModuleScriptLoaderTest::ModuleScriptLoaderTest()
    : PageTestBase(base::test::TaskEnvironment::TimeSource::MOCK_TIME),
      url_("https://example.test"),
      security_origin_(SecurityOrigin::Create(url_)) {
}

void ModuleScriptLoaderTest::InitializeForDocument() {
  auto* fetch_context = MakeGarbageCollected<MockFetchContext>();
  auto* properties =
      MakeGarbageCollected<TestResourceFetcherProperties>(security_origin_);
  fetcher_ = MakeGarbageCollected<ResourceFetcher>(
      ResourceFetcherInit(properties->MakeDetachable(), fetch_context,
                          base::MakeRefCounted<scheduler::FakeTaskRunner>(),
                          base::MakeRefCounted<scheduler::FakeTaskRunner>(),
                          MakeGarbageCollected<TestLoaderFactory>(
                              platform_->GetURLLoaderMockFactory()),
                          MakeGarbageCollected<MockContextLifecycleNotifier>(),
                          nullptr /* back_forward_cache_loader_helper */));
  modulator_ = MakeGarbageCollected<ModuleScriptLoaderTestModulator>(
      ToScriptStateForMainWorld(&GetFrame()));
}

void ModuleScriptLoaderTest::InitializeForWorklet() {
  auto* fetch_context = MakeGarbageCollected<MockFetchContext>();
  auto* properties =
      MakeGarbageCollected<TestResourceFetcherProperties>(security_origin_);
  fetcher_ = MakeGarbageCollected<ResourceFetcher>(
      ResourceFetcherInit(properties->MakeDetachable(), fetch_context,
                          base::MakeRefCounted<scheduler::FakeTaskRunner>(),
                          base::MakeRefCounted<scheduler::FakeTaskRunner>(),
                          MakeGarbageCollected<TestLoaderFactory>(
                              platform_->GetURLLoaderMockFactory()),
                          MakeGarbageCollected<MockContextLifecycleNotifier>(),
                          nullptr /* back_forward_cache_loader_helper */));
  reporting_proxy_ = std::make_unique<MockWorkerReportingProxy>();
  auto creation_params = std::make_unique<GlobalScopeCreationParams>(
      url_, mojom::blink::ScriptType::kModule, "GlobalScopeName", "UserAgent",
      UserAgentMetadata(), nullptr /* web_worker_fetch_context */,
      Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
      Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
      network::mojom::ReferrerPolicy::kDefault, security_origin_.get(),
      true /* is_secure_context */, HttpsState::kModern,
      nullptr /* worker_clients */, nullptr /* content_settings_client */,
      nullptr /* inherited_trial_features */, base::UnguessableToken::Create(),
      nullptr /* worker_settings */, mojom::blink::V8CacheOptions::kDefault,
      MakeGarbageCollected<WorkletModuleResponsesMap>(),
      mojo::NullRemote() /* browser_interface_broker */,
      mojo::NullRemote() /* code_cache_host_interface */,
      mojo::NullRemote() /* blob_url_store */, BeginFrameProviderParams(),
      nullptr /* parent_permissions_policy */,
      base::UnguessableToken::Create() /* agent_cluster_id */);
  creation_params->parent_context_token = GetFrame().GetLocalFrameToken();
  global_scope_ = MakeGarbageCollected<FakeWorkletGlobalScope>(
      std::move(creation_params), *reporting_proxy_, &GetFrame());
  global_scope_->ScriptController()->Initialize(NullURL());
  modulator_ = MakeGarbageCollected<ModuleScriptLoaderTestModulator>(
      global_scope_->ScriptController()->GetScriptState());
}
// TODO(nhiroki): Add tests for workers.

void ModuleScriptLoaderTest::TestFetchDataURL(
    ModuleScriptCustomFetchType custom_fetch_type,
    TestModuleScriptLoaderClient* client) {
  auto* registry = MakeGarbageCollected<ModuleScriptLoaderRegistry>();
  KURL url("data:text/javascript,export default 'grapes';");
  ModuleScriptLoader::Fetch(
      ModuleScriptFetchRequest::CreateForTest(url, ModuleType::kJavaScript),
      fetcher_, ModuleGraphLevel::kTopLevelModuleFetch, GetModulator(),
      custom_fetch_type, registry, client);
}

void ModuleScriptLoaderTest::TestFetchDataURLJSONModule(
    ModuleScriptCustomFetchType custom_fetch_type,
    TestModuleScriptLoaderClient* client) {
  auto* registry = MakeGarbageCollected<ModuleScriptLoaderRegistry>();
  KURL url(
      "data:application/"
      "json,{\"1\":{\"name\":\"MIKE\",\"surname\":\"TAYLOR\"},\"2\":{\"name\":"
      "\"TOM\",\"surname\":\"JERRY\"}}");
  ModuleScriptLoader::Fetch(
      ModuleScriptFetchRequest::CreateForTest(url, ModuleType::kJSON), fetcher_,
      ModuleGraphLevel::kTopLevelModuleFetch, GetModulator(), custom_fetch_type,
      registry, client);
}

void ModuleScriptLoaderTest::TestFetchDataURLInvalidJSONModule(
    ModuleScriptCustomFetchType custom_fetch_type,
    TestModuleScriptLoaderClient* client) {
  auto* registry = MakeGarbageCollected<ModuleScriptLoaderRegistry>();
  KURL url(
      "data:application/"
      "json,{{{");
  ModuleScriptLoader::Fetch(
      ModuleScriptFetchRequest::CreateForTest(url, ModuleType::kJSON), fetcher_,
      ModuleGraphLevel::kTopLevelModuleFetch, GetModulator(), custom_fetch_type,
      registry, client);
}

TEST_F(ModuleScriptLoaderTest, FetchDataURL) {
  InitializeForDocument();
  TestModuleScriptLoaderClient* client =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchDataURL(ModuleScriptCustomFetchType::kNone, client);

  // TODO(leszeks): This should finish synchronously, but currently due
  // to the script resource/script streamer interaction, it does not.
  RunUntilIdle();
  EXPECT_TRUE(client->WasNotifyFinished());
  ASSERT_TRUE(client->GetModuleScript());
  EXPECT_FALSE(client->GetModuleScript()->HasEmptyRecord());
  EXPECT_FALSE(client->GetModuleScript()->HasParseError());
}

TEST_F(ModuleScriptLoaderTest, FetchDataURLJSONModule) {
  InitializeForDocument();
  TestModuleScriptLoaderClient* client =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchDataURLJSONModule(ModuleScriptCustomFetchType::kNone, client);

  // TODO(leszeks): This should finish synchronously, but currently due
  // to the script resource/script streamer interaction, it does not.
  RunUntilIdle();
  EXPECT_TRUE(client->WasNotifyFinished());
  ASSERT_TRUE(client->GetModuleScript());
  EXPECT_FALSE(client->GetModuleScript()->HasEmptyRecord());
  EXPECT_FALSE(client->GetModuleScript()->HasParseError());
}

TEST_F(ModuleScriptLoaderTest, FetchDataURLInvalidJSONModule) {
  InitializeForDocument();
  TestModuleScriptLoaderClient* client =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchDataURLInvalidJSONModule(ModuleScriptCustomFetchType::kNone, client);

  // TODO(leszeks): This should finish synchronously, but currently due
  // to the script resource/script streamer interaction, it does not.
  RunUntilIdle();
  EXPECT_TRUE(client->WasNotifyFinished());
  ASSERT_TRUE(client->GetModuleScript());
  EXPECT_TRUE(client->GetModuleScript()->HasEmptyRecord());
  EXPECT_TRUE(client->GetModuleScript()->HasParseError());
}

TEST_F(ModuleScriptLoaderTest, FetchDataURL_OnWorklet) {
  InitializeForWorklet();
  TestModuleScriptLoaderClient* client1 =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchDataURL(ModuleScriptCustomFetchType::kWorkletAddModule, client1);

  EXPECT_FALSE(client1->WasNotifyFinished())
      << "ModuleScriptLoader should finish asynchronously.";
  RunUntilIdle();

  EXPECT_TRUE(client1->WasNotifyFinished());
  ASSERT_TRUE(client1->GetModuleScript());
  EXPECT_FALSE(client1->GetModuleScript()->HasEmptyRecord());
  EXPECT_FALSE(client1->GetModuleScript()->HasParseError());

  // Try to fetch the same URL again in order to verify the case where
  // WorkletModuleResponsesMap serves a cache.
  TestModuleScriptLoaderClient* client2 =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchDataURL(ModuleScriptCustomFetchType::kWorkletAddModule, client2);

  EXPECT_FALSE(client2->WasNotifyFinished())
      << "ModuleScriptLoader should finish asynchronously.";
  RunUntilIdle();

  EXPECT_TRUE(client2->WasNotifyFinished());
  ASSERT_TRUE(client2->GetModuleScript());
  EXPECT_FALSE(client2->GetModuleScript()->HasEmptyRecord());
  EXPECT_FALSE(client2->GetModuleScript()->HasParseError());
}

TEST_F(ModuleScriptLoaderTest, FetchDataURLJSONModule_OnWorklet) {
  InitializeForWorklet();
  TestModuleScriptLoaderClient* client1 =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchDataURLJSONModule(ModuleScriptCustomFetchType::kWorkletAddModule,
                             client1);

  EXPECT_FALSE(client1->WasNotifyFinished())
      << "ModuleScriptLoader should finish asynchronously.";
  RunUntilIdle();

  EXPECT_TRUE(client1->WasNotifyFinished());
  ASSERT_TRUE(client1->GetModuleScript());
  EXPECT_FALSE(client1->GetModuleScript()->HasEmptyRecord());
  EXPECT_FALSE(client1->GetModuleScript()->HasParseError());

  // Try to fetch the same URL again in order to verify the case where
  // WorkletModuleResponsesMap serves a cache.
  TestModuleScriptLoaderClient* client2 =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchDataURLJSONModule(ModuleScriptCustomFetchType::kWorkletAddModule,
                             client2);

  EXPECT_FALSE(client2->WasNotifyFinished())
      << "ModuleScriptLoader should finish asynchronously.";
  RunUntilIdle();

  EXPECT_TRUE(client2->WasNotifyFinished());
  ASSERT_TRUE(client2->GetModuleScript());
  EXPECT_FALSE(client2->GetModuleScript()->HasEmptyRecord());
  EXPECT_FALSE(client2->GetModuleScript()->HasParseError());
}

TEST_F(ModuleScriptLoaderTest, FetchDataURLInvalidJSONModule_OnWorklet) {
  InitializeForWorklet();
  TestModuleScriptLoaderClient* client1 =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchDataURLInvalidJSONModule(
      ModuleScriptCustomFetchType::kWorkletAddModule, client1);

  EXPECT_FALSE(client1->WasNotifyFinished())
      << "ModuleScriptLoader should finish asynchronously.";
  RunUntilIdle();

  EXPECT_TRUE(client1->WasNotifyFinished());
  ASSERT_TRUE(client1->GetModuleScript());
  EXPECT_TRUE(client1->GetModuleScript()->HasEmptyRecord());
  EXPECT_TRUE(client1->GetModuleScript()->HasParseError());

  // Try to fetch the same URL again in order to verify the case where
  // WorkletModuleResponsesMap serves a cache.
  TestModuleScriptLoaderClient* client2 =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchDataURLInvalidJSONModule(
      ModuleScriptCustomFetchType::kWorkletAddModule, client2);

  EXPECT_FALSE(client2->WasNotifyFinished())
      << "ModuleScriptLoader should finish asynchronously.";
  RunUntilIdle();

  EXPECT_TRUE(client2->WasNotifyFinished());
  ASSERT_TRUE(client2->GetModuleScript());
  EXPECT_TRUE(client2->GetModuleScript()->HasEmptyRecord());
  EXPECT_TRUE(client2->GetModuleScript()->HasParseError());
}

void ModuleScriptLoaderTest::TestInvalidSpecifier(
    ModuleScriptCustomFetchType custom_fetch_type,
    TestModuleScriptLoaderClient* client) {
  auto* registry = MakeGarbageCollected<ModuleScriptLoaderRegistry>();
  KURL url("data:text/javascript,import 'invalid';export default 'grapes';");
  ModuleScriptLoader::Fetch(
      ModuleScriptFetchRequest::CreateForTest(url, ModuleType::kJavaScript),
      fetcher_, ModuleGraphLevel::kTopLevelModuleFetch, GetModulator(),
      custom_fetch_type, registry, client);
}

TEST_F(ModuleScriptLoaderTest, InvalidSpecifier) {
  InitializeForDocument();
  TestModuleScriptLoaderClient* client =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestInvalidSpecifier(ModuleScriptCustomFetchType::kNone, client);

  // TODO(leszeks): This should finish synchronously, but currently due
  // to the script resource/script streamer interaction, it does not.
  RunUntilIdle();
  EXPECT_TRUE(client->WasNotifyFinished());

  ASSERT_TRUE(client->GetModuleScript());
  EXPECT_TRUE(client->GetModuleScript()->HasEmptyRecord());
  EXPECT_TRUE(client->GetModuleScript()->HasParseError());
}

TEST_F(ModuleScriptLoaderTest, InvalidSpecifier_OnWorklet) {
  InitializeForWorklet();
  TestModuleScriptLoaderClient* client =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestInvalidSpecifier(ModuleScriptCustomFetchType::kWorkletAddModule, client);

  EXPECT_FALSE(client->WasNotifyFinished())
      << "ModuleScriptLoader should finish asynchronously.";
  RunUntilIdle();

  EXPECT_TRUE(client->WasNotifyFinished());
  ASSERT_TRUE(client->GetModuleScript());
  EXPECT_TRUE(client->GetModuleScript()->HasEmptyRecord());
  EXPECT_TRUE(client->GetModuleScript()->HasParseError());
}

void ModuleScriptLoaderTest::TestFetchInvalidURL(
    ModuleScriptCustomFetchType custom_fetch_type,
    TestModuleScriptLoaderClient* client) {
  auto* registry = MakeGarbageCollected<ModuleScriptLoaderRegistry>();
  KURL url;
  EXPECT_FALSE(url.IsValid());
  ModuleScriptLoader::Fetch(
      ModuleScriptFetchRequest::CreateForTest(url, ModuleType::kJavaScript),
      fetcher_, ModuleGraphLevel::kTopLevelModuleFetch, GetModulator(),
      custom_fetch_type, registry, client);
}

TEST_F(ModuleScriptLoaderTest, FetchInvalidURL) {
  InitializeForDocument();
  TestModuleScriptLoaderClient* client =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchInvalidURL(ModuleScriptCustomFetchType::kNone, client);

  // TODO(leszeks): This should finish synchronously, but currently due
  // to the script resource/script streamer interaction, it does not.
  RunUntilIdle();
  EXPECT_TRUE(client->WasNotifyFinished());
  EXPECT_FALSE(client->GetModuleScript());
}

TEST_F(ModuleScriptLoaderTest, FetchInvalidURL_OnWorklet) {
  InitializeForWorklet();
  TestModuleScriptLoaderClient* client =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchInvalidURL(ModuleScriptCustomFetchType::kWorkletAddModule, client);

  EXPECT_FALSE(client->WasNotifyFinished())
      << "ModuleScriptLoader should finish asynchronously.";
  RunUntilIdle();

  EXPECT_TRUE(client->WasNotifyFinished());
  EXPECT_FALSE(client->GetModuleScript());
}

void ModuleScriptLoaderTest::TestFetchURL(
    ModuleScriptCustomFetchType custom_fetch_type,
    TestModuleScriptLoaderClient* client) {
  KURL url("https://example.test/module.js");
  url_test_helpers::RegisterMockedURLLoad(
      url, test::CoreTestDataPath("module.js"), "text/javascript",
      platform_->GetURLLoaderMockFactory());

  auto* registry = MakeGarbageCollected<ModuleScriptLoaderRegistry>();
  ModuleScriptLoader::Fetch(
      ModuleScriptFetchRequest::CreateForTest(url, ModuleType::kJavaScript),
      fetcher_, ModuleGraphLevel::kTopLevelModuleFetch, GetModulator(),
      custom_fetch_type, registry, client);
}

TEST_F(ModuleScriptLoaderTest, FetchURL) {
  InitializeForDocument();
  TestModuleScriptLoaderClient* client =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchURL(ModuleScriptCustomFetchType::kNone, client);

  EXPECT_FALSE(client->WasNotifyFinished())
      << "ModuleScriptLoader unexpectedly finished synchronously.";
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
  // TODO(leszeks): This should finish synchronously, but currently due
  // to the script resource/script streamer interaction, it does not.
  RunUntilIdle();

  EXPECT_TRUE(client->WasNotifyFinished());
  EXPECT_TRUE(client->GetModuleScript());
}

TEST_F(ModuleScriptLoaderTest, FetchURL_OnWorklet) {
  InitializeForWorklet();
  TestModuleScriptLoaderClient* client =
      MakeGarbageCollected<TestModuleScriptLoaderClient>();
  TestFetchURL(ModuleScriptCustomFetchType::kWorkletAddModule, client);

  EXPECT_FALSE(client->WasNotifyFinished())
      << "ModuleScriptLoader unexpectedly finished synchronously.";
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
  RunUntilIdle();

  EXPECT_TRUE(client->WasNotifyFinished());
  EXPECT_TRUE(client->GetModuleScript());
}

}  // namespace blink
```