Response:
Let's break down the thought process for analyzing the `dynamic_module_resolver_test.cc` file.

1. **Understand the Goal:** The primary goal is to understand what this *test* file is testing. Since it's named `..._test.cc`, its purpose is to verify the functionality of some other code. The name `dynamic_module_resolver_test.cc` strongly suggests it's testing the `DynamicModuleResolver` class.

2. **Identify the Tested Class:**  A quick scan of the includes at the top confirms this: `#include "third_party/blink/renderer/core/script/dynamic_module_resolver.h"`. This tells us the core subject of the tests.

3. **Determine the Testing Strategy:**  Test files typically follow a pattern:
    * **Setup:** Initialize the environment and any necessary dependencies.
    * **Action:** Execute the code under test.
    * **Assertion:** Verify that the outcome matches the expected behavior.

4. **Examine the Test Fixture:** The code defines a test fixture `DynamicModuleResolverTest` inheriting from `testing::Test` and `ModuleTestBase`. This fixture provides a common setup and teardown for the individual tests. The `SetUp` and `TearDown` methods hint at the kind of initialization involved (likely setting up a testing environment for modules). The `task_environment_` member suggests asynchronous operations are involved.

5. **Analyze Individual Tests:**  Now, go through each `TEST_F` function within the fixture:

    * **`ResolveSuccess`:**  The name suggests this tests a successful module resolution. Look for keywords like "resolve," "success," and assertions that check for expected positive outcomes. The code creates a `DynamicModuleResolver`, a `ScriptPromiseResolver`, and a `CaptureExportedStringFunction`. It then calls `ResolveDynamically`. The assertions check if the captured value from the resolved module is correct. The `DynamicModuleResolverTestModulator` is a crucial part, acting as a mock for module fetching.

    * **`ResolveJSONModuleSuccess`:**  Similar to the above, but specifically for JSON modules. The key difference is the `import_attributes` and the expectation that the `Modulator::FetchTree` is called with the correct `ModuleType::kJSON`. It acknowledges that full JSON module evaluation isn't the focus here, just the resolution process.

    * **`ResolveSpecifierFailure`:**  This test anticipates a failure during module specifier resolution. It uses a deliberately invalid specifier (`"invalid-specifier"`) and expects an error. The `CaptureErrorFunction` is used to verify the error type and message.

    * **`ResolveModuleTypeFailure`:** This test focuses on invalid module types in import attributes. Again, it expects an error and uses `CaptureErrorFunction` to check the details.

    * **`FetchFailure`:** This tests the scenario where fetching the module fails. The `modulator->ResolveTreeFetch(nullptr)` simulates this failure. The test expects an error.

    * **`ExceptionThrown`:** This test deals with exceptions thrown during module evaluation. The compiled module deliberately throws an error. The test verifies that this error is caught and propagated.

    * **`ResolveWithNullReferrerScriptSuccess`:** This test checks the case where the dynamic import has no explicit referrer script. It sets up a document URL and verifies successful resolution.

    * **`ResolveWithReferrerScriptInfoBaseURL`:** This test verifies that the base URL provided in the `ReferrerScriptInfo` is correctly used when resolving the module.

6. **Identify Key Components and Their Roles:** As you analyze the tests, start noting down the important classes and their interactions:

    * **`DynamicModuleResolver`:** The class being tested. Its core responsibility is resolving dynamic module requests.
    * **`DynamicModuleResolverTestModulator`:** A mock/stub implementation of `Modulator`. It controls the module fetching and resolution process in the test environment. It allows the tests to simulate different outcomes (success, failure, specific module content).
    * **`ScriptPromiseResolver`:** Used to handle the asynchronous nature of dynamic imports.
    * **`ScriptPromise`:** The result of a dynamic import, which can either resolve with the module namespace or reject with an error.
    * **`CaptureExportedStringFunction` and `CaptureErrorFunction`:**  Helper classes to capture the results (success value or error details) of the promise.
    * **`ModuleRequest`:**  Represents the information about the module being requested (specifier, attributes).
    * **`ReferrerScriptInfo`:**  Provides context about the script initiating the dynamic import.
    * **`ModuleScript`:** Represents a compiled module.

7. **Connect to Web Technologies (JavaScript, HTML, CSS):** Now, relate the functionality to web development concepts:

    * **JavaScript:** The core of dynamic modules. The tests directly involve executing JavaScript module code.
    * **HTML:** Dynamic imports are initiated from `<script>` tags or JavaScript code embedded in HTML. The referrer URL often comes from the HTML document's URL.
    * **CSS:** While less directly related, CSS Modules are also a type of module. The testing of import attributes (`type: "json"`) hints at the possibility of other module types beyond JavaScript, and CSS could be another.

8. **Infer Logic and Assumptions:** Based on the tests, deduce the logic within `DynamicModuleResolver`:

    * It takes a `ModuleRequest` and `ReferrerScriptInfo`.
    * It uses a `Modulator` to handle the actual fetching and resolution of modules.
    * It returns a `ScriptPromise` that represents the outcome of the dynamic import.
    * It handles different scenarios: successful resolution, specifier errors, module type errors, fetch failures, and exceptions during module execution.

9. **Consider User/Programming Errors:** Think about how a developer might misuse dynamic imports, based on the test cases:

    * Incorrect module specifiers.
    * Specifying non-existent or incorrect module types in import attributes.
    * Network issues leading to fetch failures.
    * Errors within the imported module's code.

10. **Trace User Operations to the Code:**  Imagine the steps a user takes in a browser that would lead to this code being executed:

    * A user navigates to a webpage.
    * The browser parses the HTML.
    * The browser encounters a `<script>` tag with dynamic import syntax (`import()`).
    * The JavaScript engine begins the process of fetching and evaluating the requested module, involving the `DynamicModuleResolver`.

By following these steps, we can systematically analyze the provided test file and understand its purpose, functionality, relationship to web technologies, underlying logic, potential errors, and how it fits into the broader browser execution flow. The process involves careful reading of the code, understanding the testing patterns, and connecting the technical details to higher-level concepts.
这个文件 `dynamic_module_resolver_test.cc` 是 Chromium Blink 引擎中用于测试 `DynamicModuleResolver` 类的单元测试文件。它的主要功能是验证 `DynamicModuleResolver` 在处理 JavaScript 动态模块导入 (dynamic `import()`) 时的各种场景和逻辑是否正确。

以下是该文件的功能以及与 JavaScript、HTML、CSS 的关系，逻辑推理，常见错误和调试线索：

**功能:**

1. **测试动态模块的成功解析和加载:** 验证当动态导入的模块成功获取并执行时，`DynamicModuleResolver` 是否能正确地解析模块、加载依赖并返回模块的命名空间。
2. **测试不同类型的模块加载:**  测试加载不同类型的模块，例如 JavaScript 模块和 JSON 模块（通过 `import { type: 'json' } from './data.json'` 语法）。
3. **测试模块解析失败的情况:**  验证当模块标识符 (module specifier) 解析失败时（例如，使用了无效的路径或模块名），`DynamicModuleResolver` 是否能正确地返回错误。
4. **测试模块类型错误的情况:** 验证当动态导入语句中指定的模块类型不被支持时，`DynamicModuleResolver` 是否能正确地返回错误。
5. **测试模块获取失败的情况:** 验证当模块的网络请求失败时，`DynamicModuleResolver` 是否能正确地处理并返回错误。
6. **测试模块执行过程中抛出异常的情况:** 验证当动态导入的模块在执行过程中抛出异常时，`DynamicModuleResolver` 是否能捕获并将其传递给 Promise 的 reject 回调。
7. **测试在没有 referrer script 的情况下动态导入:** 验证当动态导入操作不是由特定的脚本触发时（例如，在控制台中执行），`DynamicModuleResolver` 是否能正常工作。
8. **测试使用 `ReferrerScriptInfo` 指定的基础 URL:** 验证当提供明确的 `ReferrerScriptInfo` 时，`DynamicModuleResolver` 是否使用该信息来解析模块的路径。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** 该文件主要测试的是 JavaScript 的动态模块导入功能。`DynamicModuleResolver` 是 Blink 引擎中负责处理 `import()` 表达式的核心组件。测试用例模拟了各种 JavaScript 动态导入的场景，包括成功加载、解析错误、类型错误和运行时错误。例如：
    * **成功加载:** 测试了当 `import('./dependency.js')` 成功加载并执行时，是否能访问到模块导出的变量。
    * **解析错误:** 测试了当 `import('invalid-specifier')` 使用了无法解析的模块标识符时，是否能捕获 `TypeError`。
    * **运行时错误:** 测试了当导入的模块中包含 `throw Error('bar')` 语句时，是否能将错误传递给 Promise 的 reject 回调。

* **HTML:**  动态模块导入通常发生在 HTML 文档加载的 JavaScript 代码中。 虽然测试本身不涉及 HTML 的解析，但其模拟的场景源于浏览器对 HTML 中 `<script>` 标签内 JavaScript 代码的处理。`ReferrerScriptInfo` 中包含的 URL 信息通常来源于触发动态导入的 HTML 文档的 URL 或 `<script>` 标签的 `src` 属性。 例如，在 `ResolveWithNullReferrerScriptSuccess` 测试中，设置了 `scope.GetDocument().SetURL(KURL("https://example.com"))`，模拟了在 `https://example.com` 页面上执行动态导入的场景。

* **CSS:**  该文件也涉及到了 CSS 模块的概念，尽管没有深入测试 CSS 模块的具体加载和解析逻辑。`ResolveJSONModuleSuccess` 测试用例中使用了 `import { type: 'json' } from './dependency.json'` 语法，这与 CSS 模块的导入语法类似（例如 `import style from './style.css' assert { type: 'css' };`）。 这表明 `DynamicModuleResolver` 需要能够处理不同类型的模块，而不仅仅是 JavaScript 模块。

**逻辑推理 (假设输入与输出):**

假设有以下动态导入语句：

**输入 1:**
```javascript
// 在 https://example.com/referrer.js 中
import('./dependency.js');
```
* **假设输入:**
    * `module_request`:  `./dependency.js`
    * `referrer_script_info`:  包含 `https://example.com/referrer.js` 的 URL 信息
* **预期输出:**  如果 `dependency.js` 存在且没有错误，则 Promise resolve，并返回 `dependency.js` 导出的模块命名空间。

**输入 2:**
```javascript
// 在 https://example.com/index.html 的 <script> 标签中
import 'invalid-specifier';
```
* **假设输入:**
    * `module_request`: `invalid-specifier`
    * `referrer_script_info`: 包含 `https://example.com/index.html` 的 URL 信息
* **预期输出:** Promise reject，并返回一个 `TypeError`，错误消息类似于 "Failed to resolve module specifier 'invalid-specifier'".

**输入 3:**
```javascript
import('./data.json', { assert: { type: 'json' } });
```
* **假设输入:**
    * `module_request`: `./data.json`
    * `referrer_script_info`:  触发导入的脚本信息
    * `import_attributes`:  `{ type: 'json' }`
* **预期输出:**  如果 `data.json` 是有效的 JSON 文件，则 Promise resolve，并返回解析后的 JSON 对象。

**用户或编程常见的使用错误:**

1. **错误的模块标识符 (Module Specifier):** 用户在 `import()` 中提供的路径不正确，导致模块无法找到。例如：
   ```javascript
   import('./non-existent-module.js'); // 文件不存在
   import 'my-module'; // 没有配置模块解析规则
   ```
   测试用例 `ResolveSpecifierFailure` 模拟了这种情况。

2. **错误的模块类型 (Module Type):**  在动态导入时指定了不支持的模块类型。例如：
   ```javascript
   import('./some-module', { assert: { type: 'unknown' } });
   ```
   测试用例 `ResolveModuleTypeFailure` 模拟了这种情况。

3. **网络错误:**  由于网络问题，模块文件无法下载。测试用例 `FetchFailure` 模拟了这种情况。

4. **模块代码中的运行时错误:**  导入的模块在执行过程中抛出异常。测试用例 `ExceptionThrown` 模拟了这种情况。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个网页。**
2. **浏览器解析 HTML，遇到包含 JavaScript 代码的 `<script>` 标签。**
3. **JavaScript 代码中包含动态导入语句 `import('./my-module.js')`。**
4. **当 JavaScript 引擎执行到 `import()` 语句时，会创建一个 `ModuleRequest` 对象，其中包含了要导入的模块标识符和可能的导入属性。**
5. **`DynamicModuleResolver` 接收到这个 `ModuleRequest` 对象以及 `ReferrerScriptInfo`（包含当前脚本的信息）。**
6. **`DynamicModuleResolver` 首先会尝试解析模块标识符，将其转换为一个绝对 URL。**
7. **如果解析成功，`DynamicModuleResolver` 会发起一个网络请求来获取模块的内容。**
8. **如果网络请求成功，模块的内容会被解析并编译成一个 `ModuleScript` 对象。**
9. **如果模块是 JavaScript 模块，则会执行模块的代码。**
10. **如果模块执行成功，Promise 会 resolve，并将模块的导出值传递给 resolve 回调。如果执行过程中发生错误，Promise 会 reject，并将错误信息传递给 reject 回调。**

在调试过程中，如果动态导入出现问题，开发者可以关注以下几点：

* **浏览器控制台的错误信息:**  查看是否有关于模块加载失败、解析错误或运行时错误的提示。
* **网络面板:**  检查模块文件的网络请求状态，确认文件是否成功下载。
* **断点调试:**  在浏览器开发者工具中，在 `import()` 语句处设置断点，逐步跟踪 `DynamicModuleResolver` 的执行过程，查看模块标识符的解析、网络请求的发送和模块的编译执行过程。
* **检查模块标识符的拼写和路径是否正确。**
* **检查服务器是否正确配置了 MIME 类型 (例如，JavaScript 文件应使用 `application/javascript` 或 `text/javascript`)。**
* **如果涉及到模块类型，检查 `import` 语句中的 `assert` 属性是否正确。**

`dynamic_module_resolver_test.cc` 文件中的各种测试用例正是为了覆盖这些可能出错的环节，确保 `DynamicModuleResolver` 能够正确处理各种场景，为开发者提供可靠的动态模块导入功能。

### 提示词
```
这是目录为blink/renderer/core/script/dynamic_module_resolver_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/script/dynamic_module_resolver.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/referrer_script_info.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_fetch_request.h"
#include "third_party/blink/renderer/core/script/js_module_script.h"
#include "third_party/blink/renderer/core/testing/dummy_modulator.h"
#include "third_party/blink/renderer/core/testing/module_test_base.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

constexpr const char* kTestReferrerURL = "https://example.com/referrer.js";
constexpr const char* kTestDependencyURL = "https://example.com/dependency.js";
constexpr const char* kTestDependencyURLJSON =
    "https://example.com/dependency.json";

const KURL TestReferrerURL() {
  return KURL(kTestReferrerURL);
}
const KURL TestDependencyURL() {
  return KURL(kTestDependencyURL);
}
const KURL TestDependencyURLJSON() {
  return KURL(kTestDependencyURLJSON);
}
ReferrerScriptInfo TestReferrerScriptInfo() {
  return ReferrerScriptInfo(TestReferrerURL(), ScriptFetchOptions());
}

class DynamicModuleResolverTestModulator final : public DummyModulator {
 public:
  explicit DynamicModuleResolverTestModulator(ScriptState* script_state)
      : script_state_(script_state) {
    Modulator::SetModulator(script_state, this);
  }
  ~DynamicModuleResolverTestModulator() override = default;

  void ResolveTreeFetch(ModuleScript* module_script) {
    ASSERT_TRUE(pending_client_);
    pending_client_->NotifyModuleTreeLoadFinished(module_script);
    pending_client_ = nullptr;
  }
  void SetExpectedFetchTreeURL(const KURL& url) {
    expected_fetch_tree_url_ = url;
  }
  void SetExpectedFetchTreeModuleType(const ModuleType& module_type) {
    expected_fetch_tree_module_type_ = module_type;
  }
  bool fetch_tree_was_called() const { return fetch_tree_was_called_; }

  void Trace(Visitor*) const override;

 private:
  // Implements Modulator:
  ScriptState* GetScriptState() final { return script_state_.Get(); }

  ModuleScript* GetFetchedModuleScript(const KURL& url,
                                       ModuleType module_type) final {
    EXPECT_EQ(TestReferrerURL(), url);
    ModuleScript* module_script =
        JSModuleScript::CreateForTest(this, v8::Local<v8::Module>(), url);
    return module_script;
  }

  KURL ResolveModuleSpecifier(const String& module_request,
                              const KURL& base_url,
                              String*) final {
    if (module_request == "invalid-specifier")
      return KURL();

    return KURL(base_url, module_request);
  }

  void FetchTree(const KURL& url,
                 ModuleType module_type,
                 ResourceFetcher*,
                 mojom::blink::RequestContextType,
                 network::mojom::RequestDestination,
                 const ScriptFetchOptions&,
                 ModuleScriptCustomFetchType custom_fetch_type,
                 ModuleTreeClient* client,
                 String) final {
    EXPECT_EQ(expected_fetch_tree_url_, url);
    EXPECT_EQ(expected_fetch_tree_module_type_, module_type);

    // Currently there are no usage of custom fetch hooks for dynamic import in
    // web specifications.
    EXPECT_EQ(ModuleScriptCustomFetchType::kNone, custom_fetch_type);

    pending_client_ = client;
    fetch_tree_was_called_ = true;
  }

  Member<ScriptState> script_state_;
  Member<ModuleTreeClient> pending_client_;
  KURL expected_fetch_tree_url_;
  ModuleType expected_fetch_tree_module_type_ = ModuleType::kJavaScript;
  bool fetch_tree_was_called_ = false;
};

void DynamicModuleResolverTestModulator::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  visitor->Trace(pending_client_);
  DummyModulator::Trace(visitor);
}

// CaptureExportedStringFunction implements a javascript function
// with a single argument of type module namespace.
// CaptureExportedStringFunction captures the exported string value
// from the module namespace as a WTF::String, exposed via CapturedValue().
class CaptureExportedStringFunction final
    : public ThenCallable<IDLAny, CaptureExportedStringFunction> {
 public:
  explicit CaptureExportedStringFunction(const String& export_name)
      : export_name_(export_name) {}

  bool WasCalled() const { return was_called_; }
  const String& CapturedValue() const { return captured_value_; }

  void React(ScriptState* script_state, ScriptValue value) {
    was_called_ = true;

    v8::Isolate* isolate = script_state->GetIsolate();
    v8::Local<v8::Context> context = script_state->GetContext();

    v8::Local<v8::Object> module_namespace =
        value.V8Value()->ToObject(context).ToLocalChecked();
    v8::Local<v8::Value> exported_value =
        module_namespace->Get(context, V8String(isolate, export_name_))
            .ToLocalChecked();
    captured_value_ = ToCoreString(
        isolate, exported_value->ToString(context).ToLocalChecked());
  }

 private:
  const String export_name_;
  bool was_called_ = false;
  String captured_value_;
};

// CaptureErrorFunction implements a javascript function which captures
// name and error of the exception passed as its argument.
class CaptureErrorFunction final
    : public ThenCallable<IDLAny, CaptureErrorFunction> {
 public:
  CaptureErrorFunction() = default;

  bool WasCalled() const { return was_called_; }
  const String& Name() const { return name_; }
  const String& Message() const { return message_; }

  void React(ScriptState* script_state, ScriptValue value) {
    was_called_ = true;

    v8::Isolate* isolate = script_state->GetIsolate();
    v8::Local<v8::Context> context = script_state->GetContext();

    v8::Local<v8::Object> error_object =
        value.V8Value()->ToObject(context).ToLocalChecked();

    v8::Local<v8::Value> name =
        error_object->Get(context, V8String(isolate, "name")).ToLocalChecked();
    name_ = ToCoreString(isolate, name->ToString(context).ToLocalChecked());
    v8::Local<v8::Value> message =
        error_object->Get(context, V8String(isolate, "message"))
            .ToLocalChecked();
    message_ =
        ToCoreString(isolate, message->ToString(context).ToLocalChecked());
  }

 private:
  bool was_called_ = false;
  String name_;
  String message_;
};

class DynamicModuleResolverTestNotReached final
    : public ThenCallable<IDLAny, DynamicModuleResolverTestNotReached> {
 public:
  DynamicModuleResolverTestNotReached() = default;

  void React(ScriptState*, ScriptValue) { ADD_FAILURE(); }
};

class DynamicModuleResolverTest : public testing::Test, public ModuleTestBase {
 public:
  void SetUp() override { ModuleTestBase::SetUp(); }

  void TearDown() override { ModuleTestBase::TearDown(); }
  test::TaskEnvironment task_environment_;
};

}  // namespace

TEST_F(DynamicModuleResolverTest, ResolveSuccess) {
  V8TestingScope scope;
  auto* modulator = MakeGarbageCollected<DynamicModuleResolverTestModulator>(
      scope.GetScriptState());
  modulator->SetExpectedFetchTreeURL(TestDependencyURL());

  auto* promise_resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());
  auto promise = promise_resolver->Promise();

  auto* capture = MakeGarbageCollected<CaptureExportedStringFunction>("foo");
  promise.Then(scope.GetScriptState(), capture,
               MakeGarbageCollected<DynamicModuleResolverTestNotReached>());

  auto* resolver = MakeGarbageCollected<DynamicModuleResolver>(modulator);
  ModuleRequest module_request("./dependency.js",
                               TextPosition::MinimumPosition(),
                               Vector<ImportAttribute>());
  resolver->ResolveDynamically(module_request, TestReferrerScriptInfo(),
                               promise_resolver);

  scope.PerformMicrotaskCheckpoint();
  EXPECT_FALSE(capture->WasCalled());

  v8::Local<v8::Module> record = ModuleTestBase::CompileModule(
      scope.GetScriptState(), "export const foo = 'hello';", TestReferrerURL());
  ModuleScript* module_script =
      JSModuleScript::CreateForTest(modulator, record, TestDependencyURL());
  EXPECT_TRUE(ModuleRecord::Instantiate(scope.GetScriptState(), record,
                                        TestReferrerURL())
                  .IsEmpty());
  modulator->ResolveTreeFetch(module_script);

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(capture->WasCalled());
  EXPECT_EQ("hello", capture->CapturedValue());
}

TEST_F(DynamicModuleResolverTest, ResolveJSONModuleSuccess) {
  V8TestingScope scope;
  auto* modulator = MakeGarbageCollected<DynamicModuleResolverTestModulator>(
      scope.GetScriptState());
  modulator->SetExpectedFetchTreeURL(TestDependencyURLJSON());
  modulator->SetExpectedFetchTreeModuleType(ModuleType::kJSON);

  auto* promise_resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());

  auto* resolver = MakeGarbageCollected<DynamicModuleResolver>(modulator);
  Vector<ImportAttribute> import_attributes{
      ImportAttribute("type", "json", TextPosition::MinimumPosition())};
  ModuleRequest module_request(
      "./dependency.json", TextPosition::MinimumPosition(), import_attributes);
  resolver->ResolveDynamically(module_request, TestReferrerScriptInfo(),
                               promise_resolver);

  // Instantiating and evaluating a JSON module requires a lot of
  // machinery not currently available in this unit test suite. For
  // the purposes of a DynamicModuleResolver unit test, it should be sufficient
  // to validate that the correct arguments are passed from
  // DynamicModuleResolver::ResolveDynamically to Modulator::FetchTree, which is
  // validated during DynamicModuleResolverTestModulator::FetchTree.
}

TEST_F(DynamicModuleResolverTest, ResolveSpecifierFailure) {
  V8TestingScope scope;
  auto* modulator = MakeGarbageCollected<DynamicModuleResolverTestModulator>(
      scope.GetScriptState());
  modulator->SetExpectedFetchTreeURL(TestDependencyURL());

  auto* promise_resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());
  auto promise = promise_resolver->Promise();

  auto* capture = MakeGarbageCollected<CaptureErrorFunction>();
  promise.Then(scope.GetScriptState(),
               MakeGarbageCollected<DynamicModuleResolverTestNotReached>(),
               capture);

  auto* resolver = MakeGarbageCollected<DynamicModuleResolver>(modulator);
  ModuleRequest module_request("invalid-specifier",
                               TextPosition::MinimumPosition(),
                               Vector<ImportAttribute>());
  resolver->ResolveDynamically(module_request, TestReferrerScriptInfo(),
                               promise_resolver);

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(capture->WasCalled());
  EXPECT_EQ("TypeError", capture->Name());
  EXPECT_TRUE(capture->Message().StartsWith("Failed to resolve"));
}

TEST_F(DynamicModuleResolverTest, ResolveModuleTypeFailure) {
  V8TestingScope scope;
  auto* modulator = MakeGarbageCollected<DynamicModuleResolverTestModulator>(
      scope.GetScriptState());
  modulator->SetExpectedFetchTreeURL(TestDependencyURL());

  auto* promise_resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());
  auto promise = promise_resolver->Promise();

  auto* capture = MakeGarbageCollected<CaptureErrorFunction>();
  promise.Then(scope.GetScriptState(),
               MakeGarbageCollected<DynamicModuleResolverTestNotReached>(),
               capture);

  auto* resolver = MakeGarbageCollected<DynamicModuleResolver>(modulator);
  Vector<ImportAttribute> import_attributes{
      ImportAttribute("type", "notARealType", TextPosition::MinimumPosition())};
  ModuleRequest module_request(
      "./dependency.js", TextPosition::MinimumPosition(), import_attributes);
  resolver->ResolveDynamically(module_request, TestReferrerScriptInfo(),
                               promise_resolver);

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(capture->WasCalled());
  EXPECT_EQ("TypeError", capture->Name());
  EXPECT_EQ("\"notARealType\" is not a valid module type.", capture->Message());
}

TEST_F(DynamicModuleResolverTest, FetchFailure) {
  V8TestingScope scope;
  auto* modulator = MakeGarbageCollected<DynamicModuleResolverTestModulator>(
      scope.GetScriptState());
  modulator->SetExpectedFetchTreeURL(TestDependencyURL());

  auto* promise_resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());
  auto promise = promise_resolver->Promise();

  auto* capture = MakeGarbageCollected<CaptureErrorFunction>();
  promise.Then(scope.GetScriptState(),
               MakeGarbageCollected<DynamicModuleResolverTestNotReached>(),
               capture);

  auto* resolver = MakeGarbageCollected<DynamicModuleResolver>(modulator);
  ModuleRequest module_request("./dependency.js",
                               TextPosition::MinimumPosition(),
                               Vector<ImportAttribute>());
  resolver->ResolveDynamically(module_request, TestReferrerScriptInfo(),
                               promise_resolver);

  EXPECT_FALSE(capture->WasCalled());

  modulator->ResolveTreeFetch(nullptr);

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(capture->WasCalled());
  EXPECT_EQ("TypeError", capture->Name());
  EXPECT_TRUE(capture->Message().StartsWith("Failed to fetch"));
}

TEST_F(DynamicModuleResolverTest, ExceptionThrown) {
  V8TestingScope scope;
  auto* modulator = MakeGarbageCollected<DynamicModuleResolverTestModulator>(
      scope.GetScriptState());
  modulator->SetExpectedFetchTreeURL(TestDependencyURL());

  auto* promise_resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());
  auto promise = promise_resolver->Promise();

  auto* capture = MakeGarbageCollected<CaptureErrorFunction>();
  promise.Then(scope.GetScriptState(),
               MakeGarbageCollected<DynamicModuleResolverTestNotReached>(),
               capture);

  auto* resolver = MakeGarbageCollected<DynamicModuleResolver>(modulator);
  ModuleRequest module_request("./dependency.js",
                               TextPosition::MinimumPosition(),
                               Vector<ImportAttribute>());
  resolver->ResolveDynamically(module_request, TestReferrerScriptInfo(),
                               promise_resolver);

  EXPECT_FALSE(capture->WasCalled());

  v8::Local<v8::Module> record = ModuleTestBase::CompileModule(
      scope.GetScriptState(), "throw Error('bar')", TestReferrerURL());
  ModuleScript* module_script =
      JSModuleScript::CreateForTest(modulator, record, TestDependencyURL());
  EXPECT_TRUE(ModuleRecord::Instantiate(scope.GetScriptState(), record,
                                        TestReferrerURL())
                  .IsEmpty());
  modulator->ResolveTreeFetch(module_script);

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(capture->WasCalled());
  EXPECT_EQ("Error", capture->Name());
  EXPECT_EQ("bar", capture->Message());
}

TEST_F(DynamicModuleResolverTest, ResolveWithNullReferrerScriptSuccess) {
  V8TestingScope scope;
  scope.GetDocument().SetURL(KURL("https://example.com"));

  auto* modulator = MakeGarbageCollected<DynamicModuleResolverTestModulator>(
      scope.GetScriptState());
  modulator->SetExpectedFetchTreeURL(TestDependencyURL());

  auto* promise_resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());
  auto promise = promise_resolver->Promise();

  auto* capture = MakeGarbageCollected<CaptureExportedStringFunction>("foo");
  promise.Then(scope.GetScriptState(), capture,
               MakeGarbageCollected<DynamicModuleResolverTestNotReached>());

  auto* resolver = MakeGarbageCollected<DynamicModuleResolver>(modulator);
  ModuleRequest module_request("./dependency.js",
                               TextPosition::MinimumPosition(),
                               Vector<ImportAttribute>());
  resolver->ResolveDynamically(module_request, ReferrerScriptInfo(),
                               promise_resolver);

  scope.PerformMicrotaskCheckpoint();
  EXPECT_FALSE(capture->WasCalled());

  v8::Local<v8::Module> record = ModuleTestBase::CompileModule(
      scope.GetScriptState(), "export const foo = 'hello';",
      TestDependencyURL());
  ModuleScript* module_script =
      JSModuleScript::CreateForTest(modulator, record, TestDependencyURL());
  EXPECT_TRUE(ModuleRecord::Instantiate(scope.GetScriptState(), record,
                                        TestDependencyURL())
                  .IsEmpty());
  modulator->ResolveTreeFetch(module_script);

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(capture->WasCalled());
  EXPECT_EQ("hello", capture->CapturedValue());
}

TEST_F(DynamicModuleResolverTest, ResolveWithReferrerScriptInfoBaseURL) {
  V8TestingScope scope;
  scope.GetDocument().SetURL(KURL("https://example.com"));

  auto* modulator = MakeGarbageCollected<DynamicModuleResolverTestModulator>(
      scope.GetScriptState());
  modulator->SetExpectedFetchTreeURL(
      KURL("https://example.com/correct/dependency.js"));

  auto* promise_resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      scope.GetScriptState());
  auto* resolver = MakeGarbageCollected<DynamicModuleResolver>(modulator);
  KURL correct_base_url("https://example.com/correct/baz.js");
  ModuleRequest module_request("./dependency.js",
                               TextPosition::MinimumPosition(),
                               Vector<ImportAttribute>());
  resolver->ResolveDynamically(
      module_request,
      ReferrerScriptInfo(correct_base_url, ScriptFetchOptions()),
      promise_resolver);

  scope.PerformMicrotaskCheckpoint();
  EXPECT_TRUE(modulator->fetch_tree_was_called());
}

}  // namespace blink
```