Response:
Let's break down the thought process for analyzing the given C++ test file for Chromium's Blink engine.

**1. Initial Scan and Goal Identification:**

The first step is to quickly scan the file and identify its purpose. The filename `service_worker_container_test.cc` strongly suggests this is a test file for the `ServiceWorkerContainer` class. The `#include` directives confirm this, along with other related classes like `ServiceWorkerRegistration`. The presence of `testing/gtest/include/gtest/gtest.h` definitively labels it as a unit test file using the Google Test framework.

The goal of this file is to test the functionality of the `ServiceWorkerContainer` class.

**2. High-Level Functionality Breakdown:**

Now, let's look at the major components within the file:

* **Includes:** These tell us the dependencies of the test file and give hints about the tested functionality. We see includes for service workers, scripting (V8 bindings), DOM elements, and testing infrastructure.
* **Namespaces:**  The `blink` namespace confirms this is part of the Blink rendering engine. The anonymous namespace `namespace { ... }` often contains helper functions and classes specific to this test file.
* **Helper Classes and Functions:**  We see classes like `StubScriptFunction`, `ScriptValueTest`, `ExpectDOMException`, `ExpectTypeError`, and `NotReachedWebServiceWorkerProvider`. These are clearly designed to simplify the testing process by creating controlled environments and assertions.
* **Test Fixture:** The `ServiceWorkerContainerTest` class, inheriting from `PageTestBase`, is the core of the test setup. It provides methods for setting up the test environment (like setting the page URL) and common testing logic.
* **Individual Tests:**  Functions starting with `TEST_F` are the individual test cases. Their names (e.g., `Register_CrossOriginScriptIsRejected`) give a good indication of the specific scenario being tested.
* **Stubbing/Mocking:** The `StubWebServiceWorkerProvider` is a crucial component for isolating the `ServiceWorkerContainer` during testing. It allows us to verify interactions with the underlying `WebServiceWorkerProvider` without needing a full implementation.

**3. Detailed Analysis of Key Components:**

* **Helper Functions/Classes:**
    * **Promise Handling (`StubScriptFunction`, `ExpectRejected`):**  Service worker operations are often asynchronous and use Promises. These helpers are designed to test the rejection paths of Promises.
    * **Exception Assertions (`ExpectDOMException`, `ExpectTypeError`):** These helpers check if the correct exception type and message are thrown under specific conditions.
    * **Provider Mocking (`NotReachedWebServiceWorkerProvider`, `StubWebServiceWorkerProvider`):**  Crucial for controlling the behavior of dependencies and verifying that certain interactions occur (or don't occur). `NotReachedWebServiceWorkerProvider` asserts that the provider *isn't* called in certain negative test cases. `StubWebServiceWorkerProvider` allows verification of the arguments passed to the real provider.

* **`ServiceWorkerContainerTest` Fixture:**  The `SetUp` method initializes the testing environment. The helper methods like `TestRegisterRejected` and `TestGetRegistrationRejected` encapsulate common rejection testing logic, reducing code duplication. `GetScriptState` provides access to the JavaScript execution environment.

* **Test Cases:**  Each `TEST_F` focuses on a specific aspect of `ServiceWorkerContainer` functionality. Notice the naming convention: `Action_Scenario_ExpectedOutcome`. This makes the tests easy to understand. Examples:
    * `Register_CrossOriginScriptIsRejected`:  Tests that registering a service worker script from a different origin is rejected.
    * `GetRegistration_CrossOriginURLIsRejected`: Tests that getting a registration for a URL from a different origin is rejected.
    * `RegisterUnregister_NonHttpsSecureOriginDelegatesToProvider`: Tests that registration on a non-HTTPS secure origin correctly calls the provider.
    * `ReceiveMessage`: Tests the handling of incoming messages to the container.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, the crucial step is to connect the C++ code to the user-facing web technologies.

* **JavaScript:** Service workers are fundamentally a JavaScript API. The `registerServiceWorker` and `getRegistration` methods in the C++ code directly correspond to the JavaScript methods of the `navigator.serviceWorker` object. The tests involving Promises directly reflect how developers interact with these APIs in JavaScript. The `ReceiveMessage` tests relate to the `postMessage` API used for communication between the service worker and the controlled page.
* **HTML:** The context where service workers operate is within a web page. The `PageTestBase` fixture simulates loading a web page. The tests implicitly involve the HTML document and its associated origin.
* **CSS:** While not directly tested in *this specific file*, CSS is indirectly related. Service workers can intercept network requests, potentially affecting how CSS files are loaded and cached. However, the primary focus here is on the core service worker registration and management logic.

**5. Logic and Assumptions:**

The tests make logical assumptions about how service workers should behave according to web standards. For instance, the cross-origin checks are based on the same-origin policy. The tests assume that the underlying platform correctly implements the necessary security and networking features.

**6. User/Programming Errors:**

The tests highlight common errors developers might make:

* **Registering a script from a different origin:**  The `Register_CrossOriginScriptIsRejected` test directly addresses this.
* **Using an invalid scope:** The `Register_UnsupportedSchemeIsRejected` test touches upon this.
* **Trying to get a registration for a cross-origin URL:** The `GetRegistration_CrossOriginURLIsRejected` test illustrates this.

**7. Debugging Clues and User Actions:**

The tests provide valuable debugging clues. If a test fails, it pinpoints a specific scenario where the `ServiceWorkerContainer` is not behaving as expected. The test names and assertions help developers understand the root cause of the issue.

To reach this code, a user would typically:

1. **Open a web page in a Chromium-based browser.**
2. **The web page contains JavaScript code that interacts with the Service Worker API (e.g., calls `navigator.serviceWorker.register(...)`).**
3. **The browser's JavaScript engine executes this code.**
4. **The JavaScript engine calls the corresponding C++ implementation in the Blink engine (specifically the `ServiceWorkerContainer` class).**
5. **If something goes wrong during registration or other service worker operations, the code paths tested in this file might be involved.**

**Self-Correction/Refinement during Thought Process:**

Initially, one might focus solely on the C++ code. However, it's crucial to constantly relate it back to the web platform and developer interactions. Recognizing the JavaScript API equivalents and the underlying web standards is key to fully understanding the purpose and implications of these tests. Also, understanding the role of mocking/stubbing is vital for grasping how these unit tests achieve isolation. Finally, thinking about the user actions that trigger this code helps to contextualize the tests and their importance.
这个文件 `service_worker_container_test.cc` 是 Chromium Blink 引擎中用于测试 `ServiceWorkerContainer` 类的单元测试文件。 `ServiceWorkerContainer` 是浏览器中代表服务工作线程的容器的对象，它允许网页注册、获取和管理服务工作线程。

以下是该文件的功能分解：

**主要功能：**

1. **测试 `ServiceWorkerContainer` 类的各种方法和功能。**  这包括但不限于：
    * `registerServiceWorker()`: 注册一个新的服务工作线程。
    * `getRegistration()`: 获取已注册的服务工作线程。
    * 接收来自服务工作线程的消息 (通过 `ReceiveMessage`)。
    * 处理注册时的各种错误情况（例如跨域问题，无效的 URL）。
    * 验证传递给底层 `WebServiceWorkerProvider` 的参数。

2. **使用 Google Test 框架进行单元测试。**  该文件定义了多个以 `TEST_F` 开头的测试用例，每个测试用例都针对 `ServiceWorkerContainer` 的特定行为或场景进行验证。

3. **提供测试辅助工具。**  文件中定义了一些辅助类和函数，用于简化测试的编写和断言，例如：
    * `StubScriptFunction`: 用于测试 Promise 的 rejected 状态。
    * `ExpectRejected`: 用于断言 Promise 被拒绝，并执行进一步的断言。
    * `ExpectDOMException`: 用于断言 Promise 被一个特定的 `DOMException` 拒绝。
    * `ExpectTypeError`: 用于断言 Promise 被一个特定的 `TypeError` 拒绝。
    * `NotReachedWebServiceWorkerProvider`: 用于断言在某些情况下不应该调用底层的 `WebServiceWorkerProvider`。
    * `StubWebServiceWorkerProvider`: 一个简单的 `WebServiceWorkerProvider` 的桩实现，用于验证 `ServiceWorkerContainer` 是否正确地调用了它并传递了正确的参数。

**与 JavaScript, HTML, CSS 的关系：**

`ServiceWorkerContainer` 是 Web 标准中定义的一个 JavaScript API，通过 `navigator.serviceWorker` 访问。因此，这个 C++ 测试文件直接关联到 JavaScript 的功能。

* **JavaScript:**
    * **`navigator.serviceWorker.register()`:** 该文件中的测试用例 `Register_CrossOriginScriptIsRejected`, `Register_UnsupportedSchemeIsRejected`, `Register_CrossOriginScopeIsRejected`, `RegisterUnregister_NonHttpsSecureOriginDelegatesToProvider`, `RegisterUnregister_UpdateViaCacheOptionDelegatesToProvider`, `Register_TypeOptionDelegatesToProvider` 等都在测试 `ServiceWorkerContainer` 中与 JavaScript 方法 `register()` 对应的 C++ 实现。例如，`Register_CrossOriginScriptIsRejected` 测试了当 JavaScript 调用 `navigator.serviceWorker.register()` 注册一个跨域的脚本时，C++ 代码是否会返回 `SecurityError`。
    * **`navigator.serviceWorker.getRegistration()`:**  测试用例 `GetRegistration_CrossOriginURLIsRejected`, `GetRegistration_OmittedDocumentURLDefaultsToPageURL` 测试了与 JavaScript 方法 `getRegistration()` 对应的 C++ 实现。例如，`GetRegistration_CrossOriginURLIsRejected` 测试了当 JavaScript 调用 `navigator.serviceWorker.getRegistration()` 并传入一个跨域的 URL 时，C++ 代码是否会返回 `SecurityError`。
    * **`postMessage()` (通过 `message` 事件):**  `ReceiveMessage` 和 `ReceiveMessageLockedToAgentCluster`, `ReceiveMessageWhichCannotDeserialize` 测试了 `ServiceWorkerContainer` 如何接收并处理来自 Service Worker 的消息。这对应于 Service Worker 中使用 `postMessage()` 向控制页面发送消息，然后在页面上通过 `serviceWorkerContainer.onmessage` 监听 `message` 事件。

* **HTML:**
    * 服务工作线程的作用域是由 HTML 页面决定的。测试用例中通过 `SetPageURL()` 设置了页面的 URL，这会影响服务工作线程的注册作用域。例如，`Register_CrossOriginScopeIsRejected` 测试了尝试注册一个与当前页面不同源的作用域时是否会被拒绝。

* **CSS:**
    * 虽然这个测试文件本身没有直接测试与 CSS 相关的逻辑，但服务工作线程可以拦截网络请求，包括 CSS 文件的请求。因此，`ServiceWorkerContainer` 的正确性对于确保 CSS 资源的正确加载和缓存至关重要。然而，这个测试文件更侧重于注册和消息传递的核心功能。

**逻辑推理与假设输入输出：**

**假设输入 (以 `Register_CrossOriginScriptIsRejected` 为例):**

* 用户在 `https://www.example.com` 页面上执行 JavaScript 代码：
  ```javascript
  navigator.serviceWorker.register('https://www.example.com:8080/worker.js', { scope: '/' });
  ```
* Blink 引擎接收到注册服务工作线程的请求，脚本 URL 为 `https://www.example.com:8080/worker.js`，作用域为 `/`。

**逻辑推理:**

* `ServiceWorkerContainer` 的 `registerServiceWorker` 方法会被调用。
* 该方法会检查提供的脚本 URL 的源 (`https://www.example.com:8080`) 是否与当前页面的源 (`https://www.example.com`) 相同。
* 由于端口不同，源不相同。

**输出:**

* `registerServiceWorker` 方法会拒绝注册，并返回一个被拒绝的 Promise。
* Promise 的 rejected 值是一个 `DOMException` 对象，其 `name` 属性为 "SecurityError"，`message` 属性包含关于源不匹配的描述。
* 测试用例 `ExpectDOMException("SecurityError", ...)` 会断言这个输出。

**涉及的用户或编程常见使用错误：**

1. **跨域注册脚本：** 开发者可能会错误地尝试从与当前页面不同源的 URL 注册服务工作线程脚本。例如：
   ```javascript
   navigator.serviceWorker.register('https://another-domain.com/worker.js');
   ```
   `Register_CrossOriginScriptIsRejected` 测试了这个错误，会抛出 `SecurityError`。

2. **使用不支持的协议作为作用域：** 开发者可能会错误地使用 `wss://` 或其他非 `http://` 或 `https://` 的协议作为作用域。例如：
   ```javascript
   navigator.serviceWorker.register('/worker.js', { scope: 'wss://example.com/' });
   ```
   `Register_UnsupportedSchemeIsRejected` 测试了这个错误，会抛出 `TypeError`。

3. **跨域设置作用域：** 开发者可能会错误地将服务工作线程的作用域设置为与当前页面不同源的 URL。例如：
   ```javascript
   navigator.serviceWorker.register('/worker.js', { scope: 'https://another-domain.com/' });
   ```
   `Register_CrossOriginScopeIsRejected` 测试了这个错误，会抛出 `SecurityError`。

4. **尝试获取跨域文档的注册信息：** 开发者可能会尝试获取与当前页面不同源的文档的注册信息。例如：
   ```javascript
   navigator.serviceWorker.getRegistration('https://another-domain.com/');
   ```
   `GetRegistration_CrossOriginURLIsRejected` 测试了这个错误，会抛出 `SecurityError`。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入一个 URL 并访问一个网页 (例如 `https://www.example.com`)。**
2. **该网页的 HTML 文件被加载并解析。**
3. **网页的 JavaScript 代码开始执行。**
4. **JavaScript 代码调用 `navigator.serviceWorker.register('worker.js')` 或 `navigator.serviceWorker.getRegistration()`。**
5. **浏览器将这些 JavaScript API 调用转换为对 Blink 引擎中 `ServiceWorkerContainer` 相应 C++ 方法的调用。**
6. **如果在注册过程中，脚本 URL 或作用域违反了同源策略或其他安全限制，则 `ServiceWorkerContainer` 的代码（就像这个测试文件所测试的那样）会抛出异常或返回错误，最终导致 Promise 被拒绝。**
7. **如果在获取注册信息时，提供的 URL 与当前页面不同源，也会触发类似的错误处理逻辑。**
8. **当接收到来自 Service Worker 的消息时，浏览器会调用 `ServiceWorkerContainer::ReceiveMessage` 方法，该方法的行为也在该测试文件中被验证。**

**作为调试线索：**

如果开发者在他们的网页上遇到了服务工作线程注册或管理方面的问题，例如注册失败，或者无法接收到来自服务工作线程的消息，那么查看与 `ServiceWorkerContainer` 相关的测试用例可以提供一些线索：

* **如果看到控制台报错 `SecurityError` 或 `TypeError`，并且涉及到服务工作线程的注册，可以查看 `Register_CrossOriginScriptIsRejected`，`Register_UnsupportedSchemeIsRejected`，`Register_CrossOriginScopeIsRejected` 等测试用例，看看是否符合这些测试用例覆盖的错误场景。**
* **如果获取注册信息时出现问题，可以查看 `GetRegistration_CrossOriginURLIsRejected` 测试用例。**
* **如果消息传递出现问题，可以查看 `ReceiveMessage` 相关的测试用例，了解消息反序列化失败或跨 Agent Cluster 传递可能导致的问题。**

总之，`service_worker_container_test.cc` 是确保 `ServiceWorkerContainer` 类按照预期工作的关键部分，它模拟了各种用户操作和编程场景，并验证了其行为的正确性，同时也揭示了开发者在使用 Service Worker API 时可能犯的常见错误。

### 提示词
```
这是目录为blink/renderer/modules/service_worker/service_worker_container_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/service_worker/service_worker_container.h"

#include <memory>
#include <utility>

#include "base/memory/raw_ref.h"
#include "base/test/bind.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/script/script_type.mojom-blink.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_provider.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/wait_for_event.h"
#include "third_party/blink/renderer/modules/service_worker/navigator_service_worker.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "v8/include/v8.h"

namespace blink {
namespace {

// Promise-related test support.

class StubScriptFunction : public ThenCallable<IDLAny, StubScriptFunction> {
 public:
  void React(ScriptState*, ScriptValue result) { result_ = result; }
  ScriptValue Result() const {
    CHECK(!result_.IsEmpty());
    return result_;
  }

  void Trace(Visitor* visitor) const override {
    ThenCallable<IDLAny, StubScriptFunction>::Trace(visitor);
    visitor->Trace(result_);
  }

 private:
  ScriptValue result_;
};

class ScriptValueTest {
 public:
  virtual ~ScriptValueTest() = default;
  virtual void operator()(ScriptState*, ScriptValue) const = 0;
};

// Runs microtasks and expects |promise| to be rejected. Calls
// |valueTest| with the value passed to |reject|, if any.
void ExpectRejected(ScriptState* script_state,
                    ScriptPromise<ServiceWorkerRegistration>& promise,
                    const ScriptValueTest& value_test) {
  StubScriptFunction* rejected = MakeGarbageCollected<StubScriptFunction>();
  promise.Catch(script_state, rejected);
  script_state->GetContext()->GetMicrotaskQueue()->PerformCheckpoint(
      script_state->GetIsolate());
  value_test(script_state, rejected->Result());
}

// DOM-related test support.

// Matches a ScriptValue and a DOMException with a specific name and message.
class ExpectDOMException : public ScriptValueTest {
 public:
  ExpectDOMException(const String& expected_name,
                     const String& expected_message)
      : expected_name_(expected_name), expected_message_(expected_message) {}

  ~ExpectDOMException() override = default;

  void operator()(ScriptState* script_state, ScriptValue value) const override {
    DOMException* exception = V8DOMException::ToWrappable(
        script_state->GetIsolate(), value.V8Value());
    EXPECT_TRUE(exception) << "the value should be a DOMException";
    if (!exception)
      return;
    EXPECT_EQ(expected_name_, exception->name());
    EXPECT_EQ(expected_message_, exception->message());
  }

 private:
  String expected_name_;
  String expected_message_;
};

// Matches a ScriptValue and a TypeError with a message.
class ExpectTypeError : public ScriptValueTest {
 public:
  ExpectTypeError(const String& expected_message)
      : expected_message_(expected_message) {}

  ~ExpectTypeError() override = default;

  void operator()(ScriptState* script_state, ScriptValue value) const override {
    v8::Isolate* isolate = script_state->GetIsolate();
    v8::Local<v8::Context> context = script_state->GetContext();
    v8::Local<v8::Object> error_object =
        value.V8Value()->ToObject(context).ToLocalChecked();
    v8::Local<v8::Value> name =
        error_object->Get(context, V8String(isolate, "name")).ToLocalChecked();
    v8::Local<v8::Value> message =
        error_object->Get(context, V8String(isolate, "message"))
            .ToLocalChecked();

    EXPECT_EQ("TypeError",
              ToCoreString(isolate, name->ToString(context).ToLocalChecked()));
    EXPECT_EQ(
        expected_message_,
        ToCoreString(isolate, message->ToString(context).ToLocalChecked()));
  }

 private:
  String expected_message_;
};

// Service Worker-specific tests.

class NotReachedWebServiceWorkerProvider : public WebServiceWorkerProvider {
 public:
  ~NotReachedWebServiceWorkerProvider() override = default;

  void RegisterServiceWorker(
      const WebURL& scope,
      const WebURL& script_url,
      blink::mojom::blink::ScriptType script_type,
      mojom::ServiceWorkerUpdateViaCache update_via_cache,
      const WebFetchClientSettingsObject& fetch_client_settings_object,
      std::unique_ptr<WebServiceWorkerRegistrationCallbacks> callbacks)
      override {
    ADD_FAILURE()
        << "the provider should not be called to register a Service Worker";
  }

  bool ValidateScopeAndScriptURL(const WebURL& scope,
                                 const WebURL& script_url,
                                 WebString* error_message) override {
    return true;
  }
};

class ServiceWorkerContainerTest : public PageTestBase {
 protected:
  void SetUp() override { PageTestBase::SetUp(gfx::Size()); }

  ~ServiceWorkerContainerTest() override {
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

  ScriptState* GetScriptState() {
    return ToScriptStateForMainWorld(GetDocument().GetFrame());
  }

  void SetPageURL(const String& url) {
    NavigateTo(KURL(NullURL(), url));
  }

  void TestRegisterRejected(const String& script_url,
                            const String& scope,
                            const ScriptValueTest& value_test) {
    // When the registration is rejected, a register call must not reach
    // the provider.
    ServiceWorkerContainer* container =
        ServiceWorkerContainer::CreateForTesting(
            *GetFrame().DomWindow(),
            std::make_unique<NotReachedWebServiceWorkerProvider>());
    ScriptState::Scope script_scope(GetScriptState());
    RegistrationOptions* options = RegistrationOptions::Create();
    options->setScope(scope);
    ScriptPromise<ServiceWorkerRegistration> promise =
        container->registerServiceWorker(GetScriptState(), script_url, options);
    ExpectRejected(GetScriptState(), promise, value_test);
  }

  void TestGetRegistrationRejected(const String& document_url,
                                   const ScriptValueTest& value_test) {
    ServiceWorkerContainer* container =
        ServiceWorkerContainer::CreateForTesting(
            *GetFrame().DomWindow(),
            std::make_unique<NotReachedWebServiceWorkerProvider>());
    ScriptState::Scope script_scope(GetScriptState());
    ScriptPromise<ServiceWorkerRegistration> promise =
        container->getRegistration(GetScriptState(), document_url);
    ExpectRejected(GetScriptState(), promise, value_test);
  }
};

TEST_F(ServiceWorkerContainerTest, Register_CrossOriginScriptIsRejected) {
  SetPageURL("https://www.example.com");
  TestRegisterRejected(
      "https://www.example.com:8080/",  // Differs by port
      "https://www.example.com/",
      ExpectDOMException("SecurityError",
                         "Failed to register a ServiceWorker: The origin of "
                         "the provided scriptURL "
                         "('https://www.example.com:8080') does not match the "
                         "current origin ('https://www.example.com')."));
}

TEST_F(ServiceWorkerContainerTest, Register_UnsupportedSchemeIsRejected) {
  SetPageURL("https://www.example.com");
  TestRegisterRejected(
      "https://www.example.com",
      "wss://www.example.com/",  // Only support http and https
      ExpectTypeError(
          "Failed to register a ServiceWorker: The URL protocol "
          "of the scope ('wss://www.example.com/') is not supported."));
}

TEST_F(ServiceWorkerContainerTest, Register_CrossOriginScopeIsRejected) {
  SetPageURL("https://www.example.com");
  TestRegisterRejected(
      "https://www.example.com",
      "http://www.example.com/",  // Differs by protocol
      ExpectDOMException("SecurityError",
                         "Failed to register a ServiceWorker: The origin of "
                         "the provided scope ('http://www.example.com') does "
                         "not match the current origin "
                         "('https://www.example.com')."));
}

TEST_F(ServiceWorkerContainerTest, GetRegistration_CrossOriginURLIsRejected) {
  SetPageURL("https://www.example.com/");
  TestGetRegistrationRejected(
      "https://foo.example.com/",  // Differs by host
      ExpectDOMException("SecurityError",
                         "Failed to get a ServiceWorkerRegistration: The "
                         "origin of the provided documentURL "
                         "('https://foo.example.com') does not match the "
                         "current origin ('https://www.example.com')."));
}

class StubWebServiceWorkerProvider {
  DISALLOW_NEW();

 public:
  StubWebServiceWorkerProvider()
      : register_call_count_(0),
        get_registration_call_count_(0),
        script_type_(mojom::blink::ScriptType::kClassic),
        update_via_cache_(mojom::ServiceWorkerUpdateViaCache::kImports) {}

  // Creates a WebServiceWorkerProvider. This can outlive the
  // StubWebServiceWorkerProvider, but |registerServiceWorker| and
  // other methods must not be called after the
  // StubWebServiceWorkerProvider dies.
  std::unique_ptr<WebServiceWorkerProvider> Provider() {
    return std::make_unique<WebServiceWorkerProviderImpl>(*this);
  }

  size_t RegisterCallCount() { return register_call_count_; }
  const WebURL& RegisterScope() { return register_scope_; }
  const WebURL& RegisterScriptURL() { return register_script_url_; }
  size_t GetRegistrationCallCount() { return get_registration_call_count_; }
  const WebURL& GetRegistrationURL() { return get_registration_url_; }
  mojom::blink::ScriptType ScriptType() const { return script_type_; }
  mojom::ServiceWorkerUpdateViaCache UpdateViaCache() const {
    return update_via_cache_;
  }

 private:
  class WebServiceWorkerProviderImpl : public WebServiceWorkerProvider {
   public:
    WebServiceWorkerProviderImpl(StubWebServiceWorkerProvider& owner)
        : owner_(owner) {}

    ~WebServiceWorkerProviderImpl() override = default;

    void RegisterServiceWorker(
        const WebURL& scope,
        const WebURL& script_url,
        blink::mojom::blink::ScriptType script_type,
        mojom::ServiceWorkerUpdateViaCache update_via_cache,
        const WebFetchClientSettingsObject& fetch_client_settings_object,
        std::unique_ptr<WebServiceWorkerRegistrationCallbacks> callbacks)
        override {
      owner_->register_call_count_++;
      owner_->register_scope_ = scope;
      owner_->register_script_url_ = script_url;
      owner_->script_type_ = script_type;
      owner_->update_via_cache_ = update_via_cache;
      registration_callbacks_to_delete_.push_back(std::move(callbacks));
    }

    void GetRegistration(
        const WebURL& document_url,
        std::unique_ptr<WebServiceWorkerGetRegistrationCallbacks> callbacks)
        override {
      owner_->get_registration_call_count_++;
      owner_->get_registration_url_ = document_url;
      get_registration_callbacks_to_delete_.push_back(std::move(callbacks));
    }

    bool ValidateScopeAndScriptURL(const WebURL& scope,
                                   const WebURL& script_url,
                                   WebString* error_message) override {
      return true;
    }

   private:
    const raw_ref<StubWebServiceWorkerProvider> owner_;
    Vector<std::unique_ptr<WebServiceWorkerRegistrationCallbacks>>
        registration_callbacks_to_delete_;
    Vector<std::unique_ptr<WebServiceWorkerGetRegistrationCallbacks>>
        get_registration_callbacks_to_delete_;
  };

 private:
  size_t register_call_count_;
  WebURL register_scope_;
  WebURL register_script_url_;
  size_t get_registration_call_count_;
  WebURL get_registration_url_;
  mojom::blink::ScriptType script_type_;
  mojom::ServiceWorkerUpdateViaCache update_via_cache_;
};

TEST_F(ServiceWorkerContainerTest,
       RegisterUnregister_NonHttpsSecureOriginDelegatesToProvider) {
  SetPageURL("http://localhost/x/index.html");

  StubWebServiceWorkerProvider stub_provider;
  ServiceWorkerContainer* container = ServiceWorkerContainer::CreateForTesting(
      *GetFrame().DomWindow(), stub_provider.Provider());

  // register
  {
    ScriptState::Scope script_scope(GetScriptState());
    RegistrationOptions* options = RegistrationOptions::Create();
    options->setScope("y/");
    container->registerServiceWorker(GetScriptState(), "/x/y/worker.js",
                                     options);

    EXPECT_EQ(1ul, stub_provider.RegisterCallCount());
    EXPECT_EQ(WebURL(KURL("http://localhost/x/y/")),
              stub_provider.RegisterScope());
    EXPECT_EQ(WebURL(KURL("http://localhost/x/y/worker.js")),
              stub_provider.RegisterScriptURL());
    EXPECT_EQ(mojom::blink::ScriptType::kClassic, stub_provider.ScriptType());
    EXPECT_EQ(mojom::ServiceWorkerUpdateViaCache::kImports,
              stub_provider.UpdateViaCache());
  }
}

TEST_F(ServiceWorkerContainerTest,
       GetRegistration_OmittedDocumentURLDefaultsToPageURL) {
  SetPageURL("http://localhost/x/index.html");

  StubWebServiceWorkerProvider stub_provider;
  ServiceWorkerContainer* container = ServiceWorkerContainer::CreateForTesting(
      *GetFrame().DomWindow(), stub_provider.Provider());

  {
    ScriptState::Scope script_scope(GetScriptState());
    container->getRegistration(GetScriptState(), "");
    EXPECT_EQ(1ul, stub_provider.GetRegistrationCallCount());
    EXPECT_EQ(WebURL(KURL("http://localhost/x/index.html")),
              stub_provider.GetRegistrationURL());
    EXPECT_EQ(mojom::blink::ScriptType::kClassic, stub_provider.ScriptType());
    EXPECT_EQ(mojom::ServiceWorkerUpdateViaCache::kImports,
              stub_provider.UpdateViaCache());
  }
}

TEST_F(ServiceWorkerContainerTest,
       RegisterUnregister_UpdateViaCacheOptionDelegatesToProvider) {
  SetPageURL("http://localhost/x/index.html");

  StubWebServiceWorkerProvider stub_provider;
  ServiceWorkerContainer* container = ServiceWorkerContainer::CreateForTesting(
      *GetFrame().DomWindow(), stub_provider.Provider());

  // register
  {
    ScriptState::Scope script_scope(GetScriptState());
    RegistrationOptions* options = RegistrationOptions::Create();
    options->setUpdateViaCache("none");
    container->registerServiceWorker(GetScriptState(), "/x/y/worker.js",
                                     options);

    EXPECT_EQ(1ul, stub_provider.RegisterCallCount());
    EXPECT_EQ(WebURL(KURL(KURL(), "http://localhost/x/y/")),
              stub_provider.RegisterScope());
    EXPECT_EQ(WebURL(KURL(KURL(), "http://localhost/x/y/worker.js")),
              stub_provider.RegisterScriptURL());
    EXPECT_EQ(mojom::blink::ScriptType::kClassic, stub_provider.ScriptType());
    EXPECT_EQ(mojom::ServiceWorkerUpdateViaCache::kNone,
              stub_provider.UpdateViaCache());
  }
}

TEST_F(ServiceWorkerContainerTest, Register_TypeOptionDelegatesToProvider) {
  SetPageURL("http://localhost/x/index.html");

  StubWebServiceWorkerProvider stub_provider;
  ServiceWorkerContainer* container = ServiceWorkerContainer::CreateForTesting(
      *GetFrame().DomWindow(), stub_provider.Provider());

  // register
  {
    ScriptState::Scope script_scope(GetScriptState());
    RegistrationOptions* options = RegistrationOptions::Create();
    options->setType("module");
    container->registerServiceWorker(GetScriptState(), "/x/y/worker.js",
                                     options);

    EXPECT_EQ(1ul, stub_provider.RegisterCallCount());
    EXPECT_EQ(WebURL(KURL(KURL(), "http://localhost/x/y/")),
              stub_provider.RegisterScope());
    EXPECT_EQ(WebURL(KURL(KURL(), "http://localhost/x/y/worker.js")),
              stub_provider.RegisterScriptURL());
    EXPECT_EQ(mojom::blink::ScriptType::kModule, stub_provider.ScriptType());
    EXPECT_EQ(mojom::ServiceWorkerUpdateViaCache::kImports,
              stub_provider.UpdateViaCache());
  }
}

WebServiceWorkerObjectInfo MakeServiceWorkerObjectInfo() {
  return {1,
          mojom::blink::ServiceWorkerState::kActivated,
          WebURL(KURL(KURL(), "http://localhost/x/y/worker.js")),
          {},
          {}};
}

TransferableMessage MakeTransferableMessage() {
  TransferableMessage message;
  message.owned_encoded_message = {0xff, 0x09, '0'};
  message.encoded_message = message.owned_encoded_message;
  message.sender_agent_cluster_id = base::UnguessableToken::Create();
  return message;
}

TEST_F(ServiceWorkerContainerTest, ReceiveMessage) {
  SetPageURL("http://localhost/x/index.html");

  StubWebServiceWorkerProvider stub_provider;
  ServiceWorkerContainer* container = ServiceWorkerContainer::CreateForTesting(
      *GetFrame().DomWindow(), stub_provider.Provider());

  base::RunLoop run_loop;
  auto* wait = MakeGarbageCollected<WaitForEvent>();
  wait->AddEventListener(container, event_type_names::kMessage);
  wait->AddEventListener(container, event_type_names::kMessageerror);
  wait->AddCompletionClosure(run_loop.QuitClosure());
  container->ReceiveMessage(MakeServiceWorkerObjectInfo(),
                            MakeTransferableMessage());
  run_loop.Run();

  auto* event = wait->GetLastEvent();
  EXPECT_EQ(event->type(), event_type_names::kMessage);
}

TEST_F(ServiceWorkerContainerTest, ReceiveMessageLockedToAgentCluster) {
  SetPageURL("http://localhost/x/index.html");

  StubWebServiceWorkerProvider stub_provider;
  ServiceWorkerContainer* container = ServiceWorkerContainer::CreateForTesting(
      *GetFrame().DomWindow(), stub_provider.Provider());

  base::RunLoop run_loop;
  auto* wait = MakeGarbageCollected<WaitForEvent>();
  wait->AddEventListener(container, event_type_names::kMessage);
  wait->AddEventListener(container, event_type_names::kMessageerror);
  wait->AddCompletionClosure(run_loop.QuitClosure());
  auto message = MakeTransferableMessage();
  message.locked_to_sender_agent_cluster = true;
  container->ReceiveMessage(MakeServiceWorkerObjectInfo(), std::move(message));
  run_loop.Run();

  auto* event = wait->GetLastEvent();
  EXPECT_EQ(event->type(), event_type_names::kMessageerror);
}

TEST_F(ServiceWorkerContainerTest, ReceiveMessageWhichCannotDeserialize) {
  SetPageURL("http://localhost/x/index.html");

  StubWebServiceWorkerProvider stub_provider;
  LocalDOMWindow* window = GetFrame().DomWindow();
  ServiceWorkerContainer* container = ServiceWorkerContainer::CreateForTesting(
      *window, stub_provider.Provider());

  SerializedScriptValue::ScopedOverrideCanDeserializeInForTesting
      override_can_deserialize_in(base::BindLambdaForTesting(
          [&](const SerializedScriptValue& value,
              ExecutionContext* execution_context, bool can_deserialize) {
            EXPECT_EQ(execution_context, window);
            EXPECT_TRUE(can_deserialize);
            return false;
          }));

  base::RunLoop run_loop;
  auto* wait = MakeGarbageCollected<WaitForEvent>();
  wait->AddEventListener(container, event_type_names::kMessage);
  wait->AddEventListener(container, event_type_names::kMessageerror);
  wait->AddCompletionClosure(run_loop.QuitClosure());
  container->ReceiveMessage(MakeServiceWorkerObjectInfo(),
                            MakeTransferableMessage());
  run_loop.Run();

  auto* event = wait->GetLastEvent();
  EXPECT_EQ(event->type(), event_type_names::kMessageerror);
}

}  // namespace
}  // namespace blink
```