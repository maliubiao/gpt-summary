Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger test file (`web_frame_test.cc`) in the Chromium Blink engine. The focus should be on how this code relates to JavaScript, HTML, and CSS. I also need to identify any logical inferences made by the code, potential user or programming errors it addresses, and remember this is the second of 19 parts.

Here's a breakdown of the code's functionality:

1. **JavaScript Execution with Promises:**  Several tests (`ExecuteScriptWithPromiseFulfilled`, `ExecuteScriptWithPromiseRejected`, `ExecuteScriptWithFrameRemovalBeforePromiseResolves`, `ExecuteScriptWithMultiplePromises`, etc.) demonstrate how Blink handles JavaScript execution when the script returns a Promise. This includes scenarios where the Promise is resolved, rejected, or the frame is removed before the Promise settles.

2. **Executing Multiple Scripts:** The tests `ExecuteScriptWithMultiplePromises`, `ExecuteScriptWithMultipleSourcesWhereFirstIsPromise`, `ExecuteScriptWithMultipleSourcesWhereLastIsPromise`, `ExecuteScriptWithPromisesWhereOnlyFirstIsFulfilled`, and `ExecuteScriptWithPromisesWhereOnlyLastIsFulfilled` examine how Blink executes multiple JavaScript code snippets sequentially and how the results (especially when Promises are involved) are handled.

3. **Executing V8 Functions Directly:** The `RequestExecuteV8Function` tests show how to directly execute a V8 function within the context of a frame. This is a more low-level way to interact with JavaScript execution. The tests also cover scenarios where execution is attempted while the renderer is suspended.

4. **Iframe Removal from Script:** The `IframeScriptRemovesSelf` test checks the behavior when JavaScript code within an iframe attempts to remove the iframe itself.

5. **Capability Delegation via `postMessage`:** The `CapabilityDelegationMessageEventTest` explores how `postMessage` can be used to delegate capabilities (like payment, fullscreen, display-capture) between frames, particularly when user activation is involved.

6. **Handling Forms:** The `FormWithNullFrame` test appears to check for potential crashes when dealing with form data in a context where the frame might be null.

7. **JavaScript in Chrome Pages:** The `ChromePageJavascript` and `ChromePageNoJavascript` tests verify how JavaScript execution is handled in special "chrome://" pages, including the ability to disallow JavaScript.

8. **Modifying `location`:** The `LocationSetHostWithMissingPort` and `LocationSetEmptyPort` tests examine how setting the `host` and `port` properties of the `location` object in JavaScript affects the URL.

9. **`DidClearWindowObject` Callback:** The `DidClearWindowObjectIsNotRecursive` test checks that the `DidClearWindowObject` callback (which signals the creation of a new JavaScript global object) is not called recursively.

10. **CSS Matching Callbacks:** The `WebFrameCSSCallbackTest` suite focuses on testing the `DidMatchCSS` callback, which allows the browser to notify clients when elements start or stop matching specific CSS selectors. This involves testing scenarios with author stylesheets, shared computed styles, attribute changes, and the `display` property.

Based on this analysis, I can now formulate the summary.
这是 `blink/renderer/core/frame/web_frame_test.cc` 文件的第 2 部分，主要集中在以下功能：

**1. JavaScript 执行与 Promise 处理:**

* **功能:** 测试了在 WebFrame 中执行 JavaScript 代码并处理返回的 Promise 的各种场景。这包括 Promise 成功 resolve、reject 以及在 Promise resolve 前 Frame 被移除的情况。
* **与 JavaScript 的关系:** 这些测试直接涉及到 JavaScript 的 Promise 对象及其生命周期。
* **举例说明:**
    * **假设输入:** JavaScript 代码 `Promise.resolve('hello');`
    * **预期输出:** 回调函数接收到字符串 "hello"。
    * **假设输入:** JavaScript 代码 `Promise.reject('error');`
    * **预期输出:** 回调函数接收到 `std::nullopt`，表示 Promise 被拒绝。
    * **假设输入:**  一个创建了一个永远不会 resolve 的 Promise 的 iframe，然后在 Promise resolve 前移除了该 iframe。
    * **预期输出:**  最初回调函数不会完成，移除 iframe 后回调函数完成并接收到 `std::nullopt`。
* **逻辑推理:**  代码推断 Promise 的状态（resolve 或 reject）并将其转换为 C++ 可以处理的 `base::Value` 或 `std::nullopt`。

**2. 批量 JavaScript 执行:**

* **功能:**  测试了在 WebFrame 中执行多个 JavaScript 代码片段的功能，并验证了返回结果的处理方式，尤其是当其中包含 Promise 时。
* **与 JavaScript 的关系:**  测试了连续执行多个 JavaScript 代码的效果。
* **举例说明:**
    * **假设输入:** JavaScript 代码片段 `["Promise.resolve('hello');", "Promise.resolve('world');"]`
    * **预期输出:** 回调函数接收到最后一个 Promise 的结果 "world"。
    * **假设输入:** JavaScript 代码片段 `["Promise.resolve('hello');", "(new Promise((r) => { window.resolveSecond = r; }));"]`，然后执行 `window.resolveSecond('world');`
    * **预期输出:** 最初回调函数不会完成，执行 `window.resolveSecond('world');` 后，回调函数接收到 "world"。
* **逻辑推理:** 代码需要跟踪多个脚本的执行状态，并返回最后一个脚本的结果。

**3. 直接调用 V8 函数:**

* **功能:**  测试了 `RequestExecuteV8Function` 方法，允许直接在 WebFrame 的 JavaScript 上下文中执行一个 V8 函数。
* **与 JavaScript 的关系:**  这种方式直接操作底层的 V8 引擎，是更细粒度的 JavaScript 执行控制。
* **举例说明:**
    * **假设输入:** 一个 C++ 函数 `callback`，它接收两个参数并返回第二个参数。
    * **预期输出:**  `RequestExecuteV8Function` 调用 `callback`，传入 `undefined` 和字符串 "hello"，最终回调函数接收到 "hello"。
* **用户或编程常见的使用错误:**  在调用 `RequestExecuteV8Function` 时，如果传入了错误的参数数量或类型，可能会导致 JavaScript 运行时错误或崩溃。

**4. 在 Renderer 暂停时执行 JavaScript:**

* **功能:**  测试了当 Renderer 暂停时，调用 `RequestExecuteV8Function` 的行为，以及用户手势如何影响执行。
* **与 JavaScript 的关系:**  涉及到 JavaScript 执行的时机和优先级。
* **举例说明:**
    * **假设输入:**  Renderer 被暂停，调用 `RequestExecuteV8Function` 执行一个返回 "hello" 的函数。
    * **预期输出:**  最初回调函数不会完成，解除 Renderer 暂停后，回调函数接收到 "hello"。
    * **假设输入:** Renderer 被暂停，但存在用户手势激活，执行访问 `navigator.userActivation.isActive` 的脚本。
    * **预期输出:** 最初回调函数不会完成，解除 Renderer 暂停后，回调函数接收到 `true`。

**5. Iframe 自移除脚本:**

* **功能:**  测试了 iframe 中的 JavaScript 代码移除自身时的行为。
* **与 JavaScript 和 HTML 的关系:**  涉及到 JavaScript 操作 DOM 结构，特别是移除 iframe 元素。
* **举例说明:**
    * **假设输入:** iframe 中执行 JavaScript 代码 `var iframe = window.top.document.getElementsByTagName('iframe')[0]; window.top.document.body.removeChild(iframe); 'hello';`
    * **预期输出:** 回调函数完成，但没有返回任何结果（`std::nullopt`），因为 iframe 已经被移除。
* **用户或编程常见的使用错误:** 在 iframe 中尝试访问已经被移除的父窗口或元素可能会导致错误。

**6. Capability Delegation (能力委托) 通过 `postMessage`:**

* **功能:**  测试了通过 `postMessage` 在不同 Frame 之间传递能力委托信息的功能，例如支付、全屏、屏幕捕获等。这需要用户激活才能生效。
* **与 JavaScript 和 HTML 的关系:**  涉及到 JavaScript 的 `postMessage` API 和 HTML 的 iframe 元素，以及浏览器提供的特定能力。
* **举例说明:**
    * **假设输入:**  主 Frame 通过 `postMessage` 向 iframe 发送消息，并带有 `delegate: 'payment'` 选项，且存在用户激活。
    * **预期输出:** iframe 接收到的 `message` 事件的 `delegatedCapability` 属性为 `mojom::blink::DelegatedCapability::kPayment`。
    * **假设输入:**  主 Frame 通过 `postMessage` 发送消息，但没有用户激活。
    * **预期输出:** iframe 接收到的 `delegatedCapability` 为 `mojom::blink::DelegatedCapability::kNone`，即使指定了委托。
* **用户或编程常见的使用错误:**  开发者可能忘记在需要能力委托时添加用户激活，导致委托失败。

**7. 处理空 Frame 的 Form:**

* **功能:** 测试了在某些情况下，当 Form 关联的 Frame 为空时，代码是否能够正常处理，避免崩溃。
* **与 HTML 的关系:** 涉及到 HTML 的 Form 元素。
* **举例说明:** 创建一个包含 Form 的页面，然后移除关联的 Frame，再尝试访问 Form 的数据。这个测试主要是为了防止程序崩溃。

**8. Chrome 页面中的 JavaScript:**

* **功能:** 测试了在 `chrome://` 协议的页面中执行 JavaScript 的行为，包括可以禁止 JavaScript 执行的情况。
* **与 JavaScript 的关系:**  涉及到特定浏览器页面的 JavaScript 执行策略。
* **举例说明:**
    * 加载一个 `chrome://history` 页面，并尝试执行 JavaScript 代码修改页面内容，验证 JavaScript 可以执行。
    * 注册 "chrome" 协议不允许 JavaScript URL 后，再次尝试执行 JavaScript 代码，验证 JavaScript 被阻止。

**9. 修改 `location` 对象:**

* **功能:** 测试了通过 JavaScript 修改 `location.host` 和 `location.port` 属性的行为，特别是处理缺失或为空的端口号。
* **与 JavaScript 和 HTML 的关系:** 涉及到 JavaScript 的 `window.location` 对象和 URL 的解析。
* **举例说明:**
    * 设置 `location.host = 'internal.test:'` 应该被解析为 `internal.test:0`。
    * 设置 `location.port = ''` 应该移除端口号。

**10. `DidClearWindowObject` 回调:**

* **功能:** 测试了 `DidClearWindowObject` 回调函数是否是非递归调用的。该回调在创建新的 JavaScript 全局对象时触发。
* **与 JavaScript 的关系:** 涉及到 JavaScript 全局对象的生命周期。
* **举例说明:**  加载一个空白页面，在 `DidClearWindowObject` 回调中执行 JavaScript 代码，验证回调不会再次触发。

**11. CSS 匹配回调 (`DidMatchCSS`):**

* **功能:**  测试了当 DOM 元素的 CSS 匹配状态发生变化时，通过 `DidMatchCSS` 回调通知客户端的功能。这包括添加/移除样式规则、元素属性变化、`display` 属性变化等场景。
* **与 CSS 的关系:**  直接关联到 CSS 选择器的匹配和渲染过程。
* **举例说明:**
    * 注册监听 `div.initial_on` 选择器，加载包含该元素的 HTML，验证回调被触发。
    * 动态添加/移除元素的 class 属性，观察 `DidMatchCSS` 回调是否被正确触发。
    * 修改元素的 `display` 属性为 `none` 或 `block`，观察回调是否反映了元素的可见性变化。

**总结第 2 部分的功能:**

这部分 `web_frame_test.cc` 文件主要测试了 `WebFrame` 类在处理 JavaScript 执行、Promise、直接 V8 函数调用、iframe 操作、能力委托、特定浏览器页面中的脚本行为、`location` 对象修改以及 CSS 匹配回调等方面的功能。这些测试确保了 Blink 引擎能够正确且安全地执行 JavaScript 代码，处理异步操作，并与渲染引擎协同工作，为 Web 页面的动态行为提供基础保障。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
terForTest` fails to convert the promise to `base::Value`,
  // the callback receives `std::nullopt`.
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_FALSE(callback_helper.HasAnyResults());
}

TEST_F(WebFrameTest, ExecuteScriptWithPromiseFulfilled) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  constexpr char kScript[] = R"(Promise.resolve('hello');)";

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                           kScript, callback_helper.Callback());
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("hello", callback_helper.SingleStringValue());
}

TEST_F(WebFrameTest, ExecuteScriptWithPromiseRejected) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  constexpr char kScript[] = R"(Promise.reject('hello');)";

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                           kScript, callback_helper.Callback());
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  // Promise rejection, similar to errors, are represented by `std::nullopt`
  // passed to the callback.
  EXPECT_FALSE(callback_helper.HasAnyResults());
}

TEST_F(WebFrameTest, ExecuteScriptWithFrameRemovalBeforePromiseResolves) {
  RegisterMockedHttpURLLoad("single_iframe.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "single_iframe.html");

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());

  constexpr char kScript[] = R"((new Promise((r) => {}));)";

  WebLocalFrame* iframe =
      web_view_helper.LocalMainFrame()->FirstChild()->ToWebLocalFrame();
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptInMainWorld(iframe, kScript, callback_helper.Callback());
  RunPendingTasks();
  EXPECT_FALSE(callback_helper.DidComplete());

  constexpr char kRemoveFrameScript[] =
      "var iframe = document.getElementsByTagName('iframe')[0]; "
      "document.body.removeChild(iframe);";
  web_view_helper.LocalMainFrame()->ExecuteScript(
      WebScriptSource(kRemoveFrameScript));
  RunPendingTasks();

  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_FALSE(callback_helper.HasAnyResults());
}

TEST_F(WebFrameTest, ExecuteScriptWithMultiplePromises) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  const String scripts[] = {
      "Promise.resolve('hello');",
      "Promise.resolve('world');",
  };

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptsInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                            scripts, callback_helper.Callback());
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  // The result of the last script is returned.
  EXPECT_EQ("world", callback_helper.SingleStringValue());
}

TEST_F(WebFrameTest, ExecuteScriptWithMultiplePromisesWithDelayedSettlement) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  const String scripts[] = {
      "Promise.resolve('hello');",
      "(new Promise((r) => { window.resolveSecond = r; }));",
  };

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptsInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                            scripts, callback_helper.Callback());
  RunPendingTasks();
  EXPECT_FALSE(callback_helper.DidComplete());

  {
    ScriptExecutionCallbackHelper second_callback_helper;
    ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                             String("window.resolveSecond('world');"),
                             second_callback_helper.Callback());
    RunPendingTasks();
    EXPECT_TRUE(second_callback_helper.DidComplete());
    // `undefined` is mapped to `nullopt`.
    EXPECT_FALSE(second_callback_helper.HasAnyResults());
  }

  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("world", callback_helper.SingleStringValue());
}

TEST_F(WebFrameTest, ExecuteScriptWithMultipleSourcesWhereFirstIsPromise) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  const String scripts[] = {
      "Promise.resolve('hello');",
      "'world';",
  };

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptsInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                            scripts, callback_helper.Callback());
  RunPendingTasks();

  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("world", callback_helper.SingleStringValue());
}

TEST_F(WebFrameTest, ExecuteScriptWithMultipleSourcesWhereLastIsPromise) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  const String scripts[] = {
      "'hello';",
      "Promise.resolve('world');",
  };

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptsInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                            scripts, callback_helper.Callback());
  RunPendingTasks();

  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("world", callback_helper.SingleStringValue());
}

TEST_F(WebFrameTest, ExecuteScriptWithPromisesWhereOnlyFirstIsFulfilled) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  String scripts[] = {
      "Promise.resolve('hello');",
      "Promise.reject('world');",
  };

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptsInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                            scripts, callback_helper.Callback());
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  // Promise rejection, similar to errors, are represented by `std::nullopt`
  // passed to the callback.
  EXPECT_FALSE(callback_helper.HasAnyResults());
}

TEST_F(WebFrameTest, ExecuteScriptWithPromisesWhereOnlyLastIsFulfilled) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  String scripts[] = {
      "Promise.reject('hello');",
      "Promise.resolve('world');",
  };

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptsInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                            scripts, callback_helper.Callback());
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("world", callback_helper.SingleStringValue());
}

TEST_F(WebFrameTest, RequestExecuteV8Function) {
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  auto callback = [](const v8::FunctionCallbackInfo<v8::Value>& info) {
    EXPECT_EQ(2, info.Length());
    EXPECT_TRUE(info[0]->IsUndefined());
    info.GetReturnValue().Set(info[1]);
  };

  v8::Isolate* isolate = web_view_helper.GetAgentGroupScheduler().Isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context =
      web_view_helper.LocalMainFrame()->MainWorldScriptContext();
  ScriptExecutionCallbackHelper callback_helper;
  v8::Local<v8::Function> function =
      v8::Function::New(context, callback).ToLocalChecked();
  v8::Local<v8::Value> args[] = {v8::Undefined(isolate),
                                 V8String(isolate, "hello")};
  web_view_helper.GetWebView()
      ->MainFrame()
      ->ToWebLocalFrame()
      ->RequestExecuteV8Function(context, function, v8::Undefined(isolate),
                                 std::size(args), args,
                                 callback_helper.Callback());
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("hello", callback_helper.SingleStringValue());
}

TEST_F(WebFrameTest, RequestExecuteV8FunctionWhileSuspended) {
  DisableRendererSchedulerThrottling();
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  auto callback = [](const v8::FunctionCallbackInfo<v8::Value>& info) {
    info.GetReturnValue().Set(V8String(info.GetIsolate(), "hello"));
  };

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  v8::Local<v8::Context> context =
      web_view_helper.LocalMainFrame()->MainWorldScriptContext();

  // Suspend scheduled tasks so the script doesn't run.
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  web_view_helper.GetWebView()->GetPage()->SetPaused(true);

  ScriptExecutionCallbackHelper callback_helper;
  v8::Local<v8::Function> function =
      v8::Function::New(context, callback).ToLocalChecked();
  main_frame->RequestExecuteV8Function(context, function,
                                       v8::Undefined(context->GetIsolate()), 0,
                                       nullptr, callback_helper.Callback());
  RunPendingTasks();
  EXPECT_FALSE(callback_helper.DidComplete());

  web_view_helper.GetWebView()->GetPage()->SetPaused(false);
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("hello", callback_helper.SingleStringValue());
}

TEST_F(WebFrameTest, RequestExecuteV8FunctionWhileSuspendedWithUserGesture) {
  DisableRendererSchedulerThrottling();
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());

  // Suspend scheduled tasks so the script doesn't run.
  web_view_helper.GetWebView()->GetPage()->SetPaused(true);
  LocalFrame::NotifyUserActivation(
      web_view_helper.LocalMainFrame()->GetFrame(),
      mojom::UserActivationNotificationType::kTest);
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                           "navigator.userActivation.isActive;",
                           callback_helper.Callback());
  RunPendingTasks();
  EXPECT_FALSE(callback_helper.DidComplete());

  web_view_helper.GetWebView()->GetPage()->SetPaused(false);
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_TRUE(callback_helper.SingleBoolValue());
}

TEST_F(WebFrameTest, IframeScriptRemovesSelf) {
  RegisterMockedHttpURLLoad("single_iframe.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "single_iframe.html");

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());
  ScriptExecutionCallbackHelper callback_helper;
  ExecuteScriptInMainWorld(
      web_view_helper.GetWebView()
          ->MainFrame()
          ->FirstChild()
          ->ToWebLocalFrame(),
      "var iframe = window.top.document.getElementsByTagName('iframe')[0]; "
      "window.top.document.body.removeChild(iframe); 'hello';",
      callback_helper.Callback());
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_FALSE(callback_helper.HasAnyResults());
}

namespace {

class CapabilityDelegationMessageListener final : public NativeEventListener {
 public:
  void Invoke(ExecutionContext*, Event* event) override {
    delegated_capability_ =
        static_cast<MessageEvent*>(event)->delegatedCapability();
  }

  bool DelegateCapability() {
    if (delegated_capability_ == mojom::blink::DelegatedCapability::kNone)
      return false;
    delegated_capability_ = mojom::blink::DelegatedCapability::kNone;
    return true;
  }

 private:
  mojom::blink::DelegatedCapability delegated_capability_ =
      mojom::blink::DelegatedCapability::kNone;
};

}  // namespace

TEST_F(WebFrameTest, CapabilityDelegationMessageEventTest) {
  RegisterMockedHttpURLLoad("single_iframe.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "single_iframe.html");

  auto* main_frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
  auto* child_frame = To<LocalFrame>(main_frame->FirstChild());
  DCHECK(main_frame);
  DCHECK(child_frame);

  auto* message_event_listener =
      MakeGarbageCollected<CapabilityDelegationMessageListener>();
  child_frame->GetDocument()->domWindow()->addEventListener(
      event_type_names::kMessage, message_event_listener);

  v8::HandleScope scope(web_view_helper.GetAgentGroupScheduler().Isolate());

  {
    String post_message_wo_request(
        "window.frames[0].postMessage('0', {targetOrigin: '/'});");
    String post_message_w_payment_request(
        "window.frames[0].postMessage("
        "'1', {targetOrigin: '/', delegate: 'payment'});");

    // The delegation info is not passed through a postMessage that is sent
    // without either user activation or the delegation option.
    {
      ScriptExecutionCallbackHelper callback_helper;
      ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                               post_message_wo_request,
                               callback_helper.Callback());
      RunPendingTasks();
      EXPECT_TRUE(callback_helper.DidComplete());
      EXPECT_FALSE(message_event_listener->DelegateCapability());
    }

    // The delegation info is not passed through a postMessage that is sent
    // without user activation but with the delegation option.
    {
      ScriptExecutionCallbackHelper callback_helper;
      ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                               post_message_w_payment_request,
                               callback_helper.Callback());
      RunPendingTasks();
      EXPECT_TRUE(callback_helper.DidComplete());
      EXPECT_FALSE(message_event_listener->DelegateCapability());
    }

    // The delegation info is not passed through a postMessage that is sent with
    // user activation but without the delegation option.
    {
      ScriptExecutionCallbackHelper callback_helper;
      ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                               post_message_wo_request,
                               callback_helper.Callback(),
                               blink::mojom::PromiseResultOption::kAwait,
                               blink::mojom::UserActivationOption::kActivate);
      RunPendingTasks();
      EXPECT_TRUE(callback_helper.DidComplete());
      EXPECT_FALSE(message_event_listener->DelegateCapability());
    }

    // The delegation info is passed through a postMessage that is sent with
    // both user activation and the delegation option.
    {
      ScriptExecutionCallbackHelper callback_helper;
      ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                               post_message_w_payment_request,
                               callback_helper.Callback(),
                               blink::mojom::PromiseResultOption::kAwait,
                               blink::mojom::UserActivationOption::kActivate);
      RunPendingTasks();
      EXPECT_TRUE(callback_helper.DidComplete());
      EXPECT_TRUE(message_event_listener->DelegateCapability());
    }
  }

  {
    String post_message_w_fullscreen_request(
        "window.frames[0].postMessage("
        "'1', {targetOrigin: '/', delegate: 'fullscreen'});");

    // The delegation info is passed through a postMessage that is sent with
    // both user activation and the delegation option for another known
    // capability.
    ScriptExecutionCallbackHelper callback_helper;
    ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                             post_message_w_fullscreen_request,
                             callback_helper.Callback(),
                             blink::mojom::PromiseResultOption::kAwait,
                             blink::mojom::UserActivationOption::kActivate);
    RunPendingTasks();
    EXPECT_TRUE(callback_helper.DidComplete());
    EXPECT_TRUE(message_event_listener->DelegateCapability());
  }

  {
    String post_message_w_display_capture_request(
        "window.frames[0].postMessage("
        "'1', {targetOrigin: '/', delegate: 'display-capture'});");

    // The delegation info is passed through a postMessage that is sent with
    // both user activation and the delegation option for another known
    // capability.
    ScriptExecutionCallbackHelper callback_helper;
    ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                             post_message_w_display_capture_request,
                             callback_helper.Callback(),
                             blink::mojom::PromiseResultOption::kAwait,
                             blink::mojom::UserActivationOption::kActivate);
    RunPendingTasks();
    EXPECT_TRUE(callback_helper.DidComplete());
    EXPECT_TRUE(message_event_listener->DelegateCapability());
  }

  {
    String post_message_w_unknown_request(
        "window.frames[0].postMessage("
        "'1', {targetOrigin: '/', delegate: 'foo'});");

    // The delegation info is not passed through a postMessage that is sent with
    // user activation and the delegation option for an unknown capability.
    ScriptExecutionCallbackHelper callback_helper;
    ExecuteScriptInMainWorld(web_view_helper.GetWebView()->MainFrameImpl(),
                             post_message_w_unknown_request,
                             callback_helper.Callback(),
                             blink::mojom::PromiseResultOption::kAwait,
                             blink::mojom::UserActivationOption::kActivate);
    RunPendingTasks();
    EXPECT_TRUE(callback_helper.DidComplete());
    EXPECT_FALSE(message_event_listener->DelegateCapability());
  }
}

TEST_F(WebFrameTest, FormWithNullFrame) {
  RegisterMockedHttpURLLoad("form.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "form.html");

  WebVector<WebFormElement> forms =
      web_view_helper.LocalMainFrame()->GetDocument().Forms();
  web_view_helper.Reset();

  EXPECT_EQ(forms.size(), 1u);

  // This test passes if this doesn't crash.
  WebSearchableFormData searchable_data_form(forms[0]);
}

TEST_F(WebFrameTest, ChromePageJavascript) {
  RegisterMockedChromeURLLoad("history.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(chrome_url_ + "history.html");

  // Try to run JS against the chrome-style URL.
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                "javascript:document.body.appendChild(document."
                                "createTextNode('Clobbered'))");

  // Now retrieve the frame's text and ensure it was modified by running
  // javascript.
  std::string content = TestWebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_NE(std::string::npos, content.find("Clobbered"));
}

TEST_F(WebFrameTest, ChromePageNoJavascript) {
  RegisterMockedChromeURLLoad("history.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(chrome_url_ + "history.html");

  // Try to run JS against the chrome-style URL after prohibiting it.
#if DCHECK_IS_ON()
  // TODO(crbug.com/1329535): Remove if threaded preload scanner doesn't launch.
  // This is needed because the preload scanner creates a thread when loading a
  // page.
  WTF::SetIsBeforeThreadCreatedForTest();
#endif
  WebSecurityPolicy::RegisterURLSchemeAsNotAllowingJavascriptURLs("chrome");
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                "javascript:document.body.appendChild(document."
                                "createTextNode('Clobbered'))");

  // Now retrieve the frame's text and ensure it wasn't modified by running
  // javascript.
  std::string content = TestWebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_EQ(std::string::npos, content.find("Clobbered"));
}

TEST_F(WebFrameTest, LocationSetHostWithMissingPort) {
  std::string file_name = "print-location-href.html";
  RegisterMockedHttpURLLoad(file_name);
  // TODO(crbug.com/751425): We should use the mock functionality
  // via the WebViewHelper instance in each test case.
  RegisterMockedURLLoadFromBase("http://internal.test:0/", file_name);

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + file_name);

  // Setting host to "hostname:" should be treated as "hostname:0".
  frame_test_helpers::LoadFrame(
      web_view_helper.GetWebView()->MainFrameImpl(),
      "javascript:location.host = 'internal.test:'; void 0;");

  frame_test_helpers::LoadFrame(
      web_view_helper.GetWebView()->MainFrameImpl(),
      "javascript:document.body.textContent = location.href; void 0;");

  std::string content = TestWebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_EQ("http://internal.test/" + file_name, content);
}

TEST_F(WebFrameTest, LocationSetEmptyPort) {
  std::string file_name = "print-location-href.html";
  RegisterMockedHttpURLLoad(file_name);
  // TODO(crbug.com/751425): We should use the mock functionality
  // via the WebViewHelper instance in each test case.
  RegisterMockedURLLoadFromBase("http://internal.test:0/", file_name);

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + file_name);

  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                "javascript:location.port = ''; void 0;");

  frame_test_helpers::LoadFrame(
      web_view_helper.GetWebView()->MainFrameImpl(),
      "javascript:document.body.textContent = location.href; void 0;");

  std::string content = TestWebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_EQ("http://internal.test/" + file_name, content);
}

class EvaluateOnLoadWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  EvaluateOnLoadWebFrameClient() = default;
  ~EvaluateOnLoadWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void DidClearWindowObject() override {
    EXPECT_FALSE(executing_);
    was_executed_ = true;
    executing_ = true;
    v8::HandleScope handle_scope(Frame()->GetAgentGroupScheduler()->Isolate());
    Frame()->ExecuteScriptAndReturnValue(
        WebScriptSource(WebString("window.someProperty = 42;")));
    executing_ = false;
  }

  bool executing_ = false;
  bool was_executed_ = false;
};

TEST_F(WebFrameTest, DidClearWindowObjectIsNotRecursive) {
  EvaluateOnLoadWebFrameClient web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", &web_frame_client);
  EXPECT_TRUE(web_frame_client.was_executed_);
}

class CSSCallbackWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  CSSCallbackWebFrameClient() : update_count_(0) {}
  ~CSSCallbackWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void DidMatchCSS(
      const WebVector<WebString>& newly_matching_selectors,
      const WebVector<WebString>& stopped_matching_selectors) override;

  HashSet<String>& MatchedSelectors() {
    auto it = matched_selectors_.find(Frame());
    if (it != matched_selectors_.end())
      return it->value;

    auto add_result = matched_selectors_.insert(Frame(), HashSet<String>());
    return add_result.stored_value->value;
  }

  HashMap<WebLocalFrame*, HashSet<String>> matched_selectors_;
  int update_count_;
};

void CSSCallbackWebFrameClient::DidMatchCSS(
    const WebVector<WebString>& newly_matching_selectors,
    const WebVector<WebString>& stopped_matching_selectors) {
  ++update_count_;

  HashSet<String>& frame_selectors = MatchedSelectors();
  for (size_t i = 0; i < newly_matching_selectors.size(); ++i) {
    String selector = newly_matching_selectors[i];
    EXPECT_TRUE(frame_selectors.find(selector) == frame_selectors.end())
        << selector;
    frame_selectors.insert(selector);
  }
  for (size_t i = 0; i < stopped_matching_selectors.size(); ++i) {
    String selector = stopped_matching_selectors[i];
    EXPECT_TRUE(frame_selectors.find(selector) != frame_selectors.end())
        << selector;
    frame_selectors.erase(selector);
    EXPECT_TRUE(frame_selectors.find(selector) == frame_selectors.end())
        << selector;
  }
}

class WebFrameCSSCallbackTest : public testing::Test {
 protected:
  WebFrameCSSCallbackTest() {
    frame_ = helper_.InitializeAndLoad("about:blank", &client_)
                 ->MainFrame()
                 ->ToWebLocalFrame();
  }

  ~WebFrameCSSCallbackTest() override {
    EXPECT_EQ(1U, client_.matched_selectors_.size());
  }

  WebDocument Doc() const { return frame_->GetDocument(); }

  int UpdateCount() const { return client_.update_count_; }

  const HashSet<String>& MatchedSelectors() {
    auto it = client_.matched_selectors_.find(frame_);
    if (it != client_.matched_selectors_.end())
      return it->value;

    auto add_result =
        client_.matched_selectors_.insert(frame_, HashSet<String>());
    return add_result.stored_value->value;
  }

  void LoadHTML(const std::string& html) {
    frame_test_helpers::LoadHTMLString(frame_, html, ToKURL("about:blank"));
  }

  void ExecuteScript(const WebString& code) {
    frame_->ExecuteScript(WebScriptSource(code));
    frame_->View()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
    RunPendingTasks();
  }

  test::TaskEnvironment task_environment_;
  CSSCallbackWebFrameClient client_;
  frame_test_helpers::WebViewHelper helper_;
  WebLocalFrame* frame_;
};

TEST_F(WebFrameCSSCallbackTest, AuthorStyleSheet) {
  LoadHTML(
      "<style>"
      // This stylesheet checks that the internal property and value can't be
      // set by a stylesheet, only WebDocument::watchCSSSelectors().
      "div.initial_on { -internal-callback: none; }"
      "div.initial_off { -internal-callback: -internal-presence; }"
      "</style>"
      "<div class=\"initial_on\"></div>"
      "<div class=\"initial_off\"></div>");

  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("div.initial_on"));
  frame_->GetDocument().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  RunPendingTasks();
  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("div.initial_on"));

  // Check that adding a watched selector calls back for already-present nodes.
  selectors.push_back(WebString::FromUTF8("div.initial_off"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  RunPendingTasks();
  EXPECT_EQ(2, UpdateCount());
  EXPECT_THAT(MatchedSelectors(),
              UnorderedElementsAre("div.initial_off", "div.initial_on"));

  // Check that we can turn off callbacks for certain selectors.
  Doc().WatchCSSSelectors(WebVector<WebString>());
  frame_->View()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  RunPendingTasks();
  EXPECT_EQ(3, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre());
}

TEST_F(WebFrameCSSCallbackTest, SharedComputedStyle) {
  // Check that adding an element calls back when it matches an existing rule.
  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));

  ExecuteScript(
      "i1 = document.createElement('span');"
      "i1.id = 'first_span';"
      "document.body.appendChild(i1)");
  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  // Adding a second element that shares a ComputedStyle shouldn't call back.
  // We use <span>s to avoid default style rules that can set
  // ComputedStyle::unique().
  ExecuteScript(
      "i2 = document.createElement('span');"
      "i2.id = 'second_span';"
      "i1 = document.getElementById('first_span');"
      "i1.parentNode.insertBefore(i2, i1.nextSibling);");
  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  // Removing the first element shouldn't call back.
  ExecuteScript(
      "i1 = document.getElementById('first_span');"
      "i1.parentNode.removeChild(i1);");
  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  // But removing the second element *should* call back.
  ExecuteScript(
      "i2 = document.getElementById('second_span');"
      "i2.parentNode.removeChild(i2);");
  EXPECT_EQ(2, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre());
}

TEST_F(WebFrameCSSCallbackTest, CatchesAttributeChange) {
  LoadHTML("<span></span>");

  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span[attr=\"value\"]"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  RunPendingTasks();

  EXPECT_EQ(0, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre());

  ExecuteScript(
      "document.querySelector('span').setAttribute('attr', 'value');");
  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span[attr=\"value\"]"));
}

TEST_F(WebFrameCSSCallbackTest, DisplayNone) {
  LoadHTML("<div style='display:none'><span></span></div>");

  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  RunPendingTasks();

  EXPECT_EQ(0, UpdateCount()) << "Don't match elements in display:none trees.";

  ExecuteScript(
      "d = document.querySelector('div');"
      "d.style.display = 'block';");
  EXPECT_EQ(1, UpdateCount()) << "Match elements when they become displayed.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "d = document.querySelector('div');"
      "d.style.display = 'none';");
  EXPECT_EQ(2, UpdateCount())
      << "Unmatch elements when they become undisplayed.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre());

  ExecuteScript(
      "s = document.querySelector('span');"
      "s.style.display = 'none';");
  EXPECT_EQ(2, UpdateCount())
      << "No effect from no-display'ing a span that's already undisplayed.";

  ExecuteScript(
      "d = document.querySelector('div');"
      "d.style.display = 'block';");
  EXPECT_EQ(2, UpdateCount())
      << "No effect from displaying a div whose span is display:none.";

  ExecuteScript(
      "s = document.querySelector('span');"
      "s.style.display = 'inline';");
  EXPECT_EQ(3, UpdateCount())
      << "Now the span is visible and produces a callback.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "s = document.querySelector('span');"
      "s.style.display = 'none';");
  EXPECT_EQ(4, UpdateCount())
      << "Undisplaying the span directly should produce another callback.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre());
}

TEST_F(WebFrameCSSCallbackTest, DisplayCo
```