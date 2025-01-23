Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `activity_logger_test.cc` immediately suggests that this code tests the functionality of an "activity logger."  The `blink` namespace and inclusion of files like `v8_dom_activity_logger.h` further solidify this. The core purpose is to verify that the `V8DOMActivityLogger` is correctly logging specific actions performed in the Blink rendering engine.

2. **Examine the Test Structure:**  The file uses the `gtest` framework. This means looking for `TEST_F` macros, which define individual test cases. We also see a `class ActivityLoggerTest : public testing::Test`, which sets up the testing environment.

3. **Analyze the `TestActivityLogger` Class:** This custom class inherits from `V8DOMActivityLogger`. This is a strong clue that it's designed to *observe* and *record* the activities logged by the real `V8DOMActivityLogger`. The key methods to focus on are `LogGetter`, `LogSetter`, `LogMethod`, and `LogEvent`. These methods simply append strings representing the logged activity to a `logged_activities_` vector. The `VerifyActivities` method compares the logged activities with expected values.

4. **Understand the Setup in `ActivityLoggerTest`:**
    * An instance of `TestActivityLogger` is created.
    * `V8DOMActivityLogger::SetActivityLogger` is called. This is crucial! It *replaces* the default activity logger with our test logger. This allows the tests to capture the logged events. The `kIsolatedWorldId` suggests this logger is specifically for isolated JavaScript environments (like extensions or user scripts).
    * `WebViewHelper` is used to create a test web page environment.
    * `ExecuteScriptInMainWorld` and `ExecuteScriptInIsolatedWorld` are helper functions to run JavaScript code in different contexts.

5. **Dissect Individual Test Cases:** Each `TEST_F` function focuses on a specific scenario:
    * **Event Handler:**  Checks logging when event listeners are added (using `onclick`, `onchange`, `setAttribute('on...')`, `addEventListener`).
    * **Element Creation:** Tests logging when various HTML elements (`script`, `iframe`, `a`, `link`, `input`, `button`, `form`) are created, especially when their `src` or `href` attributes are set (triggering resource requests).
    * **Attribute Manipulation:** Focuses on logging when specific attributes (like `src`, `href`, `formaction`) of different elements are set via JavaScript. It checks different ways of setting attributes: direct property assignment, `setAttribute`, and `setAttributeNode`.
    * **`LocalDOMWindow` Attributes:** Tests changes to the `location` object (setting `href`, `assign`, `replace`, `protocol`, etc.), which are critical for navigation.
    * **Resource Requests:**  Covers scenarios that trigger network requests (iframes, images, stylesheets, scripts, XHR).

6. **Identify Connections to Web Technologies:**  The test cases directly manipulate HTML elements and their attributes, and trigger actions that are fundamental to how web pages work:
    * **JavaScript:**  The tests execute JavaScript code to create and modify elements and their properties.
    * **HTML:** The tests create and manipulate HTML elements like `<a>`, `<script>`, `<iframe>`, etc.
    * **CSS:** The tests involve `<link>` elements with `rel="stylesheet"` and data URLs for CSS, demonstrating logging related to CSS loading.
    * **URLs and Resource Loading:** The frequent use of `data:` URLs and the "blinkRequestResource" log entries highlight the connection to how the browser fetches resources.
    * **Events:** The "EventHandler" test directly deals with JavaScript event handling.

7. **Infer Logic and Reasoning:** The tests follow a clear pattern:
    * **Setup:** Create a basic HTML page.
    * **Action:** Execute JavaScript code that performs a specific action (e.g., adding an event listener, creating an element).
    * **Verification:** Check the `activity_logger_` to see if the expected log entries are present.
    * **Isolated vs. Main World:**  The tests often run the same JavaScript in both the main world and an isolated world. This is likely to ensure the logger works correctly in different JavaScript contexts. The fact that the main world execution often produces empty logs suggests the logger is specifically targeting isolated worlds.

8. **Consider User/Developer Errors:**
    * **Incorrect `data:` URLs:** The tests use `data:` URLs extensively. A common error is to format these URLs incorrectly, leading to resource loading failures. The logger can help diagnose if a URL was even *attempted* to be loaded.
    * **Misunderstanding Isolated Worlds:** Developers might not realize their extension/user script code runs in an isolated world and that certain APIs might behave differently or be restricted. The logger helps understand what actions are being tracked in that context.
    * **Event Listener Issues:** Forgetting to add an event listener or adding it to the wrong element can lead to unexpected behavior. The logger can confirm if the `addEventListener` call was actually made.
    * **Attribute Naming Errors:**  Typos in attribute names when using `setAttribute` will prevent the attribute from being set correctly. The logger records the attempted attribute setting.

9. **Trace User Actions (Debugging Clues):**  To reach the logged activities, a user would typically:
    1. **Load a web page:** This starts the rendering process.
    2. **Interact with the page or have JavaScript execute:** This triggers the JavaScript code that creates elements, sets attributes, or adds event listeners. Specifically for these tests, the JavaScript code being tested is what drives the actions.
    3. **(In the case of isolated worlds):**  The user might have an extension or user script installed that modifies the page. The logger is particularly relevant here.
    4. **A developer debugging:** A developer might enable this type of logging to understand what actions their JavaScript code (or third-party code) is performing.

By systematically examining the code structure, individual tests, and the purpose of the `TestActivityLogger`, we can deduce the functionality and its relationship to web technologies. The inclusion of both main world and isolated world tests is a key observation, leading to the understanding that this logger is likely focused on activities within isolated JavaScript environments.
这个C++源代码文件 `activity_logger_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件，专门用于测试 `V8DOMActivityLogger` 类的功能。 `V8DOMActivityLogger` 的作用是记录在 V8 JavaScript 虚拟机中发生的与 DOM 相关的活动。

**功能列举:**

1. **测试 `V8DOMActivityLogger` 的日志记录功能:**  该文件通过模拟各种 JavaScript 操作，例如创建 DOM 元素、设置属性、添加事件监听器等，来验证 `V8DOMActivityLogger` 是否正确地记录了这些活动。
2. **验证不同类型的 DOM 活动是否被正确记录:** 测试涵盖了获取器 (getter)、设置器 (setter)、方法调用 (method) 和事件触发 (event) 等不同类型的 DOM 操作。
3. **测试在隔离的 JavaScript 环境中的日志记录:** 代码中区分了在主世界 (main world) 和隔离世界 (isolated world) 中执行脚本的情况，表明该文件也测试了在扩展或其他隔离的 JavaScript 环境中的日志记录功能。
4. **提供调试信息:**  通过记录这些活动，`V8DOMActivityLogger` 可以帮助开发者理解和调试 JavaScript 代码与 DOM 的交互。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联到 JavaScript 与 HTML 和 CSS 的交互，因为它模拟了 JavaScript 代码如何操作 DOM。以下是具体的例子：

* **JavaScript 创建和操作 HTML 元素:**
    * 测试代码中使用了 `document.body.innerHTML = '<a onclick=\\\'do()\\\'>test</a>';` 来创建一个 `<a>` 元素并设置 `onclick` 属性。`V8DOMActivityLogger` 应该记录下元素的创建和属性的设置。
    * `document.createElement('script')` 和 `document.body.appendChild(script)`  用于动态创建和添加 `<script>` 元素，这也会被记录。
* **JavaScript 设置 HTML 元素的属性:**
    * `script.src = 'data:text/javascript;charset=utf-8,B';` 和 `script.setAttribute('src', 'data:text/javascript;charset=utf-8,C');` 测试了通过 JavaScript 设置 `<script>` 元素的 `src` 属性。
    *  类似地，测试了 `<a>`, `<iframe>`, `<link>`, `<input>`, `<button>`, `<form>` 等元素的属性设置，例如 `a.href = ...`, `iframe.src = ...`。
* **JavaScript 添加事件监听器:**
    * `document.body.addEventListener('onload', function(){});` 测试了 `addEventListener` 方法的使用，`V8DOMActivityLogger` 应该记录下事件类型和目标元素。
* **JavaScript 修改 CSS 相关属性 (间接):**
    * 虽然测试中没有直接修改 CSS 属性，但通过创建 `<link rel='stylesheet' href='...'>` 元素，间接地触发了 CSS 资源的加载。`V8DOMActivityLogger` 应该记录下资源请求。
* **JavaScript 操作 `window.location` (涉及导航):**
    * `location.href = ...`, `location.assign(...)`, `location.replace(...)` 等操作会改变页面的 URL，这也会被 `V8DOMActivityLogger` 记录。

**逻辑推理 (假设输入与输出):**

假设有以下 JavaScript 代码在隔离世界中执行：

```javascript
const div = document.createElement('div');
div.id = 'myDiv';
document.body.appendChild(div);
div.addEventListener('click', () => { console.log('Clicked!'); });
```

**假设输入:** 上述 JavaScript 代码字符串。

**预期输出 (根据测试代码的逻辑):**

```
blinkAddElement | div |
blinkSetAttribute | div | id |  | myDiv
blinkAddEventListener | BODY | click
```

* `blinkAddElement | div | `:  记录了 `<div>` 元素的创建。
* `blinkSetAttribute | div | id |  | myDiv`: 记录了 `<div>` 元素的 `id` 属性被设置为 `myDiv`。
* `blinkAddEventListener | BODY | click`: 记录了在 `<body>` 元素上添加了一个 `click` 事件监听器。

**涉及用户或者编程常见的使用错误及举例说明:**

1. **拼写错误导致事件监听器未生效:** 用户可能错误地将 `addEventListener` 写成 `addEventListner`，导致事件监听器没有被正确添加。`V8DOMActivityLogger` 会记录下 `blinkAddEventListener` 调用 (如果参数正确)，但可能无法记录到实际的事件处理。

   ```javascript
   // 错误示例
   document.getElementById('myButton').addEventListner('click', () => { /* ... */ });

   // 日志可能显示类似：
   // blinkAddEventListener | BUTTON | click  (如果 V8 没有直接报错)
   ```

2. **在不正确的元素上添加事件监听器:** 用户可能尝试在一个不支持特定事件的元素上添加监听器，或者在元素被移除后仍然尝试添加。

   ```javascript
   // 错误示例：尝试在 <div> 上监听 'load' 事件
   document.createElement('div').addEventListener('load', () => {});

   // 日志可能显示：
   // blinkAddEventListener | DIV | load
   ```

3. **错误地设置 `src` 或 `href` 属性:** 用户可能将 `src` 或 `href` 设置为无效的 URL，导致资源加载失败。 `V8DOMActivityLogger` 会记录下属性的设置和可能的资源请求 (即使请求失败)。

   ```javascript
   // 错误示例：设置一个不存在的图片 URL
   const img = document.createElement('img');
   img.src = 'nonexistent_image.jpg';
   document.body.appendChild(img);

   // 日志可能显示：
   // blinkAddElement | img | nonexistent_image.jpg
   // blinkRequestResource | Image | nonexistent_image.jpg
   ```

**说明用户操作是如何一步步的到达这里，作为调试线索:**

要触发 `V8DOMActivityLogger` 并看到这些日志记录，通常涉及以下步骤：

1. **用户加载一个网页:**  当用户在浏览器中输入网址或点击链接时，浏览器开始加载网页的 HTML 内容。
2. **浏览器解析 HTML 并构建 DOM 树:**  Blink 引擎会解析 HTML 代码，并构建一个表示页面结构的 DOM 树。
3. **浏览器执行 JavaScript 代码:**  网页中包含的 `<script>` 标签内的 JavaScript 代码会被 V8 引擎执行。
4. **JavaScript 代码操作 DOM:**  JavaScript 代码可能会创建、修改或删除 DOM 元素，设置属性，添加事件监听器等。这些操作会触发 `V8DOMActivityLogger` 的日志记录。
5. **(针对隔离世界):** 如果用户安装了浏览器扩展或使用了用户脚本，这些脚本运行在隔离的 JavaScript 环境中，它们对 DOM 的操作也会被记录 (如测试代码所示，重点测试了隔离世界)。

**作为调试线索:**

* **分析 `blinkAddElement` 日志:**  可以追踪哪些元素被 JavaScript 代码动态创建。如果页面上出现了不期望的元素，可以查看是否是由某个脚本创建的。
* **分析 `blinkSetAttribute` 日志:**  可以追踪元素属性的修改。如果元素的属性值不正确，可以查看是哪个脚本在何时修改了它。
* **分析 `blinkAddEventListener` 日志:** 可以了解哪些事件监听器被添加到哪些元素上。如果某个事件没有被正确处理，可以检查监听器是否被正确添加。
* **分析 `blinkRequestResource` 日志:**  可以追踪页面加载的各种资源 (脚本、样式表、图片等)。如果资源加载失败或加载了不期望的资源，可以查看是哪个操作触发了资源请求。

总而言之， `activity_logger_test.cc` 这个文件通过一系列单元测试，确保了 `V8DOMActivityLogger` 能够准确地记录 JavaScript 代码与 DOM 交互的各种活动，这对于理解和调试复杂的 Web 应用程序至关重要。尤其是在涉及到浏览器扩展或用户脚本等隔离环境时，该日志记录功能可以提供宝贵的调试信息。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/activity_logger_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "base/memory/ptr_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_cache.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_activity_logger.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "v8/include/v8.h"

namespace blink {

using blink::frame_test_helpers::WebViewHelper;
using blink::frame_test_helpers::PumpPendingRequestsForFrameToLoad;

class TestActivityLogger : public V8DOMActivityLogger {
 public:
  ~TestActivityLogger() override = default;

  void LogGetter(ScriptState* script_state, const String& api_name) override {
    logged_activities_.push_back(api_name);
  }

  void LogSetter(ScriptState* script_state,
                 const String& api_name,
                 const v8::Local<v8::Value>& new_value) override {
    logged_activities_.push_back(api_name + " | " +
                                 ToCoreStringWithUndefinedOrNullCheck(
                                     script_state->GetIsolate(), new_value));
  }

  void LogMethod(ScriptState* script_state,
                 const String& api_name,
                 base::span<const v8::Local<v8::Value>> args) override {
    String activity_string = api_name;
    for (const auto& arg : args) {
      activity_string =
          activity_string + " | " +
          ToCoreStringWithUndefinedOrNullCheck(script_state->GetIsolate(), arg);
    }
    logged_activities_.push_back(activity_string);
  }

  void LogEvent(ExecutionContext* execution_context,
                const String& event_name,
                base::span<const String> args) override {
    String activity_string = event_name;
    for (const auto& arg : args) {
      activity_string = activity_string + " | " + arg;
    }
    logged_activities_.push_back(activity_string);
  }

  void clear() { logged_activities_.clear(); }
  bool VerifyActivities(const Vector<String>& expected) const {
    EXPECT_EQ(expected.size(), logged_activities_.size());
    for (wtf_size_t i = 0;
         i < std::min(expected.size(), logged_activities_.size()); ++i) {
      EXPECT_EQ(expected[i], logged_activities_[i]);
    }
    return logged_activities_ == expected;
  }

 private:
  Vector<String> logged_activities_;
};

class ActivityLoggerTest : public testing::Test {
 protected:
  ActivityLoggerTest() {
    activity_logger_ = new TestActivityLogger();
    V8DOMActivityLogger::SetActivityLogger(kIsolatedWorldId, String(),
                                           base::WrapUnique(activity_logger_));
    web_view_helper_.Initialize();
    local_frame_ = web_view_helper_.GetWebView()->MainFrameImpl()->GetFrame();
    frame_test_helpers::LoadFrame(
        web_view_helper_.GetWebView()->MainFrameImpl(), "about:blank");
  }

  ~ActivityLoggerTest() override {
    WebCache::Clear();
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

  void ExecuteScriptInMainWorld(const String& script) const {
    ClassicScript::CreateUnspecifiedScript(script)->RunScript(
        local_frame_->DomWindow());
    PumpPendingRequestsForFrameToLoad(web_view_helper_.LocalMainFrame());
  }

  void ExecuteScriptInIsolatedWorld(const String& script) const {
    v8::HandleScope scope(local_frame_->DomWindow()->GetIsolate());
    ClassicScript::CreateUnspecifiedScript(script)
        ->RunScriptInIsolatedWorldAndReturnValue(local_frame_->DomWindow(),
                                                 kIsolatedWorldId);
    PumpPendingRequestsForFrameToLoad(web_view_helper_.LocalMainFrame());
  }

  bool VerifyActivities(const String& activities) {
    Vector<String> activity_vector;
    activities.Split("\n", activity_vector);
    return activity_logger_->VerifyActivities(activity_vector);
  }

 private:
  static const int kIsolatedWorldId = 1;

  test::TaskEnvironment task_environment_;
  WebViewHelper web_view_helper_;
  Persistent<LocalFrame> local_frame_;
  // TestActivityLogger is owned by a static table within V8DOMActivityLogger
  // and should be alive as long as not overwritten.
  TestActivityLogger* activity_logger_;
};

TEST_F(ActivityLoggerTest, EventHandler) {
  const char* code =
      "document.body.innerHTML = '<a onclick=\\\'do()\\\'>test</a>';"
      "document.body.onchange = function(){};"
      "document.body.setAttribute('onfocus', 'fnc()');"
      "document.body.addEventListener('onload', function(){});";
  const char* expected_activities =
      "blinkAddEventListener | A | click\n"
      "blinkAddElement | a | \n"
      "blinkAddEventListener | BODY | change\n"
      "blinkAddEventListener | DOMWindow | focus\n"
      "blinkAddEventListener | BODY | onload";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, ScriptElement) {
  const char* code =
      "document.body.innerHTML = '<script "
      "src=\\\'data:text/javascript;charset=utf-8,\\\'></script>';"
      "document.body.innerHTML = '<script>console.log(\\\'test\\\')</script>';"
      "var script = document.createElement('script');"
      "document.body.appendChild(script);"
      "script = document.createElement('script');"
      "script.src = 'data:text/javascript;charset=utf-8,';"
      "document.body.appendChild(script);"
      "document.write('<body><script "
      "src=\\\'data:text/javascript;charset=utf-8,\\\'></script></body>');"
      "document.close();";
  const char* expected_activities =
      "blinkAddElement | script | data:text/javascript;charset=utf-8,\n"
      "blinkAddElement | script | \n"
      "blinkAddElement | script | \n"
      "blinkAddElement | script | data:text/javascript;charset=utf-8,\n"
      "blinkRequestResource | Script | data:text/javascript;charset=utf-8,\n"
      "blinkAddElement | script | data:text/javascript;charset=utf-8,\n"
      "blinkRequestResource | Script | data:text/javascript;charset=utf-8,";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, IFrameElement) {
  const char* code =
      "document.body.innerHTML = '<iframe "
      "src=\\\'data:text/html;charset=utf-8,\\\'></iframe>';"
      "document.body.innerHTML = '<iframe></iframe>';"
      "var iframe = document.createElement('iframe');"
      "document.body.appendChild(iframe);"
      "iframe = document.createElement('iframe');"
      "iframe.src = 'data:text/html;charset=utf-8,';"
      "document.body.appendChild(iframe);"
      "document.write('<body><iframe "
      "src=\\\'data:text/html;charset=utf-8,\\\'></iframe></body>');"
      "document.close();";
  const char* expected_activities =
      "blinkAddElement | iframe | data:text/html;charset=utf-8,\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,\n"
      "blinkAddElement | iframe | \n"
      "blinkAddElement | iframe | \n"
      "blinkAddElement | iframe | data:text/html;charset=utf-8,\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,\n"
      "blinkAddElement | iframe | data:text/html;charset=utf-8,\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, AnchorElement) {
  const char* code =
      "document.body.innerHTML = '<a "
      "href=\\\'data:text/css;charset=utf-8,\\\'></a>';"
      "document.body.innerHTML = '<a></a>';"
      "var a = document.createElement('a');"
      "document.body.appendChild(a);"
      "a = document.createElement('a');"
      "a.href = 'data:text/css;charset=utf-8,';"
      "document.body.appendChild(a);"
      "document.write('<body><a "
      "href=\\\'data:text/css;charset=utf-8,\\\'></a></body>');"
      "document.close();";
  const char* expected_activities =
      "blinkAddElement | a | data:text/css;charset=utf-8,\n"
      "blinkAddElement | a | \n"
      "blinkAddElement | a | \n"
      "blinkAddElement | a | data:text/css;charset=utf-8,\n"
      "blinkAddElement | a | data:text/css;charset=utf-8,";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, LinkElement) {
  const char* code =
      "document.body.innerHTML = '<link rel=\\\'stylesheet\\\' "
      "href=\\\'data:text/css;charset=utf-8,\\\'></link>';"
      "document.body.innerHTML = '<link></link>';"
      "var link = document.createElement('link');"
      "document.body.appendChild(link);"
      "link = document.createElement('link');"
      "link.rel = 'stylesheet';"
      "link.href = 'data:text/css;charset=utf-8,';"
      "document.body.appendChild(link);"
      "document.write('<body><link rel=\\\'stylesheet\\\' "
      "href=\\\'data:text/css;charset=utf-8,\\\'></link></body>');"
      "document.close();";
  const char* expected_activities =
      "blinkAddElement | link | stylesheet | data:text/css;charset=utf-8,\n"
      "blinkRequestResource | CSS stylesheet | data:text/css;charset=utf-8,\n"
      "blinkAddElement | link |  | \n"
      "blinkAddElement | link |  | \n"
      "blinkAddElement | link | stylesheet | data:text/css;charset=utf-8,\n"
      "blinkRequestResource | CSS stylesheet | data:text/css;charset=utf-8,\n"
      "blinkAddElement | link | stylesheet | data:text/css;charset=utf-8,\n"
      "blinkRequestResource | CSS stylesheet | data:text/css;charset=utf-8,";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, InputElement) {
  const char* code =
      "document.body.innerHTML = '<input type=\\\'submit\\\' "
      "formaction=\\\'data:text/html;charset=utf-8,\\\'></input>';"
      "document.body.innerHTML = '<input></input>';"
      "var input = document.createElement('input');"
      "document.body.appendChild(input);"
      "input = document.createElement('input');"
      "input.type = 'submit';"
      "input.formAction = 'data:text/html;charset=utf-8,';"
      "document.body.appendChild(input);"
      "document.write('<body><input type=\\\'submit\\\' "
      "formaction=\\\'data:text/html;charset=utf-8,\\\'></input></body>');"
      "document.close();";
  const char* expected_activities =
      "blinkAddElement | input | submit | data:text/html;charset=utf-8,\n"
      "blinkAddElement | input |  | \n"
      "blinkAddElement | input |  | \n"
      "blinkAddElement | input | submit | data:text/html;charset=utf-8,\n"
      "blinkAddElement | input | submit | data:text/html;charset=utf-8,";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, ButtonElement) {
  const char* code =
      "document.body.innerHTML = '<button type=\\\'submit\\\' "
      "formmethod=\\\'post\\\' "
      "formaction=\\\'data:text/html;charset=utf-8,\\\'></input>';"
      "document.body.innerHTML = '<button></button>';"
      "var button = document.createElement('button');"
      "document.body.appendChild(button);"
      "button = document.createElement('button');"
      "button.type = 'submit';"
      "button.formMethod = 'post';"
      "button.formAction = 'data:text/html;charset=utf-8,';"
      "document.body.appendChild(button);"
      "document.write('<body><button type=\\\'submit\\\' "
      "formmethod=\\\'post\\\' "
      "formaction=\\\'data:text/html;charset=utf-8,\\\'></button></body>');"
      "document.close();";
  const char* expected_activities =
      "blinkAddElement | button | submit | post | "
      "data:text/html;charset=utf-8,\n"
      "blinkAddElement | button |  |  | \n"
      "blinkAddElement | button |  |  | \n"
      "blinkAddElement | button | submit | post | "
      "data:text/html;charset=utf-8,\n"
      "blinkAddElement | button | submit | post | "
      "data:text/html;charset=utf-8,";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, FormElement) {
  const char* code =
      "document.body.innerHTML = '<form method=\\\'post\\\' "
      "action=\\\'data:text/html;charset=utf-8,\\\'></form>';"
      "document.body.innerHTML = '<form></form>';"
      "var form = document.createElement('form');"
      "document.body.appendChild(form);"
      "form = document.createElement('form');"
      "form.method = 'post';"
      "form.action = 'data:text/html;charset=utf-8,';"
      "document.body.appendChild(form);"
      "document.write('<body><form method=\\\'post\\\' "
      "action=\\\'data:text/html;charset=utf-8,\\\'></form></body>');"
      "document.close();";
  const char* expected_activities =
      "blinkAddElement | form | post | data:text/html;charset=utf-8,\n"
      "blinkAddElement | form |  | \n"
      "blinkAddElement | form |  | \n"
      "blinkAddElement | form | post | data:text/html;charset=utf-8,\n"
      "blinkAddElement | form | post | data:text/html;charset=utf-8,";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, ScriptSrcAttribute) {
  const char* code =
      "document.open();"
      "document.write('<script "
      "src=\\\'data:text/javascript;charset=utf-8,A\\\'></script>');"
      "document.close();"
      "var script = document.getElementsByTagName('script')[0];"
      "script.src = 'data:text/javascript;charset=utf-8,B';"
      "script.setAttribute('src', 'data:text/javascript;charset=utf-8,C');"
      "script.setAttributeNS('', 'src', "
      "'data:text/javascript;charset=utf-8,D');"
      "var attr = document.createAttribute('src');"
      "attr.value = 'data:text/javascript;charset=utf-8,E';"
      "script.setAttributeNode(attr);";
  const char* expected_activities =
      "blinkAddElement | script | data:text/javascript;charset=utf-8,A\n"
      "blinkRequestResource | Script | data:text/javascript;charset=utf-8,A\n"
      "blinkSetAttribute | script | src | data:text/javascript;charset=utf-8,A "
      "| data:text/javascript;charset=utf-8,B\n"
      "blinkSetAttribute | script | src | data:text/javascript;charset=utf-8,B "
      "| data:text/javascript;charset=utf-8,C\n"
      "blinkSetAttribute | script | src | data:text/javascript;charset=utf-8,C "
      "| data:text/javascript;charset=utf-8,D\n"
      "blinkSetAttribute | script | src | data:text/javascript;charset=utf-8,D "
      "| data:text/javascript;charset=utf-8,E";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, IFrameSrcAttribute) {
  const char* code =
      "document.body.innerHTML = '<iframe "
      "src=\\\'data:text/html;charset=utf-8,A\\\'></iframe>';"
      "var iframe = document.getElementsByTagName('iframe')[0];"
      "iframe.src = 'data:text/html;charset=utf-8,B';"
      "iframe.setAttribute('src', 'data:text/html;charset=utf-8,C');"
      "iframe.setAttributeNS('', 'src', 'data:text/html;charset=utf-8,D');"
      "var attr = document.createAttribute('src');"
      "attr.value = 'data:text/html;charset=utf-8,E';"
      "iframe.setAttributeNode(attr);";
  const char* expected_activities =
      "blinkAddElement | iframe | data:text/html;charset=utf-8,A\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,A\n"
      "blinkSetAttribute | iframe | src | data:text/html;charset=utf-8,A | "
      "data:text/html;charset=utf-8,B\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,B\n"
      "blinkSetAttribute | iframe | src | data:text/html;charset=utf-8,B | "
      "data:text/html;charset=utf-8,C\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,C\n"
      "blinkSetAttribute | iframe | src | data:text/html;charset=utf-8,C | "
      "data:text/html;charset=utf-8,D\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,D\n"
      "blinkSetAttribute | iframe | src | data:text/html;charset=utf-8,D | "
      "data:text/html;charset=utf-8,E\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,E";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, AnchorHrefAttribute) {
  const char* code =
      "document.body.innerHTML = '<a "
      "href=\\\'data:text/html;charset=utf-8,A\\\'></a>';"
      "var a = document.getElementsByTagName('a')[0];"
      "a.href = 'data:text/html;charset=utf-8,B';"
      "a.setAttribute('href', 'data:text/html;charset=utf-8,C');"
      "a.setAttributeNS('', 'href', 'data:text/html;charset=utf-8,D');"
      "var attr = document.createAttribute('href');"
      "attr.value = 'data:text/html;charset=utf-8,E';"
      "a.setAttributeNode(attr);";
  const char* expected_activities =
      "blinkAddElement | a | data:text/html;charset=utf-8,A\n"
      "blinkSetAttribute | a | href | data:text/html;charset=utf-8,A | "
      "data:text/html;charset=utf-8,B\n"
      "blinkSetAttribute | a | href | data:text/html;charset=utf-8,B | "
      "data:text/html;charset=utf-8,C\n"
      "blinkSetAttribute | a | href | data:text/html;charset=utf-8,C | "
      "data:text/html;charset=utf-8,D\n"
      "blinkSetAttribute | a | href | data:text/html;charset=utf-8,D | "
      "data:text/html;charset=utf-8,E";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, LinkHrefAttribute) {
  const char* code =
      "document.body.innerHTML = '<link rel=\\\'stylesheet\\\' "
      "href=\\\'data:text/css;charset=utf-8,A\\\'></link>';"
      "var link = document.getElementsByTagName('link')[0];"
      "link.href = 'data:text/css;charset=utf-8,B';"
      "link.setAttribute('href', 'data:text/css;charset=utf-8,C');"
      "link.setAttributeNS('', 'href', 'data:text/css;charset=utf-8,D');"
      "var attr = document.createAttribute('href');"
      "attr.value = 'data:text/css;charset=utf-8,E';"
      "link.setAttributeNode(attr);";
  const char* expected_activities =
      "blinkAddElement | link | stylesheet | data:text/css;charset=utf-8,A\n"
      "blinkRequestResource | CSS stylesheet | data:text/css;charset=utf-8,A\n"
      "blinkSetAttribute | link | href | data:text/css;charset=utf-8,A | "
      "data:text/css;charset=utf-8,B\n"
      "blinkRequestResource | CSS stylesheet | data:text/css;charset=utf-8,B\n"
      "blinkSetAttribute | link | href | data:text/css;charset=utf-8,B | "
      "data:text/css;charset=utf-8,C\n"
      "blinkRequestResource | CSS stylesheet | data:text/css;charset=utf-8,C\n"
      "blinkSetAttribute | link | href | data:text/css;charset=utf-8,C | "
      "data:text/css;charset=utf-8,D\n"
      "blinkRequestResource | CSS stylesheet | data:text/css;charset=utf-8,D\n"
      "blinkSetAttribute | link | href | data:text/css;charset=utf-8,D | "
      "data:text/css;charset=utf-8,E\n"
      "blinkRequestResource | CSS stylesheet | data:text/css;charset=utf-8,E";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, InputFormActionAttribute) {
  const char* code =
      "document.body.innerHTML = '<input type=\\\'button\\\' "
      "formaction=\\\'data:text/html;charset=utf-8,A\\\'></input>';"
      "var input = document.getElementsByTagName('input')[0];"
      "input.formAction = 'data:text/html;charset=utf-8,B';"
      "input.setAttribute('formaction', 'data:text/html;charset=utf-8,C');"
      "input.setAttributeNS('', 'formaction', "
      "'data:text/html;charset=utf-8,D');"
      "var attr = document.createAttribute('formaction');"
      "attr.value = 'data:text/html;charset=utf-8,E';"
      "input.setAttributeNode(attr);";
  const char* expected_activities =
      "blinkAddElement | input | button | data:text/html;charset=utf-8,A\n"
      "blinkSetAttribute | input | formaction | data:text/html;charset=utf-8,A "
      "| data:text/html;charset=utf-8,B\n"
      "blinkSetAttribute | input | formaction | data:text/html;charset=utf-8,B "
      "| data:text/html;charset=utf-8,C\n"
      "blinkSetAttribute | input | formaction | data:text/html;charset=utf-8,C "
      "| data:text/html;charset=utf-8,D\n"
      "blinkSetAttribute | input | formaction | data:text/html;charset=utf-8,D "
      "| data:text/html;charset=utf-8,E";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, ButtonFormActionAttribute) {
  const char* code =
      "document.body.innerHTML = '<button type=\\\'submit\\\' "
      "formmethod=\\\'post\\\' "
      "formaction=\\\'data:text/html;charset=utf-8,A\\\'></input>';"
      "var button = document.getElementsByTagName('button')[0];"
      "button.formAction = 'data:text/html;charset=utf-8,B';"
      "button.setAttribute('formaction', 'data:text/html;charset=utf-8,C');"
      "button.setAttributeNS('', 'formaction', "
      "'data:text/html;charset=utf-8,D');"
      "var attr = document.createAttribute('formaction');"
      "attr.value = 'data:text/html;charset=utf-8,E';"
      "button.setAttributeNode(attr);";
  const char* expected_activities =
      "blinkAddElement | button | submit | post | "
      "data:text/html;charset=utf-8,A\n"
      "blinkSetAttribute | button | formaction | "
      "data:text/html;charset=utf-8,A | data:text/html;charset=utf-8,B\n"
      "blinkSetAttribute | button | formaction | "
      "data:text/html;charset=utf-8,B | data:text/html;charset=utf-8,C\n"
      "blinkSetAttribute | button | formaction | "
      "data:text/html;charset=utf-8,C | data:text/html;charset=utf-8,D\n"
      "blinkSetAttribute | button | formaction | "
      "data:text/html;charset=utf-8,D | data:text/html;charset=utf-8,E";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, FormActionAttribute) {
  const char* code =
      "document.body.innerHTML = '<form "
      "action=\\\'data:text/html;charset=utf-8,A\\\'></form>';"
      "var form = document.getElementsByTagName('form')[0];"
      "form.action = 'data:text/html;charset=utf-8,B';"
      "form.setAttribute('action', 'data:text/html;charset=utf-8,C');"
      "form.setAttributeNS('', 'action', 'data:text/html;charset=utf-8,D');"
      "var attr = document.createAttribute('action');"
      "attr.value = 'data:text/html;charset=utf-8,E';"
      "form.setAttributeNode(attr);";
  const char* expected_activities =
      "blinkAddElement | form |  | data:text/html;charset=utf-8,A\n"
      "blinkSetAttribute | form | action | data:text/html;charset=utf-8,A | "
      "data:text/html;charset=utf-8,B\n"
      "blinkSetAttribute | form | action | data:text/html;charset=utf-8,B | "
      "data:text/html;charset=utf-8,C\n"
      "blinkSetAttribute | form | action | data:text/html;charset=utf-8,C | "
      "data:text/html;charset=utf-8,D\n"
      "blinkSetAttribute | form | action | data:text/html;charset=utf-8,D | "
      "data:text/html;charset=utf-8,E";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, LocalDOMWindowAttribute) {
  ScopedAllowContentInitiatedDataUrlNavigationsForTest allow_data_url(true);

  const char* code =
      "location.href = 'data:text/html;charset=utf-8,A';"
      "location.assign('data:text/html;charset=utf-8,B');"
      "location.replace('data:text/html;charset=utf-8,C');"
      "location.protocol = 'protocol';"
      "location.pathname = 'pathname';"
      "location.search = 'search';"
      "location.hash = 'hash';"
      "location.href = 'about:blank';";
  const char* expected_activities =
      "blinkSetAttribute | LocalDOMWindow | url | about:blank | "
      "data:text/html;charset=utf-8,A\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,A\n"
      "blinkSetAttribute | LocalDOMWindow | url | about:blank | "
      "data:text/html;charset=utf-8,B\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,B\n"
      "blinkSetAttribute | LocalDOMWindow | url | about:blank | "
      "data:text/html;charset=utf-8,C\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,C\n"
      "blinkSetAttribute | LocalDOMWindow | url | about:blank | "
      "protocol:blank\n"
      "blinkRequestResource | Main resource | protocol:blank\n"
      "blinkSetAttribute | LocalDOMWindow | url | about:blank | "
      "about:pathname\n"
      "blinkSetAttribute | LocalDOMWindow | url | about:blank | "
      "about:blank?search\n"
      "blinkSetAttribute | LocalDOMWindow | url | about:blank | "
      "about:blank#hash\n"
      "blinkSetAttribute | LocalDOMWindow | url | about:blank#hash | "
      "about:blank\n";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

TEST_F(ActivityLoggerTest, RequestResource) {
  const char* code =
      "document.write('<iframe "
      "src=\\\'data:text/html;charset=utf-8,A\\\'></iframe>');"
      "document.write('<img "
      "src=\\\'data:text/html;charset=utf-8,B\\\'></img>');"
      "document.write('<link rel=\\\'stylesheet\\\' "
      "href=\\\'data:text/html;charset=utf-8,C\\\'></link>');"
      "document.write('<script "
      "src=\\\'data:text/html;charset=utf-8,D\\\'></script>');"
      "document.close();"
      "var xhr = new XMLHttpRequest(); xhr.open('GET', "
      "'data:text/html;charset=utf-8,E'); xhr.send();";
  const char* expected_activities =
      "blinkAddElement | iframe | data:text/html;charset=utf-8,A\n"
      "blinkRequestResource | Main resource | data:text/html;charset=utf-8,A\n"
      "blinkAddElement | link | stylesheet | data:text/html;charset=utf-8,C\n"
      "blinkRequestResource | CSS stylesheet | data:text/html;charset=utf-8,C\n"
      "blinkAddElement | script | data:text/html;charset=utf-8,D\n"
      "blinkRequestResource | Script | data:text/html;charset=utf-8,D\n"
      "blinkRequestResource | XMLHttpRequest | data:text/html;charset=utf-8,E\n"
      "blinkRequestResource | Image | data:text/html;charset=utf-8,B\n";
  ExecuteScriptInMainWorld(code);
  ASSERT_TRUE(VerifyActivities(""));
  ExecuteScriptInIsolatedWorld(code);
  ASSERT_TRUE(VerifyActivities(expected_activities));
}

}  // namespace blink
```