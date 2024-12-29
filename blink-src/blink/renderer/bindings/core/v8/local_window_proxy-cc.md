Response:
My thinking process to analyze the `local_window_proxy.cc` file went through several steps:

1. **Understand the Purpose and Context:** I first noted the file path: `blink/renderer/bindings/core/v8/local_window_proxy.cc`. This immediately tells me a few key things:
    * It's part of the Blink rendering engine (Chromium's fork of WebKit).
    * It's related to the V8 JavaScript engine integration.
    * It's about a "local window proxy," suggesting it's an intermediary or representation of the browser's `window` object within the V8 context for a specific frame.

2. **Scan the Imports:**  I quickly reviewed the `#include` directives. These are highly informative. I looked for categories of imports:
    * **V8 related:** Headers like `v8.h`, `v8_binding_for_core.h`, `v8_window.h`, `v8_context_snapshot.h`, etc. These confirm the strong V8 integration and hint at managing V8 contexts and objects.
    * **Blink Core:** Headers like `local_dom_window.h`, `local_frame.h`, `html_document.h`, `content_security_policy.h`, `script_controller.h`, etc. These connect the proxy to the underlying browser concepts like frames, documents, and security policies.
    * **Platform/Utility:** Headers like `base/debug/dump_without_crashing.h`, `base/metrics/`, `platform/bindings/`, etc. These suggest logging, performance tracking, and binding mechanisms.

3. **Identify Key Classes and Methods:** I skimmed the code for the main class, `LocalWindowProxy`. I paid attention to its public methods:
    * `Trace`: Standard Blink tracing for garbage collection.
    * `DisposeContext`:  Crucial for managing the lifecycle of the V8 context associated with the window. The different `Lifecycle` enum values are important.
    * `Initialize`:  Sets up the V8 context and its relationship to the native `DOMWindow`.
    * `CreateContext`:  The actual creation of the V8 context. The mention of "snapshot" is significant.
    * `InstallConditionalFeatures`: Hints at enabling certain JavaScript features based on context.
    * `SetupWindowPrototypeChain`:  Fundamental to how the JavaScript `window` object inherits properties and methods.
    * `UpdateDocumentProperty`, `UpdateActivityLogger`, `SetSecurityToken`, `UpdateDocument`, `UpdateDocumentForMainWorld`, `NamedItemAdded`, `NamedItemRemoved`, `UpdateSecurityOrigin`, `SetAbortScriptExecution`: These suggest the proxy keeps the V8 representation synchronized with the underlying browser state (document, security, etc.).

4. **Analyze Functionality by Grouping Methods:** I started grouping the methods based on their likely purpose:
    * **Lifecycle Management:** `DisposeContext`, `Initialize`, `CreateContext`. These are fundamental to the proxy's role.
    * **V8 Context Setup:** `SetupWindowPrototypeChain`, `InstallConditionalFeatures`. These explain how the JavaScript environment is built.
    * **Synchronization with Browser State:** `UpdateDocumentProperty`, `UpdateActivityLogger`, `SetSecurityToken`, `UpdateDocument`, `UpdateSecurityOrigin`. These are essential for consistency between JavaScript and the browser.
    * **Handling Named Properties:** `NamedItemAdded`, `NamedItemRemoved`. This addresses a specific optimization for accessing elements by name in the document.
    * **Error Handling/Debugging:** The `DCHECK` statements are important for development. The `TRACE_EVENT` calls are for performance analysis.

5. **Connect to JavaScript, HTML, and CSS:** With the functionality understood, I started connecting it to web technologies:
    * **JavaScript:** The entire file is about bridging the gap between the browser's internal representation of a window and the JavaScript `window` object. The methods deal directly with V8 contexts and objects.
    * **HTML:** The `UpdateDocumentProperty` and the named item handling are directly related to how JavaScript interacts with the HTML document. The `HTMLDocument` and `HTMLElement` imports are crucial here. The examples involving `document.getElementById` and accessing iframes show concrete use cases.
    * **CSS:** While not directly manipulating CSS, the file is part of the rendering pipeline that makes CSSOM (CSS Object Model) accessible to JavaScript. Changes in the HTML structure (and thus potential CSS implications) can trigger updates handled by this proxy.

6. **Consider Logic and Input/Output:** For key methods like `DisposeContext` and `Initialize`, I considered the states they operate on (`Lifecycle` enum) and the actions they perform. This allowed me to formulate hypothetical input/output scenarios.

7. **Identify Potential User Errors:** I thought about common JavaScript errors or developer misunderstandings related to the `window` object, such as accessing properties before the document is ready or issues with cross-origin access. The `ContentSecurityPolicy` aspect was also important here, as it relates to security restrictions.

8. **Trace User Actions to the Code:**  I tried to reverse-engineer how user actions (like opening a new tab or clicking a link) would eventually lead to the execution of code in this file. The creation of frames and the need for a corresponding JavaScript environment are the key triggers.

9. **Refine and Organize:** Finally, I structured the information logically, using clear headings and bullet points to present the functionality, relationships, and examples effectively. I also made sure to explain any assumptions or interpretations I made.

Essentially, I approached this like a detective examining a piece of evidence. I looked for clues in the code itself (imports, class names, method names), considered the broader context (Blink, V8, web standards), and then pieced together a coherent picture of the file's role and significance. The key was to move from the specific details of the code to the higher-level concepts of web development.
`blink/renderer/bindings/core/v8/local_window_proxy.cc` 文件的主要功能是**在Blink渲染引擎中，为特定的本地帧（LocalFrame）创建一个和管理其对应的JavaScript `window` 对象的代理（Proxy）**。 这个代理负责将Blink的内部状态和功能暴露给JavaScript环境，并处理JavaScript代码与Blink内部的交互。

更具体地说，`LocalWindowProxy` 负责：

1. **创建和管理V8上下文（Context）：**  为每个本地帧创建一个独立的V8执行环境。这包括初始化V8堆、创建全局对象（`window`），并设置必要的属性和方法。
2. **将Blink对象绑定到V8对象：** 将Blink内部的 `DOMWindow` 对象（代表浏览器的窗口）与V8的全局对象（`window`）关联起来，使得JavaScript代码可以访问和操作Blink的DOM结构和其他API。
3. **处理JavaScript调用：** 拦截JavaScript代码对 `window` 对象及其属性和方法的调用，并将这些调用路由到Blink内部相应的处理逻辑。
4. **管理V8上下文的生命周期：**  负责在帧被创建、导航、销毁等不同生命周期阶段，初始化、更新和清理相关的V8上下文。
5. **处理安全策略（CSP）：**  根据 Content Security Policy (CSP) 设置 V8 上下文的行为，例如是否允许 `eval()` 等。
6. **支持扩展（Extensions）：**  加载和安装浏览器扩展到 V8 上下文中。
7. **性能优化：**  使用 V8 快照（Snapshot）技术来加速 V8 上下文的创建。
8. **处理命名项（Named Items）：**  优化对 `document` 对象上通过 `name` 属性访问元素的性能。

**与JavaScript, HTML, CSS的功能的关系及举例说明：**

`LocalWindowProxy` 是连接 JavaScript 和浏览器内部功能的核心桥梁。

* **JavaScript:**
    * **`window` 对象：** `LocalWindowProxy` 最直接关联的就是 JavaScript 的全局对象 `window`。 JavaScript 中所有不属于特定对象的方法和属性，默认都属于 `window` 对象。例如：
        ```javascript
        console.log(window.innerWidth); // 获取浏览器窗口的内部宽度
        window.alert("Hello!"); // 显示一个警告框
        window.document.getElementById("myElement"); // 访问文档中的元素
        ```
        `LocalWindowProxy` 负责将这些 JavaScript 调用转换为对 Blink 内部 `DOMWindow` 和 `Document` 对象的调用。
    * **事件处理：** JavaScript 中通过 `window.onload` 或 `addEventListener` 注册的事件监听器，其触发和回调函数的执行也由 `LocalWindowProxy` 管理的 V8 上下文处理。
    * **定时器：** `setTimeout` 和 `setInterval` 等定时器函数的执行也是在 `LocalWindowProxy` 管理的 V8 上下文中进行。

* **HTML:**
    * **`document` 对象：** `window.document` 属性指向表示当前 HTML 文档的 `Document` 对象。`LocalWindowProxy` 的 `UpdateDocumentProperty` 方法负责更新 V8 中 `window.document` 的值，使其指向当前帧的 `HTMLDocument` 对象。例如：
        ```javascript
        let title = window.document.title; // 获取 HTML 文档的标题
        let element = window.document.createElement('div'); // 创建一个新的 div 元素
        ```
    * **命名项访问优化：**  `LocalWindowProxy` 中的 `NamedItemAdded` 和 `NamedItemRemoved` 方法优化了通过 `document.namedItem` 或直接通过 `document.元素name` 访问 HTML 元素（特别是 iframe 和表单元素）的性能。例如：
        ```html
        <iframe name="myFrame" src="..."></iframe>
        <script>
          let frame = window.document.myFrame; // 直接通过 name 访问 iframe
          console.log(frame.contentWindow);
        </script>
        ```
        当 HTML 中添加或删除具有 `name` 属性的元素时，`LocalWindowProxy` 会更新 V8 中 `document` 对象的属性访问器，以提高访问效率。

* **CSS:**
    * **CSSOM (CSS Object Model)：** 虽然 `LocalWindowProxy` 不直接操作 CSS，但它是 JavaScript 访问和操作 CSSOM 的入口点。通过 `window.getComputedStyle()` 可以获取元素的计算样式，通过修改元素的 `style` 属性可以动态修改样式。这些操作都发生在 `LocalWindowProxy` 管理的 V8 上下文中。例如：
        ```javascript
        let element = document.getElementById('myElement');
        let color = window.getComputedStyle(element).color; // 获取元素的颜色
        element.style.backgroundColor = 'red'; // 修改元素的背景颜色
        ```

**逻辑推理的假设输入与输出：**

**假设输入：** 用户在浏览器中打开一个包含以下 HTML 的网页：

```html
<!DOCTYPE html>
<html>
<head>
  <title>Test Page</title>
</head>
<body>
  <iframe name="myFrame" src="about:blank"></iframe>
  <script>
    console.log(window.frames['myFrame'].location.href);
  </script>
</body>
</html>
```

**逻辑推理过程（简化）：**

1. **帧创建：** Blink 渲染引擎会为这个 HTML 创建一个主帧和一个子帧（iframe）。
2. **LocalWindowProxy 创建：** 对于主帧和子帧，都会分别创建一个 `LocalWindowProxy` 实例。
3. **V8 上下文初始化：**  每个 `LocalWindowProxy` 都会初始化一个独立的 V8 上下文。
4. **`window` 对象关联：**  Blink 的 `DOMWindow` 对象（代表主帧和子帧的窗口）会分别与各自 V8 上下文中的全局对象 `window` 关联。
5. **命名项添加：** 当解析到 `<iframe name="myFrame">` 时，`LocalWindowProxy` 的 `NamedItemAdded` 方法会被调用，更新主帧 `document` 对象的属性访问器，使得可以通过 `window.frames['myFrame']` 或 `window.myFrame` 访问该 iframe 的 `contentWindow`。
6. **JavaScript 执行：**  当执行 JavaScript 代码 `console.log(window.frames['myFrame'].location.href);` 时：
    * `window.frames['myFrame']` 会通过优化的命名项访问机制获取到 iframe 的 `contentWindow` 代理。
    * `.location` 访问会路由到 iframe 的 `contentWindow` 对象的 `location` 属性。
    * `.href` 访问会获取到 iframe 的 URL（这里是 "about:blank"）。
    * `console.log()` 将结果输出到控制台。

**假设输出：**  在浏览器的开发者工具控制台中输出 "about:blank"。

**涉及用户或者编程常见的使用错误及举例说明：**

1. **跨域访问限制：**  JavaScript 代码尝试访问不同源（origin）的 `window` 对象的属性，这是浏览器出于安全考虑禁止的。
    ```html
    <!-- 假设 example.com 和 different-domain.com 的域名不同 -->
    <iframe id="otherFrame" src="https://different-domain.com"></iframe>
    <script>
      let frame = document.getElementById('otherFrame');
      try {
        console.log(frame.contentWindow.document.title); // 可能会抛出 SecurityError
      } catch (e) {
        console.error("跨域访问错误:", e);
      }
    </script>
    ```
    `LocalWindowProxy` 在处理此类访问时会根据浏览器的同源策略进行检查，并阻止跨域访问。

2. **在文档加载完成前访问 `document` 对象：**  在 HTML 文档完全加载和解析之前执行 JavaScript 代码，可能会导致 `document` 对象尚未完全初始化，从而访问其属性或方法时出错。
    ```html
    <script>
      console.log(document.getElementById('nonExistent')); // 可能返回 null
    </script>
    ```
    虽然 `LocalWindowProxy` 会在文档加载过程中逐步初始化 `document` 对象，但在文档完全准备好之前进行操作是不安全的。

3. **错误地操作 `window` 对象：**  例如，尝试修改只读的 `window` 属性，或者调用不存在的方法。
    ```javascript
    window.innerWidth = 1000; // 尝试修改只读属性，会被忽略或报错
    window.nonExistentFunction(); // 调用不存在的函数，会抛出 TypeError
    ```
    `LocalWindowProxy` 代理的 `window` 对象会尽可能遵循 Web 标准的行为，对于不合法的操作会产生相应的 JavaScript 错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者在调试一个网页，发现 JavaScript 代码在访问一个 iframe 的 `contentWindow` 时出现了问题。以下是用户操作可能如何一步步到达 `LocalWindowProxy` 的相关代码，以及如何利用它作为调试线索：

1. **用户打开网页：**  浏览器开始加载和解析 HTML 内容。
2. **Blink 创建帧：**  当解析到 `<iframe>` 标签时，Blink 渲染引擎会创建一个新的本地帧（`LocalFrame`）。
3. **`LocalWindowProxy` 创建：**  对于这个新创建的帧，Blink 会实例化一个 `LocalWindowProxy` 对象，负责管理该帧的 JavaScript 上下文。
4. **V8 上下文初始化：** `LocalWindowProxy::Initialize()` 方法会被调用，创建一个新的 V8 上下文并与该帧的 `DOMWindow` 对象关联。
5. **命名项注册（如果 iframe 有 `name` 属性）：** `LocalWindowProxy::NamedItemAdded()` 方法会被调用，更新父帧 `document` 对象的属性访问器，以便 JavaScript 可以通过 `name` 访问 iframe。
6. **JavaScript 执行：** 用户触发了某个事件或页面加载完成，导致 JavaScript 代码执行，例如：
   ```javascript
   let frameWindow = document.getElementById('myIframe').contentWindow;
   console.log(frameWindow.location.href);
   ```
7. **属性访问代理：** 当 JavaScript 代码访问 `frameWindow.location` 时，V8 引擎会通过 `LocalWindowProxy` 拦截这个操作。
8. **Blink 内部调用：** `LocalWindowProxy` 会将这个 JavaScript 属性访问转换为对 Blink 内部 `DOMWindow` 对象的 `location` 属性的访问。
9. **调试线索：** 如果在第 7 步或第 8 步出现问题，例如：
    * `frameWindow` 为 `null` 或 `undefined`：说明 JavaScript 代码可能在 iframe 加载完成前执行，或者 `getElementById` 选择器有误。可以检查 JavaScript 代码的执行时机和选择器是否正确。
    * 访问 `location` 属性时抛出跨域错误：说明父页面和 iframe 的域名不同，违反了同源策略。需要检查页面的域名配置。
    * 访问 `location.href` 时返回意外的值：可能需要检查 iframe 的加载状态和 URL。

通过查看 `LocalWindowProxy` 的源代码，开发者可以理解 Blink 如何将 JavaScript 的 `window` 对象映射到内部的 `DOMWindow` 对象，以及如何处理属性和方法的访问。这有助于理解错误发生的根本原因，并找到相应的解决方案。例如，如果在 `NamedItemAdded` 中存在 bug，可能导致通过 `name` 访问 iframe 失败。 理解 `LocalWindowProxy` 的工作原理对于调试涉及 JavaScript 和浏览器内部交互的问题至关重要。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/local_window_proxy.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008, 2009, 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/bindings/core/v8/local_window_proxy.h"

#include <tuple>

#include "base/debug/dump_without_crashing.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/single_sample_metrics.h"
#include "third_party/blink/renderer/bindings/core/v8/isolated_world_csp.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_context_snapshot.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_for_context_dispose.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_html_document.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_initializer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_page_popup_controller_binding.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_window.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/html/document_name_collection.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/inspector/inspector_task_runner.h"
#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/extensions_registry.h"
#include "third_party/blink/renderer/platform/bindings/origin_trial_features.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_activity_logger.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/v8_private_property.h"
#include "third_party/blink/renderer/platform/bindings/v8_set_return_value.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/weborigin/reporting_disposition.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_operators.h"
#include "v8/include/v8.h"

namespace blink {

void LocalWindowProxy::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  WindowProxy::Trace(visitor);
}

void LocalWindowProxy::DisposeContext(Lifecycle next_status,
                                      FrameReuseStatus frame_reuse_status) {
  DCHECK(next_status == Lifecycle::kV8MemoryIsForciblyPurged ||
         next_status == Lifecycle::kGlobalObjectIsDetached ||
         next_status == Lifecycle::kFrameIsDetached ||
         next_status == Lifecycle::kFrameIsDetachedAndV8MemoryIsPurged);

  // If the current lifecycle is kV8MemoryIsForciblyPurged, next status should
  // be either kFrameIsDetachedAndV8MemoryIsPurged, or kGlobalObjectIsDetached.
  // If the former, |global_proxy_| should become weak, and if the latter, the
  // necessary operations are already done so can return here.
  if (lifecycle_ == Lifecycle::kV8MemoryIsForciblyPurged) {
    DCHECK(next_status == Lifecycle::kGlobalObjectIsDetached ||
           next_status == Lifecycle::kFrameIsDetachedAndV8MemoryIsPurged);
    lifecycle_ = next_status;
    return;
  }

  if (lifecycle_ != Lifecycle::kContextIsInitialized)
    return;

  ScriptState::Scope scope(script_state_);
  v8::Local<v8::Context> context = script_state_->GetContext();
  // The embedder could run arbitrary code in response to the
  // willReleaseScriptContext callback, so all disposing should happen after
  // it returns.
  GetFrame()->Client()->WillReleaseScriptContext(context, world_->GetWorldId());
  CHECK_EQ(GetIsolate(), script_state_->GetIsolate());
  MainThreadDebugger::Instance(GetIsolate())
      ->ContextWillBeDestroyed(script_state_);
  if (next_status == Lifecycle::kV8MemoryIsForciblyPurged ||
      next_status == Lifecycle::kGlobalObjectIsDetached) {
    // Clean up state on the global proxy, which will be reused.
    v8::Local<v8::Object> global = context->Global();
    if (!global_proxy_.IsEmpty()) {
      CHECK(global_proxy_ == global);
      CHECK_EQ(ToScriptWrappable<DOMWindow>(GetIsolate(), global),
               ToScriptWrappable<DOMWindow>(
                   GetIsolate(), global->GetPrototype().As<v8::Object>()));
    }
    auto* window = GetFrame()->DomWindow();
    V8DOMWrapper::ClearNativeInfo(GetIsolate(), global,
                                  V8Window::GetWrapperTypeInfo());
    script_state_->World().DomDataStore().ClearIfEqualTo(window, global);
#if DCHECK_IS_ON()
    HeapVector<Member<DOMWrapperWorld>> all_worlds;
    DOMWrapperWorld::AllWorldsInIsolate(script_state_->GetIsolate(),
                                        all_worlds);
    for (auto& world : all_worlds) {
      DCHECK(!world->DomDataStore().EqualTo(window, global));
    }
#endif  // DCHECK_IS_ON()
    script_state_->DetachGlobalObject();
#if DCHECK_IS_ON()
    DidDetachGlobalObject();
#endif
  }

  script_state_->DisposePerContextData();
  // It's likely that disposing the context has created a lot of
  // garbage. Notify V8 about this so it'll have a chance of cleaning
  // it up when idle.
  V8GCForContextDispose::Instance().NotifyContextDisposed(
      script_state_->GetIsolate(), GetFrame()->IsMainFrame(),
      frame_reuse_status);

  DCHECK_EQ(lifecycle_, Lifecycle::kContextIsInitialized);
  lifecycle_ = next_status;
}

void LocalWindowProxy::Initialize() {
  TRACE_EVENT2("v8", "LocalWindowProxy::Initialize", "IsMainFrame",
               GetFrame()->IsMainFrame(), "IsOutermostMainFrame",
               GetFrame()->IsOutermostMainFrame());
  CHECK(!GetFrame()->IsProvisional());
  base::ElapsedTimer timer;

  ScriptForbiddenScope::AllowUserAgentScript allow_script;
  v8::HandleScope handle_scope(GetIsolate());

  CreateContext();

  ScriptState::Scope scope(script_state_);
  v8::Local<v8::Context> context = script_state_->GetContext();
  if (global_proxy_.IsEmpty()) {
    global_proxy_.Reset(GetIsolate(), context->Global());
    CHECK(!global_proxy_.IsEmpty());
  }

  SetupWindowPrototypeChain();

  // Setup handling for eval checks for the context. Isolated worlds which don't
  // specify their own CSPs are exempt from eval checks currently.
  // TODO(crbug.com/982388): For other CSP checks, we use the main world CSP
  // when an isolated world doesn't specify its own CSP. We should do the same
  // here.
  const bool evaluate_csp_for_eval =
      world_->IsMainWorld() ||
      (world_->IsIsolatedWorld() &&
       IsolatedWorldCSP::Get().HasContentSecurityPolicy(world_->GetWorldId()));
  if (evaluate_csp_for_eval) {
    ContentSecurityPolicy* csp =
        GetFrame()->DomWindow()->GetContentSecurityPolicyForCurrentWorld();
    context->AllowCodeGenerationFromStrings(!csp->ShouldCheckEval());
    context->SetErrorMessageForCodeGenerationFromStrings(
        V8String(GetIsolate(), csp->EvalDisabledErrorMessage()));
    context->SetErrorMessageForWasmCodeGeneration(
        V8String(GetIsolate(), csp->WasmEvalDisabledErrorMessage()));
  }

  scoped_refptr<const SecurityOrigin> origin;
  if (world_->IsMainWorld()) {
    // This also updates the ActivityLogger for the main world.
    UpdateDocumentForMainWorld();
    origin = GetFrame()->DomWindow()->GetSecurityOrigin();
  } else {
    UpdateActivityLogger();
    origin = world_->IsolatedWorldSecurityOrigin(
        GetFrame()->DomWindow()->GetAgentClusterID());
    SetSecurityToken(origin.get());
  }

  {
    TRACE_EVENT2("v8", "ContextCreatedNotification", "IsMainFrame",
                 GetFrame()->IsMainFrame(), "IsOutermostMainFrame",
                 GetFrame()->IsOutermostMainFrame());
    MainThreadDebugger::Instance(script_state_->GetIsolate())
        ->ContextCreated(script_state_, GetFrame(), origin.get());
    GetFrame()->Client()->DidCreateScriptContext(context, world_->GetWorldId());
  }

  InstallConditionalFeatures();

  if (World().IsMainWorld()) {
    probe::DidCreateMainWorldContext(GetFrame());
    GetFrame()->Loader().DispatchDidClearWindowObjectInMainWorld();
  }
  base::UmaHistogramTimes("V8.LocalWindowProxy.InitializeTime",
                          timer.Elapsed());
}

void LocalWindowProxy::CreateContext() {
  TRACE_EVENT2("v8", "LocalWindowProxy::CreateContext", "IsMainFrame",
               GetFrame()->IsMainFrame(), "IsOutermostMainFrame",
               GetFrame()->IsOutermostMainFrame());
  base::ElapsedTimer timer;

  v8::ExtensionConfiguration extension_configuration =
      ScriptController::ExtensionsFor(GetFrame()->DomWindow());

  DCHECK(GetFrame()->DomWindow());
  v8::Local<v8::Context> context;
  {
    v8::Isolate* isolate = GetIsolate();
    V8PerIsolateData::UseCounterDisabledScope use_counter_disabled(
        V8PerIsolateData::From(isolate));
    Document* document = GetFrame()->GetDocument();

    v8::Local<v8::Object> global_proxy = global_proxy_.Get(isolate);
    context = V8ContextSnapshot::CreateContextFromSnapshot(
        isolate, World(), &extension_configuration, global_proxy, document);
    context_was_created_from_snapshot_ = !context.IsEmpty();

    // Even if we enable V8 context snapshot feature, we may hit this branch
    // in some cases, e.g. loading XML files.
    if (context.IsEmpty()) {
      v8::Local<v8::ObjectTemplate> global_template =
          V8Window::GetWrapperTypeInfo()
              ->GetV8ClassTemplate(isolate, World())
              .As<v8::FunctionTemplate>()
              ->InstanceTemplate();
      CHECK(!global_template.IsEmpty());
      context = v8::Context::New(isolate, &extension_configuration,
                                 global_template, global_proxy,
                                 v8::DeserializeInternalFieldsCallback(),
                                 GetFrame()->DomWindow()->GetMicrotaskQueue());
      VLOG(1) << "A context is created NOT from snapshot";
    }
  }
  CHECK(!context.IsEmpty());

#if DCHECK_IS_ON()
  DidAttachGlobalObject();
#endif

  script_state_ = ScriptState::Create(context, world_, GetFrame()->DomWindow());

  DCHECK(lifecycle_ == Lifecycle::kContextIsUninitialized ||
         lifecycle_ == Lifecycle::kGlobalObjectIsDetached);
  lifecycle_ = Lifecycle::kContextIsInitialized;
  DCHECK(script_state_->ContextIsValid());
  base::UmaHistogramTimes("V8.LocalWindowProxy.CreateContextTime",
                          timer.Elapsed());
}

void LocalWindowProxy::InstallConditionalFeatures() {
  TRACE_EVENT2("v8", "InstallConditionalFeatures", "IsMainFrame",
               GetFrame()->IsMainFrame(), "IsOutermostMainFrame",
               GetFrame()->IsOutermostMainFrame());

  if (context_was_created_from_snapshot_) {
    V8ContextSnapshot::InstallContextIndependentProps(script_state_);
  }

  V8PerContextData* per_context_data = script_state_->PerContextData();
  std::ignore =
      per_context_data->ConstructorForType(V8Window::GetWrapperTypeInfo());
  // Inform V8 that origin trial information is now connected with the context,
  // and V8 can extend the context with origin trial features.
  script_state_->GetIsolate()->InstallConditionalFeatures(
      script_state_->GetContext());
  ExtensionsRegistry::GetInstance().InstallExtensions(script_state_);
}

void LocalWindowProxy::SetupWindowPrototypeChain() {
  TRACE_EVENT2("v8", "LocalWindowProxy::SetupWindowPrototypeChain",
               "IsMainFrame", GetFrame()->IsMainFrame(), "IsOutermostMainFrame",
               GetFrame()->IsOutermostMainFrame());

  // Associate the window wrapper object and its prototype chain with the
  // corresponding native DOMWindow object.
  DOMWindow* window = GetFrame()->DomWindow();
  const WrapperTypeInfo* wrapper_type_info = window->GetWrapperTypeInfo();
  v8::Local<v8::Context> context = script_state_->GetContext();

  // The global proxy object.  Note this is not the global object.
  v8::Local<v8::Object> global_proxy = context->Global();
  CHECK(global_proxy_ == global_proxy);
  // Use the global proxy as window wrapper object.
  V8DOMWrapper::SetNativeInfo(GetIsolate(), global_proxy, window);
  CHECK(global_proxy_ == window->AssociateWithWrapper(GetIsolate(), world_,
                                                      wrapper_type_info,
                                                      global_proxy));

  // The global object, aka window wrapper object.
  v8::Local<v8::Object> window_wrapper =
      global_proxy->GetPrototype().As<v8::Object>();
  V8DOMWrapper::SetNativeInfo(GetIsolate(), window_wrapper, window);

  // The prototype object of Window interface.
  v8::Local<v8::Object> window_prototype =
      window_wrapper->GetPrototype().As<v8::Object>();
  CHECK(!window_prototype.IsEmpty());

  // The named properties object of Window interface.
  v8::Local<v8::Object> window_properties =
      window_prototype->GetPrototype().As<v8::Object>();
  CHECK(!window_properties.IsEmpty());
  V8DOMWrapper::SetNativeInfo(GetIsolate(), window_properties, window);

  // [CachedAccessor=kWindowProxy]
  V8PrivateProperty::GetCachedAccessor(
      GetIsolate(), V8PrivateProperty::CachedAccessor::kWindowProxy)
      .Set(window_wrapper, global_proxy);

  if (GetFrame()->GetPage()->GetChromeClient().IsPopup()) {
    // TODO(yukishiino): Remove installPagePopupController and implement
    // PagePopupController in another way.
    V8PagePopupControllerBinding::InstallPagePopupController(context,
                                                             window_wrapper);
  }
}

void LocalWindowProxy::UpdateDocumentProperty() {
  DCHECK(world_->IsMainWorld());
  TRACE_EVENT2("v8", "LocalWindowProxy::UpdateDocumentProperty", "IsMainFrame",
               GetFrame()->IsMainFrame(), "IsOutermostMainFrame",
               GetFrame()->IsOutermostMainFrame());

  ScriptState::Scope scope(script_state_);
  v8::Local<v8::Context> context = script_state_->GetContext();
  v8::Local<v8::Value> document_wrapper =
      ToV8Traits<Document>::ToV8(script_state_, GetFrame()->GetDocument());
  DCHECK(document_wrapper->IsObject());

  // Update the cached accessor for window.document.
  CHECK(V8PrivateProperty::GetWindowDocumentCachedAccessor(GetIsolate())
            .Set(context->Global(), document_wrapper));
}

void LocalWindowProxy::UpdateActivityLogger() {
  script_state_->PerContextData()->SetActivityLogger(
      V8DOMActivityLogger::ActivityLogger(
          world_->GetWorldId(), GetFrame()->GetDocument()
                                    ? GetFrame()->GetDocument()->baseURI()
                                    : KURL()));
}

void LocalWindowProxy::SetSecurityToken(const SecurityOrigin* origin) {
  // The security token is a fast path optimization for cross-context v8 checks.
  // If two contexts have the same token, then the SecurityOrigins can access
  // each other. Otherwise, v8 will fall back to a full CanAccess() check.
  String token;
  // The default v8 security token is to the global object itself. By
  // definition, the global object is unique and using it as the security token
  // will always trigger a full CanAccess() check from any other context.
  //
  // Using the default security token to force a callback to CanAccess() is
  // required for three things:
  // 1. When a new window is opened, the browser displays the pending URL rather
  //    than about:blank. However, if the Document is accessed, it is no longer
  //    safe to show the pending URL, as the initial empty Document may have
  //    been modified. Forcing a CanAccess() call allows Blink to notify the
  //    browser if the initial empty Document is accessed.
  // 2. If document.domain is set, a full CanAccess() check is required as two
  //    Documents are only same-origin if document.domain is set to the same
  //    value. Checking this can currently only be done in Blink, so require a
  //    full CanAccess() check.
  bool use_default_security_token =
      world_->IsMainWorld() &&
      (GetFrame()->GetDocument()->IsInitialEmptyDocument() ||
       origin->DomainWasSetInDOM());
  if (origin && !use_default_security_token)
    token = origin->ToTokenForFastCheck();

  // 3. The ToTokenForFastCheck method on SecurityOrigin returns null string for
  //    empty security origins and for security origins that should only allow
  //    access to themselves (i.e. opaque origins). Using the default security
  //    token serves for two purposes: it allows fast-path security checks for
  //    accesses inside the same context, and forces a full CanAccess() check
  //    for contexts that don't inherit the same origin.
  v8::HandleScope handle_scope(GetIsolate());
  v8::Local<v8::Context> context = script_state_->GetContext();
  if (token.IsNull()) {
    context->UseDefaultSecurityToken();
    return;
  }

  if (world_->IsIsolatedWorld()) {
    const SecurityOrigin* frame_security_origin =
        GetFrame()->DomWindow()->GetSecurityOrigin();
    String frame_security_token = frame_security_origin->ToTokenForFastCheck();
    // We need to check the return value of domainWasSetInDOM() on the
    // frame's SecurityOrigin because, if that's the case, only
    // SecurityOrigin::domain_ would have been modified.
    // domain_ is not used by SecurityOrigin::toString(), so we would end
    // up generating the same token that was already set.
    if (frame_security_origin->DomainWasSetInDOM() ||
        frame_security_token.IsNull()) {
      context->UseDefaultSecurityToken();
      return;
    }
    token = frame_security_token + token;
  }

  // NOTE: V8 does identity comparison in fast path, must use a symbol
  // as the security token.
  context->SetSecurityToken(V8AtomicString(GetIsolate(), token));
}

void LocalWindowProxy::UpdateDocument() {
  // For an uninitialized main window proxy, there's nothing we need
  // to update. The update is done when the window proxy gets initialized later.
  if (lifecycle_ == Lifecycle::kContextIsUninitialized)
    return;

  // For a navigated-away window proxy, reinitialize it as a new window with new
  // context and document.
  if (lifecycle_ == Lifecycle::kGlobalObjectIsDetached) {
    Initialize();
    DCHECK_EQ(Lifecycle::kContextIsInitialized, lifecycle_);
    // Initialization internally updates the document properties, so just
    // return afterwards.
    return;
  }

  if (!world_->IsMainWorld())
    return;

  UpdateDocumentForMainWorld();
}

void LocalWindowProxy::UpdateDocumentForMainWorld() {
  DCHECK(world_->IsMainWorld());
  UpdateActivityLogger();
  UpdateDocumentProperty();
  UpdateSecurityOrigin(GetFrame()->DomWindow()->GetSecurityOrigin());
}

namespace {

// GetNamedProperty(), Getter(), NamedItemAdded(), and NamedItemRemoved()
// optimize property access performance for Document.
//
// Document interface has [LegacyOverrideBuiltIns] and a named getter. If we
// implemented the named getter as a standard IDL-mapped code, we would call a
// Blink function before any of Document property access, and it would be
// performance overhead even for builtin properties. Our implementation updates
// V8 accessors for a Document wrapper when a named object is added or removed,
// and avoid to check existence of names objects on accessing any properties.
//
// See crbug.com/614559 for how this affected benchmarks.

v8::Local<v8::Value> GetNamedProperty(HTMLDocument* html_document,
                                      const AtomicString& key,
                                      v8::Local<v8::Object> creation_context,
                                      v8::Isolate* isolate) {
  if (!html_document->HasNamedItem(key))
    return v8::Local<v8::Value>();

  DocumentNameCollection* items = html_document->DocumentNamedItems(key);
  if (items->IsEmpty())
    return v8::Local<v8::Value>();

  if (items->HasExactlyOneItem()) {
    HTMLElement* element = items->Item(0);
    DCHECK(element);
    if (auto* iframe = DynamicTo<HTMLIFrameElement>(*element)) {
      if (Frame* frame = iframe->ContentFrame()) {
        return frame->DomWindow()->ToV8(isolate, creation_context);
      }
    }
    return element->ToV8(isolate, creation_context);
  }
  return items->ToV8(isolate, creation_context);
}

void Getter(v8::Local<v8::Name> property,
            const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (!property->IsString())
    return;
  // FIXME: Consider passing StringImpl directly.
  v8::Isolate* isolate = info.GetIsolate();
  AtomicString name = ToCoreAtomicString(isolate, property.As<v8::String>());
  HTMLDocument* html_document =
      V8HTMLDocument::ToWrappableUnsafe(isolate, info.Holder());
  DCHECK(html_document);
  v8::Local<v8::Value> namedPropertyValue =
      GetNamedProperty(html_document, name, info.Holder(), isolate);
  bool hasNamedProperty = !namedPropertyValue.IsEmpty();

  v8::Local<v8::Value> prototypeChainValue;
  bool hasPropertyInPrototypeChain =
      info.Holder()
          ->GetRealNamedPropertyInPrototypeChain(isolate->GetCurrentContext(),
                                                 property.As<v8::String>())
          .ToLocal(&prototypeChainValue);

  if (hasNamedProperty) {
    bindings::V8SetReturnValue(info, namedPropertyValue);
    UseCounter::Count(
        html_document,
        hasPropertyInPrototypeChain
            ? WebFeature::kDOMClobberedShadowedDocumentPropertyAccessed
            : WebFeature::kDOMClobberedNotShadowedDocumentPropertyAccessed);

    return;
  }
  if (hasPropertyInPrototypeChain) {
    bindings::V8SetReturnValue(info, prototypeChainValue);
  }
}

void EmptySetter(v8::Local<v8::Name> name,
                 v8::Local<v8::Value> value,
                 const v8::PropertyCallbackInfo<void>& info) {
  // Empty setter is required to keep the native data property in "accessor"
  // state even in case the value is updated by user code.
}

}  // namespace

void LocalWindowProxy::NamedItemAdded(HTMLDocument* document,
                                      const AtomicString& name) {
  DCHECK(world_->IsMainWorld());

  // Currently only contexts in attached frames can change the named items.
  // TODO(yukishiino): Support detached frame's case, too, since the spec is not
  // saying that the document needs to be attached to the DOM.
  // https://html.spec.whatwg.org/C/dom.html#dom-document-nameditem
  DCHECK(lifecycle_ == Lifecycle::kContextIsInitialized);
  // TODO(yukishiino): Remove the following if-clause due to the above DCHECK.
  if (lifecycle_ != Lifecycle::kContextIsInitialized)
    return;

  ScriptState::Scope scope(script_state_);
  v8::Local<v8::Object> document_wrapper =
      world_->DomDataStore().Get(GetIsolate(), document).ToLocalChecked();
  // When a non-configurable own property (e.g. unforgeable attribute) already
  // exists, `SetNativeDataProperty` fails and throws. Ignore the exception
  // because own properties have priority over named properties.
  // https://webidl.spec.whatwg.org/#dfn-named-property-visibility
  v8::TryCatch try_block(GetIsolate());
  std::ignore = document_wrapper->SetNativeDataProperty(
      GetIsolate()->GetCurrentContext(), V8String(GetIsolate(), name), Getter,
      EmptySetter);
}

void LocalWindowProxy::NamedItemRemoved(HTMLDocument* document,
                                        const AtomicString& name) {
  DCHECK(world_->IsMainWorld());

  // Currently only contexts in attached frames can change the named items.
  // TODO(yukishiino): Support detached frame's case, too, since the spec is not
  // saying that the document needs to be attached to the DOM.
  // https://html.spec.whatwg.org/C/dom.html#dom-document-nameditem
  DCHECK(lifecycle_ == Lifecycle::kContextIsInitialized);
  // TODO(yukishiino): Remove the following if-clause due to the above DCHECK.
  if (lifecycle_ != Lifecycle::kContextIsInitialized)
    return;

  if (document->HasNamedItem(name))
    return;
  ScriptState::Scope scope(script_state_);
  v8::Local<v8::Object> document_wrapper =
      world_->DomDataStore().Get(GetIsolate(), document).ToLocalChecked();
  document_wrapper
      ->Delete(GetIsolate()->GetCurrentContext(), V8String(GetIsolate(), name))
      .ToChecked();
}

void LocalWindowProxy::UpdateSecurityOrigin(const SecurityOrigin* origin) {
  // For an uninitialized window proxy, there's nothing we need to update. The
  // update is done when the window proxy gets initialized later.
  if (lifecycle_ == Lifecycle::kContextIsUninitialized ||
      lifecycle_ == Lifecycle::kGlobalObjectIsDetached)
    return;

  SetSecurityToken(origin);
}

void LocalWindowProxy::SetAbortScriptExecution(
    v8::Context::AbortScriptExecutionCallback callback) {
  InitializeIfNeeded();
  script_state_->GetContext()->SetAbortScriptExecution(callback);
}

LocalWindowProxy::LocalWindowProxy(v8::Isolate* isolate,
                                   LocalFrame& frame,
                                   DOMWrapperWorld* world)
    : WindowProxy(isolate, frame, world) {}

}  // namespace blink

"""

```