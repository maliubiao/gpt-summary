Response:
Let's break down the thought process for analyzing the `script_controller.cc` file.

1. **Understand the Goal:** The primary goal is to understand the *functionality* of this specific Chromium Blink engine file. This means identifying its key responsibilities and how it interacts with other parts of the browser, especially concerning JavaScript, HTML, and CSS. The prompt also requests examples, error scenarios, and debugging information.

2. **Initial Reading and Keyword Spotting:**  Start by quickly reading through the code, looking for obvious keywords and class names. Things like `ScriptController`, `v8`, `JavaScript`, `Document`, `Frame`, `Window`, `Eval`, `CSP`, `Extension`,  `URL`, and `Inspector` jump out. These provide initial clues about the file's domain.

3. **Core Responsibility - The Name Says It:** The name `ScriptController` strongly suggests its primary role: managing and controlling the execution of scripts within a web page. This is the central hypothesis to test as we delve deeper.

4. **Analyzing Included Headers:** The `#include` directives are invaluable. They reveal dependencies and hint at related functionality:
    * `v8_binding_for_core.h`, `v8_gc_controller.h`, `v8_script_runner.h`: Clearly related to the V8 JavaScript engine integration.
    * `document.h`, `local_dom_window.h`, `local_frame.h`:  Indicates interaction with the DOM structure and frame hierarchy.
    * `content_security_policy.h`: Suggests involvement in security policies related to script execution.
    * `inspector_...h`: Points to interactions with the browser's developer tools.
    * `classic_script.h`: Deals with the representation of JavaScript code.

5. **Examining Public Methods:** Focus on the public methods of the `ScriptController` class. These represent the file's external interface and key functionalities:
    * `WindowProxy()`:  Likely responsible for providing access to the JavaScript `window` object.
    * `UpdateSecurityOrigin()`:  Suggests management of security contexts for scripts.
    * `DisableEval()`, `SetWasmEvalErrorMessage()`: Directly related to controlling the `eval()` function and WebAssembly execution.
    * `RegisterExtensionIfNeeded()`, `ExtensionsFor()`:  Deals with V8 extensions.
    * `ExecuteJavaScriptURL()`:  Handles the execution of `javascript:` URLs.
    * `EvaluateMethodInMainWorld()`:  Provides a way to call JavaScript functions from the C++ side.
    * `CanExecuteScript()`:  A crucial check for determining if script execution is allowed.
    * `CreateNewInspectorIsolatedWorld()`:  Manages isolated JavaScript environments for the developer tools.

6. **Connecting the Dots - Function to Feature:**  Start connecting the methods to specific web development features:
    * `ExecuteJavaScriptURL()` clearly relates to how clicking on `javascript:` links or entering them in the address bar works.
    * `DisableEval()` and `SetWasmEvalErrorMessage()` are about security restrictions.
    * The extension methods deal with extending JavaScript's capabilities.
    * `EvaluateMethodInMainWorld()` is about the browser's internal interaction with JavaScript.

7. **Considering User Actions:** Think about how a user's actions in a browser lead to the execution of code within this file:
    * Opening a web page involves parsing HTML, which might contain `<script>` tags.
    * Clicking a link with `javascript:` in the `href`.
    * Typing or pasting JavaScript code into the browser's console.
    * Developer tools interacting with the page's JavaScript.
    * Browser extensions injecting scripts.

8. **Identifying Potential Issues and Edge Cases:**  Look for areas where things could go wrong:
    * Security vulnerabilities related to `eval()`.
    * Content Security Policy blocking script execution.
    * Errors in JavaScript code.
    * Attempts to execute scripts in contexts where they are disallowed.

9. **Formulating Examples and Scenarios:**  Based on the identified functionalities, create concrete examples:
    * **JavaScript Execution:**  Show a simple `<script>` tag and how it triggers script execution managed by the `ScriptController`.
    * **`eval()` Blocking:** Demonstrate how calling `eval()` might be blocked due to CSP.
    * **JavaScript URLs:**  Illustrate the behavior of `javascript:` links.

10. **Structuring the Output:** Organize the information logically, covering the requested aspects:
    * **Functionality:** Provide a concise overview of the file's purpose.
    * **Relationship to Web Technologies:** Explain how the code interacts with JavaScript, HTML, and CSS, giving specific examples.
    * **Logical Reasoning:** If the code performs decisions or transformations, describe the input and output.
    * **User/Programming Errors:**  Highlight common mistakes and how they might manifest.
    * **Debugging:** Explain how user actions lead to this code being executed, offering debugging entry points.

11. **Refinement and Review:** Read through the analysis to ensure clarity, accuracy, and completeness. Check if all parts of the prompt have been addressed. For instance, explicitly stating the assumptions made during logical reasoning adds rigor.

**Self-Correction Example During the Process:**

* **Initial Thought:** "This file just runs JavaScript."
* **Realization:**  After looking at `DisableEval()` and CSP-related code, I realize it's not *just* running JavaScript, but also *controlling* how and when JavaScript is allowed to run, especially concerning security. This refines the understanding of its role.

By following these steps, you can systematically analyze a source code file and extract meaningful information about its function and relationship to the broader system.
```cpp
/*
 * Copyright (C) 2008, 2009 Google Inc. All rights reserved.
 * Copyright (C) 2009 Apple Inc. All rights reserved.
 * Copyright (C) 2014 Opera Software ASA. All rights reserved.
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

#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"

// ... (rest of the includes and the code)
```

Based on the provided source code of `blink/renderer/bindings/core/v8/script_controller.cc`, here's a breakdown of its functionalities:

**Core Functionality: Managing JavaScript Execution within a Frame**

The primary responsibility of `ScriptController` is to manage the execution of JavaScript code within a browsing context (specifically, a `LocalFrame` in Blink). It acts as an intermediary between the core rendering engine and the V8 JavaScript engine.

**Key Functions:**

1. **V8 Integration:**
   - **Initialization and Access:** It manages the V8 `Isolate` (the V8 engine instance) for a frame. It provides access to the `v8::Context` (the JavaScript execution environment) through `WindowProxy`.
   - **Script Execution:**  It's responsible for running JavaScript code, whether from `<script>` tags, event handlers, or `javascript:` URLs. This involves using `V8ScriptRunner`.
   - **Garbage Collection:** It interacts with `V8GCController` to manage garbage collection in the V8 heap.
   - **Extensions:** It supports registering and managing V8 extensions, which can add custom functionality to the JavaScript environment.

2. **Context Management:**
   - **Window Object:** It manages the `window` object for the frame, represented by `LocalWindowProxy`.
   - **Isolated Worlds:** It supports creating and managing isolated JavaScript worlds, primarily used by browser extensions and the Inspector (developer tools). This allows scripts in different contexts to run without interfering with each other.

3. **Security and Policy Enforcement:**
   - **Content Security Policy (CSP):** It enforces Content Security Policy directives by controlling which scripts are allowed to execute based on the document's origin and CSP headers.
   - **Disabling `eval()`:** It provides mechanisms to disable the `eval()` function and WebAssembly evaluation for security reasons.
   - **`javascript:` URL Handling:** It handles the execution of `javascript:` URLs, including security checks and potential navigation.

4. **Communication with the Rendering Engine:**
   - **Document Updates:** It notifies the rendering engine when JavaScript might have modified the DOM.
   - **Frame Lifecycle:** It participates in the frame lifecycle, including discarding a frame and handling navigation.
   - **Event Handling:** While not directly handling events, it's involved in executing the JavaScript code associated with event handlers.

5. **Inspector Integration:**
   - It creates isolated worlds for the Inspector to interact with the page's JavaScript without interference.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This is the core focus. `ScriptController` is the central point for executing JavaScript code.
    - **Example:** When a `<script>` tag is encountered in the HTML, the parser informs the `ScriptController`, which then compiles and executes the JavaScript code within that tag.
    - **Example:** When an event like `onclick` is triggered on an HTML element with an inline JavaScript handler (`<button onclick="alert('Clicked!')"></button>`), the `ScriptController` executes the `"alert('Clicked!')"` code.
    - **Example:**  Calling `eval("2 + 2")` in JavaScript would involve the `ScriptController` to evaluate this string as JavaScript code (unless `eval()` is disabled).

* **HTML:** `ScriptController` interacts with HTML in several ways:
    - **`<script>` Tag Processing:** As mentioned above, it's responsible for executing scripts embedded within HTML.
    - **Event Handlers:**  It executes JavaScript code specified in HTML event attributes (e.g., `onclick`, `onload`).
    - **`javascript:` URLs in `<a>` tags:** When a user clicks on a link like `<a href="javascript:void(0)"></a>`, the `ScriptController` handles the execution of the `javascript:` URL.

* **CSS:** While `ScriptController` doesn't directly interpret CSS, JavaScript code executed by it can dynamically manipulate CSS styles.
    - **Example:**  JavaScript code like `document.getElementById('myElement').style.color = 'red';` would be executed by the `ScriptController` and would result in the CSS `color` property of the element with the ID `myElement` being changed.
    - **Example:** JavaScript can dynamically add or remove CSS classes to HTML elements, affecting their styling.

**Logical Reasoning (Hypothetical):**

**Scenario:** A user clicks on a button with an `onclick` handler that calls a function `calculateSum(a, b)`.

**Assumptions:**
- The HTML contains `<button onclick="calculateSum(5, 10)">Click Me</button>`.
- A JavaScript function `calculateSum(a, b)` is defined in a `<script>` tag.

**Input:**
- User clicks the button.
- The browser's event handling mechanism triggers the `onclick` event.
- The string `"calculateSum(5, 10)"` needs to be executed as JavaScript.

**Processing within `ScriptController` (simplified):**
1. The `ScriptController` receives the string `"calculateSum(5, 10)"` associated with the `onclick` event.
2. It uses the V8 engine to parse and compile this string into executable JavaScript code within the current execution context.
3. It executes the code, which calls the `calculateSum` function with arguments `5` and `10`.
4. The `calculateSum` function performs its calculation and potentially returns a value (though the return value might not be directly used in this event handler context).

**Output:**
- The `calculateSum` function's logic is executed.
- If `calculateSum` modifies the DOM or performs other side effects, those changes will be reflected in the rendered page.

**User or Programming Common Usage Errors:**

1. **Security Errors (CSP):**
   - **Error:** A website includes a `<script>` tag that attempts to load a script from a domain not allowed by the Content Security Policy.
   - **User Action:**  Navigating to the website.
   - **`ScriptController` Role:** The `ScriptController` checks the CSP headers and blocks the execution of the external script, preventing potential cross-site scripting (XSS) attacks.
   - **Console Output/Error:** A message in the browser's developer console indicating that the script was blocked due to CSP.

2. **`eval()` Usage When Disabled:**
   - **Error:** JavaScript code attempts to use the `eval()` function when it has been disabled (e.g., by CSP or by the browser's internal settings).
   - **User Action:**  The website's JavaScript code attempts to call `eval()`.
   - **`ScriptController` Role:** The `ScriptController` checks if `eval()` is allowed in the current context. If not, it throws an error.
   - **Console Output/Error:** A `ReferenceError` or a similar error indicating that `eval` is not defined or is restricted.

3. **Syntax Errors in JavaScript:**
   - **Error:** A `<script>` tag contains JavaScript code with syntax errors.
   - **User Action:** Navigating to the website.
   - **`ScriptController` Role:** The V8 engine, invoked by the `ScriptController`, will attempt to parse the script. If it encounters a syntax error, it will throw an exception.
   - **Console Output/Error:** A syntax error message in the browser's developer console, indicating the line number and nature of the error.

4. **Referencing Undefined Variables or Functions:**
   - **Error:** JavaScript code attempts to use a variable or function that hasn't been declared or is out of scope.
   - **User Action:** The JavaScript code executes the line containing the error.
   - **`ScriptController` Role:** The V8 engine, during execution, will encounter a `ReferenceError`.
   - **Console Output/Error:** A `ReferenceError` in the browser's developer console, specifying the undefined variable or function.

**User Operation Steps Leading to `script_controller.cc`:**

Let's consider a simple scenario: A user navigates to a web page containing JavaScript.

1. **User Enters URL or Clicks Link:** The user types a URL in the address bar or clicks on a hyperlink.
2. **Browser Requests Resource:** The browser sends a request to the server for the HTML content of the page.
3. **Server Responds with HTML:** The server sends the HTML content back to the browser.
4. **HTML Parsing Begins:** The browser's HTML parser starts processing the received HTML.
5. **`<script>` Tag Encountered:** The parser encounters a `<script>` tag.
6. **Script Extraction and Compilation:** The content of the `<script>` tag (the JavaScript code) is extracted. The parser (or a related component) informs the `ScriptController` about the script.
7. **`ScriptController` Invokes V8:** The `ScriptController` uses the V8 engine to compile the JavaScript code.
8. **Script Execution:** The `ScriptController` (through `V8ScriptRunner`) executes the compiled JavaScript code within the appropriate JavaScript context (the `window` object for that frame).
9. **JavaScript Interacts with DOM/CSS:** The executed JavaScript code might manipulate the Document Object Model (DOM) or Cascading Style Sheets (CSS).
10. **Rendering Updates:** Changes made by JavaScript to the DOM or CSS trigger the rendering engine to update the visual representation of the page.

**Debugging Clues:**

If you suspect an issue related to JavaScript execution, here are some debugging steps that would involve `script_controller.cc` indirectly:

1. **Check Browser's Developer Console:**  Look for JavaScript errors (syntax errors, `ReferenceError`s, CSP violations). These errors often originate from the code managed by `ScriptController`.
2. **Set Breakpoints in JavaScript Code:** Use the browser's developer tools to set breakpoints in your JavaScript code. When the execution reaches those breakpoints, you can inspect the call stack. While you won't directly see `script_controller.cc` in the JavaScript call stack, the events leading up to the JavaScript execution are managed by it.
3. **Inspect Network Tab:**  If you suspect issues with loading external JavaScript files, check the Network tab in the developer tools to see if the scripts were loaded successfully and if there were any CSP-related blocking.
4. **Examine CSP Headers:** Inspect the `Content-Security-Policy` headers in the Network tab to understand the security restrictions in place.
5. **Blink-Specific Debugging (More Advanced):**
   - **Logging:**  Blink has extensive logging capabilities. You might find logs related to script execution, CSP enforcement, or V8 integration.
   - **Tracing:** Blink's tracing infrastructure (`TRACE_EVENT`) can provide detailed information about the execution flow, including the involvement of `ScriptController`. You would need to build a debug version of Chromium and enable tracing.

In summary, `script_controller.cc` is a crucial component in the Chromium Blink rendering engine, acting as the central coordinator for JavaScript execution within web pages. It bridges the gap between the rendering engine and the V8 JavaScript engine, enforcing security policies and managing different execution contexts. Understanding its role is essential for comprehending how web pages with JavaScript functionality are processed and rendered.

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/script_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2008, 2009 Google Inc. All rights reserved.
 * Copyright (C) 2009 Apple Inc. All rights reserved.
 * Copyright (C) 2014 Opera Software ASA. All rights reserved.
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

#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"

#include <memory>
#include <utility>

#include "base/functional/callback_helpers.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy_manager.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/progress_tracker.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"

namespace blink {

namespace {
bool IsTrivialScript(const String& script) {
  if (script.length() > 25) {
    return false;
  }

  DEFINE_STATIC_LOCAL(Vector<String>, trivial_scripts,
                      ({"void(0)",
                        "void0",
                        "void(false)",
                        "void(null)",
                        "void(-1)",
                        "false",
                        "true",
                        "",
                        "''",
                        "\"\"",
                        "undefined",
                        "0",
                        "1",
                        "'1'",
                        "print()",
                        "window.print()",
                        "close()",
                        "window.close()",
                        "history.back()",
                        "window.history.back()",
                        "history.go(-1)",
                        "window.history.go(-1)"}));
  String processed_script = script.StripWhiteSpace().Replace(";", "");
  return trivial_scripts.Contains(processed_script);
}

}  // namespace

void ScriptController::Trace(Visitor* visitor) const {
  visitor->Trace(window_);
  visitor->Trace(window_proxy_manager_);
}

LocalWindowProxy* ScriptController::WindowProxy(DOMWrapperWorld& world) {
  return window_proxy_manager_->WindowProxy(world);
}

void ScriptController::UpdateSecurityOrigin(
    const SecurityOrigin* security_origin) {
  window_proxy_manager_->UpdateSecurityOrigin(security_origin);
}

TextPosition ScriptController::EventHandlerPosition() const {
  ScriptableDocumentParser* parser =
      window_->document()->GetScriptableDocumentParser();
  if (parser)
    return parser->GetTextPosition();
  return TextPosition::MinimumPosition();
}

void ScriptController::DisableEval(const String& error_message) {
  SetEvalForWorld(DOMWrapperWorld::MainWorld(GetIsolate()),
                  false /* allow_eval */, error_message);
}

void ScriptController::SetWasmEvalErrorMessage(const String& error_message) {
  SetWasmEvalErrorMessageForWorld(DOMWrapperWorld::MainWorld(GetIsolate()),
                                  /*allow_eval=*/false, error_message);
}

void ScriptController::DisableEvalForIsolatedWorld(
    int32_t world_id,
    const String& error_message) {
  DCHECK(DOMWrapperWorld::IsIsolatedWorldId(world_id));
  DOMWrapperWorld* world =
      DOMWrapperWorld::EnsureIsolatedWorld(GetIsolate(), world_id);
  SetEvalForWorld(*world, false /* allow_eval */, error_message);
}

void ScriptController::SetWasmEvalErrorMessageForIsolatedWorld(
    int32_t world_id,
    const String& error_message) {
  DCHECK(DOMWrapperWorld::IsIsolatedWorldId(world_id));
  DOMWrapperWorld* world =
      DOMWrapperWorld::EnsureIsolatedWorld(GetIsolate(), world_id);
  SetWasmEvalErrorMessageForWorld(*world, /*allow_eval=*/false, error_message);
}

void ScriptController::SetEvalForWorld(DOMWrapperWorld& world,
                                       bool allow_eval,
                                       const String& error_message) {
  v8::HandleScope handle_scope(GetIsolate());
  LocalWindowProxy* proxy =
      world.IsMainWorld()
          ? window_proxy_manager_->MainWorldProxyMaybeUninitialized()
          : WindowProxy(world);

  v8::Local<v8::Context> v8_context = proxy->ContextIfInitialized();
  if (v8_context.IsEmpty())
    return;

  v8_context->AllowCodeGenerationFromStrings(allow_eval);
  if (allow_eval)
    return;

  v8_context->SetErrorMessageForCodeGenerationFromStrings(
      V8String(GetIsolate(), error_message));
}

void ScriptController::SetWasmEvalErrorMessageForWorld(
    DOMWrapperWorld& world,
    bool allow_eval,
    const String& error_message) {
  // For now we have nothing to do in case we want to enable wasm-eval.
  if (allow_eval)
    return;

  v8::HandleScope handle_scope(GetIsolate());
  LocalWindowProxy* proxy =
      world.IsMainWorld()
          ? window_proxy_manager_->MainWorldProxyMaybeUninitialized()
          : WindowProxy(world);

  v8::Local<v8::Context> v8_context = proxy->ContextIfInitialized();
  if (v8_context.IsEmpty())
    return;

  v8_context->SetErrorMessageForWasmCodeGeneration(
      V8String(GetIsolate(), error_message));
}

namespace {

Vector<const char*>& RegisteredExtensionNames() {
  DEFINE_STATIC_LOCAL(Vector<const char*>, extension_names, ());
  return extension_names;
}

}  // namespace

void ScriptController::RegisterExtensionIfNeeded(
    std::unique_ptr<v8::Extension> extension) {
  for (const auto* extension_name : RegisteredExtensionNames()) {
    if (!strcmp(extension_name, extension->name()))
      return;
  }
  RegisteredExtensionNames().push_back(extension->name());
  v8::RegisterExtension(std::move(extension));
}

v8::ExtensionConfiguration ScriptController::ExtensionsFor(
    const ExecutionContext* context) {
  if (context->ShouldInstallV8Extensions()) {
    return v8::ExtensionConfiguration(RegisteredExtensionNames().size(),
                                      RegisteredExtensionNames().data());
  }
  return v8::ExtensionConfiguration();
}

void ScriptController::UpdateDocument() {
  window_proxy_manager_->UpdateDocument();
}

void ScriptController::DiscardFrame() {
  DCHECK(window_->GetFrame());
  auto* previous_document_loader =
      window_->GetFrame()->Loader().GetDocumentLoader();
  DCHECK(previous_document_loader);
  auto params =
      previous_document_loader->CreateWebNavigationParamsToCloneDocument();
  WebNavigationParams::FillStaticResponse(params.get(), "text/html", "UTF-8",
                                          base::span<const char>());
  params->frame_load_type = WebFrameLoadType::kReplaceCurrentItem;
  window_->GetFrame()->Loader().CommitNavigation(std::move(params), nullptr,
                                                 CommitReason::kDiscard);
}

void ScriptController::ExecuteJavaScriptURL(
    const KURL& url,
    network::mojom::CSPDisposition csp_disposition,
    const DOMWrapperWorld* world_for_csp) {
  DCHECK(url.ProtocolIsJavaScript());

  if (!window_->GetFrame())
    return;

  bool had_navigation_before =
      window_->GetFrame()->Loader().HasProvisionalNavigation();

  // https://html.spec.whatwg.org/multipage/browsing-the-web.html#javascript-protocol
  // Step 6. "Let baseURL be settings's API base URL." [spec text]
  const KURL base_url = window_->BaseURL();

  String script_source = window_->CheckAndGetJavascriptUrl(
      world_for_csp, url, nullptr /* element */, csp_disposition);

  // Step 7. "Let script be the result of creating a classic script given
  // scriptSource, settings, baseURL, and the default classic script fetch
  // options." [spec text]
  //
  // We pass |SanitizeScriptErrors::kDoNotSanitize| because |muted errors| is
  // false by default.
  ClassicScript* script = ClassicScript::Create(
      script_source, KURL(), base_url, ScriptFetchOptions(),
      ScriptSourceLocationType::kJavascriptUrl,
      SanitizeScriptErrors::kDoNotSanitize);

  DCHECK_EQ(&window_->GetScriptController(), this);
  v8::Isolate* isolate = GetIsolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Value> v8_result =
      script->RunScriptAndReturnValue(window_).GetSuccessValueOrEmpty();
  UseCounter::Count(window_.Get(), WebFeature::kExecutedJavaScriptURL);

  // CSPDisposition::CHECK indicate that the JS URL comes from a site (and not
  // from bookmarks or extensions). Empty v8_result indicate that the script
  // had a failure at the time of execution.
  if (csp_disposition == network::mojom::CSPDisposition::CHECK &&
      !v8_result.IsEmpty()) {
    if (!IsTrivialScript(script_source)) {
      UseCounter::Count(window_.Get(),
                        WebFeature::kExecutedNonTrivialJavaScriptURL);
    }
  }

  // If executing script caused this frame to be removed from the page, we
  // don't want to try to replace its document!
  if (!window_->GetFrame())
    return;
  // If a navigation begins during the javascript: url's execution, ignore
  // the return value of the script. Otherwise, replacing the document with a
  // string result would cancel the navigation.
  // TODO(crbug.com/1085514): Consider making HasProvisionalNavigation return
  // true when a form submission is pending instead of having a separate check
  // for form submissions here.
  if (!had_navigation_before &&
      (window_->GetFrame()->Loader().HasProvisionalNavigation() ||
       window_->GetFrame()->IsFormSubmissionPending())) {
    return;
  }
  if (v8_result.IsEmpty() || !v8_result->IsString())
    return;

  UseCounter::Count(window_.Get(),
                    WebFeature::kReplaceDocumentViaJavaScriptURL);

  auto* previous_document_loader =
      window_->GetFrame()->Loader().GetDocumentLoader();
  DCHECK(previous_document_loader);
  auto params =
      previous_document_loader->CreateWebNavigationParamsToCloneDocument();
  String result = ToCoreString(isolate, v8::Local<v8::String>::Cast(v8_result));
  WebNavigationParams::FillStaticResponse(
      params.get(), "text/html", "UTF-8",
      StringUTF8Adaptor(
          result, kStrictUTF8ConversionReplacingUnpairedSurrogatesWithFFFD));
  params->frame_load_type = WebFrameLoadType::kReplaceCurrentItem;
  window_->GetFrame()->Loader().CommitNavigation(std::move(params), nullptr,
                                                 CommitReason::kJavascriptUrl);
}

v8::Local<v8::Value> ScriptController::EvaluateMethodInMainWorld(
    v8::Local<v8::Function> function,
    v8::Local<v8::Value> receiver,
    int argc,
    v8::Local<v8::Value> argv[]) {
  if (!CanExecuteScript(
          ExecuteScriptPolicy::kDoNotExecuteScriptWhenScriptsDisabled)) {
    return v8::Local<v8::Value>();
  }

  // |script_state->GetContext()| should be initialized already due to the
  // WindowProxy() call inside ToScriptStateForMainWorld().
  ScriptState* script_state = ToScriptStateForMainWorld(window_->GetFrame());
  if (!script_state) {
    return v8::Local<v8::Value>();
  }
  DCHECK_EQ(script_state->GetIsolate(), GetIsolate());

  v8::Context::Scope scope(script_state->GetContext());
  v8::EscapableHandleScope handle_scope(GetIsolate());

  v8::TryCatch try_catch(GetIsolate());
  try_catch.SetVerbose(true);

  ExecutionContext* executionContext = ExecutionContext::From(script_state);

  v8::MaybeLocal<v8::Value> resultObj = V8ScriptRunner::CallFunction(
      function, executionContext, receiver, argc,
      static_cast<v8::Local<v8::Value>*>(argv), ToIsolate(window_->GetFrame()));

  if (resultObj.IsEmpty())
    return v8::Local<v8::Value>();

  return handle_scope.Escape(resultObj.ToLocalChecked());
}

bool ScriptController::CanExecuteScript(ExecuteScriptPolicy policy) {
  if (policy == ExecuteScriptPolicy::kDoNotExecuteScriptWhenScriptsDisabled &&
      !window_->CanExecuteScripts(kAboutToExecuteScript))
    return false;

  if (window_->document()->IsInitialEmptyDocument())
    window_->GetFrame()->Loader().DidAccessInitialDocument();

  return true;
}

v8::Isolate* ScriptController::GetIsolate() const {
  return window_proxy_manager_->GetIsolate();
}

DOMWrapperWorld* ScriptController::CreateNewInspectorIsolatedWorld(
    const String& world_name) {
  DOMWrapperWorld* world = DOMWrapperWorld::Create(
      GetIsolate(), DOMWrapperWorld::WorldType::kInspectorIsolated);
  // Bail out if we could not create an isolated world.
  if (!world)
    return nullptr;
  if (!world_name.empty()) {
    DOMWrapperWorld::SetNonMainWorldHumanReadableName(world->GetWorldId(),
                                                      world_name);
  }
  // Make sure the execution context exists.
  WindowProxy(*world);
  return world;
}

}  // namespace blink
```