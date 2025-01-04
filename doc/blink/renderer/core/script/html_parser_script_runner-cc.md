Response:
Let's break down the thought process to analyze the provided C++ code.

1. **Understand the Goal:** The request is to analyze the `html_parser_script_runner.cc` file in Blink and explain its functionality, especially its relation to JavaScript, HTML, and CSS. It also asks for examples, logical reasoning, error handling, and debugging hints.

2. **Identify the Core Functionality:** The name "HTMLParserScriptRunner" immediately suggests its primary role: managing the execution of scripts encountered during HTML parsing.

3. **Examine Key Data Members:**  Looking at the class members provides crucial context:
    * `reentry_permit_`:  This hints at handling re-entrant parsing situations, likely due to inline scripts.
    * `document_`:  The runner is tied to a specific HTML document.
    * `host_`:  An interface to interact with the HTML parser (like providing input stream).
    * `parser_blocking_script_`:  Indicates the runner manages scripts that block further parsing.
    * `scripts_to_execute_after_parsing_`: Manages scripts that should run after the initial HTML parsing is complete (like `defer` scripts).

4. **Analyze Key Methods:**  Focus on the most prominent methods:
    * `ProcessScriptElement`:  This seems to be the main entry point when a `<script>` tag is encountered. It handles both inline and external scripts.
    * `ExecutePendingParserBlockingScriptAndDispatchEvent`:  Specifically handles executing scripts that block parsing.
    * `ExecutePendingDeferredScriptAndDispatchEvent`:  Deals with scripts that are deferred.
    * `ExecuteParsingBlockingScripts`:  Manages the loop for executing parser-blocking scripts.
    * `ExecuteScriptsWaitingForParsing`: Handles the execution of deferred scripts after parsing.
    * `IsParserBlockingScriptReady`:  Checks if a parser-blocking script is ready to execute (considering dependencies).

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The core purpose is to run JavaScript code embedded or linked in HTML. The methods clearly deal with script execution, loading, and dependencies.
    * **HTML:**  The runner interacts directly with the HTML parser. It receives `<script>` elements and determines how they should be handled in the parsing process. The concept of "parser-blocking" is directly related to HTML parsing.
    * **CSS:** The code mentions "style sheet that is blocking scripts."  This highlights a crucial interaction:  CSS loading can delay script execution. The `IsParserBlockingScriptReady` method explicitly checks for this.

6. **Illustrate with Examples:**  Think of common HTML scenarios:
    * **Inline Script:** `<script>console.log("hello");</script>` - How would this be processed?  Likely as a parser-blocking inline script.
    * **External Script:** `<script src="script.js"></script>` - How would the loading and execution be managed?  Potentially parser-blocking until loaded.
    * **`defer` Script:** `<script src="deferred.js" defer></script>` - How is this added to `scripts_to_execute_after_parsing_`?
    * **CSS Blocking:**  Imagine a `<link rel="stylesheet" href="style.css">` *before* a `<script>`. How does the script runner wait for the CSS to load if it's blocking?

7. **Infer Logical Reasoning:**
    * **Parser Blocking:**  The code clearly prioritizes certain scripts to block the parser. Why? To ensure that scripts that might manipulate the DOM are executed before the parser continues building the DOM.
    * **Deferred Scripts:**  Why have a separate queue for deferred scripts? To allow the initial HTML parsing to complete before executing scripts that don't need to run immediately.
    * **Asynchronous Loading:** The code hints at asynchronous script loading and the need to wait for resources.

8. **Consider User/Programming Errors:**
    * **Blocking Behavior:** A common mistake is having a large, synchronous script at the beginning of the `<body>`, which can significantly delay page rendering.
    * **Dependency Issues:** Scripts relying on each other being loaded in the correct order can lead to errors if `async` or `defer` are not used carefully.

9. **Construct Debugging Hints:** Think about how a developer might end up in this code during debugging:
    * **Breakpoints:** Setting breakpoints in `ProcessScriptElement` or the execution methods would be useful.
    * **Tracing:** The code itself uses `TRACE_EVENT`. Understanding how to view these trace events would be key.
    * **Performance Analysis:**  Investigating why parsing is slow might lead to this code.

10. **Structure the Answer:** Organize the findings into clear sections as requested (functionality, relation to web tech, examples, reasoning, errors, debugging).

11. **Review and Refine:**  Read through the generated answer, ensuring clarity, accuracy, and completeness. Are the examples relevant? Is the reasoning sound?  Are the debugging tips practical?  *Self-correction: Initially, I might have focused too much on the individual methods without clearly explaining the overarching flow of script processing during HTML parsing. Refining this would involve emphasizing the role of the parser-blocking queue and the deferred queue.*
好的，让我们来详细分析一下 `blink/renderer/core/script/html_parser_script_runner.cc` 这个文件。

**功能概述:**

`HTMLParserScriptRunner` 的主要职责是在 HTML 解析过程中管理和执行 `<script>` 标签中的 JavaScript 代码。它作为 HTML 解析器和 JavaScript 引擎之间的桥梁，负责以下关键功能：

1. **识别和管理待执行的脚本:** 当 HTML 解析器遇到 `<script>` 标签时，`HTMLParserScriptRunner` 会接收到通知，并根据脚本的属性（例如 `src`, `async`, `defer`）将其添加到不同的待执行队列中。
2. **处理不同类型的脚本:**  它区分并处理以下几种类型的脚本：
    * **Parser-blocking scripts (阻塞解析的脚本):**  默认情况下，内联脚本和没有 `async` 或 `defer` 属性的外部脚本会阻塞 HTML 解析器的进一步解析，直到脚本执行完成。
    * **Deferred scripts (延迟脚本):** 带有 `defer` 属性的脚本会在 HTML 文档解析完成后，按照它们在文档中出现的顺序执行。
    * **Asynchronous scripts (异步脚本):** 带有 `async` 属性的外部脚本会并行下载，并在下载完成后立即执行，不保证执行顺序。
3. **控制脚本执行的时机:** `HTMLParserScriptRunner` 负责决定何时执行哪个脚本。对于阻塞解析的脚本，它会在解析到 `</script>` 标签时尝试执行。对于延迟脚本，它会在解析完成后执行。
4. **处理脚本加载:** 对于外部脚本，它会监控脚本的加载状态，并在加载完成后触发执行。
5. **维护脚本嵌套层级:**  当脚本执行时，可能会插入新的 `<script>` 标签（例如通过 `document.write`），`HTMLParserScriptRunner` 会维护一个脚本嵌套层级，以防止无限递归。
6. **与 HTML 解析器协同工作:**  它通过 `HTMLParserScriptRunnerHost` 接口与 HTML 解析器进行通信，例如通知解析器脚本已加载，可以继续解析。
7. **性能追踪和调试支持:**  代码中包含 `TRACE_EVENT` 等宏，用于性能追踪和调试。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **与 JavaScript 的关系:** `HTMLParserScriptRunner` 的核心任务就是执行 JavaScript 代码。
    * **例子:**  当解析器遇到 `<script> console.log("Hello from inline script"); </script>` 时，`HTMLParserScriptRunner` 会提取 `console.log("Hello from inline script");` 这段 JavaScript 代码并交给 JavaScript 引擎执行。
    * **例子:** 当解析器遇到 `<script src="myscript.js"></script>` 时，`HTMLParserScriptRunner` 会触发 `myscript.js` 的加载，并在加载完成后执行其中的 JavaScript 代码。

* **与 HTML 的关系:** `HTMLParserScriptRunner` 是 HTML 解析过程中的一个关键组成部分。它依赖于 HTML 结构（特别是 `<script>` 标签）来确定需要执行的脚本。
    * **例子:** HTML 中的 `<script async src="analytics.js"></script>` 会指示 `HTMLParserScriptRunner` 异步加载并执行 `analytics.js`，而不会阻塞 HTML 的解析。
    * **例子:** HTML 中的 `<script defer src="interactions.js"></script>` 会告诉 `HTMLParserScriptRunner` 在 HTML 解析完成后，再执行 `interactions.js`。

* **与 CSS 的关系:**  CSS 的加载会影响脚本的执行，特别是对于阻塞解析的脚本。如果存在正在加载的 CSS 样式表，并且该样式表被标记为阻塞脚本（通常是因为它在脚本之前），`HTMLParserScriptRunner` 会暂停脚本的执行，直到 CSS 加载完成。
    * **例子:** 如果 HTML 中有以下代码：
        ```html
        <link rel="stylesheet" href="style.css">
        <script>
          // 这段脚本可能会依赖 style.css 中的样式信息
          console.log(getComputedStyle(document.body).backgroundColor);
        </script>
        ```
        `HTMLParserScriptRunner` 会在 `style.css` 加载完成后再执行这段脚本，以确保脚本可以获取到正确的样式信息。

**逻辑推理 (假设输入与输出):**

假设 HTML 解析器解析到以下片段：

```html
<script>console.log("First inline");</script>
<script src="external1.js"></script>
<script async src="async1.js"></script>
<script defer src="defer1.js"></script>
<script>console.log("Second inline");</script>
<script defer src="defer2.js"></script>
```

**假设输入:**  HTML 解析器解析到上述代码片段。

**逻辑推理过程:**

1. **`<script>console.log("First inline");</script>`:**
   - `HTMLParserScriptRunner` 识别到这是一个内联脚本，默认是阻塞解析的。
   - **假设输出:**  `console.log("First inline")` 会被立即执行，HTML 解析暂停。

2. **`<script src="external1.js"></script>`:**
   - `HTMLParserScriptRunner` 识别到这是一个外部脚本，没有 `async` 或 `defer` 属性，默认是阻塞解析的。
   - **假设输出:**  `external1.js` 开始加载，HTML 解析继续暂停，直到 `external1.js` 加载并执行完毕。

3. **`<script async src="async1.js"></script>`:**
   - `HTMLParserScriptRunner` 识别到这是一个异步外部脚本。
   - **假设输出:** `async1.js` 开始异步加载，HTML 解析继续进行，`async1.js` 下载完成后会立即执行，执行顺序不确定。

4. **`<script defer src="defer1.js"></script>`:**
   - `HTMLParserScriptRunner` 识别到这是一个延迟外部脚本。
   - **假设输出:** `defer1.js` 开始加载，但不会阻塞 HTML 解析，也不会立即执行，而是被添加到延迟执行队列中。

5. **`<script>console.log("Second inline");</script>`:**
   - `HTMLParserScriptRunner` 识别到这是一个内联脚本，默认是阻塞解析的。
   - **假设输出:** `console.log("Second inline")` 会被执行，HTML 解析暂停。

6. **`<script defer src="defer2.js"></script>`:**
   - `HTMLParserScriptRunner` 识别到这是一个延迟外部脚本。
   - **假设输出:** `defer2.js` 开始加载，但不会阻塞 HTML 解析，也不会立即执行，而是被添加到延迟执行队列中。

**最终输出 (执行顺序):**

1. "First inline" (立即执行)
2. `external1.js` 的内容 (加载并执行)
3. "Second inline" (立即执行)
4. `async1.js` 的内容 (异步加载完成后执行，可能在 `defer1.js` 或 `defer2.js` 之前或之后)
5. `defer1.js` 的内容 (HTML 解析完成后，按照出现顺序执行)
6. `defer2.js` 的内容 (HTML 解析完成后，按照出现顺序执行)

**用户或编程常见的使用错误及举例说明:**

1. **阻塞渲染:**  将大量同步执行的 JavaScript 代码放在 `<head>` 或 `<body>` 的开头，会导致浏览器渲染页面时出现明显的延迟，用户会看到白屏。
   ```html
   <!DOCTYPE html>
   <html>
   <head>
       <meta charset="UTF-8">
       <title>Blocking Example</title>
       <script>
           // 假设这段代码执行时间很长
           for (let i = 0; i < 1000000000; i++) {
               // Do something
           }
       </script>
   </head>
   <body>
       <h1>Hello World</h1>
   </body>
   </html>
   ```
   **错误:** 用户会长时间看到空白页面，直到脚本执行完成。

2. **依赖执行顺序的异步脚本:**  不正确地使用 `async` 可能会导致脚本执行顺序错乱，如果后面的脚本依赖于前面异步脚本的结果，则可能出错。
   ```html
   <script async src="module1.js"></script>
   <script async src="module2.js"></script>
   <script>
       // 假设 module2.js 的执行依赖于 module1.js 初始化的一些全局变量
       console.log(globalVariableFromModule1); // 可能会报错，因为 module1.js 可能还没执行完
   </script>
   ```
   **错误:** `module2.js` 可能会在 `module1.js` 之前执行，导致依赖的变量未定义。

3. **`document.write` 的滥用:** 在解析完成后使用 `document.write` 可能会导致页面内容被覆盖，或者在某些情况下不执行。虽然 `HTMLParserScriptRunner` 需要处理这种情况，但这不是推荐的做法。
   ```html
   <!DOCTYPE html>
   <html>
   <head>
       <meta charset="UTF-8">
       <title>Document Write Example</title>
   </head>
   <body>
       <script>
           window.onload = function() {
               document.write("<h1>Content written after load</h1>");
           };
       </script>
       <h1>Initial Content</h1>
   </body>
   </html>
   ```
   **错误:**  在 `window.onload` 事件触发后，`document.write` 可能会清除现有的页面内容。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者遇到了一个与脚本执行顺序或者阻塞渲染相关的问题，想要调试 `HTMLParserScriptRunner.cc` 中的代码，可能的步骤如下：

1. **用户在浏览器中打开一个网页:**  用户的这个操作会触发浏览器的 HTML 解析器开始解析网页的 HTML 内容。

2. **HTML 解析器遇到 `<script>` 标签:** 当解析器遇到一个 `<script>` 标签时，它会创建一个 `HTMLScriptElement` 对象，并将相关信息传递给 `HTMLParserScriptRunner`。

3. **`HTMLParserScriptRunner::ProcessScriptElement` 被调用:** 这是处理 `<script>` 标签的主要入口点。开发者可能会在这个函数设置断点，查看传入的 `script_element` 和 `script_start_position`。

4. **根据脚本类型，代码会进入不同的处理分支:**
   - 如果是阻塞脚本，可能会进入 `ExecutePendingParserBlockingScriptAndDispatchEvent`。
   - 如果是延迟脚本，会被添加到 `scripts_to_execute_after_parsing_` 队列。
   - 如果是异步脚本，可能会触发脚本的异步加载。

5. **如果涉及到外部脚本:**
   - `ScriptLoader` 会负责脚本的加载。
   - 当脚本加载完成时，`HTMLParserScriptRunner::PendingScriptFinished` 会被调用。

6. **如果问题是阻塞渲染:** 开发者可能会关注 `IsParserBlockingScriptReady` 函数，查看是否有 CSS 阻塞了脚本的执行。

7. **如果问题是执行顺序:** 开发者可能会查看 `ExecuteScriptsWaitingForParsing` 函数，了解延迟脚本的执行顺序。

**调试线索:**

* **断点:** 在 `ProcessScriptElement`, `ExecutePendingParserBlockingScriptAndDispatchEvent`, `ExecuteScriptsWaitingForParsing`, `PendingScriptFinished` 等关键函数设置断点，可以观察脚本的处理流程。
* **日志输出:**  可以使用 `DLOG` 或 `VLOG` 在代码中添加日志输出，记录关键变量的值，例如脚本的 URL、加载状态、执行时机等。
* **Chrome DevTools 的 Performance 面板:**  可以用来分析页面加载过程中的性能瓶颈，查看脚本的加载和执行时间，以及是否发生了阻塞渲染。
* **Chrome DevTools 的 Sources 面板:**  可以用来调试 JavaScript 代码，查看脚本执行时的调用栈。
* **Blink 内部的 Tracing 工具:** 代码中使用的 `TRACE_EVENT` 可以通过 Chrome 的 `chrome://tracing` 工具进行查看，了解脚本处理过程中的详细事件。

总而言之，`HTMLParserScriptRunner.cc` 是 Blink 渲染引擎中一个至关重要的组件，它负责在 HTML 解析过程中协调和执行 JavaScript 代码，确保网页的动态功能能够正确运行。理解其功能和工作原理对于理解浏览器如何加载和执行 JavaScript 代码至关重要，也有助于开发者避免常见的性能问题和错误。

Prompt: 
```
这是目录为blink/renderer/core/script/html_parser_script_runner.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2010 Google, Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/script/html_parser_script_runner.h"

#include <inttypes.h>
#include <memory>
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/dom/document_parser_timing.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/nesting_level_incrementer.h"
#include "third_party/blink/renderer/core/html/parser/html_input_stream.h"
#include "third_party/blink/renderer/core/script/html_parser_script_runner_host.h"
#include "third_party/blink/renderer/core/script/script_loader.h"
#include "third_party/blink/renderer/core/script/script_runner.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"

namespace blink {

namespace {

// TODO(bmcquade): move this to a shared location if we find ourselves wanting
// to trace similar data elsewhere in the codebase.
std::unique_ptr<TracedValue> GetTraceArgsForScriptElement(
    Document& document,
    const TextPosition& text_position,
    const KURL& url) {
  auto value = std::make_unique<TracedValue>();
  if (!url.IsNull())
    value->SetString("url", url.GetString());
  if (document.GetFrame()) {
    value->SetString(
        "frame",
        String::Format("0x%" PRIx64,
                       static_cast<uint64_t>(
                           reinterpret_cast<intptr_t>(document.GetFrame()))));
  }
  if (text_position.line_.ZeroBasedInt() > 0 ||
      text_position.column_.ZeroBasedInt() > 0) {
    value->SetInteger("lineNumber", text_position.line_.OneBasedInt());
    value->SetInteger("columnNumber", text_position.column_.OneBasedInt());
  }
  return value;
}

void DoExecuteScript(PendingScript* pending_script, Document& document) {
  TRACE_EVENT_WITH_FLOW1(
      "blink", "HTMLParserScriptRunner ExecuteScript",
      pending_script->GetElement(), TRACE_EVENT_FLAG_FLOW_IN, "data",
      GetTraceArgsForScriptElement(document, pending_script->StartingPosition(),
                                   pending_script->UrlForTracing()));
  pending_script->ExecuteScriptBlock();
}

void TraceParserBlockingScript(const PendingScript* pending_script,
                               Document& document) {
  // The HTML parser must yield before executing script in the following
  // cases:
  // * the script's execution is blocked on the completed load of the script
  //   resource
  //   (https://html.spec.whatwg.org/C/#pending-parsing-blocking-script)
  // * the script's execution is blocked on the load of a style sheet or other
  //   resources that are blocking scripts
  //   (https://html.spec.whatwg.org/C/#a-style-sheet-that-is-blocking-scripts)
  //
  // Both of these cases can introduce significant latency when loading a
  // web page, especially for users on slow connections, since the HTML parser
  // must yield until the blocking resources finish loading.
  //
  // We trace these parser yields here using flow events, so we can track
  // both when these yields occur, as well as how long the parser had
  // to yield. The connecting flow events are traced once the parser becomes
  // unblocked when the script actually executes, in doExecuteScript.
  ScriptElementBase* element = pending_script->GetElement();
  if (!element)
    return;
  bool waiting_for_resources = !document.IsScriptExecutionReady();

  auto script_element_trace_lambda = [&]() {
    return GetTraceArgsForScriptElement(document,
                                        pending_script->StartingPosition(),
                                        pending_script->UrlForTracing());
  };
  if (!pending_script->IsReady()) {
    if (waiting_for_resources) {
      TRACE_EVENT_WITH_FLOW1(
          "blink", "YieldParserForScriptLoadAndBlockingResources", element,
          TRACE_EVENT_FLAG_FLOW_OUT, "data", script_element_trace_lambda());
    } else {
      TRACE_EVENT_WITH_FLOW1("blink", "YieldParserForScriptLoad", element,
                             TRACE_EVENT_FLAG_FLOW_OUT, "data",
                             script_element_trace_lambda());
    }
  } else if (waiting_for_resources) {
    TRACE_EVENT_WITH_FLOW1("blink", "YieldParserForScriptBlockingResources",
                           element, TRACE_EVENT_FLAG_FLOW_OUT, "data",
                           script_element_trace_lambda());
  }
}

}  // namespace

HTMLParserScriptRunner::HTMLParserScriptRunner(
    HTMLParserReentryPermit* reentry_permit,
    Document* document,
    HTMLParserScriptRunnerHost* host)
    : reentry_permit_(reentry_permit), document_(document), host_(host) {
  DCHECK(host_);
}

HTMLParserScriptRunner::~HTMLParserScriptRunner() {}

void HTMLParserScriptRunner::Detach() {
  if (!document_)
    return;

  if (parser_blocking_script_)
    parser_blocking_script_->Dispose();
  parser_blocking_script_ = nullptr;

  while (!scripts_to_execute_after_parsing_.empty()) {
    PendingScript* pending_script =
        scripts_to_execute_after_parsing_.TakeFirst();
    pending_script->Dispose();
  }
  document_ = nullptr;
  // m_reentryPermit is not cleared here, because the script runner
  // may continue to run pending scripts after the parser has
  // detached.
}

bool HTMLParserScriptRunner::IsParserBlockingScriptReady() {
  DCHECK(ParserBlockingScript());
  if (!document_->IsScriptExecutionReady())
    return false;
  // TODO(crbug.com/1344772) Consider moving this condition to
  // Document::IsScriptExecutionReady(), while we are not yet sure.
  if (base::FeatureList::IsEnabled(features::kForceInOrderScript) &&
      document_->GetScriptRunner()->HasForceInOrderScripts())
    return false;
  return ParserBlockingScript()->IsReady();
}

// Corresponds to some steps of the "Otherwise" Clause of 'An end tag whose
// tag name is "script"'
// <specdef href="https://html.spec.whatwg.org/C/#scriptEndTag">
void HTMLParserScriptRunner::
    ExecutePendingParserBlockingScriptAndDispatchEvent() {
  // <spec step="B.1">Let the script be the pending parsing-blocking
  // script.</spec>
  PendingScript* pending_script = parser_blocking_script_;

  // Stop watching loads before executeScript to prevent recursion if the script
  // reloads itself.
  // TODO(kouhei): Consider merging this w/ pendingScript->dispose() after the
  // if block.
  // TODO(kouhei, hiroshige): Consider merging this w/ the code clearing
  // |parser_blocking_script_| below.
  pending_script->StopWatchingForLoad();

  if (!IsExecutingScript()) {
    // TODO(kouhei, hiroshige): Investigate why we need checkpoint here.
    document_->GetAgent().event_loop()->PerformMicrotaskCheckpoint();
    // The parser cannot be unblocked as a microtask requested another
    // resource
    if (!document_->IsScriptExecutionReady())
      return;
  }

  // <spec step="B.2">Set the pending parsing-blocking script to null.</spec>
  parser_blocking_script_ = nullptr;

  {
    // <spec step="B.10">Increment the parser's script nesting level by one (it
    // should be zero before this step, so this sets it to one).</spec>
    HTMLParserReentryPermit::ScriptNestingLevelIncrementer
        nesting_level_incrementer =
            reentry_permit_->IncrementScriptNestingLevel();

    // <spec step="B.11">Execute the script element the script.</spec>
    DCHECK(IsExecutingScript());
    DoExecuteScript(pending_script, *document_);

    // <spec step="B.12">Decrement the parser's script nesting level by one. If
    // the parser's script nesting level is zero (which it always should be at
    // this point), then set the parser pause flag to false.</spec>
    //
    // This is implemented by ~ScriptNestingLevelIncrementer().
  }

  DCHECK(!IsExecutingScript());
}

// Should be correspond to
//
// <specdef
// href="https://html.spec.whatwg.org/C/#execute-the-script-element">
//
// but currently does more than specced, because historically this and
// ExecutePendingParserBlockingScriptAndDispatchEvent() was the same method.
void HTMLParserScriptRunner::ExecutePendingDeferredScriptAndDispatchEvent(
    PendingScript* pending_script) {
  // Stop watching loads before executeScript to prevent recursion if the script
  // reloads itself.
  // TODO(kouhei): Consider merging this w/ pendingScript->dispose() after the
  // if block.
  pending_script->StopWatchingForLoad();

  if (!IsExecutingScript()) {
    // TODO(kouhei, hiroshige): Investigate why we need checkpoint here.
    document_->GetAgent().event_loop()->PerformMicrotaskCheckpoint();
  }

  DoExecuteScript(pending_script, *document_);
}

void HTMLParserScriptRunner::PendingScriptFinished(
    PendingScript* pending_script) {
  // Handle cancellations of parser-blocking script loads without
  // notifying the host (i.e., parser) if these were initiated by nested
  // document.write()s. The cancellation may have been triggered by
  // script execution to signal an abrupt stop (e.g., window.close().)
  //
  // The parser is unprepared to be told, and doesn't need to be.
  if (IsExecutingScript() && pending_script->WasCanceled()) {
    pending_script->Dispose();

    DCHECK_EQ(pending_script, ParserBlockingScript());
    parser_blocking_script_ = nullptr;

    return;
  }

  // Posting the script execution part to a new task so that we can allow
  // yielding for cooperative scheduling. Cooperative scheduling requires that
  // the Blink C++ stack be thin when it executes JavaScript.
  document_->GetTaskRunner(TaskType::kInternalContinueScriptLoading)
      ->PostTask(FROM_HERE,
                 WTF::BindOnce(&HTMLParserScriptRunnerHost::NotifyScriptLoaded,
                               WrapPersistent(host_.Get())));
}

// <specdef href="https://html.spec.whatwg.org/C/#scriptEndTag">
//
// Script handling lives outside the tree builder to keep each class simple.
void HTMLParserScriptRunner::ProcessScriptElement(
    Element* script_element,
    const TextPosition& script_start_position) {
  DCHECK(script_element);

  // FIXME: If scripting is disabled, always just return.

  bool had_preload_scanner = host_->HasPreloadScanner();

  // <spec>An end tag whose tag name is "script" ...</spec>
  //
  // Try to execute the script given to us.
  ProcessScriptElementInternal(script_element, script_start_position);

  // <spec>... At this stage, if the pending parsing-blocking script is not
  // null, then:</spec>
  if (HasParserBlockingScript()) {
    if (IsExecutingScript()) {
      // <spec step="A">If the script nesting level is not zero:
      //
      // Set the parser pause flag to true, and abort the processing of any
      // nested invocations of the tokenizer, yielding control back to the
      // caller. (Tokenization will resume when the caller returns to the
      // "outer" tree construction stage.)</spec>

      // Unwind to the outermost HTMLParserScriptRunner::processScriptElement
      // before continuing parsing.
      return;
    }

    // - "Otherwise":

    TraceParserBlockingScript(ParserBlockingScript(), *document_);
    parser_blocking_script_->MarkParserBlockingLoadStartTime();

    // If preload scanner got created, it is missing the source after the
    // current insertion point. Append it and scan.
    if (!had_preload_scanner && host_->HasPreloadScanner())
      host_->AppendCurrentInputStreamToPreloadScannerAndScan();

    ExecuteParsingBlockingScripts();
  }
}

bool HTMLParserScriptRunner::HasParserBlockingScript() const {
  return ParserBlockingScript();
}

// <specdef href="https://html.spec.whatwg.org/C/#scriptEndTag">
//
// <spec>An end tag whose tag name is "script" ...</spec>
void HTMLParserScriptRunner::ExecuteParsingBlockingScripts() {
  // <spec step="B">Otherwise:
  //
  // While the pending parsing-blocking script is not null:</spec>
  //
  // <spec step="B.5">If the parser's Document has a style sheet that is
  // blocking scripts or the script's ready to be parser-executed is false: spin
  // the event loop until the parser's Document has no style sheet that is
  // blocking scripts and the script's ready to be parser-executed becomes
  // true.</spec>
  //
  // These conditions correspond to IsParserBlockingScriptReady().
  // If it is false at the time of #prepare-the-script-element,
  // ExecuteParsingBlockingScripts() will be called later
  // when IsParserBlockingScriptReady() might become true:
  // - Called from HTMLParserScriptRunner::ExecuteScriptsWaitingForResources()
  //   when the parser's Document has no style sheet that is blocking scripts,
  // - Called from HTMLParserScriptRunner::ExecuteScriptsWaitingForLoad()
  //   when the script's "ready to be parser-executed" flag is set, or
  // - Other cases where any of the conditions isn't met or even when there are
  //   no longer parser blocking scripts at all.
  //   (For example, see the comment in ExecuteScriptsWaitingForLoad())
  //
  // Because we check the conditions below and do nothing if the conditions
  // aren't met, it's safe to have extra ExecuteParsingBlockingScripts() calls.
  while (HasParserBlockingScript() && IsParserBlockingScriptReady()) {
    DCHECK(document_);
    DCHECK(!IsExecutingScript());
    DCHECK(document_->IsScriptExecutionReady());

    // <spec step="B.9">Let the insertion point be just before the next input
    // character.</spec>
    InsertionPointRecord insertion_point_record(host_->InputStream());

    ExecutePendingParserBlockingScriptAndDispatchEvent();

    // <spec step="B.13">Let the insertion point be undefined again.</spec>
    //
    // Implemented as ~InsertionPointRecord().
  }
}

void HTMLParserScriptRunner::ExecuteScriptsWaitingForLoad() {
  // Note(https://crbug.com/1093051): ExecuteScriptsWaitingForLoad() is
  // triggered asynchronously from PendingScriptFinished(pending_script), but
  // the |pending_script| might be no longer the ParserBlockginScript() here,
  // because it might have been evaluated or disposed after
  // PendingScriptFinished() before ExecuteScriptsWaitingForLoad(). Anyway we
  // call ExecuteParsingBlockingScripts(), because necessary conditions for
  // evaluation are checked safely there.

  TRACE_EVENT0("blink", "HTMLParserScriptRunner::executeScriptsWaitingForLoad");
  DCHECK(!IsExecutingScript());
  ExecuteParsingBlockingScripts();
}

void HTMLParserScriptRunner::ExecuteScriptsWaitingForResources() {
  TRACE_EVENT0("blink",
               "HTMLParserScriptRunner::executeScriptsWaitingForResources");
  DCHECK(document_);
  DCHECK(!IsExecutingScript());
  DCHECK(document_->IsScriptExecutionReady());
  ExecuteParsingBlockingScripts();
}

// <specdef href="https://html.spec.whatwg.org/C/#stop-parsing">
PendingScript* HTMLParserScriptRunner::TryTakeReadyScriptWaitingForParsing(
    HeapDeque<Member<PendingScript>>* waiting_scripts) {
  DCHECK(!waiting_scripts->empty());

  // <spec step="5.1">Spin the event loop until the first script in the list of
  // scripts that will execute when the document has finished parsing has its
  // ready to be parser-executed set to true and the parser's Document has no
  // style sheet that is blocking scripts.</spec>
  if (!document_->IsScriptExecutionReady())
    return nullptr;
  PendingScript* script = waiting_scripts->front();
  if (!script->IsReady()) {
    if (!script->IsWatchingForLoad()) {
      // First time when all the conditions except for
      // `PendingScript::IsReady()` are satisfied. Note that
      // `TryTakeReadyScriptWaitingForParsing()` can triggered by script and
      // stylesheet load completions multiple times, so `IsWatchingForLoad()` is
      // checked to avoid double execution of this code block. When
      // `IsWatchingForLoad()` is true, its existing client is always `this`.
      script->WatchForLoad(this);
      TraceParserBlockingScript(script, *document_);
      script->MarkParserBlockingLoadStartTime();
    }
    return nullptr;
  }
  return waiting_scripts->TakeFirst().Get();
}

// <specdef href="https://html.spec.whatwg.org/C/#stop-parsing">
//
// This will run the developer deferred scripts.
bool HTMLParserScriptRunner::ExecuteScriptsWaitingForParsing() {
  TRACE_EVENT0("blink",
               "HTMLParserScriptRunner::executeScriptsWaitingForParsing");

  // <spec step="5">While the list of scripts that will execute when the
  // document has finished parsing is not empty:</spec>
  while (!scripts_to_execute_after_parsing_.empty()) {
    DCHECK(!IsExecutingScript());
    DCHECK(!HasParserBlockingScript());
    DCHECK(scripts_to_execute_after_parsing_.front()->IsExternalOrModule());

    // <spec step="5.3">Remove the first script element from the list of scripts
    // that will execute when the document has finished parsing (i.e. shift out
    // the first entry in the list).</spec>
    PendingScript* first =
        TryTakeReadyScriptWaitingForParsing(&scripts_to_execute_after_parsing_);
    if (!first)
      return false;

    // <spec step="5.2">Execute the script element given by the first script in
    // the list of scripts that will execute when the document has finished
    // parsing.</spec>
    ExecutePendingDeferredScriptAndDispatchEvent(first);

    // FIXME: What is this m_document check for?
    if (!document_)
      return false;
  }

  return true;
}

// The initial steps for 'An end tag whose tag name is "script"'
// <specdef href="https://html.spec.whatwg.org/C/#scriptEndTag">
// <specdef label="prepare-the-script-element"
// href="https://html.spec.whatwg.org/C/#prepare-the-script-element">
void HTMLParserScriptRunner::ProcessScriptElementInternal(
    Element* script,
    const TextPosition& script_start_position) {
  DCHECK(document_);
  DCHECK(!HasParserBlockingScript());
  {
    ScriptLoader* script_loader = ScriptLoaderFromElement(script);

    // FIXME: Align trace event name and function name.
    TRACE_EVENT1("blink", "HTMLParserScriptRunner::execute", "data",
                 GetTraceArgsForScriptElement(*document_, script_start_position,
                                              NullURL()));
    DCHECK(script_loader->IsParserInserted());

    // <spec>... If the active speculative HTML parser is null and the
    // JavaScript execution context stack is empty, then perform a microtask
    // checkpoint. ...</spec>
    if (!IsExecutingScript())
      document_->GetAgent().event_loop()->PerformMicrotaskCheckpoint();

    // <spec>... Let the old insertion point have the same value as the current
    // insertion point. Let the insertion point be just before the next input
    // character. ...</spec>
    InsertionPointRecord insertion_point_record(host_->InputStream());

    // <spec>... Increment the parser's script nesting level by one. ...</spec>
    HTMLParserReentryPermit::ScriptNestingLevelIncrementer
        nesting_level_incrementer =
            reentry_permit_->IncrementScriptNestingLevel();

    // <spec>... prepare the script element script. This might cause some script
    // to execute, which might cause new characters to be inserted into the
    // tokenizer, and might cause the tokenizer to output more tokens, resulting
    // in a reentrant invocation of the parser. ...</spec>
    PendingScript* pending_script = script_loader->PrepareScript(
        reentry_permit_->ScriptNestingLevel() == 1u
            ? ScriptLoader::ParserBlockingInlineOption::kAllow
            : ScriptLoader::ParserBlockingInlineOption::kDeny,
        script_start_position);

    if (!pending_script)
      return;

    switch (pending_script->GetSchedulingType()) {
      case ScriptSchedulingType::kDefer:
        // Developer deferred.
        DCHECK(pending_script->IsExternalOrModule());
        // <spec
        // href="https://html.spec.whatwg.org/C/#prepare-the-script-element"
        // step="31.4.1">Append el to its parser document's list of scripts that
        // will execute when the document has finished parsing.</spec>
        scripts_to_execute_after_parsing_.push_back(pending_script);
        break;

      case ScriptSchedulingType::kParserBlocking:
        // <spec label="prepare-the-script-element" step="31.5.1">Set el's
        // parser document's pending parsing-blocking script to el.</spec>
      case ScriptSchedulingType::kParserBlockingInline:
        // <spec label="prepare-the-script-element" step="32.2.1">Set el's
        // parser document's pending parsing-blocking script to el.</spec>

        CHECK(!parser_blocking_script_);
        parser_blocking_script_ = pending_script;

        // We only care about a load callback if resource is not yet ready.
        // The caller of `ProcessScriptElementInternal()` will attempt to run
        // `parser_blocking_script_` if ready before returning control to the
        // parser.
        if (!parser_blocking_script_->IsReady())
          parser_blocking_script_->WatchForLoad(this);
        break;

      case ScriptSchedulingType::kAsync:
      case ScriptSchedulingType::kInOrder:
      case ScriptSchedulingType::kForceInOrder:
      case ScriptSchedulingType::kImmediate:
      case ScriptSchedulingType::kNotSet:
      case ScriptSchedulingType::kDeprecatedForceDefer:
        NOTREACHED();
    }

    // <spec>... Decrement the parser's script nesting level by one. If the
    // parser's script nesting level is zero, then set the parser pause flag to
    // false. ...</spec>
    //
    // Implemented by ~ScriptNestingLevelIncrementer().

    // <spec>... Let the insertion point have the value of the old insertion
    // point. ...</spec>
    //
    // Implemented by ~InsertionPointRecord().
  }
}

void HTMLParserScriptRunner::Trace(Visitor* visitor) const {
  visitor->Trace(reentry_permit_);
  visitor->Trace(document_);
  visitor->Trace(host_);
  visitor->Trace(parser_blocking_script_);
  visitor->Trace(scripts_to_execute_after_parsing_);
  PendingScriptClient::Trace(visitor);
}

}  // namespace blink

"""

```