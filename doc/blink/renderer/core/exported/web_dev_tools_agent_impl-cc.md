Response:
Let's break down the thought process to analyze the `web_dev_tools_agent_impl.cc` file.

1. **Understand the Core Purpose:** The filename itself is a big clue: `web_dev_tools_agent_impl.cc`. This immediately suggests it's the implementation of a DevTools agent within the Blink rendering engine. The "exported" part implies it's providing some kind of interface or service to other parts of Chromium.

2. **Scan the Includes:**  The included headers are extremely informative. I'd categorize them mentally:
    * **Fundamental C++:** `<v8-inspector.h>`, `<memory>`, `<utility>`, `base/auto_reset.h`, etc. These are standard library or Chromium base utilities.
    * **Blink Platform Abstractions:** `third_party/blink/public/platform/...` (e.g., `WebScopedPagePauser`, `WebString`, `Platform`). These represent platform-independent interfaces for Blink.
    * **Blink Web API:** `third_party/blink/public/web/...` (e.g., `WebSettings`, `WebViewClient`). These are the "public" web-facing APIs that developers interact with (though this file is internal Blink code).
    * **Blink Core Rendering:** `third_party/blink/renderer/bindings/core/v8/...`, `third_party/blink/renderer/core/...`. This is the meat of the Blink rendering engine, dealing with V8 integration, frames, layout, events, and *crucially*, the `inspector` directory. The sheer number of `inspector/...` includes screams "this file is about DevTools."

3. **Identify Key Classes and Namespaces:** The code uses the `blink` namespace. Looking at the classes defined and used directly gives a sense of the functionality:
    * `WebDevToolsAgentImpl`: The central class of this file.
    * `DevToolsAgent`: A core DevTools class.
    * `DevToolsSession`: Represents a connection to DevTools.
    * Many `Inspector...Agent` classes (e.g., `InspectorDOMAgent`, `InspectorCSSAgent`, `InspectorNetworkAgent`). This confirms the file is responsible for coordinating various DevTools features.
    * `InspectedFrames`: Manages the frames being inspected.
    * `MainThreadDebugger`:  Deals with pausing and stepping in JavaScript.
    * `ClientMessageLoopAdapter`: Handles pausing the rendering process.

4. **Analyze Functionality by Grouping:**  Instead of reading line by line, look for patterns and groupings of related actions:
    * **Session Management (`AttachSession`, `DetachSession`):**  How are DevTools connections established and closed?
    * **Agent Creation in `AttachSession`:** What specific DevTools agents are created and what are their roles (DOM, CSS, Network, etc.)?
    * **JavaScript Debugging (related to `MainThreadDebugger`, `ClientMessageLoopAdapter`):** How is JavaScript execution paused and resumed?  Look for functions like `WaitForDebugger`, `ContinueProgram`, and mentions of pausing.
    * **Element Inspection (`InspectElement`):** How does the "Inspect Element" feature work?  This involves hit testing.
    * **Overlay Interactions (functions involving `overlay_agents_`):**  How does DevTools draw highlights and information on the page?
    * **Lifecycle Management (`WillBeDestroyed`):** What cleanup happens when this object is no longer needed?
    * **Communication (related to `FlushProtocolNotifications`):** How does this code send messages to the DevTools frontend?
    * **Input Handling (`HandleInputEvent`):** How does DevTools intercept and handle user input?

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** Based on the included agent classes:
    * **JavaScript:** The presence of `MainThreadDebugger`, interactions with V8 (`v8::Isolate`, `v8::inspector::V8Inspector`), and agent names like `InspectorDOMDebuggerAgent` clearly link to JavaScript debugging.
    * **HTML:**  `InspectorDOMAgent`, `InspectorDOMSnapshotAgent` deal with the Document Object Model (DOM), which represents the HTML structure. `InspectElement` directly targets HTML elements.
    * **CSS:** `InspectorCSSAgent` is explicitly for CSS inspection and manipulation.

6. **Infer Logic and Assumptions:**  Consider how the code *must* work. For example:
    * When a DevTools session starts, the corresponding agents need to be created and initialized.
    * Pausing JavaScript requires stopping the main thread's execution.
    * Inspecting an element involves finding the element under the mouse cursor.
    * Changes made in the DevTools often need to be reflected in the rendered page, which involves communication between the agent and the rendering engine.

7. **Identify Potential User Errors/Scenarios:** Think about how a developer interacts with DevTools and what could go wrong:
    * Trying to inspect an element that doesn't exist.
    * Having multiple DevTools windows open.
    * Issues with breakpoints and stepping in asynchronous code.

8. **Trace User Actions (Debugging Clues):**  Imagine the steps a user takes to get to a specific point in this code:
    * Opening DevTools.
    * Selecting the "Elements" tab.
    * Using the "Inspect Element" tool.
    * Setting a breakpoint in JavaScript.
    * Triggering a network request.

9. **Structure the Explanation:**  Organize the findings into logical categories: Core Functionality, Relationship to Web Technologies, Logic and Assumptions, User Errors, and Debugging Clues. Use clear and concise language. Provide specific examples from the code where possible.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This file just creates DevTools agents."
* **Correction:** "It does create agents, but it also manages the lifecycle of DevTools sessions, handles pausing/resuming execution, and facilitates communication between the rendering engine and the DevTools frontend."
* **Initial thought:**  Focus heavily on individual functions.
* **Correction:** Group related functions and focus on the overall workflows and responsibilities.
* **Realization:** The `ClientMessageLoopAdapter` is crucial for understanding how the rendering process is paused, so dedicate more attention to it.

By following these steps, iteratively refining understanding, and focusing on the high-level purpose and key interactions, a comprehensive analysis of the `web_dev_tools_agent_impl.cc` file can be achieved.
这个文件 `blink/renderer/core/exported/web_dev_tools_agent_impl.cc` 是 Chromium Blink 引擎中负责实现 Web 开发者工具（DevTools）代理的核心组件。它的主要功能是作为 Blink 渲染引擎和 DevTools 前端之间的桥梁，允许开发者通过 DevTools 界面来检查和调试网页。

以下是它的详细功能列表：

**核心功能:**

1. **DevTools 会话管理:**
   -  负责创建、连接和断开 DevTools 会话 (`AttachSession`, `DetachSession`)。
   -  每个 DevTools 窗口或连接都会对应一个 `DevToolsSession` 对象。

2. **DevTools 协议实现:**
   -  实现了 DevTools 协议中定义的各种接口和方法，允许 DevTools 前端向 Blink 发送命令并接收事件。
   -  这些命令和事件涵盖了 DOM 检查、CSS 操作、JavaScript 调试、网络监控、性能分析等多个方面。

3. **代理对象管理:**
   -  创建并管理各种 DevTools 相关的代理对象，这些代理对象负责特定领域的功能，例如：
     - `InspectorDOMAgent`:  负责 DOM 树的检查和操作。
     - `InspectorCSSAgent`: 负责 CSS 样式的检查和修改。
     - `InspectorNetworkAgent`: 负责网络请求的监控和分析。
     - `InspectorPageAgent`: 负责页面级别的操作，如导航、截图等。
     - `InspectorDebuggerAgent` (功能分散在 `InspectorDOMDebuggerAgent` 等): 负责 JavaScript 代码的调试。
     - 其他各种 `Inspector...Agent` 用于处理特定领域的 DevTools 功能。

4. **JavaScript 调试支持:**
   -  与 V8 JavaScript 引擎的 Inspector 集成，允许在 DevTools 中设置断点、单步执行、查看变量等。
   -  使用 `MainThreadDebugger` 类来管理主线程的调试状态。
   -  `ClientMessageLoopAdapter` 用于在调试暂停时控制消息循环，防止页面失去响应。

5. **元素检查功能:**
   -  实现 "Inspect Element" 功能 (`InspectElement`)，允许用户点击页面上的元素并在 DevTools 中查看其对应的 DOM 节点和 CSS 样式。

6. **Overlay 绘制:**
   -  管理 DevTools overlay 的绘制 (`PaintOverlays`, `UpdateOverlaysPrePaint`)，用于在页面上高亮显示元素、显示布局信息等。

7. **网络监控:**
   -  与网络模块交互，收集网络请求的信息，并通过 `InspectorNetworkAgent` 将这些信息传递给 DevTools 前端。

8. **性能分析:**
   -  收集页面性能相关的数据，并通过 `InspectorPerformanceAgent` 等提供给 DevTools 前端进行分析。

9. **模拟器功能:**
   -  通过 `InspectorEmulationAgent` 实现设备模拟、地理位置模拟等功能。

10. **与其他 Blink 组件的交互:**
    -  与 `LocalFrame`、`Page`、`Document` 等 Blink 核心类进行交互，获取页面结构、样式、脚本执行状态等信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    - **功能关系:**  该文件直接负责 JavaScript 的调试功能。当开发者在 DevTools 中设置断点时，`WebDevToolsAgentImpl` 会通过 `MainThreadDebugger` 与 V8 Inspector 交互，暂停 JavaScript 的执行。
    - **举例说明:**
        - **假设输入:**  开发者在 `script.js` 文件的第 10 行设置了一个断点。
        - **逻辑推理:** 当 JavaScript 执行到第 10 行时，V8 Inspector 会通知 `WebDevToolsAgentImpl`，然后 `WebDevToolsAgentImpl` 会暂停主线程的执行，并将程序执行状态（调用栈、变量值等）发送到 DevTools 前端。
        - **输出:** DevTools 前端会显示代码执行停在第 10 行，并允许开发者查看当前作用域的变量。
        - **用户操作:**  开发者可以通过 DevTools 的步进按钮（Step Over, Step Into, Step Out）来控制 JavaScript 代码的执行流程。

* **HTML:**
    - **功能关系:**  `InspectorDOMAgent` 负责将页面的 DOM 结构以树状形式呈现给 DevTools 前端，并允许开发者在 DevTools 中修改 HTML 结构。
    - **举例说明:**
        - **用户操作:** 开发者在 DevTools 的 "Elements" 面板中选中一个 `<div>` 元素。
        - **逻辑推理:** DevTools 前端发送请求到 `WebDevToolsAgentImpl`，`InspectorDOMAgent` 接收到请求，并根据内部的 DOM 结构找到对应的节点。
        - **输出:** DevTools 前端会高亮显示页面上对应的 `<div>` 元素，并显示其属性和子元素。
        - **用户操作:** 开发者在 DevTools 中修改了该 `<div>` 元素的 `class` 属性。
        - **逻辑推理:** DevTools 前端将修改请求发送到 `WebDevToolsAgentImpl`，`InspectorDOMAgent` 更新 Blink 内部的 DOM 结构。
        - **输出:**  页面上该 `<div>` 元素的样式会根据新的 `class` 属性进行更新。

* **CSS:**
    - **功能关系:** `InspectorCSSAgent` 负责将元素的样式信息（包括应用的 CSS 规则、计算后的样式等）提供给 DevTools 前端，并允许开发者在 DevTools 中修改 CSS 样式。
    - **举例说明:**
        - **用户操作:** 开发者在 DevTools 的 "Elements" 面板中选中一个元素，并在 "Styles" 面板中查看其样式。
        - **逻辑推理:** DevTools 前端请求该元素的样式信息，`InspectorCSSAgent` 查询 Blink 内部的样式计算结果。
        - **输出:** DevTools 前端会显示应用于该元素的所有 CSS 规则，包括来自 CSS 文件、`<style>` 标签和内联样式的规则。
        - **用户操作:** 开发者在 DevTools 中修改了该元素的 `color` 属性。
        - **逻辑推理:** DevTools 前端将修改请求发送到 `WebDevToolsAgentImpl`，`InspectorCSSAgent` 会更新该元素的样式，并触发页面的重绘。
        - **输出:** 页面上该元素的文本颜色会立即发生改变。

**逻辑推理的假设输入与输出:**

* **假设输入:** DevTools 前端发送一个命令，要求获取当前页面的所有 CSS 样式表。
* **逻辑推理:** `WebDevToolsAgentImpl` 将该请求转发给 `InspectorCSSAgent`。`InspectorCSSAgent` 遍历当前文档的所有样式表对象，并提取每个样式表的 URL、内容等信息。
* **输出:** `WebDevToolsAgentImpl` 将包含所有样式表信息的 JSON 数据返回给 DevTools 前端。

**涉及用户或编程常见的使用错误及举例说明:**

* **错误:** 在 JavaScript 调试时，修改了代码但没有重新加载页面，导致断点设置在旧版本的代码上。
    * **说明:**  DevTools 的 JavaScript 调试是基于当前加载到浏览器的代码。如果开发者在编辑器中修改了代码，但没有刷新页面，DevTools 仍然会使用旧的代码进行调试，这会导致断点位置不准确或无法命中。
* **错误:**  在修改 CSS 时，不小心修改了全局样式，影响了页面上其他元素的样式。
    * **说明:** DevTools 允许直接修改 CSS 规则，但开发者需要注意修改的范围。如果修改了影响范围过大的选择器，可能会意外地改变其他元素的样式。
* **错误:**  尝试在未加载任何页面的空浏览器窗口中打开 DevTools 并尝试检查元素。
    * **说明:** DevTools 需要依附于一个具体的页面才能进行元素检查等操作。在没有加载任何页面的情况下，相关的 DOM 结构不存在，因此无法执行检查操作。

**用户操作如何一步步的到达这里，作为调试线索:**

假设开发者想要调试一个 JavaScript 问题，并最终可能需要查看 `web_dev_tools_agent_impl.cc` 中的代码，可能的操作步骤如下：

1. **打开 DevTools:** 用户在浏览器中打开 DevTools (通常通过右键点击页面选择 "检查" 或使用 F12 快捷键)。
2. **定位到 "Sources" 面板:** 用户切换到 DevTools 的 "Sources" 面板，这是 JavaScript 调试的主要界面。
3. **打开相关的 JavaScript 文件:** 用户在 "Sources" 面板中找到并打开需要调试的 JavaScript 文件。
4. **设置断点:** 用户在代码的某一行点击行号，设置一个断点。
5. **触发断点:** 用户在页面上执行某些操作，触发了之前设置断点的 JavaScript 代码的执行。
6. **观察程序暂停:** 当代码执行到断点时，程序会暂停执行，DevTools 会显示当前的执行状态。
7. **单步调试:** 用户可以使用 DevTools 的单步执行按钮 (Step Over, Step Into, Step Out) 来控制代码的执行流程，观察变量的变化。
8. **发现问题可能与 DevTools 集成有关:**  如果在单步调试过程中，发现某些行为与 DevTools 的交互有关，例如断点命中时机的处理、变量值的获取等，开发者可能会怀疑问题出在 DevTools 与 Blink 的集成部分。
9. **搜索相关代码:** 开发者可能会搜索与 DevTools 相关的 Blink 源代码，例如包含 "DevToolsAgent" 关键字的文件，从而找到 `web_dev_tools_agent_impl.cc`。
10. **查看代码逻辑:** 开发者会查看 `web_dev_tools_agent_impl.cc` 中与 JavaScript 调试相关的代码，例如 `MainThreadDebugger` 的使用、断点通知的处理等，以理解 Blink 如何与 DevTools 进行 JavaScript 调试的交互。

总而言之，`web_dev_tools_agent_impl.cc` 是 Blink 引擎中至关重要的组件，它连接了渲染引擎和开发者工具，使得开发者能够方便地检查、调试和优化网页。它涉及到 JavaScript 执行、HTML 结构、CSS 样式以及网络通信等多个 Web 技术的核心方面。

### 提示词
```
这是目录为blink/renderer/core/exported/web_dev_tools_agent_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010-2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/exported/web_dev_tools_agent_impl.h"

#include <v8-inspector.h>
#include <memory>
#include <utility>

#include "base/auto_reset.h"
#include "base/unguessable_token.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_scoped_page_pauser.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/core_probe_sink.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/exported/web_settings_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"
#include "third_party/blink/renderer/core/inspector/devtools_agent.h"
#include "third_party/blink/renderer/core/inspector/devtools_session.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_animation_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_css_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_debugger_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_snapshot_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_emulation_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_event_breakpoints_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_io_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_layer_tree_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_log_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_media_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_memory_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_network_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_overlay_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_page_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_performance_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_performance_timeline_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_preload_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_container.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_content_loader.h"
#include "third_party/blink/renderer/core/inspector/inspector_task_runner.h"
#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

bool IsMainFrame(WebLocalFrameImpl* frame) {
  // TODO(dgozman): sometimes view->mainFrameImpl() does return null, even
  // though |frame| is meant to be main frame.  See http://crbug.com/526162.
  return frame->ViewImpl() && !frame->Parent();
}

}  // namespace

class ClientMessageLoopAdapter : public MainThreadDebugger::ClientMessageLoop {
 public:
  ~ClientMessageLoopAdapter() override {
    DCHECK(running_for_debug_break_kind_ != kInstrumentationPause);
    instance_ = nullptr;
  }

  static void EnsureMainThreadDebuggerCreated(v8::Isolate* isolate) {
    if (instance_)
      return;
    std::unique_ptr<ClientMessageLoopAdapter> instance(
        new ClientMessageLoopAdapter(
            Platform::Current()->CreateNestedMessageLoopRunner()));
    instance_ = instance.get();
    MainThreadDebugger::Instance(isolate)->SetClientMessageLoop(
        std::move(instance));
  }

  static void ActivatePausedDebuggerWindow(WebLocalFrameImpl* frame) {
    if (!instance_ || !instance_->paused_frame_ ||
        instance_->paused_frame_ == frame) {
      return;
    }
    if (!base::FeatureList::IsEnabled(
            features::kShowHudDisplayForPausedPages)) {
      return;
    }
    instance_->paused_frame_->DevToolsAgentImpl(/*create_if_necessary=*/true)
        ->GetDevToolsAgent()
        ->BringDevToolsWindowToFocus();
  }

  static void ContinueProgram() {
    // Release render thread if necessary.
    if (instance_)
      instance_->QuitNow();
  }

  static void PauseForPageWait(WebLocalFrameImpl* frame) {
    if (instance_)
      instance_->RunForPageWait(frame);
  }

 private:
  // A RAII class that disables input events for frames that belong to the
  // same browsing context group. Note that this does not support nesting, as
  // DevTools doesn't require nested pauses.
  class ScopedInputEventsDisabler {
   public:
    explicit ScopedInputEventsDisabler(WebLocalFrameImpl& frame)
        : browsing_context_group_token_(WebFrame::ToCoreFrame(frame)
                                            ->GetPage()
                                            ->BrowsingContextGroupToken()) {
      WebFrameWidgetImpl::SetIgnoreInputEvents(browsing_context_group_token_,
                                               true);
    }

    ~ScopedInputEventsDisabler() {
      WebFrameWidgetImpl::SetIgnoreInputEvents(browsing_context_group_token_,
                                               false);
    }

   private:
    const base::UnguessableToken browsing_context_group_token_;
  };

  explicit ClientMessageLoopAdapter(
      std::unique_ptr<Platform::NestedMessageLoopRunner> message_loop)
      : message_loop_(std::move(message_loop)) {
    DCHECK(message_loop_.get());
  }

  void Run(LocalFrame* frame, MessageLoopKind message_loop_kind) override {
    if (running_for_debug_break_kind_) {
      return;
    }

    running_for_debug_break_kind_ = message_loop_kind;
    if (!running_for_page_wait_) {
      switch (message_loop_kind) {
        case kNormalPause:
          RunLoop(WebLocalFrameImpl::FromFrame(frame));
          break;
        case kInstrumentationPause:
          RunInstrumentationPauseLoop(WebLocalFrameImpl::FromFrame(frame));
          break;
      }
    }
  }

  void RunForPageWait(WebLocalFrameImpl* frame) {
    if (running_for_page_wait_)
      return;

    running_for_page_wait_ = true;
    if (!running_for_debug_break_kind_) {
      RunLoop(frame);
    } else {
      // We should not start waiting for the debugger during instrumentation
      // pauses, so the current pause must be a normal pause.
      DCHECK_EQ(*running_for_debug_break_kind_, kNormalPause);
    }
  }

  void QuitNow() override {
    if (!running_for_debug_break_kind_) {
      return;
    }

    if (!running_for_page_wait_) {
      switch (*running_for_debug_break_kind_) {
        case kNormalPause:
          DoQuitNormalPause();
          break;
        case kInstrumentationPause:
          DoQuitInstrumentationPause();
          break;
      }
    }
    running_for_debug_break_kind_.reset();
  }

  void RunInstrumentationPauseLoop(WebLocalFrameImpl* frame) {
    // 0. Flush pending frontend messages.
    WebDevToolsAgentImpl* agent =
        frame->DevToolsAgentImpl(/*create_if_necessary=*/true);
    agent->FlushProtocolNotifications();

    // 1. Run the instrumentation message loop. Also remember the task runner
    // so that we can later quit the loop.
    DCHECK(!inspector_task_runner_for_instrumentation_pause_);
    inspector_task_runner_for_instrumentation_pause_ =
        frame->GetFrame()->GetInspectorTaskRunner();
    inspector_task_runner_for_instrumentation_pause_
        ->ProcessInterruptingTasks();
  }

  void DoQuitInstrumentationPause() {
    DCHECK(inspector_task_runner_for_instrumentation_pause_);
    inspector_task_runner_for_instrumentation_pause_
        ->RequestQuitProcessingInterruptingTasks();
    inspector_task_runner_for_instrumentation_pause_.reset();
  }

  void RunLoop(WebLocalFrameImpl* frame) {
    // 0. Flush pending frontend messages.
    WebDevToolsAgentImpl* agent =
        frame->DevToolsAgentImpl(/*create_if_necessary=*/true);
    agent->FlushProtocolNotifications();
    agent->MainThreadDebuggerPaused();
    CHECK(!paused_frame_);
    paused_frame_ = WrapWeakPersistent(frame);

    // 1. Disable input events.
    CHECK(!input_events_disabler_);
    input_events_disabler_ =
        std::make_unique<ScopedInputEventsDisabler>(*frame);
    for (auto* const view : WebViewImpl::AllInstances())
      view->GetChromeClient().NotifyPopupOpeningObservers();

    // 2. Disable active objects
    page_pauser_ = std::make_unique<WebScopedPagePauser>(*frame);

    // 3. Process messages until quitNow is called.
    message_loop_->Run();
  }

  void RunIfWaitingForDebugger(LocalFrame* frame) override {
    if (!running_for_page_wait_)
      return;
    if (!running_for_debug_break_kind_) {
      DoQuitNormalPause();
    }
    running_for_page_wait_ = false;
  }

  void DoQuitNormalPause() {
    // Undo steps (3), (2) and (1) from above.
    // NOTE: This code used to be above right after the |mesasge_loop_->Run()|
    // code, but it is moved here to support browser-side navigation.
    DCHECK(running_for_page_wait_ ||
           *running_for_debug_break_kind_ == kNormalPause);
    message_loop_->QuitNow();
    page_pauser_.reset();
    input_events_disabler_.reset();

    CHECK(paused_frame_);
    if (paused_frame_->GetFrame()) {
      paused_frame_->DevToolsAgentImpl(/*create_if_necessary=*/true)
          ->MainThreadDebuggerResumed();
    }
    paused_frame_ = nullptr;
  }

  std::optional<MessageLoopKind> running_for_debug_break_kind_;
  bool running_for_page_wait_ = false;
  std::unique_ptr<Platform::NestedMessageLoopRunner> message_loop_;
  std::unique_ptr<ScopedInputEventsDisabler> input_events_disabler_;
  std::unique_ptr<WebScopedPagePauser> page_pauser_;
  WeakPersistent<WebLocalFrameImpl> paused_frame_;
  scoped_refptr<InspectorTaskRunner>
      inspector_task_runner_for_instrumentation_pause_;
  static ClientMessageLoopAdapter* instance_;
};

ClientMessageLoopAdapter* ClientMessageLoopAdapter::instance_ = nullptr;

void WebDevToolsAgentImpl::AttachSession(DevToolsSession* session,
                                         bool restore) {
  if (!network_agents_.size())
    Thread::Current()->AddTaskObserver(this);

  InspectedFrames* inspected_frames = inspected_frames_.Get();
  v8::Isolate* isolate =
      inspected_frames->Root()->GetPage()->GetAgentGroupScheduler().Isolate();
  ClientMessageLoopAdapter::EnsureMainThreadDebuggerCreated(isolate);
  MainThreadDebugger* main_thread_debugger =
      MainThreadDebugger::Instance(isolate);

  int context_group_id =
      main_thread_debugger->ContextGroupId(inspected_frames->Root());
  session->ConnectToV8(main_thread_debugger->GetV8Inspector(),
                       context_group_id);

  InspectorDOMAgent* dom_agent = session->CreateAndAppend<InspectorDOMAgent>(
      isolate, inspected_frames, session->V8Session());

  session->CreateAndAppend<InspectorLayerTreeAgent>(inspected_frames, this);

  InspectorNetworkAgent* network_agent =
      session->CreateAndAppend<InspectorNetworkAgent>(inspected_frames, nullptr,
                                                      session->V8Session());

  auto* css_agent = session->CreateAndAppend<InspectorCSSAgent>(
      dom_agent, inspected_frames, network_agent,
      resource_content_loader_.Get(), resource_container_.Get());

  InspectorDOMDebuggerAgent* dom_debugger_agent =
      session->CreateAndAppend<InspectorDOMDebuggerAgent>(isolate, dom_agent,
                                                          session->V8Session());

  session->CreateAndAppend<InspectorEventBreakpointsAgent>(
      session->V8Session());

  session->CreateAndAppend<InspectorPerformanceAgent>(inspected_frames);

  session->CreateAndAppend<InspectorDOMSnapshotAgent>(inspected_frames,
                                                      dom_debugger_agent);

  session->CreateAndAppend<InspectorAnimationAgent>(inspected_frames, css_agent,
                                                    session->V8Session());

  session->CreateAndAppend<InspectorMemoryAgent>(inspected_frames);

  auto* page_agent = session->CreateAndAppend<InspectorPageAgent>(
      inspected_frames, this, resource_content_loader_.Get(),
      session->V8Session());

  session->CreateAndAppend<InspectorLogAgent>(
      &inspected_frames->Root()->GetPage()->GetConsoleMessageStorage(),
      inspected_frames->Root()->GetPerformanceMonitor(), session->V8Session());

  InspectorOverlayAgent* overlay_agent =
      session->CreateAndAppend<InspectorOverlayAgent>(
          web_local_frame_impl_.Get(), inspected_frames, session->V8Session(),
          dom_agent);

  session->CreateAndAppend<InspectorIOAgent>(isolate, session->V8Session());

  session->CreateAndAppend<InspectorAuditsAgent>(
      network_agent,
      &inspected_frames->Root()->GetPage()->GetInspectorIssueStorage(),
      inspected_frames, web_local_frame_impl_->AutofillClient());

  session->CreateAndAppend<InspectorMediaAgent>(
      inspected_frames, /*worker_global_scope=*/nullptr);

  auto* virtual_time_controller =
      web_local_frame_impl_->View()->Scheduler()->GetVirtualTimeController();
  DCHECK(virtual_time_controller);
  // TODO(dgozman): we should actually pass the view instead of frame, but
  // during remote->local transition we cannot access mainFrameImpl() yet, so
  // we have to store the frame which will become the main frame later.
  session->CreateAndAppend<InspectorEmulationAgent>(web_local_frame_impl_.Get(),
                                                    *virtual_time_controller);

  session->CreateAndAppend<InspectorPerformanceTimelineAgent>(inspected_frames);

  session->CreateAndAppend<InspectorPreloadAgent>(inspected_frames);

  // Call session init callbacks registered from higher layers.
  CoreInitializer::GetInstance().InitInspectorAgentSession(
      session, include_view_agents_, dom_agent, inspected_frames,
      web_local_frame_impl_->ViewImpl()->GetPage());

  if (node_to_inspect_) {
    overlay_agent->Inspect(node_to_inspect_);
    node_to_inspect_ = nullptr;
  }

  network_agents_.insert(session, network_agent);
  page_agents_.insert(session, page_agent);
  overlay_agents_.insert(session, overlay_agent);
}

// static
WebDevToolsAgentImpl* WebDevToolsAgentImpl::CreateForFrame(
    WebLocalFrameImpl* frame) {
  return MakeGarbageCollected<WebDevToolsAgentImpl>(frame, IsMainFrame(frame));
}

WebDevToolsAgentImpl::WebDevToolsAgentImpl(
    WebLocalFrameImpl* web_local_frame_impl,
    bool include_view_agents)
    : web_local_frame_impl_(web_local_frame_impl),
      probe_sink_(web_local_frame_impl_->GetFrame()->GetProbeSink()),
      resource_content_loader_(
          MakeGarbageCollected<InspectorResourceContentLoader>(
              web_local_frame_impl_->GetFrame())),
      inspected_frames_(MakeGarbageCollected<InspectedFrames>(
          web_local_frame_impl_->GetFrame())),
      resource_container_(
          MakeGarbageCollected<InspectorResourceContainer>(inspected_frames_)),
      include_view_agents_(include_view_agents) {
  DCHECK(IsMainThread());
  agent_ = MakeGarbageCollected<DevToolsAgent>(
      this, inspected_frames_.Get(), probe_sink_.Get(),
      web_local_frame_impl_->GetFrame()->GetInspectorTaskRunner(),
      Platform::Current()->GetIOTaskRunner());
}

WebDevToolsAgentImpl::~WebDevToolsAgentImpl() {}

void WebDevToolsAgentImpl::Trace(Visitor* visitor) const {
  visitor->Trace(agent_);
  visitor->Trace(network_agents_);
  visitor->Trace(page_agents_);
  visitor->Trace(overlay_agents_);
  visitor->Trace(web_local_frame_impl_);
  visitor->Trace(probe_sink_);
  visitor->Trace(resource_content_loader_);
  visitor->Trace(inspected_frames_);
  visitor->Trace(resource_container_);
  visitor->Trace(node_to_inspect_);
}

void WebDevToolsAgentImpl::WillBeDestroyed() {
  DCHECK(web_local_frame_impl_->GetFrame());
  DCHECK(inspected_frames_->Root()->View());
  agent_->Dispose();
  resource_content_loader_->Dispose();
}

void WebDevToolsAgentImpl::BindReceiver(
    mojo::PendingAssociatedRemote<mojom::blink::DevToolsAgentHost> host_remote,
    mojo::PendingAssociatedReceiver<mojom::blink::DevToolsAgent> receiver) {
  agent_->BindReceiver(
      std::move(host_remote), std::move(receiver),
      web_local_frame_impl_->GetTaskRunner(TaskType::kInternalInspector));
}

void WebDevToolsAgentImpl::DetachSession(DevToolsSession* session) {
  network_agents_.erase(session);
  page_agents_.erase(session);
  overlay_agents_.erase(session);
  if (!network_agents_.size())
    Thread::Current()->RemoveTaskObserver(this);
}

void WebDevToolsAgentImpl::InspectElement(
    const gfx::Point& point_in_local_root) {
  gfx::PointF point =
      web_local_frame_impl_->FrameWidgetImpl()->DIPsToBlinkSpace(
          gfx::PointF(point_in_local_root));

  HitTestRequest::HitTestRequestType hit_type =
      HitTestRequest::kMove | HitTestRequest::kReadOnly |
      HitTestRequest::kAllowChildFrameContent;
  HitTestRequest request(hit_type);
  WebMouseEvent dummy_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            base::TimeTicks::Now());
  dummy_event.SetPositionInWidget(point);
  gfx::Point transformed_point = gfx::ToFlooredPoint(
      TransformWebMouseEvent(web_local_frame_impl_->GetFrameView(), dummy_event)
          .PositionInRootFrame());
  HitTestLocation location(
      web_local_frame_impl_->GetFrameView()->ConvertFromRootFrame(
          transformed_point));
  HitTestResult result(request, location);
  web_local_frame_impl_->GetFrame()->ContentLayoutObject()->HitTest(location,
                                                                    result);
  Node* node = result.InnerNode();
  if (!node && web_local_frame_impl_->GetFrame()->GetDocument())
    node = web_local_frame_impl_->GetFrame()->GetDocument()->documentElement();

  if (!overlay_agents_.empty()) {
    for (auto& it : overlay_agents_)
      it.value->Inspect(node);
  } else {
    node_to_inspect_ = node;
  }
}

void WebDevToolsAgentImpl::DebuggerTaskStarted() {
  probe::WillStartDebuggerTask(probe_sink_);
}

void WebDevToolsAgentImpl::DebuggerTaskFinished() {
  probe::DidFinishDebuggerTask(probe_sink_);
}

void WebDevToolsAgentImpl::DidCommitLoadForLocalFrame(LocalFrame* frame) {
  resource_container_->DidCommitLoadForLocalFrame(frame);
  resource_content_loader_->DidCommitLoadForLocalFrame(frame);
}

bool WebDevToolsAgentImpl::ScreencastEnabled() {
  for (auto& it : page_agents_) {
    if (it.value->ScreencastEnabled())
      return true;
  }
  return false;
}

void WebDevToolsAgentImpl::PageLayoutInvalidated(bool resized) {
  for (auto& it : overlay_agents_)
    it.value->PageLayoutInvalidated(resized);
}

void WebDevToolsAgentImpl::DidShowNewWindow() {
  if (!wait_for_debugger_when_shown_)
    return;
  wait_for_debugger_when_shown_ = false;
  base::AutoReset<bool> is_paused(&is_paused_for_new_window_shown_, true);
  WaitForDebugger();
}

void WebDevToolsAgentImpl::WaitForDebuggerWhenShown() {
  wait_for_debugger_when_shown_ = true;
}

void WebDevToolsAgentImpl::WaitForDebugger() {
  ClientMessageLoopAdapter::PauseForPageWait(web_local_frame_impl_);
}

bool WebDevToolsAgentImpl::IsPausedForNewWindow() {
  return is_paused_for_new_window_shown_;
}

bool WebDevToolsAgentImpl::IsInspectorLayer(const cc::Layer* layer) {
  for (auto& it : overlay_agents_) {
    if (it.value->IsInspectorLayer(layer))
      return true;
  }
  return false;
}

String WebDevToolsAgentImpl::EvaluateInOverlayForTesting(const String& script) {
  String result;
  for (auto& it : overlay_agents_)
    result = it.value->EvaluateInOverlayForTest(script);
  return result;
}

void WebDevToolsAgentImpl::UpdateOverlaysPrePaint() {
  for (auto& it : overlay_agents_)
    it.value->UpdatePrePaint();
}

void WebDevToolsAgentImpl::PaintOverlays(GraphicsContext& context) {
  for (auto& it : overlay_agents_)
    it.value->PaintOverlay(context);
}

void WebDevToolsAgentImpl::DispatchBufferedTouchEvents() {
  for (auto& it : overlay_agents_)
    it.value->DispatchBufferedTouchEvents();
}

void WebDevToolsAgentImpl::SetPageIsScrolling(bool is_scrolling) {
  for (auto& it : overlay_agents_)
    it.value->SetPageIsScrolling(is_scrolling);
}

WebInputEventResult WebDevToolsAgentImpl::HandleInputEvent(
    const WebInputEvent& event) {
  for (auto& it : overlay_agents_) {
    auto result = it.value->HandleInputEvent(event);
    if (result != WebInputEventResult::kNotHandled)
      return result;
  }
  return WebInputEventResult::kNotHandled;
}

void WebDevToolsAgentImpl::ActivatePausedDebuggerWindow(
    WebLocalFrameImpl* local_root) {
  ClientMessageLoopAdapter::ActivatePausedDebuggerWindow(local_root);
}

String WebDevToolsAgentImpl::NavigationInitiatorInfo(LocalFrame* frame) {
  for (auto& it : network_agents_) {
    String initiator = it.value->NavigationInitiatorInfo(frame);
    if (!initiator.IsNull())
      return initiator;
  }
  return String();
}

void WebDevToolsAgentImpl::FlushProtocolNotifications() {
  agent_->FlushProtocolNotifications();
}

void WebDevToolsAgentImpl::MainThreadDebuggerPaused() {
  agent_->DebuggerPaused();
}

void WebDevToolsAgentImpl::MainThreadDebuggerResumed() {
  agent_->DebuggerResumed();
}

void WebDevToolsAgentImpl::WillProcessTask(
    const base::PendingTask& pending_task,
    bool was_blocked_or_low_priority) {
  if (network_agents_.empty())
    return;
  v8::Isolate* isolate =
      inspected_frames_->Root()->GetPage()->GetAgentGroupScheduler().Isolate();
  ThreadDebugger::IdleFinished(isolate);
}

void WebDevToolsAgentImpl::DidProcessTask(
    const base::PendingTask& pending_task) {
  if (network_agents_.empty())
    return;
  v8::Isolate* isolate =
      inspected_frames_->Root()->GetPage()->GetAgentGroupScheduler().Isolate();
  ThreadDebugger::IdleStarted(isolate);
  FlushProtocolNotifications();
}

}  // namespace blink
```