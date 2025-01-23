Response:
My thought process to analyze the provided C++ code snippet and answer the user's request goes like this:

1. **Understand the Goal:** The user wants a breakdown of the `thread_debugger_common_impl.cc` file's functionality within the Chromium Blink engine, specifically its relation to web technologies (JavaScript, HTML, CSS), potential logical inferences, and common usage errors. They also want a summary of the file's purpose.

2. **Initial Scan for Keywords:** I'll quickly scan the code for relevant keywords and patterns. I see:
    * `#include`: Indicates dependencies on other parts of the Blink engine. The included headers like `v8_binding_for_core.h`, `v8_blob.h`, `v8_dom_exception.h`, `v8_event.h`, `v8_node.h`, `v8_script_runner.h`, `element.h`, `node.h`, `html_collection.h`, `inspector_dom_debugger_agent.h`,  `script.h` strongly suggest this file is involved in how the debugger interacts with the web page's DOM and JavaScript execution.
    * `v8::Isolate`:  This confirms interaction with the V8 JavaScript engine.
    * `inspector`:  The directory `blink/renderer/core/inspector/` clearly indicates this code is part of the Blink DevTools integration.
    * `ThreadDebugger`: The class name itself suggests its role in debugging.
    * Function names like `AsyncTaskScheduled`, `AsyncTaskCanceled`, `AsyncTaskStarted`, `AsyncTaskFinished`, `PromiseRejected`, `PromiseRejectionRevoked` point to asynchronous operation tracking and promise handling, which are common in JavaScript.
    * Functions like `deepSerialize` and `SerializeNodeToV8Object` and constants like `"nodeType"`, `"nodeValue"`, `"attributes"`, `"children"` suggest functionality for converting DOM elements into a format suitable for the debugger.
    *  `getEventListeners`, `getAccessibleName`, `getAccessibleRole`, `monitorEvents`, `unmonitorEvents` are clearly debugger-related commands exposed to the console.
    * `ConsoleMessageLevel`: Indicates handling of console messages.

3. **Group Functionality by High-Level Purpose:** Based on the keywords and included headers, I can start grouping the file's functionalities:
    * **Asynchronous Task Tracking:** The `AsyncTask*` functions manage the lifecycle of asynchronous operations for debugging.
    * **Promise Debugging:** The `PromiseRejected` and `PromiseRejectionRevoked` functions handle promise-related events.
    * **DOM Serialization for Debugger:** The `deepSerialize` and related `SerializeNodeToV8Object` functions convert DOM nodes and related structures into a format the debugger can understand and display. This is crucial for the "Elements" panel in DevTools.
    * **Console API Extensions:** The `installAdditionalCommandLineAPI` function adds custom commands like `getEventListeners`, `monitorEvents`, etc., to the browser's developer console.
    * **General Debugger Utilities:** Functions like `V8MessageLevelToMessageLevel`, `StoreCurrentStackTrace`, `currentTimeMS`, `valueSubtype`, and `descriptionForValueSubtype` provide general utility functions for the debugger.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The file heavily interacts with V8, handling JavaScript exceptions (`PromiseRejected`), providing console API extensions for interacting with JavaScript objects (`getEventListeners`, `monitorEvents`), and tracking asynchronous JavaScript operations.
    * **HTML:** The DOM serialization functions (`deepSerialize`, `SerializeNodeToV8Object`) are central to how the debugger displays the HTML structure in the "Elements" panel. It extracts node types, attributes, children, and shadow DOM information.
    * **CSS:** While not directly manipulating CSS properties, the ability to inspect elements and their attributes (which can include `class` for CSS selectors) indirectly relates to CSS debugging. The `getAccessibleName` and `getAccessibleRole` functions also relate to accessibility, which can be influenced by CSS.

5. **Logical Inferences and Examples:**
    * **Asynchronous Tasks:**  If an asynchronous JavaScript operation (like a `setTimeout` or a network request) is started, `AsyncTaskScheduled` would be called. When it completes, `AsyncTaskFinished` is called. The debugger uses this to track the flow of asynchronous code.
    * **Promise Rejection:** If a JavaScript promise is rejected without a `catch` handler, `PromiseRejected` would be called, allowing the debugger to report the uncaught rejection.
    * **DOM Serialization:** If the debugger needs to display a `<div>` element, `SerializeNodeToV8Object` would be called to create a representation of that element containing its tag name, attributes, and child nodes.

6. **Common Usage Errors (from a *developer's perspective using the debugger*):**
    * **Misunderstanding Asynchronous Flow:** Not realizing that breakpoints might hit in unexpected orders due to asynchronous operations. The debugger's async task tracking helps with this.
    * **Incorrectly Inspecting DOM:**  Assuming the live DOM is static. Dynamic changes made by JavaScript can be confusing if the developer doesn't understand how to use the debugger's features for live inspection.
    * **Over-reliance on Console Logging:**  While helpful, it's less structured than using the debugger's breakpoints and variable inspection.

7. **Summarize the Functionality:**  Combine the grouped functionalities into a concise summary. The core purpose is to provide the infrastructure for the Blink engine's debugger, enabling developers to inspect JavaScript execution, the DOM structure, and track asynchronous operations.

8. **Structure the Output:** Organize the information clearly with headings and bullet points, addressing each aspect of the user's request (functionality, relation to web technologies, logical inferences, usage errors, and summary). Use clear and concise language.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and accurate response to the user's request. The iterative process of scanning, grouping, connecting, and exemplifying ensures I cover all the key aspects of the code's functionality and its relevance to web development.
好的，让我们来分析一下 `blink/renderer/core/inspector/thread_debugger_common_impl.cc` 这个文件。

**文件功能归纳：**

这个文件是 Chromium Blink 引擎中负责实现线程调试器通用功能的关键部分。它提供了一系列底层的接口和工具，用于支持开发者工具（DevTools）对 JavaScript 代码的调试，包括：

* **异步任务跟踪:** 记录和跟踪异步操作的调度、取消、开始和结束，这对于理解和调试基于 Promise、setTimeout 等机制的异步代码至关重要。
* **Promise 调试:**  处理 Promise 的 rejected 和 revoked 事件，帮助开发者追踪未处理的 Promise 异常。
* **DOM 节点序列化:** 将 DOM 节点及其属性、子节点等信息转换为 DevTools 可以理解的 JSON 格式，用于在 Elements 面板中展示 DOM 结构。
* **控制台 API 扩展:**  提供一些额外的命令行 API，例如 `getEventListeners` 和 `monitorEvents`，方便开发者在控制台中进行更深入的调试。
* **通用调试工具:** 提供一些辅助函数，例如将 V8 的消息级别转换为 DevTools 的消息级别，存储当前调用栈，获取当前时间等。
* **对象类型判断:** 判断 V8 对象是否是特定的类型，例如 Node、HTMLCollection 等，用于在调试器中提供更精细的展示和处理。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件与 JavaScript 和 HTML 的关系非常密切，与 CSS 的关系是间接的。

* **JavaScript:**
    * **异步任务跟踪:** 当 JavaScript 代码中执行了类似 `setTimeout` 或 `requestAnimationFrame` 这样的异步操作时，这个文件中的 `AsyncTaskScheduled` 函数会被调用记录该任务。当任务执行完毕后，`AsyncTaskFinished` 会被调用。
        * **假设输入:**  JavaScript 代码执行 `setTimeout(() => { console.log("Hello"); }, 1000);`
        * **输出:** DevTools 的 Performance 面板或 Console 面板可以显示出这个定时器任务的开始和结束时间，方便分析性能问题。
    * **Promise 调试:** 当一个 Promise 被 rejected 且没有被 `catch` 处理时，`PromiseRejected` 函数会被调用，并记录相关的错误信息。
        * **假设输入:** JavaScript 代码执行 `Promise.reject("Something went wrong!");`
        * **输出:** DevTools 的 Console 面板会显示 "Uncaught (in promise) Something went wrong!" 的错误信息，方便开发者定位问题。
    * **控制台 API 扩展:** `getEventListeners(document.body)`  会调用这个文件中注册的回调函数，返回 `document.body` 上注册的所有事件监听器信息。
        * **假设输入:**  在 DevTools Console 中输入 `getEventListeners(document.getElementById('myButton'))`
        * **输出:** Console 面板会显示 `myButton` 元素上绑定的各种事件监听器及其回调函数。
    * **脚本求值结果处理:** 文件中包含了对 `ScriptEvaluationResult` 的处理，这意味着它参与了 DevTools 执行 JavaScript 代码片段（例如在 Console 面板中输入代码）的过程。

* **HTML:**
    * **DOM 节点序列化:** 当 DevTools 的 Elements 面板需要展示页面 DOM 结构时，会调用 `deepSerialize` 或 `SerializeNodeToV8Object` 这样的函数，将 HTML 元素（例如 `<div>`, `<p>`) 转换为 JSON 数据。
        * **假设输入:** 一个包含 `<div id="container"><span>Text</span></div>` 的 HTML 片段。
        * **输出:**  DevTools 会接收到类似如下的 JSON 数据：
        ```json
        {
          "type": "node",
          "value": {
            "nodeType": 1,
            "nodeValue": null,
            "childNodeCount": 1,
            "backendNodeId": 123, // 假设的 backendNodeId
            "loaderId": "...",
            "localName": "div",
            "namespaceURI": "http://www.w3.org/1999/xhtml",
            "attributes": {
              "id": "container"
            },
            "shadowRoot": null,
            "children": [
              {
                "type": "node",
                "value": {
                  "nodeType": 1,
                  "nodeValue": null,
                  "childNodeCount": 0,
                  "backendNodeId": 456, // 假设的 backendNodeId
                  "loaderId": "...",
                  "localName": "span",
                  "namespaceURI": "http://www.w3.org/1999/xhtml",
                  "attributes": {},
                  "shadowRoot": null,
                  "children": []
                }
              }
            ]
          }
        }
        ```

* **CSS:**
    * 虽然这个文件不直接处理 CSS 属性或选择器，但它提供的 DOM 节点序列化功能是 DevTools Elements 面板展示元素样式的基础。通过序列化 DOM 节点，DevTools 才能关联到应用于该节点的 CSS 样式。
    * `getAccessibleName` 和 `getAccessibleRole` 这样的函数也与可访问性相关，而 CSS 可以影响元素的可访问性属性。

**逻辑推理的假设输入与输出：**

* **假设输入:**  DevTools 通过 Inspector API 请求某个特定 DOM 节点的详细信息（包括子节点，最大深度为 2）。
* **输出:** `deepSerialize` 函数会根据请求的深度，递归地调用 `SerializeNodeToV8Object`，将该节点及其两层子节点的信息序列化成 JSON 数据返回给 DevTools。

**涉及用户或者编程常见的使用错误，请举例说明：**

这个文件本身是 Blink 引擎的内部实现，普通开发者不会直接与其交互。 然而，它所支持的功能在开发者使用 DevTools 时，可能会遇到一些使用上的误解或错误：

* **忘记处理 Promise Rejection:**  如果开发者编写了返回 Promise 的异步代码，但忘记添加 `.catch()` 处理 rejected 状态，DevTools 的 Console 面板会显示 "Uncaught (in promise)" 的错误。 这不是这个文件本身的错误，而是开发者在使用 Promise 时的常见疏忽。
* **误解 `getEventListeners` 的作用域:**  开发者可能会认为 `getEventListeners(window)` 会返回所有全局事件监听器，但实际上它主要返回直接绑定到 `window` 对象上的监听器。对于通过事件委托绑定到 `document` 或其他祖先元素的监听器，需要使用对应的目标元素作为参数。
* **过度依赖 `monitorEvents`:**  `monitorEvents` 会在控制台中记录大量事件信息，如果监控的事件类型过多或目标元素触发的事件过于频繁，可能会导致控制台输出过多，影响调试效率。

**总结：**

`blink/renderer/core/inspector/thread_debugger_common_impl.cc` 是 Blink 引擎中线程调试器实现的核心组件之一。它提供了基础的功能，使得 DevTools 能够与 Blink 引擎进行交互，获取 JavaScript 运行状态、DOM 结构等信息，从而支持开发者进行高效的调试。它与 JavaScript 和 HTML 紧密相关，是构建强大浏览器开发者工具的重要基石。

### 提示词
```
这是目录为blink/renderer/core/inspector/thread_debugger_common_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/thread_debugger_common_impl.h"

#include <memory>

#include "base/check.h"
#include "base/rand_util.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_blob.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_token_list.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_event.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_event_listener.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_event_listener_info.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_event_target.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_html_all_collection.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_html_collection.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_node.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_node_list.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_trusted_html.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_trusted_script.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_trusted_script_url.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_window.h"
#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_list.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_debugger_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/inspector/v8_inspector_string.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_html.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_script.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_script_url.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/v8_set_return_value.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
namespace blink {

ThreadDebuggerCommonImpl::ThreadDebuggerCommonImpl(v8::Isolate* isolate)
    : ThreadDebugger(isolate), isolate_(isolate) {}

ThreadDebuggerCommonImpl::~ThreadDebuggerCommonImpl() = default;

// static
mojom::ConsoleMessageLevel
ThreadDebuggerCommonImpl::V8MessageLevelToMessageLevel(
    v8::Isolate::MessageErrorLevel level) {
  mojom::ConsoleMessageLevel result = mojom::ConsoleMessageLevel::kInfo;
  switch (level) {
    case v8::Isolate::kMessageDebug:
      result = mojom::ConsoleMessageLevel::kVerbose;
      break;
    case v8::Isolate::kMessageWarning:
      result = mojom::ConsoleMessageLevel::kWarning;
      break;
    case v8::Isolate::kMessageError:
      result = mojom::ConsoleMessageLevel::kError;
      break;
    case v8::Isolate::kMessageLog:
    case v8::Isolate::kMessageInfo:
    default:
      result = mojom::ConsoleMessageLevel::kInfo;
      break;
  }
  return result;
}

void ThreadDebuggerCommonImpl::AsyncTaskScheduled(
    const StringView& operation_name,
    void* task,
    bool recurring) {
  DCHECK_EQ(reinterpret_cast<intptr_t>(task) % 2, 0);
  v8_inspector_->asyncTaskScheduled(ToV8InspectorStringView(operation_name),
                                    task, recurring);
}

void ThreadDebuggerCommonImpl::AsyncTaskCanceled(void* task) {
  DCHECK_EQ(reinterpret_cast<intptr_t>(task) % 2, 0);
  v8_inspector_->asyncTaskCanceled(task);
}

void ThreadDebuggerCommonImpl::AllAsyncTasksCanceled() {
  v8_inspector_->allAsyncTasksCanceled();
}

void ThreadDebuggerCommonImpl::AsyncTaskStarted(void* task) {
  DCHECK_EQ(reinterpret_cast<intptr_t>(task) % 2, 0);
  v8_inspector_->asyncTaskStarted(task);
}

void ThreadDebuggerCommonImpl::AsyncTaskFinished(void* task) {
  DCHECK_EQ(reinterpret_cast<intptr_t>(task) % 2, 0);
  v8_inspector_->asyncTaskFinished(task);
}

v8_inspector::V8StackTraceId ThreadDebuggerCommonImpl::StoreCurrentStackTrace(
    const StringView& description) {
  return v8_inspector_->storeCurrentStackTrace(
      ToV8InspectorStringView(description));
}

void ThreadDebuggerCommonImpl::ExternalAsyncTaskStarted(
    const v8_inspector::V8StackTraceId& parent) {
  v8_inspector_->externalAsyncTaskStarted(parent);
}

void ThreadDebuggerCommonImpl::ExternalAsyncTaskFinished(
    const v8_inspector::V8StackTraceId& parent) {
  v8_inspector_->externalAsyncTaskFinished(parent);
}

unsigned ThreadDebuggerCommonImpl::PromiseRejected(
    v8::Local<v8::Context> context,
    const String& error_message,
    v8::Local<v8::Value> exception,
    std::unique_ptr<SourceLocation> location) {
  const StringView default_message = "Uncaught (in promise)";
  String message = error_message;
  if (message.empty()) {
    message = "Uncaught (in promise)";
  } else if (message.StartsWith("Uncaught ")) {
    message = "Uncaught (in promise)" + StringView(message, 8);
  }

  ReportConsoleMessage(
      ToExecutionContext(context), mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kError, message, location.get());
  String url = location->Url();
  return GetV8Inspector()->exceptionThrown(
      context, ToV8InspectorStringView(default_message), exception,
      ToV8InspectorStringView(message), ToV8InspectorStringView(url),
      location->LineNumber(), location->ColumnNumber(),
      location->TakeStackTrace(), location->ScriptId());
}

void ThreadDebuggerCommonImpl::PromiseRejectionRevoked(
    v8::Local<v8::Context> context,
    unsigned promise_rejection_id) {
  const String message = "Handler added to rejected promise";
  GetV8Inspector()->exceptionRevoked(context, promise_rejection_id,
                                     ToV8InspectorStringView(message));
}

// TODO(mustaq): Is it tied to a specific user action? https://crbug.com/826293
void ThreadDebuggerCommonImpl::beginUserGesture() {
  auto* window = CurrentDOMWindow(isolate_);
  LocalFrame::NotifyUserActivation(
      window ? window->GetFrame() : nullptr,
      mojom::blink::UserActivationNotificationType::kDevTools);
}

namespace {
static const char kType[] = "type";
static const char kValue[] = "value";
enum ShadowTreeSerialization { kNone, kOpen, kAll };

v8::Local<v8::String> TypeStringKey(v8::Isolate* isolate_) {
  return V8String(isolate_, kType);
}
v8::Local<v8::String> ValueStringKey(v8::Isolate* isolate_) {
  return V8String(isolate_, kValue);
}

v8::Local<v8::Object> SerializeNodeToV8Object(
    Node* node,
    v8::Isolate* isolate,
    int max_node_depth,
    ShadowTreeSerialization include_shadow_tree) {
  static const char kAttributes[] = "attributes";
  static const char kBackendNodeId[] = "backendNodeId";
  static const char kChildren[] = "children";
  static const char kChildNodeCount[] = "childNodeCount";
  static const char kLoaderId[] = "loaderId";
  static const char kLocalName[] = "localName";
  static const char kNamespaceURI[] = "namespaceURI";
  static const char kNode[] = "node";
  static const char kNodeType[] = "nodeType";
  static const char kNodeValue[] = "nodeValue";
  static const char kShadowRoot[] = "shadowRoot";
  static const char kShadowRootMode[] = "mode";
  static const char kShadowRootOpen[] = "open";
  static const char kShadowRootClosed[] = "closed";
  static const char kFrameIdParameterName[] = "frameId";

  v8::LocalVector<v8::Name> serialized_value_keys(isolate);
  v8::LocalVector<v8::Value> serialized_value_values(isolate);
  serialized_value_keys.push_back(V8String(isolate, kNodeType));
  serialized_value_values.push_back(
      v8::Number::New(isolate, node->getNodeType()));

  if (!node->nodeValue().IsNull()) {
    serialized_value_keys.push_back(V8String(isolate, kNodeValue));
    serialized_value_values.push_back(V8String(isolate, node->nodeValue()));
  }

  serialized_value_keys.push_back(V8String(isolate, kChildNodeCount));
  serialized_value_values.push_back(
      v8::Number::New(isolate, node->CountChildren()));

  DOMNodeId backend_node_id = node->GetDomNodeId();
  serialized_value_keys.push_back(V8String(isolate, kBackendNodeId));
  serialized_value_values.push_back(v8::Number::New(isolate, backend_node_id));

  serialized_value_keys.push_back(V8String(isolate, kLoaderId));
  serialized_value_values.push_back(V8String(
      isolate, IdentifiersFactory::LoaderId(node->GetDocument().Loader())));

  if (node->IsAttributeNode()) {
    Attr* attribute = To<Attr>(node);

    serialized_value_keys.push_back(V8String(isolate, kLocalName));
    serialized_value_values.push_back(
        V8String(isolate, attribute->localName()));

    serialized_value_keys.push_back(V8String(isolate, kNamespaceURI));
    if (attribute->namespaceURI().IsNull()) {
      serialized_value_values.push_back(v8::Null(isolate));
    } else {
      serialized_value_values.push_back(
          V8String(isolate, attribute->namespaceURI()));
    }
  }

  if (node->IsElementNode()) {
    Element* element = To<Element>(node);

    if (HTMLFrameOwnerElement* frameOwnerElement =
            DynamicTo<HTMLFrameOwnerElement>(node)) {
      if (frameOwnerElement->ContentFrame()) {
        serialized_value_keys.push_back(
            V8String(isolate, kFrameIdParameterName));
        serialized_value_values.push_back(V8String(
            isolate,
            IdentifiersFactory::IdFromToken(
                frameOwnerElement->ContentFrame()->GetDevToolsFrameToken())));
      }
    }

    if (ShadowRoot* shadow_root = node->GetShadowRoot()) {
      // Do not decrease `max_node_depth` for shadow root. Shadow root should be
      // serialized fully, while it's children will be serialized respecting
      // max_node_depth and include_shadow_tree.
      v8::Local<v8::Object> serialized_shadow = SerializeNodeToV8Object(
          shadow_root, isolate, max_node_depth, include_shadow_tree);

      serialized_value_keys.push_back(V8String(isolate, kShadowRoot));
      serialized_value_values.push_back(serialized_shadow);
    } else {
      serialized_value_keys.push_back(V8String(isolate, kShadowRoot));
      serialized_value_values.push_back(v8::Null(isolate));
    }

    serialized_value_keys.push_back(V8String(isolate, kLocalName));
    serialized_value_values.push_back(V8String(isolate, element->localName()));

    serialized_value_keys.push_back(V8String(isolate, kNamespaceURI));
    serialized_value_values.push_back(
        V8String(isolate, element->namespaceURI()));

    v8::LocalVector<v8::Name> node_attributes_keys(isolate);
    v8::LocalVector<v8::Value> node_attributes_values(isolate);

    for (const Attribute& attribute : element->Attributes()) {
      node_attributes_keys.push_back(
          V8String(isolate, attribute.GetName().ToString()));
      node_attributes_values.push_back(V8String(isolate, attribute.Value()));
    }

    DCHECK(node_attributes_values.size() == node_attributes_keys.size());
    v8::Local<v8::Object> node_attributes = v8::Object::New(
        isolate, v8::Null(isolate), node_attributes_keys.data(),
        node_attributes_values.data(), node_attributes_keys.size());

    serialized_value_keys.push_back(V8String(isolate, kAttributes));
    serialized_value_values.push_back(node_attributes);
  }

  bool include_children = max_node_depth > 0;
  if (node->IsShadowRoot()) {
    ShadowRoot* shadow_root = To<ShadowRoot>(node);

    // Include children of shadow root only if `max_depth` is not reached and
    // one of the following is true:
    // 1. `include_shadow_tree` set to `all` regardless of the shadow type.
    // 2. `include_shadow_tree` set to `open` and the shadow type is `open`.
    if (include_shadow_tree == kNone) {
      include_children = false;
    } else if (include_shadow_tree == kOpen &&
               shadow_root->GetMode() != ShadowRootMode::kOpen) {
      include_children = false;
    }

    serialized_value_keys.push_back(V8String(isolate, kShadowRootMode));
    serialized_value_values.push_back(
        V8String(isolate, shadow_root->GetMode() == ShadowRootMode::kOpen
                              ? kShadowRootOpen
                              : kShadowRootClosed));
  }

  if (include_children) {
    NodeList* child_nodes = node->childNodes();

    v8::Local<v8::Array> children =
        v8::Array::New(isolate, child_nodes->length());

    for (unsigned int i = 0; i < child_nodes->length(); i++) {
      Node* child_node = child_nodes->item(i);
      v8::Local<v8::Object> serialized_child_node = SerializeNodeToV8Object(
          child_node, isolate, max_node_depth - 1, include_shadow_tree);

      children
          ->CreateDataProperty(isolate->GetCurrentContext(), i,
                               serialized_child_node)
          .Check();
    }
    serialized_value_keys.push_back(V8String(isolate, kChildren));
    serialized_value_values.push_back(children);
  }

  DCHECK(serialized_value_values.size() == serialized_value_keys.size());

  v8::Local<v8::Object> serialized_value = v8::Object::New(
      isolate, v8::Null(isolate), serialized_value_keys.data(),
      serialized_value_values.data(), serialized_value_keys.size());

  v8::LocalVector<v8::Name> result_keys(isolate);
  v8::LocalVector<v8::Value> result_values(isolate);

  result_keys.push_back(TypeStringKey(isolate));
  result_values.push_back(V8String(isolate, kNode));

  result_keys.push_back(ValueStringKey(isolate));
  result_values.push_back(serialized_value);

  return v8::Object::New(isolate, v8::Null(isolate), result_keys.data(),
                         result_values.data(), result_keys.size());
}

std::unique_ptr<v8_inspector::DeepSerializedValue> DeepSerializeHtmlCollection(
    HTMLCollection* html_collection,
    v8::Isolate* isolate_,
    int max_depth,
    int max_node_depth,
    ShadowTreeSerialization include_shadow_tree) {
  static const char kHtmlCollection[] = "htmlcollection";
  if (max_depth > 0) {
    v8::Local<v8::Array> children =
        v8::Array::New(isolate_, html_collection->length());

    for (unsigned int i = 0; i < html_collection->length(); i++) {
      Node* child_node = html_collection->item(i);
      v8::Local<v8::Object> serialized_child_node = SerializeNodeToV8Object(
          child_node, isolate_, max_node_depth, include_shadow_tree);
      children
          ->CreateDataProperty(isolate_->GetCurrentContext(), i,
                               serialized_child_node)
          .Check();
    }
    return std::make_unique<v8_inspector::DeepSerializedValue>(
        ToV8InspectorStringBuffer(kHtmlCollection), children);
  }

  return std::make_unique<v8_inspector::DeepSerializedValue>(
      ToV8InspectorStringBuffer(kHtmlCollection));
}

std::unique_ptr<v8_inspector::DeepSerializedValue> DeepSerializeNodeList(
    NodeList* node_list,
    v8::Isolate* isolate_,
    int max_depth,
    int max_node_depth,
    ShadowTreeSerialization include_shadow_tree) {
  static const char kNodeList[] = "nodelist";
  if (max_depth > 0) {
    v8::Local<v8::Array> children =
        v8::Array::New(isolate_, node_list->length());

    for (unsigned int i = 0; i < node_list->length(); i++) {
      Node* child_node = node_list->item(i);
      v8::Local<v8::Object> serialized_child_node = SerializeNodeToV8Object(
          child_node, isolate_, max_node_depth, include_shadow_tree);
      children
          ->CreateDataProperty(isolate_->GetCurrentContext(), i,
                               serialized_child_node)
          .Check();
    }
    return std::make_unique<v8_inspector::DeepSerializedValue>(
        ToV8InspectorStringBuffer(kNodeList), children);
  }

  return std::make_unique<v8_inspector::DeepSerializedValue>(
      ToV8InspectorStringBuffer(kNodeList));
}

std::unique_ptr<v8_inspector::DeepSerializedValue> DeepSerializeNode(
    Node* node,
    v8::Isolate* isolate,
    int max_node_depth,
    ShadowTreeSerialization include_shadow_tree) {
  v8::Local<v8::Object> node_v8_object = SerializeNodeToV8Object(
      node, isolate, max_node_depth, include_shadow_tree);

  v8::Local<v8::Value> value_v8_object =
      node_v8_object->Get(isolate->GetCurrentContext(), ValueStringKey(isolate))
          .ToLocalChecked();

  // Safely get `type` from object value.
  v8::MaybeLocal<v8::Value> maybe_type_v8_value =
      node_v8_object->Get(isolate->GetCurrentContext(), TypeStringKey(isolate));
  DCHECK(!maybe_type_v8_value.IsEmpty());
  v8::Local<v8::Value> type_v8_value = maybe_type_v8_value.ToLocalChecked();
  DCHECK(type_v8_value->IsString());
  v8::Local<v8::String> type_v8_string = type_v8_value.As<v8::String>();
  String type_string = ToCoreString(isolate, type_v8_string);
  StringView type_string_view = StringView(type_string);
  std::unique_ptr<v8_inspector::StringBuffer> type_string_buffer =
      ToV8InspectorStringBuffer(type_string_view);

  return std::make_unique<v8_inspector::DeepSerializedValue>(
      std::move(type_string_buffer), value_v8_object);
}

std::unique_ptr<v8_inspector::DeepSerializedValue> DeepSerializeWindow(
    DOMWindow* window,
    v8::Isolate* isolate) {
  static const char kContextParameterName[] = "context";

  v8::LocalVector<v8::Name> keys(isolate);
  v8::LocalVector<v8::Value> values(isolate);

  keys.push_back(V8String(isolate, kContextParameterName));
  values.push_back(
      V8String(isolate, IdentifiersFactory::IdFromToken(
                            window->GetFrame()->GetDevToolsFrameToken())));

  return std::make_unique<v8_inspector::DeepSerializedValue>(
      ToV8InspectorStringBuffer("window"),
      v8::Object::New(isolate, v8::Null(isolate), keys.data(), values.data(),
                      keys.size()));
}

}  // namespace

// If `additional_parameters` cannot be parsed, return `false` and provide
// `error_message`.
bool ReadAdditionalSerializationParameters(
    v8::Local<v8::Object> additional_parameters,
    int& max_node_depth,
    ShadowTreeSerialization& include_shadow_tree,
    v8::Local<v8::Context> context,
    std::unique_ptr<v8_inspector::StringBuffer>* error_message) {
  static const char kMaxNodeDepthParameterName[] = "maxNodeDepth";
  static const char kIncludeShadowTreeParameterName[] = "includeShadowTree";
  static const char kIncludeShadowTreeValueNone[] = "none";
  static const char kIncludeShadowTreeValueOpen[] = "open";
  static const char kIncludeShadowTreeValueAll[] = "all";

  // Set default values.
  max_node_depth = 0;
  include_shadow_tree = ShadowTreeSerialization::kNone;

  if (additional_parameters.IsEmpty()) {
    return true;
  }

  v8::MaybeLocal<v8::Value> include_shadow_tree_parameter =
      additional_parameters->Get(
          context,
          V8String(context->GetIsolate(), kIncludeShadowTreeParameterName));
  if (!include_shadow_tree_parameter.IsEmpty()) {
    v8::Local<v8::Value> include_shadow_tree_value =
        include_shadow_tree_parameter.ToLocalChecked();
    if (!include_shadow_tree_value->IsUndefined()) {
      if (!include_shadow_tree_value->IsString()) {
        *error_message = ToV8InspectorStringBuffer(
            String("Parameter " + String(kIncludeShadowTreeParameterName) +
                   " should be of type string."));
        return false;
      }
      String include_shadow_tree_string = ToCoreString(
          context->GetIsolate(), include_shadow_tree_value.As<v8::String>());

      if (include_shadow_tree_string == kIncludeShadowTreeValueNone) {
        include_shadow_tree = ShadowTreeSerialization::kNone;
      } else if (include_shadow_tree_string == kIncludeShadowTreeValueOpen) {
        include_shadow_tree = ShadowTreeSerialization::kOpen;
      } else if (include_shadow_tree_string == kIncludeShadowTreeValueAll) {
        include_shadow_tree = ShadowTreeSerialization::kAll;
      } else {
        *error_message = ToV8InspectorStringBuffer(
            String("Unknown value " + String(kIncludeShadowTreeParameterName) +
                   ":" + include_shadow_tree_string));
        return false;
      }
    }
  }

  v8::MaybeLocal<v8::Value> max_node_depth_parameter =
      additional_parameters->Get(
          context, V8String(context->GetIsolate(), kMaxNodeDepthParameterName));
  if (!max_node_depth_parameter.IsEmpty()) {
    v8::Local<v8::Value> max_node_depth_value =
        max_node_depth_parameter.ToLocalChecked();
    if (!max_node_depth_value->IsUndefined()) {
      if (!max_node_depth_value->IsInt32()) {
        *error_message = ToV8InspectorStringBuffer(
            String("Parameter " + String(kMaxNodeDepthParameterName) +
                   " should be of type int."));
        return false;
      }
      max_node_depth = max_node_depth_value.As<v8::Int32>()->Value();
    }
  }
  return true;
}

std::unique_ptr<v8_inspector::DeepSerializationResult>
ThreadDebuggerCommonImpl::deepSerialize(
    v8::Local<v8::Value> v8_value,
    int max_depth,
    v8::Local<v8::Object> additional_parameters) {
  int max_node_depth;
  ShadowTreeSerialization include_shadow_tree;

  std::unique_ptr<v8_inspector::StringBuffer> error_message;
  bool success = ReadAdditionalSerializationParameters(
      additional_parameters, max_node_depth, include_shadow_tree,
      isolate_->GetCurrentContext(), &error_message);
  if (!success) {
    return std::make_unique<v8_inspector::DeepSerializationResult>(
        std::move(error_message));
  }

  if (!v8_value->IsObject()) {
    return nullptr;
  }
  v8::Local<v8::Object> object = v8_value.As<v8::Object>();

  // Serialize according to https://w3c.github.io/webdriver-bidi.
  if (Node* node = V8Node::ToWrappable(isolate_, object)) {
    return std::make_unique<v8_inspector::DeepSerializationResult>(
        DeepSerializeNode(node, isolate_, max_node_depth, include_shadow_tree));
  }

  // Serialize as a regular array
  if (HTMLCollection* html_collection =
          V8HTMLCollection::ToWrappable(isolate_, object)) {
    return std::make_unique<v8_inspector::DeepSerializationResult>(
        DeepSerializeHtmlCollection(html_collection, isolate_, max_depth,
                                    max_node_depth, include_shadow_tree));
  }

  // Serialize as a regular array
  if (NodeList* node_list = V8NodeList::ToWrappable(isolate_, object)) {
    return std::make_unique<v8_inspector::DeepSerializationResult>(
        DeepSerializeNodeList(node_list, isolate_, max_depth, max_node_depth,
                              include_shadow_tree));
  }

  if (DOMWindow* window = V8Window::ToWrappable(isolate_, object)) {
    return std::make_unique<v8_inspector::DeepSerializationResult>(
        DeepSerializeWindow(window, isolate_));
  }

  // TODO(caseq): consider object->IsApiWrapper() + checking for all kinds
  // of (Typed)?Array(Buffers)?. IsApiWrapper() returns true for these, but
  // we want them to fall through to default serialization and not be treated
  // as "platform objects".
  if (V8DOMWrapper::IsWrapper(isolate_, object)) {
    return std::make_unique<v8_inspector::DeepSerializationResult>(
        std::make_unique<v8_inspector::DeepSerializedValue>(
            ToV8InspectorStringBuffer("platformobject")));
  }

  return nullptr;
}

std::unique_ptr<v8_inspector::StringBuffer>
ThreadDebuggerCommonImpl::valueSubtype(v8::Local<v8::Value> value) {
  static const char kNode[] = "node";
  static const char kArray[] = "array";
  static const char kError[] = "error";
  static const char kBlob[] = "blob";
  static const char kTrustedType[] = "trustedtype";

  if (V8Node::HasInstance(isolate_, value)) {
    return ToV8InspectorStringBuffer(kNode);
  }
  if (V8NodeList::HasInstance(isolate_, value) ||
      V8DOMTokenList::HasInstance(isolate_, value) ||
      V8HTMLCollection::HasInstance(isolate_, value) ||
      V8HTMLAllCollection::HasInstance(isolate_, value)) {
    return ToV8InspectorStringBuffer(kArray);
  }
  if (V8DOMException::HasInstance(isolate_, value)) {
    return ToV8InspectorStringBuffer(kError);
  }
  if (V8Blob::HasInstance(isolate_, value)) {
    return ToV8InspectorStringBuffer(kBlob);
  }
  if (V8TrustedHTML::HasInstance(isolate_, value) ||
      V8TrustedScript::HasInstance(isolate_, value) ||
      V8TrustedScriptURL::HasInstance(isolate_, value)) {
    return ToV8InspectorStringBuffer(kTrustedType);
  }
  return nullptr;
}

std::unique_ptr<v8_inspector::StringBuffer>
ThreadDebuggerCommonImpl::descriptionForValueSubtype(
    v8::Local<v8::Context> context,
    v8::Local<v8::Value> value) {
  if (TrustedHTML* trusted_html = V8TrustedHTML::ToWrappable(isolate_, value)) {
    return ToV8InspectorStringBuffer(trusted_html->toString());
  } else if (TrustedScript* trusted_script =
                 V8TrustedScript::ToWrappable(isolate_, value)) {
    return ToV8InspectorStringBuffer(trusted_script->toString());
  } else if (TrustedScriptURL* trusted_script_url =
                 V8TrustedScriptURL::ToWrappable(isolate_, value)) {
    return ToV8InspectorStringBuffer(trusted_script_url->toString());
  } else if (Node* node = V8Node::ToWrappable(isolate_, value)) {
    StringBuilder description;
    switch (node->getNodeType()) {
      case Node::kElementNode: {
        const auto* element = To<blink::Element>(node);
        description.Append(element->TagQName().ToString());

        const AtomicString& id = element->GetIdAttribute();
        if (!id.empty()) {
          description.Append('#');
          description.Append(id);
        }
        if (element->HasClass()) {
          auto element_class_names = element->ClassNames();
          auto n_classes = element_class_names.size();
          for (unsigned i = 0; i < n_classes; ++i) {
            description.Append('.');
            description.Append(element_class_names[i]);
          }
        }
        break;
      }
      case Node::kDocumentTypeNode: {
        description.Append("<!DOCTYPE ");
        description.Append(node->nodeName());
        description.Append('>');
        break;
      }
      default: {
        description.Append(node->nodeName());
        break;
      }
    }
    DCHECK(description.length());

    return ToV8InspectorStringBuffer(description.ToString());
  }
  return nullptr;
}

double ThreadDebuggerCommonImpl::currentTimeMS() {
  return base::Time::Now().InMillisecondsFSinceUnixEpoch();
}

bool ThreadDebuggerCommonImpl::isInspectableHeapObject(
    v8::Local<v8::Object> object) {
  return !object->IsApiWrapper() || V8DOMWrapper::IsWrapper(isolate_, object);
}

static void ReturnDataCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(info.Data());
}

static v8::Maybe<bool> CreateDataProperty(v8::Local<v8::Context> context,
                                          v8::Local<v8::Object> object,
                                          v8::Local<v8::Name> key,
                                          v8::Local<v8::Value> value) {
  v8::TryCatch try_catch(context->GetIsolate());
  v8::Isolate::DisallowJavascriptExecutionScope throw_js(
      context->GetIsolate(),
      v8::Isolate::DisallowJavascriptExecutionScope::THROW_ON_FAILURE);
  return object->CreateDataProperty(context, key, value);
}

static void CreateFunctionPropertyWithData(
    v8::Local<v8::Context> context,
    v8::Local<v8::Object> object,
    const char* name,
    v8::FunctionCallback callback,
    v8::Local<v8::Value> data,
    const char* description,
    v8::SideEffectType side_effect_type) {
  v8::Local<v8::String> func_name = V8String(context->GetIsolate(), name);
  v8::Local<v8::Function> func;
  if (!v8::Function::New(context, callback, data, 0,
                         v8::ConstructorBehavior::kThrow, side_effect_type)
           .ToLocal(&func))
    return;
  func->SetName(func_name);
  v8::Local<v8::String> return_value =
      V8String(context->GetIsolate(), description);
  v8::Local<v8::Function> to_string_function;
  if (v8::Function::New(context, ReturnDataCallback, return_value, 0,
                        v8::ConstructorBehavior::kThrow,
                        v8::SideEffectType::kHasNoSideEffect)
          .ToLocal(&to_string_function))
    CreateDataProperty(context, func,
                       V8AtomicString(context->GetIsolate(), "toString"),
                       to_string_function);
  CreateDataProperty(context, object, func_name, func);
}

v8::Maybe<bool> ThreadDebuggerCommonImpl::CreateDataPropertyInArray(
    v8::Local<v8::Context> context,
    v8::Local<v8::Array> array,
    int index,
    v8::Local<v8::Value> value) {
  v8::TryCatch try_catch(context->GetIsolate());
  v8::Isolate::DisallowJavascriptExecutionScope throw_js(
      context->GetIsolate(),
      v8::Isolate::DisallowJavascriptExecutionScope::THROW_ON_FAILURE);
  return array->CreateDataProperty(context, index, value);
}

void ThreadDebuggerCommonImpl::CreateFunctionProperty(
    v8::Local<v8::Context> context,
    v8::Local<v8::Object> object,
    const char* name,
    v8::FunctionCallback callback,
    const char* description,
    v8::SideEffectType side_effect_type) {
  CreateFunctionPropertyWithData(context, object, name, callback,
                                 v8::External::New(context->GetIsolate(), this),
                                 description, side_effect_type);
}

void ThreadDebuggerCommonImpl::installAdditionalCommandLineAPI(
    v8::Local<v8::Context> context,
    v8::Local<v8::Object> object) {
  CreateFunctionProperty(
      context, object, "getEventListeners",
      ThreadDebuggerCommonImpl::GetEventListenersCallback,
      "function getEventListeners(node) { [Command Line API] }",
      v8::SideEffectType::kHasNoSideEffect);

  CreateFunctionProperty(
      context, object, "getAccessibleName",
      ThreadDebuggerCommonImpl::GetAccessibleNameCallback,
      "function getAccessibleName(node) { [Command Line API] }",
      v8::SideEffectType::kHasNoSideEffect);

  CreateFunctionProperty(
      context, object, "getAccessibleRole",
      ThreadDebuggerCommonImpl::GetAccessibleRoleCallback,
      "function getAccessibleRole(node) { [Command Line API] }",
      v8::SideEffectType::kHasNoSideEffect);

  v8::Isolate* isolate = context->GetIsolate();
  ScriptEvaluationResult result =
      ClassicScript::CreateUnspecifiedScript(
          "(function(e) { console.log(e.type, e); })",
          ScriptSourceLocationType::kInternal)
          ->RunScriptOnScriptStateAndReturnValue(
              ScriptState::From(isolate, context));
  if (result.GetResultType() != ScriptEvaluationResult::ResultType::kSuccess) {
    // On pages where scripting is disabled or CSP sandbox directive is used,
    // this can be blocked and thus early exited here.
    // This is probably OK because `monitorEvents()` console API is anyway not
    // working on such pages. For more discussion see
    // https://crrev.com/c/3258735/9/third_party/blink/renderer/core/inspector/thread_debugger.cc#529
    return;
  }

  v8::Local<v8::Value> function_value = result.GetSuccessValue();
  DCHECK(function_value->IsFunction());
  CreateFunctionPropertyWithData(
      context, object, "monitorEvents",
      ThreadDebuggerCommonImpl::MonitorEventsCallback, function_value,
      "function monitorEvents(object, [types]) { [Command Line API] }",
      v8::SideEffectType::kHasSideEffect);
  CreateFunctionPropertyWithData(
      context, object, "unmonitorEvents",
      ThreadDebuggerCommonImpl::UnmonitorEventsCallback, function_value,
      "function unmonitorEvents(object, [types]) { [Command
```