Response:
Let's break down the thought process to analyze the `web_node.cc` file.

1. **Understand the Goal:** The request asks for the functionalities of `web_node.cc`, its relation to web technologies (JavaScript, HTML, CSS), potential errors, and how a user might reach this code.

2. **Identify the Core Purpose:** The file is named `web_node.cc` and located in `blink/renderer/core/exported/`. The `exported` directory suggests this code provides an interface to Blink's internal `Node` representation for external (to the core rendering engine) use. The `#include "third_party/blink/public/web/web_node.h"` confirms this: it's the implementation of the public `WebNode` interface.

3. **Analyze Included Headers:** The included headers offer significant clues about the functionalities. Scan through them and categorize their significance:
    * **Public Blink Interfaces (`third_party/blink/public/web/*`):**  These are the main interfaces exposed: `WebDocument`, `WebDOMEvent`, `WebElement`, `WebElementCollection`, `WebString`. This tells us `WebNode` interacts with documents, events, elements, and collections of elements, using Blink's string type.
    * **Platform Abstractions (`third_party/blink/public/platform/*`):** `TaskType`, `WebString`. Indicates interaction with platform-level concerns like task scheduling.
    * **Internal Core Blink (`third_party/blink/renderer/core/*`):** These are crucial for understanding the underlying implementation: `accessibility/ax_object_cache.h`, `dom/*`, `editing/*`, `execution_context/*`, `exported/web_plugin_container_impl.h`, `html/*`, `layout/*`, `paint/*`. This points to functionalities related to the DOM structure, event handling, editing, accessibility, plugin management, HTML specifics, layout calculations, and painting.
    * **Platform/Utility (`third_party/blink/renderer/platform/*`):** `bindings/*`, `heap/*`, `wtf/*`. These relate to JavaScript bindings, memory management, and general utilities.

4. **Examine the `WebNode` Class Methods:**  Go through the public methods of the `WebNode` class. For each method, infer its function based on its name and return type. Group related methods:
    * **Construction/Assignment:** `WebNode()`, `WebNode(const WebNode&) `, `operator=`, `~WebNode()`, `Reset()`, `Assign()`. Standard object lifecycle management.
    * **Comparison:** `Equals()`, `LessThan()`. For comparing `WebNode` instances.
    * **Tree Traversal:** `ParentNode()`, `ParentOrShadowHostNode()`, `FirstChild()`, `LastChild()`, `PreviousSibling()`, `NextSibling()`. Navigating the DOM tree.
    * **Information Retrieval:** `NodeValue()`, `GetDocument()`, `IsNull()`, `IsConnected()`, `IsLink()`, `IsTextNode()`, `IsCommentNode()`, `IsElementNode()`, `IsDocumentNode()`, `IsDocumentTypeNode()`. Getting basic properties of the node.
    * **Focus and Editing:** `IsFocusable()`, `IsContentEditable()`, `RootEditableElement()`, `IsInsideFocusableElementOrARIAWidget()`, `Focused()`. Related to user interaction and content manipulation.
    * **JavaScript Interaction:** `ToV8Value()`. Converting the internal representation to a JavaScript object.
    * **Event Handling:** `SimulateClick()`, `AddEventListener()`. Triggering and listening for events.
    * **Element/Node Selection:** `GetElementsByHTMLTagName()`, `QuerySelector()`, `QuerySelectorAll()`, `FindTextInElementWith()`, `FindAllTextNodesMatchingRegex()`. Finding specific nodes within the tree.
    * **Layout and Rendering:** `ScrollingElementIdForTesting()`. Relating to scrolling.
    * **Plugins:** `PluginContainer()`. Accessing plugin information.
    * **Internal Access:** `WebNode(Node*)`, `operator=`, `operator Node*()`, `GetDomNodeId()`, `FromDomNodeId()`. Ways to get the underlying Blink `Node`.

5. **Connect to Web Technologies:** Now, link the observed functionalities to JavaScript, HTML, and CSS:
    * **JavaScript:**  Methods like `ToV8Value`, `AddEventListener`, `QuerySelector`, `QuerySelectorAll`, and the ability to get and set node properties (via `NodeValue` and other accessors) are directly used by JavaScript to interact with the DOM.
    * **HTML:**  The structure represented by `WebNode` directly corresponds to the HTML structure. Methods like `GetElementsByHTMLTagName` and tree traversal are used to navigate and manipulate the HTML.
    * **CSS:**  Methods like `IsFocusable`, `IsContentEditable`, and even the layout information accessed by `ScrollingElementIdForTesting` are influenced by CSS styles. The `UpdateStyleAndLayoutTreeForElement` call in `IsFocusable` is a direct link.

6. **Consider Logic and Examples:** Think about how specific methods are used and construct simple scenarios:
    * **`ParentNode()`:**  Input: a `WebNode` representing a `<p>` element inside a `<div>`. Output: a `WebNode` representing the `<div>`.
    * **`QuerySelector()`:** Input: a `WebNode` representing a document, selector ".my-class". Output: the first `WebNode` representing an element with the class "my-class" (or an empty `WebNode` if none exists).
    * **`AddEventListener()`:**  Show how to attach a click handler using JavaScript-like syntax (even though this is C++ implementing the interface).

7. **Identify Potential Errors:**  Focus on common mistakes when working with the DOM:
    * **Null Nodes:** Accessing properties of a null `WebNode` (e.g., after a `querySelector` returns nothing).
    * **Incorrect Type Assumptions:** Assuming a node is an `WebElement` when it's a text node.
    * **Modifying Live Collections:**  Explain the potential issues with modifying the DOM while iterating over a live `NodeList` or `HTMLCollection`.

8. **Trace User Actions (Debugging Clues):** Think about how a developer might end up looking at this code:
    * **Debugging DOM manipulation:**  Setting breakpoints in JavaScript related to DOM operations.
    * **Investigating rendering issues:** When layout or painting is incorrect, examining the underlying DOM structure is crucial.
    * **Analyzing event handling:**  Tracing the flow of events.
    * **Developing browser extensions or dev tools:** These often interact directly with the DOM structure.

9. **Structure the Answer:** Organize the information logically with clear headings and bullet points. Start with the main functionalities, then connect to web technologies, provide examples, discuss errors, and finally, outline debugging scenarios.

10. **Review and Refine:** Read through the answer to ensure accuracy, clarity, and completeness. Make sure the examples are easy to understand and the explanations are concise. Check for any jargon that might need further clarification. For instance, explicitly mention that `WebNode` is a C++ representation used within the browser engine and is the underlying implementation for JavaScript's DOM API.
文件 `blink/renderer/core/exported/web_node.cc` 是 Chromium Blink 渲染引擎中的一个 C++ 源代码文件。它实现了 `blink::WebNode` 类，这个类是 Blink 引擎向外部（例如，Chromium 的其他部分或者开发者工具）提供的 **DOM 节点 (Node) 的接口**。

**功能列举:**

`WebNode` 类提供了一系列方法来操作和访问底层的 Blink 引擎中的 `Node` 对象。 它的主要功能包括：

* **节点属性访问:**
    * 获取和判断节点的基本属性，例如节点类型 (`IsElementNode`, `IsTextNode`, `IsCommentNode`, `IsDocumentNode`, `IsDocumentTypeNode`)。
    * 获取节点的文本内容 (`NodeValue`)。
    * 判断节点是否连接到文档 (`IsConnected`)。
    * 判断节点是否是链接 (`IsLink`)。
* **DOM 树遍历:**
    * 获取节点的父节点 (`ParentNode`, `ParentOrShadowHostNode`)。
    * 获取节点的第一个子节点 (`FirstChild`)。
    * 获取节点的最后一个子节点 (`LastChild`)。
    * 获取节点的前一个兄弟节点 (`PreviousSibling`)。
    * 获取节点的后一个兄弟节点 (`NextSibling`)。
* **文档访问:**
    * 获取节点所属的文档 (`GetDocument`)。
* **焦点和编辑:**
    * 判断节点是否可以获得焦点 (`IsFocusable`)。
    * 判断节点是否可编辑 (`IsContentEditable`)。
    * 获取根可编辑元素 (`RootEditableElement`)。
    * 判断节点是否在可聚焦元素或 ARIA widget 内部 (`IsInsideFocusableElementOrARIAWidget`)。
    * 判断节点是否拥有焦点 (`Focused`)。
* **事件模拟和监听:**
    * 模拟点击事件 (`SimulateClick`)。
    * 添加事件监听器 (`AddEventListener`)。
* **元素查找:**
    * 通过标签名查找子元素 (`GetElementsByHTMLTagName`)。
    * 使用 CSS 选择器查找子元素 (`QuerySelector`, `QuerySelectorAll`)。
    * 在元素中查找包含特定文本的文本节点 (`FindTextInElementWith`)。
    * 查找匹配正则表达式的所有文本节点 (`FindAllTextNodesMatchingRegex`)。
* **与 JavaScript 交互:**
    * 将 `WebNode` 对象转换为 JavaScript 的 V8 值 (`ToV8Value`)，使得 JavaScript 代码可以操作这个节点。
* **内部状态访问:**
    * 判断节点是否为空 (`IsNull`)。
    * 获取 DOM 节点 ID (`GetDomNodeId`, `FromDomNodeId`)，用于在 Blink 内部唯一标识节点。
* **布局和渲染相关:**
    * 获取滚动元素的 ID (`ScrollingElementIdForTesting`)，主要用于测试。
* **插件容器:**
    * 获取与节点关联的插件容器 (`PluginContainer`)。

**与 JavaScript, HTML, CSS 的关系及举例:**

`WebNode` 是 Blink 引擎暴露给外部操作 DOM 的核心接口，因此它与 JavaScript, HTML, CSS 都有着密切的关系。

* **与 JavaScript 的关系:**
    * **JavaScript 通过 `WebNode` 操作 DOM 结构:**  JavaScript 中的 `document.getElementById()`, `element.querySelector()`, `element.parentNode`, `element.childNodes` 等方法，在 Blink 内部最终会调用 `WebNode` 提供的相应方法。
        * **假设输入 (JavaScript):** `const parent = document.getElementById('myDiv').parentNode;`
        * **输出 (C++ `WebNode`):**  `WebNode::ParentNode()` 方法被调用，返回代表父节点的 `WebNode` 对象。
    * **事件处理:** JavaScript 可以通过 `addEventListener` 注册事件监听器，当事件发生时，Blink 会创建 `WebDOMEvent` 对象，并传递给 JavaScript。`WebNode::AddEventListener`  是实现这一机制的基础。
        * **假设输入 (JavaScript):** `document.getElementById('myButton').addEventListener('click', () => { console.log('Clicked!'); });`
        * **输出 (C++ `WebNode`):** `WebNode::AddEventListener` 被调用，将 JavaScript 的回调函数注册到对应的底层 `Node` 对象上。
    * **属性访问和修改:** JavaScript 可以访问和修改 DOM 元素的属性，例如 `element.innerHTML`, `element.textContent`。 这些操作也会涉及到 `WebNode` 提供的方法。
        * **假设输入 (JavaScript):** `document.getElementById('myParagraph').textContent = 'New Text';`
        * **输出 (C++ `WebNode`):** 可能会涉及到设置底层 `Node` 对象的节点值。
    * **`ToV8Value` 的作用:**  当 JavaScript 代码尝试访问一个 DOM 节点时，Blink 会使用 `ToV8Value` 将底层的 `WebNode` 对象转换为 JavaScript 可以理解和操作的 V8 对象。

* **与 HTML 的关系:**
    * **`WebNode` 代表 HTML 结构:**  每一个 HTML 标签、文本节点、注释等都会在 Blink 内部表示为一个 `Node` 对象，而 `WebNode` 就是这些 `Node` 对象的外部接口。
    * **DOM 树的构建:**  当浏览器解析 HTML 文档时，会创建一个由 `Node` 对象组成的 DOM 树，`WebNode` 提供了遍历这个树的接口。
        * **假设输入 (HTML):** `<div><p>Hello</p></div>`
        * **输出 (C++ `WebNode`):**  会创建代表 `div` 元素和 `p` 元素的 `WebNode` 对象，并且 `p` 元素的 `WebNode` 的 `ParentNode()` 方法会返回 `div` 元素的 `WebNode`。
    * **元素查找:** `GetElementsByHTMLTagName` 等方法允许根据 HTML 标签名查找元素。

* **与 CSS 的关系:**
    * **`IsFocusable` 的影响:**  一个元素是否可以通过 Tab 键获得焦点，受到 CSS 中 `tabindex` 属性的影响。 `WebNode::IsFocusable` 的实现会考虑这些因素，并且可能会触发样式计算 (`UpdateStyleAndLayoutTreeForElement`)。
        * **假设输入 (HTML & CSS):** `<button tabindex="0">Click Me</button>`,  （无特别 CSS 样式影响焦点）。
        * **输出 (C++ `WebNode`):**  对于代表该 button 元素的 `WebNode`，`IsFocusable()` 将返回 `true`。
    * **`IsContentEditable` 的影响:**  CSS 中的 `user-modify` 属性或者 HTML 元素的 `contenteditable` 属性会影响一个元素是否可编辑。 `WebNode::IsContentEditable` 的实现会考虑这些因素，也会触发样式计算。
        * **假设输入 (HTML):** `<div contenteditable="true">Edit me</div>`
        * **输出 (C++ `WebNode`):** 对于代表该 div 元素的 `WebNode`，`IsContentEditable()` 将返回 `true`。

**逻辑推理的假设输入与输出:**

* **假设输入:**  一个代表 `<div><span>Text</span></div>` 中 `span` 元素的 `WebNode` 对象 `span_node`。
* **逻辑推理:**
    * `span_node.ParentNode()` 将会返回一个代表 `div` 元素的 `WebNode` 对象。
    * `span_node.PreviousSibling()` 将会返回一个空的 `WebNode` 对象 (因为 `span` 是 `div` 的第一个也是唯一的子元素)。
    * `span_node.NodeValue()` 将会返回 "Text"。
    * `span_node.GetDocument()` 将会返回包含该 `span` 元素的文档的 `WebDocument` 对象。

**用户或编程常见的使用错误举例说明:**

* **操作空节点:**  在 JavaScript 中使用 `querySelector` 或 `getElementById` 获取元素时，如果元素不存在，会返回 `null`。如果尝试在 `null` 对象上调用 DOM 方法，会导致 JavaScript 错误。在 C++ 层面，这意味着 `WebNode` 对象可能包装了一个空的 `private_` 指针。尝试调用 `private_->parentNode()` 等方法会导致崩溃。
    * **用户操作:** 用户访问了一个 JavaScript 代码尝试操作一个不存在的 DOM 元素的网页。
    * **调试线索:**  在 C++ 代码中，可能会看到 `private_.IsNull()` 为 `true`，或者在解引用 `private_` 指针时发生段错误。
* **类型假设错误:**  开发者可能错误地假设一个 `WebNode` 对象一定是 `WebElement`，并尝试进行类型转换。如果实际的节点是文本节点或注释节点，转换会失败。
    * **编程错误:**  C++ 代码中，错误地使用了 `blink::To<Element>(web_node.ConstUnwrap<Node>())` 而没有进行类型检查。
    * **调试线索:**  检查 `web_node.IsElementNode()` 的返回值，或者在类型转换失败的地方设置断点。
* **忘记处理 `WebNode` 的生命周期:** `WebNode` 对象通常是对底层 Blink 引擎 `Node` 对象的引用。如果底层的 `Node` 对象被销毁，而外部仍然持有 `WebNode` 对象，则访问该 `WebNode` 对象可能会导致问题。
    * **编程错误:**  长时间持有 `WebNode` 对象，而没有考虑 DOM 树的变化。
    * **调试线索:**  使用内存调试工具检查悬挂指针或野指针。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器中加载网页:**  浏览器开始解析 HTML、CSS 和 JavaScript。
2. **JavaScript 代码执行并操作 DOM:**  JavaScript 代码使用 DOM API（例如 `document.getElementById`, `element.addEventListener`）来查找、修改和监听 DOM 元素。
3. **Blink 引擎接收到 JavaScript 的 DOM 操作请求:** JavaScript 引擎 (V8) 通过 Blink 提供的接口调用到 C++ 代码。
4. **`WebNode` 的相关方法被调用:**  例如，当 JavaScript 调用 `element.parentNode` 时，会触发 `WebNode::ParentNode()` 的执行。 当 JavaScript 调用 `element.addEventListener` 时，会触发 `WebNode::AddEventListener()` 的执行。
5. **如果出现错误，开发者可能会需要调试 Blink 引擎的 C++ 代码:**
    * **设置断点:**  开发者可能会在 `web_node.cc` 的相关方法中设置断点，例如在 `WebNode::ParentNode()` 或 `WebNode::AddEventListener()` 中。
    * **查看调用堆栈:**  当程序执行到断点时，可以查看调用堆栈，了解 JavaScript 代码是如何一步步调用到 `WebNode` 的方法的。
    * **检查 `WebNode` 对象的状态:**  查看 `private_` 指针是否为空，节点的类型等信息。

**示例调试场景:**

假设用户报告一个网页上的按钮点击后没有反应。开发者可能会按照以下步骤调试：

1. **检查 JavaScript 代码:** 查看按钮的 `click` 事件监听器是否正确注册，回调函数是否有错误。
2. **检查 HTML 结构:** 确认按钮元素是否存在，ID 是否正确。
3. **如果 JavaScript 代码没有明显错误，开发者可能会怀疑是 Blink 引擎的问题。**
4. **在 `web_node.cc` 中 `WebNode::AddEventListener` 设置断点。**
5. **刷新网页并点击按钮。**
6. **如果断点被命中，说明 JavaScript 的 `addEventListener` 调用成功传递到了 Blink。**
7. **接下来，开发者可能会在 `blink/renderer/core/dom/node.cc` 中与事件分发相关的代码中设置断点，例如 `Node::dispatchEvent`。**
8. **继续执行，查看事件是否被正确分发和处理。**

通过这样的调试流程，开发者可以逐步定位问题是出在 JavaScript 代码、DOM 结构，还是 Blink 引擎的内部实现。 `web_node.cc` 文件作为 Blink 暴露给外部操作 DOM 的接口，是调试过程中非常重要的一个环节。

Prompt: 
```
这是目录为blink/renderer/core/exported/web_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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

#include "third_party/blink/public/web/web_node.h"

#include <ostream>

#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_dom_event.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_element_collection.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_list.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/dom/tag_collection.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_regexp.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

WebNode::WebNode() = default;

WebNode::WebNode(const WebNode& n) {
  Assign(n);
}

WebNode& WebNode::operator=(const WebNode& n) {
  Assign(n);
  return *this;
}

WebNode::~WebNode() {
  Reset();
}

void WebNode::Reset() {
  private_.Reset();
}

void WebNode::Assign(const WebNode& other) {
  private_ = other.private_;
}

bool WebNode::Equals(const WebNode& n) const {
  return private_.Get() == n.private_.Get();
}

bool WebNode::LessThan(const WebNode& n) const {
  return private_.Get() < n.private_.Get();
}

WebNode WebNode::ParentNode() const {
  return WebNode(const_cast<ContainerNode*>(private_->parentNode()));
}

WebNode WebNode::ParentOrShadowHostNode() const {
  return WebNode(
      const_cast<ContainerNode*>(private_->ParentOrShadowHostNode()));
}

WebString WebNode::NodeValue() const {
  return private_->nodeValue();
}

WebDocument WebNode::GetDocument() const {
  return WebDocument(&private_->GetDocument());
}

WebNode WebNode::FirstChild() const {
  return WebNode(private_->firstChild());
}

WebNode WebNode::LastChild() const {
  return WebNode(private_->lastChild());
}

WebNode WebNode::PreviousSibling() const {
  return WebNode(private_->previousSibling());
}

WebNode WebNode::NextSibling() const {
  return WebNode(private_->nextSibling());
}

bool WebNode::IsNull() const {
  return private_.IsNull();
}

bool WebNode::IsConnected() const {
  return private_->isConnected();
}

bool WebNode::IsLink() const {
  return private_->IsLink();
}

bool WebNode::IsTextNode() const {
  return private_->IsTextNode();
}

bool WebNode::IsCommentNode() const {
  return private_->getNodeType() == Node::kCommentNode;
}

bool WebNode::IsFocusable() const {
  auto* element = ::blink::DynamicTo<Element>(private_.Get());
  if (!element)
    return false;
  if (!private_->GetDocument().HaveRenderBlockingResourcesLoaded())
    return false;
  private_->GetDocument().UpdateStyleAndLayoutTreeForElement(
      element, DocumentUpdateReason::kFocus);
  return element->IsFocusable();
}

bool WebNode::IsContentEditable() const {
  private_->GetDocument().UpdateStyleAndLayoutTree();
  return blink::IsEditable(*private_);
}

WebElement WebNode::RootEditableElement() const {
  return blink::RootEditableElement(*private_);
}

bool WebNode::IsInsideFocusableElementOrARIAWidget() const {
  return AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *this->ConstUnwrap<Node>());
}

v8::Local<v8::Value> WebNode::ToV8Value(v8::Isolate* isolate) {
  if (!private_.Get())
    return v8::Local<v8::Value>();
  return ToV8Traits<Node>::ToV8(ScriptState::ForCurrentRealm(isolate),
                                private_.Get());
}

bool WebNode::IsElementNode() const {
  return private_->IsElementNode();
}

bool WebNode::IsDocumentNode() const {
  return private_->IsDocumentNode();
}

bool WebNode::IsDocumentTypeNode() const {
  return private_->getNodeType() == Node::kDocumentTypeNode;
}

void WebNode::SimulateClick() {
  private_->GetExecutionContext()
      ->GetTaskRunner(TaskType::kUserInteraction)
      ->PostTask(FROM_HERE,
                 WTF::BindOnce(&Node::DispatchSimulatedClick,
                               WrapWeakPersistent(private_.Get()), nullptr,
                               SimulatedClickCreationScope::kFromUserAgent));
}

WebElementCollection WebNode::GetElementsByHTMLTagName(
    const WebString& tag) const {
  if (private_->IsContainerNode()) {
    return WebElementCollection(
        blink::To<ContainerNode>(private_.Get())
            ->getElementsByTagNameNS(html_names::xhtmlNamespaceURI, tag));
  }
  return WebElementCollection();
}

WebElement WebNode::QuerySelector(const WebString& selector) const {
  if (!private_->IsContainerNode())
    return WebElement();
  return blink::To<ContainerNode>(private_.Get())
      ->QuerySelector(selector, IGNORE_EXCEPTION_FOR_TESTING);
}

WebVector<WebElement> WebNode::QuerySelectorAll(
    const WebString& selector) const {
  if (!private_->IsContainerNode())
    return WebVector<WebElement>();
  StaticElementList* elements =
      blink::To<ContainerNode>(private_.Get())
          ->QuerySelectorAll(selector, IGNORE_EXCEPTION_FOR_TESTING);
  if (elements) {
    WebVector<WebElement> vector;
    vector.reserve(elements->length());
    for (unsigned i = 0; i < elements->length(); ++i) {
      vector.push_back(elements->item(i));
    }
    return vector;
  }
  return WebVector<WebElement>();
}

WebString WebNode::FindTextInElementWith(
    const WebString& substring,
    base::FunctionRef<bool(const WebString&)> validity_checker) const {
  ContainerNode* container_node =
      blink::DynamicTo<ContainerNode>(private_.Get());
  if (!container_node) {
    return WebString();
  }
  return WebString(container_node->FindTextInElementWith(
      substring, [&](const String& text) { return validity_checker(text); }));
}

WebVector<WebNode> WebNode::FindAllTextNodesMatchingRegex(
    const WebString& regex) const {
  ContainerNode* container_node =
      blink::DynamicTo<ContainerNode>(private_.Get());
  if (!container_node) {
    return WebVector<WebNode>();
  }

  StaticNodeList* nodes = container_node->FindAllTextNodesMatchingRegex(regex);
  if (!nodes) {
    return WebVector<WebNode>();
  }

  WebVector<WebNode> nodes_vector;
  nodes_vector.reserve(nodes->length());
  for (unsigned i = 0; i < nodes->length(); i++) {
    nodes_vector.push_back(nodes->item(i));
  }

  return nodes_vector;
}

bool WebNode::Focused() const {
  return private_->IsFocused();
}

cc::ElementId WebNode::ScrollingElementIdForTesting() const {
  return private_->GetLayoutBox()->GetScrollableArea()->GetScrollElementId();
}

WebPluginContainer* WebNode::PluginContainer() const {
  return private_->GetWebPluginContainer();
}

WebNode::WebNode(Node* node) : private_(node) {
  DCHECK(IsMainThread());
}

WebNode& WebNode::operator=(Node* node) {
  private_ = node;
  return *this;
}

WebNode::operator Node*() const {
  return private_.Get();
}

int WebNode::GetDomNodeId() const {
  return private_.Get()->GetDomNodeId();
}

// static
WebNode WebNode::FromDomNodeId(int dom_node_id) {
  return WebNode(Node::FromDomNodeId(dom_node_id));
}

base::ScopedClosureRunner WebNode::AddEventListener(
    EventType event_type,
    base::RepeatingCallback<void(WebDOMEvent)> handler) {
  class EventListener : public NativeEventListener {
   public:
    EventListener(Node* node,
                  base::RepeatingCallback<void(WebDOMEvent)> handler)
        : node_(node), handler_(std::move(handler)) {}

    void Invoke(ExecutionContext*, Event* event) override {
      handler_.Run(WebDOMEvent(event));
    }

    void AddListener() {
      node_->addEventListener(event_type_name(), this,
                              /*use_capture=*/false);
    }

    void RemoveListener() {
      node_->removeEventListener(event_type_name(), this,
                                 /*use_capture=*/false);
    }

    void Trace(Visitor* visitor) const override {
      NativeEventListener::Trace(visitor);
      visitor->Trace(node_);
    }

   private:
    const AtomicString& event_type_name() {
      switch (event_type_) {
        case EventType::kSelectionchange:
          return event_type_names::kSelectionchange;
      }
      NOTREACHED();
    }

    Member<Node> node_;
    EventType event_type_;
    base::RepeatingCallback<void(WebDOMEvent)> handler_;
  };

  WebPrivatePtrForGC<EventListener> listener =
      MakeGarbageCollected<EventListener>(Unwrap<Node>(), std::move(handler));
  listener->AddListener();
  return base::ScopedClosureRunner(WTF::BindOnce(
      &EventListener::RemoveListener, WrapWeakPersistent(listener.Get())));
}

std::ostream& operator<<(std::ostream& ostream, const WebNode& node) {
  return ostream << node.ConstUnwrap<Node>();
}

}  // namespace blink

"""

```