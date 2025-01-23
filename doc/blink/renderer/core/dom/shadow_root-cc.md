Response:
Let's break down the thought process for analyzing the `shadow_root.cc` file.

1. **Understand the Goal:** The request asks for the functionality of this specific Chromium Blink file, its relationship to web technologies (JavaScript, HTML, CSS), examples, potential errors, and debugging context.

2. **Identify the Core Abstraction:** The filename `shadow_root.cc` immediately suggests the file is about Shadow DOM. This is the central concept around which the analysis will revolve.

3. **Scan for Key Concepts and Data Structures:** Quickly read through the code, looking for important classes, methods, and member variables. Keywords like `ShadowRootMode`, `SlotAssignment`, `HTMLSlotElement`, `CustomElementRegistry`, `referenceTarget`, and methods like `innerHTML`, `setInnerHTML`, `appendChild`, `querySelector`, etc., are strong indicators of the file's purpose.

4. **Group Functionality:**  Organize the identified concepts into logical categories. In this case, the functions naturally fall into these groups:

    * **Creation and Basic Structure:**  How a `ShadowRoot` is created and its fundamental properties (mode, host, etc.).
    * **Content Management:** How content is added and manipulated within the shadow root (`innerHTML`, `setInnerHTML`, `appendChild`, etc.).
    * **Slotting:** The core Shadow DOM mechanism for distributing content (`SlotAssignment`, `HTMLSlotElement`, `assignedNodes`).
    * **Styling:** How CSS interacts with shadow roots.
    * **Events and Focus:** How events and focus behave within the Shadow DOM.
    * **Custom Elements:** Integration with custom elements.
    * **Reference Target:** A more specialized feature related to accessibility.
    * **Lifecycle:**  How the shadow root is attached and detached from the DOM.

5. **Relate to Web Technologies:**  For each functional group, connect it to corresponding JavaScript, HTML, and CSS concepts.

    * **JavaScript:**  Focus on the APIs exposed to JavaScript, like `attachShadow()`, the `shadowRoot` property, and methods for manipulating the shadow DOM.
    * **HTML:** Identify the relevant HTML elements, like `<slot>`, and the structure of shadow trees.
    * **CSS:** Consider how CSS selectors and inheritance work with shadow boundaries. Think about `:host`, `::slotted`, and how styling is encapsulated.

6. **Develop Examples:** Create simple, illustrative code snippets demonstrating the interaction between the C++ code (implicitly) and the web technologies. These examples should be concise and highlight the core concepts.

7. **Consider Logical Reasoning and Hypothetical Scenarios:**  Think about the internal logic of the functions. For instance, how `SlotAssignment` determines which nodes go into which slots. Create a simple hypothetical input (e.g., specific HTML structure) and predict the output (e.g., how nodes are assigned).

8. **Identify Potential User Errors:**  Think about common mistakes developers might make when working with Shadow DOM. This could involve incorrect slot usage, confusion about styling boundaries, or improper event handling.

9. **Outline Debugging Steps:** Imagine a scenario where a developer encounters an issue related to Shadow DOM. Describe the steps they might take to investigate, potentially leading them to examine the `shadow_root.cc` file (even if indirectly). Emphasize the sequence of user actions that trigger the code.

10. **Refine and Structure:** Organize the information logically. Use headings and bullet points for clarity. Ensure the language is precise and avoids jargon where possible. Review for completeness and accuracy.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the C++ implementation details.
* **Correction:** Shift focus to the *functionality* from a web developer's perspective, and how the C++ code enables that functionality.
* **Initial thought:** Provide very technical explanations of the data structures.
* **Correction:**  Keep the explanation at a higher level, focusing on the *purpose* of the data structures (e.g., `SlotAssignment` manages slot distribution) rather than the low-level implementation.
* **Initial thought:**  Assume the reader has deep knowledge of Chromium internals.
* **Correction:** Explain concepts in a way that is understandable to someone familiar with web development but not necessarily with the Blink rendering engine.
* **Missed initial connection:** Initially might not explicitly connect the `ShadowRoot` class to the JavaScript `ShadowRoot` interface.
* **Correction:** Explicitly state that this C++ class is the implementation behind the JavaScript API.

By following this thought process, breaking down the problem into manageable parts, and constantly relating the C++ code to the broader web ecosystem, we can effectively analyze the functionality of the `shadow_root.cc` file and provide a comprehensive and helpful answer.
好的，我们来分析一下 `blink/renderer/core/dom/shadow_root.cc` 文件的功能。

**文件功能概述:**

`shadow_root.cc` 文件实现了 Chromium Blink 引擎中 `ShadowRoot` 类的逻辑。 `ShadowRoot` 是 Shadow DOM 的核心概念，它代表一个与元素关联的文档片段，这个文档片段定义了该元素的 shadow tree。 简而言之，这个文件负责管理和维护 Shadow DOM 的行为和状态。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ShadowRoot` 是 Web Components 技术中的关键部分，直接与 JavaScript, HTML, 和 CSS 交互：

1. **JavaScript:**
   - **创建 Shadow Root:** JavaScript 通过 `element.attachShadow({mode: 'open' | 'closed'})` 方法来创建一个 `ShadowRoot` 对象，这个操作在 C++ 层最终会涉及到 `ShadowRoot` 类的实例化。
     ```javascript
     const host = document.querySelector('#my-element');
     const shadowRoot = host.attachShadow({ mode: 'open' });
     shadowRoot.innerHTML = '<p>This is in the shadow DOM.</p>';
     ```
   - **访问 Shadow Root:**  对于 `mode: 'open'` 的 shadow root，可以通过 `element.shadowRoot` 属性访问到对应的 `ShadowRoot` 对象。
     ```javascript
     const shadowParagraph = host.shadowRoot.querySelector('p');
     console.log(shadowParagraph.textContent); // 输出 "This is in the shadow DOM."
     ```
   - **操作 Shadow Root 的内容:**  可以使用标准的 DOM API (如 `appendChild`, `querySelector`, `innerHTML` 等) 来操作 shadow root 中的内容。  这些操作最终会调用 `ShadowRoot` 类中相应的方法，例如 `setInnerHTML`。
   - **事件穿透 (Event Retargeting):**  Shadow DOM 实现了事件的重新分发，使得从 shadow tree 内部触发的事件，在 shadow host 外部捕获时，其 `target` 会被调整为 shadow host。 `ShadowRoot` 的逻辑参与了事件穿透的实现。
   - **`slot` 元素和内容分发:**  JavaScript 可以控制 light DOM (host 元素的子节点) 如何被分发到 shadow tree 中的 `<slot>` 元素中。 `ShadowRoot` 类负责管理 slot 的分配和更新。

2. **HTML:**
   - **`<slot>` 元素:**  HTML 中的 `<slot>` 元素是 Shadow DOM 的一个关键特性，它作为 shadow tree 中的占位符，用于插入 host 元素的 light DOM 内容。 `ShadowRoot` 类跟踪和管理这些 `<slot>` 元素，并决定哪些 light DOM 节点应该被渲染到哪个 slot 中。
     ```html
     <my-element>
       <span>This is light DOM content.</span>
     </my-element>

     <template id="my-element-template">
       <p>Shadow content before the slot.</p>
       <slot></slot>
       <p>Shadow content after the slot.</p>
     </template>
     ```
   - **声明式 Shadow DOM (Declarative Shadow DOM):**  虽然 `shadow_root.cc` 主要处理的是通过 JavaScript 创建的 shadow root，但它也与声明式 Shadow DOM 有关联。声明式 Shadow DOM 使用 `<template shadowroot="open|closed">` 标签在 HTML 中声明 shadow root。解析器会创建相应的 `ShadowRoot` 对象。

3. **CSS:**
   - **样式封装:** Shadow DOM 实现了样式的封装，shadow tree 内部的 CSS 规则默认不会影响到外部的 DOM，反之亦然。 `ShadowRoot` 定义了样式作用域的边界。
   - **`:host` 选择器:**  CSS 中可以使用 `:host` 选择器来选中 shadow host 元素自身，这个选择器的作用域限定在 shadow root 内部。
     ```css
     :host {
       display: block;
       border: 1px solid black;
     }
     ```
   - **`::slotted()` 选择器:** CSS 中可以使用 `::slotted()` 选择器来选中分发到 `<slot>` 中的 light DOM 节点。
     ```css
     ::slotted(span) {
       color: blue;
     }
     ```
   - **样式继承:**  某些样式属性会从 shadow host 继承到 shadow tree 中。 `ShadowRoot` 的逻辑参与了样式继承的计算。

**逻辑推理、假设输入与输出:**

假设我们有以下 JavaScript 代码：

```javascript
const host = document.createElement('div');
document.body.appendChild(host);
const shadowRoot = host.attachShadow({ mode: 'open' });
shadowRoot.innerHTML = '<p id="shadow-p">Shadow Paragraph</p>';
const shadowPara = shadowRoot.querySelector('#shadow-p');
```

**假设输入:**
- 调用 `host.attachShadow({ mode: 'open' })`。
- 设置 `shadowRoot.innerHTML` 为包含一个 `<p>` 元素的字符串。
- 调用 `shadowRoot.querySelector('#shadow-p')`。

**逻辑推理 (在 `shadow_root.cc` 层面):**
1. `attachShadow` 方法会创建一个新的 `ShadowRoot` 对象，并将其关联到 `host` 元素。
2. 设置 `innerHTML` 会调用 `ShadowRoot::setInnerHTML`，该方法会解析 HTML 字符串，创建相应的 DOM 节点 (一个 `<p>` 元素)，并将这些节点添加到 `ShadowRoot` 的子节点列表中。 这涉及到 Blink 的 HTML 解析器和 DOM 构建逻辑。
3. `querySelector` 方法会在 `ShadowRoot` 的树结构中查找匹配选择器的元素。它会遍历 shadow tree，找到 `id` 为 "shadow-p" 的 `<p>` 元素。

**预期输出:**
- `shadowRoot` 变量将引用新创建的 `ShadowRoot` 对象。
- `shadowPara` 变量将引用 shadow root 中 `id` 为 "shadow-p" 的 `<p>` 元素。

**用户或编程常见的使用错误及举例说明:**

1. **尝试访问封闭模式 (closed mode) shadow root 的 `shadowRoot` 属性:**
   ```javascript
   const host = document.querySelector('#my-element');
   const shadowRoot = host.attachShadow({ mode: 'closed' });
   console.log(host.shadowRoot); // 输出 null
   ```
   **错误原因:** 当创建 shadow root 时指定 `mode: 'closed'`，则 JavaScript 无法直接访问该 shadow root。这是为了增强封装性。

2. **在错误的上下文中使用 `:host` 或 `::slotted()` 选择器:**
   ```css
   /* 外部 CSS 文件 */
   #my-element {
     :host { /* 错误：:host 只能在 shadow root 内部的样式中使用 */
       border: 1px solid red;
     }
   }
   ```
   **错误原因:**  `:host` 和 `::slotted()` 是 Shadow DOM 特有的 CSS 选择器，只能在 shadow tree 内部的 `<style>` 标签或通过 JavaScript 添加的样式中使用。

3. **混淆 light DOM 和 shadow DOM 的事件目标:**
   ```html
   <my-element>
     <button>Click Me</button>
   </my-element>
   <template id="my-element-template">
     <style>
       button { background-color: yellow; }
     </style>
     <button id="shadow-button">Click Me Too</button>
   </template>
   <script>
     const host = document.querySelector('my-element');
     const shadowRoot = host.attachShadow({ mode: 'open' });
     shadowRoot.appendChild(document.getElementById('my-element-template').content.cloneNode(true));

     host.querySelector('button').addEventListener('click', (event) => {
       console.log('Light DOM button clicked', event.target); // event.target 是 light DOM 的 button
     });

     shadowRoot.querySelector('#shadow-button').addEventListener('click', (event) => {
       console.log('Shadow DOM button clicked', event.target); // event.target 是 shadow DOM 的 button
     });

     host.addEventListener('click', (event) => {
       console.log('Host clicked', event.target); // 点击 shadow button 时，event.target 是 host 元素本身 (事件重定向)
     });
   </script>
   ```
   **错误原因:**  不理解事件在 Shadow DOM 中的传播和目标重定向机制，可能导致事件监听器绑定到错误的元素或错误地假设事件目标。

**用户操作是如何一步步的到达这里，作为调试线索:**

当开发者在浏览器中使用涉及 Shadow DOM 的功能时，Blink 引擎会执行 `shadow_root.cc` 中的代码。以下是一些可能触发相关代码执行的用户操作和调试线索：

1. **页面加载和解析:**
   - **用户操作:** 访问包含使用 Shadow DOM 的 Web Components 的网页。
   - **调试线索:**  Blink 的 HTML 解析器会识别出带有 `attachShadow()` 调用的 JavaScript 代码或者声明式 Shadow DOM 的 `<template>` 标签。这会导致 `ShadowRoot` 对象的创建和关联。可以在 Blink 的解析器和 DOM 构建相关的代码中设置断点。

2. **JavaScript 创建 Shadow Root:**
   - **用户操作:** 网页上的 JavaScript 代码执行 `element.attachShadow()`。
   - **调试线索:**  在 Blink 的 JavaScript 绑定层 (V8 bindings) 可以找到 `attachShadow` 方法的实现，该实现会调用到 C++ 的 `ShadowRoot` 构造函数。可以断点查看 `ShadowRoot` 对象的创建过程。

3. **操作 Shadow Root 的内容:**
   - **用户操作:** JavaScript 代码修改 `shadowRoot.innerHTML` 或使用其他 DOM API 操作 shadow tree。
   - **调试线索:**  在 `ShadowRoot::setInnerHTML`, `ShadowRoot::appendChild` 等方法中设置断点，观察 DOM 节点的添加和修改过程。

4. **样式计算和应用:**
   - **用户操作:** 浏览器渲染页面，需要计算元素的样式，包括 shadow tree 中的元素。
   - **调试线索:**  Blink 的样式引擎会遍历 DOM 树，包括 shadow tree，计算每个元素的样式。可以查看 `StyleResolver` 和相关类的代码，了解样式如何跨越 shadow boundary 应用和继承。

5. **事件分发:**
   - **用户操作:** 用户与 shadow tree 内部的元素交互 (例如点击按钮)。
   - **调试线索:**  Blink 的事件分发系统会处理事件的冒泡和捕获，并进行事件目标重定向。可以在事件分发相关的代码中设置断点，观察事件如何穿透 shadow boundary。

6. **Slot 内容分配:**
   - **用户操作:** 页面包含使用 `<slot>` 元素的 Web Components，light DOM 内容需要被分发到 shadow tree 中。
   - **调试线索:**  `ShadowRoot` 类中的 `SlotAssignment` 负责管理 slot 的分配。可以查看 `SlotAssignment` 相关的代码，了解内容如何被匹配到相应的 slot。

**总结:**

`shadow_root.cc` 文件是 Chromium Blink 引擎中实现 Shadow DOM 机制的关键组件。它负责 `ShadowRoot` 对象的生命周期管理、内容操作、样式封装、事件处理以及 slot 内容分配等核心功能。理解这个文件的功能有助于深入理解 Web Components 和浏览器的渲染机制。 当开发者在使用 Shadow DOM 时遇到问题，可以通过分析 Blink 引擎的源码，特别是 `shadow_root.cc` 及其相关的类，来定位和解决问题。

### 提示词
```
这是目录为blink/renderer/core/dom/shadow_root.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
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

#include "third_party/blink/renderer/core/dom/shadow_root.h"

#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observable_array_css_style_sheet.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_shadow_root_mode.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_slot_assignment_mode.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_list.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/id_target_observer.h"
#include "third_party/blink/renderer/core/dom/id_target_observer_registry.h"
#include "third_party/blink/renderer/core/dom/slot_assignment.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/dom/whitespace_attacher.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/sanitizer/sanitizer_api.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_types_util.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"

namespace blink {

class ReferenceTargetIdObserver : public IdTargetObserver {
 public:
  ReferenceTargetIdObserver(const AtomicString& id, ShadowRoot* root)
      : IdTargetObserver(root->EnsureIdTargetObserverRegistry(), id),
        root_(root) {}

  using IdTargetObserver::Id;

  void Trace(Visitor* visitor) const override {
    visitor->Trace(root_);
    IdTargetObserver::Trace(visitor);
  }

  void IdTargetChanged() override { root_->ReferenceTargetChanged(); }

 private:
  Member<ShadowRoot> root_;
};

struct SameSizeAsShadowRoot : public DocumentFragment,
                              public TreeScope,
                              public ElementRareDataField {
  Member<void*> member[3];
  unsigned flags[1];
};

ASSERT_SIZE(ShadowRoot, SameSizeAsShadowRoot);

ShadowRoot::ShadowRoot(Document& document,
                       ShadowRootMode mode,
                       SlotAssignmentMode assignment_mode)
    : DocumentFragment(nullptr, kCreateShadowRoot),
      TreeScope(*this, document),
      child_shadow_root_count_(0),
      mode_(static_cast<unsigned>(mode)),
      registered_with_parent_shadow_root_(false),
      delegates_focus_(false),
      slot_assignment_mode_(static_cast<unsigned>(assignment_mode)),
      has_focusgroup_attribute_on_descendant_(false) {}

ShadowRoot::~ShadowRoot() = default;

SlotAssignment& ShadowRoot::EnsureSlotAssignment() {
  if (!slot_assignment_)
    slot_assignment_ = MakeGarbageCollected<SlotAssignment>(*this);
  return *slot_assignment_;
}

HTMLSlotElement* ShadowRoot::AssignedSlotFor(const Node& node) {
  if (!slot_assignment_)
    return nullptr;
  return slot_assignment_->FindSlot(node);
}

void ShadowRoot::DidAddSlot(HTMLSlotElement& slot) {
  EnsureSlotAssignment().DidAddSlot(slot);
}

void ShadowRoot::DidChangeHostChildSlotName(const AtomicString& old_value,
                                            const AtomicString& new_value) {
  if (!slot_assignment_)
    return;
  slot_assignment_->DidChangeHostChildSlotName(old_value, new_value);
}

Node* ShadowRoot::Clone(Document&,
                        NodeCloningData&,
                        ContainerNode*,
                        ExceptionState&) const {
  NOTREACHED() << "ShadowRoot nodes are not clonable.";
}

String ShadowRoot::innerHTML() const {
  return CreateMarkup(this, kChildrenOnly);
}

void ShadowRoot::setInnerHTML(const String& html,
                              ExceptionState& exception_state) {
  if (DocumentFragment* fragment = CreateFragmentForInnerOuterHTML(
          html, &host(), kAllowScriptingContent,
          Element::ParseDeclarativeShadowRoots::kDontParse,
          Element::ForceHtml::kDontForce, exception_state)) {
    ReplaceChildrenWithFragment(this, fragment, exception_state);
  }
}

void ShadowRoot::setHTMLUnsafe(const String& html,
                               ExceptionState& exception_state) {
  UseCounter::Count(GetDocument(), WebFeature::kHTMLUnsafeMethods);
  if (DocumentFragment* fragment = CreateFragmentForInnerOuterHTML(
          html, &host(), kAllowScriptingContent,
          Element::ParseDeclarativeShadowRoots::kParse,
          Element::ForceHtml::kDontForce, exception_state)) {
    if (RuntimeEnabledFeatures::SanitizerAPIEnabled()) {
      SanitizerAPI::SanitizeUnsafeInternal(fragment, nullptr, exception_state);
    }
    ReplaceChildrenWithFragment(this, fragment, exception_state);
  }
}

void ShadowRoot::setHTMLUnsafe(const String& html,
                               SetHTMLOptions* options,
                               ExceptionState& exception_state) {
  if (DocumentFragment* fragment = CreateFragmentForInnerOuterHTML(
          html, &host(), kAllowScriptingContent,
          Element::ParseDeclarativeShadowRoots::kParse,
          Element::ForceHtml::kDontForce, exception_state)) {
    if (RuntimeEnabledFeatures::SanitizerAPIEnabled()) {
      SanitizerAPI::SanitizeUnsafeInternal(fragment, options, exception_state);
    }
    ReplaceChildrenWithFragment(this, fragment, exception_state);
  }
}

void ShadowRoot::setHTML(const String& html,
                         SetHTMLOptions* options,
                         ExceptionState& exception_state) {
  if (DocumentFragment* fragment = CreateFragmentForInnerOuterHTML(
          html, &host(), kAllowScriptingContent,
          Element::ParseDeclarativeShadowRoots::kParse,
          Element::ForceHtml::kDontForce, exception_state)) {
    if (RuntimeEnabledFeatures::SanitizerAPIEnabled()) {
      SanitizerAPI::SanitizeSafeInternal(fragment, options, exception_state);
    }
    ReplaceChildrenWithFragment(this, fragment, exception_state);
  }
}

void ShadowRoot::RebuildLayoutTree(WhitespaceAttacher& whitespace_attacher) {
  DCHECK(!NeedsReattachLayoutTree());
  DCHECK(!ChildNeedsReattachLayoutTree());
  RebuildChildrenLayoutTrees(whitespace_attacher);
}

void ShadowRoot::DetachLayoutTree(bool performing_reattach) {
  ContainerNode::DetachLayoutTree(performing_reattach);

  // Shadow host may contain unassigned light dom children that need detaching.
  // Assigned nodes are detached by the slot element.
  for (Node& child : NodeTraversal::ChildrenOf(host())) {
    if (!child.IsSlotable() || child.AssignedSlotWithoutRecalc())
      continue;

    if (child.GetDocument() == GetDocument())
      child.DetachLayoutTree(performing_reattach);
  }
}

Node::InsertionNotificationRequest ShadowRoot::InsertedInto(
    ContainerNode& insertion_point) {
  DocumentFragment::InsertedInto(insertion_point);

  if (!insertion_point.isConnected())
    return kInsertionDone;

  GetDocument().GetStyleEngine().ShadowRootInsertedToDocument(*this);

  GetDocument().GetSlotAssignmentEngine().Connected(*this);

  // FIXME: When parsing <video controls>, InsertedInto() is called many times
  // without invoking RemovedFrom().  For now, we check
  // registered_with_parent_shadow_root. We would like to
  // DCHECK(!registered_with_parent_shadow_root) here.
  // https://bugs.webkit.org/show_bug.cig?id=101316
  if (registered_with_parent_shadow_root_)
    return kInsertionDone;

  if (ShadowRoot* root = host().ContainingShadowRoot()) {
    root->AddChildShadowRoot();
    registered_with_parent_shadow_root_ = true;
  }

  return kInsertionDone;
}

void ShadowRoot::RemovedFrom(ContainerNode& insertion_point) {
  if (insertion_point.isConnected()) {
    if (NeedsSlotAssignmentRecalc())
      GetDocument().GetSlotAssignmentEngine().Disconnected(*this);
    GetDocument().GetStyleEngine().ShadowRootRemovedFromDocument(this);
    if (registered_with_parent_shadow_root_) {
      ShadowRoot* root = host().ContainingShadowRoot();
      if (!root)
        root = insertion_point.ContainingShadowRoot();
      if (root)
        root->RemoveChildShadowRoot();
      registered_with_parent_shadow_root_ = false;
    }
  }

  DocumentFragment::RemovedFrom(insertion_point);
}

V8ShadowRootMode ShadowRoot::mode() const {
  switch (GetMode()) {
    case ShadowRootMode::kOpen:
      return V8ShadowRootMode(V8ShadowRootMode::Enum::kOpen);
    case ShadowRootMode::kClosed:
      return V8ShadowRootMode(V8ShadowRootMode::Enum::kClosed);
    case ShadowRootMode::kUserAgent:
      // UA ShadowRoot should not be exposed to the Web.
      break;
  }
  NOTREACHED();
}

V8SlotAssignmentMode ShadowRoot::slotAssignment() const {
  return V8SlotAssignmentMode(IsManualSlotting()
                                  ? V8SlotAssignmentMode::Enum::kManual
                                  : V8SlotAssignmentMode::Enum::kNamed);
}

void ShadowRoot::SetNeedsAssignmentRecalc() {
  if (!slot_assignment_)
    return;
  return slot_assignment_->SetNeedsAssignmentRecalc();
}

bool ShadowRoot::NeedsSlotAssignmentRecalc() const {
  return slot_assignment_ && slot_assignment_->NeedsAssignmentRecalc();
}

void ShadowRoot::ChildrenChanged(const ChildrenChange& change) {
  ContainerNode::ChildrenChanged(change);

  if (change.type ==
      ChildrenChangeType::kFinishedBuildingDocumentFragmentTree) {
    // No need to call CheckForSiblingStyleChanges() as at this point the
    // node is not in the active document (CheckForSiblingStyleChanges() does
    // nothing when not in the active document).
    DCHECK(!InActiveDocument());
  } else if (change.IsChildElementChange()) {
    Element* changed_element = To<Element>(change.sibling_changed);
    bool removed = change.type == ChildrenChangeType::kElementRemoved;
    CheckForSiblingStyleChanges(
        removed ? kSiblingElementRemoved : kSiblingElementInserted,
        changed_element, change.sibling_before_change,
        change.sibling_after_change);
    GetDocument()
        .GetStyleEngine()
        .ScheduleInvalidationsForHasPseudoAffectedByInsertionOrRemoval(
            this, change.sibling_before_change, *changed_element, removed);
  }

  // In the case of input types like button where the child element is not
  // in a container, we need to explicit adjust directionality.
  if (TextControlElement* text_element =
          HTMLElement::ElementIfAutoDirectionalityFormAssociatedOrNull(
              &host())) {
    text_element->AdjustDirectionalityIfNeededAfterChildrenChanged(change);
  }
}

void ShadowRoot::SetRegistry(CustomElementRegistry* registry) {
  DCHECK(!registry_);
  DCHECK(!registry ||
         RuntimeEnabledFeatures::ScopedCustomElementRegistryEnabled());
  registry_ = registry;
  if (registry) {
    registry->AssociatedWith(GetDocument());
  }
}

void ShadowRoot::setReferenceTarget(const AtomicString& reference_target) {
  if (!RuntimeEnabledFeatures::ShadowRootReferenceTargetEnabled()) {
    return;
  }

  if (referenceTarget() == reference_target) {
    return;
  }

  const Element* previous_reference_target_element = referenceTargetElement();

  if (reference_target_id_observer_) {
    reference_target_id_observer_->Unregister();
  }

  reference_target_id_observer_ =
      reference_target ? MakeGarbageCollected<ReferenceTargetIdObserver>(
                             reference_target, this)
                       : nullptr;

  if (previous_reference_target_element != referenceTargetElement()) {
    ReferenceTargetChanged();
  }
}

const AtomicString& ShadowRoot::referenceTarget() const {
  return reference_target_id_observer_ ? reference_target_id_observer_->Id()
                                       : g_null_atom;
}

Element* ShadowRoot::referenceTargetElement() const {
  return getElementById(referenceTarget());
}

void ShadowRoot::ReferenceTargetChanged() {
  // When this ShadowRoot's reference target changes, notify anything observing
  // the host element's ID, since they may have been referring to the reference
  // target instead.
  if (const auto& id = host().GetIdAttribute()) {
    if (auto* registry = host().GetTreeScope().GetIdTargetObserverRegistry()) {
      registry->NotifyObservers(id);
    }
  }

  if (host().isConnected()) {
    if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
      cache->HandleReferenceTargetChanged(host());
    }
  }
}

void ShadowRoot::Trace(Visitor* visitor) const {
  visitor->Trace(slot_assignment_);
  visitor->Trace(registry_);
  visitor->Trace(reference_target_id_observer_);
  ElementRareDataField::Trace(visitor);
  TreeScope::Trace(visitor);
  DocumentFragment::Trace(visitor);
}

std::ostream& operator<<(std::ostream& ostream, const ShadowRootMode& mode) {
  switch (mode) {
    case ShadowRootMode::kUserAgent:
      ostream << "UserAgent";
      break;
    case ShadowRootMode::kOpen:
      ostream << "Open";
      break;
    case ShadowRootMode::kClosed:
      ostream << "Closed";
      break;
  }
  return ostream;
}

}  // namespace blink
```