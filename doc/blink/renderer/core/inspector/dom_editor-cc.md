Response:
Let's break down the thought process for analyzing the `dom_editor.cc` file.

**1. Initial Understanding of the File's Purpose:**

The file path `blink/renderer/core/inspector/dom_editor.cc` strongly suggests that this code is part of the Blink rendering engine and is responsible for editing the DOM (Document Object Model) specifically within the context of the browser's developer tools (Inspector). The name `DOMEditor` further reinforces this idea.

**2. Identifying Key Classes and Their Roles:**

A quick scan of the code reveals several inner classes like `RemoveChildAction`, `InsertBeforeAction`, `SetAttributeAction`, etc. These names immediately suggest they represent specific DOM manipulation operations. The base class `InspectorHistory::Action` implies these actions are part of an undo/redo mechanism. The `DOMEditor` class itself seems to be the orchestrator of these actions. The presence of `InspectorHistory` as a member of `DOMEditor` confirms the undo/redo functionality.

**3. Analyzing Individual Action Classes:**

For each action class (e.g., `RemoveChildAction`):

* **Constructor:**  Examine the constructor parameters to understand what information is needed to perform the action (e.g., parent node, the node to remove).
* **`Perform()`:**  This is the core logic for executing the action. Look for DOM manipulation methods like `RemoveChild`, `InsertBefore`, `setAttribute`, `removeAttribute`, `setNodeValue`.
* **`Undo()`:** This is crucial for understanding the undo functionality. It should reverse the effects of `Perform()`.
* **`Redo()`:** This should reapply the action, often mirroring the logic in `Perform()` but potentially leveraging cached state from `Perform()`.
* **`Trace()`:**  This is for Blink's garbage collection and not directly relevant to the *functionality* of the DOM editing, so it can be noted but not deeply analyzed for the core purpose.

**4. Understanding the `DOMEditor` Class:**

* **Constructor:** Note that it takes an `InspectorHistory` object. This establishes the dependency for undo/redo.
* **Public Methods (e.g., `InsertBefore`, `RemoveChild`, `SetAttribute`):** These methods directly correspond to common DOM manipulation operations. Notice that they create the appropriate `Action` object and delegate to the `history_->Perform()` method. This clearly shows the `DOMEditor`'s role in managing the history of DOM edits.
* **Overloaded Methods Returning `protocol::Response`:** The presence of these methods suggests an interface with the browser's DevTools protocol. They perform the same DOM manipulations but wrap the result in a structured response object, including handling potential exceptions. This is the entry point for DevTools commands.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:** The DOM is the fundamental structure that JavaScript interacts with. The `DOMEditor` provides the backend implementation for JavaScript code that modifies the DOM. Think of JavaScript code like `document.getElementById('myDiv').appendChild(newNode)` – `DOMEditor` handles the actual low-level manipulation.
* **HTML:** The initial HTML structure is parsed to create the DOM. The `DOMEditor` allows for dynamic changes to this structure. The `SetOuterHTMLAction` is a direct example of how HTML content can be manipulated.
* **CSS:** While the `DOMEditor` doesn't directly manipulate CSS styles, changes to the DOM structure can trigger CSS recalculations and reflows. Adding or removing elements, changing class names (via attributes), all affect how CSS is applied.

**6. Identifying Potential User/Programming Errors:**

Focus on the `ExceptionState` parameters passed to DOM manipulation methods. Think about what could go wrong during these operations:

* **Invalid Node:** Trying to remove or insert a node that doesn't exist or is detached.
* **Incorrect Parent/Child Relationships:**  Trying to insert a node into an inappropriate parent.
* **Setting Invalid Attribute Values:** While the code doesn't explicitly validate attribute values, the underlying DOM implementation would likely handle this and throw errors.
* **Operating on the Wrong Document:** Although less common with the Inspector, in general DOM manipulation needs to happen on the correct document.

**7. Logical Inference and Examples:**

* **Undo/Redo:**  The structure of the `Action` classes clearly demonstrates the undo/redo mechanism. Imagine a sequence of `InsertBefore` and `RemoveChild` actions. The `Undo()` calls would reverse these actions in the opposite order.
* **`SetOuterHTML` and Patching:** The `SetOuterHTMLAction` uses `DOMPatchSupport`. This hints at a more sophisticated mechanism for updating potentially complex DOM subtrees, potentially using diffing algorithms to optimize changes.

**8. Structuring the Output:**

Organize the findings into clear categories: Functionality, Relationship to Web Technologies, Logical Inference, and Common Errors. Use bullet points and examples to make the information easy to understand. For the web technology relationships, provide specific examples of how the `DOMEditor` enables those technologies. For logical inference, provide simple input/output scenarios to illustrate the concepts.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps the `DOMEditor` directly performs the DOM manipulation.
* **Correction:**  Realized that the `Action` classes encapsulate the actual manipulation, and the `DOMEditor` orchestrates them through the `InspectorHistory`. This clarifies the undo/redo mechanism.
* **Initial thought:** The focus is purely on direct DOM manipulation.
* **Refinement:** Recognized the connection to the DevTools protocol via the overloaded methods, indicating how these actions are initiated from the frontend.

By following these steps, systematically analyzing the code, and connecting it to broader concepts, one can arrive at a comprehensive understanding of the `dom_editor.cc` file's purpose and functionality.
这个文件 `blink/renderer/core/inspector/dom_editor.cc` 是 Chromium Blink 渲染引擎中负责处理与 DOM（文档对象模型）编辑相关的操作的核心组件。它在 Inspector (开发者工具) 的上下文中工作，允许开发者对网页的 DOM 结构进行实时的修改。

以下是它的主要功能和与 Web 技术的关系：

**功能列举:**

1. **提供 DOM 编辑操作的接口:** `DOMEditor` 类提供了一系列方法，用于执行常见的 DOM 修改操作，例如：
    * `InsertBefore`: 在指定节点前插入一个新节点。
    * `RemoveChild`: 移除一个子节点。
    * `SetAttribute`: 设置元素的属性。
    * `RemoveAttribute`: 移除元素的属性。
    * `SetOuterHTML`: 替换节点的外部 HTML。
    * `ReplaceChild`: 替换一个子节点。
    * `SetNodeValue`: 设置节点的值（例如文本节点的文本内容）。

2. **实现 DOM 编辑操作的撤销/重做 (Undo/Redo) 功能:**  通过内部使用 `InspectorHistory` 类，`DOMEditor` 能够记录所有的 DOM 编辑操作，并支持撤销和重做这些操作。每个编辑操作都被封装成一个 `InspectorHistory::Action` 的子类，例如 `RemoveChildAction`，`InsertBeforeAction` 等。

3. **与 Inspector 前端通信:**  `DOMEditor` 提供了一些方法返回 `protocol::Response` 对象，这些方法通常对应于 Inspector 前端发送的 DOM 编辑命令。这些方法会调用底层的 DOM 操作方法，并将结果封装成符合 Inspector 协议的响应返回给前端。

4. **处理 DOM 操作可能产生的异常:**  在执行 DOM 操作时，可能会遇到各种异常情况（例如，尝试移除不存在的节点）。`DOMEditor` 使用 `ExceptionState` 对象来捕获和处理这些异常，并将错误信息返回给 Inspector 前端。

5. **支持 DOM 的细粒度更新 (Patching):**  `SetOuterHTML` 操作背后使用了 `DOMPatchSupport` 类，这意味着它可以更智能地更新 DOM 结构，而不是简单地替换整个子树。这有助于保持页面状态和性能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`DOMEditor` 扮演着 Inspector 前端 (通常由 JavaScript 编写) 和浏览器内核中实际的 DOM 操作之间的桥梁。当开发者在 Inspector 中修改 DOM 时，Inspector 前端会发送相应的命令给后端，`DOMEditor` 接收并执行这些命令。

* **JavaScript:**
    * **关系:**  开发者在浏览器的控制台中或通过 Chrome DevTools 协议发送的 JavaScript 代码经常会操作 DOM。Inspector 的 DOM 面板提供的编辑功能实际上是对这些 JavaScript DOM 操作的一种可视化和交互式的替代。
    * **举例:**  当开发者在 Inspector 的 Elements 面板中选中一个元素并点击 "Edit as HTML" 修改其内容时，Inspector 前端会将修改后的 HTML 发送给后端。`DOMEditor::SetOuterHTML` 方法会被调用，将新的 HTML 解析并应用到 DOM 树上，这与 JavaScript 中使用 `element.outerHTML = '...'` 的效果类似。

* **HTML:**
    * **关系:**  `DOMEditor` 的核心功能就是修改 HTML 结构所对应的 DOM 树。所有的编辑操作最终都会反映在页面的 HTML 结构上。
    * **举例:**  在 Inspector 中右键点击一个元素并选择 "Delete element"，Inspector 前端会调用后端相应的 `RemoveChild` 操作。`DOMEditor::RemoveChild` 方法会被调用，从 DOM 树中移除该元素，这直接影响了页面的 HTML 结构。假设 HTML 如下：
      ```html
      <div id="parent">
        <span>Child</span>
      </div>
      ```
      如果移除 `<span>` 元素，`DOMEditor::RemoveChild` 的输入可能是 `parent_node` 指向 `<div>` 元素，`node` 指向 `<span>` 元素。输出是 `<span>` 元素从 DOM 树中移除。

* **CSS:**
    * **关系:**  虽然 `DOMEditor` 不直接修改 CSS 样式，但对 DOM 结构的修改会触发浏览器的样式重新计算和页面重绘。例如，添加或删除元素、修改元素的 class 或 id 属性都会影响 CSS 规则的应用。
    * **举例:**  在 Inspector 中选中一个元素，然后在 Attributes 面板中添加一个 `class="new-style"` 属性。`DOMEditor::SetAttribute` 方法会被调用，输入是 `element` 指向当前选中的元素，`name` 是 "class"，`value` 是 "new-style"。输出是该元素的 `class` 属性被设置为 "new-style"。这可能导致应用新的 CSS 规则，从而改变元素的显示样式。

**逻辑推理与假设输入输出:**

假设我们在 Inspector 中执行以下操作：

1. **删除一个元素:**
   * **假设输入:**  `DOMEditor::RemoveChild` 方法接收一个指向父节点的 `ContainerNode* parent_node` 和一个指向要删除的子节点的 `Node* node`。 例如，`parent_node` 指向一个 `<div>` 元素，`node` 指向该 `<div>` 内的一个 `<p>` 元素。
   * **输出:**  `DOMEditor` 会调用底层的 DOM 操作，将 `<p>` 元素从其父 `<div>` 元素中移除。如果操作成功，返回 `protocol::Response::Success()`。

2. **在元素前插入一个新元素:**
   * **假设输入:** `DOMEditor::InsertBefore` 方法接收 `ContainerNode* parent_node` (父节点), `Node* node` (要插入的新节点), 和 `Node* anchor_node` (作为插入位置参考的现有子节点)。例如，`parent_node` 指向一个 `<ul>` 元素，`node` 指向新创建的 `<li>` 元素，`anchor_node` 指向 `<ul>` 中已有的一个 `<li>` 元素。
   * **输出:** `DOMEditor` 会将新的 `<li>` 元素插入到 `anchor_node` 之前。如果操作成功，返回 `protocol::Response::Success()`。

3. **修改元素的属性:**
   * **假设输入:** `DOMEditor::SetAttribute` 方法接收 `Element* element` (要修改属性的元素), `const String& name` (属性名), 和 `const String& value` (属性值)。 例如，`element` 指向一个 `<img>` 元素，`name` 是 "src"，`value` 是 "new_image.png"。
   * **输出:** `DOMEditor` 会将该 `<img>` 元素的 `src` 属性值更新为 "new_image.png"。如果操作成功，返回 `protocol::Response::Success()`。

**用户或编程常见的使用错误举例:**

1. **尝试操作不存在的节点:**  如果 Inspector 前端尝试删除一个已经被其他操作删除的节点，`DOMEditor::RemoveChild` 会因为找不到该节点而抛出异常。例如，用户在短时间内连续点击两次 "删除元素" 按钮，可能会发生这种情况。`ExceptionState` 会记录错误信息，并返回一个表示错误的 `protocol::Response`。

2. **插入节点到错误的父节点:**  尝试将一个节点插入到不允许包含该类型子节点的父节点中。例如，尝试将一个 `<div>` 元素直接插入到 `<table>` 元素中，而不是 `<tr>` 或 `<td>` 中。底层的 DOM 操作会抛出异常，`DOMEditor` 会捕获并返回错误信息。

3. **设置无效的属性值:** 虽然 `DOMEditor` 本身不负责验证属性值的有效性，但底层的 DOM 实现可能会拒绝某些无效的属性值。例如，尝试将 `<img>` 元素的 `src` 属性设置为空字符串可能不会立即报错，但可能会导致图片加载失败。某些属性可能有更严格的约束，设置不符合约束的值会导致异常。

4. **在 `SetOuterHTML` 中引入格式错误的 HTML:** 如果用户在 Inspector 中编辑 HTML 并引入了格式错误的标签或结构，`DOMPatchSupport` 在解析 HTML 时可能会失败，导致 `SetOuterHTML` 操作失败并返回错误。

总而言之，`blink/renderer/core/inspector/dom_editor.cc` 是 Blink 渲染引擎中 Inspector 组件的关键部分，它负责接收来自 Inspector 前端的 DOM 编辑指令，并将其转换为对底层 DOM 结构的实际操作，同时提供了撤销/重做、错误处理和与 Web 技术集成的功能。

### 提示词
```
这是目录为blink/renderer/core/inspector/dom_editor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/inspector/dom_editor.h"

#include "base/memory/scoped_refptr.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/inspector/dom_patch_support.h"
#include "third_party/blink/renderer/core/inspector/inspector_history.h"
#include "third_party/blink/renderer/core/inspector/protocol/protocol.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

class DOMEditor::RemoveChildAction final : public InspectorHistory::Action {
 public:
  RemoveChildAction(ContainerNode* parent_node, Node* node)
      : InspectorHistory::Action("RemoveChild"),
        parent_node_(parent_node),
        node_(node) {}
  RemoveChildAction(const RemoveChildAction&) = delete;
  RemoveChildAction& operator=(const RemoveChildAction&) = delete;

  bool Perform(ExceptionState& exception_state) override {
    anchor_node_ = node_->nextSibling();
    return Redo(exception_state);
  }

  bool Undo(ExceptionState& exception_state) override {
    parent_node_->InsertBefore(node_.Get(), anchor_node_.Get(),
                               exception_state);
    return !exception_state.HadException();
  }

  bool Redo(ExceptionState& exception_state) override {
    parent_node_->RemoveChild(node_.Get(), exception_state);
    return !exception_state.HadException();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(parent_node_);
    visitor->Trace(node_);
    visitor->Trace(anchor_node_);
    InspectorHistory::Action::Trace(visitor);
  }

 private:
  Member<ContainerNode> parent_node_;
  Member<Node> node_;
  Member<Node> anchor_node_;
};

class DOMEditor::InsertBeforeAction final : public InspectorHistory::Action {
 public:
  InsertBeforeAction(ContainerNode* parent_node, Node* node, Node* anchor_node)
      : InspectorHistory::Action("InsertBefore"),
        parent_node_(parent_node),
        node_(node),
        anchor_node_(anchor_node) {}
  InsertBeforeAction(const InsertBeforeAction&) = delete;
  InsertBeforeAction& operator=(const InsertBeforeAction&) = delete;

  bool Perform(ExceptionState& exception_state) override {
    if (node_->parentNode()) {
      remove_child_action_ = MakeGarbageCollected<RemoveChildAction>(
          node_->parentNode(), node_.Get());
      if (!remove_child_action_->Perform(exception_state))
        return false;
    }
    parent_node_->InsertBefore(node_.Get(), anchor_node_.Get(),
                               exception_state);
    return !exception_state.HadException();
  }

  bool Undo(ExceptionState& exception_state) override {
    parent_node_->RemoveChild(node_.Get(), exception_state);
    if (exception_state.HadException())
      return false;
    if (remove_child_action_)
      return remove_child_action_->Undo(exception_state);
    return true;
  }

  bool Redo(ExceptionState& exception_state) override {
    if (remove_child_action_ && !remove_child_action_->Redo(exception_state))
      return false;
    parent_node_->InsertBefore(node_.Get(), anchor_node_.Get(),
                               exception_state);
    return !exception_state.HadException();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(parent_node_);
    visitor->Trace(node_);
    visitor->Trace(anchor_node_);
    visitor->Trace(remove_child_action_);
    InspectorHistory::Action::Trace(visitor);
  }

 private:
  Member<ContainerNode> parent_node_;
  Member<Node> node_;
  Member<Node> anchor_node_;
  Member<RemoveChildAction> remove_child_action_;
};

class DOMEditor::RemoveAttributeAction final : public InspectorHistory::Action {
 public:
  RemoveAttributeAction(Element* element, const AtomicString& name)
      : InspectorHistory::Action("RemoveAttribute"),
        element_(element),
        name_(name) {}
  RemoveAttributeAction(const RemoveAttributeAction&) = delete;
  RemoveAttributeAction& operator=(const RemoveAttributeAction&) = delete;

  bool Perform(ExceptionState& exception_state) override {
    value_ = element_->getAttribute(name_);
    return Redo(exception_state);
  }

  bool Undo(ExceptionState& exception_state) override {
    element_->setAttribute(name_, value_, exception_state);
    return true;
  }

  bool Redo(ExceptionState&) override {
    element_->removeAttribute(name_);
    return true;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(element_);
    InspectorHistory::Action::Trace(visitor);
  }

 private:
  Member<Element> element_;
  AtomicString name_;
  AtomicString value_;
};

class DOMEditor::SetAttributeAction final : public InspectorHistory::Action {
 public:
  SetAttributeAction(Element* element,
                     const AtomicString& name,
                     const AtomicString& value)
      : InspectorHistory::Action("SetAttribute"),
        element_(element),
        name_(name),
        value_(value),
        had_attribute_(false) {}
  SetAttributeAction(const SetAttributeAction&) = delete;
  SetAttributeAction& operator=(const SetAttributeAction&) = delete;

  bool Perform(ExceptionState& exception_state) override {
    const AtomicString& value = element_->getAttribute(name_);
    had_attribute_ = !value.IsNull();
    if (had_attribute_)
      old_value_ = value;
    return Redo(exception_state);
  }

  bool Undo(ExceptionState& exception_state) override {
    if (had_attribute_)
      element_->setAttribute(name_, old_value_, exception_state);
    else
      element_->removeAttribute(name_);
    return true;
  }

  bool Redo(ExceptionState& exception_state) override {
    element_->setAttribute(name_, value_, exception_state);
    return true;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(element_);
    InspectorHistory::Action::Trace(visitor);
  }

 private:
  Member<Element> element_;
  AtomicString name_;
  AtomicString value_;
  bool had_attribute_;
  AtomicString old_value_;
};

class DOMEditor::SetOuterHTMLAction final : public InspectorHistory::Action {
 public:
  SetOuterHTMLAction(Node* node, const String& html)
      : InspectorHistory::Action("SetOuterHTML"),
        node_(node),
        next_sibling_(node->nextSibling()),
        html_(html),
        new_node_(nullptr),
        history_(MakeGarbageCollected<InspectorHistory>()),
        dom_editor_(MakeGarbageCollected<DOMEditor>(history_.Get())) {}
  SetOuterHTMLAction(const SetOuterHTMLAction&) = delete;
  SetOuterHTMLAction& operator=(const SetOuterHTMLAction&) = delete;

  bool Perform(ExceptionState& exception_state) override {
    old_html_ = CreateMarkup(node_.Get());
    Document* document = IsA<Document>(node_.Get()) ? To<Document>(node_.Get())
                                                    : node_->ownerDocument();
    DCHECK(document);
    if (!document->documentElement())
      return false;
    DOMPatchSupport dom_patch_support(dom_editor_.Get(), *document);
    new_node_ =
        dom_patch_support.PatchNode(node_.Get(), html_, exception_state);
    return !exception_state.HadException();
  }

  bool Undo(ExceptionState& exception_state) override {
    return history_->Undo(exception_state);
  }

  bool Redo(ExceptionState& exception_state) override {
    return history_->Redo(exception_state);
  }

  Node* NewNode() { return new_node_.Get(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(node_);
    visitor->Trace(next_sibling_);
    visitor->Trace(new_node_);
    visitor->Trace(history_);
    visitor->Trace(dom_editor_);
    InspectorHistory::Action::Trace(visitor);
  }

 private:
  Member<Node> node_;
  Member<Node> next_sibling_;
  String html_;
  String old_html_;
  Member<Node> new_node_;
  Member<InspectorHistory> history_;
  Member<DOMEditor> dom_editor_;
};

class DOMEditor::ReplaceChildNodeAction final
    : public InspectorHistory::Action {
 public:
  ReplaceChildNodeAction(ContainerNode* parent_node,
                         Node* new_node,
                         Node* old_node)
      : InspectorHistory::Action("ReplaceChildNode"),
        parent_node_(parent_node),
        new_node_(new_node),
        old_node_(old_node) {}
  ReplaceChildNodeAction(const ReplaceChildNodeAction&) = delete;
  ReplaceChildNodeAction& operator=(const ReplaceChildNodeAction&) = delete;

  bool Perform(ExceptionState& exception_state) override {
    return Redo(exception_state);
  }

  bool Undo(ExceptionState& exception_state) override {
    parent_node_->ReplaceChild(old_node_, new_node_.Get(), exception_state);
    return !exception_state.HadException();
  }

  bool Redo(ExceptionState& exception_state) override {
    parent_node_->ReplaceChild(new_node_, old_node_.Get(), exception_state);
    return !exception_state.HadException();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(parent_node_);
    visitor->Trace(new_node_);
    visitor->Trace(old_node_);
    InspectorHistory::Action::Trace(visitor);
  }

 private:
  Member<ContainerNode> parent_node_;
  Member<Node> new_node_;
  Member<Node> old_node_;
};

class DOMEditor::SetNodeValueAction final : public InspectorHistory::Action {
 public:
  SetNodeValueAction(Node* node, const String& value)
      : InspectorHistory::Action("SetNodeValue"), node_(node), value_(value) {}
  SetNodeValueAction(const SetNodeValueAction&) = delete;
  SetNodeValueAction& operator=(const SetNodeValueAction&) = delete;

  bool Perform(ExceptionState&) override {
    old_value_ = node_->nodeValue();
    return Redo(IGNORE_EXCEPTION_FOR_TESTING);
  }

  bool Undo(ExceptionState&) override {
    node_->setNodeValue(old_value_);
    return true;
  }

  bool Redo(ExceptionState&) override {
    node_->setNodeValue(value_);
    return true;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(node_);
    InspectorHistory::Action::Trace(visitor);
  }

 private:
  Member<Node> node_;
  String value_;
  String old_value_;
};

DOMEditor::DOMEditor(InspectorHistory* history) : history_(history) {}

bool DOMEditor::InsertBefore(ContainerNode* parent_node,
                             Node* node,
                             Node* anchor_node,
                             ExceptionState& exception_state) {
  return history_->Perform(
      MakeGarbageCollected<InsertBeforeAction>(parent_node, node, anchor_node),
      exception_state);
}

bool DOMEditor::RemoveChild(ContainerNode* parent_node,
                            Node* node,
                            ExceptionState& exception_state) {
  return history_->Perform(
      MakeGarbageCollected<RemoveChildAction>(parent_node, node),
      exception_state);
}

bool DOMEditor::SetAttribute(Element* element,
                             const String& name,
                             const String& value,
                             ExceptionState& exception_state) {
  return history_->Perform(
      MakeGarbageCollected<SetAttributeAction>(element, AtomicString(name),
                                               AtomicString(value)),
      exception_state);
}

bool DOMEditor::RemoveAttribute(Element* element,
                                const String& name,
                                ExceptionState& exception_state) {
  return history_->Perform(
      MakeGarbageCollected<RemoveAttributeAction>(element, AtomicString(name)),
      exception_state);
}

bool DOMEditor::SetOuterHTML(Node* node,
                             const String& html,
                             Node** new_node,
                             ExceptionState& exception_state) {
  SetOuterHTMLAction* action =
      MakeGarbageCollected<SetOuterHTMLAction>(node, html);
  bool result = history_->Perform(action, exception_state);
  if (result)
    *new_node = action->NewNode();
  return result;
}

bool DOMEditor::ReplaceChild(ContainerNode* parent_node,
                             Node* new_node,
                             Node* old_node,
                             ExceptionState& exception_state) {
  return history_->Perform(MakeGarbageCollected<ReplaceChildNodeAction>(
                               parent_node, new_node, old_node),
                           exception_state);
}

bool DOMEditor::SetNodeValue(Node* node,
                             const String& value,
                             ExceptionState& exception_state) {
  return history_->Perform(
      MakeGarbageCollected<SetNodeValueAction>(node, value), exception_state);
}

static protocol::Response ToResponse(
    DummyExceptionStateForTesting& exception_state) {
  if (exception_state.HadException()) {
    String name_prefix = IsDOMExceptionCode(exception_state.Code())
                             ? DOMException::GetErrorName(
                                   exception_state.CodeAs<DOMExceptionCode>()) +
                                   " "
                             : g_empty_string;
    String msg = name_prefix + exception_state.Message();
    return protocol::Response::ServerError(msg.Utf8());
  }
  return protocol::Response::Success();
}

protocol::Response DOMEditor::InsertBefore(ContainerNode* parent_node,
                                           Node* node,
                                           Node* anchor_node) {
  DummyExceptionStateForTesting exception_state;
  InsertBefore(parent_node, node, anchor_node, exception_state);
  return ToResponse(exception_state);
}

protocol::Response DOMEditor::RemoveChild(ContainerNode* parent_node,
                                          Node* node) {
  DummyExceptionStateForTesting exception_state;
  RemoveChild(parent_node, node, exception_state);
  return ToResponse(exception_state);
}

protocol::Response DOMEditor::SetAttribute(Element* element,
                                           const String& name,
                                           const String& value) {
  DummyExceptionStateForTesting exception_state;
  SetAttribute(element, name, value, exception_state);
  return ToResponse(exception_state);
}

protocol::Response DOMEditor::RemoveAttribute(Element* element,
                                              const String& name) {
  DummyExceptionStateForTesting exception_state;
  RemoveAttribute(element, name, exception_state);
  return ToResponse(exception_state);
}

protocol::Response DOMEditor::SetOuterHTML(Node* node,
                                           const String& html,
                                           Node** new_node) {
  DummyExceptionStateForTesting exception_state;
  SetOuterHTML(node, html, new_node, exception_state);
  return ToResponse(exception_state);
}

protocol::Response DOMEditor::SetNodeValue(Node* parent_node,
                                           const String& value) {
  DummyExceptionStateForTesting exception_state;
  SetNodeValue(parent_node, value, exception_state);
  return ToResponse(exception_state);
}

void DOMEditor::Trace(Visitor* visitor) const {
  visitor->Trace(history_);
}

}  // namespace blink
```