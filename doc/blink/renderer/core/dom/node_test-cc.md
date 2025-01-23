Response:
The user is asking for an analysis of the C++ source code file `node_test.cc` from the Chromium Blink rendering engine. I need to explain its purpose, how it relates to web technologies like JavaScript, HTML, and CSS, provide examples of logical reasoning within the tests, illustrate potential user errors, and describe how a user's action might lead to this code being executed.

Here's a breakdown of the tasks:

1. **Purpose of the file:** Identify that this is a unit test file for the `Node` class in Blink.
2. **Relationship to JavaScript, HTML, CSS:** Explain how the tested functionalities of `Node` are exposed or interacted with in the context of these web technologies.
3. **Logical reasoning examples:** Analyze specific test cases for their input, the logic being tested, and the expected output.
4. **Common user/programming errors:**  Infer potential error scenarios that the tests are designed to prevent or detect.
5. **User operations leading to this code:** Describe how typical user interactions in a browser could eventually trigger the execution of the code being tested.
## 对 blink/renderer/core/dom/node_test.cc 的功能分析

`blink/renderer/core/dom/node_test.cc` 是 Chromium Blink 引擎中 `core/dom/node.h` 的单元测试文件。它的主要功能是：

**1. 测试 `blink::Node` 类的各种功能和行为。**  `Node` 类是 DOM（文档对象模型）中所有节点类型的基类，包括元素（Element）、文本节点（Text）、注释节点（Comment）等。这个测试文件旨在验证 `Node` 类及其子类的核心方法和属性的正确性。

**2. 确保 DOM 操作的正确性。**  通过编写各种测试用例，模拟不同的 DOM 操作场景，例如：
    * 节点的创建和添加
    * 节点属性的获取和设置
    * 节点关系的维护（父节点、子节点等）
    * 节点是否可以被选中
    * 与 Shadow DOM 相关的操作
    * 布局树的更新和重新附加
    * 判断节点是否包含特定祖先节点

**3. 回归测试。**  当代码发生修改时，运行这些测试可以确保新的更改没有引入错误，并保持现有功能的稳定性。

**4. 提供代码示例和使用指导。**  虽然不是主要目的，但阅读这些测试用例可以帮助开发者理解 `Node` 类及其相关类的使用方式和预期行为。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`Node` 类是浏览器引擎处理 HTML、CSS 和 JavaScript 的核心部分。它代表了网页的结构和内容，并且可以通过 JavaScript 进行操作。

* **HTML:**  HTML 结构在浏览器中被解析成 DOM 树，每个 HTML 标签都会对应一个或多个 `Node` 对象（例如 `<div>` 对应 `HTMLDivElement`，文本内容对应 `Text` 节点）。测试用例中经常使用 `SetBodyContent` 来设置 HTML 内容，模拟 HTML 结构。
    * **例子:**  `TEST_F(NodeTest, canStartSelection)`  测试用例通过设置包含 `<a>` 和 `<b>` 标签的 HTML 内容，然后验证这两个元素及其子节点是否可以开始文本选择。这直接关系到用户在网页上选择文本的功能。

* **CSS:** CSS 样式规则会影响 DOM 节点的渲染和布局。测试用例中涉及到布局树的重新附加 (`ReattachLayoutTreeForNode`)，这与 CSS 的解析和应用密切相关。例如，节点的 `display` 属性会影响其在布局树中的行为。
    * **例子:** `TEST_F(NodeTest, AttachContext_PreviousInFlow_BlockRoot)` 测试用例创建了一个 `<div>` 元素，并测试在重新附加布局树时，该节点是否被正确处理。`<div>` 默认是块级元素，其布局行为受 CSS 影响。
    * **例子:** 涉及到 `display:contents` 和 `position:absolute/float` 的测试用例，都在验证不同 CSS 属性下，布局树重新附加时的行为。

* **JavaScript:** JavaScript 代码可以通过 DOM API 来访问和操作 DOM 节点。例如，可以使用 `document.getElementById` 获取元素，使用 `appendChild` 添加子节点，使用 `setAttribute` 修改属性。测试用例中模拟了这些操作，例如创建和添加 Shadow DOM (`CreateUserAgentShadowRoot`, `AppendChild`)。
    * **例子:** `TEST_F(NodeTest, customElementState)` 测试用例验证了自定义元素的生命周期状态，这通常与 JavaScript 的自定义元素 API 相关。
    * **例子:**  涉及 Shadow DOM 的测试用例，例如 `TEST_F(NodeTest, canStartSelectionWithShadowDOM)` 和 `TEST_F(NodeTest, MutationOutsideFlatTreeStyleDirty)`，都模拟了 JavaScript 操作 Shadow DOM 的场景。

**逻辑推理的假设输入与输出：**

以下列举几个测试用例中的逻辑推理：

1. **`TEST_F(NodeTest, canStartSelection)`**
    * **假设输入:**  一个包含 `<a>` 和 `<b>` 元素的 DOM 结构。
    * **逻辑推理:** `<a>` 标签通常用于创建链接，其内容本身不可直接选中，而 `<b>` 标签用于加粗文本，其内容可以被选中。
    * **预期输出:**  `one->CanStartSelection()` 返回 `false`，`two->CanStartSelection()` 返回 `true`。

2. **`TEST_F(NodeTest, AttachContext_PreviousInFlow_BlockRoot)`**
    * **假设输入:**  一个 `display` 属性为默认值（block）的 `<div>` 元素。
    * **逻辑推理:**  块级元素在布局树中会占据一行，重新附加布局树时，它本身会成为前一个 in-flow 的布局对象。
    * **预期输出:** `previous_in_flow` 指针指向该 `<div>` 元素的布局对象。

3. **`TEST_F(NodeTest, ContainsChild)`**
    * **假设输入:**  一个父 `<div>` 元素（id="a"）包含一个子 `<div>` 元素（id="b"）。
    * **逻辑推理:**  `contains()` 方法用于判断一个节点是否是另一个节点的后代。
    * **预期输出:** `a->contains(b)` 返回 `true`。

**涉及用户或编程常见的使用错误及举例说明：**

虽然单元测试主要关注代码的正确性，但通过分析测试用例，可以推断出一些用户或编程中可能出现的错误：

* **错误地认为链接文本可以直接被选中。**  `TEST_F(NodeTest, canStartSelection)` 揭示了链接元素的内容节点（Text 节点）是不能直接开始选中的，需要选中链接本身。用户可能会尝试直接拖拽链接文本进行选择，但实际行为是选中整个链接。

* **不理解不同 CSS `display` 属性对布局的影响。**  `AttachContext_PreviousInFlow` 系列的测试用例强调了 `display: contents`、`float` 和 `position: absolute` 等属性对布局树的影响。开发者可能会错误地假设所有节点在重新附加布局树时都会有前一个 in-flow 的兄弟节点。

* **对 Shadow DOM 的包含关系理解错误。**  `TEST_F(NodeTest, ContainsPseudo)`  测试了父节点是否包含其伪元素。初学者可能不清楚伪元素在 DOM 树中的逻辑位置以及如何判断包含关系。

* **在不应该触发样式重算的场景下触发了样式重算。**  `TEST_F(NodeTest, appendChildProcessingInstructionNoStyleRecalc)` 和 `TEST_F(NodeTest, appendChildCommentNoStyleRecalc)` 测试了添加处理指令和注释节点是否会触发不必要的样式重算。开发者可能会错误地认为任何 DOM 操作都会导致样式重算。

**用户操作是如何一步步的到达这里，作为调试线索：**

当用户在浏览器中进行以下操作时，可能会触发与 `Node` 类相关的代码执行，从而使开发者在调试时需要关注 `node_test.cc` 中测试的逻辑：

1. **加载网页:**  当浏览器加载 HTML 页面时，解析器会将 HTML 结构转换为 DOM 树，这个过程会创建大量的 `Node` 对象。如果页面结构复杂或包含 Shadow DOM，那么与 `Node` 相关的逻辑会被频繁调用。
2. **用户交互 (点击、拖拽、输入):**
    * **文本选择:** 用户拖拽鼠标选择文本时，会触发与 `CanStartSelection` 相关的逻辑。如果出现选择异常，开发者可能需要检查 `Node::CanStartSelection` 的实现。
    * **元素属性修改:**  用户通过 JavaScript 修改元素属性（例如 `element.style.color = 'red'`)，会导致样式更新和布局树的可能重构，这会涉及到 `Node` 及其子类的状态更新和布局计算。`MutationOutsideFlatTreeStyleDirty` 测试用例模拟了这种情况。
    * **动态添加/删除元素:**  JavaScript 代码动态地添加或删除 DOM 节点（例如 `element.appendChild(newNode)`），会触发 DOM 树的变更和布局的更新，这些操作都依赖于 `Node` 类的基本功能。 `appendChildProcessingInstructionNoStyleRecalc` 和 `appendChildCommentNoStyleRecalc` 测试了特定情况下的优化。
    * **使用 Shadow DOM 的组件:** 当网页使用了 Web Components 和 Shadow DOM 时，浏览器需要处理 Shadow DOM 的创建、插入、更新和 slot 分配等操作，这些都与 `Node` 类的 Shadow DOM 相关方法紧密相连。 `HasMediaControlAncestor` 和 `UpdateChildDirtyAncestorsOnSlotAssignment` 等测试用例覆盖了这些场景。
3. **CSS 样式计算和应用:** 浏览器的渲染引擎会根据 CSS 规则计算每个节点的最终样式，并将样式信息应用于布局树。这个过程涉及到对 `Node` 对象的样式属性的访问和计算。`AttachContext_PreviousInFlow` 系列的测试用例模拟了布局树重新附加的过程，这与 CSS 样式应用息息相关。

**调试线索:**

当在浏览器开发工具中观察到以下现象时，可能需要查看 `node_test.cc` 中相关的测试用例：

* **DOM 结构异常:**  例如，元素的父子关系不正确，或者节点意外消失。
* **样式应用错误:**  例如，CSS 样式没有正确地应用到某个元素上。
* **JavaScript DOM 操作失败:**  例如，尝试获取或修改节点属性时出错。
* **Shadow DOM 行为异常:**  例如，slot 分配不正确，或者 Shadow DOM 的样式没有正确隔离。
* **性能问题:**  例如，频繁的样式重算或布局重排导致页面卡顿。

通过分析 `node_test.cc` 中的测试用例，开发者可以更好地理解 `Node` 类的预期行为，从而更有效地定位和解决与 DOM 操作相关的 bug。测试用例通常会覆盖各种边界情况和特殊场景，可以帮助开发者发现潜在的问题。

### 提示词
```
这是目录为blink/renderer/core/dom/node_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/node.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_shadow_root_init.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/comment.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder.h"
#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

class FakeMediaControlElement : public HTMLDivElement {
 public:
  FakeMediaControlElement(Document& document) : HTMLDivElement(document) {}

  bool IsMediaControlElement() const override { return true; }
};

class FakeMediaControls : public HTMLDivElement {
 public:
  FakeMediaControls(Document& document) : HTMLDivElement(document) {}

  bool IsMediaControls() const override { return true; }
};

class NodeTest : public EditingTestBase {
 protected:
  LayoutObject* ReattachLayoutTreeForNode(Node& node) {
    node.SetForceReattachLayoutTree();
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
    GetDocument().GetStyleEngine().RecalcStyle();
    Node::AttachContext context;
    context.parent = LayoutTreeBuilderTraversal::ParentLayoutObject(node);
    GetDocument().GetStyleEngine().in_layout_tree_rebuild_ = true;
    node.ReattachLayoutTree(context);
    return context.previous_in_flow;
  }

  // Generate the following DOM structure and return the innermost <div>.
  //  + div#root
  //    + #shadow
  //      + test node
  //      |  + #shadow
  //      |    + div class="test"
  Node* InitializeUserAgentShadowTree(Element* test_node) {
    SetBodyContent("<div id=\"root\"></div>");
    Element* root = GetDocument().getElementById(AtomicString("root"));
    ShadowRoot& first_shadow = root->CreateUserAgentShadowRoot();

    first_shadow.AppendChild(test_node);
    ShadowRoot& second_shadow = test_node->CreateUserAgentShadowRoot();

    auto* class_div = MakeGarbageCollected<HTMLDivElement>(GetDocument());
    class_div->setAttribute(html_names::kClassAttr, AtomicString("test"));
    second_shadow.AppendChild(class_div);
    return class_div;
  }
};

TEST_F(NodeTest, canStartSelection) {
  const char* body_content =
      "<a id=one href='http://www.msn.com'>one</a><b id=two>two</b>";
  SetBodyContent(body_content);
  Node* one = GetDocument().getElementById(AtomicString("one"));
  Node* two = GetDocument().getElementById(AtomicString("two"));

  EXPECT_FALSE(one->CanStartSelection());
  EXPECT_FALSE(one->firstChild()->CanStartSelection());
  EXPECT_TRUE(two->CanStartSelection());
  EXPECT_TRUE(two->firstChild()->CanStartSelection());
}

TEST_F(NodeTest, canStartSelectionWithShadowDOM) {
  const char* body_content = "<div id=host><span id=one>one</span></div>";
  const char* shadow_content = "<a href='http://www.msn.com'><slot></slot></a>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");
  Node* one = GetDocument().getElementById(AtomicString("one"));

  EXPECT_FALSE(one->CanStartSelection());
  EXPECT_FALSE(one->firstChild()->CanStartSelection());
}

TEST_F(NodeTest, customElementState) {
  const char* body_content = "<div id=div></div>";
  SetBodyContent(body_content);
  Element* div = GetDocument().getElementById(AtomicString("div"));
  EXPECT_EQ(CustomElementState::kUncustomized, div->GetCustomElementState());
  EXPECT_TRUE(div->IsDefined());

  div->SetCustomElementState(CustomElementState::kUndefined);
  EXPECT_EQ(CustomElementState::kUndefined, div->GetCustomElementState());
  EXPECT_FALSE(div->IsDefined());

  div->SetCustomElementState(CustomElementState::kCustom);
  EXPECT_EQ(CustomElementState::kCustom, div->GetCustomElementState());
  EXPECT_TRUE(div->IsDefined());
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_TextRoot) {
  SetBodyContent("Text");
  Node* root = GetDocument().body()->firstChild();
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_TRUE(previous_in_flow);
  EXPECT_EQ(root->GetLayoutObject(), previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_InlineRoot) {
  SetBodyContent("<span id=root>Text <span></span></span>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_TRUE(previous_in_flow);
  EXPECT_EQ(root->GetLayoutObject(), previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_BlockRoot) {
  SetBodyContent("<div id=root>Text <span></span></div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_TRUE(previous_in_flow);
  EXPECT_EQ(root->GetLayoutObject(), previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_FloatRoot) {
  SetBodyContent("<div id=root style='float:left'><span></span></div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_FALSE(previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_AbsoluteRoot) {
  SetBodyContent("<div id=root style='position:absolute'><span></span></div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_FALSE(previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_Text) {
  SetBodyContent("<div id=root style='display:contents'>Text</div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_TRUE(previous_in_flow);
  EXPECT_EQ(root->firstChild()->GetLayoutObject(), previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_Inline) {
  SetBodyContent("<div id=root style='display:contents'><span></span></div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_TRUE(previous_in_flow);
  EXPECT_EQ(root->firstChild()->GetLayoutObject(), previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_Block) {
  SetBodyContent("<div id=root style='display:contents'><div></div></div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_TRUE(previous_in_flow);
  EXPECT_EQ(root->firstChild()->GetLayoutObject(), previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_Float) {
  SetBodyContent(
      "<style>"
      "  #root { display:contents }"
      "  .float { float:left }"
      "</style>"
      "<div id=root><div class=float></div></div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_FALSE(previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_AbsolutePositioned) {
  SetBodyContent(
      "<style>"
      "  #root { display:contents }"
      "  .abs { position:absolute }"
      "</style>"
      "<div id=root><div class=abs></div></div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_FALSE(previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_SkipAbsolute) {
  SetBodyContent(
      "<style>"
      "  #root { display:contents }"
      "  .abs { position:absolute }"
      "</style>"
      "<div id=root>"
      "<div class=abs></div><span id=inline></span><div class=abs></div>"
      "</div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* span = GetDocument().getElementById(AtomicString("inline"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_TRUE(previous_in_flow);
  EXPECT_EQ(span->GetLayoutObject(), previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_SkipFloats) {
  SetBodyContent(
      "<style>"
      "  #root { display:contents }"
      "  .float { float:left }"
      "</style>"
      "<div id=root>"
      "<div class=float></div>"
      "<span id=inline></span>"
      "<div class=float></div>"
      "</div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* span = GetDocument().getElementById(AtomicString("inline"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_TRUE(previous_in_flow);
  EXPECT_EQ(span->GetLayoutObject(), previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_InsideDisplayContents) {
  SetBodyContent(
      "<style>"
      "  #root, .contents { display:contents }"
      "  .float { float:left }"
      "</style>"
      "<div id=root>"
      "<span></span><div class=contents><span id=inline></span></div>"
      "</div>");
  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* span = GetDocument().getElementById(AtomicString("inline"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_TRUE(previous_in_flow);
  EXPECT_EQ(span->GetLayoutObject(), previous_in_flow);
}

TEST_F(NodeTest, AttachContext_PreviousInFlow_Slotted) {
  SetBodyContent("<div id=host><span id=inline></span></div>");
  ShadowRoot& shadow_root =
      GetDocument()
          .getElementById(AtomicString("host"))
          ->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(
      "<div id=root style='display:contents'><span></span><slot></slot></div>");
  UpdateAllLifecyclePhasesForTest();

  Element* root = shadow_root.getElementById(AtomicString("root"));
  Element* span = GetDocument().getElementById(AtomicString("inline"));
  LayoutObject* previous_in_flow = ReattachLayoutTreeForNode(*root);

  EXPECT_TRUE(previous_in_flow);
  EXPECT_EQ(span->GetLayoutObject(), previous_in_flow);
}

TEST_F(NodeTest, HasMediaControlAncestor_Fail) {
  auto* node = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  EXPECT_FALSE(node->HasMediaControlAncestor());
  EXPECT_FALSE(InitializeUserAgentShadowTree(node)->HasMediaControlAncestor());
}

TEST_F(NodeTest, HasMediaControlAncestor_MediaControlElement) {
  FakeMediaControlElement* node =
      MakeGarbageCollected<FakeMediaControlElement>(GetDocument());
  EXPECT_TRUE(node->HasMediaControlAncestor());
  EXPECT_TRUE(InitializeUserAgentShadowTree(node)->HasMediaControlAncestor());
}

TEST_F(NodeTest, HasMediaControlAncestor_MediaControls) {
  FakeMediaControls* node =
      MakeGarbageCollected<FakeMediaControls>(GetDocument());
  EXPECT_TRUE(node->HasMediaControlAncestor());
  EXPECT_TRUE(InitializeUserAgentShadowTree(node)->HasMediaControlAncestor());
}

TEST_F(NodeTest, appendChildProcessingInstructionNoStyleRecalc) {
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetDocument().ChildNeedsStyleRecalc());
  auto* pi =
      MakeGarbageCollected<ProcessingInstruction>(GetDocument(), "A", "B");
  GetDocument().body()->appendChild(pi, ASSERT_NO_EXCEPTION);
  EXPECT_FALSE(GetDocument().ChildNeedsStyleRecalc());
}

TEST_F(NodeTest, appendChildCommentNoStyleRecalc) {
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetDocument().ChildNeedsStyleRecalc());
  Comment* comment = Comment::Create(GetDocument(), "comment");
  GetDocument().body()->appendChild(comment, ASSERT_NO_EXCEPTION);
  EXPECT_FALSE(GetDocument().ChildNeedsStyleRecalc());
}

TEST_F(NodeTest, MutationOutsideFlatTreeStyleDirty) {
  SetBodyContent("<div id=host><span id=nonslotted></span></div>");
  GetDocument()
      .getElementById(AtomicString("host"))
      ->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());
  GetDocument()
      .getElementById(AtomicString("nonslotted"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("color:green"));
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());
}

TEST_F(NodeTest, SkipStyleDirtyHostChild) {
  SetBodyContent("<div id=host><span></span></div>");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<div style='display:none'><slot></slot></div>");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());

  // Check that we do not mark an element for style recalc when the element and
  // its flat tree parent are display:none.
  To<Element>(host->firstChild())
      ->setAttribute(html_names::kStyleAttr, AtomicString("color:green"));
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());
}

TEST_F(NodeTest, ContainsChild) {
  SetBodyContent("<div id=a><div id=b></div></div>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  Element* b = GetDocument().getElementById(AtomicString("b"));
  EXPECT_TRUE(a->contains(b));
}

TEST_F(NodeTest, ContainsNoSibling) {
  SetBodyContent("<div id=a></div><div id=b></div>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  Element* b = GetDocument().getElementById(AtomicString("b"));
  EXPECT_FALSE(a->contains(b));
}

TEST_F(NodeTest, ContainsPseudo) {
  SetBodyContent(
      "<style>#a::before{content:'aaa';}</style>"
      "<div id=a></div>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  PseudoElement* pseudo = a->GetPseudoElement(kPseudoIdBefore);
  ASSERT_TRUE(pseudo);
  EXPECT_TRUE(a->contains(pseudo));
}

TEST_F(NodeTest, SkipForceReattachDisplayNone) {
  SetBodyContent("<div id=host><span style='display:none'></span></div>");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<slot name='target'></slot>");
  UpdateAllLifecyclePhasesForTest();

  Element* span = To<Element>(host->firstChild());
  span->setAttribute(html_names::kSlotAttr, AtomicString("target"));
  GetDocument().GetSlotAssignmentEngine().RecalcSlotAssignments();

  // Node::FlatTreeParentChanged for a display:none could trigger style recalc,
  // but we should skip a forced re-attach for nodes with a null ComputedStyle.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  EXPECT_TRUE(span->NeedsStyleRecalc());
  EXPECT_FALSE(span->GetForceReattachLayoutTree());
}

TEST_F(NodeTest, UpdateChildDirtyAncestorsOnSlotAssignment) {
  SetBodyContent("<div id=host><span></span></div>");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(
      "<div><slot></slot></div><div id='child-dirty'><slot "
      "name='target'></slot></div>");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());

  auto* span = To<Element>(host->firstChild());
  auto* ancestor = shadow_root.getElementById(AtomicString("child-dirty"));

  // Make sure the span is dirty before the re-assignment.
  span->setAttribute(html_names::kStyleAttr, AtomicString("color:green"));
  EXPECT_FALSE(ancestor->ChildNeedsStyleRecalc());

  // Re-assign to second slot.
  span->setAttribute(html_names::kSlotAttr, AtomicString("target"));
  GetDocument().GetSlotAssignmentEngine().RecalcSlotAssignments();
  EXPECT_TRUE(ancestor->ChildNeedsStyleRecalc());
}

TEST_F(NodeTest, UpdateChildDirtySlotAfterRemoval) {
  SetBodyContent(R"HTML(
    <div id="host"><span style="display:contents"></span></div>
  )HTML");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<slot></slot>");
  UpdateAllLifecyclePhasesForTest();

  auto* span = To<Element>(host->firstChild());
  auto* slot = shadow_root.firstChild();

  // Make sure the span is dirty, and the slot marked child-dirty before the
  // removal.
  span->setAttribute(html_names::kStyleAttr, AtomicString("color:green"));
  EXPECT_TRUE(span->NeedsStyleRecalc());
  EXPECT_TRUE(slot->ChildNeedsStyleRecalc());
  EXPECT_TRUE(host->ChildNeedsStyleRecalc());
  EXPECT_TRUE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_TRUE(GetDocument().GetStyleEngine().NeedsStyleRecalc());

  // The StyleRecalcRoot is now the span. Removing the span should clear the
  // root and the child-dirty bits on the ancestors.
  span->remove();

  EXPECT_FALSE(slot->ChildNeedsStyleRecalc());
  EXPECT_FALSE(host->ChildNeedsStyleRecalc());
  EXPECT_FALSE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(GetDocument().GetStyleEngine().NeedsStyleRecalc());
}

TEST_F(NodeTest, UpdateChildDirtyAfterSlotRemoval) {
  SetBodyContent(R"HTML(
    <div id="host"><span style="display:contents"></span></div>
  )HTML");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<div><slot></slot></div>");
  UpdateAllLifecyclePhasesForTest();

  auto* span = To<Element>(host->firstChild());
  auto* div = shadow_root.firstChild();
  auto* slot = div->firstChild();

  // Make sure the span is dirty, and the slot marked child-dirty before the
  // removal.
  span->setAttribute(html_names::kStyleAttr, AtomicString("color:green"));
  EXPECT_TRUE(span->NeedsStyleRecalc());
  EXPECT_TRUE(slot->ChildNeedsStyleRecalc());
  EXPECT_TRUE(div->ChildNeedsStyleRecalc());
  EXPECT_TRUE(host->ChildNeedsStyleRecalc());
  EXPECT_TRUE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_TRUE(GetDocument().GetStyleEngine().NeedsStyleRecalc());

  // The StyleRecalcRoot is now the span. Removing the slot breaks the flat
  // tree ancestor chain so that the span is no longer in the flat tree. The
  // StyleRecalcRoot is cleared.
  slot->remove();

  EXPECT_FALSE(div->ChildNeedsStyleRecalc());
  EXPECT_FALSE(host->ChildNeedsStyleRecalc());
  EXPECT_FALSE(GetDocument().body()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(GetDocument().GetStyleEngine().NeedsStyleRecalc());
}

TEST_F(NodeTest, UpdateChildDirtyAfterSlottingDirtyNode) {
  SetBodyContent("<div id=host><span></span></div>");

  auto* host = GetDocument().getElementById(AtomicString("host"));
  auto* span = To<Element>(host->firstChild());

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<div><slot name=x></slot></div>");
  UpdateAllLifecyclePhasesForTest();

  // Make sure the span is style dirty.
  span->setAttribute(html_names::kStyleAttr, AtomicString("color:green"));

  // Assign span to slot.
  span->setAttribute(html_names::kSlotAttr, AtomicString("x"));

  GetDocument().GetSlotAssignmentEngine().RecalcSlotAssignments();

  // Make sure shadow tree div and slot are marked with ChildNeedsStyleRecalc
  // when the dirty span is slotted in.
  EXPECT_TRUE(shadow_root.firstChild()->ChildNeedsStyleRecalc());
  EXPECT_TRUE(shadow_root.firstChild()->firstChild()->ChildNeedsStyleRecalc());
  EXPECT_TRUE(span->NeedsStyleRecalc());

  // This used to call a DCHECK failure. Make sure we don't regress.
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(NodeTest, ReassignStyleDirtyElementIntoSlotOutsideFlatTree) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div>
      <template shadowrootmode="open">
        <div>
          <slot name="s1"></slot>
        </div>
        <div>
          <template shadowrootmode="open">
            <div></div>
          </template>
          <slot name="s2"></slot>
        </div>
      </template>
      <span id="slotted" slot="s1"></span>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* slotted = GetDocument().getElementById(AtomicString("slotted"));

  // Starts with #slotted in the flat tree as a child of the s1 slot.
  EXPECT_TRUE(slotted->GetComputedStyle());

  // Mark #slotted dirty.
  slotted->SetInlineStyleProperty(CSSPropertyID::kColor, "orange");
  EXPECT_TRUE(slotted->NeedsStyleRecalc());

  // Mark for slot reassignment. The #s2 slot is outside the flat tree because
  // its parent is a shadow host with no slots in the shadow tree.
  slotted->setAttribute(html_names::kSlotAttr, AtomicString("s2"));

  // After doing the slot assignment, the #slotted element should no longer be
  // marked dirty and its ComputedStyle should be null because it's outside the
  // flat tree.
  GetDocument().GetSlotAssignmentEngine().RecalcSlotAssignments();
  EXPECT_FALSE(slotted->NeedsStyleRecalc());
  EXPECT_FALSE(slotted->GetComputedStyle());
}

TEST_F(NodeTest, FlatTreeParentForChildDirty) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id="host">
      <template shadowrootmode="open">
        <slot id="slot1">
          <span id="fallback1"></span>
        </slot>
        <slot id="slot2">
          <span id="fallback2"></span>
        </slot>
      </template>
      <div id="slotted"></div>
      <div id="not_slotted" slot="notfound"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* host = GetDocument().getElementById(AtomicString("host"));
  Element* slotted = GetDocument().getElementById(AtomicString("slotted"));
  Element* not_slotted =
      GetDocument().getElementById(AtomicString("not_slotted"));

  ShadowRoot* shadow_root = host->GetShadowRoot();
  Element* slot1 = shadow_root->getElementById(AtomicString("slot1"));
  Element* slot2 = shadow_root->getElementById(AtomicString("slot2"));
  Element* fallback1 = shadow_root->getElementById(AtomicString("fallback1"));
  Element* fallback2 = shadow_root->getElementById(AtomicString("fallback2"));

  EXPECT_EQ(host->FlatTreeParentForChildDirty(), GetDocument().body());
  EXPECT_EQ(slot1->FlatTreeParentForChildDirty(), host);
  EXPECT_EQ(slot2->FlatTreeParentForChildDirty(), host);
  EXPECT_EQ(slotted->FlatTreeParentForChildDirty(), slot1);
  EXPECT_EQ(not_slotted->FlatTreeParentForChildDirty(), nullptr);
  EXPECT_EQ(fallback1->FlatTreeParentForChildDirty(), nullptr);
  EXPECT_EQ(fallback2->FlatTreeParentForChildDirty(), slot2);
}

}  // namespace blink
```