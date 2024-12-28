Response:
Let's break down the thought process for analyzing the `html_element_stack.cc` file.

1. **Understand the Goal:** The request asks for the functionalities of the file, its relation to HTML/CSS/JS, examples, logical inferences with input/output, and common usage errors.

2. **Identify the Core Abstraction:** The filename `html_element_stack.cc` and the included header `html_element_stack.h` strongly suggest the file implements a stack data structure. The "element" part implies it's a stack of HTML elements.

3. **Analyze Includes:** The `#include` directives provide crucial context:
    * Core DOM elements (`Element`, `HTMLBodyElement`, `HTMLHeadElement`, `HTMLHtmlElement`). This confirms it deals with the DOM structure.
    * HTML form elements (`HTMLFormControlElement`, `HTMLSelectElement`). Indicates handling of form-related elements during parsing.
    * HTML names (`html_names.h`). Shows it's aware of standard HTML tags.
    * MathML and SVG names (`mathml_names.h`, `svg_names.h`). Suggests it handles parsing of these embedded content types within HTML.
    * `RuntimeEnabledFeatures.h`. Points to feature flags that can alter parsing behavior.

4. **Examine the Class Definition:**  The `HTMLElementStack` class is the central entity. Look at its member variables:
    * `root_node_`:  Likely the root of the HTML document (or fragment).
    * `head_element_`, `body_element_`:  Pointers to specific important elements. This hints at special handling for these.
    * `top_`:  The top of the stack (linked list of `HTMLStackItem`).
    * `stack_depth_`: Keeps track of the stack size.

5. **Analyze Public Methods:**  These reveal the primary functionalities:
    * **Push/Pop:**  Fundamental stack operations (`Push`, `Pop`, `PopAll`, `PopUntil`).
    * **Find/Contains:** Methods to query the stack for elements.
    * **Scope Checking (`InScope`, `InListItemScope`, etc.):**  These are crucial for HTML parsing rules. The "scope" concept is central to how browsers understand the context of elements. The various `Is...ScopeMarker` functions are key to implementing these checks.
    * **Special Element Handling (`PushHTMLHeadElement`, `PopHTMLBodyElement`, etc.):**  Confirms special treatment for core HTML structural elements.
    * **Removal (`Remove`, `RemoveHTMLHeadElement`):**  Allows removing elements from the stack (important for error recovery and certain parsing scenarios).
    * **`FurthestBlockForFormattingElement`:** This method's name suggests it's related to how the browser handles formatting elements (like `<b>`, `<i>`) and block-level elements.
    * **`Replace`:** Allows replacing an element on the stack.
    * **Helper Methods (`HasOnlyOneElement`, `SecondElementIsHTMLBodyElement`):** Indicate specific checks needed during parsing.

6. **Analyze Private/Helper Methods:** These provide implementation details:
    * `PushCommon`, `PopCommon`, `RemoveNonTopCommon`:  Core logic for stack manipulation.
    * `IsScopeMarker...` functions: Define the boundaries for scope checks, based on HTML, MathML, and SVG tags.

7. **Connect to HTML/CSS/JS:**
    * **HTML:** The entire class is dedicated to parsing and managing HTML elements. The stack represents the nested structure of the HTML document being parsed.
    * **CSS:** While this class doesn't directly *apply* CSS, the correct parsing of HTML structure (which this class helps with) is *essential* for CSS selectors to work correctly. CSS selectors rely on the DOM tree structure.
    * **JavaScript:** Similarly, this class doesn't execute JS. However, the DOM tree created through the parsing process (which this stack is a part of) is what JavaScript interacts with. Incorrect parsing leads to a wrong DOM, and therefore, JavaScript acting on the wrong elements.

8. **Infer Logical Operations and Examples:**
    * **Stack Operations:** Imagine pushing and popping tags as you encounter them in HTML. The examples in the answer illustrate this.
    * **Scope Checking:**  Think about how the browser determines if a `<td>` tag is inside a `<table>`. The scope checking methods are for this.
    * **Error Handling:** The `PopUntil` methods suggest handling cases where closing tags are missing or misplaced.

9. **Identify Potential Errors:**  Focus on how the stack could be misused or how incorrect HTML input could lead to problems. Examples like unclosed tags, mismatched tags, or incorrect nesting are relevant.

10. **Structure the Answer:** Organize the findings into clear sections as requested: Functionalities, Relationships (with examples), Logical Inferences (with input/output), and Common Errors (with examples). Use clear and concise language.

11. **Review and Refine:** Ensure the answer is accurate, comprehensive, and easy to understand. Double-check the code snippets and examples. For example, make sure the input/output examples for logical inference are valid and illustrative. Ensure the error examples highlight genuine problems that could occur during parsing.

By following these steps, one can systematically analyze the source code and extract the necessary information to answer the prompt effectively. The key is to understand the purpose of the code within the larger context of a web browser's rendering engine.
这个文件 `blink/renderer/core/html/parser/html_element_stack.cc` 实现了 Chromium Blink 引擎中 HTML 解析器的**元素堆栈 (Element Stack)** 功能。 它的核心作用是**维护当前正在解析的 HTML 元素的层级关系**，这对于正确理解和构建 DOM 树至关重要。

以下是它的详细功能列表：

**核心功能：**

1. **存储元素：**  它使用栈数据结构来存储在解析过程中遇到的 HTML 元素。每当遇到一个开始标签时，相应的元素会被推入栈中；遇到结束标签时，相应的元素会从栈中弹出。
2. **维护元素层级关系：**  栈的特性天然地维护了元素的嵌套关系。栈顶的元素总是当前正在处理的最内层元素。
3. **追踪特定元素：**  它维护了指向 `<html>`， `<head>` 和 `<body>` 元素的指针 (`root_node_`, `head_element_`, `body_element_`)，因为这些元素在 HTML 解析过程中扮演着特殊的角色。
4. **支持文档片段：**  它可以处理文档片段的解析，允许解析不完整的 HTML 结构。
5. **实现作用域 (Scope) 检查：**  提供了多种 `InScope` 方法，用于判断特定元素是否在当前上下文中有效。这对于处理一些特殊的 HTML 规则至关重要，例如某些元素只能嵌套在特定的父元素下。
6. **支持错误处理和恢复：**  提供 `PopUntil` 系列方法，允许在遇到错误或需要调整解析状态时，从栈中弹出元素直到达到特定条件。
7. **处理 HTML, MathML 和 SVG 的集成点：** 提供了 `IsMathMLTextIntegrationPoint` 和 `IsHTMLIntegrationPoint` 方法，用于处理 HTML 中嵌入 MathML 和 SVG 的情况。
8. **处理 `<template>` 元素：**  提供了 `HasTemplateInHTMLScope` 方法来检查当前作用域内是否存在 `<template>` 元素。
9. **支持 DOM Parts API:**  如果启用了 DOM Parts API，它会跟踪具有 `parseparts` 属性的元素，并确保正确处理它们。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML：**  `html_element_stack.cc` 的核心功能就是解析 HTML。它直接处理 HTML 标签，并根据 HTML 语法规则维护元素的层级关系。
    * **举例：** 当解析器遇到 `<p><span>文本</span></p>` 时，会先将 `<p>` 元素推入栈，然后将 `<span>` 元素推入栈。遇到 `</span>` 时，`<span>` 被弹出，遇到 `</p>` 时，`<p>` 被弹出。栈的变化直接反映了 HTML 的嵌套结构。
* **CSS：**  虽然这个文件不直接处理 CSS，但它构建的元素层级结构是 CSS 选择器工作的基础。CSS 选择器需要依赖正确的 DOM 树结构才能准确匹配元素并应用样式。
    * **举例：** CSS 规则 `p span { color: red; }` 只有在 `<span>` 元素正确嵌套在 `<p>` 元素下时才能生效。`html_element_stack.cc` 确保了这种嵌套关系的正确性。
* **JavaScript：**  JavaScript 通常通过 DOM API 来操作 HTML 元素。`html_element_stack.cc` 构建的 DOM 树是 JavaScript 操作的对象。解析错误或错误的元素层级关系会导致 JavaScript 代码无法按预期工作。
    * **举例：** 如果由于解析错误，`document.querySelector('p span')` 找不到预期的 `<span>` 元素，可能是因为 `html_element_stack.cc` 在解析过程中没有正确处理 `<p>` 和 `<span>` 的关系。

**逻辑推理示例 (假设输入与输出)：**

**假设输入：** HTML 片段 `<div><ul><li>Item 1` (缺少 `</li>` 和 `</ul>` 闭合标签)

**逻辑推理：**

1. 解析器遇到 `<div>`，将 `<div>` 元素推入栈。
2. 解析器遇到 `<ul>`，将 `<ul>` 元素推入栈。
3. 解析器遇到 `<li>`，将 `<li>` 元素推入栈。
4. 解析器遇到文本 "Item 1"。
5. 由于缺少 `</li>`，根据 HTML 规则，解析器可能需要进行错误处理。`html_element_stack.cc` 中的 `PopUntil` 方法可能会被调用，例如 `PopUntil(HTMLTag::kLi)`，但这会导致弹出 `<li>` 自身，因为栈顶就是 `<li>`。更合理的处理方式是隐式关闭 `<li>`。
6. 由于缺少 `</ul>`，解析器在遇到其他可能触发闭合的标签（或者到达文件末尾）时，需要弹出 `<ul>` 和 `<div>`。  例如，如果接下来遇到 `</div>`， `PopUntilPopped(HTMLTag::kUl)` 会被调用。

**假设输出 (元素堆栈变化)：**

初始状态：空

1. 推入 `<div>`
   栈：[`div`]
2. 推入 `<ul>`
   栈：[`div`, `ul`]
3. 推入 `<li>`
   栈：[`div`, `ul`, `li`]
4. (假设隐式关闭 `<li>`，实际实现可能更复杂)
   栈：[`div`, `ul`]
5. (假设遇到 `</div>`)
   弹出 `<ul>`
   栈：[`div`]
6. 弹出 `<div>`
   栈：[]

**用户或编程常见的使用错误举例：**

1. **未闭合的标签：**  用户在编写 HTML 时忘记闭合标签，例如 `<p>文本`。`html_element_stack.cc` 在解析时需要处理这种情况，可能通过自动闭合或标记错误。
   * **例子：**  输入 `<div><p>内容</div>` (缺少 `</p>`)。解析器在遇到 `</div>` 时，栈顶是 `<p>`，它会尝试找到正确的父元素，并可能隐式关闭 `<p>`。
2. **标签嵌套错误：**  用户错误地嵌套标签，例如 `<b><i>文本</b></i>`。 `html_element_stack.cc` 需要根据 HTML 规范处理这些错误，可能调整元素的层级关系以生成一个有效的 DOM 树。
   * **例子：**  输入 `<b><i>文本</b></i>`。解析器遇到 `<b>` 和 `<i>` 并推入栈。当遇到 `</b>` 时，栈顶是 `<i>`，这会触发错误处理，可能将 `<b>` 弹出，然后再弹出 `<i>`，最后处理 `</i>`。
3. **在不允许的位置使用特定标签：** 某些 HTML 标签只能在特定的父元素下使用。 `html_element_stack.cc` 中的作用域检查方法 (`InScope`) 用于检测并处理这些违规情况。
   * **例子：**  输入 `<table><p>表格内容</p></table>`。`<p>` 标签不能直接作为 `<table>` 的子元素。解析器会检测到这个错误，并可能将 `<p>` 元素放置在 `<table>` 之外或进行其他调整。

总而言之，`html_element_stack.cc` 是 Blink 引擎 HTML 解析器的核心组件，负责维护元素层级关系，处理各种 HTML 语法规则，并为构建正确的 DOM 树奠定基础，这对于网页的正常渲染和 JavaScript 的操作至关重要。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_element_stack.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2010 Google, Inc. All Rights Reserved.
 * Copyright (C) 2011 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY GOOGLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL GOOGLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/parser/html_element_stack.h"

#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/mathml_names.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

using HTMLTag = html_names::HTMLTag;

namespace {

inline bool IsScopeMarkerTag(const HTMLTag& tag) {
  if (tag == HTMLTag::kCaption || tag == HTMLTag::kApplet ||
      tag == HTMLTag::kHTML || tag == HTMLTag::kMarquee ||
      tag == HTMLTag::kObject || tag == HTMLTag::kTable ||
      tag == HTMLTag::kTd || tag == HTMLTag::kTemplate || tag == HTMLTag::kTh) {
    return true;
  }
  if (tag == HTMLTag::kSelect &&
      RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
    return true;
  }
  return false;
}

inline bool IsRootNode(HTMLStackItem* item) {
  return item->IsDocumentFragmentNode() ||
         item->HasTagName(html_names::kHTMLTag);
}

inline bool IsScopeMarkerNonHTML(HTMLStackItem* item) {
  return item->IsDocumentFragmentNode() ||
         item->HasTagName(mathml_names::kMiTag) ||
         item->HasTagName(mathml_names::kMoTag) ||
         item->HasTagName(mathml_names::kMnTag) ||
         item->HasTagName(mathml_names::kMsTag) ||
         item->HasTagName(mathml_names::kMtextTag) ||
         item->HasTagName(mathml_names::kAnnotationXmlTag) ||
         item->HasTagName(svg_names::kForeignObjectTag) ||
         item->HasTagName(svg_names::kDescTag) ||
         item->HasTagName(svg_names::kTitleTag);
}

inline bool IsScopeMarker(HTMLStackItem* item) {
  if (item->IsHTMLNamespace()) {
    return IsScopeMarkerTag(item->GetHTMLTag()) ||
           item->IsDocumentFragmentNode();
  }
  return IsScopeMarkerNonHTML(item);
}

inline bool IsListItemScopeMarker(HTMLStackItem* item) {
  if (item->IsHTMLNamespace()) {
    return IsScopeMarkerTag(item->GetHTMLTag()) ||
           item->IsDocumentFragmentNode() ||
           item->GetHTMLTag() == HTMLTag::kOl ||
           item->GetHTMLTag() == HTMLTag::kUl;
  }
  return IsScopeMarkerNonHTML(item);
}

inline bool IsTableScopeMarker(HTMLStackItem* item) {
  if (item->IsHTMLNamespace()) {
    switch (item->GetHTMLTag()) {
      case HTMLTag::kHTML:
      case HTMLTag::kTable:
      case HTMLTag::kTemplate:
        return true;
      default:
        break;
    }
  }
  return item->IsDocumentFragmentNode();
}

inline bool IsTableBodyScopeMarker(HTMLStackItem* item) {
  if (item->IsHTMLNamespace()) {
    switch (item->GetHTMLTag()) {
      case HTMLTag::kHTML:
      case HTMLTag::kTbody:
      case HTMLTag::kTfoot:
      case HTMLTag::kThead:
      case HTMLTag::kTemplate:
        return true;
      default:
        break;
    }
  }
  return item->IsDocumentFragmentNode();
}

inline bool IsTableRowScopeMarker(HTMLStackItem* item) {
  if (item->IsHTMLNamespace()) {
    switch (item->GetHTMLTag()) {
      case HTMLTag::kHTML:
      case HTMLTag::kTr:
      case HTMLTag::kTemplate:
        return true;
      default:
        break;
    }
  }
  return item->IsDocumentFragmentNode();
}

inline bool IsForeignContentScopeMarker(HTMLStackItem* item) {
  return item->IsInHTMLNamespace() ||
         HTMLElementStack::IsMathMLTextIntegrationPoint(item) ||
         HTMLElementStack::IsHTMLIntegrationPoint(item);
}

inline bool IsButtonScopeMarker(HTMLStackItem* item) {
  if (item->IsHTMLNamespace()) {
    return IsScopeMarkerTag(item->GetHTMLTag()) ||
           item->IsDocumentFragmentNode() ||
           item->GetHTMLTag() == HTMLTag::kButton;
  }
  return IsScopeMarkerNonHTML(item);
}

inline bool IsSelectScopeMarker(HTMLStackItem* item) {
  return !item->HasTagName(html_names::kOptgroupTag) &&
         !item->HasTagName(html_names::kOptionTag);
}

}  // namespace

HTMLElementStack::HTMLElementStack()
    : root_node_(nullptr),
      head_element_(nullptr),
      body_element_(nullptr),
      stack_depth_(0) {}

bool HTMLElementStack::HasOnlyOneElement() const {
  return !TopStackItem()->NextItemInStack();
}

bool HTMLElementStack::SecondElementIsHTMLBodyElement() const {
  // This is used the fragment case of <body> and <frameset> in the "in body"
  // insertion mode.
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tokenization.html#parsing-main-inbody
  DCHECK(root_node_);
  // If we have a body element, it must always be the second element on the
  // stack, as we always start with an html element, and any other element
  // would cause the implicit creation of a body element.
  return !!body_element_;
}

void HTMLElementStack::PopHTMLHeadElement() {
  DCHECK_EQ(Top(), head_element_);
  head_element_ = nullptr;
  PopCommon();
}

void HTMLElementStack::PopHTMLBodyElement() {
  DCHECK_EQ(Top(), body_element_);
  body_element_ = nullptr;
  PopCommon();
}

void HTMLElementStack::PopAll() {
  root_node_ = nullptr;
  head_element_ = nullptr;
  body_element_ = nullptr;
  stack_depth_ = 0;
  while (top_) {
    Node& node = *TopNode();
    auto* element = DynamicTo<Element>(node);
    if (element) {
      element->FinishParsingChildren();
      if (auto* select = DynamicTo<HTMLSelectElement>(node))
        select->SetBlocksFormSubmission(true);
    }
    top_ = top_->ReleaseNextItemInStack();
  }
}

void HTMLElementStack::Pop() {
  DCHECK(TopStackItem()->GetHTMLTag() != HTMLTag::kHead ||
         !TopStackItem()->IsHTMLNamespace());
  PopCommon();
}

void HTMLElementStack::PopUntil(html_names::HTMLTag tag) {
  // kUnknown by itself is not enough to uniquely a tag. This code should only
  // be called with HTMLTags other than kUnknown.
  DCHECK_NE(tag, HTMLTag::kUnknown);
  while (!TopStackItem()->IsHTMLNamespace() ||
         TopStackItem()->GetHTMLTag() != tag) {
    // pop() will ASSERT if a <body>, <head> or <html> will be popped.
    Pop();
  }
}

void HTMLElementStack::PopUntilPopped(html_names::HTMLTag tag) {
  PopUntil(tag);
  Pop();
}

void HTMLElementStack::PopUntilNumberedHeaderElementPopped() {
  while (!TopStackItem()->IsNumberedHeaderElement())
    Pop();
  Pop();
}

void HTMLElementStack::PopUntil(Element* element) {
  while (Top() != element)
    Pop();
}

void HTMLElementStack::PopUntilPopped(Element* element) {
  PopUntil(element);
  Pop();
}

void HTMLElementStack::PopUntilTableScopeMarker() {
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tokenization.html#clear-the-stack-back-to-a-table-context
  while (!IsTableScopeMarker(TopStackItem()))
    Pop();
}

void HTMLElementStack::PopUntilTableBodyScopeMarker() {
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tokenization.html#clear-the-stack-back-to-a-table-body-context
  while (!IsTableBodyScopeMarker(TopStackItem()))
    Pop();
}

void HTMLElementStack::PopUntilTableRowScopeMarker() {
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tokenization.html#clear-the-stack-back-to-a-table-row-context
  while (!IsTableRowScopeMarker(TopStackItem()))
    Pop();
}

// http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#mathml-text-integration-point
bool HTMLElementStack::IsMathMLTextIntegrationPoint(HTMLStackItem* item) {
  if (!item->IsElementNode())
    return false;
  return item->HasTagName(mathml_names::kMiTag) ||
         item->HasTagName(mathml_names::kMoTag) ||
         item->HasTagName(mathml_names::kMnTag) ||
         item->HasTagName(mathml_names::kMsTag) ||
         item->HasTagName(mathml_names::kMtextTag);
}

// http://www.whatwg.org/specs/web-apps/current-work/multipage/tree-construction.html#html-integration-point
bool HTMLElementStack::IsHTMLIntegrationPoint(HTMLStackItem* item) {
  if (!item->IsElementNode())
    return false;
  if (item->HasTagName(mathml_names::kAnnotationXmlTag)) {
    Attribute* encoding_attr =
        item->GetAttributeItem(mathml_names::kEncodingAttr);
    if (encoding_attr) {
      const String& encoding = encoding_attr->Value();
      return EqualIgnoringASCIICase(encoding, "text/html") ||
             EqualIgnoringASCIICase(encoding, "application/xhtml+xml");
    }
    return false;
  }
  return item->HasTagName(svg_names::kForeignObjectTag) ||
         item->HasTagName(svg_names::kDescTag) ||
         item->HasTagName(svg_names::kTitleTag);
}

void HTMLElementStack::PopUntilForeignContentScopeMarker() {
  while (!IsForeignContentScopeMarker(TopStackItem()))
    Pop();
}

void HTMLElementStack::PushRootNode(HTMLStackItem* root_item) {
  DCHECK(root_item->IsDocumentFragmentNode());
  PushRootNodeCommon(root_item);
}

void HTMLElementStack::PushHTMLHtmlElement(HTMLStackItem* item) {
  DCHECK(item->HasTagName(html_names::kHTMLTag));
  PushRootNodeCommon(item);
}

void HTMLElementStack::PushRootNodeCommon(HTMLStackItem* root_item) {
  DCHECK(!top_);
  DCHECK(!root_node_);
  root_node_ = root_item->GetNode();
  PushCommon(root_item);
}

void HTMLElementStack::PushHTMLHeadElement(HTMLStackItem* item) {
  DCHECK(item->HasTagName(html_names::kHeadTag));
  DCHECK(!head_element_);
  head_element_ = item->GetElement();
  PushCommon(item);
}

void HTMLElementStack::PushHTMLBodyElement(HTMLStackItem* item) {
  DCHECK(item->HasTagName(html_names::kBodyTag));
  DCHECK(!body_element_);
  body_element_ = item->GetElement();
  PushCommon(item);
}

void HTMLElementStack::Push(HTMLStackItem* item) {
  DCHECK(!item->HasTagName(html_names::kHTMLTag));
  DCHECK(!item->HasTagName(html_names::kHeadTag));
  DCHECK(!item->HasTagName(html_names::kBodyTag));
  DCHECK(root_node_);
  PushCommon(item);
}

void HTMLElementStack::InsertAbove(HTMLStackItem* item,
                                   HTMLStackItem* item_below) {
  DCHECK(!item->NextItemInStack());
  DCHECK(item);
  DCHECK(item_below);
  DCHECK(top_);
  DCHECK(!item->HasTagName(html_names::kHTMLTag));
  DCHECK(!item->HasTagName(html_names::kHeadTag));
  DCHECK(!item->HasTagName(html_names::kBodyTag));
  DCHECK(root_node_);
  if (item_below == top_) {
    Push(item);
    return;
  }

  for (HTMLStackItem* item_above = top_.Get(); item_above;
       item_above = item_above->NextItemInStack()) {
    if (item_above->NextItemInStack() != item_below) {
      continue;
    }

    stack_depth_++;
    item->SetNextItemInStack(item_above->ReleaseNextItemInStack());
    item_above->SetNextItemInStack(item);
    item->GetElement()->BeginParsingChildren();
    return;
  }
  NOTREACHED();
}

HTMLStackItem* HTMLElementStack::OneBelowTop() const {
  // We should never call this if there are fewer than 2 elements on the stack.
  DCHECK(top_);
  DCHECK(top_->NextItemInStack());
  if (top_->NextItemInStack()->IsElementNode()) {
    return top_->NextItemInStack();
  }
  return nullptr;
}

void HTMLElementStack::RemoveHTMLHeadElement(Element* element) {
  DCHECK_EQ(head_element_, element);
  if (top_->GetElement() == element) {
    PopHTMLHeadElement();
    return;
  }
  head_element_ = nullptr;
  RemoveNonTopCommon(element);
}

void HTMLElementStack::Remove(Element* element) {
  DCHECK(!IsA<HTMLHeadElement>(element));
  if (top_->GetElement() == element) {
    Pop();
    return;
  }
  RemoveNonTopCommon(element);
}

HTMLStackItem* HTMLElementStack::Find(Element* element) const {
  for (HTMLStackItem* item = top_.Get(); item; item = item->NextItemInStack()) {
    if (item->GetNode() == element) {
      return item;
    }
  }
  return nullptr;
}

HTMLStackItem* HTMLElementStack::Topmost(html_names::HTMLTag tag) const {
  // kUnknown by itself is not enough to uniquely a tag. This code should only
  // be called with HTMLTags other than kUnknown.
  DCHECK_NE(tag, HTMLTag::kUnknown);
  for (HTMLStackItem* item = top_.Get(); item; item = item->NextItemInStack()) {
    if (item->IsHTMLNamespace() && tag == item->GetHTMLTag()) {
      return item;
    }
  }
  return nullptr;
}

bool HTMLElementStack::Contains(Element* element) const {
  return !!Find(element);
}

template <bool isMarker(HTMLStackItem*)>
bool InScopeCommon(HTMLStackItem* top, html_names::HTMLTag tag) {
  // kUnknown by itself is not enough to uniquely a tag. This code should only
  // be called with HTMLTags other than kUnknown.
  DCHECK_NE(HTMLTag::kUnknown, tag);
  for (HTMLStackItem* item = top; item; item = item->NextItemInStack()) {
    if (tag == item->GetHTMLTag() && item->IsHTMLNamespace())
      return true;
    if (isMarker(item))
      return false;
  }
  NOTREACHED();  // <html> is always on the stack and is a scope marker.
}

bool HTMLElementStack::HasNumberedHeaderElementInScope() const {
  for (HTMLStackItem* item = top_.Get(); item; item = item->NextItemInStack()) {
    if (item->IsNumberedHeaderElement())
      return true;
    if (IsScopeMarker(item))
      return false;
  }
  NOTREACHED();  // <html> is always on the stack and is a scope marker.
}

bool HTMLElementStack::InScope(Element* target_element) const {
  for (HTMLStackItem* item = top_.Get(); item; item = item->NextItemInStack()) {
    if (item->GetNode() == target_element)
      return true;
    if (IsScopeMarker(item))
      return false;
  }
  NOTREACHED();  // <html> is always on the stack and is a scope marker.
}

bool HTMLElementStack::InScope(html_names::HTMLTag tag) const {
  return InScopeCommon<IsScopeMarker>(top_.Get(), tag);
}

bool HTMLElementStack::InListItemScope(html_names::HTMLTag tag) const {
  return InScopeCommon<IsListItemScopeMarker>(top_.Get(), tag);
}

bool HTMLElementStack::InTableScope(html_names::HTMLTag tag) const {
  return InScopeCommon<IsTableScopeMarker>(top_.Get(), tag);
}

bool HTMLElementStack::InButtonScope(html_names::HTMLTag tag) const {
  return InScopeCommon<IsButtonScopeMarker>(top_.Get(), tag);
}

bool HTMLElementStack::InSelectScope(html_names::HTMLTag tag) const {
  // IsSelectScopeMarker has rigid checks about having <option>s or
  // <optgroup>s between the top and the <select> which don't hold
  // true anymore when permitting other tags when SelectParserRelaxation is
  // enabled.
  if (RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
    return InScopeCommon<IsScopeMarker>(top_.Get(), tag);
  } else {
    return InScopeCommon<IsSelectScopeMarker>(top_.Get(), tag);
  }
}

bool HTMLElementStack::HasTemplateInHTMLScope() const {
  return InScopeCommon<IsRootNode>(top_.Get(), HTMLTag::kTemplate);
}

Element* HTMLElementStack::HtmlElement() const {
  DCHECK(root_node_);
  return To<Element>(root_node_.Get());
}

Element* HTMLElementStack::HeadElement() const {
  DCHECK(head_element_);
  return head_element_.Get();
}

Element* HTMLElementStack::BodyElement() const {
  DCHECK(body_element_);
  return body_element_.Get();
}

ContainerNode* HTMLElementStack::RootNode() const {
  DCHECK(root_node_);
  return root_node_.Get();
}

void HTMLElementStack::PushCommon(HTMLStackItem* item) {
  DCHECK(root_node_);

  if (dom_parts_allowed_state_ == DOMPartsAllowed::kInsideParseParts &&
      item->HasParsePartsAttribute() && body_element_) {
    DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
    ++parse_parts_count_;
  }

  stack_depth_++;
  item->SetNextItemInStack(top_.Release());
  top_ = item;
}

void HTMLElementStack::PopCommon() {
  DCHECK(!TopStackItem()->HasTagName(html_names::kHTMLTag));
  DCHECK(!TopStackItem()->HasTagName(html_names::kHeadTag) || !head_element_);
  DCHECK(!TopStackItem()->HasTagName(html_names::kBodyTag) || !body_element_);
  Top()->FinishParsingChildren();

  DCHECK(!TopStackItem()->HasParsePartsAttribute() || parse_parts_count_ ||
         !body_element_ ||
         dom_parts_allowed_state_ != DOMPartsAllowed::kInsideParseParts);
  if (parse_parts_count_ && TopStackItem()->HasParsePartsAttribute() &&
      dom_parts_allowed_state_ == DOMPartsAllowed::kInsideParseParts) {
    --parse_parts_count_;
  }

  top_ = top_->ReleaseNextItemInStack();

  stack_depth_--;
}

void HTMLElementStack::RemoveNonTopCommon(Element* element) {
  DCHECK(!IsA<HTMLHtmlElement>(element));
  DCHECK(!IsA<HTMLBodyElement>(element));
  DCHECK_NE(Top(), element);
  for (HTMLStackItem* item = top_.Get(); item; item = item->NextItemInStack()) {
    if (item->NextItemInStack()->GetElement() == element) {
      // FIXME: Is it OK to call finishParsingChildren()
      // when the children aren't actually finished?
      element->FinishParsingChildren();

      DCHECK(!TopStackItem()->HasParsePartsAttribute() || parse_parts_count_);
      if (parse_parts_count_ &&
          item->NextItemInStack()->HasParsePartsAttribute() &&
          dom_parts_allowed_state_ == DOMPartsAllowed::kInsideParseParts) {
        --parse_parts_count_;
      }

      item->SetNextItemInStack(
          item->ReleaseNextItemInStack()->ReleaseNextItemInStack());
      stack_depth_--;
      return;
    }
  }
  NOTREACHED();
}

HTMLStackItem* HTMLElementStack::FurthestBlockForFormattingElement(
    Element* formatting_element) const {
  HTMLStackItem* furthest_block = nullptr;
  for (HTMLStackItem* item = top_.Get(); item; item = item->NextItemInStack()) {
    if (item->GetElement() == formatting_element) {
      return furthest_block;
    }
    if (item->IsSpecialNode()) {
      furthest_block = item;
    }
  }
  NOTREACHED();
}

void HTMLElementStack::Replace(HTMLStackItem* old_item,
                               HTMLStackItem* new_item) {
  DCHECK(old_item);
  DCHECK(new_item);
  DCHECK(!new_item->NextItemInStack());
  HTMLStackItem* previous_item = nullptr;
  for (HTMLStackItem* item = top_.Get(); item; item = item->NextItemInStack()) {
    if (item == old_item) {
      if (previous_item) {
        previous_item->ReleaseNextItemInStack();
        previous_item->SetNextItemInStack(new_item);
      }
      new_item->SetNextItemInStack(old_item->ReleaseNextItemInStack());
      return;
    }
    previous_item = item;
  }
  // This should only be called with items in the stack.
  NOTREACHED();
}

void HTMLElementStack::Trace(Visitor* visitor) const {
  visitor->Trace(top_);
  visitor->Trace(root_node_);
  visitor->Trace(head_element_);
  visitor->Trace(body_element_);
}

#ifndef NDEBUG

void HTMLElementStack::Show() {
  for (HTMLStackItem* item = top_.Get(); item; item = item->NextItemInStack()) {
    LOG(INFO) << *item->GetElement();
  }
}

#endif

}  // namespace blink

"""

```