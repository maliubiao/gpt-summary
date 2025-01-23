Response:
My thought process for analyzing the provided code snippet and fulfilling the request goes like this:

1. **Understand the Goal:** The core request is to analyze the `serialization.cc` file in the Blink rendering engine, identify its functionalities, and explain its relationships with web technologies (JavaScript, HTML, CSS), along with examples, potential errors, debugging tips, and a summary of its purpose. The "part 1 of 2" indicates that the focus should be on the functionalities within the provided snippet.

2. **Initial Scan for Keywords and Core Concepts:** I quickly scanned the code for key terms related to serialization, DOM manipulation, HTML, CSS, and editing. Keywords like "Serialization," "Markup," "Fragment," "Element," "Attribute," "Node," "Position," "Range," "Style," "ParseHTML," "ParseXML," "CreateMarkup,"  "DocumentFragment,"  and namespaces like `blink` and `html_names` stand out. These keywords give me a high-level idea of the file's purpose.

3. **Identify Major Functional Areas:** Based on the keywords and the structure of the code (namespaces, classes, and functions), I started to identify distinct functional areas. The main areas I noticed are:
    * **Markup Creation (Serialization):** Functions like `CreateMarkup` (with different overloads for `Position` and `PositionInFlatTree`), `MarkupAccumulator`, and `StyledMarkupSerializer` are clearly involved in converting DOM structures into string representations (HTML markup).
    * **Fragment Creation (Deserialization/Parsing):** Functions like `CreateFragmentFromMarkup`, `CreateFragmentFromMarkupWithContext`, `CreateFragmentFromText`, `CreateFragmentForInnerOuterHTML`, and `CreateContextualFragment` are involved in parsing HTML strings and creating `DocumentFragment` objects.
    * **URL Handling:** The `CompleteURLs` function indicates functionality for resolving relative URLs within a markup string.
    * **Contextual Markup Creation:**  Functions like `HighestAncestorToWrapMarkup` and `CreateFragmentFromMarkupWithContext` deal with creating markup that preserves the surrounding context of a selected range.
    * **Text-Based Fragment Creation:** `CreateFragmentFromText` handles the conversion of plain text into a `DocumentFragment`, considering rich text editing and newline handling.
    * **Helper Functions:**  Several smaller helper functions (e.g., `IsHTMLBlockElement`, `AncestorToRetainStructureAndAppearance`, `PropertyMissingOrEqualToNone`) support the main serialization and deserialization logic.

4. **Analyze Function Signatures and Logic (Superficial):** I examined the function signatures to understand their inputs and outputs. For example, `CreateMarkup` takes start and end positions and `CreateMarkupOptions`, and returns a `String`. `CreateFragmentFromMarkup` takes a `Document`, markup string, base URL, and content policy, and returns a `DocumentFragment`. I didn't delve into the deep implementation details at this stage, just the general purpose.

5. **Relate to Web Technologies:**  Now I started connecting the identified functionalities to JavaScript, HTML, and CSS.
    * **HTML:** The file deals extensively with HTML elements, attributes, and the process of parsing HTML. The creation and manipulation of `DocumentFragment` are fundamental to HTML DOM manipulation in JavaScript.
    * **CSS:** The presence of `CSSPropertyValueSet`, `CSSValue`, and the `StyledMarkupSerializer` indicates that CSS styles are considered during the serialization process. This is important for preserving the visual appearance of copied or serialized content.
    * **JavaScript:** While the `serialization.cc` file itself is C++, its functionalities are exposed to JavaScript through the Blink rendering engine's APIs. JavaScript methods like `innerHTML`, `outerHTML`, `createContextualFragment`, and selection-related APIs would internally utilize the logic implemented in this file.

6. **Consider Examples and Scenarios:** I started thinking about concrete examples of how these functionalities are used in a browser:
    * **Copy/Paste:**  When a user copies content from a webpage, the `CreateMarkup` functions are used to generate the HTML representation of the selected content. Pasting then involves using the fragment creation functions.
    * **`innerHTML`/`outerHTML`:** Setting these JavaScript properties involves parsing a string of HTML using functions like `CreateFragmentForInnerOuterHTML`. Getting these properties involves serialization using `CreateMarkup`.
    * **`createContextualFragment`:** This JavaScript method directly maps to the `CreateContextualFragment` function in the C++ code.

7. **Think About Potential Errors and Debugging:**  I considered common errors related to HTML manipulation and how they might relate to this code:
    * **Invalid HTML:**  Parsing invalid HTML can lead to unexpected results. The `ParseHTML` and `ParseXML` functions might encounter errors.
    * **Incorrect Base URLs:**  Using a wrong base URL can cause links in the serialized markup to be incorrect.
    * **Missing Context:** When using `createContextualFragment`, providing incorrect context can lead to unexpected DOM structures.
    * **Debugging:**  I thought about how a developer might end up debugging this part of the engine (e.g., by setting breakpoints in the C++ code when investigating issues with copy/paste or `innerHTML`).

8. **Logical Inference (Simple Cases):** For straightforward functions, I could make basic assumptions about inputs and outputs. For instance, if `CreateMarkup` is called on a selected `<b>text</b>` element, the output would likely be the string `"<b>text</b>"`. If `CreateFragmentFromMarkup` is given the string `"<div>test</div>"`, it will likely produce a `DocumentFragment` containing a `div` element.

9. **Structure the Output:**  I organized my analysis according to the request's requirements: functionalities, relationships with web technologies (with examples), logical inferences (with input/output), common errors, debugging clues, and a summary.

10. **Refine and Iterate:**  I reviewed my analysis to ensure accuracy and clarity. I made sure to connect the C++ code back to the user's perspective and common web development tasks. I paid attention to the "part 1 of 2" instruction, focusing on the functionality present within the provided snippet. I avoided speculating too much about functionalities that might be in the missing "part 2."

This iterative process of scanning, identifying, analyzing, connecting, and refining helped me break down the code and generate a comprehensive response that addresses all aspects of the request.
```
这是目录为blink/renderer/core/editing/serializers/serialization.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

根据提供的代码片段（`serialization.cc` 的一部分），我们可以归纳出以下主要功能：

**主要功能:**

1. **将DOM结构序列化为HTML标记 (Serialization):**
   -  `CreateMarkup()` 系列函数是核心，负责将DOM树或其一部分转换为HTML字符串。它有多个重载版本，可以处理 `Position` 对象或者 `PositionInFlatTree` 对象，并接受 `CreateMarkupOptions` 来控制序列化的行为（例如，是否包含样式信息，是否解析绝对URL等）。
   -  `MarkupAccumulator` 和 `StyledMarkupSerializer` 是实现序列化的关键辅助类。`StyledMarkupSerializer` 特别关注于在序列化时保留元素的样式信息。
   -  `HighestAncestorToWrapMarkup()` 函数用于确定包裹被序列化内容的最高祖先元素，这对于保留上下文结构很重要。

2. **将HTML标记解析为DOM片段 (Deserialization/Parsing):**
   - `CreateFragmentFromMarkup()` 函数接收HTML字符串，并将其解析为一个 `DocumentFragment` 对象。这允许将一段HTML代码动态插入到现有的DOM树中。
   - `CreateFragmentFromMarkupWithContext()` 函数更进一步，它接收带有标记的HTML字符串，其中标记指示了要提取的片段的起始和结束位置，并能保留周围的上下文结构。
   - `CreateFragmentFromText()` 函数将纯文本转换为 `DocumentFragment`，它会根据上下文处理换行符，并可能创建 `<br>` 或 `<p>` 元素。
   - `CreateFragmentForInnerOuterHTML()` 和 `CreateContextualFragment()` 用于处理 `innerHTML`、`outerHTML` 和 `createContextualFragment` 等 JavaScript API 的底层实现，将 HTML 字符串解析成 DOM 片段。

3. **处理URL:**
   - `CompleteURLs()` 函数用于解析和补全 `DocumentFragment` 中元素的 URL 属性，使其成为绝对 URL，这在复制或移动 DOM 片段时非常重要。

4. **处理纯文本和换行:**
   - `FillContainerFromString()` 函数用于将包含制表符的字符串填充到容器元素中，创建相应的文本节点和 `<span>` 元素来表示制表符。
   - `CreateFragmentFromText()` 能够根据上下文和文本内容智能地处理换行符，生成合适的 HTML 结构。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**
    * **`innerHTML` 和 `outerHTML` 的设置:** 当你在 JavaScript 中设置一个元素的 `innerHTML` 或 `outerHTML` 属性时，Blink 引擎会调用 `CreateFragmentForInnerOuterHTML()` 来解析你提供的 HTML 字符串并创建 `DocumentFragment`。例如：
      ```javascript
      const div = document.createElement('div');
      div.innerHTML = '<span>Hello</span>'; // 这里会调用 `CreateFragmentForInnerOuterHTML()`
      ```
    * **`document.createRange().surroundContents()` 或 selection API 的使用:**  当用户通过拖拽选择或使用键盘选择文本后，JavaScript 可以使用 Range API 来获取选中的内容。Blink 引擎会使用 `CreateMarkup()` 来获取选中文本的 HTML 字符串表示。
    * **`document.createContextualFragment()`:** 这个 JavaScript 方法直接对应于 `CreateContextualFragment()` 函数，用于在特定上下文中解析 HTML 字符串。
      ```javascript
      const div = document.createElement('div');
      const fragment = div.ownerDocument.createRange().createContextualFragment('<b>Bold Text</b>'); // 这里会调用 `CreateContextualFragment()`
      div.appendChild(fragment);
      ```

* **HTML:**
    * **HTML 的解析:**  此文件中的函数负责将 HTML 字符串转换为浏览器可以理解和渲染的 DOM 结构。例如，`CreateFragmentFromMarkup()` 会解析类似 `"<div><p>Text</p></div>"` 的字符串，生成对应的 `HTMLDivElement` 和 `HTMLParagraphElement`。
    * **复制和粘贴:** 当用户在网页上复制内容时，浏览器会调用 `CreateMarkup()` 来序列化选中的 DOM 节点。粘贴时，则会使用 `CreateFragmentFromMarkup()` 或类似函数来解析剪贴板中的 HTML 内容。

* **CSS:**
    * **保留样式信息:**  `StyledMarkupSerializer` 会在序列化时考虑元素的样式信息。例如，如果一个 `<span>` 元素有 `style="color: red;"`，`CreateMarkup()` 在使用合适的选项时会生成包含这个样式信息的 HTML 字符串。
    * **处理 `white-space` 属性:**  `ShouldPreserveNewline()` 函数会检查元素的 `white-space` CSS 属性，以确定是否应该保留换行符，这会影响 `CreateFragmentFromText()` 的行为。

**逻辑推理的假设输入与输出:**

* **假设输入 (CreateMarkup):**  一个包含 `<span>Hello</span>` 元素的 `Range` 对象。
* **输出 (CreateMarkup):**  字符串 `"<span>Hello</span>"`

* **假设输入 (CreateFragmentFromMarkup):**  字符串 `"<p>World</p>"` 和一个 `Document` 对象。
* **输出 (CreateFragmentFromMarkup):**  一个 `DocumentFragment`，其包含一个 `HTMLParagraphElement`，内部包含一个文本节点 "World"。

* **假设输入 (CreateFragmentFromText):**  字符串 `"Line 1\nLine 2"` 和一个可编辑元素的 `EphemeralRange` 对象。
* **输出 (CreateFragmentFromText):**  一个 `DocumentFragment`，可能包含两个 `HTMLParagraphElement`，分别包含 "Line 1" 和 "Line 2"，或者如果上下文支持，可能会使用 `<br>` 元素分隔。

**用户或编程常见的使用错误:**

* **传递不合法的 HTML 给 `innerHTML` 或 `createContextualFragment`:**  例如，传递 `"<div><p>Unclosed div"` 将会导致解析错误，浏览器可能会尝试自动修复，但结果可能不是预期的。
* **忘记设置正确的 base URL:**  在使用 `CreateFragmentFromMarkup()` 解析包含相对 URL 的 HTML 时，如果没有提供正确的 base URL，链接可能会失效。
* **在 XML 文档中使用 `innerHTML` 设置 HTML 特有的标签:**  在 XML 文档中设置 `innerHTML` 为 HTML 标签（如 `<div>`）会导致错误，因为 XML 对标签的格式有更严格的要求。
* **假设 `CreateFragmentFromText()` 会完全按照输入的文本格式生成 HTML:**  `CreateFragmentFromText()` 会根据上下文进行智能处理，例如，在富文本编辑器中，多个换行符可能会被转换为多个段落，而不是简单的 `<br>` 标签。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在网页上进行复制操作 (Ctrl+C 或右键点击 -> 复制):**
   - 浏览器会获取用户选中的内容，这可能涉及到遍历 DOM 树来确定选区的边界。
   - Blink 引擎的编辑模块会调用 `CreateMarkup()` 或相关函数来将选中的 DOM 结构序列化为 HTML 字符串，并存储到剪贴板中。

2. **用户在网页上使用 JavaScript 设置 `innerHTML` 或 `outerHTML`:**
   - JavaScript 代码执行，尝试设置元素的 `innerHTML` 或 `outerHTML` 属性。
   - Blink 引擎会调用 `CreateFragmentForInnerOuterHTML()` 或类似函数，将提供的 HTML 字符串解析为 `DocumentFragment`。
   - 解析过程中，可能会调用底层的 HTML 解析器，并利用此文件中的函数来创建 DOM 节点。

3. **用户在 JavaScript 中调用 `document.createContextualFragment()`:**
   - JavaScript 代码执行，调用 `createContextualFragment()` 方法，并传入 HTML 字符串。
   - Blink 引擎会直接调用 `CreateContextualFragment()` 函数来解析 HTML 字符串并创建 `DocumentFragment`。

4. **开发者使用开发者工具调试:**
   - 当网页出现 HTML 解析或渲染问题时，开发者可能会使用 Chrome 开发者工具的 Elements 面板查看 DOM 结构，或者在 Sources 面板中设置断点，跟踪 JavaScript 代码中涉及到 `innerHTML`、`outerHTML` 或 Range API 的调用。
   - 如果问题涉及到复制粘贴或动态插入 HTML，开发者可能会怀疑是序列化或反序列化过程出了问题，从而查看 Blink 引擎中与 `serialization.cc` 相关的代码。

**功能归纳 (第1部分):**

总的来说，这份代码片段主要负责 **Blink 渲染引擎中 DOM 结构的序列化与反序列化**。它提供了将 DOM 树转换为 HTML 字符串的功能，以及将 HTML 字符串解析为可操作的 DOM 片段的功能。这对于实现诸如复制粘贴、动态更新页面内容以及支持 JavaScript 的 DOM 操作至关重要。它也初步涉及了如何处理文本内容并将其转换为合适的 HTML 结构。由于这是第 1 部分，可能后续的部分会涉及到更复杂的序列化场景，例如处理 Shadow DOM 或 SVG 等。

### 提示词
```
这是目录为blink/renderer/core/editing/serializers/serialization.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2008, 2009, 2010, 2011 Google Inc. All rights reserved.
 * Copyright (C) 2011 Igalia S.L.
 * Copyright (C) 2011 Motorola Mobility. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/serializers/serialization.h"

#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/single_thread_task_runner.h"
#include "base/timer/elapsed_timer.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/single_request_url_loader_factory.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/cdata_section.h"
#include "third_party/blink/renderer/core/dom/child_list_mutation_scope.h"
#include "third_party/blink/renderer/core/dom/comment.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/editing_strategy.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/serializers/markup_accumulator.h"
#include "third_party/blink/renderer/core/editing/serializers/styled_markup_serializer.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_quote_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/parser/html_document_parser_fastpath.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/svg/svg_style_element.h"
#include "third_party/blink/renderer/core/svg/svg_use_element.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/runtime_call_stats.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_client.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

class AttributeChange {
  DISALLOW_NEW();

 public:
  AttributeChange() : name_(QualifiedName::Null()) {}

  AttributeChange(Element* element,
                  const QualifiedName& name,
                  const String& value)
      : element_(element), name_(name), value_(value) {}

  void Apply() { element_->setAttribute(name_, AtomicString(value_)); }

  void Trace(Visitor* visitor) const { visitor->Trace(element_); }

 private:
  Member<Element> element_;
  QualifiedName name_;
  String value_;
};

}  // namespace blink

WTF_ALLOW_INIT_WITH_MEM_FUNCTIONS(blink::AttributeChange)

namespace blink {

namespace {

class EmptyLocalFrameClientWithFailingLoaderFactory final
    : public EmptyLocalFrameClient {
 public:
  scoped_refptr<network::SharedURLLoaderFactory> GetURLLoaderFactory()
      override {
    // TODO(crbug.com/1413912): CreateSanitizedFragmentFromMarkupWithContext may
    // call this method for data: URL resources. But ResourceLoader::Start()
    // don't need to call GetURLLoaderFactory() for data: URL because
    // ResourceLoader handles the data: URL resource load without the returned
    // SharedURLLoaderFactory.
    // Note: Non-data: URL resource can't be loaded because the CORS check in
    // BaseFetchContext::CanRequestInternal fails for non-data: URL resources.
    return base::MakeRefCounted<network::SingleRequestURLLoaderFactory>(
        WTF::BindOnce(
            [](const network::ResourceRequest& resource_request,
               mojo::PendingReceiver<network::mojom::URLLoader> receiver,
               mojo::PendingRemote<network::mojom::URLLoaderClient> client) {
              NOTREACHED();
            }));
  }
};

void LogFastPathParserTotalTime(base::TimeDelta parse_time) {
  // The time needed to parse is typically < 1ms (even at the 99%).
  UMA_HISTOGRAM_CUSTOM_MICROSECONDS_TIMES(
      "Blink.HTMLFastPathParser.TotalParseTime2", parse_time,
      base::Microseconds(1), base::Milliseconds(10), 100);
}

}  // namespace

static void CompleteURLs(DocumentFragment& fragment, const String& base_url) {
  HeapVector<AttributeChange> changes;

  KURL parsed_base_url(base_url);

  for (Element& element : ElementTraversal::DescendantsOf(fragment)) {
    AttributeCollection attributes = element.Attributes();
    // AttributeCollection::iterator end = attributes.end();
    for (const auto& attribute : attributes) {
      if (element.IsURLAttribute(attribute) && !attribute.Value().empty())
        changes.push_back(AttributeChange(
            &element, attribute.GetName(),
            KURL(parsed_base_url, attribute.Value()).GetString()));
    }
  }

  for (auto& change : changes)
    change.Apply();
}

static bool IsHTMLBlockElement(const Node* node) {
  DCHECK(node);
  return IsA<HTMLTableCellElement>(*node) ||
         IsNonTableCellHTMLBlockElement(node);
}

static HTMLElement* AncestorToRetainStructureAndAppearanceForBlock(
    Element* common_ancestor_block) {
  if (!common_ancestor_block)
    return nullptr;

  if (common_ancestor_block->HasTagName(html_names::kTbodyTag) ||
      IsA<HTMLTableRowElement>(*common_ancestor_block))
    return Traversal<HTMLTableElement>::FirstAncestor(*common_ancestor_block);

  if (IsNonTableCellHTMLBlockElement(common_ancestor_block))
    return To<HTMLElement>(common_ancestor_block);

  return nullptr;
}

static inline HTMLElement* AncestorToRetainStructureAndAppearance(
    Node* common_ancestor) {
  return AncestorToRetainStructureAndAppearanceForBlock(
      EnclosingBlock(common_ancestor));
}

static inline HTMLElement*
AncestorToRetainStructureAndAppearanceWithNoLayoutObject(
    const Node& common_ancestor) {
  auto* common_ancestor_block = To<HTMLElement>(EnclosingNodeOfType(
      FirstPositionInOrBeforeNode(common_ancestor), IsHTMLBlockElement));
  return AncestorToRetainStructureAndAppearanceForBlock(common_ancestor_block);
}

bool PropertyMissingOrEqualToNone(CSSPropertyValueSet* style,
                                  CSSPropertyID property_id) {
  if (!style)
    return false;
  const CSSValue* value = style->GetPropertyCSSValue(property_id);
  if (!value)
    return true;
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value)
    return false;
  return identifier_value->GetValueID() == CSSValueID::kNone;
}

template <typename Strategy>
static HTMLElement* HighestAncestorToWrapMarkup(
    const PositionTemplate<Strategy>& start_position,
    const PositionTemplate<Strategy>& end_position,
    const CreateMarkupOptions& options) {
  Node* first_node = start_position.NodeAsRangeFirstNode();
  // For compatibility reason, we use container node of start and end
  // positions rather than first node and last node in selection.
  Node* common_ancestor =
      Strategy::CommonAncestor(*start_position.ComputeContainerNode(),
                               *end_position.ComputeContainerNode());
  DCHECK(common_ancestor);
  HTMLElement* special_common_ancestor = nullptr;
  if (options.ShouldAnnotateForInterchange()) {
    // Include ancestors that aren't completely inside the range but are
    // required to retain the structure and appearance of the copied markup.
    special_common_ancestor =
        AncestorToRetainStructureAndAppearance(common_ancestor);
    if (first_node) {
      const Position& first_node_position =
          FirstPositionInOrBeforeNode(*first_node);
      if (Node* parent_list_node =
              EnclosingNodeOfType(first_node_position, IsListItem)) {
        if (AreSameRanges(parent_list_node, start_position, end_position)) {
          ContainerNode* ancestor = parent_list_node->parentNode();
          while (ancestor && !IsHTMLListElement(ancestor))
            ancestor = ancestor->parentNode();
          special_common_ancestor = To<HTMLElement>(ancestor);
        }
      }

      // Retain the Mail quote level by including all ancestor mail block
      // quotes.
      if (auto* highest_mail_blockquote =
              To<HTMLQuoteElement>(HighestEnclosingNodeOfType(
                  first_node_position, IsMailHTMLBlockquoteElement,
                  kCanCrossEditingBoundary))) {
        special_common_ancestor = highest_mail_blockquote;
      }
    }
  }

  Node* check_ancestor =
      special_common_ancestor ? special_common_ancestor : common_ancestor;
  if (check_ancestor->GetLayoutObject()) {
    // We want to constrain the ancestor to the enclosing block.
    // Ex: <b><p></p></b> is an ill-formed html and we don't want to return <b>
    // as the ancestor because paragraph element is the enclosing block of the
    // start and end positions provided to this API.
    // TODO(editing-dev): Make |HighestEnclosingNodeOfType| take const pointer
    // to remove the |const_cast| below.
    Node* constraining_ancestor =
        options.ConstrainingAncestor()
            ? const_cast<Node*>(options.ConstrainingAncestor())
            : EnclosingBlock(check_ancestor);
    auto* new_special_common_ancestor =
        To<HTMLElement>(HighestEnclosingNodeOfType(
            Position::FirstPositionInNode(*check_ancestor),
            &IsPresentationalHTMLElement, kCanCrossEditingBoundary,
            constraining_ancestor));
    if (new_special_common_ancestor)
      special_common_ancestor = new_special_common_ancestor;
  }

  // If a single tab is selected, commonAncestor will be a text node inside a
  // tab span. If two or more tabs are selected, commonAncestor will be the tab
  // span. In either case, if there is a specialCommonAncestor already, it will
  // necessarily be above any tab span that needs to be included.
  if (!special_common_ancestor &&
      IsTabHTMLSpanElementTextNode(common_ancestor)) {
    special_common_ancestor =
        To<HTMLSpanElement>(Strategy::Parent(*common_ancestor));
  }
  if (!special_common_ancestor && IsTabHTMLSpanElement(common_ancestor))
    special_common_ancestor = To<HTMLSpanElement>(common_ancestor);

  if (auto* enclosing_anchor = To<HTMLAnchorElement>(EnclosingElementWithTag(
          Position::FirstPositionInNode(special_common_ancestor
                                            ? *special_common_ancestor
                                            : *common_ancestor),
          html_names::kATag)))
    special_common_ancestor = enclosing_anchor;

  return special_common_ancestor;
}

template <typename Strategy>
class CreateMarkupAlgorithm {
 public:
  static String CreateMarkup(
      const PositionTemplate<Strategy>& start_position,
      const PositionTemplate<Strategy>& end_position,
      const CreateMarkupOptions& options = CreateMarkupOptions());
};

// FIXME: Shouldn't we omit style info when annotate ==
// DoNotAnnotateForInterchange?
// FIXME: At least, annotation and style info should probably not be included in
// range.markupString()
template <typename Strategy>
String CreateMarkupAlgorithm<Strategy>::CreateMarkup(
    const PositionTemplate<Strategy>& start_position,
    const PositionTemplate<Strategy>& end_position,
    const CreateMarkupOptions& options) {
  if (start_position.IsNull() || end_position.IsNull())
    return g_empty_string;

  CHECK_LE(start_position.CompareTo(end_position), 0);

  bool collapsed = start_position == end_position;
  if (collapsed)
    return g_empty_string;
  Node* common_ancestor =
      Strategy::CommonAncestor(*start_position.ComputeContainerNode(),
                               *end_position.ComputeContainerNode());
  if (!common_ancestor)
    return g_empty_string;

  Document* document = start_position.GetDocument();

  DCHECK(!document->NeedsLayoutTreeUpdate());
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      document->Lifecycle());

  HTMLElement* special_common_ancestor = HighestAncestorToWrapMarkup<Strategy>(
      start_position, end_position, options);
  StyledMarkupSerializer<Strategy> serializer(start_position, end_position,
                                              special_common_ancestor, options);
  return serializer.CreateMarkup();
}

String CreateMarkup(const Position& start_position,
                    const Position& end_position,
                    const CreateMarkupOptions& options) {
  return CreateMarkupAlgorithm<EditingStrategy>::CreateMarkup(
      start_position, end_position, options);
}

String CreateMarkup(const PositionInFlatTree& start_position,
                    const PositionInFlatTree& end_position,
                    const CreateMarkupOptions& options) {
  return CreateMarkupAlgorithm<EditingInFlatTreeStrategy>::CreateMarkup(
      start_position, end_position, options);
}

DocumentFragment* CreateFragmentFromMarkup(
    Document& document,
    const String& markup,
    const String& base_url,
    ParserContentPolicy parser_content_policy) {
  // We use a fake body element here to trick the HTML parser to using the
  // InBody insertion mode.
  auto* fake_body = MakeGarbageCollected<HTMLBodyElement>(document);
  DocumentFragment* fragment = DocumentFragment::Create(document);

  fragment->ParseHTML(markup, fake_body, parser_content_policy);

  if (!base_url.empty() && base_url != BlankURL() &&
      base_url != document.BaseURL())
    CompleteURLs(*fragment, base_url);

  return fragment;
}

static const char kFragmentMarkerTag[] = "webkit-fragment-marker";

static bool FindNodesSurroundingContext(DocumentFragment* fragment,
                                        Comment*& node_before_context,
                                        Comment*& node_after_context) {
  if (!fragment->firstChild())
    return false;
  for (Node& node : NodeTraversal::StartsAt(*fragment->firstChild())) {
    auto* comment_node = DynamicTo<Comment>(node);
    if (comment_node && comment_node->data() == kFragmentMarkerTag) {
      if (!node_before_context) {
        node_before_context = comment_node;
      } else {
        node_after_context = comment_node;
        return true;
      }
    }
  }
  return false;
}

static void TrimFragment(DocumentFragment* fragment,
                         Comment* node_before_context,
                         Comment* node_after_context) {
  Node* next = nullptr;
  for (Node* node = fragment->firstChild(); node; node = next) {
    if (node_before_context->IsDescendantOf(node)) {
      next = NodeTraversal::Next(*node);
      continue;
    }
    next = NodeTraversal::NextSkippingChildren(*node);
    DCHECK(!node->contains(node_after_context))
        << node << " " << node_after_context;
    node->parentNode()->RemoveChild(node, ASSERT_NO_EXCEPTION);
    if (node_before_context == node)
      break;
  }

  DCHECK(node_after_context->parentNode()) << node_after_context;
  for (Node* node = node_after_context; node; node = next) {
    next = NodeTraversal::NextSkippingChildren(*node);
    node->parentNode()->RemoveChild(node, ASSERT_NO_EXCEPTION);
  }
}

DocumentFragment* CreateFragmentFromMarkupWithContext(
    Document& document,
    const String& markup,
    unsigned fragment_start,
    unsigned fragment_end,
    const String& base_url,
    ParserContentPolicy parser_content_policy) {
  // FIXME: Need to handle the case where the markup already contains these
  // markers.

  StringBuilder tagged_markup;
  tagged_markup.Append(markup.Left(fragment_start));
  MarkupFormatter::AppendComment(tagged_markup, kFragmentMarkerTag);
  tagged_markup.Append(
      markup.Substring(fragment_start, fragment_end - fragment_start));
  MarkupFormatter::AppendComment(tagged_markup, kFragmentMarkerTag);
  tagged_markup.Append(markup.Substring(fragment_end));

  DocumentFragment* tagged_fragment = CreateFragmentFromMarkup(
      document, tagged_markup.ToString(), base_url, parser_content_policy);

  Comment* node_before_context = nullptr;
  Comment* node_after_context = nullptr;
  if (!FindNodesSurroundingContext(tagged_fragment, node_before_context,
                                   node_after_context))
    return nullptr;

  auto* tagged_document = MakeGarbageCollected<Document>(
      DocumentInit::Create()
          .WithExecutionContext(document.GetExecutionContext())
          .WithAgent(document.GetAgent()));

  auto* root =
      MakeGarbageCollected<Element>(QualifiedName::Null(), tagged_document);
  root->AppendChild(tagged_fragment);
  tagged_document->AppendChild(root);

  const EphemeralRange range(
      Position::AfterNode(*node_before_context).ParentAnchoredEquivalent(),
      Position::BeforeNode(*node_after_context).ParentAnchoredEquivalent());

  DCHECK(range.CommonAncestorContainer());
  Node& common_ancestor = *range.CommonAncestorContainer();
  HTMLElement* special_common_ancestor =
      AncestorToRetainStructureAndAppearanceWithNoLayoutObject(common_ancestor);

  // When there's a special common ancestor outside of the fragment, we must
  // include it as well to preserve the structure and appearance of the
  // fragment. For example, if the fragment contains TD, we need to include the
  // enclosing TABLE tag as well.
  DocumentFragment* fragment = DocumentFragment::Create(document);
  if (special_common_ancestor)
    fragment->AppendChild(special_common_ancestor);
  else
    fragment->ParserTakeAllChildrenFrom(To<ContainerNode>(common_ancestor));

  TrimFragment(fragment, node_before_context, node_after_context);

  return fragment;
}

String CreateMarkup(const Node* node,
                    ChildrenOnly children_only,
                    AbsoluteURLs should_resolve_urls,
                    const ShadowRootInclusion& shadow_root_inclusion) {
  if (!node)
    return "";

  MarkupAccumulator accumulator(should_resolve_urls,
                                IsA<HTMLDocument>(node->GetDocument())
                                    ? SerializationType::kHTML
                                    : SerializationType::kXML,
                                shadow_root_inclusion);
  return accumulator.SerializeNodes<EditingStrategy>(*node, children_only);
}

static void FillContainerFromString(ContainerNode* paragraph,
                                    const String& string) {
  Document& document = paragraph->GetDocument();

  if (string.empty()) {
    paragraph->AppendChild(MakeGarbageCollected<HTMLBRElement>(document));
    return;
  }

  DCHECK_EQ(string.find('\n'), kNotFound) << string;

  Vector<String> tab_list;
  string.Split('\t', true, tab_list);
  StringBuilder tab_text;
  bool first = true;
  wtf_size_t num_entries = tab_list.size();
  for (wtf_size_t i = 0; i < num_entries; ++i) {
    const String& s = tab_list[i];

    // append the non-tab textual part
    if (!s.empty()) {
      if (!tab_text.empty()) {
        paragraph->AppendChild(
            CreateTabSpanElement(document, tab_text.ToString()));
        tab_text.Clear();
      }
      Text* text_node = document.createTextNode(
          StringWithRebalancedWhitespace(s, first, i + 1 == num_entries));
      paragraph->AppendChild(text_node);
    }

    // there is a tab after every entry, except the last entry
    // (if the last character is a tab, the list gets an extra empty entry)
    if (i + 1 != num_entries)
      tab_text.Append('\t');
    else if (!tab_text.empty())
      paragraph->AppendChild(
          CreateTabSpanElement(document, tab_text.ToString()));

    first = false;
  }
}

bool IsPlainTextMarkup(Node* node) {
  DCHECK(node);
  auto* element = DynamicTo<HTMLDivElement>(*node);
  if (!element)
    return false;

  if (!element->hasAttributes())
    return false;

  if (element->HasOneChild()) {
    return element->firstChild()->IsTextNode() ||
           element->firstChild()->hasChildren();
  }

  return element->HasChildCount(2) &&
         IsTabHTMLSpanElementTextNode(element->firstChild()->firstChild()) &&
         element->lastChild()->IsTextNode();
}

static bool ShouldPreserveNewline(const EphemeralRange& range) {
  if (Node* node = range.StartPosition().NodeAsRangeFirstNode()) {
    if (LayoutObject* layout_object = node->GetLayoutObject())
      return layout_object->Style()->ShouldPreserveBreaks();
  }

  if (Node* node = range.StartPosition().AnchorNode()) {
    if (LayoutObject* layout_object = node->GetLayoutObject())
      return layout_object->Style()->ShouldPreserveBreaks();
  }

  return false;
}

DocumentFragment* CreateFragmentFromText(const EphemeralRange& context,
                                         const String& text) {
  if (context.IsNull())
    return nullptr;

  Document& document = context.GetDocument();
  DocumentFragment* fragment = document.createDocumentFragment();

  if (text.empty())
    return fragment;

  String string = text;
  string.Replace("\r\n", "\n");
  string.Replace('\r', '\n');

  if (!IsRichlyEditablePosition(context.StartPosition()) ||
      ShouldPreserveNewline(context)) {
    fragment->AppendChild(document.createTextNode(string));
    if (string.EndsWith('\n')) {
      auto* element = MakeGarbageCollected<HTMLBRElement>(document);
      element->setAttribute(html_names::kClassAttr,
                            AtomicString(AppleInterchangeNewline));
      fragment->AppendChild(element);
    }
    return fragment;
  }

  // A string with no newlines gets added inline, rather than being put into a
  // paragraph.
  if (string.find('\n') == kNotFound) {
    FillContainerFromString(fragment, string);
    return fragment;
  }

  // Break string into paragraphs. Extra line breaks turn into empty paragraphs.
  Element* block =
      EnclosingBlock(context.StartPosition().NodeAsRangeFirstNode());
  bool use_clones_of_enclosing_block =
      block && !IsA<HTMLBodyElement>(block) && !IsA<HTMLHtmlElement>(block) &&
      block != RootEditableElementOf(context.StartPosition());

  Vector<String> list;
  string.Split('\n', true, list);  // true gets us empty strings in the list
  wtf_size_t num_lines = list.size();
  for (wtf_size_t i = 0; i < num_lines; ++i) {
    const String& s = list[i];

    Element* element = nullptr;
    if (s.empty() && i + 1 == num_lines) {
      // For last line, use the "magic BR" rather than a P.
      element = MakeGarbageCollected<HTMLBRElement>(document);
      element->setAttribute(html_names::kClassAttr,
                            AtomicString(AppleInterchangeNewline));
    } else {
      if (use_clones_of_enclosing_block)
        element = &block->CloneWithoutChildren();
      else
        element = CreateDefaultParagraphElement(document);
      FillContainerFromString(element, s);
    }
    fragment->AppendChild(element);
  }
  return fragment;
}

DocumentFragment* CreateFragmentForInnerOuterHTML(
    const String& markup,
    Element* context_element,
    ParserContentPolicy parser_content_policy,
    Element::ParseDeclarativeShadowRoots parse_declarative_shadows,
    Element::ForceHtml force_html,
    ExceptionState& exception_state) {
  DCHECK(context_element);
  const HTMLTemplateElement* template_element =
      DynamicTo<HTMLTemplateElement>(*context_element);
  if (template_element && !template_element->GetExecutionContext()) {
    return nullptr;
  }

  Document& document =
      IsA<HTMLTemplateElement>(*context_element)
          ? context_element->GetDocument().EnsureTemplateDocument()
          : context_element->GetDocument();
  DocumentFragment* fragment = DocumentFragment::Create(document);
  document.setAllowDeclarativeShadowRoots(
      parse_declarative_shadows ==
      Element::ParseDeclarativeShadowRoots::kParse);

  if (IsA<HTMLDocument>(document) || force_html == Element::ForceHtml::kForce) {
    bool log_tag_stats = false;
    base::ElapsedTimer parse_timer;
    HTMLFragmentParsingBehaviorSet parser_behavior;
    if (parse_declarative_shadows ==
        Element::ParseDeclarativeShadowRoots::kParse) {
      parser_behavior.Put(HTMLFragmentParsingBehavior::kIncludeShadowRoots);
    }
    const bool parsed_fast_path = TryParsingHTMLFragment(
        markup, document, *fragment, *context_element, parser_content_policy,
        parser_behavior, &log_tag_stats);
    if (parsed_fast_path) {
      LogFastPathParserTotalTime(parse_timer.Elapsed());
#if DCHECK_IS_ON()
      // As a sanity check for the fast-path, create another fragment using
      // the full parser and compare the results.
      // See https://bugs.chromium.org/p/chromium/issues/detail?id=1407201
      // for details.
      DocumentFragment* fragment2 = DocumentFragment::Create(document);
      fragment2->ParseHTML(markup, context_element, parser_content_policy);
      DCHECK_EQ(CreateMarkup(fragment), CreateMarkup(fragment2))
          << " supplied value " << markup;
      DCHECK(fragment->isEqualNode(fragment2));
#endif
      return fragment;
    }
    fragment = DocumentFragment::Create(document);
    fragment->ParseHTML(markup, context_element, parser_content_policy);
    LogFastPathParserTotalTime(parse_timer.Elapsed());
    if (log_tag_stats &&
        RuntimeEnabledFeatures::InnerHTMLParserFastpathLogFailureEnabled()) {
      LogTagsForUnsupportedTagTypeFailure(*fragment);
    }
    return fragment;
  }

  bool was_valid = fragment->ParseXML(markup, context_element, exception_state,
                                      parser_content_policy);
  if (!was_valid) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The provided markup is invalid XML, and "
        "therefore cannot be inserted into an XML "
        "document.");
    return nullptr;
  }
  return fragment;
}

DocumentFragment* CreateFragmentForTransformToFragment(
    const String& source_string,
    const String& source_mime_type,
    Document& output_doc) {
  DocumentFragment* fragment = output_doc.createDocumentFragment();

  // The HTML spec says that we should execute scripts and set their already
  // started flag to false for transformToFragment, so we use
  // kAllowScriptingContentAndDoNotMarkAlreadyStarted in ParseHTML and ParseXML
  // below. https://html.spec.whatwg.org/multipage/scripting.html#scriptTagXSLT

  if (source_mime_type == "text/html") {
    // As far as I can tell, there isn't a spec for how transformToFragment is
    // supposed to work. Based on the documentation I can find, it looks like we
    // want to start parsing the fragment in the InBody insertion mode.
    // Unfortunately, that's an implementation detail of the parser. We achieve
    // that effect here by passing in a fake body element as context for the
    // fragment.
    auto* fake_body = MakeGarbageCollected<HTMLBodyElement>(output_doc);
    fragment->ParseHTML(source_string, fake_body,
                        kAllowScriptingContentAndDoNotMarkAlreadyStarted);
  } else if (source_mime_type == "text/plain") {
    fragment->ParserAppendChild(Text::Create(output_doc, source_string));
  } else {
    bool successful_parse =
        fragment->ParseXML(source_string, nullptr, IGNORE_EXCEPTION,
                           kAllowScriptingContentAndDoNotMarkAlreadyStarted);
    if (!successful_parse)
      return nullptr;
  }

  // FIXME: Do we need to mess with URLs here?

  return fragment;
}

static inline void RemoveElementPreservingChildren(DocumentFragment* fragment,
                                                   HTMLElement* element) {
  Node* next_child = nullptr;
  for (Node* child = element->firstChild(); child; child = next_child) {
    next_child = child->nextSibling();
    element->RemoveChild(child);
    fragment->InsertBefore(child, element);
  }
  fragment->RemoveChild(element);
}

DocumentFragment* CreateContextualFragment(
    const String& markup,
    Element* element,
    ParserContentPolicy parser_content_policy,
    ExceptionState& exception_state) {
  DCHECK(element);

  DocumentFragment* fragment = CreateFragmentForInnerOuterHTML(
      markup, element, parser_content_policy,
      Element::ParseDeclarativeShadowRoots::kDontParse,
      Element::ForceHtml::kDontForce, exception_state);
  if (!fragment)
    return nullptr;

  // We need to pop <html> and <body> elements and remove <head> to
  // accommodate folks passing complete HTML documents to make the
  // child of an element.

  Node* next_node = nullptr;
  for (Node* node = fragment->firstChild(); node; node = next_node) {
    next_node = node->nextSibling();
    if (IsA<HTMLHtmlElement>(node) || IsA<HTMLHeadElement>(node) ||
        IsA<HTMLBodyElement>(node)) {
      auto* child_element = To<HTMLElement>(node);
      if (Node* first_child = child_element->firstChild())
        next_node = first_child;
      RemoveElementPreservingChildren(fragment, child_element);
    }
  }
  return fragment;
}

void ReplaceChildrenWithFragment(ContainerNode* container,
                                 DocumentFragment* fragment,
                                 ExceptionState& exception_state) {
  DCHECK(container);
  RUNTIME_CALL_TIMER_SCOPE(
      container->GetDocument().GetAgent().isolate(),
      RuntimeCallStats::CounterId::kReplaceChildrenWithFragment);
  ContainerNode* container_node(container);

  ChildListMutationScope mutation(*container_node);

  if (!fragment->firstChild()) {
    container_node->RemoveChildren();
    return;
  }

  // FIXME: No need to replace the child it is a text node an
```