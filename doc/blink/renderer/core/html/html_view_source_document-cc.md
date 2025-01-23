Response:
Let's break down the thought process for analyzing the `HTMLViewSourceDocument.cc` file.

1. **Understand the Goal:** The primary goal of this file is to implement the "View Source" functionality in a web browser. This means taking the raw HTML (and potentially other resources) and displaying it in a readable, often syntax-highlighted, format.

2. **Identify the Core Class:** The name of the file and the initial `class HTMLViewSourceDocument` declaration immediately point to the central class responsible for this functionality.

3. **Look for Key Methods:**  Think about the essential steps involved in viewing source:
    * **Parsing:**  How is the raw source processed? Look for methods related to parsing. `CreateParser()` stands out.
    * **Structure Creation:** How is the output document built? Look for methods that create elements and arrange them. `CreateContainingTable()` is a strong clue.
    * **Source Ingestion:** How is the raw source code fed into the document? `AddSource()` seems like the main entry point for the source code.
    * **Token Processing:**  The `AddSource()` method branches into different `Process...Token` methods. This suggests the parser breaks the source into tokens, and these methods handle each type of token.

4. **Examine the `CreateContainingTable()` Method:** This method seems responsible for setting up the basic structure of the view-source page. Observe the creation of:
    * `<html>`, `<head>`, `<body>` elements.
    * A `<div>` for the line gutter.
    * A `<table>` to hold the source code.
    * A checkbox for line wrapping.
    * A `<form>` to contain the checkbox (important for preventing unwanted form restoration).

5. **Analyze the `AddSource()` Method:**  This acts as a dispatcher, based on the `HTMLToken` type. This reinforces the idea of token-based parsing.

6. **Dive into the `Process...Token` Methods:**  These methods are where the actual source formatting happens. Look for:
    * How different token types (DOCTYPE, tags, comments, characters) are handled.
    * The use of `<span>` elements to apply different styles (syntax highlighting).
    * The `AddSpanWithClassName()` helper method, which simplifies creating styled spans.
    * The handling of attributes within tags (`ProcessTagToken`).
    * Special cases, like the `base` tag and `srcset` attribute.
    * The handling of links (`<a>` elements).

7. **Connect to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The entire purpose is to display HTML source. The code explicitly creates various HTML elements (`<div>`, `<table>`, `<span>`, etc.).
    * **CSS:** The code adds `class` attributes to elements (`line-number`, `line-content`, `html-tag`, etc.). This strongly suggests that CSS is used to style these elements for syntax highlighting and layout. The "line-wrap" class is a direct example of CSS control.
    * **JavaScript:**  The `ViewSourceEventListener` and the `checkbox->addEventListener` line demonstrate the use of JavaScript to make the line-wrapping feature interactive. When the checkbox state changes, the JavaScript updates the `class` attribute of the table, triggering a CSS change.

8. **Consider Logic and Assumptions:**
    * **Input:** The input is the raw HTML source code of a web page.
    * **Output:** The output is an HTML document displaying the source code, typically with syntax highlighting and line numbers. The line-wrapping checkbox is an interactive element that modifies the output.
    * **Assumptions:**  The code assumes a standard HTML structure for the view-source page itself. It relies on CSS for styling and JavaScript for interactivity.

9. **Think About Potential Errors:** What could go wrong?
    * Incorrectly parsing the source HTML could lead to mis-highlighted or incorrectly structured output.
    * Issues with the JavaScript event listener could break the line-wrapping feature.
    * CSS errors could lead to a poorly formatted view-source page.

10. **Structure the Explanation:** Organize the findings into logical sections:
    * Core functionality.
    * Relationship to HTML, CSS, and JavaScript (with examples).
    * Logical flow (input/output).
    * Common errors.

11. **Review and Refine:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that might need clarification. For example, explaining "syntax highlighting" might be useful.

This detailed breakdown, starting from the overall goal and drilling down into specific methods and their interactions, allows for a comprehensive understanding of the `HTMLViewSourceDocument.cc` file and its role in the Chromium Blink engine.
这个文件 `blink/renderer/core/html/html_view_source_document.cc` 的主要功能是 **生成并展示网页的源代码视图**。当你在浏览器中选择 "查看网页源代码" 或类似选项时，这个文件中的代码会被执行，创建一个新的文档，其中包含原始网页的 HTML 结构和内容，并以一种易于阅读的方式呈现出来。

以下是该文件的详细功能点，并与 JavaScript, HTML, CSS 的关系进行说明：

**主要功能:**

1. **创建 View Source 文档:** `HTMLViewSourceDocument` 类继承自 `HTMLDocument`，它代表了查看源代码时创建的特殊文档类型。
2. **解析源代码:**  它使用 `HTMLViewSourceParser` 来解析原始网页的 HTML 源代码。
3. **结构化展示:**  它将解析后的源代码以结构化的方式呈现出来，通常使用表格 (`<table>`) 来组织，每一行源代码对应表格的一行。
4. **语法高亮:**  虽然这个文件本身不负责具体的 CSS 样式，但它会通过添加特定的 CSS 类名到不同的 HTML 元素 (如 `<span>`) 上，来方便 CSS 对源代码进行语法高亮显示。例如，标签名、属性名、属性值、注释等会被赋予不同的类名。
5. **行号显示:**  它会在每一行源代码旁边显示行号，方便用户定位代码。
6. **处理特殊标签和属性:**
    * **`<base>` 标签:**  当遇到 `<base>` 标签时，会提取其 `href` 属性，这可能会影响到源代码中其他相对 URL 的解析。
    * **`<a>` 标签和 `href` 属性:** 对于 `<a>` 标签的 `href` 属性，会将其处理为可点击的链接。
    * **`<img>` 或其他元素的 `src` 属性:** 对于包含 URL 的属性，也会将其处理为潜在的链接。
    * **`srcset` 属性:**  会解析 `srcset` 属性中的多个 URL，并将它们都显示为链接。
7. **提供行号包裹控制:**  它包含一个复选框，允许用户切换是否自动换行显示源代码，这涉及到 CSS 的 `white-space` 属性的控制。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**
    * **生成 HTML 结构:** 这个文件的核心功能是生成一个 HTML 文档来展示源代码。它会创建 `<html>`, `<head>`, `<body>`, `<table>`, `<tr>`, `<td>`, `<span>` 等 HTML 元素来构建这个视图。
    * **类名用于 CSS 样式:** 它会为不同的代码片段添加特定的 HTML 类名，例如 `class="html-tag"`, `class="html-attribute-name"`, `class="html-attribute-value"`, `class="html-comment"` 等。这些类名是 CSS 样式化的基础，使得浏览器可以根据这些类名应用不同的颜色、字体等，实现语法高亮。
    * **链接处理:** 对于 `<a>` 标签和包含 URL 的属性，会生成实际的 `<a>` 标签，使得用户可以直接点击查看链接指向的内容。
    * **表格结构:** 使用 `<table>` 结构来布局源代码，使得每一行代码和行号对齐。

    **举例:**

    假设原始 HTML 中有以下代码：

    ```html
    <div class="container">
      <!-- This is a comment -->
      <a href="https://example.com">Example Link</a>
    </div>
    ```

    `HTMLViewSourceDocument` 生成的 HTML 结构可能如下 (简化版)：

    ```html
    <table>
      <tr>
        <td class="line-number" value="1">1</td>
        <td class="line-content">
          <span class="html-tag">&lt;div</span>
          <span class="html-attribute-name"> class</span>
          <span class="html-attribute-value">="container"</span>
          <span class="html-tag">&gt;</span>
        </td>
      </tr>
      <tr>
        <td class="line-number" value="2">2</td>
        <td class="line-content">
          <span class="html-comment">&lt;!-- This is a comment --&gt;</span>
        </td>
      </tr>
      <tr>
        <td class="line-number" value="3">3</td>
        <td class="line-content">
          <span class="html-tag">&lt;a</span>
          <span class="html-attribute-name"> href</span>
          <span class="html-attribute-value">="<a href="https://example.com" target="_blank" rel="noreferrer noopener" class="html-attribute-value html-external-link">https://example.com</a>"</span>
          <span class="html-tag">&gt;</span>
          Example Link
          <span class="html-tag">&lt;/a&gt;</span>
        </td>
      </tr>
      <tr>
        <td class="line-number" value="4">4</td>
        <td class="line-content">
          <span class="html-tag">&lt;/div&gt;</span>
        </td>
      </tr>
    </table>
    ```

* **CSS:**
    * **样式化类名:**  该文件生成的 HTML 结构中的类名 (如 `html-tag`, `html-attribute-name` 等) 会被 CSS 样式规则所使用，从而实现不同代码元素的颜色、字体、背景等样式。
    * **行号样式:** CSS 会控制行号的显示位置、样式等。
    * **行号包裹控制:**  当用户切换行号包裹复选框时，JavaScript 会修改表格的类名 (`line-wrap` 或空字符串)。CSS 中定义了 `.line-wrap` 类的样式，例如使用 `white-space: pre-wrap;` 来实现自动换行。

    **举例:**

    可能存在以下的 CSS 规则来样式化查看源代码：

    ```css
    .html-tag { color: blue; }
    .html-attribute-name { color: red; }
    .html-attribute-value { color: green; }
    .html-comment { color: gray; }
    .line-number { background-color: #f0f0f0; padding-right: 10px; }
    .line-wrap .line-content { white-space: pre-wrap; }
    .line-content { white-space: pre; overflow-x: auto; }
    ```

* **JavaScript:**
    * **交互性:**  `ViewSourceEventListener` 类和相关的代码负责处理行号包裹复选框的 `change` 事件。当复选框的状态改变时，JavaScript 代码会更新表格元素的 `class` 属性，从而触发 CSS 样式的变化，实现行号包裹的切换。
    * **动态行为 (有限):** 在查看源代码的页面中，JavaScript 的使用通常比较有限，主要用于一些简单的交互功能，例如这里的行号包裹控制。

    **举例:**

    当用户点击行号包裹复选框时，`ViewSourceEventListener::Invoke` 方法会被调用。如果复选框被选中，它会将表格的 `class` 属性设置为 "line-wrap"，否则设置为空字符串。

    ```c++
    void ViewSourceEventListener::Invoke(ExecutionContext*, Event* event) override {
      DCHECK_EQ(event->type(), event_type_names::kChange);
      table_->setAttribute(html_names::kClassAttr, checkbox_->Checked()
                                                       ? AtomicString("line-wrap")
                                                       : g_empty_atom);
    }
    ```

**逻辑推理的例子:**

**假设输入:** 一个包含内联 CSS 样式的 HTML 片段：

```html
<p style="color: red;">This is red text.</p>
```

**处理过程:** `HTMLViewSourceDocument` 会解析这个片段，并生成如下的 HTML 结构 (简化)：

```html
<table>
  <tr>
    <td class="line-number" value="1">1</td>
    <td class="line-content">
      <span class="html-tag">&lt;p</span>
      <span class="html-attribute-name"> style</span>
      <span class="html-attribute-value">="color: red;"</span>
      <span class="html-tag">&gt;</span>
      This is red text.
      <span class="html-tag">&lt;/p&gt;</span>
    </td>
  </tr>
</table>
```

**假设输出:**  在浏览器中查看源代码时，会看到类似这样的结构，并且 "style" 会以一种颜色显示 (例如红色或紫色，取决于 CSS 规则)，"color: red;" 会以另一种颜色显示 (例如绿色)。

**用户或编程常见的使用错误:**

1. **假设源代码与渲染结果完全一致:**  用户可能会认为查看源代码看到的内容与浏览器实际渲染的 DOM 结构完全一致。但实际上，浏览器在解析 HTML 的过程中可能会进行一些修正和优化，例如自动闭合未闭合的标签，添加缺失的 `<html>`, `<head>`, `<body>` 标签等。查看源代码看到的是原始的标记，而不是最终的 DOM 树。
2. **依赖源代码顺序进行 JavaScript 操作:**  程序员有时可能会依赖查看源代码时标签的顺序来编写 JavaScript 代码，但这可能是不稳定的，因为浏览器的解析过程可能会对标签顺序进行调整。应该始终基于 DOM 结构进行 JavaScript 操作，而不是依赖源代码的字面顺序。
3. **错误地编辑查看源代码页面:**  用户可能会尝试在查看源代码的页面上直接编辑代码并期望更改原始网页。但实际上，查看源代码的页面是一个静态的表示，对其进行的修改不会影响原始网页。要修改网页，需要编辑服务器上的源文件或使用浏览器的开发者工具进行实时的 DOM 编辑。

总而言之，`html_view_source_document.cc` 文件是 Chromium Blink 引擎中负责生成和展示网页源代码视图的关键组件，它通过生成结构化的 HTML 并添加特定的类名，配合 CSS 和 JavaScript，为用户提供了一个易于阅读和交互的源代码查看体验。

### 提示词
```
这是目录为blink/renderer/core/html/html_view_source_document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2008, 2009, 2010 Apple Inc. All rights reserved.
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
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/html_view_source_document.h"

#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/core/css/css_value_id_mappings.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_label_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_base_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html/html_table_row_element.h"
#include "third_party/blink/renderer/core/html/html_table_section_element.h"
#include "third_party/blink/renderer/core/html/parser/html_view_source_parser.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"

namespace blink {

class ViewSourceEventListener : public NativeEventListener {
 public:
  ViewSourceEventListener(HTMLTableElement* table, HTMLInputElement* checkbox)
      : table_(table), checkbox_(checkbox) {}

  void Invoke(ExecutionContext*, Event* event) override {
    DCHECK_EQ(event->type(), event_type_names::kChange);
    table_->setAttribute(html_names::kClassAttr, checkbox_->Checked()
                                                     ? AtomicString("line-wrap")
                                                     : g_empty_atom);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(table_);
    visitor->Trace(checkbox_);
    NativeEventListener::Trace(visitor);
  }

 private:
  Member<HTMLTableElement> table_;
  Member<HTMLInputElement> checkbox_;
};

HTMLViewSourceDocument::HTMLViewSourceDocument(const DocumentInit& initializer)
    : HTMLDocument(initializer), type_(initializer.GetMimeType()) {
  SetIsViewSource(true);
  SetCompatibilityMode(kNoQuirksMode);
  LockCompatibilityMode();
}

DocumentParser* HTMLViewSourceDocument::CreateParser() {
  return MakeGarbageCollected<HTMLViewSourceParser>(*this, type_);
}

void HTMLViewSourceDocument::CreateContainingTable() {
  auto* html = MakeGarbageCollected<HTMLHtmlElement>(*this);
  ParserAppendChild(html);
  auto* head = MakeGarbageCollected<HTMLHeadElement>(*this);
  auto* meta =
      MakeGarbageCollected<HTMLMetaElement>(*this, CreateElementFlags());
  meta->setAttribute(html_names::kNameAttr, keywords::kColorScheme);
  meta->setAttribute(html_names::kContentAttr, AtomicString("light dark"));
  head->ParserAppendChild(meta);
  html->ParserAppendChild(head);
  auto* body = MakeGarbageCollected<HTMLBodyElement>(*this);
  html->ParserAppendChild(body);

  // Create a line gutter div that can be used to make sure the gutter extends
  // down the height of the whole document.
  auto* div = MakeGarbageCollected<HTMLDivElement>(*this);
  div->setAttribute(html_names::kClassAttr,
                    AtomicString("line-gutter-backdrop"));
  body->ParserAppendChild(div);

  auto* table = MakeGarbageCollected<HTMLTableElement>(*this);
  tbody_ = MakeGarbageCollected<HTMLTableSectionElement>(html_names::kTbodyTag,
                                                         *this);
  table->ParserAppendChild(tbody_);
  current_ = tbody_;
  line_number_ = 0;

  // Create a checkbox to control line wrapping.
  auto* checkbox = MakeGarbageCollected<HTMLInputElement>(*this);
  checkbox->setAttribute(html_names::kTypeAttr, input_type_names::kCheckbox);
  checkbox->addEventListener(
      event_type_names::kChange,
      MakeGarbageCollected<ViewSourceEventListener>(table, checkbox),
      /*use_capture=*/false);
  checkbox->setAttribute(html_names::kAriaLabelAttr, WTF::AtomicString(Locale::DefaultLocale().QueryString(
                              IDS_VIEW_SOURCE_LINE_WRAP)));
  auto* label = MakeGarbageCollected<HTMLLabelElement>(*this);
  label->ParserAppendChild(
      Text::Create(*this, WTF::AtomicString(Locale::DefaultLocale().QueryString(
                              IDS_VIEW_SOURCE_LINE_WRAP))));
  label->setAttribute(html_names::kClassAttr,
                      AtomicString("line-wrap-control"));
  label->ParserAppendChild(checkbox);
  // Add the checkbox to a form with autocomplete=off, to avoid form
  // restoration from changing the value of the checkbox.
  auto* form = MakeGarbageCollected<HTMLFormElement>(*this);
  form->setAttribute(html_names::kAutocompleteAttr, AtomicString("off"));
  form->ParserAppendChild(label);
  body->ParserAppendChild(form);
  body->ParserAppendChild(table);
}

void HTMLViewSourceDocument::AddSource(
    const String& source,
    HTMLToken& token,
    const HTMLAttributesRanges& attributes_ranges,
    int token_start) {
  if (!current_)
    CreateContainingTable();

  switch (token.GetType()) {
    case HTMLToken::kUninitialized:
      NOTREACHED();
    case HTMLToken::DOCTYPE:
      ProcessDoctypeToken(source, token);
      break;
    case HTMLToken::kEndOfFile:
      ProcessEndOfFileToken(source, token);
      break;
    case HTMLToken::kStartTag:
    case HTMLToken::kEndTag:
      ProcessTagToken(source, token, attributes_ranges, token_start);
      break;
    case HTMLToken::kComment:
      ProcessCommentToken(source, token);
      break;
    case HTMLToken::kCharacter:
    case HTMLToken::kDOMPart:
      // Process DOM Parts as character tokens.
      ProcessCharacterToken(source, token);
      break;
  }
}

void HTMLViewSourceDocument::ProcessDoctypeToken(const String& source,
                                                 HTMLToken&) {
  current_ = AddSpanWithClassName(class_doctype_);
  AddText(source, class_doctype_);
  current_ = td_;
}

void HTMLViewSourceDocument::ProcessEndOfFileToken(const String& source,
                                                   HTMLToken&) {
  current_ = AddSpanWithClassName(class_end_of_file_);
  AddText(source, class_end_of_file_);
  current_ = td_;
}

void HTMLViewSourceDocument::ProcessTagToken(
    const String& source,
    const HTMLToken& token,
    const HTMLAttributesRanges& attributes_ranges,
    int token_start) {
  current_ = AddSpanWithClassName(class_tag_);

  AtomicString tag_name = token.GetName().AsAtomicString();

  unsigned index = 0;
  wtf_size_t attribute_index = 0;
  DCHECK_EQ(token.Attributes().size(), attributes_ranges.attributes().size());
  while (index < source.length()) {
    if (attribute_index == attributes_ranges.attributes().size()) {
      // We want to show the remaining characters in the token.
      index = AddRange(source, index, source.length(), g_empty_atom);
      DCHECK_EQ(index, source.length());
      break;
    }

    const HTMLToken::Attribute& attribute = token.Attributes()[attribute_index];
    const AtomicString name(attribute.GetName());
    const AtomicString value(attribute.GetValue());

    const HTMLAttributesRanges::Attribute& attribute_range =
        attributes_ranges.attributes()[attribute_index];

    index =
        AddRange(source, index, attribute_range.name_range.start - token_start,
                 g_empty_atom);
    index =
        AddRange(source, index, attribute_range.name_range.end - token_start,
                 class_attribute_name_);

    if (tag_name == html_names::kBaseTag && name == html_names::kHrefAttr)
      AddBase(value);

    index =
        AddRange(source, index, attribute_range.value_range.start - token_start,
                 g_empty_atom);

    if (name == html_names::kSrcsetAttr) {
      index = AddSrcset(source, index,
                        attribute_range.value_range.end - token_start);
    } else {
      bool is_link =
          name == html_names::kSrcAttr || name == html_names::kHrefAttr;
      index =
          AddRange(source, index, attribute_range.value_range.end - token_start,
                   class_attribute_value_, is_link,
                   tag_name == html_names::kATag, value);
    }

    ++attribute_index;
  }
  current_ = td_;
}

void HTMLViewSourceDocument::ProcessCommentToken(const String& source,
                                                 HTMLToken&) {
  current_ = AddSpanWithClassName(class_comment_);
  AddText(source, class_comment_);
  current_ = td_;
}

void HTMLViewSourceDocument::ProcessCharacterToken(const String& source,
                                                   HTMLToken&) {
  AddText(source, g_empty_atom);
}

Element* HTMLViewSourceDocument::AddSpanWithClassName(
    const AtomicString& class_name) {
  if (current_ == tbody_) {
    AddLine(class_name);
    return current_.Get();
  }

  auto* span = MakeGarbageCollected<HTMLSpanElement>(*this);
  span->setAttribute(html_names::kClassAttr, class_name);
  current_->ParserAppendChild(span);
  return span;
}

void HTMLViewSourceDocument::AddLine(const AtomicString& class_name) {
  // Create a table row.
  auto* trow = MakeGarbageCollected<HTMLTableRowElement>(*this);
  tbody_->ParserAppendChild(trow);

  // Create a cell that will hold the line number (it is generated in the
  // stylesheet using counters).
  auto* td =
      MakeGarbageCollected<HTMLTableCellElement>(html_names::kTdTag, *this);
  td->setAttribute(html_names::kClassAttr, AtomicString("line-number"));
  td->SetIntegralAttribute(html_names::kValueAttr, ++line_number_);
  trow->ParserAppendChild(td);

  // Create a second cell for the line contents
  td = MakeGarbageCollected<HTMLTableCellElement>(html_names::kTdTag, *this);
  td->setAttribute(html_names::kClassAttr, AtomicString("line-content"));
  trow->ParserAppendChild(td);
  current_ = td_ = td;

  // Open up the needed spans.
  if (!class_name.empty()) {
    if (class_name == "html-attribute-name" ||
        class_name == "html-attribute-value")
      current_ = AddSpanWithClassName(class_tag_);
    current_ = AddSpanWithClassName(class_name);
  }
}

void HTMLViewSourceDocument::FinishLine() {
  if (!current_->HasChildren()) {
    auto* br = MakeGarbageCollected<HTMLBRElement>(*this);
    current_->ParserAppendChild(br);
  }
  current_ = tbody_;
}

void HTMLViewSourceDocument::AddText(const String& text,
                                     const AtomicString& class_name) {
  if (text.empty())
    return;

  // Add in the content, splitting on linebreaks.
  // \r and \n both count as linebreaks, but \r\n only counts as one linebreak.
  Vector<String> lines;
  {
    unsigned start_pos = 0;
    unsigned pos = 0;
    while (pos < text.length()) {
      if (text[pos] == '\r') {
        lines.push_back(text.Substring(start_pos, pos - start_pos));
        pos++;
        if (pos < text.length() && text[pos] == '\n') {
          pos++;  // \r\n counts as a single line break.
        }
        start_pos = pos;
      } else if (text[pos] == '\n') {
        lines.push_back(text.Substring(start_pos, pos - start_pos));
        pos++;
        start_pos = pos;
      } else {
        pos++;
      }
    }
    lines.push_back(text.Substring(start_pos, text.length() - start_pos));
  }

  unsigned size = lines.size();
  for (unsigned i = 0; i < size; i++) {
    String substring = lines[i];
    if (current_ == tbody_)
      AddLine(class_name);
    if (substring.empty()) {
      if (i == size - 1)
        break;
      FinishLine();
      continue;
    }
    Element* old_element = current_;
    current_->ParserAppendChild(Text::Create(*this, substring));
    current_ = old_element;
    if (i < size - 1)
      FinishLine();
  }
}

int HTMLViewSourceDocument::AddRange(const String& source,
                                     int start,
                                     int end,
                                     const AtomicString& class_name,
                                     bool is_link,
                                     bool is_anchor,
                                     const AtomicString& link) {
  DCHECK_LE(start, end);
  if (start == end)
    return start;

  String text = source.Substring(start, end - start);
  if (!class_name.empty()) {
    if (is_link)
      current_ = AddLink(link, is_anchor);
    else
      current_ = AddSpanWithClassName(class_name);
  }
  AddText(text, class_name);
  if (!class_name.empty() && current_ != tbody_)
    current_ = To<Element>(current_->parentNode());
  return end;
}

Element* HTMLViewSourceDocument::AddBase(const AtomicString& href) {
  auto* base = MakeGarbageCollected<HTMLBaseElement>(*this);
  base->setAttribute(html_names::kHrefAttr, href);
  current_->ParserAppendChild(base);
  return base;
}

Element* HTMLViewSourceDocument::AddLink(const AtomicString& url,
                                         bool is_anchor) {
  if (current_ == tbody_)
    AddLine(class_tag_);

  // Now create a link for the attribute value instead of a span.
  auto* anchor = MakeGarbageCollected<HTMLAnchorElement>(*this);
  const char* class_value;
  if (is_anchor)
    class_value = "html-attribute-value html-external-link";
  else
    class_value = "html-attribute-value html-resource-link";
  anchor->setAttribute(html_names::kClassAttr, AtomicString(class_value));
  anchor->setAttribute(html_names::kTargetAttr, AtomicString("_blank"));
  anchor->setAttribute(html_names::kHrefAttr, url);
  anchor->setAttribute(html_names::kRelAttr,
                       AtomicString("noreferrer noopener"));
  // Disallow JavaScript hrefs. https://crbug.com/808407
  if (anchor->Url().ProtocolIsJavaScript())
    anchor->setAttribute(html_names::kHrefAttr, AtomicString("about:blank"));
  current_->ParserAppendChild(anchor);
  return anchor;
}

int HTMLViewSourceDocument::AddSrcset(const String& source,
                                      int start,
                                      int end) {
  String srcset = source.Substring(start, end - start);
  Vector<String> srclist;
  srcset.Split(',', true, srclist);
  unsigned size = srclist.size();
  for (unsigned i = 0; i < size; i++) {
    Vector<String> tmp;
    srclist[i].Split(' ', tmp);
    if (tmp.size() > 0) {
      AtomicString link(tmp[0]);
      current_ = AddLink(link, false);
      AddText(srclist[i], class_attribute_value_);
      current_ = To<Element>(current_->parentNode());
    } else {
      AddText(srclist[i], class_attribute_value_);
    }
    if (i + 1 < size)
      AddText(",", class_attribute_value_);
  }
  return end;
}

void HTMLViewSourceDocument::Trace(Visitor* visitor) const {
  visitor->Trace(current_);
  visitor->Trace(tbody_);
  visitor->Trace(td_);
  HTMLDocument::Trace(visitor);
}

}  // namespace blink
```