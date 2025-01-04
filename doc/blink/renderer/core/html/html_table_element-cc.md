Response:
My thinking process to analyze the `HTMLTableElement.cc` file went through these steps:

1. **Identify the Core Purpose:**  The file name `html_table_element.cc` immediately tells me this file defines the behavior and properties of the `<table>` HTML element within the Blink rendering engine.

2. **Scan for Key Classes and Methods:** I quickly scanned the code for class names, method names, and included headers. This gives a high-level overview of the functionalities. I noticed includes like `HTMLTableCaptionElement`, `HTMLTableRowElement`, `CSSPropertyValueSet`, and methods like `insertRow`, `deleteRow`, `setCaption`, `setTHead`, etc. These immediately suggest the file handles the structure and manipulation of table elements.

3. **Analyze Functionality Groupings:** I started categorizing the identified methods and data members based on their apparent purpose. I noticed groups related to:
    * **Structure Manipulation:**  Methods like `setCaption`, `setTHead`, `setTFoot`, `createTHead`, `createTBody`, `insertRow`, `deleteRow` clearly deal with adding and removing table parts.
    * **Attribute Handling:**  Methods like `ParseAttribute`, `CollectStyleForPresentationAttribute`, `IsPresentationAttribute` indicate the file processes HTML attributes of the `<table>` tag.
    * **Styling:**  Includes related to CSS and methods like `AdditionalPresentationAttributeStyle`, `AdditionalCellStyle`, `AdditionalGroupStyle`, and the handling of attributes like `border`, `bgcolor`, `cellspacing` strongly suggest the file influences the visual presentation of the table.
    * **Collections:**  Methods like `rows()` and `tBodies()` point to managing collections of child elements.

4. **Connect to Web Technologies:** As I identified these groups, I started connecting them to their corresponding roles in web development:
    * **HTML:** The manipulation of caption, head, foot, rows, and bodies directly relates to the structure defined by HTML `<table>` and its related tags.
    * **CSS:** The styling aspects, attribute handling related to visual properties, and the creation of `CSSPropertyValueSet` objects directly tie into how CSS styles the table.
    * **JavaScript:**  The methods for inserting and deleting rows, and the getters/setters for caption, head, and foot elements are all directly exposed to JavaScript for dynamic manipulation of the table.

5. **Look for Specific Examples and Logic:**  I then went deeper into specific methods to understand the logic and identify concrete examples.
    * **Attribute Mapping to CSS:**  I noticed how HTML attributes like `border`, `bgcolor`, `align`, `cellspacing`, and `rules` are translated into corresponding CSS properties. This allowed me to create illustrative examples.
    * **Error Handling:** I looked for `ExceptionState` usage, particularly in methods like `insertRow` and `deleteRow`, to understand how the code handles invalid input (e.g., out-of-bounds indices).
    * **Conditional Logic:** I examined the `if/else` structures within methods like `GetCellBorders` and the attribute parsing functions to understand how different attribute values lead to different internal states or CSS styles. This is where I could infer the input/output behavior.

6. **Identify Potential User Errors:**  Based on the error handling and the functionality provided, I could identify common user errors, such as providing incorrect indices for row manipulation or using invalid attribute values.

7. **Refine and Structure the Output:** Finally, I organized my findings into the requested categories: functionalities, relationships with web technologies (with examples), logical reasoning (with input/output), and common user errors. I aimed for clarity and provided concrete code snippets or conceptual explanations where necessary.

**Self-Correction/Refinement during the process:**

* **Initial Broadness:** My initial scan might have been too broad. I had to refine my focus to the core functionalities and avoid getting bogged down in every detail.
* **Connecting the Dots:** I constantly checked if my understanding of a specific method or code block aligned with its broader purpose within the `HTMLTableElement`. For example, realizing that `SetNeedsTableStyleRecalc` is a crucial step after attribute changes to ensure the rendering is updated.
* **Clarity of Examples:**  I made sure the examples I provided were clear and directly illustrated the point I was making about the relationship with HTML, CSS, or JavaScript.
* **Addressing All Prompts:** I revisited the original prompt to ensure I had addressed all aspects, including the functionalities, relationships with web technologies, logical reasoning, and user errors.

By following this structured approach, combining high-level overview with detailed analysis, and continuously connecting the code to its role in web technologies, I could effectively analyze the `HTMLTableElement.cc` file and generate a comprehensive summary.
这个文件 `blink/renderer/core/html/html_table_element.cc` 是 Chromium Blink 渲染引擎中负责处理 HTML `<table>` 元素的核心代码。它定义了 `HTMLTableElement` 类，该类继承自 `HTMLElement`，并实现了与 HTML 表格相关的各种功能。

以下是该文件的主要功能及其与 JavaScript、HTML 和 CSS 的关系，以及一些逻辑推理的例子和常见用户错误：

**功能列举:**

1. **表示和操作 HTML `<table>` 元素:**  这是最基本的功能。该文件定义了 `HTMLTableElement` 类，作为 HTML 文档中 `<table>` 标签在内存中的表示。
2. **管理表格的子元素:**  包括 `<caption>`, `<thead>`, `<tfoot>`, `<tbody>`, `<tr>` 等元素。  该文件提供了访问和修改这些子元素的方法，例如：
    * `caption()`: 获取表格的 `<caption>` 元素。
    * `setCaption()`: 设置表格的 `<caption>` 元素。
    * `tHead()`: 获取表格的 `<thead>` 元素。
    * `setTHead()`: 设置表格的 `<thead>` 元素。
    * `tFoot()`: 获取表格的 `<tfoot>` 元素。
    * `setTFoot()`: 设置表格的 `<tfoot>` 元素。
    * `createTHead()`, `deleteTHead()`, `createTFoot()`, `deleteTFoot()`, `createTBody()`, `deleteCaption()`:  创建和删除这些子元素。
3. **管理表格行:** 提供了插入和删除行的方法：
    * `insertRow()`: 在表格中插入一个新行。
    * `deleteRow()`: 删除表格中的指定行。
4. **处理表格的 HTML 属性:**  例如 `border`, `cellspacing`, `cellpadding`, `align`, `bgcolor`, `rules`, `frame` 等。该文件负责解析这些属性，并将它们转化为内部状态或影响表格的渲染。
5. **影响表格的 CSS 样式:**  虽然具体的样式计算由 Blink 的 CSS 引擎负责，但 `HTMLTableElement` 会根据 HTML 属性生成一些默认的或影响 CSS 计算的样式。例如，根据 `border` 属性设置边框宽度，根据 `rules` 属性影响边框的显示方式。
6. **提供 JavaScript 接口:**  该文件中定义的方法会被暴露给 JavaScript，允许脚本动态地操作表格的结构和属性。例如，JavaScript 可以调用 `tableElement.insertRow()` 来添加新的行。
7. **处理表格的布局和渲染:** 虽然具体的布局算法在其他文件中实现，但 `HTMLTableElement` 的状态和属性会影响表格的最终渲染结果。例如，`cellspacing` 属性会影响单元格之间的间距。
8. **维护表格元素的集合:**  例如 `rows()` 返回一个包含表格所有行的 `HTMLTableRowsCollection` 对象，`tBodies()` 返回包含所有 `<tbody>` 元素的 `HTMLCollection` 对象。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**
    * **功能:** 该文件中的类对应于 HTML 中的 `<table>` 标签。
    * **举例:** 当 HTML 解析器遇到 `<table>` 标签时，会创建一个 `HTMLTableElement` 对象来表示它。文件中定义的属性和方法对应于 `<table>` 标签的属性和可以进行的操作。
    * **假设输入:** HTML 代码 `<table border="1"><tr><td>Data</td></tr></table>`
    * **输出:**  会创建一个 `HTMLTableElement` 对象，其 `border_attr_` 内部状态会被设置为 `true` (或相应的数值表示)。

* **JavaScript:**
    * **功能:**  JavaScript 可以通过 DOM API 访问和操作 `HTMLTableElement` 对象。
    * **举例:** JavaScript 代码 `document.getElementById('myTable').insertRow();` 会调用 `HTMLTableElement` 中的 `insertRow()` 方法，在表格中动态插入一行。
    * **假设输入:**  JavaScript 代码获取一个 `<table>` 元素，并调用 `insertRow(0)`。
    * **输出:**  会在表格的开头插入一个新的 `<tr>` 元素。

* **CSS:**
    * **功能:**  CSS 规则可以用来设置 `<table>` 元素的样式，而 `HTMLTableElement` 的某些属性会影响默认样式或与 CSS 属性的交互。
    * **举例:**  HTML 属性 `border="2"` 会影响表格边框的默认渲染，CSS 属性 `border-collapse: collapse;` 可以覆盖默认的边框行为。 文件中的 `CollectStyleForPresentationAttribute` 方法展示了如何将 HTML 属性转换为 CSS 属性。
    * **假设输入:** HTML 代码 `<table rules="rows">`。
    * **输出:**  在渲染时，Blink 会应用 `border-collapse: collapse;` 样式，并且只在行之间显示边框。  `GetCellBorders()` 方法会根据 `rules` 属性返回相应的枚举值，最终影响单元格的默认边框样式。

**逻辑推理的例子 (假设输入与输出):**

* **假设输入:**  一个空的 `<table>` 元素，然后调用 JavaScript 代码 `table.insertRow();`。
* **输出:**  `insertRow()` 方法会检测到表格没有 `<tbody>`，因此会自动创建一个 `<tbody>` 元素，然后在其中插入一个新的 `<tr>` 元素。

* **假设输入:**  一个带有 `<thead>` 和 `<tbody>` 的表格，调用 JavaScript 代码 `table.insertRow(1);`。
* **输出:**  `insertRow(1)` 方法会遍历表格的行（包括 `<thead>` 中的行），然后在索引为 1 的位置（即 `<thead>` 之后的第一行）插入一个新的 `<tr>` 元素。

* **假设输入:**  一个 `<table>` 元素，设置了 HTML 属性 `cellspacing="10"`。
* **输出:**  `ParseAttribute` 方法会解析 `cellspacing` 属性的值，并将其存储在 `padding_` 成员变量中。  这最终会影响渲染时单元格之间的水平和垂直间距。  `CollectStyleForPresentationAttribute` 方法会将 `cellspacing` 转换为 CSS 属性 `-webkit-border-horizontal-spacing` 和 `-webkit-border-vertical-spacing`。

**涉及用户或编程常见的使用错误举例说明:**

1. **使用错误的索引插入或删除行:**
    * **错误:** JavaScript 代码 `table.insertRow(100);`  在一个只有 5 行的表格上调用。
    * **结果:**  `insertRow()` 方法会抛出一个 `DOMException`，错误代码为 `INDEX_SIZE_ERR`，因为提供的索引超出了表格的行数。

2. **尝试设置非法的子元素:**
    * **错误:** JavaScript 代码尝试使用 `setTHead()` 设置一个不是 `<thead`>` 元素的节点。
    * **结果:**  `setTHead()` 方法会检查传入的节点类型，如果不是 `HTMLTableSectionElement` 且标签名为 "thead"，则会抛出一个 `DOMException`，错误代码为 `HIERARCHY_REQUEST_ERR`。

3. **混淆 `deleteRow(-1)` 的行为:**
    * **常见误解:**  认为 `deleteRow(-1)` 会删除索引为 -1 的行（不存在）。
    * **正确行为:** `deleteRow(-1)` 会删除表格中的最后一行。  用户可能会错误地假设 -1 代表“不删除任何行”。

4. **过度依赖 HTML 属性进行样式设置:**
    * **问题:** 虽然 HTML 属性如 `border`, `bgcolor` 可以设置表格的样式，但推荐使用 CSS 进行样式控制，因为 CSS 提供了更强大和灵活的样式设置能力。过度依赖 HTML 属性会导致样式难以维护和管理。

5. **忘记 `<tbody>` 的重要性:**
    * **问题:**  在动态添加行时，如果没有显式创建 `<tbody>` 元素，浏览器会自动创建。开发者可能没有意识到这一点，导致一些操作行为不符合预期。

总而言之，`html_table_element.cc` 文件是 Blink 渲染引擎中关于 HTML 表格的核心实现，它负责表格元素的创建、属性解析、子元素管理，并提供了与 JavaScript 和 CSS 交互的基础。理解这个文件有助于深入了解浏览器如何处理和渲染 HTML 表格。

Prompt: 
```
这是目录为blink/renderer/core/html/html_table_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 1997 Martin Jones (mjones@kde.org)
 *           (C) 1997 Torben Weis (weis@kde.org)
 *           (C) 1998 Waldo Bastian (bastian@kde.org)
 *           (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 * Copyright (C) 2003, 2004, 2005, 2006, 2008, 2010, 2011 Apple Inc. All rights
 * reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/html/html_table_element.h"

#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_inherited_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/node_lists_node_data.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/html_table_caption_element.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_row_element.h"
#include "third_party/blink/renderer/core/html/html_table_rows_collection.h"
#include "third_party/blink/renderer/core/html/html_table_section_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/weborigin/referrer.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

HTMLTableElement::HTMLTableElement(Document& document)
    : HTMLElement(html_names::kTableTag, document),
      border_attr_(false),
      border_color_attr_(false),
      frame_attr_(false),
      rules_attr_(kUnsetRules),
      padding_(1) {}

// An explicit empty destructor should be in html_table_element.cc, because
// if an implicit destructor is used or an empty destructor is defined in
// html_table_element.h, when including html_table_element.h, msvc tries to
// expand the destructor and causes a compile error because of lack of
// CSSPropertyValueSet definition.
HTMLTableElement::~HTMLTableElement() = default;

HTMLTableCaptionElement* HTMLTableElement::caption() const {
  return Traversal<HTMLTableCaptionElement>::FirstChild(*this);
}

void HTMLTableElement::setCaption(HTMLTableCaptionElement* new_caption,
                                  ExceptionState& exception_state) {
  deleteCaption();
  if (new_caption)
    InsertBefore(new_caption, firstChild(), exception_state);
}

HTMLTableSectionElement* HTMLTableElement::tHead() const {
  return To<HTMLTableSectionElement>(Traversal<HTMLElement>::FirstChild(
      *this, HasHTMLTagName(html_names::kTheadTag)));
}

void HTMLTableElement::setTHead(HTMLTableSectionElement* new_head,
                                ExceptionState& exception_state) {
  if (new_head && !new_head->HasTagName(html_names::kTheadTag)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kHierarchyRequestError,
                                      "Not a thead element.");
    return;
  }

  deleteTHead();
  if (!new_head)
    return;

  HTMLElement* child;
  for (child = Traversal<HTMLElement>::FirstChild(*this); child;
       child = Traversal<HTMLElement>::NextSibling(*child)) {
    if (!child->HasTagName(html_names::kCaptionTag) &&
        !child->HasTagName(html_names::kColgroupTag))
      break;
  }

  InsertBefore(new_head, child, exception_state);
}

HTMLTableSectionElement* HTMLTableElement::tFoot() const {
  return To<HTMLTableSectionElement>(Traversal<HTMLElement>::FirstChild(
      *this, HasHTMLTagName(html_names::kTfootTag)));
}

void HTMLTableElement::setTFoot(HTMLTableSectionElement* new_foot,
                                ExceptionState& exception_state) {
  if (new_foot && !new_foot->HasTagName(html_names::kTfootTag)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kHierarchyRequestError,
                                      "Not a tfoot element.");
    return;
  }

  deleteTFoot();

  if (new_foot)
    AppendChild(new_foot, exception_state);
}

HTMLTableSectionElement* HTMLTableElement::createTHead() {
  if (HTMLTableSectionElement* existing_head = tHead())
    return existing_head;
  auto* head = MakeGarbageCollected<HTMLTableSectionElement>(
      html_names::kTheadTag, GetDocument());
  setTHead(head, IGNORE_EXCEPTION_FOR_TESTING);
  return head;
}

void HTMLTableElement::deleteTHead() {
  RemoveChild(tHead(), IGNORE_EXCEPTION_FOR_TESTING);
}

HTMLTableSectionElement* HTMLTableElement::createTFoot() {
  if (HTMLTableSectionElement* existing_foot = tFoot())
    return existing_foot;
  auto* foot = MakeGarbageCollected<HTMLTableSectionElement>(
      html_names::kTfootTag, GetDocument());
  setTFoot(foot, IGNORE_EXCEPTION_FOR_TESTING);
  return foot;
}

void HTMLTableElement::deleteTFoot() {
  RemoveChild(tFoot(), IGNORE_EXCEPTION_FOR_TESTING);
}

HTMLTableSectionElement* HTMLTableElement::createTBody() {
  auto* body = MakeGarbageCollected<HTMLTableSectionElement>(
      html_names::kTbodyTag, GetDocument());
  Node* reference_element = LastBody() ? LastBody()->nextSibling() : nullptr;

  InsertBefore(body, reference_element);
  return body;
}

HTMLTableCaptionElement* HTMLTableElement::createCaption() {
  if (HTMLTableCaptionElement* existing_caption = caption())
    return existing_caption;
  auto* caption = MakeGarbageCollected<HTMLTableCaptionElement>(GetDocument());
  setCaption(caption, IGNORE_EXCEPTION_FOR_TESTING);
  return caption;
}

void HTMLTableElement::deleteCaption() {
  RemoveChild(caption(), IGNORE_EXCEPTION_FOR_TESTING);
}

HTMLTableSectionElement* HTMLTableElement::LastBody() const {
  return To<HTMLTableSectionElement>(Traversal<HTMLElement>::LastChild(
      *this, HasHTMLTagName(html_names::kTbodyTag)));
}

HTMLTableRowElement* HTMLTableElement::insertRow(
    int index,
    ExceptionState& exception_state) {
  if (index < -1) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The index provided (" + String::Number(index) + ") is less than -1.");
    return nullptr;
  }

  HTMLTableRowElement* last_row = nullptr;
  HTMLTableRowElement* row = nullptr;
  if (index == -1) {
    last_row = HTMLTableRowsCollection::LastRow(*this);
  } else {
    for (int i = 0; i <= index; ++i) {
      row = HTMLTableRowsCollection::RowAfter(*this, last_row);
      if (!row) {
        if (i != index) {
          exception_state.ThrowDOMException(
              DOMExceptionCode::kIndexSizeError,
              "The index provided (" + String::Number(index) +
                  ") is greater than the number of rows in the table (" +
                  String::Number(i) + ").");
          return nullptr;
        }
        break;
      }
      last_row = row;
    }
  }

  ContainerNode* parent;
  if (last_row) {
    parent = row ? row->parentNode() : last_row->parentNode();
  } else {
    parent = LastBody();
    if (!parent) {
      auto* new_body = MakeGarbageCollected<HTMLTableSectionElement>(
          html_names::kTbodyTag, GetDocument());
      auto* new_row = MakeGarbageCollected<HTMLTableRowElement>(GetDocument());
      new_body->AppendChild(new_row, exception_state);
      AppendChild(new_body, exception_state);
      return new_row;
    }
  }

  auto* new_row = MakeGarbageCollected<HTMLTableRowElement>(GetDocument());
  parent->InsertBefore(new_row, row, exception_state);
  return new_row;
}

void HTMLTableElement::deleteRow(int index, ExceptionState& exception_state) {
  if (index < -1) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The index provided (" + String::Number(index) + ") is less than -1.");
    return;
  }

  HTMLTableRowElement* row = nullptr;
  int i = 0;
  if (index == -1) {
    row = HTMLTableRowsCollection::LastRow(*this);
    if (!row)
      return;
  } else {
    for (i = 0; i <= index; ++i) {
      row = HTMLTableRowsCollection::RowAfter(*this, row);
      if (!row)
        break;
    }
  }
  if (!row) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The index provided (" + String::Number(index) +
            ") is greater than the number of rows in the table (" +
            String::Number(i) + ").");
    return;
  }
  row->remove(exception_state);
}

void HTMLTableElement::SetNeedsTableStyleRecalc() const {
  Element* element = ElementTraversal::Next(*this, this);
  while (element) {
    element->SetNeedsStyleRecalc(
        kLocalStyleChange,
        StyleChangeReasonForTracing::FromAttribute(html_names::kRulesAttr));
    if (IsA<HTMLTableCellElement>(*element))
      element = ElementTraversal::NextSkippingChildren(*element, this);
    else
      element = ElementTraversal::Next(*element, this);
  }
}

static bool GetBordersFromFrameAttributeValue(const AtomicString& value,
                                              bool& border_top,
                                              bool& border_right,
                                              bool& border_bottom,
                                              bool& border_left) {
  border_top = false;
  border_right = false;
  border_bottom = false;
  border_left = false;

  if (EqualIgnoringASCIICase(value, "above"))
    border_top = true;
  else if (EqualIgnoringASCIICase(value, "below"))
    border_bottom = true;
  else if (EqualIgnoringASCIICase(value, "hsides"))
    border_top = border_bottom = true;
  else if (EqualIgnoringASCIICase(value, "vsides"))
    border_left = border_right = true;
  else if (EqualIgnoringASCIICase(value, "lhs"))
    border_left = true;
  else if (EqualIgnoringASCIICase(value, "rhs"))
    border_right = true;
  else if (EqualIgnoringASCIICase(value, "box") ||
           EqualIgnoringASCIICase(value, "border"))
    border_top = border_bottom = border_left = border_right = true;
  else if (!EqualIgnoringASCIICase(value, "void"))
    return false;
  return true;
}

void HTMLTableElement::CollectStyleForPresentationAttribute(
    const QualifiedName& name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  if (name == html_names::kWidthAttr) {
    AddHTMLLengthToStyle(style, CSSPropertyID::kWidth, value,
                         kAllowPercentageValues, kDontAllowZeroValues);
  } else if (name == html_names::kHeightAttr) {
    AddHTMLLengthToStyle(style, CSSPropertyID::kHeight, value);
  } else if (name == html_names::kBorderAttr) {
    unsigned width = ParseBorderWidthAttribute(value);
    AddPropertyToPresentationAttributeStyle(
        style, CSSPropertyID::kBorderTopWidth, width,
        CSSPrimitiveValue::UnitType::kPixels);
    AddPropertyToPresentationAttributeStyle(
        style, CSSPropertyID::kBorderBottomWidth, width,
        CSSPrimitiveValue::UnitType::kPixels);
    AddPropertyToPresentationAttributeStyle(
        style, CSSPropertyID::kBorderLeftWidth, width,
        CSSPrimitiveValue::UnitType::kPixels);
    AddPropertyToPresentationAttributeStyle(
        style, CSSPropertyID::kBorderRightWidth, width,
        CSSPrimitiveValue::UnitType::kPixels);
  } else if (name == html_names::kBordercolorAttr) {
    if (!value.empty())
      AddHTMLColorToStyle(style, CSSPropertyID::kBorderColor, value);
  } else if (name == html_names::kBgcolorAttr) {
    AddHTMLColorToStyle(style, CSSPropertyID::kBackgroundColor, value);
  } else if (name == html_names::kBackgroundAttr) {
    AddHTMLBackgroundImageToStyle(style, value);
  } else if (name == html_names::kValignAttr) {
    if (!value.empty()) {
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kVerticalAlign, value);
    }
  } else if (name == html_names::kCellspacingAttr) {
    if (!value.empty()) {
      for (CSSPropertyID property_id :
           {CSSPropertyID::kWebkitBorderHorizontalSpacing,
            CSSPropertyID::kWebkitBorderVerticalSpacing}) {
        AddHTMLLengthToStyle(style, property_id, value,
                             kDontAllowPercentageValues);
      }
    }
  } else if (name == html_names::kAlignAttr) {
    if (!value.empty()) {
      if (EqualIgnoringASCIICase(value, "center")) {
        AddPropertyToPresentationAttributeStyle(
            style, CSSPropertyID::kMarginInlineStart, CSSValueID::kAuto);
        AddPropertyToPresentationAttributeStyle(
            style, CSSPropertyID::kMarginInlineEnd, CSSValueID::kAuto);
      } else {
        AddPropertyToPresentationAttributeStyle(style, CSSPropertyID::kFloat,
                                                value);
      }
    }
  } else if (name == html_names::kRulesAttr) {
    // The presence of a valid rules attribute causes border collapsing to be
    // enabled.
    if (rules_attr_ != kUnsetRules) {
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kBorderCollapse, CSSValueID::kCollapse);
    }
  } else if (name == html_names::kFrameAttr) {
    bool border_top;
    bool border_right;
    bool border_bottom;
    bool border_left;
    if (GetBordersFromFrameAttributeValue(value, border_top, border_right,
                                          border_bottom, border_left)) {
      for (CSSPropertyID property_id :
           {CSSPropertyID::kBorderTopWidth, CSSPropertyID::kBorderBottomWidth,
            CSSPropertyID::kBorderLeftWidth,
            CSSPropertyID::kBorderRightWidth}) {
        AddPropertyToPresentationAttributeStyle(style, property_id,
                                                CSSValueID::kThin);
      }
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kBorderTopStyle,
          border_top ? CSSValueID::kSolid : CSSValueID::kHidden);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kBorderBottomStyle,
          border_bottom ? CSSValueID::kSolid : CSSValueID::kHidden);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kBorderLeftStyle,
          border_left ? CSSValueID::kSolid : CSSValueID::kHidden);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kBorderRightStyle,
          border_right ? CSSValueID::kSolid : CSSValueID::kHidden);
    }
  } else {
    HTMLElement::CollectStyleForPresentationAttribute(name, value, style);
  }
}

bool HTMLTableElement::IsPresentationAttribute(
    const QualifiedName& name) const {
  if (name == html_names::kWidthAttr || name == html_names::kHeightAttr ||
      name == html_names::kBgcolorAttr || name == html_names::kBackgroundAttr ||
      name == html_names::kValignAttr || name == html_names::kVspaceAttr ||
      name == html_names::kHspaceAttr || name == html_names::kAlignAttr ||
      name == html_names::kCellspacingAttr || name == html_names::kBorderAttr ||
      name == html_names::kBordercolorAttr || name == html_names::kFrameAttr ||
      name == html_names::kRulesAttr)
    return true;
  return HTMLElement::IsPresentationAttribute(name);
}

void HTMLTableElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  CellBorders borders_before = GetCellBorders();
  uint16_t old_padding = padding_;

  if (name == html_names::kBorderAttr) {
    // FIXME: This attribute is a mess.
    border_attr_ = ParseBorderWidthAttribute(params.new_value);
  } else if (name == html_names::kBordercolorAttr) {
    border_color_attr_ = !params.new_value.empty();
  } else if (name == html_names::kFrameAttr) {
    // FIXME: This attribute is a mess.
    bool border_top;
    bool border_right;
    bool border_bottom;
    bool border_left;
    frame_attr_ = GetBordersFromFrameAttributeValue(
        params.new_value, border_top, border_right, border_bottom, border_left);
  } else if (name == html_names::kRulesAttr) {
    rules_attr_ = kUnsetRules;
    if (EqualIgnoringASCIICase(params.new_value, "none"))
      rules_attr_ = kNoneRules;
    else if (EqualIgnoringASCIICase(params.new_value, "groups"))
      rules_attr_ = kGroupsRules;
    else if (EqualIgnoringASCIICase(params.new_value, "rows"))
      rules_attr_ = kRowsRules;
    else if (EqualIgnoringASCIICase(params.new_value, "cols"))
      rules_attr_ = kColsRules;
    else if (EqualIgnoringASCIICase(params.new_value, "all"))
      rules_attr_ = kAllRules;
  } else if (params.name == html_names::kCellpaddingAttr) {
    if (!params.new_value.empty()) {
      padding_ =
          std::max(0, std::min((int32_t)std::numeric_limits<uint16_t>::max(),
                               params.new_value.ToInt()));
    } else {
      padding_ = 1;
    }
  } else if (params.name == html_names::kColsAttr) {
    // ###
  } else {
    HTMLElement::ParseAttribute(params);
  }

  if (borders_before != GetCellBorders() || old_padding != padding_) {
    shared_cell_style_ = nullptr;
    SetNeedsTableStyleRecalc();
  }
}

static CSSPropertyValueSet* CreateBorderStyle(CSSValueID value) {
  auto* style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  style->SetLonghandProperty(CSSPropertyID::kBorderTopStyle, value);
  style->SetLonghandProperty(CSSPropertyID::kBorderBottomStyle, value);
  style->SetLonghandProperty(CSSPropertyID::kBorderLeftStyle, value);
  style->SetLonghandProperty(CSSPropertyID::kBorderRightStyle, value);
  return style;
}

const CSSPropertyValueSet*
HTMLTableElement::AdditionalPresentationAttributeStyle() {
  if (frame_attr_)
    return nullptr;

  if (!border_attr_ && !border_color_attr_) {
    // Setting the border to 'hidden' allows it to win over any border
    // set on the table's cells during border-conflict resolution.
    if (rules_attr_ != kUnsetRules) {
      DEFINE_STATIC_LOCAL(Persistent<CSSPropertyValueSet>, solid_border_style,
                          (CreateBorderStyle(CSSValueID::kHidden)));
      return solid_border_style;
    }
    return nullptr;
  }

  if (border_color_attr_) {
    DEFINE_STATIC_LOCAL(Persistent<CSSPropertyValueSet>, solid_border_style,
                        (CreateBorderStyle(CSSValueID::kSolid)));
    return solid_border_style;
  }
  DEFINE_STATIC_LOCAL(Persistent<CSSPropertyValueSet>, outset_border_style,
                      (CreateBorderStyle(CSSValueID::kOutset)));
  return outset_border_style;
}

HTMLTableElement::CellBorders HTMLTableElement::GetCellBorders() const {
  switch (rules_attr_) {
    case kNoneRules:
    case kGroupsRules:
      return kNoBorders;
    case kAllRules:
      return kSolidBorders;
    case kColsRules:
      return kSolidBordersColsOnly;
    case kRowsRules:
      return kSolidBordersRowsOnly;
    case kUnsetRules:
      if (!border_attr_)
        return kNoBorders;
      if (border_color_attr_)
        return kSolidBorders;
      return kInsetBorders;
  }
  NOTREACHED();
}

CSSPropertyValueSet* HTMLTableElement::CreateSharedCellStyle() {
  auto* style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);

  switch (GetCellBorders()) {
    case kSolidBordersColsOnly:
      style->SetLonghandProperty(CSSPropertyID::kBorderLeftWidth,
                                 CSSValueID::kThin);
      style->SetLonghandProperty(CSSPropertyID::kBorderRightWidth,
                                 CSSValueID::kThin);
      style->SetLonghandProperty(CSSPropertyID::kBorderLeftStyle,
                                 CSSValueID::kSolid);
      style->SetLonghandProperty(CSSPropertyID::kBorderRightStyle,
                                 CSSValueID::kSolid);
      style->SetProperty(CSSPropertyID::kBorderColor,
                         *CSSInheritedValue::Create());
      break;
    case kSolidBordersRowsOnly:
      style->SetLonghandProperty(CSSPropertyID::kBorderTopWidth,
                                 CSSValueID::kThin);
      style->SetLonghandProperty(CSSPropertyID::kBorderBottomWidth,
                                 CSSValueID::kThin);
      style->SetLonghandProperty(CSSPropertyID::kBorderTopStyle,
                                 CSSValueID::kSolid);
      style->SetLonghandProperty(CSSPropertyID::kBorderBottomStyle,
                                 CSSValueID::kSolid);
      style->SetProperty(CSSPropertyID::kBorderColor,
                         *CSSInheritedValue::Create());
      break;
    case kSolidBorders:
      style->SetProperty(CSSPropertyID::kBorderWidth,
                         *CSSNumericLiteralValue::Create(
                             1, CSSPrimitiveValue::UnitType::kPixels));
      style->SetProperty(CSSPropertyID::kBorderStyle,
                         *CSSIdentifierValue::Create(CSSValueID::kSolid));
      style->SetProperty(CSSPropertyID::kBorderColor,
                         *CSSInheritedValue::Create());
      break;
    case kInsetBorders:
      style->SetProperty(CSSPropertyID::kBorderWidth,
                         *CSSNumericLiteralValue::Create(
                             1, CSSPrimitiveValue::UnitType::kPixels));
      style->SetProperty(CSSPropertyID::kBorderStyle,
                         *CSSIdentifierValue::Create(CSSValueID::kInset));
      style->SetProperty(CSSPropertyID::kBorderColor,
                         *CSSInheritedValue::Create());
      break;
    case kNoBorders:
      // If 'rules=none' then allow any borders set at cell level to take
      // effect.
      break;
  }

  if (padding_)
    style->SetProperty(CSSPropertyID::kPadding,
                       *CSSNumericLiteralValue::Create(
                           padding_, CSSPrimitiveValue::UnitType::kPixels));

  return style;
}

const CSSPropertyValueSet* HTMLTableElement::AdditionalCellStyle() {
  if (!shared_cell_style_)
    shared_cell_style_ = CreateSharedCellStyle();
  return shared_cell_style_.Get();
}

static CSSPropertyValueSet* CreateGroupBorderStyle(int rows) {
  auto* style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  if (rows) {
    style->SetLonghandProperty(CSSPropertyID::kBorderTopWidth,
                               CSSValueID::kThin);
    style->SetLonghandProperty(CSSPropertyID::kBorderBottomWidth,
                               CSSValueID::kThin);
    style->SetLonghandProperty(CSSPropertyID::kBorderTopStyle,
                               CSSValueID::kSolid);
    style->SetLonghandProperty(CSSPropertyID::kBorderBottomStyle,
                               CSSValueID::kSolid);
  } else {
    style->SetLonghandProperty(CSSPropertyID::kBorderLeftWidth,
                               CSSValueID::kThin);
    style->SetLonghandProperty(CSSPropertyID::kBorderRightWidth,
                               CSSValueID::kThin);
    style->SetLonghandProperty(CSSPropertyID::kBorderLeftStyle,
                               CSSValueID::kSolid);
    style->SetLonghandProperty(CSSPropertyID::kBorderRightStyle,
                               CSSValueID::kSolid);
  }
  return style;
}

const CSSPropertyValueSet* HTMLTableElement::AdditionalGroupStyle(bool rows) {
  if (rules_attr_ != kGroupsRules)
    return nullptr;

  if (rows) {
    DEFINE_STATIC_LOCAL(Persistent<CSSPropertyValueSet>, row_border_style,
                        (CreateGroupBorderStyle(true)));
    return row_border_style;
  }
  DEFINE_STATIC_LOCAL(Persistent<CSSPropertyValueSet>, column_border_style,
                      (CreateGroupBorderStyle(false)));
  return column_border_style;
}

bool HTMLTableElement::IsURLAttribute(const Attribute& attribute) const {
  return attribute.GetName() == html_names::kBackgroundAttr ||
         HTMLElement::IsURLAttribute(attribute);
}

bool HTMLTableElement::HasLegalLinkAttribute(const QualifiedName& name) const {
  return name == html_names::kBackgroundAttr ||
         HTMLElement::HasLegalLinkAttribute(name);
}

HTMLTableRowsCollection* HTMLTableElement::rows() {
  return EnsureCachedCollection<HTMLTableRowsCollection>(kTableRows);
}

HTMLCollection* HTMLTableElement::tBodies() {
  return EnsureCachedCollection<HTMLCollection>(kTableTBodies);
}

const AtomicString& HTMLTableElement::Rules() const {
  return FastGetAttribute(html_names::kRulesAttr);
}

const AtomicString& HTMLTableElement::Summary() const {
  return FastGetAttribute(html_names::kSummaryAttr);
}

void HTMLTableElement::Trace(Visitor* visitor) const {
  visitor->Trace(shared_cell_style_);
  HTMLElement::Trace(visitor);
}

}  // namespace blink

"""

```