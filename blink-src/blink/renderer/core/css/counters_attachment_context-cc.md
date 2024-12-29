Response:
My thought process to analyze the `counters_attachment_context.cc` file and answer the user's request would go like this:

1. **Understand the Core Functionality:**  The filename itself (`counters_attachment_context.cc`) strongly suggests it deals with CSS counters. The presence of terms like "increment," "reset," "stack," "inheritance," and references to HTML list elements further reinforces this. My initial hypothesis is that this code manages the state and behavior of CSS counters within the Blink rendering engine.

2. **Break Down the Code:** I'd scan the file for key structures and functions:
    * **`CountersAttachmentContext` class:** This is the main actor. I'd note its members like `counter_inheritance_table_`.
    * **`CounterEntry` struct:**  Represents a single counter instance. Crucially, it links to a `LayoutObject`.
    * **`CounterInheritanceTable`:**  A map to store counters, likely keyed by counter name. The value is a `CounterStack`.
    * **`CounterStack`:**  A stack data structure, indicating that counters can be nested or layered.
    * **`EnterObject` and `LeaveObject`:** These functions suggest this code is involved in processing elements as the layout tree is being traversed.
    * **`ProcessCounter`, `CreateCounter`, `UpdateCounterValue`, `RemoveStaleCounters`, `RemoveCounterIfAncestorExists`:** These function names clearly describe counter manipulation logic.
    * **`GetCounterValues`:** Used to retrieve counter values for CSS `counter()` and `counters()` functions.
    * **`MaybeCreateListItemCounter`:**  Handles implicit counter creation for list items.
    * **`ObscurePageCounterIfNeeded` and `UnobscurePageCounterIfNeeded`:**  Deal with the special behavior of counters within `@page` contexts.
    * **`EnterStyleContainmentScope` and `LeaveStyleContainmentScope`:**  Manage how CSS containment affects counters.
    * **Helper functions:** `IsAncestorOf`, `DetermineCounterTypeAndValue`, `IsReset`, `IsSetOrReset`, `CalculateCounterValue`.

3. **Identify Key Concepts and Relationships:**
    * **CSS Counters:** The fundamental concept. I'd recall how CSS counters work with `counter-increment`, `counter-reset`, `counter-set`, and the `counter()`/`counters()` functions.
    * **Layout Tree:** The code interacts heavily with `LayoutObject` and `Element`, indicating its role in the rendering process.
    * **DOM Tree:**  The code navigates the DOM using functions like `ParentElement`.
    * **Style System:** The code accesses `ComputedStyle` and `CounterDirectiveMap`.
    * **Inheritance:** The `counter_inheritance_table_` and the logic in functions like `RemoveStaleCounters` and `RemoveCounterIfAncestorExists` point to how counter values are inherited through the DOM tree.
    * **List Items:** Special handling for `<li>`, `<ol>`, `<ul>` suggests implicit counter creation for lists.
    * **Page Context:**  The code addresses the unique behavior of counters in `@page` rules.
    * **Style Containment:** The code manages how `contain` property affects counter scope.

4. **Connect to JavaScript, HTML, and CSS:**
    * **CSS:**  The most direct connection. The code implements the behavior defined by the CSS Counter Styles specification. I'd think of examples of how CSS counters are used (e.g., numbering sections, creating custom list markers).
    * **HTML:** The code interacts with specific HTML elements like list elements. The presence of `HTMLOListElement`, `HTMLUListElement`, etc., is a clear indicator.
    * **JavaScript:** While this C++ code doesn't directly execute JavaScript, its functionality is exposed to JavaScript indirectly. JavaScript can manipulate the DOM and CSS properties, which in turn trigger the counter logic in this code. For example, adding or removing elements, or changing CSS rules related to counters.

5. **Infer Logical Reasoning and Provide Examples:**
    * Based on the function names and code, I can infer the logic for incrementing, resetting, and setting counter values. I'd create simple HTML/CSS examples to illustrate the input and expected output. For instance, a nested list demonstrating counter inheritance.

6. **Anticipate User Errors:**
    * I'd think about common mistakes developers make with CSS counters, such as forgetting to reset a counter, incorrect scoping, or misunderstanding how `counter()` and `counters()` work. I'd try to relate these potential errors back to the logic within the code.

7. **Construct a Debugging Scenario:**
    * I'd imagine a user observing an unexpected counter value on a webpage. I'd outline the steps a developer might take, starting from inspecting the element in the browser's developer tools, checking the computed styles for counter-related properties, and potentially setting breakpoints in the Blink rendering engine (if they have access and expertise) to trace the execution flow within `counters_attachment_context.cc`.

8. **Structure the Answer:**  Finally, I'd organize my findings into a clear and structured answer, covering each point requested by the user: functionality, relationships with web technologies, logical reasoning, user errors, and debugging. I'd use code examples to make the explanations concrete.

By following this systematic approach, I can comprehensively analyze the given source code and provide a detailed and informative response to the user's query. The process involves understanding the purpose, dissecting the code, identifying key concepts, connecting it to web technologies, inferring logic, anticipating errors, and outlining debugging strategies.
好的，让我们来详细分析一下 `blink/renderer/core/css/counters_attachment_context.cc` 这个文件。

**文件功能概览**

`counters_attachment_context.cc` 文件是 Chromium Blink 渲染引擎中负责处理 CSS 计数器（CSS Counters）的核心组件。它的主要功能是：

1. **维护计数器状态:**  跟踪和管理页面中所有已定义的 CSS 计数器的当前值。
2. **处理计数器指令:**  解释和执行 CSS 规则中 `counter-increment`、`counter-reset` 和 `counter-set` 属性定义的计数器操作。
3. **管理计数器作用域:**  处理计数器的继承和作用域规则，确保计数器在正确的元素范围内生效。
4. **为 `counter()` 和 `counters()` 函数提供值:**  当渲染引擎遇到 CSS 函数 `counter()` 或 `counters()` 时，此文件负责提供正确的计数器值。
5. **处理列表项计数器:**  对于有序列表（`<ol>`）和列表项（`<li>`），实现默认的列表项计数行为。
6. **处理 `@page` 上下文中的计数器:**  特殊处理在 `@page` 规则中定义的计数器，例如页码。
7. **处理样式包含（Style Containment）边界:**  当遇到设置了 `contain` 属性的元素时，管理计数器的作用域隔离。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件直接关系到 CSS 的功能，并通过渲染引擎将 CSS 的效果体现在 HTML 结构上。JavaScript 可以动态地修改 HTML 结构和 CSS 样式，间接地影响此文件的行为。

**CSS:**

* **`counter-increment`:**  指定计数器递增的值。
   ```css
   body {
     counter-reset: section; /* 初始化名为 section 的计数器 */
   }
   h2::before {
     counter-increment: section; /* 每次 h2 元素前递增 section 计数器 */
     content: "Section " counter(section) ": ";
   }
   ```
   **`CountersAttachmentContext` 的功能：** 当渲染引擎遇到 `h2` 元素时，会调用 `CountersAttachmentContext::ProcessCounter`，根据 `counter-increment: section;` 指令，增加名为 `section` 的计数器的值。

* **`counter-reset`:** 指定计数器初始化的值。
   ```css
   ol {
     counter-reset: list-item 0; /* 初始化名为 list-item 的计数器为 0 */
   }
   li::marker {
     content: counter(list-item) ". ";
     counter-increment: list-item; /* 每次 li 元素前递增 list-item 计数器 */
   }
   ```
   **`CountersAttachmentContext` 的功能：** 当渲染引擎遇到 `<ol>` 元素时，会调用 `CountersAttachmentContext::ProcessCounter`，根据 `counter-reset: list-item 0;` 指令，将 `list-item` 计数器的值重置为 0。

* **`counter-set`:**  设置计数器的值，而不是递增或重置。
   ```css
   .special-item {
     counter-set: list-item 5; /* 将 list-item 计数器设置为 5 */
   }
   ```
   **`CountersAttachmentContext` 的功能：** 当渲染引擎遇到带有 `.special-item` 类的元素时，会调用 `CountersAttachmentContext::ProcessCounter`，根据 `counter-set: list-item 5;` 指令，将 `list-item` 计数器的值设置为 5。

* **`counter()` 和 `counters()` 函数:**  用于在 `content` 属性中显示计数器的值。
   ```css
   /* 上面的 h2::before 例子已经展示了 counter() 的用法 */
   .outline::before {
     counter-reset: section 0 subsection 0;
   }
   h3::before {
     counter-increment: subsection;
     content: counters(section, ".") "." counter(subsection) ": ";
   }
   ```
   **`CountersAttachmentContext` 的功能：** 当渲染引擎需要渲染 `h2::before` 或 `h3::before` 的 `content` 时，会调用 `CountersAttachmentContext::GetCounterValues` 来获取 `section` 或 `subsection` 计数器的值，以便将其插入到内容中。

**HTML:**

* **列表元素 (`<ol>`, `<ul>`, `<li>`):**  `CountersAttachmentContext` 会自动为列表项创建和管理默认的 `list-item` 计数器。
   ```html
   <ol>
     <li>Item 1</li>
     <li>Item 2</li>
   </ol>
   ```
   **`CountersAttachmentContext` 的功能：** 当渲染引擎处理这个 `<ol>` 时，`CountersAttachmentContext::MaybeCreateListItemCounter` 会被调用，隐式地为每个 `<li>` 元素创建或更新 `list-item` 计数器。

**JavaScript:**

* JavaScript 可以通过修改元素的 `style` 属性或者添加/删除带有计数器相关样式的 CSS 类来影响 `CountersAttachmentContext` 的行为。
   ```javascript
   const body = document.querySelector('body');
   body.style.counterReset = 'myCounter 10'; // 使用 JavaScript 设置 counter-reset
   ```
   **`CountersAttachmentContext` 的功能：** 当 JavaScript 修改了元素的样式，导致计数器相关的 CSS 属性发生变化时，渲染引擎会重新布局和绘制，`CountersAttachmentContext` 会根据新的样式规则更新计数器的状态。

**逻辑推理及假设输入与输出**

假设有以下 HTML 和 CSS：

**HTML:**

```html
<div class="section">
  <h2>Title A</h2>
  <div class="subsection">
    <h3>Sub Title 1</h3>
  </div>
  <div class="subsection">
    <h3>Sub Title 2</h3>
  </div>
</div>
<div class="section">
  <h2>Title B</h2>
</div>
```

**CSS:**

```css
body {
  counter-reset: section;
}
.section {
  counter-increment: section;
  counter-reset: subsection;
}
h2::before {
  content: "Section " counter(section) ": ";
}
h3::before {
  counter-increment: subsection;
  content: counter(section) "." counter(subsection) ": ";
}
```

**假设输入：**  渲染引擎开始处理上述 HTML 结构和 CSS 样式。

**`CountersAttachmentContext` 的处理过程：**

1. **处理 `body` 元素:** `EnterObject` 被调用，根据 `counter-reset: section;` 初始化全局计数器 `section` 为 0。
2. **处理第一个 `<div class="section">`:** `EnterObject` 被调用。
   - 根据 `counter-increment: section;`，`section` 计数器递增为 1。
   - 根据 `counter-reset: subsection;`，初始化该 `div` 作用域下的 `subsection` 计数器为 0。
3. **处理 `<h2>Title A</h2>`:** `EnterObject` 被调用。
   - 渲染 `h2::before` 的 `content`，调用 `GetCounterValues` 获取 `section` 的值 (1)，输出 "Section 1: "。
4. **处理第一个 `<div class="subsection">`:** `EnterObject` 被调用。
5. **处理 `<h3>Sub Title 1</h3>`:** `EnterObject` 被调用。
   - 根据父元素 `.section` 的 `counter-increment: subsection;`，`subsection` 计数器递增为 1。
   - 渲染 `h3::before` 的 `content`，调用 `GetCounterValues` 获取 `section` (1) 和 `subsection` (1) 的值，输出 "1.1: "。
6. **处理第二个 `<div class="subsection">`:** `LeaveObject` 被调用，离开第一个 `subsection` 的作用域。`EnterObject` 被调用，进入第二个 `subsection` 的作用域。由于 `.section` 元素设置了 `counter-reset: subsection;`，所以 `subsection` 计数器又被重置为 0。
7. **处理 `<h3>Sub Title 2</h3>`:** `EnterObject` 被调用。
   - 根据父元素 `.section` 的 `counter-increment: subsection;`，`subsection` 计数器递增为 1。
   - 渲染 `h3::before` 的 `content`，调用 `GetCounterValues` 获取 `section` (1) 和 `subsection` (1) 的值，输出 "1.1: "。
8. **处理第二个 `<div class="section">`:** `LeaveObject` 被调用，离开第一个 `section` 的作用域。`EnterObject` 被调用，进入第二个 `section` 的作用域。
   - 根据 `counter-increment: section;`，`section` 计数器递增为 2。
   - 根据 `counter-reset: subsection;`，初始化该 `div` 作用域下的 `subsection` 计数器为 0。
9. **处理 `<h2>Title B</h2>`:** `EnterObject` 被调用。
   - 渲染 `h2::before` 的 `content`，调用 `GetCounterValues` 获取 `section` 的值 (2)，输出 "Section 2: "。

**假设输出：**  最终渲染出的效果中，计数器的值如下：

* Section 1: Title A
* 1.1: Sub Title 1
* 1.1: Sub Title 2
* Section 2: Title B

**用户或编程常见的使用错误**

1. **忘记 `counter-reset`:**  如果没有初始化计数器，`counter-increment` 会在之前的值上继续递增，可能导致意外的结果。
   ```css
   /* 缺少 counter-reset */
   h2::before {
     counter-increment: section;
     content: "Section " counter(section) ": ";
   }
   ```
   **`CountersAttachmentContext` 的行为：** 如果之前有其他元素也递增了 `section` 计数器，那么这里的 `h2` 元素会继续累加，而不是从 1 开始。

2. **计数器名称拼写错误:**  在 `counter-increment`、`counter-reset` 或 `counter()` 中使用了不同的计数器名称。
   ```css
   body {
     counter-reset: secton; /* 拼写错误 */
   }
   h2::before {
     counter-increment: section;
     content: "Section " counter(section) ": ";
   }
   ```
   **`CountersAttachmentContext` 的行为：**  `counter(section)` 将无法找到名为 `section` 的计数器，可能输出默认值（通常是 0 或空字符串）。

3. **在不应该使用的地方递增计数器:**  例如，在一个没有 `content` 的元素上递增计数器，但没有地方显示它。
   ```css
   .hidden-counter {
     counter-increment: myCounter;
   }
   ```
   **`CountersAttachmentContext` 的行为：**  计数器的值会递增，但由于没有 `counter()` 或 `counters()` 函数引用它，这个递增对用户是不可见的。这可能会导致后续使用该计数器时出现意外的值。

4. **错误的作用域理解:**  没有正确理解计数器的作用域规则，导致计数器在某些地方意外地被重置或影响。
   ```css
   .container {
     counter-reset: item;
   }
   .item::before {
     counter-increment: item;
     content: counter(item) ". ";
   }
   /* 如果 .container 嵌套，可能会导致 item 计数器在内部 container 中被重新初始化 */
   ```
   **`CountersAttachmentContext` 的行为：**  当进入内部的 `.container` 元素时，`CountersAttachmentContext` 会根据 `counter-reset: item;` 重新初始化 `item` 计数器，导致计数从 1 重新开始。

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户在网页上看到一个编号不正确的列表项。以下是用户操作和对应的调试线索，最终可能会涉及到 `counters_attachment_context.cc`：

1. **用户观察到错误:**  用户浏览网页，发现一个有序列表的编号跳跃或重复。
2. **开发者打开开发者工具:**  按下 F12 或右键点击 "检查"。
3. **检查元素:**  在 "Elements" 面板中选中编号错误的列表项 (`<li>`)。
4. **查看计算样式 (Computed Styles):**  在 "Styles" 或 "Computed" 面板中，查找与计数器相关的 CSS 属性，例如 `counter-increment` 和 `counter-reset`。
   - **调试线索：** 查看是否有意外的 `counter-reset` 导致计数器被重置，或者 `counter-increment` 的值是否正确。
5. **检查父元素样式:**  向上查找父元素（`<ol>` 或其他容器）的样式，看是否有影响计数器的 CSS 规则。
   - **调试线索：**  检查父元素是否设置了 `counter-reset`，影响了子元素的计数器。
6. **检查伪元素样式:**  如果计数器是通过 `::before` 或 `::after` 伪元素显示的，检查这些伪元素的样式。
   - **调试线索：**  确认 `content` 属性中使用了正确的 `counter()` 函数，并且计数器名称拼写正确。
7. **查看 "Rendering" 面板 (可能需要手动开启):**  某些浏览器提供了 "Rendering" 面板，可以查看布局树结构和渲染信息，这有助于理解元素的渲染顺序和作用域。
   - **调试线索：**  查看元素的渲染顺序是否符合预期，是否有元素意外地影响了计数器的作用域。
8. **如果问题仍然无法解决，开发者可能会深入到浏览器引擎的调试:**
   - **设置断点:**  如果开发者有 Chromium 的源码和调试环境，他们可能会在 `counters_attachment_context.cc` 中的关键函数（例如 `ProcessCounter`, `GetCounterValues`, `MaybeCreateListItemCounter`）设置断点。
   - **重现问题:**  在调试模式下加载网页，当执行到断点时，检查计数器的状态 (`counter_inheritance_table_`)，以及相关的 `LayoutObject` 和 `ComputedStyle` 信息。
   - **单步执行:**  逐步执行代码，观察计数器的值是如何被修改和传递的，从而找到错误的根源。

**总结**

`counters_attachment_context.cc` 是 Blink 渲染引擎中处理 CSS 计数器的关键组成部分。它负责维护计数器状态、处理计数器指令、管理作用域，并为 `counter()` 和 `counters()` 函数提供值。理解这个文件的功能有助于深入了解 CSS 计数器的工作原理，并为调试相关问题提供线索。用户通过与网页的交互，最终可能触发到这个文件的执行逻辑，而开发者可以通过浏览器开发者工具和引擎调试来追踪和解决计数器相关的问题。

Prompt: 
```
这是目录为blink/renderer/core/css/counters_attachment_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/counters_attachment_context.h"

#include "base/containers/adapters.h"
#include "base/not_fatal_until.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/html/html_directory_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_menu_element.h"
#include "third_party/blink/renderer/core/html/html_olist_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/html/list_item_ordinal.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {

namespace {

bool IsAncestorOf(const Element& ancestor, const Element& descendant) {
  for (const Element* parent =
           LayoutTreeBuilderTraversal::ParentElement(descendant);
       parent; parent = LayoutTreeBuilderTraversal::ParentElement(*parent)) {
    if (parent == ancestor) {
      return true;
    }
  }
  return false;
}

std::optional<std::pair<unsigned, int>> DetermineCounterTypeAndValue(
    const LayoutObject& layout_object,
    const CounterDirectives& directives) {
  if (layout_object.IsText() && !layout_object.IsBR()) {
    return std::nullopt;
  }
  const ComputedStyle& style = layout_object.StyleRef();
  switch (style.StyleType()) {
    case kPseudoIdNone:
    case kPseudoIdCheck:
    case kPseudoIdBefore:
    case kPseudoIdAfter:
    case kPseudoIdSelectArrow:
    case kPseudoIdMarker:
    case kPseudoIdScrollMarkerGroup:
    case kPseudoIdScrollMarker:
      break;
    default:
      return std::nullopt;  // Counters are forbidden from all other pseudo
                            // elements.
  }

  if (directives.IsDefined()) {
    unsigned type_mask = 0;
    int value = directives.CombinedValue();
    type_mask |= directives.IsIncrement()
                     ? static_cast<unsigned>(
                           CountersAttachmentContext::Type::kIncrementType)
                     : 0u;
    type_mask |=
        directives.IsReset()
            ? static_cast<unsigned>(CountersAttachmentContext::Type::kResetType)
            : 0;
    type_mask |=
        directives.IsSet()
            ? static_cast<unsigned>(CountersAttachmentContext::Type::kSetType)
            : 0;
    return std::make_pair(type_mask, value);
  }
  return std::nullopt;
}

inline bool IsReset(unsigned counter_type) {
  return counter_type &
         static_cast<unsigned>(CountersAttachmentContext::Type::kResetType);
}

inline bool IsSetOrReset(unsigned counter_type) {
  return counter_type & static_cast<unsigned>(
                            CountersAttachmentContext::Type::kResetType) ||
         counter_type &
             static_cast<unsigned>(CountersAttachmentContext::Type::kSetType);
}

int CalculateCounterValue(unsigned counter_type,
                          int counter_value,
                          int counter_current_value) {
  if (IsSetOrReset(counter_type)) {
    return counter_value;
  }
  return base::CheckAdd(counter_current_value, counter_value)
      .ValueOrDefault(counter_current_value);
}

}  // namespace

void CountersAttachmentContext::CounterEntry::Trace(Visitor* visitor) const {
  visitor->Trace(layout_object);
}

CountersAttachmentContext::CountersAttachmentContext()
    : counter_inheritance_table_(
          MakeGarbageCollected<CounterInheritanceTable>()) {}

bool CountersAttachmentContext::ElementGeneratesListItemCounter(
    const Element& element) {
  return IsA<HTMLOListElement>(element) || IsA<HTMLUListElement>(element) ||
         IsA<HTMLLIElement>(element) || IsA<HTMLMenuElement>(element) ||
         IsA<HTMLDirectoryElement>(element);
}

CountersAttachmentContext CountersAttachmentContext::DeepClone() const {
  CountersAttachmentContext clone(*this);
  clone.counter_inheritance_table_ =
      MakeGarbageCollected<CounterInheritanceTable>(
          *counter_inheritance_table_);
  for (auto& [counter_name, stack] : *clone.counter_inheritance_table_) {
    stack = MakeGarbageCollected<CounterStack>(*stack);
    for (Member<CounterEntry>& entry : *stack) {
      entry = MakeGarbageCollected<CounterEntry>(*entry);
    }
  }
  return clone;
}

void CountersAttachmentContext::EnterObject(const LayoutObject& layout_object,
                                            bool is_page_box) {
  if (!attachment_root_is_document_element_) {
    return;
  }
  const ComputedStyle& style = layout_object.StyleRef();
  const CounterDirectiveMap* counter_directives = style.GetCounterDirectives();
  if (counter_directives) {
    for (auto& [counter_name, directives] : *counter_directives) {
      std::optional<std::pair<unsigned, int>> type_and_value =
          DetermineCounterTypeAndValue(layout_object, directives);
      if (!type_and_value.has_value()) {
        continue;
      }
      auto [counter_type, value_argument] = type_and_value.value();
      ProcessCounter(layout_object, counter_name, counter_type, value_argument,
                     is_page_box);
    }
  }
  // If there were no explicit counter related property set for `list-item`
  // counter, maybe we need to create implicit one.
  if (const auto* element = DynamicTo<Element>(layout_object.GetNode())) {
    if (ElementGeneratesListItemCounter(*element) &&
        (!counter_directives ||
         counter_directives->find(list_item_) == counter_directives->end())) {
      MaybeCreateListItemCounter(*element);
    }
  }

  if (is_page_box) {
    // By default, @page boxes keep track of the page number. If the special
    // counter named "page" has no directives at all, increment it by one.
    //
    // See https://drafts.csswg.org/css-page-3/#page-based-counters
    const AtomicString page_str("page");
    if (!counter_directives ||
        counter_directives->find(page_str) == counter_directives->end()) {
      ProcessCounter(layout_object, page_str,
                     static_cast<unsigned>(Type::kIncrementType),
                     /*value_argument=*/1, is_page_box);
    }
  }

  // Create style containment boundary if the element has contains style.
  // Doing it after counters creation as the element itself is not included
  // in the style containment scope.
  if (style.ContainsStyle()) {
    EnterStyleContainmentScope();
  }
}

void CountersAttachmentContext::LeaveObject(const LayoutObject& layout_object,
                                            bool is_page_box) {
  if (!attachment_root_is_document_element_) {
    return;
  }
  const ComputedStyle& style = layout_object.StyleRef();
  // Remove style containment boundary if the element has contains style.
  // Doing it here as reverse to EnterObject().
  if (style.ContainsStyle()) {
    LeaveStyleContainmentScope();
  }
  const CounterDirectiveMap* counter_directives = style.GetCounterDirectives();
  if (counter_directives) {
    for (auto& [counter_name, directives] : *counter_directives) {
      std::optional<std::pair<unsigned, int>> type_and_value =
          DetermineCounterTypeAndValue(layout_object, directives);
      if (!type_and_value.has_value()) {
        continue;
      }
      auto [counter_type, counter_value] = type_and_value.value();
      if (!layout_object.GetNode()) {
        UnobscurePageCounterIfNeeded(counter_name, counter_type, is_page_box);
      }
      if (!IsReset(counter_type)) {
        continue;
      }
      // Remove self from stack if previous counter on stack is ancestor to
      // self. This is done since we should always inherit from ancestor first,
      // and in the case described, all next elements would inherit ancestor
      // instead of self, so remove self.
      RemoveCounterIfAncestorExists(layout_object, counter_name);
    }
  }
  // If there were no explicit counter related property set for `list-item`
  // counter, maybe we need to remove implicit one.
  if (const auto* element = DynamicTo<Element>(layout_object.GetNode())) {
    if (ElementGeneratesListItemCounter(*element) &&
        (!counter_directives ||
         counter_directives->find(list_item_) == counter_directives->end())) {
      RemoveCounterIfAncestorExists(layout_object, list_item_);
    }
  }
}

// Check if we need to create implicit list-item counter.
void CountersAttachmentContext::MaybeCreateListItemCounter(
    const Element& element) {
  const LayoutObject* layout_object = element.GetLayoutObject();
  DCHECK(layout_object);
  RemoveStaleCounters(*layout_object, list_item_);
  if (ListItemOrdinal* ordinal = ListItemOrdinal::Get(element)) {
    if (const auto& explicit_value = ordinal->ExplicitValue()) {
      CreateCounter(*layout_object, list_item_, explicit_value.value());
      return;
    }
    int value = ListItemOrdinal::IsInReversedOrderedList(element) ? -1 : 1;
    unsigned type_mask =
        static_cast<unsigned>(CountersAttachmentContext::Type::kIncrementType);
    UpdateCounterValue(*layout_object, list_item_, type_mask, value);
    return;
  }
  if (auto* olist = DynamicTo<HTMLOListElement>(element)) {
    int value = base::ClampAdd(olist->StartConsideringItemCount(),
                               olist->IsReversed() ? 1 : -1);
    CreateCounter(*layout_object, list_item_, value);
    return;
  }
  if (IsA<HTMLUListElement>(element) || IsA<HTMLMenuElement>(element) ||
      IsA<HTMLDirectoryElement>(element)) {
    CreateCounter(*layout_object, list_item_, 0);
    return;
  }
}

// Traverse the stack and collect counters values for counter() and counters()
// functions.
Vector<int> CountersAttachmentContext::GetCounterValues(
    const LayoutObject& layout_object,
    const AtomicString& counter_name,
    bool only_last) {
  RemoveStaleCounters(layout_object, counter_name);
  Vector<int> result;
  auto counter_stack_it = counter_inheritance_table_->find(counter_name);
  if (counter_stack_it == counter_inheritance_table_->end()) {
    return {0};
  }
  CounterStack& counter_stack = *counter_stack_it->value;
  if (counter_stack.empty()) {
    return {0};
  }

  // Counters changed within a page or page margin context obscure all counters
  // of the same name within the document.
  bool is_page_counter = false;

  for (const CounterEntry* entry : base::Reversed(counter_stack)) {
    // counter() and counters() can cross style containment boundaries.
    if (!entry) {
      if (is_page_counter) {
        // The boundary in this case is there to obscure counters defined in the
        // document (and also also page context, if we're in a page margin
        // context).
        break;
      }
      continue;
    }
    result.push_back(entry->value);
    if (only_last) {
      break;
    }
    if (!is_page_counter) {
      is_page_counter = !entry->layout_object->GetNode();
    }
  }
  if (result.empty()) {
    result.push_back(0);
  }
  return result;
}

void CountersAttachmentContext::ProcessCounter(
    const LayoutObject& layout_object,
    const AtomicString& counter_name,
    unsigned counter_type,
    int value_argument,
    bool is_page_box) {
  // First, there might be some counters on stack that are stale, remove
  // those (e.g. remove counters whose parent is not ancestors from stack).
  RemoveStaleCounters(layout_object, counter_name);

  // Counters in page boxes and page margin boxes may be special. If they are,
  // do the special stuff and return.
  if (!layout_object.GetNode() &&
      ObscurePageCounterIfNeeded(layout_object, counter_name, counter_type,
                                 value_argument, is_page_box)) {
    return;
  }

  // Reset counter always creates counter.
  if (IsReset(counter_type)) {
    CreateCounter(layout_object, counter_name, value_argument);
    return;
  }

  // Otherwise, get the value of last counter from stack and update its value.
  // Note: this can create counter, if there are no counters on stack.
  UpdateCounterValue(layout_object, counter_name, counter_type, value_argument);
}

bool CountersAttachmentContext::ObscurePageCounterIfNeeded(
    const LayoutObject& layout_object,
    const AtomicString& counter_name,
    unsigned counter_type,
    int value_argument,
    bool is_page_box) {
  DCHECK(!layout_object.GetNode());
  auto counter_stack_it = counter_inheritance_table_->find(counter_name);

  // If a counter is reset within a page context, this obscures all counters of
  // the same name within the document. The spec additionally says that this
  // should also happen to counters that are just incremented. But that would
  // make page counters completely useless, as we'd be unable to increment
  // counters across pages. So don't do that.
  // See https://github.com/w3c/csswg-drafts/issues/4759
  //
  // Similarly, if a counter is incremented or reset within a page *margin*
  // context, this obscures all counters of the same name within the document,
  // and in the page context.
  if (counter_stack_it == counter_inheritance_table_->end() ||
      (is_page_box && !IsReset(counter_type))) {
    return false;
  }
  CounterStack& counter_stack = *counter_stack_it->value;
  if (!counter_stack.empty() && counter_stack.back()) {
    int counter_value = CalculateCounterValue(counter_type, value_argument,
                                              counter_stack.back()->value);
    auto* new_entry =
        MakeGarbageCollected<CounterEntry>(layout_object, counter_value);
    // To obscure previous counters, push an empty entry onto the stack.
    counter_stack.push_back(nullptr);
    // Pushing nullptr entries is also a trick used by style containment. But
    // since the 'contain' property doesn't apply in a page / page margin
    // context, there should be no conflicts.
    DCHECK(!layout_object.ShouldApplyStyleContainment());
    // Then add the new counter with the new value.
    counter_stack.push_back(new_entry);

    return true;
  }

  return false;
}

void CountersAttachmentContext::UnobscurePageCounterIfNeeded(
    const AtomicString& counter_name,
    unsigned counter_type,
    bool is_page_box) {
  auto counter_stack_it = counter_inheritance_table_->find(counter_name);
  if (counter_stack_it == counter_inheritance_table_->end() ||
      (is_page_box && !IsReset(counter_type))) {
    return;
  }
  CounterStack& counter_stack = *counter_stack_it->value;
  while (!counter_stack.empty()) {
    // We should only pop page / page margin boxes.
    DCHECK(!counter_stack.back() ||
           !counter_stack.back()->layout_object->GetNode());

    bool is_boundary = !counter_stack.back();
    counter_stack.pop_back();
    if (is_boundary) {
      break;
    }
  }
}

// Push the counter on stack or create stack if there is none. Also set the
// value in the table.
// Also, per https://drafts.csswg.org/css-lists/#instantiating-counters: If
// innermost counter’s originating element is `layout_object` or a previous
// sibling of `layout_object`, remove innermost counter from counters.
void CountersAttachmentContext::CreateCounter(const LayoutObject& layout_object,
                                              const AtomicString& counter_name,
                                              int value) {
  auto* new_entry = MakeGarbageCollected<CounterEntry>(layout_object, value);
  auto counter_stack_it = counter_inheritance_table_->find(counter_name);
  if (counter_stack_it == counter_inheritance_table_->end()) {
    CounterStack* counter_stack =
        MakeGarbageCollected<CounterStack>(1u, new_entry);
    counter_inheritance_table_->insert(counter_name, counter_stack);
    return;
  }
  CounterStack& counter_stack = *counter_stack_it->value;
  if (const auto* element = DynamicTo<Element>(layout_object.GetNode())) {
    // Remove innermost counter with same or previous sibling originating
    // element.
    if (!counter_stack.empty() && counter_stack.back()) {
      const auto* current =
          To<Element>(counter_stack.back()->layout_object->GetNode());
      DCHECK(current);
      if (LayoutTreeBuilderTraversal::ParentElement(*current) ==
          LayoutTreeBuilderTraversal::ParentElement(*element)) {
        counter_stack.pop_back();
      }
    }
  }
  counter_stack.push_back(new_entry);
}

// Remove counters parent is not ancestor of current element from stack,
// meaning that we left the scope of such counter already, e.g.:
//        ()
//    ()--------(S)
// (R)-(I)-()
// R will create and put on stack counter;
// I will use it from stack, but when we visit the next sibling of I,
// we don't remove R from stack, even we leave its scope, as we would have
// to check every last child in the tree if there were any counters created
// on this level. Instead, once we reach S we pop all stale counters from stack,
// here R will be removed from stack.
void CountersAttachmentContext::RemoveStaleCounters(
    const LayoutObject& layout_object,
    const AtomicString& counter_name) {
  const auto* element = DynamicTo<Element>(layout_object.GetNode());
  if (!element) {
    return;
  }
  auto counter_stack_it = counter_inheritance_table_->find(counter_name);
  if (counter_stack_it == counter_inheritance_table_->end()) {
    return;
  }
  CounterStack& counter_stack = *counter_stack_it->value;
  while (!counter_stack.empty()) {
    // If we hit style containment boundary, stop.
    const CounterEntry* entry = counter_stack.back();
    if (!entry) {
      break;
    }
    const LayoutObject& last_object = *entry->layout_object;
    if (const auto* last_element = DynamicTo<Element>(last_object.GetNode())) {
      const Element* parent =
          LayoutTreeBuilderTraversal::ParentElement(*last_element);
      // We pop all elements whose parent is not ancestor of `element`.
      if (!parent || IsAncestorOf(*parent, *element)) {
        break;
      }
    }
    counter_stack.pop_back();
  }
}

// When leaving the element that created counter we might want to
// pop it from stack, if previous counter on stack is ancestor of it.
// This is done because we should always inherit counters from ancestor first,
// so, if the previous counter is ancestor to the last one, the last one will
// never be inherited, remove it.
void CountersAttachmentContext::RemoveCounterIfAncestorExists(
    const LayoutObject& layout_object,
    const AtomicString& counter_name) {
  auto counter_stack_it = counter_inheritance_table_->find(counter_name);
  if (counter_stack_it == counter_inheritance_table_->end()) {
    return;
  }
  CounterStack& counter_stack = *counter_stack_it->value;
  // Don't remove the last on stack counter or style containment boundary.
  if (counter_stack.empty() || counter_stack.size() == 1) {
    return;
  }
  const CounterEntry* last_entry = counter_stack.back();
  // Also don't remove if the last counter's originating element is not
  // `layout_object`.
  if (!last_entry || last_entry->layout_object != layout_object) {
    return;
  }
  const CounterEntry* previous_entry = counter_stack[counter_stack.size() - 2];
  if (!previous_entry) {
    return;
  }
  const LayoutObject& previous_object = *previous_entry->layout_object;
  if (const auto* element = DynamicTo<Element>(layout_object.GetNode())) {
    const auto* previous_element =
        DynamicTo<Element>(previous_object.GetNode());
    if (previous_element && IsAncestorOf(*previous_element, *element)) {
      counter_stack.pop_back();
    }
  }
}

// Update the value of last on stack counter or create a new one, if there
// is no last counter on stack.
void CountersAttachmentContext::UpdateCounterValue(
    const LayoutObject& layout_object,
    const AtomicString& counter_name,
    unsigned counter_type,
    int counter_value) {
  int default_counter_value =
      CalculateCounterValue(counter_type, counter_value, 0);
  auto counter_stack_it = counter_inheritance_table_->find(counter_name);
  // If there are no counters with such counter_name, create stack and push
  // new counter on it.
  if (counter_stack_it == counter_inheritance_table_->end()) {
    CreateCounter(layout_object, counter_name, default_counter_value);
    return;
  }
  // If the stack is empty or the last element on stack is style containment
  // boundary, create and push counter on stack.
  CounterStack& counter_stack = *counter_stack_it->value;
  if (counter_stack.empty() || !counter_stack.back()) {
    CreateCounter(layout_object, counter_name, default_counter_value);
    return;
  }
  // Otherwise take the value of last counter on stack from the table and
  // update it.
  CounterEntry& current = *counter_stack.back();
  current.value =
      CalculateCounterValue(counter_type, counter_value, current.value);
}

void CountersAttachmentContext::EnterStyleContainmentScope() {
  // Push a style containment boundary (nullptr) to each existing stack.
  // Note: if there will be counters with new counter_name created later,
  // it still will work correctly as we will remove all counters until
  // counter stack is empty, when we will leave style containment scope.
  for (auto& [counter_name, counter_stack] : *counter_inheritance_table_) {
    counter_stack->push_back(nullptr);
  }
}

void CountersAttachmentContext::LeaveStyleContainmentScope() {
  // Pop counters until the stack is empty (happens if we created a counter with
  // a previously unseen counter_name after we entered style containment scope)
  // or nullptr is the last on stack (we reached the style containment
  // boundary).
  for (auto& [counter_name, counter_stack] : *counter_inheritance_table_) {
    while (!counter_stack->empty() && counter_stack->back() != nullptr) {
      counter_stack->pop_back();
    }
    if (!counter_stack->empty() && counter_stack->back() == nullptr) {
      counter_stack->pop_back();
    }
  }
}

}  // namespace blink

"""

```