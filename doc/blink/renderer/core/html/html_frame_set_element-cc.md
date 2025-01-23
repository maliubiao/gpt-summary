Response:
Let's break down the thought process to analyze this `HTMLFrameSetElement.cc` file.

**1. Initial Understanding - What is a `<frameset>`?**

The very first step is understanding the core HTML element this code represents. A `<frameset>` is used to create a layout with multiple independent browsing contexts (frames) within a single browser window. It's largely a legacy feature, but it's still part of the HTML specification and thus needs to be implemented in a browser engine.

**2. High-Level Functionality (Based on Filename and Initial Code Scan):**

*   The filename `html_frame_set_element.cc` directly indicates it's the implementation for the `<frameset>` HTML element within the Blink rendering engine.
*   The `#include` directives at the beginning give hints about the dependencies and functionalities. We see includes for:
    *   Core HTML elements (`html_frame_element.h`)
    *   CSS (`css_property_names.h`)
    *   DOM (`document.h`, `element_traversal.h`, `events/event.h`)
    *   JavaScript integration (`bindings/core/v8/js_event_handler_for_content_attribute.h`)
    *   Layout (`layout/layout_frame_set.h`, `layout/frame_set_layout_data.h`)
    *   Events (`events/mouse_event.h`)
    *   Frames (`frame/local_frame.h`)

This suggests the file handles the creation, styling, layout, and event handling related to `<frameset>` elements.

**3. Deep Dive into Key Sections (Function by Function):**

Now, let's go through the code section by section, understanding the purpose of each function:

*   **Constructor (`HTMLFrameSetElement::HTMLFrameSetElement`)**:  Standard constructor, initializes the element, sets a flag for custom style callbacks, and counts usage for internal metrics.
*   **`IsPresentationAttribute` and `CollectStyleForPresentationAttribute`**: These functions handle the parsing of specific HTML attributes (`bordercolor`) that directly translate to CSS styles. This shows a relationship between HTML attributes and CSS styling.
*   **`ParseAttribute`**: This is a crucial function. It's responsible for handling changes to various attributes of the `<frameset>` element. It's where the core logic for attributes like `rows`, `cols`, `frameborder`, `noresize`, `border`, and event handlers (`onload`, `onresize`, etc.) reside. This directly connects the HTML attributes to the internal behavior of the element and the browser. The presence of handlers for many window-level events indicates the `<frameset>` acts as a container for the overall window structure in this context.
*   **`HasFrameBorder`, `NoResize`, `Border`, `HasBorderColor`**: These are getter functions that determine the current state of the `<frameset>` based on its attributes and potentially its parent `<frameset>`. This shows how attributes can cascade or inherit.
*   **`EdgeInfo`, `FillFromEdgeInfo`, `CollectEdgeInfoIfDirty`, `DirtyEdgeInfo`, `DirtyEdgeInfoAndFullPaintInvalidation`, `AllowBorderRows`, `AllowBorderColumns`**: This group of functions deals with managing the borders and resizing behavior between frames. It involves tracking which borders are allowed and which frame edges are resizable. The "dirty" mechanism suggests an optimization where this information is only recalculated when necessary.
*   **`LayoutObjectIsNeeded` and `CreateLayoutObject`**: These functions are part of the Blink rendering pipeline. They determine if a layout object needs to be created for the `<frameset>` and then create the appropriate layout object (`LayoutFrameSet`). This links the DOM element to the rendering process.
*   **`AttachLayoutTree`**: Called when the `<frameset>` is attached to the rendering tree. It initializes the resizing state.
*   **`DefaultEventHandler`**:  Handles default events, particularly mouse events for resizing frames. This is where the interactive behavior of resizing frames is implemented.
*   **`InsertedInto`**: Handles the insertion of the `<frameset>` into the DOM. It has special logic for informing the document that a `<frameset>` is present, which affects how the "body" is treated.
*   **`WillRecalcStyle`**:  Handles the need to recalculate styles and potentially reattach the layout tree.
*   **`UserResize`, `SetIsResizing`, `StartResizing`, `ContinueResizing`, `SplitPosition`**:  These functions implement the core logic for user-initiated frame resizing through mouse interaction. They calculate split positions and adjust frame sizes.
*   **`CanResizeRow`, `CanResizeColumn`, `HitTestSplit`**: Helper functions for determining if a resize is possible at a given mouse position.
*   **`ResizeChildrenData`, `ResizeAxis`**:  Manages the data structures needed to track resizing information for rows and columns. The `ResizeAxis` struct is a helper to encapsulate the resizing state for a single axis (rows or columns).

**4. Identifying Relationships with HTML, CSS, and JavaScript:**

As we analyze the functions, the relationships become clear:

*   **HTML:** The entire file is about the `<frameset>` *HTML element*. The `ParseAttribute` function directly processes HTML attributes.
*   **CSS:**  `IsPresentationAttribute` and `CollectStyleForPresentationAttribute` handle the mapping of HTML attributes to CSS properties. The `Border` function takes a `ComputedStyle` object as input.
*   **JavaScript:** The `ParseAttribute` function handles many `on...` attributes (e.g., `onload`, `onresize`). These are *JavaScript event handlers* defined directly in the HTML. The code uses `JSEventHandlerForContentAttribute` to manage these.

**5. Logical Reasoning and Assumptions:**

When the code checks for parent `<frameset>` elements (e.g., in `HasFrameBorder`, `NoResize`, `Border`), it's assuming a *nested frameset structure*. This is a valid HTML construct. The code then propagates certain properties upwards in the hierarchy.

**6. Identifying Potential User/Programming Errors:**

By understanding the purpose of the code, we can infer potential errors:

*   **Incorrect Attribute Values:**  Providing invalid values for attributes like `rows` or `cols` might lead to unexpected layout. The parsing logic tries to handle this to some extent.
*   **Conflicting Attributes:** Setting both `frameborder="0"` and `border="10"` might lead to confusion about which style should apply. The code has specific logic for handling the precedence of these attributes.
*   **Incorrect Event Handler Syntax:**  Mistyping or using incorrect JavaScript syntax within the `on...` attributes will result in errors that are handled by the JavaScript engine, but the setup occurs here.
*   **Resizing Issues:** If the `rows` or `cols` attributes are set in a way that creates very small or zero-sized frames, the resizing logic might behave unexpectedly. The checks for zero sizes in `ContinueResizing` address this.

**7. Structuring the Output:**

Finally, the last step is to organize the information gleaned from the analysis into a clear and structured output, as demonstrated in your initial prompt's expected format. This involves summarizing the functionality, providing specific examples of relationships with HTML, CSS, and JavaScript, outlining the logical reasoning, and listing common errors.
好的，我们来分析一下 `blink/renderer/core/html/html_frame_set_element.cc` 这个文件。

**文件功能概要:**

该文件实现了 Chromium Blink 渲染引擎中 `HTMLFrameSetElement` 类的功能。`HTMLFrameSetElement` 类对应 HTML 中的 `<frameset>` 标签，用于创建包含多个框架（`<frame>` 或 `<iframe>`）的窗口布局。

**核心功能点包括:**

1. **解析和管理 `<frameset>` 标签的属性:**
    *   解析 `rows` 和 `cols` 属性，定义框架的行和列的尺寸和分布。
    *   处理 `border`, `frameborder`, `bordercolor`, `noresize` 等属性，控制框架边框的显示和调整行为。
    *   管理与窗口相关的事件处理属性，如 `onload`, `onresize`, `onbeforeunload` 等。

2. **控制框架的布局和渲染:**
    *   创建和管理 `LayoutFrameSet` 布局对象，负责框架的实际布局计算。
    *   处理框架之间的边框和间距。
    *   支持用户通过拖拽边框调整框架的大小。

3. **处理框架的交互行为:**
    *   响应鼠标事件，实现框架边框的拖拽调整。
    *   维护框架的可调整状态。

4. **维护框架的边缘信息:**
    *   跟踪框架边缘是否允许显示边框，以及是否允许用户调整大小。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML:**
    *   该文件直接对应 HTML 中的 `<frameset>` 标签。它的主要职责是解析和解释 HTML 中定义的 `<frameset>` 及其子元素（`<frame>`）。
    *   **举例:** 当浏览器解析到 `<frameset rows="50%,50%" cols="25%,75%">` 时，`ParseAttribute` 函数会解析 `rows` 和 `cols` 属性，并将解析结果存储在 `row_lengths_` 和 `col_lengths_` 成员变量中。这将决定页面如何分割成四个框架。

*   **CSS:**
    *   该文件中的代码会影响 `<frameset>` 元素的样式，特别是与边框相关的样式。
    *   `IsPresentationAttribute` 和 `CollectStyleForPresentationAttribute` 函数处理直接在 HTML 标签上设置的样式属性，例如 `bordercolor`。
    *   **举例:** 当 HTML 中设置 `<frameset bordercolor="red">` 时，`CollectStyleForPresentationAttribute` 会将 `border-color: red` 添加到元素的样式中。虽然 `<frameset>` 本身的可视样式属性不多，但它会影响其子框架的边框显示。

*   **JavaScript:**
    *   该文件处理与 `<frameset>` 元素相关的 JavaScript 事件处理程序。HTML 中定义的事件属性（如 `onload`, `onresize`）会被解析并关联到相应的 JavaScript 代码。
    *   **举例:** 当 HTML 中定义 `<frameset onload="alert('页面加载完成')">` 时，`ParseAttribute` 函数会创建一个 `JSEventHandlerForContentAttribute` 对象来处理 `load` 事件。当页面加载完成后，会执行 `alert('页面加载完成')` 这段 JavaScript 代码。
    *   用户可以通过 JavaScript 动态修改 `<frameset>` 的属性，例如使用 `element.rows = "20%,80%"` 来改变框架的布局。`ParseAttribute` 函数也会处理这些动态修改。

**逻辑推理及假设输入与输出:**

*   **假设输入:**  一个包含以下 `<frameset>` 标签的 HTML 文档：

    ```html
    <frameset rows="100,*" frameborder="yes" border="5">
      <frame src="frame_a.html">
      <frameset cols="50%,50%">
        <frame src="frame_b.html">
        <frame src="frame_c.html">
      </frameset>
    </frameset>
    ```

*   **逻辑推理:**
    1. **外层 `<frameset>` 解析:** `ParseAttribute` 会解析 `rows="100,*"`, `frameborder="yes"`, `border="5"`。`rows` 表示第一行固定高度 100 像素，第二行占据剩余空间。`frameborder="yes"` 表示显示边框。`border="5"` 表示边框宽度为 5 像素。
    2. **内层 `<frameset>` 解析:**  当解析到内层的 `<frameset>` 时，会解析 `cols="50%,50%"`，表示将剩余空间分成两列，每列占据 50%。
    3. **布局计算:** `CreateLayoutObject` 会创建 `LayoutFrameSet` 对象。`LayoutFrameSet` 会根据解析到的 `rows` 和 `cols` 值计算每个框架的实际尺寸和位置。
    4. **边框处理:** 根据 `frameborder` 和 `border` 的值，渲染引擎会在框架之间绘制边框。
    5. **用户调整大小:** 如果用户拖动框架之间的边框，`DefaultEventHandler` 中的 `UserResize` 函数会被调用，根据鼠标位置计算新的框架尺寸，并更新布局。

*   **预期输出（部分）：**
    *   外层框架集第一行高度为 100 像素。
    *   外层框架集第二行的高度为浏览器窗口高度减去 100 像素。
    *   内层框架集的两列宽度相等，均为外层框架集第二行宽度的 50%。
    *   框架之间会显示宽度为 5 像素的边框。
    *   用户可以拖动框架之间的边框来调整框架的大小（除非设置了 `noresize` 属性）。

**涉及用户或编程常见的使用错误及举例说明:**

1. **`rows` 或 `cols` 属性值格式错误:**
    *   **错误示例:** `<frameset rows="100px;200px">`  (使用分号分隔，应该使用逗号)
    *   **结果:** 浏览器可能无法正确解析，导致布局错乱或使用默认布局。

2. **`rows` 和 `cols` 定义不完整或冲突:**
    *   **错误示例:**  只定义了 `rows` 但没有定义 `cols`，或者定义的 `rows` 和 `cols` 无法完全覆盖可用空间。
    *   **结果:**  可能导致部分空间未被使用，或者框架的分布不符合预期。

3. **在 `<frameset>` 中错误地嵌套了 `<body>` 标签:**
    *   **错误示例:**

        ```html
        <frameset>
          <frame src="frame1.html">
          <body>This is wrong</body>
        </frameset>
        ```

    *   **结果:** 浏览器通常会忽略 `<frameset>` 内的 `<body>` 标签，因为 `<frameset>` 本身就定义了页面的结构。

4. **混淆使用 `<frameset>` 和 `<iframe>`:**
    *   **说明:** 虽然两者都用于嵌入内容，但 `<frameset>` 用于定义整个窗口的框架结构，而 `<iframe>` 用于在页面中嵌入独立的 HTML 文档。混淆使用可能导致语义不清晰或布局问题。

5. **忘记处理 `noresize` 属性:**
    *   **场景:** 开发者可能希望某些框架的大小固定，不允许用户调整，但忘记设置 `noresize` 属性。
    *   **结果:** 用户仍然可以拖动这些框架的边框来改变其大小。

6. **过度依赖 `<frameset>` 进行布局:**
    *   **说明:** `<frameset>` 是一个相对较老的 HTML 特性，现代 Web 开发更推荐使用 CSS 布局（如 Flexbox 或 Grid）来实现更灵活和强大的页面布局。过度依赖 `<frameset>` 可能导致维护困难和兼容性问题。

7. **在 JavaScript 事件处理程序中操作不当的框架对象:**
    *   **场景:** 在 `onload` 事件处理程序中，尝试访问尚未完全加载的框架的内容。
    *   **结果:** 可能导致 JavaScript 错误或无法获取到预期的框架内容。

总而言之，`html_frame_set_element.cc` 文件是 Blink 引擎中处理 `<frameset>` 标签的核心实现，它连接了 HTML 结构、CSS 样式和 JavaScript 交互，负责解析、布局和管理基于框架的页面结构。理解这个文件的功能有助于理解浏览器如何渲染和处理使用 `<frameset>` 的网页。

### 提示词
```
这是目录为blink/renderer/core/html/html_frame_set_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2000 Simon Hausmann (hausmann@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2006, 2009, 2010 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/html/html_frame_set_element.h"

#include "third_party/blink/renderer/bindings/core/v8/js_event_handler_for_content_attribute.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/html/frame_edge_info.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_frame_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/frame_set_layout_data.h"
#include "third_party/blink/renderer/core/layout/layout_frame_set.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

namespace {

constexpr int kDefaultBorderThicknessPx = 6;

const Vector<LayoutUnit>& ColumnSizes(const LayoutBox& box) {
  DCHECK(IsA<LayoutFrameSet>(box));
  // |object| should have only 1 physical fragment because <frameset> is
  // monolithic.
  const auto* data = box.GetPhysicalFragment(0)->GetFrameSetLayoutData();
  DCHECK(data);
  return data->col_sizes;
}

const Vector<LayoutUnit>& RowSizes(const LayoutBox& box) {
  DCHECK(IsA<LayoutFrameSet>(box));
  // |object| should have only 1 physical fragment because <frameset> is
  // monolithic.
  const auto* data = box.GetPhysicalFragment(0)->GetFrameSetLayoutData();
  DCHECK(data);
  return data->row_sizes;
}

}  // namespace

HTMLFrameSetElement::HTMLFrameSetElement(Document& document)
    : HTMLElement(html_names::kFramesetTag, document) {
  SetHasCustomStyleCallbacks();
  UseCounter::Count(document, WebFeature::kHTMLFrameSetElement);
}

bool HTMLFrameSetElement::IsPresentationAttribute(
    const QualifiedName& name) const {
  if (name == html_names::kBordercolorAttr)
    return true;
  return HTMLElement::IsPresentationAttribute(name);
}

void HTMLFrameSetElement::CollectStyleForPresentationAttribute(
    const QualifiedName& name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  if (name == html_names::kBordercolorAttr)
    AddHTMLColorToStyle(style, CSSPropertyID::kBorderColor, value);
  else
    HTMLElement::CollectStyleForPresentationAttribute(name, value, style);
}

void HTMLFrameSetElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  const AtomicString& value = params.new_value;
  if (name == html_names::kRowsAttr) {
    if (!value.IsNull()) {
      row_lengths_ = ParseListOfDimensions(value.GetString());
      SetNeedsStyleRecalc(kSubtreeStyleChange,
                          StyleChangeReasonForTracing::FromAttribute(name));
      if (GetLayoutObject() && TotalRows() != resize_rows_.deltas_.size())
        ResizeChildrenData();
    }
    DirtyEdgeInfo();
  } else if (name == html_names::kColsAttr) {
    if (!value.IsNull()) {
      col_lengths_ = ParseListOfDimensions(value.GetString());
      SetNeedsStyleRecalc(kSubtreeStyleChange,
                          StyleChangeReasonForTracing::FromAttribute(name));
      if (GetLayoutObject() && TotalCols() != resize_cols_.deltas_.size())
        ResizeChildrenData();
    }
    DirtyEdgeInfo();
  } else if (name == html_names::kFrameborderAttr) {
    if (!value.IsNull()) {
      if (EqualIgnoringASCIICase(value, "no") ||
          EqualIgnoringASCIICase(value, "0")) {
        frameborder_ = false;
      } else if (EqualIgnoringASCIICase(value, "yes") ||
                 EqualIgnoringASCIICase(value, "1")) {
        frameborder_ = true;
      }
    } else {
      frameborder_.reset();
    }
    DirtyEdgeInfoAndFullPaintInvalidation();
    for (auto& frame_set :
         Traversal<HTMLFrameSetElement>::DescendantsOf(*this)) {
      frame_set.DirtyEdgeInfoAndFullPaintInvalidation();
    }
  } else if (name == html_names::kNoresizeAttr) {
    DirtyEdgeInfo();
  } else if (name == html_names::kBorderAttr) {
    if (!value.IsNull()) {
      border_ = value.ToInt();
    } else {
      border_.reset();
    }
    if (auto* box = GetLayoutBox()) {
      box->SetNeedsLayoutAndFullPaintInvalidation(
          layout_invalidation_reason::kAttributeChanged);
    }
  } else if (name == html_names::kBordercolorAttr) {
    if (GetLayoutBox()) {
      for (const auto& frame_set :
           Traversal<HTMLFrameSetElement>::DescendantsOf(*this)) {
        if (auto* box = frame_set.GetLayoutBox()) {
          box->SetNeedsLayoutAndFullPaintInvalidation(
              layout_invalidation_reason::kAttributeChanged);
        }
      }
    }
  } else if (name == html_names::kOnafterprintAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kAfterprint,
        JSEventHandlerForContentAttribute::Create(GetExecutionContext(), name,
                                                  value));
  } else if (name == html_names::kOnbeforeprintAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kBeforeprint,
        JSEventHandlerForContentAttribute::Create(GetExecutionContext(), name,
                                                  value));
  } else if (name == html_names::kOnloadAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kLoad, JSEventHandlerForContentAttribute::Create(
                                     GetExecutionContext(), name, value));
  } else if (name == html_names::kOnbeforeunloadAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kBeforeunload,
        JSEventHandlerForContentAttribute::Create(
            GetExecutionContext(), name, value,
            JSEventHandler::HandlerType::kOnBeforeUnloadEventHandler));
  } else if (name == html_names::kOnunloadAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kUnload, JSEventHandlerForContentAttribute::Create(
                                       GetExecutionContext(), name, value));
  } else if (name == html_names::kOnpagehideAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kPagehide, JSEventHandlerForContentAttribute::Create(
                                         GetExecutionContext(), name, value));
  } else if (name == html_names::kOnpageshowAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kPageshow, JSEventHandlerForContentAttribute::Create(
                                         GetExecutionContext(), name, value));
  } else if (name == html_names::kOnblurAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kBlur, JSEventHandlerForContentAttribute::Create(
                                     GetExecutionContext(), name, value));
  } else if (name == html_names::kOnerrorAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kError,
        JSEventHandlerForContentAttribute::Create(
            GetExecutionContext(), name, value,
            JSEventHandler::HandlerType::kOnErrorEventHandler));
  } else if (name == html_names::kOnfocusAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kFocus, JSEventHandlerForContentAttribute::Create(
                                      GetExecutionContext(), name, value));
  } else if (name == html_names::kOnfocusinAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kFocusin, JSEventHandlerForContentAttribute::Create(
                                        GetExecutionContext(), name, value));
  } else if (name == html_names::kOnfocusoutAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kFocusout, JSEventHandlerForContentAttribute::Create(
                                         GetExecutionContext(), name, value));
  } else if (RuntimeEnabledFeatures::OrientationEventEnabled() &&
             name == html_names::kOnorientationchangeAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kOrientationchange,
        JSEventHandlerForContentAttribute::Create(GetExecutionContext(), name,
                                                  value));
  } else if (name == html_names::kOnhashchangeAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kHashchange,
        JSEventHandlerForContentAttribute::Create(GetExecutionContext(), name,
                                                  value));
  } else if (name == html_names::kOnmessageAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kMessage, JSEventHandlerForContentAttribute::Create(
                                        GetExecutionContext(), name, value));
  } else if (name == html_names::kOnresizeAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kResize, JSEventHandlerForContentAttribute::Create(
                                       GetExecutionContext(), name, value));
  } else if (name == html_names::kOnscrollAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kScroll, JSEventHandlerForContentAttribute::Create(
                                       GetExecutionContext(), name, value));
  } else if (name == html_names::kOnstorageAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kStorage, JSEventHandlerForContentAttribute::Create(
                                        GetExecutionContext(), name, value));
  } else if (name == html_names::kOnonlineAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kOnline, JSEventHandlerForContentAttribute::Create(
                                       GetExecutionContext(), name, value));
  } else if (name == html_names::kOnofflineAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kOffline, JSEventHandlerForContentAttribute::Create(
                                        GetExecutionContext(), name, value));
  } else if (name == html_names::kOnpopstateAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kPopstate, JSEventHandlerForContentAttribute::Create(
                                         GetExecutionContext(), name, value));
  } else if (name == html_names::kOnlanguagechangeAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kLanguagechange,
        JSEventHandlerForContentAttribute::Create(GetExecutionContext(), name,
                                                  value));
  } else if (RuntimeEnabledFeatures::TimeZoneChangeEventEnabled() &&
             name == html_names::kOntimezonechangeAttr) {
    GetDocument().SetWindowAttributeEventListener(
        event_type_names::kTimezonechange,
        JSEventHandlerForContentAttribute::Create(GetExecutionContext(), name,
                                                  value));
  } else {
    HTMLElement::ParseAttribute(params);
  }
}

bool HTMLFrameSetElement::HasFrameBorder() const {
  if (frameborder_.has_value())
    return *frameborder_;
  if (const auto* frame_set = DynamicTo<HTMLFrameSetElement>(parentNode()))
    return frame_set->HasFrameBorder();
  return true;
}

bool HTMLFrameSetElement::NoResize() const {
  if (FastHasAttribute(html_names::kNoresizeAttr))
    return true;
  if (const auto* frame_set = DynamicTo<HTMLFrameSetElement>(parentNode()))
    return frame_set->NoResize();
  return false;
}

int HTMLFrameSetElement::Border(const ComputedStyle& style) const {
  if (!HasFrameBorder())
    return 0;
  if (border_.has_value()) {
    return *border_ == 0
               ? 0
               : std::max(ClampTo<int>(*border_ * style.EffectiveZoom()), 1);
  }
  if (const auto* frame_set = DynamicTo<HTMLFrameSetElement>(parentNode()))
    return frame_set->Border(style);
  return ClampTo<int>(kDefaultBorderThicknessPx * style.EffectiveZoom());
}

bool HTMLFrameSetElement::HasBorderColor() const {
  if (FastHasAttribute(html_names::kBordercolorAttr))
    return true;
  if (const auto* frame_set = DynamicTo<HTMLFrameSetElement>(parentNode()))
    return frame_set->HasBorderColor();
  return false;
}

FrameEdgeInfo HTMLFrameSetElement::EdgeInfo() const {
  const_cast<HTMLFrameSetElement*>(this)->CollectEdgeInfoIfDirty();
  FrameEdgeInfo result(NoResize(), true);

  wtf_size_t rows_count = TotalRows();
  wtf_size_t cols_count = TotalCols();
  DCHECK_GT(rows_count, 0u);
  DCHECK_GT(cols_count, 0u);
  result.SetPreventResize(kLeftFrameEdge, resize_cols_.prevent_resize_[0]);
  result.SetAllowBorder(kLeftFrameEdge, allow_border_cols_[0]);
  result.SetPreventResize(kRightFrameEdge,
                          resize_cols_.prevent_resize_[cols_count]);
  result.SetAllowBorder(kRightFrameEdge, allow_border_cols_[cols_count]);
  result.SetPreventResize(kTopFrameEdge, resize_rows_.prevent_resize_[0]);
  result.SetAllowBorder(kTopFrameEdge, allow_border_rows_[0]);
  result.SetPreventResize(kBottomFrameEdge,
                          resize_rows_.prevent_resize_[rows_count]);
  result.SetAllowBorder(kBottomFrameEdge, allow_border_rows_[rows_count]);
  return result;
}

void HTMLFrameSetElement::FillFromEdgeInfo(const FrameEdgeInfo& edge_info,
                                           wtf_size_t r,
                                           wtf_size_t c) {
  if (edge_info.AllowBorder(kLeftFrameEdge))
    allow_border_cols_[c] = true;
  if (edge_info.AllowBorder(kRightFrameEdge))
    allow_border_cols_[c + 1] = true;
  if (edge_info.PreventResize(kLeftFrameEdge))
    resize_cols_.prevent_resize_[c] = true;
  if (edge_info.PreventResize(kRightFrameEdge))
    resize_cols_.prevent_resize_[c + 1] = true;

  if (edge_info.AllowBorder(kTopFrameEdge))
    allow_border_rows_[r] = true;
  if (edge_info.AllowBorder(kBottomFrameEdge))
    allow_border_rows_[r + 1] = true;
  if (edge_info.PreventResize(kTopFrameEdge))
    resize_rows_.prevent_resize_[r] = true;
  if (edge_info.PreventResize(kBottomFrameEdge))
    resize_rows_.prevent_resize_[r + 1] = true;
}

void HTMLFrameSetElement::CollectEdgeInfoIfDirty() {
  if (!is_edge_info_dirty_)
    return;
  is_edge_info_dirty_ = false;
  resize_cols_.prevent_resize_.Fill(NoResize());
  allow_border_cols_.Fill(false);
  resize_rows_.prevent_resize_.Fill(NoResize());
  allow_border_rows_.Fill(false);

  LayoutObject* child = GetLayoutObject()->SlowFirstChild();
  if (!child)
    return;

  wtf_size_t rows_count = TotalRows();
  wtf_size_t cols_count = TotalCols();
  for (wtf_size_t r = 0; r < rows_count; ++r) {
    for (wtf_size_t c = 0; c < cols_count; ++c) {
      const auto* node = child->GetNode();
      if (const auto* frame_set = DynamicTo<HTMLFrameSetElement>(node))
        FillFromEdgeInfo(frame_set->EdgeInfo(), r, c);
      else
        FillFromEdgeInfo(To<HTMLFrameElement>(node)->EdgeInfo(), r, c);
      child = child->NextSibling();
      if (!child)
        return;
    }
  }
}

void HTMLFrameSetElement::DirtyEdgeInfo() {
  is_edge_info_dirty_ = true;
  if (auto* parent_frame_set = DynamicTo<HTMLFrameSetElement>(parentNode()))
    parent_frame_set->DirtyEdgeInfo();
}

void HTMLFrameSetElement::DirtyEdgeInfoAndFullPaintInvalidation() {
  is_edge_info_dirty_ = true;
  if (auto* box = GetLayoutBox()) {
    box->SetNeedsLayoutAndFullPaintInvalidation(
        layout_invalidation_reason::kAttributeChanged);
  }
  if (auto* parent_frame_set = DynamicTo<HTMLFrameSetElement>(parentNode()))
    parent_frame_set->DirtyEdgeInfoAndFullPaintInvalidation();
}

const Vector<bool>& HTMLFrameSetElement::AllowBorderRows() const {
  const_cast<HTMLFrameSetElement*>(this)->CollectEdgeInfoIfDirty();
  return allow_border_rows_;
}
const Vector<bool>& HTMLFrameSetElement::AllowBorderColumns() const {
  const_cast<HTMLFrameSetElement*>(this)->CollectEdgeInfoIfDirty();
  return allow_border_cols_;
}

bool HTMLFrameSetElement::LayoutObjectIsNeeded(
    const DisplayStyle& style) const {
  // For compatibility, frames layoutObject even when display: none is set.
  return true;
}

LayoutObject* HTMLFrameSetElement::CreateLayoutObject(
    const ComputedStyle& style) {
  if (style.ContentBehavesAsNormal())
    return MakeGarbageCollected<LayoutFrameSet>(this);
  return LayoutObject::CreateObject(this, style);
}

void HTMLFrameSetElement::AttachLayoutTree(AttachContext& context) {
  HTMLElement::AttachLayoutTree(context);
  is_resizing_ = false;
  ResizeChildrenData();
}

void HTMLFrameSetElement::DefaultEventHandler(Event& evt) {
  auto* mouse_event = DynamicTo<MouseEvent>(evt);
  if (mouse_event && !NoResize() && GetLayoutObject() &&
      GetLayoutObject()->IsFrameSet()) {
    if (UserResize(*mouse_event)) {
      evt.SetDefaultHandled();
      return;
    }
  }
  HTMLElement::DefaultEventHandler(evt);
}

Node::InsertionNotificationRequest HTMLFrameSetElement::InsertedInto(
    ContainerNode& insertion_point) {
  if (insertion_point.isConnected() && GetDocument().GetFrame()) {
    // A document using <frameset> likely won't literally have a body, but as
    // far as the client is concerned, the frameset is effectively the body.
    GetDocument().WillInsertBody();
  }
  return HTMLElement::InsertedInto(insertion_point);
}
void HTMLFrameSetElement::WillRecalcStyle(const StyleRecalcChange) {
  if (NeedsStyleRecalc() && GetLayoutObject()) {
    if (GetForceReattachLayoutTree()) {
      // Adding a frameset to the top layer for fullscreen forces a reattach.
      SetNeedsReattachLayoutTree();
    } else {
      GetLayoutObject()->SetNeedsLayoutAndFullPaintInvalidation(
          layout_invalidation_reason::kStyleChange);
    }
    ClearNeedsStyleRecalc();
  }
}

bool HTMLFrameSetElement::UserResize(const MouseEvent& event) {
  const auto& box = *GetLayoutBox();
  if (!is_resizing_) {
    if (box.NeedsLayout())
      return false;
    if (event.type() == event_type_names::kMousedown && event.IsLeftButton()) {
      gfx::PointF local_pos =
          box.AbsoluteToLocalPoint(event.AbsoluteLocation());
      StartResizing(ColumnSizes(box), local_pos.x(), resize_cols_);
      StartResizing(RowSizes(box), local_pos.y(), resize_rows_);
      if (resize_cols_.IsResizingSplit() || resize_rows_.IsResizingSplit()) {
        SetIsResizing(true);
        return true;
      }
    }
  } else {
    if (event.type() == event_type_names::kMousemove ||
        (event.type() == event_type_names::kMouseup && event.IsLeftButton())) {
      gfx::PointF local_pos =
          box.AbsoluteToLocalPoint(event.AbsoluteLocation());
      ContinueResizing(ColumnSizes(box), local_pos.x(), resize_cols_);
      ContinueResizing(RowSizes(box), local_pos.y(), resize_rows_);
      if (event.type() == event_type_names::kMouseup && event.IsLeftButton()) {
        SetIsResizing(false);
        return true;
      }
    }
  }

  return false;
}

void HTMLFrameSetElement::SetIsResizing(bool is_resizing) {
  is_resizing_ = is_resizing;
  if (LocalFrame* frame = GetDocument().GetFrame())
    frame->GetEventHandler().SetResizingFrameSet(is_resizing ? this : nullptr);
}

void HTMLFrameSetElement::StartResizing(const Vector<LayoutUnit>& sizes,
                                        int position,
                                        ResizeAxis& resize_axis) {
  int split = HitTestSplit(sizes, position);
  CollectEdgeInfoIfDirty();
  if (!resize_axis.CanResizeSplitAt(split)) {
    resize_axis.split_being_resized_ = ResizeAxis::kNoSplit;
    return;
  }
  resize_axis.split_being_resized_ = split;
  resize_axis.split_resize_offset_ = position - SplitPosition(sizes, split);
}

void HTMLFrameSetElement::ContinueResizing(const Vector<LayoutUnit>& sizes,
                                           int position,
                                           ResizeAxis& resize_axis) {
  if (GetLayoutObject()->NeedsLayout())
    return;
  if (!resize_axis.IsResizingSplit())
    return;
  const int split_index = resize_axis.split_being_resized_;
  int current_split_position = SplitPosition(sizes, split_index);
  int delta =
      (position - current_split_position) - resize_axis.split_resize_offset_;
  if (!delta)
    return;
  const LayoutUnit original_size_prev =
      sizes[split_index - 1] - resize_axis.deltas_[split_index - 1];
  const LayoutUnit original_size_next =
      sizes[split_index] - resize_axis.deltas_[split_index];
  if ((original_size_prev != 0 && sizes[split_index - 1] + delta <= 0) ||
      (original_size_next != 0 && sizes[split_index] - delta <= 0)) {
    resize_axis.deltas_.Fill(0);
  } else {
    resize_axis.deltas_[split_index - 1] += delta;
    resize_axis.deltas_[split_index] -= delta;
  }
  GetLayoutObject()->SetNeedsLayoutAndFullPaintInvalidation(
      layout_invalidation_reason::kSizeChanged);
}

int HTMLFrameSetElement::SplitPosition(const Vector<LayoutUnit>& sizes,
                                       int split) const {
  if (GetLayoutObject()->NeedsLayout())
    return 0;

  int border_thickness = Border(GetLayoutObject()->StyleRef());

  int size = sizes.size();
  if (!size)
    return 0;

  int position = 0;
  for (int i = 0; i < split && i < size; ++i)
    position += sizes[i].ToInt() + border_thickness;
  return position - border_thickness;
}

bool HTMLFrameSetElement::CanResizeRow(const gfx::Point& p) const {
  const_cast<HTMLFrameSetElement*>(this)->CollectEdgeInfoIfDirty();
  return resize_rows_.CanResizeSplitAt(
      HitTestSplit(RowSizes(*GetLayoutBox()), p.y()));
}

bool HTMLFrameSetElement::CanResizeColumn(const gfx::Point& p) const {
  const_cast<HTMLFrameSetElement*>(this)->CollectEdgeInfoIfDirty();
  return resize_cols_.CanResizeSplitAt(
      HitTestSplit(ColumnSizes(*GetLayoutBox()), p.x()));
}

int HTMLFrameSetElement::HitTestSplit(const Vector<LayoutUnit>& sizes,
                                      int position) const {
  if (GetLayoutObject()->NeedsLayout())
    return ResizeAxis::kNoSplit;

  int border_thickness = Border(GetLayoutObject()->StyleRef());
  if (border_thickness <= 0)
    return ResizeAxis::kNoSplit;

  wtf_size_t size = sizes.size();
  if (!size)
    return ResizeAxis::kNoSplit;

  int split_position = sizes[0].ToInt();
  for (wtf_size_t i = 1; i < size; ++i) {
    if (position >= split_position &&
        position < split_position + border_thickness)
      return static_cast<int>(i);
    split_position += border_thickness + sizes[i].ToInt();
  }
  return ResizeAxis::kNoSplit;
}

void HTMLFrameSetElement::ResizeChildrenData() {
  resize_rows_.Resize(TotalRows());
  resize_cols_.Resize(TotalCols());

  // To track edges for borders, we need to be (size + 1). This is because a
  // parent frameset may ask us for information about our left/top/right/bottom
  // edges in order to make its own decisions about what to do. We are capable
  // of tainting that parent frameset's borders, so we have to cache this info.
  allow_border_rows_.resize(TotalRows() + 1);
  allow_border_cols_.resize(TotalCols() + 1);
}

void HTMLFrameSetElement::ResizeAxis::Resize(wtf_size_t number_of_frames) {
  deltas_.resize(number_of_frames);
  deltas_.Fill(0);
  split_being_resized_ = kNoSplit;

  // To track edges for resizability, we need to be (size + 1). This is because
  // a parent frameset may ask us for information about our left/top/right/
  // bottom edges in order to make its own decisions about what to do. We are
  // capable of tainting that parent frameset's borders, so we have to cache
  // this info.
  prevent_resize_.resize(number_of_frames + 1);
}

bool HTMLFrameSetElement::ResizeAxis::CanResizeSplitAt(int split_index) const {
  return split_index != kNoSplit && !prevent_resize_[split_index];
}

}  // namespace blink
```