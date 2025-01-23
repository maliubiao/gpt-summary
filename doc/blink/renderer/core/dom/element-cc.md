Response:
My thought process to arrive at the summary of `element.cc` functionality goes like this:

1. **Understand the Goal:** The core request is to summarize the functionality of the `element.cc` file in the Chromium Blink rendering engine. Specifically, I need to identify its primary role, connections to web technologies (JavaScript, HTML, CSS), common errors, and how user actions might lead to its execution.

2. **Initial Scan for Keywords:** I quickly read through the included headers and the start of the `Element` class definition. Keywords like "DOM", "style", "events", "accessibility", "layout", "HTML", "CSS", and "JavaScript" jump out. This gives me a high-level idea that the file is central to how elements in the DOM are managed and interact with styling, scripting, and accessibility.

3. **Focus on the `Element` Class:** The filename `element.cc` strongly suggests the primary responsibility is the `Element` class. I look for its core attributes and methods. The provided code shows:
    * Inheritance from `ContainerNode`: Indicates it handles children.
    * `tag_name_`:  Stores the HTML tag.
    * `computed_style_`: Manages the element's computed style.
    * Methods related to attributes (`GetAttribute`, `SetAttribute`, `GetIntegralAttribute`), classes (`classList`),  styling (`GetInlineStyle`, `GetComputedStyle`), event handling, focus, scrolling, shadow DOM, and accessibility.

4. **Analyze Included Headers:**  The `#include` directives are extremely informative. I categorize them mentally:
    * **Core DOM:**  `dom/attr.h`, `dom/container_node.h`, `dom/document.h`, `dom/dom_token_list.h`, `dom/shadow_root.h`, etc. These confirm the file's central role in the DOM structure.
    * **CSS and Styling:** `css/`, `style/`. Many headers relate to CSS parsing, style resolution, computed styles, and interactions with the rendering engine's styling mechanisms.
    * **HTML:** `html/`. Headers for specific HTML elements (`html_div_element.h`, `html_image_element.h`), forms, and HTML parsing highlight the connection to the structure of web pages.
    * **JavaScript Binding:** `bindings/core/v8/`. Headers involving `V8` indicate the file bridges the gap between the C++ DOM and JavaScript.
    * **Events:** `events/`. Headers related to event dispatching and specific event types show how elements react to user interactions and script-driven events.
    * **Accessibility:** `accessibility/`. Headers for `AXContext` and `AXObjectCache` confirm the file's involvement in making web content accessible.
    * **Layout:** `layout/`. Headers related to layout objects and the layout tree demonstrate the element's role in the visual presentation of the page.
    * **Other Blink Components:**  Headers from `core/animation`, `core/editing`, `core/fullscreen`, `core/scroll`, etc., reveal the broad range of features the `Element` class touches.

5. **Identify Key Functionality Blocks:** Based on the headers and initial scan, I can group the functionalities:
    * **Basic Element Properties:** Tag name, attributes, classes.
    * **Styling:**  Applying and managing CSS styles.
    * **Event Handling:**  Responding to user actions and script events.
    * **DOM Manipulation:**  Adding/removing children, traversing the tree.
    * **Focus and Interaction:**  Handling focus, tab navigation.
    * **Shadow DOM:**  Creating and managing encapsulated subtrees.
    * **Accessibility:** Providing information to assistive technologies.
    * **Layout and Rendering:**  Contributing to the visual layout of the page.
    * **JavaScript Integration:**  Exposing DOM elements to JavaScript.

6. **Connect to Web Technologies:**
    * **HTML:** The file directly deals with HTML elements, parsing attributes, and reflecting them in the DOM.
    * **CSS:**  It manages how CSS rules are applied to elements, affecting their appearance.
    * **JavaScript:**  It provides the underlying C++ implementation for DOM APIs that JavaScript uses to interact with web page structure and style.

7. **Consider Common Errors and User Actions:**  I think about what developers and users might do that involves element manipulation:
    * **JavaScript Errors:** Incorrectly accessing or modifying element properties, event handling errors.
    * **HTML Errors:** Invalid HTML structure, misused attributes.
    * **CSS Errors:**  Incorrect CSS syntax, unintended style conflicts.
    * **User Actions:** Clicking, typing, scrolling, focusing elements.

8. **Deduce Debugging Clues:** Knowing the file's role, I consider what kind of debugging information would be relevant: element properties, styles, event listeners, DOM tree structure.

9. **Structure the Summary:** I organize the findings into logical sections based on the prompt's requirements:
    * **Core Functionality:**  The main purpose of the file.
    * **Relationship to Web Technologies:**  Concrete examples of how it interacts with HTML, CSS, and JavaScript.
    * **Common Errors:**  Potential pitfalls for developers.
    * **User Actions and Debugging:** How user behavior leads to this code and what to look for when debugging.

10. **Refine and Elaborate:** I review my initial points, adding more detail and specific examples based on the code snippets and header files. For instance, noticing the `EnqueueAutofocus` function leads to an explanation of the autofocus attribute. Seeing the various `V8` headers helps explain the JavaScript bridge.

By following these steps, I can move from a basic understanding of the filename to a comprehensive summary of the `element.cc` file's critical role within the Blink rendering engine. The key is to analyze the provided code, understand the context within a browser engine, and relate it back to the core web technologies.
这是Blink渲染引擎中 `blink/renderer/core/dom/element.cc` 文件的第一部分，它定义了 `Element` 类的核心功能。`Element` 类是所有 HTML 和 SVG 元素的基类，负责管理元素的基本属性、行为和与其他 Web 技术（JavaScript, HTML, CSS）的交互。

**功能归纳:**

1. **核心 DOM 节点表示:**  `element.cc` 定义了 `Element` 类，它是 Blink 中表示 DOM 树中元素的关键类。它继承自 `ContainerNode`，因此可以包含其他节点（如文本节点或其他元素）。

2. **元素属性管理:**  包含了处理元素属性（attributes）的逻辑，例如获取、设置、删除属性，以及处理特殊的反射属性（reflecting attributes）。

3. **CSS 样式应用:**  `Element` 类是应用 CSS 样式的核心，包含了获取和管理元素的内联样式 (`style` 属性) 和计算样式（computed style）的逻辑。这涉及到与 CSS 解析器、样式解析器和布局引擎的交互。

4. **事件处理:**  `Element` 类是事件目标，负责接收和分发事件。它包含了添加、移除事件监听器，以及触发事件的机制。

5. **焦点控制:**  包含了与元素焦点相关的逻辑，例如判断元素是否可聚焦、设置和获取 `tabindex` 属性、以及处理 `focus` 和 `blur` 事件。

6. **Shadow DOM 支持:**  包含了创建和管理 Shadow DOM 的功能，允许元素拥有独立的、封装的 DOM 子树。

7. **Accessibility (可访问性):**  `Element` 类与 Accessibility 模块交互，提供元素的语义信息给辅助技术，例如屏幕阅读器。

8. **JavaScript 绑定:**  `Element` 类通过 V8 绑定暴露给 JavaScript，使得 JavaScript 代码可以操作 DOM 元素。

9. **布局相关:**  虽然布局的主要逻辑在 `LayoutObject` 中，但 `Element` 类也包含一些与布局相关的逻辑，例如判断元素是否需要布局、以及触发布局更新。

10. **通用元素行为:**  定义了一些所有元素共享的通用行为，例如克隆节点、比较节点、获取元素的文本内容等。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML:**
    * **功能:**  `Element` 类直接对应 HTML 文档中的标签。
    * **举例:**  当 HTML 解析器遇到 `<div id="container"></div>` 时，会创建一个 `Element` 类的实例，其 `tag_name_` 为 "div"，并使用 "container" 设置其 `id` 属性。

* **CSS:**
    * **功能:** `Element` 类负责应用 CSS 规则以确定元素的最终样式。
    * **举例:**  CSS 规则 `.container { width: 100px; }` 会影响 `id` 为 "container" 的 `Element` 实例的计算样式 (`computed_style_`)，设置其宽度为 100px。可以通过 JavaScript 的 `element.style.width` (访问内联样式) 或 `getComputedStyle(element).width` (访问计算样式) 来访问或操作。

* **JavaScript:**
    * **功能:** `Element` 类提供了 JavaScript 可以操作的 DOM 接口。
    * **举例:**  JavaScript 代码 `document.getElementById('container')` 会返回与 HTML 中的 `<div id="container">` 对应的 `Element` 实例。JavaScript 可以调用该实例的方法，例如 `element.setAttribute('class', 'new-class')` 来修改元素的属性，或 `element.addEventListener('click', function() { ... })` 来添加事件监听器。

**逻辑推理 (假设输入与输出):**

* **假设输入:** 一个 `div` 元素被添加到 DOM 中。
* **输出:**  `element.cc` 中的代码会被调用来创建 `Element` 对象，设置其标签名为 "div"，并初始化相关数据结构。

* **假设输入:** JavaScript 代码 `element.classList.add('highlight')` 被执行在一个 `Element` 实例上。
* **输出:**  `element.cc` 中处理 `classList` 属性的代码会被调用，将 "highlight" 添加到元素的 class 属性中，并可能触发样式重新计算。

**用户或编程常见的使用错误举例:**

* **错误:** 尝试访问一个不存在的属性，例如 `element.nonExistentProperty`。
* **`element.cc` 中的处理:**  `Element` 类会处理属性的获取，对于不存在的属性，通常会返回 `nullptr` 或默认值，避免程序崩溃。JavaScript 可能会得到 `undefined`。

* **错误:** 在 JavaScript 中设置了错误的 CSS 属性值，例如 `element.style.width = 'abc'`.
* **`element.cc` 中的处理:**  虽然 `element.cc` 不直接负责 JavaScript 的错误处理，但它会接收到这个无效的值，并可能在样式解析阶段拒绝应用，或者将其解析为默认值。浏览器控制台可能会显示警告。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中加载网页:**  HTML 解析器开始解析网页的 HTML 结构。
2. **解析器遇到 HTML 标签:**  例如 `<button id="myButton">Click Me</button>`。
3. **创建 `Element` 实例:**  Blink 的 HTML 解析器会调用 `element.cc` 中的代码，创建一个 `HTMLButtonElement` 类的实例（`Element` 的子类）。
4. **设置元素属性:** 解析器会读取标签的属性，例如 "id"，并调用 `Element::setAttribute()` 方法来设置元素的属性。
5. **应用 CSS 样式:** 渲染引擎会根据 CSS 规则，计算元素的最终样式。这涉及到访问 `Element` 实例的 `computed_style_`。
6. **用户点击按钮:**  浏览器检测到用户的点击操作。
7. **事件分发:**  事件系统会创建一个 `MouseEvent` 对象，并将其分发到目标元素（`HTMLButtonElement` 实例）。
8. **事件监听器执行:** 如果 JavaScript 代码中为该按钮添加了点击事件监听器，`element.cc` 中的事件处理逻辑会将事件传递给 JavaScript 引擎执行相应的回调函数.

**总结:**

`blink/renderer/core/dom/element.cc` 的第一部分主要负责定义 `Element` 类的基础结构和核心功能，使其能够作为 DOM 树中的基本构建块，并与 HTML 结构、CSS 样式和 JavaScript 脚本进行交互。它为元素的属性管理、样式应用、事件处理、焦点控制、Shadow DOM 支持和可访问性提供了基础机制。理解 `Element` 类的功能是理解 Blink 渲染引擎如何处理网页内容的关键。

### 提示词
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Peter Kelly (pmk@post.com)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 *           (C) 2007 David Smith (catfish.man@gmail.com)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012, 2013 Apple Inc.
 * All rights reserved.
 *           (C) 2007 Eric Seidel (eric@webkit.org)
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

#include "third_party/blink/renderer/core/dom/element.h"

#include <algorithm>
#include <bitset>
#include <limits>
#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "cc/input/snap_selection_strategy.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/public/web/web_autofill_state.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_aria_notification_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_check_visibility_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_pointer_lock_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_into_view_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_to_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_shadow_root_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_boolean_scrollintoviewoptions.h"
#include "third_party/blink/renderer/core/accessibility/ax_context.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/animation/css/css_animations.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/css/container_query_data.h"
#include "third_party/blink/renderer/core/css/container_query_evaluator.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_markup.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_selector_watch.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/cssom/inline_style_property_map.h"
#include "third_party/blink/renderer/core/css/native_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/out_of_flow_data.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"
#include "third_party/blink/renderer/core/css/post_style_update_scope.h"
#include "third_party/blink/renderer/core/css/property_set_css_style_declaration.h"
#include "third_party/blink/renderer/core/css/resolver/selector_filter_parent_scope.h"
#include "third_party/blink/renderer/core/css/resolver/style_adjuster.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_stats.h"
#include "third_party/blink/renderer/core/css/selector_query.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_containment_scope_tree.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/column_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/dataset_dom_string_map.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_lifecycle.h"
#include "third_party/blink/renderer/core/dom/document_part_root.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/element_data_cache.h"
#include "third_party/blink/renderer/core/dom/element_rare_data_vector.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_result.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatcher.h"
#include "third_party/blink/renderer/core/dom/events/event_path.h"
#include "third_party/blink/renderer/core/dom/first_letter_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder.h"
#include "third_party/blink/renderer/core/dom/mutation_observer_interest_group.h"
#include "third_party/blink/renderer/core/dom/mutation_record.h"
#include "third_party/blink/renderer/core/dom/named_node_map.h"
#include "third_party/blink/renderer/core/dom/node_cloning_data.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/presentation_attribute_style.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/slot_assignment.h"
#include "third_party/blink/renderer/core/dom/space_split_string.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/dom/whitespace_attacher.h"
#include "third_party/blink/renderer/core/editing/commands/undo_stack.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/focus_event.h"
#include "third_party/blink/renderer/core/events/interest_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_list.h"
#include "third_party/blink/renderer/core/html/anchor_element_observer.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_field_set_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_controls_collection.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_options_collection.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_quote_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_table_rows_collection.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/nesting_level_incrementer.h"
#include "third_party/blink/renderer/core/html/parser/html_element_stack.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_utils.h"
#include "third_party/blink/renderer/core/html_element_type_helpers.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/intersection_observer/element_intersection_observer_data.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_controller.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/forms/layout_fieldset.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/root_scroller_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/sync_scroll_attempt_heuristic.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observation.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_size.h"
#include "third_party/blink/renderer/core/sanitizer/sanitizer_api.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/scroll/smooth_scroll_sequencer.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/svg/svg_a_element.h"
#include "third_party/blink/renderer/core/svg/svg_animated_href.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_stop_element.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_use_element.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_types_util.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_pseudo_element_base.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_transition_element.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/core/xml_names.h"
#include "third_party/blink/renderer/platform/bindings/dom_data_store.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_activity_logger.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_context_data.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/renderer/platform/region_capture_crop_id.h"
#include "third_party/blink/renderer/platform/restriction_target_id.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/bidi_paragraph.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/hash_functions.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/text_position.h"
#include "ui/accessibility/ax_mode.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

namespace {

class DisplayLockStyleScope {
  STACK_ALLOCATED();

 public:
  explicit DisplayLockStyleScope(Element* element) : element_(element) {
    // Note that we don't store context as a member of this scope, since it may
    // get created as part of element self style recalc.
  }

  ~DisplayLockStyleScope() {
    if (auto* context = element_->GetDisplayLockContext()) {
      if (did_update_children_) {
        context->DidStyleChildren();
        if (auto* document_rules = DocumentSpeculationRules::FromIfExists(
                element_->GetDocument())) {
          document_rules->DidStyleChildren(element_);
        }
      }
    }
  }

  bool ShouldUpdateChildStyle() const {
    // We can't calculate this on construction time, because the element's lock
    // state may changes after self-style calculation ShouldStyle(children).
    auto* context = element_->GetDisplayLockContext();
    return !context || context->ShouldStyleChildren();
  }
  void DidUpdateChildStyle() { did_update_children_ = true; }
  // Returns true if the element was force unlocked due to missing requirements.
  StyleRecalcChange DidUpdateSelfStyle(StyleRecalcChange change) {
    if (auto* context = element_->GetDisplayLockContext()) {
      context->DidStyleSelf();
      // After we notified context that we styled self, it may cause an unlock /
      // modification to the blocked style change, so accumulate the change here
      // again. Note that if the context is locked we will restore it as the
      // blocked style change in RecalcStyle.
      return change.Combine(context->TakeBlockedStyleRecalcChange());
    }
    return change;
  }

  void NotifyChildStyleRecalcWasBlocked(const StyleRecalcChange& change) {
    DCHECK(!ShouldUpdateChildStyle());
    // The only way to be blocked here is if we have a display lock context.
    DCHECK(element_->GetDisplayLockContext());

    element_->GetDisplayLockContext()->NotifyChildStyleRecalcWasBlocked(change);
    if (auto* document_rules =
            DocumentSpeculationRules::FromIfExists(element_->GetDocument())) {
      document_rules->ChildStyleRecalcBlocked(element_);
    }
  }

 private:
  Element* element_;
  bool did_update_children_ = false;
};

bool IsRootEditableElementWithCounting(const Element& element) {
  bool is_editable = IsRootEditableElement(element);
  Document& doc = element.GetDocument();
  if (!doc.IsActive()) {
    return is_editable;
  }
  // -webkit-user-modify doesn't affect text control elements.
  if (element.IsTextControl()) {
    return is_editable;
  }
  const auto* style = element.GetComputedStyle();
  if (!style) {
    return is_editable;
  }
  auto user_modify = style->UsedUserModify();
  AtomicString ce_value =
      element.FastGetAttribute(html_names::kContenteditableAttr).LowerASCII();
  if (ce_value.IsNull() || ce_value == keywords::kFalse) {
    if (user_modify == EUserModify::kReadWritePlaintextOnly) {
      UseCounter::Count(doc, WebFeature::kPlainTextEditingEffective);
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyPlainTextEffective);
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyEffective);
    } else if (user_modify == EUserModify::kReadWrite) {
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyReadWriteEffective);
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyEffective);
    }
  } else if (ce_value.empty() || ce_value == keywords::kTrue) {
    if (user_modify == EUserModify::kReadWritePlaintextOnly) {
      UseCounter::Count(doc, WebFeature::kPlainTextEditingEffective);
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyPlainTextEffective);
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyEffective);
    } else if (user_modify == EUserModify::kReadOnly) {
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyReadOnlyEffective);
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyEffective);
    }
  } else if (ce_value == keywords::kPlaintextOnly) {
    UseCounter::Count(doc, WebFeature::kPlainTextEditingEffective);
    if (user_modify == EUserModify::kReadWrite) {
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyReadWriteEffective);
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyEffective);
    } else if (user_modify == EUserModify::kReadOnly) {
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyReadOnlyEffective);
      UseCounter::Count(doc, WebFeature::kWebKitUserModifyEffective);
    }
  }
  return is_editable;
}

bool HasLeftwardDirection(const Element& element) {
  auto* style = element.GetComputedStyle();
  if (!style) {
    return false;
  }

  const auto writing_direction = style->GetWritingDirection();
  return writing_direction.InlineEnd() == PhysicalDirection::kLeft ||
         writing_direction.BlockEnd() == PhysicalDirection::kLeft;
}

bool HasUpwardDirection(const Element& element) {
  auto* style = element.GetComputedStyle();
  if (!style) {
    return false;
  }

  const auto writing_direction = style->GetWritingDirection();
  return writing_direction.InlineEnd() == PhysicalDirection::kUp ||
         writing_direction.BlockEnd() == PhysicalDirection::kUp;
}

// TODO(meredithl): Automatically generate this method once the IDL compiler has
// been refactored. See http://crbug.com/839389 for details.
bool IsElementReflectionAttribute(const QualifiedName& name) {
  if (name == html_names::kAriaActivedescendantAttr) {
    return true;
  }
  if (name == html_names::kAriaControlsAttr) {
    return true;
  }
  if (name == html_names::kAriaDescribedbyAttr) {
    return true;
  }
  if (name == html_names::kAriaDetailsAttr) {
    return true;
  }
  if (name == html_names::kAriaErrormessageAttr) {
    return true;
  }
  if (name == html_names::kAriaFlowtoAttr) {
    return true;
  }
  if (name == html_names::kAriaLabeledbyAttr) {
    return true;
  }
  if (name == html_names::kAriaLabelledbyAttr) {
    return true;
  }
  if (name == html_names::kAriaOwnsAttr) {
    return true;
  }
  if (name == html_names::kPopovertargetAttr) {
    return true;
  }
  if (name == html_names::kAnchorAttr) {
    return true;
  }
  if (name == html_names::kCommandforAttr) {
    return true;
  }
  if (name == html_names::kInteresttargetAttr) {
    return true;
  }
  if (name == html_names::kSelectedcontentelementAttr) {
    return true;
  }
  return false;
}

// Checks that the given element |candidate| is a descendant of
// |attribute_element|'s  shadow including ancestors.
bool ElementIsDescendantOfShadowIncludingAncestor(
    const Element& attribute_element,
    const Element& candidate) {
  auto* candidate_root = &candidate.TreeRoot();
  auto* element_root = &attribute_element.TreeRoot();
  while (true) {
    if (candidate_root == element_root) {
      return true;
    }
    if (!element_root->IsInShadowTree()) {
      return false;
    }
    element_root = &element_root->OwnerShadowHost()->TreeRoot();
  }
}

// The first algorithm in
// https://html.spec.whatwg.org/C/#the-autofocus-attribute
void EnqueueAutofocus(Element& element) {
  // When an element with the autofocus attribute specified is inserted into a
  // document, run the following steps:
  DCHECK(element.isConnected());
  if (!element.IsAutofocusable()) {
    return;
  }

  // 1. If the user has indicated (for example, by starting to type in a form
  // control) that they do not wish focus to be changed, then optionally return.

  // We don't implement this optional step. If other browsers have such
  // behavior, we should follow it or standardize it.

  // 2. Let target be the element's node document.
  Document& doc = element.GetDocument();
  LocalDOMWindow* window = doc.domWindow();

  // 3. If target's browsing context is null, then return.
  if (!window) {
    return;
  }

  // 4. If target's active sandboxing flag set has the sandboxed automatic
  // features browsing context flag, then return.
  if (window->IsSandboxed(
          network::mojom::blink::WebSandboxFlags::kAutomaticFeatures)) {
    window->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kSecurity,
        mojom::ConsoleMessageLevel::kError,
        String::Format(
            "Blocked autofocusing on a <%s> element because the element's "
            "frame "
            "is sandboxed and the 'allow-scripts' permission is not set.",
            element.TagQName().ToString().Ascii().c_str())));
    return;
  }

  // 5. For each ancestorBC of target's browsing context's ancestor browsing
  // contexts: if ancestorBC's active document's origin is not same origin with
  // target's origin, then return.
  for (Frame* frame = doc.GetFrame(); frame; frame = frame->Parent()) {
    if (!frame->IsCrossOriginToOutermostMainFrame()) {
      continue;
    }
    window->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kSecurity,
        mojom::ConsoleMessageLevel::kError,
        String::Format("Blocked autofocusing on a <%s> element in a "
                       "cross-origin subframe.",
                       element.TagQName().ToString().Ascii().c_str())));
    return;
  }

  // 6. Let topDocument be the active document of target's browsing context's
  // top-level browsing context.
  Document& top_document = element.GetDocument().TopDocument();

  top_document.EnqueueAutofocusCandidate(element);
}

bool WillUpdateSizeContainerDuringLayout(const LayoutObject& layout_object) {
  // When a size-container LayoutObject is marked as needs layout,
  // BlockNode::Layout() will resume style recalc with an up-to-date size in
  // StyleEngine::UpdateStyleAndLayoutTreeForContainer().
  return layout_object.NeedsLayout() &&
         layout_object.IsEligibleForSizeContainment();
}

bool IsValidShadowHostName(const AtomicString& local_name) {
  DEFINE_STATIC_LOCAL(HashSet<AtomicString>, shadow_root_tags,
                      ({
                          html_names::kArticleTag.LocalName(),
                          html_names::kAsideTag.LocalName(),
                          html_names::kBlockquoteTag.LocalName(),
                          html_names::kBodyTag.LocalName(),
                          html_names::kDivTag.LocalName(),
                          html_names::kFooterTag.LocalName(),
                          html_names::kH1Tag.LocalName(),
                          html_names::kH2Tag.LocalName(),
                          html_names::kH3Tag.LocalName(),
                          html_names::kH4Tag.LocalName(),
                          html_names::kH5Tag.LocalName(),
                          html_names::kH6Tag.LocalName(),
                          html_names::kHeaderTag.LocalName(),
                          html_names::kNavTag.LocalName(),
                          html_names::kMainTag.LocalName(),
                          html_names::kPTag.LocalName(),
                          html_names::kSectionTag.LocalName(),
                          html_names::kSpanTag.LocalName(),
                      }));
  return shadow_root_tags.Contains(local_name);
}

const AtomicString& V8ShadowRootModeToString(V8ShadowRootMode::Enum mode) {
  if (mode == V8ShadowRootMode::Enum::kOpen) {
    return keywords::kOpen;
  }
  return keywords::kClosed;
}

}  // namespace

Element::Element(const QualifiedName& tag_name,
                 Document* document,
                 ConstructionType type)
    : ContainerNode(document, type),
      tag_name_(tag_name),
      computed_style_(nullptr) {}

Element* Element::GetAnimationTarget() {
  return this;
}

bool Element::HasElementFlag(ElementFlags mask) const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->HasElementFlag(mask);
  }
  return false;
}

void Element::SetElementFlag(ElementFlags mask, bool value) {
  if (ElementRareDataVector* data = GetElementRareData()) {
    data->SetElementFlag(mask, value);
  } else if (value) {
    EnsureElementRareData().SetElementFlag(mask, value);
  }
}

void Element::ClearElementFlag(ElementFlags mask) {
  if (ElementRareDataVector* data = GetElementRareData()) {
    data->ClearElementFlag(mask);
  }
}

void Element::ClearTabIndexExplicitlyIfNeeded() {
  if (ElementRareDataVector* data = GetElementRareData()) {
    data->ClearTabIndexExplicitly();
  }
}

void Element::SetTabIndexExplicitly() {
  EnsureElementRareData().SetTabIndexExplicitly();
}

void Element::setTabIndex(int value) {
  SetIntegralAttribute(html_names::kTabindexAttr, value);
}

int Element::tabIndex() const {
  // https://html.spec.whatwg.org/C/#dom-tabindex
  // The tabIndex IDL attribute must reflect the value of the tabindex content
  // attribute. The default value is 0 if the element is an a, area, button,
  // frame, iframe, input, object, select, textarea, or SVG a element, or is a
  // summary element that is a summary for its parent details. The default value
  // is −1 otherwise.
  return GetIntegralAttribute(html_names::kTabindexAttr, DefaultTabIndex());
}

int Element::DefaultTabIndex() const {
  return -1;
}

bool Element::IsFocusableStyle(UpdateBehavior update_behavior) const {
  // TODO(vmpstr): Note that this may be called by accessibility during layout
  // tree attachment, at which point we might not have cleared all of the dirty
  // bits to ensure that the layout tree doesn't need an update. This should be
  // fixable by deferring AX tree updates as a separate phase after layout tree
  // attachment has happened. At that point `InStyleRecalc()` portion of the
  // following DCHECK can be removed.

  // In order to check focusable style, we use the existence of LayoutObjects
  // as a proxy for determining whether the element would have a display mode
  // that restricts visibility (such as display: none). However, with
  // display-locking, it is possible that we deferred such LayoutObject
  // creation. We need to ensure to update style and layout tree to have
  // up-to-date information.
  //
  // Note also that there may be situations where focus / keyboard navigation
  // causes us to have dirty style, so we update StyleAndLayoutTreeForNode here.
  // If the style and layout tree are clean, then this should be a quick
  // operation. See crbug.com/1079385 for details.
  //
  // Also note that if this node is ignored due to a display lock for focus
  // activation reason, we simply return false to avoid updating style & layout
  // tree for this node.
  if (DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
          *this, DisplayLockActivationReason::kUserFocus)) {
    return false;
  }
  if (update_behavior == UpdateBehavior::kStyleAndLayout) {
    GetDocument().UpdateStyleAndLayoutTreeForElement(
        this, DocumentUpdateReason::kFocus);
  } else {
    DCHECK(!NeedsStyleRecalc()) << this;
  }
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetDocument().Lifecycle());

  DCHECK(
      !GetDocument().IsActive() || GetDocument().InStyleRecalc() ||
      !GetDocument().NeedsLayoutTreeUpdateForNodeIncludingDisplayLocked(*this))
      << *this;

  if (LayoutObject* layout_object = GetLayoutObject()) {
    return layout_object->StyleRef().IsFocusable();
  }

  if (HasDisplayContentsStyle() &&
      RuntimeEnabledFeatures::DisplayContentsFocusableEnabled()) {
    if (const ComputedStyle* style =
            ComputedStyle::NullifyEnsured(GetComputedStyle())) {
      return style->IsFocusable();
    }
  }

  // If a canvas represents embedded content, its descendants are not rendered.
  // But they are still allowed to be focusable as long as their style allows
  // focus, their canvas is rendered, and its style allows focus.
  if (IsInCanvasSubtree()) {
    const ComputedStyle* style = GetComputedStyle();
    if (!style || !style->IsFocusable()) {
      return false;
    }

    const HTMLCanvasElement* canvas =
        Traversal<HTMLCanvasElement>::FirstAncestorOrSelf(*this);
    DCHECK(canvas);
    if (LayoutObject* layout_object = canvas->GetLayoutObject()) {
      return layout_object->IsC
```