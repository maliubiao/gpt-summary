Response:
The user wants to understand the functionality of the `ax_node_object.cc` file in the Chromium Blink engine. I need to:

1. **Summarize the file's core purpose:** Based on the filename and the included headers, this file is responsible for creating and managing accessibility objects (`AXNodeObject`) that represent DOM nodes.
2. **Identify relationships with web technologies:** Determine how this file interacts with JavaScript, HTML, and CSS.
3. **Provide illustrative examples:**  Give specific scenarios showcasing these interactions.
4. **Explain logical reasoning (if any):**  If the code snippet implies any decision-making, I need to provide hypothetical inputs and outputs.
5. **Point out potential usage errors:**  Identify common mistakes developers might make that could lead to issues in this area.
6. **Describe user actions leading here:** Explain the sequence of user interactions that would involve this file.
7. **Focus on the provided code snippet:**  Analyze the code, especially the `ShouldIncludeBasedOnSemantics` function and the surrounding helper functions.
8. **Summarize the functionality of *this specific part* of the file:** Since this is part 1 of 10, the request is to summarize the features within this initial chunk.

**Mental Walkthrough of the Code Snippet:**

* **Headers:** The included headers indicate this file interacts with various aspects of the rendering engine, including DOM, CSS, layout, events, and accessibility.
* **Helper Functions:**  The code defines numerous helper functions like `IsPotentialInPageLinkTarget`, `IsLinkable`, `ShouldIgnoreListItem`, `GetDOMTableAXAncestor`, `CreateKeyboardEvent`, `GetTitle`, `CanHaveInlineTextBoxChildren`, `HasLayoutText`, and `GetListMarker`. These functions suggest the file is responsible for determining accessibility properties and behavior based on DOM structure, layout, and element attributes.
* **`AXNodeObject` Class:** This is the core class. It takes a `Node` or `LayoutObject` as input, signifying its role in bridging the DOM/layout tree with the accessibility tree.
* **`ShouldIncludeBasedOnSemantics` Function:** This function is central to determining if a DOM node should be represented in the accessibility tree. It checks for ARIA attributes, element types (like SVG), and other semantic cues. The logic within this function is about filtering and deciding which elements are relevant for accessibility.

**Hypothesized Functionality based on the Code:**

This file seems to be responsible for:

* **Creating accessibility representations of DOM nodes.**
* **Determining the inclusion of nodes in the accessibility tree based on semantic information (ARIA attributes, element types).**
* **Handling user interactions that might involve accessibility (like slider adjustments).**
* **Providing information about the accessibility properties of a node.**

**Connecting to Web Technologies:**

* **HTML:** The file extensively uses HTML element types (`HTMLAnchorElement`, `HTMLInputElement`, `SVGSVGElement`, etc.) and attributes (`aria-label`, `title`, `alt`).
* **CSS:** The file checks layout properties (`display: none`) and uses layout objects to determine accessibility information.
* **JavaScript:** While not directly in this snippet, the file interacts with JavaScript events (like `keydown`, `keyup`) when handling accessibility actions. JavaScript can also manipulate the DOM, which will be reflected in the accessibility tree built by this file.

**Confidence Score:** 5/5 - The code and included headers strongly suggest the file's purpose.

**Next Steps:** I will now structure the answer, starting with a general summary of the file's function and then elaborating on the connections with web technologies, examples, logical reasoning, potential errors, user actions, and finally, a summary of the specific functionality covered in this first part.
这是 `blink/renderer/modules/accessibility/ax_node_object.cc` 文件的第一部分，主要负责 **创建和管理表示 DOM 节点的辅助功能对象 (Accessibility Object, AXObject)**，并确定这些对象是否应该包含在辅助功能树中。

**功能归纳 (第1部分):**

1. **AXNodeObject 的创建和初始化:**  定义了 `AXNodeObject` 类，它是 `AXObject` 的一个子类，用于表示 DOM 树中的节点。它可以由 `Node` 或 `LayoutObject` 初始化，根据是否需要关联布局信息来决定。
2. **辅助功能树包含判断 (`ShouldIncludeBasedOnSemantics`):**  核心功能是决定一个 DOM 节点是否应该被包含到辅助功能树中。这部分代码实现了基于语义信息的判断逻辑，例如：
    * **Presentational 属性:** 如果元素被标记为 presentational (例如，通过 ARIA `role="presentation"` 或 `role="none"`)，通常会被忽略。
    * **特定元素类型的处理:**  对一些特定的 HTML 和 SVG 元素进行了特殊处理，例如：
        * **Document 节点:** 始终包含。
        * **Ruby 注解:**  默认忽略，避免重复朗读。
        * **表单控件过滤:**  根据特定的过滤条件忽略某些表单控件。
        * **SVG `<symbol>` 元素:** 作为模板定义，通常被忽略。
        * **非空的 SVG 根元素 (`<svg>`)**:  通常包含。
        * **包含 `<title>` 或 `<desc>` 子元素的 SVG 元素:** 通常包含。
        * **SVG `<g>` 元素:** 可以根据设置选择是否忽略。
3. **辅助功能动作 (`AlterSliderOrSpinButtonValue`):** 实现了修改滑块 (slider) 或微调按钮 (spinbutton) 值的辅助功能动作。这涉及：
    * 获取当前值和步长。
    * 根据增加或减少动作计算新值。
    * 根据配置选择直接设置值或模拟键盘事件 (向上/向下/向左/向右箭头键)。模拟键盘事件可以触发 JavaScript 的事件处理程序。
4. **获取激活后代 (`ActiveDescendant`):**  用于获取具有 `aria-activedescendant` 属性的元素的激活子元素，常用于自定义的组合框或菜单等组件。
5. **判断是否可以包含内联文本框子节点 (`CanHaveInlineTextBoxChildren`):**  基于元素的角色和是否有布局对象来判断其是否可以包含表示文本内容的内联文本框子节点。
6. **判断是否有布局文本 (`HasLayoutText`):**  判断一个辅助功能对象是否关联着需要布局的文本内容。
7. **获取列表标记 (`GetListMarker`):**  用于获取列表项的标记 (bullet point 或数字)。
8. **一些辅助函数:** 定义了许多辅助函数，用于判断元素的特定属性或状态，例如 `IsPotentialInPageLinkTarget` (是否是页面内链接的目标), `IsLinkable` (是否可以作为链接), `ShouldIgnoreListItem` (是否应该忽略列表项) 等。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **功能:** `AXNodeObject` 直接关联到 HTML 元素。`ShouldIncludeBasedOnSemantics` 函数会检查 HTML 元素的标签名 (例如 `<a>`, `<img>`, `<svg>`) 和属性 (例如 `role`, `aria-label`, `aria-activedescendant`) 来决定是否包含该元素。
    * **举例:**
        * `<div role="presentation">`:  `ShouldIncludeBasedOnSemantics` 会因为 `role="presentation"` 而返回 `kIgnoreObject`，该 `div` 不会出现在辅助功能树中。
        * `<img src="image.png" alt="描述">`: `ShouldIncludeBasedOnSemantics` 会包含这个 `img` 元素，因为它是语义化的内容，并且 `alt` 属性提供了文本描述。
        * `<svg><title>SVG 标题</title></svg>`: `ShouldIncludeBasedOnSemantics` 会包含这个 `svg` 元素，因为它包含 `<title>` 子元素。
* **CSS:**
    * **功能:**  虽然这个代码片段没有直接操作 CSS 属性，但辅助功能树的构建依赖于渲染引擎的布局信息。`HasLayoutText` 函数会检查元素是否有布局对象。如果一个元素通过 CSS 设置了 `display: none;`，它通常不会有布局对象，因此也不会被包含在辅助功能树中 (除非有特殊的 ARIA 属性覆盖)。
    * **举例:**
        * `<div style="display: none;">`:  这个 `div` 通常不会被包含到辅助功能树中，因为它不可见。
        * 带有 CSS 计数器的列表 (`<ol style="counter-reset: item;"><li>...</li></ol>`): 列表标记的展示依赖于 CSS，`GetListMarker` 可能会与 CSS 的渲染结果相关联。
* **JavaScript:**
    * **功能:** `AlterSliderOrSpinButtonValue` 函数在模拟键盘事件时，会触发与这些事件关联的 JavaScript 事件处理程序。JavaScript 可以动态地修改 DOM 结构和属性，这些修改会影响辅助功能树的构建。
    * **举例:**
        * 一个自定义的滑块用 JavaScript 实现，监听键盘事件来更新滑块的值。当辅助功能调用 `AlterSliderOrSpinButtonValue` 并模拟箭头键时，相应的 JavaScript 事件处理程序会被触发，从而更新滑块的视觉状态。
        * JavaScript 可以动态地添加或移除元素的 `aria-label` 属性，这将直接影响辅助功能树中该元素的名称。

**逻辑推理的假设输入与输出:**

* **假设输入 (针对 `ShouldIncludeBasedOnSemantics`):** 一个 `<span aria-hidden="true">隐藏内容</span>` 元素。
* **输出:** `kIgnoreObject`，因为 `aria-hidden="true"` 指示该元素对辅助技术不可见。

* **假设输入 (针对 `AlterSliderOrSpinButtonValue`，增加滑块值):**  一个 `<input type="range" min="0" max="100" step="10" value="30">` 元素。
* **输出 (取决于是否启用合成键盘事件):**
    * **未启用:** 直接设置 `value` 为 `40` 并触发 `change` 事件。
    * **启用:** 模拟一个向右箭头键的 `keydown` 和 `keyup` 事件。

**用户或编程常见的使用错误:**

* **过度使用 `role="presentation"` 或 `aria-hidden="true"`:** 开发者可能会为了视觉效果而隐藏重要的语义内容，导致辅助技术用户无法访问这些信息。例如，将导航链接的父 `div` 设置为 `role="presentation"` 会导致整个导航结构被忽略。
* **动态更新 DOM 后未通知辅助功能树:**  如果 JavaScript 动态修改了 DOM 结构或元素的 ARIA 属性，但没有触发相应的辅助功能树更新，辅助技术可能无法获取到最新的信息。
* **自定义组件缺乏正确的 ARIA 属性:**  开发者在创建自定义的交互组件 (例如，自定义的下拉菜单) 时，如果没有正确地使用 ARIA 属性 (例如 `role`, `aria-expanded`, `aria-activedescendant`)，辅助技术用户可能无法理解和操作这些组件。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户与网页交互:** 用户使用鼠标、键盘或辅助技术与网页进行交互。
2. **辅助技术请求信息:**  屏幕阅读器等辅助技术需要获取网页的结构和内容信息。
3. **Chromium 辅助功能接口:** 辅助技术通过 Chromium 的辅助功能接口 (Accessibility APIs) 请求信息。
4. **Blink 辅助功能模块:**  Chromium 的 Blink 渲染引擎中的辅助功能模块 (包括 `ax_node_object.cc`) 负责构建和维护辅助功能树，并将信息传递给辅助技术。
5. **创建 `AXNodeObject`:** 当渲染引擎渲染 DOM 树时，会为 DOM 节点创建相应的 `AXNodeObject`。
6. **调用 `ShouldIncludeBasedOnSemantics`:**  在构建辅助功能树的过程中，会调用 `ShouldIncludeBasedOnSemantics` 来判断哪些 `AXNodeObject` 应该被包含。
7. **辅助功能动作触发:** 当用户在辅助技术中执行特定操作 (例如，增加滑块的值) 时，辅助技术会调用相应的 Chromium 辅助功能接口。
8. **调用 `AlterSliderOrSpinButtonValue`:**  Chromium 接收到辅助功能动作请求后，可能会调用 `AXNodeObject` 的相关方法，例如 `AlterSliderOrSpinButtonValue`。

**调试线索:**

* 如果辅助功能树中缺少了某个元素，可以检查该元素的 ARIA 属性和父元素的属性，以及 `ShouldIncludeBasedOnSemantics` 函数的逻辑，看是否因为某些条件而被排除。
* 如果滑块或微调按钮的辅助功能行为不正确，可以断点调试 `AlterSliderOrSpinButtonValue` 函数，查看值的计算和事件的触发是否符合预期。
* 可以使用 Chromium 的辅助功能检查工具 (例如，在 Chrome 的开发者工具中启用 Accessibility 面板) 来查看辅助功能树的结构和属性，帮助定位问题。

总而言之，`ax_node_object.cc` 的这部分代码是 Blink 渲染引擎中辅助功能实现的核心组成部分，负责将 DOM 树转换为辅助功能树，并处理与辅助功能相关的用户交互。它与 HTML 的结构、CSS 的渲染以及 JavaScript 的动态行为紧密相关。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_node_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共10部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2012, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/accessibility/ax_node_object.h"

#include <math.h>

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <queue>

#include "base/auto_reset.h"
#include "base/containers/contains.h"
#include "base/containers/fixed_flat_set.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap_options.h"
#include "third_party/blink/renderer/core/css/counter_style_map.h"
#include "third_party/blink/renderer/core/css/css_resolution_units.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/markers/custom_highlight_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/events/event_util.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/highlight/highlight.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_field_set_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_label_element.h"
#include "third_party/blink/renderer/core/html/forms/html_legend_element.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_output_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/forms/labels_node_list.h"
#include "third_party/blink/renderer/core/html/forms/radio_input_type.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_details_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_directory_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_dlist_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_hr_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_map_element.h"
#include "third_party/blink/renderer/core/html/html_menu_element.h"
#include "third_party/blink/renderer/core/html/html_meter_element.h"
#include "third_party/blink/renderer/core/html/html_olist_element.h"
#include "third_party/blink/renderer/core/html/html_paragraph_element.h"
#include "third_party/blink/renderer/core/html/html_permission_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_progress_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_summary_element.h"
#include "third_party/blink/renderer/core/html/html_table_caption_element.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_col_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html/html_table_row_element.h"
#include "third_party/blink/renderer/core/html/html_table_section_element.h"
#include "third_party/blink/renderer/core/html/html_time_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/inline/abstract_inline_text_box.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_html_canvas.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_row.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_section.h"
#include "third_party/blink/renderer/core/loader/progress_tracker.h"
#include "third_party/blink/renderer/core/mathml/mathml_element.h"
#include "third_party/blink/renderer/core/mathml_names.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_api.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/svg/svg_a_element.h"
#include "third_party/blink/renderer/core/svg/svg_desc_element.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_foreign_object_element.h"
#include "third_party/blink/renderer/core/svg/svg_g_element.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_symbol_element.h"
#include "third_party/blink/renderer/core/svg/svg_text_element.h"
#include "third_party/blink/renderer/core/svg/svg_title_element.h"
#include "third_party/blink/renderer/core/svg/svg_use_element.h"
#include "third_party/blink/renderer/core/xlink_names.h"
#include "third_party/blink/renderer/modules/accessibility/ax_block_flow_iterator.h"
#include "third_party/blink/renderer/modules/accessibility/ax_image_map_link.h"
#include "third_party/blink/renderer/modules/accessibility/ax_inline_text_box.h"
#include "third_party/blink/renderer/modules/accessibility/ax_node_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/ax_position.h"
#include "third_party/blink/renderer/modules/accessibility/ax_range.h"
#include "third_party/blink/renderer/modules/accessibility/ax_relation_cache.h"
#include "third_party/blink/renderer/platform/graphics/image_data_buffer.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/skia/include/core/SkImage.h"
#include "ui/accessibility/accessibility_features.h"
#include "ui/accessibility/ax_common.h"
#include "ui/accessibility/ax_role_properties.h"
#include "ui/events/keycodes/dom/dom_code.h"
#include "ui/events/keycodes/dom/keycode_converter.h"
#include "ui/gfx/geometry/transform.h"

namespace blink {
namespace {

bool ShouldUseLayoutNG(const blink::LayoutObject& layout_object) {
  return layout_object.IsInline() &&
         layout_object.IsInLayoutNGInlineFormattingContext();
}

// It is not easily possible to find out if an element is the target of an
// in-page link.
// As a workaround, we consider the following to be potential targets:
// - <a name>
// - <foo id> -- an element with an id that is not SVG, a <label> or <optgroup>.
//     <label> does not make much sense as an in-page link target.
//     Exposing <optgroup> is redundant, as the group is already exposed via a
//     child in its shadow DOM, which contains the accessible name.
//   #document -- this is always a potential link target via <a name="#">.
//   This is a compromise that does not include too many elements, and
//   has minimal impact on tests.
bool IsPotentialInPageLinkTarget(blink::Node& node) {
  auto* element = blink::DynamicTo<blink::Element>(&node);
  if (!element) {
    // The document itself is a potential link target, e.g. via <a name="#">.
    return blink::IsA<blink::Document>(node);
  }

  // We exclude elements that are in the shadow DOM. They cannot be linked by a
  // document fragment from the main page:as they have their own id namespace.
  if (element->ContainingShadowRoot())
    return false;

  // SVG elements are unlikely link targets, and we want to avoid creating
  // a lot of noise in the AX tree or breaking tests unnecessarily.
  if (element->IsSVGElement())
    return false;

  // <a name>
  if (auto* anchor = blink::DynamicTo<blink::HTMLAnchorElement>(element)) {
    if (anchor->HasName())
      return true;
  }

  // <foo id> not in an <optgroup> or <label>.
  if (element->HasID() && !blink::IsA<blink::HTMLLabelElement>(element) &&
      !blink::IsA<blink::HTMLOptGroupElement>(element)) {
    return true;
  }

  return false;
}

bool IsLinkable(const blink::AXObject& object) {
  if (!object.GetLayoutObject()) {
    return false;
  }

  // See https://wiki.mozilla.org/Accessibility/AT-Windows-API for the elements
  // Mozilla considers linkable.
  return object.IsLink() || object.IsImage() ||
         object.GetLayoutObject()->IsText();
}

bool IsImageOrAltText(blink::LayoutObject* layout_object, blink::Node* node) {
  DCHECK(layout_object);
  if (layout_object->IsImage()) {
    return true;
  }
  if (IsA<blink::HTMLImageElement>(node)) {
    return true;
  }
  auto* html_input_element = DynamicTo<blink::HTMLInputElement>(node);
  return html_input_element && html_input_element->HasFallbackContent();
}

bool ShouldIgnoreListItem(blink::Node* node) {
  DCHECK(node);

  // http://www.w3.org/TR/wai-aria/complete#presentation
  // A list item is presentational if its parent is a native list but
  // it has an explicit ARIA role set on it that's anything other than "list".
  blink::Element* parent = blink::FlatTreeTraversal::ParentElement(*node);
  if (!parent) {
    return false;
  }

  if (IsA<blink::HTMLMenuElement>(*parent) ||
      IsA<blink::HTMLUListElement>(*parent) ||
      IsA<blink::HTMLOListElement>(*parent)) {
    AtomicString role =
        blink::AXObject::AriaAttribute(*parent, blink::html_names::kRoleAttr);
    if (!role.empty() && role != "list" && role != "directory") {
      return true;
    }
  }
  return false;
}

bool IsNeutralWithinTable(blink::AXObject* obj) {
  if (!obj)
    return false;
  ax::mojom::blink::Role role = obj->RoleValue();
  return role == ax::mojom::blink::Role::kGroup ||
         role == ax::mojom::blink::Role::kGenericContainer ||
         role == ax::mojom::blink::Role::kRowGroup;
}

// Within a table, provide the accessible, semantic parent of |node|,
// by traversing the DOM tree, ignoring elements that are neutral in a table.
// Return the AXObject for the ancestor.
blink::AXObject* GetDOMTableAXAncestor(blink::Node* node,
                                       blink::AXObjectCacheImpl& cache) {
  // Used by code to determine roles of elements inside of an HTML table,
  // Use DOM to get parent since parent_ is not initialized yet when role is
  // being computed, and because HTML table structure should not take into
  // account aria-owns.
  if (!node)
    return nullptr;

  while (true) {
    node = blink::LayoutTreeBuilderTraversal::Parent(*node);
    if (!node)
      return nullptr;

    blink::AXObject* ax_object = cache.Get(node);
    if (ax_object && !IsNeutralWithinTable(ax_object))
      return ax_object;
  }
}

// Return the first LayoutTableSection if maybe_table is a non-anonymous
// table. If non-null, set table_out to the containing table.
blink::LayoutTableSection* FirstTableSection(
    blink::LayoutObject* maybe_table,
    blink::LayoutTable** table_out = nullptr) {
  if (auto* table = DynamicTo<blink::LayoutTable>(maybe_table)) {
    if (table->GetNode()) {
      if (table_out) {
        *table_out = table;
      }
      return table->FirstSection();
    }
  }
  if (table_out) {
    *table_out = nullptr;
  }
  return nullptr;
}

enum class AXAction {
  kActionIncrement = 0,
  kActionDecrement,
};

blink::KeyboardEvent* CreateKeyboardEvent(
    blink::LocalDOMWindow* local_dom_window,
    blink::WebInputEvent::Type type,
    AXAction action,
    blink::AccessibilityOrientation orientation,
    ax::mojom::blink::WritingDirection text_direction) {
  blink::WebKeyboardEvent key(type,
                              blink::WebInputEvent::Modifiers::kNoModifiers,
                              base::TimeTicks::Now());

  if (action == AXAction::kActionIncrement) {
    if (orientation == blink::kAccessibilityOrientationVertical) {
      key.dom_key = ui::DomKey::ARROW_UP;
      key.dom_code = static_cast<int>(ui::DomCode::ARROW_UP);
      key.native_key_code = key.windows_key_code = blink::VKEY_UP;
    } else if (text_direction == ax::mojom::blink::WritingDirection::kRtl) {
      key.dom_key = ui::DomKey::ARROW_LEFT;
      key.dom_code = static_cast<int>(ui::DomCode::ARROW_LEFT);
      key.native_key_code = key.windows_key_code = blink::VKEY_LEFT;
    } else {  // horizontal and left to right
      key.dom_key = ui::DomKey::ARROW_RIGHT;
      key.dom_code = static_cast<int>(ui::DomCode::ARROW_RIGHT);
      key.native_key_code = key.windows_key_code = blink::VKEY_RIGHT;
    }
  } else if (action == AXAction::kActionDecrement) {
    if (orientation == blink::kAccessibilityOrientationVertical) {
      key.dom_key = ui::DomKey::ARROW_DOWN;
      key.dom_code = static_cast<int>(ui::DomCode::ARROW_DOWN);
      key.native_key_code = key.windows_key_code = blink::VKEY_DOWN;
    } else if (text_direction == ax::mojom::blink::WritingDirection::kRtl) {
      key.dom_key = ui::DomKey::ARROW_RIGHT;
      key.dom_code = static_cast<int>(ui::DomCode::ARROW_RIGHT);
      key.native_key_code = key.windows_key_code = blink::VKEY_RIGHT;
    } else {  // horizontal and left to right
      key.dom_key = ui::DomKey::ARROW_LEFT;
      key.dom_code = static_cast<int>(ui::DomCode::ARROW_LEFT);
      key.native_key_code = key.windows_key_code = blink::VKEY_LEFT;
    }
  }

  return blink::KeyboardEvent::Create(key, local_dom_window, true);
}

unsigned TextStyleFlag(ax::mojom::blink::TextStyle text_style_enum) {
  return static_cast<unsigned>(1 << static_cast<int>(text_style_enum));
}

ax::mojom::blink::TextDecorationStyle
TextDecorationStyleToAXTextDecorationStyle(
    const blink::ETextDecorationStyle text_decoration_style) {
  switch (text_decoration_style) {
    case blink::ETextDecorationStyle::kDashed:
      return ax::mojom::blink::TextDecorationStyle::kDashed;
    case blink::ETextDecorationStyle::kSolid:
      return ax::mojom::blink::TextDecorationStyle::kSolid;
    case blink::ETextDecorationStyle::kDotted:
      return ax::mojom::blink::TextDecorationStyle::kDotted;
    case blink::ETextDecorationStyle::kDouble:
      return ax::mojom::blink::TextDecorationStyle::kDouble;
    case blink::ETextDecorationStyle::kWavy:
      return ax::mojom::blink::TextDecorationStyle::kWavy;
  }

  NOTREACHED();
}

String GetTitle(blink::Element* element) {
  if (!element)
    return String();

  if (blink::SVGElement* svg_element =
          blink::DynamicTo<blink::SVGElement>(element)) {
    // Don't use title() in SVG, as it calls innerText() which updates layout.
    // Unfortunately, this must duplicate some logic from SVGElement::title().
    if (svg_element->InUseShadowTree()) {
      String title = GetTitle(svg_element->OwnerShadowHost());
      if (!title.empty())
        return title;
    }
    // If we aren't an instance in a <use> or the <use> title was not found,
    // then find the first <title> child of this element. If a title child was
    // found, return the text contents.
    if (auto* title_element =
            blink::Traversal<blink::SVGTitleElement>::FirstChild(*element)) {
      return title_element->GetInnerTextWithoutUpdate();
    }
    return String();
  }

  return element->title();
}

bool CanHaveInlineTextBoxChildren(const blink::AXObject* obj) {
  if (!ui::CanHaveInlineTextBoxChildren(obj->RoleValue())) {
    return false;
  }

  // Requires a layout object for there to be any inline text boxes.
  if (!obj->GetLayoutObject()) {
    return false;
  }

  // Inline text boxes are included if and only if the parent is unignored.
  // If the parent is ignored but included in tree, the inline textbox is
  // still withheld.
  return !obj->IsIgnored();
}

bool HasLayoutText(const blink::AXObject* obj) {
  // This method should only be used when layout is clean.
#if DCHECK_IS_ON()
  DCHECK(obj->GetDocument()->Lifecycle().GetState() >=
         blink::DocumentLifecycle::kLayoutClean)
      << "Unclean document at lifecycle "
      << obj->GetDocument()->Lifecycle().ToString();
#endif

  // If no layout object, could be display:none or display locked.
  if (!obj->GetLayoutObject()) {
    return false;
  }

  if (blink::DisplayLockUtilities::LockedAncestorPreventingPaint(
          *obj->GetLayoutObject())) {
    return false;
  }

  // Only text has inline textbox children.
  if (!obj->GetLayoutObject()->IsText()) {
    return false;
  }

  // TODO(accessibility): Unclear why text would need layout if it's not display
  // locked and the document is currently in a clean layout state.
  // It seems to be fairly rare, but is creating some crashes, and there is
  // no repro case yet.
  if (obj->GetLayoutObject()->NeedsLayout()) {
    DCHECK(false) << "LayoutText needed layout but was not display locked: "
                  << obj;
    return false;
  }

  return true;
}

// TODO(crbug.com/371011661): Use single list marker representation for a11y.
// Accessibility is treating list markers in two different ways:
// 1. As a regular list marker object;
// 2. As a object of type none, thus ignoring the list marker, and adding the
// text as its child. Regardless of the way being used for a particular list
// item, we need to know how to connect the list marker with the next text on
// the line. `layout_object`represents the node being investigated, and `parent`
// may contain the parent of this object, if it is included in the tree.
const LayoutObject* GetListMarker(const LayoutObject& layout_object,
                                  const AXObject* parent) {
  if (layout_object.IsLayoutOutsideListMarker()) {
    // This  is the default case: this LayoutObject represents a list marker.
    return &layout_object;
  }
  if (parent && parent->RoleValue() == ax::mojom::blink::Role::kNone &&
      parent->GetLayoutObject() &&
      parent->GetLayoutObject()->IsLayoutOutsideListMarker()) {
    // The parent of the node being investigated is a list marker, so it will be
    // used in the computation to connect things in the same line.
    return parent->GetLayoutObject();
  }
  return nullptr;
}

}  // namespace

using html_names::kAltAttr;
using html_names::kTitleAttr;
using html_names::kTypeAttr;
using html_names::kValueAttr;
using mojom::blink::FormControlType;

// In ARIA 1.1, default value of aria-level was changed to 2.
const int kDefaultHeadingLevel = 2;

// When an AXNodeObject is created with a Node instead of a LayoutObject it
// means that the LayoutObject is purposely being set to null, as it is not
// relevant for this object in the AX tree.
AXNodeObject::AXNodeObject(Node* node, AXObjectCacheImpl& ax_object_cache)
    : AXObject(ax_object_cache),
      node_(node) {}

AXNodeObject::AXNodeObject(LayoutObject* layout_object,
                           AXObjectCacheImpl& ax_object_cache)
    : AXObject(ax_object_cache),
      node_(layout_object->GetNode()),
      layout_object_(layout_object) {
#if DCHECK_IS_ON()
  layout_object_->SetHasAXObject(true);
#endif
}

AXNodeObject::~AXNodeObject() {
  DCHECK(!node_);
  DCHECK(!layout_object_);
}

void AXNodeObject::AlterSliderOrSpinButtonValue(bool increase) {
  if (!GetNode())
    return;
  if (!IsSlider() && !IsSpinButton())
    return;

  float value;
  if (!ValueForRange(&value))
    return;

  if (!RuntimeEnabledFeatures::
          SynthesizedKeyboardEventsForAccessibilityActionsEnabled()) {
    // If synthesized keyboard events are disabled, we need to set the value
    // directly here.

    // If no step was provided on the element, use a default value.
    float step;
    if (!StepValueForRange(&step)) {
      if (IsNativeSlider() || IsNativeSpinButton()) {
        step = StepRange().Step().ToString().ToFloat();
      } else {
        return;
      }
    }

    value += increase ? step : -step;

    if (native_role_ == ax::mojom::blink::Role::kSlider ||
        native_role_ == ax::mojom::blink::Role::kSpinButton) {
      OnNativeSetValueAction(String::Number(value));
      // Dispatching an event could result in changes to the document, like
      // this AXObject becoming detached.
      if (IsDetached())
        return;

      AXObjectCache().HandleValueChanged(GetNode());
      return;
    }
  }

  // If we have synthesized keyboard events enabled, we generate a keydown
  // event:
  // * For a native slider, the dispatch of the event will reach
  // RangeInputType::HandleKeydownEvent(), where the value will be set and the
  // AXObjectCache notified. The corresponding keydown/up JS events will be
  // fired so the website doesn't know it was produced by an AT action.
  // * For an ARIA slider, the corresponding keydown/up JS events will be
  // fired. It is expected that the handlers for those events manage the
  // update of the slider value.

  AXAction action =
      increase ? AXAction::kActionIncrement : AXAction::kActionDecrement;
  LocalDOMWindow* local_dom_window = GetDocument()->domWindow();
  AccessibilityOrientation orientation = Orientation();
  ax::mojom::blink::WritingDirection text_direction = GetTextDirection();

  // A kKeyDown event is kRawKeyDown + kChar events. We cannot synthesize it
  // because the KeyboardEvent constructor will prevent it, to force us to
  // decide if we must produce both events. In our case, we don't have to
  // produce a kChar event because we are synthesizing arrow key presses, and
  // only keys that output characters are expected to produce kChar events.
  KeyboardEvent* keydown =
      CreateKeyboardEvent(local_dom_window, WebInputEvent::Type::kRawKeyDown,
                          action, orientation, text_direction);
  GetNode()->DispatchEvent(*keydown);

  // The keydown handler may have caused the node to be removed.
  if (!GetNode())
    return;

  KeyboardEvent* keyup =
      CreateKeyboardEvent(local_dom_window, WebInputEvent::Type::kKeyUp, action,
                          orientation, text_direction);

  // Add a 100ms delay between keydown and keyup to make events look less
  // evidently synthesized.
  GetDocument()
      ->GetTaskRunner(TaskType::kUserInteraction)
      ->PostDelayedTask(
          FROM_HERE,
          WTF::BindOnce(
              [](Node* node, KeyboardEvent* evt) {
                if (node) {
                  node->DispatchEvent(*evt);
                }
              },
              WrapWeakPersistent(GetNode()), WrapPersistent(keyup)),
          base::Milliseconds(100));
}

AXObject* AXNodeObject::ActiveDescendant() const {
  Element* element = GetElement();
  if (!element)
    return nullptr;

  if (RoleValue() == ax::mojom::blink::Role::kMenuListPopup) {
    if (HTMLSelectElement* select =
            DynamicTo<HTMLSelectElement>(parent_->GetNode())) {
      // TODO(accessibility): as a simplification, just expose the active
      // descendant of a <select size=1> at all times, like we do for other
      // active descendant situations,
      return select->PopupIsVisible() || select->IsFocusedElementInDocument()
                 ? AXObjectCache().Get(select->OptionToBeShown())
                 : nullptr;
    }
  }

  if (auto* select = DynamicTo<HTMLSelectElement>(GetNode())) {
    if (!select->UsesMenuList()) {
      return AXObjectCache().Get(select->ActiveSelectionEnd());
    }
  }

  const Element* descendant = ElementFromAttributeOrInternals(
      element, html_names::kAriaActivedescendantAttr);
  if (!descendant) {
    return nullptr;
  }
  AXObject* ax_descendant = AXObjectCache().Get(descendant);
  return ax_descendant && ax_descendant->IsVisible() ? ax_descendant : nullptr;
}

bool IsExemptFromInlineBlockCheck(ax::mojom::blink::Role role) {
  return role == ax::mojom::blink::Role::kSvgRoot ||
         role == ax::mojom::blink::Role::kCanvas ||
         role == ax::mojom::blink::Role::kEmbeddedObject;
}

AXObjectInclusion AXNodeObject::ShouldIncludeBasedOnSemantics(
    IgnoredReasons* ignored_reasons) const {
  DCHECK(GetDocument());

  // All nodes must have an unignored parent within their tree under
  // the root node of the web area, so force that node to always be unignored.
  if (IsA<Document>(GetNode())) {
    return kIncludeObject;
  }

  if (IsPresentational()) {
    if (ignored_reasons)
      ignored_reasons->push_back(IgnoredReason(kAXPresentational));
    return kIgnoreObject;
  }

  Node* node = GetNode();
  if (!node) {
    // Nodeless pseudo element images are included, even if they don't have CSS
    // alt text. This can allow auto alt to be applied to them.
    if (IsImage())
      return kIncludeObject;

    return kDefaultBehavior;
  }

  // Avoid double speech. The ruby text describes pronunciation of the ruby
  // base, and generally produces redundant screen reader output. Expose it only
  // as a description on the <ruby> element so that screen reader users can
  // toggle it on/off as with other descriptions/annotations.
  if (RoleValue() == ax::mojom::blink::Role::kRubyAnnotation ||
      (RoleValue() == ax::mojom::blink::Role::kStaticText && ParentObject() &&
       ParentObject()->RoleValue() ==
           ax::mojom::blink::Role::kRubyAnnotation)) {
    return kIgnoreObject;
  }

  Element* element = GetElement();
  if (!element) {
    return kDefaultBehavior;
  }

  if (IsExcludedByFormControlsFilter()) {
    if (ignored_reasons) {
      ignored_reasons->push_back(IgnoredReason(kAXUninteresting));
    }
    return kIgnoreObject;
  }

  if (IsA<SVGElement>(node)) {
    // The symbol element is used to define graphical templates which can be
    // instantiated by a use element but which are not rendered directly. We
    // don't want to include these template objects, or their subtrees, where
    // they appear in the DOM. Any associated semantic information (e.g. the
    // title child of a symbol) may participate in the text alternative
    // computation where it is instantiated by the use element.
    // https://svgwg.org/svg2-draft/struct.html#SymbolElement
    if (Traversal<SVGSymbolElement>::FirstAncestorOrSelf(*node))
      return kIgnoreObject;

    // Include non-empty SVG root as clients may want to treat it as an image.
    if (IsA<SVGSVGElement>(node) && GetLayoutObject() &&
        GetLayoutObject()->IsSVGRoot() && element->firstElementChild()) {
      return kIncludeObject;
    }

    // The SVG-AAM states that user agents MUST provide an accessible object
    // for rendered SVG elements that have at least one direct child title or
    // desc element that is not empty after trimming whitespace. But it also
    // says, "User agents MAY include elements with these child elements without
    // checking for valid text content." So just check for their existence in
    // order to be performant. https://w3c.github.io/svg-aam/#include_elements
    if (ElementTraversal::FirstChild(
            *To<ContainerNode>(node), [](auto& element) {
              return element.HasTagName(svg_names::kTitleTag) ||
                     element.HasTagName(svg_names::kDescTag);
            })) {
      return kIncludeObject;
    }

    // If setting enabled, do not ignore SVG grouping (<g>) elements.
    if (IsA<SVGGElement>(node)) {
      
"""


```