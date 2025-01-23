Response:
The user wants a summary of the functionality of the provided C++ code snippet, specifically focusing on:

1. **General Functionality:** What does this code do?
2. **Relation to Web Technologies:** How does it interact with JavaScript, HTML, and CSS?
3. **Logical Inference:** Are there any implicit logic flows or data transformations?
4. **Potential User Errors:** What mistakes might a developer make when using this functionality?

The code snippet is the beginning of the `InspectorCSSAgent` class in the Chromium Blink rendering engine. Based on the includes and the method names, it seems responsible for providing CSS-related information and manipulation capabilities to the browser's developer tools.

Here's a breakdown of the functionalities evident in the provided code:

* **Inspector Integration:** The class name and included headers (`inspector_dom_agent.h`, `inspector_network_agent.h`, `protocol/css.h`) strongly suggest its role in the DevTools inspector.
* **CSS Object Representation:**  The code uses various CSS classes like `CSSStyleSheet`, `CSSRule`, `CSSStyleRule`, `CSSMediaRule`, etc., indicating it's involved in representing and managing CSS structures.
* **Style Editing:**  Methods like `SetStyleSheetText`, `SetRuleSelector`, `SetStyleText`, `AddRule`, and the `InspectorCSSAgent::StyleSheetAction` subclasses clearly point towards the ability to modify CSS styles.
* **Computed Style Retrieval:** The inclusion of `CSSComputedStyleDeclaration` suggests the capability to fetch the final computed styles of elements.
* **Font Information:** The presence of `CSSFontFace`, `Font`, and related headers indicates functionality for inspecting and managing fonts.
* **Pseudo-Class Handling:** The `ComputePseudoClassMask` function and the `ForcePseudoClassFlags` enum suggest support for simulating different pseudo-class states for inspection.
* **Resource Loading:** The interaction with `InspectorResourceContentLoader` suggests it handles loading and processing CSS resources.
* **Event Handling:** The `DOMListener` interface implies it reacts to DOM changes to keep CSS information up-to-date.

**Plan for Summarization:**

1. **High-level Functionality:** State that it's a DevTools agent for CSS inspection and manipulation.
2. **CSS Relationship:** Explain how it represents and allows modification of CSS rules, stylesheets, and computed styles. Provide examples.
3. **HTML Relationship:** Describe how it connects CSS to HTML elements.
4. **JavaScript Relationship:** Mention how the DevTools protocol (implied by `protocol/css.h`) allows JavaScript in the DevTools frontend to interact with this agent.
5. **Logical Inference (Example):** Pick a simple action like changing a style and describe the likely input and output.
6. **Common Errors (Example):**  Think about common mistakes when editing CSS in DevTools (e.g., syntax errors).
7. **Concise Summary:**  Wrap up with a brief overview of its core purpose.
这是一个名为 `InspectorCSSAgent` 的 Chromium Blink 引擎源代码文件，它的主要功能是**作为开发者工具（DevTools）的一部分，提供检查和修改网页 CSS 样式的功能。**

更具体地说，从提供的代码片段来看，它可以归纳为以下几个核心功能：

**1. CSS 信息的提供和表示:**

*   **表示 CSS 结构:**  它能够解析和表示网页中的各种 CSS 结构，包括：
    *   样式表 (`CSSStyleSheet`)，无论是外部链接的、`<style>` 标签内的还是元素的 `style` 属性中的。
    *   各种 CSS 规则 (`CSSRule`)，例如：
        *   样式规则 (`CSSStyleRule`)
        *   媒体查询规则 (`CSSMediaRule`)
        *   容器查询规则 (`CSSContainerRule`)
        *   支持规则 (`CSSSupportsRule`)
        *   关键帧规则 (`CSSKeyframesRule`, `CSSKeyframeRule`)
        *   作用域规则 (`CSSScopeRule`)
        *   层叠层规则 (`CSSLayerBlockRule`, `CSSLayerStatementRule`)
        *   导入规则 (`CSSImportRule`)
        *   字体相关规则 (`CSSFontFace`, `CSSFontPaletteValuesRule`)
    *   CSS 声明 (`CSSStyleDeclaration`) 和属性。
*   **提供 CSS 属性值:**  可以获取元素的计算样式 (`CSSComputedStyleDeclaration`)。
*   **处理伪元素:**  能够处理和表示伪元素（例如 `::before`, `::after`）。
*   **字体信息:**  能够处理和提供字体相关的信息 (`CSSFontFace`, `Font`)。

**2. CSS 样式的修改和编辑:**

*   **修改样式表文本:**  允许修改整个样式表的文本内容 (`SetStyleSheetTextAction`)。
*   **修改规则选择器:** 允许修改 CSS 规则的选择器 (`ModifyRuleAction` - `kSetRuleSelector`)。
*   **修改规则内的样式声明:** 允许修改 CSS 规则内的具体样式声明 (`ModifyRuleAction` - `kSetStyleText`)。
*   **修改媒体查询文本:** 允许修改媒体查询规则的文本 (`ModifyRuleAction` - `kSetMediaRuleText`)。
*   **修改容器查询文本:** 允许修改容器查询规则的文本 (`ModifyRuleAction` - `kSetContainerRuleText`)。
*   **修改支持规则文本:** 允许修改支持规则的文本 (`ModifyRuleAction` - `kSetSupportsRuleText`)。
*   **修改关键帧的关键帧值:** 允许修改关键帧规则的关键帧值 (`ModifyRuleAction` - `kSetKeyframeKey`)。
*   **修改属性名:** 允许修改样式声明中的属性名 (`ModifyRuleAction` - `kSetPropertyName`)。
*   **修改作用域规则文本:** 允许修改作用域规则的文本 (`ModifyRuleAction` - `kSetScopeRuleText`)。
*   **修改行内样式:** 允许修改元素的行内 `style` 属性 (`SetElementStyleAction`)。
*   **添加新的 CSS 规则:** 允许向样式表中添加新的 CSS 规则 (`AddRuleAction`)。
*   **历史记录支持:**  通过 `InspectorHistory` 来管理 CSS 修改操作，支持撤销和重做。

**3. 与 JavaScript, HTML, CSS 的关系举例说明:**

*   **CSS:** `InspectorCSSAgent` 的核心功能就是处理 CSS。例如，通过 DevTools 可以修改一个元素的 `color` 属性，这会调用 `InspectorCSSAgent` 相应的方法来更新底层的 CSSOM (CSS Object Model)。
*   **HTML:** `InspectorCSSAgent` 通过 `InspectorDOMAgent` 获取 HTML 元素的信息，并将 CSS 规则与 HTML 元素关联起来。例如，当你在 DevTools 中查看一个元素的“Computed”样式时，`InspectorCSSAgent` 会根据该元素及其应用的 CSS 规则计算出最终的样式。
*   **JavaScript:** 虽然这段代码本身是 C++，但它通过 DevTools 协议与前端的 JavaScript 代码进行通信。DevTools 前端使用 JavaScript 调用协议中定义的方法，比如 `CSS.getComputedStyleForNode`，来请求 `InspectorCSSAgent` 提供信息。例如，在 DevTools 的 "Elements" 面板中，当你点击一个元素并查看其样式时，前端 JavaScript 代码会调用 `CSS` 相关的协议方法，`InspectorCSSAgent` 负责处理这些请求并返回结果。

**4. 逻辑推理（假设输入与输出）：**

**假设输入:**  用户在 DevTools 中选中一个 `<div>` 元素，并尝试将该元素的 `color` 属性从 `black` 修改为 `red`。

**输出:**

1. `InspectorCSSAgent` 接收到来自 DevTools 前端的请求，包含要修改的节点 ID 和新的 CSS 属性值 (`color: red`)。
2. `InspectorCSSAgent` 找到该元素应用的 CSS 规则。
3. 如果该规则中已经存在 `color` 属性，则更新其值。
4. 如果该规则中不存在 `color` 属性，则添加该属性。
5. `InspectorCSSAgent` 将修改后的 CSSOM 反馈给渲染引擎，触发页面重新渲染。
6. `InspectorCSSAgent` 将修改操作记录到历史记录中，以便用户可以撤销或重做。
7. `InspectorCSSAgent` 通过 DevTools 协议将修改结果发送回 DevTools 前端，更新用户界面。

**5. 涉及用户或者编程常见的使用错误举例说明:**

*   **在 DevTools 中输入无效的 CSS 语法:**  例如，输入 `color: ;` 或 `background-color: #ggghhh;`。`InspectorCSSAgent` 会尝试解析这些输入，如果解析失败，可能会报错或者无法应用修改。
*   **尝试修改只读的样式表:** 某些样式表（例如浏览器默认样式表）可能不允许修改。`InspectorCSSAgent` 可能会阻止这些修改。
*   **并发修改样式:**  虽然不太常见，但在复杂的场景下，如果 JavaScript 代码也在动态修改样式，用户在 DevTools 中的修改可能会与 JavaScript 的修改产生冲突，导致意想不到的结果。
*   **错误地定位要修改的规则或属性:** 用户可能在 DevTools 中选择了错误的 CSS 规则或属性进行修改，导致修改没有达到预期效果。

**总结一下它的功能（第1部分）：**

`InspectorCSSAgent` 是 Chromium Blink 引擎中负责为开发者工具提供 CSS 检查和编辑功能的核心组件。它能够表示和操作网页中的各种 CSS 结构，包括样式表、规则和属性。它允许用户通过 DevTools 修改 CSS 样式，并与 HTML 元素关联起来。该组件还支持操作历史记录，以便用户可以撤销和重做 CSS 修改操作。它通过 DevTools 协议与前端 JavaScript 代码通信，实现开发者工具的交互。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_css_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "third_party/blink/renderer/core/inspector/inspector_css_agent.h"

#include <utility>

#include "base/auto_reset.h"
#include "third_party/blink/public/common/metrics/document_update_reason.h"
#include "third_party/blink/renderer/core/animation/css/css_animation_data.h"
#include "third_party/blink/renderer/core/css/cascade_layer.h"
#include "third_party/blink/renderer/core/css/cascade_layer_map.h"
#include "third_party/blink/renderer/core/css/check_pseudo_has_cache_scope.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_container_rule.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/css_font_face.h"
#include "third_party/blink/renderer/core/css/css_font_face_source.h"
#include "third_party/blink/renderer/core/css/css_font_palette_values_rule.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_gradient_value.h"
#include "third_party/blink/renderer/core/css/css_import_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframe_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframes_rule.h"
#include "third_party/blink/renderer/core/css/css_layer_block_rule.h"
#include "third_party/blink/renderer/core/css/css_layer_statement_rule.h"
#include "third_party/blink/renderer/core/css/css_media_rule.h"
#include "third_party/blink/renderer/core/css/css_property_name.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_rule.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_rule.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_scope_rule.h"
#include "third_party/blink/renderer/core/css/css_starting_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_supports_rule.h"
#include "third_party/blink/renderer/core/css/css_variable_data.h"
#include "third_party/blink/renderer/core/css/font_face.h"
#include "third_party/blink/renderer/core/css/font_size_functions.h"
#include "third_party/blink/renderer/core/css/media_list.h"
#include "third_party/blink/renderer/core/css/media_query.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/out_of_flow_data.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_rule_usage_tracker.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_rule_font_palette_values.h"
#include "third_party/blink/renderer/core/css/style_sheet.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/css/style_sheet_list.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/dom/tree_scope.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_contrast.h"
#include "third_party/blink/renderer/core/inspector/inspector_ghost_rules.h"
#include "third_party/blink/renderer/core/inspector/inspector_history.h"
#include "third_party/blink/renderer/core/inspector/inspector_network_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_container.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_content_loader.h"
#include "third_party/blink/renderer/core/inspector/inspector_style_resolver.h"
#include "third_party/blink/renderer/core/inspector/protocol/css.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/style_generated_image.h"
#include "third_party/blink/renderer/core/style/style_image.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_custom_platform_data.h"
#include "third_party/blink/renderer/platform/fonts/shaping/caching_word_shaper.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/text/text_run.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/string_concatenate.h"

namespace blink {

namespace {

int g_frontend_operation_counter = 0;

class FrontendOperationScope {
  STACK_ALLOCATED();

 public:
  FrontendOperationScope() { ++g_frontend_operation_counter; }
  ~FrontendOperationScope() { --g_frontend_operation_counter; }
};

Element* GetPseudoIdAndTag(Element* element,
                           PseudoId& element_pseudo_id,
                           AtomicString& view_transition_name) {
  auto* resolved_element = element;
  if (auto* pseudo_element = DynamicTo<PseudoElement>(element)) {
    resolved_element = IsTransitionPseudoElement(pseudo_element->GetPseudoId())
                           ? pseudo_element->UltimateOriginatingElement()
                           : pseudo_element->ParentOrShadowHostElement();
    // TODO(khushalsagar) : This should never be null.
    if (!resolved_element)
      return nullptr;

    element_pseudo_id = pseudo_element->GetPseudoIdForStyling();
    view_transition_name = pseudo_element->view_transition_name();
  }
  return resolved_element;
}

String CreateShorthandValue(Document& document,
                            const String& shorthand,
                            const String& old_text,
                            const String& longhand,
                            const String& new_value) {
  auto* style_sheet_contents =
      MakeGarbageCollected<StyleSheetContents>(StrictCSSParserContext(
          document.GetExecutionContext()->GetSecureContextMode()));
  String text = " div { " + shorthand + ": " + old_text + "; }";
  CSSParser::ParseSheet(MakeGarbageCollected<CSSParserContext>(document),
                        style_sheet_contents, text);

  auto* style_sheet = MakeGarbageCollected<CSSStyleSheet>(style_sheet_contents);
  auto* rule = To<CSSStyleRule>(style_sheet->ItemInternal(0));
  CSSStyleDeclaration* style = rule->style();
  DummyExceptionStateForTesting exception_state;
  style->setProperty(document.GetExecutionContext(), longhand, new_value,
                     style->getPropertyPriority(longhand), exception_state);
  return style->getPropertyValue(shorthand);
}

HeapVector<Member<CSSStyleRule>> FilterDuplicateRules(
    RuleIndexList* rule_list) {
  HeapVector<Member<CSSStyleRule>> uniq_rules;
  HeapHashSet<Member<CSSRule>> uniq_rules_set;
  for (unsigned i = rule_list ? rule_list->size() : 0; i > 0; --i) {
    CSSRule* rule = rule_list->at(i - 1).first;
    auto* style_rule = DynamicTo<CSSStyleRule>(rule);
    if (!style_rule || uniq_rules_set.Contains(rule))
      continue;
    uniq_rules_set.insert(rule);
    uniq_rules.push_back(style_rule);
  }
  uniq_rules.Reverse();
  return uniq_rules;
}

void CollectPlatformFontsFromRunFontDataList(
    const HeapVector<ShapeResult::RunFontData>& run_font_data_list,
    HashMap<std::pair<int, String>, std::pair<int, String>>* font_stats) {
  for (const auto& run_font_data : run_font_data_list) {
    const auto* simple_font_data = run_font_data.font_data_.Get();
    String family_name = simple_font_data->PlatformData().FontFamilyName();
    if (family_name.IsNull())
      family_name = "";
    String postscript_name =
        simple_font_data->PlatformData().GetPostScriptName();
    if (postscript_name.IsNull()) {
      postscript_name = "";
    }
    auto font_key = std::make_pair(simple_font_data->IsCustomFont() ? 1 : 0,
                                   postscript_name);
    auto font_stats_it = font_stats->find(font_key);
    if (font_stats_it == font_stats->end()) {
      font_stats->insert(
          font_key, std::make_pair(run_font_data.glyph_count_, family_name));
    } else {
      font_stats_it->value.first += run_font_data.glyph_count_;
    }
  }
}

}  // namespace

typedef blink::protocol::CSS::Backend::EnableCallback EnableCallback;
typedef blink::protocol::CSS::Backend::TakeComputedStyleUpdatesCallback
    TakeComputedStyleUpdatesCallback;

enum ForcePseudoClassFlags {
  kPseudoNone = 0,
  kPseudoHover = 1 << 0,
  kPseudoFocus = 1 << 1,
  kPseudoActive = 1 << 2,
  kPseudoVisited = 1 << 3,
  kPseudoFocusWithin = 1 << 4,
  kPseudoFocusVisible = 1 << 5,
  kPseudoTarget = 1 << 6,
  kPseudoEnabled = 1 << 7,
  kPseudoDisabled = 1 << 8,
  kPseudoValid = 1 << 9,
  kPseudoInvalid = 1 << 10,
  kPseudoUserValid = 1 << 11,
  kPseudoUserInvalid = 1 << 12,
  kPseudoRequired = 1 << 13,
  kPseudoOptional = 1 << 14,
  kPseudoReadOnly = 1 << 15,
  kPseudoReadWrite = 1 << 16,
  kPseudoInRange = 1 << 17,
  kPseudoOutOfRange = 1 << 18,
  kPseudoChecked = 1 << 19,
  kPseudoIndeterminate = 1 << 20,
  kPseudoPlaceholderShown = 1 << 21,
  kPseudoAutofill = 1 << 22,
  kPseudoLink = 1 << 23,
};

static unsigned ComputePseudoClassMask(
    std::unique_ptr<protocol::Array<String>> pseudo_class_array) {
  DEFINE_STATIC_LOCAL(String, active, ("active"));
  DEFINE_STATIC_LOCAL(String, hover, ("hover"));
  DEFINE_STATIC_LOCAL(String, focus, ("focus"));
  DEFINE_STATIC_LOCAL(String, focusVisible, ("focus-visible"));
  DEFINE_STATIC_LOCAL(String, focusWithin, ("focus-within"));
  DEFINE_STATIC_LOCAL(String, target, ("target"));
  // Specific pseudo states
  DEFINE_STATIC_LOCAL(String, enabled, ("enabled"));
  DEFINE_STATIC_LOCAL(String, disabled, ("disabled"));
  DEFINE_STATIC_LOCAL(String, valid, ("valid"));
  DEFINE_STATIC_LOCAL(String, invalid, ("invalid"));
  DEFINE_STATIC_LOCAL(String, userValid, ("user-valid"));
  DEFINE_STATIC_LOCAL(String, userInvalid, ("user-invalid"));
  DEFINE_STATIC_LOCAL(String, required, ("required"));
  DEFINE_STATIC_LOCAL(String, optional, ("optional"));
  DEFINE_STATIC_LOCAL(String, readOnly, ("read-only"));
  DEFINE_STATIC_LOCAL(String, readWrite, ("read-write"));
  DEFINE_STATIC_LOCAL(String, inRange, ("in-range"));
  DEFINE_STATIC_LOCAL(String, outOfRange, ("out-of-range"));
  DEFINE_STATIC_LOCAL(String, visited, ("visited"));
  DEFINE_STATIC_LOCAL(String, checked, ("checked"));
  DEFINE_STATIC_LOCAL(String, indeterminate, ("indeterminate"));
  DEFINE_STATIC_LOCAL(String, placeholderShown, ("placeholder-shown"));
  DEFINE_STATIC_LOCAL(String, autofill, ("autofill"));
  DEFINE_STATIC_LOCAL(String, link, ("link"));

  if (!pseudo_class_array || pseudo_class_array->empty())
    return kPseudoNone;

  unsigned result = kPseudoNone;
  for (const String& pseudo_class : *pseudo_class_array) {
    if (pseudo_class == active) {
      result |= kPseudoActive;
    } else if (pseudo_class == hover) {
      result |= kPseudoHover;
    } else if (pseudo_class == focus) {
      result |= kPseudoFocus;
    } else if (pseudo_class == focusVisible) {
      result |= kPseudoFocusVisible;
    } else if (pseudo_class == focusWithin) {
      result |= kPseudoFocusWithin;
    } else if (pseudo_class == target) {
      result |= kPseudoTarget;
    } else if (pseudo_class == enabled) {
      result |= kPseudoEnabled;
    } else if (pseudo_class == disabled) {
      result |= kPseudoDisabled;
    } else if (pseudo_class == valid) {
      result |= kPseudoValid;
    } else if (pseudo_class == invalid) {
      result |= kPseudoInvalid;
    } else if (pseudo_class == userValid) {
      result |= kPseudoUserValid;
    } else if (pseudo_class == userInvalid) {
      result |= kPseudoUserInvalid;
    } else if (pseudo_class == required) {
      result |= kPseudoRequired;
    } else if (pseudo_class == optional) {
      result |= kPseudoOptional;
    } else if (pseudo_class == readOnly) {
      result |= kPseudoReadOnly;
    } else if (pseudo_class == readWrite) {
      result |= kPseudoReadWrite;
    } else if (pseudo_class == inRange) {
      result |= kPseudoInRange;
    } else if (pseudo_class == outOfRange) {
      result |= kPseudoOutOfRange;
    } else if (pseudo_class == visited) {
      result |= kPseudoVisited;
    } else if (pseudo_class == checked) {
      result |= kPseudoChecked;
    } else if (pseudo_class == indeterminate) {
      result |= kPseudoIndeterminate;
    } else if (pseudo_class == placeholderShown) {
      result |= kPseudoPlaceholderShown;
    } else if (pseudo_class == autofill) {
      result |= kPseudoAutofill;
    } else if (pseudo_class == link) {
      result |= kPseudoLink;
    }
  }
  return result;
}

class InspectorCSSAgent::StyleSheetAction : public InspectorHistory::Action {
 public:
  StyleSheetAction(const String& name) : InspectorHistory::Action(name) {}
  StyleSheetAction(const StyleSheetAction&) = delete;
  StyleSheetAction& operator=(const StyleSheetAction&) = delete;

  virtual std::unique_ptr<protocol::CSS::CSSStyle> TakeSerializedStyle(
      Element* element) {
    return nullptr;
  }
};

class InspectorCSSAgent::SetStyleSheetTextAction final
    : public InspectorCSSAgent::StyleSheetAction {
 public:
  SetStyleSheetTextAction(InspectorStyleSheetBase* style_sheet,
                          const String& text)
      : InspectorCSSAgent::StyleSheetAction("SetStyleSheetText"),
        style_sheet_(style_sheet),
        text_(text) {}
  SetStyleSheetTextAction(const SetStyleSheetTextAction&) = delete;
  SetStyleSheetTextAction& operator=(const SetStyleSheetTextAction&) = delete;

  bool Perform(ExceptionState& exception_state) override {
    if (!style_sheet_->GetText(&old_text_))
      return false;
    return Redo(exception_state);
  }

  bool Undo(ExceptionState& exception_state) override {
    return style_sheet_->SetText(old_text_, exception_state);
  }

  bool Redo(ExceptionState& exception_state) override {
    return style_sheet_->SetText(text_, exception_state);
  }

  String MergeId() override {
    return String::Format("SetStyleSheetText %s",
                          style_sheet_->Id().Utf8().c_str());
  }

  void Merge(Action* action) override {
    DCHECK_EQ(action->MergeId(), MergeId());

    SetStyleSheetTextAction* other =
        static_cast<SetStyleSheetTextAction*>(action);
    text_ = other->text_;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(style_sheet_);
    InspectorCSSAgent::StyleSheetAction::Trace(visitor);
  }

 private:
  Member<InspectorStyleSheetBase> style_sheet_;
  String text_;
  String old_text_;
};

class InspectorCSSAgent::ModifyRuleAction final
    : public InspectorCSSAgent::StyleSheetAction {
 public:
  enum Type {
    kSetRuleSelector,
    kSetStyleText,
    kSetMediaRuleText,
    kSetContainerRuleText,
    kSetSupportsRuleText,
    kSetKeyframeKey,
    kSetPropertyName,
    kSetScopeRuleText,
  };

  ModifyRuleAction(Type type,
                   InspectorStyleSheet* style_sheet,
                   const SourceRange& range,
                   const String& text)
      : InspectorCSSAgent::StyleSheetAction("ModifyRuleAction"),
        style_sheet_(style_sheet),
        type_(type),
        new_text_(text),
        old_range_(range),
        css_rule_(nullptr) {}
  ModifyRuleAction(const ModifyRuleAction&) = delete;
  ModifyRuleAction& operator=(const ModifyRuleAction&) = delete;

  bool Perform(ExceptionState& exception_state) override {
    return Redo(exception_state);
  }

  bool Undo(ExceptionState& exception_state) override {
    switch (type_) {
      case kSetRuleSelector:
        return style_sheet_->SetRuleSelector(new_range_, old_text_, nullptr,
                                             nullptr, exception_state);
      case kSetStyleText:
        return style_sheet_->SetStyleText(new_range_, old_text_, nullptr,
                                          nullptr, exception_state);
      case kSetMediaRuleText:
        return style_sheet_->SetMediaRuleText(new_range_, old_text_, nullptr,
                                              nullptr, exception_state);
      case kSetContainerRuleText:
        return style_sheet_->SetContainerRuleText(
            new_range_, old_text_, nullptr, nullptr, exception_state);
      case kSetSupportsRuleText:
        return style_sheet_->SetSupportsRuleText(new_range_, old_text_, nullptr,
                                                 nullptr, exception_state);
      case kSetKeyframeKey:
        return style_sheet_->SetKeyframeKey(new_range_, old_text_, nullptr,
                                            nullptr, exception_state);
      case kSetPropertyName:
        return style_sheet_->SetPropertyName(new_range_, old_text_, nullptr,
                                             nullptr, exception_state);
      case kSetScopeRuleText:
        return style_sheet_->SetScopeRuleText(new_range_, old_text_, nullptr,
                                              nullptr, exception_state);
      default:
        NOTREACHED();
    }
  }

  bool Redo(ExceptionState& exception_state) override {
    switch (type_) {
      case kSetRuleSelector:
        css_rule_ = style_sheet_->SetRuleSelector(
            old_range_, new_text_, &new_range_, &old_text_, exception_state);
        break;
      case kSetStyleText:
        css_rule_ = style_sheet_->SetStyleText(
            old_range_, new_text_, &new_range_, &old_text_, exception_state);
        break;
      case kSetMediaRuleText:
        css_rule_ = style_sheet_->SetMediaRuleText(
            old_range_, new_text_, &new_range_, &old_text_, exception_state);
        break;
      case kSetContainerRuleText:
        css_rule_ = style_sheet_->SetContainerRuleText(
            old_range_, new_text_, &new_range_, &old_text_, exception_state);
        break;
      case kSetSupportsRuleText:
        css_rule_ = style_sheet_->SetSupportsRuleText(
            old_range_, new_text_, &new_range_, &old_text_, exception_state);
        break;
      case kSetKeyframeKey:
        css_rule_ = style_sheet_->SetKeyframeKey(
            old_range_, new_text_, &new_range_, &old_text_, exception_state);
        break;
      case kSetPropertyName:
        css_rule_ = style_sheet_->SetPropertyName(
            old_range_, new_text_, &new_range_, &old_text_, exception_state);
        break;
      case kSetScopeRuleText:
        css_rule_ = style_sheet_->SetScopeRuleText(
            old_range_, new_text_, &new_range_, &old_text_, exception_state);
        break;
      default:
        NOTREACHED();
    }
    return css_rule_ != nullptr;
  }

  CSSRule* TakeRule() {
    CSSRule* result = css_rule_;
    css_rule_ = nullptr;
    return result;
  }

  std::unique_ptr<protocol::CSS::CSSStyle> TakeSerializedStyle(
      Element* element) override {
    if (type_ != kSetStyleText)
      return nullptr;
    CSSRule* rule = TakeRule();
    if (auto* style_rule = DynamicTo<CSSStyleRule>(rule))
      return style_sheet_->BuildObjectForStyle(style_rule->style(), element);
    if (auto* keyframe_rule = DynamicTo<CSSKeyframeRule>(rule))
      return style_sheet_->BuildObjectForStyle(keyframe_rule->style(), element);
    if (auto* property_rule = DynamicTo<CSSPropertyRule>(rule)) {
      return style_sheet_->BuildObjectForStyle(property_rule->Style(), nullptr);
    }
    if (auto* font_palette_values_rule =
            DynamicTo<CSSFontPaletteValuesRule>(rule)) {
      return style_sheet_->BuildObjectForStyle(
          font_palette_values_rule->Style(), nullptr);
    }
    if (auto* position_try_rule = DynamicTo<CSSPositionTryRule>(rule)) {
      return style_sheet_->BuildObjectForStyle(position_try_rule->style(),
                                               nullptr);
    }
    return nullptr;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(style_sheet_);
    visitor->Trace(css_rule_);
    InspectorCSSAgent::StyleSheetAction::Trace(visitor);
  }

  String MergeId() override {
    return String::Format("ModifyRuleAction:%d %s:%d", type_,
                          style_sheet_->Id().Utf8().c_str(), old_range_.start);
  }

  bool IsNoop() override { return old_text_ == new_text_; }

  void Merge(Action* action) override {
    DCHECK_EQ(action->MergeId(), MergeId());

    ModifyRuleAction* other = static_cast<ModifyRuleAction*>(action);
    new_text_ = other->new_text_;
    new_range_ = other->new_range_;
  }

 private:
  Member<InspectorStyleSheet> style_sheet_;
  Type type_;
  String old_text_;
  String new_text_;
  SourceRange old_range_;
  SourceRange new_range_;
  Member<CSSRule> css_rule_;
};

class InspectorCSSAgent::SetElementStyleAction final
    : public InspectorCSSAgent::StyleSheetAction {
 public:
  SetElementStyleAction(InspectorStyleSheetForInlineStyle* style_sheet,
                        const String& text)
      : InspectorCSSAgent::StyleSheetAction("SetElementStyleAction"),
        style_sheet_(style_sheet),
        text_(text) {}
  SetElementStyleAction(const SetElementStyleAction&) = delete;
  SetElementStyleAction& operator=(const SetElementStyleAction&) = delete;

  bool Perform(ExceptionState& exception_state) override {
    return Redo(exception_state);
  }

  bool Undo(ExceptionState& exception_state) override {
    return style_sheet_->SetText(old_text_, exception_state);
  }

  bool Redo(ExceptionState& exception_state) override {
    if (!style_sheet_->GetText(&old_text_))
      return false;
    return style_sheet_->SetText(text_, exception_state);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(style_sheet_);
    InspectorCSSAgent::StyleSheetAction::Trace(visitor);
  }

  String MergeId() override {
    return String::Format("SetElementStyleAction:%s",
                          style_sheet_->Id().Utf8().c_str());
  }

  std::unique_ptr<protocol::CSS::CSSStyle> TakeSerializedStyle(
      Element* element) override {
    return style_sheet_->BuildObjectForStyle(style_sheet_->InlineStyle(),
                                             element);
  }

  void Merge(Action* action) override {
    DCHECK_EQ(action->MergeId(), MergeId());

    SetElementStyleAction* other = static_cast<SetElementStyleAction*>(action);
    text_ = other->text_;
  }

 private:
  Member<InspectorStyleSheetForInlineStyle> style_sheet_;
  String text_;
  String old_text_;
};

class InspectorCSSAgent::AddRuleAction final
    : public InspectorCSSAgent::StyleSheetAction {
 public:
  AddRuleAction(InspectorStyleSheet* style_sheet,
                const String& rule_text,
                const SourceRange& location)
      : InspectorCSSAgent::StyleSheetAction("AddRule"),
        style_sheet_(style_sheet),
        rule_text_(rule_text),
        location_(location) {}
  AddRuleAction(const AddRuleAction&) = delete;
  AddRuleAction& operator=(const AddRuleAction&) = delete;

  bool Perform(ExceptionState& exception_state) override {
    return Redo(exception_state);
  }

  bool Undo(ExceptionState& exception_state) override {
    CSSStyleSheet::InspectorMutationScope scope(style_sheet_->PageStyleSheet());
    return style_sheet_->DeleteRule(added_range_, exception_state);
  }

  bool Redo(ExceptionState& exception_state) override {
    CSSStyleSheet::InspectorMutationScope scope(style_sheet_->PageStyleSheet());
    css_rule_ = style_sheet_->AddRule(rule_text_, location_, &added_range_,
                                      exception_state);
    if (exception_state.HadException())
      return false;
    return true;
  }

  CSSStyleRule* TakeRule() {
    CSSStyleRule* result = css_rule_;
    css_rule_ = nullptr;
    return result;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(style_sheet_);
    visitor->Trace(css_rule_);
    InspectorCSSAgent::StyleSheetAction::Trace(visitor);
  }

 private:
  Member<InspectorStyleSheet> style_sheet_;
  Member<CSSStyleRule> css_rule_;
  String rule_text_;
  String old_text_;
  SourceRange location_;
  SourceRange added_range_;
};

// static
CSSStyleRule* InspectorCSSAgent::AsCSSStyleRule(CSSRule* rule) {
  return DynamicTo<CSSStyleRule>(rule);
}

// static
CSSMediaRule* InspectorCSSAgent::AsCSSMediaRule(CSSRule* rule) {
  return DynamicTo<CSSMediaRule>(rule);
}

// static
CSSContainerRule* InspectorCSSAgent::AsCSSContainerRule(CSSRule* rule) {
  return DynamicTo<CSSContainerRule>(rule);
}

// static
CSSSupportsRule* InspectorCSSAgent::AsCSSSupportsRule(CSSRule* rule) {
  return DynamicTo<CSSSupportsRule>(rule);
}

// static
CSSScopeRule* InspectorCSSAgent::AsCSSScopeRule(CSSRule* rule) {
  return DynamicTo<CSSScopeRule>(rule);
}

InspectorCSSAgent::InspectorCSSAgent(
    InspectorDOMAgent* dom_agent,
    InspectedFrames* inspected_frames,
    InspectorNetworkAgent* network_agent,
    InspectorResourceContentLoader* resource_content_loader,
    InspectorResourceContainer* resource_container)
    : dom_agent_(dom_agent),
      inspected_frames_(inspected_frames),
      network_agent_(network_agent),
      resource_content_loader_(resource_content_loader),
      resource_container_(resource_container),
      resource_content_loader_client_id_(
          resource_content_loader->CreateClientId()),
      enable_requested_(&agent_state_, /*default_value=*/false),
      enable_completed_(false),
      coverage_enabled_(&agent_state_, /*default_value=*/false),
      local_fonts_enabled_(&agent_state_, /*default_value=*/true) {
  DCHECK(dom_agent);
  DCHECK(network_agent);
}

InspectorCSSAgent::~InspectorCSSAgent() = default;

void InspectorCSSAgent::Restore() {
  if (enable_requested_.Get())
    CompleteEnabled();
  if (coverage_enabled_.Get())
    SetCoverageEnabled(true);
}

void InspectorCSSAgent::FlushPendingProtocolNotifications() {
  if (!invalidated_documents_.size())
    return;
  HeapHashSet<Member<Document>> invalidated_documents;
  invalidated_documents_.swap(invalidated_documents);
  for (Document* document : invalidated_documents)
    UpdateActiveStyleSheets(document);
}

void InspectorCSSAgent::Reset() {
  id_to_inspector_style_sheet_.clear();
  id_to_inspector_style_sheet_for_inline_style_.clear();
  css_style_sheet_to_inspector_style_sheet_.clear();
  document_to_css_style_sheets_.clear();
  invalidated_documents_.clear();
  node_to_inspector_style_sheet_.clear();
  notify_computed_style_updated_node_ids_.clear();
  ResetNonPersistentData();
}

void InspectorCSSAgent::ResetNonPersistentData() {
  ResetPseudoStates();
}

void InspectorCSSAgent::enable(std::unique_ptr<EnableCallback> prp_callback) {
  if (!dom_agent_->Enabled()) {
    prp_callback->sendFailure(protocol::Response::ServerError(
        "DOM agent needs to be enabled first."));
    return;
  }
  enable_requested_.Set(true);
  resource_content_loader_->EnsureResourcesContentLoaded(
      resource_content_loader_client_id_,
      WTF::BindOnce(&InspectorCSSAgent::ResourceContentLoaded,
                    WrapPersistent(this), std::move(prp_callback)));
}

void InspectorCSSAgent::ResourceContentLoaded(
    std::unique_ptr<EnableCallback> callback) {
  if (enable_requested_.Get())  // Could be disabled while fetching resources.
    CompleteEnabled();
  callback->sendSuccess();
}

void InspectorCSSAgent::CompleteEnabled() {
  instrumenting_agents_->AddInspectorCSSAgent(this);
  dom_agent_->AddDOMListener(this);
  HeapVector<Member<Document>> documents = dom_agent_->Documents();
  for (Document* document : documents) {
    UpdateActiveStyleSheets(document);
    TriggerFontsUpdatedForDocument(document);
  }
  enable_completed_ = true;
}

void InspectorCSSAgent::TriggerFontsUpdatedForDocument(Document* document) {
  const HeapLinkedHashSet<Member<FontFace>>& faces =
      document->GetStyleEngine()
          .GetFontSelector()
          ->GetFontFaceCache()
          ->CssConnectedFontFaces();
  for (FontFace* face : faces) {
    CSSFontFace* css_face = face->CssFontFace();
    if (!css_face)
      continue;
    const CSSFontFaceSource* source = css_face->FrontSource();
    if (!source || !source->IsLoaded())
      continue;
    const FontCustomPlatformData* data = source->GetCustomPlaftormData();
    if (!data)
      continue;
    FontsUpdated(face, source->GetURL(), data);
  }
}

protocol::Response InspectorCSSAgent::disable() {
  Reset();
  dom_agent_->RemoveDOMListener(this);
  instrumenting_agents_->RemoveInspectorCSSAgent(this);
  enable_completed_ = false;
  enable_requested_.Set(false);
  resource_content_loader_->Cancel(resource_content_loader_client_id_);
  coverage_enabled_.Set(false);
  local_fonts_enabled_.Set(true);
  SetCoverageEnable
```