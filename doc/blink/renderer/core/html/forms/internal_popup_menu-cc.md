Response:
Let's break down the thought process for analyzing this `InternalPopupMenu.cc` file.

1. **Initial Scan for Key Terms:**  The first thing I do is a quick skim, looking for obvious keywords related to the core functionality. I see terms like "PopupMenu", "HTMLSelectElement", "option", "optgroup", "separator", "style", "CSS", "JavaScript", "document", "popup", "chrome_client", "accessibility". These immediately tell me this code is about rendering a special kind of popup specifically for `<select>` elements and deals with styling and potentially user interaction.

2. **Identify the Core Class:** The name `InternalPopupMenu` is central. I recognize the "Internal" prefix often indicates a private or implementation-specific class within a larger system. The constructor `InternalPopupMenu(ChromeClient*, HTMLSelectElement&)` reinforces its connection to a specific `<select>` element and a browser-level component (`ChromeClient`).

3. **Functionality Deduced from Includes and Class Members:**  Next, I examine the included headers and the class member variables.

    * **Includes:** Headers like `<accessibility/ax_object_cache.h>`, `<css/...>`, `<dom/...>`, `<html/forms/...>`, `<input/event_handler.h>`, `<layout/...>`, `<page/chrome_client.h>`, `<page/page_popup.h>` are strong indicators of the involved functionalities: accessibility, styling, DOM manipulation, form-specific elements, event handling, layout, and interaction with the browser's UI framework for popups.
    * **Members:** `owner_element_`, `popup_`, `chrome_client_`, `needs_update_`, and `taller_options_` directly suggest the class manages the lifecycle and state of a popup associated with a `<select>` element, using the `ChromeClient` for platform interaction.

4. **Analyzing Key Methods:** I then focus on the most important methods, paying attention to their names and parameters:

    * **`WriteDocument(SegmentedBuffer& data)`:** This immediately stands out. The name and the `SegmentedBuffer` strongly suggest this method is responsible for generating the HTML content of the popup. I look for what's being written: HTML boilerplate (`<!DOCTYPE html>`), `<meta>` tags (especially "color-scheme"), `<style>` blocks (including handling of pseudo-elements like `::-webkit-scrollbar-*`), and `<script>` blocks. The presence of `ChooserResourceLoader` suggests external resources are being included. The passing of data related to selected index and anchor rectangle further clarifies the purpose.

    * **`AddOption`, `AddOptGroup`, `AddSeparator`:** These methods are clearly responsible for serializing different types of elements within the `<select>` dropdown into the popup's HTML structure. I note the information being extracted (label, value, title, ARIA attributes, disabled state) and how styling is applied via `AddElementStyle`.

    * **`AddElementStyle`:** This method is crucial for understanding how CSS is applied to the popup's content. It compares the styles of the individual option/optgroup/separator elements with the base style of the `<select>` to only include necessary style overrides, optimizing the output.

    * **`SetValueAndClosePopup`, `SetValue`, `DidClosePopup`, `CancelPopup`, `Show`, `Hide`, `Update`, `DisconnectClient`:** These methods clearly manage the lifecycle and interaction of the popup. They handle setting the selected value back to the `<select>` element, closing the popup, and responding to user actions. The interaction with `chrome_client_` is evident.

    * **`CreateCSSFontSelector`:** This indicates that the popup has its own isolated mechanism for font selection.

5. **Identifying Relationships with Web Technologies:**  As I analyze the methods, the connections to HTML, CSS, and JavaScript become clear:

    * **HTML:** The `WriteDocument` method generates HTML. The methods for adding options, optgroups, and separators directly correspond to HTML elements.
    * **CSS:**  The inclusion of `<style>` blocks, the handling of CSS properties within `AddElementStyle` (e.g., `backgroundColor`, `color`, `fontSize`), and the special handling of pseudo-elements confirm the interaction with CSS.
    * **JavaScript:** The `<script>` block in `WriteDocument` and the passing of `dialogArguments` suggest that JavaScript within the popup handles the interactive behavior. The `ChooserResourceLoader` likely provides JavaScript code.

6. **Logical Inference and Assumptions:**  Based on the code, I can infer certain behaviors and make assumptions:

    * **Input/Output:** If the `<select>` element has multiple `<option>` elements, `WriteDocument` will output an HTML structure representing these options. If an option is disabled, the corresponding HTML will likely have a `disabled` attribute or a specific CSS class.
    * **User Interaction:**  Clicking on an item in the popup (presumably handled by JavaScript in the popup) will trigger `SetValueAndClosePopup`, which then updates the underlying `<select>` element.

7. **Identifying Potential User/Programming Errors:** I look for patterns that could lead to errors:

    * **State Management:** The `needs_update_` flag suggests a potential race condition if the underlying `<select>` element changes while the popup is open.
    * **Style Conflicts:** While the code tries to be efficient with style application, complex CSS on the `<select>` element could potentially lead to unexpected styling in the popup.
    * **Accessibility Issues:** Incorrect ARIA attributes on the `<option>` or `<optgroup>` elements could create accessibility problems.

8. **Structuring the Output:** Finally, I organize my findings into the requested categories: functionality, relationships with web technologies (with examples), logical inferences, and potential errors. I try to provide concrete examples to illustrate the points. I also pay attention to the prompt's requirement to explicitly state assumptions and input/output scenarios.

This iterative process of scanning, identifying key elements, analyzing methods, and connecting the code to web technologies allows for a comprehensive understanding of the `InternalPopupMenu.cc` file's role within the Blink rendering engine.
这个文件 `blink/renderer/core/html/forms/internal_popup_menu.cc` 的主要功能是**实现 HTML `<select>` 元素下拉列表的内部弹出菜单**。它负责创建、管理和更新这个弹出菜单的 UI 和行为。

以下是该文件的详细功能分解，以及与 JavaScript、HTML 和 CSS 的关系，逻辑推理示例和常见错误：

**功能列表:**

1. **创建弹出菜单的 DOM 结构:**  `WriteDocument` 方法负责生成弹出菜单的 HTML 内容。这个内容会被渲染成用户看到的下拉列表。
2. **渲染选项和选项组:**  `AddOption` 和 `AddOptGroup` 方法分别负责将 `<option>` 和 `<optgroup>` 元素的数据转换为弹出菜单中对应的条目。
3. **渲染分隔符:** `AddSeparator` 方法负责渲染 `<hr>` 元素作为弹出菜单中的分隔线。
4. **应用样式:** 该文件会读取 `<select>` 元素及其子元素的计算样式 (ComputedStyle)，并将相关的样式信息应用到弹出菜单的元素上，确保弹出菜单的外观与原始 `<select>` 元素一致。这包括字体、颜色、背景、边框等等。
5. **处理用户交互:**  `SetValueAndClosePopup` 方法处理用户在弹出菜单中选择一个选项后的操作，它会将选择的值设置回原始的 `<select>` 元素并关闭弹出菜单。
6. **更新弹出菜单:** `Update` 方法负责在 `<select>` 元素的状态发生变化时更新弹出菜单的内容，例如添加、删除或修改选项。
7. **管理弹出菜单的生命周期:**  `Show` 方法负责显示弹出菜单，`Hide` 和 `CancelPopup` 负责隐藏或取消弹出菜单，`Dispose` 负责释放资源。
8. **处理辅助功能 (Accessibility):**  该文件涉及到辅助功能，例如设置菜单项的 ARIA 属性，以及将菜单项的边界信息传递给辅助功能树。
9. **处理 RTL (Right-to-Left) 布局:**  该文件会根据 `<select>` 元素的文本方向 (direction) 属性来调整弹出菜单的布局。
10. **使用独立的 CSSFontSelector:**  `CreateCSSFontSelector` 方法创建了一个专门用于弹出菜单的 `CSSFontSelector`，这可能为了隔离字体加载和管理，避免影响主文档的字体。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **功能关系:** 该文件负责渲染与 `<select>`, `<option>`, `<optgroup>`, `<hr>` 这些 HTML 元素对应的 UI。
    * **举例说明:**  当 HTML 中有如下 `<select>` 元素时：
      ```html
      <select id="mySelect">
        <option value="apple">Apple</option>
        <optgroup label="Fruits">
          <option value="banana">Banana</option>
          <option value="orange">Orange</option>
        </optgroup>
        <hr>
        <option value="grape">Grape</option>
      </select>
      ```
      `InternalPopupMenu` 会将这些元素解析并渲染成一个弹出菜单，其中 "Apple"、"Banana"、"Orange" 和 "Grape" 会作为菜单项展示，"Fruits" 作为选项组的标题，而 `<hr>` 会渲染成一条分隔线。

* **CSS:**
    * **功能关系:**  该文件读取并应用 `<select>` 元素及其子元素的 CSS 样式到弹出菜单上，保证视觉一致性。
    * **举例说明:** 如果 `<select>` 元素设置了如下 CSS 样式：
      ```css
      #mySelect {
        font-family: Arial, sans-serif;
        font-size: 16px;
        color: blue;
      }
      #mySelect option {
        background-color: lightgray;
      }
      ```
      那么 `InternalPopupMenu` 生成的弹出菜单中的选项，它们的字体将是 Arial (或 sans-serif)，字号为 16px，文字颜色为蓝色，背景色为浅灰色。`AppendOwnerElementPseudoStyles` 函数还处理了诸如 `::-webkit-scrollbar` 这样的伪元素样式。

* **JavaScript:**
    * **功能关系:**  虽然这个 C++ 文件本身不包含 JavaScript 代码，但它生成的弹出菜单的 HTML 结构中会包含 JavaScript 代码 (`ChooserResourceLoader::GetPickerCommonJS()` 和 `ChooserResourceLoader::GetListPickerJS()`)，用于处理弹出菜单的交互逻辑，例如监听鼠标事件、高亮选中项等。 `window.dialogArguments` 会将一些数据传递给弹出菜单的 JavaScript 代码。
    * **举例说明:**  当用户点击弹出菜单中的一个选项时，弹出菜单的 JavaScript 代码会获取该选项的值，然后通过某种机制（可能是调用 Blink 提供的接口）将这个值传递回 C++ 代码的 `SetValueAndClosePopup` 方法，最终更新原始的 `<select>` 元素。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. 一个包含以下 `<select>` 元素的 HTML 文档被加载：
    ```html
    <select id="citySelect">
      <option value="bj">北京</option>
      <option value="sh" selected>上海</option>
      <option value="gz" disabled>广州</option>
    </select>
    ```
2. 用户点击了该 `<select>` 元素，触发弹出菜单的显示。

**输出 (`WriteDocument` 方法生成的部分 HTML 和 JavaScript 数据):**

```html
<!DOCTYPE html><head><meta charset='UTF-8'><meta name='color-scheme' content='only light'><style>
/* ... (scrollbar 样式等) ... */
</style></head><body><div id=main>Loading...</div><script>
window.dialogArguments = {
selectedIndex: 1, // "上海" 是选中的
baseStyle: {
  /* ... (select 元素的基本样式信息) ... */
},
children: [
  {label: "北京", value: 0, style: {}},
  {label: "上海", value: 1, style: {}},
  {label: "广州", value: 2, disabled: true, style: {}},
],
anchorRectInScreen: {"x":100,"y":100,"width":50,"height":20}, // 假设的屏幕坐标
zoomFactor: 1,
scaleFactor: 1,
isRTL: false,
paddingStart: 2,
};
/* ... (公共 JavaScript 和列表选择器 JavaScript) ... */
</script></body>
```

**逻辑推理:**

*   `selectedIndex: 1` 是因为 "上海" 选项带有 `selected` 属性。
*   `children` 数组包含了每个 `<option>` 元素的标签 (label) 和值 (value)。
*   对于禁用的选项 "广州"，会添加 `disabled: true` 属性。
*   `anchorRectInScreen` 提供了 `<select>` 元素在屏幕上的位置和大小，用于定位弹出菜单。

**用户或编程常见的使用错误举例说明:**

1. **样式冲突导致弹出菜单显示异常:**
    *   **错误示例:**  开发者定义了非常复杂的全局 CSS 样式，这些样式意外地影响了弹出菜单的内部元素，导致布局错乱或者样式显示不正确。
    *   **说明:**  由于弹出菜单是在一个临时的、独立的上下文中渲染的，全局样式可能会产生意想不到的影响。Blink 尝试隔离样式，但复杂情况下仍可能发生冲突。

2. **JavaScript 错误导致弹出菜单行为异常:**
    *   **错误示例:**  开发者编写的 JavaScript 代码尝试直接操作弹出菜单的 DOM 结构，但由于弹出菜单的 DOM 是由 Blink 内部管理的，这种直接操作可能会导致不可预测的结果甚至崩溃。
    *   **说明:**  开发者应该通过 Blink 提供的 API 和事件来与弹出菜单进行交互，而不是直接操作其 DOM。

3. **辅助功能属性缺失或不正确:**
    *   **错误示例:**  虽然 Blink 自动处理一些辅助功能，但如果 `<option>` 或 `<optgroup>` 元素上的 `aria-label` 或 `title` 属性使用不当，可能会影响屏幕阅读器等辅助技术对弹出菜单的理解。
    *   **说明:**  开发者应该遵循 Web 内容可访问性指南 (WCAG) 正确使用 ARIA 属性。

4. **动态修改 `<select>` 元素后未触发更新:**
    *   **错误示例:**  开发者使用 JavaScript 动态地添加或删除 `<option>` 元素，但没有通知 `InternalPopupMenu` 进行更新，导致已经显示的弹出菜单内容与实际 `<select>` 元素不一致。
    *   **说明:**  Blink 会在 `<select>` 元素发生变化时自动尝试更新弹出菜单，但在某些复杂的动态修改场景下可能需要手动触发更新。`UpdateFromElement` 方法可能与此有关。

总而言之，`internal_popup_menu.cc` 是 Chromium Blink 引擎中一个关键的组成部分，它专注于 `<select>` 元素下拉列表的内部实现，涉及到 HTML 结构生成、CSS 样式应用、与 JavaScript 的数据交互以及辅助功能等多个方面。理解这个文件的功能有助于深入了解浏览器如何渲染和管理表单控件。

### 提示词
```
这是目录为blink/renderer/core/html/forms/internal_popup_menu.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/forms/internal_popup_menu.h"

#include "base/containers/span.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/input/web_mouse_event.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_value_id_mappings.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_request.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/forms/chooser_resource_loader.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_hr_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page_popup.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/platform/fonts/font_selector.h"
#include "third_party/blink/renderer/platform/fonts/font_selector_client.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "ui/base/ui_base_features.h"
#include "ui/gfx/geometry/rect.h"

namespace blink {

namespace {

// TODO crbug.com/516675 Add stretch to serialization

const char* FontStyleToString(FontSelectionValue slope) {
  if (slope == kItalicSlopeValue) {
    return "italic";
  }
  return "normal";
}

StringView TextTransformToString(ETextTransform transform) {
  return GetCSSValueNameAs<StringView>(PlatformEnumToCSSValueID(transform));
}

StringView TextAlignToString(ETextAlign align) {
  return GetCSSValueNameAs<StringView>(PlatformEnumToCSSValueID(align));
}

const String SerializeComputedStyleForProperty(const ComputedStyle& style,
                                               CSSPropertyID id) {
  const CSSProperty& property = CSSProperty::Get(id);
  const CSSValue* value = property.CSSValueFromComputedStyle(
      style, nullptr, false, CSSValuePhase::kResolvedValue);
  return String::Format("%s : %s;\n", property.GetPropertyName(),
                        value->CssText().Utf8().c_str());
}

const String SerializeColorScheme(const ComputedStyle& style) {
  // Only serialize known color-scheme values to make sure we do not allow
  // injections via <custom-ident> into the popup.
  StringBuilder buffer;
  bool first_added = false;
  for (const AtomicString& ident : style.ColorScheme()) {
    if (ident == AtomicString("only") || ident == AtomicString("light") ||
        ident == AtomicString("dark")) {
      if (first_added)
        buffer.Append(" ");
      else
        first_added = true;
      buffer.Append(ident);
    }
  }
  if (!first_added)
    return String("normal");
  return buffer.ToString();
}

ScrollbarPart ScrollbarPartFromPseudoId(PseudoId id) {
  switch (id) {
    case kPseudoIdScrollbar:
      return kScrollbarBGPart;
    case kPseudoIdScrollbarThumb:
      return kThumbPart;
    case kPseudoIdScrollbarTrack:
    case kPseudoIdScrollbarTrackPiece:
      return kBackTrackPart;
    default:
      break;
  }
  return kNoPart;
}

const ComputedStyle* StyleForHoveredScrollbarPart(HTMLSelectElement& element,
                                                  const ComputedStyle* style,
                                                  Scrollbar* scrollbar,
                                                  PseudoId target_id) {
  ScrollbarPart part = ScrollbarPartFromPseudoId(target_id);
  if (part == kNoPart)
    return nullptr;
  scrollbar->SetHoveredPart(part);
  const ComputedStyle* part_style = element.UncachedStyleForPseudoElement(
      StyleRequest(target_id, To<CustomScrollbar>(scrollbar), part, style));
  return part_style;
}

}  // anonymous namespace

class PopupMenuCSSFontSelector : public CSSFontSelector,
                                 private FontSelectorClient {
 public:
  PopupMenuCSSFontSelector(Document&, CSSFontSelector*);
  ~PopupMenuCSSFontSelector() override;

  // We don't override willUseFontData() for now because the old PopupListBox
  // only worked with fonts loaded when opening the popup.
  const FontData* GetFontData(const FontDescription&,
                              const FontFamily&) override;

  void Trace(Visitor*) const override;

 private:
  void FontsNeedUpdate(FontSelector*, FontInvalidationReason) override;

  Member<CSSFontSelector> owner_font_selector_;
};

PopupMenuCSSFontSelector::PopupMenuCSSFontSelector(
    Document& document,
    CSSFontSelector* owner_font_selector)
    : CSSFontSelector(document), owner_font_selector_(owner_font_selector) {
  owner_font_selector_->RegisterForInvalidationCallbacks(this);
}

PopupMenuCSSFontSelector::~PopupMenuCSSFontSelector() = default;

const FontData* PopupMenuCSSFontSelector::GetFontData(
    const FontDescription& description,
    const FontFamily& font_family) {
  return owner_font_selector_->GetFontData(description, font_family);
}

void PopupMenuCSSFontSelector::FontsNeedUpdate(FontSelector* font_selector,
                                               FontInvalidationReason reason) {
  DispatchInvalidationCallbacks(reason);
}

void PopupMenuCSSFontSelector::Trace(Visitor* visitor) const {
  visitor->Trace(owner_font_selector_);
  CSSFontSelector::Trace(visitor);
  FontSelectorClient::Trace(visitor);
}

// ----------------------------------------------------------------

class InternalPopupMenu::ItemIterationContext {
  STACK_ALLOCATED();

 public:
  ItemIterationContext(const ComputedStyle& style, SegmentedBuffer& buffer)
      : base_style_(style),
        background_color_(
            style.VisitedDependentColor(GetCSSPropertyBackgroundColor())),
        buffer_(buffer) {}

  void SerializeBaseStyle() {
    DCHECK(!is_in_group_);
    PagePopupClient::AddString("baseStyle: {", buffer_);
    if (!BaseStyle().ColorSchemeForced()) {
      AddProperty("backgroundColor", background_color_.SerializeAsCSSColor(),
                  buffer_);
      AddProperty("color",
                  BaseStyle()
                      .VisitedDependentColor(GetCSSPropertyColor())
                      .SerializeAsCSSColor(),
                  buffer_);
    }
    AddProperty("textTransform",
                TextTransformToString(BaseStyle().TextTransform()), buffer_);
    AddProperty("textAlign", TextAlignToString(BaseStyle().GetTextAlign(false)),
                buffer_);
    AddProperty("fontSize", BaseFont().ComputedPixelSize(), buffer_);
    AddProperty("fontStyle", String(FontStyleToString(BaseFont().Style())),
                buffer_);
    AddProperty("fontVariant",
                BaseFont().VariantCaps() == FontDescription::kSmallCaps
                    ? String("small-caps")
                    : String(),
                buffer_);

    AddProperty(
        "fontFamily",
        ComputedStyleUtils::ValueForFontFamily(BaseFont().Family())->CssText(),
        buffer_);

    PagePopupClient::AddString("},\n", buffer_);
  }

  Color BackgroundColor() const {
    return is_in_group_ ? group_style_->VisitedDependentColor(
                              GetCSSPropertyBackgroundColor())
                        : background_color_;
  }
  // Do not use baseStyle() for background-color, use backgroundColor()
  // instead.
  const ComputedStyle& BaseStyle() {
    return is_in_group_ ? *group_style_ : base_style_;
  }
  const FontDescription& BaseFont() {
    return is_in_group_ ? group_style_->GetFontDescription()
                        : base_style_.GetFontDescription();
  }
  void StartGroupChildren(const ComputedStyle& group_style) {
    DCHECK(!is_in_group_);
    PagePopupClient::AddString("children: [", buffer_);
    is_in_group_ = true;
    group_style_ = &group_style;
  }
  void FinishGroupIfNecessary() {
    if (!is_in_group_)
      return;
    PagePopupClient::AddString("],},\n", buffer_);
    is_in_group_ = false;
    group_style_ = nullptr;
  }

  const ComputedStyle& base_style_;
  Color background_color_;
  const ComputedStyle* group_style_;

  unsigned list_index_ = 0;
  bool is_in_group_ = false;
  SegmentedBuffer& buffer_;
};

// ----------------------------------------------------------------

InternalPopupMenu::InternalPopupMenu(ChromeClient* chrome_client,
                                     HTMLSelectElement& owner_element)
    : chrome_client_(chrome_client),
      owner_element_(owner_element),
      popup_(nullptr),
      needs_update_(false) {}

InternalPopupMenu::~InternalPopupMenu() {
  DCHECK(!popup_);
}

void InternalPopupMenu::Trace(Visitor* visitor) const {
  visitor->Trace(chrome_client_);
  visitor->Trace(owner_element_);
  PopupMenu::Trace(visitor);
}

void InternalPopupMenu::WriteDocument(SegmentedBuffer& data) {
  HTMLSelectElement& owner_element = *owner_element_;
  // When writing the document, we ensure the ComputedStyle of the select
  // element's items (see AddElementStyle). This requires a style-clean tree.
  // See Element::EnsureComputedStyle for further explanation.
  DCHECK(!owner_element.GetDocument().NeedsLayoutTreeUpdate());
  gfx::Rect anchor_rect_in_screen = chrome_client_->LocalRootToScreenDIPs(
      owner_element.VisibleBoundsInLocalRoot(),
      owner_element.GetDocument().View());

  float scale_factor = chrome_client_->WindowToViewportScalar(
      owner_element.GetDocument().GetFrame(), 1.f);
  PagePopupClient::AddString("<!DOCTYPE html><head><meta charset='UTF-8'>",
                             data);

  const ComputedStyle& owner_style = owner_element.ComputedStyleRef();

  // Add the color-scheme of the <select> element to the popup as a color-scheme
  // meta.
  PagePopupClient::AddString("<meta name='color-scheme' content='only ", data);
  PagePopupClient::AddString(owner_style.DarkColorScheme() ? "dark" : "light",
                             data);
  PagePopupClient::AddString("'><style>\n", data);

  LayoutObject* owner_layout = owner_element.GetLayoutObject();

  std::pair<PseudoId, const String> targets[] = {
      {kPseudoIdScrollbar, "select::-webkit-scrollbar"},
      {kPseudoIdScrollbarThumb, "select::-webkit-scrollbar-thumb"},
      {kPseudoIdScrollbarTrack, "select::-webkit-scrollbar-track"},
      {kPseudoIdScrollbarTrackPiece, "select::-webkit-scrollbar-track-piece"},
      {kPseudoIdScrollbarCorner, "select::-webkit-scrollbar-corner"}};

  Scrollbar* temp_scrollbar = nullptr;
  const LayoutBox* box = owner_element.InnerElement().GetLayoutBox();
  if (box && box->GetScrollableArea()) {
    if (ScrollableArea* scrollable = box->GetScrollableArea()) {
      temp_scrollbar = MakeGarbageCollected<CustomScrollbar>(
          scrollable, kVerticalScrollbar, box);
    }
  }
  for (auto target : targets) {
    if (const ComputedStyle* style =
            owner_layout->GetCachedPseudoElementStyle(target.first)) {
      AppendOwnerElementPseudoStyles(target.second, data, *style);
    }
    // For Pseudo-class styles, Style should be calculated via that status.
    if (temp_scrollbar) {
      const ComputedStyle* part_style = StyleForHoveredScrollbarPart(
          owner_element, owner_element.GetComputedStyle(), temp_scrollbar,
          target.first);
      if (part_style) {
        AppendOwnerElementPseudoStyles(target.second + ":hover", data,
                                       *part_style);
      }
    }
  }
  if (temp_scrollbar)
    temp_scrollbar->DisconnectFromScrollableArea();

  data.Append(ChooserResourceLoader::GetPickerCommonStyleSheet());
  data.Append(ChooserResourceLoader::GetListPickerStyleSheet());
  if (taller_options_) {
    int padding = static_cast<int>(roundf(4 * scale_factor));
    int min_height = static_cast<int>(roundf(24 * scale_factor));
    PagePopupClient::AddString(String::Format("option, optgroup {"
                                              "padding-top: %dpx;"
                                              "}\n"
                                              "option {"
                                              "padding-bottom: %dpx;"
                                              "min-block-size: %dpx;"
                                              "display: flex;"
                                              "align-items: center;"
                                              "}\n",
                                              padding, padding, min_height),
                               data);
    // Sets the min target size of <option> to 24x24 CSS pixels to meet
    // Accessibility standards.
    if (RuntimeEnabledFeatures::SelectOptionAccessibilityTargetSizeEnabled()) {
      PagePopupClient::AddString(
          String::Format("option {"
                         "display: block;"
                         "align-content: center;"
                         "min-inline-size: %dpx;"
                         "min-block-size: %dpx;"
                         "box-sizing: border-box;"
                         "}\n",
                         min_height, std::max(24, min_height)),
          data);
    }
  }

  PagePopupClient::AddString(
      "</style></head><body><div id=main>Loading...</div><script>\n"
      "window.dialogArguments = {\n",
      data);
  AddProperty("selectedIndex", owner_element.SelectedListIndex(), data);
  ItemIterationContext context(owner_style, data);
  context.SerializeBaseStyle();
  PagePopupClient::AddString("children: [\n", data);
  const HeapVector<Member<HTMLElement>>& items = owner_element.GetListItems();
  for (; context.list_index_ < items.size(); ++context.list_index_) {
    Element& child = *items[context.list_index_];
    if (!IsA<HTMLOptGroupElement>(child.parentNode()))
      context.FinishGroupIfNecessary();
    if (auto* option = DynamicTo<HTMLOptionElement>(child))
      AddOption(context, *option);
    else if (auto* optgroup = DynamicTo<HTMLOptGroupElement>(child))
      AddOptGroup(context, *optgroup);
    else if (auto* hr = DynamicTo<HTMLHRElement>(child))
      AddSeparator(context, *hr);
  }
  context.FinishGroupIfNecessary();
  PagePopupClient::AddString("],\n", data);

  AddProperty("anchorRectInScreen", anchor_rect_in_screen, data);
  AddProperty("zoomFactor", 1, data);
  AddProperty("scaleFactor", scale_factor, data);
  bool is_rtl = !owner_style.IsLeftToRightDirection();
  AddProperty("isRTL", is_rtl, data);
  AddProperty("paddingStart",
              is_rtl ? owner_element.ClientPaddingRight().ToDouble()
                     : owner_element.ClientPaddingLeft().ToDouble(),
              data);
  PagePopupClient::AddString("};\n", data);
  data.Append(ChooserResourceLoader::GetPickerCommonJS());
  data.Append(ChooserResourceLoader::GetListPickerJS());

  PagePopupClient::AddString("</script></body>\n", data);
}

void InternalPopupMenu::AddElementStyle(ItemIterationContext& context,
                                        HTMLElement& element) {
  const ComputedStyle* style = owner_element_->ItemComputedStyle(element);
  DCHECK(style);
  SegmentedBuffer& data = context.buffer_;
  // TODO(tkent): We generate unnecessary "style: {\n},\n" even if no
  // additional style.
  PagePopupClient::AddString("style: {\n", data);
  if (style->Visibility() == EVisibility::kHidden) {
    AddProperty("visibility", String("hidden"), data);
  }
  if (style->Display() == EDisplay::kNone) {
    AddProperty("display", String("none"), data);
  }
  const ComputedStyle& base_style = context.BaseStyle();
  if (base_style.Direction() != style->Direction()) {
    AddProperty(
        "direction",
        String(style->Direction() == TextDirection::kRtl ? "rtl" : "ltr"),
        data);
  }
  if (IsOverride(style->GetUnicodeBidi()))
    AddProperty("unicodeBidi", String("bidi-override"), data);

  if (!base_style.ColorSchemeForced()) {
    bool color_applied = false;
    Color foreground_color =
        style->VisitedDependentColor(GetCSSPropertyColor());
    if (base_style.VisitedDependentColor(GetCSSPropertyColor()) !=
        foreground_color) {
      AddProperty("color", foreground_color.SerializeAsCSSColor(), data);
      color_applied = true;
    }
    Color background_color =
        style->VisitedDependentColor(GetCSSPropertyBackgroundColor());
    if (background_color != Color::kTransparent &&
        (context.BackgroundColor() != background_color)) {
      AddProperty("backgroundColor", background_color.SerializeAsCSSColor(),
                  data);
      color_applied = true;
    }
    if (color_applied)
      AddProperty("colorScheme", SerializeColorScheme(*style), data);
  }

  const FontDescription& base_font = context.BaseFont();
  const FontDescription& font_description =
      style->GetFont().GetFontDescription();
  if (base_font.ComputedPixelSize() != font_description.ComputedPixelSize()) {
    // We don't use FontDescription::specifiedSize() because this element
    // might have its own zoom level.
    AddProperty("fontSize", font_description.ComputedPixelSize(), data);
  }
  // Our UA stylesheet has font-weight:normal for OPTION.
  if (kNormalWeightValue != font_description.Weight()) {
    AddProperty("fontWeight", font_description.Weight().ToString(), data);
  }
  if (base_font.Family() != font_description.Family()) {
    AddProperty(
        "fontFamily",
        ComputedStyleUtils::ValueForFontFamily(font_description.Family())
            ->CssText(),
        data);
  }
  if (base_font.Style() != font_description.Style()) {
    AddProperty("fontStyle",
                String(FontStyleToString(font_description.Style())), data);
  }

  if (base_font.VariantCaps() != font_description.VariantCaps() &&
      font_description.VariantCaps() == FontDescription::kSmallCaps)
    AddProperty("fontVariant", String("small-caps"), data);

  if (base_style.TextTransform() != style->TextTransform()) {
    AddProperty("textTransform", TextTransformToString(style->TextTransform()),
                data);
  }
  if (base_style.GetTextAlign(false) != style->GetTextAlign(false)) {
    AddProperty("textAlign", TextAlignToString(style->GetTextAlign(false)),
                data);
  }

  PagePopupClient::AddString("},\n", data);
}

void InternalPopupMenu::AddOption(ItemIterationContext& context,
                                  HTMLOptionElement& element) {
  SegmentedBuffer& data = context.buffer_;
  PagePopupClient::AddString("{", data);
  AddProperty("label", element.DisplayLabel(), data);
  AddProperty("value", context.list_index_, data);
  if (!element.title().empty())
    AddProperty("title", element.title(), data);
  const AtomicString& aria_label =
      element.FastGetAttribute(html_names::kAriaLabelAttr);
  if (!aria_label.empty())
    AddProperty("ariaLabel", aria_label, data);
  if (element.IsDisabledFormControl())
    AddProperty("disabled", true, data);
  AddElementStyle(context, element);
  PagePopupClient::AddString("},", data);
}

void InternalPopupMenu::AddOptGroup(ItemIterationContext& context,
                                    HTMLOptGroupElement& element) {
  SegmentedBuffer& data = context.buffer_;
  PagePopupClient::AddString("{\n", data);
  PagePopupClient::AddString("type: \"optgroup\",\n", data);
  AddProperty("label", element.GroupLabelText(), data);
  AddProperty("title", element.title(), data);
  AddProperty("ariaLabel", element.FastGetAttribute(html_names::kAriaLabelAttr),
              data);
  AddProperty("disabled", element.IsDisabledFormControl(), data);
  AddElementStyle(context, element);
  context.StartGroupChildren(*owner_element_->ItemComputedStyle(element));
  // We should call ItemIterationContext::finishGroupIfNecessary() later.
}

void InternalPopupMenu::AddSeparator(ItemIterationContext& context,
                                     HTMLHRElement& element) {
  SegmentedBuffer& data = context.buffer_;
  PagePopupClient::AddString("{\n", data);
  PagePopupClient::AddString("type: \"separator\",\n", data);
  AddProperty("title", element.title(), data);
  AddProperty("ariaLabel", element.FastGetAttribute(html_names::kAriaLabelAttr),
              data);
  AddProperty("disabled", element.IsDisabledFormControl(), data);
  AddElementStyle(context, element);
  PagePopupClient::AddString("},\n", data);
}

void InternalPopupMenu::AppendOwnerElementPseudoStyles(
    const String& target,
    SegmentedBuffer& data,
    const ComputedStyle& style) {
  PagePopupClient::AddString(target + "{ \n", data);

  const CSSPropertyID serialize_targets[] = {
      CSSPropertyID::kDisplay,        CSSPropertyID::kBackgroundColor,
      CSSPropertyID::kWidth,          CSSPropertyID::kBorderBottom,
      CSSPropertyID::kBorderLeft,     CSSPropertyID::kBorderRight,
      CSSPropertyID::kBorderTop,      CSSPropertyID::kBorderRadius,
      CSSPropertyID::kBackgroundClip, CSSPropertyID::kBoxShadow};

  for (CSSPropertyID id : serialize_targets) {
    PagePopupClient::AddString(SerializeComputedStyleForProperty(style, id),
                               data);
  }

  PagePopupClient::AddString("}\n", data);
}

CSSFontSelector* InternalPopupMenu::CreateCSSFontSelector(
    Document& popup_document) {
  Document& owner_document = OwnerElement().GetDocument();
  return MakeGarbageCollected<PopupMenuCSSFontSelector>(
      popup_document, owner_document.GetStyleEngine().GetFontSelector());
}

void InternalPopupMenu::SetValueAndClosePopup(int num_value,
                                              const String& string_value) {
  DCHECK(popup_);
  DCHECK(owner_element_);
  if (!string_value.empty()) {
    bool success;
    int list_index = string_value.ToInt(&success);
    DCHECK(success);

    EventQueueScope scope;
    owner_element_->SelectOptionByPopup(list_index);
    if (popup_)
      chrome_client_->ClosePagePopup(popup_);
    // 'change' event is dispatched here.  For compatbility with
    // Angular 1.2, we need to dispatch a change event before
    // mouseup/click events.
  } else {
    if (popup_)
      chrome_client_->ClosePagePopup(popup_);
  }
  // We dispatch events on the owner element to match the legacy behavior.
  // Other browsers dispatch click events before and after showing the popup.
  if (owner_element_) {
    WebMouseEvent event;
    event.SetFrameScale(1);
    PhysicalRect bounding_box = owner_element_->BoundingBox();
    event.SetPositionInWidget(bounding_box.X(), bounding_box.Y());
    event.SetTimeStamp(base::TimeTicks::Now());
    Element* owner = &OwnerElement();
    if (LocalFrame* frame = owner->GetDocument().GetFrame()) {
      frame->GetEventHandler().HandleTargetedMouseEvent(
          owner, event, event_type_names::kMouseup, Vector<WebMouseEvent>(),
          Vector<WebMouseEvent>());
      frame->GetEventHandler().HandleTargetedMouseEvent(
          owner, event, event_type_names::kClick, Vector<WebMouseEvent>(),
          Vector<WebMouseEvent>());
    }
  }
}

void InternalPopupMenu::SetValue(const String& value) {
  DCHECK(owner_element_);
  bool success;
  int list_index = value.ToInt(&success);
  DCHECK(success);
  owner_element_->ProvisionalSelectionChanged(list_index);
}

void InternalPopupMenu::DidClosePopup() {
  // Clearing popup_ first to prevent from trying to close the popup again.
  popup_ = nullptr;
  if (owner_element_)
    owner_element_->PopupDidHide();
}

Element& InternalPopupMenu::OwnerElement() {
  return *owner_element_;
}

ChromeClient& InternalPopupMenu::GetChromeClient() {
  return *chrome_client_;
}

Locale& InternalPopupMenu::GetLocale() {
  return Locale::DefaultLocale();
}

void InternalPopupMenu::CancelPopup() {
  if (popup_)
    chrome_client_->ClosePagePopup(popup_);
  if (owner_element_)
    owner_element_->PopupDidCancel();
}

void InternalPopupMenu::Dispose() {
  if (popup_)
    chrome_client_->ClosePagePopup(popup_);
}

void InternalPopupMenu::Show(PopupMenu::ShowEventType type) {
  DCHECK(!popup_);
  taller_options_ =
      type == PopupMenu::kTouch ||
      RuntimeEnabledFeatures::ForceTallerSelectPopupEnabled() ||
      RuntimeEnabledFeatures::SelectOptionAccessibilityTargetSizeEnabled();
  popup_ = chrome_client_->OpenPagePopup(this);
}

void InternalPopupMenu::Hide() {
  CancelPopup();
}

void InternalPopupMenu::UpdateFromElement(UpdateReason) {
  needs_update_ = true;
}

AXObject* InternalPopupMenu::PopupRootAXObject() const {
  return popup_ ? popup_->RootAXObject(owner_element_) : nullptr;
}

void InternalPopupMenu::Update(bool force_update) {
  if (!popup_ || !owner_element_ || (!needs_update_ && !force_update))
    return;
  // disconnectClient() might have been called.
  if (!owner_element_)
    return;
  needs_update_ = false;

  if (!gfx::Rect(gfx::Point(), OwnerElement().GetDocument().View()->Size())
           .Intersects(OwnerElement().PixelSnappedBoundingBox())) {
    Hide();
    return;
  }

  SegmentedBuffer data;
  PagePopupClient::AddString("window.updateData = {\n", data);
  PagePopupClient::AddString("type: \"update\",\n", data);
  ItemIterationContext context(*owner_element_->GetComputedStyle(), data);
  context.SerializeBaseStyle();
  PagePopupClient::AddString("children: [", data);
  const HeapVector<Member<HTMLElement>>& items = owner_element_->GetListItems();
  for (; context.list_index_ < items.size(); ++context.list_index_) {
    Element& child = *items[context.list_index_];
    if (!IsA<HTMLOptGroupElement>(child.parentNode()))
      context.FinishGroupIfNecessary();
    if (auto* option = DynamicTo<HTMLOptionElement>(child))
      AddOption(context, *option);
    else if (auto* optgroup = DynamicTo<HTMLOptGroupElement>(child))
      AddOptGroup(context, *optgroup);
    else if (auto* hr = DynamicTo<HTMLHRElement>(child))
      AddSeparator(context, *hr);
  }
  context.FinishGroupIfNecessary();
  PagePopupClient::AddString("],\n", data);
  gfx::Rect anchor_rect_in_screen = chrome_client_->LocalRootToScreenDIPs(
      owner_element_->VisibleBoundsInLocalRoot(),
      OwnerElement().GetDocument().View());
  AddProperty("anchorRectInScreen", anchor_rect_in_screen, data);
  PagePopupClient::AddString("}\n", data);
  Vector<char> flatten_data = std::move(data).CopyAs<Vector<char>>();
  popup_->PostMessageToPopup(
      String::FromUTF8(base::as_string_view(flatten_data)));
}

void InternalPopupMenu::DisconnectClient() {
  owner_element_ = nullptr;
  // Cannot be done during finalization, so instead done when the
  // layout object is destroyed and disconnected.
  Dispose();
}

void InternalPopupMenu::SetMenuListOptionsBoundsInAXTree(
    WTF::Vector<gfx::Rect>& options_bounds,
    gfx::Point popup_origin) {
  WebFrameWidgetImpl* widget =
      WebLocalFrameImpl::FromFrame(owner_element_->GetDocument().GetFrame())
          ->LocalRootFrameWidget();
  if (!widget) {
    return;
  }

  // Convert popup origin point from screen coordinates to blink coordinates.
  gfx::Rect widget_view_rect = widget->ViewRect();
  popup_origin.Offset(-widget_view_rect.x(), -widget_view_rect.y());
  popup_origin = widget->DIPsToRoundedBlinkSpace(popup_origin);

  // Factor in the scroll offset of the select's window.
  LocalDOMWindow* window = owner_element_->GetDocument().domWindow();
  const float page_zoom_factor =
      owner_element_->GetDocument().GetFrame()->LayoutZoomFactor();
  popup_origin.Offset(window->scrollX() * page_zoom_factor,
                      window->scrollY() * page_zoom_factor);

  // We need to make sure we take into account any iframes. Since OOPIF and
  // srcdoc iframes aren't allowed to access the root viewport, we need to
  // iterate through the frame owner's parent nodes and accumulate the offsets.
  Frame* frame = owner_element_->GetDocument().GetFrame();
  while (frame->Owner()) {
    if (auto* frame_view = frame->View()) {
        gfx::Point frame_point = frame_view->Location();
        popup_origin.Offset(-frame_point.x(), -frame_point.y());
    }
    frame = frame->Parent();
  }

  for (auto& option_bounds : options_bounds) {
    option_bounds.Offset(popup_origin.x(), popup_origin.y());
  }

  AXObjectCache* cache = owner_element_->GetDocument().ExistingAXObjectCache();
  if (cache) {
    cache->SetMenuListOptionsBounds(owner_element_, options_bounds);
  }
}

}  // namespace blink
```