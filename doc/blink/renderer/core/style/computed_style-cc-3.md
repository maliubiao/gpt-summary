Response:
Let's break down the thought process to analyze the provided C++ code snippet and answer the prompt effectively.

**1. Initial Understanding and Goal:**

The first step is to recognize that this is a *fragment* of a larger C++ file within the Chromium/Blink rendering engine. The file is `computed_style.cc`, and the prompt explicitly states this. The goal is to understand the *functions* of the provided code, how it relates to web technologies (HTML, CSS, JavaScript), and to highlight potential issues and usage scenarios. The prompt also emphasizes that this is part 4 of 4, implying a need for a concluding summary.

**2. Function-by-Function Analysis (Decomposition):**

The core of the analysis involves examining each function individually. For each function, ask:

* **What does it do?**  Focus on the logic within the function. Look at the variables, conditions, and return values.
* **What are the inputs and outputs (explicit and implicit)?**  Identify the parameters and the return type. Also, consider what data the function accesses (member variables, other functions).
* **Why would this function exist? What problem does it solve?**  This helps connect the code to the broader purpose of a rendering engine.
* **Are there any interesting edge cases or specific logic that stands out?** For example, the comment about the IE quirk in `ShouldPlaceListMarkerInside()` is a key detail.

**Example of Detailed Function Analysis (Mental Walkthrough):**

Let's take `ShouldPlaceListMarkerInside()` as an example:

* **Line 1:** `if (Display() == EDisplay::kInlineListItem || ListStylePosition() == EListStylePosition::kInside)` -  This is a direct check of CSS properties. If the element is an `inline-list-item` or has `list-style-position: inside`, the marker should be inside. This connects directly to CSS.
* **Line 4:** `if (IsA<HTMLLIElement>(parent) && !IsInsideListElement() && PseudoElementLayoutObjectIsNeeded(kPseudoIdMarker, marker_style, &parent))` - This is more complex.
    * `IsA<HTMLLIElement>(parent)`: Checks if the parent is an `<li>`. This relates to HTML structure.
    * `!IsInsideListElement()`: Checks if the `<li>` isn't nested within an `<ol>` or `<ul>`.
    * `PseudoElementLayoutObjectIsNeeded(...)`: This suggests logic related to how the list marker (a pseudo-element) is rendered.
* **Line 8:** `parent.GetDocument().CountUse(WebFeature::kInsideListMarkerPositionQuirk);` -  This is a crucial clue. It indicates a *quirk* based on old IE behavior. This highlights a historical aspect of browser compatibility.
* **Return values:**  The function returns `true` if the marker should be inside, `false` otherwise.

**3. Identifying Relationships to Web Technologies:**

As each function is analyzed, actively look for connections to HTML, CSS, and JavaScript:

* **HTML:**  Functions dealing with element types (`HTMLLIElement`, `HTMLBodyElement`), parent-child relationships, and document structure.
* **CSS:** Functions checking or resolving CSS properties (`Display`, `ListStylePosition`, `AccentColor`, `ScrollbarThumbColor`, `contain`, `container-type`, `position`, `transform-style`, `will-change`, `overlay`, `field-sizing`, `user-select`, `color-scheme`, etc.). Think about how these properties affect the visual presentation of web pages.
* **JavaScript:** While this code is C++, understand that the *results* of these computations influence how JavaScript interacts with the DOM and CSSOM. For instance, JavaScript can read computed styles. The `TextAutosizer` also hints at potential JavaScript involvement in text rendering.

**4. Identifying Logic and Potential Input/Output Scenarios:**

For functions with conditional logic, consider simple "what if" scenarios:

* **`ShouldPlaceListMarkerInside()`:**
    * **Input:** An `<li>` element directly in the `<body>` (no `<ul>` or `<ol>`).
    * **Output:** `true` (due to the IE quirk).
    * **Input:** An `<li>` element inside a `<ul>`.
    * **Output:**  Depends on the `list-style-position` CSS property.
* **`ShouldApplyAnyContainment()`:** Think about different `display` values and `contain` property values.

**5. Identifying Potential User/Programming Errors:**

Consider how developers might misuse or misunderstand the underlying logic:

* **`ShouldPlaceListMarkerInside()`:**  A developer might be surprised by the behavior of an `<li>` outside of a list and not realize it's due to a historical quirk.
* **`ShouldApplyAnyContainment()`:** Incorrectly assuming `contain: layout` applies to all display types could lead to unexpected layout behavior.
* **`ComputedStyleBuilder`:**  Directly manipulating the internal `ComputedStyleBuilder` without understanding the implications of inheritance and cascading could lead to inconsistencies.

**6. Structuring the Answer:**

Organize the findings logically:

* **Overall Function:** Start with a high-level summary of the file's purpose.
* **Detailed Function Breakdown:** Group functions by related functionality (e.g., list markers, colors, containment, stacking contexts, etc.). For each group, explain the functions and their relevance to web technologies.
* **Logic and Examples:** Provide clear input/output scenarios for key functions to illustrate their behavior.
* **User/Programming Errors:**  Offer concrete examples of potential mistakes.
* **Summary (Part 4):**  Reiterate the core responsibilities of the `ComputedStyle` class and its role in the rendering process.

**7. Refinement and Clarity:**

Review the answer for clarity, accuracy, and completeness. Ensure that the explanations are easy to understand, even for someone who isn't deeply familiar with the Blink rendering engine. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just calculates styles."
* **Correction:** Realize that it's not just calculation, but also handling quirks, managing inheritance, and making decisions about rendering behavior based on style properties.
* **Initial thought:**  Focus only on the code's direct actions.
* **Correction:**  Consider the *implications* for web developers and how these C++ functions manifest in the behavior of web pages.

By following this structured approach, the analysis becomes more thorough and the answer addresses all aspects of the prompt effectively.
```
这是目录为blink/renderer/core/style/computed_style.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

基于提供的代码片段，我们可以推断出 `ComputedStyle::cc` 文件（的这部分）的主要功能是**计算和确定元素的最终样式属性值**，这些值会影响元素的渲染方式。它涵盖了各种影响元素外观和行为的关键样式属性。

**功能列举 (基于提供的代码片段):**

1. **决定列表标记的位置 (`ShouldPlaceListMarkerInside`)**:
   - 判断列表项的标记是否应该显示在列表项内容内部 (`list-style-position: inside`)。
   - 处理特殊情况，例如没有父级 `<ol>` 或 `<ul>` 的 `<li>` 元素，基于历史原因强制将其标记放在内部（这是一个需要注意的 quirk）。

2. **解析和解决颜色值 (`AccentColorResolved`, `ScrollbarThumbColorResolved`, `ScrollbarTrackColorResolved`)**:
   - 处理 `accent-color` 和滚动条相关颜色属性。
   - 能够解析 `auto` 关键字，并根据当前的颜色方案 (light/dark mode) 和当前颜色进行解析。

3. **判断是否应用 Containment (`ShouldApplyAnyContainment`)**:
   - 确定是否应该应用 CSS Containment 属性 (`contain`) 来进行性能优化。
   - 根据元素的 display 类型和指定的 containment 值进行判断。

4. **判断元素是否可以作为 Size Container Queries 的容器 (`CanMatchSizeContainerQueries`)**:
   - 检查元素是否设置了 `container-type: size` 或 `container: size`。
   - 排除非根 SVG 元素。

5. **判断元素是否是 Interleaving Root (`IsInterleavingRoot`)**:
   - 确定元素是否是某些高级布局特性（如 Size Container Queries, `position-try` 回退, Anchor Positioning）的根。

6. **判断滚动条是否被自定义样式隐藏 (`ScrollbarIsHiddenByCustomStyle`)**:
   - 检查是否通过伪元素 `::-webkit-scrollbar` 的 `display: none` 隐藏了滚动条。

7. **计算元素是否创建堆叠上下文 (z-index) 但不依赖 Containment (`CalculateIsStackingContextWithoutContainment`)**:
   - 确定元素是否由于某些 CSS 属性（如 `transform-style: preserve-3d`, `transform`, `position: fixed`, `position: sticky`, `will-change`, 特定动画等）而创建了新的堆叠上下文。

8. **判断元素是否渲染在顶层 (`IsRenderedInTopLayer`)**:
   - 检查元素是否在顶层 (`<dialog>`, `<popup>`) 且 `overlay: auto` 或使用了 `::backdrop` 伪元素。

9. **应用控件的固定尺寸 (`ApplyControlFixedSize`)**:
   - 确定是否应该对表单控件应用固定的尺寸，可能与 `field-sizing: fixed` 或自动填充状态有关。

10. **构建和修改 ComputedStyle 对象 (`ComputedStyleBuilder`)**:
    - 提供了构建 `ComputedStyle` 对象的机制，可以基于初始样式和父级样式进行构建。
    - 允许修改各种样式属性，例如背景图、缩放、字体方向、文本自动缩放倍数、颜色方案等。
    - 处理样式的继承和变量。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS**: 该文件直接处理和解释 CSS 属性。
    - **例子**: `ShouldPlaceListMarkerInside()` 检查 `display` 和 `list-style-position` CSS 属性。
    - **例子**: `AccentColorResolved()` 解析 `accent-color` CSS 属性。
    - **例子**: `ShouldApplyAnyContainment()` 检查 `contain` CSS 属性。

* **HTML**:  该文件需要知道元素的 HTML 结构和类型。
    - **例子**: `ShouldPlaceListMarkerInside()` 检查父元素是否是 `HTMLLIElement`，并判断元素是否在列表内部。
    - **例子**: `ShouldApplyAnyContainment()` 检查元素是否是 `HTMLBodyElement` 或 `HTMLHtmlElement`。

* **JavaScript**: 虽然这段代码本身是 C++，但它计算出的 `ComputedStyle` 对象会被 JavaScript 使用。
    - **例子**: JavaScript 可以通过 `window.getComputedStyle(element)` 获取元素的最终样式，而 `ComputedStyle::cc` (及其相关部分) 就是计算这些样式的地方。
    - **例子**: JavaScript 可以设置或修改 CSS 属性，这些修改最终会影响到 `ComputedStyle` 的计算结果。
    - **例子**: `TextAutosizingMultiplier` 的设置可能与 JavaScript 控制的文本大小调整功能有关。

**逻辑推理的假设输入与输出:**

**场景 1: `ShouldPlaceListMarkerInside`**

* **假设输入**: 一个 `<li>` 元素，其父元素是 `<div>`，没有设置 `list-style-position` 属性。
* **输出**: `true` (因为 `!IsInsideListElement()` 为真，并且满足了 IE quirk 的条件)。

* **假设输入**: 一个 `<li>` 元素，其父元素是 `<ul>`。
* **输出**: `false` (除非设置了 `list-style-position: inside`)。

**场景 2: `ShouldApplyAnyContainment`**

* **假设输入**: 一个 `<div>` 元素，`display: block`, `contain: layout`。
* **输出**: `true` (`effective_containment & kContainsLayout` 为真，且 `display` 不是表格类型)。

* **假设输入**: 一个 `<table>` 元素，`display: table`, `contain: layout`。
* **输出**: `false` (因为 `IsDisplayTableType(display)` 为真，且 `display` 不是 `EDisplay::kTableBox` 或 `EDisplay::kTableCell` 或 `EDisplay::kTableCaption`)。

**用户或编程常见的使用错误举例:**

1. **误解 IE Quirk**: 开发者可能没有意识到，在没有父级列表的 `<li>` 元素中，列表标记会默认放在内部，这可能导致意外的布局。
   ```html
   <div><li>Item outside list</li></div>
   ```
   开发者可能期望标记在外部，但由于 quirk，它会在内部。

2. **过度依赖 Containment**: 开发者可能在所有元素上都应用了 `contain: layout`，而没有考虑到表格元素的特殊性，导致布局问题或性能下降。

3. **不理解堆叠上下文的创建**: 开发者可能意外地创建了新的堆叠上下文，导致 z-index 属性的行为不符合预期。例如，对一个元素应用了 `transform: translateZ(0)` 但没有意识到它会创建一个新的堆叠上下文。

4. **错误地假设 `auto` 颜色值的解析**: 开发者可能认为 `accent-color: auto` 会继承父元素的颜色，但实际上它会根据浏览器或操作系统的主题来决定。

**归纳 `ComputedStyle::cc` (本部分) 的功能:**

这部分 `ComputedStyle::cc` 的核心功能是**最终确定和计算影响元素视觉呈现和行为的各种 CSS 属性值**。它涉及到：

* **根据 CSS 规则、继承关系和浏览器默认样式进行计算。**
* **处理特定 CSS 属性的逻辑和特殊情况 (例如，IE quirk)。**
* **决定元素是否参与某些高级布局特性 (如 Containment, Container Queries, 堆叠上下文)。**
* **提供构建和修改 `ComputedStyle` 对象的机制。**

总而言之，`ComputedStyle::cc` 是 Blink 渲染引擎中至关重要的一个组成部分，它连接了 CSS 样式规则和最终的渲染结果，确保网页能够按照预期的方式呈现给用户。 这部分代码片段展现了其处理多种关键样式属性，并考虑了历史兼容性和性能优化的复杂性。

### 提示词
```
这是目录为blink/renderer/core/style/computed_style.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
e.
  if (Display() == EDisplay::kInlineListItem ||
      ListStylePosition() == EListStylePosition::kInside) {
    return true;
  }
  // Force the marker of <li> elements with no <ol> or <ul> ancestor to have
  // an inside position.
  // TODO(crbug.com/41241289): This quirk predates WebKit, it was added to match
  // the behavior of the Internet Explorer from that time. However, Microsoft
  // ended up removing it (before switching to Blink), and Firefox never had it,
  // so it may be possible to get rid of it.
  if (IsA<HTMLLIElement>(parent) && !IsInsideListElement() &&
      PseudoElementLayoutObjectIsNeeded(kPseudoIdMarker, marker_style,
                                        &parent)) {
    parent.GetDocument().CountUse(WebFeature::kInsideListMarkerPositionQuirk);
    return true;
  }
  return false;
}

std::optional<blink::Color> ComputedStyle::AccentColorResolved() const {
  const StyleAutoColor& auto_color = AccentColor();
  if (auto_color.IsAutoColor()) {
    return std::nullopt;
  }
  return auto_color.Resolve(GetCurrentColor(), UsedColorScheme());
}

std::optional<blink::Color> ComputedStyle::ScrollbarThumbColorResolved() const {
  if (const StyleScrollbarColor* scrollbar_color = UsedScrollbarColor()) {
    return scrollbar_color->GetThumbColor().Resolve(GetCurrentColor(),
                                                    UsedColorScheme());
  }
  return std::nullopt;
}

std::optional<blink::Color> ComputedStyle::ScrollbarTrackColorResolved() const {
  if (const StyleScrollbarColor* scrollbar_color = UsedScrollbarColor()) {
    return scrollbar_color->GetTrackColor().Resolve(GetCurrentColor(),
                                                    UsedColorScheme());
  }
  return std::nullopt;
}

bool ComputedStyle::ShouldApplyAnyContainment(const Element& element,
                                              const DisplayStyle& display_style,
                                              unsigned effective_containment) {
  DCHECK(IsA<HTMLBodyElement>(element) || IsA<HTMLHtmlElement>(element))
      << "Since elements can override the computed display for which box type "
         "to create, this method is not generally correct. Use "
         "LayoutObject::ShouldApplyAnyContainment if possible.";
  if (effective_containment & kContainsStyle) {
    return true;
  }
  if (!element.LayoutObjectIsNeeded(display_style)) {
    return false;
  }
  EDisplay display = display_style.Display();
  if (display == EDisplay::kInline) {
    return false;
  }
  if ((effective_containment & kContainsSize) &&
      (!IsDisplayTableType(display) || display == EDisplay::kTableCaption ||
       ShouldUseContentDataForElement(display_style.GetContentData()))) {
    return true;
  }
  return (effective_containment & (kContainsLayout | kContainsPaint)) &&
         (!IsDisplayTableType(display) || IsDisplayTableBox(display) ||
          display == EDisplay::kTableCell ||
          display == EDisplay::kTableCaption);
}

bool ComputedStyle::CanMatchSizeContainerQueries(const Element& element) const {
  return IsContainerForSizeContainerQueries() &&
         (!element.IsSVGElement() ||
          To<SVGElement>(element).IsOutermostSVGSVGElement());
}

bool ComputedStyle::IsInterleavingRoot(const ComputedStyle* style) {
  const ComputedStyle* unensured = ComputedStyle::NullifyEnsured(style);
  return unensured && (unensured->IsContainerForSizeContainerQueries() ||
                       unensured->GetPositionTryFallbacks() ||
                       unensured->HasAnchorFunctions());
}

bool ComputedStyle::ScrollbarIsHiddenByCustomStyle(Element* element) const {
  // It is necessary to check the cached styles because native input
  // controls are styled this way.
  const ComputedStyle* cached_scrollbar_style =
      GetCachedPseudoElementStyle(kPseudoIdScrollbar);
  if (cached_scrollbar_style &&
      cached_scrollbar_style->Display() == EDisplay::kNone) {
    return true;
  }

  if (!element) {
    return false;
  }

  const ComputedStyle* uncached_scrollbar_style =
      element->UncachedStyleForPseudoElement(
          StyleRequest(kPseudoIdScrollbar, StyleRequest::kForComputedStyle));
  return uncached_scrollbar_style &&
         uncached_scrollbar_style->Display() == EDisplay::kNone;
}

bool ComputedStyle::CalculateIsStackingContextWithoutContainment() const {
  // Force a stacking context for transform-style: preserve-3d. This happens
  // even if preserves-3d is ignored due to a 'grouping property' being
  // present which requires flattening. See:
  // ComputedStyle::HasGroupingPropertyForUsedTransformStyle3D().
  // This is legacy behavior that is left ambiguous in the official specs.
  // See https://crbug.com/663650 for more details.
  if (TransformStyle3D() == ETransformStyle3D::kPreserve3d) {
    return true;
  }
  if (ForcesStackingContext()) {
    return true;
  }
  if (StyleType() == kPseudoIdBackdrop) {
    return true;
  }
  if (HasTransformRelatedProperty()) {
    return true;
  }
  if (HasStackingGroupingProperty(BoxReflect())) {
    return true;
  }
  if (GetPosition() == EPosition::kFixed) {
    return true;
  }
  if (GetPosition() == EPosition::kSticky) {
    return true;
  }
  if (HasPropertyThatCreatesStackingContext(WillChangeProperties())) {
    return true;
  }
  if (ShouldCompositeForCurrentAnimations()) {
    // TODO(882625): This becomes unnecessary when will-change correctly takes
    // into account active animations.
    return true;
  }
  return false;
}

bool ComputedStyle::IsRenderedInTopLayer(const Element& element) const {
  return (element.IsInTopLayer() && Overlay() == EOverlay::kAuto) ||
         StyleType() == kPseudoIdBackdrop;
}

bool ComputedStyle::ApplyControlFixedSize(const Node* node) const {
  if (FieldSizing() == EFieldSizing::kFixed) {
    return true;
  }
  if (!node) {
    return false;
  }
  const auto* control = DynamicTo<HTMLFormControlElement>(node);
  if (!control) {
    control = DynamicTo<HTMLFormControlElement>(node->OwnerShadowHost());
  }
  return control && control->GetAutofillState() != WebAutofillState::kNotFilled;
}

ComputedStyleBuilder::ComputedStyleBuilder(const ComputedStyle& style)
    : ComputedStyleBuilderBase(style) {}

ComputedStyleBuilder::ComputedStyleBuilder(
    const ComputedStyle& initial_style,
    const ComputedStyle& parent_style,
    IsAtShadowBoundary is_at_shadow_boundary)
    : ComputedStyleBuilderBase(initial_style, parent_style) {
  // Even if surrounding content is user-editable, shadow DOM should act as a
  // single unit, and not necessarily be editable
  if (is_at_shadow_boundary == kAtShadowBoundary) {
    SetUserModify(initial_style.UserModify());
  }

  // TODO(crbug.com/1410068): Once `user-select` isn't inherited, we should
  // get rid of following if-statement.
  if (parent_style.UserSelect() == EUserSelect::kContain) {
    SetUserSelect(EUserSelect::kAuto);  // FIXME(sesse): Is this right?
  }

  // TODO(sesse): Why do we do this?
  SetBaseTextDecorationData(parent_style.AppliedTextDecorationData());
}

const ComputedStyle* ComputedStyleBuilder::TakeStyle() {
  return MakeGarbageCollected<ComputedStyle>(ComputedStyle::BuilderPassKey(),
                                             *this);
}

const ComputedStyle* ComputedStyleBuilder::CloneStyle() const {
  ResetAccess();
  has_own_inherited_variables_ = false;
  has_own_non_inherited_variables_ = false;
  return MakeGarbageCollected<ComputedStyle>(ComputedStyle::BuilderPassKey(),
                                             *this);
}

void ComputedStyleBuilder::PropagateIndependentInheritedProperties(
    const ComputedStyle& parent_style) {
  ComputedStyleBuilderBase::PropagateIndependentInheritedProperties(
      parent_style);
  if (!HasVariableReference() && !HasVariableDeclaration() &&
      (InheritedVariablesInternal().Get() !=
       parent_style.InheritedVariables())) {
    has_own_inherited_variables_ = false;
    MutableInheritedVariablesInternal() =
        parent_style.InheritedVariablesInternal();
  }
}

void ComputedStyleBuilder::ClearBackgroundImage() {
  FillLayer* curr_child = &AccessBackgroundLayers();
  curr_child->SetImage(
      FillLayer::InitialFillImage(EFillLayerType::kBackground));
  for (curr_child = curr_child->Next(); curr_child;
       curr_child = curr_child->Next()) {
    curr_child->ClearImage();
  }
}

bool ComputedStyleBuilder::SetEffectiveZoom(float f) {
  // Clamp the effective zoom value to a smaller (but hopeful still large
  // enough) range, to avoid overflow in derived computations.
  float clamped_effective_zoom = ClampTo<float>(f, 1e-6, 1e6);
  if (EffectiveZoom() == clamped_effective_zoom) {
    return false;
  }
  SetEffectiveZoomInternal(clamped_effective_zoom);
  // Record UMA for the effective zoom in order to assess the relative
  // importance of sub-pixel behavior, and related features and bugs.
  // Clamp to a max of 400%, to make the histogram behave better at no
  // real cost to our understanding of the zooms in use.
  base::UmaHistogramSparse(
      "Blink.EffectiveZoom",
      std::clamp<float>(clamped_effective_zoom * 100, 0, 400));
  return true;
}

// Compute the FontOrientation from this style. It's derived from WritingMode
// and TextOrientation.
FontOrientation ComputedStyleBuilder::ComputeFontOrientation() const {
  // https://drafts.csswg.org/css-writing-modes/#propdef-text-orientation
  // > the property has no effect in horizontal typographic modes.
  if (IsHorizontalTypographicMode(GetWritingMode())) {
    return FontOrientation::kHorizontal;
  }
  switch (GetTextOrientation()) {
    case ETextOrientation::kMixed:
      return FontOrientation::kVerticalMixed;
    case ETextOrientation::kUpright:
      return FontOrientation::kVerticalUpright;
    case ETextOrientation::kSideways:
      return FontOrientation::kVerticalRotated;
    default:
      NOTREACHED();
  }
}

// Update FontOrientation in FontDescription if it is different. FontBuilder
// takes care of updating it, but if WritingMode or TextOrientation were
// changed after the style was constructed, this function synchronizes
// FontOrientation to match to this style.
void ComputedStyleBuilder::UpdateFontOrientation() {
  FontOrientation orientation = ComputeFontOrientation();
  if (GetFontDescription().Orientation() == orientation) {
    return;
  }
  FontDescription font_description = GetFontDescription();
  font_description.SetOrientation(orientation);
  SetFontDescription(font_description);
}

void ComputedStyleBuilder::SetTextAutosizingMultiplier(float multiplier) {
  if (TextAutosizingMultiplier() == multiplier) {
    return;
  }

  SetTextAutosizingMultiplierInternal(multiplier);

  float size = GetFontDescription().SpecifiedSize();

  DCHECK(std::isfinite(size));
  if (!std::isfinite(size) || size < 0) {
    size = 0;
  } else {
    size = std::min(kMaximumAllowedFontSize, size);
  }

  FontDescription desc(GetFontDescription());
  desc.SetSpecifiedSize(size);

  float computed_size = size * EffectiveZoom();

  float autosized_font_size = TextAutosizer::ComputeAutosizedFontSize(
      computed_size, multiplier, EffectiveZoom());
  desc.SetComputedSize(std::min(kMaximumAllowedFontSize, autosized_font_size));

  SetFontDescription(desc);
}

void ComputedStyleBuilder::SetUsedColorScheme(
    ColorSchemeFlags flags,
    mojom::blink::PreferredColorScheme preferred_color_scheme,
    bool force_dark) {
  bool prefers_dark =
      preferred_color_scheme == mojom::blink::PreferredColorScheme::kDark;
  bool has_dark = flags & static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark);
  bool has_light =
      flags & static_cast<ColorSchemeFlags>(ColorSchemeFlag::kLight);
  bool has_only = flags & static_cast<ColorSchemeFlags>(ColorSchemeFlag::kOnly);
  bool dark_scheme =
      // Dark scheme because the preferred scheme is dark and color-scheme
      // contains dark.
      (has_dark && prefers_dark) ||
      // Dark scheme because the the only recognized color-scheme is dark.
      (has_dark && !has_light) ||
      // Dark scheme because we have a dark color-scheme override for forced
      // darkening and no 'only' which opts out.
      (force_dark && !has_only) ||
      // Typically, forced darkening should be used with a dark preferred
      // color-scheme. This is to support the FORCE_DARK_ONLY behavior from
      // WebView where this combination is passed to the renderer.
      (force_dark && !prefers_dark);

  SetDarkColorScheme(dark_scheme);

  bool forced_scheme =
      // No dark in the color-scheme property, but we still forced it to dark.
      (!has_dark && dark_scheme) ||
      // Always use forced color-scheme for preferred light color-scheme with
      // forced darkening. The combination of preferred color-scheme of light
      // with a color-scheme property value of "light dark" chooses the light
      // color-scheme. Typically, forced darkening should be used with a dark
      // preferred color-scheme. This is to support the FORCE_DARK_ONLY
      // behavior from WebView where this combination is passed to the
      // renderer.
      (force_dark && !prefers_dark);

  SetColorSchemeForced(forced_scheme);

  const bool is_normal =
      flags == static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal);
  SetColorSchemeFlagsIsNormal(is_normal);
}

CSSVariableData* ComputedStyleBuilder::GetVariableData(
    const AtomicString& name,
    bool is_inherited_property) const {
  return blink::GetVariableData(*this, name, is_inherited_property);
}

StyleInheritedVariables& ComputedStyleBuilder::MutableInheritedVariables() {
  Member<StyleInheritedVariables>& variables =
      MutableInheritedVariablesInternal();
  if (!has_own_inherited_variables_) {
    variables = variables
                    ? MakeGarbageCollected<StyleInheritedVariables>(*variables)
                    : MakeGarbageCollected<StyleInheritedVariables>();
  }
  has_own_inherited_variables_ = true;
  DCHECK(variables);
  return *variables;
}

StyleNonInheritedVariables&
ComputedStyleBuilder::MutableNonInheritedVariables() {
  Member<StyleNonInheritedVariables>& variables =
      MutableNonInheritedVariablesInternal();
  if (!has_own_non_inherited_variables_) {
    variables =
        variables ? MakeGarbageCollected<StyleNonInheritedVariables>(*variables)
                  : MakeGarbageCollected<StyleNonInheritedVariables>();
  }
  has_own_non_inherited_variables_ = true;
  DCHECK(variables);
  return *variables;
}

void ComputedStyleBuilder::CopyInheritedVariablesFrom(
    const ComputedStyle* style) {
  if (style->InheritedVariablesInternal()) {
    has_own_inherited_variables_ = false;
    MutableInheritedVariablesInternal() = style->InheritedVariablesInternal();
  }
}

void ComputedStyleBuilder::CopyNonInheritedVariablesFrom(
    const ComputedStyle* style) {
  if (style->NonInheritedVariablesInternal()) {
    has_own_non_inherited_variables_ = false;
    MutableNonInheritedVariablesInternal() =
        style->NonInheritedVariablesInternal();
  }
}

STATIC_ASSERT_ENUM(cc::OverscrollBehavior::Type::kAuto,
                   EOverscrollBehavior::kAuto);
STATIC_ASSERT_ENUM(cc::OverscrollBehavior::Type::kContain,
                   EOverscrollBehavior::kContain);
STATIC_ASSERT_ENUM(cc::OverscrollBehavior::Type::kNone,
                   EOverscrollBehavior::kNone);

}  // namespace blink
```