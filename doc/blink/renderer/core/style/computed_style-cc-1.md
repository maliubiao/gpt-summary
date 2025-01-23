Response:
The user wants a summary of the functionality of the provided C++ code snippet from `computed_style.cc`. This code appears to be part of a function that determines the differences between two `ComputedStyle` objects and sets flags on a `StyleDifference` object based on these differences. These flags indicate what needs to be recomputed or repainted when the style of an element changes.

Here's a breakdown of the code's logic:

1. **Initial Checks:** The code first checks for differences that necessitate a full layout and paint invalidation.
2. **Full Layout:**  It then checks for differences requiring a full layout but not necessarily immediate paint invalidation.
3. **Positioned Movement Layout:** Checks if out-of-flow or in-flow elements with inset changes need a positioned movement layout.
4. **Normal Paint Invalidation:** Checks for differences that require a normal paint invalidation.
5. **Specific Property Changes:**  A large block of `if` statements checks for changes in specific CSS properties (e.g., `background-color`, `border-radius`, `opacity`, `transform`, `visibility`, `z-index`). For each property, it sets corresponding flags on the `diff` object. Some of these checks involve comparing the current and old values of the property.
6. **Dependencies:**  It handles cases where changes in one property affect others (e.g., color changes affecting filters).
7. **Last Checks:** Checks for scroll anchor disabling property changes based on scroll anchor or transform changes.
8. **Omitted Checks:**  Explicitly mentions that cursors and animations are not checked here.

Therefore, the core function of this code is to efficiently determine the necessary updates to the rendering pipeline when an element's computed style changes. It avoids unnecessary re-rendering by precisely identifying the aspects that are affected by the style change.
这个代码片段是 `ComputedStyle` 类中一个名为 `VisualInvalidationDiff` 的成员函数的一部分。  它的主要功能是**计算两个 `ComputedStyle` 对象之间的视觉差异，并根据这些差异设置 `StyleDifference` 对象中的标志，以指示需要进行的渲染更新**。

具体来说，这段代码做了以下事情：

1. **检查并设置需要完全布局和普通绘制失效的差异:**
   - 如果之前的检查已经确定需要完全布局 (`!diff.NeedsFullLayout()`) 或者不需要普通绘制失效 (`!diff.NeedsNormalPaintInvalidation()`)，并且 `DiffNeedsFullLayoutAndPaintInvalidation` 函数返回 `true`，那么就设置 `diff` 对象需要完全布局和普通绘制失效的标志。
   -  `DiffNeedsFullLayoutAndPaintInvalidation` 函数内部会针对表格的 `border-collapse: collapse` 属性以及 `border-style: hidden` 和 `none` 之间的差异进行判断，因为这些差异可能导致尺寸变化。

2. **检查并设置需要完全布局的差异:**
   - 如果尚未标记为需要完全布局 (`!diff.NeedsFullLayout()`)，并且 `DiffNeedsFullLayout` 函数返回 `true`，则设置 `diff` 对象需要完全布局的标志。
   - `DiffNeedsFullLayout` 函数会检查 `layout` 属性、`border-width` 属性、非静态定位元素的 `margin` 属性、`stroke` 相关属性以及与自定义布局相关的属性变化。

3. **检查并设置需要定位移动布局的差异:**
   - 如果不需要完全布局 (`!diff.NeedsLayout()`)：
     - 检查 `field_diff` 中是否包含 `kOutOfFlow` 标志，并且当前元素是否是脱离文档流定位的 (`HasOutOfFlowPosition()`)，如果是，则设置需要定位移动布局的标志。
     - 检查 `field_diff` 中是否包含 `kInset` 标志，并且当前元素是否是在文档流中定位的 (`HasInFlowPosition()`)，如果是，则设置需要定位移动布局的标志。

4. **检查并设置需要普通绘制失效的差异:**
   - 如果不需要普通绘制失效 (`!diff.NeedsNormalPaintInvalidation()`)，并且 `DiffNeedsNormalPaintInvalidation` 函数返回 `true`，则设置 `diff` 对象需要普通绘制失效的标志。
   - `DiffNeedsNormalPaintInvalidation` 函数会检查 `paint` 属性、`accent-color`、`outline`、`background`、依赖于 `currentColor` 的背景属性、`border-visual`、`border-outline-visited-color` 以及与 `paint()` 函数图像相关的属性变化。

5. **检查并设置需要重新计算视觉溢出的差异:**
   - 如果 `DiffNeedsRecomputeVisualOverflow` 函数返回 `true`，则设置 `diff` 对象需要重新计算视觉溢出的标志。
   - `DiffNeedsRecomputeVisualOverflow` 函数会检查 `visual-overflow`、`border-image`、`outline` 以及 `text-decoration` 的视觉溢出相关变化。

6. **检查并设置合成原因改变的差异:**
   - 如果 `DiffCompositingReasonsChanged` 函数返回 `true`，则设置 `diff` 对象合成原因改变的标志。
   - `DiffCompositingReasonsChanged` 函数会检查 `compositing` 属性、`transform-style: preserve-3d`、`contain: paint`、溢出可见性以及与 3D 变换相关的潜在合成原因变化。

7. **检查并设置特定 CSS 属性改变的差异:**
   - 针对各种具体的 CSS 属性（如 `background-color`、`blend-mode`、`border-radius`、`clip`、`clip-path`、`color`、`filter`、`transform`、`mask`、`opacity`、`scrollbar-color`、`scrollbar-style`、`text-decoration`、`visibility`、`z-index` 等），如果 `field_diff` 中包含对应的标志，则设置 `diff` 对象中相应的属性已改变的标志。
   - 对于某些属性，还会进行更细致的比较，例如 `clip` 属性会比较是否同时设置了 `HasOutOfFlowPosition()` 和 `!HasAutoClip()` 以及裁剪区域是否相同。`scrollbar-style` 会检查是否拥有滚动条伪元素以及是否使用标准滚动条样式。`visibility` 会检查是否从 `collapse` 变为非 `collapse` 或反之。

8. **处理 `currentColor` 依赖:**
   - 如果检测到文本装饰或颜色发生变化 (`diff.TextDecorationOrColorChanged()`)，并且存在依赖于 `currentColor` 的滤镜 (`HasFilter() && Filter().UsesCurrentColor()`) 或背景滤镜 (`HasBackdropFilter() && BackdropFilter().UsesCurrentColor()`)，则会相应地设置滤镜改变或合成原因改变的标志。

9. **处理滚动锚点禁用属性的改变:**
   - 如果 `field_diff` 中包含 `kScrollAnchor` 标志，或者发生了变换 (`diff.TransformChanged()`)，则设置滚动锚点禁用属性已改变的标志。

10. **忽略 `cursor` 和动画:**
    - 注释说明 `cursor` 属性的变化会在鼠标事件中处理，不需要触发布局或绘制失效。动画的变化也会在新样式应用到 `LayoutObject` 时处理。

**与 JavaScript, HTML, CSS 的关系：**

- **CSS:** 这段代码的核心是处理 CSS 属性的变化。它根据 CSS 属性的改变来决定如何更新页面的渲染。例如：
    - 当 CSS 的 `background-color` 属性改变时 (`field_diff & kBackgroundColor`)，会设置 `BackgroundColorChanged` 标志，通知渲染引擎需要重新绘制背景。
    - 当 CSS 的 `transform` 属性改变时 (`field_diff & kTransformData` 或相关标志)，会设置 `TransformDataChanged` 或 `OtherTransformPropertyChanged` 等标志，可能触发合成层的更新或重新绘制。
    - 当 CSS 的 `visibility: collapse` 属性发生变化时 (`field_diff & kVisibility`)，会设置 `NeedsFullLayout` 标志，因为它会影响元素的布局空间。

- **HTML:** HTML 结构定义了元素的层级关系，而 CSS 属性的应用会受到 HTML 结构的影响。`ComputedStyle` 对象是基于 HTML 元素的样式计算结果。这段代码中，例如 `HasOutOfFlowPosition()` 和 `HasInFlowPosition()` 就是根据元素的定位方式（受到 HTML 结构和 CSS 的 `position` 属性影响）来判断的。

- **JavaScript:** JavaScript 可以动态修改元素的 CSS 样式。当 JavaScript 修改样式后，Blink 引擎会重新计算元素的 `ComputedStyle`，然后调用类似 `VisualInvalidationDiff` 这样的函数来判断需要进行的渲染更新。

**假设输入与输出 (逻辑推理):**

**假设输入 1:**

- `old_style`:  `background-color: red; width: 100px;`
- `new_style`:  `background-color: blue; width: 100px;`

**输出 1:**

- `field_diff` 中会包含 `kBackgroundColor` 标志。
- `diff.NeedsFullLayout()` 为 `false` (因为宽度没有变化)。
- `diff.NeedsNormalPaintInvalidation()` 为 `true` (因为背景颜色变化需要重新绘制)。
- `diff.SetBackgroundColorChanged()` 会被调用。

**假设输入 2:**

- `old_style`: `position: static; width: 100px;`
- `new_style`: `position: absolute; width: 100px;`

**输出 2:**

- `field_diff` 中会包含与 `position` 相关的标志 (可能是 `kLayout`)。
- `diff.NeedsFullLayout()` 为 `true` (因为定位方式的改变通常需要重新布局)。
- `diff.NeedsNormalPaintInvalidation()` 可能会为 `true` (取决于具体实现中是否将定位方式的改变视为需要绘制失效)。

**假设输入 3:**

- `old_style`: `opacity: 1;`
- `new_style`: `opacity: 0.5;`

**输出 3:**

- `field_diff` 中会包含 `kOpacity` 标志。
- `diff.NeedsFullLayout()` 为 `false`。
- `diff.NeedsNormalPaintInvalidation()` 可能会为 `true` (取决于合成层的处理)。
- `diff.SetOpacityChanged()` 会被调用。

**用户或编程常见的使用错误举例:**

1. **频繁修改样式导致的性能问题:**  如果 JavaScript 代码在一个循环中频繁地修改元素的样式，例如每次循环都改变 `left` 或 `top` 属性，会导致 Blink 引擎频繁地进行样式计算和渲染更新，可能造成页面卡顿。`VisualInvalidationDiff` 的作用是尽量优化这些更新，但过度频繁的修改仍然会影响性能。

2. **不必要的样式重置:** 有时开发者可能会不小心重置一些不需要修改的样式，例如，只打算修改背景颜色，却不小心将其他相关的背景属性也重置了。这会导致 `VisualInvalidationDiff` 检测到更多差异，可能触发不必要的渲染更新。

3. **过度使用复杂 CSS 属性:** 某些 CSS 属性，例如 `filter` 和 `clip-path`，在变化时可能需要进行更复杂的计算和渲染。过度或不必要地使用这些属性并频繁修改它们可能会导致性能问题。

**归纳一下它的功能 (针对提供的代码片段):**

这段代码的主要功能是**高效地比较两个 `ComputedStyle` 对象，并根据 CSS 属性的变化情况，精确地标记出需要进行的布局和绘制失效操作**。它通过检查各种 CSS 属性的差异，并设置 `StyleDifference` 对象中的相应标志，从而指导 Blink 渲染引擎进行最小化的必要更新，提高渲染效率和性能。

### 提示词
```
这是目录为blink/renderer/core/style/computed_style.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
llLayout();
    diff.SetNeedsNormalPaintInvalidation();
    diff.SetZIndexChanged();
  }

  if ((!diff.NeedsFullLayout() || !diff.NeedsNormalPaintInvalidation()) &&
      DiffNeedsFullLayoutAndPaintInvalidation(other, field_diff)) {
    diff.SetNeedsFullLayout();
    diff.SetNeedsNormalPaintInvalidation();
  }

  if (!diff.NeedsFullLayout() &&
      DiffNeedsFullLayout(document, other, field_diff)) {
    diff.SetNeedsFullLayout();
  }

  if (!diff.NeedsLayout()) {
    if ((field_diff & kOutOfFlow) && HasOutOfFlowPosition()) {
      diff.SetNeedsPositionedMovementLayout();
    } else if ((field_diff & kInset) && HasInFlowPosition()) {
      diff.SetNeedsPositionedMovementLayout();
    }
  }

  if (!diff.NeedsNormalPaintInvalidation() &&
      DiffNeedsNormalPaintInvalidation(document, other, field_diff)) {
    diff.SetNeedsNormalPaintInvalidation();
  }

  if (DiffNeedsRecomputeVisualOverflow(other, field_diff)) {
    diff.SetNeedsRecomputeVisualOverflow();
  }

  if (DiffCompositingReasonsChanged(other, field_diff)) {
    diff.SetCompositingReasonsChanged();
  }

  if (field_diff & kBackgroundColor) {
    // If the background color change is not due to a composited animation,
    // then paint invalidation is required; but we can defer the decision until
    // we know whether the color change will be rendered by the compositor.
    diff.SetBackgroundColorChanged();
  }
  if (field_diff & kBlendMode) {
    diff.SetBlendModeChanged();
  }
  if (field_diff & kBorderRadius) {
    diff.SetBorderRadiusChanged();
  }
  if (field_diff & kClip) {
    bool has_clip = HasOutOfFlowPosition() && !HasAutoClip();
    bool other_has_clip = other.HasOutOfFlowPosition() && !other.HasAutoClip();
    if (has_clip != other_has_clip || (has_clip && Clip() != other.Clip())) {
      diff.SetCSSClipChanged();
    }
  }
  if (field_diff & kClipPath) {
    diff.SetClipPathChanged();
  }
  if (field_diff & kColor) {
    diff.SetTextDecorationOrColorChanged();
  }
  if (field_diff & kFilterData) {
    diff.SetFilterChanged();
  }
  if (field_diff & kHasTransform) {
    if (HasTransform() != other.HasTransform()) {
      diff.SetOtherTransformPropertyChanged();
    }
  }
  if (field_diff & kMask) {
    diff.SetMaskChanged();
  }
  if (field_diff & kOpacity) {
    diff.SetOpacityChanged();
  }
  if (field_diff & kScrollbarColor) {
    if (UsedScrollbarColor() != other.UsedScrollbarColor()) {
      diff.SetNeedsNormalPaintInvalidation();
    }
  }
  if (field_diff & kScrollbarStyle) {
    if (HasPseudoElementStyle(kPseudoIdScrollbar) !=
            other.HasPseudoElementStyle(kPseudoIdScrollbar) ||
        UsesStandardScrollbarStyle() != other.UsesStandardScrollbarStyle()) {
      diff.SetNeedsFullLayout();
      diff.SetNeedsNormalPaintInvalidation();
    }
  }
  if (field_diff & kTextDecoration) {
    diff.SetTextDecorationOrColorChanged();
  }
  if (field_diff & kTransformData) {
    diff.SetTransformDataChanged();
  }
  if (field_diff & kTransformOther) {
    diff.SetOtherTransformPropertyChanged();
  }
  if (field_diff & kTransformProperty) {
    diff.SetTransformPropertyChanged();
  }
  if (field_diff & kVisibility) {
    if ((Visibility() == EVisibility::kCollapse) !=
        (other.Visibility() == EVisibility::kCollapse)) {
      diff.SetNeedsFullLayout();
    }
  }
  if (field_diff & kZIndex) {
    diff.SetZIndexChanged();
  }

  // If the (current)color changes and a filter or backdrop-filter uses it, the
  // filter or backdrop-filter needs to be updated. This reads
  // `diff.TextDecorationOrColorChanged()` and so needs to be after the setters,
  // above.
  if (diff.TextDecorationOrColorChanged()) {
    if (HasFilter() && Filter().UsesCurrentColor()) {
      diff.SetFilterChanged();
    }
    if (HasBackdropFilter() && BackdropFilter().UsesCurrentColor()) {
      // This could be optimized with a targeted backdrop-filter-changed
      // invalidation.
      diff.SetCompositingReasonsChanged();
    }
  }

  // The following condition needs to be at last, because it may depend on
  // conditions in diff computed above.
  if ((field_diff & kScrollAnchor) || diff.TransformChanged()) {
    diff.SetScrollAnchorDisablingPropertyChanged();
  }

  // Cursors are not checked, since they will be set appropriately in response
  // to mouse events, so they don't need to cause any paint invalidation or
  // layout.

  // Animations don't need to be checked either. We always set the new style on
  // the layoutObject, so we will get a chance to fire off the resulting
  // transition properly.

  return diff;
}

bool ComputedStyle::DiffNeedsFullLayoutAndPaintInvalidation(
    const ComputedStyle& other,
    uint64_t field_diff) const {
  if (IsDisplayTableType(Display())) {
    // In the collapsing border model, 'hidden' suppresses other borders, while
    // 'none' does not, so these style differences can be width differences.
    if ((BorderCollapse() == EBorderCollapse::kCollapse) &&
        ((BorderTopStyle() == EBorderStyle::kHidden &&
          other.BorderTopStyle() == EBorderStyle::kNone) ||
         (BorderTopStyle() == EBorderStyle::kNone &&
          other.BorderTopStyle() == EBorderStyle::kHidden) ||
         (BorderBottomStyle() == EBorderStyle::kHidden &&
          other.BorderBottomStyle() == EBorderStyle::kNone) ||
         (BorderBottomStyle() == EBorderStyle::kNone &&
          other.BorderBottomStyle() == EBorderStyle::kHidden) ||
         (BorderLeftStyle() == EBorderStyle::kHidden &&
          other.BorderLeftStyle() == EBorderStyle::kNone) ||
         (BorderLeftStyle() == EBorderStyle::kNone &&
          other.BorderLeftStyle() == EBorderStyle::kHidden) ||
         (BorderRightStyle() == EBorderStyle::kHidden &&
          other.BorderRightStyle() == EBorderStyle::kNone) ||
         (BorderRightStyle() == EBorderStyle::kNone &&
          other.BorderRightStyle() == EBorderStyle::kHidden))) {
      return true;
    }
  }

  // Movement of non-static-positioned object is special cased in
  // ComputedStyle::VisualInvalidationDiff().

  return false;
}

bool ComputedStyle::DiffNeedsFullLayout(const Document& document,
                                        const ComputedStyle& other,
                                        uint64_t field_diff) const {
  if (field_diff & kLayout) {
    return true;
  }

  if (field_diff & kBorderWidth) {
    if (BorderTopWidth() != other.BorderTopWidth() ||
        BorderRightWidth() != other.BorderRightWidth() ||
        BorderBottomWidth() != other.BorderBottomWidth() ||
        BorderLeftWidth() != other.BorderLeftWidth()) {
      return true;
    }
  }

  if ((field_diff & kMargin) && !HasOutOfFlowPosition()) {
    return true;
  }

  if (field_diff & kStroke) {
    if (HasStroke() != other.HasStroke()) {
      return true;
    }
    if (HasDashArray() != other.HasDashArray()) {
      return true;
    }
  }

  if (IsDisplayLayoutCustomBox() &&
      DiffNeedsFullLayoutForLayoutCustom(document, other)) {
    return true;
  }

  if (DisplayLayoutCustomParentName() &&
      DiffNeedsFullLayoutForLayoutCustomChild(document, other)) {
    return true;
  }

  return false;
}

bool ComputedStyle::DiffNeedsFullLayoutForLayoutCustom(
    const Document& document,
    const ComputedStyle& other) const {
  DCHECK(IsDisplayLayoutCustomBox());

  LayoutWorklet* worklet = LayoutWorklet::From(*document.domWindow());
  const AtomicString& name = DisplayLayoutCustomName();

  if (!worklet->GetDocumentDefinitionMap()->Contains(name)) {
    return false;
  }

  const DocumentLayoutDefinition* definition =
      worklet->GetDocumentDefinitionMap()->at(name);
  if (definition == kInvalidDocumentLayoutDefinition) {
    return false;
  }

  if (!PropertiesEqual(definition->NativeInvalidationProperties(), other)) {
    return true;
  }

  if (!CustomPropertiesEqual(definition->CustomInvalidationProperties(),
                             other)) {
    return true;
  }

  return false;
}

bool ComputedStyle::DiffNeedsFullLayoutForLayoutCustomChild(
    const Document& document,
    const ComputedStyle& other) const {
  LayoutWorklet* worklet = LayoutWorklet::From(*document.domWindow());
  const AtomicString& name = DisplayLayoutCustomParentName();

  if (!worklet->GetDocumentDefinitionMap()->Contains(name)) {
    return false;
  }

  const DocumentLayoutDefinition* definition =
      worklet->GetDocumentDefinitionMap()->at(name);
  if (definition == kInvalidDocumentLayoutDefinition) {
    return false;
  }

  if (!PropertiesEqual(definition->ChildNativeInvalidationProperties(),
                       other)) {
    return true;
  }

  if (!CustomPropertiesEqual(definition->ChildCustomInvalidationProperties(),
                             other)) {
    return true;
  }

  return false;
}

bool ComputedStyle::DiffNeedsNormalPaintInvalidation(
    const Document& document,
    const ComputedStyle& other,
    uint64_t field_diff) const {
  if (field_diff & kPaint) {
    return true;
  }

  if ((field_diff & kAccentColor) &&
      AccentColorResolved() != other.AccentColorResolved()) {
    return true;
  }

  if ((field_diff & kOutline) && !OutlineVisuallyEqual(other)) {
    return true;
  }

  if ((field_diff & kBackground) &&
      !BackgroundInternal().VisuallyEqual(other.BackgroundInternal())) {
    return true;
  }

  if (field_diff & kBackgroundCurrentColor) {
    // If the background-image or background-color depends on currentColor
    // (e.g., background-image: linear-gradient(currentColor, #fff) or
    // background-color: color-mix(in srgb, currentcolor ...)), and the color
    // has changed, we need to recompute it even though VisuallyEqual()
    // thinks the old and new background styles are identical.
    if ((BackgroundInternal().AnyLayerUsesCurrentColor() ||
         BackgroundColor().IsUnresolvedColorFunction() ||
         InternalVisitedBackgroundColor().IsUnresolvedColorFunction()) &&
        (GetCurrentColor() != other.GetCurrentColor() ||
         GetInternalVisitedCurrentColor() !=
             other.GetInternalVisitedCurrentColor())) {
      return true;
    }
  }

  if ((field_diff & kBorderVisual) && !BorderVisuallyEqual(other)) {
    return true;
  }

  if ((field_diff & kBorderOutlineVisitedColor) &&
      BorderOutlineVisitedColorChanged(other)) {
    return true;
  }

  if (PaintImagesInternal()) {
    for (const auto& image : PaintImagesInternal()->Images()) {
      DCHECK(image);
      if (DiffNeedsPaintInvalidationForPaintImage(*image, other, document)) {
        return true;
      }
    }
  }

  return false;
}

bool ComputedStyle::DiffNeedsPaintInvalidationForPaintImage(
    const StyleImage& image,
    const ComputedStyle& other,
    const Document& document) const {
  // https://crbug.com/835589: early exit when paint target is associated with
  // a link.
  if (InsideLink() != EInsideLink::kNotInsideLink) {
    return false;
  }

  CSSPaintValue* value = To<CSSPaintValue>(image.CssValue());

  // NOTE: If the invalidation properties vectors are null, we are invalid as
  // we haven't yet been painted (and can't provide the invalidation
  // properties yet).
  if (!value->NativeInvalidationProperties(document) ||
      !value->CustomInvalidationProperties(document)) {
    return true;
  }

  if (!PropertiesEqual(*value->NativeInvalidationProperties(document), other)) {
    return true;
  }

  if (!CustomPropertiesEqual(*value->CustomInvalidationProperties(document),
                             other)) {
    return true;
  }

  return false;
}

bool ComputedStyle::PropertiesEqual(const Vector<CSSPropertyID>& properties,
                                    const ComputedStyle& other) const {
  for (CSSPropertyID property_id : properties) {
    // TODO(ikilpatrick): remove IsInterpolableProperty check once
    // CSSPropertyEquality::PropertiesEqual correctly handles all properties.
    const CSSProperty& property = CSSProperty::Get(property_id);
    if (!property.IsInterpolable() ||
        !CSSPropertyEquality::PropertiesEqual(PropertyHandle(property), *this,
                                              other)) {
      return false;
    }
  }

  return true;
}

bool ComputedStyle::CustomPropertiesEqual(
    const Vector<AtomicString>& properties,
    const ComputedStyle& other) const {
  // Short-circuit if neither of the styles have custom properties.
  if (!HasVariables() && !other.HasVariables()) {
    return true;
  }

  for (const AtomicString& property_name : properties) {
    if (!base::ValuesEquivalent(GetVariableData(property_name),
                                other.GetVariableData(property_name))) {
      return false;
    }
    if (!base::ValuesEquivalent(GetVariableValue(property_name),
                                other.GetVariableValue(property_name))) {
      return false;
    }
  }

  return true;
}

bool ComputedStyle::PotentialCompositingReasonsFor3DTransformChanged(
    const ComputedStyle& other) const {
  // Compositing reasons for 3D transforms depend on the LayoutObject type (see:
  // |LayoutObject::HasTransformRelatedProperty|)) This will return true for
  // some LayoutObjects that end up not supporting transforms.
  return CompositingReasonFinder::PotentialCompositingReasonsFor3DTransform(
             *this) !=
         CompositingReasonFinder::PotentialCompositingReasonsFor3DTransform(
             other);
}

bool ComputedStyle::DiffNeedsRecomputeVisualOverflow(
    const ComputedStyle& other,
    uint64_t field_diff) const {
  if (field_diff & kVisualOverflow) {
    return true;
  }

  if ((field_diff & kBorderImage) && !BorderVisualOverflowEqual(other)) {
    return true;
  }

  if ((field_diff & kOutline) && !OutlineVisuallyEqual(other)) {
    return true;
  }

  if ((field_diff & kTextDecoration) &&
      TextDecorationVisualOverflowChanged(other)) {
    return true;
  }

  return false;
}

bool ComputedStyle::DiffCompositingReasonsChanged(const ComputedStyle& other,
                                                  uint64_t field_diff) const {
  if (field_diff & kCompositing) {
    return true;
  }

  if (UsedTransformStyle3D() != other.UsedTransformStyle3D()) {
    return true;
  }

  if (ContainsPaint() != other.ContainsPaint()) {
    return true;
  }

  if (IsOverflowVisibleAlongBothAxes() !=
      other.IsOverflowVisibleAlongBothAxes()) {
    return true;
  }

  if (PotentialCompositingReasonsFor3DTransformChanged(other)) {
    return true;
  }

  return false;
}

bool ComputedStyle::HasCSSPaintImagesUsingCustomProperty(
    const AtomicString& custom_property_name,
    const Document& document) const {
  if (PaintImagesInternal()) {
    for (const auto& image : PaintImagesInternal()->Images()) {
      DCHECK(image);
      // IsPaintImage is true for CSS Paint images only, please refer to the
      // constructor of StyleGeneratedImage.
      if (image->IsPaintImage()) {
        return To<StyleGeneratedImage>(image.Get())
            ->IsUsingCustomProperty(custom_property_name, document);
      }
    }
  }
  return false;
}

static bool HasPropertyThatCreatesStackingContext(
    const Vector<CSSPropertyID>& properties) {
  for (CSSPropertyID property : properties) {
    switch (ResolveCSSPropertyID(property)) {
      case CSSPropertyID::kOpacity:
      case CSSPropertyID::kTransform:
      case CSSPropertyID::kTransformStyle:
      case CSSPropertyID::kPerspective:
      case CSSPropertyID::kTranslate:
      case CSSPropertyID::kRotate:
      case CSSPropertyID::kScale:
      case CSSPropertyID::kOffsetPath:
      case CSSPropertyID::kOffsetPosition:
      case CSSPropertyID::kMask:
      case CSSPropertyID::kWebkitMaskBoxImage:
      case CSSPropertyID::kClipPath:
      case CSSPropertyID::kWebkitBoxReflect:
      case CSSPropertyID::kFilter:
      case CSSPropertyID::kBackdropFilter:
      case CSSPropertyID::kZIndex:
      case CSSPropertyID::kPosition:
      case CSSPropertyID::kMixBlendMode:
      case CSSPropertyID::kIsolation:
      case CSSPropertyID::kContain:
      case CSSPropertyID::kViewTransitionName:
        return true;
      default:
        break;
    }
  }
  return false;
}

static bool IsWillChangeTransformHintProperty(CSSPropertyID property) {
  switch (ResolveCSSPropertyID(property)) {
    case CSSPropertyID::kTransform:
    case CSSPropertyID::kPerspective:
    case CSSPropertyID::kTransformStyle:
      return true;
    default:
      break;
  }
  return false;
}

static bool IsWillChangeHintForAnyTransformProperty(CSSPropertyID property) {
  switch (ResolveCSSPropertyID(property)) {
    case CSSPropertyID::kTransform:
    case CSSPropertyID::kPerspective:
    case CSSPropertyID::kTranslate:
    case CSSPropertyID::kScale:
    case CSSPropertyID::kRotate:
    case CSSPropertyID::kOffsetPath:
    case CSSPropertyID::kOffsetPosition:
    case CSSPropertyID::kTransformStyle:
      return true;
    default:
      break;
  }
  return false;
}

static bool IsWillChangeCompositingHintProperty(CSSPropertyID property) {
  if (IsWillChangeHintForAnyTransformProperty(property)) {
    return true;
  }
  switch (ResolveCSSPropertyID(property)) {
    case CSSPropertyID::kOpacity:
    case CSSPropertyID::kFilter:
    case CSSPropertyID::kBackdropFilter:
    case CSSPropertyID::kTop:
    case CSSPropertyID::kLeft:
    case CSSPropertyID::kBottom:
    case CSSPropertyID::kRight:
      return true;
    default:
      break;
  }
  return false;
}

bool ComputedStyle::HasWillChangeCompositingHint() const {
  return base::ranges::any_of(WillChangeProperties(),
                              IsWillChangeCompositingHintProperty);
}

bool ComputedStyle::HasWillChangeTransformHint() const {
  return base::ranges::any_of(WillChangeProperties(),
                              IsWillChangeTransformHintProperty);
}

bool ComputedStyle::HasWillChangeHintForAnyTransformProperty() const {
  return base::ranges::any_of(WillChangeProperties(),
                              IsWillChangeHintForAnyTransformProperty);
}

bool ComputedStyle::RequireTransformOrigin(
    ApplyTransformOrigin apply_origin,
    ApplyMotionPath apply_motion_path) const {
  // transform-origin brackets the transform with translate operations.
  // Optimize for the case where the only transform is a translation, since the
  // transform-origin is irrelevant in that case.
  if (apply_origin != kIncludeTransformOrigin) {
    return false;
  }

  if (apply_motion_path == kIncludeMotionPath) {
    return true;
  }

  for (const auto& operation : Transform().Operations()) {
    TransformOperation::OperationType type = operation->GetType();
    if (type != TransformOperation::kTranslateX &&
        type != TransformOperation::kTranslateY &&
        type != TransformOperation::kTranslate &&
        type != TransformOperation::kTranslateZ &&
        type != TransformOperation::kTranslate3D) {
      return true;
    }
  }

  return Scale() || Rotate();
}

InterpolationQuality ComputedStyle::GetInterpolationQuality() const {
  if (ImageRendering() == EImageRendering::kPixelated) {
    return kInterpolationNone;
  }

  if (ImageRendering() == EImageRendering::kWebkitOptimizeContrast) {
    return kInterpolationLow;
  }

  return GetDefaultInterpolationQuality();
}

void ComputedStyle::LoadDeferredImages(Document& document) const {
  if (HasBackgroundImage()) {
    for (const FillLayer* background_layer = &BackgroundLayers();
         background_layer; background_layer = background_layer->Next()) {
      if (StyleImage* image = background_layer->GetImage()) {
        if (image->IsImageResource() && image->IsLazyloadPossiblyDeferred()) {
          To<StyleFetchedImage>(image)->LoadDeferredImage(document);
        }
      }
    }
  }
}

ETransformBox ComputedStyle::UsedTransformBox(
    TransformBoxContext box_context) const {
  ETransformBox transform_box = TransformBox();
  if (box_context == TransformBoxContext::kSvg) {
    // For SVG elements without associated CSS layout box, the used value for
    // content-box is fill-box and for border-box is stroke-box.
    switch (transform_box) {
      case ETransformBox::kContentBox:
        transform_box = ETransformBox::kFillBox;
        break;
      case ETransformBox::kBorderBox:
        transform_box = ETransformBox::kStrokeBox;
        break;
      case ETransformBox::kFillBox:
      case ETransformBox::kStrokeBox:
      case ETransformBox::kViewBox:
        break;
    }
    // If transform-box is stroke-box and the element has "vector-effect:
    // non-scaling-stroke", then the used transform-box is fill-box.
    if (transform_box == ETransformBox::kStrokeBox &&
        VectorEffect() == EVectorEffect::kNonScalingStroke) {
      transform_box = ETransformBox::kFillBox;
    }
  } else {
    // For elements with associated CSS layout box, the used value for fill-box
    // is content-box and for stroke-box and view-box is border-box.
    switch (transform_box) {
      case ETransformBox::kContentBox:
      case ETransformBox::kBorderBox:
        break;
      case ETransformBox::kFillBox:
        transform_box = ETransformBox::kContentBox;
        break;
      case ETransformBox::kStrokeBox:
      case ETransformBox::kViewBox:
        transform_box = ETransformBox::kBorderBox;
        break;
    }
  }
  return transform_box;
}

void ComputedStyle::ApplyTransform(
    gfx::Transform& result,
    const LayoutBox* box,
    const PhysicalRect& reference_box,
    ApplyTransformOperations apply_operations,
    ApplyTransformOrigin apply_origin,
    ApplyMotionPath apply_motion_path,
    ApplyIndependentTransformProperties apply_independent_transform_properties)
    const {
  ApplyTransform(result, box, gfx::RectF(reference_box), apply_operations,
                 apply_origin, apply_motion_path,
                 apply_independent_transform_properties);
}

void ComputedStyle::ApplyTransform(
    gfx::Transform& result,
    const LayoutBox* box,
    const gfx::RectF& bounding_box,
    ApplyTransformOperations apply_operations,
    ApplyTransformOrigin apply_origin,
    ApplyMotionPath apply_motion_path,
    ApplyIndependentTransformProperties apply_independent_transform_properties)
    const {
  if (!HasOffset()) {
    apply_motion_path = kExcludeMotionPath;
  }
  bool apply_transform_origin =
      RequireTransformOrigin(apply_origin, apply_motion_path);

  float origin_x = 0;
  float origin_y = 0;
  float origin_z = 0;

  const gfx::SizeF& box_size = bounding_box.size();
  if (apply_transform_origin ||
      // We need to calculate originX and originY for applying motion path.
      apply_motion_path == kIncludeMotionPath) {
    origin_x = FloatValueForLength(GetTransformOrigin().X(), box_size.width()) +
               bounding_box.x();
    origin_y =
        FloatValueForLength(GetTransformOrigin().Y(), box_size.height()) +
        bounding_box.y();
    if (apply_transform_origin) {
      origin_z = GetTransformOrigin().Z();
      result.Translate3d(origin_x, origin_y, origin_z);
    }
  }

  if (apply_independent_transform_properties ==
      kIncludeIndependentTransformProperties) {
    if (Translate()) {
      Translate()->Apply(result, box_size);
    }

    if (Rotate()) {
      Rotate()->Apply(result, box_size);
    }

    if (Scale()) {
      Scale()->Apply(result, box_size);
    }
  }

  if (apply_motion_path == kIncludeMotionPath) {
    ApplyMotionPathTransform(origin_x, origin_y, box, bounding_box, result);
  }

  if (apply_operations == kIncludeTransformOperations) {
    for (const auto& operation : Transform().Operations()) {
      operation->Apply(result, box_size);
    }
  }

  if (apply_transform_origin) {
    result.Translate3d(-origin_x, -origin_y, -origin_z);
  }
}

namespace {

gfx::RectF GetReferenceBox(const LayoutBox* box, CoordBox coord_box) {
  if (box) {
    if (const LayoutBlock* containing_block = box->ContainingBlock()) {
      // In SVG contexts, all values behave as view-box.
      if (box->IsSVG()) {
        return gfx::RectF(SVGViewportResolver(*box).ResolveViewport());
      }
      // https://drafts.csswg.org/css-box-4/#typedef-coord-box
      switch (coord_box) {
        case CoordBox::kFillBox:
        case CoordBox::kContentBox:
          return gfx::RectF(containing_block->PhysicalContentBoxRect());
        case CoordBox::kPaddingBox:
          return gfx::RectF(containing_block->PhysicalPaddingBoxRect());
        case CoordBox::kViewBox:
        case CoordBox::kStrokeBox:
        case CoordBox::kBorderBox:
          return gfx::RectF(containing_block->PhysicalBorderBoxRect());
      }
    }
  }
  // As the motion path calculations can be called before all the layout
  // has been correctly calculated, we can end up here.
  return gfx::RectF();
}

gfx::PointF GetOffsetFromContainingBlock(const LayoutBox* box) {
  if (box) {
    if (const LayoutBlock* containing_block = box->ContainingBlock()) {
      gfx::PointF offset = box->LocalToAncestorPoint(
          gfx::PointF(), containing_block, kIgnoreTransforms);
      return offset;
    }
  }
  return {0, 0};
}

// https://drafts.fxtf.org/motion/#offset-position-property
gfx::PointF GetStartingPointOfThePath(
    const gfx::PointF& offset_from_reference_box,
    const LengthPoint& offset_position,
    const gfx::SizeF& reference_box_size) {
  if (offset_position.X().IsAuto()) {
    return offset_from_reference_box;
  }
  if (offset_position.X().IsNone()) {
    // Currently all the use cases will behave as "at center".
    return PointForLengthPoint(
        LengthPoint(Length::Percent(50), Length::Percent(50)),
        reference_box_size);
  }
  return PointForLengthPoint(offset_position, reference_box_size);
}

}  // namespace

PointAndTangent ComputedStyle::CalculatePointAndTangentOnBasicShape(
    const BasicShape& shape,
    const gfx::PointF& starting_point,
    const gfx::SizeF& reference_box_size) const {
  Path path;
  if (const auto* circle_or_ellipse =
          DynamicTo<BasicShapeWithCenterAndRadii>(shape);
      circle_or_ellipse && !circle_or_ellipse->HasExplicitCenter()) {
    // For all <basic-shape>s, if they accept an at <position> argument
    // but that argument is omitted, and the element defines
    // an offset starting position via offset-position,
    // it uses the specified offset starting position for that argument.
    circle_or_ellipse->GetPathFromCenter(
        path, starting_point, gfx::RectF(reference_box_size), EffectiveZoom());
  } else {
    shape.GetPath(path, gfx::RectF(reference_box_size), EffectiveZoom());
  }
  float shape_length = path.length();
  float path_length = FloatValueForLength(OffsetDistance(), shape_length);
  // All the shapes are closed at this point.
  if (shape_length > 0) {
    path_length = fmod(path_length, shape_length);
    if (path_length < 0) {
      path_length += shape_length;
    }
  }
  return path.PointAndNormalAtLength(path_length);
}

PointAndTangent ComputedStyle::CalculatePointAndTangentOnRay(
    const StyleRay& ray,
    const LayoutBox* box,
    const gfx::PointF& starting_point,
    const gfx::SizeF& reference_box_size) const {
  float ray_length =
      ray.CalculateRayPathLength(starting_point, reference_box_size);
  if (ray.Contain() && box) {
    // The length of the offset path is reduced so that the element stays
    // within the containing block even at offset-distance: 100%.
    // Specifically, the path’s length is reduced by half the width
    // or half the height of the element’s border box,
    // whichever is larger, and floored at zero.
    const PhysicalRect border_box_rect = box->PhysicalBorderBoxRect();
    const float largest_side = std::max(border_box_rect.Width().ToFloat(),
                                        border_box_rect.Height().ToFloat());
    ray_length -= largest_side / 2;
    ray_length = std::max(ray_length, 0.f);
  }
  const float path_length = FloatValueForLength(OffsetDistance(), ray_length);
  return ray.PointAndNormalAtLength(starting_point, path_length);
}

PointAndTangent ComputedStyle::CalculatePointAndTangentOnPath(
    const Path& path) const {
  float zoom = EffectiveZoom();
  float path_length = path.length();
  float float_distance =
      FloatValueForLength(OffsetDistance(), path_length * zoom) / zoom;
  float computed_distance;
  if (path.IsClosed() && path_length > 0) {
    computed_distance = fmod(float_distance, path_length);
    if (computed_distance < 0) {
      computed_distance += path_length;
    }
  } else {
    computed_distance = ClampTo<float>(float_distance, 0, path_length);
  }
  PointAndTangent path_position =
      path.PointAndNormalAtLength(computed_distance);
  path_position.point.Scale(zoom, zoom);
  return path_position;
}

void ComputedStyle::ApplyMotionPathTransform(float origin_x,
                                             float origin_y,
                                             const LayoutBox* box,
                                             const gfx::RectF& bounding_box,
                                             gfx::Transform& transform) const {
  const OffsetPathOperation* offset_path = OffsetPath();
  if (!offset_path) {
    return;
  }

  const LengthPoint& position = OffsetPosition();
  const StyleOffsetRotation& rotate = OffsetRotate();
  CoordBox coord_box = offset_path->GetCoordBox();

  PointAndTangent path_position;
  if (const auto* shape_operation =
          DynamicTo<ShapeOffsetPathOperation>(offset_path)) {
    const BasicShape& basic_shape = shape_operation->GetBasicShape();
    switch (basic_shape.GetType()) {
      case BasicShape::kStylePathType: {
        const StylePath& path = To<StylePath>(basic_shape);
        path_position = CalculatePointAndTangentOnPath(path.GetPath());
        break;
      }
      case BasicShape::kStyleRayType: {
        const gfx::RectF reference_box = GetReferenceBox(box, coord_box);
        const gfx::PointF offset_from_reference_box =
            GetOffsetFromContainingBlock(box) -
            reference_box.OffsetFromOrigin();
        const gfx::SizeF& reference_box_size = reference_box.size();
        const StyleRay& ray = To<StyleRay>(basic_shape);
        // Specifies the origin of the ray, where the ray’s line begins (the 0%
        // position). It’s resolved by using the <position> to position a 0x0
        // object area within the box’s containing block. If omitted, it uses
        // the offset starting position of the element, given by
        // offset-position. If the element doesn’t have an offset starting
        // position either, it behaves as at center.
        // NOTE: In current parsing implementation:
        // if `at position` is omitted, it will be computed as 50% 50%.
        gfx::PointF starting_point;
        if (ray.HasExplicitCenter() || position.X().IsNone()) {
          starting_point = PointForCenterCoordinate(
              ray.CenterX(), ray.CenterY(), reference_box_size);
        } else {
          starting_point = GetStartingPointOfThePath(
              offset_from_reference_box, position, reference_box_size);
        }
        path_position = CalculatePointAndTangentOnRay(ray, box, starting_point,
                                                      reference_box_size);
        // `path_position.point` is now relative to the containing block.
        // Make it relative to the box.
        path_position.point -= offset_from_reference_box.OffsetFromOrigin();
        break;
      }
      case BasicShape::kBasicShapeCircleType:
      case BasicShape::kBasicShapeEllipseType:
      case BasicShape::kBasicShapeInsetType:
      case BasicShape::kBasicShapePolygonType: {
        const gfx::RectF reference_box = GetReferenceBox(box, coord_box);
        const gfx::PointF offset_from_reference_box =
            GetOffsetFromContainingBlock(box) -
            reference_box.OffsetFromOrigin();
        const gfx::SizeF& reference_box_size = reference_box.size();
        const gfx::PointF starting_point = GetStartingPointOfThePath(
            offset_from_reference_box, position, reference_box_size);
        path_position = CalculatePointAndTangentOnBasicShape(
            basic_shape, starting_point, reference_box_size);
        // `path_position.point` is now relative to the containing block.
        // Make it relative to the box.
        path_position.point -= offset_from_reference_box.OffsetFromOrigin();
        break;
      }
    }
  } else if (IsA<CoordBoxOffsetPathOperation>(offset_path)) {
    if (box && box->ContainingBlock()) {
      scoped_refptr<BasicShapeInset> inset = BasicShapeInset::Create();
      inset->SetTop(Length::Fixed(0));
      inset->SetBottom(Length::Fixed(0));
      inset->SetLeft(Length::Fixed(0));
      inset->SetRight(Length::Fixed(0));
      const ComputedStyle& style = box->ContainingBlock()->StyleRef();
      inset->SetTopLeftRadius(style.BorderTopLeftRadius());
      inset->SetTopRightRadius(style.BorderTopR
```