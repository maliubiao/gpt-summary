Response:
The user wants a summary of the functionality of the provided C++ code snippet from `style_adjuster.cc`. This file seems to be responsible for adjusting the computed style of elements in the Blink rendering engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name `style_adjuster.cc` and the function `AdjustComputedStyle` clearly indicate that this code is about modifying or refining the computed styles of elements.

2. **Analyze Individual Functions:** Go through each function defined in the snippet and understand its specific role:
    * `IsEditableElement`: Checks if an element is editable (textareas or input fields).
    * `IsPasswordFieldWithUnrevealedPassword`: Checks if an element is a password field with the password hidden.
    * `AdjustEffectiveTouchAction`: Modifies the `touch-action` CSS property based on inheritance, element type, and other factors. This involves handling interactions like panning and zooming.
    * `AdjustStyleForInert`:  Deals with the `inert` attribute, making elements non-interactive. It considers modal dialogs, fullscreen elements, and transitions to `display: none`.
    * `AdjustForForcedColorsMode`:  Handles adjustments needed when the browser is in forced colors mode for accessibility. It resets certain styles like shadows and background images and resolves system colors.
    * `AdjustForSVGTextElement`: Resets column-related CSS properties for SVG text elements.
    * `AdjustComputedStyle`: This is the main function. It orchestrates the other adjustment functions and performs various style modifications based on element type, CSS properties, and other conditions.

3. **Categorize Adjustments in `AdjustComputedStyle`:** Group the different types of adjustments performed in the main function:
    * **Basic HTML Element Adjustments:** Handling `display` values, especially for document elements and out-of-flow elements. Calling `AdjustStyleForHTMLElement`.
    * **Positioning and Stacking Context:**  Dealing with `z-index`, stacking contexts, and the `overlay` property.
    * **Display Properties:** Adjusting `display` based on context (e.g., `contents`, `math`). Calling `AdjustStyleForDisplay`.
    * **Text and Decorations:**  Handling `text-decoration` inheritance and adjustments for highlight pseudos. Calling `AdjustStyleForFirstLetter`, `AdjustStyleForMarker`.
    * **Background and Mask Layers:**  Adjusting and managing background and mask layers.
    * **Theme and Accessibility:**  Calling `AdjustForForcedColorsMode` and `LayoutTheme::GetTheme().AdjustStyle`.
    * **Interactivity:** Calling `AdjustStyleForInert` and `AdjustStyleForEditing`.
    * **SVG and MathML:** Handling specific adjustments for SVG and MathML elements. Calling `AdjustStyleForSvgElement`.
    * **Sticky Positioning:** Tracking sticky elements.
    * **Flexbox/Grid Layout:** Adjusting `justify-items` with the `legacy` keyword.
    * **Touch Interactions:** Calling `AdjustEffectiveTouchAction`.
    * **Media Controls:** Specific adjustments for media controls.
    * **Text Overflow:** Handling `text-overflow: ellipsis` for input placeholders.
    * **Custom Style Callbacks:** Allowing elements to modify their own styles.
    * **View Transitions:** Identifying elements participating in view transitions.
    * **Content Visibility:** Handling `content-visibility: auto`.

4. **Identify Relationships with Web Technologies:**
    * **JavaScript:** The code interacts with the DOM (e.g., checking element types, getting document information), which is the bridge between JavaScript and the rendered page. The `CanExecuteScripts` check is a direct link.
    * **HTML:** The code directly manipulates styles based on HTML elements and their attributes (e.g., `input`, `textarea`, `inert`, `touch-action`, `style`).
    * **CSS:** The entire purpose is to adjust CSS properties. The code directly works with CSS concepts like `display`, `position`, `z-index`, `overflow`, `background-image`, `text-decoration`, `touch-action`, forced colors mode, and more.

5. **Infer Logic and Potential Input/Output:**  For functions like `IsEditableElement` and `IsPasswordFieldWithUnrevealedPassword`, the input is an `Element*`, and the output is a boolean. For `AdjustEffectiveTouchAction`, the inputs are style information and the element, and the output is the modified computed style (specifically the `touch-action`). For `AdjustStyleForInert`, the input is an element, and the output is the modification of the `isHTMLInert` style.

6. **Consider User and Programmer Errors:**
    * **User Errors:** Incorrect HTML structure or invalid CSS might lead to unexpected style adjustments. For instance, an editable element might not be recognized if its HTML structure is unusual.
    * **Programmer Errors:**  Incorrectly setting CSS properties via JavaScript could lead to the `StyleAdjuster` making adjustments that were not intended. Misunderstanding the inheritance of `touch-action` could also lead to problems.

7. **Trace User Actions (Debugging Clues):**  Think about how a user's interaction might lead to this code being executed:
    * Loading a web page: The initial rendering process will involve style resolution and adjustments.
    * User interaction (clicks, scrolls, focus):  These can trigger style recalculations, especially for pseudo-classes or dynamic styles.
    * JavaScript manipulation of styles or attributes:  Changes made via JavaScript will necessitate style recomputation.
    * Browser features (forced colors mode, inert attribute): Enabling or using these features will directly involve this code.

8. **Synthesize and Structure the Summary:**  Organize the findings into a coherent summary, covering the main functionalities, relationships with web technologies, logic examples, potential errors, and debugging information. Since this is part 2, focus on summarizing the overall function.好的，这是对第二部分代码的功能归纳：

**功能归纳：**

这段代码是 `blink/renderer/core/css/resolver/style_adjuster.cc` 文件的一部分，主要负责在计算元素的最终样式时进行各种调整和修正。其核心功能可以归纳为以下几点：

1. **处理可编辑元素和密码字段：**
   - `IsEditableElement` 函数用于判断一个元素是否可编辑，主要针对 `<textarea>` 和文本类型的 `<input>` 元素。
   - `IsPasswordFieldWithUnrevealedPassword` 函数用于判断一个 `<input>` 元素是否为密码类型且密码未显示。

2. **调整 `touch-action` 属性：**
   - `AdjustEffectiveTouchAction` 函数负责计算和调整元素的最终 `touch-action` 属性。它会考虑父元素的 `touch-action` 继承、元素的类型、是否是 SVG 根元素、以及是否需要布局对象等因素。
   - 此函数还处理了内部的 `kInternalPanXScrolls` 和 `kInternalNotWritable` 标志位，用于后续对可编辑区域的优化。
   - 还会考虑文档级别的 `垂直滚动强制` 策略以及是否启用了 `滑动移动光标` 功能。
   - 针对启用了 `StylusHandwriting` 功能的可编辑非密码字段，会移除 `kInternalNotWritable` 标志。
   - 最后，会将计算出的 `touch-action` 传递给子 frame。

3. **处理 `inert` 属性：**
   - `AdjustStyleForInert` 函数负责处理 `inert` 属性，使元素变为非交互状态。
   - 它会检查元素是否设置了 `inert` 属性，或者是否是模态对话框/全屏元素的父元素，以及元素是否正在过渡到 `display: none`。

4. **处理强制颜色模式：**
   - `AdjustForForcedColorsMode` 函数在浏览器处于强制颜色模式时进行样式调整。
   - 它会重置 `text-shadow`、`box-shadow`、`color-scheme`、`scrollbar-color` 等属性为初始值。
   - 如果背景图片是 URL 类型的，则会清除背景图片。
   - 还会根据用户偏好的颜色方案重新解析一些内部强制颜色属性。

5. **调整 SVG 文本元素的样式：**
   - `AdjustForSVGTextElement` 函数会将 SVG 文本元素的列相关属性重置为初始值。

6. **主样式调整函数 `AdjustComputedStyle`：**
   - 这是核心函数，它接收样式解析状态和元素作为参数，并执行一系列的样式调整逻辑。
   - 它会调用前面提到的各种辅助调整函数，例如 `AdjustStyleForHTMLElement`（未在此段代码中显示）、`AdjustStyleForFirstLetter`、`AdjustStyleForMarker`、`AdjustStyleForDisplay` 等。
   - **处理 `display` 属性：** 根据元素类型和上下文调整 `display` 属性，例如对于绝对定位或固定定位的元素，会将其外部 display 设置为 block-like。
   - **处理层叠上下文：**  根据 `z-index` 和元素类型（例如根元素、`SVGForeignObjectElement`、设置了 `overlay: auto` 的元素、伪元素等）设置是否强制创建层叠上下文。
   - **处理 `overflow` 属性：**  当 `overflow-x` 或 `overflow-y` 不为 `visible` 时调用 `AdjustOverflow` 函数（未在此段代码中显示）。
   - **处理文本装饰：**  根据元素是否阻止文本装饰的传播以及是否是高亮伪元素来设置 `BaseTextDecorationData`。
   - **处理高亮伪元素：**  对于高亮伪元素，其 `color` 和 `internal-visited-color` 会使用原始元素的颜色。
   - **调整背景和遮罩层：** 调用 `AdjustBackgroundLayers` 和 `AdjustMaskLayers` 函数。
   - **应用主题样式：** 调用 `LayoutTheme::GetTheme().AdjustStyle` 来应用平台或用户主题的样式。
   - **处理可编辑元素样式：** 调用 `AdjustStyleForEditing` 函数（未在此段代码中显示）。
   - **处理 SVG 元素样式：** 调用 `AdjustStyleForSvgElement` 函数。
   - **处理 MathML 元素样式：** 如果 MathML 元素的 `display` 为 `contents`，则将其设置为 `none`。
   - **处理 sticky 定位：** 如果元素的 `position` 为 `sticky`，则标记该子树为 sticky 子树。
   - **处理 `justify-items` 属性：**  处理 `justify-items` 属性中 `legacy` 关键字的计算值。
   - **处理媒体控件样式：** 如果元素是媒体控件且未设置有效的 `-webkit-appearance`，则清除背景图片。
   - **处理文本溢出省略号：**  对于 input 占位符和建议文本等场景，会根据元素状态调整 `text-overflow` 属性。
   - **调用自定义样式回调：** 如果元素有自定义样式回调，则会调用 `element->AdjustStyle`。
   - **标记视图过渡参与者：**  如果元素是视图过渡的参与者（排除根元素），则设置相应的标志。
   - **处理 `content-visibility: auto`：**  如果启用了相关特性且 `content-visibility` 为 `auto`，则设置 `contain-intrinsic-size: auto`。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:** 代码直接操作和识别 HTML 元素（例如 `HTMLInputElement`, `HTMLTextAreaElement`, `HTMLCanvasElement`, `SVGElement`, `MathMLElement` 等），并根据元素的类型和属性进行样式调整。例如，`IsEditableElement` 检查元素是否是 `<textarea>` 或特定类型的 `<input>`。
* **CSS:**  该代码的核心目标是计算和调整元素的 CSS 样式。它读取和修改各种 CSS 属性，例如 `display`, `position`, `z-index`, `touch-action`, `overflow`, `background-image`, `text-decoration`, `color`, `text-shadow`, `box-shadow`, `color-scheme`, `content-visibility` 等。例如，`AdjustEffectiveTouchAction` 就是在处理 `touch-action` 这个 CSS 属性。
* **JavaScript:** 虽然这段 C++ 代码本身不是 JavaScript，但它所处理的样式计算结果会直接影响到 JavaScript 可以查询到的元素样式。此外，JavaScript 可以通过 DOM API 动态修改元素的属性和样式，这些修改最终会触发 Blink 引擎重新进行样式计算，并会调用到 `StyleAdjuster` 中的逻辑。例如，JavaScript 可以设置元素的 `inert` 属性，从而触发 `AdjustStyleForInert` 的执行。另外，`element->GetExecutionContext()->CanExecuteScripts()` 表明该代码会考虑脚本执行的上下文。

**逻辑推理、假设输入与输出：**

**示例 1：`IsEditableElement`**

* **假设输入：** 一个指向 `HTMLInputElement` 对象的指针，该对象的 `type` 属性为 "text"，且未设置 `disabled` 和 `readonly` 属性。
* **输出：** `true`

* **假设输入：** 一个指向 `HTMLInputElement` 对象的指针，该对象的 `type` 属性为 "checkbox"。
* **输出：** `false`

**示例 2：`AdjustEffectiveTouchAction`**

* **假设输入：**
    * `parent_style.EffectiveTouchAction()` 为 `TouchAction::kAuto`
    * `element` 指向一个 `<div>` 元素，其 CSS 样式设置了 `touch-action: pan-x;`
    * `builder.GetTouchAction()` 返回 `TouchAction::kPanX`
* **输出（通过 `builder.SetEffectiveTouchAction` 设置）：** `TouchAction::kPanX` (因为子元素的 touch-action 会与父元素的交集)

* **假设输入：**
    * `parent_style.EffectiveTouchAction()` 为 `TouchAction::kManipulation`
    * `element` 指向一个 `<div>` 元素，其 CSS 样式设置了 `touch-action: pan-x;`
    * `builder.GetTouchAction()` 返回 `TouchAction::kPanX`
* **输出：** `TouchAction::kNone` (因为 `kManipulation` 不包含 `kPanX`)

**用户或编程常见的使用错误：**

1. **HTML 结构错误导致 `IsEditableElement` 误判：** 例如，如果开发者错误地将输入框放在了禁用的父元素内，即使输入框自身没有禁用，`IsDisabledOrReadOnly()` 可能会返回 `true`。

2. **CSS `touch-action` 属性设置不当：**  开发者可能错误地设置了 `touch-action: none;` 导致元素无法滚动或进行其他触摸操作，但期望用户能够进行这些操作。调试时，可以通过查看元素的 computed style 中的 `touch-action` 值来排查。

3. **滥用 `inert` 属性：**  开发者可能无意中给某个父元素设置了 `inert` 属性，导致其内部的交互元素都失效。用户可能会抱怨某些按钮或链接无法点击。调试时，需要检查元素的 `isHTMLInert` 属性。

4. **强制颜色模式下的样式问题：** 开发者可能没有考虑到强制颜色模式，导致在开启该模式时，网站的颜色和样式变得非常糟糕，因为某些样式被强制重置了。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户加载网页：** 当用户在浏览器中输入网址或点击链接加载网页时，Blink 渲染引擎开始解析 HTML、CSS 和 JavaScript。

2. **样式计算阶段：**  在渲染过程中的样式计算阶段，Blink 会构建 DOM 树和 CSSOM 树，然后根据 CSS 选择器和继承规则计算每个元素的样式。

3. **`StyleResolver::Compute*` 函数调用：**  在样式计算过程中，会调用 `StyleResolver::Compute` 或类似的函数来计算元素的样式。

4. **`StyleAdjuster::AdjustComputedStyle` 调用：**  在计算出初步的样式后，`StyleAdjuster::AdjustComputedStyle` 函数会被调用，对初步的样式进行各种调整和修正，以处理特殊情况和浏览器策略。

5. **用户交互触发重绘/重排：**  当用户与网页进行交互（例如点击、滚动、输入文本）或者 JavaScript 修改了 DOM 结构或样式时，可能会触发浏览器的重绘或重排。

6. **重新进行样式计算：**  在重绘或重排过程中，受影响的元素会重新进行样式计算，再次调用 `StyleAdjuster::AdjustComputedStyle` 来确保样式的正确性。

**调试线索：**

* **断点调试：** 可以在 `StyleAdjuster::AdjustComputedStyle` 函数内部设置断点，观察特定元素在样式计算过程中的属性变化。
* **Computed Style 查看器：** 使用浏览器开发者工具的 "Elements" 面板，查看元素的 "Computed" 样式，可以了解最终应用到元素上的样式值，并能看到哪些属性被 `StyleAdjuster` 调整过。
* **搜索相关代码：**  根据具体的样式问题，可以在 Blink 源代码中搜索相关的 CSS 属性或函数名，例如搜索 `touch-action` 可以找到 `AdjustEffectiveTouchAction` 函数。
* **UseCounter 和 WebFeature：** 代码中使用了 `UseCounter` 来统计某些特性的使用情况，这可以帮助理解哪些代码路径被执行。

总而言之，`style_adjuster.cc` 中的这段代码是 Blink 渲染引擎中样式计算的关键组成部分，负责对元素的最终样式进行精细的调整，确保在各种场景下样式的正确性和一致性，并处理了诸如可编辑性、触摸交互、辅助功能等重要特性。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_adjuster.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
nt>(*element)) {
    return !textarea->IsDisabledOrReadOnly();
  }

  if (auto* input = DynamicTo<HTMLInputElement>(*element)) {
    return !input->IsDisabledOrReadOnly() && input->IsTextField();
  }

  return false;
}

bool StyleAdjuster::IsPasswordFieldWithUnrevealedPassword(Element* element) {
  if (!element) {
    return false;
  }
  if (auto* input = DynamicTo<HTMLInputElement>(element)) {
    return input->FormControlType() == FormControlType::kInputPassword &&
           !input->ShouldRevealPassword();
  }
  return false;
}

void StyleAdjuster::AdjustEffectiveTouchAction(
    ComputedStyleBuilder& builder,
    const ComputedStyle& parent_style,
    Element* element,
    bool is_svg_root) {
  TouchAction inherited_action = parent_style.EffectiveTouchAction();

  if (!element) {
    builder.SetEffectiveTouchAction(TouchAction::kAuto & inherited_action);
    return;
  }

  bool is_replaced_canvas = IsA<HTMLCanvasElement>(element) &&
                            element->GetExecutionContext() &&
                            element->GetExecutionContext()->CanExecuteScripts(
                                kNotAboutToExecuteScript);
  bool is_non_replaced_inline_elements =
      builder.IsDisplayInlineType() &&
      !(builder.IsDisplayReplacedType() || is_svg_root ||
        IsA<HTMLImageElement>(element) || is_replaced_canvas);
  bool is_table_row_or_column = builder.IsDisplayTableRowOrColumnType();
  bool is_layout_object_needed =
      element->LayoutObjectIsNeeded(builder.GetDisplayStyle());

  TouchAction element_touch_action = TouchAction::kAuto;
  // Touch actions are only supported by elements that support both the CSS
  // width and height properties.
  // See https://www.w3.org/TR/pointerevents/#the-touch-action-css-property.
  if (!is_non_replaced_inline_elements && !is_table_row_or_column &&
      is_layout_object_needed) {
    element_touch_action = builder.GetTouchAction();
    // kInternalPanXScrolls is only for internal usage, GetTouchAction()
    // doesn't contain this bit. We set this bit when kPanX is set so it can be
    // cleared for eligible editable areas later on.
    if ((element_touch_action & TouchAction::kPanX) != TouchAction::kNone) {
      element_touch_action |= TouchAction::kInternalPanXScrolls;
    }

    // kInternalNotWritable is only for internal usage, GetTouchAction()
    // doesn't contain this bit. We set this bit when kPan is set so it can be
    // cleared for eligible non-password editable areas later on.
    if ((element_touch_action & TouchAction::kPan) != TouchAction::kNone) {
      element_touch_action |= TouchAction::kInternalNotWritable;
    }
  }

  bool is_child_document = element == element->GetDocument().documentElement();

  // Apply touch action inherited from parent frame.
  if (is_child_document && element->GetDocument().GetFrame()) {
    inherited_action &=
        TouchAction::kPan | TouchAction::kInternalPanXScrolls |
        TouchAction::kInternalNotWritable |
        element->GetDocument().GetFrame()->InheritedEffectiveTouchAction();
  }

  // The effective touch action is the intersection of the touch-action values
  // of the current element and all of its ancestors up to the one that
  // implements the gesture. Since panning is implemented by the scroller it is
  // re-enabled for scrolling elements.
  // The panning-restricted cancellation should also apply to iframes, so we
  // allow (panning & local touch action) on the first descendant element of a
  // iframe element.
  inherited_action = AdjustTouchActionForElement(inherited_action, builder,
                                                 parent_style, element);

  TouchAction enforced_by_policy = TouchAction::kNone;
  if (element->GetDocument().IsVerticalScrollEnforced()) {
    enforced_by_policy = TouchAction::kPanY;
  }
  if (::features::IsSwipeToMoveCursorEnabled() &&
      IsEditableElement(element, builder)) {
    element_touch_action &= ~TouchAction::kInternalPanXScrolls;
  }

  // TODO(crbug.com/1346169): Full style invalidation is needed when this
  // feature status changes at runtime as it affects the computed style.
  if (RuntimeEnabledFeatures::StylusHandwritingEnabled() &&
      (element_touch_action & TouchAction::kPan) == TouchAction::kPan &&
      IsEditableElement(element, builder) &&
      !IsPasswordFieldWithUnrevealedPassword(element)) {
    element_touch_action &= ~TouchAction::kInternalNotWritable;
  }

  // Apply the adjusted parent effective touch actions.
  builder.SetEffectiveTouchAction((element_touch_action & inherited_action) |
                                  enforced_by_policy);

  // Propagate touch action to child frames.
  if (auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(element)) {
    Frame* content_frame = frame_owner->ContentFrame();
    if (content_frame) {
      content_frame->SetInheritedEffectiveTouchAction(
          builder.EffectiveTouchAction());
    }
  }
}

static void AdjustStyleForInert(ComputedStyleBuilder& builder,
                                Element* element) {
  if (!element) {
    return;
  }

  Document& document = element->GetDocument();
  if (element->IsInertRoot()) {
    UseCounter::Count(document, WebFeature::kInertAttribute);
    builder.SetIsHTMLInert(true);
    builder.SetIsHTMLInertIsInherited(false);
    return;
  }

  const Element* modal_element = document.ActiveModalDialog();
  if (!modal_element) {
    modal_element = Fullscreen::FullscreenElementFrom(document);
  }
  if (modal_element == element) {
    builder.SetIsHTMLInert(false);
    builder.SetIsHTMLInertIsInherited(false);
    return;
  }
  if (modal_element && element == document.documentElement()) {
    builder.SetIsHTMLInert(true);
    builder.SetIsHTMLInertIsInherited(false);
    return;
  }

  if (StyleBaseData* base_data = builder.BaseData()) {
    if (base_data->GetBaseComputedStyle()->Display() == EDisplay::kNone) {
      // Elements which are transitioning to display:none should become inert:
      // https://github.com/w3c/csswg-drafts/issues/8389
      builder.SetIsHTMLInert(true);
      builder.SetIsHTMLInertIsInherited(false);
      return;
    }
  }
}

void StyleAdjuster::AdjustForForcedColorsMode(ComputedStyleBuilder& builder,
                                              Document& document) {
  if (!builder.InForcedColorsMode() ||
      builder.ForcedColorAdjust() != EForcedColorAdjust::kAuto) {
    return;
  }

  builder.SetTextShadow(ComputedStyleInitialValues::InitialTextShadow());
  builder.SetBoxShadow(ComputedStyleInitialValues::InitialBoxShadow());
  builder.SetColorScheme({AtomicString("light"), AtomicString("dark")});
  builder.SetScrollbarColor(
      ComputedStyleInitialValues::InitialScrollbarColor());
  if (builder.ShouldForceColor(builder.AccentColor())) {
    builder.SetAccentColor(ComputedStyleInitialValues::InitialAccentColor());
  }
  if (!builder.HasUrlBackgroundImage()) {
    builder.ClearBackgroundImage();
  }

  mojom::blink::ColorScheme color_scheme = mojom::blink::ColorScheme::kLight;
  if (document.GetStyleEngine().GetPreferredColorScheme() ==
      mojom::blink::PreferredColorScheme::kDark) {
    color_scheme = mojom::blink::ColorScheme::kDark;
  }
  const ui::ColorProvider* color_provider =
      document.GetColorProviderForPainting(color_scheme);
  auto is_in_web_app_scope = document.IsInWebAppScope();

  // Re-resolve some internal forced color properties whose initial
  // values are system colors. This is necessary to ensure we get
  // the correct computed value from the color provider for the
  // system color when the theme changes.
  if (builder.InternalForcedBackgroundColor().IsSystemColor()) {
    builder.SetInternalForcedBackgroundColor(
        builder.InternalForcedBackgroundColor().ResolveSystemColor(
            color_scheme, color_provider, is_in_web_app_scope));
  }
  if (builder.InternalForcedColor().IsSystemColor()) {
    builder.SetInternalForcedColor(
        builder.InternalForcedColor().ResolveSystemColor(
            color_scheme, color_provider, is_in_web_app_scope));
  }
  if (builder.InternalForcedVisitedColor().IsSystemColor()) {
    builder.SetInternalForcedVisitedColor(
        builder.InternalForcedVisitedColor().ResolveSystemColor(
            color_scheme, color_provider, is_in_web_app_scope));
  }
}

void StyleAdjuster::AdjustForSVGTextElement(ComputedStyleBuilder& builder) {
  builder.SetColumnGap(ComputedStyleInitialValues::InitialColumnGap());
  builder.SetColumnWidthInternal(
      ComputedStyleInitialValues::InitialColumnWidth());
  builder.SetColumnRuleStyle(
      ComputedStyleInitialValues::InitialColumnRuleStyle());
  builder.SetColumnRuleWidthInternal(
      ComputedStyleInitialValues::InitialColumnRuleWidth());
  builder.SetColumnRuleColor(
      ComputedStyleInitialValues::InitialColumnRuleColor());
  builder.SetInternalVisitedColumnRuleColor(
      ComputedStyleInitialValues::InitialInternalVisitedColumnRuleColor());
  builder.SetColumnCountInternal(
      ComputedStyleInitialValues::InitialColumnCount());
  builder.SetHasAutoColumnCountInternal(
      ComputedStyleInitialValues::InitialHasAutoColumnCount());
  builder.SetHasAutoColumnWidthInternal(
      ComputedStyleInitialValues::InitialHasAutoColumnWidth());
  builder.ResetColumnFill();
  builder.ResetColumnSpan();
}

void StyleAdjuster::AdjustComputedStyle(StyleResolverState& state,
                                        Element* element) {
  DCHECK(state.LayoutParentStyle());
  DCHECK(state.ParentStyle());
  ComputedStyleBuilder& builder = state.StyleBuilder();
  const ComputedStyle& parent_style = *state.ParentStyle();
  const ComputedStyle& layout_parent_style = *state.LayoutParentStyle();

  auto* html_element = DynamicTo<HTMLElement>(element);
  if (html_element &&
      (builder.Display() != EDisplay::kNone ||
       element->LayoutObjectIsNeeded(builder.GetDisplayStyle()))) {
    AdjustStyleForHTMLElement(builder, *html_element);
  }

  if (builder.Display() != EDisplay::kNone) {
    bool is_document_element =
        element && element->GetDocument().documentElement() == element;
    // https://drafts.csswg.org/css-position-4/#top-styling
    // Elements in the top layer must be out-of-flow positioned.
    // Root elements that are in the top layer should just be left alone
    // because the fullscreen.css doesn't apply any style to them.
    if ((builder.Overlay() == EOverlay::kAuto && !is_document_element) ||
        builder.StyleType() == kPseudoIdBackdrop) {
      if (!builder.HasOutOfFlowPosition()) {
        builder.SetPosition(EPosition::kAbsolute);
      }
      if (builder.Display() == EDisplay::kContents) {
        // See crbug.com/1240701 for more details.
        // https://fullscreen.spec.whatwg.org/#new-stacking-layer
        // If its specified display property is contents, it computes to block.
        builder.SetDisplay(EDisplay::kBlock);
      }
    }

    // Absolute/fixed positioned elements, floating elements and the document
    // element need block-like outside display.
    if (is_document_element ||
        (builder.Display() != EDisplay::kContents &&
         (builder.HasOutOfFlowPosition() || builder.IsFloating()))) {
      builder.SetDisplay(EquivalentBlockDisplay(builder.Display()));
    }

    // math display values on non-MathML elements compute to flow display
    // values.
    if (!IsA<MathMLElement>(element) && builder.IsDisplayMathType()) {
      builder.SetDisplay(builder.Display() == EDisplay::kBlockMath
                             ? EDisplay::kBlock
                             : EDisplay::kInline);
    }

    // We don't adjust the first letter style earlier because we may change the
    // display setting in AdjustStyleForHTMLElement() above.
    AdjustStyleForFirstLetter(builder);
    AdjustStyleForMarker(builder, parent_style, &state.GetElement());

    if (builder.StyleType() != kPseudoIdScrollMarker) {
      AdjustStyleForDisplay(builder, layout_parent_style, element,
                            element ? &element->GetDocument() : nullptr);
    }

    // If this is a child of a LayoutCustom, we need the name of the parent
    // layout function for invalidation purposes.
    if (layout_parent_style.IsDisplayLayoutCustomBox()) {
      builder.SetDisplayLayoutCustomParentName(
          layout_parent_style.DisplayLayoutCustomName());
    }

    bool is_in_main_frame = element && element->GetDocument().IsInMainFrame();
    // The root element of the main frame has no backdrop, so don't allow
    // it to have a backdrop filter either.
    if (is_document_element && is_in_main_frame &&
        builder.HasBackdropFilter()) {
      builder.SetBackdropFilter(FilterOperations());
    }
  } else {
    AdjustStyleForFirstLetter(builder);
  }

  builder.SetForcesStackingContext(false);

  // Make sure our z-index value is only applied if the object is positioned.
  if (!builder.HasAutoZIndex()) {
    if (builder.GetPosition() == EPosition::kStatic &&
        !LayoutParentStyleForcesZIndexToCreateStackingContext(
            layout_parent_style)) {
      builder.SetEffectiveZIndexZero(true);
    } else {
      builder.SetForcesStackingContext(true);
    }
  }

  if (element == state.GetDocument().documentElement() ||
      (element && IsA<SVGForeignObjectElement>(*element)) ||
      builder.Overlay() == EOverlay::kAuto ||
      builder.StyleType() == kPseudoIdBackdrop ||
      builder.StyleType() == kPseudoIdViewTransition ||
      IsCanvasPlacedElement(element)) {
    builder.SetForcesStackingContext(true);
  }

  if (builder.OverflowX() != EOverflow::kVisible ||
      builder.OverflowY() != EOverflow::kVisible) {
    AdjustOverflow(builder, element ? element : state.GetPseudoElement());
  }

  // Highlight pseudos propagate decorations with inheritance only.
  if (StopPropagateTextDecorations(builder, element) ||
      state.IsForHighlight()) {
    builder.SetBaseTextDecorationData(nullptr);
  } else {
    builder.SetBaseTextDecorationData(
        layout_parent_style.AppliedTextDecorationData());
  }

  // The computed value of currentColor for highlight pseudos is the
  // color that would have been used if no highlights were applied,
  // i.e. the originating element's color.
  if (state.UsesHighlightPseudoInheritance() &&
      state.OriginatingElementStyle()) {
    const ComputedStyle* originating_style = state.OriginatingElementStyle();
    if (builder.ColorIsCurrentColor()) {
      builder.SetColor(originating_style->Color());
    }
    if (builder.InternalVisitedColorIsCurrentColor()) {
      builder.SetInternalVisitedColor(
          originating_style->InternalVisitedColor());
    }
  }

  // Cull out any useless layers and also repeat patterns into additional
  // layers.
  builder.AdjustBackgroundLayers();
  builder.AdjustMaskLayers();

  // A subset of CSS properties should be forced at computed value time:
  // https://drafts.csswg.org/css-color-adjust-1/#forced-colors-properties.
  AdjustForForcedColorsMode(builder, state.GetDocument());

  // Let the theme also have a crack at adjusting the style.
  LayoutTheme::GetTheme().AdjustStyle(element, builder);

  AdjustStyleForInert(builder, element);

  AdjustStyleForEditing(builder, element);

  if (auto* svg_element = DynamicTo<SVGElement>(element); svg_element) {
    AdjustStyleForSvgElement(*svg_element, builder, layout_parent_style);
  } else if (IsA<MathMLElement>(element)) {
    if (builder.Display() == EDisplay::kContents) {
      // https://drafts.csswg.org/css-display/#unbox-mathml
      builder.SetDisplay(EDisplay::kNone);
    }
  }

  // If this node is sticky it marks the creation of a sticky subtree, which we
  // must track to properly handle document lifecycle in some cases.
  //
  // It is possible that this node is already in a sticky subtree (i.e. we have
  // nested sticky nodes) - in that case the bit will already be set via
  // inheritance from the ancestor and there is no harm to setting it again.
  if (builder.GetPosition() == EPosition::kSticky) {
    builder.SetSubtreeIsSticky(true);
  }

  // If the inherited value of justify-items includes the 'legacy'
  // keyword (plus 'left', 'right' or 'center'), 'legacy' computes to
  // the the inherited value.  Otherwise, 'auto' computes to 'normal'.
  if (parent_style.JustifyItems().PositionType() == ItemPositionType::kLegacy &&
      builder.JustifyItems().GetPosition() == ItemPosition::kLegacy) {
    builder.SetJustifyItems(parent_style.JustifyItems());
  }

  AdjustEffectiveTouchAction(builder, parent_style, element,
                             IsOutermostSVGElement(element));

  bool is_media_control =
      element && element->ShadowPseudoId().StartsWith("-webkit-media-controls");
  if (is_media_control && !builder.HasEffectiveAppearance()) {
    // For compatibility reasons if the element is a media control and the
    // -webkit-appearance is none then we should clear the background image.
    builder.MutableBackgroundInternal().ClearImage();
  }

  if (element && builder.TextOverflow() == ETextOverflow::kEllipsis) {
    const AtomicString& pseudo_id = element->ShadowPseudoId();
    if (pseudo_id == shadow_element_names::kPseudoInputPlaceholder ||
        pseudo_id == shadow_element_names::kPseudoInternalInputSuggested) {
      TextControlElement* text_control =
          ToTextControl(element->OwnerShadowHost());
      DCHECK(text_control);
      // TODO(futhark@chromium.org): We force clipping text overflow for focused
      // input elements since we don't want to render ellipsis during editing.
      // We should do this as a general solution which also includes
      // contenteditable elements being edited. The computed style should not
      // change, but LayoutBlockFlow::ShouldTruncateOverflowingText() should
      // instead return false when text is being edited inside that block.
      // https://crbug.com/814954
      builder.SetTextOverflow(text_control->ValueForTextOverflow());
    }
  }

  if (element && element->HasCustomStyleCallbacks()) {
    element->AdjustStyle(base::PassKey<StyleAdjuster>(), builder);
  }

  // We need to use styled element here to ensure coverage for pseudo-elements.
  if (state.GetStyledElement() &&
      ViewTransitionUtils::IsViewTransitionElementExcludingRootFromSupplement(
          *state.GetStyledElement())) {
    builder.SetElementIsViewTransitionParticipant();
  }

  if (RuntimeEnabledFeatures::
          CSSContentVisibilityImpliesContainIntrinsicSizeAutoEnabled() &&
      builder.ContentVisibility() == EContentVisibility::kAuto) {
    builder.SetContainIntrinsicSizeAuto();
  }
}

}  // namespace blink
```