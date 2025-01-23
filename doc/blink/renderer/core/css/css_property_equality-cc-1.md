Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine. This is the second part of a two-part file. The code is about comparing CSS property values for equality.

Here's a plan to address the user's request:

1. **Summarize the overall purpose of the code:**  It defines how to check if two CSS property values are equal.
2. **Relate to JavaScript, HTML, and CSS:** Explain how this code is used in the context of web development. Specifically, how CSS properties defined in CSS stylesheets or through JavaScript are compared internally by the browser.
3. **Provide input/output examples:** Show how different CSS property values would be evaluated for equality.
4. **Illustrate potential user errors:**  Highlight situations where incorrect CSS might lead to unexpected comparison results.
5. **Explain user actions leading to this code execution:** Describe how user interactions on a webpage might trigger the need to compare CSS properties.
6. **Focus on the specific code provided in Part 2:**  Since this is part 2, summarize the specific CSS properties handled in this section of the code.
7. **Combine the insights from both parts:** Since this is the second part, provide a consolidated summary of the overall file's function, considering the likely content of part 1 (which would handle other CSS properties).
好的，这是文件 `blink/renderer/core/css/css_property_equality.cc` 的第二部分代码，它延续了第一部分的功能，即**定义了如何判断两个 CSS 属性值是否相等**。

**归纳其功能：**

这部分代码针对一系列特定的 CSS 属性 ID，提供了用于比较两个 `ComputedStyle` 对象中对应属性值是否相等的具体实现。  对于每个 `case` 分支，它会根据当前的 `CSSPropertyID`，提取出两个 `ComputedStyle` 对象 (`a` 和 `b`) 中该属性的值，并使用相应的比较运算符或辅助函数进行比较，最终返回一个布尔值 (`true` 表示相等，`false` 表示不相等)。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件是浏览器引擎内部实现的一部分，它不直接与 JavaScript, HTML, 或 CSS 代码交互。然而，它的功能是支撑这些 Web 技术正常运行的关键。

* **CSS:**  此代码直接处理 CSS 属性。例如，当 CSS 样式规则被应用到一个 HTML 元素上时，浏览器需要存储和比较这些属性的值。 这个文件中的代码定义了如何比较不同的 CSS 属性值，例如 `color`, `width`, `font-size` 等。

    * **例子:** 假设你在 CSS 中定义了两个规则：
        ```css
        .element1 {
          color: blue;
          width: 100px;
        }
        .element2 {
          color: blue;
          width: 100px;
        }
        ```
        当浏览器计算这两个元素的样式时，`css_property_equality.cc` 中的代码会被调用来判断它们的 `color` 属性和 `width` 属性是否相等。对于 `color` 属性，会比较 `a.Color()` 和 `b.Color()` 的值（可能对应于颜色值的内部表示）。对于 `width` 属性，会比较 `a.Width()` 和 `b.Width()` 的值（可能对应于长度值的内部表示）。

* **JavaScript:** JavaScript 可以动态地修改元素的 CSS 样式。当 JavaScript 代码修改样式后，浏览器可能需要判断新的样式是否与之前的样式相同，或者与另一个元素的样式相同。

    * **例子:**  考虑以下 JavaScript 代码：
        ```javascript
        const element = document.getElementById('myElement');
        const initialColor = element.style.color;
        element.style.color = 'red';
        const newColor = element.style.color;

        // 浏览器内部可能会使用类似的功能来判断 initialColor 和 newColor 是否相同。
        ```
        虽然 JavaScript 直接操作的是字符串形式的 CSS 属性值，但浏览器在内部处理时，会将其转换为内部表示，并可能使用 `css_property_equality.cc` 中的逻辑来比较这些值。

* **HTML:** HTML 结构决定了 CSS 规则的应用对象。当浏览器解析 HTML 并应用 CSS 时，需要确定哪些样式规则适用于哪些元素。这个过程可能涉及到比较不同规则中 CSS 属性的优先级和特异性，虽然 `css_property_equality.cc` 不直接参与优先级计算，但它为最终确定属性值是否一致提供了基础。

**逻辑推理、假设输入与输出：**

假设我们正在比较两个 `ComputedStyle` 对象 `styleA` 和 `styleB` 的 `text-indent` 属性。

* **假设输入:**
    * `styleA.TextIndent()` 返回表示 `20px` 的内部值。
    * `styleB.TextIndent()` 返回表示 `20px` 的内部值。

* **代码执行:**  `case CSSPropertyID::kTextIndent:` 分支会被执行，然后会执行 `return a.TextIndent() == b.TextIndent();`

* **输出:** `true` (因为两个 `TextIndent` 的值相等)。

再假设我们比较 `text-overflow` 属性：

* **假设输入:**
    * `styleA.TextOverflow()` 返回 `TextOverflow::kEllipsis`。
    * `styleB.TextOverflow()` 返回 `TextOverflow::kClip`。

* **代码执行:** `case CSSPropertyID::kTextOverflow:` 分支会被执行，然后会执行 `return a.TextOverflow() == b.TextOverflow();`

* **输出:** `false` (因为 `TextOverflow::kEllipsis` 不等于 `TextOverflow::kClip`)。

**用户或编程常见的使用错误举例：**

虽然用户不直接操作这个 C++ 文件，但用户编写的 CSS 或 JavaScript 代码中的错误可能会导致意外的比较结果，进而影响页面的渲染和行为。

* **拼写错误或无效的 CSS 值:** 如果 CSS 中某个属性的值拼写错误或者不是有效的 CSS 值，浏览器可能无法正确解析，导致比较时结果不符合预期。

    * **例子:**  用户在 CSS 中写了 `colr: bule;` 而不是 `color: blue;`，浏览器可能忽略这个属性，导致在比较 `color` 属性时，会使用默认值，而不是用户期望的值。

* **JavaScript 类型错误:** 在 JavaScript 中修改样式时，如果使用了错误的类型，也可能导致问题。

    * **例子:**  用户尝试设置元素的 `width` 为字符串 `"100"` 而不是数字或带单位的字符串 `"100px"`，浏览器在处理时可能会有不同的行为，最终影响比较结果。

* **单位不一致:**  即使数值相同，但单位不同，CSS 属性值通常也被认为是不同的。

    * **例子:**  一个元素的 `width` 是 `100px`，另一个元素的 `width` 是 `100em`，虽然数值都是 100，但单位不同，比较结果为不相等。

**用户操作如何一步步到达这里（作为调试线索）：**

这个文件在浏览器引擎的样式计算和渲染流程中被使用。以下是一些可能导致执行到这段代码的用户操作：

1. **加载网页:** 当用户在浏览器中打开一个网页时，浏览器会解析 HTML 和 CSS。
2. **样式计算:** 浏览器会根据 CSS 规则和 HTML 结构计算每个元素的最终样式 (`ComputedStyle`)。在这个过程中，可能需要比较不同样式规则中相同属性的值来确定最终应用的样式。
3. **动态样式修改:** 用户与网页交互，例如鼠标悬停、点击等，可能会触发 JavaScript 代码来修改元素的样式。
4. **CSS 动画和过渡:**  当 CSS 动画或过渡发生时，浏览器需要在动画的每一帧或过渡的不同阶段计算元素的样式，这涉及到比较起始和结束状态的属性值，以及中间状态的属性值。
5. **开发者工具检查元素:** 当用户在开发者工具中检查元素的样式时，浏览器可能需要比较元素的当前样式与之前的样式，或者与其他元素的样式，以便高亮显示应用的样式规则。
6. **性能分析:**  开发者进行性能分析时，浏览器可能会记录样式的变化和重新计算，这也会涉及到属性值的比较。

**总结 Part 2 的功能:**

这部分代码具体负责比较以下 CSS 属性的值是否相等：

* 文本相关：`text-indent`, `text-overflow`, `text-rendering`, `text-shadow`, `text-size-adjust`, `text-spacing-trim`, `text-transform`, `text-underline-offset`, `text-underline-position`, `text-wrap-mode`, `text-wrap-style`
* 定位相关：`top`, `overlay`
* 交互相关：`touch-action`, `user-select`
* 变形和视觉效果：`transform-box`, `transform-style`, `vector-effect`, `visibility`, `clip-path`, `filter`, `backdrop-filter`, `perspective`, `perspective-origin`, `transform`, `translate`, `rotate`, `scale`
* 垂直对齐：`vertical-align`
* 视口过渡：`view-transition-class`, `view-transition-group`, `view-transition-name`, `view-transition-capture-mode`
* 表格和列布局：`webkit-border-horizontal-spacing`, `webkit-border-vertical-spacing`, `column-count`, `column-gap`, `row-gap`, `column-rule-color`, `column-rule-width`, `column-width`
* 字体相关：`webkit-font-smoothing`, `webkit-locale`
* 遮罩：`webkit-mask-box-image-outset`, `webkit-mask-box-image-slice`, `webkit-mask-box-image-source`, `webkit-mask-box-image-width`, `mask-clip`, `mask-composite`, `mask-image`, `mask-origin`, `mask-mode`, `webkit-mask-position-x`, `webkit-mask-position-y`, `mask-repeat`, `mask-size`
* 文本装饰：`webkit-text-fill-color`, `webkit-text-orientation`, `webkit-text-stroke-color`, `webkit-text-stroke-width`
* 尺寸和坐标：`size`, `transform-origin`, `webkit-perspective-origin-x`, `webkit-perspective-origin-y`, `webkit-transform-origin-x`, `webkit-transform-origin-y`, `webkit-transform-origin-z`, `width`, `cx`, `cy`, `x`, `y`, `r`, `rx`, `ry`
* 其他：`white-space-collapse`, `widows`, `word-break`, `word-spacing`, `d`, `z-index`, `contain-intrinsic-width`, `contain-intrinsic-height`, `aspect-ratio`, `math-depth`, `accent-color`, `text-emphasis-color`, `zoom`, `position-try-order`, `position-try-fallbacks`, `position-visibility`

此外，代码还处理了一些带有 `-webkit-` 前缀的属性，以及一些不应该直接比较的属性（例如，简写属性、内部属性、非动画属性等），并通过 `NOTREACHED()` 宏来标记这些不应该被执行到的情况，以帮助开发者发现潜在的错误。

**结合 Part 1 和 Part 2 的总结:**

整个 `css_property_equality.cc` 文件的核心功能是为 Blink 渲染引擎提供了一个详细的、针对各种 CSS 属性的相等性比较机制。它通过一个大的 `switch` 语句，针对不同的 `CSSPropertyID` 执行特定的比较逻辑。这个文件对于浏览器的样式计算、动画和过渡效果的实现至关重要，确保了在各种场景下，CSS 属性值能够被准确地比较和处理。 虽然开发者通常不直接接触这个文件，但其背后的逻辑直接影响着网页的渲染结果和用户体验。

### 提示词
```
这是目录为blink/renderer/core/css/css_property_equality.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
dent:
      return a.TextIndent() == b.TextIndent();
    case CSSPropertyID::kTextOverflow:
      return a.TextOverflow() == b.TextOverflow();
    case CSSPropertyID::kTextRendering:
      return a.GetFontDescription().TextRendering() ==
             b.GetFontDescription().TextRendering();
    case CSSPropertyID::kTextShadow:
      return base::ValuesEquivalent(a.TextShadow(), b.TextShadow());
    case CSSPropertyID::kTextSizeAdjust:
      return a.GetTextSizeAdjust() == b.GetTextSizeAdjust();
    case CSSPropertyID::kTextSpacingTrim:
      return a.GetFontDescription().GetTextSpacingTrim() ==
             b.GetFontDescription().GetTextSpacingTrim();
    case CSSPropertyID::kTextTransform:
      return a.TextTransform() == b.TextTransform();
    case CSSPropertyID::kTextUnderlineOffset:
      return a.TextUnderlineOffset() == b.TextUnderlineOffset();
    case CSSPropertyID::kTextUnderlinePosition:
      return a.GetTextUnderlinePosition() == b.GetTextUnderlinePosition();
    case CSSPropertyID::kTextWrapMode:
      return a.GetTextWrapMode() == b.GetTextWrapMode();
    case CSSPropertyID::kTextWrapStyle:
      return a.GetTextWrapStyle() == b.GetTextWrapStyle();
    case CSSPropertyID::kTop:
      return a.Top() == b.Top();
    case CSSPropertyID::kOverlay:
      return a.Overlay() == b.Overlay();
    case CSSPropertyID::kTouchAction:
      return a.GetTouchAction() == b.GetTouchAction();
    case CSSPropertyID::kTransformBox:
      return a.TransformBox() == b.TransformBox();
    case CSSPropertyID::kTransformStyle:
      return a.TransformStyle3D() == b.TransformStyle3D();
    case CSSPropertyID::kUserSelect:
      return a.UserSelect() == b.UserSelect();
    case CSSPropertyID::kVectorEffect:
      return a.VectorEffect() == b.VectorEffect();
    case CSSPropertyID::kVerticalAlign:
      return a.VerticalAlign() == b.VerticalAlign() &&
             (a.VerticalAlign() != EVerticalAlign::kLength ||
              a.GetVerticalAlignLength() == b.GetVerticalAlignLength());
    case CSSPropertyID::kViewTransitionClass:
      return a.ViewTransitionClass() == b.ViewTransitionClass();
    case CSSPropertyID::kViewTransitionGroup:
      return a.ViewTransitionGroup() == b.ViewTransitionGroup();
    case CSSPropertyID::kViewTransitionName:
      return a.ViewTransitionName() == b.ViewTransitionName();
    case CSSPropertyID::kViewTransitionCaptureMode:
      return a.ViewTransitionCaptureMode() == b.ViewTransitionCaptureMode();
    case CSSPropertyID::kVisibility:
      return a.Visibility() == b.Visibility();
    case CSSPropertyID::kWebkitBorderHorizontalSpacing:
      return a.HorizontalBorderSpacing() == b.HorizontalBorderSpacing();
    case CSSPropertyID::kWebkitBorderVerticalSpacing:
      return a.VerticalBorderSpacing() == b.VerticalBorderSpacing();
    case CSSPropertyID::kClipPath:
      return base::ValuesEquivalent(a.ClipPath(), b.ClipPath());
    case CSSPropertyID::kColumnCount:
      return a.ColumnCount() == b.ColumnCount();
    case CSSPropertyID::kColumnGap:
      return a.ColumnGap() == b.ColumnGap();
    case CSSPropertyID::kRowGap:
      return a.RowGap() == b.RowGap();
    case CSSPropertyID::kColumnRuleColor:
      return a.ColumnRuleColor() == b.ColumnRuleColor() &&
             a.InternalVisitedColumnRuleColor() ==
                 b.InternalVisitedColumnRuleColor();
    case CSSPropertyID::kColumnRuleWidth:
      return a.ColumnRuleWidth() == b.ColumnRuleWidth();
    case CSSPropertyID::kColumnWidth:
      return a.ColumnWidth() == b.ColumnWidth();
    case CSSPropertyID::kFilter:
      return a.Filter() == b.Filter();
    case CSSPropertyID::kBackdropFilter:
      return a.BackdropFilter() == b.BackdropFilter();
    case CSSPropertyID::kWebkitFontSmoothing:
      return a.GetFontDescription().FontSmoothing() ==
             b.GetFontDescription().FontSmoothing();
    case CSSPropertyID::kWebkitLineClamp:
      return a.WebkitLineClamp() == b.WebkitLineClamp();
    case CSSPropertyID::kWebkitLocale:
      return a.Locale() == b.Locale();
    case CSSPropertyID::kWebkitMaskBoxImageOutset:
      return a.MaskBoxImageOutset() == b.MaskBoxImageOutset();
    case CSSPropertyID::kWebkitMaskBoxImageSlice:
      return a.MaskBoxImageSlices() == b.MaskBoxImageSlices();
    case CSSPropertyID::kWebkitMaskBoxImageSource:
      return base::ValuesEquivalent(a.MaskBoxImageSource(),
                                    b.MaskBoxImageSource());
    case CSSPropertyID::kWebkitMaskBoxImageWidth:
      return a.MaskBoxImageWidth() == b.MaskBoxImageWidth();
    case CSSPropertyID::kMaskClip:
      return FillLayersEqual<CSSPropertyID::kMaskClip>(a.MaskLayers(),
                                                       b.MaskLayers());
    case CSSPropertyID::kMaskComposite:
      return FillLayersEqual<CSSPropertyID::kMaskComposite>(a.MaskLayers(),
                                                            b.MaskLayers());
    case CSSPropertyID::kMaskImage:
      return FillLayersEqual<CSSPropertyID::kMaskImage>(a.MaskLayers(),
                                                        b.MaskLayers());
    case CSSPropertyID::kMaskOrigin:
      return FillLayersEqual<CSSPropertyID::kMaskOrigin>(a.MaskLayers(),
                                                         b.MaskLayers());
    case CSSPropertyID::kMaskMode:
      return FillLayersEqual<CSSPropertyID::kMaskMode>(a.MaskLayers(),
                                                       b.MaskLayers());
    case CSSPropertyID::kWebkitMaskPositionX:
      return FillLayersEqual<CSSPropertyID::kWebkitMaskPositionX>(
          a.MaskLayers(), b.MaskLayers());
    case CSSPropertyID::kWebkitMaskPositionY:
      return FillLayersEqual<CSSPropertyID::kWebkitMaskPositionY>(
          a.MaskLayers(), b.MaskLayers());
    case CSSPropertyID::kMaskRepeat:
      return FillLayersEqual<CSSPropertyID::kMaskRepeat>(a.MaskLayers(),
                                                         b.MaskLayers());
    case CSSPropertyID::kMaskSize:
      return FillLayersEqual<CSSPropertyID::kMaskSize>(a.MaskLayers(),
                                                       b.MaskLayers());
    case CSSPropertyID::kWebkitTextFillColor:
      return a.TextFillColor() == b.TextFillColor();
    case CSSPropertyID::kWebkitTextOrientation:
      return a.GetTextOrientation() == b.GetTextOrientation();
    case CSSPropertyID::kPerspective:
      return a.Perspective() == b.Perspective();
    case CSSPropertyID::kPerspectiveOrigin:
      return a.PerspectiveOrigin() == b.PerspectiveOrigin();
    case CSSPropertyID::kWebkitTextStrokeColor:
      return a.TextStrokeColor() == b.TextStrokeColor() &&
             a.InternalVisitedTextStrokeColor() ==
                 b.InternalVisitedTextStrokeColor();
    case CSSPropertyID::kWebkitTextStrokeWidth:
      return a.TextStrokeWidth() == b.TextStrokeWidth();
    case CSSPropertyID::kTransform:
      return a.Transform() == b.Transform();
    case CSSPropertyID::kTranslate:
      return base::ValuesEquivalent<TransformOperation>(a.Translate(),
                                                        b.Translate());
    case CSSPropertyID::kRotate:
      return base::ValuesEquivalent<TransformOperation>(a.Rotate(), b.Rotate());
    case CSSPropertyID::kScale:
      return base::ValuesEquivalent<TransformOperation>(a.Scale(), b.Scale());
    case CSSPropertyID::kSize:
      return a.GetPageSizeType() == b.GetPageSizeType() &&
             a.PageSize() == b.PageSize();
    case CSSPropertyID::kTransformOrigin:
      return a.GetTransformOrigin() == b.GetTransformOrigin();
    case CSSPropertyID::kWebkitPerspectiveOriginX:
      return a.PerspectiveOrigin().X() == b.PerspectiveOrigin().X();
    case CSSPropertyID::kWebkitPerspectiveOriginY:
      return a.PerspectiveOrigin().Y() == b.PerspectiveOrigin().Y();
    case CSSPropertyID::kWebkitTransformOriginX:
      return a.GetTransformOrigin().X() == b.GetTransformOrigin().X();
    case CSSPropertyID::kWebkitTransformOriginY:
      return a.GetTransformOrigin().Y() == b.GetTransformOrigin().Y();
    case CSSPropertyID::kWebkitTransformOriginZ:
      return a.GetTransformOrigin().Z() == b.GetTransformOrigin().Z();
    case CSSPropertyID::kWhiteSpaceCollapse:
      return a.GetWhiteSpaceCollapse() == b.GetWhiteSpaceCollapse();
    case CSSPropertyID::kWidows:
      return a.Widows() == b.Widows();
    case CSSPropertyID::kWidth:
      return a.Width() == b.Width();
    case CSSPropertyID::kWordBreak:
      return a.WordBreak() == b.WordBreak();
    case CSSPropertyID::kWordSpacing:
      return a.WordSpacing() == b.WordSpacing();
    case CSSPropertyID::kD:
      return base::ValuesEquivalent(a.D(), b.D());
    case CSSPropertyID::kCx:
      return a.Cx() == b.Cx();
    case CSSPropertyID::kCy:
      return a.Cy() == b.Cy();
    case CSSPropertyID::kX:
      return a.X() == b.X();
    case CSSPropertyID::kY:
      return a.Y() == b.Y();
    case CSSPropertyID::kR:
      return a.R() == b.R();
    case CSSPropertyID::kRx:
      return a.Rx() == b.Rx();
    case CSSPropertyID::kRy:
      return a.Ry() == b.Ry();
    case CSSPropertyID::kZIndex:
      return a.HasAutoZIndex() == b.HasAutoZIndex() &&
             (a.HasAutoZIndex() || a.ZIndex() == b.ZIndex());
    case CSSPropertyID::kContainIntrinsicWidth:
      return a.ContainIntrinsicWidth() == b.ContainIntrinsicWidth();
    case CSSPropertyID::kContainIntrinsicHeight:
      return a.ContainIntrinsicHeight() == b.ContainIntrinsicHeight();
    case CSSPropertyID::kAspectRatio:
      return a.AspectRatio() == b.AspectRatio();
    case CSSPropertyID::kMathDepth:
      return a.MathDepth() == b.MathDepth();
    case CSSPropertyID::kAccentColor:
      return a.AccentColor() == b.AccentColor();
    case CSSPropertyID::kTextEmphasisColor:
      return a.TextEmphasisColor() == b.TextEmphasisColor();
    case CSSPropertyID::kZoom:
      return a.Zoom() == b.Zoom();
    case CSSPropertyID::kPositionTryOrder:
      return a.PositionTryOrder() == b.PositionTryOrder();
    case CSSPropertyID::kPositionTryFallbacks:
      return base::ValuesEquivalent(a.GetPositionTryFallbacks(),
                                    b.GetPositionTryFallbacks());
    case CSSPropertyID::kPositionVisibility:
      return a.GetPositionVisibility() == b.GetPositionVisibility();

    // These properties are not animateable, but perhaps equality should still
    // be defined for them.
    case CSSPropertyID::kScrollTimelineAxis:
    case CSSPropertyID::kScrollTimelineName:
    case CSSPropertyID::kViewTimelineAxis:
    case CSSPropertyID::kViewTimelineInset:
    case CSSPropertyID::kViewTimelineName:
      NOTREACHED() << property.GetCSSPropertyName().ToAtomicString().Ascii();

    // Webkit Aliases. These should not be reachable since they are converted to
    // their non-aliased counterpart before calling this function.
    case CSSPropertyID::kAliasEpubCaptionSide:
    case CSSPropertyID::kAliasEpubTextCombine:
    case CSSPropertyID::kAliasEpubTextEmphasis:
    case CSSPropertyID::kAliasEpubTextEmphasisColor:
    case CSSPropertyID::kAliasEpubTextEmphasisStyle:
    case CSSPropertyID::kAliasEpubTextOrientation:
    case CSSPropertyID::kAliasEpubTextTransform:
    case CSSPropertyID::kAliasEpubWordBreak:
    case CSSPropertyID::kAliasEpubWritingMode:
    case CSSPropertyID::kAliasWebkitAlignContent:
    case CSSPropertyID::kAliasWebkitAlignItems:
    case CSSPropertyID::kAliasWebkitAlignSelf:
    case CSSPropertyID::kAliasWebkitAlternativeAnimationWithTimeline:
    case CSSPropertyID::kAliasWebkitAnimation:
    case CSSPropertyID::kAliasWebkitAnimationDelay:
    case CSSPropertyID::kAliasWebkitAnimationDirection:
    case CSSPropertyID::kAliasWebkitAnimationDuration:
    case CSSPropertyID::kAliasWebkitAnimationFillMode:
    case CSSPropertyID::kAliasWebkitAnimationIterationCount:
    case CSSPropertyID::kAliasWebkitAnimationName:
    case CSSPropertyID::kAliasWebkitAnimationPlayState:
    case CSSPropertyID::kAliasWebkitAnimationTimingFunction:
    case CSSPropertyID::kAliasWebkitAppRegion:
    case CSSPropertyID::kAliasWebkitAppearance:
    case CSSPropertyID::kAliasWebkitBackfaceVisibility:
    case CSSPropertyID::kAliasWebkitBackgroundClip:
    case CSSPropertyID::kAliasWebkitBackgroundOrigin:
    case CSSPropertyID::kAliasWebkitBackgroundSize:
    case CSSPropertyID::kAliasWebkitBorderAfter:
    case CSSPropertyID::kAliasWebkitBorderAfterColor:
    case CSSPropertyID::kAliasWebkitBorderAfterStyle:
    case CSSPropertyID::kAliasWebkitBorderAfterWidth:
    case CSSPropertyID::kAliasWebkitBorderBefore:
    case CSSPropertyID::kAliasWebkitBorderBeforeColor:
    case CSSPropertyID::kAliasWebkitBorderBeforeStyle:
    case CSSPropertyID::kAliasWebkitBorderBeforeWidth:
    case CSSPropertyID::kAliasWebkitBorderBottomLeftRadius:
    case CSSPropertyID::kAliasWebkitBorderBottomRightRadius:
    case CSSPropertyID::kAliasWebkitBorderEnd:
    case CSSPropertyID::kAliasWebkitBorderEndColor:
    case CSSPropertyID::kAliasWebkitBorderEndStyle:
    case CSSPropertyID::kAliasWebkitBorderEndWidth:
    case CSSPropertyID::kAliasWebkitBorderRadius:
    case CSSPropertyID::kAliasWebkitBorderStart:
    case CSSPropertyID::kAliasWebkitBorderStartColor:
    case CSSPropertyID::kAliasWebkitBorderStartStyle:
    case CSSPropertyID::kAliasWebkitBorderStartWidth:
    case CSSPropertyID::kAliasWebkitBorderTopLeftRadius:
    case CSSPropertyID::kAliasWebkitBorderTopRightRadius:
    case CSSPropertyID::kAliasWebkitBoxShadow:
    case CSSPropertyID::kAliasWebkitBoxSizing:
    case CSSPropertyID::kAliasWebkitClipPath:
    case CSSPropertyID::kAliasWebkitColumnCount:
    case CSSPropertyID::kAliasWebkitColumnGap:
    case CSSPropertyID::kAliasWebkitColumnRule:
    case CSSPropertyID::kAliasWebkitColumnRuleColor:
    case CSSPropertyID::kAliasWebkitColumnRuleStyle:
    case CSSPropertyID::kAliasWebkitColumnRuleWidth:
    case CSSPropertyID::kAliasWebkitColumnSpan:
    case CSSPropertyID::kAliasWebkitColumnWidth:
    case CSSPropertyID::kAliasWebkitColumns:
    case CSSPropertyID::kAliasWebkitFilter:
    case CSSPropertyID::kAliasWebkitFlex:
    case CSSPropertyID::kAliasWebkitFlexBasis:
    case CSSPropertyID::kAliasWebkitFlexDirection:
    case CSSPropertyID::kAliasWebkitFlexFlow:
    case CSSPropertyID::kAliasWebkitFlexGrow:
    case CSSPropertyID::kAliasWebkitFlexShrink:
    case CSSPropertyID::kAliasWebkitFlexWrap:
    case CSSPropertyID::kAliasWebkitFontFeatureSettings:
    case CSSPropertyID::kAliasWebkitHyphenateCharacter:
    case CSSPropertyID::kAliasWebkitJustifyContent:
    case CSSPropertyID::kAliasWebkitLogicalHeight:
    case CSSPropertyID::kAliasWebkitLogicalWidth:
    case CSSPropertyID::kAliasWebkitMarginAfter:
    case CSSPropertyID::kAliasWebkitMarginBefore:
    case CSSPropertyID::kAliasWebkitMarginEnd:
    case CSSPropertyID::kAliasWebkitMarginStart:
    case CSSPropertyID::kAliasWebkitMask:
    case CSSPropertyID::kAliasWebkitMaskClip:
    case CSSPropertyID::kAliasWebkitMaskComposite:
    case CSSPropertyID::kAliasWebkitMaskImage:
    case CSSPropertyID::kAliasWebkitMaskOrigin:
    case CSSPropertyID::kAliasWebkitMaskPosition:
    case CSSPropertyID::kAliasWebkitMaskRepeat:
    case CSSPropertyID::kAliasWebkitMaskSize:
    case CSSPropertyID::kAliasWebkitMaxLogicalHeight:
    case CSSPropertyID::kAliasWebkitMaxLogicalWidth:
    case CSSPropertyID::kAliasWebkitMinLogicalHeight:
    case CSSPropertyID::kAliasWebkitMinLogicalWidth:
    case CSSPropertyID::kAliasWebkitOpacity:
    case CSSPropertyID::kAliasWebkitOrder:
    case CSSPropertyID::kAliasWebkitPaddingAfter:
    case CSSPropertyID::kAliasWebkitPaddingBefore:
    case CSSPropertyID::kAliasWebkitPaddingEnd:
    case CSSPropertyID::kAliasWebkitPaddingStart:
    case CSSPropertyID::kAliasWebkitPerspective:
    case CSSPropertyID::kAliasWebkitPerspectiveOrigin:
    case CSSPropertyID::kAliasWebkitShapeImageThreshold:
    case CSSPropertyID::kAliasWebkitShapeMargin:
    case CSSPropertyID::kAliasWebkitShapeOutside:
    case CSSPropertyID::kAliasWebkitTextEmphasis:
    case CSSPropertyID::kAliasWebkitTextEmphasisColor:
    case CSSPropertyID::kAliasWebkitTextEmphasisPosition:
    case CSSPropertyID::kAliasWebkitTextEmphasisStyle:
    case CSSPropertyID::kAliasWebkitTextSizeAdjust:
    case CSSPropertyID::kAliasWebkitTransform:
    case CSSPropertyID::kAliasWebkitTransformOrigin:
    case CSSPropertyID::kAliasWebkitTransformStyle:
    case CSSPropertyID::kAliasWebkitTransition:
    case CSSPropertyID::kAliasWebkitTransitionDelay:
    case CSSPropertyID::kAliasWebkitTransitionDuration:
    case CSSPropertyID::kAliasWebkitTransitionProperty:
    case CSSPropertyID::kAliasWebkitTransitionTimingFunction:
    case CSSPropertyID::kAliasWebkitUserSelect:
    case CSSPropertyID::kAliasWordWrap:
    case CSSPropertyID::kAliasGridColumnGap:
    case CSSPropertyID::kAliasGridRowGap:
    case CSSPropertyID::kAliasGridGap:
      NOTREACHED()
          << "Aliases CSS properties should be converted to their non-aliased "
             "counterpart before calling this function. CSS property name: "
          << property.GetCSSPropertyName().ToAtomicString().Ascii();

    // Webkit prefixed properties which don't have non-aliased counterparts.
    // TODO ensure that each of these are reachable since they supposedly aren't
    // just aliases.
    case CSSPropertyID::kWebkitBorderImage:
    case CSSPropertyID::kWebkitBoxAlign:
    case CSSPropertyID::kWebkitBoxDecorationBreak:
    case CSSPropertyID::kWebkitBoxDirection:
    case CSSPropertyID::kWebkitBoxFlex:
    case CSSPropertyID::kWebkitBoxOrdinalGroup:
    case CSSPropertyID::kWebkitBoxOrient:
    case CSSPropertyID::kWebkitBoxPack:
    case CSSPropertyID::kWebkitBoxReflect:
    case CSSPropertyID::kWebkitLineBreak:
    case CSSPropertyID::kWebkitMaskBoxImageRepeat:
    case CSSPropertyID::kWebkitPrintColorAdjust:
    case CSSPropertyID::kWebkitRtlOrdering:
    case CSSPropertyID::kWebkitRubyPosition:
    case CSSPropertyID::kWebkitTapHighlightColor:
    case CSSPropertyID::kWebkitTextCombine:
    case CSSPropertyID::kWebkitTextDecorationsInEffect:
    case CSSPropertyID::kWebkitTextSecurity:
    case CSSPropertyID::kWebkitUserDrag:
    case CSSPropertyID::kWebkitUserModify:
      return true;

    // These logical properties compute to physical properties. Transitions
    // should check for equality on physical properties and run there.
    case CSSPropertyID::kBlockSize:
    case CSSPropertyID::kBorderBlockEndColor:
    case CSSPropertyID::kBorderBlockEndStyle:
    case CSSPropertyID::kBorderBlockEndWidth:
    case CSSPropertyID::kBorderBlockStartColor:
    case CSSPropertyID::kBorderBlockStartStyle:
    case CSSPropertyID::kBorderBlockStartWidth:
    case CSSPropertyID::kBorderEndEndRadius:
    case CSSPropertyID::kBorderEndStartRadius:
    case CSSPropertyID::kBorderInlineEndColor:
    case CSSPropertyID::kBorderInlineEndStyle:
    case CSSPropertyID::kBorderInlineEndWidth:
    case CSSPropertyID::kBorderInlineStartColor:
    case CSSPropertyID::kBorderInlineStartStyle:
    case CSSPropertyID::kBorderInlineStartWidth:
    case CSSPropertyID::kBorderStartEndRadius:
    case CSSPropertyID::kBorderStartStartRadius:
    case CSSPropertyID::kBorderBlock:
    case CSSPropertyID::kBorderBlockColor:
    case CSSPropertyID::kBorderBlockEnd:
    case CSSPropertyID::kBorderBlockStart:
    case CSSPropertyID::kBorderBlockStyle:
    case CSSPropertyID::kBorderBlockWidth:
    case CSSPropertyID::kBorderInline:
    case CSSPropertyID::kBorderInlineColor:
    case CSSPropertyID::kBorderInlineEnd:
    case CSSPropertyID::kBorderInlineStart:
    case CSSPropertyID::kBorderInlineStyle:
    case CSSPropertyID::kBorderInlineWidth:
    case CSSPropertyID::kContainIntrinsicBlockSize:
    case CSSPropertyID::kContainIntrinsicInlineSize:
    case CSSPropertyID::kInsetInlineStart:
    case CSSPropertyID::kInsetInlineEnd:
    case CSSPropertyID::kInsetBlockStart:
    case CSSPropertyID::kInsetBlockEnd:
    case CSSPropertyID::kInternalOverflowBlock:
    case CSSPropertyID::kInternalOverflowInline:
    case CSSPropertyID::kOverflowBlock:
    case CSSPropertyID::kOverflowInline:
    case CSSPropertyID::kOverscrollBehaviorBlock:
    case CSSPropertyID::kOverscrollBehaviorInline:
    case CSSPropertyID::kMinInlineSize:
    case CSSPropertyID::kMinBlockSize:
    case CSSPropertyID::kMaxInlineSize:
    case CSSPropertyID::kMaxBlockSize:
    case CSSPropertyID::kMarginInlineStart:
    case CSSPropertyID::kMarginInlineEnd:
    case CSSPropertyID::kMarginBlockStart:
    case CSSPropertyID::kMarginBlockEnd:
    case CSSPropertyID::kPaddingInlineStart:
    case CSSPropertyID::kPaddingInlineEnd:
    case CSSPropertyID::kPaddingBlockStart:
    case CSSPropertyID::kPaddingBlockEnd:
    case CSSPropertyID::kScrollMarginBlockEnd:
    case CSSPropertyID::kScrollMarginBlockStart:
    case CSSPropertyID::kScrollMarginInlineEnd:
    case CSSPropertyID::kScrollMarginInlineStart:
    case CSSPropertyID::kScrollPaddingBlockEnd:
    case CSSPropertyID::kScrollPaddingBlockStart:
    case CSSPropertyID::kScrollPaddingInlineEnd:
    case CSSPropertyID::kScrollPaddingInlineStart:
    case CSSPropertyID::kScrollStartBlock:
    case CSSPropertyID::kScrollStartInline:
    case CSSPropertyID::kInlineSize:
    case CSSPropertyID::kInsetBlock:
    case CSSPropertyID::kInsetInline:
    case CSSPropertyID::kMarginBlock:
    case CSSPropertyID::kMarginInline:
    case CSSPropertyID::kPaddingBlock:
    case CSSPropertyID::kPaddingInline:
    case CSSPropertyID::kScrollMarginBlock:
    case CSSPropertyID::kScrollMarginInline:
    case CSSPropertyID::kScrollPaddingBlock:
    case CSSPropertyID::kScrollPaddingInline:
      NOTREACHED() << property.GetCSSPropertyName().ToAtomicString().Ascii();

    // No transitions on internal properties:
    case CSSPropertyID::kInternalAlignContentBlock:
    case CSSPropertyID::kInternalEmptyLineHeight:
    case CSSPropertyID::kInternalFontSizeDelta:
    case CSSPropertyID::kInternalForcedBackgroundColor:
    case CSSPropertyID::kInternalForcedBorderColor:
    case CSSPropertyID::kInternalForcedColor:
    case CSSPropertyID::kInternalForcedOutlineColor:
    case CSSPropertyID::kInternalForcedVisitedColor:
    case CSSPropertyID::kInternalVisitedBackgroundColor:
    case CSSPropertyID::kInternalVisitedBorderBlockEndColor:
    case CSSPropertyID::kInternalVisitedBorderBlockStartColor:
    case CSSPropertyID::kInternalVisitedBorderBottomColor:
    case CSSPropertyID::kInternalVisitedBorderInlineEndColor:
    case CSSPropertyID::kInternalVisitedBorderInlineStartColor:
    case CSSPropertyID::kInternalVisitedBorderLeftColor:
    case CSSPropertyID::kInternalVisitedBorderRightColor:
    case CSSPropertyID::kInternalVisitedBorderTopColor:
    case CSSPropertyID::kInternalVisitedCaretColor:
    case CSSPropertyID::kInternalVisitedColor:
    case CSSPropertyID::kInternalVisitedColumnRuleColor:
    case CSSPropertyID::kInternalVisitedFill:
    case CSSPropertyID::kInternalVisitedOutlineColor:
    case CSSPropertyID::kInternalVisitedStroke:
    case CSSPropertyID::kInternalVisitedTextDecorationColor:
    case CSSPropertyID::kInternalVisitedTextEmphasisColor:
    case CSSPropertyID::kInternalVisitedTextFillColor:
    case CSSPropertyID::kInternalVisitedTextStrokeColor:
      NOTREACHED() << property.GetCSSPropertyName().ToAtomicString().Ascii();

    // Shorthand properties shouldn't be compared, use their longhands.
    case CSSPropertyID::kBackground:
    case CSSPropertyID::kBackgroundPosition:
    case CSSPropertyID::kBorder:
    case CSSPropertyID::kBorderBottom:
    case CSSPropertyID::kBorderColor:
    case CSSPropertyID::kBorderImage:
    case CSSPropertyID::kBorderLeft:
    case CSSPropertyID::kBorderRadius:
    case CSSPropertyID::kBorderRight:
    case CSSPropertyID::kBorderSpacing:
    case CSSPropertyID::kBorderStyle:
    case CSSPropertyID::kBorderTop:
    case CSSPropertyID::kBorderWidth:
    case CSSPropertyID::kColumnRule:
    case CSSPropertyID::kColumns:
    case CSSPropertyID::kContainIntrinsicSize:
    case CSSPropertyID::kContainer:
    case CSSPropertyID::kInset:
    case CSSPropertyID::kFlex:
    case CSSPropertyID::kFlexFlow:
    case CSSPropertyID::kFont:
    case CSSPropertyID::kFontSynthesis:
    case CSSPropertyID::kFontVariant:
    case CSSPropertyID::kGap:
    case CSSPropertyID::kGrid:
    case CSSPropertyID::kGridArea:
    case CSSPropertyID::kGridColumn:
    case CSSPropertyID::kGridRow:
    case CSSPropertyID::kGridTemplate:
    case CSSPropertyID::kListStyle:
    case CSSPropertyID::kMargin:
    case CSSPropertyID::kMarker:
    case CSSPropertyID::kMask:
    case CSSPropertyID::kMasonryTrack:
    case CSSPropertyID::kOffset:
    case CSSPropertyID::kOutline:
    case CSSPropertyID::kOverflow:
    case CSSPropertyID::kOverscrollBehavior:
    case CSSPropertyID::kPadding:
    case CSSPropertyID::kPageBreakAfter:
    case CSSPropertyID::kPageBreakBefore:
    case CSSPropertyID::kPageBreakInside:
    case CSSPropertyID::kPlaceContent:
    case CSSPropertyID::kPlaceItems:
    case CSSPropertyID::kPlaceSelf:
    case CSSPropertyID::kPositionTry:
    case CSSPropertyID::kScrollMargin:
    case CSSPropertyID::kScrollPadding:
    case CSSPropertyID::kScrollStart:
    case CSSPropertyID::kScrollTimeline:
    case CSSPropertyID::kTextBox:
    case CSSPropertyID::kTextDecoration:
    case CSSPropertyID::kTextEmphasis:
    case CSSPropertyID::kTextSpacing:
    case CSSPropertyID::kTextWrap:
    case CSSPropertyID::kTransition:
    case CSSPropertyID::kViewTimeline:
    case CSSPropertyID::kWebkitColumnBreakAfter:
    case CSSPropertyID::kWebkitColumnBreakBefore:
    case CSSPropertyID::kWebkitColumnBreakInside:
    case CSSPropertyID::kWebkitMaskBoxImage:
    case CSSPropertyID::kMaskPosition:
    case CSSPropertyID::kWebkitTextStroke:
    case CSSPropertyID::kWhiteSpace:
      NOTREACHED() << property.GetCSSPropertyName().ToAtomicString().Ascii();

    // Non-animateable properties
    case CSSPropertyID::kAlternativeAnimationWithTimeline:
    case CSSPropertyID::kAnimation:
    case CSSPropertyID::kAnimationComposition:
    case CSSPropertyID::kAnimationDelay:
    case CSSPropertyID::kAnimationDirection:
    case CSSPropertyID::kAnimationDuration:
    case CSSPropertyID::kAnimationFillMode:
    case CSSPropertyID::kAnimationIterationCount:
    case CSSPropertyID::kAnimationName:
    case CSSPropertyID::kAnimationPlayState:
    case CSSPropertyID::kAnimationRange:
    case CSSPropertyID::kAnimationRangeEnd:
    case CSSPropertyID::kAnimationRangeStart:
    case CSSPropertyID::kAnimationTimeline:
    case CSSPropertyID::kAnimationTimingFunction:
    case CSSPropertyID::kContain:
    case CSSPropertyID::kContainerName:
    case CSSPropertyID::kContainerType:
    case CSSPropertyID::kDirection:
    case CSSPropertyID::kTextCombineUpright:
    case CSSPropertyID::kTextOrientation:
    case CSSPropertyID::kTimelineScope:
    case CSSPropertyID::kTransitionBehavior:
    case CSSPropertyID::kTransitionDelay:
    case CSSPropertyID::kTransitionDuration:
    case CSSPropertyID::kTransitionProperty:
    case CSSPropertyID::kTransitionTimingFunction:
    case CSSPropertyID::kUnicodeBidi:
    case CSSPropertyID::kWebkitWritingMode:
    case CSSPropertyID::kWillChange:
    case CSSPropertyID::kWritingMode:
      NOTREACHED() << property.GetCSSPropertyName().ToAtomicString().Ascii();

    // TODO(crbug.com/1459374): Implement comparison for these properties. They
    // are reachable via transitions now.
    case CSSPropertyID::kAdditiveSymbols:
    case CSSPropertyID::kAscentOverride:
    case CSSPropertyID::kBasePalette:
    case CSSPropertyID::kDescentOverride:
    case CSSPropertyID::kFallback:
    case CSSPropertyID::kFontDisplay:
    case CSSPropertyID::kInherits:
    case CSSPropertyID::kInitialValue:
    case CSSPropertyID::kLineGapOverride:
    case CSSPropertyID::kNavigation:
    case CSSPropertyID::kNegative:
    case CSSPropertyID::kOverrideColors:
    case CSSPropertyID::kPad:
    case CSSPropertyID::kPrefix:
    case CSSPropertyID::kRange:
    case CSSPropertyID::kSpeakAs:
    case CSSPropertyID::kSrc:
    case CSSPropertyID::kSuffix:
    case CSSPropertyID::kSymbols:
    case CSSPropertyID::kSyntax:
    case CSSPropertyID::kSystem:
    case CSSPropertyID::kTypes:
    case CSSPropertyID::kUnicodeRange:
      return true;

    // Invalid properties.
    case CSSPropertyID::kAll:
    case CSSPropertyID::kInvalid:
    case CSSPropertyID::kVariable:
      NOTREACHED() << property.GetCSSPropertyName().ToAtomicString().Ascii();
  }
}

}  // namespace blink
```