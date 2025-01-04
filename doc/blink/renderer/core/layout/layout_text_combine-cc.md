Response:
Let's break down the thought process for analyzing the `LayoutTextCombine.cc` file and generating the detailed response.

**1. Initial Understanding and Purpose:**

* **Keywords:** The file name `layout_text_combine.cc` immediately suggests it's related to handling text combination in layout. The "combine" likely refers to the `text-combine-upright` CSS property.
* **Namespace:** The code is within the `blink` namespace and the `LayoutTextCombine` class inherits from `LayoutBlockFlow`, giving a hint about its role in the layout process.
* **Copyright:**  The copyright header confirms it's part of the Chromium Blink rendering engine.

**2. Core Functionality - Identifying Key Methods:**

* **Constructor/Destructor:** Basic object lifecycle. The constructor initializes `IsAtomicInlineLevel(true)`, indicating it behaves as a single inline element.
* **`CreateAnonymous()`:**  This static method is crucial. "Anonymous" suggests it's created internally, not directly from HTML. It takes a `LayoutText` child, sets up styles (crucially, using `StyleAdjuster::AdjustStyleForTextCombine`), and links the text node. This points to the core function of wrapping text for combination.
* **`GetTextContent()`:**  Simple retrieval of the combined text. The `DCHECK(!NeedsCollectInlines() && GetInlineNodeData())` hints at how the text is stored.
* **`AssertStyleIsValid()`:** This reinforces the special styling required for combined text, listing specific CSS properties that must have certain values.
* **`DesiredWidth()`:** Calculates the desired width of the combined text block, considering underlines and overlines. The comment mentioning EPUB is a valuable insight into real-world use cases.
* **`ComputeInlineSpacing()`:** Calculates spacing related to the width adjustment. The dependency on `scale_x_` is noted.
* **`ApplyScaleX()` and `UnapplyScaleX()`:** These methods strongly suggest a scaling transformation is being applied, likely for compressing the text.
* **`AdjustOffsetForHitTest()` and `AdjustOffsetForLocalCaretRect()`:**  These relate to handling user interaction (clicks, cursor placement) within the transformed text.
* **`AdjustRectForBoundingBox()`:**  Modifying the bounding box, also related to the scaling transformation.
* **`ComputeTextBoundsRectForHitTest()`:**  Calculating the precise area for hit testing within the text.
* **`ResetLayout()`:**  Resets internal state related to compression.
* **`AdjustTextLeftForPaint()` and `AdjustTextTopForPaint()`:**  Adjustments specifically for rendering the text with the transformation.
* **`ComputeAffineTransformForPaint()`:**  Constructs the actual transformation matrix, including scaling and synthetic oblique.
* **`NeedsAffineTransformInPaint()`:**  Determines if a transformation is needed.
* **`ComputeTextFrameRect()`:**  Calculates the frame rectangle, particularly relevant for vertical writing modes.
* **`RecalcContentsInkOverflow()`:** Calculates the area covered by the combined text, including decorations and emphasis marks.
* **`VisualRectForPaint()`:**  Gets the visual rectangle for painting.
* **`SetScaleX()` and `SetCompressedFont()`:**  Methods to apply the compression transformation, either through scaling or by using a pre-compressed font.
* **`UsingSyntheticOblique()`:** Checks for synthetic italics.

**3. Connecting to HTML, CSS, and JavaScript:**

* **CSS Property:** The most obvious connection is the `text-combine-upright` CSS property. The comments and logic directly address its implementation.
* **HTML Structure:**  The `CreateAnonymous()` method creating a wrapper around a `LayoutText` node illustrates how the engine manipulates the underlying structure.
* **JavaScript Interaction (Implied):** While not directly in this file, JavaScript could manipulate the `text-combine-upright` property via the CSSOM, triggering the logic in this file.

**4. Logical Reasoning and Examples:**

* **Scaling:** The `ApplyScaleX` and `UnapplyScaleX` functions strongly suggest a compression effect. Hypothesizing different `scale_x` values leads to predictable output changes in width.
* **Font Changes:** The `SetCompressedFont()` method suggests that an alternative, pre-compressed font can be used.
* **Hit Testing:**  The `AdjustOffsetForHitTest` demonstrates how the engine needs to reverse the scaling to accurately determine where a user clicked.

**5. Identifying Potential User/Programming Errors:**

* **Missing `text-combine-upright`:**  The code relies on the CSS property being set. Forgetting this would mean the code isn't invoked.
* **Invalid `scale_x`:** The `DCHECK_GT(new_scale_x, 0.0f)` highlights the requirement for a positive scale.
* **Incorrect Font Setup:** If `SetCompressedFont` is used with an incompatible font, rendering issues could occur.

**6. Structuring the Response:**

* **Start with a high-level summary of the file's purpose.**
* **Detail each function, explaining its role and significance.**
* **Explicitly connect the code to HTML, CSS, and JavaScript.**
* **Provide concrete examples of logical reasoning with input and output.**
* **Highlight common usage errors.**
* **Use clear and concise language.**
* **Maintain a logical flow, building from basic functionality to more complex aspects.**

**Self-Correction/Refinement During Analysis:**

* Initially, I might have focused too much on the layout aspects. Realizing the strong connection to the `text-combine-upright` CSS property is crucial.
*  The anonymous nature of the `LayoutTextCombine` node is an important detail that needs to be highlighted.
* The comments within the code, particularly those referencing specific HTML test files or specifications, provide valuable context. Paying attention to these comments is essential for a complete understanding.

By following this structured analysis, focusing on key elements, and drawing connections to web technologies, a comprehensive and accurate explanation of the `LayoutTextCombine.cc` file can be generated.
这个 `blink/renderer/core/layout/layout_text_combine.cc` 文件实现了 Chromium Blink 引擎中用于处理 CSS 属性 `text-combine-upright` 的布局逻辑。该属性用于将连续的文本字符组合成一个类似单个字符的紧凑显示形式，常用于排版东亚文字，特别是数字和缩略语。

以下是该文件的主要功能及其与 HTML、CSS、JavaScript 的关系，逻辑推理，以及可能的用户/编程错误：

**功能列举:**

1. **创建 `LayoutTextCombine` 对象:** 该文件定义了 `LayoutTextCombine` 类，它继承自 `LayoutBlockFlow` 并被标记为原子内联级别 (`SetIsAtomicInlineLevel(true)`)。这意味着它在布局中像一个独立的内联元素一样被处理。
2. **匿名创建:**  提供了一个静态方法 `CreateAnonymous(LayoutText* text_child)`，用于创建一个匿名的 `LayoutTextCombine` 对象来包裹一个 `LayoutText` 对象。这是实现 `text-combine-upright` 效果的关键，因为它在布局树中引入了一个额外的节点。
3. **样式调整:** 在 `CreateAnonymous` 中，使用 `StyleAdjuster::AdjustStyleForTextCombine()` 来调整新创建的 `LayoutTextCombine` 对象的样式，确保它具有正确的默认值，例如无文本装饰、水平书写模式等。
4. **获取文本内容:** `GetTextContent()` 方法用于获取组合后的文本内容。
5. **样式断言:** `AssertStyleIsValid()` 方法用于在调试模式下检查 `LayoutTextCombine` 对象的样式是否符合预期，这有助于发现样式设置错误。
6. **计算期望宽度:** `DesiredWidth()` 方法计算组合文本的期望宽度。这个宽度通常与一个 `em` 单位相当，但会根据是否存在下划线或上划线进行调整。
7. **计算内联间距:** `ComputeInlineSpacing()` 计算组合文本两侧的内联间距，用于在水平布局中居中显示组合文本。
8. **应用和取消缩放:**  提供 `ApplyScaleX()` 和 `UnapplyScaleX()` 方法，用于在水平方向上对组合文本进行缩放变换，这是实现文本压缩显示的关键。
9. **调整偏移量:** `AdjustOffsetForHitTest()` 和 `AdjustOffsetForLocalCaretRect()` 方法用于调整鼠标点击测试和光标位置的偏移量，以适应缩放变换。
10. **调整边界框:** `AdjustRectForBoundingBox()` 用于调整组合文本的边界框，同样是为了适应缩放变换。
11. **计算点击测试的文本边界:** `ComputeTextBoundsRectForHitTest()` 计算用于点击测试的文本边界矩形。
12. **重置布局:** `ResetLayout()` 方法用于重置与文本组合相关的布局信息，例如压缩字体和缩放比例。
13. **调整绘制位置:** `AdjustTextLeftForPaint()` 和 `AdjustTextTopForPaint()` 用于调整组合文本在绘制时的水平和垂直位置，以考虑缩放和字体基线。
14. **计算仿射变换:** `ComputeAffineTransformForPaint()` 用于计算绘制组合文本所需的仿射变换矩阵，包括缩放和斜体效果。
15. **判断是否需要仿射变换:** `NeedsAffineTransformInPaint()` 用于判断是否需要在绘制时应用仿射变换。
16. **计算文本框架矩形:** `ComputeTextFrameRect()` 计算组合文本的框架矩形，主要用于垂直书写模式。
17. **重新计算内容墨水溢出:** `RecalcContentsInkOverflow()` 计算组合文本内容的墨水溢出区域，包括文本装饰和强调标记。
18. **获取绘制的视觉矩形:** `VisualRectForPaint()` 获取用于绘制的组合文本的视觉矩形。
19. **设置水平缩放比例:** `SetScaleX()` 方法用于设置水平缩放比例，用于文本压缩。
20. **设置压缩字体:** `SetCompressedFont()` 方法用于设置用于组合文本的压缩字体。
21. **判断是否使用合成斜体:** `UsingSyntheticOblique()` 用于判断是否使用了合成斜体效果。

**与 JavaScript, HTML, CSS 的关系:**

* **CSS:** `LayoutTextCombine` 的核心功能是响应 CSS 属性 `text-combine-upright`。当浏览器解析到带有此属性的元素时，布局引擎会创建 `LayoutTextCombine` 对象来处理该元素的文本内容。
    * **示例:**
      ```html
      <span style="text-combine-upright: all;">ABC</span>
      <span style="text-combine-upright: digits 2;">12</span>
      ```
      在这个例子中，CSS 属性 `text-combine-upright` 告诉浏览器将 "ABC" 或 "12" 组合成一个垂直排列的紧凑形式。`LayoutTextCombine` 负责实现这种布局。
* **HTML:** HTML 提供了包含文本内容的元素，这些文本内容会被 `LayoutTextCombine` 处理。`LayoutTextCombine` 通常包裹在 `LayoutText` 对象周围，后者直接对应 HTML 中的文本节点。
* **JavaScript:** JavaScript 可以通过 DOM API 修改元素的样式，包括 `text-combine-upright` 属性。当 JavaScript 修改了这个属性，布局引擎会重新计算布局，并可能创建或销毁 `LayoutTextCombine` 对象。
    * **示例:**
      ```javascript
      const span = document.querySelector('span');
      span.style.textCombineUpright = 'digits 2';
      ```
      这段 JavaScript 代码会动态地将 `text-combine-upright` 属性应用于一个 `<span>` 元素，从而触发 `LayoutTextCombine` 的相关逻辑。

**逻辑推理 (假设输入与输出):**

假设我们有以下 HTML 和 CSS：

```html
<span id="combine-text" style="text-combine-upright: digits 2;">123</span>
```

1. **输入:**  一个包含文本 "123" 的 `LayoutText` 对象，其父元素的样式包含 `text-combine-upright: digits 2;`。
2. **推理:**
   - 布局引擎会检测到 `text-combine-upright` 属性。
   - `LayoutTextCombine::CreateAnonymous()` 会被调用，创建一个新的 `LayoutTextCombine` 对象来包裹 `LayoutText` 对象。
   - `StyleAdjuster::AdjustStyleForTextCombine()` 会设置 `LayoutTextCombine` 的默认样式。
   - `DesiredWidth()` 会计算组合文本的期望宽度，可能接近一个 `em` 的大小。
   - `SetScaleX()` 可能会被调用，根据需要压缩文本以适应期望的宽度。例如，如果需要将 "12" 压缩成一个字符的宽度，`scale_x_` 可能会被设置为一个小于 1 的值。
   - 在绘制阶段，`ComputeAffineTransformForPaint()` 会生成一个缩放变换矩阵，将 "12" 水平压缩。
3. **输出:**
   - 渲染结果是在页面上看到 "12" 这两个数字被垂直排列并可能水平压缩在一起，看起来像一个单独的符号。
   - `GetTextContent()` 将返回原始文本 "123"。
   - `VisualRectForPaint()` 将返回组合后的文本在页面上的实际渲染区域。

**用户或编程常见的使用错误:**

1. **忘记设置 `text-combine-upright` 属性:** 如果开发者希望使用文本组合效果，但忘记在 CSS 中设置 `text-combine-upright` 属性，那么 `LayoutTextCombine` 的逻辑就不会被触发，文本将按正常方式渲染。
   * **错误示例:**
     ```html
     <span>12</span>  <!-- 缺少 text-combine-upright 属性 -->
     ```
2. **`text-combine-upright` 的值不正确:**  `text-combine-upright` 属性接受特定的值（例如 `all`, `digits <n>`, `none`）。如果使用了无效的值，浏览器可能会忽略该属性或产生意外的渲染结果。
   * **错误示例:**
     ```html
     <span style="text-combine-upright: something-wrong;">12</span>
     ```
3. **与不支持的 CSS 属性同时使用:**  虽然 `LayoutTextCombine` 内部会处理一些样式，但某些 CSS 属性可能与 `text-combine-upright` 的效果冲突，导致不期望的渲染结果。例如，尝试对组合后的文本应用特定的 `letter-spacing` 可能不会生效，因为 `LayoutTextCombine` 可能会覆盖这些样式。
4. **JavaScript 操作后布局未更新:**  如果 JavaScript 动态地修改了包含 `text-combine-upright` 属性的元素的文本内容，但由于某些原因布局没有正确更新，可能会导致页面显示的内容与预期不符。这通常不是 `LayoutTextCombine` 本身的问题，而是整个渲染流程中的问题。
5. **假设组合文本是单个字符:**  开发者可能会错误地认为组合后的文本在所有方面都像一个单独的字符。例如，在处理文本输入或复制粘贴时，需要注意组合文本实际上是由多个字符组成的。`GetTextContent()` 返回原始的多个字符就说明了这一点。

总而言之，`layout_text_combine.cc` 文件是 Blink 引擎中实现 `text-combine-upright` CSS 属性的关键部分，它负责创建和管理用于组合文本的布局对象，并处理相关的样式调整、缩放变换和绘制逻辑，以实现将多个字符紧凑显示为一个单元的效果。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_text_combine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_text_combine.h"

#include "third_party/blink/renderer/core/css/resolver/style_adjuster.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_rect.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/ink_overflow.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node_data.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/inline_paint_context.h"
#include "third_party/blink/renderer/core/paint/line_relative_rect.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/transforms/affine_transform.h"

namespace blink {

LayoutTextCombine::LayoutTextCombine() : LayoutBlockFlow(nullptr) {
  SetIsAtomicInlineLevel(true);
}

LayoutTextCombine::~LayoutTextCombine() = default;

// static
LayoutTextCombine* LayoutTextCombine::CreateAnonymous(LayoutText* text_child) {
  DCHECK(ShouldBeParentOf(*text_child)) << text_child;
  auto* const layout_object = MakeGarbageCollected<LayoutTextCombine>();
  auto& document = text_child->GetDocument();
  layout_object->SetDocumentForAnonymous(&document);
  ComputedStyleBuilder new_style_builder =
      document.GetStyleResolver().CreateAnonymousStyleBuilderWithDisplay(
          text_child->StyleRef(), EDisplay::kInlineBlock);
  StyleAdjuster::AdjustStyleForTextCombine(new_style_builder);
  layout_object->SetStyle(new_style_builder.TakeStyle());
  layout_object->AddChild(text_child);
  LayoutTextCombine::AssertStyleIsValid(text_child->StyleRef());
  return layout_object;
}

String LayoutTextCombine::GetTextContent() const {
  DCHECK(!NeedsCollectInlines() && GetInlineNodeData()) << this;
  return GetInlineNodeData()->ItemsData(false).text_content;
}

// static
void LayoutTextCombine::AssertStyleIsValid(const ComputedStyle& style) {
  // See also |StyleAdjuster::AdjustStyleForTextCombine()|.
#if DCHECK_IS_ON()
  DCHECK_EQ(style.GetTextDecorationLine(), TextDecorationLine::kNone);
  DCHECK_EQ(style.GetTextEmphasisMark(), TextEmphasisMark::kNone);
  DCHECK_EQ(style.GetWritingMode(), WritingMode::kHorizontalTb);
  DCHECK_EQ(style.LetterSpacing(), 0.0f);
  DCHECK(!style.HasAppliedTextDecorations());
  DCHECK_EQ(style.TextIndent(), Length::Fixed());
  DCHECK_EQ(style.GetFont().GetFontDescription().Orientation(),
            FontOrientation::kHorizontal);
#endif
}

float LayoutTextCombine::DesiredWidth() const {
  DCHECK_EQ(StyleRef().GetFont().GetFontDescription().Orientation(),
            FontOrientation::kHorizontal);
  const float one_em = StyleRef().ComputedFontSize();
  if (EnumHasFlags(
          Parent()->StyleRef().TextDecorationsInEffect(),
          TextDecorationLine::kUnderline | TextDecorationLine::kOverline)) {
    return one_em;
  }
  // Allow em + 10% margin if there are no underline and overeline for
  // better looking. This isn't specified in the spec[1], but EPUB group
  // wants this.
  // [1] https://www.w3.org/TR/css-writing-modes-3/
  constexpr float kTextCombineMargin = 1.1f;
  return one_em * kTextCombineMargin;
}

float LayoutTextCombine::ComputeInlineSpacing() const {
  DCHECK_EQ(StyleRef().GetFont().GetFontDescription().Orientation(),
            FontOrientation::kHorizontal);
  DCHECK(scale_x_);
  const LayoutUnit line_height = StyleRef().GetFontHeight().LineHeight();
  return (line_height - DesiredWidth()) / 2;
}

PhysicalOffset LayoutTextCombine::ApplyScaleX(
    const PhysicalOffset& offset) const {
  DCHECK(scale_x_.has_value());
  const float spacing = ComputeInlineSpacing();
  return PhysicalOffset(LayoutUnit(offset.left * *scale_x_ + spacing),
                        offset.top);
}

PhysicalRect LayoutTextCombine::ApplyScaleX(const PhysicalRect& rect) const {
  DCHECK(scale_x_.has_value());
  return PhysicalRect(ApplyScaleX(rect.offset), ApplyScaleX(rect.size));
}

PhysicalSize LayoutTextCombine::ApplyScaleX(const PhysicalSize& size) const {
  DCHECK(scale_x_.has_value());
  return PhysicalSize(LayoutUnit(size.width * *scale_x_), size.height);
}

PhysicalOffset LayoutTextCombine::UnapplyScaleX(
    const PhysicalOffset& offset) const {
  DCHECK(scale_x_.has_value());
  const float spacing = ComputeInlineSpacing();
  return PhysicalOffset(LayoutUnit((offset.left - spacing) / *scale_x_),
                        offset.top);
}

PhysicalOffset LayoutTextCombine::AdjustOffsetForHitTest(
    const PhysicalOffset& offset_in_container) const {
  if (!scale_x_) {
    return offset_in_container;
  }
  return UnapplyScaleX(offset_in_container);
}

PhysicalOffset LayoutTextCombine::AdjustOffsetForLocalCaretRect(
    const PhysicalOffset& offset_in_container) const {
  if (!scale_x_) {
    return offset_in_container;
  }
  return ApplyScaleX(offset_in_container);
}

PhysicalRect LayoutTextCombine::AdjustRectForBoundingBox(
    const PhysicalRect& rect) const {
  if (!scale_x_) {
    return rect;
  }
  // See "text-combine-upright-compression-007.html"
  return ApplyScaleX(rect);
}

PhysicalRect LayoutTextCombine::ComputeTextBoundsRectForHitTest(
    const FragmentItem& text_item,
    const PhysicalOffset& inline_root_offset) const {
  DCHECK(text_item.IsText()) << text_item;
  PhysicalRect rect = text_item.SelfInkOverflowRect();
  rect.Move(text_item.OffsetInContainerFragment());
  rect = AdjustRectForBoundingBox(rect);
  rect.Move(inline_root_offset);
  return rect;
}

void LayoutTextCombine::ResetLayout() {
  compressed_font_ = Font();
  has_compressed_font_ = false;
  scale_x_.reset();
}

LayoutUnit LayoutTextCombine::AdjustTextLeftForPaint(
    LayoutUnit position) const {
  if (!scale_x_) {
    return position;
  }
  const float spacing = ComputeInlineSpacing();
  return LayoutUnit(position + spacing / *scale_x_);
}

LayoutUnit LayoutTextCombine::AdjustTextTopForPaint(LayoutUnit text_top) const {
  DCHECK_EQ(StyleRef().GetFont().GetFontDescription().Orientation(),
            FontOrientation::kHorizontal);
  const SimpleFontData& font_data = *StyleRef().GetFont().PrimaryFont();
  const float internal_leading = font_data.InternalLeading();
  const float half_leading = internal_leading / 2;
  const int ascent = font_data.GetFontMetrics().Ascent();
  return LayoutUnit(text_top + ascent - half_leading);
}

AffineTransform LayoutTextCombine::ComputeAffineTransformForPaint(
    const PhysicalOffset& paint_offset) const {
  DCHECK(NeedsAffineTransformInPaint());
  AffineTransform matrix;
  if (UsingSyntheticOblique()) {
    const LayoutUnit text_left = AdjustTextLeftForPaint(paint_offset.left);
    const LayoutUnit text_top = AdjustTextTopForPaint(paint_offset.top);
    matrix.Translate(text_left, text_top);
    // TODO(yosin): We should use angle specified in CSS instead of
    // constant value -15deg. See also |DrawBlobs()| in [1] for vertical
    // upright oblique.
    // [1] "third_party/blink/renderer/platform/fonts/font.cc"
    constexpr float kSlantAngle = -15.0f;
    matrix.SkewY(kSlantAngle);
    matrix.Translate(-text_left, -text_top);
  }
  if (scale_x_.has_value()) {
    matrix.Translate(paint_offset.left, paint_offset.top);
    matrix.Scale(*scale_x_, 1.0f);
    matrix.Translate(-paint_offset.left, -paint_offset.top);
  }
  return matrix;
}

bool LayoutTextCombine::NeedsAffineTransformInPaint() const {
  return scale_x_.has_value() || UsingSyntheticOblique();
}

LineRelativeRect LayoutTextCombine::ComputeTextFrameRect(
    const PhysicalOffset paint_offset) const {
  const ComputedStyle& style = Parent()->StyleRef();
  DCHECK(style.GetFont().GetFontDescription().IsVerticalBaseline());

  const LayoutUnit one_em = style.ComputedFontSizeAsFixed();
  const FontHeight text_metrics = style.GetFontHeight();
  const LayoutUnit line_height = text_metrics.LineHeight();
  return {LineRelativeOffset::CreateFromBoxOrigin(paint_offset),
          LogicalSize(one_em, line_height)};
}

PhysicalRect LayoutTextCombine::RecalcContentsInkOverflow(
    const InlineCursor& cursor) const {
  const ComputedStyle& style = Parent()->StyleRef();
  DCHECK(style.GetFont().GetFontDescription().IsVerticalBaseline());

  const LineRelativeRect line_relative_text_rect =
      ComputeTextFrameRect(PhysicalOffset());

  // Note: |text_rect| and |ink_overflow| are both in logical direction.
  // It is unusual for a PhysicalRect to be in a logical direction, typically
  // a LineRelativeRect will be used instead, but the TextCombine case
  // requires it.
  const PhysicalRect text_rect{
      PhysicalOffset(), PhysicalSize{line_relative_text_rect.size.inline_size,
                                     line_relative_text_rect.size.block_size}};
  LogicalRect ink_overflow(text_rect.offset.left, text_rect.offset.top,
                           text_rect.size.width, text_rect.size.height);

  const WritingMode writing_mode = style.GetWritingMode();
  if (style.HasAppliedTextDecorations()) {
    // |LayoutTextCombine| does not support decorating box, as it is not
    // supported in vertical flow and text-combine is only for vertical flow.
    const LogicalRect decoration_rect = InkOverflow::ComputeDecorationOverflow(
        cursor, style, style.GetFont(),
        /* offset_in_container */ PhysicalOffset(), ink_overflow,
        /* inline_context */ nullptr, writing_mode);
    ink_overflow.Unite(decoration_rect);
  }

  if (style.GetTextEmphasisMark() != TextEmphasisMark::kNone) {
    ink_overflow = InkOverflow::ComputeEmphasisMarkOverflow(
        style, text_rect.size, ink_overflow);
  }

  if (const ShadowList* text_shadow = style.TextShadow()) {
    InkOverflow::ExpandForShadowOverflow(ink_overflow, *text_shadow,
                                         writing_mode);
  }

  PhysicalRect local_ink_overflow =
      WritingModeConverter({writing_mode, TextDirection::kLtr}, text_rect.size)
          .ToPhysical(ink_overflow);
  local_ink_overflow.ExpandEdgesToPixelBoundaries();
  return local_ink_overflow;
}

gfx::Rect LayoutTextCombine::VisualRectForPaint(
    const PhysicalOffset& paint_offset) const {
  DCHECK_EQ(PhysicalFragmentCount(), 1u);
  PhysicalRect ink_overflow = GetPhysicalFragment(0)->InkOverflowRect();
  ink_overflow.Move(paint_offset);
  return ToEnclosingRect(ink_overflow);
}

void LayoutTextCombine::SetScaleX(float new_scale_x) {
  DCHECK_GT(new_scale_x, 0.0f);
  DCHECK(!scale_x_.has_value());
  DCHECK(!has_compressed_font_);
  // Note: Even if rounding, e.g. LayoutUnit::FromFloatRound(), we still have
  // gap between painted characters in text-combine-upright-value-all-002.html
  scale_x_ = new_scale_x;
}

void LayoutTextCombine::SetCompressedFont(const Font& font) {
  DCHECK(!has_compressed_font_);
  DCHECK(!scale_x_.has_value());
  compressed_font_ = font;
  has_compressed_font_ = true;
}

bool LayoutTextCombine::UsingSyntheticOblique() const {
  return Parent()
      ->StyleRef()
      .GetFont()
      .GetFontDescription()
      .IsSyntheticOblique();
}

}  // namespace blink

"""

```