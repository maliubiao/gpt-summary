Response:
Let's break down the thought process for analyzing this C++ code file.

1. **Understand the Context:** The first step is recognizing this is Chromium's Blink rendering engine code specifically for MathML layout. The file path `blink/renderer/core/layout/mathml/math_layout_utils.cc` clearly indicates this. MathML is a standard for representing mathematical notation in web pages. "Layout" suggests this code deals with how MathML elements are positioned and sized on the screen.

2. **Identify Core Functionality (High-Level):** Skim through the code, looking for function names and included headers. Headers like `mathml_fraction_element.h`, `mathml_operator_element.h`, etc., signal that the code interacts with specific MathML elements. Function names like `CreateConstraintSpaceForMathChild`, `ComputeMinAndMaxContentContributionForMathChild`, `IsValidMathMLFraction`, `GetRadicalHorizontalParameters`, `FractionLineThickness`, and `GetMathMLEmbellishedOperatorProperties` provide strong hints about the file's purpose. It appears to be a utility file containing functions for various aspects of MathML layout calculations and validation.

3. **Categorize Functions by Purpose:**  Group the functions based on what they seem to do. Initial categories might include:
    * **Layout Constraint Creation:**  `CreateConstraintSpaceForMathChild`, `ComputeMinAndMaxContentContributionForMathChild` (These deal with the constraints used during layout).
    * **Element Validation:** `IsValidMathMLFraction`, `IsValidMathMLScript`, `IsValidMathMLRadical`, `IsValidMultiscript` (These functions check the validity of MathML element structures).
    * **Parameter Calculation:** `GetRadicalHorizontalParameters`, `GetRadicalVerticalParameters`, `GetMinMaxSizesForVerticalStretchyOperator`, `FractionLineThickness`, `MathAxisHeight` (These calculate specific dimensions and properties).
    * **Element Property Retrieval:** `GetMathMLEmbellishedOperatorProperties` (This fetches specific properties of embellished operators).
    * **Helper Functions:** `FirstChildInFlow`, `NextSiblingInFlow`, `InFlowChildCountIs` (These seem to be utility functions for traversing the layout tree).
    * **Special Condition Checks:** `IsUnderOverLaidOutAsSubSup`, `IsTextOnlyToken`, `IsOperatorWithSpecialShaping`, `IsSpaceLike`, `IsStretchyOperator` (These check for specific layout conditions).

4. **Analyze Individual Functions (More Detail):**  Go through each function, reading the code and comments (if available). Pay attention to:
    * **Input Parameters:** What data does the function take?  This gives clues about what information it operates on.
    * **Output/Return Value:** What does the function return? This indicates its purpose (e.g., a boolean for validation, a size or parameter struct).
    * **Internal Logic:** What calculations or checks does the function perform?  Look for uses of other functions or constants. For example, the `GetRadical*Parameters` functions use `MathConstant`, suggesting they retrieve values based on font metrics or style settings. The `IsValid*` functions often iterate through children.
    * **Dependencies:** What other classes or functions does this function call? This reveals relationships within the codebase.

5. **Identify Connections to Web Technologies (JavaScript, HTML, CSS):** Think about how the functionality of this C++ code relates to the front-end web.
    * **HTML:** MathML is embedded directly in HTML using tags like `<math>`, `<mfrac>`, `<msqrt>`, etc. The validation functions directly relate to ensuring these HTML structures are correct according to the MathML specification.
    * **CSS:** CSS styles MathML elements. Functions that calculate sizes or parameters (like `FractionLineThickness` or the radical parameters) often consider `ComputedStyle`, indicating that CSS properties influence the layout. The use of `ValueForLength` confirms this.
    * **JavaScript:** While this C++ code doesn't directly *execute* JavaScript, the *results* of this layout code impact how JavaScript interacts with the rendered MathML. For instance, JavaScript might need to know the dimensions of a MathML element to position other elements relative to it. User interactions handled by JavaScript could trigger re-layout, which would involve this code.

6. **Look for Logic and Assumptions:**  Note any specific logic or assumptions made in the code. For example, the `IsValidMultiscript` function has specific rules about the order and presence of `<mprescripts>`. This reflects the MathML specification.

7. **Consider Potential User/Programming Errors:**  Think about how incorrect usage of MathML in HTML or bugs in the rendering engine could lead to issues. Invalid MathML structures (e.g., an `<mfrac>` with one child) would be flagged by the validation functions. Incorrect or missing font data could impact parameter calculations.

8. **Structure the Explanation:** Organize the findings into clear categories (Functionality, Relationship to Web Technologies, Logical Reasoning, User/Programming Errors). Use bullet points and examples to make the explanation easy to understand.

9. **Refine and Elaborate:** Review the explanation for clarity and completeness. Add more details or examples where needed. For instance, when explaining the connection to CSS, mention specific CSS properties like `math-depth`, `font-size`, etc. For logical reasoning, provide concrete examples of input and expected output.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just does layout calculations."  **Correction:** Realized that it also includes validation logic, which is crucial for correct rendering.
* **Initial thought:** "The connections to web technologies are obvious." **Refinement:**  Needed to provide *specific* examples of how the C++ code interacts with HTML (MathML tags), CSS (styling), and how the *outcomes* affect JavaScript.
* **Initial thought:** "The logical reasoning is simple." **Refinement:**  Decided to include hypothetical input/output examples to make the logic more tangible and easier to grasp.
* **Initial thought:** "User errors are just syntax mistakes." **Refinement:** Considered errors that might be harder to spot, like relying on default values when fonts are missing.

By following these steps, including careful reading, categorization, analysis of individual components, and consideration of the broader context, a comprehensive understanding of the `math_layout_utils.cc` file can be developed.
这个文件 `blink/renderer/core/layout/mathml/math_layout_utils.cc` 是 Chromium Blink 引擎中专门用于 MathML (Mathematical Markup Language) 布局计算的工具函数集合。它提供了一系列静态函数，用于处理 MathML 元素的布局和尺寸计算，以及验证 MathML 结构的有效性。

以下是该文件的主要功能：

**1. 创建布局约束 (Constraint Space):**

* **`CreateConstraintSpaceForMathChild`:**  为 MathML 元素的子节点创建布局约束空间。布局约束空间定义了子节点在布局过程中可用的尺寸、百分比解析、缓存槽等信息。
    * **与 CSS 关系:**  该函数接收父节点的 `ComputedStyle`，这意味着 MathML 元素的布局会受到 CSS 样式的影响，例如 `font-size`、`direction` 等。
    * **假设输入与输出:**
        * **假设输入:** 一个父 MathML 元素的 `BlockNode`，子元素的预期可用尺寸 `child_available_size`，父元素的 `ConstraintSpace`，子元素的 `LayoutInputNode` 等。
        * **输出:**  根据输入创建的 `ConstraintSpace` 对象，包含了适用于子元素的布局约束信息。

**2. 计算最小和最大内容贡献 (Min/Max Content Contribution):**

* **`ComputeMinAndMaxContentContributionForMathChild`:**  计算 MathML 子节点对其父节点的最小和最大内容尺寸贡献。这对于确定父节点的尺寸至关重要。
    * **与 CSS 关系:** 同样接收父节点的 `ComputedStyle`，意味着 CSS 样式会影响内容尺寸的计算。例如，子元素的边距 (margins) 会被考虑在内。
    * **假设输入与输出:**
        * **假设输入:** 父元素的 `ComputedStyle`，父元素的 `ConstraintSpace`，子元素的 `BlockNode`，子元素可用的块状尺寸 `child_available_block_size`。
        * **输出:**  一个 `MinMaxSizesResult` 对象，包含子元素的最小和最大内联尺寸。

**3. 遍历布局树:**

* **`FirstChildInFlow`:**  获取一个节点的第一个处于正常流中的子节点（排除浮动和绝对定位的子节点）。
* **`NextSiblingInFlow`:** 获取一个节点的下一个处于正常流中的兄弟节点。
* **`InFlowChildCountIs`:**  检查一个节点是否正好有指定数量的处于正常流中的子节点。

**4. 验证 MathML 结构的有效性:**

* **`IsValidMathMLFraction`:**  验证一个节点是否是有效的 `<mfrac>` (分数) 元素，即它是否恰好有两个处于正常流中的子节点（分子和分母）。
    * **与 HTML 关系:**  直接关联到 HTML 中 `<mfrac>` 标签的正确使用。
    * **用户/编程常见的使用错误:**
        * **错误示例:**  `<mfrac> <mn>1</mn> </mfrac>` (缺少分母) 或者 `<mfrac> <mn>1</mn> <mn>2</mn> <mn>3</mn> </mfrac>` (多于两个子节点)。
* **`IsValidMultiscript`:**  验证一个节点是否是有效的 `<mmultiscripts>` (多重上标/下标) 元素，根据 MathML 规范检查其子节点的结构，包括是否存在 `<mprescripts>` 分隔符。
    * **与 HTML 关系:** 关联到 HTML 中 `<mmultiscripts>` 和 `<mprescripts>` 标签的正确使用。
    * **用户/编程常见的使用错误:**  不正确的子节点顺序或 `<mprescripts>` 的使用，例如 `<mmultiscripts> <mn>1</mn> <mn>2</mn> <mprescripts/> <mn>3</mn> </mmultiscripts>` 是有效的，但 `<mmultiscripts> <mprescripts/> <mn>1</mn> <mn>2</mn> <mn>3</mn> </mmultiscripts>` 则可能无效。
* **`IsValidMathMLScript`:**  根据节点的 `ScriptType()` 验证 `<msub>` (下标), `<msup>` (上标), `<msubsup>` (上下标), `<munder>` (下划线), `<mover>` (上划线), `<munderover>` (上下划线), `<mmultiscripts>` 等脚本元素的子节点数量是否正确。
    * **与 HTML 关系:** 关联到各种 MathML 脚本标签的正确使用。
    * **用户/编程常见的使用错误:**  例如，`<msub> <mn>1</mn> </msub>` (缺少下标) 或者 `<msubsup> <mn>1</mn> <mn>2</mn> </msubsup>` (缺少上标)。
* **`IsValidMathMLRadical`:** 验证一个节点是否是有效的 `<msqrt>` (平方根) 或 `<mroot>` (n 次根) 元素。对于 `<mroot>`，它需要有两个子节点（根式和指数）。
    * **与 HTML 关系:** 关联到 HTML 中 `<msqrt>` 和 `<mroot>` 标签的正确使用。
    * **用户/编程常见的使用错误:**  `<mroot> <mn>8</mn> </mroot>` (对于 `mroot` 缺少指数)。

**5. 获取 MathML 元素的布局参数:**

* **`GetRadicalHorizontalParameters`:** 获取根号的水平布局参数，如根号前的核间距和根号后的核间距。
* **`GetRadicalVerticalParameters`:** 获取根号的垂直布局参数，如根号线的粗细、垂直间隙、额外的上升高度等。
* **`GetMinMaxSizesForVerticalStretchyOperator`:**  计算垂直方向可伸缩运算符的最小和最大尺寸。
    * **与 CSS 关系:**  运算符的伸缩行为可能受到字体和 CSS 样式的影响。
* **`FractionLineThickness`:** 获取分数线的粗细。
    * **与 CSS 关系:**  可以受到 CSS 属性 `math-fraction-bar-thickness` 的影响。
* **`MathAxisHeight`:** 获取数学轴的高度，这是 MathML 布局中的一个重要基准线。
    * **与 CSS 关系:**  通常与字体的 `x-height` 相关。
* **`MathTableBaseline`:** 计算 MathML 表格的基线位置。

**6. 判断 MathML 元素的特性:**

* **`IsUnderOverLaidOutAsSubSup`:** 判断 `<munder>` 或 `<mover>` 元素是否应该像 `<msubsup>` 那样布局（即上下标形式），这取决于其基元素的特性。
* **`IsTextOnlyToken`:** 判断一个节点是否是仅包含文本内容的 token 元素 (例如 `<mn>`, `<mi>`, `<mtext>`)。
* **`IsOperatorWithSpecialShaping`:** 判断一个 token 元素是否是具有特殊形状的运算符 (例如可伸缩运算符或大型运算符)。
    * **与 CSS 关系:**  运算符的 "stretchy" 和 "largeop" 属性可能受到 MathML 属性或默认行为的影响。
* **`IsSpaceLike`:** 判断一个 MathML 元素是否被认为是 "space-like"，即它本身就是一个空格元素 (`<mspace>`) 或者是一个只包含空格类子元素的组合元素。
* **`GetCoreOperator`:**  从一个可能被装饰的 MathML 结构中提取核心的 `<mo>` (运算符) 元素。
* **`GetMathMLEmbellishedOperatorProperties`:** 获取一个被装饰的运算符的属性，例如是否有可移动的 limits (用于 `<munderover>` 等)，是否可伸缩，是否是大型运算符，以及左右间距。
    * **与 CSS 关系:**  运算符的间距可能受到 CSS 属性 `math-lspace` 和 `math-rspace` 的影响。
* **`IsStretchyOperator`:** 判断一个节点是否是指定方向上可伸缩的运算符。

**总结:**

`math_layout_utils.cc` 文件是 Blink 引擎中处理 MathML 布局的核心工具集。它提供了用于创建布局约束、计算尺寸、验证结构以及获取和判断 MathML 元素特性的各种函数。 这些功能直接关系到 MathML 在网页上的正确渲染，并会受到 HTML 结构和 CSS 样式的双重影响。 开发者在使用 MathML 时如果结构不符合规范，或者浏览器引擎在处理布局时出现错误，都可能导致渲染问题。

Prompt: 
```
这是目录为blink/renderer/core/layout/mathml/math_layout_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/mathml/math_layout_utils.h"

#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/mathml/mathml_fraction_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_operator_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_radical_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_scripts_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_token_element.h"

namespace blink {

ConstraintSpace CreateConstraintSpaceForMathChild(
    const BlockNode& parent_node,
    const LogicalSize& child_available_size,
    const ConstraintSpace& parent_space,
    const LayoutInputNode& child,
    LayoutResultCacheSlot cache_slot,
    const std::optional<ConstraintSpace::MathTargetStretchBlockSizes>
        target_stretch_block_sizes,
    const std::optional<LayoutUnit> target_stretch_inline_size) {
  const ComputedStyle& parent_style = parent_node.Style();
  const ComputedStyle& child_style = child.Style();
  DCHECK(child.CreatesNewFormattingContext());
  ConstraintSpaceBuilder builder(
      parent_space, child_style.GetWritingDirection(), true /* is_new_fc */);
  SetOrthogonalFallbackInlineSizeIfNeeded(parent_style, child, &builder);
  builder.SetAvailableSize(child_available_size);
  builder.SetPercentageResolutionSize(child_available_size);
  builder.SetCacheSlot(cache_slot);
  if (target_stretch_block_sizes)
    builder.SetTargetStretchBlockSizes(*target_stretch_block_sizes);
  if (target_stretch_inline_size)
    builder.SetTargetStretchInlineSize(*target_stretch_inline_size);

  // TODO(crbug.com/1125137): add ink metrics.
  return builder.ToConstraintSpace();
}

MinMaxSizesResult ComputeMinAndMaxContentContributionForMathChild(
    const ComputedStyle& parent_style,
    const ConstraintSpace& parent_space,
    const BlockNode& child,
    LayoutUnit child_available_block_size) {
  DCHECK(child.CreatesNewFormattingContext());
  MinMaxConstraintSpaceBuilder builder(parent_space, parent_style, child,
                                       true /* is_new_fc */);
  builder.SetAvailableBlockSize(child_available_block_size);
  builder.SetPercentageResolutionBlockSize(child_available_block_size);
  const auto space = builder.ToConstraintSpace();

  auto result = ComputeMinAndMaxContentContribution(parent_style, child, space);

  // Add margins directly here.
  result.sizes +=
      ComputeMarginsFor(space, child.Style(), parent_space).InlineSum();

  return result;
}

LayoutInputNode FirstChildInFlow(const BlockNode& node) {
  LayoutInputNode child = node.FirstChild();
  while (child && child.IsOutOfFlowPositioned())
    child = child.NextSibling();
  return child;
}

LayoutInputNode NextSiblingInFlow(const BlockNode& node) {
  LayoutInputNode sibling = node.NextSibling();
  while (sibling && sibling.IsOutOfFlowPositioned())
    sibling = sibling.NextSibling();
  return sibling;
}

inline bool InFlowChildCountIs(const BlockNode& node, unsigned count) {
  DCHECK(count == 2 || count == 3);
  auto child = To<BlockNode>(FirstChildInFlow(node));
  while (count && child) {
    child = To<BlockNode>(NextSiblingInFlow(child));
    count--;
  }
  return !count && !child;
}

bool IsValidMathMLFraction(const BlockNode& node) {
  return InFlowChildCountIs(node, 2);
}

static bool IsPrescriptDelimiter(const BlockNode& block_node) {
  auto* node = block_node.GetDOMNode();
  return node && IsA<MathMLElement>(node) &&
         node->HasTagName(mathml_names::kMprescriptsTag);
}

// Valid according to:
// https://w3c.github.io/mathml-core/#prescripts-and-tensor-indices-mmultiscripts
inline bool IsValidMultiscript(const BlockNode& node) {
  auto child = To<BlockNode>(FirstChildInFlow(node));
  if (!child || IsPrescriptDelimiter(child))
    return false;
  bool number_of_scripts_is_even = true;
  bool prescript_delimiter_found = false;
  while (child) {
    child = To<BlockNode>(NextSiblingInFlow(child));
    if (!child)
      continue;
    if (IsPrescriptDelimiter(child)) {
      if (!number_of_scripts_is_even || prescript_delimiter_found)
        return false;
      prescript_delimiter_found = true;
      continue;
    }
    number_of_scripts_is_even = !number_of_scripts_is_even;
  }
  return number_of_scripts_is_even;
}

bool IsValidMathMLScript(const BlockNode& node) {
  switch (node.ScriptType()) {
    case MathScriptType::kUnder:
    case MathScriptType::kOver:
    case MathScriptType::kSub:
    case MathScriptType::kSuper:
      return InFlowChildCountIs(node, 2);
    case MathScriptType::kSubSup:
    case MathScriptType::kUnderOver:
      return InFlowChildCountIs(node, 3);
    case MathScriptType::kMultiscripts:
      return IsValidMultiscript(node);
    default:
      NOTREACHED();
  }
}

bool IsValidMathMLRadical(const BlockNode& node) {
  auto* radical =
      DynamicTo<MathMLRadicalElement>(node.GetDOMNode());
  return !radical->HasIndex() || InFlowChildCountIs(node, 2);
}

RadicalHorizontalParameters GetRadicalHorizontalParameters(
    const ComputedStyle& style) {
  RadicalHorizontalParameters parameters;
  parameters.kern_before_degree = LayoutUnit(
      MathConstant(style,
                   OpenTypeMathSupport::MathConstants::kRadicalKernBeforeDegree)
          .value_or(5 * style.FontSize() * kMathUnitFraction));
  parameters.kern_after_degree = LayoutUnit(
      MathConstant(style,
                   OpenTypeMathSupport::MathConstants::kRadicalKernAfterDegree)
          .value_or(-10 * style.FontSize() * kMathUnitFraction));
  return parameters;
}

RadicalVerticalParameters GetRadicalVerticalParameters(
    const ComputedStyle& style,
    bool has_index) {
  RadicalVerticalParameters parameters;
  bool has_display = HasDisplayStyle(style);
  float rule_thickness = RuleThicknessFallback(style);
  const SimpleFontData* font_data = style.GetFont().PrimaryFont();
  float x_height = font_data ? font_data->GetFontMetrics().XHeight() : 0;
  parameters.rule_thickness = LayoutUnit(
      MathConstant(style,
                   OpenTypeMathSupport::MathConstants::kRadicalRuleThickness)
          .value_or(rule_thickness));
  parameters.vertical_gap = LayoutUnit(
      MathConstant(
          style, has_display
                     ? OpenTypeMathSupport::MathConstants::
                           kRadicalDisplayStyleVerticalGap
                     : OpenTypeMathSupport::MathConstants::kRadicalVerticalGap)
          .value_or(has_display ? rule_thickness + x_height / 4
                                : 5 * rule_thickness / 4));
  parameters.extra_ascender = LayoutUnit(
      MathConstant(style,
                   OpenTypeMathSupport::MathConstants::kRadicalExtraAscender)
          .value_or(parameters.rule_thickness));
  if (has_index) {
    parameters.degree_bottom_raise_percent =
        MathConstant(style, OpenTypeMathSupport::MathConstants::
                                kRadicalDegreeBottomRaisePercent)
            .value_or(.6);
  }
  return parameters;
}

MinMaxSizes GetMinMaxSizesForVerticalStretchyOperator(
    const ComputedStyle& style,
    UChar character) {
  // https://w3c.github.io/mathml-core/#dfn-preferred-inline-size-of-a-glyph-stretched-along-the-block-axis
  const SimpleFontData* font_data = style.GetFont().PrimaryFont();
  MinMaxSizes sizes;
  if (!font_data)
    return sizes;

  if (auto base_glyph = font_data->GlyphForCharacter(character)) {
    sizes.Encompass(LayoutUnit(font_data->WidthForGlyph(base_glyph)));

    const HarfBuzzFace* harfbuzz_face =
        font_data->PlatformData().GetHarfBuzzFace();

    for (auto& variant : OpenTypeMathSupport::GetGlyphVariantRecords(
             harfbuzz_face, base_glyph, OpenTypeMathStretchData::Vertical)) {
      sizes.Encompass(LayoutUnit(font_data->WidthForGlyph(variant)));
    }

    for (auto& part : OpenTypeMathSupport::GetGlyphPartRecords(
             harfbuzz_face, base_glyph,
             OpenTypeMathStretchData::StretchAxis::Vertical)) {
      sizes.Encompass(LayoutUnit(font_data->WidthForGlyph(part.glyph)));
    }
  }

  return sizes;
}

bool IsUnderOverLaidOutAsSubSup(const BlockNode& node) {
  DCHECK(IsValidMathMLScript(node));
  if (HasDisplayStyle(node.Style()))
    return false;
  if (!node.IsBlock() || !node.IsMathML())
    return false;
  const auto base = To<BlockNode>(FirstChildInFlow(node));
  const auto base_properties = GetMathMLEmbellishedOperatorProperties(base);
  return base_properties && base_properties->has_movablelimits;
}

bool IsTextOnlyToken(const BlockNode& node) {
  if (!node.IsBlock() || !node.IsMathML() || !node.FirstChild().IsInline())
    return false;
  if (auto* element = DynamicTo<MathMLTokenElement>(node.GetDOMNode()))
    return !element->GetTokenContent().characters.IsNull();
  return false;
}

bool IsOperatorWithSpecialShaping(const BlockNode& node) {
  if (!IsTextOnlyToken(node))
    return false;
  // https://w3c.github.io/mathml-core/#layout-of-operators
  if (auto* element = DynamicTo<MathMLOperatorElement>(node.GetDOMNode())) {
    UChar32 base_code_point = element->GetTokenContent().code_point;
    if (base_code_point == kNonCharacter ||
        !node.Style().GetFont().PrimaryFont() ||
        !node.Style().GetFont().PrimaryFont()->GlyphForCharacter(
            base_code_point))
      return false;

    if (element->HasBooleanProperty(MathMLOperatorElement::kStretchy))
      return true;

    if (element->HasBooleanProperty(MathMLOperatorElement::kLargeOp) &&
        HasDisplayStyle(node.Style()))
      return true;
  }
  return false;
}

namespace {

inline LayoutUnit DefaultFractionLineThickness(const ComputedStyle& style) {
  return LayoutUnit(
      MathConstant(style,
                   OpenTypeMathSupport::MathConstants::kFractionRuleThickness)
          .value_or(RuleThicknessFallback(style)));
}

}  // namespace

LayoutUnit MathAxisHeight(const ComputedStyle& style) {
  const SimpleFontData* font_data = style.GetFont().PrimaryFont();
  float x_height = font_data ? font_data->GetFontMetrics().XHeight() : 0;
  return LayoutUnit(
      MathConstant(style, OpenTypeMathSupport::MathConstants::kAxisHeight)
          .value_or(x_height / 2));
}

LayoutUnit FractionLineThickness(const ComputedStyle& style) {
  return std::max<LayoutUnit>(
      ValueForLength(style.GetMathFractionBarThickness(),
                     DefaultFractionLineThickness(style)),
      LayoutUnit());
}

LayoutUnit MathTableBaseline(const ComputedStyle& style,
                             LayoutUnit block_offset) {
  // The center of the table is aligned with the math axis.
  // See: https://w3c.github.io/mathml-core/#table-or-matrix-mtable
  return LayoutUnit(block_offset / 2 + MathAxisHeight(style));
}

namespace {

// This function has bad theoretical worst-case complexity. However, real-life
// MathML formulas don't use deeply nested space-like expressions so it should
// be fine in in practice. See https://github.com/w3c/mathml/issues/115
static bool IsSpaceLike(const BlockNode& node) {
  DCHECK(node);
  if (!node.IsMathML())
    return false;
  // See https://w3c.github.io/mathml-core/#dfn-space-like
  const auto* element = DynamicTo<MathMLElement>(node.GetDOMNode());
  // 1. An <mtext> or <mspace>;
  if (element && (element->HasTagName(mathml_names::kMtextTag) ||
                  element->HasTagName(mathml_names::kMspaceTag)))
    return true;
  // 2. Or a grouping element or <mpadded> all of whose in-flow children are
  // space-like.
  // Note: This also handles the case of anonymous <mrow>'s generated by
  // <msqrt> and <mpadded> elements.
  if ((element && (element->IsGroupingElement() ||
                   element->HasTagName(mathml_names::kMpaddedTag))) ||
      node.IsAnonymous()) {
    for (auto child = To<BlockNode>(FirstChildInFlow(node)); child;
         child = To<BlockNode>(NextSiblingInFlow(child))) {
      if (!IsSpaceLike(child))
        return false;
    }
    return true;
  }
  return false;
}

// This function has bad theoretical worst-case complexity. However, real-life
// MathML formulas don't use deeply nested expressions that are embellished
// operators or that are essentially made of space-like descendants, so it
// should be fine in in practice. See https://github.com/w3c/mathml/issues/115
MathMLOperatorElement* GetCoreOperator(const BlockNode& node) {
  if (!node || !node.IsMathML())
    return nullptr;

  // See https://w3c.github.io/mathml-core/#embellished-operators
  auto* element = DynamicTo<MathMLElement>(node.GetDOMNode());
  if (element && element->HasTagName(mathml_names::kMoTag)) {
    // 1. An <mo> element;
    return To<MathMLOperatorElement>(element);
  }
  if (element && (IsA<MathMLScriptsElement>(element) ||
                  element->HasTagName(mathml_names::kMfracTag))) {
    // 2. A scripted element or an <mfrac>, whose first in-flow child exists
    // and is an embellished operator;
    auto first_child = FirstChildInFlow(node);
    return IsA<BlockNode>(first_child)
               ? GetCoreOperator(To<BlockNode>(first_child))
               : nullptr;
  }
  if ((element && (element->IsGroupingElement() ||
                   element->HasTagName(mathml_names::kMpaddedTag))) ||
      node.IsAnonymous()) {
    // 3. A grouping element or <mpadded>, whose in-flow children consist (in
    // any order) of one embellished operator and zero or more space-like
    // elements.
    // Note: This also handles the case of anonymous <mrow>'s generated by
    // <msqrt> and <mpadded> elements.
    MathMLOperatorElement* core_operator = nullptr;
    for (auto child = To<BlockNode>(FirstChildInFlow(node)); child;
         child = To<BlockNode>(NextSiblingInFlow(child))) {
      // Skip space-like children as they don't affect whether the parent is an
      // embellished operator.
      if (IsSpaceLike(child))
        continue;

      // The parent is not an embellished operator if it contains two children
      // that are not space-like.
      if (core_operator)
        return nullptr;
      core_operator = GetCoreOperator(child);

      // The parent is not an embellished operator if it contains a child that
      // is neither space-like nor an embellished operator.
      if (!core_operator)
        return nullptr;
    }
    return core_operator;
  }
  return nullptr;
}

}  // namespace

std::optional<MathMLEmbellishedOperatorProperties>
GetMathMLEmbellishedOperatorProperties(const BlockNode& node) {
  auto* core_operator = GetCoreOperator(node);
  if (!core_operator)
    return std::nullopt;
  DCHECK(core_operator->GetLayoutObject());
  const auto& core_operator_style =
      core_operator->GetLayoutObject()->StyleRef();

  MathMLEmbellishedOperatorProperties properties;

  properties.has_movablelimits =
      core_operator->HasBooleanProperty(MathMLOperatorElement::kMovableLimits);

  properties.is_stretchy =
      core_operator->HasBooleanProperty(MathMLOperatorElement::kStretchy);

  properties.is_large_op =
      core_operator->HasBooleanProperty(MathMLOperatorElement::kLargeOp);

  properties.is_vertical = core_operator->IsVertical();

  LayoutUnit leading_space(core_operator->DefaultLeadingSpace() *
                           core_operator_style.FontSize());
  properties.lspace =
      ValueForLength(core_operator_style.GetMathLSpace(), leading_space)
          .ClampNegativeToZero();

  LayoutUnit trailing_space(core_operator->DefaultTrailingSpace() *
                            core_operator_style.FontSize());
  properties.rspace =
      ValueForLength(core_operator_style.GetMathRSpace(), trailing_space)
          .ClampNegativeToZero();

  return properties;
}

bool IsStretchyOperator(const BlockNode& node, bool stretch_axis_is_vertical) {
  const auto properties = GetMathMLEmbellishedOperatorProperties(node);
  return properties && properties->is_stretchy &&
         properties->is_vertical == stretch_axis_is_vertical;
}

}  // namespace blink

"""

```