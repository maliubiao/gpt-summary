Response:
Let's break down the thought process for analyzing the `ink_overflow.cc` file and generating the explanation.

1. **Understand the Goal:** The primary goal is to explain the functionality of the `InkOverflow` class in the given Chromium Blink source code file and its relation to web technologies.

2. **Initial Scan and Keyword Identification:**  First, I'd quickly scan the code for important keywords and patterns. This includes:
    * Class name: `InkOverflow`
    * `#include` directives:  These reveal dependencies and related areas. Notice headers related to layout, editing (markers), highlighting, painting, and styling.
    * Data members:  `single_`, `container_`, `outsets_`, `type_`. These suggest different ways of storing ink overflow information.
    * Methods with descriptive names: `Self`, `Contents`, `SelfAndContents`, `SetSelf`, `SetContents`, `SetTextInkOverflow`, `ComputeTextInkOverflow`, `ComputeDecorationOverflow`, etc. These are the core functions we need to understand.
    * `enum Type`: This defines the different states or representations of ink overflow.
    * `#ifdef DCHECK_IS_ON()`: Indicates debugging-related code.
    *  Uses of `PhysicalRect`, `PhysicalSize`, `LogicalRect`, `LayoutUnit`:  These point to layout and geometry concepts.

3. **Deconstructing the Class Structure:**  Based on the scanned information, I can start to build a mental model of the `InkOverflow` class:
    * It's designed to store information about how far content "inks" or bleeds outside its normal bounds.
    * It seems to have different ways to represent this overflow:
        * No overflow (`kNone`).
        * Small overflow using an array of `outsets_`.
        * Larger overflow stored in a `SingleInkOverflow` object.
        * Separate self and content overflow in a `ContainerInkOverflow` object.
    * The `Type` enum manages the active representation.

4. **Analyzing Key Methods and Their Functionality:** I'd now focus on the crucial methods:

    * **`Self()`, `Contents()`, `SelfAndContents()`:** These methods retrieve the stored ink overflow information for the element itself, its contents, or both, respectively. The `switch` statements based on `Type` are essential for understanding how the data is accessed in each case.
    * **`SetSelf()`, `SetContents()`, `Set()`:** These methods set the ink overflow values. The logic for deciding between small and large storage (`TrySetOutsets`) is important.
    * **`SetTextInkOverflow()` and `SetSvgTextInkOverflow()`:** These are specific methods for calculating and setting ink overflow for text content, distinguishing between regular HTML text and SVG text.
    * **`ComputeTextInkOverflow()`:** This is a core method. I'd look at its internal logic:
        * It uses `scaled_font.TextInkBounds()` to get the basic ink bounds of the text.
        * It then considers text decorations, emphasis marks, and shadows.
        * It calls other `Compute...Overflow` methods for specific aspects.
    * **`ComputeDecorationOverflow()`:** This method calculates the overflow caused by text decorations (underline, overline, line-through, spelling/grammar errors). It also considers decorations from selections and markers.
    * **`ComputeMarkerOverflow()` and `ComputeCustomHighlightOverflow()`:** These methods handle the overflow caused by different types of document markers (text fragments, custom highlights, spelling/grammar errors).

5. **Connecting to Web Technologies (JavaScript, HTML, CSS):** Now, I'd consider how the functionalities relate to web development:

    * **CSS:**
        * `text-decoration`:  Directly related to `ComputeDecorationOverflow()`.
        * `text-shadow`: Related to `ExpandForShadowOverflow()`.
        * `text-emphasis`: Related to `ComputeEmphasisMarkOverflow()`.
        * `::selection`:  The code explicitly handles selection-based text decorations.
        * Custom highlights (using the CSS Custom Highlight API): Directly connected to `ComputeCustomHighlightOverflow()`.
    * **HTML:** The structure of the HTML document and the text content within it are what the `InkOverflow` class operates on. The `InlineCursor` and `FragmentItem` are tied to how the layout engine breaks down HTML content.
    * **JavaScript:** While the C++ code itself isn't directly JavaScript, JavaScript APIs can trigger layout and rendering, which in turn would involve the `InkOverflow` calculations. For instance, modifying the DOM or CSS styles via JavaScript could lead to updates in ink overflow. The Custom Highlight API, often used via JavaScript, is a prime example.

6. **Logical Reasoning and Examples:**  For each functional aspect, I'd try to construct simple examples to illustrate the input and output:

    * **Basic Text Overflow:** A simple `<div>` with overflowing text.
    * **Text Decoration Overflow:**  Text with underlines or other decorations that extend beyond the text itself.
    * **Shadow Overflow:** Text with a large text shadow.
    * **Marker Overflow:**  Text with spelling errors or custom highlights.

7. **Identifying Common Usage Errors:**  I'd think about potential mistakes developers might make that could relate to ink overflow:

    * Assuming content is clipped when it's actually overflowing (especially with decorations or shadows).
    * Incorrectly calculating the size of elements due to not considering ink overflow.
    * Issues with overlapping content if ink overflow isn't accounted for.

8. **Structuring the Explanation:**  Finally, I'd organize the information logically:

    * Start with a concise summary of the file's purpose.
    * Break down the key functionalities.
    * Provide concrete examples for each connection to web technologies.
    * Include examples of logical reasoning with input and output.
    * Highlight common usage errors.

9. **Refinement and Review:** I'd reread the explanation to ensure clarity, accuracy, and completeness. I'd check if the examples are easy to understand and if the connections to web technologies are well-explained. For instance, initially, I might just say "handles text decorations," but refining it to mention specific CSS properties like `text-decoration-line` makes it much clearer.

This iterative process of scanning, deconstructing, analyzing, connecting, exemplifying, and structuring helps in creating a comprehensive and understandable explanation of the given source code.
这个文件 `blink/renderer/core/layout/ink_overflow.cc` 的主要功能是**计算和存储渲染对象（LayoutObject）的 “墨水溢出”（Ink Overflow）区域**。

**墨水溢出** 指的是渲染对象在绘制时，其视觉效果（如文本装饰线、阴影、标记等）可能超出其内容边界的区域。理解和跟踪墨水溢出对于正确的布局、绘制和命中测试至关重要。

以下是该文件功能的详细说明，并结合 JavaScript, HTML, CSS 的关系进行举例：

**1. 核心功能：计算墨水溢出区域**

`InkOverflow` 类负责计算三种类型的墨水溢出：

* **自身墨水溢出 (Self Ink Overflow):**  指的是渲染对象自身产生的视觉效果超出其内容盒子的区域，例如 `text-shadow` 导致的阴影。
* **内容墨水溢出 (Contents Ink Overflow):** 指的是渲染对象的子内容（主要是文本）产生的视觉效果超出其内容盒子的区域，例如文本的下划线或拼写错误标记。
* **自身和内容墨水溢出 (Self and Contents Ink Overflow):**  包含以上两种溢出的总和。

该文件中的 `ComputeTextInkOverflow`, `ComputeDecorationOverflow`, `ComputeEmphasisMarkOverflow`, `ExpandForShadowOverflow`, `ComputeMarkerOverflow`, `ComputeCustomHighlightOverflow` 等方法都是用于计算不同视觉效果造成的墨水溢出。

**与 JavaScript, HTML, CSS 的关系举例：**

* **CSS `text-decoration` (如 `underline`, `overline`, `line-through`)：**
    * 当 HTML 元素应用了 `text-decoration` 样式时，`ComputeDecorationOverflow` 函数会被调用来计算这些装饰线超出文本内容区域的范围。
    * **假设输入：** 一个包含文本 "Hello" 的 `<span>` 元素，CSS 样式为 `text-decoration: underline;`。
    * **逻辑推理：** `ComputeDecorationOverflow` 会根据字体大小、下划线的位置和粗细，计算出下划线向下延伸超出文本内容盒子的距离。
    * **输出：**  `InkOverflow` 对象会存储一个 `Contents` 类型的溢出区域，其底部边界会超出文本内容盒子的底部。

* **CSS `text-shadow`：**
    * 当 HTML 元素应用了 `text-shadow` 样式时，`ExpandForShadowOverflow` 函数会被调用来计算阴影向外扩展的范围。
    * **假设输入：** 一个包含文本 "World" 的 `<div>` 元素，CSS 样式为 `text-shadow: 2px 2px 5px black;`。
    * **逻辑推理：** `ExpandForShadowOverflow` 会根据阴影的偏移量 (2px, 2px) 和模糊半径 (5px)，计算出阴影向各个方向扩展的距离。
    * **输出：** `InkOverflow` 对象会存储一个 `Self` 类型的溢出区域，其边界会超出文本内容盒子的各个方向。

* **CSS `text-emphasis`：**
    * 当 HTML 元素应用了 `text-emphasis` 样式时，`ComputeEmphasisMarkOverflow` 函数会被调用来计算强调标记超出文本内容区域的范围。
    * **假设输入：** 一个包含文本 "啊" 的 `<p>` 元素，CSS 样式为 `text-emphasis: filled sesame over red;`。
    * **逻辑推理：** `ComputeEmphasisMarkOverflow` 会根据强调标记的形状、大小和位置（`over` 或 `under`），计算出其超出文本内容盒子的距离。
    * **输出：** `InkOverflow` 对象会存储一个 `Contents` 类型的溢出区域，其顶部或底部边界会超出文本内容盒子的相应方向。

* **浏览器拼写或语法检查标记：**
    * 当浏览器检测到拼写或语法错误时，会添加相应的标记。`ComputeMarkerOverflow` 函数会被调用来计算这些标记超出文本内容区域的范围。
    * **假设输入：** 一个包含拼写错误的单词 "worlld" 的 `<div>` 元素。
    * **逻辑推理：** `ComputeMarkerOverflow` 会根据波浪线的形状和位置，计算出其向下延伸超出文本内容盒子的距离。
    * **输出：** `InkOverflow` 对象会存储一个 `Contents` 类型的溢出区域，其底部边界会超出文本内容盒子的底部。

* **JavaScript Custom Highlight API：**
    * 当 JavaScript 代码使用 Custom Highlight API (例如 `CSS.highlights.set()`) 来高亮文本时，`ComputeCustomHighlightOverflow` 函数会被调用来计算高亮效果（例如背景色或文本装饰线）超出文本内容区域的范围。
    * **假设输入：**  JavaScript 代码使用 Custom Highlight API 将文本 "Example" 的一部分高亮显示，并设置了背景色和下划线。
    * **逻辑推理：** `ComputeCustomHighlightOverflow` 会根据高亮的样式（背景色不会溢出，但下划线会溢出），计算出溢出区域。
    * **输出：** `InkOverflow` 对象会存储一个 `Contents` 类型的溢出区域，如果高亮有文本装饰线，则其边界会超出文本内容盒子。

**2. 存储墨水溢出信息**

`InkOverflow` 类使用不同的内部表示来存储墨水溢出信息，以优化内存使用：

* **`kNone`:**  表示没有墨水溢出。
* **`kSmallSelf`, `kSmallContents`:** 使用小的定长数组 `outsets_` 来存储溢出边界的偏移量。适用于溢出量较小的情况。
* **`kSelf`, `kContents`:** 使用 `SingleInkOverflow` 对象来存储一个矩形的溢出区域。
* **`kSelfAndContents`:** 使用 `ContainerInkOverflow` 对象来分别存储自身和内容的溢出区域。

**3. 提供访问接口**

`InkOverflow` 类提供了 `Self()`, `Contents()`, `SelfAndContents()` 等方法来获取计算出的墨水溢出区域。这些方法会根据内部存储的类型返回相应的 `PhysicalRect`。

**4. 调试支持**

该文件包含一些使用 `#ifdef DCHECK_IS_ON()` 包裹的调试代码，用于在开发版本中检查潜在的错误，例如访问未设置的墨水溢出值。

**逻辑推理的假设输入与输出：**

* **假设输入：** 一个没有应用任何视觉效果的 `<div>` 元素。
* **输出：**  `InkOverflow` 对象的类型为 `kNone`，`Self()`, `Contents()`, `SelfAndContents()` 方法返回的矩形与元素的内容盒子完全一致。

* **假设输入：**  一个文本节点，其父元素设置了 `overflow: hidden;` 并且文本有下划线装饰。
* **输出：** `InkOverflow` 对象会计算出下划线造成的 `Contents` 溢出，即使该溢出会被父元素的 `overflow: hidden;` 裁剪掉。`InkOverflow` 的计算是独立的，并不考虑裁剪。

**涉及用户或编程常见的使用错误：**

* **假设用户错误：** 开发者可能错误地认为设置了 `overflow: hidden;` 或 `clip-path` 等 CSS 属性后就不需要考虑墨水溢出。实际上，墨水溢出仍然会发生，只是会被裁剪掉，这可能影响布局计算或命中测试。例如，一个带有阴影的元素，即使阴影被裁剪，其墨水溢出区域仍然会影响鼠标事件的响应范围。

* **假设编程错误：** 在 Blink 引擎的开发中，如果一个布局或绘制相关的代码没有正确地考虑 `InkOverflow`，可能会导致视觉效果绘制不完整或鼠标事件响应错误。例如，在计算元素边界时没有加上墨水溢出的量，可能会导致点击阴影区域时无法选中元素。

**总结：**

`blink/renderer/core/layout/ink_overflow.cc` 文件中的 `InkOverflow` 类是 Chromium Blink 渲染引擎中一个关键的组成部分，负责准确地计算和存储各种视觉效果造成的墨水溢出。这对于确保 Web 页面能够正确地布局、绘制和响应用户交互至关重要。它与 JavaScript, HTML, CSS 的各种视觉特性紧密相关，并为渲染引擎的后续处理提供了必要的信息。

Prompt: 
```
这是目录为blink/renderer/core/layout/ink_overflow.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/ink_overflow.h"

#include "build/chromeos_buildflags.h"
#include "third_party/blink/renderer/core/editing/markers/custom_highlight_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/highlight/highlight_style_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_rect.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/text_decoration_offset.h"
#include "third_party/blink/renderer/core/paint/highlight_painter.h"
#include "third_party/blink/renderer/core/paint/inline_paint_context.h"
#include "third_party/blink/renderer/core/paint/marker_range_mapping_context.h"
#include "third_party/blink/renderer/core/paint/text_decoration_info.h"
#include "third_party/blink/renderer/core/style/applied_text_decoration.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/transforms/affine_transform.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"

namespace blink {

namespace {

struct SameSizeAsInkOverflow {
  void* pointer;
#if DCHECK_IS_ON()
  InkOverflow::Type type;
#endif
};

ASSERT_SIZE(InkOverflow, SameSizeAsInkOverflow);

inline bool HasOverflow(const PhysicalRect& rect, const PhysicalSize& size) {
  if (rect.IsEmpty())
    return false;
  return rect.X() < 0 || rect.Y() < 0 || rect.Right() > size.width ||
         rect.Bottom() > size.height;
}

}  // namespace

#if DCHECK_IS_ON()
// Define this for the debugging purpose to DCHECK if uncomputed ink overflow is
// happening. As DCHECK builds ship, enabling this for all DCHECK builds causes
// more troubles than to help.
//
// #define DISALLOW_READING_UNSET

unsigned InkOverflow::read_unset_as_none_ = 0;

InkOverflow::~InkOverflow() {
  // Because |Type| is kept outside of the instance, callers must call |Reset|
  // before destructing.
  DCHECK(type_ == Type::kNotSet || type_ == Type::kNone ||
         type_ == Type::kInvalidated)
      << static_cast<int>(type_);
}
#endif

InkOverflow::InkOverflow(Type source_type, const InkOverflow& source) {
  source.CheckType(source_type);
  new (this) InkOverflow();
  switch (source_type) {
    case Type::kNotSet:
    case Type::kInvalidated:
    case Type::kNone:
      break;
    case Type::kSmallSelf:
    case Type::kSmallContents:
      static_assert(sizeof(outsets_) == sizeof(single_),
                    "outsets should be the size of a pointer");
      single_ = source.single_;
#if DCHECK_IS_ON()
      for (wtf_size_t i = 0; i < std::size(outsets_); ++i)
        DCHECK_EQ(outsets_[i], source.outsets_[i]);
#endif
      break;
    case Type::kSelf:
    case Type::kContents:
      single_ = new SingleInkOverflow(*source.single_);
      break;
    case Type::kSelfAndContents:
      container_ = new ContainerInkOverflow(*source.container_);
      break;
  }
  SetType(source_type);
}

InkOverflow::InkOverflow(Type source_type, InkOverflow&& source) {
  source.CheckType(source_type);
  new (this) InkOverflow();
  switch (source_type) {
    case Type::kNotSet:
    case Type::kInvalidated:
    case Type::kNone:
      break;
    case Type::kSmallSelf:
    case Type::kSmallContents:
      static_assert(sizeof(outsets_) == sizeof(single_),
                    "outsets should be the size of a pointer");
      single_ = source.single_;
#if DCHECK_IS_ON()
      for (wtf_size_t i = 0; i < std::size(outsets_); ++i)
        DCHECK_EQ(outsets_[i], source.outsets_[i]);
#endif
      break;
    case Type::kSelf:
    case Type::kContents:
      single_ = source.single_;
      source.single_ = nullptr;
      break;
    case Type::kSelfAndContents:
      container_ = source.container_;
      source.container_ = nullptr;
      break;
  }
  SetType(source_type);
}

InkOverflow::Type InkOverflow::Reset(Type type, Type new_type) {
  CheckType(type);
  DCHECK(new_type == Type::kNotSet || new_type == Type::kNone ||
         new_type == Type::kInvalidated);
  switch (type) {
    case Type::kNotSet:
    case Type::kInvalidated:
    case Type::kNone:
    case Type::kSmallSelf:
    case Type::kSmallContents:
      break;
    case Type::kSelf:
    case Type::kContents:
      delete single_;
      break;
    case Type::kSelfAndContents:
      delete container_;
      break;
  }
  return SetType(new_type);
}

PhysicalRect InkOverflow::FromOutsets(const PhysicalSize& size) const {
  const LayoutUnit left_outset(LayoutUnit::FromRawValue(outsets_[0]));
  const LayoutUnit top_outset(LayoutUnit::FromRawValue(outsets_[1]));
  return {-left_outset, -top_outset,
          left_outset + size.width + LayoutUnit::FromRawValue(outsets_[2]),
          top_outset + size.height + LayoutUnit::FromRawValue(outsets_[3])};
}

PhysicalRect InkOverflow::Self(Type type, const PhysicalSize& size) const {
  CheckType(type);
  switch (type) {
    case Type::kNotSet:
    case Type::kInvalidated:
#if defined(DISALLOW_READING_UNSET)
      if (!read_unset_as_none_)
        NOTREACHED();
      [[fallthrough]];
#endif
    case Type::kNone:
    case Type::kSmallContents:
    case Type::kContents:
      return {PhysicalOffset(), size};
    case Type::kSmallSelf:
      return FromOutsets(size);
    case Type::kSelf:
    case Type::kSelfAndContents:
      DCHECK(single_);
      return single_->ink_overflow;
  }
  NOTREACHED();
}

PhysicalRect InkOverflow::Contents(Type type, const PhysicalSize& size) const {
  CheckType(type);
  switch (type) {
    case Type::kNotSet:
    case Type::kInvalidated:
#if defined(DISALLOW_READING_UNSET)
      if (!read_unset_as_none_)
        NOTREACHED();
#endif
    case Type::kNone:
    case Type::kSmallSelf:
    case Type::kSelf:
      return PhysicalRect();
    case Type::kSmallContents:
      return FromOutsets(size);
    case Type::kContents:
      DCHECK(single_);
      return single_->ink_overflow;
    case Type::kSelfAndContents:
      DCHECK(container_);
      return container_->contents_ink_overflow;
  }
  NOTREACHED();
}

PhysicalRect InkOverflow::SelfAndContents(Type type,
                                          const PhysicalSize& size) const {
  CheckType(type);
  switch (type) {
    case Type::kNotSet:
    case Type::kInvalidated:
#if defined(DISALLOW_READING_UNSET)
      if (!read_unset_as_none_)
        NOTREACHED();
#endif
    case Type::kNone:
      return {PhysicalOffset(), size};
    case Type::kSmallSelf:
    case Type::kSmallContents:
      return FromOutsets(size);
    case Type::kSelf:
    case Type::kContents:
      DCHECK(single_);
      return single_->ink_overflow;
    case Type::kSelfAndContents:
      DCHECK(container_);
      return container_->SelfAndContentsInkOverflow();
  }
  NOTREACHED();
}

// Store |ink_overflow| as |SmallRawValue| if possible and returns |true|.
// Returns |false| if |ink_overflow| is too large for |SmallRawValue|.
bool InkOverflow::TrySetOutsets(Type type,
                                LayoutUnit left_outset,
                                LayoutUnit top_outset,
                                LayoutUnit right_outset,
                                LayoutUnit bottom_outset) {
  CheckType(type);
  const LayoutUnit max_small_value(
      LayoutUnit::FromRawValue(std::numeric_limits<SmallRawValue>::max()));
  if (left_outset > max_small_value)
    return false;
  if (top_outset > max_small_value)
    return false;
  if (right_outset > max_small_value)
    return false;
  if (bottom_outset > max_small_value)
    return false;
  Reset(type);
  outsets_[0] = left_outset.RawValue();
  outsets_[1] = top_outset.RawValue();
  outsets_[2] = right_outset.RawValue();
  outsets_[3] = bottom_outset.RawValue();
  return true;
}

InkOverflow::Type InkOverflow::SetSingle(Type type,
                                         const PhysicalRect& ink_overflow,
                                         const PhysicalSize& size,
                                         Type new_type,
                                         Type new_small_type) {
  CheckType(type);
  DCHECK(HasOverflow(ink_overflow, size));

  const LayoutUnit left_outset = (-ink_overflow.X()).ClampNegativeToZero();
  const LayoutUnit top_outset = (-ink_overflow.Y()).ClampNegativeToZero();
  const LayoutUnit right_outset =
      (ink_overflow.Right() - size.width).ClampNegativeToZero();
  const LayoutUnit bottom_outset =
      (ink_overflow.Bottom() - size.height).ClampNegativeToZero();

  if (TrySetOutsets(type, left_outset, top_outset, right_outset, bottom_outset))
    return SetType(new_small_type);

  const PhysicalRect adjusted_ink_overflow(
      -left_outset, -top_outset, left_outset + size.width + right_outset,
      top_outset + size.height + bottom_outset);

  switch (type) {
    case Type::kSelfAndContents:
      Reset(type);
      [[fallthrough]];
    case Type::kNotSet:
    case Type::kInvalidated:
    case Type::kNone:
    case Type::kSmallSelf:
    case Type::kSmallContents:
      single_ = new SingleInkOverflow(adjusted_ink_overflow);
      return SetType(new_type);
    case Type::kSelf:
    case Type::kContents:
      DCHECK(single_);
      single_->ink_overflow = adjusted_ink_overflow;
      return SetType(new_type);
  }
  NOTREACHED();
}

InkOverflow::Type InkOverflow::SetSelf(Type type,
                                       const PhysicalRect& ink_overflow,
                                       const PhysicalSize& size) {
  CheckType(type);
  if (!HasOverflow(ink_overflow, size))
    return Reset(type);
  return SetSingle(type, ink_overflow, size, Type::kSelf, Type::kSmallSelf);
}

InkOverflow::Type InkOverflow::SetContents(Type type,
                                           const PhysicalRect& ink_overflow,
                                           const PhysicalSize& size) {
  CheckType(type);
  if (!HasOverflow(ink_overflow, size))
    return Reset(type);
  return SetSingle(type, ink_overflow, size, Type::kContents,
                   Type::kSmallContents);
}

InkOverflow::Type InkOverflow::Set(Type type,
                                   const PhysicalRect& self,
                                   const PhysicalRect& contents,
                                   const PhysicalSize& size) {
  CheckType(type);

  if (!HasOverflow(self, size)) {
    if (!HasOverflow(contents, size))
      return Reset(type);
    return SetSingle(type, contents, size, Type::kContents,
                     Type::kSmallContents);
  }
  if (!HasOverflow(contents, size))
    return SetSingle(type, self, size, Type::kSelf, Type::kSmallSelf);

  switch (type) {
    case Type::kSelf:
    case Type::kContents:
      Reset(type);
      [[fallthrough]];
    case Type::kNotSet:
    case Type::kInvalidated:
    case Type::kNone:
    case Type::kSmallSelf:
    case Type::kSmallContents:
      container_ = new ContainerInkOverflow(self, contents);
      return SetType(Type::kSelfAndContents);
    case Type::kSelfAndContents:
      DCHECK(container_);
      container_->ink_overflow = self;
      container_->contents_ink_overflow = contents;
      return Type::kSelfAndContents;
  }
  NOTREACHED();
}

InkOverflow::Type InkOverflow::SetTextInkOverflow(
    Type type,
    const InlineCursor& cursor,
    const TextFragmentPaintInfo& text_info,
    const ComputedStyle& style,
    const PhysicalRect& rect_in_container,
    const InlinePaintContext* inline_context,
    PhysicalRect* ink_overflow_out) {
  CheckType(type);
  DCHECK(type == Type::kNotSet || type == Type::kInvalidated);
  std::optional<PhysicalRect> ink_overflow =
      ComputeTextInkOverflow(cursor, text_info, style, style.GetFont(),
                             rect_in_container, inline_context);
  if (!ink_overflow) {
    *ink_overflow_out = {PhysicalOffset(), rect_in_container.size};
    return Reset(type);
  }
  ink_overflow->ExpandEdgesToPixelBoundaries();
  *ink_overflow_out = *ink_overflow;
  return SetSelf(type, *ink_overflow, rect_in_container.size);
}

InkOverflow::Type InkOverflow::SetSvgTextInkOverflow(
    Type type,
    const InlineCursor& cursor,
    const TextFragmentPaintInfo& text_info,
    const ComputedStyle& style,
    const Font& scaled_font,
    const gfx::RectF& rect,
    float scaling_factor,
    float length_adjust_scale,
    const AffineTransform& transform,
    PhysicalRect* ink_overflow_out) {
  CheckType(type);
  DCHECK(type == Type::kNotSet || type == Type::kInvalidated);
  // Unapply length_adjust_scale because the size argument is compared with
  // Font::TextInkBounds().
  PhysicalSize item_size =
      style.IsHorizontalWritingMode()
          ? PhysicalSize(LayoutUnit(rect.width() / length_adjust_scale),
                         LayoutUnit(rect.height()))
          : PhysicalSize(LayoutUnit(rect.width()),
                         LayoutUnit(rect.height() / length_adjust_scale));
  // No |inline_context| because the decoration box is not supported for SVG.
  std::optional<PhysicalRect> ink_overflow =
      ComputeTextInkOverflow(cursor, text_info, style, scaled_font,
                             PhysicalRect(PhysicalOffset(), item_size),
                             /* inline_context */ nullptr);
  const bool needs_transform =
      scaling_factor != 1.0f || !transform.IsIdentity();
  PhysicalSize unscaled_size = PhysicalSize::FromSizeFRound(rect.size());
  unscaled_size.Scale(1.0f / scaling_factor);
  if (!ink_overflow) {
    if (needs_transform) {
      gfx::RectF transformed_rect = transform.MapRect(rect);
      transformed_rect.Offset(-rect.x(), -rect.y());
      transformed_rect.Scale(1 / scaling_factor);
      *ink_overflow_out = PhysicalRect::EnclosingRect(transformed_rect);
      ink_overflow_out->ExpandEdgesToPixelBoundaries();
      return SetSelf(type, *ink_overflow_out, unscaled_size);
    }
    *ink_overflow_out = {PhysicalOffset(), unscaled_size};
    ink_overflow_out->ExpandEdgesToPixelBoundaries();
    return Reset(type);
  }
  // Apply length_adjust_scale before applying AffineTransform.
  if (style.IsHorizontalWritingMode()) {
    ink_overflow->SetX(LayoutUnit(ink_overflow->X() * length_adjust_scale));
    ink_overflow->SetWidth(
        LayoutUnit(ink_overflow->Width() * length_adjust_scale));
  } else {
    ink_overflow->SetY(LayoutUnit(ink_overflow->Y() * length_adjust_scale));
    ink_overflow->SetHeight(
        LayoutUnit(ink_overflow->Height() * length_adjust_scale));
  }
  if (needs_transform) {
    gfx::RectF transformed_rect(*ink_overflow);
    transformed_rect.Offset(rect.x(), rect.y());
    transformed_rect = transform.MapRect(transformed_rect);
    transformed_rect.Offset(-rect.x(), -rect.y());
    transformed_rect.Scale(1 / scaling_factor);
    *ink_overflow_out = PhysicalRect::EnclosingRect(transformed_rect);
    ink_overflow_out->ExpandEdgesToPixelBoundaries();
    return SetSelf(type, *ink_overflow_out, unscaled_size);
  }
  *ink_overflow_out = *ink_overflow;
  ink_overflow_out->ExpandEdgesToPixelBoundaries();
  return SetSelf(type, *ink_overflow, unscaled_size);
}

// static
std::optional<PhysicalRect> InkOverflow::ComputeTextInkOverflow(
    const InlineCursor& cursor,
    const TextFragmentPaintInfo& text_info,
    const ComputedStyle& style,
    const Font& scaled_font,
    const PhysicalRect& rect_in_container,
    const InlinePaintContext* inline_context) {
  // Glyph bounds is in logical coordinate, origin at the alphabetic baseline.
  const gfx::RectF text_ink_bounds = scaled_font.TextInkBounds(text_info);
  LogicalRect ink_overflow = LogicalRect::EnclosingRect(text_ink_bounds);
  const WritingMode writing_mode = style.GetWritingMode();

  // Make the origin at the logical top of this fragment.
  if (const SimpleFontData* font_data = scaled_font.PrimaryFont()) {
    ink_overflow.offset.block_offset +=
        font_data->GetFontMetrics().FixedAscent(kAlphabeticBaseline);
  }

  if (float stroke_width = style.TextStrokeWidth()) {
    ink_overflow.Inflate(LayoutUnit::FromFloatCeil(stroke_width / 2.0f));
  }

  // Following effects, such as shadows, operate on the text decorations,
  // so compute text decoration overflow first.
  LogicalRect decoration_rect = ComputeDecorationOverflow(
      cursor, style, scaled_font, rect_in_container.offset, ink_overflow,
      inline_context, writing_mode);
  ink_overflow.Unite(decoration_rect);

  if (style.GetTextEmphasisMark() != TextEmphasisMark::kNone) {
    ink_overflow = ComputeEmphasisMarkOverflow(style, rect_in_container.size,
                                               ink_overflow);
  }

  if (const ShadowList* text_shadow = style.TextShadow()) {
    ExpandForShadowOverflow(ink_overflow, *text_shadow, writing_mode);
  }

  PhysicalRect local_ink_overflow =
      WritingModeConverter({writing_mode, TextDirection::kLtr},
                           rect_in_container.size)
          .ToPhysical(ink_overflow);

  // Uniting the frame rect ensures that non-ink spaces such side bearings, or
  // even space characters, are included in the visual rect for decorations.
  if (!HasOverflow(local_ink_overflow, rect_in_container.size))
    return std::nullopt;

  local_ink_overflow.Unite({{}, rect_in_container.size});
  return local_ink_overflow;
}

// static
LogicalRect InkOverflow::ComputeEmphasisMarkOverflow(
    const ComputedStyle& style,
    const PhysicalSize& size,
    const LogicalRect& ink_overflow_in) {
  DCHECK(style.GetTextEmphasisMark() != TextEmphasisMark::kNone);

  LayoutUnit emphasis_mark_height = LayoutUnit(
      style.GetFont().EmphasisMarkHeight(style.TextEmphasisMarkString()));
  DCHECK_GE(emphasis_mark_height, LayoutUnit());

  LogicalRect ink_overflow = ink_overflow_in;
  if (style.GetTextEmphasisLineLogicalSide() == LineLogicalSide::kOver) {
    ink_overflow.ShiftBlockStartEdgeTo(
        std::min(ink_overflow.offset.block_offset, -emphasis_mark_height));
  } else {
    LayoutUnit logical_height =
        style.IsHorizontalWritingMode() ? size.height : size.width;
    ink_overflow.ShiftBlockEndEdgeTo(std::max(
        ink_overflow.BlockEndOffset(), logical_height + emphasis_mark_height));
  }
  return ink_overflow;
}

// static
void InkOverflow::ExpandForShadowOverflow(LogicalRect& ink_overflow,
                                          const ShadowList& text_shadow,
                                          const WritingMode writing_mode) {
  LineBoxStrut text_shadow_logical_outsets =
      PhysicalBoxStrut::Enclosing(text_shadow.RectOutsetsIncludingOriginal())
          .ConvertToLineLogical({writing_mode, TextDirection::kLtr});
  ink_overflow.ExpandEdges(
      text_shadow_logical_outsets.line_over.ClampNegativeToZero(),
      text_shadow_logical_outsets.inline_end.ClampNegativeToZero(),
      text_shadow_logical_outsets.line_under.ClampNegativeToZero(),
      text_shadow_logical_outsets.inline_start.ClampNegativeToZero());
}

// static
LogicalRect InkOverflow::ComputeDecorationOverflow(
    const InlineCursor& cursor,
    const ComputedStyle& style,
    const Font& scaled_font,
    const PhysicalOffset& container_offset,
    const LogicalRect& ink_overflow,
    const InlinePaintContext* inline_context,
    const WritingMode writing_mode) {
  LogicalRect accumulated_bound = ink_overflow;
  if (!scaled_font.PrimaryFont()) {
    return accumulated_bound;
  }
  // Text decoration from the fragment's style.
  if (style.HasAppliedTextDecorations()) {
    accumulated_bound = ComputeAppliedDecorationOverflow(
        style, scaled_font, container_offset, ink_overflow, inline_context);
  }

  // Text decorations due to selection
  if (cursor.Current().GetLayoutObject()->IsSelected()) [[unlikely]] {
    const ComputedStyle* selection_style = style.HighlightData().Selection();
    if (selection_style) {
      if (selection_style->HasAppliedTextDecorations()) {
        LogicalRect selection_bound = ComputeAppliedDecorationOverflow(
            *selection_style, scaled_font, container_offset, ink_overflow,
            inline_context);
        accumulated_bound.Unite(selection_bound);
      }
      if (const ShadowList* text_shadow = selection_style->TextShadow()) {
        ExpandForShadowOverflow(accumulated_bound, *text_shadow, writing_mode);
      }
    }
  }

  // To extract decorations due to markers, we need a fragment item and a
  // node. Ideally we would use cursor.Current().GetNode() but that's const
  // and the style functions we need to access pseudo styles take non-const
  // nodes.
  const FragmentItem* fragment_item = cursor.CurrentItem();
  if (!fragment_item->IsText() || fragment_item->IsSvgText() ||
      fragment_item->IsGeneratedText()) {
    return accumulated_bound;
  }
  const LayoutObject* layout_object = cursor.CurrentMutableLayoutObject();
  DCHECK(layout_object);
  Text* text_node = DynamicTo<Text>(layout_object->GetNode());
  // ::first-letter passes the IsGeneratedText check but has no text node.
  if (!text_node) {
    return accumulated_bound;
  }

  DocumentMarkerController& controller = text_node->GetDocument().Markers();
  if (!controller.HasAnyMarkersForText(*text_node)) {
    return accumulated_bound;
  }
  TextOffsetRange fragment_dom_offsets =
      HighlightPainter::GetFragmentDOMOffsets(
          *text_node, fragment_item->StartOffset(), fragment_item->EndOffset());

  DocumentMarkerVector target_markers = controller.MarkersFor(
      *text_node, DocumentMarker::kTextFragment, fragment_dom_offsets.start,
      fragment_dom_offsets.end);
  if (!target_markers.empty()) {
    LogicalRect target_bound = ComputeMarkerOverflow(
        target_markers, DocumentMarker::kTextFragment, fragment_item,
        fragment_dom_offsets, text_node, style, scaled_font, container_offset,
        ink_overflow, inline_context, writing_mode);
    accumulated_bound.Unite(target_bound);
  }

  DocumentMarkerVector custom_markers = controller.MarkersFor(
      *text_node, DocumentMarker::kCustomHighlight, fragment_dom_offsets.start,
      fragment_dom_offsets.end);
  if (!custom_markers.empty()) {
    LogicalRect custom_bound = ComputeCustomHighlightOverflow(
        custom_markers, fragment_item, fragment_dom_offsets, text_node, style,
        scaled_font, container_offset, ink_overflow, inline_context);
    accumulated_bound.Unite(custom_bound);
  }

  DocumentMarkerVector spelling_markers = controller.MarkersFor(
      *text_node, DocumentMarker::kSpelling, fragment_dom_offsets.start,
      fragment_dom_offsets.end);
  if (!spelling_markers.empty()) {
    LogicalRect spelling_bound = ComputeMarkerOverflow(
        spelling_markers, DocumentMarker::kSpelling, fragment_item,
        fragment_dom_offsets, text_node, style, scaled_font, container_offset,
        ink_overflow, inline_context, writing_mode);
    accumulated_bound.Unite(spelling_bound);
  }

  DocumentMarkerVector grammar_markers = controller.MarkersFor(
      *text_node, DocumentMarker::kGrammar, fragment_dom_offsets.start,
      fragment_dom_offsets.end);
  if (!grammar_markers.empty()) {
    LogicalRect grammar_bound = ComputeMarkerOverflow(
        grammar_markers, DocumentMarker::kGrammar, fragment_item,
        fragment_dom_offsets, text_node, style, scaled_font, container_offset,
        ink_overflow, inline_context, writing_mode);
    accumulated_bound.Unite(grammar_bound);
  }
  return accumulated_bound;
}

LogicalRect InkOverflow::ComputeAppliedDecorationOverflow(
    const ComputedStyle& style,
    const Font& scaled_font,
    const PhysicalOffset& offset_in_container,
    const LogicalRect& ink_overflow,
    const InlinePaintContext* inline_context,
    const AppliedTextDecoration* decoration_override) {
  DCHECK(style.HasAppliedTextDecorations() || decoration_override);
  // SVGText is currently the only reason we use decoration_override,
  // so use it as a proxy for determining minimum thickness.
  const MinimumThickness1 kMinimumThicknessIsOne(!decoration_override);
  TextDecorationInfo decoration_info(
      LineRelativeOffset::CreateFromBoxOrigin(offset_in_container),
      ink_overflow.size.inline_size, style, inline_context,
      TextDecorationLine::kNone, Color(), decoration_override, &scaled_font,
      kMinimumThicknessIsOne);
  TextDecorationOffset decoration_offset(style);
  gfx::RectF accumulated_bound;
  for (wtf_size_t i = 0; i < decoration_info.AppliedDecorationCount(); i++) {
    decoration_info.SetDecorationIndex(i);
    if (decoration_info.HasUnderline()) {
      decoration_info.SetUnderlineLineData(decoration_offset);
      accumulated_bound.Union(decoration_info.Bounds());
    }
    if (decoration_info.HasOverline()) {
      decoration_info.SetOverlineLineData(decoration_offset);
      accumulated_bound.Union(decoration_info.Bounds());
    }
    if (decoration_info.HasLineThrough()) {
      decoration_info.SetLineThroughLineData();
      accumulated_bound.Union(decoration_info.Bounds());
    }
    if (decoration_info.HasSpellingError() ||
        decoration_info.HasGrammarError()) {
      decoration_info.SetSpellingOrGrammarErrorLineData(decoration_offset);
      accumulated_bound.Union(decoration_info.Bounds());
    }
  }
  // Adjust the container coordinate system to the local coordinate system.
  accumulated_bound -= gfx::Vector2dF(offset_in_container);
  return LogicalRect::EnclosingRect(accumulated_bound);
}

LogicalRect InkOverflow::ComputeMarkerOverflow(
    const DocumentMarkerVector& markers,
    const DocumentMarker::MarkerType type,
    const FragmentItem* fragment_item,
    const TextOffsetRange& fragment_dom_offsets,
    Text* text_node,
    const ComputedStyle& style,
    const Font& scaled_font,
    const PhysicalOffset& offset_in_container,
    const LogicalRect& ink_overflow,
    const InlinePaintContext* inline_context,
    const WritingMode writing_mode) {
  DCHECK(!fragment_item->IsSvgText());
  LogicalRect accumulated_bound = ink_overflow;
  auto* pseudo_style = HighlightStyleUtils::HighlightPseudoStyle(
      text_node, style, HighlightPainter::PseudoFor(type));
  const ShadowList* text_shadow =
      pseudo_style ? pseudo_style->TextShadow() : nullptr;
  bool has_pseudo_decorations =
      pseudo_style && pseudo_style->HasAppliedTextDecorations();
  bool is_spelling_or_grammar =
      type == DocumentMarker::kSpelling || type == DocumentMarker::kGrammar;
  if (has_pseudo_decorations || is_spelling_or_grammar || text_shadow) {
    MarkerRangeMappingContext mapping_context(*text_node, fragment_dom_offsets);
    for (auto marker : markers) {
      std::optional<TextOffsetRange> marker_offsets =
          mapping_context.GetTextContentOffsets(*marker);
      if (!marker_offsets) {
        continue;
      }
      LogicalRect decoration_bound;
      if (has_pseudo_decorations) {
        decoration_bound = ComputeAppliedDecorationOverflow(
            *pseudo_style, scaled_font, offset_in_container, ink_overflow,
            inline_context);
      } else if (is_spelling_or_grammar) {
        const AppliedTextDecoration synthesised{
            HighlightPainter::LineFor(type),
            {},
            HighlightPainter::ColorFor(type),
            {},
            {}};
        decoration_bound = ComputeAppliedDecorationOverflow(
            style, scaled_font, offset_in_container, ink_overflow,
            inline_context, &synthesised);
      }
      accumulated_bound.Unite(decoration_bound);
      if (text_shadow) [[unlikely]] {
        ExpandForShadowOverflow(accumulated_bound, *text_shadow, writing_mode);
      }
    }
  }
  return accumulated_bound;
}

LogicalRect InkOverflow::ComputeCustomHighlightOverflow(
    const DocumentMarkerVector& markers,
    const FragmentItem* fragment_item,
    const TextOffsetRange& fragment_dom_offsets,
    Text* text_node,
    const ComputedStyle& style,
    const Font& scaled_font,
    const PhysicalOffset& offset_in_container,
    const LogicalRect& ink_overflow,
    const InlinePaintContext* inline_context) {
  DCHECK(!fragment_item->IsSvgText());
  LogicalRect accumulated_bound;

  MarkerRangeMappingContext mapping_context(*text_node, fragment_dom_offsets);
  for (auto marker : markers) {
    std::optional<TextOffsetRange> marker_offsets =
        mapping_context.GetTextContentOffsets(*marker);
    if (!marker_offsets) {
      return LogicalRect();
    }

    const CustomHighlightMarker& highlight_marker =
        To<CustomHighlightMarker>(*marker);
    const auto* pseudo_style = HighlightStyleUtils::HighlightPseudoStyle(
        text_node, style, kPseudoIdHighlight,
        highlight_marker.GetHighlightName());

    LogicalRect decoration_bound;
    if (pseudo_style && pseudo_style->HasAppliedTextDecorations()) {
      decoration_bound = ComputeAppliedDecorationOverflow(
          *pseudo_style, scaled_font, offset_in_container, ink_overflow,
          inline_context);
      accumulated_bound.Unite(decoration_bound);
    }
  }
  return accumulated_bound;
}

}  // namespace blink

"""

```