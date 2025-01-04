Response:
Let's break down the thought process for analyzing this code and generating the explanation.

1. **Understand the Goal:** The primary goal is to understand the functionality of `svg_text_layout_attributes_builder.cc` and its relation to web technologies. This involves figuring out what it *does* and *how* it relates to HTML, CSS, and JavaScript.

2. **Identify Key Classes and Structures:**  The first step is to scan the code for significant classes and structures. The names themselves often provide clues:
    * `SVGTextLayoutAttributesBuilder`:  This is the core class, and the name suggests it builds attributes related to SVG text layout.
    * `LayoutAttributesIterator`:  Likely iterates through layout attributes.
    * `LayoutAttributesStack`:  Manages a stack of attribute iterators, hinting at a hierarchical structure (like the DOM).
    * `SVGTextLengthContext`: Holds context related to `textLength` attributes.
    * `SvgCharacterData`: Represents data for individual characters, holding positioning info.
    * `SvgTextContentRange`: Represents a range of text with specific properties.

3. **Trace the Core Function `Build()`:** The `Build()` function seems to be the central logic. Analyze its steps and the data it manipulates:
    * It takes the text content and inline items as input.
    * It uses `LayoutAttributesStack` and `SVGTextLengthContext` stack.
    * It iterates through `items`, which likely correspond to elements within the SVG text structure (`<tspan>`, `<textPath>`, etc.).
    * It updates `SvgCharacterData` for each character based on attributes from the stacks.
    * It identifies ranges affected by `textLength` and `textPath`.

4. **Connect to SVG Attributes:**  Look for how the code interacts with specific SVG attributes:
    * `x`, `y`, `dx`, `dy`, `rotate`: These are explicitly handled by `LayoutAttributesIterator`.
    * `textLength`:  Used in `HasValidTextLength` and managed by the `text_length_stack`.
    *  The presence of `SVGTextPositioningElement` indicates handling of elements that define these attributes.
    * `<textPath>`:  Specifically handled in the `Build()` function, affecting the `in_text_path` flag and `anchored_chunk`.

5. **Relate to HTML, CSS, and JavaScript:**  Now consider how these SVG concepts and the code's functionality connect to the broader web ecosystem:
    * **HTML:** SVG is embedded in HTML, so this code contributes to rendering SVG elements defined in HTML. The `<text>`, `<tspan>`, and `<textPath>` elements are the direct HTML counterparts.
    * **CSS:** CSS properties can affect SVG elements, though this specific code seems more focused on the SVG-specific attributes. Mention that CSS styles *influence* the layout process that this builder contributes to.
    * **JavaScript:** JavaScript can manipulate SVG attributes. The code handles the *result* of these manipulations as the animated values are used. Give an example of JavaScript changing the `x` attribute.

6. **Infer Functionality and Purpose:** Based on the analysis, synthesize the core functionality: This code resolves the positioning attributes for individual characters within SVG text elements, considering the nesting of elements and the effect of attributes like `x`, `y`, `dx`, `dy`, `rotate`, and `textLength`, as well as the influence of `<textPath>`.

7. **Consider Edge Cases and Potential Errors:** Think about situations where things might go wrong or where the code needs to handle specific cases:
    * Invalid `textLength` values.
    * The interaction between nested `<tspan>` and `<textPath>` elements.
    * The behavior when attributes have different lengths (the "matched or last" logic for `rotate`).
    * Common mistakes developers might make when using these attributes.

8. **Construct Input/Output Examples:**  Create simple examples to illustrate how the code would behave with specific input:
    * Basic `<text>` with `x` and `y`.
    * `<tspan>` elements with `dx` and `dy`.
    * `<textPath>` elements and how they affect positioning.
    * Examples showing how `textLength` might influence the output.

9. **Organize the Explanation:** Structure the explanation logically, starting with the core functionality and then delving into specifics and connections. Use clear headings and bullet points to improve readability.

10. **Refine and Review:**  Read through the explanation, checking for clarity, accuracy, and completeness. Make sure the examples are clear and illustrative. Ensure the connection to web technologies is well-articulated. For example, I initially might not have emphasized the role of animated values as much, but upon review, realized the `CurrentValue()` calls highlight that.

**Self-Correction Example During the Process:**

Initially, I might have focused too much on the individual attribute handling in `LayoutAttributesIterator`. However, reviewing the `Build()` function makes it clear that the *stack* (`LayoutAttributesStack`) is crucial for understanding how inherited and locally defined attributes interact. This realization would lead to a more balanced explanation emphasizing the stack's role in resolving attribute values. Similarly, I might have initially overlooked the specifics of how `textLength` is handled, but noticing the `text_length_stack` and related logic would prompt me to include that functionality in the explanation.
这个文件 `svg_text_layout_attributes_builder.cc` 是 Chromium Blink 渲染引擎中的一部分，专门负责构建 SVG 文本布局所需的各种属性。它的主要功能是**根据 SVG 文本元素（如 `<text>`, `<tspan>`, `<textPath>` 等）的属性，计算出每个字符在布局时的具体位置和旋转角度等信息。**

以下是该文件功能的详细列举：

**核心功能：**

1. **解析和处理 SVG 文本定位属性：**  该文件主要处理 SVG 文本元素上用于定位和旋转的属性，包括 `x`, `y`, `dx`, `dy`, 和 `rotate`。
2. **处理嵌套的 SVG 文本元素：**  它能够处理 `<text>` 元素内部嵌套的 `<tspan>` 和 `<textPath>` 等元素，并正确地继承和应用相应的属性。
3. **实现 SVG 文本布局算法的关键步骤：**  该文件实现了 SVG2 规范中 "3. Resolve character positioning" 算法的关键部分，负责计算每个字符的最终位置和旋转。
4. **管理属性栈：**  使用 `LayoutAttributesStack` 来维护当前正在处理的 SVG 文本元素的属性状态，确保嵌套元素能正确继承和覆盖父元素的属性。
5. **处理 `<textPath>` 元素：**  专门处理 `<textPath>` 元素，标记出位于路径上的文本字符，并影响后续的布局计算。
6. **处理 `textLength` 属性：**  识别并处理 `textLength` 属性，该属性允许用户指定文本的总长度，引擎会根据此长度调整字符间距。
7. **生成 `SvgInlineNodeData`：**  最终将计算出的字符定位和旋转信息存储在 `SvgInlineNodeData` 对象中，供后续的布局和绘制阶段使用。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML：** 该文件处理的是 HTML 中嵌入的 SVG 内容，特别是 `<text>` 及其相关子元素。
    * **举例：** 当浏览器解析到以下 HTML 时，该文件会参与 `<text>` 元素的布局计算。
      ```html
      <svg>
        <text x="10" y="20" rotate="30">Hello</text>
      </svg>
      ```
* **CSS：** CSS 可以影响 SVG 元素的某些样式属性，但该文件主要关注的是 SVG 特有的定位属性。CSS 的 `transform` 属性也可以影响 SVG 元素的变换，但这与该文件直接处理的字符级别的定位有所区别。
    * **举例：** CSS 可以改变文本的颜色和字体大小，但这不影响 `svg_text_layout_attributes_builder.cc` 计算的 `x`, `y`, `rotate` 等属性。
      ```html
      <svg>
        <style>
          .my-text {
            font-size: 16px;
            fill: blue;
          }
        </style>
        <text class="my-text" x="10" y="20">Hello</text>
      </svg>
      ```
* **JavaScript：** JavaScript 可以动态地修改 SVG 元素的属性，这些修改会影响到 `svg_text_layout_attributes_builder.cc` 的计算结果。
    * **举例：** JavaScript 可以修改 `<tspan>` 的 `dx` 和 `dy` 属性，从而改变其内部字符的位置。
      ```html
      <svg id="mySvg">
        <text x="10" y="20">
          <tspan id="part1">Hello</tspan>
          <tspan id="part2" dx="5" dy="10">World</tspan>
        </text>
      </svg>
      <script>
        document.getElementById('part2').setAttribute('dx', '10');
      </script>
      ```
      当 JavaScript 修改 `dx` 属性后，重新布局时，`svg_text_layout_attributes_builder.cc` 会读取更新后的 `dx` 值并用于计算 "World" 中每个字符的位置。

**逻辑推理及假设输入与输出：**

假设有以下 SVG 代码片段：

```html
<svg>
  <text x="10" y="20">
    <tspan dx="5">A</tspan>
    B
    <tspan dy="10">C</tspan>
  </text>
</svg>
```

**假设输入：**

* `ifc_text_content`: "ABC" (文本内容)
* `items`:  一个包含以下 `InlineItem` 的列表（简化表示）：
    * OpenTag `<text>`
    * OpenTag `<tspan>`
    * Text "A"
    * CloseTag `</tspan>`
    * Text "B"
    * OpenTag `<tspan>`
    * Text "C"
    * CloseTag `</tspan>`
    * CloseTag `</text>`

**逻辑推理：**

1. 初始化属性栈，包含 `<text>` 元素的属性 `x=10`, `y=20`。
2. 处理 `<tspan>` 标签，将 `<tspan>` 的属性（此处为 `dx=5`）压入属性栈。
3. 处理字符 "A"：
   - `x` 从栈中获取，为 10。
   - `y` 从栈中获取，为 20。
   - `dx` 从栈中获取，为 5。
   - 计算出 "A" 的最终位置可能为 (10 + 5, 20)。
4. 处理字符 "B"：
   - `x` 从栈中获取，为 10。
   - `y` 从栈中获取，为 20。
   - `dx` 从栈中没有当前 `<tspan>` 的 `dx`，可能继承上一个或为默认值。
   - 计算出 "B" 的最终位置可能在 "A" 的后面，基于默认的字符间距。
5. 处理 `<tspan>` 标签，将 `<tspan>` 的属性（此处为 `dy=10`）压入属性栈。
6. 处理字符 "C"：
   - `x` 从栈中获取，为 10。
   - `y` 从栈中获取，为 20。
   - `dy` 从栈中获取，为 10。
   - 计算出 "C" 的最终位置可能为 (某个 x 值, 20 + 10)。
7. 最终将这些计算出的每个字符的定位信息存储起来。

**假设输出 (简化表示)：**

一个 `SvgInlineNodeData` 对象，包含类似以下的字符数据：

```
[
  { index: 0, char: 'A', x: 15, y: 20, rotate: 0 },
  { index: 1, char: 'B', x: some_value, y: 20, rotate: 0 },
  { index: 2, char: 'C', x: some_other_value, y: 30, rotate: 0 }
]
```

**用户或编程常见的使用错误举例：**

1. **`rotate` 属性值的数量与字符数量不匹配：**
   - **错误代码：** `<text rotate="10 20">ABCD</text>`
   - **说明：**  `rotate` 属性只有两个值，但文本有四个字符。该文件会根据 SVG 规范处理这种情况，可能会重复使用最后一个值。
2. **在 `<textPath>` 内部错误地使用绝对定位属性 `x` 和 `y`：**
   - **错误代码：**
     ```html
     <svg>
       <path id="myPath" d="M10,50 C40,10 60,90 90,50" />
       <text>
         <textPath xlink:href="#myPath" x="20" y="30">Text on a path</textPath>
       </text>
     </svg>
     ```
   - **说明：**  在 `<textPath>` 内部使用 `x` 和 `y` 属性通常会被忽略，因为文本的位置是由路径决定的。开发者可能误以为这些属性会相对于路径进行偏移。
3. **`textLength` 属性值不合理导致文本变形：**
   - **错误代码：** `<text textLength="10">A very long text</text>`
   - **说明：**  `textLength` 的值远小于文本的实际长度，浏览器会强制将文本压缩到指定的长度，可能导致文本难以阅读。
4. **嵌套 `<textPath>` 元素：**
   - **错误代码：**
     ```html
     <svg>
       <text>
         <textPath xlink:href="#path1">
           <textPath xlink:href="#path2">Nested Text</textPath>
         </textPath>
       </text>
     </svg>
     ```
   - **说明：**  SVG 规范不允许嵌套 `<textPath>` 元素，该文件会按照规范处理，可能只渲染外层的 `<textPath>` 或产生未定义的行为。

总而言之，`svg_text_layout_attributes_builder.cc` 是 Blink 渲染引擎中负责精确计算 SVG 文本布局属性的关键组件，它深入理解 SVG 规范中关于文本定位的规则，并将其转化为浏览器可以理解和执行的布局信息。

Prompt: 
```
这是目录为blink/renderer/core/layout/svg/svg_text_layout_attributes_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/svg/svg_text_layout_attributes_builder.h"

#include <optional>

#include "base/containers/adapters.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/svg/svg_animated_length.h"
#include "third_party/blink/renderer/core/svg/svg_animated_length_list.h"
#include "third_party/blink/renderer/core/svg/svg_animated_number_list.h"
#include "third_party/blink/renderer/core/svg/svg_length_context.h"
#include "third_party/blink/renderer/core/svg/svg_text_positioning_element.h"

namespace blink {

struct SVGTextLengthContext {
  DISALLOW_NEW();

 public:
  void Trace(Visitor* visitor) const { visitor->Trace(layout_object); }

  Member<const LayoutObject> layout_object;
  unsigned start_index;
};

}  // namespace blink

WTF_ALLOW_MOVE_INIT_AND_COMPARE_WITH_MEM_FUNCTIONS(blink::SVGTextLengthContext)

namespace blink {

namespace {

// Iterates over x/y/dx/dy/rotate attributes on an SVGTextPositioningElement.
//
// This class is used only by LayoutAttributesStack.
// This class is not copyable.
class LayoutAttributesIterator final
    : public GarbageCollected<LayoutAttributesIterator> {
 public:
  LayoutAttributesIterator(const LayoutObject& layout_object, bool in_text_path)
      : element_(To<SVGTextPositioningElement>(layout_object.GetNode())),
        x_(element_->x()->CurrentValue()),
        y_(element_->y()->CurrentValue()),
        dx_(element_->dx()->CurrentValue()),
        dy_(element_->dy()->CurrentValue()),
        rotate_(element_->rotate()->CurrentValue()),
        in_text_path_(in_text_path) {}
  LayoutAttributesIterator(const LayoutAttributesIterator&) = delete;
  LayoutAttributesIterator& operator=(const LayoutAttributesIterator&) = delete;

  void Trace(Visitor* visitor) const {
    visitor->Trace(element_);
    visitor->Trace(x_);
    visitor->Trace(y_);
    visitor->Trace(dx_);
    visitor->Trace(dy_);
    visitor->Trace(rotate_);
  }

  bool HasX() const { return consumed_ < x_->length(); }
  bool HasY() const { return consumed_ < y_->length(); }
  bool HasDx() const { return consumed_ < dx_->length(); }
  bool HasDy() const { return consumed_ < dy_->length(); }

  float X() const {
    return x_->at(consumed_)->Value(SVGLengthContext(element_));
  }
  float Y() const {
    return y_->at(consumed_)->Value(SVGLengthContext(element_));
  }
  float Dx() const {
    return dx_->at(consumed_)->Value(SVGLengthContext(element_));
  }
  float Dy() const {
    return dy_->at(consumed_)->Value(SVGLengthContext(element_));
  }

  float MatchedOrLastRotate() const {
    uint32_t length = rotate_->length();
    if (length == 0) {
      return SvgCharacterData::EmptyValue();
    }
    if (consumed_ < length) {
      return rotate_->at(consumed_)->Value();
    }
    return rotate_->at(length - 1)->Value();
  }

  bool InTextPath() const { return in_text_path_; }

  // This function should be called whenever we handled an addressable
  // character in a descendant LayoutText.
  void Advance() { ++consumed_; }

 private:
  // The following six Member<>s never be null.
  const Member<const SVGTextPositioningElement> element_;
  const Member<const SVGLengthList> x_;
  const Member<const SVGLengthList> y_;
  const Member<const SVGLengthList> dx_;
  const Member<const SVGLengthList> dy_;
  const Member<const SVGNumberList> rotate_;
  const bool in_text_path_;
  // How many addressable characters in this element are consumed.
  unsigned consumed_ = 0;
};

// A stack of LayoutAttributesIterator.
// This class is not copyable.
class LayoutAttributesStack final {
  STACK_ALLOCATED();

 public:
  LayoutAttributesStack() = default;
  ~LayoutAttributesStack() { DCHECK_EQ(stack_.size(), 0u); }
  LayoutAttributesStack(const LayoutAttributesStack&) = delete;
  LayoutAttributesStack& operator=(const LayoutAttributesStack&) = delete;

  void Push(const LayoutObject& layout_object, bool in_text_path) {
    stack_.push_back(MakeGarbageCollected<LayoutAttributesIterator>(
        layout_object, in_text_path));
  }
  void Pop() { stack_.pop_back(); }

  // Advance all of iterators in the stack.
  void Advance() {
    DCHECK_GT(stack_.size(), 0u);
    for (auto& iterator : stack_) {
      iterator->Advance();
    }
  }

  // X(), Y(), Dx(), and Dy() return an effective 'x, 'y', 'dx', or 'dy' value,
  // or EmptyValue().

  float X() const {
    auto it = base::ranges::find_if(base::Reversed(stack_),
                                    &LayoutAttributesIterator::HasX);
    return it != stack_.rend() ? (*it)->X() : SvgCharacterData::EmptyValue();
  }
  float Y() const {
    auto it = base::ranges::find_if(base::Reversed(stack_),
                                    &LayoutAttributesIterator::HasY);
    return it != stack_.rend() ? (*it)->Y() : SvgCharacterData::EmptyValue();
  }
  float Dx() const {
    auto it = base::ranges::find_if(base::Reversed(stack_),
                                    &LayoutAttributesIterator::HasDx);
    return it != stack_.rend() ? (*it)->Dx() : SvgCharacterData::EmptyValue();
  }
  float Dy() const {
    auto it = base::ranges::find_if(base::Reversed(stack_),
                                    &LayoutAttributesIterator::HasDy);
    return it != stack_.rend() ? (*it)->Dy() : SvgCharacterData::EmptyValue();
  }

  float MatchedOrLastRotate() const {
    for (const auto& attrs : base::Reversed(stack_)) {
      float rotate = attrs->MatchedOrLastRotate();
      if (!SvgCharacterData::IsEmptyValue(rotate)) {
        return rotate;
      }
    }
    return SvgCharacterData::EmptyValue();
  }

  bool ShouldStartAnchoredChunk(bool horizontal) const {
    // According to the algorithm, the x/y attributes on the nearest
    // SVGTextPositioningElement should overwrite |anchored chunk| flag set by
    // ancestors.  It's incorrect.
    // https://github.com/w3c/svgwg/issues/839
    //
    // If the current position is not in a <textPath>, we should just check
    // existence of available x/y attributes in ancestors.
    // Otherwise, we should check available x/y attributes declared in the
    // <textPath> descendants.

    if (!stack_.back()->InTextPath()) {
      return !SvgCharacterData::IsEmptyValue(X()) ||
             !SvgCharacterData::IsEmptyValue(Y());
    }

    for (const auto& attrs : base::Reversed(stack_)) {
      if (!attrs->InTextPath()) {
        return false;
      }
      if (horizontal) {
        if (attrs->HasX()) {
          return true;
        }
      } else {
        if (attrs->HasY()) {
          return true;
        }
      }
    }
    return false;
  }

 private:
  HeapVector<Member<LayoutAttributesIterator>> stack_;
};

bool HasUpdated(const SvgCharacterData& data) {
  return data.HasX() || data.HasY() || data.HasDx() || data.HasDy() ||
         data.HasRotate() || data.anchored_chunk;
}

bool HasValidTextLength(const LayoutObject& layout_object) {
  if (auto* element =
          DynamicTo<SVGTextContentElement>(layout_object.GetNode())) {
    if (element->TextLengthIsSpecifiedByUser()) {
      float text_length = element->textLength()->CurrentValue()->Value(
          SVGLengthContext(element));
      // text_length is 0.0 if the textLength attribute has an invalid
      // string. Legacy SVG <text> skips textLength processing if the
      // attribute is "0" or invalid. Firefox skips textLength processing if
      // textLength value is smaller than the intrinsic width of the text.
      // This code follows the legacy behavior.
      return text_length > 0.0f;
    }
  }
  return false;
}

}  // anonymous namespace

SvgTextLayoutAttributesBuilder::SvgTextLayoutAttributesBuilder(InlineNode ifc)
    : block_flow_(To<LayoutBlockFlow>(ifc.GetLayoutBox())) {}

// This is an implementation of "3. Resolve character positioning" in [1],
// without recursion.
//
// An SVGCharacterDataWithAnchor stores resolve_x, resolve_y, resolve_dx,
// resolve_dy, "rotate" of result[], and "anchored chunk" of result[].
//
// [1]: https://svgwg.org/svg2-draft/text.html#TextLayoutAlgorithm
void SvgTextLayoutAttributesBuilder::Build(
    const String& ifc_text_content,
    const HeapVector<InlineItem>& items) {
  LayoutAttributesStack attr_stack;
  HeapVector<SVGTextLengthContext> text_length_stack;
  unsigned addressable_index = 0;
  bool is_first_char = true;
  bool in_text_path = false;
  std::optional<unsigned> text_path_start;
  bool first_char_in_text_path = false;
  const bool horizontal = block_flow_->IsHorizontalWritingMode();

  attr_stack.Push(*block_flow_, in_text_path);
  if (HasValidTextLength(*block_flow_)) {
    text_length_stack.push_back(
        SVGTextLengthContext{block_flow_, addressable_index});
  }
  for (const auto& item : items) {
    const LayoutObject* object = item.GetLayoutObject();

    if (item.Type() == InlineItem::kOpenTag) {
      if (object->IsSVGTSpan()) {
        attr_stack.Push(*object, in_text_path);
      } else if (object->IsSVGTextPath()) {
        // 2.2. Set the "anchored chunk" flag of result[index] to true.
        first_char_in_text_path = true;
        // 2.3. Set in_text_path flag true.
        in_text_path = true;
        text_path_start = addressable_index;
      }
      if (HasValidTextLength(*object)) {
        text_length_stack.push_back(
            SVGTextLengthContext{object, addressable_index});
      }

    } else if (item.Type() == InlineItem::kCloseTag) {
      if (object->IsSVGTSpan()) {
        attr_stack.Pop();
      } else if (object->IsSVGTextPath()) {
        // 4.1. Set "in_text_path" flag false.
        // According to the specification, <textPath> can't be nested.
        in_text_path = false;
        first_char_in_text_path = false;
        DCHECK(text_path_start);
        if (addressable_index != *text_path_start) {
          text_path_range_list_.push_back(SvgTextContentRange{
              object, *text_path_start, addressable_index - 1});
        }
        text_path_start.reset();
      }
      if (text_length_stack.size() > 0u &&
          text_length_stack.back().layout_object == object) {
        if (text_length_stack.back().start_index != addressable_index) {
          text_length_range_list_.push_back(
              SvgTextContentRange{object, text_length_stack.back().start_index,
                                  addressable_index - 1});
        }
        text_length_stack.pop_back();
      }

    } else if (item.Type() != InlineItem::kText) {
      continue;
    }

    StringView item_string(ifc_text_content, item.StartOffset(), item.Length());
    for (unsigned i = 0; i < item.Length();) {
      SvgCharacterData data;

      // 2.2. Set the "anchored chunk" flag of result[index] to true.
      // 1.6.1.1. If i < new_check_count, then set the "anchored chunk" flag
      // of result[index + j] to true. Else set the flag to false.
      if (first_char_in_text_path) {
        data.anchored_chunk = true;
      } else {
        data.anchored_chunk = attr_stack.ShouldStartAnchoredChunk(horizontal);
      }

      // 1.6.1.2. If i < length of x, then set resolve_x[index + j] to x[i].
      data.x = attr_stack.X();

      // 1.6.1.3. If "in_text_path" flag is true and the "horizontal" flag is
      // false, unset resolve_x[index].
      if (in_text_path && !horizontal) {
        data.x = SvgCharacterData::EmptyValue();
      }
      // Not in the specification; Set X of the first character in a
      // <textPath> to 0 in order to:
      //   - Reset dx in AdjustPositionsDxDy().
      //   - Anchor at 0 in ApplyAnchoring().
      // https://github.com/w3c/svgwg/issues/274
      if (first_char_in_text_path && horizontal && !data.HasX()) {
        data.x = 0.0f;
      }

      // 1.6.1.4. If i < length of y, then set resolve_y[index + j] to y[i].
      data.y = attr_stack.Y();

      // 1.6.1.5. If "in_text_path" flag is true and the "horizontal" flag is
      // true, unset resolve_y[index].
      if (in_text_path && horizontal) {
        data.y = SvgCharacterData::EmptyValue();
      }
      // Not in the specification; Set Y of the first character in a
      // <textPath> to 0 in order to:
      //   - Reset dy in AdjustPositionsDxDy().
      //   - Anchor at 0 in ApplyAnchoring().
      // https://github.com/w3c/svgwg/issues/274
      if (first_char_in_text_path && !horizontal && !data.HasY()) {
        data.y = 0.0f;
      }

      first_char_in_text_path = false;

      // Not in the specification; The following code sets the initial inline
      // offset of 'current text position' to 0.
      // See InlineLayoutAlgorithm::CreateLine() for the initial block offset.
      if (is_first_char) {
        is_first_char = false;
        if (horizontal) {
          if (!data.HasX()) {
            data.x = 0.0f;
          }
        } else {
          if (!data.HasY()) {
            data.y = 0.0f;
          }
        }
      }

      // 1.6.1.6. If i < length of dx, then set resolve_dx[index + j] to dx[i].
      data.dx = attr_stack.Dx();

      // 1.6.1.7. If i < length of dy, then set resolve_dy[index + j] to dy[i].
      data.dy = attr_stack.Dy();

      // 1.6.1.8. If i < length of rotate, then set the angle value of
      // result[index + j] to rotate[i]. Otherwise, if rotate is not empty,
      // then set result[index + j] to result[index + j − 1].
      data.rotate = attr_stack.MatchedOrLastRotate();

      if (HasUpdated(data)) {
        resolved_.push_back(std::make_pair(addressable_index, data));
        ifc_text_content_offsets_.push_back(item.StartOffset() + i);
      }
      ++addressable_index;
      attr_stack.Advance();
      i = item_string.NextCodePointOffset(i);
    }
  }
  if (text_length_stack.size() > 0u) {
    DCHECK_EQ(text_length_stack.back().layout_object, block_flow_);
    DCHECK_EQ(text_length_stack.back().start_index, 0u);
    text_length_range_list_.push_back(
        SvgTextContentRange{block_flow_, 0u, addressable_index - 1});
    text_length_stack.pop_back();
  }
  attr_stack.Pop();
  DCHECK_EQ(resolved_.size(), ifc_text_content_offsets_.size());
}

SvgInlineNodeData* SvgTextLayoutAttributesBuilder::CreateSvgInlineNodeData() {
  auto* svg_node_data = MakeGarbageCollected<SvgInlineNodeData>();
  svg_node_data->character_data_list = std::move(resolved_);
  svg_node_data->text_length_range_list = std::move(text_length_range_list_);
  svg_node_data->text_path_range_list = std::move(text_path_range_list_);
  return svg_node_data;
}

unsigned SvgTextLayoutAttributesBuilder::IfcTextContentOffsetAt(
    wtf_size_t index) {
  return ifc_text_content_offsets_.at(index);
}

}  // namespace blink

"""

```