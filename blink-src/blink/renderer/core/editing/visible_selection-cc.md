Response:
My thought process for analyzing the `visible_selection.cc` file went through these stages:

1. **Understand the Core Purpose:** The filename and the initial comments clearly point to this file being responsible for handling the *visible* selection within the Blink rendering engine. The key word here is "visible," implying that it deals with how the selection is presented and interacts with the user, considering factors like granularity and document structure.

2. **Identify Key Classes and Templates:**  I noticed the pervasive use of the `VisibleSelectionTemplate` template class. This immediately tells me that the code is designed to work with different strategies for representing the document structure (e.g., DOM tree vs. flat tree). This is a common pattern in Blink to handle different tree traversals. I also noted the `SelectionTemplate` class, which seems to be a lower-level representation of the selection.

3. **Break Down Functionality by Public Methods and Static Functions:** I started listing the prominent functions and methods, trying to categorize their purpose:

    * **Constructors:** How are `VisibleSelection` objects created? This led to identifying the various constructors and the `Creator` nested class.
    * **Accessors:** How can I get information *out* of a `VisibleSelection` object? This includes methods like `Start()`, `End()`, `Anchor()`, `Focus()`, `IsCaret()`, `IsRange()`, `IsNone()`, etc.
    * **Mutators/Transformers:** How can I create new `VisibleSelection` objects or representations based on existing ones? This includes `AsSelection()`, `ToNormalizedEphemeralRange()`, `ExpandWithGranularity()`.
    * **Comparison:** How can I check if two selections are the same?  This points to the `operator==`.
    * **Visibility-Related:** What functions explicitly deal with the "visible" aspect? This includes `CreateVisibleSelection()` and the adjustments performed within `ComputeVisibleSelection()`.
    * **Utility Functions:** What helper functions exist outside the class?  I noted `FirstEphemeralRangeOf()` and the `NormalizeRange()` overloads.

4. **Trace Data Flow in `ComputeVisibleSelection()`:** This function appeared to be the core logic for creating a visible selection. I meticulously examined the sequence of adjustments:

    * **Canonicalization:**  Ensuring a consistent representation of the underlying selection.
    * **Granularity Adjustment:**  Expanding or contracting the selection based on user-defined units (character, word, etc.).
    * **Shadow Boundary Adjustment:** Preventing the selection from crossing shadow DOM boundaries.
    * **Editing Boundary Adjustment:**  Respecting the boundaries of editable regions.
    * **Type Adjustment:**  Final adjustments based on the selection type.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):** I then thought about how each piece of functionality relates to the core web technologies:

    * **HTML:** The selection directly operates on the DOM structure defined by HTML. Examples: selecting text within a `<p>` tag, selecting an entire `<div>`.
    * **CSS:** While `visible_selection.cc` doesn't directly manipulate CSS, the *result* of the selection (the visual highlighting) is styled by CSS. The concept of editable regions is also tied to CSS properties like `contenteditable`.
    * **JavaScript:** JavaScript uses the browser's selection API (e.g., `window.getSelection()`) which is ultimately backed by code like this. JavaScript can manipulate the selection, trigger events based on selection changes, and use selection information.

6. **Consider User Actions and Debugging:**  I imagined how a user interacts with the browser and how those actions might lead to this code being executed. This helped me create the "User Interaction Walkthrough" and the "Debugging Scenario."  I thought about common user errors related to selection, like unintended selections or selections not behaving as expected.

7. **Infer Logical Reasoning and Assumptions:**  I looked for places where the code makes decisions or transformations. The `ComputeVisibleSelection` function is full of logical steps. I tried to articulate the assumptions behind these steps (e.g., the need for canonicalization, the different types of boundaries).

8. **Organize and Refine:** Finally, I structured my analysis into clear categories (Functionality, Relationships, Logic, Errors, Debugging) to make it easy to understand. I used examples to illustrate the concepts. I reviewed my explanation for clarity and accuracy.

Essentially, I followed a pattern of understanding the high-level purpose, diving into the details of the code, connecting those details to the broader context of web technologies and user interaction, and then synthesizing my findings into a comprehensive explanation. The process is iterative; I often jump back and forth between different levels of detail as my understanding grows.


好的，让我们来详细分析一下 `blink/renderer/core/editing/visible_selection.cc` 文件的功能。

**文件功能概览**

`visible_selection.cc` 文件定义了 Blink 渲染引擎中用于表示和操作用户可见文本选择的核心类 `VisibleSelection` 及其模板类 `VisibleSelectionTemplate`。它的主要职责是：

1. **表示可见的文本选择:**  它封装了选区的起始位置（anchor）、结束位置（focus）以及选区的方向性（affinity），并考虑了诸如光标（caret）和范围（range）等不同类型的选择。
2. **处理不同类型的文档结构:** 通过模板类 `VisibleSelectionTemplate`，该文件可以处理基于 DOM 树 (`EditingStrategy`) 和扁平树 (`EditingInFlatTreeStrategy`) 的选择。
3. **提供创建和修改可见选区的方法:**  它提供了多种方法来创建、复制和修改 `VisibleSelection` 对象，例如基于 `Selection` 对象创建，或者通过调整粒度（字符、单词等）来扩展选区。
4. **提供查询选区信息的方法:** 可以获取选区的起始和结束位置、判断是否为光标、是否为空、是否为范围等。
5. **处理选区的规范化和调整:**  它负责将逻辑选择转换为在渲染树中可见的选区，并根据不同的边界（阴影 DOM 边界、可编辑区域边界）进行调整。
6. **与其他编辑模块协同工作:** 该文件与编辑相关的其他模块（如 `EphemeralRange`、`SelectionAdjuster` 等）密切合作，共同完成文本编辑功能。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`VisibleSelection` 类是 Blink 渲染引擎内部的核心概念，它直接支撑着浏览器提供的选择功能，因此与 JavaScript, HTML, CSS 都有密切关系：

**1. 与 JavaScript 的关系:**

* **JavaScript Selection API:**  JavaScript 通过 `window.getSelection()` API 可以获取当前页面中的用户选择。  `VisibleSelection` 类是 Blink 内部实现这个 API 的关键部分。当 JavaScript 代码调用 `window.getSelection()` 或修改选择时，最终会涉及到 `VisibleSelection` 对象的创建和操作。
* **事件处理:**  JavaScript 可以监听与选择相关的事件，例如 `selectionchange`。当用户的选择发生改变时，Blink 内部会更新 `VisibleSelection` 对象，并触发相应的 JavaScript 事件。

**举例:**

```javascript
// JavaScript 获取当前选区的文本内容
const selection = window.getSelection();
const selectedText = selection.toString();
console.log(selectedText);

// JavaScript 设置选区
const range = document.createRange();
const startNode = document.getElementById('startNode');
const endNode = document.getElementById('endNode');
range.setStart(startNode, 0);
range.setEnd(endNode, endNode.childNodes.length);
selection.removeAllRanges();
selection.addRange(range);
```

在这些 JavaScript 操作的背后，Blink 引擎会使用 `VisibleSelection` 类来管理和维护选区的状态。

**2. 与 HTML 的关系:**

* **内容选择:**  `VisibleSelection` 的核心功能是选择 HTML 文档中的内容。用户通过鼠标拖拽或键盘操作选择的文本或元素，最终都会被表示为 `VisibleSelection` 对象。
* **可编辑区域:** HTML 中的 `contenteditable` 属性定义了哪些区域可以被用户编辑。`VisibleSelection` 会考虑这些可编辑区域的边界，确保选择操作在允许的范围内进行。
* **Shadow DOM:**  `VisibleSelection` 需要处理 Shadow DOM 的边界，防止选择跨越 Shadow Host 和 Shadow Tree。

**举例:**

```html
<p>这是一个段落，用户可以 <b>选择</b> 其中的文本。</p>

<div contenteditable="true">
  这是一个可编辑的区域。
</div>

<my-component>
  #shadow-root
  <p>这是 Shadow DOM 中的内容。</p>
</my-component>
```

当用户在上述 HTML 结构中进行选择时，`VisibleSelection` 会根据 DOM 树的结构和 `contenteditable` 属性来确定选区的范围。

**3. 与 CSS 的关系:**

* **选区样式:** CSS 伪元素 `::selection` 允许开发者自定义用户选择文本时的样式（例如背景颜色、文本颜色）。虽然 `visible_selection.cc` 本身不负责样式渲染，但它提供的选区信息被渲染引擎用于应用这些样式。
* **光标样式:** CSS 的 `caret-color` 属性可以设置文本输入框中光标的颜色。 `VisibleSelection` 中关于光标的处理与此相关。

**举例:**

```css
::selection {
  background-color: yellow;
  color: black;
}

input {
  caret-color: blue;
}
```

当用户选择文本时，CSS 中定义的 `::selection` 样式会被应用到 `VisibleSelection` 所表示的选区上。

**逻辑推理 (假设输入与输出)**

假设用户在以下 HTML 片段中进行选择：

```html
<p id="para">Hello <b>World</b>!</p>
```

**场景 1：用户点击 "H" 字符，然后拖拽到 "o" 字符。**

* **假设输入:** 用户操作，起始位置在 "Hello" 的 "H" 之前，结束位置在 "Hello" 的 "o" 之后。
* **逻辑推理:**
    * `CreateVisibleSelection` 函数会被调用，基于起始和结束位置创建一个 `SelectionInDOMTree` 对象。
    * `VisibleSelection::Creator::ComputeVisibleSelection` 会被调用，根据 `TextGranularity::kCharacter` 进行调整。
    * 规范化后，`anchor_` 将指向 `<p>` 元素的第一个文本节点 "Hello" 的开头，`focus_` 将指向该文本节点中 "o" 之后的位置。
    * `anchor_is_first_` 将为 true。
* **预期输出:** 一个 `VisibleSelection` 对象，其 `Start()` 返回指向 "H" 之前的 `Position`，`End()` 返回指向 "o" 之后的 `Position`，表示选择了 "Hello" 这五个字符。

**场景 2：用户双击 "World"。**

* **假设输入:** 用户双击 "World" 这个单词。
* **逻辑推理:**
    * 系统会识别出双击操作，并根据单词的粒度进行选择。
    * `CreateVisibleSelection` 函数会被调用，基于双击的位置创建一个初始的 `SelectionInDOMTree` 对象。
    * `VisibleSelection::Creator::ComputeVisibleSelection` 会被调用，这次的 `TextGranularity` 可能是 `kWord`。
    * `SelectionAdjuster::AdjustSelectionRespectingGranularity` 会将选区扩展到整个单词的边界。
    * 规范化后，`anchor_` 将指向 `<b>` 元素的文本节点 "World" 的开头，`focus_` 将指向该文本节点的结尾之后。
    * `anchor_is_first_` 将为 true。
* **预期输出:** 一个 `VisibleSelection` 对象，其 `Start()` 返回指向 "World" 之前的 `Position`，`End()` 返回指向 "World" 之后的 `Position`，表示选择了 "World" 这个单词。

**用户或编程常见的使用错误 (及如何到达这里)**

**1. 选择状态与 DOM 结构不一致:**

* **错误:**  JavaScript 代码直接修改了 DOM 结构，但没有同步更新选择状态，导致 `VisibleSelection` 对象持有的位置信息不再有效。
* **如何到达 `visible_selection.cc`:**
    1. 用户在页面上进行了一些选择。
    2. JavaScript 代码使用 `innerHTML` 或类似方法移除了包含选区一部分的 DOM 节点。
    3. 浏览器内部尝试使用过时的 `VisibleSelection` 对象进行操作（例如，获取选区文本）。
    4. 这可能会导致 `IsValidFor()` 检查失败，或者在访问 `anchor_` 或 `focus_` 指向的节点时出现问题，最终在调试过程中定位到 `visible_selection.cc`。

**2. 在 Shadow DOM 中进行不正确的选择操作:**

* **错误:**  尝试创建一个跨越 Shadow DOM 边界的选择，而没有正确处理 Shadow Host 和 Shadow Root。
* **如何到达 `visible_selection.cc`:**
    1. 页面包含使用了 Shadow DOM 的 Web Components。
    2. JavaScript 代码尝试创建一个 Range 对象，其起始节点在 Shadow Host 外部，结束节点在 Shadow Tree 内部，或者反之。
    3. 当这个 Range 被转换为 `VisibleSelection` 时，`SelectionAdjuster::AdjustSelectionToAvoidCrossingShadowBoundaries` 函数会进行调整，开发者可能会在调试这个调整过程时进入 `visible_selection.cc`。

**3. 在不可编辑区域尝试进行选择操作:**

* **错误:**  代码尝试在 `contenteditable="false"` 的元素内部设置或获取选择。
* **如何到达 `visible_selection.cc`:**
    1. 页面包含 `contenteditable="false"` 的元素。
    2. JavaScript 代码尝试使用 `selection.addRange()` 在该元素内部设置选区。
    3. `VisibleSelection` 在创建或调整过程中，会检查位置的 `IsContentEditable()` 属性，如果发现位置在不可编辑区域，可能会进行调整或抛出错误（具体取决于实现），调试时可能会进入 `visible_selection.cc`。

**用户操作如何一步步的到达这里 (作为调试线索)**

1. **用户鼠标按下并拖动:**
   * 用户在浏览器窗口中，在一个可编辑或可选择的区域内，按下鼠标左键。
   * 浏览器接收到 `mousedown` 事件。
   * 浏览器内部开始记录鼠标按下的位置。
   * 当鼠标移动时，浏览器不断接收 `mousemove` 事件。
   * 在处理 `mousemove` 事件的过程中，Blink 渲染引擎会根据鼠标移动的轨迹，动态更新用户的可见选择。
   * 这涉及创建和修改 `VisibleSelection` 对象，相关的代码执行会进入 `visible_selection.cc` 文件。

2. **用户双击或三击:**
   * 用户在文本上快速双击或三击。
   * 浏览器识别出双击或三击操作。
   * Blink 渲染引擎根据双击或三击的位置，以及预定义的粒度（单词、行等），计算出要选择的文本范围。
   * 这个计算过程会调用 `VisibleSelection::Creator::ComputeVisibleSelection`，并根据不同的 `TextGranularity` 进行调整。

3. **用户使用键盘进行选择 (Shift + 方向键):**
   * 用户按下 Shift 键，并同时按下方向键（例如，Shift + Right Arrow）。
   * 浏览器接收到 `keydown` 事件。
   * Blink 渲染引擎会根据按下的方向键，扩展或缩小当前的 `VisibleSelection`。
   * 这涉及到修改现有的 `VisibleSelection` 对象的 `focus_` 位置，并可能调用 `ExpandWithGranularity` 等函数。

4. **JavaScript 代码操作选择:**
   * 网页上的 JavaScript 代码调用了 `window.getSelection()` 获取选择对象，或者使用 `selection.addRange()` 等方法修改了选择。
   * 这些 JavaScript API 的底层实现会直接调用 Blink 渲染引擎中处理选择的相关代码，包括 `visible_selection.cc` 中定义的类和方法。

**调试线索:**

当你在调试与选择相关的问题时，如果断点命中了 `visible_selection.cc` 文件，你可以关注以下信息：

* **`anchor_` 和 `focus_` 的值:**  这两个成员变量表示选区的起始和结束位置，检查它们指向的 DOM 节点和偏移量是否符合预期。
* **`affinity_` 的值:**  确定选区的方向性，这对于理解光标位置或范围的扩展方向很重要。
* **调用堆栈:**  查看调用 `visible_selection.cc` 中函数的上层代码，可以帮助你理解是哪个模块触发了选择操作。
* **相关的事件:**  例如，`mousedown`、`mousemove`、`mouseup`、`keydown`、`selectionchange` 等事件的处理函数可能会涉及到 `VisibleSelection` 的创建和修改。
* **DOM 树结构:**  确认相关的 DOM 节点的结构和属性（例如，`contenteditable`），这有助于理解选择的边界和行为。

希望以上详细的解释能够帮助你理解 `blink/renderer/core/editing/visible_selection.cc` 文件的功能及其与 Web 技术的关系。

Prompt: 
```
这是目录为blink/renderer/core/editing/visible_selection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2004, 2005, 2006 Apple Computer, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/visible_selection.h"

#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/iterators/character_iterator.h"
#include "third_party/blink/renderer/core/editing/selection_adjuster.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

template <typename Strategy>
VisibleSelectionTemplate<Strategy>::VisibleSelectionTemplate()
    : affinity_(TextAffinity::kDownstream), anchor_is_first_(true) {}

template <typename Strategy>
VisibleSelectionTemplate<Strategy>::VisibleSelectionTemplate(
    const SelectionTemplate<Strategy>& selection)
    : anchor_(selection.Anchor()),
      focus_(selection.Focus()),
      affinity_(selection.Affinity()),
      anchor_is_first_(selection.IsAnchorFirst()) {}

template <typename Strategy>
class VisibleSelectionTemplate<Strategy>::Creator {
  STATIC_ONLY(Creator);

 public:
  static VisibleSelectionTemplate<Strategy> CreateWithGranularity(
      const SelectionTemplate<Strategy>& selection,
      TextGranularity granularity) {
    return VisibleSelectionTemplate<Strategy>(
        ComputeVisibleSelection(selection, granularity));
  }

  static SelectionTemplate<Strategy> ComputeVisibleSelection(
      const SelectionTemplate<Strategy>& passed_selection,
      TextGranularity granularity,
      const WordInclusion& inclusion = WordInclusion::kDefault) {
    DCHECK(!NeedsLayoutTreeUpdate(passed_selection.Anchor()));
    DCHECK(!NeedsLayoutTreeUpdate(passed_selection.Focus()));

    const SelectionTemplate<Strategy>& canonicalized_selection =
        CanonicalizeSelection(passed_selection);

    if (canonicalized_selection.IsNone())
      return SelectionTemplate<Strategy>();

    const SelectionTemplate<Strategy>& granularity_adjusted_selection =
        SelectionAdjuster::AdjustSelectionRespectingGranularity(
            canonicalized_selection, granularity, inclusion);
    const SelectionTemplate<Strategy>& shadow_adjusted_selection =
        SelectionAdjuster::AdjustSelectionToAvoidCrossingShadowBoundaries(
            granularity_adjusted_selection);
    const SelectionTemplate<Strategy>& editing_adjusted_selection =
        SelectionAdjuster::AdjustSelectionToAvoidCrossingEditingBoundaries(
            shadow_adjusted_selection);
    const SelectionTemplate<Strategy>& type_adjusted_selection =
        SelectionAdjuster::AdjustSelectionType(
            typename SelectionTemplate<Strategy>::Builder(
                editing_adjusted_selection)
                .SetAffinity(passed_selection.Affinity())
                .Build());
    return type_adjusted_selection;
  }
};

VisibleSelection CreateVisibleSelection(const SelectionInDOMTree& selection) {
  return VisibleSelection::Creator::CreateWithGranularity(
      selection, TextGranularity::kCharacter);
}

VisibleSelectionInFlatTree CreateVisibleSelection(
    const SelectionInFlatTree& selection) {
  return VisibleSelectionInFlatTree::Creator::CreateWithGranularity(
      selection, TextGranularity::kCharacter);
}

SelectionInDOMTree ExpandWithGranularity(const SelectionInDOMTree& selection,
                                         TextGranularity granularity,
                                         const WordInclusion& inclusion) {
  return VisibleSelection::Creator::ComputeVisibleSelection(
      selection, granularity, inclusion);
}

SelectionInFlatTree ExpandWithGranularity(const SelectionInFlatTree& selection,
                                          TextGranularity granularity,
                                          const WordInclusion& inclusion) {
  return VisibleSelectionInFlatTree::Creator::ComputeVisibleSelection(
      selection, granularity, inclusion);
}

template <typename Strategy>
VisibleSelectionTemplate<Strategy>::VisibleSelectionTemplate(
    const VisibleSelectionTemplate<Strategy>& other)
    : anchor_(other.anchor_),
      focus_(other.focus_),
      affinity_(other.affinity_),
      anchor_is_first_(other.anchor_is_first_) {}

template <typename Strategy>
VisibleSelectionTemplate<Strategy>& VisibleSelectionTemplate<Strategy>::
operator=(const VisibleSelectionTemplate<Strategy>& other) {
  anchor_ = other.anchor_;
  focus_ = other.focus_;
  affinity_ = other.affinity_;
  anchor_is_first_ = other.anchor_is_first_;
  return *this;
}

template <typename Strategy>
SelectionTemplate<Strategy> VisibleSelectionTemplate<Strategy>::AsSelection()
    const {
  if (anchor_.IsNull()) {
    return typename SelectionTemplate<Strategy>::Builder()
        .Build();
  }
  return typename SelectionTemplate<Strategy>::Builder()
      .SetBaseAndExtent(anchor_, focus_)
      .SetAffinity(affinity_)
      .Build();
}

template <typename Strategy>
bool VisibleSelectionTemplate<Strategy>::IsCaret() const {
  return anchor_.IsNotNull() && anchor_ == focus_;
}

template <typename Strategy>
bool VisibleSelectionTemplate<Strategy>::IsNone() const {
  return anchor_.IsNull();
}

template <typename Strategy>
bool VisibleSelectionTemplate<Strategy>::IsRange() const {
  return anchor_ != focus_;
}

template <typename Strategy>
PositionTemplate<Strategy> VisibleSelectionTemplate<Strategy>::Start() const {
  return anchor_is_first_ ? anchor_ : focus_;
}

template <typename Strategy>
PositionTemplate<Strategy> VisibleSelectionTemplate<Strategy>::End() const {
  return anchor_is_first_ ? focus_ : anchor_;
}

EphemeralRange FirstEphemeralRangeOf(const VisibleSelection& selection) {
  if (selection.IsNone())
    return EphemeralRange();
  Position start = selection.Start().ParentAnchoredEquivalent();
  Position end = selection.End().ParentAnchoredEquivalent();
  return EphemeralRange(start, end);
}

template <typename Strategy>
EphemeralRangeTemplate<Strategy>
VisibleSelectionTemplate<Strategy>::ToNormalizedEphemeralRange() const {
  return NormalizeRange(AsSelection());
}

template <typename Strategy>
static EphemeralRangeTemplate<Strategy> NormalizeRangeAlgorithm(
    const SelectionTemplate<Strategy>& selection) {
  if (selection.IsNone())
    return EphemeralRangeTemplate<Strategy>();

  // Make sure we have an updated layout since this function is called
  // in the course of running edit commands which modify the DOM.
  // Failing to ensure this can result in equivalentXXXPosition calls returning
  // incorrect results.
  DCHECK(!NeedsLayoutTreeUpdate(selection.Anchor())) << selection;

  if (selection.IsCaret()) {
    // If the selection is a caret, move the range start upstream. This
    // helps us match the conventions of text editors tested, which make
    // style determinations based on the character before the caret, if any.
    const PositionTemplate<Strategy> start =
        MostBackwardCaretPosition(selection.ComputeStartPosition())
            .ParentAnchoredEquivalent();
    return EphemeralRangeTemplate<Strategy>(start, start);
  }
  // If the selection is a range, select the minimum range that encompasses
  // the selection. Again, this is to match the conventions of text editors
  // tested, which make style determinations based on the first character of
  // the selection. For instance, this operation helps to make sure that the
  // "X" selected below is the only thing selected. The range should not be
  // allowed to "leak" out to the end of the previous text node, or to the
  // beginning of the next text node, each of which has a different style.
  //
  // On a treasure map, <b>X</b> marks the spot.
  //                       ^ selected
  //
  DCHECK(selection.IsRange());
  return NormalizeRange(selection.ComputeRange());
}

EphemeralRange NormalizeRange(const SelectionInDOMTree& selection) {
  return NormalizeRangeAlgorithm(selection);
}

EphemeralRangeInFlatTree NormalizeRange(const SelectionInFlatTree& selection) {
  return NormalizeRangeAlgorithm(selection);
}

template <typename Strategy>
static SelectionTemplate<Strategy> CanonicalizeSelection(
    const SelectionTemplate<Strategy>& selection) {
  if (selection.IsNone())
    return SelectionTemplate<Strategy>();
  const PositionTemplate<Strategy>& anchor =
      CreateVisiblePosition(selection.Anchor(), selection.Affinity())
          .DeepEquivalent();
  if (selection.IsCaret()) {
    if (anchor.IsNull()) {
      return SelectionTemplate<Strategy>();
    }
    return typename SelectionTemplate<Strategy>::Builder()
        .Collapse(anchor)
        .Build();
  }
  const PositionTemplate<Strategy>& focus =
      CreateVisiblePosition(selection.Focus(), selection.Affinity())
          .DeepEquivalent();
  if (anchor.IsNotNull() && focus.IsNotNull()) {
    return typename SelectionTemplate<Strategy>::Builder()
        .SetBaseAndExtent(anchor, focus)
        .Build();
  }
  if (anchor.IsNotNull()) {
    return typename SelectionTemplate<Strategy>::Builder()
        .Collapse(anchor)
        .Build();
  }
  if (focus.IsNotNull()) {
    return
        typename SelectionTemplate<Strategy>::Builder().Collapse(focus).Build();
  }
  return SelectionTemplate<Strategy>();
}

template <typename Strategy>
bool VisibleSelectionTemplate<Strategy>::IsValidFor(
    const Document& document) const {
  if (IsNone())
    return true;
  return anchor_.IsValidFor(document) && focus_.IsValidFor(document);
}

template <typename Strategy>
bool VisibleSelectionTemplate<Strategy>::IsContentEditable() const {
  return IsEditablePosition(Start());
}

template <typename Strategy>
Element* VisibleSelectionTemplate<Strategy>::RootEditableElement() const {
  return RootEditableElementOf(Start());
}

template <typename Strategy>
static bool EqualSelectionsAlgorithm(
    const VisibleSelectionTemplate<Strategy>& selection1,
    const VisibleSelectionTemplate<Strategy>& selection2) {
  if (selection1.Affinity() != selection2.Affinity())
    return false;

  if (selection1.IsNone())
    return selection2.IsNone();

  const VisibleSelectionTemplate<Strategy> selection_wrapper1(selection1);
  const VisibleSelectionTemplate<Strategy> selection_wrapper2(selection2);

  return selection_wrapper1.Anchor() == selection_wrapper2.Anchor() &&
         selection_wrapper1.Focus() == selection_wrapper2.Focus();
}

template <typename Strategy>
bool VisibleSelectionTemplate<Strategy>::operator==(
    const VisibleSelectionTemplate<Strategy>& other) const {
  return EqualSelectionsAlgorithm<Strategy>(*this, other);
}

template <typename Strategy>
VisiblePositionTemplate<Strategy>
VisibleSelectionTemplate<Strategy>::VisibleStart() const {
  return CreateVisiblePosition(
      Start(), IsRange() ? TextAffinity::kDownstream : Affinity());
}

template <typename Strategy>
VisiblePositionTemplate<Strategy>
VisibleSelectionTemplate<Strategy>::VisibleEnd() const {
  return CreateVisiblePosition(
      End(), IsRange() ? TextAffinity::kUpstream : Affinity());
}

template <typename Strategy>
VisiblePositionTemplate<Strategy>
VisibleSelectionTemplate<Strategy>::VisibleAnchor() const {
  return CreateVisiblePosition(
      anchor_, IsRange() ? (IsAnchorFirst() ? TextAffinity::kUpstream
                                            : TextAffinity::kDownstream)
                         : Affinity());
}

template <typename Strategy>
VisiblePositionTemplate<Strategy>
VisibleSelectionTemplate<Strategy>::VisibleFocus() const {
  return CreateVisiblePosition(
      focus_, IsRange() ? (IsAnchorFirst() ? TextAffinity::kDownstream
                                           : TextAffinity::kUpstream)
                        : Affinity());
}

template <typename Strategy>
void VisibleSelectionTemplate<Strategy>::Trace(Visitor* visitor) const {
  visitor->Trace(anchor_);
  visitor->Trace(focus_);
}

#if DCHECK_IS_ON()

template <typename Strategy>
void VisibleSelectionTemplate<Strategy>::ShowTreeForThis() const {
  if (!Start().AnchorNode()) {
    LOG(INFO) << "\nselection is null";
    return;
  }
  LOG(INFO) << "\n"
            << Start()
                   .AnchorNode()
                   ->ToMarkedTreeString(Start().AnchorNode(), "S",
                                        End().AnchorNode(), "E")
                   .Utf8()
            << "start: " << Start().ToAnchorTypeAndOffsetString().Utf8() << "\n"
            << "end: " << End().ToAnchorTypeAndOffsetString().Utf8();
}

#endif

template <typename Strategy>
void VisibleSelectionTemplate<Strategy>::PrintTo(
    const VisibleSelectionTemplate<Strategy>& selection,
    std::ostream* ostream) {
  if (selection.IsNone()) {
    *ostream << "VisibleSelection()";
    return;
  }
  *ostream << "VisibleSelection(anchor: " << selection.Anchor()
           << " focus:" << selection.Focus() << " start: " << selection.Start()
           << " end: " << selection.End() << ' ' << selection.Affinity() << ' '
           << ')';
}

template class CORE_TEMPLATE_EXPORT VisibleSelectionTemplate<EditingStrategy>;
template class CORE_TEMPLATE_EXPORT
    VisibleSelectionTemplate<EditingInFlatTreeStrategy>;

std::ostream& operator<<(std::ostream& ostream,
                         const VisibleSelection& selection) {
  VisibleSelection::PrintTo(selection, &ostream);
  return ostream;
}

std::ostream& operator<<(std::ostream& ostream,
                         const VisibleSelectionInFlatTree& selection) {
  VisibleSelectionInFlatTree::PrintTo(selection, &ostream);
  return ostream;
}

}  // namespace blink

#if DCHECK_IS_ON()

void ShowTree(const blink::VisibleSelection& sel) {
  sel.ShowTreeForThis();
}

void ShowTree(const blink::VisibleSelection* sel) {
  if (sel)
    sel->ShowTreeForThis();
}

void ShowTree(const blink::VisibleSelectionInFlatTree& sel) {
  sel.ShowTreeForThis();
}

void ShowTree(const blink::VisibleSelectionInFlatTree* sel) {
  if (sel)
    sel->ShowTreeForThis();
}
#endif

"""

```