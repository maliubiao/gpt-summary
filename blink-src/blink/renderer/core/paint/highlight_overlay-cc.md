Response:
Let's break down the thought process for analyzing the `highlight_overlay.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relation to web technologies (JavaScript, HTML, CSS), examples, logical reasoning with input/output, common user errors, and debugging context.

2. **Initial Scan and Keyword Identification:** Quickly read through the file, looking for key terms and concepts. I notice:
    * `HighlightOverlay` (the central class)
    * `HighlightLayer`, `HighlightRange`, `HighlightEdge`, `HighlightDecoration`, `HighlightPart` (data structures)
    * Different highlight types: `kOriginating`, `kCustom`, `kGrammar`, `kSpelling`, `kTargetText`, `kSearchText`, `kSearchTextActiveMatch`, `kSelection`
    * `ComputeLayers`, `ComputeEdges`, `ComputeParts` (core functions)
    * References to `Document`, `Node`, `ComputedStyle`, `Text`, `LayoutSelectionStatus`, `DocumentMarkerVector`, `HighlightRegistry` (Blink concepts)
    * Mentions of CSS pseudo-elements (`::highlight`, `::grammar-error`, etc.)

3. **Deconstruct the Functionality:**  Based on the keywords, I can infer the core purpose: to manage and calculate the visual representation of text highlights in a web page. Specifically, it deals with:
    * **Defining different types of highlights:**  The various `HighlightLayerType` enums and their corresponding pseudo-elements.
    * **Determining the order of highlights:**  The `ComparePaintOrder` function and the interaction with `HighlightRegistry`.
    * **Calculating the boundaries of highlights:** The `HighlightRange` and the `ComputeEdges` function.
    * **Styling highlights:** The connection to `ComputedStyle` and the `HighlightStyleUtils`.
    * **Breaking down highlights into paintable parts:** The `ComputeParts` function.

4. **Relate to Web Technologies:**  Now, I explicitly connect these internal functionalities to the user-facing web technologies:
    * **HTML:**  Highlights apply to text content within HTML elements.
    * **CSS:**  The styling of highlights is heavily influenced by CSS, especially pseudo-elements like `::selection` and the `::highlight()` pseudo-class. Custom highlights are directly linked to CSS custom highlight registrations.
    * **JavaScript:**  JavaScript APIs (like the Selection API and the Custom Highlight API) trigger the creation and modification of highlights.

5. **Provide Concrete Examples:**  For each web technology connection, create simple, illustrative examples. This helps solidify the understanding.

6. **Analyze Logical Reasoning (Input/Output):**  The `ComputeLayers`, `ComputeEdges`, and `ComputeParts` functions are prime candidates for input/output analysis.
    * **`ComputeLayers`:** Input is the context (document, node, styles, markers). Output is the ordered list of highlight layers with associated styles. I can create a hypothetical scenario (a text node with a selection and a custom highlight) and trace how the layers would be generated.
    * **`ComputeEdges`:** Input is the node, layers, and marker information. Output is a sorted list of "edges" representing the start and end points of highlights. Again, a scenario with a selection and a custom highlight can illustrate the edge creation.
    * **`ComputeParts`:** Input is the text fragment information, layers, and edges. Output is the breakdown of the text into parts with associated styling for each active highlight. This requires a slightly more complex scenario to showcase the different highlight combinations.

7. **Identify Common Usage Errors:** Think about how developers might misuse or misunderstand highlight functionality:
    * **CSS specificity:** Conflicting styles on different highlight layers.
    * **Incorrect range definitions:** Issues with the JavaScript APIs for creating custom highlights.
    * **Z-index conflicts:**  While the code handles internal ordering, developers might have broader z-index issues if highlights overlap other content.

8. **Construct a Debugging Scenario:**  Describe a step-by-step user interaction that would lead to this code being executed. Start from a simple user action (selecting text, using the Find feature, or a website with custom highlights) and follow the likely chain of events within the browser. This demonstrates how a seemingly simple user action triggers complex internal logic.

9. **Structure and Refine:** Organize the information logically using headings and bullet points. Ensure clarity and conciseness. Review the examples and explanations for accuracy and completeness. For instance, initially, I might have just said "CSS styles the highlights." But I refined it to specify the relevant CSS features like pseudo-elements and custom highlight registrations. Similarly, I initially thought about just the Selection API but realized the Custom Highlight API was also crucial.

10. **Self-Correction/Refinement During the Process:** As I was writing the examples and explanations, I might have realized I needed to clarify certain points or provide more detail. For instance, when discussing `ComparePaintOrder`, I realized I needed to emphasize its role in determining the visual stacking order of overlapping highlights. I also double-checked the connection between `HighlightLayerType` and the corresponding pseudo-elements. I also considered if the "user errors" were *directly* within this code or were more related to *using* the highlight features, leaning towards the latter as this file primarily deals with internal calculations.

By following this structured approach, I can systematically analyze the source code and provide a comprehensive answer that addresses all aspects of the request.
好的，我们来分析一下 `blink/renderer/core/paint/highlight_overlay.cc` 这个文件。

**功能概述**

`highlight_overlay.cc` 文件的主要功能是**计算和管理文本高亮的覆盖层 (overlay)**。  它负责确定如何在渲染过程中绘制各种类型的文本高亮，例如：

* **用户选择高亮 (Selection Highlight):** 用户通过鼠标或键盘选择的文本。
* **搜索高亮 (Search Highlight):**  在页面中搜索关键词时匹配到的文本。
* **当前激活的搜索匹配高亮 (Active Search Match Highlight):** 当前正在查看的搜索结果。
* **拼写错误/语法错误高亮 (Spelling/Grammar Error Highlight):**  浏览器检测到的拼写或语法错误。
* **目标文本高亮 (Target Text Highlight):**  通常用于锚点链接跳转后高亮显示的目标文本。
* **自定义高亮 (Custom Highlight):**  通过 JavaScript API (Custom Highlight API) 创建的高亮。
* **起始样式高亮 (Originating Highlight):**  应用文本的基础样式，作为其他高亮的基准。

该文件定义了用于表示高亮信息的各种数据结构，并实现了计算这些高亮在渲染时需要的信息的逻辑，例如：

* **高亮层 (HighlightLayer):** 表示一种类型的高亮，包含其类型、名称（用于自定义高亮）和样式信息。
* **高亮范围 (HighlightRange):** 表示高亮在文本中的起始和结束偏移量。
* **高亮边缘 (HighlightEdge):** 表示高亮范围的开始或结束边界，并包含其所属的图层信息，用于排序。
* **高亮装饰 (HighlightDecoration):** 表示高亮的装饰效果，如下划线、删除线等。
* **高亮背景 (HighlightBackground):** 表示高亮的背景颜色。
* **高亮文本阴影 (HighlightTextShadow):** 表示高亮的文本阴影效果。
* **高亮部分 (HighlightPart):** 表示一段连续的文本，具有相同的高亮样式组合。

**与 JavaScript, HTML, CSS 的关系**

`highlight_overlay.cc` 文件是 Chromium 渲染引擎 Blink 的一部分，它负责将 HTML、CSS 和 JavaScript 的描述转化为用户可见的网页。 该文件在处理文本高亮时与这三种技术都有密切关系：

* **HTML:**  高亮最终作用于 HTML 文档中的文本内容。该文件接收表示 HTML 结构和文本内容的输入，并计算需要在哪些文本范围内绘制高亮。
    * **举例:**  当用户在 HTML 页面中选择一段文本时，浏览器会记录选区的起始和结束位置，这些信息最终会传递到 `highlight_overlay.cc` 中，用于计算选择高亮的覆盖层。
* **CSS:**  CSS 决定了高亮的样式。不同的高亮类型 (例如选择、搜索、自定义) 可以通过 CSS 伪元素进行样式化。
    * **举例:**
        * `::selection` 伪元素允许开发者自定义用户选择文本的背景色和文本颜色。`highlight_overlay.cc` 会根据 `::selection` 的 CSS 规则来确定选择高亮的颜色。
        * Custom Highlight API 允许开发者注册自定义的高亮样式，这些样式会对应到特定的 CSS 伪类，例如 `::highlight(my-highlight)`. `highlight_overlay.cc` 会获取这些自定义的 CSS 样式信息。
        * `::spelling-error` 和 `::grammar-error` 伪元素用于设置拼写和语法错误高亮的样式。
* **JavaScript:**  JavaScript 可以通过 API 来触发或修改高亮。
    * **举例:**
        * **Selection API:**  JavaScript 可以使用 `window.getSelection()` 获取用户当前的选区，或者使用 `document.getSelection().empty()` 清空选区。这些操作会间接地影响 `highlight_overlay.cc` 的计算结果。
        * **Find in Page (搜索):**  当用户在页面中使用 "查找" 功能时，JavaScript 会在页面中搜索匹配的文本，并将这些匹配信息传递给渲染引擎，最终由 `highlight_overlay.cc` 计算搜索高亮。
        * **Custom Highlight API:**  JavaScript 可以使用 `CSS.highlights.set()` 和 `CSS.highlights.delete()` 来创建和删除自定义高亮。这些 API 的调用会直接影响 `highlight_overlay.cc` 中自定义高亮的计算。

**逻辑推理 (假设输入与输出)**

假设我们有一个简单的 HTML 文本节点：

```html
<p id="myText">This is some text to highlight.</p>
```

**场景 1: 用户选择文本**

* **假设输入:**
    * 用户使用鼠标选中了 "some text" 这几个字符。
    * `node`:  指向 "This is some text to highlight." 这个文本节点的指针。
    * `selection`: 一个 `LayoutSelectionStatus` 对象，包含 `start = 8`, `end = 17` (对应 "some text" 的偏移量)。

* **输出:**
    * `ComputeEdges` 函数会生成两个 `HighlightEdge` 对象:
        * 一个表示选择高亮开始的边缘: `HighlightEdge{range: [8, 17), type: kSelection, layer_index: X, edge_type: kStart}` (X 是选择高亮图层的索引)。
        * 一个表示选择高亮结束的边缘: `HighlightEdge{range: [8, 17), type: kSelection, layer_index: X, edge_type: kEnd}`。
    * `ComputeParts` 函数会根据这些边缘信息生成一个或多个 `HighlightPart` 对象，其中包含 "some text" 部分，并标记其为选择高亮。

**场景 2: JavaScript 创建自定义高亮**

* **假设输入:**
    * JavaScript 代码执行了以下操作：
    ```javascript
    const textNode = document.getElementById('myText').firstChild;
    const range = document.createRange();
    range.setStart(textNode, 11); // "text" 的起始位置
    range.setEnd(textNode, 15);   // "text" 的结束位置

    const highlights = CSS.highlights;
    const myHighlight = new Highlight(range);
    highlights.set('my-custom-highlight', myHighlight);
    ```
    * `node`: 指向 "This is some text to highlight." 这个文本节点的指针。
    * `custom`: 一个包含自定义高亮标记的 `DocumentMarkerVector`，其中包含一个针对 "text" 范围 (偏移 11 到 15) 的 `CustomHighlightMarker`，其名称为 "my-custom-highlight"。

* **输出:**
    * `ComputeLayers` 函数会创建一个类型为 `kCustom`，名称为 "my-custom-highlight" 的 `HighlightLayer`。
    * `ComputeEdges` 函数会生成两个 `HighlightEdge` 对象:
        * 一个表示自定义高亮开始的边缘: `HighlightEdge{range: [11, 15), type: kCustom, layer_index: Y, edge_type: kStart}` (Y 是自定义高亮图层的索引)。
        * 一个表示自定义高亮结束的边缘: `HighlightEdge{range: [11, 15), type: kCustom, layer_index: Y, edge_type: kEnd}`。
    * `ComputeParts` 函数会生成包含 "text" 部分的 `HighlightPart` 对象，并标记其为自定义高亮。

**用户或编程常见的使用错误**

* **CSS 样式冲突导致高亮显示不正确:**  开发者可能定义了冲突的 CSS 规则，导致不同类型的高亮互相覆盖或样式不符合预期。
    * **举例:**  同时设置了 `::selection` 和 `::highlight(my-highlight)` 的背景色，但优先级设置不当，导致用户选择文本时，自定义高亮的颜色覆盖了选择高亮的颜色。
* **JavaScript Custom Highlight API 使用不当:**
    * **范围设置错误:**  传递给 `Highlight` 构造函数的 Range 对象可能起始或结束位置错误，导致高亮范围不符合预期。
    * **忘记注册自定义高亮样式:**  使用 Custom Highlight API 创建了高亮，但没有在 CSS 中定义对应的 `::highlight()` 伪类的样式，导致高亮没有视觉效果。
* **假设文本内容不会改变:**  在计算高亮时，如果文本内容在之后发生了改变 (例如通过 JavaScript 修改 DOM)，之前计算的高亮信息可能失效，需要重新计算。
* **性能问题:**  在包含大量文本和高亮的页面上，频繁地创建和更新高亮可能导致性能问题。

**用户操作是如何一步步的到达这里，作为调试线索**

以下是一些用户操作可能触发 `highlight_overlay.cc` 代码执行的场景，可以作为调试线索：

1. **用户选择文本:**
   * 用户使用鼠标按下并拖动，或使用 Shift + 方向键来选择页面上的文本。
   * 浏览器捕获这些用户输入事件。
   * 渲染引擎接收到选区改变的通知。
   * Blink 核心代码会更新选区状态，并触发重绘流程。
   * 在绘制文本的过程中，`highlight_overlay.cc` 中的 `ComputeLayers`, `ComputeEdges`, `ComputeParts` 等函数会被调用，计算选择高亮的覆盖层信息。

2. **用户使用 "查找" 功能 (Ctrl+F 或 Cmd+F):**
   * 用户按下快捷键打开查找栏，并输入要搜索的关键词。
   * JavaScript 代码会执行搜索操作，并在页面中标记匹配的文本。
   * 渲染引擎接收到搜索结果的通知。
   * `highlight_overlay.cc` 会被调用，计算搜索高亮和当前激活匹配高亮的覆盖层信息。

3. **页面加载并包含链接锚点:**
   * 用户点击一个包含锚点的链接 (例如 `<a href="#target">`) 或直接访问带有锚点的 URL。
   * 浏览器滚动到目标元素。
   * 渲染引擎可能会高亮显示目标元素，`highlight_overlay.cc` 会计算目标文本高亮的覆盖层。

4. **网站使用了 Custom Highlight API:**
   * 网站的 JavaScript 代码使用了 Custom Highlight API 来创建自定义的高亮。
   * 当这些 API 被调用时，渲染引擎会接收到创建或修改自定义高亮的通知。
   * `highlight_overlay.cc` 会被调用，计算自定义高亮的覆盖层信息。

5. **浏览器检测到拼写或语法错误:**
   * 用户在可编辑的文本区域 (例如 `<textarea>` 或设置了 `contenteditable` 属性的元素) 输入文本。
   * 浏览器内置的拼写或语法检查器检测到错误。
   * 渲染引擎会高亮显示这些错误，`highlight_overlay.cc` 会计算拼写或语法错误高亮的覆盖层。

**作为调试线索，可以关注以下几点:**

* **断点设置:** 在 `ComputeLayers`, `ComputeEdges`, `ComputeParts` 等关键函数入口处设置断点，查看输入参数 (例如 `node`, `selection`, `custom` 等) 的值，了解高亮计算的上下文。
* **日志输出:** 在关键路径上添加日志输出，记录高亮类型、范围、图层信息等，帮助理解高亮的计算过程。
* **检查相关数据结构:**  查看 `HighlightLayer`, `HighlightRange`, `HighlightEdge`, `HighlightPart` 等数据结构的内容，确认高亮的属性是否符合预期。
* **CSS 样式检查:**  使用浏览器的开发者工具检查相关元素的样式，特别是与高亮相关的伪元素 (`::selection`, `::highlight()`, `::spelling-error` 等) 的样式，确认 CSS 规则是否正确应用。
* **JavaScript 代码审查:**  如果涉及到自定义高亮，审查相关的 JavaScript 代码，确保 Custom Highlight API 的使用方式正确，例如 Range 对象的设置、高亮名称的注册等。

总而言之，`highlight_overlay.cc` 是 Blink 渲染引擎中负责文本高亮渲染的核心组件，它接收来自不同来源 (用户交互、JavaScript API、浏览器内置功能) 的高亮信息，并根据 CSS 样式规则计算出最终的渲染结果。理解它的功能和与 Web 技术的关系，可以帮助开发者更好地理解和调试网页中的文本高亮问题。

Prompt: 
```
这是目录为blink/renderer/core/paint/highlight_overlay.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/highlight_overlay.h"

#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/custom_highlight_marker.h"
#include "third_party/blink/renderer/core/editing/markers/text_match_marker.h"
#include "third_party/blink/renderer/core/highlight/highlight_registry.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/paint/marker_range_mapping_context.h"
#include "third_party/blink/renderer/platform/fonts/text_fragment_paint_info.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

using HighlightLayerType = HighlightOverlay::HighlightLayerType;
using HighlightLayer = HighlightOverlay::HighlightLayer;
using HighlightRange = HighlightOverlay::HighlightRange;
using HighlightEdge = HighlightOverlay::HighlightEdge;
using HighlightDecoration = HighlightOverlay::HighlightDecoration;
using HighlightBackground = HighlightOverlay::HighlightBackground;
using HighlightTextShadow = HighlightOverlay::HighlightTextShadow;
using HighlightPart = HighlightOverlay::HighlightPart;

unsigned ClampOffset(unsigned offset, const TextFragmentPaintInfo& fragment) {
  return std::min(std::max(offset, fragment.from), fragment.to);
}

String HighlightTypeToString(HighlightLayerType type) {
  StringBuilder result{};
  switch (type) {
    case HighlightLayerType::kOriginating:
      result.Append("originating");
      break;
    case HighlightLayerType::kCustom:
      result.Append("custom");
      break;
    case HighlightLayerType::kGrammar:
      result.Append("grammar");
      break;
    case HighlightLayerType::kSpelling:
      result.Append("spelling");
      break;
    case HighlightLayerType::kTargetText:
      result.Append("target");
      break;
    case HighlightLayerType::kSearchText:
      result.Append("search");
      break;
    case HighlightLayerType::kSearchTextActiveMatch:
      result.Append("search:current");
      break;
    case HighlightLayerType::kSelection:
      result.Append("selection");
      break;
    default:
      NOTREACHED();
  }
  return result.ToString();
}

uint16_t HighlightLayerIndex(const HeapVector<HighlightLayer>& layers,
                             HighlightLayerType type,
                             const AtomicString& name = g_null_atom) {
  // This may be a performance bottleneck when there are many layers,
  // the solution being to keep a Map in addition to the Vector. But in
  // practice it's hard to see a document using more than tens of custom
  // highlights.
  wtf_size_t index = 0;
  wtf_size_t layers_size = layers.size();
  while (index < layers_size &&
         (layers[index].type != type || layers[index].name != name)) {
    index++;
  }
  CHECK_LT(index, layers_size);
  return static_cast<uint16_t>(index);
}

}  // namespace

HighlightLayer::HighlightLayer(HighlightLayerType type,
                               const AtomicString& name)
    : type(type),
      name(std::move(name)) {}

String HighlightLayer::ToString() const {
  StringBuilder result{};
  result.Append(HighlightTypeToString(type));
  if (!name.IsNull()) {
    result.Append("(");
    result.Append(name);
    result.Append(")");
  }
  return result.ToString();
}

enum PseudoId HighlightLayer::PseudoId() const {
  switch (type) {
    case HighlightLayerType::kOriginating:
      return kPseudoIdNone;
    case HighlightLayerType::kCustom:
      return kPseudoIdHighlight;
    case HighlightLayerType::kGrammar:
      return kPseudoIdGrammarError;
    case HighlightLayerType::kSpelling:
      return kPseudoIdSpellingError;
    case HighlightLayerType::kTargetText:
      return kPseudoIdTargetText;
    case HighlightLayerType::kSearchText:
      return kPseudoIdSearchText;
    case HighlightLayerType::kSearchTextActiveMatch:
      return kPseudoIdSearchText;
    case HighlightLayerType::kSelection:
      return kPseudoIdSelection;
    default:
      NOTREACHED();
  }
}

const AtomicString& HighlightLayer::PseudoArgument() const {
  return name;
}

bool HighlightLayer::operator==(const HighlightLayer& other) const {
  // For equality we are not concerned with the styles or decorations.
  // Those are dependent on the type and name.
  return type == other.type && name == other.name;
}

bool HighlightLayer::operator!=(const HighlightLayer& other) const {
  return !operator==(other);
}

int8_t HighlightLayer::ComparePaintOrder(
    const HighlightLayer& other,
    const HighlightRegistry* registry) const {
  if (type < other.type) {
    return HighlightRegistry::OverlayStackingPosition::
        kOverlayStackingPositionBelow;
  }
  if (type > other.type) {
    return HighlightRegistry::OverlayStackingPosition::
        kOverlayStackingPositionAbove;
  }
  if (type != HighlightLayerType::kCustom) {
    return HighlightRegistry::OverlayStackingPosition::
        kOverlayStackingPositionEquivalent;
  }
  DCHECK(registry);
  const HighlightRegistryMap& map = registry->GetHighlights();
  auto* this_entry =
      map.Find<HighlightRegistryMapEntryNameTranslator>(PseudoArgument())
          ->Get();
  auto* other_entry =
      map.Find<HighlightRegistryMapEntryNameTranslator>(other.PseudoArgument())
          ->Get();
  return registry->CompareOverlayStackingPosition(
      PseudoArgument(), this_entry->highlight, other.PseudoArgument(),
      other_entry->highlight);
}

HighlightRange::HighlightRange(unsigned from, unsigned to)
    : from(from), to(to) {
  DCHECK_LT(from, to);
}

bool HighlightRange::operator==(const HighlightRange& other) const {
  return from == other.from && to == other.to;
}

bool HighlightRange::operator!=(const HighlightRange& other) const {
  return !operator==(other);
}

String HighlightRange::ToString() const {
  StringBuilder result{};
  result.Append("[");
  result.AppendNumber(from);
  result.Append(",");
  result.AppendNumber(to);
  result.Append(")");
  return result.ToString();
}

String HighlightEdge::ToString() const {
  StringBuilder result{};
  if (edge_type == HighlightEdgeType::kStart) {
    result.Append("<");
    result.AppendNumber(Offset());
    result.Append(" ");
  }
  result.AppendNumber(layer_index);
  result.Append(":");
  result.Append(HighlightTypeToString(layer_type));
  if (edge_type == HighlightEdgeType::kEnd) {
    result.Append(" ");
    result.AppendNumber(Offset());
    result.Append(">");
  }
  return result.ToString();
}

unsigned HighlightEdge::Offset() const {
  switch (edge_type) {
    case HighlightEdgeType::kStart:
      return range.from;
    case HighlightEdgeType::kEnd:
      return range.to;
  }
}

bool HighlightEdge::LessThan(const HighlightEdge& other,
                             const HeapVector<HighlightLayer>& layers,
                             const HighlightRegistry* registry) const {
  if (Offset() < other.Offset()) {
    return true;
  }
  if (Offset() > other.Offset()) {
    return false;
  }
  if (edge_type > other.edge_type) {
    return true;
  }
  if (edge_type < other.edge_type) {
    return false;
  }
  return layers[layer_index].ComparePaintOrder(layers[other.layer_index],
                                               registry) < 0;
}

bool HighlightEdge::operator==(const HighlightEdge& other) const {
  return Offset() == other.Offset() && edge_type == other.edge_type &&
         layer_type == other.layer_type && layer_index == other.layer_index;
}

bool HighlightEdge::operator!=(const HighlightEdge& other) const {
  return !operator==(other);
}

HighlightDecoration::HighlightDecoration(HighlightLayerType type,
                                         uint16_t layer_index,
                                         HighlightRange range,
                                         Color override_color)
    : type(type),
      layer_index(layer_index),
      range(range),
      highlight_override_color(override_color) {}

String HighlightDecoration::ToString() const {
  StringBuilder result{};
  result.AppendNumber(layer_index);
  result.Append(":");
  result.Append(HighlightTypeToString(type));
  result.Append(" ");
  result.Append(range.ToString());
  return result.ToString();
}

bool HighlightDecoration::operator==(const HighlightDecoration& other) const {
  return type == other.type && layer_index == other.layer_index &&
         range == other.range;
}

bool HighlightDecoration::operator!=(const HighlightDecoration& other) const {
  return !operator==(other);
}

String HighlightBackground::ToString() const {
  StringBuilder result{};
  result.AppendNumber(layer_index);
  result.Append(":");
  result.Append(HighlightTypeToString(type));
  result.Append(" ");
  result.Append(color.SerializeAsCSSColor());
  return result.ToString();
}

bool HighlightBackground::operator==(const HighlightBackground& other) const {
  return type == other.type && layer_index == other.layer_index &&
         color == other.color;
}

bool HighlightBackground::operator!=(const HighlightBackground& other) const {
  return !operator==(other);
}

String HighlightTextShadow::ToString() const {
  StringBuilder result{};
  result.AppendNumber(layer_index);
  result.Append(":");
  result.Append(HighlightTypeToString(type));
  result.Append(" ");
  result.Append(current_color.SerializeAsCSSColor());
  return result.ToString();
}

bool HighlightTextShadow::operator==(const HighlightTextShadow& other) const {
  return type == other.type && layer_index == other.layer_index &&
         current_color == other.current_color;
}

bool HighlightTextShadow::operator!=(const HighlightTextShadow& other) const {
  return !operator==(other);
}

HighlightPart::HighlightPart(HighlightLayerType type,
                             uint16_t layer_index,
                             HighlightRange range,
                             TextPaintStyle style,
                             float stroke_width,
                             Vector<HighlightDecoration> decorations,
                             Vector<HighlightBackground> backgrounds,
                             Vector<HighlightTextShadow> text_shadows)
    : type(type),
      layer_index(layer_index),
      range(range),
      style(style),
      stroke_width(stroke_width),
      decorations(std::move(decorations)),
      backgrounds(std::move(backgrounds)),
      text_shadows(std::move(text_shadows)) {}

HighlightPart::HighlightPart(HighlightLayerType type,
                             uint16_t layer_index,
                             HighlightRange range,
                             TextPaintStyle style,
                             float stroke_width,
                             Vector<HighlightDecoration> decorations)
    : type(type),
      layer_index(layer_index),
      range(range),
      style(style),
      stroke_width(stroke_width),
      decorations(std::move(decorations)),
      backgrounds({}),
      text_shadows({}) {}

String HighlightPart::ToString() const {
  StringBuilder result{};
  result.Append("\n");
  result.AppendNumber(layer_index);
  result.Append(":");
  result.Append(HighlightTypeToString(type));
  result.Append(" ");
  result.Append(range.ToString());
  // A part should contain one kOriginating decoration struct, followed by one
  // decoration struct for each active overlay in highlight painting order,
  // along with background and shadow structs for the active overlays only.
  // Stringify the three vectors in a way that keeps the layers aligned.
  if (decorations.size() >= 1) {
    result.Append("\n    decoration ");
    result.Append(decorations[0].ToString());
  }
  wtf_size_t len =
      std::max(std::max(decorations.size(), backgrounds.size() + 1),
               text_shadows.size() + 1) -
      1;
  for (wtf_size_t i = 0; i < len; i++) {
    result.Append("\n  ");
    if (i + 1 < decorations.size()) {
      result.Append("  decoration ");
      result.Append(decorations[i + 1].ToString());
    }
    if (i < backgrounds.size()) {
      result.Append("  background ");
      result.Append(backgrounds[i].ToString());
    }
    if (i < text_shadows.size()) {
      result.Append("  shadow ");
      result.Append(text_shadows[i].ToString());
    }
  }
  return result.ToString();
}

bool HighlightPart::operator==(const HighlightPart& other) const {
  return type == other.type && layer_index == other.layer_index &&
         range == other.range && decorations == other.decorations &&
         backgrounds == other.backgrounds && text_shadows == other.text_shadows;
}

bool HighlightPart::operator!=(const HighlightPart& other) const {
  return !operator==(other);
}

HeapVector<HighlightLayer> HighlightOverlay::ComputeLayers(
    const Document& document,
    Node* node,
    const ComputedStyle& originating_style,
    const TextPaintStyle& originating_text_style,
    const PaintInfo& paint_info,
    const LayoutSelectionStatus* selection,
    const DocumentMarkerVector& custom,
    const DocumentMarkerVector& grammar,
    const DocumentMarkerVector& spelling,
    const DocumentMarkerVector& target,
    const DocumentMarkerVector& search) {
  const HighlightRegistry* registry =
      HighlightRegistry::GetHighlightRegistry(node);
  HeapVector<HighlightLayer> layers{};
  layers.emplace_back(HighlightLayerType::kOriginating);

  const auto* text_node = DynamicTo<Text>(node);
  if (!text_node) {
    DCHECK(custom.empty() && grammar.empty() && spelling.empty() &&
           target.empty() && search.empty())
        << "markers can not be painted without a valid Text node";
    if (selection) {
      layers.emplace_back(HighlightLayerType::kSelection);
    }
    return layers;
  }

  if (!custom.empty()) {
    // We must be able to store the layer index within 16 bits. Enforce
    // that now when making layers.
    unsigned max_custom_layers =
        std::numeric_limits<uint16_t>::max() -
        static_cast<unsigned>(HighlightLayerType::kSelection);
    const HashSet<AtomicString>& active_highlights =
        registry->GetActiveHighlights(*text_node);
    auto highlight_iter = active_highlights.begin();
    unsigned layer_count = 0;
    while (highlight_iter != active_highlights.end() &&
           layer_count < max_custom_layers) {
      HighlightLayer layer{HighlightLayerType::kCustom, *highlight_iter};
      DCHECK(!layers.Contains(layer));
      layers.push_back(layer);
      highlight_iter++;
      layer_count++;
    }
  }
  if (!grammar.empty())
    layers.emplace_back(HighlightLayerType::kGrammar);
  if (!spelling.empty())
    layers.emplace_back(HighlightLayerType::kSpelling);
  if (!target.empty())
    layers.emplace_back(HighlightLayerType::kTargetText);
  if (!search.empty() &&
      RuntimeEnabledFeatures::SearchTextHighlightPseudoEnabled()) {
    layers.emplace_back(HighlightLayerType::kSearchText);
    layers.emplace_back(HighlightLayerType::kSearchTextActiveMatch);
  }
  if (selection)
    layers.emplace_back(HighlightLayerType::kSelection);

  std::sort(layers.begin(), layers.end(),
            [registry](const HighlightLayer& p, const HighlightLayer& q) {
              return p.ComparePaintOrder(q, registry) < 0;
            });

  layers[0].style = &originating_style;
  layers[0].text_style.style = originating_text_style;
  layers[0].text_style.text_decoration_color =
      originating_style.VisitedDependentColor(
          GetCSSPropertyTextDecorationColor());
  layers[0].decorations_in_effect =
      originating_style.HasAppliedTextDecorations()
          ? originating_style.TextDecorationsInEffect()
          : TextDecorationLine::kNone;
  for (wtf_size_t i = 1; i < layers.size(); i++) {
    layers[i].style =
        layers[i].type == HighlightLayerType::kSearchTextActiveMatch
            ? originating_style.HighlightData().SearchTextCurrent()
            : HighlightStyleUtils::HighlightPseudoStyle(
                  node, originating_style, layers[i].PseudoId(),
                  layers[i].PseudoArgument());
    layers[i].text_style = HighlightStyleUtils::HighlightPaintingStyle(
        document, originating_style, layers[i].style, node,
        layers[i].PseudoId(), layers[i - 1].text_style.style, paint_info,
        layers[i].type == HighlightLayerType::kSearchTextActiveMatch
            ? SearchTextIsActiveMatch::kYes
            : SearchTextIsActiveMatch::kNo);
    layers[i].decorations_in_effect =
        layers[i].style && layers[i].style->HasAppliedTextDecorations()
            ? layers[i].style->TextDecorationsInEffect()
            : TextDecorationLine::kNone;
  }
  return layers;
}

Vector<HighlightEdge> HighlightOverlay::ComputeEdges(
    const Node* node,
    bool is_generated_text_fragment,
    std::optional<TextOffsetRange> dom_offsets,
    const HeapVector<HighlightLayer>& layers,
    const LayoutSelectionStatus* selection,
    const DocumentMarkerVector& custom,
    const DocumentMarkerVector& grammar,
    const DocumentMarkerVector& spelling,
    const DocumentMarkerVector& target,
    const DocumentMarkerVector& search) {
  const HighlightRegistry* registry =
      HighlightRegistry::GetHighlightRegistry(node);
  Vector<HighlightEdge> result{};

  if (selection) {
    DCHECK_LT(selection->start, selection->end);
    uint16_t layer_index =
        HighlightLayerIndex(layers, HighlightLayerType::kSelection);
    result.emplace_back(HighlightRange{selection->start, selection->end},
                        HighlightLayerType::kSelection, layer_index,
                        HighlightEdgeType::kStart);
    result.emplace_back(HighlightRange{selection->start, selection->end},
                        HighlightLayerType::kSelection, layer_index,
                        HighlightEdgeType::kEnd);
  }

  // |node| might not be a Text node (e.g. <br>), or it might be nullptr (e.g.
  // ::first-letter). In both cases, we should still try to paint kOriginating
  // and kSelection if necessary, but we can’t paint marker-based highlights,
  // because GetTextContentOffset requires a Text node. Markers are defined and
  // stored in terms of Text nodes anyway, so this check should never fail.
  const auto* text_node = DynamicTo<Text>(node);
  if (!text_node) {
    DCHECK(custom.empty() && grammar.empty() && spelling.empty() &&
           target.empty() && search.empty())
        << "markers can not be painted without a valid Text node";
  } else if (is_generated_text_fragment) {
    // Custom highlights and marker-based highlights are defined in terms of
    // DOM ranges in a Text node. Generated text either has no Text node or does
    // not derive its content from the Text node (e.g. ellipsis, soft hyphens).
    // TODO(crbug.com/17528) handle ::first-letter
    DCHECK(custom.empty() && grammar.empty() && spelling.empty() &&
           target.empty() && search.empty())
        << "no marker can ever apply to fragment items with generated text";
  } else {
    DCHECK(dom_offsets);
    MarkerRangeMappingContext mapping_context(*text_node, *dom_offsets);
    for (const auto& marker : custom) {
      std::optional<TextOffsetRange> marker_offsets =
          mapping_context.GetTextContentOffsets(*marker);
      if (!marker_offsets) {
        continue;
      }
      const unsigned content_start = marker_offsets->start;
      const unsigned content_end = marker_offsets->end;
      if (content_start >= content_end)
        continue;
      auto* custom_marker = To<CustomHighlightMarker>(marker.Get());
      uint16_t layer_index =
          HighlightLayerIndex(layers, HighlightLayerType::kCustom,
                              custom_marker->GetHighlightName());
      result.emplace_back(HighlightRange{content_start, content_end},
                          HighlightLayerType::kCustom, layer_index,
                          HighlightEdgeType::kStart);
      result.emplace_back(HighlightRange{content_start, content_end},
                          HighlightLayerType::kCustom, layer_index,
                          HighlightEdgeType::kEnd);
    }

    if (!grammar.empty()) {
      mapping_context.Reset();
      uint16_t layer_index =
          HighlightLayerIndex(layers, HighlightLayerType::kGrammar);
      for (const auto& marker : grammar) {
        std::optional<TextOffsetRange> marker_offsets =
            mapping_context.GetTextContentOffsets(*marker);
        if (!marker_offsets) {
          continue;
        }
        const unsigned content_start = marker_offsets->start;
        const unsigned content_end = marker_offsets->end;
        if (content_start >= content_end) {
          continue;
        }
        result.emplace_back(HighlightRange{content_start, content_end},
                            HighlightLayerType::kGrammar, layer_index,
                            HighlightEdgeType::kStart);
        result.emplace_back(HighlightRange{content_start, content_end},
                            HighlightLayerType::kGrammar, layer_index,
                            HighlightEdgeType::kEnd);
      }
    }
    if (!spelling.empty()) {
      mapping_context.Reset();
      uint16_t layer_index =
          HighlightLayerIndex(layers, HighlightLayerType::kSpelling);
      for (const auto& marker : spelling) {
        std::optional<TextOffsetRange> marker_offsets =
            mapping_context.GetTextContentOffsets(*marker);
        if (!marker_offsets) {
          continue;
        }
        const unsigned content_start = marker_offsets->start;
        const unsigned content_end = marker_offsets->end;
        if (content_start >= content_end) {
          continue;
        }
        result.emplace_back(HighlightRange{content_start, content_end},
                            HighlightLayerType::kSpelling, layer_index,
                            HighlightEdgeType::kStart);
        result.emplace_back(HighlightRange{content_start, content_end},
                            HighlightLayerType::kSpelling, layer_index,
                            HighlightEdgeType::kEnd);
      }
    }
    if (!target.empty()) {
      mapping_context.Reset();
      uint16_t layer_index =
          HighlightLayerIndex(layers, HighlightLayerType::kTargetText);
      for (const auto& marker : target) {
        std::optional<TextOffsetRange> marker_offsets =
            mapping_context.GetTextContentOffsets(*marker);
        if (!marker_offsets) {
          continue;
        }
        const unsigned content_start = marker_offsets->start;
        const unsigned content_end = marker_offsets->end;
        if (content_start >= content_end) {
          continue;
        }
        result.emplace_back(HighlightRange{content_start, content_end},
                            HighlightLayerType::kTargetText, layer_index,
                            HighlightEdgeType::kStart);
        result.emplace_back(HighlightRange{content_start, content_end},
                            HighlightLayerType::kTargetText, layer_index,
                            HighlightEdgeType::kEnd);
      }
    }
    if (!search.empty() &&
        RuntimeEnabledFeatures::SearchTextHighlightPseudoEnabled()) {
      mapping_context.Reset();
      uint16_t layer_index_not_current =
          HighlightLayerIndex(layers, HighlightLayerType::kSearchText);
      uint16_t layer_index_current = HighlightLayerIndex(
          layers, HighlightLayerType::kSearchTextActiveMatch);
      for (const auto& marker : search) {
        std::optional<TextOffsetRange> marker_offsets =
            mapping_context.GetTextContentOffsets(*marker);
        if (!marker_offsets) {
          continue;
        }
        const unsigned content_start = marker_offsets->start;
        const unsigned content_end = marker_offsets->end;
        if (content_start >= content_end) {
          continue;
        }
        auto* text_match_marker = To<TextMatchMarker>(marker.Get());
        HighlightLayerType type =
            text_match_marker->IsActiveMatch()
                ? HighlightLayerType::kSearchTextActiveMatch
                : HighlightLayerType::kSearchText;
        uint16_t layer_index = text_match_marker->IsActiveMatch()
                                   ? layer_index_current
                                   : layer_index_not_current;
        result.emplace_back(HighlightRange{content_start, content_end}, type,
                            layer_index, HighlightEdgeType::kStart);
        result.emplace_back(HighlightRange{content_start, content_end}, type,
                            layer_index, HighlightEdgeType::kEnd);
      }
    }
  }

  std::sort(result.begin(), result.end(),
            [layers, registry](const HighlightEdge& p, const HighlightEdge& q) {
              return p.LessThan(q, layers, registry);
            });

  return result;
}

HeapVector<HighlightPart> HighlightOverlay::ComputeParts(
    const TextFragmentPaintInfo& content_offsets,
    const HeapVector<HighlightLayer>& layers,
    const Vector<HighlightEdge>& edges) {
  DCHECK_EQ(layers[0].type, HighlightLayerType::kOriginating);
  const float originating_stroke_width =
      layers[0].style ? layers[0].style->TextStrokeWidth() : 0;
  const HighlightStyleUtils::HighlightTextPaintStyle& originating_text_style =
      layers[0].text_style;
  const HighlightDecoration originating_decoration{
      HighlightLayerType::kOriginating,
      0,
      {content_offsets.from, content_offsets.to},
      originating_text_style.text_decoration_color};

  HeapVector<HighlightPart> result;
  Vector<std::optional<HighlightRange>> active(layers.size());
  std::optional<unsigned> prev_offset{};
  if (edges.empty()) {
    result.push_back(HighlightPart{HighlightLayerType::kOriginating,
                                   0,
                                   {content_offsets.from, content_offsets.to},
                                   originating_text_style.style,
                                   originating_stroke_width,
                                   {originating_decoration}});
    return result;
  }
  if (content_offsets.from < edges.front().Offset()) {
    result.push_back(
        HighlightPart{HighlightLayerType::kOriginating,
                      0,
                      {content_offsets.from,
                       ClampOffset(edges.front().Offset(), content_offsets)},
                      originating_text_style.style,
                      originating_stroke_width,
                      {originating_decoration}});
  }
  for (const HighlightEdge& edge : edges) {
    // If there is actually some text between the previous and current edges...
    if (prev_offset.has_value() && *prev_offset < edge.Offset()) {
      // ...and the range overlaps with the fragment being painted...
      unsigned part_from = ClampOffset(*prev_offset, content_offsets);
      unsigned part_to = ClampOffset(edge.Offset(), content_offsets);
      if (part_from < part_to) {
        // ...then find the topmost layer and enqueue a new part to be painted.
        HighlightPart part{HighlightLayerType::kOriginating,
                           0,
                           {part_from, part_to},
                           originating_text_style.style,
                           originating_stroke_width,
                           {originating_decoration},
                           {},
                           {}};
        HighlightStyleUtils::HighlightTextPaintStyle previous_layer_style =
            originating_text_style;
        for (wtf_size_t i = 1; i < layers.size(); i++) {
          if (active[i]) {
            unsigned decoration_from =
                ClampOffset(active[i]->from, content_offsets);
            unsigned decoration_to =
                ClampOffset(active[i]->to, content_offsets);
            part.type = layers[i].type;
            part.layer_index = static_cast<uint16_t>(i);
            HighlightStyleUtils::HighlightTextPaintStyle part_style =
                layers[i].text_style;
            HighlightStyleUtils::ResolveColorsFromPreviousLayer(
                part_style, previous_layer_style);
            part.style = part_style.style;
            part.decorations.push_back(
                HighlightDecoration{layers[i].type,
                                    static_cast<uint16_t>(i),
                                    {decoration_from, decoration_to},
                                    part_style.text_decoration_color});
            part.backgrounds.push_back(
                HighlightBackground{layers[i].type, static_cast<uint16_t>(i),
                                    part_style.background_color});
            part.text_shadows.push_back(
                HighlightTextShadow{layers[i].type, static_cast<uint16_t>(i),
                                    part_style.style.current_color});
            previous_layer_style = part_style;
          }
        }
        result.push_back(part);
      }
    }
    // This algorithm malfunctions if the edges represent overlapping ranges.
    DCHECK(active[edge.layer_index]
               ? edge.edge_type == HighlightEdgeType::kEnd
               : edge.edge_type == HighlightEdgeType::kStart)
        << "edge should be kStart iff the layer is active or else kEnd";
    if (edge.edge_type == HighlightEdgeType::kStart) {
      active[edge.layer_index].emplace(edge.range);
    } else {
      active[edge.layer_index].reset();
    }
    prev_offset.emplace(edge.Offset());
  }
  if (edges.back().Offset() < content_offsets.to) {
    result.push_back(
        HighlightPart{HighlightLayerType::kOriginating,
                      0,
                      {ClampOffset(edges.back().Offset(), content_offsets),
                       content_offsets.to},
                      originating_text_style.style,
                      originating_stroke_width,
                      {originating_decoration}});
  }
  return result;
}

std::ostream& operator<<(std::ostream& result,
                         const HighlightOverlay::HighlightLayer& layer) {
  return result << layer.ToString().Utf8();
}

std::ostream& operator<<(std::ostream& result,
                         const HighlightOverlay::HighlightEdge& edge) {
  return result << edge.ToString().Utf8();
}

std::ostream& operator<<(std::ostream& result,
                         const HighlightOverlay::HighlightPart& part) {
  return result << part.ToString().Utf8();
}

}  // namespace blink

"""

```