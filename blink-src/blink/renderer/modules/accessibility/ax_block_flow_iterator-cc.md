Response:
Let's break down the thought process for analyzing the `ax_block_flow_iterator.cc` file.

1. **Understand the Core Purpose:** The file name itself, "ax_block_flow_iterator," strongly suggests its role: iterating through the block flow of an accessible object. Accessibility (AX) is the key domain here. Block flow refers to the layout of content in block-level elements, typically flowing vertically. An iterator is a common design pattern for traversing a collection.

2. **Identify Key Data Structures:** Look for the main classes and data structures being used. The file defines `AXBlockFlowData` and `AXBlockFlowIterator`.

3. **Analyze `AXBlockFlowData`:**
    * **Constructor:**  It takes a `LayoutBlockFlow*`. This signals that it's concerned with the layout representation of block elements. The `#if DCHECK_IS_ON()` block suggests debugging aids related to block fragmentation.
    * **`ProcessLayoutBlock` and `ProcessBoxFragment`:** These methods indicate the core logic for analyzing the layout tree. They traverse the physical fragments of a block.
    * **`fragment_properties_`:** This vector stores information about individual fragments.
    * **`layout_fragment_map_`:**  A map linking `LayoutObject` pointers to fragment indices. This is likely for efficient lookups of where a specific layout object appears in the block flow.
    * **`lines_`:**  A vector of `Line` structs. This is a crucial piece of information, suggesting the iterator deals with the concept of lines within the block flow. The `Line` struct itself contains `start_index`, `length`, `forced_break`, and `break_index`, all pointing to line-specific details.
    * **`GetText(wtf_size_t item_index)`:** This method retrieves the text content of a specific fragment. The logic within it, especially the `IncludeTrailingWhitespace` call, is worth noting.
    * **`GetProperties(wtf_size_t index)`:** Provides access to the fragment properties.
    * **`FindFirstFragment`:**  Looks up the starting fragment index for a given `LayoutObject`.
    * **`GetPosition`:** Maps a linear index to a fragmentainer and item index, indicating the multi-layered structure of block flow.
    * **`ItemAt` and `BoxFragment`:**  Provide direct access to `FragmentItem` and `PhysicalBoxFragment` objects.

4. **Analyze `AXBlockFlowIterator`:**
    * **Constructor:** Takes an `AXObject*`. This confirms its connection to the accessibility tree. It retrieves `AXBlockFlowData` from the object's cache.
    * **`Next()`:**  The core iteration method. It increments the `current_index_`. The logic involving `DeltaToNextForSameLayoutObject()` suggests handling cases where multiple fragments belong to the same layout object.
    * **`GetText()`:**  Uses the `AXBlockFlowData::GetText()` method to retrieve the text of the current fragment.
    * **`GetCharacterLayoutPixelOffsets()`:** This method strongly hints at the relationship with rendering. It calculates the pixel offsets of individual characters within the current text fragment, relying on `ShapeResult`.
    * **`NextOnLine()` and `PreviousOnLine()`:**  These are key methods for navigating the block flow line by line, using the `fragment_properties_` to find the next/previous fragment on the same line.
    * **`GetMapKey()`:**  Returns a key representing the current position (fragment items and index).

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:**  The structure of the HTML document dictates the block-level elements (e.g., `<div>`, `<p>`) that will be processed by `AXBlockFlowData`. The presence of `<br>` tags is directly related to the `forced_break` property in the `Line` struct.
    * **CSS:**  CSS properties like `display: block`, `line-height`, `white-space`, and font styles heavily influence the layout of the block flow, which is what this iterator is traversing. The `IncludeTrailingWhitespace` function directly deals with how `white-space` properties affect the inclusion of spaces.
    * **JavaScript:** JavaScript can manipulate the DOM, adding, removing, or modifying elements and their styles. These changes can trigger re-layout, which would then affect the `AXBlockFlowData` and the iterator's behavior. Accessibility APIs used by assistive technologies are often accessed through JavaScript.

6. **Identify Logic and Assumptions:**
    * **Trailing Whitespace Handling:** The `IncludeTrailingWhitespace` function is a clear example of specific logic to handle edge cases in text rendering and accessibility requirements. It assumes that elided trailing spaces might be necessary for assistive technologies.
    * **Line Breaks:** The iterator understands the concept of lines and how line breaks (both explicit and implicit) are handled.
    * **Fragment Grouping:** The `DeltaToNextForSameLayoutObject()` logic assumes that related content might be split into multiple fragments.

7. **Consider User/Programming Errors:**
    * **Incorrect Accessibility Tree:** If the underlying accessibility tree is not correctly built, the `AXBlockFlowData` might be incomplete or incorrect, leading to unexpected behavior in the iterator.
    * **Modifying DOM During Iteration:**  If the DOM is modified while the iterator is in use, the internal state of the iterator might become invalid. This is a common issue with iterators in general.

8. **Trace User Actions:**  Think about a typical user interaction that would lead to this code being executed. A user browsing a webpage with block-level content, especially if they are using assistive technologies like screen readers, would trigger the creation of accessibility objects and the need to traverse their content. Selecting text, navigating with the keyboard, or using screen reader commands are all relevant actions.

9. **Structure the Explanation:** Organize the findings into logical sections like Functionality, Relationship to Web Technologies, Logic and Assumptions, Errors, and User Actions. Use clear and concise language, and provide concrete examples where possible.

Self-Correction/Refinement during the thought process:

* **Initial thought:**  Maybe the iterator simply goes through all layout objects within a block.
* **Correction:** The presence of `lines_` and methods like `NextOnLine` indicate a more granular level of iteration, focusing on the flow of text content within the lines of the block.
* **Initial thought:** The `GetCharacterLayoutPixelOffsets` is about rendering the text visually.
* **Refinement:** While related to rendering, its primary purpose in the accessibility context is likely to provide precise character boundaries and positions to assistive technologies.

By following these steps and engaging in this iterative refinement, we can arrive at a comprehensive understanding of the `ax_block_flow_iterator.cc` file and its role within the Chromium accessibility system.
这个文件 `blink/renderer/modules/accessibility/ax_block_flow_iterator.cc` 定义了 `AXBlockFlowData` 和 `AXBlockFlowIterator` 两个类，它们的核心功能是**为了辅助 Accessibility (可访问性) 功能，提供对块级元素内容（文本和某些内联元素）的迭代和信息提取能力**。

**具体功能分解：**

**1. `AXBlockFlowData` 类:**

* **功能：**
    * **存储和预处理块级元素的布局信息，以便高效地进行基于行的文本迭代。** 它会分析 `LayoutBlockFlow` 对象（表示一个块级布局容器）的物理碎片 (PhysicalBoxFragment) 和碎片内的项目 (FragmentItem)。
    * **记录文本片段 (text fragments) 的属性，例如它们所属的行、前后的同行的文本片段等。** 这有助于实现按行遍历文本。
    * **维护一个从 `LayoutObject` 到其在块流中对应碎片索引的映射 (`layout_fragment_map_`)。** 这可以快速找到特定布局对象在块流中的位置。
    * **存储块流中的行信息 (`lines_`)，包括每行的起始索引、长度、是否强制换行以及换行符的位置。**
    * **提供获取特定索引处文本片段内容 (`GetText`) 和属性 (`GetProperties`) 的方法。**
    * **判断某个索引对应的碎片是否在当前行 (`OnCurrentLine`)。**

* **与 JavaScript, HTML, CSS 的关系：**
    * **HTML：**  `AXBlockFlowData` 处理的 `LayoutBlockFlow` 对象是由 HTML 中的块级元素（如 `<div>`, `<p>`, `<h1>` 等）渲染而成的。HTML 的结构决定了块级元素的层级和内容。
    * **CSS：** CSS 样式会影响块级元素的布局，包括行高、换行方式、`white-space` 属性等。这些布局信息会被 `AXBlockFlowData` 分析并存储。例如，`white-space: pre-wrap` 会影响换行的处理方式。
    * **JavaScript：** JavaScript 可以动态修改 DOM 结构和 CSS 样式，这些修改会导致重新布局，从而影响 `AXBlockFlowData` 中存储的信息。辅助功能 API (Accessibility APIs) 通常会通过 JavaScript 暴露给开发者，而这些 API 可能会用到 `AXBlockFlowIterator` 提供的数据。

* **逻辑推理 (假设输入与输出):**
    * **假设输入：** 一个包含以下 HTML 的 `LayoutBlockFlow` 对象：
      ```html
      <div>
        This is line one.<br>
        And this is line two.
      </div>
      ```
    * **输出 (部分 `AXBlockFlowData` 信息):**
        * `lines_`:  可能包含两个 `Line` 结构，分别对应两行文本。
            * 第一行: `start_index` 指向 "This is line one." 的第一个碎片，`forced_break` 为 `true` (因为有 `<br>`)。
            * 第二行: `start_index` 指向 "And this is line two." 的第一个碎片，`forced_break` 为 `false`。
        * `fragment_properties_`: 每个文本片段会有一个对应的 `FragmentProperties`，记录它所属的 `line_index`，以及 `previous_on_line` 和 `next_on_line` 的索引。

**2. `AXBlockFlowIterator` 类:**

* **功能：**
    * **提供一个迭代器，用于遍历 `AXBlockFlowData` 中存储的文本片段。**
    * **允许按顺序获取块级元素中的文本内容 (`GetText`)。**
    * **获取当前文本片段中每个字符的布局像素偏移 (`GetCharacterLayoutPixelOffsets`)，这对于屏幕阅读器等辅助技术定位光标非常重要。**
    * **支持在同一行内的文本片段之间移动 (`NextOnLine`, `PreviousOnLine`)。** 这对于按行读取内容很有用。

* **与 JavaScript, HTML, CSS 的关系：**
    * **HTML/CSS：** 迭代器遍历的文本片段是由 HTML 结构和 CSS 样式共同决定的。例如，CSS 的 `display: inline` 元素如果包含在块级元素内，其文本内容也会被迭代器访问到。
    * **JavaScript：** 辅助功能相关的 JavaScript 代码可能会使用 `AXBlockFlowIterator` 来获取元素的文本内容和布局信息，以便传递给辅助技术。例如，屏幕阅读器可能会利用这些信息来合成语音。

* **逻辑推理 (假设输入与输出):**
    * **假设输入：** 一个指向上述 HTML 示例中 `<div>` 元素的 `AXObject`。
    * **操作：** 创建一个 `AXBlockFlowIterator` 并调用 `Next()` 和 `GetText()` 方法。
    * **输出：**
        * 第一次调用 `Next()` 后，`GetText()` 可能返回 "This is line one." 中的一部分文本片段（取决于如何进行碎片化）。
        * 多次调用 `Next()` 和 `GetText()` 会依次返回该块级元素中的所有文本片段。
        * 调用 `NextOnLine()` 会移动到同一行中的下一个文本片段。

* **用户或编程常见的使用错误：**
    * **未调用 `Next()` 就调用 `GetText()` 或 `GetCharacterLayoutPixelOffsets()`:** 迭代器需要先移动到某个有效的片段，才能获取其信息。代码中通过 `DCHECK(current_index_)` 来进行断言检查。
    * **在迭代过程中修改 DOM 结构：**  如果 `AXBlockFlowData` 的数据基于过时的布局信息，迭代器的行为可能会变得不可预测。

* **用户操作是如何一步步的到达这里，作为调试线索：**

    1. **用户与网页交互：** 用户打开一个包含块级元素的网页，例如浏览一篇博客文章或一个包含大量文本的网页。
    2. **辅助功能被激活：** 用户可能启用了屏幕阅读器、键盘导航或其他辅助技术。
    3. **Accessibility Tree 构建：** 当辅助功能被激活时，浏览器会构建 Accessibility Tree，这是一个表示页面可访问性信息的树形结构，其中包含了 `AXObject` 等对象。
    4. **请求文本内容：** 屏幕阅读器或其他辅助技术需要获取页面内容的文本信息才能呈现给用户。它们会通过 Accessibility API 请求 `AXObject` 的文本内容。
    5. **`AXBlockFlowData` 创建：**  对于包含文本内容的块级元素的 `AXObject`，可能会创建 `AXBlockFlowData` 对象来预处理其布局信息。
    6. **`AXBlockFlowIterator` 创建和使用：** 为了按顺序获取块级元素的文本内容，会创建一个 `AXBlockFlowIterator` 对象，并使用其 `Next()` 和 `GetText()` 等方法来遍历文本片段。
    7. **`GetCharacterLayoutPixelOffsets()` 的使用：** 当屏幕阅读器需要精确定位光标或高亮显示文本时，可能会调用 `GetCharacterLayoutPixelOffsets()` 来获取每个字符的布局位置。

**调试线索：**

* 如果在辅助功能开启的情况下，屏幕阅读器读取的文本顺序或内容不正确，或者光标位置错乱，那么问题可能出在 `AXBlockFlowData` 的信息构建或 `AXBlockFlowIterator` 的迭代逻辑上。
* 可以通过在 `AXBlockFlowData` 的 `ProcessLayoutBlock` 和 `ProcessBoxFragment` 方法中添加日志输出来查看布局信息的处理过程。
* 可以在 `AXBlockFlowIterator` 的 `Next()`, `GetText()`, `GetCharacterLayoutPixelOffsets()` 等方法中添加断点或日志输出来跟踪迭代器的行为。
* 检查 `layout_fragment_map_` 和 `lines_` 中的数据是否正确反映了页面的布局结构。

总而言之，`ax_block_flow_iterator.cc` 文件中的代码是 Blink 引擎为了实现网页内容的可访问性而设计的重要组成部分，它专注于提取和组织块级元素的文本信息，以便辅助技术能够正确地理解和呈现网页内容。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_block_flow_iterator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/accessibility/ax_block_flow_iterator.h"

#include <numeric>

#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_span.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/modules/accessibility/ax_debug_utils.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/platform/fonts/character_range.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"

namespace blink {

namespace {

// Determines if a trailing space is required for a11y. An end-of-line text
// fragment does not include trailing whitespace since not rendered; however,
// we need to know there is a space there for editing purposes in a11y.
// A trailing whitespace is included if all of the following conditions are met:
//  * The line does not end in a forced linebreak (e.g. <br>)
//  * The position of the linebreak is immediately after the text fragment.
//  * The character immediately following the text fragment is a space.
//  * The trailing space was elided (not included in the next fragment)
//  * The trailing space is associated with the same layout object.
bool IncludeTrailingWhitespace(const WTF::String& text,
                               wtf_size_t offset,
                               const FragmentItem& item,
                               const AXBlockFlowData::Line& line) {
  if (line.forced_break) {
    return false;
  }

  if (line.break_index != offset + 1) {
    return false;
  }

  if (text[offset] != WTF::unicode::kSpaceCharacter) {
    return false;
  }

  if (item.Style().ShouldPreserveWhiteSpaces()) {
    return false;
  }

  const LayoutObject* layout_object = item.GetLayoutObject();
  const OffsetMapping* mapping = OffsetMapping::GetFor(layout_object);
  if (!mapping) {
    return false;
  }

  const base::span<const OffsetMappingUnit> mapping_units =
      mapping->GetMappingUnitsForTextContentOffsetRange(offset, offset + 1);
  if (mapping_units.begin() == mapping_units.end()) {
    return false;
  }
  const OffsetMappingUnit& mapping_unit = mapping_units.front();
  return mapping_unit.GetLayoutObject() == layout_object;
}

}  // end anonymous namespace

WTF::String AXBlockFlowData::GetText(wtf_size_t item_index) const {
  Position position = GetPosition(item_index);
  const PhysicalBoxFragment* box_fragment =
      BoxFragment(position.fragmentainer_index);
  const FragmentItems& fragment_items = *box_fragment->Items();
  const FragmentItem& item = fragment_items.Items()[position.item_index];
  if (item.Type() == FragmentItem::kGeneratedText) {
    return item.GeneratedText().ToString();
  }
  if (item.Type() != FragmentItem::kText) {
    return WTF::String();
  }
  wtf_size_t start_offset = item.TextOffset().start;
  wtf_size_t end_offset = item.TextOffset().end;
  wtf_size_t length = end_offset - start_offset;

  // TODO: handle first line text content.
  String full_text = fragment_items.Text(item.UsesFirstLineStyle());

  const FragmentProperties& fragment_properties =
      fragment_properties_[item_index];

  // If the text elided a trailing whitespace, we may need to reintroduce it.
  // Trailing whitespace is elided since not rendered; however, there may still
  // be required for a11y.
  if (fragment_properties.line_index) {
    const AXBlockFlowData::Line& line =
        lines_[fragment_properties.line_index.value()];
    if (IncludeTrailingWhitespace(full_text, end_offset, item, line)) {
      length++;
    }
  }

  return StringView(full_text, start_offset, length).ToString();
}

const AXBlockFlowData::FragmentProperties& AXBlockFlowData::GetProperties(
    wtf_size_t index) const {
  return fragment_properties_[index];
}

void AXBlockFlowData::Trace(Visitor* visitor) const {
  visitor->Trace(block_flow_container_);
  visitor->Trace(layout_fragment_map_);
  visitor->Trace(lines_);
  visitor->Trace(fragment_properties_);
}

AXBlockFlowData::AXBlockFlowData(LayoutBlockFlow* layout_block_flow)
    : block_flow_container_(layout_block_flow) {
#if DCHECK_IS_ON()
  // Launch with --vmodule=ax_debug_utils=2 to see a diagnostic dump of the
  // block fragmentation.
  DumpBlockFragmentationData(layout_block_flow);
#endif  // DCHECK_IS_ON()

  ProcessLayoutBlock(layout_block_flow);
}

AXBlockFlowData::~AXBlockFlowData() = default;

void AXBlockFlowData::ProcessLayoutBlock(LayoutBlockFlow* container) {
  wtf_size_t starting_fragment_index = 0;
  int container_fragment_count = container->PhysicalFragmentCount();
  // To compute hidden correctly, we need to walk the ancestor chain.
  if (container_fragment_count) {
    for (int fragment_index = 0; fragment_index < container_fragment_count;
         fragment_index++) {
      const PhysicalBoxFragment* fragment =
          container->GetPhysicalFragment(fragment_index);
      if (fragment->Items()) {
        wtf_size_t next_starting_index =
            starting_fragment_index + fragment->Items()->Size();
        fragment_properties_.resize(next_starting_index);
        ProcessBoxFragment(fragment, starting_fragment_index);
        starting_fragment_index = next_starting_index;
      }
    }
  }
  total_fragment_count_ = starting_fragment_index;
}

void AXBlockFlowData::ProcessBoxFragment(const PhysicalBoxFragment* fragment,
                                         wtf_size_t starting_fragment_index) {
  const FragmentItems* items = fragment->Items();
  if (!items) {
    return;
  }

  wtf_size_t fragment_index = starting_fragment_index;
  std::optional<wtf_size_t> previous_on_line;
  for (auto it = items->Items().begin(); it != items->Items().end();
       it++, fragment_index++) {
    const LayoutObject* layout_object = it->GetLayoutObject();
    auto range_it = layout_fragment_map_.find(layout_object);
    if (range_it == layout_fragment_map_.end()) {
      layout_fragment_map_.insert(layout_object, fragment_index);
    }

    bool on_current_line = OnCurrentLine(fragment_index);
    if (it->Type() == FragmentItem::kLine) {
      wtf_size_t length = it->DescendantsCount();
      const InlineBreakToken* break_token = it->GetInlineBreakToken();
      bool forced_break = break_token && break_token->IsForcedBreak();
      std::optional<wtf_size_t> break_index;
      if (break_token) {
        break_index = break_token->StartTextOffset();
      }
      lines_.push_back<Line>({.start_index = fragment_index,
                              .length = length,
                              .forced_break = forced_break,
                              .break_index = break_index});
      if (!on_current_line) {
        previous_on_line = std::nullopt;
      }
      on_current_line = true;
    }

    FragmentProperties& properties = fragment_properties_[fragment_index];
    if (on_current_line) {
      properties.line_index = lines_.size() - 1;
    }

    if (it->Type() == FragmentItem::kText ||
        it->Type() == FragmentItem::kGeneratedText) {
      if (previous_on_line) {
        properties.previous_on_line = previous_on_line;
        fragment_properties_[previous_on_line.value()].next_on_line =
            fragment_index;
      }
      previous_on_line = fragment_index;
    }

    // TODO (accessibility): Handle box fragments with children stored in a
    // separate physical box fragment. We should be able to process these in
    // a single pass and make AXNodeObject::NextOnLine a trivial lookup.
  }
}

bool AXBlockFlowData::OnCurrentLine(wtf_size_t index) const {
  if (lines_.empty()) {
    return false;
  }

  // The fragment is on the current line if within the line's boundaries.
  const Line& candidate = lines_.back();
  return candidate.start_index < index &&
         candidate.start_index + candidate.length > index;
}

const std::optional<wtf_size_t> AXBlockFlowData::FindFirstFragment(
    const LayoutObject* layout_object) const {
  auto it = layout_fragment_map_.find(layout_object);
  if (it != layout_fragment_map_.end()) {
    return it->value;
  }
  return std::nullopt;
}

const AXBlockFlowData::Position AXBlockFlowData::GetPosition(
    wtf_size_t index) const {
  wtf_size_t container_fragment_count =
      block_flow_container_->PhysicalFragmentCount();

  if (container_fragment_count) {
    for (wtf_size_t fragment_index = 0;
         fragment_index < container_fragment_count; fragment_index++) {
      const PhysicalBoxFragment* fragment =
          block_flow_container_->GetPhysicalFragment(fragment_index);
      wtf_size_t size = fragment->Items()->Size();
      if (index < size) {
        return {.fragmentainer_index = fragment_index, .item_index = index};
      }
      index -= size;
    }
  }
  return {container_fragment_count, 0};
}

const FragmentItem* AXBlockFlowData::ItemAt(wtf_size_t index) const {
  if (index >= Size()) {
    return nullptr;
  }

  Position position = GetPosition(index);
  const PhysicalBoxFragment* box_fragment =
      block_flow_container_->GetPhysicalFragment(position.fragmentainer_index);
  return &box_fragment->Items()->Items()[position.item_index];
}

const PhysicalBoxFragment* AXBlockFlowData::BoxFragment(
    wtf_size_t index) const {
  return block_flow_container_->GetPhysicalFragment(index);
}

AXBlockFlowIterator::AXBlockFlowIterator(const AXObject* object)
    : block_flow_data_(object->AXObjectCache().GetBlockFlowData(object)),
      layout_object_(object->GetLayoutObject()) {
  start_index_ = block_flow_data_->FindFirstFragment(layout_object_);
}

bool AXBlockFlowIterator::Next() {
  text_.reset();
  character_widths_.reset();

  if (!start_index_) {
    return false;
  }

  if (!current_index_) {
    current_index_ = start_index_.value();
    return true;
  }

  wtf_size_t delta = block_flow_data_->ItemAt(current_index_.value())
                         ->DeltaToNextForSameLayoutObject();
  if (delta) {
    current_index_ = current_index_.value() + delta;
    return true;
  }

  return false;
}

const WTF::String& AXBlockFlowIterator::GetText() {
  DCHECK(current_index_) << "Must call Next to set initial iterator position "
                            "before calling GetText";

  if (text_) {
    return text_.value();
  }

  text_ = block_flow_data_->GetText(current_index_.value());
  return text_.value();
}

// static
WTF::String AXBlockFlowIterator::GetTextForTesting(
    AXBlockFlowIterator::MapKey map_key) {
  const FragmentItems* items = map_key.first;
  wtf_size_t index = map_key.second;
  const FragmentItem item = items->Items()[index];
  wtf_size_t start_offset = item.TextOffset().start;
  wtf_size_t end_offset = item.TextOffset().end;
  wtf_size_t length = end_offset - start_offset;
  String full_text = items->Text(/*first_line=*/false);
  return StringView(full_text, start_offset, length).ToString();
}

const std::vector<int>& AXBlockFlowIterator::GetCharacterLayoutPixelOffsets() {
  DCHECK(current_index_) << "Must call Next to set initial iterator position "
                            "before calling GetCharacterOffsets";

  if (character_widths_) {
    return character_widths_.value();
  }

  wtf_size_t length = GetText().length();
  const FragmentItem& item = *block_flow_data_->ItemAt(current_index_.value());
  const ShapeResultView* shape_result_view = item.TextShapeResult();
  float width_tally = 0;
  if (shape_result_view) {
    ShapeResult* shape_result = shape_result_view->CreateShapeResult();
    if (shape_result) {
      Vector<CharacterRange> ranges;
      shape_result->IndividualCharacterRanges(&ranges);
      character_widths_ = std::vector<int>();
      character_widths_->reserve(std::max(ranges.size(), length));
      character_widths_->resize(0);
      for (const auto& range : ranges) {
        width_tally += range.Width();
        character_widths_->push_back(roundf(width_tally));
      }
    }
  }
  // Pad with zero-width characters to the required length.
  for (wtf_size_t i = character_widths_->size(); i < length; i++) {
    character_widths_->push_back(width_tally);
  }
  return character_widths_.value();
}

const std::optional<AXBlockFlowIterator::MapKey>
AXBlockFlowIterator::NextOnLine() {
  DCHECK(current_index_)
      << "Must call Next to set initial iterator position before calling "
      << "NextOnLine";

  const AXBlockFlowData::FragmentProperties& properties =
      block_flow_data_->GetProperties(current_index_.value());
  if (properties.next_on_line) {
    const AXBlockFlowData::Position position =
        block_flow_data_->GetPosition(properties.next_on_line.value());
    const PhysicalBoxFragment* box_fragment =
        block_flow_data_->BoxFragment(position.fragmentainer_index);
    return MapKey(box_fragment->Items(), position.item_index);
  }

  return std::nullopt;
}

const std::optional<AXBlockFlowIterator::MapKey>
AXBlockFlowIterator::PreviousOnLine() {
  DCHECK(current_index_)
      << "Must call Next to set initial iterator position before calling "
      << "PreviousOnLine";

  const AXBlockFlowData::FragmentProperties& properties =
      block_flow_data_->GetProperties(current_index_.value());
  if (properties.previous_on_line) {
    const AXBlockFlowData::Position position =
        block_flow_data_->GetPosition(properties.previous_on_line.value());
    const PhysicalBoxFragment* box_fragment =
        block_flow_data_->BoxFragment(position.fragmentainer_index);
    return MapKey(box_fragment->Items(), position.item_index);
  }

  return std::nullopt;
}

const AXBlockFlowIterator::MapKey AXBlockFlowIterator::GetMapKey() const {
  DCHECK(current_index_)
      << "Must call Next to set initial iterator position before calling "
      << "GetMapKey";

  const AXBlockFlowData::Position position =
      block_flow_data_->GetPosition(current_index_.value());
  const PhysicalBoxFragment* box_fragment =
      block_flow_data_->BoxFragment(position.fragmentainer_index);
  return MapKey(box_fragment->Items(), position.item_index);
}

}  // namespace blink

"""

```