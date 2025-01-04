Response:
My thought process to arrive at the summary of `text_autosizer.cc` went through these stages:

1. **Understanding the Request:** The core request is to understand the functionality of the `text_autosizer.cc` file in the Chromium Blink engine, specifically focusing on its role in text autosizing. The prompt also asks for connections to web technologies (HTML, CSS, JavaScript), logical reasoning, potential errors, and a summary of the provided code snippet.

2. **Initial Scan and Keyword Spotting:**  I started by quickly scanning the code, looking for recurring keywords and phrases. Terms like "TextAutosizer", "LayoutBlock", "LayoutText", "multiplier", "cluster", "fingerprint", "page info", and functions like `Inflate`, `ApplyMultiplier`, `ComputeFingerprint`, `ClassifyBlock`, `ClusterHasEnoughTextToAutosize` immediately jumped out. These keywords provide the central themes of the file.

3. **Identifying Core Functionality:**  Based on the keywords, I hypothesized that the primary purpose of this file is to dynamically adjust the size of text on a web page. The "autosizer" in the name strongly suggests this. The presence of "multiplier" indicates a scaling mechanism.

4. **Analyzing Key Data Structures:** I noted the presence of `Cluster` and `Fingerprint`. This suggested a mechanism for grouping related layout elements for autosizing and identifying them consistently. The `page_info_` member variable hinted at storing global information relevant to the autosizing process.

5. **Tracing the Autosizing Process (Hypothetical Flow):** I started to piece together a mental model of how the autosizing might work:
    * **Detection:** The system needs to detect blocks of text that are candidates for autosizing (`IsPotentialClusterRoot`).
    * **Grouping:**  Related blocks are grouped into "clusters" (`MaybeCreateCluster`).
    * **Decision:** A decision is made about whether a cluster needs autosizing, likely based on the amount of text (`ClusterHasEnoughTextToAutosize`).
    * **Scaling:** If autosizing is needed, a multiplier is calculated and applied to the text elements (`ApplyMultiplier`, `Inflate`).
    * **Configuration:** Page-level settings and viewport information are considered (`UpdatePageInfo`).
    * **Optimization/Identification:** "Fingerprints" are used to efficiently track and identify layout elements and their properties (`ComputeFingerprint`).

6. **Connecting to Web Technologies:**  I started to make explicit connections to HTML, CSS, and JavaScript:
    * **HTML:**  The code interacts with `LayoutBlock`, `LayoutText`, and elements like `HTMLTextAreaElement`. The autosizing directly affects how HTML content is rendered.
    * **CSS:**  CSS properties like `font-size`, `width`, `overflow`, `display`, and `writing-mode` are clearly used in the decision-making process (`ClassifyBlock`, `BlockSuppressesAutosizing`). The autosizing effectively overrides or adjusts the default text rendering based on these styles.
    * **JavaScript:** While this specific file doesn't contain JavaScript, the broader context of the Blink engine implies that JavaScript could trigger layout changes that would then invoke the text autosizer. Features like dynamic content loading or style manipulation could lead to autosizing being applied.

7. **Considering Edge Cases and Potential Errors:** I looked for conditions that might lead to unexpected behavior or errors:
    * **Conflicting Settings:**  What happens if the user has zoomed in significantly? How does that interact with autosizing?
    * **Layout Thrashing:** Could frequent layout changes trigger excessive autosizing calculations?
    * **Inconsistent Application:** The code mentions ensuring consistency within lists (`IsListItem`). What happens if the logic for this is flawed?
    * **Destroyed Objects:** The `Destroy` function highlights the need to handle cases where layout objects are removed during the layout process.

8. **Structuring the Summary:** I organized my findings into logical categories based on the prompt's requirements:
    * **Core Functionality:**  The primary purpose of the file.
    * **Relationship to Web Technologies:** Concrete examples of how the code interacts with HTML, CSS, and JavaScript.
    * **Logical Reasoning:** Explaining the decision-making process and providing hypothetical inputs and outputs (though the code itself didn't offer direct input/output examples in the traditional sense, I focused on the conditions that trigger autosizing).
    * **User/Programming Errors:** Common pitfalls or scenarios where the autosizing might not work as expected.

9. **Refining and Consolidating:** I reviewed my initial thoughts and refined the language to be more precise and concise. I made sure to address all aspects of the prompt. For the "归纳一下它的功能" (summarize its functionality) part, I focused on a high-level description of the file's purpose.

This iterative process of scanning, hypothesizing, analyzing, connecting, and refining allowed me to construct a comprehensive understanding of the `text_autosizer.cc` file and its role in the Blink rendering engine. The key was to move from the concrete code elements to the abstract functionality and its implications for web page rendering.
好的，根据您提供的代码片段，以下是`blink/renderer/core/layout/text_autosizer.cc` 文件（第一部分）的功能归纳：

**核心功能：自动调整网页文本大小**

该文件的核心功能是实现 Chromium Blink 引擎中的 **文本自动调整 (Text Autosizing)** 功能。这个功能旨在提升在移动设备等小屏幕设备上的阅读体验，通过动态调整文本大小来避免文本过小难以阅读的问题。

**具体功能点：**

1. **识别可进行文本自动调整的区域 (Clusters):**
   - 定义了“潜在的集群根 (Potential Cluster Root)” 的概念，这些是能够独立进行文本自动调整的最小单元（通常是块级元素）。
   - 通过 `IsPotentialClusterRoot` 函数判断一个 `LayoutObject` 是否可以作为集群的根。
   - 排除内联元素（除非是 `inline-block` 等）、普通的列表项等不适合单独调整大小的元素。

2. **判断是否需要进行文本自动调整:**
   - 通过 `ClusterHasEnoughTextToAutosize` 函数判断一个文本集群是否包含足够多的文本内容，从而决定是否需要对其进行自动调整。
   - 考虑文本的长度、容器的宽度等因素。
   - 对于 `textarea` 等表单控件或用户可编辑区域，默认认为需要自动调整。

3. **计算和应用文本大小调整倍数 (Multiplier):**
   - 虽然这部分代码片段中没有直接看到计算 `multiplier` 的逻辑，但文件名和代码结构表明该文件负责管理和应用这个倍数。
   - `Inflate` 函数用于遍历布局对象树，并调用 `ApplyMultiplier` 函数来实际应用计算出的倍数。

4. **维护页面级别的自动调整信息 (PageInfo):**
   - 使用 `PageInfo` 结构体来存储页面级别的自动调整设置和状态，例如是否启用了文本自动调整、页面是否需要自动调整等。
   - `UpdatePageInfo` 函数负责更新这些信息，考虑到屏幕尺寸、用户设置等因素。

5. **利用指纹 (Fingerprint) 机制进行优化:**
   - 通过 `ComputeFingerprint` 函数为布局对象生成指纹，用于跟踪和识别具有相同特征的布局结构。
   - `fingerprint_mapper_` 用于存储和管理这些指纹，可能用于优化自动调整的性能，避免重复计算。

6. **处理布局过程中的相关逻辑:**
   - `Record` 函数在布局开始前记录需要进行自动调整的块。
   - `PrepareForLayout` 和 `BeginLayout` 函数在布局开始时进行准备工作，例如创建集群。
   - `EndLayout` 函数在布局结束后清理状态。

**与 Javascript, HTML, CSS 的关系：**

* **HTML:**  `text_autosizer.cc` 直接操作由 HTML 结构生成的布局树 (`LayoutObject` 及其子类，如 `LayoutBlock`, `LayoutText`)。它根据 HTML 元素的类型（例如 `HTMLTextAreaElement`）和内容来决定是否进行自动调整。

* **CSS:**  该文件会读取和分析元素的 CSS 样式信息 (`ComputedStyle`)，例如：
    * **`font-size`**:  虽然自动调整会修改最终的渲染大小，但原始的 `font-size` 是判断的依据之一。
    * **`width`**, **`height`**:  用于判断容器的大小，影响文本是否需要换行以及是否需要自动调整。
    * **`display`**:  区分块级元素和内联元素，决定是否可以作为集群根。
    * **`overflow`**:  判断容器是否限制了高度，影响自动调整的策略。
    * **`white-space`**:  `BlockSuppressesAutosizing` 函数会检查 `ShouldWrapLine()`，这与 `white-space` 属性有关。
    * **`user-modify`**:  用于判断元素是否可编辑，影响自动调整的判断。
    * **链接样式**: `BlockIsRowOfLinks` 会检查链接的字体大小。

* **Javascript:** 虽然这段代码是 C++，但文本自动调整功能会影响 JavaScript 获取到的元素尺寸信息。JavaScript 代码可能会查询元素的渲染尺寸，而文本自动调整会直接影响这些尺寸。此外，JavaScript 也可能动态修改 HTML 结构和 CSS 样式，从而间接触发或影响文本自动调整的行为。

**逻辑推理（假设输入与输出）：**

* **假设输入：** 一个 `div` 元素包含大量文本，其父元素的宽度较小，导致文本在小屏幕设备上显示过小难以阅读。文本自动调整功能已启用。
* **输出：** `text_autosizer.cc` 会将这个 `div` 识别为一个潜在的集群根。通过 `ClusterHasEnoughTextToAutosize` 判断其包含足够多的文本。最终，会计算出一个大于 1 的 `multiplier`，并应用到该 `div` 内的文本元素上，使得文本的渲染大小增大。

* **假设输入：** 一个包含少量链接的 `div` 元素，每个链接的字体大小相同。文本自动调整功能已启用。
* **输出：** `BlockIsRowOfLinks` 函数会判断这个 `div` 是一个链接行，并可能阻止对其进行文本自动调整，以保持链接排列的一致性。

**用户或编程常见的使用错误：**

* **错误地认为所有文本都会被自动调整：**  开发者可能误以为页面上的所有文本都会被自动调整，但实际上，该功能有其判断条件和限制，例如小的文本块可能不会被调整。
* **过度依赖文本自动调整而忽略响应式设计：**  开发者可能过度依赖文本自动调整来解决小屏幕适配问题，而忽略了更根本的响应式设计，例如使用 media queries 来调整布局和字体大小。
* **动态修改内容后未触发重新布局：** 如果 JavaScript 动态添加了大量文本内容，但没有触发页面的重新布局，可能导致文本自动调整未能及时生效。
* **与某些 CSS 属性冲突：** 某些 CSS 属性，例如明确设置了很小的 `font-size`，可能会影响文本自动调整的效果，或者导致自动调整被抑制。

**功能归纳：**

总而言之，`blink/renderer/core/layout/text_autosizer.cc` 的主要职责是 **智能地识别网页中需要进行文本自动调整的区域，并根据一定的策略和页面状态，动态地调整这些区域的文本大小，以提升在小屏幕设备上的阅读体验。** 它通过分析布局结构、CSS 样式和页面信息来实现这一目标，并利用指纹机制进行优化。

Prompt: 
```
这是目录为blink/renderer/core/layout/text_autosizer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/layout/text_autosizer.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/list/layout_list_item.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_row.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_section.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "ui/gfx/geometry/rect.h"

namespace blink {

namespace {

inline int GetLayoutInlineSize(const Document& document,
                               const LocalFrameView& main_frame_view) {
  gfx::Size size = main_frame_view.GetLayoutSize();
  return document.GetLayoutView()->IsHorizontalWritingMode() ? size.width()
                                                             : size.height();
}

}  // namespace

static LayoutObject* ParentElementLayoutObject(
    const LayoutObject* layout_object) {
  // At style recalc, the layoutObject's parent may not be attached,
  // so we need to obtain this from the DOM tree.
  const Node* node = layout_object->GetNode();
  if (!node)
    return nullptr;

  // FIXME: This should be using LayoutTreeBuilderTraversal::parent().
  if (Element* parent = node->parentElement())
    return parent->GetLayoutObject();
  return nullptr;
}

static bool IsNonTextAreaFormControl(const LayoutObject* layout_object) {
  const Node* node = layout_object ? layout_object->GetNode() : nullptr;
  const auto* element = DynamicTo<Element>(node);
  if (!element)
    return false;

  return (element->IsFormControlElement() &&
          !IsA<HTMLTextAreaElement>(element));
}

static bool IsPotentialClusterRoot(const LayoutObject* layout_object) {
  // "Potential cluster roots" are the smallest unit for which we can
  // enable/disable text autosizing.
  // - Must have children.
  //   An exception is made for LayoutView which should create a root to
  //   maintain consistency with documents that have no child nodes but may
  //   still have LayoutObject children.
  // - Must not be inline, as different multipliers on one line looks terrible.
  //   Exceptions are inline-block and alike elements (inline-table,
  //   -webkit-inline-*), as they often contain entire multi-line columns of
  //   text.
  // - Must not be normal list items, as items in the same list should look
  //   consistent, unless they are floating or position:absolute/fixed.
  Node* node = layout_object->GeneratingNode();
  if (node && !node->hasChildren() && !IsA<LayoutView>(layout_object))
    return false;
  if (!layout_object->IsLayoutBlock())
    return false;
  if (layout_object->IsInline() &&
      !layout_object->StyleRef().IsDisplayReplacedType())
    return false;
  if (layout_object->IsListItem()) {
    return (layout_object->IsFloating() ||
            layout_object->IsOutOfFlowPositioned());
  }

  return true;
}

static bool IsIndependentDescendant(const LayoutBlock* layout_object) {
  DCHECK(IsPotentialClusterRoot(layout_object));

  LayoutBlock* containing_block = layout_object->ContainingBlock();
  return IsA<LayoutView>(layout_object) || layout_object->IsFloating() ||
         layout_object->IsOutOfFlowPositioned() ||
         layout_object->IsTableCell() || layout_object->IsTableCaption() ||
         layout_object->IsFlexibleBox() ||
         (containing_block && containing_block->IsHorizontalWritingMode() !=
                                  layout_object->IsHorizontalWritingMode()) ||
         layout_object->StyleRef().IsDisplayReplacedType() ||
         layout_object->IsTextArea() ||
         layout_object->StyleRef().UsedUserModify() != EUserModify::kReadOnly;
}

static bool BlockIsRowOfLinks(const LayoutBlock* block) {
  // A "row of links" is a block for which:
  //  1. It does not contain non-link text elements longer than 3 characters
  //  2. It contains a minimum of 3 inline links and all links should
  //     have the same specified font size.
  //  3. It should not contain <br> elements.
  //  4. It should contain only inline elements unless they are containers,
  //     children of link elements or children of sub-containers.
  int link_count = 0;
  LayoutObject* layout_object = block->FirstChild();
  float matching_font_size = -1;

  while (layout_object) {
    if (!IsPotentialClusterRoot(layout_object)) {
      if (layout_object->IsText() &&
          To<LayoutText>(layout_object)
                  ->TransformedText()
                  .LengthWithStrippedWhiteSpace() > 3) {
        return false;
      }
      if (!layout_object->IsInline() || layout_object->IsBR())
        return false;
    }
    if (layout_object->StyleRef().IsLink()) {
      link_count++;
      if (matching_font_size < 0)
        matching_font_size = layout_object->StyleRef().SpecifiedFontSize();
      else if (matching_font_size !=
               layout_object->StyleRef().SpecifiedFontSize())
        return false;

      // Skip traversing descendants of the link.
      layout_object = layout_object->NextInPreOrderAfterChildren(block);
      continue;
    }
    layout_object = layout_object->NextInPreOrder(block);
  }

  return (link_count >= 3);
}

static inline bool HasAnySizingKeyword(const Length& length) {
  return length.HasAutoOrContentOrIntrinsic() || length.HasStretch() ||
         length.IsNone();
}

static bool BlockHeightConstrained(const LayoutBlock* block) {
  // FIXME: Propagate constrainedness down the tree, to avoid inefficiently
  // walking back up from each box.
  // FIXME: This code needs to take into account vertical writing modes.
  // FIXME: Consider additional heuristics, such as ignoring fixed heights if
  // the content is already overflowing before autosizing kicks in.
  for (; block; block = block->ContainingBlock()) {
    const ComputedStyle& style = block->StyleRef();
    if (style.OverflowY() != EOverflow::kVisible &&
        style.OverflowY() != EOverflow::kHidden) {
      return false;
    }
    if (!HasAnySizingKeyword(style.Height()) ||
        !HasAnySizingKeyword(style.MaxHeight()) ||
        block->IsOutOfFlowPositioned()) {
      // Some sites (e.g. wikipedia) set their html and/or body elements to
      // height:100%, without intending to constrain the height of the content
      // within them.
      return !block->IsDocumentElement() && !block->IsBody() &&
             !IsA<LayoutView>(block);
    }
    if (block->IsFloating())
      return false;
  }
  return false;
}

static bool BlockOrImmediateChildrenAreFormControls(const LayoutBlock* block) {
  if (IsNonTextAreaFormControl(block))
    return true;
  const LayoutObject* layout_object = block->FirstChild();
  while (layout_object) {
    if (IsNonTextAreaFormControl(layout_object))
      return true;
    layout_object = layout_object->NextSibling();
  }

  return false;
}

// Some blocks are not autosized even if their parent cluster wants them to.
static bool BlockSuppressesAutosizing(const LayoutBlock* block) {
  if (BlockOrImmediateChildrenAreFormControls(block))
    return true;

  if (BlockIsRowOfLinks(block))
    return true;

  // Don't autosize block-level text that can't wrap (as it's likely to
  // expand sideways and break the page's layout).
  if (!block->StyleRef().ShouldWrapLine()) {
    return true;
  }

  if (BlockHeightConstrained(block))
    return true;

  return false;
}

static bool HasExplicitWidth(const LayoutBlock* block) {
  // FIXME: This heuristic may need to be expanded to other ways a block can be
  // wider or narrower than its parent containing block.
  return block->Style() && !HasAnySizingKeyword(block->StyleRef().Width());
}

static LayoutObject* GetParent(const LayoutObject* object) {
  LayoutObject* parent = nullptr;
  // LayoutObject haven't added to layout tree yet
  if (object->GetNode() && object->GetNode()->parentNode())
    parent = object->GetNode()->parentNode()->GetLayoutObject();
  return parent;
}

TextAutosizer::TextAutosizer(const Document* document)
    : document_(document),
      first_block_to_begin_layout_(nullptr),
#if DCHECK_IS_ON()
      blocks_that_have_begun_layout_(),
#endif
      cluster_stack_(),
      fingerprint_mapper_(),
      page_info_(),
      update_page_info_deferred_(false),
      did_check_cross_site_use_count_(false) {
}

TextAutosizer::~TextAutosizer() = default;

void TextAutosizer::Record(LayoutBlock* block) {
  if (!page_info_.setting_enabled_)
    return;

#if DCHECK_IS_ON()
  DCHECK(!blocks_that_have_begun_layout_.Contains(block));
#endif
  if (!ClassifyBlock(block, INDEPENDENT | EXPLICIT_WIDTH)) {
    // !everHadLayout() means the object hasn't layout yet
    // which means this object is new added.
    // We only deal with new added block here.
    // If parent is new added, no need to check its children.
    LayoutObject* parent = GetParent(block);
    if (!block->EverHadLayout() && parent && parent->EverHadLayout())
      MarkSuperclusterForConsistencyCheck(parent);
    return;
  }

  if (Fingerprint fingerprint = ComputeFingerprint(block))
    fingerprint_mapper_.AddTentativeClusterRoot(block, fingerprint);

  if (!block->EverHadLayout())
    MarkSuperclusterForConsistencyCheck(block);
}

void TextAutosizer::Record(LayoutText* text) {
  if (!text || !ShouldHandleLayout())
    return;
  LayoutObject* parent = GetParent(text);
  if (parent && parent->EverHadLayout())
    MarkSuperclusterForConsistencyCheck(parent);
}

void TextAutosizer::Destroy(LayoutObject* layout_object) {
  if (!page_info_.setting_enabled_ && !fingerprint_mapper_.HasFingerprints())
    return;

#if DCHECK_IS_ON()
  if (layout_object->IsLayoutBlock()) {
    DCHECK(!blocks_that_have_begun_layout_.Contains(
        To<LayoutBlock>(layout_object)));
  }
#endif

  bool result = fingerprint_mapper_.Remove(layout_object);

  if (layout_object->IsLayoutBlock())
    return;

  if (result && first_block_to_begin_layout_) {
    // LayoutBlock with a fingerprint was destroyed during layout.
    // Clear the cluster stack and the supercluster map to avoid stale pointers.
    // Speculative fix for http://crbug.com/369485.
    first_block_to_begin_layout_ = nullptr;
    cluster_stack_.clear();
  }
}

TextAutosizer::BeginLayoutBehavior TextAutosizer::PrepareForLayout(
    LayoutBlock* block) {
#if DCHECK_IS_ON()
  blocks_that_have_begun_layout_.insert(block);
#endif

  if (!first_block_to_begin_layout_) {
    first_block_to_begin_layout_ = block;
    PrepareClusterStack(block->Parent());
    if (IsA<LayoutView>(block))
      CheckSuperclusterConsistency();
  } else if (block == CurrentCluster()->root_) {
    // Ignore beginLayout on the same block twice.
    // This can happen with paginated overflow.
    return kStopLayout;
  }

  return kContinueLayout;
}

void TextAutosizer::PrepareClusterStack(LayoutObject* layout_object) {
  if (!layout_object)
    return;
  PrepareClusterStack(layout_object->Parent());
  if (auto* block = DynamicTo<LayoutBlock>(layout_object)) {
#if DCHECK_IS_ON()
    blocks_that_have_begun_layout_.insert(block);
#endif
    if (Cluster* cluster = MaybeCreateCluster(block))
      cluster_stack_.push_back(cluster);
  }
}

void TextAutosizer::BeginLayout(LayoutBlock* block) {
  DCHECK(ShouldHandleLayout());

  if (PrepareForLayout(block) == kStopLayout)
    return;

  DCHECK(!cluster_stack_.empty() || IsA<LayoutView>(block));
  if (cluster_stack_.empty())
    did_check_cross_site_use_count_ = false;

  if (Cluster* cluster = MaybeCreateCluster(block))
    cluster_stack_.push_back(cluster);

  DCHECK(!cluster_stack_.empty());

  // Cells in auto-layout tables are handled separately by InflateAutoTable.
  auto* cell = DynamicTo<LayoutTableCell>(block);
  bool is_auto_table_cell =
      cell && !cell->Table()->StyleRef().IsFixedTableLayout();
  if (!is_auto_table_cell && !cluster_stack_.empty())
    Inflate(block);
}

void TextAutosizer::InflateAutoTable(LayoutTable* table) {
  DCHECK(table);
  DCHECK(!table->StyleRef().IsFixedTableLayout());
  DCHECK(table->ContainingBlock());

  Cluster* cluster = CurrentCluster();
  if (cluster->root_ != table)
    return;

  // Pre-inflate cells that have enough text so that their inflated preferred
  // widths will be used for column sizing.
  for (LayoutObject* child = table->FirstChild(); child;
       child = child->NextSibling()) {
    auto* section = DynamicTo<LayoutTableSection>(child);
    if (!section) {
      continue;
    }
    for (const LayoutTableRow* row = section->FirstRow(); row;
         row = row->NextRow()) {
      for (LayoutTableCell* cell = row->FirstCell(); cell;
           cell = cell->NextCell()) {
        if (!cell->NeedsLayout()) {
          continue;
        }
        BeginLayout(cell);
        Inflate(cell, kDescendToInnerBlocks);
        EndLayout(cell);
      }
    }
  }
}

void TextAutosizer::EndLayout(LayoutBlock* block) {
  DCHECK(ShouldHandleLayout());

  if (block == first_block_to_begin_layout_) {
    first_block_to_begin_layout_ = nullptr;
    cluster_stack_.clear();
#if DCHECK_IS_ON()
    blocks_that_have_begun_layout_.clear();
#endif
    // Tables can create two layout scopes for the same block so the isEmpty
    // check below is needed to guard against endLayout being called twice.
  } else if (!cluster_stack_.empty() && CurrentCluster()->root_ == block) {
    cluster_stack_.pop_back();
  }
}

float TextAutosizer::Inflate(LayoutObject* parent,
                             InflateBehavior behavior,
                             float multiplier) {
  Cluster* cluster = CurrentCluster();
  bool has_text_child = false;

  LayoutObject* child = nullptr;
  if (parent->IsLayoutBlock() &&
      (parent->ChildrenInline() || behavior == kDescendToInnerBlocks)) {
    child = To<LayoutBlock>(parent)->FirstChild();
  } else if (parent->IsLayoutInline()) {
    child = To<LayoutInline>(parent)->FirstChild();
  }

  while (child) {
    if (child->IsText()) {
      has_text_child = true;
      // We only calculate this multiplier on-demand to ensure the parent block
      // of this text has entered layout.
      if (!multiplier) {
        multiplier =
            cluster->flags_ & SUPPRESSING ? 1.0f : ClusterMultiplier(cluster);
      }
      ApplyMultiplier(child, multiplier);

      if (behavior == kDescendToInnerBlocks) {
        // The ancestor nodes might be inline-blocks. We should
        // SetIntrinsicLogicalWidthsDirty for ancestor nodes here.
        child->SetIntrinsicLogicalWidthsDirty();
      } else if (parent->IsLayoutInline()) {
        // FIXME: Investigate why MarkOnlyThis is sufficient.
        child->SetIntrinsicLogicalWidthsDirty(kMarkOnlyThis);
      }
    } else if (child->IsLayoutInline()) {
      multiplier = Inflate(child, behavior, multiplier);
      // If this LayoutInline is an anonymous inline that has multiplied
      // children, apply the multiplifer to the parent too. We compute
      // ::first-line style from the style of the parent block.
      if (multiplier && child->IsAnonymous())
        has_text_child = true;
    } else if (child->IsLayoutBlock() && behavior == kDescendToInnerBlocks &&
               !ClassifyBlock(child,
                              INDEPENDENT | EXPLICIT_WIDTH | SUPPRESSING)) {
      multiplier = Inflate(child, behavior, multiplier);
    }
    child = child->NextSibling();
  }

  if (has_text_child) {
    ApplyMultiplier(parent, multiplier);  // Parent handles line spacing.
  } else if (!parent->IsListItem()) {
    // For consistency, a block with no immediate text child should always have
    // a multiplier of 1.
    ApplyMultiplier(parent, 1);
  }

  if (parent->IsLayoutListItem()) {
    float list_item_multiplier = ClusterMultiplier(cluster);
    ApplyMultiplier(parent, list_item_multiplier);

    // The list item has to be treated special because we can have a tree such
    // that you have a list item for a form inside it. The list marker then ends
    // up inside the form and when we try to get the clusterMultiplier we have
    // the wrong cluster root to work from and get the wrong value.
    LayoutObject* marker = To<LayoutListItem>(parent)->Marker();

    // A LayoutOutsideListMarker has a text child that needs its font
    // multiplier updated. Just mark the entire subtree, to make sure we get to
    // it.
    for (LayoutObject* walker = marker; walker;
         walker = walker->NextInPreOrder(marker)) {
      ApplyMultiplier(walker, list_item_multiplier);
      walker->SetIntrinsicLogicalWidthsDirty(kMarkOnlyThis);
    }
  }

  if (page_info_.has_autosized_) {
    document_->CountUse(WebFeature::kTextAutosizing);
    if (page_info_.shared_info_.device_scale_adjustment != 1.0f) {
      document_->CountUse(WebFeature::kUsedDeviceScaleAdjustment);
    }
  }

  return multiplier;
}

bool TextAutosizer::ShouldHandleLayout() const {
  return page_info_.setting_enabled_ && page_info_.page_needs_autosizing_ &&
         !update_page_info_deferred_;
}

bool TextAutosizer::PageNeedsAutosizing() const {
  return page_info_.page_needs_autosizing_;
}

void TextAutosizer::MarkSuperclusterForConsistencyCheck(LayoutObject* object) {
  if (!object || !ShouldHandleLayout())
    return;

  Supercluster* last_supercluster = nullptr;
  while (object) {
    if (auto* block = DynamicTo<LayoutBlock>(object)) {
      if (block->IsTableCell() ||
          ClassifyBlock(block, INDEPENDENT | EXPLICIT_WIDTH)) {
        // If supercluster hasn't been created yet, create one.
        bool is_new_entry = false;
        Supercluster* supercluster =
            fingerprint_mapper_.CreateSuperclusterIfNeeded(block, is_new_entry);
        if (supercluster && supercluster->inherit_parent_multiplier_ ==
                                kDontInheritMultiplier) {
          if (supercluster->has_enough_text_to_autosize_ == kNotEnoughText) {
            fingerprint_mapper_.GetPotentiallyInconsistentSuperclusters()
                .insert(supercluster);
          }
          return;
        }
        if (supercluster &&
            (is_new_entry ||
             supercluster->has_enough_text_to_autosize_ == kNotEnoughText))
          last_supercluster = supercluster;
      }
    }
    object = GetParent(object);
  }

  // If we didn't add any supercluster, we should add one.
  if (last_supercluster) {
    fingerprint_mapper_.GetPotentiallyInconsistentSuperclusters().insert(
        last_supercluster);
  }
}

bool TextAutosizer::HasLayoutInlineSizeChanged() const {
  DCHECK(document_->GetFrame()->IsMainFrame());
  int new_inline_size =
      GetLayoutInlineSize(*document_, *document_->GetFrame()->View());
  return new_inline_size != page_info_.shared_info_.main_frame_layout_width;
}

// Static.
void TextAutosizer::UpdatePageInfoInAllFrames(Frame* main_frame) {
  DCHECK(main_frame && main_frame == main_frame->Tree().Top());
  for (Frame* frame = main_frame; frame; frame = frame->Tree().TraverseNext()) {
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    if (!local_frame)
      continue;

    Document* document = local_frame->GetDocument();
    // If document is being detached, skip updatePageInfo.
    if (!document || !document->IsActive())
      continue;
    if (TextAutosizer* text_autosizer = document->GetTextAutosizer()) {
      text_autosizer->UpdatePageInfo();

      // Share the page information from the local mainframe with remote ones.
      // TODO(wjmaclean): Refactor this code into a non-static class function
      // called UpdateWebTextAutosizerPageInfoIfNecessary().
      if (frame->IsMainFrame()) {
        const PageInfo& page_info = text_autosizer->page_info_;
        const mojom::blink::TextAutosizerPageInfo& old_page_info =
            document->GetPage()->TextAutosizerPageInfo();
        if (page_info.shared_info_ != old_page_info) {
          document->GetPage()->GetChromeClient().DidUpdateTextAutosizerPageInfo(
              page_info.shared_info_);
          // Remember the RemotePageSettings in the mainframe's renderer so we
          // know when they change.
          document->GetPage()->SetTextAutosizerPageInfo(page_info.shared_info_);
        }
      }
    }
  }
}

void TextAutosizer::UpdatePageInfo() {
  if (update_page_info_deferred_ || !document_->GetPage() ||
      !document_->GetSettings())
    return;

  PageInfo previous_page_info(page_info_);
  page_info_.setting_enabled_ =
      document_->GetSettings()->GetTextAutosizingEnabled();

  if (!page_info_.setting_enabled_ || document_->Printing()) {
    page_info_.page_needs_autosizing_ = false;
  } else {
    auto* layout_view = document_->GetLayoutView();
    bool horizontal_writing_mode =
        IsHorizontalWritingMode(layout_view->StyleRef().GetWritingMode());

    Frame& frame = document_->GetFrame()->Tree().Top();
    if (frame.IsRemoteFrame()) {
      // When the frame is remote, the local main frame is responsible for
      // computing shared_info_ and passing them down to the OOPIF renderers.
      page_info_.shared_info_ = document_->GetPage()->TextAutosizerPageInfo();
    } else {
      LocalFrame& main_frame = To<LocalFrame>(frame);
      gfx::Size frame_size =
          document_->GetSettings()->GetTextAutosizingWindowSizeOverride();
      if (frame_size.IsEmpty())
        frame_size = WindowSize();

      page_info_.shared_info_.main_frame_width =
          horizontal_writing_mode ? frame_size.width() : frame_size.height();

      page_info_.shared_info_.main_frame_layout_width =
          GetLayoutInlineSize(*document_, *main_frame.View());

      // If the page has a meta viewport, don't apply the device scale
      // adjustment.
      if (!main_frame.GetDocument()
               ->GetViewportData()
               .GetViewportDescription()
               .IsSpecifiedByAuthor()) {
        page_info_.shared_info_.device_scale_adjustment =
            document_->GetSettings()->GetDeviceScaleAdjustment();
      } else {
        page_info_.shared_info_.device_scale_adjustment = 1.0f;
      }
    }
    // TODO(pdr): Accessibility should be moved out of the text autosizer.
    // See: crbug.com/645717. We keep the font scale factor available so
    // sites that rely on the now deprecated text-size-adjust can still
    // determine the user's desired text scaling.
    page_info_.accessibility_font_scale_factor_ =
        document_->GetSettings()->GetAccessibilityFontScaleFactor();

    // TODO(pdr): pageNeedsAutosizing should take into account whether
    // text-size-adjust is used anywhere on the page because that also needs to
    // trigger autosizing. See: crbug.com/646237.
    page_info_.page_needs_autosizing_ =
        !!page_info_.shared_info_.main_frame_width &&
        (page_info_.accessibility_font_scale_factor_ *
             page_info_.shared_info_.device_scale_adjustment *
             (static_cast<float>(
                  page_info_.shared_info_.main_frame_layout_width) /
              page_info_.shared_info_.main_frame_width) >
         1.0f);
  }

  if (page_info_.page_needs_autosizing_) {
    // If page info has changed, multipliers may have changed. Force a layout to
    // recompute them.
    if (page_info_.shared_info_ != previous_page_info.shared_info_ ||
        page_info_.accessibility_font_scale_factor_ !=
            previous_page_info.accessibility_font_scale_factor_ ||
        page_info_.setting_enabled_ != previous_page_info.setting_enabled_)
      SetAllTextNeedsLayout();
  } else if (previous_page_info.has_autosized_) {
    // If we are no longer autosizing the page, we won't do anything during the
    // next layout. Set all the multipliers back to 1 now.
    ResetMultipliers();
    page_info_.has_autosized_ = false;
  }
}

gfx::Size TextAutosizer::WindowSize() const {
  Page* page = document_->GetPage();
  DCHECK(page);
  return page->GetVisualViewport().Size();
}

void TextAutosizer::ResetMultipliers() {
  LayoutObject* layout_object = document_->GetLayoutView();
  while (layout_object) {
    if (const ComputedStyle* style = layout_object->Style()) {
      if (style->TextAutosizingMultiplier() != 1)
        ApplyMultiplier(layout_object, 1, kLayoutNeeded);
    }
    layout_object = layout_object->NextInPreOrder();
  }
}

void TextAutosizer::SetAllTextNeedsLayout(LayoutBlock* container) {
  if (!container)
    container = document_->GetLayoutView();
  LayoutObject* object = container;
  while (object) {
    if (!object->EverHadLayout()) {
      // Object is new added node, so no need to deal with its children
      object = object->NextInPreOrderAfterChildren(container);
    } else {
      if (object->IsText()) {
        object->SetNeedsLayoutAndFullPaintInvalidation(
            layout_invalidation_reason::kTextAutosizing);
        object->SetNeedsCollectInlines();
      }
      object = object->NextInPreOrder(container);
    }
  }
}

TextAutosizer::BlockFlags TextAutosizer::ClassifyBlock(
    const LayoutObject* layout_object,
    BlockFlags mask) const {
  const auto* block = DynamicTo<LayoutBlock>(layout_object);
  if (!block)
    return 0;

  BlockFlags flags = 0;
  if (IsPotentialClusterRoot(block)) {
    if (mask & POTENTIAL_ROOT)
      flags |= POTENTIAL_ROOT;

    if ((mask & INDEPENDENT) &&
        (IsIndependentDescendant(block) || block->IsTable() ||
         block->StyleRef().SpecifiesColumns()))
      flags |= INDEPENDENT;

    if ((mask & EXPLICIT_WIDTH) && HasExplicitWidth(block))
      flags |= EXPLICIT_WIDTH;

    if ((mask & SUPPRESSING) && BlockSuppressesAutosizing(block))
      flags |= SUPPRESSING;
  }
  return flags;
}

bool TextAutosizer::ClusterWouldHaveEnoughTextToAutosize(
    const LayoutBlock* root,
    const LayoutBlock* width_provider) {
  Cluster* hypothetical_cluster =
      MakeGarbageCollected<Cluster>(root, ClassifyBlock(root), nullptr);
  return ClusterHasEnoughTextToAutosize(hypothetical_cluster, width_provider);
}

bool TextAutosizer::ClusterHasEnoughTextToAutosize(
    Cluster* cluster,
    const LayoutBlock* width_provider) {
  if (cluster->has_enough_text_to_autosize_ != kUnknownAmountOfText)
    return cluster->has_enough_text_to_autosize_ == kHasEnoughText;

  const LayoutBlock* root = cluster->root_;
  if (!width_provider)
    width_provider = ClusterWidthProvider(root);

  // TextAreas and user-modifiable areas get a free pass to autosize regardless
  // of text content.
  if (root->IsTextArea() ||
      (root->Style() &&
       root->StyleRef().UsedUserModify() != EUserModify::kReadOnly)) {
    cluster->has_enough_text_to_autosize_ = kHasEnoughText;
    return true;
  }

  if (cluster->flags_ & SUPPRESSING) {
    cluster->has_enough_text_to_autosize_ = kNotEnoughText;
    return false;
  }

  // 4 lines of text is considered enough to autosize.
  float minimum_text_length_to_autosize = WidthFromBlock(width_provider) * 4;
  if (LocalFrame* frame = document_->GetFrame()) {
    minimum_text_length_to_autosize /=
        document_->GetPage()->GetChromeClient().WindowToViewportScalar(frame,
                                                                       1);
  }

  float length = 0;
  LayoutObject* descendant = root->FirstChild();
  while (descendant) {
    if (descendant->IsLayoutBlock()) {
      if (ClassifyBlock(descendant, INDEPENDENT | SUPPRESSING)) {
        descendant = descendant->NextInPreOrderAfterChildren(root);
        continue;
      }
    } else if (descendant->IsText()) {
      // Note: Using text().LengthWithStrippedWhiteSpace() instead of
      // resolvedTextLength() because the lineboxes will not be built until
      // layout. These values can be different.
      // Note: This is an approximation assuming each character is 1em wide.
      length += To<LayoutText>(descendant)
                    ->TransformedText()
                    .LengthWithStrippedWhiteSpace() *
                descendant->StyleRef().SpecifiedFontSize();

      if (length >= minimum_text_length_to_autosize) {
        cluster->has_enough_text_to_autosize_ = kHasEnoughText;
        return true;
      }
    }
    descendant = descendant->NextInPreOrder(root);
  }

  cluster->has_enough_text_to_autosize_ = kNotEnoughText;
  return false;
}

TextAutosizer::Fingerprint TextAutosizer::GetFingerprint(
    LayoutObject* layout_object) {
  Fingerprint result = fingerprint_mapper_.Get(layout_object);
  if (!result) {
    result = ComputeFingerprint(layout_object);
    fingerprint_mapper_.Add(layout_object, result);
  }
  return result;
}

TextAutosizer::Fingerprint TextAutosizer::ComputeFingerprint(
    const LayoutObject* layout_object) {
  auto* element = DynamicTo<Element>(layout_object->GeneratingNode());
  if (!element)
    return 0;

  FingerprintSourceData data;
  if (LayoutObject* parent = ParentElementLayoutObject(layout_object))
    data.parent_hash_ = GetFingerprint(parent);

  data.qualified_name_hash_ = WTF::GetHash(element->TagQName());

  if (const ComputedStyle* style = layout_object->Style()) {
    data.packed_style_properties_ = static_cast<unsigned>(style->Direction());
    data.packed_style_properties_ |=
        (static_cast<unsigned>(style->GetPosition()) << 1);
    data.packed_style_properties_ |=
        (static_cast<unsigned>(style->UnresolvedFloating()) << 4);
    data.packed_style_properties_ |=
        (static_cast<unsigned>(style->Display()) << 7);
    const Length& width = style->Width();
    data.packed_style_properties_ |= (width.GetType() << 12);
    // packedStyleProperties effectively using 16 bits now.

    // TODO(kojii): The width can be computed from style only when it's fixed.
    // consider for adding: writing mode, padding.
    data.width_ = width.IsFixed() ? width.GetFloatValue() : .0f;
  }

  // Use nodeIndex as a rough approximation of column number
  // (it's too early to call LayoutTableCell::col).
  // FIXME: account for colspan
  if (layout_object->IsTableCell())
    data.column_ = layout_object->GetNode()->NodeIndex();

  return StringHasher::HashMemory(base::byte_span_from_ref(data));
}

TextAutosizer::Cluster* TextAutosizer::MaybeCreateCluster(LayoutBlock* block) {
  BlockFlags flags = ClassifyBloc
"""


```