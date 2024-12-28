Response:
The user wants to understand the functionality of the `layout_text.cc` file in the Chromium Blink rendering engine. I need to analyze the provided code snippet and identify its core responsibilities. Then, I must explain how these responsibilities relate to JavaScript, HTML, and CSS. I also need to provide examples of logical reasoning with hypothetical inputs and outputs, and common user/programming errors related to this functionality. Finally, for this first part of the request, I need to summarize the overall function of the code.

**Core Functionality Identification:**

- The file deals with the layout of text content within the rendering engine.
- It manages the representation of text as a `LayoutText` object.
- It handles the visual presentation of text, considering factors like styling, text transformations, and security.
- It interacts with the editing functionalities of the browser.
- It seems to be transitioning towards a new layout engine (LayoutNG), indicated by the `valid_ng_items_` flag and related methods.

**Relationship with JavaScript, HTML, and CSS:**

- **HTML:** The `LayoutText` object is directly associated with text nodes in the HTML DOM tree.
- **CSS:**  CSS properties like `font-family`, `font-size`, `color`, `text-transform`, and `visibility` directly influence how `LayoutText` renders the text.
- **JavaScript:** JavaScript can manipulate the content of text nodes, triggering updates to the associated `LayoutText` objects and their layout. JavaScript also interacts with the selection and editing functionalities, which are handled in part by this file.

**Logical Reasoning Examples:**

- **Input:** A text node in HTML with the content "hello" and CSS style `text-transform: uppercase`.
- **Processing:** The `LayoutText` object associated with this node would store the original text "hello". When rendering, it would apply the `text-transform` and display "HELLO".
- **Output:** The rendered output on the screen shows "HELLO".

- **Input:** A text input field where the user types "password". The CSS style `text-security: disc` is applied.
- **Processing:**  The `LayoutText` object would initially store the typed characters. Due to `text-security`, the `SecureTextTimer` would be involved. After a short delay, the text might be masked (e.g., displayed as bullets).
- **Output:**  The input field initially shows "password", then changes to "********".

**Common Errors:**

- Programmers might incorrectly manipulate the text content without properly updating the layout information, leading to rendering inconsistencies.
- Users might experience unexpected text transformations or masking due to CSS styles.

**Summary for Part 1:**

The `layout_text.cc` file is responsible for managing the layout and rendering of text content within the Blink rendering engine. It acts as an intermediary between the HTML text nodes and their visual representation on the screen, taking into account CSS styling, text transformations, and security settings. It also plays a crucial role in text editing and selection functionalities. The code appears to be in a state of transition towards a new layout architecture (LayoutNG).
这是 `blink/renderer/core/layout/layout_text.cc` 文件的第一部分，主要负责 **文本内容的布局和渲染**。它在 Blink 渲染引擎中扮演着核心角色，处理如何将 HTML 中的文本节点以及由 CSS 生成的文本内容转化为屏幕上可见的像素。

以下是其功能的详细归纳：

**核心功能:**

1. **文本表示:**  `LayoutText` 类是 Blink 中表示一段需要进行布局的文本的基本单元。它存储了文本内容 (`text_`) 以及相关的布局信息。
2. **样式应用:**  它接收并应用 CSS 样式 (`ComputedStyle`)，这些样式会影响文本的渲染，例如字体、大小、颜色、可见性、`text-transform` 和 `text-security` 等。
3. **文本转换与安全:**  它负责根据 CSS 的 `text-transform` 属性（如 `uppercase`, `lowercase`）转换文本，以及根据 `text-security` 属性（如密码输入框的星号显示）处理文本的显示。
4. **布局管理:**  它参与 Blink 的布局过程，特别是 inline 布局。它会创建或管理 `AbstractInlineTextBox` 对象（虽然这部分代码中尚未完全展开），这些对象代表了文本在行内的布局盒子。
5. **选择与编辑:**  它与文本的选择和编辑功能紧密相关。它提供了获取文本盒子的信息、光标位置、以及将 DOM 偏移映射到文本内容偏移的方法，这些对于实现文本选择、插入、删除等操作至关重要。
6. **辅助功能 (Accessibility):**  它会考虑辅助功能的需求，例如在文本可见性或 `inert` 状态改变时通知辅助功能对象缓存。
7. **性能优化:**  它包含一些性能优化措施，例如在样式改变时只在需要时才重新布局，以及在布局前预加载字体数据。
8. **LayoutNG 支持 (进行中):** 代码中包含一些与新的布局引擎 LayoutNG 相关的逻辑，例如 `valid_ng_items_` 标志和相关的设置和清除方法，表明 Blink 正在将文本布局迁移到 LayoutNG。
9. **内容捕获:**  它与内容捕获管理器交互，当 `LayoutText` 对象被销毁时通知管理器。
10. **密码安全:**  它包含 `SecureTextTimer` 类，用于处理密码字段的显示，即在用户输入后短时间内显示明文，然后切换到密码符号。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **关系:** `LayoutText` 对象通常与 HTML 中的 `<text>` 节点关联。当浏览器解析 HTML 时，对于文本内容会创建相应的 `LayoutText` 对象。
    * **举例:**  如果 HTML 中有 `<p>这是一段文本</p>`，那么 "这是一段文本" 这部分内容会对应一个 `LayoutText` 对象。

* **CSS:**
    * **关系:** CSS 样式规则直接影响 `LayoutText` 的渲染。
    * **举例:**
        * CSS 中设置 `p { font-size: 16px; color: blue; }` 会使得对应 `<p>` 标签内的 `LayoutText` 对象按照 16 像素大小和蓝色渲染文本。
        * CSS 中设置 `input[type="password"] { text-security: disc; }` 会导致密码输入框的 `LayoutText` 对象使用圆点或其他符号代替实际输入的字符。
        * CSS 中设置 `span { text-transform: uppercase; }` 会将 `<span>` 标签内的文本转换为大写显示。

* **JavaScript:**
    * **关系:** JavaScript 可以操作 DOM，修改文本节点的内容，从而触发 `LayoutText` 对象的更新和重新布局。JavaScript 还可以访问和操作与文本相关的属性和方法，例如获取文本的边界框。
    * **举例:**
        * JavaScript 代码 `document.querySelector('p').textContent = '新的文本';` 会改变 `<p>` 标签内的文本内容，导致对应的 `LayoutText` 对象更新。
        * JavaScript 可以使用 `getBoundingClientRect()` 等方法获取 `LayoutText` 对象在屏幕上的位置和大小信息。
        * JavaScript 可以通过程序创建包含文本内容的 DOM 节点，这些节点在渲染时也会创建相应的 `LayoutText` 对象。

**逻辑推理的假设输入与输出:**

假设有以下 HTML 和 CSS：

```html
<p id="myText" style="text-transform: uppercase;">hello</p>
```

**假设输入:**  渲染引擎处理到 `id="myText"` 的 `<p>` 元素。

**处理过程:**

1. 创建一个 `LayoutBlock` 对象来表示 `<p>` 元素。
2. 创建一个 `LayoutText` 对象来表示文本内容 "hello"。
3. 将 CSS 样式 `text-transform: uppercase;` 应用到 `LayoutText` 对象。
4. `LayoutText` 对象内部会根据 `text-transform` 的值将 "hello" 转换为 "HELLO"。

**假设输出:**  在屏幕上渲染出大写的 "HELLO"。

**用户或编程常见的使用错误举例:**

1. **直接修改文本节点的值但不触发布局更新:**  如果开发者使用某些底层 API 直接修改了文本节点的值，但没有通知 Blink 重新布局，可能会导致渲染结果与实际 DOM 状态不一致。例如，在某些特殊情况下绕过了 Blink 的正常 DOM 更新机制。

2. **错误理解 `text-security` 的作用范围:**  开发者可能错误地认为设置了 `text-security` 就能完全阻止用户复制粘贴密码，但实际上这主要控制的是屏幕上的显示效果，用户仍然可以通过浏览器开发者工具或其他方式获取到原始文本。

3. **在 JavaScript 中手动计算文本尺寸而不考虑 CSS 样式:**  开发者可能尝试使用 JavaScript 手动计算文本的宽度和高度，但如果没有充分考虑 CSS 样式（例如字体、字号、行高等），计算结果可能会与浏览器实际渲染的尺寸不符。

4. **过度依赖文本内容长度进行布局判断:**  开发者可能会直接使用 `LayoutText` 的文本长度进行某些布局判断，而忽略了文本可能因为 `text-transform` 或其他样式发生变化，导致渲染后的视觉长度与原始文本长度不一致。

**总结 (针对第一部分):**

`blink/renderer/core/layout/layout_text.cc` 文件的第一部分定义了 `LayoutText` 类，它是 Blink 渲染引擎中负责文本内容布局和渲染的核心组件。它处理文本内容的存储、CSS 样式的应用（包括文本转换和安全处理）、参与 inline 布局过程，并与选择、编辑和辅助功能等模块进行交互。代码中也体现了向新的布局引擎 LayoutNG 迁移的趋势。 该文件是连接 HTML 文本内容、CSS 样式以及最终屏幕渲染的关键桥梁。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_text.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * (C) 1999 Lars Knoll (knoll@kde.org)
 * (C) 2000 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007 Apple Inc. All rights reserved.
 * Copyright (C) 2006 Andrew Wellington (proton@wiretapped.net)
 * Copyright (C) 2006 Graham Dennis (graham.dennis@gmail.com)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/layout_text.h"

#include <algorithm>

#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/content_capture/content_capture_manager.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/dom/text_diff_range.h"
#include "third_party/blink/renderer/core/editing/bidi_adjustment.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/inline_box_position.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_rect.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/abstract_inline_text_box.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_span.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/platform/fonts/character_range.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/text/character.h"
#include "third_party/blink/renderer/platform/text/hyphenation.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/text_offset_map.h"
#include "ui/gfx/geometry/quad_f.h"

namespace blink {

namespace {

struct SameSizeAsLayoutText : public LayoutObject {
  uint32_t bitfields : 4;
  DOMNodeId node_id;
  String text;
  LogicalOffset previous_starting_point;
  InlineItemSpan inline_items;
  wtf_size_t first_fragment_item_index_;
};

ASSERT_SIZE(LayoutText, SameSizeAsLayoutText);

class SecureTextTimer;
typedef HeapHashMap<WeakMember<const LayoutText>, Member<SecureTextTimer>>
    SecureTextTimerMap;
static SecureTextTimerMap& GetSecureTextTimers() {
  DEFINE_STATIC_LOCAL(const Persistent<SecureTextTimerMap>, map,
                      (MakeGarbageCollected<SecureTextTimerMap>()));
  return *map;
}

class SecureTextTimer final : public GarbageCollected<SecureTextTimer>,
                              public TimerBase {
 public:
  explicit SecureTextTimer(LayoutText* layout_text)
      : TimerBase(layout_text->GetDocument().GetTaskRunner(
            TaskType::kUserInteraction)),
        layout_text_(layout_text),
        last_typed_character_offset_(-1) {}

  static SecureTextTimer* ActiveInstanceFor(const LayoutText* layout_text) {
    auto it = GetSecureTextTimers().find(layout_text);
    if (it != GetSecureTextTimers().end()) {
      SecureTextTimer* secure_text_timer = it->value;
      if (secure_text_timer && secure_text_timer->IsActive()) {
        return secure_text_timer;
      }
    }
    return nullptr;
  }

  void RestartWithNewText(unsigned last_typed_character_offset) {
    last_typed_character_offset_ = last_typed_character_offset;
    if (Settings* settings = layout_text_->GetDocument().GetSettings()) {
      StartOneShot(base::Seconds(settings->GetPasswordEchoDurationInSeconds()),
                   FROM_HERE);
    }
  }
  void Invalidate() { last_typed_character_offset_ = -1; }
  unsigned LastTypedCharacterOffset() { return last_typed_character_offset_; }

  void Trace(Visitor* visitor) const { visitor->Trace(layout_text_); }

 private:
  void Fired() override {
    DCHECK(GetSecureTextTimers().Contains(layout_text_));
    // Forcing setting text as it may be masked later
    layout_text_->ForceSetText(layout_text_->TransformedText());
  }

  Member<LayoutText> layout_text_;
  int last_typed_character_offset_;
};

class SelectionDisplayItemClient
    : public GarbageCollected<SelectionDisplayItemClient>,
      public DisplayItemClient {
 public:
  String DebugName() const final { return "Selection"; }
  void Trace(Visitor* visitor) const override {
    DisplayItemClient::Trace(visitor);
  }
};

using SelectionDisplayItemClientMap =
    HeapHashMap<WeakMember<const LayoutText>,
                Member<SelectionDisplayItemClient>>;
SelectionDisplayItemClientMap& GetSelectionDisplayItemClientMap() {
  DEFINE_STATIC_LOCAL(Persistent<SelectionDisplayItemClientMap>, map,
                      (MakeGarbageCollected<SelectionDisplayItemClientMap>()));
  return *map;
}

}  // anonymous namespace

LayoutText::LayoutText(Node* node, String str)
    : LayoutObject(node),
      valid_ng_items_(false),
      has_bidi_control_items_(false),
      is_text_fragment_(false),
      has_abstract_inline_text_box_(false),
      text_(std::move(str)) {
  DCHECK(text_);
  DCHECK(!node || !node->IsDocumentNode());

  if (node)
    GetFrameView()->IncrementVisuallyNonEmptyCharacterCount(text_.length());
}

void LayoutText::Trace(Visitor* visitor) const {
  visitor->Trace(inline_items_);
  LayoutObject::Trace(visitor);
}

LayoutText* LayoutText::CreateEmptyAnonymous(Document& doc,
                                             const ComputedStyle* style) {
  auto* text = MakeGarbageCollected<LayoutText>(nullptr, StringImpl::empty_);
  text->SetDocumentForAnonymous(&doc);
  text->SetStyle(style);
  return text;
}

bool LayoutText::IsWordBreak() const {
  NOT_DESTROYED();
  return false;
}

void LayoutText::StyleWillChange(StyleDifference diff,
                                 const ComputedStyle& new_style) {
  NOT_DESTROYED();

  if (const ComputedStyle* current_style = Style()) {
    // Process accessibility for style changes that affect text.
    if (current_style->Visibility() != new_style.Visibility() ||
        current_style->IsInert() != new_style.IsInert()) {
      if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
        cache->StyleChanged(this, /*visibility_or_inertness_changed*/ true);
      }
    }
  }
}

void LayoutText::StyleDidChange(StyleDifference diff,
                                const ComputedStyle* old_style) {
  NOT_DESTROYED();
  // There is no need to ever schedule paint invalidations from a style change
  // of a text run, since we already did this for the parent of the text run.
  // We do have to schedule layouts, though, since a style change can force us
  // to need to relayout.
  if (diff.NeedsFullLayout()) {
    SetNeedsLayoutAndIntrinsicWidthsRecalc(
        layout_invalidation_reason::kStyleChange);
  }

  const ComputedStyle& new_style = StyleRef();
  ETextTransform old_transform =
      old_style ? old_style->TextTransform() : ETextTransform::kNone;
  ETextSecurity old_security =
      old_style ? old_style->TextSecurity() : ETextSecurity::kNone;
  if (old_transform != new_style.TextTransform() ||
      old_security != new_style.TextSecurity()) {
    TransformAndSecureOriginalText();
  } else if (old_transform == new_style.TextTransform() &&
             new_style.TextTransform() != ETextTransform::kNone &&
             old_style->Locale() != new_style.Locale()) {
    TransformAndSecureOriginalText();
  }

  // This is an optimization that kicks off font load before layout.
  if (!TransformedText().ContainsOnlyWhitespaceOrEmpty()) {
    new_style.GetFont().WillUseFontData(TransformedText());
  }

  TextAutosizer* text_autosizer = GetDocument().GetTextAutosizer();
  if (!old_style && text_autosizer)
    text_autosizer->Record(this);

  if (diff.NeedsReshape()) {
    valid_ng_items_ = false;
    SetNeedsCollectInlines();
  }

  SetHorizontalWritingMode(new_style.IsHorizontalWritingMode());
}

void LayoutText::RemoveAndDestroyTextBoxes() {
  NOT_DESTROYED();
  if (!DocumentBeingDestroyed()) {
    if (Parent()) {
      Parent()->DirtyLinesFromChangedChild(this);
    }
    if (FirstInlineFragmentItemIndex()) {
      DetachAbstractInlineTextBoxesIfNeeded();
      FragmentItems::LayoutObjectWillBeDestroyed(*this);
      ClearFirstInlineFragmentItemIndex();
    }
  } else if (FirstInlineFragmentItemIndex()) {
    DetachAbstractInlineTextBoxesIfNeeded();
    ClearFirstInlineFragmentItemIndex();
  }
  DeleteTextBoxes();
}

void LayoutText::WillBeDestroyed() {
  NOT_DESTROYED();

  if (SecureTextTimer* timer = GetSecureTextTimers().Take(this))
    timer->Stop();

  GetSelectionDisplayItemClientMap().erase(this);

  if (node_id_ != kInvalidDOMNodeId) {
    if (auto* manager = GetOrResetContentCaptureManager())
      manager->OnLayoutTextWillBeDestroyed(*GetNode());
    node_id_ = kInvalidDOMNodeId;
  }

  RemoveAndDestroyTextBoxes();
  LayoutObject::WillBeDestroyed();
  valid_ng_items_ = false;

#if DCHECK_IS_ON()
  if (IsInLayoutNGInlineFormattingContext())
    DCHECK(!first_fragment_item_index_);
#endif
}

void LayoutText::DeleteTextBoxes() {
  NOT_DESTROYED();
  DetachAbstractInlineTextBoxesIfNeeded();
}

void LayoutText::DetachAbstractInlineTextBoxes() {
  NOT_DESTROYED();
  // TODO(layout-dev): Because We should call |WillDestroy()| once for
  // associated fragments, when you reuse fragments, you should construct
  // AbstractInlineTextBox for them.
  DCHECK(has_abstract_inline_text_box_);
  has_abstract_inline_text_box_ = false;
  // TODO(yosin): Make sure we call this function within valid containg block
  // of |this|.
  InlineCursor cursor;
  for (cursor.MoveTo(*this); cursor; cursor.MoveToNextForSameLayoutObject())
    AbstractInlineTextBox::WillDestroy(cursor);
}

void LayoutText::ClearFirstInlineFragmentItemIndex() {
  NOT_DESTROYED();
  CHECK(IsInLayoutNGInlineFormattingContext()) << *this;
  DetachAbstractInlineTextBoxesIfNeeded();
  first_fragment_item_index_ = 0u;
}

void LayoutText::SetFirstInlineFragmentItemIndex(wtf_size_t index) {
  NOT_DESTROYED();
  CHECK(IsInLayoutNGInlineFormattingContext());
  // TODO(yosin): Call |AbstractInlineTextBox::WillDestroy()|.
  DCHECK_NE(index, 0u);
  DetachAbstractInlineTextBoxesIfNeeded();
  // Changing the first fragment item index causes
  // LayoutText::FirstAbstractInlineTextBox to return a box,
  // so notify the AX object for this LayoutText that it might need to
  // recompute its text child.
  if (index > 0 && first_fragment_item_index_ == 0) {
    if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
      cache->TextChanged(this);
    }
  }
  first_fragment_item_index_ = index;
}

void LayoutText::InLayoutNGInlineFormattingContextWillChange(bool new_value) {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext())
    ClearFirstInlineFragmentItemIndex();
  else
    DeleteTextBoxes();

  // Because there are no inline boxes associated to this text, we should not
  // have abstract inline text boxes too.
  DCHECK(!has_abstract_inline_text_box_);
}

Vector<LayoutText::TextBoxInfo> LayoutText::GetTextBoxInfo() const {
  NOT_DESTROYED();
  // This function may kick the layout (e.g., |LocalRect()|), but Inspector may
  // call this function outside of the layout phase.
  FontCachePurgePreventer fontCachePurgePreventer;

  Vector<TextBoxInfo> results;
  if (const OffsetMapping* mapping = GetOffsetMapping()) {
    bool in_hidden_for_paint = false;
    InlineCursor cursor;
    cursor.MoveTo(*this);
    for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
      // TODO(yosin): We should introduce |FragmentItem::IsTruncated()| to
      // skip them instead of using |IsHiddenForPaint()| with ordering of
      // fragments.
      if (cursor.Current().IsHiddenForPaint()) {
        in_hidden_for_paint = true;
      } else if (in_hidden_for_paint) {
        // Because of we finished original fragments (not painted), we should
        // ignore truncated fragments (actually painted).
        break;
      }
      // We don't put generated texts, e.g. ellipsis, hyphen, etc. not in text
      // content, into results. Note: CSS "content" aren't categorized this.
      if (cursor.Current().IsLayoutGeneratedText())
        continue;
      // When the corresponding DOM range contains collapsed whitespaces, NG
      // produces one fragment but legacy produces multiple text boxes broken at
      // collapsed whitespaces. We break the fragment at collapsed whitespaces
      // to match the legacy output.
      const TextOffsetRange offset = cursor.Current().TextOffset();
      for (const OffsetMappingUnit& unit :
           mapping->GetMappingUnitsForTextContentOffsetRange(offset.start,
                                                             offset.end)) {
        DCHECK_EQ(unit.GetLayoutObject(), this);
        if (unit.GetType() == OffsetMappingUnitType::kCollapsed) {
          continue;
        }
        // [clamped_start, clamped_end] of |fragment| matches a legacy text box.
        const unsigned clamped_start =
            std::max(unit.TextContentStart(), offset.start);
        const unsigned clamped_end =
            std::min(unit.TextContentEnd(), offset.end);
        DCHECK_LT(clamped_start, clamped_end);
        const unsigned box_length = clamped_end - clamped_start;

        // Compute rect of the legacy text box.
        PhysicalRect rect = cursor.CurrentLocalRect(clamped_start, clamped_end);
        rect.offset += cursor.Current().OffsetInContainerFragment();

        // Compute start of the legacy text box.
        if (unit.AssociatedNode()) {
          // In case of |text_| comes from DOM node.
          if (const std::optional<unsigned> box_start = CaretOffsetForPosition(
                  mapping->GetLastPosition(clamped_start))) {
            results.push_back(TextBoxInfo{rect, *box_start, box_length});
            continue;
          }
          NOTREACHED();
        }
        // Handle CSS generated content, e.g. ::before/::after
        const OffsetMappingUnit* const mapping_unit =
            mapping->GetLastMappingUnit(clamped_start);
        DCHECK(mapping_unit) << this << " at " << clamped_start;
        const unsigned dom_offset =
            mapping_unit->ConvertTextContentToLastDOMOffset(clamped_start);
        results.push_back(TextBoxInfo{rect, dom_offset, box_length});
      }
    }
    return results;
  }

  return results;
}

bool LayoutText::HasInlineFragments() const {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext())
    return first_fragment_item_index_;
  return false;
}

String LayoutText::OriginalText() const {
  NOT_DESTROYED();
  auto* text_node = DynamicTo<Text>(GetNode());
  return text_node ? text_node->data() : String();
}

unsigned LayoutText::OriginalTextLength() const {
  NOT_DESTROYED();
  DCHECK(!IsBR());
  return OriginalText().length();
}

String LayoutText::PlainText() const {
  NOT_DESTROYED();
  if (GetNode()) {
    if (const OffsetMapping* mapping = GetOffsetMapping()) {
      StringBuilder result;
      for (const OffsetMappingUnit& unit :
           mapping->GetMappingUnitsForNode(*GetNode())) {
        result.Append(
            StringView(mapping->GetText(), unit.TextContentStart(),
                       unit.TextContentEnd() - unit.TextContentStart()));
      }
      return result.ToString();
    }
    // TODO(crbug.com/591099): Remove this branch when legacy layout is removed.
    return blink::PlainText(EphemeralRange::RangeOfContents(*GetNode()));
  }

  // FIXME: this is just a stopgap until TextIterator is adapted to support
  // generated text.
  StringBuilder plain_text_builder;
  unsigned last_end_offset = 0;
  for (const auto& text_box : GetTextBoxInfo()) {
    if (!text_box.dom_length)
      continue;

    // Append a trailing space of the last |text_box| if it was collapsed.
    const unsigned end_offset = text_box.dom_start_offset + text_box.dom_length;
    if (last_end_offset && text_box.dom_start_offset > last_end_offset &&
        !IsASCIISpace(text_[end_offset - 1])) {
      plain_text_builder.Append(kSpaceCharacter);
    }
    last_end_offset = end_offset;

    String text =
        text_.Substring(text_box.dom_start_offset, text_box.dom_length)
            .SimplifyWhiteSpace(WTF::kDoNotStripWhiteSpace);
    plain_text_builder.Append(text);
  }
  return plain_text_builder.ToString();
}

template <typename PhysicalRectCollector>
void LayoutText::CollectLineBoxRects(const PhysicalRectCollector& yield,
                                     ClippingOption option) const {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext()) {
    InlineCursor cursor;
    cursor.MoveTo(*this);
    for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
      if (option != ClippingOption::kNoClipping) [[unlikely]] {
        DCHECK_EQ(option, ClippingOption::kClipToEllipsis);
        if (cursor.Current().IsHiddenForPaint())
          continue;
      }
      yield(cursor.Current().RectInContainerFragment());
    }
    return;
  }
}

void LayoutText::QuadsInAncestorInternal(Vector<gfx::QuadF>& quads,
                                         const LayoutBoxModelObject* ancestor,
                                         MapCoordinatesFlags mode) const {
  NOT_DESTROYED();
  CollectLineBoxRects([this, &quads, ancestor, mode](const PhysicalRect& r) {
    quads.push_back(LocalRectToAncestorQuad(r, ancestor, mode));
  });
}

bool LayoutText::MapDOMOffsetToTextContentOffset(const OffsetMapping& mapping,
                                                 unsigned* start,
                                                 unsigned* end) const {
  NOT_DESTROYED();
  DCHECK_LE(*start, *end);

  // Adjust |start| to the next non-collapsed offset if |start| is collapsed.
  Position start_position =
      PositionForCaretOffset(std::min(*start, OriginalTextLength()));
  Position non_collapsed_start_position =
      mapping.StartOfNextNonCollapsedContent(start_position);

  // If all characters after |start| are collapsed, adjust to the last
  // non-collapsed offset.
  if (non_collapsed_start_position.IsNull()) {
    non_collapsed_start_position =
        mapping.EndOfLastNonCollapsedContent(start_position);

    // If all characters are collapsed, return false.
    if (non_collapsed_start_position.IsNull())
      return false;
  }

  *start = mapping.GetTextContentOffset(non_collapsed_start_position).value();

  // Adjust |end| to the last non-collapsed offset if |end| is collapsed.
  Position end_position =
      PositionForCaretOffset(std::min(*end, OriginalTextLength()));
  Position non_collpased_end_position =
      mapping.EndOfLastNonCollapsedContent(end_position);

  // Note: `non_collpased_{start,end}_position}` can be position before/after
  // non-`Text` node. See http://crbug.com/1389193
  if (non_collpased_end_position.IsNull() ||
      non_collpased_end_position <= non_collapsed_start_position) {
    // If all characters in the range are collapsed, make |end| = |start|.
    *end = *start;
  } else {
    *end = mapping.GetTextContentOffset(non_collpased_end_position).value();
  }

  DCHECK_LE(*start, *end);
  return true;
}

void LayoutText::AbsoluteQuadsForRange(Vector<gfx::QuadF>& quads,
                                       unsigned start,
                                       unsigned end) const {
  NOT_DESTROYED();
  // Work around signed/unsigned issues. This function takes unsigneds, and is
  // often passed UINT_MAX to mean "all the way to the end". InlineTextBox
  // coordinates are unsigneds, so changing this function to take ints causes
  // various internal mismatches. But selectionRect takes ints, and passing
  // UINT_MAX to it causes trouble. Ideally we'd change selectionRect to take
  // unsigneds, but that would cause many ripple effects, so for now we'll just
  // clamp our unsigned parameters to INT_MAX.
  DCHECK(end == UINT_MAX || end <= INT_MAX);
  DCHECK_LE(start, static_cast<unsigned>(INT_MAX));
  start = std::min(start, static_cast<unsigned>(INT_MAX));
  end = std::min(end, static_cast<unsigned>(INT_MAX));

  if (auto* mapping = GetOffsetMapping()) {
    if (!MapDOMOffsetToTextContentOffset(*mapping, &start, &end))
      return;

    const auto* const text_combine = DynamicTo<LayoutTextCombine>(Parent());

    // We don't want to add collapsed (i.e., start == end) quads from text
    // fragments that intersect [start, end] only at the boundary, unless they
    // are the only quads found. For example, when we have
    // - text fragments: ABC  DEF  GHI
    // - text offsets:   012  345  678
    // and input range [3, 6], since fragment "DEF" gives non-collapsed quad,
    // we no longer add quads from "ABC" and "GHI" since they are collapsed.
    // TODO(layout-dev): This heuristic doesn't cover all cases, as we return
    // 2 collapsed quads (instead of 1) for range [3, 3] in the above example.
    bool found_non_collapsed_quad = false;
    Vector<gfx::QuadF, 1> collapsed_quads_candidates;

    // Find fragments that have text for the specified range.
    DCHECK_LE(start, end);
    InlineCursor cursor;
    bool is_last_end_included = false;
    for (cursor.MoveTo(*this); cursor; cursor.MoveToNextForSameLayoutObject()) {
      const FragmentItem& item = *cursor.Current();
      DCHECK(item.IsText());
      bool is_collapsed = false;
      PhysicalRect rect;
      if (!item.IsGeneratedText()) {
        const TextOffsetRange& offset = item.TextOffset();
        if (start > offset.end || end < offset.start) {
          is_last_end_included = false;
          continue;
        }
        is_last_end_included = offset.end <= end;
        const unsigned clamped_start = std::max(start, offset.start);
        const unsigned clamped_end = std::min(end, offset.end);
        rect = cursor.CurrentLocalRect(clamped_start, clamped_end);
        is_collapsed = clamped_start >= clamped_end;
      } else if (item.IsEllipsis()) {
        continue;
      } else {
        // Hyphens. Include if the last end was included.
        if (!is_last_end_included)
          continue;
        rect = item.LocalRect();
      }
      if (text_combine) [[unlikely]] {
        rect = text_combine->AdjustRectForBoundingBox(rect);
      }
      gfx::QuadF quad;
      if (const SvgFragmentData* svg_data = item.GetSvgFragmentData()) {
        gfx::RectF float_rect(rect);
        float_rect.Offset(svg_data->rect.OffsetFromOrigin());
        quad = item.BuildSvgTransformForBoundingBox().MapQuad(
            gfx::QuadF(float_rect));
        const float scaling_factor = item.SvgScalingFactor();
        quad.Scale(1 / scaling_factor, 1 / scaling_factor);
        quad = LocalToAbsoluteQuad(quad);
      } else {
        rect.Move(cursor.CurrentOffsetInBlockFlow());
        quad = LocalRectToAbsoluteQuad(rect);
      }
      if (!is_collapsed) {
        quads.push_back(quad);
        found_non_collapsed_quad = true;
      } else {
        collapsed_quads_candidates.push_back(quad);
      }
    }
    if (!found_non_collapsed_quad)
      quads.AppendVector(collapsed_quads_candidates);
    return;
  }
}

gfx::RectF LayoutText::LocalBoundingBoxRectForAccessibility() const {
  NOT_DESTROYED();
  gfx::RectF result;
  CollectLineBoxRects(
      [&result](const PhysicalRect& rect) { result.Union(gfx::RectF(rect)); },
      kClipToEllipsis);
  return result;
}

PositionWithAffinity LayoutText::PositionForPoint(
    const PhysicalOffset& point) const {
  NOT_DESTROYED();
  // NG codepath requires |kPrePaintClean|.
  // |SelectionModifier| calls this only in legacy codepath.
  DCHECK(!IsLayoutNGObject() || GetDocument().Lifecycle().GetState() >=
                                    DocumentLifecycle::kPrePaintClean);

  if (IsInLayoutNGInlineFormattingContext()) {
    // Because of Texts in "position:relative" can be outside of line box, we
    // attempt to find a fragment containing |point|.
    // See All/LayoutViewHitTestTest.HitTestHorizontal/* and
    // All/LayoutViewHitTestTest.HitTestVerticalRL/*
    InlineCursor cursor;
    cursor.MoveTo(*this);
    const LayoutBlockFlow* containing_block_flow = cursor.GetLayoutBlockFlow();
    DCHECK(containing_block_flow);
    PhysicalOffset point_in_contents = point;
    if (containing_block_flow->IsScrollContainer()) {
      point_in_contents += PhysicalOffset(
          containing_block_flow->PixelSnappedScrolledContentOffset());
    }
    const auto* const text_combine = DynamicTo<LayoutTextCombine>(Parent());
    const PhysicalBoxFragment* container_fragment = nullptr;
    PhysicalOffset point_in_container_fragment;
    DCHECK(!IsSVGInlineText());
    for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
      DCHECK(&cursor.ContainerFragment());
      if (container_fragment != &cursor.ContainerFragment()) {
        container_fragment = &cursor.ContainerFragment();
        point_in_container_fragment =
            point_in_contents - container_fragment->OffsetFromOwnerLayoutBox();
        if (text_combine) [[unlikely]] {
          point_in_container_fragment =
              text_combine->AdjustOffsetForHitTest(point_in_container_fragment);
        }
      }
      if (!ToEnclosingRect(cursor.Current().RectInContainerFragment())
               .Contains(ToFlooredPoint(point_in_container_fragment)))
        continue;
      if (auto position_with_affinity =
              cursor.PositionForPointInChild(point_in_container_fragment)) {
        // Note: Due by Bidi adjustment, |position_with_affinity| isn't
        // relative to this.
        return AdjustForEditingBoundary(position_with_affinity);
      }
    }
    // Try for leading and trailing spaces between lines.
    return containing_block_flow->PositionForPoint(point);
  }

  return CreatePositionWithAffinity(0);
}

PhysicalRect LayoutText::LocalCaretRect(int caret_offset) const {
  NOT_DESTROYED();
  return PhysicalRect();
}

bool LayoutText::IsAllCollapsibleWhitespace() const {
  NOT_DESTROYED();
  unsigned length = text_.length();
  if (text_.Is8Bit()) {
    for (unsigned i = 0; i < length; ++i) {
      if (!StyleRef().IsCollapsibleWhiteSpace(text_.Characters8()[i])) {
        return false;
      }
    }
    return true;
  }
  for (unsigned i = 0; i < length; ++i) {
    if (!StyleRef().IsCollapsibleWhiteSpace(text_.Characters16()[i])) {
      return false;
    }
  }
  return true;
}

UChar32 LayoutText::FirstCharacterAfterWhitespaceCollapsing() const {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext()) {
    InlineCursor cursor;
    cursor.MoveTo(*this);
    if (cursor) {
      const StringView text = cursor.Current().Text(cursor);
      return text.length() ? text.CodepointAt(0) : 0;
    }
  }
  return 0;
}

UChar32 LayoutText::LastCharacterAfterWhitespaceCollapsing() const {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext()) {
    InlineCursor cursor;
    cursor.MoveTo(*this);
    if (cursor) {
      const StringView text = cursor.Current().Text(cursor);
      return text.length() ? text.CodepointAt(text.length() - 1) : 0;
    }
  }
  return 0;
}

PhysicalOffset LayoutText::FirstLineBoxTopLeft() const {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext()) {
    // TODO(kojii): Some clients call this against dirty-tree, but NG fragments
    // are not safe to read for dirty-tree. crbug.com/963103
    if (!IsFirstInlineFragmentSafe()) [[unlikely]] {
      return PhysicalOffset();
    }
    InlineCursor cursor;
    cursor.MoveTo(*this);
    return cursor ? cursor.Current().OffsetInContainerFragment()
                  : PhysicalOffset();
  }
  return PhysicalOffset();
}

void LayoutText::LogicalStartingPointAndHeight(
    LogicalOffset& logical_starting_point,
    LayoutUnit& logical_height) const {
  NOT_DESTROYED();
  if (IsInLayoutNGInlineFormattingContext()) {
    InlineCursor cursor;
    cursor.MoveTo(*this);
    if (!cursor)
      return;
    PhysicalOffset physical_offset =
        cursor.Current().OffsetInContainerFragment();
    if (StyleRef().GetWritingDirection().IsHorizontalLtr()) {
      cursor.MoveToLastForSameLayoutObject();
      logical_height = cursor.Current().RectInContainerFragment().Bottom() -
                       physical_offset.top;
      logical_starting_point = {physical_offset.left, physical_offset.top};
      return;
    }
    PhysicalSize outer_size = ContainingBlock()->Size();
    logical_starting_point = physical_offset.ConvertToLogical(
        StyleRef().GetWritingDirection(), outer_size, cursor.Current().Size());
    cursor.MoveToLastForSameLayoutObject();
    PhysicalRect last_physical_rect =
        cursor.Current().RectInContainerFragment();
    LogicalOffset logical_ending_point =
        WritingModeConverter(StyleRef().GetWritingDirection(), outer_size)
            .ToLogical(last_physical_rect)
            .EndOffset();
    logical_height =
        logical_ending_point.block_offset - logical_starting_point.block_offset;
  }
}

void LayoutText::SetTextWithOffset(String text, const TextDiffRange& diff) {
  NOT_DESTROYED();
  if (text_ == text) {
    return;
  }

  if (InlineNode::SetTextWithOffset(this, text, diff)) {
    DCHECK(!NeedsCollectInlines());
    // Prevent |TextDidChange()| to propagate |NeedsCollectInlines|
    SetNeedsCollectInlines(true);
    TextDidChange();
    valid_ng_items_ = true;
    ClearNeedsCollectInlines();
    return;
  }

  // If the text node is empty, dirty the line where new text will be inserted.
  if (!HasInlineFragments() && Parent()) {
    Parent()->DirtyLinesFromChangedChild(this);
  }

  ForceSetText(std::move(text));

  // TODO(layout-dev): Invalidation is currently all or nothing in LayoutNG,
  // this is probably fine for InlineItem reuse as recreating the individual
  // items is relatively cheap. If partial relayout performance improvement are
  // needed partial re-shapes are likely to be sufficient. Revisit as needed.
  valid_ng_items_ = false;
}

void LayoutText::TransformAndSecureOriginalText() {
  NOT_DESTROYED();
  if (String text_to_transform = OriginalText()) {
    ForceSetText(std::move(text_to_transform));
  }
}

static inline bool IsInlineFlowOrEmptyText(const LayoutObject* o) {
  if (o->IsLayoutInline())
    return true;
  if (!o->IsText())
    return 
"""


```