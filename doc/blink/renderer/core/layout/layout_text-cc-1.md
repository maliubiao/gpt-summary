Response:
The user is asking for a summary of the functionality of the `LayoutText` class in the Chromium Blink rendering engine, based on the provided source code. I need to identify the core responsibilities of this class, and if/how it interacts with web technologies like JavaScript, HTML, and CSS. I also need to identify any logical reasoning within the code and common user/programming errors it might address.

Here's a breakdown of how to approach this:

1. **Identify Core Responsibilities:** Read through the code and look for methods that indicate the class's main functions. Keywords like `SetText`, `TransformText`, `SecureText`, `Layout`, `Paint`, `Selection`, and `Caret` are good indicators.

2. **Analyze Interactions with Web Technologies:**
    * **HTML:**  Consider how `LayoutText` represents text content within the DOM. Look for methods that relate to nodes or text nodes.
    * **CSS:**  Examine how the class handles styling. The `ComputedStyle` and methods like `ApplyTextTransform` and `TextSecurity` are key.
    * **JavaScript:**  Think about how JavaScript might interact with or modify text content, potentially triggering updates in `LayoutText`. The code itself might not directly call JS, but its functions support features that JS can manipulate.

3. **Identify Logical Reasoning:** Look for conditional statements (if/else), loops, and calculations. Try to infer the input and output of these logical blocks. For example, the `SecureText` function clearly takes plaintext and a mask as input and outputs masked text and an offset map.

4. **Identify Common Errors:** Look for checks, assertions (`DCHECK`), and error handling mechanisms. Consider what kinds of incorrect usage or data might cause issues that the code attempts to prevent. For example, the checks around `text_offset` in `ContainsCaretOffset` suggest potential issues with out-of-bounds access.

5. **Structure the Summary:** Organize the findings into logical categories. Start with a high-level overview, then delve into specifics like text manipulation, layout, painting, selection, and caret handling.

**Pre-computation and Pre-analysis (Mental Walkthrough):**

* **Text Storage and Manipulation:** The class clearly stores and manipulates text content. It handles transformations like `text-transform` and security masking.
* **Layout Integration:**  It's part of the layout process, influencing how text is rendered on the screen. Methods like `SetNeedsLayout` confirm this.
* **Painting:**  The `InvalidatePaint` method and interaction with `DisplayItemClient` indicate its role in the rendering pipeline.
* **Selection and Caret:**  Methods for handling selections (`LocalSelectionVisualRect`, `IsSelected`) and caret positioning (`PositionForCaretOffset`, `CaretMinOffset`, `CaretMaxOffset`) are present.
* **Bidirectional Text:** The presence of `has_bidi_control_items_` suggests handling of right-to-left text.
* **LayoutNG:** Mentions of `IsInLayoutNGInlineFormattingContext` indicate its integration with the LayoutNG rendering engine.

By following these steps, I can generate a comprehensive and accurate summary of the `LayoutText` class's functionality.
Based on the provided code snippet for `blink/renderer/core/layout/layout_text.cc`, here's a summary of its functionalities, focusing on its relationship with JavaScript, HTML, CSS, logical reasoning, and potential user errors:

**Core Functionalities of `LayoutText`:**

* **Represents and Manages Text Content:** This class is responsible for holding and manipulating the actual text content within a layout object. It stores the text and provides methods to access and modify it.
* **Text Transformation and Security:** It handles CSS text transformations (like `uppercase`, `lowercase`, `capitalize`) and text security features (like password masking using circles, discs, or squares).
* **Integration with Layout Engine:** It plays a crucial role in the layout process, determining how text is arranged and rendered on the screen. It interacts with other layout objects and contributes to the calculation of element dimensions.
* **Selection and Caret Handling:** It provides methods for determining the position of the caret within the text, calculating selection rectangles, and understanding the boundaries of selectable content.
* **Invalidation and Updates:**  It manages the invalidation of its layout and paint when the text content or styling changes, ensuring the rendering is up-to-date.
* **Interaction with Accessibility:** It notifies the accessibility tree when the text content changes.
* **Interaction with Content Capture:** It can notify a content capture manager about text changes.
* **LayoutNG Integration:** The code shows clear integration with the LayoutNG rendering engine, utilizing concepts like `FragmentItem` and `InlineCursor`.

**Relationship with JavaScript, HTML, and CSS:**

* **HTML:**  The `LayoutText` object directly corresponds to text content within HTML elements. When HTML text content is parsed, a corresponding `LayoutText` object is created to represent it in the render tree.
    * **Example:**  Consider the HTML `<div>Hello World</div>`. The text "Hello World" would be represented by a `LayoutText` object within the layout tree for this `div`.
* **CSS:** CSS styles directly influence how `LayoutText` behaves and renders.
    * **`text-transform`:** The `ApplyTextTransform` method directly applies the CSS `text-transform` property.
        * **Example:** If the CSS rule is `text-transform: uppercase;`, the `ApplyTextTransform` method would convert "hello" to "HELLO".
    * **`text-security`:** The `SecureText` method and the switch statement based on `style->TextSecurity()` handle the CSS `text-security` property.
        * **Example:** If the CSS rule is `text-security: disc;`, the text "password" might be rendered as "●●●●●●●●".
    * **Font Properties:**  While not explicitly shown in this snippet, changes in font properties would trigger `InvalidateSubtreeLayoutForFontUpdates`, leading to a re-layout.
* **JavaScript:** JavaScript can indirectly affect `LayoutText` through DOM manipulation.
    * **Example:** If JavaScript code modifies the `textContent` of an HTML element, the corresponding `LayoutText` object will be updated via the `SetTextIfNeeded` or `ForceSetText` methods. This change will then trigger layout and paint updates.
    * **Selection API:** JavaScript's Selection API interacts with the methods in `LayoutText` related to caret position and selection boundaries.

**Logical Reasoning with Assumptions, Inputs, and Outputs:**

* **`PreviousCharacter()`:**
    * **Assumption:**  We need to find the character immediately preceding the current `LayoutText` object in the rendering order.
    * **Input:** The current `LayoutText` object.
    * **Logic:** It traverses the render tree backwards using `PreviousInPreOrder()` until it finds another text layout object. If found, it extracts the last character of that object's transformed text.
    * **Output:** The previous character (a `UChar`) or a space character if no preceding text is found.
* **`TransformAndSecureText()`:**
    * **Assumption:** Text transformations and security masking should be applied based on the current style.
    * **Input:** The original text string.
    * **Logic:** It first applies text transformations based on the `text-transform` CSS property. Then, based on the `text-security` CSS property, it masks the transformed text with specified characters.
    * **Output:** The transformed and secured text string, along with a `TextOffsetMap` to track changes in length due to transformations.
* **`SecureText()`:**
    * **Assumption:**  Only parts of the text should be revealed momentarily when typing in a secure field.
    * **Input:** The plaintext string and a mask character.
    * **Logic:** It iterates through the plaintext and replaces characters with the mask, except for the last typed character (if the `SecureTextTimer` is active).
    * **Output:** The masked string and a `TextOffsetMap` indicating where multi-character grapheme clusters were masked with a single mask character.
* **`ContainsCaretOffset()`:**
    * **Assumption:** We need to determine if a given text offset falls within the non-collapsed content of the `LayoutText` object.
    * **Input:** An integer `text_offset`.
    * **Logic:** It checks if the offset is within the bounds of the text. If offset mappings exist (due to text transforms), it uses them to determine if the offset corresponds to non-collapsed content. It handles edge cases like the beginning and end of the text.
    * **Output:** `true` if the offset is within non-collapsed content, `false` otherwise.

**Common User or Programming Errors:**

* **Incorrectly Assuming Text Length After Transformation:** Users or developers might try to access characters in the original text string using indices calculated based on the displayed (transformed) text length. This can lead to out-of-bounds errors if text transformations change the length of the string. The `TextOffsetMap` is crucial for mapping offsets between the original and transformed text.
    * **Example:** Original text: "aBc", `text-transform: uppercase`. Transformed text: "ABC". If someone tries to access the 3rd character of the original string thinking it's 'c' based on the transformed length, they'll be correct in this case. However, if the transformation added characters, like with list markers, the indices would be off.
* **Misunderstanding Text Security:** Developers might assume that setting `text-security` completely prevents access to the original text. While it masks the display, the underlying text content is still present and can be accessed programmatically if the context allows.
* **Incorrectly Handling Caret Positioning with Transformations:** When dealing with text transformations, especially those that change the length or structure (like combining characters), directly using offsets from the original text might lead to incorrect caret positioning. The `GetOffsetMapping()` and related methods help in correctly mapping caret positions between the original and transformed text.
* **Forgetting to Invalidate Layout After Text Changes:** If text content is modified programmatically without triggering a layout invalidation, the visual representation might not update correctly. The `TextDidChange()` and related methods ensure that layout and paint updates are scheduled.

**Summary of Functionality (Part 2):**

In essence, `LayoutText` is the fundamental building block for representing and managing text content within the Blink rendering engine. It bridges the gap between the raw text in the HTML and its visual representation on the screen, taking into account CSS styling, text transformations, security, and interaction with other rendering components like selection and accessibility. It handles the complexities of text manipulation and ensures that changes are reflected correctly in the rendered output. The class is deeply integrated with the layout process, the painting pipeline, and other browser functionalities that rely on understanding the structure and content of text.

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_text.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
false;
  return To<LayoutText>(o)->HasEmptyText();
}

UChar LayoutText::PreviousCharacter() const {
  NOT_DESTROYED();
  // find previous text layoutObject if one exists
  const LayoutObject* previous_text = PreviousInPreOrder();
  for (; previous_text; previous_text = previous_text->PreviousInPreOrder()) {
    if (!IsInlineFlowOrEmptyText(previous_text))
      break;
  }
  UChar prev = kSpaceCharacter;
  if (previous_text && previous_text->IsText()) {
    if (const String& previous_string =
            To<LayoutText>(previous_text)->TransformedText()) {
      prev = previous_string[previous_string.length() - 1];
    }
  }
  return prev;
}

void LayoutText::SetTextInternal(String text) {
  NOT_DESTROYED();
  DCHECK(text);
  text_ = String(std::move(text));
  DCHECK(text_);
  DCHECK(!IsBR() ||
         (TransformedTextLength() == 1 && text_[0] == kNewlineCharacter));
}

String LayoutText::TransformAndSecureText(const String& original,
                                          TextOffsetMap& offset_map) const {
  NOT_DESTROYED();
  if (const ComputedStyle* style = Style()) {
    String transformed =
        style->ApplyTextTransform(original, PreviousCharacter(), &offset_map);

    UChar mask = 0;
    // We use the same characters here as for list markers.
    // See CollectUACounterStyleRules() in ua_counter_style_map.cc.
    switch (style->TextSecurity()) {
      case ETextSecurity::kNone:
        return transformed;
      case ETextSecurity::kCircle:
        mask = kWhiteBulletCharacter;
        break;
      case ETextSecurity::kDisc:
        mask = kBulletCharacter;
        break;
      case ETextSecurity::kSquare:
        mask = kBlackSquareCharacter;
        break;
    }
    auto [masked, secure_map] = SecureText(transformed, mask);
    if (!secure_map.IsEmpty()) {
      offset_map = TextOffsetMap(offset_map, secure_map);
    }
    return masked;
  }
  return original;
}

std::pair<String, TextOffsetMap> LayoutText::SecureText(const String& plain,
                                                        UChar mask) const {
  NOT_DESTROYED();
  if (!plain.length()) {
    return std::make_pair(plain, TextOffsetMap());
  }

  int last_typed_character_offset_to_reveal = -1;
  if (auto* secure_text_timer = SecureTextTimer::ActiveInstanceFor(this)) {
    last_typed_character_offset_to_reveal =
        secure_text_timer->LastTypedCharacterOffset();
  }

  StringBuilder builder;
  // `mask` always needs a 16bit buffer.
  builder.Reserve16BitCapacity(plain.length());
  TextOffsetMap offset_map;
  for (unsigned offset = 0; offset < plain.length();) {
    unsigned cluster_size = LengthOfGraphemeCluster(plain, offset);
    unsigned next_offset = offset + cluster_size;
    if (last_typed_character_offset_to_reveal >= 0) {
      unsigned last_typed_offset =
          base::checked_cast<unsigned>(last_typed_character_offset_to_reveal);
      if (offset <= last_typed_offset && last_typed_offset < next_offset) {
        builder.Append(StringView(plain, offset, cluster_size));
        offset = next_offset;
        continue;
      }
    }
    builder.Append(mask);
    offset = next_offset;
    if (cluster_size != 1) {
      offset_map.Append(offset, builder.length());
    }
  }
  return std::make_pair(builder.ToString(), offset_map);
}

void LayoutText::SetVariableLengthTransformResult(
    wtf_size_t original_length,
    const TextOffsetMap& offset_map) {
  if (offset_map.IsEmpty()) {
    ClearHasVariableLengthTransform();
    return;
  }
  has_variable_length_transform_ = true;
  View()->RegisterVariableLengthTransformResult(*this,
                                                {original_length, offset_map});
}

VariableLengthTransformResult LayoutText::GetVariableLengthTransformResult()
    const {
  return View()->GetVariableLengthTransformResult(*this);
}

void LayoutText::ClearHasVariableLengthTransform() {
  NOT_DESTROYED();
  if (has_variable_length_transform_) {
    View()->UnregisterVariableLengthTransformResult(*this);
  }
  has_variable_length_transform_ = false;
}

void LayoutText::SetTextIfNeeded(String text) {
  NOT_DESTROYED();
  DCHECK(text);

  if (text_ == text) {
    return;
  }
  ForceSetText(std::move(text));
}

void LayoutText::ForceSetText(String text) {
  NOT_DESTROYED();
  DCHECK(text);
  SetTextInternal(std::move(text));
  TextDidChange();
}

void LayoutText::SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
    LayoutInvalidationReasonForTracing reason) {
  auto* const text_combine = DynamicTo<LayoutTextCombine>(Parent());
  if (text_combine) [[unlikely]] {
    // Number of characters in text may change compressed font or scaling of
    // text combine. So, we should invalidate |LayoutNGTextCombine| to repaint.
    text_combine
        ->SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
            reason);
    return;
  }
  LayoutObject::SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
      reason);
}

void LayoutText::TextDidChange() {
  NOT_DESTROYED();
  // If intrinsic_logical_widths_dirty_ of an orphan child is true,
  // LayoutObjectChildList::InsertChildNode() fails to set true to owner.
  // To avoid that, we call SetNeedsLayoutAndIntrinsicWidthsRecalc() only if
  // this LayoutText has parent.
  if (Parent()) {
    SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
        layout_invalidation_reason::kTextChanged);
  }
  TextDidChangeWithoutInvalidation();
}

void LayoutText::TextDidChangeWithoutInvalidation() {
  NOT_DESTROYED();
  TextOffsetMap offset_map;
  wtf_size_t original_length = text_.length();
  text_ = TransformAndSecureText(text_, offset_map);
  SetVariableLengthTransformResult(original_length, offset_map);
  if (auto* secure_text_timer = SecureTextTimer::ActiveInstanceFor(this)) {
    // text_ may be updated later before timer fires. We invalidate the
    // last_typed_character_offset_ to avoid inconsistency.
    secure_text_timer->Invalidate();
  }

  if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache())
    cache->TextChanged(this);

  TextAutosizer* text_autosizer = GetDocument().GetTextAutosizer();
  if (text_autosizer)
    text_autosizer->Record(this);

  if (HasNodeId()) {
    if (auto* content_capture_manager = GetOrResetContentCaptureManager())
      content_capture_manager->OnNodeTextChanged(*GetNode());
  }

  valid_ng_items_ = false;
  ClearHasNoControlItems();
  SetNeedsCollectInlines();
}

void LayoutText::InvalidateSubtreeLayoutForFontUpdates() {
  NOT_DESTROYED();
  if (IsFontFallbackValid())
    return;

  valid_ng_items_ = false;
  SetNeedsCollectInlines();
  SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
      layout_invalidation_reason::kFontsChanged);
}

PhysicalRect LayoutText::PhysicalLinesBoundingBox() const {
  NOT_DESTROYED();
  PhysicalRect result;
  CollectLineBoxRects(
      [&result](const PhysicalRect& r) { result.UniteIfNonZero(r); });
  // Some callers expect correct offset even if the rect is empty.
  if (result == PhysicalRect())
    result.offset = FirstLineBoxTopLeft();
  // Note: |result.offset| is relative to container fragment.
  const auto* const text_combine = DynamicTo<LayoutTextCombine>(Parent());
  if (text_combine) [[unlikely]] {
    return text_combine->AdjustRectForBoundingBox(result);
  }
  return result;
}

PhysicalRect LayoutText::VisualOverflowRect() const {
  NOT_DESTROYED();
  DCHECK(IsInLayoutNGInlineFormattingContext());
  return FragmentItem::LocalVisualRectFor(*this);
}

PhysicalRect LayoutText::LocalSelectionVisualRect() const {
  NOT_DESTROYED();
  DCHECK(!NeedsLayout());

  if (!IsSelected())
    return PhysicalRect();

  const FrameSelection& frame_selection = GetFrame()->Selection();
  if (IsInLayoutNGInlineFormattingContext()) {
    const auto* svg_inline_text = DynamicTo<LayoutSVGInlineText>(this);
    float scaling_factor =
        svg_inline_text ? svg_inline_text->ScalingFactor() : 1.0f;
    PhysicalRect rect;
    InlineCursor cursor(*FragmentItemsContainer());
    for (cursor.MoveTo(*this); cursor; cursor.MoveToNextForSameLayoutObject()) {
      if (cursor.Current().IsHiddenForPaint())
        continue;
      const LayoutSelectionStatus status =
          frame_selection.ComputeLayoutSelectionStatus(cursor);
      if (status.start == status.end)
        continue;
      PhysicalRect item_rect = cursor.CurrentLocalSelectionRectForText(status);
      if (svg_inline_text) {
        gfx::RectF float_rect(item_rect);
        const FragmentItem& item = *cursor.CurrentItem();
        float_rect.Offset(item.GetSvgFragmentData()->rect.OffsetFromOrigin());
        if (item.HasSvgTransformForBoundingBox()) {
          float_rect =
              item.BuildSvgTransformForBoundingBox().MapRect(float_rect);
        }
        if (scaling_factor != 1.0f)
          float_rect.Scale(1 / scaling_factor);
        item_rect = PhysicalRect::EnclosingRect(float_rect);
      } else {
        item_rect.offset += cursor.Current().OffsetInContainerFragment();
      }
      rect.Unite(item_rect);
    }
    return rect;
  }

  return PhysicalRect();
}

void LayoutText::InvalidateVisualOverflow() {
  DCHECK(IsInLayoutNGInlineFormattingContext());
  InlineCursor cursor;
  for (cursor.MoveTo(*this); cursor; cursor.MoveToNextForSameLayoutObject())
    cursor.Current()->GetMutableForPainting().InvalidateInkOverflow();
}

const OffsetMapping* LayoutText::GetOffsetMapping() const {
  NOT_DESTROYED();
  return OffsetMapping::GetFor(this);
}

Position LayoutText::PositionForCaretOffset(unsigned offset) const {
  NOT_DESTROYED();
  // ::first-letter handling should be done by LayoutTextFragment override.
  DCHECK(!IsTextFragment());
  // BR handling should be done by LayoutBR override.
  DCHECK(!IsBR());
  // WBR handling should be done by LayoutWordBreak override.
  DCHECK(!IsWordBreak());
  DCHECK_LE(offset, OriginalTextLength());
  const Node* node = GetNode();
  if (!node)
    return Position();
  auto* text_node = To<Text>(node);
  // TODO(layout-dev): Support offset change due to text-transform.
#if DCHECK_IS_ON()
  // Ensures that the clamping hack kicks in only with text-transform.
  if (StyleRef().TextTransform() == ETextTransform::kNone)
    DCHECK_LE(offset, text_node->length());
#endif
  const unsigned clamped_offset = std::min(offset, text_node->length());
  return Position(node, clamped_offset);
}

std::optional<unsigned> LayoutText::CaretOffsetForPosition(
    const Position& position) const {
  NOT_DESTROYED();
  // ::first-letter handling should be done by LayoutTextFragment override.
  DCHECK(!IsTextFragment());
  // BR handling should be done by LayoutBR override.
  DCHECK(!IsBR());
  // WBR handling should be done by LayoutWordBreak override.
  DCHECK(!IsWordBreak());
  if (position.IsNull() || position.AnchorNode() != GetNode())
    return std::nullopt;
  DCHECK(GetNode()->IsTextNode());
  if (position.IsBeforeAnchor())
    return 0;
  if (position.IsAfterAnchor())
    return OriginalTextLength();
  DCHECK(position.IsOffsetInAnchor()) << position;
  DCHECK_LE(position.OffsetInContainerNode(),
            static_cast<int>(OriginalTextLength()))
      << position;
  return position.OffsetInContainerNode();
}

int LayoutText::CaretMinOffset() const {
  NOT_DESTROYED();
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());

  if (auto* mapping = GetOffsetMapping()) {
    const Position first_position = PositionForCaretOffset(0);
    if (first_position.IsNull())
      return 0;
    std::optional<unsigned> candidate = CaretOffsetForPosition(
        mapping->StartOfNextNonCollapsedContent(first_position));
    // Align with the legacy behavior that 0 is returned if the entire node
    // contains only collapsed whitespaces.
    const bool fully_collapsed =
        !candidate || *candidate == TransformedTextLength();
    return fully_collapsed ? 0 : *candidate;
  }

  return 0;
}

int LayoutText::CaretMaxOffset() const {
  NOT_DESTROYED();
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());

  const unsigned text_length = OriginalTextLength();
  if (auto* mapping = GetOffsetMapping()) {
    const Position last_position = PositionForCaretOffset(text_length);
    if (last_position.IsNull())
      return text_length;
    std::optional<unsigned> candidate = CaretOffsetForPosition(
        mapping->EndOfLastNonCollapsedContent(last_position));
    // Align with the legacy behavior that |TextLenght()| is returned if the
    // entire node contains only collapsed whitespaces.
    const bool fully_collapsed = !candidate || *candidate == 0u;
    return fully_collapsed ? text_length : *candidate;
  }

  return text_length;
}

unsigned LayoutText::NonCollapsedCaretMaxOffset() const {
  NOT_DESTROYED();
  return OriginalTextLength();
}

unsigned LayoutText::ResolvedTextLength() const {
  NOT_DESTROYED();
  if (auto* mapping = GetOffsetMapping()) {
    const Position start_position = PositionForCaretOffset(0);
    const Position end_position =
        PositionForCaretOffset(NonCollapsedCaretMaxOffset());
    if (start_position.IsNull()) {
      DCHECK(end_position.IsNull()) << end_position;
      return 0;
    }
    DCHECK(end_position.IsNotNull()) << start_position;
    std::optional<unsigned> start =
        mapping->GetTextContentOffset(start_position);
    std::optional<unsigned> end = mapping->GetTextContentOffset(end_position);
    if (!start.has_value() || !end.has_value()) {
      DCHECK(!start.has_value()) << this;
      DCHECK(!end.has_value()) << this;
      return 0;
    }
    DCHECK_LE(*start, *end);
    return *end - *start;
  }

  return 0;
}

bool LayoutText::HasNonCollapsedText() const {
  NOT_DESTROYED();
  if (GetOffsetMapping()) {
    return ResolvedTextLength();
  }
  return false;
}

bool LayoutText::ContainsCaretOffset(int text_offset) const {
  NOT_DESTROYED();
  DCHECK_GE(text_offset, 0);
  if (auto* mapping = GetOffsetMapping()) {
    const int text_length = static_cast<int>(NonCollapsedCaretMaxOffset());
    if (text_offset > text_length) {
      return false;
    }
    const Position position = PositionForCaretOffset(text_offset);
    if (position.IsNull()) {
      return false;
    }
    // Return `true` if the position is not collapsed.
    if (text_offset < text_length &&
        mapping->IsBeforeNonCollapsedContent(position)) {
      return true;
    }
    // The position is collapsed. Return `false` if this is the first character,
    // or the previous character is also collapsed.
    if (!text_offset || !mapping->IsAfterNonCollapsedContent(position)) {
      return false;
    }
    // The previous character isn't collapsed. Return `false` if it's a newline,
    // otherwise `true`.
    if (std::optional<UChar> ch = mapping->GetCharacterBefore(position)) {
      return *ch != kNewlineCharacter;
    }
    // TODO(crbug.com/326745564): It's not clear when the code reaches here, and
    // thus it's not clear whether it should return `true` or `false`.
  }

  return false;
}

bool LayoutText::IsBeforeNonCollapsedCharacter(unsigned text_offset) const {
  NOT_DESTROYED();
  if (auto* mapping = GetOffsetMapping()) {
    if (text_offset >= NonCollapsedCaretMaxOffset()) {
      return false;
    }
    const Position position = PositionForCaretOffset(text_offset);
    if (position.IsNull())
      return false;
    return mapping->IsBeforeNonCollapsedContent(position);
  }

  return false;
}

bool LayoutText::IsAfterNonCollapsedCharacter(unsigned text_offset) const {
  NOT_DESTROYED();
  if (auto* mapping = GetOffsetMapping()) {
    if (!text_offset)
      return false;
    const Position position = PositionForCaretOffset(text_offset);
    if (position.IsNull())
      return false;
    return mapping->IsAfterNonCollapsedContent(position);
  }

  return false;
}

void LayoutText::MomentarilyRevealLastTypedCharacter(
    unsigned last_typed_character_offset) {
  NOT_DESTROYED();
  auto it = GetSecureTextTimers().find(this);
  SecureTextTimer* secure_text_timer =
      it != GetSecureTextTimers().end() ? it->value : nullptr;
  if (!secure_text_timer) {
    secure_text_timer = MakeGarbageCollected<SecureTextTimer>(this);
    GetSecureTextTimers().insert(this, secure_text_timer);
  }
  secure_text_timer->RestartWithNewText(last_typed_character_offset);
}

AbstractInlineTextBox* LayoutText::FirstAbstractInlineTextBox() {
  NOT_DESTROYED();
  DCHECK(IsInLayoutNGInlineFormattingContext());
  InlineCursor cursor;
  cursor.MoveTo(*this);
  return AbstractInlineTextBox::GetOrCreate(cursor);
}

void LayoutText::InvalidatePaint(const PaintInvalidatorContext& context) const {
  NOT_DESTROYED();
  if (ShouldInvalidateSelection() && !IsSelected())
    GetSelectionDisplayItemClientMap().erase(this);
  LayoutObject::InvalidatePaint(context);
}

void LayoutText::InvalidateDisplayItemClients(
    PaintInvalidationReason reason) const {
  NOT_DESTROYED();
  LayoutObject::InvalidateDisplayItemClients(reason);

  if (const auto* selection_client = GetSelectionDisplayItemClient()) {
    ObjectPaintInvalidator(*this).InvalidateDisplayItemClient(*selection_client,
                                                              reason);
  }

#if DCHECK_IS_ON()
  if (IsInLayoutNGInlineFormattingContext()) {
    InlineCursor cursor;
    for (cursor.MoveTo(*this); cursor; cursor.MoveToNextForSameLayoutObject()) {
      DCHECK_EQ(cursor.Current().GetDisplayItemClient(), this);
    }
  }
#endif
}

const DisplayItemClient* LayoutText::GetSelectionDisplayItemClient() const {
  NOT_DESTROYED();
  if (!IsInLayoutNGInlineFormattingContext()) [[unlikely]] {
    return nullptr;
  }
  // When |this| is in text-combine box, we should use text-combine box as
  // display client item to paint caret with affine transform.
  const auto* const text_combine = DynamicTo<LayoutTextCombine>(Parent());
  if (text_combine && text_combine->NeedsAffineTransformInPaint())
      [[unlikely]] {
    return text_combine;
  }
  if (!IsSelected())
    return nullptr;
  auto it = GetSelectionDisplayItemClientMap().find(this);
  if (it != GetSelectionDisplayItemClientMap().end())
    return &*it->value;
  return GetSelectionDisplayItemClientMap()
      .insert(this, MakeGarbageCollected<SelectionDisplayItemClient>())
      .stored_value->value.Get();
}

PhysicalRect LayoutText::DebugRect() const {
  NOT_DESTROYED();
  return PhysicalRect(ToEnclosingRect(PhysicalLinesBoundingBox()));
}

DOMNodeId LayoutText::EnsureNodeId() {
  NOT_DESTROYED();
  if (node_id_ == kInvalidDOMNodeId) {
    if (auto* content_capture_manager = GetOrResetContentCaptureManager()) {
      if (auto* node = GetNode()) {
        content_capture_manager->ScheduleTaskIfNeeded(*node);
        node_id_ = node->GetDomNodeId();
      }
    }
  }
  return node_id_;
}

ContentCaptureManager* LayoutText::GetOrResetContentCaptureManager() {
  NOT_DESTROYED();
  if (auto* node = GetNode()) {
    if (auto* frame = node->GetDocument().GetFrame()) {
      return frame->LocalFrameRoot().GetOrResetContentCaptureManager();
    }
  }
  return nullptr;
}

void LayoutText::SetInlineItems(InlineItemsData* data,
                                wtf_size_t begin,
                                wtf_size_t size) {
  NOT_DESTROYED();
#if DCHECK_IS_ON()
  for (wtf_size_t i = begin; i < begin + size; i++) {
    DCHECK_EQ(data->items[i].GetLayoutObject(), this);
  }
#endif
  auto* items = GetInlineItems();
  if (!items)
    return;
  valid_ng_items_ = true;
  items->SetItems(data, begin, size);
}

void LayoutText::ClearInlineItems() {
  NOT_DESTROYED();
  has_bidi_control_items_ = false;
  valid_ng_items_ = false;
  if (auto* items = GetInlineItems()) {
    items->Clear();
  }
}

const InlineItemSpan& LayoutText::InlineItems() const {
  NOT_DESTROYED();
  DCHECK(valid_ng_items_);
  DCHECK(GetInlineItems());
  DCHECK(!GetInlineItems()->empty());
  return *GetInlineItems();
}

#if DCHECK_IS_ON()
void LayoutText::RecalcVisualOverflow() {
  // We should never reach here, because |PaintLayer| calls
  // |RecalcVisualOverflow| for each layer, and the containing |LayoutObject|
  // should recalculate its |FragmentItem|s without traversing descendant
  // |LayoutObject|s.
  if (IsInline() && IsInLayoutNGInlineFormattingContext()) {
    NOTREACHED();
  }

  LayoutObject::RecalcVisualOverflow();
}
#endif

}  // namespace blink

"""


```