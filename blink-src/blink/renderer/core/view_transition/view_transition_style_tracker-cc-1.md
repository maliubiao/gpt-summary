Response:
The user wants a summary of the functionalities of the provided C++ code snippet from the Chromium Blink engine. The code is part of the `ViewTransitionStyleTracker` class. I need to extract the key functionalities and explain how they relate to web technologies like JavaScript, HTML, and CSS. I should also provide examples of logical reasoning (input/output) and common user/programming errors. Finally, I need to ensure this response is the second part of a three-part series, focusing on summarizing the functionalities within this specific snippet.

**Plan:**

1. **Identify Core Functions:** Analyze the methods within the provided snippet and their purpose.
2. **Relate to Web Technologies:**  Connect the functionalities to how view transitions are implemented and controlled via JavaScript, applied via CSS, and affect the HTML structure.
3. **Logical Reasoning Examples:** Create simple scenarios with hypothetical inputs and the expected outputs based on the code.
4. **Common Errors:** Identify potential mistakes users or developers might make when working with view transitions.
5. **Summarize Functionality:**  Provide a concise overview of what this code segment does.
这是 `blink/renderer/core/view_transition/view_transition_style_tracker.cc` 文件 `ViewTransitionStyleTracker` 类的部分代码，主要负责在视图转换过程中管理和跟踪元素的样式信息。以下是这段代码的功能归纳：

**功能归纳:**

1. **元素注册与验证 (`FlattenAndVerifyElements`):**
    *   将待参与视图转换的元素及其对应的名称（`view-transition-name`）从 `pending_transition_element_names_` 映射中提取出来。
    *   按照元素被 `setViewTransitionName` 调用的顺序进行排序。
    *   **验证是否有重复的 `view-transition-name`**。如果存在重复，会向控制台输出错误信息，并阻止视图转换。

2. **计算包含组名称 (`ComputeContainingGroupName`):**
    *   根据元素的 `view-transition-group` CSS 属性，以及已有的组状态映射 (`group_state_map_`)，递归地向上查找包含当前元素的视图转换组的名称。
    *   支持 `contain`、`nearest` 和自定义的组名称策略。

3. **捕获快照 (`Capture`):**
    *   **前提条件检查:** 确保文档元素存在且已完成布局。
    *   **浏览器控件处理:** 如果是跨文档转换，并且需要 `snap_browser_controls`，则将浏览器控件的状态设置为完全显示。
    *   **状态更新:** 将 `ViewTransitionStyleTracker` 的状态设置为 `kCapturing`。
    *   **存储元素数据:** 遍历参与转换的元素，为每个元素创建 `ElementData` 对象，存储元素的引用、索引、旧快照 ID、类名列表以及包含组的名称。
    *   **生成资源 ID:** 为每个参与转换的元素生成唯一的 `viz::ViewTransitionElementResourceId` 作为快照 ID。
    *   **更新样式引擎:**  将参与转换的名称列表传递给样式引擎，以便创建相应的伪元素树。
    *   **触发样式失效:** 调用 `InvalidateStyle()` 触发样式重新计算，以生成伪元素。
    *   **记录初始根元素大小:** 记录捕获时的根元素的布局大小。
    *   **创建子帧快照层:** 如果启用了本地 iframe 的 paint holding 功能，并且当前文档不是根 frame，则创建一个 `cc::ViewTransitionContentLayer` 用于子帧的快照。

4. **接收合成器传递的捕获矩形 (`SetCaptureRectsFromCompositor`):**
    *   **仅在特定 Feature 启用时生效:** 只有当 `ViewTransitionOverflowRectFromSurfaceEnabled()` 返回 true 时才处理。
    *   **更新元素数据:** 使用合成器提供的矩形信息更新 `element_data_map_` 中对应元素的捕获矩形信息。这将覆盖之前基于布局溢出计算的猜测值。
    *   **更新伪元素大小:** 同时更新 `::view-transition-old` 伪元素的固有大小，使其与合成器提供的捕获矩形一致。

5. **完成捕获 (`CaptureResolved`):**
    *   **状态更新:** 将 `ViewTransitionStyleTracker` 的状态设置为 `kCaptured`。
    *   **抑制命中测试:**  失效命中测试缓存。
    *   **触发样式失效:** 调用 `InvalidateStyle()`。
    *   **解除元素引用:** 将 `element_data_map_` 中 `ElementData` 对象的 `target_element` 设置为 null。

6. **获取正在转换的元素 (`GetTransitioningElements`):**
    *   返回当前状态下（非 `kIdle` 或 `kCaptured`）参与视图转换的非根元素列表。

7. **获取视图转换类名列表 (`GetViewTransitionClassList`):**
    *   根据 `view-transition-name` 返回元素在捕获时具有的文档作用域的类名列表。

8. **获取包含组名称 (`GetContainingGroupName`):**
    *   在 `kStarted` 状态下，根据 `view-transition-name` 返回其包含的视图转换组的名称。

9. **开始过渡 (`Start`):**
    *   **前提条件检查:** 状态必须为 `kCaptured`。
    *   **子帧快照层清理:** 清理可能存在的子帧快照层。
    *   **元素注册与验证:**  再次处理待参与视图转换的元素，类似于 `Capture` 阶段。
    *   **状态更新:** 将 `ViewTransitionStyleTracker` 的状态设置为 `kStarted`。
    *   **存储新状态元素数据:** 遍历参与转换的元素，为每个元素更新或创建 `ElementData` 对象，存储元素的引用、新快照 ID、类名列表以及包含组的名称。
    *   **处理新增名称:** 如果存在新的 `view-transition-name`，则更新样式引擎的名称列表。
    *   **触发样式失效:** 调用 `InvalidateStyle()` 触发样式重新计算，以生成新的内容伪元素。
    *   **通知动画器:** 通知页面动画器有视图转换正在进行。

10. **完成开始过渡 (`StartFinished`):**
    *   状态检查：必须为 `kStarted`。
    *   调用 `EndTransition()` 结束过渡。

11. **中止过渡 (`Abort`):**
    *   调用 `EndTransition()` 结束过渡。

12. **本地子帧渲染被节流 (`DidThrottleLocalSubframeRendering`):**
    *   在 `kCapturing` 状态下，如果子帧渲染被节流，则创建一个非 live 的子帧快照层。

13. **结束过渡 (`EndTransition`):**
    *   **状态更新:** 将 `ViewTransitionStyleTracker` 的状态设置为 `kFinished`。
    *   **失效命中测试:** 失效命中测试缓存。
    *   **触发样式失效:** 调用 `InvalidateStyle()` 以移除伪元素树。
    *   **清理数据:** 清空 `element_data_map_` 和 `pending_transition_element_names_`，重置序列 ID，并清除样式引擎中的视图转换名称。
    *   **通知动画器:** 通知页面动画器视图转换已结束。

14. **获取快照 ID (`GetSnapshotId`):**
    *   根据元素查找其对应的快照 ID，在 `HasLiveNewContent()` 为 true 时返回新快照 ID，否则返回旧快照 ID。

15. **获取子帧快照层 (`GetSubframeSnapshotLayer`):**
    *   返回子帧的快照层。

16. **创建伪元素 (`CreatePseudoElement`):**
    *   根据父元素、伪元素 ID 和 `view-transition-name` 创建不同的视图转换伪元素实例（例如 `ViewTransitionTransitionElement`, `ViewTransitionGroupPseudoElement`, `ViewTransitionContentElement` 等）。
    *   对于 `::view-transition-old` 和 `::view-transition-new` 伪元素，会从 `element_data_map_` 中获取对应的元素数据，并设置其固有大小和快照 ID。

17. **运行预绘制后步骤 (`RunPostPrePaintSteps`):**
    *   **前提条件检查:** 确保文档元素存在且已完成布局，设备像素比没有变化，并且快照根元素的大小没有改变。
    *   **大小限制检查:** 检查快照根元素的大小是否超过最大捕获尺寸。
    *   **更新元素几何信息和样式属性:** 遍历参与转换的元素，计算其容器属性、可视溢出矩形、捕获矩形以及需要捕获的 CSS 属性值。如果这些信息发生变化，则更新 `element_data_map_` 中的缓存。
    *   **更新伪元素大小:** 如果元素的几何信息发生变化，则更新其对应的 `::view-transition-old` 或 `::view-transition-new` 伪元素的固有大小。
    *   **同步捕获状态:** 在 `kCapturing` 状态下，将当前状态缓存为旧快照状态。
    *   **更新快照根样式:** 调用 `LayoutViewTransitionRoot` 的方法更新快照样式。
    *   **触发样式失效:** 如果有任何元素的几何信息或样式属性发生变化，则调用 `InvalidateStyle()`。

18. **计算实时元素的几何信息 (`ComputeLiveElementGeometry`):**
    *   计算参与转换的元素的容器属性、可视溢出矩形和捕获矩形。
    *   会考虑元素的变换、缩放、边框大小、内边距等因素。
    *   根据是否启用 layered capture，参考盒模型可能为 content-box。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript:**
    *   通过 JavaScript 调用 `document.startViewTransition()` 触发视图转换。
    *   可以使用 JavaScript 获取参与转换的元素的 `view-transition-name`。
    *   **假设输入:** JavaScript 代码 `document.body.style.viewTransitionName = 'my-element';` 将 body 元素的 `view-transition-name` 设置为 'my-element'。
    *   **输出:**  `FlattenAndVerifyElements` 函数会将 body 元素及其名称 'my-element' 添加到内部数据结构中，并在后续的捕获和过渡阶段使用。

*   **HTML:**
    *   HTML 结构定义了参与视图转换的元素。
    *   **假设输入:** HTML 代码 `<div style="view-transition-name: image-container;">...</div>` 定义了一个 `view-transition-name` 为 "image-container" 的 div 元素。
    *   **输出:** `ViewTransitionStyleTracker` 会识别这个 div 元素并为其创建相应的伪元素，如 `::view-transition-image-pair(image-container)`, `::view-transition-old(image-container)`, `::view-transition-new(image-container)`。

*   **CSS:**
    *   使用 CSS 属性 `view-transition-name` 来标识参与视图转换的元素。
    *   使用 CSS 伪元素（如 `::view-transition`, `::view-transition-group`, `::view-transition-image-pair`, `::view-transition-old`, `::view-transition-new`）来控制过渡动画。
    *   使用 CSS 属性 `view-transition-group` 定义视图转换组。
    *   **假设输入:** CSS 代码 `.image-container::view-transition-old { opacity: 0; }` 定义了当图片容器作为旧状态时，其 `::view-transition-old` 伪元素的初始透明度为 0。
    *   **输出:**  当视图转换开始时，浏览器会应用这个样式到对应的伪元素上，从而实现淡出效果。

**逻辑推理的假设输入与输出:**

*   **假设输入:** `pending_transition_element_names_` 包含两个元素：
    *   Element A，名称 "element-a"，添加顺序 1
    *   Element B，名称 "element-b"，添加顺序 0
*   **输出 (`FlattenAndVerifyElements`):**
    *   `elements` 向量将包含 Element B，然后是 Element A (根据添加顺序排序)。
    *   `transition_names` 向量将包含 "element-b"，然后是 "element-a"。

*   **假设输入:**  元素 C 的 `view-transition-group` CSS 属性设置为 `contain(group-x)`, 且 `group_state_map_` 中 "group-x" 的 `contain` 值为 "root-group"。
*   **输出 (`ComputeContainingGroupName`):**  对于元素 C，将返回 "root-group"。

**涉及用户或者编程常见的使用错误举例:**

*   **重复的 `view-transition-name`:**  用户为多个不同的元素设置了相同的 `view-transition-name`。这会导致 `FlattenAndVerifyElements` 函数返回 `false`，并在控制台输出错误信息，阻止视图转换。
*   **在不支持视图转换的浏览器中使用:**  如果浏览器不支持视图转换 API，相关的 JavaScript 方法和 CSS 属性将不会生效。
*   **在过渡过程中修改 DOM 结构或样式导致提前结束:**  如果在视图转换进行中，通过 JavaScript 剧烈地修改了 DOM 结构或者参与转换的元素的关键样式，可能会导致过渡提前结束或出现不期望的效果。
*   **忘记设置 `view-transition-name`:**  如果希望某个元素参与视图转换，但忘记设置 `view-transition-name` 属性，该元素将不会被跟踪，也不会产生相应的伪元素。

Prompt: 
```
这是目录为blink/renderer/core/view_transition/view_transition_style_tracker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
on_names) {
  // Fail if the document element does not exist, since that's the place where
  // we attach pseudo elements, and if it's not there, we can't do a transition.
  if (!document_->documentElement()) {
    return false;
  }

  // If the root element exists but doesn't generate a layout object then there
  // can't be any elements participating in the transition since no element can
  // generate a box. This is a valid state for things like entry or exit
  // animations.
  if (!document_->documentElement()->GetLayoutObject()) {
    return true;
  }

  // We need to flatten the data first, and sort it by ordering which reflects
  // the setElement ordering.
  struct FlatData : public GarbageCollected<FlatData> {
    FlatData(Element* element, const AtomicString& name, int ordering)
        : element(element), name(name), ordering(ordering) {}
    Member<Element> element;
    AtomicString name;
    int ordering;

    void Trace(Visitor* visitor) const { visitor->Trace(element); }
  };
  VectorOf<FlatData> flat_list;

  // Flatten it.
  for (auto& [element, names] : pending_transition_element_names_) {
    DCHECK(element->GetLayoutObject());

    // TODO(khushalsagar): Simplify this, we don't support multiple
    // view-transition-names per element.
    for (auto& name_pair : names) {
      flat_list.push_back(MakeGarbageCollected<FlatData>(
          element, name_pair.first, name_pair.second));
    }
  }

  // Sort it.
  std::sort(flat_list.begin(), flat_list.end(),
            [](const FlatData* a, const FlatData* b) {
              return a->ordering < b->ordering;
            });

  // Verify it.
  for (auto& flat_data : flat_list) {
    auto& name = flat_data->name;
    auto& element = flat_data->element;

    if (transition_names.Contains(name)) [[unlikely]] {
      StringBuilder message;
      message.Append(kDuplicateTagBaseError);
      message.Append(name);

      Vector<DOMNodeId> nodes;
      // Find all the elements with this name.
      for (auto& name_finder : flat_list) {
        if (name_finder->name == name) {
          nodes.push_back(name_finder->element->GetDomNodeId());
        }
      }

      AddConsoleError(message.ReleaseString(), std::move(nodes));
      return false;
    }

    transition_names.push_back(name);
    elements.push_back(element);
  }
  return true;
}

AtomicString ViewTransitionStyleTracker::ComputeContainingGroupName(
    const AtomicString& name,
    const StyleViewTransitionGroup& group) const {
  if (!group_state_map_.Contains(name)) {
    return g_null_atom;
  }

  const auto& parent_state = group_state_map_.at(name);
  if (group.IsNormal() || group.IsContain()) {
    return parent_state.contain;
  }

  if (group.IsNearest() || group.CustomName() == parent_state.nearest) {
    return parent_state.nearest;
  }

  return ComputeContainingGroupName(parent_state.nearest, group);
}

bool ViewTransitionStyleTracker::Capture(bool snap_browser_controls) {
  DCHECK_EQ(state_, State::kIdle);

  // Flatten `pending_transition_element_names_` into a vector of names and
  // elements. This process also verifies that the name-element combinations are
  // valid.
  VectorOf<AtomicString> transition_names;
  VectorOf<Element> elements;
  bool success = FlattenAndVerifyElements(elements, transition_names);
  if (!success)
    return false;

  // In a cross-document transition, top controls are animated to shown when
  // the navigation starts. When capturing the outgoing snapshots, the
  // animation may still be in progress. Ensure controls are snapped to fully
  // showing before capturing. This ensures the root clip is at the correct
  // size and that fixed elements are positioned by layout in the same way they
  // will be on the incoming view.
  if (snap_browser_controls) {
    SnapBrowserControlsToFullyShown();
  }

  // Now we know that we can start a transition. Update the state and populate
  // `element_data_map_`.
  state_ = State::kCapturing;
  InvalidateHitTestingCache();

  captured_name_count_ = transition_names.size();
  element_data_map_.ReserveCapacityForSize(captured_name_count_);
  HeapHashMap<Member<Element>, viz::ViewTransitionElementResourceId>
      element_snapshot_ids;
  int next_index = 0;
  for (int i = 0; i < captured_name_count_; ++i) {
    const auto& name = transition_names[i];
    const auto& element = elements[i];

    // Reuse any previously generated snapshot_id for this element. If there was
    // none yet, then generate the resource id.
    auto& snapshot_id =
        element_snapshot_ids
            .insert(element, viz::ViewTransitionElementResourceId())
            .stored_value->value;
    if (!snapshot_id.IsValid()) {
      snapshot_id = GenerateResourceId();
      capture_resource_ids_.push_back(snapshot_id);
    }

    auto* element_data = MakeGarbageCollected<ElementData>();
    element_data->target_element = element;
    element_data->element_index = next_index++;
    element_data->old_snapshot_id = snapshot_id;
    element_data->class_list = GetDocumentScopedClassList(element);

    // This is guaranteed to be in order if valid, as transition_names is
    // already sorted.
    element_data->containing_group_name = ComputeContainingGroupName(
        name, element->ComputedStyleRef().ViewTransitionGroup());
    element_data_map_.insert(name, std::move(element_data));

    if (element->IsDocumentElement()) {
      is_root_transitioning_ = true;
    }
  }

#if DCHECK_IS_ON()
  for (wtf_size_t i = 0; i < transition_names.size(); ++i) {
    DCHECK_EQ(transition_names.Find(transition_names[i]), i)
        << " Duplicate transition name: " << transition_names[i];
  }
#endif

  // This informs the style engine the set of names we have, which will be used
  // to create the pseudo element tree.
  document_->GetStyleEngine().SetViewTransitionNames(transition_names);

  // We need a style invalidation to generate the pseudo element tree.
  InvalidateStyle();

  set_element_sequence_id_ = 0;
  pending_transition_element_names_.clear();

  DCHECK(!snapshot_root_layout_size_at_capture_.has_value());
  snapshot_root_layout_size_at_capture_ = GetSnapshotRootSize();

  if (RuntimeEnabledFeatures::PaintHoldingForLocalIframesEnabled() &&
      !document_->GetFrame()->IsLocalRoot()) {
    subframe_snapshot_layer_ = cc::ViewTransitionContentLayer::Create(
        GenerateResourceId(), /*is_live_content_layer=*/true);
    capture_resource_ids_.push_back(
        subframe_snapshot_layer_->ViewTransitionResourceId());
  }

  return true;
}

void ViewTransitionStyleTracker::SetCaptureRectsFromCompositor(
    const std::unordered_map<viz::ViewTransitionElementResourceId, gfx::RectF>&
        rects) {
  if (!RuntimeEnabledFeatures::ViewTransitionOverflowRectFromSurfaceEnabled()) {
    // CC might collect these rects when the feature is disabled, but we're
    // ignoring them in that case.
    return;
  }

  CHECK(!HasLiveNewContent());
  for (auto& entry : element_data_map_) {
    auto& element_data = entry.value;

    // This implies that the snapshot wasn't painted.
    if (!rects.contains(element_data->old_snapshot_id) ||
        !element_data->ShouldPropagateVisualOverflowRectAsMaxExtentsRect()) {
      continue;
    }

    // The capture rects from the compositor are now the source of truth for the
    // old elements. We no longer need to guess the max extents using the layout
    // ink overflow and apply corrections, as old pseudo-elements paint existing
    // textures with the captured geometry.
    auto rect_from_compositor = rects.at(element_data->old_snapshot_id);
    auto captured_rect =
        PhysicalRect(gfx::ToEnclosedRect(rect_from_compositor));

    // TODO(crbug.com/40840594): Add a CHECK that the compositor rect is a
    // subset of the computed visual overflow. ATM this fails in one edge case
    // (negative clip-path), the CHECK should be added once that's fixed.

    element_data->cached_visual_overflow_rect_in_layout_space =
        element_data->visual_overflow_rect_in_layout_space = captured_rect;

    // This rect no longer matters.
    element_data->cached_captured_rect_in_layout_space.reset();

    if (auto* pseudo_element =
            document_->documentElement()->GetStyledPseudoElement(
                PseudoId::kPseudoIdViewTransitionOld, entry.key)) {
      static_cast<ViewTransitionContentElement*>(pseudo_element)
          ->SetIntrinsicSize(rect_from_compositor,
                             element_data->GetReferenceRect(
                                 /*use_cached_data=*/true, device_pixel_ratio_),
                             /*propagates_max_extents_rect=*/false);
    }
  }
}

void ViewTransitionStyleTracker::CaptureResolved() {
  DCHECK_EQ(state_, State::kCapturing);

  state_ = State::kCaptured;
  // TODO(crbug.com/1347473): We should also suppress hit testing at this point,
  // since we're about to start painting the element as a captured snapshot, but
  // we still haven't given script chance to modify the DOM to the new state.
  InvalidateHitTestingCache();

  // Since the elements will be unset, we need to invalidate their style first.
  // TODO(vmpstr): We don't have to invalidate the pseudo styles at this point,
  // just the transition elements. We can split InvalidateStyle() into two
  // functions as an optimization.
  InvalidateStyle();

  for (auto& entry : element_data_map_) {
    auto& element_data = entry.value;

    element_data->target_element = nullptr;
  }
  is_root_transitioning_ = false;
}

VectorOf<Element> ViewTransitionStyleTracker::GetTransitioningElements() const {
  // In stable states, we don't have transitioning elements.
  if (state_ == State::kIdle || state_ == State::kCaptured)
    return {};

  VectorOf<Element> result;
  for (auto& entry : element_data_map_) {
    if (entry.value->target_element &&
        !entry.value->target_element->IsDocumentElement()) {
      result.push_back(entry.value->target_element);
    }
  }
  return result;
}

const Vector<AtomicString>&
ViewTransitionStyleTracker::GetViewTransitionClassList(
    const AtomicString& name) const {
  CHECK(element_data_map_.Contains(name));
  return element_data_map_.at(name)->class_list;
}

AtomicString ViewTransitionStyleTracker::GetContainingGroupName(
    const AtomicString& name) const {
  if (!RuntimeEnabledFeatures::NestedViewTransitionEnabled() ||
      state_ != State::kStarted) {
    return g_null_atom;
  }

  // GetContainingGroup can be called on an invalid name, e.g. when searching
  // for the parent of a non-existent name.
  if (!element_data_map_.Contains(name)) {
    return g_null_atom;
  }
  return element_data_map_.at(name)->containing_group_name;
}

bool ViewTransitionStyleTracker::Start() {
  DCHECK_EQ(state_, State::kCaptured);

  subframe_snapshot_layer_.reset();

  // Flatten `pending_transition_element_names_` into a vector of names and
  // elements. This process also verifies that the name-element combinations are
  // valid.
  VectorOf<AtomicString> transition_names;
  VectorOf<Element> elements;
  bool success = FlattenAndVerifyElements(elements, transition_names);
  if (!success)
    return false;

  state_ = State::kStarted;
  InvalidateHitTestingCache();

  HeapHashMap<Member<Element>, viz::ViewTransitionElementResourceId>
      element_snapshot_ids;

  bool found_new_names = false;
  // If this tracker was created from serialized state, transition tags are
  // initialized with the style system in the start phase.
  if (deserialized_) {
    DCHECK(document_->GetStyleEngine().ViewTransitionTags().empty());
    found_new_names = true;
  }

  // We would have an new element index for each of the element_data_map_
  // entries.
  int next_index = element_data_map_.size();
  for (wtf_size_t i = 0; i < elements.size(); ++i) {
    const auto& name = transition_names[i];
    const auto& element = elements[i];

    // Insert a new name data if there is no data for this name yet.
    if (!element_data_map_.Contains(name)) {
      found_new_names = true;
      auto* data = MakeGarbageCollected<ElementData>();
      data->element_index = next_index++;
      element_data_map_.insert(name, data);
    }

    // Reuse any previously generated snapshot_id for this element. If there was
    // none yet, then generate the resource id.
    auto& snapshot_id =
        element_snapshot_ids
            .insert(element, viz::ViewTransitionElementResourceId())
            .stored_value->value;
    if (!snapshot_id.IsValid()) {
      snapshot_id = GenerateResourceId();
    }

    auto& element_data = element_data_map_.find(name)->value;
    DCHECK(!element_data->target_element);
    element_data->target_element = element;
    element_data->new_snapshot_id = snapshot_id;
    element_data->class_list = GetDocumentScopedClassList(element);

    // The parent is guaranteed to be in the list already, as transition_names
    // is sorted by paint order.
    element_data->containing_group_name = ComputeContainingGroupName(
        name, element->ComputedStyleRef().ViewTransitionGroup());

    // Verify that the element_index assigned in Capture is less than next_index
    // here, just as a sanity check.
    DCHECK_LT(element_data->element_index, next_index);

    if (element->IsDocumentElement()) {
      is_root_transitioning_ = true;
    }
  }

  if (found_new_names) {
    VectorOf<std::pair<AtomicString, int>> new_name_pairs;
    for (auto& [name, data] : element_data_map_) {
      new_name_pairs.push_back(std::make_pair(name, data->element_index));
    }

    std::sort(new_name_pairs.begin(), new_name_pairs.end(),
              [](const std::pair<AtomicString, int>& left,
                 const std::pair<AtomicString, int>& right) {
                return left.second < right.second;
              });

#if DCHECK_IS_ON()
    int last_index = -1;
#endif
    VectorOf<AtomicString> new_names;
    for (auto& [name, index] : new_name_pairs) {
      new_names.push_back(name);
#if DCHECK_IS_ON()
      DCHECK_NE(last_index, index);
      last_index = index;
#endif
    }

#if DCHECK_IS_ON()
    for (wtf_size_t i = 0; i < new_names.size(); ++i) {
      DCHECK_EQ(new_names.Find(new_names[i]), i)
          << " Duplicate transition name: " << new_names[i];
    }
#endif

    document_->GetStyleEngine().SetViewTransitionNames(new_names);
  }

  DCHECK_GE(document_->Lifecycle().GetState(),
            DocumentLifecycle::kPrePaintClean);

  // We need a style invalidation to generate new content pseudo elements for
  // new elements in the DOM.
  InvalidateStyle();

  if (auto* page = document_->GetPage())
    page->Animator().SetHasViewTransition(true);
  return true;
}

void ViewTransitionStyleTracker::StartFinished() {
  DCHECK_EQ(state_, State::kStarted);
  EndTransition();
}

void ViewTransitionStyleTracker::Abort() {
  EndTransition();
}

void ViewTransitionStyleTracker::DidThrottleLocalSubframeRendering() {
  DCHECK_EQ(state_, State::kCapturing);

  if (subframe_snapshot_layer_) {
    auto resource_id = subframe_snapshot_layer_->ViewTransitionResourceId();
    subframe_snapshot_layer_ = cc::ViewTransitionContentLayer::Create(
        resource_id, /*is_live_content_layer=*/false);
  }
}

void ViewTransitionStyleTracker::EndTransition() {
  CHECK_NE(state_, State::kFinished);

  state_ = State::kFinished;
  InvalidateHitTestingCache();

  // We need a style invalidation to remove the pseudo element tree. This needs
  // to be done before we clear the data, since we need to invalidate the
  // transition elements stored in `element_data_map_`.
  InvalidateStyle();

  element_data_map_.clear();
  pending_transition_element_names_.clear();
  set_element_sequence_id_ = 0;
  document_->GetStyleEngine().SetViewTransitionNames({});
  is_root_transitioning_ = false;
  if (auto* page = document_->GetPage())
    page->Animator().SetHasViewTransition(false);
}

viz::ViewTransitionElementResourceId ViewTransitionStyleTracker::GetSnapshotId(
    const Element& element) const {
  viz::ViewTransitionElementResourceId resource_id;

  for (const auto& entry : element_data_map_) {
    // This loop is based on the assumption that an element can have multiple
    // names. But this concept is not supported by the web API.
    if (entry.value->target_element == element) {
      const auto& snapshot_id = HasLiveNewContent()
                                    ? entry.value->new_snapshot_id
                                    : entry.value->old_snapshot_id;
      DCHECK(!resource_id.IsValid() || resource_id == snapshot_id);
      if (!resource_id.IsValid())
        resource_id = snapshot_id;
    }
  }

  return resource_id;
}

const scoped_refptr<cc::ViewTransitionContentLayer>&
ViewTransitionStyleTracker::GetSubframeSnapshotLayer() const {
  return subframe_snapshot_layer_;
}

PseudoElement* ViewTransitionStyleTracker::CreatePseudoElement(
    Element* parent,
    PseudoId pseudo_id,
    const AtomicString& view_transition_name) const {
  DCHECK(IsTransitionPseudoElement(pseudo_id));
  DCHECK(pseudo_id == kPseudoIdViewTransition || view_transition_name);

  switch (pseudo_id) {
    case kPseudoIdViewTransition:
      return MakeGarbageCollected<ViewTransitionTransitionElement>(parent,
                                                                   this);

    case kPseudoIdViewTransitionGroup: {
      return MakeGarbageCollected<ViewTransitionPseudoElementBase>(
          parent, pseudo_id, view_transition_name, this);
    }
    case kPseudoIdViewTransitionImagePair:
      return MakeGarbageCollected<ImageWrapperPseudoElement>(
          parent, pseudo_id, view_transition_name, this);

    case kPseudoIdViewTransitionOld: {
      DCHECK(view_transition_name);
      const auto& element_data =
          element_data_map_.find(view_transition_name)->value;

      // If live data is tracking new elements then use the cached data for
      // the pseudo element displaying snapshot of old element.
      bool use_cached_data = HasLiveNewContent();
      auto captured_rect = element_data->GetCapturedSubrect(use_cached_data);
      auto reference_rect_in_enclosing_layer_space =
          element_data->GetReferenceRect(use_cached_data, device_pixel_ratio_);
      auto snapshot_id = element_data->old_snapshot_id;

      // Note that we say that this layer is not a live content
      // layer, even though it may currently be displaying live contents. The
      // reason is that we want to avoid updating this value later, which
      // involves propagating the update all the way to cc. However, this means
      // that we have to have the save directive come in the same frame as the
      // first frame that displays this content. Otherwise, we risk DCHECK. This
      // is currently the behavior as specced, but this is subtle.
      // TODO(vmpstr): Maybe we should just use HasLiveNewContent() here, and
      // update it when the value changes.
      auto* pseudo_element = MakeGarbageCollected<ViewTransitionContentElement>(
          parent, pseudo_id, view_transition_name, snapshot_id,
          /*is_live_content_element=*/false, this);
      pseudo_element->SetIntrinsicSize(
          captured_rect, reference_rect_in_enclosing_layer_space,
          element_data->ShouldPropagateVisualOverflowRectAsMaxExtentsRect());
      return pseudo_element;
    }

    case kPseudoIdViewTransitionNew: {
      DCHECK(view_transition_name);
      const auto& element_data =
          element_data_map_.find(view_transition_name)->value;
      bool use_cached_data = false;
      auto captured_rect = element_data->GetCapturedSubrect(use_cached_data);
      auto border_box_rect =
          element_data->GetReferenceRect(use_cached_data, device_pixel_ratio_);
      auto snapshot_id = element_data->new_snapshot_id;

      auto* pseudo_element = MakeGarbageCollected<ViewTransitionContentElement>(
          parent, pseudo_id, view_transition_name, snapshot_id,
          /*is_live_content_element=*/true, this);
      pseudo_element->SetIntrinsicSize(
          captured_rect, border_box_rect,
          element_data->ShouldPropagateVisualOverflowRectAsMaxExtentsRect());
      return pseudo_element;
    }

    default:
      NOTREACHED();
  }
}

bool ViewTransitionStyleTracker::RunPostPrePaintSteps() {
  DCHECK_GE(document_->Lifecycle().GetState(),
            DocumentLifecycle::kPrePaintClean);
  // Abort if the document element is not there.
  if (!document_->documentElement()) {
    return false;
  }

  if (!document_->documentElement()->GetLayoutObject()) {
    // If we have any view transition elements, while having no
    // documentElement->GetLayoutObject(), we should abort. Target elements are
    // only set on the current phase of the animation, so it means that the
    // documentElement's layout object disappeared in this phase.
    for (auto& entry : element_data_map_) {
      auto& element_data = entry.value;
      if (element_data->target_element) {
        return false;
      }
    }
    return true;
  }

  DCHECK(document_->documentElement() &&
         document_->documentElement()->GetLayoutObject());
  // We don't support changing device pixel ratio, because it's uncommon and
  // textures may have already been captured at a different size.
  if (device_pixel_ratio_ != DevicePixelRatioFromDocument(*document_)) {
    return false;
  }

  if (SnapshotRootDidChangeSize()) {
    return false;
  }

  const int max_capture_size_in_layout = ComputeMaxCaptureSize(
      *document_,
      document_->GetPage()->GetChromeClient().GetMaxRenderBufferBounds(
          *document_->GetFrame()),
      *snapshot_root_layout_size_at_capture_);

  if (snapshot_root_layout_size_at_capture_->width() >
          max_capture_size_in_layout ||
      snapshot_root_layout_size_at_capture_->height() >
          max_capture_size_in_layout) {
    // TODO(crbug.com/1516874): This skips the transition if the root is too
    // large to fit into a texture but non-root elements clip in this case
    // instead. It would be better to clip the root like we do child elements,
    // rather than skipping (and that would comply better with the spec).

    // For main frames the capture size should never be bigger than the
    // window so we only expect to end up here due to large subframes.
    CHECK(!document_->GetFrame()->IsOutermostMainFrame());
    return false;
  }

  bool needs_style_invalidation = false;

  for (auto& entry : element_data_map_) {
    auto& element_data = entry.value;
    if (!element_data->target_element)
      continue;

    DCHECK(document_->documentElement());
    auto* layout_object = element_data->target_element->GetLayoutObject();
    if (!layout_object) {
      return false;
    }

    // End the transition if any of the objects have become fragmented.
    if (layout_object->IsFragmented()) {
      return false;
    }

    ContainerProperties container_properties;
    PhysicalRect visual_overflow_rect_in_layout_space;
    std::optional<gfx::RectF> captured_rect_in_layout_space;

    if (element_data->target_element->IsDocumentElement()) {
      auto layout_view_size = PhysicalSize(GetSnapshotRootSize());
      auto layout_view_size_in_css_space = layout_view_size;
      layout_view_size_in_css_space.Scale(1 / device_pixel_ratio_);
      container_properties = ContainerProperties{
          PhysicalRect(PhysicalOffset(), layout_view_size_in_css_space),
          gfx::Transform(), std::nullopt};
      visual_overflow_rect_in_layout_space.size = layout_view_size;
    } else {
      ComputeLiveElementGeometry(
          max_capture_size_in_layout, *layout_object, container_properties,
          visual_overflow_rect_in_layout_space, captured_rect_in_layout_space);
    }

    FlatMapBuilder<CSSPropertyID, String> css_property_builder(
        std::size(kPropertiesToCapture));

    auto capture_property = [&](CSSPropertyID id) {
      if (const CSSValue* css_value =
              CSSProperty::Get(id).CSSValueFromComputedStyle(
                  layout_object->StyleRef(),
                  /*layout_object=*/nullptr,
                  /*allow_visited_style=*/false,
                  CSSValuePhase::kComputedValue)) {
        css_property_builder.Insert(id, css_value->CssText());
      }
    };

    for (CSSPropertyID id : kPropertiesToCapture) {
      capture_property(id);
    }

    if (ViewTransitionUtils::UseLayeredCapture(layout_object->StyleRef())) {
      for (CSSPropertyID id : kLayeredCaptureProperties) {
        capture_property(id);
      }
    }

    auto css_properties = std::move(css_property_builder).Finish();

    if (element_data->container_properties == container_properties &&
        visual_overflow_rect_in_layout_space ==
            element_data->visual_overflow_rect_in_layout_space &&
        captured_rect_in_layout_space ==
            element_data->captured_rect_in_layout_space &&
        css_properties == element_data->captured_css_properties) {
      continue;
    }

    element_data->container_properties = container_properties;

    element_data->visual_overflow_rect_in_layout_space =
        visual_overflow_rect_in_layout_space;
    element_data->captured_css_properties = css_properties;
    element_data->captured_rect_in_layout_space = captured_rect_in_layout_space;

    PseudoId live_content_element = HasLiveNewContent()
                                        ? kPseudoIdViewTransitionNew
                                        : kPseudoIdViewTransitionOld;
    DCHECK(document_->documentElement());
    if (auto* pseudo_element =
            document_->documentElement()->GetStyledPseudoElement(
                live_content_element, entry.key)) {
      // A pseudo element of type |tansition*content| must be created using
      // ViewTransitionContentElement.
      bool use_cached_data = false;
      auto captured_rect = element_data->GetCapturedSubrect(use_cached_data);
      auto border_box_rect =
          element_data->GetReferenceRect(use_cached_data, device_pixel_ratio_);
      static_cast<ViewTransitionContentElement*>(pseudo_element)
          ->SetIntrinsicSize(
              captured_rect, border_box_rect,
              element_data
                  ->ShouldPropagateVisualOverflowRectAsMaxExtentsRect());
    }

    // Ensure that the cached state stays in sync with the current state while
    // we're capturing.
    if (state_ == State::kCapturing) {
      element_data->CacheStateForOldSnapshot();
    }

    needs_style_invalidation = true;
  }

  if (LayoutViewTransitionRoot* snapshot_containing_block =
          document_->GetLayoutView()->GetViewTransitionRoot()) {
    snapshot_containing_block->UpdateSnapshotStyle(*this);
  }

  if (needs_style_invalidation) {
    InvalidateStyle();
  }

  return true;
}

void ViewTransitionStyleTracker::ComputeLiveElementGeometry(
    int max_capture_size,
    LayoutObject& layout_object,
    ContainerProperties& container_properties,
    PhysicalRect& visual_overflow_rect_in_layout_space,
    std::optional<gfx::RectF>& captured_rect_in_layout_space) const {
  DCHECK(!layout_object.IsLayoutView());

  // TODO(bokan): This doesn't account for the local offset of an inline
  // element within its container. The object-view-box inset will ensure the
  // snapshot is rendered in the correct place but the pseudo is positioned
  // w.r.t. to the container. This can look awkward since the opposing
  // snapshot may have a different object-view-box. Inline positioning and
  // scaling more generally might use some improvements.
  // https://crbug.com/1416951.
  auto snapshot_matrix_in_layout_space =
      ComputeViewportTransform(layout_object);

  // The FixedToSnapshot offset below takes points from the fixed
  // viewport into the snapshot viewport. However, the transform is
  // currently into frame coordinates; when a scrollbar (or gutter) appears on
  // the left, the fixed viewport origin is actually at (15, 0) in frame
  // coordinates (assuming 15px scrollbars). Therefore we must first shift
  // by the scrollbar width so we're in fixed viewport coordinates.
  gfx::Vector2d fixed_to_frame =
      -document_->GetLayoutView()->OriginAdjustmentForScrollbars();
  snapshot_matrix_in_layout_space.PostTranslate(fixed_to_frame);

  gfx::Vector2d snapshot_to_fixed_offset = -GetFixedToSnapshotRootOffset();
  snapshot_matrix_in_layout_space.PostTranslate(snapshot_to_fixed_offset);

  auto snapshot_matrix_in_css_space = snapshot_matrix_in_layout_space;
  snapshot_matrix_in_css_space.Zoom(1.0 / device_pixel_ratio_);

  PhysicalOffset offset_in_css_space;
  if (RuntimeEnabledFeatures::ViewTransitionOverflowRectFromSurfaceEnabled()) {
    // In this mode, the max extents rect (the capture rect we guess here) and
    // the border box are in the enclosing layer coordinate space. That's a more
    // convenient coordinate space than the element's own space as it matches
    // CC's coordinate space (e.g. RenderSurfaceImpl::content_rect()).
    if (auto* layout_inline = DynamicTo<LayoutInline>(layout_object)) {
      offset_in_css_space = layout_inline->PhysicalLinesBoundingBox().offset;
    }

    offset_in_css_space.Scale(1.f / device_pixel_ratio_);
  }

  // For layered capture, the reference box might be the content box, based on
  // box-sizing.
  PhysicalSize border_box_size_in_css_space;
  const bool use_layered_capture =
      ViewTransitionUtils::UseLayeredCapture(layout_object.StyleRef());

  std::optional<ContainerProperties::BoxGeometry> box_geometry;
  if (layout_object.IsSVGChild() || IsA<LayoutBox>(layout_object)) {
    // ResizeObserverEntry is created to reuse the logic for parsing object
    // size for different types of LayoutObjects. However, this works only
    // for SVGChild and LayoutBox.
    auto* resize_observer_entry = MakeGarbageCollected<ResizeObserverEntry>(
        To<Element>(layout_object.GetNode()));
    auto entry_size = resize_observer_entry->borderBoxSize()[0];
    // ResizeObserver gives us CSS space pixels.
    border_box_size_in_css_space =
        layout_object.IsHorizontalWritingMode()
            ? PhysicalSize(LayoutUnit(entry_size->inlineSize()),
                           LayoutUnit(entry_size->blockSize()))
            : PhysicalSize(LayoutUnit(entry_size->blockSize()),
                           LayoutUnit(entry_size->inlineSize()));
  } else if (auto* layout_inline = DynamicTo<LayoutInline>(layout_object)) {
    border_box_size_in_css_space =
        layout_inline->PhysicalLinesBoundingBox().size;
    // Convert to CSS pixels instead of layout pixels.
    border_box_size_in_css_space.Scale(1.f / device_pixel_ratio_);
  }

  if (use_layered_capture && layout_object.IsBoxModelObject()) {
    PhysicalRect padding_box(PhysicalOffset(), border_box_size_in_css_space);
    padding_box.Contract(
        To<LayoutBoxModelObject>(layout_object).BorderOutsets());
    PhysicalRect content_box = padding_box;
    content_box.Contract(
        To<LayoutBoxModelObject>(layout_object).PaddingOutsets());
    box_geometry = ContainerProperties::BoxGeometry{
        .content_box = content_box,
        .padding_box = padding_box,
        .box_sizing = layout_object.StyleRef().BoxSizing()};
  }

  float effective_zoom = layout_object.StyleRef().EffectiveZoom();

  // If the object's effective zoom differs from device_pixel_ratio, adjust
  // the border box size by that difference to get the css space size.
  if (std::abs(effective_zoom - device_pixel_ratio_) >=
      std::numeric_limits<float>::epsilon()) {
    float device_to_css_pixels_ratio = effective_zoom / device_pixel_ratio_;
    border_box_size_in_css_space.Scale(device_to_css_pixels_ratio);
    if (box_geometry) {
      box_geometry->content_box.Scale(device_to_css_pixels_ratio);
      box_geometry->padding_box.Scale(device_to_css_pixels_ratio);
    }
  }

  snapshot_matrix_in_css_space = ConvertFromTopLeftToCenter(
      snapshot_matrix_in_css_space, border_box_size_in_css_space);

  if (auto* box = DynamicTo<LayoutBoxModelObject>(layout_object)) {
    visual_overflow_rect_in_layout_space = ComputeVisualOverflowRect(*box);
  }

  // This is intentionally computed in layout space to include scaling from
  // device scale factor. The element's texture will be in physical pixel
  // bounds which includes this scale.
  captured_rect_in_layout_space = ComputeCaptureRect(
      max_capture_size, visual_overflow_rect_in_layout_space,
      snapshot_matrix_in_layout_space, *snapshot_root_layout_size_at_capture_);
  container_properties = {
      PhysicalRect(offset_in_css_space, border_box_size_in_css_space),
      snapshot_matrix_in_css_space, box_geometry};
}

bool ViewTransitionStyleTracker::HasActiveAnimations() const {
  auto pseudo_has_animation = [](PseudoElement* pseudo_element) {
    auto* animations = pseudo_element->GetElementAnimations()
"""


```