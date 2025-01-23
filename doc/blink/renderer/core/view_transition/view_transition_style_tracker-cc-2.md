Response:
The user wants a summary of the functionality of the provided C++ code. I need to identify the key responsibilities of the `ViewTransitionStyleTracker` class and explain how it interacts with web technologies like JavaScript, HTML, and CSS. I should also look for any logical reasoning in the code and common usage errors related to view transitions.

Here's a plan:
1. **Identify the core purpose:** Analyze the class name and the methods it contains to understand its main function.
2. **Relate to web technologies:** Look for connections to styling, animations, and the DOM. Explain how the code affects the rendering and behavior of web pages during view transitions.
3. **Analyze logical reasoning:** Examine specific code blocks for conditional logic and data transformations. If possible, infer input and output based on the code's behavior.
4. **Identify potential usage errors:** Consider scenarios where incorrect usage of the view transition API could lead to issues based on the code's implementation.
5. **Summarize functionality:**  Condense the findings into a concise description of the `ViewTransitionStyleTracker`'s role.
这是 `blink/renderer/core/view_transition/view_transition_style_tracker.cc` 文件的第三部分，延续了前两部分的内容，主要负责在视图过渡过程中管理和追踪元素的样式变化以及相关的属性。

**归纳一下它的功能:**

延续前两部分，`ViewTransitionStyleTracker` 的主要功能包括：

1. **管理和获取捕获剪切 (Capture Clip):**
   - `UpdateCaptureClip()`:  更新元素的捕获剪切属性节点，用于在过渡期间裁剪元素。
   - `GetCaptureClip()`: 获取元素的捕获剪切属性节点。
   - **与 CSS 关系:**  捕获剪切实际上影响了元素的渲染方式，类似于 CSS 的 `clip-path` 属性，用于限定元素的可视区域。

2. **判断元素是否参与过渡:**
   - `IsTransitionElement()`: 判断给定的元素是否是视图过渡的一部分。
   - **与 HTML 关系:**  该方法判断的元素通常是在 JavaScript 中使用 `document.startViewTransition()` 时指定的需要过渡的元素。

3. **判断元素是否需要捕获剪切节点:**
   - `NeedsCaptureClipNode()`:  判断元素是否需要一个用于捕获的剪切属性节点。

4. **控制样式规则的应用:**
   - `StyleRulesToInclude()`:  根据当前过渡状态，决定应该应用哪些样式规则（例如，只应用 UA 样式，还是应用所有样式）。
   - **与 CSS 关系:**  该方法影响浏览器如何解析和应用 CSS 样式，在不同的过渡阶段可能应用不同的样式规则集合。

5. **获取快照根 (Snapshot Root) 的相关信息:**
   - `GetSnapshotRootInFixedViewport()`: 获取快照根在固定视口中的矩形区域。
   - `GetSnapshotRootSize()`: 获取快照根的尺寸。
   - `GetFixedToSnapshotRootOffset()`: 获取固定视口到快照根的偏移量。
   - `GetFrameToSnapshotRootOffset()`: 获取帧到快照根的偏移量。
   - **与 HTML, CSS 关系:** 快照根通常是文档元素，其大小和位置受到 HTML 结构和 CSS 样式的影响，例如视口元标签、`width`、`height` 属性等。

6. **提取视图过渡状态信息:**
   - `GetViewTransitionState()`:  获取当前视图过渡的状态信息，包括元素的位置、大小、捕获的 CSS 属性等。这些信息会被传递到新的文档，用于协调过渡动画。
   - **与 JavaScript 关系:**  这些状态信息最终会通过某种机制传递到 JavaScript 环境，可能用于调试或高级的自定义过渡效果。
   - **假设输入与输出:**
     - **假设输入:**  当前文档中存在一些标记为需要过渡的元素，并且完成了快照捕获阶段。
     - **输出:**  一个 `ViewTransitionState` 对象，包含了这些元素的标签名、在布局空间的边界框、视口矩阵、捕获的 CSS 属性（如 `opacity`、`transform` 等）、以及旧快照的 ID 等信息。

7. **检查快照根的尺寸是否改变:**
   - `SnapshotRootDidChangeSize()`: 判断快照根的尺寸是否与捕获时的尺寸不同。

8. **使样式失效:**
   - `InvalidateStyle()`:  使相关的样式失效，触发重新样式计算，以应用过渡期间的样式。
   - **与 CSS 关系:**  此方法强制浏览器重新解析和应用 CSS 样式，确保在过渡的不同阶段使用正确的样式规则。

9. **提供 UA 样式表:**
   - `UAStyleSheet()`:  生成并返回用于视图过渡的 User-Agent 样式表，包含过渡伪元素的样式和动画定义。
   - **与 CSS 关系:**  此方法动态生成 CSS 样式，用于定义视图过渡期间伪元素 (`::view-transition-group()`, `::view-transition-image-pair()`, 等) 的外观和动画效果。
   - **假设输入与输出:**
     - **假设输入:**  某些元素被标记为需要过渡，并且处于过渡的 `kStarted` 状态。
     - **输出:**  一个 `CSSStyleSheet` 对象，其中包含了针对这些元素的过渡伪元素以及它们的动画定义，例如，针对某个 `view-transition-name` 的元素，会生成类似如下的 CSS 规则：
       ```css
       ::view-transition-group(my-image) {
         isolation: isolate; /* 创建层叠上下文 */
       }
       ::view-transition-image-pair(my-image) {
         position: absolute;
         inset: 0;
         contain: layout paint style;
       }
       ::view-transition-old(my-image) {
         animation: ...;
       }
       ::view-transition-new(my-image) {
         animation: ...;
       }
       ```

10. **判断是否存在新的内容:**
    - `HasLiveNewContent()`: 判断是否已经进入过渡的 `kStarted` 状态，此时表示新的内容已经加载。

11. **使命中测试缓存失效:**
    - `InvalidateHitTestingCache()`:  使命中测试缓存失效，因为在过渡期间可能会动态创建和销毁伪元素，影响命中测试结果。

12. **元素数据的缓存:**
    - `ElementData::CacheStateForOldSnapshot()`: 缓存元素在旧快照时的状态，例如容器属性和 CSS 属性，用于后续的动画计算。

13. **计算元素的视觉溢出区域 (Visual Overflow Rect):**
    - `ComputeVisualOverflowRect()`: 计算元素的视觉溢出区域，这在捕获元素快照时非常重要。
    - **与 CSS 关系:**  该方法考虑了元素的 `overflow` 属性、`clip-path`、`box-shadow` 等 CSS 属性的影响。

14. **生成资源 ID:**
    - `GenerateResourceId()`:  生成用于视图过渡元素的唯一资源 ID。

15. **处理浏览器控件的快照:**
    - `SnapBrowserControlsToFullyShown()`:  在捕获快照前，确保浏览器控件完全显示，以避免在过渡中出现不期望的位移。

**用户或编程常见的使用错误举例:**

* **未正确设置 `view-transition-name`:** 如果在 JavaScript 中启动视图过渡，但忘记在 CSS 中为需要过渡的元素设置 `view-transition-name` 属性，或者设置了相同的名称给不应该共享过渡的元素，会导致过渡效果不符合预期，甚至出错。
    ```javascript
    // JavaScript
    document.startViewTransition(() => {
      // 更新 DOM
    });
    ```
    ```css
    /* 错误示例：两个不相关的图片使用了相同的 view-transition-name */
    .old-image {
      view-transition-name: image-transition;
    }
    .new-image {
      view-transition-name: image-transition;
    }
    ```
* **在过渡期间修改影响布局的关键 CSS 属性:**  如果在视图过渡正在进行时，通过 JavaScript 或其他方式修改了影响元素布局的关键 CSS 属性（例如 `width`、`height`、`position`），可能会导致过渡动画出现跳跃或不流畅的情况，因为浏览器可能需要重新布局。
* **过度依赖 JavaScript 操作过渡元素样式:**  虽然可以在 JavaScript 中操作过渡元素的样式，但过多的手动操作可能会与浏览器自动生成的过渡动画冲突，导致不一致的效果。最佳实践是主要通过 CSS 定义过渡效果，并让浏览器处理大部分的动画细节。
* **在不支持视图过渡的浏览器中使用:**  如果代码没有进行兼容性检查，在不支持视图过渡 API 的浏览器中会报错或没有过渡效果。

总而言之，`ViewTransitionStyleTracker` 在 Chromium Blink 引擎中扮演着至关重要的角色，它负责管理视图过渡过程中元素的样式状态，确保过渡动画的正确渲染和执行，并与 JavaScript、HTML 和 CSS 功能紧密相关，共同实现平滑的页面过渡效果。

### 提示词
```
这是目录为blink/renderer/core/view_transition/view_transition_style_tracker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
;
    if (!animations) {
      return false;
    }

    for (auto& animation_pair : animations->Animations()) {
      auto animation_play_state =
          animation_pair.key->CalculateAnimationPlayState();
      if (animation_play_state == V8AnimationPlayState::Enum::kRunning ||
          animation_play_state == V8AnimationPlayState::Enum::kPaused) {
        return true;
      }
    }
    return false;
  };
  return !!ViewTransitionUtils::FindPseudoIf(*document_, pseudo_has_animation);
}

PaintPropertyChangeType ViewTransitionStyleTracker::UpdateCaptureClip(
    const Element& element,
    const ClipPaintPropertyNodeOrAlias* current_clip,
    const TransformPaintPropertyNodeOrAlias* current_transform) {
  for (auto& entry : element_data_map_) {
    auto& element_data = entry.value;
    if (element_data->target_element != &element) {
      continue;
    }

    ClipPaintPropertyNode::State state(
        *current_transform, *element_data->captured_rect_in_layout_space,
        FloatRoundedRect(*element_data->captured_rect_in_layout_space));

    if (!element_data->clip_node) {
      element_data->clip_node =
          ClipPaintPropertyNode::Create(*current_clip, std::move(state));
#if DCHECK_IS_ON()
      element_data->clip_node->SetDebugName(element.DebugName() +
                                            "ViewTransition");
#endif
      return PaintPropertyChangeType::kNodeAddedOrRemoved;
    }
    return element_data->clip_node->Update(*current_clip, std::move(state));
  }
  NOTREACHED();
}

const ClipPaintPropertyNode* ViewTransitionStyleTracker::GetCaptureClip(
    const Element& element) const {
  for (auto& entry : element_data_map_) {
    auto& element_data = entry.value;
    if (element_data->target_element != &element) {
      continue;
    }
    DCHECK(element_data->clip_node);
    return element_data->clip_node.Get();
  }
  NOTREACHED();
}

bool ViewTransitionStyleTracker::IsTransitionElement(
    const Element& element) const {
  // In stable states, we don't have transition elements.
  if (state_ == State::kIdle || state_ == State::kCaptured)
    return false;

  if (element.IsDocumentElement()) {
    return is_root_transitioning_;
  }

  for (auto& entry : element_data_map_) {
    if (entry.value->target_element == &element) {
      return true;
    }
  }
  return false;
}

bool ViewTransitionStyleTracker::NeedsCaptureClipNode(
    const Element& node) const {
  if (state_ == State::kIdle || state_ == State::kCaptured) {
    return false;
  }

  for (auto& entry : element_data_map_) {
    if (entry.value->target_element != &node) {
      continue;
    }

    DCHECK(!entry.value->captured_rect_in_layout_space.has_value() ||
           !entry.value->target_element->IsDocumentElement())
        << "The root element should never need a clip node";
    return entry.value->captured_rect_in_layout_space.has_value();
  }
  return false;
}

StyleRequest::RulesToInclude ViewTransitionStyleTracker::StyleRulesToInclude()
    const {
  switch (state_) {
    case State::kIdle:
    case State::kCapturing:
    case State::kCaptured:
      return StyleRequest::kUAOnly;
    case State::kStarted:
    case State::kFinished:
      return StyleRequest::kAll;
  }

  NOTREACHED();
}

namespace {

// Returns the outsets applied by browser UI on the fixed viewport that will
// transform it into the snapshot viewport.
gfx::Outsets GetFixedToSnapshotViewportOutsets(Document& document) {
  DCHECK(document.View());
  DCHECK(document.GetPage());
  DCHECK(document.GetFrame());
  DCHECK(document.GetLayoutView());

  int top = 0;
  int right = 0;
  int bottom = 0;
  int left = 0;

  if (document.GetFrame()->IsOutermostMainFrame()) {
    BrowserControls& controls = document.GetPage()->GetBrowserControls();
    // If Blink's size is currently smaller to accommodate the browser controls,
    // outset the snapshot root to include the area occupied by browser
    // controls. Note: for cross-document transitions, this relies on the
    // browser resizing Blink before requesting the outgoing document snapshot.
    if (controls.ShrinkViewport()) {
      top += controls.TopHeight() - controls.TopMinHeight();
      bottom += controls.BottomHeight() - controls.BottomMinHeight();
    }

    bottom += document.GetFrame()
                  ->GetWidgetForLocalRoot()
                  ->GetVirtualKeyboardResizeHeight();
  }

  PhysicalBoxStrut scrollbar_strut =
      document.GetLayoutView()->ComputeScrollbars();
  // A left-side scrollbar (i.e. in an RTL writing-mode) should overlay the
  // snapshot viewport as well. This cannot currently happen in Chrome but it
  // can in other browsers. Handle this case in the event
  // https://crbug.com/249860 is ever fixed.
  // This includes outsets for scrollbar-gutter; both sides could include
  // scrollbar space simultaneously.
  left += scrollbar_strut.left.ToInt();
  right += scrollbar_strut.right.ToInt();
  bottom += scrollbar_strut.bottom.ToInt();
  top += scrollbar_strut.top.ToInt();

  gfx::Outsets outsets;
  outsets.set_top(top);
  outsets.set_right(right);
  outsets.set_bottom(bottom);
  outsets.set_left(left);
  return outsets;
}
}  // namespace

gfx::Rect ViewTransitionStyleTracker::GetSnapshotRootInFixedViewport() const {
  DCHECK(document_->View());
  DCHECK(document_->GetLayoutView());

  LayoutView& layout_view = *document_->GetLayoutView();
  LocalFrameView& frame_view = *document_->View();

  // Start with the position: fixed viewport and expand it by any
  // insetting UI such as the mobile URL bar, virtual-keyboard, scrollbars,
  // etc.
  // TODO(bokan): Differing behavior based on ViewportEnabled is a bit of a
  // kludge but is required since with ViewportEnabled the frame size may
  // actually be larger than than the LayoutView (the ICB) so we must use it.
  // However, LayoutView::ClientWidth/Height is the only way I know to get the
  // correct content size when the frame is inset by a scrollbar-gutter.
  // Luckily these two cases are mutually exclusive: ViewportEnabled is only
  // used with overlay scrollbars which have no gutter, however, it'd be better
  // if we could query a single property directly from layout information.
  gfx::Rect snapshot_viewport_rect =
      document_->GetSettings()->GetViewportEnabled()
          ? gfx::Rect(frame_view.Size().width(), frame_view.Size().height())
          : gfx::Rect(layout_view.ClientWidth().ToInt(),
                      layout_view.ClientHeight().ToInt());
  snapshot_viewport_rect.Outset(GetFixedToSnapshotViewportOutsets(*document_));

  return snapshot_viewport_rect;
}

gfx::Size ViewTransitionStyleTracker::GetSnapshotRootSize() const {
  return GetSnapshotRootInFixedViewport().size();
}

gfx::Vector2d ViewTransitionStyleTracker::GetFixedToSnapshotRootOffset() const {
  return GetSnapshotRootInFixedViewport().OffsetFromOrigin();
}

gfx::Vector2d ViewTransitionStyleTracker::GetFrameToSnapshotRootOffset() const {
  DCHECK(document_->GetLayoutView());
  DCHECK(document_->View());

  gfx::Outsets outsets = GetFixedToSnapshotViewportOutsets(*document_);
  gfx::Vector2d fixed_to_snapshot(-outsets.left(), -outsets.top());

  // A scrollbar (or gutter) on the left or top is placed within the frame but
  // offsets the fixed viewport so remove its size from the fixed-to-snapshot
  // offset to get the frame-to-snapshot offset.
  gfx::Vector2d frame_to_snapshot =
      fixed_to_snapshot +
      document_->GetLayoutView()->OriginAdjustmentForScrollbars();

  return frame_to_snapshot;
}

ViewTransitionState ViewTransitionStyleTracker::GetViewTransitionState() const {
  DCHECK_EQ(state_, State::kCaptured);

  ViewTransitionState transition_state;

  transition_state.device_pixel_ratio = device_pixel_ratio_;
  DCHECK(snapshot_root_layout_size_at_capture_);
  transition_state.snapshot_root_size_at_capture =
      *snapshot_root_layout_size_at_capture_;

  for (const auto& entry : element_data_map_) {
    const auto& element_data = entry.value;
    DCHECK(element_data->container_properties.has_value());

    auto& element = transition_state.elements.emplace_back();
    element.tag_name = entry.key.Utf8();
    element.border_box_rect_in_enclosing_layer_css_space =
        gfx::RectF(element_data->container_properties
                       ->border_box_rect_in_enclosing_layer_css_space);
    element.viewport_matrix =
        element_data->container_properties->snapshot_matrix;
    if (const auto& box_geometry =
            element_data->container_properties->box_geometry) {
      element
          .layered_box_properties = ViewTransitionElement::LayeredBoxProperties{
          .content_box = gfx::RectF(box_geometry->content_box),
          .padding_box = gfx::RectF(box_geometry->padding_box),
          .box_sizing =
              box_geometry->box_sizing == EBoxSizing::kContentBox
                  ? mojom::blink::ViewTransitionElementBoxSizing::kContentBox
                  : mojom::blink::ViewTransitionElementBoxSizing::kBorderBox};
    }
    element.overflow_rect_in_layout_space =
        gfx::RectF(element_data->visual_overflow_rect_in_layout_space);

    element.snapshot_id = element_data->old_snapshot_id;
    element.paint_order = element_data->element_index;
    element.captured_rect_in_layout_space =
        element_data->captured_rect_in_layout_space;

    FlatMapBuilder<mojom::blink::ViewTransitionPropertyId, std::string>
        css_property_builder(element_data->captured_css_properties.size());
    for (const auto& [id, value] : element_data->captured_css_properties) {
      css_property_builder.Insert(ToTranstionPropertyId(id), value.Utf8());
    }
    element.captured_css_properties = std::move(css_property_builder).Finish();
    for (const auto& class_name : element_data->class_list) {
      element.class_list.push_back(class_name.Utf8());
    }
    element.containing_group_name =
        element_data->containing_group_name
            ? element_data->containing_group_name.Utf8()
            : "";
  }

  // Preserve the transition id for the new document.
  transition_state.transition_token = transition_token_;

  // To ensure the any new resources generated by the new document don't
  // collide in id with this document's resources, pass the next sequence id so
  // the new document can continue the sequence.
  transition_state.next_element_resource_id = GenerateResourceId().local_id();

  if (subframe_snapshot_layer_) {
    transition_state.subframe_snapshot_id =
        subframe_snapshot_layer_->ViewTransitionResourceId();
  }

  state_extracted_ = true;

  // TODO(khushalsagar): Need to send offsets to retain positioning of
  // ::view-transition.

  return transition_state;
}

bool ViewTransitionStyleTracker::SnapshotRootDidChangeSize() const {
  if (!snapshot_root_layout_size_at_capture_.has_value()) {
    return false;
  }

  gfx::Size current_size = GetSnapshotRootSize();

  // Allow 1px of diff since the snapshot root can be adjusted by
  // viewport-resizing UI (e.g. the virtual keyboard insets the viewport but
  // then outsets the viewport rect to get the snapshot root). These
  // adjustments can be off by a pixel due to different pixel snapping.
  if (std::abs(snapshot_root_layout_size_at_capture_->width() -
               current_size.width()) <= 1 &&
      std::abs(snapshot_root_layout_size_at_capture_->height() -
               current_size.height()) <= 1) {
    return false;
  }

  return true;
}

void ViewTransitionStyleTracker::InvalidateStyle() {
  ua_style_sheet_ = nullptr;

  if (auto* originating_element = document_->documentElement()) {
    originating_element->SetNeedsStyleRecalc(
        kLocalStyleChange, StyleChangeReasonForTracing::Create(
                               style_change_reason::kViewTransition));
  }

  auto invalidate_style = [](PseudoElement* pseudo_element) {
    pseudo_element->SetNeedsStyleRecalc(
        kLocalStyleChange, StyleChangeReasonForTracing::Create(
                               style_change_reason::kViewTransition));
  };
  ViewTransitionUtils::ForEachTransitionPseudo(*document_, invalidate_style);

  // Invalidate layout view compositing properties.
  if (auto* layout_view = document_->GetLayoutView()) {
    layout_view->SetNeedsPaintPropertyUpdate();
  }

  for (auto& entry : element_data_map_) {
    if (!entry.value->target_element ||
        entry.value->target_element->IsDocumentElement()) {
      continue;
    }

    // We need to recalc style on each of the target elements, because we store
    // whether the element is a view transition participant on the computed
    // style. InvalidateStyle() is an indication that this state may have
    // changed.
    entry.value->target_element->SetNeedsStyleRecalc(
        kLocalStyleChange, StyleChangeReasonForTracing::Create(
                               style_change_reason::kViewTransition));

    auto* object = entry.value->target_element->GetLayoutObject();
    if (!object)
      continue;

    // We propagate the view transition element id on an effect node for the
    // object. This means that we should update the paint properties to update
    // the view transition element id.
    object->SetNeedsPaintPropertyUpdate();

    // All elements participating in a transition are forced to become stacking
    // contexts. This state may change when the transition ends.
    if (auto* layer = object->EnclosingLayer()) {
      layer->DirtyStackingContextZOrderLists();
    }
  }

  document_->GetDisplayLockDocumentState()
      .NotifyViewTransitionPseudoTreeChanged();
}

CSSStyleSheet& ViewTransitionStyleTracker::UAStyleSheet() {
  if (ua_style_sheet_)
    return *ua_style_sheet_;

  // Animations are added in the start phase of the transition.
  // Note that the cached ua_style_sheet_ above is invalidated when |state_|
  // moves to kStarted stage to generate a new stylesheet including styles for
  // animations.
  const bool add_animations = state_ == State::kStarted;

  ViewTransitionStyleBuilder builder;
  builder.AddUAStyle(StaticUAStyles());
  if (add_animations)
    builder.AddUAStyle(AnimationUAStyles());

  for (auto& entry : element_data_map_) {
    const auto& view_transition_name = entry.key.GetString();
    auto& element_data = entry.value;

    // TODO(vmpstr): We will run a style resolution before the first time we get
    // a chance to update our rendering in RunPostPrePaintSteps. There is no
    // point in adding any styles here, because those will be wrong. The TODO
    // here is to skip this step earlier, instead of per each element.
    if (!element_data->container_properties) {
      continue;
    }

    gfx::Transform old_parent_inverse_transform;
    gfx::Transform new_parent_inverse_transform;
    if (element_data->containing_group_name && HasLiveNewContent()) {
      CHECK(element_data_map_.Contains(element_data->containing_group_name));
      const auto& containing_group_data =
          element_data_map_.at(element_data->containing_group_name);
      old_parent_inverse_transform =
          containing_group_data->cached_container_properties.snapshot_matrix
              .InverseOrIdentity();

      old_parent_inverse_transform.Translate(
          -containing_group_data->cached_container_properties.BorderOffset());

      if (containing_group_data->container_properties) {
        const auto& new_container_properties =
            *containing_group_data->container_properties;
        new_parent_inverse_transform =

            new_container_properties.snapshot_matrix.InverseOrIdentity();
        new_parent_inverse_transform.Translate(
            -new_container_properties.BorderOffset());
      }
    }

    // This updates the styles on the pseudo-elements as described in
    // https://drafts.csswg.org/css-view-transitions-1/#style-transition-pseudo-elements-algorithm.
    builder.AddContainerStyles(
        view_transition_name, *element_data->container_properties,
        element_data->captured_css_properties, new_parent_inverse_transform);

    // This sets up the styles to animate the pseudo-elements as described in
    // https://drafts.csswg.org/css-view-transitions-1/#setup-transition-pseudo-elements-algorithm.
    if (add_animations) {
      CHECK(element_data->old_snapshot_id.IsValid() ||
            element_data->new_snapshot_id.IsValid());

      auto type = ViewTransitionStyleBuilder::AnimationType::kBoth;
      if (!element_data->old_snapshot_id.IsValid()) {
        type = ViewTransitionStyleBuilder::AnimationType::kNewOnly;
      } else if (!element_data->new_snapshot_id.IsValid()) {
        type = ViewTransitionStyleBuilder::AnimationType::kOldOnly;
      }

      builder.AddAnimations(type, view_transition_name,
                            element_data->cached_container_properties,
                            element_data->cached_animated_css_properties,
                            old_parent_inverse_transform);
    }
  }

  // We can't use the default UA parser, because it doesn't work for CSS URLs.
  // Filters & clip-path can have local (#) URLs and are copied into a UA
  // stylesheet, So we need to parse the stylesheet with a base URL override.
  auto* ua_parser_context = MakeGarbageCollected<CSSParserContext>(
      kUASheetMode, SecureContextMode::kInsecureContext);

  auto* ua_parser_context_with_base_url =
      MakeGarbageCollected<CSSParserContext>(
          ua_parser_context, document_->BaseURL(),
          ua_parser_context->IsOriginClean(), ua_parser_context->GetReferrer(),
          ua_parser_context->Charset(), nullptr);

  auto* sheet =
      MakeGarbageCollected<StyleSheetContents>(ua_parser_context_with_base_url);
  sheet->ParseString(builder.Build());
  ua_style_sheet_ = MakeGarbageCollected<CSSStyleSheet>(sheet);
  return *ua_style_sheet_;
}

bool ViewTransitionStyleTracker::HasLiveNewContent() const {
  return state_ == State::kStarted;
}

void ViewTransitionStyleTracker::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(element_data_map_);
  visitor->Trace(pending_transition_element_names_);
  visitor->Trace(ua_style_sheet_);
}

void ViewTransitionStyleTracker::InvalidateHitTestingCache() {
  // Hit-testing data is cached based on the current DOM version. Normally, this
  // version is incremented any time there is a DOM modification or an attribute
  // change to some element (which can result in a new style). However, with
  // view transitions, we dynamically create and destroy hit-testable
  // pseudo elements based on the current state. This means that we have to
  // manually modify the DOM tree version since there is no other mechanism that
  // will do it.
  document_->IncDOMTreeVersion();
}

void ViewTransitionStyleTracker::ElementData::Trace(Visitor* visitor) const {
  visitor->Trace(target_element);
  visitor->Trace(clip_node);
}

// TODO(vmpstr): We need to write tests for the following:
// * A local transform on the transition element.
// * A transform on an ancestor which changes its screen space transform.
gfx::RectF ViewTransitionStyleTracker::ElementData::GetInkOverflowRect(
    bool use_cached_data) const {
  return gfx::RectF(use_cached_data
                        ? cached_visual_overflow_rect_in_layout_space
                        : visual_overflow_rect_in_layout_space);
}

gfx::RectF ViewTransitionStyleTracker::ElementData::GetCapturedSubrect(
    bool use_cached_data) const {
  if (RuntimeEnabledFeatures::ViewTransitionOverflowRectFromSurfaceEnabled() &&
      use_cached_data) {
    return GetInkOverflowRect(true);
  }
  auto captured_rect = use_cached_data ? cached_captured_rect_in_layout_space
                                       : captured_rect_in_layout_space;
  return captured_rect.value_or(GetInkOverflowRect(use_cached_data));
}

gfx::RectF ViewTransitionStyleTracker::ElementData::GetReferenceRect(
    bool use_cached_data,
    float device_scale_factor) const {
  // TODO(vmpstr): Make container_properties a non-vector non-optional member.
  if (!use_cached_data && !container_properties) {
    return gfx::RectF();
  }
  const auto& properties =
      use_cached_data ? cached_container_properties : *container_properties;
  PhysicalRect rect = properties.border_box_rect_in_enclosing_layer_css_space;
  if (properties.box_geometry) {
    rect = properties.box_geometry->content_box;
    rect.Move(properties.border_box_rect_in_enclosing_layer_css_space.offset);
  }
  rect.Scale(device_scale_factor);
  return gfx::RectF(rect);
}

bool ViewTransitionStyleTracker::ElementData::
    ShouldPropagateVisualOverflowRectAsMaxExtentsRect() const {
  return RuntimeEnabledFeatures::
             ViewTransitionOverflowRectFromSurfaceEnabled() &&
         target_element && !target_element->IsDocumentElement();
}

void ViewTransitionStyleTracker::ElementData::CacheStateForOldSnapshot() {
  if (container_properties) {
    cached_container_properties = *container_properties;
  }
  cached_visual_overflow_rect_in_layout_space =
      visual_overflow_rect_in_layout_space;
  cached_captured_rect_in_layout_space = captured_rect_in_layout_space;

  FlatMapBuilder<CSSPropertyID, String> builder(
      std::size(kPropertiesToAnimate));
  for (auto& id : kPropertiesToAnimate) {
    auto it = captured_css_properties.find(id);
    if (it != captured_css_properties.end()) {
      builder.Insert(it->first, it->second);
    }
  }
  cached_animated_css_properties = std::move(builder).Finish();
}

// TODO(vmpstr): This could be optimized by caching values for individual layout
// boxes. However, it's unclear when the cache should be cleared.
PhysicalRect ViewTransitionStyleTracker::ComputeVisualOverflowRect(
    LayoutBoxModelObject& box,
    const LayoutBoxModelObject* ancestor) const {
  DCHECK(!box.IsLayoutView());
  if (RuntimeEnabledFeatures::ViewTransitionOverflowRectFromSurfaceEnabled()) {
    // In this mode, we don't try to compute the pixel-precise capture rect.
    // Instead, we compute the max extents: a rect that's close enough to that
    // rect and contains it. This rect is used for clipping computation in CC.
    // When displaying live content, ViewTransitionContentImpl would later
    // "correct" this rect to the actual capture rect that's computed inside CC.
    // Note that this rect is in enclosing layer space, to match the CC
    // coordinate space. So the border box rect also has to be in the same
    // coordinate space.
    auto rect = box.EnclosingLayer()
                    ->LocalBoundingBoxIncludingSelfPaintingDescendants();
    if (!ViewTransitionUtils::UseLayeredCapture(box.StyleRef())) {
      rect = box.ApplyFiltersToRect(rect);
    }

    // Correct for fractional offset.
    rect.Move(box.FirstFragment().PaintOffset());
    return PhysicalRect(ToEnclosingRect(rect));
  }

  if (ancestor) {
    if (auto* element = DynamicTo<Element>(box.GetNode());
        element && IsTransitionElement(*element)) {
      return {};
    }
  }

  const bool visible = box.StyleRef().Visibility() == EVisibility::kVisible ||
                       !box.VisualRectRespectsVisibility();
  const bool layered_effects_contribute_to_visual_overflow =
      ancestor || !ViewTransitionUtils::UseLayeredCapture(box.StyleRef());
  PhysicalRect result;

  if (layered_effects_contribute_to_visual_overflow) {
    if (auto clip_path_bounds =
            ClipPathClipper::LocalClipPathBoundingBox(box)) {
      // TODO(crbug.com/40840594): This is just the bounds of the clip-path, as
      // opposed to the intersection between the clip-path and the border box
      // bounds. This seems suboptimal, but that's the rect that we use further
      // down the pipeline to generate the texture.
      // TODO(khushalsagar): This doesn't account for CSS clip property.
      if (visible) {
        result = PhysicalRect::EnclosingRect(*clip_path_bounds);
        if (ancestor) {
          box.MapToVisualRectInAncestorSpace(ancestor, result,
                                             kUseGeometryMapper);
        }
      }

      return result;
    }
  }

  auto* paint_layer = box.Layer();
  if (!paint_layer || (!box.ChildPaintBlockedByDisplayLock() &&
                       !paint_layer->KnownToClipSubtreeToPaddingBox())) {
    const LayoutBoxModelObject* ancestor_for_recursion =
        ancestor ? ancestor : &box;
    for (auto* child = box.SlowFirstChild(); child;
         child = child->NextSibling()) {
      // Recurse for every child. Doing a paint walk here is insufficient
      // because of visibility considerations on each layout object. See
      // crbug.com/1458568 for more details.
      if (auto* child_box = DynamicTo<LayoutBoxModelObject>(child)) {
        PhysicalRect mapped_overflow_rect =
            ComputeVisualOverflowRect(*child_box, ancestor_for_recursion);
        result.Unite(mapped_overflow_rect);
      } else if (auto* child_text = DynamicTo<LayoutText>(child)) {
        if (box.IsLayoutInline()) {
          continue;
        }

        const bool child_visible =
            child_text->StyleRef().Visibility() == EVisibility::kVisible ||
            !child_text->VisualRectRespectsVisibility();
        if (!child_visible) {
          continue;
        }

        auto overflow_rect = child_text->VisualOverflowRect();
        child_text->MapToVisualRectInAncestorSpace(
            ancestor_for_recursion, overflow_rect, kUseGeometryMapper);
        result.Unite(overflow_rect);
      }
    }
  }

  PhysicalRect overflow_rect;
  if (visible) {
    if (auto* layout_box = DynamicTo<LayoutBox>(box)) {
      overflow_rect = layout_box->PhysicalBorderBoxRect();
      if (layout_box->StyleRef().HasVisualOverflowingEffect()) {
        PhysicalBoxStrut outsets =
            layout_box->ComputeVisualEffectOverflowOutsets();
        overflow_rect.Expand(outsets);
      }
    } else {
      overflow_rect = To<LayoutInline>(box).LinesVisualOverflowBoundingBox();
    }
  }

  if (ancestor) {
    // For any recursive call, we map our overflow rect into the
    // ancestor space and combine that with the result. GeometryMapper should
    // take care of any filters and clips that are necessary between this box
    // and the ancestor.
    if (visible) {
      box.MapToVisualRectInAncestorSpace(ancestor, overflow_rect,
                                         kUseGeometryMapper);
      result.Unite(overflow_rect);
    }
  } else {
    // We're at the root of the recursion, so clip self painting descendant
    // overflow by the overflow clip rect, then add in the visual overflow (with
    // filters) from the own painting layer.
    if (auto* layout_box = DynamicTo<LayoutBox>(&box);
        layout_box && layout_box->ShouldClipOverflowAlongEitherAxis()) {
      result.Intersect(layout_box->OverflowClipRect(PhysicalOffset()));
    } else if (auto* layout_inline = DynamicTo<LayoutInline>(box)) {
      // We need the `overflow_rect` to be relative to the inline's
      // border-box. However, `LayoutInline::LinesVisualOverflowBoundingBox()`
      // is relative to the inline's container's border-box. The offset below
      // removes the translation between the container's border-box and the
      // inline's border-box.
      //
      // This mapping is done internally by
      // `LayoutObject::MapToVisualRectInAncestorSpace` so its not necessary
      // when computing overflow for an ancestor.
      overflow_rect.Move(-layout_inline->PhysicalLinesBoundingBox().offset);
    }

    if (visible) {
      result.Unite(overflow_rect);
    }

    if (layered_effects_contribute_to_visual_overflow) {
      result = box.ApplyFiltersToRect(result);
    }

    // TODO(crbug.com/1432868): This captures a couple of common cases --
    // box-shadow and no box shadow on the element. However, this isn't at all
    // comprehensive. The paint system determines per element whether it
    // should pixel snap or enclosing rect or something else. We need to think
    // of a better way to fix this for all cases.
    result.Move(box.FirstFragment().PaintOffset());
    if (visible && box.StyleRef().BoxShadow()) {
      result = PhysicalRect(ToEnclosingRect(result));
    } else {
      result = PhysicalRect(ToPixelSnappedRect(result));
    }
  }
  return result;
}

const char* ViewTransitionStyleTracker::StateToString(State state) {
  switch (state) {
    case State::kIdle:
      return "Idle";
    case State::kCapturing:
      return "Capturing";
    case State::kCaptured:
      return "Captured";
    case State::kStarted:
      return "Started";
    case State::kFinished:
      return "Finished";
  }
  NOTREACHED();
}

viz::ViewTransitionElementResourceId
ViewTransitionStyleTracker::GenerateResourceId() const {
  // If we've already send the state to the incoming document, generating a new
  // ID now would collide with IDs generated by that document.
  CHECK(!state_extracted_);
  auto* supplement = ViewTransitionSupplement::FromIfExists(*document_);
  CHECK(supplement);
  return supplement->GenerateResourceId(transition_token_);
}

void ViewTransitionStyleTracker::SnapBrowserControlsToFullyShown() {
  CHECK(document_->GetFrame()->IsOutermostMainFrame());
  BrowserControls& controls = document_->GetPage()->GetBrowserControls();
  ScrollableArea& root_scroller = *document_->View()->GetScrollableArea();

  // If (and only if) the page is scrolled to a non-0 offset, the top controls
  // animation keeps content from moving by producing a "counter-scroll" as the
  // controls animate. Preemptively perform this counter-scroll now, so that it
  // is included when snapshot transforms are computed.
  if (root_scroller.ScrollPosition().y()) {
    float counter_scroll = controls.TopHeight() - controls.ContentOffset();

    // Without FractionalScrollOffsets, the compositor commits only integer
    // values of scroll delta, but it always sends exact browser controls
    // delta. This means our computed counter-scroll does not include the
    // fractional part remaining in the compositor delta. The full counter
    // scroll will be an integer, since the compositor rounds the sent
    // offset, we round the counter-scroll as well which snaps it in the
    // opposing direction the compositor snapped to account for the missing
    // (or additional) pixel in the compositor's committed delta.
    if (!RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled()) {
      counter_scroll = base::ClampRound(counter_scroll);
    }

    // Fully show the controls also ensures scroll bounds can accommodate the
    // counter-scroll so do this before scrolling.
    controls.SetShownRatio(1, 1);
    root_scroller.ScrollBy(ScrollOffset(0, counter_scroll),
                           mojom::blink::ScrollType::kCompositor);

    // The next commit should overwrite any scrolling that occurred on the
    // compositor thread since it last committed values. Since the compositor
    // may still be animating the browser controls, and we add the full
    // controls distance here, any deltas that have occurred since this
    // BeginMainFrame would be double-applied. More generally, the snapshot
    // transform matrices will be computed in this Blink frame; any deltas
    // that have occurred on the compositor since this frame was issued won't
    // be accounted for in snapshot transforms.
    root_scroller.DropCompositorScrollDeltaNextCommit();
  } else {
    controls.SetShownRatio(1, 1);
  }
}

}  // namespace blink
```