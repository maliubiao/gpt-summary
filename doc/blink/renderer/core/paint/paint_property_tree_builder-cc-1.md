Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of the `blink/renderer/core/paint/paint_property_tree_builder.cc` file in the Chromium Blink engine. This is the second part of a larger code block.

Here's a breakdown of how to approach this:

1. **Identify the Core Task:** The file name hints at building "paint property trees". This snippet likely contributes to that process.

2. **Examine Key Functions:** Look for functions with descriptive names and analyze their purpose. Focus on how they manipulate or create property tree nodes.

3. **Trace Data Flow:**  Observe how data is passed and modified within the functions. Pay attention to variables like `properties_`, `context_`, and the different types of paint property nodes (e.g., `TransformPaintPropertyNode`, `EffectPaintPropertyNode`).

4. **Look for Conditionals:**  Understand the conditions under which different actions are taken. This often involves checking flags like `NeedsPaintPropertyUpdate()`, `NeedsTransformForSVGChild()`, and comparing compositing reasons.

5. **Connect to Web Concepts:** Relate the code's actions to CSS properties, HTML elements, and JavaScript interactions (like animations).

6. **Infer Assumptions and Outputs:**  Based on the code's logic, hypothesize what inputs would lead to specific outputs or modifications in the property tree.

7. **Consider User Errors:** Think about common mistakes developers might make in their HTML/CSS/JS that would cause this code to be executed in specific ways or reveal potential issues.

8. **Determine User Actions:**  Imagine the user interactions that would trigger the rendering process and lead to the execution of this code.

9. **Focus on the Given Snippet (Part 2):**  Since this is part 2, understand how it builds upon or relates to the (unseen) first part and sets the stage for the subsequent parts.

**Mental Walkthrough of the Code Snippet:**

* **Sticky Positioning:** The code handles sticky positioning (`UpdateStickyTranslation`). It calculates constraints based on the `layout_constraint` and creates a `CompositorStickyConstraint`. This is directly related to the CSS `position: sticky;` property.
* **Anchor Positioning:**  The code manages anchor positioning (`UpdateAnchorPositionScrollTranslation`). It calculates a translation offset based on `AnchorPositionScrollData`. This is related to the CSS anchor positioning features.
* **Direct Compositing Updates:** Functions like `DirectlyUpdateCcTransform` and `DirectlyUpdateCcOpacity` suggest optimization strategies for updating properties on the compositor thread, especially for animations.
* **SVG Transforms:** There's specific handling for SVG elements (`UpdateTransformForSVGChild`), recognizing that SVG transforms work differently than HTML transforms.
* **Individual Transform Properties:**  The `UpdateIndividualTransform` function is a generic way to handle `translate`, `rotate`, `scale`, and `transform` CSS properties. It checks if the property is needed, computes the transformation matrix, and updates the `TransformPaintPropertyNode`.
* **Effect Nodes:** The code checks for conditions requiring an "effect node" (`NeedsEffect`), which relates to properties like `opacity`, `blend-mode`, `filter`, and `mask`.
* **Clip Paths:** There's logic related to `clip-path` (`NeedsClipPathClipOrMask`).
* **View Transitions:** The code deals with view transitions (`NeedsEffectForViewTransition`).

**Synthesizing the Summary for Part 2:**

Based on the analysis, Part 2 seems heavily focused on updating the *transform* and *effect* parts of the paint property tree. It handles different types of transforms (CSS `transform`, individual transforms like `translate`, `rotate`, `scale`, and SVG transforms) and determines when an effect node is necessary due to properties like opacity, blend modes, filters, masks, and view transitions. It also handles sticky and anchor positioning, which involve transformations related to scrolling.
Based on the provided code snippet, here's a summary of the functionalities implemented in this part of `paint_property_tree_builder.cc`:

**Core Functionality:**

This section of the code primarily focuses on **updating the transform and effect properties** within the paint property tree. It determines when and how to create or modify `TransformPaintPropertyNode` and `EffectPaintPropertyNode` based on various factors like CSS properties, animations, and compositing reasons.

**Specific Functionalities:**

* **Updating Sticky Positioning Transforms (`UpdateStickyTranslation`)**:
    * Detects if an element has sticky positioning and if its containing scroll container scrolls.
    * Creates a `CompositorStickyConstraint` object to store detailed information about the sticky behavior, including offsets, anchor status (left, right, top, bottom), and the rectangles of the constraining and sticky boxes relative to the scroll container.
    * Identifies the nearest ancestor that shifts the sticky layer for proper compositor integration.
    * Updates the transform property with the sticky translation.

* **Updating Anchor Position Scroll Translations (`UpdateAnchorPositionScrollTranslation`)**:
    * Checks if an element requires anchor position scroll translation (related to the `anchor()` CSS function).
    * Calculates the necessary translation offset based on the accumulated adjustments from the anchor positioning.
    * Creates a `cc::AnchorPositionScrollData` object to store information about the scroll adjustments and the relevant scroll containers.
    * Updates the transform property with the anchor position scroll translation.

* **Optimizing Compositor Updates (`DirectlyUpdateCcTransform`, `DirectlyUpdateCcOpacity`)**:
    * Implements optimizations to directly update the associated compositor transform or opacity node when only simple values have changed (e.g., during animations) without needing a full property tree rebuild. This improves performance.

* **Handling SVG Transforms (`UpdateTransformForSVGChild`)**:
    * Provides specific logic for updating transforms on SVG child elements, which have different transform mechanisms compared to HTML elements.
    * Calculates the transform matrix based on `LocalToSVGParentTransform()`.
    * Creates a `TransformPaintPropertyNode` specifically for SVG transforms.

* **Updating Individual Transform Properties (`UpdateIndividualTransform`)**:
    * A generic function used to update specific transform properties like `translate`, `rotate`, `scale`, and `offset`.
    * Takes function pointers to determine if the property is needed and how to compute the transformation matrix.
    * Creates or updates a `TransformPaintPropertyNode` for the specific transform.

* **Updating `translate` (`UpdateTranslate`)**:
    * Uses `UpdateIndividualTransform` to handle the CSS `translate` property.

* **Updating `rotate` (`UpdateRotate`)**:
    * Uses `UpdateIndividualTransform` to handle the CSS `rotate` property.

* **Updating `scale` (`UpdateScale`)**:
    * Uses `UpdateIndividualTransform` to handle the CSS `scale` property.

* **Updating `offset` (`UpdateOffset`)**:
    * Uses `UpdateIndividualTransform` to handle the CSS `offset-path` and related properties.

* **Updating `transform` (`UpdateTransform`)**:
    * Uses `UpdateIndividualTransform` to handle the general CSS `transform` property.
    * Manages the `rendering_context_id` based on `transform-style: preserve-3d`.
    * Clears any pending transform updates for the object.

* **Determining the Need for Clip Paths, Clips, or Masks (`NeedsClipPathClipOrMask`)**:
    * Checks if a `LayoutObject` requires a clip-path, considering animated clip paths and static clip paths on elements with layers or as SVG children.

* **Determining the Need for Effect Nodes (`NeedsEffect`, `NeedsEffectIgnoringClipPath`, `NeedsEffectForViewTransition`)**:
    * Evaluates various CSS properties and conditions to determine if an `EffectPaintPropertyNode` is needed for an element. This includes:
        * Direct compositing reasons.
        * Isolated stacking contexts and blend modes.
        * Backdrop filters.
        * Opacity.
        * Masks.
        * View Transition names.
        * Mask-based clip paths.

* **Determining if Effect Can Use Current Clip as Output Clip (`EffectCanUseCurrentClipAsOutputClip`)**:
    * Checks if the current clip can be used as the output clip for the effect node, which can optimize later rendering stages.

**Relationship to JavaScript, HTML, and CSS:**

This code directly implements the logic for how CSS properties related to transformations, effects, and positioning are translated into the internal representation used for rendering in Blink.

* **CSS Properties:**
    * **Transformations:** `transform`, `translate`, `rotate`, `scale`, `transform-origin`, `transform-style`, `backface-visibility`, `offset-path`, `offset-position`, `offset-rotate`.
    * **Effects:** `opacity`, `blend-mode`, `filter`, `backdrop-filter`, `mask`, `clip-path`.
    * **Positioning:** `position: sticky;`, anchor positioning properties (`anchor-name`, `anchor-scroll`, etc.).
    * **View Transitions:** `view-transition-name`.

* **HTML Elements:**  The code operates on `LayoutObject` instances, which represent the render tree nodes corresponding to HTML elements. The logic varies depending on the type of element (e.g., SVG elements have special handling).

* **JavaScript:** JavaScript can trigger changes to CSS properties through direct manipulation or animations. This code is responsible for reacting to these changes and updating the paint property tree accordingly. For example:
    * **CSS Animations and Transitions:** The code checks for active transform and other property animations (`HasActiveTransformAnimation`, `IsRunningTransformAnimationOnCompositor`).
    * **JavaScript manipulation of style:** When JavaScript modifies style properties, the rendering pipeline, including this code, will be triggered to reflect those changes.

**Examples:**

* **CSS `transform: rotate(45deg);` on a `<div>`:** The `UpdateTransform` or `UpdateRotate` functions would be called. The code would calculate the rotation matrix and update the `TransformPaintPropertyNode` for that `<div>`.

* **CSS `position: sticky; top: 10px;` on a `<header>` inside a scrollable `<div>`:** The `UpdateStickyTranslation` function would be executed. The `CompositorStickyConstraint` would store the `top_offset` as 10px, and the `is_anchored_top` flag would be true.

* **CSS `opacity: 0.5;` on an `<img>`:** The `NeedsEffect` function would return true, and an `EffectPaintPropertyNode` would be created or updated with the opacity value.

* **CSS `clip-path: circle(50%);` on a `<span>`:** The `NeedsClipPathClipOrMask` function would return true, and a clip would be associated with the `EffectPaintPropertyNode` (or potentially a separate clip node).

* **JavaScript animation using `element.animate()` to change the `transform` property:** The `DirectlyUpdateCcTransform` optimization might be used if only simple transform values are changing, directly updating the compositor's representation without a full rebuild.

**Assumed Input and Output (Illustrative for a single function):**

**Function:** `UpdateStickyTranslation`

**Hypothetical Input:**

* A `LayoutBox` representing a `<header>` element with `position: sticky; top: 20px;`.
* The `LayoutConstraint` for this element indicates that it's within a scrollable container.
* `context_.current.scroll` indicates that the scroll container has been scrolled.

**Hypothetical Output:**

* A `CompositorStickyConstraint` object is created and associated with the element's paint properties.
* This object has:
    * `is_anchored_top = true`
    * `top_offset = 20.0f`
    * Other relevant constraint information populated based on the layout.
* The `TransformPaintPropertyNode` for the element is updated to reflect the sticky positioning translation based on the scroll offset.

**Common User/Programming Errors and How They Might Lead Here:**

* **Incorrect or Missing `position: relative` on an ancestor of a `position: sticky` element:**  The sticky behavior might not work as expected. While this code handles the creation of the sticky constraint, layout calculations in other parts of the engine might be affected.

* **Complex CSS Animations on Transforms:**  While the direct update optimizations are in place, excessively complex or poorly performing animations could lead to frequent updates in this code, potentially causing jank or performance issues.

* **Conflicting Transform Properties:**  Setting multiple transform properties that interfere with each other might lead to unexpected results. This code will process each property update, but the final rendered output might not be what the developer intended.

* **Using unsupported or experimental CSS properties:** If a developer uses a CSS property that is not fully implemented or has bugs, the behavior within this code might be incorrect or unexpected.

**User Operations as Debugging Clues:**

If you are debugging issues related to transformations, effects, or sticky positioning, tracing the execution flow through this file can be crucial. Here's how user actions could lead to this code:

1. **Page Load:**  When a web page is loaded, the rendering engine parses the HTML and CSS. The initial layout and paint pass will involve this code to build the initial paint property tree.

2. **Scrolling:**  When a user scrolls a page containing sticky elements, the `UpdateStickyTranslation` function will be called repeatedly to update the transform of the sticky elements based on the scroll position.

3. **CSS Property Changes (via JavaScript or CSS Transitions/Animations):**
    * If JavaScript modifies the `transform`, `opacity`, `clip-path`, or other relevant CSS properties, this code will be invoked to update the paint property tree.
    * CSS transitions or animations will also trigger updates in this code as the animated values change over time.

4. **Resizing the Browser Window:** Resizing can trigger layout changes, which might necessitate updates to transform properties, especially for elements with responsive designs or sticky positioning.

5. **Interactions that Trigger Reflow/Repaint:**  User actions like hovering over elements (triggering pseudo-class changes), focusing on form fields, or other dynamic interactions can lead to repaints, potentially involving updates within this file.

By understanding how user actions trigger the rendering pipeline and how this specific file contributes to building the paint property tree, developers can gain valuable insights for debugging rendering-related issues in Chromium.

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
urrent.scroll;
        if (scroll_container_scrolls) {
          auto constraint = std::make_unique<CompositorStickyConstraint>();
          constraint->is_anchored_left =
              layout_constraint->left_inset.has_value();
          constraint->is_anchored_right =
              layout_constraint->right_inset.has_value();
          constraint->is_anchored_top =
              layout_constraint->top_inset.has_value();
          constraint->is_anchored_bottom =
              layout_constraint->bottom_inset.has_value();

          constraint->left_offset =
              layout_constraint->left_inset.value_or(LayoutUnit()).ToFloat();
          constraint->right_offset =
              layout_constraint->right_inset.value_or(LayoutUnit()).ToFloat();
          constraint->top_offset =
              layout_constraint->top_inset.value_or(LayoutUnit()).ToFloat();
          constraint->bottom_offset =
              layout_constraint->bottom_inset.value_or(LayoutUnit()).ToFloat();
          constraint->constraint_box_rect =
              gfx::RectF(layout_constraint->constraining_rect);
          constraint->scroll_container_relative_sticky_box_rect = gfx::RectF(
              layout_constraint->scroll_container_relative_sticky_box_rect);
          constraint->scroll_container_relative_containing_block_rect =
              gfx::RectF(layout_constraint
                             ->scroll_container_relative_containing_block_rect);
          if (const LayoutBoxModelObject* sticky_box_shifting_ancestor =
                  layout_constraint->nearest_sticky_layer_shifting_sticky_box) {
            constraint->nearest_element_shifting_sticky_box =
                CompositorElementIdFromUniqueObjectId(
                    sticky_box_shifting_ancestor->UniqueId(),
                    CompositorElementIdNamespace::kStickyTranslation);
          }
          if (const LayoutBoxModelObject* containing_block_shifting_ancestor =
                  layout_constraint
                      ->nearest_sticky_layer_shifting_containing_block) {
            constraint->nearest_element_shifting_containing_block =
                CompositorElementIdFromUniqueObjectId(
                    containing_block_shifting_ancestor->UniqueId(),
                    CompositorElementIdNamespace::kStickyTranslation);
          }
          state.sticky_constraint = std::move(constraint);
        }
      }

      OnUpdateTransform(properties_->UpdateStickyTranslation(
          *context_.current.transform, std::move(state)));
    } else {
      OnClearTransform(properties_->ClearStickyTranslation());
    }
  }

  if (properties_->StickyTranslation())
    context_.current.transform = properties_->StickyTranslation();
}

void FragmentPaintPropertyTreeBuilder::UpdateAnchorPositionScrollTranslation() {
  DCHECK(properties_);
  if (NeedsPaintPropertyUpdate()) {
    if (NeedsAnchorPositionScrollTranslation(object_)) {
      const auto& box = To<LayoutBox>(object_);
      const AnchorPositionScrollData& anchor_position_scroll_data =
          *box.GetAnchorPositionScrollData();
      gfx::Vector2dF translation_offset =
          -anchor_position_scroll_data.AccumulatedAdjustment();
      TransformPaintPropertyNode::State state{
          {gfx::Transform::MakeTranslation(translation_offset)}};

      // TODO(crbug.com/1309178): We should disable composited scrolling if the
      // snapshot's scrollers do not match the current scrollers.

      DCHECK(full_context_.direct_compositing_reasons &
             CompositingReason::kAnchorPosition);
      state.direct_compositing_reasons = CompositingReason::kAnchorPosition;

      // TODO(crbug.com/1309178): Not using GetCompositorElementId() here
      // because anchor-positioned elements don't work properly under multicol
      // for now, to keep consistency with
      // CompositorElementIdFromUniqueObjectId() below. This will be fixed by
      // LayoutNG block fragments.
      state.compositor_element_id = CompositorElementIdFromUniqueObjectId(
          box.UniqueId(),
          CompositorElementIdNamespace::kAnchorPositionScrollTranslation);
      state.rendering_context_id = context_.rendering_context_id;
      state.flattens_inherited_transform =
          context_.should_flatten_inherited_transform;

      state.anchor_position_scroll_data =
          std::make_unique<cc::AnchorPositionScrollData>();
      state.anchor_position_scroll_data->adjustment_container_ids =
          std::vector<CompositorElementId>(
              anchor_position_scroll_data.AdjustmentContainerIds().begin(),
              anchor_position_scroll_data.AdjustmentContainerIds().end());
      state.anchor_position_scroll_data->accumulated_scroll_origin =
          anchor_position_scroll_data.AccumulatedAdjustmentScrollOrigin();
      state.anchor_position_scroll_data->needs_scroll_adjustment_in_x =
          anchor_position_scroll_data.NeedsScrollAdjustmentInX();
      state.anchor_position_scroll_data->needs_scroll_adjustment_in_y =
          anchor_position_scroll_data.NeedsScrollAdjustmentInY();

      OnUpdateTransform(properties_->UpdateAnchorPositionScrollTranslation(
          *context_.current.transform, std::move(state)));
    } else {
      OnClearTransform(properties_->ClearAnchorPositionScrollTranslation());
    }
  }

  if (properties_->AnchorPositionScrollTranslation()) {
    context_.current.transform = properties_->AnchorPositionScrollTranslation();
  }
}

// Directly updates the associated cc transform node if possible, and
// downgrades the |PaintPropertyChangeType| if successful.
static void DirectlyUpdateCcTransform(
    const TransformPaintPropertyNode& transform,
    const LayoutObject& object,
    PaintPropertyChangeType& change_type) {
  // We only assume worst-case overlap testing due to animations (see:
  // |GeometryMapper::VisualRectForCompositingOverlap()|) so we can only use
  // the direct transform update (which skips checking for compositing changes)
  // when animations are present.
  if (change_type == PaintPropertyChangeType::kChangedOnlySimpleValues &&
      transform.HasActiveTransformAnimation()) {
    if (auto* paint_artifact_compositor =
            object.GetFrameView()->GetPaintArtifactCompositor()) {
      bool updated =
          paint_artifact_compositor->DirectlyUpdateTransform(transform);
      if (updated) {
        change_type = PaintPropertyChangeType::kChangedOnlyCompositedValues;
        transform.CompositorSimpleValuesUpdated();
      }
    }
  }
}

static void DirectlyUpdateCcOpacity(const LayoutObject& object,
                                    ObjectPaintProperties& properties,
                                    PaintPropertyChangeType& change_type) {
  if (change_type == PaintPropertyChangeType::kChangedOnlySimpleValues &&
      properties.Effect()->HasDirectCompositingReasons()) {
    if (auto* paint_artifact_compositor =
            object.GetFrameView()->GetPaintArtifactCompositor()) {
      bool updated =
          paint_artifact_compositor->DirectlyUpdateCompositedOpacityValue(
              *properties.Effect());
      if (updated) {
        change_type = PaintPropertyChangeType::kChangedOnlyCompositedValues;
        properties.Effect()->CompositorSimpleValuesUpdated();
      }
    }
  }
}

// TODO(dbaron): Remove this function when we can remove the
// BackfaceVisibilityInteropEnabled() check, and have the caller use
// CompositingReason::kDirectReasonsForTransformProperty directly.
static CompositingReasons CompositingReasonsForTransformProperty() {
  CompositingReasons reasons =
      CompositingReason::kDirectReasonsForTransformProperty;

  if (RuntimeEnabledFeatures::BackfaceVisibilityInteropEnabled())
    reasons |= CompositingReason::kBackfaceInvisibility3DAncestor;

  return reasons;
}

// TODO(crbug.com/1278452): Merge SVG handling into the primary codepath.
static bool NeedsTransformForSVGChild(
    const LayoutObject& object,
    CompositingReasons direct_compositing_reasons) {
  if (!object.IsSVGChild() || object.IsText())
    return false;
  if (direct_compositing_reasons &
      (CompositingReasonsForTransformProperty() |
       CompositingReason::kDirectReasonsForTranslateProperty |
       CompositingReason::kDirectReasonsForRotateProperty |
       CompositingReason::kDirectReasonsForScaleProperty))
    return true;
  return !object.LocalToSVGParentTransform().IsIdentity();
}

TransformPaintPropertyNode::TransformAndOrigin
FragmentPaintPropertyTreeBuilder::TransformAndOriginForSVGChild() const {
  if (full_context_.direct_compositing_reasons &
      CompositingReason::kActiveTransformAnimation) {
    if (CompositorAnimations::CanStartTransformAnimationOnCompositorForSVG(
            *To<SVGElement>(object_.GetNode()))) {
      const gfx::RectF reference_box =
          TransformHelper::ComputeReferenceBox(object_);
      // Composited transform animation works only if
      // LocalToSVGParentTransform() reflects the CSS transform properties.
      // If this fails, we need to exclude the case in
      // CompositorAnimations::CanStartTransformAnimationOnCompositorForSVG().
      DCHECK_EQ(TransformHelper::ComputeTransform(
                    object_.GetDocument(), object_.StyleRef(), reference_box,
                    ComputedStyle::kIncludeTransformOrigin),
                object_.LocalToSVGParentTransform());
      // For composited transform animation to work, we need to store transform
      // origin separately. It's baked in object_.LocalToSVGParentTransform().
      return {TransformHelper::ComputeTransform(
                  object_.GetDocument(), object_.StyleRef(), reference_box,
                  ComputedStyle::kExcludeTransformOrigin)
                  .ToTransform(),
              gfx::Point3F(TransformHelper::ComputeTransformOrigin(
                  object_.StyleRef(), reference_box))};
    }
  }
  return {object_.LocalToSVGParentTransform().ToTransform()};
}

// SVG does not use the general transform update of |UpdateTransform|, instead
// creating a transform node for SVG-specific transforms without 3D.
// TODO(crbug.com/1278452): Merge SVG handling into the primary codepath.
void FragmentPaintPropertyTreeBuilder::UpdateTransformForSVGChild(
    CompositingReasons direct_compositing_reasons) {
  DCHECK(properties_);
  DCHECK(object_.IsSVGChild());
  // SVG does not use paint offset internally, except for SVGForeignObject which
  // has different SVG and HTML coordinate spaces.
  DCHECK(object_.IsSVGForeignObject() ||
         context_.current.paint_offset.IsZero());

  if (NeedsPaintPropertyUpdate()) {
    if (NeedsTransformForSVGChild(object_, direct_compositing_reasons)) {
      // The origin is included in the local transform, so leave origin empty.
      TransformPaintPropertyNode::State state;
      state.transform_and_origin = TransformAndOriginForSVGChild();

      // TODO(pdr): There is additional logic in
      // FragmentPaintPropertyTreeBuilder::UpdateTransform that likely needs to
      // be included here, such as setting animation_is_axis_aligned.
      state.direct_compositing_reasons =
          direct_compositing_reasons & CompositingReasonsForTransformProperty();
      state.flattens_inherited_transform =
          context_.should_flatten_inherited_transform;
      state.rendering_context_id = context_.rendering_context_id;
      state.is_for_svg_child = true;
      state.compositor_element_id = GetCompositorElementId(
          CompositorElementIdNamespace::kPrimaryTransform);

      TransformPaintPropertyNode::AnimationState animation_state;
      animation_state.is_running_animation_on_compositor =
          object_.StyleRef().IsRunningTransformAnimationOnCompositor();
      auto effective_change_type = properties_->UpdateTransform(
          *context_.current.transform, std::move(state), animation_state);
      DirectlyUpdateCcTransform(*properties_->Transform(), object_,
                                effective_change_type);
      OnUpdateTransform(effective_change_type);
    } else {
      OnClearTransform(properties_->ClearTransform());
    }
  }

  if (properties_->Transform()) {
    context_.current.transform = properties_->Transform();
    context_.should_flatten_inherited_transform = true;
    context_.rendering_context_id = 0;
  }
}

static gfx::Point3F GetTransformOrigin(const LayoutBox& box,
                                       const PhysicalRect& reference_box) {
  // Transform origin has no effect without a transform or motion path.
  if (!box.HasTransform())
    return gfx::Point3F();
  const gfx::SizeF reference_box_size(reference_box.size);
  const auto& style = box.StyleRef();
  return gfx::Point3F(FloatValueForLength(style.GetTransformOrigin().X(),
                                          reference_box_size.width()) +
                          reference_box.X().ToFloat(),
                      FloatValueForLength(style.GetTransformOrigin().Y(),
                                          reference_box_size.height()) +
                          reference_box.Y().ToFloat(),
                      style.GetTransformOrigin().Z());
}

static bool NeedsIndividualTransform(
    const LayoutObject& object,
    CompositingReasons relevant_compositing_reasons,
    bool (*style_test)(const ComputedStyle&)) {
  if (object.IsText() || object.IsSVGChild())
    return false;

  if (relevant_compositing_reasons)
    return true;

  if (!object.IsBox())
    return false;

  if (style_test(object.StyleRef()))
    return true;

  return false;
}

static bool NeedsTranslate(const LayoutObject& object,
                           CompositingReasons direct_compositing_reasons) {
  return NeedsIndividualTransform(
      object,
      direct_compositing_reasons &
          CompositingReason::kDirectReasonsForTranslateProperty,
      [](const ComputedStyle& style) {
        return style.Translate() || style.HasCurrentTranslateAnimation();
      });
}

static bool NeedsRotate(const LayoutObject& object,
                        CompositingReasons direct_compositing_reasons) {
  return NeedsIndividualTransform(
      object,
      direct_compositing_reasons &
          CompositingReason::kDirectReasonsForRotateProperty,
      [](const ComputedStyle& style) {
        return style.Rotate() || style.HasCurrentRotateAnimation();
      });
}

static bool NeedsScale(const LayoutObject& object,
                       CompositingReasons direct_compositing_reasons) {
  return NeedsIndividualTransform(
      object,
      direct_compositing_reasons &
          CompositingReason::kDirectReasonsForScaleProperty,
      [](const ComputedStyle& style) {
        return style.Scale() || style.HasCurrentScaleAnimation();
      });
}

static bool NeedsOffset(const LayoutObject& object,
                        CompositingReasons direct_compositing_reasons) {
  return NeedsIndividualTransform(
      object, CompositingReason::kNone,
      [](const ComputedStyle& style) { return style.HasOffset(); });
}

static bool NeedsTransform(const LayoutObject& object,
                           CompositingReasons direct_compositing_reasons) {
  if (object.IsText() || object.IsSVGChild())
    return false;

  if (object.StyleRef().BackfaceVisibility() == EBackfaceVisibility::kHidden)
    return true;

  if (direct_compositing_reasons & CompositingReasonsForTransformProperty())
    return true;

  if (!object.IsBox())
    return false;

  if (object.StyleRef().HasTransformOperations() ||
      object.StyleRef().HasCurrentTransformAnimation() ||
      object.StyleRef().Preserves3D())
    return true;

  return false;
}

static bool UpdateBoxSizeAndCheckActiveAnimationAxisAlignment(
    const LayoutBox& object,
    CompositingReasons compositing_reasons) {
  if (!(compositing_reasons & (CompositingReason::kActiveTransformAnimation |
                               CompositingReason::kActiveScaleAnimation |
                               CompositingReason::kActiveRotateAnimation |
                               CompositingReason::kActiveTranslateAnimation)))
    return false;

  if (!object.GetNode() || !object.GetNode()->IsElementNode())
    return false;
  const Element* element = To<Element>(object.GetNode());
  auto* animations = element->GetElementAnimations();
  DCHECK(animations);
  return animations->UpdateBoxSizeAndCheckTransformAxisAlignment(
      gfx::SizeF(object.Size()));
}

static TransformPaintPropertyNode::TransformAndOrigin TransformAndOriginState(
    const LayoutBox& box,
    const PhysicalRect& reference_box,
    void (*compute_matrix)(const LayoutBox& box,
                           const PhysicalRect& reference_box,
                           gfx::Transform& matrix)) {
  gfx::Transform matrix;
  compute_matrix(box, reference_box, matrix);
  return {matrix, GetTransformOrigin(box, reference_box)};
}

static bool IsLayoutShiftRootTransform(
    const TransformPaintPropertyNode& transform) {
  // This is to keep the layout shift behavior before crrev.com/c/4024030.
  return transform.HasActiveTransformAnimation() ||
         !transform.IsIdentityOr2dTranslation();
}

void FragmentPaintPropertyTreeBuilder::UpdateIndividualTransform(
    bool (*needs_property)(const LayoutObject&, CompositingReasons),
    void (*compute_matrix)(const LayoutBox& box,
                           const PhysicalRect& reference_box,
                           gfx::Transform& matrix),
    CompositingReasons compositing_reasons_for_property,
    CompositorElementIdNamespace compositor_namespace,
    bool (ComputedStyle::*running_on_compositor_test)() const,
    const TransformPaintPropertyNode* (ObjectPaintProperties::*getter)() const,
    PaintPropertyChangeType (ObjectPaintProperties::*updater)(
        const TransformPaintPropertyNodeOrAlias&,
        TransformPaintPropertyNode::State&&,
        const TransformPaintPropertyNode::AnimationState&),
    bool (ObjectPaintProperties::*clearer)()) {
  // TODO(crbug.com/1278452): Merge SVG handling into the primary
  // codepath (which is this one).
  DCHECK(!object_.IsSVGChild());
  DCHECK(properties_);

  if (NeedsPaintPropertyUpdate()) {
    // A transform node is allocated for transforms, preserves-3d and any
    // direct compositing reason. The latter is required because this is the
    // only way to represent compositing both an element and its stacking
    // descendants.
    if ((*needs_property)(object_, full_context_.direct_compositing_reasons)) {
      TransformPaintPropertyNode::State state;

      // A few pieces of the code are only for the 'transform' property
      // and not for the others.
      bool handling_transform_property =
          compositor_namespace ==
          CompositorElementIdNamespace::kPrimaryTransform;

      const ComputedStyle& style = object_.StyleRef();
      if (object_.IsBox()) {
        auto& box = To<LayoutBox>(object_);
        // Each individual fragment should have its own transform origin, based
        // on the fragment reference box.
        PhysicalRect reference_box = ComputeReferenceBox(BoxFragment());

        if (IsMissingActualFragment()) {
          // If the fragment doesn't really exist in the current fragmentainer,
          // treat its block-size as zero. See figure in
          // https://www.w3.org/TR/css-break-3/#transforms
          if (style.IsHorizontalWritingMode()) {
            reference_box.SetHeight(LayoutUnit());
          } else {
            reference_box.SetWidth(LayoutUnit());
          }
        }

        // If we are running transform animation on compositor, we should
        // disable 2d translation optimization to ensure that the compositor
        // gets the correct origin (which might be omitted by the optimization)
        // to the compositor, in case later animated values will use the origin.
        // See http://crbug.com/937929 for why we are not using
        // style.IsRunningTransformAnimationOnCompositor() etc. here.
        state.transform_and_origin =
            TransformAndOriginState(box, reference_box, compute_matrix);

        // TODO(trchen): transform-style should only be respected if a
        // PaintLayer is created. If a node with transform-style: preserve-3d
        // does not exist in an existing rendering context, it establishes a
        // new one.
        state.rendering_context_id = context_.rendering_context_id;
        if (handling_transform_property && style.Preserves3D() &&
            !state.rendering_context_id) {
          state.rendering_context_id = WTF::GetHash(&object_);
        }

        // TODO(crbug.com/1185254): Make this work correctly for block
        // fragmentation. It's the size of each individual PhysicalBoxFragment
        // that's interesting, not the total LayoutBox size.
        state.animation_is_axis_aligned =
            UpdateBoxSizeAndCheckActiveAnimationAxisAlignment(
                box, full_context_.direct_compositing_reasons);
      }

      state.direct_compositing_reasons =
          full_context_.direct_compositing_reasons &
          compositing_reasons_for_property;

      state.flattens_inherited_transform =
          context_.should_flatten_inherited_transform;
      if (running_on_compositor_test) {
        state.compositor_element_id =
            GetCompositorElementId(compositor_namespace);
      }

      if (handling_transform_property) {
        if (object_.HasHiddenBackface()) {
          state.backface_visibility =
              TransformPaintPropertyNode::BackfaceVisibility::kHidden;
        } else if (!context_.can_inherit_backface_visibility ||
                   style.Has3DTransformOperation()) {
          // We want to set backface-visibility back to visible, if the
          // parent doesn't allow this element to inherit backface visibility
          // (e.g. if the parent preserves 3d), or this element has a
          // syntactically-3D transform in *any* of the transform properties
          // (not just 'transform'). This means that backface-visibility on
          // an ancestor element no longer affects this element.
          state.backface_visibility =
              TransformPaintPropertyNode::BackfaceVisibility::kVisible;
        } else {
          // Otherwise we want to inherit backface-visibility.
          DCHECK_EQ(state.backface_visibility,
                    TransformPaintPropertyNode::BackfaceVisibility::kInherited);
        }
      }

      TransformPaintPropertyNode::AnimationState animation_state;
      animation_state.is_running_animation_on_compositor =
          running_on_compositor_test && (style.*running_on_compositor_test)();
      auto effective_change_type = (properties_->*updater)(
          *context_.current.transform, std::move(state), animation_state);
      DirectlyUpdateCcTransform(*(properties_->*getter)(), object_,
                                effective_change_type);
      OnUpdateTransform(effective_change_type);
    } else {
      OnClearTransform((properties_->*clearer)());
    }
  }

  if (const auto* transform = (properties_->*getter)()) {
    context_.current.transform = transform;
    if (!transform->Matrix().Is2dTransform()) {
      // We need to not flatten from this node through to this element's
      // transform node.  (If this is the transform node, we'll undo
      // this in the caller.)
      context_.should_flatten_inherited_transform = false;
    }
    if (!IsLayoutShiftRootTransform(*transform)) {
      context_.translation_2d_to_layout_shift_root_delta +=
          transform->Get2dTranslation();
    }
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateTranslate() {
  UpdateIndividualTransform(
      &NeedsTranslate,
      [](const LayoutBox& box, const PhysicalRect& reference_box,
         gfx::Transform& matrix) {
        const ComputedStyle& style = box.StyleRef();
        if (style.Translate())
          style.Translate()->Apply(matrix, gfx::SizeF(reference_box.size));
      },
      CompositingReason::kDirectReasonsForTranslateProperty,
      CompositorElementIdNamespace::kTranslateTransform,
      &ComputedStyle::IsRunningTranslateAnimationOnCompositor,
      &ObjectPaintProperties::Translate,
      &ObjectPaintProperties::UpdateTranslate,
      &ObjectPaintProperties::ClearTranslate);
}

void FragmentPaintPropertyTreeBuilder::UpdateRotate() {
  UpdateIndividualTransform(
      &NeedsRotate,
      [](const LayoutBox& box, const PhysicalRect& reference_box,
         gfx::Transform& matrix) {
        const ComputedStyle& style = box.StyleRef();
        if (style.Rotate())
          style.Rotate()->Apply(matrix, gfx::SizeF(reference_box.size));
      },
      CompositingReason::kDirectReasonsForRotateProperty,
      CompositorElementIdNamespace::kRotateTransform,
      &ComputedStyle::IsRunningRotateAnimationOnCompositor,
      &ObjectPaintProperties::Rotate, &ObjectPaintProperties::UpdateRotate,
      &ObjectPaintProperties::ClearRotate);
}

void FragmentPaintPropertyTreeBuilder::UpdateScale() {
  UpdateIndividualTransform(
      &NeedsScale,
      [](const LayoutBox& box, const PhysicalRect& reference_box,
         gfx::Transform& matrix) {
        const ComputedStyle& style = box.StyleRef();
        if (style.Scale())
          style.Scale()->Apply(matrix, gfx::SizeF(reference_box.size));
      },
      CompositingReason::kDirectReasonsForScaleProperty,
      CompositorElementIdNamespace::kScaleTransform,
      &ComputedStyle::IsRunningScaleAnimationOnCompositor,
      &ObjectPaintProperties::Scale, &ObjectPaintProperties::UpdateScale,
      &ObjectPaintProperties::ClearScale);
}

void FragmentPaintPropertyTreeBuilder::UpdateOffset() {
  UpdateIndividualTransform(
      &NeedsOffset,
      [](const LayoutBox& box, const PhysicalRect& reference_box,
         gfx::Transform& matrix) {
        const ComputedStyle& style = box.StyleRef();
        style.ApplyTransform(
            matrix, &box, reference_box,
            ComputedStyle::kExcludeTransformOperations,
            ComputedStyle::kExcludeTransformOrigin,
            ComputedStyle::kIncludeMotionPath,
            ComputedStyle::kExcludeIndependentTransformProperties);
      },
      CompositingReason::kNone,
      // TODO(dbaron): When we support animating offset on the
      // compositor, we need to use an element ID specific to offset.
      // This is currently unused.
      CompositorElementIdNamespace::kPrimary, nullptr,
      &ObjectPaintProperties::Offset, &ObjectPaintProperties::UpdateOffset,
      &ObjectPaintProperties::ClearOffset);
}

void FragmentPaintPropertyTreeBuilder::UpdateTransform() {
  UpdateIndividualTransform(
      &NeedsTransform,
      [](const LayoutBox& box, const PhysicalRect& reference_box,
         gfx::Transform& matrix) {
        const ComputedStyle& style = box.StyleRef();
        style.ApplyTransform(
            matrix, &box, reference_box,
            ComputedStyle::kIncludeTransformOperations,
            ComputedStyle::kExcludeTransformOrigin,
            ComputedStyle::kExcludeMotionPath,
            ComputedStyle::kExcludeIndependentTransformProperties);
      },
      CompositingReasonsForTransformProperty(),
      CompositorElementIdNamespace::kPrimaryTransform,
      &ComputedStyle::IsRunningTransformAnimationOnCompositor,
      &ObjectPaintProperties::Transform,
      &ObjectPaintProperties::UpdateTransform,
      &ObjectPaintProperties::ClearTransform);

  // Since we're doing a full update, clear list of objects waiting for a
  // deferred update
  object_.GetFrameView()->RemovePendingTransformUpdate(object_);

  // properties_->Transform() is present if a CSS transform is present,
  // and is also present if transform-style: preserve-3d is set.
  // See NeedsTransform.
  if (const auto* transform = properties_->Transform()) {
    context_.current.transform = transform;
    if (object_.StyleRef().Preserves3D()) {
      context_.rendering_context_id = transform->RenderingContextId();
      context_.should_flatten_inherited_transform = false;
    } else {
      context_.rendering_context_id = 0;
      context_.should_flatten_inherited_transform = true;
    }
  } else if (!object_.IsAnonymous()) {
    // 3D rendering contexts follow the DOM ancestor chain, so
    // flattening should apply regardless of presence of transform.
    context_.rendering_context_id = 0;
    context_.should_flatten_inherited_transform = true;
  }
}

static bool NeedsClipPathClipOrMask(const LayoutObject& object) {
  // We only apply clip-path if the LayoutObject has a layer or is an SVG
  // child. See NeedsEffect() for additional information on the former.
  return !object.IsText() &&
         (ClipPathClipper::HasCompositeClipPathAnimation(object) ||
          (object.StyleRef().HasClipPath() &&
           (object.HasLayer() || object.IsSVGChild())));
}

static bool NeedsEffectForViewTransition(const LayoutObject& object) {
  // The view-transition-name property when set creates a backdrop filter root.
  // We do this by ensuring that this object needs an effect node.
  //
  // This is not required for the root element since its snapshot comes from the
  // root stacking context which is already a backdrop filter root.
  const auto& style = object.StyleRef();
  if (style.ElementIsViewTransitionParticipant()) {
    DCHECK(
        ViewTransitionUtils::IsViewTransitionElementExcludingRootFromSupplement(
            *To<Element>(object.GetNode())));
    return true;
  } else {
#if DCHECK_IS_ON()
    auto* element = DynamicTo<Element>(object.GetNode());
    DCHECK(!element ||
           !ViewTransitionUtils::
               IsViewTransitionElementExcludingRootFromSupplement(*element))
        << element;
#endif
  }

  return style.ViewTransitionName() && !object.IsDocumentElement() &&
         !object.IsLayoutView();
}

static bool NeedsEffectIgnoringClipPath(
    const LayoutObject& object,
    CompositingReasons direct_compositing_reasons) {
  if (object.IsText()) {
    DCHECK(!(direct_compositing_reasons &
             CompositingReason::kDirectReasonsForEffectProperty));
    return false;
  }

  if (direct_compositing_reasons &
      CompositingReason::kDirectReasonsForEffectProperty)
    return true;

  const ComputedStyle& style = object.StyleRef();

  // For now some objects (e.g. LayoutTableCol) with stacking context style
  // don't create layer thus are not actual stacking contexts, so the HasLayer()
  // condition. TODO(crbug.com/892734): Support effects for LayoutTableCol.
  const bool is_css_isolated_group =
      object.HasLayer() && object.IsStackingContext();

  if (!is_css_isolated_group && !object.IsSVG())
    return false;

  if (object.IsSVG() && SVGLayoutSupport::IsIsolationRequired(&object))
    return true;

  if (is_css_isolated_group) {
    const auto* layer = To<LayoutBoxModelObject>(object).Layer();
    DCHECK(layer);

    if (layer->HasNonIsolatedDescendantWithBlendMode())
      return true;
  }

  if (object.IsBlendingAllowed() &&
      WebCoreCompositeToSkiaComposite(
          kCompositeSourceOver, style.GetBlendMode()) != SkBlendMode::kSrcOver)
    return true;

  if (!style.BackdropFilter().IsEmpty())
    return true;

  if (style.Opacity() != 1.0f)
    return true;

  // A mask needs an effect node on the current LayoutObject to define the scope
  // of masked contents to be the current LayoutObject and its descendants.
  if (style.HasMask()) {
    return true;
  }

  // The view-transition-name property when set creates a backdrop filter root.
  // We do this by ensuring that this object needs an effect node.
  // This is not required for the root element since its snapshot comes from the
  // root stacking context which is already a backdrop filter root.
  if (NeedsEffectForViewTransition(object)) {
    return true;
  }

  return false;
}

bool FragmentPaintPropertyTreeBuilder::NeedsEffect() const {
  DCHECK(NeedsPaintPropertyUpdate());
  // A mask-based clip-path needs an effect node, similar to a normal mask.
  if (needs_mask_based_clip_path_)
    return true;
  return NeedsEffectIgnoringClipPath(object_,
                                     full_context_.direct_compositing_reasons);
}

// An effect node can use the current clip as its output clip if the clip won't
// end before the effect ends. Having explicit output clip can let the later
// stages use more optimized code path.
bool FragmentPaintPropertyTreeBuilder::EffectCanUseCurrentClipAsOutputClip()
    const {
  DCHECK(NeedsEffect());

  if (!object_.HasLayer()) {
    // This is either SVG or it's the effect node to create flattening at the
    // leaves of a 3D scene.
    //
    // Either way, the effect never interleaves with clips, because
    // positioning is the only situation where clip order changes.
    return true;
  }

  const auto* layer = To<LayoutBoxModelObject>(object_).Layer();
  // Out-of-flow descendants not conta
"""


```