Response:
The user wants to understand the functionality of the `compositor_animations.cc` file in the Chromium Blink engine. I need to:

1. **Summarize the file's purpose**: Based on the includes and the code structure, this file seems responsible for managing animations that can be run on the compositor thread, off the main thread.
2. **Explain its relationship with web technologies**: Connect the concepts in the code (like CSS properties, transformations, filters) to their counterparts in Javascript, HTML, and CSS.
3. **Infer logical flow**: Analyze the functions and their interactions to understand how animation decisions are made. This involves understanding the conditions under which an animation can be offloaded to the compositor.
4. **Identify potential user/developer errors**: Based on the checks and conditions in the code, determine what common mistakes might prevent an animation from being compositor-driven.
5. **Focus on the provided first part**:  Since this is part 1 of 2, I need to summarize the functionality covered in this specific code snippet.

**Plan:**

* **Functionality:** Identify the core tasks performed by the functions in this part of the file. This includes checking if animations can be composited, handling incompatible animations, and preparing animation data for the compositor.
* **Web technology relationship:**  Give examples of how CSS properties like `opacity`, `transform`, and `filter`, as well as animation timing, relate to the code.
* **Logical reasoning:**  Focus on the `CheckCanStartAnimationOnCompositor` function and its sub-functions to illustrate the decision-making process. Create a hypothetical scenario and trace its execution.
* **User errors:**  Highlight common mistakes that could lead to an animation not being composited, based on the failure reasons defined in the code.
* **Summary:** Concisely summarize the capabilities of the code presented in this first part.
```cpp
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
 * contributors may be used to endorse or promote products derived from this software without specific prior written permission.
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/animation/compositor_animations.h"

#include <algorithm>
#include <cmath>
#include <memory>

#include "cc/animation/animation_id_provider.h"
#include "cc/animation/filter_animation_curve.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/animation/animation_effect.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_color.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_double.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_filter_operations.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_transform.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_value.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/css/background_color_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/box_shadow_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/clip_path_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_transformable_container.h"
#include "third_party/blink/renderer/core/paint/filter_effect_builder.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/platform/animation/animation_translation_util.h"
#include "third_party/blink/renderer/platform/animation/compositor_animation.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/platform_paint_worklet_layer_painter.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/gfx/animation/keyframe/animation_curve.h"
#include "ui/gfx/animation/keyframe/keyframed_animation_curve.h"

namespace blink {

namespace {

constexpr auto kCompositableProperties = std::to_array<CSSPropertyID>({
    CSSPropertyID::kBackdropFilter,
    CSSPropertyID::kFilter,
    CSSPropertyID::kOpacity,
    CSSPropertyID::kRotate,
    CSSPropertyID::kScale,
    CSSPropertyID::kTransform,
    CSSPropertyID::kTranslate,
});

bool ConsiderAnimationAsIncompatible(const Animation& animation,
                                     const Animation& animation_to_add,
                                     const EffectModel& effect_to_add) {
  if (&animation == &animation_to_add)
    return false;

  if (animation.PendingInternal())
    return true;

  switch (animation.CalculateAnimationPlayState()) {
    case V8AnimationPlayState::Enum::kIdle:
      return false;
    case V8AnimationPlayState::Enum::kRunning:
      return true;
    case V8AnimationPlayState::Enum::kPaused:
    case V8AnimationPlayState::Enum::kFinished:
      if (Animation::HasLowerCompositeOrdering(
              &animation, &animation_to_add,
              Animation::CompareAnimationsOrdering::kPointerOrder)) {
        return effect_to_add.AffectedByUnderlyingAnimations();
      }
      return true;
    default:
      NOTREACHED();
  }
}

bool IsTransformRelatedCSSProperty(const PropertyHandle property) {
  return property.IsCSSProperty() &&
         (property.GetCSSProperty().IDEquals(CSSPropertyID::kRotate) ||
          property.GetCSSProperty().IDEquals(CSSPropertyID::kScale) ||
          property.GetCSSProperty().IDEquals(CSSPropertyID::kTransform) ||
          property.GetCSSProperty().IDEquals(CSSPropertyID::kTranslate));
}

bool HasIncompatibleAnimations(const Element& target_element,
                               const Animation& animation_to_add,
                               const EffectModel& effect_to_add) {
  if (!target_element.HasAnimations())
    return false;

  std::array<bool, kCompositableProperties.size()> affects_property;
  for (size_t i = 0; i < kCompositableProperties.size(); i++) {
    PropertyHandle property(CSSProperty::Get(kCompositableProperties[i]));
    affects_property[i] = effect_to_add.Affects(property);
  }

  ElementAnimations* element_animations = target_element.GetElementAnimations();
  DCHECK(element_animations);

  for (const auto& entry : element_animations->Animations()) {
    Animation* attached_animation = entry.key;
    const auto* effect =
        DynamicTo<KeyframeEffect>(attached_animation->effect());
    if (!effect || effect->EffectTarget() != target_element)
      continue;

    if (!ConsiderAnimationAsIncompatible(*attached_animation, animation_to_add,
                                         effect_to_add)) {
      continue;
    }

    for (size_t i = 0; i < kCompositableProperties.size(); i++) {
      if (!affects_property[i])
        continue;

      PropertyHandle property(CSSProperty::Get(kCompositableProperties[i]));
      if (effect->Affects(property))
        return true;
    }
  }

  return false;
}

void DefaultToUnsupportedProperty(
    PropertyHandleSet* unsupported_properties,
    const PropertyHandle& property,
    CompositorAnimations::FailureReasons* reasons) {
  (*reasons) |= CompositorAnimations::kUnsupportedCSSProperty;
  if (unsupported_properties) {
    unsupported_properties->insert(property);
  }
}

// True if it is either a no-op background-color animation, or a no-op custom
// property animation.
bool IsNoOpPaintWorkletOrVariableAnimation(const PropertyHandle& property,
                                      const LayoutObject* layout_object) {
  // If the background color paint worklet was painted, a unique id will be
  // generated. See BackgroundColorPaintWorklet::GetBGColorPaintWorkletParams
  // for details.
  // Similar to that, if a CSS paint worklet was painted, a unique id will be
  // generated. See CSSPaintValue::GetImage for details.
  bool has_unique_id = layout_object->FirstFragment().HasUniqueId();
  if (has_unique_id)
    return false;
  // Now the |has_unique_id| == false.
  bool is_no_op_bgcolor_anim =
      RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled() &&
      property.GetCSSProperty().PropertyID() == CSSPropertyID::kBackgroundColor;
  bool is_no_op_clip_anim =
      RuntimeEnabledFeatures::CompositeClipPathAnimationEnabled() &&
      property.GetCSSProperty().PropertyID() == CSSPropertyID::kClipPath;
  bool is_no_op_variable_anim =
      property.GetCSSProperty().PropertyID() == CSSPropertyID::kVariable;
  return is_no_op_variable_anim || is_no_op_clip_anim || is_no_op_bgcolor_anim;
}

bool CompositedAnimationRequiresProperties(const PropertyHandle& property,
                                           LayoutObject* layout_object) {
  if (!property.IsCSSProperty())
    return false;
  switch (property.GetCSSProperty().PropertyID()) {
    case CSSPropertyID::kRotate:
    case CSSPropertyID::kScale:
    case CSSPropertyID::kTranslate:
    case CSSPropertyID::kTransform:
      return !layout_object || layout_object->IsTransformApplicable();
    case CSSPropertyID::kOpacity:
    case CSSPropertyID::kBackdropFilter:
    case CSSPropertyID::kFilter:
      return true;
    default:
      return false;
  }
}

}  // namespace

CompositorElementIdNamespace
CompositorAnimations::CompositorElementNamespaceForProperty(
    CSSPropertyID property) {
  switch (property) {
    case CSSPropertyID::kOpacity:
    case CSSPropertyID::kBackdropFilter:
      return CompositorElementIdNamespace::kPrimaryEffect;
    case CSSPropertyID::kRotate:
      return CompositorElementIdNamespace::kRotateTransform;
    case CSSPropertyID::kScale:
      return CompositorElementIdNamespace::kScaleTransform;
    case CSSPropertyID::kTranslate:
      return CompositorElementIdNamespace::kTranslateTransform;
    case CSSPropertyID::kTransform:
      return CompositorElementIdNamespace::kPrimaryTransform;
    case CSSPropertyID::kFilter:
      return CompositorElementIdNamespace::kEffectFilter;
    case CSSPropertyID::kBackgroundColor:
    case CSSPropertyID::kBoxShadow:
    case CSSPropertyID::kClipPath:
    case CSSPropertyID::kVariable:
      // TODO(crbug.com/883721): Variables and these raster-inducing properties
      // should not require the target element to have any composited property
      // tree nodes - i.e. should not need to check for existence of a property
      // tree node. For now, variable animations target the primary animation
      // target node - the effect namespace.
      return CompositorElementIdNamespace::kPrimaryEffect;
    default:
      NOTREACHED();
  }
}

CompositorAnimations::FailureReasons
CompositorAnimations::CheckCanStartEffectOnCompositor(
    const Timing& timing,
    const Timing::NormalizedTiming& normalized_timing,
    const Element& target_element,
    const Animation* animation_to_add,
    const EffectModel& effect,
    const PaintArtifactCompositor* paint_artifact_compositor,
    double animation_playback_rate,
    PropertyHandleSet* unsupported_properties) {
  FailureReasons reasons = kNoFailure;
  const auto& keyframe_effect = To<KeyframeEffectModelBase>(effect);

  LayoutObject* layout_object = target_element.GetLayoutObject();
  // Elements with subtrees containing will-change: contents are not
  // composited for animations as if the contents change the tiles
  // would need to be rerastered anyways.
  if (layout_object && layout_object->Style()->SubtreeWillChangeContents()) {
    reasons |= kTargetHasInvalidCompositingState;
  }

  const PropertyHandleSet& properties =
      keyframe_effect.EnsureDynamicProperties();
  if (RuntimeEnabledFeatures::StaticAnimationOptimizationEnabled()) {
    // If all properties are static, we don't need to composite. The animation
    // can only change at a phase boundary.
    if (properties.empty()) {
      reasons |= kAnimationHasNoVisibleChange;
    }
  }
  if (keyframe_effect.HasStaticProperty()) {
    UseCounter::Count(target_element.GetDocument(),
                      WebFeature::kStaticPropertyInAnimation);
  }
  for (const auto& property : properties) {
    if (!property.IsCSSProperty()) {
      // None of the below reasons make any sense if |property| isn't CSS, so we
      // skip the rest of the loop in that case.
      reasons |= kAnimationAffectsNonCSSProperties;
      continue;
    }

    if (IsTransformRelatedCSSProperty(property)) {
      // We use this later in computing element IDs too.
      if (layout_object && !layout_object->IsTransformApplicable()) {
        // TODO(dbaron): We could consider ignoring the
        // transform-related property and still running the others on
        // the compositor.
        reasons |= kTransformRelatedPropertyCannotBeAcceleratedOnTarget;
      }
      if (const auto* svg_element = DynamicTo<SVGElement>(target_element)) {
        reasons |=
            CheckCanStartTransformAnimationOnCompositorForSVG(*svg_element);
        // TODO(https://crbug.com/1278452): When we make the transform tree
        // structure for SVG work like everything else, we should instead
        // start compositing animations of transform properties other than
        // transform.
        if (!property.GetCSSProperty().IDEquals(CSSPropertyID::kTransform))
          reasons |= kSVGTargetHasIndependentTransformProperty;
      }
    }

    const PropertySpecificKeyframeVector& keyframes =
        *keyframe_effect.GetPropertySpecificKeyframes(property);
    DCHECK_GE(keyframes.size(), 2U);
    for (const auto& keyframe : keyframes) {
      if (keyframe->Composite() != EffectModel::kCompositeReplace &&
          !keyframe->IsNeutral()) {
        reasons |= kEffectHasNonReplaceCompositeMode;
      }

      // FIXME: Determine candidacy based on the CSSValue instead of a snapshot
      // CompositorKeyframeValue.
      switch (property.GetCSSProperty().PropertyID()) {
        case CSSPropertyID::kOpacity:
          break;
        case CSSPropertyID::kRotate:
        case CSSPropertyID::kScale:
        case CSSPropertyID::kTranslate:
        case CSSPropertyID::kTransform:
          break;
        case CSSPropertyID::kFilter:
          if (keyframe->GetCompositorKeyframeValue() &&
              To<CompositorKeyframeFilterOperations>(
                  keyframe->GetCompositorKeyframeValue())
                  ->Operations()
                  .HasFilterThatMovesPixels()) {
            reasons |= kFilterRelatedPropertyMayMovePixels;
          }
          break;
        case CSSPropertyID::kBackdropFilter:
          // Backdrop-filter pixel moving filters do not change the layer bounds
          // like regular filters do, so they can still be composited.
          break;
        case CSSPropertyID::kBackgroundColor:
        case CSSPropertyID::kBoxShadow:
        case CSSPropertyID::kClipPath: {
          NativePaintImageGenerator* generator = nullptr;
          // Not having a layout object is a reason for not compositing marked
          // in CompositorAnimations::CheckCanStartElementOnCompositor.
          if (!layout_object) {
            continue;
          }
          if (property.GetCSSProperty().PropertyID() ==
                  CSSPropertyID::kBackgroundColor &&
              RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled()) {
            generator = target_element.GetDocument()
                            .GetFrame()
                            ->GetBackgroundColorPaintImageGenerator();
          } else if (property.GetCSSProperty().PropertyID() ==
                         CSSPropertyID::kBoxShadow &&
                     RuntimeEnabledFeatures ::
                         CompositeBoxShadowAnimationEnabled()) {
            generator = target_element.GetDocument()
                            .GetFrame()
                            ->GetBoxShadowPaintImageGenerator();
          } else if (property.GetCSSProperty().PropertyID() ==
                         CSSPropertyID::kClipPath &&
                     RuntimeEnabledFeatures::
                         CompositeClipPathAnimationEnabled()) {
            generator = target_element.GetDocument()
                            .GetFrame()
                            ->GetClipPathPaintImageGenerator();
          }
          Animation* compositable_animation = nullptr;

          // The generator may be null in tests.
          if (generator) {
            compositable_animation =
                generator->GetAnimationIfCompositable(&target_element);
          }

          if (!compositable_animation) {
            DefaultToUnsupportedProperty(unsupported_properties, property,
                                         &reasons);
          }
          break;
        }
        case CSSPropertyID::kVariable: {
          // Custom properties are supported only in the case of
          // OffMainThreadCSSPaintEnabled, and even then only for some specific
          // property types. Otherwise they are treated as unsupported.
          const CompositorKeyframeValue* keyframe_value =
              keyframe->GetCompositorKeyframeValue();
          if (keyframe_value) {
            DCHECK(RuntimeEnabledFeatures::OffMainThreadCSSPaintEnabled());
            DCHECK(keyframe_value->IsDouble() || keyframe_value->IsColor());
            // If a custom property is not used by CSS Paint, then we should not
            // support that on the compositor thread.
            if (layout_object && layout_object->Style() &&
                !layout_object->Style()->HasCSSPaintImagesUsingCustomProperty(
                    property.CustomPropertyName(),
                    layout_object->GetDocument())) {
              DefaultToUnsupportedProperty(unsupported_properties, property,
                                           &reasons);
            }
            // TODO: Add support for keyframes containing different types
            if (!keyframes.front() ||
                !keyframes.front()->GetCompositorKeyframeValue() ||
                keyframes.front()->GetCompositorKeyframeValue()->GetType() !=
                    keyframe_value->GetType()) {
              reasons |= kMixedKeyframeValueTypes;
            }
          } else {
            // We skip the rest of the loop in this case for the same reason as
            // unsupported CSS properties - see below.
            DefaultToUnsupportedProperty(unsupported_properties, property,
                                         &reasons);
            continue;
          }
          break;
        }
        default:
          // We skip the rest of the loop in this case because
          // |GetCompositorKeyframeValue()| will be false so we will
          // accidentally count this as kInvalidAnimationOrEffect as well.
          DefaultToUnsupportedProperty(unsupported_properties, property,
                                       &reasons);
          continue;
      }

      // The compositor animation for paint worklet animations do not snapshot
      // the individual keyframes. Instead the keyframes are interpolated within
      // the worklet based on the overall animation progress.
      const bool needs_compositor_keyframe_value =
          CompositedPropertyRequiresSnapshot(property);
      // If an element does not have style, then it will never have taken a
      // snapshot of its (non-existent) value for the compositor to use.
      if (needs_compositor_keyframe_value &&
          !keyframe->GetCompositorKeyframeValue()) {
        reasons |= kInvalidAnimationOrEffect;
      }
    }
  }

  if (CompositorPropertyAnimationsHaveNoEffect(target_element, effect,
                                               paint_artifact_compositor)) {
#if DCHECK_IS_ON()
    if (effect.Affects(PropertyHandle(GetCSSPropertyBackgroundColor()))) {
      ElementAnimations* element_animations =
          target_element.GetElementAnimations();
      DCHECK(element_animations &&
             element_animations->CompositedBackgroundColorStatus() !=
                 ElementAnimations::CompositedPaintStatus::kComposited);
    }
    if (effect.Affects(PropertyHandle(GetCSSPropertyClipPath()))) {
      ElementAnimations* element_animations =
          target_element.GetElementAnimations();
      DCHECK(element_animations &&
             element_animations->CompositedClipPathStatus() !=
                 ElementAnimations::CompositedPaintStatus::kComposited);
    }
#endif
    reasons |= kAnimationHasNoVisibleChange;
  }

  if (animation_to_add &&
      HasIncompatibleAnimations(target_element, *animation_to_add, effect)) {
    reasons |= kTargetHasIncompatibleAnimations;
  }

  CompositorTiming out;
  base::TimeDelta time_offset =
      animation_to_add ? animation_to_add->ComputeCompositorTimeOffset()
                       : base::TimeDelta();
  if (!ConvertTimingForCompositor(timing, normalized_timing, time_offset, out,
                                  animation_playback_rate)) {
    reasons |= kEffectHasUnsupportedTimingParameters;
  }

  return reasons;
}

bool CompositorAnimations::CompositorPropertyAnimationsHaveNoEffect(
    const Element& target_element,
    const EffectModel& effect,
    const PaintArtifactCompositor* paint_artifact_compositor) {
  LayoutObject* layout_object = target_element.GetLayoutObject();

  if (!paint_artifact_compositor) {
    // TODO(pdr): This should return true. This likely only affects tests.
    return false;
  }

  bool any_compositor_properties_missing = false;
  bool any_compositor_properties_present = false;

  const auto& keyframe_effect = To<KeyframeEffectModelBase>(effect);
  const auto& groups = keyframe_effect.GetPropertySpecificKeyframeGroups();
  bool has_paint_properties =
      layout_object && layout_object->FirstFragment().PaintProperties();
  for (const PropertyHandle& property : groups.Keys()) {
    if (!CompositedAnimationRequiresProperties(property, layout_object))
      continue;

    if (!has_paint_properties) {
      // We have an animated property that requires a property node but no paint
      // properties.
      any_compositor_properties_missing = true;
      break;
    }

    CompositorElementId target_element_id =
        CompositorElementIdFromUniqueObjectId(
            layout_object->UniqueId(),
            CompositorAnimations::CompositorElementNamespaceForProperty(
                property.GetCSSProperty().PropertyID()));
    DCHECK(target_element_id);
    if (paint_artifact_compositor->HasComposited(target_element_id))
      any_compositor_properties_present = true;
    else
      any_compositor_properties_missing = true;
  }

  // Because animations are a direct compositing reason for paint properties,
  // the only case when we wouldn't have compositor paint properties if when
  // they were optimized out due to not having an effect. An example of this is
  // hidden animations that do not paint.
  if (any_compositor_properties_missing) {
    // Because we're only considering properties that are animated on this
    // element, we should either have all properties or be missing all
    // properties.
    DCHECK(!any_compositor_properties_present);
    return true;
  }

  return false;
}

CompositorAnimations::FailureReasons
CompositorAnimations::CheckCanStartElementOnCompositor(
    const Element& target_element,
    const EffectModel& model) {
  FailureReasons reasons = kNoFailure;

  // TODO(crbug.com/1287221): Add a more specific reason.
  if (target_element.GetDocument().ShouldForceReduceMotion())
    reasons |= kAcceleratedAnimationsDisabled;

  // Both of these checks are required. It is legal to enable the compositor
  // thread but disable threaded animations, and there are situations where
  // threaded animations are enabled globally but this particular LocalFrame
  // does not have a compositor (e.g. for overlays).
  const Settings* settings = target_element.GetDocument().GetSettings();
  if ((settings && !settings->GetAcceleratedCompositingEnabled()) ||
      !Platform::Current()->IsThreadedAnimationEnabled()) {
    reasons |= kAcceleratedAnimationsDisabled;
  }

  if (const auto* svg_element = DynamicTo<SVGElement>(target_element))
    reasons |= CheckCanStartSVGElementOnCompositor(*svg_element);

  if (const auto* layout_object = target_element.GetLayoutObject()) {
    // We query paint property tree state below to determine whether the
    // animation is compositable. TODO(crbug.com/676456): There is a known
    // lifecycle violation where an animation can be cancelled during style
    // update. See CompositorAnimations::CancelAnimationOnCompositor().
    // When this is fixed we would like to enable the DCHECK below.
    // DCHECK_GE(GetDocument().Lifecycle().GetState(),
    //           DocumentLifecycle::kPrePaintClean);
    bool has_direct_compositing_reasons = false;
    if (layout_object->IsFragmented()) {
      // Composited animation on multiple fragments is not supported.
      reasons |= kTargetHasInvalidCompositingState;
    } else if (const auto* paint_properties =
                   layout_object->FirstFragment().PaintProperties()) {
      const auto* transform = paint_properties->Transform();
      const auto* scale = paint_properties->Scale();
      const auto* rotate = paint_properties->Rotate();
      const auto* translate = paint_properties->Translate();
      const auto* effect = paint_properties->Effect();
      const auto* filter = paint_properties->Filter();
      has_direct_compositing_reasons =
          (transform && transform->HasDirectCompositingReasons()) ||
          (scale && scale->HasDirectCompositingReasons()) ||
          (rotate && rotate->HasDirectCompositingReasons()) ||
          (translate && translate->HasDirectCompositingReasons()) ||
          (effect && effect->HasDirectCompositingReasons()) ||
          (filter && filter->HasDirectCompositingReasons());
    }
    if (!has_direct_compositing_reasons &&
        To<KeyframeEffectModelBase>(model).RequiresPropertyNode()) {
      reasons |= kTargetHasInvalidCompositingState;
    }
  } else {
    reasons |= kTargetHasInvalidCompositingState;
  }

  return reasons;
}

// TODO(crbug.com/809685): consider refactor this function.
CompositorAnimations::FailureReasons
CompositorAnimations::CheckCanStartAnimationOnCompositor(
    const Timing& timing,
    const Timing::NormalizedTiming& normalized_timing,
    const Element& target_element,
    const Animation* animation_to_add,
    const EffectModel& effect,
    const PaintArtifactCompositor* paint_artifact_compositor,
    double animation_playback_rate,
    PropertyHandleSet* unsupported_properties) {
  FailureReasons reasons = CheckCanStartEffectOnCompositor(
      timing, normalized_timing, target_element, animation_to_add, effect,
      paint_artifact_compositor, animation_playback_rate,
      unsupported_properties);
  return reasons | CheckCanStartElementOnCompositor(target_element, effect);
}

void CompositorAnimations::CancelIncompatibleAnimationsOnCompositor(
    const Element& target_element,
    const Animation& animation_to_add,
    const EffectModel& effect_to_add) {
  if (!target_element.HasAnimations())
    return;

  std::array<bool, kCompositableProperties.size()> affects_property;
  for (size_t i = 0; i < kCompositableProperties.size(); i++) {
    PropertyHandle property(CSSProperty::Get(kCompositableProperties[i]));
    affects_property[i] = effect_to_add.Affects(property);
  }

  ElementAnimations* element_animations = target_element.GetElementAnimations();
  DCHECK(element_animations);

  for (const auto& entry : element_animations->Animations()) {
    Animation* attached_animation = entry.key;
    const auto* effect =
        DynamicTo<KeyframeEffect>(attached_animation->effect());
    if (!effect || effect->EffectTarget() != target_element)
      continue;

    if (!ConsiderAnimationAsIncompatible(*attached_animation, animation_to_add,
                                         effect_to_add)) {
      continue;
    }

    for (size_t i = 0; i < kCompositableProperties.size(); i++) {
      if (!affects_property[i])
        continue;

      PropertyHandle property(CSSProperty::Get(kCompositableProperties[i]));
      if (effect->Affects(property)) {
        attached_animation->CancelAnimationOnCompositor();
        break;
      }
    }
  }
}

void CompositorAnimations::StartAnimationOnCompositor(
    const Element& element,
    int group,
    std::optional<double> start_time,
    base::TimeDelta time_offset,
    const Timing& timing,
    const Timing::NormalizedTiming& normalized_timing,
    const Animation* animation,
    CompositorAnimation& compositor_animation,
    const EffectModel& effect,
    Vector<int>& started_keyframe_model_ids,
    double animation_playback_rate,
    bool is_monotonic_timeline,
    bool is_boundary_aligned) {
  DCHECK(started_keyframe_model_ids.empty());
  // TODO(petermayo): Pass the PaintArtifactCompositor before
  // BlinkGenPropertyTrees is always on.
  DCHECK_EQ(CheckCanStartAnimationOnCompositor(
                timing, normalized_timing, element, animation, effect, nullptr,
                animation_playback_rate),
            kNoFailure);

  const auto& keyframe_effect = To<KeyframeEffectModelBase>(effect);

  Vector<std::unique_ptr<cc::KeyframeModel>> keyframe_models;
  GetAnimationOnCompositor(element, timing, normalized_timing, group,
                           start_time, time_offset, keyframe_effect,
                           keyframe_models, animation_playback_rate,
                           is_monotonic_timeline, is_boundary_aligned);
  DCHECK(!keyframe_models.empty());
  for (auto& keyframe_model : keyframe_models) {
    int id = keyframe_model->id();
    compositor_animation.AddKeyframeModel(std::move(keyframe_model));
    started_keyframe_model_ids.push_back(id);
  }
  DCHECK(!started_keyframe_model_ids.empty());
}

void CompositorAnimations::CancelAnimationOnCompositor(
    const Element& element,
    CompositorAnimation* compositor_animation,
    int id,
    const EffectModel& model) {
  if (CheckCanStartElementOnCompositor(element, model) != kNoFailure) {
    // When an element is being detached, we cancel any associated
    // Animations for CSS animations. But by the time we get
    // here the mapping will have been removed.
    // FIXME: Defer remove/pause operations until after the
    // compositing update.
    return;
  }
  if (compositor_animation)
    compositor_animation->RemoveKeyframeModel(id);
}

void CompositorAnimations::PauseAnimationForTestingOnCompositor(
    const Element& element,
    const Animation& animation,
    int id,
    base::TimeDelta pause_time,
    const EffectModel& model) {
  DCHECK_EQ(Check
Prompt: 
```
这是目录为blink/renderer/core/animation/compositor_animations.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/animation/compositor_animations.h"

#include <algorithm>
#include <cmath>
#include <memory>

#include "cc/animation/animation_id_provider.h"
#include "cc/animation/filter_animation_curve.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/animation/animation_effect.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_color.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_double.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_filter_operations.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_transform.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_value.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/css/background_color_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/box_shadow_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/clip_path_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_transformable_container.h"
#include "third_party/blink/renderer/core/paint/filter_effect_builder.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/platform/animation/animation_translation_util.h"
#include "third_party/blink/renderer/platform/animation/compositor_animation.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/platform_paint_worklet_layer_painter.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/gfx/animation/keyframe/animation_curve.h"
#include "ui/gfx/animation/keyframe/keyframed_animation_curve.h"

namespace blink {

namespace {

constexpr auto kCompositableProperties = std::to_array<CSSPropertyID>({
    CSSPropertyID::kBackdropFilter,
    CSSPropertyID::kFilter,
    CSSPropertyID::kOpacity,
    CSSPropertyID::kRotate,
    CSSPropertyID::kScale,
    CSSPropertyID::kTransform,
    CSSPropertyID::kTranslate,
});

bool ConsiderAnimationAsIncompatible(const Animation& animation,
                                     const Animation& animation_to_add,
                                     const EffectModel& effect_to_add) {
  if (&animation == &animation_to_add)
    return false;

  if (animation.PendingInternal())
    return true;

  switch (animation.CalculateAnimationPlayState()) {
    case V8AnimationPlayState::Enum::kIdle:
      return false;
    case V8AnimationPlayState::Enum::kRunning:
      return true;
    case V8AnimationPlayState::Enum::kPaused:
    case V8AnimationPlayState::Enum::kFinished:
      if (Animation::HasLowerCompositeOrdering(
              &animation, &animation_to_add,
              Animation::CompareAnimationsOrdering::kPointerOrder)) {
        return effect_to_add.AffectedByUnderlyingAnimations();
      }
      return true;
    default:
      NOTREACHED();
  }
}

bool IsTransformRelatedCSSProperty(const PropertyHandle property) {
  return property.IsCSSProperty() &&
         (property.GetCSSProperty().IDEquals(CSSPropertyID::kRotate) ||
          property.GetCSSProperty().IDEquals(CSSPropertyID::kScale) ||
          property.GetCSSProperty().IDEquals(CSSPropertyID::kTransform) ||
          property.GetCSSProperty().IDEquals(CSSPropertyID::kTranslate));
}

bool HasIncompatibleAnimations(const Element& target_element,
                               const Animation& animation_to_add,
                               const EffectModel& effect_to_add) {
  if (!target_element.HasAnimations())
    return false;

  std::array<bool, kCompositableProperties.size()> affects_property;
  for (size_t i = 0; i < kCompositableProperties.size(); i++) {
    PropertyHandle property(CSSProperty::Get(kCompositableProperties[i]));
    affects_property[i] = effect_to_add.Affects(property);
  }

  ElementAnimations* element_animations = target_element.GetElementAnimations();
  DCHECK(element_animations);

  for (const auto& entry : element_animations->Animations()) {
    Animation* attached_animation = entry.key;
    const auto* effect =
        DynamicTo<KeyframeEffect>(attached_animation->effect());
    if (!effect || effect->EffectTarget() != target_element)
      continue;

    if (!ConsiderAnimationAsIncompatible(*attached_animation, animation_to_add,
                                         effect_to_add)) {
      continue;
    }

    for (size_t i = 0; i < kCompositableProperties.size(); i++) {
      if (!affects_property[i])
        continue;

      PropertyHandle property(CSSProperty::Get(kCompositableProperties[i]));
      if (effect->Affects(property))
        return true;
    }
  }

  return false;
}

void DefaultToUnsupportedProperty(
    PropertyHandleSet* unsupported_properties,
    const PropertyHandle& property,
    CompositorAnimations::FailureReasons* reasons) {
  (*reasons) |= CompositorAnimations::kUnsupportedCSSProperty;
  if (unsupported_properties) {
    unsupported_properties->insert(property);
  }
}

// True if it is either a no-op background-color animation, or a no-op custom
// property animation.
bool IsNoOpPaintWorkletOrVariableAnimation(const PropertyHandle& property,
                                      const LayoutObject* layout_object) {
  // If the background color paint worklet was painted, a unique id will be
  // generated. See BackgroundColorPaintWorklet::GetBGColorPaintWorkletParams
  // for details.
  // Similar to that, if a CSS paint worklet was painted, a unique id will be
  // generated. See CSSPaintValue::GetImage for details.
  bool has_unique_id = layout_object->FirstFragment().HasUniqueId();
  if (has_unique_id)
    return false;
  // Now the |has_unique_id| == false.
  bool is_no_op_bgcolor_anim =
      RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled() &&
      property.GetCSSProperty().PropertyID() == CSSPropertyID::kBackgroundColor;
  bool is_no_op_clip_anim =
      RuntimeEnabledFeatures::CompositeClipPathAnimationEnabled() &&
      property.GetCSSProperty().PropertyID() == CSSPropertyID::kClipPath;
  bool is_no_op_variable_anim =
      property.GetCSSProperty().PropertyID() == CSSPropertyID::kVariable;
  return is_no_op_variable_anim || is_no_op_clip_anim || is_no_op_bgcolor_anim;
}

bool CompositedAnimationRequiresProperties(const PropertyHandle& property,
                                           LayoutObject* layout_object) {
  if (!property.IsCSSProperty())
    return false;
  switch (property.GetCSSProperty().PropertyID()) {
    case CSSPropertyID::kRotate:
    case CSSPropertyID::kScale:
    case CSSPropertyID::kTranslate:
    case CSSPropertyID::kTransform:
      return !layout_object || layout_object->IsTransformApplicable();
    case CSSPropertyID::kOpacity:
    case CSSPropertyID::kBackdropFilter:
    case CSSPropertyID::kFilter:
      return true;
    default:
      return false;
  }
}

}  // namespace

CompositorElementIdNamespace
CompositorAnimations::CompositorElementNamespaceForProperty(
    CSSPropertyID property) {
  switch (property) {
    case CSSPropertyID::kOpacity:
    case CSSPropertyID::kBackdropFilter:
      return CompositorElementIdNamespace::kPrimaryEffect;
    case CSSPropertyID::kRotate:
      return CompositorElementIdNamespace::kRotateTransform;
    case CSSPropertyID::kScale:
      return CompositorElementIdNamespace::kScaleTransform;
    case CSSPropertyID::kTranslate:
      return CompositorElementIdNamespace::kTranslateTransform;
    case CSSPropertyID::kTransform:
      return CompositorElementIdNamespace::kPrimaryTransform;
    case CSSPropertyID::kFilter:
      return CompositorElementIdNamespace::kEffectFilter;
    case CSSPropertyID::kBackgroundColor:
    case CSSPropertyID::kBoxShadow:
    case CSSPropertyID::kClipPath:
    case CSSPropertyID::kVariable:
      // TODO(crbug.com/883721): Variables and these raster-inducing properties
      // should not require the target element to have any composited property
      // tree nodes - i.e. should not need to check for existence of a property
      // tree node. For now, variable animations target the primary animation
      // target node - the effect namespace.
      return CompositorElementIdNamespace::kPrimaryEffect;
    default:
      NOTREACHED();
  }
}

CompositorAnimations::FailureReasons
CompositorAnimations::CheckCanStartEffectOnCompositor(
    const Timing& timing,
    const Timing::NormalizedTiming& normalized_timing,
    const Element& target_element,
    const Animation* animation_to_add,
    const EffectModel& effect,
    const PaintArtifactCompositor* paint_artifact_compositor,
    double animation_playback_rate,
    PropertyHandleSet* unsupported_properties) {
  FailureReasons reasons = kNoFailure;
  const auto& keyframe_effect = To<KeyframeEffectModelBase>(effect);

  LayoutObject* layout_object = target_element.GetLayoutObject();
  // Elements with subtrees containing will-change: contents are not
  // composited for animations as if the contents change the tiles
  // would need to be rerastered anyways.
  if (layout_object && layout_object->Style()->SubtreeWillChangeContents()) {
    reasons |= kTargetHasInvalidCompositingState;
  }

  const PropertyHandleSet& properties =
      keyframe_effect.EnsureDynamicProperties();
  if (RuntimeEnabledFeatures::StaticAnimationOptimizationEnabled()) {
    // If all properties are static, we don't need to composite. The animation
    // can only change at a phase boundary.
    if (properties.empty()) {
      reasons |= kAnimationHasNoVisibleChange;
    }
  }
  if (keyframe_effect.HasStaticProperty()) {
    UseCounter::Count(target_element.GetDocument(),
                      WebFeature::kStaticPropertyInAnimation);
  }
  for (const auto& property : properties) {
    if (!property.IsCSSProperty()) {
      // None of the below reasons make any sense if |property| isn't CSS, so we
      // skip the rest of the loop in that case.
      reasons |= kAnimationAffectsNonCSSProperties;
      continue;
    }

    if (IsTransformRelatedCSSProperty(property)) {
      // We use this later in computing element IDs too.
      if (layout_object && !layout_object->IsTransformApplicable()) {
        // TODO(dbaron): We could consider ignoring the
        // transform-related property and still running the others on
        // the compositor.
        reasons |= kTransformRelatedPropertyCannotBeAcceleratedOnTarget;
      }
      if (const auto* svg_element = DynamicTo<SVGElement>(target_element)) {
        reasons |=
            CheckCanStartTransformAnimationOnCompositorForSVG(*svg_element);
        // TODO(https://crbug.com/1278452): When we make the transform tree
        // structure for SVG work like everything else, we should instead
        // start compositing animations of transform properties other than
        // transform.
        if (!property.GetCSSProperty().IDEquals(CSSPropertyID::kTransform))
          reasons |= kSVGTargetHasIndependentTransformProperty;
      }
    }

    const PropertySpecificKeyframeVector& keyframes =
        *keyframe_effect.GetPropertySpecificKeyframes(property);
    DCHECK_GE(keyframes.size(), 2U);
    for (const auto& keyframe : keyframes) {
      if (keyframe->Composite() != EffectModel::kCompositeReplace &&
          !keyframe->IsNeutral()) {
        reasons |= kEffectHasNonReplaceCompositeMode;
      }

      // FIXME: Determine candidacy based on the CSSValue instead of a snapshot
      // CompositorKeyframeValue.
      switch (property.GetCSSProperty().PropertyID()) {
        case CSSPropertyID::kOpacity:
          break;
        case CSSPropertyID::kRotate:
        case CSSPropertyID::kScale:
        case CSSPropertyID::kTranslate:
        case CSSPropertyID::kTransform:
          break;
        case CSSPropertyID::kFilter:
          if (keyframe->GetCompositorKeyframeValue() &&
              To<CompositorKeyframeFilterOperations>(
                  keyframe->GetCompositorKeyframeValue())
                  ->Operations()
                  .HasFilterThatMovesPixels()) {
            reasons |= kFilterRelatedPropertyMayMovePixels;
          }
          break;
        case CSSPropertyID::kBackdropFilter:
          // Backdrop-filter pixel moving filters do not change the layer bounds
          // like regular filters do, so they can still be composited.
          break;
        case CSSPropertyID::kBackgroundColor:
        case CSSPropertyID::kBoxShadow:
        case CSSPropertyID::kClipPath: {
          NativePaintImageGenerator* generator = nullptr;
          // Not having a layout object is a reason for not compositing marked
          // in CompositorAnimations::CheckCanStartElementOnCompositor.
          if (!layout_object) {
            continue;
          }
          if (property.GetCSSProperty().PropertyID() ==
                  CSSPropertyID::kBackgroundColor &&
              RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled()) {
            generator = target_element.GetDocument()
                            .GetFrame()
                            ->GetBackgroundColorPaintImageGenerator();
          } else if (property.GetCSSProperty().PropertyID() ==
                         CSSPropertyID::kBoxShadow &&
                     RuntimeEnabledFeatures ::
                         CompositeBoxShadowAnimationEnabled()) {
            generator = target_element.GetDocument()
                            .GetFrame()
                            ->GetBoxShadowPaintImageGenerator();
          } else if (property.GetCSSProperty().PropertyID() ==
                         CSSPropertyID::kClipPath &&
                     RuntimeEnabledFeatures::
                         CompositeClipPathAnimationEnabled()) {
            generator = target_element.GetDocument()
                            .GetFrame()
                            ->GetClipPathPaintImageGenerator();
          }
          Animation* compositable_animation = nullptr;

          // The generator may be null in tests.
          if (generator) {
            compositable_animation =
                generator->GetAnimationIfCompositable(&target_element);
          }

          if (!compositable_animation) {
            DefaultToUnsupportedProperty(unsupported_properties, property,
                                         &reasons);
          }
          break;
        }
        case CSSPropertyID::kVariable: {
          // Custom properties are supported only in the case of
          // OffMainThreadCSSPaintEnabled, and even then only for some specific
          // property types. Otherwise they are treated as unsupported.
          const CompositorKeyframeValue* keyframe_value =
              keyframe->GetCompositorKeyframeValue();
          if (keyframe_value) {
            DCHECK(RuntimeEnabledFeatures::OffMainThreadCSSPaintEnabled());
            DCHECK(keyframe_value->IsDouble() || keyframe_value->IsColor());
            // If a custom property is not used by CSS Paint, then we should not
            // support that on the compositor thread.
            if (layout_object && layout_object->Style() &&
                !layout_object->Style()->HasCSSPaintImagesUsingCustomProperty(
                    property.CustomPropertyName(),
                    layout_object->GetDocument())) {
              DefaultToUnsupportedProperty(unsupported_properties, property,
                                           &reasons);
            }
            // TODO: Add support for keyframes containing different types
            if (!keyframes.front() ||
                !keyframes.front()->GetCompositorKeyframeValue() ||
                keyframes.front()->GetCompositorKeyframeValue()->GetType() !=
                    keyframe_value->GetType()) {
              reasons |= kMixedKeyframeValueTypes;
            }
          } else {
            // We skip the rest of the loop in this case for the same reason as
            // unsupported CSS properties - see below.
            DefaultToUnsupportedProperty(unsupported_properties, property,
                                         &reasons);
            continue;
          }
          break;
        }
        default:
          // We skip the rest of the loop in this case because
          // |GetCompositorKeyframeValue()| will be false so we will
          // accidentally count this as kInvalidAnimationOrEffect as well.
          DefaultToUnsupportedProperty(unsupported_properties, property,
                                       &reasons);
          continue;
      }

      // The compositor animation for paint worklet animations do not snapshot
      // the individual keyframes. Instead the keyframes are interpolated within
      // the worklet based on the overall animation progress.
      const bool needs_compositor_keyframe_value =
          CompositedPropertyRequiresSnapshot(property);
      // If an element does not have style, then it will never have taken a
      // snapshot of its (non-existent) value for the compositor to use.
      if (needs_compositor_keyframe_value &&
          !keyframe->GetCompositorKeyframeValue()) {
        reasons |= kInvalidAnimationOrEffect;
      }
    }
  }

  if (CompositorPropertyAnimationsHaveNoEffect(target_element, effect,
                                               paint_artifact_compositor)) {
#if DCHECK_IS_ON()
    if (effect.Affects(PropertyHandle(GetCSSPropertyBackgroundColor()))) {
      ElementAnimations* element_animations =
          target_element.GetElementAnimations();
      DCHECK(element_animations &&
             element_animations->CompositedBackgroundColorStatus() !=
                 ElementAnimations::CompositedPaintStatus::kComposited);
    }
    if (effect.Affects(PropertyHandle(GetCSSPropertyClipPath()))) {
      ElementAnimations* element_animations =
          target_element.GetElementAnimations();
      DCHECK(element_animations &&
             element_animations->CompositedClipPathStatus() !=
                 ElementAnimations::CompositedPaintStatus::kComposited);
    }
#endif
    reasons |= kAnimationHasNoVisibleChange;
  }

  if (animation_to_add &&
      HasIncompatibleAnimations(target_element, *animation_to_add, effect)) {
    reasons |= kTargetHasIncompatibleAnimations;
  }

  CompositorTiming out;
  base::TimeDelta time_offset =
      animation_to_add ? animation_to_add->ComputeCompositorTimeOffset()
                       : base::TimeDelta();
  if (!ConvertTimingForCompositor(timing, normalized_timing, time_offset, out,
                                  animation_playback_rate)) {
    reasons |= kEffectHasUnsupportedTimingParameters;
  }

  return reasons;
}

bool CompositorAnimations::CompositorPropertyAnimationsHaveNoEffect(
    const Element& target_element,
    const EffectModel& effect,
    const PaintArtifactCompositor* paint_artifact_compositor) {
  LayoutObject* layout_object = target_element.GetLayoutObject();

  if (!paint_artifact_compositor) {
    // TODO(pdr): This should return true. This likely only affects tests.
    return false;
  }

  bool any_compositor_properties_missing = false;
  bool any_compositor_properties_present = false;

  const auto& keyframe_effect = To<KeyframeEffectModelBase>(effect);
  const auto& groups = keyframe_effect.GetPropertySpecificKeyframeGroups();
  bool has_paint_properties =
      layout_object && layout_object->FirstFragment().PaintProperties();
  for (const PropertyHandle& property : groups.Keys()) {
    if (!CompositedAnimationRequiresProperties(property, layout_object))
      continue;

    if (!has_paint_properties) {
      // We have an animated property that requires a property node but no paint
      // properties.
      any_compositor_properties_missing = true;
      break;
    }

    CompositorElementId target_element_id =
        CompositorElementIdFromUniqueObjectId(
            layout_object->UniqueId(),
            CompositorAnimations::CompositorElementNamespaceForProperty(
                property.GetCSSProperty().PropertyID()));
    DCHECK(target_element_id);
    if (paint_artifact_compositor->HasComposited(target_element_id))
      any_compositor_properties_present = true;
    else
      any_compositor_properties_missing = true;
  }

  // Because animations are a direct compositing reason for paint properties,
  // the only case when we wouldn't have compositor paint properties if when
  // they were optimized out due to not having an effect. An example of this is
  // hidden animations that do not paint.
  if (any_compositor_properties_missing) {
    // Because we're only considering properties that are animated on this
    // element, we should either have all properties or be missing all
    // properties.
    DCHECK(!any_compositor_properties_present);
    return true;
  }

  return false;
}

CompositorAnimations::FailureReasons
CompositorAnimations::CheckCanStartElementOnCompositor(
    const Element& target_element,
    const EffectModel& model) {
  FailureReasons reasons = kNoFailure;

  // TODO(crbug.com/1287221): Add a more specific reason.
  if (target_element.GetDocument().ShouldForceReduceMotion())
    reasons |= kAcceleratedAnimationsDisabled;

  // Both of these checks are required. It is legal to enable the compositor
  // thread but disable threaded animations, and there are situations where
  // threaded animations are enabled globally but this particular LocalFrame
  // does not have a compositor (e.g. for overlays).
  const Settings* settings = target_element.GetDocument().GetSettings();
  if ((settings && !settings->GetAcceleratedCompositingEnabled()) ||
      !Platform::Current()->IsThreadedAnimationEnabled()) {
    reasons |= kAcceleratedAnimationsDisabled;
  }

  if (const auto* svg_element = DynamicTo<SVGElement>(target_element))
    reasons |= CheckCanStartSVGElementOnCompositor(*svg_element);

  if (const auto* layout_object = target_element.GetLayoutObject()) {
    // We query paint property tree state below to determine whether the
    // animation is compositable. TODO(crbug.com/676456): There is a known
    // lifecycle violation where an animation can be cancelled during style
    // update. See CompositorAnimations::CancelAnimationOnCompositor().
    // When this is fixed we would like to enable the DCHECK below.
    // DCHECK_GE(GetDocument().Lifecycle().GetState(),
    //           DocumentLifecycle::kPrePaintClean);
    bool has_direct_compositing_reasons = false;
    if (layout_object->IsFragmented()) {
      // Composited animation on multiple fragments is not supported.
      reasons |= kTargetHasInvalidCompositingState;
    } else if (const auto* paint_properties =
                   layout_object->FirstFragment().PaintProperties()) {
      const auto* transform = paint_properties->Transform();
      const auto* scale = paint_properties->Scale();
      const auto* rotate = paint_properties->Rotate();
      const auto* translate = paint_properties->Translate();
      const auto* effect = paint_properties->Effect();
      const auto* filter = paint_properties->Filter();
      has_direct_compositing_reasons =
          (transform && transform->HasDirectCompositingReasons()) ||
          (scale && scale->HasDirectCompositingReasons()) ||
          (rotate && rotate->HasDirectCompositingReasons()) ||
          (translate && translate->HasDirectCompositingReasons()) ||
          (effect && effect->HasDirectCompositingReasons()) ||
          (filter && filter->HasDirectCompositingReasons());
    }
    if (!has_direct_compositing_reasons &&
        To<KeyframeEffectModelBase>(model).RequiresPropertyNode()) {
      reasons |= kTargetHasInvalidCompositingState;
    }
  } else {
    reasons |= kTargetHasInvalidCompositingState;
  }

  return reasons;
}

// TODO(crbug.com/809685): consider refactor this function.
CompositorAnimations::FailureReasons
CompositorAnimations::CheckCanStartAnimationOnCompositor(
    const Timing& timing,
    const Timing::NormalizedTiming& normalized_timing,
    const Element& target_element,
    const Animation* animation_to_add,
    const EffectModel& effect,
    const PaintArtifactCompositor* paint_artifact_compositor,
    double animation_playback_rate,
    PropertyHandleSet* unsupported_properties) {
  FailureReasons reasons = CheckCanStartEffectOnCompositor(
      timing, normalized_timing, target_element, animation_to_add, effect,
      paint_artifact_compositor, animation_playback_rate,
      unsupported_properties);
  return reasons | CheckCanStartElementOnCompositor(target_element, effect);
}

void CompositorAnimations::CancelIncompatibleAnimationsOnCompositor(
    const Element& target_element,
    const Animation& animation_to_add,
    const EffectModel& effect_to_add) {
  if (!target_element.HasAnimations())
    return;

  std::array<bool, kCompositableProperties.size()> affects_property;
  for (size_t i = 0; i < kCompositableProperties.size(); i++) {
    PropertyHandle property(CSSProperty::Get(kCompositableProperties[i]));
    affects_property[i] = effect_to_add.Affects(property);
  }

  ElementAnimations* element_animations = target_element.GetElementAnimations();
  DCHECK(element_animations);

  for (const auto& entry : element_animations->Animations()) {
    Animation* attached_animation = entry.key;
    const auto* effect =
        DynamicTo<KeyframeEffect>(attached_animation->effect());
    if (!effect || effect->EffectTarget() != target_element)
      continue;

    if (!ConsiderAnimationAsIncompatible(*attached_animation, animation_to_add,
                                         effect_to_add)) {
      continue;
    }

    for (size_t i = 0; i < kCompositableProperties.size(); i++) {
      if (!affects_property[i])
        continue;

      PropertyHandle property(CSSProperty::Get(kCompositableProperties[i]));
      if (effect->Affects(property)) {
        attached_animation->CancelAnimationOnCompositor();
        break;
      }
    }
  }
}

void CompositorAnimations::StartAnimationOnCompositor(
    const Element& element,
    int group,
    std::optional<double> start_time,
    base::TimeDelta time_offset,
    const Timing& timing,
    const Timing::NormalizedTiming& normalized_timing,
    const Animation* animation,
    CompositorAnimation& compositor_animation,
    const EffectModel& effect,
    Vector<int>& started_keyframe_model_ids,
    double animation_playback_rate,
    bool is_monotonic_timeline,
    bool is_boundary_aligned) {
  DCHECK(started_keyframe_model_ids.empty());
  // TODO(petermayo): Pass the PaintArtifactCompositor before
  // BlinkGenPropertyTrees is always on.
  DCHECK_EQ(CheckCanStartAnimationOnCompositor(
                timing, normalized_timing, element, animation, effect, nullptr,
                animation_playback_rate),
            kNoFailure);

  const auto& keyframe_effect = To<KeyframeEffectModelBase>(effect);

  Vector<std::unique_ptr<cc::KeyframeModel>> keyframe_models;
  GetAnimationOnCompositor(element, timing, normalized_timing, group,
                           start_time, time_offset, keyframe_effect,
                           keyframe_models, animation_playback_rate,
                           is_monotonic_timeline, is_boundary_aligned);
  DCHECK(!keyframe_models.empty());
  for (auto& keyframe_model : keyframe_models) {
    int id = keyframe_model->id();
    compositor_animation.AddKeyframeModel(std::move(keyframe_model));
    started_keyframe_model_ids.push_back(id);
  }
  DCHECK(!started_keyframe_model_ids.empty());
}

void CompositorAnimations::CancelAnimationOnCompositor(
    const Element& element,
    CompositorAnimation* compositor_animation,
    int id,
    const EffectModel& model) {
  if (CheckCanStartElementOnCompositor(element, model) != kNoFailure) {
    // When an element is being detached, we cancel any associated
    // Animations for CSS animations. But by the time we get
    // here the mapping will have been removed.
    // FIXME: Defer remove/pause operations until after the
    // compositing update.
    return;
  }
  if (compositor_animation)
    compositor_animation->RemoveKeyframeModel(id);
}

void CompositorAnimations::PauseAnimationForTestingOnCompositor(
    const Element& element,
    const Animation& animation,
    int id,
    base::TimeDelta pause_time,
    const EffectModel& model) {
  DCHECK_EQ(CheckCanStartElementOnCompositor(element, model), kNoFailure);
  CompositorAnimation* compositor_animation =
      animation.GetCompositorAnimation();
  DCHECK(compositor_animation);
  compositor_animation->PauseKeyframeModel(id, pause_time);
}

void CompositorAnimations::AttachCompositedLayers(
    Element& element,
    CompositorAnimation* compositor_animation) {
  if (!compositor_animation)
    return;

  CompositorElementIdNamespace element_id_namespace =
      CompositorElementIdNamespace::kPrimary;
  // We create an animation namespace element id when an element has created all
  // property tree nodes which may be required by the keyframe effects. The
  // animation affects multiple element ids, and one is pushed each
  // KeyframeModel. See |GetAnimationOnCompositor|. We use the kPrimaryEffect
  // node to know if nodes have been created for animations.
  element_id_namespace = CompositorElementIdNamespace::kPrimaryEffect;
  compositor_animation->AttachElement(CompositorElementIdFromUniqueObjectId(
      element.GetLayoutObject()->UniqueId(), element_id_namespace));
}

bool CompositorAnimations::ConvertTimingForCompositor(
    const Timing& timing,
    const Timing::NormalizedTiming& normalized_timing,
    base::TimeDelta time_offset,
    CompositorTiming& out,
    double animation_playback_rate,
    bool is_monotonic_timeline,
    bool is_boundary_aligned) {
  timing.AssertValid();

  if (animation_playback_rate == 0)
    return false;

  // FIXME: Compositor does not know anything about endDelay.
  if (!normalized_timing.end_delay.is_zero())
    return false;

  if (!timing.iteration_count ||
      normalized_timing.iteration_duration.is_zero() ||
      normalized_timing.iteration_duration.is_max())
    return false;

  // Compositor's time offset is positive for seeking into the animation.
  DCHECK(animation_playback_rate);
  double delay = animation_playback_rate > 0
                     ? normalized_timing.start_delay.InSecondsF()
                     : 0;

  bas
"""


```