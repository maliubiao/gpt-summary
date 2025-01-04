Response:
Let's break down the thought process for analyzing this `keyframe_effect.cc` file.

1. **Understand the Context:** The first step is to recognize that this is a Chromium Blink rendering engine source file. The directory `blink/renderer/core/animation/` strongly suggests it deals with animations. The filename `keyframe_effect.cc` hints at managing keyframe-based animations.

2. **Identify the Core Class:**  The file name directly corresponds to the `KeyframeEffect` class definition within the code. This is the central element we need to understand.

3. **Analyze Includes:**  The `#include` directives provide valuable clues about dependencies and related functionalities. Look for key terms:
    * **`bindings/core/v8`**: This indicates interaction with JavaScript through the V8 engine. Specifically, `V8_KEYFRAME_EFFECT_OPTIONS` and `V8_OBJECT_BUILDER` suggest this class handles options passed from JavaScript and potentially builds JavaScript objects.
    * **`animation/`**:  Numerous includes from this directory (`AnimationInputHelpers`, `AnimationUtils`, `CompositorAnimations`, etc.) reinforce the file's role in animation management. Each included file likely represents a specific aspect of the animation pipeline.
    * **`css/`**:  Includes like `CSSSelectorParser`, `CSSPropertyRef`, and `StyleResolver` point to the file's involvement with CSS properties and how they are applied in animations.
    * **`dom/`**:  `Element` and `PseudoElement` indicate that `KeyframeEffect` operates on DOM elements and their associated pseudo-elements.
    * **`platform/animation/`**: `CompositorAnimation` suggests interaction with the compositor thread for potentially hardware-accelerated animations.

4. **Examine the `Create` Methods:**  The static `Create` methods are often the entry points for creating instances of the class. Notice the different overloads, some taking `ScriptValue` for keyframes and options, directly indicating how JavaScript interacts with this class. The presence of `ExceptionState&` signals error handling during the creation process.

5. **Analyze Member Variables:**  The private member variables reveal the state managed by the `KeyframeEffect` class:
    * `effect_target_`, `target_element_`, `target_pseudo_`: These clearly relate to the target of the animation (element, pseudo-element).
    * `model_`:  This suggests a separate "model" object responsible for holding the animation data (keyframes, timing functions, etc.). The `KeyframeEffectModelBase` type confirms this.
    * `sampled_effect_`: This hints at a mechanism for sampling the effect at a specific time, likely for applying the animation's effects.
    * `priority_`: Indicates prioritization of this effect.
    * `ignore_css_keyframes_`: A flag to control whether CSS-defined keyframes are used.
    * `compositor_keyframe_model_ids_`:  Suggests interaction with the compositor for hardware-accelerated animations.

6. **Explore Key Methods and Their Functionality:**  Go through the public methods and understand their purpose:
    * **Getters and Setters:** Methods like `getTarget`, `setTarget`, `pseudoElement`, `setPseudoElement`, `composite`, `setComposite`, `getKeyframes`, `setKeyframes` provide access to and modification of the `KeyframeEffect`'s properties. Pay attention to how these methods interact with the `model_`.
    * **`Affects`:** Determines if the effect modifies a specific CSS property.
    * **`CheckCanStartAnimationOnCompositor` and `StartAnimationOnCompositor`:**  These are crucial for understanding how animations are moved to the compositor for better performance.
    * **`CancelAnimationOnCompositor`:** Handles stopping compositor-based animations.
    * **`ApplyEffects` and `ClearEffects`:**  Manage the application and removal of the animation's visual changes. The interaction with `SampledEffect` is key here.
    * **`Attach` and `Detach`:**  Manage the lifecycle of the effect within the animation system.
    * **`CalculateTimeToEffectChange`:** Deals with timing calculations for the animation.
    * **`HasIncompatibleStyle` and `AffectsImportantProperty`:**  Handle cases where compositor animations might conflict with CSS styles.
    * **`InterpolationsForCommitStyles`:**  Deals with collecting the active animation values for style updates.

7. **Identify Relationships to Web Technologies:** Based on the included headers and the functionality of the methods:
    * **JavaScript:**  The `Create` methods accepting `ScriptValue` and the `getKeyframes` method returning `HeapVector<ScriptValue>` clearly show interaction with JavaScript. The options parameters also come from JavaScript.
    * **HTML:** The `Element* target` parameters and the handling of `PseudoElement` demonstrate the effect's association with HTML elements.
    * **CSS:** The manipulation of CSS properties (through `PropertyHandle`), the handling of pseudo-elements, and the presence of methods related to important properties and style compatibility directly link this class to CSS. The parsing of keyframes from CSS syntax is also evident.

8. **Look for Logic and Assumptions:**
    * The `CalculateKeyframeOrdering` function demonstrates sorting of keyframes based on their offsets or original index, depending on whether it's a CSS animation or a Web Animation API animation.
    * The logic in `ApplyEffects` around `SampledEffect` suggests a caching or optimization mechanism for applying animation values.
    * The checks for compositor compatibility involve assumptions about which properties can be efficiently animated on the GPU.

9. **Scan for Potential User/Developer Errors:** Look for places where incorrect input or usage might cause problems:
    * The `setPseudoElement` method includes validation to ensure the pseudo-selector is valid.
    * The `Create` methods use `ExceptionState` for error reporting, indicating potential issues during object creation if invalid parameters are provided.
    *  The comments around TODOs can point to areas where current behavior might be incomplete or have known issues.

10. **Structure the Analysis:**  Organize the findings into logical sections (Functionality, Relationships, Logic, Usage Errors) for clarity. Use examples where possible to illustrate the concepts.

By following these steps, we can systematically analyze the source code and extract meaningful information about its purpose, interactions, and potential issues. The process involves understanding the domain (web animations), examining the code structure and dependencies, and inferring functionality from the method names and their parameters.
Based on the provided source code for `blink/renderer/core/animation/keyframe_effect.cc`, here's a breakdown of its functionality, its relationship with web technologies, logical inferences, and potential user errors:

**Functionality of `keyframe_effect.cc`:**

This file defines the `KeyframeEffect` class, which is a core component in Blink's animation system responsible for managing and applying keyframe-based animations to DOM elements. Here are its primary functions:

1. **Manages Keyframe Data:**
   - Stores and manipulates keyframe data associated with an animation effect. This includes the properties being animated, their values at different points in time (keyframes), and timing functions.
   - It uses a `KeyframeEffectModelBase` (or its subclasses like `StringKeyframeEffectModel`) to hold the actual keyframe data.

2. **Targets DOM Elements (and Pseudo-elements):**
   - Associates the animation effect with a specific `Element` or a pseudo-element of an `Element`.
   - Allows setting and getting the target element and the target pseudo-element.

3. **Handles Timing and Playback:**
   - Integrates with the broader animation system to manage the timing of the effect (start delay, duration, iterations, etc.). This is inherited from the `AnimationEffect` base class.

4. **Applies Animation Effects:**
   - When an animation is playing, `KeyframeEffect` is responsible for sampling the keyframe data at the current time and applying the corresponding styles to the target element.
   - It uses a `SampledEffect` object to cache and apply the interpolated values.

5. **Supports Compositor Animations:**
   - Plays a key role in determining if an animation can be offloaded to the compositor thread for smoother, hardware-accelerated rendering.
   - Provides methods to start, cancel, and manage animations on the compositor.
   - Checks for conditions that prevent compositing (e.g., animating properties marked as `!important`, targeting elements with CSS `offset` properties).

6. **Interacts with JavaScript:**
   - Provides static `Create` methods that are called from JavaScript when creating `KeyframeEffect` objects (e.g., using the Web Animations API's `KeyframeEffect` constructor).
   - Handles conversion of JavaScript objects representing keyframes and timing options into internal Blink representations.
   - Provides the `getKeyframes` method to retrieve the computed keyframe data back to JavaScript.

7. **Handles Composite Operations:**
   - Manages the `composite` operation (e.g., `replace`, `add`, `accumulate`) which determines how the animation's effects are combined with existing styles.

8. **Manages Priority:**
   - Stores and manages the priority of the animation effect, influencing how multiple animations affecting the same property are resolved.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:**
    - **Creation:** The `KeyframeEffect::Create` methods are the primary entry point from JavaScript when using the Web Animations API. For instance:
      ```javascript
      const element = document.getElementById('myElement');
      const keyframes = [
        { opacity: 0, offset: 0 },
        { opacity: 1, offset: 1 }
      ];
      const options = { duration: 1000 };
      const keyframeEffect = new KeyframeEffect(element, keyframes, options);
      ```
    - **Retrieval:** The `getKeyframes` method allows JavaScript to inspect the computed keyframes:
      ```javascript
      const computedKeyframes = keyframeEffect.getKeyframes();
      console.log(computedKeyframes);
      ```
    - **Setting Keyframes:** The `setKeyframes` method allows JavaScript to modify the keyframes of an existing effect:
      ```javascript
      keyframeEffect.setKeyframes([
        { transform: 'translateX(0px)', offset: 0 },
        { transform: 'translateX(100px)', offset: 1 }
      ]);
      ```
    - **Controlling Composite Operation:** The `composite` property (getter and setter) maps directly to the JavaScript API:
      ```javascript
      keyframeEffect.composite = 'add';
      ```

* **HTML:**
    - **Targeting Elements:** The `KeyframeEffect` is always associated with a specific HTML `Element` (or a pseudo-element). The JavaScript examples above demonstrate targeting an element using `document.getElementById`.
    - **Pseudo-elements:** The `pseudoElement` property allows animations to target specific parts of an element, like `::before` or `::after`:
      ```javascript
      const keyframeEffect = new KeyframeEffect(element, keyframes, { pseudoElement: '::before' });
      ```

* **CSS:**
    - **Animating CSS Properties:** The keyframes define changes to CSS properties (e.g., `opacity`, `transform`, `color`). The `Affects` method checks if the effect modifies a given CSS property.
    - **CSS Animations and Transitions:** While this file primarily deals with the Web Animations API, it also interacts with CSS animations and transitions. The `ignore_css_keyframes_` flag suggests a mechanism to potentially prioritize Web Animations API keyframes over CSS-defined keyframes.
    - **`!important`:** The code checks if the animation affects properties marked as `!important` in CSS, which can prevent compositor offloading.
    - **CSS `offset`:**  The code checks if the target element has CSS `offset` properties (like `offset-path`), which can also impact compositor animation eligibility.
    - **Pseudo-element Selectors:** The `ValidateAndCanonicalizePseudo` function ensures that the pseudo-element selectors provided are valid CSS syntax.

**Logical Inferences (Assumptions and Outputs):**

1. **Keyframe Ordering:**
   - **Assumption:** Keyframes can be provided in any order.
   - **Logic:** The `CalculateKeyframeOrdering` function sorts keyframes based on their `offset` values (for standard keyframes) or their original index (for timeline offsets or if explicitly requested). This ensures the animation progresses logically.
   - **Input (Example):** A `KeyframeVector` with keyframes having offsets [0.5, 0, 1].
   - **Output:** A `Vector<int>` representing the sorted indices, e.g., [1, 0, 2].

2. **Pseudo-element Validation:**
   - **Assumption:** Pseudo-element selectors from JavaScript might not always be correctly formatted.
   - **Logic:** The `ValidateAndCanonicalizePseudo` function checks if the provided pseudo-element selector is valid and canonicalizes legacy forms (e.g., `:before` to `::before`).
   - **Input (Example):**  The string `":before"`.
   - **Output:** The string `"::before"` and the function returns `true`.
   - **Input (Example):** The string `":invalid-pseudo"`.
   - **Output:** The original string remains unchanged, and the function returns `false`.

3. **Compositor Animation Eligibility:**
   - **Assumption:**  Certain conditions prevent animations from being efficiently run on the compositor.
   - **Logic:** The `CheckCanStartAnimationOnCompositor` method performs a series of checks, considering factors like:
     - наличие keyframes.
     - наличие target element.
     - использование CSS `offset` properties on the target.
     - animating properties marked as `!important`.
     - whether the affected properties are compositable.
   - **Input (Example):** A `KeyframeEffect` targeting an element with `opacity` and `transform` keyframes, with no `!important` styles or CSS `offset`.
   - **Output:** `CompositorAnimations::kNoFailure`.
   - **Input (Example):** A `KeyframeEffect` targeting an element with a CSS rule like `opacity: 0 !important;` and trying to animate `opacity`.
   - **Output:** `CompositorAnimations::kAffectsImportantProperty`.

4. **Applying Effects (Sampling):**
   - **Assumption:** Animation values need to be calculated (sampled) at specific points in time.
   - **Logic:** The `ApplyEffects` method, when the animation is active, samples the `KeyframeEffectModelBase` at the current time to determine the interpolated values for the animated properties. It uses the `SampledEffect` to store these values and apply them.
   - **Input (Example):** An animation at 50% progress with keyframes for `opacity: 0` at 0% and `opacity: 1` at 100%.
   - **Output:** The `SampledEffect` will contain an interpolation for `opacity` with a value of approximately 0.5.

**Common Usage Errors (User or Programming):**

1. **Invalid Pseudo-selector:** Providing an incorrect or non-standard pseudo-element selector in the `pseudoElement` option will result in a `DOMException`.
   ```javascript
   const effect = new KeyframeEffect(element, keyframes, { pseudoElement: ':invalid' }); // This will throw an error.
   ```

2. **Animating `!important` Properties:** Attempting to animate a CSS property that is marked as `!important` might not have the desired effect, especially for compositor animations. The browser might prioritize the `!important` style. While the animation might run, it might not be offloaded to the compositor, and the `!important` style might override the animation's effect.

3. **Conflicting Animations:**  Multiple animations targeting the same property on the same element can lead to unexpected results. The browser uses animation priority and the order of application to resolve conflicts. Developers need to be mindful of potential clashes.

4. **Incorrect Keyframe Offsets:** Providing keyframes with offsets outside the range of 0 to 1, or with offsets that are not in ascending order (for standard keyframes), can lead to unpredictable animation behavior.

5. **Type Mismatches in Keyframe Values:** Providing keyframe values that are not compatible with the property being animated (e.g., trying to animate `opacity` with a string value) will likely be ignored or cause errors.

6. **Modifying Keyframes After Animation Starts (Performance):** While the API allows modifying keyframes after an animation has started, doing so frequently can impact performance as the animation system needs to re-evaluate and potentially restart the animation.

7. **Forgetting to Attach Animation to an Element/Timeline:** Creating a `KeyframeEffect` alone doesn't start the animation. It needs to be associated with an `Animation` object, which in turn needs to be played on an `AnimationTimeline`.

This analysis provides a comprehensive overview of the `keyframe_effect.cc` file's role and functionality within the Chromium Blink rendering engine.

Prompt: 
```
这是目录为blink/renderer/core/animation/keyframe_effect.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

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

#include "third_party/blink/renderer/core/animation/keyframe_effect.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_keyframe_effect_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_keyframeeffectoptions_unrestricteddouble.h"
#include "third_party/blink/renderer/core/animation/animation_input_helpers.h"
#include "third_party/blink/renderer/core/animation/animation_utils.h"
#include "third_party/blink/renderer/core/animation/compositor_animations.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_transform.h"
#include "third_party/blink/renderer/core/animation/effect_input.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/sampled_effect.h"
#include "third_party/blink/renderer/core/animation/timing_calculations.h"
#include "third_party/blink/renderer/core/animation/timing_input.h"
#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/platform/animation/compositor_animation.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

namespace {

// Verifies that a pseudo-element selector lexes and canonicalizes legacy forms
bool ValidateAndCanonicalizePseudo(String& selector) {
  if (selector.IsNull()) {
    return true;
  } else if (selector.StartsWith("::")) {
    return true;
  } else if (selector == ":before") {
    selector = "::before";
    return true;
  } else if (selector == ":after") {
    selector = "::after";
    return true;
  } else if (selector == ":first-letter") {
    selector = "::first-letter";
    return true;
  } else if (selector == ":first-line") {
    selector = "::first-line";
    return true;
  }
  return false;
}

enum class KeyframeOrderStrategy { kSpecifiedOrdering, kCssKeyframeOrdering };

Vector<int> CalculateKeyframeOrdering(const KeyframeVector& keyframes,
                                      KeyframeOrderStrategy strategy) {
  Vector<int> indices;
  indices.ReserveInitialCapacity(keyframes.size());
  for (wtf_size_t i = 0; i < keyframes.size(); i++) {
    indices.push_back(i);
  }

  if (keyframes.empty()) {
    return indices;
  }

  if (strategy == KeyframeOrderStrategy::kSpecifiedOrdering) {
    auto less_than = [&keyframes](int a, int b) {
      // Sort by original index
      return keyframes[a]->Index() < keyframes[b]->Index();
    };
    std::stable_sort(indices.begin(), indices.end(), less_than);
  } else {
    // CSS keyframe order.
    auto less_than = [&keyframes](int a, int b) {
      auto* first = keyframes[a].Get();
      auto* second = keyframes[b].Get();
      // Sort plain percentages ahead of timeline offsets
      if (first->GetTimelineOffset().has_value() !=
          second->GetTimelineOffset().has_value()) {
        return second->GetTimelineOffset().has_value();
      }
      // Sort timeline offsets by original index.
      if (first->GetTimelineOffset().has_value()) {
        return first->Index() < second->Index();
      }
      // Sort plain percentages by offset.
      return first->Offset() < second->Offset();
    };
    std::stable_sort(indices.begin(), indices.end(), less_than);
  }
  return indices;
}

}  // namespace

KeyframeEffect* KeyframeEffect::Create(
    ScriptState* script_state,
    Element* element,
    const ScriptValue& keyframes,
    const V8UnionKeyframeEffectOptionsOrUnrestrictedDouble* options,
    ExceptionState& exception_state) {
  Document* document = element ? &element->GetDocument() : nullptr;
  Timing timing = TimingInput::Convert(options, document, exception_state);
  if (exception_state.HadException())
    return nullptr;

  EffectModel::CompositeOperation composite = EffectModel::kCompositeReplace;
  String pseudo = String();
  if (options->IsKeyframeEffectOptions()) {
    auto* effect_options = options->GetAsKeyframeEffectOptions();
    composite = EffectModel::EnumToCompositeOperation(
        effect_options->composite().AsEnum());
    if (!effect_options->pseudoElement().empty()) {
      pseudo = effect_options->pseudoElement();
      if (!ValidateAndCanonicalizePseudo(pseudo)) {
        // TODO(gtsteel): update when
        // https://github.com/w3c/csswg-drafts/issues/4586 resolves
        exception_state.ThrowDOMException(
            DOMExceptionCode::kSyntaxError,
            "A valid pseudo-selector must be null or start with ::.");
      }
    }
  }

  KeyframeEffectModelBase* model = EffectInput::Convert(
      element, keyframes, composite, script_state, exception_state);
  if (exception_state.HadException())
    return nullptr;
  KeyframeEffect* effect =
      MakeGarbageCollected<KeyframeEffect>(element, model, timing);

  if (!pseudo.empty()) {
    effect->target_pseudo_ = pseudo;
    if (element) {
      element->GetDocument().UpdateStyleAndLayoutTreeForElement(
          element, DocumentUpdateReason::kWebAnimation);

      AtomicString pseudo_argument = WTF::g_null_atom;

      PseudoId pseudo_id = CSSSelectorParser::ParsePseudoElement(
          pseudo, element, pseudo_argument);
      effect->effect_target_ =
          element->GetStyledPseudoElement(pseudo_id, pseudo_argument);
    }
  }
  return effect;
}

KeyframeEffect* KeyframeEffect::Create(ScriptState* script_state,
                                       Element* element,
                                       const ScriptValue& keyframes,
                                       ExceptionState& exception_state) {
  KeyframeEffectModelBase* model =
      EffectInput::Convert(element, keyframes, EffectModel::kCompositeReplace,
                           script_state, exception_state);
  if (exception_state.HadException())
    return nullptr;
  return MakeGarbageCollected<KeyframeEffect>(element, model, Timing());
}

KeyframeEffect* KeyframeEffect::Create(ScriptState* script_state,
                                       KeyframeEffect* source,
                                       ExceptionState& exception_state) {
  Timing new_timing = source->SpecifiedTiming();
  KeyframeEffectModelBase* model = source->Model()->Clone();
  return MakeGarbageCollected<KeyframeEffect>(source->EffectTarget(), model,
                                              new_timing, source->GetPriority(),
                                              source->GetEventDelegate());
}

KeyframeEffect::KeyframeEffect(Element* target,
                               KeyframeEffectModelBase* model,
                               const Timing& timing,
                               Priority priority,
                               EventDelegate* event_delegate)
    : AnimationEffect(timing, event_delegate),
      effect_target_(target),
      target_element_(target),
      target_pseudo_(),
      model_(model),
      sampled_effect_(nullptr),
      priority_(priority),
      ignore_css_keyframes_(false) {
  DCHECK(model_);

  // fix target for css animations and transitions
  if (target && target->IsPseudoElement()) {
    // The |target_element_| is used to target events in script when
    // animating pseudo elements. This requires using the DOM element that the
    // pseudo element originates from.
    target_element_ =
        DynamicTo<PseudoElement>(target)->UltimateOriginatingElement();
    DCHECK(!target_element_->IsPseudoElement());
    target_pseudo_ = PseudoElement::PseudoElementNameForEvents(target);
  }

  CountAnimatedProperties();
}

KeyframeEffect::~KeyframeEffect() = default;

void KeyframeEffect::setTarget(Element* new_target) {
  DCHECK(!new_target || !new_target->IsPseudoElement());
  target_element_ = new_target;
  RefreshTarget();
}

const String& KeyframeEffect::pseudoElement() const {
  return target_pseudo_;
}

void KeyframeEffect::setPseudoElement(String pseudo,
                                      ExceptionState& exception_state) {
  if (ValidateAndCanonicalizePseudo(pseudo)) {
    target_pseudo_ = pseudo;
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "A valid pseudo-selector must be null or start with ::.");
    return;
  }

  RefreshTarget();
}

void KeyframeEffect::RefreshTarget() {
  Element* new_target;
  if (!target_element_) {
    new_target = nullptr;
  } else if (target_pseudo_.empty()) {
    new_target = target_element_;
  } else {
    target_element_->GetDocument().UpdateStyleAndLayoutTreeForElement(
        target_element_, DocumentUpdateReason::kWebAnimation);
    AtomicString argument;
    PseudoId pseudoId = CSSSelectorParser::ParsePseudoElement(
        target_pseudo_, target_element_, argument);
    new_target = target_element_->GetPseudoElement(pseudoId, argument);
  }

  if (new_target != effect_target_) {
    DetachTarget(GetAnimation());
    effect_target_ = new_target;
    AttachTarget(GetAnimation());
    InvalidateAndNotifyOwner();
  }
}

V8CompositeOperation KeyframeEffect::composite() const {
  return V8CompositeOperation(
      EffectModel::CompositeOperationToEnum(CompositeInternal()));
}

void KeyframeEffect::setComposite(const V8CompositeOperation& composite) {
  Model()->SetComposite(
      EffectModel::EnumToCompositeOperation(composite.AsEnum()));

  ClearEffects();
  InvalidateAndNotifyOwner();
}

// Returns a list of 'ComputedKeyframes'. A ComputedKeyframe consists of the
// normal keyframe data combined with the computed offset for the given
// keyframe.
// https://w3.org/TR/web-animations-1/#dom-keyframeeffect-getkeyframes
HeapVector<ScriptValue> KeyframeEffect::getKeyframes(
    ScriptState* script_state) {
  if (Animation* animation = GetAnimation()) {
    animation->FlushPendingUpdates();
    if (AnimationTimeline* timeline = animation->TimelineInternal()) {
      animation->ResolveTimelineOffsets(timeline->GetTimelineRange());
    }
  }

  HeapVector<ScriptValue> computed_keyframes;
  if (!model_->HasFrames() || !script_state->ContextIsValid())
    return computed_keyframes;

  KeyframeVector keyframes = ignore_css_keyframes_
                                 ? model_->GetFrames()
                                 : model_->GetComputedKeyframes(EffectTarget());

  KeyframeOrderStrategy strategy =
      ignore_css_keyframes_ || !model_->IsCssKeyframeEffectModel()
          ? KeyframeOrderStrategy::kSpecifiedOrdering
          : KeyframeOrderStrategy::kCssKeyframeOrdering;
  Vector<int> indices = CalculateKeyframeOrdering(keyframes, strategy);

  Vector<double> computed_offsets =
      KeyframeEffectModelBase::GetComputedOffsets(keyframes);
  computed_keyframes.ReserveInitialCapacity(keyframes.size());
  ScriptState::Scope scope(script_state);
  for (wtf_size_t i = 0; i < keyframes.size(); i++) {
    V8ObjectBuilder object_builder(script_state);
    keyframes[indices[i]]->AddKeyframePropertiesToV8Object(object_builder,
                                                           target());
    object_builder.AddNumber("computedOffset", computed_offsets[indices[i]]);
    computed_keyframes.push_back(object_builder.GetScriptValue());
  }

  return computed_keyframes;
}

void KeyframeEffect::setKeyframes(ScriptState* script_state,
                                  const ScriptValue& keyframes,
                                  ExceptionState& exception_state) {
  StringKeyframeVector new_keyframes = EffectInput::ParseKeyframesArgument(
      target(), keyframes, script_state, exception_state);
  if (exception_state.HadException())
    return;

  ignore_css_keyframes_ = true;

  if (auto* model = DynamicTo<TransitionKeyframeEffectModel>(Model()))
    SetModel(model->CloneAsEmptyStringKeyframeModel());

  DCHECK(Model()->IsStringKeyframeEffectModel());
  SetKeyframes(new_keyframes);
}

void KeyframeEffect::SetKeyframes(StringKeyframeVector keyframes) {
  To<StringKeyframeEffectModel>(Model())->SetFrames(keyframes);

  // Changing the keyframes will invalidate any sampled effect, as well as
  // potentially affect the effect owner.
  ClearEffects();
  InvalidateAndNotifyOwner();
  CountAnimatedProperties();
}

bool KeyframeEffect::Affects(const PropertyHandle& property) const {
  return model_->Affects(property);
}

bool KeyframeEffect::HasRevert() const {
  return model_->HasRevert();
}

void KeyframeEffect::NotifySampledEffectRemovedFromEffectStack() {
  sampled_effect_ = nullptr;
}

CompositorAnimations::FailureReasons
KeyframeEffect::CheckCanStartAnimationOnCompositor(
    const PaintArtifactCompositor* paint_artifact_compositor,
    double animation_playback_rate,
    PropertyHandleSet* unsupported_properties) const {
  CompositorAnimations::FailureReasons reasons =
      CompositorAnimations::kNoFailure;

  // There would be no reason to composite an effect that has no keyframes; it
  // has no visual result.
  if (model_->Properties().empty())
    reasons |= CompositorAnimations::kInvalidAnimationOrEffect;

  // There would be no reason to composite an effect that has no target; it has
  // no visual result.
  if (!effect_target_) {
    reasons |= CompositorAnimations::kInvalidAnimationOrEffect;
  } else if (!IsCurrent()) {
    // There is no reason to composite an effect that is not current, and
    // CheckCanStartAnimationOnCompositor might assert about having some but
    // not all properties if we call it on such an animation.
    reasons |= CompositorAnimations::kInvalidAnimationOrEffect;
  } else {
    if (effect_target_->GetComputedStyle() &&
        effect_target_->GetComputedStyle()->HasOffset())
      reasons |= CompositorAnimations::kTargetHasCSSOffset;

    // Do not animate a property on the compositor that is marked important.
    if (AffectsImportantProperty())
      reasons |= CompositorAnimations::kAffectsImportantProperty;

    reasons |= CompositorAnimations::CheckCanStartAnimationOnCompositor(
        SpecifiedTiming(), NormalizedTiming(), *effect_target_, GetAnimation(),
        *Model(), paint_artifact_compositor, animation_playback_rate,
        unsupported_properties);
  }

  return reasons;
}

void KeyframeEffect::StartAnimationOnCompositor(
    int group,
    std::optional<double> start_time,
    base::TimeDelta time_offset,
    double animation_playback_rate,
    CompositorAnimation* compositor_animation,
    bool is_monotonic_timeline,
    bool is_boundary_aligned) {
  DCHECK(!HasActiveAnimationsOnCompositor());
  // TODO(petermayo): Maybe we should recheck that we can start on the
  // compositor if we have the compositable IDs somewhere.

  if (!compositor_animation)
    compositor_animation = GetAnimation()->GetCompositorAnimation();

  DCHECK(compositor_animation);
  DCHECK(effect_target_);
  DCHECK(Model());

  CompositorAnimations::StartAnimationOnCompositor(
      *effect_target_, group, start_time, time_offset, SpecifiedTiming(),
      NormalizedTiming(), GetAnimation(), *compositor_animation, *Model(),
      compositor_keyframe_model_ids_, animation_playback_rate,
      is_monotonic_timeline, is_boundary_aligned);
  DCHECK(!compositor_keyframe_model_ids_.empty());
}

bool KeyframeEffect::HasActiveAnimationsOnCompositor() const {
  return !compositor_keyframe_model_ids_.empty();
}

bool KeyframeEffect::HasActiveAnimationsOnCompositor(
    const PropertyHandle& property) const {
  return HasActiveAnimationsOnCompositor() && Affects(property);
}

bool KeyframeEffect::CancelAnimationOnCompositor(
    CompositorAnimation* compositor_animation) {
  if (!HasActiveAnimationsOnCompositor())
    return false;
  // Don't check effect_target_->GetLayoutObject(); we might be here because
  // it's *just* been set to null.
  if (!effect_target_)
    return false;
  DCHECK(Model());
  for (const auto& compositor_keyframe_model_id :
       compositor_keyframe_model_ids_) {
    CompositorAnimations::CancelAnimationOnCompositor(
        *effect_target_, compositor_animation, compositor_keyframe_model_id,
        *Model());
  }
  compositor_keyframe_model_ids_.clear();
  return true;
}

void KeyframeEffect::CancelIncompatibleAnimationsOnCompositor() {
  if (effect_target_ && GetAnimation() && model_->HasFrames()) {
    DCHECK(Model());
    CompositorAnimations::CancelIncompatibleAnimationsOnCompositor(
        *effect_target_, *GetAnimation(), *Model());
  }
}

void KeyframeEffect::PauseAnimationForTestingOnCompositor(
    base::TimeDelta pause_time) {
  DCHECK(HasActiveAnimationsOnCompositor());
  if (!effect_target_ || !effect_target_->GetLayoutObject())
    return;
  DCHECK(GetAnimation());
  DCHECK(Model());
  for (const auto& compositor_keyframe_model_id :
       compositor_keyframe_model_ids_) {
    CompositorAnimations::PauseAnimationForTestingOnCompositor(
        *effect_target_, *GetAnimation(), compositor_keyframe_model_id,
        pause_time, *Model());
  }
}

void KeyframeEffect::AttachCompositedLayers() {
  DCHECK(effect_target_);
  DCHECK(GetAnimation());
  CompositorAnimation* compositor_animation =
      GetAnimation()->GetCompositorAnimation();
  if (compositor_animation && !Model()->RequiresPropertyNode()) {
    compositor_animation->AttachPaintWorkletElement();
    return;
  }
  CompositorAnimations::AttachCompositedLayers(*effect_target_,
                                               compositor_animation);
}

bool KeyframeEffect::HasAnimation() const {
  return !!owner_;
}

bool KeyframeEffect::HasPlayingAnimation() const {
  return owner_ && owner_->Playing();
}

void KeyframeEffect::Trace(Visitor* visitor) const {
  visitor->Trace(effect_target_);
  visitor->Trace(target_element_);
  visitor->Trace(model_);
  visitor->Trace(sampled_effect_);
  AnimationEffect::Trace(visitor);
}

namespace {

using TransformPropertiesArray = std::array<const CSSProperty*, 4>;

const TransformPropertiesArray& TransformProperties() {
  static const TransformPropertiesArray kTransformProperties{
      &GetCSSPropertyTransform(), &GetCSSPropertyScale(),
      &GetCSSPropertyRotate(), &GetCSSPropertyTranslate()};
  return kTransformProperties;
}

}  // namespace

bool KeyframeEffect::UpdateBoxSizeAndCheckTransformAxisAlignment(
    const gfx::SizeF& box_size) {
  bool preserves_axis_alignment = true;
  bool has_transform = false;
  TransformOperation::BoxSizeDependency size_dependencies =
      TransformOperation::kDependsNone;
  for (const auto* property : TransformProperties()) {
    const auto* keyframes =
        Model()->GetPropertySpecificKeyframes(PropertyHandle(*property));
    if (!keyframes)
      continue;

    has_transform = true;
    for (const auto& keyframe : *keyframes) {
      const auto* value = keyframe->GetCompositorKeyframeValue();
      if (!value)
        continue;
      const auto& transform_operations =
          To<CompositorKeyframeTransform>(value)->GetTransformOperations();
      if (!transform_operations.PreservesAxisAlignment())
        preserves_axis_alignment = false;
      size_dependencies = TransformOperation::CombineDependencies(
          size_dependencies, transform_operations.BoxSizeDependencies());
    }
  }

  if (!has_transform)
    return true;

  if (HasAnimation()) {
    if (effect_target_size_) {
      if ((size_dependencies & TransformOperation::kDependsWidth) &&
          (effect_target_size_->width() != box_size.width()))
        RestartRunningAnimationOnCompositor();
      else if ((size_dependencies & TransformOperation::kDependsHeight) &&
               (effect_target_size_->height() != box_size.height()))
        RestartRunningAnimationOnCompositor();
    }
  }

  effect_target_size_ = box_size;

  return preserves_axis_alignment;
}

void KeyframeEffect::RestartRunningAnimationOnCompositor() {
  Animation* animation = GetAnimation();
  if (!animation)
    return;

  // No need to to restart an animation that is in the process of starting up,
  // paused or idle.
  if (!animation->StartTimeInternal())
    return;

  animation->RestartAnimationOnCompositor();
}

bool KeyframeEffect::IsIdentityOrTranslation() const {
  for (const auto* property : TransformProperties()) {
    const auto* keyframes =
        Model()->GetPropertySpecificKeyframes(PropertyHandle(*property));
    if (!keyframes)
      continue;

    for (const auto& keyframe : *keyframes) {
      if (const auto* value = keyframe->GetCompositorKeyframeValue()) {
        if (!To<CompositorKeyframeTransform>(value)
                 ->GetTransformOperations()
                 .IsIdentityOrTranslation()) {
          return false;
        }
      }
    }
  }
  return true;
}

EffectModel::CompositeOperation KeyframeEffect::CompositeInternal() const {
  return model_->Composite();
}

void KeyframeEffect::ApplyEffects() {
  DCHECK(IsInEffect());
  if (!effect_target_ || !model_->HasFrames())
    return;

  if (GetAnimation() && HasIncompatibleStyle()) {
    GetAnimation()->CancelAnimationOnCompositor();
  }

  std::optional<double> iteration = CurrentIteration();
  DCHECK(iteration);
  DCHECK_GE(iteration.value(), 0);
  bool changed = false;

  // Determine if the left or right limit is used when at a discontinuity in
  // timing function.  The css-easing spec calls for using a "before flag", and
  // instructions for setting the flag are in the web-animations-1 spec.
  // The term "before" is somehwat convoluted since the before flag is to be set
  // to true of in the before phase of the animation and playing forward, or in
  // the after phase of the animation and playing backwards. Using limit
  // direction in place of a "before" flag since the ultimate goal is to
  // determine the one-sided limit to use.
  // See https://drafts.csswg.org/css-easing/#step-easing-algo
  // See
  // https://www.w3.org/TR/web-animations-1/#calculating-the-transformed-progress
  // TODO(crbug.com/347967022): Fix reversed animation in the after phase.
  TimingFunction::LimitDirection limit_direction =
      (GetPhase() == Timing::kPhaseBefore)
          ? TimingFunction::LimitDirection::LEFT
          : TimingFunction::LimitDirection::RIGHT;

  if (sampled_effect_) {
    changed =
        model_->Sample(ClampTo<int>(iteration.value(), 0), Progress().value(),
                       limit_direction, NormalizedTiming().iteration_duration,
                       sampled_effect_->MutableInterpolations());
  } else {
    HeapVector<Member<Interpolation>> interpolations;
    model_->Sample(ClampTo<int>(iteration.value(), 0), Progress().value(),
                   limit_direction, NormalizedTiming().iteration_duration,
                   interpolations);
    if (!interpolations.empty()) {
      auto* sampled_effect =
          MakeGarbageCollected<SampledEffect>(this, owner_->SequenceNumber());
      sampled_effect->MutableInterpolations().swap(interpolations);
      sampled_effect_ = sampled_effect;
      effect_target_->EnsureElementAnimations().GetEffectStack().Add(
          sampled_effect);
      changed = true;
    } else {
      return;
    }
  }

  if (changed) {
    effect_target_->SetNeedsAnimationStyleRecalc();
    auto* svg_element = DynamicTo<SVGElement>(effect_target_.Get());
    if (RuntimeEnabledFeatures::WebAnimationsSVGEnabled() && svg_element)
      svg_element->SetWebAnimationsPending();
  }
}

void KeyframeEffect::ClearEffects() {
  if (!sampled_effect_) {
    return;
  }
  sampled_effect_->Clear();
  sampled_effect_ = nullptr;
  if (GetAnimation())
    GetAnimation()->RestartAnimationOnCompositor();
  if (!effect_target_->GetDocument().Lifecycle().InDetach()) {
    effect_target_->SetNeedsAnimationStyleRecalc();
  }
  auto* svg_element = DynamicTo<SVGElement>(effect_target_.Get());
  if (RuntimeEnabledFeatures::WebAnimationsSVGEnabled() && svg_element)
    svg_element->ClearWebAnimatedAttributes();
  Invalidate();
}

void KeyframeEffect::UpdateChildrenAndEffects() const {
  if (!model_->HasFrames())
    return;
  DCHECK(owner_);
  if (IsInEffect() && !owner_->EffectSuppressed() &&
      !owner_->ReplaceStateRemoved()) {
    const_cast<KeyframeEffect*>(this)->ApplyEffects();
  } else {
    const_cast<KeyframeEffect*>(this)->ClearEffects();
  }
}

void KeyframeEffect::Attach(AnimationEffectOwner* owner) {
  AttachTarget(owner->GetAnimation());
  AnimationEffect::Attach(owner);
}

void KeyframeEffect::Detach() {
  DetachTarget(GetAnimation());
  AnimationEffect::Detach();
}

void KeyframeEffect::AttachTarget(Animation* animation) {
  if (!effect_target_ || !animation)
    return;
  effect_target_->EnsureElementAnimations().Animations().insert(animation);
  effect_target_->SetNeedsAnimationStyleRecalc();
  auto* svg_element = DynamicTo<SVGElement>(effect_target_.Get());
  if (RuntimeEnabledFeatures::WebAnimationsSVGEnabled() && svg_element)
    svg_element->SetWebAnimationsPending();
}

void KeyframeEffect::DetachTarget(Animation* animation) {
  if (effect_target_ && animation)
    effect_target_->GetElementAnimations()->Animations().erase(animation);
  // If we have sampled this effect previously, we need to purge that state.
  // ClearEffects takes care of clearing the cached sampled effect, informing
  // the target that it needs to refresh its style, and doing any necessary
  // update on the compositor.
  ClearEffects();
}

AnimationTimeDelta KeyframeEffect::CalculateTimeToEffectChange(
    bool forwards,
    std::optional<AnimationTimeDelta> local_time,
    AnimationTimeDelta time_to_next_iteration) const {
  const AnimationTimeDelta start_time = NormalizedTiming().start_delay;

  const AnimationTimeDelta end_time_minus_end_delay =
      start_time + NormalizedTiming().active_duration;

  const AnimationTimeDelta end_time =
      end_time_minus_end_delay + NormalizedTiming().end_delay;

  const AnimationTimeDelta after_time =
      std::min(end_time_minus_end_delay, end_time);

  Timing::Phase phase = GetPhase();
  DCHECK(local_time || phase == Timing::kPhaseNone);
  switch (phase) {
    case Timing::kPhaseNone:
      return AnimationTimeDelta::Max();
    case Timing::kPhaseBefore:
      // Return value is clamped at 0 to prevent unexpected results that could
      // be caused by returning negative values.
      return forwards ? std::max(start_time - local_time.value(),
                                 AnimationTimeDelta())
                      : AnimationTimeDelta::Max();
    case Timing::kPhaseActive:
      if (forwards) {
        // Need service to apply fill / fire events.
        const AnimationTimeDelta time_to_end = after_time - local_time.value();
        if (RequiresIterationEvents()) {
          return std::min(time_to_end, time_to_next_iteration);
        }
        return time_to_end;
      }
      return {};
    case Timing::kPhaseAfter:
      DCHECK(TimingCalculations::GreaterThanOrEqualToWithinTimeTolerance(
          local_time.value(), after_time));
      if (forwards) {
        // If an animation has a positive-valued end delay, we need an
        // additional tick at the end time to ensure that the finished event is
        // delivered.
        return end_time > local_time ? end_time - local_time.value()
                                     : AnimationTimeDelta::Max();
      }
      return local_time.value() - after_time;
    default:
      NOTREACHED();
  }
}

std::optional<AnimationTimeDelta> KeyframeEffect::TimelineDuration() const {
  if (GetAnimation() && GetAnimation()->TimelineInternal()) {
    return GetAnimation()->TimelineInternal()->GetDuration();
  }
  return std::nullopt;
}

// Returns true if transform, translate, rotate or scale is composited
// and a motion path or other transform properties
// has been introduced on the element
bool KeyframeEffect::HasIncompatibleStyle() const {
  if (!effect_target_->GetComputedStyle())
    return false;

  if (HasActiveAnimationsOnCompositor()) {
    if (effect_target_->GetComputedStyle()->HasOffset()) {
      for (const auto* property : TransformProperties()) {
        if (Affects(PropertyHandle(*property))) {
          return true;
        }
      }
    }
  }

  return false;
}

bool KeyframeEffect::AffectsImportantProperty() const {
  if (!effect_target_->GetComputedStyle())
    return false;

  const CSSBitset* important_properties =
      effect_target_->GetComputedStyle()->GetBaseImportantSet();

  if (!important_properties)
    return false;

  for (CSSPropertyID property_id : *important_properties) {
    if (Affects(PropertyHandle(CSSProperty::Get(property_id))))
      return true;
  }

  return false;
}

ActiveInterpolationsMap KeyframeEffect::InterpolationsForCommitStyles() {
  // If the associated animation has been removed, it needs to be temporarily
  // reintroduced to the effect stack in order to be including in the
  // interpolations map.
  bool removed = owner_->ReplaceStateRemoved();
  if (removed)
    ApplyEffects();

  auto property_pass_filter = [](const PropertyHandle& property) {
    return property.IsCSSProperty();
  };

  ActiveInterpolationsMap results = EffectStack::ActiveInterpolations(
      &target()->GetElementAnimations()->GetEffectStack(),
      /*new_animations=*/nullptr,
      /*suppressed_animations=*/nullptr, kDefaultPriority, property_pass_filter,
      this);

  if (removed) {
    ClearEffects();
  }

  return results;
}

void KeyframeEffect::SetLogicalPropertyResolutionContext(
    WritingDirectionMode writing_direction) {
  if (auto* model = DynamicTo<StringKeyframeEffectModel>(Model())) {
    if (model->SetLogicalPropertyResolutionContext(writing_direction)) {
      ClearEffects();
      InvalidateAndNotifyOwner();
    }
  }
}

void KeyframeEffect::CountAnimatedProperties() const {
  if (target_element_) {
    Document& document = target_element_->GetDocument();
    for (const auto& property : model_->Properties()) {
      if (property.IsCSSProperty()) {
        DCHECK(IsValidCSSPropertyID(property.GetCSSProperty().PropertyID()));
        document.CountAnimatedProperty(property.GetCSSProperty().PropertyID());
      }
    }
  }
}

}  // namespace blink

"""

```