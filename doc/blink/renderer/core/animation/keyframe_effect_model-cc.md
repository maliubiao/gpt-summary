Response:
My thought process to analyze the provided code and answer the request went something like this:

1. **Understand the Goal:** The request asks for the functionalities of the `keyframe_effect_model.cc` file within the Chromium Blink engine. It also specifically asks about its relationship with JavaScript, HTML, and CSS, as well as examples of logical reasoning and common usage errors.

2. **Initial Skim and Keyword Identification:** I quickly skimmed the code looking for key terms and patterns. I noted things like "KeyframeEffectModelBase," "keyframes," "properties," "animation," "compositor," "CSS," "JavaScript," "HTML," "offset," "timing function," "interpolation," and various methods like `Sample`, `Snapshot*`, `SetFrames`, etc. This gave me a high-level idea of the file's purpose.

3. **Focus on Class Structure:** I identified the main class, `KeyframeEffectModelBase`. This is the core of the file. I paid attention to its member variables (e.g., `keyframes_`, `keyframe_groups_`, `interpolation_effect_`, `composite_`) and methods.

4. **Deconstruct Functionalities by Method:** I systematically went through the public methods of `KeyframeEffectModelBase` and tried to understand their roles. I paid attention to:
    * **Getters:** `Properties()`, `EnsureDynamicProperties()`, `HasStaticProperty()`, `IsTransformRelatedEffect()`, `IsReplaceOnly()` - these reveal what information the class can provide.
    * **Setters:** `SetFrames()`, `SetComposite()`, `SetLogicalPropertyResolutionContext()` - these indicate how the state of the model is modified.
    * **Core Logic:** `Sample()`, `SnapshotNeutralCompositorKeyframes()`, `SnapshotAllCompositorKeyframesIfNecessary()`, `GetComputedOffsets()`, `ResolveTimelineOffsets()` - these methods represent the key actions and computations performed by the class.
    * **Internal Management:** `EnsureKeyframeGroups()`, `EnsureInterpolationEffectPopulated()`, `IndexKeyframesAndResolveComputedOffsets()`, `ClearCachedData()` - these are for internal data management and optimization.

5. **Identify Relationships with Web Technologies:**  As I examined the methods, I actively looked for connections to JavaScript, HTML, and CSS.
    * **CSS:** The file heavily interacts with CSS properties (e.g., `GetCSSPropertyOpacity()`, `GetCSSPropertyTransform()`), CSS values, and concepts like `composite`. The `Snapshot*` methods clearly deal with how CSS animations are handled for compositing. The concept of keyframes directly maps to CSS `@keyframes`.
    * **JavaScript:**  The `SetFrames()` methods are likely called when JavaScript uses the Web Animations API (e.g., `element.animate()`) to define keyframes. The `Sample()` method is indirectly related to how the browser advances the animation based on the timeline controlled (often implicitly) by the JavaScript animation.
    * **HTML:** The code interacts with `Element` objects. CSS animations are applied to HTML elements.

6. **Logical Reasoning Examples:** I looked for places where the code makes decisions or computations based on input. The `GetComputedOffsets()` method was a prime example of logical deduction, where it determines the implicit offsets of keyframes when not explicitly provided. The conditional logic in `EnsureInterpolationEffectPopulated()` based on `RuntimeEnabledFeatures::StaticAnimationOptimizationEnabled()` also shows a form of logic.

7. **Common Usage Errors:** I considered what could go wrong when using CSS animations or the Web Animations API, which this code supports. Incorrectly specified offsets, conflicting keyframe values, and not understanding the implications of compositing seemed like relevant examples.

8. **Structure the Answer:**  I organized the information into logical sections as requested:
    * **Functionality:** I listed the key responsibilities of the class based on my analysis of the methods.
    * **Relationships with JavaScript, HTML, CSS:** I provided explicit examples connecting the code to these technologies.
    * **Logical Reasoning:** I chose `GetComputedOffsets()` as a clear example and detailed its input and output.
    * **Common Usage Errors:** I provided practical examples of mistakes developers might make.

9. **Refine and Clarify:** I reread my answer to ensure clarity, accuracy, and conciseness. I tried to use language that was easy to understand while still being technically accurate. I also ensured I addressed all parts of the original request.

This iterative process of skimming, detailed analysis, and connecting the code to the broader web development context allowed me to generate the comprehensive answer. The comments in the code itself were also helpful in understanding specific logic and design decisions.

这个文件 `keyframe_effect_model.cc` 是 Chromium Blink 渲染引擎中负责处理 CSS 动画和 Web Animations API 中关键帧效果的核心组件。 它主要负责以下功能：

**1. 存储和管理关键帧数据:**

*   **存储关键帧:**  它使用 `HeapVector<Member<Keyframe>>` 或 `HeapVector<Member<StringKeyframe>>` 来存储动画的关键帧。每个关键帧定义了在特定时间点的属性值。
*   **管理关键帧的偏移量 (offset):**  处理显式设置的偏移量（例如 `offset: 50%`）和时间轴偏移量（与滚动或其他时间轴关联），并计算最终的 `ComputedOffset`。对于没有显式偏移量的关键帧，它会根据其他关键帧的位置进行计算。
*   **分组管理属性特定的关键帧:**  它将具有相同 CSS 属性的关键帧组织到 `KeyframeGroupMap` 中，方便后续处理，例如插值计算和合成。

**2. 计算动画过程中的属性值 (插值):**

*   **`Sample()` 方法:** 这是核心的采样函数。给定一个迭代次数、动画进度 (fraction) 和时间相关信息，它会计算出当前时刻的属性值。
*   **插值效果 (Interpolation Effect):** 使用 `InterpolationEffect` 对象来执行关键帧之间的插值计算，从而得到动画过程中的平滑过渡效果。
*   **处理缓动函数 (Timing Function):**  考虑每个关键帧的缓动函数，影响插值的速度曲线。

**3. 支持合成 (Compositing) 优化:**

*   **快照中性的合成器关键帧 (`SnapshotNeutralCompositorKeyframes`) 和快照所有合成器关键帧 (`SnapshotAllCompositorKeyframesIfNecessary`):** 这两个方法用于确定哪些属性需要在合成器线程上进行动画，以提高性能。它们会比较动画前后的样式，并对需要合成的属性创建快照。
*   **`SnapshotCompositableProperties` 和 `SnapshotCompositorKeyFrames`:** 这些辅助方法用于遍历可合成的属性，并为每个属性的关键帧填充合成器需要的值。
*   **判断是否需要属性节点 (`RequiresPropertyNode`):**  确定动画是否需要创建 PropertyNode，这是 Compositing 的一部分。

**4. 处理逻辑属性:**

*   **`SetLogicalPropertyResolutionContext()`:**  允许设置书写方向模式（从左到右或从右到左），以便正确处理像 `margin-inline-start` 这样的逻辑属性。

**5. 其他重要功能:**

*   **确定动态属性 (`EnsureDynamicProperties`):**  识别在动画过程中会发生变化的属性。
*   **判断是否包含静态属性 (`HasStaticProperty`):**  如果一个动画的所有关键帧中某个属性的值都相同，则该属性是静态的，可以进行优化。
*   **处理合成操作 (`SetComposite`):** 设置动画的合成操作（例如 `replace`, `add`, `accumulate`）。
*   **判断是否为变换相关的效果 (`IsTransformRelatedEffect`):**  判断动画是否影响 `transform`, `rotate`, `scale`, `translate` 等属性。
*   **判断是否为仅替换合成 (`IsReplaceOnly`):**  检查动画是否所有的关键帧都使用了 `replace` 合成操作。
*   **处理时间轴偏移 (`ResolveTimelineOffsets`):**  当动画与时间轴（例如滚动时间轴）关联时，解析关键帧的时间轴偏移量，将其转换为实际的动画进度。
*   **清除缓存数据 (`ClearCachedData`):**  在关键帧数据或配置发生变化时，清除缓存的插值效果和分组信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **JavaScript (Web Animations API):**
    *   **关系:**  `KeyframeEffectModelBase` 是 Web Animations API 的底层实现。当你在 JavaScript 中使用 `element.animate()` 创建动画时，Blink 引擎会创建 `KeyframeEffectModelBase` 的实例来管理这个动画。
    *   **举例:**
        ```javascript
        const element = document.getElementById('myElement');
        element.animate([
          { opacity: 0, offset: 0 },
          { opacity: 1, offset: 1 }
        ], {
          duration: 1000
        });
        ```
        在这个例子中，传递给 `animate()` 方法的关键帧数组会被转换为 `Keyframe` 对象并存储在 `KeyframeEffectModelBase` 中。`offset` 属性会被用来计算 `ComputedOffset`。

*   **CSS (CSS Animations):**
    *   **关系:**  `KeyframeEffectModelBase` 也用于处理 CSS 动画（通过 `@keyframes` 规则定义）。当浏览器解析 CSS 并遇到动画时，会创建相应的 `KeyframeEffectModelBase` 对象。
    *   **举例:**
        ```css
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        #myElement {
          animation: fadeIn 1s;
        }
        ```
        在这个例子中，`fadeIn` 动画的关键帧信息（`from` 和 `to` 实际上会被转换为偏移量为 0 和 1 的关键帧）会被解析并存储在 `KeyframeEffectModelBase` 中。

*   **HTML:**
    *   **关系:**  动画效果最终会应用到 HTML 元素上。 `KeyframeEffectModelBase` 的方法，如 `SnapshotCompositableProperties`，需要 `Element` 对象作为参数，以便访问元素的样式信息和进行合成相关的操作。
    *   **举例:**  上述 JavaScript 和 CSS 的例子中，动画都是应用于 HTML 元素 `#myElement` 的。`KeyframeEffectModelBase` 会操作与该元素关联的样式。

**逻辑推理的假设输入与输出举例:**

假设我们有以下关键帧定义：

**输入:**

```
Keyframes:
  Keyframe 1: offset: null, opacity: 0.5
  Keyframe 2: offset: 0.75, opacity: 1
  Keyframe 3: offset: 1, opacity: 0
```

**逻辑推理:**  `GetComputedOffsets()` 方法会根据已有的偏移量来计算缺失的偏移量。

**输出:**

```
Computed Offsets:
  Keyframe 1: offset: 0  // 因为第一个关键帧缺失偏移量，默认为 0
  Keyframe 2: offset: 0.75
  Keyframe 3: offset: 1
```

另一个例子，考虑时间轴偏移：

**输入:**

```
Keyframes:
  Keyframe 1: offset: "entry 100px", opacity: 0.5  // 假设 "entry" 时间轴范围从 0px 到 200px
  Keyframe 2: offset: "exit 50%", opacity: 1     // 假设 "exit" 时间轴范围从 300px 到 400px
```

**假设时间轴范围和位置:** `timeline_range` 为 "entry"， `range_start` 为 0， `range_end` 为 200。

**逻辑推理:** `ResolveTimelineOffsets()` 会将时间轴偏移量转换为 0 到 1 之间的值。

**输出:**

```
Computed Offsets:
  Keyframe 1: offset: 0.5  // "entry 100px" 在 0px 到 200px 的中间
  Keyframe 2: 关键帧 2 的偏移量需要根据 "exit" 时间轴范围计算，如果当前时间轴不是 "exit"，则该关键帧可能不可达。
```

**用户或编程常见的使用错误举例:**

1. **关键帧偏移量顺序错误:**
    *   **错误:** 在 JavaScript 或 CSS 中定义关键帧时，偏移量不是递增的。
        ```javascript
        element.animate([
          { opacity: 1, offset: 0.5 },
          { opacity: 0, offset: 0.2 } // 错误：0.2 在 0.5 之前
        ], { duration: 1000 });
        ```
    *   **结果:**  `KeyframeEffectModelBase` 可能会调整或忽略这些关键帧，导致动画效果不符合预期。

2. **在 CSS 动画中混合使用 `from`/`to` 和带有偏移量的关键帧:**
    *   **错误:**  同时使用 `from`/`to` 和带有 `offset` 属性的关键帧可能会导致理解上的混乱和意外行为。`from` 相当于 `offset: 0`，`to` 相当于 `offset: 1`。
    *   **结果:** 动画效果可能不符合预期，因为浏览器需要处理多种定义关键帧的方式。

3. **在合成线程动画中修改非合成属性:**
    *   **错误:**  尝试在 CSS 动画或 Web Animations API 中动画修改一个无法在合成线程上高效处理的属性（例如 `width`、`height`），可能会导致性能问题，因为这会触发主线程的重绘和重排。
    *   **结果:** 动画可能卡顿或掉帧。`KeyframeEffectModelBase` 中的快照机制会尝试缓解这个问题，但最好还是动画可合成的属性（例如 `opacity`, `transform`）。

4. **时间轴偏移配置错误:**
    *   **错误:**  在使用视图时间轴或其他自定义时间轴时，关键帧的偏移量引用了不存在或配置错误的命名范围。
    *   **结果:**  `KeyframeEffectModelBase` 可能无法解析这些偏移量，导致相关的关键帧不生效，动画效果缺失。 在代码中可以看到，如果时间轴偏移无法解析，关键帧会被标记为不可达。

理解 `keyframe_effect_model.cc` 的功能对于深入了解浏览器如何处理动画以及如何优化动画性能至关重要。 它涉及到 CSS 动画、Web Animations API 以及浏览器渲染流水线的多个方面。

### 提示词
```
这是目录为blink/renderer/core/animation/keyframe_effect_model.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
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

#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"

#include <limits>
#include <utility>

#include "third_party/blink/renderer/core/animation/animation_effect.h"
#include "third_party/blink/renderer/core/animation/compositor_animations.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/css/css_property_equality.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "ui/gfx/geometry/transform.h"

namespace blink {

PropertyHandleSet KeyframeEffectModelBase::Properties() const {
  PropertyHandleSet result;
  for (const auto& keyframe : keyframes_) {
    if (!keyframe->HasComputedOffset()) {
      // Keyframe is not reachable. This case occurs when we have a timeline
      // offset in the keyframe but are not using a view timeline and thus the
      // offset cannot be resolved.
      continue;
    }
    for (const auto& property : keyframe->Properties()) {
      result.insert(property);
    }
  }
  return result;
}

const PropertyHandleSet& KeyframeEffectModelBase::EnsureDynamicProperties() const {
  if (dynamic_properties_) {
    return *dynamic_properties_;
  }

  dynamic_properties_ = std::make_unique<PropertyHandleSet>();
  EnsureKeyframeGroups();
  if (!RuntimeEnabledFeatures::StaticAnimationOptimizationEnabled()) {
    // Unless the static optimization is enabled, all properties are considered
    // dynamic.
    for (const auto& entry : *keyframe_groups_) {
      dynamic_properties_->insert(entry.key);
    }
  } else {
    for (const auto& entry : *keyframe_groups_) {
      if (!entry.value->IsStatic()) {
        dynamic_properties_->insert(entry.key);
      }
    }
  }

  return *dynamic_properties_;
}

bool KeyframeEffectModelBase::HasStaticProperty() const {
  EnsureKeyframeGroups();
  for (const auto& entry : *keyframe_groups_) {
    if (entry.value->IsStatic()) {
      return true;
    }
  }
  return false;
}

template <class K>
void KeyframeEffectModelBase::SetFrames(HeapVector<K>& keyframes) {
  // TODO(samli): Should also notify/invalidate the animation
  keyframes_.clear();
  keyframes_.AppendVector(keyframes);
  IndexKeyframesAndResolveComputedOffsets();
  ClearCachedData();
}

template CORE_EXPORT void KeyframeEffectModelBase::SetFrames(
    HeapVector<Member<Keyframe>>& keyframes);
template CORE_EXPORT void KeyframeEffectModelBase::SetFrames(
    HeapVector<Member<StringKeyframe>>& keyframes);

void KeyframeEffectModelBase::SetComposite(CompositeOperation composite) {
  composite_ = composite;
  ClearCachedData();
}

bool KeyframeEffectModelBase::Sample(
    int iteration,
    double fraction,
    TimingFunction::LimitDirection limit_direction,
    AnimationTimeDelta iteration_duration,
    HeapVector<Member<Interpolation>>& result) const {
  DCHECK_GE(iteration, 0);
  EnsureKeyframeGroups();
  EnsureInterpolationEffectPopulated();

  bool changed = iteration != last_iteration_ || fraction != last_fraction_ ||
                 iteration_duration != last_iteration_duration_;
  last_iteration_ = iteration;
  last_fraction_ = fraction;
  last_iteration_duration_ = iteration_duration;
  interpolation_effect_->GetActiveInterpolations(fraction, limit_direction,
                                                 result);
  return changed;
}

namespace {

using CompositablePropertiesArray = std::array<const CSSProperty*, 9>;

const CompositablePropertiesArray& CompositableProperties() {
  static const CompositablePropertiesArray kCompositableProperties{
      &GetCSSPropertyOpacity(),        &GetCSSPropertyRotate(),
      &GetCSSPropertyScale(),          &GetCSSPropertyTransform(),
      &GetCSSPropertyTranslate(),      &GetCSSPropertyFilter(),
      &GetCSSPropertyBackdropFilter(), &GetCSSPropertyBackgroundColor(),
      &GetCSSPropertyClipPath()};
  return kCompositableProperties;
}

enum class OffsetType {
  // Specified percentage offsets, e.g.
  // elem.animate([{offset: 0, ...}, {offset: "50%", ...}], {});
  kSpecified,

  // Specified offset calculations, e.g.
  // elem.animate([{offset: "calc(10px)", ...}, {offset: "exit 50%", ...}], {});
  kTimeline,

  // Programmatic keyframes with missing offsets, e.g.
  // elem.animate([{... /* no offset */}, {... /* no offset */}], {});
  kComputed
};

}  // namespace

bool KeyframeEffectModelBase::SnapshotNeutralCompositorKeyframes(
    Element& element,
    const ComputedStyle& old_style,
    const ComputedStyle& new_style,
    const ComputedStyle* parent_style) const {
  auto should_snapshot_property = [&old_style,
                                   &new_style](const PropertyHandle& property) {
    return !CSSPropertyEquality::PropertiesEqual(property, old_style,
                                                 new_style) &&
           CompositorAnimations::CompositedPropertyRequiresSnapshot(property);
  };
  auto should_snapshot_keyframe = [](const PropertySpecificKeyframe& keyframe) {
    return keyframe.IsNeutral();
  };

  return SnapshotCompositableProperties(element, new_style, parent_style,
                                        should_snapshot_property,
                                        should_snapshot_keyframe);
}

bool KeyframeEffectModelBase::SnapshotAllCompositorKeyframesIfNecessary(
    Element& element,
    const ComputedStyle& base_style,
    const ComputedStyle* parent_style) const {
  if (!needs_compositor_keyframes_snapshot_)
    return false;
  needs_compositor_keyframes_snapshot_ = false;

  bool has_neutral_compositable_keyframe = false;
  auto should_snapshot_property = [](const PropertyHandle& property) {
    return CompositorAnimations::CompositedPropertyRequiresSnapshot(property);
  };
  auto should_snapshot_keyframe =
      [&has_neutral_compositable_keyframe](
          const PropertySpecificKeyframe& keyframe) {
        has_neutral_compositable_keyframe |= keyframe.IsNeutral();
        return true;
      };

  bool updated = SnapshotCompositableProperties(
      element, base_style, parent_style, should_snapshot_property,
      should_snapshot_keyframe);

  if (updated && has_neutral_compositable_keyframe) {
    UseCounter::Count(element.GetDocument(),
                      WebFeature::kSyntheticKeyframesInCompositedCSSAnimation);
  }
  return updated;
}

bool KeyframeEffectModelBase::SnapshotCompositableProperties(
    Element& element,
    const ComputedStyle& computed_style,
    const ComputedStyle* parent_style,
    ShouldSnapshotPropertyFunction should_snapshot_property,
    ShouldSnapshotKeyframeFunction should_snapshot_keyframe) const {
  EnsureKeyframeGroups();
  bool updated = false;
  for (const auto* compositable_property : CompositableProperties()) {
    updated |= SnapshotCompositorKeyFrames(
        PropertyHandle(*compositable_property), element, computed_style,
        parent_style, should_snapshot_property, should_snapshot_keyframe);
  }

  // Custom properties need to be handled separately, since not all values
  // can be animated.  Need to resolve the value of each custom property to
  // ensure that it can be animated.
  const PropertyRegistry* property_registry =
      element.GetDocument().GetPropertyRegistry();
  if (!property_registry)
    return updated;

  for (const AtomicString& name : computed_style.GetVariableNames()) {
    if (property_registry->WasReferenced(name)) {
      // This variable has been referenced as a property value at least once
      // during style resolution in the document. Animating this property on
      // the compositor could introduce misalignment in frame synchronization.
      //
      // TODO(kevers): For non-inherited properites, check if referenced in
      // computed style. References elsewhere in the document should not prevent
      // compositing.
      continue;
    }
    updated |= SnapshotCompositorKeyFrames(
        PropertyHandle(name), element, computed_style, parent_style,
        should_snapshot_property, should_snapshot_keyframe);
  }
  return updated;
}

bool KeyframeEffectModelBase::SnapshotCompositorKeyFrames(
    const PropertyHandle& property,
    Element& element,
    const ComputedStyle& computed_style,
    const ComputedStyle* parent_style,
    ShouldSnapshotPropertyFunction should_snapshot_property,
    ShouldSnapshotKeyframeFunction should_snapshot_keyframe) const {
  if (!should_snapshot_property(property))
    return false;

  auto it = keyframe_groups_->find(property);
  if (it == keyframe_groups_->end())
    return false;

  PropertySpecificKeyframeGroup* keyframe_group = it->value;

  bool updated = false;
  for (auto& keyframe : keyframe_group->keyframes_) {
    if (!should_snapshot_keyframe(*keyframe))
      continue;

    updated |= keyframe->PopulateCompositorKeyframeValue(
        property, element, computed_style, parent_style);
  }
  return updated;
}

template <class K>
Vector<double> KeyframeEffectModelBase::GetComputedOffsets(
    const HeapVector<K>& keyframes) {
  // To avoid having to create two vectors when converting from the nullable
  // offsets to the non-nullable computed offsets, we keep the convention in
  // this function that std::numeric_limits::quiet_NaN() represents null.
  double last_offset = -std::numeric_limits<double>::max();
  Vector<double> result;
  Vector<OffsetType> offset_types;
  result.reserve(keyframes.size());
  offset_types.reserve(keyframes.size());

  for (const auto& keyframe : keyframes) {
    std::optional<double> offset = keyframe->Offset();
    if (offset && !keyframe->GetTimelineOffset()) {
      DCHECK_GE(offset.value(), last_offset);
      last_offset = offset.value();
    }
    result.push_back(offset.value_or(Keyframe::kNullComputedOffset));

    // A timeline offset must always have a valid range within the context of
    // a keyframe model. Otherwise, it is converted to a specified offset during
    // construction of the model.
    DCHECK(!keyframe->GetTimelineOffset() ||
           keyframe->GetTimelineOffset()->name !=
               TimelineOffset::NamedRange::kNone);

    OffsetType type = keyframe->GetTimelineOffset()
                          ? OffsetType::kTimeline
                          : (offset.has_value() ? OffsetType::kSpecified
                                                : OffsetType::kComputed);
    offset_types.push_back(type);
  }

  if (result.empty()) {
    return result;
  }

  // Ensure we have an offset at the upper bound of the range.
  for (int i = result.size() - 1; i >= 0; --i) {
    if (offset_types[i] == OffsetType::kSpecified) {
      break;
    }
    if (offset_types[i] == OffsetType::kComputed) {
      result[i] = 1;
      break;
    }
  }

  // Ensure we have an offset at the lower bound of the range.
  wtf_size_t last_index = 0;
  for (wtf_size_t i = 0; i < result.size(); ++i) {
    if (offset_types[i] == OffsetType::kSpecified) {
      last_offset = result[i];
      last_index = i;
      break;
    }
    if (offset_types[i] == OffsetType::kComputed && result[i] != 1) {
      last_offset = 0;
      last_index = i;
      result[i] = 0;
      break;
    }
  }

  if (last_offset < 0) {
    // All offsets are timeline offsets.
    return result;
  }

  wtf_size_t skipped_since_last_index = 0;
  for (wtf_size_t i = last_index + 1; i < result.size(); ++i) {
    double offset = result[i];
    // Keyframes with timeline offsets do not participate in the evaluation of
    // computed offsets.
    bool skipKeyframe = keyframes[i]->GetTimelineOffset().has_value();
    if (skipKeyframe) {
      skipped_since_last_index++;
    } else if (!std::isnan(offset)) {
      wtf_size_t skipped_during_fill = 0;
      for (wtf_size_t j = 1; j < i - last_index; ++j) {
        if (keyframes[last_index + j]->GetTimelineOffset().has_value()) {
          skipped_during_fill++;
          continue;
        }
        result[last_index + j] =
            last_offset + (offset - last_offset) * (j - skipped_during_fill) /
                              (i - last_index - skipped_since_last_index);
      }
      last_index = i;
      last_offset = offset;
      skipped_since_last_index = 0;
    }
  }

  return result;
}

template CORE_EXPORT Vector<double> KeyframeEffectModelBase::GetComputedOffsets(
    const HeapVector<Member<Keyframe>>& keyframes);
template CORE_EXPORT Vector<double> KeyframeEffectModelBase::GetComputedOffsets(
    const HeapVector<Member<StringKeyframe>>& keyframes);

bool KeyframeEffectModelBase::IsTransformRelatedEffect() const {
  return Affects(PropertyHandle(GetCSSPropertyTransform())) ||
         Affects(PropertyHandle(GetCSSPropertyRotate())) ||
         Affects(PropertyHandle(GetCSSPropertyScale())) ||
         Affects(PropertyHandle(GetCSSPropertyTranslate()));
}

bool KeyframeEffectModelBase::SetLogicalPropertyResolutionContext(
    WritingDirectionMode writing_direction) {
  bool changed = false;
  for (wtf_size_t i = 0; i < keyframes_.size(); i++) {
    if (auto* string_keyframe = DynamicTo<StringKeyframe>(*keyframes_[i])) {
      if (string_keyframe->HasLogicalProperty()) {
        string_keyframe->SetLogicalPropertyResolutionContext(writing_direction);
        changed = true;
      }
    }
  }
  if (changed)
    ClearCachedData();
  return changed;
}

void KeyframeEffectModelBase::Trace(Visitor* visitor) const {
  visitor->Trace(keyframes_);
  visitor->Trace(keyframe_groups_);
  visitor->Trace(interpolation_effect_);
  EffectModel::Trace(visitor);
}

void KeyframeEffectModelBase::EnsureKeyframeGroups() const {
  if (keyframe_groups_) {
    return;
  }

  keyframe_groups_ = MakeGarbageCollected<KeyframeGroupMap>();
  scoped_refptr<TimingFunction> zero_offset_easing = default_keyframe_easing_;
  for (wtf_size_t i = 0; i < keyframes_.size(); i++) {
    const auto& keyframe = keyframes_[i];
    double computed_offset = keyframe->ComputedOffset().value();

    if (computed_offset == 0) {
      zero_offset_easing = &keyframe->Easing();
    }

    if (!std::isfinite(computed_offset)) {
      continue;
    }

    for (const PropertyHandle& property : keyframe->Properties()) {
      Member<PropertySpecificKeyframeGroup>& group =
          keyframe_groups_->insert(property, nullptr).stored_value->value;
      if (!group)
        group = MakeGarbageCollected<PropertySpecificKeyframeGroup>();

      Keyframe::PropertySpecificKeyframe* property_specific_keyframe =
          keyframe->CreatePropertySpecificKeyframe(property, composite_,
                                                   computed_offset);
      has_revert_ |= property_specific_keyframe->IsRevert();
      has_revert_ |= property_specific_keyframe->IsRevertLayer();
      group->AppendKeyframe(property_specific_keyframe);
    }
  }

  // Add synthetic keyframes and determine if the keyframe values are static.
  has_synthetic_keyframes_ = false;
  for (const auto& entry : *keyframe_groups_) {
    if (entry.value->AddSyntheticKeyframeIfRequired(zero_offset_easing))
      has_synthetic_keyframes_ = true;

    entry.value->RemoveRedundantKeyframes();
    entry.value->CheckIfStatic();
  }
}

bool KeyframeEffectModelBase::RequiresPropertyNode() const {
  for (const auto& property : EnsureDynamicProperties()) {
    if (!property.IsCSSProperty() ||
        (property.GetCSSProperty().PropertyID() != CSSPropertyID::kVariable &&
         property.GetCSSProperty().PropertyID() !=
             CSSPropertyID::kBackgroundColor &&
         property.GetCSSProperty().PropertyID() != CSSPropertyID::kClipPath))
      return true;
  }
  return false;
}

void KeyframeEffectModelBase::EnsureInterpolationEffectPopulated() const {
  if (interpolation_effect_->IsPopulated())
    return;

  for (const auto& entry : *keyframe_groups_) {
    const PropertySpecificKeyframeVector& keyframes = entry.value->Keyframes();
    if (RuntimeEnabledFeatures::StaticAnimationOptimizationEnabled()) {
      // Skip cross-fade interpolations in the static property optimization to
      // avoid introducing a side-effect in serialization of the computed value.
      // cross-fade(A 50%, A 50%) is visually equivalent to rendering A, but at
      // present, we expect the computed style to reflect an explicit
      // cross-fade.
      PropertyHandle handle = entry.key;
      if (entry.value->IsStatic() && handle.IsCSSProperty() &&
          handle.GetCSSProperty().PropertyID() !=
              CSSPropertyID::kListStyleImage) {
        // All keyframes have the same property value.
        // Create an interpolation from starting keyframe to starting keyframe.
        // The resulting interpolation record will be marked as static and can
        // short-circuit the local fraction calculation.
        CHECK(keyframes.size());
        interpolation_effect_->AddStaticValuedInterpolation(entry.key,
                                                            *keyframes[0]);
        continue;
      }
    }
    for (wtf_size_t i = 0; i < keyframes.size() - 1; i++) {
      wtf_size_t start_index = i;
      wtf_size_t end_index = i + 1;
      double start_offset = keyframes[start_index]->Offset();
      double end_offset = keyframes[end_index]->Offset();
      double apply_from = start_offset;
      double apply_to = end_offset;

      if (i == 0) {
        apply_from = -std::numeric_limits<double>::infinity();
        if (end_offset == 0.0) {
          DCHECK_NE(keyframes[end_index + 1]->Offset(), 0.0);
          end_index = start_index;
        }
      }
      if (i == keyframes.size() - 2) {
        apply_to = std::numeric_limits<double>::infinity();
        if (start_offset == 1.0) {
          DCHECK_NE(keyframes[start_index - 1]->Offset(), 1.0);
          start_index = end_index;
        }
      }

      if (apply_from != apply_to) {
        interpolation_effect_->AddInterpolationsFromKeyframes(
            entry.key, *keyframes[start_index], *keyframes[end_index],
            apply_from, apply_to);
      }
      // else the interpolation will never be used in sampling
    }
  }

  interpolation_effect_->SetPopulated();
}

void KeyframeEffectModelBase::IndexKeyframesAndResolveComputedOffsets() {
  Vector<double> computed_offsets = GetComputedOffsets(keyframes_);
  // Snapshot the indices so that we can recover the original ordering.
  for (wtf_size_t i = 0; i < keyframes_.size(); i++) {
    keyframes_[i]->SetIndex(i);
    keyframes_[i]->SetComputedOffset(computed_offsets[i]);
  }
}

bool KeyframeEffectModelBase::ResolveTimelineOffsets(
    const TimelineRange& timeline_range,
    double range_start,
    double range_end) {
  if (timeline_range == last_timeline_range_ &&
      last_range_start_ == range_start && last_range_end_ == range_end) {
    return false;
  }

  bool needs_update = false;
  for (const auto& keyframe : keyframes_) {
    needs_update |=
        keyframe->ResolveTimelineOffset(timeline_range, range_start, range_end);
  }
  if (needs_update) {
    std::stable_sort(keyframes_.begin(), keyframes_.end(), &Keyframe::LessThan);
    ClearCachedData();
  }

  last_timeline_range_ = timeline_range;
  last_range_start_ = range_start;
  last_range_end_ = range_end;

  return needs_update;
}

void KeyframeEffectModelBase::ClearCachedData() {
  keyframe_groups_ = nullptr;
  dynamic_properties_.reset();
  interpolation_effect_->Clear();
  last_fraction_ = std::numeric_limits<double>::quiet_NaN();
  needs_compositor_keyframes_snapshot_ = true;

  last_timeline_range_ = std::nullopt;
  last_range_start_ = std::nullopt;
  last_range_end_ = std::nullopt;
}

bool KeyframeEffectModelBase::IsReplaceOnly() const {
  EnsureKeyframeGroups();
  for (const auto& entry : *keyframe_groups_) {
    for (const auto& keyframe : entry.value->Keyframes()) {
      if (keyframe->Composite() != EffectModel::kCompositeReplace)
        return false;
    }
  }
  return true;
}

void KeyframeEffectModelBase::PropertySpecificKeyframeGroup::AppendKeyframe(
    Keyframe::PropertySpecificKeyframe* keyframe) {
  DCHECK(keyframes_.empty() ||
         keyframes_.back()->Offset() <= keyframe->Offset());
  keyframes_.push_back(std::move(keyframe));
}

void KeyframeEffectModelBase::PropertySpecificKeyframeGroup::
    RemoveRedundantKeyframes() {
  // As an optimization, removes interior keyframes that have the same offset
  // as both their neighbors, as they will never be used by sample().
  // Note that synthetic keyframes must be added before this method is
  // called.
  DCHECK_GE(keyframes_.size(), 2U);
  for (int i = keyframes_.size() - 2; i > 0; --i) {
    double offset = keyframes_[i]->Offset();
    bool has_same_offset_as_previous_neighbor =
        keyframes_[i - 1]->Offset() == offset;
    bool has_same_offset_as_next_neighbor =
        keyframes_[i + 1]->Offset() == offset;
    if (has_same_offset_as_previous_neighbor &&
        has_same_offset_as_next_neighbor)
      keyframes_.EraseAt(i);
  }
  DCHECK_GE(keyframes_.size(), 2U);
}

void KeyframeEffectModelBase::PropertySpecificKeyframeGroup::CheckIfStatic() {
  has_static_value_ = false;

  DCHECK_GE(keyframes_.size(), 2U);
  const PropertySpecificKeyframe* first = keyframes_[0];
  const CSSPropertySpecificKeyframe* css_keyframe =
      DynamicTo<CSSPropertySpecificKeyframe>(first);

  // Transitions are only started if the end-points mismatch with caveat for
  // visited/unvisited properties. For now, limit to detected static properties
  // in a CSS animations since a common source of static properties is expansion
  // of shorthand properties to their longhand counterparts.
  if (!css_keyframe) {
    return;
  }

  const CSSValue* target_value = css_keyframe->Value();
  CompositeOperation target_composite_operation = css_keyframe->Composite();

  for (wtf_size_t i = 1; i < keyframes_.size(); i++) {
    const CSSPropertySpecificKeyframe* keyframe =
        To<CSSPropertySpecificKeyframe>(keyframes_[i].Get());
    if (keyframe->Composite() != target_composite_operation) {
      return;
    }
    // A neutral keyframe has a null value. Either all keyframes must be
    // neutral or none to be static. If any of the values are non-null their
    // CSS values must precisely match. It is not enough to resolve to the same
    // value.
    if (target_value) {
      if (!keyframe->Value() || *keyframe->Value() != *target_value) {
        return;
      }
    } else {
      if (keyframe->Value()) {
        return;
      }
    }
  }

  has_static_value_ = true;
}

bool KeyframeEffectModelBase::PropertySpecificKeyframeGroup::
    AddSyntheticKeyframeIfRequired(
        scoped_refptr<TimingFunction> zero_offset_easing) {
  DCHECK(!keyframes_.empty());

  bool added_synthetic_keyframe = false;

  if (keyframes_.front()->Offset() > 0.0) {
    keyframes_.insert(0, keyframes_.front()->NeutralKeyframe(
                             0, std::move(zero_offset_easing)));
    added_synthetic_keyframe = true;
  }
  if (keyframes_.back()->Offset() < 1.0) {
    AppendKeyframe(keyframes_.back()->NeutralKeyframe(1, nullptr));
    added_synthetic_keyframe = true;
  }

  return added_synthetic_keyframe;
}

}  // namespace blink
```