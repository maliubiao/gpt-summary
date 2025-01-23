Response:
The user wants a summary of the functionalities of the provided C++ code file, which is part of the Chromium Blink rendering engine and specifically deals with the Inspector's animation features. I need to identify the core responsibilities of this code and how it interacts with web technologies like JavaScript, HTML, and CSS.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the Class:** The core of the file is the `InspectorAnimationAgent` class. The name itself strongly suggests its purpose: managing the inspection of animations.

2. **Analyze Includes:**  The included headers provide valuable clues about the class's dependencies and functionalities. Keywords like "animation", "CSS", "DOM", "inspector", and "protocol" are significant.
    *  `core/animation/*`: Indicates interaction with the Blink animation system.
    *  `core/css/*`:  Suggests handling of CSS animations and transitions.
    *  `core/dom/*`:  Implies interaction with HTML elements and the DOM tree.
    *  `core/inspector/protocol/animation.h`:  This is key. It signifies that this class is responsible for implementing the "Animation" domain of the Chrome DevTools Protocol (CDP). This means it's the bridge between the browser's animation engine and the developer tools frontend.
    *  `bindings/core/v8/*`: Shows interaction with V8, the JavaScript engine, for exposing animation information to JavaScript and the DevTools.

3. **Examine Member Variables:** The class members provide insights into the data it manages:
    * `inspected_frames_`:  Indicates it operates within the context of a web page or frame.
    * `css_agent_`:  Suggests a dependency on the CSS agent for retrieving style information.
    * `v8_session_`:  Confirms interaction with the V8 debugger.
    * `id_to_animation_snapshot_`, `id_to_animation_`, `cleared_animations_`, `notify_animation_updated_tasks_`:  These collections suggest the agent keeps track of animation states and updates.
    * `enabled_`, `playback_rate_`:  Represent configurable state related to animation inspection.

4. **Analyze Public Methods:** The public methods are the primary interface of the class and reveal its core functions:
    * `enable()`, `disable()`:  Control the activation of the animation inspection.
    * `getPlaybackRate()`, `setPlaybackRate()`: Allow reading and modifying the playback rate of animations, crucial for debugging.
    * `getCurrentTime()`, `setPaused()`, `seekAnimations()`: Provide control over the animation timeline for inspection.
    * `releaseAnimations()`:  Likely used to clean up resources and stop tracking specific animations.
    * `setTiming()`: Allows modification of animation duration and delay.
    * `resolveAnimation()`: Exposes the underlying `Animation` object to the DevTools, enabling further JavaScript-based inspection.
    * `BuildObjectForAnimation()`: This function is vital. It constructs the protocol-specific representation of an animation object that's sent to the DevTools frontend.

5. **Analyze Private Methods:**  Private methods reveal the internal workings of the class:
    * Methods like `CompareAndUpdateInternalSnapshot` and `CompareAndUpdateKeyframesSnapshot` suggest logic for tracking changes in animation properties and optimizing updates sent to the DevTools.
    * `CreateCSSId` likely generates a unique identifier for CSS animations/transitions based on their properties and associated CSS rules.
    * Methods prefixed with `Did` (e.g., `DidCreateAnimation`, `AnimationUpdated`) are often callbacks from other parts of the Blink engine, indicating how this agent gets notified about animation events.

6. **Connect to Web Technologies:** Based on the analysis above, it's clear how this agent relates to JavaScript, HTML, and CSS:
    * **JavaScript:** The `resolveAnimation()` method directly provides a way to access `Animation` objects in JavaScript within the DevTools console. The agent also uses V8 bindings for data conversion.
    * **HTML:** The agent deals with animations applied to HTML elements. The `EffectTarget()` and node ID retrieval demonstrate this connection.
    * **CSS:**  The agent specifically handles CSS Animations and CSS Transitions. It parses CSS rules (keyframes, properties) to display animation details in the DevTools. The `CSSId` creation further links it to specific CSS rules.

7. **Infer Logic and Assumptions:**  The code implies certain logic:
    * It needs to efficiently track and update animation state changes to avoid overwhelming the DevTools frontend.
    * It makes assumptions about the structure of the Blink animation system and how animation data is represented.

8. **Identify Potential Errors:** Common errors would likely involve:
    * Trying to interact with animations that no longer exist or have been released.
    * Incorrectly setting animation timing values.
    * Issues arising from the asynchronous nature of animation updates.

9. **Formulate the Summary:** Based on the above points, construct a concise summary highlighting the core functionalities and their relationships to web technologies.

**(Self-Correction/Refinement):** Initially, I might focus too much on individual method implementations. The key is to step back and identify the high-level purpose of the class and how the various components work together to achieve that goal. Recognizing the connection to the DevTools Protocol is crucial for understanding its role. Also, explicitly mentioning the handling of different animation types (Web Animations, CSS Animations, CSS Transitions) is important.
这是 Chromium Blink 引擎中 `blink/renderer/core/inspector/inspector_animation_agent.cc` 文件的第一部分，主要功能是**作为 Chrome 开发者工具的后端，负责收集、监控和控制网页中的动画效果，并将这些信息传递给开发者工具的前端界面**。

以下是详细的功能列举和相关说明：

**核心功能：**

1. **动画监控与管理：**
   - **启用/禁用动画检查:**  通过 `enable()` 和 `disable()` 方法控制动画监控的开关。启用后，会开始监听并记录页面中的动画。
   - **跟踪动画创建和更新:** 监听动画的创建 (`DidCreateAnimation`) 和更新 (`AnimationUpdated`) 事件，记录动画的状态变化。
   - **存储动画信息:** 使用 `id_to_animation_`, `id_to_animation_snapshot_` 等数据结构来存储当前页面中的动画对象及其快照信息，用于跟踪和比较动画状态。
   - **清理动画信息:** 当动画被释放时，从跟踪列表中移除 (`releaseAnimations`)。

2. **与开发者工具前端通信：**
   - **发送动画创建事件:** 当检测到新动画创建时，通过 `GetFrontend()->animationCreated(animation_id)` 将动画 ID 发送给前端。
   - **发送动画开始事件:** 当动画开始播放时，通过 `GetFrontend()->animationStarted(BuildObjectForAnimation(*animation))` 发送包含动画详细信息的对象。
   - **发送动画更新事件:** 当动画状态发生变化时（如播放、暂停、时间更新），通过 `GetFrontend()->animationUpdated(BuildObjectForAnimation(*animation))` 发送更新后的动画信息。
   - **发送动画取消事件:** 当动画被取消或停止时，通过 `GetFrontend()->animationCanceled(animation_id)` 通知前端。

3. **提供动画控制功能：**
   - **获取和设置播放速率:**  `getPlaybackRate()` 和 `setPlaybackRate()` 方法允许开发者工具获取和修改页面中所有动画的播放速度。
   - **获取当前时间:** `getCurrentTime()` 方法返回指定动画的当前播放时间。
   - **暂停和恢复动画:** `setPaused()` 方法允许暂停或恢复指定的动画。
   - **跳转到指定时间:** `seekAnimations()` 方法允许将指定的动画跳转到特定的时间点。
   - **设置动画时长和延迟:** `setTiming()` 方法允许修改动画的持续时间和延迟。
   - **解析动画对象:** `resolveAnimation()` 方法将内部的 `Animation` 对象暴露给 JavaScript，允许在开发者工具的控制台中进行交互。

4. **构建动画信息的协议对象：**
   - **`BuildObjectForAnimation()`:**  这是核心方法，负责将 Blink 引擎内部的 `Animation` 对象转换为开发者工具协议 (`protocol::Animation::Animation`) 中定义的格式，以便前端能够理解和展示。这个方法会提取动画的各种属性，如 ID、名称、播放状态、播放速率、起始时间、当前时间、类型、动画效果等。
   - **`BuildObjectForAnimationEffect()`:** 负责构建动画效果 (`protocol::Animation::AnimationEffect`) 对象，包含延迟、结束延迟、迭代次数、持续时间、方向、填充模式、缓动函数等信息。
   - **`BuildObjectForAnimationKeyframes()`:** 负责构建关键帧规则 (`protocol::Animation::KeyframesRule`) 对象，包含关键帧的偏移量和缓动函数。
   - **`BuildObjectForViewOrScrollTimeline()`:**  负责构建视图或滚动时间轴 (`protocol::Animation::ViewOrScrollTimeline`) 对象，用于关联基于滚动的动画。

**与 Javascript, HTML, CSS 的关系及举例说明：**

* **CSS:**
    * **功能关系:** 该 Agent 负责监控和控制通过 CSS Animation 和 CSS Transition 实现的动画效果。
    * **举例说明:**  当网页中存在以下 CSS 动画时，`InspectorAnimationAgent` 会捕获到它：
      ```css
      .my-element {
        animation-name: fadeIn;
        animation-duration: 1s;
      }

      @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      ```
      `BuildObjectForAnimation()` 会提取 `animation-name` (`fadeIn`) 作为动画名称，`animation-duration` (`1s`) 作为动画时长，并解析 `@keyframes` 规则生成关键帧信息。
    * **举例说明:** 对于 CSS Transition：
      ```css
      .my-element {
        transition-property: opacity;
        transition-duration: 0.5s;
      }

      .my-element:hover {
        opacity: 0.5;
      }
      ```
      当鼠标悬停在 `.my-element` 上时，触发 opacity 属性的过渡动画，`InspectorAnimationAgent` 会记录这个过渡，并将 `transition-property` (`opacity`) 作为动画名称。

* **Javascript:**
    * **功能关系:** 该 Agent 也负责监控和控制通过 Web Animations API (`document.getAnimations()`, `element.animate()`) 创建的动画。
    * **举例说明:** 使用 JavaScript 创建动画：
      ```javascript
      const element = document.querySelector('.my-element');
      const animation = element.animate([
        { opacity: 0 },
        { opacity: 1 }
      ], {
        duration: 1000
      });
      ```
      `InspectorAnimationAgent` 会捕获到这个通过 `element.animate()` 创建的 `Animation` 对象，并通过 `BuildObjectForAnimation()` 将其信息发送到开发者工具。
    * **`resolveAnimation()` 的作用:** 开发者可以通过在开发者工具的 "动画" 面板中选择一个动画，然后使用 "在控制台中显示" 功能，这时 `resolveAnimation()` 会被调用，将对应的 `Animation` 对象暴露为一个 JavaScript 变量，允许开发者在控制台中直接操作该动画对象（例如 `animation.pause()`, `animation.currentTime = 500`）。

* **HTML:**
    * **功能关系:** 动画是应用于 HTML 元素的，该 Agent 需要知道动画作用于哪个元素。
    * **举例说明:** 无论是 CSS 动画还是 JavaScript 动画，都依附于特定的 HTML 元素。 `BuildObjectForAnimationEffect()` 中的 `IdentifiersFactory::IntIdForNode(effect->EffectTarget())` 就是获取动画目标元素的节点 ID，以便在开发者工具中关联动画和元素。

**逻辑推理和假设输入/输出：**

* **假设输入:** 用户在开发者工具的 "动画" 面板中点击了某个动画的 "暂停" 按钮。
* **逻辑推理:**  前端会发送一个请求到后端，调用 `InspectorAnimationAgent` 的 `setPaused()` 方法，并将该动画的 ID 和 `paused=true` 传递过来。
* **输出:** `setPaused()` 方法会根据动画 ID 找到对应的 `Animation` 对象，并调用其 `pause()` 方法，从而暂停动画的播放。同时，后端会发送 `animationUpdated` 事件更新动画状态，前端会更新动画面板的显示。

**用户或编程常见的使用错误：**

* **在 `disable()` 之后尝试操作动画:** 用户可能在禁用动画检查后，仍然尝试在开发者工具中修改动画属性或进行控制。此时，由于 Agent 已经停止监听和跟踪动画，操作将不会生效，或者可能会报错。
* **假设输入了错误的动画 ID:** 开发者工具前端在发送请求时，如果由于某种原因传入了一个不存在的动画 ID，`AssertAnimation()` 方法会返回错误，导致后续操作失败。
* **频繁快速地修改动画属性:**  开发者可能在短时间内频繁地修改动画的播放速率或当前时间，这可能会导致 Blink 引擎内部的动画状态更新过于频繁，影响性能，或者导致开发者工具显示的信息与实际动画状态不一致。为了避免这种情况，代码中使用了 `PostDelayedTask` 来延迟 `NotifyAnimationUpdated` 的执行，进行一定的节流。

**本部分功能归纳：**

这是 `InspectorAnimationAgent` 的核心部分，负责**建立开发者工具与 Blink 渲染引擎中动画系统的桥梁**。它负责监听动画的创建和更新，并将这些信息以结构化的方式传递给开发者工具前端。同时，它也提供了前端控制动画播放状态、时间和速度的能力，使得开发者能够方便地调试和分析网页中的动画效果。 这部分代码主要关注动画信息的收集、组织和基本控制功能的实现。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_animation_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/inspector_animation_agent.h"

#include <memory>

#include "base/location.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_computed_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_optional_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_string_unrestricteddouble.h"
#include "third_party/blink/renderer/core/animation/animation.h"
#include "third_party/blink/renderer/core/animation/animation_effect.h"
#include "third_party/blink/renderer/core/animation/css/css_animation.h"
#include "third_party/blink/renderer/core/animation/css/css_animations.h"
#include "third_party/blink/renderer/core/animation/css/css_transition.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/effect_model.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/scroll_snapshot_timeline.h"
#include "third_party/blink/renderer/core/animation/string_keyframe.h"
#include "third_party/blink/renderer/core/animation/view_timeline.h"
#include "third_party/blink/renderer/core/css/css_keyframe_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframes_rule.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/cssom/css_unit_value.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_css_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_style_sheet.h"
#include "third_party/blink/renderer/core/inspector/protocol/animation.h"
#include "third_party/blink/renderer/core/inspector/v8_inspector_string.h"
#include "third_party/blink/renderer/platform/animation/timing_function.h"
#include "third_party/blink/renderer/platform/crypto.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/hash_traits.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

namespace {

protocol::DOM::ScrollOrientation ToScrollOrientation(
    ScrollSnapshotTimeline::ScrollAxis scroll_axis_enum,
    bool is_horizontal_writing_mode) {
  switch (scroll_axis_enum) {
    case ScrollSnapshotTimeline::ScrollAxis::kBlock:
      return is_horizontal_writing_mode
                 ? protocol::DOM::ScrollOrientationEnum::Vertical
                 : protocol::DOM::ScrollOrientationEnum::Horizontal;
    case ScrollSnapshotTimeline::ScrollAxis::kInline:
      return is_horizontal_writing_mode
                 ? protocol::DOM::ScrollOrientationEnum::Horizontal
                 : protocol::DOM::ScrollOrientationEnum::Vertical;
    case ScrollSnapshotTimeline::ScrollAxis::kX:
      return protocol::DOM::ScrollOrientationEnum::Horizontal;
    case ScrollSnapshotTimeline::ScrollAxis::kY:
      return protocol::DOM::ScrollOrientationEnum::Vertical;
  }
}

double NormalizedDuration(
    V8UnionCSSNumericValueOrStringOrUnrestrictedDouble* duration) {
  if (duration->IsUnrestrictedDouble()) {
    return duration->GetAsUnrestrictedDouble();
  }

  if (duration->IsCSSNumericValue()) {
    CSSUnitValue* percentage_unit_value = duration->GetAsCSSNumericValue()->to(
        CSSPrimitiveValue::UnitType::kPercentage);
    if (percentage_unit_value) {
      return percentage_unit_value->value();
    }
  }
  return 0;
}

double AsDoubleOrZero(Timing::V8Delay* value) {
  if (!value->IsDouble())
    return 0;

  return value->GetAsDouble();
}

}  // namespace

InspectorAnimationAgent::InspectorAnimationAgent(
    InspectedFrames* inspected_frames,
    InspectorCSSAgent* css_agent,
    v8_inspector::V8InspectorSession* v8_session)
    : inspected_frames_(inspected_frames),
      css_agent_(css_agent),
      v8_session_(v8_session),
      is_cloning_(false),
      enabled_(&agent_state_, /*default_value=*/false),
      playback_rate_(&agent_state_, /*default_value=*/1.0) {
  DCHECK(css_agent);
}

String InspectorAnimationAgent::AnimationDisplayName(
    const Animation& animation) {
  if (!animation.id().empty()) {
    return animation.id();
  } else if (auto* css_animation = DynamicTo<CSSAnimation>(animation)) {
    return css_animation->animationName();
  } else if (auto* css_transition = DynamicTo<CSSTransition>(animation)) {
    return css_transition->transitionProperty();
  } else {
    return "";
  }
}

void InspectorAnimationAgent::Restore() {
  if (enabled_.Get()) {
    instrumenting_agents_->AddInspectorAnimationAgent(this);
    setPlaybackRate(playback_rate_.Get());
  }
}

void InspectorAnimationAgent::InvalidateInternalState() {
  id_to_animation_snapshot_.clear();
  id_to_animation_.clear();
  cleared_animations_.clear();
  notify_animation_updated_tasks_.clear();
}

protocol::Response InspectorAnimationAgent::enable() {
  enabled_.Set(true);
  instrumenting_agents_->AddInspectorAnimationAgent(this);

  if (inspected_frames_->Root()->IsProvisional()) {
    // Running getAnimations on a document attached to a provisional frame can
    // cause a crash: crbug.com/40670727
    return protocol::Response::Success();
  }

  Document* document = inspected_frames_->Root()->GetDocument();
  DocumentAnimations& document_animations = document->GetDocumentAnimations();
  HeapVector<Member<Animation>> animations =
      document_animations.getAnimations(document->GetTreeScope());
  for (Animation* animation : animations) {
    const String& animation_id = String::Number(animation->SequenceNumber());
    V8AnimationPlayState::Enum play_state =
        animation->CalculateAnimationPlayState();
    bool is_play_state_running_or_finished =
        play_state == V8AnimationPlayState::Enum::kRunning ||
        play_state == V8AnimationPlayState::Enum::kFinished;
    if (!is_play_state_running_or_finished ||
        cleared_animations_.Contains(animation_id) ||
        id_to_animation_.Contains(animation_id)) {
      continue;
    }

    AnimationSnapshot* snapshot;
    if (id_to_animation_snapshot_.Contains(animation_id)) {
      snapshot = id_to_animation_snapshot_.at(animation_id);
    } else {
      snapshot = MakeGarbageCollected<AnimationSnapshot>();
      id_to_animation_snapshot_.Set(animation_id, snapshot);
    }

    this->CompareAndUpdateInternalSnapshot(*animation, snapshot);
    id_to_animation_.Set(animation_id, animation);
    GetFrontend()->animationCreated(animation_id);
    GetFrontend()->animationStarted(BuildObjectForAnimation(*animation));
  }

  return protocol::Response::Success();
}

protocol::Response InspectorAnimationAgent::disable() {
  setPlaybackRate(1.0);
  enabled_.Clear();
  instrumenting_agents_->RemoveInspectorAnimationAgent(this);
  InvalidateInternalState();
  return protocol::Response::Success();
}

void InspectorAnimationAgent::DidCommitLoadForLocalFrame(LocalFrame* frame) {
  if (frame == inspected_frames_->Root()) {
    InvalidateInternalState();
  }
  setPlaybackRate(playback_rate_.Get());
}

static std::unique_ptr<protocol::Animation::ViewOrScrollTimeline>
BuildObjectForViewOrScrollTimeline(AnimationTimeline* timeline) {
  ScrollSnapshotTimeline* scroll_snapshot_timeline =
      DynamicTo<ScrollSnapshotTimeline>(timeline);
  if (scroll_snapshot_timeline) {
    Node* resolved_source = scroll_snapshot_timeline->ResolvedSource();
    if (!resolved_source) {
      return nullptr;
    }

    LayoutBox* scroll_container = scroll_snapshot_timeline->ScrollContainer();
    if (!scroll_container) {
      return nullptr;
    }

    std::unique_ptr<protocol::Animation::ViewOrScrollTimeline> timeline_object =
        protocol::Animation::ViewOrScrollTimeline::create()
            .setSourceNodeId(IdentifiersFactory::IntIdForNode(resolved_source))
            .setAxis(ToScrollOrientation(
                scroll_snapshot_timeline->GetAxis(),
                scroll_container->IsHorizontalWritingMode()))
            .build();
    std::optional<ScrollSnapshotTimeline::ScrollOffsets> scroll_offsets =
        scroll_snapshot_timeline->GetResolvedScrollOffsets();
    if (scroll_offsets.has_value()) {
      timeline_object->setStartOffset(scroll_offsets->start);
      timeline_object->setEndOffset(scroll_offsets->end);
    }

    ViewTimeline* view_timeline =
        DynamicTo<ViewTimeline>(scroll_snapshot_timeline);
    if (view_timeline && view_timeline->subject()) {
      timeline_object->setSubjectNodeId(
          IdentifiersFactory::IntIdForNode(view_timeline->subject()));
    }

    return timeline_object;
  }

  return nullptr;
}

static std::unique_ptr<protocol::Animation::AnimationEffect>
BuildObjectForAnimationEffect(KeyframeEffect* effect) {
  ComputedEffectTiming* computed_timing = effect->getComputedTiming();
  double delay = AsDoubleOrZero(computed_timing->delay());
  double end_delay = AsDoubleOrZero(computed_timing->endDelay());
  String easing = effect->SpecifiedTiming().timing_function->ToString();

  std::unique_ptr<protocol::Animation::AnimationEffect> animation_object =
      protocol::Animation::AnimationEffect::create()
          .setDelay(delay)
          .setEndDelay(end_delay)
          .setIterationStart(computed_timing->iterationStart())
          .setIterations(computed_timing->iterations())
          .setDuration(NormalizedDuration(computed_timing->duration()))
          .setDirection(computed_timing->direction().AsString())
          .setFill(computed_timing->fill().AsString())
          .setEasing(easing)
          .build();
  if (effect->EffectTarget()) {
    animation_object->setBackendNodeId(
        IdentifiersFactory::IntIdForNode(effect->EffectTarget()));
  }
  return animation_object;
}

static std::unique_ptr<protocol::Animation::KeyframeStyle>
BuildObjectForStringKeyframe(const StringKeyframe* keyframe,
                             double computed_offset) {
  String offset = String::NumberToStringECMAScript(computed_offset * 100) + "%";

  std::unique_ptr<protocol::Animation::KeyframeStyle> keyframe_object =
      protocol::Animation::KeyframeStyle::create()
          .setOffset(offset)
          .setEasing(keyframe->Easing().ToString())
          .build();
  return keyframe_object;
}

static std::unique_ptr<protocol::Animation::KeyframesRule>
BuildObjectForAnimationKeyframes(const KeyframeEffect* effect) {
  if (!effect || !effect->Model() || !effect->Model()->IsKeyframeEffectModel())
    return nullptr;
  const KeyframeEffectModelBase* model = effect->Model();
  Vector<double> computed_offsets =
      KeyframeEffectModelBase::GetComputedOffsets(model->GetFrames());
  auto keyframes =
      std::make_unique<protocol::Array<protocol::Animation::KeyframeStyle>>();

  for (wtf_size_t i = 0; i < model->GetFrames().size(); i++) {
    const Keyframe* keyframe = model->GetFrames().at(i);
    // Ignore CSS Transitions
    if (!keyframe->IsStringKeyframe())
      continue;
    const auto* string_keyframe = To<StringKeyframe>(keyframe);
    keyframes->emplace_back(
        BuildObjectForStringKeyframe(string_keyframe, computed_offsets.at(i)));
  }
  return protocol::Animation::KeyframesRule::create()
      .setKeyframes(std::move(keyframes))
      .build();
}

std::unique_ptr<protocol::Animation::Animation>
InspectorAnimationAgent::BuildObjectForAnimation(blink::Animation& animation) {
  String animation_type = AnimationType::WebAnimation;
  std::unique_ptr<protocol::Animation::AnimationEffect> animation_effect_object;

  if (animation.effect()) {
    animation_effect_object =
        BuildObjectForAnimationEffect(To<KeyframeEffect>(animation.effect()));

    if (IsA<CSSTransition>(animation)) {
      animation_type = AnimationType::CSSTransition;
    } else {
      animation_effect_object->setKeyframesRule(
          BuildObjectForAnimationKeyframes(
              To<KeyframeEffect>(animation.effect())));

      if (IsA<CSSAnimation>(animation))
        animation_type = AnimationType::CSSAnimation;
    }
  }

  String id = String::Number(animation.SequenceNumber());
  double current_time = Timing::NullValue();
  std::optional<AnimationTimeDelta> animation_current_time =
      animation.CurrentTimeInternal();
  if (animation_current_time) {
    current_time = animation_current_time.value().InMillisecondsF();
  }

  std::unique_ptr<protocol::Animation::Animation> animation_object =
      protocol::Animation::Animation::create()
          .setId(id)
          .setName(AnimationDisplayName(animation))
          .setPausedState(animation.Paused())
          .setPlayState(
              V8AnimationPlayState(animation.CalculateAnimationPlayState())
                  .AsString())
          .setPlaybackRate(animation.playbackRate())
          .setStartTime(NormalizedStartTime(animation))
          .setCurrentTime(current_time)
          .setType(animation_type)
          .build();
  if (animation_type != AnimationType::WebAnimation)
    animation_object->setCssId(CreateCSSId(animation));
  if (animation_effect_object)
    animation_object->setSource(std::move(animation_effect_object));

  std::unique_ptr<protocol::Animation::ViewOrScrollTimeline>
      view_or_scroll_timeline =
          BuildObjectForViewOrScrollTimeline(animation.TimelineInternal());
  if (view_or_scroll_timeline) {
    animation_object->setViewOrScrollTimeline(
        std::move(view_or_scroll_timeline));
  }
  return animation_object;
}

protocol::Response InspectorAnimationAgent::getPlaybackRate(
    double* playback_rate) {
  *playback_rate = ReferenceTimeline().PlaybackRate();
  return protocol::Response::Success();
}

protocol::Response InspectorAnimationAgent::setPlaybackRate(
    double playback_rate) {
  for (LocalFrame* frame : *inspected_frames_)
    frame->GetDocument()->Timeline().SetPlaybackRate(playback_rate);
  playback_rate_.Set(playback_rate);
  return protocol::Response::Success();
}

protocol::Response InspectorAnimationAgent::getCurrentTime(
    const String& id,
    double* current_time) {
  blink::Animation* animation = nullptr;
  protocol::Response response = AssertAnimation(id, animation);
  if (!response.IsSuccess())
    return response;

  *current_time = Timing::NullValue();
  if (animation->Paused() || !animation->TimelineInternal()->IsActive()) {
    std::optional<AnimationTimeDelta> animation_current_time =
        animation->CurrentTimeInternal();
    if (animation_current_time) {
      *current_time = animation_current_time.value().InMillisecondsF();
    }
  } else {
    // Use startTime where possible since currentTime is limited.
    std::optional<AnimationTimeDelta> animation_start_time =
        animation->StartTimeInternal();
    if (animation_start_time) {
      std::optional<AnimationTimeDelta> timeline_time =
          animation->TimelineInternal()->CurrentTime();
      // TODO(crbug.com/916117): Handle NaN values for scroll linked animations.
      if (timeline_time) {
        *current_time = timeline_time.value().InMillisecondsF() -
                        animation_start_time.value().InMillisecondsF();
      }
    }
  }
  return protocol::Response::Success();
}

protocol::Response InspectorAnimationAgent::setPaused(
    std::unique_ptr<protocol::Array<String>> animation_ids,
    bool paused) {
  for (const String& animation_id : *animation_ids) {
    blink::Animation* animation = nullptr;
    protocol::Response response = AssertAnimation(animation_id, animation);
    if (!response.IsSuccess())
      return response;
    if (paused && !animation->Paused()) {
      // Ensure we restore a current time if the animation is limited.
      std::optional<AnimationTimeDelta> current_time;
      if (!animation->TimelineInternal()->IsActive()) {
        current_time = animation->CurrentTimeInternal();
      } else {
        std::optional<AnimationTimeDelta> start_time =
            animation->StartTimeInternal();
        if (start_time) {
          std::optional<AnimationTimeDelta> timeline_time =
              animation->TimelineInternal()->CurrentTime();
          // TODO(crbug.com/916117): Handle NaN values.
          if (timeline_time) {
            current_time = timeline_time.value() - start_time.value();
          }
        }
      }

      animation->pause();
      if (current_time) {
        animation->SetCurrentTimeInternal(current_time.value());
      }
    } else if (!paused && animation->Paused()) {
      animation->Unpause();
    }
  }
  return protocol::Response::Success();
}

protocol::Response InspectorAnimationAgent::seekAnimations(
    std::unique_ptr<protocol::Array<String>> animation_ids,
    double current_time) {
  for (const String& animation_id : *animation_ids) {
    blink::Animation* animation = nullptr;
    protocol::Response response = AssertAnimation(animation_id, animation);
    if (!response.IsSuccess())
      return response;
    if (!animation->Paused()) {
      animation->play();
    }
    animation->SetCurrentTimeInternal(
        ANIMATION_TIME_DELTA_FROM_MILLISECONDS(current_time));
  }
  return protocol::Response::Success();
}

protocol::Response InspectorAnimationAgent::releaseAnimations(
    std::unique_ptr<protocol::Array<String>> animation_ids) {
  for (const String& animation_id : *animation_ids) {
    auto it = id_to_animation_.find(animation_id);
    if (it != id_to_animation_.end())
      it->value->SetEffectSuppressed(false);

    id_to_animation_.erase(animation_id);
    cleared_animations_.insert(animation_id);
    id_to_animation_snapshot_.erase(animation_id);
    notify_animation_updated_tasks_.erase(animation_id);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorAnimationAgent::setTiming(
    const String& animation_id,
    double duration,
    double delay) {
  blink::Animation* animation = nullptr;
  protocol::Response response = AssertAnimation(animation_id, animation);
  if (!response.IsSuccess())
    return response;

  NonThrowableExceptionState exception_state;

  OptionalEffectTiming* timing = OptionalEffectTiming::Create();
  timing->setDuration(
      MakeGarbageCollected<V8UnionCSSNumericValueOrStringOrUnrestrictedDouble>(
          duration));
  timing->setDelay(MakeGarbageCollected<Timing::V8Delay>(delay));
  animation->effect()->updateTiming(timing, exception_state);
  return protocol::Response::Success();
}

protocol::Response InspectorAnimationAgent::resolveAnimation(
    const String& animation_id,
    std::unique_ptr<v8_inspector::protocol::Runtime::API::RemoteObject>*
        result) {
  blink::Animation* animation = nullptr;
  protocol::Response response = AssertAnimation(animation_id, animation);
  if (!response.IsSuccess())
    return response;

  const Element* element =
      To<KeyframeEffect>(animation->effect())->EffectTarget();
  Document* document = element->ownerDocument();
  LocalFrame* frame = document ? document->GetFrame() : nullptr;
  ScriptState* script_state = ToScriptStateForMainWorld(frame);
  if (!script_state) {
    return protocol::Response::ServerError(
        "Element not associated with a document.");
  }

  ScriptState::Scope scope(script_state);
  static const char kAnimationObjectGroup[] = "animation";
  v8_session_->releaseObjectGroup(
      ToV8InspectorStringView(kAnimationObjectGroup));
  *result = v8_session_->wrapObject(
      script_state->GetContext(),
      ToV8Traits<Animation>::ToV8(script_state, animation),
      ToV8InspectorStringView(kAnimationObjectGroup),
      false /* generatePreview */);
  if (!*result) {
    return protocol::Response::ServerError(
        "Element not associated with a document.");
  }
  return protocol::Response::Success();
}

String InspectorAnimationAgent::CreateCSSId(blink::Animation& animation) {
  static CSSPropertyID g_animation_properties[] = {
      CSSPropertyID::kAnimationDelay,
      CSSPropertyID::kAnimationDirection,
      CSSPropertyID::kAnimationDuration,
      CSSPropertyID::kAnimationFillMode,
      CSSPropertyID::kAnimationIterationCount,
      CSSPropertyID::kAnimationName,
      CSSPropertyID::kAnimationTimingFunction,
  };
  static CSSPropertyID g_transition_properties[] = {
      CSSPropertyID::kTransitionDelay,
      CSSPropertyID::kTransitionDuration,
      CSSPropertyID::kTransitionProperty,
      CSSPropertyID::kTransitionTimingFunction,
  };

  auto* effect = To<KeyframeEffect>(animation.effect());
  Vector<CSSPropertyName> css_property_names;
  if (IsA<CSSAnimation>(animation)) {
    for (CSSPropertyID property : g_animation_properties)
      css_property_names.push_back(CSSPropertyName(property));
  } else if (auto* css_transition = DynamicTo<CSSTransition>(animation)) {
    for (CSSPropertyID property : g_transition_properties)
      css_property_names.push_back(CSSPropertyName(property));
    css_property_names.push_back(css_transition->TransitionCSSPropertyName());
  } else {
    NOTREACHED();
  }

  Element* element = effect->EffectTarget();
  HeapVector<Member<CSSStyleDeclaration>> styles =
      css_agent_->MatchingStyles(element);
  Digestor digestor(kHashAlgorithmSha1);
  digestor.UpdateUtf8(IsA<CSSTransition>(animation)
                          ? AnimationType::CSSTransition
                          : AnimationType::CSSAnimation);
  digestor.UpdateUtf8(animation.id());
  for (const CSSPropertyName& name : css_property_names) {
    CSSStyleDeclaration* style =
        css_agent_->FindEffectiveDeclaration(name, styles);
    // Ignore inline styles.
    if (!style || !style->ParentStyleSheet() || !style->parentRule() ||
        style->parentRule()->GetType() != CSSRule::kStyleRule)
      continue;
    digestor.UpdateUtf8(name.ToAtomicString());
    digestor.UpdateUtf8(css_agent_->StyleSheetId(style->ParentStyleSheet()));
    digestor.UpdateUtf8(To<CSSStyleRule>(style->parentRule())->selectorText());
  }
  DigestValue digest_result;
  digestor.Finish(digest_result);
  DCHECK(!digestor.has_failed());
  return Base64Encode(base::make_span(digest_result).first<10>());
}

void InspectorAnimationAgent::DidCreateAnimation(unsigned sequence_number) {
  if (is_cloning_)
    return;
  GetFrontend()->animationCreated(String::Number(sequence_number));
}

void InspectorAnimationAgent::NotifyAnimationUpdated(
    const String& animation_id) {
  if (!notify_animation_updated_tasks_.Contains(animation_id)) {
    return;
  }

  notify_animation_updated_tasks_.erase(animation_id);
  blink::Animation* animation = id_to_animation_.at(animation_id);
  if (!animation) {
    return;
  }

  V8AnimationPlayState::Enum play_state =
      animation->CalculateAnimationPlayState();
  if (play_state != V8AnimationPlayState::Enum::kRunning &&
      play_state != V8AnimationPlayState::Enum::kFinished) {
    return;
  }

  GetFrontend()->animationUpdated(BuildObjectForAnimation(*animation));
}

bool InspectorAnimationAgent::CompareAndUpdateKeyframesSnapshot(
    KeyframeEffect* keyframe_effect,
    HeapVector<Member<AnimationKeyframeSnapshot>>*
        animation_snapshot_keyframes) {
  bool should_notify_frontend = false;
  const KeyframeEffectModelBase* model = keyframe_effect->Model();
  Vector<double> computed_offsets =
      KeyframeEffectModelBase::GetComputedOffsets(model->GetFrames());
  if (model->GetFrames().size() != animation_snapshot_keyframes->size()) {
    // Notify frontend if there were previous keyframe snapshots and the
    // size has changed. Otherwise we don't notify frontend as it means
    // this is the first initialization of the `animation_snapshot_keyframes`
    // vector.
    if (animation_snapshot_keyframes->size() != 0) {
      should_notify_frontend = true;
    }

    for (wtf_size_t i = 0; i < model->GetFrames().size(); i++) {
      const Keyframe* keyframe = model->GetFrames().at(i);
      if (!keyframe->IsStringKeyframe()) {
        continue;
      }

      const auto* string_keyframe = To<StringKeyframe>(keyframe);
      AnimationKeyframeSnapshot* keyframe_snapshot =
          MakeGarbageCollected<AnimationKeyframeSnapshot>();
      keyframe_snapshot->computed_offset = computed_offsets.at(i);
      keyframe_snapshot->easing = string_keyframe->Easing().ToString();
      animation_snapshot_keyframes->emplace_back(keyframe_snapshot);
    }

    return should_notify_frontend;
  }

  for (wtf_size_t i = 0; i < animation_snapshot_keyframes->size(); i++) {
    AnimationKeyframeSnapshot* keyframe_snapshot =
        animation_snapshot_keyframes->at(i);
    const Keyframe* keyframe = model->GetFrames().at(i);
    if (!keyframe->IsStringKeyframe()) {
      continue;
    }

    const auto* string_keyframe = To<StringKeyframe>(keyframe);
    if (keyframe_snapshot->computed_offset != computed_offsets.at(i)) {
      keyframe_snapshot->computed_offset = computed_offsets.at(i);
      should_notify_frontend = true;
    }

    if (keyframe_snapshot->easing != string_keyframe->Easing().ToString()) {
      keyframe_snapshot->easing = string_keyframe->Easing().ToString();
      should_notify_frontend = true;
    }
  }

  return should_notify_frontend;
}

bool InspectorAnimationAgent::CompareAndUpdateInternalSnapshot(
    blink::Animation& animation,
    AnimationSnapshot* snapshot) {
  V8AnimationPlayState::Enum new_play_state =
      animation.PendingInternal() ? V8AnimationPlayState::Enum::kPending
                                  : animation.CalculateAnimationPlayState();
  bool should_notify_frontend = false;
  double start_time = NormalizedStartTime(animation);
  if (snapshot->start_time != start_time) {
    snapshot->start_time = start_time;
    should_notify_frontend = true;
  }

  if (snapshot->play_state != new_play_state) {
    snapshot->play_state = new_play_state;
    should_notify_frontend = true;
  }

  if (animation.effect()) {
    ComputedEffectTiming* computed_timing =
        animation.effect()->getComputedTiming();
    if (computed_timing) {
      double duration = NormalizedDuration(computed_timing->duration());
      double delay = AsDoubleOrZero(computed_timing->delay());
      double end_delay = AsDoubleOrZero(computed_timing->endDelay());
      double iterations = computed_timing->iterations();
      String easing = computed_timing->easing();
      if (snapshot->duration != duration) {
        snapshot->duration = duration;
        should_notify_frontend = true;
      }

      if (snapshot->delay != delay) {
        snapshot->delay = delay;
        should_notify_frontend = true;
      }

      if (snapshot->end_delay != end_delay) {
        snapshot->end_delay = end_delay;
        should_notify_frontend = true;
      }

      if (snapshot->iterations != iterations) {
        snapshot->iterations = iterations;
        should_notify_frontend = true;
      }

      if (snapshot->timing_function != easing) {
        snapshot->timing_function = easing;
        should_notify_frontend = true;
      }
    }

    if (KeyframeEffect* keyframe_effect =
            DynamicTo<KeyframeEffect>(animation.effect())) {
      if (CompareAndUpdateKeyframesSnapshot(keyframe_effect,
                                            &snapshot->keyframes)) {
        should_notify_frontend = true;
      }
    }
  }

  ScrollSnapshotTimeline* scroll_snapshot_timeline =
      DynamicTo<ScrollSnapshotTimeline>(animation.TimelineInternal());
  if (scroll_snapshot_timeline) {
    std::optional<ScrollSnapshotTimeline::ScrollOffsets> scroll_offsets =
        scroll_snapshot_timeline->GetResolvedScrollOffsets();
    if (scroll_offsets.has_value()) {
      if (scroll_offsets->start != snapshot->start_offset) {
        snapshot->start_offset = scroll_offsets->start;
        should_notify_frontend = true;
      }

      if (scroll_offsets->end != snapshot->end_offset) {
        snapshot->end_offset = scroll_offsets->end;
        should_notify_frontend = true;
      }
    }
  }

  return should_notify_frontend;
}

void InspectorAnimationAgent::AnimationUpdated(blink::Animation* animation) {
  const String& animation_id = String::Number(animation->SequenceNumber());
  // We no longer care about animations that have been released.
  if (cleared_animations_.Contains(animation_id)) {
    return;
  }

  // Initialize the animation snapshot to keep track of animation state changes
  // on `AnimationUpdated` probe calls.
  // * If a snapshot is found, it means there were previous calls to
  // AnimationUpdated so, we retrieve the snapshot for comparison.
  // * If a snapshot is not found, it means this is the animation's first call
  // to AnimationUpdated so, we create a snapshot and store the play state for
  // future comparisons.
  AnimationSnapshot* snapshot;
  V8AnimationPlayState::Enum new_play_state =
      animation->PendingInternal() ? V8AnimationPlayState::Enum::kPending
                                   : animation->CalculateAnimationPlayState();
  V8AnimationPlayState::Enum old_play_state = V8AnimationPlayState::Enum::kIdle;
  if (id_to_animation_snapshot_.Contains(animation_id)) {
    snapshot = id_to_animation_snapshot_.at(animation_id);
    old_play_state = snapshot->play_state;
    snapshot->play_state = new_play_state;
  } else {
    snapshot = MakeGarbageCollected<AnimationSnapshot>();
    snapshot->play_state = new_play_state;
    id_to_animation_snapshot_.Set(animation_id, snapshot);
  }

  // Do not record pending animations in `id_to_animation_` and do not notify
  // frontend.
  if (new_play_state == V8AnimationPlayState::Enum::kPending) {
    return;
  }

  // Record newly starting animations only once.
  if (old_play_state != new_play_state) {
    switch (new_play_state) {
      case V8AnimationPlayState::Enum::kRunning:
      case V8AnimationPlayState::Enum::kFinished: {
        if (id_to_animation_.Contains(animation_id)) {
          break;
        }

        this->CompareAndUpdateInternalSnapshot(*animation, snapshot);
        id_to_animation_.Set(animation_id, animation);
        GetFrontend()->animationStarted(BuildObjectForAnimation(*animation));
        break;
      }
      case V8AnimationPlayState::Enum::kIdle:
      case V8AnimationPlayState::Enum::kPaused:
        GetFrontend()->animationCanceled(animation_id);
        break;
      case V8AnimationPlayState::Enum::kPending:
        NOTREACHED();
    }
  }

  // We only send animationUpdated events for running or finished animations.
  if (new_play_state != V8AnimationPlayState::Enum::kRunning &&
      new_play_state != V8AnimationPlayState::Enum::kFinished) {
    return;
  }

  bool should_notify_frontend =
      this->CompareAndUpdateInternalSnapshot(*animation, snapshot);
  if (should_notify_frontend &&
      !notify_animation_updated_tasks_.Contains(animation_id)) {
    notify_animation_updated_tasks_.insert(animation_id);
    scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        inspected_frames_->Root()->GetTaskRunner(TaskType::kInternalInspector);
    task_runner->PostDelayedTask(
        FROM_HERE,
        WTF::BindOnce(&InspectorAnimationAgent::NotifyAnimationUpdated,
                      WrapPersistent(weak_factory_.GetWeakCell()),
                      animation_id),
        base::Milliseconds(50));
  }
}

void InspectorAnimationAgent::DidClearDocumentOfWindowObject(
    LocalFrame* frame) {
  if (!enabled_.Get())
    return;
  DCHECK(frame->GetDocument());
  frame->GetDocument()->Timeline().SetPlaybackRate(
      ReferenceTimeline().PlaybackRate());
}

protocol::Response InspectorAnimationAgent::AssertAnimation(
    const String& id,
    blink::Animation*& result) {
  auto it = id_to_animation_.find(id);
  if (it == id_to_animation_.end()) {
    result = nullptr;
    return protocol::Response::ServerError(
        "Could not find animation with given id");
  }
  result
```