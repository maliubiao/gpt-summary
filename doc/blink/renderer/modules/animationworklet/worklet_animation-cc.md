Response:
Let's break down the thought process for analyzing this Chromium source code snippet.

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code, specifically focusing on its relation to JavaScript, HTML, and CSS, along with examples, potential errors, debugging steps, and a concise summary of its functionality. It's also part 1 of 2, implying we should focus on the core logic introduced in this section.

2. **Initial Scan for Key Concepts:**  Quickly read through the code, paying attention to included headers, class names, function names, and key variables. This gives a high-level overview. Notice terms like "WorkletAnimation," "KeyframeEffect," "AnimationTimeline," "ScriptState," "V8Union," "CompositorAnimation," "playbackRate," "currentTime," "playState," etc. These immediately suggest this code deals with animations driven by a worklet and interacts with the browser's animation system.

3. **Identify the Core Class:** The central class is `WorkletAnimation`. The code provides its constructor and several methods. This class is clearly the focus of the functionality being described.

4. **Analyze Functionality by Method:**  Go through the methods of `WorkletAnimation` one by one, understanding their purpose.

    * **`Create()` overloads:** These are factory methods. They take various arguments related to animation definition (animator name, effects, timeline, options) and construct a `WorkletAnimation` object. The use of `V8Union` suggests interaction with JavaScript objects. Error handling with `ExceptionState` is apparent.
    * **Constructor:** Initializes the `WorkletAnimation` with the provided parameters, sets up internal data structures (like `local_times_`, `effect_timings_`), and attaches the animation to the effects.
    * **`playState()`, `play()`, `currentTime()`, `startTime()`, `pause()`, `cancel()`, `playbackRate()`, `setPlaybackRate()`:** These are the standard animation control methods, directly mapping to the Web Animations API. They manipulate the animation's state and timing.
    * **`UpdateIfNecessary()`, `Update()`:** These methods handle updating the animation's time and state, potentially triggering recalculations.
    * **`SetCurrentTime()`:**  This method is crucial for understanding how the animation's time is managed, considering timeline activity and play state. The logic within needs careful examination.
    * **`UpdateCompositingState()`, `InvalidateCompositingState()`, `StartOnMain()`, `CanStartOnCompositor()`, `StartOnCompositor()`, `UpdateOnCompositor()`, `DestroyCompositorAnimation()`:** This block of methods deals with a key aspect: running the animation on the compositor thread for better performance. This involves checking conditions, creating and updating `CompositorAnimation` objects.
    * **`GetEffect()`:** A simple getter for the animation's effect.
    * **`IsActiveAnimation()`, `IsTimelineActive()`, `IsCurrentTimeInitialized()`:** Helper methods for checking the animation's state.
    * **`InitialCurrentTime()`:**  Calculates the initial time based on the timeline, which is important for starting the animation correctly.
    * **`UpdateCurrentTimeIfNeeded()`, `CurrentTime()`, `CurrentTimeInternal()`:**  These methods are responsible for calculating and updating the animation's current time, considering timeline activity and potential discrepancies.
    * **`UpdateInputState()`, `SetOutputState()`, `NotifyLocalTimeUpdated()`:** These methods indicate communication with the animation worklet itself, passing input and receiving output.
    * **`Dispose()`:** Cleans up resources.
    * **`Trace()`:**  For debugging and memory management.

5. **Identify Relationships with Web Technologies:**

    * **JavaScript:**  The use of `ScriptState`, `V8Union`, `ScriptValue`, and `SerializedScriptValue` clearly indicates interaction with JavaScript. The `Create()` methods are called from JavaScript. The methods like `play()`, `pause()`, `currentTime()`, etc., directly correspond to the Web Animations API exposed to JavaScript.
    * **HTML:** The animation is applied to elements in the HTML document. The code references `Element` and `Node`.
    * **CSS:** The `KeyframeEffect` and `Timing` objects represent CSS animation properties. The concept of a `DocumentTimeline` and `ScrollTimeline` are tied to CSS features.

6. **Look for Logic and Potential Issues:**

    * **Compositor Integration:** The complexity around `StartOnCompositor()` and related methods suggests potential issues related to synchronization between the main thread and the compositor thread. Fallbacks to the main thread if compositing isn't possible are present.
    * **Timeline Management:** The logic in `SetCurrentTime()` and `UpdateCurrentTimeIfNeeded()` regarding timeline activity is intricate and a potential source of bugs if not handled correctly.
    * **Error Handling:** The use of `ExceptionState` in `Create()` and other methods highlights places where errors can occur due to invalid input or state.
    * **Performance Considerations:** The move to the compositor thread is a performance optimization, suggesting potential issues if animations can't be composited.
    * **Worklet Communication:** The interaction with the `AnimationWorkletDispatcherInput` and `AnimationWorkletOutput` implies potential issues with data transfer and synchronization with the worklet.

7. **Construct Examples (Hypothetical Input/Output):**  Think of common animation scenarios and how they might interact with this code. For example, starting a simple fade-in animation on an element with a document timeline. Consider scenarios with scroll timelines as well.

8. **Identify User/Programming Errors:** Based on the code's functionality, identify common mistakes users or developers might make, like providing invalid effect types, using unsupported timelines, or calling methods in the wrong state.

9. **Outline Debugging Steps:**  Trace the execution flow. Where would breakpoints be useful?  How would you inspect the state of the `WorkletAnimation` object?  Consider the user actions that lead to this code being executed.

10. **Synthesize a Summary:**  Condense the findings into a concise summary of the file's purpose.

11. **Review and Refine:** Read through the generated response and ensure accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed. For example, initially, I might not have explicitly highlighted the multi-effect limitation. A review would catch this. Also, ensuring the examples are concrete and easy to understand is crucial.

This iterative process of scanning, analyzing, relating to web technologies, identifying issues, and synthesizing allows for a comprehensive understanding of the source code. The "part 1 of 2" instruction suggests focusing on the core animation logic and deferring more advanced aspects (which might appear in the next part) for later.
好的，让我们来分析一下 `blink/renderer/modules/animationworklet/worklet_animation.cc` 文件的功能。

**文件功能归纳:**

这个 C++ 文件定义了 `WorkletAnimation` 类，它是 Blink 渲染引擎中用于处理 **Animation Worklet** 创建的动画的核心组件。  `WorkletAnimation` 允许开发者通过 JavaScript 定义自定义动画逻辑并在一个独立的工作线程（Worklet）中运行这些逻辑，从而实现高性能的动画效果。

**详细功能分解:**

1. **动画的创建和初始化:**
   - 提供了多个 `Create` 方法，用于从 JavaScript 代码中创建 `WorkletAnimation` 对象。
   - 这些方法接收动画器名称 (`animator_name`)、动画效果 (`effects`)、时间线 (`timeline`) 和可选的参数 (`options`)。
   - 负责验证输入参数，例如动画效果必须是 `KeyframeEffect` 类型，时间线类型目前不支持 `ScrollTimeline`。
   - 将 JavaScript 传递的参数转换为 C++ 内部表示，例如使用 `SerializedScriptValue` 序列化 JavaScript 对象。
   - 为动画生成唯一的 ID (`WorkletAnimationId`)。
   - 将 `WorkletAnimation` 对象与指定的 `AnimationTimeline` 关联。

2. **动画的生命周期管理:**
   - 实现了动画的播放 (`play`)、暂停 (`pause`) 和取消 (`cancel`) 等操作。
   - 维护动画的播放状态 (`play_state_`)，例如 `idle`、`pending`、`running`、`paused`。
   - 跟踪动画是否已经开始 (`has_started_`)。
   - 管理动画的当前时间 (`current_time_`) 和起始时间 (`start_time_`)。

3. **动画效果的处理:**
   - 存储动画的 `KeyframeEffect` 列表 (`effects_`)。
   - 支持单个或序列的 `KeyframeEffect`（但目前多效果支持需要开启实验性特性 `GroupEffectEnabled`）。
   - 将 `WorkletAnimation` 对象附加到其关联的 `KeyframeEffect` 上。

4. **动画时间线的管理:**
   - 支持关联 `DocumentTimeline` 或 `ScrollTimeline`（但目前 `ScrollTimeline` 支持受限）。
   - 负责将 JavaScript 传递的时间线对象转换为 C++ 的 `AnimationTimeline` 对象。
   - 跟踪时间线的激活状态 (`was_timeline_active_`)，以便在时间线状态变化时更新动画的时间。

5. **与 Compositor 的交互:**
   - 决定动画是否可以在 Compositor 线程上运行以提高性能。
   - 实现了将动画启动 (`StartOnCompositor`) 和更新 (`UpdateOnCompositor`) 到 Compositor 线程的逻辑。
   - 使用 `CompositorAnimation` 对象来表示 Compositor 线程上的动画。
   - 处理 Compositor 线程上的动画完成或取消等事件。
   - 如果动画无法在 Compositor 线程上运行，则回退到主线程运行 (`StartOnMain`).

6. **与 Animation Worklet 的通信:**
   - 维护动画器名称 (`animator_name_`)，用于标识处理该动画的 Animation Worklet 中的哪个动画器。
   - 存储传递给 Animation Worklet 的选项 (`options_`)。
   - 提供了 `UpdateInputState` 方法，用于向 Animation Worklet 传递动画的当前状态（例如当前时间），作为 Worklet 执行自定义动画逻辑的输入。
   - 提供了 `SetOutputState` 方法，用于接收 Animation Worklet 返回的动画状态更新（例如每个效果的本地时间）。

7. **错误处理和调试:**
   - 使用 `ExceptionState` 来抛出 JavaScript 异常，例如当动画效果类型不正确或动画器未注册时。
   - 在控制台中输出警告信息，例如当尝试设置播放速率为 0 时。
   - 包含用于调试的 `Trace` 方法。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    - `WorkletAnimation` 对象是由 JavaScript 代码通过 `CSS.animationWorklet.createAnimation()` 方法创建的。
    ```javascript
    // 假设 'my-animator' 是在 Animation Worklet 中注册的动画器名称
    const animation = new WorkletAnimation('my-animator', keyframeEffect, document.timeline);
    document.timeline.play(animation);
    ```
    - 传递给 `WorkletAnimation` 的 `effects` 和 `timeline` 参数通常是 JavaScript 中的 `KeyframeEffect` 和 `DocumentTimeline` 或 `ScrollTimeline` 对象。
    - `options` 参数是一个 JavaScript 对象，其内容会被序列化并传递给 Animation Worklet。
    - 通过 `animation.play()`, `animation.pause()`, `animation.currentTime`, `animation.playbackRate` 等 JavaScript API 来控制 `WorkletAnimation` 的行为。

* **HTML:**
    - `WorkletAnimation` 最终会影响 HTML 元素的样式。
    - `KeyframeEffect` 通常会关联一个或多个 HTML 元素作为其动画目标。
    - 当 `WorkletAnimation` 在 Compositor 线程上运行时，可以高效地更新 HTML 元素的视觉属性，例如 `transform`, `opacity` 等，而不会阻塞主线程。

* **CSS:**
    - `KeyframeEffect` 定义了动画的关键帧，这与 CSS 动画的概念密切相关。
    - `DocumentTimeline` 和 `ScrollTimeline` 是与 CSS 时间线相关的概念，用于控制动画的进度。
    - Animation Worklet 的目标是提供一种更灵活和高性能的方式来实现 CSS 动画效果。

**逻辑推理与假设输入/输出:**

假设 JavaScript 代码创建了一个 `WorkletAnimation`，用于修改一个元素的 `opacity` 属性：

**假设输入:**

- **`animator_name`:** "fade-animator" (假设 Animation Worklet 中存在名为 "fade-animator" 的动画器)
- **`effects`:** 一个包含一个 `KeyframeEffect` 对象的序列，该 `KeyframeEffect` 的目标是一个 `div` 元素，并且定义了 `opacity` 属性从 0 到 1 的动画。
- **`timeline`:** `document.timeline` (默认的文档时间线)
- **`options`:**  一个空对象 `{}`

**逻辑推理:**

1. `WorkletAnimation::Create` 方法被调用。
2. 验证 `effects` 参数是否为 `KeyframeEffect` 类型（假设是）。
3. 验证 `timeline` 参数是否为支持的类型（`DocumentTimeline` 是支持的）。
4. 检查名为 "fade-animator" 的动画器是否已在 `WorkletAnimationController` 中注册。
5. 创建一个 `WorkletAnimation` 对象，并将上述参数存储在对象的成员变量中。
6. 如果 JavaScript 调用了 `animation.play()`，则 `WorkletAnimation::play` 方法会被调用。
7. `play` 方法会尝试将动画启动到 Compositor 线程（如果条件允许）。
8. 如果在 Compositor 线程上运行，Compositor 会根据时间线和动画器的逻辑来更新元素的 `opacity` 属性。
9. 如果在主线程上运行，则会定期调用 Animation Worklet 中的 "fade-animator"，并根据其返回的结果更新元素的样式。

**潜在输出（取决于 Animation Worklet 中的 "fade-animator" 的具体实现）:**

- 目标 `div` 元素的 `opacity` 属性会在指定的时间内从 0 平滑过渡到 1。

**用户或编程常见的使用错误及举例说明:**

1. **使用不支持的动画效果类型:**
   ```javascript
   // 错误：AnimationWorklet 目前只支持 KeyframeEffect
   const effect = new CustomAnimationEffect(...);
   const animation = new WorkletAnimation('my-animator', effect, document.timeline);
   // 会导致异常： "Effect must be a KeyframeEffect object"
   ```

2. **使用不支持的时间线类型:**
   ```javascript
   // 错误：ScrollTimeline 目前可能不受完全支持
   const scrollTimeline = new ScrollTimeline(...);
   const animation = new WorkletAnimation('my-animator', keyframeEffect, scrollTimeline);
   // 可能会导致异常： "ScrollTimeline is not yet supported for worklet animations"
   ```

3. **尝试在动画器未注册的情况下创建动画:**
   ```javascript
   // 错误： 假设 'non-existent-animator' 没有在 Animation Worklet 中注册
   const animation = new WorkletAnimation('non-existent-animator', keyframeEffect, document.timeline);
   // 会导致异常： "The animator 'non-existent-animator' has not yet been registered."
   ```

4. **在错误的状态下调用动画控制方法:**  例如，在动画已经取消后再次调用 `play()`。虽然代码会进行一些检查，但理解动画的状态转换很重要。

**用户操作到达此处的调试线索:**

1. 用户在 JavaScript 代码中使用了 `CSS.animationWorklet.createAnimation()` 方法来创建 `WorkletAnimation` 对象。
2. 用户调用了 `animation.play()` 方法来启动动画。
3. Blink 渲染引擎接收到创建动画的请求，并执行 `WorkletAnimation::Create` 方法。
4. 如果在创建或播放过程中发生错误（例如，使用了不支持的参数），则会在 `WorkletAnimation::Create` 或 `WorkletAnimation::play` 等方法中抛出异常。
5. 开发者可以使用 Chrome DevTools 的断点功能，在 `blink/renderer/modules/animationworklet/worklet_animation.cc` 文件中的相关方法上设置断点，来检查动画对象的创建和状态转换过程。
6. 可以检查传递给 `Create` 方法的参数是否正确，以及动画的 `play_state_`, `current_time_`, `start_time_` 等成员变量的值。
7. 如果涉及到 Compositor 线程，可以使用 `chrome://tracing` 工具来查看 Compositor 线程上的动画活动。

**第1部分功能归纳:**

`blink/renderer/modules/animationworklet/worklet_animation.cc` 文件的第 1 部分主要负责 **`WorkletAnimation` 对象的创建、初始化和基本的生命周期管理**。它处理了从 JavaScript 到 C++ 的参数转换，验证了输入参数的有效性，并初步确定了动画的运行方式（主线程或 Compositor 线程）。 核心功能包括：

- **创建和初始化 `WorkletAnimation` 对象。**
- **处理动画的基本控制操作 (play, pause, cancel)。**
- **管理动画效果和时间线。**
- **初步判断动画是否可以运行在 Compositor 线程。**
- **与 Animation Worklet 进行初步的交互（通过存储动画器名称和选项）。**
- **进行错误处理和提供调试信息。**

这部分代码为后续的动画执行和更新奠定了基础。

### 提示词
```
这是目录为blink/renderer/modules/animationworklet/worklet_animation.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/animationworklet/worklet_animation.h"

#include <optional>

#include "cc/animation/animation_timeline.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_animationeffect_animationeffectsequence.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_documenttimeline_scrolltimeline.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/animation/scroll_timeline_util.h"
#include "third_party/blink/renderer/core/animation/timing.h"
#include "third_party/blink/renderer/core/animation/worklet_animation_controller.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/modules/animationworklet/css_animation_worklet.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

bool ConvertAnimationEffects(
    const V8UnionAnimationEffectOrAnimationEffectSequence* effects,
    HeapVector<Member<KeyframeEffect>>& keyframe_effects,
    String& error_string) {
  DCHECK(effects);
  DCHECK(keyframe_effects.empty());

  // Currently we only support KeyframeEffect.
  switch (effects->GetContentType()) {
    case V8UnionAnimationEffectOrAnimationEffectSequence::ContentType::
        kAnimationEffect: {
      AnimationEffect* effect = effects->GetAsAnimationEffect();
      KeyframeEffect* keyframe_effect = DynamicTo<KeyframeEffect>(effect);
      if (!keyframe_effect) {
        error_string = "Effect must be a KeyframeEffect object";
        return false;
      }
      keyframe_effects.push_back(keyframe_effect);
      break;
    }
    case V8UnionAnimationEffectOrAnimationEffectSequence::ContentType::
        kAnimationEffectSequence: {
      const HeapVector<Member<AnimationEffect>>& effect_sequence =
          effects->GetAsAnimationEffectSequence();
      keyframe_effects.ReserveInitialCapacity(effect_sequence.size());
      for (const auto& effect : effect_sequence) {
        KeyframeEffect* keyframe_effect =
            DynamicTo<KeyframeEffect>(effect.Get());
        if (!keyframe_effect) {
          error_string = "Effects must all be KeyframeEffect objects";
          return false;
        }
        keyframe_effects.push_back(keyframe_effect);
      }
      break;
    }
  }

  if (keyframe_effects.empty()) {
    error_string = "Effects array must be non-empty";
    return false;
  }

  if (keyframe_effects.size() > 1 &&
      !RuntimeEnabledFeatures::GroupEffectEnabled()) {
    error_string = "Multiple effects are not currently supported";
    return false;
  }

  return true;
}

bool IsActive(V8AnimationPlayState::Enum state) {
  switch (state) {
    case V8AnimationPlayState::Enum::kIdle:
    case V8AnimationPlayState::Enum::kPending:
      return false;
    case V8AnimationPlayState::Enum::kRunning:
    case V8AnimationPlayState::Enum::kPaused:
      return true;
    default:
      // kUnset and kFinished are not used in WorkletAnimation.
      NOTREACHED();
  }
}

bool ValidateTimeline(const V8UnionDocumentTimelineOrScrollTimeline* timeline,
                      String& error_string) {
  if (!timeline)
    return true;
  if (timeline->IsScrollTimeline()) {
    // crbug.com/1238130 Add support for progress based timelines to worklet
    // animations
    error_string = "ScrollTimeline is not yet supported for worklet animations";
    return false;
  }
  return true;
}

AnimationTimeline* ConvertAnimationTimeline(
    const Document& document,
    const V8UnionDocumentTimelineOrScrollTimeline* timeline) {
  if (!timeline)
    return &document.Timeline();
  switch (timeline->GetContentType()) {
    case V8UnionDocumentTimelineOrScrollTimeline::ContentType::
        kDocumentTimeline:
      return timeline->GetAsDocumentTimeline();
    case V8UnionDocumentTimelineOrScrollTimeline::ContentType::kScrollTimeline:
      return timeline->GetAsScrollTimeline();
  }
  NOTREACHED();
}

void StartEffectOnCompositor(CompositorAnimation* animation,
                             KeyframeEffect* effect) {
  DCHECK(effect);
  DCHECK(effect->EffectTarget());
  Element& target = *effect->EffectTarget();
  effect->Model()->SnapshotAllCompositorKeyframesIfNecessary(
      target, target.ComputedStyleRef(), target.ParentComputedStyle());

  int group = 0;
  std::optional<double> start_time = std::nullopt;

  // Normally the playback rate of a blink animation gets translated into
  // equivalent playback rate of cc::KeyframeModels.
  // This has worked for regular animations since their current time was not
  // exposed in cc. However, for worklet animations this does not work because
  // the current time is exposed and it is an animation level concept as
  // opposed to a keyframe model level concept.
  // So it makes sense here that we use "1" as playback rate for KeyframeModels
  // and separately plumb the playback rate to cc worklet animation.
  // TODO(majidvp): Remove playbackRate from KeyframeModel in favor of having
  // it on animation. https://crbug.com/925373.
  double playback_rate = 1;

  effect->StartAnimationOnCompositor(group, start_time, base::TimeDelta(),
                                     playback_rate, animation);
}

unsigned NextSequenceNumber() {
  // TODO(majidvp): This should actually come from the same source as other
  // animation so that they have the correct ordering.
  static unsigned next = 0;
  return ++next;
}

double ToMilliseconds(std::optional<base::TimeDelta> time) {
  return time ? time->InMillisecondsF()
              : std::numeric_limits<double>::quiet_NaN();
}

// Calculates start time backwards from the current time and
// timeline.currentTime.
std::optional<base::TimeDelta> CalculateStartTime(base::TimeDelta current_time,
                                                  double playback_rate,
                                                  AnimationTimeline& timeline) {
  // Handle some special cases, note |playback_rate| can never be 0 before
  // SetPlaybackRateInternal has a DCHECK for that.
  DCHECK_NE(playback_rate, 0);
  if (current_time.is_max())
    return base::Milliseconds(0);
  if (current_time.is_min())
    return base::TimeDelta::Max();
  std::optional<double> timeline_current_time_ms =
      timeline.CurrentTimeMilliseconds();
  return base::Milliseconds(timeline_current_time_ms.value()) -
         (current_time / playback_rate);
}

}  // namespace

WorkletAnimation* WorkletAnimation::Create(
    ScriptState* script_state,
    const String& animator_name,
    const V8UnionAnimationEffectOrAnimationEffectSequence* effects,
    ExceptionState& exception_state) {
  return Create(script_state, animator_name, effects, nullptr, ScriptValue(),
                exception_state);
}

WorkletAnimation* WorkletAnimation::Create(
    ScriptState* script_state,
    const String& animator_name,
    const V8UnionAnimationEffectOrAnimationEffectSequence* effects,
    const V8UnionDocumentTimelineOrScrollTimeline* timeline,
    ExceptionState& exception_state) {
  return Create(script_state, animator_name, effects, timeline, ScriptValue(),
                exception_state);
}

WorkletAnimation* WorkletAnimation::Create(
    ScriptState* script_state,
    const String& animator_name,
    const V8UnionAnimationEffectOrAnimationEffectSequence* effects,
    const V8UnionDocumentTimelineOrScrollTimeline* timeline,
    const ScriptValue& options,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  HeapVector<Member<KeyframeEffect>> keyframe_effects;
  String error_string;
  if (!ConvertAnimationEffects(effects, keyframe_effects, error_string)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      error_string);
    return nullptr;
  }

  if (!ValidateTimeline(timeline, error_string)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      error_string);
    return nullptr;
  }

  Document& document = *LocalDOMWindow::From(script_state)->document();
  if (!document.GetWorkletAnimationController().IsAnimatorRegistered(
          animator_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The animator '" + animator_name + "' has not yet been registered.");
    return nullptr;
  }

  AnimationWorklet* worklet =
      CSSAnimationWorklet::animationWorklet(script_state);

  WorkletAnimationId id = worklet->NextWorkletAnimationId();

  AnimationTimeline* animation_timeline =
      ConvertAnimationTimeline(document, timeline);

  scoped_refptr<SerializedScriptValue> animation_options;
  if (!options.IsEmpty()) {
    animation_options = SerializedScriptValue::Serialize(
        script_state->GetIsolate(), options.V8Value(),
        SerializedScriptValue::SerializeOptions(
            SerializedScriptValue::kNotForStorage),
        exception_state);
    if (exception_state.HadException())
      return nullptr;
  }

  WorkletAnimation* animation = MakeGarbageCollected<WorkletAnimation>(
      id, animator_name, document, keyframe_effects, animation_timeline,
      std::move(animation_options));

  return animation;
}

WorkletAnimation::WorkletAnimation(
    WorkletAnimationId id,
    const String& animator_name,
    Document& document,
    const HeapVector<Member<KeyframeEffect>>& effects,
    AnimationTimeline* timeline,
    scoped_refptr<SerializedScriptValue> options)
    : sequence_number_(NextSequenceNumber()),
      id_(id),
      animator_name_(animator_name),
      playback_rate_(1),
      was_timeline_active_(false),
      document_(document),
      effects_(effects),
      timeline_(timeline),
      options_(std::make_unique<WorkletAnimationOptions>(options)),
      effect_needs_restart_(false) {
  DCHECK(IsMainThread());

  auto timings = base::MakeRefCounted<base::RefCountedData<Vector<Timing>>>();
  timings->data.ReserveInitialCapacity(effects_.size());

  auto normalized_timings = base::MakeRefCounted<
      base::RefCountedData<Vector<Timing::NormalizedTiming>>>();
  normalized_timings->data.ReserveInitialCapacity(effects_.size());

  DCHECK_GE(effects_.size(), 1u);
  for (auto& effect : effects_) {
    AnimationEffect* target_effect = effect;
    target_effect->Attach(this);
    local_times_.push_back(std::nullopt);
    timings->data.push_back(target_effect->SpecifiedTiming());
    normalized_timings->data.push_back(target_effect->NormalizedTiming());
  }
  effect_timings_ = std::make_unique<WorkletAnimationEffectTimings>(
      timings, normalized_timings);
}

V8AnimationPlayState WorkletAnimation::playState() {
  DCHECK(IsMainThread());
  return V8AnimationPlayState(play_state_);
}

void WorkletAnimation::play(ExceptionState& exception_state) {
  DCHECK(IsMainThread());
  if (play_state_ == V8AnimationPlayState::Enum::kPending ||
      play_state_ == V8AnimationPlayState::Enum::kRunning) {
    return;
  }

  if (play_state_ == V8AnimationPlayState::Enum::kPaused) {
    // If we have ever started before then just unpause otherwise we need to
    // start the animation.
    if (has_started_) {
      SetPlayState(V8AnimationPlayState::Enum::kPending);
      SetCurrentTime(CurrentTime());
      InvalidateCompositingState();
      return;
    }
  } else {
    DCHECK(!IsCurrentTimeInitialized());
  }

  String failure_message;
  if (!CheckCanStart(&failure_message)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      failure_message);
    return;
  }

  document_->GetWorkletAnimationController().AttachAnimation(*this);
  // While animation is pending, it hold time at Zero, see:
  // https://drafts.csswg.org/web-animations-1/#playing-an-animation-section
  SetPlayState(V8AnimationPlayState::Enum::kPending);
  SetCurrentTime(InitialCurrentTime());
  has_started_ = true;

  for (auto& effect : effects_) {
    Element* target = effect->EffectTarget();
    if (!target)
      continue;

    // TODO(crbug.com/896249): Currently we have to keep a set of worklet
    // animations in ElementAnimations so that the compositor knows that there
    // are active worklet animations running. Ideally, this should be done via
    // the regular Animation path, i.e., unify the logic between the two
    // Animations.
    target->EnsureElementAnimations().GetWorkletAnimations().insert(this);
    target->SetNeedsAnimationStyleRecalc();
  }
}

std::optional<double> WorkletAnimation::currentTime() {
  std::optional<base::TimeDelta> current_time = CurrentTime();
  if (!current_time)
    return std::nullopt;
  return ToMilliseconds(current_time.value());
}

std::optional<double> WorkletAnimation::startTime() {
  // The timeline may have become newly active or inactive, which then can cause
  // the start time to change.
  UpdateCurrentTimeIfNeeded();
  if (!start_time_)
    return std::nullopt;
  return ToMilliseconds(start_time_.value());
}

void WorkletAnimation::pause(ExceptionState& exception_state) {
  DCHECK(IsMainThread());
  if (play_state_ == V8AnimationPlayState::Enum::kPaused) {
    return;
  }

  // If animation is pending it means we have not sent an update to
  // compositor. Since we are pausing, immediately start the animation
  // which updates start time and marks animation as main thread.
  // This ensures we have a valid current time to hold.
  if (play_state_ == V8AnimationPlayState::Enum::kPending) {
    StartOnMain();
  }

  // If animation is playing then we should hold the current time
  // otherwise hold zero.
  SetPlayState(V8AnimationPlayState::Enum::kPaused);
  std::optional<base::TimeDelta> new_current_time =
      IsCurrentTimeInitialized() ? CurrentTime() : InitialCurrentTime();
  DCHECK(new_current_time);
  SetCurrentTime(new_current_time);
}

void WorkletAnimation::cancel() {
  DCHECK(IsMainThread());
  if (play_state_ == V8AnimationPlayState::Enum::kIdle) {
    return;
  }
  document_->GetWorkletAnimationController().DetachAnimation(*this);
  if (compositor_animation_) {
    GetEffect()->CancelAnimationOnCompositor(compositor_animation_.get());
    DestroyCompositorAnimation();
  }
  has_started_ = false;
  local_times_.Fill(std::nullopt);
  running_on_main_thread_ = false;
  // TODO(crbug.com/883312): Because this animation has been detached and will
  // not receive updates anymore, we have to update its value upon cancel.
  // Similar to regular animations, we should not detach them immediately and
  // update the value in the next frame.
  if (IsActive(play_state_)) {
    for (auto& effect : effects_) {
      effect->UpdateInheritedTime(std::nullopt,
                                  /* is_idle */ false, playback_rate_,
                                  kTimingUpdateOnDemand);
    }
  }
  SetPlayState(V8AnimationPlayState::Enum::kIdle);
  SetCurrentTime(std::nullopt);

  for (auto& effect : effects_) {
    Element* target = effect->EffectTarget();
    if (!target)
      continue;
    // TODO(crbug.com/896249): Currently we have to keep a set of worklet
    // animations in ElementAnimations so that the compositor knows that there
    // are active worklet animations running. Ideally, this should be done via
    // the regular Animation path, i.e., unify the logic between the two
    // Animations.
    target->EnsureElementAnimations().GetWorkletAnimations().erase(this);
    target->SetNeedsAnimationStyleRecalc();
  }
}

bool WorkletAnimation::Playing() const {
  return play_state_ == V8AnimationPlayState::Enum::kRunning;
}

void WorkletAnimation::UpdateIfNecessary() {
  // TODO(crbug.com/833846): This is updating more often than necessary. This
  // gets fixed once WorkletAnimation becomes a subclass of Animation.
  Update(kTimingUpdateOnDemand);
}

double WorkletAnimation::playbackRate(ScriptState* script_state) const {
  return playback_rate_;
}

void WorkletAnimation::setPlaybackRate(ScriptState* script_state,
                                       double playback_rate) {
  if (playback_rate == playback_rate_)
    return;

  // TODO(https://crbug.com/821910): Implement 0 playback rate after pause()
  // support is in.
  if (!playback_rate) {
    if (document_->GetFrame() && ExecutionContext::From(script_state)) {
      document_->GetFrame()->Console().AddMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::ConsoleMessageSource::kJavaScript,
              mojom::ConsoleMessageLevel::kWarning,
              "WorkletAnimation currently does not support "
              "playback rate of Zero."));
    }
    return;
  }

  SetPlaybackRateInternal(playback_rate);
}

void WorkletAnimation::SetPlaybackRateInternal(double playback_rate) {
  DCHECK(std::isfinite(playback_rate));
  DCHECK_NE(playback_rate, playback_rate_);
  DCHECK(playback_rate);

  std::optional<base::TimeDelta> previous_current_time = CurrentTime();
  playback_rate_ = playback_rate;
  // Update startTime in order to maintain previous currentTime and, as a
  // result, prevent the animation from jumping.
  if (previous_current_time)
    SetCurrentTime(previous_current_time);

  if (Playing())
    document_->GetWorkletAnimationController().InvalidateAnimation(*this);
}

void WorkletAnimation::EffectInvalidated() {
  InvalidateCompositingState();
}

void WorkletAnimation::Update(TimingUpdateReason reason) {
  if (play_state_ != V8AnimationPlayState::Enum::kRunning &&
      play_state_ != V8AnimationPlayState::Enum::kPaused) {
    return;
  }

  DCHECK_EQ(effects_.size(), local_times_.size());
  for (wtf_size_t i = 0; i < effects_.size(); ++i) {
    effects_[i]->UpdateInheritedTime(
        local_times_[i]
            ? std::make_optional(AnimationTimeDelta(local_times_[i].value()))
            : std::nullopt,
        /* is_idle */ false, playback_rate_, reason);
  }
}

bool WorkletAnimation::CheckCanStart(String* failure_message) {
  DCHECK(IsMainThread());

  for (auto& effect : effects_) {
    if (effect->Model()->HasFrames())
      continue;
    *failure_message = "Animation effect has no keyframes";
    return false;
  }

  return true;
}

void WorkletAnimation::SetCurrentTime(
    std::optional<base::TimeDelta> current_time) {
  DCHECK(timeline_);
  DCHECK(current_time || play_state_ == V8AnimationPlayState::Enum::kIdle);
  // The procedure either:
  // 1) updates the hold time (for paused animations, non-existent or inactive
  //    timeline)
  // 2) updates the start time (for playing animations)
  bool should_hold = play_state_ == V8AnimationPlayState::Enum::kPaused ||
                     !current_time || !IsTimelineActive();
  if (should_hold) {
    start_time_ = std::nullopt;
    hold_time_ = current_time;
  } else {
    start_time_ =
        CalculateStartTime(current_time.value(), playback_rate_, *timeline_);
    hold_time_ = std::nullopt;
  }
  last_current_time_ = current_time;
  was_timeline_active_ = IsTimelineActive();
}

void WorkletAnimation::UpdateCompositingState() {
  DCHECK(play_state_ != V8AnimationPlayState::Enum::kIdle);

  if (play_state_ == V8AnimationPlayState::Enum::kPending) {
#if DCHECK_IS_ON()
    String warning_message;
    DCHECK(CheckCanStart(&warning_message));
    DCHECK(warning_message.empty());
#endif  // DCHECK_IS_ON()
    if (StartOnCompositor())
      return;
    StartOnMain();
  } else if (play_state_ == V8AnimationPlayState::Enum::kRunning) {
    // TODO(majidvp): If keyframes have changed then it may be possible to now
    // run the animation on compositor. The current logic does not allow this
    // switch from main to compositor to happen. https://crbug.com/972691.
    if (!running_on_main_thread_) {
      if (!UpdateOnCompositor()) {
        // When an animation that is running on compositor loses the target, it
        // falls back to main thread. We need to initialize the last play state
        // before this transition to avoid re-adding the same animation to the
        // worklet.
        last_play_state_ = play_state_;

        StartOnMain();
      }
    }
  }
  DCHECK(running_on_main_thread_ != !!compositor_animation_)
      << "Active worklet animation should either run on main or compositor";
}

void WorkletAnimation::InvalidateCompositingState() {
  effect_needs_restart_ = true;
  document_->GetWorkletAnimationController().InvalidateAnimation(*this);
}

void WorkletAnimation::StartOnMain() {
  running_on_main_thread_ = true;
  std::optional<base::TimeDelta> current_time =
      IsCurrentTimeInitialized() ? CurrentTime() : InitialCurrentTime();
  DCHECK(current_time);
  SetPlayState(V8AnimationPlayState::Enum::kRunning);
  SetCurrentTime(current_time);
}

bool WorkletAnimation::CanStartOnCompositor() {
  if (effects_.size() > 1) {
    // Compositor doesn't support multiple effects but they can be run via main.
    return false;
  }

  if (!GetEffect()->EffectTarget())
    return false;

  Element& target = *GetEffect()->EffectTarget();

  // TODO(crbug.com/836393): This should not be possible but it is currently
  // happening and needs to be investigated/fixed.
  if (!target.GetComputedStyle())
    return false;
  // CheckCanStartAnimationOnCompositor requires that the property-specific
  // keyframe groups have been created. To ensure this we manually snapshot the
  // frames in the target effect.
  // TODO(smcgruer): This shouldn't be necessary - Animation doesn't do this.
  GetEffect()->Model()->SnapshotAllCompositorKeyframesIfNecessary(
      target, target.ComputedStyleRef(), target.ParentComputedStyle());

  CompositorAnimations::FailureReasons failure_reasons =
      GetEffect()->CheckCanStartAnimationOnCompositor(nullptr, playback_rate_);

  if (failure_reasons != CompositorAnimations::kNoFailure)
    return false;

  // If the scroll source is not composited, fall back to main thread.
  if (timeline_->IsScrollTimeline() &&
      !CompositorAnimations::CanStartScrollTimelineOnCompositor(
          To<ScrollTimeline>(*timeline_).ResolvedSource())) {
    return false;
  }

  // TODO(crbug.com/1281413): This function has returned false since the launch
  // of CompositeAfterPaint, but that may not be intended. Should this return
  // true?
  return false;
}

bool WorkletAnimation::StartOnCompositor() {
  DCHECK(IsMainThread());
  // There is no need to proceed if an animation has already started on main
  // thread.
  // TODO(majidvp): If keyframes have changed then it may be possible to now
  // run the animation on compositor. The current logic does not allow this
  // switch from main to compositor to happen. https://crbug.com/972691.
  if (running_on_main_thread_)
    return false;

  if (!CanStartOnCompositor())
    return false;

  if (!compositor_animation_) {
    // TODO(smcgruer): If the scroll source later gets a LayoutBox (e.g. was
    // display:none and now isn't) or the writing mode changes, we need to
    // update the compositor to have the correct orientation and start/end
    // offset information.
    compositor_animation_ = CompositorAnimation::CreateWorkletAnimation(
        id_, animator_name_, playback_rate_, std::move(options_),
        std::move(effect_timings_));
    compositor_animation_->SetAnimationDelegate(this);
  }

  // Register ourselves on the compositor timeline. This will cause our cc-side
  // animation animation to be registered.
  cc::AnimationTimeline* compositor_timeline =
      timeline_ ? timeline_->EnsureCompositorTimeline() : nullptr;
  if (compositor_timeline) {
    if (GetCompositorAnimation()) {
      compositor_timeline->AttachAnimation(
          GetCompositorAnimation()->CcAnimation());
    }
    // Note that while we attach here but we don't detach because the
    // |compositor_timeline| is detached in its destructor.
    if (compositor_timeline->IsScrollTimeline())
      document_->AttachCompositorTimeline(compositor_timeline);
  }

  CompositorAnimations::AttachCompositedLayers(*GetEffect()->EffectTarget(),
                                               compositor_animation_.get());

  // TODO(smcgruer): We need to start all of the effects, not just the first.
  StartEffectOnCompositor(compositor_animation_.get(), GetEffect());
  SetPlayState(V8AnimationPlayState::Enum::kRunning);
  SetCurrentTime(InitialCurrentTime());
  return true;
}

bool WorkletAnimation::UpdateOnCompositor() {
  if (effect_needs_restart_) {
    // We want to update the keyframe effect on compositor animation without
    // destroying the compositor animation instance. This is achieved by
    // canceling, and starting the blink keyframe effect on compositor.
    effect_needs_restart_ = false;
    GetEffect()->CancelAnimationOnCompositor(compositor_animation_.get());
    if (!CanStartOnCompositor()) {
      // Destroy the compositor animation if the animation is no longer
      // compositable.
      //
      // TODO(821910): At the moment destroying the compositor animation
      // instance also deletes the animator instance which is problematic for
      // stateful animators. A more seamless hand-off is needed here and for
      // pause.
      DestroyCompositorAnimation();
      return false;
    }

    StartEffectOnCompositor(compositor_animation_.get(), GetEffect());
  }

  if (timeline_->IsScrollTimeline())
    timeline_->UpdateCompositorTimeline();

  compositor_animation_->UpdatePlaybackRate(playback_rate_);
  return true;
}

void WorkletAnimation::DestroyCompositorAnimation() {
  if (compositor_animation_ && compositor_animation_->IsElementAttached())
    compositor_animation_->DetachElement();

  cc::AnimationTimeline* compositor_timeline =
      timeline_ ? timeline_->CompositorTimeline() : nullptr;
  if (compositor_timeline && GetCompositorAnimation()) {
    compositor_timeline->DetachAnimation(
        GetCompositorAnimation()->CcAnimation());
  }

  if (compositor_animation_) {
    compositor_animation_->SetAnimationDelegate(nullptr);
    compositor_animation_ = nullptr;
  }
}

KeyframeEffect* WorkletAnimation::GetEffect() const {
  DCHECK(effects_.at(0));
  return effects_.at(0).Get();
}

bool WorkletAnimation::IsActiveAnimation() const {
  return IsActive(play_state_);
}

bool WorkletAnimation::IsTimelineActive() const {
  return timeline_ && timeline_->IsActive();
}

bool WorkletAnimation::IsCurrentTimeInitialized() const {
  return start_time_ || hold_time_;
}

// Returns initial current time of an animation. This method is called when
// calculating initial start time.
// Document-linked animations are initialized with the current time of zero
// and start time of the document timeline current time.
// Scroll-linked animations are initialized with the start time of
// zero (i.e., scroll origin) and the current time corresponding to the current
// scroll position adjusted by the playback rate.
//
// More information at AnimationTimeline::InitialStartTimeForAnimations
//
// TODO(https://crbug.com/986925): The playback rate should be taken into
// consideration when calculating the initial current time.
// https://drafts.csswg.org/web-animations/#playing-an-animation-section
std::optional<base::TimeDelta> WorkletAnimation::InitialCurrentTime() const {
  if (play_state_ == V8AnimationPlayState::Enum::kIdle || !IsTimelineActive()) {
    return std::nullopt;
  }

  std::optional<base::TimeDelta> starting_time =
      timeline_->InitialStartTimeForAnimations();
  std::optional<double> current_time = timeline_->CurrentTimeMilliseconds();

  if (!starting_time || !current_time) {
    return std::nullopt;
  }

  return (base::Milliseconds(current_time.value()) - starting_time.value()) *
         playback_rate_;
}

void WorkletAnimation::UpdateCurrentTimeIfNeeded() {
  bool is_timeline_active = IsTimelineActive();
  if (is_timeline_active != was_timeline_active_) {
    if (is_timeline_active) {
      if (!IsCurrentTimeInitialized()) {
        // The animation has started with inactive timeline. Initialize the
        // current time now.
        SetCurrentTime(InitialCurrentTime());
      } else {
        // Apply hold_time on current_time.
        SetCurrentTime(hold_time_);
      }
    } else {
      // Apply current_time on hold_time.
      SetCurrentTime(last_current_time_);
    }
    was_timeline_active_ = is_timeline_active;
  }
}

std::optional<base::TimeDelta> WorkletAnimation::CurrentTime() {
  if (play_state_ == V8AnimationPlayState::Enum::kIdle) {
    return std::nullopt;
  }

  // Current time calculated for scroll-linked animations depends on style
  // of the associated scroller. However it does not force style recalc when it
  // changes. This may create a situation when style has changed, style recalc
  // didn't run and the current time is calculated on the "dirty" style.
  UpdateCurrentTimeIfNeeded();
  last_current_time_ = CurrentTimeInternal();
  return last_current_time_;
}

std::optional<base::TimeDelta> WorkletAnimation::CurrentTimeInternal() const {
  if (play_state_ == V8AnimationPlayState::Enum::kIdle) {
    return std::nullopt;
  }

  if (hold_time_)
    return hold_time_.value();

  // We return early here when the animation has started with inactive
  // timeline and the timeline has never been activated.
  if (!IsTimelineActive())
    return std::nullopt;

  // Currently ScrollTimeline may return unresolved current time when:
  // - Current scroll offset is less than startScrollOffset and fill mode is
  //   none or forward.
  // OR
  // - Current scroll offset is greater than or equal to endScrollOffset and
  //   fill mode is none or backwards.
  std::optional<double> timeline_time_ms = timeline_->CurrentTimeMilliseconds();
  if (!timeline_time_ms)
    return std::nullopt;

  base::TimeDelta timeline_time = base::Milliseconds(timeline_time_ms.value());
  DCHECK(start_time_);
  return (timeline_time - start_time_.value()) * playback_rate_;
}

void WorkletAnimation::UpdateInputState(
    AnimationWorkletDispatcherInput* input_state) {
  std::optional<base::TimeDelta> current_time = CurrentTime();
  if (!running_on_main_thread_) {
    return;
  }
  bool was_active = IsActive(last_play_state_);
  bool is_active = IsActive(play_state_);

  // We don't animate if there is no valid current time.
  if (!current_time)
    return;

  bool did_time_change = current_time != last_input_update_current_time_;
  last_input_update_current_time_ = current_time;

  double current_time_ms = current_time.value().InMillisecondsF();

  if (!was_active && is_active) {
    input_state->Add({id_, animator_name_.Utf8(), current_time_ms,
                      CloneOptions(), CloneEffectTimings()});
  } else if (was_active && is_active) {
    // Skip if the input time is not changed.
    if (did_time_change)
      // TODO(jortaylo): EffectTimings need to be sent to the worklet during
      // updates, otherwise the timing info will become outdated.
      // https://crbug.com/915344.
      input_state->Update({id_, current_time_ms});
  } else if (was_active && !is_active) {
    input_state->Remove(id_);
  }
  last_play_state_ = play_state_;
}

void WorkletAnimation::SetOutputState(
    const AnimationWorkletOutput::AnimationState& state) {
  DCHECK(state.worklet_animation_id == id_);
  // The local times for composited effects, i.e. not running on main, are
  // updated via posting animation events from the compositor thread to the main
  // thread (see WorkletAnimation::NotifyLocalTimeUpdated).
  DCHECK(local_times_.size() == state.local_times.size() &&
         running_on_main_thread_);
  for (wtf_size_t i = 0; i < state.local_times.size(); ++i)
    local_times_[i] = state.local_times[i];
}

void WorkletAnimation::NotifyLocalTimeUpdated(
    std::optional<base::TimeDelta> local_time) {
  DCHECK(!running_on_main_thread_);
  local_times_[0] = local_time;
}

void WorkletAnimation::Dispose() {
  DCHECK(IsMainThread());
  DestroyCompositorAnimation();
}

void WorkletAnimation::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(effe
```