Response:
My thinking process to arrive at the summary of `svg_smil_element.cc` went through these stages:

1. **Initial Scan and Keyword Identification:** I first scanned the code for prominent keywords and class names. "SMIL," "animation," "SVG," "time," "begin," "end," "repeat," "duration," "event," "condition," and various data structures like `SMILInstanceTimeList` stood out. This immediately suggested the file deals with SVG animation using SMIL (Synchronized Multimedia Integration Language).

2. **Understanding the Core Class:** The filename itself, `svg_smil_element.cc`, pointed to a central class: `SVGSMILElement`. I looked for its constructor, destructor, and key methods. This confirmed that this class is the main actor in handling SMIL animation elements within Blink.

3. **Analyzing Key Functionality Blocks:** I started grouping related functionalities:
    * **Time Management:** The presence of `SMILInstanceTimeList`, `ParseClockValue`, `ParseOffsetValue`, `Dur`, `RepeatDur`, `RepeatCount`, `ResolveInterval`, `ComputeNextIntervalTime`, and the handling of `begin_times_` and `end_times_` clearly indicated a focus on parsing, managing, and calculating animation timing.
    * **Conditions and Events:** The `Condition` class, `ConnectConditions`, `DisconnectConditions`, `ParseCondition`, and handling of `onbegin`, `onend`, and `onrepeat` attributes highlighted the ability to trigger animations based on events and other conditions.
    * **Active State and Interval Management:**  Variables like `active_state_`, `interval_`, `previous_interval_`, and methods like `UpdateInterval`, `SetNewInterval`, `SetNewIntervalEnd` suggested mechanisms for tracking and updating the animation's active state and the intervals it occupies.
    * **Target Element:** The `target_element_` and related methods (`BuildPendingResource`, `SetTargetElement`) indicated that SMIL animations target specific SVG elements.
    * **Restart and Fill:** The `restart_` and `fill_` variables and their corresponding attribute parsing confirmed the implementation of these SMIL animation features.
    * **Prioritization:**  The `IsHigherPriorityThan` method hinted at a mechanism for resolving conflicts or ordering when multiple animations are active.

4. **Mapping to Web Standards:** My knowledge of web standards helped connect these code elements to the actual behavior of SMIL animations in browsers. For example, I knew that `<animate>`, `<set>`, `<animateMotion>`, etc., are SMIL elements, and attributes like `begin`, `end`, `dur`, `repeatCount` are core to SMIL. This allowed me to interpret the code in a broader context.

5. **Identifying Relationships with HTML, CSS, and JavaScript:** I considered how SMIL interacts with other web technologies:
    * **HTML:**  SMIL animations are embedded within SVG elements, which are themselves embedded in HTML. The code's interaction with the DOM through `parentElement()`, `GetTreeScope()`, and the `InsertedInto` and `RemovedFrom` methods demonstrates this connection.
    * **CSS:** While SMIL has its own timing model, it can indirectly influence CSS properties. The code's focus on manipulating SVG attributes (which can affect rendering) highlights this. However, the code explicitly notes that the `fill` attribute is handled differently for animation elements, distinguishing it from CSS properties.
    * **JavaScript:** The parsing of `onbegin`, `onend`, and `onrepeat` attributes and the use of `JSEventHandlerForContentAttribute` clearly show how JavaScript event handlers can be attached to SMIL animation events. The ability to script the `begin` and `end` times also connects to JavaScript.

6. **Formulating Examples and Use Cases:** Based on the identified functionalities, I constructed concrete examples of how these features would be used in an actual web page. This involved imagining simple SVG animations and how their timing and behavior would be defined using SMIL attributes.

7. **Inferring Potential Errors:** By understanding how users interact with SMIL attributes, I could identify common mistakes, such as incorrect syntax for time values, conflicting timing definitions, or referencing non-existent target elements.

8. **Tracing User Operations:**  I considered the typical steps a developer would take to create and debug a SMIL animation, from writing the SVG/SMIL code to using browser developer tools. This allowed me to create a plausible sequence of actions leading to the point where a developer might examine the `svg_smil_element.cc` code.

9. **Structuring the Summary:** Finally, I organized my findings into a logical structure, covering the core functionality, relationships with other web technologies, examples, potential errors, and user interaction. I focused on clear and concise language, avoiding overly technical jargon. Since this was the first part of the summary, I specifically focused on outlining the major functions of the file without going into excessive detail about the implementation of each function.

This iterative process of scanning, analyzing, connecting to standards, generating examples, and structuring helped me develop a comprehensive understanding of the `svg_smil_element.cc` file's role within the Blink rendering engine.
这是对 `blink/renderer/core/svg/animation/svg_smil_element.cc` 文件功能的归纳总结，重点在第一部分的内容。

**功能归纳:**

`svg_smil_element.cc` 文件定义了 `SVGSMILElement` 类，它是 Chromium Blink 引擎中处理 SVG SMIL (Synchronized Multimedia Integration Language) 动画元素的核心类。其主要功能可以归纳为：

1. **解析和管理 SMIL 动画的定时属性:**
   -  解析 `begin`, `end`, `dur`, `repeatCount`, `repeatDur`, `min`, `max` 等 SMIL 动画的定时属性，并将这些值转换为内部表示 (`SMILTime`, `SMILRepeatCount` 等）。
   -  维护动画的起始时间和结束时间列表 (`begin_times_`, `end_times_`)，并根据属性变化进行更新和排序。
   -  提供方法计算动画的简单持续时间 (`SimpleDuration`) 和重复持续时间 (`RepeatingDuration`)。

2. **处理动画的开始和结束条件:**
   -  解析 `begin` 和 `end` 属性中的各种定时值，包括 offset-values, clock-values，以及基于事件和同步的条件表达式。
   -  创建和管理 `Condition` 对象，用于表示动画的开始或结束条件，例如基于特定事件的触发或与其他动画元素的同步。
   -  连接和断开与条件相关的事件监听器和同步基础元素，以便在条件满足时触发动画。

3. **管理动画的目标元素:**
   -  通过 `href` 属性（或 `xlink:href`）确定动画的目标 SVG 元素。
   -  观察目标元素的变化，并在目标元素变更或从文档中移除时更新引用。

4. **维护动画的活动状态和时间间隔:**
   -  维护动画的当前活动状态 (`active_state_`)，例如 `kInactive`, `kActive`, `kFrozen`。
   -  使用 `SMILInterval` 类表示动画的活动时间间隔。
   -  计算和更新动画的当前时间间隔，并考虑各种定时属性和条件。

5. **支持动画的重启和填充行为:**
   -  解析 `restart` 属性，并确定动画在父元素或自身重复时是否重启。
   -  解析 `fill` 属性，并确定动画在非活动期间是否保持最后一帧。

6. **处理动画事件:**
   -  设置和管理 `onbegin`, `onend`, `onrepeat` 等事件的监听器，以便在动画的不同阶段触发 JavaScript 代码。

7. **与其他 Blink 引擎组件的集成:**
   -  使用 `UseCounter` 记录 SMIL 功能的使用情况。
   -  与 `SMILTimeContainer` 协同工作，获取当前的 presentation time 并进行时间同步。
   -  使用 `IdTargetObserver` 观察目标元素的变化。
   -  使用 `NativeEventListener` 处理基于事件的动画触发条件。

**与 Javascript, HTML, CSS 的关系举例说明:**

* **Javascript:**
    -  `onbegin`, `onend`, `onrepeat` 属性可以绑定 JavaScript 函数，在动画开始、结束或重复时执行。例如，在 HTML 中：
       ```html
       <animate attributeName="opacity" from="0" to="1" dur="1s" onbegin="console.log('动画开始了！')" />
       ```
    -  可以通过 JavaScript 脚本动态修改 SMIL 元素的属性，例如修改 `begin` 属性来延迟动画的开始。

* **HTML:**
    -  SMIL 动画元素（如 `<animate>`, `<set>`, `<animateMotion>` 等）直接嵌入在 SVG 元素中，而 SVG 元素又可以嵌入在 HTML 文档中。
    -  `href` 或 `xlink:href` 属性用于指定动画作用的目标 HTML 或 SVG 元素。例如：
       ```html
       <svg>
         <rect id="targetRect" width="100" height="100" fill="red" />
         <animate attributeName="x" from="0" to="200" dur="1s" begin="0s" xlink:href="#targetRect" />
       </svg>
       ```

* **CSS:**
    -  虽然 SMIL 主要处理动画的定时和行为，但它会影响 SVG 元素的视觉表现，从而间接地与 CSS 相关联。 例如，通过 `<animate>` 元素改变 SVG 元素的 `fill` 属性，会影响元素的颜色渲染，这与 CSS 的 `fill` 属性功能类似。
    -  该文件代码中提到，对于动画元素，`fill` 属性不会映射到 CSS 的 `fill` 属性，说明 Blink 引擎对这两种 `fill` 属性做了区分处理。

**逻辑推理 (假设输入与输出):**

假设输入一个 `<animate>` 元素，其 `begin` 属性设置为 `2s; rect1.click + 1s`， `dur` 属性设置为 `3s`。

* **输入:** `<animate attributeName="opacity" from="0" to="1" dur="3s" begin="2s; rect1.click + 1s" xlink:href="#myRect"/>` 以及文档中 id 为 `rect1` 的元素。
* **逻辑推理:**
    -  `begin` 属性包含两个条件：
        -  `2s`: 动画将在文档加载 2 秒后开始。
        -  `rect1.click + 1s`: 当 id 为 `rect1` 的元素被点击后 1 秒开始。
    -  `dur` 属性表示动画的持续时间为 3 秒。
* **输出:**  `SVGSMILElement` 会解析这些属性，创建两个 `Condition` 对象（一个对应 offset-value，一个对应 event-value），并注册一个点击事件监听器到 `rect1` 元素。动画将在 2 秒后开始，或者在 `rect1` 被点击后的 1 秒后开始，取两者较早的时间。动画从 opacity 0 渐变到 1，持续 3 秒。

**用户或编程常见的使用错误举例说明:**

1. **错误的定时值语法:** 用户可能输入了无法解析的定时值，例如 `begin="2 ss"` (多了一个 's')，导致动画无法按预期启动。Blink 引擎会尝试解析，如果失败则可能忽略该值或使用默认值。
2. **循环依赖:** 两个或多个动画的开始或结束条件相互依赖，导致死锁或意外行为。例如，动画 A 的结束触发动画 B 的开始，而动画 B 的结束又触发动画 A 的开始。
3. **目标元素 ID 不存在:**  `href` 或 `xlink:href` 属性指向的元素 ID 在文档中不存在，导致动画无法找到目标，从而不起作用。
4. **事件名称拼写错误:** 在事件触发条件下，事件名称拼写错误（例如 `onclick` 写成 `clik`），导致监听器无法正确注册，动画无法响应事件。

**用户操作如何一步步的到达这里 (调试线索):**

1. **开发者编写包含 SMIL 动画的 SVG 代码，并将其嵌入到 HTML 页面中。**
2. **用户在浏览器中加载该 HTML 页面。**
3. **Blink 引擎开始解析 HTML 和 SVG 代码，创建 DOM 树和渲染树。**
4. **当解析到 SMIL 动画元素（例如 `<animate>`) 时，会创建对应的 `SVGSMILElement` 对象。**
5. **`SVGSMILElement::InsertedInto` 方法会被调用，进行初始化工作，例如获取 `SMILTimeContainer`，解析 `begin` 属性等。**
6. **`SVGSMILElement::BuildPendingResource` 方法会被调用，用于查找和关联动画的目标元素。**
7. **如果 `begin` 属性包含事件条件（例如 `rect1.click`），`SVGSMILElement::ConnectConditions` 会被调用，创建 `ConditionEventListener` 并添加到目标元素上。**
8. **用户与页面交互，例如点击了 `rect1` 元素。**
9. **浏览器触发 `click` 事件。**
10. **之前注册的 `ConditionEventListener` 捕获到该事件，并调用其 `Invoke` 方法。**
11. **在 `Invoke` 方法中，会调用 `SVGSMILElement::AddInstanceTimeAndUpdate`，将事件发生的时间添加到动画的起始时间列表中。**
12. **Blink 的动画调度器会根据时间列表和当前时间，决定何时激活动画。**
13. **如果开发者遇到动画不工作或行为异常，可能会使用浏览器开发者工具查看元素的属性，或者设置断点在 `svg_smil_element.cc` 相关的代码中进行调试，例如在 `ParseBeginOrEnd`, `ConnectConditions`, `AddInstanceTimeAndUpdate` 等方法中查看变量的值和执行流程，以找出问题所在。**

总而言之，`svg_smil_element.cc` 是 Blink 引擎中负责解析、管理和执行 SVG SMIL 动画的核心组件，它连接了 SVG 动画的声明式定义和底层的渲染机制。

### 提示词
```
这是目录为blink/renderer/core/svg/animation/svg_smil_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2008 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/svg/animation/svg_smil_element.h"

#include <algorithm>

#include "base/auto_reset.h"
#include "base/time/time.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/js_event_handler_for_content_attribute.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/id_target_observer.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/svg/animation/smil_time_container.h"
#include "third_party/blink/renderer/core/svg/svg_set_element.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_uri_reference.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

// Compute the next time an interval with a certain (non-zero) simple duration
// will repeat, relative to a certain presentation time.
SMILTime ComputeNextRepeatTime(SMILTime interval_begin,
                               SMILTime simple_duration,
                               SMILTime presentation_time) {
  DCHECK(simple_duration);
  DCHECK_LE(interval_begin, presentation_time);
  SMILTime time_in_interval = presentation_time - interval_begin;
  SMILTime time_until_next_repeat =
      simple_duration - (time_in_interval % simple_duration);
  return presentation_time + time_until_next_repeat;
}

}  // namespace

void SMILInstanceTimeList::Append(SMILTime time, SMILTimeOrigin origin) {
  instance_times_.push_back(SMILTimeWithOrigin(time, origin));
  time_origins_.Put(origin);
}

void SMILInstanceTimeList::InsertSortedAndUnique(SMILTime time,
                                                 SMILTimeOrigin origin) {
  SMILTimeWithOrigin time_with_origin(time, origin);
  auto position = std::lower_bound(instance_times_.begin(),
                                   instance_times_.end(), time_with_origin);
  // Don't add it if we already have one of those.
  for (auto it = position; it != instance_times_.end(); ++it) {
    if (position->Time() != time)
      break;
    // If they share both time and origin, we don't need to add it,
    // we just need to react.
    if (position->Origin() == origin)
      return;
  }
  instance_times_.insert(
      static_cast<wtf_size_t>(position - instance_times_.begin()),
      time_with_origin);
  time_origins_.Put(origin);
}

void SMILInstanceTimeList::RemoveWithOrigin(SMILTimeOrigin origin) {
  if (!time_origins_.Has(origin)) {
    return;
  }
  auto tail = std::remove_if(instance_times_.begin(), instance_times_.end(),
                             [origin](const SMILTimeWithOrigin& instance_time) {
                               return instance_time.Origin() == origin;
                             });
  instance_times_.Shrink(
      static_cast<wtf_size_t>(tail - instance_times_.begin()));
  time_origins_.Remove(origin);
}

void SMILInstanceTimeList::Sort() {
  std::sort(instance_times_.begin(), instance_times_.end());
}

SMILTime SMILInstanceTimeList::NextAfter(SMILTime time) const {
  // Find the value in |list| that is strictly greater than |time|.
  auto next_item = std::lower_bound(
      instance_times_.begin(), instance_times_.end(), time,
      [](const SMILTimeWithOrigin& instance_time, const SMILTime& time) {
        return instance_time.Time() <= time;
      });
  if (next_item == instance_times_.end())
    return SMILTime::Unresolved();
  return next_item->Time();
}

// This is used for duration type time values that can't be negative.
static constexpr SMILTime kInvalidCachedTime = SMILTime::Earliest();

class ConditionEventListener final : public NativeEventListener {
 public:
  ConditionEventListener(SVGSMILElement* animation,
                         SVGSMILElement::Condition* condition)
      : animation_(animation), condition_(condition) {}

  void DisconnectAnimation() { animation_ = nullptr; }

  void Invoke(ExecutionContext*, Event*) override {
    if (!animation_)
      return;
    animation_->AddInstanceTimeAndUpdate(
        condition_->GetBeginOrEnd(),
        animation_->Elapsed() + condition_->Offset(), SMILTimeOrigin::kEvent);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(animation_);
    visitor->Trace(condition_);
    NativeEventListener::Trace(visitor);
  }

 private:
  Member<SVGSMILElement> animation_;
  Member<SVGSMILElement::Condition> condition_;
};

SVGSMILElement::Condition::Condition(Type type,
                                     BeginOrEnd begin_or_end,
                                     const AtomicString& base_id,
                                     const AtomicString& name,
                                     SMILTime offset,
                                     unsigned repeat)
    : type_(type),
      begin_or_end_(begin_or_end),
      base_id_(base_id),
      name_(name),
      offset_(offset),
      repeat_(repeat) {}

SVGSMILElement::Condition::~Condition() = default;

void SVGSMILElement::Condition::Trace(Visitor* visitor) const {
  visitor->Trace(base_element_);
  visitor->Trace(base_id_observer_);
  visitor->Trace(event_listener_);
}

void SVGSMILElement::Condition::ConnectSyncBase(SVGSMILElement& timed_element) {
  DCHECK(!base_id_.empty());
  DCHECK_EQ(type_, kSyncBase);
  DCHECK(!base_element_);
  auto* svg_smil_element =
      DynamicTo<SVGSMILElement>(SVGURIReference::ObserveTarget(
          base_id_observer_, timed_element.GetTreeScope(), base_id_,
          WTF::BindRepeating(&SVGSMILElement::BuildPendingResource,
                             WrapWeakPersistent(&timed_element))));
  if (!svg_smil_element)
    return;
  base_element_ = svg_smil_element;
  svg_smil_element->AddSyncBaseDependent(timed_element);
}

void SVGSMILElement::Condition::DisconnectSyncBase(
    SVGSMILElement& timed_element) {
  DCHECK_EQ(type_, kSyncBase);
  SVGURIReference::UnobserveTarget(base_id_observer_);
  if (!base_element_)
    return;
  To<SVGSMILElement>(*base_element_).RemoveSyncBaseDependent(timed_element);
  base_element_ = nullptr;
}

void SVGSMILElement::Condition::ConnectEventBase(
    SVGSMILElement& timed_element) {
  DCHECK_EQ(type_, kEventBase);
  DCHECK(!base_element_);
  DCHECK(!event_listener_);
  Element* target;
  if (base_id_.empty()) {
    target = timed_element.targetElement();
  } else {
    target = SVGURIReference::ObserveTarget(
        base_id_observer_, timed_element.GetTreeScope(), base_id_,
        WTF::BindRepeating(&SVGSMILElement::BuildPendingResource,
                           WrapWeakPersistent(&timed_element)));
  }
  if (!target)
    return;
  event_listener_ =
      MakeGarbageCollected<ConditionEventListener>(&timed_element, this);
  base_element_ = target;
  base_element_->addEventListener(name_, event_listener_, false);
}

void SVGSMILElement::Condition::DisconnectEventBase(
    SVGSMILElement& timed_element) {
  DCHECK_EQ(type_, kEventBase);
  SVGURIReference::UnobserveTarget(base_id_observer_);
  if (!event_listener_)
    return;
  base_element_->removeEventListener(name_, event_listener_, false);
  base_element_ = nullptr;
  event_listener_->DisconnectAnimation();
  event_listener_ = nullptr;
}

SVGSMILElement::SVGSMILElement(const QualifiedName& tag_name, Document& doc)
    : SVGElement(tag_name, doc),
      SVGTests(this),
      target_element_(nullptr),
      conditions_connected_(false),
      has_end_event_conditions_(false),
      is_waiting_for_first_interval_(true),
      is_scheduled_(false),
      interval_(SMILInterval::Unresolved()),
      previous_interval_(SMILInterval::Unresolved()),
      active_state_(kInactive),
      restart_(kRestartAlways),
      fill_(kFillRemove),
      last_progress_{0.0f, 0},
      document_order_index_(0),
      queue_handle_(kNotFound),
      cached_dur_(kInvalidCachedTime),
      cached_repeat_dur_(kInvalidCachedTime),
      cached_repeat_count_(SMILRepeatCount::Invalid()),
      cached_min_(kInvalidCachedTime),
      cached_max_(kInvalidCachedTime),
      interval_has_changed_(false),
      instance_lists_have_changed_(false),
      interval_needs_revalidation_(false),
      is_notifying_dependents_(false) {}

SVGSMILElement::~SVGSMILElement() = default;

void SVGSMILElement::ClearResourceAndEventBaseReferences() {
  SVGURIReference::UnobserveTarget(target_id_observer_);
  RemoveAllOutgoingReferences();
}

void SVGSMILElement::BuildPendingResource() {
  ClearResourceAndEventBaseReferences();
  DisconnectConditions();

  if (!isConnected()) {
    // Reset the target element if we are no longer in the document.
    SetTargetElement(nullptr);
    return;
  }

  const AtomicString& href = SVGURIReference::LegacyHrefString(*this);
  Element* target;
  if (href.empty()) {
    target = parentElement();
  } else {
    target = SVGURIReference::ObserveTarget(target_id_observer_, *this, href);
  }
  auto* svg_target = DynamicTo<SVGElement>(target);

  if (svg_target && !svg_target->isConnected())
    svg_target = nullptr;

  SetTargetElement(svg_target);

  if (svg_target) {
    // Register us with the target in the dependencies map. Any change of
    // hrefElement that leads to relayout/repainting now informs us, so we can
    // react to it.
    AddReferenceTo(svg_target);
  }
  ConnectConditions();
}

void SVGSMILElement::Reset() {
  active_state_ = kInactive;
  is_waiting_for_first_interval_ = true;
  interval_ = SMILInterval::Unresolved();
  previous_interval_ = SMILInterval::Unresolved();
  last_progress_ = {0.0f, 0};
}

Node::InsertionNotificationRequest SVGSMILElement::InsertedInto(
    ContainerNode& root_parent) {
  SVGElement::InsertedInto(root_parent);

  if (!root_parent.isConnected())
    return kInsertionDone;

  UseCounter::Count(GetDocument(), WebFeature::kSVGSMILElementInDocument);
  if (GetDocument().IsLoadCompleted()) {
    UseCounter::Count(&GetDocument(),
                      WebFeature::kSVGSMILElementInsertedAfterLoad);
  }

  SVGSVGElement* owner = ownerSVGElement();
  if (!owner)
    return kInsertionDone;

  time_container_ = owner->TimeContainer();
  DCHECK(time_container_);
  time_container_->SetDocumentOrderIndexesDirty();

  // "If no attribute is present, the default begin value (an offset-value of 0)
  // must be evaluated."
  if (!FastHasAttribute(svg_names::kBeginAttr) && begin_times_.IsEmpty())
    begin_times_.Append(SMILTime(), SMILTimeOrigin::kAttribute);

  BuildPendingResource();
  return kInsertionDone;
}

void SVGSMILElement::RemovedFrom(ContainerNode& root_parent) {
  if (root_parent.isConnected()) {
    ClearResourceAndEventBaseReferences();
    ClearConditions();
    SetTargetElement(nullptr);
    time_container_ = nullptr;
  }

  SVGElement::RemovedFrom(root_parent);
}

SMILTime SVGSMILElement::ParseOffsetValue(const String& data) {
  bool ok;
  double result = 0;
  const String parse = data.StripWhiteSpace();
  if (parse.EndsWith('h')) {
    result = parse.Left(parse.length() - 1).ToDouble(&ok) *
             base::Time::kSecondsPerHour;
  } else if (parse.EndsWith("min")) {
    result = parse.Left(parse.length() - 3).ToDouble(&ok) *
             base::Time::kSecondsPerMinute;
  } else if (parse.EndsWith("ms")) {
    result = parse.Left(parse.length() - 2).ToDouble(&ok) /
             base::Time::kMillisecondsPerSecond;
  } else if (parse.EndsWith('s')) {
    result = parse.Left(parse.length() - 1).ToDouble(&ok);
  } else {
    result = parse.ToDouble(&ok);
  }
  return ok ? SMILTime::FromSecondsD(result) : SMILTime::Unresolved();
}

SMILTime SVGSMILElement::ParseClockValue(const String& data) {
  if (data.IsNull())
    return SMILTime::Unresolved();

  String parse = data.StripWhiteSpace();

  DEFINE_STATIC_LOCAL(const AtomicString, indefinite_value, ("indefinite"));
  if (parse == indefinite_value)
    return SMILTime::Indefinite();

  double result = 0;
  bool ok;
  wtf_size_t double_point_one = parse.find(':');
  wtf_size_t double_point_two = parse.find(':', double_point_one + 1);
  if (double_point_one == 2 && double_point_two == 5 && parse.length() >= 8) {
    result += parse.Substring(0, 2).ToUIntStrict(&ok) * 60 * 60;
    if (!ok)
      return SMILTime::Unresolved();
    result += parse.Substring(3, 2).ToUIntStrict(&ok) * 60;
    if (!ok)
      return SMILTime::Unresolved();
    result += parse.Substring(6).ToDouble(&ok);
  } else if (double_point_one == 2 && double_point_two == kNotFound &&
             parse.length() >= 5) {
    result += parse.Substring(0, 2).ToUIntStrict(&ok) * 60;
    if (!ok)
      return SMILTime::Unresolved();
    result += parse.Substring(3).ToDouble(&ok);
  } else {
    return ParseOffsetValue(parse);
  }

  if (!ok)
    return SMILTime::Unresolved();
  return SMILTime::FromSecondsD(result);
}

bool SVGSMILElement::ParseCondition(const String& value,
                                    BeginOrEnd begin_or_end) {
  String parse_string = value.StripWhiteSpace();

  bool is_negated = false;
  bool ok;
  wtf_size_t pos = parse_string.find('+');
  if (pos == kNotFound) {
    pos = parse_string.find('-');
    is_negated = pos != kNotFound;
  }
  String condition_string;
  SMILTime offset;
  if (pos == kNotFound) {
    condition_string = parse_string;
  } else {
    condition_string = parse_string.Left(pos).StripWhiteSpace();
    String offset_string = parse_string.Substring(pos + 1).StripWhiteSpace();
    offset = ParseOffsetValue(offset_string);
    if (offset.IsUnresolved())
      return false;
    if (is_negated)
      offset = -offset;
  }
  if (condition_string.empty())
    return false;
  pos = condition_string.find('.');

  String base_id;
  String name_string;
  if (pos == kNotFound) {
    name_string = condition_string;
  } else {
    base_id = condition_string.Left(pos);
    name_string = condition_string.Substring(pos + 1);
  }
  if (name_string.empty())
    return false;

  Condition::Type type;
  int repeat = -1;
  if (name_string.StartsWith("repeat(") && name_string.EndsWith(')')) {
    repeat =
        name_string.Substring(7, name_string.length() - 8).ToUIntStrict(&ok);
    if (!ok)
      return false;
    name_string = "repeat";
    type = Condition::kSyncBase;
  } else if (name_string == "begin" || name_string == "end") {
    if (base_id.empty())
      return false;
    UseCounter::Count(&GetDocument(),
                      WebFeature::kSVGSMILBeginOrEndSyncbaseValue);
    type = Condition::kSyncBase;
  } else if (name_string.StartsWith("accesskey(")) {
    // FIXME: accesskey() support.
    type = Condition::kAccessKey;
  } else {
    UseCounter::Count(&GetDocument(), WebFeature::kSVGSMILBeginOrEndEventValue);
    type = Condition::kEventBase;
  }

  conditions_.push_back(MakeGarbageCollected<Condition>(
      type, begin_or_end, AtomicString(base_id), AtomicString(name_string),
      offset, repeat));

  if (type == Condition::kEventBase && begin_or_end == kEnd)
    has_end_event_conditions_ = true;

  return true;
}

void SVGSMILElement::ParseBeginOrEnd(const String& parse_string,
                                     BeginOrEnd begin_or_end) {
  auto& time_list = begin_or_end == kBegin ? begin_times_ : end_times_;
  if (begin_or_end == kEnd)
    has_end_event_conditions_ = false;

  // Remove any previously added offset-values.
  // TODO(fs): Ought to remove instance times originating from sync-bases,
  // events etc. as well if those conditions are no longer in the attribute.
  time_list.RemoveWithOrigin(SMILTimeOrigin::kAttribute);

  Vector<String> split_string;
  parse_string.Split(';', split_string);
  for (const auto& item : split_string) {
    SMILTime value = ParseClockValue(item);
    if (value.IsUnresolved())
      ParseCondition(item, begin_or_end);
    else
      time_list.Append(value, SMILTimeOrigin::kAttribute);
  }
  // "If no attribute is present, the default begin value (an offset-value of 0)
  // must be evaluated."
  if (begin_or_end == kBegin && parse_string.IsNull())
    begin_times_.Append(SMILTime(), SMILTimeOrigin::kAttribute);

  time_list.Sort();
}

void SVGSMILElement::ParseAttribute(const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  const AtomicString& value = params.new_value;
  if (name == svg_names::kBeginAttr) {
    if (!conditions_.empty()) {
      ClearConditions();
      ParseBeginOrEnd(FastGetAttribute(svg_names::kEndAttr), kEnd);
    }
    ParseBeginOrEnd(value.GetString(), kBegin);
    if (isConnected()) {
      ConnectConditions();
      instance_lists_have_changed_ = true;
      InstanceListChanged();
    }
  } else if (name == svg_names::kEndAttr) {
    if (!conditions_.empty()) {
      ClearConditions();
      ParseBeginOrEnd(FastGetAttribute(svg_names::kBeginAttr), kBegin);
    }
    ParseBeginOrEnd(value.GetString(), kEnd);
    if (isConnected()) {
      ConnectConditions();
      instance_lists_have_changed_ = true;
      InstanceListChanged();
    }
  } else if (name == svg_names::kOnbeginAttr) {
    SetAttributeEventListener(event_type_names::kBeginEvent,
                              JSEventHandlerForContentAttribute::Create(
                                  GetExecutionContext(), name, value));
  } else if (name == svg_names::kOnendAttr) {
    SetAttributeEventListener(event_type_names::kEndEvent,
                              JSEventHandlerForContentAttribute::Create(
                                  GetExecutionContext(), name, value));
  } else if (name == svg_names::kOnrepeatAttr) {
    SetAttributeEventListener(event_type_names::kRepeatEvent,
                              JSEventHandlerForContentAttribute::Create(
                                  GetExecutionContext(), name, value));
  } else if (name == svg_names::kRestartAttr) {
    if (value == "never")
      restart_ = kRestartNever;
    else if (value == "whenNotActive")
      restart_ = kRestartWhenNotActive;
    else
      restart_ = kRestartAlways;
  } else if (name == svg_names::kFillAttr) {
    fill_ = value == "freeze" ? kFillFreeze : kFillRemove;
  } else if (name == svg_names::kDurAttr) {
    cached_dur_ = kInvalidCachedTime;
    IntervalStateChanged();
  } else if (name == svg_names::kRepeatDurAttr) {
    cached_repeat_dur_ = kInvalidCachedTime;
    IntervalStateChanged();
  } else if (name == svg_names::kRepeatCountAttr) {
    cached_repeat_count_ = SMILRepeatCount::Invalid();
    IntervalStateChanged();
  } else if (name == svg_names::kMinAttr) {
    cached_min_ = kInvalidCachedTime;
    IntervalStateChanged();
  } else if (name == svg_names::kMaxAttr) {
    cached_max_ = kInvalidCachedTime;
    IntervalStateChanged();
  } else if (SVGURIReference::IsKnownAttribute(name)) {
    // TODO(fs): Could be smarter here when 'href' is specified and 'xlink:href'
    // is changed.
    BuildPendingResource();
  } else {
    SVGElement::ParseAttribute(params);
  }
}

bool SVGSMILElement::IsPresentationAttribute(
    const QualifiedName& attr_name) const {
  // Don't map 'fill' to the 'fill' property for animation elements.
  if (attr_name == svg_names::kFillAttr)
    return false;
  return SVGElement::IsPresentationAttribute(attr_name);
}

void SVGSMILElement::CollectStyleForPresentationAttribute(
    const QualifiedName& attr_name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  if (attr_name == svg_names::kFillAttr)
    return;
  SVGElement::CollectStyleForPresentationAttribute(attr_name, value, style);
}

SVGAnimatedPropertyBase* SVGSMILElement::PropertyFromAttribute(
    const QualifiedName& attribute_name) const {
  if (SVGAnimatedPropertyBase* property =
          SVGTests::PropertyFromAttribute(attribute_name)) {
    return property;
  }
  return SVGElement::PropertyFromAttribute(attribute_name);
}

void SVGSMILElement::ConnectConditions() {
  if (conditions_connected_)
    DisconnectConditions();
  for (Condition* condition : conditions_) {
    if (condition->GetType() == Condition::kSyncBase)
      condition->ConnectSyncBase(*this);
    else if (condition->GetType() == Condition::kEventBase)
      condition->ConnectEventBase(*this);
  }
  conditions_connected_ = true;
}

void SVGSMILElement::DisconnectConditions() {
  if (!conditions_connected_)
    return;
  for (Condition* condition : conditions_) {
    if (condition->GetType() == Condition::kSyncBase)
      condition->DisconnectSyncBase(*this);
    else if (condition->GetType() == Condition::kEventBase)
      condition->DisconnectEventBase(*this);
  }
  conditions_connected_ = false;
}

void SVGSMILElement::ClearConditions() {
  DisconnectConditions();
  conditions_.clear();
}

void SVGSMILElement::SetTargetElement(SVGElement* target) {
  if (target == target_element_)
    return;
  WillChangeAnimationTarget();
  target_element_ = target;
  DidChangeAnimationTarget();
}

SMILTime SVGSMILElement::Elapsed() const {
  return time_container_ ? time_container_->Elapsed() : SMILTime();
}

SMILTime SVGSMILElement::BeginTimeForPrioritization(
    SMILTime presentation_time) const {
  if (GetActiveState() == kFrozen) {
    if (interval_.BeginsAfter(presentation_time))
      return previous_interval_.begin;
  }
  return interval_.begin;
}

bool SVGSMILElement::IsHigherPriorityThan(const SVGSMILElement* other,
                                          SMILTime presentation_time) const {
  // FIXME: This should also consider possible timing relations between the
  // elements.
  SMILTime this_begin = BeginTimeForPrioritization(presentation_time);
  SMILTime other_begin = other->BeginTimeForPrioritization(presentation_time);
  if (this_begin == other_begin)
    return DocumentOrderIndex() > other->DocumentOrderIndex();
  return this_begin > other_begin;
}

SMILTime SVGSMILElement::Dur() const {
  if (cached_dur_ != kInvalidCachedTime)
    return cached_dur_;
  const AtomicString& value = FastGetAttribute(svg_names::kDurAttr);
  SMILTime clock_value = ParseClockValue(value);
  return cached_dur_ =
             clock_value <= SMILTime() ? SMILTime::Unresolved() : clock_value;
}

SMILTime SVGSMILElement::RepeatDur() const {
  if (cached_repeat_dur_ != kInvalidCachedTime)
    return cached_repeat_dur_;
  const AtomicString& value = FastGetAttribute(svg_names::kRepeatDurAttr);
  SMILTime clock_value = ParseClockValue(value);
  cached_repeat_dur_ =
      clock_value <= SMILTime() ? SMILTime::Unresolved() : clock_value;
  return cached_repeat_dur_;
}

static SMILRepeatCount ParseRepeatCount(const AtomicString& value) {
  if (value.IsNull())
    return SMILRepeatCount::Unspecified();
  if (value == "indefinite")
    return SMILRepeatCount::Indefinite();
  bool ok;
  double result = value.ToDouble(&ok);
  if (ok && result > 0 && std::isfinite(result))
    return SMILRepeatCount::Numeric(result);
  return SMILRepeatCount::Unspecified();
}

SMILRepeatCount SVGSMILElement::RepeatCount() const {
  if (!cached_repeat_count_.IsValid()) {
    cached_repeat_count_ =
        ParseRepeatCount(FastGetAttribute(svg_names::kRepeatCountAttr));
  }
  DCHECK(cached_repeat_count_.IsValid());
  return cached_repeat_count_;
}

SMILTime SVGSMILElement::MaxValue() const {
  if (cached_max_ != kInvalidCachedTime)
    return cached_max_;
  const AtomicString& value = FastGetAttribute(svg_names::kMaxAttr);
  SMILTime result = ParseClockValue(value);
  return cached_max_ = (result.IsUnresolved() || result <= SMILTime())
                           ? SMILTime::Indefinite()
                           : result;
}

SMILTime SVGSMILElement::MinValue() const {
  if (cached_min_ != kInvalidCachedTime)
    return cached_min_;
  const AtomicString& value = FastGetAttribute(svg_names::kMinAttr);
  SMILTime result = ParseClockValue(value);
  return cached_min_ = (result.IsUnresolved() || result < SMILTime())
                           ? SMILTime()
                           : result;
}

SMILTime SVGSMILElement::SimpleDuration() const {
  return std::min(Dur(), SMILTime::Indefinite());
}

void SVGSMILElement::AddInstanceTime(BeginOrEnd begin_or_end,
                                     SMILTime time,
                                     SMILTimeOrigin origin) {
  auto& list = begin_or_end == kBegin ? begin_times_ : end_times_;
  list.InsertSortedAndUnique(time, origin);
  instance_lists_have_changed_ = true;
}

void SVGSMILElement::AddInstanceTimeAndUpdate(BeginOrEnd begin_or_end,
                                              SMILTime time,
                                              SMILTimeOrigin origin) {
  // Ignore new instance times for 'end' if the element is not active
  // and the origin is script.
  if (begin_or_end == kEnd && GetActiveState() == kInactive &&
      origin == SMILTimeOrigin::kScript)
    return;
  AddInstanceTime(begin_or_end, time, origin);
  InstanceListChanged();
}

SMILTime SVGSMILElement::RepeatingDuration() const {
  // Computing the active duration
  // http://www.w3.org/TR/SMIL2/smil-timing.html#Timing-ComputingActiveDur
  SMILRepeatCount repeat_count = RepeatCount();
  SMILTime repeat_dur = RepeatDur();
  SMILTime simple_duration = SimpleDuration();
  if (!simple_duration ||
      (repeat_dur.IsUnresolved() && repeat_count.IsUnspecified()))
    return simple_duration;
  repeat_dur = std::min(repeat_dur, SMILTime::Indefinite());
  SMILTime repeat_count_duration = simple_duration.Repeat(repeat_count);
  if (!repeat_count_duration.IsUnresolved())
    return std::min(repeat_dur, repeat_count_duration);
  return repeat_dur;
}

SMILTime SVGSMILElement::ResolveActiveEnd(SMILTime resolved_begin) const {
  SMILTime resolved_end = SMILTime::Indefinite();
  if (!end_times_.IsEmpty()) {
    SMILTime next_end = end_times_.NextAfter(resolved_begin);
    if (next_end.IsUnresolved()) {
      // If we have no pending end conditions, don't generate a new interval.
      if (!has_end_event_conditions_)
        return SMILTime::Unresolved();
    } else {
      resolved_end = next_end;
    }
  }
  // Computing the active duration
  // http://www.w3.org/TR/SMIL2/smil-timing.html#Timing-ComputingActiveDur
  SMILTime preliminary_active_duration;
  if (!resolved_end.IsUnresolved() && Dur().IsUnresolved() &&
      RepeatDur().IsUnresolved() && RepeatCount().IsUnspecified())
    preliminary_active_duration = resolved_end - resolved_begin;
  else if (!resolved_end.IsFinite())
    preliminary_active_duration = RepeatingDuration();
  else
    preliminary_active_duration =
        std::min(RepeatingDuration(), resolved_end - resolved_begin);

  SMILTime min_value = MinValue();
  SMILTime max_value = MaxValue();
  if (min_value > max_value) {
    // Ignore both.
    // http://www.w3.org/TR/2001/REC-smil-animation-20010904/#MinMax
    min_value = SMILTime();
    max_value = SMILTime::Indefinite();
  }
  return resolved_begin +
         std::min(max_value, std::max(min_value, preliminary_active_duration));
}

SMILInterval SVGSMILElement::ResolveInterval(SMILTime begin_after,
                                             SMILTime end_after) {
  const bool first = is_waiting_for_first_interval_;
  // Simplified version of the pseudocode in
  // http://www.w3.org/TR/SMIL3/smil-timing.html#q90.
  const size_t kMaxIterations = std::max(begin_times_.size() * 4, 1000000u);
  size_t current_iteration = 0;
  for (auto search_start = begin_times_.begin();
       search_start != begin_times_.end(); ++search_start) {
    // Find the (next) instance time in the 'begin' list that is greater or
    // equal to |begin_after|.
    auto begin_item = std::lower_bound(
        search_start, begin_times_.end(), begin_after,
        [](const SMILTimeWithOrigin& instance_time, const SMILTime& time) {
          return instance_time.Time() < time;
        });
    // If there are no more 'begin' instance times, or we encountered the
    // special value "indefinite" (which doesn't yield an instance time in the
    // 'begin' list), we're done.
    if (begin_item == begin_times_.end() || begin_item->Time().IsIndefinite())
      break;
    SMILTime temp_end = ResolveActiveEnd(begin_item->Time());
    if (temp_end.IsUnresolved())
      break;
    SMILInterval interval(begin_item->Time(), temp_end);
    // Don't allow the interval to end in the past.
    if (temp_end > end_after)
      return interval;
    // The resolved interval was in the past. If it's the first interval being
    // resolved, then update interval state since it could be active (frozen).
    // Skip the interval if it ends before the time container starts
    // (presentation time is 0).
    if (first && temp_end > SMILTime()) {
      interval_ = interval;
      is_waiting_for_first_interval_ = false;
    }
    // Ensure forward progress by only considering the part of the 'begin' list
    // after |begin_item| for the next iteration.
    search_start = begin_item;
    begin_after = temp_end;
    // Debugging signal for crbug.com/1021630.
    CHECK_LT(current_iteration++, kMaxIterations);
  }
  return SMILInterval::Unresolved();
}

void SVGSMILElement::SetNewInterval(const SMILInterval& interval) {
  interval_ = interval;
  NotifyDependentsOnNewInterval(interval_);
}

void SVGSMILElement::SetNewIntervalEnd(SMILTime new_end) {
  interval_.end = new_end;
  NotifyDependentsOnNewInterval(interval_);
}

SMILTime SVGSMILElement::ComputeNextIntervalTime(
    SMILTime presentation_time,
    IncludeRepeats include_repeats) const {
  SMILTime next_interval_time = SMILTime::Unresolved();
  if (interval_.BeginsAfter(presentation_time)) {
    next_interval_time = interval_.begin;
  } else if (interval_.EndsAfter(presentation_time)) {
    SMILTime simple_duration = SimpleDuration();
    if (include_repeats == kIncludeRepeats && simple_duration) {
      SMILTime next_repeat_time = ComputeNextRepeatTime(
          interval_.begin, simple_duration, presentation_time);
      DCHECK(next_repeat_time.IsFinite());
      next_interval_time = std::min(next_repeat_time, interval_.end);
    } else {
      next_interval_time = interval_.end;
    }
  }
  SMILTime next_begin = begin_times_.NextAfter(presentation_time);
  // The special value "indefinite" does not yield an instance time in the
  // begin list, so only consider finite values here.
  if (next_begin.IsFinite())
    next_interval_time = std::min(next_interval_time, next_begin);
  return next_interval_time;
}

void SVGSMILElement::InstanceListChanged() {
  DCHECK(instance_lists_have_changed_);
  SMILTime current_presentation_time =
      time_container_ ? time_container_->LatestUpdatePresentationTime()
                      : SMILTime();
  DCHECK(!current_presentation_time.IsUnresolved());
  const bool was_active = GetActiveState() == kActive;
  UpdateInterval(current_presentation_time);
  // Check active state and reschedule using the time just before the current
  // presentation time. This means that the next animation update will take
  // care of updating the active state and send events as needed.
  SMILTime previous_p
```