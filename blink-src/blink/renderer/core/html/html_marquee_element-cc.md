Response:
Let's break down the thought process for analyzing the `HTMLMarqueeElement.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of this Chromium Blink engine source file, specifically focusing on its relationships with HTML, CSS, JavaScript, logical reasoning (with examples), and common user/programming errors.

2. **Initial Scan and Keywords:**  Quickly scan the code for familiar terms related to HTML, CSS, and JavaScript. Keywords like `HTMLMarqueeElement`, `HTMLElement`, `CSSPropertyID`, `Document`, `Animation`, `JavaScript`, and attribute names like `scrollAmount`, `scrollDelay`, `loop`, `direction`, `behavior` jump out. The copyright notice and includes also provide context.

3. **Core Functionality Identification:**  The name of the file and the class `HTMLMarqueeElement` immediately suggest this code is responsible for implementing the `<marquee>` HTML element. This element is known for its scrolling text behavior.

4. **Deconstruct the Class:** Examine the class members and methods to understand how the marquee functionality is implemented.

   * **Constructor (`HTMLMarqueeElement::HTMLMarqueeElement`)**: Notes the use of `UseCounter` for tracking usage, indicating this is a feature being monitored. The call to `EnsureUserAgentShadowRoot()` is a key detail, hinting at the use of shadow DOM for styling and structure.

   * **`DidAddUserAgentShadowRoot`**: This method constructs the internal structure of the marquee using a shadow DOM. It creates a `<style>` element for basic styling (inline-block, overflow, etc.) and a `<div>` (named `mover_`) that will contain the actual content and be animated. A `<slot>` is used to project the content of the `<marquee>` element into the shadow DOM. This connects the internal implementation with the user-provided HTML content.

   * **Animation Mechanisms (`RequestAnimationFrameCallback`, `AnimationFinished`, `ContinueAnimation`)**: These classes and methods clearly handle the animation logic. `RequestAnimationFrameCallback` uses the browser's animation frame mechanism for smooth updates. `AnimationFinished` is an event handler triggered when an animation cycle completes. `ContinueAnimation` is the core logic that determines if and how the animation should proceed, creating and starting animations using Blink's animation APIs.

   * **Attribute Handling (e.g., `scrollAmount`, `scrollDelay`, `loop`, `GetBehavior`, `GetDirection`)**:  These methods are responsible for retrieving and setting the values of the `<marquee>` element's attributes. Pay attention to default values and error handling (like in `setLoop`).

   * **Presentation Attribute Handling (`IsPresentationAttribute`, `CollectStyleForPresentationAttribute`)**: These methods deal with styling the `<marquee>` element directly using HTML attributes like `bgcolor`, `height`, `width`, etc. This links directly to CSS styling.

   * **Animation Parameters and Transformation (`GetMetrics`, `GetAnimationParameters`, `CreateTransform`)**: These methods calculate the necessary parameters for the animation, such as the distance to scroll and the CSS `transform` values to apply. They consider different `behavior` and `direction` attributes.

   * **`InsertedInto` and `RemovedFrom`**: These lifecycle methods manage the starting and stopping of the animation when the `<marquee>` is added to or removed from the DOM.

5. **Relate to HTML, CSS, and JavaScript:** Now connect the identified functionality to the respective web technologies.

   * **HTML:** The code directly implements the `<marquee>` tag. The attributes it handles (`scrollAmount`, `scrollDelay`, `loop`, `direction`, `behavior`, `bgcolor`, `height`, `width`, etc.) are all standard HTML attributes of the `<marquee>` element.

   * **CSS:** The `DidAddUserAgentShadowRoot` method uses CSS to provide default styling. `CollectStyleForPresentationAttribute` translates HTML presentational attributes into CSS properties. The animation itself manipulates the `transform` CSS property.

   * **JavaScript:**  The interaction with JavaScript is through the browser's animation APIs (requestAnimationFrame, Animation objects, event listeners). While the C++ code *implements* the behavior, JavaScript running in the browser can interact with the `<marquee>` element's properties and methods.

6. **Logical Reasoning and Examples:** Identify the decision-making processes within the code and illustrate them with examples. The `switch` statements in `GetAnimationParameters` based on `behavior` and `direction` are prime candidates. Consider different attribute combinations and their resulting animation behavior.

7. **User/Programming Errors:** Think about how developers might misuse the `<marquee>` element or its attributes. Invalid attribute values (e.g., negative `scrollAmount`), particularly large values that could cause performance issues, and relying on `<marquee>` for critical information display (due to accessibility concerns) are potential errors.

8. **Structure and Refine:** Organize the findings into the requested categories (functionality, HTML/CSS/JS relation, logical reasoning, errors). Use clear and concise language. Provide specific code snippets or attribute examples to support the explanations.

9. **Review and Iterate:** Reread the analysis to ensure accuracy and completeness. Check if all aspects of the request have been addressed. For instance, did I explain the shadow DOM usage adequately?  Are the logical reasoning examples clear?

This step-by-step approach ensures a thorough understanding of the code and its relationship to web technologies, leading to a comprehensive and informative analysis.
好的，让我们来分析一下 `blink/renderer/core/html/html_marquee_element.cc` 这个文件。

**功能概述:**

这个文件定义了 Chromium Blink 引擎中 `HTMLMarqueeElement` 类的实现。`HTMLMarqueeElement` 类对应于 HTML 中的 `<marquee>` 标签，该标签用于创建滚动的文本或图像。

**核心功能点:**

1. **`<marquee>` 标签的实现:**  这是最主要的功能。代码负责解析 `<marquee>` 标签的属性，并控制其在页面上的滚动行为。

2. **滚动动画控制:**  代码实现了控制滚动速度、方向、行为（循环、来回、滑动）以及循环次数的逻辑。它使用 Blink 的动画框架 (`KeyframeEffect`) 来实现平滑的滚动效果。

3. **属性处理:**  文件中的方法（如 `scrollAmount()`, `scrollDelay()`, `loop()`, `GetBehavior()`, `GetDirection()`）负责获取和设置 `<marquee>` 标签的各种属性值。

4. **样式处理:**  代码处理了一些与样式相关的属性，例如 `bgcolor`, `height`, `width` 等，并将它们转换为对应的 CSS 样式。

5. **生命周期管理:**  通过 `InsertedInto()` 和 `RemovedFrom()` 方法，控制当 `<marquee>` 元素被添加到或从 DOM 中移除时，动画的启动和停止。

6. **Shadow DOM 的使用:**  `HTMLMarqueeElement` 使用 Shadow DOM 来封装其内部结构和样式，避免与页面其他部分的样式冲突。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **功能关系:** `HTMLMarqueeElement.cc` 实现了 `<marquee>` HTML 标签的功能。浏览器解析到 `<marquee>` 标签时，会创建 `HTMLMarqueeElement` 的实例来处理它。
    * **举例:**
      ```html
      <marquee direction="right" scrollamount="20">这是一段滚动的文字</marquee>
      ```
      这段 HTML 代码创建了一个向右滚动、每次滚动 20 像素的 `<marquee>` 元素。`HTMLMarqueeElement.cc` 中的代码会读取 `direction` 和 `scrollamount` 属性，并据此控制滚动动画。

* **JavaScript:**
    * **功能关系:** JavaScript 可以通过 DOM API 与 `<marquee>` 元素进行交互，例如获取和设置其属性，以及调用 `start()` 和 `stop()` 方法来控制滚动。
    * **举例:**
      ```javascript
      const marquee = document.querySelector('marquee');
      marquee.start(); // 启动滚动
      marquee.scrollAmount = 10; // 修改滚动速度
      ```
      JavaScript 代码可以获取 `<marquee>` 元素，并调用其 `start()` 方法，这个方法最终会调用 `HTMLMarqueeElement::start()`。设置 `scrollAmount` 属性会触发 `HTMLMarqueeElement::setScrollAmount()` 方法。

* **CSS:**
    * **功能关系:** 虽然 `<marquee>` 标签有一些自身的属性来控制样式，但 CSS 也可以用于设置 `<marquee>` 元素的样式，例如边距、背景色等。此外，`HTMLMarqueeElement.cc` 内部使用了 CSS `transform` 属性来实现滚动动画。
    * **举例:**
      ```css
      marquee {
        background-color: lightblue;
        border: 1px solid black;
        padding: 10px;
      }
      ```
      这段 CSS 代码会给所有的 `<marquee>` 元素设置背景色、边框和内边距。此外，`HTMLMarqueeElement.cc` 在 `DidAddUserAgentShadowRoot` 中设置了内部元素的 CSS 属性，例如 `display`, `overflow`, `white-space` 和 `will-change: transform;`。滚动动画的核心是通过改变内部 `div` 元素的 `transform` 属性实现的。

**逻辑推理及假设输入与输出:**

假设我们有以下 `<marquee>` 元素：

```html
<marquee direction="left" behavior="alternate" scrollamount="10" loop="3">内容</marquee>
```

* **假设输入:**
    * 元素被添加到 DOM 中。
    * `direction` 属性为 "left"。
    * `behavior` 属性为 "alternate"。
    * `scrollamount` 属性为 "10"。
    * `loop` 属性为 "3"。

* **逻辑推理:**
    1. 当元素被添加到 DOM 时，`InsertedInto()` 方法会被调用，进而调用 `start()` 方法启动动画。
    2. `GetDirection()` 返回 `kLeft`。
    3. `GetBehavior()` 返回 `kAlternate`。
    4. `scrollAmount()` 返回 `10`。
    5. `loop()` 返回 `3`。
    6. `ContinueAnimation()` 会根据这些属性计算动画参数。对于 `alternate` 行为，动画会在左右边界之间来回滚动。
    7. 每次滚动的距离取决于 `<marquee>` 元素的宽度和内容的宽度。
    8. 动画会执行 3 次来回滚动 (loop=3)。
    9. `CreateEffectModel()` 会创建 `transform` 动画，在水平方向上来回移动内部的 `mover_` 元素。

* **假设输出:**
    * 文本 "内容" 会在 `<marquee>` 元素内部从右向左滚动，到达左边界后会反向从左向右滚动。
    * 每次滚动的步长与 `scrollamount` 有关，影响滚动的速度。
    * 整个滚动动画会重复 3 次。

**用户或编程常见的使用错误举例说明:**

1. **不合理的属性值:**
   * **错误:** 设置 `scrollamount` 为负数或非常大的值。
   * **后果:** 负数可能导致意外行为，过大的值可能导致滚动过快，用户难以阅读内容，并可能影响性能。
   * **代码体现:** `scrollAmount()` 方法中会进行非负整数的校验，但如果提供超出范围的数值，可能会返回默认值，或者在后续的动画计算中产生问题。

2. **依赖 `<marquee>` 实现关键信息展示:**
   * **错误:**  使用 `<marquee>` 来展示重要的、用户必须阅读的信息。
   * **后果:** 滚动的内容可能被用户错过，特别是当滚动速度过快时，会影响信息的可访问性。现代 Web 开发中，通常有更好的方式来呈现重要信息。
   * **代码体现:** 虽然代码实现了 `<marquee>` 的功能，但并没有对这种使用场景进行限制或警告。

3. **过度使用 `<marquee>` 导致页面混乱:**
   * **错误:** 在页面上放置过多的 `<marquee>` 元素。
   * **后果:**  大量的滚动文本会分散用户的注意力，使页面显得杂乱无章，影响用户体验。
   * **代码体现:**  `HTMLMarqueeElement.cc` 只是实现了单个 `<marquee>` 元素的功能，并不会限制页面上 `<marquee>` 元素的数量。

4. **尝试用 CSS 完全替代 `<marquee>` 的滚动效果:**
   * **错误:**  虽然可以用 CSS 动画模拟一些简单的滚动效果，但 `<marquee>` 标签的某些特定行为（例如 `alternate`）可能需要复杂的 CSS 实现，并且与原生 `<marquee>` 的行为可能存在细微差异。
   * **代码体现:**  `HTMLMarqueeElement.cc` 提供了对 `<marquee>` 特有属性的支持，例如 `behavior`，这表明 CSS 动画可能无法完全覆盖 `<marquee>` 的所有功能。

5. **忘记 `<marquee>` 元素的可访问性问题:**
   * **错误:**  没有考虑到滚动文本可能给某些用户带来阅读困难，特别是那些有认知障碍或注意力缺陷的用户。
   * **后果:**  降低了网站的可访问性。
   * **代码体现:**  虽然 Blink 引擎实现了 `<marquee>` 的功能，但开发者有责任确保其使用符合可访问性标准。现代 Web 开发中，通常推荐使用更可访问的替代方案。

总而言之，`blink/renderer/core/html/html_marquee_element.cc` 文件是 Chromium 引擎中实现 `<marquee>` 标签核心功能的代码。它涉及到 HTML 结构的解析、CSS 样式的应用以及使用 Blink 动画框架来驱动滚动效果。理解这个文件有助于深入了解浏览器如何渲染和处理这个古老的 HTML 元素。

Prompt: 
```
这是目录为blink/renderer/core/html/html_marquee_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 * Copyright (C) 2003, 2007, 2010 Apple Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "third_party/blink/renderer/core/html/html_marquee_element.h"

#include <cstdlib>

#include "third_party/blink/renderer/bindings/core/v8/v8_html_marquee_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_keyframe_effect_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_optional_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_string_unrestricteddouble.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/animation/string_keyframe.h"
#include "third_party/blink/renderer/core/animation/timing_input.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/frame_request_callback_collection.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

HTMLMarqueeElement::HTMLMarqueeElement(Document& document)
    : HTMLElement(html_names::kMarqueeTag, document) {
  UseCounter::Count(document, WebFeature::kHTMLMarqueeElement);
  EnsureUserAgentShadowRoot();
}

void HTMLMarqueeElement::DidAddUserAgentShadowRoot(ShadowRoot& shadow_root) {
  auto* style = MakeGarbageCollected<HTMLStyleElement>(GetDocument());
  style->setTextContent(
      ":host { display: inline-block; overflow: hidden;"
      "text-align: initial; white-space: nowrap; }"
      ":host([direction=\"up\"]), :host([direction=\"down\"]) { overflow: "
      "initial; overflow-y: hidden; white-space: initial; }"
      ":host > div { will-change: transform; }");
  shadow_root.AppendChild(style);

  auto* mover = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  shadow_root.AppendChild(mover);

  mover->AppendChild(MakeGarbageCollected<HTMLSlotElement>(GetDocument()));
  mover_ = mover;
}

class HTMLMarqueeElement::RequestAnimationFrameCallback final
    : public FrameCallback {
 public:
  explicit RequestAnimationFrameCallback(HTMLMarqueeElement* marquee)
      : marquee_(marquee) {}
  RequestAnimationFrameCallback(const RequestAnimationFrameCallback&) = delete;
  RequestAnimationFrameCallback& operator=(
      const RequestAnimationFrameCallback&) = delete;

  void Invoke(double) override {
    marquee_->continue_callback_request_id_ = 0;
    marquee_->ContinueAnimation();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(marquee_);
    FrameCallback::Trace(visitor);
  }

 private:
  Member<HTMLMarqueeElement> marquee_;
};

class HTMLMarqueeElement::AnimationFinished final : public NativeEventListener {
 public:
  explicit AnimationFinished(HTMLMarqueeElement* marquee) : marquee_(marquee) {}

  void Invoke(ExecutionContext*, Event*) override {
    ++marquee_->loop_count_;
    marquee_->start();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(marquee_);
    NativeEventListener::Trace(visitor);
  }

 private:
  Member<HTMLMarqueeElement> marquee_;
};

Node::InsertionNotificationRequest HTMLMarqueeElement::InsertedInto(
    ContainerNode& insertion_point) {
  HTMLElement::InsertedInto(insertion_point);

  if (isConnected())
    start();

  return kInsertionDone;
}

void HTMLMarqueeElement::RemovedFrom(ContainerNode& insertion_point) {
  HTMLElement::RemovedFrom(insertion_point);
  if (insertion_point.isConnected()) {
    stop();
  }
}

bool HTMLMarqueeElement::IsHorizontal() const {
  Direction direction = GetDirection();
  return direction != kUp && direction != kDown;
}

unsigned HTMLMarqueeElement::scrollAmount() const {
  unsigned scroll_amount = 0;
  AtomicString value = FastGetAttribute(html_names::kScrollamountAttr);
  if (value.empty() || !ParseHTMLNonNegativeInteger(value, scroll_amount) ||
      scroll_amount > 0x7fffffffu)
    return kDefaultScrollAmount;
  return scroll_amount;
}

void HTMLMarqueeElement::setScrollAmount(unsigned value) {
  SetUnsignedIntegralAttribute(html_names::kScrollamountAttr, value,
                               kDefaultScrollAmount);
}

unsigned HTMLMarqueeElement::scrollDelay() const {
  unsigned scroll_delay = 0;
  AtomicString value = FastGetAttribute(html_names::kScrolldelayAttr);
  if (value.empty() || !ParseHTMLNonNegativeInteger(value, scroll_delay) ||
      scroll_delay > 0x7fffffffu)
    return kDefaultScrollDelayMS;
  return scroll_delay;
}

void HTMLMarqueeElement::setScrollDelay(unsigned value) {
  SetUnsignedIntegralAttribute(html_names::kScrolldelayAttr, value,
                               kDefaultScrollDelayMS);
}

int HTMLMarqueeElement::loop() const {
  bool ok;
  int loop = FastGetAttribute(html_names::kLoopAttr).ToInt(&ok);
  if (!ok || loop <= 0)
    return kDefaultLoopLimit;
  return loop;
}

void HTMLMarqueeElement::setLoop(int value, ExceptionState& exception_state) {
  if (value <= 0 && value != -1) {
    exception_state.ThrowDOMException(DOMExceptionCode::kIndexSizeError,
                                      "The provided value (" +
                                          String::Number(value) +
                                          ") is neither positive nor -1.");
    return;
  }
  SetIntegralAttribute(html_names::kLoopAttr, value);
}

void HTMLMarqueeElement::start() {
  if (continue_callback_request_id_)
    return;

  RequestAnimationFrameCallback* callback =
      MakeGarbageCollected<RequestAnimationFrameCallback>(this);
  continue_callback_request_id_ = GetDocument().RequestAnimationFrame(callback);
}

void HTMLMarqueeElement::stop() {
  if (continue_callback_request_id_) {
    GetDocument().CancelAnimationFrame(continue_callback_request_id_);
    continue_callback_request_id_ = 0;
    return;
  }

  if (player_)
    player_->pause();
}

bool HTMLMarqueeElement::IsPresentationAttribute(
    const QualifiedName& attr) const {
  if (attr == html_names::kBgcolorAttr || attr == html_names::kHeightAttr ||
      attr == html_names::kHspaceAttr || attr == html_names::kVspaceAttr ||
      attr == html_names::kWidthAttr) {
    return true;
  }
  return HTMLElement::IsPresentationAttribute(attr);
}

void HTMLMarqueeElement::CollectStyleForPresentationAttribute(
    const QualifiedName& attr,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  if (attr == html_names::kBgcolorAttr) {
    AddHTMLColorToStyle(style, CSSPropertyID::kBackgroundColor, value);
  } else if (attr == html_names::kHeightAttr) {
    AddHTMLLengthToStyle(style, CSSPropertyID::kHeight, value);
  } else if (attr == html_names::kHspaceAttr) {
    AddHTMLLengthToStyle(style, CSSPropertyID::kMarginLeft, value);
    AddHTMLLengthToStyle(style, CSSPropertyID::kMarginRight, value);
  } else if (attr == html_names::kVspaceAttr) {
    AddHTMLLengthToStyle(style, CSSPropertyID::kMarginTop, value);
    AddHTMLLengthToStyle(style, CSSPropertyID::kMarginBottom, value);
  } else if (attr == html_names::kWidthAttr) {
    AddHTMLLengthToStyle(style, CSSPropertyID::kWidth, value);
  } else {
    HTMLElement::CollectStyleForPresentationAttribute(attr, value, style);
  }
}

StringKeyframeEffectModel* HTMLMarqueeElement::CreateEffectModel(
    const AnimationParameters& parameters) {
  StyleSheetContents* style_sheet_contents =
      mover_->GetDocument().ElementSheet().Contents();
  MutableCSSPropertyValueSet::SetResult set_result;

  SecureContextMode secure_context_mode =
      mover_->GetExecutionContext()->GetSecureContextMode();

  StringKeyframeVector keyframes;
  auto* keyframe1 = MakeGarbageCollected<StringKeyframe>();
  set_result = keyframe1->SetCSSPropertyValue(
      CSSPropertyID::kTransform, parameters.transform_begin,
      secure_context_mode, style_sheet_contents);
  DCHECK_NE(MutableCSSPropertyValueSet::kParseError, set_result);
  keyframes.push_back(keyframe1);

  auto* keyframe2 = MakeGarbageCollected<StringKeyframe>();
  set_result = keyframe2->SetCSSPropertyValue(
      CSSPropertyID::kTransform, parameters.transform_end, secure_context_mode,
      style_sheet_contents);
  DCHECK(set_result != MutableCSSPropertyValueSet::kParseError);
  keyframes.push_back(keyframe2);

  return MakeGarbageCollected<StringKeyframeEffectModel>(
      keyframes, EffectModel::kCompositeReplace,
      LinearTimingFunction::Shared());
}

void HTMLMarqueeElement::ContinueAnimation() {
  if (!ShouldContinue())
    return;

  if (player_ && player_->CalculateAnimationPlayState() ==
                     V8AnimationPlayState::Enum::kPaused) {
    player_->play();
    return;
  }

  AnimationParameters parameters = GetAnimationParameters();
  int scroll_delay = scrollDelay();
  int scroll_amount = scrollAmount();

  if (scroll_delay < kMinimumScrollDelayMS &&
      !FastHasAttribute(html_names::kTruespeedAttr))
    scroll_delay = kDefaultScrollDelayMS;
  double duration = 0;
  if (scroll_amount)
    duration = parameters.distance * scroll_delay / scroll_amount;
  if (duration <= 0)
    return;

  StringKeyframeEffectModel* effect_model = CreateEffectModel(parameters);
  Timing timing;
  OptionalEffectTiming* effect_timing = OptionalEffectTiming::Create();
  effect_timing->setFill("forwards");
  effect_timing->setDuration(
      MakeGarbageCollected<V8UnionCSSNumericValueOrStringOrUnrestrictedDouble>(
          duration));
  TimingInput::Update(timing, effect_timing, nullptr, ASSERT_NO_EXCEPTION);

  auto* keyframe_effect =
      MakeGarbageCollected<KeyframeEffect>(mover_, effect_model, timing);
  Animation* player = mover_->GetDocument().Timeline().Play(keyframe_effect);
  player->setId(g_empty_string);
  player->setOnfinish(MakeGarbageCollected<AnimationFinished>(this));

  player_ = player;
}

bool HTMLMarqueeElement::ShouldContinue() {
  int loop_count = loop();

  // By default, slide loops only once.
  if (loop_count <= 0 && GetBehavior() == kSlide)
    loop_count = 1;

  if (loop_count <= 0)
    return true;
  return loop_count_ < loop_count;
}

HTMLMarqueeElement::Behavior HTMLMarqueeElement::GetBehavior() const {
  const AtomicString& behavior = FastGetAttribute(html_names::kBehaviorAttr);
  if (EqualIgnoringASCIICase(behavior, "alternate"))
    return kAlternate;
  if (EqualIgnoringASCIICase(behavior, "slide"))
    return kSlide;
  return kScroll;
}

HTMLMarqueeElement::Direction HTMLMarqueeElement::GetDirection() const {
  const AtomicString& direction = FastGetAttribute(html_names::kDirectionAttr);
  if (EqualIgnoringASCIICase(direction, "down"))
    return kDown;
  if (EqualIgnoringASCIICase(direction, "up"))
    return kUp;
  if (EqualIgnoringASCIICase(direction, "right"))
    return kRight;
  return kLeft;
}

HTMLMarqueeElement::Metrics HTMLMarqueeElement::GetMetrics() {
  Metrics metrics;
  CSSStyleDeclaration* marquee_style =
      GetDocument().domWindow()->getComputedStyle(this);
  // For marquees that are declared inline, getComputedStyle returns "auto" for
  // width and height. Setting all the metrics to zero disables animation for
  // inline marquees.
  if (marquee_style->getPropertyValue("width") == "auto" &&
      marquee_style->getPropertyValue("height") == "auto") {
    metrics.content_height = 0;
    metrics.content_width = 0;
    metrics.marquee_width = 0;
    metrics.marquee_height = 0;
    return metrics;
  }

  if (IsHorizontal()) {
    mover_->style()->setProperty(GetExecutionContext(), "width",
                                 "-webkit-max-content", "important",
                                 ASSERT_NO_EXCEPTION);
  } else {
    mover_->style()->setProperty(GetExecutionContext(), "height",
                                 "-webkit-max-content", "important",
                                 ASSERT_NO_EXCEPTION);
  }
  CSSStyleDeclaration* mover_style =
      GetDocument().domWindow()->getComputedStyle(mover_);

  metrics.content_width = mover_style->getPropertyValue("width").ToDouble();
  metrics.content_height = mover_style->getPropertyValue("height").ToDouble();
  metrics.marquee_width = marquee_style->getPropertyValue("width").ToDouble();
  metrics.marquee_height = marquee_style->getPropertyValue("height").ToDouble();

  if (IsHorizontal()) {
    mover_->style()->removeProperty("width", ASSERT_NO_EXCEPTION);
  } else {
    mover_->style()->removeProperty("height", ASSERT_NO_EXCEPTION);
  }

  return metrics;
}

HTMLMarqueeElement::AnimationParameters
HTMLMarqueeElement::GetAnimationParameters() {
  AnimationParameters parameters;
  Metrics metrics = GetMetrics();

  double total_width = metrics.marquee_width + metrics.content_width;
  double total_height = metrics.marquee_height + metrics.content_height;

  double inner_width = metrics.marquee_width - metrics.content_width;
  double inner_height = metrics.marquee_height - metrics.content_height;

  switch (GetBehavior()) {
    case kAlternate:
      switch (GetDirection()) {
        case kRight:
          parameters.transform_begin =
              CreateTransform(inner_width >= 0 ? 0 : inner_width);
          parameters.transform_end =
              CreateTransform(inner_width >= 0 ? inner_width : 0);
          parameters.distance = std::abs(inner_width);
          break;
        case kUp:
          parameters.transform_begin =
              CreateTransform(inner_height >= 0 ? inner_height : 0);
          parameters.transform_end =
              CreateTransform(inner_height >= 0 ? 0 : inner_height);
          parameters.distance = std::abs(inner_height);
          break;
        case kDown:
          parameters.transform_begin =
              CreateTransform(inner_height >= 0 ? 0 : inner_height);
          parameters.transform_end =
              CreateTransform(inner_height >= 0 ? inner_height : 0);
          parameters.distance = std::abs(inner_height);
          break;
        case kLeft:
        default:
          parameters.transform_begin =
              CreateTransform(inner_width >= 0 ? inner_width : 0);
          parameters.transform_end =
              CreateTransform(inner_width >= 0 ? 0 : inner_width);
          parameters.distance = std::abs(inner_width);
      }

      if (loop_count_ % 2)
        std::swap(parameters.transform_begin, parameters.transform_end);
      break;
    case kSlide:
      switch (GetDirection()) {
        case kRight:
          parameters.transform_begin = CreateTransform(-metrics.content_width);
          parameters.transform_end = CreateTransform(inner_width);
          parameters.distance = metrics.marquee_width;
          break;
        case kUp:
          parameters.transform_begin = CreateTransform(metrics.marquee_height);
          parameters.transform_end = "translateY(0)";
          parameters.distance = metrics.marquee_height;
          break;
        case kDown:
          parameters.transform_begin = CreateTransform(-metrics.content_height);
          parameters.transform_end = CreateTransform(inner_height);
          parameters.distance = metrics.marquee_height;
          break;
        case kLeft:
        default:
          parameters.transform_begin = CreateTransform(metrics.marquee_width);
          parameters.transform_end = "translateX(0)";
          parameters.distance = metrics.marquee_width;
      }
      break;
    case kScroll:
    default:
      switch (GetDirection()) {
        case kRight:
          parameters.transform_begin = CreateTransform(-metrics.content_width);
          parameters.transform_end = CreateTransform(metrics.marquee_width);
          parameters.distance = total_width;
          break;
        case kUp:
          parameters.transform_begin = CreateTransform(metrics.marquee_height);
          parameters.transform_end = CreateTransform(-metrics.content_height);
          parameters.distance = total_height;
          break;
        case kDown:
          parameters.transform_begin = CreateTransform(-metrics.content_height);
          parameters.transform_end = CreateTransform(metrics.marquee_height);
          parameters.distance = total_height;
          break;
        case kLeft:
        default:
          parameters.transform_begin = CreateTransform(metrics.marquee_width);
          parameters.transform_end = CreateTransform(-metrics.content_width);
          parameters.distance = total_width;
      }
      break;
  }

  return parameters;
}

AtomicString HTMLMarqueeElement::CreateTransform(double value) const {
  char axis = IsHorizontal() ? 'X' : 'Y';
  return String::Format("translate%c(", axis) +
         String::NumberToStringECMAScript(value) + "px)";
}

void HTMLMarqueeElement::Trace(Visitor* visitor) const {
  visitor->Trace(mover_);
  visitor->Trace(player_);
  HTMLElement::Trace(visitor);
}

}  // namespace blink

"""

```