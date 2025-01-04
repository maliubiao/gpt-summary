Response: Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request is to analyze the functionality of `web_gesture_event.cc` within the Chromium Blink engine, specifically focusing on its relationship to web technologies (HTML, CSS, JavaScript), logical reasoning with input/output examples, and common usage errors.

2. **Initial Code Scan (High-Level):**
   - Notice the `#include` directives. This immediately tells us the code interacts with other parts of the Blink/Chromium system (`WebInputEvent`, `gfx::Transform`, potentially UI elements).
   - Identify the main class: `WebGestureEvent`. This is the central data structure being manipulated.
   - Recognize namespaces: `blink` and an anonymous namespace. This helps in understanding the scope and organization.

3. **Function-by-Function Analysis (Core Logic):**  Go through each function and understand its purpose:
   - `IsContinuousGestureEvent`:  Simple check for specific event types.
   - `GetTransformForEvent`:  Calculates a transformation matrix based on scroll or pinch events. This hints at how gestures manipulate the visual layout.
   - `Clone`:  Creates a copy of the event. Standard practice for event handling.
   - `CanCoalesce`: Determines if two gesture events of the same type can be merged. This is important for performance and responsiveness, preventing a flood of similar events. Pay close attention to the conditions for coalescing scroll and pinch events.
   - `Coalesce`:  Merges two compatible gesture events, updating the delta or scale.
   - `GetScrollInputType`:  Maps the gesture source to a UI scroll input type. This connects the low-level gesture input to higher-level UI concepts.
   - `DeltaXInRootFrame`, `DeltaYInRootFrame`:  Calculates the scroll delta in the root frame's coordinate system, considering potential scaling.
   - `DeltaUnits`, `InertialPhase`, `Synthetic`:  Accessors for specific gesture event properties.
   - `TapAreaInRootFrame`:  Calculates the area of a tap gesture, adjusting for scaling.
   - `PositionInRootFrame`:  Calculates the position of the gesture in the root frame's coordinate system, accounting for transformations.
   - `TapCount`, `TapDownCount`: Accessors for tap-related properties.
   - `ApplyTouchAdjustment`: Adjusts the event's position based on root frame coordinates. This is crucial for accurate hit testing.
   - `FlattenTransform`: Applies any accumulated transformation to the event's data and resets the transform. This is likely done before dispatching the event to the renderer.
   - `IsCompatibleScrollorPinch`: Checks if two touchscreen scroll or pinch events can be logically combined.
   - `CoalesceScrollAndPinch`:  Handles the complex logic of combining concurrent scroll and pinch gestures on touchscreens. This is a key area related to smooth zooming and panning.
   - `GenerateInjectedScrollbarGestureScroll`: Creates a synthetic scroll event mimicking scrollbar interaction.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):**
   - **JavaScript:**  Gesture events are the foundation for many interactive JavaScript functionalities. JavaScript code listens for these events (e.g., `addEventListener('wheel', ...)`, `addEventListener('touchstart', ...)`, `addEventListener('gesturestart', ...)` although the latter is deprecated and touch events are more common now for pinch). The properties of `WebGestureEvent` directly influence the data available in the JavaScript event objects.
   - **HTML:**  The target element of a gesture event (determined through hit-testing) influences how the browser reacts. The structure of the HTML document determines the rendering tree and thus the target of these events.
   - **CSS:**  CSS transforms and scrolling properties are directly affected by gesture events. For example, a pinch gesture can trigger a CSS `transform: scale()` on an element, or a scroll gesture can change the `scrollTop` and `scrollLeft` properties. The `frame_scale_` member and related calculations directly connect to CSS zoom and transforms.

5. **Identify Logical Reasoning and Provide Examples:**
   - Focus on functions that perform transformations or comparisons: `CanCoalesce`, `Coalesce`, `GetTransformForEvent`, `CoalesceScrollAndPinch`.
   - Create simple scenarios to illustrate the input and output. For instance, with `CanCoalesce`, two identical scroll events can be merged, resulting in a larger delta.

6. **Consider Common Usage Errors:**
   - Think about how developers might misuse or misunderstand these events:
     - Assuming pixel-perfect anchor points for pinch coalescing.
     - Not accounting for `frame_scale_` when performing calculations in JavaScript.
     - Incorrectly interpreting the meaning of delta values (e.g., assuming they are always in pixels).

7. **Structure the Analysis:** Organize the findings logically:
   - Start with a general overview of the file's purpose.
   - Detail the functionality of each key function.
   - Clearly connect the concepts to JavaScript, HTML, and CSS with specific examples.
   - Provide input/output examples for logical functions.
   - Highlight potential usage errors with concrete illustrations.

8. **Refine and Review:**  Read through the analysis to ensure clarity, accuracy, and completeness. Check for any jargon that might need explanation. Make sure the examples are easy to understand.

Self-Correction/Refinement during the process:

- **Initial thought:**  Focus heavily on the event types. **Correction:** Realize the data within the event structures (like `data.scroll_update`) is equally important.
- **Initial thought:**  Only consider direct event listeners in JavaScript. **Correction:**  Acknowledge that browser behaviors (like pinch-to-zoom) also rely on these events internally.
- **Initial thought:**  Provide very technical C++ examples. **Correction:** Frame the examples in terms of user interactions and the resulting web page behavior. This makes it more accessible.
- **Initial thought:** List every single function. **Correction:** Focus on the most significant functions that illustrate the core purpose and connections to web technologies.

By following this structured approach, combining code understanding with knowledge of web technologies and common development pitfalls, a comprehensive and helpful analysis can be produced.
这个文件 `blink/common/input/web_gesture_event.cc` 定义了 `blink::WebGestureEvent` 类及其相关的功能。`WebGestureEvent` 类是 Chromium Blink 引擎中用于表示各种触摸和鼠标手势事件的关键数据结构。它封装了关于手势的信息，例如手势类型、位置、时间戳、以及特定于手势类型的数据。

以下是该文件的主要功能：

**1. 定义和表示手势事件:**

* **`WebGestureEvent` 类:**  这是核心类，用于表示各种手势事件，例如滚动（scroll）、缩放（pinch）、轻触（tap）、长按（long press）、滑动（swipe）等。
* **不同的手势类型:** 文件中通过枚举 `WebGestureEvent::Type` 定义了各种手势类型，例如 `kGestureScrollBegin`, `kGestureScrollUpdate`, `kGesturePinchBegin`, `kGestureTap`, `kGestureLongPress` 等。
* **手势数据:** `WebGestureEvent` 类内部包含一个联合体 `data`，用于存储不同手势类型所需的特定数据。例如，`scroll_update` 结构体存储滚动的偏移量，`pinch_update` 结构体存储缩放比例。

**2. 手势事件的创建和复制:**

* **`Clone()` 方法:** 提供了一种创建 `WebGestureEvent` 对象副本的方式。这在事件处理流程中可能用于传递或修改事件而不影响原始事件。

**3. 手势事件的合并 (Coalescing):**

* **`CanCoalesce()` 方法:**  判断当前手势事件是否可以与另一个手势事件合并。合并通常用于优化性能，避免处理过多的相似事件。例如，连续的滚动事件或缩放事件可以被合并成一个事件。
* **`Coalesce()` 方法:**  实际执行手势事件的合并操作。对于滚动事件，它会累加滚动的偏移量；对于缩放事件，它会累乘缩放比例。

**4. 获取手势事件的属性:**

* **`GetScrollInputType()` 方法:**  根据手势的来源设备（触摸屏、触摸板等）返回对应的滚动输入类型。
* **`DeltaXInRootFrame()`, `DeltaYInRootFrame()` 方法:**  返回相对于根框架的滚动偏移量。这考虑了可能的框架缩放。
* **`DeltaUnits()` 方法:** 返回滚动偏移的单位（例如，按像素滚动、按行滚动、按百分比滚动）。
* **`InertialPhase()` 方法:** 返回滚动的惯性阶段（开始、更新、结束）。
* **`Synthetic()` 方法:**  指示手势事件是否是合成生成的。
* **`TapAreaInRootFrame()` 方法:**  返回轻触区域的大小（考虑了框架缩放）。
* **`PositionInRootFrame()` 方法:** 返回手势事件在根框架中的位置（考虑了框架平移和缩放）。
* **`TapCount()`, `TapDownCount()` 方法:**  返回轻触或按下的次数。

**5. 手势事件的变换和调整:**

* **`ApplyTouchAdjustment()` 方法:**  用于调整手势事件的位置，通常用于处理触摸事件的精确目标定位。
* **`FlattenTransform()` 方法:**  将应用于手势事件的框架变换（平移和缩放）应用到事件的数据中，并重置变换。这确保了事件数据反映了最终的坐标。

**6. 复杂的触摸屏滚动和缩放合并逻辑:**

* **`IsCompatibleScrollorPinch()` 方法:**  判断两个触摸屏上的滚动或缩放事件是否兼容，可以进行更复杂的合并。
* **`CoalesceScrollAndPinch()` 方法:**  实现了一种更高级的合并策略，用于处理在触摸屏上同时发生的滚动和缩放手势。它可以将两个连续的滚动/缩放事件合并成一个滚动事件和一个缩放事件，以更精确地反映用户的操作。

**7. 生成注入的滚动条手势事件:**

* **`GenerateInjectedScrollbarGestureScroll()` 方法:**  用于创建模拟的滚动条手势事件。这在某些情况下，例如通过 JavaScript API 触发滚动时，可能需要模拟用户通过滚动条进行滚动。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`WebGestureEvent` 是 Blink 引擎处理用户交互的核心部分，它直接关联到网页的交互行为，因此与 JavaScript, HTML, 和 CSS 都有密切关系。

* **JavaScript:**
    * **事件监听:** JavaScript 代码可以使用 `addEventListener` 监听各种手势事件，例如 `touchstart`, `touchmove`, `touchend`, `wheel` (虽然 `wheel` 事件不是直接的 `WebGestureEvent`，但其背后的处理逻辑会涉及到手势识别)。
    * **事件对象:** 当手势发生时，浏览器会创建一个对应的事件对象传递给 JavaScript。对于触摸事件，虽然 JavaScript 层面看到的是 `TouchEvent`，但底层 Blink 引擎会将其转换为 `WebGestureEvent` 进行处理。对于鼠标滚轮事件 (`wheel`)，虽然它有自己的事件类型，但在某些情况下也会触发相关的 `WebGestureEvent`，特别是对于触摸板上的平滑滚动。
    * **操作网页:** JavaScript 可以根据接收到的手势事件信息来操作网页的 DOM 结构、修改 CSS 样式、执行动画等。
    * **举例:**
        ```javascript
        document.addEventListener('touchstart', function(event) {
          console.log('Touch start at:', event.touches[0].clientX, event.touches[0].clientY);
        });

        document.addEventListener('wheel', function(event) {
          console.log('Scroll delta X:', event.deltaX, 'Y:', event.deltaY);
        });
        ```
        当用户在屏幕上触摸或使用鼠标滚轮时，这些事件监听器会被触发，并打印出相关的信息，这些信息最终都来源于底层的 `WebGestureEvent` 数据。

* **HTML:**
    * **交互元素:** HTML 定义了网页的结构和交互元素，例如按钮、链接、可滚动区域等。这些元素是手势事件的目标。
    * **事件目标:** 当用户在一个 HTML 元素上执行手势时，该元素会成为手势事件的目标。`WebGestureEvent` 中包含了事件发生的位置信息，可以用来判断事件的目标元素。
    * **举例:** 一个 `<div>` 元素设置了滚动溢出 (`overflow: auto;`)，当用户在该 `<div>` 元素上进行滑动操作时，会触发 `WebGestureEvent`，导致该 `<div>` 元素的内容滚动。

* **CSS:**
    * **视觉效果和布局:** CSS 用于定义网页的视觉效果和布局。手势事件可以触发 CSS 属性的变化，从而实现动态效果。
    * **滚动和缩放:** CSS 的 `overflow`, `scroll-behavior`, `transform` 等属性与手势操作密切相关。例如，通过 CSS `transform: scale()` 可以实现元素的缩放效果，而 pinch 手势事件正是驱动这种效果的基础。
    * **举例:**
        ```css
        .zoomable {
          transition: transform 0.3s ease-in-out;
        }
        ```
        当 JavaScript 接收到 pinch 手势事件并修改 `.zoomable` 元素的 `transform` 属性时，CSS 的 `transition` 效果会使缩放过程平滑过渡。底层是通过 `WebGestureEvent` 传递的缩放信息来实现的。

**逻辑推理的假设输入与输出举例:**

**场景：合并两个连续的触摸屏滚动事件**

**假设输入:**

1. **`last_event` (类型: `kGestureScrollUpdate`):**
   * `TimeStamp`: T1
   * `SourceDevice`: `kTouchscreen`
   * `modifiers`: 0
   * `data.scroll_update.delta_x`: 10
   * `data.scroll_update.delta_y`: 0

2. **`new_event` (类型: `kGestureScrollUpdate`):**
   * `TimeStamp`: T2 (T2 > T1)
   * `SourceDevice`: `kTouchscreen`
   * `modifiers`: 0
   * `data.scroll_update.delta_x`: 5
   * `data.scroll_update.delta_y`: -2

**逻辑推理 (基于 `Coalesce()` 方法):**

由于 `last_event` 和 `new_event` 都是 `kGestureScrollUpdate` 类型的触摸屏事件，且具有相同的 `modifiers` 和 `SourceDevice`，因此 `CanCoalesce()` 会返回 `true`。

`Coalesce()` 方法会被调用，将 `new_event` 合并到 `last_event` 中。

**输出 (合并后的 `last_event`):**

* `TimeStamp`: T1 (合并通常保留第一个事件的时间戳)
* `SourceDevice`: `kTouchscreen`
* `modifiers`: 0
* `data.scroll_update.delta_x`: 10 + 5 = 15
* `data.scroll_update.delta_y`: 0 + (-2) = -2

**场景：合并两个靠近的 Pinch 缩放事件**

**假设输入:**

1. **`last_event` (类型: `kGesturePinchUpdate`):**
   * `TimeStamp`: T1
   * `SourceDevice`:  (任意)
   * `modifiers`: 0
   * `PositionInWidget`: (100, 100)
   * `data.pinch_update.scale`: 1.1

2. **`new_event` (类型: `kGesturePinchUpdate`):**
   * `TimeStamp`: T2 (T2 > T1)
   * `SourceDevice`: (与 `last_event` 相同)
   * `modifiers`: 0
   * `PositionInWidget`: (101, 99)  // 靠近 last_event 的位置
   * `data.pinch_update.scale`: 1.2

**逻辑推理 (基于 `CanCoalesce()` 和 `Coalesce()`):**

由于两个事件都是 `kGesturePinchUpdate` 类型，并且它们在 widget 中的位置足够接近（满足 `kAnchorTolerance`），因此 `CanCoalesce()` 返回 `true`。

`Coalesce()` 方法会被调用。

**输出 (合并后的 `last_event`):**

* `TimeStamp`: T1
* `SourceDevice`: (与输入相同)
* `modifiers`: 0
* `PositionInWidget`: (保持不变，合并通常不改变位置)
* `data.pinch_update.scale`: 1.1 * 1.2 = 1.32

**用户或编程常见的使用错误举例:**

1. **错误地假设合并后的事件具有最新的时间戳:** 开发者可能会错误地认为合并后的事件时间戳会更新为最后一个合并事件的时间戳。实际上，合并通常保留第一个事件的时间戳。

   ```javascript
   let lastEvent = null;
   element.addEventListener('wheel', function(event) {
     if (lastEvent && canCoalesceSimilarEvents(lastEvent, event)) {
       coalesceEvents(lastEvent, event);
       console.log("Coalesced event at:", lastEvent.timeStamp); // 可能会误以为是最新时间
     } else {
       lastEvent = event;
       console.log("New event at:", event.timeStamp);
     }
   });
   ```

2. **在 JavaScript 中直接操作 `WebGestureEvent` 对象:**  开发者无法直接创建或修改 `WebGestureEvent` 对象。这些对象由浏览器内部创建和管理。尝试这样做会导致错误。

3. **没有考虑到 `frame_scale_` 进行坐标转换:** 当处理嵌套的 iframe 或使用了缩放时，`position_in_widget_` 坐标可能需要转换到根框架坐标。如果开发者直接使用 `position_in_widget_` 而没有考虑 `frame_scale_`，可能会导致位置计算错误。

4. **在进行 Pinch 合并时假设精确的锚点:**  `CanCoalesce()` 方法对于 `kGesturePinchUpdate` 使用了一个容差值 (`kAnchorTolerance`) 来判断锚点是否足够接近。开发者不应假设锚点必须完全一致才能合并。

5. **不理解惯性滚动的 `InertialPhase`:** 开发者可能会忽略 `InertialPhase` 属性，导致在处理惯性滚动时出现不正确的行为。例如，可能会在惯性滚动过程中继续应用非惯性滚动的逻辑。

理解 `blink/common/input/web_gesture_event.cc` 的功能对于理解 Chromium 如何处理用户输入和构建流畅的 Web 体验至关重要。它不仅定义了手势事件的结构，还包含了优化事件处理的关键逻辑，例如事件合并。

Prompt: 
```
这是目录为blink/common/input/web_gesture_event.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/input/web_gesture_event.h"

#include <limits>

#include "ui/gfx/geometry/transform.h"

namespace blink {

namespace {

bool IsContinuousGestureEvent(WebInputEvent::Type type) {
  switch (type) {
    case WebGestureEvent::Type::kGestureScrollUpdate:
    case WebGestureEvent::Type::kGesturePinchUpdate:
      return true;
    default:
      return false;
  }
}

// Returns the transform matrix corresponding to the gesture event.
gfx::Transform GetTransformForEvent(const WebGestureEvent& gesture_event) {
  gfx::Transform gesture_transform;
  if (gesture_event.GetType() == WebInputEvent::Type::kGestureScrollUpdate) {
    gesture_transform.Translate(gesture_event.data.scroll_update.delta_x,
                                gesture_event.data.scroll_update.delta_y);
  } else if (gesture_event.GetType() ==
             WebInputEvent::Type::kGesturePinchUpdate) {
    float scale = gesture_event.data.pinch_update.scale;
    gesture_transform.Translate(-gesture_event.PositionInWidget().x(),
                                -gesture_event.PositionInWidget().y());
    gesture_transform.Scale(scale, scale);
    gesture_transform.Translate(gesture_event.PositionInWidget().x(),
                                gesture_event.PositionInWidget().y());
  } else {
    NOTREACHED() << "Invalid event type for transform retrieval: "
                 << WebInputEvent::GetName(gesture_event.GetType());
  }
  return gesture_transform;
}

}  // namespace

std::unique_ptr<WebInputEvent> WebGestureEvent::Clone() const {
  return std::make_unique<WebGestureEvent>(*this);
}

bool WebGestureEvent::CanCoalesce(const WebInputEvent& event) const {
  if (!IsGestureEventType(event.GetType()))
    return false;
  const WebGestureEvent& gesture_event =
      static_cast<const WebGestureEvent&>(event);
  if (GetType() != gesture_event.GetType() ||
      SourceDevice() != gesture_event.SourceDevice() ||
      GetModifiers() != gesture_event.GetModifiers())
    return false;

  if (GetType() == WebInputEvent::Type::kGestureScrollUpdate)
    return true;

  // GesturePinchUpdate scales can be combined only if they share a focal point,
  // e.g., with double-tap drag zoom.
  // Due to the imprecision of OOPIF coordinate conversions, the positions may
  // not be exactly equal, so we only require approximate equality.
  constexpr float kAnchorTolerance = 1.f;
  if (GetType() == WebInputEvent::Type::kGesturePinchUpdate &&
      (std::abs(PositionInWidget().x() - gesture_event.PositionInWidget().x()) <
       kAnchorTolerance) &&
      (std::abs(PositionInWidget().y() - gesture_event.PositionInWidget().y()) <
       kAnchorTolerance)) {
    return true;
  }

  return false;
}

void WebGestureEvent::Coalesce(const WebInputEvent& event) {
  DCHECK(CanCoalesce(event));
  const WebGestureEvent& gesture_event =
      static_cast<const WebGestureEvent&>(event);
  if (GetType() == WebInputEvent::Type::kGestureScrollUpdate) {
    data.scroll_update.delta_x += gesture_event.data.scroll_update.delta_x;
    data.scroll_update.delta_y += gesture_event.data.scroll_update.delta_y;
  } else if (GetType() == WebInputEvent::Type::kGesturePinchUpdate) {
    data.pinch_update.scale *= gesture_event.data.pinch_update.scale;
    // Ensure the scale remains bounded above 0 and below Infinity so that
    // we can reliably perform operations like log on the values.
    if (data.pinch_update.scale < std::numeric_limits<float>::min())
      data.pinch_update.scale = std::numeric_limits<float>::min();
    else if (data.pinch_update.scale > std::numeric_limits<float>::max())
      data.pinch_update.scale = std::numeric_limits<float>::max();
  }
}

ui::ScrollInputType WebGestureEvent::GetScrollInputType() const {
  switch (SourceDevice()) {
    case WebGestureDevice::kTouchpad:
      DCHECK(IsGestureScroll() || IsPinchGestureEventType(GetType()));
      // TODO(crbug.com/1060268): Use of Wheel for Touchpad, especially for
      // pinch events, is confusing and not ideal. There are currently a few
      // different enum types in use across chromium code base for specifying
      // gesture input device. Since we don't want to add yet another one, the
      // most appropriate enum type to use here seems to be
      // `ui::ScrollInputType` which does not have a separate value for
      // touchpad. There is an intention to unify all these enum types. We
      // should consider having a separate touchpad device type in the unified
      // enum type.
      return ui::ScrollInputType::kWheel;
    case WebGestureDevice::kTouchscreen:
      DCHECK(IsGestureScroll() || IsPinchGestureEventType(GetType()));
      return ui::ScrollInputType::kTouchscreen;
    case WebGestureDevice::kSyntheticAutoscroll:
      DCHECK(IsGestureScroll());
      return ui::ScrollInputType::kAutoscroll;
    case WebGestureDevice::kScrollbar:
      DCHECK(IsGestureScroll());
      return ui::ScrollInputType::kScrollbar;
    case WebGestureDevice::kUninitialized:
      break;
  }
  NOTREACHED();
}

float WebGestureEvent::DeltaXInRootFrame() const {
  float delta_x = (type_ == WebInputEvent::Type::kGestureScrollBegin)
                      ? data.scroll_begin.delta_x_hint
                      : data.scroll_update.delta_x;

  bool is_percent = (type_ == WebInputEvent::Type::kGestureScrollBegin)
                        ? data.scroll_begin.delta_hint_units ==
                              ui::ScrollGranularity::kScrollByPercentage
                        : data.scroll_update.delta_units ==
                              ui::ScrollGranularity::kScrollByPercentage;

  return is_percent ? delta_x : delta_x / frame_scale_;
}

float WebGestureEvent::DeltaYInRootFrame() const {
  float delta_y = (type_ == WebInputEvent::Type::kGestureScrollBegin)
                      ? data.scroll_begin.delta_y_hint
                      : data.scroll_update.delta_y;

  bool is_percent = (type_ == WebInputEvent::Type::kGestureScrollBegin)
                        ? data.scroll_begin.delta_hint_units ==
                              ui::ScrollGranularity::kScrollByPercentage
                        : data.scroll_update.delta_units ==
                              ui::ScrollGranularity::kScrollByPercentage;

  return is_percent ? delta_y : delta_y / frame_scale_;
}

ui::ScrollGranularity WebGestureEvent::DeltaUnits() const {
  if (type_ == WebInputEvent::Type::kGestureScrollBegin)
    return data.scroll_begin.delta_hint_units;
  if (type_ == WebInputEvent::Type::kGestureScrollUpdate)
    return data.scroll_update.delta_units;
  DCHECK_EQ(type_, WebInputEvent::Type::kGestureScrollEnd);
  return data.scroll_end.delta_units;
}

WebGestureEvent::InertialPhaseState WebGestureEvent::InertialPhase() const {
  if (type_ == WebInputEvent::Type::kGestureScrollBegin)
    return data.scroll_begin.inertial_phase;
  if (type_ == WebInputEvent::Type::kGestureScrollUpdate)
    return data.scroll_update.inertial_phase;
  DCHECK_EQ(type_, WebInputEvent::Type::kGestureScrollEnd);
  return data.scroll_end.inertial_phase;
}

bool WebGestureEvent::Synthetic() const {
  if (type_ == WebInputEvent::Type::kGestureScrollBegin)
    return data.scroll_begin.synthetic;
  DCHECK_EQ(type_, WebInputEvent::Type::kGestureScrollEnd);
  return data.scroll_end.synthetic;
}

gfx::SizeF WebGestureEvent::TapAreaInRootFrame() const {
  if (type_ == WebInputEvent::Type::kGestureTwoFingerTap) {
    return gfx::SizeF(data.two_finger_tap.first_finger_width / frame_scale_,
                      data.two_finger_tap.first_finger_height / frame_scale_);
  } else if (type_ == WebInputEvent::Type::kGestureShortPress ||
             type_ == WebInputEvent::Type::kGestureLongPress ||
             type_ == WebInputEvent::Type::kGestureLongTap) {
    return gfx::SizeF(data.long_press.width / frame_scale_,
                      data.long_press.height / frame_scale_);
  } else if (type_ == WebInputEvent::Type::kGestureTap ||
             type_ == WebInputEvent::Type::kGestureTapUnconfirmed ||
             type_ == WebInputEvent::Type::kGestureDoubleTap) {
    return gfx::SizeF(data.tap.width / frame_scale_,
                      data.tap.height / frame_scale_);
  } else if (type_ == WebInputEvent::Type::kGestureTapDown) {
    return gfx::SizeF(data.tap_down.width / frame_scale_,
                      data.tap_down.height / frame_scale_);
  } else if (type_ == WebInputEvent::Type::kGestureShowPress) {
    return gfx::SizeF(data.show_press.width / frame_scale_,
                      data.show_press.height / frame_scale_);
  }
  // This function is called for all gestures and determined if the tap
  // area is empty or not; so return an empty rect here.
  return gfx::SizeF();
}

gfx::PointF WebGestureEvent::PositionInRootFrame() const {
  return gfx::ScalePoint(position_in_widget_, 1 / frame_scale_) +
         frame_translate_;
}

int WebGestureEvent::TapCount() const {
  DCHECK_EQ(type_, WebInputEvent::Type::kGestureTap);
  return data.tap.tap_count;
}

int WebGestureEvent::TapDownCount() const {
  DCHECK_EQ(type_, WebInputEvent::Type::kGestureTapDown);
  return data.tap_down.tap_down_count;
}

void WebGestureEvent::ApplyTouchAdjustment(
    const gfx::PointF& root_frame_coords) {
  // Update the window-relative position of the event so that the node that
  // was ultimately hit is under this point (i.e. elementFromPoint for the
  // client co-ordinates in a 'click' event should yield the target). The
  // global position is intentionally left unmodified because it's intended to
  // reflect raw co-ordinates unrelated to any content.
  frame_translate_ = root_frame_coords -
                     gfx::ScalePoint(position_in_widget_, 1 / frame_scale_);
}

void WebGestureEvent::FlattenTransform() {
  if (frame_scale_ != 1) {
    switch (type_) {
      case WebInputEvent::Type::kGestureScrollBegin:
        if (data.scroll_begin.delta_hint_units !=
            ui::ScrollGranularity::kScrollByPercentage) {
          data.scroll_begin.delta_x_hint /= frame_scale_;
          data.scroll_begin.delta_y_hint /= frame_scale_;
        }
        break;
      case WebInputEvent::Type::kGestureScrollUpdate:
        if (data.scroll_update.delta_units !=
            ui::ScrollGranularity::kScrollByPercentage) {
          data.scroll_update.delta_x /= frame_scale_;
          data.scroll_update.delta_y /= frame_scale_;
        }
        break;
      case WebInputEvent::Type::kGestureTwoFingerTap:
        data.two_finger_tap.first_finger_width /= frame_scale_;
        data.two_finger_tap.first_finger_height /= frame_scale_;
        break;
      case WebInputEvent::Type::kGestureShortPress:
      case WebInputEvent::Type::kGestureLongPress:
      case WebInputEvent::Type::kGestureLongTap:
        data.long_press.width /= frame_scale_;
        data.long_press.height /= frame_scale_;
        break;
      case WebInputEvent::Type::kGestureTap:
      case WebInputEvent::Type::kGestureTapUnconfirmed:
      case WebInputEvent::Type::kGestureDoubleTap:
        data.tap.width /= frame_scale_;
        data.tap.height /= frame_scale_;
        break;
      case WebInputEvent::Type::kGestureTapDown:
        data.tap_down.width /= frame_scale_;
        data.tap_down.height /= frame_scale_;
        break;
      case WebInputEvent::Type::kGestureShowPress:
        data.show_press.width /= frame_scale_;
        data.show_press.height /= frame_scale_;
        break;
      default:
        break;
    }
  }

  SetPositionInWidget(PositionInRootFrame());
  frame_translate_ = gfx::Vector2dF();
  frame_scale_ = 1;
}

// Whether |event_in_queue| is a touchscreen GesturePinchUpdate or
// GestureScrollUpdate and has the same modifiers/source as the new
// scroll/pinch event. Compatible touchscreen scroll and pinch event pairs
// can be logically coalesced.
bool WebGestureEvent::IsCompatibleScrollorPinch(
    const WebGestureEvent& new_event,
    const WebGestureEvent& event_in_queue) {
  DCHECK(new_event.GetType() == WebInputEvent::Type::kGestureScrollUpdate ||
         new_event.GetType() == WebInputEvent::Type::kGesturePinchUpdate)
      << "Invalid event type for pinch/scroll coalescing: "
      << WebInputEvent::GetName(new_event.GetType());
  DLOG_IF(WARNING, new_event.TimeStamp() < event_in_queue.TimeStamp())
      << "Event time not monotonic?\n";
  return (event_in_queue.GetType() ==
              WebInputEvent::Type::kGestureScrollUpdate ||
          event_in_queue.GetType() ==
              WebInputEvent::Type::kGesturePinchUpdate) &&
         event_in_queue.GetModifiers() == new_event.GetModifiers() &&
         event_in_queue.SourceDevice() == WebGestureDevice::kTouchscreen &&
         new_event.SourceDevice() == WebGestureDevice::kTouchscreen;
}

std::pair<std::unique_ptr<WebGestureEvent>, std::unique_ptr<WebGestureEvent>>
WebGestureEvent::CoalesceScrollAndPinch(
    const WebGestureEvent* second_last_event,
    const WebGestureEvent& last_event,
    const WebGestureEvent& new_event) {
  DCHECK(!last_event.CanCoalesce(new_event))
      << "New event can't be coalesced with the last event in queue directly.";
  DCHECK(IsContinuousGestureEvent(new_event.GetType()));
  DCHECK(IsCompatibleScrollorPinch(new_event, last_event));
  DCHECK(!second_last_event ||
         IsCompatibleScrollorPinch(new_event, *second_last_event));

  auto scroll_event = std::make_unique<WebGestureEvent>(
      WebInputEvent::Type::kGestureScrollUpdate, new_event.GetModifiers(),
      new_event.TimeStamp(), new_event.SourceDevice());
  scroll_event->primary_pointer_type = new_event.primary_pointer_type;
  scroll_event->primary_unique_touch_event_id =
      new_event.primary_unique_touch_event_id;
  auto pinch_event = std::make_unique<WebGestureEvent>(*scroll_event);
  pinch_event->SetType(WebInputEvent::Type::kGesturePinchUpdate);
  pinch_event->SetPositionInWidget(
      new_event.GetType() == WebInputEvent::Type::kGesturePinchUpdate
          ? new_event.PositionInWidget()
          : last_event.PositionInWidget());

  gfx::Transform combined_scroll_pinch = GetTransformForEvent(last_event);
  if (second_last_event) {
    combined_scroll_pinch.PreConcat(GetTransformForEvent(*second_last_event));
  }
  combined_scroll_pinch.PostConcat(GetTransformForEvent(new_event));

  float combined_scale = combined_scroll_pinch.To2dScale().x();
  gfx::Vector2dF combined_translation = combined_scroll_pinch.To2dTranslation();
  scroll_event->data.scroll_update.delta_x =
      (combined_translation.x() + pinch_event->PositionInWidget().x()) /
          combined_scale -
      pinch_event->PositionInWidget().x();
  scroll_event->data.scroll_update.delta_y =
      (combined_translation.y() + pinch_event->PositionInWidget().y()) /
          combined_scale -
      pinch_event->PositionInWidget().y();
  pinch_event->data.pinch_update.scale = combined_scale;

  return std::make_pair(std::move(scroll_event), std::move(pinch_event));
}

std::unique_ptr<blink::WebGestureEvent>
WebGestureEvent::GenerateInjectedScrollbarGestureScroll(
    WebInputEvent::Type type,
    base::TimeTicks timestamp,
    gfx::PointF position_in_widget,
    gfx::Vector2dF scroll_delta,
    ui::ScrollGranularity granularity) {
  std::unique_ptr<WebGestureEvent> generated_gesture_event =
      std::make_unique<WebGestureEvent>(type, WebInputEvent::kNoModifiers,
                                        timestamp,
                                        WebGestureDevice::kScrollbar);
  DCHECK(generated_gesture_event->IsGestureScroll());

  if (type == WebInputEvent::Type::kGestureScrollBegin) {
    // Gesture events expect the scroll delta to be flipped. Gesture events'
    // scroll deltas are interpreted as the finger's delta in relation to the
    // screen (which is the reverse of the scrolling direction).
    generated_gesture_event->data.scroll_begin.delta_x_hint = -scroll_delta.x();
    generated_gesture_event->data.scroll_begin.delta_y_hint = -scroll_delta.y();
    generated_gesture_event->data.scroll_begin.inertial_phase =
        WebGestureEvent::InertialPhaseState::kNonMomentum;
    generated_gesture_event->data.scroll_begin.delta_hint_units = granularity;
  } else if (type == WebInputEvent::Type::kGestureScrollUpdate) {
    generated_gesture_event->data.scroll_update.delta_x = -scroll_delta.x();
    generated_gesture_event->data.scroll_update.delta_y = -scroll_delta.y();
    generated_gesture_event->data.scroll_update.inertial_phase =
        WebGestureEvent::InertialPhaseState::kNonMomentum;
    generated_gesture_event->data.scroll_update.delta_units = granularity;
  }

  generated_gesture_event->SetPositionInWidget(position_in_widget);
  return generated_gesture_event;
}

}  // namespace blink

"""

```