Response:
Let's break down the thought process for analyzing the `mouse_event.cc` file and generating the comprehensive response.

**1. Initial Understanding of the Request:**

The request is to analyze a specific Chromium Blink engine source code file (`mouse_event.cc`) and identify its functionalities, relationships with web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning (input/output), and highlight potential user/programming errors.

**2. First Pass - Skimming for Keywords and Structure:**

I would start by quickly scanning the code, looking for:

* **Includes:** These reveal dependencies and the file's scope. I see includes related to events, DOM elements, frames, layout, painting, and bindings. This strongly suggests the file deals with the core implementation of mouse events within the rendering engine.
* **Class Definition (`MouseEvent`):** This is the central entity. I'd note its inheritance (`UIEventWithKeyState`) indicating it's a specific type of UI event handling keyboard state.
* **Public Methods:** Methods like `Create`, `initMouseEvent`, `button`, `offsetX`, `offsetY`, `layerX`, `layerY`, `DispatchEvent`. These are the public interfaces and hints about the file's functionality.
* **Private/Internal Methods:** Methods like `InitCoordinates`, `ComputeRelativePosition`, `InitMouseEventInternal`. These reveal internal implementation details.
* **Static Methods/Functions:** Functions like `ButtonsToWebInputEventModifiers`, `WebInputEventModifiersToButtons`, `LayoutZoomFactor`, `FindTargetLayoutObject`. These often represent utility functions.
* **Namespace (`blink`):**  Indicates this is part of the Blink rendering engine.
* **Comments and Copyright Notices:**  Provide context about the file's origin and licensing.

**3. Deeper Dive - Analyzing Key Functionalities:**

Now, I'd go through the code more deliberately, focusing on understanding what each section does:

* **Creation of `MouseEvent` Objects:** The `Create` methods are crucial. They show how `MouseEvent` instances are created, taking various parameters (script state, event type, initializers). The fallback DOM window concept for isolated worlds is interesting.
* **Initialization (`InitMouseEventInternal`, `InitCoordinates`):**  These methods are responsible for setting the internal state of the `MouseEvent` object based on input parameters. The handling of `clientX`, `clientY`, `screenX`, `screenY`, and the interplay with zoom factors is important.
* **Coordinate System Transformations (`ComputeRelativePosition`):**  This is a complex part. I'd carefully examine how `offsetX`, `offsetY`, `layerX`, and `layerY` are calculated, paying attention to the interaction with layout objects, padding boxes, and layers. The comments mentioning "poorly defined" `layerX/Y` are noteworthy.
* **Event Dispatching (`DispatchEvent`):** This method is central to how the event propagates through the DOM tree. The special handling of `click` and `dblclick` events is highlighted.
* **Button Mapping (`ButtonsToWebInputEventModifiers`, `WebInputEventModifiersToButtons`):**  These functions handle the conversion between Blink's internal button representation and the web input event modifiers.
* **Getter Methods (`button`, `offsetX`, `offsetY`, `layerX`, `layerY`):**  These provide access to the event's properties. The special case for the `button` getter based on event type is worth noting.
* **Target Element Handling (`toElement`, `fromElement`):** These methods relate to identifying the source and destination elements of mouse events.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

As I understand the functionalities, I'd start making connections to web technologies:

* **JavaScript:** The `MouseEvent` class directly maps to the JavaScript `MouseEvent` object available in browsers. The parameters in the `Create` and `initMouseEvent` methods correspond to properties of the JavaScript `MouseEvent` interface. The dispatching mechanism is what makes JavaScript event listeners work.
* **HTML:** Mouse events are triggered by interactions with HTML elements. The code references various HTML elements (`HTMLCanvasElement`, `HTMLMediaElement`, etc.), indicating how mouse events are handled on these specific elements.
* **CSS:** CSS affects the layout and rendering of HTML elements. The `ComputeRelativePosition` method explicitly deals with layout boxes and padding, demonstrating the influence of CSS on mouse event coordinates. The zoom factor calculation is also relevant to how CSS zoom affects event positions.

**5. Logical Reasoning (Input/Output Examples):**

Based on my understanding, I would construct hypothetical scenarios:

* **Simple Click:** Mouse click on a `<div>`. Input: client coordinates, target element. Output: `offsetX`, `offsetY` relative to the `<div>`.
* **Click on an Inline Element:** Highlight the difference in relative position calculation.
* **Click with Scrolling:** Show how page coordinates are adjusted for scroll position.
* **Double Click:** Demonstrate the generation of both `click` and `dblclick` events.

**6. Identifying Potential Errors:**

Thinking about common mistakes, both for users (web developers) and Blink developers:

* **Incorrect Coordinate Assumptions:**  Developers might incorrectly assume `offsetX/Y` are always relative to the border box, neglecting padding.
* **Forgetting Zoom Factors:**  Not accounting for page zoom can lead to miscalculations.
* **Misunderstanding `layerX/Y`:** The "poorly defined" nature of `layerX/Y` is a source of potential confusion.
* **Event Listener Errors:** Incorrectly attaching or handling event listeners can lead to missed or unexpected event behavior.

**7. Structuring the Response:**

Finally, I'd organize my findings into a clear and structured response, using headings, bullet points, and code examples where appropriate. The goal is to provide a comprehensive yet easy-to-understand explanation of the `mouse_event.cc` file's role. I would start with a summary of the core functionality and then delve into specific aspects like the relationship with web technologies, logical reasoning, and common errors.

**Self-Correction/Refinement:**

Throughout this process, I would constantly review my understanding and the code. If something seems unclear or contradictory, I'd go back to the code for closer inspection. For example, understanding *why* the `button()` getter has special handling for certain event types requires careful reading of the code and perhaps some knowledge of the DOM specification. Similarly, the intricacies of `ComputeRelativePosition` might require multiple readings and tracing the logic through different scenarios.
好的，让我们详细分析一下 `blink/renderer/core/events/mouse_event.cc` 文件的功能。

**文件功能概览:**

`mouse_event.cc` 文件是 Chromium Blink 引擎中负责处理鼠标事件的核心代码。它定义了 `MouseEvent` 类，该类是浏览器中鼠标事件的实现，并负责处理与鼠标交互相关的各种信息和行为。其主要功能包括：

1. **表示和存储鼠标事件信息:**  `MouseEvent` 类封装了与特定鼠标事件相关的所有数据，例如鼠标的位置（屏幕坐标、客户端坐标、页面坐标、偏移坐标、图层坐标）、按下的按钮、辅助按键状态（Ctrl, Alt, Shift, Meta）、相关目标元素等。
2. **事件的创建和初始化:**  文件中提供了多种创建 `MouseEvent` 对象的方法 (`Create`)，以及初始化鼠标事件属性的方法 (`initMouseEvent`, `InitMouseEventInternal`, `InitCoordinates`)。这些方法允许在不同的场景下创建和配置鼠标事件。
3. **坐标转换和计算:**  `MouseEvent` 负责进行各种坐标系的转换，例如将屏幕坐标转换为客户端坐标、页面坐标以及相对于特定元素的偏移坐标 (`offsetX`, `offsetY`) 和图层坐标 (`layerX`, `layerY`)。  `ComputeRelativePosition` 函数是进行这些计算的核心。
4. **与底层输入事件的交互:**  代码中涉及到将底层的 Web 输入事件属性 (`WebPointerProperties`) 转换为 `MouseEvent` 的属性，例如将按钮状态 (`WebPointerProperties::Buttons`) 转换为 `MouseEvent` 的 `buttons_` 属性。
5. **事件的派发和传播:**  `DispatchEvent` 方法负责将 `MouseEvent` 派发到相应的事件目标，并控制事件的传播过程（冒泡和捕获）。
6. **处理特定鼠标事件的逻辑:**  虽然这个文件本身主要关注 `MouseEvent` 类的定义和基本操作，但它也包含一些针对特定鼠标事件（例如 `click`, `dblclick`）的特殊处理逻辑。
7. **提供 JavaScript 可访问的接口:**  `MouseEvent` 类最终会通过 Blink 的绑定机制暴露给 JavaScript，使得网页开发者可以通过 JavaScript 代码来监听和处理鼠标事件。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`mouse_event.cc` 文件在浏览器内部工作，直接支持了 JavaScript 中对鼠标事件的处理，并且其行为受到 HTML 结构和 CSS 样式的间接影响。

**1. 与 JavaScript 的关系:**

* **JavaScript 事件对象:** `MouseEvent` 类在 C++ 层面实现了浏览器中 JavaScript 的 `MouseEvent` 对象。当用户在网页上进行鼠标操作时，Blink 引擎会创建 `MouseEvent` 对象，并将其传递给 JavaScript 事件处理函数。
   ```javascript
   document.getElementById('myDiv').addEventListener('click', function(event) {
     console.log('鼠标点击事件发生！');
     console.log('客户端 X 坐标:', event.clientX); // 这里 event 就是一个 MouseEvent 对象
     console.log('偏移 X 坐标:', event.offsetX);
   });
   ```
* **事件监听器:** JavaScript 代码可以使用 `addEventListener` 方法来注册鼠标事件的监听器。当 `mouse_event.cc` 中的代码检测到相应的鼠标事件发生时，会触发这些监听器。
* **事件属性访问:** JavaScript 代码可以直接访问 `MouseEvent` 对象的各种属性，例如 `clientX`, `clientY`, `offsetX`, `offsetY`, `button`, `buttons`, `ctrlKey`, `altKey`, `shiftKey`, `metaKey`, `target`, `relatedTarget` 等。这些属性的值在 `mouse_event.cc` 中被计算和存储。

**2. 与 HTML 的关系:**

* **事件目标:**  鼠标事件的目标是 HTML 元素。当用户点击、移动鼠标到某个 HTML 元素上时，`mouse_event.cc` 中的代码会确定哪个元素是事件的目标 (`target`)。
* **事件类型:**  不同的鼠标事件类型（例如 `click`, `mousedown`, `mouseup`, `mousemove`, `mouseover`, `mouseout`, `mouseenter`, `mouseleave`, `dblclick`) 对应着用户在 HTML 元素上的不同交互行为。`mouse_event.cc` 负责处理这些不同类型的事件。
* **HTML 结构影响坐标:** HTML 元素的布局和嵌套结构会影响鼠标事件的坐标计算。例如，`offsetX` 和 `offsetY` 是相对于事件目标元素的内边距边界计算的。

**3. 与 CSS 的关系:**

* **CSS 影响布局和坐标:** CSS 样式决定了 HTML 元素的尺寸、位置、边距、内边距等属性，这些属性会直接影响鼠标事件坐标的计算。例如，如果一个元素设置了 `padding`，那么 `offsetX` 和 `offsetY` 的原点就会在内边距的左上角。
* **CSS `transform` 可能会影响坐标:**  CSS 的 `transform` 属性可以改变元素在页面上的渲染位置，这可能会影响到某些鼠标事件坐标的计算，尤其是在涉及到层叠上下文和坐标转换时。`ComputeRelativePosition` 方法中可以看到对 Layout 对象的处理，这与 CSS 布局密切相关。
* **`pointer-events` CSS 属性:**  CSS 的 `pointer-events` 属性可以控制元素是否以及如何响应鼠标事件。`mouse_event.cc` 中的事件派发逻辑会受到 `pointer-events` 属性的影响。

**逻辑推理的假设输入与输出举例:**

假设用户在一个 `<div>` 元素上点击了鼠标左键：

* **假设输入:**
    * 鼠标点击事件发生时的屏幕坐标：`(screenX: 100, screenY: 200)`
    * 鼠标点击事件发生时，鼠标指针位于 `<div>` 元素的客户端坐标：`(clientX: 50, clientY: 60)`
    * `<div>` 元素在页面中的滚动偏移量：`(scrollX: 10, scrollY: 5)`
    * `<div>` 元素相对于其父元素的偏移量：`(offsetLeft: 20, offsetTop: 30)`
    * 用户点击的是鼠标左键。

* **逻辑推理过程 (`mouse_event.cc` 内部可能进行的计算):**
    * **创建 `MouseEvent` 对象:**  根据底层输入事件的信息创建一个 `MouseEvent` 实例。
    * **初始化坐标:**
        * `screenX_ = 100`, `screenY_ = 200`
        * `clientX_ = 50`, `clientY_ = 60`
        * `page_x_ = clientX_ + scrollX = 50 + 10 = 60`
        * `page_y_ = clientY_ + scrollY = 60 + 5 = 65`
    * **计算 `offsetX` 和 `offsetY` (在 `ComputeRelativePosition` 中):**  `offsetX` 和 `offsetY` 是相对于事件目标元素的内边距边界计算的。假设 `<div>` 元素的内边距为 `(paddingLeft: 5, paddingTop: 5)`，则：
        * `offset_x_ = page_x_ - (div的绝对位置的X坐标 + paddingLeft)`
        * `offset_y_ = page_y_ - (div的绝对位置的Y坐标 + paddingTop)`
        *  `div的绝对位置的X坐标` 大致等于 `div的父元素的绝对位置的X坐标 + offsetLeft`
        *  `div的绝对位置的Y坐标` 大致等于 `div的父元素的绝对位置的Y坐标 + offsetTop`
        *  具体的计算会涉及到布局树的信息。

* **假设输出 (部分 `MouseEvent` 属性值):**
    * `screenX()`: 100
    * `screenY()`: 200
    * `clientX()`: 50
    * `clientY()`: 60
    * `pageX()`: 60
    * `pageY()`: 65
    * `offsetX()`:  取决于 `<div>` 元素的布局和内边距，例如可能是 0 (如果点击在内边距的左上角)
    * `offsetY()`:  取决于 `<div>` 元素的布局和内边距，例如可能是 0
    * `button()`: 0 (表示左键)
    * `buttons()`: 1 (表示左键按下)
    * `target()`: 指向该 `<div>` 元素的 DOM 节点

**用户或编程常见的使用错误举例:**

1. **混淆客户端坐标和页面坐标:**
   * **错误代码 (JavaScript):**
     ```javascript
     document.addEventListener('click', function(event) {
       // 错误地认为 event.clientX 是相对于整个页面的坐标
       console.log('页面 X 坐标 (错误):', event.clientX + window.scrollX);
     });
     ```
   * **说明:** 开发者可能会错误地认为 `event.clientX` 就是相对于整个可滚动页面的坐标，而忘记加上页面的滚动偏移量。正确的做法是使用 `event.pageX`。

2. **错误地假设 `offsetX` 和 `offsetY` 的参考点:**
   * **错误代码 (JavaScript):**
     ```javascript
     document.getElementById('myButton').addEventListener('click', function(event) {
       // 错误地认为 offsetX 是相对于按钮的边框计算的
       console.log('相对于边框的 X 坐标 (可能错误):', event.offsetX);
     });
     ```
   * **说明:**  `offsetX` 和 `offsetY` 是相对于目标元素的内边距边界计算的，而不是边框。如果开发者没有理解这一点，可能会在涉及到边框宽度的计算时出错。

3. **在异步操作中错误地使用事件对象:**
   * **错误代码 (JavaScript):**
     ```javascript
     document.getElementById('myLink').addEventListener('click', function(event) {
       setTimeout(function() {
         // 此时 event 对象可能已经被回收或状态改变
         console.log('点击的目标元素:', event.target);
       }, 1000);
     });
     ```
   * **说明:**  虽然 `MouseEvent` 对象在事件处理函数执行期间是有效的，但在异步操作的回调函数中访问它时，需要注意其生命周期。在某些情况下，事件对象可能已经被回收或其状态已经改变。建议在异步操作前将需要的数据提取出来。

4. **不理解事件冒泡和捕获:**
   * **错误场景:**  在一个嵌套的元素结构中，父元素和子元素都注册了相同的鼠标事件监听器，开发者如果没有理解事件冒泡或捕获的机制，可能会遇到事件处理顺序上的困惑。

5. **滥用或误解 `layerX` 和 `layerY`:**
   * **说明:**  正如代码注释中提到的，`layerX` 和 `layerY` 的定义较为模糊，并且不总是对应于 `PaintLayer` 的偏移。开发者应该谨慎使用这两个属性，并理解其潜在的不确定性。

总而言之，`blink/renderer/core/events/mouse_event.cc` 文件是 Blink 引擎处理鼠标事件的基础，它负责创建、初始化、计算和派发鼠标事件，并将这些信息传递给 JavaScript，从而使得网页能够响应用户的鼠标交互。理解这个文件的功能有助于深入理解浏览器事件机制的工作原理。

Prompt: 
```
这是目录为blink/renderer/core/events/mouse_event.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2001 Peter Kelly (pmk@post.com)
 * Copyright (C) 2001 Tobias Anton (anton@stud.fbi.fh-darmstadt.de)
 * Copyright (C) 2006 Samuel Weinig (sam.weinig@gmail.com)
 * Copyright (C) 2003, 2005, 2006, 2008 Apple Inc. All rights reserved.
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
 */

#include "third_party/blink/renderer/core/events/mouse_event.h"

#include "third_party/blink/public/common/input/web_pointer_properties.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mouse_event_init.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatcher.h"
#include "third_party/blink/renderer/core/dom/events/event_path.h"
#include "third_party/blink/renderer/core/event_interface_names.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/input/input_device_capabilities.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"

namespace blink {

namespace {

float LayoutZoomFactor(const LocalDOMWindow* local_dom_window) {
  if (!local_dom_window)
    return 1.f;
  LocalFrame* frame = local_dom_window->GetFrame();
  if (!frame)
    return 1.f;
  return frame->LayoutZoomFactor();
}

const LayoutObject* FindTargetLayoutObject(Node*& target_node) {
  LayoutObject* layout_object = target_node->GetLayoutObject();
  if (!layout_object || !layout_object->IsSVG())
    return layout_object;
  // If this is an SVG node, compute the offset to the padding box of the
  // outermost SVG root (== the closest ancestor that has a CSS layout box.)
  while (!layout_object->IsSVGRoot())
    layout_object = layout_object->Parent();
  // Update the target node to point to the SVG root.
  target_node = layout_object->GetNode();
  auto* svg_element = DynamicTo<SVGElement>(target_node);
  DCHECK(!target_node ||
         (svg_element && svg_element->IsOutermostSVGSVGElement()));
  return layout_object;
}

unsigned ButtonsToWebInputEventModifiers(uint16_t buttons) {
  unsigned modifiers = 0;

  if (buttons & static_cast<uint16_t>(WebPointerProperties::Buttons::kLeft))
    modifiers |= WebInputEvent::kLeftButtonDown;
  if (buttons & static_cast<uint16_t>(WebPointerProperties::Buttons::kRight))
    modifiers |= WebInputEvent::kRightButtonDown;
  if (buttons & static_cast<uint16_t>(WebPointerProperties::Buttons::kMiddle))
    modifiers |= WebInputEvent::kMiddleButtonDown;
  if (buttons & static_cast<uint16_t>(WebPointerProperties::Buttons::kBack))
    modifiers |= WebInputEvent::kBackButtonDown;
  if (buttons & static_cast<uint16_t>(WebPointerProperties::Buttons::kForward))
    modifiers |= WebInputEvent::kForwardButtonDown;

  return modifiers;
}

}  // namespace

MouseEvent* MouseEvent::Create(ScriptState* script_state,
                               const AtomicString& type,
                               const MouseEventInit* initializer) {
  LocalDOMWindow* fallback_dom_window = nullptr;
  if (script_state) {
    if (script_state->World().IsIsolatedWorld()) {
      UIEventWithKeyState::DidCreateEventInIsolatedWorld(
          initializer->ctrlKey(), initializer->altKey(),
          initializer->shiftKey(), initializer->metaKey());
    }
    // If we don't have a view, we'll have to get a fallback dom window in
    // order to properly account for device scale factor.
    if (!initializer || !initializer->view()) {
      if (auto* execution_context = ExecutionContext::From(script_state);
          execution_context && execution_context->IsWindow()) {
        fallback_dom_window = static_cast<LocalDOMWindow*>(execution_context);
      }
    }
  }
  return MakeGarbageCollected<MouseEvent>(
      type, initializer, base::TimeTicks::Now(), kRealOrIndistinguishable,
      kMenuSourceNone, fallback_dom_window);
}

MouseEvent* MouseEvent::Create(const AtomicString& event_type,
                               const MouseEventInit* initializer,
                               base::TimeTicks platform_time_stamp,
                               SyntheticEventType synthetic_event_type,
                               WebMenuSourceType menu_source_type) {
  return MakeGarbageCollected<MouseEvent>(
      event_type, initializer, platform_time_stamp, synthetic_event_type,
      menu_source_type);
}

MouseEvent::MouseEvent()
    : position_type_(PositionType::kPosition),
      button_(0),
      buttons_(0),
      related_target_(nullptr),
      synthetic_event_type_(kRealOrIndistinguishable) {}

MouseEvent::MouseEvent(const AtomicString& event_type,
                       const MouseEventInit* initializer,
                       base::TimeTicks platform_time_stamp,
                       SyntheticEventType synthetic_event_type,
                       WebMenuSourceType menu_source_type,
                       LocalDOMWindow* fallback_dom_window)
    : UIEventWithKeyState(event_type, initializer, platform_time_stamp),
      screen_x_(initializer->screenX()),
      screen_y_(initializer->screenY()),
      movement_delta_(initializer->movementX(), initializer->movementY()),
      position_type_(synthetic_event_type == kPositionless
                         ? PositionType::kPositionless
                         : PositionType::kPosition),
      button_(initializer->button()),
      buttons_(initializer->buttons()),
      related_target_(initializer->relatedTarget()),
      synthetic_event_type_(synthetic_event_type),
      menu_source_type_(menu_source_type) {
  InitCoordinates(initializer->clientX(), initializer->clientY(),
                  fallback_dom_window);
  modifiers_ |= ButtonsToWebInputEventModifiers(buttons_);
}

void MouseEvent::InitCoordinates(const double client_x,
                                 const double client_y,
                                 const LocalDOMWindow* fallback_dom_window) {
  client_x_ = page_x_ = client_x;
  client_y_ = page_y_ = client_y;
  absolute_location_ = gfx::PointF(client_x, client_y);

  auto* local_dom_window = DynamicTo<LocalDOMWindow>(view());
  float zoom_factor = LayoutZoomFactor(local_dom_window ? local_dom_window
                                                        : fallback_dom_window);

  if (local_dom_window) {
    if (LocalFrame* frame = local_dom_window->GetFrame()) {
      // Adjust page_x_ and page_y_ by layout viewport scroll offset.
      if (ScrollableArea* scrollable_area = frame->View()->LayoutViewport()) {
        gfx::Vector2d scroll_offset = scrollable_area->ScrollOffsetInt();
        page_x_ += scroll_offset.x() / zoom_factor;
        page_y_ += scroll_offset.y() / zoom_factor;
      }
    }
  }

  // absolute_location_ is not an API value. It's in layout space.
  absolute_location_.Scale(zoom_factor);

  // Correct values of the following are computed lazily, see
  // ComputeRelativePosition().
  offset_x_ = page_x_;
  offset_y_ = page_y_;
  layer_location_ = gfx::PointF(page_x_, page_y_);

  has_cached_relative_position_ = false;
}

void MouseEvent::SetCoordinatesFromWebPointerProperties(
    const WebPointerProperties& web_pointer_properties,
    const LocalDOMWindow* dom_window,
    MouseEventInit* initializer) {
  gfx::PointF client_point;
  gfx::PointF screen_point = web_pointer_properties.PositionInScreen();
  float inverse_zoom_factor = 1.0f;
  if (dom_window && dom_window->GetFrame() && dom_window->GetFrame()->View()) {
    LocalFrame* frame = dom_window->GetFrame();
    gfx::PointF root_frame_point = web_pointer_properties.PositionInWidget();
    if (Page* p = frame->GetPage()) {
      if (p->GetPointerLockController().GetElement() &&
          !p->GetPointerLockController().LockPending()) {
        p->GetPointerLockController().GetPointerLockPosition(&root_frame_point,
                                                             &screen_point);
      }
    }
    gfx::PointF frame_point =
        frame->View()->ConvertFromRootFrame(root_frame_point);
    inverse_zoom_factor = 1.0f / frame->LayoutZoomFactor();
    client_point = gfx::ScalePoint(frame_point, inverse_zoom_factor);
  }

  initializer->setScreenX(screen_point.x());
  initializer->setScreenY(screen_point.y());
  initializer->setClientX(client_point.x());
  initializer->setClientY(client_point.y());

  // TODO(crbug.com/982379): We need to merge the code path of raw movement
  // events and regular events so that we can remove the block below.
  if (web_pointer_properties.is_raw_movement_event) {
    // TODO(nzolghadr): We need to scale movement attrinutes as well. But if we
    // do that here and round it to the int again it causes inconsistencies
    // between screenX/Y and cumulative movementX/Y.
    initializer->setMovementX(web_pointer_properties.movement_x);
    initializer->setMovementY(web_pointer_properties.movement_y);
  }
}

uint16_t MouseEvent::WebInputEventModifiersToButtons(unsigned modifiers) {
  uint16_t buttons = 0;

  if (modifiers & WebInputEvent::kLeftButtonDown)
    buttons |= static_cast<uint16_t>(WebPointerProperties::Buttons::kLeft);
  if (modifiers & WebInputEvent::kRightButtonDown) {
    buttons |= static_cast<uint16_t>(WebPointerProperties::Buttons::kRight);
  }
  if (modifiers & WebInputEvent::kMiddleButtonDown) {
    buttons |= static_cast<uint16_t>(WebPointerProperties::Buttons::kMiddle);
  }
  if (modifiers & WebInputEvent::kBackButtonDown)
    buttons |= static_cast<uint16_t>(WebPointerProperties::Buttons::kBack);
  if (modifiers & WebInputEvent::kForwardButtonDown) {
    buttons |= static_cast<uint16_t>(WebPointerProperties::Buttons::kForward);
  }

  return buttons;
}

void MouseEvent::initMouseEvent(ScriptState* script_state,
                                const AtomicString& type,
                                bool bubbles,
                                bool cancelable,
                                AbstractView* view,
                                int detail,
                                int screen_x,
                                int screen_y,
                                int client_x,
                                int client_y,
                                bool ctrl_key,
                                bool alt_key,
                                bool shift_key,
                                bool meta_key,
                                int16_t button,
                                EventTarget* related_target,
                                uint16_t buttons) {
  if (IsBeingDispatched())
    return;

  if (script_state && script_state->World().IsIsolatedWorld())
    UIEventWithKeyState::DidCreateEventInIsolatedWorld(ctrl_key, alt_key,
                                                       shift_key, meta_key);

  InitModifiers(ctrl_key, alt_key, shift_key, meta_key);
  InitMouseEventInternal(type, bubbles, cancelable, view, detail, screen_x,
                         screen_y, client_x, client_y, GetModifiers(), button,
                         related_target, nullptr, buttons);
}

void MouseEvent::InitMouseEventInternal(
    const AtomicString& type,
    bool bubbles,
    bool cancelable,
    AbstractView* view,
    int detail,
    double screen_x,
    double screen_y,
    double client_x,
    double client_y,
    WebInputEvent::Modifiers modifiers,
    int16_t button,
    EventTarget* related_target,
    InputDeviceCapabilities* source_capabilities,
    uint16_t buttons) {
  InitUIEventInternal(type, bubbles, cancelable, related_target, view, detail,
                      source_capabilities);

  screen_x_ = screen_x;
  screen_y_ = screen_y;
  button_ = button;
  buttons_ = buttons;
  related_target_ = related_target;
  modifiers_ = modifiers;

  InitCoordinates(client_x, client_y);

  // FIXME: SyntheticEventType is not set to RealOrIndistinguishable here.
}

void MouseEvent::InitCoordinatesForTesting(double screen_x,
                                           double screen_y,
                                           double client_x,
                                           double client_y) {
  screen_x_ = screen_x;
  screen_y_ = screen_y;
  InitCoordinates(client_x, client_y);
}

const AtomicString& MouseEvent::InterfaceName() const {
  return event_interface_names::kMouseEvent;
}

bool MouseEvent::IsMouseEvent() const {
  return true;
}

int16_t MouseEvent::button() const {
  const AtomicString& event_name = type();
  if (button_ == -1 || event_name == event_type_names::kMousemove ||
      event_name == event_type_names::kMouseleave ||
      event_name == event_type_names::kMouseenter ||
      event_name == event_type_names::kMouseover ||
      event_name == event_type_names::kMouseout) {
    return 0;
  }
  return button_;
}

bool MouseEvent::IsLeftButton() const {
  return button() == static_cast<int16_t>(WebPointerProperties::Button::kLeft);
}

unsigned MouseEvent::which() const {
  // For the DOM, the return values for left, middle and right mouse buttons are
  // 0, 1, 2, respectively.
  // For the Netscape "which" property, the return values for left, middle and
  // right mouse buttons are 1, 2, 3, respectively.
  // So we must add 1.
  return (unsigned)(button_ + 1);
}

Node* MouseEvent::toElement() const {
  // MSIE extension - "the object toward which the user is moving the mouse
  // pointer"
  if (type() == event_type_names::kMouseout ||
      type() == event_type_names::kMouseleave)
    return relatedTarget() ? relatedTarget()->ToNode() : nullptr;

  return target() ? target()->ToNode() : nullptr;
}

Node* MouseEvent::fromElement() const {
  // MSIE extension - "object from which activation or the mouse pointer is
  // exiting during the event" (huh?)
  if (type() != event_type_names::kMouseout &&
      type() != event_type_names::kMouseleave)
    return relatedTarget() ? relatedTarget()->ToNode() : nullptr;

  return target() ? target()->ToNode() : nullptr;
}

void MouseEvent::Trace(Visitor* visitor) const {
  visitor->Trace(related_target_);
  UIEventWithKeyState::Trace(visitor);
}

DispatchEventResult MouseEvent::DispatchEvent(EventDispatcher& dispatcher) {
  // TODO(mustaq): Move click-specific code to `PointerEvent::DispatchEvent`.
  GetEventPath().AdjustForRelatedTarget(dispatcher.GetNode(), relatedTarget());

  bool is_click = type() == event_type_names::kClick;

  if (!isTrusted())
    return dispatcher.Dispatch();

  if (is_click || type() == event_type_names::kMousedown ||
      type() == event_type_names::kMouseup ||
      type() == event_type_names::kDblclick) {
    GetEventPath().AdjustForDisabledFormControl();
  }

  if (type().empty())
    return DispatchEventResult::kNotCanceled;  // Shouldn't happen.

  if (is_click) {
    auto& path = GetEventPath();
    bool saw_disabled_control = false;
    for (unsigned i = 0; i < path.size(); i++) {
      auto& node = path[i].GetNode();
      if (saw_disabled_control && node.WillRespondToMouseClickEvents()) {
        UseCounter::Count(
            node.GetDocument(),
            WebFeature::kParentOfDisabledFormControlRespondsToMouseEvents);
      }
      if (IsDisabledFormControl(&node))
        saw_disabled_control = true;
    }
  }

  DCHECK(!target() || target() != relatedTarget());

  EventTarget* related_target = relatedTarget();

  DispatchEventResult dispatch_result = dispatcher.Dispatch();

  if (!is_click || detail() != 2)
    return dispatch_result;

  // Special case: If it's a double click event, we also send the dblclick
  // event. This is not part of the DOM specs, but is used for compatibility
  // with the ondblclick="" attribute. This is treated as a separate event in
  // other DOM-compliant browsers like Firefox, and so we do the same.
  MouseEvent& double_click_event = *MouseEvent::Create();
  double_click_event.InitMouseEventInternal(
      event_type_names::kDblclick, bubbles(), cancelable(), view(), detail(),
      screenX(), screenY(), clientX(), clientY(), GetModifiers(), button(),
      related_target, sourceCapabilities(), buttons());
  double_click_event.SetComposed(composed());

  // Inherit the trusted status from the original event.
  double_click_event.SetTrusted(isTrusted());
  if (DefaultHandled())
    double_click_event.SetDefaultHandled();
  DispatchEventResult double_click_dispatch_result =
      EventDispatcher::DispatchEvent(dispatcher.GetNode(), double_click_event);
  if (double_click_dispatch_result != DispatchEventResult::kNotCanceled)
    return double_click_dispatch_result;
  return dispatch_result;
}

void MouseEvent::ReceivedTarget() {
  has_cached_relative_position_ = false;
}

void MouseEvent::ComputeRelativePosition() {
  Node* target_node = target() ? target()->ToNode() : nullptr;
  if (!target_node)
    return;

  // Compute coordinates that are based on the target.
  offset_x_ = page_x_;
  offset_y_ = page_y_;
  layer_location_ = gfx::PointF(page_x_, page_y_);

  LocalDOMWindow* dom_window_for_zoom_factor =
      DynamicTo<LocalDOMWindow>(view());
  if (!dom_window_for_zoom_factor)
    dom_window_for_zoom_factor = target_node->GetDocument().domWindow();

  float zoom_factor = LayoutZoomFactor(dom_window_for_zoom_factor);
  float inverse_zoom_factor = 1 / zoom_factor;

  // Must have an updated layout tree for this math to work correctly.
  target_node->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kInput);

  // Adjust offsetLocation to be relative to the target's padding box.
  if (const LayoutObject* layout_object = FindTargetLayoutObject(target_node)) {
    gfx::PointF local_pos =
        layout_object->AbsoluteToLocalPoint(AbsoluteLocation());

    if (layout_object->IsInline()) {
      UseCounter::Count(
          target_node->GetDocument(),
          WebFeature::kMouseEventRelativePositionForInlineElement);
    }

    // Adding this here to address crbug.com/570666. Basically we'd like to
    // find the local coordinates relative to the padding box not the border
    // box.
    if (layout_object->IsBoxModelObject()) {
      const auto* layout_box = To<LayoutBoxModelObject>(layout_object);
      local_pos.Offset(-layout_box->BorderLeft(), -layout_box->BorderTop());
    }

    offset_x_ = local_pos.x() * inverse_zoom_factor;
    offset_y_ = local_pos.y() * inverse_zoom_factor;
  }

  // Adjust layerLocation to be relative to the layer.
  // FIXME: event.layerX and event.layerY are poorly defined,
  // and probably don't always correspond to PaintLayer offsets.
  // https://bugs.webkit.org/show_bug.cgi?id=21868
  Node* n = target_node;
  while (n && !n->GetLayoutObject())
    n = n->parentNode();

  if (n) {
    layer_location_.Scale(zoom_factor);
    if (LocalFrameView* view = n->GetLayoutObject()->View()->GetFrameView())
      layer_location_ = view->DocumentToFrame(layer_location_);

    PaintLayer* layer = n->GetLayoutObject()->EnclosingLayer();
    layer = layer->EnclosingSelfPaintingLayer();

    PhysicalOffset physical_offset =
        layer->GetLayoutObject().LocalToAbsolutePoint(PhysicalOffset(),
                                                      kIgnoreTransforms);
    layer_location_ -= gfx::Vector2dF(physical_offset);

    layer_location_.Scale(inverse_zoom_factor);
  }

  has_cached_relative_position_ = true;
}

void MouseEvent::RecordLayerXYMetrics() {
  Node* node = target() ? target()->ToNode() : nullptr;
  if (!node)
    return;
  // Using the target for these metrics is a heuristic for measuring the impact
  // of https://crrev.com/370604#c57. The heuristic will be accurate for canvas
  // elements which do not have children, but will undercount the impact on
  // child elements (e.g., descendants of frames).
  if (IsA<HTMLMediaElement>(node)) {
    UseCounter::Count(node->GetDocument(), WebFeature::kLayerXYWithMediaTarget);
  } else if (IsA<HTMLCanvasElement>(node)) {
    UseCounter::Count(node->GetDocument(),
                      WebFeature::kLayerXYWithCanvasTarget);
  } else if (IsA<HTMLFrameElementBase>(node)) {
    UseCounter::Count(node->GetDocument(), WebFeature::kLayerXYWithFrameTarget);
  } else if (IsA<SVGElement>(node)) {
    UseCounter::Count(node->GetDocument(), WebFeature::kLayerXYWithSVGTarget);
  }
}

int MouseEvent::layerX() {
  if (!has_cached_relative_position_)
    ComputeRelativePosition();

  RecordLayerXYMetrics();

  return ClampTo<int>(std::floor(layer_location_.x()));
}

int MouseEvent::layerY() {
  if (!has_cached_relative_position_)
    ComputeRelativePosition();

  RecordLayerXYMetrics();

  return ClampTo<int>(std::floor(layer_location_.y()));
}

double MouseEvent::offsetX() const {
  if (!HasPosition())
    return 0;
  if (!has_cached_relative_position_)
    const_cast<MouseEvent*>(this)->ComputeRelativePosition();
  return std::round(offset_x_);
}

double MouseEvent::offsetY() const {
  if (!HasPosition())
    return 0;
  if (!has_cached_relative_position_)
    const_cast<MouseEvent*>(this)->ComputeRelativePosition();
  return std::round(offset_y_);
}

}  // namespace blink

"""

```