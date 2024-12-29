Response:
My thinking process to analyze the provided C++ code snippet for `mouse_event_manager.cc` follows these steps:

1. **Identify the Core Responsibility:** The filename and the initial comments clearly indicate this file manages mouse events within the Blink rendering engine. This will be the central theme of the analysis.

2. **Scan Includes for Clues:**  The included header files provide a wealth of information about the functionalities the class interacts with. I categorize them mentally:
    * **Platform/Input:** `WebInputEventResult`, `WebMouseEvent`, `WebGestureEvent`, `InputDeviceCapabilities` -  Deals with raw input events.
    * **Bindings/V8:** `V8DragEventInit`, `V8PointerEventInit` - Suggests interaction with JavaScript event handling.
    * **Clipboard:** `DataObject`, `DataTransfer`, `DataTransferAccessPolicy` - Points to drag-and-drop functionality.
    * **DOM:** `Element`, `Node`, `LocalDOMWindow` -  Indicates manipulation and interaction with the Document Object Model.
    * **Editing:**  `EditingUtilities`, `EphemeralRange`, `FrameSelection`, `SelectionController`, `VisibleSelection` - Shows involvement in text selection and editing.
    * **Events:** `DragEvent`, `MouseEvent`, `PointerEventFactory`, `WebInputEventConversion` - Deals with creating and dispatching various event types.
    * **Frame:** `LocalFrame`, `LocalFrameView`, `Settings` - Implies interaction with the frame structure of a web page.
    * **HTML:** `HTMLLabelElement`, `HTMLImageElement` - Hints at specific HTML element handling.
    * **Input:** `EventHandler`, `EventHandlingUtil`, `KeyboardEventManager` - Interaction with broader input handling mechanisms.
    * **Layout:** `HitTestResult`, `LayoutView` - Connection to the rendering layout process.
    * **Page:** `AutoscrollController`, `DragController`, `DragState`, `FocusController`, `Page`, `PointerLockController` - Indicates involvement in page-level features and states.
    * **Paint:** `PaintLayer`, `PaintLayerScrollableArea`, `PaintTiming` - Interaction with rendering layers.
    * **SVG:** `SVGDocumentExtensions` - Special handling for SVG documents.
    * **Timing:** `EventTiming` -  Timing information for events.
    * **Features:** `RuntimeEnabledFeatures` - Handling of experimental or conditional features.

3. **Analyze Class Members:**  The private members of `MouseEventManager` offer further insight:
    * `frame_`, `scroll_manager_`: Direct references to associated frame and scroll management.
    * `element_under_mouse_`, `original_element_under_mouse_removed_`:  Tracking the element the mouse is currently over, and whether it was removed. Crucial for hover states and boundary events.
    * `mouse_press_node_`: The node where the mouse button was initially pressed. Important for click and drag logic.
    * `mouse_down_may_start_autoscroll_`, `mouse_down_may_start_drag_`: Flags to determine potential actions based on the mouse down event.
    * `mouse_pressed_`:  Boolean indicating if a mouse button is currently held down.
    * `click_count_`:  Tracks the number of consecutive clicks.
    * `mousedown_element_`: The element where the `mousedown` event occurred.
    * `mouse_down_pos_`, `mouse_down_timestamp_`, `mouse_down_`: Store information about the last `mousedown` event.
    * `svg_pan_`:  Indicates if panning is active in an SVG document.
    * `drag_start_pos_in_root_frame_`: The position where a drag operation started.
    * `hover_state_dirty_`: A flag indicating that the hover state needs to be recalculated.
    * `last_known_mouse_*`, `is_mouse_position_unknown_`:  Store the last known mouse position.
    * Drag-related members (`drag_source_`, `dnd_operation_`, `drag_data_transfer_`) confirm involvement in drag-and-drop.

4. **Examine Public Methods:** The public methods reveal the main actions the `MouseEventManager` performs:
    * `Clear()`: Resets the state of the manager.
    * `DispatchMouseEvent()`: The core method for sending mouse events to JavaScript.
    * `SetElementUnderMouse()`: Updates the element the mouse is over and dispatches boundary events.
    * `HandleMousePressEvent()`, `HandleMouseReleaseEvent()`, `HandleMouseMoveEvent()` (not in this snippet, but implied):  The primary handlers for raw mouse events.
    * `HandleDragDropIfPossible()`: Deals with drag-and-drop gestures.
    * Methods related to hover state (`RecomputeMouseHoverStateIfNeeded`, `MarkHoverStateDirty`).
    * Methods for getting and setting the mouse position.

5. **Connect the Dots and Infer Functionality:**  Based on the includes, members, and methods, I synthesize the functionalities:
    * **Receiving and Processing Raw Mouse Events:** The manager receives `WebMouseEvent` from the platform.
    * **Hit Testing:**  Implicitly, it works with hit-testing results to determine the target element.
    * **Event Dispatching:**  It creates and dispatches `MouseEvent` and `PointerEvent` to JavaScript using the DOM event system. It handles bubbling and capturing.
    * **Hover Effects:** It tracks the element under the mouse to trigger `:hover` styles and dispatch `mouseover`/`mouseout`/`mouseenter`/`mouseleave` events.
    * **Click Handling:** It manages click counts and dispatches `click` and `auxclick` events, taking into account context menu behavior.
    * **Drag and Drop:** It initiates and manages drag-and-drop operations, interacting with `DragController` and `DataTransfer`.
    * **Text Selection:** It collaborates with `SelectionController` to handle text selection initiated by mouse gestures.
    * **Autoscroll:** It integrates with `AutoscrollController` to enable automatic scrolling during selection or drag operations.
    * **Focus Management:** It influences focus behavior based on mouse clicks, particularly related to form elements and shadow DOM.
    * **SVG Pan:** It provides special handling for panning within SVG documents.

6. **Identify Relationships with JavaScript, HTML, and CSS:**
    * **JavaScript:** The core function is dispatching events that JavaScript event listeners can catch. The `MouseEventInit` and `PointerEventInit` structures directly map to JavaScript event objects.
    * **HTML:** The manager operates on `Element` and `Node` objects, directly representing HTML elements. It handles events specific to certain HTML elements like `<label>`.
    * **CSS:** The hover state management directly influences the application of CSS `:hover` styles.

7. **Consider Logic and Examples:**
    * **Hover:**  Mouse moves over an element -> `SetElementUnderMouse` called -> `mouseover` event dispatched on the new element, `mouseout` on the old.
    * **Click:** `mousedown` on an element -> `mouseup` on the same element (or a descendant) -> `click` event dispatched.
    * **Drag:** `mousedown` and drag -> `dragstart`, `drag`, `dragenter`, `dragleave`, `dragover`, `drop`, `dragend` events.

8. **Think About User/Programming Errors:**
    * Forgetting to prevent default behavior in a `mousedown` handler might lead to unexpected browser behavior like text selection.
    * Incorrectly handling drag events can cause drag-and-drop to fail.

9. **Trace User Actions:**  Consider the sequence of events from a user's perspective leading to this code:
    * User moves the mouse -> Mouse driver -> Operating System -> Browser's input handling -> Blink's input pipeline -> `MouseEventManager`.
    * User clicks a button -> Similar flow.
    * User drags an element -> Similar flow involving gesture recognition.

10. **Summarize the Functionality (for Part 1):**  Focus on the core responsibilities identified earlier, emphasizing the event handling and interaction with the DOM. Avoid going into too much detail about features that might be covered in Part 2.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and accurate description of its functionality and relationships with other web technologies.
好的，我们来分析一下 `blink/renderer/core/input/mouse_event_manager.cc` 文件的功能。

**文件功能归纳:**

`MouseEventManager` 类主要负责处理和分发鼠标事件。它的核心职责是接收来自底层系统的鼠标事件，确定事件的目标，并将其转换为可以在 Blink 渲染引擎中使用的 `MouseEvent` 或 `PointerEvent` 对象，最终将这些事件分发到相应的 DOM 元素上。

**具体功能点:**

1. **接收和预处理鼠标事件:**
   - 接收来自 Chromium 平台层的 `WebMouseEvent` 结构体，这些结构体包含了原始的鼠标事件信息（例如，鼠标位置、按键状态、修饰键等）。
   - 维护鼠标位置信息，例如最后一次已知的位置和屏幕坐标。
   - 判断鼠标位置是否未知（例如，鼠标移出浏览器窗口）。

2. **确定鼠标事件目标:**
   -  `MouseEventManager` 并不直接进行 hit-testing (命中测试，确定哪个元素在鼠标下方)，这通常由更底层的模块完成。但是，它维护着鼠标下方的元素 (`element_under_mouse_`)。
   -  处理鼠标移入和移出元素的情况，并分发 `mouseover`、`mouseout`、`mouseenter` 和 `mouseleave` 事件。

3. **创建和分发鼠标事件对象:**
   -  根据 `WebMouseEvent` 的类型（`mousedown`、`mouseup`、`mousemove`、`click` 等）创建对应的 `MouseEvent` 或 `PointerEvent` 对象。
   -  设置事件对象的属性，例如坐标、按键状态、修饰键、点击次数、相关目标等。
   -  使用 `target->DispatchEvent()` 方法将事件分发到目标元素。

4. **处理点击事件:**
   -  跟踪点击次数 (`click_count_`)，用于区分单击和双击等。
   -  判断是否应该分发 `click` 或 `auxclick` 事件（例如，左键单击 vs. 中键/右键单击）。
   -  考虑上下文菜单事件的情况，可能阻止 `click` 事件的派发。

5. **处理拖拽事件:**
   -  检测鼠标按下是否可能启动拖拽操作 (`mouse_down_may_start_drag_`)。
   -  记录拖拽开始的位置。
   -  与 `DragController` 协作处理拖拽相关的事件（虽然这部分代码片段中没有直接展示）。

6. **处理文本选择:**
   -  与 `SelectionController` 协作，处理鼠标按下和拖动时的文本选择。
   -  判断鼠标按下是否可能开始文本选择 (`frame_->GetEventHandler().GetSelectionController().MouseDownMayStartSelect()`)。

7. **处理自动滚动 (Autoscroll):**
   -  检测鼠标按下是否可能启动自动滚动 (`mouse_down_may_start_autoscroll_`)，例如在选择文本时拖动到窗口边缘。
   -  与 `AutoscrollController` 协作。

8. **处理焦点:**
   -  在鼠标按下时，根据点击位置的元素是否可聚焦来处理焦点转移。
   -  考虑 `<label>` 元素与其关联控件的焦点处理。

9. **处理 SVG 特有的交互:**
   -  支持 SVG 文档的平移 (pan) 功能。

10. **维护鼠标悬停状态:**
    - 跟踪鼠标下的元素，用于触发 `:hover` CSS 样式。
    - `MarkHoverStateDirty()` 和 `RecomputeMouseHoverStateIfNeeded()` 用于优化悬停状态的更新。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    - `MouseEventManager` 最终会将鼠标事件转换为可以在 JavaScript 中被监听和处理的 `MouseEvent` 或 `PointerEvent` 对象。
    - **举例:** 当用户点击一个按钮时，`MouseEventManager` 会创建一个 `click` 事件对象，并将其分发到该按钮对应的 DOM 元素上。JavaScript 中可以通过 `button.addEventListener('click', function(event) { ... });` 来监听和处理这个事件。
    - **代码关联:** 文件中包含了 `third_party/blink/renderer/bindings/core/v8/v8_drag_event_init.h` 和 `third_party/blink/renderer/bindings/core/v8/v8_pointer_event_init.h`，这表明它使用 V8 绑定来创建可以传递给 JavaScript 的事件对象。

* **HTML:**
    - `MouseEventManager` 操作的对象是 HTML 元素 (`Element`) 和节点 (`Node`)。它需要确定鼠标事件发生在哪个 HTML 元素上，并将事件分发到该元素。
    - **举例:** 用户鼠标移动到一个 `<div>` 元素上，`MouseEventManager` 会检测到这个事件，并将 `mouseover` 事件分发到该 `<div>` 元素上。
    - **代码关联:** 文件中大量使用了 `Element*` 和 `Node*` 类型的变量，例如 `element_under_mouse_`、`mouse_press_node_` 等。

* **CSS:**
    - `MouseEventManager` 的鼠标悬停状态管理直接影响 CSS 的 `:hover` 伪类的效果。当鼠标移动到一个元素上时，`MouseEventManager` 会更新悬停状态，浏览器会根据 CSS 规则应用相应的样式。
    - **举例:** CSS 规则 `div:hover { background-color: red; }` 的生效依赖于 `MouseEventManager` 正确地识别出鼠标当前悬停在 `<div>` 元素上。
    - **代码关联:** `MarkHoverStateDirty()` 和 `RecomputeMouseHoverStateIfNeeded()` 方法的存在表明了它负责维护影响 CSS 渲染的状态。

**逻辑推理与假设输入输出:**

**假设输入:** 用户在浏览器窗口的 (100, 200) 坐标处点击鼠标左键。

**逻辑推理步骤:**

1. **平台层捕获事件:** 操作系统或浏览器平台层捕获到鼠标按下事件，创建 `WebMouseEvent` 对象，包含类型为 `kMouseDown`，位置为 (100, 200)，左键按下等信息。
2. **事件传递到 Blink:** 该 `WebMouseEvent` 被传递到 Blink 渲染引擎。
3. **`MouseEventManager` 接收事件:** `MouseEventManager` 的某个处理函数（例如，`HandleMousePressEvent`，虽然这个代码片段中没有完整展示）接收到这个 `WebMouseEvent`。
4. **Hit-testing (未在此代码中):**  Blink 的其他模块会进行 hit-testing，确定 (100, 200) 坐标下的 DOM 元素，假设是 `<button id="myButton">Click Me</button>`。
5. **设置 `mouse_press_node_`:** `MouseEventManager` 会将 `mouse_press_node_` 设置为该 `<button>` 元素对应的 `Element` 对象。
6. **创建 `MouseEvent` 或 `PointerEvent`:**  `MouseEventManager` 创建一个 `MouseEvent` 或 `PointerEvent` 对象，类型为 `mousedown`，坐标设置为 (100, 200)，`button` 属性表示左键被按下。
7. **事件分发:** `MouseEventManager` 调用 `buttonElement->DispatchEvent(mouseEvent)` 将事件分发到 `<button>` 元素。
8. **JavaScript 处理:** 如果 JavaScript 中有为该按钮注册的 `mousedown` 事件监听器，该监听器会被触发。

**假设输出:** 如果有 JavaScript 代码 `document.getElementById('myButton').addEventListener('mousedown', function(event) { console.log('Mouse down on button!'); });`，那么控制台会输出 "Mouse down on button!"。

**用户或编程常见的使用错误举例:**

1. **忘记阻止默认行为:**  在 JavaScript 的鼠标事件监听器中，如果没有调用 `event.preventDefault()`，可能会导致浏览器执行默认行为。
   - **例子:**  在一个链接的 `mousedown` 事件监听器中，如果忘记调用 `preventDefault()`，用户点击链接后，除了执行自定义的 JavaScript 代码外，还会导航到链接指向的 URL。
   - **到达 `MouseEventManager` 的路径:** 用户点击链接 -> 浏览器生成 `mousedown` 事件 -> `MouseEventManager` 分发 `mousedown` 事件到链接元素 -> JavaScript 监听器执行（可能没有阻止默认行为） ->  浏览器继续处理 `mousedown` 的默认行为。

2. **错误地假设事件目标:**  开发者可能会错误地假设鼠标事件总是发生在他们期望的元素上，而忽略了事件冒泡或捕获阶段。
   - **例子:**  在一个包含多个子元素的容器上监听点击事件，如果没有正确处理事件委托，可能会在点击子元素时得到错误的事件目标。
   - **到达 `MouseEventManager` 的路径:** 用户点击子元素 -> 浏览器生成 `mousedown` 和 `mouseup` 事件 -> `MouseEventManager` 根据 hit-testing 确定初始目标（子元素） -> 事件冒泡到父元素 -> 父元素的监听器被触发。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户移动鼠标:**  用户的物理鼠标移动被操作系统捕获。
2. **操作系统传递事件:** 操作系统将鼠标移动事件（包含坐标）传递给浏览器进程。
3. **浏览器进程处理:** 浏览器进程接收到事件，并将其转换为平台独立的 `WebMouseEvent` 结构。
4. **事件传递到渲染进程:**  对于网页内容区域的鼠标事件，浏览器进程将 `WebMouseEvent` 发送到负责渲染该网页的渲染进程。
5. **Blink 接收事件:** 渲染进程中的 Blink 引擎接收到 `WebMouseEvent`。
6. **事件分发到 `MouseEventManager`:**  Blink 的输入处理管道将 `WebMouseEvent` 传递给 `MouseEventManager` 进行处理。
7. **`MouseEventManager` 处理:** `MouseEventManager` 根据事件类型和目标进行相应的处理，例如更新鼠标位置、分发事件等。

**作为调试线索，可以关注以下几点:**

* **事件类型:** 确定是哪个类型的鼠标事件触发了代码执行（`mousedown`、`mouseup`、`mousemove` 等）。
* **鼠标坐标:** 检查鼠标事件的坐标是否符合预期。
* **事件目标:**  确认事件被分发到了正确的 DOM 元素。
* **事件属性:**  检查事件对象的其他属性，例如按键状态、修饰键等，是否正确。
* **调用栈:**  通过调试工具查看调用栈，可以了解事件是如何一步步传递到 `MouseEventManager` 的。

**第 1 部分功能归纳:**

`MouseEventManager` 的主要功能是**接收、处理和分发底层产生的鼠标事件，将其转换为 Blink 引擎可以使用的 `MouseEvent` 或 `PointerEvent` 对象，并最终传递给相应的 DOM 元素进行处理。**  它负责维护鼠标状态、处理点击和拖拽等交互，并与 JavaScript、HTML 和 CSS 的事件模型紧密相关。

Prompt: 
```
这是目录为blink/renderer/core/input/mouse_event_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/input/mouse_event_manager.h"

#include "build/build_config.h"
#include "third_party/blink/public/platform/web_input_event_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_drag_event_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_pointer_event_init.h"
#include "third_party/blink/renderer/core/clipboard/data_object.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer_access_policy.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_controller.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/events/drag_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/events/pointer_event_factory.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_label_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/event_handling_util.h"
#include "third_party/blink/renderer/core/input/input_device_capabilities.h"
#include "third_party/blink/renderer/core/input/keyboard_event_manager.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/drag_controller.h"
#include "third_party/blink/renderer/core/page/drag_state.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/svg/svg_document_extensions.h"
#include "third_party/blink/renderer/core/timing/event_timing.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/gfx/geometry/point_conversions.h"

namespace blink {

namespace {

void UpdateMouseMovementXY(const WebMouseEvent& mouse_event,
                           const gfx::PointF* last_position,
                           LocalDOMWindow* dom_window,
                           MouseEventInit* initializer) {
  if (!mouse_event.is_raw_movement_event &&
      mouse_event.GetType() == WebInputEvent::Type::kMouseMove &&
      last_position) {
    // movementX/Y is type int for now, so we need to truncated the coordinates
    // before calculate movement.
    initializer->setMovementX(
        base::saturated_cast<int>(mouse_event.PositionInScreen().x()) -
        base::saturated_cast<int>(last_position->x()));
    initializer->setMovementY(
        base::saturated_cast<int>(mouse_event.PositionInScreen().y()) -
        base::saturated_cast<int>(last_position->y()));
  }
}

void SetMouseEventAttributes(MouseEventInit* initializer,
                             Node* target_node,
                             const AtomicString& mouse_event_type,
                             const WebMouseEvent& mouse_event,
                             const gfx::PointF* last_position,
                             EventTarget* related_target,
                             int click_count) {
  bool is_mouse_enter_or_leave =
      mouse_event_type == event_type_names::kMouseenter ||
      mouse_event_type == event_type_names::kMouseleave;

  initializer->setBubbles(!is_mouse_enter_or_leave);
  initializer->setCancelable(!is_mouse_enter_or_leave);
  MouseEvent::SetCoordinatesFromWebPointerProperties(
      mouse_event.FlattenTransform(), target_node->GetDocument().domWindow(),
      initializer);
  UpdateMouseMovementXY(mouse_event, last_position,
                        target_node->GetDocument().domWindow(), initializer);
  initializer->setButton(static_cast<int16_t>(mouse_event.button));
  initializer->setButtons(
      MouseEvent::WebInputEventModifiersToButtons(mouse_event.GetModifiers()));
  initializer->setView(target_node->GetDocument().domWindow());
  initializer->setComposed(!is_mouse_enter_or_leave);
  initializer->setDetail(click_count);
  initializer->setRelatedTarget(related_target);
  UIEventWithKeyState::SetFromWebInputEventModifiers(
      initializer,
      static_cast<WebInputEvent::Modifiers>(mouse_event.GetModifiers()));
  initializer->setSourceCapabilities(
      target_node->GetDocument().domWindow()
          ? target_node->GetDocument()
                .domWindow()
                ->GetInputDeviceCapabilities()
                ->FiresTouchEvents(mouse_event.FromTouch())
          : nullptr);
}

// TODO(crbug.com/653490): Read these values from the OS.
#if BUILDFLAG(IS_MAC)
const int kDragThresholdX = 3;
const int kDragThresholdY = 3;
constexpr base::TimeDelta kTextDragDelay = base::Seconds(0.15);
#else
const int kDragThresholdX = 4;
const int kDragThresholdY = 4;
constexpr base::TimeDelta kTextDragDelay = base::Seconds(0.0);
#endif

}  // namespace

enum class DragInitiator { kMouse, kTouch };

MouseEventManager::MouseEventManager(LocalFrame& frame,
                                     ScrollManager& scroll_manager)
    : frame_(frame),
      scroll_manager_(scroll_manager),
      is_mouse_position_unknown_(true) {
  Clear();
}

void MouseEventManager::Clear() {
  element_under_mouse_ = nullptr;
  original_element_under_mouse_removed_ = false;
  mouse_press_node_ = nullptr;
  mouse_down_may_start_autoscroll_ = false;
  mouse_down_may_start_drag_ = false;
  mouse_pressed_ = false;
  click_count_ = 0;
  mousedown_element_ = nullptr;
  mouse_down_pos_ = gfx::Point();
  mouse_down_timestamp_ = base::TimeTicks();
  mouse_down_ = WebMouseEvent();
  svg_pan_ = false;
  drag_start_pos_in_root_frame_ = PhysicalOffset();
  hover_state_dirty_ = false;

  // We deliberately avoid clearing mouse position fields (last_known_mouse_*
  // and is_mouse_position_unknown_) so that we can apply hover effects in the
  // new document after a navigation.  See crbug.com/354649089.

  ResetDragSource();
  ClearDragDataTransfer();
}

MouseEventManager::~MouseEventManager() = default;

void MouseEventManager::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(scroll_manager_);
  visitor->Trace(element_under_mouse_);
  visitor->Trace(mouse_press_node_);
  visitor->Trace(mousedown_element_);
  SynchronousMutationObserver::Trace(visitor);
}

MouseEventManager::MouseEventBoundaryEventDispatcher::
    MouseEventBoundaryEventDispatcher(MouseEventManager* mouse_event_manager,
                                      const WebMouseEvent* web_mouse_event)
    : BoundaryEventDispatcher(event_type_names::kMouseover,
                              event_type_names::kMouseout,
                              event_type_names::kMouseenter,
                              event_type_names::kMouseleave),
      mouse_event_manager_(mouse_event_manager),
      web_mouse_event_(web_mouse_event) {}

void MouseEventManager::MouseEventBoundaryEventDispatcher::Dispatch(
    EventTarget* target,
    EventTarget* related_target,
    const AtomicString& type,
    bool check_for_listener) {
  mouse_event_manager_->DispatchMouseEvent(target, type, *web_mouse_event_,
                                           nullptr, related_target,
                                           check_for_listener);
}

void MouseEventManager::SendBoundaryEvents(EventTarget* exited_target,
                                           bool original_exited_target_removed,
                                           EventTarget* entered_target,
                                           const WebMouseEvent& mouse_event) {
  MouseEventBoundaryEventDispatcher boundary_event_dispatcher(this,
                                                              &mouse_event);
  boundary_event_dispatcher.SendBoundaryEvents(
      exited_target, original_exited_target_removed, entered_target);
}

WebInputEventResult MouseEventManager::DispatchMouseEvent(
    EventTarget* target,
    const AtomicString& mouse_event_type,
    const WebMouseEvent& mouse_event,
    const gfx::PointF* last_position,
    EventTarget* related_target,
    bool check_for_listener,
    const PointerId& pointer_id,
    const String& pointer_type) {
  DCHECK(mouse_event_type == event_type_names::kMouseup ||
         mouse_event_type == event_type_names::kMousedown ||
         mouse_event_type == event_type_names::kMousemove ||
         mouse_event_type == event_type_names::kMouseout ||
         mouse_event_type == event_type_names::kMouseover ||
         mouse_event_type == event_type_names::kMouseleave ||
         mouse_event_type == event_type_names::kMouseenter ||
         mouse_event_type == event_type_names::kContextmenu ||
         mouse_event_type == event_type_names::kClick ||
         mouse_event_type == event_type_names::kAuxclick);

  WebInputEventResult input_event_result = WebInputEventResult::kNotHandled;

  if (target && target->ToNode()) {
    Node* target_node = target->ToNode();
    int click_count = 0;
    if (mouse_event_type == event_type_names::kMouseup ||
        mouse_event_type == event_type_names::kMousedown ||
        mouse_event_type == event_type_names::kClick ||
        mouse_event_type == event_type_names::kAuxclick) {
      click_count = click_count_;
    }
    std::optional<EventTiming> event_timing;
    bool should_dispatch =
        !check_for_listener || target->HasEventListeners(mouse_event_type);
    if (mouse_event_type == event_type_names::kContextmenu ||
        mouse_event_type == event_type_names::kClick ||
        mouse_event_type == event_type_names::kAuxclick) {
      PointerEventInit* initializer = PointerEventInit::Create();
      SetMouseEventAttributes(initializer, target_node, mouse_event_type,
                              mouse_event, last_position, related_target,
                              click_count);
      initializer->setPointerId(pointer_id);
      initializer->setPointerType(pointer_type);
      PointerEvent* event = PointerEvent::Create(
          mouse_event_type, initializer, mouse_event.TimeStamp(),
          mouse_event.FromTouch() ? MouseEvent::kFromTouch
                                  : MouseEvent::kRealOrIndistinguishable,
          mouse_event.menu_source_type);
      if (frame_ && frame_->DomWindow()) {
        event_timing =
            EventTiming::TryCreate(frame_->DomWindow(), *event, target);
      }
      if (should_dispatch) {
        input_event_result = event_handling_util::ToWebInputEventResult(
            target->DispatchEvent(*event));
      }
    } else {
      MouseEventInit* initializer = MouseEventInit::Create();
      SetMouseEventAttributes(initializer, target_node, mouse_event_type,
                              mouse_event, last_position, related_target,
                              click_count);
      MouseEvent* event = MouseEvent::Create(
          mouse_event_type, initializer, mouse_event.TimeStamp(),
          mouse_event.FromTouch() ? MouseEvent::kFromTouch
                                  : MouseEvent::kRealOrIndistinguishable,
          mouse_event.menu_source_type);
      if (frame_ && frame_->DomWindow()) {
        event_timing =
            EventTiming::TryCreate(frame_->DomWindow(), *event, target);
      }
      if (should_dispatch) {
        input_event_result = event_handling_util::ToWebInputEventResult(
            target->DispatchEvent(*event));
      }
    }
  }

  return input_event_result;
}

// TODO(https://crbug.com/1147674): This bypasses PointerEventManager states!
// This method is called only from GestureManager, and that's one of the reasons
// PointerEvents are incomplete for touch gesture.
WebInputEventResult
MouseEventManager::SetElementUnderMouseAndDispatchMouseEvent(
    Element* target_element,
    const AtomicString& event_type,
    const WebMouseEvent& web_mouse_event) {
  // This method is used by GestureManager::HandleGestureTap to apply hover
  // states based on the tap. Note that we do not want to update the cached
  // mouse position here (using SetLastKnownMousePosition), since that would
  // cause the hover state to stick to the tap's viewport coordinates after a
  // scroll.
  //
  // TODO(crbug.com/368256331): If there IS a cached mouse position, the hover
  // state will revert to it as soon as somebody calls MarkHoverStateDirty,
  // which isn't ideal.

  SetElementUnderMouse(target_element, web_mouse_event);
  return DispatchMouseEvent(
      element_under_mouse_, event_type, web_mouse_event, nullptr, nullptr,
      false, web_mouse_event.id,
      PointerEventFactory::PointerTypeNameForWebPointPointerType(
          web_mouse_event.pointer_type));
}

namespace {

bool HasClickListenersInAncestor(Node* node) {
  for (; node; node = FlatTreeTraversal::Parent(*node)) {
    if (node->HasEventListeners(event_type_names::kClick)) {
      return true;
    }
  }
  return false;
}

}  // namespace

WebInputEventResult MouseEventManager::DispatchMouseClickIfNeeded(
    Element* mouse_release_target,
    Element* captured_click_target,
    const WebMouseEvent& mouse_event,
    const PointerId& pointer_id,
    const String& pointer_type) {
  // We only prevent click event when the click may cause contextmenu to popup.
  // However, we always send auxclick.
  bool context_menu_event = false;
#if BUILDFLAG(IS_MAC)
  // FIXME: The Mac port achieves the same behavior by checking whether the
  // context menu is currently open in WebPage::mouseEvent(). Consider merging
  // the implementations.
  if (mouse_event.button == WebPointerProperties::Button::kLeft &&
      mouse_event.GetModifiers() & WebInputEvent::Modifiers::kControlKey)
    context_menu_event = true;
#endif

  const bool should_dispatch_click_event =
      click_count_ > 0 && !context_menu_event && mousedown_element_ &&
      mouse_release_target && mousedown_element_->isConnected();
  if (!should_dispatch_click_event)
    return WebInputEventResult::kNotHandled;

  Node* click_target_node = nullptr;
  Node* common_ancestor = mouse_release_target->CommonAncestor(
      *mousedown_element_, event_handling_util::ParentForClickEvent);

  if (RuntimeEnabledFeatures::ClickToCapturedPointerEnabled() &&
      captured_click_target) {
    click_target_node = captured_click_target;
  } else if (mousedown_element_->GetDocument() ==
             mouse_release_target->GetDocument()) {
    click_target_node = common_ancestor;
  }

  if (!click_target_node)
    return WebInputEventResult::kNotHandled;

  const AtomicString click_event_type =
      (mouse_event.button == WebPointerProperties::Button::kLeft)
          ? event_type_names::kClick
          : event_type_names::kAuxclick;

  if (captured_click_target && (common_ancestor != captured_click_target) &&
      (click_event_type == event_type_names::kClick) &&
      (HasClickListenersInAncestor(common_ancestor) ||
       HasClickListenersInAncestor(captured_click_target))) {
    UseCounter::Count(frame_->GetDocument(),
                      WebFeature::kExplicitPointerCaptureClickTargetDiff);
  }

  return DispatchMouseEvent(click_target_node, click_event_type, mouse_event,
                            nullptr, nullptr, false, pointer_id, pointer_type);
}

void MouseEventManager::RecomputeMouseHoverStateIfNeeded() {
  // |RecomputeMouseHoverState| may set |hover_state_dirty_| to be true.
  if (HoverStateDirty()) {
    hover_state_dirty_ = false;
    RecomputeMouseHoverState();
  }
}

void MouseEventManager::RecomputeMouseHoverState() {
  if (is_mouse_position_unknown_)
    return;

  LocalFrameView* view = frame_->View();
  if (!view)
    return;

  if (!frame_->GetPage() || !frame_->GetPage()->GetFocusController().IsActive())
    return;

  // Don't dispatch a synthetic mouse move event if the mouse cursor is not
  // visible to the user.
  if (!frame_->GetPage()->IsCursorVisible())
    return;

  // Don't dispatch a synthetic event if pointer is locked.
  if (frame_->GetPage()->GetPointerLockController().GetElement())
    return;

  WebPointerEvent::Button button = WebPointerProperties::Button::kNoButton;
  int modifiers = KeyboardEventManager::GetCurrentModifierState() |
                  WebInputEvent::kRelativeMotionEvent;
  if (mouse_pressed_) {
    button = WebPointerProperties::Button::kLeft;
    modifiers |= WebInputEvent::kLeftButtonDown;
  }
  WebMouseEvent fake_mouse_move_event(WebInputEvent::Type::kMouseMove,
                                      last_known_mouse_position_,
                                      last_known_mouse_screen_position_, button,
                                      0, modifiers, base::TimeTicks::Now());
  Vector<WebMouseEvent> coalesced_events, predicted_events;
  frame_->GetEventHandler().HandleMouseMoveEvent(
      TransformWebMouseEvent(view, fake_mouse_move_event), coalesced_events,
      predicted_events);
}

void MouseEventManager::MarkHoverStateDirty() {
  DCHECK(frame_->IsLocalRoot());
  hover_state_dirty_ = true;
}

bool MouseEventManager::HoverStateDirty() {
  DCHECK(frame_->IsLocalRoot());
  return hover_state_dirty_;
}

void MouseEventManager::SetElementUnderMouse(
    Element* target,
    const WebMouseEvent& web_mouse_event) {
  CHECK(
      !original_element_under_mouse_removed_ ||
      RuntimeEnabledFeatures::BoundaryEventDispatchTracksNodeRemovalEnabled());

  Element* last_element_under_mouse = element_under_mouse_;
  bool original_last_element_under_mouse_removed =
      original_element_under_mouse_removed_;

  element_under_mouse_ = target;
  // Clear the "removed" state for the updated `element_under_mouse_`.
  original_element_under_mouse_removed_ = false;

  // TODO(mustaq): Why do we need the `ScrollableArea` code below and not in
  // `PointerEventManager::SetElementUnderPointer()`?
  PaintLayer* layer_for_last_node =
      event_handling_util::LayerForNode(last_element_under_mouse);
  PaintLayer* layer_for_node_under_mouse =
      event_handling_util::LayerForNode(element_under_mouse_.Get());
  Page* page = frame_->GetPage();

  if (page && (layer_for_last_node &&
               (!layer_for_node_under_mouse ||
                layer_for_node_under_mouse != layer_for_last_node))) {
    // The mouse has moved between layers.
    if (ScrollableArea* scrollable_area_for_last_node =
            event_handling_util::AssociatedScrollableArea(layer_for_last_node))
      scrollable_area_for_last_node->MouseExitedContentArea();
  }

  if (page && (layer_for_node_under_mouse &&
               (!layer_for_last_node ||
                layer_for_node_under_mouse != layer_for_last_node))) {
    // The mouse has moved between layers.
    if (ScrollableArea* scrollable_area_for_node_under_mouse =
            event_handling_util::AssociatedScrollableArea(
                layer_for_node_under_mouse))
      scrollable_area_for_node_under_mouse->MouseEnteredContentArea();
  }

  if (last_element_under_mouse &&
      last_element_under_mouse->GetDocument() != frame_->GetDocument()) {
    last_element_under_mouse = nullptr;
  }

  SendBoundaryEvents(last_element_under_mouse,
                     original_last_element_under_mouse_removed,
                     element_under_mouse_, web_mouse_event);
}

void MouseEventManager::NodeChildrenWillBeRemoved(ContainerNode& container) {
  if (RuntimeEnabledFeatures::BoundaryEventDispatchTracksNodeRemovalEnabled()) {
    return;
  }
  if (container == mousedown_element_) {
    return;
  }
  if (!mousedown_element_ ||
      !container.IsShadowIncludingInclusiveAncestorOf(*mousedown_element_)) {
    return;
  }
  mousedown_element_ = nullptr;
}

void MouseEventManager::NodeWillBeRemoved(Node& node_to_be_removed) {
  if (mousedown_element_ &&
      node_to_be_removed.IsShadowIncludingInclusiveAncestorOf(
          *mousedown_element_)) {
    // We don't dispatch click events if the mousedown node is removed
    // before a mouseup event. It is compatible with IE and Firefox.
    mousedown_element_ = nullptr;
  }
  if (mouse_press_node_ &&
      node_to_be_removed.IsShadowIncludingInclusiveAncestorOf(
          *mouse_press_node_)) {
    // If the mouse_press_node_ is removed, we should dispatch future default
    // keyboard actions (i.e. scrolling) to the still connected parent.
    mouse_press_node_ = node_to_be_removed.parentNode();
  }
  if (RuntimeEnabledFeatures::BoundaryEventDispatchTracksNodeRemovalEnabled() &&
      element_under_mouse_ &&
      node_to_be_removed.IsShadowIncludingInclusiveAncestorOf(
          *element_under_mouse_)) {
    element_under_mouse_ = node_to_be_removed.parentElement();
    original_element_under_mouse_removed_ = true;
  }
}

Element* MouseEventManager::GetElementUnderMouse() {
  return element_under_mouse_.Get();
}

WebInputEventResult MouseEventManager::HandleMouseFocus(
    const HitTestResult& hit_test_result,
    InputDeviceCapabilities* source_capabilities) {
  // If clicking on a frame scrollbar, do not mess up with content focus.
  if (auto* layout_view = frame_->ContentLayoutObject()) {
    if (hit_test_result.GetScrollbar() && frame_->ContentLayoutObject()) {
      if (hit_test_result.GetScrollbar()->GetLayoutBox() == layout_view) {
        return WebInputEventResult::kNotHandled;
      }
    }
  }

  // The layout needs to be up to date to determine if an element is focusable.
  frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kFocus);

  Element* element = element_under_mouse_;

  if (!RuntimeEnabledFeatures::LabelAndDelegatesFocusNewHandlingEnabled()) {
    // When clicking on a <label> for a form associated custom element with
    // delegatesFocus, we should focus the custom element's focus delegate.
    if (auto* label = DynamicTo<HTMLLabelElement>(element)) {
      auto* control = label->Control();
      if (control && control->IsShadowHostWithDelegatesFocus()) {
        element = control;
      }
    }
  }

  while (element) {
    if (element->IsMouseFocusable() && element->IsFocusedElementInDocument()) {
      return WebInputEventResult::kNotHandled;
    }
    if (element->IsMouseFocusable() ||
        element->IsShadowHostWithDelegatesFocus()) {
      break;
    }
    if (RuntimeEnabledFeatures::MouseFocusFlatTreeParentEnabled()) {
      element = FlatTreeTraversal::ParentElement(*element);
    } else {
      element = element->ParentOrShadowHostElement();
    }
  }
  DCHECK(!element || element->IsMouseFocusable() ||
         element->IsShadowHostWithDelegatesFocus());

  // To fix <rdar://problem/4895428> Can't drag selected ToDo, we don't focus
  // a node on mouse down if it's selected and inside a focused node. It will
  // be focused if the user does a mouseup over it, however, because the
  // mouseup will set a selection inside it, which will call
  // FrameSelection::setFocusedNodeIfNeeded.
  // TODO(editing-dev): The use of VisibleSelection should be audited. See
  // crbug.com/657237 for details.
  if (element &&
      frame_->Selection().ComputeVisibleSelectionInDOMTree().IsRange()) {
    // Don't check for scroll controls pseudo elements, since they can't
    // be in selection, until we support selecting their content.
    // Just clear the selection, since it won't be cleared otherwise.
    if (RuntimeEnabledFeatures::PseudoElementsFocusableEnabled() &&
        element->IsScrollControlPseudoElement()) {
      frame_->Selection().Clear();
    } else {
      const EphemeralRange& range = frame_->Selection()
                                        .ComputeVisibleSelectionInDOMTree()
                                        .ToNormalizedEphemeralRange();
      if (IsNodeFullyContained(range, *element) &&
          element->IsDescendantOf(frame_->GetDocument()->FocusedElement())) {
        return WebInputEventResult::kNotHandled;
      }
    }
  }

  // Only change the focus when clicking scrollbars if it can transfered to a
  // mouse focusable node.
  if (!element && hit_test_result.GetScrollbar())
    return WebInputEventResult::kHandledSystem;

  Page* const page = frame_->GetPage();
  if (!page)
    return WebInputEventResult::kNotHandled;

  // If focus shift is blocked, we eat the event. Note we should never
  // clear swallowEvent if the page already set it (e.g., by canceling
  // default behavior).
  if (element && !element->IsMouseFocusable() &&
      SlideFocusOnShadowHostIfNecessary(*element)) {
    return RuntimeEnabledFeatures::
                   SelectionOnShadowDOMWithDelegatesFocusEnabled()
               ? WebInputEventResult::kNotHandled
               : WebInputEventResult::kHandledSystem;
  }

  // We call setFocusedElement even with !element in order to blur
  // current focus element when a link is clicked; this is expected by
  // some sites that rely on onChange handlers running from form
  // fields before the button click is processed.
  if (!page->GetFocusController().SetFocusedElement(
          element, frame_,
          FocusParams(SelectionBehaviorOnFocus::kNone,
                      mojom::blink::FocusType::kMouse, source_capabilities)))
    return WebInputEventResult::kHandledSystem;
  return WebInputEventResult::kNotHandled;
}

bool MouseEventManager::SlideFocusOnShadowHostIfNecessary(
    const Element& element) {
  if (Element* delegated_target = element.GetFocusableArea()) {
    // Use FocusType::kMouse instead of FocusType::kForward
    // in order to prevent :focus-visible from being set
    delegated_target->Focus(FocusParams(
        SelectionBehaviorOnFocus::kReset, mojom::blink::FocusType::kMouse,
        nullptr, FocusOptions::Create(), FocusTrigger::kUserGesture));
    return true;
  }
  return false;
}

void MouseEventManager::HandleMouseReleaseEventUpdateStates() {
  ClearDragHeuristicState();
  InvalidateClick();
  frame_->GetEventHandler().GetSelectionController().SetMouseDownMayStartSelect(
      false);
}

void MouseEventManager::HandleMousePressEventUpdateStates(
    const WebMouseEvent& mouse_event) {
  mouse_pressed_ = true;
  SetLastKnownMousePosition(mouse_event);
  mouse_down_may_start_drag_ = false;
  mouse_down_may_start_autoscroll_ = false;
  mouse_down_timestamp_ = mouse_event.TimeStamp();

  if (LocalFrameView* view = frame_->View()) {
    mouse_down_pos_ = view->ConvertFromRootFrame(
        gfx::ToFlooredPoint(mouse_event.PositionInRootFrame()));
  } else {
    InvalidateClick();
  }

  frame_->GetEventHandler().GetSelectionController().SetMouseDownMayStartSelect(
      false);
}

bool MouseEventManager::IsMousePositionUnknown() {
  return is_mouse_position_unknown_;
}

gfx::PointF MouseEventManager::LastKnownMousePositionInViewport() {
  return last_known_mouse_position_;
}

gfx::PointF MouseEventManager::LastKnownMouseScreenPosition() {
  return last_known_mouse_screen_position_;
}

void MouseEventManager::SetLastKnownMousePosition(const WebMouseEvent& event) {
  is_mouse_position_unknown_ =
      event.GetType() == WebInputEvent::Type::kMouseLeave;
  last_known_mouse_position_in_root_frame_ =
      PhysicalOffset(gfx::ToFlooredPoint(event.PositionInRootFrame()));
  last_known_mouse_position_ = event.PositionInWidget();
  last_known_mouse_screen_position_ = event.PositionInScreen();
}

void MouseEventManager::SetLastMousePositionAsUnknown() {
  is_mouse_position_unknown_ = true;
}

WebInputEventResult MouseEventManager::HandleMousePressEvent(
    const MouseEventWithHitTestResults& event) {
  TRACE_EVENT0("blink", "MouseEventManager::handleMousePressEvent");

  ResetDragSource();

  frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kInput);

  bool single_click = event.Event().click_count <= 1;

  mouse_down_may_start_drag_ = single_click && !IsSelectionOverLink(event) &&
                               !IsExtendingSelection(event);

  mouse_down_ = event.Event();

  if (frame_->GetDocument()->IsSVGDocument() &&
      frame_->GetDocument()->AccessSVGExtensions().ZoomAndPanEnabled()) {
    if ((event.Event().GetModifiers() & WebInputEvent::Modifiers::kShiftKey) &&
        single_click) {
      svg_pan_ = true;
      frame_->GetDocument()->AccessSVGExtensions().StartPan(
          frame_->View()->ConvertFromRootFrame(gfx::PointF(
              gfx::ToFlooredPoint(event.Event().PositionInRootFrame()))));
      return WebInputEventResult::kHandledSystem;
    }
  }

  // We don't do this at the start of mouse down handling,
  // because we don't want to do it until we know we didn't hit a widget.
  if (single_click)
    FocusDocumentView();

  // |SelectionController| calls |PositionForPoint()| which requires
  // |kPrePaintClean|. |FocusDocumentView| above is the last possible
  // modifications before we call |SelectionController|.
  if (LocalFrameView* frame_view = frame_->View()) {
    frame_view->UpdateAllLifecyclePhasesExceptPaint(
        DocumentUpdateReason::kInput);
  }

  Node* inner_node = event.InnerNode();

  mouse_press_node_ = inner_node;
  frame_->GetDocument()->SetSequentialFocusNavigationStartingPoint(inner_node);
  drag_start_pos_in_root_frame_ =
      PhysicalOffset(gfx::ToFlooredPoint(event.Event().PositionInRootFrame()));

  mouse_pressed_ = true;

  bool swallow_event =
      frame_->GetEventHandler().GetSelectionController().HandleMousePressEvent(
          event);

  // TODO(crbug.com/1324667): Ensure that autoscroll handles mouse_press_node_
  // removal correctly, allowing scrolling the still attached ancestor.
  mouse_down_may_start_autoscroll_ =
      frame_->GetEventHandler()
          .GetSelectionController()
          .MouseDownMayStartSelect() ||
      (mouse_press_node_ && mouse_press_node_->GetLayoutBox() &&
       mouse_press_node_->GetLayoutBox()->IsUserScrollable());

  return swallow_event ? WebInputEventResult::kHandledSystem
                       : WebInputEventResult::kNotHandled;
}

WebInputEventResult MouseEventManager::HandleMouseReleaseEvent(
    const MouseEventWithHitTestResults& event) {
  AutoscrollController* controller = scroll_manager_->GetAutoscrollController();
  if (controller && controller->SelectionAutoscrollInProgress())
    scroll_manager_->StopAutoscroll();

  // |SelectionController| calls |PositionForPoint()| which requires
  // |kPrePaintClean|. |FocusDocumentView| above is the last possible
  // modifications before we call |SelectionController|.
  if (LocalFrameView* frame_view = frame_->View()) {
    frame_view->UpdateAllLifecyclePhasesExceptPaint(
        DocumentUpdateReason::kInput);
  }

  return frame_->GetEventHandler()
                 .GetSelectionController()
                 .HandleMouseReleaseEvent(event, drag_start_pos_in_root_frame_)
             ? WebInputEventResult::kHandledSystem
             : WebInputEventResult::kNotHandled;
}

void MouseEventManager::UpdateSelectionForMouseDrag() {
  frame_->GetEventHandler()
      .GetSelectionController()
      .UpdateSelectionForMouseDrag(drag_start_pos_in_root_frame_,
                                   last_known_mouse_position_in_root_frame_);
}

bool MouseEventManager::HandleDragDropIfPossible(
    const GestureEventWithHitTestResults& targeted_event) {
  const WebGestureEvent& gesture_event = targeted_event.Event();
  unsigned modifiers = gesture_event.GetModifiers();

  mouse_down_ =
      WebMouseEvent(WebInputEvent::Type::kMouseDown, gesture_event,
                    WebPointerProperties::Button::kLeft, 1,
                    modifiers | WebInputEvent::Modifiers::kLeftButtonDown |
                        WebInputEvent::Modifiers::kIsCompatibilityEventForTouch,
                    base::TimeTicks::Now());

  WebMouseEvent mouse_drag_event(
      WebInputEvent::Type::kMouseMove, gesture_event,
      WebPointerProperties::Button::kLeft, 1,
      modifiers | WebInputEvent::Modifiers::kLeftButtonDown |
      
"""


```