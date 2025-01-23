Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_plugin_container_impl.cc`. This is the second part of a two-part file analysis. I need to synthesize the functionalities described in this part and, ideally, combine them with the information from the first part (although the first part is not provided here, I should assume it handled related responsibilities).

My approach will be to go through each function in the code snippet and describe its purpose. Then, I'll look for connections to JavaScript, HTML, and CSS, provide examples, explain any logical reasoning with inputs and outputs, identify potential user or programming errors, and detail how a user's actions might lead to this code being executed. Finally, I'll combine these individual summaries into an overall summary of the code's purpose.
```cpp
void WebPluginContainerImpl::Update(drag_status, drag_data,
                                      drag_operation_mask, drag_location,
                                      drag_screen_location);
}
```

**功能:**  这个函数 `Update` 似乎与处理插件上的拖放操作有关。它接收有关拖动状态、拖动数据、允许的拖动操作掩码以及拖动事件发生的位置（相对于插件和屏幕）的信息。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** JavaScript 可以发起拖放操作，或者监听拖放事件。当用户在包含插件的网页上拖动元素时，浏览器会将相关信息传递给这个 `Update` 函数，以便插件能够感知并处理拖放行为。
    * **举例:**  一个网页可能有一个 JavaScript 监听器，当用户开始拖动一个文件到插件区域时，会设置拖动数据类型（例如 "text/uri-list"）和拖动效果。
* **HTML:** HTML `object` 或 `embed` 标签定义了插件的容器。拖放操作的目标就是这个 HTML 元素。
    * **举例:**  `<object type="application/x-my-plugin" id="myPlugin"></object>`。用户拖动文件到这个 `object` 元素上时会触发相关事件。
* **CSS:** CSS 可以影响插件容器的视觉外观，例如大小、位置等，但它本身不直接参与拖放逻辑的处理。

**逻辑推理:**

* **假设输入:**
    * `drag_status`:  表示当前拖动状态，例如开始拖动、正在拖动、拖动结束、进入插件区域、离开插件区域等。
    * `drag_data`:  包含被拖动的数据，例如文件列表、文本、URL 等。
    * `drag_operation_mask`:  一个位掩码，指示允许的拖动操作类型，例如复制、移动、链接等。
    * `drag_location`:  拖动事件发生时，鼠标相对于插件容器的位置。
    * `drag_screen_location`: 拖动事件发生时，鼠标相对于屏幕的位置。
* **可能输出:**  这个函数本身没有直接的返回值。它的作用是更新插件内部的状态，以便插件能够根据拖放事件做出相应的响应，例如高亮显示、接收拖放数据等。

**用户或编程常见的使用错误:**

* **用户错误:** 用户可能尝试拖动不支持的数据类型到插件上，导致插件无法处理。
* **编程错误:** 插件开发者可能没有正确实现拖放处理逻辑，导致程序崩溃或行为异常。例如，没有检查 `drag_operation_mask` 就直接执行了某种操作。

**用户操作如何到达这里 (调试线索):**

1. 用户在网页上开始拖动一个元素（例如一个文件图标）。
2. 鼠标指针移动到嵌入的插件区域上方。
3. 浏览器检测到拖动事件进入插件的边界。
4. Blink 渲染引擎将拖动事件信息传递给 `WebPluginContainerImpl` 的 `Update` 函数。

---

```cpp
void WebPluginContainerImpl::HandleWheelEvent(WheelEvent& event) {
  gfx::PointF absolute_location = event.NativeEvent().PositionInRootFrame();

  // Translate the root frame position to content coordinates.
  absolute_location =
      ParentFrameView()->ConvertFromRootFrame(absolute_location);

  gfx::PointF local_point =
      element_->GetLayoutObject()->AbsoluteToLocalPoint(absolute_location);
  WebMouseWheelEvent translated_event = event.NativeEvent().FlattenTransform();
  translated_event.SetPositionInWidget(local_point.x(), local_point.y());

  ui::Cursor dummy_cursor;
  if (web_plugin_->HandleInputEvent(
          WebCoalescedInputEvent(translated_event, ui::LatencyInfo()),
          &dummy_cursor) != WebInputEventResult::kNotHandled)
    event.SetDefaultHandled();
}
```

**功能:**  `HandleWheelEvent` 函数处理鼠标滚轮事件。它将滚轮事件的坐标转换为插件内部的坐标系，并将转换后的事件传递给插件进行处理。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** JavaScript 可以监听 `wheel` 事件，但如果插件处理了该事件，JavaScript 可能无法接收到。
* **HTML:** 滚轮事件发生在包含插件的 HTML 元素上。
* **CSS:** CSS 的滚动属性可能会影响页面的滚动行为，但与插件内部的滚轮事件处理没有直接关系。

**逻辑推理:**

* **假设输入:** 一个 `WheelEvent` 对象，包含滚轮滚动的方向和距离，以及事件发生时的坐标。
* **输出:**  如果插件处理了滚轮事件（返回 `WebInputEventResult::kNotHandled` 之外的值），则 `event.SetDefaultHandled()` 会阻止浏览器进行默认的滚动操作。

**用户或编程常见的使用错误:**

* **用户错误:** 无。
* **编程错误:**  插件开发者可能没有正确处理滚轮事件，导致插件内的滚动行为不符合预期。

**用户操作如何到达这里 (调试线索):**

1. 用户将鼠标指针悬停在插件区域上方。
2. 用户滚动鼠标滚轮。
3. 浏览器生成 `WheelEvent` 对象。
4. Blink 渲染引擎将该事件传递给 `WebPluginContainerImpl` 的 `HandleWheelEvent` 函数。

---

```cpp
void WebPluginContainerImpl::HandleKeyboardEvent(KeyboardEvent& event) {
  WebKeyboardEventBuilder web_event(event);
  if (web_event.GetType() == WebInputEvent::Type::kUndefined)
    return;

  if (HandleCutCopyPasteKeyboardEvent(web_event)) {
    event.SetDefaultHandled();
    return;
  }

  ui::Cursor dummy_cursor;
  if (web_plugin_->HandleInputEvent(
          WebCoalescedInputEvent(web_event, ui::LatencyInfo()),
          &dummy_cursor) != WebInputEventResult::kNotHandled) {
    event.SetDefaultHandled();
  }
}
```

**功能:** `HandleKeyboardEvent` 函数处理键盘事件。它将浏览器接收到的 `KeyboardEvent` 转换为插件可以理解的 `WebKeyboardEvent`，然后传递给插件进行处理。它还会在将事件传递给插件之前检查是否是剪切、复制或粘贴的快捷键。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** JavaScript 可以监听 `keydown`, `keyup`, `keypress` 事件，但如果插件处理了键盘事件，JavaScript 可能无法接收到。
* **HTML:** 键盘事件的目标是当前焦点所在的元素，如果插件获得了焦点，则键盘事件会发送到插件。
* **CSS:** CSS 可以影响元素获得焦点时的样式，但与键盘事件的处理没有直接关系。

**逻辑推理:**

* **假设输入:** 一个 `KeyboardEvent` 对象，包含按下的键码、修饰键状态等信息.
* **输出:** 如果插件处理了键盘事件，或者 `HandleCutCopyPasteKeyboardEvent` 返回 `true`，则 `event.SetDefaultHandled()` 会阻止浏览器执行默认的键盘操作（例如文本输入）。

**用户或编程常见的使用错误:**

* **用户错误:** 无。
* **编程错误:** 插件开发者可能没有正确处理键盘事件，导致插件无法响应用户的键盘输入。

**用户操作如何到达这里 (调试线索):**

1. 用户点击插件区域，使插件获得焦点。
2. 用户按下键盘上的某个键。
3. 浏览器生成 `KeyboardEvent` 对象。
4. Blink 渲染引擎将该事件传递给 `WebPluginContainerImpl` 的 `HandleKeyboardEvent` 函数。

---

```cpp
bool WebPluginContainerImpl::HandleCutCopyPasteKeyboardEvent(
    const WebKeyboardEvent& event) {
  // ... 省略实现 ...
}
```

**功能:** `HandleCutCopyPasteKeyboardEvent` 函数专门处理剪切、复制和粘贴的键盘快捷键。它检查按下的键和修饰键是否符合这些快捷键的组合，并调用相应的操作（例如 `Copy()` 或 `ExecuteEditCommand()`）。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** JavaScript 可以通过监听键盘事件并检查键码来实现类似的功能，但此函数提供了一种在插件层面处理这些快捷键的方式。
* **HTML:**  与包含插件的 HTML 元素交互时可能触发这些快捷键。
* **CSS:** 无直接关系。

**逻辑推理:**

* **假设输入:** 一个 `WebKeyboardEvent` 对象。
* **输出:** 返回 `true` 如果事件是剪切、复制或粘贴的快捷键，并且操作已执行；否则返回 `false`。

**用户或编程常见的使用错误:**

* **用户错误:** 无。
* **编程错误:** 插件开发者可能没有正确实现 `HasSelection()`, `CanEditText()`, `Copy()`, 或 `ExecuteEditCommand()` 等相关方法，导致剪切、复制、粘贴功能无法正常工作。

**用户操作如何到达这里 (调试线索):**

1. 用户在插件获得焦点后，按下 Ctrl+C (复制), Ctrl+X (剪切), Ctrl+V (粘贴) 或其他相关的快捷键。
2. `HandleKeyboardEvent` 函数首先被调用。
3. `HandleKeyboardEvent` 函数调用 `HandleCutCopyPasteKeyboardEvent` 来检查是否是剪切、复制或粘贴的快捷键。

---

```cpp
WebTouchEvent WebPluginContainerImpl::TransformTouchEvent(
    const WebInputEvent& event) {
  // ... 省略实现 ...
}

WebCoalescedInputEvent WebPluginContainerImpl::TransformCoalescedTouchEvent(
    const WebCoalescedInputEvent& coalesced_event) {
  // ... 省略实现 ...
}
```

**功能:** 这两个函数 `TransformTouchEvent` 和 `TransformCoalescedTouchEvent` 用于转换触摸事件的坐标。由于触摸事件的坐标是相对于根框架的，而插件需要相对于自身坐标系的坐标，因此需要进行转换。`TransformCoalescedTouchEvent` 处理的是合并后的触摸事件。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** JavaScript 可以监听 `touchstart`, `touchmove`, `touchend`, `touchcancel` 事件。
* **HTML:** 触摸事件发生在包含插件的 HTML 元素上。
* **CSS:**  CSS 可以影响页面的滚动和触摸行为，例如通过 `-webkit-overflow-scrolling: touch;` 启用流畅滚动，但这与插件内部的触摸事件坐标转换没有直接关系。

**逻辑推理:**

* **假设输入:**  `TransformTouchEvent` 接收一个 `WebInputEvent` (实际上是一个 `WebTouchEvent`) 对象。 `TransformCoalescedTouchEvent` 接收一个 `WebCoalescedInputEvent` 对象。
* **输出:**  返回一个新的 `WebTouchEvent` 或 `WebCoalescedInputEvent` 对象，其触摸点的坐标已转换为插件的局部坐标系。

**用户或编程常见的使用错误:**

* **用户错误:** 无。
* **编程错误:**  坐标转换逻辑错误可能导致插件对触摸位置的判断不准确。

**用户操作如何到达这里 (调试线索):**

1. 用户触摸包含插件的屏幕区域。
2. 浏览器生成触摸事件。
3. Blink 渲染引擎在将触摸事件传递给插件之前，会调用 `TransformTouchEvent` 或 `TransformCoalescedTouchEvent` 来转换坐标。

---

```cpp
void WebPluginContainerImpl::HandleTouchEvent(TouchEvent& event) {
  // ... 省略实现 ...
}
```

**功能:** `HandleTouchEvent` 函数处理触摸事件。根据 `touch_event_request_type_` 的值，它可能将原始触摸事件直接传递给插件，或者模拟鼠标事件并传递给插件。

**与 JavaScript, HTML, CSS 的关系:**  同上。

**逻辑推理:**

* **假设输入:** 一个 `TouchEvent` 对象。
* **输出:** 如果插件处理了触摸事件，则 `event.SetDefaultHandled()` 会阻止浏览器执行默认的触摸操作（例如滚动或缩放）。

**用户或编程常见的使用错误:**

* **用户错误:** 无。
* **编程错误:**  如果 `touch_event_request_type_` 设置不正确，可能导致触摸事件无法正确传递给插件或被错误地处理。

**用户操作如何到达这里 (调试线索):**

1. 用户触摸包含插件的屏幕区域。
2. 浏览器生成 `TouchEvent` 对象。
3. Blink 渲染引擎将该事件传递给 `WebPluginContainerImpl` 的 `HandleTouchEvent` 函数。

---

```cpp
void WebPluginContainerImpl::HandleGestureEvent(GestureEvent& event) {
  // ... 省略实现 ...
}
```

**功能:** `HandleGestureEvent` 函数处理手势事件，例如轻击、滑动、捏合等。它将手势事件的坐标转换为插件内部的坐标系，并将转换后的事件传递给插件进行处理。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** JavaScript 可以监听 `gesturestart`, `gesturechange`, `gestureend` 等手势事件（虽然这些事件已弃用，现在推荐使用触摸事件和 Pointer Events API）。
* **HTML:** 手势事件发生在包含插件的 HTML 元素上。
* **CSS:** 无直接关系。

**逻辑推理:**

* **假设输入:** 一个 `GestureEvent` 对象。
* **输出:** 如果插件处理了手势事件，则 `event.SetDefaultHandled()` 会阻止浏览器执行默认的手势操作（例如页面缩放）。

**用户或编程常见的使用错误:**

* **用户错误:** 无。
* **编程错误:**  插件开发者可能没有正确处理手势事件，导致插件无法响应用户的手势操作。

**用户操作如何到达这里 (调试线索):**

1. 用户在包含插件的屏幕区域执行手势操作（例如双指捏合）。
2. 浏览器生成 `GestureEvent` 对象。
3. Blink 渲染引擎将该事件传递给 `WebPluginContainerImpl` 的 `HandleGestureEvent` 函数。

---

```cpp
void WebPluginContainerImpl::SynthesizeMouseEventIfPossible(TouchEvent& event) {
  // ... 省略实现 ...
}
```

**功能:** `SynthesizeMouseEventIfPossible` 函数尝试从触摸事件合成鼠标事件，并将合成的鼠标事件传递给插件。这通常用于向不支持触摸事件的旧插件提供兼容性。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** JavaScript 可以监听鼠标事件 (click, mousedown, mouseup, mousemove)。
* **HTML:**  合成的鼠标事件的目标是包含插件的 HTML 元素。
* **CSS:** 无直接关系。

**逻辑推理:**

* **假设输入:** 一个 `TouchEvent` 对象。
* **输出:** 如果成功合成了鼠标事件并被插件处理，则 `event.SetDefaultHandled()` 可能会被调用。

**用户或编程常见的使用错误:**

* **用户错误:** 无。
* **编程错误:**  合成鼠标事件的逻辑可能不完美，导致插件接收到的鼠标事件与真实的鼠标事件有所不同。

**用户操作如何到达这里 (调试线索):**

1. 用户触摸包含插件的屏幕区域。
2. 如果 `touch_event_request_type_` 被设置为合成鼠标事件，则 `HandleTouchEvent` 函数会调用 `SynthesizeMouseEventIfPossible`。

---

```cpp
void WebPluginContainerImpl::FocusPlugin() {
  // ... 省略实现 ...
}
```

**功能:** `FocusPlugin` 函数使插件获得焦点。当插件获得焦点时，它可以接收键盘输入和其他焦点相关的事件。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** JavaScript 可以通过调用 `focus()` 方法来使元素获得焦点。
* **HTML:**  焦点状态与 HTML 元素的交互相关。
* **CSS:**  可以使用 `:focus` 伪类来定义元素获得焦点时的样式。

**逻辑推理:**

* **假设输入:** 无。
* **输出:**  插件元素获得焦点。

**用户操作如何到达这里 (调试线索):**

1. 用户点击插件区域。
2. 某些事件处理函数（例如 `HandleTouchEvent` 或 `HandleGestureEvent`）可能会调用 `FocusPlugin` 来确保插件获得焦点，以便处理后续的输入事件。

---

```cpp
void WebPluginContainerImpl::ComputeClipRectsForPlugin(
    const HTMLFrameOwnerElement* owner_element,
    gfx::Rect& window_rect,
    gfx::Rect& clipped_local_rect,
    gfx::Rect& unclipped_int_local_rect) const {
  // ... 省略实现 ...
}

void WebPluginContainerImpl::CalculateGeometry(gfx::Rect& window_rect,
                                               gfx::Rect& clip_rect,
                                               gfx::Rect& unobscured_rect) {
  // ... 省略实现 ...
}
```

**功能:**  `ComputeClipRectsForPlugin` 和 `CalculateGeometry` 函数用于计算插件的几何信息，包括其在窗口中的位置、被裁剪的区域以及未被遮挡的区域。这些信息对于正确渲染插件至关重要。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** JavaScript 可以通过 DOM API 获取元素的几何信息 (例如 `getBoundingClientRect()`)。
* **HTML:** 插件的位置和大小由其在 HTML 结构中的位置和相关的 CSS 样式决定。
* **CSS:** CSS 属性（例如 `position`, `width`, `height`, `overflow`) 会影响插件的几何信息和裁剪区域。

**逻辑推理:**

* **假设输入:**  `ComputeClipRectsForPlugin` 接收插件的父元素。
* **输出:**  填充 `window_rect`, `clipped_local_rect`, 和 `unclipped_int_local_rect` 变量，这些变量描述了插件的几何信息。

**用户或编程常见的使用错误:**

* **用户错误:** 无。
* **编程错误:**  CSS 样式或 JavaScript 代码可能导致插件的位置或大小计算错误。

**用户操作如何到达这里 (调试线索):**

1. 当网页布局发生变化，或者插件需要重新绘制时，渲染引擎会调用这些函数来确定插件的新几何信息。

## 归纳一下它的功能 (第2部分)

这个代码片段主要负责处理与嵌入式 Web 插件的 **用户交互** 和 **几何信息管理** 相关的任务。 具体来说，它的功能包括：

* **处理拖放事件:** 接收并处理发生在插件上的拖放操作，更新插件状态。
* **处理鼠标滚轮事件:**  转换滚轮事件坐标并传递给插件。
* **处理键盘事件:**  转换键盘事件并传递给插件，并特殊处理剪切、复制和粘贴快捷键。
* **处理触摸和手势事件:**  转换触摸和手势事件的坐标，并根据配置选择直接传递或合成鼠标事件传递给插件。
* **设置插件焦点:**  使插件获得焦点以接收键盘输入。
* **计算插件几何信息:**  计算插件在页面中的位置、裁剪区域和未遮挡区域，用于正确渲染。

总而言之，这段代码是 Chromium Blink 引擎中连接网页和插件的关键部分，它确保了用户与插件的各种交互能够被正确捕获、转换和传递给插件进行处理，并维护了插件在页面上的正确显示。

### 提示词
```
这是目录为blink/renderer/core/exported/web_plugin_container_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
pdate(drag_status, drag_data,
                                      drag_operation_mask, drag_location,
                                      drag_screen_location);
}

void WebPluginContainerImpl::HandleWheelEvent(WheelEvent& event) {
  gfx::PointF absolute_location = event.NativeEvent().PositionInRootFrame();

  // Translate the root frame position to content coordinates.
  absolute_location =
      ParentFrameView()->ConvertFromRootFrame(absolute_location);

  gfx::PointF local_point =
      element_->GetLayoutObject()->AbsoluteToLocalPoint(absolute_location);
  WebMouseWheelEvent translated_event = event.NativeEvent().FlattenTransform();
  translated_event.SetPositionInWidget(local_point.x(), local_point.y());

  ui::Cursor dummy_cursor;
  if (web_plugin_->HandleInputEvent(
          WebCoalescedInputEvent(translated_event, ui::LatencyInfo()),
          &dummy_cursor) != WebInputEventResult::kNotHandled)
    event.SetDefaultHandled();
}

void WebPluginContainerImpl::HandleKeyboardEvent(KeyboardEvent& event) {
  WebKeyboardEventBuilder web_event(event);
  if (web_event.GetType() == WebInputEvent::Type::kUndefined)
    return;

  if (HandleCutCopyPasteKeyboardEvent(web_event)) {
    event.SetDefaultHandled();
    return;
  }

  ui::Cursor dummy_cursor;
  if (web_plugin_->HandleInputEvent(
          WebCoalescedInputEvent(web_event, ui::LatencyInfo()),
          &dummy_cursor) != WebInputEventResult::kNotHandled) {
    event.SetDefaultHandled();
  }
}

bool WebPluginContainerImpl::HandleCutCopyPasteKeyboardEvent(
    const WebKeyboardEvent& event) {
  if (event.GetType() != WebInputEvent::Type::kRawKeyDown &&
      event.GetType() != WebInputEvent::Type::kKeyDown) {
    return false;
  }

  int input_modifiers = event.GetModifiers() & WebInputEvent::kInputModifiers;
  if (input_modifiers == kEditingModifier) {
    // Only copy/cut if there's a selection, so that we only ever do
    // this for Pepper plugins that support copying/cutting.
    if (web_plugin_->HasSelection()) {
      if (event.windows_key_code == VKEY_C ||
          event.windows_key_code == VKEY_INSERT) {
        Copy();
        return true;
      }
      if (event.windows_key_code == VKEY_X)
        return ExecuteEditCommand("Cut", "");
    }
    // Ask the plugin if it can edit text before executing "Paste".
    if (event.windows_key_code == VKEY_V && web_plugin_->CanEditText())
      return ExecuteEditCommand("Paste", "");
    return false;
  }

  if (input_modifiers == WebInputEvent::kShiftKey) {
    // Alternate shortcuts for "Cut" and "Paste" are Shift + Delete and Shift +
    // Insert, respectively.
    if (event.windows_key_code == VKEY_DELETE && web_plugin_->HasSelection())
      return ExecuteEditCommand("Cut", "");
    if (event.windows_key_code == VKEY_INSERT && web_plugin_->CanEditText())
      return ExecuteEditCommand("Paste", "");
    return false;
  }

  // Invoke "PasteAndMatchStyle" using Ctrl + Shift + V to paste as plain
  // text.
  if (input_modifiers == (kEditingModifier | WebInputEvent::kShiftKey) &&
      event.windows_key_code == VKEY_V && web_plugin_->CanEditText()) {
    return ExecuteEditCommand("PasteAndMatchStyle", "");
  }
  return false;
}

WebTouchEvent WebPluginContainerImpl::TransformTouchEvent(
    const WebInputEvent& event) {
  DCHECK(blink::WebInputEvent::IsTouchEventType(event.GetType()));
  const WebTouchEvent* touch_event = static_cast<const WebTouchEvent*>(&event);
  WebTouchEvent transformed_event = touch_event->FlattenTransform();

  LocalFrameView* parent = ParentFrameView();
  for (unsigned i = 0; i < transformed_event.touches_length; ++i) {
    gfx::PointF absolute_location =
        transformed_event.touches[i].PositionInWidget();

    // Translate the root frame position to content coordinates.
    absolute_location = parent->ConvertFromRootFrame(absolute_location);

    gfx::PointF local_point =
        element_->GetLayoutObject()->AbsoluteToLocalPoint(absolute_location);
    transformed_event.touches[i].SetPositionInWidget(local_point);
  }
  return transformed_event;
}

WebCoalescedInputEvent WebPluginContainerImpl::TransformCoalescedTouchEvent(
    const WebCoalescedInputEvent& coalesced_event) {
  WebCoalescedInputEvent transformed_event(
      TransformTouchEvent(coalesced_event.Event()).Clone(), {}, {},
      coalesced_event.latency_info());
  for (size_t i = 0; i < coalesced_event.CoalescedEventSize(); ++i) {
    transformed_event.AddCoalescedEvent(
        TransformTouchEvent(coalesced_event.CoalescedEvent(i)));
  }
  for (size_t i = 0; i < coalesced_event.PredictedEventSize(); ++i) {
    transformed_event.AddPredictedEvent(
        TransformTouchEvent(coalesced_event.PredictedEvent(i)));
  }
  return transformed_event;
}

void WebPluginContainerImpl::HandleTouchEvent(TouchEvent& event) {
  switch (touch_event_request_type_) {
    case kTouchEventRequestTypeNone:
      return;
    case kTouchEventRequestTypeRaw:
    case kTouchEventRequestTypeRawLowLatency: {
      if (!event.NativeEvent())
        return;

      if (event.type() == event_type_names::kTouchstart)
        FocusPlugin();

      WebCoalescedInputEvent transformed_event =
          TransformCoalescedTouchEvent(*event.NativeEvent());

      ui::Cursor dummy_cursor;
      if (web_plugin_->HandleInputEvent(transformed_event, &dummy_cursor) !=
          WebInputEventResult::kNotHandled)
        event.SetDefaultHandled();
      // FIXME: Can a plugin change the cursor from a touch-event callback?
      return;
    }
    case kTouchEventRequestTypeSynthesizedMouse:
      SynthesizeMouseEventIfPossible(event);
      return;
  }
}

void WebPluginContainerImpl::HandleGestureEvent(GestureEvent& event) {
  if (event.NativeEvent().GetType() == WebInputEvent::Type::kUndefined)
    return;
  if (event.NativeEvent().GetType() == WebInputEvent::Type::kGestureTapDown)
    FocusPlugin();

  // Take a copy of the event and translate it into the coordinate
  // system of the plugin.
  WebGestureEvent translated_event = event.NativeEvent();
  gfx::PointF absolute_root_frame_location =
      event.NativeEvent().PositionInRootFrame();
  gfx::PointF local_point = element_->GetLayoutObject()->AbsoluteToLocalPoint(
      absolute_root_frame_location);
  translated_event.FlattenTransform();
  translated_event.SetPositionInWidget(local_point);

  ui::Cursor dummy_cursor;
  if (web_plugin_->HandleInputEvent(
          WebCoalescedInputEvent(translated_event, ui::LatencyInfo()),
          &dummy_cursor) != WebInputEventResult::kNotHandled) {
    event.SetDefaultHandled();
    return;
  }

  // FIXME: Can a plugin change the cursor from a touch-event callback?
}

void WebPluginContainerImpl::SynthesizeMouseEventIfPossible(TouchEvent& event) {
  WebMouseEventBuilder web_event(element_->GetLayoutObject(), event);
  if (web_event.GetType() == WebInputEvent::Type::kUndefined)
    return;

  ui::Cursor dummy_cursor;
  if (web_plugin_->HandleInputEvent(
          WebCoalescedInputEvent(web_event, ui::LatencyInfo()),
          &dummy_cursor) != WebInputEventResult::kNotHandled)
    event.SetDefaultHandled();
}

void WebPluginContainerImpl::FocusPlugin() {
  LocalFrame* frame = element_->GetDocument().GetFrame();
  DCHECK(IsAttached() && frame && frame->GetPage());
  frame->GetPage()->GetFocusController().SetFocusedElement(element_, frame);
}

void WebPluginContainerImpl::ComputeClipRectsForPlugin(
    const HTMLFrameOwnerElement* owner_element,
    gfx::Rect& window_rect,
    gfx::Rect& clipped_local_rect,
    gfx::Rect& unclipped_int_local_rect) const {
  DCHECK(owner_element);

  if (!owner_element->GetLayoutObject()) {
    clipped_local_rect = gfx::Rect();
    unclipped_int_local_rect = gfx::Rect();
    return;
  }

  LayoutView* root_view = element_->GetDocument().View()->GetLayoutView();
  while (root_view->GetFrame()->OwnerLayoutObject())
    root_view = root_view->GetFrame()->OwnerLayoutObject()->View();

  auto* box = To<LayoutBox>(owner_element->GetLayoutObject());

  // Note: FrameRect() for this plugin is equal to contentBoxRect, mapped to
  // the containing view space, and rounded off.  See
  // LayoutEmbeddedContent::UpdateGeometry. To remove the lossy effect of
  // rounding off, use contentBoxRect directly.
  PhysicalRect unclipped_root_frame_rect = box->PhysicalContentBoxRect();
  box->MapToVisualRectInAncestorSpace(root_view, unclipped_root_frame_rect);
  unclipped_root_frame_rect =
      root_view->GetFrameView()->DocumentToFrame(unclipped_root_frame_rect);

  // The frameRect is already in absolute space of the local frame to the
  // plugin so map it up to the root frame.
  window_rect = FrameRect();
  PhysicalRect layout_window_rect =
      element_->GetDocument().View()->GetLayoutView()->LocalToAbsoluteRect(
          PhysicalRect(window_rect), kTraverseDocumentBoundaries);

  window_rect = ToPixelSnappedRect(layout_window_rect);

  PhysicalRect clipped_root_frame_rect = unclipped_root_frame_rect;
  clipped_root_frame_rect.Intersect(PhysicalRect(
      PhysicalOffset(), PhysicalSize(root_view->GetFrameView()->Size())));

  unclipped_int_local_rect = ToEnclosingRect(box->AbsoluteToLocalRect(
      unclipped_root_frame_rect, kTraverseDocumentBoundaries));
  // As a performance optimization, map the clipped rect separately if is
  // different than the unclipped rect.
  if (clipped_root_frame_rect != unclipped_root_frame_rect) {
    clipped_local_rect = ToEnclosingRect(box->AbsoluteToLocalRect(
        clipped_root_frame_rect, kTraverseDocumentBoundaries));
  } else {
    clipped_local_rect = unclipped_int_local_rect;
  }
}

void WebPluginContainerImpl::CalculateGeometry(gfx::Rect& window_rect,
                                               gfx::Rect& clip_rect,
                                               gfx::Rect& unobscured_rect) {
  // GetDocument().LayoutView() can be null when we receive messages from the
  // plugins while we are destroying a frame.
  // TODO: Can we just check element_->GetDocument().IsActive() ?
  if (element_->GetLayoutObject()->GetDocument().GetLayoutView()) {
    // Take our element and get the clip rect from the enclosing layer and
    // frame view.
    ComputeClipRectsForPlugin(element_, window_rect, clip_rect,
                              unobscured_rect);
  }
}

}  // namespace blink
```