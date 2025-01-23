Response:
Let's break down the thought process for analyzing this `external_popup_menu.cc` file.

1. **Initial Reading and Keyword Spotting:** The first step is to read through the code, paying attention to class names, method names, included headers, and any comments. Keywords like "PopupMenu," "HTMLSelectElement," "Show," "Hide," "DispatchEvent," "Update," and "DidAcceptIndices" jump out. The inclusion of headers like `third_party/blink/public/common/input/web_mouse_event.h` and references to `gfx::Rect` also provide hints.

2. **Identifying the Core Purpose:** Based on the keywords, the file seems to be responsible for managing a popup menu specifically for `<select>` elements in HTML. The "external" part likely means it's not a purely in-Blink implementation but interacts with the browser process.

3. **Tracing the `Show` Function:** The `ShowInternal()` and `Show()` functions are crucial for understanding how the popup is displayed.
    * **`ShowInternal()`:** This function gathers information about the `<select>` element (item height, font size, menu items, alignment, multiple selection) and sends this information to the browser process via `local_frame_->GetLocalFrameHostRemote().ShowPopupMenu()`. This confirms the interaction with the browser. It also calculates the popup's position based on the `<select>` element's layout.
    * **`Show()`:**  This function calls `ShowInternal()` and then has some platform-specific (Mac) logic to handle mouse events. This suggests the popup's appearance might be triggered by a mouse click.

4. **Analyzing Data Flow:**  Follow the data being passed to `ShowPopupMenu()`. The `GetPopupMenuInfo()` function is responsible for populating the `menu_items`. This function iterates through the `<option>` and `<optgroup>` elements within the `<select>` and creates `mojom::blink::MenuItemPtr` objects. This clearly links the C++ code to the HTML structure.

5. **Understanding Event Handling:** The presence of `DispatchEvent()` and the Mac-specific mouse event handling points to how user interactions with the popup are processed. The `DidAcceptIndices()` function is called when the user selects items in the popup, and it updates the `<select>` element accordingly. `DidCancel()` handles the case where the popup is dismissed without a selection.

6. **Considering Updates and Hiding:** The `Update()` and `Hide()` functions explain how the popup is refreshed (e.g., when the `<select>` element changes) and dismissed. The `DisconnectClient()` function suggests cleanup when the associated `<select>` element is no longer valid.

7. **Identifying Connections to Web Technologies:**
    * **HTML:** The entire purpose revolves around `<select>`, `<option>`, and `<optgroup>` elements. The code parses their structure and attributes.
    * **JavaScript:** While this specific file doesn't directly execute JavaScript, the popup's behavior (showing, selection) is often initiated or influenced by JavaScript interactions with the `<select>` element. JavaScript event listeners on the `<select>` element can trigger the popup.
    * **CSS:** The code retrieves computed styles (font size, direction) to correctly render the popup. The position of the popup is also based on the layout of the `<select>` element, which is determined by CSS.

8. **Inferring User Actions:** By understanding the functions involved, you can deduce the user actions that lead to this code being executed:
    * Clicking on a `<select>` element.
    * A JavaScript action that programmatically triggers the display of the dropdown.

9. **Looking for Potential Errors:** Consider scenarios where things might go wrong.
    * The `<select>` element is removed from the DOM while the popup is open.
    * Race conditions between updates and user interactions.
    * Incorrectly configured `<select>` element structure.

10. **Structuring the Explanation:**  Organize the findings into logical sections: Functionality, Relationship to Web Technologies, Logic/Assumptions, Common Errors, and User Interaction. Use clear language and provide specific examples. For the examples, create simple HTML snippets to illustrate the concepts.

11. **Refinement and Review:**  Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that might need further explanation. For instance, initially, I might just say "interacts with the browser process," but then I would refine it to mention "IPC" or "inter-process communication" for more technical accuracy if needed for the target audience. I would also double-check that the examples accurately reflect the code's behavior.
好的，让我们来详细分析一下 `blink/renderer/core/html/forms/external_popup_menu.cc` 这个文件。

**功能概述**

这个文件实现了 Chromium Blink 渲染引擎中用于 `<select>` HTML 表单元素弹出外部下拉菜单的功能。当用户与 `<select>` 元素交互，需要显示下拉选项时，这个文件中的代码负责创建、显示、更新和管理这个独立的外部弹出菜单。

**与 JavaScript, HTML, CSS 的关系**

这个文件与 Web 前端的三大技术都有着密切的关系：

* **HTML:**  它是为 HTML 的 `<select>` 元素服务的。代码的核心任务就是根据 `<select>` 元素及其子元素 `<option>` 和 `<optgroup>` 的结构和内容来生成弹出菜单的选项。
    * **举例：**
        ```html
        <select id="mySelect">
          <option value="apple">Apple</option>
          <option value="banana" selected>Banana</option>
          <optgroup label="Fruits">
            <option value="orange">Orange</option>
          </optgroup>
          <hr>
          <option value="grape">Grape</option>
        </select>
        ```
        当用户点击这个 `<select>` 元素时，`ExternalPopupMenu` 会解析这个 HTML 结构，提取出 "Apple", "Banana", "Fruits" (作为分组标题), "Orange", (分隔线), "Grape" 这些文本，以及它们的选中状态、是否禁用等信息，用于构建弹出菜单。

* **JavaScript:** 虽然这个 C++ 文件本身不执行 JavaScript，但它与 JavaScript 的交互是必不可少的。
    * **举例：** JavaScript 可以通过监听 `<select>` 元素的事件（例如 `click` 或 `focus`）来触发弹出菜单的显示。当用户在弹出菜单中选择一个选项后，`ExternalPopupMenu` 会将选择结果通知 Blink 核心，Blink 核心最终会触发 `<select>` 元素的 `change` 事件，JavaScript 代码可以监听这个事件并执行相应的操作。
    * **举例：** JavaScript 可以动态地添加、删除或修改 `<select>` 元素的 `<option>`，`ExternalPopupMenu` 需要能够响应这些 DOM 变化并更新弹出菜单的内容。

* **CSS:**  CSS 样式会影响 `<select>` 元素本身的外观，以及弹出菜单中选项的呈现。
    * **举例：** `<select>` 元素的 `font-size`、`direction` 等 CSS 属性会被 `ExternalPopupMenu` 读取，用于设置弹出菜单的字体大小、文字方向等。
    * **举例：**  虽然弹出菜单本身是一个独立的窗口，但其部分样式可能会受到页面 CSS 的影响，或者浏览器会使用一些默认的样式来渲染菜单项。

**逻辑推理与假设输入输出**

假设用户点击了一个如下的 `<select>` 元素：

```html
<select id="mySelect">
  <option value="1">Option One</option>
  <option value="2" selected>Option Two</option>
  <option value="3">Option Three</option>
</select>
```

**假设输入:** 用户点击了 `id="mySelect"` 的 `<select>` 元素。

**`ShowInternal()` 函数的逻辑推理:**

1. **获取菜单信息:** `GetPopupMenuInfo()` 函数会被调用，它会遍历 `<select>` 元素的子元素：
   - `<option value="1">Option One</option>`  -> 生成一个菜单项，标签为 "Option One"，未选中。
   - `<option value="2" selected>Option Two</option>` -> 生成一个菜单项，标签为 "Option Two"，已选中。
   - `<option value="3">Option Three</option>` -> 生成一个菜单项，标签为 "Option Three"，未选中。
2. **获取样式信息:**  获取 `<select>` 元素的 `font-size` 等样式信息，计算菜单项的高度。
3. **计算位置:** 获取 `<select>` 元素在页面中的绝对位置和尺寸。
4. **与浏览器进程通信:** 调用 `local_frame_->GetLocalFrameHostRemote().ShowPopupMenu()`，将菜单项信息、位置、尺寸等传递给浏览器进程，请求显示外部弹出菜单。

**假设输出 (传递给浏览器进程的信息):**

* **菜单项:**
    * `label`: "Option One", `checked`: false
    * `label`: "Option Two", `checked`: true
    * `label`: "Option Three", `checked`: false
* **选中项索引:** 1 (对应 "Option Two")
* **菜单位置和尺寸:** 基于 `<select>` 元素的位置和尺寸计算出的屏幕坐标。
* **字体大小和菜单项高度:** 从 CSS 样式中获取。

**用户或编程常见的使用错误**

* **错误地修改 `<select>` 元素结构:**  在弹出菜单显示期间，如果 JavaScript 代码不小心移除了 `<select>` 元素或其某个 `<option>` 子元素，`ExternalPopupMenu` 可能会崩溃或出现未定义的行为，因为它依赖于这些元素的有效性。
    * **举例：**
        ```javascript
        const selectElement = document.getElementById('mySelect');
        selectElement.innerHTML = ''; // 清空了 <select> 的内容
        ```
        如果在弹出菜单显示时执行这段代码，可能会导致错误。

* **忘记处理 `change` 事件:**  开发者可能会忘记监听 `<select>` 元素的 `change` 事件，导致用户在弹出菜单中选择选项后，程序无法感知到用户的选择。
    * **举例：**
        ```javascript
        const selectElement = document.getElementById('mySelect');
        // 缺少对 selectElement.addEventListener('change', ...) 的处理
        ```

* **CSS 样式冲突导致显示问题:**  过于复杂的 CSS 样式可能会意外地影响弹出菜单的显示，例如遮挡了部分内容或导致布局错乱。

**用户操作到达这里的步骤**

1. **用户加载包含 `<select>` 元素的网页。** 浏览器解析 HTML，创建 DOM 树，并渲染页面。
2. **用户将鼠标指针移动到 `<select>` 元素上，或者使用键盘焦点选中了该元素。**  这可能会触发一些默认的浏览器行为，例如显示焦点边框。
3. **用户点击 `<select>` 元素，或者按下特定的键盘按键（例如 `Alt + Down Arrow`）。** 浏览器识别到用户想要打开下拉菜单。
4. **Blink 渲染引擎开始处理用户的交互事件。**  对于 `<select>` 元素，Blink 知道需要显示一个外部弹出菜单。
5. **Blink 创建 `ExternalPopupMenu` 对象，并调用其 `Show()` 方法。**
6. **`Show()` 方法内部调用 `ShowInternal()`。**
7. **`ShowInternal()` 函数执行上述的逻辑推理，获取菜单信息、样式信息、计算位置等。**
8. **`ShowInternal()` 函数通过 IPC (Inter-Process Communication) 将请求发送给 Chromium 浏览器进程。**
9. **Chromium 浏览器进程接收到请求，创建并显示一个原生的操作系统弹出菜单。** 菜单的外观和行为可能受到操作系统主题的影响。
10. **用户在弹出菜单中进行选择或取消。**
11. **操作系统将用户的选择结果通知给浏览器进程。**
12. **浏览器进程再将结果通过 IPC 发送回 Blink 渲染进程。**
13. **`ExternalPopupMenu` 对象接收到选择结果，并调用 `DidAcceptIndices()` 或 `DidCancel()` 方法。**
14. **`DidAcceptIndices()` 方法会更新 `<select>` 元素的选中状态，并触发 `change` 事件。**
15. **`DidCancel()` 方法会关闭弹出菜单，不进行任何选择。**

总而言之，`external_popup_menu.cc` 负责了 `<select>` 元素下拉菜单在 Blink 渲染引擎内部的具体实现，它连接了 HTML 结构、CSS 样式以及用户的交互行为，并与浏览器进程协同工作来呈现最终的下拉菜单效果。

### 提示词
```
这是目录为blink/renderer/core/html/forms/external_popup_menu.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/html/forms/external_popup_menu.h"

#include "base/numerics/safe_conversions.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_mouse_event.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/events/current_input_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_hr_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/quad_f.h"

namespace blink {

namespace {

float GetDprForSizeAdjustment(const Element& owner_element) {
  float dpr = 1.0f;
  // Android doesn't need these adjustments and it makes tests fail.
#ifndef OS_ANDROID
  LocalFrame* frame = owner_element.GetDocument().GetFrame();
  const Page* page = frame ? frame->GetPage() : nullptr;
  dpr = page->GetChromeClient().GetScreenInfo(*frame).device_scale_factor;
#endif
  return dpr;
}

}  // namespace

ExternalPopupMenu::ExternalPopupMenu(LocalFrame& frame,
                                     HTMLSelectElement& owner_element)
    : owner_element_(owner_element),
      local_frame_(frame),
      dispatch_event_timer_(frame.GetTaskRunner(TaskType::kInternalDefault),
                            this,
                            &ExternalPopupMenu::DispatchEvent),
      receiver_(this, owner_element.GetExecutionContext()) {}

ExternalPopupMenu::~ExternalPopupMenu() = default;

void ExternalPopupMenu::Trace(Visitor* visitor) const {
  visitor->Trace(owner_element_);
  visitor->Trace(local_frame_);
  visitor->Trace(dispatch_event_timer_);
  visitor->Trace(receiver_);
  PopupMenu::Trace(visitor);
}

void ExternalPopupMenu::Reset() {
  receiver_.reset();
}

bool ExternalPopupMenu::ShowInternal() {
  // Blink core reuses the PopupMenu of an element.  For simplicity, we do
  // recreate the actual external popup every time.
  Reset();

  int32_t item_height;
  double font_size;
  int32_t selected_item;
  Vector<mojom::blink::MenuItemPtr> menu_items;
  bool right_aligned;
  bool allow_multiple_selection;
  GetPopupMenuInfo(*owner_element_, &item_height, &font_size, &selected_item,
                   &menu_items, &right_aligned, &allow_multiple_selection);
  if (menu_items.empty())
    return false;

  auto* execution_context = owner_element_->GetExecutionContext();
  if (!receiver_.is_bound()) {
    LayoutObject* layout_object = owner_element_->GetLayoutObject();
    if (!layout_object || !layout_object->IsBox())
      return false;
    auto* box = To<LayoutBox>(layout_object);
    gfx::Rect rect =
        ToEnclosingRect(box->LocalToAbsoluteRect(box->PhysicalBorderBoxRect()));
    gfx::Rect rect_in_viewport = local_frame_->View()->FrameToViewport(rect);
    float scale_for_emulation = WebLocalFrameImpl::FromFrame(local_frame_)
                                    ->LocalRootFrameWidget()
                                    ->GetEmulatorScale();

    // rect_in_viewport needs to be in CSS pixels.
    float dpr = GetDprForSizeAdjustment(*owner_element_);
    if (dpr != 1.0) {
      rect_in_viewport = gfx::ScaleToRoundedRect(rect_in_viewport, 1 / dpr);
    }

    gfx::Rect bounds =
        gfx::Rect(rect_in_viewport.x() * scale_for_emulation,
                  rect_in_viewport.y() * scale_for_emulation,
                  rect_in_viewport.width(), rect_in_viewport.height());
    local_frame_->GetLocalFrameHostRemote().ShowPopupMenu(
        receiver_.BindNewPipeAndPassRemote(execution_context->GetTaskRunner(
            TaskType::kInternalUserInteraction)),
        bounds, item_height, font_size, selected_item, std::move(menu_items),
        right_aligned, allow_multiple_selection);
    return true;
  }

  // The client might refuse to create a popup (when there is already one
  // pending to be shown for example).
  DidCancel();
  return false;
}

void ExternalPopupMenu::Show(PopupMenu::ShowEventType) {
  if (!ShowInternal())
    return;
#if BUILDFLAG(IS_MAC)
  const WebInputEvent* current_event = CurrentInputEvent::Get();
  if (current_event &&
      current_event->GetType() == WebInputEvent::Type::kMouseDown) {
    synthetic_event_ = std::make_unique<WebMouseEvent>();
    *synthetic_event_ = *static_cast<const WebMouseEvent*>(current_event);
    synthetic_event_->SetType(WebInputEvent::Type::kMouseUp);
    dispatch_event_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
    // FIXME: show() is asynchronous. If preparing a popup is slow and a
    // user released the mouse button before showing the popup, mouseup and
    // click events are correctly dispatched. Dispatching the synthetic
    // mouseup event is redundant in this case.
  }
#endif
}

void ExternalPopupMenu::DispatchEvent(TimerBase*) {
  static_cast<WebWidget*>(
      WebLocalFrameImpl::FromFrame(local_frame_->LocalFrameRoot())
          ->FrameWidgetImpl())
      ->HandleInputEvent(
          blink::WebCoalescedInputEvent(*synthetic_event_, ui::LatencyInfo()));
  synthetic_event_.reset();
}

void ExternalPopupMenu::Hide() {
  if (owner_element_)
    owner_element_->PopupDidHide();
  Reset();
}

void ExternalPopupMenu::UpdateFromElement(UpdateReason reason) {
  switch (reason) {
    case kBySelectionChange:
    case kByDOMChange:
      if (needs_update_)
        return;
      needs_update_ = true;
      owner_element_->GetDocument()
          .GetTaskRunner(TaskType::kUserInteraction)
          ->PostTask(FROM_HERE, WTF::BindOnce(&ExternalPopupMenu::Update,
                                              WrapPersistent(this)));
      break;

    case kByStyleChange:
      // TODO(tkent): We should update the popup location/content in some
      // cases.  e.g. Updating ComputedStyle of the SELECT element affects
      // popup position and OPTION style.
      break;
  }
}

void ExternalPopupMenu::Update() {
  if (!receiver_.is_bound() || !owner_element_)
    return;
  owner_element_->GetDocument().UpdateStyleAndLayoutTree();
  // disconnectClient() might have been called.
  if (!owner_element_)
    return;
  needs_update_ = false;

  if (ShowInternal())
    return;
  // We failed to show a popup.  Notify it to the owner.
  Hide();
}

void ExternalPopupMenu::DisconnectClient() {
  Hide();
  owner_element_ = nullptr;
  dispatch_event_timer_.Stop();
}

void ExternalPopupMenu::DidAcceptIndices(const Vector<int32_t>& indices) {
  local_frame_->NotifyUserActivation(
      mojom::blink::UserActivationNotificationType::kInteraction);

  // Calling methods on the HTMLSelectElement might lead to this object being
  // derefed. This ensures it does not get deleted while we are running this
  // method.
  if (!owner_element_) {
    Reset();
    return;
  }

  HTMLSelectElement* owner_element = owner_element_;
  owner_element->PopupDidHide();

  if (indices.empty()) {
    owner_element->SelectOptionByPopup(-1);
  } else if (!owner_element->IsMultiple()) {
    owner_element->SelectOptionByPopup(
        ToPopupMenuItemIndex(indices[indices.size() - 1], *owner_element));
  } else {
    Vector<int> list_indices;
    wtf_size_t list_count = base::checked_cast<wtf_size_t>(indices.size());
    list_indices.reserve(list_count);
    for (wtf_size_t i = 0; i < list_count; ++i)
      list_indices.push_back(ToPopupMenuItemIndex(indices[i], *owner_element));
    owner_element->SelectMultipleOptionsByPopup(list_indices);
  }
  Reset();
}

void ExternalPopupMenu::DidCancel() {
  if (owner_element_)
    owner_element_->PopupDidHide();
  Reset();
}

void ExternalPopupMenu::GetPopupMenuInfo(
    HTMLSelectElement& owner_element,
    int32_t* item_height,
    double* font_size,
    int32_t* selected_item,
    Vector<mojom::blink::MenuItemPtr>* menu_items,
    bool* right_aligned,
    bool* allow_multiple_selection) {
  const HeapVector<Member<HTMLElement>>& list_items =
      owner_element.GetListItems();
  wtf_size_t item_count = list_items.size();
  for (wtf_size_t i = 0; i < item_count; ++i) {
    if (owner_element.ItemIsDisplayNone(*list_items[i]))
      continue;

    Element& item_element = *list_items[i];
#if BUILDFLAG(IS_ANDROID)
    // Separators get rendered as selectable options on android
    if (IsA<HTMLHRElement>(item_element)) {
      continue;
    }
#endif
    auto popup_item = mojom::blink::MenuItem::New();
    popup_item->label = owner_element.ItemText(item_element);
    popup_item->tool_tip = item_element.title();
    popup_item->checked = false;
    if (IsA<HTMLHRElement>(item_element)) {
      popup_item->type = mojom::blink::MenuItem::Type::kSeparator;
    } else if (IsA<HTMLOptGroupElement>(item_element)) {
      popup_item->type = mojom::blink::MenuItem::Type::kGroup;
    } else {
      popup_item->type = mojom::blink::MenuItem::Type::kOption;
      popup_item->checked = To<HTMLOptionElement>(item_element).Selected();
    }
    popup_item->enabled = !item_element.IsDisabledFormControl();
    const ComputedStyle& style = *owner_element.ItemComputedStyle(item_element);
    popup_item->text_direction = ToBaseTextDirection(style.Direction());
    popup_item->has_text_direction_override =
        IsOverride(style.GetUnicodeBidi());
    menu_items->push_back(std::move(popup_item));
  }

  const ComputedStyle& menu_style = owner_element.GetComputedStyle()
                                        ? *owner_element.GetComputedStyle()
                                        : *owner_element.EnsureComputedStyle();
  const SimpleFontData* font_data = menu_style.GetFont().PrimaryFont();
  DCHECK(font_data);
  // These coordinates need to be in CSS pixels.
  float dpr = GetDprForSizeAdjustment(owner_element);
  *item_height = font_data ? font_data->GetFontMetrics().Height() / dpr : 0;
  *font_size = static_cast<int>(
      menu_style.GetFont().GetFontDescription().ComputedSize() / dpr);
  *selected_item = ToExternalPopupMenuItemIndex(
      owner_element.SelectedListIndex(), owner_element);

  *right_aligned = menu_style.Direction() == TextDirection::kRtl;

  *allow_multiple_selection = owner_element.IsMultiple();
}

int ExternalPopupMenu::ToPopupMenuItemIndex(int external_popup_menu_item_index,
                                            HTMLSelectElement& owner_element) {
  if (external_popup_menu_item_index < 0)
    return external_popup_menu_item_index;

  int index_tracker = 0;
  const HeapVector<Member<HTMLElement>>& items = owner_element.GetListItems();
  for (wtf_size_t i = 0; i < items.size(); ++i) {
    if (owner_element.ItemIsDisplayNone(*items[i]))
      continue;
#if BUILDFLAG(IS_ANDROID)
    // <hr> elements are not sent to the browser on android
    if (IsA<HTMLHRElement>(*items[i])) {
      continue;
    }
#endif
    if (index_tracker++ == external_popup_menu_item_index)
      return i;
  }
  return -1;
}

int ExternalPopupMenu::ToExternalPopupMenuItemIndex(
    int popup_menu_item_index,
    HTMLSelectElement& owner_element) {
  if (popup_menu_item_index < 0)
    return popup_menu_item_index;

  int index_tracker = 0;
  const HeapVector<Member<HTMLElement>>& items = owner_element.GetListItems();
  for (wtf_size_t i = 0; i < items.size(); ++i) {
    if (owner_element.ItemIsDisplayNone(*items[i]))
      continue;
#if BUILDFLAG(IS_ANDROID)
    // <hr> elements are not sent to the browser on android
    if (IsA<HTMLHRElement>(*items[i])) {
      continue;
    }
#endif
    if (popup_menu_item_index == static_cast<int>(i))
      return index_tracker;
    ++index_tracker;
  }
  return -1;
}

}  // namespace blink
```