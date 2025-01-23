Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for an explanation of a specific Chromium Blink file (`media_control_playback_speed_list_element.cc`). The key is to identify its purpose, how it interacts with web technologies (JavaScript, HTML, CSS), potential errors, and how a user might reach this code.

2. **Initial Scan for Keywords:**  Look for obvious terms related to web development and media:
    * `playback speed`: This is central.
    * `list`:  Indicates a collection of items.
    * `menu`: Suggests a user interface element for selection.
    * `HTMLInputElement`, `HTMLLabelElement`, `HTMLSpanElement`: These are direct indicators of HTML element manipulation.
    * `setAttribute`, `ParserAppendChild`:  Methods for modifying the DOM (Document Object Model).
    * `event.type() == event_type_names::kClick`, `event_type_names::kChange`:  Signals event handling, fundamental to web interaction.
    * `scrollIntoView`: Suggests managing the visibility of elements within a container.
    * `MediaElement`: This is a crucial class for controlling media playback.
    * `MediaControlsImpl`:  This likely represents the overall media controls functionality, and this element is a part of it.
    * `IDS_MEDIA_...`: These look like string identifiers, probably for localized text.
    * `base::UmaHistogramEnumeration`: This points to usage statistics tracking.

3. **Infer the Core Functionality:** Based on the keywords, the file's primary function seems to be managing a user interface element that allows the user to select different playback speeds for a media element. It's a *list* of *playback speeds* within the *media controls*.

4. **Analyze Interaction with Web Technologies:**

    * **HTML:** The code directly creates and manipulates HTML elements (`<label>`, `<input type="checkbox">`, `<span>`). It sets attributes like `role`, `aria-label`, `data-playback-rate`, `checked`. This means the output of this C++ code directly results in HTML structures in the browser.

    * **CSS:**  The lines `SetShadowPseudoId(...)` strongly suggest interaction with CSS. Shadow DOM is used to encapsulate the styling and structure of these controls, preventing interference from the page's main CSS. The specific pseudo-IDs (`-internal-media-controls-playback-speed-list`, etc.) are hooks for CSS styling rules defined elsewhere.

    * **JavaScript:** While there isn't explicit JavaScript code in this file, the event handling (`kClick`, `kChange`) is the bridge between user actions and C++ logic. The *result* of these events might trigger JavaScript actions elsewhere (e.g., in the `HTMLMediaElement` implementation or in other parts of the media controls). The `scrollIntoView` method is also often triggered or controlled via JavaScript.

5. **Logical Reasoning and Examples:**

    * **Input/Output:** Consider what happens when the user clicks on a playback speed.
        * **Input:** A click event on a specific list item (which is a `<label>` containing a checkbox).
        * **Processing:** The `DefaultEventHandler` handles the `kChange` event on the checkbox. It reads the `data-playback-rate` attribute, updates the `MediaElement`'s playback rate, and closes the menu.
        * **Output:** The video playback speed changes, and the playback speed menu disappears from the UI.

    * **Assumptions:**  Assume the `MediaElement()` method correctly retrieves the associated video/audio element. Assume the string IDs (`IDS_MEDIA_...`) are correctly mapped to localized text.

6. **User/Programming Errors:**

    * **User Error:**  Accidentally clicking on the wrong playback speed. The UI should provide clear visual feedback.
    * **Programming Error (within this file or related):**
        * Incorrect `playback_rate` values in the `kPlaybackSpeeds` array.
        * Forgetting to update the `aria-checked` attribute when a speed is selected (affects accessibility).
        * Issues with the `scrollIntoView` logic causing the selected item not to be centered.
        * Incorrect handling of edge cases (though this specific file seems fairly straightforward).

7. **Tracing User Steps (Debugging):** How does the user get here?  This requires thinking about the typical media playback control flow:

    1. **Play a Video/Audio:** The user needs an `<video>` or `<audio>` element on the page.
    2. **Open Media Controls:** The browser's default media controls need to be visible (often by hovering over the media element).
    3. **Access Overflow Menu:** There's usually an "overflow" or "more options" button (often represented by three dots). Clicking this opens a secondary menu.
    4. **Select Playback Speed:** Within the overflow menu, there's an option to change the playback speed. Clicking this option likely triggers the display of the `MediaControlPlaybackSpeedListElement`.

8. **Structure the Explanation:** Organize the information logically:
    * Start with the main function.
    * Explain the interaction with web technologies with clear examples.
    * Provide input/output scenarios for logical reasoning.
    * Describe potential errors.
    * Outline the user steps to reach this code.

9. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation. Make sure the examples are understandable. For instance, explicitly stating the HTML elements involved strengthens the explanation.

This iterative process of scanning, inferring, analyzing interactions, reasoning, and structuring is key to understanding and explaining complex code like this. The focus is on identifying the *purpose* and *context* of the code within the larger system.
这个文件 `media_control_playback_speed_list_element.cc` 是 Chromium Blink 引擎中负责实现媒体播放控制中 **播放速度选择列表** 功能的源代码文件。它属于媒体控制模块的一部分，用于在用户想要调整视频或音频播放速度时提供一个可选项的菜单。

以下是它的功能分解以及与 JavaScript, HTML, CSS 的关系：

**核心功能:**

1. **创建播放速度选项列表:**
   - 它定义了一组预设的播放速度值 (例如 0.25x, 0.5x, 1x, 1.25x, 1.5x, 1.75x, 2x)，这些值存储在 `kPlaybackSpeeds` 数组中。
   - 它动态地创建 HTML 元素来表示这些播放速度选项。每个选项通常是一个带有复选框的标签 (`<label>`).
   - 当用户打开播放速度菜单时，此文件中的代码会被调用来生成这些列表项。

2. **处理用户选择:**
   - 它监听用户的点击事件 (`click`) 和复选框的 `change` 事件。
   - 当用户选择一个播放速度时，它会读取与该选项关联的播放速率值（存储在 `data-playback-rate` 属性中）。
   - 它会调用 `HTMLMediaElement` 的方法 (`setDefaultPlaybackRate` 和 `setPlaybackRate`) 来更新实际的播放速度。

3. **视觉反馈和状态管理:**
   - 它会标记当前选中的播放速度选项（通过设置复选框的 `checked` 属性和 `aria-checked` 属性）。
   - 当菜单重新打开时，它会确保上次选择的播放速度被正确选中。
   - `CenterCheckedItem()` 函数用于将当前选中的项目滚动到可见区域的中心，提供更好的用户体验。

4. **辅助功能 (Accessibility):**
   - 它设置了 `role="menu"` 和 `aria-label` 属性，为屏幕阅读器等辅助技术提供关于该元素用途的描述。
   - 每个播放速度选项都有 `role="menuitemcheckbox"` 和 `aria-checked` 属性，帮助用户了解当前是否选中。
   - 使用 `aria-hidden` 来避免重复朗读标签内容。

5. **性能统计 (UMA):**
   - 它使用 `base::UmaHistogramEnumeration` 来记录用户选择的播放速度，用于分析用户行为和改进产品。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**
    - 此 C++ 代码动态地生成 HTML 结构。例如，`CreatePlaybackSpeedListItem` 函数会创建 `<label>` 和 `<input type="checkbox">` 元素。
    - 它设置 HTML 元素的属性，如 `role`, `aria-label`, `data-playback-rate`, `checked`, `tabindex` 等。
    - 例如，创建播放速度为 1.5x 的选项时，可能会生成类似以下的 HTML 结构：
      ```html
      <label role="menuitemcheckbox" aria-checked="false" aria-label="1.5x" tabindex="0">
          <span aria-hidden="true">1.5x</span>
          <input type="checkbox" aria-hidden="true" data-playback-rate="1.5" tabindex="-1">
      </label>
      ```

* **CSS:**
    - `SetShadowPseudoId` 函数用于设置元素的 Shadow DOM 的伪元素 ID (e.g., `-internal-media-controls-playback-speed-list`, `-internal-media-controls-playback-speed-list-item`)。
    - 这些伪元素 ID 可以被 CSS 选择器用来定义播放速度列表的样式，例如布局、字体、颜色、选中状态的视觉效果等。
    - 例如，你可能会在相关的 CSS 文件中找到类似以下的规则：
      ```css
      ::-webkit-media-controls-playback-speed-list {
          /* 播放速度列表的样式 */
          display: flex;
          flex-direction: column;
      }

      ::-webkit-media-controls-playback-speed-list-item {
          /* 播放速度列表项的样式 */
          padding: 5px;
      }

      ::-webkit-media-controls-playback-speed-list-item:checked {
          /* 选中状态的样式 */
          background-color: lightblue;
      }
      ```

* **JavaScript:**
    - 此 C++ 代码本身不包含 JavaScript，但它与 JavaScript 代码密切相关。
    - 当用户与播放速度列表交互时（例如点击一个选项），浏览器会触发相应的事件（`click`, `change`）。这些事件会被 Blink 引擎捕获，并最终由这个 C++ 文件中的 `DefaultEventHandler` 处理。
    - JavaScript 代码可能会负责触发播放速度菜单的显示和隐藏，或者在播放速度改变后执行其他操作。
    - 例如，一个 JavaScript 事件监听器可能会监听用户点击媒体控制栏上的“播放速度”按钮，然后调用 Blink 提供的接口来显示这个播放速度列表。

**逻辑推理 (假设输入与输出):**

**假设输入:** 用户点击了媒体播放器控制栏上的 "播放速度" 按钮，并且当前播放速度为 1.0x。

**步骤:**

1. **`SetIsWanted(true)` 被调用:**  当用户点击 "播放速度" 按钮时，可能会调用此函数来显示播放速度列表。
2. **`RefreshPlaybackSpeedListMenu()` 被调用:**  此函数会清空现有的列表项，并重新创建播放速度选项。由于当前播放速度是 1.0x，对应的复选框会被设置为选中状态。
3. **HTML 结构生成:**  会生成包含各个播放速度选项的 HTML 元素，其中 1.0x 选项的 `<input>` 元素的 `checked` 属性会被设置为 `true`，并且 `<label>` 元素的 `aria-checked` 属性也会设置为 `true`。
4. **用户点击一个非当前速度的选项 (例如 1.5x):**
   - 浏览器会触发 `click` 事件，然后触发 `change` 事件。
   - **`DefaultEventHandler` 被调用:**
     - `event.target()` 会指向与 1.5x 选项关联的 `<input>` 元素。
     - `To<Element>(target)->GetFloatingPointAttribute(PlaybackRateAttrName())` 会读取到 `1.5`。
     - `MediaElement().setDefaultPlaybackRate(1.5)` 和 `MediaElement().setPlaybackRate(1.5)` 被调用，实际更改媒体元素的播放速度。
     - `RecordPlaybackSpeedUMA(MediaControlsPlaybackSpeed::k1_5X)` 会记录该操作。
     - `SetIsWanted(false)` 被调用，关闭播放速度列表。
     - `event.SetDefaultHandled()` 阻止浏览器执行默认的复选框行为。

**输出:**

- 媒体的播放速度变为 1.5x。
- 播放速度列表菜单消失。
- 统计信息被记录。

**用户或编程常见的使用错误:**

* **用户错误:**
    - **误触:** 用户可能不小心点击了错误的播放速度选项。这可以通过清晰的 UI 和确认机制来缓解。
* **编程错误:**
    - **播放速度值不一致:**  `kPlaybackSpeeds` 数组中的显示名称和实际播放速率值可能不匹配。
    - **未更新选中状态:**  在更新播放速度后，没有正确更新选中状态的视觉反馈 (例如，复选框没有被勾选)，导致用户困惑。
    - **辅助功能属性缺失或不正确:**  忘记设置或错误设置 `role` 或 `aria-` 属性会影响使用辅助技术的用户体验。
    - **事件处理错误:**  `DefaultEventHandler` 中的逻辑错误可能导致播放速度无法正确设置或菜单无法正确关闭。
    - **性能问题:** 如果播放速度列表包含大量选项，动态创建和管理这些元素可能会影响性能。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开包含 `<video>` 或 `<audio>` 元素的网页。**
2. **媒体播放器控制栏显示。** 这通常发生在用户与媒体元素交互（例如，鼠标悬停）时。
3. **用户寻找并点击 "播放速度" 按钮或类似的菜单按钮。**  这个按钮通常会显示当前的播放速度 (例如 "1x") 或一个图标。
4. **点击 "播放速度" 按钮会触发 JavaScript 代码。**  这个 JavaScript 代码可能会：
   - 切换播放速度列表的可见性。
   - 调用 Blink 提供的接口来显示或更新播放速度列表。
5. **Blink 引擎接收到显示播放速度列表的请求。**
6. **`MediaControlPlaybackSpeedListElement::SetIsWanted(true)` 被调用。**
7. **如果需要刷新列表，`MediaControlPlaybackSpeedListElement::RefreshPlaybackSpeedListMenu()` 被调用。**  此函数会创建或更新播放速度选项的 HTML 结构。
8. **用户在列表中点击一个播放速度选项。**
9. **浏览器捕获到 `click` 事件，然后触发 `change` 事件（因为点击的是 `<label>` 包含 `<input type="checkbox">`）。**
10. **事件被路由到 `MediaControlPlaybackSpeedListElement::DefaultEventHandler()`。**
11. **`DefaultEventHandler` 中的逻辑会读取选中的播放速度，更新媒体元素的播放速率，并关闭列表。**

**调试线索:**

- 如果播放速度列表没有显示出来，检查 JavaScript 代码中是否正确处理了 "播放速度" 按钮的点击事件，以及是否调用了正确的 Blink 接口来显示列表。
- 如果播放速度列表显示不正确（例如，选项缺失或显示错误），检查 `RefreshPlaybackSpeedListMenu()` 函数中的逻辑，特别是 `kPlaybackSpeeds` 数组和 HTML 元素的创建过程。
- 如果选择播放速度后没有生效，检查 `DefaultEventHandler` 中是否正确读取了 `data-playback-rate` 属性，以及是否成功调用了 `MediaElement().setPlaybackRate()`。
- 如果辅助功能有问题，检查 `role` 和 `aria-` 属性是否设置正确。
- 使用浏览器的开发者工具 (Elements 面板) 可以查看动态生成的 HTML 结构和 CSS 样式，帮助理解代码的实际效果。
- 使用断点调试 C++ 代码可以跟踪事件处理流程和变量的值，更深入地理解代码的执行过程。

### 提示词
```
这是目录为blink/renderer/modules/media_controls/elements/media_control_playback_speed_list_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/media_controls/elements/media_control_playback_speed_list_element.h"

#include "base/metrics/histogram_functions.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_into_view_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_boolean_scrollintoviewoptions.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/frame_request_callback_collection.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_label_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_impl.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "ui/strings/grit/ax_strings.h"

namespace blink {

namespace {

// This enum is used to record histograms. Do not reorder.
enum class MediaControlsPlaybackSpeed {
  k0_25X = 0,
  k0_5X,
  k0_75X,
  k1X,
  k1_25X,
  k1_5X,
  k1_75X,
  k2X,
  kMaxValue = k2X,
};

void RecordPlaybackSpeedUMA(MediaControlsPlaybackSpeed playback_speed) {
  base::UmaHistogramEnumeration("Media.Controls.PlaybackSpeed", playback_speed);
}

struct PlaybackSpeed {
  const int display_name;
  const double playback_rate;
};

static const PlaybackSpeed kPlaybackSpeeds[] = {
    {IDS_MEDIA_OVERFLOW_MENU_PLAYBACK_SPEED_0_25X_TITLE, 0.25},
    {IDS_MEDIA_OVERFLOW_MENU_PLAYBACK_SPEED_0_5X_TITLE, 0.5},
    {IDS_MEDIA_OVERFLOW_MENU_PLAYBACK_SPEED_0_75X_TITLE, 0.75},
    {IDS_MEDIA_OVERFLOW_MENU_PLAYBACK_SPEED_NORMAL_TITLE, 1.0},
    {IDS_MEDIA_OVERFLOW_MENU_PLAYBACK_SPEED_1_25X_TITLE, 1.25},
    {IDS_MEDIA_OVERFLOW_MENU_PLAYBACK_SPEED_1_5X_TITLE, 1.5},
    {IDS_MEDIA_OVERFLOW_MENU_PLAYBACK_SPEED_1_75X_TITLE, 1.75},
    {IDS_MEDIA_OVERFLOW_MENU_PLAYBACK_SPEED_2X_TITLE, 2.0}};

const QualifiedName& PlaybackRateAttrName() {
  // Save the playback rate in an attribute.
  DEFINE_STATIC_LOCAL(QualifiedName, playback_rate_attr,
                      (AtomicString("data-playback-rate")));
  return playback_rate_attr;
}

}  // anonymous namespace

class MediaControlPlaybackSpeedListElement::RequestAnimationFrameCallback final
    : public FrameCallback {
 public:
  explicit RequestAnimationFrameCallback(
      MediaControlPlaybackSpeedListElement* list)
      : list_(list) {}

  RequestAnimationFrameCallback(const RequestAnimationFrameCallback&) = delete;
  RequestAnimationFrameCallback& operator=(
      const RequestAnimationFrameCallback&) = delete;

  void Invoke(double) override { list_->CenterCheckedItem(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(list_);
    FrameCallback::Trace(visitor);
  }

 private:
  Member<MediaControlPlaybackSpeedListElement> list_;
};

MediaControlPlaybackSpeedListElement::MediaControlPlaybackSpeedListElement(
    MediaControlsImpl& media_controls)
    : MediaControlPopupMenuElement(media_controls) {
  setAttribute(html_names::kRoleAttr, AtomicString("menu"));
  setAttribute(html_names::kAriaLabelAttr,
               WTF::AtomicString(GetLocale().QueryString(
                   IDS_MEDIA_OVERFLOW_MENU_PLAYBACK_SPEED_SUBMENU_TITLE)));
  SetShadowPseudoId(
      AtomicString("-internal-media-controls-playback-speed-list"));
}

bool MediaControlPlaybackSpeedListElement::WillRespondToMouseClickEvents() {
  return true;
}

void MediaControlPlaybackSpeedListElement::SetIsWanted(bool wanted) {
  if (wanted)
    RefreshPlaybackSpeedListMenu();

  if (!wanted && !GetMediaControls().OverflowMenuIsWanted())
    GetMediaControls().CloseOverflowMenu();

  MediaControlPopupMenuElement::SetIsWanted(wanted);
}

void MediaControlPlaybackSpeedListElement::DefaultEventHandler(Event& event) {
  if (event.type() == event_type_names::kClick) {
    // This handles the back button click. Clicking on a menu item triggers the
    // change event instead.
    GetMediaControls().ToggleOverflowMenu();
    event.SetDefaultHandled();
  } else if (event.type() == event_type_names::kChange) {
    // Identify which input element was selected and update playback speed
    Node* target = event.target()->ToNode();
    if (!target || !target->IsElementNode())
      return;

    double playback_rate =
        To<Element>(target)->GetFloatingPointAttribute(PlaybackRateAttrName());
    MediaElement().setDefaultPlaybackRate(playback_rate);
    MediaElement().setPlaybackRate(playback_rate);

    if (playback_rate == 0.25) {
      RecordPlaybackSpeedUMA(MediaControlsPlaybackSpeed::k0_25X);
    } else if (playback_rate == 0.5) {
      RecordPlaybackSpeedUMA(MediaControlsPlaybackSpeed::k0_5X);
    } else if (playback_rate == 0.75) {
      RecordPlaybackSpeedUMA(MediaControlsPlaybackSpeed::k0_75X);
    } else if (playback_rate == 1.0) {
      RecordPlaybackSpeedUMA(MediaControlsPlaybackSpeed::k1X);
    } else if (playback_rate == 1.25) {
      RecordPlaybackSpeedUMA(MediaControlsPlaybackSpeed::k1_25X);
    } else if (playback_rate == 1.5) {
      RecordPlaybackSpeedUMA(MediaControlsPlaybackSpeed::k1_5X);
    } else if (playback_rate == 1.75) {
      RecordPlaybackSpeedUMA(MediaControlsPlaybackSpeed::k1_75X);
    } else if (playback_rate == 2.0) {
      RecordPlaybackSpeedUMA(MediaControlsPlaybackSpeed::k2X);
    } else {
      NOTREACHED();
    }

    // Close the playback speed list.
    SetIsWanted(false);
    event.SetDefaultHandled();
  }
  MediaControlPopupMenuElement::DefaultEventHandler(event);
}

Element* MediaControlPlaybackSpeedListElement::CreatePlaybackSpeedListItem(
    const int display_name,
    const double playback_rate) {
  auto* playback_speed_item =
      MakeGarbageCollected<HTMLLabelElement>(GetDocument());
  playback_speed_item->SetShadowPseudoId(
      AtomicString("-internal-media-controls-playback-speed-list-item"));
  auto* playback_speed_item_input =
      MakeGarbageCollected<HTMLInputElement>(GetDocument());
  playback_speed_item_input->SetShadowPseudoId(
      AtomicString("-internal-media-controls-playback-speed-list-item-input"));
  playback_speed_item_input->setAttribute(html_names::kAriaHiddenAttr,
                                          keywords::kTrue);
  playback_speed_item_input->setType(input_type_names::kCheckbox);
  playback_speed_item_input->SetFloatingPointAttribute(PlaybackRateAttrName(),
                                                       playback_rate);
  if (playback_rate == MediaElement().playbackRate()) {
    playback_speed_item_input->SetChecked(true);
    playback_speed_item->setAttribute(html_names::kAriaCheckedAttr,
                                      keywords::kTrue);
    checked_item_ = playback_speed_item;
  }
  // Allows to focus the list entry label instead of the checkbox.
  playback_speed_item->setTabIndex(0);
  playback_speed_item_input->setTabIndex(-1);

  // Set playback speed label into an aria-hidden span so that aria will not
  // repeat the contents twice.
  auto playback_speed_label = GetLocale().QueryString(display_name);
  auto* playback_speed_label_span =
      MakeGarbageCollected<HTMLSpanElement>(GetDocument());
  playback_speed_label_span->setInnerText(playback_speed_label);
  playback_speed_label_span->setAttribute(html_names::kAriaHiddenAttr,
                                          keywords::kTrue);
  playback_speed_item->setAttribute(html_names::kAriaLabelAttr,
                                    WTF::AtomicString(playback_speed_label));
  playback_speed_item->ParserAppendChild(playback_speed_label_span);
  playback_speed_item->ParserAppendChild(playback_speed_item_input);

  return playback_speed_item;
}

Element* MediaControlPlaybackSpeedListElement::CreatePlaybackSpeedHeaderItem() {
  auto* header_item = MakeGarbageCollected<HTMLLabelElement>(GetDocument());
  header_item->SetShadowPseudoId(
      AtomicString("-internal-media-controls-playback-speed-list-header"));
  header_item->ParserAppendChild(
      Text::Create(GetDocument(),
                   GetLocale().QueryString(
                       IDS_MEDIA_OVERFLOW_MENU_PLAYBACK_SPEED_SUBMENU_TITLE)));
  header_item->setAttribute(html_names::kRoleAttr, AtomicString("button"));
  header_item->setAttribute(html_names::kAriaLabelAttr,
                            AtomicString(GetLocale().QueryString(
                                IDS_AX_MEDIA_BACK_TO_OPTIONS_BUTTON)));
  header_item->setTabIndex(0);
  return header_item;
}

void MediaControlPlaybackSpeedListElement::RefreshPlaybackSpeedListMenu() {
  EventDispatchForbiddenScope::AllowUserAgentEvents allow_events;
  RemoveChildren(kOmitSubtreeModifiedEvent);

  ParserAppendChild(CreatePlaybackSpeedHeaderItem());

  checked_item_ = nullptr;

  // Construct a menu for playback speeds.
  for (unsigned i = 0; i < std::size(kPlaybackSpeeds); i++) {
    auto& playback_speed = kPlaybackSpeeds[i];
    auto* playback_speed_item = CreatePlaybackSpeedListItem(
        playback_speed.display_name, playback_speed.playback_rate);
    playback_speed_item->setAttribute(
        html_names::kAriaSetsizeAttr,
        WTF::AtomicString::Number(std::size(kPlaybackSpeeds)));
    playback_speed_item->setAttribute(html_names::kAriaPosinsetAttr,
                                      WTF::AtomicString::Number(i + 1));
    playback_speed_item->setAttribute(html_names::kRoleAttr,
                                      AtomicString("menuitemcheckbox"));
    ParserAppendChild(playback_speed_item);
  }
  RequestAnimationFrameCallback* callback =
      MakeGarbageCollected<RequestAnimationFrameCallback>(this);
  GetDocument().RequestAnimationFrame(callback);
}

void MediaControlPlaybackSpeedListElement::CenterCheckedItem() {
  if (!checked_item_)
    return;
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("center");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  checked_item_->scrollIntoView(arg);
  checked_item_->Focus(FocusParams(FocusTrigger::kUserGesture));
}

void MediaControlPlaybackSpeedListElement::Trace(Visitor* visitor) const {
  visitor->Trace(checked_item_);
  MediaControlPopupMenuElement::Trace(visitor);
}

}  // namespace blink
```