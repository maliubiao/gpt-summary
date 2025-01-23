Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Core Purpose:** The file name `date_time_chooser_impl.cc` and the namespace `blink` and mention of `chromium` immediately suggest this is part of a web browser's rendering engine, specifically handling the date/time picker functionality for HTML `<input>` elements.

2. **Identify Key Classes and Relationships:**  Scan the `#include` directives and the class declaration. We see:
    * `DateTimeChooserImpl`: This is the central class we're analyzing.
    * `DateTimeChooserClient`:  This looks like an interface or abstract class that `DateTimeChooserImpl` interacts with. It likely handles communication back to the form element.
    * `DateTimeChooserParameters`: A struct or class holding the input parameters needed to configure the chooser.
    * `LocalFrame`, `LocalFrameView`, `ChromeClient`, `PagePopup`: These are related to the browser's windowing and rendering mechanisms. The popup suggests a separate window or overlay for the date/time picker.
    * `InputType::Type`: An enum likely defining the different types of date/time inputs (date, time, datetime-local, etc.).
    * `DateComponents`: A class for representing and manipulating date/time values.
    * Resource loaders (`ChooserResourceLoader`) suggest the chooser has its own HTML, CSS, and JavaScript.

3. **Analyze the Constructor and Destructor:**
    * The constructor initializes the object, taking parameters like `LocalFrame`, `DateTimeChooserClient`, and `DateTimeChooserParameters`. It also creates a `PagePopup`. The `DCHECK` statements are important – they enforce preconditions.
    * The destructor is a default one, meaning no explicit cleanup is needed beyond what the members' destructors handle.

4. **Examine Key Methods:** Focus on methods that seem to have core functionality:
    * `EndChooser()`:  Closes the popup.
    * `WriteDocument()`: This is a crucial method. It generates the HTML content for the date/time picker popup. This is where the interaction with HTML, CSS, and JavaScript will be most evident. Pay close attention to how it uses `ChooserResourceLoader` and constructs the `window.dialogArguments` object.
    * `SetValueAndClosePopup()`, `SetValue()`: These methods handle the user's selection, passing the chosen value back to the client.
    * `CancelPopup()`:  Handles closing the popup without a selection.
    * `DidClosePopup()`:  Notifies the client when the popup is closed.
    * `AdjustSettings()`: Likely allows for customization of the popup's settings.

5. **Trace Data Flow in `WriteDocument()`:** This is the most complex method and requires careful analysis:
    * It starts by setting up the basic HTML structure (`<!DOCTYPE html>`, `<head>`, `<style>`, `<body>`).
    * It loads CSS from `ChooserResourceLoader`. This confirms the use of CSS for styling.
    * It creates a `window.dialogArguments` JavaScript object. This object holds data passed from the C++ code to the JavaScript running in the popup. This is the **key bridge** between the C++ implementation and the UI.
    * It populates `window.dialogArguments` with values from `parameters_`, such as min/max dates, step values, the current value, locale information, and even labels (using `GetLocale().QueryString()`).
    * It loads JavaScript files from `ChooserResourceLoader`. This confirms the use of JavaScript for the interactive logic of the picker.
    * It includes conditional logic based on the `parameters_->type` to load specific CSS and JavaScript (e.g., for time pickers).
    * The inclusion of suggestion-related properties indicates support for pre-filled or suggested values.

6. **Connect to Web Technologies:**  Now, explicitly link the code to HTML, CSS, and JavaScript:
    * **HTML:** The `WriteDocument()` method generates the basic structure of the date/time picker UI. The `<div id=main>` is likely a placeholder that JavaScript will manipulate.
    * **CSS:**  The `ChooserResourceLoader::Get*StyleSheet()` calls load CSS rules that control the visual appearance of the picker.
    * **JavaScript:** The `ChooserResourceLoader::Get*JS()` calls load JavaScript code that handles user interactions, updates the UI, and sends the selected value back. The `window.dialogArguments` object is how C++ data is made available to this JavaScript.

7. **Consider User Interactions and Errors:** Think about how a user interacts with a date/time input field and how this code supports that:
    * Clicking on a date/time input field triggers the browser to create and show the picker (handled by the browser's UI and invoking this C++ code).
    * The user then interacts with the calendar or time selection controls in the popup (implemented in the JavaScript).
    *  Potential errors:
        * Entering values outside the `min` and `max` range.
        * Incorrect date/time formats (although the picker UI should largely prevent this).
        * Issues with locale settings causing display problems.

8. **Logical Reasoning and Assumptions:** Identify places where the code makes assumptions or performs logic:
    * The `ValueToDateTimeString()` function converts numerical values to date/time strings based on the input type. Assumptions are made about the meaning of the numerical values for each type.
    * The code uses locale-specific information (first day of the week, month names, etc.).
    * The logic for handling suggestions involves iterating through the `parameters_->suggestions` vector.

9. **Step-by-Step User Operation:**  Trace the user's journey:
    1. User encounters an `<input type="date">` (or similar) element on a webpage.
    2. User clicks or focuses on this input field.
    3. The browser detects the input type and determines that a date/time picker is needed.
    4. The browser's rendering engine (Blink) creates a `DateTimeChooserImpl` object, passing relevant information (the `DateTimeChooserParameters`).
    5. The `DateTimeChooserImpl` creates a popup window.
    6. The `WriteDocument()` method is called to generate the HTML, CSS, and JavaScript for the popup.
    7. The popup is displayed to the user.
    8. The user interacts with the calendar or time controls (handled by JavaScript).
    9. The user clicks "OK" or a similar confirmation button (handled by JavaScript, which calls back to C++).
    10. The JavaScript in the popup calls `window.opener.dialogArguments.callback(...)` (or similar), which eventually leads to the `SetValue()` method in `DateTimeChooserImpl`.
    11. The `SetValue()` method updates the original input field's value.
    12. The popup closes.

10. **Refine and Organize:**  Structure the analysis clearly, using headings and bullet points. Provide concrete examples for HTML, CSS, and JavaScript interactions. Ensure the explanation flows logically.

This detailed thinking process helps in dissecting the code, understanding its purpose, and connecting it to the broader context of web development. It also allows for identifying potential areas of interaction with web technologies and common user scenarios.
好的，让我们详细分析一下 `blink/renderer/core/html/forms/date_time_chooser_impl.cc` 这个文件的功能。

**文件功能总览**

`date_time_chooser_impl.cc` 文件实现了 Chromium Blink 引擎中用于显示日期和时间选择器（俗称“日历弹出框”或“时间选择器”）的逻辑。当网页上的 `<input type="date">`, `<input type="time">`, `<input type="datetime-local">`, `<input type="month">`, 或 `<input type="week">` 元素被激活时，浏览器会调用这个文件中的代码来创建一个弹出式的日期/时间选择界面。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件虽然是 C++ 代码，但它与 JavaScript、HTML 和 CSS 紧密相关，因为它负责生成和控制选择器弹出的用户界面。

1. **HTML (结构):**
   - `WriteDocument` 方法负责生成弹出框的 HTML 结构。
   - 例如，你可以看到代码中拼接了基本的 HTML 框架，包括 `<head>` 和 `<body>` 标签。
   - `<div id=main>Loading...</div>`  这部分创建了一个占位符，JavaScript 将会在加载完成后填充选择器的实际内容。

   ```c++
   void DateTimeChooserImpl::WriteDocument(SegmentedBuffer& data) {
     AddString(
         "<!DOCTYPE html><head><meta charset='UTF-8'><meta name='color-scheme' "
         "content='light dark'><style>\n",
         data);
     // ... 更多 CSS 加载 ...
     AddString(
         "</style></head><body><div id=main>Loading...</div><script>\n"
         "window.dialogArguments = {\n",
         data);
     // ... JavaScript 数据传递 ...
     AddString("}\n", data);
     // ... JavaScript 加载 ...
     AddString("</script></body>\n", data);
   }
   ```

2. **CSS (样式):**
   - `WriteDocument` 方法会加载多个 CSS 文件，这些文件定义了日期/时间选择器的视觉样式。
   - `ChooserResourceLoader::GetPickerCommonStyleSheet()` 获取通用的选择器样式。
   - `ChooserResourceLoader::GetSuggestionPickerStyleSheet()` 获取建议列表的样式。
   - `ChooserResourceLoader::GetCalendarPickerStyleSheet()` 获取日历选择器的样式。
   - `ChooserResourceLoader::GetTimePickerStyleSheet()` 获取时间选择器的样式。
   - 代码中还动态添加了一些内联 CSS，例如设置禁用状态下按钮的颜色。

3. **JavaScript (交互逻辑):**
   - `WriteDocument` 方法会加载多个 JavaScript 文件，这些文件负责处理选择器的交互逻辑，例如：
     - 渲染日历网格。
     - 处理用户的点击事件（选择日期、月份、年份等）。
     - 更新时间字段。
     - 将用户选择的值传递回原始的 HTML 表单元素。
   - **关键的桥梁是 `window.dialogArguments`:**  C++ 代码将需要传递给 JavaScript 的数据（例如，当前值、最小值、最大值、本地化字符串等）放入一个名为 `window.dialogArguments` 的 JavaScript 对象中。JavaScript 代码可以访问这个对象来初始化和控制选择器。

   ```c++
   void DateTimeChooserImpl::WriteDocument(SegmentedBuffer& data) {
       // ...
       AddString(
           "</style></head><body><div id=main>Loading...</div><script>\n"
           "window.dialogArguments = {\n",
           data);
       AddProperty("anchorRectInScreen", parameters_->anchor_rect_in_screen, data);
       AddProperty("zoomFactor", ScaledZoomFactor(), data);
       AddProperty("min",
                   ValueToDateTimeString(parameters_->minimum, parameters_->type),
                   data);
       // ... 更多属性 ...
       AddString("}\n", data);

       data.Append(ChooserResourceLoader::GetPickerCommonJS());
       data.Append(ChooserResourceLoader::GetSuggestionPickerJS());
       data.Append(ChooserResourceLoader::GetMonthPickerJS());
       // ... 更多 JavaScript 加载 ...
       AddString("</script></body>\n", data);
   }
   ```

**逻辑推理、假设输入与输出**

假设用户在一个包含以下 HTML 的网页上与日期输入框交互：

```html
<input type="date" id="myDate" min="2023-01-01" max="2023-12-31" value="2023-07-15">
```

1. **假设输入:** 用户点击了这个日期输入框。
2. **DateTimeChooserImpl 的初始化:**
   - `DateTimeChooserImpl` 的构造函数会被调用，传入以下参数（简化）：
     - `frame_`:  当前页面的框架对象。
     - `client_`:  一个回调接口，用于将选择的值返回给输入元素。
     - `parameters`: 一个包含从 HTML 元素提取的参数的对象，例如：
       - `parameters.type`: `InputType::Type::kDate`
       - `parameters.minimum`:  代表 "2023-01-01" 的时间戳。
       - `parameters.maximum`:  代表 "2023-12-31" 的时间戳。
       - `parameters.double_value`: 代表 "2023-07-15" 的时间戳。
       - `parameters.locale`:  用户的语言环境设置。
3. **`WriteDocument` 的执行:**
   - `WriteDocument` 方法会被调用来生成弹出框的 HTML。
   - **假设输出 (部分 `window.dialogArguments`):**
     ```javascript
     window.dialogArguments = {
       "min": "2023-01-01",
       "max": "2023-12-31",
       "currentValue": "2023-07-15",
       "locale": "zh-CN", // 假设用户是中文环境
       // ... 其他属性 ...
     }
     ```
4. **JavaScript 处理:**  加载的 JavaScript 代码会读取 `window.dialogArguments`，并据此渲染出一个日历界面，其中：
   - 最小可选日期是 2023 年 1 月 1 日。
   - 最大可选日期是 2023 年 12 月 31 日。
   - 默认选中的日期是 2023 年 7 月 15 日。
   - 界面上的文字会根据 `locale` 设置显示为中文。
5. **用户交互:** 用户在日历上选择了一个新的日期，比如 2023 年 8 月 20 日。
6. **值传递回 C++:** JavaScript 代码会将 "2023-08-20" 这个字符串传递回 C++ 的 `DateTimeChooserImpl` 对象。
7. **`SetValueAndClosePopup` 或 `SetValue` 调用:**  `SetValue("2023-08-20")` 方法会被调用。
8. **回调到客户端:** `client_->DidChooseValue("2023-08-20")` 被调用，将选择的值传递回负责管理输入元素的 C++ 代码。
9. **HTML 更新:**  网页上的 `<input id="myDate">` 元素的 `value` 属性会被更新为 "2023-08-20"。

**用户或编程常见的使用错误举例**

1. **`min` 和 `max` 属性设置错误:**
   - **用户操作:** 开发者在 HTML 中设置了 `min` 和 `max` 属性，但是 `max` 的值小于 `min` 的值。
   - **结果:**  日期选择器可能会表现异常，例如无法打开，或者可选日期范围不正确。
   - **代码体现:** `WriteDocument` 方法会将这些错误的值传递给 JavaScript，但 JavaScript 可能会有自己的校验逻辑来处理这种情况，或者直接导致 UI 错误。

2. **`step` 属性设置不合理:**
   - **用户操作:** 对于时间类型的输入框，开发者设置了一个非法的 `step` 值（例如，对于分钟选择，`step` 设置为大于 60 的值）。
   - **结果:** 时间选择器的步进逻辑会出错，可能无法按照预期进行增减。
   - **代码体现:** `WriteDocument` 会将 `parameters_->step` 的值传递给 JavaScript，JavaScript 负责根据这个值来控制时间的步进。

3. **本地化问题:**
   - **用户操作:**  开发者没有考虑到不同用户的语言环境，依赖硬编码的字符串或者假设特定的日期格式。
   - **结果:**  日期选择器在不同的语言环境下显示不正确，例如月份名称、星期几的显示错误。
   - **代码体现:** `DateTimeChooserImpl` 使用 `Locale` 对象来获取本地化的字符串，例如 `GetLocale().QueryString(IDS_FORM_CALENDAR_TODAY)`。如果系统的本地化配置不正确，或者 Blink 没有正确获取到用户的语言环境，就可能出现问题.

4. **JavaScript 错误:**
   - **编程错误:**  负责日期选择器交互的 JavaScript 代码中存在错误。
   - **结果:**  日期选择器可能无法正常工作，例如无法响应用户的点击，或者无法将选择的值传递回 HTML 元素。
   - **代码体现:** 虽然 C++ 代码本身没有 JavaScript 错误，但它负责加载 JavaScript 代码。如果加载的 JavaScript 文件存在问题，就会影响日期选择器的功能。

**用户操作如何一步步到达这里**

1. **用户打开一个包含日期/时间输入框的网页。** 例如，一个带有 `<input type="date" id="birthday">` 的表单。
2. **用户点击或聚焦于该输入框。** 浏览器检测到这是一个需要特定 UI 控件的表单元素。
3. **浏览器（更具体地说是 Blink 渲染引擎）判断需要显示一个日期选择器。**  这通常是基于输入框的 `type` 属性。
4. **Blink 创建一个 `DateTimeChooserImpl` 对象。**  这个对象负责管理日期选择器的生命周期和用户界面。
5. **`DateTimeChooserImpl` 调用 `frame_->View()->GetChromeClient()->OpenPagePopup(this)`。**  这会请求浏览器创建一个弹出窗口来显示日期选择器。
6. **`DateTimeChooserImpl::WriteDocument` 方法被调用。**  这个方法生成弹出窗口的 HTML 内容，包括必要的 CSS 和 JavaScript。
7. **浏览器加载并渲染 `WriteDocument` 生成的 HTML 内容。**  用户看到日期选择器的界面。
8. **用户与日期选择器进行交互，选择日期或时间。**  这个交互主要由加载的 JavaScript 代码处理。
9. **用户点击“确定”或类似按钮来确认选择。**  JavaScript 代码将用户选择的值传递回 C++ 代码。
10. **`DateTimeChooserImpl::SetValueAndClosePopup` 或 `DateTimeChooserImpl::SetValue` 被调用。**
11. **`client_->DidChooseValue(value)` 被调用。**  `client_` 通常是管理该输入框的更高层级的对象，它会更新 HTML 输入框的 `value` 属性。
12. **弹出窗口关闭。**
13. **用户在原始网页的输入框中看到了他们选择的日期或时间。**

总而言之，`date_time_chooser_impl.cc` 是 Blink 渲染引擎中实现日期和时间选择器功能的核心 C++ 代码，它负责生成选择器的 HTML 结构、引入 CSS 样式、加载 JavaScript 交互逻辑，并将用户的选择传递回网页。它在 Web 技术栈中扮演着连接底层 C++ 逻辑和前端用户界面的重要角色。

### 提示词
```
这是目录为blink/renderer/core/html/forms/date_time_chooser_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/html/forms/date_time_chooser_impl.h"

#include "build/build_config.h"
#include "third_party/blink/public/mojom/choosers/date_time_chooser.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/forms/chooser_resource_loader.h"
#include "third_party/blink/renderer/core/html/forms/date_time_chooser_client.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page_popup.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/renderer/platform/text/date_components.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "ui/base/ui_base_features.h"
#include "ui/strings/grit/ax_strings.h"

namespace blink {

DateTimeChooserImpl::DateTimeChooserImpl(
    LocalFrame* frame,
    DateTimeChooserClient* client,
    const DateTimeChooserParameters& parameters)
    : frame_(frame),
      client_(client),
      popup_(nullptr),
      parameters_(&parameters),
      locale_(Locale::Create(parameters.locale)) {
  DCHECK(RuntimeEnabledFeatures::InputMultipleFieldsUIEnabled());
  DCHECK(frame_);
  DCHECK(client_);
  popup_ = frame_->View()->GetChromeClient()->OpenPagePopup(this);
  parameters_ = nullptr;
}

DateTimeChooserImpl::~DateTimeChooserImpl() = default;

void DateTimeChooserImpl::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(client_);
  DateTimeChooser::Trace(visitor);
}

void DateTimeChooserImpl::EndChooser() {
  if (!popup_)
    return;
  frame_->View()->GetChromeClient()->ClosePagePopup(popup_);
}

AXObject* DateTimeChooserImpl::RootAXObject(Element* popup_owner) {
  return popup_ ? popup_->RootAXObject(popup_owner) : nullptr;
}

static String ValueToDateTimeString(double value, InputType::Type type) {
  DateComponents components;
  switch (type) {
    case InputType::Type::kDate:
      components.SetMillisecondsSinceEpochForDate(value);
      break;
    case InputType::Type::kDateTimeLocal:
      components.SetMillisecondsSinceEpochForDateTimeLocal(value);
      break;
    case InputType::Type::kMonth:
      components.SetMonthsSinceEpoch(value);
      break;
    case InputType::Type::kTime:
      components.SetMillisecondsSinceMidnight(value);
      break;
    case InputType::Type::kWeek:
      components.SetMillisecondsSinceEpochForWeek(value);
      break;
    default:
      NOTREACHED();
  }
  return components.GetType() == DateComponents::kInvalid
             ? String()
             : components.ToString();
}

void DateTimeChooserImpl::WriteDocument(SegmentedBuffer& data) {
  String step_string = String::Number(parameters_->step);
  String step_base_string = String::Number(parameters_->step_base, 11);
  String today_label_string;
  String other_date_label_string;
  switch (parameters_->type) {
    case InputType::Type::kMonth:
      today_label_string = GetLocale().QueryString(IDS_FORM_THIS_MONTH_LABEL);
      other_date_label_string =
          GetLocale().QueryString(IDS_FORM_OTHER_MONTH_LABEL);
      break;
    case InputType::Type::kWeek:
      today_label_string = GetLocale().QueryString(IDS_FORM_THIS_WEEK_LABEL);
      other_date_label_string =
          GetLocale().QueryString(IDS_FORM_OTHER_WEEK_LABEL);
      break;
    default:
      today_label_string = GetLocale().QueryString(IDS_FORM_CALENDAR_TODAY);
      other_date_label_string =
          GetLocale().QueryString(IDS_FORM_OTHER_DATE_LABEL);
  }

  AddString(
      "<!DOCTYPE html><head><meta charset='UTF-8'><meta name='color-scheme' "
      "content='light dark'><style>\n",
      data);

  data.Append(ChooserResourceLoader::GetPickerCommonStyleSheet());
  data.Append(ChooserResourceLoader::GetSuggestionPickerStyleSheet());

  const String& disabled_color_style =
      RuntimeEnabledFeatures::
              CalendarPickerMonthPopupButtonDisabledColorEnabled()
          ? ":root { --month-popup-button-disabled-color: rgba(16, 16, 16, "
            "0.9) }"
          : ":root { --month-popup-button-disabled-color: rgba(16, 16, 16, "
            "0.3) }";
  AddString(disabled_color_style, data);

  data.Append(ChooserResourceLoader::GetCalendarPickerStyleSheet());
  if (parameters_->type == InputType::Type::kTime ||
      parameters_->type == InputType::Type::kDateTimeLocal) {
    data.Append(ChooserResourceLoader::GetTimePickerStyleSheet());
  }
  AddString(
      "</style></head><body><div id=main>Loading...</div><script>\n"
      "window.dialogArguments = {\n",
      data);
  AddProperty("anchorRectInScreen", parameters_->anchor_rect_in_screen, data);
  AddProperty("zoomFactor", ScaledZoomFactor(), data);
  AddProperty("min",
              ValueToDateTimeString(parameters_->minimum, parameters_->type),
              data);
  AddProperty("max",
              ValueToDateTimeString(parameters_->maximum, parameters_->type),
              data);
  AddProperty("step", step_string, data);
  AddProperty("stepBase", step_base_string, data);
  AddProperty("required", parameters_->required, data);
  AddProperty(
      "currentValue",
      ValueToDateTimeString(parameters_->double_value, parameters_->type),
      data);
  AddProperty("focusedFieldIndex", parameters_->focused_field_index, data);
  AddProperty("locale", parameters_->locale.GetString(), data);
  AddProperty("todayLabel", today_label_string, data);
  AddLocalizedProperty("clearLabel", IDS_FORM_CALENDAR_CLEAR, data);
  AddLocalizedProperty("weekLabel", IDS_FORM_WEEK_NUMBER_LABEL, data);
  AddLocalizedProperty("axShowMonthSelector",
                       IDS_AX_CALENDAR_SHOW_MONTH_SELECTOR, data);
  AddLocalizedProperty("axShowNextMonth", IDS_AX_CALENDAR_SHOW_NEXT_MONTH,
                       data);
  AddLocalizedProperty("axShowPreviousMonth",
                       IDS_AX_CALENDAR_SHOW_PREVIOUS_MONTH, data);
  AddLocalizedProperty("axHourLabel", IDS_AX_HOUR_FIELD_TEXT, data);
  AddLocalizedProperty("axMinuteLabel", IDS_AX_MINUTE_FIELD_TEXT, data);
  AddLocalizedProperty("axSecondLabel", IDS_AX_SECOND_FIELD_TEXT, data);
  AddLocalizedProperty("axMillisecondLabel", IDS_AX_MILLISECOND_FIELD_TEXT,
                       data);
  AddLocalizedProperty("axAmPmLabel", IDS_AX_AM_PM_FIELD_TEXT, data);
  AddProperty("weekStartDay", locale_->FirstDayOfWeek(), data);
  AddProperty("shortMonthLabels", locale_->ShortMonthLabels(), data);
  AddProperty("dayLabels", locale_->WeekDayShortLabels(), data);
  AddProperty("ampmLabels", locale_->TimeAMPMLabels(), data);
  AddProperty("isLocaleRTL", locale_->IsRTL(), data);
  AddProperty("isRTL", parameters_->is_anchor_element_rtl, data);
#if BUILDFLAG(IS_MAC)
  AddProperty("isBorderTransparent", true, data);
#endif
  AddProperty("mode", InputType::TypeToString(parameters_->type).GetString(),
              data);
  AddProperty("isAMPMFirst", parameters_->is_ampm_first, data);
  AddProperty("hasAMPM", parameters_->has_ampm, data);
  AddProperty("hasSecond", parameters_->has_second, data);
  AddProperty("hasMillisecond", parameters_->has_millisecond, data);
  if (parameters_->suggestions.size()) {
    Vector<String> suggestion_values;
    Vector<String> localized_suggestion_values;
    Vector<String> suggestion_labels;
    for (unsigned i = 0; i < parameters_->suggestions.size(); i++) {
      suggestion_values.push_back(ValueToDateTimeString(
          parameters_->suggestions[i]->value, parameters_->type));
      localized_suggestion_values.push_back(
          parameters_->suggestions[i]->localized_value);
      suggestion_labels.push_back(parameters_->suggestions[i]->label);
    }
    AddProperty("suggestionValues", suggestion_values, data);
    AddProperty("localizedSuggestionValues", localized_suggestion_values, data);
    AddProperty("suggestionLabels", suggestion_labels, data);
    AddProperty(
        "inputWidth",
        static_cast<unsigned>(parameters_->anchor_rect_in_screen.width()),
        data);
    AddProperty(
        "showOtherDateEntry",
        LayoutTheme::GetTheme().SupportsCalendarPicker(parameters_->type),
        data);
    AddProperty("otherDateLabel", other_date_label_string, data);

    const ComputedStyle* style = OwnerElement().GetComputedStyle();
    mojom::blink::ColorScheme color_scheme =
        style ? style->UsedColorScheme() : mojom::blink::ColorScheme::kLight;

    AddProperty("suggestionHighlightColor",
                LayoutTheme::GetTheme()
                    .ActiveListBoxSelectionBackgroundColor(color_scheme)
                    .SerializeAsCSSColor(),
                data);
    AddProperty("suggestionHighlightTextColor",
                LayoutTheme::GetTheme()
                    .ActiveListBoxSelectionForegroundColor(color_scheme)
                    .SerializeAsCSSColor(),
                data);
  }
  AddString("}\n", data);

  data.Append(ChooserResourceLoader::GetPickerCommonJS());
  data.Append(ChooserResourceLoader::GetSuggestionPickerJS());
  data.Append(ChooserResourceLoader::GetMonthPickerJS());
  if (parameters_->type == InputType::Type::kTime) {
    data.Append(ChooserResourceLoader::GetTimePickerJS());
  } else if (parameters_->type == InputType::Type::kDateTimeLocal) {
    data.Append(ChooserResourceLoader::GetTimePickerJS());
    data.Append(ChooserResourceLoader::GetDateTimeLocalPickerJS());
  }
  data.Append(ChooserResourceLoader::GetCalendarPickerJS());
  AddString("</script></body>\n", data);
}

Element& DateTimeChooserImpl::OwnerElement() {
  return client_->OwnerElement();
}

ChromeClient& DateTimeChooserImpl::GetChromeClient() {
  return *frame_->View()->GetChromeClient();
}

Locale& DateTimeChooserImpl::GetLocale() {
  return *locale_;
}

void DateTimeChooserImpl::SetValueAndClosePopup(int num_value,
                                                const String& string_value) {
  if (num_value >= 0)
    SetValue(string_value);
  EndChooser();
}

void DateTimeChooserImpl::SetValue(const String& value) {
  client_->DidChooseValue(value);
}

void DateTimeChooserImpl::CancelPopup() {
  EndChooser();
}

void DateTimeChooserImpl::DidClosePopup() {
  DCHECK(client_);
  popup_ = nullptr;
  client_->DidEndChooser();
}

void DateTimeChooserImpl::AdjustSettings(Settings& popup_settings) {
  AdjustSettingsFromOwnerColorScheme(popup_settings);
}

}  // namespace blink
```