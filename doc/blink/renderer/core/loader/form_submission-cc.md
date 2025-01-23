Response:
My thought process for analyzing the `form_submission.cc` file went something like this:

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies, logic analysis, potential errors, and how a user reaches this code. This means I need to go beyond a simple description and connect it to the bigger picture of web browsing.

2. **Initial Scan for Key Terms:** I immediately looked for keywords related to forms, submissions, HTTP methods (GET, POST), and related concepts. Terms like "FormSubmission", "HTMLFormElement", "FormData", "ResourceRequest", "navigation", "action", "method", "enctype", and "target" jumped out. This gives me a high-level understanding that the file deals with the process of submitting HTML forms.

3. **Identify Primary Classes and Functions:**  The `FormSubmission` class is clearly central. I examined its constructors and the `Create` and `Navigate` methods. The `Attributes` nested class also seemed important for managing form attributes. The static helper functions like `GenerateFormDataIdentifier` and `AppendMailtoPostFormDataToURL` are also noteworthy.

4. **Deconstruct Functionality - The "What":**  I started piecing together the steps involved in form submission based on the code:
    * **Parsing Attributes:** The `Attributes` class and its `Parse...` methods are responsible for extracting and validating information from the HTML form element and the submit button.
    * **Constructing Form Data:**  The code creates `FormData` objects and encodes them based on the form's `enctype` attribute (URL-encoded or multipart).
    * **Building the Request:**  A `ResourceRequest` is created, specifying the URL, HTTP method, headers, and body for the submission.
    * **Handling Different Submission Types:** The code differentiates between GET, POST, and `dialog` methods, as well as special cases like `mailto:` forms.
    * **Targeting and Navigation:** It determines the target frame for the submission and initiates navigation using `FrameLoadRequest`.
    * **Security Considerations:** I noticed checks for insecure requests and handling of `rel="noopener"` and `rel="noreferrer"`.

5. **Connect to Web Technologies - The "How":** This is where I linked the C++ code to the user-facing web technologies:
    * **HTML:**  The code directly interacts with `HTMLFormElement` and `HTMLFormControlElement`, parsing their attributes. The examples of `action`, `method`, `enctype`, and `target` are crucial.
    * **JavaScript:**  JavaScript can trigger form submissions programmatically using `form.submit()` or by clicking submit buttons. The code needs to handle submissions initiated by JavaScript events.
    * **CSS:**  While CSS doesn't directly influence the *submission* process, it affects the *appearance* of forms and submit buttons, which leads users to interact with them.
    * **HTTP:** The core of form submission is sending HTTP requests. The code manipulates HTTP methods, headers, and the request body.

6. **Logical Reasoning and Examples - The "Why":**  For specific code sections, I tried to understand the logic and create hypothetical scenarios:
    * **`ParseAction`:**  Inputting a URL with spaces and seeing them trimmed.
    * **`ParseEncodingType`:**  Recognizing valid `enctype` values and defaulting to URL-encoded.
    * **`AppendMailtoPostFormDataToURL`:** Imagining a mailto form with POST data and how it's appended to the URL.
    * **Conditional Logic:** Considering the `if` statements for different HTTP methods and `enctype` values.

7. **User/Programming Errors - The "Gotchas":**  I thought about common mistakes developers or users might make:
    * **Incorrect `enctype`:**  Not using `multipart/form-data` for file uploads.
    * **Missing `action`:** Forgetting to specify the submission URL.
    * **JavaScript errors:**  JavaScript code preventing the default form submission behavior.
    * **Network issues:**  While not directly in this code, the submission relies on the network.

8. **User Journey and Debugging - The "Where":**  This required tracing back from the C++ code to the user's actions:
    * **Direct Interaction:** Clicking a submit button is the most common path.
    * **JavaScript Interaction:**  JavaScript can programmatically trigger submissions.
    * **Intermediate Steps:**  The browser parses HTML, renders the form, and listens for user events.

9. **Structure and Clarity:**  Finally, I organized the information into clear sections with headings and bullet points to make it easy to understand. I tried to use concise language and avoid overly technical jargon where possible.

**Self-Correction/Refinement:**

* **Initial thought:** I initially focused too much on the low-level details of the C++ code. I realized I needed to emphasize the connections to the higher-level web technologies.
* **Adding Concrete Examples:**  The initial draft lacked specific examples for how HTML, JavaScript, and CSS interact with form submission. I added concrete HTML snippets and JavaScript scenarios to illustrate the points.
* **Clarifying the Debugging Section:** I realized the "user journey" needed to be more explicit, outlining the steps from user action to the execution of this code.

By following these steps, I aimed to provide a comprehensive and understandable explanation of the `form_submission.cc` file, catering to the various aspects of the request.
好的，让我们来分析一下 `blink/renderer/core/loader/form_submission.cc` 这个文件。

**文件功能概述**

`form_submission.cc` 文件的核心功能是处理 HTML 表单的提交过程。它负责收集表单数据，构建 HTTP 请求，并启动导航到目标 URL。更具体地说，它做了以下事情：

1. **解析表单提交属性:**  从 `HTMLFormElement` 和触发提交的元素（如 `<input type="submit">`）中提取 `action` (提交地址), `method` (提交方法，GET 或 POST), `enctype` (编码类型), `target` (目标窗口) 等属性。
2. **构建表单数据:**  根据 `enctype` 的值，将表单中的数据编码成不同的格式，例如 `application/x-www-form-urlencoded` 或 `multipart/form-data`。
3. **创建 `ResourceRequest`:**  创建一个 `ResourceRequest` 对象，其中包含了提交的目标 URL、HTTP 方法、请求头（如 `Content-Type`），以及编码后的表单数据作为请求体。
4. **处理不同的提交方法:**  根据 `method` 属性，采取不同的处理方式：
    * **GET:** 将表单数据附加到 URL 的查询字符串中。
    * **POST:** 将表单数据放在 HTTP 请求体中发送。
    * **dialog:** 用于 `<form method="dialog">`，通常与 `<dialog>` 元素一起使用，用于在不进行完整页面导航的情况下返回结果。
5. **处理 `mailto:` 协议:**  对于提交到 `mailto:` URL 的表单，会将 POST 数据特殊处理后添加到 URL 中。
6. **处理 `target` 属性:**  确定表单提交的目标帧或窗口。
7. **处理导航策略:**  根据触发事件（例如点击链接或按钮）的特性，设置导航策略，例如是否打开新窗口、是否替换当前历史记录等。
8. **触发导航:**  使用 `FrameLoader` 来执行导航操作，将页面加载到目标帧或窗口。
9. **处理安全相关的头信息:** 例如 `rel="noopener"` 和 `rel="noreferrer"` 对导航请求的影响。

**与 JavaScript, HTML, CSS 的关系及举例说明**

* **HTML:**  `form_submission.cc` 直接处理 HTML 表单元素 (`<form>`) 及其子元素（如 `<input>`, `<textarea>`, `<button>`)。它读取 HTML 属性来确定提交行为。
    * **例子:**  当用户点击一个 `<input type="submit" value="提交">` 按钮时，浏览器会查找包含该按钮的 `<form>` 元素，并使用 `form_submission.cc` 中的逻辑来处理提交。`form` 元素的 `action` 属性决定了提交的 URL，`method` 属性决定了 HTTP 方法，等等。
    ```html
    <form action="/submit-data" method="post" enctype="multipart/form-data" target="_blank">
      <input type="text" name="username" value="test">
      <input type="file" name="avatar">
      <input type="submit" value="提交">
    </form>
    ```
    在这个例子中，`form_submission.cc` 会解析 `action` 为 `/submit-data`，`method` 为 `post`，`enctype` 为 `multipart/form-data`，`target` 为 `_blank`。

* **JavaScript:** JavaScript 可以通过多种方式与表单提交交互：
    * **监听 `submit` 事件:** JavaScript 可以监听表单的 `submit` 事件，并在提交前执行自定义逻辑，例如验证表单数据或取消默认提交行为。
    * **调用 `form.submit()`:** JavaScript 可以调用表单元素的 `submit()` 方法来触发提交，这将最终调用 `form_submission.cc` 中的代码。
    * **动态修改表单属性:** JavaScript 可以动态修改表单的 `action`, `method`, `enctype` 等属性，这些修改会影响 `form_submission.cc` 的处理。
    * **创建和提交 `FormData` 对象:** JavaScript 可以手动创建 `FormData` 对象并使用 `fetch` API 发送，虽然不直接通过 HTML 表单提交，但概念上与 `form_submission.cc` 处理的数据类似。
    * **例子:**
    ```html
    <form id="myForm" action="/submit-data" method="get">
      <input type="text" name="search" value="">
      <button type="submit">搜索</button>
    </form>
    <script>
      document.getElementById('myForm').addEventListener('submit', function(event) {
        event.preventDefault(); // 阻止默认的表单提交
        const searchTerm = document.querySelector('input[name="search"]').value;
        console.log('用户搜索了:', searchTerm);
        // 可以使用 fetch API 发送数据，或者修改 form 的 action 后再提交
      });
    </script>
    ```
    在这个例子中，JavaScript 阻止了默认的提交行为，并可以执行自定义操作。如果没有 `event.preventDefault()`，点击按钮仍会触发 `form_submission.cc` 的逻辑。

* **CSS:** CSS 主要负责表单元素的外观和布局，不直接参与表单提交的逻辑。然而，用户与表单的交互（例如点击按钮）会触发提交过程，而这些按钮的外观是由 CSS 控制的。
    * **例子:**  CSS 可以样式化提交按钮，使其看起来像一个按钮，并提供视觉反馈，鼓励用户点击并提交表单。虽然 CSS 不直接调用 `form_submission.cc`，但它影响用户行为，间接地导致代码的执行。

**逻辑推理、假设输入与输出**

假设用户在一个包含以下表单的页面上操作：

```html
<form id="testForm" action="/process" method="post" enctype="application/x-www-form-urlencoded" target="_self">
  <input type="text" name="name" value="John Doe">
  <input type="email" name="email" value="john.doe@example.com">
  <button type="submit">提交</button>
</form>
```

**假设输入:** 用户点击了 "提交" 按钮。

**`form_submission.cc` 的处理过程（逻辑推理）:**

1. **解析属性:**  `form_submission.cc` 会提取 `testForm` 的属性：
   * `action`: `/process`
   * `method`: `post`
   * `enctype`: `application/x-www-form-urlencoded`
   * `target`: `_self`
2. **构建表单数据:**  由于 `enctype` 是 `application/x-www-form-urlencoded`，表单数据会被编码成类似 `name=John+Doe&email=john.doe%40example.com` 的字符串。
3. **创建 `ResourceRequest`:**
   * `url`: `/process`
   * `httpMethod`: `POST`
   * `httpBody`: 包含编码后的表单数据的 `EncodedFormData` 对象。
   * `Content-Type`: `application/x-www-form-urlencoded`
4. **确定目标帧:** `target` 是 `_self`，意味着在当前帧中加载结果。
5. **触发导航:** `FrameLoader` 会使用创建的 `ResourceRequest` 在当前帧中加载 `/process`。

**假设输出:** 浏览器会向服务器发送一个 POST 请求到 `/process`，请求体中包含编码后的表单数据。页面导航到 `/process` 的响应。

**用户或编程常见的使用错误及举例说明**

1. **`enctype` 使用不当:**
   * **错误:**  当表单包含 `<input type="file">` 时，`enctype` 没有设置为 `multipart/form-data`。
   * **后果:** 文件内容不会被正确上传到服务器，或者服务器可能无法解析请求。
   * **例子:**
     ```html
     <form action="/upload" method="post" enctype="application/x-www-form-urlencoded">
       <input type="file" name="myFile">
       <input type="submit">
     </form>
     ```
     在这个例子中，文件内容将不会被正确编码并发送。

2. **`action` 属性缺失或错误:**
   * **错误:**  `<form>` 元素没有 `action` 属性，或者 `action` 指向错误的 URL。
   * **后果:** 表单可能提交到错误的地址，导致服务器端无法处理或返回错误。
   * **例子:**
     ```html
     <form method="post">
       <input type="text" name="data">
       <input type="submit">
     </form>
     ```
     这个表单提交到哪里取决于当前页面的 URL，这可能不是期望的行为。

3. **JavaScript 阻止默认提交但未正确处理:**
   * **错误:**  JavaScript 使用 `event.preventDefault()` 阻止了默认的表单提交，但没有使用 `fetch` 或其他方法来发送数据。
   * **后果:** 表单数据不会被发送到服务器。
   * **例子:**
     ```html
     <form id="myForm" action="/submit" method="post">
       <input type="text" name="info">
       <button type="submit">提交</button>
     </form>
     <script>
       document.getElementById('myForm').addEventListener('submit', function(event) {
         event.preventDefault();
         console.log('提交被阻止了！');
         // 忘记发送数据
       });
     </script>
     ```

4. **混淆 GET 和 POST 方法:**
   * **错误:**  使用 GET 方法提交大量数据，或者提交敏感信息（如密码）。
   * **后果:**  GET 请求的 URL 长度有限制，大量数据可能会被截断。敏感信息会暴露在 URL 中，不安全。

**用户操作如何一步步到达这里 (调试线索)**

1. **用户在浏览器中加载包含 HTML 表单的网页。**
2. **用户与表单进行交互，例如填写输入框、选择选项。**
3. **用户触发表单提交，通常是通过点击 `<input type="submit">` 或 `<button type="submit">` 元素。**  也可能是 JavaScript 代码调用了 `form.submit()`。
4. **浏览器事件处理机制捕获到提交事件。**
5. **Blink 渲染引擎开始处理表单提交。** 这时，`form_submission.cc` 中的代码会被调用。
6. **`HTMLFormElement::SubmitForm()` 或类似的方法会被调用，它会创建 `FormSubmission` 对象。**
7. **`FormSubmission::Create()` 方法会被调用，负责解析表单属性和构建 `FormSubmission` 对象。**
8. **如果需要进行网络请求（GET 或 POST），`FormSubmission::Navigate()` 方法会被调用。**
9. **`FrameLoader` 使用 `ResourceRequest` 发起网络请求，并处理服务器的响应。**

**调试线索:**

* **断点:** 在 `form_submission.cc` 的关键函数（如 `FormSubmission::Create()`, `FormSubmission::Navigate()`) 设置断点，可以查看表单属性是如何被解析的，`ResourceRequest` 是如何构建的。
* **网络面板:** 浏览器的开发者工具中的 "网络" 面板可以查看实际发送的 HTTP 请求，包括 URL、方法、请求头、请求体，这可以帮助验证 `form_submission.cc` 生成的请求是否正确。
* **事件监听:**  在 JavaScript 中监听表单的 `submit` 事件，可以查看事件对象，了解提交是如何被触发的。
* **UseCounter 和 WebFeature:**  代码中使用了 `UseCounter` 来统计某些特性的使用情况，这可以提供一些关于代码执行路径的信息。

希望以上分析能够帮助你理解 `blink/renderer/core/loader/form_submission.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/core/loader/form_submission.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
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

#include "third_party/blink/renderer/core/loader/form_submission.h"

#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "third_party/blink/public/common/security_context/insecure_request_policy.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/policy_container.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/network/form_data_encoder.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"

namespace blink {

static int64_t GenerateFormDataIdentifier() {
  // Initialize to the current time to reduce the likelihood of generating
  // identifiers that overlap with those from past/future browser sessions.
  static int64_t next_identifier =
      (base::Time::Now() - base::Time::UnixEpoch()).InMicroseconds();
  return ++next_identifier;
}

static void AppendMailtoPostFormDataToURL(KURL& url,
                                          const EncodedFormData& data,
                                          const String& encoding_type) {
  String body = data.FlattenToString();

  if (EqualIgnoringASCIICase(encoding_type, "text/plain")) {
    // Convention seems to be to decode, and s/&/\r\n/. Also, spaces are encoded
    // as %20.
    body = DecodeURLEscapeSequences(
        String(body.Replace('&', "\r\n").Replace('+', ' ') + "\r\n"),
        DecodeURLMode::kUTF8OrIsomorphic);
  }

  Vector<char> body_data;
  body_data.AppendSpan(base::span_from_cstring("body="));
  FormDataEncoder::EncodeStringAsFormData(body_data, body.Utf8(),
                                          FormDataEncoder::kNormalizeCRLF);
  body = String(body_data).Replace('+', "%20");

  StringBuilder query;
  query.Append(url.Query());
  if (!query.empty())
    query.Append('&');
  query.Append(body);
  url.SetQuery(query.ToString());
}

void FormSubmission::Attributes::ParseAction(const String& action) {
  // m_action cannot be converted to KURL (bug https://crbug.com/388664)
  action_ = StripLeadingAndTrailingHTMLSpaces(action);
}

AtomicString FormSubmission::Attributes::ParseEncodingType(const String& type) {
  if (EqualIgnoringASCIICase(type, "multipart/form-data"))
    return AtomicString("multipart/form-data");
  if (EqualIgnoringASCIICase(type, "text/plain"))
    return AtomicString("text/plain");
  return AtomicString("application/x-www-form-urlencoded");
}

void FormSubmission::Attributes::UpdateEncodingType(const String& type) {
  encoding_type_ = ParseEncodingType(type);
  is_multi_part_form_ = (encoding_type_ == "multipart/form-data");
}

FormSubmission::SubmitMethod FormSubmission::Attributes::ParseMethodType(
    const String& type) {
  if (EqualIgnoringASCIICase(type, "post"))
    return FormSubmission::kPostMethod;
  if (EqualIgnoringASCIICase(type, "dialog"))
    return FormSubmission::kDialogMethod;
  return FormSubmission::kGetMethod;
}

void FormSubmission::Attributes::UpdateMethodType(const String& type) {
  method_ = ParseMethodType(type);
}

String FormSubmission::Attributes::MethodString(SubmitMethod method) {
  switch (method) {
    case kGetMethod:
      return "get";
    case kPostMethod:
      return "post";
    case kDialogMethod:
      return "dialog";
  }
  NOTREACHED();
}

void FormSubmission::Attributes::CopyFrom(const Attributes& other) {
  method_ = other.method_;
  is_multi_part_form_ = other.is_multi_part_form_;

  action_ = other.action_;
  target_ = other.target_;
  encoding_type_ = other.encoding_type_;
  accept_charset_ = other.accept_charset_;
}

inline FormSubmission::FormSubmission(
    SubmitMethod method,
    const KURL& action,
    const AtomicString& target,
    const AtomicString& content_type,
    Element* submitter,
    scoped_refptr<EncodedFormData> data,
    const Event* event,
    NavigationPolicy navigation_policy,
    mojom::blink::TriggeringEventInfo triggering_event_info,
    ClientNavigationReason reason,
    std::unique_ptr<ResourceRequest> resource_request,
    Frame* target_frame,
    WebFrameLoadType load_type,
    LocalDOMWindow* origin_window,
    const LocalFrameToken& initiator_frame_token,
    bool has_rel_opener,
    std::unique_ptr<SourceLocation> source_location,
    mojo::PendingRemote<mojom::blink::NavigationStateKeepAliveHandle>
        initiator_navigation_state_keep_alive_handle)
    : method_(method),
      action_(action),
      target_(target),
      content_type_(content_type),
      submitter_(submitter),
      form_data_(std::move(data)),
      navigation_policy_(navigation_policy),
      triggering_event_info_(triggering_event_info),
      reason_(reason),
      resource_request_(std::move(resource_request)),
      target_frame_(target_frame),
      load_type_(load_type),
      origin_window_(origin_window),
      initiator_frame_token_(initiator_frame_token),
      has_rel_opener_(has_rel_opener),
      source_location_(std::move(source_location)),
      initiator_navigation_state_keep_alive_handle_(
          std::move(initiator_navigation_state_keep_alive_handle)) {}

inline FormSubmission::FormSubmission(const String& result)
    : method_(kDialogMethod), result_(result) {}

FormSubmission* FormSubmission::Create(HTMLFormElement* form,
                                       const Attributes& attributes,
                                       const Event* event,
                                       HTMLFormControlElement* submit_button) {
  DCHECK(form);

  FormSubmission::Attributes copied_attributes;
  copied_attributes.CopyFrom(attributes);
  if (submit_button) {
    AtomicString attribute_value;
    if (!(attribute_value =
              submit_button->FastGetAttribute(html_names::kFormactionAttr))
             .IsNull())
      copied_attributes.ParseAction(attribute_value);
    if (!(attribute_value =
              submit_button->FastGetAttribute(html_names::kFormenctypeAttr))
             .IsNull())
      copied_attributes.UpdateEncodingType(attribute_value);
    if (!(attribute_value =
              submit_button->FastGetAttribute(html_names::kFormmethodAttr))
             .IsNull())
      copied_attributes.UpdateMethodType(attribute_value);
    if (!(attribute_value =
              submit_button->FastGetAttribute(html_names::kFormtargetAttr))
             .IsNull())
      copied_attributes.SetTarget(attribute_value);
  }

  if (copied_attributes.Method() == kDialogMethod) {
    if (submit_button) {
      return MakeGarbageCollected<FormSubmission>(
          submit_button->ResultForDialogSubmit());
    }
    return MakeGarbageCollected<FormSubmission>("");
  }

  Document& document = form->GetDocument();
  KURL action_url = document.CompleteURL(copied_attributes.Action().empty()
                                             ? document.Url().GetString()
                                             : copied_attributes.Action());

  if ((document.domWindow()->GetSecurityContext().GetInsecureRequestPolicy() &
       mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests) !=
          mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone &&
      action_url.ProtocolIs("http") &&
      !network::IsUrlPotentiallyTrustworthy(GURL(action_url))) {
    UseCounter::Count(document,
                      WebFeature::kUpgradeInsecureRequestsUpgradedRequestForm);
    action_url.SetProtocol("https");
    if (action_url.Port() == 80)
      action_url.SetPort(443);
  }

  bool is_mailto_form = action_url.ProtocolIs("mailto");
  bool is_multi_part_form = false;
  AtomicString encoding_type = copied_attributes.EncodingType();

  if (copied_attributes.Method() == kPostMethod) {
    is_multi_part_form = copied_attributes.IsMultiPartForm();
    if (is_multi_part_form && is_mailto_form) {
      encoding_type = AtomicString("application/x-www-form-urlencoded");
      is_multi_part_form = false;
    }
  }
  WTF::TextEncoding data_encoding =
      is_mailto_form
          ? UTF8Encoding()
          : FormDataEncoder::EncodingFromAcceptCharset(
                copied_attributes.AcceptCharset(), document.Encoding());
  FormData* dom_form_data = form->ConstructEntryList(
      submit_button, data_encoding.EncodingForFormSubmission());
  DCHECK(dom_form_data);

  scoped_refptr<EncodedFormData> form_data;
  String boundary;

  if (is_multi_part_form) {
    form_data = dom_form_data->EncodeMultiPartFormData();
    boundary = form_data->Boundary().data();
  } else {
    form_data = dom_form_data->EncodeFormData(
        attributes.Method() == kGetMethod
            ? EncodedFormData::kFormURLEncoded
            : EncodedFormData::ParseEncodingType(encoding_type));
    if (copied_attributes.Method() == kPostMethod && is_mailto_form) {
      // Convert the form data into a string that we put into the URL.
      AppendMailtoPostFormDataToURL(action_url, *form_data, encoding_type);
      form_data = EncodedFormData::Create();
    }
  }

  form_data->SetIdentifier(GenerateFormDataIdentifier());
  form_data->SetContainsPasswordData(dom_form_data->ContainsPasswordData());

  if (copied_attributes.Method() != FormSubmission::kPostMethod &&
      !action_url.ProtocolIsJavaScript()) {
    action_url.SetQuery(form_data->FlattenToString());
  }

  std::unique_ptr<ResourceRequest> resource_request =
      std::make_unique<ResourceRequest>(action_url);
  ClientNavigationReason reason = ClientNavigationReason::kFormSubmissionGet;
  if (copied_attributes.Method() == FormSubmission::kPostMethod) {
    reason = ClientNavigationReason::kFormSubmissionPost;
    resource_request->SetHttpMethod(http_names::kPOST);
    resource_request->SetHttpBody(form_data);

    // construct some user headers if necessary
    if (boundary.empty()) {
      resource_request->SetHTTPContentType(encoding_type);
    } else {
      resource_request->SetHTTPContentType(encoding_type +
                                           "; boundary=" + boundary);
    }
  }
  LocalFrame* form_local_frame = form->GetDocument().GetFrame();
  resource_request->SetHasUserGesture(
      LocalFrame::HasTransientUserActivation(form_local_frame));
  resource_request->SetFormSubmission(true);

  mojom::blink::TriggeringEventInfo triggering_event_info;
  if (event) {
    triggering_event_info =
        event->isTrusted()
            ? mojom::blink::TriggeringEventInfo::kFromTrustedEvent
            : mojom::blink::TriggeringEventInfo::kFromUntrustedEvent;
    if (event->UnderlyingEvent())
      event = event->UnderlyingEvent();
  } else {
    triggering_event_info = mojom::blink::TriggeringEventInfo::kNotFromEvent;
  }

  FrameLoadRequest frame_request(form->GetDocument().domWindow(),
                                 *resource_request);
  NavigationPolicy navigation_policy = NavigationPolicyFromEvent(event);
  if (navigation_policy == kNavigationPolicyLinkPreview) {
    return nullptr;
  }
  frame_request.SetNavigationPolicy(navigation_policy);
  frame_request.SetClientNavigationReason(reason);
  if (submit_button) {
    frame_request.SetSourceElement(submit_button);
  } else {
    frame_request.SetSourceElement(form);
  }
  frame_request.SetTriggeringEventInfo(triggering_event_info);
  AtomicString target_or_base_target = frame_request.CleanNavigationTarget(
      copied_attributes.Target().empty() ? document.BaseTarget()
                                         : copied_attributes.Target());

  if (form->HasRel(HTMLFormElement::kNoReferrer)) {
    frame_request.SetNoReferrer();
    frame_request.SetNoOpener();
  }
  if (form->HasRel(HTMLFormElement::kNoOpener) ||
      (EqualIgnoringASCIICase(target_or_base_target, "_blank") &&
       !form->HasRel(HTMLFormElement::kOpener) &&
       form->GetDocument()
           .domWindow()
           ->GetFrame()
           ->GetSettings()
           ->GetTargetBlankImpliesNoOpenerEnabledWillBeRemoved())) {
    frame_request.SetNoOpener();
  }
  if (RuntimeEnabledFeatures::RelOpenerBcgDependencyHintEnabled(
          document.domWindow()) &&
      form->HasRel(HTMLFormElement::kOpener) &&
      !frame_request.GetWindowFeatures().noopener) {
    frame_request.SetExplicitOpener();
  }

  Frame* target_frame =
      form_local_frame->Tree()
          .FindOrCreateFrameForNavigation(frame_request, target_or_base_target)
          .frame;

  // Apply replacement now, before any async steps, as the result may change.
  WebFrameLoadType load_type = WebFrameLoadType::kStandard;
  LocalFrame* target_local_frame = DynamicTo<LocalFrame>(target_frame);
  if (target_local_frame &&
      target_local_frame->NavigationShouldReplaceCurrentHistoryEntry(
          frame_request, load_type)) {
    load_type = WebFrameLoadType::kReplaceCurrentItem;
  }

  return MakeGarbageCollected<FormSubmission>(
      copied_attributes.Method(), action_url, target_or_base_target,
      encoding_type, frame_request.GetSourceElement(), std::move(form_data),
      event, frame_request.GetNavigationPolicy(), triggering_event_info, reason,
      std::move(resource_request), target_frame, load_type,
      form->GetDocument().domWindow(), form_local_frame->GetLocalFrameToken(),
      frame_request.GetWindowFeatures().explicit_opener,
      CaptureSourceLocation(form->GetDocument().domWindow()),
      form_local_frame->IssueKeepAliveHandle());
}

void FormSubmission::Trace(Visitor* visitor) const {
  visitor->Trace(submitter_);
  visitor->Trace(target_frame_);
  visitor->Trace(origin_window_);
}

void FormSubmission::Navigate() {
  FrameLoadRequest frame_request(origin_window_.Get(), *resource_request_);
  frame_request.SetNavigationPolicy(navigation_policy_);
  frame_request.SetClientNavigationReason(reason_);
  frame_request.SetSourceElement(submitter_);
  frame_request.SetTriggeringEventInfo(triggering_event_info_);
  frame_request.SetInitiatorFrameToken(initiator_frame_token_);
  frame_request.SetInitiatorNavigationStateKeepAliveHandle(
      std::move(initiator_navigation_state_keep_alive_handle_));
  frame_request.SetSourceLocation(std::move(source_location_));
  if (has_rel_opener_) {
    frame_request.SetExplicitOpener();
  }

  if (target_frame_ && !target_frame_->GetPage())
    return;

  if (target_frame_)
    target_frame_->Navigate(frame_request, load_type_);
}

}  // namespace blink
```