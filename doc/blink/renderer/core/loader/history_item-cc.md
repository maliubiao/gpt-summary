Response:
Let's break down the request and the provided code to construct a comprehensive answer.

**1. Understanding the Goal:**

The request asks for a detailed explanation of the `history_item.cc` file in Chromium's Blink rendering engine. The key is to identify its purpose, its relationship with web technologies (JavaScript, HTML, CSS), and common usage scenarios, especially errors and debugging.

**2. Initial Code Analysis (Skimming):**

A quick glance reveals several important aspects:

* **Includes:**  The file includes headers related to page state, URLs, form data, serialization, and other core Blink components. This suggests `HistoryItem` deals with saving and restoring browsing states.
* **`HistoryItem` Class:** The core of the file defines the `HistoryItem` class.
* **`Create` Method:**  A static `Create` method suggests a factory pattern for creating `HistoryItem` objects from `PageState`. This hints at deserialization.
* **Setters and Getters:**  Numerous `Set...` and `Get...` methods indicate the class holds various pieces of information related to a browsing history entry (URL, referrer, scroll position, form data, etc.).
* **`ToPageState` Method:** This strongly suggests the reverse of `Create`: serializing a `HistoryItem` back into a `PageState`.
* **`GenerateResourceRequest`:**  This method suggests `HistoryItem` can be used to recreate network requests.
* **`DocumentState`:**  The presence of `DocumentState` and related methods indicates interaction with the state of the rendered document.
* **`SerializedScriptValue`:**  The usage of this class points to saving and restoring JavaScript state.
* **`ScrollAnchorData`:**  This suggests saving and restoring scroll positions based on specific elements.

**3. Deep Dive and Functional Analysis (Connecting the Dots):**

Now, let's go through the code more systematically to infer the functions:

* **Representing Browsing History:** The core function is clearly to represent a single entry in the browser's history. This includes all the information needed to go back or forward to a specific page state.
* **Saving Page State:** The `ToPageState` method is crucial here. It serializes the `HistoryItem`'s data into a `PageState` object, which is likely stored by the browser. This includes:
    * URL, referrer, target.
    * Scroll position and scale.
    * Form data.
    * JavaScript state (using `SerializedScriptValue`).
    * Scroll anchor information.
    * Document-specific state (using `DocumentState`).
    * Navigation API state.
* **Restoring Page State:** The `Create` method does the reverse. It takes a `PageState` and creates a `HistoryItem`. This is used when navigating back or forward.
* **Recreating Requests:** `GenerateResourceRequest` allows the browser to reconstruct the original network request associated with a history item. This is needed when navigating back/forward or when the page needs to be reloaded from history.
* **Managing Form Data:** The class handles storing and retrieving form data, including file uploads.
* **Handling Scroll Restoration:** The `scroll_offset`, `page_scale_factor`, and `scroll_anchor_data` members are explicitly for saving and restoring the viewport's scroll position and zoom level. The scroll anchor helps to maintain the user's context when navigating back or forward.
* **Storing JavaScript State:** `state_object_` and `navigation_api_state_` use `SerializedScriptValue` to capture the state of the JavaScript environment. This is important for features like `history.pushState` and `history.replaceState`.
* **Unique Identifiers:**  `item_sequence_number_` and `document_sequence_number_` likely help in managing the history stack and distinguishing different entries. `navigation_api_key_` and `navigation_api_id_` are related to the Navigation API.

**4. Relationship with Web Technologies:**

* **HTML:** The `HistoryItem` stores the URL, which points to an HTML document. It also stores the document state, potentially including information derived from the HTML structure. The scroll anchor feature directly relates to elements within the HTML.
* **CSS:** While not directly storing CSS, the scroll position and zoom level are affected by how the CSS renders the page.
* **JavaScript:** The most significant relationship is through `SerializedScriptValue`. This allows JavaScript state (variables, objects) to be saved and restored when navigating through history. The Navigation API (using `pushState`, `replaceState`, `popstate` event) directly manipulates the browser's history and the state associated with `HistoryItem` objects.

**5. Logical Reasoning, Assumptions, and Examples:**

This involves creating scenarios to illustrate how `HistoryItem` works.

* **Assumption:**  When the user navigates to a new page or uses `history.pushState`, a new `HistoryItem` is created and added to the browser's history stack.
* **Assumption:** When the user clicks the back or forward button, the browser retrieves the corresponding `HistoryItem` and uses its data to restore the page.

**Example (Navigation):**

* **Input:** User navigates from `pageA.html` to `pageB.html`.
* **Process:** A `HistoryItem` is created for `pageA.html` (capturing its state) and added to the history. A new `HistoryItem` is created for `pageB.html`.
* **Output (Back Button):** When the user clicks "back", the `HistoryItem` for `pageA.html` is retrieved. The browser uses the data in this `HistoryItem` (URL, scroll position, JavaScript state, etc.) to restore `pageA.html` to its previous state.

**Example (`history.pushState`):**

* **Input (JavaScript):** `window.history.pushState({data: 'myData'}, 'Title', '/newPage');`
* **Process:** A new `HistoryItem` is created with the URL `/newPage`, the title "Title", and the state object `{data: 'myData'}` (serialized).
* **Output (Back Button):** When the user clicks "back", the `popstate` event is fired, and the `event.state` will contain the deserialized `{data: 'myData'}`.

**6. Common Usage Errors:**

This focuses on mistakes developers might make that relate to `HistoryItem` indirectly.

* **Incorrectly using `history.pushState`/`replaceState`:** Forgetting to serialize complex objects or assuming data will persist without proper handling.
* **Relying on browser history for critical state:**  Assuming that simply using the back button will perfectly restore all application state, especially if external resources or server-side data are involved.
* **Not handling the `popstate` event correctly:**  Failing to update the UI or application state when the user navigates back or forward.

**7. Debugging Clues:**

This focuses on how a developer might end up looking at `history_item.cc` during debugging.

* **Scenario:** A user reports that the back button doesn't restore the page to the correct state (e.g., form data is lost, scroll position is wrong, JavaScript state is not as expected).
* **Debugging Steps:**
    1. **Initial Investigation:** Check browser console for errors, inspect network requests.
    2. **Deeper Dive:** If the issue seems related to state management during navigation, a developer might look into how Blink handles history. This could lead them to `history_item.cc` to understand how page state is saved and restored.
    3. **Breakpoints:** Setting breakpoints in `HistoryItem::Create` or `HistoryItem::ToPageState` can help inspect the data being serialized and deserialized.
    4. **Examining PageState:** Understanding how `PageState` is structured and how it maps to the members of `HistoryItem` is crucial.
    5. **Tracing:** Following the flow of execution when a back/forward navigation occurs can reveal if the correct `HistoryItem` is being loaded and processed.

**8. Structuring the Answer:**

Finally, organize the information logically with clear headings and examples, ensuring that each part of the request is addressed. The goal is to provide a comprehensive yet understandable explanation for someone unfamiliar with this specific piece of Chromium's codebase.
好的，我们来详细分析一下 `blink/renderer/core/loader/history_item.cc` 这个文件及其功能。

**文件功能总览:**

`history_item.cc` 文件定义了 `HistoryItem` 类，这个类在 Chromium Blink 渲染引擎中扮演着至关重要的角色，它主要负责**存储和管理浏览器导航历史中的单个条目 (entry) 的状态信息**。你可以把它想象成浏览器“前进”和“后退”功能背后的数据载体。

**核心功能分解:**

1. **存储页面状态 (Saving Page State):**
   - `HistoryItem` 对象保存了恢复到特定历史点所需的各种信息。这包括：
     - **URL (`url_string_`)**: 访问页面的完整 URL。
     - **Referrer (`referrer_`, `referrer_policy_`)**:  用户从哪个页面链接过来，以及 Referrer Policy 设置。
     - **滚动位置 (`view_state_->scroll_offset_`, `view_state_->visual_viewport_scroll_offset_`)**: 页面滚动到的位置。
     - **页面缩放 (`view_state_->page_scale_factor_`)**: 页面的缩放级别。
     - **表单数据 (`form_data_`, `form_content_type_`)**: 如果是通过 POST 请求提交的表单，则保存表单数据和内容类型。
     - **JavaScript 状态 (`state_object_`, `navigation_api_state_`)**:  通过 `history.pushState()` 或 `history.replaceState()` 保存的 JavaScript 对象。
     - **文档状态 (`document_state_vector_`, `document_state_`)**:  与页面内容相关的其他状态信息，例如表单元素的值。
     - **滚动锚点 (`view_state_->scroll_anchor_data_`)**:  用于在恢复页面时尽可能将用户带回到之前浏览的特定元素附近。
     - **导航 API 相关信息 (`navigation_api_key_`, `navigation_api_id_`)**:  用于支持 Navigation API 的状态管理。
     - **序列号 (`item_sequence_number_`, `document_sequence_number_`)**:  用于唯一标识历史条目。

2. **创建和恢复历史条目 (Creating and Restoring History Items):**
   - `HistoryItem::Create(const PageState& page_state)`:  静态方法，接收一个 `PageState` 对象并创建一个 `HistoryItem`。`PageState` 是一个更通用的数据结构，用于序列化和反序列化页面状态。这个方法负责从序列化的 `PageState` 中提取信息并填充 `HistoryItem` 的各个字段。
   - `ToPageState() const`:  方法将 `HistoryItem` 的当前状态序列化为一个 `PageState` 对象。这用于在需要存储历史记录时（例如，会话恢复）将 `HistoryItem` 的信息持久化。

3. **生成资源请求 (Generating Resource Requests):**
   - `GenerateResourceRequest(mojom::FetchCacheMode cache_mode)`:  方法根据 `HistoryItem` 中存储的信息（URL、Referrer、表单数据等）创建一个 `ResourceRequest` 对象。这在用户点击“前进”或“后退”按钮时，浏览器需要重新加载页面或提交表单时使用。

4. **管理文档状态 (Managing Document State):**
   - `SetDocumentState()`, `GetDocumentState()`, `ClearDocumentState()`:  用于设置、获取和清除与文档相关的状态信息。
   - `GetReferencedFilePaths()`:  获取文档状态中引用的文件路径，这可能用于权限管理或其他目的。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    - **`history.pushState()` 和 `history.replaceState()`**:  这两个 JavaScript API 允许开发者在不重新加载页面的情况下修改浏览器的历史记录。`HistoryItem` 的 `state_object_` 字段就是用来存储通过这两个 API 传递的 JavaScript 对象。
        - **假设输入 (JavaScript):**
          ```javascript
          window.history.pushState({ page: 1 }, "title 1", "?page=1");
          ```
        - **输出 (在 `HistoryItem` 中):**  当这个 `pushState` 被执行后，会创建一个新的 `HistoryItem`，其 `state_object_` 会包含 `{ "page": 1 }` 这个序列化后的 JavaScript 对象。
    - **`popstate` 事件**: 当用户点击“前进”或“后退”按钮时，会触发 `popstate` 事件。事件对象包含与该历史条目关联的 `state`。`HistoryItem` 负责存储这些状态，使得在 `popstate` 事件中可以访问到。
    - **Scroll Restoration API**:  JavaScript 可以通过设置 `history.scrollRestoration` 来控制滚动行为。`HistoryItem` 存储了 `scroll_restoration_type`，用于记录这个设置。

* **HTML:**
    - **URL**:  `HistoryItem` 存储了页面的 URL，这是 HTML 文档的地址。
    - **表单 (`<form>`)**:  如果用户提交了一个 HTML 表单，并且使用了 POST 方法，`HistoryItem` 会存储表单的数据 (`form_data_`)，以便在用户点击“后退”按钮时可以恢复表单的状态（尽管出于安全原因，通常需要用户确认是否重新提交）。
        - **假设输入 (HTML 表单):**
          ```html
          <form method="POST">
              <input type="text" name="username" value="testuser">
              <input type="submit">
          </form>
          ```
        - **输出 (在 `HistoryItem` 中):**  当表单提交后，对应的 `HistoryItem` 会包含 `username=testuser` 这样的编码后的表单数据。
    - **锚点 (`#`)**: URL 中的锚点信息也包含在 `HistoryItem` 的 URL 中，因此“前进”和“后退”可以恢复到页面内的特定位置。

* **CSS:**
    - **滚动位置**: 虽然 `HistoryItem` 不直接存储 CSS，但页面的滚动位置受到 CSS 布局的影响。`HistoryItem` 存储的滚动位置信息确保了页面在“前进”和“后退”时能够恢复到用户之前的浏览位置，这与 CSS 的渲染结果密切相关。
    - **页面缩放**:  用户通过浏览器缩放页面，`HistoryItem` 会存储 `page_scale_factor_`，使得在导航历史中切换时可以恢复页面的缩放级别。

**逻辑推理的假设输入与输出:**

* **假设输入:** 用户在浏览一个包含大量图片的页面后，滚动到页面的底部。
* **逻辑推理:** 当用户导航到另一个页面时，会创建一个新的 `HistoryItem` 来记录当前页面的状态。这个 `HistoryItem` 会存储当前页面的 URL 和当前的滚动偏移量（接近页面底部）。
* **输出:** 当用户点击“后退”按钮回到这个页面时，浏览器会加载之前存储的 `HistoryItem`，并使用其中的滚动偏移量来恢复到页面底部附近的位置。

**用户或编程常见的使用错误:**

1. **错误地理解 `history.state` 的生命周期:**  开发者可能会错误地认为 `history.state` 在页面刷新后仍然存在。实际上，每次页面完全加载或刷新，`history.state` 都会被清除，除非通过 `pushState` 或 `replaceState` 重新设置。
    - **举例:**  一个单页应用（SPA）在初始加载时设置了一个 `history.state`，然后用户刷新了页面。开发者可能期望在页面加载后仍然能访问到这个初始状态，但这通常是不成立的。
2. **在 `popstate` 事件处理中未考虑初始状态:** 当页面首次加载时，不会触发 `popstate` 事件。开发者需要确保他们的 `popstate` 事件处理程序也能处理页面初始加载的情况，或者使用其他方法初始化状态。
3. **序列化复杂对象到 `history.state` 时出错:** `history.state` 只能存储可以被安全序列化的 JavaScript 对象。如果尝试存储包含循环引用或不可序列化类型的对象，可能会导致错误或数据丢失。
4. **忘记更新 `history.state`:**  在单页应用中进行状态变更时，开发者可能忘记使用 `pushState` 或 `replaceState` 更新 `history.state`，导致用户点击“前进”或“后退”时状态不一致。

**用户操作如何一步步到达这里，作为调试线索:**

假设开发者正在调试一个关于浏览器“后退”按钮行为异常的问题，例如页面后退后滚动位置不正确。以下是可能导致他们查看 `history_item.cc` 的步骤：

1. **用户报告问题:** 用户反馈在特定网站上点击“后退”按钮后，页面没有恢复到之前的滚动位置。
2. **开发者重现问题:** 开发者尝试重现用户的操作路径，确认问题存在。
3. **初步调试 (浏览器开发者工具):** 开发者可能首先使用浏览器的开发者工具来检查：
   - **Network 面板:** 查看是否有不必要的请求发生，或者请求的参数是否正确。
   - **Console 面板:** 查看是否有 JavaScript 错误。
   - **Elements 面板:** 查看 DOM 结构是否如预期。
4. **深入分析 (Blink 渲染引擎代码):** 如果初步调试没有找到明显原因，开发者可能会怀疑是 Blink 渲染引擎在处理历史记录时出现了问题。
5. **定位相关代码:** 开发者可能会根据问题的特性（例如，滚动位置），猜测相关的代码模块。`blink/renderer/core/loader/` 目录下与加载和导航相关的代码是重点关注对象。
6. **查看 `history_item.cc`:**  由于 `HistoryItem` 负责存储和管理历史记录的状态，开发者可能会查看这个文件，以了解：
   - **滚动位置是如何存储的:**  查看 `view_state_->scroll_offset_` 和相关代码。
   - **页面状态的序列化和反序列化过程:**  查看 `ToPageState()` 和 `Create()` 方法，了解滚动位置信息是如何被保存和恢复的。
   - **是否有任何逻辑错误或边界条件处理不当:** 例如，在处理不同类型的页面或滚动场景时是否存在问题。
7. **设置断点和日志:** 开发者可能会在 `history_item.cc` 中设置断点，例如在 `HistoryItem::Create()` 和 `ToPageState()` 中，以及在设置和获取滚动位置的方法中，来跟踪滚动位置信息的流动。他们也可能会添加日志输出，以便在运行时观察相关变量的值。
8. **分析代码逻辑:** 仔细阅读代码，理解其背后的逻辑，特别是与滚动位置恢复相关的部分，查找潜在的 bug。

总而言之，`history_item.cc` 是 Blink 渲染引擎中一个核心的文件，它负责管理浏览器导航历史中的页面状态。理解其功能对于调试与“前进”、“后退”、`history.pushState` 等功能相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/loader/history_item.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2005, 2006, 2008, 2011 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/loader/history_item.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/public/common/page_state/page_state.h"
#include "third_party/blink/public/common/page_state/page_state_serialization.h"
#include "third_party/blink/public/platform/web_http_body.h"
#include "third_party/blink/public/platform/web_url_request_util.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/uuid.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/point_conversions.h"

namespace blink {

namespace {

std::vector<std::optional<std::u16string>> ToOptionalString16Vector(
    base::span<const String> input) {
  std::vector<std::optional<std::u16string>> output;
  output.reserve(input.size());
  for (const auto& i : input) {
    output.emplace_back(WebString::ToOptionalString16(i));
  }
  return output;
}

}  // namespace

static int64_t GenerateSequenceNumber() {
  // Initialize to the current time to reduce the likelihood of generating
  // identifiers that overlap with those from past/future browser sessions.
  static int64_t next =
      (base::Time::Now() - base::Time::UnixEpoch()).InMicroseconds();
  return ++next;
}

HistoryItem* HistoryItem::Create(const PageState& page_state) {
  ExplodedPageState exploded_page_state;
  if (!DecodePageState(page_state.ToEncodedData(), &exploded_page_state)) {
    return nullptr;
  }

  auto* new_item = MakeGarbageCollected<HistoryItem>();
  const ExplodedFrameState& state = exploded_page_state.top;
  new_item->SetURLString(WebString::FromUTF16(state.url_string));
  new_item->SetReferrer(WebString::FromUTF16(state.referrer));
  new_item->SetReferrerPolicy(state.referrer_policy);
  new_item->SetTarget(WebString::FromUTF16(state.target));
  if (state.state_object) {
    new_item->SetStateObject(SerializedScriptValue::Create(
        WebString::FromUTF16(*state.state_object)));
  }

  Vector<String> document_state;
  for (auto& ds : state.document_state) {
    document_state.push_back(WebString::FromUTF16(ds));
  }
  new_item->SetDocumentState(document_state);

  new_item->SetScrollRestorationType(state.scroll_restoration_type);

  if (state.did_save_scroll_or_scale_state) {
    // TODO(crbug.com/1274078): Are these conversions from blink scroll offset
    // to gfx::PointF and gfx::Point correct?
    new_item->SetVisualViewportScrollOffset(
        state.visual_viewport_scroll_offset.OffsetFromOrigin());
    new_item->SetScrollOffset(
        ScrollOffset(state.scroll_offset.OffsetFromOrigin()));
    new_item->SetPageScaleFactor(state.page_scale_factor);
  }

  // These values are generated at HistoryItem construction time, and we only
  // want to override those new values with old values if the old values are
  // defined. A value of 0 means undefined in this context.
  if (state.item_sequence_number) {
    new_item->SetItemSequenceNumber(state.item_sequence_number);
  }
  if (state.document_sequence_number) {
    new_item->SetDocumentSequenceNumber(state.document_sequence_number);
  }
  if (state.navigation_api_key) {
    new_item->SetNavigationApiKey(
        WebString::FromUTF16(state.navigation_api_key));
  }
  if (state.navigation_api_id) {
    new_item->SetNavigationApiId(WebString::FromUTF16(state.navigation_api_id));
  }

  if (state.navigation_api_state) {
    new_item->SetNavigationApiState(SerializedScriptValue::Create(
        WebString::FromUTF16(*state.navigation_api_state)));
  }

  new_item->SetFormContentType(
      WebString::FromUTF16(state.http_body.http_content_type));
  if (state.http_body.request_body) {
    new_item->SetFormData(
        blink::GetWebHTTPBodyForRequestBody(*state.http_body.request_body));
  }

  new_item->SetScrollAnchorData(
      {WebString::FromUTF16(state.scroll_anchor_selector),
       state.scroll_anchor_offset, state.scroll_anchor_simhash});
  return new_item;
}

HistoryItem::HistoryItem()
    : item_sequence_number_(GenerateSequenceNumber()),
      document_sequence_number_(GenerateSequenceNumber()),
      navigation_api_key_(WTF::CreateCanonicalUUIDString()),
      navigation_api_id_(WTF::CreateCanonicalUUIDString()) {}

HistoryItem::~HistoryItem() = default;

const String& HistoryItem::UrlString() const {
  return url_string_;
}

KURL HistoryItem::Url() const {
  return KURL(url_string_);
}

const String& HistoryItem::GetReferrer() const {
  return referrer_;
}

network::mojom::ReferrerPolicy HistoryItem::GetReferrerPolicy() const {
  return referrer_policy_;
}

void HistoryItem::SetURLString(const String& url_string) {
  if (url_string_ != url_string)
    url_string_ = url_string;
}

void HistoryItem::SetURL(const KURL& url) {
  SetURLString(url.GetString());
}

void HistoryItem::SetReferrer(const String& referrer) {
  referrer_ = referrer;
}

void HistoryItem::SetReferrerPolicy(network::mojom::ReferrerPolicy policy) {
  referrer_policy_ = policy;
}

HistoryItem::ViewState& HistoryItem::GetOrCreateViewState() {
  if (!view_state_) {
    view_state_ = ViewState();
  }
  return *view_state_;
}

void HistoryItem::SetVisualViewportScrollOffset(const ScrollOffset& offset) {
  GetOrCreateViewState().visual_viewport_scroll_offset_ = offset;
}

void HistoryItem::SetScrollOffset(const ScrollOffset& offset) {
  GetOrCreateViewState().scroll_offset_ = offset;
}

void HistoryItem::SetPageScaleFactor(float scale_factor) {
  GetOrCreateViewState().page_scale_factor_ = scale_factor;
}

void HistoryItem::SetScrollAnchorData(
    const ScrollAnchorData& scroll_anchor_data) {
  GetOrCreateViewState().scroll_anchor_data_ = scroll_anchor_data;
}

void HistoryItem::SetDocumentState(const Vector<String>& state) {
  DCHECK(!document_state_);
  document_state_vector_ = state;
}

void HistoryItem::SetDocumentState(DocumentState* state) {
  document_state_ = state;
}

const Vector<String>& HistoryItem::GetDocumentState() const {
  // TODO(dcheng): This is super weird. It seems like it would be better to just
  // populate the vector eagerly once when calling `SetDocumentState()` with a
  // `DocumentState` object.
  if (document_state_)
    document_state_vector_ = document_state_->ToStateVector();
  return document_state_vector_;
}

Vector<String> HistoryItem::GetReferencedFilePaths() const {
  return FormController::GetReferencedFilePaths(GetDocumentState());
}

void HistoryItem::ClearDocumentState() {
  document_state_.Clear();
  document_state_vector_.clear();
}

void HistoryItem::SetStateObject(scoped_refptr<SerializedScriptValue> object) {
  state_object_ = std::move(object);
}

const AtomicString& HistoryItem::FormContentType() const {
  return form_content_type_;
}

void HistoryItem::SetFormData(scoped_refptr<EncodedFormData> form_data) {
  form_data_ = std::move(form_data);
}

void HistoryItem::SetFormContentType(const AtomicString& form_content_type) {
  form_content_type_ = form_content_type;
}

EncodedFormData* HistoryItem::FormData() const {
  return form_data_.get();
}

void HistoryItem::SetNavigationApiState(
    scoped_refptr<SerializedScriptValue> value) {
  navigation_api_state_ = std::move(value);
}

ResourceRequest HistoryItem::GenerateResourceRequest(
    mojom::FetchCacheMode cache_mode) {
  ResourceRequest request(url_string_);
  request.SetReferrerString(referrer_);
  request.SetReferrerPolicy(referrer_policy_);
  request.SetCacheMode(cache_mode);
  if (form_data_) {
    request.SetHttpMethod(http_names::kPOST);
    request.SetHttpBody(form_data_);
    request.SetHTTPContentType(form_content_type_);
    request.SetHTTPOriginToMatchReferrerIfNeeded();
  }
  return request;
}

void HistoryItem::Trace(Visitor* visitor) const {
  visitor->Trace(document_state_);
}

PageState HistoryItem::ToPageState() const {
  ExplodedPageState state;
  state.referenced_files = GetReferencedFilePathsForSerialization();

  state.top.url_string = WebString::ToOptionalString16(UrlString());
  state.top.referrer = WebString::ToOptionalString16(GetReferrer());
  state.top.referrer_policy = GetReferrerPolicy();
  state.top.target = WebString::ToOptionalString16(Target());
  if (StateObject()) {
    state.top.state_object =
        WebString::ToOptionalString16(StateObject()->ToWireString());
  }
  state.top.scroll_restoration_type = ScrollRestorationType();

  ScrollAnchorData anchor;
  if (const auto& scroll_and_view_state = GetViewState()) {
    // TODO(crbug.com/1274078): Are these conversions from blink scroll offset
    // to gfx::PointF and gfx::Point correct?
    state.top.visual_viewport_scroll_offset = gfx::PointAtOffsetFromOrigin(
        scroll_and_view_state->visual_viewport_scroll_offset_);
    state.top.scroll_offset = gfx::ToFlooredPoint(
        gfx::PointAtOffsetFromOrigin(scroll_and_view_state->scroll_offset_));
    state.top.page_scale_factor = scroll_and_view_state->page_scale_factor_;
    state.top.did_save_scroll_or_scale_state = true;
    anchor = scroll_and_view_state->scroll_anchor_data_;
  } else {
    state.top.visual_viewport_scroll_offset = gfx::PointF();
    state.top.scroll_offset = gfx::Point();
    state.top.page_scale_factor = 0;
    state.top.did_save_scroll_or_scale_state = false;
  }

  state.top.scroll_anchor_selector =
      WebString::ToOptionalString16(anchor.selector_);
  state.top.scroll_anchor_offset = anchor.offset_;
  state.top.scroll_anchor_simhash = anchor.simhash_;

  state.top.item_sequence_number = ItemSequenceNumber();
  state.top.document_sequence_number = DocumentSequenceNumber();

  state.top.document_state = ToOptionalString16Vector(GetDocumentState());

  state.top.http_body.http_content_type =
      WebString::ToOptionalString16(FormContentType());
  WebHTTPBody http_body(FormData());
  if (!http_body.IsNull()) {
    state.top.http_body.request_body =
        blink::GetRequestBodyForWebHTTPBody(http_body);
    state.top.http_body.contains_passwords = http_body.ContainsPasswordData();
  }

  state.top.navigation_api_key =
      WebString::ToOptionalString16(GetNavigationApiKey());
  state.top.navigation_api_id =
      WebString::ToOptionalString16(GetNavigationApiId());
  if (GetNavigationApiState()) {
    state.top.navigation_api_state =
        WebString::ToOptionalString16(GetNavigationApiState()->ToWireString());
  }

  std::string encoded_data;
  EncodePageState(state, &encoded_data);
  return PageState::CreateFromEncodedData(encoded_data);
}

std::vector<std::optional<std::u16string>>
HistoryItem::GetReferencedFilePathsForSerialization() const {
  HashSet<String> file_paths;

  // These additional paths are presumably used by PageState so the browser can
  // grant the renderer access to referenced files during session restore. This
  // logic dates to https://crrev.com/db4a9b4108635b3678c3f9fd5bdd1f98001db216,
  // and it is not entirely clear if it is still needed.
  const EncodedFormData* form_data = FormData();
  if (form_data) {
    for (const FormDataElement& element : form_data->Elements()) {
      if (element.type_ == FormDataElement::kEncodedFile) {
        file_paths.insert(element.filename_);
      }
    }
  }

  for (const String& path : GetReferencedFilePaths()) {
    file_paths.insert(path);
  }

  std::vector<std::optional<std::u16string>> result;
  result.reserve(file_paths.size());
  base::ranges::transform(file_paths, std::back_inserter(result),
                          WebString::ToOptionalString16);
  return result;
}

}  // namespace blink
```