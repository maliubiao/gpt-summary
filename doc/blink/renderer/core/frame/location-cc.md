Response:
Let's break down the thought process for analyzing this `location.cc` file.

1. **Understand the Goal:** The primary goal is to understand the *functionality* of this C++ file within the Chromium/Blink context, specifically focusing on its relationship with web technologies (JavaScript, HTML, CSS) and potential user/programming errors.

2. **Identify the Core Concept:** The filename `location.cc` and the `Location` class within it immediately suggest a connection to the `window.location` object in JavaScript. This is the central point around which the analysis will revolve.

3. **Analyze the Includes:**  The included header files provide valuable clues about the file's dependencies and responsibilities:
    * `location.h`:  The corresponding header file, likely containing the `Location` class declaration.
    * `bindings/core/v8/...`:  Indicates this code interacts with the V8 JavaScript engine, bridging C++ and JavaScript. This is crucial for understanding the connection to `window.location`.
    * `core/dom/document.h`:  Shows interaction with the DOM, as `window.location` reflects the URL of the current document.
    * `core/frame/...`: Points to the file's role within the browser's frame structure, responsible for managing web pages and their navigation. `LocalFrame`, `RemoteDOMWindow`, `LocalDOMWindow` are key entities here.
    * `core/loader/...`:  Suggests involvement in the page loading process initiated by changes to `location`.
    * `core/url/...`:  Confirms that this file deals with URL manipulation.
    * `platform/bindings/...`:  Further emphasizes the C++/JavaScript binding aspect.
    * `platform/weborigin/...`: Highlights the importance of security and origin concepts in the context of `location`.

4. **Examine the `Location` Class:**  The constructor `Location(DOMWindow* dom_window)` establishes that a `Location` object is associated with a `DOMWindow`. This reinforces the JavaScript `window.location` connection.

5. **Analyze Key Methods (and Group by Functionality):**

    * **Getting URL Components:** Methods like `href()`, `protocol()`, `host()`, `hostname()`, `port()`, `pathname()`, `search()`, `hash()`, and `origin()` clearly correspond to the properties of the JavaScript `location` object. They extract and return different parts of the URL. This is a primary function.

    * **Setting URL Components:** The `setHref()`, `setProtocol()`, `setHost()`, etc., methods mirror the ability to *modify* the URL through JavaScript assignments (e.g., `window.location.href = "..."`). This leads to navigation or changes within the current page. The `SetLocation()` method is the core logic for these setters.

    * **Navigation Methods:**  `assign()` and `replace()` directly correspond to JavaScript's `location.assign()` and `location.replace()`. `reload()` handles the page refresh.

    * **Other Methods:**
        * `Wrap()`:  This is a V8 binding function, responsible for creating the JavaScript wrapper object for the C++ `Location` instance. The distinction between `LocalDOMWindow` and `RemoteDOMWindow` is important here for security and isolation.
        * `Trace()`: Part of Blink's garbage collection mechanism.
        * `ancestorOrigins()`: Provides information about the origin chain, which is relevant to security.
        * `toString()`:  A standard method that returns the `href`.
        * `GetDocument()` and `IsAttached()`: Utility methods to access the associated document and check if the frame is still valid.

6. **Connect to Web Technologies:**  Based on the method analysis, draw explicit connections:

    * **JavaScript:** The getters and setters directly map to the properties and methods of the `window.location` object. Provide concrete examples.
    * **HTML:** Changes to `location.hash` can trigger navigation to specific elements with matching IDs. The `href` attribute of `<a>` tags can lead to navigation which the `Location` object handles.
    * **CSS:**  While less direct, changing the `location` can cause the browser to load a completely new page, which will involve loading and applying new CSS. Mention the concept of different stylesheets based on URL.

7. **Identify Logical Reasoning and Assumptions:** Focus on the `SetLocation()` method. It involves:

    * **Input:** A URL string, potentially from JavaScript.
    * **Assumptions:**  The current window has the necessary permissions. The URL is valid.
    * **Output:**  A navigation event (or an exception).

8. **Pinpoint User/Programming Errors:** Think about how developers might misuse the `location` object:

    * **Invalid URLs:**  Setting an invalid URL can cause errors.
    * **Security Errors:** Trying to navigate to a cross-origin frame without permission.
    * **Typos:**  Simple mistakes in URL strings.
    * **Incorrect Protocol:**  Trying to set a non-standard or disallowed protocol.

9. **Structure the Output:** Organize the findings logically:

    * **Overview:** Start with a high-level summary of the file's purpose.
    * **Key Functions:** List the main responsibilities.
    * **Relationship to Web Technologies:** Explain the connections with JavaScript, HTML, and CSS with examples.
    * **Logical Reasoning:** Detail the input, assumptions, and output of key methods like `SetLocation()`.
    * **Common Errors:**  Provide specific examples of user or programming mistakes.

10. **Refine and Review:** Read through the analysis to ensure clarity, accuracy, and completeness. Are the examples easy to understand? Have all the important aspects been covered?  Is the language precise? For example, initially, I might just say "handles navigation," but refining it to "initiates navigation requests based on URL changes" is more accurate.

By following this structured approach, combining code analysis with an understanding of web technologies, it's possible to thoroughly analyze the functionality of a complex file like `location.cc`.
这个文件 `blink/renderer/core/frame/location.cc` 是 Chromium Blink 引擎中负责实现 `window.location` JavaScript 接口的核心部分。它处理与当前窗口或 iframe 的 URL 相关的各种操作。

以下是 `location.cc` 的主要功能：

**1. 提供 JavaScript `window.location` 对象的 C++ 实现:**

   - `Location` 类是 JavaScript 中 `window.location` 对象的底层 C++ 表示。它封装了与 URL 相关的属性和方法。
   - 当 JavaScript 代码访问 `window.location` 的属性（例如 `href`, `protocol`, `host` 等）或调用其方法（例如 `assign`, `replace`, `reload`）时，最终会调用到 `Location` 类中的相应 C++ 方法。

**2. 获取和设置 URL 的各个组成部分:**

   - 提供了获取当前文档 URL 的各个部分的接口，对应于 `window.location` 的属性：
     - `href()`: 返回完整的 URL 字符串。
     - `protocol()`: 返回协议部分（例如 "http:", "https:"）。
     - `host()`: 返回主机名和端口号。
     - `hostname()`: 返回主机名。
     - `port()`: 返回端口号。
     - `pathname()`: 返回路径部分。
     - `search()`: 返回查询字符串部分（以 "?" 开头）。
     - `hash()`: 返回哈希值部分（以 "#" 开头）。
     - `origin()`: 返回源（协议、域名和端口）。
     - `ancestorOrigins()`: 返回一个 `DOMStringList`，包含所有祖先窗口的源。

   - 提供了设置 URL 各个部分的接口，对应于在 JavaScript 中直接赋值给 `window.location` 的属性：
     - `setHref()`: 设置完整的 URL，导致页面跳转。
     - `setProtocol()`: 设置协议部分，可能导致页面跳转。
     - `setHost()`: 设置主机名和端口号，可能导致页面跳转。
     - `setHostname()`: 设置主机名，可能导致页面跳转。
     - `setPort()`: 设置端口号，可能导致页面跳转。
     - `setPathname()`: 设置路径部分，可能导致页面跳转。
     - `setSearch()`: 设置查询字符串部分，可能导致页面跳转。
     - `setHash()`: 设置哈希值部分，通常不会导致完整页面加载，而是触发页面内的锚点跳转。

**3. 提供页面导航功能:**

   - `assign(url_string)`: 类似于直接给 `window.location.href` 赋值，加载一个新的 URL，并在浏览历史中创建新记录。
   - `replace(url_string)`: 加载一个新的 URL，但会替换当前的浏览历史记录。
   - `reload()`: 重新加载当前页面。

**4. 处理跨域安全策略:**

   - 在 `Wrap()` 方法中，对于跨域的 `RemoteDOMWindow`，会创建特殊的远程对象包装器，以限制 JavaScript 对跨域 `location` 对象的访问。
   - 在设置 URL 相关属性和调用导航方法时，会检查当前窗口是否有权限导航到目标 URL（通过 `CanNavigate()` 方法），以防止跨域脚本执行恶意操作。

**5. 与 V8 JavaScript 引擎的绑定:**

   - 使用 Blink 的绑定机制，将 C++ 的 `Location` 类及其方法暴露给 JavaScript。
   - `Wrap(ScriptState*)` 方法负责创建与 C++ `Location` 对象关联的 JavaScript 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  `location.cc` 最直接地实现了 JavaScript 的 `window.location` API。
    * **例子:**
        ```javascript
        // 获取当前页面的 URL
        let currentURL = window.location.href;
        console.log(currentURL);

        // 跳转到新的页面
        window.location.href = 'https://www.example.com';

        // 修改 URL 的 hash 值
        window.location.hash = 'section1';

        // 重新加载页面
        window.location.reload();
        ```
        当执行这些 JavaScript 代码时，Blink 引擎会调用 `location.cc` 中相应的 C++ 方法，例如 `href()`, `setHref()`, `setHash()`, `reload()`。

* **HTML:**  HTML 中的链接 ( `<a href="...">` ) 和表单提交等操作会影响 `window.location` 的值，并最终由 `location.cc` 处理。
    * **例子:**
        ```html
        <!-- 点击链接会修改 window.location.href -->
        <a href="newpage.html">Go to New Page</a>

        <!-- 表单提交会修改 window.location.href 或 window.location.search -->
        <form action="/submit" method="get">
          <input type="text" name="query" value="search term">
          <button type="submit">Search</button>
        </form>
        ```
        当用户点击链接或提交表单时，浏览器会解析 HTML 并生成相应的导航请求，这个请求会被传递到 Blink 引擎，最终影响到 `Location` 对象的状态。

* **CSS:**  CSS 本身不直接与 `window.location` 交互，但页面的 URL 可以影响 CSS 的加载和应用。例如，可以使用媒体查询根据 URL 的不同部分应用不同的样式，或者不同的页面可能会加载不同的 CSS 文件。
    * **例子 (间接关系):**
        假设你有一个根据 URL 路径应用不同背景色的 CSS：
        ```css
        /* style.css */
        body {
          background-color: white;
        }

        body.homepage {
          background-color: lightblue;
        }

        body.product-page {
          background-color: lightgreen;
        }
        ```
        你的 HTML 可能会根据 `window.location.pathname` 来添加不同的 CSS 类：
        ```javascript
        // 在 JavaScript 中根据 URL 路径添加 CSS 类
        if (window.location.pathname === '/') {
          document.body.classList.add('homepage');
        } else if (window.location.pathname.startsWith('/product/')) {
          document.body.classList.add('product-page');
        }
        ```
        虽然 CSS 本身不操作 `location`，但页面的 URL 会影响应用哪些 CSS 规则。

**逻辑推理的假设输入与输出:**

**假设输入:**  JavaScript 代码执行 `window.location.href = 'https://example.com/path?query=value#hash';`

**逻辑推理和输出:**

1. **输入解析:** `setHref()` 方法接收 URL 字符串 `'https://example.com/path?query=value#hash'`。
2. **URL 解析:** Blink 会将该字符串解析成 `KURL` 对象，提取协议、主机、路径、查询、哈希等部分。
3. **安全检查:**  会检查当前 frame 是否允许导航到 `https://example.com` 这个源。如果跨域，会检查是否有相应的权限。
4. **导航请求:** 创建一个 `FrameLoadRequest` 对象，包含目标 URL。
5. **页面加载:**  FrameLoader 启动新的页面加载过程。
6. **历史记录更新:** 如果是 `assign()` 或直接修改 `href`，浏览历史会添加新记录。如果是 `replace()`，则替换当前记录。
7. **输出:** 浏览器导航到 `https://example.com/path?query=value#hash`，页面内容被替换。

**用户或编程常见的使用错误举例说明:**

1. **尝试导航到无效的 URL:**
   ```javascript
   window.location.href = 'invalid-url'; // 可能导致错误或无法导航
   ```
   `setHref()` 方法在内部会调用 `CompleteURL()` 来解析 URL。如果解析失败，会抛出 `DOMExceptionCode::kSyntaxError`。

2. **在不允许导航的上下文中修改 `location`:**
   如果一个 iframe 的 `sandbox` 属性阻止了导航，尝试修改 `window.location` 会失败。
   ```html
   <iframe sandbox="allow-scripts"></iframe>
   <script>
     // 在沙箱 iframe 中尝试导航
     window.frames[0].location.href = 'https://www.example.com'; // 可能抛出 SecurityError
   </script>
   ```
   `SetLocation()` 方法会调用 `CanNavigate()` 进行权限检查，如果检查失败会抛出 `SecurityError`。

3. **误用 `replace()` 导致无法返回上一页:**
   ```javascript
   window.location.replace('newpage.html');
   ```
   如果用户期望在 `newpage.html` 查看后能按“后退”按钮回到之前的页面，使用 `replace()` 会阻止这种行为，因为 `replace()` 替换了历史记录。

4. **拼写错误或逻辑错误导致 URL 构建不正确:**
   ```javascript
   let id = 123;
   window.location.href = '/item' + id; // 缺少了分隔符，期望是 /item/123
   ```
   这种编程错误会导致导航到错误的 URL。

5. **不理解 `hash` 的行为:**
   ```javascript
   window.location.hash = '#new-section';
   ```
   如果 `#new-section` 在当前页面不存在对应的元素，页面不会滚动到任何地方，但 URL 的 `hash` 部分会被更新。开发者可能期望页面会滚动。

总而言之，`blink/renderer/core/frame/location.cc` 是 Blink 引擎中至关重要的一个文件，它负责实现 Web 开发者常用的 `window.location` API，处理 URL 的解析、修改和页面导航，并遵循 Web 安全策略。理解它的功能有助于我们更好地理解浏览器如何处理页面跳转和 URL 操作。

### 提示词
```
这是目录为blink/renderer/core/frame/location.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2008, 2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/frame/location.h"

#include "third_party/blink/renderer/bindings/core/v8/binding_security.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/dom_window.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/remote_dom_window.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/url/dom_url_utils_read_only.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_activity_logger.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

Location::Location(DOMWindow* dom_window) : dom_window_(dom_window) {}

v8::Local<v8::Value> Location::Wrap(ScriptState* script_state) {
  // Note that this check is gated on whether or not |dom_window_| is remote,
  // not whether or not |dom_window_| is cross-origin. If |dom_window_| is
  // local, the |location| property must always return the same wrapper, even if
  // the cross-origin status changes by changing properties like
  // |document.domain|.
  if (IsA<RemoteDOMWindow>(dom_window_.Get())) {
    DCHECK(!DOMDataStore::ContainsWrapper(script_state->GetIsolate(), this));

    DOMWrapperWorld& world = script_state->World();
    v8::Isolate* isolate = script_state->GetIsolate();
    const auto* location_wrapper_type = GetWrapperTypeInfo();
    v8::Local<v8::Object> new_wrapper =
        location_wrapper_type->GetV8ClassTemplate(isolate, world)
            .As<v8::FunctionTemplate>()
            ->NewRemoteInstance()
            .ToLocalChecked();
    return V8DOMWrapper::AssociateObjectWithWrapper(
        isolate, this, location_wrapper_type, new_wrapper);
  }

  return ScriptWrappable::Wrap(script_state);
}

void Location::Trace(Visitor* visitor) const {
  visitor->Trace(dom_window_);
  ScriptWrappable::Trace(visitor);
}

inline const KURL& Location::Url() const {
  const KURL& url = GetDocument()->Url();
  if (!url.IsValid()) {
    // Use "about:blank" while the page is still loading (before we have a
    // frame).
    return BlankURL();
  }

  return url;
}

String Location::href() const {
  return Url().StrippedForUseAsHref();
}

String Location::protocol() const {
  return DOMURLUtilsReadOnly::protocol(Url());
}

String Location::host() const {
  return DOMURLUtilsReadOnly::host(Url());
}

String Location::hostname() const {
  return DOMURLUtilsReadOnly::hostname(Url());
}

String Location::port() const {
  return DOMURLUtilsReadOnly::port(Url());
}

String Location::pathname() const {
  return DOMURLUtilsReadOnly::pathname(Url());
}

String Location::search() const {
  return DOMURLUtilsReadOnly::search(Url());
}

String Location::origin() const {
  return DOMURLUtilsReadOnly::origin(Url());
}

DOMStringList* Location::ancestorOrigins() const {
  auto* origins = MakeGarbageCollected<DOMStringList>();
  if (!IsAttached())
    return origins;
  for (Frame* frame = dom_window_->GetFrame()->Tree().Parent(); frame;
       frame = frame->Tree().Parent()) {
    origins->Append(
        frame->GetSecurityContext()->GetSecurityOrigin()->ToString());
  }
  return origins;
}

String Location::toString() const {
  return href();
}

String Location::hash() const {
  return DOMURLUtilsReadOnly::hash(Url());
}

void Location::setHref(v8::Isolate* isolate,
                       const String& url_string,
                       ExceptionState& exception_state) {
  LocalDOMWindow* incumbent_window = IncumbentDOMWindow(isolate);
  LocalDOMWindow* entered_window = EnteredDOMWindow(isolate);
  SetLocation(url_string, incumbent_window, entered_window, &exception_state);
}

void Location::setProtocol(v8::Isolate* isolate,
                           const String& protocol,
                           ExceptionState& exception_state) {
  KURL url = GetDocument()->Url();
  if (!url.SetProtocol(protocol)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "'" + protocol + "' is an invalid protocol.");
    return;
  }

  SetLocation(url.GetString(), IncumbentDOMWindow(isolate),
              EnteredDOMWindow(isolate), &exception_state);
}

void Location::setHost(v8::Isolate* isolate,
                       const String& host,
                       ExceptionState& exception_state) {
  KURL url = GetDocument()->Url();
  url.SetHostAndPort(host);
  SetLocation(url.GetString(), IncumbentDOMWindow(isolate),
              EnteredDOMWindow(isolate), &exception_state);
}

void Location::setHostname(v8::Isolate* isolate,
                           const String& hostname,
                           ExceptionState& exception_state) {
  KURL url = GetDocument()->Url();
  url.SetHost(hostname);
  SetLocation(url.GetString(), IncumbentDOMWindow(isolate),
              EnteredDOMWindow(isolate), &exception_state);
}

void Location::setPort(v8::Isolate* isolate,
                       const String& port,
                       ExceptionState& exception_state) {
  KURL url = GetDocument()->Url();
  url.SetPort(port);
  SetLocation(url.GetString(), IncumbentDOMWindow(isolate),
              EnteredDOMWindow(isolate), &exception_state);
}

void Location::setPathname(v8::Isolate* isolate,
                           const String& pathname,
                           ExceptionState& exception_state) {
  KURL url = GetDocument()->Url();
  url.SetPath(pathname);
  SetLocation(url.GetString(), IncumbentDOMWindow(isolate),
              EnteredDOMWindow(isolate), &exception_state);
}

void Location::setSearch(v8::Isolate* isolate,
                         const String& search,
                         ExceptionState& exception_state) {
  KURL url = GetDocument()->Url();
  url.SetQuery(search);
  SetLocation(url.GetString(), IncumbentDOMWindow(isolate),
              EnteredDOMWindow(isolate), &exception_state);
}

void Location::setHash(v8::Isolate* isolate,
                       const String& hash,
                       ExceptionState& exception_state) {
  KURL url = GetDocument()->Url();
  String old_fragment_identifier = url.FragmentIdentifier().ToString();
  String new_fragment_identifier = hash;
  if (hash[0] == '#')
    new_fragment_identifier = hash.Substring(1);
  url.SetFragmentIdentifier(new_fragment_identifier);
  // Note that by parsing the URL and *then* comparing fragments, we are
  // comparing fragments post-canonicalization, and so this handles the
  // cases where fragment identifiers are ignored or invalid.
  if (EqualIgnoringNullity(old_fragment_identifier,
                           url.FragmentIdentifier().ToString())) {
    return;
  }
  SetLocation(url.GetString(), IncumbentDOMWindow(isolate),
              EnteredDOMWindow(isolate), &exception_state);
}

void Location::assign(v8::Isolate* isolate,
                      const String& url_string,
                      ExceptionState& exception_state) {
  LocalDOMWindow* incumbent_window = IncumbentDOMWindow(isolate);
  LocalDOMWindow* entered_window = EnteredDOMWindow(isolate);
  SetLocation(url_string, incumbent_window, entered_window, &exception_state);
}

void Location::replace(v8::Isolate* isolate,
                       const String& url_string,
                       ExceptionState& exception_state) {
  LocalDOMWindow* incumbent_window = IncumbentDOMWindow(isolate);
  LocalDOMWindow* entered_window = EnteredDOMWindow(isolate);
  SetLocation(url_string, incumbent_window, entered_window, &exception_state,
              SetLocationPolicy::kReplaceThisFrame);
}

void Location::reload() {
  if (!IsAttached())
    return;
  if (GetDocument()->Url().ProtocolIsJavaScript())
    return;
  // reload() is not cross-origin accessible, so |dom_window_| will always be
  // local.
  To<LocalDOMWindow>(dom_window_.Get())
      ->GetFrame()
      ->Reload(WebFrameLoadType::kReload);
}

void Location::SetLocation(const String& url,
                           LocalDOMWindow* incumbent_window,
                           LocalDOMWindow* entered_window,
                           ExceptionState* exception_state,
                           SetLocationPolicy set_location_policy) {
  if (!IsAttached())
    return;

  if (!incumbent_window->GetFrame())
    return;

  Document* entered_document = entered_window->document();
  if (!entered_document)
    return;

  KURL completed_url = entered_document->CompleteURL(url);
  if (completed_url.IsNull())
    return;

  if (!incumbent_window->GetFrame()->CanNavigate(*dom_window_->GetFrame(),
                                                 completed_url)) {
    if (exception_state) {
      exception_state->ThrowSecurityError(
          "The current window does not have permission to navigate the target "
          "frame to '" +
          url + "'.");
    }
    return;
  }
  if (exception_state && !completed_url.IsValid()) {
    exception_state->ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                       "'" + url + "' is not a valid URL.");
    return;
  }

  V8DOMActivityLogger* activity_logger =
      V8DOMActivityLogger::CurrentActivityLoggerIfIsolatedWorld(
          incumbent_window->GetIsolate());
  if (activity_logger) {
    Vector<String> argv;
    argv.push_back("LocalDOMWindow");
    argv.push_back("url");
    argv.push_back(entered_document->Url());
    argv.push_back(completed_url);
    // We use the CurrentDOMWindow here. `dom_window` might be remote here.
    activity_logger->LogEvent(CurrentDOMWindow(incumbent_window->GetIsolate()),
                              "blinkSetAttribute", argv);
  }

  ResourceRequestHead resource_request(completed_url);
  resource_request.SetHasUserGesture(
      LocalFrame::HasTransientUserActivation(incumbent_window->GetFrame()));

  FrameLoadRequest request(incumbent_window, resource_request);
  request.SetClientNavigationReason(ClientNavigationReason::kFrameNavigation);
  WebFrameLoadType frame_load_type = WebFrameLoadType::kStandard;
  if (set_location_policy == SetLocationPolicy::kReplaceThisFrame)
    frame_load_type = WebFrameLoadType::kReplaceCurrentItem;

  dom_window_->GetFrame()->Navigate(request, frame_load_type);
}

Document* Location::GetDocument() const {
  return To<LocalDOMWindow>(dom_window_.Get())->document();
}

bool Location::IsAttached() const {
  return dom_window_->GetFrame();
}

}  // namespace blink
```