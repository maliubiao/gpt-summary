Response:
The user wants to understand the functionality of the given C++ source code file, `web_frame_serializer_sanitization_test.cc`. Specifically, they are interested in:

1. **Functionality:** What does this code do?
2. **Relationship to web technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and examples:** If there's logical reasoning involved, what are the input and output examples?
4. **Common errors:**  Are there common user or programming errors related to this code?
5. **Debugging context:** How might a user reach this code during debugging?

**Plan:**

1. **Identify the core purpose of the file:** Based on the name and included headers, it seems to be a test file for sanitizing web frames during serialization.
2. **Analyze the tests:** Examine each `TEST_F` to understand the specific sanitization rules being tested.
3. **Relate to web technologies:** Connect the tested sanitization rules to HTML, CSS, and JavaScript concepts.
4. **Provide examples:**  For each test, construct a simplified "before" (input HTML) and "after" (expected output after sanitization) scenario.
5. **Identify potential errors:** Think about scenarios where the sanitization logic might not work as expected or where developers might misuse the serialization process.
6. **Describe the user journey:**  Consider how a user's actions in a browser could lead to the execution of frame serialization, thus making this test relevant for debugging.
这个C++源代码文件 `web_frame_serializer_sanitization_test.cc` 是 Chromium Blink 引擎中的一个**单元测试文件**。它的主要功能是**测试 `WebFrameSerializer` 在序列化 Web 页面时进行的安全清理（sanitization）功能**。

**功能概括:**

这个文件通过编写一系列测试用例，来验证 `WebFrameSerializer` 是否正确地移除了可能存在的安全隐患或不必要的内容，以确保序列化后的页面是安全的并且符合预期。 这些清理操作通常包括：

* **移除内联脚本:** 删除 HTML 元素属性中的内联 JavaScript 代码（例如 `onload`, `onclick` 等）。
* **移除特定的危险属性:** 删除一些可能被滥用的 HTML 属性（例如 `ping` 属性）。
* **移除隐藏元素:**  删除带有 `hidden` 属性的元素，但保留一些特定的隐藏元素（如 `head`, `title`）。
* **移除 `<script>` 和 `<noscript>` 标签:**  阻止 JavaScript 代码被序列化。
* **移除 `<meta>` 标签中与安全相关的指令:** 例如移除包含 "Content-Security-Policy" 的 `<meta>` 标签。
* **处理 `<iframe>` 标签:**  移除位于 `<head>` 标签内的 `<iframe>` 标签。
* **处理 `srcdoc` 属性:** 将 `<iframe>` 标签的 `srcdoc` 属性替换为 `src` 属性。
* **处理图片加载:**  测试在不同设备像素比 (DPR) 下，图片通过 `srcset` 或 `src` 加载时，序列化器是否正确处理。
* **移除弹窗覆盖层:**  选择性地移除页面上的弹窗覆盖层元素。
* **处理 `<link>` 标签的 `integrity` 属性:**  移除包含 `integrity` 属性的 `<link>` 标签，或者移除该属性本身。
* **处理 Shadow DOM:**  将 Shadow DOM 的内容序列化为带有特定属性的 `<template>` 标签。
* **处理动态 CSS:** 验证动态添加的 CSS 规则是否被正确保留。
* **处理 `<picture>` 元素:** 验证 `<picture>` 元素的 `srcset` 属性和相关的图片资源是否被正确处理。
* **处理插件元素中的图片:** 验证 `<object>` 和 `<embed>` 元素中引用的图片资源是否被正确处理。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关系到 JavaScript, HTML, 和 CSS 的安全。 `WebFrameSerializer` 的清理功能旨在移除可能存在的跨站脚本攻击 (XSS) 风险和其他安全隐患。

* **JavaScript:**
    * **功能关系:** 测试移除 HTML 元素属性中的内联 JavaScript 代码，防止序列化后的页面执行恶意脚本。
    * **举例说明:**
        * **假设输入 HTML:** `<button onclick="alert('XSS')">Click Me</button>`
        * **清理后的输出 (MHTML 中):** `<button>Click Me</button>`  `onclick` 属性被移除。

* **HTML:**
    * **功能关系:** 测试移除特定的 HTML 属性和元素，以增强安全性或清理不必要的内容。
    * **举例说明:**
        * **假设输入 HTML:** `<a href="javascript:void(0)">Click</a>`
        * **清理后的输出 (MHTML 中):** `<a>Click</a>`  `href` 属性被移除，因为其包含 JavaScript 代码。
        * **假设输入 HTML:** `<div hidden id="hidden_div">This is hidden</div>`
        * **清理后的输出 (MHTML 中):**  这段 `div` 元素不会出现在序列化后的内容中。

* **CSS:**
    * **功能关系:** 测试是否会移除包含 `integrity` 属性的 `<link>` 标签，该属性用于验证 CSS 文件的完整性，但可能在某些上下文中不适用。同时，测试动态添加的 CSS 规则是否被保留。
    * **举例说明:**
        * **假设输入 HTML:** `<link rel="stylesheet" href="style.css" integrity="sha384-...">`
        * **清理后的输出 (取决于测试用例):** 可能 `<link rel="stylesheet" href="style.css">` (`integrity` 属性被移除) 或该 `<link>` 标签完全被移除。

**逻辑推理与假设输入输出:**

大多数测试用例都是通过断言 (EXPECT_EQ, EXPECT_NE) 来验证清理结果是否符合预期。  这里举一个逻辑推理的例子：

* **测试用例:** `RemoveInlineScriptInAttributes`
* **假设输入 HTML (来自 `script_in_attributes.html`):**
  ```html
  <div onload="doSomething()"></div>
  <a href="javascript:maliciousCode()">Click me</a>
  <iframe srcdoc="<script>alert('embedded script')</script>"></iframe>
  ```
* **逻辑推理:** `WebFrameSerializer` 应该扫描 HTML 属性，检测并移除包含 JavaScript 代码的属性（如 `onload`, `href` 中的 `javascript:`）。对于 `iframe` 的 `srcdoc` 属性，其内容包含脚本，应该被移除或替换为 `src` 属性。
* **预期输出 (在生成的 MHTML 中):**
  ```
  <div></div>
  <a>Click me</a>
  <iframe src="..."></iframe>
  ```
  * `onload="doSomething()"` 被移除。
  * `href="javascript:maliciousCode()"` 被移除。
  * `srcdoc` 属性被移除，并且可能会添加一个空的 `src` 属性或者完全移除 `iframe` 的内容 (具体行为取决于 `WebFrameSerializer` 的实现)。

**用户或编程常见的使用错误及举例说明:**

虽然这个文件是测试代码，但它反映了在使用 `WebFrameSerializer` 时可能遇到的问题或需要注意的地方：

* **开发者可能错误地假设 `WebFrameSerializer` 会保留所有的 JavaScript 代码。**  这个测试明确指出，内联脚本和 `<script>` 标签会被移除。
    * **错误示例:** 开发者依赖内联的 `onload` 事件来初始化某些功能，但在序列化后这些事件处理程序将丢失。
* **开发者可能没有意识到某些 HTML 属性会被清理。**  例如，依赖 `ping` 属性来发送跟踪信息，但在序列化后这些信息将不会被发送。
* **开发者可能不理解 Shadow DOM 的序列化方式。**  Shadow DOM 的内容会被包裹在 `<template>` 标签中，而不是直接嵌入到主 DOM 树中。这可能会影响开发者在反序列化后对 DOM 结构的预期。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户浏览网页:** 用户通过 Chromium 浏览器访问一个网页。
2. **触发页面保存或离线访问功能:** 用户可能点击浏览器的“保存网页”功能，或者浏览器内部为了支持离线访问，需要对当前页面进行序列化。
3. **调用 `WebFrameSerializer`:**  Chromium 内部的机制会调用 `WebFrameSerializer` 来将当前页面的 DOM 结构、样式和资源转换为某种序列化格式 (例如 MHTML)。
4. **执行清理逻辑:** `WebFrameSerializer` 在序列化过程中会执行安全清理逻辑，例如移除脚本、危险属性等。
5. **测试 `web_frame_serializer_sanitization_test.cc` 的相关测试用例:**  当 Chromium 的开发者修改或添加 `WebFrameSerializer` 的清理逻辑时，他们会运行这个测试文件中的测试用例来确保新的修改不会引入 bug，并且清理功能能够正常工作。

**作为调试线索：**

如果开发者发现保存的网页或离线访问的网页缺少某些功能或元素，例如：

* **按钮的点击事件失效:**  可能是因为内联的 `onclick` 属性被 `WebFrameSerializer` 清理掉了。
* **某些动画或交互效果消失:**  可能是因为依赖的 JavaScript 代码或特定的 HTML 属性被移除了。
* **页面样式不完整:**  可能是因为包含 `integrity` 属性的 `<link>` 标签被移除，导致样式文件没有被加载。

那么，开发者可能会查看 `web_frame_serializer_sanitization_test.cc` 中的测试用例，来了解 `WebFrameSerializer` 进行了哪些清理操作，从而找到问题的原因并调整他们的网页代码或 `WebFrameSerializer` 的实现。 例如，他们可以搜索与特定 HTML 元素、属性或 JavaScript 功能相关的测试用例，来理解其在序列化过程中是如何被处理的。

### 提示词
```
这是目录为blink/renderer/core/exported/web_frame_serializer_sanitization_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/public/web/web_frame_serializer.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/exported/web_frame_serializer_test_helper.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

namespace blink {

namespace {

// Returns the count of match for substring |pattern| in string |str|.
int MatchSubstring(const String& str, const char* pattern, wtf_size_t size) {
  int matches = 0;
  wtf_size_t start = 0;
  while (true) {
    wtf_size_t pos = str.Find(pattern, start);
    if (pos == WTF::kNotFound)
      break;
    matches++;
    start = pos + size;
  }
  return matches;
}

}  // namespace

class WebFrameSerializerSanitizationTest : public testing::Test {
 protected:
  WebFrameSerializerSanitizationTest() { helper_.Initialize(); }

  ~WebFrameSerializerSanitizationTest() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  String GenerateMHTMLFromHtml(const String& url, const String& file_name) {
    LoadFrame(url, file_name, "text/html");
    return WebFrameSerializerTestHelper::GenerateMHTML(MainFrameImpl());
  }

  String GenerateMHTMLPartsFromPng(const String& url, const String& file_name) {
    LoadFrame(url, file_name, "image/png");
    return WebFrameSerializerTestHelper::GenerateMHTMLParts(MainFrameImpl());
  }

  void LoadFrame(const String& url,
                 const String& file_name,
                 const String& mime_type) {
    KURL parsed_url(url);
    String file_path("frameserialization/" + file_name);
    RegisterMockedFileURLLoad(parsed_url, file_path, mime_type);
    frame_test_helpers::LoadFrame(MainFrameImpl(), url.Utf8().c_str());
    MainFrameImpl()->GetFrame()->View()->UpdateAllLifecyclePhasesForTest();
    MainFrameImpl()->GetFrame()->GetDocument()->UpdateStyleAndLayoutTree();
    test::RunPendingTasks();
  }

  ShadowRoot* SetShadowContent(
      TreeScope& scope,
      const char* host,
      ShadowRootMode shadow_type,
      const char* shadow_content,
      FocusDelegation focus_delegation = FocusDelegation::kNone) {
    Element* host_element = scope.getElementById(AtomicString::FromUTF8(host));
    ShadowRoot* shadow_root;
    shadow_root = &host_element->AttachShadowRootInternal(
        shadow_type, focus_delegation, SlotAssignmentMode::kNamed,
        /*registry*/ nullptr, /*serializable*/ false, /*clonable*/ false,
        /*reference_target*/ g_null_atom);
    shadow_root->SetDelegatesFocus(focus_delegation ==
                                   FocusDelegation::kDelegateFocus);
    shadow_root->setInnerHTML(String::FromUTF8(shadow_content),
                              ASSERT_NO_EXCEPTION);
    scope.GetDocument().View()->UpdateAllLifecyclePhasesForTest();
    return shadow_root;
  }

  void RegisterMockedFileURLLoad(const KURL& url,
                                 const String& file_path,
                                 const String& mime_type = "image/png") {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |helper_|.
    url_test_helpers::RegisterMockedURLLoad(
        url, test::CoreTestDataPath(file_path.Utf8().c_str()), mime_type);
  }

  WebViewImpl* WebView() { return helper_.GetWebView(); }

  WebLocalFrameImpl* MainFrameImpl() { return helper_.LocalMainFrame(); }

 private:
  test::TaskEnvironment task_environment_;
  frame_test_helpers::WebViewHelper helper_;
};

TEST_F(WebFrameSerializerSanitizationTest, RemoveInlineScriptInAttributes) {
  String mhtml =
      GenerateMHTMLFromHtml("http://www.test.com", "script_in_attributes.html");

  // These scripting attributes should be removed.
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("onload="));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("ONLOAD="));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("onclick="));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("href="));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("from="));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("to="));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("javascript:"));

  // These non-scripting attributes should remain intact.
  EXPECT_NE(WTF::kNotFound, mhtml.Find("class="));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("id="));

  // srcdoc attribute of frame element should be replaced with src attribute.
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("srcdoc="));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("src="));
}

TEST_F(WebFrameSerializerSanitizationTest, RemoveOtherAttributes) {
  String mhtml =
      GenerateMHTMLFromHtml("http://www.test.com", "remove_attributes.html");
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("ping="));
}

TEST_F(WebFrameSerializerSanitizationTest, RemoveHiddenElements) {
  String mhtml =
      GenerateMHTMLFromHtml("http://www.test.com", "hidden_elements.html");

  // The element with hidden attribute should be removed.
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("<p id=3D\"hidden_id\""));

  // The hidden form element should be removed.
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("<input type=3D\"hidden\""));

  // The style element should be converted to link element.
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("<style"));

  // All other hidden elements should not be removed.
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<html"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<head"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<title"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<h1"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<h2"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<datalist"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<option"));
  // One for meta in head and another for meta in body.
  EXPECT_EQ(2, MatchSubstring(mhtml, "<meta", 5));
  // Two for original link elements: one in head and another in body.
  // Two for original style elemtns: one in head and another in body.
  EXPECT_EQ(4, MatchSubstring(mhtml, "<link", 5));

  // These visible elements should remain intact.
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<p id=3D\"visible_id\""));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<form"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<input type=3D\"text\""));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<div"));
}

TEST_F(WebFrameSerializerSanitizationTest, RemoveIframeInHead) {
  String mhtml =
      GenerateMHTMLFromHtml("http://www.test.com", "iframe_in_head.html");

  // The iframe elements could only be found after body. Any iframes injected to
  // head should be removed.
  EXPECT_GT(mhtml.Find("<iframe"), mhtml.Find("<body"));
}

// Regression test for crbug.com/678893, where in some cases serializing an
// image document could cause code to pick an element from an empty container.
TEST_F(WebFrameSerializerSanitizationTest, FromBrokenImageDocument) {
  // This test only cares that the result of the parts generation is empty so it
  // is simpler to not generate only that instead of the full MHTML.
  String mhtml =
      GenerateMHTMLPartsFromPng("http://www.test.com", "broken-image.png");
  EXPECT_TRUE(mhtml.empty());
}

TEST_F(WebFrameSerializerSanitizationTest, ImageLoadedFromSrcsetForHiDPI) {
  RegisterMockedFileURLLoad(KURL("http://www.test.com/1x.png"),
                            "frameserialization/1x.png");
  RegisterMockedFileURLLoad(KURL("http://www.test.com/2x.png"),
                            "frameserialization/2x.png");

  // Set high DPR in order to load image from srcset, instead of src.
  WebView()->SetZoomFactorForDeviceScaleFactor(2.0f);

  String mhtml =
      GenerateMHTMLFromHtml("http://www.test.com", "img_srcset.html");

  // srcset and sizes attributes should be skipped.
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("srcset="));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("sizes="));

  // src attribute with original URL should be preserved.
  EXPECT_EQ(2,
            MatchSubstring(mhtml, "src=3D\"http://www.test.com/1x.png\"", 34));

  // The image resource for original URL should be attached.
  EXPECT_NE(WTF::kNotFound,
            mhtml.Find("Content-Location: http://www.test.com/1x.png"));

  // Width and height attributes should be set when none is present in <img>.
  EXPECT_NE(WTF::kNotFound,
            mhtml.Find("id=3D\"i1\" width=3D\"6\" height=3D\"6\">"));

  // Height attribute should not be set if width attribute is already present in
  // <img>
  EXPECT_NE(WTF::kNotFound, mhtml.Find("id=3D\"i2\" width=3D\"8\">"));
}

TEST_F(WebFrameSerializerSanitizationTest, ImageLoadedFromSrcForNormalDPI) {
  RegisterMockedFileURLLoad(KURL("http://www.test.com/1x.png"),
                            "frameserialization/1x.png");
  RegisterMockedFileURLLoad(KURL("http://www.test.com/2x.png"),
                            "frameserialization/2x.png");

  String mhtml =
      GenerateMHTMLFromHtml("http://www.test.com", "img_srcset.html");

  // srcset and sizes attributes should be skipped.
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("srcset="));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("sizes="));

  // src attribute with original URL should be preserved.
  EXPECT_EQ(2,
            MatchSubstring(mhtml, "src=3D\"http://www.test.com/1x.png\"", 34));

  // The image resource for original URL should be attached.
  EXPECT_NE(WTF::kNotFound,
            mhtml.Find("Content-Location: http://www.test.com/1x.png"));

  // New width and height attributes should not be set.
  EXPECT_NE(WTF::kNotFound, mhtml.Find("id=3D\"i1\">"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("id=3D\"i2\" width=3D\"8\">"));
}

TEST_F(WebFrameSerializerSanitizationTest, RemovePopupOverlayIfRequested) {
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadFrame("http://www.test.com", "popup.html", "text/html");
  String mhtml =
      WebFrameSerializerTestHelper::GenerateMHTMLWithPopupOverlayRemoved(
          MainFrameImpl());
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("class=3D\"overlay"));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("class=3D\"modal"));
}

TEST_F(WebFrameSerializerSanitizationTest, PopupOverlayNotFound) {
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadFrame("http://www.test.com", "text_only_page.html", "text/html");
  WebFrameSerializerTestHelper::GenerateMHTMLWithPopupOverlayRemoved(
      MainFrameImpl());
}

TEST_F(WebFrameSerializerSanitizationTest, KeepPopupOverlayIfNotRequested) {
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  String mhtml = GenerateMHTMLFromHtml("http://www.test.com", "popup.html");
  EXPECT_NE(WTF::kNotFound, mhtml.Find("class=3D\"overlay"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("class=3D\"modal"));
}

TEST_F(WebFrameSerializerSanitizationTest, LinkIntegrity) {
  RegisterMockedFileURLLoad(KURL("http://www.test.com/beautifull.css"),
                            "frameserialization/beautifull.css", "text/css");
  RegisterMockedFileURLLoad(KURL("http://www.test.com/integrityfail.css"),
                            "frameserialization/integrityfail.css", "text/css");
  String mhtml =
      GenerateMHTMLFromHtml("http://www.test.com", "link_integrity.html");
  SCOPED_TRACE(testing::Message() << "mhtml:\n" << mhtml);

  // beautifull.css remains, without 'integrity'. integrityfail.css is removed.
  EXPECT_TRUE(
      mhtml.Contains("<link rel=3D\"stylesheet\" "
                     "href=3D\"http://www.test.com/beautifull.css\">"));
  EXPECT_EQ(WTF::kNotFound,
            mhtml.Find("http://www.test.com/integrityfail.css"));
}

TEST_F(WebFrameSerializerSanitizationTest, RemoveElements) {
  String mhtml =
      GenerateMHTMLFromHtml("http://www.test.com", "remove_elements.html");

  EXPECT_EQ(WTF::kNotFound, mhtml.Find("<script"));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("<noscript"));

  // Only the meta element containing "Content-Security-Policy" is removed.
  // Other meta elements should be preserved.
  EXPECT_EQ(WTF::kNotFound,
            mhtml.Find("<meta http-equiv=3D\"Content-Security-Policy"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<meta name=3D\"description"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<meta http-equiv=3D\"refresh"));

  // If an element is removed, its children should also be skipped.
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("<select"));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("<option"));
}

TEST_F(WebFrameSerializerSanitizationTest, ShadowDOM) {
  LoadFrame("http://www.test.com", "shadow_dom.html", "text/html");
  Document* document = MainFrameImpl()->GetFrame()->GetDocument();
  ShadowRoot* shadowRoot = SetShadowContent(
      *document, "h2", ShadowRootMode::kOpen,
      "Parent shadow\n<p id=\"h3\">Foo</p>", FocusDelegation::kDelegateFocus);
  SetShadowContent(*shadowRoot, "h3", ShadowRootMode::kClosed, "Nested shadow");
  String mhtml = WebFrameSerializerTestHelper::GenerateMHTML(MainFrameImpl());

  // Template with special attribute should be created for each shadow DOM tree.
  EXPECT_NE(WTF::kNotFound,
            mhtml.Find("<template shadowmode=3D\"open\" shadowdelegatesfocus"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("<template shadowmode=3D\"closed\">"));

  // The special attribute present in the original page should be removed.
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("shadowmode=3D\"foo\">"));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("shadowdelegatesfocus=3D\"bar\">"));
}

TEST_F(WebFrameSerializerSanitizationTest, StyleElementsWithDynamicCSS) {
  String mhtml = GenerateMHTMLFromHtml("http://www.test.com",
                                       "style_element_with_dynamic_css.html");

  // The dynamically updated CSS rules should be preserved.
  EXPECT_NE(WTF::kNotFound, mhtml.Find("div { color: blue; }"));
  EXPECT_NE(WTF::kNotFound, mhtml.Find("p { color: red; }"));
  EXPECT_EQ(WTF::kNotFound, mhtml.Find("h1 { color: green; }"));
}

TEST_F(WebFrameSerializerSanitizationTest, PictureElement) {
  RegisterMockedFileURLLoad(KURL("http://www.test.com/1x.png"),
                            "frameserialization/1x.png");
  RegisterMockedFileURLLoad(KURL("http://www.test.com/2x.png"),
                            "frameserialization/2x.png");

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(500, 500));

  String mhtml = GenerateMHTMLFromHtml("http://www.test.com", "picture.html");

  // srcset attribute should be kept.
  EXPECT_EQ(2, MatchSubstring(mhtml, "srcset=", 7));

  // 2x.png resource should be added.
  EXPECT_NE(WTF::kNotFound,
            mhtml.Find("Content-Location: http://www.test.com/2x.png"));
  EXPECT_EQ(WTF::kNotFound,
            mhtml.Find("Content-Location: http://www.test.com/1x.png"));
}

TEST_F(WebFrameSerializerSanitizationTest, ImageInPluginElement) {
  RegisterMockedFileURLLoad(KURL("http://www.test.com/1x.png"),
                            "frameserialization/1x.png");
  RegisterMockedFileURLLoad(KURL("http://www.test.com/2x.png"),
                            "frameserialization/2x.png");

  String mhtml =
      GenerateMHTMLFromHtml("http://www.test.com", "image_in_plugin.html");

  // Image resources for both object and embed elements should be added.
  EXPECT_NE(WTF::kNotFound,
            mhtml.Find("Content-Location: http://www.test.com/1x.png"));
  EXPECT_NE(WTF::kNotFound,
            mhtml.Find("Content-Location: http://www.test.com/2x.png"));
}

}  // namespace blink
```