Response:
The user wants to understand the functionality of the `html_meta_element_test.cc` file in the Chromium Blink rendering engine.

Here's a breakdown of how to address this request:

1. **Identify the core purpose of the file:** The file name `html_meta_element_test.cc` strongly suggests it contains unit tests for the `HTMLMetaElement` class.

2. **Analyze the included headers:** The headers provide clues about the aspects of `HTMLMetaElement` being tested. Look for connections to HTML, CSS, JavaScript, and browser functionality.

3. **Examine the test structure:**  The file uses the Google Test framework (`TEST_F`). Each `TEST_F` function represents a specific test case.

4. **Categorize the test cases:** Group the tests based on the specific functionality of the `HTMLMetaElement` they are testing.

5. **Explain the relationship to web technologies:** For each category, explain how it relates to HTML, CSS, and JavaScript. Provide illustrative examples.

6. **Address logical reasoning:**  Look for test cases that involve setting attributes and checking the resulting state. Formulate input and output examples.

7. **Identify potential user errors:**  Consider common mistakes developers might make when using the `<meta>` tag and how these tests might implicitly or explicitly cover those scenarios.

8. **Structure the response:** Organize the information clearly with headings and bullet points for readability.
这个文件 `html_meta_element_test.cc` 是 Chromium Blink 引擎中用于测试 `HTMLMetaElement` 类的单元测试文件。它的主要功能是验证 `HTMLMetaElement` 的各种行为和属性是否按照预期工作。

以下是该文件测试的具体功能，并解释了它们与 JavaScript、HTML 和 CSS 的关系：

**1. 测试 `viewport` meta 标签的功能:**

*   **功能:** 测试 `<meta name="viewport" content="...">` 属性中 `viewport-fit` 属性的不同取值 (`auto`, `contain`, `cover`) 是否能正确解析并影响视口的行为。
*   **与 HTML 的关系:**  `viewport` meta 标签是 HTML 中用于控制网页在不同设备上如何缩放和显示的 crucial 部分。
*   **与 CSS 的关系:** `viewport-fit` 属性会影响 CSS 中的 `safe-area-inset-*` 变量，从而影响元素的布局，特别是在有刘海屏等特殊显示区域的设备上。
*   **与 JavaScript 的关系:** 虽然测试代码本身不是 JavaScript，但 JavaScript 可以读取和修改 `viewport` meta 标签的内容，从而动态改变视口的设置。
*   **假设输入与输出:**
    *   **输入:** `<meta name='viewport' content='viewport-fit=contain'>`
    *   **输出:** `GetDocument().GetViewportData().GetViewportDescription().GetViewportFit()` 返回 `mojom::ViewportFit::kContain`。
*   **用户或编程常见的使用错误:**
    *   **错误:** 拼写错误 `viewport-fit` 属性的值，例如写成 `cotain`。
    *   **结果:**  视口可能无法按预期缩放或覆盖屏幕。测试用例 `ViewportFit_Invalid` 验证了这种情况，当提供无效值时，会回退到默认值 (`auto`)。

**2. 测试 `color-scheme` meta 标签的功能:**

*   **功能:** 测试 `<meta name="color-scheme" content="...">` 属性的不同取值 (`light`, `dark`, `normal`, `only`) 如何影响页面的首选配色方案，以及在添加、删除或修改该标签时，页面配色方案的更新是否正确。
*   **与 HTML 的关系:** `color-scheme` meta 标签允许网站声明其支持的配色方案，从而让浏览器根据用户的偏好选择合适的样式。
*   **与 CSS 的关系:**  `color-scheme` meta 标签与 CSS 媒体查询 `@media (prefers-color-scheme: light)` 和 `@media (prefers-color-scheme: dark)` 联动。浏览器会根据用户设置和 `color-scheme` 的声明来匹配相应的样式。
*   **与 JavaScript 的关系:** JavaScript 可以读取 `color-scheme` meta 标签的内容，但通常不建议直接修改，因为这应该由 HTML 定义。
*   **假设输入与输出:**
    *   **输入:** `<meta name="color-scheme" content="dark light">`
    *   **输出:** `GetDocument().GetStyleEngine().GetPageColorSchemes()` 包含 `ColorSchemeFlag::kDark` 和 `ColorSchemeFlag::kLight`。
*   **用户或编程常见的使用错误:**
    *   **错误:**  `content` 属性中使用了不支持的值，例如 `blue`。
    *   **结果:** 浏览器会忽略不支持的值。测试用例 `ColorSchemeParsing` 验证了各种合法的和非法的 `content` 值。
    *   **错误:**  在页面中定义了多个 `color-scheme` meta 标签。
    *   **结果:**  浏览器通常会采用第一个出现的 `color-scheme` 标签。测试用例 `ColorSchemeProcessing_FirstWins` 验证了这一行为。

**3. 测试在动态修改 `color-scheme` meta 标签时的行为:**

*   **功能:** 测试在运行时通过 JavaScript (虽然测试代码本身是 C++) 添加、删除或修改 `color-scheme` meta 标签时，页面的配色方案是否会动态更新。
*   **与 HTML 的关系:** 验证了 DOM 操作对 HTML 元数据的影响。
*   **与 CSS 的关系:**  确保在动态修改 meta 标签后，CSS 媒体查询能够正确地重新评估。
*   **与 JavaScript 的关系:**  JavaScript 是进行 DOM 操作的主要方式，例如使用 `document.getElementById().remove()` 或 `element.setAttribute()`。测试用例模拟了这些操作。
*   **假设输入与输出:**
    *   **输入:** 初始 HTML `<meta id="meta" name="color-scheme" content="dark">`，然后通过 JavaScript 修改 `content` 属性为 `light`。
    *   **输出:**  修改前 `GetDocument().GetStyleEngine().GetPageColorSchemes()` 包含 `ColorSchemeFlag::kDark`，修改后包含 `ColorSchemeFlag::kLight`。

**4. 测试 `referrer` meta 标签的功能:**

*   **功能:** 测试 `<meta name="referrer" content="...">` 属性的不同取值如何影响浏览器发送请求时的 Referer HTTP 头。
*   **与 HTML 的关系:** `referrer` meta 标签允许网站控制其来源信息的发送策略，出于安全和隐私考虑。
*   **与 JavaScript 的关系:** JavaScript 可以触发网络请求，`referrer` meta 标签会影响这些请求的 Referer 头。
*   **假设输入与输出:**
    *   **输入:** `<meta name="referrer" content="strict-origin">`
    *   **输出:**  `GetFrame().DomWindow()->GetReferrerPolicy()` 和 `GetFrame().DomWindow()->GetPolicyContainer()->GetReferrerPolicy()` 返回 `network::mojom::ReferrerPolicy::kStrictOrigin`。
*   **用户或编程常见的使用错误:**
    *   **错误:**  使用了拼写错误的 `content` 值。
    *   **结果:**  浏览器可能会回退到默认的 referrer policy。

**5. 测试 `monetization` meta 标签的功能:**

*   **功能:** 测试 `<meta name="monetization" content="...">` 标签是否被正确识别并触发 Web Monetization 功能的计数器。
*   **与 HTML 的关系:**  `monetization` meta 标签是 Web Monetization API 的一部分，用于声明网站的支付指针。
*   **与 JavaScript 的关系:**  Web Monetization API 可以通过 JavaScript 进行交互，而 `monetization` meta 标签提供了一种声明支付指针的方式。
*   **假设输入与输出:**
    *   **输入:** `<meta name="monetization" content="$payment.pointer.url">`
    *   **输出:** `GetDocument().IsUseCounted(WebFeature::kHTMLMetaElementMonetization)` 返回 `true`。
*   **重要说明:** 测试用例 `WebMonetizationNotCountedInSubFrame` 明确指出，子框架中的 `<meta name="monetization">` 标签不会被计数。

**总结:**

`html_meta_element_test.cc` 文件通过各种单元测试，全面地验证了 `HTMLMetaElement` 类的功能，涵盖了 `viewport`、`color-scheme`、`referrer` 和 `monetization` 等关键的 meta 标签。这些测试确保了 Blink 引擎能够正确解析和处理这些 meta 标签，从而保证了网页在不同场景下的正确渲染和行为。 这些测试与 HTML 结构、CSS 样式以及可能的 JavaScript 交互都有着密切的联系，保障了 Web 开发者能够按照规范使用这些重要的 HTML 功能。

Prompt: 
```
这是目录为blink/renderer/core/html/html_meta_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/html_meta_element.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/media_query_list.h"
#include "third_party/blink/renderer/core/css/media_query_matcher.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/color_scheme_helper.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/sim/sim_compositor.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

class HTMLMetaElementTest : public PageTestBase,
                            private ScopedDisplayCutoutAPIForTest {
 public:
  HTMLMetaElementTest() : ScopedDisplayCutoutAPIForTest(true) {}
  void SetUp() override {
    PageTestBase::SetUp();
    GetDocument().GetSettings()->SetViewportMetaEnabled(true);
  }

  mojom::ViewportFit LoadTestPageAndReturnViewportFit(const String& value) {
    LoadTestPageWithViewportFitValue(value);
    return GetDocument()
        .GetViewportData()
        .GetViewportDescription()
        .GetViewportFit();
  }

 protected:
  HTMLMetaElement* CreateColorSchemeMeta(const char* content) {
    auto* meta = MakeGarbageCollected<HTMLMetaElement>(GetDocument(),
                                                       CreateElementFlags());
    meta->setAttribute(html_names::kNameAttr, keywords::kColorScheme);
    meta->setAttribute(html_names::kContentAttr, AtomicString(content));
    return meta;
  }

  void SetColorScheme(const char* content) {
    auto* meta = To<HTMLMetaElement>(GetDocument().head()->firstChild());
    ASSERT_TRUE(meta);
    meta->setAttribute(html_names::kContentAttr, AtomicString(content));
  }

  void ExpectPageColorSchemes(ColorSchemeFlags expected) const {
    EXPECT_EQ(expected, GetDocument().GetStyleEngine().GetPageColorSchemes());
  }

 private:
  void LoadTestPageWithViewportFitValue(const String& value) {
    GetDocument().documentElement()->setInnerHTML(
        "<head>"
        "<meta name='viewport' content='viewport-fit=" +
        value +
        "'>"
        "</head>");
  }
};
class HTMLMetaElementSimTest : public SimTest {};

TEST_F(HTMLMetaElementTest, ViewportFit_Auto) {
  EXPECT_EQ(mojom::ViewportFit::kAuto,
            LoadTestPageAndReturnViewportFit("auto"));
}

TEST_F(HTMLMetaElementTest, ViewportFit_Contain) {
  EXPECT_EQ(mojom::ViewportFit::kContain,
            LoadTestPageAndReturnViewportFit("contain"));
}

TEST_F(HTMLMetaElementTest, ViewportFit_Cover) {
  EXPECT_EQ(mojom::ViewportFit::kCover,
            LoadTestPageAndReturnViewportFit("cover"));
}

TEST_F(HTMLMetaElementTest, ViewportFit_Invalid) {
  EXPECT_EQ(mojom::ViewportFit::kAuto,
            LoadTestPageAndReturnViewportFit("invalid"));
}

// TODO(https://crbug.com/1430288) remove after data collected (end of '23)
TEST_F(HTMLMetaElementTest, ViewportFit_Auto_NotUseCounted) {
  EXPECT_EQ(mojom::ViewportFit::kAuto,
            LoadTestPageAndReturnViewportFit("auto"));
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kViewportFitContain));
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kViewportFitCover));
  // TODO(https://crbug.com/1430288) remove tracking this union of features
  // after data collected (end of '23)
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kViewportFitCoverOrSafeAreaInsetBottom));
}

TEST_F(HTMLMetaElementTest, ViewportFit_Contain_IsUseCounted) {
  EXPECT_EQ(mojom::ViewportFit::kContain,
            LoadTestPageAndReturnViewportFit("contain"));
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kViewportFitCover));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kViewportFitCoverOrSafeAreaInsetBottom));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kViewportFitContain));
}

// TODO(https://crbug.com/1430288) remove after data collected (end of '23)
TEST_F(HTMLMetaElementTest, ViewportFit_Cover_IsUseCounted) {
  EXPECT_EQ(mojom::ViewportFit::kCover,
            LoadTestPageAndReturnViewportFit("cover"));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kViewportFitCover));
  // TODO(https://crbug.com/1430288) remove tracking this union of features
  // after data collected (end of '23)
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kViewportFitCoverOrSafeAreaInsetBottom));
}

TEST_F(HTMLMetaElementTest, ColorSchemeProcessing_FirstWins) {
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta name="color-scheme" content="dark">
    <meta name="color-scheme" content="light">
  )HTML");

  ExpectPageColorSchemes(static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark));
}

TEST_F(HTMLMetaElementTest, ColorSchemeProcessing_Remove) {
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta id="first-meta" name="color-scheme" content="dark">
    <meta name="color-scheme" content="light">
  )HTML");

  ExpectPageColorSchemes(static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark));

  GetDocument().getElementById(AtomicString("first-meta"))->remove();

  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kLight));
}

TEST_F(HTMLMetaElementTest, ColorSchemeProcessing_InsertBefore) {
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta name="color-scheme" content="dark">
  )HTML");

  ExpectPageColorSchemes(static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark));

  Element* head = GetDocument().head();
  head->insertBefore(CreateColorSchemeMeta("light"), head->firstChild());

  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kLight));
}

TEST_F(HTMLMetaElementTest, ColorSchemeProcessing_AppendChild) {
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta name="color-scheme" content="dark">
  )HTML");

  ExpectPageColorSchemes(static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark));

  GetDocument().head()->AppendChild(CreateColorSchemeMeta("light"));

  ExpectPageColorSchemes(static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark));
}

TEST_F(HTMLMetaElementTest, ColorSchemeProcessing_SetAttribute) {
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta id="meta" name="color-scheme" content="dark">
  )HTML");

  ExpectPageColorSchemes(static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark));

  GetDocument()
      .getElementById(AtomicString("meta"))
      ->setAttribute(html_names::kContentAttr, AtomicString("light"));

  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kLight));
}

TEST_F(HTMLMetaElementTest, ColorSchemeProcessing_RemoveContentAttribute) {
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta id="meta" name="color-scheme" content="dark">
  )HTML");

  ExpectPageColorSchemes(static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark));

  GetDocument()
      .getElementById(AtomicString("meta"))
      ->removeAttribute(html_names::kContentAttr);

  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal));
}

TEST_F(HTMLMetaElementTest, ColorSchemeProcessing_RemoveNameAttribute) {
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta id="meta" name="color-scheme" content="dark">
  )HTML");

  ExpectPageColorSchemes(static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark));

  GetDocument()
      .getElementById(AtomicString("meta"))
      ->removeAttribute(html_names::kNameAttr);

  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal));
}

TEST_F(HTMLMetaElementTest, ColorSchemeParsing) {
  GetDocument().head()->AppendChild(CreateColorSchemeMeta(""));

  SetColorScheme("");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal));

  SetColorScheme("normal");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal));

  SetColorScheme("light");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kLight));

  SetColorScheme("dark");
  ExpectPageColorSchemes(static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark));

  SetColorScheme("light dark");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kLight) |
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kDark));

  SetColorScheme(" BLUE  light   ");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kLight));

  SetColorScheme("light,dark");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal));

  SetColorScheme("light,");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal));

  SetColorScheme(",light");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal));

  SetColorScheme(", light");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal));

  SetColorScheme("light, dark");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal));

  SetColorScheme("only");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kNormal));

  SetColorScheme("only light");
  ExpectPageColorSchemes(
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kOnly) |
      static_cast<ColorSchemeFlags>(ColorSchemeFlag::kLight));
}

TEST_F(HTMLMetaElementTest, ColorSchemeForcedDarkeningAndMQ) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);

  auto* media_query = GetDocument().GetMediaQueryMatcher().MatchMedia(
      "(prefers-color-scheme: dark)");
  EXPECT_TRUE(media_query->matches());
  GetDocument().GetSettings()->SetForceDarkModeEnabled(true);
  EXPECT_TRUE(media_query->matches());

  GetDocument().head()->AppendChild(CreateColorSchemeMeta("light"));
  EXPECT_TRUE(media_query->matches());

  SetColorScheme("dark");
  EXPECT_TRUE(media_query->matches());

  SetColorScheme("light dark");
  EXPECT_TRUE(media_query->matches());
}

TEST_F(HTMLMetaElementTest, ReferrerPolicyWithoutContent) {
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta name="referrer" content="strict-origin">
    <meta name="referrer" >
  )HTML");
  EXPECT_EQ(network::mojom::ReferrerPolicy::kStrictOrigin,
            GetFrame().DomWindow()->GetReferrerPolicy());
  EXPECT_EQ(network::mojom::ReferrerPolicy::kStrictOrigin,
            GetFrame().DomWindow()->GetPolicyContainer()->GetReferrerPolicy());
}

TEST_F(HTMLMetaElementTest, ReferrerPolicyUpdatesPolicyContainer) {
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta name="referrer" content="strict-origin">
  )HTML");
  EXPECT_EQ(network::mojom::ReferrerPolicy::kStrictOrigin,
            GetFrame().DomWindow()->GetReferrerPolicy());
  EXPECT_EQ(network::mojom::ReferrerPolicy::kStrictOrigin,
            GetFrame().DomWindow()->GetPolicyContainer()->GetReferrerPolicy());
}

// This tests whether Web Monetization counter is properly triggered.
TEST_F(HTMLMetaElementTest, WebMonetizationCounter) {
  // <meta> elements that don't have name equal to "monetization" or that lack
  // a content attribute are not counted.
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta name="color-scheme" content="dark">
    <meta name="monetization">
  )HTML");
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kHTMLMetaElementMonetization));

  // A <link rel="monetization"> with a content attribute is counted.
  GetDocument().head()->setInnerHTML(R"HTML(
    <meta name="monetization" content="$payment.pointer.url">
  )HTML");
  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kHTMLMetaElementMonetization));

  // However, it does not affect the counter for <link rel="monetization">.
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kHTMLLinkElementMonetization));
}

TEST_F(HTMLMetaElementSimTest, WebMonetizationNotCountedInSubFrame) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_frame_resource("https://example.com/subframe.html",
                                  "text/html");

  LoadURL("https://example.com/");

  main_resource.Complete(
      R"HTML(
        <body onload='console.log("main body onload");'>
          <iframe src='https://example.com/subframe.html'
                  onload='console.log("child frame element onload");'></iframe>
        </body>)HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  child_frame_resource.Complete(R"HTML(
    <meta name="monetization" content="$payment.pointer.url">
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // Ensure that main frame and subframe are loaded before checking the counter.
  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));

  // <meta name="monetization"> is not counted in subframes.
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kHTMLMetaElementMonetization));
}

}  // namespace blink

"""

```