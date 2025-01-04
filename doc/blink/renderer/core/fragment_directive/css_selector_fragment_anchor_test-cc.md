Response:
Let's break down the thought process for analyzing this C++ test file and generating the descriptive explanation.

1. **Understand the Goal:** The primary goal is to explain what this specific C++ file does within the Chromium Blink rendering engine, particularly in relation to web technologies (HTML, CSS, JavaScript).

2. **Identify the File's Purpose from its Name and Location:**
   - **File Path:** `blink/renderer/core/fragment_directive/css_selector_fragment_anchor_test.cc`
   - `blink/renderer/core`: This strongly suggests it's part of the core rendering functionality.
   - `fragment_directive`: This hints at a feature related to URL fragments (the part after the `#`).
   - `css_selector_fragment_anchor`: This is the most specific part. It clearly indicates it's about handling fragment directives that use CSS selectors to target elements.
   - `test.cc`:  This suffix confirms it's a test file.

3. **Analyze the Includes:**  The included header files provide crucial clues about the file's dependencies and functionality. I'd go through them systematically:
   - `base/test/scoped_feature_list.h`: Likely used for enabling/disabling experimental features during testing.
   - `testing/gtest/include/gtest/gtest.h`:  Confirms it's using the Google Test framework.
   - `third_party/blink/public/common/features.h`:  Accessing Blink's feature flags.
   - `third_party/blink/public/web/web_script_source.h`:  Potentially for injecting or testing JavaScript (though not heavily used in this file).
   - `third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h`: Interaction with V8, the JavaScript engine (though not directly tested here, it's in the rendering core, so this is expected).
   - `third_party/blink/renderer/core/css/...`:  Working with CSS properties and styles.
   - `third_party/blink/renderer/core/frame/...`:  Dealing with frames, views, and the browsing context.
   - `third_party/blink/renderer/core/html/...`:  Interacting with HTML elements.
   - `third_party/blink/renderer/core/layout/...`:  Relates to the layout and rendering of elements.
   - `third_party/blink/renderer/core/loader/...`:  Handling document loading.
   - `third_party/blink/renderer/core/page/...`:  Page-level functionalities like focus and scrolling.
   - `third_party/blink/renderer/core/paint/...`:  Relating to the painting and rendering process.
   - `third_party/blink/renderer/core/svg/...`:  Handling SVG elements.
   - `third_party/blink/renderer/core/testing/sim/...`:  Using simulation tools for testing Blink's behavior.
   - `third_party/blink/renderer/platform/graphics/...`:  Lower-level graphics primitives.
   - `third_party/blink/renderer/platform/testing/...`:  Platform-specific testing utilities.

4. **Examine the Test Fixture (`CssSelectorFragmentAnchorTest`):**
   - `SetUp()`:  Initializes the testing environment, focusing the page, resizing the viewport – essential setup for rendering tests.
   - Helper methods (`LayoutViewport`, `ViewportRect`, `BoundingRectInFrame`, `SimulateClick`, `IsVisibleInViewport`, `IsSelectorFragmentAnchorCreated`, `GetComputedValue`, `IsElementOutlined`, `CircleSVG`): These methods abstract away common actions and checks, making the tests more readable and maintainable. They directly interact with the DOM, layout, and rendering.

5. **Analyze Individual Test Cases (e.g., `BasicTest`, `TwoCssSelectorFragmentsOutlineFirst`):**
   - **Focus on the test name:** The names are usually descriptive of the scenario being tested.
   - **Look at the `SimRequest` setup:**  This shows how the test injects HTML and other resources. Pay attention to the URL, especially the fragment part (`#:~:selector...`).
   - **Examine the `LoadURL()` call:** This triggers the navigation to the test URL with the fragment directive.
   - **Understand the HTML structure:**  The `main_request.Complete(R"HTML(...)HTML");` provides the HTML content being tested.
   - **Identify the assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`):** These are the core of the tests, verifying the expected behavior. Look for what properties are being checked (e.g., `GetDocument().CssTarget()`, `IsSelectorFragmentAnchorCreated()`, `IsElementOutlined()`).
   - **Pay attention to specific actions:**  For example, `SimulateClick()` tests how user interaction affects the fragment anchor.

6. **Connect the Dots to Web Technologies:** As you analyze the test cases and helper methods, explicitly link them back to HTML, CSS, and JavaScript concepts:
   - **HTML:** The tests manipulate and examine HTML elements (`<img>`, `<div>`, `<p>`, `<a>`).
   - **CSS:** The tests verify the application of CSS styles, particularly the outline for highlighting (`IsElementOutlined`, `GetComputedValue(CSSPropertyID::kOutlineWidth)`). The core feature being tested *uses* CSS selectors.
   - **JavaScript:** While this specific test file doesn't directly execute JavaScript, the underlying feature (CSS selector fragment anchors) affects how JavaScript might interact with the DOM after a page load with such a fragment. The presence of `v8_binding_for_core.h` acknowledges the JavaScript engine's role.

7. **Infer Functionality and Logic:** Based on the tests, deduce the core functionality being verified:
   - Parsing CSS selector fragment directives from the URL.
   - Identifying the correct HTML element based on the CSS selector.
   - Setting the identified element as the "CSS target."
   - Applying a visual highlight (outline) to the target element.
   - Prioritizing CSS selector fragments over other fragment types (like simple `#id`).
   - Handling cases where the selector is not found or is invalid.
   - Ensuring the fragment anchor persists after user interaction.
   - Encoding/decoding of the CSS selector value.

8. **Consider Potential Errors:** Think about what could go wrong when using this feature:
   - **Incorrect CSS selectors:**  Typos or using selectors that don't match any element.
   - **Encoding issues:** Not properly encoding special characters in the selector value.
   - **Browser compatibility:** Although this is a Blink test, think about how this feature might behave in other browsers (though the tests themselves focus on Blink).

9. **Structure the Explanation:** Organize the findings into a clear and logical explanation:
   - Start with a concise summary of the file's purpose.
   - Explain the relationship to HTML, CSS, and JavaScript with examples from the code.
   - Detail the logical inferences and assumptions, providing hypothetical inputs and outputs.
   - Discuss common usage errors.

10. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Make sure the examples are relevant and easy to understand. For instance, explicitly mentioning the highlighting of the targeted element with an outline is a key detail.

By following these steps, focusing on the code's structure, the test cases, and the underlying web technologies, you can effectively analyze and explain the functionality of a complex source code file like this one.
这个C++源代码文件 `css_selector_fragment_anchor_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 **CSS 选择器片段锚点 (CSS Selector Fragment Anchor)** 功能。

**核心功能：**

该文件包含了一系列单元测试，旨在验证 Blink 引擎在处理带有 CSS 选择器片段的 URL 时是否能够正确地识别并高亮显示目标 HTML 元素。  当用户访问一个包含特定格式的 URL 片段（hash 部分）时，浏览器应该能够根据 CSS 选择器找到对应的元素，并将其设置为 CSS 目标，通常会通过添加一个视觉上的突出显示（例如，外边框）来告知用户。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **HTML:** 该测试文件的核心是验证对 HTML 元素的选择和操作。所有的测试用例都会加载包含特定 HTML 结构的页面，然后断言是否正确地找到了目标元素。

   * **例子:** 在 `BasicTest` 用例中，HTML 代码包含一个 `<img>` 元素：
     ```html
     <!DOCTYPE html>
     <img id="image" src="image.svg">
     ```
     测试会验证当 URL 片段为 `#:~:selector(type=CssSelector,value=img[src$="image.svg"])` 时，这个 `<img>` 元素是否被正确识别为 CSS 目标。

2. **CSS:**  该功能的核心就是使用 CSS 选择器来定位元素。测试会验证对各种 CSS 选择器的支持，并检查目标元素是否应用了相应的样式（通常是外边框）。

   * **例子:** `BasicTest` 用例中的 URL 片段 `value=img[src$="image.svg"]`  使用了属性选择器 `[src$="image.svg"]` 来匹配 `src` 属性以 "image.svg" 结尾的 `<img>` 元素。测试会检查这个元素是否被设置为 CSS 目标，并且通常会有一个外边框（尽管测试代码本身侧重于 CSS 目标是否正确，而不是直接检查外边框的 CSS 值，但 `IsElementOutlined` 方法就是用于检查外边框）。

3. **JavaScript:** 虽然这个测试文件本身是 C++ 代码，用于测试 Blink 引擎的内部行为，但 CSS 选择器片段锚点功能会影响 JavaScript 的行为。一旦页面加载完成并找到了 CSS 目标，JavaScript 可以通过 `document.cssTarget` 属性来访问这个目标元素。

   * **例子 (假设的 JavaScript 使用):**  如果页面加载时 URL 包含 CSS 选择器片段，JavaScript 代码可以这样做：
     ```javascript
     window.addEventListener('load', () => {
       const targetElement = document.cssTarget;
       if (targetElement) {
         console.log('CSS target element found:', targetElement);
         // 可以对目标元素执行进一步的操作，例如滚动到该元素
         targetElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
       }
     });
     ```

**逻辑推理 (假设输入与输出):**

* **假设输入 URL:** `https://example.com/page.html#:~:selector(type=CssSelector,value=.my-class)`
* **假设 HTML 内容:**
  ```html
  <!DOCTYPE html>
  <div class="my-class">This is the target.</div>
  <div>Not the target.</div>
  ```
* **逻辑推理:**  Blink 引擎会解析 URL 片段，提取出 CSS 选择器 `.my-class`。然后，它会在 HTML 文档中查找匹配该选择器的元素。
* **预期输出:**  名称为 "This is the target." 的 `<div>` 元素会被识别为 CSS 目标，并且通常会应用一个外边框来突出显示。`GetDocument().CssTarget()` 方法应该返回该元素的引用。

* **假设输入 URL:** `https://example.com/another.html#:~:selector(type=CssSelector,value=#nonexistent)`
* **假设 HTML 内容:**
  ```html
  <!DOCTYPE html>
  <p>Some text.</p>
  ```
* **逻辑推理:** Blink 引擎会尝试查找 ID 为 "nonexistent" 的元素。
* **预期输出:** 由于 HTML 中不存在该 ID 的元素，所以不会找到 CSS 目标。`GetDocument().CssTarget()` 方法应该返回 `nullptr`。

**用户或编程常见的使用错误:**

1. **错误的 CSS 选择器语法:**  用户在 URL 中提供的 CSS 选择器可能存在语法错误，导致引擎无法正确解析。

   * **例子:** `#:~:selector(type=CssSelector,value=img[src=image.svg])`  (缺少引号) 或 `#:~:selector(type=CssSelector,value= .my-class)` (选择器前有空格)。
   * **结果:**  引擎可能无法找到匹配的元素，或者完全无法解析片段。

2. **选择器匹配到多个元素 (期望单个):**  CSS 选择器可能会匹配到多个元素，但 CSS 选择器片段锚点通常只会选择第一个匹配的元素作为目标。用户可能期望所有匹配的元素都被高亮，但实际并非如此。

   * **例子:** URL: `#:~:selector(type=CssSelector,value=p)`，HTML 中有多个 `<p>` 元素。
   * **结果:**  只有文档中第一个 `<p>` 元素会被设置为 CSS 目标。

3. **URL 编码问题:**  CSS 选择器中的特殊字符需要进行 URL 编码。如果编码不正确，引擎可能无法正确解析选择器。

   * **例子:**  如果选择器包含逗号 `.`，例如 `div.my,class`，则逗号需要被编码为 `%2C`。错误的 URL 可能导致解析失败。  测试用例 `ValuePartHasCommaButIsNotEncoded` 就是测试这种情况。

4. **对 CSS 选择器能力的误解:**  用户可能认为可以使用非常复杂的 CSS 选择器，例如包含伪类或伪元素的，但该功能可能存在对选择器类型的限制 (尽管测试中似乎没有明确限制)。

5. **与 JavaScript 交互时的时序问题:**  JavaScript 代码可能在页面完全加载和 CSS 目标被设置之前运行，导致 `document.cssTarget` 为空。开发者需要确保在合适的时机访问 `document.cssTarget`。

总而言之，`css_selector_fragment_anchor_test.cc` 文件通过各种测试用例，确保了 Blink 引擎能够可靠地解析和应用 CSS 选择器片段锚点功能，从而实现通过 URL 片段精确定位和突出显示网页中的元素。这对于改善用户体验，特别是当通过链接分享页面特定内容时非常重要。

Prompt: 
```
这是目录为blink/renderer/core/fragment_directive/css_selector_fragment_anchor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/element_fragment_anchor.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

using test::RunPendingTasks;

class CssSelectorFragmentAnchorTest : public SimTest {
 public:
  void SetUp() override {
    SimTest::SetUp();

    // Focus handlers aren't run unless the page is focused.
    GetDocument().GetPage()->GetFocusController().SetActive(true);
    GetDocument().GetPage()->GetFocusController().SetFocused(true);

    WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  }

  ScrollableArea* LayoutViewport() {
    return GetDocument().View()->LayoutViewport();
  }

  gfx::Rect ViewportRect() {
    return gfx::Rect(LayoutViewport()->VisibleContentRect().size());
  }

  gfx::Rect BoundingRectInFrame(Node& node) {
    return node.GetLayoutObject()->AbsoluteBoundingBoxRect();
  }

  void SimulateClick(int x, int y) {
    WebMouseEvent event(WebInputEvent::Type::kMouseDown, gfx::PointF(x, y),
                        gfx::PointF(x, y), WebPointerProperties::Button::kLeft,
                        0, WebInputEvent::Modifiers::kLeftButtonDown,
                        base::TimeTicks::Now());
    event.SetFrameScale(1);
    WebView().MainFrameWidget()->ProcessInputEventSynchronouslyForTesting(
        WebCoalescedInputEvent(event, ui::LatencyInfo()));
  }

  bool IsVisibleInViewport(Element& element) {
    return ViewportRect().Contains(BoundingRectInFrame(element));
  }

  bool IsSelectorFragmentAnchorCreated() {
    return GetDocument().View()->GetFragmentAnchor() &&
           GetDocument()
               .View()
               ->GetFragmentAnchor()
               ->IsSelectorFragmentAnchor();
  }

  const CSSValue* GetComputedValue(const CSSPropertyID& property_id,
                                   const Element& element) {
    return CSSProperty::Get(property_id)
        .CSSValueFromComputedStyle(
            element.ComputedStyleRef(), nullptr /* layout_object */,
            false /* allow_visited_style */, CSSValuePhase::kComputedValue);
  }

  bool IsElementOutlined(const Element& element) {
    const CSSValue* value =
        GetComputedValue(CSSPropertyID::kOutlineWidth, element);
    return "0px" != value->CssText();
  }

  const String CircleSVG() {
    return R"SVG(
      <svg id="svg" width="200" height="200" xmlns="http://www.w3.org/2000/svg">
         <circle class="path" cx="100" cy="100" r="100" fill="red"/>
      </svg>
    )SVG";
  }
};

// Make sure we find the element and set it as the CSS target.
TEST_F(CssSelectorFragmentAnchorTest, BasicTest) {
  SimRequest main_request(
      "https://example.com/"
      "test.html#:~:selector(type=CssSelector,value=img[src$=\"image.svg\"])",
      "text/html");
  SimRequest image_request("https://example.com/image.svg", "image/svg+xml");

  LoadURL(
      "https://example.com/"
      "test.html#:~:selector(type=CssSelector,value=img[src$=\"image.svg\"])");

  // main frame widget size is 800x600
  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <img id="image" src="image.svg">
    )HTML");

  image_request.Complete(CircleSVG());

  test::RunPendingTasks();
  Compositor().BeginFrame();

  Element& img = *GetDocument().getElementById(AtomicString("image"));

  EXPECT_EQ(img, *GetDocument().CssTarget());
  EXPECT_EQ(true, IsSelectorFragmentAnchorCreated());
}

// When more than one CssSelector Fragments are present, set the first one as
// the CSS target (which will be outlined accordingly)
TEST_F(CssSelectorFragmentAnchorTest, TwoCssSelectorFragmentsOutlineFirst) {
  SimRequest main_request(
      "https://example.com/test.html"
      "#:~:selector(type=CssSelector,value=img[src$=\"second.svg\"])"
      "&selector(type=CssSelector,value=img[src$=\"first.svg\"])",
      "text/html");
  SimRequest first_img_request("https://example.com/first.svg",
                               "image/svg+xml");
  SimRequest second_img_request("https://example.com/second.svg",
                                "image/svg+xml");

  LoadURL(
      "https://example.com/test.html"
      "#:~:selector(type=CssSelector,value=img[src$=\"second.svg\"])"
      "&selector(type=CssSelector,value=img[src$=\"first.svg\"])");

  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <img id="first" src="first.svg">
      <img id="second" src="second.svg">
    )HTML");

  first_img_request.Complete(CircleSVG());
  second_img_request.Complete(CircleSVG());

  test::RunPendingTasks();
  Compositor().BeginFrame();

  Element& second = *GetDocument().getElementById(AtomicString("second"));

  EXPECT_EQ(second, *GetDocument().CssTarget());
  EXPECT_EQ(true, IsSelectorFragmentAnchorCreated());
}

// If the first CssSelector Fragment is not found, look for the second one
// and set that as the CSS target
TEST_F(CssSelectorFragmentAnchorTest, TwoCssSelectorFragmentsFirstNotFound) {
  SimRequest main_request(
      "https://example.com/test.html"
      "#:~:selector(type=CssSelector,value=img[src$=\"penguin.svg\"])"
      "&selector(type=CssSelector,value=img[src$=\"first.svg\"])",
      "text/html");
  SimRequest image_request("https://example.com/first.svg", "image/svg+xml");

  LoadURL(
      "https://example.com/test.html"
      "#:~:selector(type=CssSelector,value=img[src$=\"penguin.svg\"])"
      "&selector(type=CssSelector,value=img[src$=\"first.svg\"])");

  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <img id="first" src="first.svg">
    )HTML");

  image_request.Complete(CircleSVG());

  test::RunPendingTasks();
  Compositor().BeginFrame();

  Element& first = *GetDocument().getElementById(AtomicString("first"));

  EXPECT_EQ(first, *GetDocument().CssTarget());
  EXPECT_EQ(true, IsSelectorFragmentAnchorCreated());
}

// If both CssSelectorFragment and ElementFragment present,
// prioritize CssSelectorFragment
TEST_F(CssSelectorFragmentAnchorTest,
       PrioritizeCssSelectorFragmentOverElementFragment) {
  SimRequest main_request(
      "https://example.com/test.html#element"
      ":~:selector(type=CssSelector,value=img[src$=\"first.svg\"])",
      "text/html");
  SimRequest image_request("https://example.com/first.svg", "image/svg+xml");

  LoadURL(
      "https://example.com/test.html#element"
      ":~:selector(type=CssSelector,value=img[src$=\"first.svg\"])");

  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <p id="element">the element!</p>
      <img id="first" src="first.svg">
    )HTML");

  image_request.Complete(CircleSVG());

  test::RunPendingTasks();
  Compositor().BeginFrame();

  Element& first = *GetDocument().getElementById(AtomicString("first"));

  EXPECT_EQ(first, *GetDocument().CssTarget());
  EXPECT_EQ(true, IsSelectorFragmentAnchorCreated());
}

// TODO(crbug/1253707): Enable after fixing!
// Don't do anything if attribute selector is not allowed according to spec
// https://github.com/WICG/scroll-to-text-fragment/blob/main/EXTENSIONS.md#proposed-solution
TEST_F(CssSelectorFragmentAnchorTest, DISABLED_CheckCssSelectorRestrictions) {
  SimRequest main_request(
      "https://example.com/test.html"
      "#:~:selector(type=CssSelector,value=div[id$=\"first\"])",
      "text/html");

  LoadURL(
      "https://example.com/test.html"
      "#:~:selector(type=CssSelector,value=div[id$=\"first\"])");

  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <div id="first">some other text</p>
    )HTML");

  test::RunPendingTasks();
  Compositor().BeginFrame();

  EXPECT_EQ(nullptr, *GetDocument().CssTarget());
  EXPECT_EQ(nullptr, GetDocument().View()->GetFragmentAnchor());
  EXPECT_EQ("https://example.com/test.html", GetDocument().Url());
}

// Make sure fragment is not dismissed after user clicks
TEST_F(CssSelectorFragmentAnchorTest, FragmentStaysAfterUserClicks) {
  SimRequest main_request(
      "https://example.com/"
      "test.html#:~:selector(type=CssSelector,value=img[src$=\"image.svg\"])",
      "text/html");
  SimRequest image_request("https://example.com/image.svg", "image/svg+xml");

  LoadURL(
      "https://example.com/"
      "test.html#:~:selector(type=CssSelector,value=img[src$=\"image.svg\"])");

  // main frame widget size is 800x600
  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <img id="image" src="image.svg">
    )HTML");

  image_request.Complete(CircleSVG());

  test::RunPendingTasks();
  Compositor().BeginFrame();

  KURL expected_url = GetDocument()
                          .GetFrame()
                          ->Loader()
                          .GetDocumentLoader()
                          ->GetHistoryItem()
                          ->Url();

  Element& img = *GetDocument().getElementById(AtomicString("image"));
  EXPECT_EQ(img, *GetDocument().CssTarget());
  EXPECT_EQ(true, IsSelectorFragmentAnchorCreated());

  SimulateClick(100, 100);

  EXPECT_TRUE(GetDocument().View()->GetFragmentAnchor());

  KURL url = GetDocument()
                 .GetFrame()
                 ->Loader()
                 .GetDocumentLoader()
                 ->GetHistoryItem()
                 ->Url();

  EXPECT_EQ(expected_url, url);
}

// Although parsed correctly, the element is not found, hence no CSS target
// should be set
TEST_F(CssSelectorFragmentAnchorTest, ParsedCorrectlyButElementNotFound) {
  SimRequest main_request(
      "https://example.com/test.html"
      "#:~:selector(type=CssSelector,value=img[src$=\"lorem.svg\"])",
      "text/html");

  LoadURL(
      "https://example.com/test.html"
      "#:~:selector(type=CssSelector,value=img[src$=\"lorem.svg\"])");

  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <p>some text</p>
    )HTML");

  test::RunPendingTasks();
  Compositor().BeginFrame();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_EQ(nullptr, GetDocument().View()->GetFragmentAnchor());
}

// value= part should be encoded/decoded
TEST_F(CssSelectorFragmentAnchorTest, ValuePartHasCommaAndIsEncoded) {
  SimRequest main_request(
      "https://example.com/test.html"
      //      "#:~:selector(value=img[src$="cat,dog"],type=CssSelector)",
      "#:~:selector(value=img%5Bsrc%24%3D%22cat%2Cdog%22%5D,type=CssSelector)",
      "text/html");
  SimRequest img_request("https://example.com/cat,dog", "image/svg+xml");

  LoadURL(
      "https://example.com/test.html"
      "#:~:selector(value=img%5Bsrc%24%3D%22cat%2Cdog%22%5D,type=CssSelector)");

  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <img id="first" src="cat,dog">
    )HTML");

  img_request.Complete(CircleSVG());

  test::RunPendingTasks();
  Compositor().BeginFrame();

  Element& first = *GetDocument().getElementById(AtomicString("first"));

  EXPECT_EQ(first, *GetDocument().CssTarget());
  EXPECT_EQ(true, IsSelectorFragmentAnchorCreated());
}

// What if value= part is not encoded, and it contains a comma,
// Should not crash and no CSS target should be set
TEST_F(CssSelectorFragmentAnchorTest, ValuePartHasCommaButIsNotEncoded) {
  SimRequest main_request(
      "https://example.com/test.html"
      "#:~:selector(value=img[src$=\"cat,dog\"],type=CssSelector)",
      "text/html");
  SimRequest img_request("https://example.com/cat,dog", "image/svg+xml");

  LoadURL(
      "https://example.com/test.html"
      "#:~:selector(value=img[src$=\"cat,dog\"],type=CssSelector)");

  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <img id="first" src="cat,dog">
    )HTML");

  img_request.Complete(CircleSVG());

  test::RunPendingTasks();
  Compositor().BeginFrame();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_EQ(nullptr, GetDocument().View()->GetFragmentAnchor());
}

TEST_F(CssSelectorFragmentAnchorTest,
       TargetElementIsNotHighlightedWithElementFragment) {
  SimRequest main_request("https://example.com/test.html#image", "text/html");
  SimRequest image_request("https://example.com/image.svg", "image/svg+xml");

  LoadURL("https://example.com/test.html#image");

  // main frame widget size is 800x600
  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <img id="image" src="image.svg">
    )HTML");

  image_request.Complete(CircleSVG());

  test::RunPendingTasks();
  Compositor().BeginFrame();

  Element& img = *GetDocument().getElementById(AtomicString("image"));

  EXPECT_FALSE(IsElementOutlined(img));
  EXPECT_EQ(img, *GetDocument().CssTarget());
}

TEST_F(CssSelectorFragmentAnchorTest,
       TargetElementIsNotHighlightedWithTextFragment) {
  SimRequest main_request("https://example.com/test.html#:~:text=some other",
                          "text/html");

  LoadURL("https://example.com/test.html#:~:text=some other");

  // main frame widget size is 800x600
  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <div id="element">some other text</div>
    )HTML");

  test::RunPendingTasks();

  Compositor().BeginFrame();

  Element& element = *GetDocument().getElementById(AtomicString("element"));

  EXPECT_FALSE(IsElementOutlined(element));
  EXPECT_EQ(element, *GetDocument().CssTarget());
}

// Simulate an anchor link navigation and check that the style is removed.
TEST_F(CssSelectorFragmentAnchorTest, SelectorFragmentTargetOutline) {
  SimRequest main_request(
      "https://example.com/test.html"
      "#:~:selector(type=CssSelector,value=img[src=\"image.svg\"])",
      "text/html");
  SimRequest image_request("https://example.com/image.svg", "image/svg+xml");

  LoadURL(
      "https://example.com/test.html"
      "#:~:selector(type=CssSelector,value=img[src=\"image.svg\"])");

  // main frame widget size is 800x600
  main_request.Complete(R"HTML(
      <!DOCTYPE html>
      <a id="element" href="#paragraph">Go to paragraph</a>
      <img id="image" src="image.svg">
      <p id="paragraph"></p>
    )HTML");

  image_request.Complete(CircleSVG());

  test::RunPendingTasks();
  Compositor().BeginFrame();

  Element& paragraph = *GetDocument().getElementById(AtomicString("paragraph"));
  Element& img = *GetDocument().getElementById(AtomicString("image"));

  EXPECT_TRUE(IsElementOutlined(img));
  EXPECT_EQ(img, *GetDocument().CssTarget());
  EXPECT_EQ(true, IsSelectorFragmentAnchorCreated());

  auto* anchor = To<HTMLAnchorElement>(
      GetDocument().getElementById(AtomicString("element")));
  anchor->click();

  EXPECT_FALSE(IsElementOutlined(img));
  EXPECT_EQ(paragraph, *GetDocument().CssTarget());
  EXPECT_EQ("https://example.com/test.html#paragraph", GetDocument().Url());
}

}  // namespace blink

"""

```