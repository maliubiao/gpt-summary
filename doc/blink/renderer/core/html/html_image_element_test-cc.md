Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for an explanation of the `html_image_element_test.cc` file, focusing on its functionality, relationship to web technologies, logical inferences, and common usage errors it might expose.

2. **Identify the Core Subject:** The filename `html_image_element_test.cc` immediately tells me this file contains tests for the `HTMLImageElement` class in the Blink rendering engine.

3. **Scan for Key Information:** I quickly scan the code for important elements:
    * **Includes:**  These reveal dependencies and what the tests interact with (`HTMLImageElement`, `Document`, `Settings`, `LocalFrameView`, etc.). The presence of `gtest/gtest.h` confirms it's a unit test file.
    * **Test Fixtures:** The `HTMLImageElementTest` and `HTMLImageElementSimTest` classes are test fixtures, setting up the environment for testing. The `PageTestBase` and `SimTest` base classes hint at different testing approaches (likely DOM manipulation and simulated network requests, respectively).
    * **Test Cases (using `TEST_F`):**  These are the individual tests, and their names are descriptive (`width`, `sourceSize`, `ImageAdRectangleUpdate`, `ResourceWidthWithPicture`, etc.). This gives me a high-level overview of what aspects of `HTMLImageElement` are being tested.
    * **Assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_NE`):** These are crucial for understanding the expected behavior being verified by each test.
    * **Setup and Helpers:** The `SetUp` method in `HTMLImageElementTest` and the custom `TestFrameClient` are important for understanding the test environment.
    * **Code manipulating the DOM:** The tests use methods like `setAttribute`, `SetBodyInnerHTML`, `GetElementById`, `appendChild`, `remove`, and directly manipulate `style`. This confirms interaction with HTML elements and their properties.
    * **JavaScript execution:** Some tests use `<script>` tags within the HTML to interact with the image element.
    * **Feature flags:** The use of `ScopedFeatureList` and checking of `WebFeature` suggests testing behavior under different browser configurations.

4. **Categorize Functionality Based on Tests:**  I group the functionalities based on the test names and their code:
    * **Attributes:** Testing the `width` and `sizes` attributes and their impact on resource width.
    * **Source Size Calculation:** Testing the `sourceSize` method.
    * **Image Ad Rectangle Reporting:**  Testing the mechanism for reporting the position and size of image ad elements using the `TestFrameClient`. This clearly connects to browser features for ad visibility and measurement.
    * **Resource Width with `<picture>`:**  Specific tests for how the `width` attribute interacts with the `<picture>` element.
    * **Shared Storage API:** Tests for the `sharedstoragewritable` attribute, including security context checks.
    * **Transparent Placeholder Images:** Tests related to `onload` events and `currentSrc` for data URI images, likely related to performance optimizations.
    * **Use Counters:** Tests checking if specific features (like `sizes="auto"`) are being tracked for usage statistics.

5. **Relate to Web Technologies:** I connect the observed functionalities to HTML, CSS, and JavaScript:
    * **HTML:** The tests directly manipulate HTML elements and attributes (`<img>`, `<picture>`, `width`, `src`, `sizes`, `loading`, `allow`).
    * **CSS:**  Tests use inline styles (`style`) to position and size the image, demonstrating the impact of CSS on the image element's rendering and reported geometry.
    * **JavaScript:**  JavaScript is used to dynamically modify the image element's attributes and styles, as well as to interact with the DOM (scrolling, adding/removing elements).

6. **Identify Logical Inferences (Input/Output):** For tests that involve a clear logical flow, I consider the input (e.g., setting attributes, initial HTML structure) and the expected output (e.g., assertion values, console messages, calls to the `TestFrameClient`). The "ImageAdRectangleUpdate" test is a good example where I can define scenarios and the expected sequence of `observed_image_ad_rects_`.

7. **Consider Common Usage Errors:** Based on the tested features, I think about potential developer mistakes:
    * **Incorrectly assuming `width` always sets `resourceWidth`:** The test highlights the nuance with `sizes` attribute.
    * **Not understanding how `sizes="auto"` works:** The use counter tests hint at the specific behavior and tracking of this value.
    * **Misusing the `sharedstoragewritable` attribute:** The security context check is a direct example of a potential error.
    * **Unexpected behavior with transparent placeholders:**  The tests on `onload` and `currentSrc` point to potential misunderstandings of how these images are handled.

8. **Structure the Answer:** I organize the information into clear sections: Functionality, Relationship to Web Technologies, Logical Inferences, and Common Usage Errors, as requested. I use bullet points and examples to make the explanation clear and easy to understand.

9. **Refine and Elaborate:** I review my initial thoughts and add more details and context where necessary. For example, when explaining the "ImageAdRectangleUpdate" test, I walk through the different stages of the test scenario.

By following these steps, I can systematically analyze the test file and generate a comprehensive and informative answer that addresses all aspects of the request.
这个文件 `html_image_element_test.cc` 是 Chromium Blink 引擎中专门用于测试 `HTMLImageElement` (HTML `<img>` 元素) 行为的 C++ 单元测试文件。它的主要功能是：

**1. 验证 `HTMLImageElement` 类的各种功能和属性是否按预期工作。** 这包括但不限于：

* **属性处理:** 测试 `width`, `height`, `sizes` 等属性的设置和获取，以及它们对图片资源加载的影响。
* **资源大小计算:** 测试在不同情况下，例如设置了 `width` 和 `sizes` 属性时，`HTMLImageElement` 如何计算其资源宽度 (`GetResourceWidth`) 和源大小 (`SourceSize`)。
* **图片广告区域更新:** 测试当 `<img>` 元素被标记为广告相关 (`SetIsAdRelated`) 时，其位置和大小变化是否能正确地通知到浏览器，这涉及到浏览器如何跟踪和处理广告。
* **与 `<picture>` 元素的交互:** 测试 `<img>` 元素在 `<picture>` 元素内部时的行为，例如资源宽度的计算。
* **Shared Storage API 集成:** 测试与 Shared Storage API 相关的属性 (`sharedstoragewritable`) 的行为，特别是安全上下文的限制。
* **透明占位符图片处理:** 测试对于使用 Data URI 的透明占位符图片，`onload` 事件和 `currentSrc` 属性是否按预期工作。
* **Use Counters (用户行为统计):** 测试某些 `<img>` 元素特性的使用情况是否被正确统计，例如 `sizes="auto"` 属性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接测试的是 `HTMLImageElement` 类的实现，而这个类是浏览器渲染 HTML 中 `<img>` 标签的核心。因此，它与 JavaScript, HTML, 和 CSS 的功能都有密切关系：

* **HTML:**
    * **功能:**  测试文件通过模拟创建和操作 `<img>` 元素 (例如使用 `SetBodyInnerHTML` 来创建带有特定属性的 `<img>` 标签) 来验证 `HTMLImageElement` 的行为。
    * **举例:**
        ```html
        <img id="target" width="400" sizes="100vw">
        ```
        测试文件会创建这样一个 `<img>` 元素，然后验证 `image->GetResourceWidth()` 是否返回预期值 (在这个例子中是视口宽度)。

* **CSS:**
    * **功能:** 测试文件通过设置 `<img>` 元素的 `style` 属性来影响其布局和尺寸，并验证这些变化是否能正确地反映在图片广告区域的通知中。
    * **举例:**
        ```javascript
        image.style.width = '10px';
        image.style.height = '10px';
        ```
        测试会设置 `<img>` 元素的宽度和高度，然后检查 `test_frame_client_->observed_image_ad_rects()` 中记录的矩形是否与设置的尺寸相符。

* **JavaScript:**
    * **功能:**  测试文件使用 JavaScript 代码来动态地修改 `<img>` 元素的属性和样式，并验证 `HTMLImageElement` 的行为是否符合预期。
    * **举例:**
        ```javascript
        var image = document.getElementById('target');
        image.setAttribute('loading', 'lazy');
        ```
        虽然这个例子在给出的代码中没有直接体现，但测试 lazy loading 的相关行为会涉及到通过 JavaScript 设置 `loading` 属性。在 `ImageAdRectangleUpdate` 测试中，JavaScript 被用来动态改变 `<img>` 元素的 `style` 属性。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个 `<img>` 元素，其 `width` 属性设置为 "400"，`sizes` 属性设置为 "100vw"。当前视口宽度为 500px。
* **预期输出:** `image->GetResourceWidth()` 应该返回 500。

* **假设输入 (ImageAdRectangleUpdate):**  一个绝对定位的 `<img>` 元素，初始位置为 (5, 5)，大小为 10x10，并且调用了 `SetIsAdRelated()`。
* **预期输出:**  `test_frame_client_->observed_image_ad_rects()` 将会包含一个元素，其 `DOMNodeId` 与该 `<img>` 元素匹配，`gfx::Rect` 为 (5, 5, 10, 10)。 如果之后通过 JavaScript 将其大小修改为 30x30，则 `observed_image_ad_rects()` 将新增一个记录，其 `gfx::Rect` 为 (5, 5, 30, 30)。如果元素被移除，则会新增一个 `gfx::Rect` 为空的记录。

**涉及用户或编程常见的使用错误:**

* **错误地认为 `width` 属性总是能直接决定资源宽度:**  测试用例 `width` 演示了，在没有 `sizes` 属性时，`width` 属性不会直接影响 `GetResourceWidth()` 的返回值。开发者可能会错误地认为设置了 `width` 就会加载特定尺寸的图片，但实际上浏览器可能根据其他因素 (例如 `sizes` 属性) 来决定最终加载的资源。
* **不理解 `sizes` 属性的作用:**  测试用例 `sourceSize` 和 `width` 验证了 `sizes` 属性如何影响图片的源大小和资源宽度。开发者如果对 `sizes` 属性的用法不熟悉，可能会导致图片在不同视口下显示不正确。
* **在不安全上下文中使用 `sharedstoragewritable` 属性:**  测试用例 `Sharedstoragewritable_InsecureContext_NotAllowed` 明确指出，`sharedstoragewritable` 属性只能在安全上下文 (HTTPS) 中使用。开发者如果在 HTTP 页面上使用这个属性，会导致错误。
* **对透明占位符图片的 `onload` 事件行为的误解:**  测试用例 `OnloadTransparentPlaceholderImage` 验证了即使是 Data URI 的透明图片也会触发 `onload` 事件。开发者可能会错误地认为这种类型的图片不会触发 `onload`，从而导致代码逻辑错误。
* **不了解 `sizes="auto"` 的行为和浏览器支持:** 测试用例 `AutoSizesUseCounters*` 表明浏览器正在跟踪 `sizes="auto"` 的使用情况。开发者需要了解这个属性的具体行为以及浏览器的支持情况。

总而言之，`html_image_element_test.cc` 是一个至关重要的测试文件，它确保了 Chromium 引擎中 `<img>` 元素的实现符合 Web 标准和预期行为，并有助于发现和防止与 HTML, CSS 和 JavaScript 相关的常见使用错误。

### 提示词
```
这是目录为blink/renderer/core/html/html_image_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/html_image_element.h"

#include <memory>

#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

class TestFrameClient : public EmptyLocalFrameClient {
 public:
  void OnMainFrameImageAdRectangleChanged(
      DOMNodeId element_id,
      const gfx::Rect& image_ad_rect) override {
    observed_image_ad_rects_.emplace_back(element_id, image_ad_rect);
  }

  const std::vector<std::pair<DOMNodeId, gfx::Rect>>& observed_image_ad_rects()
      const {
    return observed_image_ad_rects_;
  }

 private:
  std::vector<std::pair<DOMNodeId, gfx::Rect>> observed_image_ad_rects_;
};

}  // namespace

class HTMLImageElementTest : public PageTestBase {
 protected:
  static constexpr int kViewportWidth = 500;
  static constexpr int kViewportHeight = 600;

  void SetUp() override {
    test_frame_client_ = MakeGarbageCollected<TestFrameClient>();

    PageTestBase::SetupPageWithClients(
        nullptr, test_frame_client_.Get(), nullptr,
        gfx::Size(kViewportWidth, kViewportHeight));
  }

  Persistent<TestFrameClient> test_frame_client_;
};

// Instantiate class constants. Not needed after C++17.
constexpr int HTMLImageElementTest::kViewportWidth;
constexpr int HTMLImageElementTest::kViewportHeight;

TEST_F(HTMLImageElementTest, width) {
  auto* image = MakeGarbageCollected<HTMLImageElement>(GetDocument());
  image->setAttribute(html_names::kWidthAttr, AtomicString("400"));
  // TODO(yoav): `width` does not impact resourceWidth until we resolve
  // https://github.com/ResponsiveImagesCG/picture-element/issues/268
  EXPECT_EQ(std::nullopt, image->GetResourceWidth());
  image->setAttribute(html_names::kSizesAttr, AtomicString("100vw"));
  EXPECT_EQ(500, image->GetResourceWidth());
}

TEST_F(HTMLImageElementTest, sourceSize) {
  auto* image = MakeGarbageCollected<HTMLImageElement>(GetDocument());
  image->setAttribute(html_names::kWidthAttr, AtomicString("400"));
  EXPECT_EQ(kViewportWidth, image->SourceSize(*image));
  image->setAttribute(html_names::kSizesAttr, AtomicString("50vw"));
  EXPECT_EQ(250, image->SourceSize(*image));
}

TEST_F(HTMLImageElementTest, ImageAdRectangleUpdate) {
  GetDocument().GetSettings()->SetScriptEnabled(true);

  SetBodyInnerHTML(R"HTML(
    <img id="target"
         style="position:absolute;top:5px;left:5px;width:10px;height:10px;">
    </img>

    <p style="position:absolute;top:10000px;">abc</p>
  )HTML");

  HTMLImageElement* image = To<HTMLImageElement>(GetElementById("target"));
  image->SetIsAdRelated();

  EXPECT_TRUE(test_frame_client_->observed_image_ad_rects().empty());

  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(test_frame_client_->observed_image_ad_rects().size(), 1u);
  DOMNodeId id = test_frame_client_->observed_image_ad_rects()[0].first;
  EXPECT_EQ(test_frame_client_->observed_image_ad_rects()[0].second,
            gfx::Rect(5, 5, 10, 10));

  // Scrolling won't trigger another notification, as the rectangle hasn't
  // changed relative to the page.
  {
    auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
    script->setTextContent(R"JS(
      window.scroll(0, 100);
    )JS");
    GetDocument().body()->appendChild(script);
    UpdateAllLifecyclePhasesForTest();
  }

  EXPECT_EQ(test_frame_client_->observed_image_ad_rects().size(), 1u);

  // Update the size to 1x1. A new notification is expected to signal the
  // removal of the element.
  {
    auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
    script->setTextContent(R"JS(
      var image = document.getElementById('target');
      image.style.width = '1px';
      image.style.height = '1px';
    )JS");
    GetDocument().body()->appendChild(script);
    UpdateAllLifecyclePhasesForTest();
  }

  EXPECT_EQ(test_frame_client_->observed_image_ad_rects().size(), 2u);
  EXPECT_EQ(test_frame_client_->observed_image_ad_rects()[1].first, id);
  EXPECT_EQ(test_frame_client_->observed_image_ad_rects()[1].second,
            gfx::Rect());

  // Update the size to 30x30. A new notification is expected to signal the new
  // rectangle.
  {
    auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
    script->setTextContent(R"JS(
      var image = document.getElementById('target');
      image.style.width = '30px';
      image.style.height = '30px';
    )JS");
    GetDocument().body()->appendChild(script);
    UpdateAllLifecyclePhasesForTest();
  }

  EXPECT_EQ(test_frame_client_->observed_image_ad_rects().size(), 3u);
  EXPECT_EQ(test_frame_client_->observed_image_ad_rects()[2].first, id);
  EXPECT_EQ(test_frame_client_->observed_image_ad_rects()[2].second,
            gfx::Rect(5, 5, 30, 30));

  // Remove the element. A new notification is expected to signal the removal of
  // the element.
  {
    auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
    script->setTextContent(R"JS(
      var image = document.getElementById('target');
      image.remove()
    )JS");
    GetDocument().body()->appendChild(script);
    UpdateAllLifecyclePhasesForTest();
  }

  EXPECT_EQ(test_frame_client_->observed_image_ad_rects().size(), 4u);
  EXPECT_EQ(test_frame_client_->observed_image_ad_rects()[3].first, id);
  EXPECT_EQ(test_frame_client_->observed_image_ad_rects()[3].second,
            gfx::Rect());
}

TEST_F(HTMLImageElementTest, ResourceWidthWithPicture) {
  SetBodyInnerHTML(R"HTML(
    <picture>
      <source srcset="a.png" sizes="auto"/>
      <img id="i" width="5" height="5" src="b.png" loading="lazy" sizes="auto"/>
    </picture>
  )HTML");

  HTMLImageElement* image = To<HTMLImageElement>(GetElementById("i"));
  ASSERT_NE(image, nullptr);
  EXPECT_EQ(*image->GetResourceWidth(), 5);
}

TEST_F(HTMLImageElementTest, ResourceWidthWithPictureContainingScripts) {
  SetBodyInnerHTML(R"HTML(
    <picture>
      <source srcset="a.png" sizes="auto"/>
      <script></script>
      <img id="i" width="5" height="5" src="b.png" loading="lazy" sizes="auto"/>
      <script></script>
    </picture>
  )HTML");

  HTMLImageElement* image = To<HTMLImageElement>(GetElementById("i"));
  ASSERT_NE(image, nullptr);
  EXPECT_EQ(*image->GetResourceWidth(), 5);
}

using HTMLImageElementSimTest = SimTest;

TEST_F(HTMLImageElementSimTest, Sharedstoragewritable_SecureContext_Allowed) {
  WebRuntimeFeaturesBase::EnableSharedStorageAPI(true);
  WebRuntimeFeaturesBase::EnableSharedStorageAPIM118(true);
  SimRequest main_resource("https://example.com/index.html", "text/html");
  SimSubresourceRequest image_resource("https://example.com/foo.png",
                                       "image/png");
  LoadURL("https://example.com/index.html");
  main_resource.Complete(R"(
    <img src="foo.png" id="target"
      allow="shared-storage"
      sharedstoragewritable></img>
  )");

  image_resource.Complete("image data");
  EXPECT_TRUE(ConsoleMessages().empty());
}

TEST_F(HTMLImageElementSimTest,
       Sharedstoragewritable_InsecureContext_NotAllowed) {
  WebRuntimeFeaturesBase::EnableSharedStorageAPI(true);
  WebRuntimeFeaturesBase::EnableSharedStorageAPIM118(true);
  SimRequest main_resource("http://example.com/index.html", "text/html");
  SimSubresourceRequest image_resource("http://example.com/foo.png",
                                       "image/png");
  LoadURL("http://example.com/index.html");
  main_resource.Complete(R"(
    <img src="foo.png" id="target"
      allow="shared-storage"
      sharedstoragewritable></img>
  )");

  image_resource.Complete("image data");
  EXPECT_EQ(ConsoleMessages().size(), 1u);
  EXPECT_TRUE(ConsoleMessages().front().StartsWith(
      "sharedStorageWritable: sharedStorage operations are only available in "
      "secure contexts."))
      << "Expect error that Shared Storage operations are not allowed in "
         "insecure contexts but got: "
      << ConsoleMessages().front();
}

class TransparentPlaceholderImageSimTest
    : public SimTest,
      public ::testing::WithParamInterface<bool> {
 protected:
  void SetUp() override {
    SimTest::SetUp();
    if (GetParam()) {
      feature_list_.InitAndEnableFeature(
          features::kSimplifyLoadingTransparentPlaceholderImage);
    } else {
      feature_list_.InitAndDisableFeature(
          features::kSimplifyLoadingTransparentPlaceholderImage);
    }
  }

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(TransparentPlaceholderImageSimTest,
                         TransparentPlaceholderImageSimTest,
                         testing::Bool());

TEST_P(TransparentPlaceholderImageSimTest, OnloadTransparentPlaceholderImage) {
  SimRequest main_resource("http://example.com/index.html", "text/html");
  LoadURL("http://example.com/index.html");
  main_resource.Complete(R"(
    <body onload='console.log("main body onload");'>
      <img src="data:image/gif;base64,R0lGODlhAQABAIAAAP///////yH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="
           onload='console.log("image element onload");'>
    </body>)");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // Ensure that both body and image are successfully loaded.
  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("image element onload"));
}

TEST_P(TransparentPlaceholderImageSimTest,
       CurrentSrcForTransparentPlaceholderImage) {
  const String image_source =
      "data:image/gif;base64,R0lGODlhAQABAIAAAP///////"
      "yH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==";

  SimRequest main_resource("http://example.com/index.html", "text/html");
  LoadURL("http://example.com/index.html");
  main_resource.Complete(R"(
    <img id="myimg" src=)" +
                         image_source + R"(>
    <script>
      console.log(myimg.currentSrc);
    </script>)");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // Ensure that currentSrc is correctly set as the image source.
  EXPECT_TRUE(ConsoleMessages().Contains(image_source));
}

class HTMLImageElementUseCounterTest : public HTMLImageElementTest {
 protected:
  bool IsCounted(WebFeature feature) {
    return GetDocument().IsUseCounted(feature);
  }
};

TEST_F(HTMLImageElementUseCounterTest, AutoSizesUseCountersNoSizes) {
  SetBodyInnerHTML(R"HTML(
    <img id="target"
         loading="lazy">
    </img>
  )HTML");

  HTMLImageElement* image = To<HTMLImageElement>(GetElementById("target"));
  ASSERT_NE(image, nullptr);

  EXPECT_FALSE(IsCounted(WebFeature::kAutoSizesLazy));
  EXPECT_FALSE(IsCounted(WebFeature::kAutoSizesNonLazy));
}

TEST_F(HTMLImageElementUseCounterTest, AutoSizesUseCountersNonAutoSizes) {
  SetBodyInnerHTML(R"HTML(
    <img id="target"
         sizes = "33px"
         loading="lazy">
    </img>
  )HTML");

  HTMLImageElement* image = To<HTMLImageElement>(GetElementById("target"));
  ASSERT_NE(image, nullptr);

  EXPECT_FALSE(IsCounted(WebFeature::kAutoSizesLazy));
  EXPECT_FALSE(IsCounted(WebFeature::kAutoSizesNonLazy));
}

TEST_F(HTMLImageElementUseCounterTest, AutoSizesNonLazyUseCounter) {
  SetBodyInnerHTML(R"HTML(
    <img id="target"
         sizes="auto">
    </img>
  )HTML");

  HTMLImageElement* image = To<HTMLImageElement>(GetElementById("target"));
  ASSERT_NE(image, nullptr);

  EXPECT_FALSE(IsCounted(WebFeature::kAutoSizesLazy));
  EXPECT_TRUE(IsCounted(WebFeature::kAutoSizesNonLazy));
}

TEST_F(HTMLImageElementUseCounterTest, AutoSizesLazyUseCounter) {
  SetBodyInnerHTML(R"HTML(
    <img id="target"
         sizes="auto"
         loading="lazy">
    </img>
  )HTML");

  HTMLImageElement* image = To<HTMLImageElement>(GetElementById("target"));
  ASSERT_NE(image, nullptr);

  EXPECT_TRUE(IsCounted(WebFeature::kAutoSizesLazy));
  EXPECT_FALSE(IsCounted(WebFeature::kAutoSizesNonLazy));
}

}  // namespace blink
```