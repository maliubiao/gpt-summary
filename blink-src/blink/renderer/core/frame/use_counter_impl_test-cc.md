Response:
The user is asking for an analysis of the C++ source code file `blink/renderer/core/frame/use_counter_impl_test.cc`. I need to identify its purpose, its relationship with web technologies (JavaScript, HTML, CSS), and provide examples of logical reasoning, potential user/programming errors, if applicable.

**Plan:**

1. Identify the main purpose of the file. It seems to be a test file for `UseCounterImpl`.
2. Analyze the included headers to understand the functionalities being tested.
3. Examine the test cases and their assertions to determine what aspects of `UseCounterImpl` are being validated.
4. Identify connections to JavaScript, HTML, and CSS based on the tested functionalities and included headers.
5. If logical reasoning is involved in the tests, provide examples with assumed inputs and outputs.
6. If the tests highlight potential user or programming errors, illustrate them with examples.
这个文件 `blink/renderer/core/frame/use_counter_impl_test.cc` 是 Chromium Blink 引擎中 `UseCounterImpl` 类的单元测试文件。它的主要功能是 **验证 `UseCounterImpl` 类的各种功能是否按预期工作**。

`UseCounterImpl` 类的作用是 **记录浏览器引擎中各种 Web 功能的使用情况**，并将这些数据上报，用于统计和分析 Web 平台的演进和使用趋势。

**它与 javascript, html, css 的功能有关系，举例说明如下：**

`UseCounterImpl` 跟踪的功能很多都与 HTML、CSS 和 JavaScript 的使用直接相关。测试用例中通过创建 DOM 结构、设置 CSS 样式等方式来触发特定的 Web 功能，并验证 `UseCounterImpl` 是否正确记录了这些功能的使用。

**HTML 相关的例子：**

*   **测试 `HTMLRootContained` 和 `HTMLBodyContained` 功能：**
    ```c++
    TEST_F(UseCounterImplTest, HTMLRootContained) {
      // ...
      document.documentElement()->SetInlineStyleProperty(CSSPropertyID::kContain, "paint");
      // ...
      document.documentElement()->SetInlineStyleProperty(CSSPropertyID::kDisplay, "block");
      // ...
    }
    ```
    这个测试用例创建了一个 HTML 文档，并操作了 `<html>` 元素的 `contain` 和 `display` 样式属性。如果 `<html>` 元素同时设置了 `contain: paint` 并且 `display` 不是 `none`，那么 `UseCounterImpl` 应该记录 `kHTMLRootContained` 这个特性被使用了。这直接关系到 HTML 结构和 CSS 样式的应用。

**CSS 相关的例子：**

*   **测试 CSS 选择器伪类 (`:where`, `:is`, `:any-link` 等) 的使用：**
    ```c++
    TEST_F(UseCounterImplTest, CSSSelectorPseudoWhere) {
      // ...
      document.documentElement()->setInnerHTML(
          "<style>.a+:where(.b, .c+.d) { color: red; }</style>");
      // ...
    }
    ```
    这个测试用例在 HTML 中插入包含 CSS 规则的 `<style>` 标签，使用了 `:where` 伪类选择器。`UseCounterImpl` 应该记录 `kCSSSelectorPseudoWhere` 这个特性被使用了。
*   **测试 CSS 属性的使用 (例如 `background-clip`)：**
    ```c++
    TEST_F(UseCounterImplTest, BackgroundClip) {
      // ...
      document.documentElement()->setInnerHTML(
          "<style>html{background-clip: border-box;}</style>");
      // ...
    }
    ```
    这个测试用例验证了不同 `background-clip` 属性值是否被正确计数。

**虽然代码中没有直接的 JavaScript 代码，但 `UseCounterImpl` 的设计目的是为了跟踪所有可观察到的 Web 功能的使用，包括通过 JavaScript API 触发的功能。** 例如，虽然测试文件中没有直接写 JavaScript 代码，但如果某个 JavaScript API 的使用会导致特定的 CSS 样式被应用，或者触发了某个特定的浏览器行为，`UseCounterImpl` 也会记录下来。

**如果做了逻辑推理，请给出假设输入与输出:**

在这些测试用例中，逻辑推理主要体现在测试断言 (`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ` 等)。测试用例会设置特定的场景（输入），然后断言 `UseCounterImpl` 的行为（输出）是否符合预期。

**假设输入与输出的例子 (针对 `CSSSelectorPseudoWhere` 测试):**

*   **假设输入:**  HTML 文档中包含以下 `<style>` 标签：`<style>.a+:where(.b, .c+.d) { color: red; }</style>`
*   **预期输出:**  `document.IsUseCounted(WebFeature::kCSSSelectorPseudoWhere)` 返回 `true`，表示 `:where` 伪类选择器被使用。

*   **假设输入:** HTML 文档中不包含使用 `:where` 伪类选择器的 CSS 规则。
*   **预期输出:** `document.IsUseCounted(WebFeature::kCSSSelectorPseudoWhere)` 返回 `false`。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

虽然这个测试文件本身是用来验证代码正确性的，但通过分析测试用例，我们可以反推出一些用户或编程中可能出现的与 `UseCounterImpl` 记录的功能相关的错误：

1. **错误地假设某个 CSS 特性已被广泛支持:** 用户可能会使用较新的 CSS 特性，但没有考虑到某些老旧浏览器可能不支持，导致页面在这些浏览器上渲染异常。`UseCounterImpl` 的数据可以帮助开发者了解这些特性的使用情况，从而更好地权衡是否使用以及如何提供回退方案。

2. **过度依赖实验性或带有浏览器前缀的 CSS 特性:**  例如，在 `BackgroundClip` 的测试中，可以看到对 `-webkit-` 前缀的支持。开发者可能习惯使用带前缀的特性，但应该逐渐迁移到无前缀的标准特性。`UseCounterImpl` 可以跟踪这些带前缀特性的使用情况，提醒开发者进行更新。

    *   **用户/编程错误示例:**  开发者始终使用 `-webkit-background-clip: text;` 而没有使用标准的 `background-clip: text;`，导致页面在非 WebKit 内核的浏览器上可能无法正常显示文本背景裁剪效果。

3. **不小心使用了已被废弃的特性:** `UseCounterImpl` 也会记录已被废弃的特性的使用情况。开发者如果看到自己使用了这些特性，应该及时更新代码，避免未来版本移除这些特性导致的问题。

    *   **用户/编程错误示例:**  使用了某个已被标记为废弃的 JavaScript API，虽然当前版本还能正常工作，但在未来的 Chromium 版本中可能会被移除，导致代码失效。

4. **对某些 CSS 特性的理解偏差:**  例如，`CSSMarkerPseudoElementUA` 的测试表明，浏览器默认的列表标记样式不会被计数，只有开发者自定义的 `::marker` 样式才会被计数。如果开发者错误地认为所有列表标记的使用都会被记录，可能会对数据分析产生误解。

总而言之，`blink/renderer/core/frame/use_counter_impl_test.cc` 是一个重要的测试文件，它确保了 `UseCounterImpl` 能够准确地收集各种 Web 功能的使用数据，这些数据对于 Chromium 团队了解 Web 平台的使用情况、制定发展方向至关重要。理解这些测试用例也有助于开发者避免一些常见的 Web 开发错误。

Prompt: 
```
这是目录为blink/renderer/core/frame/use_counter_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/metrics/histogram_tester.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/scheme_registry.h"
#include "third_party/blink/public/mojom/use_counter/metrics/css_property_id.mojom-blink.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace {
const char kExtensionFeaturesHistogramName[] =
    "Blink.UseCounter.Extensions.Features";

const char kExtensionUrl[] = "chrome-extension://dummysite/";

int GetPageVisitsBucketforHistogram(const std::string& histogram_name) {
  if (histogram_name.find("CSS") == std::string::npos) {
    return static_cast<int>(blink::mojom::WebFeature::kPageVisits);
  }
  // For CSS histograms, the page visits bucket should be 1.
  return static_cast<int>(
      blink::mojom::blink::CSSSampleId::kTotalPagesMeasured);
}

}  // namespace

namespace blink {
using WebFeature = mojom::WebFeature;

class UseCounterImplTest : public testing::Test {
 public:
  class DummyLocalFrameClient : public EmptyLocalFrameClient {
   public:
    DummyLocalFrameClient() = default;
    const std::vector<UseCounterFeature>& observed_features() const {
      return observed_features_;
    }

   private:
    void DidObserveNewFeatureUsage(const UseCounterFeature& feature) override {
      observed_features_.push_back(feature);
    }
    std::vector<UseCounterFeature> observed_features_;
  };

  UseCounterImplTest()
      : dummy_(std::make_unique<DummyPageHolder>(
            /* initial_view_size= */ gfx::Size(),
            /* chrome_client= */ nullptr,
            /* local_frame_client= */
            MakeGarbageCollected<DummyLocalFrameClient>())) {
    Page::InsertOrdinaryPageForTesting(&dummy_->GetPage());
  }

  int ToSampleId(CSSPropertyID property) const {
    return static_cast<int>(GetCSSSampleId(property));
  }

  bool IsInternal(CSSPropertyID property) const {
    return CSSProperty::Get(property).IsInternal();
  }

  // Returns all alternative properties. In other words, a set of of all
  // properties marked with 'alternative_of' in css_properties.json5.
  //
  // This is useful for checking whether or not a given CSSPropertyID is an
  // an alternative property.
  HashSet<CSSPropertyID> GetAlternatives() const {
    HashSet<CSSPropertyID> alternatives;

    for (CSSPropertyID property : CSSPropertyIDList()) {
      if (CSSPropertyID alternative_id =
              CSSUnresolvedProperty::Get(property).GetAlternative();
          alternative_id != CSSPropertyID::kInvalid) {
        alternatives.insert(alternative_id);
      }
    }

    for (CSSPropertyID property : kCSSPropertyAliasList) {
      if (CSSPropertyID alternative_id =
              CSSUnresolvedProperty::Get(property).GetAlternative();
          alternative_id != CSSPropertyID::kInvalid) {
        alternatives.insert(alternative_id);
      }
    }

    return alternatives;
  }

 protected:
  LocalFrame* GetFrame() { return &dummy_->GetFrame(); }
  void SetIsViewSource() { dummy_->GetDocument().SetIsViewSource(true); }
  void SetURL(const KURL& url) { dummy_->GetDocument().SetURL(url); }
  Document& GetDocument() { return dummy_->GetDocument(); }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> dummy_;
  base::HistogramTester histogram_tester_;

  void UpdateAllLifecyclePhases(Document& document) {
    document.View()->UpdateAllLifecyclePhasesForTest();
  }
};

class UseCounterImplBrowserReportTest
    : public UseCounterImplTest,
      public ::testing::WithParamInterface</* URL */ const char*> {};

INSTANTIATE_TEST_SUITE_P(All,
                         UseCounterImplBrowserReportTest,
                         ::testing::Values("chrome-extension://dummysite/",
                                           "file://dummyfile",
                                           "data:;base64,",
                                           "ftp://ftp.dummy/dummy.txt",
                                           "http://foo.com",
                                           "https://bar.com"));

// UseCounter should not send events to browser when handling page with
// Non HTTP Family URLs, as these events will be discarded on the browser side
// in |MetricsWebContentsObserver::DoesTimingUpdateHaveError|.
TEST_P(UseCounterImplBrowserReportTest, ReportOnlyHTTPFamily) {
  KURL url = url_test_helpers::ToKURL(GetParam());
  SetURL(url);
  UseCounterImpl use_counter;
  use_counter.DidCommitLoad(GetFrame());

  // Count every feature types in UseCounterFeatureType.
  use_counter.Count(mojom::WebFeature::kFetch, GetFrame());
  use_counter.Count(CSSPropertyID::kHeight,
                    UseCounterImpl::CSSPropertyType::kDefault, GetFrame());
  use_counter.Count(CSSPropertyID::kHeight,
                    UseCounterImpl::CSSPropertyType::kAnimation, GetFrame());

  auto* dummy_client =
      static_cast<UseCounterImplBrowserReportTest::DummyLocalFrameClient*>(
          GetFrame()->Client());

  EXPECT_EQ(!dummy_client->observed_features().empty(),
            url.ProtocolIsInHTTPFamily());
}

TEST_F(UseCounterImplTest, RecordingExtensions) {
  const std::string histogram = kExtensionFeaturesHistogramName;
  constexpr auto item = mojom::WebFeature::kFetch;
  constexpr auto second_item = WebFeature::kFetchBodyStream;
  const std::string url = kExtensionUrl;
  CommonSchemeRegistry::RegisterURLSchemeAsExtension("chrome-extension");
  UseCounterImpl::Context context = UseCounterImpl::kExtensionContext;
  int page_visits_bucket = GetPageVisitsBucketforHistogram(histogram);

  UseCounterImpl use_counter0(context, UseCounterImpl::kCommited);

  // Test recording a single (arbitrary) counter
  EXPECT_FALSE(use_counter0.IsCounted(item));
  use_counter0.Count(item, GetFrame());
  EXPECT_TRUE(use_counter0.IsCounted(item));
  histogram_tester_.ExpectUniqueSample(histogram, static_cast<int>(item), 1);
  // Test that repeated measurements have no effect
  use_counter0.Count(item, GetFrame());
  histogram_tester_.ExpectUniqueSample(histogram, static_cast<int>(item), 1);

  // Test recording a different sample
  EXPECT_FALSE(use_counter0.IsCounted(second_item));
  use_counter0.Count(second_item, GetFrame());
  EXPECT_TRUE(use_counter0.IsCounted(second_item));
  histogram_tester_.ExpectBucketCount(histogram, static_cast<int>(item), 1);
  histogram_tester_.ExpectBucketCount(histogram, static_cast<int>(second_item),
                                      1);
  histogram_tester_.ExpectTotalCount(histogram, 2);

  // After a page load, the histograms will be updated, even when the URL
  // scheme is internal
  UseCounterImpl use_counter1(context);
  SetURL(url_test_helpers::ToKURL(url));
  use_counter1.DidCommitLoad(GetFrame());
  histogram_tester_.ExpectBucketCount(histogram, static_cast<int>(item), 1);
  histogram_tester_.ExpectBucketCount(histogram, static_cast<int>(second_item),
                                      1);
  histogram_tester_.ExpectBucketCount(histogram, page_visits_bucket, 1);
  histogram_tester_.ExpectTotalCount(histogram, 3);

  // Now a repeat measurement should get recorded again, exactly once
  EXPECT_FALSE(use_counter1.IsCounted(item));
  use_counter1.Count(item, GetFrame());
  use_counter1.Count(item, GetFrame());
  EXPECT_TRUE(use_counter1.IsCounted(item));
  histogram_tester_.ExpectBucketCount(histogram, static_cast<int>(item), 2);
  histogram_tester_.ExpectTotalCount(histogram, 4);
  CommonSchemeRegistry::RemoveURLSchemeAsExtensionForTest("chrome-extension");
}

TEST_F(UseCounterImplTest, CSSSelectorPseudoWhere) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSSelectorPseudoWhere;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>.a+:where(.b, .c+.d) { color: red; }</style>");
  EXPECT_TRUE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSSelectorPseudoIs));
}

/*
 * Counter-specific tests
 *
 * NOTE: Most individual UseCounters don't need dedicated test cases.  They are
 * "tested" by analyzing the data they generate including on some known pages.
 * Feel free to add tests for counters where the triggering logic is
 * non-trivial, but it's not required. Manual analysis is necessary to trust the
 * data anyway, real-world pages are full of edge-cases and surprises that you
 * won't find in unit testing anyway.
 */

TEST_F(UseCounterImplTest, CSSSelectorPseudoAnyLink) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSSelectorPseudoAnyLink;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>:any-link { color: red; }</style>");
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSSelectorPseudoWebkitAnyLink) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSSelectorPseudoWebkitAnyLink;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>:-webkit-any-link { color: red; }</style>");
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSTypedOMStylePropertyMap) {
  UseCounterImpl use_counter;
  WebFeature feature = WebFeature::kCSSTypedOMStylePropertyMap;
  EXPECT_FALSE(GetDocument().IsUseCounted(feature));
  GetDocument().CountUse(feature);
  EXPECT_TRUE(GetDocument().IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSSelectorPseudoIs) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSSelectorPseudoIs;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>.a+:is(.b, .c+.d) { color: red; }</style>");
  EXPECT_TRUE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSSelectorPseudoWhere));
}

TEST_F(UseCounterImplTest, CSSSelectorPseudoDir) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSSelectorPseudoDir;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>:dir(ltr) { color: red; }</style>");
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSSelectorNthChildOfSelector) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSSelectorNthChildOfSelector;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>.a:nth-child(3) { color: red; }</style>");
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>.a:nth-child(3 of .b) { color: red; }</style>");
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSGridLayoutPercentageColumnIndefiniteWidth) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kGridRowTrackPercentIndefiniteHeight;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<div style='display: inline-grid; grid-template-columns: 50%;'>"
      "</div>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSFlexibleBox) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSFlexibleBox;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<div style='display: flex;'>flexbox</div>");
  UpdateAllLifecyclePhases(document);
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSFlexibleBoxInline) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSFlexibleBox;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<div style='display: inline-flex;'>flexbox</div>");
  UpdateAllLifecyclePhases(document);
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSFlexibleBoxButton) {
  // LayoutButton is a subclass of LayoutFlexibleBox, however we don't want
  // it to be counted as usage of flexboxes as it's an implementation detail.
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSFlexibleBox;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML("<button>button</button>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, HTMLRootContained) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kHTMLRootContained;
  EXPECT_FALSE(document.IsUseCounted(feature));

  document.documentElement()->SetInlineStyleProperty(CSSPropertyID::kDisplay,
                                                     "none");
  document.documentElement()->SetInlineStyleProperty(CSSPropertyID::kContain,
                                                     "paint");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature));

  document.documentElement()->SetInlineStyleProperty(CSSPropertyID::kDisplay,
                                                     "block");
  UpdateAllLifecyclePhases(document);
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, HTMLBodyContained) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kHTMLBodyContained;
  EXPECT_FALSE(document.IsUseCounted(feature));

  document.body()->SetInlineStyleProperty(CSSPropertyID::kDisplay, "none");
  document.body()->SetInlineStyleProperty(CSSPropertyID::kContain, "paint");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature));

  document.body()->SetInlineStyleProperty(CSSPropertyID::kDisplay, "block");
  UpdateAllLifecyclePhases(document);
  EXPECT_TRUE(document.IsUseCounted(feature));
}

class DeprecationTest : public testing::Test {
 public:
  DeprecationTest()
      : dummy_(std::make_unique<DummyPageHolder>()),
        deprecation_(dummy_->GetPage().GetDeprecation()),
        use_counter_(dummy_->GetDocument().Loader()->GetUseCounter()) {
    Page::InsertOrdinaryPageForTesting(&dummy_->GetPage());
  }

 protected:
  LocalFrame* GetFrame() { return &dummy_->GetFrame(); }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> dummy_;
  Deprecation& deprecation_;
  UseCounterImpl& use_counter_;
};

TEST_F(DeprecationTest, InspectorDisablesDeprecation) {
  // The specific feature we use here isn't important.
  WebFeature feature =
      WebFeature::kCSSSelectorInternalMediaControlsOverlayCastButton;

  deprecation_.MuteForInspector();
  Deprecation::CountDeprecation(GetFrame()->DomWindow(), feature);
  EXPECT_FALSE(use_counter_.IsCounted(feature));

  deprecation_.MuteForInspector();
  Deprecation::CountDeprecation(GetFrame()->DomWindow(), feature);
  EXPECT_FALSE(use_counter_.IsCounted(feature));

  deprecation_.UnmuteForInspector();
  Deprecation::CountDeprecation(GetFrame()->DomWindow(), feature);
  EXPECT_FALSE(use_counter_.IsCounted(feature));

  deprecation_.UnmuteForInspector();
  Deprecation::CountDeprecation(GetFrame()->DomWindow(), feature);
  EXPECT_TRUE(use_counter_.IsCounted(feature));
}

TEST_F(UseCounterImplTest, CSSUnknownNamespacePrefixInSelector) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSUnknownNamespacePrefixInSelector;
  EXPECT_FALSE(document.IsUseCounted(feature));

  document.documentElement()->setInnerHTML(R"HTML(
    <style>
      @namespace svg url(http://www.w3.org/2000/svg);
      svg|a {}
      a {}
    </style>
  )HTML");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature));

  document.documentElement()->setInnerHTML("<style>foo|a {}</style>");
  UpdateAllLifecyclePhases(document);
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSSelectorHostContextInLiveProfile) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSSelectorHostContextInLiveProfile;

  document.body()->setInnerHTML(R"HTML(
    <div id="parent">
      <div id="host"></div>
    </div>
  )HTML");

  Element* host = document.getElementById(AtomicString("host"));
  ASSERT_TRUE(host);
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature));

  shadow_root.setInnerHTML(R"HTML(
      <style>
        :host-context(#parent) span {
          color: green
        }
      </style>
      <span></span>
  )HTML");

  UpdateAllLifecyclePhases(document);
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSSelectorHostContextInSnapshotProfile) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSSelectorHostContextInSnapshotProfile;

  document.body()->setInnerHTML(R"HTML(
    <div id="parent">
      <div id="host"></div>
    </div>
  )HTML");

  Element* host = document.getElementById(AtomicString("host"));
  ASSERT_TRUE(host);
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature));

  shadow_root.setInnerHTML("<span></span>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature));

  Element* span =
      shadow_root.QuerySelector(AtomicString(":host-context(#parent) span"));
  EXPECT_TRUE(span);
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, UniqueCSSSampleIds) {
  HashSet<int> ids;

  HashSet<CSSPropertyID> alternatives = GetAlternatives();

  for (CSSPropertyID property : CSSPropertyIDList()) {
    if (IsInternal(property)) {
      continue;
    }
    if (alternatives.Contains(property)) {
      // Alternative properties should use the same CSSSampleId as the
      // corresponding main property.
      continue;
    }
    EXPECT_FALSE(ids.Contains(ToSampleId(property)));
    ids.insert(ToSampleId(property));
  }

  for (CSSPropertyID property : kCSSPropertyAliasList) {
    if (alternatives.Contains(property)) {
      // Alternative properties should use the same CSSSampleId as the
      // corresponding main property.
      continue;
    }
    EXPECT_FALSE(ids.Contains(ToSampleId(property)));
    ids.insert(ToSampleId(property));
  }
}

TEST_F(UseCounterImplTest, MaximumCSSSampleId) {
  int max_sample_id = 0;

  for (CSSPropertyID property : CSSPropertyIDList()) {
    if (IsInternal(property)) {
      continue;
    }
    max_sample_id = std::max(max_sample_id, ToSampleId(property));
  }

  for (CSSPropertyID property : kCSSPropertyAliasList) {
    max_sample_id = std::max(max_sample_id, ToSampleId(property));
  }

  EXPECT_EQ(static_cast<int>(mojom::blink::CSSSampleId::kMaxValue),
            max_sample_id);
}

TEST_F(UseCounterImplTest, CSSMarkerPseudoElementUA) {
  // Check that UA styles for list markers are not counted.
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kHasMarkerPseudoElement;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.body()->setInnerHTML(R"HTML(
    <style>
      li::before {
        content: "[before]";
        display: list-item;
      }
    </style>
    <ul>
      <li style="list-style: decimal outside"></li>
      <li style="list-style: decimal inside"></li>
      <li style="list-style: disc outside"></li>
      <li style="list-style: disc inside"></li>
      <li style="list-style: '- ' outside"></li>
      <li style="list-style: '- ' inside"></li>
      <li style="list-style: linear-gradient(blue, cyan) outside"></li>
      <li style="list-style: linear-gradient(blue, cyan) inside"></li>
      <li style="list-style: none outside"></li>
      <li style="list-style: none inside"></li>
    </ul>
  )HTML");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, CSSMarkerPseudoElementAuthor) {
  // Check that author styles for list markers are counted.
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kHasMarkerPseudoElement;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.body()->setInnerHTML(R"HTML(
    <style>
      li::marker {
        color: blue;
      }
    </style>
    <ul>
      <li></li>
    </ul>
  )HTML");
  UpdateAllLifecyclePhases(document);
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST_F(UseCounterImplTest, BackgroundClip) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();

  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));

  document.documentElement()->setInnerHTML(
      "<style>html{background-clip: border-box;}</style>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));

  document.documentElement()->setInnerHTML(
      "<style>html{background-clip: content-box;}</style>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));

  document.documentElement()->setInnerHTML(
      "<style>html{background-clip: padding-box;}</style>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));

  document.documentElement()->setInnerHTML(
      "<style>html{-webkit-background-clip: border-box;}</style>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));

  document.documentElement()->setInnerHTML(
      "<style>html{-webkit-background-clip: content-box;}</style>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));

  document.documentElement()->setInnerHTML(
      "<style>html{-webkit-background-clip: padding-box;}</style>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));

  document.documentElement()->setInnerHTML(
      "<style>html{-webkit-background-clip: text;}</style>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));

  // We dropped the support for keywords without suffix.
  document.documentElement()->setInnerHTML(
      "<style>html{-webkit-background-clip: border;}</style>");
  UpdateAllLifecyclePhases(document);
  if (RuntimeEnabledFeatures::CSSBackgroundClipUnprefixEnabled()) {
    EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  } else {
    EXPECT_TRUE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  }
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));

  document.ClearUseCounterForTesting(WebFeature::kCSSBackgroundClipBorder);
  document.documentElement()->setInnerHTML(
      "<style>html{-webkit-background-clip: content;}</style>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  if (RuntimeEnabledFeatures::CSSBackgroundClipUnprefixEnabled()) {
    EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  } else {
    EXPECT_TRUE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  }
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));

  document.ClearUseCounterForTesting(WebFeature::kCSSBackgroundClipContent);
  document.documentElement()->setInnerHTML(
      "<style>html{-webkit-background-clip: padding;}</style>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipBorder));
  EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipContent));
  if (RuntimeEnabledFeatures::CSSBackgroundClipUnprefixEnabled()) {
    EXPECT_FALSE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));
  } else {
    EXPECT_TRUE(document.IsUseCounted(WebFeature::kCSSBackgroundClipPadding));
  }
}

TEST_F(UseCounterImplTest, H1UserAgentFontSizeInSectionApplied) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kH1UserAgentFontSizeInSectionApplied;

  EXPECT_FALSE(document.IsUseCounted(feature));

  document.documentElement()->setInnerHTML("<h1></h1>");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature))
      << "Not inside sectioning element";

  document.documentElement()->setInnerHTML(R"HTML(
      <article><h1 style="font-size: 10px"></h1></article>
  )HTML");
  UpdateAllLifecyclePhases(document);
  EXPECT_FALSE(document.IsUseCounted(feature))
      << "Inside sectioning element with author font-size";

  document.documentElement()->setInnerHTML(R"HTML(
      <article><h1></h1></article>
  )HTML");
  UpdateAllLifecyclePhases(document);
  EXPECT_TRUE(document.IsUseCounted(feature))
      << "Inside sectioning element with UA font-size";
}

}  // namespace blink

"""

```