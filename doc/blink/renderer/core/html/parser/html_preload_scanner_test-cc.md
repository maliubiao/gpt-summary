Response:
The user wants a summary of the functionality of the provided C++ code file, `html_preload_scanner_test.cc`. The request specifically asks to:

1. **List the functionalities** of the code.
2. **Explain relationships** with JavaScript, HTML, and CSS, with examples.
3. **Provide input/output examples** for logical inferences.
4. **Give examples of common user/programming errors.**
5. **Summarize the overall functionality** for part 1 of 3.

Let's break down the code to understand its purpose and address each point:

**1. Code Functionality:**

The core of the code is testing the `HTMLPreloadScanner`. The test cases define different HTML snippets and expected preloading behaviors. Key aspects being tested include:

* **Resource Preloading:**  Identifying and preloading resources like images, stylesheets, and scripts based on HTML tags (`<img>`, `<link>`, `<script>`).
* **`srcset` and `sizes` Attribute Handling:**  Testing how the scanner selects the appropriate image source based on viewport size and `sizes` attribute.
* **Viewport Meta Tag:** Verifying the impact of the `<meta name="viewport">` tag on resource selection.
* **Referrer Policy:** Testing how `referrerpolicy` attributes on elements affect the referrer header of preload requests.
* **CORS:**  Checking how `crossorigin` attributes affect the `RequestMode` and `CredentialsMode` of preload requests.
* **CSP:** Identifying the presence of Content Security Policy (`<meta http-equiv="Content-Security-Policy">`) tags.
* **Nonce:** Handling the `nonce` attribute for script and style tags.
* **Image Sets:** Determining if a resource is part of an image set.
* **Integrity:** Counting the number of `integrity` attributes found.
* **Lazy Loading:** Testing the behavior of the `loading="lazy"` attribute on images.
* **Attribution Reporting:** Checking for `attribution-reporting` attributes and their effect on request eligibility.
* **LCP Preloading:** Identifying and preloading resources potentially related to the Largest Contentful Paint (LCP) element.
* **Shared Storage Writable:** Testing the `sharedstoragewritable` attribute.
* **Meta Client Hints:** Testing how `<meta http-equiv="Accept-CH">` influences client hints.

**2. Relationships with JavaScript, HTML, and CSS:**

* **HTML:** The most direct relationship. The scanner parses HTML to find resources to preload. Examples include `<img src="...">`, `<link rel="stylesheet" href="...">`, `<script src="...">`. The test cases are filled with HTML examples.
* **CSS:**  The scanner identifies CSS resources through `<link rel="stylesheet" href="...">`. The handling of `srcset` and `sizes` on `<img>` tags is related to how responsive images are handled, which is often tied to CSS media queries, although the scanner itself operates at the HTML parsing level.
* **JavaScript:** The scanner identifies JavaScript resources via `<script src="...">`. The `nonce` attribute is relevant for inline scripts and CSP, which can be used to secure JavaScript execution. LCP preloading can involve preloading resources that are necessary for rendering key JavaScript-driven content.

**3. Logical Inference - Input/Output Examples:**

* **Input:** `<img srcset="small.jpg 100w, large.jpg 500w" sizes="50vw" src="fallback.jpg">` with a viewport width of 200px.
* **Output:** Preload request for `small.jpg` (since 50vw is 100px, and 100w is the closest match).

* **Input:** `<link rel="preload" href="style.css" as="style">`
* **Output:** Preload request for `style.css` with `ResourceType::kStylesheet`.

* **Input:** `<script src="app.js" nonce="abc">`
* **Output:** Preload request for `app.js` with nonce "abc".

**4. Common User/Programming Errors:**

* **Incorrect `srcset` syntax:**  Forgetting the `w` unit after the width descriptor, leading to the browser not being able to interpret the `srcset`. Example: `<img srcset="image.jpg 100">` (missing 'w').
* **Mismatched `sizes` and `srcset`:** Providing `sizes` values that don't align with the width descriptors in `srcset`, potentially causing the browser to load an unnecessarily large image. Example: `sizes="50vw"` but `srcset="small.jpg 100w"`.
* **Forgetting `as` attribute for `<link rel="preload">`:** The `as` attribute is crucial for the browser to prioritize and handle the preload correctly. Example: `<link rel="preload" href="font.woff2">` (missing `as="font"`).
* **Incorrect Referrer Policy syntax:**  Using an invalid value for the `referrerpolicy` attribute. Example: `<img src="image.jpg" referrerpolicy="wrong">`.
* **CSP errors:** Incorrectly configuring CSP can block preloaded resources. For instance, a strict `script-src 'self'` policy would block a script loaded from a CDN without the appropriate hash or nonce.

**5. Summary of Functionality (Part 1):**

This part of the `html_preload_scanner_test.cc` file focuses on testing the core functionalities of the `HTMLPreloadScanner` related to **identifying and requesting preloads for various HTML resources, primarily images**. It specifically checks how the scanner handles basic image loading, the `srcset` and `sizes` attributes for responsive images, and the influence of the viewport meta tag on resource selection. It also includes tests for referrer policy on image preloads. The tests use mock preloader to verify the generated preload requests have the expected URLs, resource types, and other parameters.
This section of the `html_preload_scanner_test.cc` file primarily focuses on **testing the ability of the `HTMLPreloadScanner` to correctly identify and generate preload requests for `<img>` elements with various attributes, especially `src`, `srcset`, and `sizes`**.

Here's a breakdown of its functionalities:

1. **Testing Basic Image Preloading:** It verifies that a simple `<img>` tag with a `src` attribute will trigger a preload request for the specified image URL.

   * **Example:** For the input `<img src='bla.gif'>`, it expects a preload request for `bla.gif`.

2. **Testing `srcset` Attribute Handling:** It examines how the scanner selects the appropriate image source from the `srcset` attribute based on the available screen resolution (implicitly tested without an explicit viewport) and generates a preload request for the chosen URL.

   * **Example:** For `<img srcset='bla.gif 320w, blabla.gif 640w'>`, it expects a preload request for `blabla.gif` assuming a sufficiently high resolution.

3. **Testing `sizes` Attribute Handling:** It verifies that the scanner uses the `sizes` attribute in conjunction with the viewport width to determine the appropriate image to preload from the `srcset`.

   * **Assumption:** The test environment provides a default viewport width (evident from the `CreateMediaValuesData` function).
   * **Example:** For `<img sizes='50vw' src='bla.gif'>` with a default viewport, it calculates 50% of the viewport width and potentially uses this to select an image from a `srcset` if present. If no `srcset`, it preloads the `src`.

4. **Testing Combinations of `src`, `srcset`, and `sizes`:** It covers scenarios where all three attributes are present, ensuring the scanner follows the correct logic for selecting the image to preload based on the viewport and specified sizes.

5. **Testing Viewport Meta Tag Influence:** It explores how the presence and content of the `<meta name="viewport">` tag affects the calculation of available screen width and subsequently the image selected for preloading from `srcset`.

   * **Example:**  If `<meta name=viewport content='width=160'>` is present, the scanner will use 160px as the viewport width when evaluating the `sizes` attribute.

6. **Testing "device-width" in Viewport:** It verifies the scanner correctly interprets `width=device-width` in the viewport meta tag and uses the device's width for image selection.

7. **Testing Disabled Viewport:** It checks the behavior when viewport processing is disabled, ensuring that `sizes` are interpreted based on a default (likely larger) viewport or are ignored.

8. **Testing Missing or Invalid Viewport Content:** It confirms that the scanner handles cases where the `viewport` meta tag is present but has no content or invalid content, potentially falling back to default behavior.

**Relationship to HTML, CSS, and JavaScript:**

* **HTML:** This test suite directly relates to HTML as it focuses on the parsing and interpretation of `<img>` tags and the `<meta name="viewport">` tag. It validates how the scanner handles various HTML attributes related to image loading.
* **CSS:** While not directly testing CSS parsing, the `sizes` attribute on the `<img>` tag is intrinsically linked to CSS media queries and responsive design. The scanner needs to understand the `vw` unit (viewport width) defined in CSS to make informed preloading decisions.
* **JavaScript:** This test file doesn't directly interact with JavaScript functionality. However, the preloading of images initiated by the scanner can improve the performance of web pages that might rely on JavaScript to manipulate or display these images later.

**Logical Inference - Assumption and Example:**

* **Assumption:** The `HTMLMockHTMLResourcePreloader` acts as a mock object to capture the preload requests generated by the `HTMLPreloadScanner`. It doesn't perform actual network requests.
* **Input:** `<img srcset="small.jpg 100w, large.jpg 500w" sizes="50vw" src="fallback.jpg">` and a viewport width of 600px (derived from `CreateMediaValuesData`).
* **Output:** The `HTMLMockHTMLResourcePreloader` would receive a preload request for `large.jpg` because `50vw` would be 300px, and `large.jpg` (500w) is the closest image within the `srcset` that is not smaller than the calculated size.

**Common User/Programming Errors (Illustrative based on the tested functionalities):**

* **Incorrectly specifying `srcset` or `sizes`:**  A developer might provide syntactically incorrect values for these attributes, preventing the browser (and the preload scanner) from correctly identifying the appropriate image.
    * **Example:** `<img srcset="image1.jpg, image2.jpg 200w">` (missing width descriptor for the first image).
* **Not understanding the interaction between `srcset`, `sizes`, and viewport:** A developer might set up responsive images incorrectly, leading to the browser loading unnecessarily large images for smaller screens, even if the preload scanner correctly identifies the intended resource.
* **Forgetting the `w` unit in `srcset`:**  Specifying widths without the `w` unit will make the `srcset` invalid.
    * **Example:** `<img srcset="image.jpg 100">`

**Summary of Functionality (Part 1):**

In summary, this first part of the `html_preload_scanner_test.cc` file focuses on rigorously testing the `HTMLPreloadScanner`'s ability to correctly identify and generate preload requests for images based on the `src`, `srcset`, and `sizes` attributes, taking into account the influence of the viewport meta tag and different viewport configurations. It ensures that the preloading mechanism behaves as expected for various responsive image scenarios.

### 提示词
```
这是目录为blink/renderer/core/html/parser/html_preload_scanner_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/parser/html_preload_scanner.h"

#include <memory>

#include "base/strings/stringprintf.h"
#include "base/test/scoped_feature_list.h"
#include "services/network/public/mojom/attribution.mojom-blink.h"
#include "services/network/public/mojom/web_client_hints_types.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/renderer/core/css/media_values_cached.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/cross_origin_attribute.h"
#include "third_party/blink/renderer/core/html/parser/background_html_scanner.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_options.h"
#include "third_party/blink/renderer/core/html/parser/html_resource_preloader.h"
#include "third_party/blink/renderer/core/html/parser/html_tokenizer.h"
#include "third_party/blink/renderer/core/html/parser/preload_request.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/element_locator.h"
#include "third_party/blink/renderer/core/media_type_names.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/client_hints_preferences.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

struct PreloadScannerTestCase {
  const char* base_url;
  const char* input_html;
  const char* preloaded_url;  // Or nullptr if no preload is expected.
  const char* output_base_url;
  ResourceType type;
  int resource_width;
  ClientHintsPreferences preferences;
};

struct RenderBlockingTestCase {
  const char* base_url;
  const char* input_html;
  RenderBlockingBehavior renderBlocking;
};

struct HTMLPreconnectTestCase {
  const char* base_url;
  const char* input_html;
  const char* preconnected_host;
  CrossOriginAttributeValue cross_origin;
};

struct ReferrerPolicyTestCase {
  const char* base_url;
  const char* input_html;
  const char* preloaded_url;  // Or nullptr if no preload is expected.
  const char* output_base_url;
  ResourceType type;
  int resource_width;
  network::mojom::ReferrerPolicy referrer_policy;
  // Expected referrer header of the preload request, or nullptr if the header
  // shouldn't be checked (and no network request should be created).
  const char* expected_referrer;
};

struct CorsTestCase {
  const char* base_url;
  const char* input_html;
  network::mojom::RequestMode request_mode;
  network::mojom::CredentialsMode credentials_mode;
};

struct CSPTestCase {
  const char* base_url;
  const char* input_html;
  bool should_see_csp_tag;
};

struct NonceTestCase {
  const char* base_url;
  const char* input_html;
  const char* nonce;
};

struct ContextTestCase {
  const char* base_url;
  const char* input_html;
  const char* preloaded_url;  // Or nullptr if no preload is expected.
  bool is_image_set;
};

struct IntegrityTestCase {
  size_t number_of_integrity_metadata_found;
  const char* input_html;
};

struct LazyLoadImageTestCase {
  const char* input_html;
  bool should_preload;
};

struct AttributionSrcTestCase {
  bool use_secure_document_url;
  const char* base_url;
  const char* input_html;
  network::mojom::AttributionReportingEligibility expected_eligibility;
  network::mojom::AttributionSupport attribution_support =
      network::mojom::AttributionSupport::kWeb;
};

struct TokenStreamMatcherTestCase {
  ElementLocator locator;
  const char* input_html;
  const char* potentially_lcp_preload_url;
  bool should_preload;
};

struct SharedStorageWritableTestCase {
  bool use_secure_document_url;
  const char* base_url;
  const char* input_html;
  bool expected_shared_storage_writable_opted_in;
};

class HTMLMockHTMLResourcePreloader : public ResourcePreloader {
 public:
  explicit HTMLMockHTMLResourcePreloader(const KURL& document_url)
      : document_url_(document_url) {}

  void TakePreloadData(std::unique_ptr<PendingPreloadData> preload_data) {
    preload_data_ = std::move(preload_data);
    TakeAndPreload(preload_data_->requests);
  }

  void PreloadRequestVerification(ResourceType type,
                                  const char* url,
                                  const char* base_url,
                                  int width,
                                  const ClientHintsPreferences& preferences) {
    if (!url) {
      EXPECT_FALSE(preload_request_) << preload_request_->ResourceURL();
      return;
    }
    EXPECT_NE(nullptr, preload_request_.get());
    if (preload_request_) {
      EXPECT_FALSE(preload_request_->IsPreconnect());
      EXPECT_EQ(type, preload_request_->GetResourceType());
      EXPECT_EQ(url, preload_request_->ResourceURL());
      EXPECT_EQ(base_url, preload_request_->BaseURL().GetString());
      EXPECT_EQ(width, preload_request_->GetResourceWidth().value_or(0));

      ClientHintsPreferences preload_preferences;
      for (const auto& value : preload_data_->meta_ch_values) {
        preload_preferences.UpdateFromMetaCH(value.value, document_url_,
                                             nullptr, value.type,
                                             value.is_doc_preloader,
                                             /*is_sync_parser=*/false);
      }
      EXPECT_EQ(preferences.ShouldSend(
                    network::mojom::WebClientHintsType::kDpr_DEPRECATED),
                preload_preferences.ShouldSend(
                    network::mojom::WebClientHintsType::kDpr_DEPRECATED));
      EXPECT_EQ(
          preferences.ShouldSend(network::mojom::WebClientHintsType::kDpr),
          preload_preferences.ShouldSend(
              network::mojom::WebClientHintsType::kDpr));
      EXPECT_EQ(
          preferences.ShouldSend(
              network::mojom::WebClientHintsType::kResourceWidth_DEPRECATED),
          preload_preferences.ShouldSend(
              network::mojom::WebClientHintsType::kResourceWidth_DEPRECATED));
      EXPECT_EQ(preferences.ShouldSend(
                    network::mojom::WebClientHintsType::kResourceWidth),
                preload_preferences.ShouldSend(
                    network::mojom::WebClientHintsType::kResourceWidth));
      EXPECT_EQ(
          preferences.ShouldSend(
              network::mojom::WebClientHintsType::kViewportWidth_DEPRECATED),
          preload_preferences.ShouldSend(
              network::mojom::WebClientHintsType::kViewportWidth_DEPRECATED));
      EXPECT_EQ(preferences.ShouldSend(
                    network::mojom::WebClientHintsType::kViewportWidth),
                preload_preferences.ShouldSend(
                    network::mojom::WebClientHintsType::kViewportWidth));
    }
  }

  void PreloadRequestVerification(
      ResourceType type,
      const char* url,
      const char* base_url,
      int width,
      network::mojom::ReferrerPolicy referrer_policy) {
    PreloadRequestVerification(type, url, base_url, width,
                               ClientHintsPreferences());
    EXPECT_EQ(referrer_policy, preload_request_->GetReferrerPolicy());
  }

  void PreloadRequestVerification(
      ResourceType type,
      const char* url,
      const char* base_url,
      int width,
      network::mojom::ReferrerPolicy referrer_policy,
      Document* document,
      const char* expected_referrer) {
    PreloadRequestVerification(type, url, base_url, width, referrer_policy);
    Resource* resource = preload_request_->Start(document);
    ASSERT_TRUE(resource);
    EXPECT_EQ(expected_referrer,
              resource->GetResourceRequest().ReferrerString());
  }

  void RenderBlockingRequestVerification(
      RenderBlockingBehavior renderBlocking) {
    ASSERT_TRUE(preload_request_);
    EXPECT_EQ(preload_request_->GetRenderBlockingBehavior(), renderBlocking);
  }

  void PreconnectRequestVerification(const String& host,
                                     CrossOriginAttributeValue cross_origin) {
    if (!host.IsNull()) {
      EXPECT_TRUE(preload_request_->IsPreconnect());
      EXPECT_EQ(preload_request_->ResourceURL(), host);
      EXPECT_EQ(preload_request_->CrossOrigin(), cross_origin);
    }
  }

  void CorsRequestVerification(
      Document* document,
      network::mojom::RequestMode request_mode,
      network::mojom::CredentialsMode credentials_mode) {
    ASSERT_TRUE(preload_request_.get());
    Resource* resource = preload_request_->Start(document);
    ASSERT_TRUE(resource);
    EXPECT_EQ(request_mode, resource->GetResourceRequest().GetMode());
    EXPECT_EQ(credentials_mode,
              resource->GetResourceRequest().GetCredentialsMode());
  }

  void NonceRequestVerification(const char* nonce) {
    ASSERT_TRUE(preload_request_.get());
    if (strlen(nonce))
      EXPECT_EQ(nonce, preload_request_->Nonce());
    else
      EXPECT_TRUE(preload_request_->Nonce().empty());
  }

  void ContextVerification(bool is_image_set) {
    ASSERT_TRUE(preload_request_.get());
    EXPECT_EQ(preload_request_->IsImageSetForTestingOnly(), is_image_set);
  }

  void CheckNumberOfIntegrityConstraints(size_t expected) {
    size_t actual = 0;
    if (preload_request_) {
      actual = preload_request_->IntegrityMetadataForTestingOnly().size();
      EXPECT_EQ(expected, actual);
    }
  }

  void LazyLoadImagePreloadVerification(bool expected) {
    if (expected) {
      EXPECT_TRUE(preload_request_.get());
    } else {
      EXPECT_FALSE(preload_request_) << preload_request_->ResourceURL();
    }
  }

  void AttributionSrcRequestVerification(
      Document* document,
      network::mojom::AttributionReportingEligibility expected_eligibility,
      network::mojom::AttributionSupport expected_support) {
    ASSERT_TRUE(preload_request_.get());
    Resource* resource = preload_request_->Start(document);
    ASSERT_TRUE(resource);

    EXPECT_EQ(
        expected_eligibility,
        resource->GetResourceRequest().GetAttributionReportingEligibility());

    EXPECT_EQ(expected_support,
              resource->GetResourceRequest().GetAttributionReportingSupport());
  }

  void IsPotentiallyLCPElementFlagVerification(bool expected) {
    EXPECT_EQ(expected, preload_request_->IsPotentiallyLCPElement())
        << preload_request_->ResourceURL();
  }

  void SharedStorageWritableRequestVerification(
      Document* document,
      bool expected_shared_storage_writable_opted_in) {
    ASSERT_TRUE(preload_request_.get());
    Resource* resource = preload_request_->Start(document);
    ASSERT_TRUE(resource);

    EXPECT_EQ(expected_shared_storage_writable_opted_in,
              resource->GetResourceRequest().GetSharedStorageWritableOptedIn());
  }

 protected:
  void Preload(std::unique_ptr<PreloadRequest> preload_request) override {
    preload_request_ = std::move(preload_request);
  }

 private:
  std::unique_ptr<PreloadRequest> preload_request_;
  std::unique_ptr<PendingPreloadData> preload_data_;
  KURL document_url_;
};

class HTMLPreloadScannerTest : public PageTestBase {
 protected:
  enum ViewportState {
    kViewportEnabled,
    kViewportDisabled,
  };

  enum PreloadState {
    kPreloadEnabled,
    kPreloadDisabled,
  };

  std::unique_ptr<MediaValuesCached::MediaValuesCachedData>
  CreateMediaValuesData() {
    auto data = std::make_unique<MediaValuesCached::MediaValuesCachedData>();
    data->viewport_width = 500;
    data->viewport_height = 600;
    data->device_width = 700;
    data->device_height = 800;
    data->device_pixel_ratio = 2.0;
    data->color_bits_per_component = 24;
    data->monochrome_bits_per_component = 0;
    data->primary_pointer_type = mojom::blink::PointerType::kPointerFineType;
    data->three_d_enabled = true;
    data->media_type = media_type_names::kScreen;
    data->strict_mode = true;
    data->display_mode = blink::mojom::DisplayMode::kBrowser;
    return data;
  }

  void RunSetUp(ViewportState viewport_state,
                PreloadState preload_state = kPreloadEnabled,
                network::mojom::ReferrerPolicy document_referrer_policy =
                    network::mojom::ReferrerPolicy::kDefault,
                bool use_secure_document_url = false,
                Vector<ElementLocator> locators = {},
                bool disable_preload_scanning = false) {
    HTMLParserOptions options(&GetDocument());
    KURL document_url = KURL("http://whatever.test/");
    if (use_secure_document_url)
      document_url = KURL("https://whatever.test/");
    NavigateTo(document_url);
    GetDocument().GetSettings()->SetViewportEnabled(viewport_state ==
                                                    kViewportEnabled);
    GetDocument().GetSettings()->SetViewportMetaEnabled(viewport_state ==
                                                        kViewportEnabled);
    GetDocument().GetSettings()->SetDoHtmlPreloadScanning(preload_state ==
                                                          kPreloadEnabled);
    GetFrame().DomWindow()->SetReferrerPolicy(document_referrer_policy);
    scanner_ = std::make_unique<HTMLPreloadScanner>(
        std::make_unique<HTMLTokenizer>(options), document_url,
        std::make_unique<CachedDocumentParameters>(&GetDocument()),
        CreateMediaValuesData(),
        TokenPreloadScanner::ScannerType::kMainDocument,
        /* script_token_scanner=*/nullptr,
        /* take_preload=*/HTMLPreloadScanner::TakePreloadFn(), locators,
        disable_preload_scanning);
  }

  void SetUp() override {
    PageTestBase::SetUp(gfx::Size());
    RunSetUp(kViewportEnabled);
  }

  void Test(PreloadScannerTestCase test_case) {
    SCOPED_TRACE(test_case.input_html);
    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url(test_case.base_url);
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));

    preloader.PreloadRequestVerification(
        test_case.type, test_case.preloaded_url, test_case.output_base_url,
        test_case.resource_width, test_case.preferences);
  }

  void Test(RenderBlockingTestCase test_case) {
    SCOPED_TRACE(test_case.input_html);
    RunSetUp(kViewportEnabled, kPreloadEnabled,
             network::mojom::ReferrerPolicy::kDefault, true);
    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url(test_case.base_url);
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));
    preloader.RenderBlockingRequestVerification(test_case.renderBlocking);
  }

  void Test(HTMLPreconnectTestCase test_case) {
    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url(test_case.base_url);
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));
    preloader.PreconnectRequestVerification(test_case.preconnected_host,
                                            test_case.cross_origin);
  }

  void Test(ReferrerPolicyTestCase test_case) {
    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url(test_case.base_url);
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));

    if (test_case.expected_referrer) {
      preloader.PreloadRequestVerification(
          test_case.type, test_case.preloaded_url, test_case.output_base_url,
          test_case.resource_width, test_case.referrer_policy, &GetDocument(),
          test_case.expected_referrer);
    } else {
      preloader.PreloadRequestVerification(
          test_case.type, test_case.preloaded_url, test_case.output_base_url,
          test_case.resource_width, test_case.referrer_policy);
    }
  }

  void Test(CorsTestCase test_case) {
    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url(test_case.base_url);
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));
    preloader.CorsRequestVerification(&GetDocument(), test_case.request_mode,
                                      test_case.credentials_mode);
  }

  void Test(CSPTestCase test_case) {
    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url(test_case.base_url);
    scanner_->AppendToEnd(String(test_case.input_html));
    auto data = scanner_->Scan(base_url);
    EXPECT_EQ(test_case.should_see_csp_tag, data->csp_meta_tag_count > 0);
  }

  void Test(NonceTestCase test_case) {
    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url(test_case.base_url);
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));
    preloader.NonceRequestVerification(test_case.nonce);
  }

  void Test(ContextTestCase test_case) {
    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url(test_case.base_url);
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));

    preloader.ContextVerification(test_case.is_image_set);
  }

  void Test(IntegrityTestCase test_case) {
    SCOPED_TRACE(test_case.input_html);
    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url("http://example.test/");
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));

    preloader.CheckNumberOfIntegrityConstraints(
        test_case.number_of_integrity_metadata_found);
  }

  void Test(LazyLoadImageTestCase test_case) {
    SCOPED_TRACE(test_case.input_html);
    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url("http://example.test/");
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));
    preloader.LazyLoadImagePreloadVerification(test_case.should_preload);
  }

  void Test(AttributionSrcTestCase test_case) {
    SCOPED_TRACE(test_case.input_html);

    GetPage().SetAttributionSupport(test_case.attribution_support);

    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url(test_case.base_url);
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));
    preloader.AttributionSrcRequestVerification(&GetDocument(),
                                                test_case.expected_eligibility,
                                                test_case.attribution_support);
  }

  void Test(TokenStreamMatcherTestCase test_case) {
    SCOPED_TRACE(test_case.input_html);
    RunSetUp(kViewportEnabled, kPreloadEnabled,
             network::mojom::ReferrerPolicy::kDefault,
             /* use_secure_document_url=*/true, {test_case.locator});
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data =
        scanner_->Scan(GetDocument().Url());
    int count = 0;
    for (const auto& request_ptr : preload_data->requests) {
      if (request_ptr->IsPotentiallyLCPElement()) {
        EXPECT_EQ(request_ptr->ResourceURL(),
                  String(test_case.potentially_lcp_preload_url));
        count++;
      }
    }

    EXPECT_EQ(test_case.should_preload ? 1 : 0, count);
  }

  void Test(SharedStorageWritableTestCase test_case) {
    SCOPED_TRACE(base::StringPrintf("Use secure doc URL: %d; HTML: '%s'",
                                    test_case.use_secure_document_url,
                                    test_case.input_html));

    HTMLMockHTMLResourcePreloader preloader(GetDocument().Url());
    KURL base_url(test_case.base_url);
    scanner_->AppendToEnd(String(test_case.input_html));
    std::unique_ptr<PendingPreloadData> preload_data = scanner_->Scan(base_url);
    preloader.TakePreloadData(std::move(preload_data));
    preloader.SharedStorageWritableRequestVerification(
        &GetDocument(), test_case.expected_shared_storage_writable_opted_in);
  }

 private:
  std::unique_ptr<HTMLPreloadScanner> scanner_;
};

TEST_F(HTMLPreloadScannerTest, testImages) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test", "<img src='bla.gif'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<img srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<img sizes='50vw' src='bla.gif'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 1x'>", "bla2.gif",
       "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 0.5x'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 100w'>", "bla2.gif",
       "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 100w, bla3.gif 250w'>",
       "bla3.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 100w, bla3.gif 250w, "
       "bla4.gif 500w'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img src='bla.gif' srcset='bla2.gif 100w, bla3.gif 250w, bla4.gif "
       "500w' sizes='50vw'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img src='bla.gif' sizes='50vw' srcset='bla2.gif 100w, bla3.gif 250w, "
       "bla4.gif 500w'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' srcset='bla2.gif 100w, bla3.gif 250w, bla4.gif 500w' "
       "src='bla.gif'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img srcset='bla2.gif 100w, bla3.gif 250w, bla4.gif 500w' "
       "src='bla.gif' sizes='50vw'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img srcset='bla2.gif 100w, bla3.gif 250w, bla4.gif 500w' sizes='50vw' "
       "src='bla.gif'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img src='bla.gif' srcset='bla2.gif 100w, bla3.gif 250w, bla4.gif "
       "500w'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 0},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testImagesWithViewport) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test",
       "<meta name=viewport content='width=160'><img srcset='bla.gif 320w, "
       "blabla.gif 640w'>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<img src='bla.gif'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<img sizes='50vw' src='bla.gif'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 80},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 1x'>", "bla2.gif",
       "http://example.test/", ResourceType::kImage, 80},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 0.5x'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 80},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 160w'>", "bla2.gif",
       "http://example.test/", ResourceType::kImage, 80},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 160w, bla3.gif 250w'>",
       "bla2.gif", "http://example.test/", ResourceType::kImage, 80},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 160w, bla3.gif 250w, "
       "bla4.gif 500w'>",
       "bla2.gif", "http://example.test/", ResourceType::kImage, 80},
      {"http://example.test",
       "<img src='bla.gif' srcset='bla2.gif 160w, bla3.gif 250w, bla4.gif "
       "500w' sizes='50vw'>",
       "bla2.gif", "http://example.test/", ResourceType::kImage, 80},
      {"http://example.test",
       "<img src='bla.gif' sizes='50vw' srcset='bla2.gif 160w, bla3.gif 250w, "
       "bla4.gif 500w'>",
       "bla2.gif", "http://example.test/", ResourceType::kImage, 80},
      {"http://example.test",
       "<img sizes='50vw' srcset='bla2.gif 160w, bla3.gif 250w, bla4.gif 500w' "
       "src='bla.gif'>",
       "bla2.gif", "http://example.test/", ResourceType::kImage, 80},
      {"http://example.test",
       "<img srcset='bla2.gif 160w, bla3.gif 250w, bla4.gif 500w' "
       "src='bla.gif' sizes='50vw'>",
       "bla2.gif", "http://example.test/", ResourceType::kImage, 80},
      {"http://example.test",
       "<img srcset='bla2.gif 160w, bla3.gif 250w, bla4.gif 500w' sizes='50vw' "
       "src='bla.gif'>",
       "bla2.gif", "http://example.test/", ResourceType::kImage, 80},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testImagesWithViewportDeviceWidth) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test",
       "<meta name=viewport content='width=device-width'><img srcset='bla.gif "
       "320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<img src='bla.gif'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<img sizes='50vw' src='bla.gif'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 350},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 1x'>", "bla2.gif",
       "http://example.test/", ResourceType::kImage, 350},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 0.5x'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 350},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 160w'>", "bla2.gif",
       "http://example.test/", ResourceType::kImage, 350},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 160w, bla3.gif 250w'>",
       "bla3.gif", "http://example.test/", ResourceType::kImage, 350},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 160w, bla3.gif 250w, "
       "bla4.gif 500w'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 350},
      {"http://example.test",
       "<img src='bla.gif' srcset='bla2.gif 160w, bla3.gif 250w, bla4.gif "
       "500w' sizes='50vw'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 350},
      {"http://example.test",
       "<img src='bla.gif' sizes='50vw' srcset='bla2.gif 160w, bla3.gif 250w, "
       "bla4.gif 500w'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 350},
      {"http://example.test",
       "<img sizes='50vw' srcset='bla2.gif 160w, bla3.gif 250w, bla4.gif 500w' "
       "src='bla.gif'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 350},
      {"http://example.test",
       "<img srcset='bla2.gif 160w, bla3.gif 250w, bla4.gif 500w' "
       "src='bla.gif' sizes='50vw'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 350},
      {"http://example.test",
       "<img srcset='bla2.gif 160w, bla3.gif 250w, bla4.gif 500w' sizes='50vw' "
       "src='bla.gif'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 350},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testImagesWithViewportDisabled) {
  RunSetUp(kViewportDisabled);
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test",
       "<meta name=viewport content='width=160'><img src='bla.gif'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<img srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<img sizes='50vw' src='bla.gif'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 1x'>", "bla2.gif",
       "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 0.5x'>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 100w'>", "bla2.gif",
       "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 100w, bla3.gif 250w'>",
       "bla3.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' src='bla.gif' srcset='bla2.gif 100w, bla3.gif 250w, "
       "bla4.gif 500w'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img src='bla.gif' srcset='bla2.gif 100w, bla3.gif 250w, bla4.gif "
       "500w' sizes='50vw'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img src='bla.gif' sizes='50vw' srcset='bla2.gif 100w, bla3.gif 250w, "
       "bla4.gif 500w'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img sizes='50vw' srcset='bla2.gif 100w, bla3.gif 250w, bla4.gif 500w' "
       "src='bla.gif'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img srcset='bla2.gif 100w, bla3.gif 250w, bla4.gif 500w' "
       "src='bla.gif' sizes='50vw'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<img srcset='bla2.gif 100w, bla3.gif 250w, bla4.gif 500w' sizes='50vw' "
       "src='bla.gif'>",
       "bla4.gif", "http://example.test/", ResourceType::kImage, 250},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testViewportNoContent) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test",
       "<meta name=viewport><img srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<meta name=viewport content=sdkbsdkjnejjha><img srcset='bla.gif 320w, "
       "blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testMetaAcceptCH) {
  ClientHintsPreferences dpr_DEPRECATED;
  ClientHintsPreferences dpr;
  ClientHintsPreferences resource_width_DEPRECATED;
  ClientHintsPreferences resource_width;
  ClientHintsPreferences all;
  ClientHintsPreferences viewport_width_DEPRECATED;
  ClientHintsPreferences viewport_width;
  dpr_DEPRECATED.SetShoul
```