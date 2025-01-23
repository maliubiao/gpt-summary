Response:
Let's break down the thought process to analyze the C++ test file and generate the desired output.

1. **Understand the Goal:** The primary goal is to analyze `css_style_sheet_resource_test.cc` and explain its function, its relation to web technologies (HTML, CSS, JavaScript), how it works (logic, inputs, outputs), potential user/programmer errors, and how a user might trigger this code.

2. **Identify Key Components:**  The first step is to scan the code for essential elements. These include:
    * **Includes:**  `#include` directives reveal dependencies and give hints about the file's purpose. Notice includes related to:
        * CSS: `css_style_sheet_resource.h`, `css/css_property_value_set.h`, `css/css_style_sheet.h`, `css/parser/css_parser_context.h`, `css/resolver/scoped_style_resolver.h`, `css/style_sheet_contents.h`
        * DOM: `dom/document.h`, `html/html_iframe_element.h`
        * Loading: `loader/resource/image_resource.h`, `loader/resource/css_style_sheet_resource.h`
        * Testing: `testing/gtest/include/gtest/gtest.h`, `testing/page_test_base.h`, `testing/sim/sim_request.h`, `testing/sim/sim_test.h`, `platform/testing/unit_test_helpers.h`
        * Platform: `platform/heap/garbage_collected.h`, `platform/loader/fetch/memory_cache.h`, `platform/weborigin/kurl.h`, `platform/wtf/text/text_encoding.h`, `platform/wtf/text/wtf_string.h`
    * **Namespaces:** `namespace blink` indicates this is part of the Blink rendering engine.
    * **Test Class:** `CSSStyleSheetResourceTest` and `CSSStyleSheetResourceSimTest` clearly indicate this is a testing file. The inheritance from `PageTestBase` and `SimTest` confirms this is for testing Blink functionality within a controlled environment.
    * **Test Functions:**  `TEST_F` macros denote individual test cases. The names of these functions are crucial for understanding the tested functionalities: `DuplicateResourceNotCached`, `CreateFromCacheRestoresOriginalSheet`, `CreateFromCacheWithMediaQueries`, `CachedWithDifferentMQEval`.
    * **Helper Functions:**  `CreateAndSaveTestStyleSheetResource()` is a utility function for setting up test scenarios.
    * **Assertions:** `ASSERT_TRUE`, `EXPECT_TRUE`, `EXPECT_FALSE`, `ASSERT_EQ`, `EXPECT_EQ`, `EXPECT_NE` are used to verify the expected behavior.

3. **Infer Functionality from Test Names and Code:**  Now, let's analyze the purpose of each test:
    * `DuplicateResourceNotCached`:  This test checks if a CSS resource with the same URL as an existing image resource is *not* cached as a CSS resource. This suggests the code handles potential conflicts in resource caching based on type.
    * `CreateFromCacheRestoresOriginalSheet`: This test verifies that retrieving a cached CSS stylesheet restores the original `StyleSheetContents` object. This points to the caching mechanism correctly preserving the parsed CSS data.
    * `CreateFromCacheWithMediaQueries`: This test is similar but specifically focuses on stylesheets with `@media` queries. It checks if the cached version can be correctly restored and if the media queries are handled.
    * `CachedWithDifferentMQEval`: This test is more complex and involves iframes. It verifies that while iframes may share the *same* cached stylesheet content, they have *different* evaluated rule sets based on their individual media query contexts (in this case, iframe width).

4. **Relate to Web Technologies:**
    * **CSS:** The file's name and content directly relate to CSS stylesheet loading and caching. The tests manipulate CSS rules, media queries, and stylesheet contents.
    * **HTML:** The tests use iframes (`HTMLIFrameElement`) and link elements (`<link rel="stylesheet">`), demonstrating the integration with HTML structure for loading stylesheets.
    * **JavaScript:** While this specific test file doesn't directly involve JavaScript, the functionality it tests *is* crucial for how JavaScript interacts with styles. JavaScript can modify styles, and the caching mechanism needs to be consistent regardless of how the stylesheet was loaded or modified.

5. **Develop Examples and Scenarios:**  Based on the test names and code, create concrete examples:
    * **Duplicate Resource:**  Imagine a website accidentally uses the same URL for an image and a CSS file. This test ensures the browser handles this gracefully.
    * **Caching and Media Queries:**  Consider a responsive website where different stylesheets are applied based on screen size. This test validates that the correct stylesheet version is retrieved from the cache for each screen size.
    * **Iframe Scenario:** A website embedding content with different layout requirements will load the same CSS but expect it to apply differently within each iframe.

6. **Identify Potential Errors:** Think about common mistakes developers might make:
    * **Incorrect Cache Headers:** If the `Cache-Control` headers are misconfigured, stylesheets might not be cached correctly or might be cached for too long.
    * **Conflicting URLs:** Accidentally using the same URL for different resource types.
    * **Media Query Issues:**  Incorrectly writing media queries or expecting them to behave the same way in all contexts.

7. **Trace User Actions:**  Consider the user's perspective and how they trigger this code:
    * **Loading a Page:** The most basic action – the browser needs to load CSS files referenced in the HTML.
    * **Navigating Between Pages:**  The browser will check the cache for stylesheets.
    * **Resizing the Browser Window:**  Triggers media query re-evaluation.
    * **Embedding Content:** Using iframes or other embedding techniques leads to loading CSS in different contexts.

8. **Structure the Output:**  Organize the information logically, following the prompt's requirements:
    * Start with a clear statement of the file's purpose.
    * Explain the relationships with HTML, CSS, and JavaScript with examples.
    * Provide concrete scenarios with assumed input and output.
    * Describe potential user/programmer errors.
    * Detail the user actions that lead to this code being executed.

9. **Refine and Review:** Read through the generated explanation to ensure clarity, accuracy, and completeness. Double-check that the examples are relevant and easy to understand. Ensure all parts of the prompt have been addressed. For instance, initially, I might have focused too much on the technical details and not enough on the user's perspective, so a review helps to balance that.
The file `blink/renderer/core/loader/resource/css_style_sheet_resource_test.cc` contains **unit tests** for the `CSSStyleSheetResource` class in the Chromium Blink rendering engine. Its primary function is to verify the correct behavior of how CSS stylesheets are loaded, cached, and handled within the rendering pipeline.

Here's a breakdown of its functionalities and relationships with web technologies:

**Core Functionality:**

* **Testing CSS Stylesheet Resource Management:** The tests in this file focus on verifying how `CSSStyleSheetResource` handles:
    * **Creation:** Instantiating new `CSSStyleSheetResource` objects.
    * **Response Handling:** Processing HTTP responses for CSS files, including setting MIME types.
    * **Caching:** Testing the interaction with the browser's memory cache for CSS resources. This includes checking if stylesheets are correctly added to and retrieved from the cache.
    * **Duplicate Resource Handling:** Ensuring that if a CSS resource has the same URL as another type of resource (e.g., an image), it's handled appropriately and doesn't cause conflicts in the cache.
    * **Parsed Stylesheet Management:** Testing how the parsed representation of the CSS (`StyleSheetContents`) is associated with the `CSSStyleSheetResource` and how it's restored from the cache.
    * **Media Query Handling:**  Verifying that when a cached stylesheet with media queries is retrieved, the media queries are correctly associated and can be evaluated in different contexts (e.g., within different iframes).

**Relationship with JavaScript, HTML, and CSS:**

* **CSS:** This file directly tests the loading and caching mechanism for **CSS stylesheets**. The tests involve creating mock CSS responses, parsing CSS content (though implicitly through `StyleSheetContents`), and verifying that the cached stylesheet can be used to style elements.
    * **Example:** The tests use CSS syntax like `div { color: red; }` and `@media (width > 300px) { ... }` to define styles and media queries, directly testing the handling of CSS rules.
* **HTML:** The tests use HTML concepts like `<iframe>` elements and `<link rel="stylesheet">` to simulate scenarios where CSS stylesheets are loaded in different contexts.
    * **Example:** The `CachedWithDifferentMQEval` test sets up an HTML page with two iframes, each loading the same CSS stylesheet. This simulates how a website might embed content with shared styles but potentially different media query environments.
* **JavaScript:** While this specific test file doesn't directly execute JavaScript code, the functionality it tests is crucial for how JavaScript interacts with styles. JavaScript can:
    * **Dynamically create and modify stylesheets:** The caching mechanism tested here would be relevant for stylesheets created or altered by JavaScript.
    * **Access and manipulate computed styles:**  The tests verify that the cached stylesheets lead to the correct computed styles on elements, which JavaScript can then access.

**Logical Reasoning (Hypothetical Inputs and Outputs):**

**Test Case: `DuplicateResourceNotCached`**

* **Hypothetical Input:**
    1. An image resource is loaded and cached with the URL "https://localhost/style.css".
    2. A CSS stylesheet resource is loaded with the *same* URL "https://localhost/style.css".
* **Expected Output:** The memory cache should contain the image resource but **not** the CSS stylesheet resource. The parsed stylesheet contents should not be marked as referenced from a resource. This prevents the browser from mistakenly treating an image as a stylesheet.

**Test Case: `CreateFromCacheRestoresOriginalSheet`**

* **Hypothetical Input:**
    1. A CSS stylesheet with the content "div { color: red; }" is loaded and cached.
    2. An attempt is made to retrieve the parsed stylesheet from the cache.
* **Expected Output:** The retrieved `StyleSheetContents` object should be the same instance as the originally parsed one, and it should contain the rule to set the color of `div` elements to red.

**Test Case: `CachedWithDifferentMQEval`**

* **Hypothetical Input:**
    1. A main HTML page with two iframes is loaded.
    2. Both iframes load the same CSS stylesheet with media queries based on width (e.g., `@media (width > 300px) { ... }`).
    3. The iframes have different widths.
* **Expected Output:**
    * Both iframes will share the same underlying `StyleSheetContents` object from the cache.
    * However, they will have different `RuleSet` objects because the media queries are evaluated based on the individual iframe's width.
    * Elements within the iframes will have different computed styles based on the media query evaluation (e.g., different opacity values).

**User or Programming Common Usage Errors (and how these tests help prevent them):**

* **Incorrect MIME Type:** If a server serves a CSS file with an incorrect MIME type (e.g., `text/plain`), the browser might not process it as a stylesheet. While this test doesn't directly simulate incorrect server responses, it checks that when a correct `style/css` MIME type is set, the resource is handled appropriately.
* **Cache Invalidation Issues:** If the caching logic is flawed, outdated stylesheets might be served even after the server has updated them. These tests help ensure that the caching mechanism respects cache directives and can retrieve the correct version.
* **Conflicting Resource URLs:**  As demonstrated in the `DuplicateResourceNotCached` test, developers might accidentally use the same URL for different types of resources. This test verifies that Blink handles this scenario without causing crashes or unexpected behavior.
* **Media Query Evaluation Errors:** If the logic for evaluating media queries in cached stylesheets is incorrect, different parts of the page (e.g., iframes) might apply the wrong styles. The `CachedWithDifferentMQEval` test specifically targets this potential error.

**How User Operations Lead to This Code (Debugging Clues):**

Imagine a user is browsing a website and encounters a styling issue, particularly with CSS and potentially involving iframes. Here's how the execution might reach the code tested in this file:

1. **User Navigates to a Webpage:** The browser starts loading the HTML content of the page.
2. **Browser Parses HTML and Finds `<link>` Tags:** The HTML parser encounters `<link rel="stylesheet" href="...">` tags, indicating external CSS files.
3. **Resource Loader Initiates CSS Requests:** For each `<link>` tag, the browser's resource loader initiates a network request to fetch the CSS file.
4. **Network Response Received:** The server responds with the CSS content and appropriate headers (including `Content-Type: style/css`).
5. **`CSSStyleSheetResource` is Created:** When the network response for a CSS file is received, the browser creates a `CSSStyleSheetResource` object to manage this resource. This is where the code tested in this file comes into play.
6. **`ResponseReceived` Method Called:** The `CSSStyleSheetResource::ResponseReceived` method is called to process the HTTP response headers.
7. **Caching Logic Executed:** The browser checks the memory cache (and potentially disk cache) to see if the stylesheet has already been loaded.
    * If it's a new resource, it might be added to the cache (as tested in `CreateAndSaveTestStyleSheetResource`).
    * If it's already in the cache, the cached version might be used (as tested in `CreateFromCacheRestoresOriginalSheet`).
8. **CSS Parsing:** The CSS content is parsed, and a `StyleSheetContents` object is created to represent the parsed stylesheet.
9. **Attaching Stylesheets to Documents:** The parsed stylesheet is attached to the `Document` object, making the styles available for rendering.
10. **Rendering Engine Applies Styles:** The rendering engine uses the loaded and parsed stylesheets to calculate the final styles for the HTML elements and paint the webpage.
11. **Iframes Involved (for `CachedWithDifferentMQEval`):** If the webpage contains iframes, the same CSS resource might be loaded in the context of multiple iframes. The caching mechanism needs to ensure that while the underlying stylesheet content might be shared, media queries are evaluated correctly for each iframe's specific environment (e.g., width).
12. **Debugging Scenario:** If a developer suspects a CSS caching issue or a problem with media queries in iframes, they might set breakpoints or add logging within the `CSSStyleSheetResource` class or related code during the loading process to understand how the resource is being handled. The tests in this file provide a reference for the expected behavior.

In essence, `css_style_sheet_resource_test.cc` acts as a safety net, ensuring that the fundamental mechanisms for loading, caching, and managing CSS stylesheets within the Blink rendering engine are working correctly. It covers various scenarios, including basic loading, caching with and without media queries, and handling of duplicate resource URLs, contributing to a stable and predictable web browsing experience.

### 提示词
```
这是目录为blink/renderer/core/loader/resource/css_style_sheet_resource_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h"

#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class Document;

namespace {

class CSSStyleSheetResourceTest : public PageTestBase {
 protected:
  CSSStyleSheetResourceTest() {
    original_memory_cache_ =
        ReplaceMemoryCacheForTesting(MakeGarbageCollected<MemoryCache>(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting()));
  }

  ~CSSStyleSheetResourceTest() override {
    ReplaceMemoryCacheForTesting(original_memory_cache_.Release());
  }

  void SetUp() override {
    PageTestBase::SetUp(gfx::Size());
    GetDocument().SetURL(KURL("https://localhost/"));
  }

  CSSStyleSheetResource* CreateAndSaveTestStyleSheetResource() {
    const char kUrl[] = "https://localhost/style.css";
    const KURL css_url(kUrl);
    ResourceResponse response(css_url);
    response.SetMimeType(AtomicString("style/css"));

    CSSStyleSheetResource* css_resource =
        CSSStyleSheetResource::CreateForTest(css_url, UTF8Encoding());
    css_resource->ResponseReceived(response);
    css_resource->FinishForTest();
    MemoryCache::Get()->Add(css_resource);
    return css_resource;
  }

  Persistent<MemoryCache> original_memory_cache_;
};

TEST_F(CSSStyleSheetResourceTest, DuplicateResourceNotCached) {
  const char kUrl[] = "https://localhost/style.css";
  const KURL image_url(kUrl);
  const KURL css_url(kUrl);
  ResourceResponse response(css_url);
  response.SetMimeType(AtomicString("style/css"));

  // Emulate using <img> to do async stylesheet preloads.

  Resource* image_resource = ImageResource::CreateForTest(image_url);
  ASSERT_TRUE(image_resource);
  MemoryCache::Get()->Add(image_resource);
  ASSERT_TRUE(MemoryCache::Get()->Contains(image_resource));

  CSSStyleSheetResource* css_resource =
      CSSStyleSheetResource::CreateForTest(css_url, UTF8Encoding());
  css_resource->ResponseReceived(response);
  css_resource->FinishForTest();

  auto* parser_context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* contents = MakeGarbageCollected<StyleSheetContents>(parser_context);
  auto* sheet = MakeGarbageCollected<CSSStyleSheet>(contents, GetDocument());
  EXPECT_TRUE(sheet);

  contents->CheckLoaded();
  css_resource->SaveParsedStyleSheet(contents);

  // Verify that the cache will have a mapping for |imageResource| at |url|.
  // The underlying |contents| for the stylesheet resource must have a
  // matching reference status.
  EXPECT_TRUE(MemoryCache::Get()->Contains(image_resource));
  EXPECT_FALSE(MemoryCache::Get()->Contains(css_resource));
  EXPECT_FALSE(contents->IsReferencedFromResource());
  EXPECT_FALSE(css_resource->CreateParsedStyleSheetFromCache(parser_context));
}

TEST_F(CSSStyleSheetResourceTest, CreateFromCacheRestoresOriginalSheet) {
  CSSStyleSheetResource* css_resource = CreateAndSaveTestStyleSheetResource();

  auto* parser_context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* contents = MakeGarbageCollected<StyleSheetContents>(parser_context);
  auto* sheet = MakeGarbageCollected<CSSStyleSheet>(contents, GetDocument());
  ASSERT_TRUE(sheet);

  contents->ParseString("div { color: red; }");
  contents->NotifyLoadedSheet(css_resource);
  contents->CheckLoaded();
  EXPECT_TRUE(contents->IsCacheableForResource());

  css_resource->SaveParsedStyleSheet(contents);
  EXPECT_TRUE(MemoryCache::Get()->Contains(css_resource));
  EXPECT_TRUE(contents->IsReferencedFromResource());

  StyleSheetContents* parsed_stylesheet =
      css_resource->CreateParsedStyleSheetFromCache(parser_context);
  ASSERT_EQ(contents, parsed_stylesheet);
}

TEST_F(CSSStyleSheetResourceTest, CreateFromCacheWithMediaQueries) {
  CSSStyleSheetResource* css_resource = CreateAndSaveTestStyleSheetResource();

  auto* parser_context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* contents = MakeGarbageCollected<StyleSheetContents>(parser_context);
  auto* sheet = MakeGarbageCollected<CSSStyleSheet>(contents, GetDocument());
  ASSERT_TRUE(sheet);

  contents->ParseString("@media { div { color: red; } }");
  contents->NotifyLoadedSheet(css_resource);
  contents->CheckLoaded();
  EXPECT_TRUE(contents->IsCacheableForResource());

  contents->EnsureRuleSet(MediaQueryEvaluator(GetDocument().GetFrame()));
  EXPECT_TRUE(contents->HasRuleSet());

  css_resource->SaveParsedStyleSheet(contents);
  EXPECT_TRUE(MemoryCache::Get()->Contains(css_resource));
  EXPECT_TRUE(contents->IsReferencedFromResource());

  StyleSheetContents* parsed_stylesheet =
      css_resource->CreateParsedStyleSheetFromCache(parser_context);
  ASSERT_TRUE(parsed_stylesheet);

  sheet->ClearOwnerNode();
  sheet = MakeGarbageCollected<CSSStyleSheet>(parsed_stylesheet, GetDocument());
  ASSERT_TRUE(sheet);

  EXPECT_TRUE(contents->HasSingleOwnerDocument());
  EXPECT_EQ(1U, contents->ClientSize());
  EXPECT_TRUE(contents->IsReferencedFromResource());
  EXPECT_TRUE(contents->HasRuleSet());

  EXPECT_TRUE(parsed_stylesheet->HasSingleOwnerDocument());
  EXPECT_TRUE(parsed_stylesheet->HasOneClient());
  EXPECT_TRUE(parsed_stylesheet->IsReferencedFromResource());
  EXPECT_TRUE(parsed_stylesheet->HasRuleSet());
}

class CSSStyleSheetResourceSimTest : public SimTest {};

TEST_F(CSSStyleSheetResourceSimTest, CachedWithDifferentMQEval) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame1_resource("https://example.com/frame1.html", "text/html");
  SimRequest frame2_resource("https://example.com/frame2.html", "text/html");

  SimRequest::Params params;
  params.response_http_headers = {{"Cache-Control", "max-age=3600"}};
  SimSubresourceRequest css_resource("https://example.com/frame.css",
                                     "text/css", params);

  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #frame1 {
        width: 200px;
        height: 200px;
      }
      #frame2 {
        width: 400px;
        height: 200px;
      }
    </style>
    <div></div>
    <iframe id="frame1" src="frame1.html"></iframe>
    <iframe id="frame2" src="frame2.html"></iframe>
  )HTML");

  frame1_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <link rel="stylesheet" href="frame.css">
    <div id="target"></div>
  )HTML");

  css_resource.Complete(R"HTML(
    #target { opacity: 0; }
    @media (width > 300px) {
      #target { opacity: 0.3; }
    }
    @media (width > 500px) {
      #target { opacity: 0.5; }
    }
  )HTML");

  test::RunPendingTasks();

  frame2_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <link rel="stylesheet" href="frame.css">
    <div id="target"></div>
  )HTML");

  test::RunPendingTasks();

  Compositor().BeginFrame();

  Document* frame1_doc = To<HTMLIFrameElement>(GetDocument().getElementById(
                                                   AtomicString("frame1")))
                             ->contentDocument();
  Document* frame2_doc = To<HTMLIFrameElement>(GetDocument().getElementById(
                                                   AtomicString("frame2")))
                             ->contentDocument();
  ASSERT_TRUE(frame1_doc);
  ASSERT_TRUE(frame2_doc);
  frame1_doc->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  frame2_doc->UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  const ActiveStyleSheetVector& frame1_sheets =
      frame1_doc->GetScopedStyleResolver()->GetActiveStyleSheets();
  const ActiveStyleSheetVector& frame2_sheets =
      frame2_doc->GetScopedStyleResolver()->GetActiveStyleSheets();
  ASSERT_EQ(frame1_sheets.size(), 1u);
  ASSERT_EQ(frame2_sheets.size(), 1u);

  // The two frames should share the same cached StyleSheetContents ...
  EXPECT_EQ(frame1_sheets[0].first->Contents(),
            frame2_sheets[0].first->Contents());

  // ... but have different RuleSets due to different media query evaluation.
  EXPECT_NE(frame1_sheets[0].second, frame2_sheets[0].second);

  // Verify styling based on MQ evaluation.
  Element* target1 = frame1_doc->getElementById(AtomicString("target"));
  ASSERT_TRUE(target1);
  EXPECT_EQ(target1->GetComputedStyle()->Opacity(), 0);
  Element* target2 = frame2_doc->getElementById(AtomicString("target"));
  ASSERT_TRUE(target2);
  EXPECT_EQ(target2->GetComputedStyle()->Opacity(), 0.3f);
}

}  // namespace
}  // namespace blink
```