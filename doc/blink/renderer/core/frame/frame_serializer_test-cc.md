Response:
Let's break down the thought process for analyzing the `frame_serializer_test.cc` file.

1. **Understand the Goal:** The file name `frame_serializer_test.cc` immediately tells us this is a *test* file. Specifically, it's testing something called `FrameSerializer`. This is the core piece of information we need to start.

2. **Identify the Tested Class:** The `#include "third_party/blink/renderer/core/frame/frame_serializer.h"` line confirms that the class being tested is indeed `FrameSerializer`.

3. **Determine the Testing Framework:**  The presence of `#include "testing/gmock/include/gmock/gmock.h"` and `#include "testing/gtest/include/gtest/gtest.h"` indicates that the file uses Google Test and Google Mock frameworks for its tests. This tells us we'll likely see `TEST_F` macros defining individual test cases and `EXPECT_...` macros for assertions.

4. **Infer Functionality from the Test Structure:** Scan the `TEST_F` definitions. Each test case name usually hints at what aspect of `FrameSerializer` is being tested. For example:
    * `HTMLElements`:  Likely tests how `FrameSerializer` handles various HTML elements.
    * `Frames`:  Probably tests the serialization of frames and iframes.
    * `CSS`: Tests how CSS and its resources (like background images) are handled.
    * `DataURI`:  Tests serialization of resources embedded directly in the HTML using `data:` URLs.

5. **Analyze Setup and Helper Functions:** Look for the `SetUp()` and `TearDown()` methods in the `FrameSerializerTest` class. These provide insights into the test environment setup and cleanup. The helper functions like `RegisterURL`, `RegisterErrorURL`, `Serialize`, `GetResources`, etc., reveal how test data is managed and how the serialization process is triggered and examined.

6. **Connect to Web Technologies (HTML, CSS, JavaScript):** As the file is in the `blink/renderer/core` directory, it's part of the rendering engine. This means `FrameSerializer` likely deals with the visual representation of web pages. The test case names and the helper functions clearly demonstrate this connection:
    * HTML elements are explicitly tested.
    * CSS files and embedded styles are handled.
    * Images are loaded and serialized.
    * Frames (and their impact on the DOM structure) are considered.

7. **Look for Specific Examples and Assertions:**  Within each `TEST_F`, examine the `RegisterURL` calls and the `EXPECT_THAT` or `EXPECT_TRUE/FALSE` assertions. These provide concrete examples of inputs and expected outputs. For instance, in the `HTMLElements` test:
    * `RegisterURL("elements.html", "text/html")` sets up the main HTML file.
    * `RegisterURL("style.css", "style.css", "text/css")` sets up a linked CSS file.
    * `EXPECT_THAT(GetResourceUrlAndMimeTypes(), ...)` asserts that the correct URLs and MIME types of the serialized resources are present.

8. **Identify Edge Cases and Error Handling:**  Note any tests that involve error scenarios, such as `RegisterErrorURL`. This suggests `FrameSerializer` needs to handle cases where resources fail to load.

9. **Infer Logical Reasoning and Assumptions:**  Consider the overall goal of serialization. The code seems to assume that when a web page is serialized, all its necessary resources (HTML, CSS, images, etc.) should be captured. The tests verify this assumption for different scenarios. The test names also imply assumptions about how different HTML features should be serialized.

10. **Consider Potential User/Programming Errors:** Think about common mistakes developers might make when dealing with web pages. For example:
    * Incorrect paths to resources.
    * Missing resources.
    * Different character encodings.
    * Mixing HTTP and HTTPS (though not explicitly shown in *these* tests, this is a common web issue). The tests with error URLs simulate some of these.

11. **Structure the Explanation:** Organize the findings into logical sections: Functionality, Relationship to Web Technologies, Logic and Assumptions, Common Errors. Use clear and concise language, providing specific code snippets or examples where relevant.

12. **Refine and Review:**  Read through the explanation to ensure accuracy and completeness. Double-check the connections between the test code and the real-world web technologies.

By following these steps, we can effectively analyze the `frame_serializer_test.cc` file and understand its purpose, functionality, and relationship to web development concepts.
这个文件 `blink/renderer/core/frame/frame_serializer_test.cc` 是 Chromium Blink 引擎中 `FrameSerializer` 类的单元测试文件。它的主要功能是**测试 `FrameSerializer` 类是否能正确地将一个 Frame（可以理解为一个网页或其内部的 iframe）及其依赖的资源序列化为一种特定的格式，通常用于保存网页为离线或 MHTML 格式。**

更具体地说，这个测试文件会创建各种不同的网页场景，然后使用 `FrameSerializer` 将这些场景序列化，并验证序列化后的结果是否符合预期。

以下是该文件功能的详细列表，并附带与 JavaScript, HTML, CSS 关系的举例说明：

**功能列表:**

1. **测试基本的 HTML 结构序列化:**
   - 验证 `FrameSerializer` 能否正确提取和保存 HTML 文档的内容，包括各种 HTML 标签、属性和文本。
   - **与 HTML 关系:** 测试用例会加载包含不同 HTML 元素（如 `<div>`, `<p>`, `<img>`, `<link>`, `<script>`, `<iframe>` 等）的 HTML 文件，并断言这些元素是否被正确序列化。
   - **举例:** `TEST_F(FrameSerializerTest, HTMLElements)` 测试用例加载 `elements.html`，其中包含了各种 HTML 元素，然后验证这些元素引用的 CSS、图片等资源是否被正确捕获。

2. **测试 CSS 样式及其资源的序列化:**
   - 验证 `FrameSerializer` 能否正确提取和保存外部 CSS 文件、内联样式、以及 CSS 中引用的资源（如背景图片、字体文件）。
   - **与 CSS 关系:** 测试用例会加载包含 `<link>` 标签引入的外部 CSS 文件，以及 `<style>` 标签定义的内联样式，并断言这些 CSS 文件及其引用的图片等资源是否被正确序列化。
   - **举例:** `TEST_F(FrameSerializerTest, CSS)` 测试用例加载 `css_test_page.html`，该页面链接了多个 CSS 文件，并定义了一些内联样式，测试会验证这些 CSS 文件和其中引用的背景图片是否被正确序列化。

3. **测试 JavaScript 脚本的处理:**
   - 验证 `FrameSerializer` 在序列化过程中如何处理 JavaScript 脚本，通常 JavaScript 本身不会被直接序列化为单独的资源，而是作为 HTML 的一部分被保存。
   - **与 JavaScript 关系:**  虽然这个测试文件主要关注资源序列化，但它隐含地测试了 `FrameSerializer` 在遇到 `<script>` 标签时的行为。
   - **举例:** 在 `TEST_F(FrameSerializerTest, MHTMLImprovedHTMLElements)` 中，开启了 `kMHTML_Improvements` 特性后，测试断言 JavaScript 脚本的 URL（如果存在）也被视为一个资源。

4. **测试不同类型的资源序列化:**
   - 验证 `FrameSerializer` 能否正确处理各种类型的资源，如图片 (`<img>`)、iframe (`<iframe>`, `<frame>`, `<object>`, `<embed>`)、字体文件 (`@font-face`)、以及通过 `data:` URL 嵌入的资源。
   - **与 HTML/CSS 关系:** 这些资源通常通过 HTML 标签的属性（如 `src`, `href`）或 CSS 样式规则（如 `background-image`, `url()`）引用。
   - **举例:**
     - `TEST_F(FrameSerializerTest, Frames)` 和 `TEST_F(FrameSerializerTest, IFrames)` 测试 iframe 和 frame 的序列化，验证其内容和引用的资源是否被捕获。
     - `TEST_F(FrameSerializerTest, Font)` 测试字体文件的序列化。
     - `TEST_F(FrameSerializerTest, DataURI)` 测试 `data:` URL 嵌入资源的序列化。

5. **测试跨 Frame 的资源引用:**
   - 验证 `FrameSerializer` 在处理包含多个 frame 或 iframe 的页面时，能否正确地识别和序列化所有 frame 中的资源。
   - **与 HTML 关系:** 这涉及到 `<frame>` 和 `<iframe>` 标签的使用。
   - **举例:** `TEST_F(FrameSerializerTest, Frames)` 和 `TEST_F(FrameSerializerTest, IFrames)` 都在测试跨 frame 的资源处理。

6. **测试资源加载失败的情况:**
   - 验证 `FrameSerializer` 在遇到资源加载失败（如 404 错误）时的处理方式，通常不会序列化加载失败的资源。
   - **与 HTML/CSS 关系:** 当 HTML 或 CSS 中引用的资源无法加载时，测试会验证 `FrameSerializer` 是否跳过这些资源。
   - **举例:** `TEST_F(FrameSerializerTest, HTMLElements)` 中注册了 `style_network_error.css` 的 404 错误，测试会验证该 CSS 文件是否仍然被记录为需要序列化的资源。 `TEST_F(FrameSerializerTest, DontIncludeErrorImage)` 测试了加载失败的图片是否不会被包含在序列化结果中。

7. **测试特殊情况和边缘情况:**
   - 包括 SVG 图片、命名空间元素、包含 XML 声明的文档、包含 DTD 的文档等。
   - **与 HTML/CSS 关系:** 这些测试覆盖了 HTML 和相关技术中更复杂或不常见的用法。
   - **举例:**
     - `TEST_F(FrameSerializerTest, SVGImageDontCrash)` 测试包含 SVG 图片的页面。
     - `TEST_F(FrameSerializerTest, NamespaceElementsDontCrash)` 测试包含命名空间元素的页面。
     - `TEST_F(FrameSerializerTest, XMLDeclaration)` 测试包含 XML 声明的 XML 文档。
     - `TEST_F(FrameSerializerTest, DTD)` 测试包含 DTD 的 HTML 文档。

**逻辑推理的假设输入与输出:**

假设输入是一个包含以下内容的 HTML 文件 (`test.html`):

```html
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <img src="image.png">
    <script>console.log("Hello");</script>
</body>
</html>
```

并且存在一个 `style.css` 文件和一个 `image.png` 文件。

**假设输入:** `test.html`, `style.css`, `image.png`

**预期输出 (简化):** `FrameSerializer` 应该能够生成一个包含以下内容的序列化结果（例如 MHTML 格式），它会包含：

- `test.html` 的内容，可能将外部资源引用替换为内容 ID 或其他标识符。
- `style.css` 的内容。
- `image.png` 的二进制数据。

**用户或编程常见的使用错误 (可能由 `FrameSerializer` 处理或需要考虑的情况):**

1. **错误的资源路径:** 如果 HTML 或 CSS 文件中引用的资源路径不正确，`FrameSerializer` 可能会尝试加载但失败。测试用例 `TEST_F(FrameSerializerTest, DontIncludeErrorImage)` 就模拟了这种情况。
   - **举例:**  在 `test.html` 中将 `<img>` 标签的 `src` 属性设置为 `imag.png` (拼写错误)，`FrameSerializer` 将无法找到该图片。

2. **跨域资源引用:**  浏览器通常有跨域安全限制。`FrameSerializer` 需要考虑如何处理跨域引用的资源，是否允许序列化，或者需要进行特殊处理。

3. **循环引用:** 如果存在资源之间的循环引用（例如，CSS 文件 A 引用 CSS 文件 B，而 CSS 文件 B 又引用 CSS 文件 A），`FrameSerializer` 需要避免无限循环。

4. **字符编码问题:**  确保序列化后的内容使用正确的字符编码，避免出现乱码。测试用例 `TEST_F(FrameSerializerTest, CSS)` 中检查了 CSS 文件的 `@charset` 声明。

5. **大型资源:**  处理非常大的资源时，需要考虑内存消耗和性能问题。

6. **动态生成的内容:**  `FrameSerializer` 通常处理的是页面加载完成时的静态内容。对于 JavaScript 动态生成的内容，可能需要特殊的处理或限制。

7. **Service Workers 和 Cache API:**  现代 Web 应用可能会使用 Service Workers 和 Cache API 来管理资源缓存。`FrameSerializer` 的行为可能受到这些机制的影响。

总而言之，`frame_serializer_test.cc` 通过一系列的单元测试，确保 `FrameSerializer` 能够可靠地将网页及其资源转换为可保存或传输的格式，这对于诸如“保存网页为离线访问”之类的功能至关重要。这些测试覆盖了 HTML、CSS、JavaScript 以及各种资源类型，并考虑了常见的边缘情况和错误场景。

### 提示词
```
这是目录为blink/renderer/core/frame/frame_serializer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (c) 2013, Opera Software ASA. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Opera Software ASA nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/frame/frame_serializer.h"

#include <string>

#include "base/run_loop.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/mhtml/serialized_resource.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
namespace {
using testing::Eq;
using testing::Pair;

class FrameSerializerTest
    : public testing::Test,
      public WebFrameSerializer::MHTMLPartsGenerationDelegate {
 public:
  FrameSerializerTest()
      : folder_("frameserializer/"),
        base_url_(url_test_helpers::ToKURL("http://www.test.com")) {}

  ~FrameSerializerTest() override {
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

 protected:
  void SetUp() override {
    // We want the images to load.
    helper_.InitializeWithSettings(&ConfigureSettings);
  }

  void TearDown() override {
    URLLoaderMockFactory::GetSingletonInstance()
        ->UnregisterAllURLsAndClearMemoryCache();
    helper_.Reset();
  }

  void SetBaseFolder(const char* folder) { folder_ = folder; }

  void RegisterURL(const KURL& url, const char* file, const char* mime_type) {
    url_test_helpers::RegisterMockedURLLoad(
        url, test::CoreTestDataPath(WebString::FromUTF8(folder_ + file)),
        WebString::FromUTF8(mime_type));
  }

  void RegisterURL(const char* url, const char* file, const char* mime_type) {
    RegisterURL(KURL(base_url_, url), file, mime_type);
  }

  void RegisterURL(const char* file, const char* mime_type) {
    RegisterURL(file, file, mime_type);
  }

  void RegisterErrorURL(const char* file, int status_code) {
    ResourceError error = ResourceError::Failure(NullURL());

    WebURLResponse response;
    response.SetMimeType("text/html");
    response.SetHttpStatusCode(status_code);

    URLLoaderMockFactory::GetSingletonInstance()->RegisterErrorURL(
        KURL(base_url_, file), response, WebURLError(error));
  }

  void RegisterSkipURL(const char* url) {
    skip_urls_.insert(KURL(base_url_, url));
  }

  void Serialize(const char* url) {
    frame_test_helpers::LoadFrame(
        helper_.GetWebView()->MainFrameImpl(),
        KURL(base_url_, url).GetString().Utf8().c_str());
    // Sometimes we have iframes created in "onload" handler - wait for them to
    // load.
    frame_test_helpers::PumpPendingRequestsForFrameToLoad(
        helper_.GetWebView()->MainFrameImpl());
    Frame* frame = helper_.LocalMainFrame()->GetFrame();
    for (; frame; frame = frame->Tree().TraverseNext()) {
      // This is safe, because tests do not do cross-site navigation
      // (and therefore don't have remote frames).
      base::RunLoop run_loop;
      FrameSerializer::SerializeFrame(
          *this, *To<LocalFrame>(frame),
          base::BindLambdaForTesting([&](Deque<SerializedResource> resources) {
            for (auto& res : resources) {
              resources_.push_back(res);
              // Don't serialize the same resource on subsequent frames. This
              // mimics how FrameSerializer is actually used.
              skip_urls_.insert(res.url);
            }
            run_loop.Quit();
          }));
      URLLoaderMockFactory::GetSingletonInstance()->ServeAsynchronousRequests();
      run_loop.Run();
    }
  }

  Deque<SerializedResource>& GetResources() { return resources_; }
  Vector<std::pair<KURL, String>> GetResourceUrlAndMimeTypes() const {
    Vector<std::pair<KURL, String>> result;
    for (const SerializedResource& r : resources_) {
      result.emplace_back(r.url, r.mime_type);
    }
    return result;
  }
  const SerializedResource* GetResource(const KURL& url,
                                        const char* mime_type) {
    String mime(mime_type);
    for (const SerializedResource& resource : resources_) {
      if (resource.url == url && !resource.data->empty() &&
          (mime.IsNull() || EqualIgnoringASCIICase(resource.mime_type, mime)))
        return &resource;
    }
    return nullptr;
  }

  const SerializedResource* GetResource(const char* url_string,
                                        const char* mime_type) {
    return GetResource(ResourceURL(url_string), mime_type);
  }

  bool IsSerialized(const char* url, const char* mime_type = nullptr) {
    return GetResource(url, mime_type);
  }

  String GetSerializedData(const char* url, const char* mime_type = nullptr) {
    const SerializedResource* resource = GetResource(url, mime_type);
    if (resource) {
      const Vector<char> data = resource->data->CopyAs<Vector<char>>();
      return String(data);
    }
    return String();
  }

  KURL ResourceURL(const String& resource_name) const {
    return KURL(base_url_, resource_name);
  }

 private:
  static void ConfigureSettings(WebSettings* settings) {
    settings->SetImagesEnabled(true);
    settings->SetLoadsImagesAutomatically(true);
    settings->SetJavaScriptEnabled(true);
  }

  // WebFrameSerializer::MHTMLPartsGenerationDelegate impl.
  bool ShouldSkipResource(const WebURL& url) override {
    return skip_urls_.Contains(url.GetString());
  }
  bool UseBinaryEncoding() override { return false; }

  bool RemovePopupOverlay() override { return false; }

  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;
  frame_test_helpers::WebViewHelper helper_;
  std::string folder_;
  KURL base_url_;
  Deque<SerializedResource> resources_;
  HashSet<String> skip_urls_;
};

TEST_F(FrameSerializerTest, HTMLElements) {
  SetBaseFolder("frameserializer/elements/");

  RegisterURL("elements.html", "text/html");
  RegisterURL("style.css", "style.css", "text/css");
  RegisterErrorURL("style_network_error.css", 404);
  RegisterURL("copyright.html", "empty.txt", "text/html");
  RegisterURL("script.js", "empty.txt", "text/javascript");

  RegisterURL("bodyBackground.png", "image.png", "image/png");

  RegisterURL("imageSrc.png", "image.png", "image/png");

  RegisterURL("inputImage.png", "image.png", "image/png");

  RegisterURL("tableBackground.png", "image.png", "image/png");
  RegisterURL("trBackground.png", "image.png", "image/png");
  RegisterURL("tdBackground.png", "image.png", "image/png");

  RegisterURL("blockquoteCite.html", "empty.txt", "text/html");
  RegisterURL("qCite.html", "empty.txt", "text/html");
  RegisterURL("delCite.html", "empty.txt", "text/html");
  RegisterURL("insCite.html", "empty.txt", "text/html");

  RegisterErrorURL("nonExisting.png", 404);

  Serialize("elements.html");
  EXPECT_THAT(GetResourceUrlAndMimeTypes(),
              testing::UnorderedElementsAre(
                  Pair(ResourceURL("elements.html"), "text/html"),
                  Pair(ResourceURL("style.css"), "text/css"),
                  Pair(ResourceURL("bodyBackground.png"), "image/png"),
                  Pair(ResourceURL("imageSrc.png"), "image/png"),
                  Pair(ResourceURL("inputImage.png"), "image/png"),
                  Pair(ResourceURL("tableBackground.png"), "image/png"),
                  Pair(ResourceURL("trBackground.png"), "image/png"),
                  Pair(ResourceURL("tdBackground.png"), "image/png"),
                  Pair(ResourceURL("style_network_error.css"), "text/css")));
}

TEST_F(FrameSerializerTest, MHTMLImprovedHTMLElements) {
  base::test::ScopedFeatureList features(
      {blink::features::kMHTML_Improvements});
  SetBaseFolder("frameserializer/elements/");

  RegisterURL("elements.html", "text/html");
  RegisterURL("style.css", "style.css", "text/css");
  RegisterErrorURL("style_network_error.css", 404);
  RegisterURL("copyright.html", "empty.txt", "text/html");
  RegisterURL("script.js", "empty.txt", "text/javascript");

  RegisterURL("bodyBackground.png", "image.png", "image/png");

  RegisterURL("imageSrc.png", "image.png", "image/png");

  RegisterURL("inputImage.png", "image.png", "image/png");

  RegisterURL("tableBackground.png", "image.png", "image/png");
  RegisterURL("trBackground.png", "image.png", "image/png");
  RegisterURL("tdBackground.png", "image.png", "image/png");

  RegisterURL("blockquoteCite.html", "empty.txt", "text/html");
  RegisterURL("qCite.html", "empty.txt", "text/html");
  RegisterURL("delCite.html", "empty.txt", "text/html");
  RegisterURL("insCite.html", "empty.txt", "text/html");

  RegisterErrorURL("nonExisting.png", 404);

  Serialize("elements.html");

  EXPECT_THAT(GetResourceUrlAndMimeTypes(),
              testing::UnorderedElementsAre(
                  Pair(ResourceURL("elements.html"), "text/html"),
                  Pair(ResourceURL("style.css"), "text/css"),
                  Pair(ResourceURL("bodyBackground.png"), "image/png"),
                  Pair(ResourceURL("imageSrc.png"), "image/png"),
                  Pair(ResourceURL("inputImage.png"), "image/png"),
                  Pair(ResourceURL("tableBackground.png"), "image/png"),
                  Pair(ResourceURL("trBackground.png"), "image/png"),
                  Pair(ResourceURL("tdBackground.png"), "image/png"),
                  Pair(testing::Property(&KURL::IsValid, Eq(true)),
                       "text/javascript")));
}

TEST_F(FrameSerializerTest, Frames) {
  SetBaseFolder("frameserializer/frames/");

  RegisterURL("simple_frames.html", "text/html");
  RegisterURL("simple_frames_top.html", "text/html");
  RegisterURL("simple_frames_1.html", "text/html");
  RegisterURL("simple_frames_3.html", "text/html");

  RegisterURL("frame_1.png", "image.png", "image/png");
  RegisterURL("frame_2.png", "image.png", "image/png");
  RegisterURL("frame_3.png", "image.png", "image/png");
  RegisterURL("frame_4.png", "image.png", "image/png");

  Serialize("simple_frames.html");

  EXPECT_EQ(8U, GetResources().size());

  EXPECT_TRUE(IsSerialized("simple_frames.html", "text/html"));
  EXPECT_TRUE(IsSerialized("simple_frames_top.html", "text/html"));
  EXPECT_TRUE(IsSerialized("simple_frames_1.html", "text/html"));
  EXPECT_TRUE(IsSerialized("simple_frames_3.html", "text/html"));

  EXPECT_TRUE(IsSerialized("frame_1.png", "image/png"));
  EXPECT_TRUE(IsSerialized("frame_2.png", "image/png"));
  EXPECT_TRUE(IsSerialized("frame_3.png", "image/png"));
  EXPECT_TRUE(IsSerialized("frame_4.png", "image/png"));

  // Verify all 3 frame src are rewritten to Content ID URLs.
  Vector<String> split_string;
  GetSerializedData("simple_frames.html", "text/html")
      .Split("<frame src=\"cid:", split_string);
  EXPECT_EQ(split_string.size(), 4u);
}

TEST_F(FrameSerializerTest, IFrames) {
  SetBaseFolder("frameserializer/frames/");

  RegisterURL("top_frame.html", "text/html");
  RegisterURL("simple_iframe.html", "text/html");
  RegisterURL("object_iframe.html", "text/html");
  RegisterURL("embed_iframe.html", "text/html");
  RegisterURL("encoded_iframe.html", "text/html");

  RegisterURL("top.png", "image.png", "image/png");
  RegisterURL("simple.png", "image.png", "image/png");
  RegisterURL("object.png", "image.png", "image/png");
  RegisterURL("embed.png", "image.png", "image/png");

  Serialize("top_frame.html");

  EXPECT_EQ(10U, GetResources().size());

  EXPECT_TRUE(IsSerialized("top_frame.html", "text/html"));
  EXPECT_TRUE(IsSerialized("simple_iframe.html", "text/html"));  // Twice.
  EXPECT_TRUE(IsSerialized("object_iframe.html", "text/html"));
  EXPECT_TRUE(IsSerialized("embed_iframe.html", "text/html"));
  EXPECT_TRUE(IsSerialized("encoded_iframe.html", "text/html"));

  EXPECT_TRUE(IsSerialized("top.png", "image/png"));
  EXPECT_TRUE(IsSerialized("simple.png", "image/png"));
  EXPECT_TRUE(IsSerialized("object.png", "image/png"));
  EXPECT_TRUE(IsSerialized("embed.png", "image/png"));

  // Ensure that frame contents are not NFC-normalized before encoding.
  String expected_meta_charset =
      "<meta http-equiv=\"Content-Type\" content=\"text/html; "
      "charset=EUC-KR\">";
  EXPECT_TRUE(GetSerializedData("encoded_iframe.html", "text/html")
                  .Contains(expected_meta_charset));
  EXPECT_TRUE(GetSerializedData("encoded_iframe.html", "text/html")
                  .Contains("\xE4\xC5\xD1\xE2"));
  EXPECT_FALSE(GetSerializedData("encoded_iframe.html", "text/html")
                   .Contains("\xE4\xC5\xE4\xC5"));
}

// Tests that when serializing a page with blank frames these are reported with
// their resources.
TEST_F(FrameSerializerTest, BlankFrames) {
  SetBaseFolder("frameserializer/frames/");

  RegisterURL("blank_frames.html", "text/html");
  RegisterURL("red_background.png", "image.png", "image/png");
  RegisterURL("orange_background.png", "image.png", "image/png");
  RegisterURL("blue_background.png", "image.png", "image/png");

  Serialize("blank_frames.html");

  EXPECT_EQ(7U, GetResources().size());

  EXPECT_TRUE(
      IsSerialized("http://www.test.com/red_background.png", "image/png"));
  EXPECT_TRUE(
      IsSerialized("http://www.test.com/orange_background.png", "image/png"));
  EXPECT_TRUE(
      IsSerialized("http://www.test.com/blue_background.png", "image/png"));

  // The blank frames no longer get magic URL (i.e. wyciwyg://frame/0), so we
  // can't really assert their presence via URL.  We also can't use content-id
  // in assertions (since it is not deterministic).  Therefore we need to rely
  // on getResources().size() assertion above and on browser-level tests
  // (i.e. SavePageMultiFrameBrowserTest.AboutBlank).
}

TEST_F(FrameSerializerTest, CSS) {
  SetBaseFolder("frameserializer/css/");

  RegisterURL("css_test_page.html", "text/html");
  RegisterURL("link_styles.css", "text/css");
  RegisterURL("encoding.css", "text/css");
  RegisterURL("import_style_from_link.css", "text/css");
  RegisterURL("import_styles.css", "text/css");
  RegisterURL("do_not_serialize.png", "image.png", "image/png");
  RegisterURL("red_background.png", "image.png", "image/png");
  RegisterURL("orange_background.png", "image.png", "image/png");
  RegisterURL("yellow_background.png", "image.png", "image/png");
  RegisterURL("green_background.png", "image.png", "image/png");
  RegisterURL("blue_background.png", "image.png", "image/png");
  RegisterURL("purple_background.png", "image.png", "image/png");
  RegisterURL("pink_background.png", "image.png", "image/png");
  RegisterURL("brown_background.png", "image.png", "image/png");
  RegisterURL("ul-dot.png", "image.png", "image/png");
  RegisterURL("ol-dot.png", "image.png", "image/png");

  const KURL image_url_from_data_url(
      url_test_helpers::ToKURL("http://www.dataurl.com"),
      "fuchsia_background.png");
  RegisterURL(image_url_from_data_url, "image.png", "image/png");

  RegisterURL("included_in_another_frame.css", "text/css");
  RegisterSkipURL("included_in_another_frame.css");

  Serialize("css_test_page.html");

  // 16 resoucres added by RegisterURL + 3 resources added due to converting
  // style elements to link elements.
  EXPECT_EQ(19U, GetResources().size());

  EXPECT_FALSE(IsSerialized("do_not_serialize.png", "image/png"));
  EXPECT_FALSE(IsSerialized("included_in_another_frame.css", "text/css"));

  EXPECT_TRUE(IsSerialized("css_test_page.html", "text/html"));
  EXPECT_TRUE(IsSerialized("link_styles.css", "text/css"));
  EXPECT_TRUE(IsSerialized("encoding.css", "text/css"));
  EXPECT_TRUE(IsSerialized("import_styles.css", "text/css"));
  EXPECT_TRUE(IsSerialized("import_style_from_link.css", "text/css"));
  EXPECT_TRUE(IsSerialized("red_background.png", "image/png"));
  EXPECT_TRUE(IsSerialized("orange_background.png", "image/png"));
  EXPECT_TRUE(IsSerialized("yellow_background.png", "image/png"));
  EXPECT_TRUE(IsSerialized("green_background.png", "image/png"));
  EXPECT_TRUE(IsSerialized("blue_background.png", "image/png"));
  EXPECT_TRUE(IsSerialized("purple_background.png", "image/png"));
  EXPECT_TRUE(IsSerialized("pink_background.png", "image/png"));
  EXPECT_TRUE(IsSerialized("brown_background.png", "image/png"));
  EXPECT_TRUE(IsSerialized("ul-dot.png", "image/png"));
  EXPECT_TRUE(IsSerialized("ol-dot.png", "image/png"));

  EXPECT_TRUE(GetResource(image_url_from_data_url, "image/png"));

  // Ensure encodings are specified.
  EXPECT_TRUE(
      GetSerializedData("link_styles.css", "text/css").StartsWith("@charset"));
  EXPECT_TRUE(GetSerializedData("import_styles.css", "text/css")
                  .StartsWith("@charset"));
  EXPECT_TRUE(GetSerializedData("import_style_from_link.css", "text/css")
                  .StartsWith("@charset"));
  EXPECT_TRUE(GetSerializedData("encoding.css", "text/css")
                  .StartsWith("@charset \"euc-kr\";"));

  // Ensure that stylesheet contents are not NFC-normalized before encoding.
  EXPECT_TRUE(GetSerializedData("encoding.css", "text/css")
                  .Contains("\xE4\xC5\xD1\xE2"));
  EXPECT_FALSE(GetSerializedData("encoding.css", "text/css")
                   .Contains("\xE4\xC5\xE4\xC5"));
}

TEST_F(FrameSerializerTest, CSSImport) {
  SetBaseFolder("frameserializer/css/");

  RegisterURL("import.html", "text/html");
  RegisterURL("import/base.css", "text/css");
  RegisterURL("import/relative/red-background.css", "text/css");
  RegisterURL("import/absolute/green-header.css", "text/css");

  Serialize("import.html");

  EXPECT_TRUE(IsSerialized("import.html", "text/html"));
  EXPECT_TRUE(IsSerialized("import/base.css", "text/css"));
  EXPECT_TRUE(IsSerialized("import/relative/red-background.css", "text/css"));
  EXPECT_TRUE(IsSerialized("import/absolute/green-header.css", "text/css"));
}

TEST_F(FrameSerializerTest, XMLDeclaration) {
  V8TestingScope scope;
  SetBaseFolder("frameserializer/xml/");

  RegisterURL("xmldecl.xml", "text/xml");
  Serialize("xmldecl.xml");

  String expected_start("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
  EXPECT_TRUE(GetSerializedData("xmldecl.xml").StartsWith(expected_start));
}

TEST_F(FrameSerializerTest, DTD) {
  SetBaseFolder("frameserializer/dtd/");

  RegisterURL("html5.html", "text/html");
  Serialize("html5.html");

  String expected_start("<!DOCTYPE html>");
  EXPECT_TRUE(GetSerializedData("html5.html").StartsWith(expected_start));
}

TEST_F(FrameSerializerTest, Font) {
  SetBaseFolder("frameserializer/font/");

  RegisterURL("font.html", "text/html");
  RegisterURL("font.ttf", "application/octet-stream");

  Serialize("font.html");

  EXPECT_TRUE(IsSerialized("font.ttf", "application/octet-stream"));
}

TEST_F(FrameSerializerTest, DataURI) {
  SetBaseFolder("frameserializer/datauri/");

  RegisterURL("page_with_data.html", "text/html");

  Serialize("page_with_data.html");

  EXPECT_EQ(1U, GetResources().size());
  EXPECT_TRUE(IsSerialized("page_with_data.html", "text/html"));
}

TEST_F(FrameSerializerTest, DataURIMorphing) {
  SetBaseFolder("frameserializer/datauri/");

  RegisterURL("page_with_morphing_data.html", "text/html");

  Serialize("page_with_morphing_data.html");

  EXPECT_EQ(2U, GetResources().size());
  EXPECT_TRUE(IsSerialized("page_with_morphing_data.html", "text/html"));
}

// Test that we don't regress https://bugs.webkit.org/show_bug.cgi?id=99105
TEST_F(FrameSerializerTest, SVGImageDontCrash) {
  SetBaseFolder("frameserializer/svg/");

  RegisterURL("page_with_svg_image.html", "text/html");
  RegisterURL("green_rectangle.svg", "image/svg+xml");

  Serialize("page_with_svg_image.html");

  EXPECT_EQ(2U, GetResources().size());

  EXPECT_TRUE(IsSerialized("green_rectangle.svg", "image/svg+xml"));
  EXPECT_GT(GetSerializedData("green_rectangle.svg", "image/svg+xml").length(),
            250U);
}

TEST_F(FrameSerializerTest, DontIncludeErrorImage) {
  SetBaseFolder("frameserializer/image/");

  RegisterURL("page_with_img_error.html", "text/html");
  RegisterURL("error_image.png", "image/png");

  Serialize("page_with_img_error.html");

  EXPECT_EQ(1U, GetResources().size());
  EXPECT_TRUE(IsSerialized("page_with_img_error.html", "text/html"));
  EXPECT_FALSE(IsSerialized("error_image.png", "image/png"));
}

TEST_F(FrameSerializerTest, NamespaceElementsDontCrash) {
  SetBaseFolder("frameserializer/namespace/");

  RegisterURL("namespace_element.html", "text/html");

  Serialize("namespace_element.html");

  EXPECT_EQ(1U, GetResources().size());
  EXPECT_TRUE(IsSerialized("namespace_element.html", "text/html"));
  EXPECT_GT(GetSerializedData("namespace_element.html", "text/html").length(),
            0U);
}

TEST_F(FrameSerializerTest, markOfTheWebDeclaration) {
  EXPECT_EQ("saved from url=(0015)http://foo.com/",
            FrameSerializer::MarkOfTheWebDeclaration(KURL("http://foo.com")));
  EXPECT_EQ("saved from url=(0015)http://f-o.com/",
            FrameSerializer::MarkOfTheWebDeclaration(KURL("http://f-o.com")));
  EXPECT_EQ("saved from url=(0019)http://foo.com-%2D/",
            FrameSerializer::MarkOfTheWebDeclaration(KURL("http://foo.com--")));
  EXPECT_EQ(
      "saved from url=(0024)http://f-%2D.com-%2D%3E/",
      FrameSerializer::MarkOfTheWebDeclaration(KURL("http://f--.com-->")));
  EXPECT_EQ(
      "saved from url=(0020)http://foo.com/?-%2D",
      FrameSerializer::MarkOfTheWebDeclaration(KURL("http://foo.com?--")));
  EXPECT_EQ(
      "saved from url=(0020)http://foo.com/#-%2D",
      FrameSerializer::MarkOfTheWebDeclaration(KURL("http://foo.com#--")));
  EXPECT_EQ("saved from url=(0026)http://foo.com/#bar-%2Dbaz",
            FrameSerializer::MarkOfTheWebDeclaration(
                KURL("http://foo.com#bar--baz")));
}

TEST_F(FrameSerializerTest, ReplaceAllCaseInsensitive) {
  auto transform = [](const String& from) { return String("</HI>"); };
  EXPECT_EQ(
      blink::internal::ReplaceAllCaseInsensitive("", "</style>", transform),
      "");
  EXPECT_EQ(
      blink::internal::ReplaceAllCaseInsensitive("test", "</style>", transform),
      "test");
  EXPECT_EQ(blink::internal::ReplaceAllCaseInsensitive("</Style>", "</style>",
                                                       transform),
            "</HI>");
  EXPECT_EQ(blink::internal::ReplaceAllCaseInsensitive("x</Style>", "</style>",
                                                       transform),
            "x</HI>");
  EXPECT_EQ(blink::internal::ReplaceAllCaseInsensitive("</Style>x", "</style>",
                                                       transform),
            "</HI>x");
  EXPECT_EQ(blink::internal::ReplaceAllCaseInsensitive(
                "test</Style>test</Style>testagain", "</style>", transform),
            "test</HI>test</HI>testagain");
}

}  // namespace
}  // namespace blink
```