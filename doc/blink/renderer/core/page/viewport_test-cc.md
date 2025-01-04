Response:
The user wants to understand the functionality of the `viewport_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose, its relation to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning with inputs and outputs, highlight potential user or programming errors, and describe how a user's action can lead to the execution of this code. Finally, I need to summarize the overall function of this code based on the first part provided.

**Plan:**

1. **Identify the core functionality:** Look for keywords and patterns that reveal the purpose of the code. The file name `viewport_test.cc` and the included headers suggest it's a test file for viewport-related functionalities.
2. **Analyze the test structure:** Understand how the tests are defined and executed using the `testing::Test` framework.
3. **Examine the included headers:** Determine the Blink components and functionalities that are being tested. Headers like `web/web_settings.h`, `core/page/viewport_description.h`, and `core/frame/page_scale_constraints.h` are particularly relevant.
4. **Analyze the test cases:** Each `TEST_F` block represents a specific test case. I need to understand what each test case is verifying. The test names like `viewport6`, `viewport7`, etc., and the `RegisterMockedHttpURLLoad` calls suggest that these tests are loading different HTML files and checking how the viewport is being configured.
5. **Relate to web technologies:** Explain how the tested functionalities are connected to HTML's `<meta viewport>` tag, CSS media queries, and JavaScript's ability to interact with viewport properties.
6. **Provide logical reasoning examples:** Create hypothetical scenarios with HTML viewport configurations and the expected outcomes based on the test logic.
7. **Identify potential errors:** Consider common mistakes developers make when configuring viewports and how these tests help to prevent or detect those errors.
8. **Explain user interaction:** Describe the user actions that would trigger the browser to parse and apply viewport settings, leading to the execution of this test code during development and testing.
9. **Summarize the functionality:** Concisely describe the primary purpose of the `viewport_test.cc` file.
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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
 * contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/viewport_description.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "ui/base/ime/mojom/virtual_keyboard_types.mojom-blink.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

class ViewportTest : public testing::Test {
 protected:
  ViewportTest()
      : base_url_("http://www.test.com/"), chrome_url_("chrome://") {}

  ~ViewportTest() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  void RegisterMockedHttpURLLoad(const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via the WebViewHelper instance in each test case.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url_), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name));
  }

  void RegisterMockedChromeURLLoad(const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via the WebViewHelper instance in each test case.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(chrome_url_), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name));
  }

  void ExecuteScript(WebLocalFrame* frame, const WebString& code) {
    frame->ExecuteScript(WebScriptSource(code));
    blink::test::RunPendingTasks();
  }

  test::TaskEnvironment task_environment_;
  std::string base_url_;
  std::string chrome_url_;

 private:
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;
};

static void SetViewportSettings(WebSettings* settings) {
  settings->SetViewportEnabled(true);
  settings->SetViewportMetaEnabled(true);
  settings->SetMainFrameResizesAreOrientationChanges(true);
}

static PageScaleConstraints RunViewportTest(Page* page,
                                            int initial_width,
                                            int initial_height) {
  gfx::Size initial_viewport_size(initial_width, initial_height);
  To<LocalFrame>(page->MainFrame())
      ->View()
      ->SetFrameRect(gfx::Rect(gfx::Point(), initial_viewport_size));
  ViewportDescription description = page->GetViewportDescription();
  PageScaleConstraints constraints = description.Resolve(
      gfx::SizeF(initial_viewport_size), Length::Fixed(980));

  constraints.FitToContentsWidth(constraints.layout_size.width(),
                                 initial_width);
  constraints.ResolveAutoInitialScale();
  return constraints;
}

TEST_F(ViewportTest, viewport6) {
  RegisterMockedHttpURLLoad("viewport/viewport-6.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-6.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(200, constraints.layout_size.width());
  EXPECT_EQ(220, constraints.layout_size.height());
  EXPECT_NEAR(1.6f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.6f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport7) {
  RegisterMockedHttpURLLoad("viewport/viewport-7.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-7.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport8) {
  RegisterMockedHttpURLLoad("viewport/viewport-8.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-8.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport9) {
  RegisterMockedHttpURLLoad("viewport/viewport-9.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-9.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport10) {
  RegisterMockedHttpURLLoad("viewport/viewport-10.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-10.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport11) {
  RegisterMockedHttpURLLoad("viewport/viewport-11.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-11.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.32f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.32f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport12) {
  RegisterMockedHttpURLLoad("viewport/viewport-12.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-12.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(640, constraints.layout_size.width());
  EXPECT_EQ(704, constraints.layout_size.height());
  EXPECT_NEAR(0.5f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport13) {
  RegisterMockedHttpURLLoad("viewport/viewport-13.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-13.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport14) {
  RegisterMockedHttpURLLoad("viewport/viewport-14.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-14.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport15) {
  RegisterMockedHttpURLLoad("viewport/viewport-15.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-15.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport16) {
  RegisterMockedHttpURLLoad("viewport/viewport-16.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-16.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(5.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport17) {
  RegisterMockedHttpURLLoad("viewport/viewport-17.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-17.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(5.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport18) {
  RegisterMockedHttpURLLoad("viewport/viewport-18.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-18.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(64, constraints.layout_size.width());
  EXPECT_NEAR(70.4, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(5.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport19) {
  RegisterMockedHttpURLLoad("viewport/viewport-19.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-19.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(160, constraints.layout_size.width());
  EXPECT_EQ(176, constraints.layout_size.height());
  EXPECT_NEAR(2.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(2.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport20) {
  RegisterMockedHttpURLLoad("viewport/viewport-20.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-20.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport21) {
  RegisterMockedHttpURLLoad("viewport/viewport-21.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-21.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport22) {
  RegisterMockedHttpURLLoad("viewport/viewport-22.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-22.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport23) {
  RegisterMockedHttpURLLoad("viewport/viewport-23.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-23.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(3.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(3.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(3.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport24) {
  RegisterMockedHttpURLLoad("viewport/viewport-24.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-24.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(4.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(4.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(4.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport25) {
  RegisterMockedHttpURLLoad("viewport/viewport-25.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-25.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport26) {
  RegisterMockedHttpURLLoad("viewport/viewport-26.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-26.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(8.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(8.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(9.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport27) {
  RegisterMockedHttpURLLoad("viewport/viewport-27.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-27.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.32f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.32f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport28) {
  RegisterMockedHttpURLLoad("viewport/viewport-28.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-28.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(352, constraints.layout_size.width());
  EXPECT_NEAR(387.2, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(0.91f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.91f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport29) {
  RegisterMockedHttpURLLoad("viewport/viewport-29.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-29.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(700, constraints.layout_size.width());
  EXPECT_EQ(770, constraints.layout_size.height());
  EXPECT_NEAR(0.46f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.46f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(
Prompt: 
```
这是目录为blink/renderer/core/page/viewport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/viewport_description.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "ui/base/ime/mojom/virtual_keyboard_types.mojom-blink.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

class ViewportTest : public testing::Test {
 protected:
  ViewportTest()
      : base_url_("http://www.test.com/"), chrome_url_("chrome://") {}

  ~ViewportTest() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  void RegisterMockedHttpURLLoad(const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via the WebViewHelper instance in each test case.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url_), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name));
  }

  void RegisterMockedChromeURLLoad(const std::string& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via the WebViewHelper instance in each test case.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(chrome_url_), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name));
  }

  void ExecuteScript(WebLocalFrame* frame, const WebString& code) {
    frame->ExecuteScript(WebScriptSource(code));
    blink::test::RunPendingTasks();
  }

  test::TaskEnvironment task_environment_;
  std::string base_url_;
  std::string chrome_url_;

 private:
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;
};

static void SetViewportSettings(WebSettings* settings) {
  settings->SetViewportEnabled(true);
  settings->SetViewportMetaEnabled(true);
  settings->SetMainFrameResizesAreOrientationChanges(true);
}

static PageScaleConstraints RunViewportTest(Page* page,
                                            int initial_width,
                                            int initial_height) {
  gfx::Size initial_viewport_size(initial_width, initial_height);
  To<LocalFrame>(page->MainFrame())
      ->View()
      ->SetFrameRect(gfx::Rect(gfx::Point(), initial_viewport_size));
  ViewportDescription description = page->GetViewportDescription();
  PageScaleConstraints constraints = description.Resolve(
      gfx::SizeF(initial_viewport_size), Length::Fixed(980));

  constraints.FitToContentsWidth(constraints.layout_size.width(),
                                 initial_width);
  constraints.ResolveAutoInitialScale();
  return constraints;
}

TEST_F(ViewportTest, viewport6) {
  RegisterMockedHttpURLLoad("viewport/viewport-6.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-6.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(200, constraints.layout_size.width());
  EXPECT_EQ(220, constraints.layout_size.height());
  EXPECT_NEAR(1.6f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.6f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport7) {
  RegisterMockedHttpURLLoad("viewport/viewport-7.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-7.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport8) {
  RegisterMockedHttpURLLoad("viewport/viewport-8.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-8.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport9) {
  RegisterMockedHttpURLLoad("viewport/viewport-9.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-9.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport10) {
  RegisterMockedHttpURLLoad("viewport/viewport-10.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-10.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport11) {
  RegisterMockedHttpURLLoad("viewport/viewport-11.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-11.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.32f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.32f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport12) {
  RegisterMockedHttpURLLoad("viewport/viewport-12.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-12.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(640, constraints.layout_size.width());
  EXPECT_EQ(704, constraints.layout_size.height());
  EXPECT_NEAR(0.5f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport13) {
  RegisterMockedHttpURLLoad("viewport/viewport-13.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-13.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport14) {
  RegisterMockedHttpURLLoad("viewport/viewport-14.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-14.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport15) {
  RegisterMockedHttpURLLoad("viewport/viewport-15.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-15.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport16) {
  RegisterMockedHttpURLLoad("viewport/viewport-16.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-16.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(5.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport17) {
  RegisterMockedHttpURLLoad("viewport/viewport-17.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-17.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(5.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport18) {
  RegisterMockedHttpURLLoad("viewport/viewport-18.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-18.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(64, constraints.layout_size.width());
  EXPECT_NEAR(70.4, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(5.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport19) {
  RegisterMockedHttpURLLoad("viewport/viewport-19.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-19.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(160, constraints.layout_size.width());
  EXPECT_EQ(176, constraints.layout_size.height());
  EXPECT_NEAR(2.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(2.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport20) {
  RegisterMockedHttpURLLoad("viewport/viewport-20.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-20.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport21) {
  RegisterMockedHttpURLLoad("viewport/viewport-21.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-21.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport22) {
  RegisterMockedHttpURLLoad("viewport/viewport-22.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-22.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport23) {
  RegisterMockedHttpURLLoad("viewport/viewport-23.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-23.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(3.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(3.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(3.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport24) {
  RegisterMockedHttpURLLoad("viewport/viewport-24.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-24.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(4.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(4.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(4.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport25) {
  RegisterMockedHttpURLLoad("viewport/viewport-25.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-25.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport26) {
  RegisterMockedHttpURLLoad("viewport/viewport-26.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-26.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(8.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(8.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(9.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport27) {
  RegisterMockedHttpURLLoad("viewport/viewport-27.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-27.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.32f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.32f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport28) {
  RegisterMockedHttpURLLoad("viewport/viewport-28.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-28.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(352, constraints.layout_size.width());
  EXPECT_NEAR(387.2, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(0.91f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.91f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport29) {
  RegisterMockedHttpURLLoad("viewport/viewport-29.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-29.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(700, constraints.layout_size.width());
  EXPECT_EQ(770, constraints.layout_size.height());
  EXPECT_NEAR(0.46f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.46f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport30) {
  RegisterMockedHttpURLLoad("viewport/viewport-30.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-30.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(200, constraints.layout_size.width());
  EXPECT_EQ(220, constraints.layout_size.height());
  EXPECT_NEAR(1.6f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.6f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport31) {
  RegisterMockedHttpURLLoad("viewport/viewport-31.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-31.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(700, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport32) {
  RegisterMockedHttpURLLoad("viewport/viewport-32.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-32.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(200, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport33) {
  RegisterMockedHttpURLLoad("viewport/viewport-33.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-33.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(2.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport34) {
  RegisterMockedHttpURLLoad("viewport/viewport-34.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-34.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(640, constraints.layout_size.width());
  EXPECT_EQ(704, constraints.layout_size.height());
  EXPECT_NEAR(0.5f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport35) {
  RegisterMockedHttpURLLoad("viewport/viewport-35.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-35.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport36) {
  RegisterMockedHttpURLLoad("viewport/viewport-36.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-36.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_NEAR(636.36, constraints.layout_size.width(), 0.01f);
  EXPECT_EQ(700, constraints.layout_size.height());
  EXPECT_NEAR(1.6f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.50f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport37) {
  RegisterMockedHttpURLLoad("viewport/viewport-37.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-37.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport38) {
  RegisterMockedHttpURLLoad("viewport/viewport-38.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-38.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(640, constraints.layout_size.width());
  EXPECT_EQ(704, constraints.layout_size.height());
  EXPECT_NEAR(0.5f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport39) {
  RegisterMockedHttpURLLoad("viewport/viewport-39.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-39.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(200, constraints.layout_size.width());
  EXPECT_EQ(700, constraints.layout_size.height());
  EXPECT_NEAR(1.6f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.6f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport40) {
  RegisterMockedHttpURLLoad("viewport/viewport-40.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-40.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(700, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(0.46f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.46f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport41) {
  RegisterMockedHttpURLLoad("viewport/viewport-41.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-41.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1000, constraints.layout_size.width());
  EXPECT_EQ(704, constraints.layou
"""


```