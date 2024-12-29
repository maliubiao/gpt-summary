Response:
The user wants a summary of the functionality of the provided C++ code snippet from `viewport_test.cc`. This is part 4 of a 5-part request, implying the user has already received descriptions of previous code sections.

I need to:

1. **Identify the core purpose:**  Based on the test names and the operations performed, the primary function is to test the Blink engine's viewport handling logic.
2. **Relate to web technologies:**  Viewport management directly impacts how HTML, CSS, and JavaScript interact to render web pages on different devices.
3. **Infer logic:** The tests set up different scenarios using mocked HTML content and then assert the expected viewport constraints (layout size, initial/minimum/maximum scale, user zoom).
4. **Highlight potential user/programming errors:**  Incorrect viewport meta tag syntax or conflicting settings are tested and can lead to unexpected rendering.
5. **Trace user interaction:** Describe the steps a user might take that would lead to this code being executed during the rendering process.
6. **Summarize the functionality of this specific part.**
```cpp
ECT_NEAR(2.60f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyHandheldFriendly) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-handheldfriendly.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-handheldfriendly.html", nullptr,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

static void SetQuirkViewportSettings(WebSettings* settings) {
  SetViewportSettings(settings);

  // This quirk allows content attributes of meta viewport tags to be merged.
  settings->SetViewportMetaMergeContentQuirk(true);
}

TEST_F(ViewportTest, viewportLegacyMergeQuirk1) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-merge-quirk-1.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-merge-quirk-1.html", nullptr,
      nullptr, SetQuirkViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(640, constraints.layout_size.width());
  EXPECT_EQ(704, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.maximum_scale, 0.01f);
  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyMergeQuirk2) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-merge-quirk-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-merge-quirk-2.html", nullptr,
      nullptr, SetQuirkViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  // This quirk allows content attributes of meta viewport tags to be merged.
  page->GetSettings().SetViewportMetaMergeContentQuirk(true);
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(500, constraints.layout_size.width());
  EXPECT_EQ(550, constraints.layout_size.height());
  EXPECT_NEAR(2.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(2.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(2.0f, constraints.maximum_scale, 0.01f);
  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyMobileOptimizedMetaWithoutContent) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-mobileoptimized.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-mobileoptimized.html", nullptr,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyMobileOptimizedMetaWith0) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-mobileoptimized-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-mobileoptimized-2.html", nullptr,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyMobileOptimizedMetaWith400) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-mobileoptimized-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-mobileoptimized-2.html", nullptr,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering2) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-2.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(300, constraints.layout_size.width());
  EXPECT_EQ(330, constraints.layout_size.height());
  EXPECT_NEAR(1.07f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.07f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering3) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-3.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-3.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(300, constraints.layout_size.width());
  EXPECT_EQ(330, constraints.layout_size.height());
  EXPECT_NEAR(1.07f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.07f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering4) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-4.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-4.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(300, constraints.layout_size.width());
  EXPECT_EQ(330, constraints.layout_size.height());
  EXPECT_NEAR(1.07f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.07f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering5) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-5.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-5.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering6) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-6.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-6.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering7) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-7.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-7.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(300, constraints.layout_size.width());
  EXPECT_EQ(330, constraints.layout_size.height());
  EXPECT_NEAR(1.07f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.07f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering8) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-8.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-8.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(300, constraints.layout_size.width());
  EXPECT_EQ(330, constraints.layout_size.height());
  EXPECT_NEAR(1.07f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.07f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyDefaultValueChangedByXHTMLMP) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-xhtmlmp.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-xhtmlmp.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest,
       viewportLegacyDefaultValueChangedByXHTMLMPAndOverriddenByMeta) {
  RegisterMockedHttpURLLoad(
      "viewport/viewport-legacy-xhtmlmp-misplaced-doctype.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-xhtmlmp-misplaced-doctype.html",
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

TEST_F(ViewportTest, viewportLegacyXHTMLMPOrdering) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-xhtmlmp-ordering.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-xhtmlmp-ordering.html", nullptr,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(640, constraints.layout_size.width());
  EXPECT_EQ(704, constraints.layout_size.height());
  EXPECT_NEAR(0.5f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyXHTMLMPRemoveAndAdd) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-xhtmlmp.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-xhtmlmp.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);

  ExecuteScript(web_view_helper.LocalMainFrame(),
                "originalDoctype = document.doctype;"
                "document.removeChild(originalDoctype);");

  constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);

  ExecuteScript(web_view_helper.LocalMainFrame(),
                "document.insertBefore(originalDoctype, document.firstChild);");

  constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLimitsAdjustedForNoUserScale) {
  RegisterMockedHttpURLLoad(
      "viewport/viewport-limits-adjusted-for-no-user-scale.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-limits-adjusted-for-no-user-scale.html",
      nullptr, nullptr, SetViewportSettings);

  web_view_helper.GetWebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 10, 10);

  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
}

TEST_F(ViewportTest, viewportLimitsAdjustedForUserScale) {
  RegisterMockedHttpURLLoad(
      "viewport/viewport-limits-adjusted-for-user-scale.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-limits-adjusted-for-user-scale.html",
      nullptr, nullptr, SetViewportSettings);
  web_view_helper.GetWebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 10, 10);

  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
}

class ConsoleMessageWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  void DidAddMessageToConsole(const WebConsoleMessage& msg,
                              const WebString& source_name,
                              unsigned source_line,
                              const WebString& stack_trace) override {
    messages.push_back(msg);
  }

  Vector<WebConsoleMessage> messages;
};

TEST_F(ViewportTest, viewportWarnings1) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-1.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-1.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_TRUE(web_frame_client.messages.empty());

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(2.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings2) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-2.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1U, web_frame_client.messages.size());
  EXPECT_EQ(mojom::ConsoleMessageLevel::kWarning,
            web_frame_client.messages[0].level);
  EXPECT_EQ("The key \"wwidth\" is not recognized and ignored.",
            web_frame_client.messages[0].text);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings3) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-3.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-3.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1U, web_frame_client.messages.size());
  EXPECT_EQ(mojom::ConsoleMessageLevel::kWarning,
            web_frame_client.messages[0].level);
  EXPECT_EQ(
      "The value \"unrecognized-width\" for key \"width\" is invalid, and has "
      "been ignored.",
      web_frame_client.messages[0].text);

  EXPECT_NEAR(980, constraints.layout_size.width(), 0.01);
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings4) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-4.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-4.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1U, web_frame_client.messages.size());
  EXPECT_EQ(mojom::ConsoleMessageLevel::kWarning,
            web_frame_client.messages[0].level);
  EXPECT_EQ(
      "The value \"123x456\" for key \"width\" was truncated to its numeric "
      "prefix.",
      web_frame_client.messages[0].text);

  EXPECT_NEAR(123.0f, constraints.layout_size.width(), 0.01);
  EXPECT_NEAR(135.3f, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(2.60f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(2.60f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings5) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-5.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-5.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1U, web_frame_client.messages.size());

  EXPECT_EQ(mojom::ConsoleMessageLevel::kWarning,
            web_frame_client.messages[0].level);
  EXPECT_EQ(
      "Error parsing a meta element's content: ';' is not a valid key-value "
      "pair separator. Please use ',' instead.",
      web_frame_client.messages[0].text);

  EXPECT_NEAR(320.0f, constraints.layout_size.width(), 0.01);
  EXPECT_NEAR(352.0f, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.maximum_scale, 0.01f);
  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings6) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-6.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-6.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1U, web_frame_client.messages.size());
  EXPECT_EQ(mojom::ConsoleMessageLevel::kWarning,
            web_frame_client.messages[0].level);
  EXPECT_EQ(
      "The value \"\" for key \"width\" is invalid, and has been ignored.",
      web_frame_client.messages[0].text);

  EXPECT_NEAR(980, constraints.layout_size.width(), 0.01);
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings7) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-7.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-7.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  RunViewportTest(page, 320, 352);

  EXPECT_EQ(0U,
Prompt: 
```
这是目录为blink/renderer/core/page/viewport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
ECT_NEAR(2.60f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyHandheldFriendly) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-handheldfriendly.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-handheldfriendly.html", nullptr,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

static void SetQuirkViewportSettings(WebSettings* settings) {
  SetViewportSettings(settings);

  // This quirk allows content attributes of meta viewport tags to be merged.
  settings->SetViewportMetaMergeContentQuirk(true);
}

TEST_F(ViewportTest, viewportLegacyMergeQuirk1) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-merge-quirk-1.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-merge-quirk-1.html", nullptr,
      nullptr, SetQuirkViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(640, constraints.layout_size.width());
  EXPECT_EQ(704, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.maximum_scale, 0.01f);
  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyMergeQuirk2) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-merge-quirk-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-merge-quirk-2.html", nullptr,
      nullptr, SetQuirkViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  // This quirk allows content attributes of meta viewport tags to be merged.
  page->GetSettings().SetViewportMetaMergeContentQuirk(true);
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(500, constraints.layout_size.width());
  EXPECT_EQ(550, constraints.layout_size.height());
  EXPECT_NEAR(2.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(2.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(2.0f, constraints.maximum_scale, 0.01f);
  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyMobileOptimizedMetaWithoutContent) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-mobileoptimized.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-mobileoptimized.html", nullptr,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyMobileOptimizedMetaWith0) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-mobileoptimized-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-mobileoptimized-2.html", nullptr,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyMobileOptimizedMetaWith400) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-mobileoptimized-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-mobileoptimized-2.html", nullptr,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering2) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-2.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(300, constraints.layout_size.width());
  EXPECT_EQ(330, constraints.layout_size.height());
  EXPECT_NEAR(1.07f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.07f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering3) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-3.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-3.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(300, constraints.layout_size.width());
  EXPECT_EQ(330, constraints.layout_size.height());
  EXPECT_NEAR(1.07f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.07f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering4) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-4.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-4.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(300, constraints.layout_size.width());
  EXPECT_EQ(330, constraints.layout_size.height());
  EXPECT_NEAR(1.07f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.07f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering5) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-5.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-5.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering6) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-6.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-6.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering7) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-7.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-7.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(300, constraints.layout_size.width());
  EXPECT_EQ(330, constraints.layout_size.height());
  EXPECT_NEAR(1.07f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.07f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyOrdering8) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-ordering-8.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-ordering-8.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();

  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(300, constraints.layout_size.width());
  EXPECT_EQ(330, constraints.layout_size.height());
  EXPECT_NEAR(1.07f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.07f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyDefaultValueChangedByXHTMLMP) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-xhtmlmp.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-xhtmlmp.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest,
       viewportLegacyDefaultValueChangedByXHTMLMPAndOverriddenByMeta) {
  RegisterMockedHttpURLLoad(
      "viewport/viewport-legacy-xhtmlmp-misplaced-doctype.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-xhtmlmp-misplaced-doctype.html",
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

TEST_F(ViewportTest, viewportLegacyXHTMLMPOrdering) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-xhtmlmp-ordering.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-xhtmlmp-ordering.html", nullptr,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(640, constraints.layout_size.width());
  EXPECT_EQ(704, constraints.layout_size.height());
  EXPECT_NEAR(0.5f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.5f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLegacyXHTMLMPRemoveAndAdd) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-xhtmlmp.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-legacy-xhtmlmp.html", nullptr, nullptr,
      SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);

  ExecuteScript(web_view_helper.LocalMainFrame(),
                "originalDoctype = document.doctype;"
                "document.removeChild(originalDoctype);");

  constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);

  ExecuteScript(web_view_helper.LocalMainFrame(),
                "document.insertBefore(originalDoctype, document.firstChild);");

  constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportLimitsAdjustedForNoUserScale) {
  RegisterMockedHttpURLLoad(
      "viewport/viewport-limits-adjusted-for-no-user-scale.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-limits-adjusted-for-no-user-scale.html",
      nullptr, nullptr, SetViewportSettings);

  web_view_helper.GetWebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 10, 10);

  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
}

TEST_F(ViewportTest, viewportLimitsAdjustedForUserScale) {
  RegisterMockedHttpURLLoad(
      "viewport/viewport-limits-adjusted-for-user-scale.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-limits-adjusted-for-user-scale.html",
      nullptr, nullptr, SetViewportSettings);
  web_view_helper.GetWebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 10, 10);

  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
}

class ConsoleMessageWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  void DidAddMessageToConsole(const WebConsoleMessage& msg,
                              const WebString& source_name,
                              unsigned source_line,
                              const WebString& stack_trace) override {
    messages.push_back(msg);
  }

  Vector<WebConsoleMessage> messages;
};

TEST_F(ViewportTest, viewportWarnings1) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-1.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-1.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_TRUE(web_frame_client.messages.empty());

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(2.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings2) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-2.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1U, web_frame_client.messages.size());
  EXPECT_EQ(mojom::ConsoleMessageLevel::kWarning,
            web_frame_client.messages[0].level);
  EXPECT_EQ("The key \"wwidth\" is not recognized and ignored.",
            web_frame_client.messages[0].text);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings3) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-3.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-3.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1U, web_frame_client.messages.size());
  EXPECT_EQ(mojom::ConsoleMessageLevel::kWarning,
            web_frame_client.messages[0].level);
  EXPECT_EQ(
      "The value \"unrecognized-width\" for key \"width\" is invalid, and has "
      "been ignored.",
      web_frame_client.messages[0].text);

  EXPECT_NEAR(980, constraints.layout_size.width(), 0.01);
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings4) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-4.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-4.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1U, web_frame_client.messages.size());
  EXPECT_EQ(mojom::ConsoleMessageLevel::kWarning,
            web_frame_client.messages[0].level);
  EXPECT_EQ(
      "The value \"123x456\" for key \"width\" was truncated to its numeric "
      "prefix.",
      web_frame_client.messages[0].text);

  EXPECT_NEAR(123.0f, constraints.layout_size.width(), 0.01);
  EXPECT_NEAR(135.3f, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(2.60f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(2.60f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings5) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-5.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-5.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1U, web_frame_client.messages.size());

  EXPECT_EQ(mojom::ConsoleMessageLevel::kWarning,
            web_frame_client.messages[0].level);
  EXPECT_EQ(
      "Error parsing a meta element's content: ';' is not a valid key-value "
      "pair separator. Please use ',' instead.",
      web_frame_client.messages[0].text);

  EXPECT_NEAR(320.0f, constraints.layout_size.width(), 0.01);
  EXPECT_NEAR(352.0f, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.maximum_scale, 0.01f);
  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings6) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-6.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-6.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1U, web_frame_client.messages.size());
  EXPECT_EQ(mojom::ConsoleMessageLevel::kWarning,
            web_frame_client.messages[0].level);
  EXPECT_EQ(
      "The value \"\" for key \"width\" is invalid, and has been ignored.",
      web_frame_client.messages[0].text);

  EXPECT_NEAR(980, constraints.layout_size.width(), 0.01);
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewportWarnings7) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-7.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-7.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  RunViewportTest(page, 320, 352);

  EXPECT_EQ(0U, web_frame_client.messages.size());
}

TEST_F(ViewportTest, viewportWarnings8) {
  ConsoleMessageWebFrameClient web_frame_client;

  RegisterMockedHttpURLLoad("viewport/viewport-warnings-8.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport/viewport-warnings-8.html", &web_frame_client,
      nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  RunViewportTest(page, 320, 352);

  EXPECT_EQ(0U, web_frame_client.messages.size());
}

TEST_F(ViewportTest, viewport1) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-merge-quirk-1.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeWithSettings(SetQuirkViewportSettings);
  web_view_impl->MainFrameWidget()->SetDeviceScaleFactorForTesting(3.f);
  frame_test_helpers::LoadFrame(
      web_view_impl->MainFrameImpl(),
      base_url_ + "viewport/viewport-legacy-merge-quirk-1.html");

  Page* page = web_view_helper.GetWebView()->GetPage();
  // Initial width and height must be scaled by DSF.
  PageScaleConstraints constraints = RunViewportTest(page, 960, 1056);

  // constraints layout width == 640 * DSF = 1920
  EXPECT_EQ(1920, constraints.layout_size.width());
  // constraints layout height == 704 * DSF = 2112
  EXPECT_EQ(2112, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.maximum_scale, 0.01f);
  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport2) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-merge-quirk-2.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeWithSettings(SetQuirkViewportSettings);
  web_view_impl->MainFrameWidget()->SetDeviceScaleFactorForTesting(3.f);
  frame_test_helpers::LoadFrame(
      web_view_impl->MainFrameImpl(),
      base_url_ + "viewport/viewport-legacy-merge-quirk-2.html");
  Page* page = web_view_helper.GetWebView()->GetPage();

  // This quirk allows content attributes of meta viewport tags to be merged.
  page->GetSettings().SetViewportMetaMergeContentQuirk(true);
  // Initial width and height must be scaled by DSF.
  PageScaleConstraints constraints = RunViewportTest(page, 960, 1056);

  // constraints layout width == 500 * DSF = 1500
  EXPECT_EQ(1500, constraints.layout_size.width());
  // constraints layout height == 550 * DSF = 1650
  EXPECT_EQ(1650, constraints.layout_size.height());
  EXPECT_NEAR(2.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(2.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(2.0f, constraints.maximum_scale, 0.01f);
  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport3) {
  RegisterMockedHttpURLLoad("viewport/viewport-48.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeWithSettings(SetViewportSettings);
  web_view_impl->MainFrameWidget()->SetDeviceScaleFactorForTesting(3.f);
  frame_test_helpers::LoadFrame(web_view_impl->MainFrameImpl(),
                                base_url_ + "viewport/viewport-48.html");

  Page* page = web_view_helper.GetWebView()->GetPage();
  // Initial width and height must be scaled by DSF.
  PageScaleConstraints constraints = RunViewportTest(page, 960, 1056);

  // constraints layout width == 3000 * DSF = 9000
  EXPECT_EQ(9000, constraints.layout_size.width());
  EXPECT_EQ(1056, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport4) {
  RegisterMockedHttpURLLoad("viewport/viewport-39.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeWithSettings(SetViewportSettings);
  web_view_impl->MainFrameWidget()->SetDeviceScaleFactorForTesting(3.f);
  frame_test_helpers::LoadFrame(web_view_impl->MainFrameImpl(),
                                base_url_ + "viewport/viewport-39.html");

  Page* page = web_view_helper.GetWebView()->GetPage();
  // Initial width and height must be scaled by DSF.
  PageScaleConstraints constraints = RunViewportTest(page, 960, 1056);

  // constraints layout width == 200 * DSF = 600
  EXPECT_EQ(600, constraints.layout_size.width());
  // constraints layout height == 700 * DSF = 2100
  EXPECT_EQ(2100, constraints.layout_size.height());
  EXPECT_NEAR(1.6f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.6f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

// Verifies that the value clamping from
// https://www.w3.org/TR/css-device-adapt-1/#width-and-height-properties
// applies to CSS pixel not physical pixel.
TEST_F(ViewportTest, viewport5) {
  RegisterMockedHttpURLLoad("viewport/viewport-48.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeWithSettings(SetViewportSettings);
  web_view_impl->MainFrameWidget()->SetDeviceScaleFactorForTesting(4.f);
  frame_test_helpers::LoadFrame(web_view_impl->MainFrameImpl(),
                                base_url_ + "viewport/viewport-48.html");

  Page* page = web_view_helper.GetWebView()->GetPage();
  // Initial width and height must be scaled by DSF.
  PageScaleConstraints constraints = RunViewportTest(page, 960, 1056);

  // constraints layout width == 3000 * DSF = 12000 and it should not be clamped
  // to 10000.
  EXPECT_EQ(12000, constraints.layout_size.width());
  EXPECT_EQ(1056, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

class ViewportHistogramsTest : public SimTest {
 public:
  ViewportHistogramsTest() = default;

  void SetUp() override {
    SimTest::SetUp();

    WebView().GetSettings()->SetViewportEnabled(true);
    WebView().GetSettings()->SetViewportMetaEnabled(true);
    WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 600));
  }

  void UseMetaTag(const String& metaTag) {
    String responseText =
        String("<!DOCTYPE html>") + metaTag +
        String("<style> body { width: 2000px; height: 2000px; } </style>");
    RunTest(responseText);
  }

  void UseDocType(const String& docType) {
    String responseText =
        docType +
        String("<style> body { width: 2000px; height: 2000px; } </style>");
    RunTest(responseText);
  }

  void ExpectType(ViewportDescription::ViewportUMAType type) {
    histogram_tester_.ExpectUniqueSample("Viewport.MetaTagType",
                                         static_cast<int>(type), 1);
  }

  void ExpectTotalCount(const std::string& histogram, int count) {
    histogram_tester_.ExpectTotalCount(histogram, 0);
  }

 private:
  void RunTest(const String& responseText) {
    SimRequest request("https://example.com/test.html", "text/html");
    LoadURL("https://example.com/test.html");
    request.Complete(responseText);

    // Pump the task queue so the meta tag gets processed.
    blink::test::RunPendingTasks();
  }

  base::HistogramTester histogram_tester_;
};

TEST_F(ViewportHistogramsTest, NoOpOnWhenViewportDisabled) {
  WebView().GetSettings()->SetViewportEnabled(false);
  UseMetaTag("<meta name='viewport' content='width=device-width'>");

  ExpectTotalCount("Viewport.MetaTagType", 0);
}

TEST_F(ViewportHistogramsTest, TypeNone) {
  UseMetaTag("");
  ExpectType(ViewportDescription::ViewportUMAType::kNoViewportTag);
}

TEST_F(ViewportHistogramsTest, TypeDeviceWidth) {
  UseMetaTag("<meta name='viewport' content='width=device-width'>");
  ExpectType(ViewportDescription::ViewportUMAType::kDeviceWidth);
}

TEST_F(ViewportHistogramsTest, TypeConstant) {
  UseMetaTag("<meta name='viewport' content='width=800'>");
  ExpectType(ViewportDescription::ViewportUMAType::kConstantWidth);
}

TEST_F(ViewportHistogramsTest, TypeHandheldFriendlyMeta) {
  UseMetaTag("<meta name='HandheldFriendly' content='true'/> ");
  ExpectType(ViewportDescription::ViewportUMAType::kMetaHandheldFriendly);
}

TEST_F(ViewportHistogramsTest, TypeMobileOptimizedMeta) {
  UseMetaTag("<meta name='MobileOptimized' content='320'/> ");
  ExpectType(ViewportDescription::ViewportUMAType::kMetaMobileOptimized);
}

TEST_F(Vie
"""


```