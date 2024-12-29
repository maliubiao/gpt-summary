Response:
The user wants to understand the functionality of a C++ test file for the Chromium Blink engine, specifically `viewport_test.cc`. The goal is to summarize its purpose based on the provided code snippet, and also explain its relation to web technologies (HTML, CSS, JavaScript), provide examples of logical reasoning (input/output), discuss potential user errors, and describe how a user might trigger this code.

Here's a breakdown of how to address each part:

1. **Functionality:** The code consists of multiple `TEST_F` blocks within a `ViewportTest` class. Each test loads a specific HTML file (e.g., `viewport-85.html`), runs a `RunViewportTest` function, and then asserts certain conditions using `EXPECT_...`. The assertions are related to `PageScaleConstraints`, such as `layout_size`, `initial_scale`, `minimum_scale`, `maximum_scale`, and whether `user_zoom` is enabled. Therefore, the main function is to test how different viewport configurations in HTML affect the calculated page scale constraints.

2. **Relationship to HTML, CSS, JavaScript:**
    * **HTML:** The core of the tests revolves around loading and parsing HTML files. The `<meta name="viewport" ...>` tag within these HTML files is what these tests are specifically targeting.
    * **CSS:** While not directly manipulated in this test file, the viewport settings impact how CSS media queries and layout calculations are performed.
    * **JavaScript:**  JavaScript can dynamically interact with the viewport through APIs like `window.innerWidth`, `window.innerHeight`, and by manipulating the viewport meta tag. While this specific test file doesn't show direct JavaScript interaction, the underlying functionality it tests is relevant to how JavaScript can respond to viewport changes.

3. **Logical Reasoning (Input/Output):**  Each test can be considered an example of logical reasoning. The *input* is the specific HTML file being loaded (implicitly containing the viewport meta tag). The *output* is the `PageScaleConstraints` object and the assertions made on its properties. For instance, if an HTML file has `<meta name="viewport" content="width=device-width, initial-scale=0.5">`, the test should verify that `initial_scale` is approximately 0.5.

4. **User/Programming Errors:**
    * **Incorrect viewport meta tag:**  A common user error is misconfiguring the viewport meta tag in their HTML. For example, setting `initial-scale` too high or low, forgetting to include `width=device-width` for responsive design, or incorrectly using the `minimum-scale` and `maximum-scale` properties. The tests in this file help verify that the browser correctly interprets these potentially erroneous configurations.
    * **Mismatched expectations in tests:** A programming error within this test file itself would be having incorrect `EXPECT_...` values for a given HTML input. This would lead to test failures.

5. **User Operations to Reach Here (Debugging):** A developer debugging viewport-related issues might end up here by:
    * Noticing incorrect rendering or scaling of a webpage on different devices.
    * Suspecting that the viewport meta tag in the HTML is not being interpreted correctly.
    * Stepping through the browser's rendering pipeline, specifically the part that parses and applies the viewport settings.
    * Looking at the code responsible for calculating `PageScaleConstraints`.
    * Running these unit tests to confirm the expected behavior for various viewport configurations.

6. **归纳总结 (Summary):** The core function of this code snippet is to **unit test the Blink rendering engine's logic for interpreting and applying viewport settings defined in HTML**. It uses various HTML files with different viewport meta tag configurations as inputs and verifies the resulting calculated page scale constraints (layout size, initial scale, min/max scale, user zoom).

Now, let's structure the response clearly and provide specific examples.Let's break down the functionality of the provided C++ code snippet from `viewport_test.cc`.

**归纳一下它的功能 (Summary of its functionality):**

This code snippet is part of a **unit test suite** for the Blink rendering engine, specifically focusing on the **viewport handling** logic. Each `TEST_F` block represents an individual test case that:

1. **Loads a specific HTML file:**  `RegisterMockedHttpURLLoad("viewport/viewport-XX.html");`  This sets up a mocked HTTP request to serve a specific HTML file from the `viewport` directory.
2. **Initializes a WebView:** `frame_test_helpers::WebViewHelper web_view_helper; web_view_helper.InitializeAndLoad(...);` This creates and loads the mocked HTML content into a testing environment that simulates a browser tab.
3. **Retrieves the Page object:** `Page* page = web_view_helper.GetWebView()->GetPage();` This gets a pointer to the `Page` object, which represents the loaded web page.
4. **Runs the viewport test logic:** `PageScaleConstraints constraints = RunViewportTest(page, 320, 352);` This is the core of the test. It calls a function (presumably defined elsewhere in the file or test fixture) that calculates the viewport constraints based on the loaded HTML and a simulated screen size (320x352 in this case).
5. **Asserts the expected viewport constraints:**  `EXPECT_EQ(...)` and `EXPECT_NEAR(...)` are used to verify that the calculated `PageScaleConstraints` (like layout width, layout height, initial scale, minimum scale, maximum scale) match the expected values for the given HTML file.
6. **Asserts the user zoom setting:** `EXPECT_TRUE(page->GetViewportDescription().user_zoom);` This checks if the test expects the user to be able to zoom in and out on the page.

**In essence, this code tests how Blink interprets different viewport meta tag configurations in HTML and calculates the resulting layout size and scaling factors.**

**它与javascript, html, css 的功能有关系吗？ 请做出对应的举例说明 (Is it related to the functionality of JavaScript, HTML, and CSS? Please provide examples):**

Yes, this code is directly related to how HTML, CSS, and (indirectly) JavaScript interact with the browser's viewport.

* **HTML:** The core of these tests revolves around the **`<meta name="viewport">` tag** in HTML. This tag is used by web developers to control the viewport's size and scaling behavior on different devices. Each test case loads an HTML file that likely contains a different configuration of this meta tag.

   * **Example:** The test `viewport85` loads `viewport-85.html`. This HTML file probably contains a `<meta name="viewport" content="width=540, initial-scale=0.59">` (or similar) which instructs the browser to set the layout viewport width to 540 pixels and the initial zoom level to 59%. The test then verifies that the `constraints.layout_size.width()` is indeed 540 and `constraints.initial_scale` is close to 0.59.

* **CSS:** While the test code doesn't directly manipulate CSS, the viewport settings heavily influence how CSS is applied. Media queries in CSS, for instance, rely on the viewport width to determine which styles to apply. The viewport also affects the initial containing block for layout.

   * **Example:** If an HTML file has `<meta name="viewport" content="width=device-width">`, the layout viewport width will match the device's screen width. CSS media queries like `@media (max-width: 768px)` will then behave according to the device's actual screen size. These tests ensure Blink correctly sets up the viewport width so that these CSS features work as expected.

* **JavaScript:** JavaScript can access and manipulate viewport properties. APIs like `window.innerWidth`, `window.innerHeight`, `document.documentElement.clientWidth`, and `document.documentElement.clientHeight` provide information about the viewport size. JavaScript can also dynamically change the `<meta name="viewport">` tag.

   * **Example:** A website might use JavaScript to detect the user's device orientation and dynamically update the viewport meta tag to optimize the layout. These tests ensure that Blink's initial viewport calculation is correct, which is the foundation upon which JavaScript's viewport interactions are built.

**如果做了逻辑推理，请给出假设输入与输出 (If logical reasoning is involved, please provide hypothetical input and output):**

Each test case inherently performs logical reasoning. The "input" is the content of the HTML file (specifically the viewport meta tag) and the simulated screen size. The "output" is the calculated `PageScaleConstraints`.

**Example of Logical Reasoning:**

**Hypothetical Input:**

* **HTML (viewport/hypothetical.html):**
  ```html
  <!DOCTYPE html>
  <html>
  <head>
    <meta name="viewport" content="width=375, initial-scale=2.0, minimum-scale=1.0, maximum-scale=5.0, user-scalable=yes">
  </head>
  <body>
    <h1>Hello World</h1>
  </body>
  </html>
  ```
* **Simulated Screen Size:** 320x352 (as used in the test)

**Expected Output (based on the logic of viewport interpretation):**

```
EXPECT_EQ(375, constraints.layout_size.width()); // The specified width
EXPECT_NEAR(412.5, constraints.layout_size.height(), 0.01f); // Likely a proportional height based on content
EXPECT_NEAR(2.0f, constraints.initial_scale, 0.01f); // As specified
EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f); // As specified
EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f); // As specified
EXPECT_TRUE(page->GetViewportDescription().user_zoom); // user-scalable=yes means user zoom is allowed
```

The test `RunViewportTest` function likely contains the core logic that takes the HTML and screen size as input and applies the browser's viewport interpretation rules to produce these output constraints.

**如果涉及用户或者编程常见的使用错误，请举例说明 (If it involves common user or programming errors, please provide examples):**

These tests are designed to catch errors in Blink's viewport implementation, which can be triggered by incorrect HTML or developer assumptions. Here are some examples of user/programming errors that these tests might indirectly help to detect or prevent:

* **User Error (Web Developer): Incorrect Viewport Meta Tag:**
    * **Forgetting `width=device-width`:** A developer might simply use `<meta name="viewport" content="initial-scale=1.0">`. On smaller devices, this could result in the website being rendered at a desktop-like width, causing it to be zoomed out and difficult to read. Tests with and without `width=device-width` ensure Blink handles these cases correctly.
    * **Setting `initial-scale` inappropriately:** Setting `initial-scale` to a very small value can make the page tiny on initial load. Tests verify the browser honors this setting.
    * **Conflicting viewport settings:**  A developer might accidentally have conflicting directives, like setting both `width` to a specific pixel value and using `width=device-width`. The tests ensure Blink has a consistent way of resolving such conflicts.
    * **Incorrectly using `minimum-scale` and `maximum-scale`:** Setting `maximum-scale=1.0` effectively disables user zoom. Tests like `viewport131` verify this behavior. Setting `minimum-scale` higher than `initial-scale` could lead to unexpected zooming behavior.

* **Programming Error (Blink Developer): Bugs in Viewport Calculation Logic:**
    * **Incorrect parsing of the viewport meta tag:** A bug in the parser could lead to misinterpreting the values in the `content` attribute.
    * **Errors in calculating layout size:** The `RunViewportTest` function likely involves complex logic to determine the initial layout viewport size based on the meta tag and device characteristics. Bugs in this calculation would be caught by these tests.
    * **Incorrect handling of user-scalable:**  Failing to correctly enable or disable user zoom based on the `user-scalable` attribute.

**说明用户操作是如何一步步的到达这里，作为调试线索 (Explain how user operations step-by-step lead to this code, as debugging clues):**

As a user interacts with a website, their actions can trigger the viewport logic that these tests verify. Here's a breakdown:

1. **User Opens a Webpage:** The user types a URL or clicks a link. The browser starts loading the HTML content.
2. **Blink Parses HTML:** The Blink rendering engine parses the HTML, including the `<head>` section where the viewport meta tag is located.
3. **Viewport Meta Tag Processing:** Blink's viewport handling code (the code being tested here) reads and interprets the attributes of the `<meta name="viewport">` tag.
4. **Layout Initialization:** Based on the viewport settings, Blink determines the initial layout viewport size, initial zoom level, and whether user zooming is allowed.
5. **Rendering:** Blink renders the webpage based on the calculated viewport. CSS media queries are evaluated against this viewport, and the initial layout is performed.
6. **User Interaction (e.g., Zooming):** If the viewport allows user zooming, the user can pinch-to-zoom or use other browser controls to change the zoom level. Blink's viewport logic handles these zoom events, potentially triggering reflows and repaints.

**Debugging Clues:**

If a web developer or a Blink developer observes unexpected behavior related to the viewport, this test file provides valuable debugging clues:

* **Incorrect Rendering/Scaling:** If a website appears zoomed in or out incorrectly on initial load, or if its layout breaks on different devices, it might indicate an issue with how Blink is interpreting the viewport meta tag. The specific `viewportXX.html` files in these tests represent various viewport configurations, and comparing the actual rendering with the expected constraints can pinpoint the problem.
* **Media Queries Not Firing Correctly:** If CSS media queries are not being applied as expected on different screen sizes, it could be due to an incorrect layout viewport width. These tests verify the calculated layout width for different viewport settings.
* **User Zoom Issues:** If user zooming is unexpectedly disabled or behaves strangely, the tests that assert the `user_zoom` flag can help identify if the `user-scalable` attribute is being processed correctly.

**Example Debugging Scenario:**

1. **User reports:** "The website is too zoomed out on my phone."
2. **Developer investigates:** They look at the website's HTML and see `<meta name="viewport" content="width=1024">`.
3. **Hypothesis:** Blink is setting the layout viewport to 1024 pixels, making it appear zoomed out on a phone with a smaller screen width.
4. **Debugging:** The developer might look at the `viewport_test.cc` file and find tests that specifically handle fixed widths in the viewport meta tag. They could even add a new test case with a similar viewport configuration to verify Blink's behavior.

**归纳一下它的功能 (Summary of its functionality for this part):**

This specific part of `viewport_test.cc` focuses on testing how Blink handles various combinations of viewport settings, particularly those affecting the layout size, initial scale, and user zoom capability. Each test case uses a distinct HTML file with different viewport configurations and asserts the expected outcome. This helps ensure that Blink correctly interprets the `<meta name="viewport">` tag and sets up the rendering environment accordingly.

Prompt: 
```
这是目录为blink/renderer/core/page/viewport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport85) {
  RegisterMockedHttpURLLoad("viewport/viewport-85.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-85.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(540, constraints.layout_size.width());
  EXPECT_EQ(594, constraints.layout_size.height());
  EXPECT_NEAR(0.59f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.59f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport86) {
  RegisterMockedHttpURLLoad("viewport/viewport-86.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-86.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_NEAR(457.14, constraints.layout_size.width(), 0.01f);
  EXPECT_NEAR(502.86, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.7f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.7f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport87) {
  RegisterMockedHttpURLLoad("viewport/viewport-87.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-87.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport88) {
  RegisterMockedHttpURLLoad("viewport/viewport-88.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-88.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport90) {
  RegisterMockedHttpURLLoad("viewport/viewport-90.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-90.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(700, constraints.layout_size.width());
  EXPECT_EQ(770, constraints.layout_size.height());
  EXPECT_NEAR(0.5f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.46f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport100) {
  RegisterMockedHttpURLLoad("viewport/viewport-100.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-100.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(400, constraints.layout_size.width());
  EXPECT_EQ(440, constraints.layout_size.height());
  EXPECT_NEAR(0.8f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.8f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport101) {
  RegisterMockedHttpURLLoad("viewport/viewport-101.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-101.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(400, constraints.layout_size.width());
  EXPECT_EQ(440, constraints.layout_size.height());
  EXPECT_NEAR(0.8f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.8f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport102) {
  RegisterMockedHttpURLLoad("viewport/viewport-102.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-102.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(400, constraints.layout_size.width());
  EXPECT_EQ(440, constraints.layout_size.height());
  EXPECT_NEAR(0.8f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.8f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport103) {
  RegisterMockedHttpURLLoad("viewport/viewport-103.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-103.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(400, constraints.layout_size.width());
  EXPECT_EQ(440, constraints.layout_size.height());
  EXPECT_NEAR(0.8f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.8f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport104) {
  RegisterMockedHttpURLLoad("viewport/viewport-104.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-104.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport105) {
  RegisterMockedHttpURLLoad("viewport/viewport-105.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-105.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport106) {
  RegisterMockedHttpURLLoad("viewport/viewport-106.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-106.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport107) {
  RegisterMockedHttpURLLoad("viewport/viewport-107.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-107.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport108) {
  RegisterMockedHttpURLLoad("viewport/viewport-108.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-108.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport109) {
  RegisterMockedHttpURLLoad("viewport/viewport-109.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-109.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport110) {
  RegisterMockedHttpURLLoad("viewport/viewport-110.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-110.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport111) {
  RegisterMockedHttpURLLoad("viewport/viewport-111.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-111.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport112) {
  RegisterMockedHttpURLLoad("viewport/viewport-112.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-112.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(400, constraints.layout_size.width());
  EXPECT_EQ(440, constraints.layout_size.height());
  EXPECT_NEAR(0.8f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.8f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport113) {
  RegisterMockedHttpURLLoad("viewport/viewport-113.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-113.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport114) {
  RegisterMockedHttpURLLoad("viewport/viewport-114.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-114.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport115) {
  RegisterMockedHttpURLLoad("viewport/viewport-115.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-115.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(400, constraints.layout_size.width());
  EXPECT_EQ(440, constraints.layout_size.height());
  EXPECT_NEAR(0.8f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.8f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport116) {
  RegisterMockedHttpURLLoad("viewport/viewport-116.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-116.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(400, constraints.layout_size.width());
  EXPECT_EQ(440, constraints.layout_size.height());
  EXPECT_NEAR(0.8f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.8f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport117) {
  RegisterMockedHttpURLLoad("viewport/viewport-117.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-117.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(400, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport118) {
  RegisterMockedHttpURLLoad("viewport/viewport-118.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-118.html",
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

TEST_F(ViewportTest, viewport119) {
  RegisterMockedHttpURLLoad("viewport/viewport-119.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-119.html",
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

TEST_F(ViewportTest, viewport120) {
  RegisterMockedHttpURLLoad("viewport/viewport-120.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-120.html",
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

TEST_F(ViewportTest, viewport121) {
  RegisterMockedHttpURLLoad("viewport/viewport-121.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-121.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport122) {
  RegisterMockedHttpURLLoad("viewport/viewport-122.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-122.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport123) {
  RegisterMockedHttpURLLoad("viewport/viewport-123.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-123.html",
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

TEST_F(ViewportTest, viewport124) {
  RegisterMockedHttpURLLoad("viewport/viewport-124.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-124.html",
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

TEST_F(ViewportTest, viewport125) {
  RegisterMockedHttpURLLoad("viewport/viewport-125.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-125.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport126) {
  RegisterMockedHttpURLLoad("viewport/viewport-126.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-126.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport127) {
  RegisterMockedHttpURLLoad("viewport/viewport-127.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-127.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport129) {
  RegisterMockedHttpURLLoad("viewport/viewport-129.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-129.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(123, constraints.layout_size.width());
  EXPECT_NEAR(135.3, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(2.60f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(2.60f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport130) {
  RegisterMockedHttpURLLoad("viewport/viewport-130.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-130.html",
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

TEST_F(ViewportTest, viewport131) {
  RegisterMockedHttpURLLoad("viewport/viewport-131.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-131.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.maximum_scale, 0.01f);
  EXPECT_FALSE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport132) {
  RegisterMockedHttpURLLoad("viewport/viewport-132.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-132.html",
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

TEST_F(ViewportTest, viewport133) {
  RegisterMockedHttpURLLoad("viewport/viewport-133.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-133.html",
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

TEST_F(ViewportTest, viewport134) {
  RegisterMockedHttpURLLoad("viewport/viewport-134.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-134.html",
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

TEST_F(ViewportTest, viewport135) {
  RegisterMockedHttpURLLoad("viewport/viewport-135.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-135.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport136) {
  RegisterMockedHttpURLLoad("viewport/viewport-136.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-136.html",
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

TEST_F(ViewportTest, viewport137) {
  RegisterMockedHttpURLLoad("viewport/viewport-137.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-137.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport138) {
  RegisterMockedHttpURLLoad("viewport/viewport-138.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-138.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_NEAR(123.0f, constraints.layout_size.width(), 0.01);
  EXPECT_NEAR(135.3f, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(2.60f, constraints.initial_scale, 0.01f);
  EXP
"""


```