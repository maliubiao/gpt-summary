Response:
The user wants to understand the functionality of a specific part of a Chromium Blink engine source code file (`manifest_parser_unittest.cc`). This is part 2 of an 8-part series, so I need to summarize the functionality covered in this particular part.

The code snippet focuses on testing the parsing logic for various fields within a web app manifest file. It uses a testing framework (likely Google Test) to verify that the manifest parser correctly handles different inputs, including valid values, invalid values, and edge cases.

Here's a breakdown of the tests in this section:

1. **`DisplayParseRules`**: Tests the parsing of the `display` field in the manifest. It checks how the parser handles different valid display modes (browser, minimal-ui, standalone, fullscreen), and how it behaves when encountering invalid values or when certain experimental features (like `borderless` or `tabbed`) are enabled or disabled via feature flags.

2. **`DisplayOverrideParseRules`**: Tests the parsing of the `display_override` field, which allows specifying an ordered list of display modes to try. It verifies that the parser handles correct string values, ignores invalid strings or non-string values, and respects feature flags for experimental display modes.

3. **`OrientationParseRules`**: Tests the parsing of the `orientation` field, which specifies the preferred screen orientation for the web app. It checks for correct parsing of valid orientation values (any, natural, landscape, portrait, etc.) and how it handles invalid or non-string values.

4. **`IconsParseRules`**: Tests the parsing of the `icons` array. It verifies that the parser correctly extracts the `src`, `type`, and `sizes` of each icon, handles missing or invalid `src` values, and correctly resolves relative URLs.

5. **`ScreenshotsParseRules`**: Tests the parsing of the `screenshots` array. It checks for correct parsing of the `src` for each screenshot and handles missing or invalid `src` values.

6. **`ScreenshotFormFactorParseRules`**: Tests the parsing of the `form_factor` field within a screenshot object. It verifies the parsing of "narrow" and checks how unspecified or invalid values are handled.

7. **`ScreenshotLabelRules`**: Tests the parsing of the `label` field within a screenshot object. It checks if valid string labels are parsed correctly and how missing or invalid label types are handled.

8. **`IconSrcParseRules`**: Specifically tests the parsing of the `src` field within an icon object, including whitespace handling, type checking, and URL resolution.

9. **`IconTypeParseRules`**: Tests the parsing of the `type` (MIME type) field within an icon object. It verifies whitespace trimming and type checking.

10. **`IconSizesParseRules`**: Tests the parsing of the `sizes` field within an icon object. It verifies the correct parsing of width and height values, including the "any" keyword, and handles various invalid size formats.

11. **`IconPurposeParseRules`**: Tests the parsing of the `purpose` field within an icon object, which specifies the intended usage of the icon (e.g., "maskable", "monochrome"). It verifies the parsing of valid purpose keywords, handles invalid keywords, and how missing or invalid `purpose` types are handled.

12. **`ShortcutsParseRules`**: Starts testing the parsing of the `shortcuts` array, but the snippet ends abruptly within this test case.

Therefore, the primary function of this part of the file is to **rigorously test the parsing of various web app manifest fields related to display, orientation, icons, and screenshots.**
这是目录为blink/renderer/modules/manifest/manifest_parser_unittest.cc的chromium blink引擎源代码文件的第2部分，主要功能是**测试 Web App Manifest 文件中关于 `display`, `display_override`, `orientation`, `icons`, `screenshots` 和 `shortcuts` 属性的解析规则**。它通过构造不同的 Manifest JSON 字符串，并断言解析后的结果是否符合预期，以此来验证 Manifest 解析器的正确性。

以下是针对每个被测试属性的详细功能归纳和相关说明：

**1. `DisplayParseRules` (显示模式解析规则):**

*   **功能:**  测试 `display` 属性的不同取值（例如："browser", "minimal-ui", "standalone", "fullscreen"）是否能被正确解析为对应的内部枚举值 (`blink::mojom::DisplayMode`)。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   `display` 属性影响 Web 应用的显示方式，例如在桌面或移动设备上是以独立的窗口运行 (standalone)，还是在浏览器标签页中运行 (browser)。这直接影响用户看到的界面和操作体验。
    *   在 JavaScript 中，可以通过 `navigator.mediaDevices.matchMedia('(display-mode: standalone)')` 等 API 查询当前应用的显示模式。
    *   虽然 `display` 属性在 Manifest 中定义，但最终的渲染和窗口管理由浏览器实现，可能会涉及到一些浏览器自身的 UI 和行为。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  `R"({ "display": "standalone" })"`
    *   **预期输出:** `manifest->display` 的值为 `blink::mojom::DisplayMode::kStandalone`
    *   **假设输入:** `R"({ "display": "invalid-mode" })"`
    *   **预期输出:** `manifest->display` 的值为 `blink::mojom::DisplayMode::kUndefined`，并且会记录一个错误信息。
*   **用户或编程常见的使用错误:**
    *   **错误:** 在 Manifest 中使用了不支持的 `display` 值，例如拼写错误或使用了过时的值。
    *   **后果:** 浏览器会忽略该值，通常会回退到默认的显示模式 (通常是 "browser")，并且可能会在开发者工具中显示警告信息。
*   **调试线索 (用户操作如何一步步到达这里):**
    1. 用户访问一个包含 Web App Manifest 文件的网页。
    2. 浏览器下载并解析 Manifest 文件。
    3. Manifest 解析器会读取 `display` 属性的值。
    4. 如果 `display` 的值无法识别，`ManifestParserTest::DisplayParseRules` 中的相关测试会捕捉到这个错误，并断言实际输出与预期输出不符。

**2. `DisplayOverrideParseRules` (显示模式覆盖解析规则):**

*   **功能:** 测试 `display_override` 属性的解析，该属性允许指定一个显示模式的优先级列表。
*   **与 JavaScript, HTML, CSS 的关系:**  类似于 `display` 属性，但提供了更灵活的控制，浏览器会按照列表顺序尝试应用显示模式。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** `R"({ "display_override": [ "standalone", "browser" ] })"`
    *   **预期输出:** `manifest->display_override` 包含两个元素，分别为 `blink::mojom::DisplayMode::kStandalone` 和 `blink::mojom::DisplayMode::kBrowser`。
    *   **假设输入:** `R"({ "display_override": [ "standalone", 123 ] })"`
    *   **预期输出:** `manifest->display_override` 只包含 `blink::mojom::DisplayMode::kStandalone`，数字 `123` 会被忽略，但不会报错。
*   **用户或编程常见的使用错误:**
    *   **错误:** 在 `display_override` 数组中使用了非字符串类型的值。
    *   **后果:** 浏览器会忽略该非字符串值，但不会影响其他有效的显示模式。
*   **调试线索:** 类似于 `DisplayParseRules`，但会检查 `manifest->display_override` 数组的内容。

**3. `OrientationParseRules` (屏幕方向解析规则):**

*   **功能:** 测试 `orientation` 属性的不同取值（例如："any", "natural", "landscape", "portrait"）是否能被正确解析为对应的屏幕方向锁定类型 (`device::mojom::ScreenOrientationLockType`)。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   `orientation` 属性影响 Web 应用在设备上运行时允许的屏幕方向。例如，设置为 "portrait" 的应用只允许竖屏显示。
    *   JavaScript 可以通过 `screen.orientation` API 获取和监听屏幕方向的变化。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** `R"({ "orientation": "landscape" })"`
    *   **预期输出:** `manifest->orientation` 的值为 `device::mojom::ScreenOrientationLockType::LANDSCAPE`。
    *   **假设输入:** `R"({ "orientation": 123 })"`
    *   **预期输出:** `manifest->orientation` 的值为默认值 (`device::mojom::ScreenOrientationLockType::DEFAULT`)，并记录一个错误信息。
*   **用户或编程常见的使用错误:**
    *   **错误:**  `orientation` 的值不是字符串，或者使用了不支持的字符串值。
    *   **后果:** 浏览器会忽略该值，使用默认的屏幕方向行为。
*   **调试线索:** 检查 `manifest->orientation` 的值。

**4. `IconsParseRules` (图标解析规则):**

*   **功能:** 测试 `icons` 属性（一个包含图标对象数组）的解析，包括 `src`（图标路径）, `type`（MIME 类型）, 和 `sizes`（图标尺寸）。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   `icons` 属性用于指定 Web 应用在各种场景下使用的图标，例如添加到桌面、任务栏、应用切换器等。
    *   这些图标可以被操作系统或浏览器使用，但通常不会直接在 HTML 或 CSS 中引用（除非你手动获取 Manifest 数据并使用）。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** `R"({ "icons": [ { "src": "icon.png", "sizes": "192x192" } ] })"`
    *   **预期输出:** `manifest->icons` 包含一个元素，该元素的 `src` 为 "http://foo.com/icon.png"（假设 Manifest 文件位于 http://foo.com/manifest.json），`sizes` 包含一个尺寸 (192, 192)。
    *   **假设输入:** `R"({ "icons": [ { "sizes": "192x192" } ] })"`
    *   **预期输出:** `manifest->icons` 为空，因为缺少 `src` 属性。
*   **用户或编程常见的使用错误:**
    *   **错误:**  `icons` 数组为空或包含格式错误的图标对象（例如缺少 `src`）。
    *   **后果:**  Web 应用可能缺少必要的图标，导致在操作系统中显示默认图标或无法正常添加到主屏幕。
*   **调试线索:** 检查 `manifest->icons` 数组的大小和每个元素的属性值。

**5. `ScreenshotsParseRules` (屏幕截图解析规则):**

*   **功能:** 测试 `screenshots` 属性（一个包含截图对象数组）的解析，主要测试 `src` 属性。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   `screenshots` 属性用于向用户展示应用的预览图，例如在应用商店或其他安装界面。
    *   与 `icons` 类似，这些截图通常不会直接在 Web 应用的代码中使用。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** `R"({ "screenshots": [ { "src": "screenshot.png" } ] })"`
    *   **预期输出:** `manifest->screenshots` 包含一个元素，该元素的 `image->src` 为 "http://foo.com/screenshot.png"。
    *   **假设输入:** `R"({ "screenshots": [ {} ] })"`
    *   **预期输出:** `manifest->screenshots` 为空，因为缺少必要的 `src` 属性。
*   **用户或编程常见的使用错误:**
    *   **错误:** `screenshots` 数组为空或包含缺少 `src` 的截图对象.
    *   **后果:**  可能无法在应用商店或安装界面正常显示应用预览。
*   **调试线索:** 检查 `manifest->screenshots` 数组的大小和每个元素的 `image->src` 值。

**6. `ScreenshotFormFactorParseRules` (屏幕截图设备类型解析规则):**

*   **功能:** 测试 `screenshots` 数组中每个截图对象的 `form_factor` 属性的解析，该属性用于指定截图适用的设备类型（例如 "narrow"）。
*   **与 JavaScript, HTML, CSS 的关系:**  不直接相关。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** `R"({ "screenshots": [ { "src": "a.png", "form_factor": "narrow" } ] })"`
    *   **预期输出:** `manifest->screenshots[0]->form_factor` 的值为 `mojom::blink::ManifestScreenshot::FormFactor::kNarrow`。
    *   **假设输入:** `R"({ "screenshots": [ { "src": "a.png", "form_factor": "wide" } ] })"`
    *   **预期输出:** `manifest->screenshots[0]->form_factor` 的值为默认值 (`mojom::blink::ManifestScreenshot::FormFactor::kUnknown`)，并记录一个错误。
*   **用户或编程常见的使用错误:**
    *   **错误:**  使用了不支持的 `form_factor` 值。
    *   **后果:** 浏览器会忽略该值。
*   **调试线索:** 检查 `manifest->screenshots` 中对应元素的 `form_factor` 值。

**7. `ScreenshotLabelRules` (屏幕截图标签解析规则):**

*   **功能:** 测试 `screenshots` 数组中每个截图对象的 `label` 属性的解析，该属性提供截图的描述文本，用于可访问性。
*   **与 JavaScript, HTML, CSS 的关系:**  不直接相关，主要用于辅助功能。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** `R"({ "screenshots": [ { "src": "a.png", "label": "Example Screenshot" } ] })"`
    *   **预期输出:** `manifest->screenshots[0]->label` 的值为 "Example Screenshot"。
    *   **假设输入:** `R"({ "screenshots": [ { "src": "a.png", "label": 123 } ] })"`
    *   **预期输出:** `manifest->screenshots[0]->label` 为空，并记录一个错误。
*   **用户或编程常见的使用错误:**
    *   **错误:** `label` 的值不是字符串类型。
    *   **后果:** 浏览器会忽略该 `label`。
*   **调试线索:** 检查 `manifest->screenshots` 中对应元素的 `label` 值。

**8. `IconSrcParseRules`, `IconTypeParseRules`, `IconSizesParseRules`, `IconPurposeParseRules`:**

*   **功能:** 这些测试分别专注于 `icons` 数组中每个图标对象的 `src`, `type`, `sizes`, 和 `purpose` 属性的解析规则，包括：
    *   **`IconSrcParseRules`:**  测试 `src` 属性的解析，包括空白符处理、类型检查以及基于 Manifest 文件 URL 的路径解析。
    *   **`IconTypeParseRules`:** 测试 `type` 属性的解析，包括空白符处理和类型检查。
    *   **`IconSizesParseRules`:** 测试 `sizes` 属性的解析，包括各种尺寸格式（例如 "42x42", "any"）的处理，以及错误格式的识别。
    *   **`IconPurposeParseRules`:** 测试 `purpose` 属性的解析，该属性用于描述图标的用途（例如 "maskable", "monochrome"）。测试包括有效值的解析、空白符处理、重复值的处理以及无效值的处理（忽略或导致整个图标被移除）。
*   **与 JavaScript, HTML, CSS 的关系:**  参考 `IconsParseRules` 的说明。
*   **逻辑推理、用户或编程常见的使用错误、调试线索:**  类似于 `IconsParseRules`，但更细粒度地针对每个属性进行测试。

**9. `ShortcutsParseRules` (快捷方式解析规则):**

*   **功能:**  开始测试 `shortcuts` 属性（一个包含快捷方式对象数组）的解析。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   `shortcuts` 允许开发者定义在应用图标上长按或右键点击时显示的快捷操作列表。
    *   这些快捷方式通常会链接到应用内的特定页面或功能。
*   **逻辑推理 (假设输入与输出):**  由于代码片段在这里结束，无法完整推断，但可以预期会测试 `url`, `name`, `icons` 等属性的解析。
*   **用户或编程常见的使用错误:**  例如缺少 `url` 或 `name` 属性。
*   **调试线索:** 检查 `manifest->shortcuts` 数组的内容。

**总结第2部分的功能:**

这部分 `manifest_parser_unittest.cc` 文件的主要功能是**细致地验证 Manifest 解析器对于 `display` 及其覆盖属性、屏幕方向、图标和屏幕截图相关属性的解析逻辑是否正确**。它通过大量的单元测试覆盖了各种可能的输入情况，包括有效值、无效值、类型错误以及边界情况，确保 Manifest 文件中的这些关键属性能够被准确地解析和使用，从而保证 Web App 的行为符合预期。
### 提示词
```
这是目录为blink/renderer/modules/manifest/manifest_parser_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ature_list;
    feature_list.InitAndDisableFeature(blink::features::kWebAppBorderless);
    auto& manifest = ParseManifest(R"({ "display": "borderless" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kUndefined);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("inapplicable 'display' value ignored.", errors()[0]);
  }

  // Parsing fails for 'borderless' when Borderless flag is enabled.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndEnableFeature(blink::features::kWebAppBorderless);
    auto& manifest = ParseManifest(R"({ "display": "borderless" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kUndefined);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("inapplicable 'display' value ignored.", errors()[0]);
  }

  // Parsing fails for 'tabbed' when flag is disabled.
  {
    ScopedWebAppTabStripForTest tabbed(false);
    auto& manifest = ParseManifest(R"({ "display": "tabbed" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kUndefined);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("inapplicable 'display' value ignored.", errors()[0]);
  }

  // Parsing fails for 'tabbed' when flag is enabled.
  {
    ScopedWebAppTabStripForTest tabbed(true);
    auto& manifest = ParseManifest(R"({ "display": "tabbed" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kUndefined);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("inapplicable 'display' value ignored.", errors()[0]);
  }
}

TEST_F(ManifestParserTest, DisplayOverrideParseRules) {

  // Smoke test: if no display_override, no value.
  {
    auto& manifest = ParseManifest(R"({ "display_override": [] })");
    EXPECT_TRUE(manifest->display_override.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if not array, value will be ignored
  {
    auto& manifest = ParseManifest(R"({ "display_override": 23 })");
    EXPECT_TRUE(manifest->display_override.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'display_override' ignored, type array expected.",
              errors()[0]);
  }

  // Smoke test: if array value is not a string, it will be ignored
  {
    auto& manifest = ParseManifest(R"({ "display_override": [ 23 ] })");
    EXPECT_TRUE(manifest->display_override.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if array value is not not recognized, it will be ignored
  {
    auto& manifest = ParseManifest(R"({ "display_override": [ "test" ] })");
    EXPECT_TRUE(manifest->display_override.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Case insensitive
  {
    auto& manifest = ParseManifest(R"({ "display_override": [ "BROWSER" ] })");
    EXPECT_FALSE(manifest->display_override.empty());
    EXPECT_EQ(manifest->display_override[0],
              blink::mojom::DisplayMode::kBrowser);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespace
  {
    auto& manifest =
        ParseManifest(R"({ "display_override": [ " browser " ] })");
    EXPECT_FALSE(manifest->display_override.empty());
    EXPECT_EQ(manifest->display_override[0],
              blink::mojom::DisplayMode::kBrowser);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'browser'
  {
    auto& manifest = ParseManifest(R"({ "display_override": [ "browser" ] })");
    EXPECT_FALSE(manifest->display_override.empty());
    EXPECT_EQ(manifest->display_override[0],
              blink::mojom::DisplayMode::kBrowser);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'browser', 'minimal-ui'
  {
    auto& manifest =
        ParseManifest(R"({ "display_override": [ "browser", "minimal-ui" ] })");
    EXPECT_FALSE(manifest->display_override.empty());
    EXPECT_EQ(manifest->display_override[0],
              blink::mojom::DisplayMode::kBrowser);
    EXPECT_EQ(manifest->display_override[1],
              blink::mojom::DisplayMode::kMinimalUi);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // if array value is not not recognized, it will be ignored
  // Accept 'browser', 'minimal-ui'
  {
    auto& manifest = ParseManifest(
        R"({ "display_override": [ 3, "browser", "invalid-display",
        "minimal-ui" ] })");
    EXPECT_FALSE(manifest->display_override.empty());
    EXPECT_EQ(manifest->display_override[0],
              blink::mojom::DisplayMode::kBrowser);
    EXPECT_EQ(manifest->display_override[1],
              blink::mojom::DisplayMode::kMinimalUi);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // validate both display and display-override fields are parsed
  // if array value is not not recognized, it will be ignored
  // Accept 'browser', 'minimal-ui', 'standalone'
  {
    auto& manifest = ParseManifest(
        R"({ "display": "standalone", "display_override": [ "browser",
        "minimal-ui", "standalone" ] })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kStandalone);
    EXPECT_EQ(0u, GetErrorCount());
    EXPECT_FALSE(manifest->display_override.empty());
    EXPECT_EQ(manifest->display_override[0],
              blink::mojom::DisplayMode::kBrowser);
    EXPECT_EQ(manifest->display_override[1],
              blink::mojom::DisplayMode::kMinimalUi);
    EXPECT_EQ(manifest->display_override[2],
              blink::mojom::DisplayMode::kStandalone);
    EXPECT_FALSE(IsManifestEmpty(manifest));
  }

  // validate duplicate entries.
  // Accept 'browser', 'minimal-ui', 'browser'
  {
    auto& manifest =
        ParseManifest(R"({ "display_override": [ "browser", "minimal-ui",
        "browser" ] })");
    EXPECT_FALSE(manifest->display_override.empty());
    EXPECT_EQ(manifest->display_override[0],
              blink::mojom::DisplayMode::kBrowser);
    EXPECT_EQ(manifest->display_override[1],
              blink::mojom::DisplayMode::kMinimalUi);
    EXPECT_EQ(manifest->display_override[2],
              blink::mojom::DisplayMode::kBrowser);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'window-controls-overlay'.
  {
    auto& manifest = ParseManifest(
        R"({ "display_override": [ "window-controls-overlay" ] })");
    EXPECT_FALSE(manifest->display_override.empty());
    EXPECT_EQ(manifest->display_override[0],
              blink::mojom::DisplayMode::kWindowControlsOverlay);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Reject 'borderless' when Borderless flag is disabled.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndDisableFeature(blink::features::kWebAppBorderless);
    auto& manifest =
        ParseManifest(R"({ "display_override": [ "borderless" ] })");
    EXPECT_TRUE(manifest->display_override.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'borderless' when Borderless flag is enabled.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndEnableFeature(blink::features::kWebAppBorderless);
    auto& manifest =
        ParseManifest(R"({ "display_override": [ "borderless" ] })");
    EXPECT_FALSE(manifest->display_override.empty());
    EXPECT_EQ(manifest->display_override[0],
              blink::mojom::DisplayMode::kBorderless);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Ignore 'tabbed' when flag is disabled.
  {
    ScopedWebAppTabStripForTest tabbed(false);
    auto& manifest = ParseManifest(R"({ "display_override": [ "tabbed" ] })");
    EXPECT_TRUE(manifest->display_override.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'tabbed' when flag is enabled.
  {
    ScopedWebAppTabStripForTest tabbed(true);
    auto& manifest = ParseManifest(R"({ "display_override": [ "tabbed" ] })");
    EXPECT_FALSE(manifest->display_override.empty());
    EXPECT_EQ(manifest->display_override[0],
              blink::mojom::DisplayMode::kTabbed);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, OrientationParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(R"({ "orientation": "natural" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::NATURAL);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(R"({ "orientation": "natural" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::NATURAL);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if name isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "orientation": {} })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::DEFAULT);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'orientation' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if name isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "orientation": 42 })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::DEFAULT);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'orientation' ignored, type string expected.",
              errors()[0]);
  }

  // Parse fails if string isn't known.
  {
    auto& manifest = ParseManifest(R"({ "orientation": "naturalish" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::DEFAULT);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("unknown 'orientation' value ignored.", errors()[0]);
  }

  // Accept 'any'.
  {
    auto& manifest = ParseManifest(R"({ "orientation": "any" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::ANY);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'natural'.
  {
    auto& manifest = ParseManifest(R"({ "orientation": "natural" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::NATURAL);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'landscape'.
  {
    auto& manifest = ParseManifest(R"({ "orientation": "landscape" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::LANDSCAPE);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'landscape-primary'.
  {
    auto& manifest = ParseManifest(R"({ "orientation": "landscape-primary" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::LANDSCAPE_PRIMARY);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'landscape-secondary'.
  {
    auto& manifest =
        ParseManifest(R"({ "orientation": "landscape-secondary" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::LANDSCAPE_SECONDARY);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'portrait'.
  {
    auto& manifest = ParseManifest(R"({ "orientation": "portrait" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::PORTRAIT);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'portrait-primary'.
  {
    auto& manifest = ParseManifest(R"({ "orientation": "portrait-primary" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::PORTRAIT_PRIMARY);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'portrait-secondary'.
  {
    auto& manifest =
        ParseManifest(R"({ "orientation": "portrait-secondary" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::PORTRAIT_SECONDARY);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Case insensitive.
  {
    auto& manifest = ParseManifest(R"({ "orientation": "LANDSCAPE" })");
    EXPECT_EQ(manifest->orientation,
              device::mojom::ScreenOrientationLockType::LANDSCAPE);
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, IconsParseRules) {
  // Smoke test: if no icon, no value.
  {
    auto& manifest = ParseManifest(R"({ "icons": [] })");
    EXPECT_TRUE(manifest->icons.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if empty icon, no value.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {} ] })");
    EXPECT_TRUE(manifest->icons.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: icon with invalid src, no value.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ { "icons": [] } ] })");
    EXPECT_TRUE(manifest->icons.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if icon with empty src, it will be present in the list.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ { "src": "" } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    EXPECT_EQ(icons.size(), 1u);
    EXPECT_EQ(icons[0]->src.GetString(), "http://foo.com/manifest.json");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if one icons with valid src, it will be present in the list.
  {
    auto& manifest = ParseManifest(R"({ "icons": [{ "src": "foo.jpg" }] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    EXPECT_EQ(icons.size(), 1u);
    EXPECT_EQ(icons[0]->src.GetString(), "http://foo.com/foo.jpg");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test.
  {
    auto& manifest = ParseManifest(R"(
          {
            "icons": [
              {
                "src": "foo.webp",
                "type": "image/webp",
                "sizes": "192x192"
              },
              {
                "src": "foo.svg",
                "type": "image/svg+xml",
                "sizes": "144x144"
              }
            ]
          }
        )");
    ASSERT_EQ(manifest->icons.size(), 2u);
    EXPECT_EQ(manifest->icons[0]->src, KURL(DefaultDocumentUrl(), "foo.webp"));
    EXPECT_EQ(manifest->icons[0]->type, "image/webp");
    EXPECT_EQ(manifest->icons[0]->sizes.size(), 1u);
    EXPECT_EQ(manifest->icons[0]->sizes[0].width(), 192);
    EXPECT_EQ(manifest->icons[0]->sizes[0].height(), 192);
    EXPECT_EQ(manifest->icons[1]->src, KURL(DefaultDocumentUrl(), "foo.svg"));
    EXPECT_EQ(manifest->icons[1]->type, "image/svg+xml");
    EXPECT_EQ(manifest->icons[1]->sizes.size(), 1u);
    EXPECT_EQ(manifest->icons[1]->sizes[0].width(), 144);
    EXPECT_EQ(manifest->icons[1]->sizes[0].height(), 144);
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, ScreenshotsParseRules) {
  // Smoke test: if no screenshot, no value.
  {
    auto& manifest = ParseManifest(R"({ "screenshots": [] })");
    EXPECT_TRUE(manifest->screenshots.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if empty screenshot, no value.
  {
    auto& manifest = ParseManifest(R"({ "screenshots": [ {} ] })");
    EXPECT_TRUE(manifest->screenshots.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: screenshot with invalid src, no value.
  {
    auto& manifest =
        ParseManifest(R"({ "screenshots": [ { "screenshots": [] } ] })");
    EXPECT_TRUE(manifest->screenshots.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if screenshot with empty src, it will be present in the list.
  {
    auto& manifest = ParseManifest(R"({ "screenshots": [ { "src": "" } ] })");
    EXPECT_FALSE(manifest->screenshots.empty());

    auto& screenshots = manifest->screenshots;
    EXPECT_EQ(screenshots.size(), 1u);
    EXPECT_EQ(screenshots[0]->image->src.GetString(),
              "http://foo.com/manifest.json");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if one icons has valid src, it will be present in the list.
  {
    auto& manifest =
        ParseManifest(R"({ "screenshots": [{ "src": "foo.jpg" }] })");
    EXPECT_FALSE(manifest->screenshots.empty());

    auto& screenshots = manifest->screenshots;
    EXPECT_EQ(screenshots.size(), 1u);
    EXPECT_EQ(screenshots[0]->image->src.GetString(), "http://foo.com/foo.jpg");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, ScreenshotFormFactorParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(
        R"({ "screenshots": [{ "src": "foo.jpg", "form_factor": "narrow" }] })");
    EXPECT_FALSE(manifest->screenshots.empty());

    auto& screenshots = manifest->screenshots;
    EXPECT_EQ(screenshots.size(), 1u);
    EXPECT_EQ(screenshots[0]->form_factor,
              mojom::blink::ManifestScreenshot::FormFactor::kNarrow);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Unspecified.
  {
    auto& manifest =
        ParseManifest(R"({ "screenshots": [{ "src": "foo.jpg"}] })");
    EXPECT_FALSE(manifest->screenshots.empty());

    auto& screenshots = manifest->screenshots;
    EXPECT_EQ(screenshots.size(), 1u);
    EXPECT_EQ(screenshots[0]->form_factor,
              mojom::blink::ManifestScreenshot::FormFactor::kUnknown);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Invalid type.
  {
    auto& manifest = ParseManifest(
        R"({ "screenshots": [{ "src": "foo.jpg", "form_factor": 1}] })");
    EXPECT_FALSE(manifest->screenshots.empty());

    auto& screenshots = manifest->screenshots;
    EXPECT_EQ(screenshots.size(), 1u);
    EXPECT_EQ(screenshots[0]->form_factor,
              mojom::blink::ManifestScreenshot::FormFactor::kUnknown);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(1u, GetErrorCount());
  }

  // Unrecognized string.
  {
    auto& manifest = ParseManifest(
        R"({ "screenshots": [{ "src": "foo.jpg", "form_factor": "windows"}] })");
    EXPECT_FALSE(manifest->screenshots.empty());

    auto& screenshots = manifest->screenshots;
    EXPECT_EQ(screenshots.size(), 1u);
    EXPECT_EQ(screenshots[0]->form_factor,
              mojom::blink::ManifestScreenshot::FormFactor::kUnknown);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(1u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, ScreenshotLabelRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(
        R"({ "screenshots": [{ "src": "foo.jpg", "label": "example screenshot." }] })");
    EXPECT_FALSE(manifest->screenshots.empty());

    auto& screenshots = manifest->screenshots;
    EXPECT_EQ(screenshots.size(), 1u);
    EXPECT_EQ(screenshots[0]->label, "example screenshot.");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }
  // Unspecified.
  {
    auto& manifest =
        ParseManifest(R"({ "screenshots": [{ "src": "foo.jpg"}] })");
    EXPECT_FALSE(manifest->screenshots.empty());

    auto& screenshots = manifest->screenshots;
    EXPECT_EQ(screenshots.size(), 1u);
    EXPECT_TRUE(screenshots[0]->label.IsNull());
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }
  // Empty string.
  {
    auto& manifest = ParseManifest(
        R"({ "screenshots": [{ "src": "foo.jpg", "label": "" }] })");
    EXPECT_FALSE(manifest->screenshots.empty());

    auto& screenshots = manifest->screenshots;
    EXPECT_EQ(screenshots.size(), 1u);
    EXPECT_EQ(screenshots[0]->label, "");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }
  // Invalid type.
  {
    auto& manifest = ParseManifest(
        R"({ "screenshots": [{ "src": "foo.jpg", "label": 2 }] })");
    EXPECT_FALSE(manifest->screenshots.empty());

    auto& screenshots = manifest->screenshots;
    EXPECT_EQ(screenshots.size(), 1u);
    EXPECT_TRUE(screenshots[0]->label.IsNull());
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(1u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, IconSrcParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "foo.png" } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->src, KURL(DefaultDocumentUrl(), "foo.png"));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Whitespaces.
  {
    auto& manifest =
        ParseManifest(R"({ "icons": [ {"src": "   foo.png   " } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->src, KURL(DefaultDocumentUrl(), "foo.png"));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if property isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": {} } ] })");
    EXPECT_TRUE(manifest->icons.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'src' ignored, type string expected.", errors()[0]);
  }

  // Don't parse if property isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": 42 } ] })");
    EXPECT_TRUE(manifest->icons.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'src' ignored, type string expected.", errors()[0]);
  }

  // Resolving has to happen based on the document_url.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "icons": [ {"src": "icons/foo.png" } ] })",
        KURL("http://foo.com/landing/index.html"), DefaultManifestUrl());
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->src.GetString(),
              "http://foo.com/landing/icons/foo.png");
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, IconTypeParseRules) {
  // Smoke test.
  {
    auto& manifest =
        ParseManifest(R"({ "icons": [ {"src": "", "type": "foo" } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->type, "foo");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest =
        ParseManifest(R"({ "icons": [ {"src": "", "type": "  foo  " } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->type, "foo");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if property isn't a string.
  {
    auto& manifest =
        ParseManifest(R"({ "icons": [ {"src": "", "type": {} } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_TRUE(manifest->icons[0]->type.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'type' ignored, type string expected.", errors()[0]);
  }

  // Don't parse if property isn't a string.
  {
    auto& manifest =
        ParseManifest(R"({ "icons": [ {"src": "", "type": 42 } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_TRUE(manifest->icons[0]->type.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'type' ignored, type string expected.", errors()[0]);
  }
}

TEST_F(ManifestParserTest, IconSizesParseRules) {
  // Smoke test.
  {
    auto& manifest =
        ParseManifest(R"({ "icons": [ {"src": "", "sizes": "42x42" } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->sizes.size(), 1u);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest =
        ParseManifest(R"({ "icons": [ {"src": "", "sizes": "  42x42  " } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->sizes.size(), 1u);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Ignore sizes if property isn't a string.
  {
    auto& manifest =
        ParseManifest(R"({ "icons": [ {"src": "", "sizes": {} } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->sizes.size(), 0u);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'sizes' ignored, type string expected.", errors()[0]);
  }

  // Ignore sizes if property isn't a string.
  {
    auto& manifest =
        ParseManifest(R"({ "icons": [ {"src": "", "sizes": 42 } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->sizes.size(), 0u);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'sizes' ignored, type string expected.", errors()[0]);
  }

  // Smoke test: value correctly parsed.
  {
    auto& manifest = ParseManifest(
        R"({ "icons": [ {"src": "", "sizes": "42x42  48x48" } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    EXPECT_EQ(icons[0]->sizes[0], gfx::Size(42, 42));
    EXPECT_EQ(icons[0]->sizes[1], gfx::Size(48, 48));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // <WIDTH>'x'<HEIGHT> and <WIDTH>'X'<HEIGHT> are equivalent.
  {
    auto& manifest = ParseManifest(
        R"({ "icons": [ {"src": "", "sizes": "42X42  48X48" } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    EXPECT_EQ(icons[0]->sizes[0], gfx::Size(42, 42));
    EXPECT_EQ(icons[0]->sizes[1], gfx::Size(48, 48));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Twice the same value is parsed twice.
  {
    auto& manifest = ParseManifest(
        R"({ "icons": [ {"src": "", "sizes": "42X42  42x42" } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    EXPECT_EQ(icons[0]->sizes[0], gfx::Size(42, 42));
    EXPECT_EQ(icons[0]->sizes[1], gfx::Size(42, 42));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Width or height can't start with 0.
  {
    auto& manifest = ParseManifest(
        R"({ "icons": [ {"src": "", "sizes": "004X007  042x00" } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->sizes.size(), 0u);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("found icon with no valid size.", errors()[0]);
  }

  // Width and height MUST contain digits.
  {
    auto& manifest = ParseManifest(
        R"({ "icons": [ {"src": "", "sizes": "e4X1.0  55ax1e10" } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->sizes.size(), 0u);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("found icon with no valid size.", errors()[0]);
  }

  // 'any' is correctly parsed and transformed to gfx::Size(0,0).
  {
    auto& manifest = ParseManifest(
        R"({ "icons": [ {"src": "", "sizes": "any AnY ANY aNy" } ] })");
    gfx::Size any = gfx::Size(0, 0);
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    EXPECT_EQ(icons[0]->sizes.size(), 4u);
    EXPECT_EQ(icons[0]->sizes[0], any);
    EXPECT_EQ(icons[0]->sizes[1], any);
    EXPECT_EQ(icons[0]->sizes[2], any);
    EXPECT_EQ(icons[0]->sizes[3], any);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Some invalid width/height combinations.
  {
    auto& manifest = ParseManifest(
        R"({ "icons": [ {"src": "", "sizes": "x 40xx 1x2x3 x42 42xx42" } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->sizes.size(), 0u);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("found icon with no valid size.", errors()[0]);
  }
}

TEST_F(ManifestParserTest, IconPurposeParseRules) {
  const String kPurposeParseStringError =
      "property 'purpose' ignored, type string expected.";
  const String kPurposeInvalidValueError =
      "found icon with no valid purpose; ignoring it.";
  const String kSomeInvalidPurposeError =
      "found icon with one or more invalid purposes; those purposes are "
      "ignored.";

  // Smoke test.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "",
        "purpose": "any" } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->purpose.size(), 1u);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim leading and trailing whitespaces.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "",
        "purpose": "  any  " } ] })");
    EXPECT_FALSE(manifest->icons.empty());
    EXPECT_EQ(manifest->icons[0]->purpose.size(), 1u);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // 'any' is added when property isn't present.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "" } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    EXPECT_EQ(icons[0]->purpose.size(), 1u);
    EXPECT_EQ(icons[0]->purpose[0],
              mojom::blink::ManifestImageResource::Purpose::ANY);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // 'any' is added with error message when property isn't a string (is a
  // number).
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "",
        "purpose": 42 } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    EXPECT_EQ(icons[0]->purpose.size(), 1u);
    EXPECT_EQ(icons[0]->purpose[0],
              mojom::blink::ManifestImageResource::Purpose::ANY);
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(kPurposeParseStringError, errors()[0]);
  }

  // 'any' is added with error message when property isn't a string (is a
  // dictionary).
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "",
        "purpose": {} } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    EXPECT_EQ(icons[0]->purpose.size(), 1u);
    EXPECT_EQ(icons[0]->purpose[0],
              mojom::blink::ManifestImageResource::Purpose::ANY);
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(kPurposeParseStringError, errors()[0]);
  }

  // Smoke test: values correctly parsed.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "",
        "purpose": "Any Monochrome Maskable" } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    ASSERT_EQ(icons[0]->purpose.size(), 3u);
    EXPECT_EQ(icons[0]->purpose[0],
              mojom::blink::ManifestImageResource::Purpose::ANY);
    EXPECT_EQ(icons[0]->purpose[1],
              mojom::blink::ManifestImageResource::Purpose::MONOCHROME);
    EXPECT_EQ(icons[0]->purpose[2],
              mojom::blink::ManifestImageResource::Purpose::MASKABLE);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces between values.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "",
        "purpose": "  Any   Monochrome  " } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    ASSERT_EQ(icons[0]->purpose.size(), 2u);
    EXPECT_EQ(icons[0]->purpose[0],
              mojom::blink::ManifestImageResource::Purpose::ANY);
    EXPECT_EQ(icons[0]->purpose[1],
              mojom::blink::ManifestImageResource::Purpose::MONOCHROME);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Twice the same value is parsed twice.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "",
        "purpose": "monochrome monochrome" } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    ASSERT_EQ(icons[0]->purpose.size(), 2u);
    EXPECT_EQ(icons[0]->purpose[0],
              mojom::blink::ManifestImageResource::Purpose::MONOCHROME);
    EXPECT_EQ(icons[0]->purpose[1],
              mojom::blink::ManifestImageResource::Purpose::MONOCHROME);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Invalid icon purpose is ignored.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "",
        "purpose": "monochrome fizzbuzz" } ] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    ASSERT_EQ(icons[0]->purpose.size(), 1u);
    EXPECT_EQ(icons[0]->purpose[0],
              mojom::blink::ManifestImageResource::Purpose::MONOCHROME);
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(kSomeInvalidPurposeError, errors()[0]);
  }

  // If developer-supplied purpose is invalid, entire icon is removed.
  {
    auto& manifest = ParseManifest(R"({ "icons": [ {"src": "",
        "purpose": "fizzbuzz" } ] })");
    ASSERT_TRUE(manifest->icons.empty());
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(kPurposeInvalidValueError, errors()[0]);
  }

  // Two icons, one with an invalid purpose and the other normal.
  {
    auto& manifest = ParseManifest(
        R"({ "icons": [ {"src": "", "purpose": "fizzbuzz" },
                       {"src": "" }] })");
    EXPECT_FALSE(manifest->icons.empty());

    auto& icons = manifest->icons;
    ASSERT_EQ(1u, icons.size());
    ASSERT_EQ(icons[0]->purpose.size(), 1u);
    EXPECT_EQ(icons[0]->purpose[0],
              mojom::blink::ManifestImageResource::Purpose::ANY);
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(kPurposeInvalidValueError, errors()[0]);
  }
}

TEST_F(ManifestParserTest, ShortcutsParseRules) {
  // Smoke test: if no shortcut, no value.
  {
    auto& manifest = ParseManifest(R"({ "shortcuts": [] })");
    EXPECT_TRUE(manifest->shortcuts.empty());
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Smoke test: if empty shortcut, no value.
  {
    auto& manifest = ParseManifest(R"({ "shortcuts": [ {} ] })");
    EXPECT_TRUE(manifest->icons.empty());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'url' of 'shortcut' not present.", errors()[0]
```