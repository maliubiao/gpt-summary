Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core task is to understand the *purpose* of the test file. The filename `web_font_typeface_factory_test.cc` immediately suggests it's testing `WebFontTypefaceFactory`. The "test" suffix confirms this.

2. **Identify the Tested Class:**  The `#include "third_party/blink/renderer/platform/fonts/web_font_typeface_factory.h"` line is a dead giveaway. This is the main class under scrutiny.

3. **Examine the Test Structure:** Look for the standard C++ testing framework keywords. `#include "testing/gmock/include/gmock/gmock.h"` and `#include "testing/gtest/include/gtest/gtest.h"` indicate Google Test and Google Mock are in use. The presence of `TEST(WebFontTypefaceFactoryTest, ...)` clearly defines individual test cases within a test suite named `WebFontTypefaceFactoryTest`.

4. **Analyze Individual Test Cases:**  Go through each `TEST(...)` block and try to understand what it's checking. Look for:
    * **Setup:** What data or objects are being created? (e.g., `sk_sp<SkData> data = SkData::MakeEmpty();`, `MockFontFormatCheck mock_font_format_check(data);`)
    * **Expectations:** What conditions are being asserted? (e.g., `EXPECT_CALL(mock_font_format_check, IsVariableFont()).Times(AtLeast(1));`)  These are the core of the test.
    * **Action:** What is the code under test being called with? (e.g., `WebFontTypefaceFactory::CreateTypeface(...)`)
    * **Assertions (Implicit):** While not always explicit `EXPECT_TRUE` or `EXPECT_FALSE`, the setup and expectations imply assertions about the behavior of `CreateTypeface`.

5. **Identify Mock Objects:** The `MockFontFormatCheck` class is a key element. Recognize that it's used to simulate the behavior of `FontFormatCheck` and control its return values in different test scenarios. This is crucial for isolating the `WebFontTypefaceFactory`'s logic.

6. **Focus on the Logic:**  Pay attention to the different scenarios being tested. Look for patterns:
    * **Feature Flags:**  The use of `ScopedFontationsForSelectedFormatsForTest` and `ScopedFontationsFontBackendForTest` hints at testing different configurations or feature states.
    * **Font Formats:** The `Is...ColorFont` and `Is...OutlineFont` methods of `MockFontFormatCheck` suggest the tests are examining how different font formats are handled.
    * **Platform Dependencies:** The `#if BUILDFLAG(IS_WIN)` and `#if BUILDFLAG(IS_APPLE)` blocks indicate platform-specific behavior is being tested.
    * **Instantiators:** The `g_expect_system`, `g_expect_fontations`, and `g_expect_fallback` variables and their usage in `CreateTypeface` are important for understanding which instantiation path is expected in each case.

7. **Relate to Web Technologies (HTML, CSS, JavaScript):**  This requires connecting the low-level font handling to how it's used in web development.
    * **CSS `@font-face`:**  Think about how CSS loads and uses fonts. The test directly relates to the browser's internal process of taking font data and creating a usable typeface.
    * **Font Formats:** Recognize that the tested font formats (COLRv0/v1, CFF2, CBDT/CBLC, SBIT, variable fonts) are all relevant to web fonts.
    * **JavaScript Font API (Indirect):** While not directly tested, understand that the `WebFontTypefaceFactory` is part of the rendering pipeline that eventually makes fonts available to JavaScript through APIs like `CanvasRenderingContext2D.fillText()`.

8. **Infer Potential Errors:**  Consider what could go wrong in the `WebFontTypefaceFactory`'s logic if it wasn't implemented correctly. Think about:
    * **Incorrect Format Detection:** The factory might misidentify a font format, leading to rendering errors or crashes.
    * **Incorrect Instantiator Selection:** Choosing the wrong method to create the typeface could lead to crashes or incorrect rendering depending on the platform and font features.
    * **Platform-Specific Issues:**  Bugs might exist on one platform but not another.

9. **Formulate Assumptions and Outputs:** For each test case, try to reason about what input to `CreateTypeface` (the font data and the mock object's return values) would lead to which output (which of the `expect_called` functions would be executed).

10. **Structure the Answer:** Organize the findings into logical sections: Purpose, Relation to Web Technologies, Logic and Assumptions, and Common Errors. Use clear and concise language, and provide specific examples where possible. Use formatting (like bullet points and code blocks) to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This is just testing font loading."  *Correction:*  It's more specific than that. It's testing the *factory* responsible for *choosing the right way* to load a font based on its format and platform.
* **Realization:** The `g_expect_*` variables are crucial. Initially, I might have overlooked their significance. Recognizing that they represent different instantiation strategies is key to understanding the test logic.
* **Connecting to Web Tech:**  It's not just about C++ code. Actively think about how the concepts being tested map to web development practices. This strengthens the explanation.
* **Focus on *why*:**  Don't just describe *what* the code does. Explain *why* these tests are important and what problems they are designed to prevent.

By following these steps, including the self-correction and refinement, we can arrive at a comprehensive and accurate understanding of the test file's purpose and its implications for web technologies.
这个文件 `web_font_typeface_factory_test.cc` 是 Chromium Blink 引擎中用于测试 `WebFontTypefaceFactory` 类的单元测试文件。 `WebFontTypefaceFactory` 的作用是根据提供的字体数据和系统环境，创建合适的字体排版对象 (`SkTypeface`)。

**功能总结:**

这个测试文件的主要功能是验证 `WebFontTypefaceFactory::CreateTypeface` 方法在不同条件下是否能正确选择字体排版对象的创建方式。它模拟了各种场景，包括：

* **不同的字体格式:** 测试对不同 OpenType 字体格式 (例如 COLRv0, COLRv1, CFF2, CBDT/CBLC, SBix, Variable Fonts) 的处理。
* **不同的平台:**  通过 `BUILDFLAG(IS_WIN)` 和 `BUILDFLAG(IS_APPLE)` 等宏，测试在 Windows 和 Apple 平台上的特定行为。
* **Fontations 特性开关:**  通过 `ScopedFontationsForSelectedFormatsForTest` 和 `ScopedFontationsFontBackendForTest` 模拟 Fontations 特性是否开启的情况，并验证其对字体创建逻辑的影响。
* **不同的字体实例化策略:**  通过 `g_expect_system`, `g_expect_fontations`, `g_expect_fallback` 等不同的 `FontInstantiator` 结构体，测试 `CreateTypeface` 方法是否会调用预期的字体创建函数 (`make_system`, `make_fontations`, `make_fallback`)。

**与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接关系到浏览器如何加载和渲染网页中使用的字体，这与 HTML, CSS 和 JavaScript 都有密切关系。

* **CSS `@font-face` 规则:**  当浏览器解析到 CSS 的 `@font-face` 规则时，它会下载指定的字体文件。 `WebFontTypefaceFactory` 的作用就是处理这些下载的字体文件数据，并将其转换为浏览器可以使用的字体排版对象。测试用例模拟了不同格式的字体文件被传入 `CreateTypeface` 方法，验证其能否正确处理。例如，如果 CSS 中使用了包含 COLRv1 彩色字体的 `@font-face` 规则，这个测试文件就验证了浏览器在处理这种字体时是否按照预期的方式创建字体排版对象。
* **JavaScript Canvas API:**  JavaScript 可以使用 Canvas API 绘制文本。  `WebFontTypefaceFactory` 创建的 `SkTypeface` 对象最终会被用于 Canvas 的文本渲染。例如，如果 JavaScript 代码使用 `ctx.font = "..."` 设置了字体，并且该字体是一个 COLRv1 彩色字体，那么这个测试文件就间接地验证了 `WebFontTypefaceFactory` 能否正确地创建这种字体，以便 Canvas 能够正确渲染。
* **HTML 文本渲染:**  最终，网页上的文本需要被渲染出来。 `WebFontTypefaceFactory` 是浏览器字体渲染管线中的关键一环，它确保了不同格式的 Web 字体能够被正确加载和使用，从而在 HTML 页面上正确显示文本。例如，如果 HTML 中使用了某个特定的字体，而该字体是 CFF2 格式，这个测试文件就验证了浏览器能否正确加载和渲染这种字体。

**逻辑推理 (假设输入与输出):**

以 `TEST(WebFontTypefaceFactoryTest, ColrV1AlwaysFallback)` 为例：

* **假设输入:**
    * `scoped_fontations_selected_formats(false)`: Fontations 特性中用于选定格式的支持被禁用。
    * `scoped_fontations(false)`: 整个 Fontations 后端特性被禁用。
    * `data`: 一个空的字体数据 (`SkData::MakeEmpty()`)。
    * `mock_font_format_check.IsColrCpalColorFontV1()` 返回 `true` (模拟传入的字体是 COLRv1 彩色字体)。
    * `g_expect_fallback` (在 Windows/Apple 平台) 或 `g_expect_system` (在其他平台) 作为 `FontInstantiator` 传入。

* **逻辑推理:**  由于 Fontations 特性被禁用，且字体是 COLRv1 格式，根据代码逻辑，Windows 和 Apple 平台会尝试使用 `make_fallback` 创建字体排版对象，而其他平台会尝试使用 `make_system`。

* **预期输出:**
    * 在 Windows/Apple 平台上，`g_expect_fallback.make_fallback` 函数会被调用，并且 `expect_called` 宏会执行，断言为真。
    * 在其他平台上，`g_expect_system.make_system` 函数会被调用，并且 `expect_called` 宏会执行，断言为真。

**用户或编程常见的使用错误 (举例说明):**

虽然这个测试文件是针对引擎内部的，但它可以帮助开发者理解一些与 Web 字体使用相关的潜在问题：

* **字体格式支持:** 用户可能会尝试在旧版浏览器中使用一些较新的字体格式（例如 COLRv1）。如果浏览器没有正确实现对该格式的支持，`WebFontTypefaceFactory` 可能无法创建字体排版对象，导致文本显示异常或者根本不显示。 这个测试文件确保了 Blink 引擎对各种字体格式的支持。
* **平台兼容性:**  某些字体格式或特性可能只在特定平台上得到支持。例如，测试用例 `ColrV0FallbackApple` 就体现了 COLRv0 字体在 Apple 平台上的特殊处理。开发者需要注意字体的平台兼容性，确保字体能在目标用户群体的设备上正常显示。
* **Fontations 特性依赖:**  如果开发者依赖于 Fontations 提供的特定字体渲染特性，但用户的浏览器禁用了 Fontations，可能会导致渲染结果与预期不符。 测试文件通过模拟 Fontations 的开启和关闭，确保了在不同配置下字体加载的正确性。
* **MIME 类型配置错误:** 当服务器提供字体文件时，如果 `Content-Type` HTTP 头配置不正确，浏览器可能无法识别字体文件的格式，导致 `WebFontTypefaceFactory` 无法正确处理。虽然这不是 `WebFontTypefaceFactory` 本身的问题，但它强调了正确配置 Web 服务器的重要性，以便浏览器能够正确加载字体资源。

总而言之，`web_font_typeface_factory_test.cc` 是 Blink 引擎中一个非常重要的测试文件，它确保了浏览器能够可靠地加载和渲染各种 Web 字体，为用户提供一致且正确的网页浏览体验。 它涵盖了不同字体格式、平台差异以及特性开关的影响，并通过单元测试的方式保证了 `WebFontTypefaceFactory` 逻辑的正确性。

### 提示词
```
这是目录为blink/renderer/platform/fonts/web_font_typeface_factory_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/fonts/web_font_typeface_factory.h"

#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/fonts/opentype/font_format_check.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

#if BUILDFLAG(IS_WIN)
#include "third_party/blink/renderer/platform/fonts/win/dwrite_font_format_support.h"
#endif

namespace blink {

using ::testing::AtLeast;
using ::testing::Return;

class MockFontFormatCheck : public FontFormatCheck {
 public:
  explicit MockFontFormatCheck(sk_sp<SkData> data) : FontFormatCheck(data) {}
  MOCK_METHOD(bool, IsVariableFont, (), (const override));
  MOCK_METHOD(bool, IsCbdtCblcColorFont, (), (const override));
  MOCK_METHOD(bool, IsColrCpalColorFontV0, (), (const override));
  MOCK_METHOD(bool, IsColrCpalColorFontV1, (), (const override));
  MOCK_METHOD(bool, IsVariableColrV0Font, (), (const override));
  MOCK_METHOD(bool, IsSbixColorFont, (), (const override));
  MOCK_METHOD(bool, IsCff2OutlineFont, (), (const override));
};

sk_sp<SkTypeface> expect_called(sk_sp<SkData>) {
  EXPECT_TRUE(true);
  return nullptr;
}

sk_sp<SkTypeface> expect_not_called(sk_sp<SkData>) {
  EXPECT_FALSE(true);
  return nullptr;
}

const WebFontTypefaceFactory::FontInstantiator g_expect_system{
    .make_system = expect_called,
    .make_fontations = expect_not_called,
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE)
    .make_fallback = expect_not_called,
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE)
};

const WebFontTypefaceFactory::FontInstantiator g_expect_fontations{
    .make_system = expect_not_called,
    .make_fontations = expect_called,
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE)
    .make_fallback = expect_not_called,
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE)
};

#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE)
const WebFontTypefaceFactory::FontInstantiator g_expect_fallback{
    .make_system = expect_not_called,
    .make_fontations = expect_not_called,
    .make_fallback = expect_called,
};
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE)

TEST(WebFontTypefaceFactoryTest, DefaultAlwaysSystem) {
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsVariableFont()).Times(AtLeast(1));
  sk_sp<SkTypeface> out_typeface;
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
                                         g_expect_system);
}

TEST(WebFontTypefaceFactoryTest, ColrV1AlwaysFallback) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      false);
  ScopedFontationsFontBackendForTest scoped_fontations(false);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsColrCpalColorFontV1())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE)
                                         g_expect_fallback
#else
                                         g_expect_system
#endif
  );
}

TEST(WebFontTypefaceFactoryTest, FontationsSelectedAlwaysColrV1) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      true);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsColrCpalColorFontV1())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
                                         g_expect_fontations);
}

TEST(WebFontTypefaceFactoryTest, Cff2AlwaysFallback) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      false);
  ScopedFontationsFontBackendForTest scoped_fontations(false);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsCff2OutlineFont())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE)
                                         g_expect_fallback
#else
                                         g_expect_system
#endif
  );
}

TEST(WebFontTypefaceFactoryTest, FontationsSelectedAlwaysCFF2) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      true);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsCff2OutlineFont())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
                                         g_expect_fontations);
}

TEST(WebFontTypefaceFactoryTest, CbdtCblcAlwaysFallback) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      false);
  ScopedFontationsFontBackendForTest scoped_fontations(false);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsCbdtCblcColorFont())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE)
                                         g_expect_fallback
#else
                                         g_expect_system
#endif
  );
}

TEST(WebFontTypefaceFactoryTest, FontationsSelectedAlwaysCbdtCblc) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      true);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsCbdtCblcColorFont())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
                                         g_expect_fontations);
}

TEST(WebFontTypefaceFactoryTest, ColrV0FallbackApple) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      false);
  ScopedFontationsFontBackendForTest scoped_fontations(false);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsColrCpalColorFontV0())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
#if BUILDFLAG(IS_APPLE)
                                         g_expect_fallback
#else
                                         g_expect_system
#endif
  );
}

TEST(WebFontTypefaceFactoryTest, VariableColrV0FallbackWindowsApple) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      false);
  ScopedFontationsFontBackendForTest scoped_fontations(false);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsColrCpalColorFontV0())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_font_format_check, IsVariableFont())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;
#if BUILDFLAG(IS_WIN)
  const WebFontTypefaceFactory::FontInstantiator& expectation =
      DWriteVersionSupportsVariations() ? g_expect_system : g_expect_fallback;
#elif BUILDFLAG(IS_APPLE)
  const WebFontTypefaceFactory::FontInstantiator& expectation =
      g_expect_fallback;
#else
  const WebFontTypefaceFactory::FontInstantiator& expectation = g_expect_system;
#endif
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check, expectation);
}

TEST(WebFontTypefaceFactoryTest, FontationsSelectedVariableSystem) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      true);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);

  sk_sp<SkTypeface> out_typeface;
#if BUILDFLAG(IS_WIN)
  const WebFontTypefaceFactory::FontInstantiator& expectation =
      DWriteVersionSupportsVariations() ? g_expect_system : g_expect_fallback;
#else
  const WebFontTypefaceFactory::FontInstantiator& expectation = g_expect_system;
#endif
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check, expectation);
}

TEST(WebFontTypefaceFactoryTest, FontationsSelectedStaticSystem) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      true);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);

  sk_sp<SkTypeface> out_typeface;
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
                                         g_expect_system);
}

TEST(WebFontTypefaceFactoryTest, FontationsSelectedVariableColrV0) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      true);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsColrCpalColorFontV0())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_font_format_check, IsVariableFont())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;

#if BUILDFLAG(IS_WIN)
  const WebFontTypefaceFactory::FontInstantiator& expectation =
      DWriteVersionSupportsVariations() ? g_expect_system : g_expect_fontations;
#else
  const WebFontTypefaceFactory::FontInstantiator& expectation =
      g_expect_fontations;
#endif
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check, expectation);
}

#if BUILDFLAG(IS_IOS)
// TODO(crbug.com/1499557): Currently fails on the platform.
#define MAYBE_SbixFallbackWindows DISABLED_SbixFallbackWindows
#else
#define MAYBE_SbixFallbackWindows SbixFallbackWindows
#endif
TEST(WebFontTypefaceFactoryTest, MAYBE_SbixFallbackWindows) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      false);
  ScopedFontationsFontBackendForTest scoped_fontations(false);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsSbixColorFont())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
#if BUILDFLAG(IS_WIN)
                                         g_expect_fallback
#else
                                         g_expect_system
#endif
  );
}

TEST(WebFontTypefaceFactoryTest, FontationsSelectedSbixNonApple) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      true);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsSbixColorFont())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;

#if BUILDFLAG(IS_APPLE)
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
                                         g_expect_system);
#else
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check,
                                         g_expect_fontations);
#endif
}

#if BUILDFLAG(IS_IOS)
// TODO(crbug.com/1499557): Currently fails on the platform.
#define MAYBE_VariationsWinFallbackIfNeeded \
  DISABLED_VariationsWinFallbackIfNeeded
#else
#define MAYBE_VariationsWinFallbackIfNeeded VariationsWinFallbackIfNeeded
#endif
TEST(WebFontTypefaceFactoryTest, MAYBE_VariationsWinFallbackIfNeeded) {
  ScopedFontationsForSelectedFormatsForTest scoped_fontations_selected_formats(
      false);
  sk_sp<SkData> data = SkData::MakeEmpty();
  MockFontFormatCheck mock_font_format_check(data);
  EXPECT_CALL(mock_font_format_check, IsVariableFont())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  sk_sp<SkTypeface> out_typeface;

#if BUILDFLAG(IS_WIN)
  const WebFontTypefaceFactory::FontInstantiator& expectation =
      DWriteVersionSupportsVariations() ? g_expect_system : g_expect_fallback;
#else
  const WebFontTypefaceFactory::FontInstantiator& expectation = g_expect_system;
#endif
  WebFontTypefaceFactory::CreateTypeface(SkData::MakeEmpty(), out_typeface,
                                         mock_font_format_check, expectation);
}

}  // namespace blink
```