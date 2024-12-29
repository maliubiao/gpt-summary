Response:
The user wants to understand the functionality of the `font_face_cache_test.cc` file in the Chromium Blink rendering engine. I need to analyze the code and explain:

1. **Functionality:** What does this test file do? What aspects of the font loading and matching process does it verify?
2. **Relationship to web technologies (JavaScript, HTML, CSS):** How does the code relate to the functionalities exposed through web standards?
3. **Logic and Input/Output:** Identify the test scenarios and the expected outcomes.
4. **Common Usage Errors:** Pinpoint potential mistakes developers might make when working with fonts that this test aims to prevent or highlight.
5. **Debugging Context:** How can this test be a starting point for debugging font-related issues in a browser?

**Plan:**

1. Read through the code to understand the test setup (`FontFaceCacheTest` class), helper functions, and individual test cases (`TEST_F`).
2. Identify the core functionality being tested, which appears to be the `FontFaceCache` and its ability to match font requests to available font faces based on CSS properties like `font-stretch`, `font-style`, and `font-weight`.
3. Connect the tested CSS properties to their usage in web development.
4. Analyze the logic of specific tests, focusing on the input (defined font faces and font requests) and the expected output (the matched font face).
5. Infer potential user/developer errors based on the tested scenarios. For example, incorrect CSS syntax for defining font faces or expecting a font to be available when it doesn't match the requested properties.
6. Describe how a developer might reach this code during debugging, potentially by tracing the font loading process or investigating why a specific font isn't being applied as expected.
好的，让我们来分析一下 `blink/renderer/core/css/font_face_cache_test.cc` 这个文件。

**功能：**

这个文件是 Chromium Blink 引擎中的一个 C++ 单元测试文件，专门用于测试 `FontFaceCache` 类的功能。`FontFaceCache` 的主要职责是缓存和管理已加载的字体面（font-face）。其核心功能在于：

1. **存储字体面信息:**  它维护着一个已加载的 `FontFace` 对象的集合，这些对象包含了字体族的名称、`src` 来源以及各种描述符（descriptors），如 `font-stretch`、`font-style`、`font-weight` 等。
2. **根据请求查找匹配的字体面:** 当渲染引擎需要使用特定字体的特定变体（例如，粗体斜体）时，`FontFaceCache` 能够根据给定的 `FontDescription`（包含所需的字体属性）查找最匹配的已加载 `FontFace`。
3. **管理 `CSSSegmentedFontFace`:**  为了更高效地处理具有多个不同属性（如不同的 `font-weight` 范围）的字体面，`FontFaceCache` 使用 `CSSSegmentedFontFace` 来组织和管理这些字体面的片段。

**与 JavaScript, HTML, CSS 的关系：**

这个文件直接关系到 CSS 的 `@font-face` 规则，这是在 CSS 中定义自定义字体的机制。

* **CSS `@font-face` 规则:**  在 CSS 中，开发者可以使用 `@font-face` 规则来声明要使用的字体资源，并指定其各种属性。例如：

```css
@font-face {
  font-family: 'MyCustomFont';
  src: url('my-custom-font.woff2') format('woff2');
  font-weight: 400;
  font-style: normal;
}

@font-face {
  font-family: 'MyCustomFont';
  src: url('my-custom-font-bold.woff2') format('woff2');
  font-weight: 700;
  font-style: normal;
}

body {
  font-family: 'MyCustomFont', sans-serif;
  font-weight: bold; /* 相当于 700 */
}
```

* **HTML:** HTML 结构中通过 CSS 来应用字体样式。例如，上面的 CSS 规则会影响到 `<body>` 元素及其子元素的字体。
* **JavaScript:** 虽然 JavaScript 不直接操作 `FontFaceCache`，但 JavaScript 可以动态修改元素的样式，从而触发字体查找过程。例如，通过 JavaScript 改变元素的 `font-weight` 属性，会间接地与 `FontFaceCache` 交互。

**举例说明：**

假设在 CSS 中定义了两个 `MyCustomFont` 的 `@font-face` 规则，一个 `font-weight: 400` (normal)，另一个 `font-weight: 700` (bold)。

1. **用户操作/HTML/CSS:** 网页的 HTML 中有文本元素，其 CSS 样式指定了 `font-family: 'MyCustomFont'` 和 `font-weight: bold;`。
2. **Blink 渲染引擎:** 当 Blink 渲染这个元素时，会构建一个 `FontDescription` 对象，其中包含 `font-family: 'MyCustomFont'` 和 `font-weight: 700`。
3. **`FontFaceCache` 查询:** 渲染引擎会使用这个 `FontDescription` 去查询 `FontFaceCache`。
4. **匹配:** `FontFaceCache` 会遍历其缓存的 `FontFace` 对象，找到 `font-family` 为 'MyCustomFont' 并且 `font-weight` 最匹配 700 的那个 `FontFace` 对象（在本例中是 `font-weight: 700` 的那个）。
5. **返回结果:** `FontFaceCache` 返回匹配的 `FontFace` 对象，渲染引擎就可以使用这个字体资源来渲染文本。

**逻辑推理与假设输入/输出：**

测试文件中的 `TEST_F` 函数展示了 `FontFaceCache` 的匹配逻辑。例如，`SimpleWidthMatch` 测试用例：

* **假设输入:**
    * 两个已加载的字体面，字体族名称都为 "Arial"，但 `font-stretch` 分别为 `ultra-expanded` 和 `condensed`。
    * 一个字体请求，要求字体族为 "Arial"，`font-stretch` 为 `condensed`。
* **逻辑推理:** `FontFaceCache` 应该找到 `font-stretch` 为 `condensed` 的那个字体面，因为它与请求的 `font-stretch` 值完全匹配。
* **预期输出:** `cache_->Get(description_condensed, kFontNameForTesting)` 应该返回一个 `CSSSegmentedFontFace` 对象，其 `FontSelectionCapabilities` 中的 `width` 属性应该为 `FontSelectionRange({kCondensedWidthValue, kCondensedWidthValue})`。

`MatchCombinations` 测试用例更复杂，它测试了在多种 `font-stretch`、`font-style` 和 `font-weight` 组合下的匹配情况。

**用户或编程常见的使用错误：**

1. **`@font-face` 规则定义不完整或错误:**  如果 `@font-face` 规则中缺少必要的属性（如 `src` 或 `font-family`），或者属性值错误（如 `src` 指向不存在的文件），`FontFaceCache` 就无法正确加载和使用这些字体。
    * **例子:**  用户在 CSS 中写了 `@font-face { font-family: 'MyFont'; }`，缺少 `src` 属性，会导致字体加载失败。
2. **请求的字体属性与已加载的字体不匹配:** 如果 HTML/CSS 中请求的字体属性（如 `font-weight: bold`）与任何已加载的字体面的属性都不匹配，浏览器可能无法找到合适的字体，最终使用默认字体或进行字体合成。
    * **例子:**  用户定义了一个 `font-weight: 400` 的字体，但在 CSS 中使用了 `font-weight: 600`，而没有定义 `600` 的字体，浏览器可能无法精确匹配。
3. **缓存问题:** 虽然 `FontFaceCache` 旨在提高性能，但在某些情况下，缓存可能导致问题。例如，在开发过程中修改了字体文件但浏览器使用了旧的缓存版本。清理浏览器缓存可以解决这类问题。

**用户操作如何一步步到达这里（作为调试线索）：**

当开发者在调试网页字体相关问题时，可能会需要查看 `FontFaceCache` 的状态和行为：

1. **页面加载和渲染:** 用户打开一个包含自定义字体的网页。
2. **字体加载失败或显示异常:**  用户发现页面上的字体没有按预期显示，例如字体样式错误、字体文件加载失败等。
3. **开发者工具检查:** 开发者打开浏览器的开发者工具（通常是 F12 键）。
4. **"Network" 面板:** 检查字体文件是否成功加载（HTTP 状态码 200）。如果加载失败，可能是 `src` 路径错误。
5. **"Elements" 或 "Styles" 面板:**  查看元素的 computed style，确认字体样式是否正确应用。检查 `@font-face` 规则是否生效。
6. **Blink 内部调试（高级）:** 如果上述步骤无法定位问题，开发者可能需要深入到 Blink 引擎内部进行调试：
    * **设置断点:** 在 `blink/renderer/core/css/font_face_cache.cc` 相关的代码中设置断点，例如 `FontFaceCache::Get` 方法，来观察字体匹配的过程。
    * **查看日志:** Blink 引擎可能会有相关的日志输出，记录字体加载和匹配的信息。
    * **分析 `FontDescription`:** 检查渲染引擎构建的 `FontDescription` 对象，确认其是否包含了预期的字体属性。
    * **分析 `FontFaceCache` 的状态:** 查看 `FontFaceCache` 中已加载的 `FontFace` 对象及其属性，确认是否包含了所需的字体变体。

通过以上步骤，开发者可以逐步排查字体加载和匹配过程中的问题，`font_face_cache_test.cc` 这个文件本身就提供了很多关于 `FontFaceCache` 如何工作的用例，可以帮助开发者理解其内部逻辑。

Prompt: 
```
这是目录为blink/renderer/core/css/font_face_cache_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/font_face_cache.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_font_face_src_value.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_font_style_range_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_segmented_font_face.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/font_face.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

class FontFaceCacheTest : public PageTestBase {
  USING_FAST_MALLOC(FontFaceCacheTest);

 protected:
  FontFaceCacheTest() = default;
  ~FontFaceCacheTest() override = default;

  void SetUp() override;

  void ClearCache();
  void AppendTestFaceForCapabilities(const CSSValue& stretch,
                                     const CSSValue& style,
                                     const CSSValue& weight);
  void AppendTestFaceForCapabilities(const CSSValue& stretch,
                                     const CSSValue& style,
                                     const CSSPrimitiveValue& start_weight,
                                     const CSSPrimitiveValue& end_weight);
  FontDescription FontDescriptionForRequest(FontSelectionValue stretch,
                                            FontSelectionValue style,
                                            FontSelectionValue weight);

  Persistent<FontFaceCache> cache_;

 protected:
  const AtomicString kFontNameForTesting{"Arial"};
};

void FontFaceCacheTest::SetUp() {
  PageTestBase::SetUp();
  cache_ = MakeGarbageCollected<FontFaceCache>();
  ClearCache();
}

void FontFaceCacheTest::ClearCache() {
  cache_->ClearAll();
}

void FontFaceCacheTest::AppendTestFaceForCapabilities(const CSSValue& stretch,
                                                      const CSSValue& style,
                                                      const CSSValue& weight) {
  CSSFontFamilyValue* family_name =
      CSSFontFamilyValue::Create(kFontNameForTesting);
  auto* src = CSSFontFaceSrcValue::CreateLocal(kFontNameForTesting);
  CSSValueList* src_value_list = CSSValueList::CreateCommaSeparated();
  src_value_list->Append(*src);
  CSSPropertyValue properties[] = {
      CSSPropertyValue(CSSPropertyName(CSSPropertyID::kFontFamily),
                       *family_name),
      CSSPropertyValue(CSSPropertyName(CSSPropertyID::kSrc), *src_value_list)};
  auto* font_face_descriptor =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(properties);

  font_face_descriptor->SetProperty(CSSPropertyID::kFontStretch, stretch);
  font_face_descriptor->SetProperty(CSSPropertyID::kFontStyle, style);
  font_face_descriptor->SetProperty(CSSPropertyID::kFontWeight, weight);

  auto* style_rule_font_face =
      MakeGarbageCollected<StyleRuleFontFace>(font_face_descriptor);
  FontFace* font_face = FontFace::Create(&GetDocument(), style_rule_font_face,
                                         false /* is_user_style */);
  CHECK(font_face);
  cache_->Add(style_rule_font_face, font_face);
}

void FontFaceCacheTest::AppendTestFaceForCapabilities(
    const CSSValue& stretch,
    const CSSValue& style,
    const CSSPrimitiveValue& start_weight,
    const CSSPrimitiveValue& end_weight) {
  CSSValueList* weight_list = CSSValueList::CreateSpaceSeparated();
  weight_list->Append(start_weight);
  weight_list->Append(end_weight);
  AppendTestFaceForCapabilities(stretch, style, *weight_list);
}

FontDescription FontFaceCacheTest::FontDescriptionForRequest(
    FontSelectionValue stretch,
    FontSelectionValue style,
    FontSelectionValue weight) {
  FontDescription description;
  description.SetFamily(FontFamily(
      kFontNameForTesting, FontFamily::InferredTypeFor(kFontNameForTesting)));
  description.SetStretch(stretch);
  description.SetStyle(style);
  description.SetWeight(weight);
  return description;
}

TEST_F(FontFaceCacheTest, Instantiate) {
  CSSIdentifierValue* stretch_value_expanded =
      CSSIdentifierValue::Create(CSSValueID::kUltraExpanded);
  CSSIdentifierValue* stretch_value_condensed =
      CSSIdentifierValue::Create(CSSValueID::kCondensed);
  CSSPrimitiveValue* weight_value = CSSNumericLiteralValue::Create(
      kBoldWeightValue, CSSPrimitiveValue::UnitType::kNumber);
  CSSIdentifierValue* style_value =
      CSSIdentifierValue::Create(CSSValueID::kItalic);

  AppendTestFaceForCapabilities(*stretch_value_expanded, *style_value,
                                *weight_value);
  AppendTestFaceForCapabilities(*stretch_value_condensed, *style_value,
                                *weight_value);
  ASSERT_EQ(cache_->GetNumSegmentedFacesForTesting(), 2ul);
}

TEST_F(FontFaceCacheTest, SimpleWidthMatch) {
  CSSIdentifierValue* stretch_value_expanded =
      CSSIdentifierValue::Create(CSSValueID::kUltraExpanded);
  CSSIdentifierValue* stretch_value_condensed =
      CSSIdentifierValue::Create(CSSValueID::kCondensed);
  CSSPrimitiveValue* weight_value = CSSNumericLiteralValue::Create(
      kNormalWeightValue, CSSPrimitiveValue::UnitType::kNumber);
  CSSIdentifierValue* style_value =
      CSSIdentifierValue::Create(CSSValueID::kNormal);
  AppendTestFaceForCapabilities(*stretch_value_expanded, *style_value,
                                *weight_value);
  AppendTestFaceForCapabilities(*stretch_value_condensed, *style_value,
                                *weight_value);
  ASSERT_EQ(cache_->GetNumSegmentedFacesForTesting(), 2ul);

  const FontDescription& description_condensed = FontDescriptionForRequest(
      kCondensedWidthValue, kNormalSlopeValue, kNormalWeightValue);
  CSSSegmentedFontFace* result =
      cache_->Get(description_condensed, kFontNameForTesting);
  ASSERT_TRUE(result);

  FontSelectionCapabilities result_capabilities =
      result->GetFontSelectionCapabilities();
  ASSERT_EQ(result_capabilities.width,
            FontSelectionRange({kCondensedWidthValue, kCondensedWidthValue}));
  ASSERT_EQ(result_capabilities.weight,
            FontSelectionRange({kNormalWeightValue, kNormalWeightValue}));
  ASSERT_EQ(result_capabilities.slope,
            FontSelectionRange({kNormalSlopeValue, kNormalSlopeValue}));
}

TEST_F(FontFaceCacheTest, SimpleWeightMatch) {
  CSSIdentifierValue* stretch_value =
      CSSIdentifierValue::Create(CSSValueID::kNormal);
  CSSIdentifierValue* style_value =
      CSSIdentifierValue::Create(CSSValueID::kNormal);
  CSSPrimitiveValue* weight_value_black =
      CSSNumericLiteralValue::Create(900, CSSPrimitiveValue::UnitType::kNumber);
  AppendTestFaceForCapabilities(*stretch_value, *style_value,
                                *weight_value_black);
  CSSPrimitiveValue* weight_value_thin =
      CSSNumericLiteralValue::Create(100, CSSPrimitiveValue::UnitType::kNumber);
  AppendTestFaceForCapabilities(*stretch_value, *style_value,
                                *weight_value_thin);
  ASSERT_EQ(cache_->GetNumSegmentedFacesForTesting(), 2ul);

  const FontDescription& description_bold = FontDescriptionForRequest(
      kNormalWidthValue, kNormalSlopeValue, kBoldWeightValue);
  CSSSegmentedFontFace* result =
      cache_->Get(description_bold, kFontNameForTesting);
  ASSERT_TRUE(result);
  FontSelectionCapabilities result_capabilities =
      result->GetFontSelectionCapabilities();
  ASSERT_EQ(result_capabilities.width,
            FontSelectionRange({kNormalWidthValue, kNormalWidthValue}));
  ASSERT_EQ(
      result_capabilities.weight,
      FontSelectionRange({FontSelectionValue(900), FontSelectionValue(900)}));
  ASSERT_EQ(result_capabilities.slope,
            FontSelectionRange({kNormalSlopeValue, kNormalSlopeValue}));
}

// For each capability, we can either not have it at all, have two of them, or
// have only one of them.
static HeapVector<Member<CSSValue>> AvailableCapabilitiesChoices(
    size_t choice,
    base::span<CSSValue*> available_values) {
  HeapVector<Member<CSSValue>> available_ones;
  switch (choice) {
    case 0:
      available_ones.push_back(available_values[0]);
      available_ones.push_back(available_values[1]);
      break;
    case 1:
      available_ones.push_back(available_values[0]);
      break;
    case 2:
      available_ones.push_back(available_values[1]);
      break;
  }
  return available_ones;
}

FontSelectionRange ExpectedRangeForChoice(
    FontSelectionValue request,
    size_t choice,
    const Vector<FontSelectionValue>& choices) {
  switch (choice) {
    case 0:
      // Both are available, the request can be matched.
      return FontSelectionRange(request, request);
    case 1:
      return FontSelectionRange(choices[0], choices[0]);
    case 2:
      return FontSelectionRange(choices[1], choices[1]);
    default:
      return FontSelectionRange(FontSelectionValue(0), FontSelectionValue(0));
  }
}

// Flaky; https://crbug.com/871812
TEST_F(FontFaceCacheTest, DISABLED_MatchCombinations) {
  CSSValue* widths[] = {CSSIdentifierValue::Create(CSSValueID::kCondensed),
                        CSSIdentifierValue::Create(CSSValueID::kExpanded)};
  CSSValue* slopes[] = {CSSIdentifierValue::Create(CSSValueID::kNormal),
                        CSSIdentifierValue::Create(CSSValueID::kItalic)};
  CSSValue* weights[] = {
      CSSNumericLiteralValue::Create(100, CSSPrimitiveValue::UnitType::kNumber),
      CSSNumericLiteralValue::Create(900,
                                     CSSPrimitiveValue::UnitType::kNumber)};

  Vector<FontSelectionValue> width_choices = {kCondensedWidthValue,
                                              kExpandedWidthValue};
  Vector<FontSelectionValue> slope_choices = {kNormalSlopeValue,
                                              kItalicSlopeValue};
  Vector<FontSelectionValue> weight_choices = {FontSelectionValue(100),
                                               FontSelectionValue(900)};

  Vector<FontDescription> test_descriptions;
  for (FontSelectionValue width_choice : width_choices) {
    for (FontSelectionValue slope_choice : slope_choices) {
      for (FontSelectionValue weight_choice : weight_choices) {
        test_descriptions.push_back(FontDescriptionForRequest(
            width_choice, slope_choice, weight_choice));
      }
    }
  }

  for (size_t width_choice : {0, 1, 2}) {
    for (size_t slope_choice : {0, 1, 2}) {
      for (size_t weight_choice : {0, 1, 2}) {
        ClearCache();
        for (CSSValue* width :
             AvailableCapabilitiesChoices(width_choice, widths)) {
          for (CSSValue* slope :
               AvailableCapabilitiesChoices(slope_choice, slopes)) {
            for (CSSValue* weight :
                 AvailableCapabilitiesChoices(weight_choice, weights)) {
              AppendTestFaceForCapabilities(*width, *slope, *weight);
            }
          }
        }
        for (FontDescription& test_description : test_descriptions) {
          CSSSegmentedFontFace* result =
              cache_->Get(test_description, kFontNameForTesting);
          ASSERT_TRUE(result);
          FontSelectionCapabilities result_capabilities =
              result->GetFontSelectionCapabilities();
          ASSERT_EQ(result_capabilities.width,
                    ExpectedRangeForChoice(test_description.Stretch(),
                                           width_choice, width_choices));
          ASSERT_EQ(result_capabilities.slope,
                    ExpectedRangeForChoice(test_description.Style(),
                                           slope_choice, slope_choices));
          ASSERT_EQ(result_capabilities.weight,
                    ExpectedRangeForChoice(test_description.Weight(),
                                           weight_choice, weight_choices));
        }
      }
    }
  }
}

TEST_F(FontFaceCacheTest, WidthRangeMatching) {
  CSSIdentifierValue* stretch_value =
      CSSIdentifierValue::Create(CSSValueID::kNormal);
  CSSIdentifierValue* style_value =
      CSSIdentifierValue::Create(CSSValueID::kNormal);
  CSSPrimitiveValue* weight_value_from =
      CSSNumericLiteralValue::Create(700, CSSPrimitiveValue::UnitType::kNumber);
  CSSPrimitiveValue* weight_value_to =
      CSSNumericLiteralValue::Create(800, CSSPrimitiveValue::UnitType::kNumber);
  CSSValueList* weight_list = CSSValueList::CreateSpaceSeparated();
  weight_list->Append(*weight_value_from);
  weight_list->Append(*weight_value_to);
  AppendTestFaceForCapabilities(*stretch_value, *style_value, *weight_list);

  CSSPrimitiveValue* second_weight_value_from =
      CSSNumericLiteralValue::Create(100, CSSPrimitiveValue::UnitType::kNumber);
  CSSPrimitiveValue* second_weight_value_to =
      CSSNumericLiteralValue::Create(200, CSSPrimitiveValue::UnitType::kNumber);
  CSSValueList* second_weight_list = CSSValueList::CreateSpaceSeparated();
  second_weight_list->Append(*second_weight_value_from);
  second_weight_list->Append(*second_weight_value_to);
  AppendTestFaceForCapabilities(*stretch_value, *style_value,
                                *second_weight_list);

  ASSERT_EQ(cache_->GetNumSegmentedFacesForTesting(), 2ul);

  const FontDescription& description_bold = FontDescriptionForRequest(
      kNormalWidthValue, kNormalSlopeValue, kBoldWeightValue);
  CSSSegmentedFontFace* result =
      cache_->Get(description_bold, kFontNameForTesting);
  ASSERT_TRUE(result);
  FontSelectionCapabilities result_capabilities =
      result->GetFontSelectionCapabilities();
  ASSERT_EQ(result_capabilities.width,
            FontSelectionRange({kNormalWidthValue, kNormalWidthValue}));
  ASSERT_EQ(
      result_capabilities.weight,
      FontSelectionRange({FontSelectionValue(700), FontSelectionValue(800)}));
  ASSERT_EQ(result_capabilities.slope,
            FontSelectionRange({kNormalSlopeValue, kNormalSlopeValue}));
}

TEST_F(FontFaceCacheTest, WidthRangeMatchingBetween400500) {
  // Two font faces equally far away from a requested font weight of 450.

  CSSIdentifierValue* stretch_value =
      CSSIdentifierValue::Create(CSSValueID::kNormal);
  CSSIdentifierValue* style_value =
      CSSIdentifierValue::Create(CSSValueID::kNormal);

  CSSPrimitiveValue* weight_values_lower[] = {
      CSSNumericLiteralValue::Create(600, CSSPrimitiveValue::UnitType::kNumber),
      CSSNumericLiteralValue::Create(415, CSSPrimitiveValue::UnitType::kNumber),
      CSSNumericLiteralValue::Create(475, CSSPrimitiveValue::UnitType::kNumber),
  };

  CSSPrimitiveValue* weight_values_upper[] = {
      CSSNumericLiteralValue::Create(610, CSSPrimitiveValue::UnitType::kNumber),
      CSSNumericLiteralValue::Create(425, CSSPrimitiveValue::UnitType::kNumber),
      CSSNumericLiteralValue::Create(485, CSSPrimitiveValue::UnitType::kNumber),
  };

  // From https://drafts.csswg.org/css-fonts-4/#font-style-matching: "If the
  // desired weight is inclusively between 400 and 500, weights greater than or
  // equal to the target weight are checked in ascending order until 500 is hit
  // and checked, followed by weights less than the target weight in descending
  // order, followed by weights greater than 500, until a match is found."

  // So, the heavy font should be matched last, after the thin font, and after
  // the font that is slightly bolder than 450.
  AppendTestFaceForCapabilities(*stretch_value, *style_value,
                                *(weight_values_lower[0]),
                                *(weight_values_upper[0]));

  ASSERT_EQ(cache_->GetNumSegmentedFacesForTesting(), 1ul);

  FontSelectionValue test_weight(450);

  const FontDescription& description_expanded = FontDescriptionForRequest(
      kNormalWidthValue, kNormalSlopeValue, test_weight);
  CSSSegmentedFontFace* result =
      cache_->Get(description_expanded, kFontNameForTesting);
  ASSERT_TRUE(result);
  ASSERT_EQ(result->GetFontSelectionCapabilities().weight.minimum,
            FontSelectionValue(600));

  AppendTestFaceForCapabilities(*stretch_value, *style_value,
                                *(weight_values_lower[1]),
                                *(weight_values_upper[1]));
  ASSERT_EQ(cache_->GetNumSegmentedFacesForTesting(), 2ul);

  result = cache_->Get(description_expanded, kFontNameForTesting);
  ASSERT_TRUE(result);
  ASSERT_EQ(result->GetFontSelectionCapabilities().weight.minimum,
            FontSelectionValue(415));

  AppendTestFaceForCapabilities(*stretch_value, *style_value,
                                *(weight_values_lower[2]),
                                *(weight_values_upper[2]));
  ASSERT_EQ(cache_->GetNumSegmentedFacesForTesting(), 3ul);

  result = cache_->Get(description_expanded, kFontNameForTesting);
  ASSERT_TRUE(result);
  ASSERT_EQ(result->GetFontSelectionCapabilities().weight.minimum,
            FontSelectionValue(475));
}

TEST_F(FontFaceCacheTest, StretchRangeMatching) {
  CSSPrimitiveValue* stretch_value_from = CSSNumericLiteralValue::Create(
      65, CSSPrimitiveValue::UnitType::kPercentage);
  CSSPrimitiveValue* stretch_value_to = CSSNumericLiteralValue::Create(
      70, CSSPrimitiveValue::UnitType::kPercentage);
  CSSIdentifierValue* style_value =
      CSSIdentifierValue::Create(CSSValueID::kNormal);
  CSSPrimitiveValue* weight_value =
      CSSNumericLiteralValue::Create(400, CSSPrimitiveValue::UnitType::kNumber);
  CSSValueList* stretch_list = CSSValueList::CreateSpaceSeparated();
  stretch_list->Append(*stretch_value_from);
  stretch_list->Append(*stretch_value_to);
  AppendTestFaceForCapabilities(*stretch_list, *style_value, *weight_value);

  const float kStretchFrom = 110;
  const float kStretchTo = 120;
  CSSPrimitiveValue* second_stretch_value_from = CSSNumericLiteralValue::Create(
      kStretchFrom, CSSPrimitiveValue::UnitType::kPercentage);
  CSSPrimitiveValue* second_stretch_value_to = CSSNumericLiteralValue::Create(
      kStretchTo, CSSPrimitiveValue::UnitType::kPercentage);
  CSSValueList* second_stretch_list = CSSValueList::CreateSpaceSeparated();
  second_stretch_list->Append(*second_stretch_value_from);
  second_stretch_list->Append(*second_stretch_value_to);
  AppendTestFaceForCapabilities(*second_stretch_list, *style_value,
                                *weight_value);

  ASSERT_EQ(cache_->GetNumSegmentedFacesForTesting(), 2ul);

  const FontDescription& description_expanded = FontDescriptionForRequest(
      FontSelectionValue(105), kNormalSlopeValue, kNormalWeightValue);
  CSSSegmentedFontFace* result =
      cache_->Get(description_expanded, kFontNameForTesting);
  ASSERT_TRUE(result);
  FontSelectionCapabilities result_capabilities =
      result->GetFontSelectionCapabilities();
  ASSERT_EQ(result_capabilities.width,
            FontSelectionRange({FontSelectionValue(kStretchFrom),
                                FontSelectionValue(kStretchTo)}));
  ASSERT_EQ(result_capabilities.weight,
            FontSelectionRange({kNormalWeightValue, kNormalWeightValue}));
  ASSERT_EQ(result_capabilities.slope,
            FontSelectionRange({kNormalSlopeValue, kNormalSlopeValue}));
}

TEST_F(FontFaceCacheTest, ObliqueRangeMatching) {
  CSSIdentifierValue* stretch_value =
      CSSIdentifierValue::Create(CSSValueID::kNormal);
  CSSPrimitiveValue* weight_value =
      CSSNumericLiteralValue::Create(400, CSSPrimitiveValue::UnitType::kNumber);

  CSSIdentifierValue* oblique_keyword_value =
      CSSIdentifierValue::Create(CSSValueID::kOblique);

  CSSValueList* oblique_range = CSSValueList::CreateCommaSeparated();
  CSSPrimitiveValue* oblique_from =
      CSSNumericLiteralValue::Create(30, CSSPrimitiveValue::UnitType::kNumber);
  CSSPrimitiveValue* oblique_to =
      CSSNumericLiteralValue::Create(35, CSSPrimitiveValue::UnitType::kNumber);
  oblique_range->Append(*oblique_from);
  oblique_range->Append(*oblique_to);
  auto* oblique_value = MakeGarbageCollected<cssvalue::CSSFontStyleRangeValue>(
      *oblique_keyword_value, *oblique_range);

  AppendTestFaceForCapabilities(*stretch_value, *oblique_value, *weight_value);

  CSSValueList* oblique_range_second = CSSValueList::CreateCommaSeparated();
  CSSPrimitiveValue* oblique_from_second =
      CSSNumericLiteralValue::Create(5, CSSPrimitiveValue::UnitType::kNumber);
  CSSPrimitiveValue* oblique_to_second =
      CSSNumericLiteralValue::Create(10, CSSPrimitiveValue::UnitType::kNumber);
  oblique_range_second->Append(*oblique_from_second);
  oblique_range_second->Append(*oblique_to_second);
  auto* oblique_value_second =
      MakeGarbageCollected<cssvalue::CSSFontStyleRangeValue>(
          *oblique_keyword_value, *oblique_range_second);

  AppendTestFaceForCapabilities(*stretch_value, *oblique_value_second,
                                *weight_value);

  ASSERT_EQ(cache_->GetNumSegmentedFacesForTesting(), 2ul);

  const FontDescription& description_italic = FontDescriptionForRequest(
      kNormalWidthValue, kItalicSlopeValue, kNormalWeightValue);
  CSSSegmentedFontFace* result =
      cache_->Get(description_italic, kFontNameForTesting);
  ASSERT_TRUE(result);
  FontSelectionCapabilities result_capabilities =
      result->GetFontSelectionCapabilities();
  ASSERT_EQ(result_capabilities.width,
            FontSelectionRange({kNormalWidthValue, kNormalWidthValue}));
  ASSERT_EQ(result_capabilities.weight,
            FontSelectionRange({kNormalWeightValue, kNormalWeightValue}));
  ASSERT_EQ(
      result_capabilities.slope,
      FontSelectionRange({FontSelectionValue(30), FontSelectionValue(35)}));
}

}  // namespace blink

"""

```