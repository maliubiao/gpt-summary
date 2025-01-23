Response:
The user wants to understand the functionality of the `shape_result_bloberizer_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose. The file name suggests it's a test file for a component responsible for "bloberizing" shape results. This likely involves converting the output of text shaping (glyphs, positions, etc.) into Skia `SkTextBlob` objects, which are efficient ways to represent rendered text.

Here's a breakdown of the thought process:

1. **Identify the core class under test:** The file name and the `#include` statement `shape_result_bloberizer.h` clearly indicate that the primary class being tested is `ShapeResultBloberizer`.

2. **Understand the purpose of `ShapeResultBloberizer`:**  Based on the name, it takes the result of text shaping (likely a `ShapeResult` object) and transforms it into a "blob". Skia's `SkTextBlob` comes to mind as the likely output format, and the code confirms this. `SkTextBlob` is used for efficient text rendering.

3. **Examine the tests:** The `TEST_F` macros define individual test cases. I need to analyze what each test is verifying about `ShapeResultBloberizer`.

    * `StartsEmpty`: Checks initial state, ensuring no pending data.
    * `StoresGlyphsOffsets`: Verifies that glyph IDs and their horizontal offsets are correctly stored before being flushed into a blob. It also checks behavior when the font changes.
    * `StoresGlyphsVerticalOffsets`: Similar to the previous test, but for vertical offsets (used in vertical text layout).
    * `MixedBlobRotation`: Tests how the bloberizer handles changes in text orientation (horizontal vs. vertical), ensuring that separate blobs are created for different orientations.
    * `CommonAccentLeftToRightFillGlyphBuffer` and `CommonAccentRightToLeftFillGlyphBuffer`: These tests compare the output of the bloberizer when shaping text word-by-word versus shaping the entire text at once. This is important for performance optimization.
    * `CommonAccentRightToLeftFillGlyphBufferNG`, `FourByteUtf8CodepointsNG`, `OffsetIntoTrailingSurrogateNG`, `LatinMultRunNG`, `SupplementaryMultiRunNG`: The "NG" suffix suggests these are tests for a "next-generation" or newer implementation of the bloberizer. These tests examine scenarios involving complex text, such as right-to-left text, multi-byte Unicode characters, and text with multiple shaping "runs" (where font or other properties change).
    * `SubRunWithZeroGlyphs`: Checks how the bloberizer handles situations where a shaping run results in zero glyphs (e.g., for a zero-width joiner).

4. **Relate to web technologies (JavaScript, HTML, CSS):**

    * **JavaScript:** JavaScript can manipulate the text content of web pages, which will eventually be shaped and potentially go through the `ShapeResultBloberizer`. Example: Changing the text of a `<div>` element.
    * **HTML:** The HTML structure defines the text content that needs to be rendered. The bloberizer processes this text. Example: A `<p>` tag containing text.
    * **CSS:** CSS styles determine the font, size, direction, and other properties of text. These properties directly influence the shaping process and thus the input to the bloberizer. Example: `font-family: Arial; direction: rtl;`.

5. **Identify logic and assumptions:** The tests often involve setting up input text, font properties, and expected outputs. I need to look for cases where the tests make assumptions about how the bloberizer should behave. For instance, the `CheckBlobBuffer` function makes assumptions about the structure of the `SkTextBlob` runs and the order of clusters in RTL text.

6. **Look for potential user errors:**  Consider how incorrect usage of web technologies could interact with the bloberizer. For example, using unsupported fonts or mixing left-to-right and right-to-left text without proper markup could lead to unexpected results.

7. **Structure the response:**  Organize the information into clear sections (functionality, relationship to web technologies, logic/assumptions, common errors) with illustrative examples. Use code snippets and explanations to make the information accessible.
这个文件 `blink/renderer/platform/fonts/shaping/shape_result_bloberizer_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `ShapeResultBloberizer` 类的功能**。`ShapeResultBloberizer` 的作用是将文本塑形（shaping）的结果转换成可以被 Skia 图形库高效渲染的 `SkTextBlob` 对象。

以下是该文件功能的详细解释：

**1. 测试 `ShapeResultBloberizer` 的基本功能:**

* **创建和管理 `SkTextBlob`:**  `ShapeResultBloberizer` 负责将一系列的字形（glyphs）及其位置信息、字体信息等组合成一个或多个 `SkTextBlob` 对象。`SkTextBlob` 是 Skia 中用于批量渲染文本的优化结构。
* **处理字体变化:** 测试用例会验证当遇到不同的字体时，`ShapeResultBloberizer` 是否会创建新的 `SkTextBlob`。
* **处理文本方向变化:** 测试用例验证了当文本方向（从左到右或从右到左）发生变化时，`ShapeResultBloberizer` 如何处理。
* **处理垂直排版:** 测试用例包含了对垂直排版的支持，验证了 `ShapeResultBloberizer` 能正确处理垂直排版的字形偏移。
* **处理不同旋转角度的文本:**  测试了在垂直排版中，不同字形的旋转角度如何被 `ShapeResultBloberizer` 处理。

**2. 测试 `ShapeResultBloberizer::FillGlyphs` 和 `ShapeResultBloberizer::FillGlyphsNG`:**

* **按需填充字形缓冲:** 这两个方法用于逐步将字形数据添加到 `ShapeResultBloberizer` 中。测试用例验证了在分段处理文本时，结果是否与一次性处理整个文本的结果一致。
* **处理复杂文本:**  测试用例涵盖了包含组合字符（如带重音的字符）、从右到左的文本、以及需要多个字节表示的 Unicode 字符（如补充字符）的情况。

**3. 模拟文本塑形过程:**

* **使用 `ShapeResultTestInfo`:**  测试用例使用了 `ShapeResultTestInfo` 辅助类来模拟文本塑形的结果，允许直接控制添加到 `ShapeResultBloberizer` 的字形、偏移等信息，而无需实际进行复杂的文本塑形。
* **对比分段塑形和整体塑形:**  部分测试用例对比了分段（例如按单词）进行文本塑形，然后用 `ShapeResultBloberizer` 处理，和一次性塑形整个文本的结果，确保两种方式的输出是一致的。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ShapeResultBloberizer` 位于渲染引擎的底层，直接参与文本的渲染过程。它与 JavaScript, HTML, CSS 的关系如下：

* **HTML:** HTML 定义了网页的结构和文本内容。浏览器解析 HTML 后，会将文本内容传递给渲染引擎进行处理。`ShapeResultBloberizer` 负责将这些文本渲染成可见的图形。
    * **举例:** 当 HTML 中包含 `<p>This is some text.</p>` 时，渲染引擎会获取 "This is some text." 这个字符串，对其进行塑形，然后使用 `ShapeResultBloberizer` 将塑形结果转换为 `SkTextBlob`，最终在屏幕上绘制出来。

* **CSS:** CSS 定义了文本的样式，包括字体、大小、颜色、行高、文本方向等。这些样式会影响文本塑形的结果，进而影响 `ShapeResultBloberizer` 的处理。
    * **举例:**
        * `font-family: Arial;`：CSS 指定了使用的字体，不同的字体可能产生不同的字形。
        * `direction: rtl;`：CSS 指定了文本方向为从右到左，`ShapeResultBloberizer` 需要正确处理这种方向的文本。
        * `font-size: 16px;`：CSS 指定了字体大小，影响字形的尺寸和偏移。

* **JavaScript:** JavaScript 可以动态修改网页的文本内容和样式。当 JavaScript 修改文本内容或影响文本样式的 CSS 属性时，渲染引擎会重新进行文本塑形，并可能再次使用 `ShapeResultBloberizer` 来更新渲染结果。
    * **举例:**
        ```javascript
        const element = document.getElementById('myText');
        element.textContent = 'New text content.';
        element.style.fontFamily = 'Verdana';
        ```
        当 JavaScript 执行这段代码时，`ShapeResultBloberizer` 可能会被用来渲染新的文本内容以及使用新的字体。

**逻辑推理的假设输入与输出:**

**假设输入 (以 `StoresGlyphsOffsets` 测试为例):**

1. **初始状态:** `ShapeResultBloberizer` 为空。
2. **添加字形 1:** 字形 ID = 42, 字体 = `font1`, 水平偏移 = 10, 集群索引 = 0。
3. **添加字形 2:** 字形 ID = 43, 字体 = `font1`, 水平偏移 = 15, 集群索引 = 1。
4. **添加字形 3:** 字形 ID = 44, 字体 = `font2`, 水平偏移 = 12, 集群索引 = 0。

**预期输出:**

1. 在添加字形 1 和 2 后，`ShapeResultBloberizer` 的 pending run 中会包含这两个字形及其偏移信息，并且 `PendingRunFontData` 指向 `font1`。
2. 当添加字形 3 时，由于字体与 pending run 的字体不同，之前的 pending run 会被提交到一个新的 `SkTextBlob` 中。
3. 此时，`ShapeResultBloberizer` 的 pending run 中会包含字形 3 及其偏移信息，并且 `PendingRunFontData` 指向 `font2`。
4. 调用 `bloberizer.Blobs()` 会返回一个包含一个 `SkTextBlob` 的容器，这个 `SkTextBlob` 包含了前两个字形的信息。

**涉及用户或者编程常见的使用错误:**

虽然 `ShapeResultBloberizer` 是引擎内部的组件，用户或开发者直接与之交互较少，但一些错误的使用方式可能会间接影响其工作：

1. **使用未安装或不可用的字体:** 如果 CSS 中指定了浏览器无法找到的字体，渲染引擎可能会使用后备字体进行渲染，这会导致 `ShapeResultBloberizer` 处理不同的字形数据，最终显示效果可能与预期不符。
    * **举例:**  CSS 中设置 `font-family: несуществующийШрифт;`，浏览器可能使用默认字体渲染。

2. **混合使用从左到右和从右到左的文本，但未正确标记:** 如果一段文本中混合了不同方向的文字，但没有使用 HTML 的 `dir` 属性或 Unicode 控制字符进行正确的标记，可能会导致文本显示顺序错乱，`ShapeResultBloberizer` 会按照错误的顺序生成 `SkTextBlob`。
    * **举例:**  HTML 中直接写 "English text 中文", 而没有使用 `<bdi>` 或 `&rlm;` 等标记来明确中文的方向。

3. **使用了非常规的 Unicode 字符或组合字符，但字体不支持:**  如果文本中包含了某些特殊的 Unicode 字符或组合方式，但所使用的字体没有相应的字形，可能导致这些字符无法正确显示，或者 `ShapeResultBloberizer` 在处理时遇到异常情况。
    * **举例:** 使用了罕见的表情符号，但系统字体不支持该表情符号。

4. **在垂直排版中对不支持垂直字形的字体使用旋转:**  如果强制对不支持垂直字形的字体进行旋转排版，可能会导致显示效果不佳，或者 `ShapeResultBloberizer` 生成的 `SkTextBlob` 不是最优的。

总而言之，`shape_result_bloberizer_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎能够正确高效地将文本塑形的结果转换为可渲染的图形数据，这对于网页的正常显示至关重要。

### 提示词
```
这是目录为blink/renderer/platform/fonts/shaping/shape_result_bloberizer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_bloberizer.h"

#include <memory>
#include <optional>

#include "skia/ext/font_utils.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/fonts/character_range.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/opentype/open_type_vertical_data.h"
#include "third_party/blink/renderer/platform/fonts/shaping/caching_word_shaper.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_test_info.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"
#include "third_party/blink/renderer/platform/fonts/text_fragment_paint_info.h"
#include "third_party/blink/renderer/platform/fonts/text_run_paint_info.h"
#include "third_party/blink/renderer/platform/testing/font_test_base.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

// Creating minimal test SimpleFontData objects,
// the font won't have any glyphs, but that's okay.
static SimpleFontData* CreateTestSimpleFontData(bool force_rotation = false) {
  return MakeGarbageCollected<SimpleFontData>(
      MakeGarbageCollected<FontPlatformData>(
          skia::DefaultTypeface(), std::string(), 10, false, false,
          TextRenderingMode::kAutoTextRendering, ResolvedFontFeatures{},
          force_rotation ? FontOrientation::kVerticalUpright
                         : FontOrientation::kHorizontal),
      nullptr);
}

class ShapeResultBloberizerTest : public FontTestBase {
 protected:
  void SetUp() override {
    font_description.SetComputedSize(12.0);
    font_description.SetLocale(LayoutLocale::Get(AtomicString("en")));
    ASSERT_EQ(USCRIPT_LATIN, font_description.GetScript());
    font_description.SetGenericFamily(FontDescription::kStandardFamily);

    cache = MakeGarbageCollected<ShapeCache>();
  }

  FontCachePurgePreventer font_cache_purge_preventer;
  FontDescription font_description;

  Persistent<ShapeCache> cache;
};

struct ExpectedRun {
  int glyph_count;
  std::string utf8;
  // Currently RTL is output in reverse of logical order, but this is not
  // a requirement. This really just expects montonicity.
  enum ClusterDirection { kAscending, kDescending } cluster_direction;
};
using ExpectedBlob = std::vector<ExpectedRun>;

struct ExpectedRange {
  unsigned from;
  unsigned to;
  unsigned length() { return to - from; }
};

void CheckBlobBuffer(const ShapeResultBloberizer::BlobBuffer& blob_buffer,
                     const std::vector<ExpectedBlob>& expected_blobs) {
  EXPECT_EQ(blob_buffer.size(), expected_blobs.size());
  auto blob_info_iter = blob_buffer.begin();
  auto&& expected_blob_iter = expected_blobs.begin();
  for (; blob_info_iter != blob_buffer.end() &&
         expected_blob_iter != expected_blobs.end();
       ++blob_info_iter, ++expected_blob_iter) {
    size_t blob_index = expected_blob_iter - expected_blobs.begin();
    const ExpectedBlob& expected_blob = *expected_blob_iter;
    SkTextBlob::Iter::Run run;
    size_t actual_run_count = 0;
    for (SkTextBlob::Iter it(*blob_info_iter->blob.get()); it.next(&run);) {
      ++actual_run_count;
    }
    EXPECT_EQ(actual_run_count, expected_blob.size()) << "Blob: " << blob_index;
    auto&& expected_run_iter = expected_blob.begin();
    SkTextBlob::Iter it(*blob_info_iter->blob.get());
    for (; it.next(&run) && expected_run_iter != expected_blob.end();
         ++expected_run_iter) {
      size_t run_index = expected_run_iter - expected_blob.begin();
      const ExpectedRun& expected_run = *expected_run_iter;
      EXPECT_EQ(expected_run.glyph_count, run.fGlyphCount)
          << "Blob: " << blob_index << " Run: " << run_index;

      int actual_size = run.fUtf8Size_forTest;
      int expected_size = expected_run.utf8.size();
      EXPECT_EQ(actual_size, expected_size)
          << "Blob: " << blob_index << " Run: " << run_index;
      for (int i = 0; i < actual_size && i < expected_size; ++i) {
        EXPECT_EQ(run.fUtf8_forTest[i], expected_run.utf8[i])
            << "Blob: " << blob_index << " Run: " << run_index << " i: " << i;
      }

      auto utf8_index_previous = run.fClusterIndex_forTest[0];
      for (int i = 0; i < run.fGlyphCount; ++i) {
        EXPECT_LE(0ul, run.fClusterIndex_forTest[i]);
        EXPECT_LT((int)run.fClusterIndex_forTest[i], run.fUtf8Size_forTest);
        auto expected_direction = expected_run.cluster_direction;
        if (expected_direction == ExpectedRun::ClusterDirection::kAscending) {
          EXPECT_LE(utf8_index_previous, run.fClusterIndex_forTest[i]);
        } else {
          EXPECT_GE(utf8_index_previous, run.fClusterIndex_forTest[i]);
        }
        utf8_index_previous = run.fClusterIndex_forTest[i];
      }
    }
  }
}

}  // anonymous namespace

TEST_F(ShapeResultBloberizerTest, StartsEmpty) {
  Font font;
  ShapeResultBloberizer bloberizer(font.GetFontDescription(),
                                   ShapeResultBloberizer::Type::kNormal);

  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingRunFontData(bloberizer),
            nullptr);
  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingRunGlyphs(bloberizer).size(),
            0ul);
  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingRunOffsets(bloberizer).size(),
            0ul);
  EXPECT_FALSE(
      ShapeResultBloberizerTestInfo::HasPendingRunVerticalOffsets(bloberizer));
  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingBlobRunCount(bloberizer),
            0ul);
  EXPECT_EQ(ShapeResultBloberizerTestInfo::CommittedBlobCount(bloberizer), 0ul);

  EXPECT_TRUE(bloberizer.Blobs().empty());
}

TEST_F(ShapeResultBloberizerTest, StoresGlyphsOffsets) {
  Font font;
  ShapeResultBloberizer bloberizer(font.GetFontDescription(),
                                   ShapeResultBloberizer::Type::kNormal);

  SimpleFontData* font1 = CreateTestSimpleFontData();
  SimpleFontData* font2 = CreateTestSimpleFontData();

  // 2 pending glyphs
  ShapeResultBloberizerTestInfo::Add(bloberizer, 42, font1,
                                     CanvasRotationInVertical::kRegular, 10, 0);
  ShapeResultBloberizerTestInfo::Add(bloberizer, 43, font1,
                                     CanvasRotationInVertical::kRegular, 15, 1);

  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingRunFontData(bloberizer),
            font1);
  EXPECT_FALSE(
      ShapeResultBloberizerTestInfo::HasPendingRunVerticalOffsets(bloberizer));
  {
    const auto& glyphs =
        ShapeResultBloberizerTestInfo::PendingRunGlyphs(bloberizer);
    EXPECT_EQ(glyphs.size(), 2ul);
    EXPECT_EQ(42, glyphs[0]);
    EXPECT_EQ(43, glyphs[1]);

    const auto& offsets =
        ShapeResultBloberizerTestInfo::PendingRunOffsets(bloberizer);
    EXPECT_EQ(offsets.size(), 2ul);
    EXPECT_EQ(10, offsets[0]);
    EXPECT_EQ(15, offsets[1]);
  }

  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingBlobRunCount(bloberizer),
            0ul);
  EXPECT_EQ(ShapeResultBloberizerTestInfo::CommittedBlobCount(bloberizer), 0ul);

  // one more glyph, different font => pending run flush
  ShapeResultBloberizerTestInfo::Add(bloberizer, 44, font2,
                                     CanvasRotationInVertical::kRegular, 12, 0);

  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingRunFontData(bloberizer),
            font2);
  EXPECT_FALSE(
      ShapeResultBloberizerTestInfo::HasPendingRunVerticalOffsets(bloberizer));
  {
    const auto& glyphs =
        ShapeResultBloberizerTestInfo::PendingRunGlyphs(bloberizer);
    EXPECT_EQ(glyphs.size(), 1ul);
    EXPECT_EQ(44, glyphs[0]);

    const auto& offsets =
        ShapeResultBloberizerTestInfo::PendingRunOffsets(bloberizer);
    EXPECT_EQ(offsets.size(), 1ul);
    EXPECT_EQ(12, offsets[0]);
  }

  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingBlobRunCount(bloberizer),
            1ul);
  EXPECT_EQ(ShapeResultBloberizerTestInfo::CommittedBlobCount(bloberizer), 0ul);

  // flush everything (1 blob w/ 2 runs)
  EXPECT_EQ(bloberizer.Blobs().size(), 1ul);
}

TEST_F(ShapeResultBloberizerTest, StoresGlyphsVerticalOffsets) {
  Font font;
  ShapeResultBloberizer bloberizer(font.GetFontDescription(),
                                   ShapeResultBloberizer::Type::kNormal);

  SimpleFontData* font1 = CreateTestSimpleFontData();
  SimpleFontData* font2 = CreateTestSimpleFontData();

  // 2 pending glyphs
  ShapeResultBloberizerTestInfo::Add(bloberizer, 42, font1,
                                     CanvasRotationInVertical::kRegular,
                                     gfx::Vector2dF(10, 0), 0);
  ShapeResultBloberizerTestInfo::Add(bloberizer, 43, font1,
                                     CanvasRotationInVertical::kRegular,
                                     gfx::Vector2dF(15, 0), 1);

  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingRunFontData(bloberizer),
            font1);
  EXPECT_TRUE(
      ShapeResultBloberizerTestInfo::HasPendingRunVerticalOffsets(bloberizer));
  {
    const auto& glyphs =
        ShapeResultBloberizerTestInfo::PendingRunGlyphs(bloberizer);
    EXPECT_EQ(glyphs.size(), 2ul);
    EXPECT_EQ(42, glyphs[0]);
    EXPECT_EQ(43, glyphs[1]);

    const auto& offsets =
        ShapeResultBloberizerTestInfo::PendingRunOffsets(bloberizer);
    EXPECT_EQ(offsets.size(), 4ul);
    EXPECT_EQ(10, offsets[0]);
    EXPECT_EQ(0, offsets[1]);
    EXPECT_EQ(15, offsets[2]);
    EXPECT_EQ(0, offsets[3]);
  }

  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingBlobRunCount(bloberizer),
            0ul);
  EXPECT_EQ(ShapeResultBloberizerTestInfo::CommittedBlobCount(bloberizer), 0ul);

  // one more glyph, different font => pending run flush
  ShapeResultBloberizerTestInfo::Add(bloberizer, 44, font2,
                                     CanvasRotationInVertical::kRegular,
                                     gfx::Vector2dF(12, 2), 2);

  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingRunFontData(bloberizer),
            font2);
  EXPECT_TRUE(
      ShapeResultBloberizerTestInfo::HasPendingRunVerticalOffsets(bloberizer));
  {
    const auto& glyphs =
        ShapeResultBloberizerTestInfo::PendingRunGlyphs(bloberizer);
    EXPECT_EQ(glyphs.size(), 1ul);
    EXPECT_EQ(44, glyphs[0]);

    const auto& offsets =
        ShapeResultBloberizerTestInfo::PendingRunOffsets(bloberizer);
    EXPECT_EQ(offsets.size(), 2ul);
    EXPECT_EQ(12, offsets[0]);
    EXPECT_EQ(2, offsets[1]);
  }

  EXPECT_EQ(ShapeResultBloberizerTestInfo::PendingBlobRunCount(bloberizer),
            1ul);
  EXPECT_EQ(ShapeResultBloberizerTestInfo::CommittedBlobCount(bloberizer), 0ul);

  // flush everything (1 blob w/ 2 runs)
  EXPECT_EQ(bloberizer.Blobs().size(), 1ul);
}

TEST_F(ShapeResultBloberizerTest, MixedBlobRotation) {
  Font font;
  ShapeResultBloberizer bloberizer(font.GetFontDescription(),
                                   ShapeResultBloberizer::Type::kNormal);

  SimpleFontData* test_font = CreateTestSimpleFontData();

  struct {
    CanvasRotationInVertical canvas_rotation;
    size_t expected_pending_glyphs;
    size_t expected_pending_runs;
    size_t expected_committed_blobs;
  } append_ops[] = {
      // append 2 horizontal glyphs -> these go into the pending glyph buffer
      {CanvasRotationInVertical::kRegular, 1u, 0u, 0u},
      {CanvasRotationInVertical::kRegular, 2u, 0u, 0u},

      // append 3 vertical rotated glyphs -> push the prev pending (horizontal)
      // glyphs into a new run in the current (horizontal) blob
      {CanvasRotationInVertical::kRotateCanvasUpright, 1u, 1u, 0u},
      {CanvasRotationInVertical::kRotateCanvasUpright, 2u, 1u, 0u},
      {CanvasRotationInVertical::kRotateCanvasUpright, 3u, 1u, 0u},

      // append 2 more horizontal glyphs -> flush the current (horizontal) blob,
      // push prev (vertical) pending glyphs into new vertical blob run
      {CanvasRotationInVertical::kRegular, 1u, 1u, 1u},
      {CanvasRotationInVertical::kRegular, 2u, 1u, 1u},

      // append 1 more vertical glyph -> flush current (vertical) blob, push
      // prev (horizontal) pending glyphs into a new horizontal blob run
      {CanvasRotationInVertical::kRotateCanvasUpright, 1u, 1u, 2u},
  };

  for (const auto& op : append_ops) {
    ShapeResultBloberizerTestInfo::Add(bloberizer, 42, test_font,
                                       op.canvas_rotation, gfx::Vector2dF(), 0);
    EXPECT_EQ(
        op.expected_pending_glyphs,
        ShapeResultBloberizerTestInfo::PendingRunGlyphs(bloberizer).size());
    EXPECT_EQ(op.canvas_rotation,
              ShapeResultBloberizerTestInfo::PendingBlobRotation(bloberizer));
    EXPECT_EQ(op.expected_pending_runs,
              ShapeResultBloberizerTestInfo::PendingBlobRunCount(bloberizer));
    EXPECT_EQ(op.expected_committed_blobs,
              ShapeResultBloberizerTestInfo::CommittedBlobCount(bloberizer));
  }

  // flush everything -> 4 blobs total
  EXPECT_EQ(4u, bloberizer.Blobs().size());
}

// Tests that filling a glyph buffer for a specific range returns the same
// results when shaping word by word as when shaping the full run in one go.
TEST_F(ShapeResultBloberizerTest, CommonAccentLeftToRightFillGlyphBuffer) {
  // "/. ." with an accent mark over the first dot.
  const UChar kStr[] = {0x2F, 0x301, 0x2E, 0x20, 0x2E};
  TextRun text_run(kStr, base::make_span(kStr).size());
  TextRunPaintInfo run_info(text_run);
  run_info.to = 3;

  Font font(font_description);
  CachingWordShaper word_shaper(font);
  ShapeResultBuffer buffer;
  word_shaper.FillResultBuffer(run_info, &buffer);
  ShapeResultBloberizer::FillGlyphs bloberizer(
      font.GetFontDescription(), run_info, buffer,
      ShapeResultBloberizer::Type::kEmitText);

  Font reference_font(font_description);
  reference_font.SetCanShapeWordByWordForTesting(false);

  CachingWordShaper reference_word_shaper(reference_font);
  ShapeResultBuffer reference_buffer;
  reference_word_shaper.FillResultBuffer(run_info, &reference_buffer);
  ShapeResultBloberizer::FillGlyphs reference_bloberizer(
      reference_font.GetFontDescription(), run_info, reference_buffer,
      ShapeResultBloberizer::Type::kEmitText);

  const auto& glyphs =
      ShapeResultBloberizerTestInfo::PendingRunGlyphs(bloberizer);
  ASSERT_EQ(glyphs.size(), 3ul);
  const auto reference_glyphs =
      ShapeResultBloberizerTestInfo::PendingRunGlyphs(reference_bloberizer);
  ASSERT_EQ(reference_glyphs.size(), 3ul);

  EXPECT_EQ(reference_glyphs[0], glyphs[0]);
  EXPECT_EQ(reference_glyphs[1], glyphs[1]);
  EXPECT_EQ(reference_glyphs[2], glyphs[2]);

  CheckBlobBuffer(
      bloberizer.Blobs(),
      {{
          {3,
           text_run.ToStringView()
               .ToString()
               .Substring(run_info.from, run_info.to - run_info.from)
               .Utf8(),
           ExpectedRun::ClusterDirection::kAscending},
      }});
}

// Tests that filling a glyph buffer for a specific range returns the same
// results when shaping word by word as when shaping the full run in one go.
TEST_F(ShapeResultBloberizerTest, CommonAccentRightToLeftFillGlyphBuffer) {
  // "[] []" with an accent mark over the last square bracket.
  const UChar kStr[] = {0x5B, 0x5D, 0x20, 0x5B, 0x301, 0x5D};
  TextRun text_run(kStr, base::make_span(kStr).size());
  text_run.SetDirection(TextDirection::kRtl);
  TextRunPaintInfo run_info(text_run);
  run_info.from = 1;

  Font font(font_description);
  CachingWordShaper word_shaper(font);
  ShapeResultBuffer buffer;
  word_shaper.FillResultBuffer(run_info, &buffer);
  ShapeResultBloberizer::FillGlyphs bloberizer(
      font.GetFontDescription(), run_info, buffer,
      ShapeResultBloberizer::Type::kEmitText);

  Font reference_font(font_description);
  reference_font.SetCanShapeWordByWordForTesting(false);

  CachingWordShaper reference_word_shaper(reference_font);
  ShapeResultBuffer reference_buffer;
  reference_word_shaper.FillResultBuffer(run_info, &reference_buffer);
  ShapeResultBloberizer::FillGlyphs reference_bloberizer(
      reference_font.GetFontDescription(), run_info, reference_buffer,
      ShapeResultBloberizer::Type::kEmitText);

  const auto& glyphs =
      ShapeResultBloberizerTestInfo::PendingRunGlyphs(bloberizer);
  ASSERT_EQ(5u, glyphs.size());
  const auto reference_glyphs =
      ShapeResultBloberizerTestInfo::PendingRunGlyphs(reference_bloberizer);
  ASSERT_EQ(5u, reference_glyphs.size());

  EXPECT_EQ(reference_glyphs[0], glyphs[0]);
  EXPECT_EQ(reference_glyphs[1], glyphs[1]);
  EXPECT_EQ(reference_glyphs[2], glyphs[2]);
  EXPECT_EQ(reference_glyphs[3], glyphs[3]);
  EXPECT_EQ(reference_glyphs[4], glyphs[4]);
}

TEST_F(ShapeResultBloberizerTest, CommonAccentRightToLeftFillGlyphBufferNG) {
  // "[] []" with an accent mark over the last square bracket.
  const UChar kStr[] = {0x5B, 0x5D, 0x20, 0x5B, 0x301, 0x5D};
  String string{base::span(kStr)};

  Font font(font_description);
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kRtl);

  ShapeResultView* result_view = ShapeResultView::Create(result);
  TextFragmentPaintInfo text_info{StringView(string), 1, string.length(),
                                  result_view};
  ShapeResultBloberizer::FillGlyphsNG bloberizer_ng(
      font.GetFontDescription(), text_info.text, text_info.from, text_info.to,
      text_info.shape_result, ShapeResultBloberizer::Type::kEmitText);

  CheckBlobBuffer(
      bloberizer_ng.Blobs(),
      {{
          {5,
           string.Substring(text_info.from, text_info.to - text_info.from)
               .Utf8(),
           ExpectedRun::ClusterDirection::kDescending},
      }});
}

TEST_F(ShapeResultBloberizerTest, FourByteUtf8CodepointsNG) {
  // Codepoints which encode to four UTF-8 code units.
  const UChar kStr[] = {0xD841, 0xDF31, 0xD841, 0xDF79};
  String string{base::span(kStr)};

  Font font(font_description);
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  ShapeResultView* result_view = ShapeResultView::Create(result);
  TextFragmentPaintInfo text_info{StringView(string), 0, string.length(),
                                  result_view};
  ShapeResultBloberizer::FillGlyphsNG bloberizer_ng(
      font.GetFontDescription(), text_info.text, text_info.from, text_info.to,
      text_info.shape_result, ShapeResultBloberizer::Type::kEmitText);

  CheckBlobBuffer(
      bloberizer_ng.Blobs(),
      {{
          {2,
           string.Substring(text_info.from, text_info.to - text_info.from)
               .Utf8(),
           ExpectedRun::ClusterDirection::kAscending},
      }});
}

TEST_F(ShapeResultBloberizerTest, OffsetIntoTrailingSurrogateNG) {
  // Codepoints which encode to four UTF-8 code units.
  const UChar kStr[] = {0xD841, 0xDF31, 0xD841, 0xDF79};
  String string{base::span(kStr)};

  Font font(font_description);
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  ShapeResultView* result_view = ShapeResultView::Create(result);
  // Start at offset 1 into text at trailing surrogate.
  TextFragmentPaintInfo text_info{StringView(string), 1, string.length(),
                                  result_view};
  ShapeResultBloberizer::FillGlyphsNG bloberizer_ng(
      font.GetFontDescription(), text_info.text, text_info.from, text_info.to,
      text_info.shape_result, ShapeResultBloberizer::Type::kEmitText);

  // Do not expect the trailing surrogate to be in any output.
  const auto& glyphs =
      ShapeResultBloberizerTestInfo::PendingRunGlyphs(bloberizer_ng);
  EXPECT_EQ(1u, glyphs.size());

  CheckBlobBuffer(
      bloberizer_ng.Blobs(),
      {{
          {1,
           string
               .Substring(text_info.from + 1, text_info.to - text_info.from - 1)
               .Utf8(),
           ExpectedRun::ClusterDirection::kAscending},
      }});
}

TEST_F(ShapeResultBloberizerTest, LatinMultRunNG) {
  TextDirection direction = TextDirection::kLtr;
  String string = "Testing ShapeResultIterator::CopyRange";

  ExpectedRange range_a{0, 5};
  ExpectedRange range_b{5, 7};
  ExpectedRange range_c{7, 32};
  ExpectedRange range_d{32, 38};
  HarfBuzzShaper shaper_a(string.Substring(range_a.from, range_a.to));
  HarfBuzzShaper shaper_b(string.Substring(range_b.from, range_b.to));
  HarfBuzzShaper shaper_c(string.Substring(range_c.from, range_c.to));
  HarfBuzzShaper shaper_d(string.Substring(range_d.from, range_d.to));

  Font font(font_description);

  FontDescription font2_description(font_description);
  font2_description.SetComputedSize(20);
  Font font2(font2_description);

  // Combine four separate results into a single one to ensure we have a result
  // with multiple runs. Interleave fonts to ensure run changes.
  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  shaper_a.Shape(&font, direction)->CopyRange(0u, range_a.length(), result);
  shaper_b.Shape(&font2, direction)->CopyRange(0u, range_b.length(), result);
  shaper_c.Shape(&font, direction)->CopyRange(0u, range_c.length(), result);
  shaper_d.Shape(&font2, direction)->CopyRange(0u, range_d.length(), result);

  ShapeResultView* result_view = ShapeResultView::Create(result);
  TextFragmentPaintInfo text_info{StringView(string), 1, string.length(),
                                  result_view};
  ShapeResultBloberizer::FillGlyphsNG bloberizer_ng(
      font.GetFontDescription(), text_info.text, text_info.from, text_info.to,
      text_info.shape_result, ShapeResultBloberizer::Type::kEmitText);

  CheckBlobBuffer(
      bloberizer_ng.Blobs(),
      {{
          // "Testi"
          {static_cast<int>(range_a.length() - 1),
           string.Substring(range_a.from + 1, range_a.length() - 1).Utf8(),
           ExpectedRun::ClusterDirection::kAscending},
          // "ng"
          {static_cast<int>(range_b.length()),
           string.Substring(range_b.from, range_b.length()).Utf8(),
           ExpectedRun::ClusterDirection::kAscending},
          // " ShapeResultIterator::Cop"
          {static_cast<int>(range_c.length()),
           string.Substring(range_c.from, range_c.length()).Utf8(),
           ExpectedRun::ClusterDirection::kAscending},
          // "yRange"
          {static_cast<int>(range_d.length()),
           string.Substring(range_d.from, range_d.length()).Utf8(),
           ExpectedRun::ClusterDirection::kAscending},
      }});
}

TEST_F(ShapeResultBloberizerTest, SupplementaryMultiRunNG) {
  TextDirection direction = TextDirection::kLtr;
  // 𠜎𠜱𠝹𠱓𠱸𠲖𠳏𠳕
  const UChar kStrSupp[] = {0xD841, 0xDF0E, 0xD841, 0xDF31, 0xD841, 0xDF79,
                            0xD843, 0xDC53, 0xD843, 0xDC78, 0xD843, 0xDC96,
                            0xD843, 0xDCCF, 0xD843, 0xDCD5};
  String string{base::span(kStrSupp)};

  ExpectedRange range_a{0, 6};
  ExpectedRange range_b{6, 12};
  ExpectedRange range_c{12, 16};
  HarfBuzzShaper shaper_a(string.Substring(range_a.from, range_a.to));
  HarfBuzzShaper shaper_b(string.Substring(range_b.from, range_b.to));
  HarfBuzzShaper shaper_c(string.Substring(range_c.from, range_c.to));

  Font font = blink::test::CreateTestFont(
      AtomicString("NotoSansCJK"),
      blink::test::BlinkRootDir() +
          "/web_tests/third_party/NotoSansCJK/NotoSansCJKjp-Regular-subset.otf",
      12);
  Font font2 = blink::test::CreateTestFont(
      AtomicString("NotoSansCJK"),
      blink::test::BlinkRootDir() +
          "/web_tests/third_party/NotoSansCJK/NotoSansCJKjp-Regular-subset.otf",
      20);

  // Combine four separate results into a single one to ensure we have a result
  // with multiple runs. Interleave fonts to ensure run changes.
  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  shaper_a.Shape(&font, direction)->CopyRange(0u, range_a.length(), result);
  shaper_b.Shape(&font2, direction)->CopyRange(0u, range_b.length(), result);
  shaper_c.Shape(&font, direction)->CopyRange(0u, range_c.length(), result);

  ShapeResultView* result_view = ShapeResultView::Create(result);
  TextFragmentPaintInfo text_info{StringView(string), 0, string.length(),
                                  result_view};
  ShapeResultBloberizer::FillGlyphsNG bloberizer_ng(
      font.GetFontDescription(), text_info.text, text_info.from, text_info.to,
      text_info.shape_result, ShapeResultBloberizer::Type::kEmitText);

  CheckBlobBuffer(bloberizer_ng.Blobs(),
                  {{
                      // "𠜎𠜱𠝹"
                      {static_cast<int>(range_a.length() / 2),
                       string.Substring(range_a.from, range_a.length()).Utf8(),
                       ExpectedRun::ClusterDirection::kAscending},
                      // "𠱓𠱸𠲖"
                      {static_cast<int>(range_b.length() / 2),
                       string.Substring(range_b.from, range_b.length()).Utf8(),
                       ExpectedRun::ClusterDirection::kAscending},
                      // "𠳏𠳕"
                      {static_cast<int>(range_c.length() / 2),
                       string.Substring(range_c.from, range_c.length()).Utf8(),
                       ExpectedRun::ClusterDirection::kAscending},
                  }});
}

// Tests that runs with zero glyphs (the ZWJ non-printable character in this
// case) are handled correctly. This test passes if it does not cause a crash.
TEST_F(ShapeResultBloberizerTest, SubRunWithZeroGlyphs) {
  // "Foo &zwnj; bar"
  const UChar kStr[] = {0x46, 0x6F, 0x6F, 0x20, 0x200C, 0x20, 0x62, 0x61, 0x71};
  TextRun text_run(kStr, base::make_span(kStr).size());

  Font font(font_description);
  CachingWordShaper shaper(font);
  gfx::RectF glyph_bounds;
  ASSERT_GT(shaper.Width(text_run, &glyph_bounds), 0);

  TextRunPaintInfo run_info(text_run);
  run_info.to = 8;

  CachingWordShaper word_shaper(font);
  ShapeResultBuffer buffer;
  word_shaper.FillResultBuffer(run_info, &buffer);
  ShapeResultBloberizer::FillGlyphs bloberizer(
      font.GetFontDescription(), run_info, buffer,
      ShapeResultBloberizer::Type::kEmitText);

  shaper.GetCharacterRange(text_run, 0, 8);
}

}  // namespace blink
```