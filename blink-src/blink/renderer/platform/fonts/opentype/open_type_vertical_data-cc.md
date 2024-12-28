Response:
Let's break down the thought process for analyzing the provided C++ code and generating the explanation.

**1. Understanding the Goal:**

The primary goal is to explain the functionality of the `open_type_vertical_data.cc` file within the Chromium Blink rendering engine. The request specifically asks about its relationship to web technologies (JavaScript, HTML, CSS), to provide examples of logical reasoning (input/output), and to highlight potential user/programming errors.

**2. Initial Code Scan and Identification of Key Areas:**

The first step is a quick scan of the code to get a high-level understanding. Keywords and structural elements that stand out include:

* **Copyright Notice:**  Indicates the origin and licensing.
* **Includes:**  Lists dependencies like `base/logging.h`, `skia/include/core/SkTypeface.h`, suggesting interaction with font handling and potentially graphics.
* **Namespaces:** `blink::open_type` clearly defines the scope.
* **Macros like `OT_MAKE_TAG`:**  Suggests the manipulation of OpenType font table tags.
* **`struct` definitions (e.g., `HheaTable`, `VheaTable`, `VORGTable`):**  These strongly indicate the code is parsing and interpreting data from OpenType font files. The names themselves hint at the specific tables being handled (Horizontal Header, Vertical Header, Vertical Origin).
* **`OpenTypeVerticalData` class:**  This is the core class, likely responsible for managing vertical font data.
* **Methods like `LoadMetrics`, `AdvanceHeight`, `GetVerticalTranslationsForGlyphs`:** These suggest specific actions related to processing font data and calculating glyph positions.
* **`kHheaTag`, `kVheaTag`, `kVORGTag`:**  These constants are the tags for the OpenType tables, confirming the focus on parsing specific parts of the font file.

**3. Deeper Dive into Functionality - Table Parsing:**

The `LoadMetrics` function is central. Analyzing its steps:

* **`CopyOpenTypeTable`:** This function retrieves raw table data from the `SkTypeface` (Skia's font representation). This is the starting point of data acquisition.
* **`ValidateTable`:** This strongly suggests error checking and ensuring the retrieved data is in the expected format. This is crucial for robustness.
* **Processing of `hhea`, `hmtx`:** Even though the file is about *vertical* data, these horizontal tables are loaded *first*. The comment "Load hhea and hmtx to get x-component of vertical origins" provides the key insight here. This hints at how horizontal metrics influence vertical positioning.
* **Processing of `vhea`, `vmtx`:** These are the core vertical metrics tables, confirming the file's primary purpose.
* **Processing of `VORG`:** The comments highlight that this is *optional* and preferred for vertical origin calculation. This shows a hierarchy of how vertical information is obtained.
* **Error handling (`DLOG(ERROR)`):**  The code includes checks for missing or broken tables, demonstrating a focus on handling invalid font data.

**4. Connecting to Web Technologies:**

This is where the thinking shifts to how the low-level font data affects what users see in a browser.

* **Vertical Text Layout:** The existence of vertical metrics tables directly implies support for vertical writing modes (like traditional Chinese or Japanese). This is the most obvious connection to CSS (`writing-mode: vertical-rl;`).
* **Glyph Positioning:** The `GetVerticalTranslationsForGlyphs` function calculates `x` and `y` offsets. This directly impacts how individual characters are placed when rendered, linking to the core functionality of HTML text display.
* **JavaScript Interaction (Indirect):**  While this C++ code doesn't directly interact with JavaScript, the *effects* of its work are visible. JavaScript code that manipulates text or layout will rely on the correct rendering provided by this engine code.
* **Font Rendering Pipeline:**  It's important to realize this is just one piece of a larger pipeline. The browser fetches fonts, this code parses them, and then the rendering engine (using Skia) draws the glyphs based on this information.

**5. Logical Reasoning (Input/Output):**

To illustrate logical reasoning, consider a specific scenario:

* **Input:** An OpenType font with a `VORG` table and a specific glyph index.
* **Process:** `LoadMetrics` parses the `VORG` table, storing the vertical origin for that glyph. `GetVerticalTranslationsForGlyphs` looks up the glyph and uses the stored origin.
* **Output:** The glyph is rendered with the correct vertical offset.

Contrast this with:

* **Input:** An OpenType font *without* a `VORG` table.
* **Process:** `LoadMetrics` won't find a `VORG`. `GetVerticalTranslationsForGlyphs` will fall back to using `vmtx` data or even a default ascent value.
* **Output:** The glyph is rendered, but the vertical positioning might be different (potentially less accurate or using a generic fallback).

**6. User/Programming Errors:**

Think about how things can go wrong from a developer's or even a user's perspective:

* **Malformed Font Files:** If a font file is corrupted or doesn't adhere to the OpenType specification, the `ValidateTable` checks will fail, and the browser might display fallback glyphs or have rendering issues. This is a common problem users encounter (e.g., a website showing squares instead of characters).
* **Missing Vertical Metrics:** If a font is intended to support vertical text but lacks the necessary `vhea` or `vmtx` tables, the browser will likely fall back to horizontal layout or use approximations, leading to incorrect rendering. This is something a font developer might overlook.
* **Incorrect CSS `writing-mode`:** If a user or web developer *expects* vertical rendering but doesn't set the `writing-mode` CSS property, this code will still parse the vertical metrics, but the layout engine won't utilize them as intended. This is a common mistake in web development.

**7. Structuring the Explanation:**

Finally, organize the information logically, starting with a high-level summary and then delving into specifics. Use clear headings and examples to make it easy to understand. Address each part of the original request (functionality, web technology links, logical reasoning, errors). Use code snippets where appropriate to illustrate points. Maintain a consistent and informative tone.

This detailed process of code analysis, conceptual linking, and scenario-based thinking is how you can arrive at a comprehensive and accurate explanation of a complex piece of software like the provided C++ file.
这个文件 `open_type_vertical_data.cc` 是 Chromium Blink 渲染引擎的一部分，专门负责处理 OpenType 字体文件中与 **垂直排版** 相关的元数据。它从字体文件中读取并解析特定的 OpenType 表格，以便在垂直书写模式下正确地渲染文本。

以下是它的主要功能：

**1. 解析 OpenType 垂直排版相关表格：**

   - **`VHEA` (Vertical Header Table):**  包含字体垂直排版的度量信息，如 ascent（上升高度）、descent（下降高度）、lineGap（行间距）等。
   - **`VMTX` (Vertical Metrics Table):** 包含每个字形的垂直排版度量，如 advanceHeight（垂直方向的步进距离）和 topSideBearing（字形顶部边距）。
   - **`VORG` (Vertical Origin Table):**  定义了每个字形在垂直排版时的原点 Y 坐标。这是控制字形垂直方向对齐的关键。
   - 还会读取 `HHEA` (Horizontal Header Table) 和 `HMTX` (Horizontal Metrics Table) 的部分信息，用于某些垂直排版的计算（例如，水平方向的步进宽度，用于计算垂直原点的 X 分量）。

**2. 提供访问垂直排版度量数据的接口：**

   - `OpenTypeVerticalData` 类存储了解析后的数据。
   - 提供方法如 `AdvanceHeight(Glyph glyph)` 来获取特定字形的垂直步进距离。
   - 提供 `GetVerticalTranslationsForGlyphs` 方法来计算一组字形的垂直方向偏移量。

**3. 处理缺少垂直排版信息的字体：**

   - 如果字体文件中缺少 `VHEA` 或 `VMTX` 等关键表格，该文件会尝试使用一些默认值或回退策略，以避免渲染失败。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件本身不直接包含 JavaScript、HTML 或 CSS 代码，但它为这些 Web 技术的渲染提供了底层支持，尤其是在处理垂直书写模式时。

**举例说明：**

* **CSS `writing-mode: vertical-rl;` 或 `writing-mode: vertical-lr;`:**  当 CSS 中设置了垂直书写模式时，Blink 渲染引擎会调用与垂直排版相关的代码，其中就包括 `open_type_vertical_data.cc` 中的功能。这个文件会根据字体文件中的 `VHEA`、`VMTX` 和 `VORG` 表格提供字形的垂直布局信息。
    * **假设输入：**  HTML 中包含一段文本，并且其 CSS 样式设置为 `writing-mode: vertical-rl;`。所使用的字体文件包含 `VHEA` 和 `VMTX` 表格，但缺少 `VORG` 表格。
    * **逻辑推理：** `OpenTypeVerticalData::LoadMetrics` 会解析 `VHEA` 和 `VMTX` 表格。当渲染引擎需要计算字形的垂直偏移时，`GetVerticalTranslationsForGlyphs` 方法会被调用。由于缺少 `VORG`，该方法会根据 `VMTX` 表格中的 `topSideBearing` 和字形的边界框来计算垂直原点。
    * **输出：** 浏览器会按照从右到左、从上到下的顺序垂直排列文本中的字形。每个字形的垂直位置是根据 `VMTX` 中的信息计算出来的。

* **HTML 文本内容包含垂直书写语言（例如，中文、日文）：** 即使没有显式设置 `writing-mode`，一些浏览器也会根据文本内容判断是否需要使用垂直排版（例如，CJK 标点符号在行首时可能会触发垂直排版）。这时，`open_type_vertical_data.cc` 同样会发挥作用。

* **JavaScript 操作文本内容或样式：** JavaScript 可以动态修改元素的文本内容或 CSS 样式，包括 `writing-mode` 属性。当 JavaScript 导致需要渲染垂直排版的文本时，底层的字体数据处理仍然会用到这个文件中的代码。

**逻辑推理举例：**

**假设输入：**  一个 OpenType 字体文件，包含以下数据：

   - `VHEA` 表格： `ascent = 1000`, `descent = 200`, `lineGap = 0`
   - `VMTX` 表格：
      - 字形索引 0 (空格): `advanceHeight = 0`, `topSideBearing = 0`
      - 字形索引 65 ('A'): `advanceHeight = 1200`, `topSideBearing = 100`
   - `size_per_unit_ = 1.0` (假设字体单位到像素的比例为 1)

**逻辑推理：**

1. **`OpenTypeVerticalData::LoadMetrics`** 会读取并解析 `VHEA` 和 `VMTX` 表格，将数据存储在内部。

2. 当需要计算字形 'A' 的垂直步进距离时，调用 **`OpenTypeVerticalData::AdvanceHeight(65)`**。

3. 由于字形索引 65 小于 `advance_heights_.size()`，函数会返回 `advance_heights_[65]`，即 `1200 * size_per_unit_ = 1200`。

4. 当需要计算字形 'A' 的垂直偏移量时，调用 **`OpenTypeVerticalData::GetVerticalTranslationsForGlyphs`**。

5. 如果 `VORG` 表格不存在，并且 `top_side_bearings_` 包含足够的信息，函数会使用 `topSideBearing`（100）和字形的边界框来计算 Y 偏移量。假设字形 'A' 的边界框顶部 y 坐标为 200。

6. 输出的 Y 偏移量将是 `bounds.y() - top_side_bearing`，即 `200 - 100 = 100`。

**用户或编程常见的使用错误举例：**

1. **字体文件损坏或不完整：** 如果用户使用的字体文件损坏，或者缺少必要的垂直排版表格（如 `VHEA` 或 `VMTX`），`OpenTypeVerticalData::LoadMetrics` 在解析时可能会失败，导致垂直排版显示不正确或回退到水平排版。
   * **错误现象：** 垂直排列的文字间距不均匀，或者字形位置错乱。

2. **字体设计不当：** 即使字体文件包含垂直排版表格，但如果表格中的数据（例如，`topSideBearing` 的值）设置不合理，也会导致渲染问题。
   * **错误现象：** 垂直排列的文字上下字形之间过于紧凑或过于分散。

3. **Web 开发者混淆逻辑像素和字体单位：** `OpenTypeVerticalData` 中的很多值是以字体单位表示的。在将这些值应用到屏幕渲染时，需要乘以正确的缩放因子 (`size_per_unit_`)。如果开发者在处理字体数据时没有进行正确的单位转换，可能会导致渲染错误。
   * **错误现象：** 垂直排列的文字大小或间距与预期不符。

4. **误用不支持垂直排版的字体：**  如果 Web 开发者尝试对一个不包含 `VHEA` 或 `VMTX` 等表格的字体应用垂直排版样式，浏览器可能会尽力渲染，但效果通常不理想，或者会使用默认的回退策略。
   * **错误现象：** 垂直排列的文字看起来像水平排列的文字旋转了 90 度，或者字形之间重叠。

总而言之，`open_type_vertical_data.cc` 是 Blink 渲染引擎中一个关键的组成部分，它负责理解和处理 OpenType 字体中与垂直排版相关的信息，从而使得浏览器能够正确地渲染垂直书写模式的文本。它的正确运行对于支持多种语言和排版需求至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/opentype/open_type_vertical_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2012 Koji Ishii <kojiishi@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/opentype/open_type_vertical_data.h"

#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/platform/fonts/opentype/open_type_types.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"
#include "third_party/blink/renderer/platform/fonts/skia/skia_text_metrics.h"
#include "third_party/skia/include/core/SkTypeface.h"

namespace blink {
namespace open_type {

// The input characters are big-endian (first is most significant).
#define OT_MAKE_TAG(ch1, ch2, ch3, ch4)                    \
  ((((uint32_t)(ch1)) << 24) | (((uint32_t)(ch2)) << 16) | \
   (((uint32_t)(ch3)) << 8) | ((uint32_t)(ch4)))

const SkFontTableTag kHheaTag = OT_MAKE_TAG('h', 'h', 'e', 'a');
const SkFontTableTag kHmtxTag = OT_MAKE_TAG('h', 'm', 't', 'x');
const SkFontTableTag kVheaTag = OT_MAKE_TAG('v', 'h', 'e', 'a');
const SkFontTableTag kVmtxTag = OT_MAKE_TAG('v', 'm', 't', 'x');
const SkFontTableTag kVORGTag = OT_MAKE_TAG('V', 'O', 'R', 'G');

#pragma pack(1)

struct HheaTable {
  DISALLOW_NEW();
  open_type::Fixed version;
  open_type::Int16 ascender;
  open_type::Int16 descender;
  open_type::Int16 line_gap;
  open_type::Int16 advance_width_max;
  open_type::Int16 min_left_side_bearing;
  open_type::Int16 min_right_side_bearing;
  open_type::Int16 x_max_extent;
  open_type::Int16 caret_slope_rise;
  open_type::Int16 caret_slope_run;
  open_type::Int16 caret_offset;
  open_type::Int16 reserved[4];
  open_type::Int16 metric_data_format;
  open_type::UInt16 number_of_h_metrics;
};

struct VheaTable {
  DISALLOW_NEW();
  open_type::Fixed version;
  open_type::Int16 ascent;
  open_type::Int16 descent;
  open_type::Int16 line_gap;
  open_type::Int16 advance_height_max;
  open_type::Int16 min_top_side_bearing;
  open_type::Int16 min_bottom_side_bearing;
  open_type::Int16 y_max_extent;
  open_type::Int16 caret_slope_rise;
  open_type::Int16 caret_slope_run;
  open_type::Int16 caret_offset;
  open_type::Int16 reserved[4];
  open_type::Int16 metric_data_format;
  open_type::UInt16 num_of_long_ver_metrics;
};

struct HmtxTable {
  DISALLOW_NEW();
  struct Entry {
    DISALLOW_NEW();
    open_type::UInt16 advance_width;
    open_type::Int16 lsb;
  } entries[1];
};

struct VmtxTable {
  DISALLOW_NEW();
  struct Entry {
    DISALLOW_NEW();
    open_type::UInt16 advance_height;
    open_type::Int16 top_side_bearing;
  } entries[1];
};

struct VORGTable {
  DISALLOW_NEW();
  open_type::UInt16 major_version;
  open_type::UInt16 minor_version;
  open_type::Int16 default_vert_origin_y;
  open_type::UInt16 num_vert_origin_y_metrics;
  struct VertOriginYMetrics {
    DISALLOW_NEW();
    open_type::UInt16 glyph_index;
    open_type::Int16 vert_origin_y;
  } vert_origin_y_metrics[1];

  size_t RequiredSize() const {
    return sizeof(*this) +
           sizeof(VertOriginYMetrics) * (num_vert_origin_y_metrics - 1);
  }
};

#pragma pack()

}  // namespace open_type

OpenTypeVerticalData::OpenTypeVerticalData(sk_sp<SkTypeface> typeface)
    : default_vert_origin_y_(0),
      size_per_unit_(0),
      ascent_fallback_(0),
      height_fallback_(0) {
  LoadMetrics(typeface);
}

static void CopyOpenTypeTable(sk_sp<SkTypeface> typeface,
                              SkFontTableTag tag,
                              Vector<char>& destination) {
  const size_t table_size = typeface->getTableSize(tag);
  destination.resize(base::checked_cast<wtf_size_t>(table_size));
  if (table_size) {
    typeface->getTableData(tag, 0, table_size, destination.data());
  }
}

void OpenTypeVerticalData::LoadMetrics(sk_sp<SkTypeface> typeface) {
  // Load hhea and hmtx to get x-component of vertical origins.
  // If these tables are missing, it's not an OpenType font.
  Vector<char> buffer;
  CopyOpenTypeTable(typeface, open_type::kHheaTag, buffer);
  const open_type::HheaTable* hhea =
      open_type::ValidateTable<open_type::HheaTable>(buffer);
  if (!hhea)
    return;
  uint16_t count_hmtx_entries = hhea->number_of_h_metrics;
  if (!count_hmtx_entries) {
    DLOG(ERROR) << "Invalid numberOfHMetrics";
    return;
  }

  CopyOpenTypeTable(typeface, open_type::kHmtxTag, buffer);
  const open_type::HmtxTable* hmtx =
      open_type::ValidateTable<open_type::HmtxTable>(buffer,
                                                     count_hmtx_entries);
  if (!hmtx) {
    DLOG(ERROR) << "hhea exists but hmtx does not (or broken)";
    return;
  }
  advance_widths_.resize(count_hmtx_entries);
  for (uint16_t i = 0; i < count_hmtx_entries; ++i)
    advance_widths_[i] = hmtx->entries[i].advance_width;

  // Load vhea first. This table is required for fonts that support vertical
  // flow.
  CopyOpenTypeTable(typeface, open_type::kVheaTag, buffer);
  const open_type::VheaTable* vhea =
      open_type::ValidateTable<open_type::VheaTable>(buffer);
  if (!vhea)
    return;
  uint16_t count_vmtx_entries = vhea->num_of_long_ver_metrics;
  if (!count_vmtx_entries) {
    DLOG(ERROR) << "Invalid numOfLongVerMetrics";
    return;
  }

  // Load VORG. This table is optional.
  CopyOpenTypeTable(typeface, open_type::kVORGTag, buffer);
  const open_type::VORGTable* vorg =
      open_type::ValidateTable<open_type::VORGTable>(buffer);
  if (vorg && buffer.size() >= vorg->RequiredSize()) {
    default_vert_origin_y_ = vorg->default_vert_origin_y;
    uint16_t count_vert_origin_y_metrics = vorg->num_vert_origin_y_metrics;
    if (!count_vert_origin_y_metrics) {
      // Add one entry so that hasVORG() becomes true
      vert_origin_y_.Set(0, default_vert_origin_y_);
    } else {
      for (uint16_t i = 0; i < count_vert_origin_y_metrics; ++i) {
        const open_type::VORGTable::VertOriginYMetrics& metrics =
            vorg->vert_origin_y_metrics[i];
        vert_origin_y_.Set(metrics.glyph_index, metrics.vert_origin_y);
      }
    }
  }

  // Load vmtx then. This table is required for fonts that support vertical
  // flow.
  CopyOpenTypeTable(typeface, open_type::kVmtxTag, buffer);
  const open_type::VmtxTable* vmtx =
      open_type::ValidateTable<open_type::VmtxTable>(buffer,
                                                     count_vmtx_entries);
  if (!vmtx) {
    DLOG(ERROR) << "vhea exists but vmtx does not (or broken)";
    return;
  }
  advance_heights_.resize(count_vmtx_entries);
  for (uint16_t i = 0; i < count_vmtx_entries; ++i)
    advance_heights_[i] = vmtx->entries[i].advance_height;

  // VORG is preferred way to calculate vertical origin than vmtx,
  // so load topSideBearing from vmtx only if VORG is missing.
  if (HasVORG())
    return;

  wtf_size_t size_extra =
      buffer.size() - sizeof(open_type::VmtxTable::Entry) * count_vmtx_entries;
  if (size_extra % sizeof(open_type::Int16)) {
    DLOG(ERROR) << "vmtx has incorrect tsb count";
    return;
  }
  wtf_size_t count_top_side_bearings =
      count_vmtx_entries + size_extra / sizeof(open_type::Int16);
  top_side_bearings_.resize(count_top_side_bearings);
  wtf_size_t i;
  for (i = 0; i < count_vmtx_entries; ++i)
    top_side_bearings_[i] = vmtx->entries[i].top_side_bearing;
  if (i < count_top_side_bearings) {
    const open_type::Int16* p_top_side_bearings_extra =
        reinterpret_cast<const open_type::Int16*>(
            &vmtx->entries[count_vmtx_entries]);
    for (; i < count_top_side_bearings; ++i, ++p_top_side_bearings_extra)
      top_side_bearings_[i] = *p_top_side_bearings_extra;
  }
}

void OpenTypeVerticalData::SetScaleAndFallbackMetrics(float size_per_unit,
                                                      float ascent,
                                                      int height) {
  size_per_unit_ = size_per_unit;
  ascent_fallback_ = ascent;
  height_fallback_ = height;
}

float OpenTypeVerticalData::AdvanceHeight(Glyph glyph) const {
  wtf_size_t count_heights = advance_heights_.size();
  if (count_heights) {
    uint16_t advance_f_unit =
        advance_heights_[glyph < count_heights ? glyph : count_heights - 1];
    float advance = advance_f_unit * size_per_unit_;
    return advance;
  }

  // No vertical info in the font file; use height as advance.
  return height_fallback_;
}

void OpenTypeVerticalData::GetVerticalTranslationsForGlyphs(
    const SkFont& font,
    const Glyph* glyphs,
    size_t count,
    float* out_xy_array) const {
  wtf_size_t count_widths = advance_widths_.size();
  DCHECK_GT(count_widths, 0u);
  bool use_vorg = HasVORG();
  wtf_size_t count_top_side_bearings = top_side_bearings_.size();
  float default_vert_origin_y = std::numeric_limits<float>::quiet_NaN();
  for (float *end = &(out_xy_array[count * 2]); out_xy_array != end;
       ++glyphs, out_xy_array += 2) {
    Glyph glyph = *glyphs;
    uint16_t width_f_unit =
        advance_widths_[glyph < count_widths ? glyph : count_widths - 1];
    float width = width_f_unit * size_per_unit_;
    out_xy_array[0] = -width / 2;

    // For Y, try VORG first.
    if (use_vorg) {
      if (glyph) {
        auto it = vert_origin_y_.find(glyph);
        if (it != vert_origin_y_.end()) {
          int16_t vert_origin_yf_unit = it->value;
          out_xy_array[1] = -vert_origin_yf_unit * size_per_unit_;
          continue;
        }
      }
      if (std::isnan(default_vert_origin_y))
        default_vert_origin_y = -default_vert_origin_y_ * size_per_unit_;
      out_xy_array[1] = default_vert_origin_y;
      continue;
    }

    // If no VORG, try vmtx next.
    if (count_top_side_bearings) {
      int16_t top_side_bearing_f_unit =
          top_side_bearings_[glyph < count_top_side_bearings
                                 ? glyph
                                 : count_top_side_bearings - 1];
      float top_side_bearing = top_side_bearing_f_unit * size_per_unit_;

      SkRect bounds;
      SkFontGetBoundsForGlyph(font, glyph, &bounds);
      out_xy_array[1] = bounds.y() - top_side_bearing;
      continue;
    }

    // No vertical info in the font file; use ascent as vertical origin.
    out_xy_array[1] = -ascent_fallback_;
  }
}

}  // namespace blink

"""

```