Response:
Let's break down the request and the provided code to construct the answer.

**1. Understanding the Core Request:**

The request asks for a detailed explanation of the `vtt_parser.cc` file, focusing on:

* **Functionality:** What does this code do?
* **Relationships:** How does it interact with JavaScript, HTML, and CSS?
* **Logic and Reasoning:** Can we infer behavior from inputs and outputs?
* **Error Handling:** What common mistakes can users or programmers make?
* **User Interaction:** How does a user's action lead to this code being executed?

**2. Initial Code Analysis and Keyword Identification:**

Scanning the code reveals key terms and concepts:

* `VTTParser`: The central class, indicating parsing functionality.
* `WebVTT`: The file format being parsed.
* `TextTrackCue`, `VTTCue`: Data structures representing individual subtitles/captions.
* `VTTRegion`: Represents regions on the video for displaying cues.
* `CSSStyleSheet`: Indicates handling of CSS within the VTT file.
* `ParseBytes`, `Flush`: Methods for processing VTT data incrementally and completing parsing.
* `kInitial`, `kHeader`, `kRegion`, `kStyle`, `kId`, `kTimingsAndSettings`, `kCueText`, `kBadCue`:  States in a state machine, suggesting a line-by-line parsing process.
* `DocumentFragment`:  Indicates the creation of DOM structures for the cue text.
* `VTTTreeBuilder`: A class for building the DOM tree from cue text.
* `VTTTokenizer`:  Suggests breaking down the cue text into meaningful units.
* `CollectTimeStamp`:  Parsing time information from the VTT file.

**3. Mapping Code to Functionality:**

Based on the keywords, we can start outlining the file's functionality:

* **Core Parsing:** The primary goal is to parse a WebVTT file, extracting cues (subtitles/captions) and associated information like timings, styling, and regions.
* **State Machine:** The `state_` variable and the `switch` statement in `Parse()` clearly indicate a state machine-driven parsing process. Each state handles a different part of the VTT file structure.
* **Cue Extraction:**  The code extracts cue IDs, start and end times, settings, and the actual text content.
* **Region Handling:**  It identifies and parses `REGION` blocks, storing them in `region_map_`.
* **Style Sheet Handling:** It identifies and parses `STYLE` blocks, creating `CSSStyleSheet` objects.
* **Cue Text Processing:** The `VTTTreeBuilder` is responsible for parsing the cue text itself, handling tags like `<b>`, `<i>`, `<c>`, `<v>`, `<ruby>`, etc., to create a DOM structure.
* **Error Handling (Implicit):** The `kBadCue` state and checks for invalid syntax imply error handling, although explicit error messages aren't prominent in this snippet.

**4. Connecting to JavaScript, HTML, and CSS:**

* **HTML:** The parsed cues are ultimately displayed on the video element in an HTML page. The `<track>` element in HTML is the standard way to link to VTT files. The DOM structure created for the cue text is integrated into the video's subtitle display. Regions also directly influence the rendering area of the cues on the video, which is part of the HTML structure.
* **CSS:** The `STYLE` blocks in the VTT file contain CSS rules that directly style the cues. The `CSSStyleSheet` objects created by the parser are applied to the video's subtitle rendering. Inline styles within the cue text (using `<c>`) also relate to CSS classes.
* **JavaScript:** JavaScript is used to load the VTT file (often via the `<track>` element), and the browser's rendering engine uses this parser to process the file. JavaScript can also interact with the `TextTrack` API to manipulate cues and their properties.

**5. Logical Reasoning (Hypothetical Inputs and Outputs):**

We can create simple VTT examples and trace the parser's expected behavior:

* **Simple Cue:** `WEBVTT\n\n00:00:00.000 --> 00:00:05.000\nThis is a simple subtitle.`  The parser should extract a cue with the given times and text.
* **Styled Cue:** `WEBVTT\n\nSTYLE\n::cue { color: yellow; }\n\n00:00:00.000 --> 00:00:05.000\nThis is <c.highlight>yellow</c>.` The parser should create a CSS style sheet and a cue with inline styling.
* **Region:** `WEBVTT\n\nREGION\nid:region01\nwidth:50%\n\n00:00:00.000 --> 00:00:05.000 region:region01\nThis is in a region.` The parser should create a region and associate the cue with it.

**6. Common User/Programming Errors:**

Based on the parsing logic, we can identify potential errors:

* **Invalid VTT Header:**  Not starting with "WEBVTT".
* **Incorrect Timestamp Format:**  Using wrong separators (e.g., comma instead of dot for milliseconds), incorrect number of digits.
* **Missing "-->":**  Not having the separator between start and end times.
* **Invalid Settings Syntax:** Incorrectly formatted region identifiers or other cue settings.
* **Malformed HTML-like Tags in Cue Text:**  Unclosed tags, incorrect nesting.

**7. User Actions Leading to the Code:**

The most direct path is:

1. **User adds a `<video>` element to an HTML page.**
2. **User adds a `<track>` element as a child of the `<video>` element.**
3. **The `src` attribute of the `<track>` element points to a `.vtt` file.**
4. **The browser fetches the VTT file.**
5. **The browser's rendering engine identifies the file type as WebVTT.**
6. **The rendering engine instantiates a `VTTParser` object.**
7. **The content of the VTT file is passed to the `ParseBytes()` method of the `VTTParser` in chunks.**
8. **Finally, `Flush()` is called to process any remaining data.**
9. **The parsed cues are then used by the video player to display subtitles/captions.**

**Self-Correction/Refinement during thought process:**

* Initially, I might focus too much on the individual functions. It's important to step back and understand the overall *flow* of the parsing process using the state machine.
*  It's crucial to link the code elements (like `VTTTreeBuilder`) to their high-level purpose (processing cue text).
*  The prompt specifically asks about user interaction. I need to explicitly describe the steps a user takes that *trigger* this code to run, not just that the code exists.
* While the code doesn't explicitly show *error messages*, the state transitions (like going to `kBadCue`) and the validation checks within functions like `CollectTimeStamp` *imply* error handling.

By following this structured approach, analyzing the code, connecting it to web technologies, and thinking about potential use cases and errors, we can construct a comprehensive and accurate answer to the request.
好的，让我们来详细分析一下 `blink/renderer/core/html/track/vtt/vtt_parser.cc` 这个文件。

**功能概览**

`vtt_parser.cc` 文件的核心功能是**解析 WebVTT (Web Video Text Tracks) 文件**。WebVTT 是一种用于显示字幕、标题、说明文字等的文本格式，常用于 HTML5 的 `<video>` 元素。  这个解析器的主要任务是将 VTT 文件的内容转换成浏览器可以理解和使用的内部数据结构，例如 `TextTrackCue` 对象。

**具体功能分解**

1. **文件头解析 (Initial, Header 状态):**
   - 验证 VTT 文件的开头是否包含必要的 "WEBVTT" 标识符。
   - 处理文件头部的可选信息，例如注释。

2. **Region 解析 (Region 状态):**
   - 解析 `REGION` 块，提取区域的 ID 和各种设置 (如宽度、高度、定位等)。
   - 将解析出的 Region 信息存储在 `region_map_` 中，以便后续 Cue 引用。

3. **Style 解析 (Style 状态):**
   - 解析 `STYLE` 块，提取 CSS 样式规则。
   - 将这些样式规则创建为 `CSSStyleSheet` 对象，以便应用于字幕的渲染。

4. **Cue 解析 (Id, TimingsAndSettings, CueText, BadCue 状态):**
   - **识别 Cue 标识符 (Id 状态):**  解析可选的 Cue ID。
   - **解析时间和设置 (TimingsAndSettings 状态):**
     - 从一行中提取 Cue 的开始时间和结束时间戳。
     - 解析 Cue 的各种设置，例如 `position`, `line`, `size`, `align`, `vertical`, `region` 等。
   - **解析 Cue 文本内容 (CueText 状态):**
     - 读取 Cue 的文本内容，可以包含简单的 HTML 标签用于格式化 (例如 `<b>`, `<i>`, `<u>`, `<c>`, `<v>`, `<ruby>`, `<rt>`, `<lang>`) 和时间戳标签 `<timestamp>`.
     - 使用 `VTTTreeBuilder` 将 Cue 文本内容解析成一个 DOM Fragment，用于渲染。
   - **处理解析错误 (BadCue 状态):**  如果遇到无法解析的行，则进入 `BadCue` 状态，尝试跳过错误并恢复解析。

5. **数据结构创建:**
   - 创建 `TextTrackCue` 对象来表示每个解析出的字幕/标题。
   - 创建 `VTTRegion` 对象来表示解析出的区域。
   - 创建 `CSSStyleSheet` 对象来表示解析出的样式表。

6. **错误处理:**
   - 能够识别和处理一些常见的 VTT 文件格式错误。
   - 当文件无法解析时，会通知 `VTTParserClient`。

**与 JavaScript, HTML, CSS 的关系及举例说明**

1. **HTML:**
   - **`<track>` 元素:**  HTML 的 `<track>` 元素用于指定视频或音频的字幕、标题或其他时间相关的文本轨道文件。 `vtt_parser.cc` 正是用来解析通过 `<track>` 元素加载的 `.vtt` 文件。
     ```html
     <video controls>
       <source src="myvideo.mp4" type="video/mp4">
       <track src="subtitles_zh.vtt" label="Chinese" kind="subtitles" srclang="zh">
     </video>
     ```
     当浏览器遇到 `<track>` 元素并且 `src` 指向一个 `.vtt` 文件时，就会调用 `vtt_parser.cc` 来解析 `subtitles_zh.vtt` 的内容。

   - **Cue 的渲染:** 解析后的 `TextTrackCue` 对象会被用于在 `<video>` 元素上渲染字幕。`vtt_parser.cc` 中 `VTTTreeBuilder` 创建的 DOM Fragment 最终会被添加到视频的字幕显示区域。

   - **Region 的影响:** 解析出的 `VTTRegion` 对象会影响字幕的显示位置和大小。如果 Cue 指定了某个 Region，字幕就会在该 Region 内显示。

2. **CSS:**
   - **`<style>` 块:** WebVTT 文件可以包含 `<style>` 块，其中定义了 CSS 规则来样式化字幕。 `vtt_parser.cc` 负责解析这些 CSS 规则并创建 `CSSStyleSheet` 对象。
     ```vtt
     WEBVTT

     STYLE
     ::cue {
       color: yellow;
       background-color: rgba(0, 0, 0, 0.8);
     }

     ::cue(.highlight) {
       font-weight: bold;
     }

     00:00:00.000 --> 00:00:05.000
     This is <c.highlight>important</c> text.
     ```
     在这个例子中，`vtt_parser.cc` 会解析 `::cue` 和 `::cue(.highlight)` 的 CSS 规则，然后当渲染到包含 `<c.highlight>` 标签的 Cue 时，会应用相应的样式。

   - **Inline 样式 (`<c>` 标签):**  VTT 允许在 Cue 文本中使用 `<c>` 标签来应用 CSS 类。`vtt_parser.cc` 会识别这些标签并将其转换为带有相应 class 属性的 HTML 元素，然后浏览器会根据 CSS 样式表来渲染这些元素。

3. **JavaScript:**
   - **`TextTrack` API:** JavaScript 可以通过 `HTMLVideoElement.textTracks` 属性访问视频的文本轨道，并可以监听 `oncuechange` 事件来响应当前显示的 Cue 的变化。
   - **动态创建和修改 Cue:**  虽然 `vtt_parser.cc` 负责解析静态的 VTT 文件，但 JavaScript 可以使用 `TextTrack` API 动态地创建、修改和添加 `TextTrackCue` 对象。
   - **控制轨道加载和显示:** JavaScript 可以控制 `<track>` 元素的启用和禁用，从而影响 `vtt_parser.cc` 的执行时机。

**逻辑推理 (假设输入与输出)**

**假设输入 (VTT 文件内容):**

```vtt
WEBVTT

REGION
id: r1
width: 50%
lines:3

00:00:00.000 --> 00:00:05.000 region:r1
这是第一行字幕。

00:00:05.000 --> 00:00:10.000 region:r1
这是<b>第二行</b>字幕。
```

**预期输出 (内部数据结构):**

- 一个 `VTTRegion` 对象，ID 为 "r1"，宽度为 50%，最大行数为 3。
- 两个 `TextTrackCue` 对象：
    - 第一个 Cue：
        - `startTime`: 0 秒
        - `endTime`: 5 秒
        - `region`: 指向上面创建的 `VTTRegion` 对象
        - `text`: "这是第一行字幕。" (解析成包含一个 Text 节点的 DocumentFragment)
    - 第二个 Cue：
        - `startTime`: 5 秒
        - `endTime`: 10 秒
        - `region`: 指向上面创建的 `VTTRegion` 对象
        - `text`: "这是<b>第二行</b>字幕。" (解析成包含一个 Text 节点和一个加粗的 VTTElement 节点的 DocumentFragment)

**用户或编程常见的使用错误及举例说明**

1. **VTT 文件头缺失或错误:**
   - **错误输入:**
     ```
     This is not a valid VTT file.

     00:00:00.000 --> 00:00:05.000
     Subtitle text.
     ```
   - **结果:** `vtt_parser.cc` 会在 `kInitial` 状态检测到文件头不正确，调用 `client_->FileFailedToParse()`，导致字幕加载失败。

2. **时间戳格式错误:**
   - **错误输入:**
     ```vtt
     WEBVTT

     00:00,00.000 --> 00:00:05.000
     Incorrect timestamp.
     ```
   - **结果:** 在 `CollectTimingsAndSettings` 状态，`CollectTimeStamp` 函数解析失败，进入 `kBadCue` 状态，该 Cue 将被丢弃。

3. **Region ID 不存在:**
   - **错误输入:**
     ```vtt
     WEBVTT

     00:00:00.000 --> 00:00:05.000 region:nonexistent_region
     This cue references a non-existent region.
     ```
   - **结果:** 在解析 Cue 的设置时，`ParseSettings` 函数找不到 ID 为 "nonexistent_region" 的 `VTTRegion`，该 Cue 的 region 属性可能不会被正确设置或者使用默认行为。

4. **`STYLE` 块 CSS 语法错误:**
   - **错误输入:**
     ```vtt
     WEBVTT

     STYLE
     ::cue {
       color: ; /* 缺少颜色值 */
     }

     00:00:00.000 --> 00:00:05.000
     Styled text.
     ```
   - **结果:** `CSSParser::ParseSheet` 在解析 `STYLE` 块时会遇到语法错误，可能会导致整个样式块被忽略或者部分规则失效。

5. **Cue 文本中未闭合的标签:**
   - **错误输入:**
     ```vtt
     WEBVTT

     00:00:00.000 --> 00:00:05.000
     This is <b>bold text.
     ```
   - **结果:** `VTTTreeBuilder` 在构建 DOM Fragment 时，可能会尝试容错处理，但结果可能不是预期的，例如后续文本可能也会被错误地认为是粗体。

**用户操作是如何一步步到达这里的**

1. **用户在一个网页上观看包含 `<video>` 元素的视频。**
2. **网页的 HTML 中包含一个 `<track>` 元素，其 `src` 属性指向一个 `.vtt` 字幕文件。**
3. **用户的浏览器开始加载网页，包括视频和字幕文件。**
4. **当浏览器加载到 `<track>` 元素时，会发起对 `.vtt` 文件的网络请求。**
5. **下载完成后，浏览器的渲染引擎 (Blink) 会识别出这是一个 WebVTT 文件。**
6. **Blink 创建一个 `VTTParser` 对象。**
7. **`.vtt` 文件的内容被传递给 `VTTParser` 的 `ParseBytes()` 方法进行解析（可能是分块传递）。**
8. **当文件内容全部传递完毕后，`Flush()` 方法会被调用以处理剩余的数据。**
9. **`VTTParser` 内部的状态机驱动解析过程，逐行读取和分析 VTT 文件的内容。**
10. **解析出的 `TextTrackCue` 对象被添加到 `cue_list_` 中。**
11. **当视频播放到特定时间点时，浏览器会从 `cue_list_` 中找到相应的 Cue，并将其渲染到视频画面上。**

总而言之，`blink/renderer/core/html/track/vtt/vtt_parser.cc` 是 Chromium Blink 引擎中负责解析 WebVTT 字幕文件的关键组件，它连接了 HTML 的 `<track>` 元素、CSS 的样式规则和 JavaScript 的 `TextTrack` API，使得网页能够呈现丰富的视频字幕和标题。

### 提示词
```
这是目录为blink/renderer/core/html/track/vtt/vtt_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc.  All rights reserved.
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

#include "third_party/blink/renderer/core/html/track/vtt/vtt_parser.h"

#include "base/metrics/histogram_functions.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/track/text_track.h"
#include "third_party/blink/renderer/core/html/track/vtt/vtt_element.h"
#include "third_party/blink/renderer/core/html/track/vtt/vtt_region.h"
#include "third_party/blink/renderer/core/html/track/vtt/vtt_scanner.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/segmented_string.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

const unsigned kFileIdentifierLength = 6;
const unsigned kRegionIdentifierLength = 6;
const unsigned kStyleIdentifierLength = 5;

bool VTTParser::ParsePercentageValue(VTTScanner& value_scanner,
                                     double& percentage) {
  double number;
  if (!value_scanner.ScanDouble(number))
    return false;
  // '%' must be present and at the end of the setting value.
  if (!value_scanner.Scan('%'))
    return false;
  if (number < 0 || number > 100)
    return false;
  percentage = number;
  return true;
}

bool VTTParser::ParsePercentageValuePair(VTTScanner& value_scanner,
                                         char delimiter,
                                         gfx::PointF& value_pair) {
  double first_coord;
  if (!ParsePercentageValue(value_scanner, first_coord))
    return false;

  if (!value_scanner.Scan(delimiter))
    return false;

  double second_coord;
  if (!ParsePercentageValue(value_scanner, second_coord))
    return false;

  value_pair = gfx::PointF(first_coord, second_coord);
  return true;
}

VTTParser::VTTParser(VTTParserClient* client, Document& document)
    : document_(&document),
      state_(kInitial),
      decoder_(std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
          TextResourceDecoderOptions::kPlainTextContent,
          UTF8Encoding()))),
      current_start_time_(0),
      current_end_time_(0),
      current_region_(nullptr),
      client_(client),
      contains_style_block_(false) {
  UseCounter::Count(document, WebFeature::kVTTCueParser);
}

void VTTParser::GetNewCues(HeapVector<Member<TextTrackCue>>& output_cues) {
  DCHECK(output_cues.empty());
  output_cues.swap(cue_list_);
}

void VTTParser::GetNewStyleSheets(
    HeapVector<Member<CSSStyleSheet>>& output_sheets) {
  DCHECK(output_sheets.empty());
  output_sheets.swap(style_sheets_);
}

void VTTParser::ParseBytes(base::span<const char> data) {
  String text_data = decoder_->Decode(data);
  line_reader_.Append(text_data);
  Parse();
}

void VTTParser::Flush() {
  String text_data = decoder_->Flush();
  line_reader_.Append(text_data);
  line_reader_.SetEndOfStream();
  Parse();
  FlushPendingCue();
  region_map_.clear();

  base::UmaHistogramBoolean("Accessibility.VTTContainsStyleBlock",
                            contains_style_block_);
}

void VTTParser::Parse() {
  // WebVTT parser algorithm. (5.1 WebVTT file parsing.)
  // Steps 1 - 3 - Initial setup.

  String line;
  while (line_reader_.GetLine(line)) {
    switch (state_) {
      case kInitial:
        // Steps 4 - 9 - Check for a valid WebVTT signature.
        if (!HasRequiredFileIdentifier(line)) {
          if (client_)
            client_->FileFailedToParse();
          return;
        }

        state_ = kHeader;
        break;

      case kHeader:
        // Steps 11 - 14 - Collect WebVTT block
        state_ = CollectWebVTTBlock(line);
        break;

      case kRegion:
        // Collect Region settings
        state_ = CollectRegionSettings(line);
        break;

      case kStyle:
        // Collect style sheet
        state_ = CollectStyleSheet(line);
        break;

      case kId:
        // Steps 17 - 20 - Allow any number of line terminators, then initialize
        // new cue values.
        if (line.empty())
          break;

        // Step 21 - Cue creation (start a new cue).
        ResetCueValues();

        // Steps 22 - 25 - Check if this line contains an optional identifier or
        // timing data.
        state_ = CollectCueId(line);
        break;

      case kTimingsAndSettings:
        // Steps 26 - 27 - Discard current cue if the line is empty.
        if (line.empty()) {
          state_ = kId;
          break;
        }

        // Steps 28 - 29 - Collect cue timings and settings.
        state_ = CollectTimingsAndSettings(line);
        break;

      case kCueText:
        // Steps 31 - 41 - Collect the cue text, create a cue, and add it to the
        // output.
        state_ = CollectCueText(line);
        break;

      case kBadCue:
        // Steps 42 - 48 - Discard lines until an empty line or a potential
        // timing line is seen.
        state_ = IgnoreBadCue(line);
        break;
    }
  }
}

void VTTParser::FlushPendingCue() {
  DCHECK(line_reader_.IsAtEndOfStream());
  // If we're in the CueText state when we run out of data, we emit the pending
  // cue.
  if (state_ == kCueText)
    CreateNewCue();
}

bool VTTParser::HasRequiredFileIdentifier(const String& line) {
  // WebVTT parser algorithm step 6:
  // If input is more than six characters long but the first six characters
  // do not exactly equal "WEBVTT", or the seventh character is not a U+0020
  // SPACE character, a U+0009 CHARACTER TABULATION (tab) character, or a
  // U+000A LINE FEED (LF) character, then abort these steps.
  if (!line.StartsWith("WEBVTT"))
    return false;
  if (line.length() > kFileIdentifierLength) {
    UChar maybe_separator = line[kFileIdentifierLength];
    // The line reader handles the line break characters, so we don't need
    // to check for LF here.
    if (maybe_separator != kSpaceCharacter &&
        maybe_separator != kTabulationCharacter)
      return false;
  }
  return true;
}

VTTParser::ParseState VTTParser::CollectRegionSettings(const String& line) {
  // End of region block
  if (CheckAndStoreRegion(line))
    return CheckAndRecoverCue(line);

  current_region_->SetRegionSettings(line);
  return kRegion;
}

VTTParser::ParseState VTTParser::CollectStyleSheet(const String& line) {
  if (line.empty() || line.Contains("-->")) {
    auto* parser_context = MakeGarbageCollected<CSSParserContext>(
        *document_, NullURL(), true /* origin_clean */, Referrer(),
        UTF8Encoding(), ResourceFetchRestriction::kOnlyDataUrls);
    auto* style_sheet_contents =
        MakeGarbageCollected<StyleSheetContents>(parser_context);
    CSSParser::ParseSheet(
        parser_context, style_sheet_contents, current_content_.ToString(),
        CSSDeferPropertyParsing::kNo, false /* allow_import_rules */);
    auto* style_sheet =
        MakeGarbageCollected<CSSStyleSheet>(style_sheet_contents);
    style_sheet->SetConstructorDocument(*document_);
    style_sheet->SetTitle("");
    style_sheets_.push_back(style_sheet);

    return CheckAndRecoverCue(line);
  }

  if (!current_content_.empty())
    current_content_.Append('\n');
  current_content_.Append(line);

  return kStyle;
}

VTTParser::ParseState VTTParser::CollectWebVTTBlock(const String& line) {
  // collect a WebVTT block parsing. (WebVTT parser algorithm step 14)

  if (!previous_line_.Contains("-->")) {
    // If Region support is enabled.
    if (RuntimeEnabledFeatures::WebVTTRegionsEnabled() &&
        CheckAndCreateRegion(line))
      return kRegion;

    // line starts with the substring "STYLE" and remaining characters
    // zero or more U+0020 SPACE characters or U+0009 CHARACTER TABULATION
    // (tab) characters expected other than these characters it is invalid.
    if (line.StartsWith("STYLE") && StringView(line, kStyleIdentifierLength)
                                        .IsAllSpecialCharacters<IsASpace>()) {
      contains_style_block_ = true;
      current_content_.Clear();
      return kStyle;
    }
  }

  // Handle cue block.
  ParseState state = CheckAndRecoverCue(line);
  if (state != kHeader) {
    if (!previous_line_.empty() && !previous_line_.Contains("-->"))
      current_id_ = AtomicString(previous_line_);

    return state;
  }

  // store previous line for cue id.
  // length is more than 1 line clear previous_line_ and ignore line.
  if (previous_line_.empty())
    previous_line_ = line;
  else
    previous_line_ = g_empty_string;
  return state;
}

VTTParser::ParseState VTTParser::CheckAndRecoverCue(const String& line) {
  // parse cue timings and settings
  if (line.Contains("-->")) {
    ParseState state = RecoverCue(line);
    if (state != kBadCue) {
      return state;
    }
  }
  return kHeader;
}

bool VTTParser::CheckAndCreateRegion(const String& line) {
  // line starts with the substring "REGION" and remaining characters
  // zero or more U+0020 SPACE characters or U+0009 CHARACTER TABULATION
  // (tab) characters expected other than these characters it is invalid.
  if (line.StartsWith("REGION") && StringView(line, kRegionIdentifierLength)
                                       .IsAllSpecialCharacters<IsASpace>()) {
    current_region_ = VTTRegion::Create(*document_);
    return true;
  }
  return false;
}

bool VTTParser::CheckAndStoreRegion(const String& line) {
  if (!line.empty() && !line.Contains("-->"))
    return false;

  if (!current_region_->id().empty())
    region_map_.Set(current_region_->id(), current_region_);
  current_region_ = nullptr;
  return true;
}

VTTParser::ParseState VTTParser::CollectCueId(const String& line) {
  if (line.Contains("-->"))
    return CollectTimingsAndSettings(line);
  current_id_ = AtomicString(line);
  return kTimingsAndSettings;
}

VTTParser::ParseState VTTParser::CollectTimingsAndSettings(const String& line) {
  VTTScanner input(line);

  // Collect WebVTT cue timings and settings. (5.3 WebVTT cue timings and
  // settings parsing.)
  // Steps 1 - 3 - Let input be the string being parsed and position be a
  // pointer into input.
  input.SkipWhile<IsASpace>();

  // Steps 4 - 5 - Collect a WebVTT timestamp. If that fails, then abort and
  // return failure. Otherwise, let cue's text track cue start time be the
  // collected time.
  if (!CollectTimeStamp(input, current_start_time_))
    return kBadCue;
  input.SkipWhile<IsASpace>();

  // Steps 6 - 9 - If the next three characters are not "-->", abort and return
  // failure.
  if (!input.Scan("-->"))
    return kBadCue;
  input.SkipWhile<IsASpace>();

  // Steps 10 - 11 - Collect a WebVTT timestamp. If that fails, then abort and
  // return failure. Otherwise, let cue's text track cue end time be the
  // collected time.
  if (!CollectTimeStamp(input, current_end_time_))
    return kBadCue;
  input.SkipWhile<IsASpace>();

  // Step 12 - Parse the WebVTT settings for the cue (conducted in
  // TextTrackCue).
  current_settings_ = input.RestOfInputAsString();
  return kCueText;
}

VTTParser::ParseState VTTParser::CollectCueText(const String& line) {
  // Step 34.
  if (line.empty()) {
    CreateNewCue();
    return kId;
  }
  // Step 35.
  if (line.Contains("-->")) {
    // Step 39-40.
    CreateNewCue();

    // Step 41 - New iteration of the cue loop.
    return RecoverCue(line);
  }
  if (!current_content_.empty())
    current_content_.Append('\n');
  current_content_.Append(line);

  return kCueText;
}

VTTParser::ParseState VTTParser::RecoverCue(const String& line) {
  // Step 17 and 21.
  ResetCueValues();

  // Step 22.
  return CollectTimingsAndSettings(line);
}

VTTParser::ParseState VTTParser::IgnoreBadCue(const String& line) {
  if (line.empty())
    return kId;
  if (line.Contains("-->"))
    return RecoverCue(line);
  return kBadCue;
}

// A helper class for the construction of a "cue fragment" from the cue text.
class VTTTreeBuilder {
  STACK_ALLOCATED();

 public:
  explicit VTTTreeBuilder(Document& document, TextTrack* track)
      : document_(&document), track_(track) {}

  DocumentFragment* BuildFromString(const String& cue_text);

 private:
  void ConstructTreeFromToken(Document&);
  Document& GetDocument() const { return *document_; }

  VTTToken token_;
  ContainerNode* current_node_ = nullptr;
  Vector<AtomicString> language_stack_;
  Document* document_;
  TextTrack* track_;
};

DocumentFragment* VTTTreeBuilder::BuildFromString(const String& cue_text) {
  // Cue text processing based on
  // 5.4 WebVTT cue text parsing rules, and
  // 5.5 WebVTT cue text DOM construction rules

  DocumentFragment* fragment = DocumentFragment::Create(GetDocument());

  if (cue_text.empty()) {
    fragment->ParserAppendChild(Text::Create(GetDocument(), ""));
    return fragment;
  }

  current_node_ = fragment;

  VTTTokenizer tokenizer(cue_text);
  language_stack_.clear();

  while (tokenizer.NextToken(token_))
    ConstructTreeFromToken(GetDocument());

  return fragment;
}

DocumentFragment* VTTParser::CreateDocumentFragmentFromCueText(
    Document& document,
    const String& cue_text,
    TextTrack* track) {
  VTTTreeBuilder tree_builder(document, track);
  return tree_builder.BuildFromString(cue_text);
}

void VTTParser::CreateNewCue() {
  VTTCue* cue = VTTCue::Create(*document_, current_start_time_,
                               current_end_time_, current_content_.ToString());
  cue->setId(current_id_);
  cue->ParseSettings(&region_map_, current_settings_);

  cue_list_.push_back(cue);
  if (client_)
    client_->NewCuesParsed();
}

void VTTParser::ResetCueValues() {
  current_id_ = g_empty_atom;
  current_settings_ = g_empty_string;
  current_start_time_ = 0;
  current_end_time_ = 0;
  current_content_.Clear();
}

bool VTTParser::CollectTimeStamp(const String& line, double& time_stamp) {
  VTTScanner input(line);
  return CollectTimeStamp(input, time_stamp);
}

static String SerializeTimeStamp(double time_stamp) {
  uint64_t value = ClampTo<uint64_t>(time_stamp * 1000);
  unsigned milliseconds = value % 1000;
  value /= 1000;
  unsigned seconds = value % 60;
  value /= 60;
  unsigned minutes = value % 60;
  unsigned hours = static_cast<unsigned>(value / 60);
  return String::Format("%02u:%02u:%02u.%03u", hours, minutes, seconds,
                        milliseconds);
}

bool VTTParser::CollectTimeStamp(VTTScanner& input, double& time_stamp) {
  // Collect a WebVTT timestamp (5.3 WebVTT cue timings and settings parsing.)
  // Steps 1 - 4 - Initial checks, let most significant units be minutes.
  enum Mode { kMinutes, kHours };
  Mode mode = kMinutes;

  // Steps 5 - 7 - Collect a sequence of characters that are 0-9.
  // If not 2 characters or value is greater than 59, interpret as hours.
  unsigned value1;
  const size_t value1_digits = input.ScanDigits(value1);
  if (!value1_digits)
    return false;
  if (value1_digits != 2 || value1 > 59)
    mode = kHours;

  // Steps 8 - 11 - Collect the next sequence of 0-9 after ':' (must be 2
  // chars).
  unsigned value2;
  if (!input.Scan(':') || input.ScanDigits(value2) != 2)
    return false;

  // Step 12 - Detect whether this timestamp includes hours.
  unsigned value3;
  if (mode == kHours || input.Match(':')) {
    if (!input.Scan(':') || input.ScanDigits(value3) != 2)
      return false;
  } else {
    value3 = value2;
    value2 = value1;
    value1 = 0;
  }

  // Steps 13 - 17 - Collect next sequence of 0-9 after '.' (must be 3 chars).
  unsigned value4;
  if (!input.Scan('.') || input.ScanDigits(value4) != 3)
    return false;
  if (value2 > 59 || value3 > 59)
    return false;

  // Steps 18 - 19 - Calculate result.
  time_stamp = (value1 * kMinutesPerHour * kSecondsPerMinute) +
               (value2 * kSecondsPerMinute) + value3 +
               (value4 * (1 / kMsPerSecond));
  return true;
}

static VttNodeType TokenToNodeType(VTTToken& token) {
  switch (token.GetName().length()) {
    case 1:
      if (token.GetName()[0] == 'c')
        return VttNodeType::kClass;
      if (token.GetName()[0] == 'v')
        return VttNodeType::kVoice;
      if (token.GetName()[0] == 'b')
        return VttNodeType::kBold;
      if (token.GetName()[0] == 'i')
        return VttNodeType::kItalic;
      if (token.GetName()[0] == 'u')
        return VttNodeType::kUnderline;
      break;
    case 2:
      if (token.GetName()[0] == 'r' && token.GetName()[1] == 't')
        return VttNodeType::kRubyText;
      break;
    case 4:
      if (token.GetName()[0] == 'r' && token.GetName()[1] == 'u' &&
          token.GetName()[2] == 'b' && token.GetName()[3] == 'y')
        return VttNodeType::kRuby;
      if (token.GetName()[0] == 'l' && token.GetName()[1] == 'a' &&
          token.GetName()[2] == 'n' && token.GetName()[3] == 'g')
        return VttNodeType::kLanguage;
      break;
  }
  return VttNodeType::kNone;
}

void VTTTreeBuilder::ConstructTreeFromToken(Document& document) {
  // http://dev.w3.org/html5/webvtt/#webvtt-cue-text-dom-construction-rules

  switch (token_.GetType()) {
    case VTTTokenTypes::kCharacter: {
      current_node_->ParserAppendChild(
          Text::Create(document, token_.Characters()));
      break;
    }
    case VTTTokenTypes::kStartTag: {
      VttNodeType node_type = TokenToNodeType(token_);
      if (node_type == VttNodeType::kNone) {
        break;
      }

      auto* curr_vtt_element = DynamicTo<VTTElement>(current_node_);
      VttNodeType current_type = curr_vtt_element
                                     ? curr_vtt_element->GetVttNodeType()
                                     : VttNodeType::kNone;
      // <rt> is only allowed if the current node is <ruby>.
      if (node_type == VttNodeType::kRubyText &&
          current_type != VttNodeType::kRuby) {
        break;
      }

      auto* child = MakeGarbageCollected<VTTElement>(node_type, &document);
      child->SetTrack(track_);

      if (!token_.Classes().empty())
        child->setAttribute(html_names::kClassAttr, token_.Classes());

      if (node_type == VttNodeType::kVoice) {
        child->setAttribute(VTTElement::VoiceAttributeName(),
                            token_.Annotation());
      } else if (node_type == VttNodeType::kLanguage) {
        language_stack_.push_back(token_.Annotation());
        child->setAttribute(VTTElement::LangAttributeName(),
                            language_stack_.back());
      }
      if (!language_stack_.empty())
        child->SetLanguage(language_stack_.back());
      current_node_->ParserAppendChild(child);
      current_node_ = child;
      break;
    }
    case VTTTokenTypes::kEndTag: {
      VttNodeType node_type = TokenToNodeType(token_);
      if (node_type == VttNodeType::kNone) {
        break;
      }

      // The only non-VTTElement would be the DocumentFragment root. (Text
      // nodes and PIs will never appear as current_node_.)
      auto* curr_vtt_element = DynamicTo<VTTElement>(current_node_);
      if (!curr_vtt_element)
        break;

      VttNodeType current_type = curr_vtt_element->GetVttNodeType();
      bool matches_current = node_type == current_type;
      if (!matches_current) {
        // </ruby> auto-closes <rt>.
        if (current_type == VttNodeType::kRubyText &&
            node_type == VttNodeType::kRuby) {
          if (current_node_->parentNode())
            current_node_ = current_node_->parentNode();
        } else {
          break;
        }
      }
      if (node_type == VttNodeType::kLanguage) {
        language_stack_.pop_back();
      }
      if (current_node_->parentNode())
        current_node_ = current_node_->parentNode();
      break;
    }
    case VTTTokenTypes::kTimestampTag: {
      double parsed_time_stamp;
      if (VTTParser::CollectTimeStamp(token_.Characters(), parsed_time_stamp)) {
        current_node_->ParserAppendChild(
            MakeGarbageCollected<ProcessingInstruction>(
                document, "timestamp", SerializeTimeStamp(parsed_time_stamp)));
      }
      break;
    }
    default:
      break;
  }
}

void VTTParser::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(current_region_);
  visitor->Trace(client_);
  visitor->Trace(cue_list_);
  visitor->Trace(region_map_);
  visitor->Trace(style_sheets_);
}

}  // namespace blink
```