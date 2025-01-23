Response:
Let's break down the thought process for analyzing this `style_perftest.cc` file.

1. **Understand the Core Purpose:** The initial comment block is crucial. It explicitly states the file's purpose: benchmarking CSS style performance in the Blink rendering engine. Keywords like "benchmark," "style performance," "isolates style from paint," and "stable benchmarking" are key. The mention of external JSON files is also important for understanding data input.

2. **Identify Key Components and Data Flow:** Scan the `#include` directives. These reveal the core Blink components involved:
    * `core/css/...`:  Indicates interaction with CSS parsing, resolving, and style application. Specifically, `StyleResolver`, `StyleEngine`, `StyleSheetContents`, `ComputedStyle`, `StyleChangeReason`.
    * `core/dom/...`: Shows involvement with the Document Object Model (DOM), particularly `Document` and `HTMLElement`.
    * `core/frame/...`:  Suggests interaction at the frame level (`LocalFrameView`).
    * `core/loader/...`: Implies loading of resources, even though it's a mock (`NoNetworkUrlLoader`).
    * `testing/perf/...`:  Confirms this is a performance test using Chromium's testing framework.
    * `base/json/...`:  Confirms the JSON data input mentioned in the initial comment.

3. **Analyze Key Functions:** Focus on the most significant functions:
    * `StripStyleTags()`:  The name is self-explanatory. Analyze its logic – it's designed to remove `<style>` tags from HTML. The reasoning is crucial: to avoid conflicts and ensure the test uses the style sheets provided in the JSON data.
    * `LoadDumpedPage()`: This is the core loading function. It takes JSON data, parses HTML, and, importantly, parses CSS stylesheets defined within the JSON. Note the `parse_iterations` and `defer_property_parsing` command-line flags. Observe how it injects stylesheets into the `StyleEngine`.
    * `MeasureStyleForDumpedPage()`: This is the heart of the benchmark. It loads a page, then performs style calculations. Pay attention to the `recalc_iterations` flag and the measurement of `initial_style_time` and `recalc_style_time`. Crucially, it measures memory allocation related to styling (`gc_allocated_bytes`, `partition_allocated_bytes`, and optionally `computed_style_used_bytes`). The pre- and post-GC measurements are important for accurate results. The skipping logic due to missing files is also relevant.
    * `MeasureAndPrintStyleForDumpedPage()`: This function ties everything together. It calls `MeasureStyleForDumpedPage` and then uses `perf_test::PerfResultReporter` to report the collected performance metrics.
    * The `TEST(StyleCalcPerfTest, ...)` functions: These are the individual test cases, each loading a different JSON file representing a different type of webpage (video, news, etc.). The `Alexa1000` test is a special case, processing multiple pages and reporting percentiles.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The test loads HTML content from the JSON files using `setInnerHTML()`. The `StripStyleTags()` function directly manipulates HTML.
    * **CSS:**  The core purpose is CSS benchmarking. The test parses CSS from the JSON, injects it into the `StyleEngine`, and measures the time taken for initial style calculation and subsequent recalculations. Command-line flags like `--style-lazy-parsing` directly relate to CSS parsing behavior.
    * **JavaScript:** While this specific file doesn't directly execute JavaScript, the tested style calculations *are* affected by JavaScript. Dynamic changes to the DOM or CSS via JavaScript would trigger style recalculations, which this test aims to measure. The test setup itself *could* involve JavaScript if the dumped pages contained inline scripts that modified styles, although the focus is on the initial static styling.

5. **Identify Logical Inferences and Assumptions:**
    * **Assumption:** The JSON files accurately represent the structure and styles of real-world webpages.
    * **Inference:** The time taken for style calculation reflects the complexity of the CSS rules and the size of the DOM.
    * **Assumption:** Isolating style calculation from painting provides more stable and accurate performance measurements.

6. **Consider User/Programming Errors:**
    * **Incorrect JSON format:** If the JSON files are malformed, parsing will fail.
    * **Missing JSON files:** The test explicitly handles this by skipping, highlighting a common setup issue.
    * **Command-line flag errors:**  Typing incorrect or conflicting command-line flags could lead to unexpected behavior.
    * **Data inconsistency:** If the HTML and CSS in the JSON are inconsistent, it could lead to incorrect style calculations.

7. **Trace User Actions (Debugging Context):**  Think about how a developer might end up looking at this file during debugging:
    * **Performance Regression:** If style performance degrades, developers would investigate this and other related files.
    * **New CSS Feature Implementation:**  When adding new CSS features, developers might use or modify this test to measure the performance impact.
    * **Memory Leaks Related to Styling:** If there are concerns about memory usage during style calculations, this test's memory metrics would be relevant.
    * **Understanding Style Calculation:** Developers new to the Blink rendering engine might study this file to understand how style calculations are performed and measured.

8. **Structure the Explanation:** Organize the findings logically, starting with the high-level purpose and then drilling down into the details of the functions, their relationships to web technologies, and the debugging context. Use clear headings and examples to improve readability.

By following these steps, one can systematically analyze the `style_perftest.cc` file and understand its functionality, its connection to web technologies, potential issues, and its role in the development and debugging process.
这个文件 `blink/renderer/core/css/style_perftest.cc` 是 Chromium Blink 引擎中的一个性能测试文件，专门用于衡量 CSS 样式计算的性能。它通过加载预先dumped（转储）的网页数据（HTML和CSS），然后执行样式计算，并报告相关性能指标。

**功能总结:**

1. **CSS 样式性能基准测试:**  它的主要目的是创建一个稳定的环境来测试 CSS 样式计算的性能，并将其与其他渲染过程（如布局和绘制）隔离。
2. **加载预先转储的网页数据:**  它依赖于外部 JSON 文件，这些文件包含了网页的 HTML 结构和 CSS 样式表。这些 JSON 文件不是直接签入代码库的，需要单独生成。
3. **模拟样式计算过程:**  它会解析 HTML 并构建 DOM 树，然后解析 CSS 样式表，并将它们应用到 DOM 树上，进行样式计算。
4. **测量性能指标:**  它测量样式解析时间、初始样式计算时间、后续样式重新计算时间，以及样式计算过程中的内存分配情况（GC 分配和分区分配）。
5. **使用命令行参数进行配置:** 它支持使用命令行参数来控制测试行为，例如：
    * `--style-parse-iterations`: 控制 CSS 解析的迭代次数。
    * `--style-lazy-parsing`:  控制是否启用 CSS 属性的延迟解析。
    * `--style-recalc-iterations`: 控制样式重新计算的迭代次数。
    * `--parse-style-only`:  只进行 CSS 解析，不进行后续的样式计算。
    * `--measure-computed-style-memory`: 测量计算样式所使用的内存。
6. **报告测试结果:** 使用 `perf_test::PerfResultReporter` 来报告测量的性能指标，例如解析时间、计算时间、内存分配等。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**
    * **功能关系：** 该文件加载 JSON 文件中包含的 HTML 字符串，并使用 `setInnerHTML()` 方法将其解析成 DOM 树。DOM 树是样式计算的基础。
    * **举例说明：** JSON 文件可能包含以下 HTML 片段：
      ```json
      { "html": "<div><p class='text'>Hello</p></div>" }
      ```
      `LoadDumpedPage` 函数会加载这个 HTML 字符串并创建相应的 DOM 结构。
    * **逻辑推理 (假设输入与输出)：**
        * **假设输入:** 一个包含复杂嵌套结构的 HTML 字符串。
        * **输出:**  `setInnerHTML()` 会根据 HTML 字符串构建相应的 DOM 树。更复杂的结构通常意味着更长的解析时间，但这个文件主要关注 *样式* 解析和计算，而不是 HTML 解析本身。

* **CSS:**
    * **功能关系：** 该文件是专门用来测试 CSS 样式性能的。它解析 JSON 文件中定义的 CSS 样式表，并将其应用到 DOM 树上。它测量解析 CSS 所需的时间，以及将这些样式应用到元素上进行计算的时间。
    * **举例说明：** JSON 文件可能包含以下 CSS 样式表：
      ```json
      {
        "stylesheets": [
          { "text": ".text { color: red; font-size: 16px; }", "type": "author" }
        ]
      }
      ```
      `LoadDumpedPage` 函数会解析这段 CSS 代码，并创建一个 `StyleSheetContents` 对象。`engine.InjectSheet()` 将这些样式表注入到样式引擎中。
    * **逻辑推理 (假设输入与输出)：**
        * **假设输入:** 包含大量 CSS 选择器和属性的 CSS 样式表。
        * **输出:** 更长的 CSS 解析时间（通过 `parse_time` 测量）以及更长的初始样式计算时间（通过 `initial_style_time` 测量），因为需要匹配更多的选择器并将更多的样式属性应用到 DOM 元素上。

* **JavaScript:**
    * **功能关系：**  虽然这个文件本身不执行 JavaScript 代码，但它测试的样式计算性能会受到 JavaScript 的影响。例如，JavaScript 可以动态地修改 DOM 结构或元素的样式，从而触发样式的重新计算。这个测试可以帮助衡量这些重新计算的性能。
    * **举例说明：** 假设 JSON 中加载的 HTML 包含一些内联的 JavaScript，或者在加载后，外部 JavaScript 修改了元素的 class 属性，这会导致浏览器重新计算受影响元素的样式。`MeasureStyleForDumpedPage` 函数中的 `page->GetDocument().UpdateStyleAndLayoutTreeForThisDocument()`  会执行这个重新计算过程。
    * **逻辑推理 (假设输入与输出)：**
        * **假设输入:**  一个网页，其 JavaScript 代码在初始加载后会频繁修改元素的 class 属性。
        * **输出:** 更长的样式重新计算时间（通过 `recalc_style_time` 测量），因为每次 class 属性的修改都会触发样式的重新计算。

**用户或编程常见的使用错误：**

1. **缺少或路径错误的 JSON 数据文件:**  该测试依赖于外部 JSON 文件。如果这些文件不存在，或者路径配置不正确，测试将会跳过。错误信息会提示文件无法读取。
   * **举例：**  用户在运行测试时忘记下载或放置必要的 `video.json`, `extension.json` 等文件到正确的位置。
2. **命令行参数使用错误:**  用户可能输入了错误的命令行参数，或者参数之间存在冲突。
   * **举例：**  用户输入了 `--style-parse-iterations abc`，导致程序无法将 "abc" 转换为整数。
3. **环境配置问题:**  测试可能依赖特定的环境配置，例如某些库的版本或依赖项。如果环境配置不正确，测试可能无法正常运行。
4. **修改了测试代码但未更新对应的 JSON 数据:** 如果测试代码被修改，例如引入了新的 CSS 特性，但没有更新用于测试的 JSON 数据以包含相关场景，那么测试结果可能无法反映真实情况。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **性能回归分析:**  当 Chromium 的性能监控系统检测到 CSS 样式计算的性能出现下降（性能回归）时，开发人员可能会被分配到调查此事。
2. **定位到 CSS 模块:**  根据性能回归的指标，开发人员会初步判断问题可能出在 CSS 相关的模块。
3. **查看性能测试:**  为了更精细地分析 CSS 性能，开发人员会查看 `blink/renderer/core/css/` 目录下与性能测试相关的代码，找到 `style_perftest.cc`。
4. **运行本地测试:** 开发人员会在本地构建 Chromium 并运行相关的性能测试，例如：
   ```bash
   ./out/Release/blink_tests --gtest_filter=StyleCalcPerfTest.*
   ```
5. **分析测试结果:**  开发人员会查看测试输出的性能指标，例如 `ParseTime`, `InitialCalcTime`, `RecalcTime`, `GCAllocated` 等，以确定具体的性能瓶颈。
6. **修改代码并重新测试:**  如果发现某个测试用例的性能明显下降，开发人员可能会查看该测试用例对应的 JSON 文件，分析其 HTML 和 CSS 结构，并尝试修改 Blink 引擎中的 CSS 相关代码来优化性能。修改后，会重新运行测试以验证优化效果。
7. **使用 Profiler:**  为了更深入地了解性能瓶颈，开发人员可能会使用性能分析工具（Profiler）来分析 `style_perftest.cc` 运行时的函数调用栈和耗时情况。这可以帮助定位到具体的性能热点函数。
8. **调试特定场景:**  如果性能回归与特定类型的网页有关，开发人员可能会尝试创建一个类似的 JSON 数据文件，并在 `style_perftest.cc` 中添加一个新的测试用例来针对性地进行调试。
9. **查看代码提交历史:**  如果性能回归发生在最近的代码变更之后，开发人员会查看相关的代码提交历史，找出可能导致性能下降的 commit，并分析其影响。

总而言之，`style_perftest.cc` 是 Blink 引擎中用于持续监控和优化 CSS 样式计算性能的关键工具。开发人员会通过运行和分析这个文件中的测试用例，来发现性能问题，验证优化效果，并确保浏览器的渲染性能。

### 提示词
```
这是目录为blink/renderer/core/css/style_perftest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A benchmark to verify style performance (and also hooks into layout,
// but not generally layout itself). This isolates style from paint etc.,
// for more stable benchmarking and profiling. Note that this test
// depends on external JSON files with stored web pages, which are
// not yet checked in. The tests will be skipped if you don't have the
// files available.

#include <string_view>

#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/json/json_reader.h"
#include "testing/perf/perf_result_reporter.h"
#include "testing/perf/perf_test.h"
#include "third_party/blink/renderer/core/css/container_query_data.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_recalc_change.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/no_network_url_loader.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/process_heap.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {

// The HTML left by the dumper script will contain any <style> tags that were
// in the DOM, which will be interpreted by setInnerHTML() and converted to
// style sheets. However, we already have our own canonical list of sheets
// (from the JSON) that we want to use. Keeping both will make for duplicated
// rules, enabling rules and sheets that have since been deleted
// (occasionally even things like “display: none !important”) and so on.
// Thus, as a kludge, we strip all <style> tags from the HTML here before
// parsing.
static WTF::String StripStyleTags(const WTF::String& html) {
  StringBuilder stripped_html;
  wtf_size_t pos = 0;
  for (;;) {
    wtf_size_t style_start =
        html.FindIgnoringCase("<style", pos);  // Allow <style id=" etc.
    if (style_start == kNotFound) {
      // No more <style> tags, so append the rest of the string.
      stripped_html.Append(html.Substring(pos, html.length() - pos));
      break;
    }
    // Bail out if it's not “<style>” or “<style ”; it's probably
    // a false positive then.
    if (style_start + 6 >= html.length() ||
        (html[style_start + 6] != ' ' && html[style_start + 6] != '>')) {
      stripped_html.Append(html.Substring(pos, style_start - pos));
      pos = style_start + 6;
      continue;
    }
    wtf_size_t style_end = html.FindIgnoringCase("</style>", style_start);
    if (style_end == kNotFound) {
      LOG(FATAL) << "Mismatched <style> tag";
    }
    stripped_html.Append(html.Substring(pos, style_start - pos));
    pos = style_end + 8;
  }
  return stripped_html.ToString();
}

static std::unique_ptr<DummyPageHolder> LoadDumpedPage(
    const base::Value::Dict& dict,
    base::TimeDelta& parse_time,
    perf_test::PerfResultReporter* reporter) {
  const std::string parse_iterations_str =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          "style-parse-iterations");
  int parse_iterations =
      parse_iterations_str.empty() ? 1 : stoi(parse_iterations_str);

  const CSSDeferPropertyParsing defer_property_parsing =
      base::CommandLine::ForCurrentProcess()->HasSwitch("style-lazy-parsing")
          ? CSSDeferPropertyParsing::kYes
          : CSSDeferPropertyParsing::kNo;

  auto page = std::make_unique<DummyPageHolder>(
      gfx::Size(800, 600), nullptr,
      MakeGarbageCollected<NoNetworkLocalFrameClient>());
  page->GetDocument().SetCompatibilityMode(Document::kNoQuirksMode);
  page->GetPage().SetDefaultPageScaleLimits(1, 4);

  Document& document = page->GetDocument();
  StyleEngine& engine = document.GetStyleEngine();
  document.documentElement()->setInnerHTML(
      StripStyleTags(WTF::String(*dict.FindString("html"))),
      ASSERT_NO_EXCEPTION);

  int num_sheets = 0;
  int num_bytes = 0;

  base::ElapsedTimer parse_timer;
  for (const base::Value& sheet_json : *dict.FindList("stylesheets")) {
    const base::Value::Dict& sheet_dict = sheet_json.GetDict();
    auto* sheet = MakeGarbageCollected<StyleSheetContents>(
        MakeGarbageCollected<CSSParserContext>(document));

    for (int i = 0; i < parse_iterations; ++i) {
      sheet->ParseString(WTF::String(*sheet_dict.FindString("text")),
                         /*allow_import_rules=*/true, defer_property_parsing);
    }
    if (*sheet_dict.FindString("type") == "user") {
      engine.InjectSheet(g_empty_atom, sheet, WebCssOrigin::kUser);
    } else {
      engine.InjectSheet(g_empty_atom, sheet, WebCssOrigin::kAuthor);
    }
    ++num_sheets;
    num_bytes += sheet_dict.FindString("text")->size();
  }
  parse_time = parse_timer.Elapsed();

  if (reporter) {
    reporter->RegisterFyiMetric("NumSheets", "");
    reporter->AddResult("NumSheets", static_cast<double>(num_sheets));

    reporter->RegisterFyiMetric("SheetSize", "kB");
    reporter->AddResult("SheetSize", static_cast<double>(num_bytes / 1024));

    reporter->RegisterImportantMetric("ParseTime", "us");
    reporter->AddResult("ParseTime", parse_time);
  }

  return page;
}

struct StylePerfResult {
  bool skipped = false;
  base::TimeDelta parse_time;
  base::TimeDelta initial_style_time;
  base::TimeDelta recalc_style_time;
  int64_t gc_allocated_bytes;
  int64_t partition_allocated_bytes;  // May be negative due to bugs.

  // Part of gc_allocated_bytes, but much more precise. Only enabled if
  // --measure-computed-style-memory is set -- and if so, gc_allocated_bytes
  // is going to be much higher due to the extra allocated objects used for
  // diffing.
  int64_t computed_style_used_bytes;
};

static StylePerfResult MeasureStyleForDumpedPage(
    const char* filename,
    bool parse_only,
    perf_test::PerfResultReporter* reporter) {
  StylePerfResult result;

  // Running more than once is useful for profiling. (If this flag does not
  // exist, it will return the empty string.)
  const std::string recalc_iterations_str =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          "style-recalc-iterations");
  int recalc_iterations =
      recalc_iterations_str.empty() ? 1 : stoi(recalc_iterations_str);

  const bool measure_computed_style_memory =
      base::CommandLine::ForCurrentProcess()->HasSwitch(
          "measure-computed-style-memory");

  // Do a forced GC run before we start loading anything, so that we have
  // a more stable baseline. Note that even with this, the GC deltas tend to
  // be different depending on what other tests that run before, so if you want
  // the more consistent memory numbers, you'll need to run only a single test
  // only (e.g. --gtest_filter=StyleCalcPerfTest.Video).
  ThreadState::Current()->CollectAllGarbageForTesting();

  size_t orig_gc_allocated_bytes =
      blink::ProcessHeap::TotalAllocatedObjectSize();
  size_t orig_partition_allocated_bytes =
      WTF::Partitions::TotalSizeOfCommittedPages();

  std::unique_ptr<DummyPageHolder> page;

  {
    std::optional<Vector<char>> serialized =
        test::ReadFromFile(test::StylePerfTestDataPath(filename));
    if (!serialized) {
      // Some test data is very large and needs to be downloaded separately,
      // so it may not always be present. Do not fail, but report the test as
      // skipped.
      result.skipped = true;
      return result;
    }
    std::optional<base::Value> json =
        base::JSONReader::Read(base::as_string_view(*serialized));
    CHECK(json.has_value());
    page = LoadDumpedPage(json->GetDict(), result.parse_time, reporter);
  }

  page->GetDocument()
      .GetStyleEngine()
      .GetStyleResolver()
      .SetCountComputedStyleBytes(measure_computed_style_memory);

  if (!parse_only) {
    {
      base::ElapsedTimer style_timer;
      for (int i = 0; i < recalc_iterations; ++i) {
        page->GetDocument().UpdateStyleAndLayoutTreeForThisDocument();
        if (i != recalc_iterations - 1) {
          page->GetDocument().GetStyleEngine().MarkAllElementsForStyleRecalc(
              StyleChangeReasonForTracing::Create("test"));
        }
      }
      result.initial_style_time = style_timer.Elapsed();
    }

    page->GetDocument().GetStyleEngine().MarkAllElementsForStyleRecalc(
        StyleChangeReasonForTracing::Create("test"));

    {
      base::ElapsedTimer style_timer;
      page->GetDocument().UpdateStyleAndLayoutTreeForThisDocument();
      result.recalc_style_time = style_timer.Elapsed();
    }
  }

  // Loading the document may have posted tasks, which can hold on to memory.
  // Run them now, to make sure they don't leak or otherwise skew the
  // statistics.
  test::RunPendingTasks();

  size_t gc_allocated_bytes = blink::ProcessHeap::TotalAllocatedObjectSize();
  size_t partition_allocated_bytes =
      WTF::Partitions::TotalSizeOfCommittedPages();

  result.gc_allocated_bytes = gc_allocated_bytes - orig_gc_allocated_bytes;
  result.partition_allocated_bytes =
      partition_allocated_bytes - orig_partition_allocated_bytes;
  if (measure_computed_style_memory) {
    result.computed_style_used_bytes = page->GetDocument()
                                           .GetStyleEngine()
                                           .GetStyleResolver()
                                           .GetComputedStyleBytesUsed();
  }

  return result;
}

static void MeasureAndPrintStyleForDumpedPage(const char* filename,
                                              const char* label) {
  auto reporter = perf_test::PerfResultReporter("BlinkStyle", label);
  const bool parse_only =
      base::CommandLine::ForCurrentProcess()->HasSwitch("parse-style-only");

  StylePerfResult result =
      MeasureStyleForDumpedPage(filename, parse_only, &reporter);
  if (result.skipped) {
    char msg[256];
    snprintf(msg, sizeof(msg), "Skipping %s test because %s could not be read",
             label, filename);
    GTEST_SKIP_(msg);
  }

  if (!parse_only) {
    reporter.RegisterImportantMetric("InitialCalcTime", "us");
    reporter.AddResult("InitialCalcTime", result.initial_style_time);

    reporter.RegisterImportantMetric("RecalcTime", "us");
    reporter.AddResult("RecalcTime", result.recalc_style_time);
  }

  if (result.computed_style_used_bytes > 0) {
    reporter.RegisterImportantMetric("ComputedStyleUsed", "kB");
    reporter.AddResult(
        "ComputedStyleUsed",
        static_cast<size_t>(result.computed_style_used_bytes) / 1024);

    // Don't print GCAllocated if we measured ComputedStyle; it causes
    // much more GC churn, which will skew the metrics.
  } else {
    reporter.RegisterImportantMetric("GCAllocated", "kB");
    reporter.AddResult("GCAllocated",
                       static_cast<size_t>(result.gc_allocated_bytes) / 1024);
  }

  reporter.RegisterImportantMetric("PartitionAllocated", "kB");
  reporter.AddResult(
      "PartitionAllocated",
      static_cast<size_t>(result.partition_allocated_bytes) / 1024);
}

TEST(StyleCalcPerfTest, Video) {
  MeasureAndPrintStyleForDumpedPage("video.json", "Video");
}

TEST(StyleCalcPerfTest, Extension) {
  MeasureAndPrintStyleForDumpedPage("extension.json", "Extension");
}

TEST(StyleCalcPerfTest, News) {
  MeasureAndPrintStyleForDumpedPage("news.json", "News");
}

TEST(StyleCalcPerfTest, ECommerce) {
  MeasureAndPrintStyleForDumpedPage("ecommerce.json", "ECommerce");
}

TEST(StyleCalcPerfTest, Social1) {
  MeasureAndPrintStyleForDumpedPage("social1.json", "Social1");
}

TEST(StyleCalcPerfTest, Social2) {
  MeasureAndPrintStyleForDumpedPage("social2.json", "Social2");
}

TEST(StyleCalcPerfTest, Encyclopedia) {
  MeasureAndPrintStyleForDumpedPage("encyclopedia.json", "Encyclopedia");
}

TEST(StyleCalcPerfTest, Sports) {
  MeasureAndPrintStyleForDumpedPage("sports.json", "Sports");
}

TEST(StyleCalcPerfTest, Search) {
  MeasureAndPrintStyleForDumpedPage("search.json", "Search");
}

// The data set for this test is not checked in, so if you want to measure it,
// you will need to recreate it yourself. You can do so using the script in
//
//   third_party/blink/renderer/core/css/scripts/style_perftest_snap_page
//
// And the URL set to use is the top 1k URLs from
//
//   tools/perf/page_sets/alexa1-10000-urls.json
TEST(StyleCalcPerfTest, Alexa1000) {
  std::vector<StylePerfResult> results;
  const bool parse_only =
      base::CommandLine::ForCurrentProcess()->HasSwitch("parse-style-only");

  for (int i = 1; i <= 1000; ++i) {
    char filename[256];
    snprintf(filename, sizeof(filename), "alexa%04d.json", i);
    StylePerfResult result =
        MeasureStyleForDumpedPage(filename, parse_only, /*reporter=*/nullptr);
    if (!result.skipped) {
      results.push_back(result);
    }
    if (i % 100 == 0) {
      LOG(INFO) << "Benchmarked " << results.size() << " pages, skipped "
                << (i - results.size()) << "...";
    }
    if (i == 10 && results.empty()) {
      LOG(INFO) << "The Alexa 1k test set has not been dumped "
                << "(tried the first 10), skipping it.";
      return;
    }
  }

  auto reporter = perf_test::PerfResultReporter("BlinkStyle", "Alexa1000");
  for (double percentile : {0.5, 0.9, 0.99}) {
    char label[256];
    size_t pos = std::min<size_t>(lrint(results.size() * percentile),
                                  results.size() - 1);

    std::nth_element(results.begin(), results.begin() + pos, results.end(),
                     [](const StylePerfResult& a, const StylePerfResult& b) {
                       return a.parse_time < b.parse_time;
                     });
    snprintf(label, sizeof(label), "ParseTime%.0fthPercentile",
             percentile * 100.0);
    reporter.RegisterImportantMetric(label, "us");
    reporter.AddResult(label, results[pos].parse_time);

    if (!parse_only) {
      std::nth_element(results.begin(), results.begin() + pos, results.end(),
                       [](const StylePerfResult& a, const StylePerfResult& b) {
                         return a.initial_style_time < b.initial_style_time;
                       });
      snprintf(label, sizeof(label), "InitialCalcTime%.0fthPercentile",
               percentile * 100.0);
      reporter.RegisterImportantMetric(label, "us");
      reporter.AddResult(label, results[pos].initial_style_time);

      std::nth_element(results.begin(), results.begin() + pos, results.end(),
                       [](const StylePerfResult& a, const StylePerfResult& b) {
                         return a.recalc_style_time < b.recalc_style_time;
                       });
      snprintf(label, sizeof(label), "RecalcTime%.0fthPercentile",
               percentile * 100.0);
      reporter.RegisterImportantMetric(label, "us");
      reporter.AddResult(label, results[pos].recalc_style_time);
    }

    std::nth_element(results.begin(), results.begin() + pos, results.end(),
                     [](const StylePerfResult& a, const StylePerfResult& b) {
                       return a.gc_allocated_bytes < b.gc_allocated_bytes;
                     });
    snprintf(label, sizeof(label), "GCAllocated%.0fthPercentile",
             percentile * 100.0);
    reporter.RegisterImportantMetric(label, "kB");
    reporter.AddResult(
        label, static_cast<size_t>(results[pos].gc_allocated_bytes) / 1024);

    std::nth_element(results.begin(), results.begin() + pos, results.end(),
                     [](const StylePerfResult& a, const StylePerfResult& b) {
                       return a.partition_allocated_bytes <
                              b.partition_allocated_bytes;
                     });
    snprintf(label, sizeof(label), "PartitionAllocated%.0fthPercentile",
             percentile * 100.0);
    reporter.RegisterImportantMetric(label, "kB");
    reporter.AddResult(
        label,
        static_cast<size_t>(results[pos].partition_allocated_bytes) / 1024);
  }
}

}  // namespace blink
```