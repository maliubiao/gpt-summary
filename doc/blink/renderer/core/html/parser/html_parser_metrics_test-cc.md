Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Scan and Identification of Key Components:**

The first step is to quickly read through the code, looking for familiar patterns and keywords. This immediately reveals:

* **Includes:** `third_party/blink/renderer/core/html/parser/html_parser_metrics.h`, `testing/gtest/include/gtest/gtest.h`, `base/test/metrics/histogram_tester.h`, `components/ukm/test_ukm_recorder.h`. These strongly suggest this code is about testing the `HTMLParserMetrics` class and how it interacts with Chromium's metrics and UKM (User Keyed Metrics) systems.
* **Namespace:** `blink`. This confirms it's part of the Blink rendering engine.
* **Test Class:** `HTMLMetricsTest` inheriting from `testing::Test`. This is standard Google Test setup.
* **Helper Class:** `frame_test_helpers::WebViewHelper`. This indicates the tests involve loading and manipulating web pages within a simulated browser environment.
* **Test Functions:** `TEST_F(HTMLMetricsTest, ...)` blocks. Each of these tests a specific aspect of `HTMLParserMetrics`.
* **`base::HistogramTester`:** Used to verify that specific histograms are recorded with expected values.
* **`ukm::TestUkmRecorder`:** Used to verify that specific UKM events and metrics are recorded.
* **`LoadHTML` function:**  Clearly used to load HTML content into the test environment.

**2. Understanding the Purpose of `HTMLParserMetrics` (based on the tests):**

By looking at the names of the histograms and UKM metrics being tested, we can infer the purpose of `HTMLParserMetrics`:

* **ChunkCount:**  The number of chunks the HTML parser processes.
* **ParsingTimeMax/Min/Total:**  Metrics related to the time spent parsing HTML.
* **TokensParsedMax/Min/Average/Total:** Metrics related to the number of HTML tokens parsed.
* **YieldedTimeMax/Min/Average:** Metrics related to how long the parser "yields" or pauses its execution (likely to allow other browser tasks to run).
* **InputCharacterCount:** The number of characters in the HTML input.

Therefore, `HTMLParserMetrics` is responsible for collecting performance data about the HTML parsing process.

**3. Analyzing Individual Tests and Their Functionality:**

Now, examine each test function in detail:

* **`ReportSingleChunk`:**  Loads a simple HTML snippet and checks that the expected histograms are recorded with the correct counts and values for a single parsing "chunk."  The key observation is the expectation that yield times are *not* reported for a single chunk.
* **`HistogramReportsTwoChunks`:** Loads a larger HTML snippet designed to cause the parser to yield (indicated by the comment about token count). It verifies that histograms are recorded and attempts to check for two chunks (though the comment indicates potential flakiness/changes in yielding behavior). This test specifically looks at scenarios where parsing is broken into multiple steps.
* **`UkmStoresValuesCorrectly`:** This test doesn't load actual HTML. Instead, it directly interacts with the `HTMLParserMetrics` object, simulating parsing events by calling `AddChunk` and `AddYieldInterval`. It then verifies that the accumulated metrics are correctly stored in the UKM system. This is a unit test focused on the internal logic of `HTMLParserMetrics`.

**4. Identifying Relationships with Web Technologies (HTML, CSS, JavaScript):**

* **HTML:** The most direct relationship. The class being tested is *specifically* for parsing HTML. The tests load HTML strings.
* **CSS:** While not directly measured, the HTML parser is responsible for identifying `<link>` tags that load CSS and triggering the CSS parsing process. Therefore, the performance of HTML parsing can indirectly impact CSS loading and rendering. The tests themselves don't directly involve CSS.
* **JavaScript:** The tests show yielding behavior, which is often related to allowing JavaScript to execute or preventing the browser from becoming unresponsive during long parsing operations. The `<script>` tag in the "TwoChunks" test is likely a yield point. Again, the tests don't directly execute JavaScript.

**5. Inferring Logic and Providing Examples (Hypothetical Inputs/Outputs):**

* **Chunking Logic:** The existence of `AddChunk` and the tests with multiple chunks suggests the parser processes HTML in segments. The "TwoChunks" test attempts to verify this.
* **Yielding Logic:** The `AddYieldInterval` method and the "TwoChunks" test clearly indicate the parser can pause its work. The comment in "TwoChunks" hints that the decision to yield might be based on the number of tokens processed.

**Hypothetical Input/Output Example:**

* **Input HTML:** `"<p>Hello</p><script>console.log('hi');</script><p>World</p>"`
* **Possible Output (simplified):**
    * **Chunk 1:** Parses `<p>Hello</p>`, `ParsingTime: 5ms`, `TokensParsed: 3`
    * **Yield:** `YieldedTime: 2ms` (before encountering the script)
    * **Chunk 2:** Parses `<script>...</script>`, `ParsingTime: 3ms`, `TokensParsed: 4`
    * **Chunk 3:** Parses `<p>World</p>`, `ParsingTime: 4ms`, `TokensParsed: 3`
    * **Final Metrics:** `ChunkCount: 3`, `ParsingTimeMax: 5ms`, `ParsingTimeMin: 3ms`, etc.

**6. Identifying Potential Usage Errors:**

The tests themselves don't reveal typical *user* errors (as users don't directly interact with this low-level code). However, they highlight potential *programming* errors or misunderstandings in how to use or interpret the `HTMLParserMetrics` class:

* **Incorrectly assuming single-chunk parsing:** The `ReportSingleChunk` test emphasizes that yield times aren't recorded for single chunks. A programmer might mistakenly expect yield metrics even when the parsing happens quickly.
* **Misunderstanding the yielding mechanism:** The comments in `HistogramReportsTwoChunks` show that the yielding behavior is tied to internal implementation details (like the number of tokens). Relying on a specific number of chunks without understanding the underlying logic could lead to brittle tests or incorrect assumptions about performance.
* **Forgetting to call `ReportMetricsAtParseEnd()`:** The `UkmStoresValuesCorrectly` test demonstrates that metrics are only reported when this method is called. Failing to do so would result in no data being recorded.

**7. Refining and Structuring the Explanation:**

Finally, organize the collected information into a clear and structured explanation, using headings and bullet points for readability. Provide concrete examples and connect the code to the broader context of web development.
这个C++源代码文件 `html_parser_metrics_test.cc` 的主要功能是**测试 Blink 渲染引擎中 `HTMLParserMetrics` 类的功能**。`HTMLParserMetrics` 类负责收集和报告 HTML 解析过程中的各种性能指标。

具体来说，这个测试文件旨在验证以下几点：

1. **统计 HTML 解析的块数 (ChunkCount):**  HTML 解析器可能将大型 HTML 文档分成多个块进行处理，以避免阻塞主线程。测试会验证是否正确记录了处理的块数。
2. **测量 HTML 解析的时间 (ParsingTime):**  测试会测量每个解析块的最大、最小和总解析时间，以及总体解析时间。
3. **统计解析的 Token 数量 (TokensParsed):**  HTML 解析器会将 HTML 文本分解成一个个的 Token。测试会统计每个解析块的最大、最小、平均和总 Token 数量。
4. **测量 Yield 的时间 (YieldedTime):** 为了防止长时间的解析阻塞主线程，HTML 解析器可能会在处理过程中 Yield (让出控制权)。测试会测量 Yield 的最大、最小和平均时间。
5. **统计输入的字符数量 (InputCharacterCount):**  记录被解析的 HTML 字符串的字符数量。
6. **向 UKM (User Keyed Metrics) 正确报告指标:** UKM 是 Chromium 用于收集用户性能数据的系统。测试会验证 `HTMLParserMetrics` 是否将收集到的指标正确地写入 UKM。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关系到 **HTML** 的功能。`HTMLParserMetrics` 监控的是 **HTML 解析器**的性能。HTML 解析是浏览器渲染网页的第一步，它将 HTML 标记转换为浏览器可以理解的 DOM 树。

* **HTML 举例：**  测试用例中 `LoadHTML(R"HTML(<div></div>)HTML");` 和 `LoadHTML(R"HTML(<head></head><div>...</div>)HTML");`  直接加载 HTML 字符串进行解析，并验证解析过程的指标。

虽然这个测试文件本身不直接涉及 JavaScript 和 CSS 的执行，但 HTML 解析是加载和执行它们的基础：

* **JavaScript 关系：**  HTML 解析器会识别 `<script>` 标签，并触发 JavaScript 的加载和执行。解析过程中的 Yielding 机制部分原因是为了防止长时间的 JavaScript 执行阻塞渲染。在 `HistogramReportsTwoChunks` 测试中，使用了大量的 `<div>` 标签，目的是让解析器处理足够多的 Token 后，可能会因为遇到 `<script>` 标签或其他条件而 Yield。
* **CSS 关系：**  HTML 解析器会识别 `<link>` 标签引入的 CSS 文件或 `<style>` 标签内的 CSS 代码，并触发 CSS 的解析和应用。虽然测试本身没有直接测试 CSS 解析，但 HTML 解析的效率会影响到 CSS 资源的发现和加载，从而间接影响 CSS 的渲染性能。

**逻辑推理与假设输入输出：**

**假设输入 (基于 `UkmStoresValuesCorrectly` 测试)：**

模拟了三次 HTML 解析的 "chunk" 和两次 "yield"：

* **Chunk 1:**
    * 解析时间: 20 微秒
    * 解析的 Token 数: 50
* **Yield 1:**
    * Yield 时间: 80 微秒
* **Chunk 2:**
    * 解析时间: 10 微秒
    * 解析的 Token 数: 40
* **Yield 2:**
    * Yield 时间: 70 微秒
* **Chunk 3:**
    * 解析时间: 30 微秒
    * 解析的 Token 数: 60

**预期输出 (基于 `UkmStoresValuesCorrectly` 测试的断言)：**

当调用 `ReportMetricsAtParseEnd()` 后，UKM 应该记录以下指标：

* `ChunkCount`: 3
* `ParsingTimeMax`: 30 微秒
* `ParsingTimeMin`: 10 微秒
* `ParsingTimeTotal`: 60 微秒 (20 + 10 + 30)
* `TokensParsedMax`: 60
* `TokensParsedMin`: 40
* `TokensParsedAverage`: 50 ((50 + 40 + 60) / 3)
* `TokensParsedTotal`: 150 (50 + 40 + 60)
* `YieldedTimeMax`: 80 微秒
* `YieldedTimeMin`: 70 微秒
* `YieldedTimeAverage`: 75 微秒 ((80 + 70) / 2)

**用户或编程常见的使用错误：**

虽然用户不会直接使用 `HTMLParserMetrics` 类，但开发 Chromium 的工程师在使用或测试相关功能时可能会犯以下错误：

1. **假设单次解析完成，而没有考虑 Chunk 的概念：**  `HTMLParserMetrics` 跟踪的是分块解析的指标。如果开发者假设 HTML 解析总是单次完成，可能会错误地理解或使用这些指标。例如，在只有一个解析块的情况下，Yield 的时间是不应该被报告的 (`ReportSingleChunk` 测试验证了这一点)。

2. **错误地理解 Yield 的触发条件：**  开发者可能不清楚 HTML 解析器何时会 Yield。在 `HistogramReportsTwoChunks` 测试中，通过插入大量的 `<div>` 标签来模拟需要 Yield 的场景。如果对 Yield 的理解有误，可能会导致测试用例不稳定或对性能瓶颈的判断失误。

3. **没有在解析结束后调用 `ReportMetricsAtParseEnd()`：**  `UkmStoresValuesCorrectly` 测试明确了只有调用 `ReportMetricsAtParseEnd()` 后，收集到的指标才会被记录到 UKM。如果忘记调用此方法，将无法获取到 HTML 解析的性能数据。

4. **在没有高精度时钟的系统上运行测试：**  测试用例中使用了 `base::TimeTicks::IsHighResolution()` 来检查系统是否支持高精度时钟。如果系统不支持，测试会直接返回，因为时间相关的指标可能会不准确。开发者需要在支持高精度时钟的环境下运行这些测试，以确保结果的可靠性。

总而言之，`html_parser_metrics_test.cc` 通过各种测试用例，确保 `HTMLParserMetrics` 类能够准确地收集和报告 HTML 解析过程中的关键性能指标，这对于理解和优化 Blink 引擎的渲染性能至关重要。

### 提示词
```
这是目录为blink/renderer/core/html/parser/html_parser_metrics_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/parser/html_parser_metrics.h"

#include "base/test/metrics/histogram_tester.h"
#include "base/test/test_mock_time_task_runner.h"
#include "build/build_config.h"
#include "components/ukm/test_ukm_recorder.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {

class HTMLMetricsTest : public testing::Test {
 public:
  HTMLMetricsTest() {
    helper_.Initialize(nullptr, nullptr, nullptr);
    // TODO(crbug.com/1329535): Remove if threaded preload scanner doesn't
    // launch.
    // Turn off preload scanning since it can mess with parser yield logic.
    helper_.LocalMainFrame()
        ->GetFrame()
        ->GetDocument()
        ->GetSettings()
        ->SetDoHtmlPreloadScanning(false);
  }

  ~HTMLMetricsTest() override = default;

  void SetUp() override {}

  void TearDown() override {}

  void LoadHTML(const std::string& html) {
    frame_test_helpers::LoadHTMLString(
        helper_.GetWebView()->MainFrameImpl(), html,
        url_test_helpers::ToKURL("https://www.foo.com/"));
  }

 protected:
  test::TaskEnvironment task_environment_;
  frame_test_helpers::WebViewHelper helper_;
};

// https://crbug.com/1222653
TEST_F(HTMLMetricsTest, DISABLED_ReportSingleChunk) {
  // Although the tests use a mock clock, the metrics recorder checks if the
  // system has a high resolution clock before recording results. As a result,
  // the tests will fail if the system does not have a high resolution clock.
  if (!base::TimeTicks::IsHighResolution())
    return;

  base::HistogramTester histogram_tester;
  LoadHTML(R"HTML(
    <div></div>
  )HTML");

  // Should have one of each metric, except the yield times because with
  // a single chunk they should not report.
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.ChunkCount4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.ParsingTimeMax4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.ParsingTimeMin4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.ParsingTimeTotal4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.TokensParsedMax4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.TokensParsedMin4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.TokensParsedAverage4",
                                    1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.TokensParsedTotal4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.YieldedTimeMax4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.YieldedTimeMin4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.YieldedTimeAverage4", 1);

  // Expect specific values for the chunks and tokens counts
  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.ChunkCount4", 1, 1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.TokensParsedMax4", 5,
                                      1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.TokensParsedMin4", 5,
                                      1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.TokensParsedAverage4",
                                      5, 1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.TokensParsedTotal4", 5,
                                      1);

  // Expect that the times have moved from the default and the max and min
  // and total are all the same (within the same bucket)
  std::vector<base::Bucket> parsing_time_max_buckets =
      histogram_tester.GetAllSamples("Blink.HTMLParsing.ParsingTimeMax4");
  std::vector<base::Bucket> parsing_time_min_buckets =
      histogram_tester.GetAllSamples("Blink.HTMLParsing.ParsingTimeMin4");
  std::vector<base::Bucket> parsing_time_total_buckets =
      histogram_tester.GetAllSamples("Blink.HTMLParsing.ParsingTimeTotal4");
  EXPECT_EQ(parsing_time_max_buckets.size(), 1u);
  EXPECT_EQ(parsing_time_min_buckets.size(), 1u);
  EXPECT_EQ(parsing_time_total_buckets.size(), 1u);
  EXPECT_GT(parsing_time_max_buckets[0].min, 0);
  EXPECT_GT(parsing_time_min_buckets[0].min, 0);
  EXPECT_GT(parsing_time_total_buckets[0].min, 0);

  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.InputCharacterCount4",
                                      19, 1);
}

// https://crbug.com/1222653
TEST_F(HTMLMetricsTest, DISABLED_HistogramReportsTwoChunks) {
  // Although the tests use a mock clock, the metrics recorder checks if the
  // system has a high resolution clock before recording results. As a result,
  // the tests will fail if the system does not have a high resolution clock.
  if (!base::TimeTicks::IsHighResolution())
    return;

  base::HistogramTester histogram_tester;

  // This content processes many tokens before a script tag used as the yield
  // threshold. If the yield behavior changes this test may need updating.
  // See the HTMLDocumentParser::PumpTokenizer method for the current yielding
  // behavior. The code below assumes that 250+ tokens is enough to yield.
  LoadHTML(R"HTML(
    <head></head>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>111 tokens to here
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>220 tokens to here
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>
    <div></div><div></div><div></div><div></div><div></div><div></div>257 tokens to here
  )HTML");

  // Comment this back in to see histogram values:
  // LOG(ERROR) << histogram_tester.GetAllHistogramsRecorded();

  // Should have one of each metric.
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.ChunkCount4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.ParsingTimeMax4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.ParsingTimeMin4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.ParsingTimeTotal4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.TokensParsedMax4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.TokensParsedMin4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.TokensParsedAverage4",
                                    1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.TokensParsedTotal4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.YieldedTimeMax4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.YieldedTimeMin4", 1);
  histogram_tester.ExpectTotalCount("Blink.HTMLParsing.YieldedTimeAverage4", 1);

  // Expect specific values for the chunks and tokens counts
  // TODO(crbug.com/1314493): See if we can get this to parse in two separate
  // chunks again with the timed budget.
  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.ChunkCount4", 1, 1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.TokensParsedMax4", 258,
                                      1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.TokensParsedMin4", 268,
                                      1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.TokensParsedAverage4",
                                      258, 1);
  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.TokensParsedTotal4",
                                      203, 1);

  // For parse times, expect that the times have moved from the default.
  std::vector<base::Bucket> parsing_time_max_buckets =
      histogram_tester.GetAllSamples("Blink.HTMLParsing.ParsingTimeMax4");
  std::vector<base::Bucket> parsing_time_min_buckets =
      histogram_tester.GetAllSamples("Blink.HTMLParsing.ParsingTimeMin4");
  std::vector<base::Bucket> parsing_time_total_buckets =
      histogram_tester.GetAllSamples("Blink.HTMLParsing.ParsingTimeTotal4");
  EXPECT_EQ(parsing_time_max_buckets.size(), 1u);
  EXPECT_EQ(parsing_time_min_buckets.size(), 1u);
  EXPECT_EQ(parsing_time_total_buckets.size(), 1u);
  EXPECT_GT(parsing_time_max_buckets[0].min, 0);
  EXPECT_GT(parsing_time_min_buckets[0].min, 0);
  EXPECT_GT(parsing_time_total_buckets[0].min, 0);

  // For yields, the values should be the same because there was only one yield,
  // but due to different histogram sizes we can't directly compare them.
  std::vector<base::Bucket> yield_time_max_buckets =
      histogram_tester.GetAllSamples("Blink.HTMLParsing.YieldedTimeMax4");
  std::vector<base::Bucket> yield_time_min_buckets =
      histogram_tester.GetAllSamples("Blink.HTMLParsing.YieldedTimeMin4");
  std::vector<base::Bucket> yield_time_average_buckets =
      histogram_tester.GetAllSamples("Blink.HTMLParsing.YieldedTimeAverage4");
  EXPECT_EQ(yield_time_max_buckets.size(), 1u);
  EXPECT_EQ(yield_time_min_buckets.size(), 1u);
  EXPECT_EQ(yield_time_average_buckets.size(), 1u);
  EXPECT_GT(yield_time_max_buckets[0].min, 0);
  EXPECT_GT(yield_time_min_buckets[0].min, 0);
  EXPECT_GT(yield_time_average_buckets[0].min, 0);

  histogram_tester.ExpectUniqueSample("Blink.HTMLParsing.InputCharacterCount4",
                                      1447, 1);
}

TEST_F(HTMLMetricsTest, UkmStoresValuesCorrectly) {
  // Although the tests use a mock clock, the metrics recorder checks if the
  // system has a high resolution clock before recording results. As a result,
  // the tests will fail if the system does not have a high resolution clock.
  if (!base::TimeTicks::IsHighResolution())
    return;

  ukm::TestUkmRecorder recorder;
  HTMLParserMetrics reporter(ukm::UkmRecorder::GetNewSourceID(), &recorder);

  // Start with empty metrics
  auto entries = recorder.GetEntriesByName("Blink.HTMLParsing");
  EXPECT_EQ(entries.size(), 0u);

  // Run a fictional sequence of calls
  base::TimeDelta first_parse_time = base::Microseconds(20);
  base::TimeDelta second_parse_time = base::Microseconds(10);
  base::TimeDelta third_parse_time = base::Microseconds(30);
  unsigned first_tokens_parsed = 50u;
  unsigned second_tokens_parsed = 40u;
  unsigned third_tokens_parsed = 60u;
  base::TimeDelta first_yield_time = base::Microseconds(80);
  base::TimeDelta second_yield_time = base::Microseconds(70);

  reporter.AddChunk(first_parse_time, first_tokens_parsed);
  reporter.AddYieldInterval(first_yield_time);
  reporter.AddChunk(second_parse_time, second_tokens_parsed);
  reporter.AddYieldInterval(second_yield_time);
  reporter.AddChunk(third_parse_time, third_tokens_parsed);
  reporter.ReportMetricsAtParseEnd();

  // Check we have a single entry
  entries = recorder.GetEntriesByName("Blink.HTMLParsing");
  EXPECT_EQ(entries.size(), 1u);
  auto* entry = entries[0].get();

  // Verify all the values
  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entry, "ChunkCount"));
  const int64_t* metric_value =
      ukm::TestUkmRecorder::GetEntryMetric(entry, "ChunkCount");
  EXPECT_EQ(*metric_value, 3);

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entry, "ParsingTimeMax"));
  metric_value = ukm::TestUkmRecorder::GetEntryMetric(entry, "ParsingTimeMax");
  EXPECT_EQ(*metric_value, third_parse_time.InMicroseconds());

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entry, "ParsingTimeMin"));
  metric_value = ukm::TestUkmRecorder::GetEntryMetric(entry, "ParsingTimeMin");
  EXPECT_EQ(*metric_value, second_parse_time.InMicroseconds());

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entry, "ParsingTimeTotal"));
  metric_value =
      ukm::TestUkmRecorder::GetEntryMetric(entry, "ParsingTimeTotal");
  EXPECT_EQ(*metric_value,
            (first_parse_time + second_parse_time + third_parse_time)
                .InMicroseconds());

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entry, "TokensParsedMax"));
  metric_value = ukm::TestUkmRecorder::GetEntryMetric(entry, "TokensParsedMax");
  EXPECT_EQ(*metric_value, third_tokens_parsed);

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entry, "TokensParsedMin"));
  metric_value = ukm::TestUkmRecorder::GetEntryMetric(entry, "TokensParsedMin");
  EXPECT_EQ(*metric_value, second_tokens_parsed);

  EXPECT_TRUE(
      ukm::TestUkmRecorder::EntryHasMetric(entry, "TokensParsedAverage"));
  metric_value =
      ukm::TestUkmRecorder::GetEntryMetric(entry, "TokensParsedAverage");
  EXPECT_EQ(
      *metric_value,
      (first_tokens_parsed + second_tokens_parsed + third_tokens_parsed) / 3);

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entry, "TokensParsedTotal"));
  metric_value =
      ukm::TestUkmRecorder::GetEntryMetric(entry, "TokensParsedTotal");
  EXPECT_EQ(*metric_value,
            first_tokens_parsed + second_tokens_parsed + third_tokens_parsed);

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entry, "YieldedTimeMax"));
  metric_value = ukm::TestUkmRecorder::GetEntryMetric(entry, "YieldedTimeMax");
  EXPECT_EQ(*metric_value, first_yield_time.InMicroseconds());

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entry, "YieldedTimeMin"));
  metric_value = ukm::TestUkmRecorder::GetEntryMetric(entry, "YieldedTimeMin");
  EXPECT_EQ(*metric_value, second_yield_time.InMicroseconds());

  EXPECT_TRUE(
      ukm::TestUkmRecorder::EntryHasMetric(entry, "YieldedTimeAverage"));
  metric_value =
      ukm::TestUkmRecorder::GetEntryMetric(entry, "YieldedTimeAverage");
  EXPECT_EQ(*metric_value,
            ((first_yield_time + second_yield_time) / 2).InMicroseconds());
}

}  // namespace blink
```