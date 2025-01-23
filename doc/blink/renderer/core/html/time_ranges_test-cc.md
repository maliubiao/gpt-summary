Response:
Let's break down the thought process for analyzing the C++ test file `time_ranges_test.cc`.

1. **Identify the Core Purpose:** The file name `time_ranges_test.cc` immediately suggests that this is a test suite for a class or component named `TimeRanges`. The presence of `#include "third_party/blink/renderer/core/html/time_ranges.h"` confirms this.

2. **Recognize the Testing Framework:** The inclusion of `#include "testing/gtest/include/gtest/gtest.h"` tells us that Google Test is being used for these unit tests. This is a common framework in Chromium projects.

3. **Understand the Test Structure:**  Google Test uses macros like `TEST(TestSuiteName, TestName)`. Each `TEST` block represents an individual test case. The test suite name here is `TimeRangesTest`.

4. **Analyze Individual Test Cases:**  Go through each `TEST` block and determine what aspect of the `TimeRanges` class it's verifying.

    * **`Empty`:** Tests the creation of an empty `TimeRanges` object and verifies it has no ranges.
    * **`SingleRange`:** Tests creating a `TimeRanges` object with a single range.
    * **`CreateFromWebTimeRanges`:**  Shows how to create a `TimeRanges` object from a `blink::WebTimeRanges` object. This hints at a possible interoperation with other Blink components.
    * **`AddOrder`:**  Confirms that adding ranges in different orders results in the same final set of merged and sorted ranges.
    * **`OverlappingAdds`:** This is a crucial test. It systematically checks how the `Add` method handles overlapping ranges, ensuring they are correctly merged. This reveals a key behavior of the `TimeRanges` class: it maintains a canonical, non-overlapping representation of time intervals.
    * **`IntersectWith_...`:**  These tests thoroughly examine the `IntersectWith` method. They cover various scenarios: self-intersection, intersection with identical ranges, empty ranges, disjoint ranges, complete overlaps, and partial overlaps (gaps). This highlights another important functionality: calculating the intersection of two sets of time ranges.
    * **`Nearest`:** Tests the `Nearest` method, which finds the closest time boundary within the ranges to a given time. The second argument to `Nearest` seems to introduce the concept of comparing distances.

5. **Identify Helper Functions and Macros:** The `ToString` function is a utility to convert `TimeRanges` objects into a string representation for easier assertion. The `ASSERT_RANGE` macro simplifies the assertion of the expected string representation.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):** Now, consider how `TimeRanges` might be used in the context of a web browser.

    * **HTML `<video>` and `<audio>` elements:**  This is the most direct connection. These elements have a `buffered` attribute that returns a `TimeRanges` object representing the currently buffered portions of the media. The tests related to adding and intersecting are directly relevant to how the browser manages buffered data.
    * **JavaScript API:** The tests implicitly suggest that the `TimeRanges` object is likely exposed to JavaScript. The test `CreateFromWebTimeRanges` suggests an internal representation (`blink::WebTimeRanges`) that might be the bridge to the JavaScript `TimeRanges` interface.
    * **No direct CSS relation:**  It's unlikely `TimeRanges` has a direct connection to CSS. CSS deals with visual presentation and layout, while `TimeRanges` manages temporal data.

7. **Infer Logical Reasoning and Assumptions:**

    * **Assumption:** The `TimeRanges` class is designed to represent a set of non-overlapping time intervals. The `Add` method's behavior confirms this.
    * **Assumption:** The time values are likely represented as floating-point numbers (doubles or floats) to allow for fractional seconds. This isn't explicitly stated but is a common practice for media times.
    * **Logical Deduction (from `OverlappingAdds`):**  When adding overlapping ranges, the resulting range spans from the earliest start time to the latest end time of the overlapping intervals.

8. **Consider Common Usage Errors:**  Think about how a developer might misuse the `TimeRanges` API.

    * **Incorrect Time Units:**  Assuming time is in seconds when it might be in milliseconds, or vice-versa, could lead to unexpected behavior.
    * **Off-by-One Errors:**  The end time of a range is often exclusive. Forgetting this can lead to ranges that don't include the intended endpoint.
    * **Modifying Underlying Data (If Exposed):** If the internal representation of `TimeRanges` is directly exposed and modifiable, incorrect manipulation could lead to inconsistent state. However, given the immutable nature suggested by methods like `Copy()`, this is less likely.

9. **Refine and Organize the Analysis:**  Structure the findings into clear categories (functionality, relation to web technologies, logical reasoning, common errors) with illustrative examples. This makes the analysis easy to understand.

By following this systematic approach, we can thoroughly analyze the provided C++ test file and understand the functionality of the `TimeRanges` class within the broader context of the Blink rendering engine.
这个文件 `time_ranges_test.cc` 是 Chromium Blink 引擎中 `TimeRanges` 类的单元测试文件。它的主要功能是验证 `TimeRanges` 类的各种方法和行为是否符合预期。`TimeRanges` 类用于表示一组不连续的时间范围，这在处理 HTML5 `<video>` 和 `<audio>` 元素的缓冲、播放进度等方面非常重要。

以下是该测试文件各项功能的详细说明，并关联了 JavaScript, HTML, CSS 的功能，以及逻辑推理和常见使用错误：

**1. 功能列举:**

* **创建和初始化 `TimeRanges` 对象:** 测试创建空的 `TimeRanges` 对象，以及使用单个或多个时间范围进行初始化。
* **添加时间范围 (`Add` 方法):** 测试向 `TimeRanges` 对象添加新的时间范围，包括处理重叠的情况，确保重叠的范围被合并。
* **从 `WebTimeRanges` 创建 (`CreateFromWebTimeRanges`):**  测试从 Blink 内部的 `WebTimeRanges` 结构创建 `TimeRanges` 对象，这表明 `TimeRanges` 类可能是对底层 Web API 的一个封装或抽象。
* **时间范围的顺序 (`AddOrder`):** 测试以不同顺序添加相同的时间范围，验证最终 `TimeRanges` 对象是否一致，表明内部实现会对范围进行排序和合并。
* **重叠范围的处理 (`OverlappingAdds`):** 详细测试添加重叠时间范围时的合并逻辑，确保最终的 `TimeRanges` 对象只包含不重叠的范围。
* **计算交集 (`IntersectWith` 方法):** 测试 `IntersectWith` 方法，该方法计算当前 `TimeRanges` 对象与另一个 `TimeRanges` 对象的交集，并更新当前对象。涵盖了自相交、与相同范围相交、与空范围相交、与不相交范围相交、以及各种重叠情况。
* **查找最近的时间点 (`Nearest` 方法):** 测试 `Nearest` 方法，该方法返回 `TimeRanges` 中最接近给定时间点的边界。

**2. 与 JavaScript, HTML, CSS 的关系:**

`TimeRanges` 类直接关联到 HTML5 的 `<video>` 和 `<audio>` 元素，并通过 JavaScript API 暴露给开发者。

* **HTML:**
    * **`<video>` 和 `<audio>` 元素的 `buffered` 属性:**  当浏览器下载媒体资源时，`buffered` 属性返回一个 `TimeRanges` 对象，表示已缓冲的媒体时间范围。例如，如果视频的前 5 秒和 10-15 秒被缓冲，`buffered` 可能返回一个包含 `[0, 5)` 和 `[10, 15)` 两个范围的 `TimeRanges` 对象。

* **JavaScript:**
    * **`HTMLMediaElement.prototype.buffered`:**  JavaScript 可以通过 `videoElement.buffered` 或 `audioElement.buffered` 访问到这个 `TimeRanges` 对象。开发者可以使用这个对象来了解哪些部分的媒体数据已经可以播放。
    * **`TimeRanges` 接口:**  JavaScript 中有一个 `TimeRanges` 接口，它与 Blink 的 `TimeRanges` 类在概念上是对应的。JavaScript 代码可以访问 `TimeRanges` 对象的 `length` 属性（返回范围的数量），以及 `start(index)` 和 `end(index)` 方法（返回指定索引范围的开始和结束时间）。

* **CSS:**
    * **无直接关系:**  `TimeRanges` 类主要处理时间数据，与 CSS 的样式和布局功能没有直接关系。

**举例说明:**

**HTML:**

```html
<video id="myVideo" src="myvideo.mp4" controls></video>
```

**JavaScript:**

```javascript
const video = document.getElementById('myVideo');

video.addEventListener('progress', () => {
  const bufferedRanges = video.buffered;
  console.log("已缓冲的时间范围数量:", bufferedRanges.length);
  for (let i = 0; i < bufferedRanges.length; i++) {
    console.log(`范围 ${i + 1}: ${bufferedRanges.start(i)} - ${bufferedRanges.end(i)}`);
  }
});
```

在这个例子中，当视频缓冲进度发生变化时，JavaScript 代码会获取 `video.buffered` 属性，它返回一个 `TimeRanges` 对象。然后，代码遍历这个对象，打印出已缓冲的时间范围。

**3. 逻辑推理 (假设输入与输出):**

* **`TEST(TimeRangesTest, OverlappingAdds)`:**
    * **假设输入:** 依次添加以下时间范围: `[0, 2)`, `[10, 11)`, `[0, 2)`, `[2, 3)`, `[2, 6)`, `[9, 10)`, `[8, 10)`, `[-1, 7)`, `[6, 9)`
    * **预期输出:** 最终的 `TimeRanges` 对象表示的时间范围为 `[-1, 11)`。这是因为重叠的范围被合并了。

* **`TEST(TimeRangesTest, IntersectWith_Gaps3)`:**
    * **假设输入:**
        * `ranges_a` 初始化为包含 `[0, 2)`, `[4, 7)`, `[8, 10)`
        * `ranges_b` 初始化为包含 `[1, 5)`, `[6, 9)`
    * **预期输出 (`ranges_a->IntersectWith(ranges_b)` 之后):** `ranges_a` 将包含 `[1, 2)`, `[4, 5)`, `[6, 7)`, `[8, 9)`。这是 `ranges_a` 和 `ranges_b` 的交集。

* **`TEST(TimeRangesTest, Nearest)`:**
    * **假设输入:** `ranges` 包含 `[0, 2)`, `[5, 7)`, 且调用 `ranges->Nearest(3, 0)`
    * **预期输出:** `2`。因为 3 位于第一个范围之后，第二个范围之前，最近的边界是第一个范围的结束时间 2。

    * **假设输入:** `ranges` 包含 `[0, 2)`, `[5, 7)`, 并且调用 `ranges->Nearest(4, 0)`
    * **预期输出:** `5`。因为 4 位于两个范围之间，距离 5 更近。

**4. 涉及用户或编程常见的使用错误:**

* **假设时间单位不一致:**  开发者可能错误地认为 `TimeRanges` 中的时间单位是毫秒，而实际是秒，或者反之，导致计算错误。
    * **错误示例 (JavaScript):**
      ```javascript
      const video = document.getElementById('myVideo');
      // 错误地认为 buffered 的时间单位是毫秒
      if (video.buffered.length > 0 && video.currentTime * 1000 < video.buffered.end(0)) {
        console.log("当前时间在第一个缓冲范围内");
      }
      ```

* **忽略范围的独占性:**  `TimeRanges` 中的范围通常是左闭右开的，即 `[start, end)`。开发者可能错误地认为 `end` 也包含在范围内。
    * **错误示例 (JavaScript):**
      ```javascript
      const video = document.getElementById('myVideo');
      if (video.buffered.length > 0 && video.currentTime <= video.buffered.end(0)) {
        // 这里应该使用 < 而不是 <=
        console.log("当前时间在第一个缓冲范围内");
      }
      ```

* **直接修改 `TimeRanges` 对象 (如果允许):**  虽然 JavaScript 中的 `TimeRanges` 对象是只读的，但在某些内部实现中，如果错误地直接修改 `TimeRanges` 对象的数据，可能会导致状态不一致。然而，通常 `TimeRanges` 的创建和修改是通过特定的方法进行的，而不是直接修改其内部数据。

* **未处理 `buffered.length` 为 0 的情况:**  在访问 `buffered.start(0)` 或 `buffered.end(0)` 之前，应该先检查 `buffered.length` 是否大于 0，否则会导致错误。
    * **错误示例 (JavaScript):**
      ```javascript
      const video = document.getElementById('myVideo');
      // 如果 buffered 为空，这段代码会出错
      console.log("第一个缓冲范围的结束时间:", video.buffered.end(0));
      ```

总而言之，`time_ranges_test.cc` 文件通过一系列单元测试，确保 `TimeRanges` 类能够正确地表示和操作时间范围，这对于实现 HTML5 媒体元素的相关功能至关重要。开发者在使用与媒体缓冲相关的 JavaScript API 时，理解 `TimeRanges` 的概念和行为是非常重要的。

### 提示词
```
这是目录为blink/renderer/core/html/time_ranges_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/html/time_ranges.h"

#include <sstream>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

static std::string ToString(const TimeRanges& ranges) {
  std::stringstream ss;
  ss << "{";
  for (unsigned i = 0; i < ranges.length(); ++i) {
    ss << " [" << ranges.start(i, IGNORE_EXCEPTION_FOR_TESTING) << ","
       << ranges.end(i, IGNORE_EXCEPTION_FOR_TESTING) << ")";
  }
  ss << " }";

  return ss.str();
}

#define ASSERT_RANGE(expected, range) ASSERT_EQ(expected, ToString(*range))

TEST(TimeRangesTest, Empty) {
  test::TaskEnvironment task_environment;
  ASSERT_RANGE("{ }", MakeGarbageCollected<TimeRanges>());
}

TEST(TimeRangesTest, SingleRange) {
  test::TaskEnvironment task_environment;
  ASSERT_RANGE("{ [1,2) }", MakeGarbageCollected<TimeRanges>(1, 2));
}

TEST(TimeRangesTest, CreateFromWebTimeRanges) {
  test::TaskEnvironment task_environment;
  blink::WebTimeRanges web_ranges(static_cast<size_t>(2));
  web_ranges[0].start = 0;
  web_ranges[0].end = 1;
  web_ranges[1].start = 2;
  web_ranges[1].end = 3;
  ASSERT_RANGE("{ [0,1) [2,3) }", MakeGarbageCollected<TimeRanges>(web_ranges));
}

TEST(TimeRangesTest, AddOrder) {
  test::TaskEnvironment task_environment;
  auto* range_a = MakeGarbageCollected<TimeRanges>();
  auto* range_b = MakeGarbageCollected<TimeRanges>();

  range_a->Add(0, 2);
  range_a->Add(3, 4);
  range_a->Add(5, 100);

  std::string expected = "{ [0,2) [3,4) [5,100) }";
  ASSERT_RANGE(expected, range_a);

  // Add the values in rangeA to rangeB in reverse order.
  for (int i = range_a->length() - 1; i >= 0; --i) {
    range_b->Add(range_a->start(i, IGNORE_EXCEPTION_FOR_TESTING),
                 range_a->end(i, IGNORE_EXCEPTION_FOR_TESTING));
  }

  ASSERT_RANGE(expected, range_b);
}

TEST(TimeRangesTest, OverlappingAdds) {
  test::TaskEnvironment task_environment;
  auto* ranges = MakeGarbageCollected<TimeRanges>();

  ranges->Add(0, 2);
  ranges->Add(10, 11);
  ASSERT_RANGE("{ [0,2) [10,11) }", ranges);

  ranges->Add(0, 2);
  ASSERT_RANGE("{ [0,2) [10,11) }", ranges);

  ranges->Add(2, 3);
  ASSERT_RANGE("{ [0,3) [10,11) }", ranges);

  ranges->Add(2, 6);
  ASSERT_RANGE("{ [0,6) [10,11) }", ranges);

  ranges->Add(9, 10);
  ASSERT_RANGE("{ [0,6) [9,11) }", ranges);

  ranges->Add(8, 10);
  ASSERT_RANGE("{ [0,6) [8,11) }", ranges);

  ranges->Add(-1, 7);
  ASSERT_RANGE("{ [-1,7) [8,11) }", ranges);

  ranges->Add(6, 9);
  ASSERT_RANGE("{ [-1,11) }", ranges);
}

TEST(TimeRangesTest, IntersectWith_Self) {
  test::TaskEnvironment task_environment;
  auto* ranges = MakeGarbageCollected<TimeRanges>(0, 2);

  ASSERT_RANGE("{ [0,2) }", ranges);

  ranges->IntersectWith(ranges);

  ASSERT_RANGE("{ [0,2) }", ranges);
}

TEST(TimeRangesTest, IntersectWith_IdenticalRange) {
  test::TaskEnvironment task_environment;
  auto* ranges_a = MakeGarbageCollected<TimeRanges>(0, 2);
  auto* ranges_b = ranges_a->Copy();

  ASSERT_RANGE("{ [0,2) }", ranges_a);
  ASSERT_RANGE("{ [0,2) }", ranges_b);

  ranges_a->IntersectWith(ranges_b);

  ASSERT_RANGE("{ [0,2) }", ranges_a);
  ASSERT_RANGE("{ [0,2) }", ranges_b);
}

TEST(TimeRangesTest, IntersectWith_Empty) {
  test::TaskEnvironment task_environment;
  auto* ranges_a = MakeGarbageCollected<TimeRanges>(0, 2);
  auto* ranges_b = MakeGarbageCollected<TimeRanges>();

  ASSERT_RANGE("{ [0,2) }", ranges_a);
  ASSERT_RANGE("{ }", ranges_b);

  ranges_a->IntersectWith(ranges_b);

  ASSERT_RANGE("{ }", ranges_a);
  ASSERT_RANGE("{ }", ranges_b);
}

TEST(TimeRangesTest, IntersectWith_DisjointRanges1) {
  test::TaskEnvironment task_environment;
  auto* ranges_a = MakeGarbageCollected<TimeRanges>();
  auto* ranges_b = MakeGarbageCollected<TimeRanges>();

  ranges_a->Add(0, 1);
  ranges_a->Add(4, 5);

  ranges_b->Add(2, 3);
  ranges_b->Add(6, 7);

  ASSERT_RANGE("{ [0,1) [4,5) }", ranges_a);
  ASSERT_RANGE("{ [2,3) [6,7) }", ranges_b);

  ranges_a->IntersectWith(ranges_b);

  ASSERT_RANGE("{ }", ranges_a);
  ASSERT_RANGE("{ [2,3) [6,7) }", ranges_b);
}

TEST(TimeRangesTest, IntersectWith_DisjointRanges2) {
  test::TaskEnvironment task_environment;
  auto* ranges_a = MakeGarbageCollected<TimeRanges>();
  auto* ranges_b = MakeGarbageCollected<TimeRanges>();

  ranges_a->Add(0, 1);
  ranges_a->Add(4, 5);

  ranges_b->Add(1, 4);
  ranges_b->Add(5, 7);

  ASSERT_RANGE("{ [0,1) [4,5) }", ranges_a);
  ASSERT_RANGE("{ [1,4) [5,7) }", ranges_b);

  ranges_a->IntersectWith(ranges_b);

  ASSERT_RANGE("{ }", ranges_a);
  ASSERT_RANGE("{ [1,4) [5,7) }", ranges_b);
}

TEST(TimeRangesTest, IntersectWith_CompleteOverlap1) {
  test::TaskEnvironment task_environment;
  auto* ranges_a = MakeGarbageCollected<TimeRanges>();
  auto* ranges_b = MakeGarbageCollected<TimeRanges>();

  ranges_a->Add(1, 3);
  ranges_a->Add(4, 5);
  ranges_a->Add(6, 9);

  ranges_b->Add(0, 10);

  ASSERT_RANGE("{ [1,3) [4,5) [6,9) }", ranges_a);
  ASSERT_RANGE("{ [0,10) }", ranges_b);

  ranges_a->IntersectWith(ranges_b);

  ASSERT_RANGE("{ [1,3) [4,5) [6,9) }", ranges_a);
  ASSERT_RANGE("{ [0,10) }", ranges_b);
}

TEST(TimeRangesTest, IntersectWith_CompleteOverlap2) {
  test::TaskEnvironment task_environment;
  auto* ranges_a = MakeGarbageCollected<TimeRanges>();
  auto* ranges_b = MakeGarbageCollected<TimeRanges>();

  ranges_a->Add(1, 3);
  ranges_a->Add(4, 5);
  ranges_a->Add(6, 9);

  ranges_b->Add(1, 9);

  ASSERT_RANGE("{ [1,3) [4,5) [6,9) }", ranges_a);
  ASSERT_RANGE("{ [1,9) }", ranges_b);

  ranges_a->IntersectWith(ranges_b);

  ASSERT_RANGE("{ [1,3) [4,5) [6,9) }", ranges_a);
  ASSERT_RANGE("{ [1,9) }", ranges_b);
}

TEST(TimeRangesTest, IntersectWith_Gaps1) {
  test::TaskEnvironment task_environment;
  auto* ranges_a = MakeGarbageCollected<TimeRanges>();
  auto* ranges_b = MakeGarbageCollected<TimeRanges>();

  ranges_a->Add(0, 2);
  ranges_a->Add(4, 6);

  ranges_b->Add(1, 5);

  ASSERT_RANGE("{ [0,2) [4,6) }", ranges_a);
  ASSERT_RANGE("{ [1,5) }", ranges_b);

  ranges_a->IntersectWith(ranges_b);

  ASSERT_RANGE("{ [1,2) [4,5) }", ranges_a);
  ASSERT_RANGE("{ [1,5) }", ranges_b);
}

TEST(TimeRangesTest, IntersectWith_Gaps2) {
  test::TaskEnvironment task_environment;
  auto* ranges_a = MakeGarbageCollected<TimeRanges>();
  auto* ranges_b = MakeGarbageCollected<TimeRanges>();

  ranges_a->Add(0, 2);
  ranges_a->Add(4, 6);
  ranges_a->Add(8, 10);

  ranges_b->Add(1, 9);

  ASSERT_RANGE("{ [0,2) [4,6) [8,10) }", ranges_a);
  ASSERT_RANGE("{ [1,9) }", ranges_b);

  ranges_a->IntersectWith(ranges_b);

  ASSERT_RANGE("{ [1,2) [4,6) [8,9) }", ranges_a);
  ASSERT_RANGE("{ [1,9) }", ranges_b);
}

TEST(TimeRangesTest, IntersectWith_Gaps3) {
  test::TaskEnvironment task_environment;
  auto* ranges_a = MakeGarbageCollected<TimeRanges>();
  auto* ranges_b = MakeGarbageCollected<TimeRanges>();

  ranges_a->Add(0, 2);
  ranges_a->Add(4, 7);
  ranges_a->Add(8, 10);

  ranges_b->Add(1, 5);
  ranges_b->Add(6, 9);

  ASSERT_RANGE("{ [0,2) [4,7) [8,10) }", ranges_a);
  ASSERT_RANGE("{ [1,5) [6,9) }", ranges_b);

  ranges_a->IntersectWith(ranges_b);

  ASSERT_RANGE("{ [1,2) [4,5) [6,7) [8,9) }", ranges_a);
  ASSERT_RANGE("{ [1,5) [6,9) }", ranges_b);
}

TEST(TimeRangesTest, Nearest) {
  test::TaskEnvironment task_environment;
  auto* ranges = MakeGarbageCollected<TimeRanges>();
  ranges->Add(0, 2);
  ranges->Add(5, 7);

  ASSERT_EQ(0, ranges->Nearest(0, 0));
  ASSERT_EQ(1, ranges->Nearest(1, 0));
  ASSERT_EQ(2, ranges->Nearest(2, 0));
  ASSERT_EQ(2, ranges->Nearest(3, 0));
  ASSERT_EQ(5, ranges->Nearest(4, 0));
  ASSERT_EQ(5, ranges->Nearest(5, 0));
  ASSERT_EQ(7, ranges->Nearest(8, 0));

  ranges->Add(9, 11);
  ASSERT_EQ(7, ranges->Nearest(8, 6));
  ASSERT_EQ(7, ranges->Nearest(8, 8));
  ASSERT_EQ(9, ranges->Nearest(8, 10));
}

}  // namespace blink
```