Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the `segment_stream_test.cc` file and its relation to web technologies (JavaScript, HTML, CSS), along with examples of logical reasoning and common errors. The key is to understand what this *test* file is testing.

2. **Identify the Core Class Under Test:** The filename `segment_stream_test.cc` strongly suggests the file tests the `SegmentStream` class. A quick scan of the `#include` directives confirms this: `#include "third_party/blink/renderer/platform/image-decoders/skia/segment_stream.h"`.

3. **Recognize the Testing Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` indicates that Google Test (gtest) is used for the unit tests. This is important because it tells us the structure of the tests (using `TEST()` macros).

4. **Analyze the Test Structure:** The code consists of multiple `TEST()` functions. Each `TEST()` function focuses on testing a specific aspect or behavior of the `SegmentStream` class. The names of the tests are descriptive (e.g., `DefaultConstructorShouldSetIsCleared`, `ReadShouldConsumeBuffer`). This gives a good overview of what functionalities are being verified.

5. **Summarize the Functionality Based on Test Names and Assertions:** Go through each test and understand what it's checking. Focus on the assertions (`ASSERT_TRUE`, `ASSERT_FALSE`, `ASSERT_EQ`). For example:
    * `DefaultConstructorShouldSetIsCleared`: Checks if a newly created `SegmentStream` is in a "cleared" state.
    * `MoveConstructorShouldCopyRhsPosition`: Checks if the move constructor correctly copies the position of the original `SegmentStream`.
    * `ReadShouldConsumeBuffer`: Checks if reading from the stream advances the internal position.
    * `SetReaderShouldUpdateLength`: Checks if setting a `SegmentReader` updates the stream's length.

6. **Identify Helper Functions:** Notice the helper functions defined in the unnamed namespace: `IsCleared`, `IsAtEnd`, `CreatePopulatedSegmentStream`, `CreateSegmentReader`, `ReadFromSegmentStream`, `PeekIntoSegmentStream`. These functions simplify the tests by providing reusable setup and assertion logic. For instance, `CreatePopulatedSegmentStream` sets up a `SegmentStream` with some data, and `IsCleared` checks the cleared status.

7. **Infer the Purpose of `SegmentStream`:**  Based on the tests, deduce the likely purpose of the `SegmentStream` class. It seems to be a class for reading data from a segment (likely a part of a larger data stream or file). Key functionalities include:
    * Managing a position within the segment.
    * Reading and peeking at data.
    * Moving the position (seeking, moving forward).
    * Resetting the position (rewinding).
    * Keeping track of whether the stream is "cleared" or at the "end".

8. **Connect to Web Technologies (JavaScript, HTML, CSS):** This is where you need to make informed connections. Consider how images are handled in web browsers:
    * **Image Decoding:** The file path `blink/renderer/platform/image-decoders/skia/` strongly suggests this class is involved in decoding images.
    * **Progressive Loading:**  Image data might arrive in chunks or segments. `SegmentStream` could be used to manage the reading of these chunks as they arrive.
    * **HTML `<img>` tag:**  When an `<img>` tag is encountered, the browser fetches the image data. `SegmentStream` might be involved in how this data is processed.
    * **CSS `background-image`:** Similar to the `<img>` tag, CSS background images also require fetching and decoding.
    * **JavaScript `fetch()` API:** JavaScript can be used to fetch image data. The fetched data might then be processed using classes like `SegmentStream` internally.

9. **Logical Reasoning (Assumptions and Outputs):** Create simple scenarios to illustrate how the `SegmentStream` might behave. Focus on the key methods like `read`, `peek`, `seek`. Provide concrete input values and the expected outcome based on the test behavior.

10. **Common Usage Errors:** Think about how a programmer might misuse the `SegmentStream` class. Common errors related to data streams include:
    * Reading beyond the end of the stream.
    * Incorrectly setting or managing the position.
    * Not handling the "cleared" state properly.
    * Making assumptions about the data available.

11. **Refine and Organize:** Review your analysis, ensuring it's clear, concise, and addresses all parts of the request. Organize the information logically under headings like "Functionality," "Relationship to Web Technologies," "Logical Reasoning," and "Common Usage Errors."  Provide specific code examples or scenarios where possible. For example, instead of just saying "reading too much data," provide a specific example of calling `read` with a size larger than the remaining data.

By following this systematic approach, you can effectively analyze the C++ test file and understand its purpose and implications within the context of a web browser engine.
这个文件 `segment_stream_test.cc` 是 Chromium Blink 引擎中用于测试 `SegmentStream` 类的单元测试文件。它的主要功能是：

**功能:**

1. **测试 `SegmentStream` 类的各种方法和行为:** 该文件包含了大量的测试用例 (以 `TEST()` 宏定义)，用于验证 `SegmentStream` 类的各种功能是否按预期工作。这包括：
    * **构造函数和赋值运算符:** 测试默认构造函数、移动构造函数、移动赋值运算符的行为，例如是否正确初始化状态 (是否清空、是否在末尾、初始位置和长度)。
    * **`SetReader()` 方法:** 测试设置 `SegmentReader` (提供底层数据访问) 后 `SegmentStream` 的状态变化，例如是否清空、是否在末尾、长度是否更新。同时测试设置为 `nullptr` 或 `SegmentReader` 大小不足的情况。
    * **`read()` 方法:** 测试从流中读取数据的功能，验证读取后流的状态变化 (位置、是否在末尾、是否清空) 以及读取的数据量是否正确。
    * **`peek()` 方法:** 测试预览流中数据的功能，验证预览操作是否会改变流的状态 (位置、是否在末尾)。
    * **`rewind()` 方法:** 测试将流的位置重置到开始的功能。
    * **`seek()` 方法:** 测试将流的位置移动到指定偏移量的功能。
    * **`move()` 方法:** 测试将流的位置向前移动指定量的功能。
    * **访问器方法:** 测试 `isCleared()`, `isAtEnd()`, `getPosition()`, `getLength()`, `hasPosition()`, `hasLength()` 这些访问器方法是否返回正确的值。

2. **确保 `SegmentStream` 类的稳定性和正确性:** 通过大量的测试用例覆盖各种使用场景和边界情况，以尽早发现和修复 `SegmentStream` 类中的 bug，提高代码质量。

**与 JavaScript, HTML, CSS 的关系:**

`SegmentStream` 类本身并不直接暴露给 JavaScript, HTML 或 CSS。它位于 Blink 引擎的底层，负责处理图像解码过程中的数据流。然而，它的正确性直接影响到浏览器如何渲染网页上的图片。

以下是可能的关联方式和举例说明：

* **图片解码:** 当浏览器加载一个图片 (例如通过 HTML 的 `<img>` 标签或 CSS 的 `background-image` 属性)，Blink 引擎会使用各种解码器来处理不同格式的图片数据。`SegmentStream` 可以作为解码器的一部分，用于读取和管理图片数据的分段 (segments)。例如，当下载一个 JPEG 图片时，数据可能以多个段的形式到达，`SegmentStream` 可以帮助解码器按顺序读取这些段。
    * **假设输入:**  一个包含 JPEG 图片数据的 `SharedBuffer`，被 `SegmentReader` 读取并传递给 `SegmentStream`。
    * **输出:**  解码器通过 `SegmentStream` 顺序读取图片数据，最终解码成可用于渲染的位图。

* **渐进式图片加载:** 对于较大的图片，浏览器可能会采用渐进式加载的方式，即先显示一个低分辨率的版本，然后随着数据下载的完成逐步提高分辨率。`SegmentStream` 可以帮助管理和读取逐步到来的图片数据段。
    * **假设输入:**  一个支持渐进式加载的图片格式 (如 Progressive JPEG) 的数据流。
    * **输出:**  `SegmentStream` 允许解码器先读取一部分数据用于渲染低分辨率版本，然后在后续读取更多数据更新图像。

* **Service Workers 和 Cache API:**  如果使用了 Service Workers 或 Cache API 来缓存图片资源，`SegmentStream` 可能在从缓存读取图片数据时被使用。
    * **假设输入:**  从浏览器缓存中读取的图片数据。
    * **输出:**  `SegmentStream` 提供了一种顺序访问缓存中图片数据的方式，供解码器使用。

**逻辑推理的假设输入与输出:**

以下是一些基于测试用例的逻辑推理示例：

* **测试 `ReadShouldConsumeBuffer`:**
    * **假设输入:** 一个包含 20 字节数据的 `SegmentStream`，调用 `read()` 方法尝试读取 10 字节。
    * **输出:** `read()` 方法返回 10，表示成功读取了 10 字节，并且 `SegmentStream` 的内部位置向前移动了 10 个字节。

* **测试 `PeekShouldNotUpdatePosition`:**
    * **假设输入:** 一个包含 20 字节数据的 `SegmentStream`，调用 `peek()` 方法尝试读取 10 字节。
    * **输出:** `peek()` 方法返回 10，表示成功预览了 10 字节，但 `SegmentStream` 的内部位置保持不变。

* **测试 `SeekShouldUpdatePosition`:**
    * **假设输入:** 一个包含 20 字节数据的 `SegmentStream`，调用 `seek(15)` 方法。
    * **输出:** `SegmentStream` 的内部位置被设置为 15。

**涉及用户或编程常见的错误:**

* **读取超出流的末尾:** 程序员可能会尝试使用 `read()` 读取比剩余数据更多的字节，导致读取失败或返回的数据不完整。
    * **示例:** 一个 `SegmentStream` 剩余 5 个字节，但调用 `read(buffer, 10)`。测试用例 `ReadShouldConsumeBufferWithoutGoingPastTheEnd` 和 `ReadShouldSetIsAtEndWhenPastEnd` 就是为了防止这种情况。

* **错误地假设流的起始位置:** 如果在创建 `SegmentStream` 时指定了偏移量 (如 `OffsetReadingTest` 中所示)，程序员需要注意后续的读取、查找等操作都是相对于这个偏移量的。
    * **示例:** 创建一个偏移量为 5 的 `SegmentStream`，然后假设从位置 0 开始读取，这会导致读取到错误的数据。

* **在流被清空后尝试操作:** `SegmentStream` 在某些操作后会被标记为 "清空" (cleared)，例如设置了无效的 `SegmentReader`。在这种状态下尝试读取或查找可能会导致未定义的行为或错误。
    * **示例:**  将一个有效的 `SegmentReader` 设置为 `SegmentStream`，然后将其设置为 `nullptr` (导致清空)，之后尝试调用 `read()`。测试用例 `SetReaderShouldSetIsClearedWhenSetToNull` 就是为了验证这种情况。

* **忘记 `peek()` 不会移动位置:** 程序员可能会错误地认为 `peek()` 和 `read()` 一样会移动流的位置，导致后续的读取操作从错误的位置开始。 测试用例 `PeekShouldNotUpdatePosition` 就是为了强调这一点。

总而言之，`segment_stream_test.cc` 通过全面的单元测试确保了 `SegmentStream` 类的正确性和健壮性，这对于 Blink 引擎处理图片数据至关重要，最终影响到用户在浏览器中浏览网页的体验。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/skia/segment_stream_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/image-decoders/skia/segment_stream.h"

#include <string_view>

#include "base/memory/scoped_refptr.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/image-decoders/segment_reader.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

// SegmentStream has 4 accessors which do not alter state:
// - isCleared()
// - isAtEnd()
// - getPosition()
// - getLength()
//
// For every operation which changes state we can test:
// - the operation completed as expected,
// - the accessors did not change, and/or
// - the accessors changed in the way we expected.
//
// There are actually 2 more accessors:
// - hasPosition()
// - hasLength()
// but these should always return true to indicate that we can call getLength()
// for example. So let's not add them to every state changing operation and add
// needless complexity.

namespace blink {

namespace {

constexpr size_t kBufferAllocationSize = 20;
constexpr size_t kInsideBufferPosition = 10;
constexpr size_t kPastEndOfBufferPosition = 30;

::testing::AssertionResult IsCleared(const SegmentStream&);
::testing::AssertionResult IsAtEnd(const SegmentStream&);
::testing::AssertionResult PositionIsZero(const SegmentStream&);
::testing::AssertionResult PositionIsInsideBuffer(const SegmentStream&);
::testing::AssertionResult PositionIsAtEndOfBuffer(const SegmentStream&);
::testing::AssertionResult LengthIsZero(const SegmentStream&);
::testing::AssertionResult LengthIsAllocationSize(const SegmentStream&);

// Many of these tests require a SegmentStream with populated data.
//
// This function creates a buffer of size |kBufferAllocationSize| and prepares
// a SegmentStream with that buffer.
// This also populates other properties such as the length, cleared state, etc.
SegmentStream CreatePopulatedSegmentStream();

// This function creates a buffer of size |kBufferAllocationSize| to be used
// when populating a SegmentStream.
scoped_refptr<SegmentReader> CreateSegmentReader();

size_t ReadFromSegmentStream(SegmentStream&,
                             size_t amount_to_read = kInsideBufferPosition);
size_t PeekIntoSegmentStream(SegmentStream&,
                             size_t amount_to_peek = kInsideBufferPosition);

}  // namespace

TEST(SegmentStreamTest, DefaultConstructorShouldSetIsCleared) {
  SegmentStream segment_stream;

  ASSERT_TRUE(IsCleared(segment_stream));
}

TEST(SegmentStreamTest, DefaultConstructorShouldSetIsAtEnd) {
  SegmentStream segment_stream;

  ASSERT_TRUE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest, DefaultContructorShouldClearPosition) {
  SegmentStream segment_stream;

  ASSERT_TRUE(PositionIsZero(segment_stream));
}

TEST(SegmentStreamTest, DefaultConstructorShouldHaveZeroLength) {
  SegmentStream segment_stream;

  ASSERT_TRUE(LengthIsZero(segment_stream));
}

TEST(SegmentStreamTest, MoveConstructorShouldSetIsClearedWhenRhsIsCleared) {
  SegmentStream cleared_segment_stream;
  ASSERT_TRUE(IsCleared(cleared_segment_stream));

  SegmentStream move_constructed_segment_stream =
      std::move(cleared_segment_stream);

  ASSERT_TRUE(IsCleared(move_constructed_segment_stream));
}

TEST(SegmentStreamTest,
     MoveConstructorShouldUnsetIsClearedWhenRhsIsNotCleared) {
  SegmentStream uncleared_segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsCleared(uncleared_segment_stream));

  SegmentStream move_constructed_segment_stream =
      std::move(uncleared_segment_stream);

  ASSERT_FALSE(IsCleared(move_constructed_segment_stream));
}

TEST(SegmentStreamTest, MoveConstructorShouldSetIsAtEndWhenRhsIsAtEnd) {
  SegmentStream at_end_segment_stream;
  ASSERT_TRUE(IsAtEnd(at_end_segment_stream));

  SegmentStream move_constructed_segment_stream =
      std::move(at_end_segment_stream);

  ASSERT_TRUE(IsAtEnd(move_constructed_segment_stream));
}

TEST(SegmentStreamTest, MoveConstructorShouldUnsetIsAtEndWhenRhsIsNotAtEnd) {
  SegmentStream not_at_end_segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsAtEnd(not_at_end_segment_stream));

  SegmentStream move_constructed_segment_stream =
      std::move(not_at_end_segment_stream);

  ASSERT_FALSE(IsAtEnd(move_constructed_segment_stream));
}

TEST(SegmentStreamTest, MoveContructorShouldCopyRhsPosition) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  segment_stream.seek(kInsideBufferPosition);
  ASSERT_EQ(kInsideBufferPosition, segment_stream.getPosition());

  SegmentStream move_constructed_segment_stream = std::move(segment_stream);

  ASSERT_EQ(kInsideBufferPosition,
            move_constructed_segment_stream.getPosition());
}

TEST(SegmentStreamTest, MoveConstructorShouldCopyRhsLength) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_EQ(kBufferAllocationSize, segment_stream.getLength());

  SegmentStream move_constructed_segment_stream = std::move(segment_stream);

  ASSERT_EQ(kBufferAllocationSize, move_constructed_segment_stream.getLength());
}

TEST(SegmentStreamTest,
     MoveAssignmentOperatorShouldSetIsClearedWhenRhsIsCleared) {
  SegmentStream cleared_segment_stream;
  ASSERT_TRUE(IsCleared(cleared_segment_stream));

  SegmentStream move_assigned_segment_stream;
  move_assigned_segment_stream = std::move(cleared_segment_stream);

  ASSERT_TRUE(IsCleared(move_assigned_segment_stream));
}

TEST(SegmentStreamTest,
     MoveAssignmentOperatorShouldUnsetIsClearedWhenRhsIsNotCleared) {
  SegmentStream uncleared_segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsCleared(uncleared_segment_stream));

  SegmentStream move_assigned_segment_stream;
  move_assigned_segment_stream = std::move(uncleared_segment_stream);

  ASSERT_FALSE(IsCleared(move_assigned_segment_stream));
}

TEST(SegmentStreamTest, MoveAssignmentOperatorShouldSetIsAtEndWhenRhsIsAtEnd) {
  SegmentStream at_end_segment_stream;
  ASSERT_TRUE(IsAtEnd(at_end_segment_stream));

  SegmentStream move_assigned_segment_stream;
  move_assigned_segment_stream = std::move(at_end_segment_stream);

  ASSERT_TRUE(IsAtEnd(move_assigned_segment_stream));
}

TEST(SegmentStreamTest,
     MoveAssignmentOperatorShouldUnsetIsAtEndWhenRhsIsNotAtEnd) {
  SegmentStream not_at_end_segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsAtEnd(not_at_end_segment_stream));

  SegmentStream move_assigned_segment_stream;
  move_assigned_segment_stream = std::move(not_at_end_segment_stream);

  ASSERT_FALSE(IsAtEnd(move_assigned_segment_stream));
}

TEST(SegmentStreamTest, MoveAssignmentOperatorShouldCopyRhsPosition) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  segment_stream.seek(kInsideBufferPosition);
  ASSERT_EQ(kInsideBufferPosition, segment_stream.getPosition());

  SegmentStream move_assigned_segment_stream;
  move_assigned_segment_stream = std::move(segment_stream);

  ASSERT_EQ(kInsideBufferPosition, move_assigned_segment_stream.getPosition());
}

TEST(SegmentStreamTest, MoveAssignmentOperatorShouldCopyRhsLength) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_EQ(kBufferAllocationSize, segment_stream.getLength());

  SegmentStream move_assigned_segment_stream;
  move_assigned_segment_stream = std::move(segment_stream);

  ASSERT_EQ(kBufferAllocationSize, move_assigned_segment_stream.getLength());
}

TEST(SegmentStreamTest, SetReaderShouldUnsetIsCleared) {
  SegmentStream segment_stream;
  scoped_refptr<SegmentReader> segment_reader = CreateSegmentReader();
  ASSERT_TRUE(IsCleared(segment_stream));

  segment_stream.SetReader(segment_reader);

  ASSERT_FALSE(IsCleared(segment_stream));
}

TEST(SegmentStreamTest, SetReaderShouldUnsetIsAtEnd) {
  SegmentStream segment_stream;
  scoped_refptr<SegmentReader> segment_reader = CreateSegmentReader();
  ASSERT_TRUE(IsAtEnd(segment_stream));

  segment_stream.SetReader(segment_reader);

  ASSERT_FALSE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest, SetReaderShouldNotChangePosition) {
  SegmentStream segment_stream;
  scoped_refptr<SegmentReader> segment_reader = CreateSegmentReader();
  ASSERT_TRUE(PositionIsZero(segment_stream));

  segment_stream.SetReader(segment_reader);

  ASSERT_TRUE(PositionIsZero(segment_stream));
}

TEST(SegmentStreamTest, SetReaderShouldUpdateLength) {
  SegmentStream segment_stream;
  scoped_refptr<SegmentReader> segment_reader = CreateSegmentReader();
  ASSERT_FALSE(LengthIsAllocationSize(segment_stream));

  segment_stream.SetReader(segment_reader);

  ASSERT_TRUE(LengthIsAllocationSize(segment_stream));
}

TEST(SegmentStreamTest, SetReaderShouldSetIsClearedWhenSetToNull) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsCleared(segment_stream));

  segment_stream.SetReader(nullptr);

  ASSERT_TRUE(IsCleared(segment_stream));
}

TEST(SegmentStreamTest, SetReaderShouldSetIsClearedWhenReaderSizeNotBigEnough) {
  SegmentStream segment_stream;
  segment_stream.seek(kPastEndOfBufferPosition);
  scoped_refptr<SegmentReader> segment_reader = CreateSegmentReader();

  segment_stream.SetReader(segment_reader);

  ASSERT_TRUE(IsCleared(segment_stream));
}

TEST(SegmentStreamTest, SetReaderShouldSetIsAtEndWhenReaderSizeNotBigEnough) {
  SegmentStream segment_stream;
  segment_stream.seek(kPastEndOfBufferPosition);
  scoped_refptr<SegmentReader> segment_reader = CreateSegmentReader();

  segment_stream.SetReader(segment_reader);

  ASSERT_TRUE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest,
     SetReaderShouldNotChangePositionWhenReaderSizeNotBigEnough) {
  SegmentStream segment_stream;
  segment_stream.seek(kPastEndOfBufferPosition);
  scoped_refptr<SegmentReader> segment_reader = CreateSegmentReader();

  segment_stream.SetReader(segment_reader);

  ASSERT_EQ(kPastEndOfBufferPosition, segment_stream.getPosition());
}

TEST(SegmentStreamTest, SetReaderShouldChangeLengthWhenReaderSizeNotBigEnough) {
  SegmentStream segment_stream;
  segment_stream.seek(kPastEndOfBufferPosition);
  scoped_refptr<SegmentReader> segment_reader = CreateSegmentReader();

  segment_stream.SetReader(segment_reader);

  ASSERT_TRUE(LengthIsAllocationSize(segment_stream));
}

TEST(SegmentStreamTest, SetReaderShouldSetIsAtEndWhenSetToNull) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsAtEnd(segment_stream));

  segment_stream.SetReader(nullptr);
  ASSERT_TRUE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest, SetReaderShouldNotChangePositionWhenSetToNull) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  const size_t amount_read = ReadFromSegmentStream(segment_stream);
  ASSERT_EQ(kInsideBufferPosition, amount_read);
  const size_t pre_nulled_position = segment_stream.getPosition();
  ASSERT_EQ(kInsideBufferPosition, pre_nulled_position);

  segment_stream.SetReader(nullptr);

  ASSERT_EQ(kInsideBufferPosition, segment_stream.getPosition());
}

TEST(SegmentStreamTest, SetReaderShouldClearLengthWhenSetToNull) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(LengthIsZero(segment_stream));

  segment_stream.SetReader(nullptr);

  ASSERT_TRUE(LengthIsZero(segment_stream));
}

TEST(SegmentStreamTest, ReadShouldConsumeBuffer) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();

  const size_t amount_read = ReadFromSegmentStream(segment_stream);

  ASSERT_EQ(kInsideBufferPosition, amount_read);
}

TEST(SegmentStreamTest, ReadShouldNotClear) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();

  ReadFromSegmentStream(segment_stream);

  ASSERT_FALSE(IsCleared(segment_stream));
}

TEST(SegmentStreamTest, ReadShouldUpdateIsAtEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsAtEnd(segment_stream));

  ReadFromSegmentStream(segment_stream, kBufferAllocationSize);

  ASSERT_TRUE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest, ReadShouldUpdatePosition) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_TRUE(PositionIsZero(segment_stream));

  ReadFromSegmentStream(segment_stream);

  ASSERT_TRUE(PositionIsInsideBuffer(segment_stream));
}

TEST(SegmentStreamTest, ReadShouldNotChangeLength) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_EQ(kBufferAllocationSize, segment_stream.getLength());

  ReadFromSegmentStream(segment_stream);

  ASSERT_EQ(kBufferAllocationSize, segment_stream.getLength());
}

TEST(SegmentStreamTest, ReadShouldConsumeBufferWithoutGoingPastTheEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();

  const size_t amount_read =
      ReadFromSegmentStream(segment_stream, kPastEndOfBufferPosition);

  ASSERT_EQ(kBufferAllocationSize, amount_read);
}

TEST(SegmentStreamTest, ReadShouldSetIsAtEndWhenPastEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsAtEnd(segment_stream));

  ReadFromSegmentStream(segment_stream, kPastEndOfBufferPosition);

  ASSERT_TRUE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest, ReadShouldTruncatePositionWhenPastEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_TRUE(PositionIsZero(segment_stream));

  ReadFromSegmentStream(segment_stream, kPastEndOfBufferPosition);

  ASSERT_TRUE(PositionIsAtEndOfBuffer(segment_stream));
}

TEST(SegmentStreamTest, PeekShouldConsumeBuffer) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();

  const size_t amount_peeked = PeekIntoSegmentStream(segment_stream);

  ASSERT_EQ(kInsideBufferPosition, amount_peeked);
}

TEST(SegmentStreamTest, PeekShouldNotClear) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();

  PeekIntoSegmentStream(segment_stream);

  ASSERT_FALSE(IsCleared(segment_stream));
}

TEST(SegmentStreamTest, PeekShouldNotUpdateIsAtEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsAtEnd(segment_stream));

  PeekIntoSegmentStream(segment_stream, kBufferAllocationSize);

  ASSERT_FALSE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest, PeekShouldNotUpdatePosition) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_TRUE(PositionIsZero(segment_stream));

  PeekIntoSegmentStream(segment_stream);

  ASSERT_TRUE(PositionIsZero(segment_stream));
}

TEST(SegmentStreamTest, PeekShouldNotChangeLength) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();

  PeekIntoSegmentStream(segment_stream);

  ASSERT_EQ(kBufferAllocationSize, segment_stream.getLength());
}

TEST(SegmentStreamTest, PeekShouldConsumeBufferWithoutGoingPastTheEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();

  const size_t amount_peeked =
      PeekIntoSegmentStream(segment_stream, kPastEndOfBufferPosition);

  ASSERT_EQ(kBufferAllocationSize, amount_peeked);
}

TEST(SegmentStreamTest, PeekShouldNotSetIsAtEndWhenPastEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsAtEnd(segment_stream));

  PeekIntoSegmentStream(segment_stream, kPastEndOfBufferPosition);

  ASSERT_FALSE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest, PeekShouldNotTruncatePositionWhenPastEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_TRUE(PositionIsZero(segment_stream));

  PeekIntoSegmentStream(segment_stream, kPastEndOfBufferPosition);

  ASSERT_TRUE(PositionIsZero(segment_stream));
}

TEST(SegmentStreamTest, RewindShouldNotClear) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ReadFromSegmentStream(segment_stream);
  ASSERT_FALSE(IsCleared(segment_stream));

  segment_stream.rewind();

  ASSERT_FALSE(IsCleared(segment_stream));
}

TEST(SegmentStreamTest, RewindShouldNotSetAtEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ReadFromSegmentStream(segment_stream);
  ASSERT_FALSE(IsAtEnd(segment_stream));

  segment_stream.rewind();

  ASSERT_FALSE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest, RewindShouldResetPosition) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ReadFromSegmentStream(segment_stream);
  ASSERT_TRUE(PositionIsInsideBuffer(segment_stream));

  segment_stream.rewind();

  ASSERT_TRUE(PositionIsZero(segment_stream));
}

TEST(SegmentStreamTest, RewindShouldNotChangeLength) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ReadFromSegmentStream(segment_stream);

  segment_stream.rewind();

  ASSERT_EQ(kBufferAllocationSize, segment_stream.getLength());
}

TEST(SegmentStreamTest, HasPositionShouldBeSupported) {
  SegmentStream segment_stream;

  ASSERT_TRUE(segment_stream.hasPosition());
}

TEST(SegmentStreamTest, SeekShouldNotSetIsCleared) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsCleared(segment_stream));

  segment_stream.seek(kInsideBufferPosition);

  ASSERT_FALSE(IsCleared(segment_stream));
}

TEST(SegmentStreamTest, SeekShouldNotSetIsAtEndWhenSeekingInsideTheBuffer) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsAtEnd(segment_stream));

  segment_stream.seek(kInsideBufferPosition);

  ASSERT_FALSE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest, SeekShouldSetIsAtEndWhenSeekingToTheEndOfTheBuffer) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_FALSE(IsAtEnd(segment_stream));

  segment_stream.seek(kBufferAllocationSize);

  ASSERT_TRUE(IsAtEnd(segment_stream));
}

TEST(SegmentStreamTest, SeekShouldUpdatePosition) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_TRUE(PositionIsZero(segment_stream));

  segment_stream.seek(kInsideBufferPosition);

  ASSERT_EQ(kInsideBufferPosition, segment_stream.getPosition());
}

TEST(SegmentStreamTest, SeekShouldNotTruncatePositionWhenPastEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_TRUE(PositionIsZero(segment_stream));

  segment_stream.seek(kPastEndOfBufferPosition);

  ASSERT_EQ(kPastEndOfBufferPosition, segment_stream.getPosition());
}

TEST(SegmentStreamTest, SeekShouldNotUpdateLength) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();

  segment_stream.seek(kInsideBufferPosition);

  ASSERT_EQ(kBufferAllocationSize, segment_stream.getLength());
}

TEST(SegmentStreamTest, MoveShouldNotSetCleared) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();

  segment_stream.move(kInsideBufferPosition);

  ASSERT_FALSE(IsCleared(segment_stream));
}

TEST(SegmentStreamTest, MoveShouldUpdatePosition) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_TRUE(PositionIsZero(segment_stream));

  segment_stream.move(kInsideBufferPosition);

  ASSERT_TRUE(PositionIsInsideBuffer(segment_stream));
}

TEST(SegmentStreamTest, MoveShouldNotTruncatePositionWhenPastEnd) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_TRUE(PositionIsZero(segment_stream));

  segment_stream.move(kPastEndOfBufferPosition);

  ASSERT_EQ(kPastEndOfBufferPosition, segment_stream.getPosition());
}

TEST(SegmentStreamTest, MoveShouldNotChangeLength) {
  SegmentStream segment_stream = CreatePopulatedSegmentStream();
  ASSERT_TRUE(LengthIsAllocationSize(segment_stream));

  segment_stream.move(kInsideBufferPosition);

  ASSERT_TRUE(LengthIsAllocationSize(segment_stream));
}

TEST(SegmentStreamTest, HasLengthShouldBeSupported) {
  SegmentStream segment_stream;
  ASSERT_TRUE(segment_stream.hasLength());
}

TEST(SegmentStreamTest, BasicReadingTest) {
  scoped_refptr<SharedBuffer> buffer = SharedBuffer::Create();
  buffer->Append(std::string_view("0123456789"));
  scoped_refptr<SegmentReader> reader =
      SegmentReader::CreateFromSharedBuffer(buffer);

  SegmentStream stream;
  stream.SetReader(reader);
  EXPECT_EQ(0u, stream.getPosition());

  std::vector<uint8_t> output(1024, 0x00);
  size_t read_bytes = stream.read(output.data(), output.size());
  std::string_view result =
      base::as_string_view(base::span(output).first(read_bytes));
  EXPECT_EQ("0123456789", result);
  EXPECT_EQ(10u, stream.getPosition());
}

TEST(SegmentStreamTest, OffsetReadingTest) {
  scoped_refptr<SharedBuffer> buffer = SharedBuffer::Create();
  buffer->Append(std::string_view("0123456789"));
  scoped_refptr<SegmentReader> reader =
      SegmentReader::CreateFromSharedBuffer(buffer);

  constexpr size_t kOffset = 5;
  SegmentStream stream(kOffset);
  stream.SetReader(reader);
  EXPECT_EQ(0u, stream.getPosition());

  // Test basic reading.
  std::vector<uint8_t> output(1024, 0x00);
  size_t read_bytes = stream.read(output.data(), output.size());
  std::string_view result =
      base::as_string_view(base::span(output).first(read_bytes));
  EXPECT_EQ("56789", result);
  EXPECT_EQ(5u, stream.getPosition());

  // Test that rewinding takes reading offset into account.
  ASSERT_TRUE(stream.rewind());
  EXPECT_EQ(0u, stream.getPosition());

  read_bytes = stream.read(output.data(), output.size());
  result = base::as_string_view(base::span(output).first(read_bytes));
  EXPECT_EQ("56789", result);
  EXPECT_EQ(5u, stream.getPosition());

  // Test that seeking takes reading offset into account.
  ASSERT_TRUE(stream.seek(2));
  EXPECT_EQ(2u, stream.getPosition());

  read_bytes = stream.read(output.data(), output.size());
  result = base::as_string_view(base::span(output).first(read_bytes));
  EXPECT_EQ("789", result);
  EXPECT_EQ(5u, stream.getPosition());
}

namespace {

::testing::AssertionResult IsCleared(const SegmentStream& segment_stream) {
  if (segment_stream.IsCleared()) {
    return ::testing::AssertionSuccess();
  }

  return ::testing::AssertionFailure() << "SegmentStream is not clear";
}

::testing::AssertionResult IsAtEnd(const SegmentStream& segment_stream) {
  if (segment_stream.isAtEnd()) {
    return ::testing::AssertionSuccess();
  }

  return ::testing::AssertionFailure() << "SegmentStream is not at the end";
}

::testing::AssertionResult PositionIsZero(const SegmentStream& segment_stream) {
  if (segment_stream.getPosition() == 0ul) {
    return ::testing::AssertionSuccess();
  }

  return ::testing::AssertionFailure() << "SegmentStream position is not 0";
}

::testing::AssertionResult PositionIsInsideBuffer(
    const SegmentStream& segment_stream) {
  if (segment_stream.getPosition() == kInsideBufferPosition) {
    return ::testing::AssertionSuccess();
  }

  return ::testing::AssertionFailure()
         << "SegmentStream position is not inside the buffer";
}

::testing::AssertionResult PositionIsAtEndOfBuffer(
    const SegmentStream& segment_stream) {
  if (segment_stream.getPosition() == kBufferAllocationSize) {
    return ::testing::AssertionSuccess();
  }

  return ::testing::AssertionFailure()
         << "SegmentStream position is not at the end of the buffer";
}

::testing::AssertionResult LengthIsZero(const SegmentStream& segment_stream) {
  if (segment_stream.getLength() == 0ul) {
    return ::testing::AssertionSuccess();
  }

  return ::testing::AssertionFailure() << "SegmentStream length is not 0";
}

::testing::AssertionResult LengthIsAllocationSize(
    const SegmentStream& segment_stream) {
  if (segment_stream.getLength() == kBufferAllocationSize) {
    return ::testing::AssertionSuccess();
  }

  return ::testing::AssertionFailure()
         << "SegmentStream length is not the allocation size";
}

SegmentStream CreatePopulatedSegmentStream() {
  SegmentStream segment_stream;
  segment_stream.SetReader(CreateSegmentReader());
  return segment_stream;
}

scoped_refptr<SegmentReader> CreateSegmentReader() {
  Vector<char> raw_buffer(kBufferAllocationSize);

  scoped_refptr<SharedBuffer> shared_buffer =
      SharedBuffer::Create(raw_buffer.data(), kBufferAllocationSize);

  scoped_refptr<SegmentReader> segment_reader =
      SegmentReader::CreateFromSharedBuffer(std::move(shared_buffer));

  return segment_reader;
}

size_t ReadFromSegmentStream(SegmentStream& segment_stream,
                             size_t amount_to_read) {
  Vector<char> read_buffer(kBufferAllocationSize);
  return segment_stream.read(read_buffer.data(), amount_to_read);
}

size_t PeekIntoSegmentStream(SegmentStream& segment_stream,
                             size_t amount_to_peek) {
  Vector<char> peek_buffer(kBufferAllocationSize);
  return segment_stream.peek(peek_buffer.data(), amount_to_peek);
}

}  // namespace
}  // namespace blink
```