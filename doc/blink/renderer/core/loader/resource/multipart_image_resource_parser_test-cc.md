Response:
My thinking process to answer the request about `multipart_image_resource_parser_test.cc` goes like this:

1. **Understand the Core Function:** The filename immediately suggests this is a *test* file. The presence of "multipart_image_resource_parser" points to the component being tested. Therefore, the primary function is to test the `MultipartImageResourceParser` class.

2. **Analyze the Includes:** The included headers provide clues about the dependencies and context:
    * `multipart_image_resource_parser.h`:  Confirms that the parser class is being tested.
    * `<stddef.h>`, `<stdint.h>`, `<string.h>`: Standard C library headers, likely used for basic data manipulation.
    * `base/numerics/safe_conversions.h`: Suggests dealing with numerical conversions, potentially related to data sizes or offsets.
    * `testing/gtest/include/gtest/gtest.h`:  Explicitly indicates the use of the Google Test framework for unit testing.
    * `third_party/blink/renderer/platform/loader/fetch/resource_response.h`:  Indicates interaction with resource loading and HTTP responses. This is crucial for understanding the context of the parser.
    * `third_party/blink/renderer/platform/network/http_names.h`:  Shows the use of standard HTTP header names.

3. **Examine the Test Structure:** The code uses the Google Test framework, so I look for `TEST()` macros. Each `TEST()` block represents a distinct test case for a specific aspect of the parser. I'll go through each test case and summarize its purpose.

4. **Identify Key Test Scenarios:**  As I go through the `TEST()` blocks, I categorize the types of scenarios being tested. Common patterns emerge:
    * **Boundary Detection:** Testing the ability to correctly identify multipart boundaries.
    * **Handling Different Boundary Conditions:** Testing cases with missing start or end boundaries, malformed boundaries (like the `--` prefix).
    * **Data Chunking:** Testing how the parser handles data arriving in chunks of various sizes and at different points (boundary, headers, data).
    * **Empty/Small Chunks:** Testing the parser's robustness with very small or empty data chunks.
    * **Leading Whitespace:** Testing how the parser handles leading whitespace (LF and CRLF) before the first boundary.

5. **Analyze the `MockClient`:** The `MockClient` class is a crucial part of the testing setup. It implements the `MultipartImageResourceParser::Client` interface. This tells me how the parser interacts with its clients: it calls `OnePartInMultipartReceived` when a new part is identified and `MultipartDataReceived` when data belonging to a part arrives. The `MockClient` stores these calls and the associated data, allowing the tests to verify the parser's behavior.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Based on the understanding of the parser and its context (resource loading, HTTP responses), I consider how this relates to web technologies:
    * **`multipart/x-mixed-replace`:** This MIME type is explicitly used and is a key indicator. It's often used for server-push scenarios where the browser expects a stream of independent resources (often images).
    * **HTML `<img>` tag:**  The most direct connection is with the `<img>` tag. If the `src` of an `<img>` points to a resource served with `multipart/x-mixed-replace`, the browser will use a parser like this to process the stream of images.
    * **JavaScript `fetch()`:**  JavaScript can also fetch resources served with this MIME type. The browser's fetch API would handle the multipart parsing internally.
    * **No direct CSS relation:**  While CSS can trigger image requests, it doesn't directly interact with the parsing of multipart responses in the same way as HTML or JavaScript.

7. **Infer Logic and Provide Examples:**  For the tests involving boundary detection and skipping whitespace, I can infer the underlying logic. I then create simple "input/output" examples to illustrate how these functions work.

8. **Identify Potential User/Developer Errors:** I consider how incorrect server-side implementation or misunderstandings of the multipart format could lead to issues that these tests are designed to catch. This leads to examples of common errors.

9. **Trace User Operations:** I think about the user actions that would lead to the browser needing to use this parser. The core action is loading a resource (usually an image) from a server that uses `multipart/x-mixed-replace`.

10. **Structure the Answer:** Finally, I organize the information logically, starting with the high-level function and then drilling down into details, providing examples, and connecting the concepts to web technologies. I use clear headings and bullet points to improve readability. I ensure I address all parts of the original request.
这个C++源代码文件 `multipart_image_resource_parser_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `MultipartImageResourceParser` 类的功能。这个类负责解析 `multipart/x-mixed-replace` 类型的 HTTP 响应，这种响应通常用于流式传输一系列独立的资源，最常见的是图片。

以下是该文件的功能详细列表，并解释了它与 JavaScript、HTML 和 CSS 的关系，以及一些逻辑推理、常见错误和调试线索：

**文件主要功能：**

1. **单元测试 `MultipartImageResourceParser` 类:**  该文件包含了多个使用 Google Test 框架编写的测试用例，用于验证 `MultipartImageResourceParser` 类的各种功能和边界情况。

2. **测试边界查找功能:**  测试 `MultipartImageResourceParser` 正确查找 multipart 消息中分隔各个部分的边界字符串的能力。

3. **测试跳过前导换行符的功能:** 验证解析器能够正确处理和跳过 multipart 消息中各个部分之前可能存在的前导换行符 (`\n` 或 `\r\n`)。

4. **测试处理各种格式的 multipart 消息:**  测试用例涵盖了各种 multipart 消息的格式，包括：
    * 正常的带有起始和结束边界的情况。
    * 缺少起始边界的情况。
    * 缺少结束边界的情况。
    * 同时缺少起始和结束边界的情况。
    * 边界字符串前带有 `--` 前缀的（一些服务器可能会这样发送）。

5. **测试分块接收数据的情况:**  模拟网络传输中数据分块到达的情况，测试解析器在接收到不同大小的数据块时是否能正确解析 multipart 消息。

6. **测试处理错误格式的边界:**  验证解析器在遇到非标准的边界字符串时是否能按预期工作。

7. **模拟客户端行为:**  通过 `MockClient` 类模拟 `MultipartImageResourceParser` 的客户端，记录解析器解析出的每个部分的回应头和数据。

**与 JavaScript, HTML, CSS 的关系：**

`MultipartImageResourceParser` 主要用于处理通过 HTTP 获取的资源，因此它与 JavaScript 和 HTML 有着密切的关系。CSS 的关系相对间接。

* **HTML (`<img>` 标签):** 当 HTML 中的 `<img>` 标签的 `src` 属性指向一个返回 `multipart/x-mixed-replace` 类型的 URL 时，浏览器会使用 `MultipartImageResourceParser` 来解析响应流。服务器会不断推送新的图片数据，浏览器接收到后会更新显示的图片，实现动态更新的效果（例如，MJPEG 流）。
    * **例子:**
        ```html
        <img src="http://example.com/stream.mjpeg">
        ```
        当浏览器请求 `stream.mjpeg` 并且服务器返回 `Content-Type: multipart/x-mixed-replace; boundary=--myboundary` 的响应时，`MultipartImageResourceParser` 就会被用来解析后续到达的图片数据。

* **JavaScript (`fetch()` API, `XMLHttpRequest`):** JavaScript 可以使用 `fetch()` API 或 `XMLHttpRequest` 对象来请求返回 `multipart/x-mixed-replace` 类型的资源。 浏览器内部会使用 `MultipartImageResourceParser` 来处理响应。开发者可以通过监听事件来获取解析出的每个部分的数据。
    * **例子 (使用 `fetch()`):**
        ```javascript
        fetch('http://example.com/stream.mjpeg')
          .then(response => {
            const reader = response.body.getReader();
            let processing = false;

            function read() {
              reader.read().then(({ done, value }) => {
                if (done) {
                  console.log('Stream finished');
                  return;
                }
                // 在这里，value 包含了新到达的数据，浏览器内部的解析器会处理它
                // 你可能需要进一步处理 value 以提取完整的图片数据
                console.log('Received data:', value);
                read();
              });
            }
            read();
          });
        ```

* **CSS (间接关系):** CSS 可以通过 `background-image` 等属性引用图片资源。如果这些图片资源是通过返回 `multipart/x-mixed-replace` 的 URL 提供，那么 `MultipartImageResourceParser` 也会参与到这些图片的加载过程中。
    * **例子:**
        ```css
        .dynamic-image {
          background-image: url('http://example.com/stream.mjpeg');
        }
        ```
        在这种情况下，浏览器会像处理 `<img>` 标签一样处理这个 CSS 背景图片。

**逻辑推理的假设输入与输出：**

以下是一些基于测试用例的假设输入和输出示例：

* **测试 `SkippableLength` (跳过前导换行符):**
    * **假设输入:**  `input = "\r\nLine"`, `position = 0`
    * **预期输出:** `2` (表示应该跳过 2 个字符，即 `\r\n`)

    * **假设输入:**  `input = "Line\nLine"`, `position = 4`
    * **预期输出:** `1` (表示应该跳过 1 个字符，即 `\n`)

* **测试 `FindBoundary` (查找边界):**
    * **假设输入:** `boundary = "bound"`, `data = "--bound"`
    * **预期输出:** `0` (表示边界从数据的第 0 个位置开始)

    * **假设输入:** `boundary = "bound"`, `data = "junk--bound"`
    * **预期输出:** `4` (表示边界从数据的第 4 个位置开始)

* **测试完整的 multipart 解析:**
    * **假设输入 (kData):**
        ```
        "--bound\n"
        "Content-type: image/png\n\n"
        "datadatadatadatadata"
        "--bound\n"
        "Content-type: image/jpg\n\n"
        "foofoofoofoofoo"
        "--bound--"
        ```
    * **假设边界 (boundary):** `"bound"`
    * **预期输出 (MockClient 的状态):**
        * `client->responses_[0]` 的 Content-Type 为 `image/png`，`client->data_[0]` 为 `"datadatadatadatadata"`。
        * `client->responses_[1]` 的 Content-Type 为 `image/jpg`，`client->data_[1]` 为 `"foofoofoofoofoo"`。

**涉及用户或者编程常见的使用错误：**

* **服务器端配置错误:** 服务器没有正确设置 `Content-Type` 为 `multipart/x-mixed-replace`，或者边界字符串不匹配。这将导致浏览器无法正确解析响应。
    * **例子:** 服务器发送了 `Content-Type: text/html` 但实际内容是 multipart 消息。
* **边界字符串不一致:**  服务器在 HTTP 头的 `boundary` 参数中指定的边界字符串与实际消息中使用的边界字符串不一致。
    * **例子:**  HTTP 头中指定 `boundary=--myboundary`，但消息中使用的是 `--otherboundary`。
* **不正确的边界格式:**  开发者可能错误地认为边界总是以 `--` 开头，而忽略了 RFC 规定的其他可能性。
* **网络传输中断或不完整:**  如果网络连接不稳定，导致 multipart 消息传输中断，`MultipartImageResourceParser` 可能无法解析出完整的资源。
* **客户端代码处理错误:**  JavaScript 开发者可能没有正确处理 `fetch()` 或 `XMLHttpRequest` 返回的流数据，导致数据丢失或解析错误。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问包含动态图片的网页:** 用户在浏览器中打开一个网页，该网页包含一个 `<img>` 标签，其 `src` 属性指向一个返回 `multipart/x-mixed-replace` 类型的 URL，或者网页通过 JavaScript 发起这样的请求。

2. **浏览器发起 HTTP 请求:** 浏览器向服务器发送 HTTP 请求以获取该 URL 的资源。

3. **服务器返回 multipart 响应:** 服务器响应这个请求，HTTP 头的 `Content-Type` 为 `multipart/x-mixed-replace`，并包含一个 `boundary` 参数。响应体包含由边界字符串分隔的多个部分，每个部分通常包含一个图片。

4. **Blink 渲染引擎接收响应:**  Blink 渲染引擎的网络模块接收到服务器的响应。

5. **创建 `MultipartImageResourceParser`:** 由于响应的 `Content-Type` 是 `multipart/x-mixed-replace`，Blink 会创建一个 `MultipartImageResourceParser` 对象来处理响应体。

6. **数据流式传输和解析:** 服务器开始流式传输 multipart 消息的数据。`MultipartImageResourceParser` 会逐步接收这些数据块，并根据边界字符串将数据分割成不同的部分。

7. **回调客户端:**  对于解析出的每个部分，`MultipartImageResourceParser` 会调用其客户端（例如，负责处理图像的模块）的回调函数，传递该部分的回应头和数据。

8. **图片渲染或处理:**  客户端接收到图片数据后，会将其解码并在页面上渲染（如果是 `<img>` 标签），或者传递给 JavaScript 代码进行进一步处理。

**调试线索:**

当出现与 `multipart/x-mixed-replace` 相关的图片显示问题时，可以考虑以下调试线索：

* **检查服务器响应头:** 使用开发者工具的网络面板检查服务器返回的 HTTP 响应头，特别是 `Content-Type` 和 `boundary` 参数是否正确。
* **检查响应体内容:**  查看响应体的内容，确认边界字符串是否正确，各个部分的数据格式是否符合预期。
* **断点调试 `MultipartImageResourceParser`:**  如果怀疑是解析器的问题，可以在 `multipart_image_resource_parser_test.cc` 中相关的测试用例中设置断点，或者在实际运行的 Blink 代码中设置断点，跟踪数据是如何被解析的。
* **查看控制台错误信息:**  浏览器控制台可能会输出与资源加载或解析相关的错误信息。
* **使用网络抓包工具:**  使用 Wireshark 或 Chrome 的网络面板导出 HAR 文件，可以详细分析网络传输过程中的数据包，检查数据是否完整、边界是否正确。

总而言之，`multipart_image_resource_parser_test.cc` 是确保 Chromium Blink 引擎能够正确处理 `multipart/x-mixed-replace` 响应的关键组成部分，这对于实现动态更新的图片显示功能至关重要。它通过详尽的测试用例覆盖了各种场景，帮助开发者避免潜在的错误。

Prompt: 
```
这是目录为blink/renderer/core/loader/resource/multipart_image_resource_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/resource/multipart_image_resource_parser.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base/numerics/safe_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/network/http_names.h"

namespace blink {
namespace multipart_image_resource_parser_test {

String ToString(const Vector<char>& data) {
  if (data.empty())
    return String("");
  return String(data);
}

class MockClient final : public GarbageCollected<MockClient>,
                         public MultipartImageResourceParser::Client {
 public:
  void OnePartInMultipartReceived(const ResourceResponse& response) override {
    responses_.push_back(response);
    data_.push_back(Vector<char>());
  }
  void MultipartDataReceived(base::span<const uint8_t> bytes) override {
    data_.back().AppendSpan(bytes);
  }

  Vector<ResourceResponse> responses_;
  Vector<Vector<char>> data_;
};

TEST(MultipartResponseTest, SkippableLength) {
  struct TestData {
    const std::string_view input;
    const wtf_size_t position;
    const wtf_size_t expected;
  };
  const auto line_tests = std::to_array<TestData>({
      {"Line", 0, 0},
      {"Line", 2, 0},
      {"Line", 10, 0},
      {"\r\nLine", 0, 2},
      {"\nLine", 0, 1},
      {"\n\nLine", 0, 1},
      {"\rLine", 0, 0},
      {"Line\r\nLine", 4, 2},
      {"Line\nLine", 4, 1},
      {"Line\n\nLine", 4, 1},
      {"Line\rLine", 4, 0},
      {"Line\r\rLine", 4, 0},
  });
  for (const auto& test : line_tests) {
    Vector<char> input;
    input.AppendSpan(base::span(test.input));
    EXPECT_EQ(test.expected,
              MultipartImageResourceParser::SkippableLengthForTest(
                  input, test.position));
  }
}

TEST(MultipartResponseTest, FindBoundary) {
  struct TestData {
    const std::string_view boundary;
    const std::string_view data;
    const size_t position;
  };
  const auto boundary_tests = std::to_array<TestData>({
      {"bound", "bound", 0},
      {"bound", "--bound", 0},
      {"bound", "junkbound", 4},
      {"bound", "junk--bound", 4},
      {"foo", "bound", kNotFound},
      {"bound", "--boundbound", 0},
  });

  for (const auto& test : boundary_tests) {
    Vector<char> boundary, data;
    boundary.AppendSpan(base::span(test.boundary));
    data.AppendSpan(base::span(test.data));
    EXPECT_EQ(test.position, MultipartImageResourceParser::FindBoundaryForTest(
                                 data, &boundary));
  }
}

TEST(MultipartResponseTest, NoStartBoundary) {
  ResourceResponse response(NullURL());
  response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  response.SetHttpHeaderField(AtomicString("Foo"), AtomicString("Bar"));
  response.SetHttpHeaderField(http_names::kContentType,
                              AtomicString("text/plain"));
  MockClient* client = MakeGarbageCollected<MockClient>();
  Vector<char> boundary;
  boundary.Append("bound", 5);

  MultipartImageResourceParser* parser =
      MakeGarbageCollected<MultipartImageResourceParser>(response, boundary,
                                                         client);
  const char kData[] =
      "Content-type: text/plain\n\n"
      "This is a sample response\n"
      "--bound--"
      "ignore junk after end token --bound\n\nTest2\n";
  parser->AppendData(base::span_from_cstring(kData));
  ASSERT_EQ(1u, client->responses_.size());
  ASSERT_EQ(1u, client->data_.size());
  EXPECT_EQ("This is a sample response", ToString(client->data_[0]));

  parser->Finish();
  ASSERT_EQ(1u, client->responses_.size());
  ASSERT_EQ(1u, client->data_.size());
  EXPECT_EQ("This is a sample response", ToString(client->data_[0]));
}

TEST(MultipartResponseTest, NoEndBoundary) {
  ResourceResponse response(NullURL());
  response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  response.SetHttpHeaderField(AtomicString("Foo"), AtomicString("Bar"));
  response.SetHttpHeaderField(http_names::kContentType,
                              AtomicString("text/plain"));
  MockClient* client = MakeGarbageCollected<MockClient>();
  Vector<char> boundary;
  boundary.Append("bound", 5);

  MultipartImageResourceParser* parser =
      MakeGarbageCollected<MultipartImageResourceParser>(response, boundary,
                                                         client);
  const char kData[] =
      "bound\nContent-type: text/plain\n\n"
      "This is a sample response\n";
  parser->AppendData(base::span_from_cstring(kData));
  ASSERT_EQ(1u, client->responses_.size());
  ASSERT_EQ(1u, client->data_.size());
  EXPECT_EQ("This is a sample ", ToString(client->data_[0]));

  parser->Finish();
  ASSERT_EQ(1u, client->responses_.size());
  ASSERT_EQ(1u, client->data_.size());
  EXPECT_EQ("This is a sample response\n", ToString(client->data_[0]));
}

TEST(MultipartResponseTest, NoStartAndEndBoundary) {
  ResourceResponse response(NullURL());
  response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  response.SetHttpHeaderField(AtomicString("Foo"), AtomicString("Bar"));
  response.SetHttpHeaderField(http_names::kContentType,
                              AtomicString("text/plain"));
  MockClient* client = MakeGarbageCollected<MockClient>();
  Vector<char> boundary;
  boundary.Append("bound", 5);

  MultipartImageResourceParser* parser =
      MakeGarbageCollected<MultipartImageResourceParser>(response, boundary,
                                                         client);
  const char kData[] =
      "Content-type: text/plain\n\n"
      "This is a sample response\n";
  parser->AppendData(base::span_from_cstring(kData));
  ASSERT_EQ(1u, client->responses_.size());
  ASSERT_EQ(1u, client->data_.size());
  EXPECT_EQ("This is a sample ", ToString(client->data_[0]));

  parser->Finish();
  ASSERT_EQ(1u, client->responses_.size());
  ASSERT_EQ(1u, client->data_.size());
  EXPECT_EQ("This is a sample response\n", ToString(client->data_[0]));
}

TEST(MultipartResponseTest, MalformedBoundary) {
  // Some servers send a boundary that is prefixed by "--".  See bug 5786.
  ResourceResponse response(NullURL());
  response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  response.SetHttpHeaderField(AtomicString("Foo"), AtomicString("Bar"));
  response.SetHttpHeaderField(http_names::kContentType,
                              AtomicString("text/plain"));
  MockClient* client = MakeGarbageCollected<MockClient>();
  Vector<char> boundary;
  boundary.Append("--bound", 7);

  MultipartImageResourceParser* parser =
      MakeGarbageCollected<MultipartImageResourceParser>(response, boundary,
                                                         client);
  const char kData[] =
      "--bound\n"
      "Content-type: text/plain\n\n"
      "This is a sample response\n"
      "--bound--"
      "ignore junk after end token --bound\n\nTest2\n";
  parser->AppendData(base::span_from_cstring(kData));
  ASSERT_EQ(1u, client->responses_.size());
  ASSERT_EQ(1u, client->data_.size());
  EXPECT_EQ("This is a sample response", ToString(client->data_[0]));

  parser->Finish();
  ASSERT_EQ(1u, client->responses_.size());
  ASSERT_EQ(1u, client->data_.size());
  EXPECT_EQ("This is a sample response", ToString(client->data_[0]));
}

// Used in for tests that break the data in various places.
struct TestChunk {
  const size_t start_position;  // offset in data
  const size_t end_position;    // end offset in data
  const size_t expected_responses;
  const std::string_view expected_data;
};

void VariousChunkSizesTest(base::span<const TestChunk> chunks,
                           size_t responses,
                           int received_data,
                           const char* completed_data) {
  const char kData[] =
      "--bound\n"                    // 0-7
      "Content-type: image/png\n\n"  // 8-32
      "datadatadatadatadata"         // 33-52
      "--bound\n"                    // 53-60
      "Content-type: image/jpg\n\n"  // 61-85
      "foofoofoofoofoo"              // 86-100
      "--bound--";                   // 101-109
  const auto data = base::span_from_cstring(kData);

  ResourceResponse response(NullURL());
  response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  MockClient* client = MakeGarbageCollected<MockClient>();
  Vector<char> boundary;
  boundary.Append("bound", 5);

  auto* parser = MakeGarbageCollected<MultipartImageResourceParser>(
      response, boundary, client);

  for (const auto& chunk : chunks) {
    ASSERT_LT(chunk.start_position, chunk.end_position);
    parser->AppendData(data.subspan(chunk.start_position,
                                    chunk.end_position - chunk.start_position));
    EXPECT_EQ(chunk.expected_responses, client->responses_.size());
    EXPECT_EQ(String(chunk.expected_data), client->data_.size() > 0
                                               ? ToString(client->data_.back())
                                               : String(""));
  }
  // Check final state
  parser->Finish();
  EXPECT_EQ(responses, client->responses_.size());
  EXPECT_EQ(completed_data, ToString(client->data_.back()));
}

TEST(MultipartResponseTest, BreakInBoundary) {
  // Break in the first boundary
  const TestChunk kBound1[] = {
      {0, 4, 0, ""}, {4, 110, 2, "foofoofoofoofoo"},
  };
  VariousChunkSizesTest(kBound1, 2, 2, "foofoofoofoofoo");

  // Break in first and second
  const TestChunk kBound2[] = {
      {0, 4, 0, ""},
      {4, 55, 1, "datadatadatad"},
      {55, 65, 1, "datadatadatadatadata"},
      {65, 110, 2, "foofoofoofoofoo"},
  };
  VariousChunkSizesTest(kBound2, 2, 3, "foofoofoofoofoo");

  // Break in second only
  const TestChunk kBound3[] = {
      {0, 55, 1, "datadatadatad"}, {55, 110, 2, "foofoofoofoofoo"},
  };
  VariousChunkSizesTest(kBound3, 2, 3, "foofoofoofoofoo");
}

TEST(MultipartResponseTest, BreakInHeaders) {
  // Break in first header
  const TestChunk kHeader1[] = {
      {0, 10, 0, ""}, {10, 35, 1, ""}, {35, 110, 2, "foofoofoofoofoo"},
  };
  VariousChunkSizesTest(kHeader1, 2, 2, "foofoofoofoofoo");

  // Break in both headers
  const TestChunk kHeader2[] = {
      {0, 10, 0, ""},
      {10, 65, 1, "datadatadatadatadata"},
      {65, 110, 2, "foofoofoofoofoo"},
  };
  VariousChunkSizesTest(kHeader2, 2, 2, "foofoofoofoofoo");

  // Break at end of a header
  const TestChunk kHeader3[] = {
      {0, 33, 1, ""},
      {33, 65, 1, "datadatadatadatadata"},
      {65, 110, 2, "foofoofoofoofoo"},
  };
  VariousChunkSizesTest(kHeader3, 2, 2, "foofoofoofoofoo");
}

TEST(MultipartResponseTest, BreakInData) {
  // All data as one chunk
  const TestChunk kData1[] = {
      {0, 110, 2, "foofoofoofoofoo"},
  };
  VariousChunkSizesTest(kData1, 2, 2, "foofoofoofoofoo");

  // breaks in data segment
  const TestChunk kData2[] = {
      {0, 35, 1, ""},
      {35, 65, 1, "datadatadatadatadata"},
      {65, 90, 2, ""},
      {90, 110, 2, "foofoofoofoofoo"},
  };
  VariousChunkSizesTest(kData2, 2, 2, "foofoofoofoofoo");

  // Incomplete send
  const TestChunk kData3[] = {
      {0, 35, 1, ""}, {35, 90, 2, ""},
  };
  VariousChunkSizesTest(kData3, 2, 2, "foof");
}

TEST(MultipartResponseTest, SmallChunk) {
  ResourceResponse response(NullURL());
  response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  response.SetHttpHeaderField(http_names::kContentType,
                              AtomicString("text/plain"));
  MockClient* client = MakeGarbageCollected<MockClient>();
  Vector<char> boundary;
  boundary.Append("bound", 5);

  MultipartImageResourceParser* parser =
      MakeGarbageCollected<MultipartImageResourceParser>(response, boundary,
                                                         client);

  // Test chunks of size 1, 2, and 0.
  const char kData[] =
      "--boundContent-type: text/plain\n\n"
      "\n--boundContent-type: text/plain\n\n"
      "\n\n--boundContent-type: text/plain\n\n"
      "--boundContent-type: text/plain\n\n"
      "end--bound--";
  parser->AppendData(base::span_from_cstring(kData));
  ASSERT_EQ(4u, client->responses_.size());
  ASSERT_EQ(4u, client->data_.size());
  EXPECT_EQ("", ToString(client->data_[0]));
  EXPECT_EQ("\n", ToString(client->data_[1]));
  EXPECT_EQ("", ToString(client->data_[2]));
  EXPECT_EQ("end", ToString(client->data_[3]));

  parser->Finish();
  ASSERT_EQ(4u, client->responses_.size());
  ASSERT_EQ(4u, client->data_.size());
  EXPECT_EQ("", ToString(client->data_[0]));
  EXPECT_EQ("\n", ToString(client->data_[1]));
  EXPECT_EQ("", ToString(client->data_[2]));
  EXPECT_EQ("end", ToString(client->data_[3]));
}

TEST(MultipartResponseTest, MultipleBoundaries) {
  // Test multiple boundaries back to back
  ResourceResponse response(NullURL());
  response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  MockClient* client = MakeGarbageCollected<MockClient>();
  Vector<char> boundary;
  boundary.Append("bound", 5);

  MultipartImageResourceParser* parser =
      MakeGarbageCollected<MultipartImageResourceParser>(response, boundary,
                                                         client);

  const char kData[] = "--bound\r\n\r\n--bound\r\n\r\nfoofoo--bound--";
  parser->AppendData(base::span_from_cstring(kData));
  ASSERT_EQ(2u, client->responses_.size());
  ASSERT_EQ(2u, client->data_.size());
  EXPECT_EQ("", ToString(client->data_[0]));
  EXPECT_EQ("foofoo", ToString(client->data_[1]));
}

TEST(MultipartResponseTest, EatLeadingLF) {
  ResourceResponse response(NullURL());
  response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  MockClient* client = MakeGarbageCollected<MockClient>();
  Vector<char> boundary;
  boundary.Append("bound", 5);

  MultipartImageResourceParser* parser =
      MakeGarbageCollected<MultipartImageResourceParser>(response, boundary,
                                                         client);
  static constexpr char kData[] =
      "\n\n\n--bound\n\n\ncontent-type: 1\n\n"
      "\n\n\n--bound\n\ncontent-type: 2\n\n"
      "\n\n\n--bound\ncontent-type: 3\n\n";
  for (base::span<const char> data = base::span_from_cstring(kData);
       !data.empty(); data = data.subspan<1>()) {
    parser->AppendData(data.first<1>());
  }
  parser->Finish();

  ASSERT_EQ(4u, client->responses_.size());
  ASSERT_EQ(4u, client->data_.size());
  EXPECT_EQ(String(), client->responses_[0].HttpHeaderField(
                          http_names::kLowerContentType));
  EXPECT_EQ("", ToString(client->data_[0]));
  EXPECT_EQ(String(), client->responses_[1].HttpHeaderField(
                          http_names::kLowerContentType));
  EXPECT_EQ("\ncontent-type: 1\n\n\n\n", ToString(client->data_[1]));
  EXPECT_EQ(String(), client->responses_[2].HttpHeaderField(
                          http_names::kLowerContentType));
  EXPECT_EQ("content-type: 2\n\n\n\n", ToString(client->data_[2]));
  EXPECT_EQ("3", client->responses_[3].HttpHeaderField(
                     http_names::kLowerContentType));
  EXPECT_EQ("", ToString(client->data_[3]));
}

TEST(MultipartResponseTest, EatLeadingCRLF) {
  ResourceResponse response(NullURL());
  response.SetMimeType(AtomicString("multipart/x-mixed-replace"));
  MockClient* client = MakeGarbageCollected<MockClient>();
  Vector<char> boundary;
  boundary.Append("bound", 5);

  MultipartImageResourceParser* parser =
      MakeGarbageCollected<MultipartImageResourceParser>(response, boundary,
                                                         client);
  static constexpr char kData[] =
      "\r\n\r\n\r\n--bound\r\n\r\n\r\ncontent-type: 1\r\n\r\n"
      "\r\n\r\n\r\n--bound\r\n\r\ncontent-type: 2\r\n\r\n"
      "\r\n\r\n\r\n--bound\r\ncontent-type: 3\r\n\r\n";
  for (base::span<const char> data = base::span_from_cstring(kData);
       !data.empty(); data = data.subspan<1>()) {
    parser->AppendData(data.first<1>());
  }
  parser->Finish();

  ASSERT_EQ(4u, client->responses_.size());
  ASSERT_EQ(4u, client->data_.size());
  EXPECT_EQ(String(), client->responses_[0].HttpHeaderField(
                          http_names::kLowerContentType));
  EXPECT_EQ("", ToString(client->data_[0]));
  EXPECT_EQ(String(), client->responses_[1].HttpHeaderField(
                          http_names::kLowerContentType));
  EXPECT_EQ("\r\ncontent-type: 1\r\n\r\n\r\n\r\n", ToString(client->data_[1]));
  EXPECT_EQ(String(), client->responses_[2].HttpHeaderField(
                          http_names::kLowerContentType));
  EXPECT_EQ("content-type: 2\r\n\r\n\r\n\r\n", ToString(client->data_[2]));
  EXPECT_EQ("3", client->responses_[3].HttpHeaderField(
                     http_names::kLowerContentType));
  EXPECT_EQ("", ToString(client->data_[3]));
}

}  // namespace multipart_image_resource_parser_test
}  // namespace blink

"""

```