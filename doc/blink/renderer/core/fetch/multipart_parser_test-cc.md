Response:
Let's break down the thought process for analyzing this C++ test file for the Blink rendering engine.

1. **Identify the Core Purpose:** The file name `multipart_parser_test.cc` immediately suggests this file contains unit tests for a `MultipartParser` class. The `#include` directives confirm this, particularly the inclusion of `third_party/blink/renderer/core/fetch/multipart_parser.h`.

2. **Understand the Testing Framework:** The inclusion of `testing/gtest/include/gtest/gtest.h` indicates the use of Google Test, a common C++ testing framework. This tells us we'll be looking for `TEST()` macros.

3. **Examine the `MockMultipartParserClient`:**  A "mock" class often simulates the behavior of a real dependency. In this case, `MockMultipartParserClient` implements the `MultipartParser::Client` interface. This is crucial because it tells us *how* the `MultipartParser` communicates its results (parsed parts) to the outside world. We see methods like `PartHeaderFieldsInMultipartReceived`, `PartDataInMultipartReceived`, and `PartDataInMultipartFullyReceived`. These methods collect data about the parsed parts in the `parts_` vector.

4. **Analyze the Test Cases (the `TEST()` blocks):**  Go through each test case and understand its intent:
    * **`AppendDataInChunks`:**  This test verifies that the parser can handle input data delivered in multiple fragments (chunks). It iterates through different chunk sizes. The key here is the loop and the `parser->AppendData(fragment)` calls.
    * **`Epilogue`:** This test focuses on how the parser handles the data *after* the final boundary (the "epilogue"). It tests various scenarios, including different types of endings and whether the parser correctly identifies the last part.
    * **`NoEndBoundary`:** This tests the case where the multipart data doesn't have a closing boundary. It expects `parser->Finish()` to return `false`, indicating an incomplete parse.
    * **`NoStartBoundary`:** This tests the case where the multipart data is missing the initial boundary. It expects `parser->AppendData()` to fail.
    * **`NoStartNorEndBoundary`:**  This tests the scenario where both start and end boundaries are missing.
    * **`Preamble`:**  This test focuses on the data *before* the first boundary (the "preamble"). It checks how the parser handles different preamble scenarios.
    * **`PreambleWithMalformedBoundary`:** This specifically tests the case where the preamble is present, but the *boundary itself* is incorrect.

5. **Identify the Key Input Data (`kBytes`):** The `kBytes` constant string is the primary input used in many tests. Carefully examine its structure: preamble, multiple parts with headers and data, and different boundary variations. This is the sample multipart data the parser is being tested against.

6. **Look for Assertions and Expectations:**  The `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, and `EXPECT_LT` macros from Google Test are used to verify the behavior of the parser. Pay close attention to what these assertions are checking (e.g., the number of parts, the content of headers, the data within each part).

7. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Think about how multipart data is used in web contexts. Form submissions with file uploads are the most common scenario. Consider how JavaScript might construct such requests, how HTML forms are structured, and if CSS has any direct interaction (unlikely).

8. **Infer Logic and Assumptions:** For example, the `Epilogue` test makes assumptions about what constitutes a valid end to multipart data. The tests with missing boundaries make assumptions about how a parser should behave in error conditions.

9. **Consider User and Programming Errors:** Think about the common mistakes developers might make when constructing or handling multipart data, such as incorrect boundary strings, missing boundaries, or not processing the data in chunks correctly.

10. **Trace User Operations (Debugging Clues):**  Imagine how a user's action could lead to the execution of this parsing code. A file upload through a `<form>` is the prime example. Follow the request flow: user selects a file, submits the form, the browser constructs a multipart request, and *this* parser is responsible for processing the server's multipart response.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This just tests the parser's ability to split the data."
* **Correction:** "No, it's more than just splitting. It's also about identifying boundaries, parsing headers, handling preambles and epilogues, and gracefully handling errors like missing boundaries."

* **Initial thought:** "The mock client is just for demonstration."
* **Correction:** "The mock client is essential. It defines the *contract* between the parser and its client. Without it, the tests wouldn't be able to verify *what* the parser found."

By following these steps, you can systematically dissect the code and arrive at a comprehensive understanding of its functionality, its relationship to web technologies, and its implications for user interactions and potential errors.
这个 C++ 文件 `multipart_parser_test.cc` 是 Chromium Blink 渲染引擎中 `MultipartParser` 类的单元测试文件。它的主要功能是：

**功能:**

1. **测试 `MultipartParser` 类的正确性:** 该文件通过一系列的测试用例，验证 `MultipartParser` 类在不同输入情况下的行为是否符合预期。`MultipartParser` 的主要职责是解析 `multipart/form-data` 或 `multipart/related` 等 MIME 类型的数据流，将其分解成多个部分（parts）。

2. **模拟客户端行为:**  文件中定义了一个名为 `MockMultipartParserClient` 的模拟类，它实现了 `MultipartParser::Client` 接口。这个模拟客户端用于接收 `MultipartParser` 解析出的数据，例如每个部分的头部信息和数据内容，方便测试用例进行断言和验证。

3. **测试不同场景:**  测试用例覆盖了多种 multipart 数据流的场景，包括：
    * **正常情况:**  包含 preamble（前导信息）、多个带 header 和 data 的 part、以及 epilogue（尾部信息）。
    * **分块输入:**  模拟数据分块到达的情况，验证解析器是否能正确处理。
    * **有无 preamble:** 测试存在或不存在 preamble 的情况。
    * **有无 epilogue:** 测试存在或不存在 epilogue 的情况，以及 epilogue 内容的各种可能性。
    * **缺少起始或结束 boundary:** 测试 boundary 不完整的情况。
    * **boundary 格式错误:** 测试 boundary 字符串不正确的情况。

**与 JavaScript, HTML, CSS 的关系:**

`MultipartParser` 直接处理的是 HTTP 传输的数据，它本身不直接与 JavaScript、HTML 或 CSS 交互。但是，它的功能对于这些技术在处理涉及到 multipart 数据的场景时至关重要。

* **JavaScript:**  JavaScript 可以通过 `XMLHttpRequest` 或 `Fetch API` 发送包含文件上传的 `multipart/form-data` 请求。服务器返回的响应也可能是 `multipart/related` 类型的数据（例如，包含多个相关资源的文档）。`MultipartParser` 负责解析这些响应数据，将不同的 part 提取出来，以便 JavaScript 可以进一步处理，例如显示图片、处理文本内容等。

    **举例说明:**
    假设一个网页的 JavaScript 代码使用 `Fetch API` 发送一个包含图片上传的表单：
    ```javascript
    const formData = new FormData();
    const fileInput = document.getElementById('imageUpload');
    formData.append('image', fileInput.files[0]);

    fetch('/upload', {
      method: 'POST',
      body: formData
    })
    .then(response => response.blob()) // 假设服务器返回的是一个包含缩略图的 multipart/related 响应
    .then(blob => {
      const imageUrl = URL.createObjectURL(blob);
      document.getElementById('thumbnail').src = imageUrl;
    });
    ```
    在这个场景中，如果服务器返回的是一个 `multipart/related` 响应，Blink 引擎的 `MultipartParser` 会负责解析这个响应，将包含缩略图的 part 提取出来，然后 `response.blob()` 可能会将这个 part 的数据转换成 Blob 对象，供 JavaScript 使用。

* **HTML:** HTML 的 `<form>` 元素可以设置 `enctype="multipart/form-data"`，用于上传文件。当用户提交这种表单时，浏览器会将表单数据编码成 multipart 格式发送给服务器。虽然 HTML 本身不直接解析 multipart 数据，但它触发了 multipart 数据的生成和传输，最终需要在浏览器端（例如，处理服务器的响应）或服务器端进行解析。

* **CSS:** CSS 与 `MultipartParser` 没有直接关系，因为它主要负责页面的样式控制，不涉及数据解析。

**逻辑推理 (假设输入与输出):**

假设 `MultipartParser` 的 boundary 设置为 `"boundary"`，并且接收到以下数据块：

**假设输入:**

```
"--boundary\r\n"
"Content-Type: text/plain\r\n"
"\r\n"
"Hello\r\n"
"--boundary--\r\n"
```

**逻辑推理:**

1. `MultipartParser` 识别到起始 boundary `"--boundary\r\n"`。
2. 解析到该 part 的头部信息 `Content-Type: text/plain`。
3. 识别到头部结束标记 `\r\n`。
4. 接收到 part 的数据 `Hello`。
5. 识别到结束 boundary `"--boundary--\r\n"`，表示数据结束。

**假设输出 (通过 `MockMultipartParserClient` 记录):**

* `PartHeaderFieldsInMultipartReceived` 被调用，`header_fields` 包含 `{"Content-Type": "text/plain"}`。
* `PartDataInMultipartReceived` 被调用，`bytes` 包含 `"Hello"`。
* `PartDataInMultipartFullyReceived` 被调用。
* `Finish()` 返回 `true` (表示解析成功)。

**用户或编程常见的使用错误:**

1. **Boundary 设置错误:**  如果 `MultipartParser` 初始化时设置的 boundary 与实际数据流中的 boundary 不一致，解析会失败。

    **举例说明:**
    用户可能在发送请求时设置了 boundary 为 `"----WebKitFormBoundary7MA4YWxkTrZu0gW"`，但在服务器端或客户端的 `MultipartParser` 中使用了错误的 boundary，例如 `"boundary"`。这将导致解析器无法正确识别 parts 的边界，从而无法正确解析数据。

2. **数据流不完整或格式错误:**  如果 multipart 数据流中缺少必要的 boundary、头部信息格式错误，或者 part 的数据格式不符合声明的 Content-Type，`MultipartParser` 可能会解析失败或产生意外的结果.

    **举例说明:**
    一个常见的错误是忘记在每个 part 的头部和数据之间添加空行 (`\r\n`)。例如：
    ```
    "--boundary\r\n"
    "Content-Type: text/plain\r\n" // 缺少空行
    "Hello\r\n"
    "--boundary--\r\n"
    ```
    `MultipartParser` 可能无法正确识别头部结束，将部分数据误认为是头部信息。

3. **没有正确处理分块数据:**  在网络传输中，multipart 数据可能以多个数据块的形式到达。如果使用 `MultipartParser` 的代码没有正确地将这些数据块逐个添加到解析器中，可能会导致解析不完整或错误。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在网页上进行操作:** 用户可能在网页上填写了一个包含文件上传的表单，并点击了“提交”按钮。
2. **浏览器构建 HTTP 请求:** 浏览器根据 HTML 表单的 `enctype="multipart/form-data"` 属性，将表单数据（包括文件内容）编码成 multipart 格式。这涉及到生成 boundary 字符串，并按照 multipart 格式组织数据。
3. **发送 HTTP 请求:** 浏览器将构建好的 HTTP 请求发送到服务器。
4. **服务器处理请求 (可能):**  服务器接收到 multipart 请求，并可能对其进行处理，例如保存上传的文件。
5. **服务器返回 multipart 响应 (可能):**  服务器在某些情况下可能会返回 multipart 类型的响应，例如 `multipart/related`，其中包含多个相关的资源。
6. **浏览器接收响应:**  Blink 渲染引擎接收到服务器返回的 HTTP 响应。
7. **Blink 处理 multipart 响应:** 如果响应的 `Content-Type` 是 `multipart/form-data` 或 `multipart/related` 等，Blink 引擎会使用 `MultipartParser` 来解析响应体。
8. **`MultipartParser` 解析数据:**  `MultipartParser` 接收响应体的数据流，根据 boundary 将其分解成不同的 part，并提取每个 part 的头部信息和数据内容。
9. **调用 `MultipartParser::Client` 的方法:**  `MultipartParser` 解析到头部或数据时，会调用 `MockMultipartParserClient` (在测试环境中) 或实际的客户端类的方法，例如 `PartHeaderFieldsInMultipartReceived` 和 `PartDataInMultipartReceived`，将解析出的信息传递出去。
10. **JavaScript 或其他 Blink 组件处理解析结果:** 解析出的 part 数据可能会被传递给 JavaScript 代码进行进一步处理，或者被 Blink 引擎的其他组件使用，例如渲染图片或处理文档。

**调试线索:**

如果在使用涉及 multipart 数据的网页时遇到问题，可以考虑以下调试步骤：

* **检查请求头:**  查看浏览器发送的 HTTP 请求头，确认 `Content-Type` 是否正确设置为 `multipart/form-data`，并检查 boundary 字符串是否正确生成。
* **检查响应头:**  查看服务器返回的 HTTP 响应头，确认 `Content-Type` 是否是预期的 multipart 类型，并检查 boundary 字符串。
* **抓包分析:** 使用网络抓包工具（如 Wireshark）捕获 HTTP 请求和响应的数据包，详细分析 multipart 数据的结构，确认 boundary 是否正确，part 的头部和数据格式是否符合规范。
* **查看浏览器开发者工具:**  浏览器的开发者工具通常可以显示请求和响应的详细信息，包括头部和部分内容，有助于初步排查问题。
* **断点调试 Blink 代码:**  如果怀疑是 Blink 引擎的 `MultipartParser` 出现问题，可以在相关代码中设置断点，跟踪数据解析的过程，查看中间状态和变量值。 这需要编译 Chromium 代码并运行调试版本。

`multipart_parser_test.cc` 这样的单元测试文件在开发过程中非常重要，它可以帮助开发者在早期发现和修复 `MultipartParser` 类中的 bug，确保其在各种场景下的正确性，从而保证浏览器处理 multipart 数据的可靠性。

Prompt: 
```
这是目录为blink/renderer/core/fetch/multipart_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/multipart_parser.h"

#include <string.h>

#include <algorithm>

#include "base/numerics/safe_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

namespace {

class MockMultipartParserClient final
    : public GarbageCollected<MockMultipartParserClient>,
      public MultipartParser::Client {
 public:
  struct Part {
    Part() = default;
    explicit Part(const HTTPHeaderMap& header_fields)
        : header_fields(header_fields), data_fully_received(false) {}
    HTTPHeaderMap header_fields;
    Vector<char> data;
    bool data_fully_received;
  };
  void PartHeaderFieldsInMultipartReceived(
      const HTTPHeaderMap& header_fields) override {
    parts_.push_back(header_fields);
  }
  void PartDataInMultipartReceived(base::span<const char> bytes) override {
    parts_.back().data.AppendSpan(bytes);
  }
  void PartDataInMultipartFullyReceived() override {
    parts_.back().data_fully_received = true;
  }
  const Part& GetPart(wtf_size_t part_index) const {
    EXPECT_LT(part_index, NumberOfParts());
    return part_index < NumberOfParts() ? parts_[part_index] : empty_part_;
  }
  wtf_size_t NumberOfParts() const { return parts_.size(); }

 private:
  Part empty_part_;
  Vector<Part> parts_;
};

constexpr char kBytes[] =
    "preamble"
    "\r\n--boundary\r\n\r\n"
    "\r\n--boundary\r\ncontent-type: application/xhtml+xml\r\n\r\n1"
    "\r\n--boundary\t\r\ncontent-type: "
    "text/html\r\n\r\n2\r\n--\r\n--bound--\r\n--\r\n2\r\n"
    "\r\n--boundary \r\ncontent-type: text/plain; charset=iso-8859-1\r\n\r\n333"
    "\r\n--boundary--\t \r\n"
    "epilogue";

TEST(MultipartParserTest, AppendDataInChunks) {
  test::TaskEnvironment task_environment;
  const size_t sizes[] = {1u, 2u, strlen(kBytes)};

  Vector<char> boundary;
  boundary.Append("boundary", 8u);
  for (const size_t size : sizes) {
    MockMultipartParserClient* client =
        MakeGarbageCollected<MockMultipartParserClient>();
    MultipartParser* parser =
        MakeGarbageCollected<MultipartParser>(boundary, client);

    auto bytes = base::span_from_cstring(kBytes);
    for (size_t i = 0u; i < bytes.size(); i += size) {
      auto fragment = bytes.subspan(i, std::min(size, bytes.size() - i));
      EXPECT_TRUE(parser->AppendData(fragment));
    }
    EXPECT_TRUE(parser->Finish()) << " size=" << size;
    EXPECT_EQ(4u, client->NumberOfParts()) << " size=" << size;
    EXPECT_EQ(0u, client->GetPart(0).header_fields.size());
    EXPECT_EQ(0u, client->GetPart(0).data.size());
    EXPECT_TRUE(client->GetPart(0).data_fully_received);
    EXPECT_EQ(1u, client->GetPart(1).header_fields.size());
    EXPECT_EQ("application/xhtml+xml",
              client->GetPart(1).header_fields.Get(http_names::kContentType));
    EXPECT_EQ("1", String(client->GetPart(1).data));
    EXPECT_TRUE(client->GetPart(1).data_fully_received);
    EXPECT_EQ(1u, client->GetPart(2).header_fields.size());
    EXPECT_EQ("text/html",
              client->GetPart(2).header_fields.Get(http_names::kContentType));
    EXPECT_EQ("2\r\n--\r\n--bound--\r\n--\r\n2\r\n",
              String(client->GetPart(2).data));
    EXPECT_TRUE(client->GetPart(2).data_fully_received);
    EXPECT_EQ(1u, client->GetPart(3).header_fields.size());
    EXPECT_EQ("text/plain; charset=iso-8859-1",
              client->GetPart(3).header_fields.Get(http_names::kContentType));
    EXPECT_EQ("333", String(client->GetPart(3).data));
    EXPECT_TRUE(client->GetPart(3).data_fully_received);
  }
}

TEST(MultipartParserTest, Epilogue) {
  test::TaskEnvironment task_environment;
  constexpr size_t ends[] = {
      0u,   // Non-empty epilogue in the end.
      8u,   // Empty epilogue in the end.
      9u,   // Partial CRLF after close delimiter in the end.
      10u,  // No CRLF after close delimiter in the end.
      12u,  // No transport padding nor CRLF after close delimiter in the end.
      13u,  // Partial close delimiter in the end.
      14u,  // No close delimiter but a delimiter in the end.
      15u   // Partial delimiter in the end.
  };

  Vector<char> boundary;
  boundary.Append("boundary", 8u);
  for (size_t end : ends) {
    MockMultipartParserClient* client =
        MakeGarbageCollected<MockMultipartParserClient>();
    MultipartParser* parser =
        MakeGarbageCollected<MultipartParser>(boundary, client);

    auto bytes = base::span_from_cstring(kBytes);
    EXPECT_TRUE(parser->AppendData(bytes.first(bytes.size() - end)));
    EXPECT_EQ(end <= 12u, parser->Finish()) << " end=" << end;
    EXPECT_EQ(4u, client->NumberOfParts()) << " end=" << end;
    EXPECT_EQ(0u, client->GetPart(0).header_fields.size());
    EXPECT_EQ(0u, client->GetPart(0).data.size());
    EXPECT_TRUE(client->GetPart(0).data_fully_received);
    EXPECT_EQ(1u, client->GetPart(1).header_fields.size());
    EXPECT_EQ("application/xhtml+xml",
              client->GetPart(1).header_fields.Get(http_names::kContentType));
    EXPECT_EQ("1", String(client->GetPart(1).data));
    EXPECT_TRUE(client->GetPart(1).data_fully_received);
    EXPECT_EQ(1u, client->GetPart(2).header_fields.size());
    EXPECT_EQ("text/html",
              client->GetPart(2).header_fields.Get(http_names::kContentType));
    EXPECT_EQ("2\r\n--\r\n--bound--\r\n--\r\n2\r\n",
              String(client->GetPart(2).data));
    EXPECT_TRUE(client->GetPart(2).data_fully_received);
    EXPECT_EQ(1u, client->GetPart(3).header_fields.size());
    EXPECT_EQ("text/plain; charset=iso-8859-1",
              client->GetPart(3).header_fields.Get(http_names::kContentType));
    switch (end) {
      case 15u:
        EXPECT_EQ("333\r\n--boundar", String(client->GetPart(3).data));
        EXPECT_FALSE(client->GetPart(3).data_fully_received);
        break;
      default:
        EXPECT_EQ("333", String(client->GetPart(3).data));
        EXPECT_TRUE(client->GetPart(3).data_fully_received);
        break;
    }
  }
}

TEST(MultipartParserTest, NoEndBoundary) {
  test::TaskEnvironment task_environment;
  constexpr char bytes[] =
      "--boundary\r\ncontent-type: application/xhtml+xml\r\n\r\n1";

  Vector<char> boundary;
  boundary.Append("boundary", 8u);
  MockMultipartParserClient* client =
      MakeGarbageCollected<MockMultipartParserClient>();
  MultipartParser* parser =
      MakeGarbageCollected<MultipartParser>(boundary, client);

  EXPECT_TRUE(parser->AppendData(base::span_from_cstring(bytes)));
  EXPECT_FALSE(parser->Finish());  // No close delimiter.
  EXPECT_EQ(1u, client->NumberOfParts());
  EXPECT_EQ(1u, client->GetPart(0).header_fields.size());
  EXPECT_EQ("application/xhtml+xml",
            client->GetPart(0).header_fields.Get(http_names::kContentType));
  EXPECT_EQ("1", String(client->GetPart(0).data));
  EXPECT_FALSE(client->GetPart(0).data_fully_received);
}

TEST(MultipartParserTest, NoStartBoundary) {
  test::TaskEnvironment task_environment;
  constexpr char bytes[] =
      "content-type: application/xhtml+xml\r\n\r\n1\r\n--boundary--\r\n";

  Vector<char> boundary;
  boundary.Append("boundary", 8u);
  MockMultipartParserClient* client =
      MakeGarbageCollected<MockMultipartParserClient>();
  MultipartParser* parser =
      MakeGarbageCollected<MultipartParser>(boundary, client);

  EXPECT_FALSE(parser->AppendData(
      base::span_from_cstring(bytes)));  // Close delimiter before delimiter.
  EXPECT_EQ(0u, client->NumberOfParts());
}

TEST(MultipartParserTest, NoStartNorEndBoundary) {
  test::TaskEnvironment task_environment;
  constexpr char bytes[] = "content-type: application/xhtml+xml\r\n\r\n1";

  Vector<char> boundary;
  boundary.Append("boundary", 8u);
  MockMultipartParserClient* client =
      MakeGarbageCollected<MockMultipartParserClient>();
  MultipartParser* parser =
      MakeGarbageCollected<MultipartParser>(boundary, client);

  EXPECT_TRUE(
      parser->AppendData(base::span_from_cstring(bytes)));  // Valid preamble.
  EXPECT_FALSE(parser->Finish());                         // No parts.
  EXPECT_EQ(0u, client->NumberOfParts());
}

constexpr size_t kStarts[] = {
    0u,   // Non-empty preamble in the beginning.
    8u,   // Empty preamble in the beginning.
    9u,   // Truncated delimiter in the beginning.
    10u,  // No preamble in the beginning.
    11u   // Truncated dash boundary in the beginning.
};

TEST(MultipartParserTest, Preamble) {
  test::TaskEnvironment task_environment;
  Vector<char> boundary;
  boundary.Append("boundary", 8u);
  for (const size_t start : kStarts) {
    MockMultipartParserClient* client =
        MakeGarbageCollected<MockMultipartParserClient>();
    MultipartParser* parser =
        MakeGarbageCollected<MultipartParser>(boundary, client);

    auto bytes = base::span_from_cstring(kBytes).subspan(start);
    EXPECT_TRUE(parser->AppendData(bytes));
    EXPECT_TRUE(parser->Finish());
    switch (start) {
      case 9u:
      case 11u:
        EXPECT_EQ(3u, client->NumberOfParts()) << " start=" << start;
        EXPECT_EQ(1u, client->GetPart(0).header_fields.size());
        EXPECT_EQ("application/xhtml+xml", client->GetPart(0).header_fields.Get(
                                               http_names::kContentType));
        EXPECT_EQ("1", String(client->GetPart(0).data));
        EXPECT_TRUE(client->GetPart(0).data_fully_received);
        EXPECT_EQ(1u, client->GetPart(1).header_fields.size());
        EXPECT_EQ("text/html", client->GetPart(1).header_fields.Get(
                                   http_names::kContentType));
        EXPECT_EQ("2\r\n--\r\n--bound--\r\n--\r\n2\r\n",
                  String(client->GetPart(1).data));
        EXPECT_TRUE(client->GetPart(1).data_fully_received);
        EXPECT_EQ(1u, client->GetPart(2).header_fields.size());
        EXPECT_EQ(
            "text/plain; charset=iso-8859-1",
            client->GetPart(2).header_fields.Get(http_names::kContentType));
        EXPECT_EQ("333", String(client->GetPart(2).data));
        EXPECT_TRUE(client->GetPart(2).data_fully_received);
        break;
      default:
        EXPECT_EQ(4u, client->NumberOfParts()) << " start=" << start;
        EXPECT_EQ(0u, client->GetPart(0).header_fields.size());
        EXPECT_EQ(0u, client->GetPart(0).data.size());
        EXPECT_TRUE(client->GetPart(0).data_fully_received);
        EXPECT_EQ(1u, client->GetPart(1).header_fields.size());
        EXPECT_EQ("application/xhtml+xml", client->GetPart(1).header_fields.Get(
                                               http_names::kContentType));
        EXPECT_EQ("1", String(client->GetPart(1).data));
        EXPECT_TRUE(client->GetPart(1).data_fully_received);
        EXPECT_EQ(1u, client->GetPart(2).header_fields.size());
        EXPECT_EQ("text/html", client->GetPart(2).header_fields.Get(
                                   http_names::kContentType));
        EXPECT_EQ("2\r\n--\r\n--bound--\r\n--\r\n2\r\n",
                  String(client->GetPart(2).data));
        EXPECT_TRUE(client->GetPart(2).data_fully_received);
        EXPECT_EQ(1u, client->GetPart(3).header_fields.size());
        EXPECT_EQ(
            "text/plain; charset=iso-8859-1",
            client->GetPart(3).header_fields.Get(http_names::kContentType));
        EXPECT_EQ("333", String(client->GetPart(3).data));
        EXPECT_TRUE(client->GetPart(3).data_fully_received);
        break;
    }
  }
}

TEST(MultipartParserTest, PreambleWithMalformedBoundary) {
  test::TaskEnvironment task_environment;
  Vector<char> boundary;
  boundary.Append("--boundary", 10u);
  for (const size_t start : kStarts) {
    MockMultipartParserClient* client =
        MakeGarbageCollected<MockMultipartParserClient>();
    MultipartParser* parser =
        MakeGarbageCollected<MultipartParser>(boundary, client);

    auto bytes = base::span_from_cstring(kBytes).subspan(start);
    EXPECT_TRUE(parser->AppendData(bytes));                   // Valid preamble.
    EXPECT_FALSE(parser->Finish());                           // No parts.
    EXPECT_EQ(0u, client->NumberOfParts());
  }
}

}  // namespace

}  // namespace blink

"""

```