Response:
My thinking process to analyze the provided C++ code and answer the request goes like this:

1. **Understand the Core Purpose:** The filename `url_request_test_job_backed_by_file_unittest.cc` immediately tells me this is a unit test file. The key class being tested is likely `URLRequestTestJobBackedByFile`. The "backed by file" part suggests this class simulates serving content from a local file.

2. **Identify Key Classes and Functions:** I scan the includes and the code to identify the main components:
    * `URLRequestTestJobBackedByFile`: The class being tested, responsible for serving files.
    * `URLRequest`:  A core networking class for making requests.
    * `URLRequestContext`: Manages the context for URL requests.
    * `TestDelegate`: A test utility to observe the behavior of the `URLRequest`.
    * `TestURLRequestTestJobBackedByFile`: A custom subclass for testing specific events.
    * `OnOpenComplete`, `OnSeekComplete`, `OnReadComplete`, `DoneReading`:  Callback functions within `URLRequestTestJobBackedByFile` that are the focus of the tests.
    * Test functions like `ZeroByteFile`, `TinyFile`, `Range`, etc.: These are the individual test cases.

3. **Analyze Functionality (Based on the Tests):** The test names and their setup reveal the functionality being tested:
    * **Serving Files:** The core function is to serve the content of a local file over a simulated network request.
    * **Handling Different File Sizes:** Tests like `ZeroByteFile`, `TinyFile`, `SmallFile`, and `BigFile` check how the class handles files of various sizes.
    * **Range Requests:** The `Range` test verifies support for HTTP range requests (requesting a specific portion of a file).
    * **Gzip Decoding:** The `DecodeSvgzFile` test checks if the class can handle compressed files based on their extension.
    * **Error Handling:** `OpenNonExistentFile`, `MultiRangeRequestNotSupported`, `RangeExceedingFileSize` test how the class behaves when encountering errors like file not found or invalid/unsupported range requests.
    * **Ignoring Parsing Errors:** `IgnoreRangeParsingError` tests the robustness of the range header parsing.
    * **Callback Verification:** The `TestURLRequestTestJobBackedByFile` class specifically checks the values passed to the `On...Complete` callbacks to ensure they are correct.

4. **Look for JavaScript Relationships:** I consider how serving local files relates to web development and JavaScript. The most direct relationship is in the context of a browser:
    * **Serving Static Assets:**  Web servers often serve static files like HTML, CSS, JavaScript, images, etc. This code simulates a *part* of that process (specifically the file serving aspect).
    * **`file://` Protocol (Indirect):**  While this test code doesn't directly use `file://`, the underlying mechanism of reading and serving local files is similar to how a browser might handle requests to local files using the `file://` protocol.

5. **Construct JavaScript Examples:** Based on the identified relationships, I create illustrative JavaScript examples:
    * Fetching a local HTML file: Shows a simple `fetch` request that could be served by a mechanism similar to the tested code.
    * Fetching a range of a file: Demonstrates how a JavaScript application might use the `Range` header in a `fetch` request, directly relating to the range request tests.

6. **Identify Logical Reasoning and Provide Examples:** The tests inherently involve logical reasoning:
    * **Assumption:**  A request for a valid file should result in the file's content being served.
    * **Input:** A request for "bytes=10-20" on a file containing "0123456789abcdefghijklm".
    * **Output:** The `OnReadComplete` callbacks should receive the bytes "abcdefghij".

7. **Identify Potential User/Programming Errors:**  Based on the error handling tests, I identify common mistakes:
    * Requesting a non-existent file.
    * Making invalid range requests (multi-range or exceeding file size).
    * Assuming all range requests are supported.

8. **Trace User Operations (Debugging Clues):** I think about how a user action could lead to this code being executed during debugging:
    * A developer setting up a test environment where a mock file server is needed.
    * A developer investigating issues related to serving local files or range requests within the Chromium browser. They might step through the code and reach this test file to understand the expected behavior.

9. **Structure the Answer:** I organize the information into clear sections as requested: Functionality, JavaScript Relationship, Logical Reasoning, Common Errors, and User Operations/Debugging. I use bullet points and code examples to make the answer easy to understand.

10. **Review and Refine:** I read through my answer to ensure accuracy, clarity, and completeness, double-checking the code snippets and explanations. For example, I make sure the JavaScript `fetch` examples are correct and relevant. I also check that the assumptions and inputs/outputs for logical reasoning are consistent with the test cases.
这是 Chromium 网络栈中 `net/test/url_request/url_request_test_job_backed_by_file_unittest.cc` 文件的源代码，它是一个单元测试文件，专门用于测试 `URLRequestTestJobBackedByFile` 类的功能。

**功能列表:**

1. **测试从本地文件提供网络请求响应的功能:**  `URLRequestTestJobBackedByFile` 类的主要目的是模拟一个网络请求，其响应内容来源于本地文件。这个单元测试文件验证了这个核心功能是否正常工作。
2. **测试不同文件大小的处理:**  测试用例涵盖了零字节文件、小文件、中等大小文件和较大文件的场景，确保 `URLRequestTestJobBackedByFile` 能正确处理各种大小的文件。
3. **测试 HTTP Range 请求的处理:**  测试用例验证了 `URLRequestTestJobBackedByFile` 是否能够正确处理 HTTP Range 请求，即只请求文件的一部分内容。
4. **测试对 gzip 压缩文件的处理:**  测试用例 `DecodeSvgzFile` 验证了对于扩展名为 `.svgz` 的 gzip 压缩文件，`URLRequestTestJobBackedByFile` 是否能够正确解压并提供内容。
5. **测试文件打开失败的处理:**  测试用例 `OpenNonExistentFile` 检查了当请求的文件不存在时，`URLRequestTestJobBackedByFile` 是否能正确返回错误。
6. **测试不支持的 Range 请求的处理:**  测试用例 `MultiRangeRequestNotSupported` 和 `RangeExceedingFileSize` 验证了对于不支持的 Range 请求（例如，多段 Range 或 Range 超出文件大小），`URLRequestTestJobBackedByFile` 是否能返回相应的错误。
7. **测试 Range 请求头解析错误的处理:** 测试用例 `IgnoreRangeParsingError` 验证了当 Range 请求头格式不正确时，`URLRequestTestJobBackedByFile` 是否能够忽略错误并返回整个文件内容。
8. **详细测试回调函数的行为:**  使用了自定义的 `TestURLRequestTestJobBackedByFile` 类，它重载了 `OnOpenComplete`、`OnSeekComplete`、`OnReadComplete` 和 `DoneReading` 等回调函数，用于细致地检查这些回调函数的调用时机和参数值。这包括验证打开结果、seek 位置、读取到的内容以及是否完成读取。

**与 JavaScript 的关系及举例说明:**

虽然这个 C++ 代码本身不包含 JavaScript，但它测试的功能与 Web 开发中 JavaScript 的应用密切相关：

* **`fetch` API 和 Range 请求:** JavaScript 的 `fetch` API 允许开发者发起网络请求，并且可以通过设置 `Range` 请求头来请求资源的部分内容。`URLRequestTestJobBackedByFile` 测试了后端如何处理这样的 Range 请求。

   **举例说明:**

   假设有一个名为 `large_image.jpg` 的本地文件，JavaScript 代码可以使用 `fetch` API 请求该图片的一部分：

   ```javascript
   fetch('http://intercepted-url/', {
       headers: {
           'Range': 'bytes=1024-2047' // 请求 1024 到 2047 字节的内容
       }
   })
   .then(response => response.blob())
   .then(blob => {
       // 处理接收到的部分图片数据
       console.log('Received a part of the image:', blob);
   });
   ```

   在这个例子中，如果 Chromium 使用了类似 `URLRequestTestJobBackedByFile` 的机制来处理这个请求（假设 URL 被拦截并路由到本地文件），那么这个 C++ 测试文件中的用例（例如 `TEST_F(URLRequestTestJobBackedByFileEventsTest, Range)`）就验证了 Chromium 后端是否能够正确响应这个 JavaScript 发起的 Range 请求。

* **加载本地静态资源:**  在某些开发场景或 Hybrid 应用中，JavaScript 可能需要加载本地的 HTML、CSS、JavaScript 或图片等静态资源。`URLRequestTestJobBackedByFile` 模拟了这种场景，确保 Chromium 可以正确地从本地文件系统读取并提供这些资源。

   **举例说明:**

   一个简单的网页可能包含一个指向本地图片的 `<img>` 标签：

   ```html
   <img src="http://intercepted-url/my_image.png">
   ```

   或者使用 JavaScript 动态加载本地脚本：

   ```javascript
   fetch('http://intercepted-url/my_script.js')
       .then(response => response.text())
       .then(scriptText => {
           eval(scriptText); // 执行本地脚本
       });
   ```

   在这个场景下，`URLRequestTestJobBackedByFile` 确保了 Chromium 能够像处理远程资源一样处理这些本地资源请求。

**逻辑推理的假设输入与输出:**

**假设输入 (针对 `TEST_F(URLRequestTestJobBackedByFileEventsTest, Range)`):**

* **本地文件内容:** 包含字符串 "abcdefghijklmnopqrstuvwxyz"。
* **Range 请求头:** "bytes=5-10"。

**逻辑推理:**  `URLRequestTestJobBackedByFile` 应该打开本地文件，定位到字节偏移量 5，然后读取 10 - 5 + 1 = 6 个字节的内容。

**预期输出:**

* `OnOpenComplete` 回调函数的 `result` 参数为 `OK` (0)。
* `OnSeekComplete` 回调函数的 `result` 参数为 `5`。
* `OnReadComplete` 回调函数会被调用，`buf` 指向包含 "fghijkl" 的内存区域，`result` 参数为 `6`。
* `DoneReading` 回调函数会被调用。
* `delegate_.data_received()` 的值应该为 "fghijkl"。

**用户或编程常见的使用错误举例说明:**

1. **请求不存在的本地文件:** 用户或开发者可能错误地指定了不存在的本地文件路径。`TEST_F(URLRequestTestJobBackedByFileEventsTest, OpenNonExistentFile)` 模拟了这种情况，会返回 `ERR_FILE_NOT_FOUND` 错误。

   **用户操作:**  在 Chromium 内核的开发或调试过程中，如果某个内部组件尝试通过 `URLRequest` 加载一个硬编码的本地文件，但该文件在文件系统中不存在，就会触发这个错误。

2. **发送不支持的 Range 请求:**  开发者可能错误地发送了多段 Range 请求，而 `URLRequestTestJobBackedByFile` 只支持单段 Range 请求。`TEST_F(URLRequestTestJobBackedByFileEventsTest, MultiRangeRequestNotSupported)` 模拟了这种情况，会返回 `ERR_REQUEST_RANGE_NOT_SATISFIABLE` 错误。

   **用户操作:**  在编写涉及到 Range 请求的代码时，可能会错误地生成了多段 Range 的请求头，例如 `"bytes=0-10,20-30"`。

3. **Range 请求超出文件大小:** 开发者可能请求了超出文件末尾的字节范围。`TEST_F(URLRequestTestJobBackedByFileEventsTest, RangeExceedingFileSize)` 模拟了这种情况，也会返回 `ERR_REQUEST_RANGE_NOT_SATISFIABLE` 错误。

   **用户操作:**  在动态计算 Range 请求的起始和结束位置时，可能会出现逻辑错误，导致请求的范围超出了文件的实际大小。

**用户操作是如何一步步的到达这里，作为调试线索:**

当开发者在 Chromium 的网络栈中遇到与加载本地文件相关的 bug 时，可能会逐步深入代码进行调试，最终到达这个单元测试文件：

1. **用户报告或开发者发现 bug:**  例如，一个网页在尝试加载本地图片时失败，或者在使用 `fetch` API 请求本地文件的一部分内容时出现错误。
2. **定位到网络请求处理代码:**  开发者会从 Chromium 的网络请求处理入口点开始调试，例如 `URLRequest` 的创建和启动。
3. **追踪请求的拦截和处理:**  对于特定类型的 URL（例如，被注册为由 `URLRequestTestJobBackedByFile` 处理的 URL），请求会被拦截并路由到 `URLRequestTestJobBackedByFile` 的实例。
4. **单步执行 `URLRequestTestJobBackedByFile` 的代码:**  开发者会单步执行 `URLRequestTestJobBackedByFile` 的 `Start` 方法，以及后续的 `OnOpenComplete`、`OnSeekComplete`、`OnReadComplete` 等回调函数，查看文件的打开、读取和数据返回过程是否正常。
5. **参考单元测试:** 为了理解 `URLRequestTestJobBackedByFile` 的预期行为，开发者会查看相关的单元测试文件，例如 `url_request_test_job_backed_by_file_unittest.cc`。这些测试用例提供了各种场景下的输入和预期输出，帮助开发者判断实际的代码行为是否符合预期，并找出 bug 的根源。
6. **运行特定的单元测试:**  如果怀疑是 Range 请求处理有问题，开发者可能会运行 `TEST_F(URLRequestTestJobBackedByFileEventsTest, Range)` 等相关的测试用例，来验证 `URLRequestTestJobBackedByFile` 在处理 Range 请求时的逻辑是否正确。

总而言之，`url_request_test_job_backed_by_file_unittest.cc` 是一个关键的测试文件，用于确保 Chromium 的网络栈能够正确地模拟从本地文件提供网络请求响应的功能，这对于加载本地资源以及处理 JavaScript 发起的 Range 请求等场景至关重要。它也为开发者提供了一个了解和调试相关功能的入口点。

### 提示词
```
这是目录为net/test/url_request/url_request_test_job_backed_by_file_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/url_request/url_request_test_job_backed_by_file.h"
#include "base/memory/raw_ptr.h"

#include <memory>

#include "base/check.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/filename_util.h"
#include "net/base/net_errors.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/url_constants.h"

namespace net {

namespace {

// A URLRequestTestJobBackedByFile for testing values passed to OnSeekComplete
// and OnReadComplete.
class TestURLRequestTestJobBackedByFile : public URLRequestTestJobBackedByFile {
 public:
  // |seek_position| will be set to the value passed in to OnSeekComplete.
  // |observed_content| will be set to the concatenated data from all calls to
  // OnReadComplete.
  TestURLRequestTestJobBackedByFile(
      URLRequest* request,
      const base::FilePath& file_path,
      const scoped_refptr<base::TaskRunner>& file_task_runner,
      int* open_result,
      int64_t* seek_position,
      bool* done_reading,
      std::string* observed_content)
      : URLRequestTestJobBackedByFile(request,
                                      file_path,
                                      file_task_runner),
        open_result_(open_result),
        seek_position_(seek_position),
        done_reading_(done_reading),
        observed_content_(observed_content) {
    *open_result_ = ERR_IO_PENDING;
    *seek_position_ = ERR_IO_PENDING;
    *done_reading_ = false;
    observed_content_->clear();
  }

  ~TestURLRequestTestJobBackedByFile() override = default;

 protected:
  void OnOpenComplete(int result) override {
    // Should only be called once.
    ASSERT_EQ(ERR_IO_PENDING, *open_result_);
    *open_result_ = result;
  }

  void OnSeekComplete(int64_t result) override {
    // Should only call this if open succeeded.
    EXPECT_EQ(OK, *open_result_);
    // Should only be called once.
    ASSERT_EQ(ERR_IO_PENDING, *seek_position_);
    *seek_position_ = result;
  }

  void OnReadComplete(IOBuffer* buf, int result) override {
    // Should only call this if seek succeeded.
    EXPECT_GE(*seek_position_, 0);
    observed_content_->append(std::string(buf->data(), result));
  }

  void DoneReading() override { *done_reading_ = true; }

  const raw_ptr<int> open_result_;
  const raw_ptr<int64_t> seek_position_;
  raw_ptr<bool> done_reading_;
  const raw_ptr<std::string> observed_content_;
};

// A simple holder for start/end used in http range requests.
struct Range {
  int start;
  int end;

  Range() {
    start = 0;
    end = 0;
  }

  Range(int start, int end) {
    this->start = start;
    this->end = end;
  }
};

// A superclass for tests of the OnReadComplete / OnSeekComplete /
// OnReadComplete functions of URLRequestTestJobBackedByFile.
class URLRequestTestJobBackedByFileEventsTest : public TestWithTaskEnvironment {
 public:
  URLRequestTestJobBackedByFileEventsTest();

 protected:
  void TearDown() override;

  // This creates a file with |content| as the contents, and then creates and
  // runs a TestURLRequestTestJobBackedByFile job to get the contents out of it,
  // and makes sure that the callbacks observed the correct bytes. If a Range
  // is provided, this function will add the appropriate Range http header to
  // the request and verify that only the bytes in that range (inclusive) were
  // observed.
  void RunSuccessfulRequestWithString(const std::string& content,
                                      const Range* range);

  // This is the same as the method above it, except that it will make sure
  // the content matches |expected_content| and allow caller to specify the
  // extension of the filename in |file_extension|.
  void RunSuccessfulRequestWithString(
      const std::string& content,
      const std::string& expected_content,
      const base::FilePath::StringPieceType& file_extension,
      const Range* range);

  // Creates and runs a TestURLRequestTestJobBackedByFile job to read from file
  // provided by |path|. If |range| value is provided, it will be passed in the
  // range header.
  void RunRequestWithPath(const base::FilePath& path,
                          const std::string& range,
                          int* open_result,
                          int64_t* seek_position,
                          bool* done_reading,
                          std::string* observed_content);

  base::ScopedTempDir directory_;
  std::unique_ptr<URLRequestContext> context_;
  TestDelegate delegate_;
};

URLRequestTestJobBackedByFileEventsTest::
    URLRequestTestJobBackedByFileEventsTest()
    : context_(CreateTestURLRequestContextBuilder()->Build()) {}

void URLRequestTestJobBackedByFileEventsTest::TearDown() {
  // Gives a chance to close the opening file.
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(!directory_.IsValid() || directory_.Delete());
  TestWithTaskEnvironment::TearDown();
}

void URLRequestTestJobBackedByFileEventsTest::RunSuccessfulRequestWithString(
    const std::string& content,
    const Range* range) {
  RunSuccessfulRequestWithString(content, content, FILE_PATH_LITERAL(""),
                                 range);
}

void URLRequestTestJobBackedByFileEventsTest::RunSuccessfulRequestWithString(
    const std::string& raw_content,
    const std::string& expected_content,
    const base::FilePath::StringPieceType& file_extension,
    const Range* range) {
  ASSERT_TRUE(directory_.CreateUniqueTempDir());
  base::FilePath path = directory_.GetPath().Append(FILE_PATH_LITERAL("test"));
  if (!file_extension.empty())
    path = path.AddExtension(file_extension);
  ASSERT_TRUE(base::WriteFile(path, raw_content));

  std::string range_value;
  if (range) {
    ASSERT_GE(range->start, 0);
    ASSERT_GE(range->end, 0);
    ASSERT_LE(range->start, range->end);
    ASSERT_LT(static_cast<unsigned int>(range->end), expected_content.length());
    range_value = base::StringPrintf("bytes=%d-%d", range->start, range->end);
  }

  {
    int open_result;
    int64_t seek_position;
    bool done_reading;
    std::string observed_content;
    RunRequestWithPath(path, range_value, &open_result, &seek_position,
                       &done_reading, &observed_content);

    EXPECT_EQ(OK, open_result);
    EXPECT_FALSE(delegate_.request_failed());
    int expected_length =
        range ? (range->end - range->start + 1) : expected_content.length();
    EXPECT_EQ(delegate_.bytes_received(), expected_length);

    std::string expected_data_received;
    if (range) {
      expected_data_received.insert(0, expected_content, range->start,
                                    expected_length);
      EXPECT_EQ(expected_data_received, observed_content);
    } else {
      expected_data_received = expected_content;
      EXPECT_EQ(raw_content, observed_content);
    }

    EXPECT_EQ(expected_data_received, delegate_.data_received());
    EXPECT_EQ(seek_position, range ? range->start : 0);
    EXPECT_TRUE(done_reading);
  }
}

void URLRequestTestJobBackedByFileEventsTest::RunRequestWithPath(
    const base::FilePath& path,
    const std::string& range,
    int* open_result,
    int64_t* seek_position,
    bool* done_reading,
    std::string* observed_content) {
  const GURL kUrl("http://intercepted-url/");

  std::unique_ptr<URLRequest> request(context_->CreateRequest(
      kUrl, DEFAULT_PRIORITY, &delegate_, TRAFFIC_ANNOTATION_FOR_TESTS));
  TestScopedURLInterceptor interceptor(
      kUrl, std::make_unique<TestURLRequestTestJobBackedByFile>(
                request.get(), path,
                base::SingleThreadTaskRunner::GetCurrentDefault(), open_result,
                seek_position, done_reading, observed_content));
  if (!range.empty()) {
    request->SetExtraRequestHeaderByName(HttpRequestHeaders::kRange, range,
                                         true /*overwrite*/);
  }
  request->Start();
  delegate_.RunUntilComplete();
}

// Helper function to make a character array filled with |size| bytes of
// test content.
std::string MakeContentOfSize(int size) {
  EXPECT_GE(size, 0);
  std::string result;
  result.reserve(size);
  for (int i = 0; i < size; i++) {
    result.append(1, static_cast<char>(i % 256));
  }
  return result;
}

TEST_F(URLRequestTestJobBackedByFileEventsTest, ZeroByteFile) {
  RunSuccessfulRequestWithString(std::string(""), nullptr);
}

TEST_F(URLRequestTestJobBackedByFileEventsTest, TinyFile) {
  RunSuccessfulRequestWithString(std::string("hello world"), nullptr);
}

TEST_F(URLRequestTestJobBackedByFileEventsTest, SmallFile) {
  RunSuccessfulRequestWithString(MakeContentOfSize(17 * 1024), nullptr);
}

TEST_F(URLRequestTestJobBackedByFileEventsTest, BigFile) {
  RunSuccessfulRequestWithString(MakeContentOfSize(3 * 1024 * 1024), nullptr);
}

TEST_F(URLRequestTestJobBackedByFileEventsTest, Range) {
  // Use a 15KB content file and read a range chosen somewhat arbitrarily but
  // not aligned on any likely page boundaries.
  int size = 15 * 1024;
  Range range(1701, (6 * 1024) + 3);
  RunSuccessfulRequestWithString(MakeContentOfSize(size), &range);
}

TEST_F(URLRequestTestJobBackedByFileEventsTest, DecodeSvgzFile) {
  std::string expected_content("Hello, World!");
  unsigned char gzip_data[] = {
      // From:
      //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
      0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00, 0x03, 0xf3,
      0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49,
      0x51, 0x04, 0x00, 0xd0, 0xc3, 0x4a, 0xec, 0x0d, 0x00, 0x00, 0x00};
  RunSuccessfulRequestWithString(
      std::string(reinterpret_cast<char*>(gzip_data), sizeof(gzip_data)),
      expected_content, FILE_PATH_LITERAL("svgz"), nullptr);
}

TEST_F(URLRequestTestJobBackedByFileEventsTest, OpenNonExistentFile) {
  base::FilePath path;
  base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &path);
  path = path.Append(
      FILE_PATH_LITERAL("net/data/url_request_unittest/non-existent.txt"));

  int open_result;
  int64_t seek_position;
  bool done_reading;
  std::string observed_content;
  RunRequestWithPath(path, std::string(), &open_result, &seek_position,
                     &done_reading, &observed_content);

  EXPECT_EQ(ERR_FILE_NOT_FOUND, open_result);
  EXPECT_FALSE(done_reading);
  EXPECT_TRUE(delegate_.request_failed());
}

TEST_F(URLRequestTestJobBackedByFileEventsTest, MultiRangeRequestNotSupported) {
  base::FilePath path;
  base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &path);
  path = path.Append(
      FILE_PATH_LITERAL("net/data/url_request_unittest/BullRunSpeech.txt"));

  int open_result;
  int64_t seek_position;
  bool done_reading;
  std::string observed_content;
  RunRequestWithPath(path, "bytes=1-5,20-30", &open_result, &seek_position,
                     &done_reading, &observed_content);

  EXPECT_EQ(OK, open_result);
  EXPECT_EQ(ERR_REQUEST_RANGE_NOT_SATISFIABLE, seek_position);
  EXPECT_FALSE(done_reading);
  EXPECT_TRUE(delegate_.request_failed());
}

TEST_F(URLRequestTestJobBackedByFileEventsTest, RangeExceedingFileSize) {
  base::FilePath path;
  base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &path);
  path = path.Append(
      FILE_PATH_LITERAL("net/data/url_request_unittest/BullRunSpeech.txt"));

  int open_result;
  int64_t seek_position;
  bool done_reading;
  std::string observed_content;
  RunRequestWithPath(path, "bytes=50000-", &open_result, &seek_position,
                     &done_reading, &observed_content);

  EXPECT_EQ(OK, open_result);
  EXPECT_EQ(ERR_REQUEST_RANGE_NOT_SATISFIABLE, seek_position);
  EXPECT_FALSE(done_reading);
  EXPECT_TRUE(delegate_.request_failed());
}

TEST_F(URLRequestTestJobBackedByFileEventsTest, IgnoreRangeParsingError) {
  base::FilePath path;
  base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &path);
  path = path.Append(
      FILE_PATH_LITERAL("net/data/url_request_unittest/simple.html"));

  int open_result;
  int64_t seek_position;
  bool done_reading;
  std::string observed_content;
  RunRequestWithPath(path, "bytes=3-z", &open_result, &seek_position,
                     &done_reading, &observed_content);

  EXPECT_EQ(OK, open_result);
  EXPECT_EQ(0, seek_position);
  EXPECT_EQ("hello\n", observed_content);
  EXPECT_TRUE(done_reading);
  EXPECT_FALSE(delegate_.request_failed());
}

}  // namespace

}  // namespace net
```