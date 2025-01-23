Response:
Let's break down the thought process to analyze the provided C++ code and generate the comprehensive explanation.

**1. Understanding the Core Task:**

The fundamental goal is to understand the functionality of the `UploadFileElementReader` class as demonstrated by its unit tests in `upload_file_element_reader_unittest.cc`. The request asks for a summary of its features, potential relationships with JavaScript, logical reasoning examples, common usage errors, and debugging context.

**2. Initial Code Scan and Key Observations:**

* **Filename and Context:**  The filename clearly indicates this is a unit test file for `UploadFileElementReader`. The `net/base` path suggests it's part of Chromium's network stack and deals with low-level network operations.
* **Testing Framework:** The code uses Google Test (`TEST_P`, `EXPECT_EQ`, `ASSERT_TRUE`, etc.) which is standard for Chromium. The `WithTaskEnvironment` base class hints at asynchronous operations.
* **Test Cases:** The names of the test cases (`ReadPartially`, `ReadAll`, `ReadTooMuch`, `MultipleInit`, etc.) provide direct clues about the functionalities being tested.
* **`UploadFileElementReader` Construction:** The `CreateReader` method and the `TEST_P` parameterization indicate that the reader can be constructed in two ways: either given a `FilePath` and opening the file itself, or given an already opened `base::File`.
* **Key Methods:** The tests heavily use `Init()` and `Read()`, suggesting these are the core functionalities. The `GetContentLength()` and `BytesRemaining()` methods are also called.
* **Error Handling:**  The code checks for `ERR_IO_PENDING`, `IsOk()`, `IsError()`, `ERR_UPLOAD_FILE_CHANGED`, and `ERR_FILE_NOT_FOUND`, highlighting the asynchronous nature and potential error scenarios.
* **Data Handling:** The tests read data from a temporary file into `IOBuffer` objects.
* **Asynchronous Operations:** The use of `TestCompletionCallback` strongly suggests that `Init()` and `Read()` are asynchronous operations.
* **File Modification Time:** The `FileChanged` test indicates that the reader can verify the file's modification time.

**3. Deconstructing the Functionality Based on Test Cases:**

* **`ReadPartially`:**  Verifies reading a portion of the file. Input: a file. Output: a chunk of the file's content.
* **`ReadAll`:** Verifies reading the entire file. Input: a file. Output: the entire file's content.
* **`ReadTooMuch`:** Tests reading beyond the file's end. Input: a file, a buffer larger than the file. Output: the file's content.
* **`MultipleInit`:**  Checks the behavior of calling `Init()` multiple times, ensuring it resets the reader. Input: a file. Output: file content after multiple inits.
* **`InitDuringAsyncOperation`:** Examines calling `Init()` while a `Read()` operation is pending, confirming cancellation and proper handling. Input: a file, initiation of a read. Output: No output from the initial read, successful subsequent read after a new `Init`.
* **`RepeatedInitDuringInit`:** Tests calling `Init()` multiple times while an `Init()` operation is pending, demonstrating proper cancellation. Input: a file, multiple `Init()` calls. Output: Successful subsequent read after the final `Init`.
* **`Range`:**  Confirms reading a specific range (offset and length) within the file. Input: a file, offset, length. Output: the specified range of the file's content.
* **`FileChanged`:**  Verifies the error condition when the file's modification time differs from the expected time. Input: a file, an older expected modification time. Output: an error indicating the file changed.
* **`InexactExpectedTimeStamp`:**  Demonstrates tolerance for slight differences in expected modification time. Input: a file, a slightly off expected modification time. Output: successful initialization.
* **`WrongPath`:**  Tests the error condition when an invalid file path is provided. Input: an invalid file path. Output: an error indicating the file was not found.

**4. Identifying Relationships with JavaScript:**

* **File Uploads:** The core functionality clearly relates to file uploads in web browsers. JavaScript running in a web page can initiate file uploads.
* **`FormData` API:**  The `FormData` API in JavaScript is the standard way to construct data to be sent in HTTP requests, including files. The `UploadFileElementReader` likely plays a role in processing the file data associated with `FormData`.
* **Asynchronous Operations (Promises/Async-Await):**  Since the C++ code uses asynchronous operations, the corresponding JavaScript interaction would involve Promises or async/await to handle the asynchronous nature of file reading and network transfer.

**5. Formulating Logical Reasoning Examples:**

Based on the test cases, creating "if-then" scenarios becomes straightforward:

* **Input:** A file with content "abcdefg", `offset = 2`, `length = 3`. **Output:** The reader will output "cde".
* **Input:**  A file that is modified after the reader is initialized with an expected modification time. **Output:** The `Init()` call will return an error.

**6. Identifying Common Usage Errors:**

* **Incorrect File Path:**  Providing a non-existent file path.
* **File Deletion:** Deleting the file while the reader is still open (though the `FLAG_WIN_SHARE_DELETE` mitigates this on Windows in the test).
* **Incorrect Offset/Length:** Providing an offset or length that goes beyond the file boundaries.
* **Mismatched Expected Modification Time:**  Assuming the file hasn't changed when it has.

**7. Tracing User Steps and Debugging:**

Thinking about how a user action leads to this code involves a sequence of events:

1. **User Selects File:** The user interacts with an HTML `<input type="file">` element and selects a file.
2. **JavaScript `FormData`:** JavaScript code uses the `FormData` API to create a request body containing the file.
3. **Browser Processing:** The browser's networking stack (where this C++ code resides) takes over the processing of the `FormData`.
4. **`UploadFileElementReader` Creation:**  The browser creates an `UploadFileElementReader` to read the contents of the selected file efficiently.
5. **`Init()` Call:** The `Init()` method is called to prepare the reader, possibly checking the file's existence and modification time.
6. **`Read()` Calls:**  The browser calls the `Read()` method in chunks to get the file data for transmission.

For debugging, one might:

* **Set Breakpoints:**  Place breakpoints in the `Init()` and `Read()` methods of `UploadFileElementReader` to inspect the file path, offset, length, and data being read.
* **Inspect Network Logs:** Examine the network requests in the browser's developer tools to see the size and content of the uploaded data.
* **Check File Permissions:** Ensure the browser process has the necessary permissions to read the selected file.

**8. Structuring the Explanation:**

Finally, organizing the gathered information into clear sections with headings and examples makes the explanation easy to understand. Using bullet points, code snippets, and "if-then" statements helps convey the information concisely. The prompt's specific requests (JavaScript relation, logical reasoning, errors, debugging) are addressed directly.
This C++ source code file, `upload_file_element_reader_unittest.cc`, contains unit tests for the `UploadFileElementReader` class in Chromium's network stack. The purpose of `UploadFileElementReader` is to efficiently read data from a file that is intended to be uploaded as part of an HTTP request.

Here's a breakdown of its functionality and how the tests demonstrate it:

**Functionality of `UploadFileElementReader`:**

* **Reading File Content:** The primary function is to read the content of a file in chunks. It supports reading the entire file or a specific range (offset and length).
* **Asynchronous Operations:** The reading operations are asynchronous, meaning they don't block the main thread. This is crucial for maintaining browser responsiveness during file uploads.
* **File Opening and Management:** It can either open the file itself given a file path or work with an already opened `base::File` object.
* **Content Length Reporting:** It provides methods to get the total content length of the file or the remaining bytes to be read.
* **File Modification Time Check:** It can optionally verify if the file's modification time matches an expected value. This helps detect if the file has been changed since the upload process began.
* **Resource Management:** It properly manages resources, such as closing the file when it's no longer needed.
* **Handling Errors:** It handles various file-related errors, such as the file not being found or the file being changed.

**Relationship with JavaScript Functionality:**

The `UploadFileElementReader` is a backend component that directly supports the file upload functionality initiated from JavaScript in a web page. Here's how they relate:

* **`HTMLInputElement` (`<input type="file">`):** When a user selects a file through a file input element in a web page, the browser needs to read the contents of this file to include it in an HTTP request.
* **`FormData` API:** JavaScript can use the `FormData` API to construct the body of an HTTP request, including files. When you append a `File` object to a `FormData` instance, the browser internally uses mechanisms like `UploadFileElementReader` to access and process the file's content.
* **`XMLHttpRequest` or `fetch` API:** When the JavaScript code sends the `FormData` using `XMLHttpRequest` or the `fetch` API, the browser's network stack utilizes `UploadFileElementReader` to stream the file data efficiently as part of the request body.

**Example:**

Imagine the following JavaScript code:

```javascript
const fileInput = document.getElementById('myFile');
const formData = new FormData();
formData.append('uploadedFile', fileInput.files[0]);

fetch('/upload', {
  method: 'POST',
  body: formData
});
```

In this scenario:

1. The user selects a file using the `fileInput`.
2. The `formData.append()` line adds the `File` object to the `FormData`.
3. When `fetch('/upload', ...)` is executed, the browser's network stack (which includes the code where `UploadFileElementReader` resides) will handle the file upload. An instance of `UploadFileElementReader` might be created to read the content of the file selected by the user. The `Read()` method of this reader would be called repeatedly to get chunks of the file data, which are then sent as part of the HTTP POST request to the `/upload` endpoint.

**Logical Reasoning with Assumptions and Outputs:**

Let's consider some test cases and perform logical reasoning:

**Test Case: `ReadPartially`**

* **Assumption (Input):** A temporary file is created with the content "123456789abcdefghi". The `UploadFileElementReader` is initialized to read this file. A buffer of size half the file size is provided for reading.
* **Logical Step:** The `Read()` method will be called with the buffer.
* **Output:** The `Read()` method will successfully read the first half of the file's content ("123456789ab") into the provided buffer. `BytesRemaining()` will return the remaining size of the file.

**Test Case: `ReadAll`**

* **Assumption (Input):** A temporary file with content "123456789abcdefghi". A buffer with the exact size of the file is provided.
* **Logical Step:** The `Read()` method is called.
* **Output:** The entire file content ("123456789abcdefghi") will be read into the buffer. `BytesRemaining()` will be 0.

**Test Case: `Range`**

* **Assumption (Input):** A temporary file with content "123456789abcdefghi". The `UploadFileElementReader` is initialized with an offset of 2 and a length that covers a portion of the file.
* **Logical Step:** The `Init()` method is called to prepare the reader with the range. Then, `Read()` is called.
* **Output:**  The `Read()` method will return the portion of the file starting from the specified offset, with the specified length.

**User or Programming Common Usage Errors:**

* **Providing an Incorrect File Path:** If the file path provided to `UploadFileElementReader` is incorrect, the `Init()` method will likely return an error (e.g., `ERR_FILE_NOT_FOUND`).

   ```c++
   // Incorrect usage:
   reader_ = std::make_unique<UploadFileElementReader>(
       base::SingleThreadTaskRunner::GetCurrentDefault().get(),
       base::FilePath(FILE_PATH_LITERAL("/non/existent/file.txt")), // Wrong path
       0, std::numeric_limits<uint64_t>::max(), base::Time());
   TestCompletionCallback init_callback;
   ASSERT_THAT(reader_->Init(init_callback.callback()), IsError(ERR_FILE_NOT_FOUND));
   ```

* **Deleting the File While Uploading:** If the user or another process deletes the file while the `UploadFileElementReader` is still reading it, subsequent `Read()` calls might fail or exhibit unexpected behavior. The test with `FLAG_WIN_SHARE_DELETE` shows how the file can be shared for deletion on Windows.

* **Incorrect Offset or Length:** Specifying an offset or length that goes beyond the bounds of the file can lead to errors or unexpected data being read. The tests ensure the reader handles such cases correctly.

* **Not Handling Asynchronous Completion:** Since `Init()` and `Read()` are asynchronous, it's crucial to use completion callbacks (like `TestCompletionCallback` in the tests) to know when the operations are finished and to handle the results. Forgetting to wait for the callback can lead to using uninitialized data or incorrect program flow.

**User Operations Leading to This Code (Debugging Clues):**

1. **User Initiates File Upload:** The user interacts with a web page and selects a file to upload using an `<input type="file">` element.
2. **Form Submission or AJAX Request:** The user submits a form containing the file input or JavaScript code initiates an AJAX request (using `XMLHttpRequest` or `fetch`) that includes the file data.
3. **Browser Processing:** The browser's rendering engine and JavaScript execution environment pass the file information to the browser's networking stack.
4. **`UploadFileElementReader` Instantiation:**  Within the networking stack, when processing the upload request, the browser may create an instance of `UploadFileElementReader` to handle reading the content of the selected file.
5. **`Init()` Call:** The `Init()` method of the `UploadFileElementReader` is called to initialize the reader, potentially opening the file and verifying its metadata.
6. **`Read()` Calls:** The browser's networking code will then repeatedly call the `Read()` method of the `UploadFileElementReader` to fetch chunks of the file's content. These chunks are then incorporated into the HTTP request body.

**Debugging Scenario:**

If a user reports that a file upload is failing or that the wrong file content is being uploaded, a developer might:

* **Set Breakpoints:** Place breakpoints in the `Init()` and `Read()` methods of `UploadFileElementReader` within the Chromium source code.
* **Inspect File Paths and Metadata:** Check the file path being passed to the `UploadFileElementReader` constructor and the metadata being retrieved in the `Init()` method.
* **Examine Buffer Contents:** Inspect the contents of the buffers being used in the `Read()` calls to verify that the correct data is being read from the file.
* **Trace Asynchronous Operations:** Follow the execution flow of the completion callbacks to ensure that the asynchronous operations are completing correctly and that errors are being handled appropriately.
* **Check File Permissions:** Verify that the browser process has the necessary permissions to read the file selected by the user.

The tests in `upload_file_element_reader_unittest.cc` are designed to cover various scenarios and edge cases to ensure the `UploadFileElementReader` functions correctly and robustly in different situations during file uploads. They serve as a critical part of the development and maintenance process for Chromium's network stack.

### 提示词
```
这是目录为net/base/upload_file_element_reader_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/upload_file_element_reader.h"

#include <stdint.h>

#include <limits>

#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

#if BUILDFLAG(IS_APPLE)
#include "base/apple/scoped_nsautorelease_pool.h"
#include "base/memory/stack_allocated.h"
#endif

using net::test::IsError;
using net::test::IsOk;

namespace net {

// When the parameter is false, the UploadFileElementReader is passed only a
// FilePath and needs to open the file itself. When it's true, it's passed an
// already open base::File.
class UploadFileElementReaderTest : public testing::TestWithParam<bool>,
                                    public WithTaskEnvironment {
 protected:
  void SetUp() override {
    // Some tests (*.ReadPartially) rely on bytes_.size() being even.
    bytes_.assign({'1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c',
                   'd', 'e', 'f', 'g', 'h', 'i'});

    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    ASSERT_TRUE(
        base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path_));
    ASSERT_TRUE(base::WriteFile(
        temp_file_path_, std::string_view(bytes_.data(), bytes_.size())));

    reader_ =
        CreateReader(0, std::numeric_limits<uint64_t>::max(), base::Time());

    TestCompletionCallback callback;
    ASSERT_THAT(reader_->Init(callback.callback()), IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_EQ(bytes_.size(), reader_->GetContentLength());
    EXPECT_EQ(bytes_.size(), reader_->BytesRemaining());
    EXPECT_FALSE(reader_->IsInMemory());
  }

  ~UploadFileElementReaderTest() override {
    reader_.reset();
    base::RunLoop().RunUntilIdle();
  }

  // Creates a UploadFileElementReader based on the value of GetParam().
  std::unique_ptr<UploadFileElementReader> CreateReader(
      int64_t offset,
      int64_t length,
      base::Time expected_modification_time) {
    if (GetParam()) {
      return std::make_unique<UploadFileElementReader>(
          base::SingleThreadTaskRunner::GetCurrentDefault().get(),
          temp_file_path_, offset, length, expected_modification_time);
    }

    // The base::File::FLAG_WIN_SHARE_DELETE lets the file be deleted without
    // the test fixture waiting on it to be closed.
    int open_flags = base::File::FLAG_OPEN | base::File::FLAG_READ |
                     base::File::FLAG_WIN_SHARE_DELETE;
#if BUILDFLAG(IS_WIN)
    // On Windows, file must be opened for asynchronous operation.
    open_flags |= base::File::FLAG_ASYNC;
#endif  // BUILDFLAG(IS_WIN)

    base::File file(temp_file_path_, open_flags);
    EXPECT_TRUE(file.IsValid());
    return std::make_unique<UploadFileElementReader>(
        base::SingleThreadTaskRunner::GetCurrentDefault().get(),
        std::move(file),
        // Use an incorrect path, to make sure that the file is never re-opened.
        base::FilePath(FILE_PATH_LITERAL("this_should_be_ignored")), offset,
        length, expected_modification_time);
  }

#if BUILDFLAG(IS_APPLE)
  // May be needed to avoid leaks on the Mac.
  STACK_ALLOCATED_IGNORE("https://crbug.com/1424190")
  base::apple::ScopedNSAutoreleasePool scoped_pool_;
#endif

  std::vector<char> bytes_;
  std::unique_ptr<UploadElementReader> reader_;
  base::ScopedTempDir temp_dir_;
  base::FilePath temp_file_path_;
};

TEST_P(UploadFileElementReaderTest, ReadPartially) {
  const size_t kHalfSize = bytes_.size() / 2;
  ASSERT_EQ(bytes_.size(), kHalfSize * 2);
  std::vector<char> buf(kHalfSize);
  auto wrapped_buffer = base::MakeRefCounted<WrappedIOBuffer>(buf);
  TestCompletionCallback read_callback1;
  ASSERT_EQ(ERR_IO_PENDING,
            reader_->Read(
                wrapped_buffer.get(), buf.size(), read_callback1.callback()));
  EXPECT_EQ(static_cast<int>(buf.size()), read_callback1.WaitForResult());
  EXPECT_EQ(bytes_.size() - buf.size(), reader_->BytesRemaining());
  EXPECT_EQ(std::vector<char>(bytes_.begin(), bytes_.begin() + kHalfSize), buf);

  TestCompletionCallback read_callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            reader_->Read(
                wrapped_buffer.get(), buf.size(), read_callback2.callback()));
  EXPECT_EQ(static_cast<int>(buf.size()), read_callback2.WaitForResult());
  EXPECT_EQ(0U, reader_->BytesRemaining());
  EXPECT_EQ(std::vector<char>(bytes_.begin() + kHalfSize, bytes_.end()), buf);
}

TEST_P(UploadFileElementReaderTest, ReadAll) {
  std::vector<char> buf(bytes_.size());
  auto wrapped_buffer = base::MakeRefCounted<WrappedIOBuffer>(buf);
  TestCompletionCallback read_callback;
  ASSERT_EQ(ERR_IO_PENDING,
            reader_->Read(
                wrapped_buffer.get(), buf.size(), read_callback.callback()));
  EXPECT_EQ(static_cast<int>(buf.size()), read_callback.WaitForResult());
  EXPECT_EQ(0U, reader_->BytesRemaining());
  EXPECT_EQ(bytes_, buf);
  // Try to read again.
  EXPECT_EQ(0,
            reader_->Read(
                wrapped_buffer.get(), buf.size(), read_callback.callback()));
}

TEST_P(UploadFileElementReaderTest, ReadTooMuch) {
  const size_t kTooLargeSize = bytes_.size() * 2;
  std::vector<char> buf(kTooLargeSize);
  auto wrapped_buffer = base::MakeRefCounted<WrappedIOBuffer>(buf);
  TestCompletionCallback read_callback;
  ASSERT_EQ(ERR_IO_PENDING,
            reader_->Read(
                wrapped_buffer.get(), buf.size(), read_callback.callback()));
  EXPECT_EQ(static_cast<int>(bytes_.size()), read_callback.WaitForResult());
  EXPECT_EQ(0U, reader_->BytesRemaining());
  buf.resize(bytes_.size());  // Resize to compare.
  EXPECT_EQ(bytes_, buf);
}

TEST_P(UploadFileElementReaderTest, MultipleInit) {
  std::vector<char> buf(bytes_.size());
  auto wrapped_buffer = base::MakeRefCounted<WrappedIOBuffer>(buf);

  // Read all.
  TestCompletionCallback read_callback1;
  ASSERT_EQ(ERR_IO_PENDING,
            reader_->Read(
                wrapped_buffer.get(), buf.size(), read_callback1.callback()));
  EXPECT_EQ(static_cast<int>(buf.size()), read_callback1.WaitForResult());
  EXPECT_EQ(0U, reader_->BytesRemaining());
  EXPECT_EQ(bytes_, buf);

  // Call Init() again to reset the state.
  TestCompletionCallback init_callback;
  ASSERT_THAT(reader_->Init(init_callback.callback()), IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback.WaitForResult(), IsOk());
  EXPECT_EQ(bytes_.size(), reader_->GetContentLength());
  EXPECT_EQ(bytes_.size(), reader_->BytesRemaining());

  // Read again.
  TestCompletionCallback read_callback2;
  ASSERT_EQ(ERR_IO_PENDING,
            reader_->Read(
                wrapped_buffer.get(), buf.size(), read_callback2.callback()));
  EXPECT_EQ(static_cast<int>(buf.size()), read_callback2.WaitForResult());
  EXPECT_EQ(0U, reader_->BytesRemaining());
  EXPECT_EQ(bytes_, buf);
}

TEST_P(UploadFileElementReaderTest, InitDuringAsyncOperation) {
  std::vector<char> buf(bytes_.size());
  auto wrapped_buffer = base::MakeRefCounted<WrappedIOBuffer>(buf);

  // Start reading all.
  TestCompletionCallback read_callback1;
  EXPECT_EQ(ERR_IO_PENDING,
            reader_->Read(
                wrapped_buffer.get(), buf.size(), read_callback1.callback()));

  // Call Init to cancel the previous read.
  TestCompletionCallback init_callback1;
  EXPECT_THAT(reader_->Init(init_callback1.callback()),
              IsError(ERR_IO_PENDING));

  // Call Init again to cancel the previous init.
  TestCompletionCallback init_callback2;
  EXPECT_THAT(reader_->Init(init_callback2.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback2.WaitForResult(), IsOk());
  EXPECT_EQ(bytes_.size(), reader_->GetContentLength());
  EXPECT_EQ(bytes_.size(), reader_->BytesRemaining());

  // Read half.
  std::vector<char> buf2(bytes_.size() / 2);
  auto wrapped_buffer2 = base::MakeRefCounted<WrappedIOBuffer>(buf2);
  TestCompletionCallback read_callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            reader_->Read(
                wrapped_buffer2.get(), buf2.size(), read_callback2.callback()));
  EXPECT_EQ(static_cast<int>(buf2.size()), read_callback2.WaitForResult());
  EXPECT_EQ(bytes_.size() - buf2.size(), reader_->BytesRemaining());
  EXPECT_EQ(std::vector<char>(bytes_.begin(), bytes_.begin() + buf2.size()),
            buf2);

  // Make sure callbacks are not called for cancelled operations.
  EXPECT_FALSE(read_callback1.have_result());
  EXPECT_FALSE(init_callback1.have_result());
}

TEST_P(UploadFileElementReaderTest, RepeatedInitDuringInit) {
  std::vector<char> buf(bytes_.size());
  auto wrapped_buffer = base::MakeRefCounted<WrappedIOBuffer>(buf);

  TestCompletionCallback init_callback1;
  EXPECT_THAT(reader_->Init(init_callback1.callback()),
              IsError(ERR_IO_PENDING));

  // Call Init again to cancel the previous init.
  TestCompletionCallback init_callback2;
  EXPECT_THAT(reader_->Init(init_callback2.callback()),
              IsError(ERR_IO_PENDING));

  // Call Init yet again to cancel the previous init.
  TestCompletionCallback init_callback3;
  EXPECT_THAT(reader_->Init(init_callback3.callback()),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(init_callback3.WaitForResult(), IsOk());
  EXPECT_EQ(bytes_.size(), reader_->GetContentLength());
  EXPECT_EQ(bytes_.size(), reader_->BytesRemaining());

  // Read all.
  TestCompletionCallback read_callback;
  int result =
      reader_->Read(wrapped_buffer.get(), buf.size(), read_callback.callback());
  EXPECT_EQ(static_cast<int>(buf.size()), read_callback.GetResult(result));
  EXPECT_EQ(0U, reader_->BytesRemaining());
  EXPECT_EQ(bytes_, buf);

  EXPECT_FALSE(init_callback1.have_result());
  EXPECT_FALSE(init_callback2.have_result());
}

TEST_P(UploadFileElementReaderTest, Range) {
  const uint64_t kOffset = 2;
  const uint64_t kLength = bytes_.size() - kOffset * 3;
  reader_ = CreateReader(kOffset, kLength, base::Time());
  TestCompletionCallback init_callback;
  ASSERT_THAT(reader_->Init(init_callback.callback()), IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback.WaitForResult(), IsOk());
  EXPECT_EQ(kLength, reader_->GetContentLength());
  EXPECT_EQ(kLength, reader_->BytesRemaining());
  std::vector<char> buf(kLength);
  auto wrapped_buffer = base::MakeRefCounted<WrappedIOBuffer>(buf);
  TestCompletionCallback read_callback;
  ASSERT_EQ(
      ERR_IO_PENDING,
      reader_->Read(wrapped_buffer.get(), kLength, read_callback.callback()));
  EXPECT_EQ(static_cast<int>(kLength), read_callback.WaitForResult());
  const std::vector<char> expected(bytes_.begin() + kOffset,
                                   bytes_.begin() + kOffset + kLength);
  EXPECT_EQ(expected, buf);
}

TEST_P(UploadFileElementReaderTest, FileChanged) {
  base::File::Info info;
  ASSERT_TRUE(base::GetFileInfo(temp_file_path_, &info));

  // Expect one second before the actual modification time to simulate change.
  const base::Time expected_modification_time =
      info.last_modified - base::Seconds(1);
  reader_ = CreateReader(0, std::numeric_limits<uint64_t>::max(),
                         expected_modification_time);
  TestCompletionCallback init_callback;
  ASSERT_THAT(reader_->Init(init_callback.callback()), IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback.WaitForResult(), IsError(ERR_UPLOAD_FILE_CHANGED));
}

TEST_P(UploadFileElementReaderTest, InexactExpectedTimeStamp) {
  base::File::Info info;
  ASSERT_TRUE(base::GetFileInfo(temp_file_path_, &info));

  const base::Time expected_modification_time =
      info.last_modified - base::Milliseconds(900);
  reader_ = CreateReader(0, std::numeric_limits<uint64_t>::max(),
                         expected_modification_time);
  TestCompletionCallback init_callback;
  ASSERT_THAT(reader_->Init(init_callback.callback()), IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback.WaitForResult(), IsOk());
}

TEST_P(UploadFileElementReaderTest, WrongPath) {
  const base::FilePath wrong_path(FILE_PATH_LITERAL("wrong_path"));
  reader_ = std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), wrong_path, 0,
      std::numeric_limits<uint64_t>::max(), base::Time());
  TestCompletionCallback init_callback;
  ASSERT_THAT(reader_->Init(init_callback.callback()), IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback.WaitForResult(), IsError(ERR_FILE_NOT_FOUND));
}

INSTANTIATE_TEST_SUITE_P(All,
                         UploadFileElementReaderTest,
                         testing::ValuesIn({false, true}));

}  // namespace net
```