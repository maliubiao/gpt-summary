Response:
Let's break down the request and the provided code step-by-step to construct a comprehensive answer.

**1. Understanding the Core Request:**

The primary goal is to analyze the `file_writer_test.cc` file and explain its functionality, its relation to web technologies, provide examples, discuss potential errors, and trace user interaction to this point.

**2. Initial Code Examination (Skimming and High-Level Understanding):**

* **Includes:** The `#include` statements tell us this code uses Google Test (`gtest`), Blink-specific classes (`Blob`, `FileWriterBase`), and platform utilities. This immediately suggests it's a unit test file for the `FileWriterBase` class.
* **Namespaces:** The `blink` namespace confirms it's part of the Chromium Blink rendering engine.
* **Constants:**  The `k...Offset` constants suggest different test scenarios for file operations.
* **`TestableFileWriter` Class:** This class inherits from `FileWriterBase` and overrides `DoTruncate`, `DoWrite`, and `DoCancel`. It also has a lot of boolean flags and member variables to track the execution of these methods and their callbacks. This clearly indicates a mocking/stubbing strategy for testing.
* **`FileWriterTest` Class:**  This is the actual test fixture, setting up an instance of `TestableFileWriter`.
* **`TEST_F` Macros:**  These are Google Test macros defining individual test cases. The names of the tests (e.g., `BasicFileWrite`, `ErrorFileTruncate`) strongly suggest the scenarios being tested.

**3. Deeper Dive into `TestableFileWriter`:**

* **Purpose:** It's designed to *simulate* different outcomes of file writing and truncation operations. Instead of actually interacting with the file system, it sets flags and calls the `Did*` methods to mimic success, failure, or cancellation.
* **Logic within `DoTruncate` and `DoWrite`:** The `if` conditions based on the `offset` values are crucial. They control *how* the simulated operation behaves (success, failure, cancellation). This is the core of the test setup.
* **Tracking with Flags:** The `received_...` flags are used to verify that the correct methods (`DoTruncate`, `DoWrite`, `DoCancel`) were called by the `FileWriterBase` class.
* **Verifying Callbacks:** The `received_did_...` flags and `fail_error_received_` are used to verify that the `FileWriterBase` class correctly calls its callback methods (`DidWriteImpl`, `DidTruncateImpl`, `DidFailImpl`) based on the simulated outcomes.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **FileWriter API:** The most direct connection is the JavaScript `FileWriter` API (part of the File API). This API allows web pages to write data to files within a sandboxed file system. The C++ `FileWriterBase` is likely the underlying implementation for this browser feature.
* **Blobs:** The use of `Blob` objects links to how JavaScript represents file-like data in the browser.
* **User Actions:** Consider how a user might trigger file saving in a web application. Downloading a file, saving an edited image, or using a web-based text editor are all potential entry points.

**5. Constructing Examples and Scenarios:**

* **Basic Operations:**  Create simple success scenarios for writing and truncating.
* **Error Handling:** Simulate file not found errors.
* **Cancellation:**  Demonstrate how a user might cancel an operation and how the code handles it.
* **Multi-part Writes:** Show a scenario with multiple `DidWrite` calls.

**6. Identifying Potential User/Programming Errors:**

* **Incorrect API Usage:**  Calling methods in the wrong order, providing invalid parameters.
* **Permissions:**  Thinking about real-world file system restrictions.
* **Race Conditions (Implicit):** While not explicitly tested here, consider scenarios where multiple file operations might conflict.

**7. Tracing User Interaction:**

* **Start with the End:** Begin with the `file_writer_test.cc` file.
* **Work Backwards:**  Consider how the `FileWriterBase` class would be used. It's likely called by code handling the JavaScript `FileWriter` API.
* **User Actions:** Identify specific user actions in a web browser that could lead to using the `FileWriter` API.

**8. Structuring the Output:**

Organize the information logically:

* **File Functionality:**  Clearly state the purpose of the test file.
* **Relationship to Web Technologies:** Explain the connection to JavaScript APIs and data structures.
* **Examples:** Provide concrete illustrations of how the code works.
* **User/Programming Errors:**  Offer practical examples of mistakes.
* **Debugging Clues:** Describe how a user might arrive at this code during debugging.

**Self-Correction/Refinement during Thought Process:**

* **Initial thought:** Focus solely on the C++ code.
* **Correction:**  Realize the importance of connecting it to the web platform and user actions.
* **Initial thought:**  Simply list the test names.
* **Correction:** Explain the *purpose* of each test and how it exercises the `FileWriterBase` class.
* **Initial thought:**  Oversimplify the user interaction.
* **Correction:** Provide a more detailed step-by-step scenario.

By following this structured approach, combining code analysis with an understanding of web technologies and user behavior, we can generate a comprehensive and accurate explanation of the `file_writer_test.cc` file.
这个文件 `blink/renderer/modules/filesystem/file_writer_test.cc` 是 Chromium Blink 渲染引擎中的一个 C++ **单元测试文件**。它的主要功能是 **测试 `FileWriterBase` 类的各种功能和边界情况**。`FileWriterBase` 是一个用于实现文件写入操作的基类，它被用来处理 JavaScript File API 中 `FileWriter` 接口的底层操作。

让我们详细列举一下它的功能和与 Web 技术的关系：

**1. 功能：**

* **测试基本的文件写入操作 (`BasicFileWrite`)：** 验证 `FileWriterBase` 能否正确处理基本的文件写入请求，包括接收路径、偏移量和要写入的 Blob 数据。它模拟成功的写入操作，并检查回调函数是否被正确调用。
* **测试基本的文件截断操作 (`BasicFileTruncate`)：**  验证 `FileWriterBase` 能否正确处理文件截断请求，包括接收路径和截断的偏移量。它模拟成功的截断操作，并检查回调函数。
* **测试文件写入错误处理 (`ErrorFileWrite`)：** 模拟文件写入过程中发生错误的情况（例如，文件未找到），并验证 `FileWriterBase` 能否正确处理错误，并调用相应的错误回调。
* **测试文件截断错误处理 (`ErrorFileTruncate`)：** 模拟文件截断过程中发生错误的情况，并验证 `FileWriterBase` 能否正确处理错误。
* **测试多次文件写入 (`MultiFileWrite`)：** 验证 `FileWriterBase` 能否处理需要多次回调 `DidWrite` 的写入操作，模拟逐步写入数据的过程。
* **测试文件写入取消（完成前和完成后 `CancelFileWriteBeforeCompletion`, `CancelFileWriteAfterCompletion`）：** 模拟在文件写入完成前和完成后取消操作，并验证 `FileWriterBase` 能否正确处理取消请求，调用取消回调，并处理未完成的写入操作。
* **测试文件截断取消 (`CancelFileTruncate`, `CancelFailedTruncate`)：** 模拟取消文件截断操作，包括在截断成功和失败的情况下取消，并验证 `FileWriterBase` 的行为。

**2. 与 JavaScript, HTML, CSS 的关系：**

这个 C++ 测试文件直接关联到 **JavaScript File API** 中的 `FileWriter` 接口。

* **JavaScript `FileWriter`:**  Web 开发者可以使用 JavaScript 的 `FileWriter` 接口来向用户本地文件系统中的文件写入数据。
* **HTML `<input type="file">`:** 用户通过 HTML 的 `<input type="file">` 元素选择本地文件后，JavaScript 可以获取到 `File` 对象，然后可以通过 `Blob` 或 `ArrayBuffer` 等形式传递给 `FileWriter` 进行写入操作。
* **CSS (间接关系):** CSS 本身不直接参与文件写入操作。但是，网页的布局和用户交互（例如，点击“保存”按钮）可能会触发 JavaScript 代码调用 `FileWriter`。

**举例说明：**

假设一个简单的 Web 应用允许用户编辑文本并在本地保存：

1. **HTML:**  页面包含一个 `<textarea>` 供用户输入文本，以及一个 `<button>` 用于触发保存操作。
2. **JavaScript:**
   ```javascript
   const saveButton = document.getElementById('saveButton');
   const textArea = document.getElementById('textArea');

   saveButton.addEventListener('click', () => {
     const textContent = textArea.value;
     const blob = new Blob([textContent], { type: 'text/plain' });

     // 获取 FileEntry (假设已经通过某种方式获得，例如 Directory API 或选择文件)
     fileEntry.createWriter(function(fileWriter) {
       fileWriter.onwriteend = function(e) {
         console.log('Write completed.');
       };
       fileWriter.onerror = function(e) {
         console.log('Write failed: ' + e.toString());
       };

       // 开始写入
       fileWriter.write(blob);
     }, function(e) {console.log('Create writer failed: ' + e.toString());});
   });
   ```
3. **C++ (`file_writer_test.cc` 测试的底层实现):** 当 JavaScript 调用 `fileWriter.write(blob)` 时，Blink 渲染引擎会调用底层的 C++ 代码来处理这个请求。`FileWriterBase` 以及其实现类（例如，实际与操作系统交互的类）将会被调用。 `file_writer_test.cc` 中的测试用例就是为了验证 `FileWriterBase` 在接收到类似这样的请求时，其内部逻辑是否正确，例如：
    * `BasicFileWrite` 测试模拟了成功写入 `blob` 数据到指定路径。
    * `ErrorFileWrite` 测试模拟了在写入过程中发生错误（例如，权限不足）。
    * `CancelFileWriteBeforeCompletion` 测试模拟了在写入过程中用户取消保存操作。

**3. 逻辑推理 (假设输入与输出):**

假设我们运行 `FileWriterTest` 中的 `BasicFileWrite` 测试：

* **假设输入:**
    * `FileWriterBase` 对象被初始化，关联到一个模拟的文件路径 "MockPath"。
    * 调用 `writer()->Write(kBasicFileWrite_Offset, *blob)`，其中 `kBasicFileWrite_Offset` 的值为 1，`blob` 是一个包含一些数据的 `Blob` 对象。
* **逻辑推理:**
    * `FileWriterBase` 的 `Write` 方法会调用派生类 `TestableFileWriter` 的 `DoWrite` 方法。
    * `DoWrite` 方法会检查 `offset` 是否等于 `kBasicFileWrite_Offset` (即 1)。
    * 因为条件成立，`DoWrite` 会调用 `DidWrite(1, true)`，模拟成功写入 1 字节并完成。
    * `DidWrite` 会更新 `TestableFileWriter` 的内部状态，例如 `received_did_write_count_` 和 `received_did_write_complete_`。
* **预期输出 (测试断言):**
    * `testable_writer_->received_write_` 为 `true`。
    * `testable_writer_->received_write_path_` 等于 "MockPath"。
    * `testable_writer_->received_write_offset_` 等于 1。
    * `testable_writer_->received_write_blob_` 指向传入的 `blob` 对象。
    * `testable_writer_->received_did_write_count_` 等于 1。
    * `testable_writer_->received_did_write_complete_` 为 `true`。

**4. 用户或编程常见的使用错误 (举例说明):**

* **JavaScript 中错误地使用 `FileWriter` API:**
    * **未处理错误回调:**  开发者可能忘记或不正确地处理 `onerror` 回调，导致文件写入失败时用户没有得到提示。
    * **尝试写入不存在的目录:**  如果 JavaScript 代码尝试写入一个用户本地文件系统中不存在的目录，`FileWriter` 操作将会失败。
    * **超过配额限制:**  如果涉及到沙箱文件系统，写入的数据量超过了分配的配额，操作会失败。
    * **并发写入冲突:**  如果多个 JavaScript 代码同时尝试写入同一个文件，可能会导致数据损坏或操作失败。
* **底层实现 (`FileWriterBase` 及其派生类) 的错误:**
    * **资源泄漏:**  在文件操作过程中未能正确释放文件句柄或其他资源。
    * **逻辑错误:**  在处理偏移量、数据大小等方面存在计算错误。
    * **线程安全问题:**  如果 `FileWriterBase` 的实现不是线程安全的，在多线程环境下可能会出现竞争条件。

**5. 用户操作是如何一步步的到达这里 (作为调试线索):**

当开发者在调试与文件写入相关的 Web 应用问题时，他们可能会逐步追踪代码执行路径到达 `file_writer_test.cc`，特别是在涉及到 Blink 渲染引擎内部行为时。以下是一个可能的调试流程：

1. **用户操作:** 用户在网页上点击了“保存”按钮，触发了一个文件保存操作。
2. **JavaScript 代码执行:**  网页上的 JavaScript 代码（类似于上面的例子）创建了一个 `Blob` 对象，并调用了 `fileEntry.createWriter()` 和 `fileWriter.write(blob)`。
3. **Blink 渲染引擎处理:** 浏览器接收到 JavaScript 的文件写入请求，并将其传递给 Blink 渲染引擎的相应模块。
4. **调用 `FileWriterBase`:**  Blink 内部会将 JavaScript 的 `FileWriter` 操作映射到 C++ 的 `FileWriterBase` 类及其派生类。
5. **调试:** 开发者可能在 JavaScript 代码中设置断点，观察 `FileWriter` 对象的状态和回调函数的执行情况。如果发现问题似乎发生在底层，他们可能会进一步查看 Blink 渲染引擎的源代码。
6. **查看 `file_writer_test.cc`:**  为了理解 `FileWriterBase` 的预期行为以及可能的错误情况，开发者可能会查看 `file_writer_test.cc` 文件，了解各种测试用例是如何验证 `FileWriterBase` 的功能的。例如，如果用户报告文件写入失败，开发者可能会查看 `ErrorFileWrite` 测试用例，了解 `FileWriterBase` 如何处理错误。
7. **设置 C++ 断点:** 如果开发者需要深入了解 Blink 内部的执行流程，他们可能会在 `FileWriterBase` 的方法（例如 `Write`、`Truncate`、`DoWrite`、`DoTruncate`）中设置断点，以便跟踪代码执行并检查变量的值。

总之，`blink/renderer/modules/filesystem/file_writer_test.cc` 是一个关键的测试文件，用于确保 Blink 渲染引擎中文件写入功能的正确性和健壮性。它与 JavaScript File API 紧密相关，并且可以作为开发者理解底层实现和调试相关问题的宝贵资源。

Prompt: 
```
这是目录为blink/renderer/modules/filesystem/file_writer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/modules/filesystem/file_writer_base.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

namespace {

// We use particular offsets to trigger particular behaviors
// in the TestableFileWriter.
const int kNoOffset = -1;
const int kBasicFileTruncate_Offset = 1;
const int kErrorFileTruncate_Offset = 2;
const int kCancelFileTruncate_Offset = 3;
const int kCancelFailedTruncate_Offset = 4;
const int kBasicFileWrite_Offset = 1;
const int kErrorFileWrite_Offset = 2;
const int kMultiFileWrite_Offset = 3;
const int kCancelFileWriteBeforeCompletion_Offset = 4;
const int kCancelFileWriteAfterCompletion_Offset = 5;

KURL mock_path_as_kurl() {
  return KURL("MockPath");
}

Blob* CreateTestBlob() {
  return MakeGarbageCollected<Blob>(BlobDataHandle::Create());
}

}  // namespace

class TestableFileWriter : public GarbageCollected<TestableFileWriter>,
                           public FileWriterBase {
 public:
  explicit TestableFileWriter() { reset(); }

  void reset() {
    received_truncate_ = false;
    received_truncate_path_ = KURL();
    received_truncate_offset_ = kNoOffset;
    received_write_ = false;
    received_write_path_ = KURL();
    received_write_offset_ = kNoOffset;
    received_write_blob_ = nullptr;
    received_cancel_ = false;

    received_did_write_count_ = 0;
    received_did_write_bytes_total_ = 0;
    received_did_write_complete_ = false;
    received_did_truncate_ = false;
    received_did_fail_ = false;
    fail_error_received_ = static_cast<base::File::Error>(0);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(received_write_blob_);
    FileWriterBase::Trace(visitor);
  }

  bool received_truncate_;
  KURL received_truncate_path_;
  int64_t received_truncate_offset_;
  bool received_write_;
  KURL received_write_path_;
  Member<const Blob> received_write_blob_;
  int64_t received_write_offset_;
  bool received_cancel_;

  int received_did_write_count_;
  int64_t received_did_write_bytes_total_;
  bool received_did_write_complete_;
  bool received_did_truncate_;
  bool received_did_fail_;
  base::File::Error fail_error_received_;

 protected:
  void DoTruncate(const KURL& path, int64_t offset) override {
    received_truncate_ = true;
    received_truncate_path_ = path;
    received_truncate_offset_ = offset;

    if (offset == kBasicFileTruncate_Offset) {
      DidSucceed();
    } else if (offset == kErrorFileTruncate_Offset) {
      DidFail(base::File::FILE_ERROR_NOT_FOUND);
    } else if (offset == kCancelFileTruncate_Offset) {
      Cancel();
      DidSucceed();  // truncate completion
      DidSucceed();  // cancel completion
    } else if (offset == kCancelFailedTruncate_Offset) {
      Cancel();
      DidFail(base::File::FILE_ERROR_NOT_FOUND);  // truncate completion
      DidSucceed();                               // cancel completion
    } else {
      FAIL();
    }
  }

  void DoWrite(const KURL& path, const Blob& blob, int64_t offset) override {
    received_write_ = true;
    received_write_path_ = path;
    received_write_offset_ = offset;
    received_write_blob_ = &blob;

    if (offset == kBasicFileWrite_Offset) {
      DidWrite(1, true);
    } else if (offset == kErrorFileWrite_Offset) {
      DidFail(base::File::FILE_ERROR_NOT_FOUND);
    } else if (offset == kMultiFileWrite_Offset) {
      DidWrite(1, false);
      DidWrite(1, false);
      DidWrite(1, true);
    } else if (offset == kCancelFileWriteBeforeCompletion_Offset) {
      DidWrite(1, false);
      Cancel();
      DidWrite(1, false);
      DidWrite(1, false);
      DidFail(base::File::FILE_ERROR_NOT_FOUND);  // write completion
      DidSucceed();                               // cancel completion
    } else if (offset == kCancelFileWriteAfterCompletion_Offset) {
      DidWrite(1, false);
      Cancel();
      DidWrite(1, false);
      DidWrite(1, false);
      DidWrite(1, true);                          // write completion
      DidFail(base::File::FILE_ERROR_NOT_FOUND);  // cancel completion
    } else {
      FAIL();
    }
  }

  void DoCancel() override { received_cancel_ = true; }

  void DidWriteImpl(int64_t bytes, bool complete) override {
    EXPECT_FALSE(received_did_write_complete_);
    ++received_did_write_count_;
    received_did_write_bytes_total_ += bytes;
    if (complete)
      received_did_write_complete_ = true;
  }

  void DidTruncateImpl() override {
    EXPECT_FALSE(received_did_truncate_);
    received_did_truncate_ = true;
  }

  void DidFailImpl(base::File::Error error) override {
    EXPECT_FALSE(received_did_fail_);
    received_did_fail_ = true;
    fail_error_received_ = error;
  }
};

class FileWriterTest : public testing::Test {
 public:
  FileWriterTest() = default;

  FileWriterTest(const FileWriterTest&) = delete;
  FileWriterTest& operator=(const FileWriterTest&) = delete;

  FileWriterBase* writer() { return testable_writer_.Get(); }

 protected:
  void SetUp() override {
    testable_writer_ = MakeGarbageCollected<TestableFileWriter>();
    testable_writer_->Initialize(mock_path_as_kurl(), 10);
  }

  test::TaskEnvironment task_environment_;
  Persistent<TestableFileWriter> testable_writer_;
};

TEST_F(FileWriterTest, BasicFileWrite) {
  Blob* blob = CreateTestBlob();
  writer()->Write(kBasicFileWrite_Offset, *blob);

  // Check that the Do* methods of the derived class get called correctly.
  EXPECT_TRUE(testable_writer_->received_write_);
  EXPECT_EQ(testable_writer_->received_write_path_, mock_path_as_kurl());
  EXPECT_EQ(kBasicFileWrite_Offset, testable_writer_->received_write_offset_);
  EXPECT_EQ(blob, testable_writer_->received_write_blob_);
  EXPECT_FALSE(testable_writer_->received_truncate_);
  EXPECT_FALSE(testable_writer_->received_cancel_);

  // Check that the Did*Impl methods of the client gets called correctly.
  EXPECT_EQ(1, testable_writer_->received_did_write_count_);
  EXPECT_TRUE(testable_writer_->received_did_write_complete_);
  EXPECT_EQ(1, testable_writer_->received_did_write_bytes_total_);
  EXPECT_FALSE(testable_writer_->received_did_truncate_);
  EXPECT_FALSE(testable_writer_->received_did_fail_);
}

TEST_F(FileWriterTest, BasicFileTruncate) {
  writer()->Truncate(kBasicFileTruncate_Offset);

  // Check that the Do* methods of the derived class get called correctly.
  EXPECT_TRUE(testable_writer_->received_truncate_);
  EXPECT_EQ(mock_path_as_kurl(), testable_writer_->received_truncate_path_);
  EXPECT_EQ(kBasicFileTruncate_Offset,
            testable_writer_->received_truncate_offset_);
  EXPECT_FALSE(testable_writer_->received_write_);
  EXPECT_FALSE(testable_writer_->received_cancel_);

  // Check that the Did*Impl methods of the client gets called correctly.
  EXPECT_TRUE(testable_writer_->received_did_truncate_);
  EXPECT_EQ(0, testable_writer_->received_did_write_count_);
  EXPECT_FALSE(testable_writer_->received_did_fail_);
}

TEST_F(FileWriterTest, ErrorFileWrite) {
  Blob* blob = CreateTestBlob();
  writer()->Write(kErrorFileWrite_Offset, *blob);

  // Check that the Do* methods of the derived class get called correctly.
  EXPECT_TRUE(testable_writer_->received_write_);
  EXPECT_EQ(testable_writer_->received_write_path_, mock_path_as_kurl());
  EXPECT_EQ(kErrorFileWrite_Offset, testable_writer_->received_write_offset_);
  EXPECT_EQ(blob, testable_writer_->received_write_blob_);
  EXPECT_FALSE(testable_writer_->received_truncate_);
  EXPECT_FALSE(testable_writer_->received_cancel_);

  // Check that the Did*Impl methods of the client gets called correctly.
  EXPECT_TRUE(testable_writer_->received_did_fail_);
  EXPECT_EQ(base::File::FILE_ERROR_NOT_FOUND,
            testable_writer_->fail_error_received_);
  EXPECT_EQ(0, testable_writer_->received_did_write_count_);
  EXPECT_FALSE(testable_writer_->received_did_truncate_);
}

TEST_F(FileWriterTest, ErrorFileTruncate) {
  writer()->Truncate(kErrorFileTruncate_Offset);

  // Check that the Do* methods of the derived class get called correctly.
  EXPECT_TRUE(testable_writer_->received_truncate_);
  EXPECT_EQ(mock_path_as_kurl(), testable_writer_->received_truncate_path_);
  EXPECT_EQ(kErrorFileTruncate_Offset,
            testable_writer_->received_truncate_offset_);
  EXPECT_FALSE(testable_writer_->received_write_);
  EXPECT_FALSE(testable_writer_->received_cancel_);

  // Check that the Did*Impl methods of the client gets called correctly.
  EXPECT_TRUE(testable_writer_->received_did_fail_);
  EXPECT_EQ(base::File::FILE_ERROR_NOT_FOUND,
            testable_writer_->fail_error_received_);
  EXPECT_FALSE(testable_writer_->received_did_truncate_);
  EXPECT_EQ(0, testable_writer_->received_did_write_count_);
}

TEST_F(FileWriterTest, MultiFileWrite) {
  Blob* blob = CreateTestBlob();
  writer()->Write(kMultiFileWrite_Offset, *blob);

  // Check that the Do* methods of the derived class get called correctly.
  EXPECT_TRUE(testable_writer_->received_write_);
  EXPECT_EQ(testable_writer_->received_write_path_, mock_path_as_kurl());
  EXPECT_EQ(kMultiFileWrite_Offset, testable_writer_->received_write_offset_);
  EXPECT_EQ(blob, testable_writer_->received_write_blob_);
  EXPECT_FALSE(testable_writer_->received_truncate_);
  EXPECT_FALSE(testable_writer_->received_cancel_);

  // Check that the Did*Impl methods of the client gets called correctly.
  EXPECT_EQ(3, testable_writer_->received_did_write_count_);
  EXPECT_TRUE(testable_writer_->received_did_write_complete_);
  EXPECT_EQ(3, testable_writer_->received_did_write_bytes_total_);
  EXPECT_FALSE(testable_writer_->received_did_truncate_);
  EXPECT_FALSE(testable_writer_->received_did_fail_);
}

TEST_F(FileWriterTest, CancelFileWriteBeforeCompletion) {
  Blob* blob = CreateTestBlob();
  writer()->Write(kCancelFileWriteBeforeCompletion_Offset, *blob);

  // Check that the Do* methods of the derived class get called correctly.
  EXPECT_TRUE(testable_writer_->received_write_);
  EXPECT_EQ(testable_writer_->received_write_path_, mock_path_as_kurl());
  EXPECT_EQ(kCancelFileWriteBeforeCompletion_Offset,
            testable_writer_->received_write_offset_);
  EXPECT_EQ(blob, testable_writer_->received_write_blob_);
  EXPECT_TRUE(testable_writer_->received_cancel_);
  EXPECT_FALSE(testable_writer_->received_truncate_);

  // Check that the Did*Impl methods of the client gets called correctly.
  EXPECT_TRUE(testable_writer_->received_did_fail_);
  EXPECT_EQ(base::File::FILE_ERROR_ABORT,
            testable_writer_->fail_error_received_);
  EXPECT_EQ(1, testable_writer_->received_did_write_count_);
  EXPECT_FALSE(testable_writer_->received_did_write_complete_);
  EXPECT_EQ(1, testable_writer_->received_did_write_bytes_total_);
  EXPECT_FALSE(testable_writer_->received_did_truncate_);
}

TEST_F(FileWriterTest, CancelFileWriteAfterCompletion) {
  Blob* blob = CreateTestBlob();
  writer()->Write(kCancelFileWriteAfterCompletion_Offset, *blob);

  // Check that the Do* methods of the derived class get called correctly.
  EXPECT_TRUE(testable_writer_->received_write_);
  EXPECT_EQ(testable_writer_->received_write_path_, mock_path_as_kurl());
  EXPECT_EQ(kCancelFileWriteAfterCompletion_Offset,
            testable_writer_->received_write_offset_);
  EXPECT_EQ(blob, testable_writer_->received_write_blob_);
  EXPECT_TRUE(testable_writer_->received_cancel_);
  EXPECT_FALSE(testable_writer_->received_truncate_);

  // Check that the Did*Impl methods of the client gets called correctly.
  EXPECT_TRUE(testable_writer_->received_did_fail_);
  EXPECT_EQ(base::File::FILE_ERROR_ABORT,
            testable_writer_->fail_error_received_);
  EXPECT_EQ(1, testable_writer_->received_did_write_count_);
  EXPECT_FALSE(testable_writer_->received_did_write_complete_);
  EXPECT_EQ(1, testable_writer_->received_did_write_bytes_total_);
  EXPECT_FALSE(testable_writer_->received_did_truncate_);
}

TEST_F(FileWriterTest, CancelFileTruncate) {
  writer()->Truncate(kCancelFileTruncate_Offset);

  // Check that the Do* methods of the derived class get called correctly.
  EXPECT_TRUE(testable_writer_->received_truncate_);
  EXPECT_EQ(mock_path_as_kurl(), testable_writer_->received_truncate_path_);
  EXPECT_EQ(kCancelFileTruncate_Offset,
            testable_writer_->received_truncate_offset_);
  EXPECT_TRUE(testable_writer_->received_cancel_);
  EXPECT_FALSE(testable_writer_->received_write_);

  // Check that the Did*Impl methods of the client gets called correctly.
  EXPECT_TRUE(testable_writer_->received_did_fail_);
  EXPECT_EQ(base::File::FILE_ERROR_ABORT,
            testable_writer_->fail_error_received_);
  EXPECT_FALSE(testable_writer_->received_did_truncate_);
  EXPECT_EQ(0, testable_writer_->received_did_write_count_);
}

TEST_F(FileWriterTest, CancelFailedTruncate) {
  writer()->Truncate(kCancelFailedTruncate_Offset);

  // Check that the Do* methods of the derived class get called correctly.
  EXPECT_TRUE(testable_writer_->received_truncate_);
  EXPECT_EQ(mock_path_as_kurl(), testable_writer_->received_truncate_path_);
  EXPECT_EQ(kCancelFailedTruncate_Offset,
            testable_writer_->received_truncate_offset_);
  EXPECT_TRUE(testable_writer_->received_cancel_);
  EXPECT_FALSE(testable_writer_->received_write_);

  // Check that the Did*Impl methods of the client gets called correctly.
  EXPECT_TRUE(testable_writer_->received_did_fail_);
  EXPECT_EQ(base::File::FILE_ERROR_ABORT,
            testable_writer_->fail_error_received_);
  EXPECT_FALSE(testable_writer_->received_did_truncate_);
  EXPECT_EQ(0, testable_writer_->received_did_write_count_);
}

}  // namespace blink

"""

```