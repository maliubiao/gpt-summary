Response:
The user wants a summary of the `elements_upload_data_stream_unittest.cc` file. I need to analyze the C++ code and identify its purpose and functionalities. The request has several specific points to address:

1. **Functionality:**  What does this test file do?  It's clearly testing the `ElementsUploadDataStream` class.
2. **Relationship with JavaScript:**  Are there any connections to JavaScript? This is part of Chromium's network stack, so interactions with web pages are likely, specifically form submissions.
3. **Logical Reasoning (Input/Output):**  If there are test cases with specific inputs and outputs, I need to highlight them.
4. **Common User/Programming Errors:** Are there test cases that simulate or prevent common mistakes?
5. **User Operations and Debugging:** How does a user's action lead to this code being executed, and how can this file be used for debugging?
6. **Summary of Functionality:** A concise summary of the file's purpose.

Let's break down the code to extract these pieces of information.

- **Includes:** The file includes headers for testing (`gtest`, `gmock`), network functionality (`net/...`), and base utilities (`base/...`). This confirms it's a unit test file for a network component.
- **`ElementsUploadDataStream`:** This is the class being tested. It manages a stream of data for uploads, composed of multiple "elements".
- **`UploadElementReader`:**  This is an interface for reading individual upload elements (bytes or files). The tests use concrete implementations like `UploadBytesElementReader` and `UploadFileElementReader`, as well as a `MockUploadElementReader` for controlled testing.
- **Test Cases:** The `TEST_F` macros define various test scenarios:
    - Empty upload data.
    - Consuming all bytes from a byte array.
    - Uploading a file.
    - Handling files smaller than the declared size.
    - Handling read errors (synchronous and asynchronous).
    - Combining file and byte array uploads.
    - Asynchronous initialization and initialization failures.
    - Reading with buffers of specific sizes.
    - Asynchronous reads.
    - Detecting file changes.
    - Multiple initializations.
    - Initializing during asynchronous operations (init and read).
- **`ReadFromUploadDataStream` function:** This helper function reads all data from an `UploadDataStream` and returns it as a string, useful for verification.
- **Mocking:** The `MockUploadElementReader` allows for simulating different behaviors of element readers (success, failure, asynchronous operations).

Now, let's address the specific points in the request.
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/elements_upload_data_stream.h"

#include <stdint.h>

#include <algorithm>
#include <limits>
#include <string_view>
#include <vector>

#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_data_stream.h"
#include "net/base/upload_file_element_reader.h"
#include "net/log/net_log_with_source.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using net::test::IsError;
using net::test::IsOk;

using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::_;

namespace net {

namespace {

const char kTestData[] = "0123456789";
const size_t kTestDataSize = std::size(kTestData) - 1;
const size_t kTestBufferSize = 1 << 14;  // 16KB.

// Reads data from the upload data stream, and returns the data as string.
std::string ReadFromUploadDataStream(UploadDataStream* stream) {
  std::string data_read;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  while (!stream->IsEOF()) {
    TestCompletionCallback callback;
    const int result =
        stream->Read(buf.get(), kTestBufferSize, callback.callback());
    const int bytes_read =
        result != ERR_IO_PENDING ? result : callback.WaitForResult();
    data_read.append(buf->data(), bytes_read);
  }
  return data_read;
}

// A mock class of UploadElementReader.
class MockUploadElementReader : public UploadElementReader {
 public:
  MockUploadElementReader(int content_length, bool is_in_memory)
      : content_length_(content_length),
        bytes_remaining_(content_length),
        is_in_memory_(is_in_memory) {}

  ~MockUploadElementReader() override = default;

  // UploadElementReader overrides.
  int Init(CompletionOnceCallback callback) override {
    // This is a back to get around Gmock's lack of support for move-only types.
    return Init(&callback);
  }
  MOCK_METHOD1(Init, int(CompletionOnceCallback* callback));
  uint64_t GetContentLength() const override { return content_length_; }
  uint64_t BytesRemaining() const override { return bytes_remaining_; }
  bool IsInMemory() const override { return is_in_memory_; }
  int Read(IOBuffer* buf,
           int buf_length,
           CompletionOnceCallback callback) override {
    return Read(buf, buf_length, &callback);
  }
  MOCK_METHOD3(Read,
               int(IOBuffer* buf,
                   int buf_length,
                   CompletionOnceCallback* callback));

  // Sets expectation to return the specified result from Init() asynchronously.
  void SetAsyncInitExpectation(int result) {
    init_result_ = result;
    EXPECT_CALL(*this, Init(_))
        .WillOnce(DoAll(Invoke(this, &MockUploadElementReader::OnInit),
                        Return(ERR_IO_PENDING)));
  }

  // Sets expectation to return the specified result from Read().
  void SetReadExpectation(int result) {
    read_result_ = result;
    EXPECT_CALL(*this, Read(_, _, _))
        .WillOnce(Invoke(this, &MockUploadElementReader::OnRead));
  }

 private:
  void OnInit(CompletionOnceCallback* callback) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(*callback), init_result_));
  }

  int OnRead(IOBuffer* buf, int buf_length, CompletionOnceCallback* callback) {
    if (read_result_ > 0)
      bytes_remaining_ = std::max(0, bytes_remaining_ - read_result_);
    if (IsInMemory()) {
      return read_result_;
    } else {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(std::move(*callback), read_result_));
      return ERR_IO_PENDING;
    }
  }

  int content_length_;
  int bytes_remaining_;
  bool is_in_memory_;

  // Result value returned from Init().
  int init_result_ = OK;

  // Result value returned from Read().
  int read_result_ = OK;
};

}  // namespace

class ElementsUploadDataStreamTest : public PlatformTest,
                                     public WithTaskEnvironment {
 public:
  void SetUp() override {
    PlatformTest::SetUp();
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }
  ~ElementsUploadDataStreamTest() override {
    element_readers_.clear();
    base::RunLoop().RunUntilIdle();
  }

  void FileChangedHelper(const base::FilePath& file_path,
                         const base::Time& time,
                         bool error_expected);

  base::ScopedTempDir temp_dir_;
  std::vector<std::unique_ptr<UploadElementReader>> element_readers_;
};

TEST_F(ElementsUploadDataStreamTest, EmptyUploadData) {
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));
  ASSERT_THAT(stream->Init(CompletionOnceCallback(), NetLogWithSource()),
              IsOk());
  EXPECT_TRUE(stream->IsInMemory());
  EXPECT_EQ(0U, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_TRUE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, ConsumeAllBytes) {
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));
  ASSERT_THAT(stream->Init(CompletionOnceCallback(), NetLogWithSource()),
              IsOk());
  EXPECT_TRUE(stream->IsInMemory());
  EXPECT_EQ(kTestDataSize, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  while (!stream->IsEOF()) {
    int bytes_read =
        stream->Read(buf.get(), kTestBufferSize, CompletionOnceCallback());
    ASSERT_LE(0, bytes_read);  // Not an error.
  }
  EXPECT_EQ(kTestDataSize, stream->position());
  ASSERT_TRUE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, File) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));

  TestCompletionCallback init_callback;
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));
  ASSERT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(init_callback.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsInMemory());
  EXPECT_EQ(kTestDataSize, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  while (!stream->IsEOF()) {
    TestCompletionCallback read_callback;
    ASSERT_EQ(
        ERR_IO_PENDING,
        stream->Read(buf.get(), kTestBufferSize, read_callback.callback()));
    ASSERT_LE(0, read_callback.WaitForResult());  // Not an error.
  }
  EXPECT_EQ(kTestDataSize, stream->position());
  ASSERT_TRUE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, FileSmallerThanLength) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));
  const uint64_t kFakeSize = kTestDataSize * 2;

  UploadFileElementReader::ScopedOverridingContentLengthForTests
      overriding_content_length(kFakeSize);

  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));

  TestCompletionCallback init_callback;
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));
  ASSERT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(init_callback.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsInMemory());
  EXPECT_EQ(kFakeSize, stream->size());
  EXPECT_EQ(0U, stream->position());

  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  EXPECT_FALSE(stream->IsEOF());

  TestCompletionCallback read_callback;
  ASSERT_EQ(ERR_IO_PENDING,
            stream->Read(buf.get(), kTestBufferSize, read_callback.callback()));
  int bytes_read = read_callback.WaitForResult();

  EXPECT_EQ(10, bytes_read);
  EXPECT_EQ(10U, stream->position());

  // UpdateDataStream will return error if there is something wrong.
  EXPECT_EQ(ERR_UPLOAD_FILE_CHANGED,
            stream->Read(buf.get(), kTestBufferSize, read_callback.callback()));
  EXPECT_EQ(10U, stream->position());

  EXPECT_FALSE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, ReadErrorSync) {
  // This element cannot be read.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader, Init(_)).WillOnce(Return(OK));
  reader->SetReadExpectation(ERR_FAILED);
  element_readers_.push_back(std::move(reader));

  // This element is ignored because of the error from the previous reader.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  ASSERT_THAT(stream->Init(CompletionOnceCallback(), NetLogWithSource()),
              IsOk());
  EXPECT_EQ(kTestDataSize * 2, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());

  // Prepare a buffer filled with non-zero data.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  std::fill_n(buf->data(), kTestBufferSize, -1);

  // Read() results in success even when the reader returns error.
  EXPECT_EQ(ERR_FAILED,
            stream->Read(buf.get(), kTestBufferSize, CompletionOnceCallback()));
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());

  // The buffer is filled with zero.
  EXPECT_EQ(0, std::count(buf->data(), buf->data() + kTestBufferSize, 0));
}

TEST_F(ElementsUploadDataStreamTest, ReadErrorAsync) {
  // This element cannot be read.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader->SetAsyncInitExpectation(OK);
  reader->SetReadExpectation(ERR_FAILED);
  element_readers_.push_back(std::move(reader));

  // This element is ignored because of the error from the previous reader.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  TestCompletionCallback init_callback;
  ASSERT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback.WaitForResult(), IsOk());
  EXPECT_EQ(kTestDataSize * 2, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());

  // Prepare a buffer filled with non-zero data.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  std::fill_n(buf->data(), kTestBufferSize, -1);

  // Read() results in success even when the reader returns error.
  TestCompletionCallback read_callback;
  ASSERT_EQ(ERR_IO_PENDING,
            stream->Read(buf.get(), kTestBufferSize, read_callback.callback()));
  EXPECT_THAT(read_callback.WaitForResult(), IsError(ERR_FAILED));
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());

  // The buffer is empty
  EXPECT_EQ(0, std::count(buf->data(), buf->data() + kTestBufferSize, 0));
}

TEST_F(ElementsUploadDataStreamTest, FileAndBytes) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  const uint64_t kFileRangeOffset = 1;
  const uint64_t kFileRangeLength = 4;
  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      kFileRangeOffset, kFileRangeLength, base::Time()));

  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));

  const uint64_t kStreamSize = kTestDataSize + kFileRangeLength;
  TestCompletionCallback init_callback;
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));
  ASSERT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(init_callback.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsInMemory());
  EXPECT_EQ(kStreamSize, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  while (!stream->IsEOF()) {
    TestCompletionCallback read_callback;
    const int result =
        stream->Read(buf.get(), kTestBufferSize, read_callback.callback());
    const int bytes_read =
        result != ERR_IO_PENDING ? result : read_callback.WaitForResult();
    ASSERT_LE(0, bytes_read);  // Not an error.
  }
  EXPECT_EQ(kStreamSize, stream->position());
  ASSERT_TRUE(stream->IsEOF());
}

// Init() with on-memory and not-on-memory readers.
TEST_F(ElementsUploadDataStreamTest, InitAsync) {
  // Create UploadDataStream with mock readers.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader, Init(_)).WillOnce(Return(OK));
  element_readers_.push_back(std::move(reader));

  auto reader2 = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader2, Init(_)).WillOnce(Return(OK));
  element_readers_.push_back(std::move(reader2));

  auto reader3 =
      std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader3->SetAsyncInitExpectation(OK);
  element_readers_.push_back(std::move(reader3));

  auto reader4 =
      std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader4->SetAsyncInitExpectation(OK);
  element_readers_.push_back(std::move(reader4));

  auto reader5 = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader5, Init(_)).WillOnce(Return(OK));
  element_readers_.push_back(std::move(reader5));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  TestCompletionCallback callback;
  ASSERT_THAT(stream->Init(callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Init() of a reader fails asynchronously.
TEST_F(ElementsUploadDataStreamTest, InitAsyncFailureAsync) {
  // Create UploadDataStream with a mock reader.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader->SetAsyncInitExpectation(ERR_FAILED);
  element_readers_.push_back(std::move(reader));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  TestCompletionCallback callback;
  ASSERT_THAT(stream->Init(callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_FAILED));
}

// Init() of a reader fails synchronously.
TEST_F(ElementsUploadDataStreamTest, InitAsyncFailureSync) {
  // Create UploadDataStream with mock readers.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader->SetAsyncInitExpectation(OK);
  element_readers_.push_back(std::move(reader));

  auto reader2 = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader2, Init(_)).WillOnce(Return(ERR_FAILED));
  element_readers_.push_back(std::move(reader2));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  TestCompletionCallback callback;
  ASSERT_THAT(stream->Init(callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_FAILED));
}

// Read with a buffer whose size is same as the data.
TEST_F(ElementsUploadDataStreamTest, ReadAsyncWithExactSizeBuffer) {
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  ASSERT_THAT(stream->Init(CompletionOnceCallback(), NetLogWithSource()),
              IsOk());
  EXPECT_TRUE(stream->IsInMemory());
  EXPECT_EQ(kTestDataSize, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestDataSize);
  int bytes_read =
      stream->Read(buf.get(), kTestDataSize, CompletionOnceCallback());
  ASSERT_TRUE(bytes_read);  // Not an error.
  EXPECT_EQ(kTestDataSize, stream->position());
  ASSERT_TRUE(stream->IsEOF());
}

// Async Read() with on-memory and not-on-memory readers.
TEST_F(ElementsUploadDataStreamTest, ReadAsync) {
  // Create UploadDataStream with mock readers.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader, Init(_)).WillOnce(Return(OK));
  reader->SetReadExpectation(kTestDataSize);
  element_readers_.push_back(std::move(reader));

  auto reader2 =
      std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader2->SetAsyncInitExpectation(OK);
  reader2->SetReadExpectation(kTestDataSize);
  element_readers_.push_back(std::move(reader2));

  auto reader3 = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader3, Init(_)).WillOnce(Return(OK));
  reader3->SetReadExpectation(kTestDataSize);
  element_readers_.push_back(std::move(reader3));

  auto reader4 =
      std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader4->SetAsyncInitExpectation(OK);
  reader4->SetReadExpectation(kTestDataSize);
  element_readers_.push_back(std::move(reader4));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  TestCompletionCallback init_callback;
  EXPECT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback.WaitForResult(), IsOk());

  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);

  // Consume the first element.
  TestCompletionCallback read_callback1;
  EXPECT_TRUE(
      stream->Read(buf.get(), kTestDataSize, read_callback1.callback()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(read_callback1.have_result());

  // Consume the second element.
  TestCompletionCallback read_callback2;
  ASSERT_EQ(ERR_IO_PENDING,
            stream->Read(buf.get(), kTestDataSize, read_callback2.callback()));
  EXPECT_TRUE(read_callback2.WaitForResult());

  // Consume the third and the fourth elements.
  TestCompletionCallback read_callback3;
  ASSERT_EQ(ERR_IO_PENDING, stream->Read(buf.get(), kTestDataSize * 2,
                                         read_callback3.callback()));
  EXPECT_EQ(static_cast<int>(kTestDataSize * 2),
            read_callback3.WaitForResult());
}

void ElementsUploadDataStreamTest::FileChangedHelper(
    const base::FilePath& file_path,
    const base::Time& time,
    bool error_expected) {
  // Don't use element_readers_ here, as this function is called twice, and
  // reusing element_readers_ is wrong.
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), file_path, 1, 2,
      time));

  TestCompletionCallback init_callback;
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers),
                                                 0));
  ASSERT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  int error_code = init_callback.WaitForResult();
  if (error_expected)
    ASSERT_THAT(error_code, IsError(ERR_UPLOAD_FILE_CHANGED));
  else
    ASSERT_THAT(error_code, IsOk());
}

TEST_F(ElementsUploadDataStreamTest, FileChanged) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  base::File::Info file_info;
  ASSERT_TRUE(base::GetFileInfo(temp_file_path, &file_info));

  // Test file not changed.
  FileChangedHelper(temp_file_path, file_info.last_modified, false);

  // Test file changed.
  FileChangedHelper(temp_file_path, file_info.last_modified - base::Seconds(1),
                    true);
}

TEST_F(ElementsUploadDataStreamTest, MultipleInit) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  // Prepare data.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  std::string expected_data(kTestData, kTestData + kTestDataSize);
  expected_data += expected_data;

  // Call Init().
  TestCompletionCallback init_callback1;
  ASSERT_THAT(stream->Init(init_callback1.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(init_callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read.
  EXPECT_EQ(expected_data, ReadFromUploadDataStream(stream.get()));
  EXPECT_TRUE(stream->IsEOF());

  // Call Init() again to reset.
  TestCompletionCallback init_callback2;
  ASSERT_THAT(stream->Init(init_callback2.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(init_callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read again.
  EXPECT_EQ(expected_data, ReadFromUploadDataStream(stream.get()));
  EXPECT_TRUE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, MultipleInitAsync) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));
  TestCompletionCallback test_callback;

  // Prepare data.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  std::string expected_data(kTestData, kTestData + kTestDataSize);
  expected_data += expected_data;

  // Call Init().
  ASSERT_THAT(stream->Init(test_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_callback.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read.
  EXPECT_EQ(expected_data, ReadFromUploadDataStream(stream.get()));
  EXPECT_TRUE(stream->IsEOF());

  // Call Init() again to reset.
  ASSERT_THAT(stream->Init(test_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_callback.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read again.
  EXPECT_EQ(expected_data, ReadFromUploadDataStream(stream.get()));

Prompt: 
```
这是目录为net/base/elements_upload_data_stream_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/elements_upload_data_stream.h"

#include <stdint.h>

#include <algorithm>
#include <limits>
#include <string_view>
#include <vector>

#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_data_stream.h"
#include "net/base/upload_file_element_reader.h"
#include "net/log/net_log_with_source.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using net::test::IsError;
using net::test::IsOk;

using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::_;

namespace net {

namespace {

const char kTestData[] = "0123456789";
const size_t kTestDataSize = std::size(kTestData) - 1;
const size_t kTestBufferSize = 1 << 14;  // 16KB.

// Reads data from the upload data stream, and returns the data as string.
std::string ReadFromUploadDataStream(UploadDataStream* stream) {
  std::string data_read;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  while (!stream->IsEOF()) {
    TestCompletionCallback callback;
    const int result =
        stream->Read(buf.get(), kTestBufferSize, callback.callback());
    const int bytes_read =
        result != ERR_IO_PENDING ? result : callback.WaitForResult();
    data_read.append(buf->data(), bytes_read);
  }
  return data_read;
}

// A mock class of UploadElementReader.
class MockUploadElementReader : public UploadElementReader {
 public:
  MockUploadElementReader(int content_length, bool is_in_memory)
      : content_length_(content_length),
        bytes_remaining_(content_length),
        is_in_memory_(is_in_memory) {}

  ~MockUploadElementReader() override = default;

  // UploadElementReader overrides.
  int Init(CompletionOnceCallback callback) override {
    // This is a back to get around Gmock's lack of support for move-only types.
    return Init(&callback);
  }
  MOCK_METHOD1(Init, int(CompletionOnceCallback* callback));
  uint64_t GetContentLength() const override { return content_length_; }
  uint64_t BytesRemaining() const override { return bytes_remaining_; }
  bool IsInMemory() const override { return is_in_memory_; }
  int Read(IOBuffer* buf,
           int buf_length,
           CompletionOnceCallback callback) override {
    return Read(buf, buf_length, &callback);
  }
  MOCK_METHOD3(Read,
               int(IOBuffer* buf,
                   int buf_length,
                   CompletionOnceCallback* callback));

  // Sets expectation to return the specified result from Init() asynchronously.
  void SetAsyncInitExpectation(int result) {
    init_result_ = result;
    EXPECT_CALL(*this, Init(_))
        .WillOnce(DoAll(Invoke(this, &MockUploadElementReader::OnInit),
                        Return(ERR_IO_PENDING)));
  }

  // Sets expectation to return the specified result from Read().
  void SetReadExpectation(int result) {
    read_result_ = result;
    EXPECT_CALL(*this, Read(_, _, _))
        .WillOnce(Invoke(this, &MockUploadElementReader::OnRead));
  }

 private:
  void OnInit(CompletionOnceCallback* callback) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(*callback), init_result_));
  }

  int OnRead(IOBuffer* buf, int buf_length, CompletionOnceCallback* callback) {
    if (read_result_ > 0)
      bytes_remaining_ = std::max(0, bytes_remaining_ - read_result_);
    if (IsInMemory()) {
      return read_result_;
    } else {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(std::move(*callback), read_result_));
      return ERR_IO_PENDING;
    }
  }

  int content_length_;
  int bytes_remaining_;
  bool is_in_memory_;

  // Result value returned from Init().
  int init_result_ = OK;

  // Result value returned from Read().
  int read_result_ = OK;
};

}  // namespace

class ElementsUploadDataStreamTest : public PlatformTest,
                                     public WithTaskEnvironment {
 public:
  void SetUp() override {
    PlatformTest::SetUp();
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }
  ~ElementsUploadDataStreamTest() override {
    element_readers_.clear();
    base::RunLoop().RunUntilIdle();
  }

  void FileChangedHelper(const base::FilePath& file_path,
                         const base::Time& time,
                         bool error_expected);

  base::ScopedTempDir temp_dir_;
  std::vector<std::unique_ptr<UploadElementReader>> element_readers_;
};

TEST_F(ElementsUploadDataStreamTest, EmptyUploadData) {
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));
  ASSERT_THAT(stream->Init(CompletionOnceCallback(), NetLogWithSource()),
              IsOk());
  EXPECT_TRUE(stream->IsInMemory());
  EXPECT_EQ(0U, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_TRUE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, ConsumeAllBytes) {
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));
  ASSERT_THAT(stream->Init(CompletionOnceCallback(), NetLogWithSource()),
              IsOk());
  EXPECT_TRUE(stream->IsInMemory());
  EXPECT_EQ(kTestDataSize, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  while (!stream->IsEOF()) {
    int bytes_read =
        stream->Read(buf.get(), kTestBufferSize, CompletionOnceCallback());
    ASSERT_LE(0, bytes_read);  // Not an error.
  }
  EXPECT_EQ(kTestDataSize, stream->position());
  ASSERT_TRUE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, File) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));

  TestCompletionCallback init_callback;
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));
  ASSERT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(init_callback.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsInMemory());
  EXPECT_EQ(kTestDataSize, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  while (!stream->IsEOF()) {
    TestCompletionCallback read_callback;
    ASSERT_EQ(
        ERR_IO_PENDING,
        stream->Read(buf.get(), kTestBufferSize, read_callback.callback()));
    ASSERT_LE(0, read_callback.WaitForResult());  // Not an error.
  }
  EXPECT_EQ(kTestDataSize, stream->position());
  ASSERT_TRUE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, FileSmallerThanLength) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));
  const uint64_t kFakeSize = kTestDataSize * 2;

  UploadFileElementReader::ScopedOverridingContentLengthForTests
      overriding_content_length(kFakeSize);

  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));

  TestCompletionCallback init_callback;
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));
  ASSERT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(init_callback.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsInMemory());
  EXPECT_EQ(kFakeSize, stream->size());
  EXPECT_EQ(0U, stream->position());

  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  EXPECT_FALSE(stream->IsEOF());

  TestCompletionCallback read_callback;
  ASSERT_EQ(ERR_IO_PENDING,
            stream->Read(buf.get(), kTestBufferSize, read_callback.callback()));
  int bytes_read = read_callback.WaitForResult();

  EXPECT_EQ(10, bytes_read);
  EXPECT_EQ(10U, stream->position());

  // UpdateDataStream will return error if there is something wrong.
  EXPECT_EQ(ERR_UPLOAD_FILE_CHANGED,
            stream->Read(buf.get(), kTestBufferSize, read_callback.callback()));
  EXPECT_EQ(10U, stream->position());

  EXPECT_FALSE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, ReadErrorSync) {
  // This element cannot be read.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader, Init(_)).WillOnce(Return(OK));
  reader->SetReadExpectation(ERR_FAILED);
  element_readers_.push_back(std::move(reader));

  // This element is ignored because of the error from the previous reader.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  ASSERT_THAT(stream->Init(CompletionOnceCallback(), NetLogWithSource()),
              IsOk());
  EXPECT_EQ(kTestDataSize * 2, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());

  // Prepare a buffer filled with non-zero data.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  std::fill_n(buf->data(), kTestBufferSize, -1);

  // Read() results in success even when the reader returns error.
  EXPECT_EQ(ERR_FAILED,
            stream->Read(buf.get(), kTestBufferSize, CompletionOnceCallback()));
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());

  // The buffer is filled with zero.
  EXPECT_EQ(0, std::count(buf->data(), buf->data() + kTestBufferSize, 0));
}

TEST_F(ElementsUploadDataStreamTest, ReadErrorAsync) {
  // This element cannot be read.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader->SetAsyncInitExpectation(OK);
  reader->SetReadExpectation(ERR_FAILED);
  element_readers_.push_back(std::move(reader));

  // This element is ignored because of the error from the previous reader.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  TestCompletionCallback init_callback;
  ASSERT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback.WaitForResult(), IsOk());
  EXPECT_EQ(kTestDataSize * 2, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());

  // Prepare a buffer filled with non-zero data.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  std::fill_n(buf->data(), kTestBufferSize, -1);

  // Read() results in success even when the reader returns error.
  TestCompletionCallback read_callback;
  ASSERT_EQ(ERR_IO_PENDING,
            stream->Read(buf.get(), kTestBufferSize, read_callback.callback()));
  EXPECT_THAT(read_callback.WaitForResult(), IsError(ERR_FAILED));
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());

  // The buffer is empty
  EXPECT_EQ(0, std::count(buf->data(), buf->data() + kTestBufferSize, 0));
}

TEST_F(ElementsUploadDataStreamTest, FileAndBytes) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  const uint64_t kFileRangeOffset = 1;
  const uint64_t kFileRangeLength = 4;
  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      kFileRangeOffset, kFileRangeLength, base::Time()));

  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));

  const uint64_t kStreamSize = kTestDataSize + kFileRangeLength;
  TestCompletionCallback init_callback;
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));
  ASSERT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(init_callback.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsInMemory());
  EXPECT_EQ(kStreamSize, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  while (!stream->IsEOF()) {
    TestCompletionCallback read_callback;
    const int result =
        stream->Read(buf.get(), kTestBufferSize, read_callback.callback());
    const int bytes_read =
        result != ERR_IO_PENDING ? result : read_callback.WaitForResult();
    ASSERT_LE(0, bytes_read);  // Not an error.
  }
  EXPECT_EQ(kStreamSize, stream->position());
  ASSERT_TRUE(stream->IsEOF());
}

// Init() with on-memory and not-on-memory readers.
TEST_F(ElementsUploadDataStreamTest, InitAsync) {
  // Create UploadDataStream with mock readers.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader, Init(_)).WillOnce(Return(OK));
  element_readers_.push_back(std::move(reader));

  auto reader2 = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader2, Init(_)).WillOnce(Return(OK));
  element_readers_.push_back(std::move(reader2));

  auto reader3 =
      std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader3->SetAsyncInitExpectation(OK);
  element_readers_.push_back(std::move(reader3));

  auto reader4 =
      std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader4->SetAsyncInitExpectation(OK);
  element_readers_.push_back(std::move(reader4));

  auto reader5 = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader5, Init(_)).WillOnce(Return(OK));
  element_readers_.push_back(std::move(reader5));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  TestCompletionCallback callback;
  ASSERT_THAT(stream->Init(callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Init() of a reader fails asynchronously.
TEST_F(ElementsUploadDataStreamTest, InitAsyncFailureAsync) {
  // Create UploadDataStream with a mock reader.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader->SetAsyncInitExpectation(ERR_FAILED);
  element_readers_.push_back(std::move(reader));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  TestCompletionCallback callback;
  ASSERT_THAT(stream->Init(callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_FAILED));
}

// Init() of a reader fails synchronously.
TEST_F(ElementsUploadDataStreamTest, InitAsyncFailureSync) {
  // Create UploadDataStream with mock readers.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader->SetAsyncInitExpectation(OK);
  element_readers_.push_back(std::move(reader));

  auto reader2 = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader2, Init(_)).WillOnce(Return(ERR_FAILED));
  element_readers_.push_back(std::move(reader2));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  TestCompletionCallback callback;
  ASSERT_THAT(stream->Init(callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_FAILED));
}

// Read with a buffer whose size is same as the data.
TEST_F(ElementsUploadDataStreamTest, ReadAsyncWithExactSizeBuffer) {
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  ASSERT_THAT(stream->Init(CompletionOnceCallback(), NetLogWithSource()),
              IsOk());
  EXPECT_TRUE(stream->IsInMemory());
  EXPECT_EQ(kTestDataSize, stream->size());
  EXPECT_EQ(0U, stream->position());
  EXPECT_FALSE(stream->IsEOF());
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestDataSize);
  int bytes_read =
      stream->Read(buf.get(), kTestDataSize, CompletionOnceCallback());
  ASSERT_TRUE(bytes_read);  // Not an error.
  EXPECT_EQ(kTestDataSize, stream->position());
  ASSERT_TRUE(stream->IsEOF());
}

// Async Read() with on-memory and not-on-memory readers.
TEST_F(ElementsUploadDataStreamTest, ReadAsync) {
  // Create UploadDataStream with mock readers.
  auto reader = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader, Init(_)).WillOnce(Return(OK));
  reader->SetReadExpectation(kTestDataSize);
  element_readers_.push_back(std::move(reader));

  auto reader2 =
      std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader2->SetAsyncInitExpectation(OK);
  reader2->SetReadExpectation(kTestDataSize);
  element_readers_.push_back(std::move(reader2));

  auto reader3 = std::make_unique<MockUploadElementReader>(kTestDataSize, true);
  EXPECT_CALL(*reader3, Init(_)).WillOnce(Return(OK));
  reader3->SetReadExpectation(kTestDataSize);
  element_readers_.push_back(std::move(reader3));

  auto reader4 =
      std::make_unique<MockUploadElementReader>(kTestDataSize, false);
  reader4->SetAsyncInitExpectation(OK);
  reader4->SetReadExpectation(kTestDataSize);
  element_readers_.push_back(std::move(reader4));

  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  // Run Init().
  TestCompletionCallback init_callback;
  EXPECT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback.WaitForResult(), IsOk());

  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);

  // Consume the first element.
  TestCompletionCallback read_callback1;
  EXPECT_TRUE(
      stream->Read(buf.get(), kTestDataSize, read_callback1.callback()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(read_callback1.have_result());

  // Consume the second element.
  TestCompletionCallback read_callback2;
  ASSERT_EQ(ERR_IO_PENDING,
            stream->Read(buf.get(), kTestDataSize, read_callback2.callback()));
  EXPECT_TRUE(read_callback2.WaitForResult());

  // Consume the third and the fourth elements.
  TestCompletionCallback read_callback3;
  ASSERT_EQ(ERR_IO_PENDING, stream->Read(buf.get(), kTestDataSize * 2,
                                         read_callback3.callback()));
  EXPECT_EQ(static_cast<int>(kTestDataSize * 2),
            read_callback3.WaitForResult());
}

void ElementsUploadDataStreamTest::FileChangedHelper(
    const base::FilePath& file_path,
    const base::Time& time,
    bool error_expected) {
  // Don't use element_readers_ here, as this function is called twice, and
  // reusing element_readers_ is wrong.
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), file_path, 1, 2,
      time));

  TestCompletionCallback init_callback;
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers),
                                                 0));
  ASSERT_THAT(stream->Init(init_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  int error_code = init_callback.WaitForResult();
  if (error_expected)
    ASSERT_THAT(error_code, IsError(ERR_UPLOAD_FILE_CHANGED));
  else
    ASSERT_THAT(error_code, IsOk());
}

TEST_F(ElementsUploadDataStreamTest, FileChanged) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  base::File::Info file_info;
  ASSERT_TRUE(base::GetFileInfo(temp_file_path, &file_info));

  // Test file not changed.
  FileChangedHelper(temp_file_path, file_info.last_modified, false);

  // Test file changed.
  FileChangedHelper(temp_file_path, file_info.last_modified - base::Seconds(1),
                    true);
}

TEST_F(ElementsUploadDataStreamTest, MultipleInit) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  // Prepare data.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  std::string expected_data(kTestData, kTestData + kTestDataSize);
  expected_data += expected_data;

  // Call Init().
  TestCompletionCallback init_callback1;
  ASSERT_THAT(stream->Init(init_callback1.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(init_callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read.
  EXPECT_EQ(expected_data, ReadFromUploadDataStream(stream.get()));
  EXPECT_TRUE(stream->IsEOF());

  // Call Init() again to reset.
  TestCompletionCallback init_callback2;
  ASSERT_THAT(stream->Init(init_callback2.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(init_callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read again.
  EXPECT_EQ(expected_data, ReadFromUploadDataStream(stream.get()));
  EXPECT_TRUE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, MultipleInitAsync) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));
  TestCompletionCallback test_callback;

  // Prepare data.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  std::string expected_data(kTestData, kTestData + kTestDataSize);
  expected_data += expected_data;

  // Call Init().
  ASSERT_THAT(stream->Init(test_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_callback.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read.
  EXPECT_EQ(expected_data, ReadFromUploadDataStream(stream.get()));
  EXPECT_TRUE(stream->IsEOF());

  // Call Init() again to reset.
  ASSERT_THAT(stream->Init(test_callback.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_callback.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read again.
  EXPECT_EQ(expected_data, ReadFromUploadDataStream(stream.get()));
  EXPECT_TRUE(stream->IsEOF());
}

TEST_F(ElementsUploadDataStreamTest, InitToReset) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  // Prepare data.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  std::vector<char> expected_data(kTestData, kTestData + kTestDataSize);
  expected_data.insert(expected_data.end(), kTestData,
                       kTestData + kTestDataSize);

  // Call Init().
  TestCompletionCallback init_callback1;
  ASSERT_THAT(stream->Init(init_callback1.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read some.
  TestCompletionCallback read_callback1;
  std::vector<char> buf(kTestDataSize + kTestDataSize / 2);
  auto wrapped_buffer = base::MakeRefCounted<WrappedIOBuffer>(buf);
  EXPECT_EQ(
      ERR_IO_PENDING,
      stream->Read(wrapped_buffer.get(), buf.size(),
                   read_callback1.callback()));
  EXPECT_EQ(static_cast<int>(buf.size()), read_callback1.WaitForResult());
  EXPECT_EQ(buf.size(), stream->position());

  // Call Init to reset the state.
  TestCompletionCallback init_callback2;
  ASSERT_THAT(stream->Init(init_callback2.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read.
  TestCompletionCallback read_callback2;
  std::vector<char> buf2(kTestDataSize * 2);
  auto wrapped_buffer2 = base::MakeRefCounted<WrappedIOBuffer>(buf2);
  EXPECT_EQ(ERR_IO_PENDING,
            stream->Read(
                wrapped_buffer2.get(), buf2.size(), read_callback2.callback()));
  EXPECT_EQ(static_cast<int>(buf2.size()), read_callback2.WaitForResult());
  EXPECT_EQ(expected_data, buf2);
}

TEST_F(ElementsUploadDataStreamTest, InitDuringAsyncInit) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  // Prepare data.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  std::vector<char> expected_data(kTestData, kTestData + kTestDataSize);
  expected_data.insert(expected_data.end(), kTestData,
                       kTestData + kTestDataSize);

  // Start Init.
  TestCompletionCallback init_callback1;
  EXPECT_THAT(stream->Init(init_callback1.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));

  // Call Init again to cancel the previous init.
  TestCompletionCallback init_callback2;
  EXPECT_THAT(stream->Init(init_callback2.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read.
  TestCompletionCallback read_callback2;
  std::vector<char> buf2(kTestDataSize * 2);
  auto wrapped_buffer2 = base::MakeRefCounted<WrappedIOBuffer>(buf2);
  EXPECT_EQ(ERR_IO_PENDING,
            stream->Read(
                wrapped_buffer2.get(), buf2.size(), read_callback2.callback()));
  EXPECT_EQ(static_cast<int>(buf2.size()), read_callback2.WaitForResult());
  EXPECT_EQ(expected_data, buf2);
  EXPECT_TRUE(stream->IsEOF());

  // Make sure callbacks are not called for cancelled operations.
  EXPECT_FALSE(init_callback1.have_result());
}

TEST_F(ElementsUploadDataStreamTest, InitDuringAsyncRead) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &temp_file_path));
  ASSERT_TRUE(base::WriteFile(temp_file_path, kTestData));

  // Prepare data.
  element_readers_.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring(kTestData)));
  element_readers_.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));
  std::unique_ptr<UploadDataStream> stream(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers_),
                                                 0));

  std::vector<char> expected_data(kTestData, kTestData + kTestDataSize);
  expected_data.insert(expected_data.end(), kTestData,
                       kTestData + kTestDataSize);

  // Call Init().
  TestCompletionCallback init_callback1;
  ASSERT_THAT(stream->Init(init_callback1.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Start reading.
  TestCompletionCallback read_callback1;
  std::vector<char> buf(kTestDataSize * 2);
  auto wrapped_buffer = base::MakeRefCounted<WrappedIOBuffer>(buf);
  EXPECT_EQ(
      ERR_IO_PENDING,
      stream->Read(wrapped_buffer.get(), buf.size(),
                   read_callback1.callback()));

  // Call Init to cancel the previous read.
  TestCompletionCallback init_callback2;
  EXPECT_THAT(stream->Init(init_callback2.callback(), NetLogWithSource()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(init_callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(stream->IsEOF());
  EXPECT_EQ(kTestDataSize * 2, stream->size());

  // Read.
  TestCompletionCallback read_callback2;
  std::vector<char> buf2(kTestDataSize * 2);
  auto wrapped_buffer2 = base::MakeRefCounted<WrappedIOBuffer>(buf2);
  EXPECT_EQ(ERR_IO_PENDING,
            stream->Read(
                wrapped_buffer2.get(), bu
"""


```