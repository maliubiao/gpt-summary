Response:
Let's break down the thought process for analyzing the `file_test.cc` file.

1. **Understand the Purpose:** The file name `file_test.cc` immediately suggests this is a test file. The location within the `blink/renderer/core/fileapi/` directory indicates it's specifically testing the `File` class within Blink's file API implementation.

2. **Identify Key Includes:**  The `#include` directives reveal the core components involved:
    * `file.h`:  This confirms the primary focus is the `File` class.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates the use of Google Test for writing the unit tests.
    * `third_party/blink/public/mojom/file/...`:  Shows interaction with Mojo interfaces related to files, suggesting asynchronous operations and communication between processes.
    * `third_party/blink/renderer/core/...`:  Highlights dependencies on other Blink core components like `Document`, `LocalFrame`, and the execution context.
    * `third_party/blink/renderer/platform/...`: Includes platform-level abstractions like `BlobDataHandle`, `FileMetadata`, and testing utilities.

3. **Examine Test Structure (General):** Unit tests typically follow a pattern: setup, action, assertion. Look for `TEST()` macros to identify individual test cases. Each test should focus on a specific aspect of the `File` class.

4. **Analyze Individual Tests:** Go through each `TEST()` case and determine what it's verifying.
    * **Naming Conventions:** The test names (`NativeFileWithoutTimestamp`, `BlobBackingFileWithUnixEpochTimestamp`, etc.) are quite descriptive and hint at the scenarios being tested. Pay attention to keywords like "NativeFile," "BlobBackingFile," "FileSystemFile," and terms related to timestamps.
    * **Assertions:**  Look for `EXPECT_*` macros. These are the core of the tests, verifying expected outcomes. Note what properties of the `File` object are being checked (e.g., `HasBackingFile()`, `GetPath()`, `FileSystemURL()`, `lastModified()`, `LastModifiedTime()`, `size()`).
    * **Setup:**  Observe how `File` objects are created in each test. Are they constructed with paths, `BlobDataHandle`s, `FileMetadata`, or filesystem URLs? This reveals different ways the `File` object can represent file information.
    * **Mocking:** Notice the `MockBlob` and `MockFileSystemManager` classes. These are used to isolate the `File` class from real file system interactions and provide controlled behavior for testing specific scenarios. Understand what these mocks are simulating. For example, `MockBlob` controls the reported modification time, and `MockFileSystemManager` handles blob registration.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** Consider how the `File` class interacts with web APIs.
    * **`<input type="file">`:** This is the most direct connection. When a user selects files, JavaScript gets `File` objects. The tests involving "NativeFile" likely relate to files selected from the user's local filesystem.
    * **`Blob` API:** The tests with "BlobBackingFile" clearly show the connection. JavaScript can create `Blob` objects, and `File` objects can be backed by them.
    * **File System Access API (less common):**  The "FileSystemFile" tests point to the File System Access API (or legacy APIs). These allow web pages to interact with a sandboxed virtual file system.

6. **Identify Logical Inferences and Assumptions:** Look for tests that implicitly demonstrate relationships or rely on specific conditions.
    * **Timestamp Handling:**  The tests with different timestamp values (Unix Epoch, Windows Epoch, Max Time) demonstrate how Blink handles these values and converts them to JavaScript's `lastModified` property.
    * **Source Comparison (`HasSameSource`):** This test verifies the logic for determining if two `File` objects refer to the same underlying data source, considering different file types (native, blob, filesystem).

7. **Recognize Potential User/Programming Errors:** Think about common mistakes developers might make when working with files in JavaScript.
    * **Assuming Local File Paths:**  The distinction between "native" files and those backed by blobs or filesystem URLs is crucial. Developers can't always assume a `File` object has a direct local file path.
    * **Incorrectly Handling Timestamps:** The tests with different timestamps highlight the importance of understanding how these values are represented and converted.
    * **Misunderstanding File Identity:** The `HasSameSource` test demonstrates that object identity isn't the same as data source identity. Two different `File` objects might refer to the same underlying file.

8. **Structure the Explanation:** Organize the findings logically, starting with the primary purpose, then detailing specific functionalities, connections to web technologies, and potential pitfalls. Use clear and concise language, and provide illustrative examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Might have initially focused too much on the low-level C++ details.
* **Correction:** Realized the prompt asks for the *functionality* from a higher-level perspective, including its relevance to web development. Shifted focus to the observable behavior and how it relates to JavaScript APIs.
* **Clarification:** Ensured the examples provided directly linked the C++ testing scenarios to corresponding JavaScript concepts (e.g., `<input type="file">`, `Blob`).
* **Completeness:** Checked if all aspects of the prompt were addressed, including logical inferences and common errors.

By following these steps, the comprehensive analysis of `file_test.cc` can be generated, effectively explaining its purpose and its relation to the broader web ecosystem.
这个文件 `blink/renderer/core/fileapi/file_test.cc` 是 Chromium Blink 引擎中用于测试 `blink::File` 类的单元测试文件。它的主要功能是验证 `File` 类的各种行为和属性是否符合预期。

以下是该文件列举的功能以及与 JavaScript、HTML、CSS 相关的说明：

**文件测试的主要功能：**

1. **`File` 对象的创建和属性设置：** 测试不同方式创建 `File` 对象，包括：
   - 从本地文件路径创建 (`NativeFile`)
   - 从 `BlobDataHandle` 创建 (`BlobBackingFile`)
   - 从文件系统 API 返回的信息创建 (`FileSystemFile`)
   - 设置和获取 `File` 对象的各种属性，如文件名、大小、最后修改时间、文件路径、文件系统 URL 等。

2. **最后修改时间 (lastModified/LastModifiedTime) 的处理：**  测试 `File` 对象如何处理和存储不同的时间戳，包括：
   - 没有时间戳的情况 (设置为当前时间)
   - Unix Epoch 时间戳
   - Windows Epoch 时间戳
   - 最大时间戳

3. **文件来源判断 (`HasSameSource`)：** 测试判断两个 `File` 对象是否指向相同的文件来源的逻辑，需要考虑不同类型的 `File` 对象（本地文件、Blob、文件系统 API 文件）。

4. **与 Mojo 接口的交互：** 虽然这个测试文件本身不直接测试 Mojo 接口，但它间接地使用了 Mojo 来创建和管理 `Blob` 对象 (`MockBlob`)，这体现了 `File` 对象与 Blink 进程间通信机制的联系。

5. **与文件系统 API 的模拟交互：** 通过 `MockFileSystemManager` 模拟文件系统 API 的行为，允许测试在不依赖实际文件系统操作的情况下验证 `File` 对象的行为，例如 `CreateForFileSystemFile` 函数的调用和 `RegisterBlob` 的回调。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`blink::File` 类是 Web API 中 `File` 接口在 Blink 渲染引擎中的实现。因此，这个测试文件直接关系到 JavaScript 中 `File` 对象的行为。

**1. JavaScript `File` 对象和 HTML `<input type="file">` 元素：**

- **功能关系：** 当用户在 HTML 页面中使用 `<input type="file">` 元素选择文件时，JavaScript 代码会获得一个或多个 `File` 对象。这些 `File` 对象在 Blink 引擎中就是由 `blink::File` 类表示的。
- **举例说明：**
  ```html
  <input type="file" id="fileInput">
  <script>
    const fileInput = document.getElementById('fileInput');
    fileInput.addEventListener('change', (event) => {
      const file = event.target.files[0];
      console.log(file.name); // 对应 blink::File 的 name 属性
      console.log(file.size); // 对应 blink::File 的 size 属性
      console.log(file.lastModified); // 对应 blink::File 的 lastModified 属性
    });
  </script>
  ```
  `file_test.cc` 中 `NativeFile` 相关的测试（例如 `NativeFileWithoutTimestamp`）就模拟了这种场景下创建的 `File` 对象。

**假设输入与输出 (针对 `NativeFileWithoutTimestamp` 测试)：**

- **假设输入：**  创建一个 `File` 对象，指定一个本地文件路径 `/native/path`，但不提供修改时间信息。
- **逻辑推理：**  由于没有提供修改时间，`File` 对象应该使用当前时间作为其 `lastModified` 属性。
- **预期输出：**
  - `file->HasBackingFile()` 为 `true` (因为有本地文件路径)
  - `file->GetPath()` 等于 `/native/path`
  - `file->FileSystemURL().IsEmpty()` 为 `true` (因为不是文件系统 API 创建的文件)
  - `file->lastModified()` 的值接近当前时间的毫秒级时间戳。

**2. JavaScript `Blob` 对象和 `File` 对象：**

- **功能关系：** JavaScript 可以创建 `Blob` 对象，并且可以基于 `Blob` 对象创建 `File` 对象。
- **举例说明：**
  ```javascript
  const blob = new Blob(['hello world'], { type: 'text/plain' });
  const file = new File([blob], 'my-file.txt', { lastModified: Date.now() });
  console.log(file.name);
  console.log(file.size);
  console.log(file.lastModified);
  ```
  `file_test.cc` 中 `BlobBackingFile` 相关的测试（例如 `BlobBackingFileWithUnixEpochTimestamp`）模拟了这种场景，其中 `File` 对象是由 `BlobDataHandle` 支持的。

**假设输入与输出 (针对 `BlobBackingFileWithUnixEpochTimestamp` 测试)：**

- **假设输入：** 创建一个 `File` 对象，指定文件名 "name"，最后修改时间为 Unix Epoch (1970-01-01 00:00:00 UTC)，并关联一个 `BlobDataHandle`。
- **逻辑推理：**  `File` 对象应该正确存储并返回指定的最后修改时间。
- **预期输出：**
  - `file->HasBackingFile()` 为 `false` (因为不是直接指向本地文件)
  - `file->GetPath().empty()` 为 `true`
  - `file->FileSystemURL().IsEmpty()` 为 `true`
  - `file->lastModified()` 等于 0 (Unix Epoch 的毫秒表示)
  - `file->LastModifiedTime()` 等于 `base::Time::UnixEpoch()`。

**3. 文件系统 API：**

- **功能关系：**  文件系统 API (例如，通过 `webkitRequestFileSystem`) 允许 Web 应用访问一个沙箱化的文件系统。通过这个 API 创建的文件也会被表示为 `File` 对象。
- **举例说明：**
  ```javascript
  window.requestFileSystem  = window.requestFileSystem || window.webkitRequestFileSystem;
  navigator.webkitPersistentStorage.requestQuota(5*1024*1024, function(grantedBytes) {
    window.requestFileSystem(window.PERSISTENT, grantedBytes, function(fs) {
      fs.root.getFile('log.txt', {create: true}, function(fileEntry) {
        fileEntry.file(function(file) {
          console.log(file.name);
          console.log(file.size);
        });
      });
    }, function(e) { console.log('Error', e); });
  }, function(e) { console.log('Error', e); });
  ```
  `file_test.cc` 中 `FileSystemFile` 相关的测试（例如 `fileSystemFileWithNativeSnapshot`）模拟了这种场景。

**假设输入与输出 (针对 `fileSystemFileWithNativeSnapshot` 测试)：**

- **假设输入：**  使用 `File::CreateForFileSystemFile` 创建一个 `File` 对象，提供文件名 "name" 和包含本地快照路径 `/native/snapshot` 的 `FileMetadata`。
- **逻辑推理：**  如果提供了本地快照路径，`File` 对象应该认为它有一个底层的本地文件。
- **预期输出：**
  - `file->HasBackingFile()` 为 `true`
  - `file->GetPath()` 等于 `/native/snapshot`
  - `file->FileSystemURL().IsEmpty()` 为 `true` (虽然是文件系统 API 的概念，但这里模拟的是一个有本地快照的情况)。

**用户或编程常见的使用错误举例说明：**

1. **假设 `File` 对象总是对应本地文件：**  开发者可能会错误地认为所有的 `File` 对象都有一个可以直接访问的本地文件路径。实际上，由 `Blob` 创建的 `File` 对象或者通过文件系统 API 创建的 `File` 对象可能没有直接的本地文件路径。
   ```javascript
   const fileInput = document.getElementById('fileInput');
   fileInput.addEventListener('change', (event) => {
     const file = event.target.files[0];
     // 错误的做法：假设 file.path 总是存在且有效
     console.log(file.path); // 大部分浏览器中，File 对象没有 path 属性
   });

   const blob = new Blob(['data'], { type: 'text/plain' });
   const blobFile = new File([blob], 'my-blob.txt');
   // 错误的做法：尝试访问 blobFile 的本地路径
   // blobFile 并没有直接对应的本地文件路径
   ```

2. **错误地处理 `lastModified` 属性：** 开发者可能没有考虑到 `lastModified` 返回的是自 Unix Epoch 以来的毫秒数，需要进行适当的转换才能得到 `Date` 对象。

### 提示词
```
这是目录为blink/renderer/core/fileapi/file_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fileapi/file.h"

#include "base/run_loop.h"
#include "base/task/thread_pool.h"
#include "base/test/bind.h"
#include "base/time/time.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/file/file_utilities.mojom-blink.h"
#include "third_party/blink/public/mojom/filesystem/file_system.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/blob/testing/fake_blob.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

namespace {

class MockBlob : public FakeBlob {
 public:
  static void Create(File* file, base::Time modified_time) {
    mojo::PendingRemote<mojom::blink::Blob> remote;
    PostCrossThreadTask(
        *base::ThreadPool::CreateSingleThreadTaskRunner({}), FROM_HERE,
        CrossThreadBindOnce(
            [](const String& uuid,
               mojo::PendingReceiver<mojom::blink::Blob> receiver,
               base::Time modified_time) {
              mojo::MakeSelfOwnedReceiver(
                  std::make_unique<MockBlob>(uuid, modified_time),
                  std::move(receiver));
            },
            file->Uuid(), remote.InitWithNewPipeAndPassReceiver(),
            modified_time));
    file->GetBlobDataHandle()->SetBlobRemoteForTesting(std::move(remote));
  }

  MockBlob(const String& uuid, base::Time modified_time)
      : FakeBlob(uuid), modified_time_(modified_time) {}

  void Clone(mojo::PendingReceiver<mojom::blink::Blob> receiver) override {
    mojo::MakeSelfOwnedReceiver(
        std::make_unique<MockBlob>(uuid_, modified_time_), std::move(receiver));
  }

  void CaptureSnapshot(CaptureSnapshotCallback callback) override {
    std::move(callback).Run(
        /*size=*/0, NullableTimeToOptionalTime(modified_time_));
  }

 private:
  base::Time modified_time_;
};

using MockRegisterBlobCallback = base::OnceCallback<
    void(const String&, const KURL&, uint64_t, std::optional<base::Time>)>;
class MockFileSystemManager : public mojom::blink::FileSystemManager {
 public:
  explicit MockFileSystemManager(
      const blink::BrowserInterfaceBrokerProxy& broker)
      : broker_(broker) {
    broker.SetBinderForTesting(
        mojom::blink::FileSystemManager::Name_,
        WTF::BindRepeating(&MockFileSystemManager::BindReceiver,
                           WTF::Unretained(this)));
  }

  ~MockFileSystemManager() override {
    broker_.SetBinderForTesting(mojom::blink::FileSystemManager::Name_, {});
  }

  // mojom::blink::FileSystem
  void Open(const scoped_refptr<const SecurityOrigin>& origin,
            mojom::blink::FileSystemType file_system_type,
            OpenCallback callback) override {}
  void ResolveURL(const KURL& filesystem_url,
                  ResolveURLCallback callback) override {}
  void Move(const KURL& src_path,
            const KURL& dest_path,
            MoveCallback callback) override {}
  void Copy(const KURL& src_path,
            const KURL& dest_path,
            CopyCallback callback) override {}
  void Remove(const KURL& path,
              bool recursive,
              RemoveCallback callback) override {}
  void ReadMetadata(const KURL& path, ReadMetadataCallback callback) override {}
  void Create(const KURL& path,
              bool exclusive,
              bool is_directory,
              bool recursive,
              CreateCallback callback) override {}
  void Exists(const KURL& path,
              bool is_directory,
              ExistsCallback callback) override {}
  void ReadDirectory(
      const KURL& path,
      mojo::PendingRemote<mojom::blink::FileSystemOperationListener>
          pending_listener) override {}
  void ReadDirectorySync(const KURL& path,
                         ReadDirectorySyncCallback callback) override {}
  void Write(const KURL& file_path,
             mojo::PendingRemote<mojom::blink::Blob> blob,
             int64_t position,
             mojo::PendingReceiver<mojom::blink::FileSystemCancellableOperation>
                 op_receiver,
             mojo::PendingRemote<mojom::blink::FileSystemOperationListener>
                 pending_listener) override {}
  void WriteSync(const KURL& file_path,
                 mojo::PendingRemote<mojom::blink::Blob> blob,
                 int64_t position,
                 WriteSyncCallback callback) override {}
  void Truncate(
      const KURL& file_path,
      int64_t length,
      mojo::PendingReceiver<mojom::blink::FileSystemCancellableOperation>
          op_receiver,
      TruncateCallback callback) override {}
  void TruncateSync(const KURL& file_path,
                    int64_t length,
                    TruncateSyncCallback callback) override {}
  void CreateSnapshotFile(const KURL& file_path,
                          CreateSnapshotFileCallback callback) override {}
  void GetPlatformPath(const KURL& file_path,
                       GetPlatformPathCallback callback) override {}
  void RegisterBlob(const String& content_type,
                    const KURL& url,
                    uint64_t length,
                    std::optional<base::Time> expected_modification_time,
                    RegisterBlobCallback callback) override {
    std::move(mock_register_blob_callback_)
        .Run(content_type, url, length, expected_modification_time);
    std::move(callback).Run(BlobDataHandle::Create());
  }

  void SetMockRegisterBlobCallback(
      MockRegisterBlobCallback mock_register_blob_callback) {
    mock_register_blob_callback_ = std::move(mock_register_blob_callback);
  }

 private:
  void BindReceiver(mojo::ScopedMessagePipeHandle handle) {
    receivers_.Add(this, mojo::PendingReceiver<mojom::blink::FileSystemManager>(
                             std::move(handle)));
  }

  const BrowserInterfaceBrokerProxy& broker_;
  mojo::ReceiverSet<mojom::blink::FileSystemManager> receivers_;
  MockRegisterBlobCallback mock_register_blob_callback_;
};

void ExpectTimestampIsNow(const File& file) {
  const base::Time now = base::Time::Now();
  const base::TimeDelta delta_now = now - base::Time::UnixEpoch();
  // Because lastModified() applies floor() internally, we should compare
  // integral millisecond values.
  EXPECT_GE(file.lastModified(), delta_now.InMilliseconds());
  EXPECT_GE(file.LastModifiedTime(), now);
}

}  // namespace

TEST(FileTest, NativeFileWithoutTimestamp) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext context;
  auto* const file = MakeGarbageCollected<File>(&context.GetExecutionContext(),
                                                "/native/path");
  MockBlob::Create(file, base::Time());

  EXPECT_TRUE(file->HasBackingFile());
  EXPECT_EQ("/native/path", file->GetPath());
  EXPECT_TRUE(file->FileSystemURL().IsEmpty());
  ExpectTimestampIsNow(*file);
}

TEST(FileTest, NativeFileWithUnixEpochTimestamp) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext context;
  auto* const file = MakeGarbageCollected<File>(&context.GetExecutionContext(),
                                                "/native/path");
  MockBlob::Create(file, base::Time::UnixEpoch());

  EXPECT_TRUE(file->HasBackingFile());
  EXPECT_EQ(0, file->lastModified());
  EXPECT_EQ(base::Time::UnixEpoch(), file->LastModifiedTime());
}

TEST(FileTest, NativeFileWithApocalypseTimestamp) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext context;
  auto* const file = MakeGarbageCollected<File>(&context.GetExecutionContext(),
                                                "/native/path");
  MockBlob::Create(file, base::Time::Max());

  EXPECT_TRUE(file->HasBackingFile());

  EXPECT_EQ((base::Time::Max() - base::Time::UnixEpoch()).InMilliseconds(),
            file->lastModified());
  EXPECT_EQ(base::Time::Max(), file->LastModifiedTime());
}

TEST(FileTest, BlobBackingFileWithoutTimestamp) {
  test::TaskEnvironment task_environment;
  auto* const file = MakeGarbageCollected<File>("name", std::nullopt,
                                                BlobDataHandle::Create());
  EXPECT_FALSE(file->HasBackingFile());
  EXPECT_TRUE(file->GetPath().empty());
  EXPECT_TRUE(file->FileSystemURL().IsEmpty());
  ExpectTimestampIsNow(*file);
}

TEST(FileTest, BlobBackingFileWithWindowsEpochTimestamp) {
  test::TaskEnvironment task_environment;
  auto* const file = MakeGarbageCollected<File>("name", base::Time(),
                                                BlobDataHandle::Create());
  EXPECT_FALSE(file->HasBackingFile());
  EXPECT_TRUE(file->GetPath().empty());
  EXPECT_TRUE(file->FileSystemURL().IsEmpty());
  EXPECT_EQ((base::Time() - base::Time::UnixEpoch()).InMilliseconds(),
            file->lastModified());
  EXPECT_EQ(base::Time(), file->LastModifiedTime());
}

TEST(FileTest, BlobBackingFileWithUnixEpochTimestamp) {
  test::TaskEnvironment task_environment;
  const scoped_refptr<BlobDataHandle> blob_data_handle =
      BlobDataHandle::Create();
  auto* const file = MakeGarbageCollected<File>("name", base::Time::UnixEpoch(),
                                                blob_data_handle);
  EXPECT_FALSE(file->HasBackingFile());
  EXPECT_TRUE(file->GetPath().empty());
  EXPECT_TRUE(file->FileSystemURL().IsEmpty());
  EXPECT_EQ(INT64_C(0), file->lastModified());
  EXPECT_EQ(base::Time::UnixEpoch(), file->LastModifiedTime());
}

TEST(FileTest, BlobBackingFileWithApocalypseTimestamp) {
  test::TaskEnvironment task_environment;
  constexpr base::Time kMaxTime = base::Time::Max();
  auto* const file =
      MakeGarbageCollected<File>("name", kMaxTime, BlobDataHandle::Create());
  EXPECT_FALSE(file->HasBackingFile());
  EXPECT_TRUE(file->GetPath().empty());
  EXPECT_TRUE(file->FileSystemURL().IsEmpty());
  EXPECT_EQ((kMaxTime - base::Time::UnixEpoch()).InMilliseconds(),
            file->lastModified());
  EXPECT_EQ(kMaxTime, file->LastModifiedTime());
}

TEST(FileTest, fileSystemFileWithNativeSnapshot) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext context;
  FileMetadata metadata;
  metadata.platform_path = "/native/snapshot";
  File* const file = File::CreateForFileSystemFile(
      &context.GetExecutionContext(), "name", metadata, File::kIsUserVisible);
  EXPECT_TRUE(file->HasBackingFile());
  EXPECT_EQ("/native/snapshot", file->GetPath());
  EXPECT_TRUE(file->FileSystemURL().IsEmpty());
}

TEST(FileTest, fileSystemFileWithNativeSnapshotAndSize) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext context;
  FileMetadata metadata;
  metadata.length = 1024ll;
  metadata.platform_path = "/native/snapshot";
  File* const file = File::CreateForFileSystemFile(
      &context.GetExecutionContext(), "name", metadata, File::kIsUserVisible);
  EXPECT_TRUE(file->HasBackingFile());
  EXPECT_EQ("/native/snapshot", file->GetPath());
  EXPECT_TRUE(file->FileSystemURL().IsEmpty());
}

TEST(FileTest, FileSystemFileWithWindowsEpochTimestamp) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext context;
  FileMetadata metadata;
  metadata.length = INT64_C(1025);
  metadata.modification_time = base::Time();
  metadata.platform_path = "/native/snapshot";
  File* const file = File::CreateForFileSystemFile(
      &context.GetExecutionContext(), "name", metadata, File::kIsUserVisible);
  EXPECT_TRUE(file->HasBackingFile());
  EXPECT_EQ("/native/snapshot", file->GetPath());
  EXPECT_TRUE(file->FileSystemURL().IsEmpty());
  EXPECT_EQ(UINT64_C(1025), file->size());
  EXPECT_EQ((base::Time() - base::Time::UnixEpoch()).InMilliseconds(),
            file->lastModified());
  EXPECT_EQ(base::Time(), file->LastModifiedTime());
}

TEST(FileTest, FileSystemFileWithUnixEpochTimestamp) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext context;
  FileMetadata metadata;
  metadata.length = INT64_C(1025);
  metadata.modification_time = base::Time::UnixEpoch();
  metadata.platform_path = "/native/snapshot";
  File* const file = File::CreateForFileSystemFile(
      &context.GetExecutionContext(), "name", metadata, File::kIsUserVisible);
  EXPECT_TRUE(file->HasBackingFile());
  EXPECT_EQ("/native/snapshot", file->GetPath());
  EXPECT_TRUE(file->FileSystemURL().IsEmpty());
  EXPECT_EQ(UINT64_C(1025), file->size());
  EXPECT_EQ(INT64_C(0), file->lastModified());
  EXPECT_EQ(base::Time::UnixEpoch(), file->LastModifiedTime());
}

TEST(FileTest, FileSystemFileWithApocalypseTimestamp) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext context;
  constexpr base::Time kMaxTime = base::Time::Max();
  FileMetadata metadata;
  metadata.length = INT64_C(1025);
  metadata.modification_time = kMaxTime;
  metadata.platform_path = "/native/snapshot";
  File* const file = File::CreateForFileSystemFile(
      &context.GetExecutionContext(), "name", metadata, File::kIsUserVisible);
  EXPECT_TRUE(file->HasBackingFile());
  EXPECT_EQ("/native/snapshot", file->GetPath());
  EXPECT_TRUE(file->FileSystemURL().IsEmpty());
  EXPECT_EQ(UINT64_C(1025), file->size());
  EXPECT_EQ((kMaxTime - base::Time::UnixEpoch()).InMilliseconds(),
            file->lastModified());
  EXPECT_EQ(kMaxTime, file->LastModifiedTime());
}

TEST(FileTest, fileSystemFileWithoutNativeSnapshot) {
  test::TaskEnvironment task_environment;
  KURL url("filesystem:http://example.com/isolated/hash/non-native-file");
  FileMetadata metadata;
  metadata.length = 0;
  File* const file = File::CreateForFileSystemFile(
      url, metadata, File::kIsUserVisible, BlobDataHandle::Create());
  EXPECT_FALSE(file->HasBackingFile());
  EXPECT_TRUE(file->GetPath().empty());
  EXPECT_EQ(url, file->FileSystemURL());
}

TEST(FileTest, hsaSameSource) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext context;
  auto* const native_file_a1 = MakeGarbageCollected<File>(
      &context.GetExecutionContext(), "/native/pathA");
  auto* const native_file_a2 = MakeGarbageCollected<File>(
      &context.GetExecutionContext(), "/native/pathA");
  auto* const native_file_b = MakeGarbageCollected<File>(
      &context.GetExecutionContext(), "/native/pathB");

  const scoped_refptr<BlobDataHandle> blob_data_a = BlobDataHandle::Create();
  const scoped_refptr<BlobDataHandle> blob_data_b = BlobDataHandle::Create();
  const base::Time kEpoch = base::Time::UnixEpoch();
  auto* const blob_file_a1 =
      MakeGarbageCollected<File>("name", kEpoch, blob_data_a);
  auto* const blob_file_a2 =
      MakeGarbageCollected<File>("name", kEpoch, blob_data_a);
  auto* const blob_file_b =
      MakeGarbageCollected<File>("name", kEpoch, blob_data_b);

  KURL url_a("filesystem:http://example.com/isolated/hash/non-native-file-A");
  KURL url_b("filesystem:http://example.com/isolated/hash/non-native-file-B");
  FileMetadata metadata;
  metadata.length = 0;
  File* const file_system_file_a1 = File::CreateForFileSystemFile(
      url_a, metadata, File::kIsUserVisible, BlobDataHandle::Create());
  File* const file_system_file_a2 = File::CreateForFileSystemFile(
      url_a, metadata, File::kIsUserVisible, BlobDataHandle::Create());
  File* const file_system_file_b = File::CreateForFileSystemFile(
      url_b, metadata, File::kIsUserVisible, BlobDataHandle::Create());

  EXPECT_FALSE(native_file_a1->HasSameSource(*blob_file_a1));
  EXPECT_FALSE(blob_file_a1->HasSameSource(*file_system_file_a1));
  EXPECT_FALSE(file_system_file_a1->HasSameSource(*native_file_a1));

  EXPECT_TRUE(native_file_a1->HasSameSource(*native_file_a1));
  EXPECT_TRUE(native_file_a1->HasSameSource(*native_file_a2));
  EXPECT_FALSE(native_file_a1->HasSameSource(*native_file_b));

  EXPECT_TRUE(blob_file_a1->HasSameSource(*blob_file_a1));
  EXPECT_TRUE(blob_file_a1->HasSameSource(*blob_file_a2));
  EXPECT_FALSE(blob_file_a1->HasSameSource(*blob_file_b));

  EXPECT_TRUE(file_system_file_a1->HasSameSource(*file_system_file_a1));
  EXPECT_TRUE(file_system_file_a1->HasSameSource(*file_system_file_a2));
  EXPECT_FALSE(file_system_file_a1->HasSameSource(*file_system_file_b));
}

TEST(FileTest, createForFileSystem) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope(KURL("http://example.com"));
  Document& document = scope.GetDocument();
  base::RunLoop run_loop;

  KURL filesystem_url(
      "filesystem:http://example.com/isolated/hash/non-native-file");
  FileMetadata metadata;
  metadata.length = 0;

  MockFileSystemManager manager(
      document.GetFrame()->GetBrowserInterfaceBroker());
  manager.SetMockRegisterBlobCallback(base::BindLambdaForTesting(
      [&](const String& content_type, const KURL& url, uint64_t length,
          std::optional<base::Time> expected_modification_time) {
        EXPECT_EQ(metadata.length, static_cast<int64_t>(length));
        EXPECT_EQ("", content_type);
        EXPECT_EQ(url, filesystem_url);
        run_loop.Quit();
      }));

  File* const file = File::CreateForFileSystemFile(
      *document.GetExecutionContext(), filesystem_url, metadata,
      File::kIsUserVisible);

  run_loop.Run();
  EXPECT_TRUE(file);
}
}  // namespace blink
```