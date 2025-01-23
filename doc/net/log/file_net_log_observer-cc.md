Response:
My thinking process to summarize the `FileNetLogObserver.cc` file goes through these stages:

1. **Understand the Goal:** The request asks for a functional summary of the C++ code, specifically focusing on its purpose within the Chromium networking stack, its relation to JavaScript, its error handling, debugging information, and overall function. Crucially, it's marked as "Part 1".

2. **Initial Scan and Keyword Identification:** I quickly scan the code, looking for prominent keywords, class names, and function names. This immediately highlights:
    * `FileNetLogObserver` (the central class)
    * `FileWriter` (responsible for file writing)
    * `WriteQueue` (manages a queue of events)
    * File operations (`base::File`, `OpenFileForWrite`, `WriteToFile`, etc.)
    * JSON serialization (`base::JSONWriter`, `SerializeNetLogValueToJson`)
    * Logging concepts (`NetLog`, `NetLogEntry`, `NetLogCaptureMode`)
    * Threading/Task management (`base::SequencedTaskRunner`, `base::ThreadPool`)
    * Different logging modes (bounded, unbounded)

3. **Core Function Identification:** Based on the keywords, I start to infer the main purpose. The name `FileNetLogObserver` strongly suggests it observes network events and writes them to a file. The `FileWriter` confirms this. The different `Create...` methods indicate different ways to configure the file logging.

4. **Bounded vs. Unbounded Logging:**  I notice the distinct `CreateBounded` and `CreateUnbounded` functions. This immediately tells me there are two primary operating modes. I'll need to explain the difference. The ".inprogress" directory mentioned in the bounded case further clarifies the strategy.

5. **Event Handling Flow:** I trace the flow of an event:
    * `OnAddEntry` is called when a network event occurs.
    * The event is serialized to JSON.
    * It's added to the `WriteQueue`.
    * The `WriteQueue` manages memory and potentially drops older events.
    * Periodically (or when a threshold is met), the `FileWriter::Flush` method is called on a separate thread.
    * `FileWriter` retrieves events from the queue and writes them to the file(s).

6. **FileWriter's Role:** I focus on the `FileWriter`. It handles:
    * Initialization (writing constants).
    * Writing individual events (potentially to multiple files in bounded mode).
    * Finalization (writing polled data).
    * Stitching files together in bounded mode.
    * Deleting files.

7. **WriteQueue's Role:** I analyze `WriteQueue`. It acts as a buffer between the main thread and the file writing thread. It has a memory limit to prevent excessive memory usage.

8. **JavaScript Interaction (or Lack Thereof):** I specifically search for any direct interaction with JavaScript APIs or concepts. I don't find any. Therefore, I conclude that its interaction is indirect, providing data that *could* be used by JavaScript-based tools for analysis. I need to clearly state this indirect relationship.

9. **Error Handling:** I look for `LOG(ERROR)` statements, file validity checks, and other error-handling mechanisms. The code logs errors when opening files. This is a key piece of information to include.

10. **Debugging Information:** The very purpose of this code is to *generate* debugging information. I need to explain *how* a user would trigger this (through browser settings or command-line flags).

11. **Logical Inference and Assumptions:** I think about potential inputs and outputs. For example, if bounded logging is used, I expect multiple event files and a final stitched file. If unbounded, a single file. I consider the impact of the `max_total_size` parameter.

12. **User Errors:** I consider common mistakes a user (or programmer configuring the logging) might make, such as providing an invalid file path or insufficient disk space.

13. **Structure and Organization:** I decide to organize the summary logically:
    * Start with a high-level overview of the file's purpose.
    * Detail the core functionalities (event observation, queuing, writing).
    * Explain the bounded and unbounded modes.
    * Address the JavaScript interaction.
    * Provide examples of logical inferences.
    * Highlight potential user errors.
    * Explain the user journey for debugging.
    * Conclude with a concise summary of its main function.

14. **Refinement and Clarity:** I review the summary to ensure it's clear, concise, and accurately reflects the code's functionality. I use precise language and avoid jargon where possible. I double-check that all parts of the original request are addressed.

This iterative process of scanning, identifying core components, tracing the data flow, and then organizing and refining the information allows me to create a comprehensive and accurate summary of the `FileNetLogObserver.cc` file. The "Part 1" indication reminds me that this is only a partial summary, and further details might be revealed in the second part.
这是 Chromium 网络栈中 `net/log/file_net_log_observer.cc` 文件的功能归纳，基于你提供的第一部分代码：

**核心功能:**

`FileNetLogObserver` 的主要功能是**将 Chromium 网络栈的 NetLog 事件记录到文件中**。它作为一个 `NetLog::Observer` 监听网络事件，并将这些事件序列化成 JSON 格式写入文件。该文件支持两种主要的记录模式：

* **有界模式 (Bounded):**  在这种模式下，日志文件的大小会受到限制。为了实现这一点，它会创建一系列的事件文件（例如 `event_file_0.json`, `event_file_1.json` 等）存储日志事件，当达到预设的最大大小或文件数量时，会覆盖旧的文件。最终，当日志记录停止时，这些分散的事件文件会被拼接成一个最终的日志文件。
* **无界模式 (Unbounded):** 在这种模式下，日志文件的大小没有限制，所有事件都会追加到一个单独的文件中。

**主要组成部分和功能细节:**

1. **`FileNetLogObserver` 类:**
   * **观察者角色:** 实现了 `NetLog::Observer` 接口，能够接收来自 `NetLog` 的事件通知。
   * **启动和停止:** 提供 `StartObserving()` 和 `StopObserving()` 方法来开始和结束日志记录。`StopObserving()` 方法还负责收集最终的 `polled_data` 并写入文件。
   * **事件处理:**  `OnAddEntry()` 方法在接收到新的 NetLog 事件时被调用。它将事件转换为 JSON 字符串，并将其添加到 `WriteQueue` 中。
   * **模式选择:** 提供静态方法 `CreateBounded()`, `CreateUnbounded()`, `CreateBoundedPreExisting()`, `CreateUnboundedPreExisting()`, `CreateBoundedFile()` 来创建不同配置的 `FileNetLogObserver` 实例，包括指定日志路径、最大大小、捕获模式等。
   * **资源管理:**  在析构函数中移除自身作为 `NetLog` 的观察者，并异步地删除所有日志文件。

2. **`WriteQueue` 类:**
   * **事件队列:**  使用 `base::queue` 存储待写入文件的 JSON 事件字符串。
   * **线程安全:**  使用 `base::Lock` 保护对队列和内存大小的访问，因为主线程添加事件，而文件写入线程消费事件。
   * **内存管理:**  维护一个内存计数器 `memory_`，并限制队列的最大内存使用量 `memory_max_`。当内存超过限制时，会丢弃最旧的事件，防止内存无限增长。
   * **批量写入:**  当队列中的事件数量达到 `kNumWriteQueueEvents` 时，会触发文件写入操作，实现批量写入，提高效率。

3. **`FileWriter` 类:**
   * **文件写入:**  负责将 `WriteQueue` 中的事件实际写入磁盘文件。
   * **有界模式处理:**  在有界模式下，管理多个事件文件的创建、写入和轮转。
   * **无界模式处理:** 在无界模式下，直接写入单个日志文件。
   * **文件拼接:** 在有界模式停止时，负责将多个事件文件、常量信息和轮询数据拼接成最终的日志文件。
   * **常量和轮询数据写入:**  `Initialize()` 方法写入常量信息， `Stop()` 方法写入最终的轮询数据。
   * **文件操作:**  使用 `base::File` 进行文件创建、写入、截断、删除等操作，所有文件操作都在专门的文件线程上执行。

4. **线程模型:**
   * **主线程:**  `FileNetLogObserver` 主要在主线程上接收和处理 NetLog 事件，并将事件添加到 `WriteQueue`。
   * **文件线程:**  `FileWriter` 的所有文件 I/O 操作都在一个独立的序列化任务队列 (sequenced task runner) 上执行，以避免阻塞主线程。

**与 JavaScript 的关系:**

从这段代码本身来看，`FileNetLogObserver` **没有直接与 JavaScript 功能交互**。 它的主要职责是处理 C++ 网络栈中的事件并将其持久化到文件中。

然而，生成的 NetLog 文件（JSON 格式）**可以被 JavaScript 代码读取和解析**，用于网络性能分析、调试等目的。例如：

* **Chrome 的 `chrome://net-export/` 工具:** 这个内置的 Chrome 工具使用 NetLog 来记录网络活动，用户可以选择将日志导出为 JSON 文件。这个 JSON 文件就可以被 JavaScript 代码读取和分析。
* **开发者工具 (DevTools):**  DevTools 中的 Network 面板在底层也使用了 NetLog 数据。虽然 DevTools 本身是用 JavaScript 编写的，但 `FileNetLogObserver` 负责将数据写入文件，DevTools 可能会读取这些文件或通过其他机制获取 NetLog 数据进行展示。
* **自定义分析工具:** 开发者可以使用 JavaScript 编写自定义的工具来解析 NetLog 文件，提取有用的网络性能指标或调试信息。

**举例说明 (假设输入与输出):**

**假设输入 (有界模式):**

* `log_path`: `/tmp/netlog.json`
* `max_total_size`: 10MB
* `total_num_event_files`: 3
* 网络活动产生了 150 个 NetLog 事件。

**逻辑推理与输出 (简化):**

1. **初始化:**  创建一个 `.inprogress` 目录 `/tmp/netlog.json.inprogress`。
2. **常量写入:** 将常量信息写入 `/tmp/netlog.json.inprogress/constants.json`。
3. **事件写入:**
   * 前 50 个事件写入 `/tmp/netlog.json.inprogress/event_file_0.json`。
   * 接下来的 50 个事件写入 `/tmp/netlog.json.inprogress/event_file_1.json`。
   * 最后 50 个事件写入 `/tmp/netlog.json.inprogress/event_file_2.json`。
4. **停止和拼接:**
   * 将轮询数据写入 `/tmp/netlog.json.inprogress/end_netlog.json`。
   * 将 `/tmp/netlog.json.inprogress/constants.json`、`/tmp/netlog.json.inprogress/event_file_0.json`、`/tmp/netlog.json.inprogress/event_file_1.json`、`/tmp/netlog.json.inprogress/event_file_2.json` 和 `/tmp/netlog.json.inprogress/end_netlog.json` 的内容拼接成 `/tmp/netlog.json`。
   * 删除 `/tmp/netlog.json.inprogress` 目录。

**假设输入 (无界模式):**

* `log_path`: `/tmp/netlog.json`
* 网络活动产生了 100 个 NetLog 事件。

**逻辑推理与输出 (简化):**

1. **初始化:** 创建或截断文件 `/tmp/netlog.json`。
2. **常量写入:** 将常量信息写入 `/tmp/netlog.json`。
3. **事件写入:**  100 个事件依次写入 `/tmp/netlog.json`。
4. **停止:** 将轮询数据写入 `/tmp/netlog.json`。

**用户或编程常见的使用错误:**

1. **文件路径权限问题:** 如果用户指定的日志文件路径没有写入权限，`OpenFileForWrite()` 会失败，导致日志记录无法进行。
   * **错误示例:**  用户尝试将日志写入到 `/root/netlog.json`，但当前用户没有 root 权限。
   * **日志输出:**  会看到类似 "Failed opening: /root/netlog.json" 的错误日志。

2. **磁盘空间不足:** 在有界模式下，如果磁盘空间不足以创建和维护多个事件文件，可能会导致写入失败。
   * **错误示例:** `max_total_size` 设置过大，但磁盘剩余空间不足。
   * **潜在结果:**  可能部分事件被记录，但最终的拼接文件可能不完整，或者出现文件写入错误。

3. **并发问题 (如果手动操作文件):**  如果用户在 NetLog 正在写入时尝试手动修改或删除日志文件，可能会导致不可预测的结果。Chromium 内部已经处理了并发写入的问题，但外部操作需要谨慎。

4. **错误配置有界模式参数:**  例如，`max_total_size` 设置过小，或者 `total_num_event_files` 设置不合理，可能会导致日志过早被覆盖，丢失重要的信息。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在 Chrome 中启用 NetLog 记录:**
   * 用户访问 `chrome://net-export/`。
   * 用户选择 "Start Logging"。
   * 用户可以选择不同的捕获级别（例如，默认、包含敏感信息、所有信息）。  这个选择会影响 `NetLogCaptureMode`。
   * 用户可以选择指定日志文件的保存路径。
   * 用户点击 "Start Logging"，这时 Chrome 会创建并启动 `FileNetLogObserver` 实例。

2. **或者，通过命令行参数启用 NetLog 记录:**
   * 用户启动 Chrome 时使用 `--log-net-log=/path/to/netlog.json` 这样的命令行参数。
   * Chrome 启动时会根据命令行参数创建并启动 `FileNetLogObserver` 实例。

3. **网络活动发生:**
   * 用户浏览网页、进行网络请求等操作。
   * Chromium 网络栈的各个组件会生成 `NetLog` 事件。

4. **`NetLog` 通知 `FileNetLogObserver`:**
   * 当新的 `NetLog` 事件产生时，`NetLog::AddEntry()` 方法会被调用。
   * `FileNetLogObserver` 作为注册的观察者，其 `OnAddEntry()` 方法会被调用。

5. **事件被添加到 `WriteQueue`:**
   * `OnAddEntry()` 方法将事件序列化为 JSON 并添加到 `WriteQueue` 中。

6. **`FileWriter` 在文件线程上写入事件:**
   * 当 `WriteQueue` 中的事件数量达到阈值或 `Flush` 操作被触发时，`FileWriter` 会将事件从队列中取出并写入到文件中。

7. **用户停止 NetLog 记录:**
   * 用户在 `chrome://net-export/` 中点击 "Stop Logging"。
   * 或者，用户关闭 Chrome 浏览器。
   * `FileNetLogObserver::StopObserving()` 方法会被调用，触发最终的数据写入和文件拼接（如果是有界模式）。

**总结 (第一部分功能归纳):**

`FileNetLogObserver` 是 Chromium 网络栈中负责将详细的网络事件记录到文件的关键组件。它支持有界和无界两种日志记录模式，使用独立的线程进行文件 I/O 操作，并通过 `WriteQueue` 管理待写入的事件，以确保性能和内存使用效率。它不直接与 JavaScript 交互，但生成的 JSON 日志文件可以被 JavaScript 代码用于分析和调试。

### 提示词
```
这是目录为net/log/file_net_log_observer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/log/file_net_log_observer.h"

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "base/containers/queue.h"
#include "base/containers/span.h"
#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/numerics/clamped_math.h"
#include "base/strings/string_number_conversions.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/values.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_entry.h"
#include "net/log/net_log_util.h"
#include "net/url_request/url_request_context.h"

namespace {

// Number of events that can build up in |write_queue_| before a task is posted
// to the file task runner to flush them to disk.
const int kNumWriteQueueEvents = 15;

// TODO(eroman): Should use something other than 10 for number of files?
const int kDefaultNumFiles = 10;

scoped_refptr<base::SequencedTaskRunner> CreateFileTaskRunner() {
  // The tasks posted to this sequenced task runner do synchronous File I/O for
  // the purposes of writing NetLog files.
  //
  // These intentionally block shutdown to ensure the log file has finished
  // being written.
  return base::ThreadPool::CreateSequencedTaskRunner(
      {base::MayBlock(), base::TaskPriority::USER_VISIBLE,
       base::TaskShutdownBehavior::BLOCK_SHUTDOWN});
}

// Truncates a file, also reseting the seek position.
void TruncateFile(base::File* file) {
  if (!file->IsValid())
    return;
  file->Seek(base::File::FROM_BEGIN, 0);
  file->SetLength(0);
}

// Opens |path| in write mode.
base::File OpenFileForWrite(const base::FilePath& path) {
  base::File result(path,
                    base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  LOG_IF(ERROR, !result.IsValid()) << "Failed opening: " << path.value();
  return result;
}

// Helper that writes data to a file. |file->IsValid()| may be false,
// in which case nothing will be written. Returns the number of bytes
// successfully written (may be less than input data in case of errors).
size_t WriteToFile(base::File* file,
                   std::string_view data1,
                   std::string_view data2 = std::string_view(),
                   std::string_view data3 = std::string_view()) {
  size_t bytes_written = 0;

  if (file->IsValid()) {
    if (!data1.empty()) {
      bytes_written +=
          file->WriteAtCurrentPos(base::as_byte_span(data1)).value_or(0);
    }
    if (!data2.empty()) {
      bytes_written +=
          file->WriteAtCurrentPos(base::as_byte_span(data2)).value_or(0);
    }
    if (!data3.empty()) {
      bytes_written +=
          file->WriteAtCurrentPos(base::as_byte_span(data3)).value_or(0);
    }
  }

  return bytes_written;
}

// Copies all of the data at |source_path| and appends it to |destination_file|,
// then deletes |source_path|.
void AppendToFileThenDelete(const base::FilePath& source_path,
                            base::File* destination_file,
                            char* read_buffer,
                            size_t read_buffer_size) {
  base::ScopedFILE source_file(base::OpenFile(source_path, "rb"));
  if (!source_file)
    return;

  // Read |source_path|'s contents in chunks of read_buffer_size and append
  // to |destination_file|.
  size_t num_bytes_read;
  while ((num_bytes_read =
              fread(read_buffer, 1, read_buffer_size, source_file.get())) > 0) {
    WriteToFile(destination_file,
                std::string_view(read_buffer, num_bytes_read));
  }

  // Now that it has been copied, delete the source file.
  source_file.reset();
  base::DeleteFile(source_path);
}

base::FilePath SiblingInprogressDirectory(const base::FilePath& log_path) {
  return log_path.AddExtension(FILE_PATH_LITERAL(".inprogress"));
}

}  // namespace

namespace net {

// Used to store events to be written to file.
using EventQueue = base::queue<std::unique_ptr<std::string>>;

// WriteQueue receives events from FileNetLogObserver on the main thread and
// holds them in a queue until they are drained from the queue and written to
// file on the file task runner.
//
// WriteQueue contains the resources shared between the main thread and the
// file task runner. |lock_| must be acquired to read or write to |queue_| and
// |memory_|.
//
// WriteQueue is refcounted and should be destroyed once all events on the
// file task runner have finished executing.
class FileNetLogObserver::WriteQueue
    : public base::RefCountedThreadSafe<WriteQueue> {
 public:
  // |memory_max| indicates the maximum amount of memory that the virtual write
  // queue can use. If |memory_| exceeds |memory_max_|, the |queue_| of events
  // is overwritten.
  explicit WriteQueue(uint64_t memory_max);

  WriteQueue(const WriteQueue&) = delete;
  WriteQueue& operator=(const WriteQueue&) = delete;

  // Adds |event| to |queue_|. Also manages the size of |memory_|; if it
  // exceeds |memory_max_|, then old events are dropped from |queue_| without
  // being written to file.
  //
  // Returns the number of events in the |queue_|.
  size_t AddEntryToQueue(std::unique_ptr<std::string> event);

  // Swaps |queue_| with |local_queue|. |local_queue| should be empty, so that
  // |queue_| is emptied. Resets |memory_| to 0.
  void SwapQueue(EventQueue* local_queue);

 private:
  friend class base::RefCountedThreadSafe<WriteQueue>;

  ~WriteQueue();

  // Queue of events to be written, shared between main thread and file task
  // runner. Main thread adds events to the queue and the file task runner
  // drains them and writes the events to file.
  //
  // |lock_| must be acquired to read or write to this.
  EventQueue queue_;

  // Tracks how much memory is being used by the virtual write queue.
  // Incremented in AddEntryToQueue() when events are added to the
  // buffer, and decremented when SwapQueue() is called and the file task
  // runner's local queue is swapped with the shared write queue.
  //
  // |lock_| must be acquired to read or write to this.
  uint64_t memory_ = 0;

  // Indicates the maximum amount of memory that the |queue_| is allowed to
  // use.
  const uint64_t memory_max_;

  // Protects access to |queue_| and |memory_|.
  //
  // A lock is necessary because |queue_| and |memory_| are shared between the
  // file task runner and the main thread. NetLog's lock protects OnAddEntry(),
  // which calls AddEntryToQueue(), but it does not protect access to the
  // observer's member variables. Thus, a race condition exists if a thread is
  // calling OnAddEntry() at the same time that the file task runner is
  // accessing |memory_| and |queue_| to write events to file. The |queue_| and
  // |memory_| counter are necessary to bound the amount of memory that is used
  // for the queue in the event that the file task runner lags significantly
  // behind the main thread in writing events to file.
  base::Lock lock_;
};

// FileWriter is responsible for draining events from a WriteQueue and writing
// them to disk. FileWriter can be constructed on any thread, and
// afterwards is only accessed on the file task runner.
class FileNetLogObserver::FileWriter {
 public:
  // If max_event_file_size == kNoLimit, then no limit is enforced.
  FileWriter(const base::FilePath& log_path,
             const base::FilePath& inprogress_dir_path,
             std::optional<base::File> pre_existing_log_file,
             uint64_t max_event_file_size,
             size_t total_num_event_files,
             scoped_refptr<base::SequencedTaskRunner> task_runner);

  FileWriter(const FileWriter&) = delete;
  FileWriter& operator=(const FileWriter&) = delete;

  ~FileWriter();

  // Writes |constants_value| to disk and opens the events array (closed in
  // Stop()).
  void Initialize(std::unique_ptr<base::Value::Dict> constants_value);

  // Closes the events array opened in Initialize() and writes |polled_data| to
  // disk. If |polled_data| cannot be converted to proper JSON, then it
  // is ignored.
  void Stop(std::unique_ptr<base::Value> polled_data);

  // Drains |queue_| from WriteQueue into a local file queue and writes the
  // events in the queue to disk.
  void Flush(scoped_refptr<WriteQueue> write_queue);

  // Deletes all netlog files. It is not valid to call any method of
  // FileNetLogObserver after DeleteAllFiles().
  void DeleteAllFiles();

  void FlushThenStop(scoped_refptr<WriteQueue> write_queue,
                     std::unique_ptr<base::Value> polled_data);

 private:
  // Returns true if there is no file size bound to enforce.
  //
  // When operating in unbounded mode, the implementation is optimized to stream
  // writes to a single file, rather than chunking them across temporary event
  // files.
  bool IsUnbounded() const;
  bool IsBounded() const;

  // Returns true if there is a file size bound to enforce and we want to stitch
  // the files together.
  bool IsBoundedAndStitchable() const;

  // Increments |current_event_file_number_|, and updates all state relating to
  // the current event file (open file handle, num bytes written, current file
  // number).
  void IncrementCurrentEventFile();

  // Returns the path to the event file having |index|. This looks like
  // "LOGDIR/event_file_<index>.json".
  base::FilePath GetEventFilePath(size_t index) const;

  // Gets the file path where constants are saved at the start of
  // logging. This looks like "LOGDIR/constants.json".
  base::FilePath GetConstantsFilePath() const;

  // Gets the file path where the final data is written at the end of logging.
  // This looks like "LOGDIR/end_netlog.json".
  base::FilePath GetClosingFilePath() const;

  // Returns the corresponding index for |file_number|. File "numbers" are a
  // monotonically increasing identifier that start at 1 (a value of zero means
  // it is uninitialized), whereas the file "index" is a bounded value that
  // wraps and identifies the file path to use.
  //
  // Keeping track of the current number rather than index makes it a bit easier
  // to assemble a file at the end, since it is unambiguous which paths have
  // been used/re-used.
  size_t FileNumberToIndex(size_t file_number) const;

  // Writes |constants_value| to a file.
  static void WriteConstantsToFile(
      std::unique_ptr<base::Value::Dict> constants_value,
      base::File* file);

  // Writes |polled_data| to a file.
  static void WritePolledDataToFile(std::unique_ptr<base::Value> polled_data,
                                    base::File* file);

  // If any events were written (wrote_event_bytes_), rewinds |file| by 2 bytes
  // in order to overwrite the trailing ",\n" that was written by the last event
  // line.
  void RewindIfWroteEventBytes(base::File* file) const;

  // Concatenates all the log files to assemble the final
  // |final_log_file_|. This single "stitched" file is what other
  // log ingesting tools expect.
  void StitchFinalLogFile();

  // Creates the .inprogress directory used by bounded mode.
  void CreateInprogressDirectory();

  // The file the final netlog is written to. In bounded mode this is mostly
  // written to once logging is stopped, whereas in unbounded mode events will
  // be directly written to it.
  base::File final_log_file_;

  // If non-empty, this is the path to |final_log_file_| created and owned
  // by FileWriter itself (rather than passed in to Create*PreExisting
  // methods of FileNetLogObserver).
  const base::FilePath final_log_path_;

  // Path to a (temporary) directory where files are written in bounded mode.
  // When logging is stopped these files are stitched together and written
  // to the final log path.
  const base::FilePath inprogress_dir_path_;

  // Holds the numbered events file where data is currently being written to.
  // The file path of this file is GetEventFilePath(current_event_file_number_).
  // The file may be !IsValid() if an error previously occurred opening the
  // file, or logging has been stopped.
  base::File current_event_file_;
  uint64_t current_event_file_size_;

  // Indicates the total number of netlog event files allowed.
  // (The files GetConstantsFilePath() and GetClosingFilePath() do
  // not count against the total.)
  const size_t total_num_event_files_;

  // Counter for the events file currently being written into. See
  // FileNumberToIndex() for an explanation of what "number" vs "index" mean.
  size_t current_event_file_number_ = 0;

  // Indicates the maximum size of each individual events file. May be kNoLimit
  // to indicate that it can grow arbitrarily large.
  const uint64_t max_event_file_size_;

  // Whether any bytes were written for events. This is used to properly format
  // JSON (events list shouldn't end with a comma).
  bool wrote_event_bytes_ = false;

  // Task runner for doing file operations.
  const scoped_refptr<base::SequencedTaskRunner> task_runner_;
};

std::unique_ptr<FileNetLogObserver> FileNetLogObserver::CreateBounded(
    const base::FilePath& log_path,
    uint64_t max_total_size,
    NetLogCaptureMode capture_mode,
    std::unique_ptr<base::Value::Dict> constants) {
  return CreateInternal(log_path, SiblingInprogressDirectory(log_path),
                        std::nullopt, max_total_size, kDefaultNumFiles,
                        capture_mode, std::move(constants));
}

std::unique_ptr<FileNetLogObserver> FileNetLogObserver::CreateUnbounded(
    const base::FilePath& log_path,
    NetLogCaptureMode capture_mode,
    std::unique_ptr<base::Value::Dict> constants) {
  return CreateInternal(log_path, base::FilePath(), std::nullopt, kNoLimit,
                        kDefaultNumFiles, capture_mode, std::move(constants));
}

std::unique_ptr<FileNetLogObserver>
FileNetLogObserver::CreateBoundedPreExisting(
    const base::FilePath& inprogress_dir_path,
    base::File output_file,
    uint64_t max_total_size,
    NetLogCaptureMode capture_mode,
    std::unique_ptr<base::Value::Dict> constants) {
  return CreateInternal(base::FilePath(), inprogress_dir_path,
                        std::make_optional<base::File>(std::move(output_file)),
                        max_total_size, kDefaultNumFiles, capture_mode,
                        std::move(constants));
}

std::unique_ptr<FileNetLogObserver>
FileNetLogObserver::CreateUnboundedPreExisting(
    base::File output_file,
    NetLogCaptureMode capture_mode,
    std::unique_ptr<base::Value::Dict> constants) {
  return CreateInternal(base::FilePath(), base::FilePath(),
                        std::make_optional<base::File>(std::move(output_file)),
                        kNoLimit, kDefaultNumFiles, capture_mode,
                        std::move(constants));
}

std::unique_ptr<FileNetLogObserver> FileNetLogObserver::CreateBoundedFile(
    base::File output_file,
    uint64_t max_total_size,
    NetLogCaptureMode capture_mode,
    std::unique_ptr<base::Value::Dict> constants) {
  return CreateInternal(base::FilePath(), base::FilePath(),
                        std::make_optional<base::File>(std::move(output_file)),
                        max_total_size, 1, capture_mode, std::move(constants));
}

FileNetLogObserver::~FileNetLogObserver() {
  if (net_log()) {
    // StopObserving was not called.
    net_log()->RemoveObserver(this);
    file_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&FileNetLogObserver::FileWriter::DeleteAllFiles,
                       base::Unretained(file_writer_.get())));
  }
  file_task_runner_->DeleteSoon(FROM_HERE, file_writer_.release());
}

void FileNetLogObserver::StartObserving(NetLog* net_log) {
  net_log->AddObserver(this, capture_mode_);
}

void FileNetLogObserver::StopObserving(std::unique_ptr<base::Value> polled_data,
                                       base::OnceClosure optional_callback) {
  net_log()->RemoveObserver(this);

  base::OnceClosure bound_flush_then_stop =
      base::BindOnce(&FileNetLogObserver::FileWriter::FlushThenStop,
                     base::Unretained(file_writer_.get()), write_queue_,
                     std::move(polled_data));

  // Note that PostTaskAndReply() requires a non-null closure.
  if (!optional_callback.is_null()) {
    file_task_runner_->PostTaskAndReply(FROM_HERE,
                                        std::move(bound_flush_then_stop),
                                        std::move(optional_callback));
  } else {
    file_task_runner_->PostTask(FROM_HERE, std::move(bound_flush_then_stop));
  }
}

void FileNetLogObserver::OnAddEntry(const NetLogEntry& entry) {
  auto json = std::make_unique<std::string>();

  *json = SerializeNetLogValueToJson(entry.ToDict());

  size_t queue_size = write_queue_->AddEntryToQueue(std::move(json));

  // If events build up in |write_queue_|, trigger the file task runner to drain
  // the queue. Because only 1 item is added to the queue at a time, if
  // queue_size > kNumWriteQueueEvents a task has already been posted, or will
  // be posted.
  if (queue_size == kNumWriteQueueEvents) {
    file_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&FileNetLogObserver::FileWriter::Flush,
                       base::Unretained(file_writer_.get()), write_queue_));
  }
}

std::unique_ptr<FileNetLogObserver> FileNetLogObserver::CreateBoundedForTests(
    const base::FilePath& log_path,
    uint64_t max_total_size,
    size_t total_num_event_files,
    NetLogCaptureMode capture_mode,
    std::unique_ptr<base::Value::Dict> constants) {
  return CreateInternal(log_path, SiblingInprogressDirectory(log_path),
                        std::nullopt, max_total_size, total_num_event_files,
                        capture_mode, std::move(constants));
}

std::unique_ptr<FileNetLogObserver> FileNetLogObserver::CreateInternal(
    const base::FilePath& log_path,
    const base::FilePath& inprogress_dir_path,
    std::optional<base::File> pre_existing_log_file,
    uint64_t max_total_size,
    size_t total_num_event_files,
    NetLogCaptureMode capture_mode,
    std::unique_ptr<base::Value::Dict> constants) {
  DCHECK_GT(total_num_event_files, 0u);

  scoped_refptr<base::SequencedTaskRunner> file_task_runner =
      CreateFileTaskRunner();

  const uint64_t max_event_file_size =
      max_total_size == kNoLimit ? kNoLimit
                                 : max_total_size / total_num_event_files;

  // The FileWriter uses a soft limit to write events to file that allows
  // the size of the file to exceed the limit, but the WriteQueue uses a hard
  // limit which the size of |WriteQueue::queue_| cannot exceed. Thus, the
  // FileWriter may write more events to file than can be contained by
  // the WriteQueue if they have the same size limit. The maximum size of the
  // WriteQueue is doubled to allow |WriteQueue::queue_| to hold enough events
  // for the FileWriter to fill all files. As long as all events have
  // sizes <= the size of an individual event file, the discrepancy between the
  // hard limit and the soft limit will not cause an issue.
  // TODO(dconnol): Handle the case when the WriteQueue  still doesn't
  // contain enough events to fill all files, because of very large events
  // relative to file size.
  auto file_writer = std::make_unique<FileWriter>(
      log_path, inprogress_dir_path, std::move(pre_existing_log_file),
      max_event_file_size, total_num_event_files, file_task_runner);

  uint64_t write_queue_memory_max =
      base::MakeClampedNum<uint64_t>(max_total_size) * 2;

  return base::WrapUnique(new FileNetLogObserver(
      file_task_runner, std::move(file_writer),
      base::MakeRefCounted<WriteQueue>(write_queue_memory_max), capture_mode,
      std::move(constants)));
}

FileNetLogObserver::FileNetLogObserver(
    scoped_refptr<base::SequencedTaskRunner> file_task_runner,
    std::unique_ptr<FileWriter> file_writer,
    scoped_refptr<WriteQueue> write_queue,
    NetLogCaptureMode capture_mode,
    std::unique_ptr<base::Value::Dict> constants)
    : file_task_runner_(std::move(file_task_runner)),
      write_queue_(std::move(write_queue)),
      file_writer_(std::move(file_writer)),
      capture_mode_(capture_mode) {
  if (!constants)
    constants = std::make_unique<base::Value::Dict>(GetNetConstants());

  DCHECK(!constants->Find("logCaptureMode"));
  constants->Set("logCaptureMode", CaptureModeToString(capture_mode));
  file_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&FileNetLogObserver::FileWriter::Initialize,
                                base::Unretained(file_writer_.get()),
                                std::move(constants)));
}

std::string FileNetLogObserver::CaptureModeToString(NetLogCaptureMode mode) {
  switch (mode) {
    case NetLogCaptureMode::kDefault:
      return "Default";
    case NetLogCaptureMode::kIncludeSensitive:
      return "IncludeSensitive";
    case NetLogCaptureMode::kEverything:
      return "Everything";
  }
  NOTREACHED();
}

FileNetLogObserver::WriteQueue::WriteQueue(uint64_t memory_max)
    : memory_max_(memory_max) {}

size_t FileNetLogObserver::WriteQueue::AddEntryToQueue(
    std::unique_ptr<std::string> event) {
  base::AutoLock lock(lock_);

  memory_ += event->size();
  queue_.push(std::move(event));

  while (memory_ > memory_max_ && !queue_.empty()) {
    // Delete oldest events in the queue.
    DCHECK(queue_.front());
    memory_ -= queue_.front()->size();
    queue_.pop();
  }

  return queue_.size();
}

void FileNetLogObserver::WriteQueue::SwapQueue(EventQueue* local_queue) {
  DCHECK(local_queue->empty());
  base::AutoLock lock(lock_);
  queue_.swap(*local_queue);
  memory_ = 0;
}

FileNetLogObserver::WriteQueue::~WriteQueue() = default;

FileNetLogObserver::FileWriter::FileWriter(
    const base::FilePath& log_path,
    const base::FilePath& inprogress_dir_path,
    std::optional<base::File> pre_existing_log_file,
    uint64_t max_event_file_size,
    size_t total_num_event_files,
    scoped_refptr<base::SequencedTaskRunner> task_runner)
    : final_log_path_(log_path),
      inprogress_dir_path_(inprogress_dir_path),
      total_num_event_files_(total_num_event_files),
      max_event_file_size_(max_event_file_size),
      task_runner_(std::move(task_runner)) {
  DCHECK_EQ(pre_existing_log_file.has_value(), log_path.empty());

  if (pre_existing_log_file.has_value()) {
    // pre_existing_log_file.IsValid() being false is fine.
    final_log_file_ = std::move(pre_existing_log_file.value());
    if (inprogress_dir_path.empty()) {
      // If we are not stitching the files together, then we aren't using
      // bounded, but we still need to to keep track of the size of the current
      // event file starting from 0 bytes written.
      current_event_file_size_ = 0;
    }
  }
}

FileNetLogObserver::FileWriter::~FileWriter() = default;

void FileNetLogObserver::FileWriter::Initialize(
    std::unique_ptr<base::Value::Dict> constants_value) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  // Open the final log file, and keep it open for the duration of logging
  // (even in bounded mode).
  if (!final_log_path_.empty())
    final_log_file_ = OpenFileForWrite(final_log_path_);
  else
    TruncateFile(&final_log_file_);

  if (IsBoundedAndStitchable()) {
    CreateInprogressDirectory();
    base::File constants_file = OpenFileForWrite(GetConstantsFilePath());
    WriteConstantsToFile(std::move(constants_value), &constants_file);
  } else {
    WriteConstantsToFile(std::move(constants_value), &final_log_file_);
  }
}

void FileNetLogObserver::FileWriter::Stop(
    std::unique_ptr<base::Value> polled_data) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  // Write out the polled data.
  if (IsBoundedAndStitchable()) {
    base::File closing_file = OpenFileForWrite(GetClosingFilePath());
    WritePolledDataToFile(std::move(polled_data), &closing_file);
  } else {
    RewindIfWroteEventBytes(&final_log_file_);
    WritePolledDataToFile(std::move(polled_data), &final_log_file_);
  }

  // If operating in bounded mode, the events were written to separate files
  // within |inprogress_dir_path_|. Assemble them into the final destination
  // file.
  if (IsBoundedAndStitchable()) {
    StitchFinalLogFile();
  }

  // Ensure the final log file has been flushed.
  final_log_file_.Close();
}

void FileNetLogObserver::FileWriter::Flush(
    scoped_refptr<FileNetLogObserver::WriteQueue> write_queue) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  EventQueue local_file_queue;
  write_queue->SwapQueue(&local_file_queue);

  while (!local_file_queue.empty()) {
    base::File* output_file;

    if (inprogress_dir_path_.empty() && IsBounded() &&
        current_event_file_size_ > max_event_file_size_) {
      return;
    }

    // If in bounded mode, output events to the current event file. Otherwise
    // output events to the final log path.
    if (IsBoundedAndStitchable()) {
      if (current_event_file_number_ == 0 ||
          current_event_file_size_ >= max_event_file_size_) {
        IncrementCurrentEventFile();
      }
      output_file = &current_event_file_;
    } else {
      output_file = &final_log_file_;
    }

    size_t bytes_written =
        WriteToFile(output_file, *local_file_queue.front(), ",\n");

    wrote_event_bytes_ |= bytes_written > 0;

    // Keep track of the filesize for current event file when in bounded mode.
    if (IsBounded()) {
      current_event_file_size_ += bytes_written;
    }
    local_file_queue.pop();
  }
}

void FileNetLogObserver::FileWriter::DeleteAllFiles() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  final_log_file_.Close();

  if (IsBoundedAndStitchable()) {
    current_event_file_.Close();
    base::DeletePathRecursively(inprogress_dir_path_);
  }

  // Only delete |final_log_file_| if it was created internally.
  // (If it was provided as a base::File by the caller, don't try to delete it).
  if (!final_log_path_.empty())
    base::DeleteFile(final_log_path_);
}

void FileNetLogObserver::FileWriter::FlushThenStop(
    scoped_refptr<FileNetLogObserver::WriteQueue> write_queue,
    std::unique_ptr<base::Value> polled_data) {
  Flush(write_queue);
  Stop(std::move(polled_data));
}

bool FileNetLogObserver::FileWriter::IsUnbounded() const {
  return max_event_file_size_ == kNoLimit;
}

bool FileNetLogObserver::FileWriter::IsBounded() const {
  return !IsUnbounded();
}

bool FileNetLogObserver::FileWriter::IsBoundedAndStitchable() const {
  return IsBounded() && !inprogress_dir_path_.empty();
}

void FileNetLogObserver::FileWriter::IncrementCurrentEventFile() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  DCHECK(IsBoundedAndStitchable());

  current_event_file_number_++;
  current_event_file_ = OpenFileForWrite(
      GetEventFilePath(FileNumberToIndex(current_event_file_number_)));
  current_event_file_size_ = 0;
}

base::FilePath FileNetLogObserver::FileWriter::GetEventFilePath(
    size_t index) const {
  DCHECK_LT(index, total_num_event_files_);
  DCHECK(IsBoundedAndStitchable());
  return inprogress_dir_path_.AppendASCII(
      "event_file_" + base::NumberToString(index) + ".json");
}

base::FilePath FileNetLogObserver::FileWriter::GetConstantsFilePath() const {
  return inprogress_dir_path_.AppendASCII("constants.json");
}

base::FilePath FileNetLogObserver::FileWriter::GetClosingFilePath() const {
  return inprogress_dir_path_.AppendASCII("end_netlog.json");
}

size_t FileNetLogObserver::FileWriter::FileNumberToIndex(
    size_t file_number) const {
  DCHECK_GT(file_number, 0u);
  // Note that "file numbers" start at 1 not 0.
  return (file_number - 1) % total_num_event_files_;
}

void FileNetLogObserver::FileWriter::WriteConstantsToFile(
    std::unique_ptr<base::Value::Dict> constants_value,
    base::File* file) {
  // Print constants to file and open events array.
  std::string json = SerializeNetLogValueToJson(*constants_value);
  WriteToFile(file, "{\"constants\":", json, ",\n\"events\": [\n");
}

void FileNetLogObserver::FileWriter::WritePolledDataToFile(
    std::unique_ptr<base::Value> polled_data,
    base::File* file) {
  // Close the events array.
  WriteToFile(file, "]");

  // Write the polled data (if any).
  if (polled_data) {
    std::string polled_data_json;
    base::JSONWriter::Write(*polled_data, &polled_data_json);
    if (!polled_data_json.empty())
      WriteToFile(file, ",\n\"polledData\": ", polled_data_json, "\n");
  }

  // Close the log.
  WriteToFile(file, "}\n");
}

void FileNetLogObserver::FileWriter::RewindIfWroteEventBytes(
    base::File* file) const {
  if (file->IsValid() && wrote_event_bytes_) {
    // To be valid JSON the events array should not end with a comma. If events
    // were written though, they will have been terminated with "\n," so strip
    // it before closing the events array.
    file->Seek(base::File::FROM_END, -2);
  }
}

void FileNetLogObserver::FileWriter::StitchFinalLogFile() {
  // Make sure all the events files are flushed (as will read them next).
  current_event_file_.Close();

  // Allocate a 64K buffer used for reading the files. At most kReadBufferSize
  // bytes will be in memory at a time.
  const size_t kReadBufferSize = 1 << 16;  // 64KiB
  auto read_buffer = std::make_unique<char[]>(kReadBufferSize);

  if (final_log_file_.IsValid()) {
    // Truncate the final log file.
    TruncateFile(&final_log_file_);

    // Append the constants file.
    AppendToFileThenDelete(GetConstantsFilePath(), &final_log_file_,
                           read_buffer.get(), kReadBufferSize);

    // Iterate over the events files, from oldest to most recent, and append
    // them to the final destination. Note that "file numbers" start at 1 not 0.
    size_t end_filenumber = current_event_file_number_ + 1;
    size_t begin_filenumber =
        current_event_file_number_ <= total_num_event_files_
            ? 1
            : end_filenumber - total_num_event_files_;
    for (size_t filenumber = begin_filenumber; filenumber < end_filenumber;
         ++filenumber) {
      AppendToFileThenDelete(GetEventFilePath(FileNumberToIndex(filenumber)),
                             &final_log_file_, read_buffer.get(),
                             kReadBufferSize);
    }

    // Account for the final event line ending in a ",\n". Strip it to form
    // valid JSON.
    RewindIfWroteEventBytes(&final_log_file_);

    // Append the polled data.
    AppendToFileThenDelete(GetClosingFilePath(), &final_log_file_,
                           read_buffer.get(), kReadBufferSize);
  }

  // Delete the inprogress directory (and anything that may still be left inside
  // it).
  base::DeletePathRecursively(inprogress_dir_path_);
}

void FileNetLogObserver::FileWriter::CreateInprogressDirectory() {
  DCHECK(IsBoundedAndStitchable());

  // If an output file couldn't be created, either creation of intermediate
  // files will also fail (if they're in a sibling directory), or are they are
  // hidden somewhere the user would be unlikely to find them, so there is
  // little reason to progress.
  if (!final_log_file_.IsValid())
    return;

  if (!base::CreateDirectory(inprogress_dir_path_)) {
    LOG(WARNING) << "Failed creating directory: "
                 << inprogress_dir_path_.value();
    return;
  }

  // It is OK if the path is wrong due to encoding - this is really just a
  // convenience display for the user in understanding what the file means.
  std::string in_progress_path = inprogress_dir_path_.AsUTF8Unsafe();

  // Since |final_log_file_| will not be written to until the very end, leave
  // some data in it explaining that the real data is currently in the
  // .inprogress directory. This ordinarily won't be visible (overwritten when
  // stopping) however if logging does not end gracefully the comments are
  // useful for recovery.
  WriteToFile(
      &final_log_file_, "Logging is in progress writing data to:\n    ",
      in_progress_path,
      "\n\n"
      "That data will be stitched into a single file (this one) once logging\n"
      "has stopped.\n"
      "\n"
      "If logging was interrupted, you can stitch a NetLog file out of the\n"
      ".inprogress directory manually using:\n"
      "\n"
      "https://chromium.googlesource.com/chromium/src/+/main/net/tools/"
      "stitch_net_log_files.py\n");
}

std::string SerializeNetLogValueToJson(const base::ValueView& value) {
  // Omit trailing ".0" when printing a DOUBLE that is representable as a 64-bit
  // integer. This makes the values returned by NetLogNumberValue() look more
  // pleasant (for repre
```