Response:
Let's break down the thought process for analyzing the provided C++ code snippet, aiming to answer the user's request.

**1. Initial Scan and Keyword Identification:**

The first step is a quick read-through to identify key areas and concepts. I look for:

* **File name:** `perf-jit.cc` - immediately suggests a connection to performance monitoring and Just-In-Time (JIT) compilation.
* **Copyright and License:** Standard boilerplate, confirms it's part of the V8 project.
* **Includes:**  `src/diagnostics/perf-jit.h`, `src/flags/flags.h`, system headers like `<fcntl.h>`, `<sys/mman.h>`, `<unistd.h>`, and others related to V8 internals (`src/codegen/...`, `src/objects/...`). These give clues about the dependencies and purpose. The `#if V8_OS_LINUX` is crucial – it's Linux-specific.
* **Namespaces:** `v8::internal` - confirms this is internal V8 code.
* **Data Structures:** `PerfJitHeader`, `PerfJitBase`, `PerfJitCodeLoad`, `PerfJitDebugEntry`, `PerfJitCodeDebugInfo`, `PerfJitCodeUnwindingInfo`. These are clearly defined data formats for logging.
* **Class Name:** `LinuxPerfJitLogger`. This is the core class responsible for the logging functionality.
* **Methods:**  `OpenJitDumpFile`, `CloseJitDumpFile`, `LogRecordedBuffer`, `LogWriteDebugInfo`, `LogWriteUnwindingInfo`, `LogWriteHeader`, etc. These are the actions the logger performs.
* **Global Variables (static):** `process_id_`, `reference_count_`, `marker_address_`, `code_index_`, `perf_output_handle_`. These indicate shared state managed by the logger.
* **Conditional Compilation:** `#if V8_ENABLE_WEBASSEMBLY`. This highlights support for WebAssembly.
* **Constants:** `kMagic`, `kVersion`, `kFilenameFormatString`, etc. These are used for defining the log format.

**2. Understanding the Core Functionality:**

Based on the identified keywords and structures, the primary function becomes clear: **This code logs JIT-compiled code information to a file for use with the Linux `perf` tool.**

Key aspects supporting this conclusion:

* The "perf-jit" in the filename.
* The `PerfJit*` structures mirroring what `perf` likely expects for JIT data.
* The file operations (`open`, `close`, `write`).
* The mention of ELF headers (`kElfHeaderSize`).
* The specific Linux system calls (`mmap`, `unlink`).

**3. Dissecting Key Methods:**

Now, let's dive into the important methods to understand their specific roles:

* **`LinuxPerfJitLogger` (constructor/destructor):** Manages the lifecycle of the log file, opening it on the first instantiation and closing it on the last. The `reference_count_` ensures proper handling of multiple loggers.
* **`OpenJitDumpFile` / `CloseJitDumpFile`:** Handle the creation/deletion of the output file, including the logic for optional unlinking.
* **`LogRecordedBuffer` (multiple overloads):** The entry point for logging code. It handles both regular JavaScript code and WebAssembly code. It filters based on flags and calls other methods to write specific debug and unwinding information.
* **`LogWriteDebugInfo`:** Writes source code location information (filename, line number, column) for JIT-compiled functions. This is crucial for `perf` to map execution back to the source.
* **`LogWriteUnwindingInfo`:**  Writes information needed for stack unwinding, enabling `perf` to generate accurate call stacks.
* **`WriteJitCodeLoadEntry`:** Writes the core "load" event, indicating that a block of JIT-compiled code has been loaded into memory.
* **`LogWriteHeader`:** Writes the initial header to the log file, identifying it as a JIT dump.

**4. Addressing Specific User Questions:**

With a good understanding of the code's purpose and key methods, I can now address the user's specific questions:

* **Functionality:**  Summarize the findings from the previous steps. Emphasize the logging to a file for `perf`, the types of information logged (code loading, debug info, unwinding info), and its Linux-specific nature.
* **Torque Source:** Check the file extension. Since it's `.cc`, it's C++, not Torque.
* **Relationship to JavaScript:** Explain that while the code itself is C++, it directly deals with the output of the JavaScript JIT compiler. Provide a simple JavaScript example and explain how running it with the `--perf-prof` flag would trigger this code to log information about the compiled JavaScript.
* **Code Logic Inference (Hypothetical Input/Output):** Choose a simple scenario, like logging a single function. Outline the expected sequence of `PerfJit*` structures written to the file, including the header, code load event, and potentially debug/unwinding info. Provide example values.
* **Common Programming Errors:**  Think about typical issues that might arise:
    * **File access problems:** Permissions, incorrect paths.
    * **Configuration issues:**  Forgetting to enable the necessary flags.
    * **Understanding the output format:**  The logged data is not directly human-readable without `perf`.

**5. Structuring the Answer:**

Finally, organize the information clearly, using headings and bullet points to make it easy to read and understand. Provide concrete examples (like the JavaScript code and hypothetical log output) to illustrate the concepts. Be precise in the language, avoiding jargon where possible, and explaining technical terms when necessary. Emphasize the Linux dependency.
好的，让我们来分析一下 `v8/src/diagnostics/perf-jit.cc` 这个 V8 源代码文件的功能。

**主要功能：**

`v8/src/diagnostics/perf-jit.cc` 的主要功能是**将 V8 引擎中 JIT（Just-In-Time）编译生成的代码信息记录下来，以便 Linux 的 `perf` 工具进行性能分析。**

更具体地说，它实现了以下功能：

1. **生成 `perf` 可识别的 JIT 代码事件:**  这个文件定义了数据结构（例如 `PerfJitHeader`, `PerfJitCodeLoad`, `PerfJitDebugInfo` 等）来格式化 JIT 代码的相关信息，使其符合 `perf` 工具期望的格式。
2. **记录代码加载事件:**  当 V8 编译并加载新的 JavaScript 或 WebAssembly 代码时，它会记录代码的起始地址、大小、以及关联的名称（通常是函数名或脚本名）。
3. **记录调试信息 (可选):** 如果启用了 `--perf-prof` 标志，它还可以记录 JIT 代码与源代码位置的映射关系（行号、列号）。这使得 `perf` 能够将性能数据关联回原始的 JavaScript 代码行。
4. **记录栈展开信息 (可选):** 如果启用了 `--perf-prof-unwinding-info` 标志，它会记录栈展开所需的信息（例如 `.eh_frame` 数据），这有助于 `perf` 正确地生成调用栈信息。
5. **文件管理:**  它负责打开和关闭用于记录信息的转储文件（dump file），文件名格式通常是 `jit-<pid>.dump`。
6. **支持 WebAssembly (可选):** 如果启用了 `V8_ENABLE_WEBASSEMBLY`，它可以记录 WebAssembly 代码的相关信息。

**是否为 Torque 源代码：**

根据您提供的代码片段，`v8/src/diagnostics/perf-jit.cc` **不是**以 `.tq` 结尾的，因此它不是一个 V8 Torque 源代码文件。它是一个标准的 C++ 源代码文件。

**与 JavaScript 功能的关系及 JavaScript 示例：**

`v8/src/diagnostics/perf-jit.cc`  虽然是用 C++ 编写的，但它与 JavaScript 的执行性能密切相关。它的作用是记录 V8 引擎在执行 JavaScript 代码时动态生成的机器码信息。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

for (let i = 0; i < 10000; i++) {
  add(i, i + 1);
}
```

**说明:**

当 V8 引擎执行这段 JavaScript 代码时，`add` 函数最初可能会被解释执行。但随着 `add` 函数被频繁调用（例如在循环中），V8 的 JIT 编译器 (如 TurboFan 或 Crankshaft) 会将其编译成优化的机器码以提高执行速度。

`v8/src/diagnostics/perf-jit.cc` 的代码会在 JIT 编译器生成 `add` 函数的机器码后，记录以下信息到转储文件中：

* **代码加载事件:**  记录了 `add` 函数生成的机器码的起始内存地址、大小，以及函数名 "add"。
* **调试信息 (如果启用):**  记录了机器码指令与 `add` 函数源代码中 `return a + b;` 这一行的对应关系（行号、列号）。

然后，你可以使用 Linux 的 `perf` 工具来分析这个转储文件，例如：

```bash
perf inject -j -i jit-<pid>.dump
perf report
```

`perf report` 会显示性能分析结果，并且如果记录了调试信息，你将能够看到性能瓶颈在 JavaScript 代码的哪一行。

**代码逻辑推理（假设输入与输出）：**

假设我们运行以下 JavaScript 代码，并启用了 `--perf-prof` 标志：

```javascript
function multiply(x, y) {
  return x * y;
}

multiply(5, 10);
```

**假设输入：**

* V8 引擎开始执行上述 JavaScript 代码。
* JIT 编译器编译了 `multiply` 函数。
* `--perf-prof` 标志已启用。

**可能的输出 (简化版)：**

转储文件中可能会写入以下信息（以伪代码表示）：

1. **PerfJitHeader:**  包含魔数、版本号、时间戳等元数据。
2. **PerfJitCodeLoad:**
   * `event_`: `kLoad`
   * `code_address_`:  `multiply` 函数机器码的起始地址 (例如 `0x7f...`)
   * `code_size_`: `multiply` 函数机器码的大小 (例如 `128`)
   * `name`: "multiply"
3. **PerfJitCodeDebugInfo:**
   * `event_`: `kDebugInfo`
   * `address_`: `multiply` 函数机器码的起始地址 (与上面相同)
   * `entry_count_`: 1 (假设只有一个源代码位置条目)
   * **PerfJitDebugEntry:**
     * `address_`:  `multiply` 函数机器码中与 `return x * y;` 对应的指令地址
     * `line_number_`:  `multiply` 函数定义中的行号 (例如 2)
     * `column_`: `return x * y;`  中 `return` 的列号 (例如 3)
     * 后面跟着脚本文件名（如果可用）。

**涉及用户常见的编程错误及示例：**

`v8/src/diagnostics/perf-jit.cc` 本身是一个 V8 内部的诊断工具，用户直接与之交互的可能性很小。然而，理解它的功能可以帮助开发者在使用 `perf` 分析 Node.js 或 Chrome 等 V8 应用时，更好地理解性能数据。

**常见的编程错误（与 `perf` 分析相关）：**

1. **忘记启用 `--perf-prof` 标志:**  如果在使用 `perf` 时没有启用 V8 的性能分析标志，`perf` 将无法获取到 JIT 代码的详细信息，性能报告可能不够准确或完整。

   **示例 (Node.js):**
   ```bash
   # 错误：没有启用 --perf-prof
   perf record -F 99 -p $(pidof node) -g -- node my_app.js
   perf report # 结果可能缺少 JIT 代码信息

   # 正确：启用 --perf-prof
   node --perf-prof my_app.js
   # 或者
   perf record -F 99 -p $(pidof node) -g -- node --perf-prof my_app.js
   perf inject -j -i perf.data
   perf report
   ```

2. **不理解 `perf inject` 的作用:**  `perf inject` 命令用于将 V8 生成的 JIT 代码信息注入到 `perf.data` 文件中，使得 `perf report` 能够正确地解析和展示这些信息。如果忘记执行 `perf inject`，性能报告可能无法正确关联到 JavaScript 源代码。

3. **在不合适的场景下使用性能分析:**  过早地进行性能优化或分析可能浪费时间。应该先确保代码功能正确，再针对性能瓶颈进行分析。

4. **误解性能分析结果:**  性能分析工具提供的数据需要仔细解读。例如，高 CPU 使用率可能并不总是意味着代码存在性能问题，可能只是因为程序正在执行大量计算密集型任务。

总而言之，`v8/src/diagnostics/perf-jit.cc` 是 V8 引擎中一个关键的组件，它为使用 Linux `perf` 工具进行 JavaScript 和 WebAssembly 代码的性能分析提供了必要的基础设施。理解它的功能有助于开发者更有效地诊断和优化他们的 V8 应用。

### 提示词
```
这是目录为v8/src/diagnostics/perf-jit.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/perf-jit.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "src/diagnostics/perf-jit.h"

#include "src/common/assert-scope.h"
#include "src/flags/flags.h"

// Only compile the {LinuxPerfJitLogger} on Linux.
#if V8_OS_LINUX

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <memory>

#include "src/base/platform/wrappers.h"
#include "src/codegen/assembler.h"
#include "src/codegen/source-position-table.h"
#include "src/diagnostics/eh-frame.h"
#include "src/objects/code-kind.h"
#include "src/objects/objects-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/utils/ostreams.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-code-manager.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

base::LazyRecursiveMutex& GetFileMutex() {
  static base::LazyRecursiveMutex file_mutex;
  return file_mutex;
}

struct PerfJitHeader {
  uint32_t magic_;
  uint32_t version_;
  uint32_t size_;
  uint32_t elf_mach_target_;
  uint32_t reserved_;
  uint32_t process_id_;
  uint64_t time_stamp_;
  uint64_t flags_;

  static const uint32_t kMagic = 0x4A695444;
  static const uint32_t kVersion = 1;
};

struct PerfJitBase {
  enum PerfJitEvent {
    kLoad = 0,
    kMove = 1,
    kDebugInfo = 2,
    kClose = 3,
    kUnwindingInfo = 4
  };

  uint32_t event_;
  uint32_t size_;
  uint64_t time_stamp_;
};

struct PerfJitCodeLoad : PerfJitBase {
  uint32_t process_id_;
  uint32_t thread_id_;
  uint64_t vma_;
  uint64_t code_address_;
  uint64_t code_size_;
  uint64_t code_id_;
};

struct PerfJitDebugEntry {
  uint64_t address_;
  int line_number_;
  int column_;
  // Followed by null-terminated name or \0xFF\0 if same as previous.
};

struct PerfJitCodeDebugInfo : PerfJitBase {
  uint64_t address_;
  uint64_t entry_count_;
  // Followed by entry_count_ instances of PerfJitDebugEntry.
};

struct PerfJitCodeUnwindingInfo : PerfJitBase {
  uint64_t unwinding_size_;
  uint64_t eh_frame_hdr_size_;
  uint64_t mapped_size_;
  // Followed by size_ - sizeof(PerfJitCodeUnwindingInfo) bytes of data.
};

const char LinuxPerfJitLogger::kFilenameFormatString[] = "%s/jit-%d.dump";

// Extra padding for the PID in the filename
const int LinuxPerfJitLogger::kFilenameBufferPadding = 16;

static const char kStringTerminator[] = {'\0'};

// The following static variables are protected by
// GetFileMutex().
int LinuxPerfJitLogger::process_id_ = 0;
uint64_t LinuxPerfJitLogger::reference_count_ = 0;
void* LinuxPerfJitLogger::marker_address_ = nullptr;
uint64_t LinuxPerfJitLogger::code_index_ = 0;
FILE* LinuxPerfJitLogger::perf_output_handle_ = nullptr;

void LinuxPerfJitLogger::OpenJitDumpFile() {
  // Open the perf JIT dump file.
  perf_output_handle_ = nullptr;

  size_t bufferSize = strlen(v8_flags.perf_prof_path) +
                      sizeof(kFilenameFormatString) + kFilenameBufferPadding;
  base::ScopedVector<char> perf_dump_name(bufferSize);
  int size = SNPrintF(perf_dump_name, kFilenameFormatString,
                      v8_flags.perf_prof_path.value(), process_id_);
  CHECK_NE(size, -1);

  int fd = open(perf_dump_name.begin(), O_CREAT | O_TRUNC | O_RDWR, 0666);
  if (fd == -1) return;

  // If --perf-prof-delete-file is given, unlink the file right after opening
  // it. This keeps the file handle to the file valid. This only works on Linux,
  // which is the only platform supported for --perf-prof anyway.
  if (v8_flags.perf_prof_delete_file)
    CHECK_EQ(0, unlink(perf_dump_name.begin()));

  marker_address_ = OpenMarkerFile(fd);
  if (marker_address_ == nullptr) return;

  perf_output_handle_ = fdopen(fd, "w+");
  if (perf_output_handle_ == nullptr) return;

  setvbuf(perf_output_handle_, nullptr, _IOFBF, kLogBufferSize);
}

void LinuxPerfJitLogger::CloseJitDumpFile() {
  if (perf_output_handle_ == nullptr) return;
  base::Fclose(perf_output_handle_);
  perf_output_handle_ = nullptr;
}

void* LinuxPerfJitLogger::OpenMarkerFile(int fd) {
  long page_size = sysconf(_SC_PAGESIZE);  // NOLINT(runtime/int)
  if (page_size == -1) return nullptr;

  // Mmap the file so that there is a mmap record in the perf_data file.
  //
  // The map must be PROT_EXEC to ensure it is not ignored by perf record.
  void* marker_address =
      mmap(nullptr, page_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
  return (marker_address == MAP_FAILED) ? nullptr : marker_address;
}

void LinuxPerfJitLogger::CloseMarkerFile(void* marker_address) {
  if (marker_address == nullptr) return;
  long page_size = sysconf(_SC_PAGESIZE);  // NOLINT(runtime/int)
  if (page_size == -1) return;
  munmap(marker_address, page_size);
}

LinuxPerfJitLogger::LinuxPerfJitLogger(Isolate* isolate)
    : CodeEventLogger(isolate) {
  base::LockGuard<base::RecursiveMutex> guard_file(GetFileMutex().Pointer());
  process_id_ = base::OS::GetCurrentProcessId();

  reference_count_++;
  // If this is the first logger, open the file and write the header.
  if (reference_count_ == 1) {
    OpenJitDumpFile();
    if (perf_output_handle_ == nullptr) return;
    LogWriteHeader();
  }
}

LinuxPerfJitLogger::~LinuxPerfJitLogger() {
  base::LockGuard<base::RecursiveMutex> guard_file(GetFileMutex().Pointer());

  reference_count_--;
  // If this was the last logger, close the file.
  if (reference_count_ == 0) {
    CloseJitDumpFile();
  }
}

uint64_t LinuxPerfJitLogger::GetTimestamp() {
  struct timespec ts;
  int result = clock_gettime(CLOCK_MONOTONIC, &ts);
  DCHECK_EQ(0, result);
  USE(result);
  static const uint64_t kNsecPerSec = 1000000000;
  return (ts.tv_sec * kNsecPerSec) + ts.tv_nsec;
}

void LinuxPerfJitLogger::LogRecordedBuffer(
    Tagged<AbstractCode> abstract_code,
    MaybeHandle<SharedFunctionInfo> maybe_sfi, const char* name,
    size_t length) {
  DisallowGarbageCollection no_gc;
  if (v8_flags.perf_basic_prof_only_functions) {
    CodeKind code_kind = abstract_code->kind(isolate_);
    if (!CodeKindIsJSFunction(code_kind)) {
      return;
    }
  }

  base::LockGuard<base::RecursiveMutex> guard_file(GetFileMutex().Pointer());

  if (perf_output_handle_ == nullptr) return;

  // We only support non-interpreted functions.
  if (!IsCode(abstract_code, isolate_)) return;
  Tagged<Code> code = Cast<Code>(abstract_code);

  // Debug info has to be emitted first.
  Handle<SharedFunctionInfo> sfi;
  if (v8_flags.perf_prof && maybe_sfi.ToHandle(&sfi)) {
    // TODO(herhut): This currently breaks for js2wasm/wasm2js functions.
    CodeKind kind = code->kind();
    if (kind != CodeKind::JS_TO_WASM_FUNCTION &&
        kind != CodeKind::WASM_TO_JS_FUNCTION) {
      DCHECK_IMPLIES(IsScript(sfi->script()),
                     Cast<Script>(sfi->script())->has_line_ends());
      LogWriteDebugInfo(code, sfi);
    }
  }

  const char* code_name = name;
  uint8_t* code_pointer = reinterpret_cast<uint8_t*>(code->instruction_start());

  // Unwinding info comes right after debug info.
  if (v8_flags.perf_prof_unwinding_info) LogWriteUnwindingInfo(code);

  WriteJitCodeLoadEntry(code_pointer, code->instruction_size(), code_name,
                        length);
}

#if V8_ENABLE_WEBASSEMBLY
void LinuxPerfJitLogger::LogRecordedBuffer(const wasm::WasmCode* code,
                                           const char* name, size_t length) {
  base::LockGuard<base::RecursiveMutex> guard_file(GetFileMutex().Pointer());

  if (perf_output_handle_ == nullptr) return;

  if (v8_flags.perf_prof_annotate_wasm) LogWriteDebugInfo(code);

  WriteJitCodeLoadEntry(code->instructions().begin(),
                        code->instructions().length(), name, length);
}
#endif  // V8_ENABLE_WEBASSEMBLY

void LinuxPerfJitLogger::WriteJitCodeLoadEntry(const uint8_t* code_pointer,
                                               uint32_t code_size,
                                               const char* name,
                                               size_t name_length) {
  PerfJitCodeLoad code_load;
  code_load.event_ = PerfJitCodeLoad::kLoad;
  code_load.size_ =
      static_cast<uint32_t>(sizeof(code_load) + name_length + 1 + code_size);
  code_load.time_stamp_ = GetTimestamp();
  code_load.process_id_ = static_cast<uint32_t>(process_id_);
  code_load.thread_id_ = static_cast<uint32_t>(base::OS::GetCurrentThreadId());
  code_load.vma_ = reinterpret_cast<uint64_t>(code_pointer);
  code_load.code_address_ = reinterpret_cast<uint64_t>(code_pointer);
  code_load.code_size_ = code_size;
  code_load.code_id_ = code_index_;

  code_index_++;

  LogWriteBytes(reinterpret_cast<const char*>(&code_load), sizeof(code_load));
  LogWriteBytes(name, name_length);
  LogWriteBytes(kStringTerminator, sizeof(kStringTerminator));
  LogWriteBytes(reinterpret_cast<const char*>(code_pointer), code_size);
}

namespace {

constexpr char kUnknownScriptNameString[] = "<unknown>";
constexpr size_t kUnknownScriptNameStringLen =
    arraysize(kUnknownScriptNameString) - 1;

namespace {
base::Vector<const char> GetScriptName(Tagged<Object> maybeScript,
                                       std::unique_ptr<char[]>* storage,
                                       const DisallowGarbageCollection& no_gc) {
  if (IsScript(maybeScript)) {
    Tagged<Object> name_or_url =
        Cast<Script>(maybeScript)->GetNameOrSourceURL();
    if (IsSeqOneByteString(name_or_url)) {
      Tagged<SeqOneByteString> str = Cast<SeqOneByteString>(name_or_url);
      return {reinterpret_cast<char*>(str->GetChars(no_gc)),
              static_cast<size_t>(str->length())};
    } else if (IsString(name_or_url)) {
      size_t length;
      *storage = Cast<String>(name_or_url)->ToCString(&length);
      return {storage->get(), length};
    }
  }
  return {kUnknownScriptNameString, kUnknownScriptNameStringLen};
}

}  // namespace

SourcePositionInfo GetSourcePositionInfo(Isolate* isolate, Tagged<Code> code,
                                         Handle<SharedFunctionInfo> function,
                                         SourcePosition pos) {
  DisallowGarbageCollection disallow;
  if (code->is_turbofanned()) {
    return pos.FirstInfo(isolate, code);
  } else {
    return SourcePositionInfo(isolate, pos, function);
  }
}

}  // namespace

void LinuxPerfJitLogger::LogWriteDebugInfo(Tagged<Code> code,
                                           Handle<SharedFunctionInfo> shared) {
  // Line ends of all scripts have been initialized prior to this.
  DisallowGarbageCollection no_gc;
  // The WasmToJS wrapper stubs have source position entries.
  Tagged<SharedFunctionInfo> raw_shared = *shared;
  if (!raw_shared->HasSourceCode()) return;

  PerfJitCodeDebugInfo debug_info;
  uint32_t size = sizeof(debug_info);

  Tagged<TrustedByteArray> source_position_table =
      code->SourcePositionTable(isolate_, raw_shared);
  // Compute the entry count and get the names of all scripts.
  // Avoid additional work if the script name is repeated. Multiple script
  // names only occur for cross-script inlining.
  uint32_t entry_count = 0;
  Tagged<Object> last_script = Smi::zero();
  size_t last_script_name_size = 0;
  std::vector<base::Vector<const char>> script_names;
  for (SourcePositionTableIterator iterator(source_position_table);
       !iterator.done(); iterator.Advance()) {
    SourcePositionInfo info(GetSourcePositionInfo(isolate_, code, shared,
                                                  iterator.source_position()));
    Tagged<Object> current_script = *info.script;
    if (current_script != last_script) {
      std::unique_ptr<char[]> name_storage;
      auto name = GetScriptName(raw_shared->script(), &name_storage, no_gc);
      script_names.push_back(name);
      // Add the size of the name after each entry.
      last_script_name_size = name.size() + sizeof(kStringTerminator);
      size += last_script_name_size;
      last_script = current_script;
    } else {
      DCHECK_LT(0, last_script_name_size);
      size += last_script_name_size;
    }
    entry_count++;
  }
  if (entry_count == 0) return;

  debug_info.event_ = PerfJitCodeLoad::kDebugInfo;
  debug_info.time_stamp_ = GetTimestamp();
  debug_info.address_ = code->instruction_start();
  debug_info.entry_count_ = entry_count;

  // Add the sizes of fixed parts of entries.
  size += entry_count * sizeof(PerfJitDebugEntry);

  int padding = ((size + 7) & (~7)) - size;
  debug_info.size_ = size + padding;
  LogWriteBytes(reinterpret_cast<const char*>(&debug_info), sizeof(debug_info));

  Address code_start = code->instruction_start();

  last_script = Smi::zero();
  int script_names_index = 0;
  for (SourcePositionTableIterator iterator(source_position_table);
       !iterator.done(); iterator.Advance()) {
    SourcePositionInfo info(GetSourcePositionInfo(isolate_, code, shared,
                                                  iterator.source_position()));
    PerfJitDebugEntry entry;
    // The entry point of the function will be placed straight after the ELF
    // header when processed by "perf inject". Adjust the position addresses
    // accordingly.
    entry.address_ = code_start + iterator.code_offset() + kElfHeaderSize;
    entry.line_number_ = info.line + 1;
    entry.column_ = info.column + 1;
    LogWriteBytes(reinterpret_cast<const char*>(&entry), sizeof(entry));
    Tagged<Object> current_script = *info.script;
    auto name_string = script_names[script_names_index];
    LogWriteBytes(name_string.begin(), name_string.size());
    LogWriteBytes(kStringTerminator, sizeof(kStringTerminator));
    if (current_script != last_script) {
      if (last_script != Smi::zero()) script_names_index++;
      last_script = current_script;
    }
  }
  char padding_bytes[8] = {0};
  LogWriteBytes(padding_bytes, padding);
}

#if V8_ENABLE_WEBASSEMBLY
void LinuxPerfJitLogger::LogWriteDebugInfo(const wasm::WasmCode* code) {
  if (code->IsAnonymous()) {
    return;
  }

  wasm::WasmModuleSourceMap* source_map =
      code->native_module()->GetWasmSourceMap();
  wasm::WireBytesRef code_ref =
      code->native_module()->module()->functions[code->index()].code;
  uint32_t code_offset = code_ref.offset();
  uint32_t code_end_offset = code_ref.end_offset();

  uint32_t entry_count = 0;
  uint32_t size = 0;

  if (!source_map || !source_map->IsValid() ||
      !source_map->HasSource(code_offset, code_end_offset)) {
    return;
  }

  for (SourcePositionTableIterator iterator(code->source_positions());
       !iterator.done(); iterator.Advance()) {
    uint32_t offset = iterator.source_position().ScriptOffset() + code_offset;
    if (!source_map->HasValidEntry(code_offset, offset)) continue;
    entry_count++;
    size += source_map->GetFilename(offset).size() + 1;
  }

  if (entry_count == 0) return;

  PerfJitCodeDebugInfo debug_info;

  debug_info.event_ = PerfJitCodeLoad::kDebugInfo;
  debug_info.time_stamp_ = GetTimestamp();
  debug_info.address_ =
      reinterpret_cast<uintptr_t>(code->instructions().begin());
  debug_info.entry_count_ = entry_count;

  size += sizeof(debug_info);
  // Add the sizes of fixed parts of entries.
  size += entry_count * sizeof(PerfJitDebugEntry);

  int padding = ((size + 7) & (~7)) - size;
  debug_info.size_ = size + padding;
  LogWriteBytes(reinterpret_cast<const char*>(&debug_info), sizeof(debug_info));

  uintptr_t code_begin =
      reinterpret_cast<uintptr_t>(code->instructions().begin());

  for (SourcePositionTableIterator iterator(code->source_positions());
       !iterator.done(); iterator.Advance()) {
    uint32_t offset = iterator.source_position().ScriptOffset() + code_offset;
    if (!source_map->HasValidEntry(code_offset, offset)) continue;
    PerfJitDebugEntry entry;
    // The entry point of the function will be placed straight after the ELF
    // header when processed by "perf inject". Adjust the position addresses
    // accordingly.
    entry.address_ = code_begin + iterator.code_offset() + kElfHeaderSize;
    entry.line_number_ =
        static_cast<int>(source_map->GetSourceLine(offset)) + 1;
    entry.column_ = 1;
    LogWriteBytes(reinterpret_cast<const char*>(&entry), sizeof(entry));
    std::string name_string = source_map->GetFilename(offset);
    LogWriteBytes(name_string.c_str(), name_string.size());
    LogWriteBytes(kStringTerminator, sizeof(kStringTerminator));
  }

  char padding_bytes[8] = {0};
  LogWriteBytes(padding_bytes, padding);
}
#endif  // V8_ENABLE_WEBASSEMBLY

void LinuxPerfJitLogger::LogWriteUnwindingInfo(Tagged<Code> code) {
  PerfJitCodeUnwindingInfo unwinding_info_header;
  unwinding_info_header.event_ = PerfJitCodeLoad::kUnwindingInfo;
  unwinding_info_header.time_stamp_ = GetTimestamp();
  unwinding_info_header.eh_frame_hdr_size_ = EhFrameConstants::kEhFrameHdrSize;

  if (code->has_unwinding_info()) {
    unwinding_info_header.unwinding_size_ = code->unwinding_info_size();
    unwinding_info_header.mapped_size_ = unwinding_info_header.unwinding_size_;
  } else {
    unwinding_info_header.unwinding_size_ = EhFrameConstants::kEhFrameHdrSize;
    unwinding_info_header.mapped_size_ = 0;
  }

  int content_size = static_cast<int>(sizeof(unwinding_info_header) +
                                      unwinding_info_header.unwinding_size_);
  int padding_size = RoundUp(content_size, 8) - content_size;
  unwinding_info_header.size_ = content_size + padding_size;

  LogWriteBytes(reinterpret_cast<const char*>(&unwinding_info_header),
                sizeof(unwinding_info_header));

  if (code->has_unwinding_info()) {
    LogWriteBytes(reinterpret_cast<const char*>(code->unwinding_info_start()),
                  code->unwinding_info_size());
  } else {
    OFStream perf_output_stream(perf_output_handle_);
    EhFrameWriter::WriteEmptyEhFrame(perf_output_stream);
  }

  char padding_bytes[] = "\0\0\0\0\0\0\0\0";
  DCHECK_LT(padding_size, static_cast<int>(sizeof(padding_bytes)));
  LogWriteBytes(padding_bytes, padding_size);
}

void LinuxPerfJitLogger::LogWriteBytes(const char* bytes, size_t size) {
  size_t rv = fwrite(bytes, 1, size, perf_output_handle_);
  DCHECK_EQ(size, rv);
  USE(rv);
}

void LinuxPerfJitLogger::LogWriteHeader() {
  DCHECK_NOT_NULL(perf_output_handle_);
  PerfJitHeader header;

  header.magic_ = PerfJitHeader::kMagic;
  header.version_ = PerfJitHeader::kVersion;
  header.size_ = sizeof(header);
  header.elf_mach_target_ = GetElfMach();
  header.reserved_ = 0xDEADBEEF;
  header.process_id_ = process_id_;
  header.time_stamp_ = static_cast<uint64_t>(
      V8::GetCurrentPlatform()->CurrentClockTimeMillisecondsHighResolution() *
      base::Time::kMicrosecondsPerMillisecond);
  header.flags_ = 0;

  LogWriteBytes(reinterpret_cast<const char*>(&header), sizeof(header));
}

}  // namespace internal
}  // namespace v8

#endif  // V8_OS_LINUX
```