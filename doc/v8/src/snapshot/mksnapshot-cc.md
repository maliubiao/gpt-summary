Response:
Let's break down the thought process to analyze the `mksnapshot.cc` code.

1. **Understand the Goal:** The first step is to grasp the fundamental purpose of this file. The directory name `v8/src/snapshot` and the filename `mksnapshot.cc` strongly suggest that this code is involved in creating snapshots within the V8 JavaScript engine. The `mk` prefix often signifies a "make" or "creation" utility.

2. **Initial Code Scan (High-Level):**  Quickly skim the includes and the main function. Notice includes like `snapshot.h`, `embedded-file-writer.h`, `v8-initialization.h`, and `libplatform/libplatform.h`. These confirm the snapshot creation aspect and interaction with the V8 platform. The `main` function is the entry point, so its structure will be key.

3. **Identify Key Components:** Look for distinct classes or major sections within `main`. The `SnapshotFileWriter` class stands out immediately. Its methods like `SetSnapshotFile`, `SetStartupBlobFile`, and `WriteSnapshot` clearly indicate its role in managing the output files. The `GetExtraCode`, `CreateSnapshotDataBlob`, and `WarmUpSnapshotDataBlob` functions suggest the different stages of snapshot creation.

4. **Analyze `SnapshotFileWriter`:**  Focus on the methods within this class.
    * `SetSnapshotFile` and `SetStartupBlobFile`: Store file paths.
    * `WriteSnapshot`: The core function. It calls `MaybeWriteSnapshotFile` and `MaybeWriteStartupBlob`.
    * `MaybeWriteStartupBlob`: Writes the raw snapshot data to a `.blob` file. Includes error handling if writing fails.
    * `MaybeWriteSnapshotFile`: Writes a C++ source file (`.cpp`) containing the snapshot data as a `uint8_t` array. It also includes boilerplate code for including headers and defining the `Snapshot::DefaultSnapshotBlob` function. Notice the `WriteSnapshotFilePrefix`, `WriteSnapshotFileData`, and `WriteSnapshotFileSuffix` helpers.
    * `WriteBinaryContentsAsCArray`: Converts the binary blob data into a C array format.
    * `GetFileDescriptorOrDie`:  A utility function for opening files with error handling.

5. **Analyze Snapshot Creation Functions:**
    * `GetExtraCode`: Loads JavaScript code from a file. This is likely the user-provided script to be included in the snapshot.
    * `CreateSnapshotDataBlob`:  The core logic for generating the initial snapshot. It uses `i::CreateSnapshotDataBlobInternal`. The "cold" snapshot.
    * `WarmUpSnapshotDataBlob`: Takes an existing snapshot and runs additional code to "warm it up." This optimizes the snapshot for specific use cases. Uses `i::WarmUpSnapshotDataBlobInternal`.

6. **Analyze `main` Function Flow:**
    * **Initialization:** Sets up flags, initializes the V8 platform and ICU.
    * **SnapshotFileWriter Setup:** Creates and configures the `SnapshotFileWriter` with output file paths.
    * **EmbeddedFileWriter Setup:**  Handles embedding built-in code.
    * **Loading Scripts:** Loads embedding and warmup scripts using `GetExtraCode`.
    * **Snapshot Creation (Cold):** Creates the initial snapshot using `CreateSnapshotDataBlob`.
    * **Optional Warmup:** If a warmup script is provided, it warms up the snapshot using `WarmUpSnapshotDataBlob`.
    * **Writing Snapshot:**  Writes the generated snapshot data to the specified files using `snapshot_writer.WriteSnapshot`.
    * **Cleanup:** Disposes of V8 resources.

7. **Connect to JavaScript:**  Recognize that the loaded scripts (`embed_script`, `warmup_script`) are JavaScript code. This code defines the initial state of the V8 heap that gets captured in the snapshot. Think of simple JavaScript examples that would create objects or define functions that would then be part of the snapshot.

8. **Infer Functionality and Purpose:** Based on the code analysis, the primary function is to create snapshot files (`.blob` and `.cpp`) that represent a pre-initialized state of the V8 engine. This can significantly speed up V8 startup time.

9. **Consider Edge Cases and Error Handling:** Note the error handling in `GetFileDescriptorOrDie` and the file writing functions. The comment about potential file corruption during crashes is also important.

10. **Address Specific Questions:** Now, go through each part of the prompt systematically:
    * **Functionality:** Summarize the core actions.
    * **`.tq` extension:**  State that it's not a Torque file.
    * **Relationship to JavaScript:** Explain how the loaded scripts define the snapshot's state and provide examples.
    * **Code Logic and I/O:**  Describe the file writing process, including prefixes, data, and suffixes. Provide a simple input (like file paths) and the expected output (the generated files).
    * **Common Programming Errors:** Think about mistakes users might make when using a tool like this, such as incorrect file paths or providing invalid JavaScript.

11. **Refine and Organize:**  Structure the answer clearly, using headings and bullet points for better readability. Ensure that the explanation flows logically.

By following these steps, one can dissect the provided C++ code, understand its purpose within the V8 project, and answer the specific questions in the prompt effectively. The key is to start with a high-level understanding and progressively drill down into the details of the code.
`v8/src/snapshot/mksnapshot.cc` 是 V8 JavaScript 引擎的一个源代码文件，它的主要功能是 **生成 V8 引擎的启动快照 (snapshot)**。

**功能详细说明:**

1. **读取和处理输入:**
   - 接收命令行参数，包括用于初始化的 JavaScript 代码文件 (`--startup-src`)，用于生成二进制快照数据的文件 (`--startup-blob`)，以及其他可选的脚本文件（例如，用于嵌入或预热快照的代码）。
   - 使用 `GetExtraCode` 函数读取这些脚本文件的内容。

2. **创建和配置 V8 Isolate:**
   - 创建一个 V8 Isolate 实例，这是 V8 引擎的独立执行环境。
   - 配置 Isolate 的一些特性，例如禁用 IC (Inline Caches) 以避免快照生成过程中的问题。
   - 设置代码范围限制，以便在快照中实现内置函数的相对跳转。

3. **生成快照数据 (核心功能):**
   - 使用 `v8::SnapshotCreator` 类来创建快照。
   - 调用 `CreateSnapshotDataBlob` 函数，该函数内部会执行提供的 JavaScript 代码 (`embed_script`)，并将其执行后的堆状态序列化成快照数据。
   - `CreateSnapshotDataBlob` 内部调用了 `i::CreateSnapshotDataBlobInternal`，这是 V8 内部生成快照数据的核心函数。
   - 如果指定了 `--embedded-src`，还会生成嵌入式代码的快照。

4. **可选的快照预热:**
   - 如果提供了预热脚本 (`warmup_script`)，会调用 `WarmUpSnapshotDataBlob` 函数。
   - `WarmUpSnapshotDataBlob` 会基于已有的快照数据，执行预热脚本，并生成一个新的、经过预热的快照。预热的目的是在快照创建时执行一些操作，使得引擎启动后性能更好。

5. **将快照数据写入文件:**
   - 使用 `SnapshotFileWriter` 类将生成的快照数据写入到指定的文件中。
   - 可以写入两个文件：
     - **C++ 头文件 (`.cpp`)**: 包含一个 `blob_data` 数组，该数组以 C 数组的形式存储了快照的二进制数据。同时包含一些辅助代码，用于将该数据转换为 `v8::StartupData` 结构。
     - **二进制文件 (`.blob`)**: 直接存储快照的原始二进制数据。

6. **处理嵌入式代码 (Embedded Code):**
   - 使用 `EmbeddedFileWriter` 类处理嵌入式代码。
   - 嵌入式代码通常是 V8 引擎内置的 JavaScript 代码或数据。

7. **静态根 (Static Roots) 生成 (可选):**
   - 如果启用了静态根生成 (`V8_STATIC_ROOTS_GENERATION_BOOL`) 并且提供了 `--static-roots-src` 参数，则会生成静态根表。静态根是 V8 堆中一些重要对象的固定位置，可以优化快照的反序列化。

**关于文件扩展名和 Torque:**

如果 `v8/src/snapshot/mksnapshot.cc` 的文件名以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是 V8 使用的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现内置函数。

**当前情况分析:**

由于提供的文件内容是 `.cc` 结尾，所以 **`v8/src/snapshot/mksnapshot.cc` 是一个 C++ 源代码文件**，而不是 Torque 文件。

**与 JavaScript 的关系及示例:**

`mksnapshot.cc` 的核心功能是为 V8 引擎创建启动快照，而启动快照本质上是 V8 堆的一个序列化状态，包含了预先编译的代码、对象和其他数据。这个快照可以直接用于初始化 V8 Isolate，从而大大缩短启动时间。

与 JavaScript 的关系在于：**`mksnapshot.cc` 通过执行 JavaScript 代码来生成快照**。

**JavaScript 示例:**

假设我们有一个 JavaScript 文件 `startup.js`，内容如下：

```javascript
// startup.js
globalThis.myGlobalVariable = { message: "Hello from snapshot!" };

function greet(name) {
  return `Hello, ${name}!`;
}

globalThis.greetFunction = greet;
```

在运行 `mksnapshot` 时，我们可以将 `startup.js` 作为输入：

```bash
out/x64.debug/obj/tools/mksnapshot --startup-src=snapshot.cc --startup-blob=snapshot.blob startup.js
```

`mksnapshot.cc` 会读取 `startup.js` 的内容，在一个临时的 V8 Isolate 中执行这段代码，然后将执行后的堆状态（包括 `myGlobalVariable` 和 `greetFunction` 的定义）保存到 `snapshot.cc` 和 `snapshot.blob` 文件中。

当 V8 引擎启动时，如果加载了这个快照，那么 `globalThis.myGlobalVariable` 和 `globalThis.greetFunction` 就会被预先定义好，可以直接使用：

```javascript
// 在加载了快照的 V8 环境中
console.log(myGlobalVariable.message); // 输出: Hello from snapshot!
console.log(greetFunction("World"));   // 输出: Hello, World!
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

- 命令行参数: `--startup-src=my_snapshot.cc --startup-blob=my_snapshot.blob init.js`
- `init.js` 内容:
  ```javascript
  const initialValue = 100;
  globalThis.startValue = initialValue * 2;
  ```

**预期输出:**

- **`my_snapshot.cc` 文件内容 (部分):**
  ```c++
  // Autogenerated snapshot file. Do not edit.

  #include "src/init/v8.h"
  #include "src/base/platform/platform.h"

  #include "src/flags/flags.h"
  #include "src/snapshot/snapshot.h"

  namespace v8 {
  namespace internal {

  alignas(kPointerAlignment) static const uint8_t blob_data[] = {
  // ... 这里是快照数据的二进制表示 ...
  };
  static const int blob_size = /* 快照数据的大小 */;
  static const v8::StartupData blob =
  { (const char*) blob_data, blob_size };

  const v8::StartupData* Snapshot::DefaultSnapshotBlob() {
    return &blob;
  }

  bool Snapshot::ShouldVerifyChecksum(const v8::StartupData* data) {
    return v8_flags.verify_snapshot_checksum;
  }
  }  // namespace internal
  }  // namespace v8
  ```
  `blob_data` 数组中会包含 `globalThis.startValue` 被设置为 `200` 的状态信息。

- **`my_snapshot.blob` 文件内容:**
  - 该文件将包含 `blob_data` 数组的原始二进制数据。

**涉及用户常见的编程错误:**

1. **文件路径错误:** 在命令行中提供的 `--startup-src`，`--startup-blob` 或其他脚本文件的路径可能不存在或不正确。这会导致 `mksnapshot` 无法打开或写入文件，从而报错退出。

   **示例:**
   ```bash
   out/x64.debug/obj/tools/mksnapshot --startup-src=nonexistent_snapshot.cc ...
   ```
   `mksnapshot` 会输出类似 "Unable to open file" 的错误信息。

2. **JavaScript 代码错误:** `mksnapshot` 在生成快照时会执行提供的 JavaScript 代码。如果这些代码包含语法错误或运行时错误，会导致快照生成失败。

   **示例:**
   假设 `init.js` 内容如下：
   ```javascript
   const a = ; // 语法错误
   ```
   运行 `mksnapshot` 会导致 V8 引擎在执行这段代码时抛出异常，`mksnapshot` 可能会捕获这个异常并报错退出。错误信息通常会包含 JavaScript 引擎的错误提示。

3. **快照大小超出限制:** 生成的快照可能非常大，尤其是在包含大量预编译代码或数据时。如果快照过大，可能会导致内存问题或加载时间过长。虽然 `mksnapshot.cc` 本身不太会直接导致这个问题，但了解快照大小的影响是重要的。

4. **在快照中引入不确定性因素:** 快照的目标是创建一个确定的、可重现的 V8 引擎初始状态。如果在生成快照的 JavaScript 代码中引入了依赖于时间、随机数或其他外部因素的操作，会导致生成的快照在不同时间或环境下有所不同，这可能会导致难以调试的问题。

   **示例:**
   假设 `init.js` 包含：
   ```javascript
   globalThis.snapshotTime = new Date();
   ```
   每次运行 `mksnapshot` 生成的快照中，`snapshotTime` 的值都会不同。

理解 `mksnapshot.cc` 的功能对于深入了解 V8 引擎的启动过程和性能优化至关重要。通过生成和使用快照，V8 能够显著缩短启动时间，提高应用程序的响应速度。

Prompt: 
```
这是目录为v8/src/snapshot/mksnapshot.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/snapshot/mksnapshot.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2006-2008 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <signal.h>
#include <stdio.h>

#include <iomanip>

#include "include/libplatform/libplatform.h"
#include "include/v8-initialization.h"
#include "src/base/platform/elapsed-timer.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/wrappers.h"
#include "src/base/vector.h"
#include "src/codegen/cpu-features.h"
#include "src/common/globals.h"
#include "src/flags/flags.h"
#include "src/snapshot/embedded/embedded-file-writer.h"
#include "src/snapshot/snapshot.h"
#include "src/snapshot/static-roots-gen.h"

namespace {

class SnapshotFileWriter {
 public:
  void SetSnapshotFile(const char* snapshot_cpp_file) {
    snapshot_cpp_path_ = snapshot_cpp_file;
  }

  void SetStartupBlobFile(const char* snapshot_blob_file) {
    snapshot_blob_path_ = snapshot_blob_file;
  }

  void WriteSnapshot(v8::StartupData blob) const {
    // TODO(crbug/633159): if we crash before the files have been fully created,
    // we end up with a corrupted snapshot file. The build step would succeed,
    // but the build target is unusable. Ideally we would write out temporary
    // files and only move them to the final destination as last step.
    v8::base::Vector<const uint8_t> blob_vector(
        reinterpret_cast<const uint8_t*>(blob.data), blob.raw_size);
    MaybeWriteSnapshotFile(blob_vector);
    MaybeWriteStartupBlob(blob_vector);
  }

 private:
  void MaybeWriteStartupBlob(v8::base::Vector<const uint8_t> blob) const {
    if (!snapshot_blob_path_) return;

    FILE* fp = GetFileDescriptorOrDie(snapshot_blob_path_);
    size_t written = fwrite(blob.begin(), 1, blob.length(), fp);
    v8::base::Fclose(fp);
    if (written != static_cast<size_t>(blob.length())) {
      i::PrintF("Writing snapshot file failed.. Aborting.\n");
      remove(snapshot_blob_path_);
      exit(1);
    }
  }

  void MaybeWriteSnapshotFile(v8::base::Vector<const uint8_t> blob) const {
    if (!snapshot_cpp_path_) return;

    FILE* fp = GetFileDescriptorOrDie(snapshot_cpp_path_);

    WriteSnapshotFilePrefix(fp);
    WriteSnapshotFileData(fp, blob);
    WriteSnapshotFileSuffix(fp);

    v8::base::Fclose(fp);
  }

  static void WriteSnapshotFilePrefix(FILE* fp) {
    fprintf(fp, "// Autogenerated snapshot file. Do not edit.\n\n");
    fprintf(fp, "#include \"src/init/v8.h\"\n");
    fprintf(fp, "#include \"src/base/platform/platform.h\"\n\n");
    fprintf(fp, "#include \"src/flags/flags.h\"\n");
    fprintf(fp, "#include \"src/snapshot/snapshot.h\"\n\n");
    fprintf(fp, "namespace v8 {\n");
    fprintf(fp, "namespace internal {\n\n");
  }

  static void WriteSnapshotFileSuffix(FILE* fp) {
    fprintf(fp, "const v8::StartupData* Snapshot::DefaultSnapshotBlob() {\n");
    fprintf(fp, "  return &blob;\n");
    fprintf(fp, "}\n");
    fprintf(fp, "\n");
    fprintf(
        fp,
        "bool Snapshot::ShouldVerifyChecksum(const v8::StartupData* data) {\n");
    fprintf(fp, "  return v8_flags.verify_snapshot_checksum;\n");
    fprintf(fp, "}\n");
    fprintf(fp, "}  // namespace internal\n");
    fprintf(fp, "}  // namespace v8\n");
  }

  static void WriteSnapshotFileData(FILE* fp,
                                    v8::base::Vector<const uint8_t> blob) {
    fprintf(
        fp,
        "alignas(kPointerAlignment) static const uint8_t blob_data[] = {\n");
    WriteBinaryContentsAsCArray(fp, blob);
    fprintf(fp, "};\n");
    fprintf(fp, "static const int blob_size = %d;\n", blob.length());
    fprintf(fp, "static const v8::StartupData blob =\n");
    fprintf(fp, "{ (const char*) blob_data, blob_size };\n");
  }

  static void WriteBinaryContentsAsCArray(
      FILE* fp, v8::base::Vector<const uint8_t> blob) {
    for (int i = 0; i < blob.length(); i++) {
      if ((i & 0x1F) == 0x1F) fprintf(fp, "\n");
      if (i > 0) fprintf(fp, ",");
      fprintf(fp, "%u", static_cast<unsigned char>(blob.at(i)));
    }
    fprintf(fp, "\n");
  }

  static FILE* GetFileDescriptorOrDie(const char* filename) {
    FILE* fp = v8::base::OS::FOpen(filename, "wb");
    if (fp == nullptr) {
      i::PrintF("Unable to open file \"%s\" for writing.\n", filename);
      exit(1);
    }
    return fp;
  }

  const char* snapshot_cpp_path_ = nullptr;
  const char* snapshot_blob_path_ = nullptr;
};

std::unique_ptr<char[]> GetExtraCode(char* filename, const char* description) {
  if (filename == nullptr || strlen(filename) == 0) return nullptr;
  ::printf("Loading script for %s: %s\n", description, filename);
  FILE* file = v8::base::OS::FOpen(filename, "rb");
  if (file == nullptr) {
    fprintf(stderr, "Failed to open '%s': errno %d\n", filename, errno);
    exit(1);
  }
  fseek(file, 0, SEEK_END);
  size_t size = ftell(file);
  rewind(file);
  char* chars = new char[size + 1];
  chars[size] = '\0';
  for (size_t i = 0; i < size;) {
    size_t read = fread(&chars[i], 1, size - i, file);
    if (ferror(file)) {
      fprintf(stderr, "Failed to read '%s': errno %d\n", filename, errno);
      exit(1);
    }
    i += read;
  }
  v8::base::Fclose(file);
  return std::unique_ptr<char[]>(chars);
}

v8::StartupData CreateSnapshotDataBlob(v8::SnapshotCreator& snapshot_creator,
                                       const char* embedded_source) {
  v8::base::ElapsedTimer timer;
  timer.Start();

  v8::StartupData result = i::CreateSnapshotDataBlobInternal(
      v8::SnapshotCreator::FunctionCodeHandling::kClear, embedded_source,
      snapshot_creator);

  if (i::v8_flags.profile_deserialization) {
    i::PrintF("[Creating snapshot took %0.3f ms]\n",
              timer.Elapsed().InMillisecondsF());
  }

  timer.Stop();
  return result;
}

v8::StartupData WarmUpSnapshotDataBlob(v8::StartupData cold_snapshot_blob,
                                       const char* warmup_source) {
  v8::base::ElapsedTimer timer;
  timer.Start();

  v8::StartupData result =
      i::WarmUpSnapshotDataBlobInternal(cold_snapshot_blob, warmup_source);

  if (i::v8_flags.profile_deserialization) {
    i::PrintF("Warming up snapshot took %0.3f ms\n",
              timer.Elapsed().InMillisecondsF());
  }

  timer.Stop();
  return result;
}

void WriteEmbeddedFile(i::EmbeddedFileWriter* writer) {
  i::EmbeddedData embedded_blob = i::EmbeddedData::FromBlob();
  writer->WriteEmbedded(&embedded_blob);
}

using CounterMap = std::map<std::string, int>;
CounterMap* counter_map_ = nullptr;

void MaybeSetCounterFunction(v8::Isolate* isolate) {
  // If --native-code-counters is on then we enable all counters to make
  // sure we generate code to increment them from the snapshot.
  //
  // Note: For the sake of the mksnapshot, the counter function must only
  // return distinct addresses for each counter s.t. the serializer can properly
  // distinguish between them. In theory it should be okay to just return an
  // incremented int value each time this function is called, but we play it
  // safe and return a real distinct memory location tied to every counter name.
  if (i::v8_flags.native_code_counters) {
    counter_map_ = new CounterMap();
    isolate->SetCounterFunction([](const char* name) -> int* {
      auto map_entry = counter_map_->find(name);
      if (map_entry == counter_map_->end()) {
        counter_map_->emplace(name, 0);
      }
      return &counter_map_->at(name);
    });
  }
}

}  // namespace

int main(int argc, char** argv) {
  v8::base::EnsureConsoleOutput();

  // Make mksnapshot runs predictable to create reproducible snapshots.
  i::v8_flags.predictable = true;

  // Disable ICs globally in mksnapshot to avoid problems with Code handlers.
  // See https://crbug.com/345280736.
  // TODO(jgruber): Re-enable once a better fix is available.
  i::v8_flags.use_ic = false;

  // Print the usage if an error occurs when parsing the command line
  // flags or if the help flag is set.
  using HelpOptions = i::FlagList::HelpOptions;
  std::string usage = "Usage: " + std::string(argv[0]) +
                      " [--startup-src=file]" + " [--startup-blob=file]" +
                      " [--embedded-src=file]" + " [--embedded-variant=label]" +
                      " [--static-roots-src=file]" + " [--target-arch=arch]" +
                      " [--target-os=os] [extras]\n\n";
  int result = i::FlagList::SetFlagsFromCommandLine(
      &argc, argv, true, HelpOptions(HelpOptions::kExit, usage.c_str()));
  if (result > 0 || (argc > 3)) {
    i::PrintF(stdout, "%s", usage.c_str());
    return result;
  }

  i::CpuFeatures::Probe(true);
  v8::V8::InitializeICUDefaultLocation(argv[0]);
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::Initialize();

  {
    SnapshotFileWriter snapshot_writer;
    snapshot_writer.SetSnapshotFile(i::v8_flags.startup_src);
    snapshot_writer.SetStartupBlobFile(i::v8_flags.startup_blob);

    i::EmbeddedFileWriter embedded_writer;
    embedded_writer.SetEmbeddedFile(i::v8_flags.embedded_src);
    embedded_writer.SetEmbeddedVariant(i::v8_flags.embedded_variant);
    embedded_writer.SetTargetArch(i::v8_flags.target_arch);
    embedded_writer.SetTargetOs(i::v8_flags.target_os);

    std::unique_ptr<char[]> embed_script =
        GetExtraCode(argc >= 2 ? argv[1] : nullptr, "embedding");
    std::unique_ptr<char[]> warmup_script =
        GetExtraCode(argc >= 3 ? argv[2] : nullptr, "warm up");

    v8::StartupData blob;
    {
      v8::Isolate* isolate = v8::Isolate::Allocate();

      MaybeSetCounterFunction(isolate);

      // The isolate contains data from builtin compilation that needs
      // to be written out if builtins are embedded.
      i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
      i_isolate->RegisterEmbeddedFileWriter(&embedded_writer);

      std::unique_ptr<v8::ArrayBuffer::Allocator> array_buffer_allocator(
          v8::ArrayBuffer::Allocator::NewDefaultAllocator());
      v8::Isolate::CreateParams create_params;
      create_params.array_buffer_allocator = array_buffer_allocator.get();

      // Set code range such that relative jumps for builtins to
      // builtin calls in the snapshot are possible.
      size_t code_range_size_mb =
          i::kMaximalCodeRangeSize == 0
              ? i::kMaxPCRelativeCodeRangeInMB
              : std::min(i::kMaximalCodeRangeSize / i::MB,
                         i::kMaxPCRelativeCodeRangeInMB);
      create_params.constraints.set_code_range_size_in_bytes(
          code_range_size_mb * i::MB);

      {
        v8::SnapshotCreator creator(isolate, create_params);

        blob = CreateSnapshotDataBlob(creator, embed_script.get());

        WriteEmbeddedFile(&embedded_writer);

#if V8_STATIC_ROOTS_GENERATION_BOOL
        if (i::v8_flags.static_roots_src) {
          i::StaticRootsTableGen::write(i_isolate,
                                        i::v8_flags.static_roots_src);
        }
#endif
      }
      isolate->Dispose();
    }

    if (warmup_script) {
      v8::StartupData cold = blob;
      blob = WarmUpSnapshotDataBlob(cold, warmup_script.get());
      delete[] cold.data;
    }

    delete counter_map_;

    CHECK(blob.data);
    snapshot_writer.WriteSnapshot(blob);
    delete[] blob.data;
  }

  v8::V8::Dispose();
  v8::V8::DisposePlatform();
  return 0;
}

"""

```