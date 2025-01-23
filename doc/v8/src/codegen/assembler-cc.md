Response:
Let's break down the thought process for analyzing this `assembler.cc` file.

1. **Understanding the Request:** The core request is to understand the *functionality* of this C++ source file within the V8 JavaScript engine. Key constraints include mentioning JavaScript relevance (if any), providing JavaScript examples, explaining code logic with inputs/outputs, and identifying common programming errors related to the code. The initial condition about the `.tq` extension is a quick check for Torque-generated code.

2. **Initial Scan and File Extension Check:** The first step is to quickly scan the content. The provided text is definitely C++ code. The request mentions checking for a `.tq` extension, but this is a `.cc` file, so it's not Torque. This immediately tells us it's handwritten C++ for the assembler.

3. **Identifying Key Classes and Namespaces:** Look for prominent class names and namespaces. The `v8::internal` namespace and the `Assembler`, `AssemblerBase`, `AssemblerOptions`, `AssemblerBuffer`, `CpuFeatureScope`, and `CpuFeatures` classes stand out. These are central to the file's purpose.

4. **Analyzing `AssemblerBase` and `Assembler`:** These classes are clearly related to assembly. The constructor of `AssemblerBase` initializes a buffer, and there are methods like `Print`, suggesting the ability to output assembled code. The presence of `RecordRelocInfo`, `DataAlign`, and methods for managing code targets and embedded objects reinforces this. `Assembler` inherits from `AssemblerBase`, indicating it provides a more specialized or extended interface.

5. **Understanding `AssemblerBuffer`:** The existence of different `AssemblerBuffer` implementations (`DefaultAssemblerBuffer`, `ExternalAssemblerBufferImpl`) points to different ways of managing the memory where the assembled code is stored. The `Grow` method in `AssemblerBuffer` suggests dynamic resizing of the buffer.

6. **Deciphering `AssemblerOptions`:**  This struct likely configures the assembler's behavior. The members like `record_reloc_info_for_serialization`, `enable_root_relative_access`, `enable_simulator_code`, and `builtin_call_jump_mode` give clues about different optimization and deployment scenarios. The `Default` method shows how these options are typically set based on the V8 isolate's configuration.

7. **Investigating `CpuFeatureScope` and `CpuFeatures`:** The names suggest handling CPU-specific instructions. `CpuFeatures` likely holds information about supported CPU features, and `CpuFeatureScope` seems to temporarily enable or disable specific features within a code block.

8. **Connecting to JavaScript (Crucial Step):** The key link to JavaScript is the purpose of the assembler itself. JavaScript code needs to be executed by the CPU. V8 compiles JavaScript into machine code. The `assembler.cc` file is responsible for *generating that machine code*. This is the fundamental connection.

9. **Developing JavaScript Examples:**  Based on the identified functionalities, think about how they relate to JavaScript.
    * **Code Generation:** Any JavaScript code triggers the assembler to generate machine code. A simple function is a good starting point.
    * **Optimization (Implicit):** The `AssemblerOptions` mention optimization flags. While not directly controllable by JavaScript, it's important to note that the assembler handles optimizations.
    * **CPU Features (Less Direct):**  While JavaScript doesn't directly control CPU features at this level, V8 might generate different code based on detected CPU capabilities for performance. This is a more advanced concept.
    * **Deoptimization:**  The `RecordDeoptReason` function is directly related to deoptimization, a key V8 mechanism. An example causing deoptimization is relevant.

10. **Formulating Code Logic Examples:**  Choose specific methods and demonstrate their behavior.
    * `AddCodeTarget`/`GetCodeTarget`:  Simulate adding and retrieving a code label/target.
    * `AddEmbeddedObject`/`GetEmbeddedObject`: Show storing and retrieving a constant value.
    * `DataAlign`:  Illustrate how alignment works with byte insertion.

11. **Identifying Common Programming Errors:** Think about how developers might misuse or misunderstand the *concepts* the assembler deals with, even though they don't directly interact with this C++ code.
    * **Performance Issues:**  Inefficient JavaScript can lead to V8 generating less optimized code.
    * **Deoptimization:**  Understanding what causes deoptimization is important for performance.
    * **Memory Issues (Less Direct):**  While the `AssemblerBuffer` manages memory, developers don't directly interact with it, but excessive code size could indirectly lead to memory issues.

12. **Structuring the Answer:** Organize the information logically. Start with the core function, then detail the key components, explain the JavaScript connection, provide examples, and finally discuss potential errors. Use clear headings and bullet points for readability.

13. **Refining and Reviewing:**  Read through the generated answer, ensuring accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed. For example, ensure the distinction between `Assembler` and `AssemblerBase` is clear.

This step-by-step approach, focusing on identifying key components and their relationships, and then connecting them back to the higher-level concept of JavaScript execution within V8, leads to a comprehensive understanding of the `assembler.cc` file's functionality.
The provided code snippet is a header file (`assembler.h` is implied by the `#include "src/codegen/assembler.h"`)  and a partial implementation file (`assembler.cc`) for the `Assembler` class in the V8 JavaScript engine. This class is a fundamental building block for V8's code generation pipeline.

Here's a breakdown of its functionalities:

**Core Functionality: Machine Code Generation**

The primary purpose of `assembler.cc` is to provide a high-level interface for generating machine code. It abstracts away the low-level details of specific CPU architectures, allowing V8's compiler to generate platform-independent assembly instructions.

**Key Components and Their Roles:**

* **`AssemblerBase`:** This is the base class providing core functionalities for managing the code buffer, tracking relocation information, and handling CPU feature flags.
    * **Code Buffer Management:**  It manages the underlying memory buffer (`AssemblerBuffer`) where the generated machine code is stored. This includes allocating, growing, and accessing the buffer.
    * **Relocation Information:** It records information needed by the linker to resolve addresses of external symbols, code targets, and embedded objects. This is crucial for creating executable code.
    * **CPU Feature Management:** It allows enabling and tracking CPU-specific features (like SIMD instructions) during code generation.
    * **Code Targets and Embedded Objects:** It provides mechanisms to store and reference code labels (targets for jumps and calls) and constant values (embedded objects) within the generated code.
* **`Assembler`:** This class inherits from `AssemblerBase` and adds more specific methods for emitting machine instructions. While the provided snippet doesn't show the actual instruction emission methods (those are likely in architecture-specific files or inline headers), its responsibilities include:
    * **High-Level Instruction Abstraction:**  It offers methods that correspond to common assembly instructions (e.g., `mov`, `add`, `jmp`, `call`), but are abstracted to work across different architectures.
    * **Deoptimization Support:** It includes methods like `RecordDeoptReason` to record information needed for deoptimization, a process where the engine reverts from optimized code to a less optimized version.
    * **Data Alignment:** The `DataAlign` method ensures that data is placed at memory addresses that are multiples of a certain value, which can improve performance on some architectures.
    * **Code Comments:**  Features for embedding comments within the generated code for debugging and analysis.
* **`AssemblerOptions`:**  A structure to configure the behavior of the assembler, including flags for serialization, embedded builtins, simulator usage, and short builtin calls.
* **`AssemblerBuffer`:** An abstract class representing the underlying buffer where the machine code is stored. Different implementations (`DefaultAssemblerBuffer`, `ExternalAssemblerBufferImpl`) handle memory allocation in different ways.
* **`CpuFeatureScope` and `CpuFeatures`:** These manage the enabling and tracking of CPU-specific features during code generation.
* **`HeapNumberRequest`:** Used to defer the allocation and embedding of `HeapNumber` objects until later in the code generation process.

**Is `v8/src/codegen/assembler.cc` a v8 torque source code?**

No, based on the file extension `.cc`, it's a standard C++ source file. Torque source files in V8 typically have a `.tq` extension.

**Relationship with Javascript and Javascript Examples:**

The `Assembler` class is directly involved in the process of taking JavaScript code and translating it into machine code that the CPU can execute. Here's how it relates and examples:

1. **Compiling JavaScript Functions:** When V8 compiles a JavaScript function, the compiler uses an `Assembler` instance to emit the corresponding machine instructions.

   ```javascript
   function add(a, b) {
     return a + b;
   }
   ```

   Internally, V8's compiler would use the `Assembler` to generate assembly instructions to:
   * Load the values of `a` and `b` from their respective locations (registers or memory).
   * Perform the addition operation.
   * Store the result.
   * Return from the function.

2. **Optimized Code Generation:**  For frequently executed code, V8's optimizing compiler (TurboFan) also uses the `Assembler` to generate highly optimized machine code.

   ```javascript
   for (let i = 0; i < 1000; i++) {
     // This loop might be optimized
     console.log(i);
   }
   ```

   The `Assembler` would be used to generate efficient loop structures, potentially unrolling the loop or using SIMD instructions (if enabled by CPU features) for better performance.

3. **Built-in Functions:** V8's built-in JavaScript functions (like `Array.prototype.map`, `String.prototype.indexOf`) are often implemented using carefully crafted assembly code generated with the `Assembler`.

   ```javascript
   const arr = [1, 2, 3];
   const doubled = arr.map(x => x * 2);
   ```

   The implementation of `Array.prototype.map` within V8 likely involves `Assembler` usage to iterate through the array and apply the provided callback function.

4. **Deoptimization:** When V8 needs to "bail out" from optimized code (e.g., due to type changes or encountering unsupported operations), the `RecordDeoptReason` method is used to mark the point of deoptimization in the generated code.

   ```javascript
   function potentiallyUnstableAdd(a, b) {
     if (typeof a === 'number' && typeof b === 'number') {
       return a + b;
     } else {
       return String(a) + String(b);
     }
   }

   let result = potentiallyUnstableAdd(5, 10); // Initially optimized for numbers
   result = potentiallyUnstableAdd("hello", "world"); // Might trigger deoptimization
   ```

   If the types of `a` and `b` change in subsequent calls, V8 might deoptimize the initially optimized code for numbers. The `Assembler` would have recorded the deoptimization points.

**Code Logic Inference with Assumptions:**

Let's focus on the `DataAlign` method:

**Assumption:** We are on an architecture where data alignment to 4-byte boundaries can improve performance.

**Input:** An `Assembler` instance where `pc_offset()` (the current position in the code buffer) is, say, `5`, and we call `DataAlign(4)`.

**Output:** The `while` loop in `DataAlign` will execute until `pc_offset()` is a multiple of 4.
* **Iteration 1:** `pc_offset() & (4 - 1)` which is `5 & 3` (binary `0101 & 0011`) equals `1`. Not zero, so `db(0xcc)` is called, adding one byte to the buffer. `pc_offset()` becomes `6`.
* **Iteration 2:** `pc_offset() & 3` is `6 & 3` (binary `0110 & 0011`) equals `2`. Not zero, `db(0xcc)` is called. `pc_offset()` becomes `7`.
* **Iteration 3:** `pc_offset() & 3` is `7 & 3` (binary `0111 & 0011`) equals `3`. Not zero, `db(0xcc)` is called. `pc_offset()` becomes `8`.
* **Iteration 4:** `pc_offset() & 3` is `8 & 3` (binary `1000 & 0011`) equals `0`. The loop terminates.

The code buffer will have been padded with three `0xcc` bytes to reach an address that is a multiple of 4.

**User-Visible Programming Errors (Indirectly Related):**

While developers don't directly interact with the `Assembler` class, certain programming practices can lead to V8 generating less efficient code, which is the ultimate output of the `Assembler`.

1. **Type Instability:** Writing JavaScript code where the types of variables change frequently can hinder V8's ability to optimize. This can lead to more frequent deoptimizations, and the generated assembly code might be less efficient.

   ```javascript
   function example(x) {
     if (Math.random() > 0.5) {
       x = 10; // x is a number
     } else {
       x = "hello"; // x is a string
     }
     return x;
   }
   ```

   V8 might have difficulty optimizing this function because the type of `x` is unpredictable.

2. **Hidden Class Changes:**  Modifying object structures dynamically can cause V8 to create new hidden classes, leading to less efficient property access and potentially triggering deoptimization.

   ```javascript
   function createPoint(x, y) {
     const point = { x: x };
     point.y = y; // Adding 'y' later changes the object's structure
     return point;
   }
   ```

   It's generally more efficient to initialize all properties of an object at once.

3. **Calling Unoptimized Functions Frequently:** If a JavaScript function cannot be optimized by TurboFan (e.g., due to excessive complexity or use of `eval`), repeatedly calling it will result in less efficient machine code being executed.

4. **Large Functions:**  Extremely long and complex JavaScript functions can sometimes be harder for the compiler to optimize effectively, potentially leading to less optimal assembly code generation.

In summary, `v8/src/codegen/assembler.cc` is a crucial component of the V8 engine responsible for the low-level task of generating machine code from higher-level representations of JavaScript. While developers don't directly use this class, their coding practices heavily influence the quality and efficiency of the machine code it produces.

### 提示词
```
这是目录为v8/src/codegen/assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright (c) 1994-2006 Sun Microsystems Inc.
// All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// - Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// - Redistribution in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// - Neither the name of Sun Microsystems or the names of contributors may
// be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// The original source code covered by the above license above has been
// modified significantly by Google Inc.
// Copyright 2012 the V8 project authors. All rights reserved.

#include "src/codegen/assembler.h"

#ifdef V8_CODE_COMMENTS
#include <iomanip>
#endif
#include "src/base/vector.h"
#include "src/codegen/assembler-inl.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/isolate.h"
#include "src/heap/heap-inl.h"  // For MemoryAllocator. TODO(jkummerow): Drop.
#include "src/snapshot/embedded/embedded-data.h"
#include "src/snapshot/snapshot.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

AssemblerOptions AssemblerOptions::Default(Isolate* isolate) {
  AssemblerOptions options;
  const bool serializer = isolate->serializer_enabled();
  const bool generating_embedded_builtin =
      isolate->IsGeneratingEmbeddedBuiltins();
  options.record_reloc_info_for_serialization = serializer;
  options.enable_root_relative_access =
      !serializer && !generating_embedded_builtin;
#ifdef USE_SIMULATOR
  // Even though the simulator is enabled, we may still need to generate code
  // that may need to run on both the simulator and real hardware. For example,
  // if we are cross-compiling and embedding a script into the snapshot, the
  // script will need to run on the host causing the embedded builtins to run in
  // the simulator. While the final cross-compiled V8 will not have a simulator.

  // So here we enable simulator specific code if not generating the snapshot or
  // if we are but we are targetting the simulator *only*.
  options.enable_simulator_code = !serializer || v8_flags.target_is_simulator;
#endif

#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_ARM64 || V8_TARGET_ARCH_LOONG64 || \
    V8_TARGET_ARCH_RISCV64
  options.code_range_base = isolate->heap()->code_range_base();
#endif
  bool short_builtin_calls =
      isolate->is_short_builtin_calls_enabled() &&
      !generating_embedded_builtin &&
      (options.code_range_base != kNullAddress) &&
      // Serialization of NEAR_BUILTIN_ENTRY reloc infos is not supported yet.
      !serializer;
  if (short_builtin_calls) {
    options.builtin_call_jump_mode = BuiltinCallJumpMode::kPCRelative;
  }
  return options;
}

namespace {

class DefaultAssemblerBuffer : public AssemblerBuffer {
 public:
  explicit DefaultAssemblerBuffer(int size)
      : buffer_(base::OwnedVector<uint8_t>::NewForOverwrite(
            std::max(AssemblerBase::kMinimalBufferSize, size))) {
#ifdef DEBUG
    ZapCode(reinterpret_cast<Address>(buffer_.begin()), buffer_.size());
#endif
  }

  uint8_t* start() const override { return buffer_.begin(); }

  int size() const override { return static_cast<int>(buffer_.size()); }

  std::unique_ptr<AssemblerBuffer> Grow(int new_size) override {
    DCHECK_LT(size(), new_size);
    return std::make_unique<DefaultAssemblerBuffer>(new_size);
  }

 private:
  base::OwnedVector<uint8_t> buffer_;
};

class ExternalAssemblerBufferImpl : public AssemblerBuffer {
 public:
  ExternalAssemblerBufferImpl(uint8_t* start, int size)
      : start_(start), size_(size) {}

  uint8_t* start() const override { return start_; }

  int size() const override { return size_; }

  std::unique_ptr<AssemblerBuffer> Grow(int new_size) override {
    FATAL("Cannot grow external assembler buffer");
  }

  void* operator new(std::size_t count);
  void operator delete(void* ptr) noexcept;

 private:
  uint8_t* const start_;
  const int size_;
};

static thread_local std::aligned_storage_t<sizeof(ExternalAssemblerBufferImpl),
                                           alignof(ExternalAssemblerBufferImpl)>
    tls_singleton_storage;

static thread_local bool tls_singleton_taken{false};

void* ExternalAssemblerBufferImpl::operator new(std::size_t count) {
  DCHECK_EQ(count, sizeof(ExternalAssemblerBufferImpl));
  if (V8_LIKELY(!tls_singleton_taken)) {
    tls_singleton_taken = true;
    return &tls_singleton_storage;
  }
  return ::operator new(count);
}

void ExternalAssemblerBufferImpl::operator delete(void* ptr) noexcept {
  if (V8_LIKELY(ptr == &tls_singleton_storage)) {
    DCHECK(tls_singleton_taken);
    tls_singleton_taken = false;
    return;
  }
  ::operator delete(ptr);
}

}  // namespace

std::unique_ptr<AssemblerBuffer> ExternalAssemblerBuffer(void* start,
                                                         int size) {
  return std::make_unique<ExternalAssemblerBufferImpl>(
      reinterpret_cast<uint8_t*>(start), size);
}

std::unique_ptr<AssemblerBuffer> NewAssemblerBuffer(int size) {
  return std::make_unique<DefaultAssemblerBuffer>(size);
}

// -----------------------------------------------------------------------------
// Implementation of AssemblerBase

// static
constexpr int AssemblerBase::kMinimalBufferSize;

// static
constexpr int AssemblerBase::kDefaultBufferSize;

AssemblerBase::AssemblerBase(const AssemblerOptions& options,
                             std::unique_ptr<AssemblerBuffer> buffer)
    : buffer_(std::move(buffer)),
      options_(options),
      enabled_cpu_features_(0),
      predictable_code_size_(false),
      constant_pool_available_(false),
      jump_optimization_info_(nullptr) {
  if (!buffer_) buffer_ = NewAssemblerBuffer(kDefaultBufferSize);
  buffer_start_ = buffer_->start();
  pc_ = buffer_start_;
}

AssemblerBase::~AssemblerBase() = default;

void AssemblerBase::Print(Isolate* isolate) {
  StdoutStream os;
  v8::internal::Disassembler::Decode(isolate, os, buffer_start_, pc_);
}

// -----------------------------------------------------------------------------
// Implementation of CpuFeatureScope

#ifdef DEBUG
CpuFeatureScope::CpuFeatureScope(AssemblerBase* assembler, CpuFeature f,
                                 CheckPolicy check)
    : assembler_(assembler) {
  DCHECK_IMPLIES(check == kCheckSupported, CpuFeatures::IsSupported(f));
  old_enabled_ = assembler_->enabled_cpu_features();
  assembler_->EnableCpuFeature(f);
}

CpuFeatureScope::~CpuFeatureScope() {
  assembler_->set_enabled_cpu_features(old_enabled_);
}
#endif

bool CpuFeatures::initialized_ = false;
bool CpuFeatures::supports_wasm_simd_128_ = false;
bool CpuFeatures::supports_cetss_ = false;
unsigned CpuFeatures::supported_ = 0;
unsigned CpuFeatures::icache_line_size_ = 0;
unsigned CpuFeatures::dcache_line_size_ = 0;

HeapNumberRequest::HeapNumberRequest(double heap_number, int offset)
    : offset_(offset) {
  value_ = heap_number;
  DCHECK(!IsSmiDouble(value_));
}

// Platform specific but identical code for all the platforms.

void Assembler::RecordDeoptReason(DeoptimizeReason reason, uint32_t node_id,
                                  SourcePosition position, int id) {
  static_assert(RelocInfoWriter::kMaxSize * 2 <= kGap);
  {
    EnsureSpace space(this);
    DCHECK(position.IsKnown());
    RecordRelocInfo(RelocInfo::DEOPT_SCRIPT_OFFSET, position.ScriptOffset());
    RecordRelocInfo(RelocInfo::DEOPT_INLINING_ID, position.InliningId());
  }
  {
    EnsureSpace space(this);
    RecordRelocInfo(RelocInfo::DEOPT_REASON, static_cast<int>(reason));
    RecordRelocInfo(RelocInfo::DEOPT_ID, id);
  }
#ifdef DEBUG
  EnsureSpace space(this);
  RecordRelocInfo(RelocInfo::DEOPT_NODE_ID, node_id);
#endif  // DEBUG
}

void Assembler::DataAlign(int m) {
  DCHECK(m >= 2 && base::bits::IsPowerOfTwo(m));
  while ((pc_offset() & (m - 1)) != 0) {
    // Pad with 0xcc (= int3 on ia32 and x64); the primary motivation is that
    // the disassembler expects to find valid instructions, but this is also
    // nice from a security point of view.
    db(0xcc);
  }
}

void AssemblerBase::RequestHeapNumber(HeapNumberRequest request) {
  request.set_offset(pc_offset());
  heap_number_requests_.push_front(request);
}

int AssemblerBase::AddCodeTarget(IndirectHandle<Code> target) {
  int current = static_cast<int>(code_targets_.size());
  if (current > 0 && !target.is_null() &&
      code_targets_.back().address() == target.address()) {
    // Optimization if we keep jumping to the same code target.
    return current - 1;
  } else {
    code_targets_.push_back(target);
    return current;
  }
}

IndirectHandle<Code> AssemblerBase::GetCodeTarget(
    intptr_t code_target_index) const {
  DCHECK_LT(static_cast<size_t>(code_target_index), code_targets_.size());
  return code_targets_[code_target_index];
}

AssemblerBase::EmbeddedObjectIndex AssemblerBase::AddEmbeddedObject(
    IndirectHandle<HeapObject> object) {
  EmbeddedObjectIndex current = embedded_objects_.size();
  // Do not deduplicate invalid handles, they are to heap object requests.
  if (!object.is_null()) {
    auto entry = embedded_objects_map_.find(object);
    if (entry != embedded_objects_map_.end()) {
      return entry->second;
    }
    embedded_objects_map_[object] = current;
  }
  embedded_objects_.push_back(object);
  return current;
}

IndirectHandle<HeapObject> AssemblerBase::GetEmbeddedObject(
    EmbeddedObjectIndex index) const {
  DCHECK_LT(index, embedded_objects_.size());
  return embedded_objects_[index];
}

int Assembler::WriteCodeComments() {
  if (!v8_flags.code_comments) return 0;
  CHECK_IMPLIES(code_comments_writer_.entry_count() > 0,
                options().emit_code_comments);
  if (code_comments_writer_.entry_count() == 0) return 0;
  int offset = pc_offset();
  code_comments_writer_.Emit(this);
  int size = pc_offset() - offset;
  DCHECK_EQ(size, code_comments_writer_.section_size());
  return size;
}

#ifdef V8_CODE_COMMENTS
int Assembler::CodeComment::depth() const { return assembler_->comment_depth_; }
void Assembler::CodeComment::Open(const std::string& comment,
                                  const SourceLocation& loc) {
  std::stringstream sstream;
  sstream << std::setfill(' ') << std::setw(depth() * kIndentWidth + 2);
  sstream << "[ " << comment;
  assembler_->comment_depth_++;
  assembler_->RecordComment(sstream.str(), loc);
}

void Assembler::CodeComment::Close() {
  assembler_->comment_depth_--;
  std::string comment = "]";
  comment.insert(0, depth() * kIndentWidth, ' ');
  DCHECK_LE(0, depth());
  // Don't record source information for the closed comment.
  assembler_->RecordComment(comment, SourceLocation());
}
#endif

}  // namespace internal
}  // namespace v8
```