Response:
Let's break down the thought process for analyzing this V8 Maglev assembler code.

**1. Understanding the Request:**

The core request is to understand the functionality of the provided C++ code snippet. Specific points of interest are:

* **General Functionality:** What does this code do?
* **Torque Connection:** Is this code potentially related to Torque (indicated by a `.tq` extension)?  (Immediate Answer: No, it's `.cc`).
* **JavaScript Relationship:** How does this code relate to JavaScript functionality? Provide JavaScript examples.
* **Code Logic Reasoning:**  If there's any complex logic, explain it with example inputs and outputs.
* **Common Programming Errors:** Are there patterns that suggest ways users might misuse or encounter errors related to this code?

**2. Initial Code Scan and High-Level Overview:**

The first step is to quickly skim the code for keywords and structure. Things that immediately stand out:

* `#include`:  This is C++, indicating header file dependencies. `src/codegen/interface-descriptors-inl.h`, `src/deoptimizer/deoptimizer.h`, `src/maglev/maglev-assembler-inl.h`, and `src/maglev/maglev-graph.h` are V8-specific headers related to code generation, deoptimization, and the Maglev compiler.
* `namespace v8 { namespace internal { namespace maglev {`:  This confirms the code is part of V8's internal Maglev compiler.
* `#define __ masm->`: This is a common V8 macro for simplifying assembler calls. `masm` likely refers to a `MaglevAssembler` instance.
* Functions like `AllocateRaw`, `Allocate`, `OSRPrologue`, `Prologue`, `LoadSingleCharacterString`, `StringFromCharCode`, `StringCharCodeOrCodePointAt`, `TruncateDoubleToInt32`, `TryTruncateDoubleToInt32`, `TryTruncateDoubleToUint32`, `TryChangeFloat64ToIndex`:  These function names suggest core functionalities related to memory management, function setup, and string/number manipulation.
* Assembler instructions like `sub`, `add`, `ldr`, `str`, `cmp`, `b`, `push`, `pop`, `vcvt_s32_f64`, `vmov`, etc.:  This confirms it's interacting directly with ARM assembly instructions.
* Use of `Register`, `DoubleRegister`, `Operand`: These are V8's abstractions over physical CPU registers and operands for assembler instructions.
* Use of `Label`, `ZoneLabelRef`: These are used for control flow within the generated code.
* Use of `Builtin::k...`, `Runtime::k...`:  These refer to pre-defined V8 built-in functions and runtime functions.
* Checks like `DCHECK`, `CHECK`, `Assert`: These are debugging and assertion mechanisms within V8.

**3. Deeper Dive into Key Functions:**

Now, let's examine the most prominent functions in more detail:

* **`AllocateRaw` and `Allocate`:** These are clearly related to memory allocation within the Maglev compiler. The code interacts with `SpaceAllocationTopAddress` and `SpaceAllocationLimitAddress`, suggesting it manages the heap. The logic checks for available space and calls a "slow path" if needed.
* **`OSRPrologue`:** "OSR" likely stands for "On-Stack Replacement."  This function seems to handle transitioning from unoptimized to optimized code while the function is running. It adjusts the stack frame.
* **`Prologue`:** This is the standard function setup. It saves registers, handles tiering (potentially moving to TurboFan), and initializes stack slots.
* **`LoadSingleCharacterString` and `StringFromCharCode`:** These are clearly related to creating single-character strings. `StringFromCharCode` handles both one-byte and two-byte characters.
* **`StringCharCodeOrCodePointAt`:** This function implements the logic for getting the character code or code point at a specific index within a string, handling different string representations (SeqString, ConsString, SlicedString, ThinString). This is a complex function with multiple branches.
* **`TruncateDoubleToInt32`, `TryTruncateDoubleToInt32`, `TryTruncateDoubleToUint32`, `TryChangeFloat64ToIndex`:** These functions deal with converting floating-point numbers to integers, with considerations for potential truncation and special cases like negative zero.

**4. Connecting to JavaScript:**

With an understanding of the C++ functions, the next step is to relate them to JavaScript.

* **Allocation:**  JavaScript object creation (`new Object()`, `[]`, etc.) eventually triggers memory allocation within V8. The `Allocate` functions are part of this process.
* **Function Calls and Optimization:**  When a JavaScript function is called repeatedly, V8 might use Maglev to generate optimized code. `OSRPrologue` and `Prologue` are involved in setting up the execution environment for these optimized functions.
* **String Operations:**  JavaScript's `String.fromCharCode()`, `charCodeAt()`, and `codePointAt()` are directly implemented by the `StringFromCharCode` and `StringCharCodeOrCodePointAt` functions.
* **Number Conversions:** JavaScript's implicit and explicit type conversions (e.g., `parseInt()`, using bitwise operators on floats) can utilize the truncation functions.

**5. Code Logic Reasoning and Examples:**

For complex functions like `StringCharCodeOrCodePointAt`, providing example inputs and outputs is crucial. Think about different string types and edge cases (e.g., out-of-bounds access, surrogate pairs).

**6. Identifying Common Programming Errors:**

Consider how a JavaScript programmer might interact with the functionality implemented by this C++ code. Common errors related to strings and numbers include:

* **Incorrect index in `charCodeAt()`/`codePointAt()`:** Leading to out-of-bounds errors.
* **Assuming one-to-one mapping between characters and bytes:**  Not understanding UTF-16 and surrogate pairs.
* **Unexpected behavior with floating-point to integer conversions:**  Not realizing truncation happens or not handling special cases like `NaN` or `Infinity`.

**7. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each part of the original request. Use headings and bullet points to improve readability. Provide concise JavaScript examples and explain the reasoning behind the code logic.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is this code directly called by JavaScript?"  **Correction:**  Not directly. It's part of the Maglev compiler, which *generates* code that executes JavaScript.
* **Realization:** The `StringCharCodeOrCodePointAt` function is quite complex. Need to break down its logic step by step and explain the different string types.
* **Focus:**  Don't just list the functions; explain their *purpose* within the Maglev compilation process and their connection to JavaScript behavior.

By following these steps, including iterative refinement, one can effectively analyze and explain the functionality of complex C++ code like the provided V8 snippet.
好的，让我们来分析一下 `v8/src/maglev/arm/maglev-assembler-arm.cc` 这个 V8 源代码文件的功能。

**核心功能：ARM 架构下的 Maglev 汇编器**

这个文件定义了 `MaglevAssembler` 类在 ARM 架构下的具体实现。`MaglevAssembler` 是 V8 中 Maglev 优化编译器的一个核心组件，它的主要职责是**生成目标机器码（ARM 汇编指令）**。

**功能拆解：**

1. **内存分配 (`Allocate`)**:
   - 提供了在堆上分配内存的功能，用于创建新的 JavaScript 对象。
   - 有两个重载版本，分别接收以立即数和寄存器表示的大小。
   - 内部使用 `AllocateRaw` 模板函数来处理实际的分配逻辑。
   - 考虑了新生代（Young Generation）和老生代（Old Generation）的分配。
   - 实现了快速路径（空间足够）和慢速路径（需要调用运行时）的分配逻辑。

2. **函数序言和尾声 (`OSRPrologue`, `Prologue`)**:
   - `Prologue`:  负责生成函数执行前的准备代码，例如：
     - 检查是否需要进行反优化 (`BailoutIfDeoptimized`).
     - 支持分层编译，如果需要，调用运行时函数进行进一步优化 (`MaglevOptimizeCodeOrTailCallOptimizedCodeSlot`).
     - 建立栈帧 (`EnterFrame`).
     - 保存上下文、函数和参数计数器等关键信息。
     - 初始化栈上的局部变量。
   - `OSRPrologue`: 用于处理 On-Stack Replacement (OSR)，即在函数执行过程中从非优化代码切换到优化代码。它需要调整栈帧以适应优化后的布局。

3. **字符串操作**:
   - `LoadSingleCharacterString`: 从预先创建的单字符字符串表中加载指定字符编码的字符串。
   - `StringFromCharCode`: 根据字符编码创建字符串。它会检查字符编码是否在一个字节范围内，如果是，则使用单字符字符串表，否则分配一个双字节字符串。
   - `StringCharCodeOrCodePointAt`: 获取字符串指定索引处的字符编码或码点。这个函数比较复杂，需要处理不同类型的字符串（SeqString, ConsString, SlicedString, ThinString）以及 UTF-16 编码中的代理对。

4. **数字类型转换**:
   - `TruncateDoubleToInt32`: 将双精度浮点数截断为 32 位整数。提供了内联的快速路径和调用内置函数的慢速路径。
   - `TryTruncateDoubleToInt32`: 尝试将双精度浮点数截断为 32 位整数，如果截断后值不变，则成功，否则跳转到失败标签。
   - `TryTruncateDoubleToUint32`: 尝试将双精度浮点数截断为无符号 32 位整数，逻辑类似 `TryTruncateDoubleToInt32`。
   - `TryChangeFloat64ToIndex`: 尝试将双精度浮点数转换为数组索引。

5. **其他**:
   - `MaybeEmitDeoptBuiltinsCall`: 可能会发出调用反优化内置函数的代码。
   - 提供了操作寄存器和内存的底层指令（通过 `__ masm->` 宏）。
   - 使用 `RegisterSnapshot` 来保存和恢复寄存器状态。
   - 使用 `Label` 和 `ZoneLabelRef` 来控制代码的跳转和分支。

**与 JavaScript 功能的关系及示例**

这个文件中的代码是 Maglev 编译器生成 ARM 机器码的关键部分，它直接影响着 JavaScript 代码的执行效率。以下是一些与 JavaScript 功能相关的例子：

**1. 对象创建 (`Allocate`)**

```javascript
const obj = {}; // 或 new Object();
const arr = [];  // 或 new Array();
```

当 JavaScript 执行上述代码时，V8 的 Maglev 编译器可能会使用 `MaglevAssembler::Allocate` 在堆上分配内存来存储新的对象或数组。

**2. 函数调用和优化 (`Prologue`, `OSRPrologue`)**

```javascript
function add(a, b) {
  return a + b;
}

for (let i = 0; i < 10000; i++) {
  add(i, i + 1);
}
```

当 `add` 函数被多次调用后，Maglev 编译器可能会介入，生成优化的机器码。`Prologue` 会设置函数的执行环境，而 `OSRPrologue` 可能在循环执行过程中将代码切换到优化版本。

**3. 字符串操作 (`LoadSingleCharacterString`, `StringFromCharCode`, `StringCharCodeOrCodePointAt`)**

```javascript
const charCode = 65;
const strFromCode = String.fromCharCode(charCode); // 'A'

const text = "Hello";
const charAt = text.charCodeAt(0); // 72
const codePointAt = text.codePointAt(0); // 72
```

`String.fromCharCode()` 的实现可能涉及到 `MaglevAssembler::StringFromCharCode`。`String.charCodeAt()` 和 `String.codePointAt()` 的实现则与 `MaglevAssembler::StringCharCodeOrCodePointAt` 相关。

**4. 数字类型转换 (`TruncateDoubleToInt32`, `TryTruncateDoubleToInt32`, `TryTruncateDoubleToUint32`, `TryChangeFloat64ToIndex`)**

```javascript
const floatNum = 3.14;
const intNum = parseInt(floatNum); // 3
const bitwiseOr = floatNum | 0;    // 3

const arr = [1, 2, 3];
const indexFloat = 1.9;
const value = arr[indexFloat]; // arr[1]，因为 1.9 被转换为索引 1
```

`parseInt()` 和按位运算符（如 `| 0`）可能会使用 `MaglevAssembler::TruncateDoubleToInt32` 或类似的函数。将浮点数用作数组索引时，V8 可能会尝试使用 `MaglevAssembler::TryChangeFloat64ToIndex` 将其转换为有效的整数索引。

**代码逻辑推理示例**

让我们以 `StringFromCharCode` 为例进行简单的逻辑推理：

**假设输入：** `char_code` 寄存器中存储字符编码 `65` (代表 'A').

**执行流程：**

1. `cmp(char_code, Operand(String::kMaxOneByteCharCode))`: 将 `char_code` (65) 与 `String::kMaxOneByteCharCode` (通常是 255) 进行比较。
2. `JumpToDeferredIf(kUnsignedGreaterThan, ...)`: 由于 65 不大于 255，所以不会跳转到延迟代码。
3. `bind(char_code_fits_one_byte)`: 执行该标签下的代码。
4. `LoadSingleCharacterString(result, char_code, scratch)`: 调用 `LoadSingleCharacterString` 函数，该函数会从单字符字符串表中加载编码为 65 的字符串 'A' 并存储到 `result` 寄存器中。

**假设输出：** `result` 寄存器中存储指向字符串 'A' 的指针。

**用户常见的编程错误示例**

涉及到这个文件功能的常见编程错误通常与 JavaScript 的动态类型和隐式类型转换有关：

1. **字符串索引越界：**

   ```javascript
   const str = "abc";
   const char = str[5]; // undefined
   const charCode = str.charCodeAt(5); // NaN
   ```

   虽然 JavaScript 不会抛出错误，但 `charCodeAt` 在索引越界时会返回 `NaN`。在 `MaglevAssembler::StringCharCodeOrCodePointAt` 的实现中，会有相应的边界检查，超出范围时可能会跳转到调用运行时函数的慢速路径。

2. **误用 `parseInt` 或位运算符进行类型转换：**

   ```javascript
   const value = "3.14";
   const intValue1 = parseInt(value); // 3
   const intValue2 = value | 0;      // 3
   ```

   用户可能没有意识到 `parseInt` 只会解析整数部分，或者位运算符会进行隐式的类型转换并截断小数部分。`MaglevAssembler::TruncateDoubleToInt32` 等函数实现了这种截断逻辑。

3. **对非字符串类型调用字符串方法：**

   ```javascript
   const num = 123;
   // num.charCodeAt(0); // TypeError: num.charCodeAt is not a function
   ```

   虽然这不是 `maglev-assembler-arm.cc` 直接处理的错误，但在 Maglev 编译的代码中，会存在类型检查，以确保操作是在正确的类型上进行的。如果类型不匹配，可能会导致反优化。

**关于 `.tq` 结尾**

你提到如果文件以 `.tq` 结尾，它将是 V8 Torque 源代码。Torque 是 V8 用于定义运行时内置函数和一些关键的编译器辅助函数的 DSL (Domain Specific Language)。`.tq` 文件会被编译成 C++ 代码。  `v8/src/maglev/arm/maglev-assembler-arm.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，包含了 `MaglevAssembler` 在 ARM 架构下的具体汇编指令生成逻辑。

总结来说，`v8/src/maglev/arm/maglev-assembler-arm.cc` 是 V8 Maglev 编译器针对 ARM 架构生成目标代码的核心组件，它实现了内存分配、函数序言/尾声、字符串操作、数字类型转换等关键功能，这些功能直接支撑着 JavaScript 代码的高效执行。

### 提示词
```
这是目录为v8/src/maglev/arm/maglev-assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/arm/maglev-assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/interface-descriptors-inl.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-graph.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm->

namespace {
void SubSizeAndTagObject(MaglevAssembler* masm, Register object,
                         Register size_in_bytes) {
  __ sub(object, object, size_in_bytes, LeaveCC);
  __ add(object, object, Operand(kHeapObjectTag), LeaveCC);
}

void SubSizeAndTagObject(MaglevAssembler* masm, Register object,
                         int size_in_bytes) {
  __ add(object, object, Operand(kHeapObjectTag - size_in_bytes), LeaveCC);
}

template <typename T>
void AllocateRaw(MaglevAssembler* masm, Isolate* isolate,
                 RegisterSnapshot register_snapshot, Register object,
                 T size_in_bytes, AllocationType alloc_type,
                 AllocationAlignment alignment) {
  // TODO(victorgomes): Call the runtime for large object allocation.
  // TODO(victorgomes): Support double alignment.
  DCHECK(masm->allow_allocate());
  DCHECK_EQ(alignment, kTaggedAligned);
  if (v8_flags.single_generation) {
    alloc_type = AllocationType::kOld;
  }
  ExternalReference top = SpaceAllocationTopAddress(isolate, alloc_type);
  ExternalReference limit = SpaceAllocationLimitAddress(isolate, alloc_type);
  ZoneLabelRef done(masm);
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  // We are a bit short on registers, so we use the same register for {object}
  // and {new_top}. Once we have defined {new_top}, we don't use {object} until
  // {new_top} is used for the last time. And there (at the end of this
  // function), we recover the original {object} from {new_top} by subtracting
  // {size_in_bytes}.
  Register new_top = object;
  // Check if there is enough space.
  __ ldr(object, __ ExternalReferenceAsOperand(top, scratch));
  __ add(new_top, object, Operand(size_in_bytes), LeaveCC);
  __ ldr(scratch, __ ExternalReferenceAsOperand(limit, scratch));
  __ cmp(new_top, scratch);
  // Otherwise call runtime.
  __ JumpToDeferredIf(kUnsignedGreaterThanEqual, AllocateSlow<T>,
                      register_snapshot, object, AllocateBuiltin(alloc_type),
                      size_in_bytes, done);
  // Store new top and tag object.
  __ Move(__ ExternalReferenceAsOperand(top, scratch), new_top);
  SubSizeAndTagObject(masm, object, size_in_bytes);
  __ bind(*done);
}
}  // namespace

void MaglevAssembler::Allocate(RegisterSnapshot register_snapshot,
                               Register object, int size_in_bytes,
                               AllocationType alloc_type,
                               AllocationAlignment alignment) {
  AllocateRaw(this, isolate_, register_snapshot, object, size_in_bytes,
              alloc_type, alignment);
}

void MaglevAssembler::Allocate(RegisterSnapshot register_snapshot,
                               Register object, Register size_in_bytes,
                               AllocationType alloc_type,
                               AllocationAlignment alignment) {
  AllocateRaw(this, isolate_, register_snapshot, object, size_in_bytes,
              alloc_type, alignment);
}

void MaglevAssembler::OSRPrologue(Graph* graph) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();

  DCHECK(graph->is_osr());
  CHECK(!graph->has_recursive_calls());

  uint32_t source_frame_size =
      graph->min_maglev_stackslots_for_unoptimized_frame_size();

  if (v8_flags.maglev_assert_stack_size && v8_flags.debug_code) {
    add(scratch, sp,
        Operand(source_frame_size * kSystemPointerSize +
                StandardFrameConstants::kFixedFrameSizeFromFp));
    cmp(scratch, fp);
    Assert(eq, AbortReason::kOsrUnexpectedStackSize);
  }

  uint32_t target_frame_size =
      graph->tagged_stack_slots() + graph->untagged_stack_slots();
  CHECK_LE(source_frame_size, target_frame_size);

  if (source_frame_size < target_frame_size) {
    ASM_CODE_COMMENT_STRING(this, "Growing frame for OSR");
    uint32_t additional_tagged =
        source_frame_size < graph->tagged_stack_slots()
            ? graph->tagged_stack_slots() - source_frame_size
            : 0;
    if (additional_tagged) {
      Move(scratch, 0);
    }
    for (size_t i = 0; i < additional_tagged; ++i) {
      Push(scratch);
    }
    uint32_t size_so_far = source_frame_size + additional_tagged;
    CHECK_LE(size_so_far, target_frame_size);
    if (size_so_far < target_frame_size) {
      sub(sp, sp,
          Operand((target_frame_size - size_so_far) * kSystemPointerSize));
    }
  }
}

void MaglevAssembler::Prologue(Graph* graph) {
  TemporaryRegisterScope temps(this);
  temps.Include({r4, r8});

  DCHECK(!graph->is_osr());

  BailoutIfDeoptimized();

  if (graph->has_recursive_calls()) {
    bind(code_gen_state()->entry_label());
  }

  // Tiering support.
  if (v8_flags.turbofan) {
    using D = MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor;
    Register flags = D::GetRegisterParameter(D::kFlags);
    Register feedback_vector = D::GetRegisterParameter(D::kFeedbackVector);
    DCHECK(!AreAliased(flags, feedback_vector, kJavaScriptCallArgCountRegister,
                       kJSFunctionRegister, kContextRegister,
                       kJavaScriptCallNewTargetRegister));
    DCHECK(!temps.Available().has(flags));
    DCHECK(!temps.Available().has(feedback_vector));
    Move(feedback_vector,
         compilation_info()->toplevel_compilation_unit()->feedback().object());
    Condition needs_processing =
        LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(flags, feedback_vector,
                                                         CodeKind::MAGLEV);
    // Tail call on Arm produces 3 instructions, so we emit that in deferred
    // code.
    JumpToDeferredIf(needs_processing, [](MaglevAssembler* masm) {
      __ TailCallBuiltin(
          Builtin::kMaglevOptimizeCodeOrTailCallOptimizedCodeSlot);
    });
  }

  EnterFrame(StackFrame::MAGLEV);
  // Save arguments in frame.
  // TODO(leszeks): Consider eliding this frame if we don't make any calls
  // that could clobber these registers.
  Push(kContextRegister);
  Push(kJSFunctionRegister);              // Callee's JS function.
  Push(kJavaScriptCallArgCountRegister);  // Actual argument count.

  // Initialize stack slots.
  if (graph->tagged_stack_slots() > 0) {
    ASM_CODE_COMMENT_STRING(this, "Initializing stack slots");
    TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    Move(scratch, 0);

    // Magic value. Experimentally, an unroll size of 8 doesn't seem any
    // worse than fully unrolled pushes.
    const int kLoopUnrollSize = 8;
    int tagged_slots = graph->tagged_stack_slots();
    if (tagged_slots < kLoopUnrollSize) {
      // If the frame is small enough, just unroll the frame fill
      // completely.
      for (int i = 0; i < tagged_slots; ++i) {
        Push(scratch);
      }
    } else {
      // Extract the first few slots to round to the unroll size.
      int first_slots = tagged_slots % kLoopUnrollSize;
      for (int i = 0; i < first_slots; ++i) {
        Push(scratch);
      }
      Register unroll_counter = temps.AcquireScratch();
      Move(unroll_counter, tagged_slots / kLoopUnrollSize);
      // We enter the loop unconditionally, so make sure we need to loop at
      // least once.
      DCHECK_GT(tagged_slots / kLoopUnrollSize, 0);
      Label loop;
      bind(&loop);
      for (int i = 0; i < kLoopUnrollSize; ++i) {
        Push(scratch);
      }
      sub(unroll_counter, unroll_counter, Operand(1), SetCC);
      b(kGreaterThan, &loop);
    }
  }
  if (graph->untagged_stack_slots() > 0) {
    // Extend rsp by the size of the remaining untagged part of the frame,
    // no need to initialise these.
    sub(sp, sp, Operand(graph->untagged_stack_slots() * kSystemPointerSize));
  }
}

void MaglevAssembler::MaybeEmitDeoptBuiltinsCall(size_t eager_deopt_count,
                                                 Label* eager_deopt_entry,
                                                 size_t lazy_deopt_count,
                                                 Label* lazy_deopt_entry) {
  CheckConstPool(true, false);
}

void MaglevAssembler::LoadSingleCharacterString(Register result,
                                                Register char_code,
                                                Register scratch) {
  DCHECK_NE(char_code, scratch);
  if (v8_flags.debug_code) {
    cmp(char_code, Operand(String::kMaxOneByteCharCode));
    Assert(kUnsignedLessThanEqual, AbortReason::kUnexpectedValue);
  }
  Register table = scratch;
  LoadRoot(table, RootIndex::kSingleCharacterStringTable);
  add(table, table, Operand(char_code, LSL, kTaggedSizeLog2));
  ldr(result, FieldMemOperand(table, OFFSET_OF_DATA_START(FixedArray)));
}

void MaglevAssembler::StringFromCharCode(RegisterSnapshot register_snapshot,
                                         Label* char_code_fits_one_byte,
                                         Register result, Register char_code,
                                         Register scratch,
                                         CharCodeMaskMode mask_mode) {
  AssertZeroExtended(char_code);
  DCHECK_NE(char_code, scratch);
  ZoneLabelRef done(this);
  if (mask_mode == CharCodeMaskMode::kMustApplyMask) {
    and_(char_code, char_code, Operand(0xFFFF));
  }
  cmp(char_code, Operand(String::kMaxOneByteCharCode));
  JumpToDeferredIf(
      kUnsignedGreaterThan,
      [](MaglevAssembler* masm, RegisterSnapshot register_snapshot,
         ZoneLabelRef done, Register result, Register char_code,
         Register scratch) {
        // Be sure to save {char_code}. If it aliases with {result}, use
        // the scratch register.
        // TODO(victorgomes): This is probably not needed any more, because
        // we now ensure that results registers don't alias with inputs/temps.
        // Confirm, and drop this check.
        if (char_code == result) {
          __ Move(scratch, char_code);
          char_code = scratch;
        }
        DCHECK_NE(char_code, result);
        DCHECK(!register_snapshot.live_tagged_registers.has(char_code));
        register_snapshot.live_registers.set(char_code);
        __ AllocateTwoByteString(register_snapshot, result, 1);
        __ strh(char_code, FieldMemOperand(
                               result, OFFSET_OF_DATA_START(SeqTwoByteString)));
        __ b(*done);
      },
      register_snapshot, done, result, char_code, scratch);
  if (char_code_fits_one_byte != nullptr) {
    bind(char_code_fits_one_byte);
  }
  LoadSingleCharacterString(result, char_code, scratch);
  bind(*done);
}

void MaglevAssembler::StringCharCodeOrCodePointAt(
    BuiltinStringPrototypeCharCodeOrCodePointAt::Mode mode,
    RegisterSnapshot& register_snapshot, Register result, Register string,
    Register index, Register instance_type, Register scratch2,
    Label* result_fits_one_byte) {
  ZoneLabelRef done(this);
  Label seq_string;
  Label cons_string;
  Label sliced_string;

  Label* deferred_runtime_call = MakeDeferredCode(
      [](MaglevAssembler* masm,
         BuiltinStringPrototypeCharCodeOrCodePointAt::Mode mode,
         RegisterSnapshot register_snapshot, ZoneLabelRef done, Register result,
         Register string, Register index) {
        DCHECK(!register_snapshot.live_registers.has(result));
        DCHECK(!register_snapshot.live_registers.has(string));
        DCHECK(!register_snapshot.live_registers.has(index));
        {
          SaveRegisterStateForCall save_register_state(masm, register_snapshot);
          __ SmiTag(index);
          __ Push(string, index);
          __ Move(kContextRegister, masm->native_context().object());
          // This call does not throw nor can deopt.
          if (mode ==
              BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt) {
            __ CallRuntime(Runtime::kStringCodePointAt);
          } else {
            DCHECK_EQ(mode,
                      BuiltinStringPrototypeCharCodeOrCodePointAt::kCharCodeAt);
            __ CallRuntime(Runtime::kStringCharCodeAt);
          }
          save_register_state.DefineSafepoint();
          __ SmiUntag(kReturnRegister0);
          __ Move(result, kReturnRegister0);
        }
        __ b(*done);
      },
      mode, register_snapshot, done, result, string, index);

  // We might need to try more than one time for ConsString, SlicedString and
  // ThinString.
  Label loop;
  bind(&loop);

  if (v8_flags.debug_code) {
    // Check if {string} is a string.
    AssertObjectTypeInRange(string, FIRST_STRING_TYPE, LAST_STRING_TYPE,
                            AbortReason::kUnexpectedValue);

    Register scratch = instance_type;
    ldr(scratch, FieldMemOperand(string, offsetof(String, length_)));
    cmp(index, scratch);
    Check(lo, AbortReason::kUnexpectedValue);
  }

  // Get instance type.
  LoadInstanceType(instance_type, string);

  {
    TemporaryRegisterScope temps(this);
    Register representation = temps.AcquireScratch();

    // TODO(victorgomes): Add fast path for external strings.
    and_(representation, instance_type, Operand(kStringRepresentationMask));
    cmp(representation, Operand(kSeqStringTag));
    b(eq, &seq_string);
    cmp(representation, Operand(kConsStringTag));
    b(eq, &cons_string);
    cmp(representation, Operand(kSlicedStringTag));
    b(eq, &sliced_string);
    cmp(representation, Operand(kThinStringTag));
    b(ne, deferred_runtime_call);
    // Fallthrough to thin string.
  }

  // Is a thin string.
  {
    ldr(string, FieldMemOperand(string, offsetof(ThinString, actual_)));
    b(&loop);
  }

  bind(&sliced_string);
  {
    TemporaryRegisterScope temps(this);
    Register offset = temps.AcquireScratch();

    LoadAndUntagTaggedSignedField(offset, string,
                                  offsetof(SlicedString, offset_));
    LoadTaggedField(string, string, offsetof(SlicedString, parent_));
    add(index, index, offset);
    b(&loop);
  }

  bind(&cons_string);
  {
    // Reuse {instance_type} register here, since CompareRoot requires a scratch
    // register as well.
    Register second_string = instance_type;
    ldr(second_string, FieldMemOperand(string, offsetof(ConsString, second_)));
    CompareRoot(second_string, RootIndex::kempty_string);
    b(ne, deferred_runtime_call);
    ldr(string, FieldMemOperand(string, offsetof(ConsString, first_)));
    b(&loop);  // Try again with first string.
  }

  bind(&seq_string);
  {
    Label two_byte_string;
    tst(instance_type, Operand(kOneByteStringTag));
    b(eq, &two_byte_string);
    // The result of one-byte string will be the same for both modes
    // (CharCodeAt/CodePointAt), since it cannot be the first half of a
    // surrogate pair.
    add(index, index,
        Operand(OFFSET_OF_DATA_START(SeqOneByteString) - kHeapObjectTag));
    ldrb(result, MemOperand(string, index));
    b(result_fits_one_byte);

    bind(&two_byte_string);
    // {instance_type} is unused from this point, so we can use as scratch.
    Register scratch = instance_type;
    lsl(scratch, index, Operand(1));
    add(scratch, scratch,
        Operand(OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag));

    if (mode == BuiltinStringPrototypeCharCodeOrCodePointAt::kCharCodeAt) {
      ldrh(result, MemOperand(string, scratch));
    } else {
      DCHECK_EQ(mode,
                BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt);
      Register string_backup = string;
      if (result == string) {
        string_backup = scratch2;
        Move(string_backup, string);
      }
      ldrh(result, MemOperand(string, scratch));

      Register first_code_point = scratch;
      and_(first_code_point, result, Operand(0xfc00));
      cmp(first_code_point, Operand(0xd800));
      b(ne, *done);

      Register length = scratch;
      ldr(length, FieldMemOperand(string_backup, offsetof(String, length_)));
      add(index, index, Operand(1));
      cmp(index, length);
      b(ge, *done);

      Register second_code_point = scratch;
      lsl(index, index, Operand(1));
      add(index, index,
          Operand(OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag));
      ldrh(second_code_point, MemOperand(string_backup, index));

      // {index} is not needed at this point.
      Register scratch2 = index;
      and_(scratch2, second_code_point, Operand(0xfc00));
      cmp(scratch2, Operand(0xdc00));
      b(ne, *done);

      int surrogate_offset = 0x10000 - (0xd800 << 10) - 0xdc00;
      add(second_code_point, second_code_point, Operand(surrogate_offset));
      lsl(result, result, Operand(10));
      add(result, result, second_code_point);
    }

    // Fallthrough.
  }

  bind(*done);

  if (v8_flags.debug_code) {
    // We make sure that the user of this macro is not relying in string and
    // index to not be clobbered.
    if (result != string) {
      Move(string, 0xdeadbeef);
    }
    if (result != index) {
      Move(index, 0xdeadbeef);
    }
  }
}

void MaglevAssembler::TruncateDoubleToInt32(Register dst, DoubleRegister src) {
  ZoneLabelRef done(this);
  Label* slow_path = MakeDeferredCode(
      [](MaglevAssembler* masm, DoubleRegister src, Register dst,
         ZoneLabelRef done) {
        __ push(lr);
        __ AllocateStackSpace(kDoubleSize);
        __ vstr(src, MemOperand(sp, 0));
        __ CallBuiltin(Builtin::kDoubleToI);
        __ ldr(dst, MemOperand(sp, 0));
        __ add(sp, sp, Operand(kDoubleSize));
        __ pop(lr);
        __ Jump(*done);
      },
      src, dst, done);
  TryInlineTruncateDoubleToI(dst, src, *done);
  Jump(slow_path);
  bind(*done);
}

void MaglevAssembler::TryTruncateDoubleToInt32(Register dst, DoubleRegister src,
                                               Label* fail) {
  UseScratchRegisterScope temps(this);
  LowDwVfpRegister low_double = temps.AcquireLowD();
  SwVfpRegister temp_vfps = low_double.low();
  DoubleRegister converted_back = low_double;
  Label done;

  // Convert the input float64 value to int32.
  vcvt_s32_f64(temp_vfps, src);
  vmov(dst, temp_vfps);

  // Convert that int32 value back to float64.
  vcvt_f64_s32(converted_back, temp_vfps);

  // Check that the result of the float64->int32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate.
  VFPCompareAndSetFlags(src, converted_back);
  JumpIf(kNotEqual, fail);

  // Check if {input} is -0.
  tst(dst, dst);
  JumpIf(kNotEqual, &done);

  // In case of 0, we need to check the high bits for the IEEE -0 pattern.
  {
    Register high_word32_of_input = temps.Acquire();
    VmovHigh(high_word32_of_input, src);
    cmp(high_word32_of_input, Operand(0));
    JumpIf(kLessThan, fail);
  }

  bind(&done);
}

void MaglevAssembler::TryTruncateDoubleToUint32(Register dst,
                                                DoubleRegister src,
                                                Label* fail) {
  UseScratchRegisterScope temps(this);
  LowDwVfpRegister low_double = temps.AcquireLowD();
  SwVfpRegister temp_vfps = low_double.low();
  DoubleRegister converted_back = low_double;
  Label done;

  // Convert the input float64 value to uint32.
  vcvt_u32_f64(temp_vfps, src);
  vmov(dst, temp_vfps);

  // Convert that uint32 value back to float64.
  vcvt_f64_u32(converted_back, temp_vfps);

  // Check that the result of the float64->uint32->float64 is equal to the input
  // (i.e. that the conversion didn't truncate.
  VFPCompareAndSetFlags(src, converted_back);
  JumpIf(kNotEqual, fail);

  // Check if {input} is -0.
  tst(dst, dst);
  JumpIf(kNotEqual, &done);

  // In case of 0, we need to check the high bits for the IEEE -0 pattern.
  {
    Register high_word32_of_input = temps.Acquire();
    VmovHigh(high_word32_of_input, src);
    cmp(high_word32_of_input, Operand(0));
    JumpIf(kLessThan, fail);
  }

  bind(&done);
}

void MaglevAssembler::TryChangeFloat64ToIndex(Register result,
                                              DoubleRegister value,
                                              Label* success, Label* fail) {
  UseScratchRegisterScope temps(this);
  LowDwVfpRegister low_double = temps.AcquireLowD();
  SwVfpRegister temp_vfps = low_double.low();
  DoubleRegister converted_back = low_double;
  // Convert the input float64 value to int32.
  vcvt_s32_f64(temp_vfps, value);
  vmov(result, temp_vfps);
  // Convert that int32 value back to float64.
  vcvt_f64_s32(converted_back, temp_vfps);
  // Check that the result of the float64->int32->float64 is equal to
  // the input (i.e. that the conversion didn't truncate).
  VFPCompareAndSetFlags(value, converted_back);
  JumpIf(kNotEqual, fail);
  Jump(success);
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8
```