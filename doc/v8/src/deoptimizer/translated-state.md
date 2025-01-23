Response: The user wants to understand the functionality of the C++ source code file `v8/src/deoptimizer/translated-state.cc`. The request is in two parts, and this is part 1.

The core functionality seems to be related to how V8 handles deoptimization, a process where optimized code needs to revert to less optimized code. The file likely deals with capturing and representing the state of the program (registers, stack, etc.) at the point of deoptimization.

Here's a breakdown of the key elements observed in the code:

1. **Translation Opcodes:**  The code uses an enum or set of constants called `TranslationOpcode`. These opcodes represent different kinds of information being captured during deoptimization, such as register values, stack slot values, literals, and frame boundaries.

2. **`TranslatedValue` Class:** This class appears to be a container for a single piece of translated state. It can hold different types of values (tagged objects, integers, floats, etc.) and has information about where the value came from (register, stack slot, literal).

3. **`TranslatedFrame` Class:**  This class likely represents a single stack frame as part of the translated state. It contains information about the function, bytecode offset, and a collection of `TranslatedValue` objects representing the state within that frame.

4. **`TranslatedState` Class:** This seems to be the main class that aggregates the translated state for the entire deoptimization process. It holds a collection of `TranslatedFrame` objects and potentially other relevant information.

5. **Deoptimization Literals:** The code interacts with `DeoptimizationLiteralArray` and `ProtectedDeoptimizationLiteralArray`. These seem to be arrays storing constant values (literals) used in the optimized code, which need to be recovered during deoptimization.

6. **Materialization:**  The code mentions "materialization." This refers to the process of reconstructing actual JavaScript objects or values from the translated state.

7. **Relationship to JavaScript:** The code deals with concepts directly related to JavaScript execution, such as stack frames, function calls, arguments, and different types of JavaScript values (numbers, strings, booleans).

To illustrate the connection to JavaScript, consider a simple scenario: a function is optimized, and then a condition occurs that triggers deoptimization. The `translated-state.cc` file would be involved in capturing the current state, including the values of variables, the call stack, and any literal values being used.

Let's construct a JavaScript example and imagine how the code might represent its state during deoptimization.
这是 `v8/src/deoptimizer/translated-state.cc` 文件的第一部分，其主要功能是定义了用于**表示和操作去优化 (deoptimization) 过程中的程序状态**的数据结构和方法。

更具体地说，它定义了以下关键组件：

*   **`TranslationOpcode`**:  一个枚举或一组常量，用于表示去优化数据流中的不同类型的操作。这些操作码描述了如何在去优化时转换和解释程序的状态，例如，从寄存器或栈槽中读取值，或者表示一个函数调用帧的开始。

*   **`TranslatedValue`**:  一个类，用于表示去优化状态中的单个值。它可以存储不同类型的值（例如，原始对象、整数、浮点数），并记录该值的来源（例如，寄存器、栈槽、字面量）。  它还包含用于后续“物化”（materialization）该值的必要信息。

*   **`TranslatedFrame`**:  一个类，用于表示去优化状态中的一个函数调用帧。它包含有关该帧的信息，例如对应的 `SharedFunctionInfo`（共享函数信息，包含函数元数据）、`BytecodeArray`（字节码数组）、以及一系列 `TranslatedValue` 对象，这些对象表示该帧内的变量和寄存器状态。

*   **`TranslatedState`**:  （尽管这部分代码没有完整展示 `TranslatedState`，但从上下文可以推断）这是一个主要的类，用于管理整个去优化过程的状态。它可能包含一个 `TranslatedFrame` 的列表，以及其他去优化所需的信息。

*   **`DeoptimizationLiteralProvider`**:  一个辅助类，用于提供在去优化过程中使用的字面量值。这些字面量可能存储在堆上或堆外。

**与 JavaScript 的关系及示例**

`translated-state.cc` 文件直接关联着 V8 引擎执行 JavaScript 代码的过程。当一段 JavaScript 代码被 V8 的优化编译器（例如 TurboFan）优化后，如果运行时环境不满足优化的假设，就需要进行去优化，回到解释执行的状态。

`translated-state.cc` 中定义的结构体和类，就是用来捕获和表示从优化代码回退到解释代码所需的程序状态。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

// 假设 'add' 函数被优化了

let result = add(1, 2); // 第一次调用，可能触发优化

result = add("hello", "world"); // 第二次调用，参数类型变化，可能触发去优化
```

当执行到第二次调用 `add("hello", "world")` 时，由于参数类型从数字变为字符串，之前基于数字优化的代码可能不再适用，V8 可能会触发去优化。

在这个去优化过程中，`translated-state.cc` 中定义的类会发挥作用：

1. **`TranslatedFrame`**:  会创建一个表示 `add` 函数调用帧的 `TranslatedFrame` 对象。这个对象会记录 `add` 函数的 `SharedFunctionInfo`（包含函数名 "add" 等信息）。

2. **`TranslatedValue`**:
    *   会创建 `TranslatedValue` 对象来表示 `add` 函数的参数 `a` 和 `b` 的当前值（"hello" 和 "world"）。
    *   可能还会创建 `TranslatedValue` 对象来表示在优化代码执行过程中使用的寄存器的值。

3. **`TranslationOpcode`**:  在解析去优化数据时，会遇到各种 `TranslationOpcode`，指示如何读取和解释这些值。例如，可能会有操作码指示从某个寄存器读取一个字符串值，或者指示当前正在处理一个 JavaScript 函数调用帧。

4. **`TranslatedState`**:  `TranslatedState` 对象会包含上述 `TranslatedFrame` 和 `TranslatedValue` 对象，从而完整地表示了去优化时的程序状态。

**代码片段中的具体功能：**

代码片段中的 `DeoptimizationFrameTranslationPrintSingleOpcode` 函数负责**打印单个去优化操作码及其操作数的信息**，用于调试和分析去优化过程。  它根据不同的 `TranslationOpcode`，从 `DeoptimizationFrameTranslation::Iterator` 中读取相应的操作数，并以人类可读的格式输出。这有助于理解去优化数据的结构和内容。

代码片段中还定义了 `TranslatedValue` 的一些静态工厂方法，例如 `NewDeferredObject`、`NewDuplicateObject`、`NewStringConcat`、`NewFloat`、`NewDouble` 等，用于**创建不同类型的 `TranslatedValue` 对象**。这些方法隐藏了 `TranslatedValue` 对象的创建细节，并提供了一种方便的方式来表示不同类型的去优化状态值。

总而言之，`v8/src/deoptimizer/translated-state.cc` 的第一部分定义了用于表示去优化状态的基础数据结构，为 V8 引擎处理代码优化和去优化提供了关键的支持。它允许 V8 精确地捕获程序在去优化点的状态，以便安全地回退到解释执行，保证 JavaScript 代码的正确执行。

### 提示词
```
这是目录为v8/src/deoptimizer/translated-state.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/deoptimizer/translated-state.h"

#include <inttypes.h>

#include <iomanip>
#include <optional>

#include "src/base/memory.h"
#include "src/common/assert-scope.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/deoptimizer/materialized-object-store.h"
#include "src/deoptimizer/translation-opcode.h"
#include "src/diagnostics/disasm.h"
#include "src/execution/frames.h"
#include "src/execution/isolate.h"
#include "src/heap/heap.h"
#include "src/numbers/conversions.h"
#include "src/objects/arguments.h"
#include "src/objects/deoptimization-data.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/heap-object.h"
#include "src/objects/oddball.h"

// Has to be the last include (doesn't have include guards)
#include "src/objects/object-macros.h"
#include "src/objects/string.h"

namespace v8 {

using base::Memory;
using base::ReadUnalignedValue;

namespace internal {

void DeoptimizationFrameTranslationPrintSingleOpcode(
    std::ostream& os, TranslationOpcode opcode,
    DeoptimizationFrameTranslation::Iterator& iterator,
    Tagged<ProtectedDeoptimizationLiteralArray> protected_literal_array,
    Tagged<DeoptimizationLiteralArray> literal_array) {
  disasm::NameConverter converter;
  switch (opcode) {
    case TranslationOpcode::BEGIN_WITH_FEEDBACK:
    case TranslationOpcode::BEGIN_WITHOUT_FEEDBACK:
    case TranslationOpcode::MATCH_PREVIOUS_TRANSLATION: {
      iterator.NextOperand();  // Skip the lookback distance.
      int frame_count = iterator.NextOperand();
      int jsframe_count = iterator.NextOperand();
      os << "{frame count=" << frame_count
         << ", js frame count=" << jsframe_count << "}";
      break;
    }

    case TranslationOpcode::INTERPRETED_FRAME_WITH_RETURN:
    case TranslationOpcode::INTERPRETED_FRAME_WITHOUT_RETURN: {
      int bytecode_offset = iterator.NextOperand();
      int shared_info_id = iterator.NextOperand();
      int bytecode_array_id = iterator.NextOperand();
      unsigned height = iterator.NextOperand();
      int return_value_offset = 0;
      int return_value_count = 0;
      if (opcode == TranslationOpcode::INTERPRETED_FRAME_WITH_RETURN) {
        DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 5);
        return_value_offset = iterator.NextOperand();
        return_value_count = iterator.NextOperand();
      } else {
        DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 3);
      }
      Tagged<Object> shared_info = literal_array->get(shared_info_id);
      Tagged<Object> bytecode_array =
          protected_literal_array->get(bytecode_array_id);
      os << "{bytecode_offset=" << bytecode_offset << ", function="
         << Cast<SharedFunctionInfo>(shared_info)->DebugNameCStr().get()
         << ", bytecode=" << Brief(bytecode_array) << ", height=" << height
         << ", retval=@" << return_value_offset << "(#" << return_value_count
         << ")}";
      break;
    }

#if V8_ENABLE_WEBASSEMBLY
    case TranslationOpcode::WASM_INLINED_INTO_JS_FRAME: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 3);
      int bailout_id = iterator.NextOperand();
      int shared_info_id = iterator.NextOperand();
      Tagged<Object> shared_info = literal_array->get(shared_info_id);
      unsigned height = iterator.NextOperand();
      os << "{bailout_id=" << bailout_id << ", function="
         << Cast<SharedFunctionInfo>(shared_info)->DebugNameCStr().get()
         << ", height=" << height << "}";
      break;
    }
#endif
    case TranslationOpcode::CONSTRUCT_CREATE_STUB_FRAME: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 2);
      int shared_info_id = iterator.NextOperand();
      Tagged<Object> shared_info = literal_array->get(shared_info_id);
      unsigned height = iterator.NextOperand();
      os << "{construct create stub, function="
         << Cast<SharedFunctionInfo>(shared_info)->DebugNameCStr().get()
         << ", height=" << height << "}";
      break;
    }

    case TranslationOpcode::CONSTRUCT_INVOKE_STUB_FRAME: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int shared_info_id = iterator.NextOperand();
      Tagged<Object> shared_info = literal_array->get(shared_info_id);
      os << "{construct invoke stub, function="
         << Cast<SharedFunctionInfo>(shared_info)->DebugNameCStr().get() << "}";
      break;
    }

    case TranslationOpcode::BUILTIN_CONTINUATION_FRAME:
    case TranslationOpcode::JAVASCRIPT_BUILTIN_CONTINUATION_FRAME:
    case TranslationOpcode::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH_FRAME: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 3);
      int bailout_id = iterator.NextOperand();
      int shared_info_id = iterator.NextOperand();
      Tagged<Object> shared_info = literal_array->get(shared_info_id);
      unsigned height = iterator.NextOperand();
      os << "{bailout_id=" << bailout_id << ", function="
         << Cast<SharedFunctionInfo>(shared_info)->DebugNameCStr().get()
         << ", height=" << height << "}";
      break;
    }

#if V8_ENABLE_WEBASSEMBLY
    case TranslationOpcode::JS_TO_WASM_BUILTIN_CONTINUATION_FRAME: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 4);
      int bailout_id = iterator.NextOperand();
      int shared_info_id = iterator.NextOperand();
      Tagged<Object> shared_info = literal_array->get(shared_info_id);
      unsigned height = iterator.NextOperand();
      int wasm_return_type = iterator.NextOperand();
      os << "{bailout_id=" << bailout_id << ", function="
         << Cast<SharedFunctionInfo>(shared_info)->DebugNameCStr().get()
         << ", height=" << height << ", wasm_return_type=" << wasm_return_type
         << "}";
      break;
    }

    case v8::internal::TranslationOpcode::LIFTOFF_FRAME: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 3);
      int bailout_id = iterator.NextOperand();
      unsigned height = iterator.NextOperand();
      unsigned function_id = iterator.NextOperand();
      os << "{bailout_id=" << bailout_id << ", height=" << height
         << ", function_id=" << function_id << "}";
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    case TranslationOpcode::INLINED_EXTRA_ARGUMENTS: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 2);
      int shared_info_id = iterator.NextOperand();
      Tagged<Object> shared_info = literal_array->get(shared_info_id);
      unsigned height = iterator.NextOperand();
      os << "{function="
         << Cast<SharedFunctionInfo>(shared_info)->DebugNameCStr().get()
         << ", height=" << height << "}";
      break;
    }

    case TranslationOpcode::REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << converter.NameOfCPURegister(reg_code) << "}";
      break;
    }

    case TranslationOpcode::INT32_REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << converter.NameOfCPURegister(reg_code) << " (int32)}";
      break;
    }

    case TranslationOpcode::INT64_REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << converter.NameOfCPURegister(reg_code) << " (int64)}";
      break;
    }

    case TranslationOpcode::SIGNED_BIGINT64_REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << converter.NameOfCPURegister(reg_code)
         << " (signed bigint64)}";
      break;
    }

    case TranslationOpcode::UNSIGNED_BIGINT64_REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << converter.NameOfCPURegister(reg_code)
         << " (unsigned bigint64)}";
      break;
    }

    case TranslationOpcode::UINT32_REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << converter.NameOfCPURegister(reg_code) << " (uint32)}";
      break;
    }

    case TranslationOpcode::BOOL_REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << converter.NameOfCPURegister(reg_code) << " (bool)}";
      break;
    }

    case TranslationOpcode::FLOAT_REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << FloatRegister::from_code(reg_code) << "}";
      break;
    }

    case TranslationOpcode::DOUBLE_REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << DoubleRegister::from_code(reg_code) << "}";
      break;
    }

    case TranslationOpcode::HOLEY_DOUBLE_REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << DoubleRegister::from_code(reg_code) << " (holey)}";
      break;
    }

    case TranslationOpcode::SIMD128_REGISTER: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int reg_code = iterator.NextOperandUnsigned();
      os << "{input=" << Simd128Register::from_code(reg_code) << " (Simd128)}";
      break;
    }

    case TranslationOpcode::TAGGED_STACK_SLOT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int input_slot_index = iterator.NextOperand();
      os << "{input=" << input_slot_index << "}";
      break;
    }

    case TranslationOpcode::INT32_STACK_SLOT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int input_slot_index = iterator.NextOperand();
      os << "{input=" << input_slot_index << " (int32)}";
      break;
    }

    case TranslationOpcode::INT64_STACK_SLOT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int input_slot_index = iterator.NextOperand();
      os << "{input=" << input_slot_index << " (int64)}";
      break;
    }

    case TranslationOpcode::SIGNED_BIGINT64_STACK_SLOT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int input_slot_index = iterator.NextOperand();
      os << "{input=" << input_slot_index << " (signed bigint64)}";
      break;
    }

    case TranslationOpcode::UNSIGNED_BIGINT64_STACK_SLOT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int input_slot_index = iterator.NextOperand();
      os << "{input=" << input_slot_index << " (unsigned bigint64)}";
      break;
    }

    case TranslationOpcode::UINT32_STACK_SLOT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int input_slot_index = iterator.NextOperand();
      os << "{input=" << input_slot_index << " (uint32)}";
      break;
    }

    case TranslationOpcode::BOOL_STACK_SLOT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int input_slot_index = iterator.NextOperand();
      os << "{input=" << input_slot_index << " (bool)}";
      break;
    }

    case TranslationOpcode::FLOAT_STACK_SLOT:
    case TranslationOpcode::DOUBLE_STACK_SLOT:
    case TranslationOpcode::SIMD128_STACK_SLOT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int input_slot_index = iterator.NextOperand();
      os << "{input=" << input_slot_index << "}";
      break;
    }

    case TranslationOpcode::HOLEY_DOUBLE_STACK_SLOT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int input_slot_index = iterator.NextOperand();
      os << "{input=" << input_slot_index << " (holey)}";
      break;
    }

    case TranslationOpcode::OPTIMIZED_OUT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 0);
      os << "{optimized_out}}";
      break;
    }

    case TranslationOpcode::LITERAL: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int literal_index = iterator.NextOperand();
      Tagged<Object> literal_value = literal_array->get(literal_index);
      os << "{literal_id=" << literal_index << " (" << Brief(literal_value)
         << ")}";
      break;
    }

    case TranslationOpcode::DUPLICATED_OBJECT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int object_index = iterator.NextOperand();
      os << "{object_index=" << object_index << "}";
      break;
    }

    case TranslationOpcode::ARGUMENTS_ELEMENTS: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      CreateArgumentsType arguments_type =
          static_cast<CreateArgumentsType>(iterator.NextOperand());
      os << "{arguments_type=" << arguments_type << "}";
      break;
    }
    case TranslationOpcode::ARGUMENTS_LENGTH: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 0);
      os << "{arguments_length}";
      break;
    }
    case TranslationOpcode::REST_LENGTH: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 0);
      os << "{rest_length}";
      break;
    }

    case TranslationOpcode::CAPTURED_OBJECT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 1);
      int args_length = iterator.NextOperand();
      os << "{length=" << args_length << "}";
      break;
    }

    case TranslationOpcode::STRING_CONCAT: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 0);
      os << "{string_concat}";
      break;
    }

    case TranslationOpcode::UPDATE_FEEDBACK: {
      DCHECK_EQ(TranslationOpcodeOperandCount(opcode), 2);
      int literal_index = iterator.NextOperand();
      FeedbackSlot slot(iterator.NextOperand());
      os << "{feedback={vector_index=" << literal_index << ", slot=" << slot
         << "}}";
      break;
    }
  }
  os << "\n";
}

// static
TranslatedValue TranslatedValue::NewDeferredObject(TranslatedState* container,
                                                   int length,
                                                   int object_index) {
  TranslatedValue slot(container, kCapturedObject);
  slot.materialization_info_ = {object_index, length};
  return slot;
}

// static
TranslatedValue TranslatedValue::NewDuplicateObject(TranslatedState* container,
                                                    int id) {
  TranslatedValue slot(container, kDuplicatedObject);
  slot.materialization_info_ = {id, -1};
  return slot;
}

// static
TranslatedValue TranslatedValue::NewStringConcat(TranslatedState* container,
                                                 int id) {
  TranslatedValue slot(container, kCapturedStringConcat);
  slot.materialization_info_ = {id, -1};
  return slot;
}

// static
TranslatedValue TranslatedValue::NewFloat(TranslatedState* container,
                                          Float32 value) {
  TranslatedValue slot(container, kFloat);
  slot.float_value_ = value;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewDouble(TranslatedState* container,
                                           Float64 value) {
  TranslatedValue slot(container, kDouble);
  slot.double_value_ = value;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewHoleyDouble(TranslatedState* container,
                                                Float64 value) {
  TranslatedValue slot(container, kHoleyDouble);
  slot.double_value_ = value;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewSimd128(TranslatedState* container,
                                            Simd128 value) {
  TranslatedValue slot(container, kSimd128);
  slot.simd128_value_ = value;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewInt32(TranslatedState* container,
                                          int32_t value) {
  TranslatedValue slot(container, kInt32);
  slot.int32_value_ = value;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewInt64(TranslatedState* container,
                                          int64_t value) {
  TranslatedValue slot(container, kInt64);
  slot.int64_value_ = value;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewInt64ToBigInt(TranslatedState* container,
                                                  int64_t value) {
  TranslatedValue slot(container, kInt64ToBigInt);
  slot.int64_value_ = value;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewUint64ToBigInt(TranslatedState* container,
                                                   uint64_t value) {
  TranslatedValue slot(container, kUint64ToBigInt);
  slot.uint64_value_ = value;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewUint32(TranslatedState* container,
                                           uint32_t value) {
  TranslatedValue slot(container, kUint32);
  slot.uint32_value_ = value;
  return slot;
}

TranslatedValue TranslatedValue::NewUint64(TranslatedState* container,
                                           uint64_t value) {
  TranslatedValue slot(container, kUint64);
  slot.uint64_value_ = value;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewBool(TranslatedState* container,
                                         uint32_t value) {
  TranslatedValue slot(container, kBoolBit);
  slot.uint32_value_ = value;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewTagged(TranslatedState* container,
                                           Tagged<Object> literal) {
  TranslatedValue slot(container, kTagged);
  slot.raw_literal_ = literal;
  return slot;
}

// static
TranslatedValue TranslatedValue::NewInvalid(TranslatedState* container) {
  return TranslatedValue(container, kInvalid);
}

Isolate* TranslatedValue::isolate() const { return container_->isolate(); }

Tagged<Object> TranslatedValue::raw_literal() const {
  DCHECK_EQ(kTagged, kind());
  return raw_literal_;
}

int32_t TranslatedValue::int32_value() const {
  DCHECK_EQ(kInt32, kind());
  return int32_value_;
}

int64_t TranslatedValue::int64_value() const {
  DCHECK(kInt64 == kind() || kInt64ToBigInt == kind());
  return int64_value_;
}

uint64_t TranslatedValue::uint64_value() const {
  DCHECK(kUint64ToBigInt == kind());
  return uint64_value_;
}

uint32_t TranslatedValue::uint32_value() const {
  DCHECK(kind() == kUint32 || kind() == kBoolBit);
  return uint32_value_;
}

Float32 TranslatedValue::float_value() const {
  DCHECK_EQ(kFloat, kind());
  return float_value_;
}

Float64 TranslatedValue::double_value() const {
  DCHECK(kDouble == kind() || kHoleyDouble == kind());
  return double_value_;
}

Simd128 TranslatedValue::simd_value() const {
  CHECK_EQ(kind(), kSimd128);
  return simd128_value_;
}

int TranslatedValue::object_length() const {
  DCHECK_EQ(kind(), kCapturedObject);
  return materialization_info_.length_;
}

int TranslatedValue::object_index() const {
  DCHECK(kind() == kCapturedObject || kind() == kDuplicatedObject);
  return materialization_info_.id_;
}

int TranslatedValue::string_concat_index() const {
  DCHECK_EQ(kind(), kCapturedStringConcat);
  return materialization_info_.id_;
}

Tagged<Object> TranslatedValue::GetRawValue() const {
  // If we have a value, return it.
  if (materialization_state() == kFinished) {
    int smi;
    if (IsHeapNumber(*storage_) &&
        DoubleToSmiInteger(Object::NumberValue(*storage_), &smi)) {
      return Smi::FromInt(smi);
    }
    return *storage_;
  }

  // Otherwise, do a best effort to get the value without allocation.
  switch (kind()) {
    case kTagged: {
      Tagged<Object> object = raw_literal();
      if (IsSlicedString(object)) {
        // If {object} is a sliced string of length smaller than
        // SlicedString::kMinLength, then trim the underlying SeqString and
        // return it. This assumes that such sliced strings are only built by
        // the fast string builder optimization of Turbofan's
        // StringBuilderOptimizer/EffectControlLinearizer.
        Tagged<SlicedString> string = Cast<SlicedString>(object);
        if (string->length() < SlicedString::kMinLength) {
          Tagged<String> backing_store = string->parent();
          CHECK(IsSeqString(backing_store));

          // Creating filler at the end of the backing store if needed.
          int string_size =
              IsSeqOneByteString(backing_store)
                  ? SeqOneByteString::SizeFor(backing_store->length())
                  : SeqTwoByteString::SizeFor(backing_store->length());
          int needed_size = IsSeqOneByteString(backing_store)
                                ? SeqOneByteString::SizeFor(string->length())
                                : SeqTwoByteString::SizeFor(string->length());
          if (needed_size < string_size) {
            Address new_end = backing_store.address() + needed_size;
            isolate()->heap()->CreateFillerObjectAt(
                new_end, (string_size - needed_size));
          }

          // Updating backing store's length, effectively trimming it.
          backing_store->set_length(string->length());

          // Zeroing the padding bytes of {backing_store}.
          SeqString::DataAndPaddingSizes sz =
              Cast<SeqString>(backing_store)->GetDataAndPaddingSizes();
          auto padding =
              reinterpret_cast<char*>(backing_store.address() + sz.data_size);
          for (int i = 0; i < sz.padding_size; ++i) {
            padding[i] = 0;
          }

          // Overwriting {string} with a filler, so that we don't leave around a
          // potentially-too-small SlicedString.
          isolate()->heap()->CreateFillerObjectAt(string.address(),
                                                  sizeof(SlicedString));

          return backing_store;
        }
      }
      return object;
    }

    case kInt32: {
      bool is_smi = Smi::IsValid(int32_value());
      if (is_smi) {
        return Smi::FromInt(int32_value());
      }
      break;
    }

    case kInt64: {
      bool is_smi = (int64_value() >= static_cast<int64_t>(Smi::kMinValue) &&
                     int64_value() <= static_cast<int64_t>(Smi::kMaxValue));
      if (is_smi) {
        return Smi::FromIntptr(static_cast<intptr_t>(int64_value()));
      }
      break;
    }

    case kInt64ToBigInt:
      // Return the arguments marker.
      break;

    case kUint32: {
      bool is_smi = (uint32_value() <= static_cast<uintptr_t>(Smi::kMaxValue));
      if (is_smi) {
        return Smi::FromInt(static_cast<int32_t>(uint32_value()));
      }
      break;
    }

    case kBoolBit: {
      if (uint32_value() == 0) {
        return ReadOnlyRoots(isolate()).false_value();
      } else {
        CHECK_EQ(1U, uint32_value());
        return ReadOnlyRoots(isolate()).true_value();
      }
    }

    case kFloat: {
      int smi;
      if (DoubleToSmiInteger(float_value().get_scalar(), &smi)) {
        return Smi::FromInt(smi);
      }
      break;
    }

    case kHoleyDouble:
      if (double_value().is_hole_nan()) {
        // Hole NaNs that made it to here represent the undefined value.
        return ReadOnlyRoots(isolate()).undefined_value();
      }
      // If this is not the hole nan, then this is a normal double value, so
      // fall through to that.
      [[fallthrough]];

    case kDouble: {
      int smi;
      if (DoubleToSmiInteger(double_value().get_scalar(), &smi)) {
        return Smi::FromInt(smi);
      }
      break;
    }

    default:
      break;
  }

  // If we could not get the value without allocation, return the arguments
  // marker.
  return ReadOnlyRoots(isolate()).arguments_marker();
}

void TranslatedValue::set_initialized_storage(Handle<HeapObject> storage) {
  DCHECK_EQ(kUninitialized, materialization_state());
  storage_ = storage;
  materialization_state_ = kFinished;
}

Handle<Object> TranslatedValue::GetValue() {
  Handle<Object> value(GetRawValue(), isolate());
  if (materialization_state() == kFinished) return value;

  if (IsSmi(*value)) {
    // Even though stored as a Smi, this number might instead be needed as a
    // HeapNumber when materializing a JSObject with a field of HeapObject
    // representation. Since we don't have this information available here, we
    // just always allocate a HeapNumber and later extract the Smi again if we
    // don't need a HeapObject.
    set_initialized_storage(
        isolate()->factory()->NewHeapNumber(Object::NumberValue(*value)));
    return value;
  }

  if (*value != ReadOnlyRoots(isolate()).arguments_marker()) {
    set_initialized_storage(Cast<HeapObject>(value));
    return storage_;
  }

  // Otherwise we have to materialize.

  if (kind() == TranslatedValue::kCapturedObject ||
      kind() == TranslatedValue::kDuplicatedObject) {
    // We need to materialize the object (or possibly even object graphs).
    // To make the object verifier happy, we materialize in two steps.

    // 1. Allocate storage for reachable objects. This makes sure that for
    //    each object we have allocated space on heap. The space will be
    //    a byte array that will be later initialized, or a fully
    //    initialized object if it is safe to allocate one that will
    //    pass the verifier.
    container_->EnsureObjectAllocatedAt(this);

    // 2. Initialize the objects. If we have allocated only byte arrays
    //    for some objects, we now overwrite the byte arrays with the
    //    correct object fields. Note that this phase does not allocate
    //    any new objects, so it does not trigger the object verifier.
    return container_->InitializeObjectAt(this);
  }

  if (kind() == TranslatedValue::kCapturedStringConcat) {
    // We need to materialize the string concatenation.
    return container_->ResolveStringConcat(this);
  }

  double number = 0;
  Handle<HeapObject> heap_object;
  switch (kind()) {
    case TranslatedValue::kInt32:
      number = int32_value();
      heap_object = isolate()->factory()->NewHeapNumber(number);
      break;
    case TranslatedValue::kInt64:
      number = int64_value();
      heap_object = isolate()->factory()->NewHeapNumber(number);
      break;
    case TranslatedValue::kInt64ToBigInt:
      heap_object = BigInt::FromInt64(isolate(), int64_value());
      break;
    case TranslatedValue::kUint64ToBigInt:
      heap_object = BigInt::FromUint64(isolate(), uint64_value());
      break;
    case TranslatedValue::kUint32:
      number = uint32_value();
      heap_object = isolate()->factory()->NewHeapNumber(number);
      break;
    case TranslatedValue::kFloat:
      number = float_value().get_scalar();
      heap_object = isolate()->factory()->NewHeapNumber(number);
      break;
    case TranslatedValue::kDouble:
    // We shouldn't have hole values by now, so treat holey double as normal
    // double.s
    case TranslatedValue::kHoleyDouble:
      number = double_value().get_scalar();
      heap_object = isolate()->factory()->NewHeapNumber(number);
      break;
    default:
      UNREACHABLE();
  }
  DCHECK(!IsSmiDouble(number) || kind() == TranslatedValue::kInt64ToBigInt ||
         kind() == TranslatedValue::kUint64ToBigInt);
  set_initialized_storage(heap_object);
  return storage_;
}

bool TranslatedValue::IsMaterializedObject() const {
  switch (kind()) {
    case kCapturedObject:
    case kDuplicatedObject:
      return true;
    default:
      return false;
  }
}

bool TranslatedValue::IsMaterializableByDebugger() const {
  // At the moment, we only allow materialization of doubles.
  return (kind() == kDouble || kind() == kHoleyDouble);
}

int TranslatedValue::GetChildrenCount() const {
  if (kind() == kCapturedObject) {
    return object_length();
  } else if (kind() == kCapturedStringConcat) {
    static constexpr int kLeft = 1, kRight = 1;
    return kLeft + kRight;
  } else {
    return 0;
  }
}

uint64_t TranslatedState::GetUInt64Slot(Address fp, int slot_offset) {
#if V8_TARGET_ARCH_32_BIT
  return ReadUnalignedValue<uint64_t>(fp + slot_offset);
#else
  return Memory<uint64_t>(fp + slot_offset);
#endif
}

uint32_t TranslatedState::GetUInt32Slot(Address fp, int slot_offset) {
  Address address = fp + slot_offset;
#if V8_TARGET_BIG_ENDIAN && V8_HOST_ARCH_64_BIT
  return Memory<uint32_t>(address + kIntSize);
#else
  return Memory<uint32_t>(address);
#endif
}

Float32 TranslatedState::GetFloatSlot(Address fp, int slot_offset) {
#if !V8_TARGET_ARCH_S390X && !V8_TARGET_ARCH_PPC64
  return Float32::FromBits(GetUInt32Slot(fp, slot_offset));
#else
  return Float32::FromBits(Memory<uint32_t>(fp + slot_offset));
#endif
}

Float64 TranslatedState::GetDoubleSlot(Address fp, int slot_offset) {
  return Float64::FromBits(GetUInt64Slot(fp, slot_offset));
}

Simd128 TranslatedState::getSimd128Slot(Address fp, int slot_offset) {
  return base::ReadUnalignedValue<Simd128>(fp + slot_offset);
}

void TranslatedValue::Handlify() {
  if (kind() == kTagged && IsHeapObject(raw_literal())) {
    set_initialized_storage(
        Handle<HeapObject>(Cast<HeapObject>(raw_literal()), isolate()));
    raw_literal_ = Tagged<Object>();
  }
}

TranslatedFrame TranslatedFrame::UnoptimizedJSFrame(
    BytecodeOffset bytecode_offset, Tagged<SharedFunctionInfo> shared_info,
    Tagged<BytecodeArray> bytecode_array, uint32_t height,
    int return_value_offset, int return_value_count) {
  TranslatedFrame frame(kUnoptimizedFunction, shared_info, bytecode_array,
                        height, return_value_offset, return_value_count);
  frame.bytecode_offset_ = bytecode_offset;
  return frame;
}

TranslatedFrame TranslatedFrame::InlinedExtraArguments(
    Tagged<SharedFunctionInfo> shared_info, uint32_t height) {
  return TranslatedFrame(kInlinedExtraArguments, shared_info, {}, height);
}

TranslatedFrame TranslatedFrame::ConstructCreateStubFrame(
    Tagged<SharedFunctionInfo> shared_info, uint32_t height) {
  return TranslatedFrame(kConstructCreateStub, shared_info, {}, height);
}

TranslatedFrame TranslatedFrame::ConstructInvokeStubFrame(
    Tagged<SharedFunctionInfo> shared_info) {
  return TranslatedFrame(kConstructInvokeStub, shared_info, {}, 0);
}

TranslatedFrame TranslatedFrame::BuiltinContinuationFrame(
    BytecodeOffset bytecode_offset, Tagged<SharedFunctionInfo> shared_info,
    uint32_t height) {
  TranslatedFrame frame(kBuiltinContinuation, shared_info, {}, height);
  frame.bytecode_offset_ = bytecode_offset;
  return frame;
}

#if V8_ENABLE_WEBASSEMBLY
TranslatedFrame TranslatedFrame::WasmInlinedIntoJSFrame(
    BytecodeOffset bytecode_offset, Tagged<SharedFunctionInfo> shared_info,
    uint32_t height) {
  TranslatedFrame frame(kWasmInlinedIntoJS, shared_info, {}, height);
  frame.bytecode_offset_ = bytecode_offset;
  return frame;
}

TranslatedFrame TranslatedFrame::JSToWasmBuiltinContinuationFrame(
    BytecodeOffset bytecode_offset, Tagged<SharedFunctionInfo> shared_info,
    uint32_t height, std::optional<wasm::ValueKind> return_kind) {
  TranslatedFrame frame(kJSToWasmBuiltinContinuation, shared_info, {}, height);
  frame.bytecode_offset_ = bytecode_offset;
  frame.return_kind_ = return_kind;
  return frame;
}

TranslatedFrame TranslatedFrame::LiftoffFrame(BytecodeOffset bytecode_offset,
                                              uint32_t height,
                                              uint32_t function_index) {
  // WebAssembly functions do not have a SharedFunctionInfo on the stack.
  // The deoptimizer has to recover the function-specific data based on the PC.
  Tagged<SharedFunctionInfo> shared_info;
  TranslatedFrame frame(kLiftoffFunction, shared_info, {}, height);
  frame.bytecode_offset_ = bytecode_offset;
  frame.wasm_function_index_ = function_index;
  return frame;
}
#endif  // V8_ENABLE_WEBASSEMBLY

TranslatedFrame TranslatedFrame::JavaScriptBuiltinContinuationFrame(
    BytecodeOffset bytecode_offset, Tagged<SharedFunctionInfo> shared_info,
    uint32_t height) {
  TranslatedFrame frame(kJavaScriptBuiltinContinuation, shared_info, {},
                        height);
  frame.bytecode_offset_ = bytecode_offset;
  return frame;
}

TranslatedFrame TranslatedFrame::JavaScriptBuiltinContinuationWithCatchFrame(
    BytecodeOffset bytecode_offset, Tagged<SharedFunctionInfo> shared_info,
    uint32_t height) {
  TranslatedFrame frame(kJavaScriptBuiltinContinuationWithCatch, shared_info,
                        {}, height);
  frame.bytecode_offset_ = bytecode_offset;
  return frame;
}

int TranslatedFrame::GetValueCount() const {
  // The function is added to all frame state descriptors in
  // InstructionSelector::AddInputsToFrameStateDescriptor.
  static constexpr int kTheFunction = 1;

  switch (kind()) {
    case kUnoptimizedFunction: {
      int parameter_count = raw_bytecode_array_->parameter_count();
      static constexpr int kTheContext = 1;
      static constexpr int kTheAccumulator = 1;
      return height() + parameter_count + kTheContext + kTheFunction +
             kTheAccumulator;
    }

    case kInlinedExtraArguments:
      return height() + kTheFunction;

    case kConstructCreateStub:
    case kConstructInvokeStub:
    case kBuiltinContinuation:
#if V8_ENABLE_WEBASSEMBLY
    case kJSToWasmBuiltinContinuation:
#endif  // V8_ENABLE_WEBASSEMBLY
    case kJavaScriptBuiltinContinuation:
    case kJavaScriptBuiltinContinuationWithCatch: {
      static constexpr int kTheContext = 1;
      return height() + kTheContext + kTheFunction;
    }
#if V8_ENABLE_WEBASSEMBLY
    case kWasmInlinedIntoJS: {
      static constexpr int kTheContext = 1;
      return height() + kTheContext + kTheFunction;
    }
    case kLiftoffFunction: {
      return height();
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    case kInvalid:
      UNREACHABLE();
  }
  UNREACHABLE();
}

void TranslatedFrame::Handlify(Isolate* isolate) {
  CHECK_EQ(handle_state_, kRawPointers);
  if (!raw_shared_info_.is_null()) {
    shared_info_ = handle(raw_shared_info_, isolate);
  }
  if (!raw_bytecode_array_.is_null()) {
    bytecode_array_ = handle(raw_bytecode_array_, isolate);
  }
  for (auto& value : values_) {
    value.Handlify();
  }
  handle_state_ = kHandles;
}

DeoptimizationLiteralProvider::DeoptimizationLiteralProvider(
    Tagged<DeoptimizationLiteralArray> literal_array)
    : literals_on_heap_(literal_array) {}

DeoptimizationLiteralProvider::DeoptimizationLiteralProvider(
    std::vector<DeoptimizationLiteral> literals)
    : literals_off_heap_(std::move(literals)) {}

DeoptimizationLiteralProvider::~DeoptimizationLiteralProvider() = default;

TranslatedValue DeoptimizationLiteralProvider::Get(TranslatedState* container,
                                                   int literal_index) const {
  if (V8_LIKELY(!literals_on_heap_.is_null())) {
    return TranslatedValue::NewTagged(container,
                                      literals_on_heap_->get(literal_index));
  }
#if !V8_ENABLE_WEBASSEMBLY
  UNREACHABLE();
#else
  CHECK(v8_flags.wasm_deopt);
  CHECK_LT(literal_index, literals_off_heap_.size());
  const DeoptimizationLiteral& literal = literals_off_heap_[literal_index];
  switch (literal.kind()) {
    case DeoptimizationLiteralKind::kWasmInt32:
      return TranslatedValue::NewInt32(container, literal.GetInt32());
    case DeoptimizationLiteralKind::kWasmInt64:
      return TranslatedValue::NewInt64(container, literal.GetInt64());
    case DeoptimizationLiteralKind::kWasmFloat32:
      return TranslatedValue::NewFloat(container, literal.GetFloat32());
    case DeoptimizationLiteralKind::kWasmFloat64:
      return TranslatedValue::NewDouble(container, literal.GetFloat64());
    case DeoptimizationLiteralKind::kWasmI31Ref:
      return TranslatedValue::NewTagged(container, literal.GetSmi());
    default:
      UNIMPLEMENTED();
  }
#endif
}

TranslatedFrame TranslatedState::CreateNextTranslatedFrame(
    DeoptTranslationIterator* iterator,
    Tagged<ProtectedDeoptimizationLiteralArray> protected_literal_array,
    const DeoptimizationLiteralProvider& literal_array, Address fp,
    FILE* trace_file) {
  TranslationOpcode opcode = iterator->NextOpcode();
  switch (opcode) {
    case TranslationOpcode::INTERPRETED_FRAME_WITH_RETURN:
    case TranslationOpcode::INTERPRETED_FRAME_WITHOUT_RETURN: {
      BytecodeOffset bytecode_offset = BytecodeOffset(iterator->NextOperand());
      Tagged<SharedFunctionInfo> shared_info = Cast<SharedFunctionInfo>(
          literal_array.get_on_heap_literals()->get(iterator->NextOperand()));
      Tagged<BytecodeArray> bytecode_array = Cast<BytecodeArray>(
          protected_literal_array->get(iterator->NextOperand()));
      uint32_t height = iterator->NextOperandUnsigned();
      int return_value_offset = 0;
      int return_value_count = 0;
      if (opcode == TranslationOpcode::INTERPRETED_FRAME_WITH_RETURN) {
        return_value_offset = iterator->NextOperand();
        return_value_count = iterator->NextOperand();
      }
      if (trace_file != nullptr) {
        std::unique_ptr<char[]> name = shared_info->DebugNameCStr();
        PrintF(trace_file, "  reading input frame %s", name.get());
        int arg_count = bytecode_array->parameter_count();
        PrintF(trace_file,
               " => bytecode_offset=%d, args=%d, height=%u, retval=%i(#%i); "
               "inputs:\n",
               bytecode_offset.ToInt(), arg_count, height, return_value_offset,
               return_value_count);
      }
      return TranslatedFrame::UnoptimizedJSFrame(
          bytecode_offset, shared_info, bytecode_array, height,
          return_value_offset, return_value_count);
    }

    case TranslationOpcode::INLINED_EXTRA_ARGUMENTS: {
      Tagged<SharedFunctionInfo> shared_info = Cast<SharedFunctionInfo>(
          literal_array.get_on_heap_literals()->get(iterator->NextOperand()));
      uint32_t height = iterator->NextOperandUnsigned();
      if (trace_file != nullptr) {
        std::unique_ptr<char[]> name = shared_info->DebugNameCStr();
        PrintF(trace_file, "  reading inlined arguments frame %s", name.get());
        PrintF(trace_file, " => height=%u; inputs:\n", height);
      }
      return TranslatedFrame::InlinedExtraArguments(shared_info, height);
    }

    case TranslationOpcode::CONSTRUCT_CREATE_STUB_FRAME: {
      Tagged<SharedFunctionInfo> shared_info = Cast<SharedFunctionInfo>(
          literal_array.get_on_heap_literals()->get(iterator->NextOperand()));
      uint32_t height = iterator->NextOperandUnsigned();
      if (trace_file != nullptr) {
        std::unique_ptr<char[]> name = shared_info->DebugNameCStr();
        PrintF(trace_file,
               "  reading construct create stub frame %s => height = %d; "
               "inputs:\n",
               name.get(), height);
      }
      return TranslatedFrame::ConstructCreateStubFrame(shared_info, height);
    }

    case TranslationOpcode::CONSTRUCT_INVOKE_STUB_FRAME: {
      Tagged<SharedFunctionInfo> shared_info = Cast<SharedFunctionInfo>(
          literal_array.get_on_heap_literals()->get(iterator->NextOperand()));
      if (trace_file != nullptr) {
        std::unique_ptr<char[]> name = shared_info->DebugNameCStr();
        PrintF(trace_file,
               "  reading construct invoke stub frame %s, inputs:\n",
               name.get());
      }
      return TranslatedFrame::ConstructInvokeStubFrame(shared_info);
    }

    case TranslationOpcode::BUILTIN_CONTINUATION_FRAME: {
      BytecodeOffset bytecode_offset = BytecodeOffset(iterator->NextOperand());
      Tagged<SharedFunctionInfo> shared_info = Cast<SharedFunctionInfo>(
          literal_array.get_on_heap_literals()->get(iterator->NextOperand()));
      uint32_t height = iterator->NextOperandUnsigned();
      if (trace_file != nullptr) {
        std::unique_ptr<char[]> name = shared_info->DebugNameCStr();
        PrintF(trace_file, "  reading builtin continuation frame %s",
               name.get());
        PrintF(trace_file, " => bytecode_offset=%d, height=%u; inputs:\n",
               bytecode_offset.ToInt(), height);
      }
      return TranslatedFrame::BuiltinContinuationFrame(bytecode_offset,
                                                       shared_info, height);
    }

#if V8_ENABLE_WEBASSEMBLY
    case TranslationOpcode::WASM_INLINED_INTO_JS_FRAME: {
      BytecodeOffset bailout_id = BytecodeOffset(iterator->NextOperand());
      Tagged<SharedFunctionInfo> shared_info = Cast<SharedFunctionInfo>(
          literal_array.get_on_heap_literals()->get(iterator->NextOperand()));
      uint32_t height = iterator->NextOperandUnsigned();
      if (trace_file != nullptr) {
        std::unique_ptr<char[]> name = shared_info->DebugNameCStr();
        PrintF(trace_file, "  reading Wasm inlined into JS frame %s",
               name.get());
        PrintF(trace_file, " => bailout_id=%d, height=%u ; inputs:\n",
               bailout_id.ToInt(), height);
      }
      return TranslatedFrame::WasmInlinedIntoJSFrame(bailout_id, shared_info,
                                                     height);
    }

    case TranslationOpcode::JS_TO_WASM_BUILTIN_CONTINUATION_FRAME: {
      BytecodeOffset bailout_id = BytecodeOffset(iterator->NextOperand());
      Tagged<SharedFunctionInfo> shared_info = Cast<SharedFunctionInfo>(
          literal_array.get_on_heap_literals()->get(iterator->NextOperand()));
      uint32_t height = iterator->NextOperandUnsigned();
      int return_kind_code = iterator->NextOperand();
      std::optional<wasm::ValueKind> return_kind;
      if (return_kind_code != kNoWasmReturnKind) {
        return_kind = static_cast<wasm::ValueKind>(return_kind_code);
      }
      if (trace_file != nullptr) {
        std::unique_ptr<char[]> name = shared_info->DebugNameCStr();
        PrintF(trace_file, "  reading JS to Wasm builtin continuation frame %s",
               name.get());
        PrintF(trace_file,
               " => bailout_id=%d, height=%u return_type=%d; inputs:\n",
               bailout_id.ToInt(), height,
               return_kind.has_value() ? return_kind.value() : -1);
      }
      return TranslatedFrame::JSToWasmBuiltinContinuationFrame(
          bailout_id, shared_info, height, return_kind);
    }

    case TranslationOpcode::LIFTOFF_FRAME: {
      BytecodeOffset bailout_id = BytecodeOffset(iterator->NextOperand());
      uint32_t height = iterator->NextOperandUnsigned();
      uint32_t function_id = iterator->NextOperandUnsigned();
      if (trace_file != nullptr) {
        PrintF(trace_file, "  reading input for liftoff frame");
        PrintF(trace_file,
               " => bailout_id=%d, height=%u, function_id=%u ; inputs:\n",
               bailout_id.ToInt(), height, function_id);
      }
      return TranslatedFrame::LiftoffFrame(bailout_id, height, function_id);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    case TranslationOpcode::JAVASCRIPT_BUILTIN_CONTINUATION_FRAME: {
      BytecodeOffset bytecode_offset = BytecodeOffset(iterator->NextOperand());
      Tagged<SharedFunctionInfo> shared_info = Cast<SharedFunctionInfo>(
          literal_array.get_on_heap_literals()->get(iterator->NextOperand()));
      uint32_t height = iterator->NextOperandUnsigned();
      if (trace_file != nullptr) {
        std::unique_ptr<char[]> name = shared_info->DebugNameCStr();
        PrintF(trace_file, "  reading JavaScript builtin continuation frame %s",
               name.get());
        PrintF(trace_file, " => bytecode_offset=%d, height=%u; inputs:\n",
               bytecode_offset.ToInt(), height);
      }
      return TranslatedFrame::JavaScriptBuiltinContinuationFrame(
          bytecode_offset, shared_info, height);
    }

    case TranslationOpcode::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH_FRAME: {
      BytecodeOffset bytecode_offset = BytecodeOffset(iterator->NextOperand());
      Tagged<SharedFunctionInfo> shared_info = Cast<SharedFunctionInfo>(
          literal_array.get_on_heap_literals()->get(iterator->NextOperand()));
      uint32_t height = iterator->NextOperandUnsigned();
      if (trace_file != nullptr) {
        std::unique_ptr<char[]> name = shared_info->DebugNameCStr();
        PrintF(trace_file,
               "  reading JavaScript builtin continuation frame with catch %s",
               name.get());
        PrintF(trace_file, " => bytecode_offset=%d, height=%u; inputs:\n",
               bytecode_offset.ToInt(), height);
      }
      return TranslatedFrame::JavaScriptBuiltinContinuationWithCatchFrame(
          bytecode_offset, shared_info, height);
    }
    case TranslationOpcode::UPDATE_FEEDBACK:
    case TranslationOpcode::BEGIN_WITH_FEEDBACK:
    case TranslationOpcode::BEGIN_WITHOUT_FEEDBACK:
    case TranslationOpcode::DUPLICATED_OBJECT:
    case TranslationOpcode::ARGUMENTS_ELEMENTS:
    case TranslationOpcode::ARGUMENTS_LENGTH:
    case TranslationOpcode::REST_LENGTH:
    case TranslationOpcode::CAPTURED_OBJECT:
    case TranslationOpcode::STRING_CONCAT:
    case TranslationOpcode::REGISTER:
    case TranslationOpcode::INT32_REGISTER:
    case TranslationOpcode::INT64_REGISTER:
    case TranslationOpcode::SIGNED_BIGINT64_REGISTER:
    case TranslationOpcode::UNSIGNED_BIGINT64_REGISTER:
    case TranslationOpcode::UINT32_REGISTER:
    case TranslationOpcode::BOOL_REGISTER:
    case TranslationOpcode::FLOAT_REGISTER:
    case TranslationOpcode::DOUBLE_REGISTER:
    case TranslationOpcode::HOLEY_DOUBLE_REGISTER:
    case TranslationOpcode::SIMD128_REGISTER:
    case TranslationOpcode::TAGGED_STACK_SLOT:
    case TranslationOpcode::INT32_STACK_SLOT:
    case TranslationOpcode::INT64_STACK_SLOT:
    case TranslationOpcode::SIGNED_BIGINT64_STACK_SLOT:
    case TranslationOpcode::UNSIGNED_BIGINT64_STACK_SLOT:
    case TranslationOpcode::UINT32_STACK_SLOT:
    case TranslationOpcode::BOOL_STACK_SLOT:
    case TranslationOpcode::FLOAT_STACK_SLOT:
    case TranslationOpcode::DOUBLE_STACK_SLOT:
    case TranslationOpcode::SIMD128_STACK_SLOT:
    case TranslationOpcode::HOLEY_DOUBLE_STACK_SLOT:
    case TranslationOpcode::LITERAL:
    case TranslationOpcode::OPTIMIZED_OUT:
    case TranslationOpcode::MATCH_PREVIOUS_TRANSLATION:
      break;
  }
  UNREACHABLE();
}

// static
void TranslatedFrame::AdvanceIterator(
    std::deque<TranslatedValue>::iterator* iter) {
  int values_to_skip = 1;
  while (values_to_skip > 0) {
    // Consume the current element.
    values_to_skip--;
    // Add all the children.
    values_to_skip += (*iter)->GetChildrenCount();

    (*iter)++;
  }
}

// Creates translated values for an arguments backing store, or the backing
// store for rest parameters depending on the given {type}. The TranslatedValue
// objects for the fields are not read from the
// DeoptimizationFrameTranslation::Iterator, but instead created on-the-fly
// based on dynamic information in the optimized frame.
void TranslatedState::CreateArgumentsElementsTranslatedValues(
    int frame_index, Address input_frame_pointer, CreateArgumentsType type,
    FILE* trace_file) {
  TranslatedFrame& frame = frames_[frame_index];
  int length =
      type == CreateArgumentsType::kRestParameter
          ? std::max(0, actual_argument_count_ - formal_parameter_count_)
          : actual_argument_count_;
  int object_index = static_cast<int>(object_positions_.size());
  int value_index = static_cast<int>(frame.values_.size());
  if (trace_file != nullptr) {
    PrintF(trace_file, "arguments elements object #%d (type = %d, length = %d)",
           object_index, static_cast<uint8_t>(type), length);
  }

  object_positions_.push_back({frame_index, value_index});
  frame.Add(TranslatedValue::NewDeferredObject(
      this, length + OFFSET_OF_DATA_START(FixedArray) / kTaggedSize,
      object_index));

  ReadOnlyRoots roots(isolate_);
  frame.Add(TranslatedValue::NewTagged(this, roots.fixed_array_map()));
  frame.Add(TranslatedValue::NewInt32(this, length));

  int number_of_holes = 0;
  if (type == CreateArgumentsType::kMappedArguments) {
    // If the actual number of arguments is less than the number of formal
    // parameters, we have fewer holes to fill to not overshoot the length.
    number_of_holes = std::min(formal_parameter_count_, length);
  }
  for (int i = 0; i < number_of_holes; ++i) {
    frame.Add(TranslatedValue::NewTagged(this, roots.the_hole_value()));
  }
  int argc = length - number_of_holes;
  int start_index = number_of_holes;
  if (type == CreateArgumentsType::kRestParameter) {
    start_index = std::max(0, formal_parameter_count_);
  }
  for (int i = 0; i < argc; i++) {
    // Skip the receiver.
    int offset = i + start_index + 1;
    Address arguments_frame = offset > formal_parameter_count_
                                  ? stack_frame_pointer_
                                  : input_frame_pointer;
    Address argument_slot = arguments_frame +
                            CommonFrameConstants::kFixedFrameSizeAboveFp +
                            offset * kSystemPointerSize;

    frame.Add(TranslatedValue::NewTagged(this, *FullObjectSlot(argument_slot)));
  }
}

// We can't intermix stack decoding and allocations because the deoptimization
// infrastracture is not GC safe.
// Thus we build a temporary structure in malloced space.
// The TranslatedValue objects created correspond to the static translation
// instructions from the DeoptTranslationIterator, except for
// TranslationOpcode::ARGUMENTS_ELEMENTS, where the number and values of the
// FixedArray elements depend on dynamic information from the optimized frame.
// Returns the number of expected nested translations from the
// DeoptTranslationIterator.
int TranslatedState::CreateNextTranslatedValue(
    int frame_index, DeoptTranslationIterator* iterator,
    const DeoptimizationLiteralProvider& literal_array, Address fp,
    RegisterValues* registers, FILE* trace_file) {
  disasm::NameConverter converter;

  TranslatedFrame& frame = frames_[frame_index];
  int value_index = static_cast<int>(frame.values_.size());

  TranslationOpcode opcode = iterator->NextOpcode();
  switch (opcode) {
    case TranslationOpcode::BEGIN_WITH_FEEDBACK:
    case TranslationOpcode::BEGIN_WITHOUT_FEEDBACK:
    case TranslationOpcode::INTERPRETED_FRAME_WITH_RETURN:
    case TranslationOpcode::INTERPRETED_FRAME_WITHOUT_RETURN:
    case TranslationOpcode::INLINED_EXTRA_ARGUMENTS:
    case TranslationOpcode::CONSTRUCT_CREATE_STUB_FRAME:
    case TranslationOpcode::CONSTRUCT_INVOKE_STUB_FRAME:
    case TranslationOpcode::JAVASCRIPT_BUILTIN_CONTINUATION_FRAME:
    case TranslationOpcode::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH_FRAME:
    case TranslationOpcode::BUILTIN_CONTINUATION_FRAME:
#if V8_ENABLE_WEBASSEMBLY
    case TranslationOpcode::WASM_INLINED_INTO_JS_FRAME:
    case TranslationOpcode::JS_TO_WASM_BUILTIN_CONTINUATION_FRAME:
    case TranslationOpcode::LIFTOFF_FRAME:
#endif  // V8_ENABLE_WEBASSEMBLY
    case TranslationOpcode::UPDATE_FEEDBACK:
    case TranslationOpcode::MATCH_PREVIOUS_TRANSLATION:
      // Peeled off before getting here.
      break;

    case TranslationOpcode::DUPLICATED_OBJECT: {
      int object_id = iterator->NextOperand();
      if (trace_file != nullptr) {
        PrintF(trace_file, "duplicated object #%d", object_id);
      }
      object_positions_.push_back(object_positions_[object_id]);
      TranslatedValue translated_value =
          TranslatedValue::NewDuplicateObject(this, object_id);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::ARGUMENTS_ELEMENTS: {
      CreateArgumentsType arguments_type =
          static_cast<CreateArgumentsType>(iterator->NextOperand());
      CreateArgumentsElementsTranslatedValues(frame_index, fp, arguments_type,
                                              trace_file);
      return 0;
    }

    case TranslationOpcode::ARGUMENTS_LENGTH: {
      if (trace_file != nullptr) {
        PrintF(trace_file, "arguments length field (length = %d)",
               actual_argument_count_);
      }
      frame.Add(TranslatedValue::NewInt32(this, actual_argument_count_));
      return 0;
    }

    case TranslationOpcode::REST_LENGTH: {
      int rest_length =
          std::max(0, actual_argument_count_ - formal_parameter_count_);
      if (trace_file != nullptr) {
        PrintF(trace_file, "rest length field (length = %d)", rest_length);
      }
      frame.Add(TranslatedValue::NewInt32(this, rest_length));
      return 0;
    }

    case TranslationOpcode::CAPTURED_OBJECT: {
      int field_count = iterator->NextOperand();
      int object_index = static_cast<int>(object_positions_.size());
      if (trace_file != nullptr) {
        PrintF(trace_file, "captured object #%d (length = %d)", object_index,
               field_count);
      }
      object_positions_.push_back({frame_index, value_index});
      TranslatedValue translated_value =
          TranslatedValue::NewDeferredObject(this, field_count, object_index);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::STRING_CONCAT: {
      if (trace_file != nullptr) {
        PrintF(trace_file, "string concatenation");
      }

      int string_concat_index =
          static_cast<int>(string_concat_positions_.size());
      string_concat_positions_.push_back({frame_index, value_index});
      TranslatedValue translated_value =
          TranslatedValue::NewStringConcat(this, string_concat_index);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      intptr_t value = registers->GetRegister(input_reg);
      Address uncompressed_value = DecompressIfNeeded(value);
      if (trace_file != nullptr) {
        PrintF(trace_file, V8PRIxPTR_FMT " ; %s ", uncompressed_value,
               converter.NameOfCPURegister(input_reg));
        ShortPrint(Tagged<Object>(uncompressed_value), trace_file);
      }
      TranslatedValue translated_value =
          TranslatedValue::NewTagged(this, Tagged<Object>(uncompressed_value));
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::INT32_REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      intptr_t value = registers->GetRegister(input_reg);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%" V8PRIdPTR " ; %s (int32)", value,
               converter.NameOfCPURegister(input_reg));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewInt32(this, static_cast<int32_t>(value));
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::INT64_REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      intptr_t value = registers->GetRegister(input_reg);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%" V8PRIdPTR " ; %s (int64)", value,
               converter.NameOfCPURegister(input_reg));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewInt64(this, static_cast<int64_t>(value));
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::SIGNED_BIGINT64_REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      intptr_t value = registers->GetRegister(input_reg);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%" V8PRIdPTR " ; %s (signed bigint64)", value,
               converter.NameOfCPURegister(input_reg));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewInt64ToBigInt(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::UNSIGNED_BIGINT64_REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      intptr_t value = registers->GetRegister(input_reg);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%" V8PRIdPTR " ; %s (unsigned bigint64)", value,
               converter.NameOfCPURegister(input_reg));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewUint64ToBigInt(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::UINT32_REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      intptr_t value = registers->GetRegister(input_reg);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%" V8PRIuPTR " ; %s (uint32)", value,
               converter.NameOfCPURegister(input_reg));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewUint32(this, static_cast<uint32_t>(value));
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::BOOL_REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      intptr_t value = registers->GetRegister(input_reg);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%" V8PRIdPTR " ; %s (bool)", value,
               converter.NameOfCPURegister(input_reg));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewBool(this, static_cast<uint32_t>(value));
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::FLOAT_REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      Float32 value = registers->GetFloatRegister(input_reg);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%e ; %s (float)", value.get_scalar(),
               RegisterName(FloatRegister::from_code(input_reg)));
      }
      TranslatedValue translated_value = TranslatedValue::NewFloat(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::DOUBLE_REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      Float64 value = registers->GetDoubleRegister(input_reg);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%e ; %s (double)", value.get_scalar(),
               RegisterName(DoubleRegister::from_code(input_reg)));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewDouble(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::HOLEY_DOUBLE_REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      Float64 value = registers->GetDoubleRegister(input_reg);
      if (trace_file != nullptr) {
        if (value.is_hole_nan()) {
          PrintF(trace_file, "the hole");
        } else {
          PrintF(trace_file, "%e", value.get_scalar());
        }
        PrintF(trace_file, " ; %s (holey double)",
               RegisterName(DoubleRegister::from_code(input_reg)));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewHoleyDouble(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::SIMD128_REGISTER: {
      int input_reg = iterator->NextOperandUnsigned();
      if (registers == nullptr) {
        TranslatedValue translated_value = TranslatedValue::NewInvalid(this);
        frame.Add(translated_value);
        return translated_value.GetChildrenCount();
      }
      Simd128 value = registers->GetSimd128Register(input_reg);
      if (trace_file != nullptr) {
        int8x16 val = value.to_i8x16();
        PrintF(trace_file,
               "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x ; %s (Simd128)",
               val.val[0], val.val[1], val.val[2], val.val[3], val.val[4],
               val.val[5], val.val[6], val.val[7], val.val[8], val.val[9],
               val.val[10], val.val[11], val.val[12], val.val[13], val.val[14],
               val.val[15], RegisterName(DoubleRegister::from_code(input_reg)));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewSimd128(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::TAGGED_STACK_SLOT: {
      int slot_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      intptr_t value = *(reinterpret_cast<intptr_t*>(fp + slot_offset));
      Address uncompressed_value = DecompressIfNeeded(value);
      if (trace_file != nullptr) {
        PrintF(trace_file, V8PRIxPTR_FMT " ;  [fp %c %3d]  ",
               uncompressed_value, slot_offset < 0 ? '-' : '+',
               std::abs(slot_offset));
        ShortPrint(Tagged<Object>(uncompressed_value), trace_file);
      }
      TranslatedValue translated_value =
          TranslatedValue::NewTagged(this, Tagged<Object>(uncompressed_value));
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::INT32_STACK_SLOT: {
      int slot_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      uint32_t value = GetUInt32Slot(fp, slot_offset);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%d ; (int32) [fp %c %3d] ",
               static_cast<int32_t>(value), slot_offset < 0 ? '-' : '+',
               std::abs(slot_offset));
      }
      TranslatedValue translated_value = TranslatedValue::NewInt32(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::INT64_STACK_SLOT: {
      int slot_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      uint64_t value = GetUInt64Slot(fp, slot_offset);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%" V8PRIdPTR " ; (int64) [fp %c %3d] ",
               static_cast<intptr_t>(value), slot_offset < 0 ? '-' : '+',
               std::abs(slot_offset));
      }
      TranslatedValue translated_value = TranslatedValue::NewInt64(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::SIGNED_BIGINT64_STACK_SLOT: {
      int slot_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      uint64_t value = GetUInt64Slot(fp, slot_offset);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%" V8PRIdPTR " ; (signed bigint64) [fp %c %3d] ",
               static_cast<intptr_t>(value), slot_offset < 0 ? '-' : '+',
               std::abs(slot_offset));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewInt64ToBigInt(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::UNSIGNED_BIGINT64_STACK_SLOT: {
      int slot_offset = OptimizedJSFrame::StackSlotOffsetRelativeToFp(
          iterator->NextOperand());
      uint64_t value = GetUInt64Slot(fp, slot_offset);
      if (trace_file != nullptr) {
        PrintF(trace_file, "%" V8PRIdPTR " ; (unsigned bigint64) [fp %c %3d] ",
               static_cast<intptr_t>(value), slot_offset < 0 ? '-' : '+',
               std::abs(slot_offset));
      }
      TranslatedValue translated_value =
          TranslatedValue::NewUint64ToBigInt(this, value);
      frame.Add(translated_value);
      return translated_value.GetChildrenCount();
    }

    case TranslationOpcode::UINT32_STACK_SLOT: {
      int slot
```