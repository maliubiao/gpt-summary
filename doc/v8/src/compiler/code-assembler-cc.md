Response:
My thinking process to arrive at the summary of `v8/src/compiler/code-assembler.cc` goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code snippet, specifically highlighting its role in V8, its relation to JavaScript, potential programming errors, and any implied code logic. The "part 1 of 3" suggests a larger context, but I should focus on the given snippet.

2. **Initial Scan and Keyword Identification:** I'll first quickly read through the code, looking for significant keywords and class names. I see:
    * `CodeAssembler`
    * `CodeAssemblerState`
    * `RawMachineAssembler`
    * `JSGraph`
    * `TNode` (and various `TNode<...>` types)
    * `Label`
    * `Return`, `Bind`, `Branch`
    * `Load`, `Store`
    * Constant creation methods (`Int32Constant`, `StringConstant`, etc.)
    * Machine types (`MachineType::...`)
    * Builtins

3. **Inferring the Core Purpose:**  The name `CodeAssembler` strongly suggests that this code is responsible for *generating machine code*. The presence of `RawMachineAssembler` reinforces this, indicating a lower-level code generation component. `JSGraph` suggests integration with the JavaScript compilation pipeline.

4. **Deconstructing Key Classes:**
    * **`CodeAssemblerState`:** This class holds the *state* required for code assembly. It contains the `RawMachineAssembler`, information about the code being generated (kind, name, builtin), and manages variables. The constructors show different ways to initialize this state, likely for different types of code generation (stubs, JS functions).
    * **`CodeAssembler`:**  This class *uses* the `CodeAssemblerState` and provides a higher-level interface for code generation. It offers methods for creating nodes in the intermediate representation (`TNode`s), performing operations, handling control flow (labels, branches, returns), and interacting with the underlying `RawMachineAssembler`.

5. **Analyzing Functionality by Category:**  I'll group the methods in `CodeAssembler` based on their apparent function:
    * **Setup/Configuration:** `CodeAssemblerState` constructors, `RegisterCallGenerationCallbacks`, `UnregisterCallGenerationCallbacks`.
    * **Code Generation Core:**  The numerous methods for creating constant `TNode`s (`Int32Constant`, `StringConstant`, etc.), performing operations (`Word32Add`, `IntPtrEqual`, `Load`, `Store`), and managing control flow (`Bind`, `Branch`, `Return`).
    * **Accessing Context and Parameters:** `GetJSContextParameter`, `DynamicJSParameterCount`.
    * **Debugging and Assertions:** `BreakOnNode`, `StaticAssert`, `EmitComment`.
    * **Machine Information:**  Methods like `Is64`, `Word32ShiftIsSafe`, and checking for hardware feature support (`IsFloat64RoundUpSupported`).
    * **Frame and Stack Management:** `LoadFramePointer`, `LoadParentFramePointer`, `LoadStackPointer`, `SetStackPointer`.
    * **Root Table Access:** `LoadRoot`, `LoadRootMapWord`.

6. **Connecting to JavaScript:** The presence of `JSGraph`, methods for handling JS function calls (`IsJSFunctionCall`, `GetJSContextParameter`), and the overall purpose of generating code for V8 clearly link this to JavaScript execution. While the code itself is C++, it's a crucial part of how JavaScript is compiled and run in V8.

7. **Identifying Potential Programming Errors:**  The code involves low-level operations and type manipulation. Potential errors could include:
    * **Incorrect Type Casting:** The use of `UncheckedCast` suggests that the programmer must ensure type safety. Incorrect casts could lead to crashes or unexpected behavior.
    * **Incorrect Offset Calculations:** When using `Load` and `Store` with offsets, incorrect calculations could lead to reading or writing to the wrong memory locations.
    * **Control Flow Errors:**  Incorrectly structured `Label`s, `Bind`s, and `Branch`es could lead to infinite loops or incorrect execution paths.
    * **Incorrect Parameter Handling:** When dealing with JS function calls, mismanaging the context or parameters could lead to errors.

8. **Considering Code Logic and Assumptions:** The code makes assumptions about the underlying architecture (32-bit or 64-bit) and the capabilities of the target machine. The numerous checks for supported hardware features demonstrate this. The way constants are created and managed also reveals underlying logic for optimizing constant lookups.

9. **Addressing the `.tq` Question:** The prompt mentions `.tq` files. Based on my knowledge of V8, `.tq` files are Torque source code, a higher-level language for writing builtins. Since the provided code is `.cc`, it's C++, not Torque. This distinction is important for understanding the code's nature.

10. **Structuring the Summary:** Finally, I'll organize my observations into a clear and concise summary, addressing each point raised in the original request:
    * Core Functionality
    * Relation to JavaScript (with an example)
    * Code Logic and Assumptions
    * Common Programming Errors
    * Handling the `.tq` misconception

This iterative process of scanning, identifying key elements, grouping functionalities, inferring purpose, and considering potential issues allows me to build a comprehensive understanding and generate the desired summary. I continually refine my understanding as I delve deeper into the code's details.
好的，这是对提供的 `v8/src/compiler/code-assembler.cc` 代码片段的功能归纳：

**核心功能：**

`v8/src/compiler/code-assembler.cc` 文件定义了 `CodeAssembler` 类及其辅助类 `CodeAssemblerState`。 `CodeAssembler` 是 V8 Turbofan 编译器中用于生成机器码的关键组件。它提供了一组高级接口，允许开发者以结构化的方式构建底层的机器指令序列，而无需直接操作汇编语言。

**具体功能点：**

1. **抽象的机器码生成接口:**  `CodeAssembler` 封装了底层的 `RawMachineAssembler`，提供了一层更易于使用的抽象。开发者可以使用 `CodeAssembler` 的方法来创建代表各种操作和值的节点（`TNode`），例如：
   * **常量创建:**  可以创建各种类型的常量，如整数 (`Int32Constant`, `Int64Constant`)、浮点数 (`Float32Constant`, `Float64Constant`)、字符串 (`StringConstant`)、布尔值 (`BooleanConstant`)、以及特殊值如 `undefined` 和 `null`。
   * **基本运算:** 提供了各种算术、逻辑、位运算等操作的方法，例如 `Word32Add`, `IntPtrEqual`, `WordShl` 等。
   * **内存访问:**  提供了加载 (`Load`) 和存储 (`Store`) 内存的方法。
   * **控制流:**  支持定义标签 (`Label`)，进行条件分支 (`Branch`)，以及函数返回 (`Return`)。
   * **函数调用:**  虽然在这个片段中没有直接展示复杂的调用，但 `CodeAssembler` 与调用描述符 (`CallDescriptor`) 集成，用于生成函数调用的代码。

2. **状态管理:** `CodeAssemblerState` 类负责维护代码生成过程中的状态信息，包括：
   * 底层的 `RawMachineAssembler` 实例。
   * 代码的类型 (`CodeKind`)，名称 (`name_`) 和关联的内置函数 (`builtin_`)。
   * 一个用于构建图的 `JSGraph` 实例，Turbofan 使用图来表示代码。
   * 变量管理 (`variables_`)。

3. **与 Turbofan 集成:**  `CodeAssembler` 生成的代码最终会被 Turbofan 编译器进一步处理和优化。`JSGraph` 的存在表明了它与 Turbofan 的图表示紧密相关。

4. **调试支持:** 提供了 `BreakOnNode` 方法，允许在特定的图节点处设置断点进行调试。

5. **常量优化:**  对于某些常量操作，`CodeAssembler` 尝试在编译时进行计算，例如在比较操作中，如果两个操作数都是常量，则直接生成结果的布尔常量。

**关于 .tq 文件和 JavaScript 关系：**

* **关于 .tq 文件:**  你说的很对，如果 `v8/src/compiler/code-assembler.cc` 文件以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。 Torque 是 V8 专门设计的一种高级语言，用于编写内置函数和运行时代码。 Torque 代码会被编译成 C++ 代码，然后再被编译成机器码。

* **与 JavaScript 的关系:**  `CodeAssembler`（以及 Torque，虽然这里是 C++ 版本）的主要目的是生成执行 JavaScript 代码所需的机器码。无论是解释执行还是编译执行，V8 最终都需要将 JavaScript 代码转化为机器指令才能运行。`CodeAssembler` 是这个转化过程中的关键工具。

**JavaScript 示例 (说明关系):**

虽然 `code-assembler.cc` 是 C++ 代码，但它生成的机器码是为了执行 JavaScript。 举个简单的例子，考虑以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个 `add` 函数时，`CodeAssembler` (或其 Torque 对应的部分) 会生成类似以下的机器码（这是一个高度简化的概念性例子，实际情况更复杂）：

```assembly
// 假设 a 和 b 是寄存器 %r1 和 %r2 中的数字
load %r1, a  // 将 a 的值加载到寄存器中 (如果不在寄存器中)
load %r2, b  // 将 b 的值加载到寄存器中
add %r0, %r1, %r2 // 将 %r1 和 %r2 的值相加，结果放入 %r0
return %r0      // 返回 %r0 中的值
```

`CodeAssembler` 提供了创建这些 `load`, `add`, `return` 等机器指令的抽象方法。  例如，在 `CodeAssembler` 中，加法操作可能通过类似 `IntPtrAdd(a_node, b_node)` 的方法来表示，其中 `a_node` 和 `b_node` 是代表变量 `a` 和 `b` 的 `TNode`。

**代码逻辑推理示例：**

假设有以下 `CodeAssembler` 代码片段：

```c++
TNode<Int32T> a = Int32Constant(10);
TNode<Int32T> b = Int32Constant(5);
TNode<BoolT> condition = Int32GreaterThan(a, b);
Label if_true(this), if_false(this);
Branch(condition, &if_true, &if_false);

Bind(&if_true);
  Return(Int32Constant(1));

Bind(&if_false);
  Return(Int32Constant(0));
```

**假设输入：** 无，因为这段代码是生成机器码的逻辑，而不是执行的逻辑。

**输出（生成的机器码的逻辑）：**  这段代码会生成一个条件分支的机器码。如果常量 `a` (10) 大于常量 `b` (5)，则返回整数常量 1，否则返回整数常量 0。由于 10 > 5 是静态确定的，编译器可能会优化掉分支，直接生成返回 1 的代码。

**用户常见的编程错误示例：**

在使用 `CodeAssembler` 时，用户可能会犯以下错误（注意，这里的“用户”通常是指 V8 的开发者或贡献者，而不是普通的 JavaScript 开发者）：

1. **类型不匹配:**  `CodeAssembler` 强调类型安全。 错误地将一个 `TNode<Object>` 传递给期望 `TNode<Int32T>` 的方法会导致编译错误或运行时错误（如果使用了 `UncheckedCast` 并且类型不兼容）。

   ```c++
   TNode<Object> obj = LoadRoot(RootIndex::kUndefinedValue);
   // 错误：尝试将 Object 视为 Int32T
   // TNode<Int32T> result = IntPtrAdd(obj, Int32Constant(1));
   ```

2. **忘记 `Bind` 标签:** 在使用 `Branch` 或其他控制流指令后，必须使用 `Bind` 将代码块与相应的标签关联起来。忘记 `Bind` 会导致代码执行流程混乱。

   ```c++
   Label my_label(this);
   Branch(some_condition, &my_label, ...);
   // 错误：忘记 Bind(&my_label);
   // ... 应该在 my_label 分支执行的代码 ...
   ```

3. **不正确的内存访问:**  使用 `Load` 和 `Store` 时，提供错误的偏移量或基址可能导致访问无效内存。

   ```c++
   TNode<RawPtrT> base_ptr = ...;
   TNode<IntPtrT> wrong_offset = IntPtrConstant(1000); // 可能超出对象边界
   Load(MachineType::Int32(), base_ptr, wrong_offset);
   ```

4. **错误地使用 `UncheckedCast`:**  `UncheckedCast` 绕过了类型检查，如果使用不当，会导致类型错误，最终可能导致崩溃或难以调试的问题。应该只在非常确定类型安全的情况下使用。

**总结一下 `v8/src/compiler/code-assembler.cc` 的功能：**

`v8/src/compiler/code-assembler.cc` 定义了 `CodeAssembler` 类，它是 V8 Turbofan 编译器中用于生成高效机器码的核心工具。它提供了一组类型安全的接口，用于创建代表各种操作和值的节点，并支持控制流、内存访问和函数调用等。`CodeAssembler` 与 Turbofan 的图表示紧密集成，并为 V8 开发者提供了一种结构化的方式来编写底层的代码生成逻辑，从而实现 JavaScript 代码的快速执行。

### 提示词
```
这是目录为v8/src/compiler/code-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/code-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/code-assembler.h"

#include <optional>
#include <ostream>

#include "src/builtins/builtins-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/tnode.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/linkage.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/pipeline.h"
#include "src/compiler/raw-machine-assembler.h"
#include "src/compiler/schedule.h"
#include "src/compiler/turbofan-graph.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory-inl.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/smi.h"
#include "src/utils/memcopy.h"
#include "src/zone/zone.h"

namespace v8 {
namespace internal {

constexpr MachineType MachineTypeOf<Smi>::value;
constexpr MachineType MachineTypeOf<Object>::value;
constexpr MachineType MachineTypeOf<MaybeObject>::value;

namespace compiler {

static_assert(std::is_convertible<TNode<Number>, TNode<Object>>::value,
              "test subtyping");
static_assert(
    std::is_convertible<TNode<Number>, TNode<UnionOf<Smi, HeapObject>>>::value,
    "test subtyping");
static_assert(
    !std::is_convertible<TNode<UnionOf<Smi, HeapObject>>, TNode<Number>>::value,
    "test subtyping");

CodeAssemblerState::CodeAssemblerState(
    Isolate* isolate, Zone* zone, const CallInterfaceDescriptor& descriptor,
    CodeKind kind, const char* name, Builtin builtin)
    // TODO(rmcilroy): Should we use Linkage::GetBytecodeDispatchDescriptor for
    // bytecode handlers?
    : CodeAssemblerState(
          isolate, zone,
          Linkage::GetStubCallDescriptor(
              zone, descriptor, descriptor.GetStackParameterCount(),
              CallDescriptor::kNoFlags, Operator::kNoProperties),
          kind, name, builtin) {}

CodeAssemblerState::CodeAssemblerState(Isolate* isolate, Zone* zone,
                                       int parameter_count, CodeKind kind,
                                       const char* name, Builtin builtin)
    : CodeAssemblerState(
          isolate, zone,
          Linkage::GetJSCallDescriptor(zone, false, parameter_count,
                                       CallDescriptor::kCanUseRoots),
          kind, name, builtin) {}

CodeAssemblerState::CodeAssemblerState(Isolate* isolate, Zone* zone,
                                       CallDescriptor* call_descriptor,
                                       CodeKind kind, const char* name,
                                       Builtin builtin)
    : raw_assembler_(new RawMachineAssembler(
          isolate, zone->New<Graph>(zone), call_descriptor,
          MachineType::PointerRepresentation(),
          InstructionSelector::SupportedMachineOperatorFlags(),
          InstructionSelector::AlignmentRequirements())),
      kind_(kind),
      name_(name),
      builtin_(builtin),
      code_generated_(false),
      variables_(zone),
      jsgraph_(zone->New<JSGraph>(
          isolate, raw_assembler_->graph(), raw_assembler_->common(),
          zone->New<JSOperatorBuilder>(zone), raw_assembler_->simplified(),
          raw_assembler_->machine())) {}

CodeAssemblerState::~CodeAssemblerState() = default;

int CodeAssemblerState::parameter_count() const {
  return static_cast<int>(raw_assembler_->parameter_count());
}

CodeAssembler::~CodeAssembler() = default;

#if DEBUG
void CodeAssemblerState::PrintCurrentBlock(std::ostream& os) {
  raw_assembler_->PrintCurrentBlock(os);
}
#endif

bool CodeAssemblerState::InsideBlock() { return raw_assembler_->InsideBlock(); }

void CodeAssemblerState::SetInitialDebugInformation(const char* msg,
                                                    const char* file,
                                                    int line) {
#if DEBUG
  AssemblerDebugInfo debug_info = {msg, file, line};
  raw_assembler_->SetCurrentExternalSourcePosition({file, line});
  raw_assembler_->SetInitialDebugInformation(debug_info);
#endif  // DEBUG
}

class BreakOnNodeDecorator final : public GraphDecorator {
 public:
  explicit BreakOnNodeDecorator(NodeId node_id) : node_id_(node_id) {}

  void Decorate(Node* node) final {
    if (node->id() == node_id_) {
      base::OS::DebugBreak();
    }
  }

 private:
  NodeId node_id_;
};

void CodeAssembler::BreakOnNode(int node_id) {
  Graph* graph = raw_assembler()->graph();
  Zone* zone = graph->zone();
  GraphDecorator* decorator =
      zone->New<BreakOnNodeDecorator>(static_cast<NodeId>(node_id));
  graph->AddDecorator(decorator);
}

void CodeAssembler::RegisterCallGenerationCallbacks(
    const CodeAssemblerCallback& call_prologue,
    const CodeAssemblerCallback& call_epilogue) {
  // The callback can be registered only once.
  DCHECK(!state_->call_prologue_);
  DCHECK(!state_->call_epilogue_);
  state_->call_prologue_ = call_prologue;
  state_->call_epilogue_ = call_epilogue;
}

void CodeAssembler::UnregisterCallGenerationCallbacks() {
  state_->call_prologue_ = nullptr;
  state_->call_epilogue_ = nullptr;
}

void CodeAssembler::CallPrologue() {
  if (state_->call_prologue_) {
    state_->call_prologue_();
  }
}

void CodeAssembler::CallEpilogue() {
  if (state_->call_epilogue_) {
    state_->call_epilogue_();
  }
}

bool CodeAssembler::Word32ShiftIsSafe() const {
  return raw_assembler()->machine()->Word32ShiftIsSafe();
}

// static
Handle<Code> CodeAssembler::GenerateCode(
    CodeAssemblerState* state, const AssemblerOptions& options,
    const ProfileDataFromFile* profile_data) {
  DCHECK(!state->code_generated_);

  RawMachineAssembler* rasm = state->raw_assembler_.get();

  Handle<Code> code;
  Graph* graph = rasm->ExportForOptimization();

  code = Pipeline::GenerateCodeForCodeStub(
             rasm->isolate(), rasm->call_descriptor(), graph, state->jsgraph_,
             rasm->source_positions(), state->kind_, state->name_,
             state->builtin_, options, profile_data)
             .ToHandleChecked();

  state->code_generated_ = true;
  return code;
}

bool CodeAssembler::Is64() const { return raw_assembler()->machine()->Is64(); }
bool CodeAssembler::Is32() const { return raw_assembler()->machine()->Is32(); }

bool CodeAssembler::IsFloat64RoundUpSupported() const {
  return raw_assembler()->machine()->Float64RoundUp().IsSupported();
}

bool CodeAssembler::IsFloat64RoundDownSupported() const {
  return raw_assembler()->machine()->Float64RoundDown().IsSupported();
}

bool CodeAssembler::IsFloat64RoundTiesEvenSupported() const {
  return raw_assembler()->machine()->Float64RoundTiesEven().IsSupported();
}

bool CodeAssembler::IsFloat64RoundTruncateSupported() const {
  return raw_assembler()->machine()->Float64RoundTruncate().IsSupported();
}

bool CodeAssembler::IsTruncateFloat64ToFloat16RawBitsSupported() const {
  return raw_assembler()
      ->machine()
      ->TruncateFloat64ToFloat16RawBits()
      .IsSupported();
}

bool CodeAssembler::IsInt32AbsWithOverflowSupported() const {
  return raw_assembler()->machine()->Int32AbsWithOverflow().IsSupported();
}

bool CodeAssembler::IsInt64AbsWithOverflowSupported() const {
  return raw_assembler()->machine()->Int64AbsWithOverflow().IsSupported();
}

bool CodeAssembler::IsIntPtrAbsWithOverflowSupported() const {
  return Is64() ? IsInt64AbsWithOverflowSupported()
                : IsInt32AbsWithOverflowSupported();
}

bool CodeAssembler::IsWord32PopcntSupported() const {
  return raw_assembler()->machine()->Word32Popcnt().IsSupported();
}

bool CodeAssembler::IsWord64PopcntSupported() const {
  return raw_assembler()->machine()->Word64Popcnt().IsSupported();
}

bool CodeAssembler::IsWord32CtzSupported() const {
  return raw_assembler()->machine()->Word32Ctz().IsSupported();
}

bool CodeAssembler::IsWord64CtzSupported() const {
  return raw_assembler()->machine()->Word64Ctz().IsSupported();
}

TNode<Int32T> CodeAssembler::UniqueInt32Constant(int32_t value) {
  return UncheckedCast<Int32T>(jsgraph()->UniqueInt32Constant(value));
}

TNode<Int32T> CodeAssembler::Int32Constant(int32_t value) {
  return UncheckedCast<Int32T>(jsgraph()->Int32Constant(value));
}

TNode<Int64T> CodeAssembler::UniqueInt64Constant(int64_t value) {
  return UncheckedCast<Int64T>(jsgraph()->UniqueInt64Constant(value));
}

TNode<Int64T> CodeAssembler::Int64Constant(int64_t value) {
  return UncheckedCast<Int64T>(jsgraph()->Int64Constant(value));
}

TNode<IntPtrT> CodeAssembler::UniqueIntPtrConstant(intptr_t value) {
  return UncheckedCast<IntPtrT>(jsgraph()->UniqueIntPtrConstant(value));
}

TNode<IntPtrT> CodeAssembler::IntPtrConstant(intptr_t value) {
  return UncheckedCast<IntPtrT>(jsgraph()->IntPtrConstant(value));
}

TNode<TaggedIndex> CodeAssembler::TaggedIndexConstant(intptr_t value) {
  DCHECK(TaggedIndex::IsValid(value));
  return UncheckedCast<TaggedIndex>(jsgraph()->TaggedIndexConstant(value));
}

TNode<Number> CodeAssembler::NumberConstant(double value) {
  int smi_value;
  if (DoubleToSmiInteger(value, &smi_value)) {
    return UncheckedCast<Number>(SmiConstant(smi_value));
  } else {
    // We allocate the heap number constant eagerly at this point instead of
    // deferring allocation to code generation
    // (see AllocateAndInstallRequestedHeapNumbers) since that makes it easier
    // to generate constant lookups for embedded builtins.
    return UncheckedCast<Number>(HeapConstantNoHole(
        isolate()->factory()->NewHeapNumberForCodeAssembler(value)));
  }
}

TNode<Smi> CodeAssembler::SmiConstant(Tagged<Smi> value) {
  return UncheckedCast<Smi>(BitcastWordToTaggedSigned(
      IntPtrConstant(static_cast<intptr_t>(value.ptr()))));
}

TNode<Smi> CodeAssembler::SmiConstant(int value) {
  return SmiConstant(Smi::FromInt(value));
}

// This emits an untyped heap constant that is never a hole.
TNode<HeapObject> CodeAssembler::UntypedHeapConstantNoHole(
    Handle<HeapObject> object) {
  // jsgraph()->HeapConstantNoHole does a CHECK that it is in fact a hole
  // value.
  return UncheckedCast<HeapObject>(jsgraph()->HeapConstantNoHole(object));
}

// This is used to emit untyped heap constants that can be a hole value.
// Only use this if you really need to and cannot use *NoHole or *Hole.
TNode<HeapObject> CodeAssembler::UntypedHeapConstantMaybeHole(
    Handle<HeapObject> object) {
  return UncheckedCast<HeapObject>(jsgraph()->HeapConstantMaybeHole(object));
}

// This is used to emit an untyped heap constant that can only be Hole values.
TNode<HeapObject> CodeAssembler::UntypedHeapConstantHole(
    Handle<HeapObject> object) {
  return UncheckedCast<HeapObject>(jsgraph()->HeapConstantHole(object));
}

TNode<String> CodeAssembler::StringConstant(const char* str) {
  Handle<String> internalized_string =
      factory()->InternalizeString(base::OneByteVector(str));
  return UncheckedCast<String>(HeapConstantNoHole(internalized_string));
}

TNode<Boolean> CodeAssembler::BooleanConstant(bool value) {
  Handle<Boolean> object = isolate()->factory()->ToBoolean(value);
  return UncheckedCast<Boolean>(
      jsgraph()->HeapConstantNoHole(i::Cast<HeapObject>(object)));
}

TNode<ExternalReference> CodeAssembler::ExternalConstant(
    ExternalReference address) {
  return UncheckedCast<ExternalReference>(
      raw_assembler()->ExternalConstant(address));
}

TNode<ExternalReference> CodeAssembler::IsolateField(IsolateFieldId id) {
  return ExternalConstant(ExternalReference::Create(id));
}

TNode<Float32T> CodeAssembler::Float32Constant(double value) {
  return UncheckedCast<Float32T>(jsgraph()->Float32Constant(value));
}

TNode<Float64T> CodeAssembler::Float64Constant(double value) {
  return UncheckedCast<Float64T>(jsgraph()->Float64Constant(value));
}

bool CodeAssembler::IsMapOffsetConstant(Node* node) {
  return raw_assembler()->IsMapOffsetConstant(node);
}

bool CodeAssembler::TryToInt32Constant(TNode<IntegralT> node,
                                       int32_t* out_value) {
  {
    Int64Matcher m(node);
    if (m.HasResolvedValue() &&
        m.IsInRange(std::numeric_limits<int32_t>::min(),
                    std::numeric_limits<int32_t>::max())) {
      *out_value = static_cast<int32_t>(m.ResolvedValue());
      return true;
    }
  }

  {
    Int32Matcher m(node);
    if (m.HasResolvedValue()) {
      *out_value = m.ResolvedValue();
      return true;
    }
  }

  return false;
}

bool CodeAssembler::TryToInt64Constant(TNode<IntegralT> node,
                                       int64_t* out_value) {
  Int64Matcher m(node);
  if (m.HasResolvedValue()) *out_value = m.ResolvedValue();
  return m.HasResolvedValue();
}

bool CodeAssembler::TryToSmiConstant(TNode<Smi> tnode, Tagged<Smi>* out_value) {
  Node* node = tnode;
  if (node->opcode() == IrOpcode::kBitcastWordToTaggedSigned) {
    node = node->InputAt(0);
  }
  return TryToSmiConstant(ReinterpretCast<IntPtrT>(tnode), out_value);
}

bool CodeAssembler::TryToSmiConstant(TNode<IntegralT> node,
                                     Tagged<Smi>* out_value) {
  IntPtrMatcher m(node);
  if (m.HasResolvedValue()) {
    intptr_t value = m.ResolvedValue();
    // Make sure that the value is actually a smi
    CHECK_EQ(0, value & ((static_cast<intptr_t>(1) << kSmiShiftSize) - 1));
    *out_value = Tagged<Smi>(static_cast<Address>(value));
    return true;
  }
  return false;
}

bool CodeAssembler::TryToIntPtrConstant(TNode<Smi> tnode, intptr_t* out_value) {
  Node* node = tnode;
  if (node->opcode() == IrOpcode::kBitcastWordToTaggedSigned ||
      node->opcode() == IrOpcode::kBitcastWordToTagged) {
    node = node->InputAt(0);
  }
  return TryToIntPtrConstant(ReinterpretCast<IntPtrT>(tnode), out_value);
}

bool CodeAssembler::TryToIntPtrConstant(TNode<IntegralT> node,
                                        intptr_t* out_value) {
  IntPtrMatcher m(node);
  if (m.HasResolvedValue()) *out_value = m.ResolvedValue();
  return m.HasResolvedValue();
}

bool CodeAssembler::IsUndefinedConstant(TNode<Object> node) {
  compiler::HeapObjectMatcher m(node);
  return m.Is(isolate()->factory()->undefined_value());
}

bool CodeAssembler::IsNullConstant(TNode<Object> node) {
  compiler::HeapObjectMatcher m(node);
  return m.Is(isolate()->factory()->null_value());
}

Node* CodeAssembler::UntypedParameter(int index) {
  if (index == kTargetParameterIndex) return raw_assembler()->TargetParameter();
  return raw_assembler()->Parameter(index);
}

bool CodeAssembler::IsJSFunctionCall() const {
  auto call_descriptor = raw_assembler()->call_descriptor();
  return call_descriptor->IsJSFunctionCall();
}

TNode<Context> CodeAssembler::GetJSContextParameter() {
  auto call_descriptor = raw_assembler()->call_descriptor();
  DCHECK(call_descriptor->IsJSFunctionCall());
  return Parameter<Context>(Linkage::GetJSCallContextParamIndex(
      static_cast<int>(call_descriptor->JSParameterCount())));
}

bool CodeAssembler::HasDynamicJSParameterCount() {
  return raw_assembler()->dynamic_js_parameter_count() != nullptr;
}

TNode<Uint16T> CodeAssembler::DynamicJSParameterCount() {
  DCHECK(HasDynamicJSParameterCount());
  return UncheckedCast<Uint16T>(raw_assembler()->dynamic_js_parameter_count());
}

void CodeAssembler::SetDynamicJSParameterCount(TNode<Uint16T> parameter_count) {
  DCHECK(!HasDynamicJSParameterCount());
  // For code to support a dynamic parameter count, it's static parameter count
  // must currently be zero, i.e. varargs. Otherwise we'd also need to ensure
  // that the dynamic parameter count is not smaller than the static one.
  //
  // TODO(saelo): it would probably be a bit nicer if we could assert here that
  // IsJSFunctionCall() is true and then use the JSParameterCount() of the
  // descriptor instead, but that doesn't work because not all users of this
  // feature are TFJ builtins (some are TFC builtins).
  DCHECK_EQ(raw_assembler()->call_descriptor()->ParameterSlotCount(), 0);
  raw_assembler()->set_dynamic_js_parameter_count(parameter_count);
}

void CodeAssembler::Return(TNode<Object> value) {
  DCHECK_EQ(1, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK(raw_assembler()->call_descriptor()->GetReturnType(0).IsTagged());
  return raw_assembler()->Return(value);
}

void CodeAssembler::Return(TNode<Object> value1, TNode<Object> value2) {
  DCHECK_EQ(2, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK(raw_assembler()->call_descriptor()->GetReturnType(0).IsTagged());
  DCHECK(raw_assembler()->call_descriptor()->GetReturnType(1).IsTagged());
  return raw_assembler()->Return(value1, value2);
}

void CodeAssembler::Return(TNode<Object> value1, TNode<Object> value2,
                           TNode<Object> value3) {
  DCHECK_EQ(3, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK(raw_assembler()->call_descriptor()->GetReturnType(0).IsTagged());
  DCHECK(raw_assembler()->call_descriptor()->GetReturnType(1).IsTagged());
  DCHECK(raw_assembler()->call_descriptor()->GetReturnType(2).IsTagged());
  return raw_assembler()->Return(value1, value2, value3);
}

void CodeAssembler::Return(TNode<Int32T> value) {
  DCHECK_EQ(1, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK_EQ(MachineType::Int32(),
            raw_assembler()->call_descriptor()->GetReturnType(0));
  return raw_assembler()->Return(value);
}

void CodeAssembler::Return(TNode<Uint32T> value) {
  DCHECK_EQ(1, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK_EQ(MachineType::Uint32(),
            raw_assembler()->call_descriptor()->GetReturnType(0));
  return raw_assembler()->Return(value);
}

void CodeAssembler::Return(TNode<WordT> value) {
  DCHECK_EQ(1, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK_EQ(
      MachineType::PointerRepresentation(),
      raw_assembler()->call_descriptor()->GetReturnType(0).representation());
  return raw_assembler()->Return(value);
}

void CodeAssembler::Return(TNode<Float32T> value) {
  DCHECK_EQ(1, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK_EQ(MachineType::Float32(),
            raw_assembler()->call_descriptor()->GetReturnType(0));
  return raw_assembler()->Return(value);
}

void CodeAssembler::Return(TNode<Float64T> value) {
  DCHECK_EQ(1, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK_EQ(MachineType::Float64(),
            raw_assembler()->call_descriptor()->GetReturnType(0));
  return raw_assembler()->Return(value);
}

void CodeAssembler::Return(TNode<WordT> value1, TNode<WordT> value2) {
  DCHECK_EQ(2, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK_EQ(
      MachineType::PointerRepresentation(),
      raw_assembler()->call_descriptor()->GetReturnType(0).representation());
  DCHECK_EQ(
      MachineType::PointerRepresentation(),
      raw_assembler()->call_descriptor()->GetReturnType(1).representation());
  return raw_assembler()->Return(value1, value2);
}

void CodeAssembler::Return(TNode<Word32T> value1, TNode<Word32T> value2) {
  DCHECK_EQ(2, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK_EQ(
      MachineRepresentation::kWord32,
      raw_assembler()->call_descriptor()->GetReturnType(0).representation());
  DCHECK_EQ(
      MachineRepresentation::kWord32,
      raw_assembler()->call_descriptor()->GetReturnType(1).representation());
  return raw_assembler()->Return(value1, value2);
}

void CodeAssembler::Return(TNode<WordT> value1, TNode<Object> value2) {
  DCHECK_EQ(2, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK_EQ(
      MachineType::PointerRepresentation(),
      raw_assembler()->call_descriptor()->GetReturnType(0).representation());
  DCHECK(raw_assembler()->call_descriptor()->GetReturnType(1).IsTagged());
  return raw_assembler()->Return(value1, value2);
}

void CodeAssembler::Return(TNode<Word32T> value1, TNode<Object> value2) {
  DCHECK_EQ(2, raw_assembler()->call_descriptor()->ReturnCount());
  DCHECK_EQ(
      MachineRepresentation::kWord32,
      raw_assembler()->call_descriptor()->GetReturnType(0).representation());
  DCHECK(raw_assembler()->call_descriptor()->GetReturnType(1).IsTagged());
  return raw_assembler()->Return(value1, value2);
}

void CodeAssembler::PopAndReturn(Node* pop, Node* value) {
  DCHECK_EQ(1, raw_assembler()->call_descriptor()->ReturnCount());
  return raw_assembler()->PopAndReturn(pop, value);
}

void CodeAssembler::PopAndReturn(Node* pop, Node* value1, Node* value2,
                                 Node* value3, Node* value4) {
  DCHECK_EQ(4, raw_assembler()->call_descriptor()->ReturnCount());
  return raw_assembler()->PopAndReturn(pop, value1, value2, value3, value4);
}

void CodeAssembler::ReturnIf(TNode<BoolT> condition, TNode<Object> value) {
  Label if_return(this), if_continue(this);
  Branch(condition, &if_return, &if_continue);
  Bind(&if_return);
  Return(value);
  Bind(&if_continue);
}

void CodeAssembler::AbortCSADcheck(Node* message) {
  raw_assembler()->AbortCSADcheck(message);
}

void CodeAssembler::DebugBreak() { raw_assembler()->DebugBreak(); }

void CodeAssembler::Unreachable() {
  DebugBreak();
  raw_assembler()->Unreachable();
}

void CodeAssembler::EmitComment(std::string str) {
  if (!v8_flags.code_comments) return;
  raw_assembler()->Comment(str);
}

void CodeAssembler::StaticAssert(TNode<BoolT> value, const char* source) {
  raw_assembler()->StaticAssert(value, source);
}

void CodeAssembler::SetSourcePosition(const char* file, int line) {
  raw_assembler()->SetCurrentExternalSourcePosition({file, line});
}

void CodeAssembler::PushSourcePosition() {
  auto position = raw_assembler()->GetCurrentExternalSourcePosition();
  state_->macro_call_stack_.push_back(position);
}

void CodeAssembler::PopSourcePosition() {
  state_->macro_call_stack_.pop_back();
}

const std::vector<FileAndLine>& CodeAssembler::GetMacroSourcePositionStack()
    const {
  return state_->macro_call_stack_;
}

void CodeAssembler::Bind(Label* label) { return label->Bind(); }

#if DEBUG
void CodeAssembler::Bind(Label* label, AssemblerDebugInfo debug_info) {
  return label->Bind(debug_info);
}
#endif  // DEBUG

TNode<RawPtrT> CodeAssembler::LoadFramePointer() {
  return UncheckedCast<RawPtrT>(raw_assembler()->LoadFramePointer());
}

TNode<RawPtrT> CodeAssembler::LoadParentFramePointer() {
  return UncheckedCast<RawPtrT>(raw_assembler()->LoadParentFramePointer());
}

#if V8_ENABLE_WEBASSEMBLY
TNode<RawPtrT> CodeAssembler::LoadStackPointer() {
  return UncheckedCast<RawPtrT>(raw_assembler()->LoadStackPointer());
}

void CodeAssembler::SetStackPointer(TNode<RawPtrT> ptr) {
  raw_assembler()->SetStackPointer(ptr);
}
#endif

TNode<RawPtrT> CodeAssembler::LoadPointerFromRootRegister(
    TNode<IntPtrT> offset) {
  return UncheckedCast<RawPtrT>(
      Load(MachineType::IntPtr(), raw_assembler()->LoadRootRegister(), offset));
}

TNode<Uint8T> CodeAssembler::LoadUint8FromRootRegister(TNode<IntPtrT> offset) {
  return UncheckedCast<Uint8T>(
      Load(MachineType::Uint8(), raw_assembler()->LoadRootRegister(), offset));
}

TNode<RawPtrT> CodeAssembler::StackSlotPtr(int size, int alignment) {
  return UncheckedCast<RawPtrT>(raw_assembler()->StackSlot(size, alignment));
}

#define DEFINE_CODE_ASSEMBLER_BINARY_OP(name, ResType, Arg1Type, Arg2Type)   \
  TNode<ResType> CodeAssembler::name(TNode<Arg1Type> a, TNode<Arg2Type> b) { \
    return UncheckedCast<ResType>(raw_assembler()->name(a, b));              \
  }
CODE_ASSEMBLER_BINARY_OP_LIST(DEFINE_CODE_ASSEMBLER_BINARY_OP)
#undef DEFINE_CODE_ASSEMBLER_BINARY_OP

TNode<PairT<Word32T, Word32T>> CodeAssembler::Int32PairAdd(
    TNode<Word32T> lhs_lo_word, TNode<Word32T> lhs_hi_word,
    TNode<Word32T> rhs_lo_word, TNode<Word32T> rhs_hi_word) {
  return UncheckedCast<PairT<Word32T, Word32T>>(raw_assembler()->Int32PairAdd(
      lhs_lo_word, lhs_hi_word, rhs_lo_word, rhs_hi_word));
}

TNode<PairT<Word32T, Word32T>> CodeAssembler::Int32PairSub(
    TNode<Word32T> lhs_lo_word, TNode<Word32T> lhs_hi_word,
    TNode<Word32T> rhs_lo_word, TNode<Word32T> rhs_hi_word) {
  return UncheckedCast<PairT<Word32T, Word32T>>(raw_assembler()->Int32PairSub(
      lhs_lo_word, lhs_hi_word, rhs_lo_word, rhs_hi_word));
}

TNode<WordT> CodeAssembler::WordShl(TNode<WordT> value, int shift) {
  return (shift != 0) ? WordShl(value, IntPtrConstant(shift)) : value;
}

TNode<WordT> CodeAssembler::WordShr(TNode<WordT> value, int shift) {
  return (shift != 0) ? WordShr(value, IntPtrConstant(shift)) : value;
}

TNode<WordT> CodeAssembler::WordSar(TNode<WordT> value, int shift) {
  return (shift != 0) ? WordSar(value, IntPtrConstant(shift)) : value;
}

TNode<Word32T> CodeAssembler::Word32Shr(TNode<Word32T> value, int shift) {
  return (shift != 0) ? Word32Shr(value, Int32Constant(shift)) : value;
}

TNode<Word32T> CodeAssembler::Word32Sar(TNode<Word32T> value, int shift) {
  return (shift != 0) ? Word32Sar(value, Int32Constant(shift)) : value;
}

#define CODE_ASSEMBLER_COMPARE(Name, ArgT, VarT, ToConstant, op)          \
  TNode<BoolT> CodeAssembler::Name(TNode<ArgT> left, TNode<ArgT> right) { \
    VarT lhs, rhs;                                                        \
    if (ToConstant(left, &lhs) && ToConstant(right, &rhs)) {              \
      return BoolConstant(lhs op rhs);                                    \
    }                                                                     \
    return UncheckedCast<BoolT>(raw_assembler()->Name(left, right));      \
  }

CODE_ASSEMBLER_COMPARE(IntPtrEqual, WordT, intptr_t, TryToIntPtrConstant, ==)
CODE_ASSEMBLER_COMPARE(WordEqual, WordT, intptr_t, TryToIntPtrConstant, ==)
CODE_ASSEMBLER_COMPARE(WordNotEqual, WordT, intptr_t, TryToIntPtrConstant, !=)
CODE_ASSEMBLER_COMPARE(Word32Equal, Word32T, int32_t, TryToInt32Constant, ==)
CODE_ASSEMBLER_COMPARE(Word32NotEqual, Word32T, int32_t, TryToInt32Constant, !=)
CODE_ASSEMBLER_COMPARE(Word64Equal, Word64T, int64_t, TryToInt64Constant, ==)
CODE_ASSEMBLER_COMPARE(Word64NotEqual, Word64T, int64_t, TryToInt64Constant, !=)
#undef CODE_ASSEMBLER_COMPARE

TNode<UintPtrT> CodeAssembler::ChangeUint32ToWord(TNode<Word32T> value) {
  if (raw_assembler()->machine()->Is64()) {
    return UncheckedCast<UintPtrT>(
        raw_assembler()->ChangeUint32ToUint64(value));
  }
  return ReinterpretCast<UintPtrT>(value);
}

TNode<IntPtrT> CodeAssembler::ChangeInt32ToIntPtr(TNode<Word32T> value) {
  if (raw_assembler()->machine()->Is64()) {
    return UncheckedCast<IntPtrT>(raw_assembler()->ChangeInt32ToInt64(value));
  }
  return ReinterpretCast<IntPtrT>(value);
}

TNode<IntPtrT> CodeAssembler::ChangeFloat64ToIntPtr(TNode<Float64T> value) {
  if (raw_assembler()->machine()->Is64()) {
    return UncheckedCast<IntPtrT>(raw_assembler()->ChangeFloat64ToInt64(value));
  }
  return UncheckedCast<IntPtrT>(raw_assembler()->ChangeFloat64ToInt32(value));
}

TNode<UintPtrT> CodeAssembler::ChangeFloat64ToUintPtr(TNode<Float64T> value) {
  if (raw_assembler()->machine()->Is64()) {
    return UncheckedCast<UintPtrT>(
        raw_assembler()->ChangeFloat64ToUint64(value));
  }
  return UncheckedCast<UintPtrT>(raw_assembler()->ChangeFloat64ToUint32(value));
}

TNode<Float64T> CodeAssembler::ChangeUintPtrToFloat64(TNode<UintPtrT> value) {
  if (raw_assembler()->machine()->Is64()) {
    // TODO(turbofan): Maybe we should introduce a ChangeUint64ToFloat64
    // machine operator to TurboFan here?
    return UncheckedCast<Float64T>(
        raw_assembler()->RoundUint64ToFloat64(value));
  }
  return UncheckedCast<Float64T>(raw_assembler()->ChangeUint32ToFloat64(value));
}

TNode<Float64T> CodeAssembler::RoundIntPtrToFloat64(Node* value) {
  if (raw_assembler()->machine()->Is64()) {
    return UncheckedCast<Float64T>(raw_assembler()->RoundInt64ToFloat64(value));
  }
  return UncheckedCast<Float64T>(raw_assembler()->ChangeInt32ToFloat64(value));
}

TNode<Int32T> CodeAssembler::TruncateFloat32ToInt32(TNode<Float32T> value) {
  return UncheckedCast<Int32T>(raw_assembler()->TruncateFloat32ToInt32(
      value, TruncateKind::kSetOverflowToMin));
}
TNode<Int64T> CodeAssembler::TruncateFloat64ToInt64(TNode<Float64T> value) {
  return UncheckedCast<Int64T>(raw_assembler()->TruncateFloat64ToInt64(
      value, TruncateKind::kSetOverflowToMin));
}
#define DEFINE_CODE_ASSEMBLER_UNARY_OP(name, ResType, ArgType) \
  TNode<ResType> CodeAssembler::name(TNode<ArgType> a) {       \
    return UncheckedCast<ResType>(raw_assembler()->name(a));   \
  }
CODE_ASSEMBLER_UNARY_OP_LIST(DEFINE_CODE_ASSEMBLER_UNARY_OP)
#undef DEFINE_CODE_ASSEMBLER_UNARY_OP

Node* CodeAssembler::Load(MachineType type, Node* base) {
  return raw_assembler()->Load(type, base);
}

Node* CodeAssembler::Load(MachineType type, Node* base, Node* offset) {
  return raw_assembler()->Load(type, base, offset);
}

TNode<Object> CodeAssembler::LoadFullTagged(Node* base) {
  return BitcastWordToTagged(Load<RawPtrT>(base));
}

TNode<Object> CodeAssembler::LoadFullTagged(Node* base, TNode<IntPtrT> offset) {
  // Please use LoadFromObject(MachineType::MapInHeader(), object,
  // IntPtrConstant(-kHeapObjectTag)) instead.
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  return BitcastWordToTagged(Load<RawPtrT>(base, offset));
}

Node* CodeAssembler::AtomicLoad(MachineType type, AtomicMemoryOrder order,
                                TNode<RawPtrT> base, TNode<WordT> offset) {
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  return raw_assembler()->AtomicLoad(AtomicLoadParameters(type, order), base,
                                     offset);
}

template <class Type>
TNode<Type> CodeAssembler::AtomicLoad64(AtomicMemoryOrder order,
                                        TNode<RawPtrT> base,
                                        TNode<WordT> offset) {
  return UncheckedCast<Type>(raw_assembler()->AtomicLoad64(
      AtomicLoadParameters(MachineType::Uint64(), order), base, offset));
}

template TNode<AtomicInt64> CodeAssembler::AtomicLoad64<AtomicInt64>(
    AtomicMemoryOrder order, TNode<RawPtrT> base, TNode<WordT> offset);
template TNode<AtomicUint64> CodeAssembler::AtomicLoad64<AtomicUint64>(
    AtomicMemoryOrder order, TNode<RawPtrT> base, TNode<WordT> offset);

Node* CodeAssembler::LoadFromObject(MachineType type, TNode<Object> object,
                                    TNode<IntPtrT> offset) {
  return raw_assembler()->LoadFromObject(type, object, offset);
}

Node* CodeAssembler::LoadProtectedPointerFromObject(TNode<Object> object,
                                                    TNode<IntPtrT> offset) {
  return raw_assembler()->LoadProtectedPointerFromObject(object, offset);
}

#ifdef V8_MAP_PACKING
Node* CodeAssembler::PackMapWord(Node* value) {
  TNode<IntPtrT> map_word =
      BitcastTaggedToWordForTagAndSmiBits(UncheckedCast<AnyTaggedT>(value));
  TNode<WordT> packed = WordXor(UncheckedCast<WordT>(map_word),
                                IntPtrConstant(Internals::kMapWordXorMask));
  return BitcastWordToTaggedSigned(packed);
}
#endif

TNode<AnyTaggedT> CodeAssembler::LoadRootMapWord(RootIndex root_index) {
#ifdef V8_MAP_PACKING
  Handle<Object> root = isolate()->root_handle(root_index);
  Node* map = HeapConstantNoHole(Cast<Map>(root));
  map = PackMapWord(map);
  return ReinterpretCast<AnyTaggedT>(map);
#else
  return LoadRoot(root_index);
#endif
}

TNode<Object> CodeAssembler::LoadRoot(RootIndex root_index) {
  if (RootsTable::IsImmortalImmovable(root_index)) {
    Handle<Object> root = isolate()->root_handle(root_index);
    if (IsSmi(*root)) {
      return SmiConstant(i::Cast<Smi>(*root));
    } else {
      return HeapConstantMaybeHole(i::Cast<HeapObject>(root));
    }
  }

  // TODO(jgruber): In theory we could generate better code for this by
  // letting the macro assembler decide how to load from the roots list. In most
  // cases, it would boil down to loading from a fixed kRootRegister offset.
  TNode<ExternalReference> isolate_root =
      ExternalConstant(ExternalReference::isolate_root(isolate()));
  int offset = IsolateData::root_slot_offset(root_index);
  return UncheckedCast<Object>(
      LoadFullTagged(isolate_root, IntPtrConstant(offset)));
}

Node* CodeAssembler::UnalignedLoad(MachineType type, TNode<RawPtrT> base,
                                   TNode<WordT> offset) {
  return raw_assembler()->UnalignedLoad(type, static_cast<Node*>(base), offset);
}

void CodeAssembler::Store(Node* base, Node* value) {
  raw_assembler()->Store(MachineRepresentation::kTagged, base, value,
                         kFullWriteBarrier);
}

void CodeAssembler::StoreToObject(MachineRepresentation rep,
                                  TNode<Object> object, TNode<IntPtrT> offset,
                                  Node* value,
                                  StoreToObjectWriteBarrier write_barrier) {
  WriteBarrierKind write_barri
```