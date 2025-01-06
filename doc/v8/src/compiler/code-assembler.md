Response: The user wants me to summarize the functionality of the C++ source code file `v8/src/compiler/code-assembler.cc`. It's the first part of a two-part file. I should also illustrate its connection to JavaScript using a JavaScript example.

**Plan:**

1. **Identify Key Classes and Structures:** Look for the main class definitions and significant data structures within the provided code.
2. **Analyze Constructor and Destructor Logic:** Understand how the core objects are initialized and cleaned up. This often reveals the purpose of the class.
3. **Examine Public Methods:** Focus on the public methods as they define the interface and functionalities exposed by the class.
4. **Look for Interactions with Other V8 Components:** Note the `#include` directives and mentions of other V8 subsystems (e.g., `JSGraph`, `RawMachineAssembler`, `Pipeline`, `Builtins`).
5. **Infer the Overall Goal:** Based on the identified elements, determine the primary purpose of the `CodeAssembler`.
6. **Connect to JavaScript:** Identify how the functionalities provided by `CodeAssembler` relate to the execution of JavaScript code. This might involve code generation, optimization, or runtime interactions.
7. **Construct a JavaScript Example:** Create a simple JavaScript snippet that demonstrates the concepts or operations facilitated by the `CodeAssembler`.
这个C++源代码文件 `v8/src/compiler/code-assembler.cc` (第1部分) 定义了 `CodeAssembler` 类及其相关的辅助类和结构体，其主要功能是提供一个**高级的接口**，用于在 **V8 编译器**中生成 **机器码**。

更具体地说，`CodeAssembler` 允许开发者以一种更抽象和类型安全的方式构建 **TurboFan 图 (TurboFan Graph)**，这是 V8 编译器中用于代码优化的中间表示。它封装了底层的 `RawMachineAssembler`，后者直接操作机器指令。

**主要功能归纳:**

1. **抽象机器码生成:**  `CodeAssembler` 提供了诸如加载、存储、算术运算、逻辑运算、控制流（跳转、分支、循环）等操作的抽象方法，这些方法最终会被转换为底层的机器码指令。
2. **类型安全:**  `CodeAssembler` 使用模板化的 `TNode` 类型来表示图中的节点，并强制执行类型约束，从而减少了手动操作机器码时可能出现的错误。例如，`TNode<Int32T>` 表示一个 32 位整数类型的节点。
3. **与 TurboFan 图集成:** `CodeAssembler` 与 V8 的 TurboFan 优化编译器紧密集成，它生成的节点会被用于构建 TurboFan 图，并参与后续的优化和代码生成过程。
4. **内置函数和运行时调用:**  它提供了方便的方法来调用 V8 的内置函数 (builtins) 和运行时函数 (runtime functions)。
5. **控制流管理:**  `CodeAssembler` 提供了 `Label` 类来管理代码块和控制流，例如实现条件分支 (`Branch`) 和跳转 (`Goto`)。
6. **变量管理:** `CodeAssemblerVariable` 类用于声明和管理局部变量，并处理在控制流中合并变量状态的情况。
7. **调试支持:** 提供了 `BreakOnNode` 方法用于在指定的图节点处设置断点，方便调试编译过程。
8. **处理调用约定:**  它处理了函数调用时的参数传递、返回值处理等细节。
9. **支持 WebAssembly (如果启用):**  包含了与 WebAssembly 相关的栈切换功能 (`SwitchToTheCentralStack`, `SwitchFromTheCentralStack`).

**与 JavaScript 的关系及 JavaScript 例子:**

`CodeAssembler` 生成的机器码最终会执行 JavaScript 代码。当 V8 编译 JavaScript 代码（特别是热点代码，会被 TurboFan 编译）时，`CodeAssembler` 就扮演着关键的角色。开发者可以使用 `CodeAssembler` 来实现 JavaScript 的内置函数、优化的代码路径或者一些底层的操作。

**JavaScript 例子:**

虽然我们不能直接在 JavaScript 中使用 `CodeAssembler` 的 API，但我们可以通过一个简单的 JavaScript 例子来理解其背后的工作原理。

假设我们有以下 JavaScript 函数：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 的 TurboFan 编译这个 `add` 函数时，`CodeAssembler` 可能会生成类似于以下逻辑的机器码（这是一个高度简化的概念性示例，并非实际生成的精确代码）：

1. **加载参数:**  从寄存器或栈中加载参数 `a` 和 `b`。
2. **类型检查:**  检查 `a` 和 `b` 的类型。
3. **执行加法:**
   - 如果 `a` 和 `b` 都是整数，则执行整数加法。
   - 如果 `a` 和 `b` 都是浮点数，则执行浮点数加法。
   - 如果类型不同，则可能调用一个更复杂的运行时函数来处理类型转换和加法。
4. **返回结果:** 将计算结果存储到指定的寄存器或栈位置，并返回。

**在 `CodeAssembler` 中，上述步骤可能会对应以下的操作 (概念性):**

```c++
// 假设在 CodeAssembler 的上下文中
TNode<Object> a = Parameter(0); // 获取第一个参数
TNode<Object> b = Parameter(1); // 获取第二个参数

// 类型检查 (简化)
Label if_a_is_smi(this), if_not_smi(this);
Branch(IsSmi(a), &if_a_is_smi, &if_not_smi);

Bind(&if_a_is_smi);
  Label if_b_is_smi(this), if_b_not_smi(this);
  Branch(IsSmi(b), &if_b_is_smi, &if_b_not_smi);

  Bind(&if_b_is_smi);
    // 执行 Smi 加法
    TNode<Smi> smi_a = UncheckedCast<Smi>(a);
    TNode<Smi> smi_b = UncheckedCast<Smi>(b);
    TNode<Smi> result = SmiAdd(smi_a, smi_b);
    Return(result);
  Bind(&if_b_not_smi);
    // 处理 b 不是 Smi 的情况 (可能调用运行时)
    Return(CallRuntime(Runtime::kAdd, ...));

Bind(&if_not_smi);
  // 处理 a 不是 Smi 的情况 (可能调用运行时)
  Return(CallRuntime(Runtime::kAdd, ...));
```

**总结:**

`CodeAssembler` 是 V8 编译器中用于生成高效机器码的关键组件。它通过提供一个高级且类型安全的接口，简化了机器码的生成过程，并与 TurboFan 优化编译器紧密配合，最终提升了 JavaScript 代码的执行效率。虽然 JavaScript 开发者不能直接使用它，但 `CodeAssembler` 的工作直接影响着 JavaScript 代码的性能。

Prompt: 
```
这是目录为v8/src/compiler/code-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
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
  WriteBarrierKind write_barrier_kind;
  switch (write_barrier) {
    case StoreToObjectWriteBarrier::kFull:
      write_barrier_kind = WriteBarrierKind::kFullWriteBarrier;
      break;
    case StoreToObjectWriteBarrier::kMap:
      write_barrier_kind = WriteBarrierKind::kMapWriteBarrier;
      break;
    case StoreToObjectWriteBarrier::kNone:
      if (CanBeTaggedPointer(rep)) {
        write_barrier_kind = WriteBarrierKind::kAssertNoWriteBarrier;
      } else {
        write_barrier_kind = WriteBarrierKind::kNoWriteBarrier;
      }
      break;
  }
  raw_assembler()->StoreToObject(rep, object, offset, value,
                                 write_barrier_kind);
}

void CodeAssembler::OptimizedStoreField(MachineRepresentation rep,
                                        TNode<HeapObject> object, int offset,
                                        Node* value) {
  raw_assembler()->OptimizedStoreField(rep, object, offset, value,
                                       WriteBarrierKind::kFullWriteBarrier);
}

void CodeAssembler::OptimizedStoreIndirectPointerField(TNode<HeapObject> object,
                                                       int offset,
                                                       IndirectPointerTag tag,
                                                       Node* value) {
  raw_assembler()->OptimizedStoreIndirectPointerField(
      object, offset, tag, value,
      WriteBarrierKind::kIndirectPointerWriteBarrier);
}

void CodeAssembler::OptimizedStoreIndirectPointerFieldNoWriteBarrier(
    TNode<HeapObject> object, int offset, IndirectPointerTag tag, Node* value) {
  raw_assembler()->OptimizedStoreIndirectPointerField(
      object, offset, tag, value, WriteBarrierKind::kNoWriteBarrier);
}

void CodeAssembler::OptimizedStoreFieldAssertNoWriteBarrier(
    MachineRepresentation rep, TNode<HeapObject> object, int offset,
    Node* value) {
  raw_assembler()->OptimizedStoreField(rep, object, offset, value,
                                       WriteBarrierKind::kAssertNoWriteBarrier);
}

void CodeAssembler::OptimizedStoreFieldUnsafeNoWriteBarrier(
    MachineRepresentation rep, TNode<HeapObject> object, int offset,
    Node* value) {
  raw_assembler()->OptimizedStoreField(rep, object, offset, value,
                                       WriteBarrierKind::kNoWriteBarrier);
}

void CodeAssembler::OptimizedStoreMap(TNode<HeapObject> object,
                                      TNode<Map> map) {
  raw_assembler()->OptimizedStoreMap(object, map);
}

void CodeAssembler::Store(Node* base, Node* offset, Node* value) {
  // Please use OptimizedStoreMap(base, value) instead.
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  raw_assembler()->Store(MachineRepresentation::kTagged, base, offset, value,
                         kFullWriteBarrier);
}

void CodeAssembler::StoreEphemeronKey(Node* base, Node* offset, Node* value) {
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  raw_assembler()->Store(MachineRepresentation::kTagged, base, offset, value,
                         kEphemeronKeyWriteBarrier);
}

void CodeAssembler::StoreNoWriteBarrier(MachineRepresentation rep, Node* base,
                                        Node* value) {
  raw_assembler()->Store(
      rep, base, value,
      CanBeTaggedPointer(rep) ? kAssertNoWriteBarrier : kNoWriteBarrier);
}

void CodeAssembler::StoreNoWriteBarrier(MachineRepresentation rep, Node* base,
                                        Node* offset, Node* value) {
  // Please use OptimizedStoreMap(base, value) instead.
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  raw_assembler()->Store(
      rep, base, offset, value,
      CanBeTaggedPointer(rep) ? kAssertNoWriteBarrier : kNoWriteBarrier);
}

void CodeAssembler::UnsafeStoreNoWriteBarrier(MachineRepresentation rep,
                                              Node* base, Node* value) {
  raw_assembler()->Store(rep, base, value, kNoWriteBarrier);
}

void CodeAssembler::UnsafeStoreNoWriteBarrier(MachineRepresentation rep,
                                              Node* base, Node* offset,
                                              Node* value) {
  // Please use OptimizedStoreMap(base, value) instead.
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  raw_assembler()->Store(rep, base, offset, value, kNoWriteBarrier);
}

void CodeAssembler::StoreFullTaggedNoWriteBarrier(TNode<RawPtrT> base,
                                                  TNode<Object> tagged_value) {
  StoreNoWriteBarrier(MachineType::PointerRepresentation(), base,
                      BitcastTaggedToWord(tagged_value));
}

void CodeAssembler::StoreFullTaggedNoWriteBarrier(TNode<RawPtrT> base,
                                                  TNode<IntPtrT> offset,
                                                  TNode<Object> tagged_value) {
  // Please use OptimizedStoreMap(base, tagged_value) instead.
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  StoreNoWriteBarrier(MachineType::PointerRepresentation(), base, offset,
                      BitcastTaggedToWord(tagged_value));
}

void CodeAssembler::AtomicStore(MachineRepresentation rep,
                                AtomicMemoryOrder order, TNode<RawPtrT> base,
                                TNode<WordT> offset, TNode<Word32T> value) {
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  raw_assembler()->AtomicStore(
      AtomicStoreParameters(rep, WriteBarrierKind::kNoWriteBarrier, order),
      base, offset, value);
}

void CodeAssembler::AtomicStore64(AtomicMemoryOrder order, TNode<RawPtrT> base,
                                  TNode<WordT> offset, TNode<UintPtrT> value,
                                  TNode<UintPtrT> value_high) {
  raw_assembler()->AtomicStore64(
      AtomicStoreParameters(MachineRepresentation::kWord64,
                            WriteBarrierKind::kNoWriteBarrier, order),
      base, offset, value, value_high);
}

#define ATOMIC_FUNCTION(name)                                                 \
  TNode<Word32T> CodeAssembler::Atomic##name(                                 \
      MachineType type, TNode<RawPtrT> base, TNode<UintPtrT> offset,          \
      TNode<Word32T> value) {                                                 \
    return UncheckedCast<Word32T>(                                            \
        raw_assembler()->Atomic##name(type, base, offset, value));            \
  }                                                                           \
  template <class Type>                                                       \
  TNode<Type> CodeAssembler::Atomic##name##64(                                \
      TNode<RawPtrT> base, TNode<UintPtrT> offset, TNode<UintPtrT> value,     \
      TNode<UintPtrT> value_high) {                                           \
    return UncheckedCast<Type>(                                               \
        raw_assembler()->Atomic##name##64(base, offset, value, value_high));  \
  }                                                                           \
  template TNode<AtomicInt64> CodeAssembler::Atomic##name##64 < AtomicInt64 > \
      (TNode<RawPtrT> base, TNode<UintPtrT> offset, TNode<UintPtrT> value,    \
       TNode<UintPtrT> value_high);                                           \
  template TNode<AtomicUint64> CodeAssembler::Atomic##name##64 <              \
      AtomicUint64 > (TNode<RawPtrT> base, TNode<UintPtrT> offset,            \
                      TNode<UintPtrT> value, TNode<UintPtrT> value_high);
ATOMIC_FUNCTION(Add)
ATOMIC_FUNCTION(Sub)
ATOMIC_FUNCTION(And)
ATOMIC_FUNCTION(Or)
ATOMIC_FUNCTION(Xor)
ATOMIC_FUNCTION(Exchange)
#undef ATOMIC_FUNCTION

TNode<Word32T> CodeAssembler::AtomicCompareExchange(MachineType type,
                                                    TNode<RawPtrT> base,
                                                    TNode<WordT> offset,
                                                    TNode<Word32T> old_value,
                                                    TNode<Word32T> new_value) {
  return UncheckedCast<Word32T>(raw_assembler()->AtomicCompareExchange(
      type, base, offset, old_value, new_value));
}

template <class Type>
TNode<Type> CodeAssembler::AtomicCompareExchange64(
    TNode<RawPtrT> base, TNode<WordT> offset, TNode<UintPtrT> old_value,
    TNode<UintPtrT> new_value, TNode<UintPtrT> old_value_high,
    TNode<UintPtrT> new_value_high) {
  // This uses Uint64() intentionally: AtomicCompareExchange is not implemented
  // for Int64(), which is fine because the machine instruction only cares
  // about words.
  return UncheckedCast<Type>(raw_assembler()->AtomicCompareExchange64(
      base, offset, old_value, old_value_high, new_value, new_value_high));
}

template TNode<AtomicInt64> CodeAssembler::AtomicCompareExchange64<AtomicInt64>(
    TNode<RawPtrT> base, TNode<WordT> offset, TNode<UintPtrT> old_value,
    TNode<UintPtrT> new_value, TNode<UintPtrT> old_value_high,
    TNode<UintPtrT> new_value_high);
template TNode<AtomicUint64>
CodeAssembler::AtomicCompareExchange64<AtomicUint64>(
    TNode<RawPtrT> base, TNode<WordT> offset, TNode<UintPtrT> old_value,
    TNode<UintPtrT> new_value, TNode<UintPtrT> old_value_high,
    TNode<UintPtrT> new_value_high);

void CodeAssembler::MemoryBarrier(AtomicMemoryOrder order) {
  raw_assembler()->MemoryBarrier(order);
}

void CodeAssembler::StoreRoot(RootIndex root_index, TNode<Object> value) {
  DCHECK(!RootsTable::IsImmortalImmovable(root_index));
  TNode<ExternalReference> isolate_root =
      ExternalConstant(ExternalReference::isolate_root(isolate()));
  int offset = IsolateData::root_slot_offset(root_index);
  StoreFullTaggedNoWriteBarrier(isolate_root, IntPtrConstant(offset), value);
}

Node* CodeAssembler::Projection(int index, Node* value) {
  DCHECK_LT(index, value->op()->ValueOutputCount());
  return raw_assembler()->Projection(index, value);
}

TNode<HeapObject> CodeAssembler::OptimizedAllocate(TNode<IntPtrT> size,
                                                   AllocationType allocation) {
  return UncheckedCast<HeapObject>(
      raw_assembler()->OptimizedAllocate(size, allocation));
}

void CodeAssembler::HandleException(Node* node) {
  if (state_->exception_handler_labels_.empty()) return;
  CodeAssemblerExceptionHandlerLabel* label =
      state_->exception_handler_labels_.back();

  if (node->op()->HasProperty(Operator::kNoThrow)) {
    return;
  }

  Label success(this), exception(this, Label::kDeferred);
  success.MergeVariables();
  exception.MergeVariables();

  raw_assembler()->Continuations(node, success.label_, exception.label_);

  Bind(&exception);
  const Operator* op = raw_assembler()->common()->IfException();
  Node* exception_value = raw_assembler()->AddNode(op, node, node);
  label->AddInputs({UncheckedCast<Object>(exception_value)});
  Goto(label->plain_label());

  Bind(&success);
  raw_assembler()->AddNode(raw_assembler()->common()->IfSuccess(), node);
}

namespace {
template <size_t kMaxSize>
class NodeArray {
 public:
  void Add(Node* node) {
    DCHECK_GT(kMaxSize, size());
    *ptr_++ = node;
  }

  Node* const* data() const { return arr_; }
  int size() const { return static_cast<int>(ptr_ - arr_); }

 private:
  Node* arr_[kMaxSize];
  Node** ptr_ = arr_;
};

#ifdef DEBUG
bool IsValidArgumentCountFor(const CallInterfaceDescriptor& descriptor,
                             size_t argument_count) {
  size_t parameter_count = descriptor.GetParameterCount();
  if (descriptor.AllowVarArgs()) {
    return argument_count >= parameter_count;
  } else {
    return argument_count == parameter_count;
  }
}
#endif  // DEBUG
}  // namespace

Node* CodeAssembler::CallRuntimeImpl(
    Runtime::FunctionId function, TNode<Object> context,
    std::initializer_list<TNode<Object>> args) {
  int result_size = Runtime::FunctionForId(function)->result_size;
#if V8_ENABLE_WEBASSEMBLY
  bool switch_to_the_central_stack =
      state_->kind_ == CodeKind::WASM_FUNCTION ||
      state_->kind_ == CodeKind::WASM_TO_JS_FUNCTION ||
      state_->kind_ == CodeKind::JS_TO_WASM_FUNCTION ||
      state_->builtin_ == Builtin::kJSToWasmWrapper ||
      state_->builtin_ == Builtin::kJSToWasmHandleReturns ||
      state_->builtin_ == Builtin::kWasmToJsWrapperCSA ||
      wasm::BuiltinLookup::IsWasmBuiltinId(state_->builtin_);
#else
  bool switch_to_the_central_stack = false;
#endif
  Builtin centry =
      Builtins::RuntimeCEntry(result_size, switch_to_the_central_stack);
  TNode<Code> centry_code =
      HeapConstantNoHole(isolate()->builtins()->code_handle(centry));
  constexpr size_t kMaxNumArgs = 7;
  DCHECK_GE(kMaxNumArgs, args.size());
  int argc = static_cast<int>(args.size());
  auto call_descriptor = Linkage::GetRuntimeCallDescriptor(
      zone(), function, argc, Operator::kNoProperties,
      Runtime::MayAllocate(function) ? CallDescriptor::kNoFlags
                                     : CallDescriptor::kNoAllocate);

  TNode<ExternalReference> ref =
      ExternalConstant(ExternalReference::Create(function));
  TNode<Int32T> arity = Int32Constant(argc);

  NodeArray<kMaxNumArgs + 4> inputs;
  inputs.Add(centry_code);
  for (const auto& arg : args) inputs.Add(arg);
  inputs.Add(ref);
  inputs.Add(arity);
  inputs.Add(context);

  CallPrologue();
  Node* return_value =
      raw_assembler()->CallN(call_descriptor, inputs.size(), inputs.data());
  HandleException(return_value);
  CallEpilogue();
  return return_value;
}

Builtin CodeAssembler::builtin() { return state()->builtin_; }

#if V8_ENABLE_WEBASSEMBLY
TNode<RawPtrT> CodeAssembler::SwitchToTheCentralStack() {
  TNode<ExternalReference> do_switch = ExternalConstant(
      ExternalReference::wasm_switch_to_the_central_stack_for_js());
  TNode<RawPtrT> central_stack_sp = TNode<RawPtrT>::UncheckedCast(CallCFunction(
      do_switch, MachineType::Pointer(),
      std::make_pair(MachineType::Pointer(),
                     ExternalConstant(ExternalReference::isolate_address())),
      std::make_pair(MachineType::Pointer(), LoadFramePointer())));

  TNode<RawPtrT> old_sp = LoadStackPointer();
  SetStackPointer(central_stack_sp);
  return old_sp;
}

void CodeAssembler::SwitchFromTheCentralStack(TNode<RawPtrT> old_sp) {
  TNode<ExternalReference> do_switch = ExternalConstant(
      ExternalReference::wasm_switch_from_the_central_stack_for_js());
  CodeAssemblerLabel skip(this);
  GotoIf(IntPtrEqual(old_sp, UintPtrConstant(0)), &skip);
  CallCFunction(
      do_switch, MachineType::Pointer(),
      std::make_pair(MachineType::Pointer(),
                     ExternalConstant(ExternalReference::isolate_address())));
  SetStackPointer(old_sp);
  Goto(&skip);
  Bind(&skip);
}

TNode<RawPtrT> CodeAssembler::SwitchToTheCentralStackIfNeeded() {
  TVariable<RawPtrT> old_sp(PointerConstant(nullptr), this);
  Label no_switch(this);
  Label end(this);  // -> return value of the call (kTaggedPointer)
  TNode<Uint8T> is_on_central_stack_flag = LoadUint8FromRootRegister(
      IntPtrConstant(IsolateData::is_on_central_stack_flag_offset()));
  GotoIf(is_on_central_stack_flag, &no_switch);
  old_sp = SwitchToTheCentralStack();
  Goto(&no_switch);
  Bind(&no_switch);
  return old_sp.value();
}
#endif

void CodeAssembler::TailCallRuntimeImpl(
    Runtime::FunctionId function, TNode<Int32T> arity, TNode<Object> context,
    std::initializer_list<TNode<Object>> args) {
  int result_size = Runtime::FunctionForId(function)->result_size;
#if V8_ENABLE_WEBASSEMBLY
  bool switch_to_the_central_stack =
      state_->kind_ == CodeKind::WASM_FUNCTION ||
      state_->kind_ == CodeKind::WASM_TO_JS_FUNCTION ||
      state_->kind_ == CodeKind::JS_TO_WASM_FUNCTION ||
      state_->builtin_ == Builtin::kJSToWasmWrapper ||
      state_->builtin_ == Builtin::kJSToWasmHandleReturns ||
      state_->builtin_ == Builtin::kWasmToJsWrapperCSA ||
      wasm::BuiltinLookup::IsWasmBuiltinId(state_->builtin_);
#else
  bool switch_to_the_central_stack = false;
#endif
  Builtin centry =
      Builtins::RuntimeCEntry(result_size, switch_to_the_central_stack);
  TNode<Code> centry_code =
      HeapConstantNoHole(isolate()->builtins()->code_handle(centry));

  constexpr size_t kMaxNumArgs = 6;
  DCHECK_GE(kMaxNumArgs, args.size());
  int argc = static_cast<int>(args.size());
  auto call_descriptor = Linkage::GetRuntimeCallDescriptor(
      zone(), function, argc, Operator::kNoProperties,
      CallDescriptor::kNoFlags);

  TNode<ExternalReference> ref =
      ExternalConstant(ExternalReference::Create(function));

  NodeArray<kMaxNumArgs + 4> inputs;
  inputs.Add(centry_code);
  for (const auto& arg : args) inputs.Add(arg);
  inputs.Add(ref);
  inputs.Add(arity);
  inputs.Add(context);

  raw_assembler()->TailCallN(call_descriptor, inputs.size(), inputs.data());
}

Node* CodeAssembler::CallStubN(StubCallMode call_mode,
                               const CallInterfaceDescriptor& descriptor,
                               int input_count, Node* const* inputs) {
  DCHECK(call_mode == StubCallMode::kCallCodeObject ||
         call_mode == StubCallMode::kCallBuiltinPointer);

  // implicit nodes are target and optionally context.
  int implicit_nodes = descriptor.HasContextParameter() ? 2 : 1;
  DCHECK_LE(implicit_nodes, input_count);
  int argc = input_count - implicit_nodes;
  DCHECK(IsValidArgumentCountFor(descriptor, argc));
  // Extra arguments not mentioned in the descriptor are passed on the stack.
  int stack_parameter_count = argc - descriptor.GetRegisterParameterCount();
  DCHECK_LE(descriptor.GetStackParameterCount(), stack_parameter_count);

  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), descriptor, stack_parameter_count, CallDescriptor::kNoFlags,
      Operator::kNoProperties, call_mode);

  CallPrologue();
  Node* return_value =
      raw_assembler()->CallN(call_descriptor, input_count, inputs);
  HandleException(return_value);
  CallEpilogue();
  return return_value;
}

void CodeAssembler::TailCallStubImpl(const CallInterfaceDescriptor& descriptor,
                                     TNode<Code> target, TNode<Object> context,
                                     std::initializer_list<Node*> args) {
  constexpr size_t kMaxNumArgs = 11;
  DCHECK_GE(kMaxNumArgs, args.size());
  DCHECK(IsValidArgumentCountFor(descriptor, args.size()));
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), descriptor, descriptor.GetStackParameterCount(),
      CallDescriptor::kNoFlags, Operator::kNoProperties);

  NodeArray<kMaxNumArgs + 2> inputs;
  inputs.Add(target);
  for (auto arg : args) inputs.Add(arg);
  if (descriptor.HasContextParameter()) {
    inputs.Add(context);
  }

  raw_assembler()->TailCallN(call_descriptor, inputs.size(), inputs.data());
}

Node* CodeAssembler::CallStubRImpl(StubCallMode call_mode,
                                   const CallInterfaceDescriptor& descriptor,
                                   TNode<Object> target, TNode<Object> context,
                                   std::initializer_list<Node*> args) {
  DCHECK(call_mode == StubCallMode::kCallCodeObject ||
         call_mode == StubCallMode::kCallBuiltinPointer);
  DCHECK(IsValidArgumentCountFor(descriptor, args.size()));

  constexpr size_t kMaxNumArgs = 10;
  DCHECK_GE(kMaxNumArgs, args.size());

  NodeArray<kMaxNumArgs + 2> inputs;
  inputs.Add(target);
  for (auto arg : args) inputs.Add(arg);
  if (descriptor.HasContextParameter()) {
    inputs.Add(context);
  }

  return CallStubN(call_mode, descriptor, inputs.size(), inputs.data());
}

Node* CodeAssembler::CallJSStubImpl(
    const CallInterfaceDescriptor& descriptor, TNode<Object> target,
    TNode<Object> context, TNode<Object> function,
    std::optional<TNode<Object>> new_target, TNode<Int32T> arity,
    std::optional<TNode<JSDispatchHandleT>> dispatch_handle,
    std::initializer_list<Node*> args) {
  constexpr size_t kMaxNumArgs = 10;
  DCHECK_GE(kMaxNumArgs, args.size());
  NodeArray<kMaxNumArgs + 6> inputs;

  inputs.Add(target);
  inputs.Add(function);
  if (new_target) {
    inputs.Add(*new_target);
  }
  inputs.Add(arity);
#ifdef V8_ENABLE_LEAPTIERING
  if (dispatch_handle) {
    inputs.Add(*dispatch_handle);
  }
#endif
  for (auto arg : args) inputs.Add(arg);
  // Context argument is implicit so isn't counted.
  DCHECK(IsValidArgumentCountFor(descriptor, inputs.size()));
  if (descriptor.HasContextParameter()) {
    inputs.Add(context);
  }

  return CallStubN(StubCallMode::kCallCodeObject, descriptor, inputs.size(),
                   inputs.data());
}

void CodeAssembler::TailCallStubThenBytecodeDispatchImpl(
    const CallInterfaceDescriptor& descriptor, Node* target, Node* context,
    std::initializer_list<Node*> args) {
  constexpr size_t kMaxNumArgs = 6;
  DCHECK_GE(kMaxNumArgs, args.size());
  DCHECK(IsValidArgumentCountFor(descriptor, args.size()));

  int argc = static_cast<int>(args.size());
  // Extra arguments not mentioned in the descriptor are passed on the stack.
  int stack_parameter_count = argc - descriptor.GetRegisterParameterCount();
  DCHECK_LE(descriptor.GetStackParameterCount(), stack_parameter_count);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), descriptor, stack_parameter_count, CallDescriptor::kNoFlags,
      Operator::kNoProperties);

  NodeArray<kMaxNumArgs + 2> inputs;
  inputs.Add(target);
  for (auto arg : args) inputs.Add(arg);
  inputs.Add(context);

  raw_assembler()->TailCallN(call_descriptor, inputs.size(), inputs.data());
}

template <class... TArgs>
void CodeAssembler::TailCallBytecodeDispatch(
    const CallInterfaceDescriptor& descriptor, TNode<RawPtrT> target,
    TArgs... args) {
  DCHECK_EQ(descriptor.GetParameterCount(), sizeof...(args));
  auto call_descriptor = Linkage::GetBytecodeDispatchCallDescriptor(
      zone(), descriptor, descriptor.GetStackParameterCount());

  Node* nodes[] = {target, args...};
  CHECK_EQ(descriptor.GetParameterCount() + 1, arraysize(nodes));
  raw_assembler()->TailCallN(call_descriptor, arraysize(nodes), nodes);
}

// Instantiate TailCallBytecodeDispatch() for argument counts used by
// CSA-generated code
template V8_EXPORT_PRIVATE void CodeAssembler::TailCallBytecodeDispatch(
    const CallInterfaceDescriptor& descriptor, TNode<RawPtrT> target,
    TNode<Object>, TNode<IntPtrT>, TNode<BytecodeArray>,
    TNode<ExternalReference>);

void CodeAssembler::TailCallJSCode(TNode<Code> code, TNode<Context> context,
                                   TNode<JSFunction> function,
                                   TNode<Object> new_target,
                                   TNode<Int32T> arg_count,
                                   TNode<JSDispatchHandleT> dispatch_handle) {
  JSTrampolineDescriptor descriptor;
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), descriptor, descriptor.GetStackParameterCount(),
      CallDescriptor::kFixedTargetRegister, Operator::kNoProperties,
      StubCallMode::kCallCodeObject);

#ifdef V8_ENABLE_LEAPTIERING
  Node* nodes[] = {code,      function,        new_target,
                   arg_count, dispatch_handle, context};
#else
  Node* nodes[] = {code, function, new_target, arg_count, context};
#endif
  // + 2 for code and context.
  CHECK_EQ(descriptor.GetParameterCount() + 2, arraysize(nodes));
  raw_assembler()->TailCallN(call_descriptor, arraysize(nodes), nodes);
}

Node* CodeAssembler::CallCFunctionN(Signature<MachineType>* signature,
                                    int input_count, Node* const* inputs) {
  auto call_descriptor = Linkage::GetSimplifiedCDescriptor(zone(), signature);
  return raw_assembler()->CallN(call_descriptor, input_count, inputs);
}

Node* CodeAssembler::CallCFunction(
    Node* function, std::optional<MachineType> return_type,
    std::initializer_list<CodeAssembler::CFunctionArg> args) {
  return raw_assembler()->CallCFunction(function, return_type, args);
}

Node* CodeAssembler::CallCFunctionWithoutFunctionDescriptor(
    Node* function, MachineType return_type,
    std::initializer_list<CodeAssembler::CFunctionArg> args) {
  return raw_assembler()->CallCFunctionWithoutFunctionDescriptor(
      function, return_type, args);
}

Node* CodeAssembler::CallCFunctionWithCallerSavedRegisters(
    Node* function, MachineType return_type, SaveFPRegsMode mode,
    std::initializer_list<CodeAssembler::CFunctionArg> args) {
  DCHECK(return_type.LessThanOrEqualPointerSize());
  return raw_assembler()->CallCFunctionWithCallerSavedRegisters(
      function, return_type, mode, args);
}

void CodeAssembler::Goto(Label* label) {
  label->MergeVariables();
  raw_assembler()->Goto(label->label_);
}

void CodeAssembler::GotoIf(TNode<IntegralT> condition, Label* true_label) {
  Label false_label(this);
  Branch(condition, true_label, &false_label);
  Bind(&false_label);
}

void CodeAssembler::GotoIfNot(TNode<IntegralT> condition, Label* false_label) {
  Label true_label(this);
  Branch(condition, &true_label, false_label);
  Bind(&true_label);
}

void CodeAssembler::Branch(TNode<IntegralT> condition, Label* true_label,
                           Label* false_label) {
  int32_t constant;
  if (TryToInt32Constant(condition, &constant)) {
    if ((true_label->is_used() || true_label->is_bound()) &&
        (false_label->is_used() || false_label->is_bound())) {
      return Goto(constant ? true_label : false_label);
    }
  }
  true_label->MergeVariables();
  false_label->MergeVariables();
  return raw_assembler()->Branch(condition, true_label->label_,
                                 false_label->label_);
}

void CodeAssembler::Branch(TNode<BoolT> condition,
                           const std::function<void()>& true_body,
                           const std::function<void()>& false_body) {
  int32_t constant;
  if (TryToInt32Constant(condition, &constant)) {
    return constant ? true_body() : false_body();
  }

  Label vtrue(this), vfalse(this);
  Branch(condition, &vtrue, &vfalse);

  Bind(&vtrue);
  true_body();

  Bind(&vfalse);
  false_body();
}

void CodeAssembler::Branch(TNode<BoolT> condition, Label* true_label,
                           const std::function<void()>& false_body) {
  int32_t constant;
  if (TryToInt32Constant(condition, &constant)) {
    return constant ? Goto(true_label) : false_body();
  }

  Label vfalse(this);
  Branch(condition, true_label, &vfalse);
  Bind(&vfalse);
  false_body();
}

void CodeAssembler::Branch(TNode<BoolT> condition,
                           const std::function<void()>& true_body,
                           Label* false_label) {
  int32_t constant;
  if (TryToInt32Constant(condition, &constant)) {
    return constant ? true_body() : Goto(false_label);
  }

  Label vtrue(this);
  Branch(condition, &vtrue, false_label);
  Bind(&vtrue);
  true_body();
}

void CodeAssembler::Switch(Node* index, Label* default_label,
                           const int32_t* case_values, Label** case_labels,
                           size_t case_count) {
  RawMachineLabel** labels =
      zone()->AllocateArray<RawMachineLabel*>(case_count);
  for (size_t i = 0; i < case_count; ++i) {
    labels[i] = case_labels[i]->label_;
    case_labels[i]->MergeVariables();
  }
  default_label->MergeVariables();
  return raw_assembler()->Switch(index, default_label->label_, case_values,
                                 labels, case_count);
}

bool CodeAssembler::UnalignedLoadSupported(MachineRepresentation rep) const {
  return raw_assembler()->machine()->UnalignedLoadSupported(rep);
}
bool CodeAssembler::UnalignedStoreSupported(MachineRepresentation rep) const {
  return raw_assembler()->machine()->UnalignedStoreSupported(rep);
}

// RawMachineAssembler delegate helpers:
Isolate* CodeAssembler::isolate() const { return raw_assembler()->isolate(); }

Factory* CodeAssembler::factory() const { return isolate()->factory(); }

Zone* CodeAssembler::zone() const { return raw_assembler()->zone(); }

bool CodeAssembler::IsExceptionHandlerActive() const {
  return !state_->exception_handler_labels_.empty();
}

RawMachineAssembler* CodeAssembler::raw_assembler() const {
  return state_->raw_assembler_.get();
}

JSGraph* CodeAssembler::jsgraph() const { return state_->jsgraph_; }

// The core implementation of Variable is stored through an indirection so
// that it can outlive the often block-scoped Variable declarations. This is
// needed to ensure that variable binding and merging through phis can
// properly be verified.
class CodeAssemblerVariable::Impl : public ZoneObject {
 public:
  explicit Impl(MachineRepresentation rep, CodeAssemblerState::VariableId id)
      :
#if DEBUG
        debug_info_(AssemblerDebugInfo(nullptr, nullptr, -1)),
#endif
        value_(nullptr),
        rep_(rep),
        var_id_(id) {
  }

#if DEBUG
  AssemblerDebugInfo debug_info() const { return debug_info_; }
  void set_debug_info(AssemblerDebugInfo debug_info) {
    debug_info_ = debug_info;
  }

  AssemblerDebugInfo debug_info_;
#endif  // DEBUG
  bool operator<(const CodeAssemblerVariable::Impl& other) const {
    return var_id_ < other.var_id_;
  }
  Node* value_;
  MachineRepresentation rep_;
  CodeAssemblerState::VariableId var_id_;
};

bool CodeAssemblerVariable::ImplComparator::operator()(
    const CodeAssemblerVariable::Impl* a,
    const CodeAssemblerVariable::Impl* b) const {
  return *a < *b;
}

CodeAssemblerVariable::CodeAssemblerVariable(CodeAssembler* assembler,
                                             MachineRepresentation rep)
    : impl_(assembler->zone()->New<Impl>(rep,
                                         assembler->state()->NextVariableId())),
      state_(assembler->state()) {
  state_->variables_.insert(impl_);
}

CodeAssemblerVariable::CodeAssemblerVariable(CodeAssembler* assembler,
                                             MachineRepresentation rep,
                                             Node* initial_value)
    : CodeAssemblerVariable(assembler, rep) {
  Bind(initial_value);
}

#if DEBUG
CodeAssemblerVariable::CodeAssemblerVariable(CodeAssembler* assembler,
                                             AssemblerDebugInfo debug_info,
                                             MachineRepresentation rep)
    : impl_(assembler->zone()->New<Impl>(rep,
                                         assembler->state()->NextVariableId())),
      state_(assembler->state()) {
  impl_->set_debug_info(debug_info);
  state_->variables_.insert(impl_);
}

CodeAssemblerVariable::CodeAssemblerVariable(CodeAssembler* assembler,
                                             AssemblerDebugInfo debug_info,
                                             MachineRepresentation rep,
                                             Node* initial_value)
    : CodeAssemblerVariable(assembler, debug_info, rep) {
  impl_->set_debug_info(debug_info);
  Bind(initial_value);
}
#endif  // DEBUG

CodeAssemblerVariable::~CodeAssemblerVariable() {
  state_->variables_.erase(impl_);
}

void CodeAssemblerVariable::Bind(Node* value) { impl_->value_ = value; }

Node* CodeAssemblerVariable::value() const {
#if DEBUG
  if (!IsBound()) {
    std::stringstream str;
    str << "#Use of unbound variable:"
        << "#\n    Variable:      " << *this << "#\n    Current Block: ";
    state_->PrintCurrentBlock(str);
    FATAL("%s", str.str().c_str());
  }
  if (!state_->InsideBlock()) {
    std::stringstream str;
    str << "#Accessing variable value outside a block:"
        << "#\n    Variable:      " << *this;
    FATAL("%s", str.str().c_str());
  }
#endif  // DEBUG
  return impl_->value_;
}

MachineRepresentation CodeAssemblerVariable::rep() const { return impl_->rep_; }

bool CodeAssemblerVariable::IsBound() const { return impl_->value_ != nullptr; }

std::ostream& operator<<(std::ostream& os,
                         const CodeAssemblerVariable::Impl& impl) {
#if DEBUG
  AssemblerDebugInfo info = impl.debug_info();
  if (info.name) os << "V" << info;
#endif  // DEBUG
  return os;
}

std::ostream& operator<<(std::ostream& os,
                         const CodeAssemblerVariable& variable) {
  os << *variable.impl_;
  return os;
}

CodeAssemblerLabel::CodeAssemblerLabel(CodeAssembler* assembler,
                                       size_t vars_count,
                                       CodeAssemblerVariable* const* vars,
                                       CodeAssemblerLabel::Type type)
    : bound_(false),
      merge_count_(0),
      state_(assembler->state()),
      label_(nullptr) {
  label_ = assembler->zone()->New<RawMachineLabel>(
      type == kDeferred ? RawMachineLabel::kDeferred
                        : RawMachineLabel::kNonDeferred);
  for (size_t i = 0; i < vars_count; ++i) {
    variable_phis_[vars[i]->impl_] = nullptr;
  }
}

CodeAssemblerLabel::~CodeAssemblerLabel() { label_->~R
"""


```