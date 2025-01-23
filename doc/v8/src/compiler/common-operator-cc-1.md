Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/common-operator.cc`. This is the second part of a three-part series.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Purpose:** The code defines a `CommonOperatorBuilder` class. The name strongly suggests it's responsible for creating and managing common operators within the V8 compiler's intermediate representation (IR).

2. **Examine Key Structures:**
    * **`CommonOperatorGlobalCache`:**  This is a singleton that holds pre-created, commonly used `Operator` objects. This is an optimization to avoid redundant allocations.
    * **`CommonOperatorBuilder`:** This class uses the cache to provide convenient methods for obtaining `Operator` instances. If an operator isn't cached, it dynamically allocates a new one using the provided `Zone` allocator.
    * **`Operator`:** This class (presumably defined elsewhere) represents an operation in the IR graph. The code snippet shows various constructors and methods for creating different kinds of operators with specific properties (like input/output counts, flags, and parameters).

3. **Analyze the Macros:**
    * `CACHED_STATE_VALUES_LIST`, `CACHED_END_LIST`, etc.: These macros are used to generate code that defines cached operator instances for different input counts. This avoids writing repetitive code.
    * `CACHED`: This macro defines a member function in `CommonOperatorBuilder` that returns a cached operator.
    * `COMMON_CACHED_OP_LIST`: This macro likely iterates through a predefined list of common operators and invokes the `CACHED` macro for each.

4. **Categorize the Operator Creation Methods:**  The `CommonOperatorBuilder` class has numerous methods like `End`, `Return`, `Branch`, `Deoptimize`, `Assert`, `Switch`, `Loop`, `Phi`, `Constant`, `Call`, etc. These correspond to various fundamental operations in the compiler's IR. Each method handles the creation of a specific type of operator, potentially using cached instances or allocating new ones.

5. **Check for `.tq` Extension:** The prompt specifically asks about `.tq`. Since the code is `.cc`, it's C++, not Torque.

6. **Relate to JavaScript (if applicable):** Many of these operators have direct or indirect relationships to JavaScript concepts. For example:
    * `Return`: Corresponds to the `return` statement.
    * `Branch`:  Used for `if`/`else` statements and other conditional logic.
    * `Deoptimize`: Happens when the V8 runtime decides that optimized code is no longer valid and needs to fall back to slower, interpreted code.
    * `Call`:  Represents function calls.
    * `Parameter`:  Represents function arguments.
    * `Constant` operators (e.g., `Int32Constant`, `HeapConstant`): Represent literal values.

7. **Identify Potential Programming Errors:** The code itself is about *creating* the IR, not executing JavaScript. Therefore, typical user programming errors aren't directly within this code's scope. However, *misusing* the `CommonOperatorBuilder` could lead to errors in the compiler's logic.

8. **Infer Input/Output for Logic:** Since this code is about *building* IR, the "input" is the information needed to create an operator (e.g., input counts, types, parameters), and the "output" is the `Operator*` itself.

9. **Synthesize the Summary:** Combine the identified functionalities into a concise summary. Emphasize the role of the `CommonOperatorBuilder` in creating and managing IR operators, the use of caching for optimization, and the connection to core compiler operations.

10. **Address the "Part 2" aspect:** Acknowledge that this is part of a larger system and that the functionality described here fits within the context of IR construction.

By following these steps, we can systematically analyze the code and provide a comprehensive answer to the user's request.
`v8/src/compiler/common-operator.cc` 的功能是定义并实现了一个用于创建和管理**通用操作符 (Common Operators)** 的构建器类 `CommonOperatorBuilder`。这些通用操作符是 V8 编译器中间表示 (IR) 中的基本构建块，代表了程序执行中的各种操作。

**主要功能归纳:**

1. **提供创建通用操作符的便捷接口:** `CommonOperatorBuilder` 类提供了一系列方法，用于创建不同类型的通用操作符，例如：
    * 控制流操作符 (`Start`, `End`, `Loop`, `Merge`, `Branch`, `Switch`, `IfValue`, `IfDefault`)
    * 数据操作符 (`Parameter`, `OsrValue`, 常量操作符如 `Int32Constant`, `Float64Constant`, `HeapConstant`)
    * 特殊操作符 (`Deoptimize`, `Assert`, `Call`, `Return`, `Phi`, `EffectPhi`, `StateValues`)
    * WebAssembly 相关操作符 (`TrapIf`, `TrapUnless`)
    * 调试和元数据操作符 (`FrameState`, `ObjectId`)

2. **利用缓存机制优化操作符创建:**  为了提高性能，`CommonOperatorBuilder` 内部使用了一个全局缓存 `CommonOperatorGlobalCache` 来存储常用的操作符实例。当需要创建这些常用操作符时，直接从缓存中获取，避免了重复分配内存和初始化操作。这通过宏定义（例如 `CACHED`, `CACHED_END_LIST` 等）来实现。

3. **封装操作符的创建细节:** `CommonOperatorBuilder` 隐藏了 `Operator` 类的直接构造过程，提供了一层抽象，使得创建操作符的代码更加简洁和易于维护。它负责设置操作符的 `IrOpcode`、属性 (properties)、名称 (name) 以及输入/输出的数量。

4. **支持带参数的操作符:**  许多操作符需要额外的参数来指定其行为，例如 `Int32Constant` 需要一个整数值，`Branch` 需要一个分支提示 (hint)。`CommonOperatorBuilder` 的方法能够接收这些参数，并将它们存储在创建的 `Operator` 对象中。

5. **处理不同输入数量的操作符:** 一些操作符（如 `End`, `Return`, `Merge`, `Phi`, `EffectPhi`) 可以接受不同数量的输入。`CommonOperatorBuilder` 通过 `switch` 语句和缓存机制来处理这些情况，为每种输入数量提供预先创建的或动态创建的操作符。

**关于代码特性的解释:**

* **`.tq` 扩展名:**  `v8/src/compiler/common-operator.cc` 以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 Torque 源代码。Torque 源代码通常以 `.tq` 结尾。

* **与 JavaScript 的关系:** `v8/src/compiler/common-operator.cc` 中的操作符与 JavaScript 的功能有着密切的关系。编译器在将 JavaScript 代码转换为机器码的过程中，会将 JavaScript 的各种语法结构和语义操作表示为这些 IR 操作符。

**JavaScript 示例：**

例如，JavaScript 中的一个简单的加法运算 `a + b`，在编译过程中可能会被表示为以下 IR 操作符（简化）：

```
// 假设 a 和 b 已经是某种 IR 节点
let add_op = builder.Add(a, b); // 假设 builder 有一个 Add 方法来创建加法操作符
```

JavaScript 中的 `if` 语句会被表示为控制流操作符：

```javascript
if (condition) {
  // ...
} else {
  // ...
}
```

对应的 IR 可能包含 `Branch` 操作符，用于根据 `condition` 的结果跳转到不同的代码块。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `CommonOperatorBuilder` 的 `Int32Constant` 方法：

* **假设输入:**  `value = 10`
* **输出:**  返回一个指向 `Operator` 对象的指针，该对象表示一个 32 位整数常量，其值为 10。这个 `Operator` 对象的 `opcode` 将是 `IrOpcode::kInt32Constant`，并且它会携带参数 `10`。

假设我们调用 `CommonOperatorBuilder` 的 `Branch` 方法：

* **假设输入:** `hint = BranchHint::kTrue`, `semantics = BranchSemantics::kNormal`
* **输出:** 返回一个指向 `Operator` 对象的指针，该对象表示一个分支操作。这个 `Operator` 对象的 `opcode` 将是 `IrOpcode::kBranch`，并且其参数会编码分支提示和语义。由于 `Branch` 操作符存在缓存，如果具有相同 hint 和 semantics 的操作符已经存在，则会返回缓存的版本。

**用户常见的编程错误（不直接相关，但可以间接影响编译器行为）:**

由于此代码是编译器的一部分，用户编写的 JavaScript 代码中的错误可能会导致生成包含特定操作符的 IR。例如：

* **类型错误:** 如果 JavaScript 代码尝试对不兼容的类型进行操作（例如，将字符串与数字相加），编译器可能会生成一些类型转换或错误处理相关的操作符，例如 `Deoptimize`，当运行时发现类型不匹配时，会触发去优化。
* **未定义的变量:** 访问未定义的变量可能会导致生成表示“读取未定义值”的操作符。

**总结 `v8/src/compiler/common-operator.cc` 的功能 (针对第 2 部分):**

作为系列的一部分，这部分代码主要关注 `CommonOperatorBuilder` 类的实现细节，展示了它是如何利用缓存机制和构造函数来创建各种通用操作符的实例。它定义了创建不同类型操作符的具体方法，并处理了具有不同输入数量的操作符的创建逻辑。这部分代码的核心目标是提供一个高效且结构化的方式来生成编译器 IR 中使用的基本操作单元。

### 提示词
```
这是目录为v8/src/compiler/common-operator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/common-operator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
SparseInputMask::Dense()) {}  // parameter
  };
#define CACHED_STATE_VALUES(input_count) \
  StateValuesOperator<input_count> kStateValues##input_count##Operator;
  CACHED_STATE_VALUES_LIST(CACHED_STATE_VALUES)
#undef CACHED_STATE_VALUES
};

namespace {
DEFINE_LAZY_LEAKY_OBJECT_GETTER(CommonOperatorGlobalCache,
                                GetCommonOperatorGlobalCache)
}  // namespace

CommonOperatorBuilder::CommonOperatorBuilder(Zone* zone)
    : cache_(*GetCommonOperatorGlobalCache()), zone_(zone) {}

#define CACHED(Name, properties, value_input_count, effect_input_count,      \
               control_input_count, value_output_count, effect_output_count, \
               control_output_count)                                         \
  const Operator* CommonOperatorBuilder::Name() {                            \
    return &cache_.k##Name##Operator;                                        \
  }
COMMON_CACHED_OP_LIST(CACHED)
#undef CACHED


const Operator* CommonOperatorBuilder::End(size_t control_input_count) {
  switch (control_input_count) {
#define CACHED_END(input_count) \
  case input_count:             \
    return &cache_.kEnd##input_count##Operator;
    CACHED_END_LIST(CACHED_END)
#undef CACHED_END
    default:
      break;
  }
  // Uncached.
  return zone()->New<Operator>(             //--
      IrOpcode::kEnd, Operator::kKontrol,   // opcode
      "End",                                // name
      0, 0, control_input_count, 0, 0, 0);  // counts
}

const Operator* CommonOperatorBuilder::Return(int value_input_count) {
  switch (value_input_count) {
#define CACHED_RETURN(input_count) \
  case input_count:                \
    return &cache_.kReturn##input_count##Operator;
    CACHED_RETURN_LIST(CACHED_RETURN)
#undef CACHED_RETURN
    default:
      break;
  }
  // Uncached.
  return zone()->New<Operator>(               //--
      IrOpcode::kReturn, Operator::kNoThrow,  // opcode
      "Return",                               // name
      value_input_count + 1, 1, 1, 0, 0, 1);  // counts
}

const Operator* CommonOperatorBuilder::StaticAssert(const char* source) {
  return zone()->New<Operator1<const char*>>(
      IrOpcode::kStaticAssert, Operator::kFoldable, "StaticAssert", 1, 1, 0, 0,
      1, 0, source);
}

const Operator* CommonOperatorBuilder::SLVerifierHint(
    const Operator* semantics,
    const std::optional<Type>& override_output_type) {
  return zone()->New<Operator1<SLVerifierHintParameters>>(
      IrOpcode::kSLVerifierHint, Operator::kNoProperties, "SLVerifierHint", 1,
      0, 0, 1, 0, 0, SLVerifierHintParameters(semantics, override_output_type));
}

const Operator* CommonOperatorBuilder::Branch(BranchHint hint,
                                              BranchSemantics semantics) {
#define CACHED_BRANCH(Semantics, Hint)                 \
  if (semantics == BranchSemantics::k##Semantics &&    \
      hint == BranchHint::k##Hint) {                   \
    return &cache_.kBranch##Semantics##Hint##Operator; \
  }
  CACHED_BRANCH_LIST(CACHED_BRANCH)
#undef CACHED_BRANCH
  UNREACHABLE();
}

const Operator* CommonOperatorBuilder::Deoptimize(
    DeoptimizeReason reason, FeedbackSource const& feedback) {
#define CACHED_DEOPTIMIZE(Reason)                                     \
  if (reason == DeoptimizeReason::k##Reason && !feedback.IsValid()) { \
    return &cache_.kDeoptimize##Reason##Operator;                     \
  }
  CACHED_DEOPTIMIZE_LIST(CACHED_DEOPTIMIZE)
#undef CACHED_DEOPTIMIZE
  // Uncached
  DeoptimizeParameters parameter(reason, feedback);
  return zone()->New<Operator1<DeoptimizeParameters>>(  // --
      IrOpcode::kDeoptimize,                            // opcodes
      Operator::kFoldable | Operator::kNoThrow,         // properties
      "Deoptimize",                                     // name
      1, 1, 1, 0, 0, 1,                                 // counts
      parameter);                                       // parameter
}

const Operator* CommonOperatorBuilder::DeoptimizeIf(
    DeoptimizeReason reason, FeedbackSource const& feedback) {
#define CACHED_DEOPTIMIZE_IF(Reason)                                  \
  if (reason == DeoptimizeReason::k##Reason && !feedback.IsValid()) { \
    return &cache_.kDeoptimizeIf##Reason##Operator;                   \
  }
  CACHED_DEOPTIMIZE_IF_LIST(CACHED_DEOPTIMIZE_IF)
#undef CACHED_DEOPTIMIZE_IF
  // Uncached
  DeoptimizeParameters parameter(reason, feedback);
  return zone()->New<Operator1<DeoptimizeParameters>>(  // --
      IrOpcode::kDeoptimizeIf,                          // opcode
      Operator::kFoldable | Operator::kNoThrow,         // properties
      "DeoptimizeIf",                                   // name
      2, 1, 1, 0, 1, 1,                                 // counts
      parameter);                                       // parameter
}

const Operator* CommonOperatorBuilder::DeoptimizeUnless(
    DeoptimizeReason reason, FeedbackSource const& feedback) {
#define CACHED_DEOPTIMIZE_UNLESS(Reason)                              \
  if (reason == DeoptimizeReason::k##Reason && !feedback.IsValid()) { \
    return &cache_.kDeoptimizeUnless##Reason##Operator;               \
  }
  CACHED_DEOPTIMIZE_UNLESS_LIST(CACHED_DEOPTIMIZE_UNLESS)
#undef CACHED_DEOPTIMIZE_UNLESS
  // Uncached
  DeoptimizeParameters parameter(reason, feedback);
  return zone()->New<Operator1<DeoptimizeParameters>>(  // --
      IrOpcode::kDeoptimizeUnless,                      // opcode
      Operator::kFoldable | Operator::kNoThrow,         // properties
      "DeoptimizeUnless",                               // name
      2, 1, 1, 0, 1, 1,                                 // counts
      parameter);                                       // parameter
}

const Operator* CommonOperatorBuilder::Assert(BranchSemantics semantics,
                                              const char* condition_string,
                                              const char* file, int line) {
  AssertParameters parameter(semantics, condition_string, file, line);
  return zone()->New<Operator1<AssertParameters>>(  // --
      IrOpcode::kAssert,                            // opcode
      Operator::kFoldable | Operator::kNoThrow,     // properties
      "Assert",                                     // name
      1, 1, 1, 0, 1, 0,                             // counts
      parameter);                                   // parameter
}

#if V8_ENABLE_WEBASSEMBLY
const Operator* CommonOperatorBuilder::TrapIf(TrapId trap_id,
                                              bool has_frame_state) {
  switch (trap_id) {
#define CACHED_TRAP_IF(Trap)                                        \
  case TrapId::k##Trap:                                             \
    return has_frame_state                                          \
               ? static_cast<const Operator*>(                      \
                     &cache_.kTrapIf##Trap##OperatorWithFrameState) \
               : &cache_.kTrapIf##Trap##OperatorWithoutFrameState;
    CACHED_TRAP_IF_LIST(CACHED_TRAP_IF)
#undef CACHED_TRAP_IF
    default:
      break;
  }
  // Uncached
  return zone()->New<Operator1<TrapId>>(         // --
      IrOpcode::kTrapIf,                         // opcode
      Operator::kFoldable | Operator::kNoThrow,  // properties
      "TrapIf",                                  // name
      1 + has_frame_state, 1, 1, 0, 1, 1,        // counts
      trap_id);                                  // parameter
}

const Operator* CommonOperatorBuilder::TrapUnless(TrapId trap_id,
                                                  bool has_frame_state) {
  switch (trap_id) {
#define CACHED_TRAP_UNLESS(Trap)                                        \
  case TrapId::k##Trap:                                                 \
    return has_frame_state                                              \
               ? static_cast<const Operator*>(                          \
                     &cache_.kTrapUnless##Trap##OperatorWithFrameState) \
               : &cache_.kTrapUnless##Trap##OperatorWithoutFrameState;
    CACHED_TRAP_UNLESS_LIST(CACHED_TRAP_UNLESS)
#undef CACHED_TRAP_UNLESS
    default:
      break;
  }
  // Uncached
  return zone()->New<Operator1<TrapId>>(         // --
      IrOpcode::kTrapUnless,                     // opcode
      Operator::kFoldable | Operator::kNoThrow,  // properties
      "TrapUnless",                              // name
      1 + has_frame_state, 1, 1, 0, 1, 1,        // counts
      trap_id);                                  // parameter
}

#endif  // V8_ENABLE_WEBASSEMBLY

const Operator* CommonOperatorBuilder::Switch(size_t control_output_count) {
  return zone()->New<Operator>(               // --
      IrOpcode::kSwitch, Operator::kKontrol,  // opcode
      "Switch",                               // name
      1, 0, 1, 0, 0, control_output_count);   // counts
}

const Operator* CommonOperatorBuilder::IfValue(int32_t index,
                                               int32_t comparison_order,
                                               BranchHint hint) {
  return zone()->New<Operator1<IfValueParameters>>(       // --
      IrOpcode::kIfValue, Operator::kKontrol,             // opcode
      "IfValue",                                          // name
      0, 0, 1, 0, 0, 1,                                   // counts
      IfValueParameters(index, comparison_order, hint));  // parameter
}

const Operator* CommonOperatorBuilder::IfDefault(BranchHint hint) {
  return zone()->New<Operator1<BranchHint>>(     // --
      IrOpcode::kIfDefault, Operator::kKontrol,  // opcode
      "IfDefault",                               // name
      0, 0, 1, 0, 0, 1,                          // counts
      hint);                                     // parameter
}

const Operator* CommonOperatorBuilder::Start(int value_output_count) {
  return zone()->New<Operator>(                                    // --
      IrOpcode::kStart, Operator::kFoldable | Operator::kNoThrow,  // opcode
      "Start",                                                     // name
      0, 0, 0, value_output_count, 1, 1);                          // counts
}


const Operator* CommonOperatorBuilder::Loop(int control_input_count) {
  switch (control_input_count) {
#define CACHED_LOOP(input_count) \
  case input_count:              \
    return &cache_.kLoop##input_count##Operator;
    CACHED_LOOP_LIST(CACHED_LOOP)
#undef CACHED_LOOP
    default:
      break;
  }
  // Uncached.
  return zone()->New<Operator>(             // --
      IrOpcode::kLoop, Operator::kKontrol,  // opcode
      "Loop",                               // name
      0, 0, control_input_count, 0, 0, 1);  // counts
}


const Operator* CommonOperatorBuilder::Merge(int control_input_count) {
  switch (control_input_count) {
#define CACHED_MERGE(input_count) \
  case input_count:               \
    return &cache_.kMerge##input_count##Operator;
    CACHED_MERGE_LIST(CACHED_MERGE)
#undef CACHED_MERGE
    default:
      break;
  }
  // Uncached.
  return zone()->New<Operator>(              // --
      IrOpcode::kMerge, Operator::kKontrol,  // opcode
      "Merge",                               // name
      0, 0, control_input_count, 0, 0, 1);   // counts
}

const Operator* CommonOperatorBuilder::LoopExitValue(
    MachineRepresentation rep) {
  switch (rep) {
#define CACHED_LOOP_EXIT_VALUE(kRep) \
  case MachineRepresentation::kRep:  \
    return &cache_.kLoopExitValue##kRep##Operator;

    CACHED_LOOP_EXIT_VALUE_LIST(CACHED_LOOP_EXIT_VALUE)
#undef CACHED_LOOP_EXIT_VALUE
    default:
      // Uncached.
      return zone()->New<Operator1<MachineRepresentation>>(  // --
          IrOpcode::kLoopExitValue, Operator::kPure,         // opcode
          "LoopExitValue",                                   // name
          1, 0, 1, 1, 0, 0,                                  // counts
          rep);                                              // parameter
  }
}

const Operator* CommonOperatorBuilder::Parameter(int index,
                                                 const char* debug_name) {
  if (!debug_name) {
    switch (index) {
#define CACHED_PARAMETER(index) \
  case index:                   \
    return &cache_.kParameter##index##Operator;
      CACHED_PARAMETER_LIST(CACHED_PARAMETER)
#undef CACHED_PARAMETER
      default:
        break;
    }
  }
  // Uncached.
  return zone()->New<Operator1<ParameterInfo>>(  // --
      IrOpcode::kParameter, Operator::kPure,     // opcode
      "Parameter",                               // name
      1, 0, 0, 1, 0, 0,                          // counts
      ParameterInfo(index, debug_name));         // parameter info
}

const Operator* CommonOperatorBuilder::OsrValue(int index) {
  return zone()->New<Operator1<int>>(                // --
      IrOpcode::kOsrValue, Operator::kNoProperties,  // opcode
      "OsrValue",                                    // name
      0, 0, 1, 1, 0, 0,                              // counts
      index);                                        // parameter
}

const Operator* CommonOperatorBuilder::Int32Constant(int32_t value) {
  return zone()->New<Operator1<int32_t>>(         // --
      IrOpcode::kInt32Constant, Operator::kPure,  // opcode
      "Int32Constant",                            // name
      0, 0, 0, 1, 0, 0,                           // counts
      value);                                     // parameter
}


const Operator* CommonOperatorBuilder::Int64Constant(int64_t value) {
  return zone()->New<Operator1<int64_t>>(         // --
      IrOpcode::kInt64Constant, Operator::kPure,  // opcode
      "Int64Constant",                            // name
      0, 0, 0, 1, 0, 0,                           // counts
      value);                                     // parameter
}

const Operator* CommonOperatorBuilder::TaggedIndexConstant(int32_t value) {
  return zone()->New<Operator1<int32_t>>(               // --
      IrOpcode::kTaggedIndexConstant, Operator::kPure,  // opcode
      "TaggedIndexConstant",                            // name
      0, 0, 0, 1, 0, 0,                                 // counts
      value);                                           // parameter
}

const Operator* CommonOperatorBuilder::Float32Constant(float value) {
  return zone()->New<Operator1<float>>(             // --
      IrOpcode::kFloat32Constant, Operator::kPure,  // opcode
      "Float32Constant",                            // name
      0, 0, 0, 1, 0, 0,                             // counts
      value);                                       // parameter
}


const Operator* CommonOperatorBuilder::Float64Constant(double value) {
  return zone()->New<Operator1<double>>(            // --
      IrOpcode::kFloat64Constant, Operator::kPure,  // opcode
      "Float64Constant",                            // name
      0, 0, 0, 1, 0, 0,                             // counts
      value);                                       // parameter
}


const Operator* CommonOperatorBuilder::ExternalConstant(
    const ExternalReference& value) {
  return zone()->New<Operator1<ExternalReference>>(  // --
      IrOpcode::kExternalConstant, Operator::kPure,  // opcode
      "ExternalConstant",                            // name
      0, 0, 0, 1, 0, 0,                              // counts
      value);                                        // parameter
}


const Operator* CommonOperatorBuilder::NumberConstant(double value) {
  return zone()->New<Operator1<double>>(           // --
      IrOpcode::kNumberConstant, Operator::kPure,  // opcode
      "NumberConstant",                            // name
      0, 0, 0, 1, 0, 0,                            // counts
      value);                                      // parameter
}

const Operator* CommonOperatorBuilder::PointerConstant(intptr_t value) {
  return zone()->New<Operator1<intptr_t>>(          // --
      IrOpcode::kPointerConstant, Operator::kPure,  // opcode
      "PointerConstant",                            // name
      0, 0, 0, 1, 0, 0,                             // counts
      value);                                       // parameter
}

const Operator* CommonOperatorBuilder::HeapConstant(
    const Handle<HeapObject>& value) {
  return zone()->New<Operator1<IndirectHandle<HeapObject>>>(  // --
      IrOpcode::kHeapConstant, Operator::kPure,               // opcode
      "HeapConstant",                                         // name
      0, 0, 0, 1, 0, 0,                                       // counts
      value);                                                 // parameter
}

const Operator* CommonOperatorBuilder::CompressedHeapConstant(
    const Handle<HeapObject>& value) {
  return zone()->New<Operator1<IndirectHandle<HeapObject>>>(  // --
      IrOpcode::kCompressedHeapConstant, Operator::kPure,     // opcode
      "CompressedHeapConstant",                               // name
      0, 0, 0, 1, 0, 0,                                       // counts
      value);                                                 // parameter
}

const Operator* CommonOperatorBuilder::TrustedHeapConstant(
    const Handle<HeapObject>& value) {
  return zone()->New<Operator1<IndirectHandle<HeapObject>>>(  // --
      IrOpcode::kTrustedHeapConstant, Operator::kPure,        // opcode
      "TrustedHeapConstant",                                  // name
      0, 0, 0, 1, 0, 0,                                       // counts
      value);                                                 // parameter
}

Handle<HeapObject> HeapConstantOf(const Operator* op) {
  DCHECK(IrOpcode::kHeapConstant == op->opcode() ||
         IrOpcode::kCompressedHeapConstant == op->opcode() ||
         IrOpcode::kTrustedHeapConstant == op->opcode());
  return OpParameter<IndirectHandle<HeapObject>>(op);
}

const char* StaticAssertSourceOf(const Operator* op) {
  DCHECK_EQ(IrOpcode::kStaticAssert, op->opcode());
  return OpParameter<const char*>(op);
}

const Operator* CommonOperatorBuilder::RelocatableInt32Constant(
    int32_t value, RelocInfo::Mode rmode) {
  return zone()->New<Operator1<RelocatablePtrConstantInfo>>(  // --
      IrOpcode::kRelocatableInt32Constant, Operator::kPure,   // opcode
      "RelocatableInt32Constant",                             // name
      0, 0, 0, 1, 0, 0,                                       // counts
      RelocatablePtrConstantInfo(value, rmode));              // parameter
}

const Operator* CommonOperatorBuilder::RelocatableInt64Constant(
    int64_t value, RelocInfo::Mode rmode) {
  return zone()->New<Operator1<RelocatablePtrConstantInfo>>(  // --
      IrOpcode::kRelocatableInt64Constant, Operator::kPure,   // opcode
      "RelocatableInt64Constant",                             // name
      0, 0, 0, 1, 0, 0,                                       // counts
      RelocatablePtrConstantInfo(value, rmode));              // parameter
}

const Operator* CommonOperatorBuilder::ObjectId(uint32_t object_id) {
  return zone()->New<Operator1<uint32_t>>(   // --
      IrOpcode::kObjectId, Operator::kPure,  // opcode
      "ObjectId",                            // name
      0, 0, 0, 1, 0, 0,                      // counts
      object_id);                            // parameter
}

const Operator* CommonOperatorBuilder::Select(MachineRepresentation rep,
                                              BranchHint hint) {
  return zone()->New<Operator1<SelectParameters>>(  // --
      IrOpcode::kSelect, Operator::kPure,           // opcode
      "Select",                                     // name
      3, 0, 0, 1, 0, 0,                             // counts
      SelectParameters(rep, hint));                 // parameter
}


const Operator* CommonOperatorBuilder::Phi(MachineRepresentation rep,
                                           int value_input_count) {
  DCHECK_LT(0, value_input_count);  // Disallow empty phis.
#define CACHED_PHI(kRep, kValueInputCount)                 \
  if (MachineRepresentation::kRep == rep &&                \
      kValueInputCount == value_input_count) {             \
    return &cache_.kPhi##kRep##kValueInputCount##Operator; \
  }
  CACHED_PHI_LIST(CACHED_PHI)
#undef CACHED_PHI
  // Uncached.
  return zone()->New<Operator1<MachineRepresentation>>(  // --
      IrOpcode::kPhi, Operator::kPure,                   // opcode
      "Phi",                                             // name
      value_input_count, 0, 1, 1, 0, 0,                  // counts
      rep);                                              // parameter
}

const Operator* CommonOperatorBuilder::TypeGuard(Type type) {
  return zone()->New<Operator1<Type>>(        // --
      IrOpcode::kTypeGuard, Operator::kPure,  // opcode
      "TypeGuard",                            // name
      1, 1, 1, 1, 1, 0,                       // counts
      type);                                  // parameter
}

const Operator* CommonOperatorBuilder::EnterMachineGraph(UseInfo use_info) {
  return zone()->New<Operator1<UseInfo>>(IrOpcode::kEnterMachineGraph,
                                         Operator::kPure, "EnterMachineGraph",
                                         1, 0, 0, 1, 0, 0, use_info);
}

const Operator* CommonOperatorBuilder::ExitMachineGraph(
    MachineRepresentation output_representation, Type output_type) {
  return zone()->New<Operator1<ExitMachineGraphParameters>>(
      IrOpcode::kExitMachineGraph, Operator::kPure, "ExitMachineGraph", 1, 0, 0,
      1, 0, 0, ExitMachineGraphParameters{output_representation, output_type});
}

const Operator* CommonOperatorBuilder::EffectPhi(int effect_input_count) {
  DCHECK_LT(0, effect_input_count);  // Disallow empty effect phis.
  switch (effect_input_count) {
#define CACHED_EFFECT_PHI(input_count) \
  case input_count:                    \
    return &cache_.kEffectPhi##input_count##Operator;
    CACHED_EFFECT_PHI_LIST(CACHED_EFFECT_PHI)
#undef CACHED_EFFECT_PHI
    default:
      break;
  }
  // Uncached.
  return zone()->New<Operator>(                  // --
      IrOpcode::kEffectPhi, Operator::kKontrol,  // opcode
      "EffectPhi",                               // name
      0, effect_input_count, 1, 0, 1, 0);        // counts
}

const Operator* CommonOperatorBuilder::InductionVariablePhi(int input_count) {
  DCHECK_LE(4, input_count);  // There must be always the entry, backedge,
                              // increment and at least one bound.
  switch (input_count) {
#define CACHED_INDUCTION_VARIABLE_PHI(input_count) \
  case input_count:                                \
    return &cache_.kInductionVariablePhi##input_count##Operator;
    CACHED_INDUCTION_VARIABLE_PHI_LIST(CACHED_INDUCTION_VARIABLE_PHI)
#undef CACHED_INDUCTION_VARIABLE_PHI
    default:
      break;
  }
  // Uncached.
  return zone()->New<Operator>(                          // --
      IrOpcode::kInductionVariablePhi, Operator::kPure,  // opcode
      "InductionVariablePhi",                            // name
      input_count, 0, 1, 1, 0, 0);                       // counts
}

const Operator* CommonOperatorBuilder::BeginRegion(
    RegionObservability region_observability) {
  switch (region_observability) {
    case RegionObservability::kObservable:
      return &cache_.kBeginRegionObservableOperator;
    case RegionObservability::kNotObservable:
      return &cache_.kBeginRegionNotObservableOperator;
  }
  UNREACHABLE();
}

const Operator* CommonOperatorBuilder::StateValues(int arguments,
                                                   SparseInputMask bitmask) {
  if (bitmask.IsDense()) {
    switch (arguments) {
#define CACHED_STATE_VALUES(arguments) \
  case arguments:                      \
    return &cache_.kStateValues##arguments##Operator;
      CACHED_STATE_VALUES_LIST(CACHED_STATE_VALUES)
#undef CACHED_STATE_VALUES
      default:
        break;
    }
  }

#if DEBUG
  DCHECK(bitmask.IsDense() || bitmask.CountReal() == arguments);
#endif

  // Uncached.
  return zone()->New<Operator1<SparseInputMask>>(  // --
      IrOpcode::kStateValues, Operator::kPure,     // opcode
      "StateValues",                               // name
      arguments, 0, 0, 1, 0, 0,                    // counts
      bitmask);                                    // parameter
}

const Operator* CommonOperatorBuilder::TypedStateValues(
    const ZoneVector<MachineType>* types, SparseInputMask bitmask) {
#if DEBUG
  DCHECK(bitmask.IsDense() ||
         bitmask.CountReal() == static_cast<int>(types->size()));
#endif

  return zone()->New<Operator1<TypedStateValueInfo>>(  // --
      IrOpcode::kTypedStateValues, Operator::kPure,    // opcode
      "TypedStateValues",                              // name
      static_cast<int>(types->size()), 0, 0, 1, 0, 0,  // counts
      TypedStateValueInfo(types, bitmask));            // parameters
}

const Operator* CommonOperatorBuilder::ArgumentsElementsState(
    ArgumentsStateType type) {
  return zone()->New<Operator1<ArgumentsStateType>>(       // --
      IrOpcode::kArgumentsElementsState, Operator::kPure,  // opcode
      "ArgumentsElementsState",                            // name
      0, 0, 0, 1, 0, 0,                                    // counts
      type);                                               // parameter
}

const Operator* CommonOperatorBuilder::ArgumentsLengthState() {
  return zone()->New<Operator>(                          // --
      IrOpcode::kArgumentsLengthState, Operator::kPure,  // opcode
      "ArgumentsLengthState",                            // name
      0, 0, 0, 1, 0, 0);                                 // counts
}

ArgumentsStateType ArgumentsStateTypeOf(Operator const* op) {
  DCHECK(op->opcode() == IrOpcode::kArgumentsElementsState);
  return OpParameter<ArgumentsStateType>(op);
}

const Operator* CommonOperatorBuilder::ObjectState(uint32_t object_id,
                                                   int pointer_slots) {
  return zone()->New<Operator1<ObjectStateInfo>>(  // --
      IrOpcode::kObjectState, Operator::kPure,     // opcode
      "ObjectState",                               // name
      pointer_slots, 0, 0, 1, 0, 0,                // counts
      ObjectStateInfo{object_id, pointer_slots});  // parameter
}

const Operator* CommonOperatorBuilder::TypedObjectState(
    uint32_t object_id, const ZoneVector<MachineType>* types) {
  return zone()->New<Operator1<TypedObjectStateInfo>>(  // --
      IrOpcode::kTypedObjectState, Operator::kPure,     // opcode
      "TypedObjectState",                               // name
      static_cast<int>(types->size()), 0, 0, 1, 0, 0,   // counts
      TypedObjectStateInfo(object_id, types));          // parameter
}

uint32_t ObjectIdOf(Operator const* op) {
  switch (op->opcode()) {
    case IrOpcode::kObjectState:
      return OpParameter<ObjectStateInfo>(op).object_id();
    case IrOpcode::kTypedObjectState:
      return OpParameter<TypedObjectStateInfo>(op).object_id();
    case IrOpcode::kObjectId:
      return OpParameter<uint32_t>(op);
    default:
      UNREACHABLE();
  }
}

MachineRepresentation DeadValueRepresentationOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kDeadValue, op->opcode());
  return OpParameter<MachineRepresentation>(op);
}

const Operator* CommonOperatorBuilder::FrameState(
    BytecodeOffset bailout_id, OutputFrameStateCombine state_combine,
    const FrameStateFunctionInfo* function_info) {
  FrameStateInfo state_info(bailout_id, state_combine, function_info);
  return zone()->New<Operator1<FrameStateInfo>>(  // --
      IrOpcode::kFrameState, Operator::kPure,     // opcode
      "FrameState",                               // name
      5, 0, 0, 1, 0, 0,                           // counts
      state_info);                                // parameter
}

const Operator* CommonOperatorBuilder::Call(
    const CallDescriptor* call_descriptor) {
  class CallOperator final : public Operator1<const CallDescriptor*> {
   public:
    explicit CallOperator(const CallDescriptor* call_descriptor)
        : Operator1<const CallDescriptor*>(
              IrOpcode::kCall, call_descriptor->properties(), "Call",
              call_descriptor->InputCount() +
                  call_descriptor->FrameStateCount(),
              Operator::ZeroIfPure(call_descriptor->properties()),
              Operator::ZeroIfEliminatable(call_descriptor->properties()),
              call_descriptor->ReturnCount(),
              Operator::ZeroIfPure(call_descriptor->properties()),
              Operator::ZeroIfNoThrow(call_descriptor->properties()),
              call_descriptor) {}

    void PrintParameter(std::ostream& os,
                        PrintVerbosity verbose) const override {
      os << "[" << *parameter() << "]";
    }
  };
  return zone()->New<CallOperator>(call_descriptor);
}

const Operator* CommonOperatorBuilder::TailCall(
    const CallDescriptor* call_descriptor) {
  class TailCallOperator final : public Operator1<const CallDescriptor*> {
   public:
    explicit TailCallOperator(const CallDescriptor* call_descriptor)
        : Operator1<const CallDescriptor*>(
              IrOpcode::kTailCall,
              call_descriptor->properties() | Operator::kNoThrow, "TailCall",
              call_descriptor->InputCount() +
                  call_descriptor->FrameStateCount(),
              1, 1, 0, 0, 1, call_descriptor) {}

    void PrintParameter(std::ostream& os,
                        PrintVerbosity verbose) const override {
      os << "[" << *parameter() << "]";
    }
  };
  return zone()->New<TailCallOperator>(call_descriptor);
}

const Operator* CommonOperatorBuilder::Projection(size_t index) {
  switch (index) {
#define CACHED_PROJECTION(index) \
  case index:                    \
    return &cache_.kProjection##index##Operator;
    CACHED_PROJECTION_LIST(CACHED_PROJECTION)
#undef CACHED_PROJECTION
    default:
      break;
  }
  // Uncached.
  return zone()->New<Operator1<size_t>>(  // --
      IrOpcode::kProjection,              // opcode
      Operator::kPure,                    // flags
      "Projection",                       // name
      1, 0, 1, 1, 0, 0,                   // counts
      index);                             // parameter
}


const Operator* CommonOperatorBuilder::ResizeMergeOrPhi(const Operator* op,
                                                        int size) {
  if (op->opcode() == IrOpcode::kPhi) {
    return Phi(PhiRepresentationOf(op), size);
  } else if (op->opcode() == IrOpcode::kEffectPhi) {
    return EffectPhi(size);
  } else if (op->opcode() == IrOpcode::kMerge) {
    return Merge(size);
  } else if (op->opcode() == IrOpcode::kLoop) {
    return Loop(size);
  } else {
    UNREACHABLE();
  }
}

const FrameStateFunctionInfo*
CommonOperatorBuilder::CreateFrameStateFunctionInfo(
    FrameStateType type, uint16_t parameter_count, uint16_t max_arguments,
    int local_count, IndirectHandle<SharedFunctionInfo> shared_info,
    IndirectHandle<BytecodeArray> bytecode_array) {
  return zone()->New<FrameStateFunctionInfo>(type, parameter_count,
                                             max_arguments, local_count,
                                             shared_info, bytecode_array);
}

#if V8_ENABLE_WEBASSEMBLY
const FrameStateFunctionInfo*
CommonOperatorBuilder::CreateJSToWasmFrameStateFunctionInfo(
    FrameStateType type, uint16_t parameter_count, int local_count,
    Handle<SharedFunctionInfo> shared_info,
    const wasm::CanonicalSig* signature) {
  DCHECK_EQ(type, FrameStateType::kJSToWasmBuiltinContinuation);
  DCHECK_NOT_NULL(signature);
  return zone()->New<JSToWasmFrameStateFunctionInfo>(
      type, parameter_count, local_count, shared_info, signature);
}
#endif  // V8_ENABLE_WEBASSEMBLY

const Operator* CommonOperatorBuilder::Chained(const Operator* op) {
  // Use Chained only for operators that are not on the effect chain already.
  DCHECK_EQ(op->EffectInputCount(), 0);
  DCHECK_EQ(op->ControlInputCount(), 0);
  const char* mnemonic;
  switch (op->opcode()) {
    case IrOpcode::kChangeInt64ToBigInt:
      mnemonic = "Chained[ChangeInt64ToBigInt]";
      break;
    case IrOpcode::kChangeUint64ToBigInt:
      mnemonic = "Chained[ChangeUint64ToBigInt]";
      break;
    default:
      UNREACHABLE();
  }
  // TODO(nicohartmann@): Need to store operator properties once we have to
  // support Operator1 operators.
  Operator::Properties properties = op->properties();
  return zone()->New<Operator>(op->opcode(), properties, mnemonic,
                               op->ValueInputCount(), 1, 1,
                               op->ValueOutputCount(), 1, 0);
}

const Operator* CommonOperatorBuilder::DeadValue(MachineRepresentation rep) {
  return zone()->New<Operator1<MachineRepresentation>>(  // --
      IrOpcode::kDeadValue, Operator::kPure,             // opcode
      "DeadValue",
```