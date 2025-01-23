Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/simplified-lowering.cc`.

The code snippet focuses on handling binary operations (specifically the modulo operator) and bounds checks during the "simplified lowering" phase of the V8 compiler. This phase aims to transform high-level, architecture-independent operations into lower-level, machine-specific instructions.

Here's a breakdown of the logic:

1. **Modulo Operator (`%`) Lowering:**
   - It checks the input types to determine the most efficient way to perform the modulo operation.
   - It prioritizes integer modulo operations (Uint32Mod, Int32Mod) if the inputs are known to be unsigned or signed 32-bit integers.
   - It considers type feedback (NumberOperationHint) to potentially use faster integer modulo if the runtime behavior suggests it.
   - If the result is used as a 32-bit integer (truncation.IsUsedAsWord32()), it aims for integer modulo.
   - If the inputs are known to be within the signed small integer range, it uses overflow-checking integer modulo operations.
   - As a fallback, if the inputs are general numbers, it uses floating-point modulo (Float64Mod).
   - It uses `UseInfo` to specify how input values should be accessed (e.g., as unsigned 32-bit, signed 32-bit, or floating-point).
   - It uses `DeferReplacement` to schedule the actual replacement of the high-level node with the lower-level machine node.
   - It uses `ChangeToUint32OverflowOp` and `ChangeToInt32OverflowOp` to replace the node with overflow-checking versions.
   - It uses `ChangeToPureOp` to replace the node with a pure machine operation.

2. **Bounds Check Lowering (`CheckBounds`):**
   - It handles the lowering of array bounds checks.
   - It checks the types of the index and length.
   - If the length is known to be an unsigned 31-bit integer, it attempts to lower the bounds check to a `CheckedUint32Bounds` operation.
   - It handles cases where the index might be a signed 32-bit integer and potentially converts it to unsigned.
   - It also handles cases with `kConvertStringAndMinusZero` flag, which might involve converting string indices or handling -0.
   - For larger lengths (PositiveSafeInteger), it uses `CheckedUint64Bounds`.
   - It utilizes `UseInfo` like `CheckedTaggedAsArrayIndex`, `CheckedSigned32AsWord32`, and `CheckedSigned64AsWord64` to specify input usage.
   - It potentially eliminates redundant bounds checks if the index is already known to be within bounds.

**Relationship to JavaScript:**

The code directly relates to how JavaScript's modulo operator (`%`) and array access (which involves bounds checks) are optimized by the V8 compiler.

**Example (Modulo):**

```javascript
function moduloExample(a, b) {
  return a % b;
}

// Example 1: Integers
moduloExample(10, 3); // V8 might use Int32Mod

// Example 2: Large unsigned integers
moduloExample(4294967290, 5); // V8 might use Uint32Mod

// Example 3: Floating-point numbers
moduloExample(3.14, 2.0); // V8 will likely use Float64Mod
```

**Example (Bounds Check):**

```javascript
function accessArray(arr, index) {
  return arr[index];
}

const myArray = [1, 2, 3];
accessArray(myArray, 1); // V8 will perform a bounds check
accessArray(myArray, -1); // Out of bounds, V8 will detect this
accessArray(myArray, 5);  // Out of bounds
```

**Assumptions and Logic:**

The code makes assumptions about the input types based on type feedback and static analysis. It tries to choose the most efficient machine operation based on these assumptions.

**Common Programming Errors:**

- **Incorrect type assumptions:** If the JavaScript code leads the type feedback to believe a variable is always an integer, but it sometimes isn't, V8 might have chosen an optimized integer modulo operation that could lead to incorrect results or deoptimization.
- **Out-of-bounds array access:** This is the primary reason for bounds checks. Accessing an array with an index outside its valid range will be caught by these checks.

**Summary of Functionality (Part 3):**

This part of `simplified-lowering.cc` focuses on **lowering binary modulo operations and array bounds checks**. It analyzes the types of operands and uses type feedback to select the most efficient underlying machine instructions for these operations. It aims to optimize performance by leveraging type information and potentially avoiding unnecessary checks or conversions. It deals with different scenarios based on whether the operands are integers (signed or unsigned), floating-point numbers, or if the result is being used in a context that requires truncation to a 32-bit integer. For bounds checks, it ensures that array accesses are within valid limits, potentially performing type conversions if necessary, especially when dealing with string indices or negative zero.

这是 `v8/src/compiler/simplified-lowering.cc` 源代码的第三部分，主要功能是 **将高级的、简化的中间表示 (Simplified nodes) 中的二进制模运算操作和数组边界检查操作降低到更底层的、更接近机器指令的操作 (Machine nodes)**。它会根据操作数的类型信息和类型反馈，选择合适的机器指令，并插入必要的类型转换和检查。

**功能归纳：**

1. **二进制模运算 (`%`) 的 Lowering：**
   -  根据输入操作数的类型（无符号 32 位整数、有符号 32 位整数、或者通用数字），选择不同的底层模运算指令（`Uint32Mod`、`Int32Mod`、`Float64Mod`）。
   -  会考虑类型反馈信息 (`NumberOperationHint`) 来优化选择，例如，如果类型反馈表明操作数通常是小的有符号整数，可能会使用带溢出检查的整数模运算。
   -  如果模运算的结果被用作 32 位整数，会优先选择整数模运算。
   -  对于已知是无符号或有符号 32 位整数的情况，会直接使用对应的整数模运算指令。
   -  作为兜底方案，如果操作数是通用的数字类型，会使用浮点数模运算。
   -  利用 `UseInfo` 来指定输入值的使用方式，例如，指示输入应该被视为无符号 32 位整数或有符号 32 位整数。
   -  使用 `DeferReplacement` 将高层节点替换为底层的机器节点。
   -  使用 `ChangeToUint32OverflowOp` 和 `ChangeToInt32OverflowOp` 将节点替换为带溢出检查的版本。
   -  使用 `ChangeToPureOp` 将节点替换为纯粹的机器操作。

2. **数组边界检查 (`CheckBounds`) 的 Lowering：**
   -  负责将高级的边界检查操作转换为底层的 `CheckedUint32Bounds` 或 `CheckedUint64Bounds` 操作。
   -  检查索引和数组长度的类型。
   -  如果数组长度是无符号 31 位整数，会尝试将其降低到 `CheckedUint32Bounds`。
   -  处理索引可能是带符号 32 位整数的情况，并可能进行转换。
   -  处理带有 `CheckBoundsFlag::kConvertStringAndMinusZero` 标志的情况，这涉及到字符串索引和负零的转换。
   -  对于较大的安全整数范围的长度，使用 `CheckedUint64Bounds`。
   -  使用 `UseInfo`，例如 `CheckedTaggedAsArrayIndex`、`CheckedSigned32AsWord32` 和 `CheckedSigned64AsWord64`，来指定输入的使用方式。
   -  在已知索引在边界内的情况下，可能会消除冗余的边界检查。

**与 JavaScript 功能的关系：**

这段代码直接关系到 JavaScript 中的模运算符 (`%`) 和数组访问 (`[]`) 的优化。V8 编译器会使用这里的逻辑来确定如何高效地执行这些操作。

**JavaScript 示例 (模运算)：**

```javascript
function moduloExample(a, b) {
  return a % b;
}

// 示例 1：整数
moduloExample(10, 3); // V8 可能会使用 Int32Mod

// 示例 2：大的无符号整数
moduloExample(4294967290, 5); // V8 可能会使用 Uint32Mod

// 示例 3：浮点数
moduloExample(3.14, 2.0); // V8 很可能使用 Float64Mod
```

**JavaScript 示例 (边界检查)：**

```javascript
function accessArray(arr, index) {
  return arr[index];
}

const myArray = [1, 2, 3];
accessArray(myArray, 1); // V8 会进行边界检查
accessArray(myArray, -1); // 越界，V8 会检测到
accessArray(myArray, 5);  // 越界
```

**代码逻辑推理和假设输入/输出：**

**假设输入 (模运算)：**

```
node->op() 是一个 kNumberMod 节点。
node->InputAt(0) 的类型是 Type::Unsigned32() (例如，来自位运算或 Math.imul)。
node->InputAt(1) 的类型是 Type::Unsigned32()。
truncation.IsUsedAsWord32() 返回 true。
```

**预期输出 (模运算)：**

V8 会将该 `kNumberMod` 节点替换为 `Uint32Mod` 机器节点，并确保输入以无符号 32 位整数的形式提供。

**假设输入 (边界检查)：**

```
node->op() 是一个 kCheckBounds 节点。
node->InputAt(0) 的类型是 Type::Integral32() (索引)。
node->InputAt(1) 的类型是 Type::Unsigned31() (数组长度)。
CheckBoundsParametersOf(node->op()).flags() 不包含 CheckBoundsFlag::kConvertStringAndMinusZero。
```

**预期输出 (边界检查)：**

V8 会将该 `kCheckBounds` 节点替换为 `CheckedUint32Bounds` 机器节点，并确保索引和长度以适当的 32 位整数形式提供。

**用户常见的编程错误：**

- **对浮点数进行位运算或期望整数模运算的行为：** JavaScript 的 `%` 运算符在操作数为浮点数时执行的是浮点数模运算，这可能与期望的整数模运算行为不同。
  ```javascript
  console.log(3.5 % 1); // 输出 0.5
  console.log(3 % 1);   // 输出 0
  ```
- **数组越界访问：** 这是边界检查要防止的主要错误。尝试访问数组中不存在的索引会导致运行时错误或未定义的行为。
  ```javascript
  const arr = [1, 2, 3];
  console.log(arr[5]); // 输出 undefined，但在 V8 内部会触发边界检查。
  ```

总之，这段代码是 V8 编译器进行优化的关键部分，它负责将高级的语言特性降低到更高效的机器指令，从而提升 JavaScript 代码的执行性能。

### 提示词
```
这是目录为v8/src/compiler/simplified-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/simplified-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
if (BothInputsAre(node, Type::Unsigned32OrMinusZeroOrNaN()) &&
        (truncation.IsUsedAsWord32() ||
         NodeProperties::GetType(node).Is(Type::Unsigned32()))) {
      // => unsigned Uint32Mod
      VisitWord32TruncatingBinop<T>(node);
      if (lower<T>()) DeferReplacement(node, lowering->Uint32Mod(node));
      return;
    }
    if (BothInputsAre(node, Type::Signed32OrMinusZeroOrNaN()) &&
        (truncation.IsUsedAsWord32() ||
         NodeProperties::GetType(node).Is(Type::Signed32()))) {
      // => signed Int32Mod
      VisitWord32TruncatingBinop<T>(node);
      if (lower<T>()) DeferReplacement(node, lowering->Int32Mod(node));
      return;
    }

    // Try to use type feedback.
    NumberOperationHint hint = NumberOperationHintOf(node->op());

    // Handle the case when no uint32 checks on inputs are necessary
    // (but an overflow check is needed on the output).
    if (BothInputsAreUnsigned32(node)) {
      if (hint == NumberOperationHint::kSignedSmall) {
        VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                      MachineRepresentation::kWord32, Type::Unsigned32());
        if (lower<T>()) ChangeToUint32OverflowOp(node);
        return;
      }
    }

    // Handle the case when no int32 checks on inputs are necessary
    // (but an overflow check is needed on the output).
    if (BothInputsAre(node, Type::Signed32())) {
      // If both the inputs the feedback are int32, use the overflow op.
      if (hint == NumberOperationHint::kSignedSmall) {
        VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                      MachineRepresentation::kWord32, Type::Signed32());
        if (lower<T>()) ChangeToInt32OverflowOp(node);
        return;
      }
    }

    if (hint == NumberOperationHint::kSignedSmall) {
      // If the result is truncated, we only need to check the inputs.
      // For the left hand side we just propagate the identify zeros
      // mode of the {truncation}; and for modulus the sign of the
      // right hand side doesn't matter anyways, so in particular there's
      // no observable difference between a 0 and a -0 then.
      UseInfo const lhs_use =
          CheckedUseInfoAsWord32FromHint(hint, truncation.identify_zeros());
      UseInfo const rhs_use =
          CheckedUseInfoAsWord32FromHint(hint, kIdentifyZeros);
      if (truncation.IsUsedAsWord32()) {
        VisitBinop<T>(node, lhs_use, rhs_use, MachineRepresentation::kWord32);
        if (lower<T>()) DeferReplacement(node, lowering->Int32Mod(node));
      } else if (BothInputsAre(node, Type::Unsigned32OrMinusZeroOrNaN())) {
        Type const restriction =
            truncation.IdentifiesZeroAndMinusZero() &&
                    TypeOf(node->InputAt(0)).Maybe(Type::MinusZero())
                ? Type::Unsigned32OrMinusZero()
                : Type::Unsigned32();
        VisitBinop<T>(node, lhs_use, rhs_use, MachineRepresentation::kWord32,
                      restriction);
        if (lower<T>()) ChangeToUint32OverflowOp(node);
      } else {
        Type const restriction =
            truncation.IdentifiesZeroAndMinusZero() &&
                    TypeOf(node->InputAt(0)).Maybe(Type::MinusZero())
                ? Type::Signed32OrMinusZero()
                : Type::Signed32();
        VisitBinop<T>(node, lhs_use, rhs_use, MachineRepresentation::kWord32,
                      restriction);
        if (lower<T>()) ChangeToInt32OverflowOp(node);
      }
      return;
    }

    if (TypeOf(node->InputAt(0)).Is(Type::Unsigned32()) &&
        TypeOf(node->InputAt(1)).Is(Type::Unsigned32()) &&
        (truncation.IsUsedAsWord32() ||
         NodeProperties::GetType(node).Is(Type::Unsigned32()))) {
      VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                    MachineRepresentation::kWord32, Type::Number());
      if (lower<T>()) DeferReplacement(node, lowering->Uint32Mod(node));
      return;
    }
    if (TypeOf(node->InputAt(0)).Is(Type::Signed32()) &&
        TypeOf(node->InputAt(1)).Is(Type::Signed32()) &&
        (truncation.IsUsedAsWord32() ||
         NodeProperties::GetType(node).Is(Type::Signed32()))) {
      VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                    MachineRepresentation::kWord32, Type::Number());
      if (lower<T>()) DeferReplacement(node, lowering->Int32Mod(node));
      return;
    }

    // default case => Float64Mod
    // For the left hand side we just propagate the identify zeros
    // mode of the {truncation}; and for modulus the sign of the
    // right hand side doesn't matter anyways, so in particular there's
    // no observable difference between a 0 and a -0 then.
    UseInfo const lhs_use = UseInfo::CheckedNumberOrOddballAsFloat64(
        truncation.identify_zeros(), FeedbackSource());
    UseInfo const rhs_use = UseInfo::CheckedNumberOrOddballAsFloat64(
        kIdentifyZeros, FeedbackSource());
    VisitBinop<T>(node, lhs_use, rhs_use, MachineRepresentation::kFloat64,
                  Type::Number());
    if (lower<T>()) ChangeToPureOp(node, Float64Op(node));
  }

  // Just assert for Propagate and Retype. Lower specialized below.
  template <Phase T>
  void InsertUnreachableIfNecessary(Node* node) {
    static_assert(propagate<T>() || retype<T>(),
                  "This version of InsertUnreachableIfNecessary has to be "
                  "called in the Propagate or Retype phase.");
  }

  template <Phase T>
  void VisitCheckBounds(Node* node, SimplifiedLowering* lowering) {
    CheckBoundsParameters const& p = CheckBoundsParametersOf(node->op());
    FeedbackSource const& feedback = p.check_parameters().feedback();
    Type const index_type = TypeOf(node->InputAt(0));
    Type const length_type = TypeOf(node->InputAt(1));

    // Conversions, if requested and needed, will be handled by the
    // representation changer, not by the lower-level Checked*Bounds operators.
    CheckBoundsFlags new_flags =
        p.flags().without(CheckBoundsFlag::kConvertStringAndMinusZero);

    if (length_type.Is(Type::Unsigned31())) {
      if (index_type.Is(Type::Integral32()) ||
          (index_type.Is(Type::Integral32OrMinusZero()) &&
           p.flags() & CheckBoundsFlag::kConvertStringAndMinusZero)) {
        // Map the values in the [-2^31,-1] range to the [2^31,2^32-1] range,
        // which will be considered out-of-bounds because the {length_type} is
        // limited to Unsigned31. This also converts -0 to 0.
        VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                      MachineRepresentation::kWord32);
        if (lower<T>()) {
          if (index_type.IsNone() || length_type.IsNone() ||
              (index_type.Min() >= 0.0 &&
               index_type.Max() < length_type.Min())) {
            // The bounds check is redundant if we already know that
            // the index is within the bounds of [0.0, length[.
            // TODO(neis): Move this into TypedOptimization?
            if (v8_flags.turbo_typer_hardening) {
              new_flags |= CheckBoundsFlag::kAbortOnOutOfBounds;
            } else {
              DeferReplacement(node, NodeProperties::GetValueInput(node, 0));
              return;
            }
          }
          ChangeOp(node,
                   simplified()->CheckedUint32Bounds(feedback, new_flags));
        }
      } else if (p.flags() & CheckBoundsFlag::kConvertStringAndMinusZero) {
        VisitBinop<T>(node, UseInfo::CheckedTaggedAsArrayIndex(feedback),
                      UseInfo::Word(), MachineType::PointerRepresentation());
        if (lower<T>()) {
          if (jsgraph_->machine()->Is64()) {
            ChangeOp(node,
                     simplified()->CheckedUint64Bounds(feedback, new_flags));
          } else {
            ChangeOp(node,
                     simplified()->CheckedUint32Bounds(feedback, new_flags));
          }
        }
      } else {
        VisitBinop<T>(
            node, UseInfo::CheckedSigned32AsWord32(kDistinguishZeros, feedback),
            UseInfo::TruncatingWord32(), MachineRepresentation::kWord32);
        if (lower<T>()) {
          ChangeOp(node,
                   simplified()->CheckedUint32Bounds(feedback, new_flags));
        }
      }
    } else {
      CHECK(length_type.Is(type_cache_->kPositiveSafeInteger));
      IdentifyZeros zero_handling =
          (p.flags() & CheckBoundsFlag::kConvertStringAndMinusZero)
              ? kIdentifyZeros
              : kDistinguishZeros;
      VisitBinop<T>(node,
                    UseInfo::CheckedSigned64AsWord64(zero_handling, feedback),
                    UseInfo::Word64(), MachineRepresentation::kWord64);
      if (lower<T>()) {
        ChangeOp(node, simplified()->CheckedUint64Bounds(feedback, new_flags));
      }
    }
  }

  UseInfo UseInfoForFastApiCallArgument(CTypeInfo type,
                                        CFunctionInfo::Int64Representation repr,
                                        FeedbackSource const& feedback) {
    switch (type.GetSequenceType()) {
      case CTypeInfo::SequenceType::kScalar: {
        uint8_t flags = uint8_t(type.GetFlags());
        if (flags & uint8_t(CTypeInfo::Flags::kEnforceRangeBit) ||
            flags & uint8_t(CTypeInfo::Flags::kClampBit)) {
          DCHECK(repr != CFunctionInfo::Int64Representation::kBigInt);
          // If the parameter is marked as `kEnforceRange` or `kClampBit`, then
          // special type conversion gets added explicitly to the generated
          // code. Therefore it is sufficient here to only require here that the
          // value is a Float64, even though the C++ signature actually asks for
          // an `int32_t`.
          return UseInfo::CheckedNumberAsFloat64(kIdentifyZeros, feedback);
        }
        switch (type.GetType()) {
          case CTypeInfo::Type::kVoid:
          case CTypeInfo::Type::kUint8:
            UNREACHABLE();
          case CTypeInfo::Type::kBool:
            return UseInfo::Bool();
          case CTypeInfo::Type::kInt32:
          case CTypeInfo::Type::kUint32:
            return UseInfo::CheckedNumberAsWord32(feedback);
          // TODO(mslekova): We deopt for unsafe integers, but ultimately we
          // want to make this less restrictive in order to stay on the fast
          // path.
          case CTypeInfo::Type::kInt64:
          case CTypeInfo::Type::kUint64:
            if (repr == CFunctionInfo::Int64Representation::kBigInt) {
              return UseInfo::CheckedBigIntTruncatingWord64(feedback);
            } else if (repr == CFunctionInfo::Int64Representation::kNumber) {
              return UseInfo::CheckedSigned64AsWord64(kIdentifyZeros, feedback);
            } else {
              UNREACHABLE();
            }
          case CTypeInfo::Type::kAny:
            return UseInfo::CheckedSigned64AsWord64(kIdentifyZeros, feedback);
          case CTypeInfo::Type::kFloat32:
          case CTypeInfo::Type::kFloat64:
            return UseInfo::CheckedNumberAsFloat64(kDistinguishZeros, feedback);
          case CTypeInfo::Type::kPointer:
          case CTypeInfo::Type::kV8Value:
          case CTypeInfo::Type::kSeqOneByteString:
          case CTypeInfo::Type::kApiObject:
            return UseInfo::AnyTagged();
        }
      }
      case CTypeInfo::SequenceType::kIsSequence: {
        CHECK_EQ(type.GetType(), CTypeInfo::Type::kVoid);
        return UseInfo::AnyTagged();
      }
        START_ALLOW_USE_DEPRECATED()
      case CTypeInfo::SequenceType::kIsTypedArray: {
        return UseInfo::AnyTagged();
      }
        END_ALLOW_USE_DEPRECATED()
      default: {
        UNREACHABLE();  // TODO(mslekova): Implement array buffers.
      }
    }
  }

  static constexpr int kInitialArgumentsCount = 10;

  template <Phase T>
  void VisitFastApiCall(Node* node, SimplifiedLowering* lowering) {
    FastApiCallParameters const& op_params =
        FastApiCallParametersOf(node->op());
    // We only consider the first function signature here. In case of function
    // overloads, we only support the case of two functions that differ for one
    // argument, which must be a JSArray in one function and a TypedArray in the
    // other function, and both JSArrays and TypedArrays have the same UseInfo
    // UseInfo::AnyTagged(). All the other argument types must match.
    const CFunctionInfo* c_signature = op_params.c_function().signature;
    const int c_arg_count = c_signature->ArgumentCount();
    CallDescriptor* call_descriptor = op_params.descriptor();
    // Arguments for CallApiCallbackOptimizedXXX builtin (including context)
    // plus JS arguments (including receiver).
    int slow_arg_count = static_cast<int>(call_descriptor->ParameterCount());
    const int value_input_count = node->op()->ValueInputCount();
    CHECK_EQ(FastApiCallNode::ArityForArgc(c_arg_count, slow_arg_count),
             value_input_count);

    FastApiCallNode n(node);

    base::SmallVector<UseInfo, kInitialArgumentsCount> arg_use_info(
        c_arg_count);
    // Propagate representation information from TypeInfo.
    int cursor = 0;
    for (int i = 0; i < c_arg_count; i++) {
      arg_use_info[i] = UseInfoForFastApiCallArgument(
          c_signature->ArgumentInfo(i), c_signature->GetInt64Representation(),
          op_params.feedback());
      ProcessInput<T>(node, cursor++, arg_use_info[i]);
    }
    // Callback data for fast call.
    DCHECK_EQ(n.CallbackDataIndex(), cursor);
    ProcessInput<T>(node, cursor++, UseInfo::AnyTagged());

    // The call code for the slow call.
    ProcessInput<T>(node, cursor++, UseInfo::AnyTagged());
    // For the slow builtin parameters (indexes [1, ..., params]), propagate
    // representation information from call descriptor.
    for (int i = 1; i <= slow_arg_count; i++) {
      ProcessInput<T>(node, cursor++,
                      TruncatingUseInfoFromRepresentation(
                          call_descriptor->GetInputType(i).representation()));
    }
    // Visit frame state input as tagged.
    DCHECK_EQ(n.FrameStateIndex(), cursor);
    ProcessInput<T>(node, cursor++, UseInfo::AnyTagged());
    DCHECK_EQ(cursor, value_input_count);

    // Effect and Control.
    ProcessRemainingInputs<T>(node, value_input_count);

    CTypeInfo return_type = op_params.c_function().signature->ReturnInfo();
    switch (return_type.GetType()) {
      case CTypeInfo::Type::kBool:
        SetOutput<T>(node, MachineRepresentation::kBit);
        return;
      case CTypeInfo::Type::kFloat32:
        SetOutput<T>(node, MachineRepresentation::kFloat32);
        return;
      case CTypeInfo::Type::kFloat64:
        SetOutput<T>(node, MachineRepresentation::kFloat64);
        return;
      case CTypeInfo::Type::kInt32:
        SetOutput<T>(node, MachineRepresentation::kWord32);
        return;
      case CTypeInfo::Type::kInt64:
      case CTypeInfo::Type::kUint64:
        if (c_signature->GetInt64Representation() ==
            CFunctionInfo::Int64Representation::kBigInt) {
          SetOutput<T>(node, MachineRepresentation::kWord64);
          return;
        }
        DCHECK_EQ(c_signature->GetInt64Representation(),
                  CFunctionInfo::Int64Representation::kNumber);
        SetOutput<T>(node, MachineRepresentation::kFloat64);
        return;
      case CTypeInfo::Type::kSeqOneByteString:
        SetOutput<T>(node, MachineRepresentation::kTagged);
        return;
      case CTypeInfo::Type::kUint32:
        SetOutput<T>(node, MachineRepresentation::kWord32);
        return;
      case CTypeInfo::Type::kUint8:
        SetOutput<T>(node, MachineRepresentation::kWord8);
        return;
      case CTypeInfo::Type::kAny:
        // This type is only supposed to be used for parameters, not returns.
        UNREACHABLE();
      case CTypeInfo::Type::kPointer:
      case CTypeInfo::Type::kApiObject:
      case CTypeInfo::Type::kV8Value:
      case CTypeInfo::Type::kVoid:
        SetOutput<T>(node, MachineRepresentation::kTagged);
        return;
    }
  }

  template <Phase T>
  bool TryOptimizeBigInt64Shift(Node* node, const Truncation& truncation,
                                SimplifiedLowering* lowering) {
    DCHECK(Is64());
    if (!truncation.IsUsedAsWord64()) return false;

    Type input_type = GetUpperBound(node->InputAt(0));
    Type shift_amount_type = GetUpperBound(node->InputAt(1));

    if (!shift_amount_type.IsHeapConstant()) return false;
    HeapObjectRef ref = shift_amount_type.AsHeapConstant()->Ref();
    if (!ref.IsBigInt()) return false;
    BigIntRef bigint = ref.AsBigInt();
    bool lossless = false;
    int64_t shift_amount = bigint.AsInt64(&lossless);
    // We bail out if we cannot represent the shift amount correctly.
    if (!lossless) return false;

    // Canonicalize {shift_amount}.
    bool is_shift_left =
        node->opcode() == IrOpcode::kSpeculativeBigIntShiftLeft;
    if (shift_amount < 0) {
      // A shift amount of abs(std::numeric_limits<int64_t>::min()) is not
      // representable.
      if (shift_amount == std::numeric_limits<int64_t>::min()) return false;
      is_shift_left = !is_shift_left;
      shift_amount = -shift_amount;
      DCHECK_GT(shift_amount, 0);
    }
    DCHECK_GE(shift_amount, 0);

    // If the operation is a *real* left shift, propagate truncation.
    // If it is a *real* right shift, the output representation is
    // word64 only if we know the input type is BigInt64.
    // Otherwise, fall through to using BigIntOperationHint.
    if (is_shift_left) {
      VisitBinop<T>(node,
                    UseInfo::CheckedBigIntTruncatingWord64(FeedbackSource{}),
                    UseInfo::Any(), MachineRepresentation::kWord64);
      if (lower<T>()) {
        if (shift_amount > 63) {
          DeferReplacement(node, jsgraph_->Int64Constant(0));
        } else if (shift_amount == 0) {
          DeferReplacement(node, node->InputAt(0));
        } else {
          DCHECK_GE(shift_amount, 1);
          DCHECK_LE(shift_amount, 63);
          ReplaceWithPureNode(
              node, graph()->NewNode(lowering->machine()->Word64Shl(),
                                     node->InputAt(0),
                                     jsgraph_->Int64Constant(shift_amount)));
        }
      }
      return true;
    } else if (input_type.Is(Type::SignedBigInt64())) {
      VisitBinop<T>(node,
                    UseInfo::CheckedBigIntTruncatingWord64(FeedbackSource{}),
                    UseInfo::Any(), MachineRepresentation::kWord64);
      if (lower<T>()) {
        if (shift_amount > 63) {
          ReplaceWithPureNode(
              node,
              graph()->NewNode(lowering->machine()->Word64Sar(),
                               node->InputAt(0), jsgraph_->Int64Constant(63)));
        } else if (shift_amount == 0) {
          DeferReplacement(node, node->InputAt(0));
        } else {
          DCHECK_GE(shift_amount, 1);
          DCHECK_LE(shift_amount, 63);
          ReplaceWithPureNode(
              node, graph()->NewNode(lowering->machine()->Word64Sar(),
                                     node->InputAt(0),
                                     jsgraph_->Int64Constant(shift_amount)));
        }
      }
      return true;
    } else if (input_type.Is(Type::UnsignedBigInt64())) {
      VisitBinop<T>(node,
                    UseInfo::CheckedBigIntTruncatingWord64(FeedbackSource{}),
                    UseInfo::Any(), MachineRepresentation::kWord64);
      if (lower<T>()) {
        if (shift_amount > 63) {
          DeferReplacement(node, jsgraph_->Int64Constant(0));
        } else if (shift_amount == 0) {
          DeferReplacement(node, node->InputAt(0));
        } else {
          DCHECK_GE(shift_amount, 1);
          DCHECK_LE(shift_amount, 63);
          ReplaceWithPureNode(
              node, graph()->NewNode(lowering->machine()->Word64Shr(),
                                     node->InputAt(0),
                                     jsgraph_->Int64Constant(shift_amount)));
        }
      }
      return true;
    }

    // None of the cases we can optimize here.
    return false;
  }

#if V8_ENABLE_WEBASSEMBLY
  static MachineType MachineTypeForWasmReturnType(
      wasm::CanonicalValueType type) {
    switch (type.kind()) {
      case wasm::kI32:
        return MachineType::Int32();
      case wasm::kI64:
        return MachineType::Int64();
      case wasm::kF32:
        return MachineType::Float32();
      case wasm::kF64:
        return MachineType::Float64();
      case wasm::kRef:
      case wasm::kRefNull:
        return MachineType::AnyTagged();
      default:
        UNREACHABLE();
    }
  }

  UseInfo UseInfoForJSWasmCallArgument(Node* input,
                                       wasm::CanonicalValueType type,
                                       FeedbackSource const& feedback) {
    // If the input type is a Number or Oddball, we can directly convert the
    // input into the Wasm native type of the argument. If not, we return
    // UseInfo::AnyTagged to signal that WasmWrapperGraphBuilder will need to
    // add Nodes to perform the conversion (in WasmWrapperGraphBuilder::FromJS).
    switch (type.kind()) {
      case wasm::kI32:
        return UseInfo::CheckedNumberOrOddballAsWord32(feedback);
      case wasm::kI64:
        return UseInfo::CheckedBigIntTruncatingWord64(feedback);
      case wasm::kF32:
      case wasm::kF64:
        // For Float32, TruncateFloat64ToFloat32 will be inserted later in
        // WasmWrapperGraphBuilder::BuildJSToWasmWrapper.
        return UseInfo::CheckedNumberOrOddballAsFloat64(kDistinguishZeros,
                                                        feedback);
      case wasm::kRef:
      case wasm::kRefNull:
        return UseInfo::AnyTagged();
      default:
        UNREACHABLE();
    }
  }

  template <Phase T>
  void VisitJSWasmCall(Node* node, SimplifiedLowering* lowering) {
    DCHECK_EQ(JSWasmCallNode::TargetIndex(), 0);
    DCHECK_EQ(JSWasmCallNode::ReceiverIndex(), 1);
    DCHECK_EQ(JSWasmCallNode::FirstArgumentIndex(), 2);

    JSWasmCallNode n(node);

    JSWasmCallParameters const& params = n.Parameters();
    const wasm::CanonicalSig* wasm_signature = params.signature();
    int wasm_arg_count = static_cast<int>(wasm_signature->parameter_count());
    DCHECK_EQ(wasm_arg_count, n.ArgumentCount());

    base::SmallVector<UseInfo, kInitialArgumentsCount> arg_use_info(
        wasm_arg_count);

    // Visit JSFunction and Receiver nodes.
    ProcessInput<T>(node, JSWasmCallNode::TargetIndex(), UseInfo::Any());
    ProcessInput<T>(node, JSWasmCallNode::ReceiverIndex(), UseInfo::Any());

    // Propagate representation information from TypeInfo.
    for (int i = 0; i < wasm_arg_count; i++) {
      TNode<Object> input = n.Argument(i);
      DCHECK_NOT_NULL(input);
      arg_use_info[i] = UseInfoForJSWasmCallArgument(
          input, wasm_signature->GetParam(i), params.feedback());
      ProcessInput<T>(node, JSWasmCallNode::ArgumentIndex(i), arg_use_info[i]);
    }

    // Visit value, context and frame state inputs as tagged.
    int first_effect_index = NodeProperties::FirstEffectIndex(node);
    DCHECK(first_effect_index >
           JSWasmCallNode::FirstArgumentIndex() + wasm_arg_count);
    for (int i = JSWasmCallNode::FirstArgumentIndex() + wasm_arg_count;
         i < first_effect_index; i++) {
      ProcessInput<T>(node, i, UseInfo::AnyTagged());
    }

    // Effect and Control.
    ProcessRemainingInputs<T>(node, NodeProperties::FirstEffectIndex(node));

    if (wasm_signature->return_count() == 1) {
      MachineType return_type =
          MachineTypeForWasmReturnType(wasm_signature->GetReturn());
      SetOutput<T>(
          node, return_type.representation(),
          JSWasmCallNode::TypeForWasmReturnType(wasm_signature->GetReturn()));
    } else {
      DCHECK_EQ(wasm_signature->return_count(), 0);
      SetOutput<T>(node, MachineRepresentation::kTagged);
    }

    // The actual lowering of JSWasmCall nodes happens later, in the subsequent
    // "wasm-inlining" phase.
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Dispatching routine for visiting the node {node} with the usage {use}.
  // Depending on the operator, propagate new usage info to the inputs.
  template <Phase T>
  void VisitNode(Node* node, Truncation truncation,
                 SimplifiedLowering* lowering) {
    tick_counter_->TickAndMaybeEnterSafepoint();

    if (lower<T>()) {
      // Kill non-effectful operations that have a None-type input and are thus
      // dead code. Otherwise we might end up lowering the operation in a way,
      // e.g. by replacing it with a constant, that cuts the dependency on a
      // deopting operation (the producer of the None type), possibly resulting
      // in a nonsense schedule.
      if (node->op()->EffectOutputCount() == 0 &&
          node->op()->ControlOutputCount() == 0 &&
          node->opcode() != IrOpcode::kDeadValue &&
          node->opcode() != IrOpcode::kStateValues &&
          node->opcode() != IrOpcode::kFrameState &&
          node->opcode() != IrOpcode::kPhi) {
        for (int i = 0; i < node->op()->ValueInputCount(); i++) {
          Node* input = node->InputAt(i);
          if (TypeOf(input).IsNone()) {
            node->ReplaceInput(0, input);
            node->TrimInputCount(1);
            ChangeOp(node,
                     common()->DeadValue(GetInfo(node)->representation()));
            return;
          }
        }
      } else {
        InsertUnreachableIfNecessary<T>(node);
      }
    }

    // Unconditionally eliminate unused pure nodes (only relevant if there's
    // a pure operation in between two effectful ones, where the last one
    // is unused).
    // Note: We must not do this for constants, as they are cached and we
    // would thus kill the cached {node} during lowering (i.e. replace all
    // uses with Dead), but at that point some node lowering might have
    // already taken the constant {node} from the cache (while it was not
    // yet killed) and we would afterwards replace that use with Dead as well.
    if (node->op()->ValueInputCount() > 0 &&
        node->op()->HasProperty(Operator::kPure) && truncation.IsUnused()) {
      return VisitUnused<T>(node);
    }

    switch (node->opcode()) {
      //------------------------------------------------------------------
      // Common operators.
      //------------------------------------------------------------------
      case IrOpcode::kStart:
        // We use Start as a terminator for the frame state chain, so even
        // tho Start doesn't really produce a value, we have to say Tagged
        // here, otherwise the input conversion will fail.
        return VisitLeaf<T>(node, MachineRepresentation::kTagged);
      case IrOpcode::kParameter:
        return VisitUnop<T>(node, UseInfo::None(),
                            linkage()
                                ->GetParameterType(ParameterIndexOf(node->op()))
                                .representation());
      case IrOpcode::kInt32Constant:
        DCHECK_EQ(0, node->InputCount());
        SetOutput<T>(node, MachineRepresentation::kWord32);
        DCHECK(NodeProperties::GetType(node).Is(Type::Machine()));
        if (V8_UNLIKELY(verification_enabled())) {
          // During lowering, SimplifiedLowering generates Int32Constants which
          // need to be treated differently by the verifier than the
          // Int32Constants introduced explicitly in machine graphs. To be able
          // to distinguish them, we record those that are being visited here
          // because they were generated before SimplifiedLowering.
          if (propagate<T>()) {
            verifier_->RecordMachineUsesOfConstant(node, node->uses());
          }
        }
        return;
      case IrOpcode::kInt64Constant:
        return VisitLeaf<T>(node, MachineRepresentation::kWord64);
      case IrOpcode::kExternalConstant:
        return VisitLeaf<T>(node, MachineType::PointerRepresentation());
      case IrOpcode::kNumberConstant: {
        double const value = OpParameter<double>(node->op());
        int value_as_int;
        if (DoubleToSmiInteger(value, &value_as_int)) {
          VisitLeaf<T>(node, MachineRepresentation::kTaggedSigned);
          if (lower<T>()) {
            intptr_t smi = base::bit_cast<intptr_t>(Smi::FromInt(value_as_int));
            Node* constant = InsertTypeOverrideForVerifier(
                NodeProperties::GetType(node),
                lowering->jsgraph()->IntPtrConstant(smi));
            DeferReplacement(node, constant);
          }
          return;
        }
        VisitLeaf<T>(node, MachineRepresentation::kTagged);
        return;
      }
      case IrOpcode::kHeapConstant:
        return VisitLeaf<T>(node, MachineRepresentation::kTaggedPointer);
      case IrOpcode::kTrustedHeapConstant:
        return VisitLeaf<T>(node, MachineRepresentation::kTaggedPointer);
      case IrOpcode::kPointerConstant: {
        VisitLeaf<T>(node, MachineType::PointerRepresentation());
        if (lower<T>()) {
          intptr_t const value = OpParameter<intptr_t>(node->op());
          DeferReplacement(node, lowering->jsgraph()->IntPtrConstant(value));
        }
        return;
      }

      case IrOpcode::kBranch: {
        const auto& p = BranchParametersOf(node->op());
        if (p.semantics() == BranchSemantics::kMachine) {
          // If this is a machine branch, the condition is a machine operator,
          // so we enter machine branch here.
          ProcessInput<T>(node, 0, UseInfo::Any());
        } else {
          DCHECK(TypeOf(node->InputAt(0)).Is(Type::Boolean()));
          ProcessInput<T>(node, 0, UseInfo::Bool());
          if (lower<T>()) {
            ChangeOp(node,
                     common()->Branch(p.hint(), BranchSemantics::kMachine));
          }
        }
        EnqueueInput<T>(node, NodeProperties::FirstControlIndex(node));
        return;
      }
      case IrOpcode::kSwitch:
        ProcessInput<T>(node, 0, UseInfo::TruncatingWord32());
        EnqueueInput<T>(node, NodeProperties::FirstControlIndex(node));
        return;
      case IrOpcode::kSelect:
        return VisitSelect<T>(node, truncation, lowering);
      case IrOpcode::kPhi:
        return VisitPhi<T>(node, truncation, lowering);
      case IrOpcode::kCall:
        return VisitCall<T>(node, lowering);
      case IrOpcode::kAssert: {
        const auto& p = AssertParametersOf(node->op());
        if (p.semantics() == BranchSemantics::kMachine) {
          // If this is a machine condition already, we don't need to do
          // anything.
          ProcessInput<T>(node, 0, UseInfo::Any());
        } else {
          DCHECK(TypeOf(node->InputAt(0)).Is(Type::Boolean()));
          ProcessInput<T>(node, 0, UseInfo::Bool());
          if (lower<T>()) {
            ChangeOp(node, common()->Assert(BranchSemantics::kMachine,
                                            p.condition_string(), p.file(),
                                            p.line()));
          }
        }
        EnqueueInput<T>(node, NodeProperties::FirstControlIndex(node));
        return;
      }

      //------------------------------------------------------------------
      // JavaScript operators.
      //------------------------------------------------------------------
      case IrOpcode::kJSToNumber:
      case IrOpcode::kJSToNumberConvertBigInt:
      case IrOpcode::kJSToNumeric: {
        DCHECK(NodeProperties::GetType(node).Is(Type::Union(
            Type::BigInt(), Type::NumberOrOddball(), graph()->zone())));
        VisitInputs<T>(node);
        // TODO(bmeurer): Optimize somewhat based on input type?
        if (truncation.IsUsedAsWord32()) {
          SetOutput<T>(node, MachineRepresentation::kWord32);
          if (lower<T>())
            lowering->DoJSToNumberOrNumericTruncatesToWord32(node, this);
        } else if (truncation.TruncatesOddballAndBigIntToNumber()) {
          SetOutput<T>(node, MachineRepresentation::kFloat64);
          if (lower<T>())
            lowering->DoJSToNumberOrNumericTruncatesToFloat64(node, this);
        } else {
          SetOutput<T>(node, MachineRepresentation::kTagged);
        }
        return;
      }
      case IrOpcode::kJSToBigInt:
      case IrOpcode::kJSToBigIntConvertNumber: {
        VisitInputs<T>(node);
        SetOutput<T>(node, MachineRepresentation::kTaggedPointer);
        return;
      }

      //------------------------------------------------------------------
      // Simplified operators.
      //------------------------------------------------------------------
      case IrOpcode::kToBoolean: {
        if (truncation.IsUsedAsBool()) {
          ProcessInput<T>(node, 0, UseInfo::Bool());
          SetOutput<T>(node, MachineRepresentation::kBit);
          if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        } else {
          V
```