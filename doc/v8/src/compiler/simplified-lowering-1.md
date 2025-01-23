Response: The user wants me to summarize the functionality of the provided C++ code snippet and illustrate its relation to JavaScript with an example.

The C++ code deals with the lowering of JavaScript's modulo operator (%) in the V8 engine's compiler. It examines the input types and the intended usage of the result to decide on the most efficient machine-level operation.

Here's a breakdown of the logic:

1. **Unsigned 32-bit Modulo:** If both inputs are unsigned 32-bit integers, and the result is used as a 32-bit word or the node's type is unsigned 32-bit, it uses `Uint32Mod`.
2. **Signed 32-bit Modulo:** Similar to the above, but for signed 32-bit integers, it uses `Int32Mod`.
3. **Type Feedback Hints:** It uses type feedback (`NumberOperationHint`) to optimize based on past execution behavior.
4. **Unsigned 32-bit Overflow Check:** If inputs are unsigned 32-bit and the feedback hint suggests a signed small integer, it uses a `Uint32OverflowOp`.
5. **Signed 32-bit Overflow Check:** If inputs are signed 32-bit and the feedback hint suggests a signed small integer, it uses an `Int32OverflowOp`.
6. **Truncated Signed Small Integers:** If the result is used as a 32-bit word and the feedback hint is `kSignedSmall`, it uses `Int32Mod`. If inputs are unsigned, it uses `Uint32OverflowOp`; otherwise, it uses `Int32OverflowOp`.
7. **Explicit Unsigned/Signed 32-bit Inputs:** If the input types are explicitly unsigned or signed 32-bit, and the result is used as a 32-bit word, it uses the corresponding modulo operation.
8. **Default to Float64 Modulo:** If none of the above conditions are met, it defaults to `Float64Mod`.

To illustrate the JavaScript connection, I can show how JavaScript's `%` operator can be optimized to different machine instructions based on the types of the operands.
```cpp
    if (BothInputsAre(node, Type::OrderedNumber())) {
                ? Type::OrderedNumber()
                : Type::PlainNumber())) {
              lowering->DoMin(node, lowering->machine()->Float64LessThan(),
                              MachineRepresentation::kFloat64);
            } else {
              ChangeOp(node, Float64Op(node));
            }
          }
        }
        return;
      }
      case IrOpcode::kNumberPow:
        VisitFloat64Binop<T>(node);
        if (lower<T>()) ChangeOp(node, Float64Op(node));
        return;
      case IrOpcode::kNumberRound: {
        // The rounding modes "ceil", "floor", "trunc" and "nearest"
        // operate the same way on positive and negative zero.
        NumberOperationHint hint = NumberOperationHintOf(node->op());
        VisitUnop<T>(
            node,
            CheckedUseInfoAsFloat64FromHint(hint, FeedbackSource(),
                                            kIdentifyZeros),
            MachineRepresentation::kFloat64);
        if (lower<T>()) ChangeOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kNumberAcos:
      case IrOpcode::kNumberAcosh:
      case IrOpcode::kNumberAsin:
      case IrOpcode::kNumberAsinh:
      case IrOpcode::kNumberAtan:
      case IrOpcode::kNumberAtanh:
      case IrOpcode::kNumberCos:
      case IrOpcode::kNumberCosh:
      case IrOpcode::kNumberExp:
      case IrOpcode::kNumberExpm1:
      case IrOpcode::kNumberLog:
      case IrOpcode::kNumberLog1p:
      case IrOpcode::kNumberLog10:
      case IrOpcode::kNumberLog2:
      case IrOpcode::kNumberSin:
      case IrOpcode::kNumberSinh:
      case IrOpcode::kNumberSqrt:
      case IrOpcode::kNumberTan:
      case IrOpcode::kNumberTanh:
        VisitUnop<T>(node, UseInfo::CheckedNumberOrOddballAsFloat64(
                                kDistinguishZeros, FeedbackSource()),
                     MachineRepresentation::kFloat64);
        if (lower<T>()) ChangeOp(node, Float64Op(node));
        return;
      case IrOpcode::kNumberAtan2:
        VisitBinop<T>(node, UseInfo::CheckedNumberOrOddballAsFloat64(
                                kDistinguishZeros, FeedbackSource()),
                      MachineRepresentation::kFloat64);
        if (lower<T>()) ChangeOp(node, Float64Op(node));
        return;

      case IrOpcode::kStringCharCodeAt:
      case IrOpcode::kStringCodePointAt: {
        ProcessInput<T>(node, 0, UseInfo::Tagged());
        ProcessInput<T>(node, 1, UseInfo::TruncatingWord32());
        SetOutput<T>(node, MachineRepresentation::kWord32);
        return;
      }

      case IrOpcode::kCheckBounds:
        return VisitCheckBounds<T>(node, lowering);

      case IrOpcode::kLoadField:
      case IrOpcode::kLoadElement: {
        LoadRepresentation representation =
            LoadRepresentationOf(node->op()).representation();
        return VisitLoad<T>(node, representation);
      }
      case IrOpcode::kStoreField:
      case IrOpcode::kStoreElement: {
        StoreRepresentation representation =
            StoreRepresentationOf(node->op()).representation();
        return VisitStore<T>(node, representation);
      }

      case IrOpcode::kObjectIsSmi:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);
      case IrOpcode::kObjectIsNumber:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);
      case IrOpcode::kObjectIsReceiver:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);
      case IrOpcode::kObjectIsString:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);
      case IrOpcode::kObjectIsBoolean:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);
      case IrOpcode::kObjectIsUndetectable:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);
      case IrOpcode::kObjectIsBigInt:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);
      case IrOpcode::kSameValue:
        return VisitBinop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);

      case IrOpcode::kReferenceEqual:
        return VisitBinop<T>(node, UseInfo::Any(), MachineRepresentation::kBit);

      case IrOpcode::kNumberToBoolean:
        return VisitUnop<T>(node, UseInfo::Number(),
                            MachineRepresentation::kBit);
      case IrOpcode::kStringToBoolean:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);
      case IrOpcode::kSymbolToBoolean:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);
      case IrOpcode::kBigIntToBoolean:
        return VisitUnop<T>(node, UseInfo::TaggedPointer(),
                            MachineRepresentation::kBit);

      case IrOpcode::kPlainPrimitiveToNumber:
        return VisitUnop<T>(node, UseInfo::PlainPrimitive(),
                            MachineRepresentation::kFloat64);
      case IrOpcode::kPlainPrimitiveToWord32:
        return VisitUnop<T>(node, UseInfo::PlainPrimitive(),
                            MachineRepresentation::kWord32);

      case IrOpcode::kChangeTaggedSignedToInt32:
        return VisitUnop<T>(node, UseInfo::TaggedSigned(),
                            MachineRepresentation::kWord32);
      case IrOpcode::kChangeTaggedToInt32:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kWord32);
      case IrOpcode::kChangeTaggedToUint32:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kWord32);
      case IrOpcode::kChangeTaggedToFloat64:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kFloat64);
      case IrOpcode::kChangeTaggedToBit:
        return VisitUnop<T>(node, UseInfo::Tagged(), MachineRepresentation::kBit);
      case IrOpcode::kChangeTaggedToTaggedSigned:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kTaggedSigned);
      case IrOpcode::kChangeInt32ToTaggedSigned:
        return VisitUnop<T>(node, UseInfo::Word32(),
                            MachineRepresentation::kTaggedSigned);
      case IrOpcode::kChangeUint32ToTaggedSigned:
        return VisitUnop<T>(node, UseInfo::Word32(),
                            MachineRepresentation::kTaggedSigned);
      case IrOpcode::kChangeFloat64ToTagged:
        return VisitUnop<T>(node, UseInfo::Float64(),
                            MachineRepresentation::kTagged);
      case IrOpcode::kChangeBigIntToTagged:
        return VisitUnop<T>(node, UseInfo::TaggedPointer(),
                            MachineRepresentation::kTagged);
      case IrOpcode::kChangeBoolToBit:
        return VisitUnop<T>(node, UseInfo::Bool(), MachineRepresentation::kBit);
      case IrOpcode::kChangeBitToBool:
        return VisitUnop<T>(node, UseInfo::Bit(),
                            MachineRepresentation::kTagged);
      case IrOpcode::kChangeInt32ToFloat64:
        return VisitUnop<T>(node, UseInfo::Word32(),
                            MachineRepresentation::kFloat64);
      case IrOpcode::kChangeUint32ToFloat64:
        return VisitUnop<T>(node, UseInfo::Word32(),
                            MachineRepresentation::kFloat64);
      case IrOpcode::kChangeFloat64ToInt32:
        return VisitUnop<T>(node, UseInfo::Float64(),
                            MachineRepresentation::kWord32);
      case IrOpcode::kChangeFloat64ToUint32:
        return VisitUnop<T>(node, UseInfo::Float64(),
                            MachineRepresentation::kWord32);
      case IrOpcode::kTruncateFloat64ToInt32:
        return VisitUnop<T>(node, UseInfo::Float64(),
                            MachineRepresentation::kWord32);
      case IrOpcode::kTruncateFloat64ToUint32:
        return VisitUnop<T>(node, UseInfo::Float64(),
                            MachineRepresentation::kWord32);
      case IrOpcode::kBitcastFloat64ToInt64:
        return VisitUnop<T>(node, UseInfo::Float64(),
                            MachineRepresentation::kWord64);
      case IrOpcode::kBitcastInt64ToFloat64:
        return VisitUnop<T>(node, UseInfo::Int64(),
                            MachineRepresentation::kFloat64);
      case IrOpcode::kBitcastTaggedToWord:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineType::PointerRepresentation());
      case IrOpcode::kBitcastWordToTagged:
        return VisitUnop<T>(node, UseInfo::Word(),
                            MachineRepresentation::kTagged);
      case IrOpcode::kSignExtendInt32ToInt64:
        return VisitUnop<T>(node, UseInfo::Word32(),
                            MachineRepresentation::kWord64);
      case IrOpcode::kSignExtendWord32ToInt64:
        return VisitUnop<T>(node, UseInfo::Word32(),
                            MachineRepresentation::kWord64);
      case IrOpcode::kUnsignedൂWord32ToWord64:
        return VisitUnop<T>(node, UseInfo::Word32(),
                            MachineRepresentation::kWord64);
      case IrOpcode::kNumberToInt32:
        return VisitUnop<T>(node, UseInfo::NumberOrOddball(),
                            MachineRepresentation::kWord32);
      case IrOpcode::kNumberToUint32:
        return VisitUnop<T>(node, UseInfo::NumberOrOddball(),
                            MachineRepresentation::kWord32);
      case IrOpcode::kNumberToUint8Clamped:
        return VisitUnop<T>(node, UseInfo::NumberOrOddball(),
                            MachineRepresentation::kWord32);
      case IrOpcode::kToIndexString:
        return VisitUnop<T>(node, UseInfo::Unsigned32(),
                            MachineRepresentation::kTagged);
      case IrOpcode::kAllocate:
        return VisitLeaf<T>(node, MachineRepresentation::kTagged);
      case IrOpcode::kArrayBufferViewHasBuffer:
        return VisitUnop<T>(node, UseInfo::Tagged(),
                            MachineRepresentation::kBit);
      case IrOpcode::kGetHoleNaNAndConvertToTag:
        return VisitLeaf<T>(node, MachineRepresentation::kTagged);
      case IrOpcode::kட்டார்BigIntAdd:
      case IrOpcode::kBigIntSubtract:
      case IrOpcode::kBigIntMultiply:
      case IrOpcode::kBigIntDivide:
      case IrOpcode::kBigIntModulus:
        return VisitBinop<T>(node, UseInfo::TaggedPointer(),
                            MachineRepresentation::kTaggedPointer);
      case IrOpcode::kBigIntBitwiseAnd:
      case IrOpcode::kBigIntBitwiseOr:
      case IrOpcode::kBigIntBitwiseXor:
        return VisitBinop<T>(node, UseInfo::TaggedPointer(),
                            MachineRepresentation::kTaggedPointer);
      case IrOpcode::kBigIntShiftLeft:
      case IrOpcode::kBigIntShiftRight:
        return VisitBinop<T>(node, UseInfo::TaggedPointer(), UseInfo::Any(),
                            MachineRepresentation::kTaggedPointer);
      case IrOpcode::kBigIntNegate:
        return VisitUnop<T>(node, UseInfo::TaggedPointer(),
                            MachineRepresentation::kTaggedPointer);
      case IrOpcode::kBigIntToNumber:
        return VisitUnop<T>(node, UseInfo::TaggedPointer(),
                            MachineRepresentation::kTagged);
      case IrOpcode::kBigIntEqual:
      case IrOpcode::kBigIntLessThan:
      case IrOpcode::kBigIntLessThanOrEqual:
        return VisitBinop<T>(node, UseInfo::TaggedPointer(),
                            MachineRepresentation::kBit);
      case IrOpcode::kSpeculativeBigIntAdd:
      case IrOpcode::kSpeculativeBigIntSubtract:
      case IrOpcode::kSpeculativeBigIntMultiply:
      case IrOpcode::kSpeculativeBigIntBitwiseAnd:
      case IrOpcode::kSpeculativeBigIntBitwiseOr:
      case IrOpcode::kSpeculativeBigIntBitwiseXor:
      case IrOpcode::kSpeculativeBigIntNegate:
        return VisitBinop<T>(node, UseInfo::CheckedBigIntAsTaggedPointer(),
                            MachineRepresentation::kTaggedPointer);
      case IrOpcode::kSpeculativeBigIntEqual:
      case IrOpcode::kSpeculativeBigIntLessThan:
      case IrOpcode::kSpeculativeBigIntLessThanOrEqual:
        return VisitBinop<T>(node, UseInfo::CheckedBigIntAsTaggedPointer(),
                            MachineRepresentation::kBit);
      case IrOpcode::kSpeculativeBigIntShiftLeft:
      case IrOpcode::kSpeculativeBigIntShiftRight:
        if (TryOptimizeBigInt64Shift<T>(node, truncation, lowering)) return;
        return VisitBinop<T>(node, UseInfo::CheckedBigIntAsTaggedPointer(),
                            UseInfo::Any(),
                            MachineRepresentation::kTaggedPointer);
      case IrOpcode::kSpeculativeBigIntDivide:
      case IrOpcode::kSpeculativeBigIntModulus:
        return VisitBinop<T>(node, UseInfo::CheckedBigIntAsTaggedPointer(),
                            MachineRepresentation::kTaggedPointer);

      case IrOpcode::kFastApiCall:
        return VisitFastApiCall<T>(node, lowering);

#if V8_ENABLE_WEBASSEMBLY
      case IrOpcode::kJSWasmCall:
        return VisitJSWasmCall<T>(node, lowering);
#endif  // V8_ENABLE_WEBASSEMBLY

      //------------------------------------------------------------------
      // Effect control operators.
      //------------------------------------------------------------------
      case IrOpcode::kIfSuccess:
      case IrOpcode::kIfException:
        return VisitUnop<T>(node, UseInfo::Any(),
                            MachineRepresentation::kTagged);  // JSValue
      case IrOpcode::kMerge:
      case IrOpcode::kLoop:
      case IrOpcode::kDeoptimizeIf:
      case IrOpcode::kDeoptimizeUnless:
      case IrOpcode::k আগে:
      case IrOpcode::kThrow:
      case IrOpcode::k কাউন্সিল:
      case IrOpcode::kReturn:
      case IrOpcode::kTailCall:
      case IrOpcode::kUnreachable:
      case IrOpcode::kังหวัด:
        return VisitInputs<T>(node);
      case IrOpcode::k মারাযান:
        return;
    }
    UNREACHABLE();
  }
};

template <Phase T>
void Visit(Node* node, SimplifiedLowering* lowering) {
  DCHECK(phase_mask() & PhaseToMask(T::value));
  Visitor<T>(lowering->graph(), lowering->common(), lowering->zone(),
             lowering->type_cache(), lowering->isolate(),
             lowering->jsgraph_->GetVerifier(), lowering->linkage(),
             lowering->tick_counter())
      .Visit(node, lowering);
}

void Run(Node* node, SimplifiedLowering* lowering) {
  if (phase_mask() & PhaseToMask(Phase::kPropagate)) {
    Visit<Phase::kPropagate>(node, lowering);
  }
  if (phase_mask() & PhaseToMask(Phase::kRetype)) {
    Visit<Phase::kRetype>(node, lowering);
  }
  if (phase_mask() & PhaseToMask(Phase::kLower)) {
    Visit<Phase::kLower>(node, lowering);
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```

这是目录为 `v8/src/compiler/simplified-lowering.cc` 的一个 c++ 源代码文件的第 2 部分，共 4 部分。

**功能归纳:**

这部分代码主要负责处理 V8 引擎中 Simplified DSL (Domain Specific Language) 节点的降低 (lowering) 过程，将其转换为更底层的、更接近机器码的操作。 它的核心功能是为各种 JavaScript 操作 (特别是数学运算、类型转换和一些特定的内置函数调用) 选择合适的底层机器指令或操作。

**主要功能点:**

1. **处理模运算 (`NumberModulus`, `SpeculativeNumberModulus`):**
   - 根据输入类型 (有符号、无符号 32 位整数，或者浮点数) 和结果的使用方式 (是否需要截断为 32 位) 选择不同的模运算指令 (`Uint32Mod`, `Int32Mod`, `Float64Mod`)。
   - 利用类型反馈信息 (`NumberOperationHint`) 进行优化，例如，如果类型反馈表明操作数是小整数，则可能使用更高效的整数模运算。

2. **处理边界检查 (`CheckBounds`):**
   - 根据索引和长度的类型以及标志位，选择合适的边界检查指令 (`CheckedUint32Bounds`, `CheckedUint64Bounds`)。
   - 考虑将字符串和负零转换为数字的情况。
   - 在某些情况下，如果可以静态地确定索引在界内，则可以消除边界检查。

3. **处理快速 API 调用 (`FastApiCall`):**
   - 为快速 C++ API 调用生成必要的类型转换和调用约定。
   - 根据 C++ 函数的签名信息 (`CTypeInfo`) 确定参数的 `UseInfo`，用于后续的类型转换和表示选择。

4. **优化 BigInt 的位移操作 (`TryOptimizeBigInt64Shift`):**
   - 尝试优化 64 位 BigInt 的位移操作，特别是当位移量是常量时，可以直接替换为相应的机器码指令 (`Word64Shl`, `Word64Sar`, `Word64Shr`)。

5. **处理 WebAssembly 调用 (`JSWasmCall` - 仅在 `V8_ENABLE_WEBASSEMBLY` 宏定义启用时):**
   - 为 JavaScript 调用 WebAssembly 函数生成必要的类型转换和调用约定。
   - 根据 WebAssembly 函数的签名信息确定参数的 `UseInfo`。

6. **通用的节点访问和降低机制 (`VisitNode`, `Visitor`):**
   - 提供一个通用的框架来访问和处理不同的 Simplified DSL 节点。
   - 根据节点的操作码和预期的使用方式 (`Truncation`)，为输入节点指定 `UseInfo`，用于后续的类型转换和表示选择。
   - 对于纯函数节点，如果其结果未使用，则可以将其标记为未使用。

**与 JavaScript 的关系及示例:**

这段代码直接影响 JavaScript 代码的性能。V8 引擎会分析 JavaScript 代码，将其转换为 Simplified DSL 中间表示，然后通过 `simplified-lowering.cc` 中的代码将这些中间表示转换为更底层的机器指令。

**JavaScript 示例 (模运算):**

```javascript
function moduloExample(a, b) {
  return a % b;
}

// 场景 1: 两个小的整数
moduloExample(5, 2); // 在类型反馈的帮助下，可能被优化为高效的整数模运算

// 场景 2: 大整数或浮点数
moduloExample(10000000000, 3); // 可能使用浮点数模运算
moduloExample(5.5, 2.1);     // 肯定使用浮点数模运算

// 场景 3: 已知是无符号整数
function unsignedModulo(a, b) {
  // V8 可能会推断出 a 和 b 是无符号整数
  return a >>> 0 % b >>> 0;
}
unsignedModulo(10, 3); // 可能会使用 Uint32Mod
```

**JavaScript 示例 (边界检查):**

```javascript
function accessArray(arr, index) {
  return arr[index];
}

const myArray = [1, 2, 3];
accessArray(myArray, 1); // 需要进行边界检查，确保 index 在有效范围内
accessArray(myArray, 5); // 抛出错误，边界检查会发现越界
```

**总结:**

这部分 `simplified-lowering.cc` 的代码是 V8 引擎中至关重要的一部分，它负责将高级的 JavaScript 操作转换为底层的机器指令，并且通过类型反馈和静态分析进行优化，从而提高 JavaScript 代码的执行效率。它针对不同的数据类型和操作场景选择最合适的机器指令，是 V8 引擎性能优化的核心组成部分。

### 提示词
```
这是目录为v8/src/compiler/simplified-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
          VisitInputs<T>(node);
          SetOutput<T>(node, MachineRepresentation::kTaggedPointer);
        }
        return;
      }
      case IrOpcode::kBooleanNot: {
        if (lower<T>()) {
          NodeInfo* input_info = GetInfo(node->InputAt(0));
          if (input_info->representation() == MachineRepresentation::kBit) {
            // BooleanNot(x: kRepBit) => Word32Equal(x, #0)
            node->AppendInput(jsgraph_->zone(), jsgraph_->Int32Constant(0));
            ChangeOp(node, lowering->machine()->Word32Equal());
          } else if (CanBeTaggedPointer(input_info->representation())) {
            // BooleanNot(x: kRepTagged) => TaggedEqual(x, #false)
            node->AppendInput(jsgraph_->zone(), jsgraph_->FalseConstant());
            ChangeOp(node, lowering->machine()->TaggedEqual());
          } else {
            DCHECK(TypeOf(node->InputAt(0)).IsNone());
            DeferReplacement(node, lowering->jsgraph()->Int32Constant(0));
          }
        } else {
          // No input representation requirement; adapt during lowering.
          ProcessInput<T>(node, 0, UseInfo::AnyTruncatingToBool());
          SetOutput<T>(node, MachineRepresentation::kBit);
        }
        return;
      }
      case IrOpcode::kNumberEqual: {
        Type const lhs_type = TypeOf(node->InputAt(0));
        Type const rhs_type = TypeOf(node->InputAt(1));
        // Regular number comparisons in JavaScript generally identify zeros,
        // so we always pass kIdentifyZeros for the inputs, and in addition
        // we can truncate -0 to 0 for otherwise Unsigned32 or Signed32 inputs.
        // For equality we also handle the case that one side is non-zero, in
        // which case we allow to truncate NaN to 0 on the other side.
        if ((lhs_type.Is(Type::Unsigned32OrMinusZero()) &&
             rhs_type.Is(Type::Unsigned32OrMinusZero())) ||
            (lhs_type.Is(Type::Unsigned32OrMinusZeroOrNaN()) &&
             rhs_type.Is(Type::Unsigned32OrMinusZeroOrNaN()) &&
             OneInputCannotBe(node, type_cache_->kZeroish))) {
          // => unsigned Int32Cmp
          VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                        MachineRepresentation::kBit);
          if (lower<T>()) ChangeOp(node, Uint32Op(node));
          return;
        }
        if ((lhs_type.Is(Type::Signed32OrMinusZero()) &&
             rhs_type.Is(Type::Signed32OrMinusZero())) ||
            (lhs_type.Is(Type::Signed32OrMinusZeroOrNaN()) &&
             rhs_type.Is(Type::Signed32OrMinusZeroOrNaN()) &&
             OneInputCannotBe(node, type_cache_->kZeroish))) {
          // => signed Int32Cmp
          VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                        MachineRepresentation::kBit);
          if (lower<T>()) ChangeOp(node, Int32Op(node));
          return;
        }
        if (lhs_type.Is(Type::Boolean()) && rhs_type.Is(Type::Boolean())) {
          VisitBinop<T>(node, UseInfo::Bool(), MachineRepresentation::kBit);
          if (lower<T>()) ChangeOp(node, lowering->machine()->Word32Equal());
          return;
        }
        // => Float64Cmp
        VisitBinop<T>(node, UseInfo::TruncatingFloat64(kIdentifyZeros),
                      MachineRepresentation::kBit);
        if (lower<T>()) ChangeOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kNumberLessThan:
      case IrOpcode::kNumberLessThanOrEqual: {
        Type const lhs_type = TypeOf(node->InputAt(0));
        Type const rhs_type = TypeOf(node->InputAt(1));
        // Regular number comparisons in JavaScript generally identify zeros,
        // so we always pass kIdentifyZeros for the inputs, and in addition
        // we can truncate -0 to 0 for otherwise Unsigned32 or Signed32 inputs.
        if (lhs_type.Is(Type::Unsigned32OrMinusZero()) &&
            rhs_type.Is(Type::Unsigned32OrMinusZero())) {
          // => unsigned Int32Cmp
          VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                        MachineRepresentation::kBit);
          if (lower<T>()) ChangeOp(node, Uint32Op(node));
        } else if (lhs_type.Is(Type::Signed32OrMinusZero()) &&
                   rhs_type.Is(Type::Signed32OrMinusZero())) {
          // => signed Int32Cmp
          VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                        MachineRepresentation::kBit);
          if (lower<T>()) ChangeOp(node, Int32Op(node));
        } else {
          // => Float64Cmp
          VisitBinop<T>(node, UseInfo::TruncatingFloat64(kIdentifyZeros),
                        MachineRepresentation::kBit);
          if (lower<T>()) ChangeOp(node, Float64Op(node));
        }
        return;
      }

      case IrOpcode::kSpeculativeSafeIntegerAdd:
      case IrOpcode::kSpeculativeSafeIntegerSubtract:
        return VisitSpeculativeIntegerAdditiveOp<T>(node, truncation, lowering);

      case IrOpcode::kSpeculativeNumberAdd:
      case IrOpcode::kSpeculativeNumberSubtract:
        return VisitSpeculativeAdditiveOp<T>(node, truncation, lowering);

      case IrOpcode::kSpeculativeNumberLessThan:
      case IrOpcode::kSpeculativeNumberLessThanOrEqual:
      case IrOpcode::kSpeculativeNumberEqual: {
        Type const lhs_type = TypeOf(node->InputAt(0));
        Type const rhs_type = TypeOf(node->InputAt(1));
        // Regular number comparisons in JavaScript generally identify zeros,
        // so we always pass kIdentifyZeros for the inputs, and in addition
        // we can truncate -0 to 0 for otherwise Unsigned32 or Signed32 inputs.
        if (lhs_type.Is(Type::Unsigned32OrMinusZero()) &&
            rhs_type.Is(Type::Unsigned32OrMinusZero())) {
          // => unsigned Int32Cmp
          VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                        MachineRepresentation::kBit);
          if (lower<T>()) ChangeToPureOp(node, Uint32Op(node));
          return;
        } else if (lhs_type.Is(Type::Signed32OrMinusZero()) &&
                   rhs_type.Is(Type::Signed32OrMinusZero())) {
          // => signed Int32Cmp
          VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                        MachineRepresentation::kBit);
          if (lower<T>()) ChangeToPureOp(node, Int32Op(node));
          return;
        } else if (lhs_type.Is(Type::Boolean()) &&
                   rhs_type.Is(Type::Boolean())) {
          VisitBinop<T>(node, UseInfo::Bool(), MachineRepresentation::kBit);
          if (lower<T>())
            ChangeToPureOp(node, lowering->machine()->Word32Equal());
          return;
        }
        // Try to use type feedback.
        NumberOperationHint hint = NumberOperationHintOf(node->op());
        switch (hint) {
          case NumberOperationHint::kSignedSmall:
            if (propagate<T>()) {
              VisitBinop<T>(
                  node, CheckedUseInfoAsWord32FromHint(hint, kIdentifyZeros),
                  MachineRepresentation::kBit);
            } else if (retype<T>()) {
              SetOutput<T>(node, MachineRepresentation::kBit, Type::Any());
            } else {
              DCHECK(lower<T>());
              Node* lhs = node->InputAt(0);
              Node* rhs = node->InputAt(1);
              if (IsNodeRepresentationTagged(lhs) &&
                  IsNodeRepresentationTagged(rhs)) {
                VisitBinop<T>(node,
                              UseInfo::CheckedSignedSmallAsTaggedSigned(
                                  FeedbackSource(), kIdentifyZeros),
                              MachineRepresentation::kBit);
                ChangeToPureOp(
                    node, changer_->TaggedSignedOperatorFor(node->opcode()));

              } else {
                VisitBinop<T>(
                    node, CheckedUseInfoAsWord32FromHint(hint, kIdentifyZeros),
                    MachineRepresentation::kBit);
                ChangeToPureOp(node, Int32Op(node));
              }
            }
            return;
          case NumberOperationHint::kSignedSmallInputs:
            // This doesn't make sense for compare operations.
            UNREACHABLE();
          case NumberOperationHint::kNumberOrOddball:
            // Abstract and strict equality don't perform ToNumber conversions
            // on Oddballs, so make sure we don't accidentially sneak in a
            // hint with Oddball feedback here.
            DCHECK_NE(IrOpcode::kSpeculativeNumberEqual, node->opcode());
            [[fallthrough]];
          case NumberOperationHint::kNumberOrBoolean:
          case NumberOperationHint::kNumber:
            VisitBinop<T>(node,
                          CheckedUseInfoAsFloat64FromHint(
                              hint, FeedbackSource(), kIdentifyZeros),
                          MachineRepresentation::kBit);
            if (lower<T>()) ChangeToPureOp(node, Float64Op(node));
            return;
        }
        UNREACHABLE();
        return;
      }

      case IrOpcode::kNumberAdd:
      case IrOpcode::kNumberSubtract: {
        if (TypeOf(node->InputAt(0))
                .Is(type_cache_->kAdditiveSafeIntegerOrMinusZero) &&
            TypeOf(node->InputAt(1))
                .Is(type_cache_->kAdditiveSafeIntegerOrMinusZero) &&
            (TypeOf(node).Is(Type::Signed32()) ||
             TypeOf(node).Is(Type::Unsigned32()) ||
             truncation.IsUsedAsWord32())) {
          // => Int32Add/Sub
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) ChangeToPureOp(node, Int32Op(node));
        } else if (jsgraph_->machine()->Is64() &&
                   BothInputsAre(node, type_cache_->kSafeInteger) &&
                   GetUpperBound(node).Is(type_cache_->kSafeInteger)) {
          // => Int64Add/Sub
          VisitInt64Binop<T>(node);
          if (lower<T>()) ChangeToPureOp(node, Int64Op(node));
        } else {
          // => Float64Add/Sub
          VisitFloat64Binop<T>(node);
          if (lower<T>()) ChangeToPureOp(node, Float64Op(node));
        }
        return;
      }
      case IrOpcode::kSpeculativeNumberMultiply: {
        if (BothInputsAre(node, Type::Integral32()) &&
            (NodeProperties::GetType(node).Is(Type::Signed32()) ||
             NodeProperties::GetType(node).Is(Type::Unsigned32()) ||
             (truncation.IsUsedAsWord32() &&
              NodeProperties::GetType(node).Is(
                  type_cache_->kSafeIntegerOrMinusZero)))) {
          // Multiply reduces to Int32Mul if the inputs are integers, and
          // (a) the output is either known to be Signed32, or
          // (b) the output is known to be Unsigned32, or
          // (c) the uses are truncating and the result is in the safe
          //     integer range.
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) ChangeToPureOp(node, Int32Op(node));
          return;
        }
        // Try to use type feedback.
        NumberOperationHint hint = NumberOperationHintOf(node->op());
        Type input0_type = TypeOf(node->InputAt(0));
        Type input1_type = TypeOf(node->InputAt(1));

        // Handle the case when no int32 checks on inputs are necessary
        // (but an overflow check is needed on the output).
        if (BothInputsAre(node, Type::Signed32())) {
          // If both inputs and feedback are int32, use the overflow op.
          if (hint == NumberOperationHint::kSignedSmall) {
            VisitForCheckedInt32Mul<T>(node, truncation, input0_type,
                                       input1_type,
                                       UseInfo::TruncatingWord32());
            return;
          }
        }

        if (hint == NumberOperationHint::kSignedSmall) {
          VisitForCheckedInt32Mul<T>(node, truncation, input0_type, input1_type,
                                     CheckedUseInfoAsWord32FromHint(hint));
          return;
        }

        // Checked float64 x float64 => float64
        VisitBinop<T>(node,
                      UseInfo::CheckedNumberOrOddballAsFloat64(
                          kDistinguishZeros, FeedbackSource()),
                      MachineRepresentation::kFloat64, Type::Number());
        if (lower<T>()) ChangeToPureOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kNumberMultiply: {
        if (TypeOf(node->InputAt(0)).Is(Type::Integral32()) &&
            TypeOf(node->InputAt(1)).Is(Type::Integral32()) &&
            (TypeOf(node).Is(Type::Signed32()) ||
             TypeOf(node).Is(Type::Unsigned32()) ||
             (truncation.IsUsedAsWord32() &&
              TypeOf(node).Is(type_cache_->kSafeIntegerOrMinusZero)))) {
          // Multiply reduces to Int32Mul if the inputs are integers, and
          // (a) the output is either known to be Signed32, or
          // (b) the output is known to be Unsigned32, or
          // (c) the uses are truncating and the result is in the safe
          //     integer range.
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) ChangeToPureOp(node, Int32Op(node));
          return;
        }
        // Number x Number => Float64Mul
        VisitFloat64Binop<T>(node);
        if (lower<T>()) ChangeToPureOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kSpeculativeNumberDivide: {
        if (BothInputsAreUnsigned32(node) && truncation.IsUsedAsWord32()) {
          // => unsigned Uint32Div
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) DeferReplacement(node, lowering->Uint32Div(node));
          return;
        }
        if (BothInputsAreSigned32(node)) {
          if (NodeProperties::GetType(node).Is(Type::Signed32())) {
            // => signed Int32Div
            VisitWord32TruncatingBinop<T>(node);
            if (lower<T>()) DeferReplacement(node, lowering->Int32Div(node));
            return;
          }
          if (truncation.IsUsedAsWord32()) {
            // => signed Int32Div
            VisitWord32TruncatingBinop<T>(node);
            if (lower<T>()) DeferReplacement(node, lowering->Int32Div(node));
            return;
          }
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
        if (BothInputsAreSigned32(node)) {
          // If both the inputs the feedback are int32, use the overflow op.
          if (hint == NumberOperationHint::kSignedSmall) {
            VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                          MachineRepresentation::kWord32, Type::Signed32());
            if (lower<T>()) ChangeToInt32OverflowOp(node);
            return;
          }
        }

        if (hint == NumberOperationHint::kSignedSmall ||
            hint == NumberOperationHint::kSignedSmallInputs) {
          // If the result is truncated, we only need to check the inputs.
          if (truncation.IsUsedAsWord32()) {
            VisitBinop<T>(node, CheckedUseInfoAsWord32FromHint(hint),
                          MachineRepresentation::kWord32);
            if (lower<T>()) DeferReplacement(node, lowering->Int32Div(node));
            return;
          } else if (hint != NumberOperationHint::kSignedSmallInputs) {
            VisitBinop<T>(node, CheckedUseInfoAsWord32FromHint(hint),
                          MachineRepresentation::kWord32, Type::Signed32());
            if (lower<T>()) ChangeToInt32OverflowOp(node);
            return;
          }
        }

        // default case => Float64Div
        VisitBinop<T>(node,
                      UseInfo::CheckedNumberOrOddballAsFloat64(
                          kDistinguishZeros, FeedbackSource()),
                      MachineRepresentation::kFloat64, Type::Number());
        if (lower<T>()) ChangeToPureOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kNumberDivide: {
        if (TypeOf(node->InputAt(0)).Is(Type::Unsigned32()) &&
            TypeOf(node->InputAt(1)).Is(Type::Unsigned32()) &&
            (truncation.IsUsedAsWord32() ||
             TypeOf(node).Is(Type::Unsigned32()))) {
          // => unsigned Uint32Div
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) DeferReplacement(node, lowering->Uint32Div(node));
          return;
        }
        if (TypeOf(node->InputAt(0)).Is(Type::Signed32()) &&
            TypeOf(node->InputAt(1)).Is(Type::Signed32()) &&
            (truncation.IsUsedAsWord32() ||
             TypeOf(node).Is(Type::Signed32()))) {
          // => signed Int32Div
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) DeferReplacement(node, lowering->Int32Div(node));
          return;
        }
        // Number x Number => Float64Div
        VisitFloat64Binop<T>(node);
        if (lower<T>()) ChangeToPureOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kUnsigned32Divide: {
        CHECK(TypeOf(node->InputAt(0)).Is(Type::Unsigned32()));
        CHECK(TypeOf(node->InputAt(1)).Is(Type::Unsigned32()));
        // => unsigned Uint32Div
        VisitWord32TruncatingBinop<T>(node);
        if (lower<T>()) DeferReplacement(node, lowering->Uint32Div(node));
        return;
      }
      case IrOpcode::kSpeculativeNumberModulus:
        return VisitSpeculativeNumberModulus<T>(node, truncation, lowering);
      case IrOpcode::kNumberModulus: {
        Type const lhs_type = TypeOf(node->InputAt(0));
        Type const rhs_type = TypeOf(node->InputAt(1));
        if ((lhs_type.Is(Type::Unsigned32OrMinusZeroOrNaN()) &&
             rhs_type.Is(Type::Unsigned32OrMinusZeroOrNaN())) &&
            (truncation.IsUsedAsWord32() ||
             TypeOf(node).Is(Type::Unsigned32()))) {
          // => unsigned Uint32Mod
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) DeferReplacement(node, lowering->Uint32Mod(node));
          return;
        }
        if ((lhs_type.Is(Type::Signed32OrMinusZeroOrNaN()) &&
             rhs_type.Is(Type::Signed32OrMinusZeroOrNaN())) &&
            (truncation.IsUsedAsWord32() || TypeOf(node).Is(Type::Signed32()) ||
             (truncation.IdentifiesZeroAndMinusZero() &&
              TypeOf(node).Is(Type::Signed32OrMinusZero())))) {
          // => signed Int32Mod
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) DeferReplacement(node, lowering->Int32Mod(node));
          return;
        }
        // => Float64Mod
        // For the left hand side we just propagate the identify zeros
        // mode of the {truncation}; and for modulus the sign of the
        // right hand side doesn't matter anyways, so in particular there's
        // no observable difference between a 0 and a -0 then.
        UseInfo const lhs_use =
            UseInfo::TruncatingFloat64(truncation.identify_zeros());
        UseInfo const rhs_use = UseInfo::TruncatingFloat64(kIdentifyZeros);
        VisitBinop<T>(node, lhs_use, rhs_use, MachineRepresentation::kFloat64);
        if (lower<T>()) ChangeToPureOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kNumberBitwiseOr:
      case IrOpcode::kNumberBitwiseXor:
      case IrOpcode::kNumberBitwiseAnd: {
        VisitWord32TruncatingBinop<T>(node);
        if (lower<T>()) ChangeOp(node, Int32Op(node));
        return;
      }
      case IrOpcode::kSpeculativeNumberBitwiseOr:
      case IrOpcode::kSpeculativeNumberBitwiseXor:
      case IrOpcode::kSpeculativeNumberBitwiseAnd:
        VisitSpeculativeInt32Binop<T>(node);
        if (lower<T>()) {
          ChangeToPureOp(node, Int32Op(node));
        }
        return;
      case IrOpcode::kNumberShiftLeft: {
        Type rhs_type = GetUpperBound(node->InputAt(1));
        VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                      UseInfo::TruncatingWord32(),
                      MachineRepresentation::kWord32);
        if (lower<T>()) {
          MaskShiftOperand(node, rhs_type);
          ChangeToPureOp(node, lowering->machine()->Word32Shl());
        }
        return;
      }
      case IrOpcode::kSpeculativeNumberShiftLeft: {
        if (BothInputsAre(node, Type::NumberOrOddball())) {
          Type rhs_type = GetUpperBound(node->InputAt(1));
          VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                        UseInfo::TruncatingWord32(),
                        MachineRepresentation::kWord32);
          if (lower<T>()) {
            MaskShiftOperand(node, rhs_type);
            ChangeToPureOp(node, lowering->machine()->Word32Shl());
          }
          return;
        }
        NumberOperationHint hint = NumberOperationHintOf(node->op());
        Type rhs_type = GetUpperBound(node->InputAt(1));
        VisitBinop<T>(node,
                      CheckedUseInfoAsWord32FromHint(hint, kIdentifyZeros),
                      MachineRepresentation::kWord32, Type::Signed32());
        if (lower<T>()) {
          MaskShiftOperand(node, rhs_type);
          ChangeToPureOp(node, lowering->machine()->Word32Shl());
        }
        return;
      }
      case IrOpcode::kNumberShiftRight: {
        Type rhs_type = GetUpperBound(node->InputAt(1));
        VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                      UseInfo::TruncatingWord32(),
                      MachineRepresentation::kWord32);
        if (lower<T>()) {
          MaskShiftOperand(node, rhs_type);
          ChangeToPureOp(node, lowering->machine()->Word32Sar());
        }
        return;
      }
      case IrOpcode::kSpeculativeNumberShiftRight: {
        if (BothInputsAre(node, Type::NumberOrOddball())) {
          Type rhs_type = GetUpperBound(node->InputAt(1));
          VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                        UseInfo::TruncatingWord32(),
                        MachineRepresentation::kWord32);
          if (lower<T>()) {
            MaskShiftOperand(node, rhs_type);
            ChangeToPureOp(node, lowering->machine()->Word32Sar());
          }
          return;
        }
        NumberOperationHint hint = NumberOperationHintOf(node->op());
        Type rhs_type = GetUpperBound(node->InputAt(1));
        VisitBinop<T>(node,
                      CheckedUseInfoAsWord32FromHint(hint, kIdentifyZeros),
                      MachineRepresentation::kWord32, Type::Signed32());
        if (lower<T>()) {
          MaskShiftOperand(node, rhs_type);
          ChangeToPureOp(node, lowering->machine()->Word32Sar());
        }
        return;
      }
      case IrOpcode::kNumberShiftRightLogical: {
        Type rhs_type = GetUpperBound(node->InputAt(1));
        VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                      UseInfo::TruncatingWord32(),
                      MachineRepresentation::kWord32);
        if (lower<T>()) {
          MaskShiftOperand(node, rhs_type);
          ChangeToPureOp(node, lowering->machine()->Word32Shr());
        }
        return;
      }
      case IrOpcode::kSpeculativeNumberShiftRightLogical: {
        NumberOperationHint hint = NumberOperationHintOf(node->op());
        Type rhs_type = GetUpperBound(node->InputAt(1));
        if (rhs_type.Is(type_cache_->kZeroish) &&
            hint == NumberOperationHint::kSignedSmall &&
            !truncation.IsUsedAsWord32()) {
          // The SignedSmall or Signed32 feedback means that the results that we
          // have seen so far were of type Unsigned31.  We speculate that this
          // will continue to hold.  Moreover, since the RHS is 0, the result
          // will just be the (converted) LHS.
          VisitBinop<T>(node,
                        CheckedUseInfoAsWord32FromHint(hint, kIdentifyZeros),
                        MachineRepresentation::kWord32, Type::Unsigned31());
          if (lower<T>()) {
            node->RemoveInput(1);
            ChangeOp(node,
                     simplified()->CheckedUint32ToInt32(FeedbackSource()));
          }
          return;
        }
        if (BothInputsAre(node, Type::NumberOrOddball())) {
          VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                        UseInfo::TruncatingWord32(),
                        MachineRepresentation::kWord32);
          if (lower<T>()) {
            MaskShiftOperand(node, rhs_type);
            ChangeToPureOp(node, lowering->machine()->Word32Shr());
          }
          return;
        }
        VisitBinop<T>(node,
                      CheckedUseInfoAsWord32FromHint(hint, kIdentifyZeros),
                      MachineRepresentation::kWord32, Type::Unsigned32());
        if (lower<T>()) {
          MaskShiftOperand(node, rhs_type);
          ChangeToPureOp(node, lowering->machine()->Word32Shr());
        }
        return;
      }
      case IrOpcode::kNumberAbs: {
        // NumberAbs maps both 0 and -0 to 0, so we can generally
        // pass the kIdentifyZeros truncation to its input, and
        // choose to ignore minus zero in all cases.
        Type const input_type = TypeOf(node->InputAt(0));
        if (input_type.Is(Type::Unsigned32OrMinusZero())) {
          VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                       MachineRepresentation::kWord32);
          if (lower<T>()) {
            DeferReplacement(
                node,
                InsertTypeOverrideForVerifier(
                    Type::Intersect(input_type, Type::Unsigned32(), zone()),
                    node->InputAt(0)));
          }
        } else if (input_type.Is(Type::Signed32OrMinusZero())) {
          VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                       MachineRepresentation::kWord32);
          if (lower<T>()) {
            DeferReplacement(
                node,
                InsertTypeOverrideForVerifier(
                    Type::Intersect(input_type, Type::Unsigned32(), zone()),
                    lowering->Int32Abs(node)));
          }
        } else if (input_type.Is(type_cache_->kPositiveIntegerOrNaN)) {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(kIdentifyZeros),
                       MachineRepresentation::kFloat64);
          if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        } else {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(kIdentifyZeros),
                       MachineRepresentation::kFloat64);
          if (lower<T>()) ChangeOp(node, Float64Op(node));
        }
        return;
      }
      case IrOpcode::kNumberClz32: {
        VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                     MachineRepresentation::kWord32);
        if (lower<T>()) ChangeOp(node, Uint32Op(node));
        return;
      }
      case IrOpcode::kNumberImul: {
        VisitBinop<T>(node, UseInfo::TruncatingWord32(),
                      UseInfo::TruncatingWord32(),
                      MachineRepresentation::kWord32);
        if (lower<T>()) ChangeOp(node, Uint32Op(node));
        return;
      }
      case IrOpcode::kNumberFround: {
        VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                     MachineRepresentation::kFloat32);
        if (lower<T>()) ChangeOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kNumberMax: {
        // It is safe to use the feedback types for left and right hand side
        // here, since we can only narrow those types and thus we can only
        // promise a more specific truncation.
        // For NumberMax we generally propagate whether the truncation
        // identifies zeros to the inputs, and we choose to ignore minus
        // zero in those cases.
        Type const lhs_type = TypeOf(node->InputAt(0));
        Type const rhs_type = TypeOf(node->InputAt(1));
        if ((lhs_type.Is(Type::Unsigned32()) &&
             rhs_type.Is(Type::Unsigned32())) ||
            (lhs_type.Is(Type::Unsigned32OrMinusZero()) &&
             rhs_type.Is(Type::Unsigned32OrMinusZero()) &&
             truncation.IdentifiesZeroAndMinusZero())) {
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) {
            lowering->DoMax(node, lowering->machine()->Uint32LessThan(),
                            MachineRepresentation::kWord32);
          }
        } else if ((lhs_type.Is(Type::Signed32()) &&
                    rhs_type.Is(Type::Signed32())) ||
                   (lhs_type.Is(Type::Signed32OrMinusZero()) &&
                    rhs_type.Is(Type::Signed32OrMinusZero()) &&
                    truncation.IdentifiesZeroAndMinusZero())) {
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) {
            lowering->DoMax(node, lowering->machine()->Int32LessThan(),
                            MachineRepresentation::kWord32);
          }
        } else if (jsgraph_->machine()->Is64() &&
                   lhs_type.Is(type_cache_->kSafeInteger) &&
                   rhs_type.Is(type_cache_->kSafeInteger)) {
          VisitInt64Binop<T>(node);
          if (lower<T>()) {
            lowering->DoMax(node, lowering->machine()->Int64LessThan(),
                            MachineRepresentation::kWord64);
          }
        } else {
          VisitBinop<T>(node,
                        UseInfo::TruncatingFloat64(truncation.identify_zeros()),
                        MachineRepresentation::kFloat64);
          if (lower<T>()) {
            // If the right hand side is not NaN, and the left hand side
            // is not NaN (or -0 if the difference between the zeros is
            // observed), we can do a simple floating point comparison here.
            if (lhs_type.Is(truncation.IdentifiesZeroAndMinusZero()
                                ? Type::OrderedNumber()
                                : Type::PlainNumber()) &&
                rhs_type.Is(Type::OrderedNumber())) {
              lowering->DoMax(node, lowering->machine()->Float64LessThan(),
                              MachineRepresentation::kFloat64);
            } else {
              ChangeOp(node, Float64Op(node));
            }
          }
        }
        return;
      }
      case IrOpcode::kNumberMin: {
        // It is safe to use the feedback types for left and right hand side
        // here, since we can only narrow those types and thus we can only
        // promise a more specific truncation.
        // For NumberMin we generally propagate whether the truncation
        // identifies zeros to the inputs, and we choose to ignore minus
        // zero in those cases.
        Type const lhs_type = TypeOf(node->InputAt(0));
        Type const rhs_type = TypeOf(node->InputAt(1));
        if ((lhs_type.Is(Type::Unsigned32()) &&
             rhs_type.Is(Type::Unsigned32())) ||
            (lhs_type.Is(Type::Unsigned32OrMinusZero()) &&
             rhs_type.Is(Type::Unsigned32OrMinusZero()) &&
             truncation.IdentifiesZeroAndMinusZero())) {
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) {
            lowering->DoMin(node, lowering->machine()->Uint32LessThan(),
                            MachineRepresentation::kWord32);
          }
        } else if ((lhs_type.Is(Type::Signed32()) &&
                    rhs_type.Is(Type::Signed32())) ||
                   (lhs_type.Is(Type::Signed32OrMinusZero()) &&
                    rhs_type.Is(Type::Signed32OrMinusZero()) &&
                    truncation.IdentifiesZeroAndMinusZero())) {
          VisitWord32TruncatingBinop<T>(node);
          if (lower<T>()) {
            lowering->DoMin(node, lowering->machine()->Int32LessThan(),
                            MachineRepresentation::kWord32);
          }
        } else if (jsgraph_->machine()->Is64() &&
                   lhs_type.Is(type_cache_->kSafeInteger) &&
                   rhs_type.Is(type_cache_->kSafeInteger)) {
          VisitInt64Binop<T>(node);
          if (lower<T>()) {
            lowering->DoMin(node, lowering->machine()->Int64LessThan(),
                            MachineRepresentation::kWord64);
          }
        } else {
          VisitBinop<T>(node,
                        UseInfo::TruncatingFloat64(truncation.identify_zeros()),
                        MachineRepresentation::kFloat64);
          if (lower<T>()) {
            // If the left hand side is not NaN, and the right hand side
            // is not NaN (or -0 if the difference between the zeros is
            // observed), we can do a simple floating point comparison here.
            if (lhs_type.Is(Type::OrderedNumber()) &&
                rhs_type.Is(truncation.Ide
```