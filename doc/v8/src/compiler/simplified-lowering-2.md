Response: The user wants a summary of the functionality of the provided C++ code snippet from the `v8/src/compiler/simplified-lowering.cc` file. Specifically, this is part 3 of 4.

The code is a visitor pattern implementation (`VisitNode`) within the `SimplifiedLowering` pass of the V8 compiler. This pass is responsible for:

1. **Lowering high-level, abstract operations (from the "Simplified" IR) into more concrete, machine-level operations (closer to the "Machine" IR).**  This involves selecting appropriate machine instructions based on the types of the operands and the target architecture.
2. **Handling different data types and their representations.** The code snippet shows how different JavaScript types (numbers, strings, BigInts, etc.) are processed and potentially converted to lower-level representations (e.g., float64, int32, word64, tagged pointers).
3. **Inserting type checks and assertions.**  The code deals with `Check...` nodes, ensuring that operations are performed on values of the expected types.
4. **Dealing with potential implicit conversions.**  JavaScript often performs implicit type conversions, and this pass materializes those conversions into explicit nodes in the graph.
5. **Optimization opportunities.**  The code snippet shows examples where certain operations can be optimized away or replaced with more efficient equivalents based on type information.

Since this is part 3, it likely handles a specific range of Simplified IR opcodes. Looking at the cases within the `switch` statement, this part appears to focus heavily on:

- **Mathematical operations on numbers:** `SpeculativeNumberAdd`, `SpeculativeNumberSubtract`, `SpeculativeNumberMultiply`, `SpeculativeNumberDivide`, `SpeculativeNumberModulus`, `SpeculativeNumberEqual`, `SpeculativeNumberLessThan`, `SpeculativeNumberLessThanOrEqual`, `SpeculativeNumberMin`, `SpeculativeNumberPow`, `NumberAtan2`, `NumberPow`, `NumberCeil`, `NumberFloor`, `NumberRound`, `NumberTrunc`, `NumberAcos`, `NumberAcosh`, `NumberAsin`, `NumberAsinh`, `NumberAtan`, `NumberAtanh`, `NumberCos`, `NumberCosh`, `NumberExp`, `NumberExpm1`, `NumberLog`, `NumberLog1p`, `NumberLog2`, `NumberLog10`, `NumberCbrt`, `NumberSin`, `NumberSinh`, `NumberTan`, `NumberTanh`, `NumberSign`, `NumberSilenceNaN`, `NumberSqrt`, `NumberToBoolean`, `NumberToInt32`, `NumberToString`, `NumberToUint32`, `NumberToUint8Clamped`.
- **Bitwise operations and shifts on BigInts:** `SpeculativeBigIntAsIntN`, `SpeculativeBigIntAsUintN`, `SpeculativeBigIntAdd`, `SpeculativeBigIntSubtract`, `SpeculativeBigIntMultiply`, `SpeculativeBigIntDivide`, `SpeculativeBigIntModulus`, `SpeculativeBigIntBitwiseAnd`, `SpeculativeBigIntBitwiseOr`, `SpeculativeBigIntBitwiseXor`, `SpeculativeBigIntShiftLeft`, `SpeculativeBigIntShiftRight`, `SpeculativeBigIntEqual`, `SpeculativeBigIntLessThan`, `SpeculativeBigIntLessThanOrEqual`, `SpeculativeBigIntNegate`.
- **String operations:** `StringConcat`, `StringEqual`, `StringLessThan`, `StringLessThanOrEqual`, `StringCharCodeAt`, `StringCodePointAt`, `StringFromSingleCharCode`, `StringFromSingleCodePoint`, `StringFromCodePointAt`, `StringIndexOf`, `StringLength`, `StringWrapperLength`, `StringSubstring`, `StringToLowerCaseIntl`, `StringToUpperCaseIntl`.
- **Type checking and conversions:** `ReferenceEqual`, `SameValueNumbersOnly`, `SameValue`, `TypeOf`, `Integral32OrMinusZeroToBigInt`, `CheckBounds`, `CheckHeapObject`, `CheckIf`, `CheckInternalizedString`, `CheckNumber`, `CheckReceiver`, `CheckReceiverOrNullOrUndefined`, `CheckSmi`, `CheckString`, `CheckStringOrStringWrapper`, `CheckSymbol`, `PlainPrimitiveToNumber`, `SpeculativeToNumber`, `SpeculativeToBigInt`.
- **Object introspection:** `ObjectIsArrayBufferView`, `ObjectIsBigInt`, `ObjectIsCallable`, `ObjectIsConstructor`, `ObjectIsDetectableCallable`, `ObjectIsFiniteNumber`, `NumberIsFinite`, `ObjectIsSafeInteger`, `NumberIsSafeInteger`, `ObjectIsInteger`, `NumberIsInteger`, `ObjectIsMinusZero`, `ObjectIsNaN`, `NumberIsNaN`, `ObjectIsNonCallable`, `ObjectIsNumber`, `ObjectIsReceiver`, `ObjectIsSmi`, `ObjectIsString`, `ObjectIsSymbol`, `ObjectIsUndetectable`.
- **Array and element access:** `Allocate`, `LoadFieldByIndex`, `LoadField`, `StoreField`, `LoadElement`, `LoadStackArgument`, `StoreElement`, `NumberIsFloat64Hole`, `TransitionAndStoreElement`, `LoadTypedElement`, `LoadDataViewElement`, `StoreTypedElement`, `StoreDataViewElement`.
- **Control flow and state management:** `LoadFramePointer`, `LoadMessage`, `StoreMessage`, `ConvertReceiver`, `ArgumentsLength`, `RestLength`, `NewDoubleElements`, `NewSmiOrObjectElements`, `NewArgumentsElements`, `CheckFloat64Hole`, `ChangeFloat64HoleToTagged`, `CheckNotTaggedHole`, `CheckClosure`, `ConvertTaggedHoleToUndefined`, `CheckEqualsSymbol`, `CheckEqualsInternalizedString`, `MapGuard`, `CheckMaps`, `TransitionElementsKind`, `CompareMaps`, `EnsureWritableFastElements`, `MaybeGrowFastElements`, `DateNow`, `DoubleArrayMax`, `DoubleArrayMin`, `FrameState`, `StateValues`, `ObjectState`, `ObjectId`, `TypeGuard`, `FinishRegion`, `Return`, `FindOrderedHashMapEntry`, `FindOrderedHashSetEntry`, `FastApiCall`, and several generic JS operators.

**Relationship to JavaScript and Examples:**

This code directly implements the semantics of various JavaScript operations at a lower level. Here are some examples illustrating the connection:

1. **`SpeculativeNumberAdd` and `+` operator:**

   ```javascript
   function add(a, b) {
     return a + b;
   }
   ```
   The `SpeculativeNumberAdd` case in the C++ code handles the addition operation. It might lower to a floating-point addition instruction if `a` and `b` are likely numbers, or involve more complex logic for other types.

2. **`NumberFloor` and `Math.floor()`:**

   ```javascript
   function roundDown(x) {
     return Math.floor(x);
   }
   ```
   The `NumberFloor` case takes the input number (`x`), potentially truncates it to a float64 if necessary, and then uses a machine-level floating-point floor operation.

3. **`SpeculativeBigIntMultiply` and `*` operator with BigInts:**

   ```javascript
   function multiplyBigInts(x, y) {
     return x * y;
   }
   ```
   The `SpeculativeBigIntMultiply` case handles the multiplication of BigInt values. It might lower to machine-level 64-bit integer multiplication if the BigInts fit within 64 bits, or call a more general BigInt multiplication routine.

4. **`StringLength` and the `length` property of strings:**

   ```javascript
   function getStringLength(str) {
     return str.length;
   }
   ```
   The `StringLength` case retrieves the length of the string. The C++ code ensures the input is a string and extracts its length, likely storing it as a 32-bit integer.

5. **`CheckSmi` and implicit Smi checks:**

   ```javascript
   function useSmi(n) {
     return n + 1; // V8 might optimize this assuming 'n' is often a small integer (Smi)
   }
   ```
   The `CheckSmi` case represents a check that a value is a Small Integer. V8 might insert such checks based on type feedback to optimize operations on Smis.

6. **`ObjectIsString` and `typeof` operator:**

   ```javascript
   function isString(x) {
     return typeof x === 'string';
   }
   ```
   The `ObjectIsString` case implements the logic for checking if a value is a string, as used by the `typeof` operator.

In essence, this part of the `SimplifiedLowering` pass bridges the gap between the abstract JavaScript semantics and the concrete machine instructions needed to execute them efficiently. It handles type conversions, inserts necessary checks, and chooses appropriate lower-level operations.

This C++ code snippet is part of the `SimplifiedLowering` phase in the V8 JavaScript engine's compiler. Its primary function is to **translate high-level, abstract operations from the "Simplified" Intermediate Representation (IR) into more concrete, machine-level operations that are closer to the target architecture's instruction set.** This process is often referred to as **lowering**.

Here's a breakdown of its key responsibilities:

* **Handling Number Operations:** This section heavily focuses on lowering various JavaScript number operations (arithmetic, comparison, mathematical functions like `Math.floor`, `Math.sin`, etc.). It considers the types of the inputs (e.g., integers, floats, or potentially uninitialized values) and chooses appropriate machine-level representations (like `float64`, `int32`, `word32`) and corresponding machine instructions. It also deals with "speculative" operations where the type might not be known statically, but the compiler makes an educated guess.
* **Processing BigInt Operations:** Similar to number operations, this part handles operations on JavaScript BigInts. It determines if operations can be performed efficiently using 64-bit integer arithmetic or if more complex BigInt routines are needed. It also handles conversions to and from fixed-size integers.
* **Lowering String Operations:** The code manages string manipulation operations like concatenation, comparison, character access, and finding substrings. It sets up the necessary inputs (often tagged pointers to string objects and potentially lengths) for lower-level machine operations or built-in functions.
* **Implementing Type Checks and Conversions:**  The code processes nodes like `CheckNumber`, `CheckSmi`, `CheckString`, etc., which enforce type expectations. It also handles explicit and implicit type conversions (e.g., `NumberToString`, `PlainPrimitiveToNumber`) by inserting appropriate conversion operations.
* **Handling Object Introspection:**  Operations like `ObjectIsArrayBufferView`, `ObjectIsBigInt`, `ObjectIsCallable`, etc., which check the type of an object, are lowered here, often resulting in simple boolean checks at the machine level.
* **Managing Array and Element Access:**  The code deals with loading and storing elements in arrays and objects, taking into account different element kinds (e.g., Smi, double, tagged). It handles transitions between different array representations for optimization.
* **Dealing with Control Flow and State:** Nodes related to control flow (like `CheckIf`) and tracking program state (like `FrameState`) are processed, setting up the necessary information for subsequent compilation stages.
* **Interfacing with Machine-Level Operations:** The code uses `lowering->machine()->...` to access the machine-specific instruction set and create corresponding machine-level nodes in the graph.
* **Optimization Based on Type Information:** The code leverages type information (obtained from earlier phases or speculative optimizations) to choose more efficient lowerings. For instance, if it's known that a value is a Smi, it can use faster integer operations.

**Relationship to JavaScript and Examples:**

This code directly implements the underlying mechanics of how JavaScript code is executed. Here are some examples illustrating the connection:

1. **JavaScript Addition (`+`)**:
   ```javascript
   function add(a, b) {
     return a + b;
   }
   ```
   The `SpeculativeNumberAdd` case in the C++ code handles the lowering of this `+` operation. Based on the types of `a` and `b`, it might be lowered to a floating-point addition instruction if they are numbers, or to string concatenation if one is a string.

2. **`Math.floor()`**:
   ```javascript
   function roundDown(x) {
     return Math.floor(x);
   }
   ```
   The `NumberFloor` case in the C++ code takes the input `x` and translates the `Math.floor` operation into a machine-level instruction for flooring a floating-point number.

3. **BigInt Multiplication (`*`)**:
   ```javascript
   const big1 = 10n;
   const big2 = 20n;
   const product = big1 * big2;
   ```
   The `SpeculativeBigIntMultiply` case handles the lowering of the `*` operation for BigInts. It determines the appropriate machine instructions or calls to runtime functions for BigInt multiplication.

4. **String Length (`.length`)**:
   ```javascript
   const str = "hello";
   const len = str.length;
   ```
   The `StringLength` case lowers the access to the `length` property of a string, extracting the stored length value.

5. **Typeof Operator**:
   ```javascript
   function getType(x) {
     return typeof x;
   }
   ```
   The `TypeOf` case handles the lowering of the `typeof` operator, determining the type of the input and representing it as a string.

In essence, this code snippet is a crucial part of the V8 compiler that makes JavaScript code executable by translating its high-level semantics into the low-level instructions that the CPU can understand. It ensures that JavaScript operations are performed efficiently by considering the underlying data types and choosing the most appropriate machine representations and instructions.

### 提示词
```
这是目录为v8/src/compiler/simplified-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
ntifiesZeroAndMinusZero()
                                ? Type::OrderedNumber()
                                : Type::PlainNumber())) {
              lowering->DoMin(node,
                              lowering->machine()->Float64LessThanOrEqual(),
                              MachineRepresentation::kFloat64);
            } else {
              ChangeOp(node, Float64Op(node));
            }
          }
        }
        return;
      }
      case IrOpcode::kSpeculativeNumberPow: {
        // Checked float64 ** float64 => float64
        VisitBinop<T>(node,
                      UseInfo::CheckedNumberOrOddballAsFloat64(
                          kDistinguishZeros, FeedbackSource()),
                      MachineRepresentation::kFloat64, Type::Number());
        if (lower<T>()) ChangeToPureOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kNumberAtan2:
      case IrOpcode::kNumberPow: {
        VisitBinop<T>(node, UseInfo::TruncatingFloat64(),
                      MachineRepresentation::kFloat64);
        if (lower<T>()) ChangeOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kNumberCeil:
      case IrOpcode::kNumberFloor:
      case IrOpcode::kNumberRound:
      case IrOpcode::kNumberTrunc: {
        // For NumberCeil, NumberFloor, NumberRound and NumberTrunc we propagate
        // the zero identification part of the truncation, and we turn them into
        // no-ops if we figure out (late) that their input is already an
        // integer, NaN or -0.
        Type const input_type = TypeOf(node->InputAt(0));
        VisitUnop<T>(node,
                     UseInfo::TruncatingFloat64(truncation.identify_zeros()),
                     MachineRepresentation::kFloat64);
        if (lower<T>()) {
          if (input_type.Is(type_cache_->kIntegerOrMinusZeroOrNaN)) {
            DeferReplacement(node, node->InputAt(0));
          } else if (node->opcode() == IrOpcode::kNumberRound) {
            DeferReplacement(node, lowering->Float64Round(node));
          } else {
            ChangeOp(node, Float64Op(node));
          }
        }
        return;
      }
      case IrOpcode::kSpeculativeBigIntAsIntN:
      case IrOpcode::kSpeculativeBigIntAsUintN: {
        const bool is_asuintn =
            node->opcode() == IrOpcode::kSpeculativeBigIntAsUintN;
        const auto p = SpeculativeBigIntAsNParametersOf(node->op());
        DCHECK_LE(0, p.bits());
        DCHECK_LE(p.bits(), 64);

        ProcessInput<T>(node, 0,
                        UseInfo::CheckedBigIntTruncatingWord64(p.feedback()));
        SetOutput<T>(
            node, MachineRepresentation::kWord64,
            is_asuintn ? Type::UnsignedBigInt64() : Type::SignedBigInt64());
        if (lower<T>()) {
          if (p.bits() == 0) {
            DeferReplacement(node, InsertTypeOverrideForVerifier(
                                       Type::UnsignedBigInt63(),
                                       jsgraph_->Int64Constant(0)));
          } else if (p.bits() == 64) {
            DeferReplacement(node, InsertTypeOverrideForVerifier(
                                       is_asuintn ? Type::UnsignedBigInt64()
                                                  : Type::SignedBigInt64(),
                                       node->InputAt(0)));
          } else {
            if (is_asuintn) {
              const uint64_t mask = (1ULL << p.bits()) - 1ULL;
              ChangeUnaryToPureBinaryOp(node, lowering->machine()->Word64And(),
                                        1, jsgraph_->Int64Constant(mask));
            } else {
              // We truncate the value to N bits, but to correctly interpret
              // negative values, we have to fill the top (64-N) bits with the
              // sign. This is done by shifting the value left and then back
              // with an arithmetic right shift. E.g. for {value} =
              // 0..0'0001'1101 (29n) and N = 3: {shifted} is 1010'0000'0..0
              // after left shift by 61 bits, {unshifted} is 1..1'1111'1101
              // after arithmetic right shift by 61. This is the 64 bit
              // representation of -3 we expect for the signed 3 bit integer
              // 101.
              const uint64_t shift = 64 - p.bits();
              Node* value = node->InputAt(0);
              Node* shifted =
                  graph()->NewNode(lowering->machine()->Word64Shl(), value,
                                   jsgraph_->Uint64Constant(shift));
              Node* unshifted =
                  graph()->NewNode(lowering->machine()->Word64Sar(), shifted,
                                   jsgraph_->Uint64Constant(shift));

              ReplaceWithPureNode(node, unshifted);
            }
          }
        }
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
      case IrOpcode::kNumberLog2:
      case IrOpcode::kNumberLog10:
      case IrOpcode::kNumberCbrt:
      case IrOpcode::kNumberSin:
      case IrOpcode::kNumberSinh:
      case IrOpcode::kNumberTan:
      case IrOpcode::kNumberTanh: {
        VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                     MachineRepresentation::kFloat64);
        if (lower<T>()) ChangeOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kNumberSign: {
        if (InputIs(node, Type::Signed32())) {
          VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                       MachineRepresentation::kWord32);
          if (lower<T>()) DeferReplacement(node, lowering->Int32Sign(node));
        } else {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kFloat64);
          if (lower<T>()) DeferReplacement(node, lowering->Float64Sign(node));
        }
        return;
      }
      case IrOpcode::kNumberSilenceNaN: {
        Type const input_type = TypeOf(node->InputAt(0));
        if (input_type.Is(Type::OrderedNumber())) {
          // No need to silence anything if the input cannot be NaN.
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kFloat64);
          if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        } else {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kFloat64);
          if (lower<T>()) ChangeOp(node, Float64Op(node));
        }
        return;
      }
      case IrOpcode::kNumberSqrt: {
        VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                     MachineRepresentation::kFloat64);
        if (lower<T>()) ChangeOp(node, Float64Op(node));
        return;
      }
      case IrOpcode::kNumberToBoolean: {
        // For NumberToBoolean we don't care whether the input is 0 or
        // -0, since both of them are mapped to false anyways, so we
        // can generally pass kIdentifyZeros truncation.
        Type const input_type = TypeOf(node->InputAt(0));
        if (input_type.Is(Type::Integral32OrMinusZeroOrNaN())) {
          // 0, -0 and NaN all map to false, so we can safely truncate
          // all of them to zero here.
          VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                       MachineRepresentation::kBit);
          if (lower<T>()) lowering->DoIntegral32ToBit(node);
        } else if (input_type.Is(Type::OrderedNumber())) {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(kIdentifyZeros),
                       MachineRepresentation::kBit);
          if (lower<T>()) lowering->DoOrderedNumberToBit(node);
        } else {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(kIdentifyZeros),
                       MachineRepresentation::kBit);
          if (lower<T>()) lowering->DoNumberToBit(node);
        }
        return;
      }
      case IrOpcode::kNumberToInt32: {
        // Just change representation if necessary.
        VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                     MachineRepresentation::kWord32);
        if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        return;
      }
      case IrOpcode::kNumberToString: {
        VisitUnop<T>(node, UseInfo::AnyTagged(),
                     MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kNumberToUint32: {
        // Just change representation if necessary.
        VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                     MachineRepresentation::kWord32);
        if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        return;
      }
      case IrOpcode::kNumberToUint8Clamped: {
        Type const input_type = TypeOf(node->InputAt(0));
        if (input_type.Is(type_cache_->kUint8OrMinusZeroOrNaN)) {
          VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                       MachineRepresentation::kWord32);
          if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        } else if (input_type.Is(Type::Unsigned32OrMinusZeroOrNaN())) {
          VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                       MachineRepresentation::kWord32);
          if (lower<T>()) lowering->DoUnsigned32ToUint8Clamped(node);
        } else if (input_type.Is(Type::Signed32OrMinusZeroOrNaN())) {
          VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                       MachineRepresentation::kWord32);
          if (lower<T>()) lowering->DoSigned32ToUint8Clamped(node);
        } else if (input_type.Is(type_cache_->kIntegerOrMinusZeroOrNaN)) {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kFloat64);
          if (lower<T>()) lowering->DoIntegerToUint8Clamped(node);
        } else {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kFloat64);
          if (lower<T>()) lowering->DoNumberToUint8Clamped(node);
        }
        return;
      }
      case IrOpcode::kIntegral32OrMinusZeroToBigInt: {
        VisitUnop<T>(node, UseInfo::Word64(kIdentifyZeros),
                     MachineRepresentation::kWord64);
        if (lower<T>()) {
          DeferReplacement(
              node, InsertTypeOverrideForVerifier(NodeProperties::GetType(node),
                                                  node->InputAt(0)));
        }
        return;
      }
      case IrOpcode::kReferenceEqual: {
        VisitBinop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kBit);
        if (lower<T>()) {
          if (COMPRESS_POINTERS_BOOL) {
            ChangeOp(node, lowering->machine()->Word32Equal());
          } else {
            ChangeOp(node, lowering->machine()->WordEqual());
          }
        }
        return;
      }
      case IrOpcode::kSameValueNumbersOnly: {
        VisitBinop<T>(node, UseInfo::AnyTagged(),
                      MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kSameValue: {
        if (truncation.IsUnused()) return VisitUnused<T>(node);
        if (BothInputsAre(node, Type::Number())) {
          VisitBinop<T>(node, UseInfo::TruncatingFloat64(),
                        MachineRepresentation::kBit);
          if (lower<T>()) {
            ChangeOp(node, lowering->simplified()->NumberSameValue());
          }
        } else {
          VisitBinop<T>(node, UseInfo::AnyTagged(),
                        MachineRepresentation::kTaggedPointer);
        }
        return;
      }
      case IrOpcode::kTypeOf: {
        return VisitUnop<T>(node, UseInfo::AnyTagged(),
                            MachineRepresentation::kTaggedPointer);
      }
      case IrOpcode::kNewConsString: {
        ProcessInput<T>(node, 0, UseInfo::TruncatingWord32());  // length
        ProcessInput<T>(node, 1, UseInfo::AnyTagged());         // first
        ProcessInput<T>(node, 2, UseInfo::AnyTagged());         // second
        SetOutput<T>(node, MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kSpeculativeBigIntAdd:
      case IrOpcode::kSpeculativeBigIntSubtract:
      case IrOpcode::kSpeculativeBigIntMultiply: {
        if (truncation.IsUnused() && BothInputsAre(node, Type::BigInt())) {
          VisitUnused<T>(node);
          return;
        }
        if (Is64() && truncation.IsUsedAsWord64()) {
          VisitBinop<T>(
              node, UseInfo::CheckedBigIntTruncatingWord64(FeedbackSource{}),
              MachineRepresentation::kWord64);
          if (lower<T>()) {
            ChangeToPureOp(node, Int64Op(node));
          }
          return;
        }
        BigIntOperationHint hint = BigIntOperationHintOf(node->op());
        switch (hint) {
          case BigIntOperationHint::kBigInt64: {
            VisitBinop<T>(
                node, UseInfo::CheckedBigInt64AsWord64(FeedbackSource{}),
                MachineRepresentation::kWord64, Type::SignedBigInt64());
            if (lower<T>()) {
              ChangeOp(node, Int64OverflowOp(node));
            }
            return;
          }
          case BigIntOperationHint::kBigInt: {
            VisitBinop<T>(
                node, UseInfo::CheckedBigIntAsTaggedPointer(FeedbackSource{}),
                MachineRepresentation::kTaggedPointer);
            if (lower<T>()) {
              ChangeOp(node, BigIntOp(node));
            }
            return;
          }
        }
      }
      case IrOpcode::kSpeculativeBigIntDivide:
      case IrOpcode::kSpeculativeBigIntModulus: {
        if (truncation.IsUnused() && BothInputsAre(node, Type::BigInt())) {
          VisitUnused<T>(node);
          return;
        }
        BigIntOperationHint hint = BigIntOperationHintOf(node->op());
        switch (hint) {
          case BigIntOperationHint::kBigInt64: {
            VisitBinop<T>(
                node, UseInfo::CheckedBigInt64AsWord64(FeedbackSource{}),
                MachineRepresentation::kWord64, Type::SignedBigInt64());
            if (lower<T>()) {
              ChangeOp(node, Int64OverflowOp(node));
            }
            return;
          }
          case BigIntOperationHint::kBigInt: {
            VisitBinop<T>(
                node, UseInfo::CheckedBigIntAsTaggedPointer(FeedbackSource{}),
                MachineRepresentation::kTaggedPointer);
            if (lower<T>()) {
              ChangeOp(node, BigIntOp(node));
            }
            return;
          }
        }
      }
      case IrOpcode::kSpeculativeBigIntBitwiseAnd:
      case IrOpcode::kSpeculativeBigIntBitwiseOr:
      case IrOpcode::kSpeculativeBigIntBitwiseXor: {
        if (truncation.IsUnused() && BothInputsAre(node, Type::BigInt())) {
          VisitUnused<T>(node);
          return;
        }
        if (Is64() && truncation.IsUsedAsWord64()) {
          VisitBinop<T>(
              node, UseInfo::CheckedBigIntTruncatingWord64(FeedbackSource{}),
              MachineRepresentation::kWord64);
          if (lower<T>()) {
            ChangeToPureOp(node, Int64Op(node));
          }
          return;
        }
        BigIntOperationHint hint = BigIntOperationHintOf(node->op());
        switch (hint) {
          case BigIntOperationHint::kBigInt64: {
            VisitBinop<T>(
                node, UseInfo::CheckedBigInt64AsWord64(FeedbackSource{}),
                MachineRepresentation::kWord64, Type::SignedBigInt64());
            if (lower<T>()) {
              ChangeToPureOp(node, Int64Op(node));
            }
            return;
          }
          case BigIntOperationHint::kBigInt: {
            VisitBinop<T>(
                node, UseInfo::CheckedBigIntAsTaggedPointer(FeedbackSource{}),
                MachineRepresentation::kTaggedPointer);
            if (lower<T>()) {
              ChangeOp(node, BigIntOp(node));
            }
            return;
          }
        }
      }
      case IrOpcode::kSpeculativeBigIntShiftLeft:
      case IrOpcode::kSpeculativeBigIntShiftRight: {
        if (truncation.IsUnused() && BothInputsAre(node, Type::BigInt())) {
          VisitUnused<T>(node);
          return;
        }
        if (Is64() && TryOptimizeBigInt64Shift<T>(node, truncation, lowering)) {
          return;
        }
        DCHECK_EQ(BigIntOperationHintOf(node->op()),
                  BigIntOperationHint::kBigInt);
        VisitBinop<T>(node,
                      UseInfo::CheckedBigIntAsTaggedPointer(FeedbackSource{}),
                      MachineRepresentation::kTaggedPointer);
        if (lower<T>()) {
          ChangeOp(node, BigIntOp(node));
        }
        return;
      }
      case IrOpcode::kSpeculativeBigIntEqual:
      case IrOpcode::kSpeculativeBigIntLessThan:
      case IrOpcode::kSpeculativeBigIntLessThanOrEqual: {
        // Loose equality can throw a TypeError when failing to cast an object
        // operand to primitive.
        if (truncation.IsUnused() && BothInputsAre(node, Type::BigInt())) {
          VisitUnused<T>(node);
          return;
        }
        BigIntOperationHint hint = BigIntOperationHintOf(node->op());
        switch (hint) {
          case BigIntOperationHint::kBigInt64: {
            VisitBinop<T>(node,
                          UseInfo::CheckedBigInt64AsWord64(FeedbackSource{}),
                          MachineRepresentation::kBit);
            if (lower<T>()) {
              ChangeToPureOp(node, Int64Op(node));
            }
            return;
          }
          case BigIntOperationHint::kBigInt: {
            VisitBinop<T>(
                node, UseInfo::CheckedBigIntAsTaggedPointer(FeedbackSource{}),
                MachineRepresentation::kTaggedPointer);
            if (lower<T>()) {
              ChangeToPureOp(node, BigIntOp(node));
            }
            return;
          }
        }
      }
      case IrOpcode::kSpeculativeBigIntNegate: {
        // NOTE: If truncation is Unused, we still need to preserve at least the
        // BigInt type check (see http://crbug.com/1431713 for some details).
        // We can use the standard lowering to word64 operations and have
        // following phases remove the unused truncation and subtraction
        // operations.
        if (Is64() && truncation.IsUsedAsWord64()) {
          VisitUnop<T>(node,
                       UseInfo::CheckedBigIntTruncatingWord64(FeedbackSource{}),
                       MachineRepresentation::kWord64);
          if (lower<T>()) {
            ChangeUnaryToPureBinaryOp(node, lowering->machine()->Int64Sub(), 0,
                                      jsgraph_->Int64Constant(0));
          }
        } else {
          VisitUnop<T>(node,
                       UseInfo::CheckedBigIntAsTaggedPointer(FeedbackSource{}),
                       MachineRepresentation::kTaggedPointer);
          if (lower<T>()) {
            ChangeToPureOp(node, lowering->simplified()->BigIntNegate());
          }
        }
        return;
      }
      case IrOpcode::kStringConcat: {
        // TODO(turbofan): We currently depend on having this first length input
        // to make sure that the overflow check is properly scheduled before the
        // actual string concatenation. We should also use the length to pass it
        // to the builtin or decide in optimized code how to construct the
        // resulting string (i.e. cons string or sequential string).
        ProcessInput<T>(node, 0, UseInfo::TaggedSigned());  // length
        ProcessInput<T>(node, 1, UseInfo::AnyTagged());     // first
        ProcessInput<T>(node, 2, UseInfo::AnyTagged());     // second
        SetOutput<T>(node, MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kStringEqual:
      case IrOpcode::kStringLessThan:
      case IrOpcode::kStringLessThanOrEqual: {
        return VisitBinop<T>(node, UseInfo::AnyTagged(),
                             MachineRepresentation::kTaggedPointer);
      }
      case IrOpcode::kStringCharCodeAt: {
        return VisitBinop<T>(node, UseInfo::AnyTagged(), UseInfo::Word(),
                             MachineRepresentation::kWord32);
      }
      case IrOpcode::kStringCodePointAt: {
        return VisitBinop<T>(node, UseInfo::AnyTagged(), UseInfo::Word(),
                             MachineRepresentation::kWord32);
      }
      case IrOpcode::kStringFromSingleCharCode: {
        VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                     MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kStringFromSingleCodePoint: {
        VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                     MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kStringFromCodePointAt: {
        return VisitBinop<T>(node, UseInfo::AnyTagged(), UseInfo::Word(),
                             MachineRepresentation::kTaggedPointer);
      }
      case IrOpcode::kStringIndexOf: {
        ProcessInput<T>(node, 0, UseInfo::AnyTagged());
        ProcessInput<T>(node, 1, UseInfo::AnyTagged());
        ProcessInput<T>(node, 2, UseInfo::TaggedSigned());
        SetOutput<T>(node, MachineRepresentation::kTaggedSigned);
        return;
      }
      case IrOpcode::kStringLength:
      case IrOpcode::kStringWrapperLength: {
        // TODO(bmeurer): The input representation should be TaggedPointer.
        // Fix this once we have a dedicated StringConcat/JSStringAdd
        // operator, which marks it's output as TaggedPointer properly.
        VisitUnop<T>(node, UseInfo::AnyTagged(),
                     MachineRepresentation::kWord32);
        return;
      }
      case IrOpcode::kStringSubstring: {
        ProcessInput<T>(node, 0, UseInfo::AnyTagged());
        ProcessInput<T>(node, 1, UseInfo::TruncatingWord32());
        ProcessInput<T>(node, 2, UseInfo::TruncatingWord32());
        ProcessRemainingInputs<T>(node, 3);
        SetOutput<T>(node, MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kStringToLowerCaseIntl:
      case IrOpcode::kStringToUpperCaseIntl: {
        VisitUnop<T>(node, UseInfo::AnyTagged(),
                     MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kCheckBounds:
        return VisitCheckBounds<T>(node, lowering);
      case IrOpcode::kCheckHeapObject: {
        if (InputCannotBe(node, Type::SignedSmall())) {
          VisitUnop<T>(node, UseInfo::AnyTagged(),
                       MachineRepresentation::kTaggedPointer);
        } else {
          VisitUnop<T>(
              node, UseInfo::CheckedHeapObjectAsTaggedPointer(FeedbackSource()),
              MachineRepresentation::kTaggedPointer);
        }
        if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        return;
      }
      case IrOpcode::kCheckIf: {
        ProcessInput<T>(node, 0, UseInfo::Bool());
        ProcessRemainingInputs<T>(node, 1);
        SetOutput<T>(node, MachineRepresentation::kNone);
        return;
      }
      case IrOpcode::kCheckInternalizedString: {
        VisitCheck<T>(node, Type::InternalizedString(), lowering);
        return;
      }
      case IrOpcode::kCheckNumber: {
        Type const input_type = TypeOf(node->InputAt(0));
        if (input_type.Is(Type::Number())) {
          VisitNoop<T>(node, truncation);
        } else {
          VisitUnop<T>(node, UseInfo::AnyTagged(),
                       MachineRepresentation::kTagged);
        }
        return;
      }
      case IrOpcode::kCheckReceiver: {
        VisitCheck<T>(node, Type::Receiver(), lowering);
        return;
      }
      case IrOpcode::kCheckReceiverOrNullOrUndefined: {
        VisitCheck<T>(node, Type::ReceiverOrNullOrUndefined(), lowering);
        return;
      }
      case IrOpcode::kCheckSmi: {
        const CheckParameters& params = CheckParametersOf(node->op());
        if (SmiValuesAre32Bits() && truncation.IsUsedAsWord32()) {
          VisitUnop<T>(node,
                       UseInfo::CheckedSignedSmallAsWord32(kDistinguishZeros,
                                                           params.feedback()),
                       MachineRepresentation::kWord32);
        } else {
          VisitUnop<T>(
              node,
              UseInfo::CheckedSignedSmallAsTaggedSigned(params.feedback()),
              MachineRepresentation::kTaggedSigned);
        }
        if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        return;
      }
      case IrOpcode::kCheckString: {
        const CheckParameters& params = CheckParametersOf(node->op());
        if (InputIs(node, Type::String())) {
          VisitUnop<T>(node, UseInfo::AnyTagged(),
                       MachineRepresentation::kTaggedPointer);
          if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        } else {
          VisitUnop<T>(
              node,
              UseInfo::CheckedHeapObjectAsTaggedPointer(params.feedback()),
              MachineRepresentation::kTaggedPointer);
        }
        return;
      }
      case IrOpcode::kCheckStringOrStringWrapper: {
        const CheckParameters& params = CheckParametersOf(node->op());
        if (InputIs(node, Type::StringOrStringWrapper())) {
          VisitUnop<T>(node, UseInfo::AnyTagged(),
                       MachineRepresentation::kTaggedPointer);
          if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        } else {
          VisitUnop<T>(
              node,
              UseInfo::CheckedHeapObjectAsTaggedPointer(params.feedback()),
              MachineRepresentation::kTaggedPointer);
        }
        return;
      }
      case IrOpcode::kCheckSymbol: {
        VisitCheck<T>(node, Type::Symbol(), lowering);
        return;
      }

      case IrOpcode::kAllocate: {
        ProcessInput<T>(node, 0, UseInfo::Word());
        ProcessRemainingInputs<T>(node, 1);
        SetOutput<T>(node, MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kLoadFramePointer: {
        SetOutput<T>(node, MachineType::PointerRepresentation());
        return;
      }
#if V8_ENABLE_WEBASSEMBLY
      case IrOpcode::kLoadStackPointer: {
        SetOutput<T>(node, MachineType::PointerRepresentation());
        return;
      }
      case IrOpcode::kSetStackPointer: {
        SetOutput<T>(node, MachineRepresentation::kNone);
        return;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      case IrOpcode::kLoadMessage: {
        if (truncation.IsUnused()) return VisitUnused<T>(node);
        VisitUnop<T>(node, UseInfo::Word(), MachineRepresentation::kTagged);
        return;
      }
      case IrOpcode::kStoreMessage: {
        ProcessInput<T>(node, 0, UseInfo::Word());
        ProcessInput<T>(node, 1, UseInfo::AnyTagged());
        ProcessRemainingInputs<T>(node, 2);
        SetOutput<T>(node, MachineRepresentation::kNone);
        return;
      }
      case IrOpcode::kLoadFieldByIndex: {
        if (truncation.IsUnused()) return VisitUnused<T>(node);
        VisitBinop<T>(node, UseInfo::AnyTagged(), UseInfo::TruncatingWord32(),
                      MachineRepresentation::kTagged);
        return;
      }
      case IrOpcode::kLoadField: {
        if (truncation.IsUnused()) return VisitUnused<T>(node);
        FieldAccess access = FieldAccessOf(node->op());
        MachineRepresentation const representation =
            access.machine_type.representation();
        VisitUnop<T>(node, UseInfoForBasePointer(access), representation);
        return;
      }
      case IrOpcode::kStoreField: {
        FieldAccess access = FieldAccessOf(node->op());
        Node* value_node = node->InputAt(1);
        NodeInfo* input_info = GetInfo(value_node);
        MachineRepresentation field_representation =
            access.machine_type.representation();

        // Convert to Smi if possible, such that we can avoid a write barrier.
        if (field_representation == MachineRepresentation::kTagged &&
            TypeOf(value_node).Is(Type::SignedSmall())) {
          field_representation = MachineRepresentation::kTaggedSigned;
        }
        WriteBarrierKind write_barrier_kind = WriteBarrierKindFor(
            access.base_is_tagged, field_representation, access.offset,
            access.type, input_info->representation(), value_node);

        ProcessInput<T>(node, 0, UseInfoForBasePointer(access));
        ProcessInput<T>(
            node, 1, TruncatingUseInfoFromRepresentation(field_representation));
        ProcessRemainingInputs<T>(node, 2);
        SetOutput<T>(node, MachineRepresentation::kNone);
        if (lower<T>()) {
          if (write_barrier_kind < access.write_barrier_kind) {
            access.write_barrier_kind = write_barrier_kind;
            ChangeOp(node, jsgraph_->simplified()->StoreField(access));
          }
        }
        return;
      }
      case IrOpcode::kLoadElement: {
        if (truncation.IsUnused()) return VisitUnused<T>(node);
        ElementAccess access = ElementAccessOf(node->op());
        VisitBinop<T>(node, UseInfoForBasePointer(access), UseInfo::Word(),
                      access.machine_type.representation());
        return;
      }
      case IrOpcode::kLoadStackArgument: {
        if (truncation.IsUnused()) return VisitUnused<T>(node);
        VisitBinop<T>(node, UseInfo::Word(), MachineRepresentation::kTagged);
        return;
      }
      case IrOpcode::kStoreElement: {
        ElementAccess access = ElementAccessOf(node->op());
        Node* value_node = node->InputAt(2);
        NodeInfo* input_info = GetInfo(value_node);
        MachineRepresentation element_representation =
            access.machine_type.representation();

        // Convert to Smi if possible, such that we can avoid a write barrier.
        if (element_representation == MachineRepresentation::kTagged &&
            TypeOf(value_node).Is(Type::SignedSmall())) {
          element_representation = MachineRepresentation::kTaggedSigned;
        }
        WriteBarrierKind write_barrier_kind = WriteBarrierKindFor(
            access.base_is_tagged, element_representation, access.type,
            input_info->representation(), value_node);
        ProcessInput<T>(node, 0, UseInfoForBasePointer(access));  // base
        ProcessInput<T>(node, 1, UseInfo::Word());                // index
        ProcessInput<T>(node, 2,
                        TruncatingUseInfoFromRepresentation(
                            element_representation));  // value
        ProcessRemainingInputs<T>(node, 3);
        SetOutput<T>(node, MachineRepresentation::kNone);
        if (lower<T>()) {
          if (write_barrier_kind < access.write_barrier_kind) {
            access.write_barrier_kind = write_barrier_kind;
            ChangeOp(node, jsgraph_->simplified()->StoreElement(access));
          }
        }
        return;
      }
      case IrOpcode::kNumberIsFloat64Hole: {
        VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                     MachineRepresentation::kBit);
        return;
      }
      case IrOpcode::kTransitionAndStoreElement: {
        Type value_type = TypeOf(node->InputAt(2));

        ProcessInput<T>(node, 0, UseInfo::AnyTagged());  // array
        ProcessInput<T>(node, 1, UseInfo::Word());       // index

        if (value_type.Is(Type::SignedSmall())) {
          ProcessInput<T>(node, 2, UseInfo::TruncatingWord32());  // value
          if (lower<T>()) {
            ChangeOp(node, simplified()->StoreSignedSmallElement());
          }
        } else if (value_type.Is(Type::Number())) {
          ProcessInput<T>(node, 2, UseInfo::TruncatingFloat64());  // value
          if (lower<T>()) {
            MapRef double_map = DoubleMapParameterOf(node->op());
            ChangeOp(node,
                     simplified()->TransitionAndStoreNumberElement(double_map));
          }
        } else if (value_type.Is(Type::NonNumber())) {
          ProcessInput<T>(node, 2, UseInfo::AnyTagged());  // value
          if (lower<T>()) {
            MapRef fast_map = FastMapParameterOf(node->op());
            ChangeOp(node, simplified()->TransitionAndStoreNonNumberElement(
                               fast_map, value_type));
          }
        } else {
          ProcessInput<T>(node, 2, UseInfo::AnyTagged());  // value
        }

        ProcessRemainingInputs<T>(node, 3);
        SetOutput<T>(node, MachineRepresentation::kNone);
        return;
      }
      case IrOpcode::kLoadTypedElement: {
        MachineRepresentation const rep =
            MachineRepresentationFromArrayType(ExternalArrayTypeOf(node->op()));
        ProcessInput<T>(node, 0, UseInfo::AnyTagged());  // buffer
        ProcessInput<T>(node, 1, UseInfo::AnyTagged());  // base pointer
        ProcessInput<T>(node, 2, UseInfo::Word());       // external pointer
        ProcessInput<T>(node, 3, UseInfo::Word());       // index
        ProcessRemainingInputs<T>(node, 4);
        SetOutput<T>(node, rep);
        return;
      }
      case IrOpcode::kLoadDataViewElement: {
        MachineRepresentation const rep =
            MachineRepresentationFromArrayType(ExternalArrayTypeOf(node->op()));
        ProcessInput<T>(node, 0, UseInfo::AnyTagged());  // object
        ProcessInput<T>(node, 1, UseInfo::Word());       // base
        ProcessInput<T>(node, 2, UseInfo::Word());       // index
        ProcessInput<T>(node, 3, UseInfo::Bool());       // little-endian
        ProcessRemainingInputs<T>(node, 4);
        SetOutput<T>(node, rep);
        return;
      }
      case IrOpcode::kStoreTypedElement: {
        MachineRepresentation const rep =
            MachineRepresentationFromArrayType(ExternalArrayTypeOf(node->op()));
        ProcessInput<T>(node, 0, UseInfo::AnyTagged());  // buffer
        ProcessInput<T>(node, 1, UseInfo::AnyTagged());  // base pointer
        ProcessInput<T>(node, 2, UseInfo::Word());       // external pointer
        ProcessInput<T>(node, 3, UseInfo::Word());       // index
        ProcessInput<T>(node, 4,
                        TruncatingUseInfoFromRepresentation(rep));  // value
        ProcessRemainingInputs<T>(node, 5);
        SetOutput<T>(node, MachineRepresentation::kNone);
        return;
      }
      case IrOpcode::kStoreDataViewElement: {
        MachineRepresentation const rep =
            MachineRepresentationFromArrayType(ExternalArrayTypeOf(node->op()));
        ProcessInput<T>(node, 0, UseInfo::AnyTagged());  // object
        ProcessInput<T>(node, 1, UseInfo::Word());       // base
        ProcessInput<T>(node, 2, UseInfo::Word());       // index
        ProcessInput<T>(node, 3,
                        TruncatingUseInfoFromRepresentation(rep));  // value
        ProcessInput<T>(node, 4, UseInfo::Bool());  // little-endian
        ProcessRemainingInputs<T>(node, 5);
        SetOutput<T>(node, MachineRepresentation::kNone);
        return;
      }
      case IrOpcode::kConvertReceiver: {
        Type input_type = TypeOf(node->InputAt(0));
        ProcessInput<T>(node, 0, UseInfo::AnyTagged());  // object
        ProcessInput<T>(node, 1, UseInfo::AnyTagged());  // native_context
        ProcessInput<T>(node, 2, UseInfo::AnyTagged());  // global_proxy
        ProcessRemainingInputs<T>(node, 3);
        SetOutput<T>(node, MachineRepresentation::kTaggedPointer);
        if (lower<T>()) {
          // Try to optimize the {node} based on the input type.
          if (input_type.Is(Type::Receiver())) {
            DeferReplacement(node, node->InputAt(0));
          } else if (input_type.Is(Type::NullOrUndefined())) {
            DeferReplacement(node, node->InputAt(2));
          } else if (!input_type.Maybe(Type::NullOrUndefined())) {
            ChangeOp(node, lowering->simplified()->ConvertReceiver(
                               ConvertReceiverMode::kNotNullOrUndefined));
          }
        }
        return;
      }
      case IrOpcode::kPlainPrimitiveToNumber: {
        if (InputIs(node, Type::Boolean())) {
          VisitUnop<T>(node, UseInfo::Bool(), MachineRepresentation::kWord32);
          if (lower<T>()) {
            DeferReplacement(node, InsertSemanticsHintForVerifier(
                                       node->op(), node->InputAt(0)));
          }
        } else if (InputIs(node, Type::String())) {
          VisitUnop<T>(node, UseInfo::AnyTagged(),
                       MachineRepresentation::kTagged);
          if (lower<T>()) {
            ChangeOp(node, simplified()->StringToNumber());
          }
        } else if (truncation.IsUsedAsWord32()) {
          if (InputIs(node, Type::NumberOrOddball())) {
            VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                         MachineRepresentation::kWord32);
            if (lower<T>()) {
              DeferReplacement(node, InsertSemanticsHintForVerifier(
                                         node->op(), node->InputAt(0)));
            }
          } else {
            VisitUnop<T>(node, UseInfo::AnyTagged(),
                         MachineRepresentation::kWord32);
            if (lower<T>()) {
              ChangeOp(node, simplified()->PlainPrimitiveToWord32());
            }
          }
        } else if (truncation.TruncatesOddballAndBigIntToNumber()) {
          if (InputIs(node, Type::NumberOrOddball())) {
            VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                         MachineRepresentation::kFloat64);
            if (lower<T>()) {
              DeferReplacement(node, InsertSemanticsHintForVerifier(
                                         node->op(), node->InputAt(0)));
            }
          } else {
            VisitUnop<T>(node, UseInfo::AnyTagged(),
                         MachineRepresentation::kFloat64);
            if (lower<T>()) {
              ChangeOp(node, simplified()->PlainPrimitiveToFloat64());
            }
          }
        } else {
          VisitUnop<T>(node, UseInfo::AnyTagged(),
                       MachineRepresentation::kTagged);
        }
        return;
      }
      case IrOpcode::kSpeculativeToNumber: {
        NumberOperationParameters const& p =
            NumberOperationParametersOf(node->op());
        switch (p.hint()) {
          case NumberOperationHint::kSignedSmall:
          case NumberOperationHint::kSignedSmallInputs:
            VisitUnop<T>(node,
                         CheckedUseInfoAsWord32FromHint(
                             p.hint(), kDistinguishZeros, p.feedback()),
                         MachineRepresentation::kWord32, Type::Signed32());
            break;
          case NumberOperationHint::kNumber:
          case NumberOperationHint::kNumberOrBoolean:
          case NumberOperationHint::kNumberOrOddball:
            VisitUnop<T>(
                node, CheckedUseInfoAsFloat64FromHint(p.hint(), p.feedback()),
                MachineRepresentation::kFloat64);
            break;
        }
        if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        return;
      }
      case IrOpcode::kSpeculativeToBigInt: {
        if (truncation.IsUnused() && InputIs(node, Type::BigInt())) {
          VisitUnused<T>(node);
          return;
        }
        if (Is64() && truncation.IsUsedAsWord64()) {
          VisitUnop<T>(node,
                       UseInfo::CheckedBigIntTruncatingWord64(FeedbackSource{}),
                       MachineRepresentation::kWord64);
        } else {
          BigIntOperationParameters const& p =
              BigIntOperationParametersOf(node->op());
          switch (p.hint()) {
            case BigIntOperationHint::kBigInt64: {
              VisitUnop<T>(node, UseInfo::CheckedBigInt64AsWord64(p.feedback()),
                           MachineRepresentation::kWord64);
              break;
            }
            case BigIntOperationHint::kBigInt: {
              VisitUnop<T>(node,
                           UseInfo::CheckedBigIntAsTaggedPointer(p.feedback()),
                           MachineRepresentation::kTaggedPointer);
            }
          }
        }
        if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        return;
      }
      case IrOpcode::kObjectIsArrayBufferView: {
        // TODO(turbofan): Introduce a Type::ArrayBufferView?
        VisitUnop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kBit);
        return;
      }
      case IrOpcode::kObjectIsBigInt: {
        VisitObjectIs<T>(node, Type::BigInt(), lowering);
        return;
      }
      case IrOpcode::kObjectIsCallable: {
        VisitObjectIs<T>(node, Type::Callable(), lowering);
        return;
      }
      case IrOpcode::kObjectIsConstructor: {
        // TODO(turbofan): Introduce a Type::Constructor?
        VisitUnop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kBit);
        return;
      }
      case IrOpcode::kObjectIsDetectableCallable: {
        VisitObjectIs<T>(node, Type::DetectableCallable(), lowering);
        return;
      }
      case IrOpcode::kObjectIsFiniteNumber: {
        Type const input_type = GetUpperBound(node->InputAt(0));
        if (input_type.Is(type_cache_->kSafeInteger)) {
          VisitUnop<T>(node, UseInfo::None(), MachineRepresentation::kBit);
          if (lower<T>()) {
            DeferReplacement(
                node, InsertTypeOverrideForVerifier(
                          true_type(), lowering->jsgraph()->Int32Constant(1)));
          }
        } else if (!input_type.Maybe(Type::Number())) {
          VisitUnop<T>(node, UseInfo::Any(), MachineRepresentation::kBit);
          if (lower<T>()) {
            DeferReplacement(
                node, InsertTypeOverrideForVerifier(
                          false_type(), lowering->jsgraph()->Int32Constant(0)));
          }
        } else if (input_type.Is(Type::Number())) {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kBit);
          if (lower<T>()) {
            ChangeOp(node, lowering->simplified()->NumberIsFinite());
          }
        } else {
          VisitUnop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kBit);
        }
        return;
      }
      case IrOpcode::kNumberIsFinite: {
        VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                     MachineRepresentation::kBit);
        return;
      }
      case IrOpcode::kObjectIsSafeInteger: {
        Type const input_type = GetUpperBound(node->InputAt(0));
        if (input_type.Is(type_cache_->kSafeInteger)) {
          VisitUnop<T>(node, UseInfo::None(), MachineRepresentation::kBit);
          if (lower<T>()) {
            DeferReplacement(
                node, InsertTypeOverrideForVerifier(
                          true_type(), lowering->jsgraph()->Int32Constant(1)));
          }
        } else if (!input_type.Maybe(Type::Number())) {
          VisitUnop<T>(node, UseInfo::Any(), MachineRepresentation::kBit);
          if (lower<T>()) {
            DeferReplacement(
                node, InsertTypeOverrideForVerifier(
                          false_type(), lowering->jsgraph()->Int32Constant(0)));
          }
        } else if (input_type.Is(Type::Number())) {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kBit);
          if (lower<T>()) {
            ChangeOp(node, lowering->simplified()->NumberIsSafeInteger());
          }
        } else {
          VisitUnop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kBit);
        }
        return;
      }
      case IrOpcode::kNumberIsSafeInteger: {
        UNREACHABLE();
      }
      case IrOpcode::kObjectIsInteger: {
        Type const input_type = GetUpperBound(node->InputAt(0));
        if (input_type.Is(type_cache_->kSafeInteger)) {
          VisitUnop<T>(node, UseInfo::None(), MachineRepresentation::kBit);
          if (lower<T>()) {
            DeferReplacement(
                node, InsertTypeOverrideForVerifier(
                          true_type(), lowering->jsgraph()->Int32Constant(1)));
          }
        } else if (!input_type.Maybe(Type::Number())) {
          VisitUnop<T>(node, UseInfo::Any(), MachineRepresentation::kBit);
          if (lower<T>()) {
            DeferReplacement(
                node, InsertTypeOverrideForVerifier(
                          false_type(), lowering->jsgraph()->Int32Constant(0)));
          }
        } else if (input_type.Is(Type::Number())) {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kBit);
          if (lower<T>()) {
            ChangeOp(node, lowering->simplified()->NumberIsInteger());
          }
        } else {
          VisitUnop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kBit);
        }
        return;
      }
      case IrOpcode::kNumberIsInteger: {
        VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                     MachineRepresentation::kBit);
        return;
      }
      case IrOpcode::kObjectIsMinusZero: {
        Type const input_type = GetUpperBound(node->InputAt(0));
        if (input_type.Is(Type::MinusZero())) {
          VisitUnop<T>(node, UseInfo::None(), MachineRepresentation::kBit);
          if (lower<T>()) {
            DeferReplacement(
                node, InsertTypeOverrideForVerifier(
                          true_type(), lowering->jsgraph()->Int32Constant(1)));
          }
        } else if (!input_type.Maybe(Type::MinusZero())) {
          VisitUnop<T>(node, UseInfo::Any(), MachineRepresentation::kBit);
          if (lower<T>()) {
            DeferReplacement(
                node, InsertTypeOverrideForVerifier(
                          false_type(), lowering->jsgraph()->Int32Constant(0)));
          }
        } else if (input_type.Is(Type::Number())) {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kBit);
          if (lower<T>()) {
            ChangeOp(node, simplified()->NumberIsMinusZero());
          }
        } else {
          VisitUnop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kBit);
        }
        return;
      }
      case IrOpcode::kObjectIsNaN: {
        Type const input_type = GetUpperBound(node->InputAt(0));
        if (input_type.Is(Type::NaN())) {
          VisitUnop<T>(node, UseInfo::None(), MachineRepresentation::kBit);
          if (lower<T>()) {
            DeferReplacement(
                node, InsertTypeOverrideForVerifier(
                          true_type(), lowering->jsgraph()->Int32Constant(1)));
          }
        } else if (!input_type.Maybe(Type::NaN())) {
          VisitUnop<T>(node, UseInfo::Any(), MachineRepresentation::kBit);
          if (lower<T>()) {
            DeferReplacement(
                node, InsertTypeOverrideForVerifier(
                          false_type(), lowering->jsgraph()->Int32Constant(0)));
          }
        } else if (input_type.Is(Type::Number())) {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kBit);
          if (lower<T>()) {
            ChangeOp(node, simplified()->NumberIsNaN());
          }
        } else {
          VisitUnop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kBit);
        }
        return;
      }
      case IrOpcode::kNumberIsNaN: {
        VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                     MachineRepresentation::kBit);
        return;
      }
      case IrOpcode::kObjectIsNonCallable: {
        VisitObjectIs<T>(node, Type::NonCallable(), lowering);
        return;
      }
      case IrOpcode::kObjectIsNumber: {
        VisitObjectIs<T>(node, Type::Number(), lowering);
        return;
      }
      case IrOpcode::kObjectIsReceiver: {
        VisitObjectIs<T>(node, Type::Receiver(), lowering);
        return;
      }
      case IrOpcode::kObjectIsSmi: {
        // TODO(turbofan): Optimize based on input representation.
        VisitUnop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kBit);
        return;
      }
      case IrOpcode::kObjectIsString: {
        VisitObjectIs<T>(node, Type::String(), lowering);
        return;
      }
      case IrOpcode::kObjectIsSymbol: {
        VisitObjectIs<T>(node, Type::Symbol(), lowering);
        return;
      }
      case IrOpcode::kObjectIsUndetectable: {
        VisitObjectIs<T>(node, Type::Undetectable(), lowering);
        return;
      }
      case IrOpcode::kArgumentsLength:
      case IrOpcode::kRestLength: {
        SetOutput<T>(node, MachineRepresentation::kTaggedSigned);
        return;
      }
      case IrOpcode::kNewDoubleElements:
      case IrOpcode::kNewSmiOrObjectElements: {
        VisitUnop<T>(node, UseInfo::Word(),
                     MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kNewArgumentsElements: {
        VisitUnop<T>(node, UseInfo::TaggedSigned(),
                     MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kCheckFloat64Hole: {
        Type const input_type = TypeOf(node->InputAt(0));
        CheckFloat64HoleMode mode =
            CheckFloat64HoleParametersOf(node->op()).mode();
        if (mode == CheckFloat64HoleMode::kAllowReturnHole) {
          // If {mode} is allow-return-hole _and_ the {truncation}
          // identifies NaN and undefined, we can just pass along
          // the {truncation} and completely wipe the {node}.
          if (truncation.IsUnused()) return VisitUnused<T>(node);
          if (truncation.TruncatesOddballAndBigIntToNumber()) {
            VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                         MachineRepresentation::kFloat64);
            if (lower<T>()) DeferReplacement(node, node->InputAt(0));
            return;
          }
        }
        VisitUnop<T>(
            node, UseInfo(MachineRepresentation::kFloat64, Truncation::Any()),
            MachineRepresentation::kFloat64, Type::Number());
        if (lower<T>() && input_type.Is(Type::Number())) {
          DeferReplacement(node, node->InputAt(0));
        }
        return;
      }
      case IrOpcode::kChangeFloat64HoleToTagged: {
        // If the {truncation} identifies NaN and undefined, we can just pass
        // along the {truncation} and completely wipe the {node}.
        if (truncation.IsUnused()) return VisitUnused<T>(node);
        if (truncation.TruncatesOddballAndBigIntToNumber()) {
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kFloat64);
          if (lower<T>()) DeferReplacement(node, node->InputAt(0));
          return;
        }
        VisitUnop<T>(
            node, UseInfo(MachineRepresentation::kFloat64, Truncation::Any()),
            MachineRepresentation::kTagged);
        return;
      }
      case IrOpcode::kCheckNotTaggedHole: {
        VisitUnop<T>(node, UseInfo::AnyTagged(),
                     MachineRepresentation::kTagged);
        return;
      }
      case IrOpcode::kCheckClosure: {
        VisitUnop<T>(
            node, UseInfo::CheckedHeapObjectAsTaggedPointer(FeedbackSource()),
            MachineRepresentation::kTaggedPointer);
        return;
      }
      case IrOpcode::kConvertTaggedHoleToUndefined: {
        if (InputIs(node, Type::NumberOrHole()) &&
            truncation.IsUsedAsWord32()) {
          // Propagate the Word32 truncation.
          VisitUnop<T>(node, UseInfo::TruncatingWord32(),
                       MachineRepresentation::kWord32);
          if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        } else if (InputIs(node, Type::NumberOrHole()) &&
                   truncation.TruncatesOddballAndBigIntToNumber()) {
          // Propagate the Float64 truncation.
          VisitUnop<T>(node, UseInfo::TruncatingFloat64(),
                       MachineRepresentation::kFloat64);
          if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        } else if (InputIs(node, Type::NonInternal())) {
          VisitUnop<T>(node, UseInfo::AnyTagged(),
                       MachineRepresentation::kTagged);
          if (lower<T>()) DeferReplacement(node, node->InputAt(0));
        } else {
          // TODO(turbofan): Add a (Tagged) truncation that identifies hole
          // and undefined, i.e. for a[i] === obj cases.
          VisitUnop<T>(node, UseInfo::AnyTagged(),
                       MachineRepresentation::kTagged);
        }
        return;
      }
      case IrOpcode::kCheckEqualsSymbol:
      case IrOpcode::kCheckEqualsInternalizedString:
        return VisitBinop<T>(node, UseInfo::AnyTagged(),
                             MachineRepresentation::kNone);
      case IrOpcode::kMapGuard:
        // Eliminate MapGuard nodes here.
        return VisitUnused<T>(node);
      case IrOpcode::kCheckMaps: {
        CheckMapsParameters const& p = CheckMapsParametersOf(node->op());
        return VisitUnop<T>(
            node, UseInfo::CheckedHeapObjectAsTaggedPointer(p.feedback()),
            MachineRepresentation::kNone);
      }
      case IrOpcode::kTransitionElementsKind: {
        return VisitUnop<T>(
            node, UseInfo::CheckedHeapObjectAsTaggedPointer(FeedbackSource()),
            MachineRepresentation::kNone);
      }
      case IrOpcode::kCompareMaps:
        return VisitUnop<T>(
            node, UseInfo::CheckedHeapObjectAsTaggedPointer(FeedbackSource()),
            MachineRepresentation::kBit);
      case IrOpcode::kEnsureWritableFastElements:
        return VisitBinop<T>(node, UseInfo::AnyTagged(),
                             MachineRepresentation::kTaggedPointer);
      case IrOpcode::kMaybeGrowFastElements: {
        ProcessInput<T>(node, 0, UseInfo::AnyTagged());         // object
        ProcessInput<T>(node, 1, UseInfo::AnyTagged());         // elements
        ProcessInput<T>(node, 2, UseInfo::TruncatingWord32());  // index
        ProcessInput<T>(node, 3, UseInfo::TruncatingWord32());  // length
        ProcessRemainingInputs<T>(node, 4);
        SetOutput<T>(node, MachineRepresentation::kTaggedPointer);
        return;
      }

      case IrOpcode::kDateNow:
        VisitInputs<T>(node);
        return SetOutput<T>(node, MachineRepresentation::kTagged);
      case IrOpcode::kDoubleArrayMax: {
        return VisitUnop<T>(node, UseInfo::AnyTagged(),
                            MachineRepresentation::kTagged);
      }
      case IrOpcode::kDoubleArrayMin: {
        return VisitUnop<T>(node, UseInfo::AnyTagged(),
                            MachineRepresentation::kTagged);
      }
      case IrOpcode::kFrameState:
        return VisitFrameState<T>(FrameState{node});
      case IrOpcode::kStateValues:
        return VisitStateValues<T>(node);
      case IrOpcode::kObjectState:
        return VisitObjectState<T>(node);
      case IrOpcode::kObjectId:
        return SetOutput<T>(node, MachineRepresentation::kTaggedPointer);

      case IrOpcode::kTypeGuard: {
        if (truncation.IsUnused()) return VisitUnused<T>(node);

        // We just get rid of the sigma here, choosing the best representation
        // for the sigma's type.
        Type type = TypeOf(node);
        MachineRepresentation representation =
            GetOutputInfoForPhi(type, truncation);

        // Here we pretend that the input has the sigma's type for the
        // conversion.
        UseInfo use(representation, truncation);
        if (propagate<T>()) {
          EnqueueInput<T>(node, 0, use);
        } else if (lower<T>()) {
          ConvertInput(node, 0, use, type);
        }
        ProcessRemainingInputs<T>(node, 1);
        SetOutput<T>(node, representation);
        return;
      }

      case IrOpcode::kFinishRegion:
        VisitInputs<T>(node);
        // Assume the output is tagged pointer.
        return SetOutput<T>(node, MachineRepresentation::kTaggedPointer);

      case IrOpcode::kReturn:
        VisitReturn<T>(node);
        // Assume the output is tagged.
        return SetOutput<T>(node, MachineRepresentation::kTagged);

      case IrOpcode::kFindOrderedHashMapEntry: {
        Type const key_type = TypeOf(node->InputAt(1));
        if (key_type.Is(Type::Signed32OrMinusZero())) {
          VisitBinop<T>(node, UseInfo::AnyTagged(), UseInfo::TruncatingWord32(),
                        MachineType::PointerRepresentation());
          if (lower<T>()) {
            ChangeOp(
                node,
                lowering->simplified()->FindOrderedHashMapEntryForInt32Key());
          }
        } else {
          VisitBinop<T>(node, UseInfo::AnyTagged(),
                        MachineRepresentation::kTaggedSigned);
        }
        return;
      }

      case IrOpcode::kFindOrderedHashSetEntry:
        VisitBinop<T>(node, UseInfo::AnyTagged(),
                      MachineRepresentation::kTaggedSigned);
        return;

      case IrOpcode::kFastApiCall: {
        VisitFastApiCall<T>(node, lowering);
        return;
      }

      // Operators with all inputs tagged and no or tagged output have uniform
      // handling.
      case IrOpcode::kEnd:
      case IrOpcode::kIfSuccess:
      case IrOpcode::kIfException:
      case IrOpcode::kIfTrue:
      case IrOpcode::kIfFalse:
      case IrOpcode::kIfValue:
      case IrOpcode::kIfDefault:
      case IrOpcode::kDeoptimize:
      case IrOpcode::kEffectPhi:
      case IrOpcode::kTerminate:
      case IrOpcode::kCheckpoint:
      case IrOpcode::kLoop:
      case IrOpcode::kMerge:
      case IrOpcode::kThrow:
      case IrOpcode::kBeginRegion:
      case IrOpcode::kProjection:
      case IrOpcode::kOsrValue:
      case IrOpcode::kArgumentsElementsState:
      case IrOpcode::kArgumentsLengthState:
      case IrOpcode::kUnreachable:
      case IrOpcode::kRuntimeAbort:
// All JavaScript operators except JSToNumber, JSToNumberConvertBigInt,
// kJSToNumeric and JSWasmCall have uniform handling.
#define OPCODE_CASE(name, ...) case IrOpcode::k##name:
        JS_SIMPLE_BINOP_LIST(OPCODE_CASE)
        JS_OBJECT_OP_LIST(OPCODE_CASE)
        JS_CONTEXT_OP_LIST(OPCODE_CASE)
        JS_OTHER_OP_LIST(OPCODE_CASE)
#undef OPCODE_CASE
      case IrOpcode::kJSBitwiseNot:
      case IrOpcode::kJSDecrement:
      case IrOpcode::kJSIncrement:
      case IrOpcode::kJSNegate:
      case IrOpcode::kJSToLength:
      case IrOpcode::kJSToName:
      case IrOpcode::kJSToObject:
      case IrOpcode::kJSToString:
      case IrOpcode::kJSParseInt:
#if V8_ENABLE_WEBASSEMBLY
        if (node->opcode() == IrOpcode::kJSWasmCall) {
          return VisitJSWasmCall<T>(node, lowering);
        }
#endif  // V8_ENABLE_WEBASSEMBLY
        VisitInputs<T>(node);
        // Assume the output is tagged.
        return SetOutput<T>(node, MachineRepresentation::kTagged);
      case IrOpcode::kDeadValue:
        ProcessInput<T>(node, 0, UseInfo::Any());
        return SetOutput<T>(node, MachineRepresentation::kNone);
      case IrOpcode::kStaticAssert:
        DCHECK(TypeOf(node->InputAt(0)).Is(Type::Boolean()));
        return VisitUnop<T>(node, UseInfo::Bool(),
                            MachineRepresentation::kTagged);
      case IrOpcode::kAssertType:
        return VisitUnop<T>(node, UseInfo::AnyTagged(),
                            MachineRepresentation::kTagged);
      case IrOpcode::kVerifyType: {
        Type inputType = TypeOf(node->InputAt(0));
        VisitUnop<T>(node, UseInfo::AnyTagged(), MachineRepresentation::kTagged,
                     inputType);
        if (lower<T>()) {
          if (inputType.CanBeAsserted()) {
            ChangeOp(node, simplified()->AssertType(inputType));
          } else {
            if (!v8_flags.fuzzing) {
#ifdef DEBUG
              inputType.Print();
#endif
              FATAL("%%VerifyType: unsupported type");
            }
            DisconnectFromEffectAndControl(node);
          }
        }
        return;
      }
      case IrOpcode::kCheckTurboshaftTypeOf: {
        NodeInfo* info = GetInfo(node->InputAt(0));
        MachineRepresentation input_rep = info->representation();
        ProcessInput<T>(node, 0, UseInfo{input_rep, Truncation::None()});
        ProcessInput<T>(node, 1, UseInfo::Any());
        SetOutput<T>(node, input_rep);
        return;
      }
      case IrOpcode::kDebugBreak:
        return;

      // Nodes from machine graphs.
      case IrOpcode::kEnterMachineGraph: {
        DCHECK_EQ(1, node->op()->ValueInputCount());
        UseInfo use_info = OpParameter<UseInfo>(node->op());
        ProcessInput<T>(node, 0, use_info);
        SetOutput<T>(node, use_info.representation());
        if (lower<T>()) {
          DeferReplacement(node, InsertTypeOverrideForVerifier(
                                     Type::Machine(), node->InputAt(0)));
        }
        return;
      }
      case IrOpcode::kExitMachineGraph: {
        DCHECK_EQ(1, node->op()->ValueInputCount());
        ProcessInput<T>(node, 0, UseInfo::Any());
        const auto& p = ExitMachineGraphParametersOf(node->op());
        SetOutput<T>(node, p.output_representation(), p.output_type());
        if (lower<T>()) {
          DeferReplacement(node, InsertTypeOverrideForVerifier(
                                     p.output_type(), node->InputAt(0)));
        }
        return;
      }
      case IrOpcode::kInt32Add:
      case IrOpcode::kInt32LessThanOrEqual:
      case IrOpcode::kInt32Sub:
      case IrOpcode::kUint32LessThan:
      case IrOpcode::kUint32LessThanOrEqual:
      case IrOpcode::kUint64LessThan:
      case IrOpcode::kUint64LessThanOrEqual:
      case IrOpcode::kUint32Div:
      case IrOpcode::kWord32And:
      case IrOpcode::kWord32Equal:
      case IrOpcode::kWord32Or:
      case IrOpcode::kWord32Shl:
      case IrOpcode::kWord32Shr:
        for (int i = 0; i < node->InputCount(); ++i) {
          ProcessInput<T>(node, i, UseInfo::Any());
        }
        SetOutput<T>(node, MachineRepresentation::kWord32);
        return;
      case IrOpcode::kInt64Add:
      case IrOpcode::kInt64Sub:
      case IrOpcode::kUint64Div:
      case IrOpcode::kWord64And:
      case IrOpcode::kWord64Shl:
      case IrOpcode::kWord64Shr:
      case IrOpcode::kChangeUint32ToUint64:
        for (int i = 0; i < node->InputCount(); ++i) {
          ProcessInput<T>(node, i, UseInfo::Any());
        }
        SetOutput<T>(node, MachineRepresentation::kWord64);
        return;
      case IrOpcode::kLoad:
        for (int i = 0; i < node->InputCount(); ++i) {
          ProcessInput<T>(node, i, UseInfo::Any());
        }
        SetOutput<T>(node, LoadRepresentationOf(node->op()).representation());
        return;

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
      case IrOpcode::kGetContinuationPreservedEmbedderData:
        SetOutput<T>(node, MachineRepresentation::kTagged);
        return;

      case IrOpcode::kSetContinuationPreservedEmbedderData:
        ProcessInput<T>(node, 0, UseInfo::AnyTagged());
        SetOutput<T>(node, MachineRepresentation::kNone);
        return;
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

      default:
        FATAL(
            "Representation inference: unsupported opcode %i (%s), node #%i\n.",
            node->opcode(), node->op()->mnemonic(), node->id());
        break;
    }
    UNREACHABLE();
  }

  void DisconnectFromEffectAndControl(Node* node) {
    if (node->op()->EffectInputCount() == 1) {
      Node* control;
      if (node->op()->ControlInputCount() == 1) {
        control = NodeProperties::GetControlInput(node);
      } else {
        DCHECK_EQ(node->op()->ControlInputCount(), 0);
        control = nullptr;
      }
      Node* effect = NodeProperties::GetEffectInput(node);
      ReplaceEffectControlUses(node, effect, control);
    } else {
      DCHECK_EQ(0, node->op()->EffectInputCount());
      DCHECK_EQ(0, node->op()->ControlOutputCount());
      DCHECK_EQ(0, node->op()->EffectOutputCount());
    }
  }

  void DeferReplacement(Node* node, Node* replacement) {
    TRACE("defer replacement #%d:%s with #%d:%s\n", node->id(),
          node->op()->mnemonic(), replacement->id(),
          replacement->op()->mnemonic());

    DisconnectFromEffectAndControl(node);
    node->NullAllInputs();  // Node is now dead.

    replacements_.push_back(node);
    replacements_.push_back(replacement);

    NotifyNodeReplaced(node, replacement);
  }

  Node* InsertTypeOverrideForVerifier(const Type& type, Node* node) {
    if (V8_UNLIKELY(verification_enabled())) {
      DCHECK(!type.IsInvalid());
      node = graph()->NewNode(common()->SLVerifierHint(nullptr, type), node);
      verifier_->RecordHint(node);
    }
    return node;
  }

  Node* InsertSemanticsHintForVerifier(const Operator* semantics, Node* node) {
    if (V8_UNLIKELY(verification_enabled())) {
      node = graph()->NewNode(common()->SLVerifierHint(semantics, {}), node);
      verifier_->RecordHint(node);
    }
    return node;
  }

 private:
  void ChangeOp(Node* node, const Operator* new_op) {
    compiler::NodeProperties::ChangeOp(node, new_op);

    if (V8_UNLIKELY(observe_node_manager_ != nullptr))
      observe_node_manager_->OnNodeChanged(kSimplifiedLoweringReducerName, node,
                                           node);
  }

  void NotifyNodeReplaced(Node* node, Node* replacement) {
    if (V8_UNLIKELY(observe_node_manager_ != nullptr))
      observe_node_manager_->OnNodeChanged(kSimplifiedLoweringReducerName, node,
                                           replacement);
  }

  Type true_type() const { return singleton_true_; }
  Type false_type() const { return singleton_false_; }

  JSGraph* jsgraph_;
  JSHeapBroker*
```