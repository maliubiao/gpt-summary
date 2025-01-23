Response: The user is asking for a summary of the C++ code provided, which is the second part of a file named `graph-builder.cc`. I need to understand the purpose of this code snippet and its relation to JavaScript.

The code consists of a large `switch` statement within a method called `EmitNode`. This method seems to handle different types of intermediate representation (IR) nodes and translates them into lower-level operations. The `IrOpcode` enum in the `case` labels suggests that this code is part of a compiler, likely V8's Turboshaft compiler, as indicated by the file path.

The code generates machine-level operations based on the semantics of the IR nodes. Many of the cases directly correspond to JavaScript operations.

Here's a plan:
1. **Identify the core functionality:** The primary goal is to translate IR nodes into lower-level operations.
2. **Categorize the handled IR opcodes:** Group the cases in the `switch` statement by the JavaScript features they relate to.
3. **Provide a high-level summary:**  Describe the overall function of the code.
4. **Give specific examples in JavaScript:** Illustrate how some of the C++ code relates to concrete JavaScript constructs.
This C++ code snippet is part of the **Turboshaft graph builder** in the V8 JavaScript engine. It represents the **second half of the `EmitNode` function**, which is responsible for **translating high-level, platform-independent intermediate representation (IR) nodes into low-level, platform-specific operations** that can be executed by the machine.

Specifically, this part of the code handles a wide variety of IR opcodes related to:

* **Memory Access:**  Storing and loading values from objects and arrays (`kStoreElement`, `kStoreField`, `kLoadFromObject`, `kLoadField`, `kLoadElement`).
* **Object and Array Manipulation:** Creating new strings and arrays (`kNewConsString`, `kNewDoubleElements`, `kNewSmiOrObjectElements`), and handling array transitions (`kTransitionAndStoreElement`, `kTransitionElementsKind`).
* **Checked Arithmetic Operations:** Performing arithmetic operations with overflow checks (`kCheckedInt32Add`, `kCheckedInt64Sub`, `kCheckedInt32Mul`, etc.).
* **BigInt Operations:** Supporting arithmetic and comparison operations on BigInts (`kBigIntAdd`, `kBigIntSubtract`, `kBigIntEqual`, etc.).
* **String Operations:** Implementing various string manipulations like character access, searching, concatenation, and comparison (`kStringCharCodeAt`, `kStringIndexOf`, `kStringConcat`, `kStringEqual`, etc.).
* **Function Arguments:** Handling access to function arguments (`kArgumentsLength`, `kRestLength`, `kNewArgumentsElements`).
* **Typed Arrays and DataViews:**  Loading and storing elements in TypedArrays and DataViews (`kLoadTypedElement`, `kStoreTypedElement`, `kLoadDataViewElement`, `kStoreDataViewElement`).
* **Map Checks and Comparisons:** Verifying the type or structure of objects (`kCompareMaps`, `kCheckMaps`).
* **Bounds Checking:** Ensuring array or buffer accesses are within valid limits (`kCheckedUint32Bounds`, `kCheckedUint64Bounds`).
* **Deoptimization:** Triggering deoptimization based on certain conditions (`kCheckIf`, `kCheckClosure`, `kCheckEqualsSymbol`, `kCheckFloat64Hole`, `kCheckNotTaggedHole`).
* **Runtime Calls:** Invoking built-in runtime functions for tasks like getting the current time or handling type checking (`kDateNow`, `kTypeOf`).
* **Fast API Calls:** Optimizing calls to native C++ functions (`kFastApiCall`).
* **Atomic Operations:** Performing atomic memory operations for concurrent programming (`kWord32AtomicLoad`, `kWord64AtomicStore`, `kWord32AtomicAdd`, etc.).
* **SIMD Operations:**  Implementing operations for Single Instruction, Multiple Data (SIMD) for improved performance on vector data (`kI8x16Add`, `kF32x4Mul`, etc.).
* **Stack Manipulation:** Operations related to the call stack (`kLoadStackArgument`, `kLoadStackPointer`, `kSetStackPointer`).
* **Debugging and Assertions:**  Including debugging aids and runtime assertions (`kDebugBreak`, `kAssert`).
* **Continuation Preserved Embedder Data:** Handling data associated with continuations (`kGetContinuationPreservedEmbedderData`, `kSetContinuationPreservedEmbedderData`).

**In essence, this code bridges the gap between the high-level understanding of JavaScript code and the low-level machine instructions needed to execute it efficiently.** It takes the abstract operations represented by the IR and translates them into concrete actions like memory loads, stores, arithmetic operations, and function calls.

**Relationship to JavaScript and Examples:**

Many of the IR opcodes directly correspond to JavaScript language features. Here are a few examples:

**1. Memory Access (`kStoreField`, `kLoadField`):**

```javascript
const obj = { x: 10 };
const value = obj.x; // Corresponds to kLoadField
obj.x = 20;         // Corresponds to kStoreField
```

The `kLoadField` case in the C++ code would handle the operation of reading the value of the `x` property from the `obj` object. The `kStoreField` case would handle the operation of writing the value `20` to the `x` property of `obj`.

**2. Array Element Access (`kStoreElement`, `kLoadElement`):**

```javascript
const arr = [1, 2, 3];
const firstElement = arr[0]; // Corresponds to kLoadElement
arr[1] = 4;                 // Corresponds to kStoreElement
```

The `kLoadElement` case would handle reading the element at index `0` from the `arr` array. The `kStoreElement` case would handle writing the value `4` to the element at index `1` in `arr`.

**3. String Concatenation (`kStringConcat`):**

```javascript
const str1 = "hello";
const str2 = " world";
const combined = str1 + str2; // Corresponds to kStringConcat
```

The `kStringConcat` case would handle the operation of joining the two strings "hello" and " world" to create a new string "hello world".

**4. Checked Arithmetic (`kCheckedInt32Add`):**

```javascript
let a = 2147483647; // Maximum 32-bit signed integer
let b = 1;
let sum = a + b; // Might cause overflow, handled by kCheckedInt32Add
```

The `kCheckedInt32Add` case would handle the addition of `a` and `b`, but with a check for potential integer overflow. If an overflow occurs, it might trigger a deoptimization or throw an error.

**5. BigInt Arithmetic (`kBigIntAdd`):**

```javascript
const bigInt1 = 9007199254740991n;
const bigInt2 = 1n;
const bigIntSum = bigInt1 + bigInt2; // Corresponds to kBigIntAdd
```

The `kBigIntAdd` case would handle the addition of the two BigInt values.

In summary, this code is a crucial part of V8's compilation pipeline, responsible for generating the low-level instructions that bring JavaScript code to life. It handles a vast array of JavaScript operations, ensuring efficient execution by translating them into optimized machine code.

### 提示词
```
这是目录为v8/src/compiler/turboshaft/graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
node->InputAt(1);
      Node* value = node->InputAt(2);
      ObjectAccess const& access = ObjectAccessOf(node->op());
      bool initializing_transitioning = inside_region;
      __ Store(Map(object), Map(offset), Map(value),
               StoreOp::Kind::TaggedBase(),
               MemoryRepresentation::FromMachineType(access.machine_type),
               access.write_barrier_kind, kHeapObjectTag,
               initializing_transitioning);
      return OpIndex::Invalid();
    }
    case IrOpcode::kStoreElement: {
      Node* object = node->InputAt(0);
      Node* index = node->InputAt(1);
      Node* value = node->InputAt(2);
      ElementAccess const& access = ElementAccessOf(node->op());
      DCHECK(!access.machine_type.IsMapWord());
      StoreOp::Kind kind = StoreOp::Kind::Aligned(access.base_is_tagged);
      MemoryRepresentation rep =
          MemoryRepresentation::FromMachineType(access.machine_type);
      bool initializing_transitioning = inside_region;
      __ Store(Map(object), Map(index), Map(value), kind, rep,
               access.write_barrier_kind, access.header_size,
               rep.SizeInBytesLog2(), initializing_transitioning);
      return OpIndex::Invalid();
    }
    case IrOpcode::kStoreField: {
      OpIndex object = Map(node->InputAt(0));
      OpIndex value = Map(node->InputAt(1));
      FieldAccess const& access = FieldAccessOf(node->op());
      // External pointer must never be stored by optimized code.
      DCHECK(!access.type.Is(compiler::Type::ExternalPointer()) ||
             !V8_ENABLE_SANDBOX_BOOL);
      // SandboxedPointers are not currently stored by optimized code.
      DCHECK(!access.type.Is(compiler::Type::SandboxedPointer()));

#ifdef V8_ENABLE_SANDBOX
      if (access.is_bounded_size_access) {
        value = __ ShiftLeft(value, kBoundedSizeShift,
                             WordRepresentation::WordPtr());
      }
#endif  // V8_ENABLE_SANDBOX

      StoreOp::Kind kind = StoreOp::Kind::Aligned(access.base_is_tagged);
      MachineType machine_type = access.machine_type;
      if (machine_type.IsMapWord()) {
        machine_type = MachineType::TaggedPointer();
#ifdef V8_MAP_PACKING
        UNIMPLEMENTED();
#endif
      }

      bool initializing_transitioning =
          access.maybe_initializing_or_transitioning_store;
      if (!inside_region) {
        // Mark stores outside a region as non-initializing and
        // non-transitioning.
        initializing_transitioning = false;
      }

      MemoryRepresentation rep =
          MemoryRepresentation::FromMachineType(machine_type);

      __ Store(object, value, kind, rep, access.write_barrier_kind,
               access.offset, initializing_transitioning,
               access.indirect_pointer_tag);
      return OpIndex::Invalid();
    }
    case IrOpcode::kLoadFromObject:
    case IrOpcode::kLoadImmutableFromObject: {
      Node* object = node->InputAt(0);
      Node* offset = node->InputAt(1);
      ObjectAccess const& access = ObjectAccessOf(node->op());
      MemoryRepresentation rep =
          MemoryRepresentation::FromMachineType(access.machine_type);
      return __ Load(Map(object), Map(offset), LoadOp::Kind::TaggedBase(), rep,
                     kHeapObjectTag);
    }
    case IrOpcode::kLoadField: {
      Node* object = node->InputAt(0);
      FieldAccess const& access = FieldAccessOf(node->op());
      StoreOp::Kind kind = StoreOp::Kind::Aligned(access.base_is_tagged);
      MachineType machine_type = access.machine_type;
      if (machine_type.IsMapWord()) {
        machine_type = MachineType::TaggedPointer();
#ifdef V8_MAP_PACKING
        UNIMPLEMENTED();
#endif
      }
      MemoryRepresentation rep =
          MemoryRepresentation::FromMachineType(machine_type);
#ifdef V8_ENABLE_SANDBOX
      bool is_sandboxed_external =
          access.type.Is(compiler::Type::ExternalPointer());
      if (is_sandboxed_external) {
        // Fields for sandboxed external pointer contain a 32-bit handle, not a
        // 64-bit raw pointer.
        rep = MemoryRepresentation::Uint32();
      }
#endif  // V8_ENABLE_SANDBOX
      OpIndex value = __ Load(Map(object), kind, rep, access.offset);
#ifdef V8_ENABLE_SANDBOX
      if (is_sandboxed_external) {
        value = __ DecodeExternalPointer(value, access.external_pointer_tag);
      }
      if (access.is_bounded_size_access) {
        DCHECK(!is_sandboxed_external);
        value = __ ShiftRightLogical(value, kBoundedSizeShift,
                                     WordRepresentation::WordPtr());
      }
#endif  // V8_ENABLE_SANDBOX
      return value;
    }
    case IrOpcode::kLoadElement: {
      Node* object = node->InputAt(0);
      Node* index = node->InputAt(1);
      ElementAccess const& access = ElementAccessOf(node->op());
      LoadOp::Kind kind = LoadOp::Kind::Aligned(access.base_is_tagged);
      MemoryRepresentation rep =
          MemoryRepresentation::FromMachineType(access.machine_type);
      return __ Load(Map(object), Map(index), kind, rep, access.header_size,
                     rep.SizeInBytesLog2());
    }
    case IrOpcode::kCheckTurboshaftTypeOf: {
      Node* input = node->InputAt(0);
      Node* type_description = node->InputAt(1);

      HeapObjectMatcher m(type_description);
      CHECK(m.HasResolvedValue() && m.Ref(broker).IsString() &&
            m.Ref(broker).AsString().IsContentAccessible());
      StringRef type_string = m.Ref(broker).AsString();
      DirectHandle<String> pattern_string =
          *type_string.ObjectIfContentAccessible(broker);
      std::unique_ptr<char[]> pattern = pattern_string->ToCString();

      auto type_opt =
          Type::ParseFromString(std::string_view{pattern.get()}, graph_zone);
      if (type_opt == std::nullopt) {
        FATAL(
            "String '%s' (of %d:CheckTurboshaftTypeOf) is not a valid type "
            "description!",
            pattern.get(), node->id());
      }

      OpIndex input_index = Map(input);
      RegisterRepresentation rep =
          __ output_graph().Get(input_index).outputs_rep()[0];
      return __ CheckTurboshaftTypeOf(input_index, rep, *type_opt, false);
    }

    case IrOpcode::kNewConsString:
      return __ NewConsString(Map(node->InputAt(0)), Map(node->InputAt(1)),
                              Map(node->InputAt(2)));
    case IrOpcode::kNewDoubleElements:
      return __ NewArray(Map(node->InputAt(0)), NewArrayOp::Kind::kDouble,
                         AllocationTypeOf(node->op()));
    case IrOpcode::kNewSmiOrObjectElements:
      return __ NewArray(Map(node->InputAt(0)), NewArrayOp::Kind::kObject,
                         AllocationTypeOf(node->op()));

    case IrOpcode::kDoubleArrayMin:
      return __ DoubleArrayMinMax(Map(node->InputAt(0)),
                                  DoubleArrayMinMaxOp::Kind::kMin);
    case IrOpcode::kDoubleArrayMax:
      return __ DoubleArrayMinMax(Map(node->InputAt(0)),
                                  DoubleArrayMinMaxOp::Kind::kMax);

    case IrOpcode::kLoadFieldByIndex:
      return __ LoadFieldByIndex(Map(node->InputAt(0)), Map(node->InputAt(1)));

    case IrOpcode::kCheckedInt64Add:
      DCHECK(Is64());
      DCHECK(dominating_frame_state.valid());
      return __ Word64SignedAddDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

    case IrOpcode::kCheckedInt64Sub:
      DCHECK(Is64());
      DCHECK(dominating_frame_state.valid());
      return __ Word64SignedSubDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

    case IrOpcode::kCheckedInt32Add:
      DCHECK(dominating_frame_state.valid());
      return __ Word32SignedAddDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

    case IrOpcode::kCheckedInt32Sub:
      DCHECK(dominating_frame_state.valid());
      return __ Word32SignedSubDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

    case IrOpcode::kCheckedInt32Mul: {
      DCHECK(dominating_frame_state.valid());
      CheckForMinusZeroMode mode = CheckMinusZeroModeOf(node->op());
      return __ Word32SignedMulDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{}, mode);
    }

    case IrOpcode::kCheckedInt64Mul:
      DCHECK(Is64());
      DCHECK(dominating_frame_state.valid());
      return __ Word64SignedMulDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

    case IrOpcode::kCheckedInt32Div:
      DCHECK(dominating_frame_state.valid());
      return __ Word32SignedDivDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

    case IrOpcode::kCheckedInt64Div:
      DCHECK(Is64());
      DCHECK(dominating_frame_state.valid());
      return __ Word64SignedDivDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

    case IrOpcode::kCheckedUint32Div:
      DCHECK(dominating_frame_state.valid());
      return __ Word32UnsignedDivDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

    case IrOpcode::kCheckedInt32Mod:
      DCHECK(dominating_frame_state.valid());
      return __ Word32SignedModDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

    case IrOpcode::kCheckedInt64Mod:
      DCHECK(Is64());
      DCHECK(dominating_frame_state.valid());
      return __ Word64SignedModDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

    case IrOpcode::kCheckedUint32Mod:
      DCHECK(dominating_frame_state.valid());
      return __ Word32UnsignedModDeoptOnOverflow(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          FeedbackSource{});

#define BIGINT_BINOP_CASE(op, kind)                                     \
  case IrOpcode::kBigInt##op:                                           \
    DCHECK(dominating_frame_state.valid());                             \
    return __ BigIntBinop(Map(node->InputAt(0)), Map(node->InputAt(1)), \
                          dominating_frame_state,                       \
                          BigIntBinopOp::Kind::k##kind);
      BIGINT_BINOP_CASE(Add, Add)
      BIGINT_BINOP_CASE(Subtract, Sub)
      BIGINT_BINOP_CASE(Multiply, Mul)
      BIGINT_BINOP_CASE(Divide, Div)
      BIGINT_BINOP_CASE(Modulus, Mod)
      BIGINT_BINOP_CASE(BitwiseAnd, BitwiseAnd)
      BIGINT_BINOP_CASE(BitwiseOr, BitwiseOr)
      BIGINT_BINOP_CASE(BitwiseXor, BitwiseXor)
      BIGINT_BINOP_CASE(ShiftLeft, ShiftLeft)
      BIGINT_BINOP_CASE(ShiftRight, ShiftRightArithmetic)
#undef BIGINT_BINOP_CASE

    case IrOpcode::kBigIntEqual:
      return __ BigIntEqual(Map(node->InputAt(0)), Map(node->InputAt(1)));

    case IrOpcode::kBigIntLessThan:
      return __ BigIntLessThan(Map(node->InputAt(0)), Map(node->InputAt(1)));
    case IrOpcode::kBigIntLessThanOrEqual:
      return __ BigIntLessThanOrEqual(Map(node->InputAt(0)),
                                      Map(node->InputAt(1)));

    case IrOpcode::kBigIntNegate:
      return __ BigIntNegate(Map<BigInt>(node->InputAt(0)));

    case IrOpcode::kLoadRootRegister:
      // Inlined usage of wasm root register operation in JS.
      return assembler.ReduceLoadRootRegister();

    case IrOpcode::kStringCharCodeAt:
      return __ StringCharCodeAt(Map(node->InputAt(0)), Map(node->InputAt(1)));
    case IrOpcode::kStringCodePointAt:
      return __ StringCodePointAt(Map(node->InputAt(0)), Map(node->InputAt(1)));

#ifdef V8_INTL_SUPPORT
    case IrOpcode::kStringToLowerCaseIntl:
      return __ StringToLowerCaseIntl(Map(node->InputAt(0)));
    case IrOpcode::kStringToUpperCaseIntl:
      return __ StringToUpperCaseIntl(Map(node->InputAt(0)));
#else
    case IrOpcode::kStringToLowerCaseIntl:
    case IrOpcode::kStringToUpperCaseIntl:
      UNREACHABLE();
#endif  // V8_INTL_SUPPORT

    case IrOpcode::kStringLength:
      return __ StringLength(Map(node->InputAt(0)));

    case IrOpcode::kStringWrapperLength: {
      V<String> str =
          __ LoadField<String>(Map<JSPrimitiveWrapper>(node->InputAt(0)),
                               AccessBuilder::ForJSPrimitiveWrapperValue());
      return __ StringLength(str);
    }

    case IrOpcode::kStringIndexOf:
      return __ StringIndexOf(Map(node->InputAt(0)), Map(node->InputAt(1)),
                              Map(node->InputAt(2)));

    case IrOpcode::kStringFromCodePointAt:
      return __ StringFromCodePointAt(Map(node->InputAt(0)),
                                      Map(node->InputAt(1)));

    case IrOpcode::kStringSubstring:
      return __ StringSubstring(Map(node->InputAt(0)), Map(node->InputAt(1)),
                                Map(node->InputAt(2)));

    case IrOpcode::kStringConcat:
      return __ StringConcat(Map(node->InputAt(0)), Map(node->InputAt(1)),
                             Map(node->InputAt(2)));

    case IrOpcode::kStringEqual:
      return __ StringEqual(Map(node->InputAt(0)), Map(node->InputAt(1)));
    case IrOpcode::kStringLessThan:
      return __ StringLessThan(Map(node->InputAt(0)), Map(node->InputAt(1)));
    case IrOpcode::kStringLessThanOrEqual:
      return __ StringLessThanOrEqual(Map(node->InputAt(0)),
                                      Map(node->InputAt(1)));

    case IrOpcode::kArgumentsLength:
      return __ ArgumentsLength();
    case IrOpcode::kRestLength:
      return __ RestLength(FormalParameterCountOf(node->op()));

    case IrOpcode::kNewArgumentsElements: {
      const auto& p = NewArgumentsElementsParametersOf(node->op());
      // EffectControlLinearizer used to use `node->op()->properties()` to
      // construct the builtin call descriptor for this operation. However, this
      // always seemed to be `kEliminatable` so the Turboshaft
      // BuiltinCallDescriptor's for those builtins have this property
      // hard-coded.
      DCHECK_EQ(node->op()->properties(), Operator::kEliminatable);
      return __ NewArgumentsElements(Map(node->InputAt(0)), p.arguments_type(),
                                     p.formal_parameter_count());
    }

    case IrOpcode::kLoadTypedElement:
      return __ LoadTypedElement(Map(node->InputAt(0)), Map(node->InputAt(1)),
                                 Map(node->InputAt(2)), Map(node->InputAt(3)),
                                 ExternalArrayTypeOf(node->op()));
    case IrOpcode::kLoadDataViewElement:
      return __ LoadDataViewElement(
          Map(node->InputAt(0)), Map(node->InputAt(1)), Map(node->InputAt(2)),
          Map(node->InputAt(3)), ExternalArrayTypeOf(node->op()));
    case IrOpcode::kLoadStackArgument:
      return __ LoadStackArgument(Map(node->InputAt(0)), Map(node->InputAt(1)));

    case IrOpcode::kStoreTypedElement:
      __ StoreTypedElement(Map(node->InputAt(0)), Map(node->InputAt(1)),
                           Map(node->InputAt(2)), Map(node->InputAt(3)),
                           Map(node->InputAt(4)),
                           ExternalArrayTypeOf(node->op()));
      return OpIndex::Invalid();
    case IrOpcode::kStoreDataViewElement:
      __ StoreDataViewElement(Map(node->InputAt(0)), Map(node->InputAt(1)),
                              Map(node->InputAt(2)), Map(node->InputAt(3)),
                              Map(node->InputAt(4)),
                              ExternalArrayTypeOf(node->op()));
      return OpIndex::Invalid();
    case IrOpcode::kTransitionAndStoreElement:
      __ TransitionAndStoreArrayElement(
          Map(node->InputAt(0)), Map(node->InputAt(1)), Map(node->InputAt(2)),
          TransitionAndStoreArrayElementOp::Kind::kElement,
          FastMapParameterOf(node->op()).object(),
          DoubleMapParameterOf(node->op()).object());
      return OpIndex::Invalid();
    case IrOpcode::kTransitionAndStoreNumberElement:
      __ TransitionAndStoreArrayElement(
          Map(node->InputAt(0)), Map(node->InputAt(1)), Map(node->InputAt(2)),
          TransitionAndStoreArrayElementOp::Kind::kNumberElement, {},
          DoubleMapParameterOf(node->op()).object());
      return OpIndex::Invalid();
    case IrOpcode::kTransitionAndStoreNonNumberElement: {
      auto kind =
          ValueTypeParameterOf(node->op())
                  .Is(compiler::Type::BooleanOrNullOrUndefined())
              ? TransitionAndStoreArrayElementOp::Kind::kOddballElement
              : TransitionAndStoreArrayElementOp::Kind::kNonNumberElement;
      __ TransitionAndStoreArrayElement(
          Map(node->InputAt(0)), Map(node->InputAt(1)), Map(node->InputAt(2)),
          kind, FastMapParameterOf(node->op()).object(), {});
      return OpIndex::Invalid();
    }
    case IrOpcode::kStoreSignedSmallElement:
      __ StoreSignedSmallElement(Map(node->InputAt(0)), Map(node->InputAt(1)),
                                 Map(node->InputAt(2)));
      return OpIndex::Invalid();

    case IrOpcode::kCompareMaps: {
      const ZoneRefSet<v8::internal::Map>& maps =
          CompareMapsParametersOf(node->op());
      return __ CompareMaps(Map(node->InputAt(0)), {}, maps);
    }

    case IrOpcode::kCheckMaps: {
      DCHECK(dominating_frame_state.valid());
      const auto& p = CheckMapsParametersOf(node->op());
      __ CheckMaps(Map(node->InputAt(0)), dominating_frame_state, {}, p.maps(),
                   p.flags(), p.feedback());
      return OpIndex{};
    }

    case IrOpcode::kCheckedUint32Bounds:
    case IrOpcode::kCheckedUint64Bounds: {
      WordRepresentation rep = node->opcode() == IrOpcode::kCheckedUint32Bounds
                                   ? WordRepresentation::Word32()
                                   : WordRepresentation::Word64();
      const CheckBoundsParameters& params = CheckBoundsParametersOf(node->op());
      OpIndex index = Map(node->InputAt(0));
      OpIndex limit = Map(node->InputAt(1));
      V<Word32> check = __ UintLessThan(index, limit, rep);
      if ((params.flags() & CheckBoundsFlag::kAbortOnOutOfBounds) != 0) {
        IF_NOT(LIKELY(check)) { __ Unreachable(); }

      } else {
        DCHECK(dominating_frame_state.valid());
        __ DeoptimizeIfNot(check, dominating_frame_state,
                           DeoptimizeReason::kOutOfBounds,
                           params.check_parameters().feedback());
      }
      return index;
    }

    case IrOpcode::kCheckIf: {
      DCHECK(dominating_frame_state.valid());
      const CheckIfParameters& params = CheckIfParametersOf(node->op());
      __ DeoptimizeIfNot(Map(node->InputAt(0)), dominating_frame_state,
                         params.reason(), params.feedback());
      return OpIndex::Invalid();
    }

    case IrOpcode::kCheckClosure:
      DCHECK(dominating_frame_state.valid());
      return __ CheckedClosure(Map(node->InputAt(0)), dominating_frame_state,
                               FeedbackCellOf(node->op()));

    case IrOpcode::kCheckEqualsSymbol:
      DCHECK(dominating_frame_state.valid());
      __ DeoptimizeIfNot(
          __ TaggedEqual(Map(node->InputAt(0)), Map(node->InputAt(1))),
          dominating_frame_state, DeoptimizeReason::kWrongName,
          FeedbackSource{});
      return OpIndex::Invalid();

    case IrOpcode::kCheckEqualsInternalizedString:
      DCHECK(dominating_frame_state.valid());
      __ CheckEqualsInternalizedString(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state);
      return OpIndex::Invalid();

    case IrOpcode::kCheckFloat64Hole: {
      DCHECK(dominating_frame_state.valid());
      V<Float64> value = Map(node->InputAt(0));
      // TODO(tebbi): If we did partial block cloning, we could emit a
      // `DeoptimizeIf` operation here. Alternatively, we could use a branch and
      // a separate block with an unconditional `Deoptimize`.
      return __ ChangeOrDeopt(
          value, dominating_frame_state, ChangeOrDeoptOp::Kind::kFloat64NotHole,
          CheckForMinusZeroMode::kDontCheckForMinusZero,
          CheckFloat64HoleParametersOf(node->op()).feedback());
    }

    case IrOpcode::kCheckNotTaggedHole: {
      DCHECK(dominating_frame_state.valid());
      V<Object> value = Map(node->InputAt(0));
      __ DeoptimizeIf(
          __ TaggedEqual(value,
                         __ HeapConstant(isolate->factory()->the_hole_value())),
          dominating_frame_state, DeoptimizeReason::kHole, FeedbackSource{});
      return value;
    }

    case IrOpcode::kLoadMessage:
      return __ LoadMessage(Map(node->InputAt(0)));
    case IrOpcode::kStoreMessage:
      __ StoreMessage(Map(node->InputAt(0)), Map(node->InputAt(1)));
      return OpIndex::Invalid();

    case IrOpcode::kSameValue:
      return __ SameValue(Map(node->InputAt(0)), Map(node->InputAt(1)),
                          SameValueOp::Mode::kSameValue);
    case IrOpcode::kSameValueNumbersOnly:
      return __ SameValue(Map(node->InputAt(0)), Map(node->InputAt(1)),
                          SameValueOp::Mode::kSameValueNumbersOnly);
    case IrOpcode::kNumberSameValue:
      return __ Float64SameValue(Map(node->InputAt(0)), Map(node->InputAt(1)));

    case IrOpcode::kTypeOf:
      return __ CallBuiltin_Typeof(isolate, Map(node->InputAt(0)));

    case IrOpcode::kFastApiCall: {
      DCHECK(dominating_frame_state.valid());
      FastApiCallNode n(node);
      const auto& params = n.Parameters();
      FastApiCallFunction c_function = params.c_function();
      const int c_arg_count = params.argument_count();

      base::SmallVector<OpIndex, 16> slow_call_arguments;
      DCHECK_EQ(node->op()->ValueInputCount(),
                c_arg_count + FastApiCallNode::kCallbackData +
                    n.SlowCallArgumentCount());
      OpIndex slow_call_callee = Map(n.SlowCallArgument(0));
      for (int i = 1; i < n.SlowCallArgumentCount(); ++i) {
        slow_call_arguments.push_back(Map(n.SlowCallArgument(i)));
      }

      auto convert_fallback_return = [this](Variable value,
                                            CFunctionInfo::Int64Representation
                                                int64_rep,
                                            CTypeInfo::Type return_type,
                                            V<Object> result) {
#define ELSE_UNREACHABLE                                    \
  ELSE {                                                    \
    __ RuntimeAbort(AbortReason::kFastCallFallbackInvalid); \
    __ Unreachable();                                       \
  }
        switch (return_type) {
          case CTypeInfo::Type::kVoid:
            __ SetVariable(value, __ UndefinedConstant());
            return;
          case CTypeInfo::Type::kBool:
            // Check that the return value is actually a boolean.
            IF (LIKELY(__ Word32BitwiseOr(
                    __ TaggedEqual(result, __ TrueConstant()),
                    __ TaggedEqual(result, __ FalseConstant())))) {
              __ SetVariable(
                  value, __ ConvertJSPrimitiveToUntagged(
                             V<Boolean>::Cast(result),
                             ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kBit,
                             ConvertJSPrimitiveToUntaggedOp::InputAssumptions::
                                 kBoolean));
            }
            ELSE_UNREACHABLE
            return;
          case CTypeInfo::Type::kInt32:
            IF (LIKELY(__ ObjectIsNumber(result))) {
              __ SetVariable(
                  value,
                  __ ConvertJSPrimitiveToUntagged(
                      V<Number>::Cast(result),
                      ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kInt32,
                      ConvertJSPrimitiveToUntaggedOp::InputAssumptions::
                          kNumberOrOddball));
            }
            ELSE_UNREACHABLE
            return;
          case CTypeInfo::Type::kUint32:
            IF (LIKELY(__ ObjectIsNumber(result))) {
              __ SetVariable(
                  value,
                  __ ConvertJSPrimitiveToUntagged(
                      V<Number>::Cast(result),
                      ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kUint32,
                      ConvertJSPrimitiveToUntaggedOp::InputAssumptions::
                          kNumberOrOddball));
            }
            ELSE_UNREACHABLE
            return;
          case CTypeInfo::Type::kInt64:
            if (int64_rep == CFunctionInfo::Int64Representation::kBigInt) {
              IF (LIKELY(__ ObjectIsBigInt(result))) {
                __ SetVariable(
                    value,
                    __ TruncateJSPrimitiveToUntagged(
                        V<BigInt>::Cast(result),
                        TruncateJSPrimitiveToUntaggedOp::UntaggedKind::kInt64,
                        TruncateJSPrimitiveToUntaggedOp::InputAssumptions::
                            kBigInt));
              }
              ELSE_UNREACHABLE
            } else {
              DCHECK_EQ(int64_rep, CFunctionInfo::Int64Representation::kNumber);
              IF (LIKELY(__ ObjectIsNumber(result))) {
                V<turboshaft::Tuple<Word64, Word32>> tuple =
                    __ TryTruncateFloat64ToInt64(
                        V<Float64>::Cast(__ ConvertJSPrimitiveToUntagged(
                            V<Number>::Cast(result),
                            ConvertJSPrimitiveToUntaggedOp::UntaggedKind::
                                kFloat64,
                            ConvertJSPrimitiveToUntaggedOp::InputAssumptions::
                                kNumberOrOddball)));
                IF (__ Word32Equal(__ template Projection<1>(tuple),
                                   TryChangeOp::kSuccessValue)) {
                  __ SetVariable(value, __ ChangeInt64ToFloat64(
                                            __ template Projection<0>(tuple)));
                }
                ELSE_UNREACHABLE
              }
              ELSE_UNREACHABLE
            }
            return;
          case CTypeInfo::Type::kUint64:
            if (int64_rep == CFunctionInfo::Int64Representation::kBigInt) {
              IF (LIKELY(__ ObjectIsBigInt(result))) {
                __ SetVariable(
                    value,
                    __ TruncateJSPrimitiveToUntagged(
                        V<BigInt>::Cast(result),
                        // Truncation from BigInt to int64 and uint64 is the
                        // same.
                        TruncateJSPrimitiveToUntaggedOp::UntaggedKind::kInt64,
                        TruncateJSPrimitiveToUntaggedOp::InputAssumptions::
                            kBigInt));
              }
              ELSE_UNREACHABLE
            } else {
              DCHECK_EQ(int64_rep, CFunctionInfo::Int64Representation::kNumber);
              IF (LIKELY(__ ObjectIsNumber(result))) {
                V<turboshaft::Tuple<Word64, Word32>> tuple =
                    __ TryTruncateFloat64ToUint64(
                        V<Float64>::Cast(__ ConvertJSPrimitiveToUntagged(
                            V<Number>::Cast(result),
                            ConvertJSPrimitiveToUntaggedOp::UntaggedKind::
                                kFloat64,
                            ConvertJSPrimitiveToUntaggedOp::InputAssumptions::
                                kNumberOrOddball)));
                IF (__ Word32Equal(__ template Projection<1>(tuple),
                                   TryChangeOp::kSuccessValue)) {
                  __ SetVariable(value, __ ChangeUint64ToFloat64(
                                            __ template Projection<0>(tuple)));
                }
                ELSE_UNREACHABLE
              }
              ELSE_UNREACHABLE
            }
            return;
          case CTypeInfo::Type::kFloat32:
          case CTypeInfo::Type::kFloat64:
            IF (LIKELY(__ ObjectIsNumber(result))) {
              V<Float64> f = V<Float64>::Cast(__ ConvertJSPrimitiveToUntagged(
                  V<Number>::Cast(result),
                  ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kFloat64,
                  ConvertJSPrimitiveToUntaggedOp::InputAssumptions::
                      kNumberOrOddball));
              if (return_type == CTypeInfo::Type::kFloat32) {
                __ SetVariable(value, __ TruncateFloat64ToFloat32(f));
              } else {
                __ SetVariable(value, f);
              }
            }
            ELSE_UNREACHABLE
            return;
          case CTypeInfo::Type::kPointer:
            __ SetVariable(value, result);
            return;
          case CTypeInfo::Type::kAny:
          case CTypeInfo::Type::kSeqOneByteString:
          case CTypeInfo::Type::kV8Value:
          case CTypeInfo::Type::kApiObject:
          case CTypeInfo::Type::kUint8:
            UNREACHABLE();
        }

#undef ELSE_UNREACHABLE
      };

      std::optional<decltype(assembler)::CatchScope> catch_scope;
      if (is_final_control) {
        Block* catch_block = Map(block->SuccessorAt(1));
        catch_scope.emplace(assembler, catch_block);
      }
      // Prepare FastCallApiOp parameters.
      base::SmallVector<OpIndex, 16> arguments;
      for (int i = 0; i < c_arg_count; ++i) {
        arguments.push_back(Map(NodeProperties::GetValueInput(node, i)));
      }
      V<Object> data_argument = Map(n.CallbackData());

      V<Context> context = Map(n.Context());

      const FastApiCallParameters* parameters =
          FastApiCallParameters::Create(c_function, __ graph_zone());

      // There is one return in addition to the return value of the C function,
      // which indicates if a fast API call actually happened.
      CTypeInfo return_type = parameters->c_signature()->ReturnInfo();
      int return_count = 2;

      // Allocate the out_reps vector in the zone, so that it lives through the
      // whole compilation.
      const base::Vector<RegisterRepresentation> out_reps =
          graph_zone->AllocateVector<RegisterRepresentation>(return_count);
      out_reps[0] = RegisterRepresentation::Word32();
      out_reps[1] = RegisterRepresentation::FromCTypeInfo(
          return_type, parameters->c_signature()->GetInt64Representation());

      V<Tuple<Word32, Any>> fast_call_result =
          __ FastApiCall(dominating_frame_state, data_argument, context,
                         base::VectorOf(arguments), parameters, out_reps);

      V<Word32> result_state = __ template Projection<0>(fast_call_result);
      V<Any> result_value =
          __ template Projection<1>(fast_call_result, out_reps[1]);
      Variable result = __ NewVariable(out_reps[1]);
      __ SetVariable(result, result_value);

      IF (UNLIKELY(
              __ Word32Equal(result_state, FastApiCallOp::kFailureValue))) {
        // We need to generate a fallback (both fast and slow call) in case
        // the generated code might fail, in case e.g. a Smi was passed where
        // a JSObject was expected and an error must be thrown.
        // None of this usually holds true for Wasm functions with
        // primitive types only, so we avoid generating an extra branch here.

        V<Object> fallback_result = V<Object>::Cast(__ Call(
            slow_call_callee, dominating_frame_state,
            base::VectorOf(slow_call_arguments),
            TSCallDescriptor::Create(params.descriptor(), CanThrow::kYes,
                                     LazyDeoptOnThrow::kNo, __ graph_zone())));

        convert_fallback_return(
            result, parameters->c_signature()->GetInt64Representation(),
            return_type.GetType(), fallback_result);
      }
      V<Any> value = __ GetVariable(result);
      if (is_final_control) {
        // The `__ FastApiCall()` before has already created exceptional control
        // flow and bound a new block for the success case. So we can just
        // `Goto` the block that Turbofan designated as the `IfSuccess`
        // successor.
        __ Goto(Map(block->SuccessorAt(0)));
      }
      return value;
    }

    case IrOpcode::kRuntimeAbort:
      __ RuntimeAbort(AbortReasonOf(node->op()));
      return OpIndex::Invalid();

    case IrOpcode::kDateNow:
      return __ CallRuntime_DateCurrentTime(isolate, __ NoContextConstant());

    case IrOpcode::kEnsureWritableFastElements:
      return __ EnsureWritableFastElements(Map(node->InputAt(0)),
                                           Map(node->InputAt(1)));

    case IrOpcode::kMaybeGrowFastElements: {
      DCHECK(dominating_frame_state.valid());
      const GrowFastElementsParameters& params =
          GrowFastElementsParametersOf(node->op());
      return __ MaybeGrowFastElements(
          Map(node->InputAt(0)), Map(node->InputAt(1)), Map(node->InputAt(2)),
          Map(node->InputAt(3)), dominating_frame_state, params.mode(),
          params.feedback());
    }

    case IrOpcode::kTransitionElementsKind:
      __ TransitionElementsKind(Map(node->InputAt(0)),
                                ElementsTransitionOf(node->op()));
      return OpIndex::Invalid();

    case IrOpcode::kAssertType: {
      compiler::Type type = OpParameter<compiler::Type>(node->op());
      CHECK(type.CanBeAsserted());
      V<TurbofanType> allocated_type;
      {
        DCHECK(isolate->CurrentLocalHeap()->is_main_thread());
        std::optional<UnparkedScope> unparked_scope;
        if (isolate->CurrentLocalHeap()->IsParked()) {
          unparked_scope.emplace(isolate->main_thread_local_isolate());
        }
        allocated_type =
            __ HeapConstant(type.AllocateOnHeap(isolate->factory()));
      }
      __ CallBuiltin_CheckTurbofanType(isolate, __ NoContextConstant(),
                                       Map(node->InputAt(0)), allocated_type,
                                       __ TagSmi(node->id()));
      return OpIndex::Invalid();
    }

    case IrOpcode::kFindOrderedHashMapEntry:
      return __ FindOrderedHashMapEntry(Map(node->InputAt(0)),
                                        Map(node->InputAt(1)));
    case IrOpcode::kFindOrderedHashSetEntry:
      return __ FindOrderedHashSetEntry(Map(node->InputAt(0)),
                                        Map(node->InputAt(1)));
    case IrOpcode::kFindOrderedHashMapEntryForInt32Key:
      return __ FindOrderedHashMapEntryForInt32Key(Map(node->InputAt(0)),
                                                   Map(node->InputAt(1)));

    case IrOpcode::kSpeculativeSafeIntegerAdd:
      DCHECK(dominating_frame_state.valid());
      return __ SpeculativeNumberBinop(
          Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state,
          SpeculativeNumberBinopOp::Kind::kSafeIntegerAdd);

    case IrOpcode::kBeginRegion:
      inside_region = true;
      return OpIndex::Invalid();
    case IrOpcode::kFinishRegion:
      inside_region = false;
      return Map(node->InputAt(0));

    case IrOpcode::kTypeGuard:
      return Map(node->InputAt(0));

    case IrOpcode::kAbortCSADcheck:
      __ AbortCSADcheck(Map(node->InputAt(0)));
      return OpIndex::Invalid();

    case IrOpcode::kDebugBreak:
      __ DebugBreak();
      return OpIndex::Invalid();

    case IrOpcode::kComment:
      __ Comment(OpParameter<const char*>(node->op()));
      return OpIndex::Invalid();

    case IrOpcode::kAssert: {
      const AssertParameters& p = AssertParametersOf(node->op());
      __ AssertImpl(Map(node->InputAt(0)), p.condition_string(), p.file(),
                    p.line());
      return OpIndex::Invalid();
    }

    case IrOpcode::kBitcastTaggedToWordForTagAndSmiBits:
      // Currently this is only used by the CSA pipeline.
      DCHECK_EQ(pipeline_kind, TurboshaftPipelineKind::kCSA);
      return __ BitcastTaggedToWordPtrForTagAndSmiBits(Map(node->InputAt(0)));
    case IrOpcode::kBitcastWordToTaggedSigned:
      return __ BitcastWordPtrToSmi(Map(node->InputAt(0)));

    case IrOpcode::kWord32AtomicLoad:
    case IrOpcode::kWord64AtomicLoad: {
      OpIndex base = Map(node->InputAt(0));
      OpIndex offset = Map(node->InputAt(1));
      const AtomicLoadParameters& p = AtomicLoadParametersOf(node->op());
      DCHECK_EQ(__ output_graph().Get(base).outputs_rep()[0],
                RegisterRepresentation::WordPtr());
      LoadOp::Kind kind;
      switch (p.kind()) {
        case MemoryAccessKind::kNormal:
          kind = LoadOp::Kind::RawAligned().Atomic();
          break;
        case MemoryAccessKind::kUnaligned:
          UNREACHABLE();
        case MemoryAccessKind::kProtectedByTrapHandler:
          kind = LoadOp::Kind::RawAligned().Atomic().Protected();
          break;
      }
      return __ Load(base, offset, kind,
                     MemoryRepresentation::FromMachineType(p.representation()),
                     node->opcode() == IrOpcode::kWord32AtomicLoad
                         ? RegisterRepresentation::Word32()
                         : RegisterRepresentation::Word64(),
                     0, 0);
    }

    case IrOpcode::kWord32AtomicStore:
    case IrOpcode::kWord64AtomicStore: {
      OpIndex base = Map(node->InputAt(0));
      OpIndex offset = Map(node->InputAt(1));
      OpIndex value = Map(node->InputAt(2));
      const AtomicStoreParameters& p = AtomicStoreParametersOf(node->op());
      DCHECK_EQ(__ output_graph().Get(base).outputs_rep()[0],
                RegisterRepresentation::WordPtr());
      StoreOp::Kind kind;
      switch (p.kind()) {
        case MemoryAccessKind::kNormal:
          kind = StoreOp::Kind::RawAligned().Atomic();
          break;
        case MemoryAccessKind::kUnaligned:
          UNREACHABLE();
        case MemoryAccessKind::kProtectedByTrapHandler:
          kind = StoreOp::Kind::RawAligned().Atomic().Protected();
          break;
      }
      __ Store(
          base, offset, value, kind,
          MemoryRepresentation::FromMachineRepresentation(p.representation()),
          p.write_barrier_kind(), 0, 0, true);
      return OpIndex::Invalid();
    }

    case IrOpcode::kWord32AtomicAdd:
    case IrOpcode::kWord32AtomicSub:
    case IrOpcode::kWord32AtomicAnd:
    case IrOpcode::kWord32AtomicOr:
    case IrOpcode::kWord32AtomicXor:
    case IrOpcode::kWord32AtomicExchange:
    case IrOpcode::kWord32AtomicCompareExchange:
    case IrOpcode::kWord64AtomicAdd:
    case IrOpcode::kWord64AtomicSub:
    case IrOpcode::kWord64AtomicAnd:
    case IrOpcode::kWord64AtomicOr:
    case IrOpcode::kWord64AtomicXor:
    case IrOpcode::kWord64AtomicExchange:
    case IrOpcode::kWord64AtomicCompareExchange: {
      int input_index = 0;
      OpIndex base = Map(node->InputAt(input_index++));
      OpIndex offset = Map(node->InputAt(input_index++));
      OpIndex expected;
      if (node->opcode() == IrOpcode::kWord32AtomicCompareExchange ||
          node->opcode() == IrOpcode::kWord64AtomicCompareExchange) {
        expected = Map(node->InputAt(input_index++));
      }
      OpIndex value = Map(node->InputAt(input_index++));
      const AtomicOpParameters& p = AtomicOpParametersOf(node->op());
      switch (node->opcode()) {
#define BINOP(binop, size)                                                 \
  case IrOpcode::kWord##size##Atomic##binop:                               \
    return __ AtomicRMW(base, offset, value, AtomicRMWOp::BinOp::k##binop, \
                        RegisterRepresentation::Word##size(),              \
                        MemoryRepresentation::FromMachineType(p.type()),   \
                        p.kind());
        BINOP(Add, 32)
        BINOP(Sub, 32)
        BINOP(And, 32)
        BINOP(Or, 32)
        BINOP(Xor, 32)
        BINOP(Exchange, 32)
        BINOP(Add, 64)
        BINOP(Sub, 64)
        BINOP(And, 64)
        BINOP(Or, 64)
        BINOP(Xor, 64)
        BINOP(Exchange, 64)
#undef BINOP
        case IrOpcode::kWord32AtomicCompareExchange:
          return __ AtomicCompareExchange(
              base, offset, expected, value, RegisterRepresentation::Word32(),
              MemoryRepresentation::FromMachineType(p.type()), p.kind());
        case IrOpcode::kWord64AtomicCompareExchange:
          return __ AtomicCompareExchange(
              base, offset, expected, value, RegisterRepresentation::Word64(),
              MemoryRepresentation::FromMachineType(p.type()), p.kind());
        default:
          UNREACHABLE();
      }
    }

    case IrOpcode::kWord32AtomicPairLoad:
      return __ AtomicWord32PairLoad(Map(node->InputAt(0)),
                                     Map(node->InputAt(1)), 0);
    case IrOpcode::kWord32AtomicPairStore:
      return __ AtomicWord32PairStore(
          Map(node->InputAt(0)), Map(node->InputAt(1)), Map(node->InputAt(2)),
          Map(node->InputAt(3)), 0);

#define ATOMIC_WORD32_PAIR_BINOP(kind)                                       \
  case IrOpcode::kWord32AtomicPair##kind:                                    \
    return __ AtomicWord32PairBinop(                                         \
        Map(node->InputAt(0)), Map(node->InputAt(1)), Map(node->InputAt(2)), \
        Map(node->InputAt(3)), AtomicRMWOp::BinOp::k##kind, 0);
      ATOMIC_WORD32_PAIR_BINOP(Add)
      ATOMIC_WORD32_PAIR_BINOP(Sub)
      ATOMIC_WORD32_PAIR_BINOP(And)
      ATOMIC_WORD32_PAIR_BINOP(Or)
      ATOMIC_WORD32_PAIR_BINOP(Xor)
      ATOMIC_WORD32_PAIR_BINOP(Exchange)
    case IrOpcode::kWord32AtomicPairCompareExchange:
      return __ AtomicWord32PairCompareExchange(
          Map(node->InputAt(0)), Map(node->InputAt(1)), Map(node->InputAt(4)),
          Map(node->InputAt(5)), Map(node->InputAt(2)), Map(node->InputAt(3)),
          0);

#ifdef V8_ENABLE_WEBASSEMBLY
#define SIMD128_BINOP(name)                                              \
  case IrOpcode::k##name:                                                \
    return __ Simd128Binop(Map(node->InputAt(0)), Map(node->InputAt(1)), \
                           Simd128BinopOp::Kind::k##name);
      FOREACH_SIMD_128_BINARY_BASIC_OPCODE(SIMD128_BINOP)
#undef SIMD128_BINOP
    case IrOpcode::kI8x16Swizzle: {
      bool relaxed = OpParameter<bool>(node->op());
      return __ Simd128Binop(Map(node->InputAt(0)), Map(node->InputAt(1)),
                             relaxed
                                 ? Simd128BinopOp::Kind::kI8x16RelaxedSwizzle
                                 : Simd128BinopOp::Kind::kI8x16Swizzle);
    }

#define SIMD128_UNOP(name)                                 \
  case IrOpcode::k##name:                                  \
    return __ Simd128Unary(Map<Simd128>(node->InputAt(0)), \
                           Simd128UnaryOp::Kind::k##name);
      FOREACH_SIMD_128_UNARY_OPCODE(SIMD128_UNOP)
#undef SIMD128_UNOP

#define SIMD128_SHIFT(name)                                \
  case IrOpcode::k##name:                                  \
    return __ Simd128Shift(Map<Simd128>(node->InputAt(0)), \
                           Map<Word32>(node->InputAt(1)),  \
                           Simd128ShiftOp::Kind::k##name);
      FOREACH_SIMD_128_SHIFT_OPCODE(SIMD128_SHIFT)
#undef SIMD128_UNOP

#define SIMD128_TEST(name)                                \
  case IrOpcode::k##name:                                 \
    return __ Simd128Test(Map<Simd128>(node->InputAt(0)), \
                          Simd128TestOp::Kind::k##name);
      FOREACH_SIMD_128_TEST_OPCODE(SIMD128_TEST)
#undef SIMD128_UNOP

#define SIMD128_SPLAT(name)                            \
  case IrOpcode::k##name##Splat:                       \
    return __ Simd128Splat(Map<Any>(node->InputAt(0)), \
                           Simd128SplatOp::Kind::k##name);
      FOREACH_SIMD_128_SPLAT_OPCODE(SIMD128_SPLAT)
#undef SIMD128_SPLAT

#define SIMD128_TERNARY(name)                                              \
  case IrOpcode::k##name:                                                  \
    return __ Simd128Ternary(Map(node->InputAt(0)), Map(node->InputAt(1)), \
                             Map(node->InputAt(2)),                        \
                             Simd128TernaryOp::Kind::k##name);
      FOREACH_SIMD_128_TERNARY_OPCODE(SIMD128_TERNARY)
#undef SIMD128_TERNARY

#define SIMD128_EXTRACT_LANE(name, suffix)                                    \
  case IrOpcode::k##name##ExtractLane##suffix:                                \
    return __ Simd128ExtractLane(Map<Simd128>(node->InputAt(0)),              \
                                 Simd128ExtractLaneOp::Kind::k##name##suffix, \
                                 OpParameter<int32_t>(node->op()));
      SIMD128_EXTRACT_LANE(I8x16, S)
      SIMD128_EXTRACT_LANE(I8x16, U)
      SIMD128_EXTRACT_LANE(I16x8, S)
      SIMD128_EXTRACT_LANE(I16x8, U)
      SIMD128_EXTRACT_LANE(I32x4, )
      SIMD128_EXTRACT_LANE(I64x2, )
      SIMD128_EXTRACT_LANE(F32x4, )
      SIMD128_EXTRACT_LANE(F64x2, )
#undef SIMD128_LANE

#define SIMD128_REPLACE_LANE(name)                                    \
  case IrOpcode::k##name##ReplaceLane:                                \
    return __ Simd128ReplaceLane(Map<Simd128>(node->InputAt(0)),      \
                                 Map<Any>(node->InputAt(1)),          \
                                 Simd128ReplaceLaneOp::Kind::k##name, \
                                 OpParameter<int32_t>(node->op()));
      SIMD128_REPLACE_LANE(I8x16)
      SIMD128_REPLACE_LANE(I16x8)
      SIMD128_REPLACE_LANE(I32x4)
      SIMD128_REPLACE_LANE(I64x2)
      SIMD128_REPLACE_LANE(F32x4)
      SIMD128_REPLACE_LANE(F64x2)
#undef SIMD128_REPLACE_LANE

    case IrOpcode::kLoadStackPointer:
      return __ LoadStackPointer();

    case IrOpcode::kSetStackPointer:
      __ SetStackPointer(Map(node->InputAt(0)));
      return OpIndex::Invalid();

#endif  // V8_ENABLE_WEBASSEMBLY

    case IrOpcode::kJSStackCheck: {
      DCHECK_EQ(OpParameter<StackCheckKind>(node->op()),
                StackCheckKind::kJSFunctionEntry);
      V<Context> context = Map(node->InputAt(0));
      V<FrameState> frame_state = Map(node->InputAt(1));
      __ JSFunctionEntryStackCheck(context, frame_state);
      return OpIndex::Invalid();
    }

    case IrOpcode::kInt32PairAdd:
    case IrOpcode::kInt32PairSub:
    case IrOpcode::kInt32PairMul:
    case IrOpcode::kWord32PairShl:
    case IrOpcode::kWord32PairSar:
    case IrOpcode::kWord32PairShr: {
      V<Word32> left_low = Map(node->InputAt(0));
      V<Word32> left_high = Map(node->InputAt(1));
      V<Word32> right_low = Map(node->InputAt(2));
      V<Word32> right_high = Map(node->InputAt(3));
      Word32PairBinopOp::Kind kind;
      switch (node->opcode()) {
        case IrOpcode::kInt32PairAdd:
          kind = Word32PairBinopOp::Kind::kAdd;
          break;
        case IrOpcode::kInt32PairSub:
          kind = Word32PairBinopOp::Kind::kSub;
          break;
        case IrOpcode::kInt32PairMul:
          kind = Word32PairBinopOp::Kind::kMul;
          break;
        case IrOpcode::kWord32PairShl:
          kind = Word32PairBinopOp::Kind::kShiftLeft;
          break;
        case IrOpcode::kWord32PairSar:
          kind = Word32PairBinopOp::Kind::kShiftRightArithmetic;
          break;
        case IrOpcode::kWord32PairShr:
          kind = Word32PairBinopOp::Kind::kShiftRightLogical;
          break;
        default:
          UNREACHABLE();
      }
      return __ Word32PairBinop(left_low, left_high, right_low, right_high,
                                kind);
    }

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    case IrOpcode::kGetContinuationPreservedEmbedderData:
      return __ GetContinuationPreservedEmbedderData();
    case IrOpcode::kSetContinuationPreservedEmbedderData:
      __ SetContinuationPreservedEmbedderData(Map(node->InputAt(0)));
      return OpIndex::Invalid();
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

    default:
      std::cerr << "unsupported node type: " << *node->op() << "\n";
      node->Print(std::cerr);
      UNIMPLEMENTED();
  }
}

}  // namespace

std::optional<BailoutReason> BuildGraph(
    PipelineData* data, Schedule* schedule, Zone* phase_zone, Linkage* linkage,
    JsWasmCallsSidetable* js_wasm_calls_sidetable) {
  GraphBuilder builder{data, phase_zone, *schedule, linkage,
                       js_wasm_calls_sidetable};
#if DEBUG
  data->graph().SetCreatedFromTurbofan();
#endif
  return builder.Run();
}

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft
```