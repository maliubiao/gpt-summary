Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `graph-builder.cc`. I need to analyze the code, identify its core responsibilities, and then address each of the user's specific points:

1. **List the functionalities:**  I'll go through the `switch` statement which processes different `IrOpcode` values and summarize what each case does.

2. **Check for Torque source:** The user provided the file name, so I can directly state that it's a C++ file, not a Torque file.

3. **Relationship to JavaScript:** I'll look for operations that are related to JavaScript concepts like objects, arrays, types, and function calls. If found, I'll provide a JavaScript example.

4. **Code logic and inference:**  Some cases involve transformations or checks. I'll pick a relevant example, define a hypothetical input, and explain the expected output or action.

5. **Common programming errors:**  I'll consider the purpose of certain operations (like type assertions or array growth) and relate them to potential mistakes developers make.

6. **Summarize the overall functionality:** I'll synthesize the individual functionalities into a concise high-level description of the code's role.

Let's break down the code's functionality by analyzing the `switch` cases:

- **Element Grow/Transition:** Handles operations related to the dynamic sizing and type changes of JavaScript arrays.
- **Type Assertions:** Enforces type constraints during compilation.
- **HashMap/HashSet Operations:** Deals with lookups in JavaScript Map and Set objects.
- **Safe Integer Arithmetic:** Performs arithmetic operations with overflow checks.
- **Regions:**  Manages logical grouping of operations.
- **Type Guards:**  Refines the type of a value based on a preceding check.
- **Debugging and Assertions:** Includes mechanisms for debugging and verifying assumptions.
- **Bitcasting:** Changes the interpretation of data without altering the underlying bits.
- **Atomic Operations:** Provides thread-safe operations on memory.
- **SIMD Operations:**  Implements Single Instruction, Multiple Data operations for parallel processing (related to WebAssembly).
- **Stack Pointer Manipulation:**  Directly interacts with the call stack.
- **Stack Checks:** Ensures sufficient stack space.
- **Integer Pair Operations:** Handles operations on 64-bit integers represented as pairs of 32-bit integers.
- **Continuation Preserved Embedder Data:**  Manages data associated with continuations.

Now I can formulate the detailed responses.
This C++ source code file, `v8/src/compiler/turboshaft/graph-builder.cc`, is a crucial part of the **Turboshaft compiler pipeline** within the V8 JavaScript engine. Its primary function is to **translate intermediate representation (IR) nodes from the *Turbofan* compiler into the *Turboshaft* compiler's graph representation**.

Here's a breakdown of its functionalities:

**Core Functionality: Building the Turboshaft Graph**

The code iterates through nodes in a schedule (likely produced by Turbofan) and, based on the `IrOpcode` of each node, generates corresponding operations and values in the Turboshaft graph. This involves:

* **Mapping Turbofan Nodes to Turboshaft Operations:** The large `switch` statement is the heart of this process. Each `case` handles a specific Turbofan `IrOpcode` and calls the appropriate `__` methods (which are likely part of the `GraphBuilder` class or its helpers) to create Turboshaft graph nodes.
* **Handling Different Operation Types:**  The code supports a wide range of operations, including:
    * **Memory Operations:** Loading and storing values in memory (including atomic operations).
    * **Arithmetic and Logical Operations:**  Performing calculations and bitwise manipulations.
    * **Object and Array Operations:** Handling operations related to JavaScript objects and arrays (like growing arrays or transitioning their element kinds).
    * **Control Flow:** While not explicitly shown in this snippet, the `GraphBuilder` would also handle control flow constructs.
    * **Type System Integration:** Asserting and guarding types.
    * **Built-in Function Calls:**  Calling predefined V8 functions.
    * **Debugging and Assertions:**  Inserting debugging aids and runtime checks.
    * **SIMD Operations:**  Supporting Single Instruction, Multiple Data operations (primarily for WebAssembly).
    * **Stack Management:**  Operations related to the call stack.

**Specific Functionalities Illustrated in the Snippet:**

* **`kGrowFastElements`:**  Handles the case where a JavaScript array needs to increase its capacity.
* **`kTransitionElementsKind`:** Deals with changing the underlying representation of array elements (e.g., from integers to doubles).
* **`kAssertType`:**  Ensures that a value conforms to a specific type at runtime.
* **`kFindOrderedHashMapEntry`/`kFindOrderedHashSetEntry`:**  Looks up entries in JavaScript `Map` and `Set` objects.
* **`kSpeculativeSafeIntegerAdd`:** Performs integer addition with overflow checks.
* **`kBeginRegion`/`kFinishRegion`:**  Marks the start and end of a logical region in the graph, potentially for optimization purposes.
* **`kTypeGuard`:**  Refines the type of a value based on a preceding type check.
* **`kAbortCSADcheck`:** Likely related to internal consistency checks in the compiler.
* **`kDebugBreak`:**  Inserts a breakpoint for debugging.
* **`kComment`:** Adds comments to the generated graph.
* **`kAssert`:**  Performs general assertions.
* **`kBitcastTaggedToWordForTagAndSmiBits`/`kBitcastWordToTaggedSigned`:**  Changes the interpretation of data between tagged pointers and raw words.
* **Atomic Operations (`kWord32AtomicLoad`, `kWord32AtomicStore`, etc.):** Implements thread-safe memory access.
* **SIMD Operations (`kI8x16Swizzle`, `kAdd`, etc.):**  Handles operations on 128-bit vectors for parallel computation (mostly used for WebAssembly).
* **Stack Pointer Operations (`kLoadStackPointer`, `kSetStackPointer`):**  Directly manipulates the call stack.
* **`kJSStackCheck`:**  Checks for sufficient stack space when entering a JavaScript function.
* **Integer Pair Operations (`kInt32PairAdd`, `kWord32PairShl`, etc.):**  Performs operations on 64-bit integers represented as two 32-bit values.
* **Continuation Preserved Embedder Data (`kGetContinuationPreservedEmbedderData`, `kSetContinuationPreservedEmbedderData`):** Manages data associated with continuations (a more advanced control flow mechanism).

**Is it a Torque source?**

No, `v8/src/compiler/turboshaft/graph-builder.cc` ends with `.cc`, which indicates it is a **C++ source file**. Torque source files in V8 typically have the `.tq` extension.

**Relationship to JavaScript and JavaScript Examples:**

Many of the operations in this code directly relate to the semantics and behavior of JavaScript. Here are a few examples:

* **`kGrowFastElements`:**  This is triggered when you add an element to a JavaScript array and it needs to resize.

   ```javascript
   const arr = [1, 2, 3];
   arr.push(4); // This might trigger a "grow fast elements" operation internally.
   ```

* **`kTransitionElementsKind`:** This happens when the types of elements in an array change, requiring a different internal representation.

   ```javascript
   const arr = [1, 2, 3]; // Initially, likely an integer array.
   arr.push(3.14); // Now it needs to transition to a floating-point array.
   ```

* **`kAssertType`:** While not directly visible in JavaScript code, the compiler uses type assertions to optimize. If the compiler makes an assumption about a variable's type, it might insert an assertion to verify it at runtime. If the assumption is wrong, it can lead to deoptimization.

* **`kFindOrderedHashMapEntry`:**  This is used when accessing properties of JavaScript objects (which are often implemented as hash maps).

   ```javascript
   const obj = { a: 1, b: 2 };
   console.log(obj.a); // This would likely involve a hash map lookup.
   ```

**Code Logic Inference (Example: `kSpeculativeSafeIntegerAdd`)**

**Hypothetical Input:**

Assume a Turbofan IR node with `IrOpcode::kSpeculativeSafeIntegerAdd` and two input nodes representing the values `5` and `10`. Let's also assume the `dominating_frame_state` is valid.

**Expected Output:**

The `GraphBuilder` would call `__ SpeculativeNumberBinop(Map(node->InputAt(0)), Map(node->InputAt(1)), dominating_frame_state, SpeculativeNumberBinopOp::Kind::kSafeIntegerAdd);`. This would create a Turboshaft graph node representing the safe integer addition of the two input values. The `Map` function likely retrieves the corresponding Turboshaft values for the input nodes. The "safe" part implies that this operation will likely check for integer overflow at runtime.

**User-Common Programming Errors (Examples):**

* **Relying on specific array element kinds:**  Programmers sometimes make assumptions about how V8 internally represents arrays. For example, they might assume an array will always hold integers. Adding a non-integer value can trigger a `kTransitionElementsKind`, which might have performance implications if unexpected.

   ```javascript
   function processArray(arr) {
     for (let i = 0; i < arr.length; i++) {
       // Assume arr[i] is always an integer
       console.log(arr[i] + 1);
     }
   }

   processArray([1, 2, 3]); // Works as expected
   processArray([1, 2, 'oops']); // Might cause unexpected behavior or deoptimization due to type changes.
   ```

* **Unintended integer overflows:** While `kSpeculativeSafeIntegerAdd` handles this, regular integer additions in JavaScript can silently overflow. This can lead to unexpected results.

   ```javascript
   let maxInt = Number.MAX_SAFE_INTEGER;
   console.log(maxInt + 1); // Still a safe integer
   console.log(maxInt + 2); // Might lead to unexpected behavior due to precision limits.
   ```

**Summary of Functionality (Part 4 of 4):**

This final part of the `graph-builder.cc` code focuses on handling a diverse set of Turbofan IR nodes, encompassing:

* **Advanced data structure operations:**  Operations on `Map` and `Set`.
* **Specialized arithmetic:** Safe integer addition.
* **Code organization and debugging:** Regions, comments, and assertions.
* **Low-level data manipulation:** Bitcasting.
* **Concurrency primitives:** Atomic operations.
* **WebAssembly support:** SIMD instructions.
* **Stack management:** Operations on the stack pointer and stack checks.
* **Operations on larger integer types:**  Integer pair operations.
* **Continuation management:**  Handling embedder data for continuations.

Overall, this code snippet demonstrates the complex and detailed work involved in translating a higher-level intermediate representation into the lower-level graph representation used by the Turboshaft compiler for optimization and code generation. It bridges the gap between the abstract operations defined by Turbofan and the concrete operations that Turboshaft can work with.

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
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

"""


```