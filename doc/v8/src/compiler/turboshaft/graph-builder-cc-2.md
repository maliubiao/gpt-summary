Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/turboshaft/graph-builder.cc`. I need to analyze the code and identify the operations it performs.

The code seems to be handling different IR opcodes and translating them into Turboshaft graph operations. It covers a range of operations related to:
- Memory access (loads and stores of fields and elements)
- Object manipulation (creating strings and arrays)
- Arithmetic and bitwise operations (including checked operations that deoptimize on overflow)
- Comparisons (including string and BigInt comparisons)
- String operations (length, indexing, substring, concatenation, equality)
- Function arguments (length, rest parameters)
- Typed arrays and DataViews
- Map checks and comparisons
- Type checks
- Fast API calls
- Runtime calls (like Date.now)
- Error handling (RuntimeAbort)

I should also check if any of the handled opcodes are related to Javascript functionality and provide examples if so.

The question also asks about the file extension `.tq`. This snippet is in `.cc`, so it's not Torque code.

Finally, I need to summarize the overall purpose of this code.
这是 `v8/src/compiler/turboshaft/graph-builder.cc` 文件的一部分代码，它主要负责将中间表示（IR）操作码转换为 Turboshaft 图中的节点。Turboshaft 是 V8 引擎中新一代的编译器框架。

**功能列举:**

这段代码展示了 `GraphBuilder` 类如何处理多种不同的 IR 操作码，并将其转换为 Turboshaft 图中的相应操作。以下是一些主要的功能：

1. **存储操作 (Store):**
   - `kStoreField`: 存储对象的字段。
   - `kStoreElement`: 存储数组的元素。
   - `kStoreGlobal`: 存储全局变量（虽然这里没有直接展示，但通常会有类似的处理）。
   - `kTransitionAndStoreElement`, `kTransitionAndStoreNumberElement`, `kTransitionAndStoreNonNumberElement`:  在存储元素的同时进行对象形状（Map）的转换。
   - `kStoreTypedElement`, `kStoreDataViewElement`: 存储类型化数组和数据视图的元素。
   - `kStoreSignedSmallElement`: 存储小的有符号整数元素。

2. **加载操作 (Load):**
   - `kLoadFromObject`, `kLoadImmutableFromObject`: 从对象加载字段。
   - `kLoadField`: 加载对象的字段。
   - `kLoadElement`: 加载数组的元素。
   - `kLoadTypedElement`, `kLoadDataViewElement`: 加载类型化数组和数据视图的元素。
   - `kLoadFieldByIndex`: 根据索引加载字段。
   - `kLoadRootRegister`: 加载根寄存器。
   - `kLoadStackArgument`: 加载栈上的参数。
   - `kLoadMessage`, `kStoreMessage`:  加载和存储消息对象（用于错误处理等）。

3. **对象创建 (Object Creation):**
   - `kNewConsString`: 创建连接字符串。
   - `kNewDoubleElements`, `kNewSmiOrObjectElements`: 创建具有特定元素类型的数组。
   - `kNewArgumentsElements`: 创建 arguments 对象。

4. **算术和位运算 (Arithmetic and Bitwise Operations):**
   - `kCheckedInt64Add`, `kCheckedInt64Sub`, `kCheckedInt32Add`, `kCheckedInt32Sub`, `kCheckedInt32Mul`, `kCheckedInt64Mul`, `kCheckedInt32Div`, `kCheckedInt64Div`, `kCheckedUint32Div`, `kCheckedInt32Mod`, `kCheckedInt64Mod`, `kCheckedUint32Mod`: 执行带溢出检查的算术运算。
   - `kBigIntAdd`, `kBigIntSubtract`, `kBigIntMultiply`, `kBigIntDivide`, `kBigIntModulus`, `kBigIntBitwiseAnd`, `kBigIntBitwiseOr`, `kBigIntBitwiseXor`, `kBigIntShiftLeft`, `kBigIntShiftRight`: BigInt 类型的算术和位运算。

5. **比较操作 (Comparison Operations):**
   - `kBigIntEqual`, `kBigIntLessThan`, `kBigIntLessThanOrEqual`: BigInt 类型的比较。
   - `kStringEqual`, `kStringLessThan`, `kStringLessThanOrEqual`: 字符串比较。
   - `kSameValue`, `kSameValueNumbersOnly`, `kNumberSameValue`: 判断值是否相等。
   - `kCompareMaps`: 比较对象的 Map（形状）。

6. **字符串操作 (String Operations):**
   - `kStringCharCodeAt`, `kStringCodePointAt`: 获取字符串指定位置的字符编码。
   - `kStringToLowerCaseIntl`, `kStringToUpperCaseIntl`: 将字符串转换为小写或大写（可能涉及国际化）。
   - `kStringLength`: 获取字符串长度。
   - `kStringWrapperLength`: 获取字符串包装对象的长度。
   - `kStringIndexOf`: 查找子字符串在字符串中的索引。
   - `kStringFromCodePointAt`: 从字符编码创建字符串。
   - `kStringSubstring`: 获取子字符串。
   - `kStringConcat`: 连接字符串。

7. **控制流和类型检查 (Control Flow and Type Checks):**
   - `kCheckTurboshaftTypeOf`: 检查对象的类型是否符合给定的描述。
   - `kCheckMaps`: 检查对象的 Map 是否为期望的 Map。
   - `kCheckedUint32Bounds`, `kCheckedUint64Bounds`: 检查索引是否在界限内。
   - `kCheckIf`: 基于条件进行去优化。
   - `kCheckClosure`: 检查是否为闭包。
   - `kCheckEqualsSymbol`, `kCheckEqualsInternalizedString`: 检查是否等于特定的 Symbol 或内部化字符串。
   - `kCheckFloat64Hole`, `kCheckNotTaggedHole`: 检查是否为浮点数空洞或标记的空洞值。

8. **函数调用和参数 (Function Calls and Arguments):**
   - `kArgumentsLength`: 获取 arguments 对象的长度。
   - `kRestLength`: 获取剩余参数的长度。
   - `kFastApiCall`: 调用 C++ 编写的快速 API 函数。

9. **其他 (Others):**
   - `kTypeOf`: 获取值的类型字符串。
   - `kRuntimeAbort`: 触发运行时中止。
   - `kDateNow`: 获取当前时间。
   - `kEnsureWritableFastElements`, `kMaybeGrowFastElements`: 确保数组具有可写的快速元素。

**关于 .tq 扩展名:**

代码注释中提到，如果 `v8/src/compiler/turboshaft/graph-builder.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。由于当前文件以 `.cc` 结尾，所以它是一个 C++ 源代码文件，而不是 Torque 文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言，它可以生成 C++ 代码。

**与 JavaScript 的关系 (With JavaScript Examples):**

这段代码处理的很多操作都与 JavaScript 的功能直接相关。以下是一些示例：

- **属性访问 (Property Access):** `kLoadField`, `kStoreField`, `kLoadFromObject`, `kStoreGlobal` 等操作对应 JavaScript 中的属性读取和赋值。
  ```javascript
  const obj = { a: 1 };
  const value = obj.a; // 对应 kLoadField 或 kLoadFromObject
  obj.a = 2;         // 对应 kStoreField
  globalThis.b = 3;  // 对应 kStoreGlobal (大致)
  ```

- **数组操作 (Array Operations):** `kLoadElement`, `kStoreElement`, `kNewDoubleElements`, `kNewSmiOrObjectElements` 等操作对应 JavaScript 中的数组访问和创建。
  ```javascript
  const arr = [1, 2];
  const element = arr[0]; // 对应 kLoadElement
  arr[1] = 3;             // 对应 kStoreElement
  const doubleArr = new Float64Array(5); // 对应 kNewDoubleElements
  const objectArr = [];                 // 对应 kNewSmiOrObjectElements
  ```

- **字符串操作 (String Operations):** `kStringLength`, `kStringIndexOf`, `kStringConcat` 等操作对应 JavaScript 中的字符串方法。
  ```javascript
  const str = "hello";
  const length = str.length;         // 对应 kStringLength
  const index = str.indexOf("l");    // 对应 kStringIndexOf
  const newStr = str + " world";    // 对应 kStringConcat
  ```

- **算术运算 (Arithmetic Operations):** `kCheckedInt32Add`, `kBigIntAdd` 等操作对应 JavaScript 中的算术运算符。
  ```javascript
  const sum = 10 + 5;     // 可能对应 kCheckedInt32Add
  const bigSum = 10n + 5n; // 对应 kBigIntAdd
  ```

- **类型检查 (Type Checks):** `kTypeOf` 操作对应 JavaScript 中的 `typeof` 运算符。
  ```javascript
  typeof 123; // 对应 kTypeOf
  ```

**代码逻辑推理 (Hypothetical Input and Output):**

假设输入一个表示 JavaScript 属性读取的 IR 节点：

**输入 (假设的 IR 节点结构):**
```
{
  opcode: IrOpcode::kLoadField,
  inputs: [object_node_index, /* offset information embedded in the opcode */],
  operator_properties: {
    field_access: {
      offset: 8, // 假设字段偏移量为 8
      machine_type: MachineType::Int32() // 假设字段类型为 Int32
    }
  }
}
```

**输出 (Turboshaft 图操作):**
```
__ Load(Map(inputs[0]), StoreOp::Kind::Aligned(true), MemoryRepresentation::Int32(), 8);
```
这里假设 `inputs[0]` 对应的节点已经转换为 Turboshaft 图中的 `Map` 操作，并且基础对象是 tagged (aligned)。输出的 Turboshaft `Load` 操作指示从指定对象的偏移量 8 处加载一个 Int32 类型的值。

**用户常见的编程错误 (Common Programming Errors):**

一些与这段代码相关的常见编程错误包括：

1. **类型错误 (Type Errors):**  在需要特定类型的地方使用了错误的类型，例如尝试将一个字符串存储到期望数字的数组中，这可能触发类似 `kTransitionAndStoreNumberElement` 或 `kTransitionAndStoreNonNumberElement` 的逻辑。

   ```javascript
   const arr = new Float64Array(1);
   arr[0] = "hello"; // 尝试将字符串赋值给 Float64Array
   ```

2. **越界访问 (Out-of-bounds Access):** 尝试访问数组或字符串的非法索引，这可能涉及到 `kCheckedUint32Bounds` 或 `kCheckedUint64Bounds` 的检查。

   ```javascript
   const arr = [1, 2];
   const value = arr[2]; // 越界访问
   ```

3. **空指针引用 (Null Pointer Dereference - 概念上类似):**  虽然 JavaScript 中没有直接的指针，但访问 `null` 或 `undefined` 的属性会导致错误，这在编译器的层面可能涉及到检查对象是否存在。

   ```javascript
   const obj = null;
   const value = obj.a; // 尝试访问 null 的属性
   ```

4. **算术溢出 (Arithmetic Overflow):** 在进行整数运算时超出最大或最小表示范围，相关的操作码如 `kCheckedInt32Add` 等会进行检查并可能导致去优化。

   ```javascript
   const MAX_INT = 2147483647;
   const result = MAX_INT + 1; // 整数溢出
   ```

**功能归纳 (Summary of Functionality):**

作为第 3 部分（共 4 部分），这段代码的功能可以归纳为：**构建 Turboshaft 编译图的核心逻辑，负责将高级的中间表示 (IR) 操作转换为底层的、更接近机器指令的操作，以便后续的优化和代码生成。**  它处理了 V8 引擎中大量的 JavaScript 语义相关的操作，包括内存访问、对象操作、算术运算、字符串处理、类型检查和控制流等，是连接前端 IR 和后端代码生成的重要桥梁。这段代码展示了 Turboshaft 如何针对不同的 IR 操作码生成相应的图节点，这些节点构成了最终可执行代码的基础。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
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

"""


```