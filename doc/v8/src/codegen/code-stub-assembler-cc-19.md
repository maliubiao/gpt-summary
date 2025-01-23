Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `code-stub-assembler.cc`. They have several constraints:

1. **List Functionality:** Describe what the code does.
2. **Torque Check:**  Determine if it *would* be a Torque file if it had a `.tq` extension.
3. **JavaScript Relation:** If it relates to JavaScript features, provide a JavaScript example.
4. **Logic Inference:** If there's logical deduction, show example input and output.
5. **Common Errors:** If it helps prevent common programming errors, illustrate with an example.
6. **Summary:** Provide a high-level summary of its role within the larger codebase, considering this is part 20 of 23.

Let's break down the code and address each point:

**Code Analysis:**

The code defines several methods within the `CodeStubAssembler` class. These methods appear to be low-level building blocks for generating machine code. They handle:

* **`instanceof`:** Implementing the `instanceof` operator.
* **Number Arithmetic:** Incrementing, decrementing, adding, and subtracting numbers, handling both Small Integers (Smis) and Heap Numbers.
* **Bitwise Operations:** Performing bitwise AND, OR, XOR, and shift operations on numbers. It distinguishes between Smi and generic Number operations.
* **Iterator Result Allocation:** Creating `JSIteratorResult` objects, which are used in the iteration protocol.
* **Promise Allocation:** Creating `JSPromiseWithResolversResult` objects.
* **Array Species Creation:**  Implementing the `ArraySpeciesCreate` abstract operation.
* **Array Buffer Handling:** Functions for checking if an `ArrayBuffer` is detached, loading its byte length, backing store pointer, and related operations for `ArrayBufferView` and `TypedArray`. This includes handling variable-length typed arrays (likely related to resizable array buffers).
* **CodeStubArguments:** A class for accessing arguments passed to a generated code stub.
* **Elements Kind Checks:**  Functions to determine the element kind of an array (e.g., packed, holey, smi-only, double).

**Constraint Fulfillment:**

1. **Functionality:** The code provides low-level functions for common JavaScript operations, data structure creation (for iterators and promises), and array buffer manipulation, used in the V8 code generation pipeline.

2. **Torque Check:**  The code is written in C++. If `v8/src/codegen/code-stub-assembler.cc` were named `v8/src/codegen/code-stub-assembler.tq`, it *would* be a V8 Torque source file. Torque is V8's domain-specific language for code generation.

3. **JavaScript Relation:** Many of these operations directly correspond to JavaScript features.

   ```javascript
   // instanceof
   const arr = [];
   console.log(arr instanceof Array); // relates to GotoIfNot(IsCallable(...)) and CallBuiltin(Builtin::kOrdinaryHasInstance, ...)

   // Number arithmetic
   let x = 5;
   x++; // relates to NumberInc
   x--; // relates to NumberDec
   let y = 10;
   let sum = x + y; // relates to NumberAdd
   let diff = x - y; // relates to NumberSub

   // Bitwise operations
   let a = 5; // 0101
   let b = 3; // 0011
   console.log(a & b); // relates to BitwiseOp with Operation::kBitwiseAnd
   console.log(a << b); // relates to BitwiseOp with Operation::kShiftLeft

   // Iterators
   const iterable = [1, 2, 3];
   const iterator = iterable[Symbol.iterator]();
   console.log(iterator.next()); // relates to AllocateJSIteratorResult

   // Promises
   const promiseWithResolvers = Promise.withResolvers(); // relates to AllocatePromiseWithResolversResult

   // Array species creation
   class MyArray extends Array {}
   const myArray = new MyArray(5);
   const anotherArray = myArray.slice(); // Internally might use ArraySpeciesCreate

   // ArrayBuffers and TypedArrays
   const buffer = new ArrayBuffer(16);
   const view = new Uint32Array(buffer); // relates to LoadJSArrayBufferByteLength, LoadJSArrayBufferViewByteLength, etc.
   ```

4. **Logic Inference:**

   **Example: `NumberInc`**

   * **Assumption Input:** `value` is a Smi representing the number 5.
   * **Steps:**
      1. `TaggedIsSmi(value)` is true.
      2. Enters the `if_issmi` block.
      3. `smi_value` becomes 5 (Smi).
      4. `one` is the Smi 1.
      5. `TrySmiAdd(smi_value, one, &if_overflow)` attempts to add 5 + 1.
      6. Since there's no overflow, `var_result` becomes the Smi representing 6.
      7. Jumps to `end`.
   * **Output:** Returns the Smi representing 6.

   **Example: `instanceof`**

   * **Assumption Input:** `object` is an instance of `Array`, `callable` is the `Array` constructor, `context` is valid.
   * **Steps:**
      1. `TaggedIsSmi(object)` is false (assuming a typical array).
      2. `IsJSReceiver(CAST(object))` is true.
      3. `IsCallable(CAST(callable))` is true.
      4. `CallBuiltin(Builtin::kOrdinaryHasInstance, context, callable, object)` is called. This builtin performs the core logic of `instanceof`.
      5. Assuming `OrdinaryHasInstance` returns true, `var_result` becomes `TrueConstant()`.
      6. Jumps to `return_result`.
   * **Output:** Returns the boolean true.

5. **Common Errors:**

   The `ThrowTypeError` calls in the `instanceof` implementation help prevent common errors:

   ```javascript
   // Common Error 1: Using instanceof with a non-object
   try {
     console.log(5 instanceof Array); // Would trigger "Non-object in instanceof check"
   } catch (e) {
     console.error(e);
   }

   // Common Error 2: Using instanceof with a non-callable
   try {
     const notAConstructor = {};
     console.log([] instanceof notAConstructor); // Would trigger "Non-callable in instanceof check"
   } catch (e) {
     console.error(e);
   }

   // Common Error 3: Operating on a detached ArrayBuffer
   const buffer = new ArrayBuffer(8);
   const view = new Uint32Array(buffer);
   buffer.detach();
   try {
     console.log(view[0]); // Would trigger "Detached operation" (handled by ThrowIfArrayBufferIsDetached/ThrowIfArrayBufferViewBufferIsDetached)
   } catch (e) {
     console.error(e);
   }
   ```

6. **Summary:**

   Given that this is part 20 of 23, and considering the functionalities covered, this section of `code-stub-assembler.cc` likely focuses on **implementing core JavaScript operators, built-in functions, and object model features at a low level**. It provides the foundational building blocks that higher-level code generation (potentially including Torque-generated code) relies on. The focus on array buffers and typed arrays suggests involvement in efficient data handling, likely used in performance-sensitive parts of the engine. The inclusion of `CodeStubArguments` indicates this code is directly involved in handling the execution of generated code stubs, which are small pieces of machine code for specific operations. It seems like this part deals with essential runtime functionalities and error handling for those functionalities.

这是 `v8/src/codegen/code-stub-assembler.cc` 的第 20 部分，它主要包含 `CodeStubAssembler` 类中用于实现各种 JavaScript 核心功能的低级代码生成助手函数。从提供的代码片段来看，其功能可以归纳为以下几点：

**功能列举:**

1. **实现 `instanceof` 运算符:**
   -  这段代码实现了 JavaScript 的 `instanceof` 运算符的逻辑。它检查一个对象是否是某个构造函数的实例。
   -  它首先检查操作数是否是接收者（对象）和可调用的（构造函数）。
   -  如果都满足条件，则调用内置的 `OrdinaryHasInstance` 算法来确定是否是实例。
   -  如果接收者不是对象或可调用者不是函数，则抛出 `TypeError`。

2. **实现数值的递增和递减操作:**
   -  `NumberInc(TNode<Number> value)` 函数实现了数值的递增操作 (`++`)。它会处理 Smi（小整数）和 HeapNumber（堆上的数字对象）两种情况，并处理溢出的情况。
   -  `NumberDec(TNode<Number> value)` 函数实现了数值的递减操作 (`--`)，逻辑与递增类似。

3. **实现数值的加法和减法操作:**
   -  `NumberAdd(TNode<Number> a, TNode<Number> b)` 函数实现了数值的加法操作 (`+`)。它尝试先进行快速的 Smi 加法，如果操作数不是 Smi，则转换为 Float64 进行加法。
   -  `NumberSub(TNode<Number> a, TNode<Number> b)` 函数实现了数值的减法操作 (`-`)，逻辑与加法类似。

4. **检查对象是否为数字:**
   -  `GotoIfNotNumber` 和 `GotoIfNumber` 函数用于在生成的代码中进行条件跳转，判断一个对象是否为数字（Smi 或 HeapNumber）。

5. **规范化位移操作数:**
   -  `NormalizeShift32OperandIfNecessary` 函数用于规范化 32 位位移操作的右操作数，确保位移量在有效范围内。

6. **实现位运算:**
   -  `BitwiseOp` 函数根据传入的操作类型 (`bitwise_op`) 执行不同的位运算（AND, OR, XOR, SHL, SAR, SHR）。
   -  `BitwiseSmiOp` 函数针对 Smi 类型的操作数执行位运算，并针对 Smi 特有的优化进行处理。

7. **分配 JSIteratorResult 对象:**
   -  `AllocateJSIteratorResult` 和 `AllocateJSIteratorResultForEntry` 函数用于分配表示迭代器结果的对象。这在实现 JavaScript 的迭代器协议时使用。

8. **分配 PromiseWithResolversResult 对象:**
   -  `AllocatePromiseWithResolversResult` 函数用于分配 `Promise.withResolvers()` 返回的对象，该对象包含 Promise 实例以及其 resolve 和 reject 函数。

9. **创建数组的派生物（Species）:**
   -  `ArraySpeciesCreate` 函数实现了根据给定对象创建一个新的数组派生物的逻辑。这与 `Symbol.species` 有关。

10. **处理 ArrayBuffer 的分离状态:**
    - `ThrowIfArrayBufferIsDetached` 和 `ThrowIfArrayBufferViewBufferIsDetached` 函数用于检查 `ArrayBuffer` 是否已分离，如果已分离则抛出 `TypeError`。这对于防止在分离的缓冲区上进行操作非常重要。

11. **加载和存储 ArrayBuffer 和 ArrayBufferView 的属性:**
    -  提供了许多函数用于加载 `JSArrayBuffer` 和 `JSArrayBufferView` 的各种属性，如字节长度、最大字节长度、后备存储指针、字节偏移量等。

12. **处理 JSTypedArray 的长度和分离状态:**
    -  `LoadJSTypedArrayLengthAndCheckDetached` 和 `LoadVariableLengthJSTypedArrayLength` 等函数用于加载 `JSTypedArray` 的长度，并检查其底层的 `ArrayBuffer` 是否已分离或超出边界。  这些函数还考虑了可变长度的 `TypedArray` 的情况。

13. **判断 JSArrayBufferView 是否已分离或超出边界:**
    - `IsJSArrayBufferViewDetachedOrOutOfBounds` 和 `IsJSArrayBufferViewDetachedOrOutOfBoundsBoolean` 用于判断 `ArrayBufferView` 是否因为其底层的 `ArrayBuffer` 分离或者访问超出其边界而处于无效状态。

14. **检查 JSTypedArray 的索引:**
    - `CheckJSTypedArrayIndex` 函数用于检查访问 `JSTypedArray` 的索引是否有效，即是否在数组的长度范围内，并检查底层缓冲区是否已分离。

15. **获取 TypedArray 的 Buffer:**
    - `GetTypedArrayBuffer` 函数用于获取 `JSTypedArray` 的底层 `ArrayBuffer`。

16. **处理代码 Stub 的参数:**
    - `CodeStubArguments` 类用于访问传递给生成的代码 Stub 的参数。它提供了获取接收者、参数值、参数长度等方法。

17. **判断 ElementsKind:**
    - 提供了多个 `IsFastElementsKind`、`IsFastPackedElementsKind` 等函数，用于判断数组的元素类型（ElementsKind），例如是否为快速元素、是否已打包、是否为双精度浮点数等。这些判断对于 V8 的性能优化至关重要。

**如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾:**

如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是 V8 开发的一种用于编写高效的运行时代码的领域特定语言。Torque 代码会被编译成 C++ 代码，最终被 V8 使用。

**与 JavaScript 功能的关系及 JavaScript 示例:**

上述列举的功能都与 JavaScript 的核心功能息息相关。以下是一些 JavaScript 示例：

```javascript
// instanceof
const arr = [];
console.log(arr instanceof Array); // 使用了 CodeStubAssembler::IsCallable 和 CallBuiltin(Builtin::kOrdinaryHasInstance, ...)

// 数值的递增和递减
let num = 5;
num++; // 使用了 CodeStubAssembler::NumberInc
num--; // 使用了 CodeStubAssembler::NumberDec

// 数值的加法和减法
let a = 10;
let b = 5;
let sum = a + b; // 使用了 CodeStubAssembler::NumberAdd
let diff = a - b; // 使用了 CodeStubAssembler::NumberSub

// 位运算
let x = 3;
let y = 5;
console.log(x & y); // 使用了 CodeStubAssembler::BitwiseOp 或 CodeStubAssembler::BitwiseSmiOp

// 迭代器
const iterable = [1, 2, 3];
const iterator = iterable[Symbol.iterator]();
console.log(iterator.next()); //  涉及到 AllocateJSIteratorResult

// Promise
const { promise, resolve, reject } = Promise.withResolvers(); // 涉及到 AllocatePromiseWithResolversResult

// ArrayBuffer 和 TypedArray
const buffer = new ArrayBuffer(16);
const view = new Uint32Array(buffer);
console.log(view.byteLength); //  使用了 CodeStubAssembler::LoadJSArrayBufferByteLength 等
try {
  buffer.detach();
  console.log(view[0]); // 可能会触发由 ThrowIfArrayBufferIsDetached 导致的错误
} catch (e) {
  console.error(e);
}
```

**代码逻辑推理示例:**

**假设输入:** `CodeStubAssembler::NumberInc` 函数接收到一个表示 Smi 值 10 的 `TNode<Number>`。

**输出:** 函数将返回一个新的 `TNode<Number>`，该节点表示 Smi 值 11。

**推理过程:**

1. `TaggedIsSmi(value)` 会判断输入值是否为 Smi，结果为 true。
2. 进入 `if_issmi` 代码块。
3. `smi_value` 被转换为 `TNode<Smi>`，其值为 10。
4. `one` 是一个表示 Smi 值 1 的常量。
5. `TrySmiAdd(smi_value, one, &if_overflow)` 尝试将 10 和 1 相加。
6. 由于没有溢出，`TrySmiAdd` 会返回一个表示 Smi 值 11 的 `TNode<Smi>`，并赋值给 `var_result`。
7. 跳转到 `end` 标签。
8. 函数返回 `var_result.value()`，即表示 Smi 值 11 的 `TNode<Number>`。

**用户常见的编程错误示例:**

1. **在 `instanceof` 中使用非对象或非函数:**
   ```javascript
   console.log(5 instanceof Array); // 错误：5 不是对象
   console.log([] instanceof 123); // 错误：123 不是函数
   ```
   `CodeStubAssembler` 中的 `GotoIfNot` 和 `ThrowTypeError` 可以防止这些错误，并在运行时抛出相应的异常。

2. **在 ArrayBuffer 分离后尝试访问其内容:**
   ```javascript
   const buffer = new ArrayBuffer(8);
   const view = new Uint32Array(buffer);
   buffer.detach();
   console.log(view[0]); // 错误：在分离的 ArrayBuffer 上进行操作
   ```
   `ThrowIfArrayBufferIsDetached` 和 `ThrowIfArrayBufferViewBufferIsDetached` 函数旨在捕获这类错误。

3. **访问 JSTypedArray 超出索引范围:**
   ```javascript
   const arr = new Uint32Array(5);
   console.log(arr[10]); // 错误：索引超出范围
   ```
   虽然提供的代码片段没有直接展示边界检查，但在 V8 的其他部分或更完整的 `CodeStubAssembler` 代码中，会有相应的逻辑（可能与 `CheckJSTypedArrayIndex` 相关）来处理这类错误，或者在生成代码时就避免越界访问。

**功能归纳 (第 20 部分，共 23 部分):**

作为整个 `code-stub-assembler.cc` 的一部分，并且是接近尾声的部分，这部分代码主要负责实现 **JavaScript 语言的核心运算符、内置函数以及与内存管理相关的底层操作**。它提供了用于处理数值运算、类型检查（如 `instanceof`）、位运算、迭代器和 Promise 等关键特性的基本构建块。尤其关注 `ArrayBuffer` 和 `TypedArray` 的处理，暗示了对内存安全和性能的高度重视。  `CodeStubArguments` 类的存在表明这部分代码与 V8 执行代码片段（code stubs）的机制紧密相关。  考虑到这是第 20 部分，可以推断之前的章节可能已经定义了更基础的工具函数和数据结构，而接下来的章节可能会涉及更高级的代码生成或与特定平台架构相关的细节。 总之，这一部分是 V8 代码生成器中至关重要的一环，它将高级的 JavaScript 语义转化为可以高效执行的底层操作。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第20部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
GotoIfNot(IsCallable(CAST(callable)), &if_notcallable);

    // Use the OrdinaryHasInstance algorithm.
    var_result = CAST(
        CallBuiltin(Builtin::kOrdinaryHasInstance, context, callable, object));
    Goto(&return_result);
  }

  BIND(&if_notcallable);
  { ThrowTypeError(context, MessageTemplate::kNonCallableInInstanceOfCheck); }

  BIND(&if_notreceiver);
  { ThrowTypeError(context, MessageTemplate::kNonObjectInInstanceOfCheck); }

  BIND(&return_true);
  var_result = TrueConstant();
  Goto(&return_result);

  BIND(&return_false);
  var_result = FalseConstant();
  Goto(&return_result);

  BIND(&return_result);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::NumberInc(TNode<Number> value) {
  TVARIABLE(Number, var_result);
  TVARIABLE(Float64T, var_finc_value);
  Label if_issmi(this), if_isnotsmi(this), do_finc(this), end(this);
  Branch(TaggedIsSmi(value), &if_issmi, &if_isnotsmi);

  BIND(&if_issmi);
  {
    Label if_overflow(this);
    TNode<Smi> smi_value = CAST(value);
    TNode<Smi> one = SmiConstant(1);
    var_result = TrySmiAdd(smi_value, one, &if_overflow);
    Goto(&end);

    BIND(&if_overflow);
    {
      var_finc_value = SmiToFloat64(smi_value);
      Goto(&do_finc);
    }
  }

  BIND(&if_isnotsmi);
  {
    TNode<HeapNumber> heap_number_value = CAST(value);

    // Load the HeapNumber value.
    var_finc_value = LoadHeapNumberValue(heap_number_value);
    Goto(&do_finc);
  }

  BIND(&do_finc);
  {
    TNode<Float64T> finc_value = var_finc_value.value();
    TNode<Float64T> one = Float64Constant(1.0);
    TNode<Float64T> finc_result = Float64Add(finc_value, one);
    var_result = AllocateHeapNumberWithValue(finc_result);
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::NumberDec(TNode<Number> value) {
  TVARIABLE(Number, var_result);
  TVARIABLE(Float64T, var_fdec_value);
  Label if_issmi(this), if_isnotsmi(this), do_fdec(this), end(this);
  Branch(TaggedIsSmi(value), &if_issmi, &if_isnotsmi);

  BIND(&if_issmi);
  {
    TNode<Smi> smi_value = CAST(value);
    TNode<Smi> one = SmiConstant(1);
    Label if_overflow(this);
    var_result = TrySmiSub(smi_value, one, &if_overflow);
    Goto(&end);

    BIND(&if_overflow);
    {
      var_fdec_value = SmiToFloat64(smi_value);
      Goto(&do_fdec);
    }
  }

  BIND(&if_isnotsmi);
  {
    TNode<HeapNumber> heap_number_value = CAST(value);

    // Load the HeapNumber value.
    var_fdec_value = LoadHeapNumberValue(heap_number_value);
    Goto(&do_fdec);
  }

  BIND(&do_fdec);
  {
    TNode<Float64T> fdec_value = var_fdec_value.value();
    TNode<Float64T> minus_one = Float64Constant(-1.0);
    TNode<Float64T> fdec_result = Float64Add(fdec_value, minus_one);
    var_result = AllocateHeapNumberWithValue(fdec_result);
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::NumberAdd(TNode<Number> a, TNode<Number> b) {
  TVARIABLE(Number, var_result);
  Label float_add(this, Label::kDeferred), end(this);
  GotoIf(TaggedIsNotSmi(a), &float_add);
  GotoIf(TaggedIsNotSmi(b), &float_add);

  // Try fast Smi addition first.
  var_result = TrySmiAdd(CAST(a), CAST(b), &float_add);
  Goto(&end);

  BIND(&float_add);
  {
    var_result = ChangeFloat64ToTagged(
        Float64Add(ChangeNumberToFloat64(a), ChangeNumberToFloat64(b)));
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::NumberSub(TNode<Number> a, TNode<Number> b) {
  TVARIABLE(Number, var_result);
  Label float_sub(this, Label::kDeferred), end(this);
  GotoIf(TaggedIsNotSmi(a), &float_sub);
  GotoIf(TaggedIsNotSmi(b), &float_sub);

  // Try fast Smi subtraction first.
  var_result = TrySmiSub(CAST(a), CAST(b), &float_sub);
  Goto(&end);

  BIND(&float_sub);
  {
    var_result = ChangeFloat64ToTagged(
        Float64Sub(ChangeNumberToFloat64(a), ChangeNumberToFloat64(b)));
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

void CodeStubAssembler::GotoIfNotNumber(TNode<Object> input,
                                        Label* is_not_number) {
  Label is_number(this);
  GotoIf(TaggedIsSmi(input), &is_number);
  Branch(IsHeapNumber(CAST(input)), &is_number, is_not_number);
  BIND(&is_number);
}

void CodeStubAssembler::GotoIfNumber(TNode<Object> input, Label* is_number) {
  GotoIf(TaggedIsSmi(input), is_number);
  GotoIf(IsHeapNumber(CAST(input)), is_number);
}

TNode<Word32T> CodeStubAssembler::NormalizeShift32OperandIfNecessary(
    TNode<Word32T> right32) {
  TVARIABLE(Word32T, result, right32);
  Label done(this);
  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  GotoIf(UniqueInt32Constant(Word32ShiftIsSafe()), &done);
  {
    result = Word32And(right32, Int32Constant(0x1F));
    Goto(&done);
  }
  BIND(&done);
  return result.value();
}

TNode<Number> CodeStubAssembler::BitwiseOp(TNode<Word32T> left32,
                                           TNode<Word32T> right32,
                                           Operation bitwise_op) {
  switch (bitwise_op) {
    case Operation::kBitwiseAnd:
      return ChangeInt32ToTagged(Signed(Word32And(left32, right32)));
    case Operation::kBitwiseOr:
      return ChangeInt32ToTagged(Signed(Word32Or(left32, right32)));
    case Operation::kBitwiseXor:
      return ChangeInt32ToTagged(Signed(Word32Xor(left32, right32)));
    case Operation::kShiftLeft:
      right32 = NormalizeShift32OperandIfNecessary(right32);
      return ChangeInt32ToTagged(Signed(Word32Shl(left32, right32)));
    case Operation::kShiftRight:
      right32 = NormalizeShift32OperandIfNecessary(right32);
      return ChangeInt32ToTagged(Signed(Word32Sar(left32, right32)));
    case Operation::kShiftRightLogical:
      right32 = NormalizeShift32OperandIfNecessary(right32);
      return ChangeUint32ToTagged(Unsigned(Word32Shr(left32, right32)));
    default:
      break;
  }
  UNREACHABLE();
}

TNode<Number> CodeStubAssembler::BitwiseSmiOp(TNode<Smi> left, TNode<Smi> right,
                                              Operation bitwise_op) {
  switch (bitwise_op) {
    case Operation::kBitwiseAnd:
      return SmiAnd(left, right);
    case Operation::kBitwiseOr:
      return SmiOr(left, right);
    case Operation::kBitwiseXor:
      return SmiXor(left, right);
    // Smi shift left and logical shift rihgt can have (Heap)Number output, so
    // perform int32 operation.
    case Operation::kShiftLeft:
    case Operation::kShiftRightLogical:
      return BitwiseOp(SmiToInt32(left), SmiToInt32(right), bitwise_op);
    // Arithmetic shift right of a Smi can't overflow to the heap number, so
    // perform int32 operation but don't check for overflow.
    case Operation::kShiftRight: {
      TNode<Int32T> left32 = SmiToInt32(left);
      TNode<Int32T> right32 =
          Signed(NormalizeShift32OperandIfNecessary(SmiToInt32(right)));
      return ChangeInt32ToTaggedNoOverflow(Word32Sar(left32, right32));
    }
    default:
      break;
  }
  UNREACHABLE();
}

TNode<JSObject> CodeStubAssembler::AllocateJSIteratorResult(
    TNode<Context> context, TNode<Object> value, TNode<Boolean> done) {
  CSA_DCHECK(this, IsBoolean(done));
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> map = CAST(
      LoadContextElement(native_context, Context::ITERATOR_RESULT_MAP_INDEX));
  TNode<HeapObject> result = Allocate(JSIteratorResult::kSize);
  StoreMapNoWriteBarrier(result, map);
  StoreObjectFieldRoot(result, JSIteratorResult::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(result, JSIteratorResult::kElementsOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldNoWriteBarrier(result, JSIteratorResult::kValueOffset, value);
  StoreObjectFieldNoWriteBarrier(result, JSIteratorResult::kDoneOffset, done);
  return CAST(result);
}

TNode<JSObject> CodeStubAssembler::AllocateJSIteratorResultForEntry(
    TNode<Context> context, TNode<Object> key, TNode<Object> value) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Smi> length = SmiConstant(2);
  int const elements_size = FixedArray::SizeFor(2);
  TNode<FixedArray> elements =
      UncheckedCast<FixedArray>(Allocate(elements_size));
  StoreObjectFieldRoot(elements, offsetof(FixedArray, map_),
                       RootIndex::kFixedArrayMap);
  StoreObjectFieldNoWriteBarrier(elements, offsetof(FixedArray, length_),
                                 length);
  StoreFixedArrayElement(elements, 0, key);
  StoreFixedArrayElement(elements, 1, value);
  TNode<Map> array_map = CAST(LoadContextElement(
      native_context, Context::JS_ARRAY_PACKED_ELEMENTS_MAP_INDEX));
  TNode<HeapObject> array =
      Allocate(ALIGN_TO_ALLOCATION_ALIGNMENT(JSArray::kHeaderSize));
  StoreMapNoWriteBarrier(array, array_map);
  StoreObjectFieldRoot(array, JSArray::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldNoWriteBarrier(array, JSArray::kElementsOffset, elements);
  StoreObjectFieldNoWriteBarrier(array, JSArray::kLengthOffset, length);
  TNode<Map> iterator_map = CAST(
      LoadContextElement(native_context, Context::ITERATOR_RESULT_MAP_INDEX));
  TNode<HeapObject> result = Allocate(JSIteratorResult::kSize);
  StoreMapNoWriteBarrier(result, iterator_map);
  StoreObjectFieldRoot(result, JSIteratorResult::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(result, JSIteratorResult::kElementsOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldNoWriteBarrier(result, JSIteratorResult::kValueOffset, array);
  StoreObjectFieldRoot(result, JSIteratorResult::kDoneOffset,
                       RootIndex::kFalseValue);
  return CAST(result);
}

TNode<JSObject> CodeStubAssembler::AllocatePromiseWithResolversResult(
    TNode<Context> context, TNode<Object> promise, TNode<Object> resolve,
    TNode<Object> reject) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> map = CAST(LoadContextElement(
      native_context, Context::PROMISE_WITHRESOLVERS_RESULT_MAP_INDEX));
  TNode<HeapObject> result = Allocate(JSPromiseWithResolversResult::kSize);
  StoreMapNoWriteBarrier(result, map);
  StoreObjectFieldRoot(result,
                       JSPromiseWithResolversResult::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(result, JSPromiseWithResolversResult::kElementsOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldNoWriteBarrier(
      result, JSPromiseWithResolversResult::kPromiseOffset, promise);
  StoreObjectFieldNoWriteBarrier(
      result, JSPromiseWithResolversResult::kResolveOffset, resolve);
  StoreObjectFieldNoWriteBarrier(
      result, JSPromiseWithResolversResult::kRejectOffset, reject);
  return CAST(result);
}

TNode<JSReceiver> CodeStubAssembler::ArraySpeciesCreate(TNode<Context> context,
                                                        TNode<Object> o,
                                                        TNode<Number> len) {
  TNode<JSReceiver> constructor =
      CAST(CallRuntime(Runtime::kArraySpeciesConstructor, context, o));
  return Construct(context, constructor, len);
}

void CodeStubAssembler::ThrowIfArrayBufferIsDetached(
    TNode<Context> context, TNode<JSArrayBuffer> array_buffer,
    const char* method_name) {
  Label if_detached(this, Label::kDeferred), if_not_detached(this);
  Branch(IsDetachedBuffer(array_buffer), &if_detached, &if_not_detached);
  BIND(&if_detached);
  ThrowTypeError(context, MessageTemplate::kDetachedOperation, method_name);
  BIND(&if_not_detached);
}

void CodeStubAssembler::ThrowIfArrayBufferViewBufferIsDetached(
    TNode<Context> context, TNode<JSArrayBufferView> array_buffer_view,
    const char* method_name) {
  TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(array_buffer_view);
  ThrowIfArrayBufferIsDetached(context, buffer, method_name);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSArrayBufferByteLength(
    TNode<JSArrayBuffer> array_buffer) {
  return LoadBoundedSizeFromObject(array_buffer,
                                   JSArrayBuffer::kRawByteLengthOffset);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSArrayBufferMaxByteLength(
    TNode<JSArrayBuffer> array_buffer) {
  return LoadBoundedSizeFromObject(array_buffer,
                                   JSArrayBuffer::kRawMaxByteLengthOffset);
}

TNode<RawPtrT> CodeStubAssembler::LoadJSArrayBufferBackingStorePtr(
    TNode<JSArrayBuffer> array_buffer) {
  return LoadSandboxedPointerFromObject(array_buffer,
                                        JSArrayBuffer::kBackingStoreOffset);
}

TNode<JSArrayBuffer> CodeStubAssembler::LoadJSArrayBufferViewBuffer(
    TNode<JSArrayBufferView> array_buffer_view) {
  return LoadObjectField<JSArrayBuffer>(array_buffer_view,
                                        JSArrayBufferView::kBufferOffset);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSArrayBufferViewByteLength(
    TNode<JSArrayBufferView> array_buffer_view) {
  return LoadBoundedSizeFromObject(array_buffer_view,
                                   JSArrayBufferView::kRawByteLengthOffset);
}

void CodeStubAssembler::StoreJSArrayBufferViewByteLength(
    TNode<JSArrayBufferView> array_buffer_view, TNode<UintPtrT> value) {
  StoreBoundedSizeToObject(array_buffer_view,
                           JSArrayBufferView::kRawByteLengthOffset, value);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSArrayBufferViewByteOffset(
    TNode<JSArrayBufferView> array_buffer_view) {
  return LoadBoundedSizeFromObject(array_buffer_view,
                                   JSArrayBufferView::kRawByteOffsetOffset);
}

void CodeStubAssembler::StoreJSArrayBufferViewByteOffset(
    TNode<JSArrayBufferView> array_buffer_view, TNode<UintPtrT> value) {
  StoreBoundedSizeToObject(array_buffer_view,
                           JSArrayBufferView::kRawByteOffsetOffset, value);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSTypedArrayLength(
    TNode<JSTypedArray> typed_array) {
  return LoadBoundedSizeFromObject(typed_array, JSTypedArray::kRawLengthOffset);
}

void CodeStubAssembler::StoreJSTypedArrayLength(TNode<JSTypedArray> typed_array,
                                                TNode<UintPtrT> value) {
  StoreBoundedSizeToObject(typed_array, JSTypedArray::kRawLengthOffset, value);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSTypedArrayLengthAndCheckDetached(
    TNode<JSTypedArray> typed_array, Label* detached) {
  TVARIABLE(UintPtrT, result);
  TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(typed_array);

  Label variable_length(this), fixed_length(this), end(this);
  Branch(IsVariableLengthJSArrayBufferView(typed_array), &variable_length,
         &fixed_length);
  BIND(&variable_length);
  {
    result =
        LoadVariableLengthJSTypedArrayLength(typed_array, buffer, detached);
    Goto(&end);
  }

  BIND(&fixed_length);
  {
    Label not_detached(this);
    Branch(IsDetachedBuffer(buffer), detached, &not_detached);
    BIND(&not_detached);
    result = LoadJSTypedArrayLength(typed_array);
    Goto(&end);
  }
  BIND(&end);
  return result.value();
}

// ES #sec-integerindexedobjectlength
TNode<UintPtrT> CodeStubAssembler::LoadVariableLengthJSTypedArrayLength(
    TNode<JSTypedArray> array, TNode<JSArrayBuffer> buffer,
    Label* detached_or_out_of_bounds) {
  // byte_length already takes array's offset into account.
  TNode<UintPtrT> byte_length = LoadVariableLengthJSArrayBufferViewByteLength(
      array, buffer, detached_or_out_of_bounds);
  TNode<IntPtrT> element_size =
      RabGsabElementsKindToElementByteSize(LoadElementsKind(array));
  return Unsigned(IntPtrDiv(Signed(byte_length), element_size));
}

TNode<UintPtrT>
CodeStubAssembler::LoadVariableLengthJSArrayBufferViewByteLength(
    TNode<JSArrayBufferView> array, TNode<JSArrayBuffer> buffer,
    Label* detached_or_out_of_bounds) {
  Label is_gsab(this), is_rab(this), end(this);
  TVARIABLE(UintPtrT, result);
  TNode<UintPtrT> array_byte_offset = LoadJSArrayBufferViewByteOffset(array);

  Branch(IsSharedArrayBuffer(buffer), &is_gsab, &is_rab);
  BIND(&is_gsab);
  {
    // Non-length-tracking GSAB-backed ArrayBufferViews shouldn't end up here.
    CSA_DCHECK(this, IsLengthTrackingJSArrayBufferView(array));
    // Read the byte length from the BackingStore.
    const TNode<ExternalReference> byte_length_function =
        ExternalConstant(ExternalReference::gsab_byte_length());
    TNode<ExternalReference> isolate_ptr =
        ExternalConstant(ExternalReference::isolate_address());
    TNode<UintPtrT> buffer_byte_length = UncheckedCast<UintPtrT>(
        CallCFunction(byte_length_function, MachineType::UintPtr(),
                      std::make_pair(MachineType::Pointer(), isolate_ptr),
                      std::make_pair(MachineType::AnyTagged(), buffer)));
    // Since the SharedArrayBuffer can't shrink, and we've managed to create
    // this JSArrayBufferDataView without throwing an exception, we know that
    // buffer_byte_length >= array_byte_offset.
    CSA_CHECK(this,
              UintPtrGreaterThanOrEqual(buffer_byte_length, array_byte_offset));
    result = UintPtrSub(buffer_byte_length, array_byte_offset);
    Goto(&end);
  }

  BIND(&is_rab);
  {
    GotoIf(IsDetachedBuffer(buffer), detached_or_out_of_bounds);

    TNode<UintPtrT> buffer_byte_length = LoadJSArrayBufferByteLength(buffer);

    Label is_length_tracking(this), not_length_tracking(this);
    Branch(IsLengthTrackingJSArrayBufferView(array), &is_length_tracking,
           &not_length_tracking);

    BIND(&is_length_tracking);
    {
      // The backing RAB might have been shrunk so that the start of the
      // TypedArray is already out of bounds.
      GotoIfNot(UintPtrLessThanOrEqual(array_byte_offset, buffer_byte_length),
                detached_or_out_of_bounds);
      result = UintPtrSub(buffer_byte_length, array_byte_offset);
      Goto(&end);
    }

    BIND(&not_length_tracking);
    {
      // Check if the backing RAB has shrunk so that the buffer is out of
      // bounds.
      TNode<UintPtrT> array_byte_length =
          LoadJSArrayBufferViewByteLength(array);
      GotoIfNot(UintPtrGreaterThanOrEqual(
                    buffer_byte_length,
                    UintPtrAdd(array_byte_offset, array_byte_length)),
                detached_or_out_of_bounds);
      result = array_byte_length;
      Goto(&end);
    }
  }
  BIND(&end);
  return result.value();
}

void CodeStubAssembler::IsJSArrayBufferViewDetachedOrOutOfBounds(
    TNode<JSArrayBufferView> array_buffer_view, Label* detached_or_oob,
    Label* not_detached_nor_oob) {
  TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(array_buffer_view);

  GotoIf(IsDetachedBuffer(buffer), detached_or_oob);
  GotoIfNot(IsVariableLengthJSArrayBufferView(array_buffer_view),
            not_detached_nor_oob);
  GotoIf(IsSharedArrayBuffer(buffer), not_detached_nor_oob);

  {
    TNode<UintPtrT> buffer_byte_length = LoadJSArrayBufferByteLength(buffer);
    TNode<UintPtrT> array_byte_offset =
        LoadJSArrayBufferViewByteOffset(array_buffer_view);

    Label length_tracking(this), not_length_tracking(this);
    Branch(IsLengthTrackingJSArrayBufferView(array_buffer_view),
           &length_tracking, &not_length_tracking);

    BIND(&length_tracking);
    {
      // The backing RAB might have been shrunk so that the start of the
      // TypedArray is already out of bounds.
      Branch(UintPtrLessThanOrEqual(array_byte_offset, buffer_byte_length),
             not_detached_nor_oob, detached_or_oob);
    }

    BIND(&not_length_tracking);
    {
      // Check if the backing RAB has shrunk so that the buffer is out of
      // bounds.
      TNode<UintPtrT> array_byte_length =
          LoadJSArrayBufferViewByteLength(array_buffer_view);
      Branch(UintPtrGreaterThanOrEqual(
                 buffer_byte_length,
                 UintPtrAdd(array_byte_offset, array_byte_length)),
             not_detached_nor_oob, detached_or_oob);
    }
  }
}

TNode<BoolT> CodeStubAssembler::IsJSArrayBufferViewDetachedOrOutOfBoundsBoolean(
    TNode<JSArrayBufferView> array_buffer_view) {
  Label is_detached_or_out_of_bounds(this),
      not_detached_nor_out_of_bounds(this), end(this);
  TVARIABLE(BoolT, result);

  IsJSArrayBufferViewDetachedOrOutOfBounds(array_buffer_view,
                                           &is_detached_or_out_of_bounds,
                                           &not_detached_nor_out_of_bounds);
  BIND(&is_detached_or_out_of_bounds);
  {
    result = BoolConstant(true);
    Goto(&end);
  }
  BIND(&not_detached_nor_out_of_bounds);
  {
    result = BoolConstant(false);
    Goto(&end);
  }
  BIND(&end);
  return result.value();
}

void CodeStubAssembler::CheckJSTypedArrayIndex(
    TNode<JSTypedArray> typed_array, TNode<UintPtrT> index,
    Label* detached_or_out_of_bounds) {
  TNode<UintPtrT> len = LoadJSTypedArrayLengthAndCheckDetached(
      typed_array, detached_or_out_of_bounds);

  GotoIf(UintPtrGreaterThanOrEqual(index, len), detached_or_out_of_bounds);
}

// ES #sec-integerindexedobjectbytelength
TNode<UintPtrT> CodeStubAssembler::LoadVariableLengthJSTypedArrayByteLength(
    TNode<Context> context, TNode<JSTypedArray> array,
    TNode<JSArrayBuffer> buffer) {
  Label miss(this), end(this);
  TVARIABLE(UintPtrT, result);

  TNode<UintPtrT> length =
      LoadVariableLengthJSTypedArrayLength(array, buffer, &miss);
  TNode<IntPtrT> element_size =
      RabGsabElementsKindToElementByteSize(LoadElementsKind(array));
  // Conversion to signed is OK since length < JSArrayBuffer::kMaxByteLength.
  TNode<IntPtrT> byte_length = IntPtrMul(Signed(length), element_size);
  result = Unsigned(byte_length);
  Goto(&end);
  BIND(&miss);
  {
    result = UintPtrConstant(0);
    Goto(&end);
  }
  BIND(&end);
  return result.value();
}

TNode<IntPtrT> CodeStubAssembler::RabGsabElementsKindToElementByteSize(
    TNode<Int32T> elements_kind) {
  TVARIABLE(IntPtrT, result);
  Label elements_8(this), elements_16(this), elements_32(this),
      elements_64(this), not_found(this), end(this);
  int32_t elements_kinds[] = {
      RAB_GSAB_UINT8_ELEMENTS,    RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
      RAB_GSAB_INT8_ELEMENTS,     RAB_GSAB_UINT16_ELEMENTS,
      RAB_GSAB_INT16_ELEMENTS,    RAB_GSAB_FLOAT16_ELEMENTS,
      RAB_GSAB_UINT32_ELEMENTS,   RAB_GSAB_INT32_ELEMENTS,
      RAB_GSAB_FLOAT32_ELEMENTS,  RAB_GSAB_FLOAT64_ELEMENTS,
      RAB_GSAB_BIGINT64_ELEMENTS, RAB_GSAB_BIGUINT64_ELEMENTS};
  Label* elements_kind_labels[] = {&elements_8,  &elements_8,  &elements_8,
                                   &elements_16, &elements_16, &elements_16,
                                   &elements_32, &elements_32, &elements_32,
                                   &elements_64, &elements_64, &elements_64};
  const size_t kTypedElementsKindCount =
      LAST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND -
      FIRST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND + 1;
  DCHECK_EQ(kTypedElementsKindCount, arraysize(elements_kinds));
  DCHECK_EQ(kTypedElementsKindCount, arraysize(elements_kind_labels));
  Switch(elements_kind, &not_found, elements_kinds, elements_kind_labels,
         kTypedElementsKindCount);
  BIND(&elements_8);
  {
    result = IntPtrConstant(1);
    Goto(&end);
  }
  BIND(&elements_16);
  {
    result = IntPtrConstant(2);
    Goto(&end);
  }
  BIND(&elements_32);
  {
    result = IntPtrConstant(4);
    Goto(&end);
  }
  BIND(&elements_64);
  {
    result = IntPtrConstant(8);
    Goto(&end);
  }
  BIND(&not_found);
  { Unreachable(); }
  BIND(&end);
  return result.value();
}

TNode<JSArrayBuffer> CodeStubAssembler::GetTypedArrayBuffer(
    TNode<Context> context, TNode<JSTypedArray> array) {
  Label call_runtime(this), done(this);
  TVARIABLE(Object, var_result);

  GotoIf(IsOnHeapTypedArray(array), &call_runtime);

  TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(array);
  GotoIf(IsDetachedBuffer(buffer), &call_runtime);
  var_result = buffer;
  Goto(&done);

  BIND(&call_runtime);
  {
    var_result = CallRuntime(Runtime::kTypedArrayGetBuffer, context, array);
    Goto(&done);
  }

  BIND(&done);
  return CAST(var_result.value());
}

CodeStubArguments::CodeStubArguments(CodeStubAssembler* assembler,
                                     TNode<IntPtrT> argc, TNode<RawPtrT> fp)
    : assembler_(assembler),
      argc_(argc),
      base_(),
      fp_(fp != nullptr ? fp : assembler_->LoadFramePointer()) {
  TNode<IntPtrT> offset = assembler_->IntPtrConstant(
      (StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
      kSystemPointerSize);
  DCHECK_NOT_NULL(argc_);
  // base_ points to the first argument, not the receiver
  // whether present or not.
  base_ = assembler_->RawPtrAdd(fp_, offset);
}

bool CodeStubArguments::MayHavePaddingArguments() const {
  // If we're using a dynamic parameter count, then there may be additional
  // padding arguments on the stack pushed by the caller.
  return assembler_->HasDynamicJSParameterCount();
}

TNode<Object> CodeStubArguments::GetReceiver() const {
  intptr_t offset = -kSystemPointerSize;
  return assembler_->LoadFullTagged(base_, assembler_->IntPtrConstant(offset));
}

void CodeStubArguments::SetReceiver(TNode<Object> object) const {
  intptr_t offset = -kSystemPointerSize;
  assembler_->StoreFullTaggedNoWriteBarrier(
      base_, assembler_->IntPtrConstant(offset), object);
}

TNode<RawPtrT> CodeStubArguments::AtIndexPtr(TNode<IntPtrT> index) const {
  TNode<IntPtrT> offset =
      assembler_->ElementOffsetFromIndex(index, SYSTEM_POINTER_ELEMENTS, 0);
  return assembler_->RawPtrAdd(base_, offset);
}

TNode<Object> CodeStubArguments::AtIndex(TNode<IntPtrT> index) const {
  CSA_DCHECK(assembler_, assembler_->UintPtrOrSmiLessThan(
                             index, GetLengthWithoutReceiver()));
  return assembler_->LoadFullTagged(AtIndexPtr(index));
}

TNode<Object> CodeStubArguments::AtIndex(int index) const {
  return AtIndex(assembler_->IntPtrConstant(index));
}

TNode<IntPtrT> CodeStubArguments::GetLengthWithoutReceiver() const {
  return assembler_->IntPtrSub(
      argc_, assembler_->IntPtrConstant(kJSArgcReceiverSlots));
}

TNode<IntPtrT> CodeStubArguments::GetLengthWithReceiver() const {
  return argc_;
}

TNode<Object> CodeStubArguments::GetOptionalArgumentValue(
    TNode<IntPtrT> index, TNode<Object> default_value) {
  CodeStubAssembler::TVariable<Object> result(assembler_);
  CodeStubAssembler::Label argument_missing(assembler_),
      argument_done(assembler_, &result);

  assembler_->GotoIf(
      assembler_->UintPtrGreaterThanOrEqual(index, GetLengthWithoutReceiver()),
      &argument_missing);
  result = AtIndex(index);
  assembler_->Goto(&argument_done);

  assembler_->BIND(&argument_missing);
  result = default_value;
  assembler_->Goto(&argument_done);

  assembler_->BIND(&argument_done);
  return result.value();
}

void CodeStubArguments::SetArgumentValue(TNode<IntPtrT> index,
                                         TNode<Object> value) {
  TNode<RawPtrT> slot = AtIndexPtr(index);
  assembler_->StoreFullTaggedNoWriteBarrier(slot, value);
}

void CodeStubArguments::ForEach(
    const CodeStubAssembler::VariableList& vars,
    const CodeStubArguments::ForEachBodyFunction& body, TNode<IntPtrT> first,
    TNode<IntPtrT> last) const {
  assembler_->Comment("CodeStubArguments::ForEach");
  if (first == nullptr) {
    first = assembler_->IntPtrConstant(0);
  }
  if (last == nullptr) {
    last = GetLengthWithoutReceiver();
  }
  TNode<RawPtrT> start = AtIndexPtr(first);
  TNode<RawPtrT> end = AtIndexPtr(last);
  const int increment = kSystemPointerSize;
  assembler_->BuildFastLoop<RawPtrT>(
      vars, start, end,
      [&](TNode<RawPtrT> current) {
        TNode<Object> arg = assembler_->LoadFullTagged(current);
        body(arg);
      },
      increment, CodeStubAssembler::LoopUnrollingMode::kNo,
      CodeStubAssembler::IndexAdvanceMode::kPost);
}

void CodeStubArguments::PopAndReturn(TNode<Object> value) {
  TNode<IntPtrT> argument_count = GetLengthWithReceiver();
  if (MayHavePaddingArguments()) {
    // If there may be padding arguments, we need to remove the maximum of the
    // parameter count and the actual argument count.
    // TODO(saelo): it would probably be nicer to have this logic in the
    // low-level assembler instead, where we also keep the parameter count
    // value. It's not even clear why we need this PopAndReturn method at all
    // in the higher-level CodeStubAssembler class, as the lower-level
    // assemblers should have all the necessary information.
    TNode<IntPtrT> parameter_count =
        assembler_->ChangeInt32ToIntPtr(assembler_->DynamicJSParameterCount());
    CodeStubAssembler::Label pop_parameter_count(assembler_),
        pop_argument_count(assembler_);
    assembler_->Branch(
        assembler_->IntPtrLessThan(argument_count, parameter_count),
        &pop_parameter_count, &pop_argument_count);
    assembler_->BIND(&pop_parameter_count);
    assembler_->PopAndReturn(parameter_count, value);
    assembler_->BIND(&pop_argument_count);
    assembler_->PopAndReturn(argument_count, value);
  } else {
    assembler_->PopAndReturn(argument_count, value);
  }
}

TNode<BoolT> CodeStubAssembler::IsFastElementsKind(
    TNode<Int32T> elements_kind) {
  static_assert(FIRST_ELEMENTS_KIND == FIRST_FAST_ELEMENTS_KIND);
  return Uint32LessThanOrEqual(elements_kind,
                               Int32Constant(LAST_FAST_ELEMENTS_KIND));
}

TNode<BoolT> CodeStubAssembler::IsFastPackedElementsKind(
    TNode<Int32T> elements_kind) {
  static_assert(FIRST_ELEMENTS_KIND == FIRST_FAST_ELEMENTS_KIND);
  // ElementsKind values that are even are packed. See
  // internal::IsFastPackedElementsKind.
  static_assert((~PACKED_SMI_ELEMENTS & 1) == 1);
  static_assert((~PACKED_ELEMENTS & 1) == 1);
  static_assert((~PACKED_DOUBLE_ELEMENTS & 1) == 1);
  return Word32And(IsNotSetWord32(elements_kind, 1),
                   IsFastElementsKind(elements_kind));
}

TNode<BoolT> CodeStubAssembler::IsFastOrNonExtensibleOrSealedElementsKind(
    TNode<Int32T> elements_kind) {
  static_assert(FIRST_ELEMENTS_KIND == FIRST_FAST_ELEMENTS_KIND);
  static_assert(LAST_FAST_ELEMENTS_KIND + 1 == PACKED_NONEXTENSIBLE_ELEMENTS);
  static_assert(PACKED_NONEXTENSIBLE_ELEMENTS + 1 ==
                HOLEY_NONEXTENSIBLE_ELEMENTS);
  static_assert(HOLEY_NONEXTENSIBLE_ELEMENTS + 1 == PACKED_SEALED_ELEMENTS);
  static_assert(PACKED_SEALED_ELEMENTS + 1 == HOLEY_SEALED_ELEMENTS);
  return Uint32LessThanOrEqual(elements_kind,
                               Int32Constant(HOLEY_SEALED_ELEMENTS));
}

TNode<BoolT> CodeStubAssembler::IsDoubleElementsKind(
    TNode<Int32T> elements_kind) {
  static_assert(FIRST_ELEMENTS_KIND == FIRST_FAST_ELEMENTS_KIND);
  static_assert((PACKED_DOUBLE_ELEMENTS & 1) == 0);
  static_assert(PACKED_DOUBLE_ELEMENTS + 1 == HOLEY_DOUBLE_ELEMENTS);
  return Word32Equal(Word32Shr(elements_kind, Int32Constant(1)),
                     Int32Constant(PACKED_DOUBLE_ELEMENTS / 2));
}

TNode<BoolT> CodeStubAssembler::IsFastSmiOrTaggedElementsKind(
    TNode<Int32T> elements_kind) {
  static_assert(FIRST_ELEMENTS_KIND == FIRST_FAST_ELEMENTS_KIND);
  static_assert(PACKED_DOUBLE_ELEMENTS > TERMINAL_FAST_ELEMENTS_KIND);
  static_assert(HOLEY_DOUBLE_ELEMENTS > TERMINAL_FAST_ELEMENTS_KIND);
  return Uint32LessThanOrEqual(elements_kind,
                               Int32Constant(TERMINAL_FAST_ELEMENTS_KIND));
}

TNode<BoolT> CodeStubAssembler::IsFastSmiElementsKind(
    TNode<Int32T> elements_kind) {
  return Uint32LessThanOrEqual(elements_kind,
                               Int32Constant(HOLEY_SMI_ELEMENTS));
}

TNode<BoolT> CodeStubAssembler::IsHoleyFastElementsKind(
    TNode<Int32T> elements_kind) {
  CSA_DCHECK(this, IsFastElementsKind(elements_kind));

  static_assert(HOLEY_SMI_ELEMENTS == (PACKED_SMI_ELEMENTS | 1));
  static_assert(HOLEY_ELEMENTS == (PACKED_ELEMENTS | 1));
  static_assert(HOLEY_DOUBLE_ELEMENTS == (PACKED_DOUBLE_ELEMENTS | 1));
  return IsSetWord32(elements_kind, 1);
}

TNode<BoolT> CodeStubAssembler::IsHoleyFastElementsKindForRead(
    TNode<Int32T> elements_kind) {
  CSA_DCHECK(this, Uint32LessThanOrEqual(
                       elements_kind,
                       Int32Constant(LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND)));

  static_assert(HOLEY_SMI_ELEMENTS == (PACKED_SMI_ELEMENTS | 1));
  static_assert(HOLEY_ELEMENTS == (PACKED_ELEMENTS | 1));
  static_assert(HOLEY_DOUBLE_ELEMENTS == (PACKED_DOUBLE_ELEMENTS | 1));
  static_assert(HOLEY_NONEXTENSIBLE_ELEMENTS ==
```