Response:
The user wants a summary of the provided C++ code snippet. The code appears to be part of the V8 JavaScript engine, specifically the `builtins-array-gen.cc` file which, as the prompt suggests, could relate to array built-in functions.

Here's a breakdown of how to approach this:

1. **Identify the file type:** The prompt explicitly states the file is `v8/src/builtins/builtins-array-gen.cc` and hints at Torque if it ended in `.tq`. Since it ends in `.cc`, it's standard C++ within the V8 project.

2. **Analyze the code structure:**  The code contains several function definitions. The names of these functions (e.g., `ArrayIncludesIndexofAssembler::GeneratePackedDoubles`, `TF_BUILTIN(ArrayIncludes, ArrayIncludesIndexofAssembler)`) suggest they are related to array methods like `includes` and `indexOf`. The `TF_BUILTIN` macro strongly indicates these are implementations of JavaScript built-in functions.

3. **Focus on the core logic:** The `GenerateSmiOrObject`, `GeneratePackedDoubles`, and `GenerateHoleyDoubles` functions seem to be the main logic for the `includes` and `indexOf` functionality. They handle different array element types (Smis/objects, packed doubles, holey doubles). The code uses labels and `GotoIf` statements, indicating a state machine-like control flow.

4. **Look for JavaScript connections:** The presence of functions like `ArrayPrototypeValues`, `ArrayPrototypeEntries`, `ArrayPrototypeKeys`, and `ArrayIteratorPrototypeNext` confirms a direct relationship with JavaScript's array iteration features.

5. **Infer functionality from names and operations:**  Function names like `ArrayIncludes`, `ArrayIndexOf`, `ArrayPrototypeValues`, etc., are strong indicators of their JavaScript counterparts. Operations like loading elements, comparing elements, and handling different element types (Smis, HeapNumbers, strings, BigInts) further clarify the purpose.

6. **Consider potential user errors:** The code handles `NaN` comparisons and checks for `undefined` and `the hole`, which are common scenarios in JavaScript array operations where users might encounter unexpected behavior.

7. **Formulate a summary:** Combine the observations into a concise description of the code's functionality.

**Self-Correction/Refinement:**

* Initially, I might just focus on the `includes` and `indexOf` parts. However, the latter part of the code deals with iterators, so it's important to include that in the summary.
* The prompt asks for a summary of *this specific part*. Therefore, I need to be careful not to summarize the *entire* `builtins-array-gen.cc` file.
* The prompt mentions "第2部分，共3部分". This indicates the provided snippet is not the complete file. My summary should reflect this limited scope.

By following these steps, I can arrive at the summarized functionality presented in the initial good answer.
这是v8源代码文件 `v8/src/builtins/builtins-array-gen.cc` 的一部分，主要实现了 `Array.prototype.includes` 和 `Array.prototype.indexOf` 这两个JavaScript数组方法的底层逻辑。

**功能归纳：**

这部分代码主要针对查找数组元素的功能，实现了以下核心逻辑：

1. **`ArrayIncludesIndexofAssembler` 类:**  这是一个汇编器类，用于生成 `Array.prototype.includes` 和 `Array.prototype.indexOf` 的快速路径代码。它针对不同类型的数组存储方式（Packed Smis/Objects, Holey Smis/Objects, Packed Doubles, Holey Doubles）提供了优化的查找实现。

2. **`GenerateSmiOrObject` 函数:**  处理包含Smi（小整数）或对象的数组的查找。它支持多种查找变体（`kIncludes` 和 `kIndexOf`）。该函数会根据数组元素的类型（Smi, HeapNumber, String, BigInt, undefined, the hole）进行不同的比较操作。

3. **`GeneratePackedDoubles` 函数:**  专门处理存储双精度浮点数的密集数组的查找。它利用 SIMD 指令（如果可用）加速查找过程，并处理 `NaN` 值的比较。

4. **`GenerateHoleyDoubles` 函数:**  处理存储双精度浮点数的稀疏数组（包含“洞”）的查找。它与 `GeneratePackedDoubles` 类似，但需要额外处理数组中的空洞。对于 `Array.prototype.includes`，空洞会被视为 `undefined`。

5. **`TF_BUILTIN(ArrayIncludes, ...)` 和 `TF_BUILTIN(ArrayIndexOf, ...)`:**  这些宏定义了 `Array.prototype.includes` 和 `Array.prototype.indexOf` 的顶层入口函数。它们会根据数组的元素类型和布局，分派到对应的 `Generate...` 函数进行处理，以实现性能优化。

6. **迭代器相关函数 (`ArrayPrototypeValues`, `ArrayPrototypeEntries`, `ArrayPrototypeKeys`, `ArrayIteratorPrototypeNext`):**  这部分代码实现了数组迭代器的功能，包括获取迭代器的值、键值对和键。`ArrayIteratorPrototypeNext`  是迭代器的核心函数，用于获取迭代器的下一个元素。它会根据数组的类型（普通数组、TypedArray）执行不同的逻辑，并处理迭代结束的情况。

7. **`ArrayConstructor` 函数:**  实现了 `Array` 构造函数的逻辑，用于创建新的数组实例。它作为一个跳板，调用 `ArrayConstructorImpl` 来完成实际的构造过程。

8. **`CreateArrayDispatchNoArgument` 和 `CreateArrayDispatchSingleArgument` 函数:**  用于优化 `Array` 构造函数在没有参数或只有一个数字参数时的创建过程，根据预分配的元素类型进行快速创建。

**与 JavaScript 功能的关系及举例：**

这部分代码直接实现了 JavaScript 中数组的 `includes` 和 `indexOf` 方法以及数组迭代器的核心逻辑。

**`Array.prototype.includes()`:**  判断数组是否包含某个元素，返回 `true` 或 `false`。

```javascript
const arr = [1, 2, 'a', NaN, undefined];
console.log(arr.includes(2));      // 输出: true
console.log(arr.includes('a'));    // 输出: true
console.log(arr.includes(NaN));    // 输出: true (SameValueZero comparison)
console.log(arr.includes(null));   // 输出: false
console.log(arr.includes(undefined)); // 输出: true
```

**`Array.prototype.indexOf()`:**  返回数组中第一次出现某个元素的索引，如果不存在则返回 -1。

```javascript
const arr = [1, 2, 'a', NaN, undefined, NaN];
console.log(arr.indexOf(2));      // 输出: 1
console.log(arr.indexOf('a'));    // 输出: 2
console.log(arr.indexOf(NaN));    // 输出: -1 (区分 NaN，使用严格相等)
console.log(arr.indexOf(undefined)); // 输出: 4
```

**数组迭代器 (`values()`, `entries()`, `keys()`):**  用于遍历数组的元素、键值对或键。

```javascript
const arr = ['a', 'b', 'c'];

// values()
for (const value of arr.values()) {
  console.log(value); // 输出: 'a', 'b', 'c'
}

// entries()
for (const [index, value] of arr.entries()) {
  console.log(index, value); // 输出: 0 'a', 1 'b', 2 'c'
}

// keys()
for (const key of arr.keys()) {
  console.log(key); // 输出: 0, 1, 2
}
```

**代码逻辑推理 (假设输入与输出):**

**假设 `Array.prototype.includes` 的输入：**

* `this` (接收者):  一个数组，例如 `[1, 2.5, 'hello']`
* `searchElement`: 要查找的元素，例如 `2.5`

**预期输出：** `true`

**代码逻辑推理过程 (简化版):**

1. 根据数组的元素类型（这里包含数字和字符串），可能会进入 `GenerateSmiOrObject` 函数。
2. 遍历数组的每个元素，将当前元素与 `searchElement` 进行比较。
3. 由于数组中存在与 `searchElement` 相等的元素 `2.5`，比较成功。
4. 函数返回 `true`。

**假设 `Array.prototype.indexOf` 的输入：**

* `this` (接收者): 一个数组，例如 `[1, NaN, 'hello']`
* `searchElement`: 要查找的元素，例如 `NaN`

**预期输出：** `-1`

**代码逻辑推理过程 (简化版):**

1. 根据数组的元素类型，可能会进入 `GenerateSmiOrObject` 函数。
2. 遍历数组的每个元素，将当前元素与 `searchElement` 进行比较。
3. 由于 `indexOf` 使用严格相等（`===`），而 `NaN === NaN` 为 `false`，即使数组中存在 `NaN`，比较也会失败。
4. 遍历完数组后未找到匹配项。
5. 函数返回 `-1`。

**涉及用户常见的编程错误：**

1. **使用 `indexOf` 查找 `NaN`：**  用户可能会期望 `[NaN].indexOf(NaN)` 返回 `0`，但实际上会返回 `-1`，因为 `NaN === NaN` 是 `false`。应该使用 `includes` 来检查 `NaN` 的存在。

   ```javascript
   const arr = [NaN];
   console.log(arr.indexOf(NaN));    // 输出: -1 (常见错误)
   console.log(arr.includes(NaN));   // 输出: true (正确用法)
   ```

2. **混淆 `indexOf` 和 `includes` 的行为：**  用户可能不清楚 `includes` 使用 SameValueZero 比较（`NaN` 等于 `NaN`），而 `indexOf` 使用严格相等。

3. **在包含空洞的数组中使用 `indexOf` 或 `includes`：** 对于 `includes`，空洞会被视为 `undefined`。对于 `indexOf`，空洞参与严格相等比较，结果取决于要查找的值。

   ```javascript
   const arr = [1, , 3]; // 注意中间的逗号，表示一个空洞
   console.log(arr.includes(undefined)); // 输出: true (空洞被视为 undefined)
   console.log(arr.indexOf(undefined));  // 输出: -1 (严格相等比较 undefined)
   console.log(arr[1]);                 // 输出: undefined
   ```

**总结一下它的功能 (针对提供的代码片段):**

这段代码是 V8 引擎中 `Array.prototype.includes` 和 `Array.prototype.indexOf` 方法以及数组迭代器功能的底层实现。它针对不同类型的数组存储方式进行了优化，以提高查找和遍历性能。代码中包含了处理不同数据类型（如数字、字符串、`NaN`、`undefined` 等）的比较逻辑，并体现了 V8 引擎对性能的追求，例如使用 SIMD 指令进行加速。 此外，它也实现了数组迭代器的核心功能，为 JavaScript 中使用 `for...of` 循环遍历数组提供了基础。

Prompt: 
```
这是目录为v8/src/builtins/builtins-array-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-array-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
urn_not_found);
    TNode<Object> element_k =
        UnsafeLoadFixedArrayElement(elements, index_var.value());
    GotoIf(TaggedEqual(element_k, search_element), &return_found);

    Increment(&index_var);
    Goto(&ident_loop);
  }

  if (variant == kIncludes) {
    BIND(&undef_loop);

    GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
              &return_not_found);
    TNode<Object> element_k =
        UnsafeLoadFixedArrayElement(elements, index_var.value());
    GotoIf(IsUndefined(element_k), &return_found);
    GotoIf(IsTheHole(element_k), &return_found);

    Increment(&index_var);
    Goto(&undef_loop);
  }

  BIND(&heap_num_loop);
  {
    Label nan_loop(this, &index_var), not_nan_loop(this, &index_var);
    Label* nan_handling = variant == kIncludes ? &nan_loop : &return_not_found;
    GotoIfNot(Float64Equal(search_num.value(), search_num.value()),
              nan_handling);

    // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
    // that the graph structure does not depend on the value of the predicate
    // (BoolConstant uses cached nodes).
    GotoIfNot(UniqueInt32Constant(kCanVectorize &&
                                  array_kind == SimpleElementKind::kSmiOrHole),
              &not_nan_loop);
    {
      Label smi_check(this), simd_call(this);
      Branch(UintPtrLessThan(array_length_untagged,
                             IntPtrConstant(kSIMDThreshold)),
             &not_nan_loop, &smi_check);
      BIND(&smi_check);
      Branch(TaggedIsSmi(search_element), &simd_call, &not_nan_loop);
      BIND(&simd_call);
      TNode<ExternalReference> simd_function = ExternalConstant(
          ExternalReference::array_indexof_includes_smi_or_object());
      TNode<IntPtrT> result = UncheckedCast<IntPtrT>(CallCFunction(
          simd_function, MachineType::UintPtr(),
          std::make_pair(MachineType::TaggedPointer(), elements),
          std::make_pair(MachineType::UintPtr(), array_length_untagged),
          std::make_pair(MachineType::UintPtr(), index_var.value()),
          std::make_pair(MachineType::TaggedPointer(), search_element)));
      index_var = ReinterpretCast<IntPtrT>(result);
      Branch(IntPtrLessThan(index_var.value(), IntPtrConstant(0)),
             &return_not_found, &return_found);
    }

    BIND(&not_nan_loop);
    {
      Label continue_loop(this), element_k_not_smi(this);
      GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
                &return_not_found);
      TNode<Object> element_k =
          UnsafeLoadFixedArrayElement(elements, index_var.value());
      GotoIfNot(TaggedIsSmi(element_k), &element_k_not_smi);
      Branch(Float64Equal(search_num.value(), SmiToFloat64(CAST(element_k))),
             &return_found, &continue_loop);

      BIND(&element_k_not_smi);
      GotoIfNot(IsHeapNumber(CAST(element_k)), &continue_loop);
      Branch(Float64Equal(search_num.value(),
                          LoadHeapNumberValue(CAST(element_k))),
             &return_found, &continue_loop);

      BIND(&continue_loop);
      Increment(&index_var);
      Goto(&not_nan_loop);
    }

    // Array.p.includes uses SameValueZero comparisons, where NaN == NaN.
    if (variant == kIncludes) {
      BIND(&nan_loop);
      Label continue_loop(this);
      GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
                &return_not_found);
      TNode<Object> element_k =
          UnsafeLoadFixedArrayElement(elements, index_var.value());
      GotoIf(TaggedIsSmi(element_k), &continue_loop);
      GotoIfNot(IsHeapNumber(CAST(element_k)), &continue_loop);
      BranchIfFloat64IsNaN(LoadHeapNumberValue(CAST(element_k)), &return_found,
                           &continue_loop);

      BIND(&continue_loop);
      Increment(&index_var);
      Goto(&nan_loop);
    }
  }

  BIND(&string_loop);
  {
    TNode<String> search_element_string = CAST(search_element);
    Label continue_loop(this), next_iteration(this, &index_var),
        slow_compare(this), runtime(this, Label::kDeferred);
    TNode<IntPtrT> search_length =
        LoadStringLengthAsWord(search_element_string);
    Goto(&next_iteration);
    BIND(&next_iteration);
    GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
              &return_not_found);
    TNode<Object> element_k =
        UnsafeLoadFixedArrayElement(elements, index_var.value());
    GotoIf(TaggedIsSmi(element_k), &continue_loop);
    GotoIf(TaggedEqual(search_element_string, element_k), &return_found);
    TNode<Uint16T> element_k_type = LoadInstanceType(CAST(element_k));
    GotoIfNot(IsStringInstanceType(element_k_type), &continue_loop);
    Branch(IntPtrEqual(search_length, LoadStringLengthAsWord(CAST(element_k))),
           &slow_compare, &continue_loop);

    BIND(&slow_compare);
    StringBuiltinsAssembler string_asm(state());
    string_asm.StringEqual_Core(search_element_string, search_type,
                                CAST(element_k), element_k_type, search_length,
                                &return_found, &continue_loop, &runtime);
    BIND(&runtime);
    TNode<Object> result = CallRuntime(Runtime::kStringEqual, context,
                                       search_element_string, element_k);
    Branch(TaggedEqual(result, TrueConstant()), &return_found, &continue_loop);

    BIND(&continue_loop);
    Increment(&index_var);
    Goto(&next_iteration);
  }

  BIND(&bigint_loop);
  {
    GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
              &return_not_found);

    TNode<Object> element_k =
        UnsafeLoadFixedArrayElement(elements, index_var.value());
    Label continue_loop(this);
    GotoIf(TaggedIsSmi(element_k), &continue_loop);
    GotoIfNot(IsBigInt(CAST(element_k)), &continue_loop);
    TNode<Object> result = CallRuntime(Runtime::kBigIntEqualToBigInt, context,
                                       search_element, element_k);
    Branch(TaggedEqual(result, TrueConstant()), &return_found, &continue_loop);

    BIND(&continue_loop);
    Increment(&index_var);
    Goto(&bigint_loop);
  }
  BIND(&return_found);
  if (variant == kIncludes) {
    Return(TrueConstant());
  } else {
    Return(SmiTag(index_var.value()));
  }

  BIND(&return_not_found);
  if (variant == kIncludes) {
    Return(FalseConstant());
  } else {
    Return(NumberConstant(-1));
  }
}

void ArrayIncludesIndexofAssembler::GeneratePackedDoubles(
    SearchVariant variant, TNode<FixedDoubleArray> elements,
    TNode<Object> search_element, TNode<Smi> array_length,
    TNode<Smi> from_index) {
  TVARIABLE(IntPtrT, index_var, SmiUntag(from_index));
  TNode<IntPtrT> array_length_untagged = PositiveSmiUntag(array_length);

  Label nan_loop(this, &index_var), not_nan_case(this),
      not_nan_loop(this, &index_var), hole_loop(this, &index_var),
      search_notnan(this), return_found(this), return_not_found(this);
  TVARIABLE(Float64T, search_num);
  search_num = Float64Constant(0);

  GotoIfNot(TaggedIsSmi(search_element), &search_notnan);
  search_num = SmiToFloat64(CAST(search_element));
  Goto(&not_nan_case);

  BIND(&search_notnan);
  GotoIfNot(IsHeapNumber(CAST(search_element)), &return_not_found);

  search_num = LoadHeapNumberValue(CAST(search_element));

  Label* nan_handling = variant == kIncludes ? &nan_loop : &return_not_found;
  BranchIfFloat64IsNaN(search_num.value(), nan_handling, &not_nan_case);

  BIND(&not_nan_case);
  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  GotoIfNot(UniqueInt32Constant(kCanVectorize), &not_nan_loop);
  {
    Label simd_call(this);
    Branch(
        UintPtrLessThan(array_length_untagged, IntPtrConstant(kSIMDThreshold)),
        &not_nan_loop, &simd_call);
    BIND(&simd_call);
    TNode<ExternalReference> simd_function =
        ExternalConstant(ExternalReference::array_indexof_includes_double());
    TNode<IntPtrT> result = UncheckedCast<IntPtrT>(CallCFunction(
        simd_function, MachineType::UintPtr(),
        std::make_pair(MachineType::TaggedPointer(), elements),
        std::make_pair(MachineType::UintPtr(), array_length_untagged),
        std::make_pair(MachineType::UintPtr(), index_var.value()),
        std::make_pair(MachineType::TaggedPointer(), search_element)));
    index_var = ReinterpretCast<IntPtrT>(result);
    Branch(IntPtrLessThan(index_var.value(), IntPtrConstant(0)),
           &return_not_found, &return_found);
  }

  BIND(&not_nan_loop);
  {
    Label continue_loop(this);
    GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
              &return_not_found);
    TNode<Float64T> element_k =
        LoadFixedDoubleArrayElement(elements, index_var.value());
    Branch(Float64Equal(element_k, search_num.value()), &return_found,
           &continue_loop);
    BIND(&continue_loop);
    Increment(&index_var);
    Goto(&not_nan_loop);
  }

  // Array.p.includes uses SameValueZero comparisons, where NaN == NaN.
  if (variant == kIncludes) {
    BIND(&nan_loop);
    Label continue_loop(this);
    GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
              &return_not_found);
    TNode<Float64T> element_k =
        LoadFixedDoubleArrayElement(elements, index_var.value());
    BranchIfFloat64IsNaN(element_k, &return_found, &continue_loop);
    BIND(&continue_loop);
    Increment(&index_var);
    Goto(&nan_loop);
  }

  BIND(&return_found);
  if (variant == kIncludes) {
    Return(TrueConstant());
  } else {
    Return(SmiTag(index_var.value()));
  }

  BIND(&return_not_found);
  if (variant == kIncludes) {
    Return(FalseConstant());
  } else {
    Return(NumberConstant(-1));
  }
}

void ArrayIncludesIndexofAssembler::GenerateHoleyDoubles(
    SearchVariant variant, TNode<FixedDoubleArray> elements,
    TNode<Object> search_element, TNode<Smi> array_length,
    TNode<Smi> from_index) {
  TVARIABLE(IntPtrT, index_var, SmiUntag(from_index));
  TNode<IntPtrT> array_length_untagged = PositiveSmiUntag(array_length);

  Label nan_loop(this, &index_var), not_nan_case(this),
      not_nan_loop(this, &index_var), hole_loop(this, &index_var),
      search_notnan(this), return_found(this), return_not_found(this);
  TVARIABLE(Float64T, search_num);
  search_num = Float64Constant(0);

  GotoIfNot(TaggedIsSmi(search_element), &search_notnan);
  search_num = SmiToFloat64(CAST(search_element));
  Goto(&not_nan_case);

  BIND(&search_notnan);
  if (variant == kIncludes) {
    GotoIf(IsUndefined(search_element), &hole_loop);
  }
  GotoIfNot(IsHeapNumber(CAST(search_element)), &return_not_found);

  search_num = LoadHeapNumberValue(CAST(search_element));

  Label* nan_handling = variant == kIncludes ? &nan_loop : &return_not_found;
  BranchIfFloat64IsNaN(search_num.value(), nan_handling, &not_nan_case);

  BIND(&not_nan_case);
  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  GotoIfNot(UniqueInt32Constant(kCanVectorize), &not_nan_loop);
  {
    Label simd_call(this);
    Branch(
        UintPtrLessThan(array_length_untagged, IntPtrConstant(kSIMDThreshold)),
        &not_nan_loop, &simd_call);
    BIND(&simd_call);
    TNode<ExternalReference> simd_function =
        ExternalConstant(ExternalReference::array_indexof_includes_double());
    TNode<IntPtrT> result = UncheckedCast<IntPtrT>(CallCFunction(
        simd_function, MachineType::UintPtr(),
        std::make_pair(MachineType::TaggedPointer(), elements),
        std::make_pair(MachineType::UintPtr(), array_length_untagged),
        std::make_pair(MachineType::UintPtr(), index_var.value()),
        std::make_pair(MachineType::TaggedPointer(), search_element)));
    index_var = ReinterpretCast<IntPtrT>(result);
    Branch(IntPtrLessThan(index_var.value(), IntPtrConstant(0)),
           &return_not_found, &return_found);
  }

  BIND(&not_nan_loop);
  {
    Label continue_loop(this);
    GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
              &return_not_found);

    // No need for hole checking here; the following Float64Equal will
    // return 'not equal' for holes anyway.
    TNode<Float64T> element_k =
        LoadFixedDoubleArrayElement(elements, index_var.value());

    Branch(Float64Equal(element_k, search_num.value()), &return_found,
           &continue_loop);
    BIND(&continue_loop);
    Increment(&index_var);
    Goto(&not_nan_loop);
  }

  // Array.p.includes uses SameValueZero comparisons, where NaN == NaN.
  if (variant == kIncludes) {
    BIND(&nan_loop);
    Label continue_loop(this);
    GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
              &return_not_found);

    // Load double value or continue if it's the hole NaN.
    TNode<Float64T> element_k = LoadFixedDoubleArrayElement(
        elements, index_var.value(), &continue_loop);

    BranchIfFloat64IsNaN(element_k, &return_found, &continue_loop);
    BIND(&continue_loop);
    Increment(&index_var);
    Goto(&nan_loop);
  }

  // Array.p.includes treats the hole as undefined.
  if (variant == kIncludes) {
    BIND(&hole_loop);
    GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
              &return_not_found);

    // Check if the element is a double hole, but don't load it.
    LoadFixedDoubleArrayElement(elements, index_var.value(), &return_found,
                                MachineType::None());

    Increment(&index_var);
    Goto(&hole_loop);
  }

  BIND(&return_found);
  if (variant == kIncludes) {
    Return(TrueConstant());
  } else {
    Return(SmiTag(index_var.value()));
  }

  BIND(&return_not_found);
  if (variant == kIncludes) {
    Return(FalseConstant());
  } else {
    Return(NumberConstant(-1));
  }
}

TF_BUILTIN(ArrayIncludes, ArrayIncludesIndexofAssembler) {
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  auto context = Parameter<Context>(Descriptor::kContext);

  Generate(kIncludes, argc, context);
}

TF_BUILTIN(ArrayIncludesSmi, ArrayIncludesIndexofAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto elements = Parameter<FixedArray>(Descriptor::kElements);
  auto search_element = Parameter<Object>(Descriptor::kSearchElement);
  auto array_length = Parameter<Smi>(Descriptor::kLength);
  auto from_index = Parameter<Smi>(Descriptor::kFromIndex);

  GenerateSmiOrObject(kIncludes, context, elements, search_element,
                      array_length, from_index, SimpleElementKind::kSmiOrHole);
}

TF_BUILTIN(ArrayIncludesSmiOrObject, ArrayIncludesIndexofAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto elements = Parameter<FixedArray>(Descriptor::kElements);
  auto search_element = Parameter<Object>(Descriptor::kSearchElement);
  auto array_length = Parameter<Smi>(Descriptor::kLength);
  auto from_index = Parameter<Smi>(Descriptor::kFromIndex);

  GenerateSmiOrObject(kIncludes, context, elements, search_element,
                      array_length, from_index, SimpleElementKind::kAny);
}

TF_BUILTIN(ArrayIncludesPackedDoubles, ArrayIncludesIndexofAssembler) {
  auto elements = Parameter<FixedArrayBase>(Descriptor::kElements);
  auto search_element = Parameter<Object>(Descriptor::kSearchElement);
  auto array_length = Parameter<Smi>(Descriptor::kLength);
  auto from_index = Parameter<Smi>(Descriptor::kFromIndex);

  ReturnIfEmpty(array_length, FalseConstant());
  GeneratePackedDoubles(kIncludes, CAST(elements), search_element, array_length,
                        from_index);
}

TF_BUILTIN(ArrayIncludesHoleyDoubles, ArrayIncludesIndexofAssembler) {
  auto elements = Parameter<FixedArrayBase>(Descriptor::kElements);
  auto search_element = Parameter<Object>(Descriptor::kSearchElement);
  auto array_length = Parameter<Smi>(Descriptor::kLength);
  auto from_index = Parameter<Smi>(Descriptor::kFromIndex);

  ReturnIfEmpty(array_length, FalseConstant());
  GenerateHoleyDoubles(kIncludes, CAST(elements), search_element, array_length,
                       from_index);
}

TF_BUILTIN(ArrayIndexOf, ArrayIncludesIndexofAssembler) {
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  auto context = Parameter<Context>(Descriptor::kContext);

  Generate(kIndexOf, argc, context);
}

TF_BUILTIN(ArrayIndexOfSmi, ArrayIncludesIndexofAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto elements = Parameter<FixedArray>(Descriptor::kElements);
  auto search_element = Parameter<Object>(Descriptor::kSearchElement);
  auto array_length = Parameter<Smi>(Descriptor::kLength);
  auto from_index = Parameter<Smi>(Descriptor::kFromIndex);

  GenerateSmiOrObject(kIndexOf, context, elements, search_element, array_length,
                      from_index, SimpleElementKind::kSmiOrHole);
}

TF_BUILTIN(ArrayIndexOfSmiOrObject, ArrayIncludesIndexofAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto elements = Parameter<FixedArray>(Descriptor::kElements);
  auto search_element = Parameter<Object>(Descriptor::kSearchElement);
  auto array_length = Parameter<Smi>(Descriptor::kLength);
  auto from_index = Parameter<Smi>(Descriptor::kFromIndex);

  GenerateSmiOrObject(kIndexOf, context, elements, search_element, array_length,
                      from_index, SimpleElementKind::kAny);
}

TF_BUILTIN(ArrayIndexOfPackedDoubles, ArrayIncludesIndexofAssembler) {
  auto elements = Parameter<FixedArrayBase>(Descriptor::kElements);
  auto search_element = Parameter<Object>(Descriptor::kSearchElement);
  auto array_length = Parameter<Smi>(Descriptor::kLength);
  auto from_index = Parameter<Smi>(Descriptor::kFromIndex);

  ReturnIfEmpty(array_length, NumberConstant(-1));
  GeneratePackedDoubles(kIndexOf, CAST(elements), search_element, array_length,
                        from_index);
}

TF_BUILTIN(ArrayIndexOfHoleyDoubles, ArrayIncludesIndexofAssembler) {
  auto elements = Parameter<FixedArrayBase>(Descriptor::kElements);
  auto search_element = Parameter<Object>(Descriptor::kSearchElement);
  auto array_length = Parameter<Smi>(Descriptor::kLength);
  auto from_index = Parameter<Smi>(Descriptor::kFromIndex);

  ReturnIfEmpty(array_length, NumberConstant(-1));
  GenerateHoleyDoubles(kIndexOf, CAST(elements), search_element, array_length,
                       from_index);
}

// ES #sec-array.prototype.values
TF_BUILTIN(ArrayPrototypeValues, CodeStubAssembler) {
  auto context = Parameter<NativeContext>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  Return(CreateArrayIterator(context, ToObject_Inline(context, receiver),
                             IterationKind::kValues));
}

// ES #sec-array.prototype.entries
TF_BUILTIN(ArrayPrototypeEntries, CodeStubAssembler) {
  auto context = Parameter<NativeContext>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  Return(CreateArrayIterator(context, ToObject_Inline(context, receiver),
                             IterationKind::kEntries));
}

// ES #sec-array.prototype.keys
TF_BUILTIN(ArrayPrototypeKeys, CodeStubAssembler) {
  auto context = Parameter<NativeContext>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  Return(CreateArrayIterator(context, ToObject_Inline(context, receiver),
                             IterationKind::kKeys));
}

// ES #sec-%arrayiteratorprototype%.next
TF_BUILTIN(ArrayIteratorPrototypeNext, CodeStubAssembler) {
  const char* method_name = "Array Iterator.prototype.next";

  auto context = Parameter<Context>(Descriptor::kContext);
  auto maybe_iterator = Parameter<Object>(Descriptor::kReceiver);

  TVARIABLE(Boolean, var_done, TrueConstant());
  TVARIABLE(Object, var_value, UndefinedConstant());

  Label allocate_entry_if_needed(this);
  Label allocate_iterator_result(this);
  Label if_typedarray(this), if_other(this, Label::kDeferred), if_array(this),
      if_generic(this, Label::kDeferred);
  Label set_done(this, Label::kDeferred);

  // If O does not have all of the internal slots of an Array Iterator Instance
  // (22.1.5.3), throw a TypeError exception
  ThrowIfNotInstanceType(context, maybe_iterator, JS_ARRAY_ITERATOR_TYPE,
                         method_name);

  TNode<JSArrayIterator> iterator = CAST(maybe_iterator);

  // Let a be O.[[IteratedObject]].
  TNode<JSReceiver> array = LoadJSArrayIteratorIteratedObject(iterator);

  // Let index be O.[[ArrayIteratorNextIndex]].
  TNode<Number> index = LoadJSArrayIteratorNextIndex(iterator);
  CSA_DCHECK(this, IsNumberNonNegativeSafeInteger(index));

  // Dispatch based on the type of the {array}.
  TNode<Map> array_map = LoadMap(array);
  TNode<Uint16T> array_type = LoadMapInstanceType(array_map);
  GotoIf(InstanceTypeEqual(array_type, JS_ARRAY_TYPE), &if_array);
  Branch(InstanceTypeEqual(array_type, JS_TYPED_ARRAY_TYPE), &if_typedarray,
         &if_other);

  BIND(&if_array);
  {
    // If {array} is a JSArray, then the {index} must be in Unsigned32 range.
    CSA_DCHECK(this, IsNumberArrayIndex(index));

    // Check that the {index} is within range for the {array}. We handle all
    // kinds of JSArray's here, so we do the computation on Uint32.
    TNode<Uint32T> index32 = ChangeNonNegativeNumberToUint32(index);
    TNode<Uint32T> length32 =
        ChangeNonNegativeNumberToUint32(LoadJSArrayLength(CAST(array)));
    GotoIfNot(Uint32LessThan(index32, length32), &set_done);
    StoreJSArrayIteratorNextIndex(
        iterator, ChangeUint32ToTagged(Uint32Add(index32, Uint32Constant(1))));

    var_done = FalseConstant();
    var_value = index;

    GotoIf(Word32Equal(LoadAndUntagToWord32ObjectField(
                           iterator, JSArrayIterator::kKindOffset),
                       Int32Constant(static_cast<int>(IterationKind::kKeys))),
           &allocate_iterator_result);

    Label if_hole(this, Label::kDeferred);
    TNode<Int32T> elements_kind = LoadMapElementsKind(array_map);
    TNode<FixedArrayBase> elements = LoadElements(CAST(array));
    GotoIfForceSlowPath(&if_generic);
    var_value = LoadFixedArrayBaseElementAsTagged(
        elements, Signed(ChangeUint32ToWord(index32)), elements_kind,
        &if_generic, &if_hole);
    Goto(&allocate_entry_if_needed);

    BIND(&if_hole);
    {
      GotoIf(IsNoElementsProtectorCellInvalid(), &if_generic);
      GotoIfNot(IsPrototypeInitialArrayPrototype(context, array_map),
                &if_generic);
      var_value = UndefinedConstant();
      Goto(&allocate_entry_if_needed);
    }
  }

  BIND(&if_other);
  {
    // We cannot enter here with either JSArray's or JSTypedArray's.
    CSA_DCHECK(this, Word32BinaryNot(IsJSArray(array)));
    CSA_DCHECK(this, Word32BinaryNot(IsJSTypedArray(array)));

    // Check that the {index} is within the bounds of the {array}s "length".
    TNode<Number> length = CAST(
        CallBuiltin(Builtin::kToLength, context,
                    GetProperty(context, array, factory()->length_string())));
    GotoIfNumberGreaterThanOrEqual(index, length, &set_done);
    StoreJSArrayIteratorNextIndex(iterator, NumberInc(index));

    var_done = FalseConstant();
    var_value = index;

    Branch(Word32Equal(LoadAndUntagToWord32ObjectField(
                           iterator, JSArrayIterator::kKindOffset),
                       Int32Constant(static_cast<int>(IterationKind::kKeys))),
           &allocate_iterator_result, &if_generic);
  }

  BIND(&set_done);
  {
    // Change the [[ArrayIteratorNextIndex]] such that the {iterator} will
    // never produce values anymore, because it will always fail the bounds
    // check. Note that this is different from what the specification does,
    // which is changing the [[IteratedObject]] to undefined, because leaving
    // [[IteratedObject]] alone helps TurboFan to generate better code with
    // the inlining in JSCallReducer::ReduceArrayIteratorPrototypeNext().
    //
    // The terminal value we chose here depends on the type of the {array},
    // for JSArray's we use kMaxUInt32 so that TurboFan can always use
    // Word32 representation for fast-path indices (and this is safe since
    // the "length" of JSArray's is limited to Unsigned32 range). For other
    // JSReceiver's we have to use kMaxSafeInteger, since the "length" can
    // be any arbitrary value in the safe integer range.
    //
    // Note specifically that JSTypedArray's will never take this path, so
    // we don't need to worry about their maximum value.
    CSA_DCHECK(this, Word32BinaryNot(IsJSTypedArray(array)));
    TNode<Number> max_length =
        SelectConstant(IsJSArray(array), NumberConstant(kMaxUInt32),
                       NumberConstant(kMaxSafeInteger));
    StoreJSArrayIteratorNextIndex(iterator, max_length);
    Goto(&allocate_iterator_result);
  }

  BIND(&if_generic);
  {
    var_value = GetProperty(context, array, index);
    Goto(&allocate_entry_if_needed);
  }

  BIND(&if_typedarray);
  {
    // Overflowing uintptr range also means end of iteration.
    TNode<UintPtrT> index_uintptr =
        ChangeSafeIntegerNumberToUintPtr(index, &allocate_iterator_result);

    // If we go outside of the {length}, we don't need to update the
    // [[ArrayIteratorNextIndex]] anymore, since a JSTypedArray's
    // length cannot change anymore, so this {iterator} will never
    // produce values again anyways.
    Label detached(this);
    TNode<UintPtrT> length =
        LoadJSTypedArrayLengthAndCheckDetached(CAST(array), &detached);
    GotoIfNot(UintPtrLessThan(index_uintptr, length),
              &allocate_iterator_result);
    // TODO(v8:4153): Consider storing next index as uintptr. Update this and
    // the relevant TurboFan code.
    StoreJSArrayIteratorNextIndex(
        iterator,
        ChangeUintPtrToTagged(UintPtrAdd(index_uintptr, UintPtrConstant(1))));

    var_done = FalseConstant();
    var_value = index;

    GotoIf(Word32Equal(LoadAndUntagToWord32ObjectField(
                           iterator, JSArrayIterator::kKindOffset),
                       Int32Constant(static_cast<int>(IterationKind::kKeys))),
           &allocate_iterator_result);

    TNode<Int32T> elements_kind = LoadMapElementsKind(array_map);
    TNode<RawPtrT> data_ptr = LoadJSTypedArrayDataPtr(CAST(array));
    var_value = LoadFixedTypedArrayElementAsTagged(data_ptr, index_uintptr,
                                                   elements_kind);
    Goto(&allocate_entry_if_needed);

    BIND(&detached);
    ThrowTypeError(context, MessageTemplate::kDetachedOperation, method_name);
  }

  BIND(&allocate_entry_if_needed);
  {
    GotoIf(Word32Equal(LoadAndUntagToWord32ObjectField(
                           iterator, JSArrayIterator::kKindOffset),
                       Int32Constant(static_cast<int>(IterationKind::kValues))),
           &allocate_iterator_result);

    TNode<JSObject> result =
        AllocateJSIteratorResultForEntry(context, index, var_value.value());
    Return(result);
  }

  BIND(&allocate_iterator_result);
  {
    TNode<JSObject> result =
        AllocateJSIteratorResult(context, var_value.value(), var_done.value());
    Return(result);
  }
}

TF_BUILTIN(ArrayConstructor, ArrayBuiltinsAssembler) {
  // This is a trampoline to ArrayConstructorImpl which just adds
  // allocation_site parameter value and sets new_target if necessary.
  auto context = Parameter<Context>(Descriptor::kContext);
  auto function = Parameter<JSFunction>(Descriptor::kTarget);
  auto new_target = Parameter<Object>(Descriptor::kNewTarget);
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);

  // If new_target is undefined, then this is the 'Call' case, so set new_target
  // to function.
  new_target =
      SelectConstant<Object>(IsUndefined(new_target), function, new_target);

  // Run the native code for the Array function called as a normal function.
  TNode<Oddball> no_gc_site = UndefinedConstant();
  TailCallBuiltin(Builtin::kArrayConstructorImpl, context, function, new_target,
                  argc, no_gc_site);
}

void ArrayBuiltinsAssembler::TailCallArrayConstructorStub(
    const Callable& callable, TNode<Context> context, TNode<JSFunction> target,
    TNode<HeapObject> allocation_site_or_undefined, TNode<Int32T> argc) {
  TNode<Code> code = HeapConstantNoHole(callable.code());

  // We are going to call here ArrayNoArgumentsConstructor or
  // ArraySingleArgumentsConstructor which in addition to the register arguments
  // also expect some number of arguments on the expression stack.
  // Since
  // 1) incoming JS arguments are still on the stack,
  // 2) the ArrayNoArgumentsConstructor, ArraySingleArgumentsConstructor and
  //    ArrayNArgumentsConstructor are defined so that the register arguments
  //    are passed on the same registers,
  // in order to be able to generate a tail call to those builtins we do the
  // following trick here: we tail call to the constructor builtin using
  // ArrayNArgumentsConstructorDescriptor, so the tail call instruction
  // pops the current frame but leaves all the incoming JS arguments on the
  // expression stack so that the target builtin can still find them where it
  // expects.
  TailCallStub(ArrayNArgumentsConstructorDescriptor{}, code, context, target,
               allocation_site_or_undefined, argc);
}

void ArrayBuiltinsAssembler::CreateArrayDispatchNoArgument(
    TNode<Context> context, TNode<JSFunction> target, TNode<Int32T> argc,
    AllocationSiteOverrideMode mode,
    std::optional<TNode<AllocationSite>> allocation_site) {
  if (mode == DISABLE_ALLOCATION_SITES) {
    Callable callable = CodeFactory::ArrayNoArgumentConstructor(
        isolate(), GetInitialFastElementsKind(), mode);

    TailCallArrayConstructorStub(callable, context, target, UndefinedConstant(),
                                 argc);
  } else {
    DCHECK_EQ(mode, DONT_OVERRIDE);
    DCHECK(allocation_site);
    TNode<Int32T> elements_kind = LoadElementsKind(*allocation_site);

    // TODO(ishell): Compute the builtin index dynamically instead of
    // iterating over all expected elements kinds.
    int last_index =
        GetSequenceIndexFromFastElementsKind(TERMINAL_FAST_ELEMENTS_KIND);
    for (int i = 0; i <= last_index; ++i) {
      Label next(this);
      ElementsKind kind = GetFastElementsKindFromSequenceIndex(i);
      GotoIfNot(Word32Equal(elements_kind, Int32Constant(kind)), &next);

      Callable callable =
          CodeFactory::ArrayNoArgumentConstructor(isolate(), kind, mode);

      TailCallArrayConstructorStub(callable, context, target, *allocation_site,
                                   argc);

      BIND(&next);
    }

    // If we reached this point there is a problem.
    Abort(AbortReason::kUnexpectedElementsKindInArrayConstructor);
  }
}

void ArrayBuiltinsAssembler::CreateArrayDispatchSingleArgument(
    TNode<Context> context, TNode<JSFunction> target, TNode<Int32T> argc,
    AllocationSiteOverrideMode mode,
    std::optional<TNode<AllocationSite>> allocation_site) {
  if (mode == DISABLE_ALLOCATION_SITES) {
    ElementsKind initial = GetInitialFastElementsKind();
    ElementsKind holey_initial = GetHoleyElementsKind(initial);
    Callable callable = CodeFactory::ArraySingleArgumentConstructor(
        isolate(), holey_initial, mode);

    TailCallArrayConstructorStub(callable, context, target, UndefinedConstant(),
                                 argc);
  } else {
    DCHECK_EQ(mode, DONT_OVERRIDE);
    DCHECK(allocation_site);
    TNode<Smi> transition_info = LoadTransitionInfo(*allocation_site);

    // Least significant bit in fast array elements kind means holeyness.
    static_assert(PACKED_SMI_ELEMENTS == 0);
    static_assert(HOLEY_SMI_ELEMENTS == 1);
    static_assert(PACKED_ELEMENTS == 2);
    static_assert(HOLEY_ELEMENTS == 3);
    static_assert(PACKED_DOUBLE_ELEMENTS == 4);
    static_assert(HOLEY_DOUBLE_ELEMENTS == 5);

    Label normal_sequence(this);
    TVARIABLE(Int32T, var_elements_kind,
              Signed(DecodeWord32<AllocationSite::ElementsKindBits>(
                  SmiToInt32(transition_info))));
    // Is the low bit set? If so, we are holey and that is good.
    int fast_elements_kind_holey_mask =
        AllocationSite::ElementsKindBits::encode(static_cast<ElementsKind>(1));
    GotoIf(IsSetSmi(transition_info, fast_elements_kind_holey_mask),
           &normal_sequence);
    {
      // Make elements kind holey and update elements kind in the type info.
      var_elements_kind = Word32Or(var_elements_kind.value(), Int32Constant(1));
      StoreOb
"""


```