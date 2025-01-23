Response:
The user wants me to analyze a C++ source code file for V8, specifically `v8/src/compiler/js-call-reducer.cc`.

Here's a breakdown of my thought process to address the request:

1. **Identify the core purpose:** The filename `js-call-reducer.cc` strongly suggests this file is responsible for *reducing* JavaScript call operations within the V8 compiler. This means it likely transforms complex or high-level JavaScript calls into simpler, lower-level operations that the underlying machine can execute more efficiently.

2. **Check for Torque:** The prompt explicitly asks to check if the file ends with `.tq`. Since the provided snippet is C++ code, the answer is no. Torque is V8's custom language for implementing built-in functions.

3. **Relate to JavaScript functionality:** Since it's a "call reducer," it must relate to how JavaScript functions are called. I need to identify the specific JavaScript features it optimizes. Looking at the code, I see functions like `JSCall4`, `CreateArrayNoThrow`, `ReduceMathUnary`, `ReduceMathBinary`, and various `ReduceStringPrototype...` functions. This indicates it deals with:
    * General function calls (`JSCall4`).
    * Array creation (`CreateArrayNoThrow`).
    * Math built-in functions (`ReduceMathUnary`, `ReduceMathBinary`).
    * String prototype methods (`ReduceStringPrototypeSubstring`, `ReduceStringPrototypeStartsWith`, `ReduceStringPrototypeEndsWith`, `ReduceStringPrototypeCharAt`, `ReduceStringPrototypeSlice`).
    * Array prototype methods (`ReduceArrayPrototypeAt`, `ReduceArrayPrototypePush`, `ReduceArrayPrototypeForEach`, `ReduceArrayPrototypeReduce`).

4. **Provide JavaScript examples:** For each identified JavaScript functionality, I need to provide a simple JavaScript code snippet. This will illustrate what the C++ code is optimizing.

5. **Look for code logic and infer inputs/outputs:** The functions with "Reduce" in their name are where the core logic lies. These functions take a JavaScript call (represented by nodes in the compiler's intermediate representation) and transform it.
    * **Example: `ReduceStringPrototypeSubstring()`:**  It takes a string, a start index, and an optional end index. It performs checks and calculations to determine the correct substring boundaries and then generates a lower-level `StringSubstring` operation.
    * **Input:** A string, a number for the start index, and optionally a number for the end index.
    * **Output:** A substring.

6. **Identify common programming errors:** The optimizations often handle edge cases and potential errors in JavaScript.
    * **Example: `ReduceStringPrototypeSubstring()`:** If the start or end index is out of bounds, the behavior is defined (usually clamped to the string length). A common error is providing invalid indices.

7. **Summarize the functionality (for part 2):** Based on the identified functionalities, I need to provide a concise summary of what `js-call-reducer.cc` does.

**Pre-computation/Pre-analysis (Internal "Mental" Steps):**

* **Understanding Compiler Optimizations:** I know that compilers try to replace expensive operations with cheaper ones where possible. This often involves type specialization (e.g., handling smi numbers directly instead of generic numbers) and inlining.
* **V8's Architecture:** I have a basic understanding of V8's compilation pipeline, including TurboFan and its intermediate representation. This helps me understand the context of "nodes" and "graphs."
* **Familiarity with JavaScript Built-ins:** I know the basic functionalities of the JavaScript built-in methods being optimized.

**Self-Correction/Refinement during thought process:**

* Initially, I might focus too much on the low-level details of the C++ code. I need to remember the prompt asks for a high-level explanation of its *functionality* related to JavaScript.
* I need to ensure the JavaScript examples are simple and directly correspond to the C++ functions being described.
* The prompt asks for *common* programming errors. I should focus on errors that are likely to occur in everyday JavaScript programming, not just obscure edge cases.

By following these steps, I can generate a comprehensive and accurate answer to the user's request.
这是 `v8/src/compiler/js-call-reducer.cc` 源代码的第 2 部分，它是一个 V8 编译器的一部分，负责对 JavaScript 函数调用进行优化。

**主要功能归纳：**

本部分代码主要定义了 `JSCallReducerAssembler` 和 `IteratingArrayBuiltinReducerAssembler` 两个类，它们提供了一系列用于在 V8 的 TurboFan 编译器中简化和优化 JavaScript 函数调用的方法。这些方法将一些常见的 JavaScript 函数调用模式转换为更高效的底层操作。

**具体功能列举：**

1. **`JSCallReducerAssembler` 类:**
   - **`JSCall`, `JSCallN` (N=0, 1, 2, 3, 4):**  提供了创建不同参数数量的 JavaScript 调用节点的方法。这些方法允许指定调用频率、反馈信息、接收者模式、推测模式和反馈关系等。
   - **`CopyNode()`:**  复制当前节点。
   - **`CreateArrayNoThrow()`:** 创建一个不会抛出异常的数组。
   - **`AllocateEmptyJSArray()`:**  分配一个空的 JavaScript 数组，可以指定元素类型。
   - **`LoadMapElementsKind()`:**  加载给定 Map 的元素类型。
   - **`ReduceMathUnary()`, `ReduceMathBinary()`:** 简化一元和二元数学运算，例如 `Math.abs()`, `Math.sin()`, `Math.pow()` 等。
   - **`ReduceStringPrototypeSubstring()`:** 优化 `String.prototype.substring()` 的调用。
   - **`ReduceStringPrototypeStartsWith()` (两个版本):** 优化 `String.prototype.startsWith()` 的调用，其中一个版本针对已知字符串字面量进行了优化。
   - **`ReduceStringPrototypeEndsWith()` (两个版本):** 优化 `String.prototype.endsWith()` 的调用，其中一个版本针对已知字符串字面量进行了优化。
   - **`ReduceStringPrototypeCharAt()` (两个版本):** 优化 `String.prototype.charAt()` 的调用，其中一个版本针对已知字符串字面量进行了优化。
   - **`ReduceStringPrototypeSlice()`:** 优化 `String.prototype.slice()` 的调用。
   - **`ReduceJSCallMathMinMaxWithArrayLike()`:** 优化 `Math.min()` 和 `Math.max()` 当参数是类数组对象时的调用。

2. **`IteratingArrayBuiltinReducerAssembler` 类:**
   - **`ReduceArrayPrototypeAt()`:** 优化 `Array.prototype.at()` 的调用。
   - **`ReduceArrayPrototypePush()`:** 优化 `Array.prototype.push()` 的调用。
   - **`ReduceArrayPrototypeForEach()`:** 优化 `Array.prototype.forEach()` 的调用。
   - **`ReduceArrayPrototypeReduce()`:** 优化 `Array.prototype.reduce()` 的调用。

**关于 Torque：**

`v8/src/compiler/js-call-reducer.cc` 文件以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系及示例：**

本文件中的代码直接对应于一些常见的 JavaScript 内置函数和方法。它通过在编译时识别这些调用模式并将其替换为更高效的底层操作来提高性能。

**JavaScript 示例：**

* **`ReduceMathUnary()` (例如 `Math.abs()`):**

```javascript
function test(x) {
  return Math.abs(x);
}
```
编译器可能会将 `Math.abs(x)` 转换为一个直接的求绝对值的机器指令，而不是一个完整的函数调用。

* **`ReduceStringPrototypeSubstring()`:**

```javascript
const str = "hello world";
const sub = str.substring(6); // "world"
```
编译器可以优化这个调用，直接在字符串内部计算并提取子字符串，而无需创建中间对象。

* **`ReduceArrayPrototypePush()`:**

```javascript
const arr = [1, 2, 3];
arr.push(4); // arr 变为 [1, 2, 3, 4]
```
编译器可以根据数组的元素类型和当前状态，优化添加新元素到数组的操作，例如直接在内存中扩展数组空间。

* **`ReduceArrayPrototypeForEach()`:**

```javascript
const arr = [10, 20, 30];
arr.forEach(function(element) {
  console.log(element);
});
```
编译器可以对 `forEach` 循环进行优化，例如内联回调函数，或者针对特定元素类型进行优化。

**代码逻辑推理和假设输入/输出：**

以 `ReduceStringPrototypeStartsWith()` 为例：

**假设输入：**
- `receiver`:  字符串 "hello world"
- `search_element`: 字符串 "hell"
- `start`: 数字 0

**代码逻辑推理：**
1. 获取接收者字符串 "hello world"。
2. 获取要搜索的字符串 "hell"。
3. 获取起始位置 0。
4. 计算 "hell" 的长度为 4。
5. 从接收者字符串的起始位置开始，逐个字符比较 "hell" 的每个字符。
6. 如果所有字符都匹配，则返回 `true`。

**假设输出：** `true`

**涉及用户常见的编程错误及示例：**

* **在字符串方法中使用错误的索引：** 例如，`substring()`，`charAt()`，`slice()` 等方法，如果传入超出字符串长度的索引，可能会导致意想不到的结果或错误。

```javascript
const str = "abc";
console.log(str.charAt(5)); // 输出 "" (空字符串) 而不是报错
console.log(str.substring(1, 5)); // 输出 "bc" (end 索引会被限制在字符串长度内)
```
`js-call-reducer.cc` 中的代码会进行边界检查，以确保这些错误不会导致程序崩溃，并按照 JavaScript 规范处理这些情况。

* **在 `Math.min()` 或 `Math.max()` 中传递非数字参数：**

```javascript
console.log(Math.min(1, 2, "a")); // 输出 NaN
```
`ReduceJSCallMathMinMaxWithArrayLike()` 这样的函数会处理这些情况，并按照 JavaScript 的规则返回 `NaN`。

* **对非数组对象使用数组方法：**

```javascript
const obj = { 0: 'a', 1: 'b', length: 2 };
// obj.forEach(item => console.log(item)); // 报错：obj.forEach is not a function
```
虽然可以使用 `call` 或 `apply` 来调用数组方法在类数组对象上，但直接调用会导致错误。`IteratingArrayBuiltinReducerAssembler` 中的代码会检查接收者的类型，并可能回退到更通用的调用方式来处理这种情况。

**总结 `js-call-reducer.cc` 的功能（针对第 2 部分）：**

本部分 `js-call-reducer.cc` 的代码主要定义了用于简化和优化 JavaScript 函数调用的汇编器辅助类。它针对特定的 JavaScript 内置函数和方法，例如数学运算、字符串操作和数组操作，提供了优化的实现路径。通过在编译时识别这些调用模式并将其转换为更高效的底层操作，显著提升了 JavaScript 代码的执行性能。它还处理了一些常见的编程错误和边界情况，以确保代码的健壮性。

### 提示词
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
ction, this_arg, arg0, arg1, arg2, n.feedback_vector(),
        ContextInput(), frame_state, effect(), control()));
  });
}

TNode<Object> JSCallReducerAssembler::JSCall4(
    TNode<Object> function, TNode<Object> this_arg, TNode<Object> arg0,
    TNode<Object> arg1, TNode<Object> arg2, TNode<Object> arg3,
    FrameState frame_state) {
  JSCallNode n(node_ptr());
  CallParameters const& p = n.Parameters();
  return MayThrow(_ {
    return AddNode<Object>(graph()->NewNode(
        javascript()->Call(JSCallNode::ArityForArgc(4), p.frequency(),
                           p.feedback(), ConvertReceiverMode::kAny,
                           p.speculation_mode(),
                           CallFeedbackRelation::kUnrelated),
        function, this_arg, arg0, arg1, arg2, arg3, n.feedback_vector(),
        ContextInput(), frame_state, effect(), control()));
  });
}

TNode<Object> JSCallReducerAssembler::CopyNode() {
  return MayThrow(_ {
    Node* copy = graph()->CloneNode(node_ptr());
    NodeProperties::ReplaceEffectInput(copy, effect());
    NodeProperties::ReplaceControlInput(copy, control());
    return AddNode<Object>(copy);
  });
}

TNode<JSArray> JSCallReducerAssembler::CreateArrayNoThrow(
    TNode<Object> ctor, TNode<Number> size, FrameState frame_state) {
  return AddNode<JSArray>(
      graph()->NewNode(javascript()->CreateArray(1, std::nullopt), ctor, ctor,
                       size, ContextInput(), frame_state, effect(), control()));
}

TNode<JSArray> JSCallReducerAssembler::AllocateEmptyJSArray(
    ElementsKind kind, NativeContextRef native_context) {
  // TODO(jgruber): Port AllocationBuilder to JSGraphAssembler.
  MapRef map = native_context.GetInitialJSArrayMap(broker(), kind);

  AllocationBuilder ab(jsgraph(), broker(), effect(), control());
  ab.Allocate(map.instance_size(), AllocationType::kYoung, Type::Array());
  ab.Store(AccessBuilder::ForMap(), map);
  Node* empty_fixed_array = jsgraph()->EmptyFixedArrayConstant();
  ab.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
           empty_fixed_array);
  ab.Store(AccessBuilder::ForJSObjectElements(), empty_fixed_array);
  ab.Store(AccessBuilder::ForJSArrayLength(kind), jsgraph()->ZeroConstant());
  for (int i = 0; i < map.GetInObjectProperties(); ++i) {
    ab.Store(AccessBuilder::ForJSObjectInObjectProperty(map, i),
             jsgraph()->UndefinedConstant());
  }
  Node* result = ab.Finish();
  InitializeEffectControl(result, control());
  return TNode<JSArray>::UncheckedCast(result);
}

TNode<Number> JSCallReducerAssembler::LoadMapElementsKind(TNode<Map> map) {
  TNode<Number> bit_field2 =
      LoadField<Number>(AccessBuilder::ForMapBitField2(), map);
  return NumberShiftRightLogical(
      NumberBitwiseAnd(bit_field2,
                       NumberConstant(Map::Bits2::ElementsKindBits::kMask)),
      NumberConstant(Map::Bits2::ElementsKindBits::kShift));
}

TNode<Object> JSCallReducerAssembler::ReduceMathUnary(const Operator* op) {
  TNode<Object> input = Argument(0);
  TNode<Number> input_as_number = SpeculativeToNumber(input);
  return TNode<Object>::UncheckedCast(graph()->NewNode(op, input_as_number));
}

TNode<Object> JSCallReducerAssembler::ReduceMathBinary(const Operator* op) {
  TNode<Object> left = Argument(0);
  TNode<Object> right = ArgumentOrNaN(1);
  TNode<Number> left_number = SpeculativeToNumber(left);
  TNode<Number> right_number = SpeculativeToNumber(right);
  return TNode<Object>::UncheckedCast(
      graph()->NewNode(op, left_number, right_number));
}

TNode<String> JSCallReducerAssembler::ReduceStringPrototypeSubstring() {
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> start = Argument(0);
  TNode<Object> end = ArgumentOrUndefined(1);

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Number> start_smi = CheckSmi(start);

  TNode<Number> length = StringLength(receiver_string);

  TNode<Number> end_smi = SelectIf<Number>(IsUndefined(end))
                              .Then(_ { return length; })
                              .Else(_ { return CheckSmi(end); })
                              .ExpectFalse()
                              .Value();

  TNode<Number> zero = TNode<Number>::UncheckedCast(ZeroConstant());
  TNode<Number> finalStart = NumberMin(NumberMax(start_smi, zero), length);
  TNode<Number> finalEnd = NumberMin(NumberMax(end_smi, zero), length);
  TNode<Number> from = NumberMin(finalStart, finalEnd);
  TNode<Number> to = NumberMax(finalStart, finalEnd);

  return StringSubstring(receiver_string, from, to);
}

TNode<Boolean> JSCallReducerAssembler::ReduceStringPrototypeStartsWith(
    StringRef search_element_string) {
  DCHECK(search_element_string.IsContentAccessible());
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> start = ArgumentOrZero(1);

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Smi> start_smi = CheckSmi(start);
  TNode<Number> length = StringLength(receiver_string);

  TNode<Number> zero = ZeroConstant();
  TNode<Number> clamped_start = NumberMin(NumberMax(start_smi, zero), length);

  int search_string_length = search_element_string.length();
  DCHECK(search_string_length <= JSCallReducer::kMaxInlineMatchSequence);

  auto out = MakeLabel(MachineRepresentation::kTagged);

  auto search_string_too_long =
      NumberLessThan(NumberSubtract(length, clamped_start),
                     NumberConstant(search_string_length));

  GotoIf(search_string_too_long, &out, BranchHint::kFalse, FalseConstant());

  static_assert(String::kMaxLength <= kSmiMaxValue);

  for (int i = 0; i < search_string_length; i++) {
    TNode<Number> k = NumberConstant(i);
    TNode<Number> receiver_string_position = TNode<Number>::UncheckedCast(
        TypeGuard(Type::UnsignedSmall(), NumberAdd(k, clamped_start)));
    Node* receiver_string_char =
        StringCharCodeAt(receiver_string, receiver_string_position);
    Node* search_string_char = jsgraph()->ConstantNoHole(
        search_element_string.GetChar(broker(), i).value());
    auto is_equal = graph()->NewNode(simplified()->NumberEqual(),
                                     search_string_char, receiver_string_char);
    GotoIfNot(is_equal, &out, FalseConstant());
  }

  Goto(&out, TrueConstant());

  Bind(&out);
  return out.PhiAt<Boolean>(0);
}

TNode<Boolean> JSCallReducerAssembler::ReduceStringPrototypeStartsWith() {
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> search_element = ArgumentOrUndefined(0);
  TNode<Object> start = ArgumentOrZero(1);

  TNode<String> receiver_string = CheckString(receiver);
  TNode<String> search_string = CheckString(search_element);
  TNode<Smi> start_smi = CheckSmi(start);
  TNode<Number> length = StringLength(receiver_string);

  TNode<Number> zero = ZeroConstant();
  TNode<Number> clamped_start = NumberMin(NumberMax(start_smi, zero), length);

  TNode<Number> search_string_length = StringLength(search_string);

  auto out = MakeLabel(MachineRepresentation::kTagged);

  auto search_string_too_long = NumberLessThan(
      NumberSubtract(length, clamped_start), search_string_length);

  GotoIf(search_string_too_long, &out, BranchHint::kFalse, FalseConstant());

  static_assert(String::kMaxLength <= kSmiMaxValue);

  ForZeroUntil(search_string_length).Do([&](TNode<Number> k) {
    TNode<Number> receiver_string_position = TNode<Number>::UncheckedCast(
        TypeGuard(Type::UnsignedSmall(), NumberAdd(k, clamped_start)));
    Node* receiver_string_char =
        StringCharCodeAt(receiver_string, receiver_string_position);
    if (!v8_flags.turbo_loop_variable) {
      // Without loop variable analysis, Turbofan's typer is unable to derive a
      // sufficiently precise type here. This is not a soundness problem, but
      // triggers graph verification errors. So we only insert the TypeGuard if
      // necessary.
      k = TypeGuard(Type::Unsigned32(), k);
    }
    Node* search_string_char = StringCharCodeAt(search_string, k);
    auto is_equal = graph()->NewNode(simplified()->NumberEqual(),
                                     receiver_string_char, search_string_char);
    GotoIfNot(is_equal, &out, FalseConstant());
  });

  Goto(&out, TrueConstant());

  Bind(&out);
  return out.PhiAt<Boolean>(0);
}

TNode<Boolean> JSCallReducerAssembler::ReduceStringPrototypeEndsWith(
    StringRef search_element_string) {
  DCHECK(search_element_string.IsContentAccessible());
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> end_position = ArgumentOrUndefined(1);
  TNode<Number> zero = ZeroConstant();

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Number> length = StringLength(receiver_string);
  int search_string_length = search_element_string.length();
  DCHECK_LE(search_string_length, JSCallReducer::kMaxInlineMatchSequence);

  TNode<Number> clamped_end =
      SelectIf<Number>(IsUndefined(end_position))
          .Then(_ { return length; })
          .Else(_ {
            return NumberMin(NumberMax(CheckSmi(end_position), zero), length);
          })
          .ExpectTrue()
          .Value();

  TNode<Number> start =
      NumberSubtract(clamped_end, NumberConstant(search_string_length));

  auto out = MakeLabel(MachineRepresentation::kTagged);

  TNode<Boolean> search_string_too_long = NumberLessThan(start, zero);
  GotoIf(search_string_too_long, &out, BranchHint::kFalse, FalseConstant());

  for (int i = 0; i < search_string_length; i++) {
    TNode<Number> k = NumberConstant(i);
    TNode<Number> receiver_string_position = TNode<Number>::UncheckedCast(
        TypeGuard(Type::UnsignedSmall(), NumberAdd(k, start)));
    Node* receiver_string_char =
        StringCharCodeAt(receiver_string, receiver_string_position);
    Node* search_string_char = jsgraph()->ConstantNoHole(
        search_element_string.GetChar(broker(), i).value());
    auto is_equal = graph()->NewNode(simplified()->NumberEqual(),
                                     receiver_string_char, search_string_char);
    GotoIfNot(is_equal, &out, FalseConstant());
  }

  Goto(&out, TrueConstant());

  Bind(&out);
  return out.PhiAt<Boolean>(0);
}

TNode<Boolean> JSCallReducerAssembler::ReduceStringPrototypeEndsWith() {
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> search_string = ArgumentOrUndefined(0);
  TNode<Object> end_position = ArgumentOrUndefined(1);
  TNode<Number> zero = ZeroConstant();

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Number> length = StringLength(receiver_string);
  TNode<String> search_element_string = CheckString(search_string);
  TNode<Number> search_string_length = StringLength(search_element_string);

  TNode<Number> clamped_end =
      SelectIf<Number>(IsUndefined(end_position))
          .Then(_ { return length; })
          .Else(_ {
            return NumberMin(NumberMax(CheckSmi(end_position), zero), length);
          })
          .ExpectTrue()
          .Value();

  TNode<Number> start = NumberSubtract(clamped_end, search_string_length);

  auto out = MakeLabel(MachineRepresentation::kTagged);

  TNode<Boolean> search_string_too_long = NumberLessThan(start, zero);
  GotoIf(search_string_too_long, &out, BranchHint::kFalse, FalseConstant());

  ForZeroUntil(search_string_length).Do([&](TNode<Number> k) {
    TNode<Number> receiver_string_position = TNode<Number>::UncheckedCast(
        TypeGuard(Type::UnsignedSmall(), NumberAdd(k, start)));
    Node* receiver_string_char =
        StringCharCodeAt(receiver_string, receiver_string_position);
    if (!v8_flags.turbo_loop_variable) {
      // Without loop variable analysis, Turbofan's typer is unable to derive a
      // sufficiently precise type here. This is not a soundness problem, but
      // triggers graph verification errors. So we only insert the TypeGuard if
      // necessary.
      k = TypeGuard(Type::Unsigned32(), k);
    }
    Node* search_string_char = StringCharCodeAt(search_element_string, k);
    auto is_equal = graph()->NewNode(simplified()->NumberEqual(),
                                     receiver_string_char, search_string_char);
    GotoIfNot(is_equal, &out, FalseConstant());
  });

  Goto(&out, TrueConstant());

  Bind(&out);
  return out.PhiAt<Boolean>(0);
}

TNode<String> JSCallReducerAssembler::ReduceStringPrototypeCharAt(
    StringRef s, uint32_t index) {
  DCHECK(s.IsContentAccessible());
  if (s.IsOneByteRepresentation()) {
    OptionalObjectRef elem = s.GetCharAsStringOrUndefined(broker(), index);
    TNode<String> elem_string =
        elem.has_value()
            ? TNode<String>::UncheckedCast(
                  jsgraph()->ConstantNoHole(elem.value(), broker()))
            : EmptyStringConstant();
    return elem_string;
  } else {
    const uint32_t length = static_cast<uint32_t>(s.length());
    if (index >= length) return EmptyStringConstant();
    Handle<SeqTwoByteString> flat = broker()->CanonicalPersistentHandle(
        broker()
            ->local_isolate_or_isolate()
            ->factory()
            ->NewRawTwoByteString(1, AllocationType::kOld)
            .ToHandleChecked());
    flat->SeqTwoByteStringSet(0, s.GetChar(broker(), index).value());
    TNode<String> two_byte_elem =
        TNode<String>::UncheckedCast(jsgraph()->HeapConstantNoHole(flat));
    return two_byte_elem;
  }
}

TNode<String> JSCallReducerAssembler::ReduceStringPrototypeCharAt() {
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> index = ArgumentOrZero(0);

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Number> index_smi = CheckSmi(index);
  TNode<Number> length = StringLength(receiver_string);

  TNode<Number> bounded_index = CheckBounds(index_smi, length);

  Node* result = StringCharCodeAt(receiver_string, bounded_index);
  TNode<String> result_string =
      StringFromSingleCharCode(TNode<Number>::UncheckedCast(result));
  return result_string;
}

TNode<String> JSCallReducerAssembler::ReduceStringPrototypeSlice() {
  TNode<Object> receiver = ReceiverInput();
  TNode<Object> start = Argument(0);
  TNode<Object> end = ArgumentOrUndefined(1);

  TNode<String> receiver_string = CheckString(receiver);
  TNode<Number> start_smi = CheckSmi(start);

  TNode<Number> length = StringLength(receiver_string);

  TNode<Number> end_smi = SelectIf<Number>(IsUndefined(end))
                              .Then(_ { return length; })
                              .Else(_ { return CheckSmi(end); })
                              .ExpectFalse()
                              .Value();

  TNode<Number> zero = TNode<Number>::UncheckedCast(ZeroConstant());
  TNode<Number> from_untyped =
      SelectIf<Number>(NumberLessThan(start_smi, zero))
          .Then(_ { return NumberMax(NumberAdd(length, start_smi), zero); })
          .Else(_ { return NumberMin(start_smi, length); })
          .ExpectFalse()
          .Value();
  // {from} is always in non-negative Smi range, but our typer cannot figure
  // that out yet.
  TNode<Smi> from = TypeGuardUnsignedSmall(from_untyped);

  TNode<Number> to_untyped =
      SelectIf<Number>(NumberLessThan(end_smi, zero))
          .Then(_ { return NumberMax(NumberAdd(length, end_smi), zero); })
          .Else(_ { return NumberMin(end_smi, length); })
          .ExpectFalse()
          .Value();
  // {to} is always in non-negative Smi range, but our typer cannot figure that
  // out yet.
  TNode<Smi> to = TypeGuardUnsignedSmall(to_untyped);

  return SelectIf<String>(NumberLessThan(from, to))
      .Then(_ { return StringSubstring(receiver_string, from, to); })
      .Else(_ { return EmptyStringConstant(); })
      .ExpectTrue()
      .Value();
}

TNode<Object> JSCallReducerAssembler::ReduceJSCallMathMinMaxWithArrayLike(
    Builtin builtin) {
  JSCallWithArrayLikeNode n(node_ptr());
  TNode<Object> arguments_list = n.Argument(0);

  auto call_builtin = MakeLabel();
  auto done = MakeLabel(MachineRepresentation::kTagged);

  // Check if {arguments_list} is a JSArray.
  GotoIf(ObjectIsSmi(arguments_list), &call_builtin);
  TNode<Map> arguments_list_map =
      LoadField<Map>(AccessBuilder::ForMap(),
                     TNode<HeapObject>::UncheckedCast(arguments_list));
  TNode<Number> arguments_list_instance_type = LoadField<Number>(
      AccessBuilder::ForMapInstanceType(), arguments_list_map);
  auto check_instance_type =
      NumberEqual(arguments_list_instance_type, NumberConstant(JS_ARRAY_TYPE));
  GotoIfNot(check_instance_type, &call_builtin);

  // Check if {arguments_list} has PACKED_DOUBLE_ELEMENTS.
  TNode<Number> arguments_list_elements_kind =
      LoadMapElementsKind(arguments_list_map);

  auto check_element_kind = NumberEqual(arguments_list_elements_kind,
                                        NumberConstant(PACKED_DOUBLE_ELEMENTS));
  GotoIfNot(check_element_kind, &call_builtin);

  // If {arguments_list} is a JSArray with PACKED_DOUBLE_ELEMENTS, calculate the
  // result with inlined loop.
  TNode<JSArray> array_arguments_list =
      TNode<JSArray>::UncheckedCast(arguments_list);
  Goto(&done, builtin == Builtin::kMathMax
                  ? DoubleArrayMax(array_arguments_list)
                  : DoubleArrayMin(array_arguments_list));

  // Otherwise, call BuiltinMathMin/Max as usual.
  Bind(&call_builtin);
  TNode<Object> call = CopyNode();
  CallParameters const& p = n.Parameters();

  // Set SpeculationMode to kDisallowSpeculation to avoid infinite
  // recursion.
  NodeProperties::ChangeOp(
      call, javascript()->CallWithArrayLike(
                p.frequency(), p.feedback(),
                SpeculationMode::kDisallowSpeculation, p.feedback_relation()));
  Goto(&done, call);

  Bind(&done);
  return done.PhiAt<Object>(0);
}

TNode<Object> IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeAt(
    ZoneVector<MapRef> maps, bool needs_fallback_builtin_call) {
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> index = ArgumentOrZero(0);

  TNode<Number> index_num = CheckSmi(index);
  TNode<FixedArrayBase> elements = LoadElements(receiver);

  TNode<Map> receiver_map =
      TNode<Map>::UncheckedCast(LoadField(AccessBuilder::ForMap(), receiver));

  auto out = MakeLabel(MachineRepresentation::kTagged);

  for (MapRef map : maps) {
    DCHECK(map.supports_fast_array_iteration(broker()));
    auto correct_map_label = MakeLabel(), wrong_map_label = MakeLabel();
    TNode<Boolean> is_map_equal = ReferenceEqual(receiver_map, Constant(map));
    Branch(is_map_equal, &correct_map_label, &wrong_map_label);
    Bind(&correct_map_label);

    TNode<Number> length = LoadJSArrayLength(receiver, map.elements_kind());

    // If index is less than 0, then subtract from length.
    TNode<Boolean> cond = NumberLessThan(index_num, ZeroConstant());
    TNode<Number> real_index_num =
        SelectIf<Number>(cond)
            .Then(_ { return NumberAdd(length, index_num); })
            .Else(_ { return index_num; })
            .ExpectTrue()  // Most common usage should be .at(-1)
            .Value();

    // Bound checking.
    GotoIf(NumberLessThan(real_index_num, ZeroConstant()), &out,
           UndefinedConstant());
    GotoIfNot(NumberLessThan(real_index_num, length), &out,
              UndefinedConstant());
    if (v8_flags.turbo_typer_hardening) {
      real_index_num = CheckBounds(real_index_num, length,
                                   CheckBoundsFlag::kAbortOnOutOfBounds);
    }

    // Retrieving element at index.
    TNode<Object> element = LoadElement<Object>(
        AccessBuilder::ForFixedArrayElement(map.elements_kind()), elements,
        real_index_num);
    if (IsHoleyElementsKind(map.elements_kind())) {
      // This case is needed in particular for HOLEY_DOUBLE_ELEMENTS: raw
      // doubles are stored in the FixedDoubleArray, and need to be converted to
      // HeapNumber or to Smi so that this function can return an Object. The
      // automatic converstion performed by
      // RepresentationChanger::GetTaggedRepresentationFor does not handle
      // holes, so we convert manually a potential hole here.
      element = ConvertHoleToUndefined(element, map.elements_kind());
    }
    Goto(&out, element);

    Bind(&wrong_map_label);
  }

  if (needs_fallback_builtin_call) {
    JSCallNode n(node_ptr());
    CallParameters const& p = n.Parameters();

    // We set SpeculationMode to kDisallowSpeculation to avoid infinite
    // recursion on the node we're creating (since, after all, it's calling
    // Array.Prototype.at).
    const Operator* op = javascript()->Call(
        JSCallNode::ArityForArgc(1), p.frequency(), p.feedback(),
        ConvertReceiverMode::kNotNullOrUndefined,
        SpeculationMode::kDisallowSpeculation, CallFeedbackRelation::kTarget);
    Node* fallback_builtin = node_ptr()->InputAt(0);

    TNode<Object> res = AddNode<Object>(graph()->NewNode(
        op, fallback_builtin, receiver, index, n.feedback_vector(),
        ContextInput(), n.frame_state(), effect(), control()));
    Goto(&out, res);
  } else {
    Goto(&out, UndefinedConstant());
  }

  Bind(&out);
  return out.PhiAt<Object>(0);
}

TNode<Number> IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypePush(
    MapInference* inference) {
  int const num_push_arguments = ArgumentCount();
  ZoneRefSet<Map> const& receiver_maps = inference->GetMaps();

  base::SmallVector<MachineRepresentation, 4> argument_reps;
  base::SmallVector<Node*, 4> argument_nodes;

  for (int i = 0; i < num_push_arguments; ++i) {
    argument_reps.push_back(MachineRepresentation::kTagged);
    argument_nodes.push_back(Argument(i));
  }

  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Map> receiver_map = LoadMap(receiver);

  auto double_label = MakeLabel(argument_reps);
  auto smi_label = MakeLabel(argument_reps);
  auto object_label = MakeLabel(argument_reps);

  for (size_t i = 0; i < receiver_maps.size(); i++) {
    MapRef map = receiver_maps[i];
    ElementsKind kind = map.elements_kind();

    if (i < receiver_maps.size() - 1) {
      TNode<Boolean> is_map_equal = ReferenceEqual(receiver_map, Constant(map));
      if (IsDoubleElementsKind(kind)) {
        GotoIf(is_map_equal, &double_label, argument_nodes);
      } else if (IsSmiElementsKind(kind)) {
        GotoIf(is_map_equal, &smi_label, argument_nodes);
      } else {
        GotoIf(is_map_equal, &object_label, argument_nodes);
      }
    } else {
      if (IsDoubleElementsKind(kind)) {
        Goto(&double_label, argument_nodes);
      } else if (IsSmiElementsKind(kind)) {
        Goto(&smi_label, argument_nodes);
      } else {
        Goto(&object_label, argument_nodes);
      }
    }
  }

  auto return_label = MakeLabel(MachineRepresentation::kTagged);

  auto build_array_push = [&](ElementsKind kind,
                              base::SmallVector<Node*, 1>& push_arguments) {
    // Only support PACKED_ELEMENTS and PACKED_DOUBLE_ELEMENTS, as "markers" of
    // what the elements array is (a FixedArray or FixedDoubleArray).
    DCHECK(kind == PACKED_ELEMENTS || kind == PACKED_DOUBLE_ELEMENTS);

    // Load the "length" property of the {receiver}.
    TNode<Smi> length = LoadJSArrayLength(receiver, kind);
    TNode<Number> return_value = length;

    // Check if we have any {values} to push.
    if (num_push_arguments > 0) {
      // Compute the resulting "length" of the {receiver}.
      TNode<Number> new_length = return_value =
          NumberAdd(length, NumberConstant(num_push_arguments));

      // Load the elements backing store of the {receiver}.
      TNode<FixedArrayBase> elements = LoadElements(receiver);
      TNode<Smi> elements_length = LoadFixedArrayBaseLength(elements);

      elements = MaybeGrowFastElements(
          kind, feedback(), receiver, elements,
          NumberAdd(length, NumberConstant(num_push_arguments - 1)),
          elements_length);

      // Update the JSArray::length field. Since this is observable,
      // there must be no other check after this.
      StoreJSArrayLength(receiver, new_length, kind);

      // Append the {values} to the {elements}.
      for (int i = 0; i < num_push_arguments; ++i) {
        StoreFixedArrayBaseElement(
            elements, NumberAdd(length, NumberConstant(i)),
            TNode<Object>::UncheckedCast(push_arguments[i]), kind);
      }
    }

    Goto(&return_label, return_value);
  };

  if (double_label.IsUsed()) {
    Bind(&double_label);
    base::SmallVector<Node*, 1> push_arguments(num_push_arguments);
    for (int i = 0; i < num_push_arguments; ++i) {
      Node* value =
          CheckNumber(TNode<Object>::UncheckedCast(double_label.PhiAt(i)));
      // Make sure we do not store signaling NaNs into double arrays.
      value = AddNode<Number>(
          graph()->NewNode(simplified()->NumberSilenceNaN(), value));
      push_arguments[i] = value;
    }
    build_array_push(PACKED_DOUBLE_ELEMENTS, push_arguments);
  }

  if (smi_label.IsUsed()) {
    Bind(&smi_label);
    base::SmallVector<Node*, 4> push_arguments(num_push_arguments);
    for (int i = 0; i < num_push_arguments; ++i) {
      Node* value = CheckSmi(TNode<Object>::UncheckedCast(smi_label.PhiAt(i)));
      push_arguments[i] = value;
    }
    Goto(&object_label, push_arguments);
  }

  if (object_label.IsUsed()) {
    Bind(&object_label);
    base::SmallVector<Node*, 1> push_arguments(num_push_arguments);
    for (int i = 0; i < num_push_arguments; ++i) {
      push_arguments[i] = object_label.PhiAt(i);
    }
    build_array_push(PACKED_ELEMENTS, push_arguments);
  }

  Bind(&return_label);
  return TNode<Number>::UncheckedCast(return_label.PhiAt(0));
}

namespace {

struct ForEachFrameStateParams {
  JSGraph* jsgraph;
  SharedFunctionInfoRef shared;
  TNode<Context> context;
  TNode<Object> target;
  FrameState outer_frame_state;
  TNode<Object> receiver;
  TNode<Object> callback;
  TNode<Object> this_arg;
  TNode<Object> original_length;
};

FrameState ForEachLoopLazyFrameState(const ForEachFrameStateParams& params,
                                     TNode<Object> k) {
  Builtin builtin = Builtin::kArrayForEachLoopLazyDeoptContinuation;
  Node* checkpoint_params[] = {params.receiver, params.callback,
                               params.this_arg, k, params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

FrameState ForEachLoopEagerFrameState(const ForEachFrameStateParams& params,
                                      TNode<Object> k) {
  Builtin builtin = Builtin::kArrayForEachLoopEagerDeoptContinuation;
  Node* checkpoint_params[] = {params.receiver, params.callback,
                               params.this_arg, k, params.original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::EAGER);
}

}  // namespace

TNode<Object>
IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeForEach(
    MapInference* inference, const bool has_stability_dependency,
    ElementsKind kind, SharedFunctionInfoRef shared) {
  FrameState outer_frame_state = FrameStateInput();
  TNode<Context> context = ContextInput();
  TNode<Object> target = TargetInput();
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> fncallback = ArgumentOrUndefined(0);
  TNode<Object> this_arg = ArgumentOrUndefined(1);

  TNode<Number> original_length = LoadJSArrayLength(receiver, kind);

  ForEachFrameStateParams frame_state_params{
      jsgraph(), shared,     context,  target,         outer_frame_state,
      receiver,  fncallback, this_arg, original_length};

  ThrowIfNotCallable(fncallback, ForEachLoopLazyFrameState(frame_state_params,
                                                           ZeroConstant()));

  ForZeroUntil(original_length).Do([&](TNode<Number> k) {
    Checkpoint(ForEachLoopEagerFrameState(frame_state_params, k));

    // Deopt if the map has changed during the iteration.
    MaybeInsertMapChecks(inference, has_stability_dependency);

    TNode<Object> element;
    std::tie(k, element) = SafeLoadElement(kind, receiver, k);

    auto continue_label = MakeLabel();
    element = MaybeSkipHole(element, kind, &continue_label);

    TNode<Number> next_k = NumberAdd(k, OneConstant());
    JSCall3(fncallback, this_arg, element, k, receiver,
            ForEachLoopLazyFrameState(frame_state_params, next_k));

    Goto(&continue_label);
    Bind(&continue_label);
  });

  return UndefinedConstant();
}

namespace {

struct ReduceFrameStateParams {
  JSGraph* jsgraph;
  SharedFunctionInfoRef shared;
  ArrayReduceDirection direction;
  TNode<Context> context;
  TNode<Object> target;
  FrameState outer_frame_state;
};

FrameState ReducePreLoopLazyFrameState(const ReduceFrameStateParams& params,
                                       TNode<Object> receiver,
                                       TNode<Object> callback, TNode<Object> k,
                                       TNode<Number> original_length) {
  Builtin builtin = (params.direction == ArrayReduceDirection::kLeft)
                        ? Builtin::kArrayReduceLoopLazyDeoptContinuation
                        : Builtin::kArrayReduceRightLoopLazyDeoptContinuation;
  Node* checkpoint_params[] = {receiver, callback, k, original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

FrameState ReducePreLoopEagerFrameState(const ReduceFrameStateParams& params,
                                        TNode<Object> receiver,
                                        TNode<Object> callback,
                                        TNode<Number> original_length) {
  Builtin builtin =
      (params.direction == ArrayReduceDirection::kLeft)
          ? Builtin::kArrayReducePreLoopEagerDeoptContinuation
          : Builtin::kArrayReduceRightPreLoopEagerDeoptContinuation;
  Node* checkpoint_params[] = {receiver, callback, original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::EAGER);
}

FrameState ReduceLoopLazyFrameState(const ReduceFrameStateParams& params,
                                    TNode<Object> receiver,
                                    TNode<Object> callback, TNode<Object> k,
                                    TNode<Number> original_length) {
  Builtin builtin = (params.direction == ArrayReduceDirection::kLeft)
                        ? Builtin::kArrayReduceLoopLazyDeoptContinuation
                        : Builtin::kArrayReduceRightLoopLazyDeoptContinuation;
  Node* checkpoint_params[] = {receiver, callback, k, original_length};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

FrameState ReduceLoopEagerFrameState(const ReduceFrameStateParams& params,
                                     TNode<Object> receiver,
                                     TNode<Object> callback, TNode<Object> k,
                                     TNode<Number> original_length,
                                     TNode<Object> accumulator) {
  Builtin builtin = (params.direction == ArrayReduceDirection::kLeft)
                        ? Builtin::kArrayReduceLoopEagerDeoptContinuation
                        : Builtin::kArrayReduceRightLoopEagerDeoptContinuation;
  Node* checkpoint_params[] = {receiver, callback, k, original_length,
                               accumulator};
  return CreateJavaScriptBuiltinContinuationFrameState(
      params.jsgraph, params.shared, builtin, params.target, params.context,
      checkpoint_params, arraysize(checkpoint_params), params.outer_frame_state,
      ContinuationFrameStateMode::EAGER);
}

}  // namespace

TNode<Object> IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeReduce(
    MapInference* inference, const bool has_stability_dependency,
    ElementsKind kind, ArrayReduceDirection direction,
    SharedFunctionInfoRef shared) {
  FrameState outer_frame_state = FrameStateInput();
  TNode<Context> context = ContextInput();
  TNode<Object> target = TargetInput();
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> fncallback =
```