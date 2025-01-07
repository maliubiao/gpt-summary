Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/heap/test-heap.cc`. The snippet contains several independent test cases for V8's heap management.

Here's a breakdown of the steps:

1. **Identify individual test cases:** The code is structured using `TEST` and `HEAP_TEST` macros, which clearly delineate individual tests.
2. **Analyze each test case:** For each test, determine the primary functionality being tested. This involves looking at the V8 API calls being used and the assertions being made (`CHECK`, `CHECK_EQ`).
3. **Relate to JavaScript concepts:** Where applicable, connect the C++ heap operations to their equivalent JavaScript behaviors.
4. **Consider `.tq` and JavaScript relationship:** Note that the file ends with `.cc` and not `.tq`, so it's C++ test code, not Torque. It tests JavaScript functionalities.
5. **Provide JavaScript examples:** Illustrate the JavaScript side of the tested heap operations.
6. **Infer input/output for logic:** If a test involves manipulating data structures, specify example inputs and expected outputs based on the code's logic.
7. **Identify potential user errors:**  Think about common mistakes developers make with the JavaScript features being tested.
8. **Aggregate the functionalities:** Summarize the purpose of the code snippet as a whole.
这是 `v8/test/cctest/heap/test-heap.cc` 源代码的第 2 部分，主要功能是测试 V8 堆的各种操作，包括：

**1. JSArray 的操作和内存布局变化：**

*   **功能：** 测试 `JSArray` 对象的创建、长度设置、元素添加以及在长度超过 `Smi` 范围时内存布局从快速模式（Smi或Object元素）切换到慢速模式（Dictionary元素）的行为。
*   **与 JavaScript 的关系：**  与 JavaScript 中数组的创建和动态增长相关。
*   **JavaScript 示例：**
    ```javascript
    let arr = []; // 创建一个空数组
    console.log(arr.length); // 输出 0
    arr[0] = "hello"; // 添加元素
    console.log(arr.length); // 输出 1
    arr.length = 4294967296; // 设置一个超过 Smi 最大值的长度
    arr[arr.length - 1] = "world"; // 在超出范围的位置添加元素
    console.log(arr.length); // 输出 4294967296
    console.log(arr[0]); // 输出 "hello"
    console.log(arr[arr.length - 1]); // 输出 "world"
    ```
*   **代码逻辑推理：**
    *   **假设输入：** 创建一个空数组，然后设置长度为一个大于 `Smi::kMaxValue` 的值。
    *   **预期输出：** 数组的内部元素存储方式会从快速模式切换到慢速模式（字典模式）。后续对数组的操作会基于字典模式进行。
*   **用户常见的编程错误：**  过度依赖数组长度的准确性，尤其是在长度被手动设置为非常大的值时，可能会导致性能问题，因为此时数组可能使用稀疏存储。

**2. JSObject 的拷贝：**

*   **功能：** 测试 `factory->CopyJSObject(obj)` 方法，用于创建一个 `JSObject` 的浅拷贝。验证拷贝后的对象与原始对象具有相同的属性和元素，并且修改拷贝后的对象不会影响原始对象。
*   **与 JavaScript 的关系：** 类似于 JavaScript 中使用扩展运算符 (`...`) 或 `Object.assign()` 进行浅拷贝。
*   **JavaScript 示例：**
    ```javascript
    let obj1 = { first: 1, second: 2, 0: "first", 1: "second" };
    let obj2 = { ...obj1 }; // 浅拷贝
    console.log(obj2); // 输出 { first: 1, second: 2, '0': 'first', '1': 'second' }
    obj2.first = "changed";
    obj2[0] = "changed_element";
    console.log(obj1.first); // 输出 1 (未被修改)
    console.log(obj1[0]); // 输出 "first" (未被修改)
    console.log(obj2.first); // 输出 "changed"
    console.log(obj2[0]); // 输出 "changed_element"
    ```
*   **代码逻辑推理：**
    *   **假设输入：** 一个包含属性和元素的 `JSObject`。
    *   **预期输出：**  `factory->CopyJSObject` 会创建一个新的 `JSObject`，其属性和元素的值与原始对象相同，但它们是独立的内存地址。
*   **用户常见的编程错误：** 误以为 `factory->CopyJSObject` 或 JavaScript 的浅拷贝是深拷贝，导致修改拷贝后的对象时意外地影响了原始对象。

**3. 字符串的分配和内部化：**

*   **功能：** 测试不同长度和编码方式（单字节和多字节）字符串的分配 (`NewStringFromUtf8`, `InternalizeUtf8String`, `InternalizeString`)。验证分配后的字符串长度正确，并且内部化字符串会创建唯一的字符串对象。
*   **与 JavaScript 的关系：** 与 JavaScript 中创建和使用字符串相关。内部化字符串类似于字符串字面量在某些情况下的共享。
*   **JavaScript 示例：**
    ```javascript
    let str1 = "abc";
    let str2 = "你好";
    let str3 = "abc";
    console.log(str1.length); // 输出 3
    console.log(str2.length); // 输出 2
    console.log(str1 === str3); // 输出 true (字符串字面量可能被共享)
    ```
*   **代码逻辑推理：**
    *   **假设输入：** 不同长度和内容的字符串。
    *   **预期输出：**  `factory->NewStringFromUtf8` 会创建新的字符串对象，而 `factory->InternalizeUtf8String` 对于相同的字符串内容会返回相同的对象引用。
*   **用户常见的编程错误：**  没有意识到字符串内部化的机制，可能会在某些场景下创建不必要的重复字符串对象，占用更多内存。

**4. 堆迭代器：**

*   **功能：** 测试 `HeapObjectIterator`，用于遍历堆中的所有对象。验证预先分配的对象可以通过迭代器找到。
*   **与 JavaScript 的关系：**  这部分是 V8 内部的堆管理机制，JavaScript 开发者通常不会直接接触。
*   **代码逻辑推理：**
    *   **假设输入：** 在堆中分配了若干不同类型的对象（数组、字符串等）。
    *   **预期输出：**  `HeapObjectIterator` 能够遍历到所有这些已分配的对象。

**5. Bytecode 的刷新 (Flushing)：**

*   **功能：** 测试 V8 的 bytecode 刷新机制。当内存压力较大时，V8 可以丢弃已编译函数的 bytecode，以回收内存。后续调用该函数时会重新编译。测试了在单引用和多引用的情况下 bytecode 的刷新和重新编译。
*   **与 JavaScript 的关系：**  这部分是 V8 的优化策略，对 JavaScript 开发者是透明的，但会影响性能和内存占用。
*   **JavaScript 示例：**  虽然无法直接用 JavaScript 模拟，但可以通过执行大量的代码，并观察内存使用情况和性能变化来间接感知 bytecode 刷新。
*   **代码逻辑推理：**
    *   **假设输入：**  定义并调用一个 JavaScript 函数。
    *   **预期输出：** 首次调用后，函数会被编译。在经过 GC 后，如果启用了 bytecode 刷新，函数的 bytecode 可能会被清除。再次调用时会重新编译。
*   **用户常见的编程错误：**  通常不会直接涉及到这个层面的错误，但理解 bytecode 刷新有助于理解 V8 的内存管理和性能优化。

**6. 与编译缓存的交互：**

*   **功能：** 测试 bytecode 刷新机制与编译缓存的交互。验证在 bytecode 被刷新后，编译缓存中的条目是否会被清除，以及在不同情况下（是否保留 script 对象）编译缓存的行为。
*   **与 JavaScript 的关系：**  编译缓存可以加速后续相同代码的执行。bytecode 刷新会影响编译缓存的有效性。

**7. NearHeapLimitCallback：**

*   **功能：** 测试 V8 提供的 `NearHeapLimitCallback` 机制。当堆内存使用接近限制时，可以注册回调函数进行处理，例如触发 GC 或调整堆限制。
*   **与 JavaScript 的关系：**  这部分是 V8 提供的用于管理内存的底层机制，JavaScript 开发者可以通过 V8 提供的 API 间接影响内存管理。

**8. Turbofan 优化后的 Bytecode 刷新：**

*   **功能：**  测试在 Turbofan 优化后，bytecode 刷新机制的行为，以及优化后的代码是否会被正确处理。

**9. CompileLazy 和增量写屏障：**

*   **功能：** 测试在增量标记期间，使用 `CompileLazy` 编译函数时，增量写屏障是否被正确使用，以确保垃圾回收的正确性。

**总结一下第 2 部分的功能：**

这段代码主要针对 V8 堆的底层机制进行测试，涵盖了 `JSArray`、`JSObject`、字符串等对象的内存分配、拷贝、内部化，以及 V8 的关键内存管理特性，如堆迭代、bytecode 刷新、编译缓存和近堆限制回调。这些测试确保了 V8 在进行内存管理和代码优化时的正确性和健壮性。开发者通常不会直接使用这些 C++ API，但理解这些测试背后的概念有助于更好地理解 V8 的工作原理，以及 JavaScript 代码的性能和内存行为。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共9部分，请归纳一下它的功能

"""
ory->InternalizeUtf8String("Array");
  Handle<Object> fun_obj =
      Object::GetProperty(isolate, CcTest::i_isolate()->global_object(), name)
          .ToHandleChecked();
  Handle<JSFunction> function = Cast<JSFunction>(fun_obj);

  // Allocate the object.
  DirectHandle<Object> element;
  Handle<JSObject> object = factory->NewJSObject(function);
  Handle<JSArray> array = Cast<JSArray>(object);
  // We just initialized the VM, no heap allocation failure yet.
  JSArray::Initialize(array, 0);

  // Set array length to 0.
  JSArray::SetLength(array, 0);
  CHECK_EQ(Smi::zero(), array->length());
  // Must be in fast mode.
  CHECK(array->HasSmiOrObjectElements());

  // array[length] = name.
  Object::SetElement(isolate, array, 0, name, ShouldThrow::kDontThrow).Check();
  CHECK_EQ(Smi::FromInt(1), array->length());
  element = i::Object::GetElement(isolate, array, 0).ToHandleChecked();
  CHECK_EQ(*element, *name);

  // Set array length with larger than smi value.
  JSArray::SetLength(array, static_cast<uint32_t>(Smi::kMaxValue) + 1);

  uint32_t int_length = 0;
  CHECK(Object::ToArrayIndex(array->length(), &int_length));
  CHECK_EQ(static_cast<uint32_t>(Smi::kMaxValue) + 1, int_length);
  CHECK(array->HasDictionaryElements());  // Must be in slow mode.

  // array[length] = name.
  Object::SetElement(isolate, array, int_length, name, ShouldThrow::kDontThrow)
      .Check();
  uint32_t new_int_length = 0;
  CHECK(Object::ToArrayIndex(array->length(), &new_int_length));
  CHECK_EQ(static_cast<double>(int_length), new_int_length - 1);
  element = Object::GetElement(isolate, array, int_length).ToHandleChecked();
  CHECK_EQ(*element, *name);
  element = Object::GetElement(isolate, array, 0).ToHandleChecked();
  CHECK_EQ(*element, *name);
}

TEST(JSObjectCopy) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  v8::HandleScope sc(CcTest::isolate());
  Handle<String> object_string(
      Cast<String>(ReadOnlyRoots(CcTest::heap()).Object_string()), isolate);
  Handle<Object> object =
      Object::GetProperty(isolate, CcTest::i_isolate()->global_object(),
                          object_string)
          .ToHandleChecked();
  Handle<JSFunction> constructor = Cast<JSFunction>(object);
  Handle<JSObject> obj = factory->NewJSObject(constructor);
  Handle<String> first = factory->InternalizeUtf8String("first");
  Handle<String> second = factory->InternalizeUtf8String("second");

  Handle<Smi> one(Smi::FromInt(1), isolate);
  Handle<Smi> two(Smi::FromInt(2), isolate);

  Object::SetProperty(isolate, obj, first, one).Check();
  Object::SetProperty(isolate, obj, second, two).Check();

  Object::SetElement(isolate, obj, 0, first, ShouldThrow::kDontThrow).Check();
  Object::SetElement(isolate, obj, 1, second, ShouldThrow::kDontThrow).Check();

  // Make the clone.
  DirectHandle<Object> value1, value2;
  Handle<JSObject> clone = factory->CopyJSObject(obj);
  CHECK(!clone.is_identical_to(obj));

  value1 = Object::GetElement(isolate, obj, 0).ToHandleChecked();
  value2 = Object::GetElement(isolate, clone, 0).ToHandleChecked();
  CHECK_EQ(*value1, *value2);
  value1 = Object::GetElement(isolate, obj, 1).ToHandleChecked();
  value2 = Object::GetElement(isolate, clone, 1).ToHandleChecked();
  CHECK_EQ(*value1, *value2);

  value1 = Object::GetProperty(isolate, obj, first).ToHandleChecked();
  value2 = Object::GetProperty(isolate, clone, first).ToHandleChecked();
  CHECK_EQ(*value1, *value2);
  value1 = Object::GetProperty(isolate, obj, second).ToHandleChecked();
  value2 = Object::GetProperty(isolate, clone, second).ToHandleChecked();
  CHECK_EQ(*value1, *value2);

  // Flip the values.
  Object::SetProperty(isolate, clone, first, two).Check();
  Object::SetProperty(isolate, clone, second, one).Check();

  Object::SetElement(isolate, clone, 0, second, ShouldThrow::kDontThrow)
      .Check();
  Object::SetElement(isolate, clone, 1, first, ShouldThrow::kDontThrow).Check();

  value1 = Object::GetElement(isolate, obj, 1).ToHandleChecked();
  value2 = Object::GetElement(isolate, clone, 0).ToHandleChecked();
  CHECK_EQ(*value1, *value2);
  value1 = Object::GetElement(isolate, obj, 0).ToHandleChecked();
  value2 = Object::GetElement(isolate, clone, 1).ToHandleChecked();
  CHECK_EQ(*value1, *value2);

  value1 = Object::GetProperty(isolate, obj, second).ToHandleChecked();
  value2 = Object::GetProperty(isolate, clone, first).ToHandleChecked();
  CHECK_EQ(*value1, *value2);
  value1 = Object::GetProperty(isolate, obj, first).ToHandleChecked();
  value2 = Object::GetProperty(isolate, clone, second).ToHandleChecked();
  CHECK_EQ(*value1, *value2);
}

TEST(StringAllocation) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  const unsigned char chars[] = {0xE5, 0xA4, 0xA7};
  for (int length = 0; length < 100; length++) {
    v8::HandleScope scope(CcTest::isolate());
    char* non_one_byte = NewArray<char>(3 * length + 1);
    char* one_byte = NewArray<char>(length + 1);
    non_one_byte[3 * length] = 0;
    one_byte[length] = 0;
    for (int i = 0; i < length; i++) {
      one_byte[i] = 'a';
      non_one_byte[3 * i] = chars[0];
      non_one_byte[3 * i + 1] = chars[1];
      non_one_byte[3 * i + 2] = chars[2];
    }
    DirectHandle<String> non_one_byte_sym = factory->InternalizeUtf8String(
        base::Vector<const char>(non_one_byte, 3 * length));
    CHECK_EQ(length, non_one_byte_sym->length());
    DirectHandle<String> one_byte_sym =
        factory->InternalizeString(base::OneByteVector(one_byte, length));
    CHECK_EQ(length, one_byte_sym->length());
    CHECK(one_byte_sym->HasHashCode());
    DirectHandle<String> non_one_byte_str =
        factory
            ->NewStringFromUtf8(
                base::Vector<const char>(non_one_byte, 3 * length))
            .ToHandleChecked();
    CHECK_EQ(length, non_one_byte_str->length());
    DirectHandle<String> one_byte_str =
        factory->NewStringFromUtf8(base::Vector<const char>(one_byte, length))
            .ToHandleChecked();
    CHECK_EQ(length, one_byte_str->length());
    DeleteArray(non_one_byte);
    DeleteArray(one_byte);
  }
}

static int ObjectsFoundInHeap(Heap* heap, Handle<Object> objs[], int size) {
  // Count the number of objects found in the heap.
  int found_count = 0;
  HeapObjectIterator iterator(heap);
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    for (int i = 0; i < size; i++) {
      // V8_EXTERNAL_CODE_SPACE specific: we might be comparing
      // InstructionStream object with non-InstructionStream object here and it
      // might produce false positives because operator== for tagged values
      // compares only lower 32 bits when pointer compression is enabled.
      if ((*objs[i]).ptr() == obj.ptr()) {
        found_count++;
      }
    }
  }
  return found_count;
}

TEST(Iteration) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  v8::HandleScope scope(CcTest::isolate());

  // Array of objects to scan heap for.
  const int objs_count = 6;
  Handle<Object> objs[objs_count];
  int next_objs_index = 0;

  // Allocate a JS array to OLD_SPACE and NEW_SPACE
  objs[next_objs_index++] = factory->NewJSArray(10);
  objs[next_objs_index++] =
      factory->NewJSArray(10, HOLEY_ELEMENTS, AllocationType::kOld);

  // Allocate a small string to OLD_DATA_SPACE and NEW_SPACE
  objs[next_objs_index++] = factory->NewStringFromStaticChars("abcdefghij");
  objs[next_objs_index++] =
      factory->NewStringFromStaticChars("abcdefghij", AllocationType::kOld);

  // Allocate a large string (for large object space).
  int large_size = kMaxRegularHeapObjectSize + 1;
  char* str = new char[large_size];
  for (int i = 0; i < large_size - 1; ++i) str[i] = 'a';
  str[large_size - 1] = '\0';
  objs[next_objs_index++] =
      factory->NewStringFromAsciiChecked(str, AllocationType::kOld);
  delete[] str;

  // Add a Map object to look for.
  objs[next_objs_index++] =
      Handle<Map>(Cast<HeapObject>(*objs[0])->map(), isolate);

  CHECK_EQ(objs_count, next_objs_index);
  CHECK_EQ(objs_count, ObjectsFoundInHeap(CcTest::heap(), objs, objs_count));
}

TEST(TestBytecodeFlushing) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  v8_flags.turbofan = false;
  v8_flags.always_turbofan = false;
  i::v8_flags.optimize_for_size = false;
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
#ifdef V8_ENABLE_SPARKPLUG
  v8_flags.always_sparkplug = false;
#endif  // V8_ENABLE_SPARKPLUG
  i::v8_flags.flush_bytecode = true;
  i::v8_flags.allow_natives_syntax = true;

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  Isolate* i_isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = i_isolate->factory();

  {
    v8::HandleScope scope(isolate);
    v8::Context::New(isolate)->Enter();
    const char* source =
        "function foo() {"
        "  var x = 42;"
        "  var y = 42;"
        "  var z = x + y;"
        "};"
        "foo()";
    IndirectHandle<String> foo_name = factory->InternalizeUtf8String("foo");

    // This compile will add the code to the compilation cache.
    {
      v8::HandleScope new_scope(isolate);
      CompileRun(source);
    }

    // Check function is compiled.
    IndirectHandle<Object> func_value =
        Object::GetProperty(i_isolate, i_isolate->global_object(), foo_name)
            .ToHandleChecked();
    CHECK(IsJSFunction(*func_value));
    IndirectHandle<JSFunction> function = Cast<JSFunction>(func_value);
    CHECK(function->shared()->is_compiled());

    // The code will survive at least two GCs.
    {
      // In this test, we need to invoke GC without stack, otherwise some
      // objects may not be reclaimed because of conservative stack scanning.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
      heap::InvokeMajorGC(heap);
    }
    CHECK(function->shared()->is_compiled());

    i::SharedFunctionInfo::EnsureOldForTesting(function->shared());
    {
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    // foo should no longer be in the compilation cache
    CHECK(!function->shared()->is_compiled());
    CHECK(!function->is_compiled(i_isolate));
    // Call foo to get it recompiled.
    CompileRun("foo()");
    CHECK(function->shared()->is_compiled());
    CHECK(function->is_compiled(i_isolate));
  }
}

static void TestMultiReferencedBytecodeFlushing(bool sparkplug_compile) {
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  v8_flags.turbofan = false;
  v8_flags.always_turbofan = false;
  i::v8_flags.optimize_for_size = false;
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
#ifdef V8_ENABLE_SPARKPLUG
  v8_flags.always_sparkplug = false;
  v8_flags.flush_baseline_code = true;
#else
  if (sparkplug_compile) return;
#endif  // V8_ENABLE_SPARKPLUG
  i::v8_flags.flush_bytecode = true;
  i::v8_flags.allow_natives_syntax = true;

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  Isolate* i_isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = i_isolate->factory();

  {
    v8::HandleScope scope(isolate);
    v8::Context::New(isolate)->Enter();
    const char* source =
        "function foo() {"
        "  var x = 42;"
        "  var y = 42;"
        "  var z = x + y;"
        "};"
        "foo()";
    IndirectHandle<String> foo_name = factory->InternalizeUtf8String("foo");

    // This compile will add the code to the compilation cache.
    {
      v8::HandleScope new_scope(isolate);
      CompileRun(source);
    }

    // Check function is compiled.
    IndirectHandle<Object> func_value =
        Object::GetProperty(i_isolate, i_isolate->global_object(), foo_name)
            .ToHandleChecked();
    CHECK(IsJSFunction(*func_value));
    IndirectHandle<JSFunction> function = Cast<JSFunction>(func_value);
    IndirectHandle<SharedFunctionInfo> shared(function->shared(), i_isolate);
    CHECK(shared->is_compiled());

    // Make a copy of the SharedFunctionInfo which points to the same bytecode.
    IndirectHandle<SharedFunctionInfo> copy =
        i_isolate->factory()->CloneSharedFunctionInfo(shared);

    if (sparkplug_compile) {
      v8::HandleScope baseline_compilation_scope(isolate);
      IsCompiledScope is_compiled_scope = copy->is_compiled_scope(i_isolate);
      Compiler::CompileSharedWithBaseline(
          i_isolate, copy, Compiler::CLEAR_EXCEPTION, &is_compiled_scope);
    }

    i::SharedFunctionInfo::EnsureOldForTesting(*shared);
    {
      // We need to invoke GC without stack, otherwise some objects may not be
      // reclaimed because of conservative stack scanning.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    // shared SFI is marked old but BytecodeArray is kept alive by copy.
    CHECK(shared->is_compiled());
    CHECK(copy->is_compiled());
    CHECK(function->is_compiled(i_isolate));

    // The feedback metadata for both SharedFunctionInfo instances should have
    // been reset.
    CHECK(shared->HasFeedbackMetadata());
    CHECK(copy->HasFeedbackMetadata());
  }
}

TEST(TestMultiReferencedBytecodeFlushing) {
  TestMultiReferencedBytecodeFlushing(/*sparkplug_compile=*/false);
}

TEST(TestMultiReferencedBytecodeFlushingWithSparkplug) {
  TestMultiReferencedBytecodeFlushing(/*sparkplug_compile=*/true);
}

HEAP_TEST(Regress10560) {
  i::v8_flags.flush_bytecode = true;
  i::v8_flags.allow_natives_syntax = true;
  // Disable flags that allocate a feedback vector eagerly.
#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
  i::v8_flags.turbofan = false;
  i::v8_flags.always_turbofan = false;
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
#ifdef V8_ENABLE_SPARKPLUG
  v8_flags.always_sparkplug = false;
#endif  // V8_ENABLE_SPARKPLUG
  i::v8_flags.lazy_feedback_allocation = true;

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  Isolate* i_isolate = CcTest::i_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();

  {
    v8::HandleScope scope(isolate);
    const char* source =
        "function foo() {"
        "  var x = 42;"
        "  var y = 42;"
        "  var z = x + y;"
        "};"
        "foo()";
    Handle<String> foo_name = factory->InternalizeUtf8String("foo");
    CompileRun(source);

    // Check function is compiled.
    Handle<Object> func_value =
        Object::GetProperty(i_isolate, i_isolate->global_object(), foo_name)
            .ToHandleChecked();
    CHECK(IsJSFunction(*func_value));
    DirectHandle<JSFunction> function = Cast<JSFunction>(func_value);
    CHECK(function->shared()->is_compiled());
    CHECK(!function->has_feedback_vector());

    // Pre-age bytecode so it will be flushed on next run.
    CHECK(function->shared()->HasBytecodeArray());
    SharedFunctionInfo::EnsureOldForTesting(function->shared());

    heap::SimulateFullSpace(heap->old_space());

    // Just check bytecode isn't flushed still
    CHECK(function->shared()->is_compiled());

    heap->set_force_gc_on_next_allocation();

    // Allocate feedback vector.
    IsCompiledScope is_compiled_scope(
        function->shared()->is_compiled_scope(i_isolate));
    JSFunction::EnsureFeedbackVector(i_isolate, function, &is_compiled_scope);

    CHECK(function->has_feedback_vector());
    CHECK(function->shared()->is_compiled());
    CHECK(function->is_compiled(i_isolate));
  }
}

UNINITIALIZED_TEST(Regress10843) {
  v8_flags.max_semi_space_size = 2;
  v8_flags.min_semi_space_size = 2;
  v8_flags.max_old_space_size = 8;
  v8_flags.compact_on_every_full_gc = true;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();
  bool callback_was_invoked = false;

  heap->AddNearHeapLimitCallback(
      [](void* data, size_t current_heap_limit,
         size_t initial_heap_limit) -> size_t {
        *reinterpret_cast<bool*>(data) = true;
        return current_heap_limit * 2;
      },
      &callback_was_invoked);

  {
    v8::Isolate::Scope isolate_scope(isolate);
    PtrComprCageAccessScope ptr_compr_cage_access_scope(i_isolate);
    HandleScope scope(i_isolate);
    std::vector<Handle<FixedArray>> arrays;
    for (int i = 0; i < 140; i++) {
      arrays.push_back(factory->NewFixedArray(10000));
    }
    heap::InvokeMajorGC(heap);
    heap::InvokeMajorGC(heap);
    for (int i = 0; i < 40; i++) {
      arrays.push_back(factory->NewFixedArray(10000));
    }
    heap::InvokeMajorGC(heap);
    for (int i = 0; i < 100; i++) {
      arrays.push_back(factory->NewFixedArray(10000));
    }
    heap::InvokeMajorGC(heap);
    CHECK(callback_was_invoked);
  }
  isolate->Dispose();
}

size_t near_heap_limit_invocation_count = 0;
size_t InvokeGCNearHeapLimitCallback(void* data, size_t current_heap_limit,
                                     size_t initial_heap_limit) {
  near_heap_limit_invocation_count++;
  if (near_heap_limit_invocation_count > 1) {
    // We are already in a GC triggered in this callback, raise the limit
    // to avoid an OOM.
    return current_heap_limit * 5;
  }

  DCHECK_EQ(near_heap_limit_invocation_count, 1);
  // Operations that may cause GC (e.g. taking heap snapshots) in the
  // near heap limit callback should not hit the AllowGarbageCollection
  // assertion.
  static_cast<v8::Isolate*>(data)->GetHeapProfiler()->TakeHeapSnapshot();
  return current_heap_limit * 5;
}

UNINITIALIZED_TEST(Regress12777) {
  v8::Isolate::CreateParams create_params;
  create_params.constraints.set_max_old_generation_size_in_bytes(10 * i::MB);
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);

  isolate->AddNearHeapLimitCallback(InvokeGCNearHeapLimitCallback, isolate);

  {
    v8::Isolate::Scope isolate_scope(isolate);

    Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
    // Allocate data to trigger the NearHeapLimitCallback.
    HandleScope scope(i_isolate);
    int length = 2 * i::MB / i::kTaggedSize;
    std::vector<Handle<FixedArray>> arrays;
    for (int i = 0; i < 5; i++) {
      arrays.push_back(i_isolate->factory()->NewFixedArray(length));
    }
    heap::InvokeMajorGC(i_isolate->heap());
    for (int i = 0; i < 5; i++) {
      arrays.push_back(i_isolate->factory()->NewFixedArray(length));
    }
    heap::InvokeMajorGC(i_isolate->heap());
    for (int i = 0; i < 5; i++) {
      arrays.push_back(i_isolate->factory()->NewFixedArray(length));
    }

    // Normally, taking a heap snapshot in the near heap limit would result in
    // a full GC, then the overhead of the promotions would cause another
    // invocation of the heap limit callback and it can raise the limit in
    // the second call to avoid an OOM, so we test that the callback can
    // indeed raise the limit this way in this case. When there is only one
    // generation, however, there would not be the overhead of promotions so the
    // callback may not be triggered again during the generation of the heap
    // snapshot. In that case we only need to check that the callback is called
    // and it can perform GC-triggering operations jsut fine there.
    size_t minimum_callback_invocation_count =
        v8_flags.single_generation ? 1 : 2;
    CHECK_GE(near_heap_limit_invocation_count,
             minimum_callback_invocation_count);
  }

  isolate->GetHeapProfiler()->DeleteAllHeapSnapshots();
  isolate->Dispose();
}

#if !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)
TEST(TestOptimizeAfterBytecodeFlushingCandidate) {
  if (v8_flags.single_generation) return;
  v8_flags.turbofan = true;
  v8_flags.always_turbofan = false;
#ifdef V8_ENABLE_SPARKPLUG
  v8_flags.always_sparkplug = false;
#endif  // V8_ENABLE_SPARKPLUG
  i::v8_flags.optimize_for_size = false;
  i::v8_flags.incremental_marking = true;
  i::v8_flags.flush_bytecode = true;
  i::v8_flags.allow_natives_syntax = true;
  ManualGCScope manual_gc_scope;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = isolate->factory();

  v8::HandleScope outer_scope(CcTest::isolate());
  const char* source =
      "function foo() {"
      "  var x = 42;"
      "  var y = 42;"
      "  var z = x + y;"
      "};"
      "foo()";
  IndirectHandle<String> foo_name = factory->InternalizeUtf8String("foo");

  // This compile will add the code to the compilation cache.
  {
    v8::HandleScope scope(CcTest::isolate());
    CompileRun(source);
  }

  // Check function is compiled.
  IndirectHandle<Object> func_value =
      Object::GetProperty(isolate, isolate->global_object(), foo_name)
          .ToHandleChecked();
  CHECK(IsJSFunction(*func_value));
  IndirectHandle<JSFunction> function = Cast<JSFunction>(func_value);
  CHECK(function->shared()->is_compiled());

  // The code will survive at least two GCs.
  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(function->shared()->is_compiled());

  i::SharedFunctionInfo::EnsureOldForTesting(function->shared());
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  CHECK(!function->shared()->is_compiled());
  CHECK(!function->is_compiled(isolate));

  // This compile will compile the function again.
  {
    v8::HandleScope scope(CcTest::isolate());
    CompileRun("foo();");
  }

  SharedFunctionInfo::EnsureOldForTesting(function->shared());
  heap::SimulateIncrementalMarking(CcTest::heap());

  // Force optimization while incremental marking is active and while
  // the function is enqueued as a candidate.
  {
    v8::HandleScope scope(CcTest::isolate());
    CompileRun(
        "%PrepareFunctionForOptimization(foo);"
        "%OptimizeFunctionOnNextCall(foo); foo();");
  }

  // Simulate one final GC and make sure the candidate wasn't flushed.
  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  CHECK(function->shared()->is_compiled());
  CHECK(function->is_compiled(isolate));
}
#endif  // !defined(V8_LITE_MODE) && defined(V8_ENABLE_TURBOFAN)

TEST(TestUseOfIncrementalBarrierOnCompileLazy) {
  if (!v8_flags.incremental_marking) return;
  // Turn off always_turbofan because it interferes with running the built-in
  // for the last call to g().
  v8_flags.always_turbofan = false;
  v8_flags.allow_natives_syntax = true;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  Heap* heap = isolate->heap();
  v8::HandleScope scope(CcTest::isolate());

  CompileRun(
      "function make_closure(x) {"
      "  return function() { return x + 3 };"
      "}"
      "var f = make_closure(5);"
      "%PrepareFunctionForOptimization(f); f();"
      "var g = make_closure(5);");

  // Check f is compiled.
  Handle<String> f_name = factory->InternalizeUtf8String("f");
  Handle<Object> f_value =
      Object::GetProperty(isolate, isolate->global_object(), f_name)
          .ToHandleChecked();
  DirectHandle<JSFunction> f_function = Cast<JSFunction>(f_value);
  CHECK(f_function->is_compiled(isolate));

  // Check g is not compiled.
  Handle<String> g_name = factory->InternalizeUtf8String("g");
  Handle<Object> g_value =
      Object::GetProperty(isolate, isolate->global_object(), g_name)
          .ToHandleChecked();
  DirectHandle<JSFunction> g_function = Cast<JSFunction>(g_value);
  CHECK(!g_function->is_compiled(isolate));

  heap::SimulateIncrementalMarking(heap);
  CompileRun("%OptimizeFunctionOnNextCall(f); f();");

  // g should now have available an optimized function, unmarked by gc. The
  // CompileLazy built-in will discover it and install it in the closure, and
  // the incremental write barrier should be used.
  CompileRun("g();");
  CHECK(g_function->is_compiled(isolate));
}

void CompilationCacheCachingBehavior(bool retain_script) {
  // If we do not have the compilation cache turned off, this test is invalid.
  if (!v8_flags.compilation_cache) {
    return;
  }
  if (!v8_flags.flush_bytecode ||
      (v8_flags.always_sparkplug && !v8_flags.flush_baseline_code)) {
    return;
  }
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();
  Factory* factory = isolate->factory();
  CompilationCache* compilation_cache = isolate->compilation_cache();
  LanguageMode language_mode = LanguageMode::kSloppy;

  v8::HandleScope outer_scope(CcTest::isolate());
  const char* raw_source = retain_script ? "function foo() {"
                                           "  var x = 42;"
                                           "  var y = 42;"
                                           "  var z = x + y;"
                                           "};"
                                           "foo();"
                                         : "(function foo() {"
                                           "  var x = 42;"
                                           "  var y = 42;"
                                           "  var z = x + y;"
                                           "})();";
  IndirectHandle<String> source = factory->InternalizeUtf8String(raw_source);

  {
    v8::HandleScope scope(CcTest::isolate());
    CompileRun(raw_source);
  }

  // The script should be in the cache now.
  {
    v8::HandleScope scope(CcTest::isolate());
    ScriptDetails script_details(Handle<Object>(),
                                 v8::ScriptOriginOptions(true, false));
    auto lookup_result =
        compilation_cache->LookupScript(source, script_details, language_mode);
    CHECK(!lookup_result.toplevel_sfi().is_null());
  }

  // Check that the code cache entry survives at least one GC.
  {
    // In this test, we need to invoke GC without stack, otherwise some objects
    // may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }
  {
    v8::HandleScope scope(CcTest::isolate());
    ScriptDetails script_details(Handle<Object>(),
                                 v8::ScriptOriginOptions(true, false));
    auto lookup_result =
        compilation_cache->LookupScript(source, script_details, language_mode);
    CHECK(!lookup_result.toplevel_sfi().is_null());

    // Progress code age until it's old and ready for GC.
    DirectHandle<SharedFunctionInfo> shared =
        lookup_result.toplevel_sfi().ToHandleChecked();
    CHECK(shared->HasBytecodeArray());
    SharedFunctionInfo::EnsureOldForTesting(*shared);
  }

  {
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    // The first GC flushes the BytecodeArray from the SFI.
    heap::InvokeMajorGC(heap);
    // The second GC removes the SFI from the compilation cache.
    heap::InvokeMajorGC(heap);
  }

  {
    v8::HandleScope scope(CcTest::isolate());
    // Ensure code aging cleared the entry from the cache.
    ScriptDetails script_details(Handle<Object>(),
                                 v8::ScriptOriginOptions(true, false));
    auto lookup_result =
        compilation_cache->LookupScript(source, script_details, language_mode);
    CHECK(lookup_result.toplevel_sfi().is_null());
    CHECK_EQ(retain_script, !lookup_result.script().is_null());
  }
}

TEST(CompilationCacheCachingBehaviorDiscardScript) {
  CompilationCacheCachingBehavior(false);
}

TEST(CompilationCacheCachingBehaviorRetainScript) {
  CompilationCacheCachingBehavior(true);
}

namespace {

template <typename T>
Handle<SharedFunctionInfo> GetSharedFunctionInfo(
    v8::Local<T> function_or_script) {
  DirectHandle<JSFunction> i_function =
      Cast<JSFunction>(v8::Utils::OpenDirectHandle(*function_or_script));
  return handle(i_function->shared(), CcTest::i_isolate());
}

template <typename T>
void AgeBytecode(v8::Local<T> function_or_script) {
  DirectHandle<SharedFunctionInfo> shared =
      GetSharedFunctionInfo(function_or_script);
  CHECK(shared->HasBytecodeArray());
  SharedFunctionInfo::EnsureOldForTesting(*shared);
}

void CompilationCacheRegeneration(bool retain_root_sfi, bool flush_root_sfi,
                                  bool flush_eager_sfi) {
  // If the compilation cache is turned off, this test is invalid.
  if (!v8_flags.compilation_cache) {
    return;
  }

  // Skip test if code flushing was disabled.
  if (!v8_flags.flush_bytecode ||
      (v8_flags.always_sparkplug && !v8_flags.flush_baseline_code)) {
    return;
  }

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = CcTest::heap();

  const char* source =
      "({"
      "  lazyFunction: function () {"
      "    var x = 42;"
      "    var y = 42;"
      "    var z = x + y;"
      "  },"
      "  eagerFunction: (function () {"
      "    var x = 43;"
      "    var y = 43;"
      "    var z = x + y;"
      "  })"
      "})";

  v8::Global<v8::Script> outer_function;
  v8::Global<v8::Function> lazy_function;
  v8::Global<v8::Function> eager_function;

  {
    v8::HandleScope scope(CcTest::isolate());
    v8::Local<v8::Context> context =
        v8::Isolate::GetCurrent()->GetCurrentContext();
    v8::Local<v8::Script> script = v8_compile(v8_str(source));
    outer_function.Reset(CcTest::isolate(), script);

    // Even though the script has not executed, it should already be parsed.
    DirectHandle<SharedFunctionInfo> script_sfi = GetSharedFunctionInfo(script);
    CHECK(script_sfi->is_compiled());

    v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();

    // Now that the script has run, we can get references to the inner
    // functions, and verify that the eager parsing heuristics are behaving as
    // expected.
    v8::Local<v8::Object> result_obj =
        result->ToObject(context).ToLocalChecked();
    v8::Local<v8::Value> lazy_function_value =
        result_obj->GetRealNamedProperty(context, v8_str("lazyFunction"))
            .ToLocalChecked();
    CHECK(lazy_function_value->IsFunction());
    CHECK(!GetSharedFunctionInfo(lazy_function_value)->is_compiled());
    lazy_function.Reset(CcTest::isolate(),
                        lazy_function_value.As<v8::Function>());
    v8::Local<v8::Value> eager_function_value =
        result_obj->GetRealNamedProperty(context, v8_str("eagerFunction"))
            .ToLocalChecked();
    CHECK(eager_function_value->IsFunction());
    eager_function.Reset(CcTest::isolate(),
                         eager_function_value.As<v8::Function>());
    CHECK(GetSharedFunctionInfo(eager_function_value)->is_compiled());
  }

  {
    v8::HandleScope scope(CcTest::isolate());

    // Progress code age until it's old and ready for GC.
    if (flush_root_sfi) {
      v8::Local<v8::Script> outer_function_value =
          outer_function.Get(CcTest::isolate());
      AgeBytecode(outer_function_value);
    }
    if (flush_eager_sfi) {
      v8::Local<v8::Function> eager_function_value =
          eager_function.Get(CcTest::isolate());
      AgeBytecode(eager_function_value);
    }
    if (!retain_root_sfi) {
      outer_function.Reset();
    }
  }

  {
    // In these tests, we need to invoke GC without stack, otherwise some
    // objects may not be reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

    if (v8_flags.stress_incremental_marking) {
      // This GC finishes incremental marking if it is already running. If
      // incremental marking was already running we would not flush the code
      // right away.
      heap::InvokeMajorGC(heap);
    }

    // The first GC performs code flushing.
    heap::InvokeMajorGC(heap);
    // The second GC clears the entry from the compilation cache.
    heap::InvokeMajorGC(heap);
  }

  // The root SharedFunctionInfo can be retained either by a Global in this
  // function or by the compilation cache.
  bool root_sfi_should_still_exist = retain_root_sfi || !flush_root_sfi;

  {
    v8::HandleScope scope(CcTest::is
"""


```