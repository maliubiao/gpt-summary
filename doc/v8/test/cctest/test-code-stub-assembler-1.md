Response: The user wants me to summarize the functionality of the C++ code provided in the text. This is the second part of a three-part code snippet. I need to focus on the code within this section. The code appears to be testing the `CodeStubAssembler` (CSA) in V8. It creates various test functions using the CSA and then executes them to verify their behavior. Many of these tests relate to specific CSA functionalities, such as object allocation, array manipulation, dictionary creation, string operations, and interaction with JavaScript built-ins. If a test is directly related to a JavaScript feature, I should illustrate it with a JavaScript example.

Here's a breakdown of the code's functionality:

1. **Object Allocation:**  Tests the allocation of JSObjects using `AllocateJSObjectFromMap`. It checks if the allocated object has the correct map, properties, and elements, and handles specific cases for JSArrays, ensuring the length field is set.
2. **Allocation Folding:** Tests the optimized allocation of `FixedArray` and `ByteArray` using CSA. It verifies the alignment and contiguity of the allocated memory blocks.
3. **Dictionary Allocation:** Tests the allocation of different dictionary types (`NameDictionary`, `OrderedNameDictionary`, `OrderedHashSet`, `OrderedHashMap`) using CSA. It compares the memory layout of CSA-allocated dictionaries with those created using standard allocation methods.
4. **`PopAndReturn` Restrictions:** Verifies that `PopAndReturn` is correctly restricted in built-ins with declared stack parameters.
5. **Stack Pointer Checks:** Tests the integrity of the stack pointer when calling functions created with CSA, ensuring it remains consistent before and after the calls.
6. **`PopAndReturn` Usage:** Tests the `PopAndReturn` functionality in CSA, both with constant and variable return values. It demonstrates how to pop arguments from the stack and return a value.
7. **String Copying:** Tests various string copying operations using CSA, including copying between one-byte and two-byte strings, and handling non-zero starting offsets.
8. **Arguments Object:** Tests the functionality of the `CodeStubArguments` object in CSA, which provides access to the arguments passed to a function. It checks if the arguments are correctly accessed and demonstrates how to iterate through them using `ForEach`.
9. **Debug Mode Detection:** Tests the `IsDebugActive` CSA function to check if the debugger is active.
10. **Short Builtin Calls Threshold:** Checks if the `kShortBuiltinCallsOldSpaceSizeThreshold` constant is correctly related to the available physical memory.
11. **Builtin Calls:** Tests calling and tail-calling JavaScript built-in functions using CSA (`CallBuiltin`, `TailCallBuiltin`).
12. **JSArray Appending:** Tests the `BuildAppendJSArray` CSA function, which appends elements to a JSArray, handling different element kinds and array growth.
13. **Promise Hook Detection:** Tests the `IsPromiseHookEnabledOrHasAsyncEventDelegate` CSA function to check if a promise hook is active.
14. **Promise Creation:** Tests the creation of `JSPromise` objects using CSA, both with default and rejected states.
15. **Symbol Type Checks:** Tests CSA functions for checking if an object is a Symbol (`IsSymbol`) or a Private Symbol (`IsPrivateSymbol`).
16. **Promise Handler Check:** Tests the `PromiseHasHandler` CSA function.
17. **Promise Context Creation:** Tests the creation of contexts related to promises, including resolving functions contexts and capabilities executor contexts.
18. **Promise Capabilities:** Tests the creation of `PromiseCapability` objects using CSA.
19. **Elements Capacity Calculation:** Tests the CSA functions for calculating the new capacity of an array's elements when it needs to grow (`CalculateNewElementsCapacity`).
20. **Root Function Allocation:** Tests the allocation of root functions with associated contexts using CSA (`AllocateRootFunctionWithContext`).
21. **Direct Memory Access:** Tests CSA's ability to load data directly from memory using raw pointers (`LoadBufferData`). It covers loading 8-bit and 16-bit values and performing bitwise operations.
22. **Loading JSArray Elements Map:** Tests the `LoadJSArrayElementsMap` CSA function to retrieve the map for a specific elements kind.
23. **Whitespace/Line Terminator Check:** Tests the `IsWhiteSpaceOrLineTerminator` CSA function.
24. **Number Relational Comparison:** Tests the `BranchIfNumberRelationalComparison` CSA function.
25. **Array Index Check:** Tests the `IsNumberArrayIndex` CSA function.
26. **Number Min/Max:** Tests the `NumberMin` and `NumberMax` CSA functions.
这个C++代码文件是V8 JavaScript引擎测试套件的一部分，专门用于测试 **CodeStubAssembler (CSA)** 的功能。CSA 是一个用于生成机器码的低级 API，它允许开发者以一种更接近汇编的方式编写高性能的代码，这些代码可以直接嵌入到 V8 的运行时中。

这个文件的第 2 部分主要侧重于测试 CSA 提供的各种 **内存分配、对象操作、字符串操作、控制流、与 JavaScript 内置函数的交互以及直接内存访问** 等功能。

以下是对代码功能的归纳：

*   **对象分配和初始化:** 测试了使用 CSA 创建和初始化 JavaScript 对象 (`JSObject`)，包括设置其 `Map`、属性 (`properties`) 和元素 (`elements`)。特别是对于 `JSArray`，还验证了 `length` 属性的设置。
*   **内存分配策略:** 测试了 CSA 中内存分配的优化策略，例如“allocation folding”，它尝试将多个小的内存分配合并成一个大的分配，以提高效率，并验证了分配的内存对齐。
*   **字典数据结构:** 测试了使用 CSA 分配和操作各种字典数据结构，如 `NameDictionary`、`OrderedNameDictionary`、`OrderedHashSet` 和 `OrderedHashMap`，并验证了其内存布局和正确性。
*   **内置函数调用:** 测试了使用 CSA 调用 JavaScript 内置函数的能力，例如 `AllocateJSObjectFromMap` 和 `GetProperty`，并验证了调用结果的正确性。
*   **尾调用优化:** 测试了使用 CSA 进行尾调用优化的能力 (`TailCallBuiltin`)。
*   **函数参数处理:** 测试了 CSA 如何处理函数参数，包括堆栈参数，并验证了 `PopAndReturn` 操作在不同上下文中的限制。
*   **字符串操作:** 测试了 CSA 提供的字符串复制功能 (`CopyStringCharacters`)，包括不同编码格式（如 OneByte 和 TwoByte）之间的复制，以及指定起始位置的复制。
*   **Arguments 对象模拟:** 测试了 CSA 中 `CodeStubArguments` 的功能，它可以用来访问传递给函数的参数，类似于 JavaScript 中的 `arguments` 对象。
*   **控制流指令:** 测试了 CSA 中的控制流指令，例如 `Branch`、`GotoIf`、`GotoIfNot`，以及循环结构 (`BuildFastLoop`)。
*   **调试支持:** 测试了 CSA 中用于检测调试器是否激活的功能 (`IsDebugActive`)。
*   **Promise 相关操作:** 测试了 CSA 中用于创建和操作 Promise 的功能，例如 `NewJSPromise`、`CreatePromiseResolvingFunctionsContext`、`CreatePromiseResolvingFunctions` 和 `CreatePromiseCapability`。
*   **直接内存访问:** 测试了 CSA 中直接读取内存数据的功能 (`LoadBufferData`)，这在处理外部数据或进行底层操作时非常有用。
*   **类型检查:** 测试了 CSA 中提供的类型检查功能，例如 `IsSymbol` 和 `IsPrivateSymbol`。
*   **数组元素容量计算:** 测试了 CSA 中计算新数组元素容量的功能 (`CalculateNewElementsCapacity`)。
*   **加载数组元素 Map:** 测试了 CSA 中加载特定元素类型数组的 Map 的功能 (`LoadJSArrayElementsMap`)。
*   **字符类型判断:** 测试了 CSA 中判断字符是否为空格或行终止符的功能 (`IsWhiteSpaceOrLineTerminator`)。
*   **数值比较:** 测试了 CSA 中进行数值比较的功能 (`BranchIfNumberRelationalComparison`)。
*   **数组索引判断:** 测试了 CSA 中判断一个数值是否为有效的数组索引的功能 (`IsNumberArrayIndex`)。
*   **数值 Min/Max 操作:** 测试了 CSA 中计算两个数值的最小值和最大值的功能 (`NumberMin` 和 `NumberMax`)。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个测试文件中的很多功能都直接对应着 JavaScript 的底层实现。CSA 代码最终会被编译成机器码，用于执行 JavaScript 代码。

1. **对象分配 (`AllocateJSObjectFromMap`):**  当你在 JavaScript 中创建一个对象时，V8 内部就会进行对象分配。

    ```javascript
    const obj = {}; // 对应 CSA 中的对象分配操作
    const arr = []; // 对应 CSA 中 JSArray 的分配操作，可能涉及到长度的初始化
    ```

2. **字典数据结构 (`AllocateNameDictionary`, 等):** JavaScript 对象的属性存储在不同的数据结构中，对于大量属性或者非字符串属性，可能会使用字典。

    ```javascript
    const obj = {};
    obj.a = 1;
    obj.b = 2;
    // V8 内部可能使用字典来存储属性 'a' 和 'b'
    ```

3. **内置函数调用 (`CallBuiltin`, `TailCallBuiltin`):**  JavaScript 的内置函数（如 `Object.getPrototypeOf`、`Array.push` 等）在 V8 内部有高效的 C++ 实现，CSA 可以直接调用这些实现。

    ```javascript
    const proto = Object.getPrototypeOf({}); // 对应 CSA 中调用获取对象原型的内置函数
    const arr = [];
    arr.push(1); // 对应 CSA 中调用数组 push 操作的内置函数
    ```

4. **字符串操作 (`CopyStringCharacters`):**  JavaScript 中对字符串的各种操作，例如拼接、截取等，底层可能涉及到字符的复制。

    ```javascript
    const str1 = "abc";
    const str2 = "def";
    const combined = str1 + str2; // 底层可能使用类似 CSA 的字符串复制功能
    ```

5. **Arguments 对象:**  JavaScript 函数内部的 `arguments` 对象用于访问传递给函数的参数。

    ```javascript
    function foo(a, b) {
      console.log(arguments[0]); // 对应 CSA 中访问 arguments 的操作
      console.log(arguments.length);
    }
    foo(1, 2);
    ```

6. **Promise 操作:** JavaScript 的 Promise 用于处理异步操作。

    ```javascript
    const promise = new Promise((resolve, reject) => {
      // ... 异步操作
      if (/* 成功 */) {
        resolve(value); // 对应 CSA 中 Promise 的 resolve 操作
      } else {
        reject(reason); // 对应 CSA 中 Promise 的 reject 操作
      }
    });
    ```

7. **类型检查 (`IsSymbol`):** JavaScript 中可以使用 `typeof` 或 `instanceof` 进行类型检查。

    ```javascript
    const sym = Symbol();
    console.log(typeof sym === 'symbol'); // 对应 CSA 中的 IsSymbol 操作
    ```

总而言之，这个测试文件的目的是确保 V8 的 CSA 功能正常工作，并且生成的代码能够正确地实现 JavaScript 的各种语言特性和内置功能，从而保证 JavaScript 代码的正确执行和性能。

Prompt: 
```
这是目录为v8/test/cctest/test-code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
emblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  {
    auto map = m.Parameter<Map>(1);
    auto properties = m.Parameter<HeapObject>(2);
    auto elements = m.Parameter<FixedArray>(3);

    TNode<JSObject> result =
        m.AllocateJSObjectFromMap(map, properties, elements);

    CodeStubAssembler::Label done(&m);
    m.GotoIfNot(m.IsJSArrayMap(map), &done);

    // JS array verification requires the length field to be set.
    m.StoreObjectFieldNoWriteBarrier(result, JSArray::kLengthOffset,
                                     m.SmiConstant(0));
    m.Goto(&done);

    m.Bind(&done);
    m.Return(result);
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Map> maps[] = {
      handle(isolate->object_function()->initial_map(), isolate),
      handle(isolate->array_function()->initial_map(), isolate),
  };

  {
    Handle<FixedArray> empty_fixed_array = factory->empty_fixed_array();
    DirectHandle<PropertyArray> empty_property_array =
        factory->empty_property_array();
    for (size_t i = 0; i < arraysize(maps); i++) {
      Handle<Map> map = maps[i];
      DirectHandle<JSObject> result = Cast<JSObject>(
          ft.Call(map, empty_fixed_array, empty_fixed_array).ToHandleChecked());
      CHECK_EQ(result->map(), *map);
      CHECK_EQ(result->property_array(), *empty_property_array);
      CHECK_EQ(result->elements(), *empty_fixed_array);
      CHECK(result->HasFastProperties());
#ifdef VERIFY_HEAP
      HeapVerifier::VerifyHeap(isolate->heap());
#endif
    }
  }

  {
    // TODO(cbruni): handle in-object properties
    DirectHandle<JSObject> object = Cast<JSObject>(v8::Utils::OpenDirectHandle(
        *CompileRun("var object = {a:1,b:2, 1:1, 2:2}; object")));
    JSObject::NormalizeProperties(isolate, object, KEEP_INOBJECT_PROPERTIES, 0,
                                  "Normalize");
    Handle<HeapObject> properties =
        V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL
            ? Handle<HeapObject>(object->property_dictionary_swiss(), isolate)
            : handle(object->property_dictionary(), isolate);
    DirectHandle<JSObject> result =
        Cast<JSObject>(ft.Call(handle(object->map(), isolate), properties,
                               handle(object->elements(), isolate))
                           .ToHandleChecked());
    CHECK_EQ(result->map(), object->map());
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      CHECK_EQ(result->property_dictionary_swiss(),
               object->property_dictionary_swiss());
    } else {
      CHECK_EQ(result->property_dictionary(), object->property_dictionary());
    }
    CHECK(!result->HasFastProperties());
#ifdef VERIFY_HEAP
    HeapVerifier::VerifyHeap(isolate->heap());
#endif
  }
}

TEST(AllocationFoldingCSA) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  const int kNumArrays = 7;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams),
                                 CodeKind::FOR_TESTING);
  CodeStubAssembler m(asm_tester.state());

  {
    TNode<IntPtrT> length = m.SmiUntag(m.Parameter<Smi>(1));
    TNode<FixedArray> result = m.UncheckedCast<FixedArray>(m.AllocateFixedArray(
        PACKED_ELEMENTS, length, CodeStubAssembler::AllocationFlag::kNone));
    for (int i = 1; i <= kNumArrays; ++i) {
      int array_length = i * kTaggedSize;
      TNode<ByteArray> array =
          m.AllocateByteArray(m.UintPtrConstant(array_length));
      m.StoreFixedArrayElement(result, i - 1, array);
    }
    m.Return(result);
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  {
    auto fixed_array_length = Handle<Smi>(Smi::FromInt(kNumArrays), isolate);
    DirectHandle<FixedArray> result =
        Cast<FixedArray>(ft.Call(fixed_array_length).ToHandleChecked());
    CHECK_EQ(result->length(), kNumArrays);
    if (V8_COMPRESS_POINTERS_8GB_BOOL) {
      CHECK(IsAligned(result->address(), kObjectAlignment8GbHeap));
    } else {
      CHECK(IsAligned(result->address(), kTaggedSize));
    }
    Tagged<ByteArray> prev_array;
    for (int i = 1; i <= kNumArrays; ++i) {
      Tagged<ByteArray> current_array = Cast<ByteArray>(result->get(i - 1));
      if (V8_COMPRESS_POINTERS_8GB_BOOL) {
        CHECK(IsAligned(current_array.address(), kObjectAlignment8GbHeap));
      } else {
        CHECK(IsAligned(current_array.address(), kTaggedSize));
      }
      CHECK_EQ(current_array->length(), i * kTaggedSize);
      if (i != 1) {
        // TODO(v8:13070): Align prev_array.AllocatedSize() to the allocation
        // size.
        CHECK_EQ(prev_array.address() + prev_array->AllocatedSize(),
                 current_array.address());
      }
      prev_array = current_array;
    }
#ifdef VERIFY_HEAP
    HeapVerifier::VerifyHeap(isolate->heap());
#endif
  }
}

namespace {

template <typename Dictionary>
using CSAAllocator =
    std::function<TNode<Dictionary>(CodeStubAssembler&, TNode<IntPtrT>)> const&;

template <typename Dictionary>
using Allocator = std::function<Handle<Dictionary>(Isolate*, int)> const&;

// Tests that allocation code emitted by {csa_alloc} yields ordered hash tables
// identical to those produced by {alloc}.
template <typename Dictionary>
void TestDictionaryAllocation(CSAAllocator<Dictionary> csa_alloc,
                              Allocator<Dictionary> alloc, int max_capacity) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  {
    auto capacity = m.Parameter<Smi>(1);
    TNode<Dictionary> result = csa_alloc(m, m.SmiUntag(capacity));
    m.Return(result);
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  {
    for (int i = 0; i < max_capacity; i = i * 1.1 + 1) {
      DirectHandle<HeapObject> result = Cast<HeapObject>(
          ft.Call(handle(Smi::FromInt(i), isolate)).ToHandleChecked());
      Handle<Dictionary> dict = alloc(isolate, i);
      // Both dictionaries should be memory equal.
      int size = dict->Size();
      CHECK_EQ(0, memcmp(reinterpret_cast<void*>(dict->address()),
                         reinterpret_cast<void*>(result->address()), size));
    }
  }
}

}  // namespace

TEST(AllocateNameDictionary) {
  auto csa_alloc = [](CodeStubAssembler& m, TNode<IntPtrT> cap) {
    return m.AllocateNameDictionary(cap);
  };
  auto alloc = [](Isolate* isolate, int capacity) {
    return NameDictionary::New(isolate, capacity);
  };
  TestDictionaryAllocation<NameDictionary>(csa_alloc, alloc, 256);
}

TEST(AllocateOrderedNameDictionary) {
  auto csa_alloc = [](CodeStubAssembler& m, TNode<IntPtrT> cap) {
    return m.AllocateOrderedNameDictionary(cap);
  };
  auto alloc = [](Isolate* isolate, int capacity) {
    return OrderedNameDictionary::Allocate(isolate, capacity).ToHandleChecked();
  };
  TestDictionaryAllocation<OrderedNameDictionary>(csa_alloc, alloc, 256);
}

TEST(AllocateOrderedHashSet) {
  // ignoring capacitites, as the API cannot take them
  auto csa_alloc = [](CodeStubAssembler& m, TNode<IntPtrT> cap) {
    return m.AllocateOrderedHashSet();
  };
  auto alloc = [](Isolate* isolate, int capacity) {
    return OrderedHashSet::Allocate(isolate, OrderedHashSet::kInitialCapacity)
        .ToHandleChecked();
  };
  TestDictionaryAllocation<OrderedHashSet>(csa_alloc, alloc, 1);
}

TEST(AllocateOrderedHashMap) {
  // ignoring capacities, as the API cannot take them
  auto csa_alloc = [](CodeStubAssembler& m, TNode<IntPtrT> cap) {
    return m.AllocateOrderedHashMap();
  };
  auto alloc = [](Isolate* isolate, int capacity) {
    return OrderedHashMap::Allocate(isolate, OrderedHashMap::kInitialCapacity)
        .ToHandleChecked();
  };
  TestDictionaryAllocation<OrderedHashMap>(csa_alloc, alloc, 1);
}

TEST(PopAndReturnFromJSBuiltinWithStackParameters) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumStackParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumStackParams));
  {
    CodeStubAssembler m(asm_tester.state());
    m.PopAndReturn(m.SmiUntag(m.Parameter<Smi>(1)),
                   m.SmiConstant(Smi::FromInt(1234)));
  }

  // Attempt to generate code must trigger CHECK failure in RawMachineAssebler.
  // PopAndReturn is not allowed in builtins with JS linkage and declared stack
  // parameters.
  asm_tester.GenerateCode();
}

TEST(PopAndReturnFromTFCBuiltinWithStackParameters) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  // Setup CSA for creating TFC-style builtin with stack arguments.
  // For the testing purposes we need any interface descriptor that has at
  // least one argument passed on stack.
  using Descriptor = FlattenIntoArrayWithMapFnDescriptor;
  Descriptor descriptor;
  CHECK_LT(0, Descriptor::GetStackParameterCount());

  CodeAssemblerTester asm_tester(isolate, Descriptor());
  {
    CodeStubAssembler m(asm_tester.state());
    m.PopAndReturn(m.SmiUntag(m.Parameter<Smi>(0)),
                   m.SmiConstant(Smi::FromInt(1234)));
  }

  // Attempt to generate code must trigger CHECK failure in RawMachineAssebler.
  // PopAndReturn is not allowed in builtins with JS linkage and declared stack
  // parameters.
  asm_tester.GenerateCode();
}

namespace {

TNode<Object> MakeConstantNode(CodeStubAssembler& m, Handle<Object> value) {
  if (IsSmi(*value)) {
    return m.SmiConstant(Smi::ToInt(*value));
  }
  return m.HeapConstantNoHole(Cast<HeapObject>(value));
}

// Buids a CSA function that calls |target| function with given arguments
// |number_of_iterations| times and checks that the stack pointer values before
// the calls and after the calls are the same.
// Then this new function is called multiple times.
template <typename... Args>
void CallFunctionWithStackPointerChecks(Isolate* isolate,
                                        Handle<Object> expected_result,
                                        Handle<Object> target,
                                        Handle<Object> receiver, Args... args) {
  // Setup CSA for creating TFJ-style builtin.
  using Descriptor = JSTrampolineDescriptor;
  CodeAssemblerTester asm_tester(isolate, Descriptor());

  {
    CodeStubAssembler m(asm_tester.state());

    TNode<Context> context = m.Parameter<Context>(Descriptor::kContext);

#ifdef V8_CC_GNU
    // GetStackPointer is available only when V8_CC_GNU is defined.
    const TNode<ExternalReference> get_stack_ptr = m.ExternalConstant(
        ExternalReference::Create(reinterpret_cast<Address>(GetStackPointer)));

    // CSA doesn't have instructions for reading current stack pointer value,
    // so we use a C function that returns address of its local variable.
    // This is a good-enough approximation for the stack pointer.
    MachineType type_intptr = MachineType::IntPtr();
    TNode<WordT> stack_pointer0 =
        m.UncheckedCast<WordT>(m.CallCFunction(get_stack_ptr, type_intptr));
#endif

    // CSA::CallCFunction() aligns stack pointer before the call, so off-by one
    // errors will not be detected. In order to handle this we do the calls in a
    // loop in order to exaggerate the effect of potentially broken stack
    // pointer so that the GetStackPointer function will be able to notice it.
    m.BuildFastLoop<IntPtrT>(
        m.IntPtrConstant(0), m.IntPtrConstant(153),
        [&](TNode<IntPtrT> index) {
          TNode<Object> result = m.Call(context, MakeConstantNode(m, target),
                                        MakeConstantNode(m, receiver),
                                        MakeConstantNode(m, args)...);
          CSA_CHECK(
              &m, m.TaggedEqual(result, MakeConstantNode(m, expected_result)));
        },
        1, CodeStubAssembler::LoopUnrollingMode::kNo,
        CodeStubAssembler::IndexAdvanceMode::kPost);

#ifdef V8_CC_GNU
    TNode<WordT> stack_pointer1 =
        m.UncheckedCast<WordT>(m.CallCFunction(get_stack_ptr, type_intptr));
    CSA_CHECK(&m, m.WordEqual(stack_pointer0, stack_pointer1));
#endif
    m.Return(m.SmiConstant(42));
  }
  FunctionTester ft(asm_tester.GenerateCode(), 1);

  DirectHandle<Object> result;
  for (int test_count = 0; test_count < 100; ++test_count) {
    result = ft.Call().ToHandleChecked();
    CHECK_EQ(Smi::FromInt(42), *result);
  }
}

}  // namespace

TEST(PopAndReturnConstant) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  // Setup CSA for creating TFJ-style builtin.
  using Descriptor = JSTrampolineDescriptor;
  CodeAssemblerTester asm_tester(isolate, Descriptor());

  const int kFormalParams = 0;
  const int kActualParams = 4 + kJSArgcReceiverSlots;
  {
    CodeStubAssembler m(asm_tester.state());
    TNode<Int32T> argc =
        m.UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
    CSA_CHECK(&m, m.Word32Equal(argc, m.Int32Constant(kActualParams)));

    int pop_count = kActualParams;
    m.PopAndReturn(m.IntPtrConstant(pop_count), m.SmiConstant(1234));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kFormalParams);

  // Now call this function multiple time also checking that the stack pointer
  // didn't change after the calls.
  Handle<Object> receiver = isolate->factory()->undefined_value();
  Handle<Smi> expected_result(Smi::FromInt(1234), isolate);
  CallFunctionWithStackPointerChecks(isolate, expected_result, ft.function,
                                     receiver,
                                     // Pass kActualParams arguments.
                                     Handle<Smi>(Smi::FromInt(1), isolate),
                                     Handle<Smi>(Smi::FromInt(2), isolate),
                                     Handle<Smi>(Smi::FromInt(3), isolate),
                                     Handle<Smi>(Smi::FromInt(4), isolate));
}

TEST(PopAndReturnVariable) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  // Setup CSA for creating TFJ-style builtin.
  using Descriptor = JSTrampolineDescriptor;
  CodeAssemblerTester asm_tester(isolate, Descriptor());

  const int kFormalParams = 0;
  const int kActualParams = 4 + kJSArgcReceiverSlots;
  {
    CodeStubAssembler m(asm_tester.state());
    TNode<Int32T> argc =
        m.UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
    CSA_CHECK(&m, m.Word32Equal(argc, m.Int32Constant(kActualParams)));

    int pop_count = kActualParams;
    m.PopAndReturn(m.IntPtrConstant(pop_count), m.SmiConstant(1234));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kFormalParams);

  // Now call this function multiple time also checking that the stack pointer
  // didn't change after the calls.
  Handle<Object> receiver = isolate->factory()->undefined_value();
  Handle<Smi> expected_result(Smi::FromInt(1234), isolate);
  CallFunctionWithStackPointerChecks(isolate, expected_result, ft.function,
                                     receiver,
                                     // Pass kActualParams arguments.
                                     Handle<Smi>(Smi::FromInt(1), isolate),
                                     Handle<Smi>(Smi::FromInt(2), isolate),
                                     Handle<Smi>(Smi::FromInt(3), isolate),
                                     Handle<Smi>(Smi::FromInt(4), isolate));
}

TEST(OneToTwoByteStringCopy) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  StringBuiltinsAssembler m(asm_tester.state());

  m.CopyStringCharacters<String>(m.Parameter<String>(1), m.Parameter<String>(2),
                                 m.IntPtrConstant(0), m.IntPtrConstant(0),
                                 m.IntPtrConstant(5), String::ONE_BYTE_ENCODING,
                                 String::TWO_BYTE_ENCODING);
  m.Return(m.SmiConstant(Smi::FromInt(0)));

  Handle<String> string1 = isolate->factory()->InternalizeUtf8String("abcde");
  base::uc16 array[] = {1000, 1001, 1002, 1003, 1004};
  Handle<String> string2 = isolate->factory()
                               ->NewStringFromTwoByte(base::ArrayVector(array))
                               .ToHandleChecked();
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call(string1, string2);
  DisallowGarbageCollection no_gc;
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[0],
           Cast<SeqTwoByteString>(string2)->GetChars(no_gc)[0]);
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[1],
           Cast<SeqTwoByteString>(string2)->GetChars(no_gc)[1]);
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[2],
           Cast<SeqTwoByteString>(string2)->GetChars(no_gc)[2]);
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[3],
           Cast<SeqTwoByteString>(string2)->GetChars(no_gc)[3]);
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[4],
           Cast<SeqTwoByteString>(string2)->GetChars(no_gc)[4]);
}

TEST(OneToOneByteStringCopy) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  StringBuiltinsAssembler m(asm_tester.state());

  m.CopyStringCharacters<String>(m.Parameter<String>(1), m.Parameter<String>(2),
                                 m.IntPtrConstant(0), m.IntPtrConstant(0),
                                 m.IntPtrConstant(5), String::ONE_BYTE_ENCODING,
                                 String::ONE_BYTE_ENCODING);
  m.Return(m.SmiConstant(Smi::FromInt(0)));

  Handle<String> string1 = isolate->factory()->InternalizeUtf8String("abcde");
  uint8_t array[] = {100, 101, 102, 103, 104};
  Handle<String> string2 = isolate->factory()
                               ->NewStringFromOneByte(base::ArrayVector(array))
                               .ToHandleChecked();
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call(string1, string2);
  DisallowGarbageCollection no_gc;
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[0],
           Cast<SeqOneByteString>(string2)->GetChars(no_gc)[0]);
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[1],
           Cast<SeqOneByteString>(string2)->GetChars(no_gc)[1]);
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[2],
           Cast<SeqOneByteString>(string2)->GetChars(no_gc)[2]);
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[3],
           Cast<SeqOneByteString>(string2)->GetChars(no_gc)[3]);
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[4],
           Cast<SeqOneByteString>(string2)->GetChars(no_gc)[4]);
}

TEST(OneToOneByteStringCopyNonZeroStart) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  StringBuiltinsAssembler m(asm_tester.state());

  m.CopyStringCharacters<String>(m.Parameter<String>(1), m.Parameter<String>(2),
                                 m.IntPtrConstant(0), m.IntPtrConstant(3),
                                 m.IntPtrConstant(2), String::ONE_BYTE_ENCODING,
                                 String::ONE_BYTE_ENCODING);
  m.Return(m.SmiConstant(Smi::FromInt(0)));

  Handle<String> string1 = isolate->factory()->InternalizeUtf8String("abcde");
  uint8_t array[] = {100, 101, 102, 103, 104};
  Handle<String> string2 = isolate->factory()
                               ->NewStringFromOneByte(base::ArrayVector(array))
                               .ToHandleChecked();
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call(string1, string2);
  DisallowGarbageCollection no_gc;
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[0],
           Cast<SeqOneByteString>(string2)->GetChars(no_gc)[3]);
  CHECK_EQ(Cast<SeqOneByteString>(string1)->GetChars(no_gc)[1],
           Cast<SeqOneByteString>(string2)->GetChars(no_gc)[4]);
  CHECK_EQ(100, Cast<SeqOneByteString>(string2)->GetChars(no_gc)[0]);
  CHECK_EQ(101, Cast<SeqOneByteString>(string2)->GetChars(no_gc)[1]);
  CHECK_EQ(102, Cast<SeqOneByteString>(string2)->GetChars(no_gc)[2]);
}

TEST(TwoToTwoByteStringCopy) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  StringBuiltinsAssembler m(asm_tester.state());

  m.CopyStringCharacters<String>(m.Parameter<String>(1), m.Parameter<String>(2),
                                 m.IntPtrConstant(0), m.IntPtrConstant(0),
                                 m.IntPtrConstant(5), String::TWO_BYTE_ENCODING,
                                 String::TWO_BYTE_ENCODING);
  m.Return(m.SmiConstant(Smi::FromInt(0)));

  base::uc16 array1[] = {2000, 2001, 2002, 2003, 2004};
  Handle<String> string1 = isolate->factory()
                               ->NewStringFromTwoByte(base::ArrayVector(array1))
                               .ToHandleChecked();
  base::uc16 array2[] = {1000, 1001, 1002, 1003, 1004};
  Handle<String> string2 = isolate->factory()
                               ->NewStringFromTwoByte(base::ArrayVector(array2))
                               .ToHandleChecked();
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  ft.Call(string1, string2);
  DisallowGarbageCollection no_gc;
  CHECK_EQ(Cast<SeqTwoByteString>(string1)->GetChars(no_gc)[0],
           Cast<SeqTwoByteString>(string2)->GetChars(no_gc)[0]);
  CHECK_EQ(Cast<SeqTwoByteString>(string1)->GetChars(no_gc)[1],
           Cast<SeqTwoByteString>(string2)->GetChars(no_gc)[1]);
  CHECK_EQ(Cast<SeqTwoByteString>(string1)->GetChars(no_gc)[2],
           Cast<SeqTwoByteString>(string2)->GetChars(no_gc)[2]);
  CHECK_EQ(Cast<SeqTwoByteString>(string1)->GetChars(no_gc)[3],
           Cast<SeqTwoByteString>(string2)->GetChars(no_gc)[3]);
  CHECK_EQ(Cast<SeqTwoByteString>(string1)->GetChars(no_gc)[4],
           Cast<SeqTwoByteString>(string2)->GetChars(no_gc)[4]);
}

TEST(Arguments) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  // Setup CSA for creating TFJ-style builtin.
  using Descriptor = JSTrampolineDescriptor;
  CodeAssemblerTester asm_tester(isolate, Descriptor());

  {
    CodeStubAssembler m(asm_tester.state());
    TNode<Int32T> argc =
        m.UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
    CodeStubArguments arguments(&m, argc);

    CSA_CHECK(&m, m.TaggedEqual(arguments.AtIndex(0), m.SmiConstant(12)));
    CSA_CHECK(&m, m.TaggedEqual(arguments.AtIndex(1), m.SmiConstant(13)));
    CSA_CHECK(&m, m.TaggedEqual(arguments.AtIndex(2), m.SmiConstant(14)));

    arguments.PopAndReturn(arguments.GetReceiver());
  }

  FunctionTester ft(asm_tester.GenerateCode(), 0);

  DirectHandle<Object> result;
  result = ft.Call(Handle<Smi>(Smi::FromInt(12), isolate),
                   Handle<Smi>(Smi::FromInt(13), isolate),
                   Handle<Smi>(Smi::FromInt(14), isolate))
               .ToHandleChecked();
  // When calling with undefined object as the receiver, the CallFunction
  // builtin swaps it to the global proxy object.
  CHECK_EQ(*isolate->global_proxy(), *result);

  result = ft.Call(Handle<Smi>(Smi::FromInt(12), isolate),
                   Handle<Smi>(Smi::FromInt(13), isolate),
                   Handle<Smi>(Smi::FromInt(14), isolate),
                   Handle<Smi>(Smi::FromInt(15), isolate))
               .ToHandleChecked();
  CHECK_EQ(*isolate->global_proxy(), *result);

  result = ft.Call(Handle<Smi>(Smi::FromInt(12), isolate),
                   Handle<Smi>(Smi::FromInt(13), isolate),
                   Handle<Smi>(Smi::FromInt(14), isolate),
                   Handle<Smi>(Smi::FromInt(15), isolate),
                   Handle<Smi>(Smi::FromInt(16), isolate),
                   Handle<Smi>(Smi::FromInt(17), isolate),
                   Handle<Smi>(Smi::FromInt(18), isolate),
                   Handle<Smi>(Smi::FromInt(19), isolate))
               .ToHandleChecked();
  CHECK_EQ(*isolate->global_proxy(), *result);
}

TEST(ArgumentsForEach) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  // Setup CSA for creating TFJ-style builtin.
  using Descriptor = JSTrampolineDescriptor;
  CodeAssemblerTester asm_tester(isolate, Descriptor());

  {
    CodeStubAssembler m(asm_tester.state());

    TNode<Int32T> argc =
        m.UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
    CodeStubArguments arguments(&m, argc);

    TVariable<Smi> sum(&m);
    CodeAssemblerVariableList list({&sum}, m.zone());

    sum = m.SmiConstant(0);

    arguments.ForEach(list, [&](TNode<Object> arg) {
      sum = m.SmiAdd(sum.value(), m.CAST(arg));
    });

    arguments.PopAndReturn(sum.value());
  }

  FunctionTester ft(asm_tester.GenerateCode(), 0);

  DirectHandle<Object> result;
  result = ft.Call(Handle<Smi>(Smi::FromInt(12), isolate),
                   Handle<Smi>(Smi::FromInt(13), isolate),
                   Handle<Smi>(Smi::FromInt(14), isolate))
               .ToHandleChecked();
  CHECK_EQ(Smi::FromInt(12 + 13 + 14), *result);

  result = ft.Call(Handle<Smi>(Smi::FromInt(12), isolate),
                   Handle<Smi>(Smi::FromInt(13), isolate),
                   Handle<Smi>(Smi::FromInt(14), isolate),
                   Handle<Smi>(Smi::FromInt(15), isolate))
               .ToHandleChecked();
  CHECK_EQ(Smi::FromInt(12 + 13 + 14 + 15), *result);

  result = ft.Call(Handle<Smi>(Smi::FromInt(12), isolate),
                   Handle<Smi>(Smi::FromInt(13), isolate),
                   Handle<Smi>(Smi::FromInt(14), isolate),
                   Handle<Smi>(Smi::FromInt(15), isolate),
                   Handle<Smi>(Smi::FromInt(16), isolate),
                   Handle<Smi>(Smi::FromInt(17), isolate),
                   Handle<Smi>(Smi::FromInt(18), isolate),
                   Handle<Smi>(Smi::FromInt(19), isolate))
               .ToHandleChecked();
  CHECK_EQ(Smi::FromInt(12 + 13 + 14 + 15 + 16 + 17 + 18 + 19), *result);
}

TEST(IsDebugActive) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  Label if_active(&m), if_not_active(&m);

  m.Branch(m.IsDebugActive(), &if_active, &if_not_active);
  m.BIND(&if_active);
  m.Return(m.TrueConstant());
  m.BIND(&if_not_active);
  m.Return(m.FalseConstant());

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK(!isolate->debug()->is_active());
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);

  bool* debug_is_active = reinterpret_cast<bool*>(
      ExternalReference::debug_is_active_address(isolate).address());

  // Cheat to enable debug (TODO: do this properly).
  *debug_is_active = true;

  result = ft.Call().ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).true_value(), *result);

  // Reset debug mode.
  *debug_is_active = false;
}

#if !defined(V8_OS_ANDROID)
// Ensure that the kShortBuiltinCallsOldSpaceSizeThreshold constant can be used
// for detecting whether the machine has >= 4GB of physical memory by checking
// the max old space size.
//
// Not on Android as short builtins do not depend on RAM on this platform, see
// comment in isolate.cc.
TEST(ShortBuiltinCallsThreshold) {
  if (!V8_SHORT_BUILTIN_CALLS_BOOL) return;

  const uint64_t kPhysicalMemoryThreshold = size_t{4} * GB;

  size_t heap_size, old, young;

  // If the physical memory is < kPhysicalMemoryThreshold then the old space
  // size must be below the kShortBuiltinCallsOldSpaceThreshold.
  heap_size = Heap::HeapSizeFromPhysicalMemory(kPhysicalMemoryThreshold - MB);
  i::Heap::GenerationSizesFromHeapSize(heap_size, &young, &old);
  CHECK_LT(old, kShortBuiltinCallsOldSpaceSizeThreshold);

  // If the physical memory is >= kPhysicalMemoryThreshold then the old space
  // size must be below the kShortBuiltinCallsOldSpaceThreshold.
  heap_size = Heap::HeapSizeFromPhysicalMemory(kPhysicalMemoryThreshold);
  i::Heap::GenerationSizesFromHeapSize(heap_size, &young, &old);
  CHECK_GE(old, kShortBuiltinCallsOldSpaceSizeThreshold);

  heap_size = Heap::HeapSizeFromPhysicalMemory(kPhysicalMemoryThreshold + MB);
  i::Heap::GenerationSizesFromHeapSize(heap_size, &young, &old);
  CHECK_GE(old, kShortBuiltinCallsOldSpaceSizeThreshold);
}
#endif  // !defined(V8_OS_ANDROID)

TEST(CallBuiltin) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  {
    auto receiver = m.Parameter<Object>(1);
    auto name = m.Parameter<Name>(2);
    auto context = m.GetJSContextParameter();

    auto value = m.CallBuiltin(Builtin::kGetProperty, context, receiver, name);
    m.Return(value);
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Factory* factory = isolate->factory();
  Handle<Name> name = factory->InternalizeUtf8String("a");
  DirectHandle<Object> value(Smi::FromInt(153), isolate);
  Handle<JSObject> object = factory->NewJSObjectWithNullProto();
  JSObject::AddProperty(isolate, object, name, value, NONE);

  DirectHandle<Object> result = ft.Call(object, name).ToHandleChecked();
  CHECK_EQ(*value, *result);
}

TEST(TailCallBuiltin) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  {
    auto receiver = m.Parameter<Object>(1);
    auto name = m.Parameter<Name>(2);
    auto context = m.GetJSContextParameter();

    m.TailCallBuiltin(Builtin::kGetProperty, context, receiver, name);
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Factory* factory = isolate->factory();
  Handle<Name> name = factory->InternalizeUtf8String("a");
  DirectHandle<Object> value(Smi::FromInt(153), isolate);
  Handle<JSObject> object = factory->NewJSObjectWithNullProto();
  JSObject::AddProperty(isolate, object, name, value, NONE);

  DirectHandle<Object> result = ft.Call(object, name).ToHandleChecked();
  CHECK_EQ(*value, *result);
}

class AppendJSArrayCodeStubAssembler : public CodeStubAssembler {
 public:
  AppendJSArrayCodeStubAssembler(compiler::CodeAssemblerState* state,
                                 ElementsKind kind)
      : CodeStubAssembler(state), kind_(kind) {}

  void TestAppendJSArrayImpl(Isolate* isolate, CodeAssemblerTester* csa_tester,
                             Handle<Object> o1, Handle<Object> o2,
                             Handle<Object> o3, Handle<Object> o4,
                             int initial_size, int result_size) {
    Handle<JSArray> array = isolate->factory()->NewJSArray(
        kind_, 2, initial_size,
        ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE);
    Object::SetElement(isolate, array, 0, Handle<Smi>(Smi::FromInt(1), isolate),
                       kDontThrow)
        .Check();
    Object::SetElement(isolate, array, 1, Handle<Smi>(Smi::FromInt(2), isolate),
                       kDontThrow)
        .Check();
    CodeStubArguments args(this,
                           IntPtrConstant(kNumParams + kJSArgcReceiverSlots));
    TVariable<IntPtrT> arg_index(this);
    Label bailout(this);
    arg_index = IntPtrConstant(0);
    TNode<Smi> length = BuildAppendJSArray(kind_, HeapConstantNoHole(array),
                                           &args, &arg_index, &bailout);
    Return(length);

    BIND(&bailout);
    Return(SmiTag(IntPtrAdd(arg_index.value(), IntPtrConstant(2))));

    FunctionTester ft(csa_tester->GenerateCode(), kNumParams);

    DirectHandle<Object> result = ft.Call(o1, o2, o3, o4).ToHandleChecked();

    CHECK_EQ(kind_, array->GetElementsKind());
    CHECK_EQ(result_size, i::Cast<Smi>(*result).value());
    CHECK_EQ(result_size, Smi::ToInt(array->length()));
    DirectHandle<Object> obj =
        JSObject::GetElement(isolate, array, 2).ToHandleChecked();
    DirectHandle<HeapObject> undefined_value(
        ReadOnlyRoots(isolate).undefined_value(), isolate);
    CHECK_EQ(result_size < 3 ? *undefined_value : *o1, *obj);
    obj = JSObject::GetElement(isolate, array, 3).ToHandleChecked();
    CHECK_EQ(result_size < 4 ? *undefined_value : *o2, *obj);
    obj = JSObject::GetElement(isolate, array, 4).ToHandleChecked();
    CHECK_EQ(result_size < 5 ? *undefined_value : *o3, *obj);
    obj = JSObject::GetElement(isolate, array, 5).ToHandleChecked();
    CHECK_EQ(result_size < 6 ? *undefined_value : *o4, *obj);
  }

  static void TestAppendJSArray(Isolate* isolate, ElementsKind kind,
                                Tagged<Object> o1, Tagged<Object> o2,
                                Tagged<Object> o3, Tagged<Object> o4,
                                int initial_size, int result_size) {
    CodeAssemblerTester asm_tester(isolate, i::JSParameterCount(kNumParams));
    AppendJSArrayCodeStubAssembler m(asm_tester.state(), kind);
    m.TestAppendJSArrayImpl(
        isolate, &asm_tester, Handle<Object>(o1, isolate),
        Handle<Object>(o2, isolate), Handle<Object>(o3, isolate),
        Handle<Object>(o4, isolate), initial_size, result_size);
  }

 private:
  static const int kNumParams = 4;
  ElementsKind kind_;
};

TEST(BuildAppendJSArrayFastElement) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 6, 6);
}

TEST(BuildAppendJSArrayFastElementGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 2, 6);
}

TEST(BuildAppendJSArrayFastSmiElement) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 6, 6);
}

TEST(BuildAppendJSArrayFastSmiElementGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 2, 6);
}

TEST(BuildAppendJSArrayFastSmiElementObject) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      ReadOnlyRoots(isolate).undefined_value(), Smi::FromInt(6), 6, 4);
}

TEST(BuildAppendJSArrayFastSmiElementObjectGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_SMI_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      ReadOnlyRoots(isolate).undefined_value(), Smi::FromInt(6), 2, 4);
}

TEST(BuildAppendJSArrayFastDoubleElements) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_DOUBLE_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 6, 6);
}

TEST(BuildAppendJSArrayFastDoubleElementsGrow) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_DOUBLE_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      Smi::FromInt(5), Smi::FromInt(6), 2, 6);
}

TEST(BuildAppendJSArrayFastDoubleElementsObject) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  AppendJSArrayCodeStubAssembler::TestAppendJSArray(
      isolate, PACKED_DOUBLE_ELEMENTS, Smi::FromInt(3), Smi::FromInt(4),
      ReadOnlyRoots(isolate).undefined_value(), Smi::FromInt(6), 6, 4);
}

namespace {

template <typename Stub, typename... Args>
void Recompile(Args... args) {
  Stub stub(args...);
  stub.DeleteStubFromCacheForTesting();
  stub.GetCode();
}

}  // namespace

void CustomPromiseHook(v8::PromiseHookType type, v8::Local<v8::Promise> promise,
                       v8::Local<v8::Value> parentPromise) {}

TEST(IsPromiseHookEnabled) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  m.Return(
      m.SelectBooleanConstant(
          m.IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate()));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);

  isolate->SetPromiseHook(CustomPromiseHook);
  result = ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).true_value(), *result);

  isolate->SetPromiseHook(nullptr);
  result = ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);
}

TEST(NewJSPromise) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<JSPromise> promise = m.NewJSPromise(context);
  m.Return(promise);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsJSPromise(*result));
}

TEST(NewJSPromise2) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, v8::Promise::kRejected, m.SmiConstant(1));
  m.Return(promise);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsJSPromise(*result));
  DirectHandle<JSPromise> js_promise = Cast<JSPromise>(result);
  CHECK_EQ(v8::Promise::kRejected, js_promise->status());
  CHECK_EQ(Smi::FromInt(1), js_promise->result());
  CHECK(!js_promise->has_handler());
}

TEST(IsSymbol) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  auto symbol = m.Parameter<HeapObject>(1);
  m.Return(m.SelectBooleanConstant(m.IsSymbol(symbol)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->NewSymbol()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).true_value(), *result);

  result = ft.Call(isolate->factory()->empty_string()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);
}

TEST(IsPrivateSymbol) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  auto symbol = m.Parameter<HeapObject>(1);
  m.Return(m.SelectBooleanConstant(m.IsPrivateSymbol(symbol)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->NewSymbol()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);

  result = ft.Call(isolate->factory()->empty_string()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);

  result = ft.Call(isolate->factory()->NewPrivateSymbol()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).true_value(), *result);
}

TEST(PromiseHasHandler) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  m.Return(m.SelectBooleanConstant(m.PromiseHasHandler(promise)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  DirectHandle<Object> result =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(), *result);
}

TEST(CreatePromiseResolvingFunctionsContext) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<NativeContext> native_context = m.LoadNativeContext(context);
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  const TNode<Context> promise_context =
      m.CreatePromiseResolvingFunctionsContext(
          context, promise, m.BooleanConstant(false), native_context);
  m.Return(promise_context);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result = ft.Call().ToHandleChecked();
  CHECK(IsContext(*result));
  DirectHandle<Context> context_js = Cast<Context>(result);
  CHECK_EQ(isolate->root(RootIndex::kEmptyScopeInfo), context_js->scope_info());
  CHECK_EQ(*isolate->native_context(), context_js->native_context());
  CHECK(IsJSPromise(context_js->get(PromiseBuiltins::kPromiseSlot)));
  CHECK_EQ(ReadOnlyRoots(isolate).false_value(),
           context_js->get(PromiseBuiltins::kDebugEventSlot));
}

TEST(CreatePromiseResolvingFunctions) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  const TNode<NativeContext> native_context = m.LoadNativeContext(context);
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  PromiseResolvingFunctions funcs = m.CreatePromiseResolvingFunctions(
      context, promise, m.BooleanConstant(false), native_context);
  TNode<JSFunction> resolve = funcs.resolve;
  TNode<JSFunction> reject = funcs.reject;
  TNode<IntPtrT> const kSize = m.IntPtrConstant(2);
  TNode<FixedArray> const arr =
      m.Cast(m.AllocateFixedArray(PACKED_ELEMENTS, kSize));
  m.StoreFixedArrayElement(arr, 0, resolve);
  m.StoreFixedArrayElement(arr, 1, reject);
  m.Return(arr);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result_obj =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsFixedArray(*result_obj));
  DirectHandle<FixedArray> result_arr = Cast<FixedArray>(result_obj);
  CHECK(IsJSFunction(result_arr->get(0)));
  CHECK(IsJSFunction(result_arr->get(1)));
}

TEST(NewElementsCapacity) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  m.Return(m.SmiTag(
      m.CalculateNewElementsCapacity(m.SmiUntag(m.Parameter<Smi>(1)))));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Smi> test_value = Handle<Smi>(Smi::FromInt(1), isolate);
  Tagged<Smi> result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(2), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1025), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
}

TEST(NewElementsCapacitySmi) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  m.Return(m.CalculateNewElementsCapacity(m.UncheckedParameter<Smi>(1)));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Smi> test_value = Handle<Smi>(Smi::FromInt(0), isolate);
  Tagged<Smi> result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(2), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
  test_value = Handle<Smi>(Smi::FromInt(1025), isolate);
  result_obj = *ft.CallChecked<Smi>(test_value);
  CHECK_EQ(
      result_obj.value(),
      static_cast<int>(JSObject::NewElementsCapacity((*test_value).value())));
}

TEST(AllocateRootFunctionWithContext) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  const auto context = m.GetJSContextParameter();
  const TNode<NativeContext> native_context = m.LoadNativeContext(context);
  const TNode<JSPromise> promise =
      m.NewJSPromise(context, m.UndefinedConstant());
  TNode<Context> promise_context = m.CreatePromiseResolvingFunctionsContext(
      context, promise, m.BooleanConstant(false), native_context);
  const TNode<JSFunction> resolve = m.AllocateRootFunctionWithContext(
      RootIndex::kPromiseCapabilityDefaultResolveSharedFun, promise_context,
      native_context);
  m.Return(resolve);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result_obj =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsJSFunction(*result_obj));
  DirectHandle<JSFunction> fun = Cast<JSFunction>(result_obj);
  CHECK_EQ(ReadOnlyRoots(isolate).empty_property_array(),
           fun->property_array());
  CHECK_EQ(ReadOnlyRoots(isolate).empty_fixed_array(), fun->elements());
  CHECK_EQ(isolate->heap()->many_closures_cell(), fun->raw_feedback_cell());
  CHECK(!fun->has_prototype_slot());
  CHECK_EQ(*isolate->factory()->promise_capability_default_resolve_shared_fun(),
           fun->shared());
  CHECK_EQ(isolate->factory()
               ->promise_capability_default_resolve_shared_fun()
               ->GetCode(isolate),
           fun->code(isolate));
}

TEST(CreatePromiseGetCapabilitiesExecutorContext) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  PromiseBuiltinsAssembler m(asm_tester.state());

  auto context = m.GetJSContextParameter();
  TNode<NativeContext> native_context = m.LoadNativeContext(context);

  TNode<PromiseCapability> capability = m.CreatePromiseCapability(
      m.UndefinedConstant(), m.UndefinedConstant(), m.UndefinedConstant());
  TNode<Context> executor_context =
      m.CreatePromiseCapabilitiesExecutorContext(native_context, capability);
  m.Return(executor_context);

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  Handle<Object> result_obj =
      ft.Call(isolate->factory()->undefined_value()).ToHandleChecked();
  CHECK(IsContext(*result_obj));
  DirectHandle<Context> context_js = Cast<Context>(result_obj);
  CHECK_EQ(PromiseBuiltins::kCapabilitiesContextLength, context_js->length());
  CHECK_EQ(isolate->root(RootIndex::kEmptyScopeInfo), context_js->scope_info());
  CHECK_EQ(*isolate->native_context(), context_js->native_context());
  CHECK(IsPromiseCapability(context_js->get(PromiseBuiltins::kCapabilitySlot)));
}

TEST(NewPromiseCapability) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  {  // Builtin Promise
    const int kNumParams = 0;
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    PromiseBuiltinsAssembler m(asm_tester.state());

    auto context = m.GetJSContextParameter();
    const TNode<NativeContext> native_context = m.LoadNativeContext(context);
    const TNode<Object> promise_constructor =
        m.LoadContextElement(native_context, Context::PROMISE_FUNCTION_INDEX);

    const TNode<True> debug_event = m.TrueConstant();
    const TNode<Object> capability =
        m.CallBuiltin(Builtin::kNewPromiseCapability, context,
                      promise_constructor, debug_event);
    m.Return(capability);

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

    Handle<Object> result_obj = ft.Call().ToHandleChecked();
    CHECK(IsPromiseCapability(*result_obj));
    DirectHandle<PromiseCapability> result =
        Cast<PromiseCapability>(result_obj);

    CHECK(IsJSPromise(result->promise()));
    CHECK(IsJSFunction(result->resolve()));
    CHECK(IsJSFunction(result->reject()));
    CHECK_EQ(
        *isolate->factory()->promise_capability_default_reject_shared_fun(),
        Cast<JSFunction>(result->reject())->shared());
    CHECK_EQ(
        *isolate->factory()->promise_capability_default_resolve_shared_fun(),
        Cast<JSFunction>(result->resolve())->shared());

    Handle<JSFunction> callbacks[] = {
        handle(Cast<JSFunction>(result->resolve()), isolate),
        handle(Cast<JSFunction>(result->reject()), isolate)};

    for (auto&& callback : callbacks) {
      DirectHandle<Context> callback_context(Cast<Context>(callback->context()),
                                             isolate);
      CHECK_EQ(isolate->root(RootIndex::kEmptyScopeInfo),
               callback_context->scope_info());
      CHECK_EQ(*isolate->native_context(), callback_context->native_context());
      CHECK_EQ(PromiseBuiltins::kPromiseContextLength,
               callback_context->length());
      CHECK_EQ(callback_context->get(PromiseBuiltins::kPromiseSlot),
               result->promise());
    }
  }

  {  // Custom Promise
    const int kNumParams = 1;
    CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
    PromiseBuiltinsAssembler m(asm_tester.state());

    auto context = m.GetJSContextParameter();

    auto constructor = m.Parameter<Object>(1);
    const TNode<True> debug_event = m.TrueConstant();
    const TNode<Object> capability = m.CallBuiltin(
        Builtin::kNewPromiseCapability, context, constructor, debug_event);
    m.Return(capability);

    FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

    Handle<JSFunction> constructor_fn =
        Cast<JSFunction>(v8::Utils::OpenHandle(*CompileRun(
            "(function FakePromise(executor) {"
            "  var self = this;"
            "  function resolve(value) { self.resolvedValue = value; }"
            "  function reject(reason) { self.rejectedReason = reason; }"
            "  executor(resolve, reject);"
            "})")));

    Handle<Object> result_obj = ft.Call(constructor_fn).ToHandleChecked();
    CHECK(IsPromiseCapability(*result_obj));
    DirectHandle<PromiseCapability> result =
        Cast<PromiseCapability>(result_obj);

    CHECK(IsJSObject(result->promise()));
    Handle<JSObject> promise(Cast<JSObject>(result->promise()), isolate);
    CHECK_EQ(constructor_fn->prototype_or_initial_map(kAcquireLoad),
             promise->map());
    CHECK(IsJSFunction(result->resolve()));
    CHECK(IsJSFunction(result->reject()));

    Handle<String> resolved_str =
        isolate->factory()->NewStringFromAsciiChecked("resolvedStr");
    Handle<String> rejected_str =
        isolate->factory()->NewStringFromAsciiChecked("rejectedStr");

    Handle<Object> argv1[] = {resolved_str};
    DirectHandle<Object> ret =
        Execution::Call(isolate, handle(result->resolve(), isolate),
                        isolate->factory()->undefined_value(), 1, argv1)
            .ToHandleChecked();

    DirectHandle<Object> prop1 =
        JSReceiver::GetProperty(isolate, promise, "resolvedValue")
            .ToHandleChecked();
    CHECK_EQ(*resolved_str, *prop1);

    Handle<Object> argv2[] = {rejected_str};
    ret = Execution::Call(isolate, handle(result->reject(), isolate),
                          isolate->factory()->undefined_value(), 1, argv2)
              .ToHandleChecked();
    DirectHandle<Object> prop2 =
        JSReceiver::GetProperty(isolate, promise, "rejectedReason")
            .ToHandleChecked();
    CHECK_EQ(*rejected_str, *prop2);
  }
}

TEST(DirectMemoryTest8BitWord32Immediate) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  int8_t buffer[] = {1, 2, 4, 8, 17, 33, 65, 127};
  const int element_count = 8;
  Label bad(&m);

  TNode<RawPtrT> buffer_node = m.PointerConstant(buffer);
  for (size_t i = 0; i < element_count; ++i) {
    for (size_t j = 0; j < element_count; ++j) {
      TNode<Uint8T> loaded =
          m.LoadBufferData<Uint8T>(buffer_node, static_cast<int>(i));
      TNode<Word32T> masked = m.Word32And(loaded, m.Int32Constant(buffer[j]));
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }
    }
  }

  m.Return(m.SmiConstant(1));

  m.BIND(&bad);
  m.Return(m.SmiConstant(0));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(1, (*ft.CallChecked<Smi>()).value());
}

TEST(DirectMemoryTest16BitWord32Immediate) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  int16_t buffer[] = {156, 2234, 4544, 8444, 1723, 3888, 658, 1278};
  const int element_count = 8;
  Label bad(&m);

  TNode<RawPtrT> buffer_node = m.PointerConstant(buffer);
  for (size_t i = 0; i < element_count; ++i) {
    for (size_t j = 0; j < element_count; ++j) {
      TNode<Uint16T> loaded = m.LoadBufferData<Uint16T>(
          buffer_node, static_cast<int>(i * sizeof(int16_t)));
      TNode<Word32T> masked = m.Word32And(loaded, m.Int32Constant(buffer[j]));
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }
    }
  }

  m.Return(m.SmiConstant(1));

  m.BIND(&bad);
  m.Return(m.SmiConstant(0));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(1, (*ft.CallChecked<Smi>()).value());
}

TEST(DirectMemoryTest8BitWord32) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  int8_t buffer[] = {1, 2, 4, 8, 17, 33, 65, 127, 67, 38};
  const int element_count = 10;
  Label bad(&m);
  TNode<Uint32T> constants[element_count];

  TNode<RawPtrT> buffer_node = m.PointerConstant(buffer);
  for (size_t i = 0; i < element_count; ++i) {
    constants[i] = m.LoadBufferData<Uint8T>(buffer_node, static_cast<int>(i));
  }

  for (size_t i = 0; i < element_count; ++i) {
    for (size_t j = 0; j < element_count; ++j) {
      TNode<Uint8T> loaded =
          m.LoadBufferData<Uint8T>(buffer_node, static_cast<int>(i));
      TNode<Word32T> masked = m.Word32And(loaded, constants[j]);
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }

      masked = m.Word32And(constants[i], constants[j]);
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }
    }
  }

  m.Return(m.SmiConstant(1));

  m.BIND(&bad);
  m.Return(m.SmiConstant(0));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(1, (*ft.CallChecked<Smi>()).value());
}

TEST(DirectMemoryTest16BitWord32) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 0;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());
  int16_t buffer[] = {1, 2, 4, 8, 12345, 33, 65, 255, 67, 3823};
  const int element_count = 10;
  Label bad(&m);
  TNode<Uint32T> constants[element_count];

  TNode<RawPtrT> buffer_node1 = m.PointerConstant(buffer);
  for (size_t i = 0; i < element_count; ++i) {
    constants[i] = m.LoadBufferData<Uint16T>(
        buffer_node1, static_cast<int>(i * sizeof(int16_t)));
  }
  TNode<RawPtrT> buffer_node2 = m.PointerConstant(buffer);

  for (size_t i = 0; i < element_count; ++i) {
    for (size_t j = 0; j < element_count; ++j) {
      TNode<Uint16T> loaded = m.LoadBufferData<Uint16T>(
          buffer_node1, static_cast<int>(i * sizeof(int16_t)));
      TNode<Word32T> masked = m.Word32And(loaded, constants[j]);
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }

      // Force a memory access relative to a high-number register.
      loaded = m.LoadBufferData<Uint16T>(buffer_node2,
                                         static_cast<int>(i * sizeof(int16_t)));
      masked = m.Word32And(loaded, constants[j]);
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }

      masked = m.Word32And(constants[i], constants[j]);
      if ((buffer[j] & buffer[i]) != 0) {
        m.GotoIf(m.Word32Equal(masked, m.Int32Constant(0)), &bad);
      } else {
        m.GotoIf(m.Word32NotEqual(masked, m.Int32Constant(0)), &bad);
      }
    }
  }

  m.Return(m.SmiConstant(1));

  m.BIND(&bad);
  m.Return(m.SmiConstant(0));

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  CHECK_EQ(1, (*ft.CallChecked<Smi>()).value());
}

TEST(LoadJSArrayElementsMap) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    auto context = m.GetJSContextParameter();
    TNode<NativeContext> native_context = m.LoadNativeContext(context);
    TNode<Int32T> kind = m.SmiToInt32(m.Parameter<Smi>(1));
    m.Return(m.LoadJSArrayElementsMap(kind, native_context));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);
  for (int kind = 0; kind <= HOLEY_DOUBLE_ELEMENTS; kind++) {
    DirectHandle<Map> csa_result =
        ft.CallChecked<Map>(handle(Smi::FromInt(kind), isolate));
    ElementsKind elements_kind = static_cast<ElementsKind>(kind);
    DirectHandle<Map> result(
        isolate->native_context()->GetInitialJSArrayMap(elements_kind),
        isolate);
    CHECK_EQ(*csa_result, *result);
  }
}

TEST(IsWhiteSpaceOrLineTerminator) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));

  {  // Returns true if whitespace, false otherwise.
    CodeStubAssembler m(asm_tester.state());
    Label if_true(&m), if_false(&m);
    m.Branch(m.IsWhiteSpaceOrLineTerminator(
                 m.UncheckedCast<Uint16T>(m.SmiToInt32(m.Parameter<Smi>(1)))),
             &if_true, &if_false);
    m.BIND(&if_true);
    m.Return(m.TrueConstant());
    m.BIND(&if_false);
    m.Return(m.FalseConstant());
  }
  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Object> true_value = ft.true_value();
  Handle<Object> false_value = ft.false_value();

  for (base::uc16 c = 0; c < 0xFFFF; c++) {
    DirectHandle<Object> expected_value =
        IsWhiteSpaceOrLineTerminator(c) ? true_value : false_value;
    ft.CheckCall(expected_value, handle(Smi::FromInt(c), isolate));
  }
}

TEST(BranchIfNumberRelationalComparison) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  Factory* f = isolate->factory();
  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    Label return_true(&m), return_false(&m);
    m.BranchIfNumberRelationalComparison(
        Operation::kGreaterThanOrEqual, m.Parameter<Number>(1),
        m.Parameter<Number>(2), &return_true, &return_false);
    m.BIND(&return_true);
    m.Return(m.BooleanConstant(true));
    m.BIND(&return_false);
    m.Return(m.BooleanConstant(false));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  ft.CheckTrue(f->NewNumber(0), f->NewNumber(0));
  ft.CheckTrue(f->NewNumber(1), f->NewNumber(0));
  ft.CheckTrue(f->NewNumber(1), f->NewNumber(1));
  ft.CheckFalse(f->NewNumber(0), f->NewNumber(1));
  ft.CheckFalse(f->NewNumber(-1), f->NewNumber(0));
  ft.CheckTrue(f->NewNumber(-1), f->NewNumber(-1));

  ft.CheckTrue(f->NewNumber(-1), f->NewNumber(-1.5));
  ft.CheckFalse(f->NewNumber(-1.5), f->NewNumber(-1));
  ft.CheckTrue(f->NewNumber(-1.5), f->NewNumber(-1.5));
}

TEST(IsNumberArrayIndex) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 1;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester.state());
    auto number = m.Parameter<Number>(1);
    m.Return(
        m.SmiFromInt32(m.UncheckedCast<Int32T>(m.IsNumberArrayIndex(number))));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  double indices[] = {Smi::kMinValue,
                      -11,
                      -1,
                      0,
                      1,
                      2,
                      Smi::kMaxValue,
                      -11.0,
                      -11.1,
                      -2.0,
                      -1.0,
                      -0.0,
                      0.0,
                      0.00001,
                      0.1,
                      1,
                      2,
                      Smi::kMinValue - 1.0,
                      Smi::kMinValue + 1.0,
                      Smi::kMinValue + 1.2,
                      kMaxInt + 1.2,
                      kMaxInt - 10.0,
                      kMaxInt - 1.0,
                      kMaxInt,
                      kMaxInt + 1.0,
                      kMaxInt + 10.0};

  for (size_t i = 0; i < arraysize(indices); i++) {
    Handle<Object> index = isolate->factory()->NewNumber(indices[i]);
    uint32_t array_index;
    CHECK_EQ(Object::ToArrayIndex(*index, &array_index),
             ((*ft.CallChecked<Smi>(index)).value() == 1));
  }
}

TEST(NumberMinMax) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  const int kNumParams = 2;
  CodeAssemblerTester asm_tester_min(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester_min.state());
    m.Return(m.NumberMin(m.Parameter<Number>(1), m.Parameter<Number>(2)));
  }
  FunctionTester ft_min(asm_tester_min.GenerateCode(), kNumParams);

  CodeAssemblerTester asm_tester_max(isolate, JSParameterCount(kNumParams));
  {
    CodeStubAssembler m(asm_tester_max.state());
    m.Return(m.NumberMax(m.Parameter<Number>(1), m.Parameter<Number>(2)));
  }
  FunctionTester ft_max(asm_tester_max.GenerateCode(), kNumParams);

  // Test smi values.
  Handle<Smi> smi_1(Smi::FromInt(1), isolate);
  Handle<Smi> smi_2(Smi::FromInt(2), isolate);
  Handle<Smi> smi_5(Smi::FromInt(5), isolate);
  CHECK_EQ((*ft_min.CallChecked<Smi>(smi_1, smi_2)).value(), 1);
  CHECK_EQ((*ft_min.CallChecked<Smi>(smi_2, smi_1)).value(), 1);
  CHECK_EQ((*ft_max.CallChecked<Smi>(smi_1, smi_2)).value(), 2);
  CHECK_EQ((*ft_max.CallChecked<Smi>(smi_2, smi_1)).value(), 2);

  // Test double values.
  Handle<Object> double_a = isolate->factory()->NewNumber(2.5);
  Handle<Object> double_b = isolate->factory()->NewNumber(3.5);
  Handle<Object> nan =
      isolate->factory()->NewNumber(std::numeric_limits<double>::quiet_NaN());
  Handle<Object> infinity = isolate->factory()->NewNumber(V8_INFINITY);

  CHECK_EQ(ft_min.CallChecked<HeapNumber>(double_a, double_b)->value(), 2.5);
  CHECK_EQ(ft_min.CallChecked<HeapNumber>(double_b, double_a)->value(), 2.5);
  CHECK_EQ(ft_min.CallChecked<HeapNumber>(infinity, double_a)->value(), 2.5);
  CHECK_EQ(ft_min.CallChecked<HeapNumber>(double_a, infinity)->value(), 2.5);
  CHECK(std::isnan(ft_min.CallChecked<HeapNumber>(nan, double_a)->value()));
  CHECK(std::isnan(ft_min.CallChecked<HeapNumber>(double_a, nan)->value()));

  CHECK_EQ(ft_max.CallChecked<HeapNumber>(double_a, double_b)->value(), 3.5);
  CHECK_EQ(ft_max.CallChecked<HeapNumber>(double_b, double_a)->value(), 3.5);
  CHECK_EQ(ft_max.CallChecked<HeapNumber>(infinity, double_a)->value(),
           V8_INFINITY);
  CHECK_EQ(ft_max.CallChecked<HeapNumber>(double_a, infinity)->value(),
           V8_INFINITY);
  CHECK(std::isnan(ft_max.CallChecked<HeapNumber>(nan, double_a)->value()));
  CHECK(std::isnan(ft_max.CallChecked<HeapNumber>(double_a, nan)->va
"""


```