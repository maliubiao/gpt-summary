Response:
My goal is to analyze the provided C++ code snippet from `v8/test/cctest/test-code-stub-assembler.cc` and summarize its functionality. Here's my thought process:

1. **Identify the Core Purpose:** The filename itself gives a strong hint: `test-code-stub-assembler.cc`. This suggests the code is testing the `CodeStubAssembler` (CSA) within V8. CSA is a low-level API used to generate machine code. Therefore, the tests are likely verifying the correct behavior of various CSA functionalities.

2. **Analyze Individual `TEST` Blocks:** The code is structured into several `TEST` blocks. Each block isolates a specific aspect of CSA. I'll examine each one individually to understand its purpose.

3. **`TEST(AllocateJSObjectFromMapCSA)`:**
    * **Code Structure:**  Uses `CodeAssemblerTester` and `CodeStubAssembler`. Defines parameters for a map, properties, and elements.
    * **Key CSA Operations:** `AllocateJSObjectFromMap`, `IsJSArrayMap`, `StoreObjectFieldNoWriteBarrier`, `SmiConstant`, `Return`.
    * **Logic:**  Allocates a JSObject. If the map is a JSArray map, it sets the `length` field.
    * **Verification:** Calls the generated code with different map types (object and array) and checks the properties of the resulting JSObject. It also tests a case with pre-existing properties.
    * **Functionality:** This test verifies that `AllocateJSObjectFromMap` correctly allocates JSObjects with and without array-specific initialization based on the provided map.

4. **`TEST(AllocationFoldingCSA)`:**
    * **Code Structure:**  Similar setup with `CodeAssemblerTester` and `CodeStubAssembler`.
    * **Key CSA Operations:** `AllocateFixedArray`, `AllocateByteArray`, `StoreFixedArrayElement`.
    * **Logic:** Allocates a `FixedArray` and then allocates several `ByteArray` objects within it.
    * **Verification:** Checks the length and alignment of the `FixedArray` and the `ByteArray` objects within it. It also checks the relative addresses of the `ByteArray` objects, hinting at allocation folding (placing objects contiguously in memory).
    * **Functionality:** This test verifies the allocation of `FixedArray` and `ByteArray` objects using CSA, specifically focusing on memory layout and potential allocation optimizations.

5. **`TEST(AllocateNameDictionary)`, `TEST(AllocateOrderedNameDictionary)`, `TEST(AllocateOrderedHashSet)`, `TEST(AllocateOrderedHashMap)`:**
    * **Code Structure:**  Uses helper functions `TestDictionaryAllocation`.
    * **Key CSA Operations (within the lambdas):** `AllocateNameDictionary`, `AllocateOrderedNameDictionary`, `AllocateOrderedHashSet`, `AllocateOrderedHashMap`.
    * **Logic (within `TestDictionaryAllocation`):**  Takes a capacity parameter, allocates a dictionary using the CSA function, and returns it.
    * **Verification (within `TestDictionaryAllocation`):**  Compares the memory contents of the CSA-allocated dictionary with a dictionary allocated using the standard V8 API.
    * **Functionality:** These tests verify the correct allocation and initialization of different dictionary types using CSA, ensuring they are memory-equivalent to those created through standard V8 mechanisms.

6. **`TEST(PopAndReturnFromJSBuiltinWithStackParameters)`, `TEST(PopAndReturnFromTFCBuiltinWithStackParameters)`:**
    * **Code Structure:**  Uses `CodeAssemblerTester` and `CodeStubAssembler`.
    * **Key CSA Operations:** `PopAndReturn`.
    * **Logic:** Attempts to use `PopAndReturn` in builtins with declared stack parameters.
    * **Verification:** Expects a `CHECK` failure during code generation because `PopAndReturn` is not allowed in this context.
    * **Functionality:** These tests verify that the CSA correctly enforces restrictions on the use of `PopAndReturn` in certain types of builtins.

7. **`TEST(PopAndReturnConstant)`, `TEST(PopAndReturnVariable)`:**
    * **Code Structure:** Uses `CodeAssemblerTester` and `CodeStubAssembler`. Utilizes a helper function `CallFunctionWithStackPointerChecks`.
    * **Key CSA Operations:** `PopAndReturn`.
    * **Logic:** Uses `PopAndReturn` to return a constant value.
    * **Verification (within `CallFunctionWithStackPointerChecks`):**  Calls the generated function multiple times and checks that the stack pointer remains the same before and after each call.
    * **Functionality:** These tests verify the functionality of `PopAndReturn` and ensure it doesn't corrupt the stack.

8. **`TEST(OneToTwoByteStringCopy)`, `TEST(OneToOneByteStringCopy)`, `TEST(OneToOneByteStringCopyNonZeroStart)`, `TEST(TwoToTwoByteStringCopy)`:**
    * **Code Structure:** Uses `CodeAssemblerTester` and `StringBuiltinsAssembler`.
    * **Key CSA Operations:** `CopyStringCharacters`.
    * **Logic:** Copies characters between strings with different encodings and with non-zero starting offsets.
    * **Verification:** Checks the character contents of the destination string after the copy.
    * **Functionality:** These tests verify the `CopyStringCharacters` CSA operation for various string encoding combinations and starting positions.

9. **`TEST(Arguments)`, `TEST(ArgumentsForEach)`:**
    * **Code Structure:** Uses `CodeAssemblerTester` and `CodeStubAssembler`. Uses `CodeStubArguments`.
    * **Key CSA Operations:** Accessing arguments via `AtIndex`, iterating through arguments via `ForEach`.
    * **Logic:** Accesses and iterates through the arguments passed to the generated function.
    * **Verification:** Checks the values of specific arguments and calculates a sum of the arguments.
    * **Functionality:** These tests verify the functionality of the `CodeStubArguments` class for accessing and iterating through function arguments.

10. **`TEST(IsDebugActive)`:**
    * **Code Structure:** Uses `CodeAssemblerTester` and `CodeStubAssembler`.
    * **Key CSA Operations:** `IsDebugActive`.
    * **Logic:** Checks if the debugger is active.
    * **Verification:** Calls the generated function with and without the debugger enabled (using a "cheat").
    * **Functionality:** This test verifies the `IsDebugActive` CSA operation.

11. **`TEST(ShortBuiltinCallsThreshold)`:**
    * **Logic:**  This test doesn't use CSA directly. It checks the relationship between physical memory and the threshold used for short builtin calls.
    * **Verification:**  Asserts that the old generation heap size is above or below a certain threshold based on the simulated physical memory.
    * **Functionality:** This test verifies a non-CSA-related constant that influences the behavior of builtins.

12. **`TEST(CallBuiltin)`, `TEST(TailCallBuiltin)`:**
    * **Code Structure:** Uses `CodeAssemblerTester` and `PromiseBuiltinsAssembler`.
    * **Key CSA Operations:** `CallBuiltin`, `TailCallBuiltin`.
    * **Logic:** Calls another built-in function (`kGetProperty`).
    * **Verification:** Checks the return value of the called builtin.
    * **Functionality:** These tests verify the `CallBuiltin` and `TailCallBuiltin` CSA operations for invoking other builtins.

13. **`TEST(AppendJSArray)`:**
    * **Code Structure:** Uses a custom `AppendJSArrayCodeStubAssembler`.
    * **Key CSA Operations:** `BuildAppendJSArray`.
    * **Logic:** Appends elements to a `JSArray` of a specific `ElementsKind`.
    * **Verification:** Checks the resulting `ElementsKind`, length, and element values of the array.
    * **Functionality:** This test verifies the `BuildAppendJSArray` CSA helper for efficiently appending elements to JSArrays.

4. **Synthesize the Overall Functionality:** After analyzing each test, I can synthesize the overall functionality of the file. It's a collection of unit tests for the `CodeStubAssembler`. Each test verifies a specific aspect of CSA, such as object allocation, memory manipulation, control flow, function calls, and interaction with the V8 runtime (e.g., checking debugger status).

5. **Address Specific Instructions:**
    * **`.tq` extension:** The filename ends in `.cc`, not `.tq`, so it's a standard C++ file.
    * **JavaScript Relation:** Several tests relate to JavaScript concepts like JSObjects, JSArrays, strings, and function arguments. I provide JavaScript examples where relevant (e.g., object creation, array manipulation, string operations).
    * **Code Logic Inference:** I provide input and output examples for tests with clear logic (e.g., `AllocateJSObjectFromMap`, `AllocationFoldingCSA`).
    * **Common Programming Errors:**  The `PopAndReturn` tests highlight a potential error of using `PopAndReturn` incorrectly in certain builtin types.
    * **Part 3 of 6:** I acknowledge this and summarize the functionality of this specific part.

By following these steps, I can systematically analyze the code and generate a comprehensive summary of its functionality, addressing all the specific instructions in the prompt.
`v8/test/cctest/test-code-stub-assembler.cc` is a C++ source file within the V8 JavaScript engine project. As the name suggests, it contains **unit tests for the `CodeStubAssembler` (CSA)**. The CodeStubAssembler is a low-level API in V8 used to generate machine code for various runtime functions and built-in operations.

Here's a breakdown of the functionalities demonstrated in this specific part of the file:

**Core Functionality: Testing CodeStubAssembler Operations**

This section of the test file focuses on verifying the correctness of several CSA functionalities related to:

* **Object Allocation:**
    * **`AllocateJSObjectFromMapCSA`:** Tests the allocation of JavaScript objects using a provided `Map` (which defines the object's structure). It checks if the allocated object has the correct map, properties, and elements. It also handles the specific case of allocating JS arrays, ensuring the `length` property is initialized.
    * **`AllocationFoldingCSA`:**  Tests the allocation of `FixedArray` and `ByteArray` objects. It likely verifies that subsequent allocations are placed contiguously in memory (allocation folding) when possible, optimizing memory usage. It also checks memory alignment.
    * **Dictionary Allocation (`AllocateNameDictionary`, `AllocateOrderedNameDictionary`, `AllocateOrderedHashSet`, `AllocateOrderedHashMap`):**  Tests the allocation of different types of dictionaries (hash tables) used by V8 for storing object properties and other data. It compares the memory layout of dictionaries created using the CSA with those created using standard V8 API calls.

* **Stack Manipulation and Function Returns:**
    * **`PopAndReturnFromJSBuiltinWithStackParameters` and `PopAndReturnFromTFCBuiltinWithStackParameters`:** These tests verify that `PopAndReturn` (a CSA operation to return from a function while adjusting the stack) is **not allowed** in specific types of built-in functions (JS builtins and TurboFan call-style builtins) that have declared stack parameters. This is a safety check to prevent stack corruption.
    * **`PopAndReturnConstant` and `PopAndReturnVariable`:** These tests verify the functionality of `PopAndReturn` for returning a constant value. They also include checks to ensure that the stack pointer remains consistent before and after the function call, preventing stack imbalances.

* **String Manipulation:**
    * **`OneToTwoByteStringCopy`, `OneToOneByteStringCopy`, `OneToOneByteStringCopyNonZeroStart`, `TwoToTwoByteStringCopy`:** These tests verify the `CopyStringCharacters` CSA operation for copying characters between strings with different encodings (one-byte and two-byte) and with different starting offsets. This is crucial for efficient string manipulation in V8.

* **Accessing Function Arguments:**
    * **`Arguments`:** Tests the `CodeStubArguments` helper class, which provides an interface to access the arguments passed to a function implemented using CSA. It checks if arguments can be accessed correctly by index.
    * **`ArgumentsForEach`:** Tests the `ForEach` method of `CodeStubArguments`, allowing iteration over the function's arguments.

* **Debugging:**
    * **`IsDebugActive`:** Tests the `IsDebugActive` CSA operation, which allows code to check if the JavaScript debugger is currently active.

* **Built-in Function Calls:**
    * **`CallBuiltin` and `TailCallBuiltin`:** These tests demonstrate how to call other built-in V8 functions from CSA code. `CallBuiltin` performs a regular call, while `TailCallBuiltin` performs a tail call optimization.

* **Array Manipulation:**
    * **`AppendJSArray`:** Tests a more complex scenario involving appending elements to a JavaScript array of a specific element kind. It checks the array's length, elements, and element kind after appending.

**Relation to JavaScript and Examples:**

Many of these tests directly relate to fundamental JavaScript operations:

* **Object Creation:** `AllocateJSObjectFromMapCSA` tests the underlying mechanism for creating JavaScript objects (like `{}`) in V8.
   ```javascript
   // Corresponding JavaScript:
   const obj = {};
   const arr = [];
   ```

* **Array Allocation and Manipulation:** `AllocationFoldingCSA` and `AppendJSArray` relate to how JavaScript arrays are created and how elements are added.
   ```javascript
   // Corresponding JavaScript:
   const myArray = [1, 2, 3];
   myArray.push(4);
   ```

* **String Operations:** The string copy tests (`OneToTwoByteStringCopy`, etc.) are about the low-level implementation of string manipulation.
   ```javascript
   // Corresponding JavaScript:
   const str1 = "abcde";
   const str2 = "fghij";
   const combined = str1 + str2; // Or manual string manipulation
   ```

* **Function Arguments:** The `Arguments` tests are about how JavaScript functions access their arguments.
   ```javascript
   // Corresponding JavaScript:
   function myFunction(a, b, c) {
     console.log(arguments[0]); // Accessing arguments
   }
   myFunction(12, 13, 14);
   ```

* **Debugging:** `IsDebugActive` is relevant to how JavaScript debuggers interact with the V8 runtime.

**Code Logic Inference (Example: `AllocateJSObjectFromMapCSA`)**

**Assumption:** The input `map` parameter determines if a JS array is being allocated.

**Input:**
* `map`: A `Handle<Map>` representing the map of a regular JavaScript object (e.g., `isolate->object_function()->initial_map()`).
* `properties`: An empty `FixedArray`.
* `elements`: An empty `FixedArray`.

**Output:**
* A `JSObject` with the provided `map`, empty `properties`, and empty `elements`. The `length` field will **not** be set explicitly because the map is not for a JS array.

**Input:**
* `map`: A `Handle<Map>` representing the map of a JavaScript array (e.g., `isolate->array_function()->initial_map()`).
* `properties`: An empty `FixedArray`.
* `elements`: An empty `FixedArray`.

**Output:**
* A `JSArray` (which is a subclass of `JSObject`) with the provided `map`, empty `properties`, and empty `elements`. The `length` field will be explicitly set to `0`.

**Common Programming Errors (Illustrative Example based on `PopAndReturn` tests):**

A common programming error related to stack manipulation (although less common in high-level JavaScript but relevant in low-level engine code) would be:

* **Incorrect stack pointer management:** Manually adjusting the stack pointer without proper care can lead to crashes, incorrect function returns, and security vulnerabilities. The `PopAndReturnFromJSBuiltinWithStackParameters` tests prevent a specific instance of this error by disallowing `PopAndReturn` in contexts where it could cause issues with declared stack parameters.

**归纳一下它的功能 (Summary of Functionality):**

This part of `v8/test/cctest/test-code-stub-assembler.cc` provides a comprehensive set of unit tests for various core functionalities of the V8 `CodeStubAssembler`. It verifies the correct implementation of operations related to:

* **Memory allocation:** for objects, arrays, and dictionaries.
* **Stack manipulation:** for function returns.
* **String manipulation:** for copying characters between strings.
* **Function argument access.**
* **Interaction with the V8 runtime:** checking debugger status and calling other built-in functions.
* **Specialized array operations:** like appending elements.

These tests are crucial for ensuring the reliability and correctness of the low-level code generation within the V8 engine. They help catch bugs and regressions in the `CodeStubAssembler` as the engine evolves.

### 提示词
```
这是目录为v8/test/cctest/test-code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    CodeAssemblerTester asm_tester(isolate, i::JSParameterCount(k
```