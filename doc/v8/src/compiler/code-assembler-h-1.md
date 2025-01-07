Response:
The user wants a summary of the provided C++ code snippet from `v8/src/compiler/code-assembler.h`. This is part 2 of 3, implying previous and subsequent parts exist and might be relevant for a complete understanding.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the core purpose:** The code snippet is within `CodeAssembler`, suggesting it's responsible for generating machine code. The numerous `TNode<>` types and operations like `Load`, `Store`, `Branch`, `CallRuntime`, `CallBuiltin` strongly point towards this.

2. **Categorize the functionalities:** Reading through the methods, I can group them into logical categories:
    * **Control Flow:**  `Branch`, `Goto`, `Switch`
    * **Memory Access:** `Load`, `Store`, `LoadRoot`, `AtomicLoad`, `AtomicStore`
    * **Stack Operations:** `LoadFramePointer`, `LoadStackPointer`, `SetStackPointer`
    * **Arithmetic Operations:** `Int32Add`, `WordShl`, `IntPtrEqual`, etc.
    * **Function Calls:** `CallRuntime`, `TailCallRuntime`, `CallBuiltin`, `TailCallBuiltin`, `CallJSBuiltin`, `TailCallJSBuiltin`, `CallJS`, `ConstructJS`, `CallCFunction`
    * **Type Conversions/Casting:** `UncheckedCast`, `BitcastTaggedToWord`, `ChangeFloat64ToIntPtr`
    * **Utilities:**  `MemoryBarrier`

3. **Relate to Javascript (if applicable):**  The presence of `CallJSBuiltin`, `TailCallJSBuiltin`, `CallJS`, and `ConstructJS` clearly indicates interaction with Javascript. These methods are the bridge between the low-level code generation and high-level Javascript execution. Examples of how these might be used in Javascript can be constructed. For instance, `CallJSBuiltin` is used when calling built-in Javascript functions like `Array.push`.

4. **Consider Torque:** The prompt mentions `.tq` files. While this specific snippet is `.h`, the presence of `CodeAssemblerParameterizedLabel` and the overall structure are characteristic of Torque-generated code or code that Torque interacts with. It's worth mentioning this connection.

5. **Address specific requests:**
    * **Function listing:**  The categorization above serves this purpose.
    * **`.tq` connection:** Explained in step 4.
    * **Javascript examples:** Provide concrete examples for relevant functions.
    * **Code logic inference (input/output):**  Focus on simpler methods like arithmetic operations to demonstrate this. More complex control flow or function calls are harder to exemplify with simple input/output without a larger context.
    * **Common programming errors:** Think about typical mistakes when dealing with low-level operations like memory management (e.g., incorrect offsets, type mismatches, forgetting write barriers).

6. **Structure the summary:** Organize the information logically, starting with the high-level purpose and then delving into the categorized functionalities. Address the specific requests from the prompt.

7. **Review and refine:**  Ensure the summary is clear, concise, and accurate. Check for any missing information or areas that could be explained better. Given this is "part 2",  acknowledging the context of being part of a larger system is important.

**Self-Correction during the thought process:**

* **Initial thought:**  Focus only on the individual functions.
* **Correction:** Realized the importance of grouping functions by their purpose to provide a more comprehensive overview.

* **Initial thought:**  Provide very technical explanations of each method.
* **Correction:**  Shifted towards explaining the *purpose* and *usage* of the methods, making it more accessible.

* **Initial thought:**  Try to provide complex input/output examples for all methods.
* **Correction:**  Focused on simpler examples for basic operations and acknowledged the difficulty for more complex scenarios without more context.

* **Initial thought:**  Omit mentioning Torque since this is a `.h` file.
* **Correction:** Included the Torque connection due to the naming conventions and overall architecture, as the prompt specifically asked about it.

By following these steps, I can generate a detailed and informative summary that addresses all the user's requests.
Based on the provided C++ code snippet from `v8/src/compiler/code-assembler.h`, here's a breakdown of its functionalities, keeping in mind this is part 2 of 3:

**归纳一下它的功能 (Summary of its functions):**

This section of `code-assembler.h` primarily focuses on providing methods for **control flow manipulation, memory access, and basic arithmetic/bitwise operations** within the code assembly process. It also includes functionalities for **calling Runtime functions, built-in functions (both standard and JavaScript-linked), and even C functions.**

Here's a more detailed breakdown:

**1. Control Flow:**

* **Conditional Branching (`Branch`):**  Provides various overloads for branching execution based on a boolean condition. This allows jumping to different labeled sections of code depending on whether the condition is true or false. It supports passing arguments to the target labels.
* **Unconditional Jump (`Goto`):** Allows direct transfer of control to a specified label, potentially passing arguments.
* **Switch Statements (`Switch`):** Implements a switch-case like structure for branching based on an integer index.

**2. Memory Access:**

* **Loading Data (`Load`):** Offers a wide range of `Load` functions to read data from memory locations. These functions handle different data types (`TNode<>`), memory locations (base address, offset), and memory access semantics (e.g., atomic loads). Specific methods exist for loading tagged values (`LoadFullTagged`) and values from the root array (`LoadRoot`).
* **Storing Data (`Store`):** Provides functions to write data to memory locations, handling different data types, offsets, and write barrier requirements (for garbage collection). Specialized methods exist for storing tagged values without write barriers (`StoreFullTaggedNoWriteBarrier`).
* **Atomic Memory Operations (`AtomicLoad`, `AtomicStore`, `AtomicAdd`, etc.):** Includes functions for performing atomic operations on memory, ensuring thread safety in concurrent environments. These operations cover load, store, add, subtract, AND, OR, XOR, exchange, and compare-and-exchange.
* **Frame and Stack Pointer Access (`LoadFramePointer`, `LoadParentFramePointer`, `LoadStackPointer`, `SetStackPointer`):** Allows access to and manipulation of the current function's stack frame and the overall stack pointer. This is crucial for managing local variables and function call contexts.

**3. Basic Arithmetic and Bitwise Operations:**

* Provides a comprehensive set of functions for performing basic arithmetic operations (addition, subtraction, multiplication) and bitwise operations (AND, OR, XOR, NOT, shifts) on various integer types (`Int32T`, `Uint32T`, `IntPtrT`, `UintPtrT`, `Int64T`, `Uint64T`).
* Includes pairwise operations for 32-bit integers (`Int32PairAdd`, `Int32PairSub`).
* Offers comparisons between different integer types (`IntPtrEqual`, `WordEqual`, etc.).

**4. Function Calls:**

* **Runtime Function Calls (`CallRuntime`, `TailCallRuntime`):** Enables calling functions within the V8 runtime environment. `TailCallRuntime` is an optimization for function calls that occur as the last operation.
* **Built-in Function Calls (`CallBuiltin`, `TailCallBuiltin`, `CallBuiltinVoid`):**  Allows calling pre-defined V8 built-in functions (implemented in C++).
* **JavaScript Built-in Function Calls (`CallJSBuiltin`, `TailCallJSBuiltin`):**  Specifically designed for calling JavaScript built-in functions, handling argument setup and context.
* **Generic JavaScript Calls (`CallJS`, `ConstructJS`):** Provides mechanisms to call arbitrary JavaScript functions and construct new JavaScript objects.
* **Tail Calling JavaScript Code (`TailCallJSCode`):**  Optimized for tail calls to JavaScript code objects.
* **C Function Calls (`CallCFunction`, `CallCFunctionN`):** Facilitates calling native C functions from the generated code.

**5. Type Conversions and Casting:**

* **Casting (`UncheckedCast`):**  Performs type casting without runtime checks (use with caution).
* **Bitcasting (`BitcastTaggedToWord`):** Changes the interpretation of the underlying bits of a tagged value.
* **Conversions between numeric types (`ChangeFloat64ToIntPtr`, `TruncateFloat32ToInt32`, etc.):** Provides functions to convert between different numeric types like floats and integers.

**6. Miscellaneous:**

* **Memory Barrier (`MemoryBarrier`):**  Ensures that memory operations are ordered correctly, especially in multi-threaded scenarios.
* **Access to Root Register (`LoadPointerFromRootRegister`, `LoadUint8FromRootRegister`):** Allows loading values from the V8 root register, which holds pointers to important global objects.
* **Unaligned Loads (`UnalignedLoad`):**  Handles loading data from memory locations that might not be aligned to the size of the data type.
* **Optimized Memory Operations (`OptimizedAllocate`, `StoreToObject`, `OptimizedStoreField`, etc.):** Provides optimized functions for common memory operations on JavaScript objects, potentially leveraging Turbofan's optimizations.

**If `v8/src/compiler/code-assembler.h` ended with `.tq`, it would indeed be a V8 Torque source code file.** Torque is V8's domain-specific language for writing performance-critical built-in functions. The C++ code generated from Torque often utilizes the functionalities provided by `code-assembler.h`.

**Relationship to JavaScript with Examples:**

Many of the functionalities in this header directly support the execution of JavaScript code. Here are a few examples:

* **`CallJSBuiltin`:** When you call a built-in JavaScript method like `Array.push()`, the V8 compiler might generate code that uses `CallJSBuiltin` internally.

   ```javascript
   const arr = [1, 2, 3];
   arr.push(4); // Internally might use CallJSBuiltin to call the Array.prototype.push implementation.
   ```

* **`ConstructJS`:** When you create a new JavaScript object using the `new` keyword, `ConstructJS` might be involved.

   ```javascript
   const date = new Date(); // Internally might use ConstructJS to call the Date constructor.
   ```

* **`LoadFromObject` and `StoreToObject`:** Accessing properties of JavaScript objects involves loading and storing values at specific memory offsets.

   ```javascript
   const obj = { x: 10 };
   const value = obj.x; // Internally might use LoadFromObject to get the value of 'x'.
   obj.y = 20;        // Internally might use StoreToObject to set the value of 'y'.
   ```

* **`Branch`:**  JavaScript's `if` statements and conditional operators are implemented using branching logic.

   ```javascript
   const x = 5;
   if (x > 0) {
       console.log("Positive"); //  Internally, a Branch instruction would be used to jump here if the condition is true.
   } else {
       console.log("Not positive"); // Internally, a Branch instruction would be used to jump here if the condition is false.
   }
   ```

**Code Logic Inference with Assumptions:**

Let's take a simple example:

**Method:** `TNode<Int32T> Int32Add(TNode<Int32T> left, TNode<Int32T> right)`

**Assumption:**  We have two `TNode<Int32T>` representing integer values.

**Input:**
* `left`: A `TNode<Int32T>` representing the integer value `10`.
* `right`: A `TNode<Int32T>` representing the integer value `5`.

**Output:**
* The function would return a new `TNode<Int32T>` representing the integer value `15` (10 + 5).

**Common Programming Errors (Relating to low-level assembly-like operations):**

* **Incorrect Memory Offsets:**  Using the wrong offset when loading or storing data can lead to reading or writing to unintended memory locations, causing crashes or unpredictable behavior.

   ```c++
   // Assuming 'object' points to a structure with an integer at offset 4.
   TNode<Int32T> value = Load<Int32T>(MachineType::Int32(), object, IntPtrConstant(8)); // Error: Incorrect offset
   ```

* **Type Mismatches:**  Trying to load or store data with an incorrect type can lead to data corruption or errors.

   ```c++
   TNode<Int32T> int_value = Int32Constant(10);
   Store(object_ptr, int_value); // Error: If 'object_ptr' expects a different type.
   ```

* **Forgetting Write Barriers:** When storing pointers to objects on the heap, failing to use a write barrier can confuse the garbage collector, leading to memory leaks or premature garbage collection.

   ```c++
   TNode<JSObject> my_object = ...;
   StoreNoWriteBarrier(MachineRepresentation::kTagged, container_ptr, my_object); // Potential error: May need a write barrier.
   ```

* **Incorrectly Handling Atomic Operations:** Using atomic operations without understanding their memory ordering guarantees can lead to race conditions and data inconsistencies in multi-threaded applications.

This part of `code-assembler.h` provides the fundamental building blocks for generating low-level code within V8's compiler. It abstracts away the specific machine instructions and provides a more convenient and type-safe way to manipulate data and control flow. The functionalities detailed here are crucial for implementing JavaScript's semantics and achieving high performance.

Prompt: 
```
这是目录为v8/src/compiler/code-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/code-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
emblerParameterizedLabel<T...>* if_false, Args... args) {
    if_true->AddInputs(args...);
    if_false->AddInputs(args...);
    Branch(condition, if_true->plain_label(), if_false->plain_label());
  }
  template <class... T, class... U>
  void Branch(TNode<BoolT> condition,
              CodeAssemblerParameterizedLabel<T...>* if_true,
              std::vector<Node*> args_true,
              CodeAssemblerParameterizedLabel<U...>* if_false,
              std::vector<Node*> args_false) {
    if_true->AddInputsVector(std::move(args_true));
    if_false->AddInputsVector(std::move(args_false));
    Branch(condition, if_true->plain_label(), if_false->plain_label());
  }

  template <class... T, class... Args>
  void Goto(CodeAssemblerParameterizedLabel<T...>* label, Args... args) {
    label->AddInputs(args...);
    Goto(label->plain_label());
  }

  void Branch(TNode<BoolT> condition, const std::function<void()>& true_body,
              const std::function<void()>& false_body);
  void Branch(TNode<BoolT> condition, Label* true_label,
              const std::function<void()>& false_body);
  void Branch(TNode<BoolT> condition, const std::function<void()>& true_body,
              Label* false_label);

  void Switch(Node* index, Label* default_label, const int32_t* case_values,
              Label** case_labels, size_t case_count);

  // Access to the frame pointer.
  TNode<RawPtrT> LoadFramePointer();
  TNode<RawPtrT> LoadParentFramePointer();
  TNode<RawPtrT> StackSlotPtr(int size, int alignment);

#if V8_ENABLE_WEBASSEMBLY
  // Access to the stack pointer.
  TNode<RawPtrT> LoadStackPointer();
  void SetStackPointer(TNode<RawPtrT> ptr);
#endif  // V8_ENABLE_WEBASSEMBLY

  TNode<RawPtrT> LoadPointerFromRootRegister(TNode<IntPtrT> offset);
  TNode<Uint8T> LoadUint8FromRootRegister(TNode<IntPtrT> offset);

  // Load raw memory location.
  Node* Load(MachineType type, Node* base);
  template <class Type>
  TNode<Type> Load(MachineType type, TNode<RawPtr<Type>> base) {
    DCHECK(
        IsSubtype(type.representation(), MachineRepresentationOf<Type>::value));
    return UncheckedCast<Type>(Load(type, static_cast<Node*>(base)));
  }
  Node* Load(MachineType type, Node* base, Node* offset);
  template <class Type>
  TNode<Type> Load(Node* base) {
    return UncheckedCast<Type>(Load(MachineTypeOf<Type>::value, base));
  }
  template <class Type>
  TNode<Type> Load(Node* base, TNode<WordT> offset) {
    return UncheckedCast<Type>(Load(MachineTypeOf<Type>::value, base, offset));
  }
  template <class Type>
  TNode<Type> AtomicLoad(AtomicMemoryOrder order, TNode<RawPtrT> base,
                         TNode<WordT> offset) {
    return UncheckedCast<Type>(
        AtomicLoad(MachineTypeOf<Type>::value, order, base, offset));
  }
  template <class Type>
  TNode<Type> AtomicLoad64(AtomicMemoryOrder order, TNode<RawPtrT> base,
                           TNode<WordT> offset);
  // Load uncompressed tagged value from (most likely off JS heap) memory
  // location.
  TNode<Object> LoadFullTagged(Node* base);
  TNode<Object> LoadFullTagged(Node* base, TNode<IntPtrT> offset);

  Node* LoadFromObject(MachineType type, TNode<Object> object,
                       TNode<IntPtrT> offset);
  Node* LoadProtectedPointerFromObject(TNode<Object> object,
                                       TNode<IntPtrT> offset);

#ifdef V8_MAP_PACKING
  Node* PackMapWord(Node* value);
#endif

  // Load a value from the root array.
  // If map packing is enabled, LoadRoot for a root map returns the unpacked map
  // word (i.e., the map). Use LoadRootMapWord to obtain the packed map word
  // instead.
  TNode<Object> LoadRoot(RootIndex root_index);
  TNode<AnyTaggedT> LoadRootMapWord(RootIndex root_index);

  template <typename Type>
  TNode<Type> UnalignedLoad(TNode<RawPtrT> base, TNode<IntPtrT> offset) {
    MachineType mt = MachineTypeOf<Type>::value;
    return UncheckedCast<Type>(UnalignedLoad(mt, base, offset));
  }

  // Store value to raw memory location.
  void Store(Node* base, Node* value);
  void Store(Node* base, Node* offset, Node* value);
  void StoreEphemeronKey(Node* base, Node* offset, Node* value);
  void StoreNoWriteBarrier(MachineRepresentation rep, Node* base, Node* value);
  void StoreNoWriteBarrier(MachineRepresentation rep, Node* base, Node* offset,
                           Node* value);
  void UnsafeStoreNoWriteBarrier(MachineRepresentation rep, Node* base,
                                 Node* value);
  void UnsafeStoreNoWriteBarrier(MachineRepresentation rep, Node* base,
                                 Node* offset, Node* value);

  // Stores uncompressed tagged value to (most likely off JS heap) memory
  // location without write barrier.
  void StoreFullTaggedNoWriteBarrier(TNode<RawPtrT> base,
                                     TNode<Object> tagged_value);
  void StoreFullTaggedNoWriteBarrier(TNode<RawPtrT> base, TNode<IntPtrT> offset,
                                     TNode<Object> tagged_value);

  // Optimized memory operations that map to Turbofan simplified nodes.
  TNode<HeapObject> OptimizedAllocate(TNode<IntPtrT> size,
                                      AllocationType allocation);
  void StoreToObject(MachineRepresentation rep, TNode<Object> object,
                     TNode<IntPtrT> offset, Node* value,
                     StoreToObjectWriteBarrier write_barrier);
  void OptimizedStoreField(MachineRepresentation rep, TNode<HeapObject> object,
                           int offset, Node* value);
  void OptimizedStoreIndirectPointerField(TNode<HeapObject> object, int offset,
                                          IndirectPointerTag tag, Node* value);
  void OptimizedStoreIndirectPointerFieldNoWriteBarrier(
      TNode<HeapObject> object, int offset, IndirectPointerTag tag,
      Node* value);
  void OptimizedStoreFieldAssertNoWriteBarrier(MachineRepresentation rep,
                                               TNode<HeapObject> object,
                                               int offset, Node* value);
  void OptimizedStoreFieldUnsafeNoWriteBarrier(MachineRepresentation rep,
                                               TNode<HeapObject> object,
                                               int offset, Node* value);
  void OptimizedStoreMap(TNode<HeapObject> object, TNode<Map>);
  void AtomicStore(MachineRepresentation rep, AtomicMemoryOrder order,
                   TNode<RawPtrT> base, TNode<WordT> offset,
                   TNode<Word32T> value);
  // {value_high} is used for 64-bit stores on 32-bit platforms, must be
  // nullptr in other cases.
  void AtomicStore64(AtomicMemoryOrder order, TNode<RawPtrT> base,
                     TNode<WordT> offset, TNode<UintPtrT> value,
                     TNode<UintPtrT> value_high);

  TNode<Word32T> AtomicAdd(MachineType type, TNode<RawPtrT> base,
                           TNode<UintPtrT> offset, TNode<Word32T> value);
  template <class Type>
  TNode<Type> AtomicAdd64(TNode<RawPtrT> base, TNode<UintPtrT> offset,
                          TNode<UintPtrT> value, TNode<UintPtrT> value_high);

  TNode<Word32T> AtomicSub(MachineType type, TNode<RawPtrT> base,
                           TNode<UintPtrT> offset, TNode<Word32T> value);
  template <class Type>
  TNode<Type> AtomicSub64(TNode<RawPtrT> base, TNode<UintPtrT> offset,
                          TNode<UintPtrT> value, TNode<UintPtrT> value_high);

  TNode<Word32T> AtomicAnd(MachineType type, TNode<RawPtrT> base,
                           TNode<UintPtrT> offset, TNode<Word32T> value);
  template <class Type>
  TNode<Type> AtomicAnd64(TNode<RawPtrT> base, TNode<UintPtrT> offset,
                          TNode<UintPtrT> value, TNode<UintPtrT> value_high);

  TNode<Word32T> AtomicOr(MachineType type, TNode<RawPtrT> base,
                          TNode<UintPtrT> offset, TNode<Word32T> value);
  template <class Type>
  TNode<Type> AtomicOr64(TNode<RawPtrT> base, TNode<UintPtrT> offset,
                         TNode<UintPtrT> value, TNode<UintPtrT> value_high);

  TNode<Word32T> AtomicXor(MachineType type, TNode<RawPtrT> base,
                           TNode<UintPtrT> offset, TNode<Word32T> value);
  template <class Type>
  TNode<Type> AtomicXor64(TNode<RawPtrT> base, TNode<UintPtrT> offset,
                          TNode<UintPtrT> value, TNode<UintPtrT> value_high);

  // Exchange value at raw memory location
  TNode<Word32T> AtomicExchange(MachineType type, TNode<RawPtrT> base,
                                TNode<UintPtrT> offset, TNode<Word32T> value);
  template <class Type>
  TNode<Type> AtomicExchange64(TNode<RawPtrT> base, TNode<UintPtrT> offset,
                               TNode<UintPtrT> value,
                               TNode<UintPtrT> value_high);

  // Compare and Exchange value at raw memory location
  TNode<Word32T> AtomicCompareExchange(MachineType type, TNode<RawPtrT> base,
                                       TNode<WordT> offset,
                                       TNode<Word32T> old_value,
                                       TNode<Word32T> new_value);

  template <class Type>
  TNode<Type> AtomicCompareExchange64(TNode<RawPtrT> base, TNode<WordT> offset,
                                      TNode<UintPtrT> old_value,
                                      TNode<UintPtrT> new_value,
                                      TNode<UintPtrT> old_value_high,
                                      TNode<UintPtrT> new_value_high);

  void MemoryBarrier(AtomicMemoryOrder order);

  // Store a value to the root array.
  void StoreRoot(RootIndex root_index, TNode<Object> value);

// Basic arithmetic operations.
#define DECLARE_CODE_ASSEMBLER_BINARY_OP(name, ResType, Arg1Type, Arg2Type) \
  TNode<ResType> name(TNode<Arg1Type> a, TNode<Arg2Type> b);
  CODE_ASSEMBLER_BINARY_OP_LIST(DECLARE_CODE_ASSEMBLER_BINARY_OP)
#undef DECLARE_CODE_ASSEMBLER_BINARY_OP

  // Pairwise operations for 32bit.
  TNode<PairT<Word32T, Word32T>> Int32PairAdd(TNode<Word32T> lhs_lo_word,
                                              TNode<Word32T> lhs_hi_word,
                                              TNode<Word32T> rhs_lo_word,
                                              TNode<Word32T> rhs_hi_word);
  TNode<PairT<Word32T, Word32T>> Int32PairSub(TNode<Word32T> lhs_lo_word,
                                              TNode<Word32T> lhs_hi_word,
                                              TNode<Word32T> rhs_lo_word,
                                              TNode<Word32T> rhs_hi_word);

  TNode<UintPtrT> WordShr(TNode<UintPtrT> left, TNode<IntegralT> right) {
    return Unsigned(WordShr(static_cast<TNode<WordT>>(left), right));
  }
  TNode<IntPtrT> WordSar(TNode<IntPtrT> left, TNode<IntegralT> right) {
    return Signed(WordSar(static_cast<TNode<WordT>>(left), right));
  }
  TNode<IntPtrT> WordShl(TNode<IntPtrT> left, TNode<IntegralT> right) {
    return Signed(WordShl(static_cast<TNode<WordT>>(left), right));
  }
  TNode<UintPtrT> WordShl(TNode<UintPtrT> left, TNode<IntegralT> right) {
    return Unsigned(WordShl(static_cast<TNode<WordT>>(left), right));
  }

  TNode<Int32T> Word32Shl(TNode<Int32T> left, TNode<Int32T> right) {
    return Signed(Word32Shl(static_cast<TNode<Word32T>>(left), right));
  }
  TNode<Uint32T> Word32Shl(TNode<Uint32T> left, TNode<Uint32T> right) {
    return Unsigned(Word32Shl(static_cast<TNode<Word32T>>(left), right));
  }
  TNode<Uint32T> Word32Shr(TNode<Uint32T> left, TNode<Uint32T> right) {
    return Unsigned(Word32Shr(static_cast<TNode<Word32T>>(left), right));
  }
  TNode<Int32T> Word32Sar(TNode<Int32T> left, TNode<Int32T> right) {
    return Signed(Word32Sar(static_cast<TNode<Word32T>>(left), right));
  }

  TNode<Int64T> Word64Shl(TNode<Int64T> left, TNode<Int64T> right) {
    return Signed(Word64Shl(static_cast<TNode<Word64T>>(left), right));
  }
  TNode<Uint64T> Word64Shl(TNode<Uint64T> left, TNode<Uint64T> right) {
    return Unsigned(Word64Shl(static_cast<TNode<Word64T>>(left), right));
  }
  TNode<Uint64T> Word64Shr(TNode<Uint64T> left, TNode<Uint64T> right) {
    return Unsigned(Word64Shr(static_cast<TNode<Word64T>>(left), right));
  }
  TNode<Int64T> Word64Sar(TNode<Int64T> left, TNode<Int64T> right) {
    return Signed(Word64Sar(static_cast<TNode<Word64T>>(left), right));
  }

  TNode<Int64T> Word64And(TNode<Int64T> left, TNode<Int64T> right) {
    return Signed(Word64And(static_cast<TNode<Word64T>>(left), right));
  }
  TNode<Uint64T> Word64And(TNode<Uint64T> left, TNode<Uint64T> right) {
    return Unsigned(Word64And(static_cast<TNode<Word64T>>(left), right));
  }

  TNode<Int64T> Word64Xor(TNode<Int64T> left, TNode<Int64T> right) {
    return Signed(Word64Xor(static_cast<TNode<Word64T>>(left), right));
  }
  TNode<Uint64T> Word64Xor(TNode<Uint64T> left, TNode<Uint64T> right) {
    return Unsigned(Word64Xor(static_cast<TNode<Word64T>>(left), right));
  }

  TNode<Int64T> Word64Not(TNode<Int64T> value) {
    return Signed(Word64Not(static_cast<TNode<Word64T>>(value)));
  }
  TNode<Uint64T> Word64Not(TNode<Uint64T> value) {
    return Unsigned(Word64Not(static_cast<TNode<Word64T>>(value)));
  }

  TNode<IntPtrT> WordAnd(TNode<IntPtrT> left, TNode<IntPtrT> right) {
    return Signed(WordAnd(static_cast<TNode<WordT>>(left),
                          static_cast<TNode<WordT>>(right)));
  }
  TNode<UintPtrT> WordAnd(TNode<UintPtrT> left, TNode<UintPtrT> right) {
    return Unsigned(WordAnd(static_cast<TNode<WordT>>(left),
                            static_cast<TNode<WordT>>(right)));
  }

  TNode<Int32T> Word32And(TNode<Int32T> left, TNode<Int32T> right) {
    return Signed(Word32And(static_cast<TNode<Word32T>>(left),
                            static_cast<TNode<Word32T>>(right)));
  }
  TNode<Uint32T> Word32And(TNode<Uint32T> left, TNode<Uint32T> right) {
    return Unsigned(Word32And(static_cast<TNode<Word32T>>(left),
                              static_cast<TNode<Word32T>>(right)));
  }

  TNode<IntPtrT> WordOr(TNode<IntPtrT> left, TNode<IntPtrT> right) {
    return Signed(WordOr(static_cast<TNode<WordT>>(left),
                         static_cast<TNode<WordT>>(right)));
  }

  TNode<Int32T> Word32Or(TNode<Int32T> left, TNode<Int32T> right) {
    return Signed(Word32Or(static_cast<TNode<Word32T>>(left),
                           static_cast<TNode<Word32T>>(right)));
  }
  TNode<Uint32T> Word32Or(TNode<Uint32T> left, TNode<Uint32T> right) {
    return Unsigned(Word32Or(static_cast<TNode<Word32T>>(left),
                             static_cast<TNode<Word32T>>(right)));
  }

  TNode<BoolT> IntPtrEqual(TNode<WordT> left, TNode<WordT> right);
  TNode<BoolT> WordEqual(TNode<WordT> left, TNode<WordT> right);
  TNode<BoolT> WordNotEqual(TNode<WordT> left, TNode<WordT> right);
  TNode<BoolT> Word32Equal(TNode<Word32T> left, TNode<Word32T> right);
  TNode<BoolT> Word32NotEqual(TNode<Word32T> left, TNode<Word32T> right);
  TNode<BoolT> Word64Equal(TNode<Word64T> left, TNode<Word64T> right);
  TNode<BoolT> Word64NotEqual(TNode<Word64T> left, TNode<Word64T> right);

  TNode<IntPtrT> WordNot(TNode<IntPtrT> a) {
    return Signed(WordNot(static_cast<TNode<WordT>>(a)));
  }
  TNode<Int32T> Word32BitwiseNot(TNode<Int32T> a) {
    return Signed(Word32BitwiseNot(static_cast<TNode<Word32T>>(a)));
  }
  TNode<BoolT> Word32Or(TNode<BoolT> left, TNode<BoolT> right) {
    return UncheckedCast<BoolT>(Word32Or(static_cast<TNode<Word32T>>(left),
                                         static_cast<TNode<Word32T>>(right)));
  }
  TNode<BoolT> Word32And(TNode<BoolT> left, TNode<BoolT> right) {
    return UncheckedCast<BoolT>(Word32And(static_cast<TNode<Word32T>>(left),
                                          static_cast<TNode<Word32T>>(right)));
  }

  TNode<Int32T> Int32Add(TNode<Int32T> left, TNode<Int32T> right) {
    return Signed(Int32Add(static_cast<TNode<Word32T>>(left),
                           static_cast<TNode<Word32T>>(right)));
  }

  TNode<Uint32T> Uint32Add(TNode<Uint32T> left, TNode<Uint32T> right) {
    return Unsigned(Int32Add(static_cast<TNode<Word32T>>(left),
                             static_cast<TNode<Word32T>>(right)));
  }

  TNode<Uint32T> Uint32Sub(TNode<Uint32T> left, TNode<Uint32T> right) {
    return Unsigned(Int32Sub(static_cast<TNode<Word32T>>(left),
                             static_cast<TNode<Word32T>>(right)));
  }

  TNode<Int32T> Int32Sub(TNode<Int32T> left, TNode<Int32T> right) {
    return Signed(Int32Sub(static_cast<TNode<Word32T>>(left),
                           static_cast<TNode<Word32T>>(right)));
  }

  TNode<Int32T> Int32Mul(TNode<Int32T> left, TNode<Int32T> right) {
    return Signed(Int32Mul(static_cast<TNode<Word32T>>(left),
                           static_cast<TNode<Word32T>>(right)));
  }

  TNode<Uint32T> Uint32Mul(TNode<Uint32T> left, TNode<Uint32T> right) {
    return Unsigned(Int32Mul(static_cast<TNode<Word32T>>(left),
                             static_cast<TNode<Word32T>>(right)));
  }

  TNode<Int64T> Int64Add(TNode<Int64T> left, TNode<Int64T> right) {
    return Signed(Int64Add(static_cast<TNode<Word64T>>(left), right));
  }

  TNode<Uint64T> Uint64Add(TNode<Uint64T> left, TNode<Uint64T> right) {
    return Unsigned(Int64Add(static_cast<TNode<Word64T>>(left), right));
  }

  TNode<Int64T> Int64Sub(TNode<Int64T> left, TNode<Int64T> right) {
    return Signed(Int64Sub(static_cast<TNode<Word64T>>(left), right));
  }

  TNode<Uint64T> Uint64Sub(TNode<Uint64T> left, TNode<Uint64T> right) {
    return Unsigned(Int64Sub(static_cast<TNode<Word64T>>(left), right));
  }

  TNode<Int64T> Int64Mul(TNode<Int64T> left, TNode<Int64T> right) {
    return Signed(Int64Mul(static_cast<TNode<Word64T>>(left), right));
  }

  TNode<Uint64T> Uint64Mul(TNode<Uint64T> left, TNode<Uint64T> right) {
    return Unsigned(Int64Mul(static_cast<TNode<Word64T>>(left), right));
  }

  TNode<IntPtrT> IntPtrAdd(TNode<IntPtrT> left, TNode<IntPtrT> right) {
    return Signed(IntPtrAdd(static_cast<TNode<WordT>>(left),
                            static_cast<TNode<WordT>>(right)));
  }
  TNode<IntPtrT> IntPtrSub(TNode<IntPtrT> left, TNode<IntPtrT> right) {
    return Signed(IntPtrSub(static_cast<TNode<WordT>>(left),
                            static_cast<TNode<WordT>>(right)));
  }
  TNode<IntPtrT> IntPtrMul(TNode<IntPtrT> left, TNode<IntPtrT> right) {
    return Signed(IntPtrMul(static_cast<TNode<WordT>>(left),
                            static_cast<TNode<WordT>>(right)));
  }
  TNode<UintPtrT> UintPtrAdd(TNode<UintPtrT> left, TNode<UintPtrT> right) {
    return Unsigned(IntPtrAdd(static_cast<TNode<WordT>>(left),
                              static_cast<TNode<WordT>>(right)));
  }
  TNode<UintPtrT> UintPtrSub(TNode<UintPtrT> left, TNode<UintPtrT> right) {
    return Unsigned(IntPtrSub(static_cast<TNode<WordT>>(left),
                              static_cast<TNode<WordT>>(right)));
  }
  TNode<RawPtrT> RawPtrAdd(TNode<RawPtrT> left, TNode<IntPtrT> right) {
    return ReinterpretCast<RawPtrT>(IntPtrAdd(left, right));
  }
  TNode<RawPtrT> RawPtrSub(TNode<RawPtrT> left, TNode<IntPtrT> right) {
    return ReinterpretCast<RawPtrT>(IntPtrSub(left, right));
  }
  TNode<IntPtrT> RawPtrSub(TNode<RawPtrT> left, TNode<RawPtrT> right) {
    return Signed(IntPtrSub(static_cast<TNode<WordT>>(left),
                            static_cast<TNode<WordT>>(right)));
  }

  TNode<WordT> WordShl(TNode<WordT> value, int shift);
  TNode<WordT> WordShr(TNode<WordT> value, int shift);
  TNode<WordT> WordSar(TNode<WordT> value, int shift);
  TNode<IntPtrT> WordShr(TNode<IntPtrT> value, int shift) {
    return UncheckedCast<IntPtrT>(WordShr(TNode<WordT>(value), shift));
  }
  TNode<IntPtrT> WordSar(TNode<IntPtrT> value, int shift) {
    return UncheckedCast<IntPtrT>(WordSar(TNode<WordT>(value), shift));
  }
  TNode<Word32T> Word32Shr(TNode<Word32T> value, int shift);
  TNode<Word32T> Word32Sar(TNode<Word32T> value, int shift);

  // Convenience overloads.
  TNode<Int32T> Int32Sub(TNode<Int32T> left, int right) {
    return Int32Sub(left, Int32Constant(right));
  }
  TNode<Word32T> Word32And(TNode<Word32T> left, int right) {
    return Word32And(left, Int32Constant(right));
  }
  TNode<Int32T> Word32Shl(TNode<Int32T> left, int right) {
    return Word32Shl(left, Int32Constant(right));
  }
  TNode<BoolT> Word32Equal(TNode<Word32T> left, int right) {
    return Word32Equal(left, Int32Constant(right));
  }

// Unary
#define DECLARE_CODE_ASSEMBLER_UNARY_OP(name, ResType, ArgType) \
  TNode<ResType> name(TNode<ArgType> a);
  CODE_ASSEMBLER_UNARY_OP_LIST(DECLARE_CODE_ASSEMBLER_UNARY_OP)
#undef DECLARE_CODE_ASSEMBLER_UNARY_OP

  template <class Dummy = void>
  TNode<IntPtrT> BitcastTaggedToWord(TNode<Smi> node) {
    static_assert(sizeof(Dummy) < 0,
                  "Should use BitcastTaggedToWordForTagAndSmiBits instead.");
  }

  // Changes a double to an inptr_t for pointer arithmetic outside of Smi range.
  // Assumes that the double can be exactly represented as an int.
  TNode<IntPtrT> ChangeFloat64ToIntPtr(TNode<Float64T> value);
  TNode<UintPtrT> ChangeFloat64ToUintPtr(TNode<Float64T> value);
  // Same in the opposite direction.
  TNode<Float64T> ChangeUintPtrToFloat64(TNode<UintPtrT> value);

  // Changes an intptr_t to a double, e.g. for storing an element index
  // outside Smi range in a HeapNumber. Lossless on 32-bit,
  // rounds on 64-bit (which doesn't affect valid element indices).
  TNode<Float64T> RoundIntPtrToFloat64(Node* value);
  // No-op on 32-bit, otherwise zero extend.
  TNode<UintPtrT> ChangeUint32ToWord(TNode<Word32T> value);
  // No-op on 32-bit, otherwise sign extend.
  TNode<IntPtrT> ChangeInt32ToIntPtr(TNode<Word32T> value);

  // Truncates a float to a 32-bit integer. If the float is outside of 32-bit
  // range, make sure that overflow detection is easy. In particular, return
  // int_min instead of int_max on arm platforms by using parameter
  // kSetOverflowToMin.
  TNode<Int32T> TruncateFloat32ToInt32(TNode<Float32T> value);
  TNode<Int64T> TruncateFloat64ToInt64(TNode<Float64T> value);

  // Projections
  template <int index, class T1, class T2>
  TNode<typename std::tuple_element<index, std::tuple<T1, T2>>::type>
  Projection(TNode<PairT<T1, T2>> value) {
    return UncheckedCast<
        typename std::tuple_element<index, std::tuple<T1, T2>>::type>(
        Projection(index, value));
  }

  // Calls
  template <class T = Object, class... TArgs>
  TNode<T> CallRuntime(Runtime::FunctionId function, TNode<Object> context,
                       TArgs... args) {
    return UncheckedCast<T>(CallRuntimeImpl(
        function, context, {implicit_cast<TNode<Object>>(args)...}));
  }

  template <class... TArgs>
  void TailCallRuntime(Runtime::FunctionId function, TNode<Object> context,
                       TArgs... args) {
    int argc = static_cast<int>(sizeof...(args));
    TNode<Int32T> arity = Int32Constant(argc);
    return TailCallRuntimeImpl(function, arity, context,
                               {implicit_cast<TNode<Object>>(args)...});
  }

  template <class... TArgs>
  void TailCallRuntime(Runtime::FunctionId function, TNode<Int32T> arity,
                       TNode<Object> context, TArgs... args) {
    return TailCallRuntimeImpl(function, arity, context,
                               {implicit_cast<TNode<Object>>(args)...});
  }

  Builtin builtin();

  // If the current code is running on a secondary stack, move the stack pointer
  // to the central stack (but not the frame pointer) and adjust the stack
  // limit. Returns the old stack pointer, or nullptr if no switch was
  // performed.
  TNode<RawPtrT> SwitchToTheCentralStackIfNeeded();
  TNode<RawPtrT> SwitchToTheCentralStack();
  // Switch the SP back to the secondary stack after switching to the central
  // stack.
  void SwitchFromTheCentralStack(TNode<RawPtrT> old_sp);

  //
  // If context passed to CallBuiltin is nullptr, it won't be passed to the
  // builtin.
  //
  template <typename T = Object, class... TArgs>
  TNode<T> CallBuiltin(Builtin id, TNode<Object> context, TArgs... args) {
    DCHECK_WITH_MSG(!Builtins::HasJSLinkage(id), "Use CallJSBuiltin instead");
    TNode<RawPtrT> old_sp;
#if V8_ENABLE_WEBASSEMBLY
    bool maybe_needs_switch = wasm::BuiltinLookup::IsWasmBuiltinId(builtin()) &&
                              !wasm::BuiltinLookup::IsWasmBuiltinId(id);
    if (maybe_needs_switch) {
      old_sp = SwitchToTheCentralStackIfNeeded();
    }
#endif
    Callable callable = Builtins::CallableFor(isolate(), id);
    TNode<Code> target = HeapConstantNoHole(callable.code());
    TNode<T> call =
        CallStub<T>(callable.descriptor(), target, context, args...);
#if V8_ENABLE_WEBASSEMBLY
    if (maybe_needs_switch) {
      SwitchFromTheCentralStack(old_sp);
    }
#endif
    return call;
  }

  template <class... TArgs>
  void CallBuiltinVoid(Builtin id, TNode<Object> context, TArgs... args) {
    DCHECK_WITH_MSG(!Builtins::HasJSLinkage(id), "Use CallJSBuiltin instead");
    Callable callable = Builtins::CallableFor(isolate(), id);
    TNode<Code> target = HeapConstantNoHole(callable.code());
    CallStubR(StubCallMode::kCallCodeObject, callable.descriptor(), target,
              context, args...);
  }

  template <class... TArgs>
  void TailCallBuiltin(Builtin id, TNode<Object> context, TArgs... args) {
    DCHECK_WITH_MSG(!Builtins::HasJSLinkage(id),
                    "Use TailCallJSBuiltin instead");
    Callable callable = Builtins::CallableFor(isolate(), id);
    TNode<Code> target = HeapConstantNoHole(callable.code());
    TailCallStub(callable.descriptor(), target, context, args...);
  }

  //
  // If context passed to CallStub is nullptr, it won't be passed to the stub.
  //

  template <class T = Object, class... TArgs>
  TNode<T> CallStub(const CallInterfaceDescriptor& descriptor,
                    TNode<Code> target, TNode<Object> context, TArgs... args) {
    return UncheckedCast<T>(CallStubR(StubCallMode::kCallCodeObject, descriptor,
                                      target, context, args...));
  }

  template <class T = Object, class... TArgs>
  TNode<T> CallBuiltinPointer(const CallInterfaceDescriptor& descriptor,
                              TNode<BuiltinPtr> target, TNode<Object> context,
                              TArgs... args) {
    return UncheckedCast<T>(CallStubR(StubCallMode::kCallBuiltinPointer,
                                      descriptor, target, context, args...));
  }

  template <class... TArgs>
  void TailCallStub(const CallInterfaceDescriptor& descriptor,
                    TNode<Code> target, TNode<Object> context, TArgs... args) {
    TailCallStubImpl(descriptor, target, context, {args...});
  }

  template <class... TArgs>
  void TailCallBytecodeDispatch(const CallInterfaceDescriptor& descriptor,
                                TNode<RawPtrT> target, TArgs... args);

  template <class... TArgs>
  void TailCallBuiltinThenBytecodeDispatch(Builtin builtin, Node* context,
                                           TArgs... args) {
    Callable callable = Builtins::CallableFor(isolate(), builtin);
    TNode<Code> target = HeapConstantNoHole(callable.code());
    TailCallStubThenBytecodeDispatchImpl(callable.descriptor(), target, context,
                                         {args...});
  }

  // A specialized version of CallBuiltin for builtins with JS linkage.
  // This for example takes care of computing and supplying the argument count.
  template <class... TArgs>
  TNode<Object> CallJSBuiltin(Builtin builtin, TNode<Context> context,
                              TNode<Object> function,
                              std::optional<TNode<Object>> new_target,
                              TNode<Object> receiver, TArgs... args) {
    DCHECK(Builtins::HasJSLinkage(builtin));
    // The receiver is also passed on the stack so needs to be included.
    DCHECK_EQ(Builtins::GetStackParameterCount(builtin), 1 + sizeof...(args));
    Callable callable = Builtins::CallableFor(isolate(), builtin);
    int argc = JSParameterCount(static_cast<int>(sizeof...(args)));
    TNode<Int32T> arity = Int32Constant(argc);
    TNode<JSDispatchHandleT> dispatch_handle = UncheckedCast<JSDispatchHandleT>(
        Uint32Constant(kInvalidDispatchHandle));
    TNode<Code> target = HeapConstantNoHole(callable.code());
    return CAST(CallJSStubImpl(callable.descriptor(), target, context, function,
                               new_target, arity, dispatch_handle,
                               {receiver, args...}));
  }

  // A specialized version of TailCallBuiltin for builtins with JS linkage.
  // The JS arguments (including receiver) must already be on the stack.
  void TailCallJSBuiltin(Builtin id, TNode<Object> context,
                         TNode<Object> function, TNode<Object> new_target,
                         TNode<Int32T> arg_count,
                         TNode<JSDispatchHandleT> dispatch_handle) {
    DCHECK(Builtins::HasJSLinkage(id));
    Callable callable = Builtins::CallableFor(isolate(), id);
    TNode<Code> target = HeapConstantNoHole(callable.code());
#ifdef V8_ENABLE_LEAPTIERING
    TailCallStub(callable.descriptor(), target, context, function, new_target,
                 arg_count, dispatch_handle);
#else
    TailCallStub(callable.descriptor(), target, context, function, new_target,
                 arg_count);
#endif
  }

  // Call the given JavaScript callable through one of the JS Call builtins.
  template <class... TArgs>
  TNode<Object> CallJS(Builtin builtin, TNode<Context> context,
                       TNode<Object> function, TNode<Object> receiver,
                       TArgs... args) {
    DCHECK(Builtins::IsAnyCall(builtin));
    Callable callable = Builtins::CallableFor(isolate(), builtin);
    int argc = JSParameterCount(static_cast<int>(sizeof...(args)));
    TNode<Int32T> arity = Int32Constant(argc);
    TNode<Code> target = HeapConstantNoHole(callable.code());
    return CAST(CallJSStubImpl(callable.descriptor(), target, context, function,
                               std::nullopt, arity, std::nullopt,
                               {receiver, args...}));
  }

  // Construct the given JavaScript callable through a JS Construct builtin.
  template <class... TArgs>
  TNode<Object> ConstructJS(Builtin builtin, TNode<Context> context,
                            TNode<Object> function, TNode<Object> new_target,
                            TArgs... args) {
    // Consider creating a Builtins::IsAnyConstruct if we ever expect other
    // Construct builtins here.
    DCHECK_EQ(builtin, Builtin::kConstruct);
    Callable callable = Builtins::CallableFor(isolate(), builtin);
    int argc = JSParameterCount(static_cast<int>(sizeof...(args)));
    TNode<Int32T> arity = Int32Constant(argc);
    TNode<Object> receiver = LoadRoot(RootIndex::kUndefinedValue);
    TNode<Code> target = HeapConstantNoHole(callable.code());
    return CAST(CallJSStubImpl(callable.descriptor(), target, context, function,
                               new_target, arity, std::nullopt,
                               {receiver, args...}));
  }

  // Tailcalls to the given code object with JSCall linkage. The JS arguments
  // (including receiver) are supposed to be already on the stack.
  // This is a building block for implementing trampoline stubs that are
  // installed instead of code objects with JSCall linkage.
  // Note that no arguments adaption is going on here - all the JavaScript
  // arguments are left on the stack unmodified. Therefore, this tail call can
  // only be used after arguments adaptation has been performed already.
  void TailCallJSCode(TNode<Code> code, TNode<Context> context,
                      TNode<JSFunction> function, TNode<Object> new_target,
                      TNode<Int32T> arg_count,
                      TNode<JSDispatchHandleT> dispatch_handle);

  Node* CallCFunctionN(Signature<MachineType>* signature, int input_count,
                       Node* const* inputs);

  // Type representing C function argument with type info.
  using CFunctionArg = std::pair<MachineType, Node*>;

  // Call to a C function.
  template <class... CArgs>
  Node* CallCFunction(Node* function, std::optional<MachineType> return_type,
                      CArgs... cargs) {
    static_assert(
        std::conjunction_v<std::is_convertible<CArgs, CFunctionArg>...>,
        "invalid argument types");
    return CallCFunction(function, return_type, {cargs...});
  }

  // Call to a C function without a function discriptor on AIX.
  template <class... CArgs>
  Node* CallCFunctionWithoutFunctionDescriptor(Node* function,
                                               MachineType return_type,
                                               CArgs... cargs) {
    static_assert(
        std::conjunction_v<std::is_convertible<CArgs, CFunctionArg>...>
"""


```