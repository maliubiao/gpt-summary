Response:
Let's break down the thought process for analyzing the `wasm-interpreter-runtime.h` file.

1. **Understand the Goal:** The request is to analyze a C++ header file within the V8 JavaScript engine related to the WebAssembly interpreter. The specific requests involve listing functionalities, checking if it's a Torque file, determining if it's related to JavaScript, providing examples if so, and covering potential programming errors and logic.

2. **Initial Scan and High-Level Understanding:**
   - Quickly read through the code to identify key classes, member functions, and data members.
   - Notice the `#ifndef` guards, include directives, and namespaces. These are standard C++ header file conventions.
   - The core class seems to be `WasmInterpreterRuntime`. Its constructor takes `WasmModule`, `Isolate`, `WasmInstanceObject`, and `CodeMap`. This suggests it's responsible for managing the runtime state of a WebAssembly instance during interpretation.

3. **Categorize Functionalities:**  Group the member functions based on their apparent purpose. Look for keywords and patterns in their names.
   - **Execution Control:**  Functions like `BeginExecution`, `ContinueExecution`, `ExecuteFunction`, `ExecuteIndirectCall`, `PrepareTailCall`. These clearly manage the flow of execution within the interpreter.
   - **Memory Management:** `MemoryGrow`, `MemorySize`, `MemoryInit`, `MemoryCopy`, `MemoryFill`. These deal with the WebAssembly linear memory.
   - **Table Operations:** `TableGet`, `TableSet`, `TableInit`, `TableCopy`, `TableGrow`, `TableSize`, `TableFill`, `UpdateIndirectCallTable`, `ClearIndirectCallCacheEntry`. These relate to WebAssembly tables (function pointers, etc.).
   - **Global Variables:** `GetGlobalAddress`, `GetGlobalRef`, `SetGlobalRef`. These are for accessing and modifying WebAssembly globals.
   - **Exception Handling:** `UnpackException`, `ThrowException`, `RethrowException`. Manages WebAssembly exceptions.
   - **Function Calls (Imports/Exports/Refs):** `ExecuteImportedFunction`, `ExecuteCallRef`, `GetFunctionRef`. Deals with calling functions across boundaries.
   - **Stack Management:** `GetInterpretedStack`, `UnwindCurrentStackFrame`, `PrintStack`. Provides access to and manipulation of the interpreter's stack.
   - **Atomic Operations:** `AllowsAtomicsWait`, `AtomicNotify`, `I32AtomicWait`, `I64AtomicWait`. Handles shared memory concurrency.
   - **Garbage Collection Helpers (GC):** `RttCanon`, `StructNewUninitialized`, `ArrayNewUninitialized`, `WasmArrayNewSegment`, `WasmArrayInitSegment`, `WasmArrayCopy`, `WasmJSToWasmObject`, `JSToWasmObject`, `WasmToJSObject`, `GetArrayType`, `GetWasmArrayRefElement`, `SubtypeCheck`, `RefIsEq`, `RefIsI31`, `RefIsStruct`, `RefIsArray`, `RefIsString`, `IsNullTypecheck`, `IsNull`, `GetNullValue`. This is a large section related to the new GC features in WebAssembly (references, structs, arrays, etc.).
   - **Data/Element Segment Handling:** `DataDrop`, `ElemDrop`. Deals with initialization data.
   - **Trapping:** `SetTrap`. Handles runtime errors.
   - **Tracing/Debugging:** (Conditional compilation with `V8_ENABLE_DRUMBRAKE_TRACING`). `Trace`, `TracePop`, `TracePush`, etc.

4. **Torque Check:** Look for the file extension. The prompt says to check if it ends in `.tq`. This file ends in `.h`, so it's *not* a Torque file.

5. **JavaScript Relationship:**  Consider how the interpreter interacts with the JavaScript environment.
   - The presence of `Isolate* isolate_` and `Handle` types strongly indicates interaction with V8's object model.
   - Functions like `ExecuteImportedFunction` and `CallExternalJSFunction` explicitly bridge the gap between WebAssembly and JavaScript.
   - `WasmToJSObject` and `JSToWasmObject` are clear indicators of value conversion.

6. **JavaScript Example:** Focus on the interop functions. A simple example would be calling a WebAssembly function from JavaScript or vice-versa. The `MemoryGrow` function is also relatively easy to illustrate from the JavaScript side.

7. **Code Logic Reasoning (Hypothetical Input/Output):** Choose a function with clear input and output. `MemoryGrow` is a good example. Define a starting state (initial memory size) and an input (delta pages) and predict the output (new memory size or -1 for failure).

8. **Common Programming Errors:** Think about the types of errors that arise when working with WebAssembly, especially in an interpreter setting.
   - **Memory Access Errors:** Going out of bounds.
   - **Type Errors:**  Mismatched function signatures, incorrect type assumptions during table operations.
   - **Null Pointer Dereferences:** When dealing with references.
   - **Stack Overflow:** Although less common in a high-level interpreter, it's still a potential issue.

9. **Review and Refine:**  Go back through the analysis and ensure accuracy and clarity. Organize the functionalities logically. Make sure the JavaScript example is correct and easy to understand. Check the hypothetical input/output for consistency. Ensure the common errors are relevant to the code.

**Self-Correction/Refinement Example During Thought Process:**

* **Initial Thought:**  "Many of these functions seem very low-level."
* **Refinement:** "Yes, but they're within the *interpreter*. The interpreter needs to handle the low-level details of WebAssembly execution. The interaction with JavaScript happens at a slightly higher level through import/export mechanisms, which this code also manages."

* **Initial Thought:** "Should I explain what each individual function does?"
* **Refinement:** "No, the request is to list the *functionalities*. Grouping related functions under broader categories like 'Memory Management' or 'Table Operations' is more effective for summarizing the purpose of the header file."

By following this systematic approach, combining code scanning with knowledge of WebAssembly and V8's architecture, we can effectively analyze the given header file and address all aspects of the request.
This header file, `v8/src/wasm/interpreter/wasm-interpreter-runtime.h`, defines the `WasmInterpreterRuntime` class, which is a crucial component for **executing WebAssembly code using the interpreter** within the V8 JavaScript engine.

Here's a breakdown of its functionalities:

**Core Interpreter Execution and Management:**

* **Initialization and Teardown:**
    * `WasmInterpreterRuntime(const WasmModule* module, Isolate* isolate, Handle<WasmInstanceObject> instance_object, WasmInterpreter::CodeMap* codemap);`:  Constructor to initialize the runtime environment for a specific WebAssembly module instance. It takes the module definition, the V8 isolate (the execution context), the instance object representing the module's state, and a code map for accessing bytecode.
    * `~WasmInterpreterRuntime();`: Destructor to clean up resources.
    * `Reset();`: Resets the runtime state, likely for re-execution or garbage collection.

* **Accessing Bytecode:**
    * `inline WasmBytecode* GetFunctionBytecode(uint32_t func_index);`: Retrieves the bytecode for a specific WebAssembly function.

* **Stack Inspection:**
    * `std::vector<WasmInterpreterStackEntry> GetInterpretedStack(Address frame_pointer) const;`: Provides a snapshot of the interpreter's call stack at a given frame pointer, useful for debugging and error reporting.
    * `int GetFunctionIndex(Address frame_pointer, int index) const;`:  Helps to identify the function associated with a specific stack frame.

* **Trap Handling:**
    * `void SetTrapFunctionIndex(int32_t func_index);`: Sets the index of a function to be called when a WebAssembly trap (runtime error) occurs.
    * `void SetTrap(TrapReason trap_reason, pc_t trap_pc);`: Records a trap with a specific reason and program counter.
    * `void SetTrap(TrapReason trap_reason, const uint8_t*& current_code);`: Records a trap based on the current instruction pointer.

* **Execution Control Flow:**
    * `void BeginExecution(WasmInterpreterThread* thread, uint32_t function_index, Address frame_pointer, uint8_t* interpreter_fp, uint32_t ref_stack_offset, const std::vector<WasmValue>* argument_values = nullptr);`: Initiates the execution of a WebAssembly function.
    * `void ContinueExecution(WasmInterpreterThread* thread, bool called_from_js);`: Resumes execution, potentially after a pause or an external call.
    * `void ExecuteFunction(const uint8_t*& code, uint32_t function_index, uint32_t current_stack_size, uint32_t ref_stack_fp_offset, uint32_t slot_offset, uint32_t return_slot_offset);`: Executes a specific WebAssembly function.
    * `void ExecuteImportedFunction(const uint8_t*& code, uint32_t func_index, uint32_t current_stack_size, uint32_t ref_stack_fp_offset, uint32_t slot_offset, uint32_t return_slot_offset);`: Executes a WebAssembly function that is imported from the host environment (JavaScript).
    * `void PrepareTailCall(const uint8_t*& code, uint32_t func_index, uint32_t current_stack_size, uint32_t return_slot_offset);`: Prepares for a tail call optimization.
    * `void ExecuteIndirectCall(const uint8_t*& current_code, uint32_t table_index, uint32_t sig_index, uint32_t entry_index, uint32_t stack_pos, uint32_t* sp, uint32_t ref_stack_fp_offset, uint32_t slot_offset, uint32_t return_slot_offset, bool is_tail_call);`: Executes an indirect function call through a WebAssembly table.
    * `void ExecuteCallRef(const uint8_t*& current_code, WasmRef func_ref, uint32_t sig_index, uint32_t stack_pos, uint32_t* sp, uint32_t ref_stack_fp_offset, uint32_t slot_offset, uint32_t return_slot_offset, bool is_tail_call);`: Executes a function call via a function reference.

* **Return Values:**
    * `const WasmValue& GetReturnValue(size_t index) const;`: Retrieves a return value from a function call.

**Memory Management:**

* **Linear Memory Access:**
    * `inline uint8_t* GetGlobalAddress(uint32_t index);`: Gets the memory address of a global variable.
    * `int32_t MemoryGrow(uint32_t delta_pages);`: Attempts to increase the size of the WebAssembly linear memory.
    * `inline uint64_t MemorySize() const;`: Returns the current size of the linear memory.
    * `inline bool IsMemory64() const;`: Indicates if the memory is 64-bit.
    * `inline uint8_t* GetMemoryStart() const;`: Returns the starting address of the linear memory.
    * `inline size_t GetMemorySize() const;`: Returns the size of the linear memory in bytes.

* **Memory Instructions:**
    * `bool MemoryInit(const uint8_t*& current_code, uint32_t data_segment_index, uint64_t dst, uint64_t src, uint64_t size);`: Implements the `memory.init` instruction, copying data from a data segment to linear memory.
    * `bool MemoryCopy(const uint8_t*& current_code, uint64_t dst, uint64_t src, uint64_t size);`: Implements the `memory.copy` instruction, copying within linear memory.
    * `bool MemoryFill(const uint8_t*& current_code, uint64_t dst, uint32_t value, uint64_t size);`: Implements the `memory.fill` instruction, filling memory with a constant value.

* **Atomic Operations:**
    * `bool AllowsAtomicsWait() const;`: Checks if atomic wait operations are allowed.
    * `int32_t AtomicNotify(uint64_t effective_index, int32_t val);`: Implements the `atomic.notify` instruction.
    * `int32_t I32AtomicWait(uint64_t effective_index, int32_t val, int64_t timeout);`: Implements the `i32.atomic.wait` instruction.
    * `int32_t I64AtomicWait(uint64_t effective_index, int64_t val, int64_t timeout);`: Implements the `i64.atomic.wait` instruction.

**Table Management:**

* **Table Access:**
    * `bool TableGet(const uint8_t*& current_code, uint32_t table_index, uint32_t entry_index, Handle<Object>* result);`: Implements the `table.get` instruction.
    * `void TableSet(const uint8_t*& current_code, uint32_t table_index, uint32_t entry_index, Handle<Object> ref);`: Implements the `table.set` instruction.

* **Table Manipulation:**
    * `void TableInit(const uint8_t*& current_code, uint32_t table_index, uint32_t element_segment_index, uint32_t dst, uint32_t src, uint32_t size);`: Implements the `table.init` instruction.
    * `void TableCopy(const uint8_t*& current_code, uint32_t dst_table_index, uint32_t src_table_index, uint32_t dst, uint32_t src, uint32_t size);`: Implements the `table.copy` instruction.
    * `uint32_t TableGrow(uint32_t table_index, uint32_t delta, Handle<Object> value);`: Implements the `table.grow` instruction.
    * `uint32_t TableSize(uint32_t table_index);`: Implements the `table.size` instruction.
    * `void TableFill(const uint8_t*& current_code, uint32_t table_index, uint32_t count, Handle<Object> value, uint32_t start);`: Implements the `table.fill` instruction.

* **Indirect Call Table Updates:**
    * `static void UpdateIndirectCallTable(Isolate* isolate, Handle<WasmInstanceObject> instance, uint32_t table_index);`: Updates the indirect call table based on changes in the module instance.
    * `static void ClearIndirectCallCacheEntry(Isolate* isolate, Handle<WasmInstanceObject> instance, uint32_t table_index, uint32_t entry_index);`: Clears a specific entry in the indirect call cache.

**Global Variables and References:**

* `inline Handle<Object> GetGlobalRef(uint32_t index) const;`: Retrieves a global variable as a V8 `Handle`.
* `inline void SetGlobalRef(uint32_t index, Handle<Object> ref) const;`: Sets the value of a global variable using a V8 `Handle`.
* `inline bool IsRefNull(Handle<Object> ref) const;`: Checks if a reference is null.
* `inline Handle<Object> GetFunctionRef(uint32_t index) const;`: Retrieves a function reference.
* `void StoreWasmRef(uint32_t ref_stack_index, const WasmRef& ref);`: Stores a WebAssembly reference onto the reference stack.
* `WasmRef ExtractWasmRef(uint32_t ref_stack_index);`: Retrieves a WebAssembly reference from the reference stack.

**Exception Handling:**

* `void UnpackException(uint32_t* sp, const WasmTag& tag, Handle<Object> exception_object, uint32_t first_param_slot_index, uint32_t first_param_ref_stack_index);`: Unpacks an exception object and prepares the stack for handling.
* `void ThrowException(const uint8_t*& code, uint32_t* sp, uint32_t tag_index);`: Throws a WebAssembly exception.
* `void RethrowException(const uint8_t*& code, uint32_t* sp, uint32_t catch_block_index);`: Rethrows a caught exception.

**Data and Element Segments:**

* `inline void DataDrop(uint32_t index);`: Implements the `data.drop` instruction.
* `inline void ElemDrop(uint32_t index);`: Implements the `elem.drop` instruction.

**Garbage Collection (GC) Helpers:**

These functions are used to interact with V8's garbage collector and manage WebAssembly's heap objects:

* `Handle<Map> RttCanon(uint32_t type_index) const;`: Gets the canonical representation of a Run-Time Type (RTT).
* `std::pair<Handle<WasmStruct>, const StructType*> StructNewUninitialized(uint32_t index) const;`: Allocates an uninitialized WebAssembly struct.
* `std::pair<Handle<WasmArray>, const ArrayType*> ArrayNewUninitialized(uint32_t length, uint32_t array_index) const;`: Allocates an uninitialized WebAssembly array.
* `WasmRef WasmArrayNewSegment(uint32_t array_index, uint32_t segment_index, uint32_t offset, uint32_t length);`: Creates a new WebAssembly array from a segment.
* `bool WasmArrayInitSegment(uint32_t segment_index, WasmRef wasm_array, uint32_t array_offset, uint32_t segment_offset, uint32_t length);`: Initializes a portion of a WebAssembly array from a segment.
* `bool WasmArrayCopy(WasmRef dest_wasm_array, uint32_t dest_index, WasmRef src_wasm_array, uint32_t src_index, uint32_t length);`: Copies elements between WebAssembly arrays.
* `WasmRef WasmJSToWasmObject(WasmRef extern_ref, ValueType value_type, uint32_t canonical_index) const;`: Converts a JavaScript object to a WebAssembly object reference (with RTT).
* `WasmRef JSToWasmObject(WasmRef extern_ref, ValueType value_type) const;`: Converts a JavaScript object to a WebAssembly object reference.
* `WasmRef WasmToJSObject(WasmRef ref) const;`: Converts a WebAssembly object reference to a JavaScript object.
* `inline const ArrayType* GetArrayType(uint32_t array_index) const;`: Gets the type information for a WebAssembly array.
* `inline WasmRef GetWasmArrayRefElement(Tagged<WasmArray> array, uint32_t index) const;`: Gets an element from a WebAssembly array.
* `bool SubtypeCheck(const WasmRef obj, const ValueType obj_type, const Handle<Map> rtt, const ValueType rtt_type, bool null_succeeds) const;`: Checks if a WebAssembly reference is a subtype of a given RTT.
* `bool RefIsEq(const WasmRef obj, const ValueType obj_type, bool null_succeeds) const;`: Checks if two WebAssembly references are equal.
* `bool RefIsI31(const WasmRef obj, const ValueType obj_type, bool null_succeeds) const;`: Checks if a reference is an `i31ref`.
* `bool RefIsStruct(const WasmRef obj, const ValueType obj_type, bool null_succeeds) const;`: Checks if a reference is a struct reference.
* `bool RefIsArray(const WasmRef obj, const ValueType obj_type, bool null_succeeds) const;`: Checks if a reference is an array reference.
* `bool RefIsString(const WasmRef obj, const ValueType obj_type, bool null_succeeds) const;`: Checks if a reference is a string reference.
* `inline bool IsNullTypecheck(const WasmRef obj, const ValueType obj_type) const;`: Checks if a reference is null for typechecking purposes.
* `inline static bool IsNull(Isolate* isolate, const WasmRef obj, const ValueType obj_type);`: Checks if a reference is null.
* `inline Tagged<Object> GetNullValue(const ValueType obj_type) const;`: Gets the null value for a specific reference type.

**Utilities and Internal State:**

* `inline Isolate* GetIsolate() const { return isolate_; }`: Returns the V8 isolate.
* `void UnwindCurrentStackFrame(uint32_t* sp, uint32_t slot_offset, uint32_t rets_size, uint32_t args_size, uint32_t rets_refs, uint32_t args_refs, uint32_t ref_stack_fp_offset);`:  Adjusts the stack pointer when exiting a function.
* `void PrintStack(uint32_t* sp, RegMode reg_mode, int64_t r0, double fp0);`: Prints the interpreter's stack, likely for debugging.
* `static void UpdateMemoryAddress(Handle<WasmInstanceObject> instance);`: Updates cached memory addresses.
* `void ResetCurrentHandleScope();`: Resets the current V8 handle scope.
* `size_t TotalBytecodeSize() const { return codemap_->TotalBytecodeSize(); }`: Returns the total size of the bytecode.

**Conditional Tracing:**

* `#ifdef V8_ENABLE_DRUMBRAKE_TRACING`:  Sections of code for detailed tracing and debugging, likely used during development.

**Regarding the File Extension:**

The file ends with `.h`, which signifies a standard C++ header file. Therefore, **it is not a V8 Torque source code file**. Torque files have the `.tq` extension.

**Relationship with JavaScript and Examples:**

The `WasmInterpreterRuntime` plays a crucial role in the interaction between JavaScript and WebAssembly when using the interpreter. Here are some ways they relate, with JavaScript examples:

1. **Calling WebAssembly from JavaScript:**

   ```javascript
   const wasmBytes = new Uint8Array([...]); // Your WASM bytecode
   WebAssembly.instantiate(wasmBytes).then(result => {
     const wasmInstance = result.instance;
     const resultFromWasm = wasmInstance.exports.add(5, 10); // Calling an exported WASM function
     console.log(resultFromWasm); // Output: 15
   });
   ```

   In this scenario, when `wasmInstance.exports.add(5, 10)` is called, the V8 engine (if the interpreter is used) would involve `WasmInterpreterRuntime` to execute the `add` function within the WebAssembly module.

2. **Calling JavaScript functions from WebAssembly (Imports):**

   Assume your WASM code imports a JavaScript function:

   ```c++
   // Inside your WASM module (conceptually)
   import "env" "jsAlert" (func $jsAlert (param i32));

   export func callJsAlert(i32 val) call $jsAlert(val);
   ```

   And in your JavaScript:

   ```javascript
   const importObject = {
     env: {
       jsAlert: (value) => {
         alert("Value from WASM: " + value);
       },
     },
   };

   const wasmBytes = new Uint8Array([...]);
   WebAssembly.instantiate(wasmBytes, importObject).then(result => {
     const wasmInstance = result.instance;
     wasmInstance.exports.callJsAlert(42); // Calls the WASM function which then calls the JS import
   });
   ```

   When `wasmInstance.exports.callJsAlert(42)` is executed, the interpreter within `WasmInterpreterRuntime` would eventually encounter the call to the imported function `$jsAlert`. The `ExecuteImportedFunction` method (or similar logic) in `WasmInterpreterRuntime` would be responsible for bridging the execution to the JavaScript `jsAlert` function.

3. **Memory Interaction:**

   ```javascript
   const wasmBytes = new Uint8Array([...]);
   WebAssembly.instantiate(wasmBytes).then(result => {
     const wasmMemory = result.instance.exports.memory; // Get the WASM memory
     const buffer = new Uint32Array(wasmMemory.buffer);
     buffer[0] = 123; // Write to WASM memory from JavaScript

     const getValueFromWasm = result.instance.exports.getValueFromMemory();
     console.log(getValueFromWasm); // Might output 123 if getValueFromMemory reads from address 0
   });
   ```

   Functions like `MemoryGrow`, `GetMemoryStart`, and the memory access operations within `WasmInterpreterRuntime` are the underlying mechanisms that allow JavaScript to interact with the WebAssembly module's linear memory.

**Code Logic Reasoning (Hypothetical Input & Output):**

Let's consider the `MemoryGrow` function:

**Assumptions:**

* A `WasmInterpreterRuntime` instance exists for a WebAssembly module with an initial memory size of 1 page (65536 bytes).
* The maximum allowed memory size for the module is not exceeded by the growth.

**Input:** `delta_pages = 2`

**Expected Output:**

* The `MemoryGrow` function should successfully increase the memory size by 2 pages.
* The return value of `MemoryGrow` should be the *previous* number of pages, which is `1`.
* After the call, the `MemorySize()` function should return 3 pages (3 * 65536 bytes).

**Input (Failure Case):** `delta_pages = a very large number` such that the maximum memory limit is exceeded.

**Expected Output:**

* `MemoryGrow` should fail to allocate the requested memory.
* The return value of `MemoryGrow` should be `-1`.
* The memory size should remain at its previous value.

**Common Programming Errors:**

Users interacting with WebAssembly through JavaScript might encounter errors related to how the interpreter operates:

1. **Incorrect Function Signatures:** If the JavaScript code calls a WebAssembly function with the wrong number or types of arguments, the interpreter will likely throw a `TypeError` or a WebAssembly trap due to signature mismatch.

   ```javascript
   // Assume WASM export 'add' takes two i32 arguments
   wasmInstance.exports.add(5); // Error: Missing argument
   wasmInstance.exports.add("hello", 10); // Error: Incorrect argument type
   ```

2. **Out-of-Bounds Memory Access:** If WebAssembly code attempts to read or write to memory outside the allocated bounds, the interpreter will detect this and trigger a trap.

   ```javascript
   // Assume WASM has a memory of 1 page (65536 bytes)
   const buffer = new Uint8Array(wasmMemory.buffer);
   buffer[70000] = 10; // Error: Accessing memory beyond the allocated size
   ```

3. **Calling Non-Existent Exports:** Trying to call a function that is not exported from the WebAssembly module will result in an error in JavaScript.

   ```javascript
   // Assume WASM doesn't export a function named 'nonExistent'
   wasmInstance.exports.nonExistent(); // Error: undefined is not a function
   ```

4. **Type Mismatches with References:** When working with the reference types proposal in WebAssembly, passing JavaScript objects of the wrong type to WebAssembly functions expecting specific reference types will lead to traps or errors.

   ```javascript
   // Assume WASM import 'processObject' expects a 'externref'
   const notAnObject = 123;
   wasmInstance.exports.processObject(notAnObject); // Error or trap depending on the implementation
   ```

In summary, `v8/src/wasm/interpreter/wasm-interpreter-runtime.h` defines the core runtime environment for the WebAssembly interpreter in V8. It manages memory, tables, function calls, exceptions, and interacts closely with the V8 engine and JavaScript environment. While not a Torque file itself, it's a fundamental piece enabling the execution of WebAssembly code within the V8 ecosystem.

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter-runtime.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter-runtime.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_INTERPRETER_WASM_INTERPRETER_RUNTIME_H_
#define V8_WASM_INTERPRETER_WASM_INTERPRETER_RUNTIME_H_

#include <memory>
#include <vector>

#include "src/base/vector.h"
#include "src/execution/simulator.h"
#include "src/wasm/interpreter/wasm-interpreter.h"

namespace v8 {

namespace internal {
class WasmInstanceObject;

namespace wasm {
class InterpreterTracer;
class WasmBytecodeGenerator;
struct WasmTag;

class WasmInterpreterRuntime {
 public:
  WasmInterpreterRuntime(const WasmModule* module, Isolate* isolate,
                         Handle<WasmInstanceObject> instance_object,
                         WasmInterpreter::CodeMap* codemap);
  ~WasmInterpreterRuntime();

  void Reset();

  inline WasmBytecode* GetFunctionBytecode(uint32_t func_index);

  std::vector<WasmInterpreterStackEntry> GetInterpretedStack(
      Address frame_pointer) const;

  int GetFunctionIndex(Address frame_pointer, int index) const;

  void SetTrapFunctionIndex(int32_t func_index);

  inline Isolate* GetIsolate() const { return isolate_; }

  inline uint8_t* GetGlobalAddress(uint32_t index);
  inline Handle<Object> GetGlobalRef(uint32_t index) const;
  inline void SetGlobalRef(uint32_t index, Handle<Object> ref) const;

  int32_t MemoryGrow(uint32_t delta_pages);
  inline uint64_t MemorySize() const;
  inline bool IsMemory64() const;
  inline uint8_t* GetMemoryStart() const { return memory_start_; }
  inline size_t GetMemorySize() const;

  bool MemoryInit(const uint8_t*& current_code, uint32_t data_segment_index,
                  uint64_t dst, uint64_t src, uint64_t size);
  bool MemoryCopy(const uint8_t*& current_code, uint64_t dst, uint64_t src,
                  uint64_t size);
  bool MemoryFill(const uint8_t*& current_code, uint64_t dst, uint32_t value,
                  uint64_t size);

  bool AllowsAtomicsWait() const;
  int32_t AtomicNotify(uint64_t effective_index, int32_t val);
  int32_t I32AtomicWait(uint64_t effective_index, int32_t val, int64_t timeout);
  int32_t I64AtomicWait(uint64_t effective_index, int64_t val, int64_t timeout);

  bool TableGet(const uint8_t*& current_code, uint32_t table_index,
                uint32_t entry_index, Handle<Object>* result);
  void TableSet(const uint8_t*& current_code, uint32_t table_index,
                uint32_t entry_index, Handle<Object> ref);
  void TableInit(const uint8_t*& current_code, uint32_t table_index,
                 uint32_t element_segment_index, uint32_t dst, uint32_t src,
                 uint32_t size);
  void TableCopy(const uint8_t*& current_code, uint32_t dst_table_index,
                 uint32_t src_table_index, uint32_t dst, uint32_t src,
                 uint32_t size);
  uint32_t TableGrow(uint32_t table_index, uint32_t delta,
                     Handle<Object> value);
  uint32_t TableSize(uint32_t table_index);
  void TableFill(const uint8_t*& current_code, uint32_t table_index,
                 uint32_t count, Handle<Object> value, uint32_t start);

  static void UpdateIndirectCallTable(Isolate* isolate,
                                      Handle<WasmInstanceObject> instance,
                                      uint32_t table_index);
  static void ClearIndirectCallCacheEntry(Isolate* isolate,
                                          Handle<WasmInstanceObject> instance,
                                          uint32_t table_index,
                                          uint32_t entry_index);

  static void UpdateMemoryAddress(Handle<WasmInstanceObject> instance);

  inline void DataDrop(uint32_t index);
  inline void ElemDrop(uint32_t index);

  void UnpackException(uint32_t* sp, const WasmTag& tag,
                       Handle<Object> exception_object,
                       uint32_t first_param_slot_index,
                       uint32_t first_param_ref_stack_index);
  void ThrowException(const uint8_t*& code, uint32_t* sp, uint32_t tag_index);
  void RethrowException(const uint8_t*& code, uint32_t* sp,
                        uint32_t catch_block_index);

  void BeginExecution(WasmInterpreterThread* thread, uint32_t function_index,
                      Address frame_pointer, uint8_t* interpreter_fp,
                      uint32_t ref_stack_offset,
                      const std::vector<WasmValue>* argument_values = nullptr);
  void ContinueExecution(WasmInterpreterThread* thread, bool called_from_js);

  void ExecuteImportedFunction(const uint8_t*& code, uint32_t func_index,
                               uint32_t current_stack_size,
                               uint32_t ref_stack_fp_offset,
                               uint32_t slot_offset,
                               uint32_t return_slot_offset);

  void PrepareTailCall(const uint8_t*& code, uint32_t func_index,
                       uint32_t current_stack_size,
                       uint32_t return_slot_offset);

  void ExecuteFunction(const uint8_t*& code, uint32_t function_index,
                       uint32_t current_stack_size,
                       uint32_t ref_stack_fp_offset, uint32_t slot_offset,
                       uint32_t return_slot_offset);

  void ExecuteIndirectCall(const uint8_t*& current_code, uint32_t table_index,
                           uint32_t sig_index, uint32_t entry_index,
                           uint32_t stack_pos, uint32_t* sp,
                           uint32_t ref_stack_fp_offset, uint32_t slot_offset,
                           uint32_t return_slot_offset, bool is_tail_call);

  void ExecuteCallRef(const uint8_t*& current_code, WasmRef func_ref,
                      uint32_t sig_index, uint32_t stack_pos, uint32_t* sp,
                      uint32_t ref_stack_fp_offset, uint32_t slot_offset,
                      uint32_t return_slot_offset, bool is_tail_call);

  const WasmValue& GetReturnValue(size_t index) const {
    DCHECK_LT(index, function_result_.size());
    return function_result_[index];
  }

  inline bool IsRefNull(Handle<Object> ref) const;
  inline Handle<Object> GetFunctionRef(uint32_t index) const;
  void StoreWasmRef(uint32_t ref_stack_index, const WasmRef& ref);
  WasmRef ExtractWasmRef(uint32_t ref_stack_index);
  void UnwindCurrentStackFrame(uint32_t* sp, uint32_t slot_offset,
                               uint32_t rets_size, uint32_t args_size,
                               uint32_t rets_refs, uint32_t args_refs,
                               uint32_t ref_stack_fp_offset);

  void PrintStack(uint32_t* sp, RegMode reg_mode, int64_t r0, double fp0);

  void SetTrap(TrapReason trap_reason, pc_t trap_pc);
  void SetTrap(TrapReason trap_reason, const uint8_t*& current_code);

  // GC helpers.
  Handle<Map> RttCanon(uint32_t type_index) const;
  std::pair<Handle<WasmStruct>, const StructType*> StructNewUninitialized(
      uint32_t index) const;
  std::pair<Handle<WasmArray>, const ArrayType*> ArrayNewUninitialized(
      uint32_t length, uint32_t array_index) const;
  WasmRef WasmArrayNewSegment(uint32_t array_index, uint32_t segment_index,
                              uint32_t offset, uint32_t length);
  bool WasmArrayInitSegment(uint32_t segment_index, WasmRef wasm_array,
                            uint32_t array_offset, uint32_t segment_offset,
                            uint32_t length);
  bool WasmArrayCopy(WasmRef dest_wasm_array, uint32_t dest_index,
                     WasmRef src_wasm_array, uint32_t src_index,
                     uint32_t length);
  WasmRef WasmJSToWasmObject(WasmRef extern_ref, ValueType value_type,
                             uint32_t canonical_index) const;
  WasmRef JSToWasmObject(WasmRef extern_ref, ValueType value_type) const;
  WasmRef WasmToJSObject(WasmRef ref) const;

  inline const ArrayType* GetArrayType(uint32_t array_index) const;
  inline WasmRef GetWasmArrayRefElement(Tagged<WasmArray> array,
                                        uint32_t index) const;
  bool SubtypeCheck(const WasmRef obj, const ValueType obj_type,
                    const Handle<Map> rtt, const ValueType rtt_type,
                    bool null_succeeds) const;
  bool RefIsEq(const WasmRef obj, const ValueType obj_type,
               bool null_succeeds) const;
  bool RefIsI31(const WasmRef obj, const ValueType obj_type,
                bool null_succeeds) const;
  bool RefIsStruct(const WasmRef obj, const ValueType obj_type,
                   bool null_succeeds) const;
  bool RefIsArray(const WasmRef obj, const ValueType obj_type,
                  bool null_succeeds) const;
  bool RefIsString(const WasmRef obj, const ValueType obj_type,
                   bool null_succeeds) const;
  inline bool IsNullTypecheck(const WasmRef obj,
                              const ValueType obj_type) const;
  inline static bool IsNull(Isolate* isolate, const WasmRef obj,
                            const ValueType obj_type);
  inline Tagged<Object> GetNullValue(const ValueType obj_type) const;

  static int memory_start_offset();
  static int instruction_table_offset();

  size_t TotalBytecodeSize() const { return codemap_->TotalBytecodeSize(); }

  void ResetCurrentHandleScope();

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  void Trace(const char* format, ...);
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  // Stored in WasmExportedFunctionData::packed_args_size; used by
  // JSToWasmInterpreterWrapper and WasmToJSInterpreterWrapper builtins.
  // Note that the max size of the packed array of args is 16000, which fits
  // into 14 bits (kV8MaxWasmFunctionParams == 1000).
  static_assert(sizeof(Simd128) * kV8MaxWasmFunctionParams < (1 << 14));
  using PackedArgsSizeField = base::BitField<uint32_t, 0, 14>;
  using HasRefArgsField = base::BitField<bool, 14, 1>;
  using HasRefRetsField = base::BitField<bool, 15, 1>;

 private:
  ExternalCallResult CallImportedFunction(const uint8_t*& current_code,
                                          uint32_t function_index, uint32_t* sp,
                                          uint32_t current_stack_size,
                                          uint32_t ref_stack_fp_index,
                                          uint32_t current_slot_offset);
  void PurgeIndirectCallCache(uint32_t table_index);

  ExternalCallResult CallExternalJSFunction(const uint8_t*& current_code,
                                            const WasmModule* module,
                                            Handle<Object> object_ref,
                                            const FunctionSig* sig,
                                            uint32_t* sp,
                                            uint32_t current_stack_slot);

  inline Address EffectiveAddress(uint64_t index) const;

  // Checks if [index, index+size) is in range [0, WasmMemSize), where
  // WasmMemSize is the size of the Memory object associated to
  // {instance_object_}. (Notice that only a single memory is supported).
  // If not in range, {size} is clamped to its valid range.
  // It in range, out_address contains the (virtual memory) address of the
  // {index}th memory location in the Wasm memory.
  inline bool BoundsCheckMemRange(uint64_t index, uint64_t* size,
                                  Address* out_address) const;

  void InitGlobalAddressCache();
  inline void InitMemoryAddresses();
  void InitIndirectFunctionTables();
  bool CheckIndirectCallSignature(uint32_t table_index, uint32_t entry_index,
                                  uint32_t sig_index) const;

  void EnsureRefStackSpace(size_t new_size);
  void ClearRefStackValues(size_t index, size_t count);

  void StoreRefArgsIntoStackSlots(uint8_t* sp, uint32_t ref_stack_fp_index,
                                  const FunctionSig* sig);
  void StoreRefResultsIntoRefStack(uint8_t* sp, uint32_t ref_stack_fp_index,
                                   const FunctionSig* sig);

  WasmInterpreterThread::ExceptionHandlingResult HandleException(
      uint32_t* sp, const uint8_t*& current_code);
  bool MatchingExceptionTag(Handle<Object> exception_object,
                            uint32_t index) const;

  bool SubtypeCheck(Tagged<Map> rtt, Tagged<Map> formal_rtt,
                    uint32_t type_index) const;

  WasmInterpreterThread* thread() const {
    DCHECK_NOT_NULL(current_thread_);
    return current_thread_;
  }
  WasmInterpreterThread::State state() const { return thread()->state(); }

  void CallWasmToJSBuiltin(Isolate* isolate, Handle<Object> object_ref,
                           Address packed_args, const FunctionSig* sig);

  inline Handle<WasmTrustedInstanceData> wasm_trusted_instance_data() const;

  Isolate* isolate_;
  const WasmModule* module_;
  Handle<WasmInstanceObject> instance_object_;
  WasmInterpreter::CodeMap* codemap_;

  uint32_t start_function_index_;
  FrameState current_frame_;
  std::vector<WasmValue> function_result_;

  int trap_function_index_;
  pc_t trap_pc_;

  // References are kept on an on-heap stack. It would not be any good to store
  // reference object pointers into stack slots because the pointers obviously
  // could be invalidated if the object moves in a GC. Furthermore we need to
  // make sure that the reference objects in the Wasm stack are marked as alive
  // for GC. This is why in each Wasm thread we instantiate a FixedArray that
  // contains all the reference objects present in the execution stack.
  // Only while calling JS functions or Wasm functions in a separate instance we
  // need to store temporarily the reference objects pointers into stack slots,
  // and in this case we need to make sure to temporarily disallow GC and avoid
  // object allocation while the reference arguments are being passed to the
  // callee and while the reference return values are being passed back to the
  // caller.
  Handle<FixedArray> reference_stack_;
  size_t current_ref_stack_size_;

  WasmInterpreterThread* current_thread_;

  uint8_t* memory_start_;

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-private-field"
#endif  // __clang__
  PWasmOp* const* instruction_table_;
#ifdef __clang__
#pragma clang diagnostic pop
#endif  // __clang__

  std::vector<uint8_t*> global_addresses_;

  struct IndirectCallValue {
    enum class Mode { kInvalid, kInternalCall, kExternalCall };

    static const uint32_t kInlineSignatureSentinel = UINT_MAX;
    static const uint32_t kInvalidFunctionIndex = UINT_MAX;

    IndirectCallValue()
        : mode(Mode::kInvalid),
          func_index(kInvalidFunctionIndex),
          sig_index(kInlineSignatureSentinel),
          signature(nullptr) {}
    IndirectCallValue(uint32_t func_index_, uint32_t sig_index)
        : mode(Mode::kInternalCall),
          func_index(func_index_),
          sig_index(sig_index),
          signature(nullptr) {}
    IndirectCallValue(const FunctionSig* signature_, uint32_t sig_index)
        : mode(Mode::kExternalCall),
          func_index(kInvalidFunctionIndex),
          sig_index(sig_index),
          signature(signature_) {}

    operator bool() const { return mode != Mode::kInvalid; }

    Mode mode;
    uint32_t func_index;
    uint32_t sig_index;
    const FunctionSig* signature;
  };
  typedef std::vector<IndirectCallValue> IndirectCallTable;
  std::vector<IndirectCallTable> indirect_call_tables_;

  using WasmToJSCallSig =
      // NOLINTNEXTLINE(readability/casting)
      Address(Address js_function, Address packed_args,
              Address saved_c_entry_fp, const FunctionSig* sig,
              Address c_entry_fp, Address callable);
  GeneratedCode<WasmToJSCallSig> generic_wasm_to_js_interpreter_wrapper_fn_;

 public:
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  void TracePop() { shadow_stack_->TracePop(); }

  size_t TracePush(ValueKind kind, uint32_t slot_offset) {
    switch (kind) {
      case kI32:
        return TracePush<int32_t>(slot_offset);
      case kI64:
        return TracePush<int64_t>(slot_offset);
      case kF32:
        return TracePush<float>(slot_offset);
      case kF64:
        return TracePush<double>(slot_offset);
      case kS128:
        return TracePush<Simd128>(slot_offset);
      case kRef:
      case kRefNull:
        return TracePush<WasmRef>(slot_offset);
      default:
        UNREACHABLE();
    }
  }
  template <typename T>
  size_t TracePush(uint32_t slot_offset) {
    shadow_stack_->TracePush<T>(slot_offset);
    return sizeof(T);
  }

  void TracePushCopy(uint32_t from_index) {
    shadow_stack_->TracePushCopy(from_index);
  }

  void TraceUpdate(uint32_t stack_index, uint32_t slot_offset) {
    shadow_stack_->TraceUpdate(stack_index, slot_offset);
  }

  void TraceSetSlotType(uint32_t stack_index, uint32_t type) {
    shadow_stack_->TraceSetSlotType(stack_index, type);
  }

  // Used to redirect tracing output from {stdout} to a file.
  InterpreterTracer* GetTracer();

  std::unique_ptr<InterpreterTracer> tracer_;
  ShadowStack* shadow_stack_;
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  WasmInterpreterRuntime(const WasmInterpreterRuntime&) = delete;
  WasmInterpreterRuntime& operator=(const WasmInterpreterRuntime&) = delete;
};

class V8_EXPORT_PRIVATE InterpreterHandle {
 public:
  static constexpr ExternalPointerTag kManagedTag = kGenericManagedTag;

  InterpreterHandle(Isolate* isolate, Handle<Tuple2> interpreter_object);

  WasmInterpreter* interpreter() { return &interpreter_; }
  const WasmModule* module() const { return module_; }

  // Returns true if exited regularly, false if a trap/exception occurred and
  // was not handled inside this activation. In the latter case, a pending
  // exception will have been set on the isolate.
  bool Execute(WasmInterpreterThread* thread, Address frame_pointer,
               uint32_t func_index,
               const std::vector<WasmValue>& argument_values,
               std::vector<WasmValue>& return_values);
  bool Execute(WasmInterpreterThread* thread, Address frame_pointer,
               uint32_t func_index, uint8_t* interpreter_fp);

  inline WasmInterpreterThread::State ContinueExecution(
      WasmInterpreterThread* thread, bool called_from_js);

  Handle<WasmInstanceObject> GetInstanceObject();

  std::vector<WasmInterpreterStackEntry> GetInterpretedStack(
      Address frame_pointer);

  int GetFunctionIndex(Address frame_pointer, int index) const;

  void SetTrapFunctionIndex(int32_t func_index);

 private:
  InterpreterHandle(const InterpreterHandle&) = delete;
  InterpreterHandle& operator=(const InterpreterHandle&) = delete;

  static ModuleWireBytes GetBytes(Tagged<Tuple2> interpreter_object);

  inline WasmInterpreterThread::State RunExecutionLoop(
      WasmInterpreterThread* thread, bool called_from_js);

  Isolate* isolate_;
  const WasmModule* module_;
  WasmInterpreter interpreter_;
};

}  // namespace wasm
}  // namespace internal
}  // namespace v8

#endif  // V8_WASM_INTERPRETER_WASM_INTERPRETER_RUNTIME_H_
```