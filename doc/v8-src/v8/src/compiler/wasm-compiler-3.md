Response: The user wants a summary of the C++ code snippet provided, which is part of `v8/src/compiler/wasm-compiler.cc`. The prompt indicates this is the 4th of 6 parts. The focus should be on the functionality of this specific part and its relationship to JavaScript.

Here's a breakdown of the code and how to approach the summarization:

1. **Identify the core functionality:** The code primarily deals with generating low-level machine code instructions (Nodes in V8's intermediate representation) for various WebAssembly (Wasm) operations. Many of these operations are SIMD (Single Instruction, Multiple Data) instructions, atomic operations, memory manipulation, table operations, and operations related to the new Wasm reference types proposal (structs, arrays, strings).

2. **Group similar operations:**  Notice blocks of code handling SIMD operations (`SimdOp`, `SimdLaneOp`, `Simd8x16ShuffleOp`), atomic operations (`AtomicOp`, `AtomicFence`), memory operations (`MemoryInit`, `MemoryCopy`, `MemoryFill`), table operations (`TableInit`, `TableCopy`, `TableGrow`, `TableSize`, `TableFill`), and reference type operations (`StructNew`, `ArrayNew`, `ArrayGet`, `ArraySet`, `StringNewWtf8`, etc.). This grouping helps in organizing the summary.

3. **Focus on the `WasmGraphBuilder` class:** This class is clearly central to the code's purpose. The methods within this class take Wasm opcodes and operands as input and produce IR `Node` objects.

4. **Relate to JavaScript (if applicable):** While the code is C++, it's about compiling *Wasm*, which interacts with JavaScript. The key connection is that Wasm code is executed within a JavaScript engine (like V8). Some Wasm features directly map to JavaScript concepts or have corresponding JavaScript APIs. For instance, Wasm SharedArrayBuffer and Atomics relate to the atomic operations in the C++ code. The new Wasm reference types (structs, arrays, strings) are designed to improve interoperability with JavaScript objects.

5. **Address the "part 4 of 6" aspect:**  This implies that this section likely handles a specific set of Wasm features or a particular stage of the compilation process. Given the content, it seems to focus on generating code for the *execution* of Wasm instructions.

6. **Use the provided examples (if any):** The user has provided C++ code. There are no direct JavaScript examples *in* the code, but the summary should provide illustrative JavaScript examples where the Wasm functionality is relevant.

7. **Structure the summary:** Start with a high-level overview, then detail the specific functionalities, and finally illustrate the connection to JavaScript.

**Self-Correction/Refinement during thought:**

* **Initial thought:** This code translates Wasm opcodes to machine code.
* **Refinement:** More specifically, it translates them to V8's intermediate representation (`Node`s), which are then further processed.
* **Initial thought:**  The SIMD instructions are about vector operations.
* **Refinement:** Explain how these map to operations on 128-bit vectors and the specific SIMD opcodes.
* **Initial thought:** Atomic operations are for concurrency.
* **Refinement:** Mention the connection to SharedArrayBuffer and the purpose of atomic operations in concurrent memory access.
* **Initial thought:** Memory operations are about reading and writing memory.
* **Refinement:** Detail the specific memory operations like `memory.init`, `memory.copy`, and `memory.fill`, and how they relate to the Wasm memory model.
* **Initial thought:** Table operations are about function pointers.
* **Refinement:** Expand this to include table initialization, copying, growing, and getting the size.
* **Initial thought:** The new reference types are like JavaScript objects.
* **Refinement:** Explain how structs and arrays in Wasm provide more structured data and how strings are being integrated. Point out the interoperability aspect.

By following these steps and refining the thoughts, a comprehensive and accurate summary can be generated.
The code snippet you provided is a part of the `WasmGraphBuilder` class in `v8/src/compiler/wasm-compiler.cc`. This class is responsible for translating WebAssembly (Wasm) bytecode into V8's internal intermediate representation (IR), which is a graph of nodes representing machine operations.

Based on the provided code, this specific part of the `WasmGraphBuilder` focuses on **generating IR nodes for various Wasm SIMD (Single Instruction, Multiple Data), Atomic, Memory, Table, and Reference Types instructions.**

Here's a breakdown of the functionality:

**1. SIMD Operations:**

*   It handles the creation of IR nodes for a wide range of Wasm SIMD instructions. These instructions operate on 128-bit vectors.
*   Examples include bitwise operations (`S128Not`, `S128Select`, `S128AndNot`), comparisons (`I64x2AllTrue`, `I32x4AllTrue`, etc.), lane extraction and replacement (`F64x2ExtractLane`, `F64x2ReplaceLane`, etc.), shuffling (`I8x16Shuffle`), and relaxed SIMD operations (with "Relaxed" in their names).
*   The code maps Wasm opcodes like `kExprS128Not` to specific machine instructions provided by the `mcgraph()->machine()` object.

**2. Atomic Operations:**

*   It generates IR nodes for Wasm's atomic memory access instructions, which are used for safe concurrent programming with shared memory.
*   It handles various atomic operations like `AtomicAdd`, `AtomicSub`, `AtomicAnd`, `AtomicOr`, `AtomicXor`, `AtomicExchange`, and `AtomicCompareExchange` for different integer sizes (32-bit and 64-bit, and their 8/16/32-bit variants).
*   It also includes handling for `AtomicLoad` and `AtomicStore` instructions.
*   Special cases like `AtomicNotify` and `AtomicWait` are handled, which involve calling runtime functions for inter-thread synchronization.

**3. Memory Operations:**

*   It generates IR nodes for Wasm instructions that manipulate memory.
*   `MemoryInit`:  Initializes a region of linear memory with data from a data segment.
*   `DataDrop`:  Marks a data segment as no longer needed.
*   `MemoryCopy`: Copies a region of memory from one location to another within linear memory.
*   `MemoryFill`: Fills a region of memory with a specific byte value.

**4. Table Operations:**

*   It generates IR nodes for Wasm instructions that operate on tables (arrays of function references or other reference types).
*   `TableInit`: Initializes a table with elements from an element segment.
*   `ElemDrop`: Marks an element segment as no longer needed.
*   `TableCopy`: Copies elements from one table to another.
*   `TableGrow`: Increases the size of a table.
*   `TableSize`: Gets the current size of a table.
*   `TableFill`: Fills a table with a specific value.

**5. Reference Types Operations (part of the emerging Wasm feature set):**

*   It handles instructions related to the new Wasm reference types proposal, which introduces more complex object types.
*   `RefTest`: Checks if a reference is of a specific type.
*   `RefCast`: Attempts to cast a reference to a specific type, potentially trapping if the cast fails.
*   `BrOnCast`: A control flow instruction that branches based on the success of a `RefCast`.
*   `BrOnEq`, `BrOnStruct`, `BrOnArray`, `BrOnI31`, `BrOnString`: Branch instructions based on type checks for specific reference types.
*   `StructNew`: Creates a new struct instance.
*   `StructGet`: Accesses a field of a struct.
*   `StructSet`: Sets the value of a field in a struct.
*   `ArrayNew`, `ArrayNewFixed`, `ArrayNewSegment`, `ArrayInitSegment`:  Creates new array instances with different initialization methods.
*   `ArrayGet`: Accesses an element of an array.
*   `ArraySet`: Sets the value of an element in an array.
*   `ArrayLen`: Gets the length of an array.
*   `ArrayCopy`: Copies elements within or between arrays.
*   `ArrayFill`: Fills an array with a specific value.
*   `RttCanon`: Creates a canonical representation of a runtime type.
*   `StringNewWtf8`, `StringNewWtf8Array`, `StringNewWtf16`, `StringNewWtf16Array`, `StringConst`: Creates new string instances from various sources.
*   `StringMeasureUtf8`, `StringMeasureWtf8`, `StringMeasureWtf16`: Gets the length of a string.
*   `StringEncodeWtf8`, `StringEncodeWtf8Array`: Encodes a string into UTF-8 in memory or an array.

**Relationship to JavaScript:**

This code plays a crucial role in how JavaScript engines execute WebAssembly. When JavaScript code loads and runs a Wasm module, the engine needs to compile the Wasm bytecode into efficient machine code. The `WasmGraphBuilder` is a key component in this compilation process within V8.

Here are some ways these functionalities relate to JavaScript:

*   **SIMD.js:** While not directly exposed in the same way as Wasm SIMD, JavaScript had an experimental SIMD API. Wasm SIMD provides a more standardized and efficient way to perform parallel computations on data within the browser, benefiting JavaScript applications that utilize Wasm.

    ```javascript
    // JavaScript (Conceptual example, might not directly map to Wasm opcodes)
    const a = new Float32x4Array([1, 2, 3, 4]);
    const b = new Float32x4Array([5, 6, 7, 8]);
    const sum = a.add(b); // Equivalent to some Wasm SIMD add operation
    ```

*   **SharedArrayBuffer and Atomics:** JavaScript's `SharedArrayBuffer` allows sharing memory between different JavaScript contexts (like web workers). The Wasm atomic operations compiled by this code enable safe concurrent access to this shared memory from Wasm modules.

    ```javascript
    // JavaScript
    const sab = new SharedArrayBuffer(1024);
    const atomicView = new Int32Array(sab);

    // ... in one worker ...
    Atomics.add(atomicView, 0, 5);

    // ... in another worker ...
    const value = Atomics.load(atomicView, 0);
    ```

*   **Wasm Memory and Tables:** Wasm's linear memory can be accessed from JavaScript using `WebAssembly.Memory`. Wasm tables can be accessed using `WebAssembly.Table`. The memory and table operations compiled here are the underlying mechanisms for managing these resources.

    ```javascript
    // JavaScript
    const memory = new WebAssembly.Memory({ initial: 1 });
    const buffer = memory.buffer;
    const memView = new Uint8Array(buffer);
    memView[0] = 42; //  Relates to Wasm memory store operations

    const table = new WebAssembly.Table({ initial: 1, element: 'anyfunc' });
    ```

*   **Wasm Reference Types (Structs, Arrays, Strings):** This is a newer feature aimed at improving interoperability between JavaScript and Wasm. These Wasm types can be directly passed between JavaScript and Wasm, reducing the need for manual serialization and deserialization.

    ```javascript
    // Hypothetical JavaScript example interacting with Wasm reference types
    const wasmInstance = await WebAssembly.instantiateStreaming(...);
    const wasmExports = wasmInstance.exports;

    const myStruct = wasmExports.createMyStruct(10, 20); // Wasm creating a struct
    console.log(wasmExports.getMyStructField(myStruct)); // Accessing a struct field

    const myString = wasmExports.createWasmString("hello");
    console.log(wasmExports.getStringLength(myString));
    ```

**In summary, this part of `wasm-compiler.cc` is responsible for a significant portion of the code generation needed to execute WebAssembly instructions related to advanced features like SIMD, concurrency, and complex data structures. It bridges the gap between the high-level Wasm bytecode and the low-level machine instructions that run on the processor, enabling efficient and powerful execution of Wasm within the JavaScript environment.**

The fact that this is "part 4 of 6" suggests that this section likely deals with the core logic of translating the *operations* within Wasm functions, building upon earlier stages that might handle function signatures, imports/exports, and memory layout, and preceding later stages that might involve optimization or final code emission.

Prompt: 
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""

      return graph()->NewNode(mcgraph()->machine()->S128Not(), inputs[0]);
    case wasm::kExprS128Select:
      return graph()->NewNode(mcgraph()->machine()->S128Select(), inputs[2],
                              inputs[0], inputs[1]);
    case wasm::kExprS128AndNot:
      return graph()->NewNode(mcgraph()->machine()->S128AndNot(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I64x2AllTrue(), inputs[0]);
    case wasm::kExprI32x4AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I32x4AllTrue(), inputs[0]);
    case wasm::kExprI16x8AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I16x8AllTrue(), inputs[0]);
    case wasm::kExprV128AnyTrue:
      return graph()->NewNode(mcgraph()->machine()->V128AnyTrue(), inputs[0]);
    case wasm::kExprI8x16AllTrue:
      return graph()->NewNode(mcgraph()->machine()->I8x16AllTrue(), inputs[0]);
    case wasm::kExprI8x16Swizzle:
      return graph()->NewNode(mcgraph()->machine()->I8x16Swizzle(false),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16RelaxedSwizzle:
      return graph()->NewNode(mcgraph()->machine()->I8x16Swizzle(true),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16RelaxedLaneSelect:
      // Relaxed lane select puts the mask as first input (same as S128Select).
      return graph()->NewNode(mcgraph()->machine()->I8x16RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprI16x8RelaxedLaneSelect:
      return graph()->NewNode(mcgraph()->machine()->I16x8RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprI32x4RelaxedLaneSelect:
      return graph()->NewNode(mcgraph()->machine()->I32x4RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprI64x2RelaxedLaneSelect:
      return graph()->NewNode(mcgraph()->machine()->I64x2RelaxedLaneSelect(),
                              inputs[2], inputs[0], inputs[1]);
    case wasm::kExprF32x4RelaxedMin:
      return graph()->NewNode(mcgraph()->machine()->F32x4RelaxedMin(),
                              inputs[0], inputs[1]);
    case wasm::kExprF32x4RelaxedMax:
      return graph()->NewNode(mcgraph()->machine()->F32x4RelaxedMax(),
                              inputs[0], inputs[1]);
    case wasm::kExprF64x2RelaxedMin:
      return graph()->NewNode(mcgraph()->machine()->F64x2RelaxedMin(),
                              inputs[0], inputs[1]);
    case wasm::kExprF64x2RelaxedMax:
      return graph()->NewNode(mcgraph()->machine()->F64x2RelaxedMax(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4RelaxedTruncF64x2SZero:
      return graph()->NewNode(
          mcgraph()->machine()->I32x4RelaxedTruncF64x2SZero(), inputs[0]);
    case wasm::kExprI32x4RelaxedTruncF64x2UZero:
      return graph()->NewNode(
          mcgraph()->machine()->I32x4RelaxedTruncF64x2UZero(), inputs[0]);
    case wasm::kExprI32x4RelaxedTruncF32x4S:
      return graph()->NewNode(mcgraph()->machine()->I32x4RelaxedTruncF32x4S(),
                              inputs[0]);
    case wasm::kExprI32x4RelaxedTruncF32x4U:
      return graph()->NewNode(mcgraph()->machine()->I32x4RelaxedTruncF32x4U(),
                              inputs[0]);
    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
}

Node* WasmGraphBuilder::SimdLaneOp(wasm::WasmOpcode opcode, uint8_t lane,
                                   Node* const* inputs) {
  has_simd_ = true;
  switch (opcode) {
    case wasm::kExprF64x2ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->F64x2ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprF64x2ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->F64x2ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprF32x4ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->F32x4ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprF32x4ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->F32x4ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI64x2ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprI64x2ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I64x2ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtractLane:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtractLane(lane),
                              inputs[0]);
    case wasm::kExprI32x4ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I32x4ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtractLaneS:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtractLaneS(lane),
                              inputs[0]);
    case wasm::kExprI16x8ExtractLaneU:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtractLaneU(lane),
                              inputs[0]);
    case wasm::kExprI16x8ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I16x8ReplaceLane(lane),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16ExtractLaneS:
      return graph()->NewNode(mcgraph()->machine()->I8x16ExtractLaneS(lane),
                              inputs[0]);
    case wasm::kExprI8x16ExtractLaneU:
      return graph()->NewNode(mcgraph()->machine()->I8x16ExtractLaneU(lane),
                              inputs[0]);
    case wasm::kExprI8x16ReplaceLane:
      return graph()->NewNode(mcgraph()->machine()->I8x16ReplaceLane(lane),
                              inputs[0], inputs[1]);
    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
}

Node* WasmGraphBuilder::Simd8x16ShuffleOp(const uint8_t shuffle[16],
                                          Node* const* inputs) {
  has_simd_ = true;
  return graph()->NewNode(mcgraph()->machine()->I8x16Shuffle(shuffle),
                          inputs[0], inputs[1]);
}

Node* WasmGraphBuilder::AtomicOp(const wasm::WasmMemory* memory,
                                 wasm::WasmOpcode opcode, Node* const* inputs,
                                 uint32_t alignment, uintptr_t offset,
                                 wasm::WasmCodePosition position) {
  struct AtomicOpInfo {
    enum Type : int8_t {
      kNoInput = 0,
      kOneInput = 1,
      kTwoInputs = 2,
      kSpecial
    };

    using OperatorByAtomicOpParams =
        const Operator* (MachineOperatorBuilder::*)(AtomicOpParameters);
    using OperatorByAtomicLoadRep =
        const Operator* (MachineOperatorBuilder::*)(AtomicLoadParameters);
    using OperatorByAtomicStoreRep =
        const Operator* (MachineOperatorBuilder::*)(AtomicStoreParameters);

    const Type type;
    const MachineType machine_type;
    const OperatorByAtomicOpParams operator_by_type = nullptr;
    const OperatorByAtomicLoadRep operator_by_atomic_load_params = nullptr;
    const OperatorByAtomicStoreRep operator_by_atomic_store_rep = nullptr;
    const wasm::ValueType wasm_type;

    constexpr AtomicOpInfo(Type t, MachineType m, OperatorByAtomicOpParams o)
        : type(t), machine_type(m), operator_by_type(o) {}
    constexpr AtomicOpInfo(Type t, MachineType m, OperatorByAtomicLoadRep o,
                           wasm::ValueType v)
        : type(t),
          machine_type(m),
          operator_by_atomic_load_params(o),
          wasm_type(v) {}
    constexpr AtomicOpInfo(Type t, MachineType m, OperatorByAtomicStoreRep o,
                           wasm::ValueType v)
        : type(t),
          machine_type(m),
          operator_by_atomic_store_rep(o),
          wasm_type(v) {}

    // Constexpr, hence just a table lookup in most compilers.
    static constexpr AtomicOpInfo Get(wasm::WasmOpcode opcode) {
      switch (opcode) {
#define CASE(Name, Type, MachType, Op) \
  case wasm::kExpr##Name:              \
    return {Type, MachineType::MachType(), &MachineOperatorBuilder::Op};
#define CASE_LOAD_STORE(Name, Type, MachType, Op, WasmType)             \
  case wasm::kExpr##Name:                                               \
    return {Type, MachineType::MachType(), &MachineOperatorBuilder::Op, \
            WasmType};

        // Binops.
        CASE(I32AtomicAdd, kOneInput, Uint32, Word32AtomicAdd)
        CASE(I64AtomicAdd, kOneInput, Uint64, Word64AtomicAdd)
        CASE(I32AtomicAdd8U, kOneInput, Uint8, Word32AtomicAdd)
        CASE(I32AtomicAdd16U, kOneInput, Uint16, Word32AtomicAdd)
        CASE(I64AtomicAdd8U, kOneInput, Uint8, Word64AtomicAdd)
        CASE(I64AtomicAdd16U, kOneInput, Uint16, Word64AtomicAdd)
        CASE(I64AtomicAdd32U, kOneInput, Uint32, Word64AtomicAdd)
        CASE(I32AtomicSub, kOneInput, Uint32, Word32AtomicSub)
        CASE(I64AtomicSub, kOneInput, Uint64, Word64AtomicSub)
        CASE(I32AtomicSub8U, kOneInput, Uint8, Word32AtomicSub)
        CASE(I32AtomicSub16U, kOneInput, Uint16, Word32AtomicSub)
        CASE(I64AtomicSub8U, kOneInput, Uint8, Word64AtomicSub)
        CASE(I64AtomicSub16U, kOneInput, Uint16, Word64AtomicSub)
        CASE(I64AtomicSub32U, kOneInput, Uint32, Word64AtomicSub)
        CASE(I32AtomicAnd, kOneInput, Uint32, Word32AtomicAnd)
        CASE(I64AtomicAnd, kOneInput, Uint64, Word64AtomicAnd)
        CASE(I32AtomicAnd8U, kOneInput, Uint8, Word32AtomicAnd)
        CASE(I32AtomicAnd16U, kOneInput, Uint16, Word32AtomicAnd)
        CASE(I64AtomicAnd8U, kOneInput, Uint8, Word64AtomicAnd)
        CASE(I64AtomicAnd16U, kOneInput, Uint16, Word64AtomicAnd)
        CASE(I64AtomicAnd32U, kOneInput, Uint32, Word64AtomicAnd)
        CASE(I32AtomicOr, kOneInput, Uint32, Word32AtomicOr)
        CASE(I64AtomicOr, kOneInput, Uint64, Word64AtomicOr)
        CASE(I32AtomicOr8U, kOneInput, Uint8, Word32AtomicOr)
        CASE(I32AtomicOr16U, kOneInput, Uint16, Word32AtomicOr)
        CASE(I64AtomicOr8U, kOneInput, Uint8, Word64AtomicOr)
        CASE(I64AtomicOr16U, kOneInput, Uint16, Word64AtomicOr)
        CASE(I64AtomicOr32U, kOneInput, Uint32, Word64AtomicOr)
        CASE(I32AtomicXor, kOneInput, Uint32, Word32AtomicXor)
        CASE(I64AtomicXor, kOneInput, Uint64, Word64AtomicXor)
        CASE(I32AtomicXor8U, kOneInput, Uint8, Word32AtomicXor)
        CASE(I32AtomicXor16U, kOneInput, Uint16, Word32AtomicXor)
        CASE(I64AtomicXor8U, kOneInput, Uint8, Word64AtomicXor)
        CASE(I64AtomicXor16U, kOneInput, Uint16, Word64AtomicXor)
        CASE(I64AtomicXor32U, kOneInput, Uint32, Word64AtomicXor)
        CASE(I32AtomicExchange, kOneInput, Uint32, Word32AtomicExchange)
        CASE(I64AtomicExchange, kOneInput, Uint64, Word64AtomicExchange)
        CASE(I32AtomicExchange8U, kOneInput, Uint8, Word32AtomicExchange)
        CASE(I32AtomicExchange16U, kOneInput, Uint16, Word32AtomicExchange)
        CASE(I64AtomicExchange8U, kOneInput, Uint8, Word64AtomicExchange)
        CASE(I64AtomicExchange16U, kOneInput, Uint16, Word64AtomicExchange)
        CASE(I64AtomicExchange32U, kOneInput, Uint32, Word64AtomicExchange)

        // Compare-exchange.
        CASE(I32AtomicCompareExchange, kTwoInputs, Uint32,
             Word32AtomicCompareExchange)
        CASE(I64AtomicCompareExchange, kTwoInputs, Uint64,
             Word64AtomicCompareExchange)
        CASE(I32AtomicCompareExchange8U, kTwoInputs, Uint8,
             Word32AtomicCompareExchange)
        CASE(I32AtomicCompareExchange16U, kTwoInputs, Uint16,
             Word32AtomicCompareExchange)
        CASE(I64AtomicCompareExchange8U, kTwoInputs, Uint8,
             Word64AtomicCompareExchange)
        CASE(I64AtomicCompareExchange16U, kTwoInputs, Uint16,
             Word64AtomicCompareExchange)
        CASE(I64AtomicCompareExchange32U, kTwoInputs, Uint32,
             Word64AtomicCompareExchange)

        // Load.
        CASE_LOAD_STORE(I32AtomicLoad, kNoInput, Uint32, Word32AtomicLoad,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicLoad, kNoInput, Uint64, Word64AtomicLoad,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I32AtomicLoad8U, kNoInput, Uint8, Word32AtomicLoad,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I32AtomicLoad16U, kNoInput, Uint16, Word32AtomicLoad,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicLoad8U, kNoInput, Uint8, Word64AtomicLoad,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicLoad16U, kNoInput, Uint16, Word64AtomicLoad,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicLoad32U, kNoInput, Uint32, Word64AtomicLoad,
                        wasm::kWasmI64)

        // Store.
        CASE_LOAD_STORE(I32AtomicStore, kOneInput, Uint32, Word32AtomicStore,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicStore, kOneInput, Uint64, Word64AtomicStore,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I32AtomicStore8U, kOneInput, Uint8, Word32AtomicStore,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I32AtomicStore16U, kOneInput, Uint16, Word32AtomicStore,
                        wasm::kWasmI32)
        CASE_LOAD_STORE(I64AtomicStore8U, kOneInput, Uint8, Word64AtomicStore,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicStore16U, kOneInput, Uint16, Word64AtomicStore,
                        wasm::kWasmI64)
        CASE_LOAD_STORE(I64AtomicStore32U, kOneInput, Uint32, Word64AtomicStore,
                        wasm::kWasmI64)

#undef CASE
#undef CASE_LOAD_STORE

        case wasm::kExprAtomicNotify:
          return {kSpecial, MachineType::Int32(),
                  OperatorByAtomicOpParams{nullptr}};
        case wasm::kExprI32AtomicWait:
          return {kSpecial, MachineType::Int32(),
                  OperatorByAtomicOpParams{nullptr}};
        case wasm::kExprI64AtomicWait:
          return {kSpecial, MachineType::Int64(),
                  OperatorByAtomicOpParams{nullptr}};
        default:
          UNREACHABLE();
      }
    }
  };

  AtomicOpInfo info = AtomicOpInfo::Get(opcode);

  const auto enforce_bounds_check = info.type != AtomicOpInfo::kSpecial
    ? EnforceBoundsCheck::kCanOmitBoundsCheck
    : EnforceBoundsCheck::kNeedsBoundsCheck;
  Node* index;
  BoundsCheckResult bounds_check_result;
  // Atomic operations need bounds checks until the backend can emit protected
  // loads. Independently, an alignemnt check is needed as well.
  std::tie(index, bounds_check_result) =
      BoundsCheckMem(memory, info.machine_type.MemSize(), inputs[0], offset,
                     position, enforce_bounds_check, AlignmentCheck::kYes);
  // MemoryAccessKind::kUnaligned is impossible due to explicit aligment check.
  MemoryAccessKind access_kind =
      bounds_check_result == BoundsCheckResult::kTrapHandler
          ? MemoryAccessKind::kProtectedByTrapHandler
          : MemoryAccessKind::kNormal;

  if (info.type != AtomicOpInfo::kSpecial) {
    const Operator* op;
    if (info.operator_by_type) {
      op = (mcgraph()->machine()->*info.operator_by_type)(
          AtomicOpParameters(info.machine_type,
                             access_kind));
    } else if (info.operator_by_atomic_load_params) {
      op = (mcgraph()->machine()->*info.operator_by_atomic_load_params)(
          AtomicLoadParameters(info.machine_type, AtomicMemoryOrder::kSeqCst,
                               access_kind));
    } else {
      op = (mcgraph()->machine()->*info.operator_by_atomic_store_rep)(
          AtomicStoreParameters(info.machine_type.representation(),
                                WriteBarrierKind::kNoWriteBarrier,
                                AtomicMemoryOrder::kSeqCst,
                                access_kind));
    }

    Node* input_nodes[6] = {MemBuffer(memory->index, offset), index};
    int num_actual_inputs = info.type;
    std::copy_n(inputs + 1, num_actual_inputs, input_nodes + 2);
    input_nodes[num_actual_inputs + 2] = effect();
    input_nodes[num_actual_inputs + 3] = control();

#ifdef V8_TARGET_BIG_ENDIAN
    // Reverse the value bytes before storing.
    if (info.operator_by_atomic_store_rep) {
      input_nodes[num_actual_inputs + 1] = BuildChangeEndiannessStore(
          input_nodes[num_actual_inputs + 1],
          info.machine_type.representation(), info.wasm_type);
    }
#endif

    Node* result = gasm_->AddNode(
        graph()->NewNode(op, num_actual_inputs + 4, input_nodes));

    if (access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
      SetSourcePosition(result, position);
    }

#ifdef V8_TARGET_BIG_ENDIAN
    // Reverse the value bytes after load.
    if (info.operator_by_atomic_load_params) {
      result =
          BuildChangeEndiannessLoad(result, info.machine_type, info.wasm_type);
    }
#endif

    return result;
  }

  Node* memory_index = gasm_->Int32Constant(memory->index);
  Node* effective_offset = gasm_->IntAdd(gasm_->UintPtrConstant(offset), index);

  switch (opcode) {
    case wasm::kExprAtomicNotify: {
      Node* function =
          gasm_->ExternalConstant(ExternalReference::wasm_atomic_notify());
      auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                     .Params(MachineType::Pointer(), MachineType::Uint32());

      Node* addr = gasm_->IntAdd(MemStart(memory->index), effective_offset);
      Node* num_waiters_to_wake = inputs[1];

      return BuildCCall(&sig, function, addr, num_waiters_to_wake);
    }

    case wasm::kExprI32AtomicWait: {
      constexpr StubCallMode kStubMode = StubCallMode::kCallWasmRuntimeStub;
      auto* call_descriptor = GetBuiltinCallDescriptor(
          Builtin::kWasmI32AtomicWait, zone_, kStubMode);

      Builtin target = Builtin::kWasmI32AtomicWait;
      Node* call_target = mcgraph()->RelocatableWasmBuiltinCallTarget(target);

      return gasm_->Call(call_descriptor, call_target, memory_index,
                         effective_offset, inputs[1],
                         BuildChangeInt64ToBigInt(inputs[2], kStubMode));
    }

    case wasm::kExprI64AtomicWait: {
      constexpr StubCallMode kStubMode = StubCallMode::kCallWasmRuntimeStub;
      auto* call_descriptor = GetBuiltinCallDescriptor(
          Builtin::kWasmI64AtomicWait, zone_, kStubMode);

      Builtin target = Builtin::kWasmI64AtomicWait;
      Node* call_target = mcgraph()->RelocatableWasmBuiltinCallTarget(target);

      return gasm_->Call(call_descriptor, call_target, memory_index,
                         effective_offset,
                         BuildChangeInt64ToBigInt(inputs[1], kStubMode),
                         BuildChangeInt64ToBigInt(inputs[2], kStubMode));
    }

    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
}

void WasmGraphBuilder::AtomicFence() {
  SetEffect(graph()->NewNode(
      mcgraph()->machine()->MemoryBarrier(AtomicMemoryOrder::kSeqCst), effect(),
      control()));
}

void WasmGraphBuilder::MemoryInit(const wasm::WasmMemory* memory,
                                  uint32_t data_segment_index, Node* dst,
                                  Node* src, Node* size,
                                  wasm::WasmCodePosition position) {
  // The data segment index must be in bounds since it is required by
  // validation.
  DCHECK_LT(data_segment_index, env_->module->num_declared_data_segments);

  Node* function =
      gasm_->ExternalConstant(ExternalReference::wasm_memory_init());

  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&dst}, position);

  auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                 .Params(MachineType::Pointer(), MachineType::Uint32(),
                         MachineType::UintPtr(), MachineType::Uint32(),
                         MachineType::Uint32(), MachineType::Uint32());
  Node* call = BuildCCall(&sig, function, GetInstanceData(),
                          gasm_->Int32Constant(memory->index), dst, src,
                          gasm_->Uint32Constant(data_segment_index), size);

  // TODO(manoskouk): Also throw kDataSegmentOutOfBounds.
  TrapIfFalse(wasm::kTrapMemOutOfBounds, call, position);
}

void WasmGraphBuilder::DataDrop(uint32_t data_segment_index,
                                wasm::WasmCodePosition position) {
  DCHECK_LT(data_segment_index, env_->module->num_declared_data_segments);

  Node* seg_size_array =
      LOAD_INSTANCE_FIELD(DataSegmentSizes, MachineType::TaggedPointer());
  static_assert(wasm::kV8MaxWasmDataSegments <= kMaxUInt32 >> 2);
  auto access = ObjectAccess(MachineType::Int32(), kNoWriteBarrier);
  gasm_->StoreToObject(
      access, seg_size_array,
      wasm::ObjectAccess::ElementOffsetInTaggedFixedUInt32Array(
          data_segment_index),
      Int32Constant(0));
}

Node* WasmGraphBuilder::StoreArgsInStackSlot(
    std::initializer_list<std::pair<MachineRepresentation, Node*>> args) {
  int slot_size = 0;
  for (auto arg : args) {
    slot_size += ElementSizeInBytes(arg.first);
  }
  DCHECK_LT(0, slot_size);
  Node* stack_slot =
      graph()->NewNode(mcgraph()->machine()->StackSlot(slot_size));

  int offset = 0;
  for (auto arg : args) {
    MachineRepresentation type = arg.first;
    Node* value = arg.second;
    gasm_->StoreUnaligned(type, stack_slot, Int32Constant(offset), value);
    offset += ElementSizeInBytes(type);
  }
  return stack_slot;
}

void WasmGraphBuilder::MemTypeToUintPtrOrOOBTrap(
    wasm::AddressType address_type, std::initializer_list<Node**> nodes,
    wasm::WasmCodePosition position) {
  MemOrTableTypeToUintPtrOrOOBTrap(address_type, nodes, position,
                                   wasm::kTrapMemOutOfBounds);
}

void WasmGraphBuilder::TableTypeToUintPtrOrOOBTrap(
    wasm::AddressType address_type, std::initializer_list<Node**> nodes,
    wasm::WasmCodePosition position) {
  MemOrTableTypeToUintPtrOrOOBTrap(address_type, nodes, position,
                                   wasm::kTrapTableOutOfBounds);
}

void WasmGraphBuilder::MemOrTableTypeToUintPtrOrOOBTrap(
    wasm::AddressType address_type, std::initializer_list<Node**> nodes,
    wasm::WasmCodePosition position, wasm::TrapReason trap_reason) {
  if (address_type == wasm::AddressType::kI32) {
    for (Node** node : nodes) {
      *node = gasm_->BuildChangeUint32ToUintPtr(*node);
    }
    return;
  }
  if constexpr (Is64()) return;
  Node* any_high_word = nullptr;
  for (Node** node : nodes) {
    Node* high_word =
        gasm_->TruncateInt64ToInt32(gasm_->Word64Shr(*node, Int32Constant(32)));
    any_high_word =
        any_high_word ? gasm_->Word32Or(any_high_word, high_word) : high_word;
    // Only keep the low word as uintptr_t.
    *node = gasm_->TruncateInt64ToInt32(*node);
  }
  TrapIfTrue(trap_reason, any_high_word, position);
}

void WasmGraphBuilder::MemoryCopy(const wasm::WasmMemory* dst_memory,
                                  const wasm::WasmMemory* src_memory, Node* dst,
                                  Node* src, Node* size,
                                  wasm::WasmCodePosition position) {
  Node* function =
      gasm_->ExternalConstant(ExternalReference::wasm_memory_copy());

  if (dst_memory->address_type == src_memory->address_type) {
    MemTypeToUintPtrOrOOBTrap(dst_memory->address_type, {&dst, &src, &size},
                              position);
  } else {
    MemTypeToUintPtrOrOOBTrap(dst_memory->address_type, {&dst}, position);
    MemTypeToUintPtrOrOOBTrap(src_memory->address_type, {&src}, position);
    wasm::AddressType min_address_type =
        dst_memory->is_memory64() && src_memory->is_memory64()
            ? wasm::AddressType::kI64
            : wasm::AddressType::kI32;
    MemTypeToUintPtrOrOOBTrap(min_address_type, {&size}, position);
  }

  auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                 .Params(MachineType::Pointer(), MachineType::Uint32(),
                         MachineType::Uint32(), MachineType::UintPtr(),
                         MachineType::UintPtr(), MachineType::UintPtr());

  Node* call =
      BuildCCall(&sig, function, GetInstanceData(),
                 gasm_->Int32Constant(dst_memory->index),
                 gasm_->Int32Constant(src_memory->index), dst, src, size);
  TrapIfFalse(wasm::kTrapMemOutOfBounds, call, position);
}

void WasmGraphBuilder::MemoryFill(const wasm::WasmMemory* memory, Node* dst,
                                  Node* value, Node* size,
                                  wasm::WasmCodePosition position) {
  Node* function =
      gasm_->ExternalConstant(ExternalReference::wasm_memory_fill());

  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&dst, &size}, position);

  auto sig = FixedSizeSignature<MachineType>::Returns(MachineType::Int32())
                 .Params(MachineType::Pointer(), MachineType::Uint32(),
                         MachineType::UintPtr(), MachineType::Uint8(),
                         MachineType::UintPtr());
  Node* call =
      BuildCCall(&sig, function, GetInstanceData(),
                 gasm_->Int32Constant(memory->index), dst, value, size);
  TrapIfFalse(wasm::kTrapMemOutOfBounds, call, position);
}

void WasmGraphBuilder::TableInit(uint32_t table_index,
                                 uint32_t elem_segment_index, Node* dst,
                                 Node* src, Node* size,
                                 wasm::WasmCodePosition position) {
  const wasm::WasmTable& table = env_->module->tables[table_index];
  TableTypeToUintPtrOrOOBTrap(table.address_type, {&dst}, position);
  gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmTableInit, Operator::kNoThrow, dst, src, size,
      gasm_->NumberConstant(table_index),
      gasm_->NumberConstant(elem_segment_index), gasm_->Int32Constant(0));
}

void WasmGraphBuilder::ElemDrop(uint32_t elem_segment_index,
                                wasm::WasmCodePosition position) {
  // The elem segment index must be in bounds since it is required by
  // validation.
  DCHECK_LT(elem_segment_index, env_->module->elem_segments.size());

  Node* elem_segments =
      LOAD_INSTANCE_FIELD(ElementSegments, MachineType::TaggedPointer());
  gasm_->StoreFixedArrayElement(
      elem_segments, elem_segment_index,
      LOAD_ROOT(EmptyFixedArray, empty_fixed_array),
      ObjectAccess(MachineType::TaggedPointer(), kFullWriteBarrier));
}

void WasmGraphBuilder::TableCopy(uint32_t table_dst_index,
                                 uint32_t table_src_index, Node* dst, Node* src,
                                 Node* size, wasm::WasmCodePosition position) {
  const wasm::WasmTable& table_dst = env_->module->tables[table_dst_index];
  const wasm::WasmTable& table_src = env_->module->tables[table_src_index];
  // TODO(crbug.com/338024338): Merge the `TableTypeToUintPtrOrOOBTrap` calls
  // into one. This would result in smaller graphs because we would have a
  // single `TrapIf` node that uses the combined high words of `dst`, `src`, and
  // `size`.
  TableTypeToUintPtrOrOOBTrap(table_dst.address_type, {&dst}, position);
  TableTypeToUintPtrOrOOBTrap(table_src.address_type, {&src}, position);
  wasm::AddressType min_address_type =
      table_src.is_table64() && table_dst.is_table64()
          ? wasm::AddressType::kI64
          : wasm::AddressType::kI32;
  TableTypeToUintPtrOrOOBTrap(min_address_type, {&size}, position);
  gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmTableCopy, Operator::kNoThrow, dst, src, size,
      gasm_->NumberConstant(table_dst_index),
      gasm_->NumberConstant(table_src_index), gasm_->NumberConstant(0));
}

Node* WasmGraphBuilder::TableGrow(uint32_t table_index, Node* value,
                                  Node* delta,
                                  wasm::WasmCodePosition position) {
  const wasm::WasmTable& table = env_->module->tables[table_index];
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);

  // If `delta` is OOB, return -1.
  if (!table.is_table64()) {
    delta = gasm_->BuildChangeUint32ToUintPtr(delta);
  } else if constexpr (!Is64()) {
    Node* high_word =
        gasm_->TruncateInt64ToInt32(gasm_->Word64Shr(delta, Int32Constant(32)));
    gasm_->GotoIf(high_word, &done, Int32Constant(-1));
    delta = gasm_->TruncateInt64ToInt32(delta);
  }

  Node* result =
      gasm_->BuildChangeSmiToInt32(gasm_->CallBuiltinThroughJumptable(
          Builtin::kWasmTableGrow, Operator::kNoThrow,
          gasm_->NumberConstant(table_index), delta, gasm_->Int32Constant(0),
          value));
  gasm_->Goto(&done, result);

  gasm_->Bind(&done);
  result = done.PhiAt(0);

  return table.is_table64() ? gasm_->ChangeInt32ToInt64(result) : result;
}

Node* WasmGraphBuilder::TableSize(uint32_t table_index) {
  Node* tables = LOAD_INSTANCE_FIELD(Tables, MachineType::TaggedPointer());
  Node* table = gasm_->LoadFixedArrayElementAny(tables, table_index);

  int length_field_size = WasmTableObject::kCurrentLengthOffsetEnd -
                          WasmTableObject::kCurrentLengthOffset + 1;
  Node* length_smi = gasm_->LoadFromObject(
      assert_size(length_field_size, MachineType::TaggedSigned()), table,
      wasm::ObjectAccess::ToTagged(WasmTableObject::kCurrentLengthOffset));
  Node* length32 = gasm_->BuildChangeSmiToInt32(length_smi);
  return env_->module->tables[table_index].is_table64()
             ? gasm_->ChangeInt32ToInt64(length32)
             : length32;
}

void WasmGraphBuilder::TableFill(uint32_t table_index, Node* start, Node* value,
                                 Node* count, wasm::WasmCodePosition position) {
  const wasm::WasmTable& table = env_->module->tables[table_index];
  TableTypeToUintPtrOrOOBTrap(table.address_type, {&start, &count}, position);
  gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmTableFill, Operator::kNoThrow, start, count,
      gasm_->Int32Constant(false), gasm_->NumberConstant(table_index), value);
}

Node* WasmGraphBuilder::DefaultValue(wasm::ValueType type) {
  DCHECK(type.is_defaultable());
  switch (type.kind()) {
    case wasm::kI8:
    case wasm::kI16:
    case wasm::kI32:
      return Int32Constant(0);
    case wasm::kI64:
      return Int64Constant(0);
    case wasm::kF16:
    case wasm::kF32:
      return Float32Constant(0);
    case wasm::kF64:
      return Float64Constant(0);
    case wasm::kS128:
      return S128Zero();
    case wasm::kRefNull:
      return RefNull(type);
    case wasm::kRtt:
    case wasm::kVoid:
    case wasm::kTop:
    case wasm::kBottom:
    case wasm::kRef:
      UNREACHABLE();
  }
}

Node* WasmGraphBuilder::StructNew(wasm::ModuleTypeIndex struct_index,
                                  const wasm::StructType* type, Node* rtt,
                                  base::Vector<Node*> fields) {
  int size = WasmStruct::Size(type);
  Node* s = gasm_->Allocate(size);
  gasm_->StoreMap(s, rtt);
  gasm_->InitializeImmutableInObject(
      ObjectAccess(MachineType::TaggedPointer(), kNoWriteBarrier), s,
      wasm::ObjectAccess::ToTagged(JSReceiver::kPropertiesOrHashOffset),
      LOAD_ROOT(EmptyFixedArray, empty_fixed_array));
  for (uint32_t i = 0; i < type->field_count(); i++) {
    gasm_->StructSet(s, fields[i], type, i, kWithoutNullCheck);
  }
  // If this assert fails then initialization of padding field might be
  // necessary.
  static_assert(Heap::kMinObjectSizeInTaggedWords == 2 &&
                    WasmStruct::kHeaderSize == 2 * kTaggedSize,
                "empty struct might require initialization of padding field");
  return s;
}

Node* WasmGraphBuilder::ArrayNew(wasm::ModuleTypeIndex array_index,
                                 const wasm::ArrayType* type, Node* length,
                                 Node* initial_value, Node* rtt,
                                 wasm::WasmCodePosition position) {
  TrapIfFalse(wasm::kTrapArrayTooLarge,
              gasm_->Uint32LessThanOrEqual(
                  length, gasm_->Uint32Constant(WasmArray::MaxLength(type))),
              position);
  wasm::ValueType element_type = type->element_type();

  // RoundUp(length * value_size, kObjectAlignment) =
  //   RoundDown(length * value_size + kObjectAlignment - 1,
  //             kObjectAlignment);
  Node* padded_length = gasm_->Word32And(
      gasm_->Int32Add(
          gasm_->Int32Mul(length,
                          Int32Constant(element_type.value_kind_size())),
          Int32Constant(kObjectAlignment - 1)),
      Int32Constant(-kObjectAlignment));
  Node* a = gasm_->Allocate(
      gasm_->Int32Add(padded_length, Int32Constant(WasmArray::kHeaderSize)));

  // Initialize the array header.
  gasm_->StoreMap(a, rtt);
  gasm_->InitializeImmutableInObject(
      ObjectAccess(MachineType::TaggedPointer(), kNoWriteBarrier), a,
      wasm::ObjectAccess::ToTagged(JSReceiver::kPropertiesOrHashOffset),
      LOAD_ROOT(EmptyFixedArray, empty_fixed_array));
  gasm_->ArrayInitializeLength(a, length);

  ArrayFillImpl(a, gasm_->Int32Constant(0),
                initial_value != nullptr
                    ? initial_value
                    : SetType(DefaultValue(element_type),
                              type->element_type().Unpacked()),
                length, type, false);

  return a;
}

Node* WasmGraphBuilder::ArrayNewFixed(const wasm::ArrayType* type, Node* rtt,
                                      base::Vector<Node*> elements) {
  wasm::ValueType element_type = type->element_type();
  Node* array = gasm_->Allocate(RoundUp(element_type.value_kind_size() *
                                            static_cast<int>(elements.size()),
                                        kObjectAlignment) +
                                WasmArray::kHeaderSize);
  gasm_->StoreMap(array, rtt);
  gasm_->InitializeImmutableInObject(
      ObjectAccess(MachineType::TaggedPointer(), kNoWriteBarrier), array,
      wasm::ObjectAccess::ToTagged(JSReceiver::kPropertiesOrHashOffset),
      LOAD_ROOT(EmptyFixedArray, empty_fixed_array));
  gasm_->ArrayInitializeLength(
      array, SetType(Int32Constant(static_cast<int>(elements.size())),
                     wasm::kWasmI32));
  for (int i = 0; i < static_cast<int>(elements.size()); i++) {
    gasm_->ArraySet(array, gasm_->Int32Constant(i), elements[i], type);
  }
  return array;
}

Node* WasmGraphBuilder::ArrayNewSegment(uint32_t segment_index, Node* offset,
                                        Node* length, Node* rtt,
                                        bool is_element,
                                        wasm::WasmCodePosition position) {
  // This call cannot be marked as eliminatable because it performs an array
  // maximum size check.
  Node* array = gasm_->CallBuiltin(
      Builtin::kWasmArrayNewSegment, Operator::kNoProperties,
      gasm_->Uint32Constant(segment_index), offset, length,
      gasm_->SmiConstant(is_element ? 1 : 0), gasm_->SmiConstant(0), rtt);
  SetSourcePosition(array, position);
  return array;
}

// TODO(jkummerow): This check would be more elegant if we made
// {ArrayNewSegment} a high-level node that's lowered later.
bool IsArrayNewSegment(Node* node) {
  if (node->opcode() != IrOpcode::kCall) return false;
  Node* callee = NodeProperties::GetValueInput(node, 0);
  if (callee->opcode() != IrOpcode::kNumberConstant) return false;
  double target = OpParameter<double>(callee->op());
  return target == static_cast<double>(Builtin::kWasmArrayNewSegment);
}

void WasmGraphBuilder::ArrayInitSegment(uint32_t segment_index, Node* array,
                                        Node* array_index, Node* segment_offset,
                                        Node* length, bool is_element,
                                        wasm::WasmCodePosition position) {
  gasm_->CallBuiltin(
      Builtin::kWasmArrayInitSegment, Operator::kNoProperties, array_index,
      segment_offset, length, gasm_->SmiConstant(segment_index),
      gasm_->SmiConstant(is_element ? 1 : 0), gasm_->SmiConstant(0), array);
  SetSourcePosition(control(), position);
}

Node* WasmGraphBuilder::RttCanon(wasm::ModuleTypeIndex type_index) {
  Node* rtt = graph()->NewNode(gasm_->simplified()->RttCanon(type_index),
                               GetInstanceData());
  return SetType(rtt, wasm::ValueType::Rtt(type_index));
}

WasmGraphBuilder::Callbacks WasmGraphBuilder::TestCallbacks(
    GraphAssemblerLabel<1>* label) {
  return {// succeed_if
          [this, label](Node* condition, BranchHint hint) -> void {
            gasm_->GotoIf(condition, label, hint, Int32Constant(1));
          },
          // fail_if
          [this, label](Node* condition, BranchHint hint) -> void {
            gasm_->GotoIf(condition, label, hint, Int32Constant(0));
          },
          // fail_if_not
          [this, label](Node* condition, BranchHint hint) -> void {
            gasm_->GotoIfNot(condition, label, hint, Int32Constant(0));
          }};
}

WasmGraphBuilder::Callbacks WasmGraphBuilder::CastCallbacks(
    GraphAssemblerLabel<0>* label, wasm::WasmCodePosition position) {
  return {// succeed_if
          [this, label](Node* condition, BranchHint hint) -> void {
            gasm_->GotoIf(condition, label, hint);
          },
          // fail_if
          [this, position](Node* condition, BranchHint hint) -> void {
            TrapIfTrue(wasm::kTrapIllegalCast, condition, position);
          },
          // fail_if_not
          [this, position](Node* condition, BranchHint hint) -> void {
            TrapIfFalse(wasm::kTrapIllegalCast, condition, position);
          }};
}

WasmGraphBuilder::Callbacks WasmGraphBuilder::BranchCallbacks(
    SmallNodeVector& no_match_controls, SmallNodeVector& no_match_effects,
    SmallNodeVector& match_controls, SmallNodeVector& match_effects) {
  return {
      // succeed_if
      [&](Node* condition, BranchHint hint) -> void {
        Node* branch = graph()->NewNode(mcgraph()->common()->Branch(hint),
                                        condition, control());
        match_controls.emplace_back(
            graph()->NewNode(mcgraph()->common()->IfTrue(), branch));
        match_effects.emplace_back(effect());
        SetControl(graph()->NewNode(mcgraph()->common()->IfFalse(), branch));
      },
      // fail_if
      [&](Node* condition, BranchHint hint) -> void {
        Node* branch = graph()->NewNode(mcgraph()->common()->Branch(hint),
                                        condition, control());
        no_match_controls.emplace_back(
            graph()->NewNode(mcgraph()->common()->IfTrue(), branch));
        no_match_effects.emplace_back(effect());
        SetControl(graph()->NewNode(mcgraph()->common()->IfFalse(), branch));
      },
      // fail_if_not
      [&](Node* condition, BranchHint hint) -> void {
        Node* branch = graph()->NewNode(mcgraph()->common()->Branch(hint),
                                        condition, control());
        no_match_controls.emplace_back(
            graph()->NewNode(mcgraph()->common()->IfFalse(), branch));
        no_match_effects.emplace_back(effect());
        SetControl(graph()->NewNode(mcgraph()->common()->IfTrue(), branch));
      }};
}

void WasmGraphBuilder::EqCheck(Node* object, bool object_can_be_null,
                               Callbacks callbacks, bool null_succeeds) {
  if (object_can_be_null) {
    if (null_succeeds) {
      callbacks.succeed_if(IsNull(object, wasm::kWasmAnyRef),
                           BranchHint::kFalse);
    } else {
      // The {IsDataRefMap} check below will fail for {null} anyway.
    }
  }
  callbacks.succeed_if(gasm_->IsSmi(object), BranchHint::kFalse);
  Node* map = gasm_->LoadMap(object);
  callbacks.fail_if_not(gasm_->IsDataRefMap(map), BranchHint::kTrue);
}

void WasmGraphBuilder::ManagedObjectInstanceCheck(Node* object,
                                                  bool object_can_be_null,
                                                  InstanceType instance_type,
                                                  Callbacks callbacks,
                                                  bool null_succeeds) {
  if (object_can_be_null) {
    if (null_succeeds) {
      callbacks.succeed_if(IsNull(object, wasm::kWasmAnyRef),
                           BranchHint::kFalse);
    } else {
      // The {IsDataRefMap} check below will fail for {null} anyway.
    }
  }
  callbacks.fail_if(gasm_->IsSmi(object), BranchHint::kFalse);
  callbacks.fail_if_not(gasm_->HasInstanceType(object, instance_type),
                        BranchHint::kTrue);
}

void WasmGraphBuilder::StringCheck(Node* object, bool object_can_be_null,
                                   Callbacks callbacks, bool null_succeeds) {
  if (object_can_be_null) {
    if (null_succeeds) {
      callbacks.succeed_if(IsNull(object, wasm::kWasmAnyRef),
                           BranchHint::kFalse);
    } else {
      // The {IsDataRefMap} check below will fail for {null} anyway.
    }
  }
  callbacks.fail_if(gasm_->IsSmi(object), BranchHint::kFalse);
  Node* map = gasm_->LoadMap(object);
  Node* instance_type = gasm_->LoadInstanceType(map);
  Node* check = gasm_->Uint32LessThan(
      instance_type, gasm_->Uint32Constant(FIRST_NONSTRING_TYPE));
  callbacks.fail_if_not(check, BranchHint::kTrue);
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnCastAbs(
    std::function<void(Callbacks)> type_checker) {
  SmallNodeVector no_match_controls, no_match_effects, match_controls,
      match_effects;
  Node *match_control, *match_effect, *no_match_control, *no_match_effect;

  type_checker(BranchCallbacks(no_match_controls, no_match_effects,
                               match_controls, match_effects));

  match_controls.emplace_back(control());
  match_effects.emplace_back(effect());

  // Wire up the control/effect nodes.
  DCHECK_EQ(match_controls.size(), match_effects.size());
  unsigned match_count = static_cast<unsigned>(match_controls.size());
  if (match_count == 1) {
    match_control = match_controls[0];
    match_effect = match_effects[0];
  } else {
    match_control = Merge(match_count, match_controls.data());
    // EffectPhis need their control dependency as an additional input.
    match_effects.emplace_back(match_control);
    match_effect = EffectPhi(match_count, match_effects.data());
  }

  DCHECK_EQ(no_match_controls.size(), no_match_effects.size());
  unsigned no_match_count = static_cast<unsigned>(no_match_controls.size());
  if (no_match_count == 1) {
    no_match_control = no_match_controls[0];
    no_match_effect = no_match_effects[0];
  } else {
    // Range is 2..4, so casting to unsigned is safe.
    no_match_control = Merge(no_match_count, no_match_controls.data());
    // EffectPhis need their control dependency as an additional input.
    no_match_effects.emplace_back(no_match_control);
    no_match_effect = EffectPhi(no_match_count, no_match_effects.data());
  }

  return {match_control, match_effect, no_match_control, no_match_effect};
}

Node* WasmGraphBuilder::RefTest(Node* object, Node* rtt,
                                WasmTypeCheckConfig config) {
  return gasm_->WasmTypeCheck(object, rtt, config);
}

Node* WasmGraphBuilder::RefTestAbstract(Node* object,
                                        WasmTypeCheckConfig config) {
  DCHECK(!config.to.has_index());
  return gasm_->WasmTypeCheckAbstract(object, config);
}

Node* WasmGraphBuilder::RefCast(Node* object, Node* rtt,
                                WasmTypeCheckConfig config,
                                wasm::WasmCodePosition position) {
  Node* cast = gasm_->WasmTypeCast(object, rtt, config);
  SetSourcePosition(cast, position);
  return cast;
}

Node* WasmGraphBuilder::RefCastAbstract(Node* object,
                                        WasmTypeCheckConfig config,
                                        wasm::WasmCodePosition position) {
  DCHECK(!config.to.has_index());
  Node* cast = gasm_->WasmTypeCastAbstract(object, config);
  SetSourcePosition(cast, position);
  return cast;
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnCast(
    Node* object, Node* rtt, WasmTypeCheckConfig config) {
  auto [true_node, false_node] =
      BranchNoHint(gasm_->WasmTypeCheck(object, rtt, config));

  return {true_node,   // control on match
          effect(),    // effect on match
          false_node,  // control on no match
          effect()};   // effect on no match
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnEq(
    Node* object, Node* /*rtt*/, WasmTypeCheckConfig config) {
  return BrOnCastAbs([this, config, object](Callbacks callbacks) -> void {
    if (config.from.is_nullable()) {
      if (config.to.is_nullable()) {
        callbacks.succeed_if(gasm_->IsNull(object, config.from),
                             BranchHint::kFalse);
      } else {
        // The {IsDataRefMap} check below will fail for {null}.
      }
    }
    callbacks.succeed_if(gasm_->IsSmi(object), BranchHint::kFalse);
    Node* map = gasm_->LoadMap(object);
    callbacks.fail_if_not(gasm_->IsDataRefMap(map), BranchHint::kTrue);
  });
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnStruct(
    Node* object, Node* /*rtt*/, WasmTypeCheckConfig config) {
  bool null_succeeds = config.to.is_nullable();
  return BrOnCastAbs(
      [this, object, config, null_succeeds](Callbacks callbacks) -> void {
        return ManagedObjectInstanceCheck(object, config.from.is_nullable(),
                                          WASM_STRUCT_TYPE, callbacks,
                                          null_succeeds);
      });
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnArray(
    Node* object, Node* /*rtt*/, WasmTypeCheckConfig config) {
  bool null_succeeds = config.to.is_nullable();
  return BrOnCastAbs(
      [this, config, object, null_succeeds](Callbacks callbacks) -> void {
        return ManagedObjectInstanceCheck(object, config.from.is_nullable(),
                                          WASM_ARRAY_TYPE, callbacks,
                                          null_succeeds);
      });
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnI31(
    Node* object, Node* /* rtt */, WasmTypeCheckConfig config) {
  return BrOnCastAbs([this, object, config](Callbacks callbacks) -> void {
    if (config.from.is_nullable()) {
      if (config.to.is_nullable()) {
        callbacks.succeed_if(gasm_->IsNull(object, config.from),
                             BranchHint::kFalse);
      } else {
        // Covered by the {IsSmi} check below.
      }
    }
    callbacks.fail_if_not(gasm_->IsSmi(object), BranchHint::kTrue);
  });
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnString(
    Node* object, Node* /*rtt*/, WasmTypeCheckConfig config) {
  bool null_succeeds = config.to.is_nullable();
  return BrOnCastAbs(
      [this, config, object, null_succeeds](Callbacks callbacks) -> void {
        return StringCheck(object, config.from.is_nullable(), callbacks,
                           null_succeeds);
      });
}

Node* WasmGraphBuilder::TypeGuard(Node* value, wasm::ValueType type) {
  DCHECK_NOT_NULL(env_);
  return SetEffect(graph()->NewNode(mcgraph()->common()->TypeGuard(Type::Wasm(
                                        type, env_->module, graph()->zone())),
                                    value, effect(), control()));
}

Node* WasmGraphBuilder::StructGet(Node* struct_object,
                                  const wasm::StructType* struct_type,
                                  uint32_t field_index, CheckForNull null_check,
                                  bool is_signed,
                                  wasm::WasmCodePosition position) {
  Node* result = gasm_->StructGet(struct_object, struct_type, field_index,
                                  is_signed, null_check);
  SetSourcePosition(result, position);
  return result;
}

void WasmGraphBuilder::StructSet(Node* struct_object,
                                 const wasm::StructType* struct_type,
                                 uint32_t field_index, Node* field_value,
                                 CheckForNull null_check,
                                 wasm::WasmCodePosition position) {
  gasm_->StructSet(struct_object, field_value, struct_type, field_index,
                   null_check);
  SetSourcePosition(effect(), position);
}

void WasmGraphBuilder::BoundsCheckArray(Node* array, Node* index,
                                        CheckForNull null_check,
                                        wasm::WasmCodePosition position) {
  if (V8_UNLIKELY(v8_flags.experimental_wasm_skip_bounds_checks)) {
    if (null_check == kWithNullCheck) {
      AssertNotNull(array, wasm::kWasmArrayRef, position);
    }
  } else {
    Node* length = gasm_->ArrayLength(array, null_check);
    SetSourcePosition(length, position);
    TrapIfFalse(wasm::kTrapArrayOutOfBounds,
                gasm_->Uint32LessThan(index, length), position);
  }
}

void WasmGraphBuilder::BoundsCheckArrayWithLength(
    Node* array, Node* index, Node* length, CheckForNull null_check,
    wasm::WasmCodePosition position) {
  if (V8_UNLIKELY(v8_flags.experimental_wasm_skip_bounds_checks)) return;
  Node* array_length = gasm_->ArrayLength(array, null_check);
  SetSourcePosition(array_length, position);
  Node* range_end = gasm_->Int32Add(index, length);
  Node* range_valid = gasm_->Word32And(
      // OOB if (index + length > array.len).
      gasm_->Uint32LessThanOrEqual(range_end, array_length),
      // OOB if (index + length) overflows.
      gasm_->Uint32LessThanOrEqual(index, range_end));
  TrapIfFalse(wasm::kTrapArrayOutOfBounds, range_valid, position);
}

Node* WasmGraphBuilder::ArrayGet(Node* array_object,
                                 const wasm::ArrayType* type, Node* index,
                                 CheckForNull null_check, bool is_signed,
                                 wasm::WasmCodePosition position) {
  BoundsCheckArray(array_object, index, null_check, position);
  return gasm_->ArrayGet(array_object, index, type, is_signed);
}

void WasmGraphBuilder::ArraySet(Node* array_object, const wasm::ArrayType* type,
                                Node* index, Node* value,
                                CheckForNull null_check,
                                wasm::WasmCodePosition position) {
  BoundsCheckArray(array_object, index, null_check, position);
  gasm_->ArraySet(array_object, index, value, type);
}

Node* WasmGraphBuilder::ArrayLen(Node* array_object, CheckForNull null_check,
                                 wasm::WasmCodePosition position) {
  Node* result = gasm_->ArrayLength(array_object, null_check);
  SetSourcePosition(result, position);
  return result;
}

void WasmGraphBuilder::ArrayCopy(Node* dst_array, Node* dst_index,
                                 CheckForNull dst_null_check, Node* src_array,
                                 Node* src_index, CheckForNull src_null_check,
                                 Node* length,
                                 const wasm::ArrayType* array_type,
                                 wasm::WasmCodePosition position) {
  BoundsCheckArrayWithLength(dst_array, dst_index, length, dst_null_check,
                             position);
  BoundsCheckArrayWithLength(src_array, src_index, length, src_null_check,
                             position);

  auto end = gasm_->MakeLabel();

  gasm_->GotoIf(gasm_->Word32Equal(length, Int32Constant(0)), &end);

  auto builtin = gasm_->MakeLabel();

  // Values determined by test/mjsunit/wasm/array-copy-benchmark.js on x64.
  int array_copy_max_loop_length;
  switch (array_type->element_type().kind()) {
    case wasm::kI32:
    case wasm::kI64:
    case wasm::kI8:
    case wasm::kI16:
      array_copy_max_loop_length = 20;
      break;
    case wasm::kF16:
    case wasm::kF32:
    case wasm::kF64:
      array_copy_max_loop_length = 35;
      break;
    case wasm::kS128:
      array_copy_max_loop_length = 100;
      break;
    case wasm::kRtt:
    case wasm::kRef:
    case wasm::kRefNull:
      array_copy_max_loop_length = 15;
      break;
    case wasm::kVoid:
    case wasm::kTop:
    case wasm::kBottom:
      UNREACHABLE();
  }

  gasm_->GotoIf(
      gasm_->Uint32LessThan(Int32Constant(array_copy_max_loop_length), length),
      &builtin);

  auto reverse = gasm_->MakeLabel();

  gasm_->GotoIf(gasm_->Uint32LessThan(src_index, dst_index), &reverse);

  Node* src_end_index = gasm_->Int32Sub(gasm_->Int32Add(src_index, length),
                                        gasm_->Int32Constant(1));
  Node* dst_end_index = gasm_->Int32Sub(gasm_->Int32Add(dst_index, length),
                                        gasm_->Int32Constant(1));

  {
    auto loop = gasm_->MakeLoopLabel(MachineRepresentation::kWord32,
                                     MachineRepresentation::kWord32);

    gasm_->Goto(&loop, src_index, dst_index);
    gasm_->Bind(&loop);

    Node* value = gasm_->ArrayGet(src_array, loop.PhiAt(0), array_type, false);
    gasm_->ArraySet(dst_array, loop.PhiAt(1), value, array_type);

    Node* condition = gasm_->Uint32LessThan(loop.PhiAt(0), src_end_index);
    gasm_->GotoIfNot(condition, &end);
    gasm_->Goto(&loop, gasm_->Int32Add(loop.PhiAt(0), Int32Constant(1)),
                gasm_->Int32Add(loop.PhiAt(1), Int32Constant(1)));
  }

  {
    gasm_->Bind(&reverse);
    auto loop = gasm_->MakeLoopLabel(MachineRepresentation::kWord32,
                                     MachineRepresentation::kWord32);

    gasm_->Goto(&loop, src_end_index, dst_end_index);
    gasm_->Bind(&loop);

    Node* value = gasm_->ArrayGet(src_array, loop.PhiAt(0), array_type, false);
    gasm_->ArraySet(dst_array, loop.PhiAt(1), value, array_type);

    Node* condition = gasm_->Uint32LessThan(src_index, loop.PhiAt(0));
    gasm_->GotoIfNot(condition, &end);
    gasm_->Goto(&loop, gasm_->Int32Sub(loop.PhiAt(0), Int32Constant(1)),
                gasm_->Int32Sub(loop.PhiAt(1), Int32Constant(1)));
  }

  {
    gasm_->Bind(&builtin);
    Node* function =
        gasm_->ExternalConstant(ExternalReference::wasm_array_copy());
    MachineType arg_types[]{MachineType::TaggedPointer(), MachineType::Uint32(),
                            MachineType::TaggedPointer(), MachineType::Uint32(),
                            MachineType::Uint32()};
    MachineSignature sig(0, 5, arg_types);
    BuildCCall(&sig, function, dst_array, dst_index, src_array, src_index,
               length);
    gasm_->Goto(&end);
  }

  gasm_->Bind(&end);
}

Node* WasmGraphBuilder::StoreInInt64StackSlot(Node* value,
                                              wasm::ValueType type) {
  Node* value_int64;
  switch (type.kind()) {
    case wasm::kI32:
    case wasm::kI8:
    case wasm::kI16:
      value_int64 =
          graph()->NewNode(mcgraph()->machine()->ChangeInt32ToInt64(), value);
      break;
    case wasm::kI64:
      value_int64 = value;
      break;
    case wasm::kS128:
      // We can only get here if {value} is the constant 0.
      DCHECK_EQ(value->opcode(), IrOpcode::kS128Zero);
      value_int64 = Int64Constant(0);
      break;
    case wasm::kF32:
      value_int64 = graph()->NewNode(
          mcgraph()->machine()->ChangeInt32ToInt64(),
          graph()->NewNode(mcgraph()->machine()->BitcastFloat32ToInt32(),
                           value));
      break;
    case wasm::kF64:
      value_int64 = graph()->NewNode(
          mcgraph()->machine()->BitcastFloat64ToInt64(), value);
      break;
    case wasm::kRefNull:
    case wasm::kRef:
      value_int64 = kSystemPointerSize == 4
                        ? graph()->NewNode(
                              mcgraph()->machine()->ChangeInt32ToInt64(), value)
                        : value;
      break;
    case wasm::kF16:
      UNIMPLEMENTED();
    case wasm::kRtt:
    case wasm::kVoid:
    case wasm::kTop:
    case wasm::kBottom:
      UNREACHABLE();
  }

  return StoreArgsInStackSlot({{MachineRepresentation::kWord64, value_int64}});
}

void WasmGraphBuilder::ArrayFill(Node* array, Node* index, Node* value,
                                 Node* length, const wasm::ArrayType* type,
                                 CheckForNull null_check,
                                 wasm::WasmCodePosition position) {
  BoundsCheckArrayWithLength(array, index, length, null_check, position);
  ArrayFillImpl(array, index, value, length, type,
                type->element_type().is_reference());
}

void WasmGraphBuilder::ArrayFillImpl(Node* array, Node* index, Node* value,
                                     Node* length, const wasm::ArrayType* type,
                                     bool emit_write_barrier) {
  DCHECK_NOT_NULL(value);
  wasm::ValueType element_type = type->element_type();

  // Initialize the array. Use an external function for large arrays with
  // null/number initializer. Use a loop for small arrays and reference arrays
  // with a non-null initial value.
  auto done = gasm_->MakeLabel();
  // TODO(manoskouk): If the loop is ever removed here, we have to update
  // ArrayNew(), ArrayNewDefault(), and ArrayFill() in
  // graph-builder-interface.cc to not mark the current loop as non-innermost.
  auto loop = gasm_->MakeLoopLabel(MachineRepresentation::kWord32);

  // The builtin cannot handle s128 values other than 0.
  if (!(element_type == wasm::kWasmS128 &&
        value->opcode() != IrOpcode::kS128Zero)) {
    constexpr uint32_t kArrayNewMinimumSizeForMemSet = 16;
    gasm_->GotoIf(gasm_->Uint32LessThan(
                      length, Int32Constant(kArrayNewMinimumSizeForMemSet)),
                  &loop, BranchHint::kNone, index);
    Node* function =
        gasm_->ExternalConstant(ExternalReference::wasm_array_fill());

    Node* stack_slot = StoreInInt64StackSlot(value, element_type);

    MachineType arg_types[]{
        MachineType::TaggedPointer(), MachineType::Uint32(),
        MachineType::Uint32(),        MachineType::Uint32(),
        MachineType::Uint32(),        MachineType::Pointer()};
    MachineSignature sig(0, 6, arg_types);
    BuildCCall(&sig, function, array, index, length,
               Int32Constant(emit_write_barrier ? 1 : 0),
               Int32Constant(element_type.raw_bit_field()), stack_slot);
    gasm_->Goto(&done);
  } else {
    gasm_->Goto(&loop, index);
  }
  gasm_->Bind(&loop);
  {
    Node* current_index = loop.PhiAt(0);
    Node* check =
        gasm_->UintLessThan(current_index, gasm_->Int32Add(index, length));
    gasm_->GotoIfNot(check, &done);
    gasm_->ArraySet(array, current_index, value, type);
    current_index = gasm_->Int32Add(current_index, Int32Constant(1));
    gasm_->Goto(&loop, current_index);
  }
  gasm_->Bind(&done);
}

// General rules for operator properties for builtin calls:
// - Use kEliminatable if it can neither throw a catchable exception nor trap.
// - Use kNoDeopt | kNoThrow if it can trap (because in that case, eliminating
//   it would avoid the trap and thereby observably change the code's behavior
//   compared to its unoptimized version).
// - If you don't use kNoThrow (nor kEliminatable which implies it), then you
//   must also set up control nodes for the throwing case, e.g. by using
//   WasmGraphBuildingInterface::CheckForException().

Node* WasmGraphBuilder::StringNewWtf8(const wasm::WasmMemory* memory,
                                      unibrow::Utf8Variant variant,
                                      Node* offset, Node* size,
                                      wasm::WasmCodePosition position) {
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringNewWtf8,
                            Operator::kNoDeopt | Operator::kNoThrow, offset,
                            size, gasm_->Int32Constant(memory->index),
                            gasm_->SmiConstant(static_cast<int32_t>(variant)));
}

Node* WasmGraphBuilder::StringNewWtf8Array(unibrow::Utf8Variant variant,
                                           Node* array, CheckForNull null_check,
                                           Node* start, Node* end,
                                           wasm::WasmCodePosition position) {
  // Special case: shortcut a sequence "array from data segment" + "string from
  // wtf8 array" to directly create a string from the segment.
  if (IsArrayNewSegment(array)) {
    // We can only pass 3 untagged parameters to the builtin (on 32-bit
    // platforms). The segment index is easy to tag: if it validated, it must
    // be in Smi range.
    Node* segment_index = NodeProperties::GetValueInput(array, 1);
    Uint32Matcher index_matcher(segment_index);
    DCHECK(index_matcher.HasResolvedValue());
    Node* segment_index_smi = gasm_->SmiConstant(index_matcher.ResolvedValue());
    // Arbitrary choice for the second tagged parameter: the segment offset.
    Node* segment_offset = NodeProperties::GetValueInput(array, 2);
    TrapIfFalse(wasm::kTrapDataSegmentOutOfBounds,
                gasm_->Uint32LessThan(segment_offset,
                                      gasm_->Uint32Constant(Smi::kMaxValue)),
                position);
    Node* segment_offset_smi = gasm_->BuildChangeInt32ToSmi(segment_offset);
    Node* segment_length = NodeProperties::GetValueInput(array, 3);
    Node* variant_smi = gasm_->SmiConstant(static_cast<int32_t>(variant));
    return gasm_->CallBuiltin(Builtin::kWasmStringFromDataSegment,
                              Operator::Operator::kNoDeopt | Operator::kNoThrow,
                              segment_length, start, end, segment_index_smi,
                              segment_offset_smi, variant_smi);
  }

  // Regular path if the shortcut wasn't taken.
  if (null_check == kWithNullCheck) {
    array = AssertNotNull(array, wasm::kWasmArrayRef, position);
  }
  return gasm_->CallBuiltin(
      Builtin::kWasmStringNewWtf8Array, Operator::kNoDeopt | Operator::kNoThrow,
      start, end, array, gasm_->SmiConstant(static_cast<int32_t>(variant)));
}

Node* WasmGraphBuilder::StringNewWtf16(const wasm::WasmMemory* memory,
                                       Node* offset, Node* size,
                                       wasm::WasmCodePosition position) {
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringNewWtf16,
                            Operator::kNoDeopt | Operator::kNoThrow,
                            gasm_->Uint32Constant(memory->index), offset, size);
}

Node* WasmGraphBuilder::StringNewWtf16Array(Node* array,
                                            CheckForNull null_check,
                                            Node* start, Node* end,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    array = AssertNotNull(array, wasm::kWasmArrayRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringNewWtf16Array,
                            Operator::kNoDeopt | Operator::kNoThrow, array,
                            start, end);
}

Node* WasmGraphBuilder::StringConst(uint32_t index) {
  return gasm_->CallBuiltin(Builtin::kWasmStringConst,
                            Operator::kNoDeopt | Operator::kNoThrow,
                            gasm_->Uint32Constant(index));
}

Node* WasmGraphBuilder::StringMeasureUtf8(Node* string, CheckForNull null_check,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringMeasureUtf8,
                            Operator::kEliminatable, string);
}

Node* WasmGraphBuilder::StringMeasureWtf8(Node* string, CheckForNull null_check,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringMeasureWtf8,
                            Operator::kEliminatable, string);
}

Node* WasmGraphBuilder::StringMeasureWtf16(Node* string,
                                           CheckForNull null_check,
                                           wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->LoadStringLength(string);
}

Node* WasmGraphBuilder::StringEncodeWtf8(const wasm::WasmMemory* memory,
                                         unibrow::Utf8Variant variant,
                                         Node* string, CheckForNull null_check,
                                         Node* offset,
                                         wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(
      Builtin::kWasmStringEncodeWtf8, Operator::kNoDeopt | Operator::kNoThrow,
      offset, gasm_->Int32Constant(memory->index),
      gasm_->Int32Constant(static_cast<int32_t>(variant)), string);
}

Node* WasmGraphBuilder::StringEncodeWtf8Array(
    unibrow::Utf8Variant variant, Node* string, CheckForNull string_null_check,
    Node* array, CheckForNull array_null_check, Node* start,
    wasm::WasmCodePosition position) {
  if (string_null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  if (array_null_check == kWithNullCheck) {
    array = AssertNotNull(array, wasm::kWasmArrayRef, p
"""


```