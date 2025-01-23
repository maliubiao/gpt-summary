Response:
Let's break down the thought process for analyzing the provided C++ header file snippet.

**1. Initial Scan and Identification of Key Structures:**

The first step is to quickly scan the code to identify the primary structures. Keywords like `struct`, `enum`, and `class` are good indicators. In this case, we immediately see `ConstantOp`, `LoadOp`, `AtomicRMWOp`, `AtomicWord32PairOp`, `MemoryBarrierOp`, and `StoreOp`. This tells us the file is likely defining different types of operations.

**2. Deep Dive into `ConstantOp`:**

* **Purpose:** The name `ConstantOp` strongly suggests this operation represents a constant value. The `Kind` enum within it confirms this, listing various types of constants (word32, word64, float, etc.).
* **Storage:** The `Storage` union is crucial. It allows `ConstantOp` to hold different data types in the same memory location, optimizing for space. The constructors for `Storage` further clarify the types of constants supported.
* **Representation:** The `Representation` static method determines how the constant value should be represented in registers (e.g., as a 32-bit word, a 64-bit word, a tagged pointer, etc.). This is essential for the compiler's register allocation phase.
* **Methods:**  Methods like `integral()`, `float32()`, `handle()`, etc., provide access to the stored constant value in the correct type. The `IsIntegral()`, `IsWord()` methods provide ways to check the type and value of the constant.
* **JavaScript Relevance (Hypothesis):** Constants are fundamental in any programming language, including JavaScript. We can hypothesize that `ConstantOp` might be used to represent literal values in JavaScript code (numbers, strings, booleans represented as tagged pointers, etc.).

**3. Analyzing `LoadOp`:**

* **Purpose:** The name `LoadOp` clearly indicates an operation that loads data from memory.
* **`Kind` Struct:** The nested `Kind` struct is complex and highly informative. It describes various attributes of a load operation, such as whether the base address is tagged, if it might be unaligned, if there's a trap handler, and whether the load is considered "load eliminable" (important for optimizations).
* **Inputs and Outputs:** `inputs_rep()` and `outputs_rep()` tell us the register representations of the inputs (base address, optional index) and output (loaded value).
* **JavaScript Relevance (Hypothesis):** Loads are essential for accessing variables, object properties, and array elements in JavaScript. We can hypothesize a `LoadOp` would be generated when accessing these.

**4. Examining `AtomicRMWOp`:**

* **Purpose:** The name suggests "Atomic Read-Modify-Write Operation." This is confirmed by the `BinOp` enum (Add, Sub, And, etc.) and the `CompareExchange` option. Atomic operations are crucial for multi-threaded environments.
* **JavaScript Relevance (Hypothesis):** While JavaScript is generally single-threaded in the main execution context, SharedArrayBuffer and Atomics API introduce shared memory and the need for atomic operations. We can hypothesize this is related to those features.

**5. Reviewing `AtomicWord32PairOp`:**

* **Purpose:** This appears to be a specialized atomic operation working on 64-bit values (pairs of 32-bit words). This is likely for platforms or scenarios where native 64-bit atomic operations are not directly available or efficient.
* **JavaScript Relevance (Hypothesis):**  Similar to `AtomicRMWOp`, this is likely tied to the SharedArrayBuffer and Atomics API for manipulating larger values atomically.

**6. Understanding `MemoryBarrierOp`:**

* **Purpose:** Memory barriers are synchronization primitives that enforce ordering of memory operations. The `AtomicMemoryOrder` enum further clarifies the type of ordering enforced.
* **JavaScript Relevance (Hypothesis):** Again, in the context of SharedArrayBuffer and Atomics, memory barriers are essential for ensuring correct data visibility and preventing race conditions between threads.

**7. Investigating `StoreOp`:**

* **Purpose:** The counterpart to `LoadOp`, this operation stores a value to memory.
* **`Kind` (Reused):**  Notice the reuse of `LoadOp::Kind`. This suggests that stores share similar characteristics with loads regarding base addressing, alignment, and trap handling.
* **`WriteBarrierKind`:** This is specific to stores in garbage-collected environments like V8. Write barriers are needed to inform the garbage collector about modifications to object references.
* **JavaScript Relevance (Hypothesis):**  Stores are fundamental for assigning values to variables, object properties, and array elements. The `WriteBarrierKind` highlights V8's memory management.

**8. Inferring Overall Functionality and Context:**

By examining the individual operation types, we can infer the overall purpose of `operations.h`:

* **Intermediate Representation (IR):** This header likely defines the operations used in Turboshaft, V8's optimizing compiler. These operations are higher-level than assembly instructions but lower-level than JavaScript source code.
* **Code Generation:** These operations form the building blocks for generating machine code. The register representations (`RegisterRepresentation`) are a strong clue to this.
* **Optimization:** The various flags and options within the operation structures (like `load_eliminable`) hint at optimization strategies the compiler employs.
* **Memory Management:**  The presence of `WriteBarrierKind` in `StoreOp` indicates the compiler's awareness of V8's garbage collection.
* **Concurrency:** The atomic operations and memory barriers point to support for concurrent JavaScript execution models (SharedArrayBuffer/Atomics).

**9. Addressing Specific Questions from the Prompt:**

* **`.tq` Extension:** The prompt correctly notes that `.tq` signifies Torque code. This header file is `.h`, so it's standard C++.
* **JavaScript Examples:** Based on the analysis, we can construct JavaScript examples that likely correspond to the defined operations (as done in the provided good answer).
* **Logic Inference:**  We can make assumptions about input and output registers based on the `inputs_rep()` and `outputs_rep()` methods.
* **Common Programming Errors:** We can relate these low-level operations to common JavaScript errors, like type mismatches leading to incorrect loads/stores or race conditions in concurrent code.

**10. Iteration and Refinement:**

The analysis is not always linear. We might jump between structures, revisit earlier assumptions, and refine our understanding as we discover more information. For example, realizing that `LoadOp::Kind` is reused in `StoreOp` reinforces the connection between these two fundamental memory access operations.

This structured approach allows us to systematically dissect the code and gain a comprehensive understanding of its purpose and functionality within the V8 JavaScript engine.
这是第 4 部分，共 11 部分，我们继续分析 `v8/src/compiler/turboshaft/operations.h` 这个 V8 源代码头文件。根据你之前提供的信息，我们知道这个文件定义了 Turboshaft 编译器中使用的各种操作（Operations）。

**归纳一下它的功能（到目前为止分析的部分）：**

到目前为止，我们分析的代码主要定义了以下几种类型的操作，它们是 Turboshaft 编译器进行代码转换和优化的基本构建块：

1. **`ConstantOp`**: 表示常量值。可以存储各种类型的常量，如整数、浮点数、Smi、堆对象句柄等。它提供了获取不同类型常量值的方法，并考虑了 WebAssembly 的特殊常量类型。

2. **`LoadOp`**: 表示从内存中加载值的操作。它定义了加载操作的各种属性，例如是否使用标记基址、是否可能未对齐、是否需要陷阱处理程序、是否可以消除加载等。它允许指定加载值的内存表示和结果的寄存器表示。

3. **`AtomicRMWOp`**: 表示原子读-修改-写操作。它支持多种原子操作，如加、减、与、或、异或、交换和比较交换。它允许指定操作数和内存的表示形式，以及内存访问的类型（例如，是否受陷阱处理程序保护）。

4. **`AtomicWord32PairOp`**:  表示对 64 位值进行原子操作，通过将其分解为两个 32 位字来实现。支持原子加载、存储以及各种原子读-修改-写操作。

5. **`MemoryBarrierOp`**: 表示内存屏障操作，用于确保多线程环境下的内存操作顺序。允许指定不同的内存顺序。

6. **`StoreOp`**: 表示将值存储到内存的操作。它重用了 `LoadOp` 的 `Kind` 结构来描述存储操作的属性。它还包含了写入屏障的信息，这对于垃圾回收器跟踪对象引用至关重要。

**更详细的功能分析 (针对提供的代码片段):**

* **`ConstantOp` 的详细功能:**
    * **存储不同类型的常量:**  通过 `union Storage` 可以存储不同类型的常量值，节省内存空间。
    * **提供类型安全的访问:**  提供了 `integral()`, `float32()`, `smi()`, `handle()` 等方法，确保以正确的类型访问常量值。
    * **支持 WebAssembly 特定的常量:**  包含了 `kRelocatableWasmCall` 等 `Kind`，表明它也用于 WebAssembly 的编译。
    * **提供比较和哈希功能:** 实现了 `operator==` 和 `hash_value`，方便在编译器内部进行常量的比较和查找。

* **`LoadOp` 的详细功能:**
    * **灵活的地址计算:**  支持基址加偏移量，还可以选择加上索引乘以元素大小。
    * **处理不同类型的基址:**  通过 `tagged_base` 区分基址是指向堆对象的指针还是原始指针。
    * **处理未对齐的访问:**  通过 `maybe_unaligned` 标记，允许处理可能未对齐的内存访问。
    * **支持陷阱处理:**  通过 `with_trap_handler` 和 `trap_on_null` 支持加载时可能发生的越界或空指针访问的陷阱处理。
    * **优化提示:**  `load_eliminable` 标志是一个重要的优化提示，指示加载的值是否可能被其他操作修改，从而影响加载消除等优化。
    * **原子性支持:** `is_atomic` 标志表明这是一个原子加载操作。

* **`AtomicRMWOp` 的详细功能:**
    * **多种原子操作:** 支持常见的原子算术和位运算，以及原子交换和比较交换。
    * **指定操作数和内存表示:** 允许为原子操作指定操作数和内存的表示形式。
    * **支持带保护的原子操作:** 可以指定原子操作是否受到陷阱处理程序的保护。

* **`AtomicWord32PairOp` 的详细功能:**
    * **模拟 64 位原子操作:**  在不支持原生 64 位原子操作的平台上，提供了一种模拟的方式。
    * **支持加载和存储:** 除了读-修改-写操作，还支持原子加载和存储 64 位值。

* **`MemoryBarrierOp` 的详细功能:**
    * **控制内存操作顺序:**  允许插入不同类型的内存屏障，以确保在多线程环境中，内存操作按照预期的顺序执行。

* **`StoreOp` 的详细功能:**
    * **与 `LoadOp` 类似的地址计算和属性:**  重用 `LoadOp::Kind` 简化了设计，并表明存储操作具有类似的属性。
    * **写入屏障:**  `write_barrier` 字段是垃圾回收的关键，用于通知垃圾回收器哪些内存位置存储了指向堆对象的指针，以便在垃圾回收时正确处理。
    * **支持初始化和转换:** `maybe_initializing_or_transitioning` 标志可能用于指示存储操作是对象初始化或属性转换的一部分。
    * **间接指针标签:** `shifted_indirect_pointer_tag` 用于处理间接指针存储，可能与 V8 的对象模型有关。
    * **原子性支持:** `is_atomic` 标志表明这是一个原子存储操作。

**关于 JavaScript 的关系和例子：**

这些操作虽然是编译器内部的表示，但都直接或间接地与 JavaScript 的功能相关。

* **`ConstantOp`**:  JavaScript 中的字面量，例如 `10`, `3.14`, `"hello"`, `null`, `undefined` 等，在编译器内部会被表示为 `ConstantOp`。

   ```javascript
   const a = 10; // 10 可能被表示为 Kind::kWord32 的 ConstantOp
   const b = "hello"; // "hello" 可能被表示为 Kind::kHeapObject 的 ConstantOp，指向一个字符串对象
   ```

* **`LoadOp`**:  JavaScript 中访问变量、对象属性或数组元素时，会生成 `LoadOp`。

   ```javascript
   const obj = { x: 5 };
   const y = obj.x; // 访问 obj.x 会生成一个 LoadOp，从 obj 对象加载 x 属性的值

   const arr = [1, 2, 3];
   const z = arr[1]; // 访问 arr[1] 会生成一个 LoadOp，计算数组元素的地址并加载值
   ```

* **`AtomicRMWOp` 和 `AtomicWord32PairOp`**:  与 JavaScript 的 `SharedArrayBuffer` 和 `Atomics` API 相关。

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
   const view = new Int32Array(sab);
   Atomics.add(view, 0, 5); // 这会生成一个 AtomicRMWOp，对共享数组缓冲区中的值进行原子加操作

   const sab64 = new SharedArrayBuffer(BigInt64Array.BYTES_PER_ELEMENT);
   const view64 = new BigInt64Array(sab64);
   //  虽然没有直接对应 AtomicWord32PairOp 的 JS API，但在内部处理 64 位原子操作时可能会用到
   ```

* **`MemoryBarrierOp`**:  在 `Atomics` API 中，某些操作（例如 `Atomics.store`, `Atomics.load`）会隐式地包含内存屏障，或者可以使用 `Atomics.fence()` 显式地插入内存屏障。

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
   const view = new Int32Array(sab);
   Atomics.store(view, 0, 10); // Atomics.store 可能包含一个隐式的内存屏障
   ```

* **`StoreOp`**:  JavaScript 中给变量赋值、设置对象属性或数组元素时，会生成 `StoreOp`。

   ```javascript
   let count = 0;
   count = 1; // 给变量赋值会生成一个 StoreOp

   const obj = {};
   obj.name = "John"; // 设置对象属性会生成一个 StoreOp

   const arr = [];
   arr[0] = 100; // 给数组元素赋值会生成一个 StoreOp
   ```

**代码逻辑推理和假设输入输出：**

以 `LoadOp` 为例：

**假设输入：**

* `base`:  一个指向对象的指针（例如，代表 JavaScript 对象 `{ x: 5 }` 的内存地址）。假设地址是 `0x12345678`。
* `offset`:  属性 `x` 在对象中的偏移量。假设是 `8` 字节。
* `loaded_rep`:  `MemoryRepresentation::Int32()`，假设 `x` 是一个 32 位整数。
* `result_rep`: `RegisterRepresentation::Word32()`，加载的结果将放入一个 32 位寄存器。

**操作：**

`LoadOp` 将会执行以下逻辑：从内存地址 `base + offset` (即 `0x12345678 + 8`) 加载一个 32 位整数。

**假设输出：**

假设地址 `0x12345680` 到 `0x12345683` 存储的值是 `0x00000005`。那么 `LoadOp` 的输出将会是将值 `5` 加载到指定的 32 位寄存器中。

**用户常见的编程错误：**

* **类型不匹配导致的错误的 `LoadOp` 或 `StoreOp`:**  如果 JavaScript 代码期望一个数字，但实际内存中存储的是一个字符串的指针，那么生成的 `LoadOp` 可能会尝试将指针加载为数字，导致类型错误或崩溃。

   ```javascript
   let value = "hello";
   let num = value + 5; // 字符串和数字相加，可能导致类型转换错误
   ```
   编译器可能会错误地假设 `value` 是一个数字并生成相应的 `LoadOp`。

* **并发编程中的数据竞争：**  在多线程环境中使用 `SharedArrayBuffer` 但没有正确地使用 `Atomics` 或内存屏障，可能导致数据竞争，即多个线程同时读写同一块内存，导致不可预测的结果。这与 `AtomicRMWOp`, `AtomicWord32PairOp`, 和 `MemoryBarrierOp` 的使用不当有关。

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
   const view = new Int32Array(sab);

   // 线程 1
   view[0] = view[0] + 1; // 没有使用 Atomics，可能发生数据竞争

   // 线程 2
   view[0] = view[0] * 2;
   ```

**总结第 4 部分的功能：**

这部分主要定义了用于操作常量值和内存的 Turboshaft 操作：

* **`ConstantOp`**:  用于表示和操作各种类型的常量。
* **`LoadOp`**:  用于从内存中加载数据，并提供了丰富的属性来描述加载操作的特性。
* **`AtomicRMWOp`**: 用于执行原子读-修改-写操作，保证多线程环境下的数据一致性。
* **`AtomicWord32PairOp`**: 用于模拟 64 位原子操作。
* **`MemoryBarrierOp`**: 用于控制内存操作的顺序，是并发编程的重要组成部分。
* **`StoreOp`**: 用于将数据存储到内存，并包含了垃圾回收和优化的相关信息。

这些操作是构建更复杂编译器优化的基础，它们在将 JavaScript 代码转换为高效机器码的过程中发挥着关键作用。它们也反映了 V8 对 WebAssembly 和并发 JavaScript 特性的支持。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/operations.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/operations.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共11部分，请归纳一下它的功能
```

### 源代码
```c
stedHeapObject,
    kRelocatableWasmCall,
    kRelocatableWasmStubCall,
    kRelocatableWasmIndirectCallTarget,
    kRelocatableWasmCanonicalSignatureId
  };

  Kind kind;
  RegisterRepresentation rep = Representation(kind);
  union Storage {
    uint64_t integral;
    i::Float32 float32;
    i::Float64 float64;
    ExternalReference external;
    IndirectHandle<HeapObject> handle;

    Storage(uint64_t integral = 0) : integral(integral) {}
    Storage(i::Tagged<Smi> smi) : integral(smi.ptr()) {}
    Storage(i::Float64 constant) : float64(constant) {}
    Storage(i::Float32 constant) : float32(constant) {}
    Storage(ExternalReference constant) : external(constant) {}
    Storage(IndirectHandle<HeapObject> constant) : handle(constant) {}

    inline bool operator==(const ConstantOp::Storage&) const {
      // It is tricky to implement this properly. We currently need to define
      // this for the matchers, but this should never be called.
      UNREACHABLE();
    }
  } storage;

  static constexpr OpEffects effects = OpEffects();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return base::VectorOf(&rep, 1);
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return {};
  }

  static RegisterRepresentation Representation(Kind kind) {
    switch (kind) {
      case Kind::kRelocatableWasmCanonicalSignatureId:
      case Kind::kWord32:
        return RegisterRepresentation::Word32();
      case Kind::kWord64:
        return RegisterRepresentation::Word64();
      case Kind::kFloat32:
        return RegisterRepresentation::Float32();
      case Kind::kFloat64:
        return RegisterRepresentation::Float64();
      case Kind::kExternal:
      case Kind::kTaggedIndex:
      case Kind::kTrustedHeapObject:
      case Kind::kRelocatableWasmCall:
      case Kind::kRelocatableWasmStubCall:
        return RegisterRepresentation::WordPtr();
      case Kind::kRelocatableWasmIndirectCallTarget:
        return RegisterRepresentation::WasmCodePointer();
      case Kind::kSmi:
      case Kind::kHeapObject:
      case Kind::kNumber:
        return RegisterRepresentation::Tagged();
      case Kind::kCompressedHeapObject:
        return RegisterRepresentation::Compressed();
    }
  }

  ConstantOp(Kind kind, Storage storage)
      : Base(), kind(kind), storage(storage) {}

  void Validate(const Graph& graph) const {
    DCHECK_IMPLIES(
        kind == Kind::kWord32,
        storage.integral <= WordRepresentation::Word32().MaxUnsignedValue());
    DCHECK_IMPLIES(
        kind == Kind::kRelocatableWasmCanonicalSignatureId,
        storage.integral <= WordRepresentation::Word32().MaxSignedValue());
  }

  uint64_t integral() const {
    DCHECK(IsIntegral());
    return storage.integral;
  }

  int64_t signed_integral() const {
    DCHECK(IsIntegral());
    switch (kind) {
      case Kind::kWord32:
      case Kind::kRelocatableWasmCanonicalSignatureId:
        return static_cast<int32_t>(storage.integral);
      case Kind::kWord64:
        return static_cast<int64_t>(storage.integral);
      default:
        UNREACHABLE();
    }
  }

  uint32_t word32() const {
    DCHECK(kind == Kind::kWord32 || kind == Kind::kWord64);
    return static_cast<uint32_t>(storage.integral);
  }

  uint64_t word64() const {
    DCHECK_EQ(kind, Kind::kWord64);
    return static_cast<uint64_t>(storage.integral);
  }

  i::Tagged<Smi> smi() const {
    DCHECK_EQ(kind, Kind::kSmi);
    return i::Tagged<Smi>(storage.integral);
  }

  i::Float64 number() const {
    DCHECK_EQ(kind, Kind::kNumber);
    return storage.float64;
  }

  i::Float32 float32() const {
    DCHECK_EQ(kind, Kind::kFloat32);
    return storage.float32;
  }

  i::Float64 float64() const {
    DCHECK_EQ(kind, Kind::kFloat64);
    return storage.float64;
  }

  int32_t tagged_index() const {
    DCHECK_EQ(kind, Kind::kTaggedIndex);
    return static_cast<int32_t>(static_cast<uint32_t>(storage.integral));
  }

  ExternalReference external_reference() const {
    DCHECK_EQ(kind, Kind::kExternal);
    return storage.external;
  }

  IndirectHandle<i::HeapObject> handle() const {
    DCHECK(kind == Kind::kHeapObject || kind == Kind::kCompressedHeapObject ||
           kind == Kind::kTrustedHeapObject);
    return storage.handle;
  }

  bool IsWord(uint64_t value) const {
    switch (kind) {
      case Kind::kWord32:
        return static_cast<uint32_t>(value) == word32();
      case Kind::kWord64:
        return value == word64();
      default:
        UNREACHABLE();
    }
  }

  bool IsIntegral() const {
    return kind == Kind::kWord32 || kind == Kind::kWord64 ||
           kind == Kind::kRelocatableWasmCall ||
           kind == Kind::kRelocatableWasmStubCall ||
           kind == Kind::kRelocatableWasmCanonicalSignatureId ||
           kind == Kind::kRelocatableWasmIndirectCallTarget;
  }

  auto options() const { return std::tuple{kind, storage}; }

  void PrintOptions(std::ostream& os) const;
  size_t hash_value(
      HashingStrategy strategy = HashingStrategy::kDefault) const {
    switch (kind) {
      case Kind::kWord32:
      case Kind::kWord64:
      case Kind::kSmi:
      case Kind::kTaggedIndex:
      case Kind::kRelocatableWasmCall:
      case Kind::kRelocatableWasmStubCall:
      case Kind::kRelocatableWasmIndirectCallTarget:
      case Kind::kRelocatableWasmCanonicalSignatureId:
        return HashWithOptions(storage.integral);
      case Kind::kFloat32:
        return HashWithOptions(storage.float32.get_bits());
      case Kind::kFloat64:
      case Kind::kNumber:
        return HashWithOptions(storage.float64.get_bits());
      case Kind::kExternal:
        return HashWithOptions(strategy == HashingStrategy::kMakeSnapshotStable
                                   ? 0
                                   : storage.external.raw());
      case Kind::kHeapObject:
      case Kind::kCompressedHeapObject:
      case Kind::kTrustedHeapObject:
        if (strategy == HashingStrategy::kMakeSnapshotStable) {
          return HashWithOptions();
        }
        return HashWithOptions(storage.handle.address());
    }
  }
  bool operator==(const ConstantOp& other) const {
    if (kind != other.kind) return false;
    switch (kind) {
      case Kind::kWord32:
      case Kind::kWord64:
      case Kind::kSmi:
      case Kind::kTaggedIndex:
      case Kind::kRelocatableWasmCall:
      case Kind::kRelocatableWasmStubCall:
      case Kind::kRelocatableWasmCanonicalSignatureId:
      case Kind::kRelocatableWasmIndirectCallTarget:
        return storage.integral == other.storage.integral;
      case Kind::kFloat32:
        // Using a bit_cast to uint32_t in order to return false when comparing
        // +0 and -0.
        // Note: for JavaScript, it would be fine to return true when both
        // values are NaNs, but for Wasm we must not merge NaNs that way.
        // Since we canonicalize NaNs for JS anyway, we don't need to treat
        // them specially here.
        return base::bit_cast<uint32_t>(storage.float32) ==
               base::bit_cast<uint32_t>(other.storage.float32);
      case Kind::kFloat64:
      case Kind::kNumber:
        // Using a bit_cast to uint64_t in order to return false when comparing
        // +0 and -0.
        // Note: for JavaScript, it would be fine to return true when both
        // values are NaNs, but for Wasm we must not merge NaNs that way.
        // Since we canonicalize NaNs for JS anyway, we don't need to treat
        // them specially here.
        return base::bit_cast<uint64_t>(storage.float64) ==
               base::bit_cast<uint64_t>(other.storage.float64);
      case Kind::kExternal:
        return storage.external.raw() == other.storage.external.raw();
      case Kind::kHeapObject:
      case Kind::kCompressedHeapObject:
      case Kind::kTrustedHeapObject:
        return storage.handle.address() == other.storage.handle.address();
    }
  }
};

// Load `loaded_rep` from: base + offset + index * 2^element_size_log2.
// For Kind::tagged_base: subtract kHeapObjectTag,
//                        `base` has to be the object start.
// For (u)int8/16, the value will be sign- or zero-extended to Word32.
// When result_rep is RegisterRepresentation::Compressed(), then the load does
// not decompress the value.
struct LoadOp : OperationT<LoadOp> {
  struct Kind {
    // The `base` input is a tagged pointer to a HeapObject.
    bool tagged_base : 1;
    // The effective address might be unaligned. This is only set to true if
    // the platform does not support unaligned loads for the given
    // MemoryRepresentation natively.
    bool maybe_unaligned : 1;
    // There is a Wasm trap handler for out-of-bounds accesses.
    bool with_trap_handler : 1;
    // The wasm trap handler is used for null accesses. Note that this requires
    // with_trap_handler as well.
    bool trap_on_null : 1;
    // If {load_eliminable} is true, then:
    //   - Stores/Loads at this address cannot overlap. Concretely, it means
    //     that something like this cannot happen:
    //
    //         const u32s = Uint32Array.of(3, 8);
    //         const u8s = new Uint8Array(u32s.buffer);
    //         u32s[0] = 0xffffffff;
    //         u8s[1] = 0; // Overlaps with previous store!
    //
    //   - Stores/Loads at this address have a canonical base. Concretely, it
    //     means that something like this cannot happen:
    //
    //         let buffer = new ArrayBuffer(10000);
    //         let ta1 = new Int32Array(buffer, 0/*offset*/);
    //         let ta2 = new Int32Array(buffer, 100*4/*offset*/);
    //         ta2[0] = 0xff;
    //         ta1[100] = 42; // Same destination as the previous store!
    //
    //   - No other thread can modify the underlying value. E.g. in the case of
    //     loading the wasm stack limit, other threads can modify the loaded
    //     value, so we always have to reload it.
    //
    // This is mainly used for load elimination: when stores/loads don't have
    // the {load_eliminable} bit set to true, more things need to be
    // invalidated.
    // In the main JS pipeline, only ArrayBuffers (= TypedArray/DataView)
    // loads/stores have this {load_eliminable} set to false,
    // and all other loads have it to true.
    bool load_eliminable : 1;
    // The loaded value may not change.
    bool is_immutable : 1;
    // The load should be atomic.
    bool is_atomic : 1;

    static constexpr Kind Aligned(BaseTaggedness base_is_tagged) {
      switch (base_is_tagged) {
        case BaseTaggedness::kTaggedBase:
          return TaggedBase();
        case BaseTaggedness::kUntaggedBase:
          return RawAligned();
      }
    }
    static constexpr Kind TaggedBase() {
      return {.tagged_base = true,
              .maybe_unaligned = false,
              .with_trap_handler = false,
              .trap_on_null = false,
              .load_eliminable = true,
              .is_immutable = false,
              .is_atomic = false};
    }
    static constexpr Kind RawAligned() {
      return {.tagged_base = false,
              .maybe_unaligned = false,
              .with_trap_handler = false,
              .trap_on_null = false,
              .load_eliminable = true,
              .is_immutable = false,
              .is_atomic = false};
    }
    static constexpr Kind RawUnaligned() {
      return {.tagged_base = false,
              .maybe_unaligned = true,
              .with_trap_handler = false,
              .trap_on_null = false,
              .load_eliminable = true,
              .is_immutable = false,
              .is_atomic = false};
    }
    static constexpr Kind Protected() {
      return {.tagged_base = false,
              .maybe_unaligned = false,
              .with_trap_handler = true,
              .trap_on_null = false,
              .load_eliminable = true,
              .is_immutable = false,
              .is_atomic = false};
    }
    static constexpr Kind TrapOnNull() {
      return {.tagged_base = true,
              .maybe_unaligned = false,
              .with_trap_handler = true,
              .trap_on_null = true,
              .load_eliminable = true,
              .is_immutable = false,
              .is_atomic = false};
    }
    static constexpr Kind MaybeUnaligned(MemoryRepresentation rep) {
      return rep == MemoryRepresentation::Int8() ||
                     rep == MemoryRepresentation::Uint8() ||
                     SupportedOperations::IsUnalignedLoadSupported(rep)
                 ? LoadOp::Kind::RawAligned()
                 : LoadOp::Kind::RawUnaligned();
    }

    constexpr Kind NotLoadEliminable() {
      Kind kind = *this;
      kind.load_eliminable = false;
      return kind;
    }

    constexpr Kind Immutable() const {
      Kind kind(*this);
      kind.is_immutable = true;
      return kind;
    }

    constexpr Kind Atomic() const {
      Kind kind(*this);
      kind.is_atomic = true;
      return kind;
    }

    bool operator==(const Kind& other) const {
      return tagged_base == other.tagged_base &&
             maybe_unaligned == other.maybe_unaligned &&
             with_trap_handler == other.with_trap_handler &&
             load_eliminable == other.load_eliminable &&
             is_immutable == other.is_immutable &&
             is_atomic == other.is_atomic && trap_on_null == other.trap_on_null;
    }
  };
  Kind kind;
  MemoryRepresentation loaded_rep;
  RegisterRepresentation result_rep;
  uint8_t element_size_log2;  // multiply index with 2^element_size_log2
  int32_t offset;             // add offset to scaled index

  OpEffects Effects() const {
    // Loads might depend on checks for pointer validity, object layout, bounds
    // checks, etc.
    // TODO(tebbi): Distinguish between on-heap and off-heap loads.
    OpEffects effects = OpEffects().CanReadMemory().CanDependOnChecks();
    if (kind.with_trap_handler) effects = effects.CanLeaveCurrentFunction();
    if (kind.is_atomic) {
      // Atomic load should not be reordered with other loads.
      effects = effects.CanWriteMemory();
    }
    return effects;
  }
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return base::VectorOf(&result_rep, 1);
  }

  MachineType machine_type() const;

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    base::Vector<const MaybeRegisterRepresentation> result =
        kind.tagged_base
            ? MaybeRepVector<MaybeRegisterRepresentation::Tagged(),
                             MaybeRegisterRepresentation::WordPtr()>()
            : MaybeRepVector<MaybeRegisterRepresentation::WordPtr(),
                             MaybeRegisterRepresentation::WordPtr()>();
    return index().valid() ? result : base::VectorOf(result.data(), 1);
  }

  OpIndex base() const { return input(0); }
  OptionalOpIndex index() const {
    return input_count == 2 ? input(1) : OpIndex::Invalid();
  }

  static constexpr bool OffsetIsValid(int32_t offset, bool tagged_base) {
    if (tagged_base) {
      // When a Load has the tagged_base Kind, it means that {offset} will
      // eventually need a "-kHeapObjectTag". If the {offset} is
      // min_int, then subtracting kHeapObjectTag will underflow.
      return offset >= std::numeric_limits<int32_t>::min() + kHeapObjectTag;
    }
    return true;
  }

  LoadOp(OpIndex base, OptionalOpIndex index, Kind kind,
         MemoryRepresentation loaded_rep, RegisterRepresentation result_rep,
         int32_t offset, uint8_t element_size_log2)
      : Base(1 + index.valid()),
        kind(kind),
        loaded_rep(loaded_rep),
        result_rep(result_rep),
        element_size_log2(element_size_log2),
        offset(offset) {
    input(0) = base;
    if (index.valid()) {
      input(1) = index.value();
    }
  }

  template <typename Fn, typename Mapper>
  V8_INLINE auto Explode(Fn fn, Mapper& mapper) const {
    return fn(mapper.Map(base()), mapper.Map(index()), kind, loaded_rep,
              result_rep, offset, element_size_log2);
  }

  void Validate(const Graph& graph) const {
    DCHECK(loaded_rep.ToRegisterRepresentation() == result_rep ||
           (loaded_rep.IsCompressibleTagged() &&
            result_rep == RegisterRepresentation::Compressed()) ||
           kind.is_atomic);
    DCHECK_IMPLIES(element_size_log2 > 0, index().valid());
    DCHECK_IMPLIES(kind.maybe_unaligned,
                   !SupportedOperations::IsUnalignedLoadSupported(loaded_rep));
    DCHECK(OffsetIsValid(offset, kind.tagged_base));
  }
  static LoadOp& New(Graph* graph, OpIndex base, OptionalOpIndex index,
                     Kind kind, MemoryRepresentation loaded_rep,
                     RegisterRepresentation result_rep, int32_t offset,
                     uint8_t element_size_log2) {
    return Base::New(graph, 1 + index.valid(), base, index, kind, loaded_rep,
                     result_rep, offset, element_size_log2);
  }
  void PrintInputs(std::ostream& os, const std::string& op_index_prefix) const;
  void PrintOptions(std::ostream& os) const;
  auto options() const {
    return std::tuple{kind, loaded_rep, result_rep, offset, element_size_log2};
  }
};

V8_INLINE size_t hash_value(LoadOp::Kind kind) {
  return base::hash_value(
      static_cast<int>(kind.tagged_base) | (kind.maybe_unaligned << 1) |
      (kind.load_eliminable << 2) | (kind.is_immutable << 3) |
      (kind.with_trap_handler << 4) | (kind.is_atomic << 5));
}

struct AtomicRMWOp : OperationT<AtomicRMWOp> {
  enum class BinOp : uint8_t {
    kAdd,
    kSub,
    kAnd,
    kOr,
    kXor,
    kExchange,
    kCompareExchange
  };
  BinOp bin_op;
  RegisterRepresentation in_out_rep;
  MemoryRepresentation memory_rep;
  MemoryAccessKind memory_access_kind;
  OpEffects Effects() const {
    OpEffects effects =
        OpEffects().CanWriteMemory().CanDependOnChecks().CanReadMemory();
    if (memory_access_kind == MemoryAccessKind::kProtectedByTrapHandler) {
      effects = effects.CanLeaveCurrentFunction();
    }
    return effects;
  }

  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return base::VectorOf(&in_out_rep, 1);
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    if (bin_op == BinOp::kCompareExchange) {
      return InitVectorOf(
          storage, {RegisterRepresentation::WordPtr(),
                    RegisterRepresentation::WordPtr(), in_out_rep, in_out_rep});
    }
    return InitVectorOf(storage,
                        {RegisterRepresentation::WordPtr(),
                         RegisterRepresentation::WordPtr(), in_out_rep});
  }

  V<WordPtr> base() const { return input<WordPtr>(0); }
  V<WordPtr> index() const { return input<WordPtr>(1); }
  OpIndex value() const { return input(2); }
  OptionalOpIndex expected() const {
    return (input_count == 4) ? input(3) : OpIndex::Invalid();
  }

  void Validate(const Graph& graph) const {
    DCHECK_EQ(bin_op == BinOp::kCompareExchange, expected().valid());
  }

  AtomicRMWOp(OpIndex base, OpIndex index, OpIndex value,
              OptionalOpIndex expected, BinOp bin_op,
              RegisterRepresentation in_out_rep,
              MemoryRepresentation memory_rep, MemoryAccessKind kind)
      : Base(3 + expected.valid()),
        bin_op(bin_op),
        in_out_rep(in_out_rep),
        memory_rep(memory_rep),
        memory_access_kind(kind) {
    input(0) = base;
    input(1) = index;
    input(2) = value;
    if (expected.valid()) {
      input(3) = expected.value();
    }
  }

  template <typename Fn, typename Mapper>
  V8_INLINE auto Explode(Fn fn, Mapper& mapper) const {
    return fn(mapper.Map(base()), mapper.Map(index()), mapper.Map(value()),
              mapper.Map(expected()), bin_op, in_out_rep, memory_rep,
              memory_access_kind);
  }

  static AtomicRMWOp& New(Graph* graph, OpIndex base, OpIndex index,
                          OpIndex value, OptionalOpIndex expected, BinOp bin_op,
                          RegisterRepresentation result_rep,
                          MemoryRepresentation input_rep,
                          MemoryAccessKind kind) {
    return Base::New(graph, 3 + expected.valid(), base, index, value, expected,
                     bin_op, result_rep, input_rep, kind);
  }

  void PrintInputs(std::ostream& os, const std::string& op_index_prefix) const;

  void PrintOptions(std::ostream& os) const;

  auto options() const {
    return std::tuple{bin_op, in_out_rep, memory_rep, memory_access_kind};
  }
};
DEFINE_MULTI_SWITCH_INTEGRAL(AtomicRMWOp::BinOp, 8)

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           AtomicRMWOp::BinOp kind);

struct AtomicWord32PairOp : OperationT<AtomicWord32PairOp> {
  enum class Kind : uint8_t {
    kAdd,
    kSub,
    kAnd,
    kOr,
    kXor,
    kExchange,
    kCompareExchange,
    kLoad,
    kStore
  };

  Kind kind;
  int32_t offset;

  static Kind KindFromBinOp(AtomicRMWOp::BinOp bin_op) {
    switch (bin_op) {
      case AtomicRMWOp::BinOp::kAdd:
        return Kind::kAdd;
      case AtomicRMWOp::BinOp::kSub:
        return Kind::kSub;
      case AtomicRMWOp::BinOp::kAnd:
        return Kind::kAnd;
      case AtomicRMWOp::BinOp::kOr:
        return Kind::kOr;
      case AtomicRMWOp::BinOp::kXor:
        return Kind::kXor;
      case AtomicRMWOp::BinOp::kExchange:
        return Kind::kExchange;
      case AtomicRMWOp::BinOp::kCompareExchange:
        return Kind::kCompareExchange;
    }
  }

  OpEffects Effects() const {
    OpEffects effects = OpEffects().CanDependOnChecks();
    if (kind == Kind::kStore) {
      return effects.CanWriteMemory();
    }
    // Atomic loads are marked as "can write memory" as they should not be
    // reordered with other loads. Secondly, they may not be removed even if
    // unused as they might make writes of other threads visible.
    return effects.CanReadMemory().CanWriteMemory();
  }

  base::Vector<const RegisterRepresentation> outputs_rep() const {
    if (kind == Kind::kStore) return {};
    return RepVector<RegisterRepresentation::Word32(),
                     RegisterRepresentation::Word32()>();
  }
  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    storage.resize(input_count);

    const bool has_index = HasIndex();
    storage[0] = RegisterRepresentation::WordPtr();  // base
    if (has_index) {
      storage[1] = RegisterRepresentation::WordPtr();  // index
    }
    if (kind != Kind::kLoad) {
      storage[1 + has_index] = RegisterRepresentation::Word32();  // value_low
      storage[2 + has_index] = RegisterRepresentation::Word32();  // value_high
      if (kind == Kind::kCompareExchange) {
        storage[3 + has_index] =
            RegisterRepresentation::Word32();  // expected_low
        storage[4 + has_index] =
            RegisterRepresentation::Word32();  // expected_high
      }
    }
    return base::VectorOf(storage);
  }

  V<WordPtr> base() const { return input<WordPtr>(0); }
  OptionalV<WordPtr> index() const {
    return HasIndex() ? input<WordPtr>(1) : V<WordPtr>::Invalid();
  }
  OptionalV<Word32> value_low() const {
    return kind != Kind::kLoad ? input<Word32>(1 + HasIndex())
                               : V<Word32>::Invalid();
  }
  OptionalV<Word32> value_high() const {
    return kind != Kind::kLoad ? input<Word32>(2 + HasIndex())
                               : V<Word32>::Invalid();
  }
  OptionalV<Word32> expected_low() const {
    return kind == Kind::kCompareExchange ? input<Word32>(3 + HasIndex())
                                          : V<Word32>::Invalid();
  }
  OptionalV<Word32> expected_high() const {
    return kind == Kind::kCompareExchange ? input<Word32>(4 + HasIndex())
                                          : V<Word32>::Invalid();
  }

  void Validate(const Graph& graph) const {}

  AtomicWord32PairOp(V<WordPtr> base, OptionalV<WordPtr> index,
                     OptionalV<Word32> value_low, OptionalV<Word32> value_high,
                     OptionalV<Word32> expected_low,
                     OptionalV<Word32> expected_high, Kind kind, int32_t offset)
      : Base(InputCount(kind, index.has_value())), kind(kind), offset(offset) {
    DCHECK_EQ(value_low.valid(), value_high.valid());
    DCHECK_EQ(expected_low.valid(), expected_high.valid());
    DCHECK_EQ(kind == Kind::kCompareExchange, expected_low.valid());
    DCHECK_EQ(kind != Kind::kLoad, value_low.valid());

    const bool has_index = index.has_value();
    DCHECK_EQ(has_index, HasIndex());

    input(0) = base;
    if (has_index) input(1) = index.value();
    if (kind != Kind::kLoad) {
      input(1 + has_index) = value_low.value();
      input(2 + has_index) = value_high.value();
      if (kind == Kind::kCompareExchange) {
        input(3 + has_index) = expected_low.value();
        input(4 + has_index) = expected_high.value();
      }
    }
  }

  template <typename Fn, typename Mapper>
  V8_INLINE auto Explode(Fn fn, Mapper& mapper) const {
    return fn(mapper.Map(base()), mapper.Map(index()), mapper.Map(value_low()),
              mapper.Map(value_high()), mapper.Map(expected_low()),
              mapper.Map(expected_high()), kind, offset);
  }

  static constexpr size_t InputCount(Kind kind, bool has_index) {
    switch (kind) {
      case Kind::kLoad:
        return 1 + has_index;  // base, index?
      case Kind::kAdd:
      case Kind::kSub:
      case Kind::kAnd:
      case Kind::kOr:
      case Kind::kXor:
      case Kind::kExchange:
      case Kind::kStore:
        return 3 + has_index;  // base, index?, value_low, value_high
      case Kind::kCompareExchange:
        return 5 + has_index;  // base, index?, value_low, value_high,
                               // expected_low, expected_high
    }
  }
  bool HasIndex() const { return input_count == InputCount(kind, true); }

  static AtomicWord32PairOp& New(Graph* graph, V<WordPtr> base,
                                 OptionalV<WordPtr> index,
                                 OptionalV<Word32> value_low,
                                 OptionalV<Word32> value_high,
                                 OptionalV<Word32> expected_low,
                                 OptionalV<Word32> expected_high, Kind kind,
                                 int32_t offset) {
    return Base::New(graph, InputCount(kind, index.has_value()), base, index,
                     value_low, value_high, expected_low, expected_high, kind,
                     offset);
  }

  void PrintInputs(std::ostream& os, const std::string& op_index_prefix) const;

  void PrintOptions(std::ostream& os) const;

  auto options() const { return std::tuple{kind, offset}; }
};

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           AtomicWord32PairOp::Kind kind);

struct MemoryBarrierOp : FixedArityOperationT<0, MemoryBarrierOp> {
  AtomicMemoryOrder memory_order;

  static constexpr OpEffects effects =
      OpEffects().CanReadHeapMemory().CanWriteMemory();

  explicit MemoryBarrierOp(AtomicMemoryOrder memory_order)
      : Base(), memory_order(memory_order) {}

  base::Vector<const RegisterRepresentation> outputs_rep() const { return {}; }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return {};
  }

  void Validate(const Graph& graph) const {}

  auto options() const { return std::tuple{memory_order}; }
  void PrintOptions(std::ostream& os) const;
};

// Store `value` to: base + offset + index * 2^element_size_log2.
// For Kind::tagged_base: subtract kHeapObjectTag,
//                        `base` has to be the object start.
struct StoreOp : OperationT<StoreOp> {
  using Kind = LoadOp::Kind;
  Kind kind;
  MemoryRepresentation stored_rep;
  WriteBarrierKind write_barrier;
  uint8_t element_size_log2;  // multiply index with 2^element_size_log2
  int32_t offset;             // add offset to scaled index
  bool maybe_initializing_or_transitioning;
  uint16_t
      shifted_indirect_pointer_tag;  // for indirect pointer stores, the
                                     // IndirectPointerTag of the store shifted
                                     // to the right by kIndirectPointerTagShift
                                     // (so it fits into 16 bits).
  // TODO(saelo): now that we have a pointer tag in these low-level operations,
  // we could also consider passing the external pointer tag (for external
  // pointers) through to the macro assembler (where we have routines to work
  // with external pointers) instead of handling those earlier in the compiler.
  // We might lose the ability to hardcode the table address though.

  OpEffects Effects() const {
    // Stores might depend on checks for pointer validity, object layout, bounds
    // checks, etc.
    // TODO(tebbi): Distinghish between on-heap and off-heap stores.
    OpEffects effects = OpEffects().CanWriteMemory().CanDependOnChecks();
    if (kind.with_trap_handler) effects = effects.CanLeaveCurrentFunction();
    if (maybe_initializing_or_transitioning) {
      effects = effects.CanDoRawHeapAccess();
    }
    if (kind.is_atomic) {
      // Atomic stores should not be eliminated away, even if the situation
      // seems to allow e.g. store-store elimination. Elimination is avoided by
      // setting the `CanReadMemory` effect.
      effects = effects.CanReadMemory();
    }
    return effects;
  }
  base::Vector<const RegisterRepresentation> outputs_rep() const { return {}; }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    RegisterRepresentation base = kind.tagged_base
                                      ? RegisterRepresentation::Tagged()
                                      : RegisterRepresentation::WordPtr();
    if (index() == OpIndex::Invalid()) {
      return InitVectorOf(
          storage, {base, stored_rep.ToRegisterRepresentationForStore()});
    }
    return InitVectorOf(storage,
                        {base, stored_rep.ToRegisterRepresentationForStore(),
                         RegisterRepresentation::WordPtr()});
  }

  OpIndex base() const { return input(0); }
  OpIndex value() const { return input(1); }
  OptionalOpIndex index() const {
    return input_count == 3 ? input(2) : OpIndex::Invalid();
  }

  IndirectPointerTag indirect_pointer_tag() const {
    uint64_t shifted = shifted_indirect_pointer_tag;
    return static_cast<IndirectPointerTag>(shifted << kIndirectPointerTagShift);
  }

  StoreOp(
      OpIndex base, OptionalOpIndex index, OpIndex value, Kind kind,
      MemoryRepresentation stored_rep, WriteBarrierKind write_barrier,
      int32_t offset, uint8_t element_size_log2,
      bool maybe_initializing_or_transitioning,
      IndirectPointerTag maybe_indirect_pointer_tag = kIndirectPointerNullTag)
      : Base(2 + index.valid()),
        kind(kind),
        stored_rep(stored_rep),
        write_barrier(write_barrier),
        element_size_log2(element_size_log2),
        offset(offset),
        maybe_initializing_or_transitioning(
            maybe_initializing_or_transitioning),
        shifted_indirect_pointer_tag(maybe_indirect_pointer_tag >>
                                     kIndirectPointerTagShift) {
    DCHECK_EQ(indirect_pointer_tag(), maybe_indirect_pointer_tag);
    input(0) = base;
    input(1) = value;
    if (index.valid()) {
      input(2) = index.value();
    }
  }

  template <typename Fn, typename Mapper>
  V8_INLINE auto Explode(Fn fn, Mapper& mapper) const {
    return fn(mapper.Map(base()), mapper.Map(index()), mapper.Map(value()),
              kind, stored_rep, write_barrier, offset, element_size_log2,
              maybe_initializing_or_transitioning, indirect_pointer_tag());
  }

  void Validate(const Graph& graph) const {
    DCHECK_IMPLIES(element_size_log2 > 0, index().valid());
    DCHECK_IMPLIES(kind.maybe_unaligned,
                   !SupportedOperations::IsUnalignedLoadSupported(stored_rep));
    DCHECK(LoadOp::OffsetIsValid(offset, kind.tagged_base));
  }
  static StoreOp& New(
      Graph* graph, OpIndex base, OptionalOpIndex index, OpIndex value,
      Kind kind, MemoryRepresentation stored_rep,
      WriteBarrierKind write_barrier, int32_t offset, uint8_t element_size_log2,
      bool maybe_initializing_or_transitioning,
      IndirectPointerTag maybe_indirect_pointer_tag = kIndirectPointerNullTag) {
    return Base::New(graph, 2 + index.valid(), base, index, value, kind,
                     stored_rep, write_barrier, offset, element_s
```