Response:
The user wants me to analyze a C++ header file from the V8 JavaScript engine source code (`v8/src/common/globals.h`). I need to list its functionalities, check if it's a Torque file (based on the `.tq` extension), explain its relationship with JavaScript (with examples), provide code logic reasoning with hypothetical inputs and outputs, and illustrate common programming errors related to the content. Finally, I need to summarize the functionalities of this specific code snippet (the second part of the file).

Based on the provided code, it seems to define various constants, enums, and type aliases related to memory management, object representation, and other low-level aspects of the V8 engine.

Here's a plan:
1. **Functionalities:** List the categories of definitions present in the code snippet (e.g., alignment constants, zap values, forward declarations, type aliases, enums related to memory and garbage collection).
2. **Torque Source:** Check if the filename ends with `.tq`. It doesn't, so it's not a Torque source file.
3. **JavaScript Relationship:** Explain how the defined constants and types relate to JavaScript concepts (e.g., object alignment affecting memory layout, zap values for debugging, garbage collection enums influencing runtime behavior). Provide JavaScript examples where these low-level details have indirect effects (e.g., performance differences due to memory layout, debugging behavior when zap values are encountered).
4. **Code Logic Reasoning:** Select a simple constant definition and explain its purpose and how it might be used. Provide a hypothetical scenario where the constant is an input, and the output is the calculated aligned value.
5. **Common Programming Errors:** Discuss potential errors that might occur if developers were to directly interact with these low-level constants (which is generally discouraged in user-level JavaScript programming), such as incorrect memory calculations or misinterpreting zap values.
6. **Summary:** Concisely summarize the key functionalities of this code snippet, focusing on memory management, object representation, and internal V8 configurations.
这是 `v8/src/common/globals.h` 的一部分，主要定义了 V8 引擎中广泛使用的全局常量、枚举和类型别名，特别是与内存管理、对象表示和引擎内部配置相关的部分。

**功能列举:**

1. **对象和指针的对齐方式定义:**
   - `kObjectAlignmentBits`, `kObjectAlignment`, `kObjectAlignmentMask`: 定义了 V8 堆中对象的对齐方式（通常与 tagged 指针大小一致）。
   - `kObjectAlignment8GbHeap`, `kObjectAlignment8GbHeapMask`: 定义了当启用 8GB 指针压缩堆时的对象对齐方式。
   - `kPointerAlignment`, `kPointerAlignmentMask`: 定义了系统指针的对齐方式。
   - `kDoubleAlignment`, `kDoubleAlignmentMask`: 定义了双精度浮点数的对齐方式。
   - `kCodeAlignmentBits`, `kCodeAlignment`, `kCodeAlignmentMask`: 定义了生成代码的对齐方式，其大小取决于目标架构。

2. **弱堆对象的掩码:**
   - `kWeakHeapObjectMask`: 用于识别弱堆对象的掩码。

3. **已清除的弱引用值:**
   - `kClearedWeakHeapObjectLower32`:  定义了已清除的弱引用值的低 32 位，用于快速识别已清除的弱引用。

4. **Zap 值 (用于调试):**
   - `kClearedFreeMemoryValue`:  用于填充已清除的空闲内存的值。
   - `kZapValue`: 用于标记已死亡对象的值。
   - `kHandleZapValue`, `kGlobalHandleZapValue`, `kTracedHandle...ZapValue`: 用于标记不同类型的句柄的值，便于调试内存问题。
   - `kFromSpaceZapValue`:  用于标记 FromSpace 的值。
   - `kDebugZapValue`: 用于调试目的的值。
   - `kSlotsZapValue`: 用于标记槽的值。
   - `kFreeListZapValue`: 用于标记空闲列表的值。
   - `kCodeZapValue`: 用于标记代码的值。
   - `kPhantomReferenceZap`: 用于标记虚引用的值。

5. **缓存行大小:**
   - `PROCESSOR_CACHE_LINE_SIZE`: 定义了处理器缓存行的大小，用于数据对齐以提高缓存利用率。

6. **NaN 的高位掩码:**
   - `kQuietNaNHighBitsMask`: 用于检测安静 NaN (Not-a-Number) 的高位掩码。

7. **枚举类型定义:**
   - `HeapObjectReferenceType`: 表示堆对象引用的类型（强或弱）。
   - `ArgumentsType`: 表示参数的类型（运行时或 JS）。
   - `AllocationSpace`: 定义了 V8 堆中不同的内存空间（如新生代、老生代、代码空间等）。
   - `AllocationType`: 定义了分配的类型（如年轻对象、老年代对象、代码对象等）。
   - `GarbageCollectionReason`:  定义了触发垃圾回收的原因。
   - `AllocationAlignment`: 定义了内存分配的对齐方式。
   - `AccessMode`: 定义了访问模式（原子或非原子）。
   - `MinimumCapacity`:  用于指示是否使用自定义的最小容量。
   - `GarbageCollector`: 定义了垃圾回收器的类型。
   - `CompactionSpaceKind`: 定义了压缩空间的类型。
   - `Executability`:  表示内存页是否可执行。
   - `PageSize`: 表示内存页的大小。
   - `CodeFlushMode`: 定义了代码刷新的模式。
   - `ExternalBackingStoreType`: 定义了外部存储器的类型。
   - `NewJSObjectType`:  指示是否为 API 包装的对象。
   - `REPLMode`:  指示脚本是否在 REPL 模式下解析和编译。
   - `ParsingWhileDebugging`: 指示脚本是否在调试期间解析。
   - `NativesFlag`: 指示代码是否内置到 VM 中。
   - `ParseRestriction`:  用于限制编译单元中允许的语句集。
   - `ScriptEventType`:  定义了脚本事件的类型。
   - `InlineCacheState`: 定义了内联缓存调用点的状态。
   - `WhereToStart`:  用于查找属性时指定从哪里开始。
   - `ResultSentinel`:  用于表示查找结果的特殊值。
   - `ShouldThrow`:  指示是否抛出错误。
   - `InterceptorResult`: 定义了拦截器回调的可能结果。
   - `ThreadKind`: 定义了线程的类型。

8. **IEEE 双精度浮点数相关的定义:**
   - `IeeeDoubleLittleEndianArchType`, `IeeeDoubleBigEndianArchType`: 用于自定义检查 IEEE 双精度浮点数的联合体，考虑了大小端。
   - `kIeeeDoubleMantissaWordOffset`, `kIeeeDoubleExponentWordOffset`: 定义了尾数和指数在双精度浮点数中的偏移量。

9. **宏定义:**
   - `HAS_SMI_TAG`, `HAS_STRONG_HEAP_OBJECT_TAG`, `HAS_WEAK_HEAP_OBJECT_TAG`: 用于检查值的标签，判断其是否为小整数 (Smi) 或堆对象。
   - `OBJECT_POINTER_ALIGN`, `ALIGN_TO_ALLOCATION_ALIGNMENT`, `OBJECT_POINTER_PADDING`: 用于计算对象指针的对齐和填充。
   - `POINTER_SIZE_ALIGN`, `POINTER_SIZE_PADDING`: 用于计算系统指针的对齐和填充。
   - `CODE_POINTER_ALIGN`, `CODE_POINTER_PADDING`: 用于计算代码指针的对齐和填充。
   - `DOUBLE_POINTER_ALIGN`: 用于计算双精度浮点数指针的对齐。

10. **其他类型别名和常量:**
    - `kSpaceTagSize`: 定义了空间标签的大小。
    - `BranchHint`:  用于分支预测的提示。
    - `ConvertReceiverMode`:  定义了关于接收者值的提示。
    - `OrdinaryToPrimitiveHint`, `ToPrimitiveHint`:  用于原始类型转换的提示。
    - `CreateArgumentsType`: 定义了 arguments 对象或 rest 参数的创建方式。
    - `kScopeInfoMaxInlinedLocalNamesSize`:  作用域信息中内联局部变量名的最大大小。
    - `ScopeType`: 定义了不同的作用域类型。

**是否为 Torque 源代码:**

`v8/src/common/globals.h`  **不是**以 `.tq` 结尾，因此它不是一个 V8 Torque 源代码文件。它是标准的 C++ 头文件。

**与 JavaScript 的功能关系及 JavaScript 举例:**

尽管这个头文件是 C++ 代码，但它定义的常量和类型直接影响 V8 引擎如何执行 JavaScript 代码。

1. **对象对齐 (`kObjectAlignment`, 等):** JavaScript 中的对象在内存中以特定的方式布局。对象对齐确保了 CPU 可以高效地访问对象的属性。
   ```javascript
   // 尽管 JavaScript 开发者无法直接控制对齐，但 V8 内部会根据这些常量来布局对象。
   const obj = { a: 1, b: 2 };
   // V8 在内存中分配 obj，并确保其属性按照 kObjectAlignment 对齐。
   ```

2. **Zap 值 (`kZapValue`, 等):** 当 V8 遇到错误或需要清理内存时，会用这些特殊的 zap 值填充内存。这有助于调试，因为这些值很容易识别。
   ```javascript
   // 开发者通常不会直接看到 zap 值，但如果 V8 内部出现错误导致内存被 zap，
   // 在调试时可能会看到类似 "deadbeef" 这样的模式。
   ```

3. **垃圾回收原因 (`GarbageCollectionReason`):**  V8 会记录触发垃圾回收的原因，这对于性能分析和理解内存行为非常重要。
   ```javascript
   // 可以通过 V8 的命令行标志或 Inspector API 查看垃圾回收的信息，
   // 其中会包含 GarbageCollectionReason。
   // 例如，在 Node.js 中使用 --trace-gc 标志。
   ```

4. **分配空间 (`AllocationSpace`):** JavaScript 对象被分配到不同的内存空间，如新生代和老生代。垃圾回收器会根据对象所在的空间采取不同的策略。
   ```javascript
   const youngObject = {}; // 可能会被分配到新生代 (NEW_SPACE)。
   // 经过多次垃圾回收后，对象可能会被晋升到老生代 (OLD_SPACE)。
   ```

**代码逻辑推理:**

**假设输入:** 一个未对齐的内存地址 `value = 0x1003`，以及对象对齐掩码 `kObjectAlignmentMask` (假设为 `0x7`，对应 8 字节对齐)。

**代码:**
```c++
constexpr intptr_t kObjectAlignmentMask = 0x7; // 假设
#define OBJECT_POINTER_ALIGN(value) \
  (((value) + ::i::kObjectAlignmentMask) & ~::i::kObjectAlignmentMask)
```

**推理过程:**

1. `value + ::i::kObjectAlignmentMask`:  `0x1003 + 0x7 = 0x100A`
2. `~::i::kObjectAlignmentMask`:  `~0x7 = ...FFF8` (假设 32 位系统)
3. `(value + ::i::kObjectAlignmentMask) & ~::i::kObjectAlignmentMask`: `0x100A & ...FFF8 = 0x1008`

**输出:**  `0x1008`，这是 `0x1003` 向上对齐到 8 字节后的地址。

**用户常见的编程错误:**

通常，JavaScript 开发者不会直接操作这些底层的内存管理常量。但是，理解这些概念可以帮助避免一些性能问题：

1. **创建大量临时对象:**  频繁创建和销毁大量临时对象会增加垃圾回收器的压力，而 `GarbageCollectionReason` 可以帮助理解 GC 的触发原因。
   ```javascript
   function processData(data) {
     for (let i = 0; i < data.length; i++) {
       const temp = { value: data[i] * 2 }; // 频繁创建临时对象
       // ...
     }
   }
   ```
   **错误:**  过度创建临时对象，导致频繁的垃圾回收。
   **改进:**  尽量复用对象或使用更高效的数据结构。

2. **内存泄漏:** 虽然 V8 有垃圾回收机制，但如果存在对不再使用的对象的强引用，仍然可能导致内存泄漏。理解 `HeapObjectReferenceType` 的概念有助于理解对象之间的引用关系。
   ```javascript
   let leakedData = [];
   function storeData(data) {
     leakedData.push(data); // 如果 storeData 被多次调用且 data 不再需要，leakedData 会一直持有引用
   }
   ```
   **错误:**  无意中保持对不再需要的对象的引用。
   **改进:**  确保不再需要的对象可以被垃圾回收，例如将引用设置为 `null`。

**功能归纳 (第 2 部分):**

这部分 `v8/src/common/globals.h` 的主要功能是定义了 V8 引擎在内存管理、对象表示和内部配置方面使用的核心常量、枚举和类型别名。它涵盖了：

- **内存对齐:** 定义了不同类型数据（对象、指针、双精度浮点数、代码）在内存中的对齐方式，这对于性能至关重要。
- **调试支持:**  定义了用于标记内存状态（已清除、已死亡）的 zap 值，方便 V8 开发者进行调试和问题排查。
- **垃圾回收相关:**  定义了与垃圾回收过程相关的枚举，如分配空间和垃圾回收原因，有助于理解 V8 的内存管理行为。
- **类型别名和枚举:**  为 V8 内部使用的各种概念定义了清晰的类型和枚举，提高了代码的可读性和可维护性。
- **底层配置:**  定义了影响 V8 引擎行为的底层配置，如缓存行大小和 NaN 的表示。

总而言之，这部分代码是 V8 引擎的基础设施，为 V8 如何管理内存、表示对象和执行 JavaScript 代码提供了底层的定义和配置。虽然 JavaScript 开发者通常不直接操作这些值，但理解它们有助于更深入地理解 V8 的工作原理和性能特性。

### 提示词
```
这是目录为v8/src/common/globals.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/common/globals.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
ointers.
constexpr int kObjectAlignmentBits = kTaggedSizeLog2;
constexpr intptr_t kObjectAlignment = 1 << kObjectAlignmentBits;
constexpr intptr_t kObjectAlignmentMask = kObjectAlignment - 1;

// Object alignment for 8GB pointer compressed heap.
constexpr intptr_t kObjectAlignment8GbHeap = 8;
constexpr intptr_t kObjectAlignment8GbHeapMask = kObjectAlignment8GbHeap - 1;

#ifdef V8_COMPRESS_POINTERS_8GB
static_assert(
    kObjectAlignment8GbHeap == 2 * kTaggedSize,
    "When the 8GB heap is enabled, all allocations should be aligned to twice "
    "the size of a tagged value.");
#endif

// Desired alignment for system pointers.
constexpr intptr_t kPointerAlignment = (1 << kSystemPointerSizeLog2);
constexpr intptr_t kPointerAlignmentMask = kPointerAlignment - 1;

// Desired alignment for double values.
constexpr intptr_t kDoubleAlignment = 8;
constexpr intptr_t kDoubleAlignmentMask = kDoubleAlignment - 1;

// Desired alignment for generated code is 64 bytes on x64 (to allow 64-bytes
// loop header alignment) and 32 bytes (to improve cache line utilization) on
// other architectures.
#if V8_TARGET_ARCH_X64
constexpr int kCodeAlignmentBits = 6;
#elif V8_TARGET_ARCH_PPC64
// 64 byte alignment is needed on ppc64 to make sure p10 prefixed instructions
// don't cross 64-byte boundaries.
constexpr int kCodeAlignmentBits = 6;
#else
constexpr int kCodeAlignmentBits = 5;
#endif
constexpr intptr_t kCodeAlignment = 1 << kCodeAlignmentBits;
constexpr intptr_t kCodeAlignmentMask = kCodeAlignment - 1;

const Address kWeakHeapObjectMask = 1 << 1;

// The lower 32 bits of the cleared weak reference value is always equal to
// the |kClearedWeakHeapObjectLower32| constant but on 64-bit architectures
// the value of the upper 32 bits part may be
// 1) zero when pointer compression is disabled,
// 2) upper 32 bits of the isolate root value when pointer compression is
//    enabled.
// This is necessary to make pointer decompression computation also suitable
// for cleared weak reference.
// Note, that real heap objects can't have lower 32 bits equal to 3 because
// this offset belongs to page header. So, in either case it's enough to
// compare only the lower 32 bits of a Tagged<MaybeObject> value in order to
// figure out if it's a cleared reference or not.
const uint32_t kClearedWeakHeapObjectLower32 = 3;

// Zap-value: The value used for zapping dead objects.
// Should be a recognizable hex value tagged as a failure.
#ifdef V8_HOST_ARCH_64_BIT
constexpr uint64_t kClearedFreeMemoryValue = 0;
constexpr uint64_t kZapValue = uint64_t{0xdeadbeedbeadbeef};
constexpr uint64_t kHandleZapValue = uint64_t{0x1baddead0baddeaf};
constexpr uint64_t kGlobalHandleZapValue = uint64_t{0x1baffed00baffedf};
constexpr uint64_t kTracedHandleEagerResetZapValue =
    uint64_t{0x1beffedaabaffedf};
constexpr uint64_t kTracedHandleMinorGCResetZapValue =
    uint64_t{0x1beffedeebaffedf};
constexpr uint64_t kTracedHandleMinorGCWeakResetZapValue =
    uint64_t{0x1beffed11baffedf};
constexpr uint64_t kTracedHandleFullGCResetZapValue =
    uint64_t{0x1beffed77baffedf};
constexpr uint64_t kFromSpaceZapValue = uint64_t{0x1beefdad0beefdaf};
constexpr uint64_t kDebugZapValue = uint64_t{0xbadbaddbbadbaddb};
constexpr uint64_t kSlotsZapValue = uint64_t{0xbeefdeadbeefdeef};
constexpr uint64_t kFreeListZapValue = 0xfeed1eaffeed1eaf;
#else
constexpr uint32_t kClearedFreeMemoryValue = 0;
constexpr uint32_t kZapValue = 0xdeadbeef;
constexpr uint32_t kHandleZapValue = 0xbaddeaf;
constexpr uint32_t kGlobalHandleZapValue = 0xbaffedf;
constexpr uint32_t kTracedHandleEagerResetZapValue = 0xbeffedf;
constexpr uint32_t kTracedHandleMinorGCResetZapValue = 0xbeffadf;
constexpr uint32_t kTracedHandleMinorGCWeakResetZapValue = 0xbe11adf;
constexpr uint32_t kTracedHandleFullGCResetZapValue = 0xbe77adf;
constexpr uint32_t kFromSpaceZapValue = 0xbeefdaf;
constexpr uint32_t kSlotsZapValue = 0xbeefdeef;
constexpr uint32_t kDebugZapValue = 0xbadbaddb;
constexpr uint32_t kFreeListZapValue = 0xfeed1eaf;
#endif

constexpr int kCodeZapValue = 0xbadc0de;
constexpr uint32_t kPhantomReferenceZap = 0xca11bac;

// On Intel architecture, cache line size is 64 bytes.
// On ARM it may be less (32 bytes), but as far this constant is
// used for aligning data, it doesn't hurt to align on a greater value.
#define PROCESSOR_CACHE_LINE_SIZE 64

// Constants relevant to double precision floating point numbers.
// If looking only at the top 32 bits, the QNaN mask is bits 19 to 30.
constexpr uint32_t kQuietNaNHighBitsMask = 0xfff << (51 - 32);

enum class V8_EXPORT_ENUM HeapObjectReferenceType {
  WEAK,
  STRONG,
};

enum class ArgumentsType {
  kRuntime,
  kJS,
};

// -----------------------------------------------------------------------------
// Forward declarations for frequently used classes

class AccessorInfo;
template <ArgumentsType>
class Arguments;
using RuntimeArguments = Arguments<ArgumentsType::kRuntime>;
using JavaScriptArguments = Arguments<ArgumentsType::kJS>;
class Assembler;
class ClassScope;
class InstructionStream;
class BigInt;
class Code;
class CodeSpace;
class Context;
class DeclarationScope;
class Debug;
class DebugInfo;
class Descriptor;
class DescriptorArray;
template <typename T>
class DirectHandle;
#ifdef V8_ENABLE_DIRECT_HANDLE
template <typename T>
class DirectHandleVector;
#endif
class TransitionArray;
class ExternalReference;
class ExposedTrustedObject;
class FeedbackVector;
class FixedArray;
class Foreign;
class FreeStoreAllocationPolicy;
class FunctionTemplateInfo;
class GlobalDictionary;
template <typename T>
class Handle;
class Heap;
class HeapNumber;
class Boolean;
class Null;
class Undefined;
class HeapObject;
class IC;
template <typename T>
using IndirectHandle = Handle<T>;
class InterceptorInfo;
class Isolate;
class JSReceiver;
class JSArray;
class JSFunction;
class JSObject;
class JSProxy;
class JSBoundFunction;
class JSWrappedFunction;
class LocalIsolate;
class MacroAssembler;
class Map;
class MarkCompactCollector;
#ifdef V8_ENABLE_DIRECT_HANDLE
template <typename T>
class MaybeDirectHandle;
#endif
template <typename T>
class MaybeHandle;
template <typename T>
class MaybeDirectHandle;
template <typename T>
using MaybeIndirectHandle = MaybeHandle<T>;
class MaybeObjectHandle;
class MaybeObjectDirectHandle;
using MaybeObjectIndirectHandle = MaybeObjectHandle;
template <typename T>
class MaybeWeak;
class MutablePageMetadata;
class MessageLocation;
class ModuleScope;
class Name;
class NameDictionary;
class NativeContext;
class NewSpace;
class NewLargeObjectSpace;
class NumberDictionary;
class Object;
class OldLargeObjectSpace;
template <HeapObjectReferenceType kRefType, typename StorageType>
class TaggedImpl;
class StrongTaggedValue;
class TaggedValue;
class CompressedObjectSlot;
class CompressedMaybeObjectSlot;
class CompressedMapWordSlot;
class CompressedHeapObjectSlot;
template <typename Cage>
class V8HeapCompressionSchemeImpl;
class MainCage;
using V8HeapCompressionScheme = V8HeapCompressionSchemeImpl<MainCage>;
#ifdef V8_ENABLE_SANDBOX
class TrustedCage;
using TrustedSpaceCompressionScheme = V8HeapCompressionSchemeImpl<TrustedCage>;
#else
// The trusted cage does not exist in this case.
using TrustedSpaceCompressionScheme = V8HeapCompressionScheme;
#endif
class ExternalCodeCompressionScheme;
template <typename CompressionScheme>
class OffHeapCompressedObjectSlot;
class FullObjectSlot;
class FullMaybeObjectSlot;
class FullHeapObjectSlot;
class OffHeapFullObjectSlot;
class OldSpace;
class ReadOnlySpace;
class RelocInfo;
class Scope;
class ScopeInfo;
class Script;
class SimpleNumberDictionary;
class Smi;
template <typename Config, class Allocator = FreeStoreAllocationPolicy>
class SplayTree;
class String;
class StringStream;
class Struct;
class Symbol;
template <typename T>
class Tagged;
template <typename... Ts>
class Union;
class Variable;
namespace maglev {
class MaglevAssembler;
}
namespace compiler {
class AccessBuilder;
}

// Number is either a Smi or a HeapNumber.
using Number = Union<Smi, HeapNumber>;
// Numeric is either a Number or a BigInt.
using Numeric = Union<Smi, HeapNumber, BigInt>;
// A primitive JavaScript value, which excludes JS objects.
using JSPrimitive =
    Union<Smi, HeapNumber, BigInt, String, Symbol, Boolean, Null, Undefined>;
// A user-exposed JavaScript value, as opposed to V8-internal values like Holes
// or a FixedArray.
using JSAny = Union<Smi, HeapNumber, BigInt, String, Symbol, Boolean, Null,
                    Undefined, JSReceiver>;
using JSAnyNotNumeric =
    Union<String, Symbol, Boolean, Null, Undefined, JSReceiver>;
using JSAnyNotNumber =
    Union<BigInt, String, Symbol, Boolean, Null, Undefined, JSReceiver>;
using JSCallable =
    Union<JSBoundFunction, JSFunction, JSObject, JSProxy, JSWrappedFunction>;
// Object prototypes are either JSReceivers or null -- they are not allowed to
// be any other primitive value.
using JSPrototype = Union<JSReceiver, Null>;

using MaybeObject = MaybeWeak<Object>;
using HeapObjectReference = MaybeWeak<HeapObject>;

using JSObjectOrUndefined = Union<JSObject, Undefined>;

// Slots are either full-pointer slots or compressed slots depending on whether
// pointer compression is enabled or not.
struct SlotTraits {
#ifdef V8_COMPRESS_POINTERS
  using TObjectSlot = CompressedObjectSlot;
  using TMaybeObjectSlot = CompressedMaybeObjectSlot;
  using THeapObjectSlot = CompressedHeapObjectSlot;
  using TOffHeapObjectSlot =
      OffHeapCompressedObjectSlot<V8HeapCompressionScheme>;
#ifdef V8_EXTERNAL_CODE_SPACE
  using TInstructionStreamSlot =
      OffHeapCompressedObjectSlot<ExternalCodeCompressionScheme>;
#else
  using TInstructionStreamSlot = TObjectSlot;
#endif  // V8_EXTERNAL_CODE_SPACE
#else
  using TObjectSlot = FullObjectSlot;
  using TMaybeObjectSlot = FullMaybeObjectSlot;
  using THeapObjectSlot = FullHeapObjectSlot;
  using TOffHeapObjectSlot = OffHeapFullObjectSlot;
  using TInstructionStreamSlot = OffHeapFullObjectSlot;
#endif  // V8_COMPRESS_POINTERS
#ifdef V8_ENABLE_SANDBOX
  using TProtectedPointerSlot =
      OffHeapCompressedObjectSlot<TrustedSpaceCompressionScheme>;
#else
  using TProtectedPointerSlot = TObjectSlot;
#endif  // V8_ENABLE_SANDBOX
};

// An ObjectSlot instance describes a kTaggedSize-sized on-heap field ("slot")
// holding an Object value (smi or strong heap object).
using ObjectSlot = SlotTraits::TObjectSlot;

// A MaybeObjectSlot instance describes a kTaggedSize-sized on-heap field
// ("slot") holding Tagged<MaybeObject> (smi or weak heap object or strong heap
// object).
using MaybeObjectSlot = SlotTraits::TMaybeObjectSlot;

// A HeapObjectSlot instance describes a kTaggedSize-sized field ("slot")
// holding a weak or strong pointer to a heap object (think:
// Tagged<HeapObjectReference>).
using HeapObjectSlot = SlotTraits::THeapObjectSlot;

// An OffHeapObjectSlot instance describes a kTaggedSize-sized field ("slot")
// holding an Object value (smi or strong heap object), whose slot location is
// off-heap.
using OffHeapObjectSlot = SlotTraits::TOffHeapObjectSlot;

// A InstructionStreamSlot instance describes a kTaggedSize-sized field
// ("slot") holding a strong pointer to an InstructionStream object. The
// InstructionStream object slots might be compressed and since code space might
// be allocated off the main heap the load operations require explicit cage base
// value for code space.
using InstructionStreamSlot = SlotTraits::TInstructionStreamSlot;

// A protected pointer is one where both the pointer itself and the pointed-to
// object are protected from modifications by an attacker if the sandbox is
// enabled. In practice, this means that they are pointers from one
// TrustedObject to another TrustedObject as (only) trusted objects cannot
// directly be manipulated by an attacker.
using ProtectedPointerSlot = SlotTraits::TProtectedPointerSlot;

using WeakSlotCallback = bool (*)(FullObjectSlot pointer);

using WeakSlotCallbackWithHeap = bool (*)(Heap* heap, FullObjectSlot pointer);

// -----------------------------------------------------------------------------
// Miscellaneous

// NOTE: SpaceIterator depends on AllocationSpace enumeration values being
// consecutive.
enum AllocationSpace {
  RO_SPACE,       // Immortal, immovable and immutable objects,
  NEW_SPACE,      // Young generation space for regular objects collected
                  // with Scavenger/MinorMS.
  OLD_SPACE,      // Old generation regular object space.
  CODE_SPACE,     // Old generation code object space, marked executable.
  SHARED_SPACE,   // Space shared between multiple isolates. Optional.
  TRUSTED_SPACE,  // Space for trusted objects. When the sandbox is enabled,
                  // this space will be located outside of it so that objects in
                  // it cannot directly be corrupted by an attacker.
  SHARED_TRUSTED_SPACE,     // Trusted space but for shared objects. Optional.
  NEW_LO_SPACE,             // Young generation large object space.
  LO_SPACE,                 // Old generation large object space.
  CODE_LO_SPACE,            // Old generation large code object space.
  SHARED_LO_SPACE,          // Space shared between multiple isolates. Optional.
  SHARED_TRUSTED_LO_SPACE,  // Like TRUSTED_SPACE but for shared large objects.
  TRUSTED_LO_SPACE,         // Like TRUSTED_SPACE but for large objects.

  FIRST_SPACE = RO_SPACE,
  LAST_SPACE = TRUSTED_LO_SPACE,
  FIRST_MUTABLE_SPACE = NEW_SPACE,
  LAST_MUTABLE_SPACE = TRUSTED_LO_SPACE,
  FIRST_GROWABLE_PAGED_SPACE = OLD_SPACE,
  LAST_GROWABLE_PAGED_SPACE = TRUSTED_SPACE,
  FIRST_SWEEPABLE_SPACE = NEW_SPACE,
  LAST_SWEEPABLE_SPACE = SHARED_TRUSTED_SPACE
};
constexpr int kSpaceTagSize = 4;
static_assert(FIRST_SPACE == 0);

constexpr bool IsAnyCodeSpace(AllocationSpace space) {
  return space == CODE_SPACE || space == CODE_LO_SPACE;
}
constexpr bool IsAnyTrustedSpace(AllocationSpace space) {
  return space == TRUSTED_SPACE || space == TRUSTED_LO_SPACE ||
         space == SHARED_TRUSTED_SPACE || space == SHARED_TRUSTED_LO_SPACE;
}
constexpr bool IsAnySharedSpace(AllocationSpace space) {
  return space == SHARED_SPACE || space == SHARED_LO_SPACE ||
         space == SHARED_TRUSTED_SPACE || space == SHARED_TRUSTED_LO_SPACE;
}
constexpr bool IsAnyNewSpace(AllocationSpace space) {
  return space == NEW_SPACE || space == NEW_LO_SPACE;
}

constexpr const char* ToString(AllocationSpace space) {
  switch (space) {
    case AllocationSpace::RO_SPACE:
      return "read_only_space";
    case AllocationSpace::NEW_SPACE:
      return "new_space";
    case AllocationSpace::OLD_SPACE:
      return "old_space";
    case AllocationSpace::CODE_SPACE:
      return "code_space";
    case AllocationSpace::SHARED_SPACE:
      return "shared_space";
    case AllocationSpace::TRUSTED_SPACE:
      return "trusted_space";
    case AllocationSpace::SHARED_TRUSTED_SPACE:
      return "shared_trusted_space";
    case AllocationSpace::NEW_LO_SPACE:
      return "new_large_object_space";
    case AllocationSpace::LO_SPACE:
      return "large_object_space";
    case AllocationSpace::CODE_LO_SPACE:
      return "code_large_object_space";
    case AllocationSpace::SHARED_LO_SPACE:
      return "shared_large_object_space";
    case AllocationSpace::SHARED_TRUSTED_LO_SPACE:
      return "shared_trusted_large_object_space";
    case AllocationSpace::TRUSTED_LO_SPACE:
      return "trusted_large_object_space";
  }
}

inline std::ostream& operator<<(std::ostream& os, AllocationSpace space) {
  return os << ToString(space);
}

enum class AllocationType : uint8_t {
  kYoung,  // Regular object allocated in NEW_SPACE or NEW_LO_SPACE.
  kOld,    // Regular object allocated in OLD_SPACE or LO_SPACE.
  kCode,   // InstructionStream object allocated in CODE_SPACE or CODE_LO_SPACE.
  kMap,    // Map object allocated in OLD_SPACE.
  kReadOnly,       // Object allocated in RO_SPACE.
  kSharedOld,      // Regular object allocated in OLD_SPACE in the shared heap.
  kSharedMap,      // Map object in OLD_SPACE in the shared heap.
  kSharedTrusted,  // Trusted objects in TRUSTED_SPACE in the shared heap.
  kTrusted,        // Object allocated in TRUSTED_SPACE or TRUSTED_LO_SPACE.
};

constexpr const char* ToString(AllocationType kind) {
  switch (kind) {
    case AllocationType::kYoung:
      return "Young";
    case AllocationType::kOld:
      return "Old";
    case AllocationType::kCode:
      return "Code";
    case AllocationType::kMap:
      return "Map";
    case AllocationType::kReadOnly:
      return "ReadOnly";
    case AllocationType::kSharedOld:
      return "SharedOld";
    case AllocationType::kSharedMap:
      return "SharedMap";
    case AllocationType::kTrusted:
      return "Trusted";
    case AllocationType::kSharedTrusted:
      return "SharedTrusted";
  }
}

inline std::ostream& operator<<(std::ostream& os, AllocationType type) {
  return os << ToString(type);
}

// Reason for a garbage collection.
//
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused. If you add new items here, update
// src/tools/metrics/histograms/enums.xml in chromium.
enum class GarbageCollectionReason : int {
  kUnknown = 0,
  kAllocationFailure = 1,
  kAllocationLimit = 2,
  kContextDisposal = 3,
  kCountersExtension = 4,
  kDebugger = 5,
  kDeserializer = 6,
  kExternalMemoryPressure = 7,
  kFinalizeMarkingViaStackGuard = 8,
  kFinalizeMarkingViaTask = 9,
  kFullHashtable = 10,
  kHeapProfiler = 11,
  kTask = 12,
  kLastResort = 13,
  kLowMemoryNotification = 14,
  kMakeHeapIterable = 15,
  kMemoryPressure = 16,
  kMemoryReducer = 17,
  kRuntime = 18,
  kSamplingProfiler = 19,
  kSnapshotCreator = 20,
  kTesting = 21,
  kExternalFinalize = 22,
  kGlobalAllocationLimit = 23,
  kMeasureMemory = 24,
  kBackgroundAllocationFailure = 25,
  kFinalizeConcurrentMinorMS = 26,
  kCppHeapAllocationFailure = 27,

  NUM_REASONS,
};

static_assert(kGarbageCollectionReasonMaxValue ==
                  static_cast<int>(GarbageCollectionReason::NUM_REASONS) - 1,
              "The value of kGarbageCollectionReasonMaxValue is inconsistent.");

constexpr const char* ToString(GarbageCollectionReason reason) {
  switch (reason) {
    case GarbageCollectionReason::kAllocationFailure:
      return "allocation failure";
    case GarbageCollectionReason::kAllocationLimit:
      return "allocation limit";
    case GarbageCollectionReason::kContextDisposal:
      return "context disposal";
    case GarbageCollectionReason::kCountersExtension:
      return "counters extension";
    case GarbageCollectionReason::kDebugger:
      return "debugger";
    case GarbageCollectionReason::kDeserializer:
      return "deserialize";
    case GarbageCollectionReason::kExternalMemoryPressure:
      return "external memory pressure";
    case GarbageCollectionReason::kFinalizeMarkingViaStackGuard:
      return "finalize incremental marking via stack guard";
    case GarbageCollectionReason::kFinalizeMarkingViaTask:
      return "finalize incremental marking via task";
    case GarbageCollectionReason::kFullHashtable:
      return "full hash-table";
    case GarbageCollectionReason::kHeapProfiler:
      return "heap profiler";
    case GarbageCollectionReason::kTask:
      return "task";
    case GarbageCollectionReason::kLastResort:
      return "last resort";
    case GarbageCollectionReason::kLowMemoryNotification:
      return "low memory notification";
    case GarbageCollectionReason::kMakeHeapIterable:
      return "make heap iterable";
    case GarbageCollectionReason::kMemoryPressure:
      return "memory pressure";
    case GarbageCollectionReason::kMemoryReducer:
      return "memory reducer";
    case GarbageCollectionReason::kRuntime:
      return "runtime";
    case GarbageCollectionReason::kSamplingProfiler:
      return "sampling profiler";
    case GarbageCollectionReason::kSnapshotCreator:
      return "snapshot creator";
    case GarbageCollectionReason::kTesting:
      return "testing";
    case GarbageCollectionReason::kExternalFinalize:
      return "external finalize";
    case GarbageCollectionReason::kGlobalAllocationLimit:
      return "global allocation limit";
    case GarbageCollectionReason::kMeasureMemory:
      return "measure memory";
    case GarbageCollectionReason::kUnknown:
      return "unknown";
    case GarbageCollectionReason::kBackgroundAllocationFailure:
      return "background allocation failure";
    case GarbageCollectionReason::kFinalizeConcurrentMinorMS:
      return "finalize concurrent MinorMS";
    case GarbageCollectionReason::kCppHeapAllocationFailure:
      return "CppHeap allocation failure";
    case GarbageCollectionReason::NUM_REASONS:
      UNREACHABLE();
  }
}

inline std::ostream& operator<<(std::ostream& os,
                                GarbageCollectionReason reason) {
  return os << ToString(reason);
}

inline size_t hash_value(AllocationType kind) {
  return static_cast<uint8_t>(kind);
}

inline constexpr bool IsSharedAllocationType(AllocationType kind) {
  return kind == AllocationType::kSharedOld ||
         kind == AllocationType::kSharedMap;
}

enum AllocationAlignment {
  // The allocated address is kTaggedSize aligned (this is default for most of
  // the allocations).
  kTaggedAligned,
  // The allocated address is kDoubleSize aligned.
  kDoubleAligned,
  // The (allocated address + kTaggedSize) is kDoubleSize aligned.
  kDoubleUnaligned
};

// TODO(ishell, v8:8875): Consider using aligned allocations once the
// allocation alignment inconsistency is fixed. For now we keep using
// tagged aligned (not double aligned) access since all our supported platforms
// allow tagged-aligned access to doubles and full words.
#define USE_ALLOCATION_ALIGNMENT_BOOL false

enum class AccessMode { ATOMIC, NON_ATOMIC };

enum MinimumCapacity {
  USE_DEFAULT_MINIMUM_CAPACITY,
  USE_CUSTOM_MINIMUM_CAPACITY
};

enum class GarbageCollector { SCAVENGER, MARK_COMPACTOR, MINOR_MARK_SWEEPER };

constexpr const char* ToString(GarbageCollector collector) {
  switch (collector) {
    case GarbageCollector::SCAVENGER:
      return "Scavenger";
    case GarbageCollector::MARK_COMPACTOR:
      return "Mark-Sweep-Compact";
    case GarbageCollector::MINOR_MARK_SWEEPER:
      return "Minor Mark-Sweep";
  }
}

inline std::ostream& operator<<(std::ostream& os, GarbageCollector collector) {
  return os << ToString(collector);
}

enum class CompactionSpaceKind {
  kNone,
  kCompactionSpaceForScavenge,
  kCompactionSpaceForMarkCompact,
  kCompactionSpaceForMinorMarkSweep,
};

enum Executability { NOT_EXECUTABLE, EXECUTABLE };

enum class PageSize { kRegular, kLarge };

enum class CodeFlushMode {
  kFlushBytecode,
  kFlushBaselineCode,
  kStressFlushCode,
};

enum class ExternalBackingStoreType {
  kArrayBuffer,
  kExternalString,
  kNumValues
};

enum class NewJSObjectType : uint8_t {
  kNoAPIWrapper,
  kAPIWrapper,
};

bool inline IsBaselineCodeFlushingEnabled(base::EnumSet<CodeFlushMode> mode) {
  return mode.contains(CodeFlushMode::kFlushBaselineCode);
}

bool inline IsByteCodeFlushingEnabled(base::EnumSet<CodeFlushMode> mode) {
  return mode.contains(CodeFlushMode::kFlushBytecode);
}

bool inline IsStressFlushingEnabled(base::EnumSet<CodeFlushMode> mode) {
  return mode.contains(CodeFlushMode::kStressFlushCode);
}

bool inline IsFlushingDisabled(base::EnumSet<CodeFlushMode> mode) {
  return mode.empty();
}

// Indicates whether a script should be parsed and compiled in REPL mode.
enum class REPLMode {
  kYes,
  kNo,
};

inline REPLMode construct_repl_mode(bool is_repl_mode) {
  return is_repl_mode ? REPLMode::kYes : REPLMode::kNo;
}

// Indicates whether a script is parsed during debugging.
enum class ParsingWhileDebugging {
  kYes,
  kNo,
};

// Flag indicating whether code is built into the VM (one of the natives files).
enum NativesFlag { NOT_NATIVES_CODE, EXTENSION_CODE, INSPECTOR_CODE };

// ParseRestriction is used to restrict the set of valid statements in a
// unit of compilation.  Restriction violations cause a syntax error.
enum ParseRestriction : bool {
  NO_PARSE_RESTRICTION,         // All expressions are allowed.
  ONLY_SINGLE_FUNCTION_LITERAL  // Only a single FunctionLiteral expression.
};

enum class ScriptEventType {
  kReserveId,
  kCreate,
  kDeserialize,
  kBackgroundCompile,
  kStreamingCompileBackground,
  kStreamingCompileForeground
};

// State for inline cache call sites. Aliased as IC::State.
enum class InlineCacheState {
  // No feedback will be collected.
  NO_FEEDBACK,
  // Has never been executed.
  UNINITIALIZED,
  // Has been executed and only one receiver type has been seen.
  MONOMORPHIC,
  // Check failed due to prototype (or map deprecation).
  RECOMPUTE_HANDLER,
  // Multiple receiver types have been seen.
  POLYMORPHIC,
  // Many DOM receiver types have been seen for the same accessor.
  MEGADOM,
  // Many receiver types have been seen.
  MEGAMORPHIC,
  // A generic handler is installed and no extra typefeedback is recorded.
  GENERIC,
};

inline size_t hash_value(InlineCacheState mode) {
  return base::bit_cast<int>(mode);
}

// Printing support.
inline const char* InlineCacheState2String(InlineCacheState state) {
  switch (state) {
    case InlineCacheState::NO_FEEDBACK:
      return "NOFEEDBACK";
    case InlineCacheState::UNINITIALIZED:
      return "UNINITIALIZED";
    case InlineCacheState::MONOMORPHIC:
      return "MONOMORPHIC";
    case InlineCacheState::RECOMPUTE_HANDLER:
      return "RECOMPUTE_HANDLER";
    case InlineCacheState::POLYMORPHIC:
      return "POLYMORPHIC";
    case InlineCacheState::MEGAMORPHIC:
      return "MEGAMORPHIC";
    case InlineCacheState::MEGADOM:
      return "MEGADOM";
    case InlineCacheState::GENERIC:
      return "GENERIC";
  }
  UNREACHABLE();
}

enum WhereToStart { kStartAtReceiver, kStartAtPrototype };

enum ResultSentinel { kNotFound = -1, kUnsupported = -2 };

enum ShouldThrow {
  kDontThrow = Internals::kDontThrow,
  kThrowOnError = Internals::kThrowOnError,
};

// The result that might be returned by Setter/Definer/Deleter interceptor
// callback when it doesn't throw an exception.
enum class InterceptorResult {
  kFalse = 0,
  kTrue = 1,
  kNotIntercepted = 2,
};

enum class ThreadKind { kMain, kBackground };

// Union used for customized checking of the IEEE double types
// inlined within v8 runtime, rather than going to the underlying
// platform headers and libraries
union IeeeDoubleLittleEndianArchType {
  double d;
  struct {
    unsigned int man_low : 32;
    unsigned int man_high : 20;
    unsigned int exp : 11;
    unsigned int sign : 1;
  } bits;
};

union IeeeDoubleBigEndianArchType {
  double d;
  struct {
    unsigned int sign : 1;
    unsigned int exp : 11;
    unsigned int man_high : 20;
    unsigned int man_low : 32;
  } bits;
};

#if V8_TARGET_LITTLE_ENDIAN
using IeeeDoubleArchType = IeeeDoubleLittleEndianArchType;
constexpr int kIeeeDoubleMantissaWordOffset = 0;
constexpr int kIeeeDoubleExponentWordOffset = 4;
#else
using IeeeDoubleArchType = IeeeDoubleBigEndianArchType;
constexpr int kIeeeDoubleMantissaWordOffset = 4;
constexpr int kIeeeDoubleExponentWordOffset = 0;
#endif

// -----------------------------------------------------------------------------
// Macros

// Testers for test.

#define HAS_SMI_TAG(value) \
  ((static_cast<i::Tagged_t>(value) & ::i::kSmiTagMask) == ::i::kSmiTag)

#define HAS_STRONG_HEAP_OBJECT_TAG(value)                          \
  (((static_cast<i::Tagged_t>(value) & ::i::kHeapObjectTagMask) == \
    ::i::kHeapObjectTag))

#define HAS_WEAK_HEAP_OBJECT_TAG(value)                            \
  (((static_cast<i::Tagged_t>(value) & ::i::kHeapObjectTagMask) == \
    ::i::kWeakHeapObjectTag))

// OBJECT_POINTER_ALIGN returns the value aligned as a HeapObject pointer
#define OBJECT_POINTER_ALIGN(value) \
  (((value) + ::i::kObjectAlignmentMask) & ~::i::kObjectAlignmentMask)

// OBJECT_POINTER_ALIGN is used to statically align object sizes to
// kObjectAlignment (which is kTaggedSize). ALIGN_TO_ALLOCATION_ALIGNMENT is
// used for dynamic allocations to align sizes and addresses to at least 8 bytes
// when an 8GB+ compressed heap is enabled.
// TODO(v8:13070): Consider merging this with OBJECT_POINTER_ALIGN.
#ifdef V8_COMPRESS_POINTERS_8GB
#define ALIGN_TO_ALLOCATION_ALIGNMENT(value)      \
  (((value) + ::i::kObjectAlignment8GbHeapMask) & \
   ~::i::kObjectAlignment8GbHeapMask)
#else
#define ALIGN_TO_ALLOCATION_ALIGNMENT(value) (value)
#endif

// OBJECT_POINTER_PADDING returns the padding size required to align value
// as a HeapObject pointer
#define OBJECT_POINTER_PADDING(value) (OBJECT_POINTER_ALIGN(value) - (value))

// POINTER_SIZE_ALIGN returns the value aligned as a system pointer.
#define POINTER_SIZE_ALIGN(value) \
  (((value) + ::i::kPointerAlignmentMask) & ~::i::kPointerAlignmentMask)

// POINTER_SIZE_PADDING returns the padding size required to align value
// as a system pointer.
#define POINTER_SIZE_PADDING(value) (POINTER_SIZE_ALIGN(value) - (value))

// CODE_POINTER_ALIGN returns the value aligned as a generated code segment.
#define CODE_POINTER_ALIGN(value) \
  (((value) + ::i::kCodeAlignmentMask) & ~::i::kCodeAlignmentMask)

// CODE_POINTER_PADDING returns the padding size required to align value
// as a generated code segment.
#define CODE_POINTER_PADDING(value) (CODE_POINTER_ALIGN(value) - (value))

// DOUBLE_POINTER_ALIGN returns the value algined for double pointers.
#define DOUBLE_POINTER_ALIGN(value) \
  (((value) + ::i::kDoubleAlignmentMask) & ~::i::kDoubleAlignmentMask)

// Prediction hint for branches.
enum class BranchHint : uint8_t { kNone, kTrue, kFalse };

// Defines hints about receiver values based on structural knowledge.
enum class ConvertReceiverMode : unsigned {
  kNullOrUndefined,     // Guaranteed to be null or undefined.
  kNotNullOrUndefined,  // Guaranteed to never be null or undefined.
  kAny,                 // No specific knowledge about receiver.

  kLast = kAny
};

inline size_t hash_value(ConvertReceiverMode mode) {
  return base::bit_cast<unsigned>(mode);
}

inline std::ostream& operator<<(std::ostream& os, ConvertReceiverMode mode) {
  switch (mode) {
    case ConvertReceiverMode::kNullOrUndefined:
      return os << "NULL_OR_UNDEFINED";
    case ConvertReceiverMode::kNotNullOrUndefined:
      return os << "NOT_NULL_OR_UNDEFINED";
    case ConvertReceiverMode::kAny:
      return os << "ANY";
  }
  UNREACHABLE();
}

// Valid hints for the abstract operation OrdinaryToPrimitive,
// implemented according to ES6, section 7.1.1.
enum class OrdinaryToPrimitiveHint { kNumber, kString };

// Valid hints for the abstract operation ToPrimitive,
// implemented according to ES6, section 7.1.1.
enum class ToPrimitiveHint { kDefault, kNumber, kString };

// Defines specifics about arguments object or rest parameter creation.
enum class CreateArgumentsType : uint8_t {
  kMappedArguments,
  kUnmappedArguments,
  kRestParameter
};

inline size_t hash_value(CreateArgumentsType type) {
  return base::bit_cast<uint8_t>(type);
}

inline std::ostream& operator<<(std::ostream& os, CreateArgumentsType type) {
  switch (type) {
    case CreateArgumentsType::kMappedArguments:
      return os << "MAPPED_ARGUMENTS";
    case CreateArgumentsType::kUnmappedArguments:
      return os << "UNMAPPED_ARGUMENTS";
    case CreateArgumentsType::kRestParameter:
      return os << "REST_PARAMETER";
  }
  UNREACHABLE();
}

// Threshold calculated using a microbenckmark.
// https://chromium-review.googlesource.com/c/v8/v8/+/3429210
constexpr int kScopeInfoMaxInlinedLocalNamesSize = 75;

enum ScopeType : uint8_t {
  SCRIPT_SCOPE,        // The top-level scope for a script or a top-level eval.
  REPL_MODE_SCOPE,     // The top-level scope for a repl-mode script.
  CLASS_SCOPE,         // The scope introduced by a class.
  EVAL_SCOPE,          // The top-level scope for an eval source.
  FUNCTION_SCOPE,      // The top-level scope for a function.
  MODULE_SCOPE,        // The scope introduced by a module literal
  CATCH_SCOPE,         // The scope introduced by catch.
  BLOCK_SCOPE,         // The scope introduced by a new block.
  WITH_SCOPE,          // The scope introduced by with.
  SHADOW_REALM_SCOPE,  // Synthetic scope for ShadowRealm NativeContexts.
};

inline std::ostream& operator<<(std::ostream& os, ScopeType type) {
  switch (type) {
    case ScopeType::EVAL_SCOPE:
      return os << "EVAL_SCOPE";
    case ScopeType::FUNCTION_SCOPE:
      return os << "FUNCTION_SCOPE";
    case ScopeType::MODULE_SCOPE:
      return os << "MODULE_SCOPE";
    case ScopeType::SCRIPT_SCOPE:
      return os << "SCRIPT_SCOPE";
    case ScopeType::CATCH_SCOPE:
      return os << "CATCH_SCOPE";
    case ScopeType::BLOCK_SCOPE:
      return os << "BLOCK_SCOPE";
    case ScopeType::CLASS_SCOPE:
      return os <<
```