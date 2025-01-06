Response:
The user wants a summary of the functionality of the provided C++ header file `v8-internal.h`. I need to go through the code and identify the key data structures, constants, and functions defined. Since this is part 2 of 3, I should focus on the specific sections provided and avoid repeating information that would likely be covered in other parts.

Here's a plan:
1. **Identify key data structures:** Look for `using` declarations that define new types, like `IndirectPointerHandle`, `TrustedPointerHandle`, `CodePointerHandle`, and `JSDispatchHandle`.
2. **Analyze constants:** Examine `constexpr` and `static const` declarations to understand the sizes, offsets, and limits related to the data structures.
3. **Understand the purpose of tables:**  Pay close attention to the descriptions of the different pointer tables (Trusted Pointer Table, Code Pointer Table, JS Dispatch Table) and their relationship to sandboxing.
4. **Focus on part 2:**  The provided text emphasizes pointer handling and memory management, particularly in the context of the sandbox. I should focus on these aspects.
5. **Summarize functionalities:** Group related definitions and constants to describe higher-level functionalities.```javascript
/* 假设 v8/include/v8-internal.h 是一个定义了 V8 内部数据结构和常量的头文件，
   并且与 JavaScript 的执行密切相关。

   以下是一些基于该头文件内容的功能归纳和 JavaScript 示例。
*/

/**
 * 功能归纳：
 *
 * 1. **间接指针处理:** 定义了 `IndirectPointerHandle` 和相关的常量，用于在启用沙箱模式时安全地引用内存。
 *    - `IndirectPointerHandle`:  表示指向指针表的 32 位索引。
 *    - `kNullIndirectPointerHandle`: 空句柄，指向包含 `nullptr` 的条目。
 *
 * 2. **受信指针 (Trusted Pointers):**  定义了 `TrustedPointerHandle` 和相关常量，用于在沙箱模式下安全地引用受信堆空间中的对象。
 *    - `TrustedPointerHandle`:  在沙箱启用时是 `IndirectPointerHandle`，禁用时是常规指针。
 *    - `kTrustedPointerTableReservationSize`: 受信指针表的虚拟内存预留大小。
 *    - `kTrustedPointerHandleShift`:  用于偏移受信指针句柄的位数。
 *    - `kNullTrustedPointerHandle`: 空受信指针句柄。
 *    - `kMaxTrustedPointers`:  受信指针表中的最大条目数。
 *
 * 3. **代码指针 (Code Pointers):** 定义了 `CodePointerHandle` 和相关常量，用于在沙箱模式下安全地引用代码对象及其指令流。
 *    - `CodePointerHandle`: 在沙箱启用时是 `IndirectPointerHandle`，禁用时是常规指针。
 *    - `kCodePointerTableReservationSize`: 代码指针表的虚拟内存预留大小。
 *    - `kCodePointerHandleShift`: 用于偏移代码指针句柄的位数。
 *    - `kNullCodePointerHandle`: 空代码指针句柄。
 *    - `kCodePointerHandleMarker`: 用于区分代码指针句柄和受信指针句柄的标记。
 *    - `kMaxCodePointers`: 代码指针表中的最大条目数。
 *    - `kCodePointerTableEntryEntrypointOffset`: 代码指针表条目中入口点的偏移量。
 *    - `kCodePointerTableEntryCodeObjectOffset`: 代码指针表条目中代码对象的偏移量。
 *
 * 4. **JavaScript 分发表 (JavaScript Dispatch Table):** 定义了 `JSDispatchHandle` 和相关常量，用于 JavaScript 方法的快速分发。
 *    - `JSDispatchHandle`: 表示指向 JavaScript 分发表的 32 位索引。
 *    - `kNullJSDispatchHandle`: 空 JavaScript 分发句柄。
 *    - `kJSDispatchTableReservationSize`: JavaScript 分发表的虚拟内存预留大小。
 *    - `kJSDispatchHandleShift`: 用于偏移 JavaScript 分发句柄的位数。
 *    - `kMaxJSDispatchEntries`: JavaScript 分发表中的最大条目数。
 *
 * 5. **Isolate 相关功能:** 提供了从 `HeapObject` 获取 `Isolate` 指针的函数 `IsolateFromNeverReadOnlySpaceObject`，以及判断是否应该抛出错误的函数 `ShouldThrowOnError`。
 *
 * 6. **内部常量:**  定义了大量的内部常量，用于描述 V8 内部对象布局、大小和偏移量。这些常量对于 V8 引擎的内部操作至关重要，例如访问对象的属性、方法和元数据。
 *    - 例如：`kHeapObjectMapOffset` (堆对象 Map 的偏移量), `kMapInstanceTypeOffset` (Map 中实例类型的偏移量) 等。
 *
 * 7. **辅助函数:** 提供了一些内联函数，用于执行常见的底层操作，例如检查初始化状态 (`CheckInitialized`)、判断是否是堆对象 (`HasHeapObjectTag`)、Smi（小整数）和地址之间的转换 (`SmiValue`, `AddressToSmi`, `IntToSmi`) 等。
 *
 * 8. **沙箱支持:** 定义了与沙箱模式相关的常量和类型，用于增强安全性。例如，受信指针和代码指针在沙箱模式下使用间接指针表。
 */

// JavaScript 示例：说明 TrustedPointerHandle 和 CodePointerHandle 的概念
// (请注意，这些是 V8 内部概念，无法直接在 JavaScript 中访问)

// 假设我们有一个指向 JavaScript 对象的受信指针
// 在 V8 内部，这可能通过 TrustedPointerHandle 来表示

// 假设我们有一个指向一段 JIT 代码的代码指针
// 在 V8 内部，这可能通过 CodePointerHandle 来表示

// 在 JavaScript 中，我们不需要直接处理这些指针，V8 引擎会负责管理内存和执行。
const obj = { a: 1 };
function add(x, y) { return x + y; }

// 当 JavaScript 引擎执行 `obj.a` 或调用 `add(2, 3)` 时，
// 内部会用到类似 TrustedPointerHandle 和 CodePointerHandle 的机制。

// JavaScript 中常见的编程错误与 V8 内部的内存管理有关，
// 但通常体现在更高的抽象层次上。

// 示例：内存泄漏（虽然 V8 有垃圾回收机制，但某些情况下仍然可能发生）
let largeArray = [];
setInterval(() => {
  largeArray.push(new Array(10000).fill(Math.random()));
}, 10);
// 开发者可能忘记清理 `largeArray`，导致内存占用持续增加。
// V8 的垃圾回收器最终会回收这些内存，但这可能会影响性能。

// 示例：访问已释放的内存（在手动管理内存的语言中更常见，但在 JavaScript 的某些场景下也可能出现问题，例如与 WebAssembly 交互时）
// 这在纯 JavaScript 中比较难直接演示，因为 V8 负责内存管理。
// 但如果与 C++ 扩展或 WebAssembly 交互不当，可能会出现类似问题。

// 代码逻辑推理：

// 假设输入一个 TrustedPointerHandle 的值：
const trustedHandleValue = 1024; // 假设这是一个有效的 TrustedPointerHandle

// 如果沙箱已启用，V8 内部会根据 kTrustedPointerHandleShift 计算出在受信指针表中的索引：
// index = trustedHandleValue >> kTrustedPointerHandleShift;
// 然后从受信指针表中加载对应的指针。

// 假设输入一个 CodePointerHandle 的值：
const codeHandleValue = 2048 + 0x1; // 假设这是一个有效的 CodePointerHandle，并且带有标记

// 如果沙箱已启用，V8 内部会检查 kCodePointerHandleMarker 来确定这是一个代码指针，
// 然后根据 kCodePointerHandleShift 计算出在代码指针表中的索引：
// index = codeHandleValue >> kCodePointerHandleShift;
// 然后从代码指针表中加载代码对象指针和入口点指针。

// 输出：根据句柄的值，V8 内部会解析出对应的内存地址或对象引用。

// 用户常见的编程错误示例：

// 1. 类型错误：在需要特定类型的对象时传递了错误类型的对象。
function processObject(obj) {
  if (typeof obj !== 'object' || obj === null) {
    throw new Error("Expected an object");
  }
  // ... 处理对象
}

processObject("not an object"); // 错误：传递了字符串而不是对象

// 2. 作用域错误：在不正确的上下文中访问变量。
function outer() {
  let x = 10;
  function inner() {
    console.log(x); // 可以访问外部作用域的变量
  }
  inner();
}
outer();

function anotherOuter() {
  function anotherInner() {
    console.log(y); // 错误：y 在此作用域中未定义
  }
  let y = 20;
  anotherInner();
}
// anotherOuter(); // 会抛出 ReferenceError

// 3. 异步编程错误：未能正确处理异步操作的结果。
function fetchData() {
  return new Promise(resolve => {
    setTimeout(() => {
      resolve("Data fetched");
    }, 100);
  });
}

async function processData() {
  const data = fetchData(); // 注意：这里没有 await
  console.log(data); // 错误：此时 data 是一个 Promise 对象，而不是 "Data fetched"
}
processData();

async function correctProcessData() {
  const data = await fetchData();
  console.log(data); // 正确：等待 Promise 完成
}
// correctProcessData();
```

**功能归纳 (第 2 部分):**

这部分 `v8/include/v8-internal.h` 的代码主要关注 V8 引擎内部的**内存管理和安全机制**，特别是在**沙箱环境**下。其核心功能可以归纳为：

1. **定义和管理间接指针 (Indirect Pointers):**  引入 `IndirectPointerHandle` 作为一种抽象的指针表示，用于在沙箱模式下安全地引用内存。这种间接性避免了直接暴露原始指针，增强了安全性。

2. **实现受信指针 (Trusted Pointers):**  定义了 `TrustedPointerHandle` 及其相关的表结构和常量，用于在沙箱环境中安全地访问位于受信堆空间的对象。这允许沙箱内的代码与沙箱外的受信代码进行受控的交互。

3. **实现代码指针 (Code Pointers):**  定义了 `CodePointerHandle` 及其相关的表结构和常量，专门用于在沙箱环境中安全地引用代码对象及其入口点。这种机制优化了代码执行的效率，并确保了沙箱的安全性。

4. **定义 JavaScript 分发表 (JS Dispatch Table):**  引入 `JSDispatchHandle` 及其相关的表结构和常量，用于优化 JavaScript 方法的调用过程，提高性能。

5. **提供内部常量和偏移量信息:**  定义了大量的常量，描述了 V8 内部数据结构的布局、大小和偏移量。这些信息是 V8 引擎进行内存操作和对象访问的基础。

6. **提供辅助函数:**  提供了一些内联函数，用于执行底层的内存操作和类型检查，例如 Smi 转换、堆对象判断等，这些函数是 V8 内部操作的 building blocks。

总的来说，这部分代码的核心目标是**在保证性能的前提下，提升 V8 引擎在沙箱环境下的安全性和内存管理的效率**。它定义了用于间接引用内存的关键数据结构和常量，为 V8 的安全执行环境提供了基础。

Prompt: 
```
这是目录为v8/include/v8-internal.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-internal.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
y, in contrast to "normal" pointers, indirect pointers never need to
// be tracked by the GC (i.e. there is no remembered set for them).
// These pointers do not exist when the sandbox is disabled.

// An IndirectPointerHandle represents a 32-bit index into a pointer table.
using IndirectPointerHandle = uint32_t;

// A null handle always references an entry that contains nullptr.
constexpr IndirectPointerHandle kNullIndirectPointerHandle = 0;

// When the sandbox is enabled, indirect pointers are used to implement:
// - TrustedPointers: an indirect pointer using the trusted pointer table (TPT)
//   and referencing a TrustedObject in one of the trusted heap spaces.
// - CodePointers, an indirect pointer using the code pointer table (CPT) and
//   referencing a Code object together with its instruction stream.

//
// Trusted Pointers.
//
// A pointer to a TrustedObject.
// When the sandbox is enabled, these are indirect pointers using the trusted
// pointer table (TPT). They are used to reference trusted objects (located in
// one of V8's trusted heap spaces, outside of the sandbox) from inside the
// sandbox in a memory-safe way. When the sandbox is disabled, these are
// regular tagged pointers.
using TrustedPointerHandle = IndirectPointerHandle;

// The size of the virtual memory reservation for the trusted pointer table.
// As with the external pointer table, a maximum table size in combination with
// shifted indices allows omitting bounds checks.
constexpr size_t kTrustedPointerTableReservationSize = 64 * MB;

// The trusted pointer handles are stores shifted to the left by this amount
// to guarantee that they are smaller than the maximum table size.
constexpr uint32_t kTrustedPointerHandleShift = 9;

// A null handle always references an entry that contains nullptr.
constexpr TrustedPointerHandle kNullTrustedPointerHandle =
    kNullIndirectPointerHandle;

// The maximum number of entries in an trusted pointer table.
constexpr int kTrustedPointerTableEntrySize = 8;
constexpr int kTrustedPointerTableEntrySizeLog2 = 3;
constexpr size_t kMaxTrustedPointers =
    kTrustedPointerTableReservationSize / kTrustedPointerTableEntrySize;
static_assert((1 << (32 - kTrustedPointerHandleShift)) == kMaxTrustedPointers,
              "kTrustedPointerTableReservationSize and "
              "kTrustedPointerHandleShift don't match");

//
// Code Pointers.
//
// A pointer to a Code object.
// Essentially a specialized version of a trusted pointer that (when the
// sandbox is enabled) uses the code pointer table (CPT) instead of the TPT.
// Each entry in the CPT contains both a pointer to a Code object as well as a
// pointer to the Code's entrypoint. This allows calling/jumping into Code with
// one fewer memory access (compared to the case where the entrypoint pointer
// first needs to be loaded from the Code object). As such, a CodePointerHandle
// can be used both to obtain the referenced Code object and to directly load
// its entrypoint.
//
// When the sandbox is disabled, these are regular tagged pointers.
using CodePointerHandle = IndirectPointerHandle;

// The size of the virtual memory reservation for the code pointer table.
// As with the other tables, a maximum table size in combination with shifted
// indices allows omitting bounds checks.
constexpr size_t kCodePointerTableReservationSize = 128 * MB;

// Code pointer handles are shifted by a different amount than indirect pointer
// handles as the tables have a different maximum size.
constexpr uint32_t kCodePointerHandleShift = 9;

// A null handle always references an entry that contains nullptr.
constexpr CodePointerHandle kNullCodePointerHandle = kNullIndirectPointerHandle;

// It can sometimes be necessary to distinguish a code pointer handle from a
// trusted pointer handle. A typical example would be a union trusted pointer
// field that can refer to both Code objects and other trusted objects. To
// support these use-cases, we use a simple marking scheme where some of the
// low bits of a code pointer handle are set, while they will be unset on a
// trusted pointer handle. This way, the correct table to resolve the handle
// can be determined even in the absence of a type tag.
constexpr uint32_t kCodePointerHandleMarker = 0x1;
static_assert(kCodePointerHandleShift > 0);
static_assert(kTrustedPointerHandleShift > 0);

// The maximum number of entries in a code pointer table.
constexpr int kCodePointerTableEntrySize = 16;
constexpr int kCodePointerTableEntrySizeLog2 = 4;
constexpr size_t kMaxCodePointers =
    kCodePointerTableReservationSize / kCodePointerTableEntrySize;
static_assert(
    (1 << (32 - kCodePointerHandleShift)) == kMaxCodePointers,
    "kCodePointerTableReservationSize and kCodePointerHandleShift don't match");

constexpr int kCodePointerTableEntryEntrypointOffset = 0;
constexpr int kCodePointerTableEntryCodeObjectOffset = 8;

// Constants that can be used to mark places that should be modified once
// certain types of objects are moved out of the sandbox and into trusted space.
constexpr bool kRuntimeGeneratedCodeObjectsLiveInTrustedSpace = true;
constexpr bool kBuiltinCodeObjectsLiveInTrustedSpace = false;
constexpr bool kAllCodeObjectsLiveInTrustedSpace =
    kRuntimeGeneratedCodeObjectsLiveInTrustedSpace &&
    kBuiltinCodeObjectsLiveInTrustedSpace;

//
// JavaScript Dispatch Table
//
// A JSDispatchHandle represents a 32-bit index into a JSDispatchTable.
using JSDispatchHandle = uint32_t;

constexpr JSDispatchHandle kNullJSDispatchHandle = 0;

// The size of the virtual memory reservation for the JSDispatchTable.
// As with the other tables, a maximum table size in combination with shifted
// indices allows omitting bounds checks.
constexpr size_t kJSDispatchTableReservationSize = 128 * MB;
constexpr uint32_t kJSDispatchHandleShift = 9;

// The maximum number of entries in a JSDispatchTable.
constexpr int kJSDispatchTableEntrySize = 16;
constexpr int kJSDispatchTableEntrySizeLog2 = 4;
constexpr size_t kMaxJSDispatchEntries =
    kJSDispatchTableReservationSize / kJSDispatchTableEntrySize;
static_assert((1 << (32 - kJSDispatchHandleShift)) == kMaxJSDispatchEntries,
              "kJSDispatchTableReservationSize and kJSDispatchEntryHandleShift "
              "don't match");

// {obj} must be the raw tagged pointer representation of a HeapObject
// that's guaranteed to never be in ReadOnlySpace.
V8_EXPORT internal::Isolate* IsolateFromNeverReadOnlySpaceObject(Address obj);

// Returns if we need to throw when an error occurs. This infers the language
// mode based on the current context and the closure. This returns true if the
// language mode is strict.
V8_EXPORT bool ShouldThrowOnError(internal::Isolate* isolate);
/**
 * This class exports constants and functionality from within v8 that
 * is necessary to implement inline functions in the v8 api.  Don't
 * depend on functions and constants defined here.
 */
class Internals {
#ifdef V8_MAP_PACKING
  V8_INLINE static constexpr Address UnpackMapWord(Address mapword) {
    // TODO(wenyuzhao): Clear header metadata.
    return mapword ^ kMapWordXorMask;
  }
#endif

 public:
  // These values match non-compiler-dependent values defined within
  // the implementation of v8.
  static const int kHeapObjectMapOffset = 0;
  static const int kMapInstanceTypeOffset = 1 * kApiTaggedSize + kApiInt32Size;
  static const int kStringResourceOffset =
      1 * kApiTaggedSize + 2 * kApiInt32Size;

  static const int kOddballKindOffset = 4 * kApiTaggedSize + kApiDoubleSize;
  static const int kJSObjectHeaderSize = 3 * kApiTaggedSize;
#ifdef V8_COMPRESS_POINTERS
  static const int kJSAPIObjectWithEmbedderSlotsHeaderSize =
      kJSObjectHeaderSize + kApiInt32Size;
#else   // !V8_COMPRESS_POINTERS
  static const int kJSAPIObjectWithEmbedderSlotsHeaderSize =
      kJSObjectHeaderSize + kApiTaggedSize;
#endif  // !V8_COMPRESS_POINTERS
  static const int kFixedArrayHeaderSize = 2 * kApiTaggedSize;
  static const int kEmbedderDataArrayHeaderSize = 2 * kApiTaggedSize;
  static const int kEmbedderDataSlotSize = kApiSystemPointerSize;
#ifdef V8_ENABLE_SANDBOX
  static const int kEmbedderDataSlotExternalPointerOffset = kApiTaggedSize;
#else
  static const int kEmbedderDataSlotExternalPointerOffset = 0;
#endif
  static const int kNativeContextEmbedderDataOffset = 6 * kApiTaggedSize;
  static const int kStringRepresentationAndEncodingMask = 0x0f;
  static const int kStringEncodingMask = 0x8;
  static const int kExternalTwoByteRepresentationTag = 0x02;
  static const int kExternalOneByteRepresentationTag = 0x0a;

  static const uint32_t kNumIsolateDataSlots = 4;
  static const int kStackGuardSize = 8 * kApiSystemPointerSize;
  static const int kNumberOfBooleanFlags = 6;
  static const int kErrorMessageParamSize = 1;
  static const int kTablesAlignmentPaddingSize = 1;
  static const int kRegExpStaticResultOffsetsVectorSize = kApiSystemPointerSize;
  static const int kBuiltinTier0EntryTableSize = 7 * kApiSystemPointerSize;
  static const int kBuiltinTier0TableSize = 7 * kApiSystemPointerSize;
  static const int kLinearAllocationAreaSize = 3 * kApiSystemPointerSize;
  static const int kThreadLocalTopSize = 30 * kApiSystemPointerSize;
  static const int kHandleScopeDataSize =
      2 * kApiSystemPointerSize + 2 * kApiInt32Size;

  // ExternalPointerTable and TrustedPointerTable layout guarantees.
  static const int kExternalPointerTableBasePointerOffset = 0;
  static const int kExternalPointerTableSize = 2 * kApiSystemPointerSize;
  static const int kExternalBufferTableSize = 2 * kApiSystemPointerSize;
  static const int kTrustedPointerTableSize = 2 * kApiSystemPointerSize;
  static const int kTrustedPointerTableBasePointerOffset = 0;

  // IsolateData layout guarantees.
  static const int kIsolateCageBaseOffset = 0;
  static const int kIsolateStackGuardOffset =
      kIsolateCageBaseOffset + kApiSystemPointerSize;
  static const int kVariousBooleanFlagsOffset =
      kIsolateStackGuardOffset + kStackGuardSize;
  static const int kErrorMessageParamOffset =
      kVariousBooleanFlagsOffset + kNumberOfBooleanFlags;
  static const int kBuiltinTier0EntryTableOffset =
      kErrorMessageParamOffset + kErrorMessageParamSize +
      kTablesAlignmentPaddingSize + kRegExpStaticResultOffsetsVectorSize;
  static const int kBuiltinTier0TableOffset =
      kBuiltinTier0EntryTableOffset + kBuiltinTier0EntryTableSize;
  static const int kNewAllocationInfoOffset =
      kBuiltinTier0TableOffset + kBuiltinTier0TableSize;
  static const int kOldAllocationInfoOffset =
      kNewAllocationInfoOffset + kLinearAllocationAreaSize;

  static const int kFastCCallAlignmentPaddingSize =
      kApiSystemPointerSize == 8 ? 5 * kApiSystemPointerSize
                                 : 1 * kApiSystemPointerSize;
  static const int kIsolateFastCCallCallerFpOffset =
      kOldAllocationInfoOffset + kLinearAllocationAreaSize +
      kFastCCallAlignmentPaddingSize;
  static const int kIsolateFastCCallCallerPcOffset =
      kIsolateFastCCallCallerFpOffset + kApiSystemPointerSize;
  static const int kIsolateFastApiCallTargetOffset =
      kIsolateFastCCallCallerPcOffset + kApiSystemPointerSize;
  static const int kIsolateLongTaskStatsCounterOffset =
      kIsolateFastApiCallTargetOffset + kApiSystemPointerSize;
  static const int kIsolateThreadLocalTopOffset =
      kIsolateLongTaskStatsCounterOffset + kApiSizetSize;
  static const int kIsolateHandleScopeDataOffset =
      kIsolateThreadLocalTopOffset + kThreadLocalTopSize;
  static const int kIsolateEmbedderDataOffset =
      kIsolateHandleScopeDataOffset + kHandleScopeDataSize;
#ifdef V8_COMPRESS_POINTERS
  static const int kIsolateExternalPointerTableOffset =
      kIsolateEmbedderDataOffset + kNumIsolateDataSlots * kApiSystemPointerSize;
  static const int kIsolateSharedExternalPointerTableAddressOffset =
      kIsolateExternalPointerTableOffset + kExternalPointerTableSize;
  static const int kIsolateCppHeapPointerTableOffset =
      kIsolateSharedExternalPointerTableAddressOffset + kApiSystemPointerSize;
#ifdef V8_ENABLE_SANDBOX
  static const int kIsolateTrustedCageBaseOffset =
      kIsolateCppHeapPointerTableOffset + kExternalPointerTableSize;
  static const int kIsolateTrustedPointerTableOffset =
      kIsolateTrustedCageBaseOffset + kApiSystemPointerSize;
  static const int kIsolateSharedTrustedPointerTableAddressOffset =
      kIsolateTrustedPointerTableOffset + kTrustedPointerTableSize;
  static const int kIsolateApiCallbackThunkArgumentOffset =
      kIsolateSharedTrustedPointerTableAddressOffset + kApiSystemPointerSize;
#else
  static const int kIsolateApiCallbackThunkArgumentOffset =
      kIsolateCppHeapPointerTableOffset + kExternalPointerTableSize;
#endif  // V8_ENABLE_SANDBOX
#else
  static const int kIsolateApiCallbackThunkArgumentOffset =
      kIsolateEmbedderDataOffset + kNumIsolateDataSlots * kApiSystemPointerSize;
#endif  // V8_COMPRESS_POINTERS
  static const int kIsolateRegexpExecVectorArgumentOffset =
      kIsolateApiCallbackThunkArgumentOffset + kApiSystemPointerSize;
  static const int kContinuationPreservedEmbedderDataOffset =
      kIsolateRegexpExecVectorArgumentOffset + kApiSystemPointerSize;
  static const int kIsolateRootsOffset =
      kContinuationPreservedEmbedderDataOffset + kApiSystemPointerSize;

  // Assert scopes
  static const int kDisallowGarbageCollectionAlign = alignof(uint32_t);
  static const int kDisallowGarbageCollectionSize = sizeof(uint32_t);

#if V8_STATIC_ROOTS_BOOL

// These constants are copied from static-roots.h and guarded by static asserts.
#define EXPORTED_STATIC_ROOTS_PTR_LIST(V) \
  V(UndefinedValue, 0x11)                 \
  V(NullValue, 0x2d)                      \
  V(TrueValue, 0x71)                      \
  V(FalseValue, 0x55)                     \
  V(EmptyString, 0x49)                    \
  V(TheHoleValue, 0x739)

  using Tagged_t = uint32_t;
  struct StaticReadOnlyRoot {
#define DEF_ROOT(name, value) static constexpr Tagged_t k##name = value;
    EXPORTED_STATIC_ROOTS_PTR_LIST(DEF_ROOT)
#undef DEF_ROOT

    // Use 0 for kStringMapLowerBound since string maps are the first maps.
    static constexpr Tagged_t kStringMapLowerBound = 0;
    static constexpr Tagged_t kStringMapUpperBound = 0x425;

#define PLUSONE(...) +1
    static constexpr size_t kNumberOfExportedStaticRoots =
        2 + EXPORTED_STATIC_ROOTS_PTR_LIST(PLUSONE);
#undef PLUSONE
  };

#endif  // V8_STATIC_ROOTS_BOOL

  static const int kUndefinedValueRootIndex = 4;
  static const int kTheHoleValueRootIndex = 5;
  static const int kNullValueRootIndex = 6;
  static const int kTrueValueRootIndex = 7;
  static const int kFalseValueRootIndex = 8;
  static const int kEmptyStringRootIndex = 9;

  static const int kNodeClassIdOffset = 1 * kApiSystemPointerSize;
  static const int kNodeFlagsOffset = 1 * kApiSystemPointerSize + 3;
  static const int kNodeStateMask = 0x3;
  static const int kNodeStateIsWeakValue = 2;

  static const int kFirstNonstringType = 0x80;
  static const int kOddballType = 0x83;
  static const int kForeignType = 0xcc;
  static const int kJSSpecialApiObjectType = 0x410;
  static const int kJSObjectType = 0x421;
  static const int kFirstJSApiObjectType = 0x422;
  static const int kLastJSApiObjectType = 0x80A;
  // Defines a range [kFirstEmbedderJSApiObjectType, kJSApiObjectTypesCount]
  // of JSApiObject instance type values that an embedder can use.
  static const int kFirstEmbedderJSApiObjectType = 0;
  static const int kLastEmbedderJSApiObjectType =
      kLastJSApiObjectType - kFirstJSApiObjectType;

  static const int kUndefinedOddballKind = 4;
  static const int kNullOddballKind = 3;

  // Constants used by PropertyCallbackInfo to check if we should throw when an
  // error occurs.
  static const int kDontThrow = 0;
  static const int kThrowOnError = 1;
  static const int kInferShouldThrowMode = 2;

  // Soft limit for AdjustAmountofExternalAllocatedMemory. Trigger an
  // incremental GC once the external memory reaches this limit.
  static constexpr size_t kExternalAllocationSoftLimit = 64 * 1024 * 1024;

#ifdef V8_MAP_PACKING
  static const uintptr_t kMapWordMetadataMask = 0xffffULL << 48;
  // The lowest two bits of mapwords are always `0b10`
  static const uintptr_t kMapWordSignature = 0b10;
  // XORing a (non-compressed) map with this mask ensures that the two
  // low-order bits are 0b10. The 0 at the end makes this look like a Smi,
  // although real Smis have all lower 32 bits unset. We only rely on these
  // values passing as Smis in very few places.
  static const int kMapWordXorMask = 0b11;
#endif

  V8_EXPORT static void CheckInitializedImpl(v8::Isolate* isolate);
  V8_INLINE static void CheckInitialized(v8::Isolate* isolate) {
#ifdef V8_ENABLE_CHECKS
    CheckInitializedImpl(isolate);
#endif
  }

  V8_INLINE static constexpr bool HasHeapObjectTag(Address value) {
    return (value & kHeapObjectTagMask) == static_cast<Address>(kHeapObjectTag);
  }

  V8_INLINE static constexpr int SmiValue(Address value) {
    return PlatformSmiTagging::SmiToInt(value);
  }

  V8_INLINE static constexpr Address AddressToSmi(Address value) {
    return (value << (kSmiTagSize + PlatformSmiTagging::kSmiShiftSize)) |
           kSmiTag;
  }

  V8_INLINE static constexpr Address IntToSmi(int value) {
    return AddressToSmi(static_cast<Address>(value));
  }

  template <typename T,
            typename std::enable_if_t<std::is_integral_v<T>>* = nullptr>
  V8_INLINE static constexpr Address IntegralToSmi(T value) {
    return AddressToSmi(static_cast<Address>(value));
  }

  template <typename T,
            typename std::enable_if_t<std::is_integral_v<T>>* = nullptr>
  V8_INLINE static constexpr bool IsValidSmi(T value) {
    return PlatformSmiTagging::IsValidSmi(value);
  }

  template <typename T,
            typename std::enable_if_t<std::is_integral_v<T>>* = nullptr>
  static constexpr std::optional<Address> TryIntegralToSmi(T value) {
    if (V8_LIKELY(PlatformSmiTagging::IsValidSmi(value))) {
      return {AddressToSmi(static_cast<Address>(value))};
    }
    return {};
  }

#if V8_STATIC_ROOTS_BOOL
  V8_INLINE static bool is_identical(Address obj, Tagged_t constant) {
    return static_cast<Tagged_t>(obj) == constant;
  }

  V8_INLINE static bool CheckInstanceMapRange(Address obj, Tagged_t first_map,
                                              Tagged_t last_map) {
    auto map = ReadRawField<Tagged_t>(obj, kHeapObjectMapOffset);
#ifdef V8_MAP_PACKING
    map = UnpackMapWord(map);
#endif
    return map >= first_map && map <= last_map;
  }
#endif

  V8_INLINE static int GetInstanceType(Address obj) {
    Address map = ReadTaggedPointerField(obj, kHeapObjectMapOffset);
#ifdef V8_MAP_PACKING
    map = UnpackMapWord(map);
#endif
    return ReadRawField<uint16_t>(map, kMapInstanceTypeOffset);
  }

  V8_INLINE static Address LoadMap(Address obj) {
    if (!HasHeapObjectTag(obj)) return kNullAddress;
    Address map = ReadTaggedPointerField(obj, kHeapObjectMapOffset);
#ifdef V8_MAP_PACKING
    map = UnpackMapWord(map);
#endif
    return map;
  }

  V8_INLINE static int GetOddballKind(Address obj) {
    return SmiValue(ReadTaggedSignedField(obj, kOddballKindOffset));
  }

  V8_INLINE static bool IsExternalTwoByteString(int instance_type) {
    int representation = (instance_type & kStringRepresentationAndEncodingMask);
    return representation == kExternalTwoByteRepresentationTag;
  }

  V8_INLINE static constexpr bool CanHaveInternalField(int instance_type) {
    static_assert(kJSObjectType + 1 == kFirstJSApiObjectType);
    static_assert(kJSObjectType < kLastJSApiObjectType);
    static_assert(kFirstJSApiObjectType < kLastJSApiObjectType);
    // Check for IsJSObject() || IsJSSpecialApiObject() || IsJSApiObject()
    return instance_type == kJSSpecialApiObjectType ||
           // inlined version of base::IsInRange
           (static_cast<unsigned>(static_cast<unsigned>(instance_type) -
                                  static_cast<unsigned>(kJSObjectType)) <=
            static_cast<unsigned>(kLastJSApiObjectType - kJSObjectType));
  }

  V8_INLINE static uint8_t GetNodeFlag(Address* obj, int shift) {
    uint8_t* addr = reinterpret_cast<uint8_t*>(obj) + kNodeFlagsOffset;
    return *addr & static_cast<uint8_t>(1U << shift);
  }

  V8_INLINE static void UpdateNodeFlag(Address* obj, bool value, int shift) {
    uint8_t* addr = reinterpret_cast<uint8_t*>(obj) + kNodeFlagsOffset;
    uint8_t mask = static_cast<uint8_t>(1U << shift);
    *addr = static_cast<uint8_t>((*addr & ~mask) | (value << shift));
  }

  V8_INLINE static uint8_t GetNodeState(Address* obj) {
    uint8_t* addr = reinterpret_cast<uint8_t*>(obj) + kNodeFlagsOffset;
    return *addr & kNodeStateMask;
  }

  V8_INLINE static void UpdateNodeState(Address* obj, uint8_t value) {
    uint8_t* addr = reinterpret_cast<uint8_t*>(obj) + kNodeFlagsOffset;
    *addr = static_cast<uint8_t>((*addr & ~kNodeStateMask) | value);
  }

  V8_INLINE static void SetEmbedderData(v8::Isolate* isolate, uint32_t slot,
                                        void* data) {
    Address addr = reinterpret_cast<Address>(isolate) +
                   kIsolateEmbedderDataOffset + slot * kApiSystemPointerSize;
    *reinterpret_cast<void**>(addr) = data;
  }

  V8_INLINE static void* GetEmbedderData(const v8::Isolate* isolate,
                                         uint32_t slot) {
    Address addr = reinterpret_cast<Address>(isolate) +
                   kIsolateEmbedderDataOffset + slot * kApiSystemPointerSize;
    return *reinterpret_cast<void* const*>(addr);
  }

  V8_INLINE static void IncrementLongTasksStatsCounter(v8::Isolate* isolate) {
    Address addr =
        reinterpret_cast<Address>(isolate) + kIsolateLongTaskStatsCounterOffset;
    ++(*reinterpret_cast<size_t*>(addr));
  }

  V8_INLINE static Address* GetRootSlot(v8::Isolate* isolate, int index) {
    Address addr = reinterpret_cast<Address>(isolate) + kIsolateRootsOffset +
                   index * kApiSystemPointerSize;
    return reinterpret_cast<Address*>(addr);
  }

  V8_INLINE static Address GetRoot(v8::Isolate* isolate, int index) {
#if V8_STATIC_ROOTS_BOOL
    Address base = *reinterpret_cast<Address*>(
        reinterpret_cast<uintptr_t>(isolate) + kIsolateCageBaseOffset);
    switch (index) {
#define DECOMPRESS_ROOT(name, ...) \
  case k##name##RootIndex:         \
    return base + StaticReadOnlyRoot::k##name;
      EXPORTED_STATIC_ROOTS_PTR_LIST(DECOMPRESS_ROOT)
#undef DECOMPRESS_ROOT
#undef EXPORTED_STATIC_ROOTS_PTR_LIST
      default:
        break;
    }
#endif  // V8_STATIC_ROOTS_BOOL
    return *GetRootSlot(isolate, index);
  }

#ifdef V8_ENABLE_SANDBOX
  V8_INLINE static Address* GetExternalPointerTableBase(v8::Isolate* isolate) {
    Address addr = reinterpret_cast<Address>(isolate) +
                   kIsolateExternalPointerTableOffset +
                   kExternalPointerTableBasePointerOffset;
    return *reinterpret_cast<Address**>(addr);
  }

  V8_INLINE static Address* GetSharedExternalPointerTableBase(
      v8::Isolate* isolate) {
    Address addr = reinterpret_cast<Address>(isolate) +
                   kIsolateSharedExternalPointerTableAddressOffset;
    addr = *reinterpret_cast<Address*>(addr);
    addr += kExternalPointerTableBasePointerOffset;
    return *reinterpret_cast<Address**>(addr);
  }
#endif

  template <typename T>
  V8_INLINE static T ReadRawField(Address heap_object_ptr, int offset) {
    Address addr = heap_object_ptr + offset - kHeapObjectTag;
#ifdef V8_COMPRESS_POINTERS
    if (sizeof(T) > kApiTaggedSize) {
      // TODO(ishell, v8:8875): When pointer compression is enabled 8-byte size
      // fields (external pointers, doubles and BigInt data) are only
      // kTaggedSize aligned so we have to use unaligned pointer friendly way of
      // accessing them in order to avoid undefined behavior in C++ code.
      T r;
      memcpy(&r, reinterpret_cast<void*>(addr), sizeof(T));
      return r;
    }
#endif
    return *reinterpret_cast<const T*>(addr);
  }

  V8_INLINE static Address ReadTaggedPointerField(Address heap_object_ptr,
                                                  int offset) {
#ifdef V8_COMPRESS_POINTERS
    uint32_t value = ReadRawField<uint32_t>(heap_object_ptr, offset);
    Address base = GetPtrComprCageBaseFromOnHeapAddress(heap_object_ptr);
    return base + static_cast<Address>(static_cast<uintptr_t>(value));
#else
    return ReadRawField<Address>(heap_object_ptr, offset);
#endif
  }

  V8_INLINE static Address ReadTaggedSignedField(Address heap_object_ptr,
                                                 int offset) {
#ifdef V8_COMPRESS_POINTERS
    uint32_t value = ReadRawField<uint32_t>(heap_object_ptr, offset);
    return static_cast<Address>(static_cast<uintptr_t>(value));
#else
    return ReadRawField<Address>(heap_object_ptr, offset);
#endif
  }

  V8_INLINE static v8::Isolate* GetIsolateForSandbox(Address obj) {
#ifdef V8_ENABLE_SANDBOX
    return reinterpret_cast<v8::Isolate*>(
        internal::IsolateFromNeverReadOnlySpaceObject(obj));
#else
    // Not used in non-sandbox mode.
    return nullptr;
#endif
  }

  template <ExternalPointerTag tag>
  V8_INLINE static Address ReadExternalPointerField(v8::Isolate* isolate,
                                                    Address heap_object_ptr,
                                                    int offset) {
#ifdef V8_ENABLE_SANDBOX
    static_assert(tag != kExternalPointerNullTag);
    // See src/sandbox/external-pointer-table-inl.h. Logic duplicated here so
    // it can be inlined and doesn't require an additional call.
    Address* table = IsSharedExternalPointerType(tag)
                         ? GetSharedExternalPointerTableBase(isolate)
                         : GetExternalPointerTableBase(isolate);
    internal::ExternalPointerHandle handle =
        ReadRawField<ExternalPointerHandle>(heap_object_ptr, offset);
    uint32_t index = handle >> kExternalPointerIndexShift;
    std::atomic<Address>* ptr =
        reinterpret_cast<std::atomic<Address>*>(&table[index]);
    Address entry = std::atomic_load_explicit(ptr, std::memory_order_relaxed);
    return entry & ~tag;
#else
    return ReadRawField<Address>(heap_object_ptr, offset);
#endif  // V8_ENABLE_SANDBOX
  }

#ifdef V8_COMPRESS_POINTERS
  V8_INLINE static Address GetPtrComprCageBaseFromOnHeapAddress(Address addr) {
    return addr & -static_cast<intptr_t>(kPtrComprCageBaseAlignment);
  }

  V8_INLINE static uint32_t CompressTagged(Address value) {
    return static_cast<uint32_t>(value);
  }

  V8_INLINE static Address DecompressTaggedField(Address heap_object_ptr,
                                                 uint32_t value) {
    Address base = GetPtrComprCageBaseFromOnHeapAddress(heap_object_ptr);
    return base + static_cast<Address>(static_cast<uintptr_t>(value));
  }

#endif  // V8_COMPRESS_POINTERS
};

// Only perform cast check for types derived from v8::Data since
// other types do not implement the Cast method.
template <bool PerformCheck>
struct CastCheck {
  template <class T>
  static void Perform(T* data);
};

template <>
template <class T>
void CastCheck<true>::Perform(T* data) {
  T::Cast(data);
}

template <>
template <class T>
void CastCheck<false>::Perform(T* data) {}

template <class T>
V8_INLINE void PerformCastCheck(T* data) {
  CastCheck<std::is_base_of<Data, T>::value &&
            !std::is_same<Data, std::remove_cv_t<T>>::value>::Perform(data);
}

// A base class for backing stores, which is needed due to vagaries of
// how static casts work with std::shared_ptr.
class BackingStoreBase {};

// The maximum value in enum GarbageCollectionReason, defined in heap.h.
// This is needed for histograms sampling garbage collection reasons.
constexpr int kGarbageCollectionReasonMaxValue = 27;

// Base class for the address block allocator compatible with standard
// containers, which registers its allocated range as strong roots.
class V8_EXPORT StrongRootAllocatorBase {
 public:
  Heap* heap() const { return heap_; }

  friend bool operator==(const StrongRootAllocatorBase& a,
                         const StrongRootAllocatorBase& b) {
    // TODO(pkasting): Replace this body with `= default` after dropping support
    // for old gcc versions.
    return a.heap_ == b.heap_;
  }

 protected:
  explicit StrongRootAllocatorBase(Heap* heap) : heap_(heap) {}
  explicit StrongRootAllocatorBase(LocalHeap* heap);
  explicit StrongRootAllocatorBase(Isolate* isolate);
  explicit StrongRootAllocatorBase(v8::Isolate* isolate);
  explicit StrongRootAllocatorBase(LocalIsolate* isolate);

  // Allocate/deallocate a range of n elements of type internal::Address.
  Address* allocate_impl(size_t n);
  void deallocate_impl(Address* p, size_t n) noexcept;

 private:
  Heap* heap_;
};

// The general version of this template behaves just as std::allocator, with
// the exception that the constructor takes the isolate as parameter. Only
// specialized versions, e.g., internal::StrongRootAllocator<internal::Address>
// and internal::StrongRootAllocator<v8::Local<T>> register the allocated range
// as strong roots.
template <typename T>
class StrongRootAllocator : private std::allocator<T> {
 public:
  using value_type = T;

  template <typename HeapOrIsolateT>
  explicit StrongRootAllocator(HeapOrIsolateT*) {}
  template <typename U>
  StrongRootAllocator(const StrongRootAllocator<U>& other) noexcept {}

  using std::allocator<T>::allocate;
  using std::allocator<T>::deallocate;
};

// TODO(pkasting): Replace with `requires` clauses after dropping support for
// old gcc versions.
template <typename Iterator, typename = void>
inline constexpr bool kHaveIteratorConcept = false;
template <typename Iterator>
inline constexpr bool kHaveIteratorConcept<
    Iterator, std::void_t<typename Iterator::iterator_concept>> = true;

template <typename Iterator, typename = void>
inline constexpr bool kHaveIteratorCategory = false;
template <typename Iterator>
inline constexpr bool kHaveIteratorCategory<
    Iterator, std::void_t<typename Iterator::iterator_category>> = true;

// Helper struct that contains an `iterator_concept` type alias only when either
// `Iterator` or `std::iterator_traits<Iterator>` do.
// Default: no alias.
template <typename Iterator, typename = void>
struct MaybeDefineIteratorConcept {};
// Use `Iterator::iterator_concept` if available.
template <typename Iterator>
struct MaybeDefineIteratorConcept<
    Iterator, std::enable_if_t<kHaveIteratorConcept<Iterator>>> {
  using iterator_concept = typename Iterator::iterator_concept;
};
// Otherwise fall back to `std::iterator_traits<Iterator>` if possible.
template <typename Iterator>
struct MaybeDefineIteratorConcept<
    Iterator, std::enable_if_t<kHaveIteratorCategory<Iterator> &&
                               !kHaveIteratorConcept<Iterator>>> {
  // There seems to be no feature-test macro covering this, so use the
  // presence of `<ranges>` as a crude proxy, since it was added to the
  // standard as part of the Ranges papers.
  // TODO(pkasting): Add this unconditionally after dropping support for old
  // libstdc++ versions.
#if __has_include(<ranges>)
  using iterator_concept =
      typename std::iterator_traits<Iterator>::iterator_concept;
#endif
};

// A class of iterators that wrap some different iterator type.
// If specified, ElementType is the type of element accessed by the wrapper
// iterator; in this case, the actual reference and pointer types of Iterator
// must be convertible to ElementType& and ElementType*, respectively.
template <typename Iterator, typename ElementType = void>
class WrappedIterator : public MaybeDefineIteratorConcept<Iterator> {
 public:
  static_assert(
      std::is_void_v<ElementType> ||
      (std::is_convertible_v<typename std::iterator_traits<Iterator>::pointer,
                             std::add_pointer_t<ElementType>> &&
       std::is_convertible_v<typename std::iterator_traits<Iterator>::reference,
                             std::add_lvalue_reference_t<ElementType>>));

  using difference_type =
      typename std::iterator_traits<Iterator>::difference_type;
  using value_type =
      std::conditional_t<std::is_void_v<ElementType>,
                         typename std::iterator_traits<Iterator>::value_type,
                         ElementType>;
  using pointer =
      std::conditional_t<std::is_void_v<ElementType>,
                         typename std::iterator_traits<Iterator>::pointer,
                         std::add_pointer_t<ElementType>>;
  using reference =
      std::conditional_t<std::is_void_v<ElementType>,
                         typename std::iterator_traits<Iterator>::reference,
                         std::add_lvalue_reference_t<ElementType>>;
  using iterator_catego
"""


```