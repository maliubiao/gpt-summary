Response:
Let's break down the thought process for analyzing this V8 header file.

1. **Identify the Core Purpose:** The filename `code-memory-access.h` immediately suggests this file deals with how V8 accesses memory designated for code execution. The initial comments confirm this, mentioning protection of executable memory.

2. **High-Level Functionality - Access Control:**  The first significant block introduces "scope objects."  This signals a pattern of RAII (Resource Acquisition Is Initialization) used to manage temporary changes in memory access permissions. The different scope types (`CodePageMemoryModificationScopeForDebugging`, `wasm::CodeSpaceWriteScope`, `RwxMemoryWriteScope`, `RwxMemoryWriteScopeForTesting`) indicate various scenarios and levels of access control.

3. **Platform-Specific Considerations (`#if V8_HAS_PKU_JIT_WRITE_PROTECT`):**  The `#ifdef` block points to platform-specific implementations. The mention of "Intel PKU" and "MacOS on ARM64" (later in the `RwxMemoryWriteScope` comments) highlights the need for different approaches to memory protection on different architectures. The macros related to `THREAD_ISOLATION_ALIGN` suggest memory alignment is important for these protection mechanisms.

4. **Core Scope: `RwxMemoryWriteScope`:** This class appears central. The comments explain its behavior on different platforms: toggling between writable and executable permissions. The terms "W^X" (Write XOR Execute) are key here. The reentrancy and thread-safety mentioned are important considerations in a multi-threaded environment like V8. The `IsSupported()` static method suggests feature detection.

5. **Thread Isolation (`ThreadIsolation` class):**  This section delves deeper into memory management. The concepts of "JIT regions," "JIT pages," and "JIT allocations" are introduced. The purpose is to track and validate writes to these regions for Control-Flow Integrity (CFI). The different `JitAllocationType` enum values indicate the kinds of code being managed. The methods like `RegisterJitPage`, `MakeExecutable`, `RegisterJitAllocation`, and `LookupJitAllocation` reveal the lifecycle management of these code regions.

6. **Writable Interfaces (`WritableJitAllocation`, `WritableFreeSpace`, `WritableJitPage`, `WritableJumpTablePair`):** These classes represent *temporary* write access to protected memory regions. They embody the "explicit allowance" mentioned in the initial comments. The `WriteHeaderSlot`, `CopyCode`, `WriteValue` methods within `WritableJitAllocation` demonstrate how data is written to these regions. The `WritableFreeSpace` suggests managing free areas within the code memory. `WritableJitPage` seems to manage a larger page containing allocations. `WritableJumpTablePair` is a specific case for managing jump tables in Wasm.

7. **RAII Pattern Revisited:** The `Writable*` classes utilize the RAII pattern (likely internally using `RwxMemoryWriteScope`) to ensure that write permissions are properly revoked when the object goes out of scope.

8. **Testing and Debugging:** The `RwxMemoryWriteScopeForTesting` class and the debugging-related scope type suggest that testing and debugging are key considerations in the design.

9. **No-Op Scope (`NopRwxMemoryWriteScope`):** This indicates situations where memory protection might be disabled or not needed, providing a consistent interface without actual protection.

10. **Putting it Together - The Flow:**  Code is generated (JIT). Memory is allocated for this code. The `ThreadIsolation` class tracks these allocations. When modifications are needed, a `Writable*` scope object is created, which internally uses `RwxMemoryWriteScope` (or its platform-specific equivalent) to temporarily enable writing. Writes are performed through the `Writable*` object, potentially with CFI validation. Once the `Writable*` object goes out of scope, write protection is re-enabled.

11. **Answering the Specific Questions:** Now, armed with this understanding, it's easier to address the prompt's specific questions:
    * **Functionality:** Summarize the core purpose of managing and controlling access to executable memory, focusing on write protection and CFI.
    * **Torque:** Check the file extension. If it's `.h`, it's a C++ header, not Torque.
    * **JavaScript Relation:**  Connect the memory protection to the security and stability of JavaScript execution in V8. Provide a simple example of how JavaScript code ultimately leads to JITed machine code in this protected memory.
    * **Code Logic Inference:** Focus on the core idea of the `RwxMemoryWriteScope`: entering makes memory writable, exiting makes it executable (or non-writable with PKU). Provide a simple scenario and expected outcome.
    * **Common Programming Errors:**  Highlight errors related to directly writing to code memory without using the provided scopes, emphasizing the security and integrity risks.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the platform-specific details of PKU or ARM64. It's important to step back and identify the *general* principles before diving into the specifics.
* I need to be careful not to confuse the different scope types. It's helpful to visualize the hierarchy: `RwxMemoryWriteScope` is the fundamental building block, and others are specialized or for testing.
* When explaining the JavaScript relation, avoid getting too deep into the JIT compilation process. Keep the example simple and focused on the outcome (executable code in memory).
* For the code logic inference, choose the simplest scenario possible to illustrate the basic functionality of `RwxMemoryWriteScope`.
* When discussing common errors, focus on the *why* – the security and stability implications – rather than just stating the error.

By following this thought process, combining top-down understanding with a detailed look at specific components, a comprehensive and accurate analysis of the header file can be achieved.
这个头文件 `v8/src/common/code-memory-access.h` 的主要功能是 **管理和控制对可执行代码内存的访问**，特别是关注于 **写保护 (write protection)** 和 **控制流完整性 (Control-Flow Integrity, CFI)**。

让我们逐点列举其功能：

**1. 提供用于管理可执行内存写权限的 Scope 类:**

* **`RwxMemoryWriteScope`:**  这是核心的 Scope 类，用于在需要修改可执行内存时临时解除写保护。它在不同的平台上具有不同的实现：
    * **macOS on ARM64 (Apple Silicon):** 使用 `pthread_jit_write_protect_np()` 系统调用在可写和可执行状态之间切换内存页面的权限，实现真正的 W^X (Write XOR Execute)。
    * **Intel PKU (Memory Protection Keys):**  利用 PKU 机制切换保护密钥的权限，主要实现写保护，执行权限无法撤销。
    * **其他平台:**  作为一个空操作 (no-op)。
* **`RwxMemoryWriteScopeForTesting`:**  `RwxMemoryWriteScope` 的非内联版本，主要用于测试目的，解决组件构建中的导出问题。
* **`CodePageMemoryModificationScopeForDebugging`:**  仅在非发布版本中使用，例如用于代码 zapping (可能是指清除或修改代码)。
* **`wasm::CodeSpaceWriteScope`:**  允许访问 WebAssembly 代码空间。
* **`NopRwxMemoryWriteScope`:**  一个空操作版本的 Scope，用于不需要实际进行权限控制的场景。
* **`CFIMetadataWriteScope` 和 `DiscardSealedMemoryScope`:**  根据编译选项，可能是 `RwxMemoryWriteScope` 或 `NopRwxMemoryWriteScope` 的别名，用于管理与 CFI 元数据和密封内存相关的写权限。

**2. `ThreadIsolation` 类:**

这个类负责更精细地管理 JIT (Just-In-Time) 代码区域，实现更严格的内存保护和 CFI：

* **跟踪 JIT 页面和分配:**  记录所有受保护的 JIT 内存区域及其分配情况。
* **验证代码写入:**  在代码创建、重定位等操作时进行验证，确保写入操作是安全的，符合 CFI 的要求。
* **管理 `WritableJitAllocation`:** 提供 `WritableJitAllocation` 对象，所有对可执行内存的写入都应该通过这个对象进行，以便进行 CFI 验证。
* **管理 `WritableJitPage`:**  提供对整个 JIT 页面的可写访问。
* **管理 `WritableFreeSpace`:**  提供对 JIT 页面中空闲空间的可写访问。
* **管理 `WritableJumpTablePair`:**  专门用于管理 WebAssembly 中的跳转表。
* **提供用于注册和注销 JIT 区域的方法:** `RegisterJitPage`, `UnregisterJitPage`, `RegisterJitAllocation`, `UnregisterWasmAllocation` 等。
* **提供查找 JIT 分配的方法:** `LookupJitAllocation`, `LookupJumpTableAllocations`。
* **提供使内存页可执行的方法:** `MakeExecutable`。
* **提供写保护内存的方法:** `WriteProtectMemory`。
* **支持 per-thread 内存权限:**  使用平台特定的机制 (例如 Intel PKU) 实现线程隔离的内存保护。

**3. 用于写入受保护内存的 `Writable*` 类:**

这些类是 RAII (Resource Acquisition Is Initialization) 风格的类，它们在构造时获取对受保护内存的写权限（通常通过 `RwxMemoryWriteScope`），并在析构时释放写权限。这确保了对可执行内存的修改是显式的且受控制的。

* **`WritableJitAllocation`:**  用于写入和修改 JIT 代码分配块。它提供了 `WriteHeaderSlot`, `CopyCode`, `WriteValue` 等方法进行写入操作，并在 DEBUG 模式下强制所有写入都通过此对象进行以确保 CFI 验证。
* **`WritableJitPage`:**  用于写入和管理整个 JIT 页面。
* **`WritableFreeSpace`:**  用于写入 JIT 页面中的空闲空间。
* **`WritableJumpTablePair`:**  用于同时获取一对 WebAssembly 跳转表的可写访问权限。

**4. 其他辅助功能:**

* **对齐宏:**  `THREAD_ISOLATION_ALIGN_SZ`, `THREAD_ISOLATION_ALIGN` 等用于确保内存对齐，这对于某些内存保护机制（如 PKU）至关重要。
* **平台相关的编译条件:**  `V8_HAS_PKU_JIT_WRITE_PROTECT`, `V8_HEAP_USE_PTHREAD_JIT_WRITE_PROTECT` 等用于根据不同的平台启用或禁用特定的功能。
* **用于在 ThreadIsolatedAllocator 中分配内存的 `StlAllocator`。**

**如果 `v8/src/common/code-memory-access.h` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

但根据你提供的文件名，它以 `.h` 结尾，所以它是 **C++ 头文件**，而不是 Torque 文件。

**与 Javascript 的功能关系:**

这个头文件直接关系到 V8 引擎执行 Javascript 代码的安全性和效率。当 V8 编译 Javascript 代码时，它会生成机器码并将其存储在可执行内存中。为了防止恶意代码修改已编译的代码或者利用漏洞跳转到不应该执行的代码区域，V8 使用了这里定义的机制来保护这些内存区域。

例如，考虑以下 Javascript 代码：

```javascript
function add(a, b) {
  return a + b;
}

const sum = add(5, 3);
```

当 V8 执行这段代码时，`add` 函数会被 JIT 编译成机器码。这段机器码会被存储在 V8 分配的可执行内存区域中。`code-memory-access.h` 中定义的 `ThreadIsolation` 和相关的 `Writable*` 类就负责管理这块内存，确保在正常执行期间，这段机器码不会被意外或恶意修改。

**代码逻辑推理:**

假设我们有一个 JIT 页面，并且想要修改其中的一个指令。

**假设输入:**

* `address`: 要修改的指令在 JIT 页面中的地址。
* `size`: 要修改的数据大小。
* `newData`: 要写入的新数据。

**代码逻辑 (简化):**

1. **获取写权限:**  需要创建一个 `WritableJitAllocation` 对象或者 `WritableJitPage` 对象来获取对包含 `address` 的内存区域的写权限。这通常会内部使用 `RwxMemoryWriteScope` 来临时解除写保护。

   ```c++
   v8::internal::WritableJitPage writablePage(page_start_address, page_size);
   // 或者如果已知是某个具体的 allocation
   // v8::internal::WritableJitAllocation writableAllocation = 
   //     v8::internal::ThreadIsolation::LookupJitAllocation(address, size, allocation_type);
   ```

2. **执行写入操作:**  通过 `WritableJitAllocation` 或 `WritableJitPage` 提供的写入方法来修改内存。

   ```c++
   writablePage.CopyData(address - page_start_address, newData, size);
   // 或者
   // writableAllocation.CopyCode(0, newData, size); // 假设从 allocation 的起始位置写入
   ```

3. **释放写权限:**  当 `WritableJitAllocation` 或 `WritableJitPage` 对象析构时，写保护会自动重新启用（通过 `RwxMemoryWriteScope` 的析构函数）。

**假设输出:**

* 位于 `address` 的内存区域现在包含 `newData`。
* 在写入操作期间，内存是可写的。
* 在写入操作完成后，内存恢复为不可写（或可执行但不可写，取决于平台和配置）。

**涉及用户常见的编程错误:**

用户（通常是 V8 引擎的开发者）在处理可执行内存时，常见的错误是 **直接写入可执行内存而没有先获取写权限**。这会导致程序崩溃或出现未定义的行为，因为操作系统会阻止对受保护内存的写入。

**示例:**

假设开发者尝试直接使用指针写入 JIT 代码区域：

```c++
// 错误示例！
char* code_ptr = reinterpret_cast<char*>(jit_code_address);
const char* new_instruction = "\x90"; // NOP 指令
*code_ptr = *new_instruction;
```

这段代码在启用了写保护的情况下会触发操作系统错误（例如，SIGSEGV 信号），因为尝试写入一个没有写权限的内存页。

**正确的做法是使用 `WritableJitAllocation` 或 `WritableJitPage` 来进行修改:**

```c++
v8::internal::WritableJitPage writablePage(page_start_address, page_size);
writablePage.CopyData(address - page_start_address, 
                      reinterpret_cast<const uint8_t*>(new_instruction), 1);
```

或者，如果目标是一个已知的 allocation：

```c++
v8::internal::WritableJitAllocation allocation =
    v8::internal::ThreadIsolation::LookupJitAllocation(address, 1, v8::internal::ThreadIsolation::JitAllocationType::kInstructionStream);
allocation.CopyCode(address - allocation.address(),
                    reinterpret_cast<const uint8_t*>(new_instruction), 1);
```

总结来说，`v8/src/common/code-memory-access.h` 是 V8 引擎中一个至关重要的头文件，它定义了用于安全地访问和修改可执行代码内存的机制，是实现代码保护和 CFI 的基础。开发者必须遵循其定义的规范，使用提供的 Scope 类和 `Writable*` 类来操作可执行内存，以避免安全漏洞和程序错误。

### 提示词
```
这是目录为v8/src/common/code-memory-access.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/common/code-memory-access.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMMON_CODE_MEMORY_ACCESS_H_
#define V8_COMMON_CODE_MEMORY_ACCESS_H_

#include <map>
#include <optional>

#include "include/v8-internal.h"
#include "include/v8-platform.h"
#include "src/base/build_config.h"
#include "src/base/macros.h"
#include "src/base/memory.h"
#include "src/base/platform/mutex.h"
#include "src/common/globals.h"

namespace v8 {
namespace internal {

// We protect writes to executable memory in some configurations and whenever
// we write to it, we need to explicitely allow it first.
//
// For this purposed, there are a few scope objects with different semantics:
//
// - CodePageMemoryModificationScopeForDebugging:
//     A scope only used in non-release builds, e.g. for code zapping.
// - wasm::CodeSpaceWriteScope:
//     Allows access to Wasm code
//
// - RwxMemoryWriteScope:
//     A scope that uses per-thread permissions to allow access. Should not be
//     used directly, but rather is the implementation of one of the above.
// - RwxMemoryWriteScopeForTesting:
//     Same, but for use in testing.

class RwxMemoryWriteScopeForTesting;
namespace wasm {
class CodeSpaceWriteScope;
}

#if V8_HAS_PKU_JIT_WRITE_PROTECT

// Alignment macros.
// Adapted from partition_allocator/thread_isolation/alignment.h.

// Page size is not a compile time constant, but we need it for alignment and
// padding of our global memory.
// We use the maximum expected value here (currently x64 only) and test in
// ThreadIsolation::Initialize() that it's a multiple of the real pagesize.
#define THREAD_ISOLATION_ALIGN_SZ 0x1000
#define THREAD_ISOLATION_ALIGN alignas(THREAD_ISOLATION_ALIGN_SZ)
#define THREAD_ISOLATION_ALIGN_OFFSET_MASK (THREAD_ISOLATION_ALIGN_SZ - 1)
#define THREAD_ISOLATION_FILL_PAGE_SZ(size)          \
  ((THREAD_ISOLATION_ALIGN_SZ -                      \
    ((size) & THREAD_ISOLATION_ALIGN_OFFSET_MASK)) % \
   THREAD_ISOLATION_ALIGN_SZ)

#else  // V8_HAS_PKU_JIT_WRITE_PROTECT

#define THREAD_ISOLATION_ALIGN_SZ 0
#define THREAD_ISOLATION_ALIGN
#define THREAD_ISOLATION_FILL_PAGE_SZ(size) 0

#endif  // V8_HAS_PKU_JIT_WRITE_PROTECT

// This scope is a wrapper for APRR/MAP_JIT machinery on MacOS on ARM64
// ("Apple M1"/Apple Silicon) or Intel PKU (aka. memory protection keys)
// with respective low-level semantics.
//
// The semantics on MacOS on ARM64 is the following:
// The scope switches permissions between writable and executable for all the
// pages allocated with RWX permissions. Only current thread is affected.
// This achieves "real" W^X and it's fast (see pthread_jit_write_protect_np()
// for details).
// By default it is assumed that the state is executable.
// It's also assumed that the process has the "com.apple.security.cs.allow-jit"
// entitlement.
//
// The semantics on Intel with PKU support is the following:
// When Intel PKU is available, the scope switches the protection key's
// permission between writable and not writable. The executable permission
// cannot be retracted with PKU. That is, this "only" achieves write
// protection, but is similarly thread-local and fast.
//
// On other platforms the scope is a no-op and thus it's allowed to be used.
//
// The scope is reentrant and thread safe.
class V8_NODISCARD RwxMemoryWriteScope {
 public:
  // The comment argument is used only for ensuring that explanation about why
  // the scope is needed is given at particular use case.
  V8_INLINE explicit RwxMemoryWriteScope(const char* comment);
  V8_INLINE ~RwxMemoryWriteScope();

  // Disable copy constructor and copy-assignment operator, since this manages
  // a resource and implicit copying of the scope can yield surprising errors.
  RwxMemoryWriteScope(const RwxMemoryWriteScope&) = delete;
  RwxMemoryWriteScope& operator=(const RwxMemoryWriteScope&) = delete;

  // Returns true if current configuration supports fast write-protection of
  // executable pages.
  V8_INLINE static bool IsSupported();

#if V8_HAS_PKU_JIT_WRITE_PROTECT
  static int memory_protection_key();

  static bool IsPKUWritable();

  // Linux resets key's permissions to kDisableAccess before executing signal
  // handlers. If the handler requires access to code page bodies it should take
  // care of changing permissions to the default state (kDisableWrite).
  static V8_EXPORT void SetDefaultPermissionsForSignalHandler();
#endif  // V8_HAS_PKU_JIT_WRITE_PROTECT

 private:
  friend class RwxMemoryWriteScopeForTesting;
  friend class wasm::CodeSpaceWriteScope;

  // {SetWritable} and {SetExecutable} implicitly enters/exits the scope.
  // These methods are exposed only for the purpose of implementing other
  // scope classes that affect executable pages permissions.
  V8_INLINE static void SetWritable();
  V8_INLINE static void SetExecutable();
};

class WritableJitPage;
class WritableJitAllocation;
class WritableJumpTablePair;

// The ThreadIsolation API is used to protect executable memory using per-thread
// memory permissions and perform validation for any writes into it.
//
// It keeps metadata about all JIT regions in write-protected memory and will
// use it to validate that the writes are safe from a CFI perspective.
// Its tasks are:
// * track JIT pages and allocations and check for validity
// * check for dangling pointers on the shadow stack (not implemented)
// * validate code writes like code creation, relocation, etc. (not implemented)
class V8_EXPORT ThreadIsolation {
 public:
  static bool Enabled();
  static void Initialize(ThreadIsolatedAllocator* allocator);

  enum class JitAllocationType {
    kInstructionStream,
    kWasmCode,
    kWasmJumpTable,
    kWasmFarJumpTable,
    kWasmLazyCompileTable,
  };

  // Register a new JIT region.
  static void RegisterJitPage(Address address, size_t size);
  // Unregister a JIT region that is about to be unmpapped.
  static void UnregisterJitPage(Address address, size_t size);
  // Make a page executable. Needs to be registered first. Should only be called
  // if Enabled() is true.
  V8_NODISCARD static bool MakeExecutable(Address address, size_t size);

  // Register a new JIT allocation for tracking and return a writable reference
  // to it. All writes should go through the returned WritableJitAllocation
  // object since it will perform additional validation required for CFI.
  static WritableJitAllocation RegisterJitAllocation(
      Address addr, size_t size, JitAllocationType type,
      bool enforce_write_api = false);
  // TODO(sroettger): remove this overwrite and use RegisterJitAllocation
  // instead.
  static WritableJitAllocation RegisterInstructionStreamAllocation(
      Address addr, size_t size, bool enforce_write_api = false);
  // Register multiple consecutive allocations together.
  static void RegisterJitAllocations(Address start,
                                     const std::vector<size_t>& sizes,
                                     JitAllocationType type);

  // Get writable reference to a previously registered allocation. All writes to
  // executable memory need to go through one of these Writable* objects since
  // this is where we perform CFI validation.
  // If enforce_write_api is set, all writes to JIT memory need to go through
  // this object.
  static WritableJitAllocation LookupJitAllocation(
      Address addr, size_t size, JitAllocationType type,
      bool enforce_write_api = false);
  // A special case of LookupJitAllocation since in Wasm, we sometimes have to
  // unlock two allocations (jump tables) together.
  static WritableJumpTablePair LookupJumpTableAllocations(
      Address jump_table_address, size_t jump_table_size,
      Address far_jump_table_address, size_t far_jump_table_size);
  // Unlock a larger region. This allowsV us to lookup allocations in this
  // region more quickly without switching the write permissions all the time.
  static WritableJitPage LookupWritableJitPage(Address addr, size_t size);

  static void UnregisterWasmAllocation(Address addr, size_t size);

  // Check for a potential dead lock in case we want to lookup the jit
  // allocation from inside a signal handler.
  static bool CanLookupStartOfJitAllocationAt(Address inner_pointer);
  static std::optional<Address> StartOfJitAllocationAt(Address inner_pointer);

  // Write-protect a given range of memory. Address and size need to be page
  // aligned.
  V8_NODISCARD static bool WriteProtectMemory(
      Address addr, size_t size, PageAllocator::Permission page_permissions);

  static void RegisterJitAllocationForTesting(Address obj, size_t size);
  static void UnregisterJitAllocationForTesting(Address addr, size_t size);

#if V8_HAS_PKU_JIT_WRITE_PROTECT
  static int pkey() { return trusted_data_.pkey; }
  static bool PkeyIsAvailable() { return trusted_data_.pkey != -1; }
#endif

#if DEBUG
  static bool initialized() { return trusted_data_.initialized; }
  static void CheckTrackedMemoryEmpty();
#endif

  // A std::allocator implementation that wraps the ThreadIsolated allocator.
  // This is needed to create STL containers backed by ThreadIsolated memory.
  template <class T>
  struct StlAllocator {
    typedef T value_type;

    StlAllocator() = default;
    template <class U>
    explicit StlAllocator(const StlAllocator<U>&) noexcept {}

    value_type* allocate(size_t n) {
      if (Enabled()) {
        return static_cast<value_type*>(
            ThreadIsolation::allocator()->Allocate(n * sizeof(value_type)));
      } else {
        return static_cast<value_type*>(::operator new(n * sizeof(T)));
      }
    }

    void deallocate(value_type* ptr, size_t n) {
      if (Enabled()) {
        ThreadIsolation::allocator()->Free(ptr);
      } else {
        ::operator delete(ptr);
      }
    }
  };

  class JitAllocation {
   public:
    explicit JitAllocation(size_t size, JitAllocationType type)
        : size_(size), type_(type) {}
    size_t Size() const { return size_; }
    JitAllocationType Type() const { return type_; }

   private:
    size_t size_;
    JitAllocationType type_;
  };

  class JitPage;

  // All accesses to the JitPage go through the JitPageReference class, which
  // will guard it against concurrent access.
  class V8_EXPORT JitPageReference {
   public:
    JitPageReference(class JitPage* page, Address address);
    JitPageReference(JitPageReference&&) V8_NOEXCEPT = default;
    JitPageReference(const JitPageReference&) = delete;
    JitPageReference& operator=(const JitPageReference&) = delete;

    base::Address Address() const { return address_; }
    size_t Size() const;
    base::Address End() const { return Address() + Size(); }
    JitAllocation& RegisterAllocation(base::Address addr, size_t size,
                                      JitAllocationType type);
    JitAllocation& LookupAllocation(base::Address addr, size_t size,
                                    JitAllocationType type);
    bool Contains(base::Address addr, size_t size,
                  JitAllocationType type) const;
    void UnregisterAllocation(base::Address addr);
    void UnregisterAllocationsExcept(base::Address start, size_t size,
                                     const std::vector<base::Address>& addr);
    void UnregisterRange(base::Address addr, size_t size);

    base::Address StartOfAllocationAt(base::Address inner_pointer);
    std::pair<base::Address, JitAllocation&> AllocationContaining(
        base::Address addr);

    bool Empty() const { return jit_page_->allocations_.empty(); }
    void Shrink(class JitPage* tail);
    void Expand(size_t offset);
    void Merge(JitPageReference& next);
    class JitPage* JitPage() { return jit_page_; }

   private:
    base::MutexGuard page_lock_;
    class JitPage* jit_page_;
    // We get the address from the key of the map when we do a JitPage lookup.
    // We can save some memory by storing it as part of the reference instead.
    base::Address address_;
  };

  class JitPage {
   public:
    explicit JitPage(size_t size) : size_(size) {}
    ~JitPage();

   private:
    base::Mutex mutex_;
    typedef std::map<Address, JitAllocation, std::less<Address>,
                     StlAllocator<std::pair<const Address, JitAllocation>>>
        AllocationMap;
    AllocationMap allocations_;
    size_t size_;

    friend class JitPageReference;
    // Allow CanLookupStartOfJitAllocationAt to check if the mutex is locked.
    friend bool ThreadIsolation::CanLookupStartOfJitAllocationAt(Address);
  };

 private:
  static ThreadIsolatedAllocator* allocator() {
    return trusted_data_.allocator;
  }

  // We store pointers in the map since we want to use the entries without
  // keeping the map locked.
  typedef std::map<Address, JitPage*, std::less<Address>,
                   StlAllocator<std::pair<const Address, JitPage*>>>
      JitPageMap;

  // The TrustedData needs to be page aligned so that we can protect it using
  // per-thread memory permissions (e.g. pkeys on x64).
  struct THREAD_ISOLATION_ALIGN TrustedData {
    ThreadIsolatedAllocator* allocator = nullptr;

#if V8_HAS_PKU_JIT_WRITE_PROTECT
    int pkey = -1;
#endif

    base::Mutex* jit_pages_mutex_;
    JitPageMap* jit_pages_;

#if DEBUG
    bool initialized = false;
#endif
  };

  static struct TrustedData trusted_data_;

  static_assert(THREAD_ISOLATION_ALIGN_SZ == 0 ||
                sizeof(trusted_data_) == THREAD_ISOLATION_ALIGN_SZ);

  // Allocate and construct C++ objects using memory backed by the
  // ThreadIsolated allocator.
  template <typename T, typename... Args>
  static void ConstructNew(T** ptr, Args&&... args);
  template <typename T>
  static void Delete(T* ptr);

  // Lookup a JitPage that spans a given range. Note that JitPages are not
  // required to align with OS pages. There are no minimum size requirements and
  // we can split and merge them under the hood for performance optimizations.
  // IOW, the returned JitPage is guaranteed to span the given range, but
  // doesn't need to be the exact previously registered JitPage.
  static JitPageReference LookupJitPage(Address addr, size_t size);
  static JitPageReference LookupJitPageLocked(Address addr, size_t size);
  static std::optional<JitPageReference> TryLookupJitPage(Address addr,
                                                          size_t size);
  // The caller needs to hold a lock of the jit_pages_mutex_
  static std::optional<JitPageReference> TryLookupJitPageLocked(Address addr,
                                                                size_t size);
  static JitPageReference SplitJitPageLocked(Address addr, size_t size);
  static JitPageReference SplitJitPage(Address addr, size_t size);
  static std::pair<JitPageReference, JitPageReference> SplitJitPages(
      Address addr1, size_t size1, Address addr2, size_t size2);

  template <class T>
  friend struct StlAllocator;
  friend class WritableJitPage;
  friend class WritableJitAllocation;
  friend class WritableJumpTablePair;
};

// A scope class that temporarily makes the JitAllocation writable. All writes
// to executable memory should go through this object since it adds validation
// that the writes are safe for CFI.
class WritableJitAllocation {
 public:
  WritableJitAllocation(const WritableJitAllocation&) = delete;
  WritableJitAllocation& operator=(const WritableJitAllocation&) = delete;
  V8_INLINE ~WritableJitAllocation();

  static WritableJitAllocation ForInstructionStream(
      Tagged<InstructionStream> istream);

  // WritableJitAllocations are used during reloc iteration. But in some
  // cases, we relocate code off-heap, e.g. when growing AssemblerBuffers.
  // This function creates a WritableJitAllocation that doesn't unlock the
  // executable memory.
  static V8_INLINE WritableJitAllocation ForNonExecutableMemory(
      Address addr, size_t size, ThreadIsolation::JitAllocationType type);

  // Writes a header slot either as a primitive or as a Tagged value.
  // Important: this function will not trigger a write barrier by itself,
  // since we want to keep the code running with write access to executable
  // memory to a minimum. You should trigger the write barriers after this
  // function goes out of scope.
  template <typename T, size_t offset>
  V8_INLINE void WriteHeaderSlot(T value);
  template <typename T, size_t offset>
  V8_INLINE void WriteHeaderSlot(Tagged<T> value, ReleaseStoreTag);
  template <typename T, size_t offset>
  V8_INLINE void WriteHeaderSlot(Tagged<T> value, RelaxedStoreTag);
  template <typename T, size_t offset>
  V8_INLINE void WriteProtectedPointerHeaderSlot(Tagged<T> value,
                                                 ReleaseStoreTag);
  template <typename T, size_t offset>
  V8_INLINE void WriteProtectedPointerHeaderSlot(Tagged<T> value,
                                                 RelaxedStoreTag);
  template <typename T>
  V8_INLINE void WriteHeaderSlot(Address address, T value, RelaxedStoreTag);

  // CopyCode and CopyData have the same implementation at the moment, but
  // they will diverge once we implement validation.
  V8_INLINE void CopyCode(size_t dst_offset, const uint8_t* src,
                          size_t num_bytes);
  V8_INLINE void CopyData(size_t dst_offset, const uint8_t* src,
                          size_t num_bytes);

  template <typename T>
  V8_INLINE void WriteUnalignedValue(Address address, T value);
  template <typename T>
  V8_INLINE void WriteValue(Address address, T value);
  template <typename T>
  V8_INLINE void WriteValue(Address address, T value, RelaxedStoreTag);

  V8_INLINE void ClearBytes(size_t offset, size_t len);

  Address address() const { return address_; }
  size_t size() const { return allocation_.Size(); }

 private:
  enum class JitAllocationSource {
    kRegister,
    kLookup,
  };
  V8_INLINE WritableJitAllocation(Address addr, size_t size,
                                  ThreadIsolation::JitAllocationType type,
                                  JitAllocationSource source,
                                  bool enforce_write_api = false);
  // Used for non-executable memory.
  V8_INLINE WritableJitAllocation(Address addr, size_t size,
                                  ThreadIsolation::JitAllocationType type);

  ThreadIsolation::JitPageReference& page_ref() { return page_ref_.value(); }

  // In DEBUG mode, we only make RWX memory writable during the write operations
  // themselves to ensure that all writes go through this object.
  // This function returns a write scope that can be used for these writes.
  V8_INLINE std::optional<RwxMemoryWriteScope> WriteScopeForApiEnforcement()
      const;

  const Address address_;
  // TODO(sroettger): we can move the memory write scopes into the Write*
  // functions in debug builds. This would allow us to ensure that all writes
  // go through this object.
  // The scope and page reference are optional in case we're creating a
  // WritableJitAllocation for off-heap memory. See ForNonExecutableMemory
  // above.
  std::optional<RwxMemoryWriteScope> write_scope_;
  std::optional<ThreadIsolation::JitPageReference> page_ref_;
  const ThreadIsolation::JitAllocation allocation_;
  bool enforce_write_api_ = false;

  friend class ThreadIsolation;
  friend class WritableJitPage;
  friend class WritableJumpTablePair;
};

// Similar to the WritableJitAllocation, all writes to free space should go
// through this object since it adds validation that the writes are safe for
// CFI.
// For convenience, it can also be used for writes to non-executable memory for
// which it will skip the CFI checks.
class WritableFreeSpace {
 public:
  // This function can be used to create a WritableFreeSpace object for
  // non-executable memory only, i.e. it won't perform CFI validation and
  // doesn't unlock the code space.
  // For executable memory, use the WritableJitPage::FreeRange function.
  static V8_INLINE WritableFreeSpace ForNonExecutableMemory(base::Address addr,
                                                            size_t size);

  WritableFreeSpace(const WritableFreeSpace&) = delete;
  WritableFreeSpace& operator=(const WritableFreeSpace&) = delete;
  V8_INLINE ~WritableFreeSpace();

  template <typename T, size_t offset>
  V8_INLINE void WriteHeaderSlot(Tagged<T> value, RelaxedStoreTag) const;
  template <size_t offset>
  void ClearTagged(size_t count) const;

  base::Address Address() const { return address_; }
  int Size() const { return size_; }
  bool Executable() const { return executable_; }

 private:
  WritableFreeSpace(base::Address addr, size_t size, bool executable);

  const base::Address address_;
  const int size_;
  const bool executable_;

  friend class WritableJitPage;
};

extern template void WritableFreeSpace::ClearTagged<kTaggedSize>(
    size_t count) const;
extern template void WritableFreeSpace::ClearTagged<2 * kTaggedSize>(
    size_t count) const;

class WritableJitPage {
 public:
  V8_INLINE WritableJitPage(Address addr, size_t size);

  WritableJitPage(const WritableJitPage&) = delete;
  WritableJitPage& operator=(const WritableJitPage&) = delete;
  V8_INLINE ~WritableJitPage();
  friend class ThreadIsolation;

  V8_INLINE WritableJitAllocation LookupAllocationContaining(Address addr);

  V8_INLINE WritableFreeSpace FreeRange(Address addr, size_t size);

  bool Empty() const { return page_ref_.Empty(); }

 private:
  RwxMemoryWriteScope write_scope_;
  ThreadIsolation::JitPageReference page_ref_;
};

class WritableJumpTablePair {
 public:
  RwxMemoryWriteScope& write_scope() { return write_scope_; }

  WritableJitAllocation& jump_table() { return writable_jump_table_; }
  WritableJitAllocation& far_jump_table() { return writable_far_jump_table_; }

  WritableJumpTablePair(const WritableJumpTablePair&) = delete;
  WritableJumpTablePair& operator=(const WritableJumpTablePair&) = delete;

  V8_EXPORT_PRIVATE static WritableJumpTablePair ForTesting(
      Address jump_table_address, size_t jump_table_size,
      Address far_jump_table_address, size_t far_jump_table_size);

 private:
  V8_INLINE WritableJumpTablePair(Address jump_table_address,
                                  size_t jump_table_size,
                                  Address far_jump_table_address,
                                  size_t far_jump_table_size);

  // This constructor is only used for testing.
  struct ForTestingTag {};
  WritableJumpTablePair(Address jump_table_address, size_t jump_table_size,
                        Address far_jump_table_address,
                        size_t far_jump_table_size, ForTestingTag);

  RwxMemoryWriteScope write_scope_;
  std::optional<std::pair<ThreadIsolation::JitPageReference,
                          ThreadIsolation::JitPageReference>>
      jump_table_pages_;

  WritableJitAllocation writable_jump_table_;
  WritableJitAllocation writable_far_jump_table_;

  friend class ThreadIsolation;
};

template <class T>
bool operator==(const ThreadIsolation::StlAllocator<T>&,
                const ThreadIsolation::StlAllocator<T>&) {
  return true;
}

template <class T>
bool operator!=(const ThreadIsolation::StlAllocator<T>&,
                const ThreadIsolation::StlAllocator<T>&) {
  return false;
}

// This class is a no-op version of the RwxMemoryWriteScope class above.
// It's used as a target type for other scope type definitions when a no-op
// semantics is required.
class V8_NODISCARD V8_ALLOW_UNUSED NopRwxMemoryWriteScope final {
 public:
  V8_INLINE NopRwxMemoryWriteScope() = default;
  V8_INLINE explicit NopRwxMemoryWriteScope(const char* comment) {
    // Define a constructor to avoid unused variable warnings.
  }
};

// Same as the RwxMemoryWriteScope but without inlining the code.
// This is a workaround for component build issue (crbug/1316800), when
// a thread_local value can't be properly exported.
class V8_NODISCARD RwxMemoryWriteScopeForTesting final
    : public RwxMemoryWriteScope {
 public:
  V8_EXPORT_PRIVATE RwxMemoryWriteScopeForTesting();
  V8_EXPORT_PRIVATE ~RwxMemoryWriteScopeForTesting();

  // Disable copy constructor and copy-assignment operator, since this manages
  // a resource and implicit copying of the scope can yield surprising errors.
  RwxMemoryWriteScopeForTesting(const RwxMemoryWriteScopeForTesting&) = delete;
  RwxMemoryWriteScopeForTesting& operator=(
      const RwxMemoryWriteScopeForTesting&) = delete;
};

#if V8_HEAP_USE_PTHREAD_JIT_WRITE_PROTECT
// Metadata are not protected yet with PTHREAD_JIT_WRITE_PROTECT
using CFIMetadataWriteScope = NopRwxMemoryWriteScope;
#else
using CFIMetadataWriteScope = RwxMemoryWriteScope;
#endif

#ifdef V8_ENABLE_MEMORY_SEALING
using DiscardSealedMemoryScope = RwxMemoryWriteScope;
#else
using DiscardSealedMemoryScope = NopRwxMemoryWriteScope;
#endif

}  // namespace internal
}  // namespace v8

#endif  // V8_COMMON_CODE_MEMORY_ACCESS_H_
```