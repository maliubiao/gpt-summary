Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Understand the Goal:** The core purpose of a unit test file is to verify the functionality of a specific unit of code. In this case, the filename `stack-unittest.cc` strongly suggests it's testing the `Stack` class in `src/heap/base/stack.h`. The `cppgc` namespace also hints at garbage collection functionality.

2. **High-Level Structure:**  A typical C++ unit test file using Google Test (`gtest`) has a common structure:
    * Includes: Necessary headers.
    * Namespaces: Organizing code.
    * Test Fixture (optional but good practice):  A class inheriting from `::testing::Test` to set up common test conditions.
    * Individual Test Cases:  Functions using `TEST_F` (for fixtures) or `TEST` (for standalone tests) macros.
    * Assertions: Macros like `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ` to verify expected outcomes.

3. **Examine the Includes:**
    * `"src/heap/base/stack.h"`: Confirms the focus is on the `Stack` class.
    * `<memory>`:  Likely for `std::unique_ptr`.
    * `<ostream>`: Potentially for debugging output (though not directly used in the visible code).
    * `"include/v8config.h"`: V8-specific configuration.
    * `"testing/gtest/include/gtest/gtest.h"`: The Google Test framework.
    * Platform-specific includes (`xmmintrin.h`): Indicates tests might have platform-dependent aspects.

4. **Analyze the Test Fixture:** The `GCStackTest` class is a test fixture.
    * It creates a `std::unique_ptr<Stack>` named `stack_`.
    * `stack_->SetStackStart()`:  Suggests the `Stack` class needs to be initialized with the current stack's starting point.
    * `GetStack()`:  A simple accessor method.

5. **Deconstruct Individual Tests:** Go through each `TEST_F` or `TEST` case. For each:
    * **Name:**  The test name (e.g., `IsOnStackForStackValue`) gives a strong indication of what's being tested.
    * **Setup:** What objects or variables are created?
    * **Action:** What methods of the `Stack` class are being called?
    * **Assertion:** What is the expected outcome verified by `EXPECT_*` macros?

6. **`IsOnStackForStackValue`:**
    * Creates a local variable `dummy`.
    * Calls `GetStack()->IsOnStack(&dummy)`.
    * Expects the result to be `true`, meaning the `Stack` object can identify stack-allocated variables.

7. **`IsOnStackForHeapValue`:**
    * Creates a heap-allocated `int` using `std::make_unique`.
    * Calls `GetStack()->IsOnStack(dummy.get())`.
    * Expects `false`, meaning it correctly identifies heap-allocated memory.

8. **`IteratePointersFindsOnStackValue` and `IteratePointersFindsOnStackValuePotentiallyUnaligned`:**
    * Introduce the `StackScanner` class, a `StackVisitor`. This hints at a mechanism to iterate through potential pointers on the stack.
    * The `StackScanner` has a `needle()` (a pointer to heap memory) and a `found_` flag. The `VisitPointer` method checks if the visited address matches the `needle`.
    * These tests create a `StackScanner`, store the `needle` in a volatile temporary (to prevent compiler optimization), and then call `GetStack()->IteratePointersForTesting(scanner.get())`.
    * The expectation is `scanner->found()` will be `true`, indicating the iteration found the pointer on the stack. The "potentially unaligned" version introduces a local `char` variable to possibly shift stack alignment.

9. **`IteratePointersFindsParameterNesting*`:**
    * Introduce `RecursivelyPassOnParameter` and `RecursivelyPassOnParameterImpl`. These functions are designed to pass a pointer (`parameter`) through a series of function calls with different parameter positions. The `V8_NOINLINE` attribute prevents inlining.
    * The goal is to verify that the stack scanning mechanism can find pointers passed as function arguments at various depths in the call stack.
    * Each `IteratePointersFindsParameterNesting` test calls `RecursivelyPassOnParameter` with a different nesting level (0 to 8).

10. **`IteratePointersFindsCalleeSavedRegisters` and `IteratePointersFindsCalleeSavedXMMRegisters`:**
    * These tests are more complex and involve inline assembly.
    * The `IteratePointersNoMangling` function is used as a target for the assembly call.
    * The tests aim to verify that the stack scanning correctly identifies pointers stored in callee-saved registers (registers that a function must preserve).
    * They move the `needle` into a callee-saved register and then trigger the stack scan.

11. **`StackAlignment`:**
    * Uses a `CheckStackAlignmentVisitor`.
    * The `VisitPointer` method attempts to load a vector using `_mm_load_ps`. This instruction requires the stack to be 16-byte aligned.
    * This test verifies that the stack remains properly aligned during the stack scanning process.

12. **Address Specific Questions:**  After understanding the tests, address the specific prompts:
    * **Functionality:** Summarize the purpose of the tests (verifying stack scanning for garbage collection).
    * **`.tq` Extension:** Explain that `.tq` indicates Torque code, and this file is C++, so it's not Torque.
    * **JavaScript Relation:** Explain the connection to garbage collection in JavaScript and provide a simple JavaScript example.
    * **Code Logic Inference:** Choose a simpler test case (like `IsOnStackForStackValue`) and demonstrate input/output.
    * **Common Programming Errors:** Explain how incorrect stack scanning can lead to dangling pointers, using a JavaScript analogy.

By following these steps, we can systematically analyze the C++ unit test file and extract its key functionalities, purpose, and potential connections to other parts of the system. The key is to break down the code into smaller, manageable parts and understand the intent behind each test case.
这个 C++ 源代码文件 `v8/test/unittests/heap/cppgc/stack-unittest.cc` 是 **V8 引擎** 中用于测试 **cppgc** (C++ garbage collector) 模块中 **stack** 相关功能的单元测试。

**功能概括:**

这个文件包含了一系列单元测试，用于验证 `src/heap/base/stack.h` 中 `Stack` 和 `StackVisitor` 类的正确性。  这些测试主要关注以下几个方面：

1. **判断内存地址是否在栈上 (`IsOnStack`):**  测试 `Stack::IsOnStack()` 方法能否正确判断一个给定的内存地址是否属于当前线程的栈空间。

2. **遍历栈上的指针 (`IteratePointersForTesting`):** 测试 `Stack::IteratePointersForTesting()` 方法及其与 `StackVisitor` 的协作。该方法用于遍历栈上的可能指针，并调用 `StackVisitor::VisitPointer()` 对每个找到的指针进行处理。

3. **查找栈上的特定值:**  测试在栈上放置特定的值（通常是堆上分配对象的指针），然后使用 `IteratePointersForTesting` 方法和 `StackVisitor` 来查找这些值。这模拟了垃圾回收器在扫描栈时查找活动对象引用的过程。

4. **处理嵌套调用和参数传递:**  通过递归调用函数并传递参数，测试栈扫描器是否能在复杂的调用栈结构中正确找到作为参数传递的指针。

5. **查找保存在寄存器中的值:**  通过内联汇编将指针值存储到 callee-saved 寄存器中，然后测试栈扫描器是否能识别出这些寄存器中保存的指针。这对于确保垃圾回收器能正确识别所有可能的对象引用至关重要。

6. **栈对齐 (`StackAlignment`):** 检查在栈遍历过程中栈是否保持正确的对齐方式。这对于一些需要特定对齐的指令（例如 SIMD 指令）非常重要。

**关于文件扩展名 `.tq` 和 JavaScript 的关系:**

* **如果 `v8/test/unittests/heap/cppgc/stack-unittest.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  当前的文件名是 `.cc`，这意味着它是 **C++ 源代码**。 Torque 文件通常用于定义 V8 内部的内置函数和类型系统。

* **如果它与 javascript 的功能有关系，请用 javascript 举例说明。**

   是的，这个文件与 JavaScript 的功能有直接关系，因为它测试的是垃圾回收机制的核心组件之一：**栈扫描**。  JavaScript 引擎使用垃圾回收来自动管理内存。当执行 JavaScript 代码时，对象会被创建并存储在堆上。为了防止不再使用的对象占用内存，垃圾回收器会定期运行，找出哪些对象仍然被程序引用，哪些可以被回收。

   栈是存储局部变量和函数调用信息的关键区域。  当 JavaScript 代码执行时，变量和对象引用可能会存储在栈上。  因此，垃圾回收器需要能够扫描栈，找出所有指向堆上存活对象的指针。

   **JavaScript 示例:**

   ```javascript
   function foo() {
     let obj = { value: 10 }; // obj 指向堆上的一个对象
     bar(obj);
   }

   function bar(ref) {
     // 在 bar 函数的栈帧中，ref 变量保存着对堆上对象的引用
     console.log(ref.value);
   }

   foo();
   ```

   在这个例子中，当 `bar` 函数被调用时，变量 `ref` 会被存储在栈上，它指向了 `foo` 函数中创建的 `obj` 对象。  `stack-unittest.cc` 中的测试就是为了确保 cppgc 的栈扫描器能够正确地找到像 `ref` 这样的指针，从而确保 `obj` 对象不会被错误地回收。

**代码逻辑推理，假设输入与输出:**

以 `TEST_F(GCStackTest, IsOnStackForStackValue)` 为例：

* **假设输入:**  一个指向栈上局部变量 `dummy` 的指针的地址。
* **代码逻辑:** `GetStack()->IsOnStack(&dummy)` 调用 `Stack::IsOnStack()` 方法，并传入 `dummy` 的地址。 `Stack::IsOnStack()` 内部会判断该地址是否位于当前线程的栈空间内。
* **预期输出:** `EXPECT_TRUE()` 断言该方法返回 `true`，因为 `dummy` 是一个栈上变量。

以 `TEST_F(GCStackTest, IteratePointersFindsOnStackValue)` 为例：

* **假设输入:**  一个指向堆上分配的 `int` 的指针 `scanner->needle()`，以及一个 `StackScanner` 对象。
* **代码逻辑:**
    1. `scanner->needle()` 获取堆上 `int` 的地址。
    2. 将该地址赋值给 `volatile int* tmp`，使用 `volatile` 关键字防止编译器优化掉这个赋值，确保指针仍然存在于栈上或寄存器中。
    3. `GetStack()->IteratePointersForTesting(scanner.get())` 调用栈遍历方法，该方法会扫描栈，并对找到的每个可能指针调用 `scanner->VisitPointer()`。
    4. `scanner->VisitPointer()` 内部会将传入的地址与 `scanner->needle()` 进行比较，如果相等则设置 `scanner->found_` 为 `true`。
* **预期输出:** `EXPECT_TRUE(scanner->found())` 断言 `scanner->found_` 为 `true`，表示栈扫描器找到了之前放置在栈上的指针。

**涉及用户常见的编程错误，请举例说明:**

这个单元测试间接涉及了与内存管理相关的常见编程错误，尤其是在使用 C++ 时：

1. **悬挂指针 (Dangling Pointers):** 如果垃圾回收器的栈扫描功能不正确，它可能无法识别指向堆上对象的有效指针。这可能导致垃圾回收器错误地回收仍然被引用的对象，从而产生悬挂指针。当程序后续尝试访问这些已回收的内存时，会导致崩溃或未定义行为。

   **C++ 例子 (模拟栈扫描错误导致悬挂指针):**

   ```c++
   #include <iostream>
   #include <memory>

   int main() {
       int* ptr;
       {
           std::unique_ptr<int> managedPtr = std::make_unique<int>(42);
           ptr = managedPtr.get(); // ptr 现在指向 managedPtr 管理的内存
           // 假设错误的栈扫描器在这里没有找到 ptr
       } // managedPtr 被销毁，它管理的内存被释放

       // ptr 成为了悬挂指针
       std::cout << *ptr << std::endl; // 访问已释放的内存，导致未定义行为
       return 0;
   }
   ```

   这个例子中，如果栈扫描器在 `managedPtr` 的作用域内没有正确识别 `ptr`，那么垃圾回收器可能会在 `managedPtr` 销毁后错误地认为该内存可以回收。

2. **内存泄漏 (Memory Leaks):** 虽然这个单元测试主要关注栈扫描，但如果垃圾回收器无法正确识别所有可达对象，也可能导致内存泄漏。  如果对象不再被引用，但栈扫描器或其他根扫描器未能识别到这一点，垃圾回收器就无法回收这些对象，导致内存占用不断增加。

**总结:**

`v8/test/unittests/heap/cppgc/stack-unittest.cc` 是 V8 引擎中一个关键的测试文件，它详细地测试了 cppgc 模块中栈扫描功能的正确性。 栈扫描是垃圾回收的关键步骤，确保了垃圾回收器能够准确地识别存活对象，避免悬挂指针和内存泄漏，从而保证 JavaScript 代码的稳定运行。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc/stack-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/stack-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/base/stack.h"

#include <memory>
#include <ostream>

#include "include/v8config.h"
#include "testing/gtest/include/gtest/gtest.h"

#if V8_OS_LINUX && (V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64)
#include <xmmintrin.h>
#endif

namespace cppgc {
namespace internal {

using heap::base::Stack;
using heap::base::StackVisitor;

namespace {

class GCStackTest : public ::testing::Test {
 public:
  GCStackTest() : stack_(std::make_unique<Stack>()) { stack_->SetStackStart(); }

  Stack* GetStack() const { return stack_.get(); }

 private:
  std::unique_ptr<Stack> stack_;
};

}  // namespace

#if !V8_OS_FUCHSIA
TEST_F(GCStackTest, IsOnStackForStackValue) {
  void* dummy;
  EXPECT_TRUE(GetStack()->IsOnStack(&dummy));
}
#endif  // !V8_OS_FUCHSIA

TEST_F(GCStackTest, IsOnStackForHeapValue) {
  auto dummy = std::make_unique<int>();
  EXPECT_FALSE(GetStack()->IsOnStack(dummy.get()));
}

namespace {

class StackScanner final : public StackVisitor {
 public:
  struct Container {
    std::unique_ptr<int> value;
  };

  StackScanner() : container_(new Container{}) {
    container_->value = std::make_unique<int>();
  }

  void VisitPointer(const void* address) final {
    if (address == container_->value.get()) found_ = true;
  }

  void Reset() { found_ = false; }
  bool found() const { return found_; }
  int* needle() const { return container_->value.get(); }

 private:
  std::unique_ptr<Container> container_;
  bool found_ = false;
};

}  // namespace

TEST_F(GCStackTest, IteratePointersFindsOnStackValue) {
  auto scanner = std::make_unique<StackScanner>();

  // No check that the needle is initially not found as on some platforms it
  // may be part of  temporaries after setting it up through StackScanner.
  {
    int* volatile tmp = scanner->needle();
    USE(tmp);
    GetStack()->IteratePointersForTesting(scanner.get());
    EXPECT_TRUE(scanner->found());
  }
}

TEST_F(GCStackTest, IteratePointersFindsOnStackValuePotentiallyUnaligned) {
  auto scanner = std::make_unique<StackScanner>();

  // No check that the needle is initially not found as on some platforms it
  // may be part of  temporaries after setting it up through StackScanner.
  {
    char a = 'c';
    USE(a);
    int* volatile tmp = scanner->needle();
    USE(tmp);
    GetStack()->IteratePointersForTesting(scanner.get());
    EXPECT_TRUE(scanner->found());
  }
}

namespace {

// Prevent inlining as that would allow the compiler to prove that the parameter
// must not actually be materialized.
//
// Parameter positions are explicit to test various calling conventions.
V8_NOINLINE void* RecursivelyPassOnParameterImpl(void* p1, void* p2, void* p3,
                                                 void* p4, void* p5, void* p6,
                                                 void* p7, void* p8,
                                                 Stack* stack,
                                                 StackVisitor* visitor) {
  if (p1) {
    return RecursivelyPassOnParameterImpl(nullptr, p1, nullptr, nullptr,
                                          nullptr, nullptr, nullptr, nullptr,
                                          stack, visitor);
  } else if (p2) {
    return RecursivelyPassOnParameterImpl(nullptr, nullptr, p2, nullptr,
                                          nullptr, nullptr, nullptr, nullptr,
                                          stack, visitor);
  } else if (p3) {
    return RecursivelyPassOnParameterImpl(nullptr, nullptr, nullptr, p3,
                                          nullptr, nullptr, nullptr, nullptr,
                                          stack, visitor);
  } else if (p4) {
    return RecursivelyPassOnParameterImpl(nullptr, nullptr, nullptr, nullptr,
                                          p4, nullptr, nullptr, nullptr, stack,
                                          visitor);
  } else if (p5) {
    return RecursivelyPassOnParameterImpl(nullptr, nullptr, nullptr, nullptr,
                                          nullptr, p5, nullptr, nullptr, stack,
                                          visitor);
  } else if (p6) {
    return RecursivelyPassOnParameterImpl(nullptr, nullptr, nullptr, nullptr,
                                          nullptr, nullptr, p6, nullptr, stack,
                                          visitor);
  } else if (p7) {
    return RecursivelyPassOnParameterImpl(nullptr, nullptr, nullptr, nullptr,
                                          nullptr, nullptr, nullptr, p7, stack,
                                          visitor);
  } else if (p8) {
    stack->IteratePointersForTesting(visitor);
    return p8;
  }
  return nullptr;
}

V8_NOINLINE void* RecursivelyPassOnParameter(size_t num, void* parameter,
                                             Stack* stack,
                                             StackVisitor* visitor) {
  switch (num) {
    case 0:
      stack->IteratePointersForTesting(visitor);
      return parameter;
    case 1:
      return RecursivelyPassOnParameterImpl(nullptr, nullptr, nullptr, nullptr,
                                            nullptr, nullptr, nullptr,
                                            parameter, stack, visitor);
    case 2:
      return RecursivelyPassOnParameterImpl(nullptr, nullptr, nullptr, nullptr,
                                            nullptr, nullptr, parameter,
                                            nullptr, stack, visitor);
    case 3:
      return RecursivelyPassOnParameterImpl(nullptr, nullptr, nullptr, nullptr,
                                            nullptr, parameter, nullptr,
                                            nullptr, stack, visitor);
    case 4:
      return RecursivelyPassOnParameterImpl(nullptr, nullptr, nullptr, nullptr,
                                            parameter, nullptr, nullptr,
                                            nullptr, stack, visitor);
    case 5:
      return RecursivelyPassOnParameterImpl(nullptr, nullptr, nullptr,
                                            parameter, nullptr, nullptr,
                                            nullptr, nullptr, stack, visitor);
    case 6:
      return RecursivelyPassOnParameterImpl(nullptr, nullptr, parameter,
                                            nullptr, nullptr, nullptr, nullptr,
                                            nullptr, stack, visitor);
    case 7:
      return RecursivelyPassOnParameterImpl(nullptr, parameter, nullptr,
                                            nullptr, nullptr, nullptr, nullptr,
                                            nullptr, stack, visitor);
    case 8:
      return RecursivelyPassOnParameterImpl(parameter, nullptr, nullptr,
                                            nullptr, nullptr, nullptr, nullptr,
                                            nullptr, stack, visitor);
    default:
      UNREACHABLE();
  }
  UNREACHABLE();
}

}  // namespace

TEST_F(GCStackTest, IteratePointersFindsParameterNesting0) {
  auto scanner = std::make_unique<StackScanner>();
  void* needle = RecursivelyPassOnParameter(0, scanner->needle(), GetStack(),
                                            scanner.get());
  EXPECT_EQ(scanner->needle(), needle);
  EXPECT_TRUE(scanner->found());
}

TEST_F(GCStackTest, IteratePointersFindsParameterNesting1) {
  auto scanner = std::make_unique<StackScanner>();
  void* needle = RecursivelyPassOnParameter(1, scanner->needle(), GetStack(),
                                            scanner.get());
  EXPECT_EQ(scanner->needle(), needle);
  EXPECT_TRUE(scanner->found());
}

TEST_F(GCStackTest, IteratePointersFindsParameterNesting2) {
  auto scanner = std::make_unique<StackScanner>();
  void* needle = RecursivelyPassOnParameter(2, scanner->needle(), GetStack(),
                                            scanner.get());
  EXPECT_EQ(scanner->needle(), needle);
  EXPECT_TRUE(scanner->found());
}

TEST_F(GCStackTest, IteratePointersFindsParameterNesting3) {
  auto scanner = std::make_unique<StackScanner>();
  void* needle = RecursivelyPassOnParameter(3, scanner->needle(), GetStack(),
                                            scanner.get());
  EXPECT_EQ(scanner->needle(), needle);
  EXPECT_TRUE(scanner->found());
}

TEST_F(GCStackTest, IteratePointersFindsParameterNesting4) {
  auto scanner = std::make_unique<StackScanner>();
  void* needle = RecursivelyPassOnParameter(4, scanner->needle(), GetStack(),
                                            scanner.get());
  EXPECT_EQ(scanner->needle(), needle);
  EXPECT_TRUE(scanner->found());
}

TEST_F(GCStackTest, IteratePointersFindsParameterNesting5) {
  auto scanner = std::make_unique<StackScanner>();
  void* needle = RecursivelyPassOnParameter(5, scanner->needle(), GetStack(),
                                            scanner.get());
  EXPECT_EQ(scanner->needle(), needle);
  EXPECT_TRUE(scanner->found());
}

TEST_F(GCStackTest, IteratePointersFindsParameterNesting6) {
  auto scanner = std::make_unique<StackScanner>();
  void* needle = RecursivelyPassOnParameter(6, scanner->needle(), GetStack(),
                                            scanner.get());
  EXPECT_EQ(scanner->needle(), needle);
  EXPECT_TRUE(scanner->found());
}

TEST_F(GCStackTest, IteratePointersFindsParameterNesting7) {
  auto scanner = std::make_unique<StackScanner>();
  void* needle = RecursivelyPassOnParameter(7, scanner->needle(), GetStack(),
                                            scanner.get());
  EXPECT_EQ(scanner->needle(), needle);
  EXPECT_TRUE(scanner->found());
}

// Disabled on msvc, due to miscompilation, see https://crbug.com/v8/10658.
#if !defined(_MSC_VER) || defined(__clang__)
TEST_F(GCStackTest, IteratePointersFindsParameterNesting8) {
  auto scanner = std::make_unique<StackScanner>();
  void* needle = RecursivelyPassOnParameter(8, scanner->needle(), GetStack(),
                                            scanner.get());
  EXPECT_EQ(scanner->needle(), needle);
  EXPECT_TRUE(scanner->found());
}
#endif  // !_MSC_VER || __clang__

namespace {
// We manually call into this function from inline assembly. Therefore we need
// to make sure that:
// 1) there is no .plt indirection (i.e. visibility is hidden);
// 2) stack is realigned in the function prologue.
extern "C" V8_NOINLINE
#if defined(__clang__)
    __attribute__((used))
#if !defined(V8_OS_WIN)
    __attribute__((visibility("hidden")))
#endif  // !defined(V8_OS_WIN)
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
    __attribute__((force_align_arg_pointer))
#endif  // __has_attribute(force_align_arg_pointer)
#endif  //  __has_attribute
#endif  // defined(__clang__)
    void
    IteratePointersNoMangling(Stack* stack, StackVisitor* visitor) {
  stack->IteratePointersForTesting(visitor);
}
}  // namespace

// The following tests use inline assembly and have been checked to work on
// clang to verify that the stack-scanning trampoline pushes callee-saved
// registers.
//
// The test uses a macro loop as asm() can only be passed string literals.
#ifdef __clang__
#ifdef V8_TARGET_ARCH_X64
#ifdef V8_OS_WIN

// Excluded from test: rbp
#define FOR_ALL_CALLEE_SAVED_REGS(V) \
  V("rdi")                           \
  V("rsi")                           \
  V("rbx")                           \
  V("r12")                           \
  V("r13")                           \
  V("r14")                           \
  V("r15")

#else  // !V8_OS_WIN

// Excluded from test: rbp
#define FOR_ALL_CALLEE_SAVED_REGS(V) \
  V("rbx")                           \
  V("r12")                           \
  V("r13")                           \
  V("r14")                           \
  V("r15")

#endif  // !V8_OS_WIN
#endif  // V8_TARGET_ARCH_X64
#endif  // __clang__

#ifdef FOR_ALL_CALLEE_SAVED_REGS

TEST_F(GCStackTest, IteratePointersFindsCalleeSavedRegisters) {
  auto scanner = std::make_unique<StackScanner>();

  // No check that the needle is initially not found as on some platforms it
  // may be part of  temporaries after setting it up through StackScanner.

// First, clear all callee-saved registers.
#define CLEAR_REGISTER(reg) asm("mov $0, %%" reg : : : reg);

  FOR_ALL_CALLEE_SAVED_REGS(CLEAR_REGISTER)
#undef CLEAR_REGISTER

  // Keep local raw pointers to keep instruction sequences small below.
  auto* local_stack = GetStack();
  auto* local_scanner = scanner.get();

#define MOVE_TO_REG_AND_CALL_IMPL(needle_reg, arg1, arg2)           \
  asm volatile("mov %0, %%" needle_reg "\n mov %1, %%" arg1         \
               "\n mov %2, %%" arg2                                 \
               "\n call %P3"                                        \
               "\n mov $0, %%" needle_reg                           \
               :                                                    \
               : "r"(local_scanner->needle()), "r"(local_stack),    \
                 "r"(local_scanner), "i"(IteratePointersNoMangling) \
               : "memory", needle_reg, arg1, arg2, "cc");

#ifdef V8_OS_WIN
#define MOVE_TO_REG_AND_CALL(reg) MOVE_TO_REG_AND_CALL_IMPL(reg, "rcx", "rdx")
#else  // !V8_OS_WIN
#define MOVE_TO_REG_AND_CALL(reg) MOVE_TO_REG_AND_CALL_IMPL(reg, "rdi", "rsi")
#endif  // V8_OS_WIN

// Moves |local_scanner->needle()| into a callee-saved register, leaving the
// callee-saved register as the only register referencing the needle.
// (Ignoring implementation-dependent dirty registers/stack.)
#define KEEP_ALIVE_FROM_CALLEE_SAVED(reg)                                     \
  local_scanner->Reset();                                                     \
  /* Wrap the inline assembly in a lambda to rely on the compiler for saving  \
  caller-saved registers. */                                                  \
  [local_stack, local_scanner]() V8_NOINLINE { MOVE_TO_REG_AND_CALL(reg) }(); \
  EXPECT_TRUE(local_scanner->found())                                         \
      << "pointer in callee-saved register not found. register: " << reg      \
      << std::endl;

  FOR_ALL_CALLEE_SAVED_REGS(KEEP_ALIVE_FROM_CALLEE_SAVED)
#undef MOVE_TO_REG_AND_CALL
#undef MOVE_TO_REG_AND_CALL_IMPL
#undef KEEP_ALIVE_FROM_CALLEE_SAVED
#undef FOR_ALL_CALLEE_SAVED_REGS
}
#endif  // FOR_ALL_CALLEE_SAVED_REGS

#if defined(__clang__) && defined(V8_TARGET_ARCH_X64) && defined(V8_OS_WIN)

#define FOR_ALL_XMM_CALLEE_SAVED_REGS(V) \
  V("xmm6")                              \
  V("xmm7")                              \
  V("xmm8")                              \
  V("xmm9")                              \
  V("xmm10")                             \
  V("xmm11")                             \
  V("xmm12")                             \
  V("xmm13")                             \
  V("xmm14")                             \
  V("xmm15")

TEST_F(GCStackTest, IteratePointersFindsCalleeSavedXMMRegisters) {
  auto scanner = std::make_unique<StackScanner>();

  // No check that the needle is initially not found as on some platforms it
  // may be part of  temporaries after setting it up through StackScanner.

// First, clear all callee-saved xmm registers.
#define CLEAR_REGISTER(reg) asm("pxor %%" reg ", %%" reg : : : reg);

  FOR_ALL_XMM_CALLEE_SAVED_REGS(CLEAR_REGISTER)
#undef CLEAR_REGISTER

  // Keep local raw pointers to keep instruction sequences small below.
  auto* local_stack = GetStack();
  auto* local_scanner = scanner.get();

// Moves |local_scanner->needle()| into a callee-saved register, leaving the
// callee-saved register as the only register referencing the needle.
// (Ignoring implementation-dependent dirty registers/stack.)
#define KEEP_ALIVE_FROM_CALLEE_SAVED(reg)                                     \
  local_scanner->Reset();                                                     \
  [local_stack, local_scanner]() V8_NOINLINE { MOVE_TO_REG_AND_CALL(reg) }(); \
  EXPECT_TRUE(local_scanner->found())                                         \
      << "pointer in callee-saved xmm register not found. register: " << reg  \
      << std::endl;

  // First, test the pointer in the low quadword.
#define MOVE_TO_REG_AND_CALL(reg)                                   \
  asm volatile("mov %0, %%rax \n movq %%rax, %%" reg                \
               "\n mov %1, %%rcx \n mov %2, %%rdx"                  \
               "\n call %P3"                                        \
               "\n pxor %%" reg ", %%" reg                          \
               :                                                    \
               : "r"(local_scanner->needle()), "r"(local_stack),    \
                 "r"(local_scanner), "i"(IteratePointersNoMangling) \
               : "memory", "rax", reg, "rcx", "rdx", "cc");

  FOR_ALL_XMM_CALLEE_SAVED_REGS(KEEP_ALIVE_FROM_CALLEE_SAVED)

#undef MOVE_TO_REG_AND_CALL
  // Then, test the pointer in the upper quadword.
#define MOVE_TO_REG_AND_CALL(reg)                                   \
  asm volatile("mov %0, %%rax \n movq %%rax, %%" reg                \
               "\n pshufd $0b01001110, %%" reg ", %%" reg           \
               "\n mov %1, %%rcx \n mov %2, %%rdx"                  \
               "\n call %P3"                                        \
               "\n pxor %%" reg ", %%" reg                          \
               :                                                    \
               : "r"(local_scanner->needle()), "r"(local_stack),    \
                 "r"(local_scanner), "i"(IteratePointersNoMangling) \
               : "memory", "rax", reg, "rcx", "rdx", "cc");

  FOR_ALL_XMM_CALLEE_SAVED_REGS(KEEP_ALIVE_FROM_CALLEE_SAVED)
#undef MOVE_TO_REG_AND_CALL
#undef KEEP_ALIVE_FROM_CALLEE_SAVED
#undef FOR_ALL_XMM_CALLEE_SAVED_REGS
}

#endif  // defined(__clang__) && defined(V8_TARGET_ARCH_X64) &&
        // defined(V8_OS_WIN)

#if V8_OS_LINUX && (V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64)
class CheckStackAlignmentVisitor final : public StackVisitor {
 public:
  void VisitPointer(const void*) final {
    float f[4] = {0.};
    volatile auto xmm = ::_mm_load_ps(f);
    USE(xmm);
  }
};

TEST_F(GCStackTest, StackAlignment) {
  auto checker = std::make_unique<CheckStackAlignmentVisitor>();
  GetStack()->IteratePointersForTesting(checker.get());
}
#endif  // V8_OS_LINUX && (V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64)

}  // namespace internal
}  // namespace cppgc
```