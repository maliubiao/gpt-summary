Response: The user wants to understand the functionality of the C++ source code file `v8/test/unittests/wasm/trap-handler-native-unittest.cc`. This file seems to be related to testing the trap handling mechanism for WebAssembly in the V8 JavaScript engine.

Here's a breakdown of the code to identify its core functionalities:

1. **Includes:** The file includes necessary headers for:
    - Platform-specific signal handling (`signal.h`, `ucontext.h`, `windows.h`).
    - Google Test framework (`gtest/gtest.h`).
    - V8's public API for WASM trap handling (`v8-wasm-trap-handler-posix.h`, `v8-wasm-trap-handler-win.h`).
    - Internal V8 components like `page-allocator.h`, `assembler-inl.h`, `trap-handler.h`, etc.
    - Utilities for testing.

2. **Conditional Compilation:**  The code uses `#if` directives to handle platform differences (Linux, macOS, Windows) and architecture differences (x64, ARM64). It also checks for `V8_TRAP_HANDLER_SUPPORTED`.

3. **Global Variables:**  Several global variables are declared:
    - `g_test_handler_executed`: A boolean flag to track if a custom signal/exception handler was executed.
    - `g_old_segv_action`, `g_old_other_action`, `g_old_bus_action`:  To store the original signal handlers before installing custom ones (POSIX).
    - `g_registered_handler`: To store the handle of the registered exception handler (Windows).
    - `g_recovery_address`: The address to jump to for recovering from a crash.
    - `g_use_as_first_chance_handler`: A flag to indicate if the custom handler should act as a first-chance handler.

4. **`TrapHandlerStyle` Enum:** Defines two modes for testing: `kDefault` (using V8's default handler) and `kCallback` (using a custom callback handler).

5. **`TrapHandlerTest` Class:** This is the main test fixture using Google Test.
    - **`SetUp()`:**  Initializes the test environment: installs a fallback signal/exception handler, sets up the trap handler based on the test parameter, allocates memory for testing, and initializes recovery code.
    - **`InstallFallbackHandler()`:** Installs a custom signal handler (POSIX) or exception handler (Windows) to intercept crashes. This handler can either attempt to use the WASM trap handler or directly jump to a recovery address.
    - **`TearDown()`:** Cleans up the test environment: releases allocated memory, removes the trap handler, and restores the original signal/exception handlers.
    - **`InitRecoveryCode()`:** Generates a small piece of assembly code (a simple return) to which the signal/exception handler can redirect execution after a crash.
    - **`SignalHandler()` (POSIX) / `TestHandler()` (Windows):** The custom signal/exception handlers. They check if the trap handler should be invoked first, and if not, set the `g_test_handler_executed` flag and modify the execution context to jump to `g_recovery_address`.
    - **`SetupTrapHandler()`:** Enables or disables V8's built-in WASM trap handler based on the test parameter.
    - **`GenerateSetThreadInWasmFlagCode()` / `GenerateResetThreadInWasmFlagCode()`:** Assembly code snippets to set and reset a thread-local flag indicating if the current thread is executing WASM code.
    - **`GetThreadInWasmFlag()`:**  Reads the value of the thread-in-wasm flag.
    - **`ExecuteBuffer()`:** Executes the assembly code in the `buffer_`.
    - **`ExecuteExpectCrash()`:** Executes code and expects a crash, verifying that the custom signal/exception handler was invoked and the thread-in-wasm flag is correctly reset.
    - **Member Variables:** `backing_store_`, `crash_address_`, `buffer_`, `recovery_buffer_` are used for managing memory and addresses during testing.

6. **Test Cases:** The file contains several test cases using the `TrapHandlerTest` fixture:
    - **`TestTrapHandlerRecovery`:** Tests that the WASM trap handler can recover from a memory access violation within WASM code. It registers a protected instruction and verifies that execution jumps to the landing pad after the crash.
    - **`TestReleaseHandlerData`:** Checks that deregistering handler data prevents the trap handler from recovering from specific memory access violations.
    - **`TestNoThreadInWasmFlag`:** Verifies that the trap handler is not active if the `thread_in_wasm` flag is not set.
    - **`TestCrashInWasmNoProtectedInstruction`:**  Ensures that the trap handler does not intervene if the crash happens at an unprotected instruction.
    - **`TestCrashInWasmWrongCrashType`:** Tests that the trap handler only handles memory access violations and not other types of crashes (e.g., division by zero).
    - **`TestCrashInOtherThread`:**  Tests the scenario where a crash occurs in a different thread that does not have the `thread_in_wasm` flag set.

7. **`CodeRunner` Class:** A simple thread class used in `TestCrashInOtherThread` to execute code in a separate thread.

8. **`INSTANTIATE_TEST_SUITE_P`:**  Configures Google Test to run the `TrapHandlerTest` with both `kDefault` and `kCallback` trap handler styles.

**In summary, the `v8/test/unittests/wasm/trap-handler-native-unittest.cc` file is designed to thoroughly test the functionality of V8's WebAssembly trap handling mechanism. It sets up controlled scenarios involving memory access violations and other types of crashes to verify that:**

- The trap handler can successfully intercept and recover from intended crashes within WASM code when the `thread_in_wasm` flag is set.
- The trap handler correctly identifies protected instructions and only acts on crashes occurring at those instructions.
- The trap handler does not interfere with crashes outside of WASM code or crashes of different types.
- The trap handler's behavior can be customized by providing a callback.
- The trap handler functions correctly in multi-threaded scenarios.

The tests cover both the default V8 trap handler and the ability to use a custom callback handler. The platform-specific code ensures that the trap handling mechanism works correctly on different operating systems.

这个C++源代码文件 `v8/test/unittests/wasm/trap-handler-native-unittest.cc` 的主要功能是**对 V8 JavaScript 引擎中用于处理 WebAssembly 陷阱（traps）的本地代码进行单元测试**。

具体来说，它测试了以下几个关键方面：

1. **陷阱处理器的恢复能力:**  测试 WebAssembly 陷阱处理器能否成功捕获并从 WebAssembly 代码中的内存访问违规错误中恢复执行。它通过模拟 WebAssembly 代码和访问违规来验证这一点。

2. **处理器数据的注册和释放:**  测试陷阱处理器数据的注册和释放机制。验证在释放处理器数据后，陷阱处理器是否不再能从特定的内存访问违规中恢复。

3. **`thread_in_wasm` 标志的影响:**  测试 `thread_in_wasm` 标志的作用。如果该标志未设置，陷阱处理器应该不会被激活。

4. **崩溃位置是否在受保护指令上:**  测试只有当崩溃发生在受保护的 WebAssembly 指令上时，陷阱处理器才会介入处理。如果崩溃发生在非受保护指令上，陷阱处理器应该不会处理。

5. **崩溃类型是否为内存访问违规:**  测试陷阱处理器只处理内存访问违规类型的崩溃。对于其他类型的崩溃（例如，除零错误），陷阱处理器应该不会处理。

6. **跨线程的崩溃处理:**  测试在多线程场景下陷阱处理器的行为。验证当崩溃发生在没有设置 `thread_in_wasm` 标志的其他线程时，陷阱处理器是否不会处理。

**核心机制和实现细节:**

- **自定义信号/异常处理:**  代码使用平台相关的 API (例如 Linux/macOS 的 `sigaction` 和 Windows 的 `AddVectoredExceptionHandler`) 注册自定义的信号或异常处理函数，用于模拟和捕获 WebAssembly 代码中的崩溃。
- **恢复地址:**  定义了一个 `g_recovery_address`，当发生预期的崩溃时，信号/异常处理函数会将程序的执行流程跳转到这个地址，从而实现从崩溃中恢复。
- **`thread_in_wasm` 标志:**  测试中会显式地设置和重置一个线程局部变量 `thread_in_wasm` 标志，这个标志用于指示当前线程是否正在执行 WebAssembly 代码。陷阱处理器通常只在 `thread_in_wasm` 标志被设置时才会生效。
- **受保护指令数据:**  代码会注册一些 "受保护的指令"，这些指令模拟了可能发生内存访问违规的 WebAssembly 代码位置。陷阱处理器会检查崩溃是否发生在这些受保护的指令上。
- **测试参数化:**  使用了 Google Test 的参数化测试功能，允许使用不同的陷阱处理器模式进行测试 (例如，使用 V8 默认的陷阱处理器或使用自定义的回调函数)。
- **汇编代码生成:**  使用 `MacroAssembler` 来动态生成一些简单的汇编代码片段，用于模拟 WebAssembly 代码和触发崩溃。

**总而言之，这个文件是一个精细设计的单元测试套件，用于验证 V8 中 WebAssembly 陷阱处理器的正确性和可靠性。它通过模拟各种崩溃场景和配置，确保 V8 能够安全有效地处理 WebAssembly 代码执行过程中可能出现的错误。**

Prompt: ```这是目录为v8/test/unittests/wasm/trap-handler-native-unittest.cc的一个c++源代码文件， 请归纳一下它的功能

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8config.h"

#if V8_OS_LINUX || V8_OS_FREEBSD
#include <signal.h>
#include <ucontext.h>
#elif V8_OS_DARWIN
#include <signal.h>
#include <sys/ucontext.h>
#elif V8_OS_WIN
#include <windows.h>
#endif

#include "testing/gtest/include/gtest/gtest.h"

#if V8_OS_POSIX
#include "include/v8-wasm-trap-handler-posix.h"
#elif V8_OS_WIN
#include "include/v8-wasm-trap-handler-win.h"
#endif
#include "src/base/page-allocator.h"
#include "src/base/vector.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/execution/simulator.h"
#include "src/objects/backing-store.h"
#include "src/trap-handler/trap-handler.h"
#include "src/utils/allocation.h"
#include "src/wasm/wasm-engine.h"
#include "test/common/assembler-tester.h"
#include "test/unittests/test-utils.h"

#if V8_TRAP_HANDLER_SUPPORTED

#if V8_HOST_ARCH_ARM64 && (!V8_OS_LINUX && !V8_OS_DARWIN && !V8_OS_WIN)
#error Unsupported platform
#endif

namespace v8 {
namespace internal {
namespace wasm {

namespace {
#if V8_HOST_ARCH_X64
constexpr Register scratch = r10;
#endif
bool g_test_handler_executed = false;
#if V8_OS_LINUX || V8_OS_DARWIN || V8_OS_FREEBSD
struct sigaction g_old_segv_action;
struct sigaction g_old_other_action;  // FPE or TRAP, depending on x64 or arm64.
struct sigaction g_old_bus_action;    // We get SIGBUS on Mac sometimes.
#elif V8_OS_WIN
void* g_registered_handler = nullptr;
#endif

// The recovery address allows us to recover from an intentional crash.
Address g_recovery_address;
// Flag to indicate if the test handler should call the trap handler as a first
// chance handler.
bool g_use_as_first_chance_handler = false;
}  // namespace

#define __ masm.

enum TrapHandlerStyle : int {
  // The test uses the default trap handler of V8.
  kDefault = 0,
  // The test installs the trap handler callback in its own test handler.
  kCallback = 1
};

std::string PrintTrapHandlerTestParam(
    ::testing::TestParamInfo<TrapHandlerStyle> info) {
  switch (info.param) {
    case kDefault:
      return "DefaultTrapHandler";
    case kCallback:
      return "Callback";
  }
  UNREACHABLE();
}

class TrapHandlerTest : public TestWithIsolate,
                        public ::testing::WithParamInterface<TrapHandlerStyle> {
 protected:
  void SetUp() override {
    InstallFallbackHandler();
    SetupTrapHandler(GetParam());
    backing_store_ = BackingStore::AllocateWasmMemory(
        i_isolate(), 1, 1, WasmMemoryFlag::kWasmMemory32,
        SharedFlag::kNotShared);
    CHECK(backing_store_);
    EXPECT_TRUE(backing_store_->has_guard_regions());
    // The allocated backing store ends with a guard page.
    crash_address_ = reinterpret_cast<Address>(backing_store_->buffer_start()) +
                     backing_store_->byte_length() + 32;
    // Allocate a buffer for the generated code.
    buffer_ = AllocateAssemblerBuffer(AssemblerBase::kDefaultBufferSize,
                                      GetRandomMmapAddr());

    InitRecoveryCode();
  }

  void InstallFallbackHandler() {
#if V8_OS_LINUX || V8_OS_DARWIN || V8_OS_FREEBSD
    // Set up a signal handler to recover from the expected crash.
    struct sigaction action;
    action.sa_sigaction = SignalHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    // SIGSEGV happens for wasm oob memory accesses on Linux.
    EXPECT_EQ(0, sigaction(SIGSEGV, &action, &g_old_segv_action));
    // SIGBUS happens for wasm oob memory accesses on macOS.
    EXPECT_EQ(0, sigaction(SIGBUS, &action, &g_old_bus_action));
#if V8_HOST_ARCH_X64
    // SIGFPE to simulate crashes which are not handled by the trap handler.
    EXPECT_EQ(0, sigaction(SIGFPE, &action, &g_old_other_action));
#elif V8_HOST_ARCH_ARM64
    // SIGTRAP to simulate crashes which are not handled by the trap handler.
    EXPECT_EQ(0, sigaction(SIGTRAP, &action, &g_old_other_action));
#elif V8_HOST_ARCH_LOONG64
    // SIGTRAP to simulate crashes which are not handled by the trap handler.
    EXPECT_EQ(0, sigaction(SIGTRAP, &action, &g_old_other_action));
#elif V8_HOST_ARCH_RISCV64
    // SIGTRAP to simulate crashes which are not handled by the trap handler.
    EXPECT_EQ(0, sigaction(SIGTRAP, &action, &g_old_other_action));
#else
#error Unsupported platform
#endif
#elif V8_OS_WIN
    g_registered_handler =
        AddVectoredExceptionHandler(/*first=*/0, TestHandler);
#endif
  }

  void TearDown() override {
    // We should always have left wasm code.
    EXPECT_TRUE(!GetThreadInWasmFlag());
    buffer_.reset();
    recovery_buffer_.reset();
    backing_store_.reset();

    // Clean up the trap handler
    trap_handler::RemoveTrapHandler();
    if (!g_test_handler_executed) {
#if V8_OS_LINUX || V8_OS_DARWIN || V8_OS_FREEBSD
      // The test handler cleans up the signal handler setup in the test. If the
      // test handler was not called, we have to do the cleanup ourselves.
      EXPECT_EQ(0, sigaction(SIGSEGV, &g_old_segv_action, nullptr));
      EXPECT_EQ(0, sigaction(SIGBUS, &g_old_bus_action, nullptr));
#if V8_HOST_ARCH_X64
      EXPECT_EQ(0, sigaction(SIGFPE, &g_old_other_action, nullptr));
#elif V8_HOST_ARCH_ARM64
      EXPECT_EQ(0, sigaction(SIGTRAP, &g_old_other_action, nullptr));
#elif V8_HOST_ARCH_LOONG64
      EXPECT_EQ(0, sigaction(SIGTRAP, &g_old_other_action, nullptr));
#elif V8_HOST_ARCH_RISCV64
      EXPECT_EQ(0, sigaction(SIGTRAP, &g_old_other_action, nullptr));
#else
#error Unsupported platform
#endif
#elif V8_OS_WIN
      RemoveVectoredExceptionHandler(g_registered_handler);
      g_registered_handler = nullptr;
#endif
    }
  }

  void InitRecoveryCode() {
    // Create a code snippet where we can jump to to recover from a signal or
    // exception. The code snippet only consists of a return statement.
    recovery_buffer_ = AllocateAssemblerBuffer(
        AssemblerBase::kDefaultBufferSize, GetRandomMmapAddr());

    MacroAssembler masm(i_isolate(), AssemblerOptions{},
                        CodeObjectRequired::kNo,
                        recovery_buffer_->CreateView());
    int recovery_offset = __ pc_offset();
#if V8_HOST_ARCH_X64
    __ Pop(scratch);
#endif
    __ Ret();
    CodeDesc desc;
    masm.GetCode(static_cast<LocalIsolate*>(nullptr), &desc);
    recovery_buffer_->MakeExecutable();
    g_recovery_address =
        reinterpret_cast<Address>(desc.buffer + recovery_offset);
  }

#if V8_OS_LINUX || V8_OS_DARWIN || V8_OS_FREEBSD
  static void SignalHandler(int signal, siginfo_t* info, void* context) {
    if (g_use_as_first_chance_handler) {
      if (v8::TryHandleWebAssemblyTrapPosix(signal, info, context)) {
        return;
      }
    }

    // Reset the signal handler, to avoid that this signal handler is called
    // repeatedly.
    sigaction(SIGSEGV, &g_old_segv_action, nullptr);
#if V8_HOST_ARCH_X64
    sigaction(SIGFPE, &g_old_other_action, nullptr);
#elif V8_HOST_ARCH_ARM64
    sigaction(SIGTRAP, &g_old_other_action, nullptr);
#elif V8_HOST_ARCH_LOONG64
    sigaction(SIGTRAP, &g_old_other_action, nullptr);
#elif V8_HOST_ARCH_RISCV64
    sigaction(SIGTRAP, &g_old_other_action, nullptr);
#else
#error Unsupported platform
#endif
    sigaction(SIGBUS, &g_old_bus_action, nullptr);

    g_test_handler_executed = true;
    // Set the $rip to the recovery code.
    ucontext_t* uc = reinterpret_cast<ucontext_t*>(context);
#if V8_OS_DARWIN && V8_HOST_ARCH_ARM64
    uc->uc_mcontext->__ss.__pc = g_recovery_address;
#elif V8_OS_DARWIN && V8_HOST_ARCH_X64
    uc->uc_mcontext->__ss.__rip = g_recovery_address;
#elif V8_OS_LINUX && V8_HOST_ARCH_ARM64
    uc->uc_mcontext.pc = g_recovery_address;
#elif V8_OS_LINUX && V8_HOST_ARCH_LOONG64
    uc->uc_mcontext.__pc = g_recovery_address;
#elif V8_OS_LINUX && V8_HOST_ARCH_RISCV64
    uc->uc_mcontext.__gregs[REG_PC] = g_recovery_address;
#elif V8_OS_LINUX && V8_HOST_ARCH_X64
    uc->uc_mcontext.gregs[REG_RIP] = g_recovery_address;
#elif V8_OS_FREEBSD
    uc->uc_mcontext.mc_rip = g_recovery_address;
#else
#error Unsupported platform
#endif
  }
#endif

#if V8_OS_WIN
  static LONG WINAPI TestHandler(EXCEPTION_POINTERS* exception) {
    if (g_use_as_first_chance_handler) {
      if (v8::TryHandleWebAssemblyTrapWindows(exception)) {
        return EXCEPTION_CONTINUE_EXECUTION;
      }
    }
    RemoveVectoredExceptionHandler(g_registered_handler);
    g_registered_handler = nullptr;
    g_test_handler_executed = true;
#if V8_HOST_ARCH_X64
    exception->ContextRecord->Rip = g_recovery_address;
#elif V8_HOST_ARCH_ARM64
    exception->ContextRecord->Pc = g_recovery_address;
#else
#error Unsupported architecture
#endif  // V8_HOST_ARCH_X64
    return EXCEPTION_CONTINUE_EXECUTION;
  }
#endif

  void SetupTrapHandler(TrapHandlerStyle style) {
    bool use_default_handler = style == kDefault;
    g_use_as_first_chance_handler = !use_default_handler;
    CHECK(v8::V8::EnableWebAssemblyTrapHandler(use_default_handler));
  }

 public:
  void GenerateSetThreadInWasmFlagCode(MacroAssembler* masm) {
#if V8_HOST_ARCH_X64
    masm->Move(scratch,
               i_isolate()->thread_local_top()->thread_in_wasm_flag_address_,
               RelocInfo::NO_INFO);
    masm->movl(MemOperand(scratch, 0), Immediate(1));
#elif V8_HOST_ARCH_ARM64
    UseScratchRegisterScope temps(masm);
    Register addr = temps.AcquireX();
    masm->Mov(addr,
              i_isolate()->thread_local_top()->thread_in_wasm_flag_address_);
    Register one = temps.AcquireX();
    masm->Mov(one, 1);
    masm->Str(one, MemOperand(addr));
#elif V8_HOST_ARCH_LOONG64
    UseScratchRegisterScope temps(masm);
    Register addr = temps.Acquire();
    masm->li(
        addr,
        static_cast<int64_t>(
            i_isolate()->thread_local_top()->thread_in_wasm_flag_address_));
    Register one = temps.Acquire();
    masm->li(one, 1);
    masm->St_d(one, MemOperand(addr, 0));
#elif V8_HOST_ARCH_RISCV64
    UseScratchRegisterScope temps(masm);
    Register addr = temps.Acquire();
    masm->li(
        addr,
        static_cast<int64_t>(
            i_isolate()->thread_local_top()->thread_in_wasm_flag_address_));
    Register one = temps.Acquire();
    masm->li(one, 1);
    masm->StoreWord(one, MemOperand(addr, 0));
#else
#error Unsupported platform
#endif
  }

  void GenerateResetThreadInWasmFlagCode(MacroAssembler* masm) {
#if V8_HOST_ARCH_X64
    masm->Move(scratch,
               i_isolate()->thread_local_top()->thread_in_wasm_flag_address_,
               RelocInfo::NO_INFO);
    masm->movl(MemOperand(scratch, 0), Immediate(0));
#elif V8_HOST_ARCH_ARM64
    UseScratchRegisterScope temps(masm);
    Register addr = temps.AcquireX();
    masm->Mov(addr,
              i_isolate()->thread_local_top()->thread_in_wasm_flag_address_);
    masm->Str(xzr, MemOperand(addr));
#elif V8_HOST_ARCH_LOONG64
    UseScratchRegisterScope temps(masm);
    Register addr = temps.Acquire();
    masm->li(
        addr,
        static_cast<int64_t>(
            i_isolate()->thread_local_top()->thread_in_wasm_flag_address_));
    masm->St_d(zero_reg, MemOperand(addr, 0));
#elif V8_HOST_ARCH_RISCV64
    UseScratchRegisterScope temps(masm);
    Register addr = temps.Acquire();
    masm->li(
        addr,
        static_cast<int64_t>(
            i_isolate()->thread_local_top()->thread_in_wasm_flag_address_));
    masm->StoreWord(zero_reg, MemOperand(addr, 0));
#else
#error Unsupported platform
#endif
  }

  bool GetThreadInWasmFlag() {
    return *reinterpret_cast<int*>(
        trap_handler::GetThreadInWasmThreadLocalAddress());
  }

  // Execute the code in buffer.
  void ExecuteBuffer() {
    buffer_->MakeExecutable();
    GeneratedCode<void>::FromAddress(
        i_isolate(), reinterpret_cast<Address>(buffer_->start()))
        .Call();
    EXPECT_FALSE(g_test_handler_executed);
  }

  // Execute the code in buffer. We expect a crash which we recover from in the
  // test handler.
  void ExecuteExpectCrash(TestingAssemblerBuffer* buffer,
                          bool check_wasm_flag = true) {
    EXPECT_FALSE(g_test_handler_executed);
    buffer->MakeExecutable();
    GeneratedCode<void>::FromAddress(i_isolate(),
                                     reinterpret_cast<Address>(buffer->start()))
        .Call();
    EXPECT_TRUE(g_test_handler_executed);
    g_test_handler_executed = false;
    if (check_wasm_flag) {
      EXPECT_FALSE(GetThreadInWasmFlag());
    }
  }

  bool test_handler_executed() { return g_test_handler_executed; }

  // The backing store used for testing the trap handler.
  std::unique_ptr<BackingStore> backing_store_;

  // Address within the guard region of the wasm memory. Accessing this memory
  // address causes a signal or exception.
  Address crash_address_;

  // Buffer for generated code.
  std::unique_ptr<TestingAssemblerBuffer> buffer_;
  // Buffer for the code for the landing pad of the test handler.
  std::unique_ptr<TestingAssemblerBuffer> recovery_buffer_;
};

// TODO(almuthanna): These tests were skipped because they cause a crash when
// they are ran on Fuchsia. This issue should be solved later on
// Ticket: https://crbug.com/1028617
#if !defined(V8_TARGET_OS_FUCHSIA)
TEST_P(TrapHandlerTest, TestTrapHandlerRecovery) {
  // Test that the wasm trap handler can recover a memory access violation in
  // wasm code (we fake the wasm code and the access violation).
  MacroAssembler masm(i_isolate(), AssemblerOptions{}, CodeObjectRequired::kNo,
                      buffer_->CreateView());
#if V8_HOST_ARCH_X64
  __ Push(scratch);
  GenerateSetThreadInWasmFlagCode(&masm);
  __ Move(scratch, crash_address_, RelocInfo::NO_INFO);
  uint32_t crash_offset = __ pc_offset();
  __ testl(MemOperand(scratch, 0), Immediate(1));
  uint32_t recovery_offset = __ pc_offset();
  GenerateResetThreadInWasmFlagCode(&masm);
  __ Pop(scratch);
#elif V8_HOST_ARCH_ARM64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.AcquireX();
  __ Mov(scratch, crash_address_);
  uint32_t crash_offset = __ pc_offset();
  __ Ldr(scratch, MemOperand(scratch));
  uint32_t recovery_offset = __ pc_offset();
  GenerateResetThreadInWasmFlagCode(&masm);
#elif V8_HOST_ARCH_LOONG64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.Acquire();
  __ li(scratch, static_cast<int64_t>(crash_address_));
  uint32_t crash_offset = __ pc_offset();
  __ Ld_d(scratch, MemOperand(scratch, 0));
  uint32_t recovery_offset = __ pc_offset();
  GenerateResetThreadInWasmFlagCode(&masm);
#elif V8_HOST_ARCH_RISCV64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.Acquire();
  __ li(scratch, static_cast<int64_t>(crash_address_));
  uint32_t crash_offset = __ pc_offset();
  __ LoadWord(scratch, MemOperand(scratch, 0));
  uint32_t recovery_offset = __ pc_offset();
  GenerateResetThreadInWasmFlagCode(&masm);
#else
#error Unsupported platform
#endif
  __ Ret();
  CodeDesc desc;
  masm.GetCode(static_cast<LocalIsolate*>(nullptr), &desc);

  trap_handler::ProtectedInstructionData protected_instruction{crash_offset};
  trap_handler::RegisterHandlerData(reinterpret_cast<Address>(desc.buffer),
                                    desc.instr_size, 1, &protected_instruction);

  uintptr_t landing_pad =
      reinterpret_cast<uintptr_t>(buffer_->start()) + recovery_offset;
  trap_handler::SetLandingPad(landing_pad);
  ExecuteBuffer();
  trap_handler::SetLandingPad(0);
}

TEST_P(TrapHandlerTest, TestReleaseHandlerData) {
  // Test that after we release handler data in the trap handler, it cannot
  // recover from the specific memory access violation anymore.
  MacroAssembler masm(i_isolate(), AssemblerOptions{}, CodeObjectRequired::kNo,
                      buffer_->CreateView());
#if V8_HOST_ARCH_X64
  __ Push(scratch);
  GenerateSetThreadInWasmFlagCode(&masm);
  __ Move(scratch, crash_address_, RelocInfo::NO_INFO);
  uint32_t crash_offset = __ pc_offset();
  __ testl(MemOperand(scratch, 0), Immediate(1));
  uint32_t recovery_offset = __ pc_offset();
  GenerateResetThreadInWasmFlagCode(&masm);
  __ Pop(scratch);
#elif V8_HOST_ARCH_ARM64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.AcquireX();
  __ Mov(scratch, crash_address_);
  uint32_t crash_offset = __ pc_offset();
  __ Ldr(scratch, MemOperand(scratch));
  uint32_t recovery_offset = __ pc_offset();
  GenerateResetThreadInWasmFlagCode(&masm);
#elif V8_HOST_ARCH_LOONG64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.Acquire();
  __ li(scratch, static_cast<int64_t>(crash_address_));
  uint32_t crash_offset = __ pc_offset();
  __ Ld_d(scratch, MemOperand(scratch, 0));
  uint32_t recovery_offset = __ pc_offset();
  GenerateResetThreadInWasmFlagCode(&masm);
#elif V8_HOST_ARCH_RISCV64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.Acquire();
  __ li(scratch, static_cast<int64_t>(crash_address_));
  uint32_t crash_offset = __ pc_offset();
  __ LoadWord(scratch, MemOperand(scratch, 0));
  uint32_t recovery_offset = __ pc_offset();
  GenerateResetThreadInWasmFlagCode(&masm);
#else
#error Unsupported platform
#endif
  __ Ret();
  CodeDesc desc;
  masm.GetCode(static_cast<LocalIsolate*>(nullptr), &desc);

  trap_handler::ProtectedInstructionData protected_instruction{crash_offset};
  int handler_id = trap_handler::RegisterHandlerData(
      reinterpret_cast<Address>(desc.buffer), desc.instr_size, 1,
      &protected_instruction);

  uintptr_t landing_pad =
      reinterpret_cast<uintptr_t>(buffer_->start()) + recovery_offset;
  trap_handler::SetLandingPad(landing_pad);
  ExecuteBuffer();
  // Deregister from the trap handler. The trap handler should not do the
  // recovery now.
  trap_handler::ReleaseHandlerData(handler_id);

  ExecuteExpectCrash(buffer_.get());
  trap_handler::SetLandingPad(0);
}

TEST_P(TrapHandlerTest, TestNoThreadInWasmFlag) {
  // That that if the thread_in_wasm flag is not set, the trap handler does not
  // get active.
  MacroAssembler masm(i_isolate(), AssemblerOptions{}, CodeObjectRequired::kNo,
                      buffer_->CreateView());
#if V8_HOST_ARCH_X64
  __ Push(scratch);
  __ Move(scratch, crash_address_, RelocInfo::NO_INFO);
  uint32_t crash_offset = __ pc_offset();
  __ testl(MemOperand(scratch, 0), Immediate(1));
  __ Pop(scratch);
#elif V8_HOST_ARCH_ARM64
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.AcquireX();
  __ Mov(scratch, crash_address_);
  uint32_t crash_offset = __ pc_offset();
  __ Ldr(scratch, MemOperand(scratch));
#elif V8_HOST_ARCH_LOONG64
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.Acquire();
  __ li(scratch, static_cast<int64_t>(crash_address_));
  uint32_t crash_offset = __ pc_offset();
  __ Ld_d(scratch, MemOperand(scratch, 0));
#elif V8_HOST_ARCH_RISCV64
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.Acquire();
  __ li(scratch, static_cast<int64_t>(crash_address_));
  uint32_t crash_offset = __ pc_offset();
  __ LoadWord(scratch, MemOperand(scratch, 0));
#else
#error Unsupported platform
#endif
  __ Ret();
  CodeDesc desc;
  masm.GetCode(static_cast<LocalIsolate*>(nullptr), &desc);

  trap_handler::ProtectedInstructionData protected_instruction{crash_offset};
  trap_handler::RegisterHandlerData(reinterpret_cast<Address>(desc.buffer),
                                    desc.instr_size, 1, &protected_instruction);

  ExecuteExpectCrash(buffer_.get());
}

TEST_P(TrapHandlerTest, TestCrashInWasmNoProtectedInstruction) {
  // Test that if the crash in wasm happened at an instruction which is not
  // protected, then the trap handler does not handle it.
  MacroAssembler masm(i_isolate(), AssemblerOptions{}, CodeObjectRequired::kNo,
                      buffer_->CreateView());
#if V8_HOST_ARCH_X64
  __ Push(scratch);
  GenerateSetThreadInWasmFlagCode(&masm);
  uint32_t no_crash_offset = __ pc_offset();
  __ Move(scratch, crash_address_, RelocInfo::NO_INFO);
  __ testl(MemOperand(scratch, 0), Immediate(1));
  GenerateResetThreadInWasmFlagCode(&masm);
  __ Pop(scratch);
#elif V8_HOST_ARCH_ARM64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.AcquireX();
  uint32_t no_crash_offset = __ pc_offset();
  __ Mov(scratch, crash_address_);
  __ Ldr(scratch, MemOperand(scratch));
  GenerateResetThreadInWasmFlagCode(&masm);
#elif V8_HOST_ARCH_LOONG64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.Acquire();
  uint32_t no_crash_offset = __ pc_offset();
  __ li(scratch, static_cast<int64_t>(crash_address_));
  __ Ld_d(scratch, MemOperand(scratch, 0));
  GenerateResetThreadInWasmFlagCode(&masm);
#elif V8_HOST_ARCH_RISCV64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.Acquire();
  uint32_t no_crash_offset = __ pc_offset();
  __ li(scratch, static_cast<int64_t>(crash_address_));
  __ LoadWord(scratch, MemOperand(scratch, 0));
  GenerateResetThreadInWasmFlagCode(&masm);
#else
#error Unsupported platform
#endif
  __ Ret();
  CodeDesc desc;
  masm.GetCode(static_cast<LocalIsolate*>(nullptr), &desc);

  trap_handler::ProtectedInstructionData protected_instruction{no_crash_offset};
  trap_handler::RegisterHandlerData(reinterpret_cast<Address>(desc.buffer),
                                    desc.instr_size, 1, &protected_instruction);

  ExecuteExpectCrash(buffer_.get());
}

TEST_P(TrapHandlerTest, TestCrashInWasmWrongCrashType) {
  // Test that if the crash reason is not a memory access violation, then the
  // wasm trap handler does not handle it.
  MacroAssembler masm(i_isolate(), AssemblerOptions{}, CodeObjectRequired::kNo,
                      buffer_->CreateView());
#if V8_HOST_ARCH_X64
  __ Push(scratch);
  GenerateSetThreadInWasmFlagCode(&masm);
  __ xorq(scratch, scratch);
  uint32_t crash_offset = __ pc_offset();
  __ divq(scratch);
  GenerateResetThreadInWasmFlagCode(&masm);
  __ Pop(scratch);
#elif V8_HOST_ARCH_ARM64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  uint32_t crash_offset = __ pc_offset();
  __ Trap();
  GenerateResetThreadInWasmFlagCode(&masm);
#elif V8_HOST_ARCH_LOONG64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  uint32_t crash_offset = __ pc_offset();
  __ Trap();
  GenerateResetThreadInWasmFlagCode(&masm);
#elif V8_HOST_ARCH_RISCV64
  GenerateSetThreadInWasmFlagCode(&masm);
  UseScratchRegisterScope temps(&masm);
  uint32_t crash_offset = __ pc_offset();
  __ Trap();
  GenerateResetThreadInWasmFlagCode(&masm);
#else
#error Unsupported platform
#endif
  __ Ret();
  CodeDesc desc;
  masm.GetCode(static_cast<LocalIsolate*>(nullptr), &desc);

  trap_handler::ProtectedInstructionData protected_instruction{crash_offset};
  trap_handler::RegisterHandlerData(reinterpret_cast<Address>(desc.buffer),
                                    desc.instr_size, 1, &protected_instruction);

#if V8_OS_POSIX
  // On Posix, the V8 default trap handler does not register for SIGFPE,
  // therefore the thread-in-wasm flag is never reset in this test. We
  // therefore do not check the value of this flag.
  bool check_wasm_flag = GetParam() != kDefault;
#elif V8_OS_WIN
  // On Windows, the trap handler returns immediately if not an exception of
  // interest.
  bool check_wasm_flag = false;
#else
  bool check_wasm_flag = true;
#endif
  ExecuteExpectCrash(buffer_.get(), check_wasm_flag);
  if (!check_wasm_flag) {
    // Reset the thread-in-wasm flag because it was probably not reset in the
    // trap handler.
    *trap_handler::GetThreadInWasmThreadLocalAddress() = 0;
  }
}
#endif

class CodeRunner : public v8::base::Thread {
 public:
  CodeRunner(TrapHandlerTest* test, TestingAssemblerBuffer* buffer)
      : Thread(Options("CodeRunner")), test_(test), buffer_(buffer) {}

  void Run() override { test_->ExecuteExpectCrash(buffer_); }

 private:
  TrapHandlerTest* test_;
  TestingAssemblerBuffer* buffer_;
};

// TODO(almuthanna): This test was skipped because it causes a crash when it is
// ran on Fuchsia. This issue should be solved later on
// Ticket: https://crbug.com/1028617
#if !defined(V8_TARGET_OS_FUCHSIA)
TEST_P(TrapHandlerTest, TestCrashInOtherThread) {
  // Test setup:
  // The current thread enters wasm land (sets the thread_in_wasm flag)
  // A second thread crashes at a protected instruction without having the flag
  // set.
  MacroAssembler masm(i_isolate(), AssemblerOptions{}, CodeObjectRequired::kNo,
                      buffer_->CreateView());
#if V8_HOST_ARCH_X64
  __ Push(scratch);
  __ Move(scratch, crash_address_, RelocInfo::NO_INFO);
  uint32_t crash_offset = __ pc_offset();
  __ testl(MemOperand(scratch, 0), Immediate(1));
  __ Pop(scratch);
#elif V8_HOST_ARCH_ARM64
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.AcquireX();
  __ Mov(scratch, crash_address_);
  uint32_t crash_offset = __ pc_offset();
  __ Ldr(scratch, MemOperand(scratch));
#elif V8_HOST_ARCH_LOONG64
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.Acquire();
  __ li(scratch, static_cast<int64_t>(crash_address_));
  uint32_t crash_offset = __ pc_offset();
  __ Ld_d(scratch, MemOperand(scratch, 0));
#elif V8_HOST_ARCH_RISCV64
  UseScratchRegisterScope temps(&masm);
  Register scratch = temps.Acquire();
  __ li(scratch, static_cast<int64_t>(crash_address_));
  uint32_t crash_offset = __ pc_offset();
  __ LoadWord(scratch, MemOperand(scratch, 0));
#else
#error Unsupported platform
#endif
  __ Ret();
  CodeDesc desc;
  masm.GetCode(static_cast<LocalIsolate*>(nullptr), &desc);

  trap_handler::ProtectedInstructionData protected_instruction{crash_offset};
  trap_handler::RegisterHandlerData(reinterpret_cast<Address>(desc.buffer),
                                    desc.instr_size, 1, &protected_instruction);

  CodeRunner runner(this, buffer_.get());
  EXPECT_FALSE(GetThreadInWasmFlag());
  // Set the thread-in-wasm flag manually in this thread.
  *trap_handler::GetThreadInWasmThreadLocalAddress() = 1;
  EXPECT_TRUE(runner.Start());
  runner.Join();
  EXPECT_TRUE(GetThreadInWasmFlag());
  // Reset the thread-in-wasm flag.
  *trap_handler::GetThreadInWasmThreadLocalAddress() = 0;
}
#endif

#if !V8_OS_FUCHSIA
INSTANTIATE_TEST_SUITE_P(Traps, TrapHandlerTest,
                         ::testing::Values(kDefault, kCallback),
                         PrintTrapHandlerTestParam);
#endif  // !V8_OS_FUCHSIA

#undef __
}  // namespace wasm
}  // namespace internal
}  // namespace v8

#endif

"""
```