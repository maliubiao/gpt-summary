Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Understanding the Request:**

The core request is to understand the functionality of `v8/src/base/debug/stack_trace_posix.cc`. The prompt also includes specific conditional instructions based on file extension and relationship to JavaScript, as well as requests for examples, logic inference, and common errors.

**2. Initial Code Scan and Key Observations:**

My first step is to quickly scan the code for prominent features and keywords. I notice:

* **Includes:** A lot of standard POSIX headers (`errno.h`, `signal.h`, `unistd.h`, etc.) and some C++ standard library headers (`map`, `memory`, `string`, `vector`). The presence of `#if` directives related to `HAVE_EXECINFO_H`, `V8_LIBC_GLIBC`, etc., suggests platform-specific code.
* **Namespaces:** The code is organized within `v8::base::debug`.
* **Classes:**  `StackTrace`, `BacktraceOutputHandler`, `PrintBacktraceOutputHandler`, `StreamBacktraceOutputHandler`. These classes hint at how stack traces are captured and presented.
* **Functions:**  `DemangleSymbols`, `ProcessBacktrace`, `StackDumpSignalHandler`, `EnableInProcessStackDumping`, `DisableSignalStackDump`, `itoa_r`. The names are quite descriptive.
* **Signal Handling:** The presence of `StackDumpSignalHandler` and the `sigaction` calls in `EnableInProcessStackDumping` strongly indicate signal handling related to debugging.
* **Demangling:** The `DemangleSymbols` function suggests the code can translate mangled C++ symbol names into human-readable forms.
* **`itoa_r`:**  This function is a custom implementation for converting integers to strings, specifically designed to be async-signal safe.
* **`WarmUpBacktrace`:** This function name suggests a performance optimization related to initial stack trace setup.

**3. Focusing on Core Functionality - Stack Traces:**

The `StackTrace` class is the central element. I look at its methods:

* **Constructor:**  Calls `backtrace()` (if `HAVE_EXECINFO_H` is defined) to capture the current call stack.
* **`Print()`:**  Uses `ProcessBacktrace` and `PrintBacktraceOutputHandler` to output the stack trace to standard error.
* **`OutputToStream()`:**  Similar to `Print()`, but outputs to a provided `std::ostream`.

This confirms that the primary purpose is to capture and display stack traces.

**4. Understanding `ProcessBacktrace`:**

This function takes the raw backtrace data and processes it. Key observations:

* **Async-Signal Safety:**  The comments explicitly mention the need for async-signal safety, especially within the signal handler. This explains the careful avoidance of `malloc` and `stdio` in certain parts.
* **Demangling:**  It conditionally calls `DemangleSymbols` to make the output more readable.
* **Output Handling:** It uses the `BacktraceOutputHandler` interface to abstract the output mechanism.

**5. Analyzing Signal Handling (`StackDumpSignalHandler`, `EnableInProcessStackDumping`):**

* **`StackDumpSignalHandler`:**  This is the crucial function invoked when a specific signal occurs (like SIGSEGV, SIGABRT). It's designed to be async-signal safe. It prints information about the signal and then calls `debug::StackTrace().Print()` to dump the stack.
* **`EnableInProcessStackDumping`:** This function sets up signal handlers for various signals. When these signals occur, `StackDumpSignalHandler` will be invoked. The `WarmUpBacktrace()` call is also important here, aiming to prevent hangs during signal handling.

**6. Demangling Logic:**

The `DemangleSymbols` function is straightforward. It finds mangled symbol prefixes (`_Z`), extracts the mangled symbol, uses `abi::__cxa_demangle` to demangle it, and replaces the mangled symbol in the output string.

**7. `itoa_r` Logic:**

This function is a custom integer-to-string conversion. The comments highlight its async-signal safety requirement. The implementation handles negative numbers and padding.

**8. Addressing the Specific Instructions:**

* **File Extension (.tq):** The code is `.cc`, so this is not a Torque file.
* **Relationship to JavaScript:** The code is part of V8, the JavaScript engine. While this C++ code doesn't directly execute JavaScript, it's used for debugging and error reporting within the engine, which is critical for JavaScript execution. This leads to the example of an error in JavaScript triggering the C++ stack trace.
* **Code Logic Inference:** The example with `EnableInProcessStackDumping` and triggering a `SIGSEGV` illustrates the flow: signal -> handler -> stack trace.
* **Common Programming Errors:**  The signal handling aspect ties directly to common errors like segmentation faults (accessing invalid memory) or division by zero, which can trigger these signals.

**9. Structuring the Output:**

Finally, I organize the findings into the requested sections: Functionality, Torque Check, JavaScript Relationship, Logic Inference, and Common Errors, using the information gathered during the analysis. I ensure clarity and provide concrete examples where requested.

**Self-Correction/Refinement:**

During the process, I might have initially focused too much on the individual functions without grasping the overall flow. Recognizing the central role of `StackTrace` and the signal handling mechanism helped connect the pieces. Also, I needed to ensure I explicitly addressed each point in the original request, even the conditional ones (like the `.tq` check). I double-checked the async-signal safety requirements mentioned in the comments and how they influenced the implementation of certain functions.
The provided C++ source code, `v8/src/base/debug/stack_trace_posix.cc`, is responsible for capturing and displaying stack traces on POSIX-compliant operating systems (like Linux, macOS). Here's a breakdown of its functionality:

**Core Functionality:**

1. **Capturing Stack Traces:**
   - It uses the `backtrace()` function (from `execinfo.h`) to retrieve the call stack of the current thread. This function collects the return addresses of the functions in the call stack.
   - The captured stack frame addresses are stored in a member array `trace_`.

2. **Formatting and Displaying Stack Traces:**
   - **Demangling Symbols:** It attempts to demangle C++ symbol names using `abi::__cxa_demangle` to make the stack trace more human-readable (e.g., converting `_ZN3foo3barEv` to `foo::bar()`).
   - **Outputting to Standard Error:** The `Print()` method outputs the stack trace to standard error (stderr).
   - **Outputting to a Stream:** The `OutputToStream()` method allows directing the stack trace output to a specified `std::ostream`.
   - **Handling Output in Signal Handlers:**  It includes logic to output stack traces even within signal handlers, which requires careful attention to async-signal safety (avoiding `malloc`, `stdio`, etc.). It provides a custom `itoa_r` function for integer-to-string conversion that is async-signal safe.

3. **Signal Handling for Stack Dumps:**
   - **`EnableInProcessStackDumping()`:** This function sets up signal handlers for various signals like `SIGILL`, `SIGABRT`, `SIGFPE`, `SIGBUS`, `SIGSEGV`, and `SIGSYS`.
   - **`StackDumpSignalHandler()`:** This is the signal handler function. When one of the registered signals is received, this function is executed. It prints information about the signal and then uses the `StackTrace` class to print the current stack trace.
   - **Async-Signal Safety in Signal Handler:** The signal handler is carefully written to be async-signal safe, meaning it avoids operations that are not guaranteed to be safe to call within a signal handler (like dynamic memory allocation).
   - **`DisableSignalStackDump()`:** This function allows disabling the stack dumping behavior within signal handlers.

4. **Warming Up Backtrace:**
   - **`WarmUpBacktrace()`:** This function is called to pre-initialize the stack trace infrastructure. This is a performance optimization to avoid potential issues (like hangs due to `malloc` calls within `backtrace` during the first invocation) when a signal occurs unexpectedly.

**Torque Source Code Check:**

The file `v8/src/base/debug/stack_trace_posix.cc` ends with `.cc`, which indicates it's a **C++ source code file**, not a V8 Torque source code file. V8 Torque files typically have the `.tq` extension.

**Relationship with JavaScript and Examples:**

This code doesn't directly execute JavaScript. However, it plays a crucial role in the debugging and error reporting of the V8 JavaScript engine. When a serious error occurs within the V8 engine's C++ code (which underpins JavaScript execution), this code can be used to generate a stack trace to help developers understand the sequence of function calls leading to the error.

**JavaScript Example:**

While you won't directly interact with `stack_trace_posix.cc` from JavaScript, consider a scenario where a bug in V8's implementation of a JavaScript feature causes a crash. Here's a conceptual illustration:

```javascript
// Imagine this code somehow triggers a bug in V8's C++ implementation
function buggyFunction() {
  // ... some complex logic that exposes a V8 internal error ...
}

try {
  buggyFunction();
} catch (e) {
  console.error("An error occurred:", e);
  // At this point, if V8 is configured to dump stack traces on crashes,
  // the output from stack_trace_posix.cc would be visible (usually on stderr).
}
```

If V8 is built with stack dumping enabled (through `EnableInProcessStackDumping`), and `buggyFunction` triggers a signal like `SIGSEGV` due to an internal error, the `StackDumpSignalHandler` would be invoked, and the stack trace generated by this C++ code would be printed to the console (stderr). This stack trace would show the sequence of C++ function calls within V8 that led to the crash, aiding in debugging the V8 engine itself.

**Code Logic Inference (Hypothetical Example):**

**Assumption:** We've called `EnableInProcessStackDumping()` and then some code triggers a segmentation fault (`SIGSEGV`).

**Input:**  A signal `SIGSEGV` is received by the process.

**Output (to stderr):**

```
Received signal 11 SEGV_MAPERR 0x...
==== C stack trace ===============================

    [0x...]
    v8::internal::... ( ... )
    v8::... ( ... )
    ... more stack frames ...
[end of stack trace]
```

**Explanation:**

1. The operating system sends a `SIGSEGV` signal to the V8 process.
2. The `StackDumpSignalHandler` is invoked because it was registered for `SIGSEGV`.
3. The handler prints "Received signal 11 SEGV_MAPERR 0x...".
4. It then creates a `StackTrace` object.
5. The `StackTrace` constructor calls `backtrace()` to capture the call stack.
6. The `Print()` method is called, which iterates through the captured stack frames.
7. For each frame, it (optionally) demangles the symbol and prints the function name and address.
8. The output shows the sequence of C++ functions that were being executed when the segmentation fault occurred.

**Common Programming Errors Related to This Code (Indirectly):**

While this code itself is for debugging, the types of errors it helps diagnose in the V8 engine often stem from common C++ programming mistakes:

1. **Segmentation Faults (SIGSEGV):**  Accessing memory that the program doesn't have permission to access (e.g., dereferencing a null pointer, accessing memory beyond array bounds).
   ```c++
   int* ptr = nullptr;
   *ptr = 10; // This will likely cause a SIGSEGV.
   ```

2. **Bus Errors (SIGBUS):**  Accessing memory at an address that doesn't have the correct alignment for the data type being accessed. This is less common on modern architectures.

3. **Floating-Point Exceptions (SIGFPE):**  Errors during floating-point arithmetic, such as division by zero.
   ```c++
   double x = 1.0;
   double y = 0.0;
   double result = x / y; // This will likely cause a SIGFPE.
   ```

4. **Abnormal Termination (SIGABRT):**  Caused by calling the `abort()` function or by certain assertion failures.

5. **Illegal Instruction (SIGILL):**  Attempting to execute an invalid or privileged instruction.

These errors, when occurring within the V8 engine's C++ code, can trigger the signal handlers set up by `EnableInProcessStackDumping`, leading to the stack traces generated by `stack_trace_posix.cc`. This helps V8 developers pinpoint the exact location in the C++ code where the error originated.

### 提示词
```
这是目录为v8/src/base/debug/stack_trace_posix.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/debug/stack_trace_posix.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Slightly adapted for inclusion in V8.
// Copyright 2016 the V8 project authors. All rights reserved.

#include "src/base/debug/stack_trace.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#if V8_LIBC_GLIBC || V8_LIBC_BSD || V8_LIBC_UCLIBC || V8_OS_SOLARIS
#define HAVE_EXECINFO_H 1
#endif

#if HAVE_EXECINFO_H
#include <cxxabi.h>
#include <execinfo.h>
#endif
#if V8_OS_DARWIN
#include <AvailabilityMacros.h>
#endif

#include "src/base/build_config.h"
#include "src/base/free_deleter.h"
#include "src/base/logging.h"
#include "src/base/macros.h"

namespace v8 {
namespace base {
namespace debug {

namespace internal {

// POSIX doesn't define any async-signal safe function for converting
// an integer to ASCII. We'll have to define our own version.
// itoa_r() converts a (signed) integer to ASCII. It returns "buf", if the
// conversion was successful or nullptr otherwise. It never writes more than
// "sz" bytes. Output will be truncated as needed, and a NUL character is always
// appended.
char* itoa_r(intptr_t i, char* buf, size_t sz, int base, size_t padding);

}  // namespace internal

namespace {

volatile sig_atomic_t in_signal_handler = 0;
bool dump_stack_in_signal_handler = true;

// The prefix used for mangled symbols, per the Itanium C++ ABI:
// http://www.codesourcery.com/cxx-abi/abi.html#mangling
const char kMangledSymbolPrefix[] = "_Z";

// Characters that can be used for symbols, generated by Ruby:
// (('a'..'z').to_a+('A'..'Z').to_a+('0'..'9').to_a + ['_']).join
const char kSymbolCharacters[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

#if HAVE_EXECINFO_H
// Demangles C++ symbols in the given text. Example:
//
// "out/Debug/base_unittests(_ZN10StackTraceC1Ev+0x20) [0x817778c]"
// =>
// "out/Debug/base_unittests(StackTrace::StackTrace()+0x20) [0x817778c]"
void DemangleSymbols(std::string* text) {
  // Note: code in this function is NOT async-signal safe (std::string uses
  // malloc internally).


  std::string::size_type search_from = 0;
  while (search_from < text->size()) {
    // Look for the start of a mangled symbol, from search_from.
    std::string::size_type mangled_start =
        text->find(kMangledSymbolPrefix, search_from);
    if (mangled_start == std::string::npos) {
      break;  // Mangled symbol not found.
    }

    // Look for the end of the mangled symbol.
    std::string::size_type mangled_end =
        text->find_first_not_of(kSymbolCharacters, mangled_start);
    if (mangled_end == std::string::npos) {
      mangled_end = text->size();
    }
    std::string mangled_symbol =
        text->substr(mangled_start, mangled_end - mangled_start);

    // Try to demangle the mangled symbol candidate.
    int status = 0;
    std::unique_ptr<char, FreeDeleter> demangled_symbol(
        abi::__cxa_demangle(mangled_symbol.c_str(), nullptr, nullptr, &status));
    if (status == 0) {  // Demangling is successful.
      // Remove the mangled symbol.
      text->erase(mangled_start, mangled_end - mangled_start);
      // Insert the demangled symbol.
      text->insert(mangled_start, demangled_symbol.get());
      // Next time, we'll start right after the demangled symbol we inserted.
      search_from = mangled_start + strlen(demangled_symbol.get());
    } else {
      // Failed to demangle.  Retry after the "_Z" we just found.
      search_from = mangled_start + 2;
    }
  }
}
#endif  // HAVE_EXECINFO_H

class BacktraceOutputHandler {
 public:
  virtual void HandleOutput(const char* output) = 0;

 protected:
  virtual ~BacktraceOutputHandler() = default;
};

#if HAVE_EXECINFO_H
void OutputPointer(void* pointer, BacktraceOutputHandler* handler) {
  // This should be more than enough to store a 64-bit number in hex:
  // 16 hex digits + 1 for null-terminator.
  char buf[17] = {'\0'};
  handler->HandleOutput("0x");
  internal::itoa_r(reinterpret_cast<intptr_t>(pointer), buf, sizeof(buf), 16,
                   12);
  handler->HandleOutput(buf);
}

void ProcessBacktrace(void* const* trace, size_t size,
                      BacktraceOutputHandler* handler) {
  // NOTE: This code MUST be async-signal safe (it's used by in-process
  // stack dumping signal handler). NO malloc or stdio is allowed here.
  handler->HandleOutput("\n");
  handler->HandleOutput("==== C stack trace ===============================\n");
  handler->HandleOutput("\n");

  bool printed = false;

  // Below part is async-signal unsafe (uses malloc), so execute it only
  // when we are not executing the signal handler.
  if (in_signal_handler == 0) {
    std::unique_ptr<char*, FreeDeleter> trace_symbols(
        backtrace_symbols(trace, static_cast<int>(size)));
    if (trace_symbols) {
      for (size_t i = 0; i < size; ++i) {
        std::string trace_symbol = trace_symbols.get()[i];
        DemangleSymbols(&trace_symbol);
        handler->HandleOutput("    ");
        handler->HandleOutput(trace_symbol.c_str());
        handler->HandleOutput("\n");
      }

      printed = true;
    }
  }

  if (!printed) {
    for (size_t i = 0; i < size; ++i) {
      handler->HandleOutput(" [");
      OutputPointer(trace[i], handler);
      handler->HandleOutput("]\n");
    }
  }
}
#endif  // HAVE_EXECINFO_H

void PrintToStderr(const char* output) {
  // NOTE: This code MUST be async-signal safe (it's used by in-process
  // stack dumping signal handler). NO malloc or stdio is allowed here.
  ssize_t return_val = write(STDERR_FILENO, output, strlen(output));
  USE(return_val);
}

void StackDumpSignalHandler(int signal, siginfo_t* info, void* void_context) {
  // NOTE: This code MUST be async-signal safe.
  // NO malloc or stdio is allowed here.

  // Record the fact that we are in the signal handler now, so that the rest
  // of StackTrace can behave in an async-signal-safe manner.
  in_signal_handler = 1;

  PrintToStderr("Received signal ");
  char buf[1024] = {0};
  internal::itoa_r(signal, buf, sizeof(buf), 10, 0);
  PrintToStderr(buf);
  if (signal == SIGBUS) {
    if (info->si_code == BUS_ADRALN)
      PrintToStderr(" BUS_ADRALN ");
    else if (info->si_code == BUS_ADRERR)
      PrintToStderr(" BUS_ADRERR ");
    else if (info->si_code == BUS_OBJERR)
      PrintToStderr(" BUS_OBJERR ");
    else
      PrintToStderr(" <unknown> ");
  } else if (signal == SIGFPE) {
    if (info->si_code == FPE_FLTDIV)
      PrintToStderr(" FPE_FLTDIV ");
    else if (info->si_code == FPE_FLTINV)
      PrintToStderr(" FPE_FLTINV ");
    else if (info->si_code == FPE_FLTOVF)
      PrintToStderr(" FPE_FLTOVF ");
    else if (info->si_code == FPE_FLTRES)
      PrintToStderr(" FPE_FLTRES ");
    else if (info->si_code == FPE_FLTSUB)
      PrintToStderr(" FPE_FLTSUB ");
    else if (info->si_code == FPE_FLTUND)
      PrintToStderr(" FPE_FLTUND ");
    else if (info->si_code == FPE_INTDIV)
      PrintToStderr(" FPE_INTDIV ");
    else if (info->si_code == FPE_INTOVF)
      PrintToStderr(" FPE_INTOVF ");
    else
      PrintToStderr(" <unknown> ");
  } else if (signal == SIGILL) {
    if (info->si_code == ILL_BADSTK)
      PrintToStderr(" ILL_BADSTK ");
    else if (info->si_code == ILL_COPROC)
      PrintToStderr(" ILL_COPROC ");
    else if (info->si_code == ILL_ILLOPN)
      PrintToStderr(" ILL_ILLOPN ");
    else if (info->si_code == ILL_ILLADR)
      PrintToStderr(" ILL_ILLADR ");
    else if (info->si_code == ILL_ILLTRP)
      PrintToStderr(" ILL_ILLTRP ");
    else if (info->si_code == ILL_PRVOPC)
      PrintToStderr(" ILL_PRVOPC ");
    else if (info->si_code == ILL_PRVREG)
      PrintToStderr(" ILL_PRVREG ");
    else
      PrintToStderr(" <unknown> ");
  } else if (signal == SIGSEGV) {
    if (info->si_code == SEGV_MAPERR)
      PrintToStderr(" SEGV_MAPERR ");
    else if (info->si_code == SEGV_ACCERR)
      PrintToStderr(" SEGV_ACCERR ");
    else
      PrintToStderr(" <unknown> ");
  }
  if (signal == SIGBUS || signal == SIGFPE || signal == SIGILL ||
      signal == SIGSEGV) {
    internal::itoa_r(reinterpret_cast<intptr_t>(info->si_addr), buf,
                     sizeof(buf), 16, 12);
    PrintToStderr(buf);
  }
  PrintToStderr("\n");
  if (dump_stack_in_signal_handler) {
    debug::StackTrace().Print();
    PrintToStderr("[end of stack trace]\n");
  }

  if (::signal(signal, SIG_DFL) == SIG_ERR) _exit(1);
}

class PrintBacktraceOutputHandler : public BacktraceOutputHandler {
 public:
  PrintBacktraceOutputHandler() = default;
  PrintBacktraceOutputHandler(const PrintBacktraceOutputHandler&) = delete;
  PrintBacktraceOutputHandler& operator=(const PrintBacktraceOutputHandler&) =
      delete;

  void HandleOutput(const char* output) override {
    // NOTE: This code MUST be async-signal safe (it's used by in-process
    // stack dumping signal handler). NO malloc or stdio is allowed here.
    PrintToStderr(output);
  }
};

class StreamBacktraceOutputHandler : public BacktraceOutputHandler {
 public:
  explicit StreamBacktraceOutputHandler(std::ostream* os) : os_(os) {}
  StreamBacktraceOutputHandler(const StreamBacktraceOutputHandler&) = delete;
  StreamBacktraceOutputHandler& operator=(const StreamBacktraceOutputHandler&) =
      delete;

  void HandleOutput(const char* output) override { (*os_) << output; }

 private:
  std::ostream* os_;
};

void WarmUpBacktrace() {
  // Warm up stack trace infrastructure. It turns out that on the first
  // call glibc initializes some internal data structures using pthread_once,
  // and even backtrace() can call malloc(), leading to hangs.
  //
  // Example stack trace snippet (with tcmalloc):
  //
  // #8  0x0000000000a173b5 in tc_malloc
  //             at ./third_party/tcmalloc/chromium/src/debugallocation.cc:1161
  // #9  0x00007ffff7de7900 in _dl_map_object_deps at dl-deps.c:517
  // #10 0x00007ffff7ded8a9 in dl_open_worker at dl-open.c:262
  // #11 0x00007ffff7de9176 in _dl_catch_error at dl-error.c:178
  // #12 0x00007ffff7ded31a in _dl_open (file=0x7ffff625e298 "libgcc_s.so.1")
  //             at dl-open.c:639
  // #13 0x00007ffff6215602 in do_dlopen at dl-libc.c:89
  // #14 0x00007ffff7de9176 in _dl_catch_error at dl-error.c:178
  // #15 0x00007ffff62156c4 in dlerror_run at dl-libc.c:48
  // #16 __GI___libc_dlopen_mode at dl-libc.c:165
  // #17 0x00007ffff61ef8f5 in init
  //             at ../sysdeps/x86_64/../ia64/backtrace.c:53
  // #18 0x00007ffff6aad400 in pthread_once
  //             at ../nptl/sysdeps/unix/sysv/linux/x86_64/pthread_once.S:104
  // #19 0x00007ffff61efa14 in __GI___backtrace
  //             at ../sysdeps/x86_64/../ia64/backtrace.c:104
  // #20 0x0000000000752a54 in base::debug::StackTrace::StackTrace
  //             at base/debug/stack_trace_posix.cc:175
  // #21 0x00000000007a4ae5 in
  //             base::(anonymous namespace)::StackDumpSignalHandler
  //             at base/process_util_posix.cc:172
  // #22 <signal handler called>
  StackTrace stack_trace;
}

}  // namespace

bool EnableInProcessStackDumping() {
  // When running in an application, our code typically expects SIGPIPE
  // to be ignored.  Therefore, when testing that same code, it should run
  // with SIGPIPE ignored as well.
  struct sigaction sigpipe_action;
  memset(&sigpipe_action, 0, sizeof(sigpipe_action));
  sigpipe_action.sa_handler = SIG_IGN;
  sigemptyset(&sigpipe_action.sa_mask);
  bool success = (sigaction(SIGPIPE, &sigpipe_action, nullptr) == 0);

  // Avoid hangs during backtrace initialization, see above.
  WarmUpBacktrace();

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  // Use SA_ONSTACK so that iff an alternate stack has been registered, the
  // handler will run on that stack instead of the default stack. This can be
  // useful for example if the stack pointer gets corrupted or in case of stack
  // overflows, since that might prevent the handler from running properly.
  action.sa_flags = SA_RESETHAND | SA_SIGINFO | SA_ONSTACK;
  action.sa_sigaction = &StackDumpSignalHandler;
  sigemptyset(&action.sa_mask);

  success &= (sigaction(SIGILL, &action, nullptr) == 0);
  success &= (sigaction(SIGABRT, &action, nullptr) == 0);
  success &= (sigaction(SIGFPE, &action, nullptr) == 0);
  success &= (sigaction(SIGBUS, &action, nullptr) == 0);
  success &= (sigaction(SIGSEGV, &action, nullptr) == 0);
  success &= (sigaction(SIGSYS, &action, nullptr) == 0);

  dump_stack_in_signal_handler = true;

  return success;
}

void DisableSignalStackDump() {
  dump_stack_in_signal_handler = false;
}

StackTrace::StackTrace() {
  // NOTE: This code MUST be async-signal safe (it's used by in-process
  // stack dumping signal handler). NO malloc or stdio is allowed here.

#if HAVE_EXECINFO_H
  // Though the backtrace API man page does not list any possible negative
  // return values, we take no chance.
  count_ = static_cast<size_t>(backtrace(trace_, arraysize(trace_)));
#else
  count_ = 0;
#endif
}

void StackTrace::Print() const {
  // NOTE: This code MUST be async-signal safe (it's used by in-process
  // stack dumping signal handler). NO malloc or stdio is allowed here.

#if HAVE_EXECINFO_H
  PrintBacktraceOutputHandler handler;
  ProcessBacktrace(trace_, count_, &handler);
#endif
}

void StackTrace::OutputToStream(std::ostream* os) const {
#if HAVE_EXECINFO_H
  StreamBacktraceOutputHandler handler(os);
  ProcessBacktrace(trace_, count_, &handler);
#endif
}

namespace internal {

// NOTE: code from sandbox/linux/seccomp-bpf/demo.cc.
char* itoa_r(intptr_t i, char* buf, size_t sz, int base, size_t padding) {
  // Make sure we can write at least one NUL byte.
  size_t n = 1;
  if (n > sz) return nullptr;

  if (base < 2 || base > 16) {
    buf[0] = '\0';
    return nullptr;
  }

  char* start = buf;

  uintptr_t j = i;

  // Handle negative numbers (only for base 10).
  if (i < 0 && base == 10) {
    // This does "j = -i" while avoiding integer overflow.
    j = static_cast<uintptr_t>(-(i + 1)) + 1;

    // Make sure we can write the '-' character.
    if (++n > sz) {
      buf[0] = '\0';
      return nullptr;
    }
    *start++ = '-';
  }

  // Loop until we have converted the entire number. Output at least one
  // character (i.e. '0').
  char* ptr = start;
  do {
    // Make sure there is still enough space left in our output buffer.
    if (++n > sz) {
      buf[0] = '\0';
      return nullptr;
    }

    // Output the next digit.
    *ptr++ = "0123456789abcdef"[j % base];
    j /= base;

    if (padding > 0) padding--;
  } while (j > 0 || padding > 0);

  // Terminate the output with a NUL character.
  *ptr = '\0';

  // Conversion to ASCII actually resulted in the digits being in reverse
  // order. We can't easily generate them in forward order, as we can't tell
  // the number of characters needed until we are done converting.
  // So, now, we reverse the string (except for the possible "-" sign).
  while (--ptr > start) {
    char ch = *ptr;
    *ptr = *start;
    *start++ = ch;
  }
  return buf;
}

}  // namespace internal

}  // namespace debug
}  // namespace base
}  // namespace v8
```