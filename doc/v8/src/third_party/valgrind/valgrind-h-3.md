Response:
The user wants to understand the functionality of a C/C++ header file (`valgrind.h`) located within the V8 JavaScript engine's source code.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core purpose:** The file name `valgrind.h` strongly suggests that this header is related to Valgrind, a powerful tool for memory debugging and profiling.

2. **Scan for Valgrind-specific elements:** The code contains macros like `VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11`. This confirms the connection to Valgrind. The macros seem to be designed for calling functions while informing Valgrind about the call.

3. **Analyze the `CALL_FN_W_*` macros:** These macros are the core of the provided code snippet. They have names like `CALL_FN_W_W`, `CALL_FN_W_WW`, etc. The `W` likely stands for "word" (representing an argument), and the number of `W`s indicates the number of arguments the function being called takes.

4. **Dissect a single macro (e.g., `CALL_FN_W_W`):**
   - It takes a return value variable (`lval`), the original function information (`orig`), and one argument (`arg1`).
   - It defines a `OrigFn` struct (not shown in the snippet but implied to hold function address and potentially other metadata).
   - It creates an argument vector `_argvec`.
   - It uses inline assembly (`__asm__ volatile`) to:
     - Move the address of the argument vector into a register (`mr 11,%1`).
     - Load the argument from the vector into a specific register (`lwz 3,4(11)` on ppc32, `ld 3, 8(11)` on ppc64). The register usage (r3, r4, r5, etc.) suggests an Application Binary Interface (ABI) convention for passing arguments.
     - Load the target function address (`lwz 11,0(11)` on ppc32, `ld  11, 0(11)` on ppc64).
     - Use `VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11` to perform the function call. The `NOREDIR` part suggests that Valgrind should not follow this call for certain instrumentation purposes.
     - Move the return value from a register back into the `_res` variable (`mr %0,3`).
     - Cast the result to the correct type.

5. **Generalize the macro analysis:** The other `CALL_FN_W_*` macros follow a similar pattern, adjusting the number of arguments loaded into registers. For a larger number of arguments (like `CALL_FN_W_9W` and above), they start using the stack to pass arguments, indicated by instructions like `addi 1,1,-16` (adjusting the stack pointer) and `stw 3,8(1)` (storing to the stack).

6. **Infer the purpose of the header file:** Based on the macros, the header file provides a way to call functions in a manner that is visible and understandable to Valgrind. This likely helps Valgrind accurately track memory operations and detect errors within these function calls.

7. **Consider the file path:** `v8/src/third_party/valgrind/valgrind.h` indicates that this is a third-party library integration. V8 uses Valgrind for its own internal testing and debugging.

8. **Address the ".tq" question:** If the file ended in `.tq`, it would be a Torque source file, a domain-specific language used in V8 for defining built-in functions. This is not the case here.

9. **Relate to JavaScript functionality:** Since Valgrind is a debugging tool, its direct relationship to JavaScript functionality is indirect. It helps ensure the underlying C++ code (which executes the JavaScript) is correct. A JavaScript example would demonstrate how memory errors in the C++ backend can manifest as unexpected behavior in JavaScript.

10. **Consider code logic and examples:** The macros themselves embody the code logic. Examples should illustrate how these macros might be used to wrap function calls.

11. **Think about common programming errors:**  Memory errors are classic C/C++ issues. Examples should showcase scenarios like memory leaks or use-after-free errors that Valgrind can detect.

12. **Summarize the functionality (for part 4 of 8):**  Focus on the core purpose: providing Valgrind-aware function call wrappers, especially for scenarios where direct calls might not be fully instrumented by Valgrind.

13. **Structure the answer:** Organize the information logically, covering each aspect of the user's request. Use clear headings and examples.

By following these steps, the detailed and informative answer can be constructed. The key is to recognize the Valgrind connection and then systematically analyze the provided code snippets.
```cpp
, "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_5W(lval, orig, arg1,arg2,arg3,arg4,arg5)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[6];
      volatile unsigned long _res;
      _argvec[0] = (unsigned long)_orig.nraddr;
      _argvec[1] = (unsigned long)arg1;
      _argvec[2] = (unsigned long)arg2;
      _argvec[3] = (unsigned long)arg3;
      _argvec[4] = (unsigned long)arg4;
      _argvec[5] = (unsigned long)arg5;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "lwz 3,4(11)\n\t"   /* arg1->r3 */
         "lwz 4,8(11)\n\t"
         "lwz 5,12(11)\n\t"
         "lwz 6,16(11)\n\t"  /* arg4->r6 */
         "lwz 7,20(11)\n\t"
         "lwz 11,0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "mr %0,3"
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[0])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_6W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[7];
      volatile unsigned long _res;
      _argvec[0] = (unsigned long)_orig.nraddr;
      _argvec[1] = (unsigned long)arg1;
      _argvec[2] = (unsigned long)arg2;
      _argvec[3] = (unsigned long)arg3;
      _argvec[4] = (unsigned long)arg4;
      _argvec[5] = (unsigned long)arg5;
      _argvec[6] = (unsigned long)arg6;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "lwz 3,4(11)\n\t"   /* arg1->r3 */
         "lwz 4,8(11)\n\t"
         "lwz 5,12(11)\n\t"
         "lwz 6,16(11)\n\t"  /* arg4->r6 */
         "lwz 7,20(11)\n\t"
         "lwz 8,24(11)\n\t"
         "lwz 11,0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "mr %0,3"
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[0])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_7W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,
                                 arg7)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[8];
      volatile unsigned long _res;
      _argvec[0] = (unsigned long)_orig.nraddr;
      _argvec[1] = (unsigned long)arg1;
      _argvec[2] = (unsigned long)arg2;
      _argvec[3] = (unsigned long)arg3;
      _argvec[4] = (unsigned long)arg4;
      _argvec[5] = (unsigned long)arg5;
      _argvec[6] = (unsigned long)arg6;
      _argvec[7] = (unsigned long)arg7;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "lwz 3,4(11)\n\t"   /* arg1->r3 */
         "lwz 4,8(11)\n\t"
         "lwz 5,12(11)\n\t"
         "lwz 6,16(11)\n\t"  /* arg4->r6 */
         "lwz 7,20(11)\n\t"
         "lwz 8,24(11)\n\t"
         "lwz 9,28(11)\n\t"
         "lwz 11,0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "mr %0,3"
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[0])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_8W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,
                                 arg7,arg8)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[9];
      volatile unsigned long _res;
      _argvec[0] = (unsigned long)_orig.nraddr;
      _argvec[1] = (unsigned long)arg1;
      _argvec[2] = (unsigned long)arg2;
      _argvec[3] = (unsigned long)arg3;
      _argvec[4] = (unsigned long)arg4;
      _argvec[5] = (unsigned long)arg5;
      _argvec[6] = (unsigned long)arg6;
      _argvec[7] = (unsigned long)arg7;
      _argvec[8] = (unsigned long)arg8;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "lwz 3,4(11)\n\t"   /* arg1->r3 */
         "lwz 4,8(11)\n\t"
         "lwz 5,12(11)\n\t"
         "lwz 6,16(11)\n\t"  /* arg4->r6 */
         "lwz 7,20(11)\n\t"
         "lwz 8,24(11)\n\t"
         "lwz 9,28(11)\n\t"
         "lwz 10,32(11)\n\t" /* arg8->r10 */
         "lwz 11,0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "mr %0,3"
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[0])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_9W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,
                                 arg7,arg8,arg9)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[10];
      volatile unsigned long _res;
      _argvec[0] = (unsigned long)_orig.nraddr;
      _argvec[1] = (unsigned long)arg1;
      _argvec[2] = (unsigned long)arg2;
      _argvec[3] = (unsigned long)arg3;
      _argvec[4] = (unsigned long)arg4;
      _argvec[5] = (unsigned long)arg5;
      _argvec[6] = (unsigned long)arg6;
      _argvec[7] = (unsigned long)arg7;
      _argvec[8] = (unsigned long)arg8;
      _argvec[9] = (unsigned long)arg9;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "addi 1,1,-16\n\t"
         /* arg9 */
         "lwz 3,36(11)\n\t"
         "stw 3,8(1)\n\t"
         /* args1-8 */
         "lwz 3,4(11)\n\t"   /* arg1->r3 */
         "lwz 4,8(11)\n\t"
         "lwz 5,12(11)\n\t"
         "lwz 6,16(11)\n\t"  /* arg4->r6 */
         "lwz 7,20(11)\n\t"
         "lwz 8,24(11)\n\t"
         "lwz 9,28(11)\n\t"
         "lwz 10,32(11)\n\t" /* arg8->r10 */
         "lwz 11,0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "addi 1,1,16\n\t"
         "mr %0,3"
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[0])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_10W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,
                                  arg7,arg8,arg9,arg10)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[11];
      volatile unsigned long _res;
      _argvec[0] = (unsigned long)_orig.nraddr;
      _argvec[1] = (unsigned long)arg1;
      _argvec[2] = (unsigned long)arg2;
      _argvec[3] = (unsigned long)arg3;
      _argvec[4] = (unsigned long)arg4;
      _argvec[5] = (unsigned long)arg5;
      _argvec[6] = (unsigned long)arg6;
      _argvec[7] = (unsigned long)arg7;
      _argvec[8] = (unsigned long)arg8;
      _argvec[9] = (unsigned long)arg9;
      _argvec[10] = (unsigned long)arg10;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "addi 1,1,-16\n\t"
         /* arg10 */
         "lwz 3,40(11)\n\t"
         "stw 3,12(1)\n\t"
         /* arg9 */
         "lwz 3,36(11)\n\t"
         "stw 3,8(1)\n\t"
         /* args1-8 */
         "lwz 3,4(11)\n\t"   /* arg1->r3 */
         "lwz 4,8(11)\n\t"
         "lwz 5,12(11)\n\t"
         "lwz 6,16(11)\n\t"  /* arg4->r6 */
         "lwz 7,20(11)\n\t"
         "lwz 8,24(11)\n\t"
         "lwz 9,28(11)\n\t"
         "lwz 10,32(11)\n\t" /* arg8->r10 */
         "lwz 11,0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "addi 1,1,16\n\t"
         "mr %0,3"
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[0])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_11W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,
                                  arg7,arg8,arg9,arg10,arg11)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[12];
      volatile unsigned long _res;
      _argvec[0] = (unsigned long)_orig.nraddr;
      _argvec[1] = (unsigned long)arg1;
      _argvec[2] = (unsigned long)arg2;
      _argvec[3] = (unsigned long)arg3;
      _argvec[4] = (unsigned long)arg4;
      _argvec[5] = (unsigned long)arg5;
      _argvec[6] = (unsigned long)arg6;
      _argvec[7] = (unsigned long)arg7;
      _argvec[8] = (unsigned long)arg8;
      _argvec[9] = (unsigned long)arg9;
      _argvec[10] = (unsigned long)arg10;
      _argvec[11] = (unsigned long)arg11;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "addi 1,1,-32\n\t"
         /* arg11 */
         "lwz 3,44(11)\n\t"
         "stw 3,16(1)\n\t"
         /* arg10 */
         "lwz 3,40(11)\n\t"
         "stw 3,12(1)\n\t"
         /* arg9 */
         "lwz 3,36(11)\n\t"
         "stw 3,8(1)\n\t"
         /* args1-8 */
         "lwz 3,4(11)\n\t"   /* arg1->r3 */
         "lwz 4,8(11)\n\t"
         "lwz 5,12(11)\n\t"
         "lwz 6,16(11)\n\t"  /* arg4->r6 */
         "lwz 7,20(11)\n\t"
         "lwz 8,24(11)\n\t"
         "lwz 9,28(11)\n\t"
         "lwz 10,32(11)\n\t" /* arg8->r10 */
         "lwz 11,0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "addi 1,1,32\n\t"
         "mr %0,3"
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[0])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_12W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,
                                arg7,arg8,arg9,arg10,arg11,arg12)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[13];
      volatile unsigned long _res;
      _argvec[0] = (unsigned long)_orig.nraddr;
      _argvec[1] = (unsigned long)arg1;
      _argvec[2] = (unsigned long)arg2;
      _argvec[3] = (unsigned long)arg3;
      _argvec[4] = (unsigned long)arg4;
      _argvec[5] = (unsigned long)arg5;
      _argvec[6] = (unsigned long)arg6;
      _argvec[7] = (unsigned long)arg7;
      _argvec[8] = (unsigned long)arg8;
      _argvec[9] = (unsigned long)arg9;
      _argvec[10] = (unsigned long)arg10;
      _argvec[11] = (unsigned long)arg11;
      _argvec[12] = (unsigned long)arg12;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "addi 1,1,-32\n\t"
         /* arg12 */
         "lwz 3,48(11)\n\t"
         "stw 3,20(1)\n\t"
         /* arg11 */
         "lwz 3,44(11)\n\t"
         "stw 3,16(1)\n\t"
         /* arg10 */
         "lwz 3,40(11)\n\t"
         "stw 3,12(1)\n\t"
         /* arg9 */
         "lwz 3,36(11)\n\t"
         "stw 3,8(1)\n\t"
         /* args1-8 */
         "lwz 3,4(11)\n\t"   /* arg1->r3 */
         "lwz 4,8(11)\n\t"
         "lwz 5,12(11)\n\t"
         "lwz 6,16(11)\n\t"  /* arg4->r6 */
         "lwz 7,20(11)\n\t"
         "lwz 8,24(11)\n\t"
         "lwz 9,28(11)\n\t"
         "lwz 10,32(11)\n\t" /* arg8->r10 */
         "lwz 11,0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "addi 1,1,32\n\t"
         "mr %0,3"
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[0])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#endif /* PLAT_ppc32_linux */

/* ------------------------ ppc64-linux ------------------------ */

#if defined(PLAT_ppc64_linux)

/* ARGREGS: r3 r4 r5 r6 r7 r8 r9 r10 (the rest on stack somewhere) */

/* These regs are trashed by the hidden call. */
#define __CALLER_SAVED_REGS                                       \
   "lr", "ctr", "xer",                                            \
   "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7",        \
   "r0", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",   \
   "r11", "r12", "r13"

/* These CALL_FN_ macros assume that on ppc64-linux, sizeof(unsigned
   long) == 8. */

#define CALL_FN_W_v(lval, orig)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[3+0];
      volatile unsigned long _res;
      /* _argvec[0] holds current r2 across the call */
      _argvec[1] = (unsigned long)_orig.r2;
      _argvec[2] = (unsigned long)_orig.nraddr;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "std 2,-16(11)\n\t"  /* save tocptr */
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */
         "ld  11, 0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "mr 11,%1\n\t"
         "mr %0,3\n\t"
         "ld 2,-16(11)" /* restore tocptr */
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[2])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_W(lval, orig, arg1)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[3+1];
      volatile unsigned long _res;
      /* _argvec[0] holds current r2 across the call */
      _argvec[1]   = (unsigned long)_orig.r2;
      _argvec[2]   = (unsigned long)_orig.nraddr;
      _argvec[2+1] = (unsigned long)arg1;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "std 2,-16(11)\n\t"  /* save tocptr */
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */
         "ld   3, 8(11)\n\t"  /* arg1->r3 */
         "ld  11, 0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "mr 11,%1\n\t"
         "mr %0,3\n\t"
         "ld 2,-16(11)" /* restore tocptr */
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[2])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_WW(lval, orig, arg1,arg2)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[3+2];
      volatile unsigned long _res;
      /* _argvec[0] holds current r2 across the call */
      _argvec[1]   = (unsigned long)_orig.r2;
      _argvec[2]   = (unsigned long)_orig.nraddr;
      _argvec[2+1] = (unsigned long)arg1;
      _argvec[2+2] = (unsigned long)arg2;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "std 2,-16(11)\n\t"  /* save tocptr */
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */
         "ld   3, 8(11)\n\t"  /* arg1->r3 */
         "ld   4, 16(11)\n\t" /* arg2->r4 */
         "ld  11, 0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "mr 11,%1\n\t"
         "mr %0,3\n\t"
         "ld 2,-16(11)" /* restore tocptr */
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[2])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_WWW(lval, orig, arg1,arg2,arg3)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[3+3];
      volatile unsigned long _res;
      /* _argvec[0] holds current r2 across the call */
      _argvec[1]   = (unsigned long)_orig.r2;
      _argvec[2]   = (unsigned long)_orig.nraddr;
      _argvec[2+1] = (unsigned long)arg1;
      _argvec[2+2] = (unsigned long)arg2;
      _argvec[2+3] = (unsigned long)arg3;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "std 2,-16(11)\n\t"  /* save tocptr */
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */
         "ld   3, 8(11)\n\t"  /* arg1->r3 */
         "ld   4, 16(11)\n\t" /* arg2->r4 */
         "ld   5, 24(11)\n\t" /* arg3->r5 */
         "ld  11, 0(11)\n\t"  /* target->r11 */
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11
         "mr 11,%1\n\t"
         "mr %0,3\n\t"
         "ld 2,-16(11)" /* restore tocptr */
         : /*out*/   "=r" (_res)
         : /*in*/    "r" (&_argvec[2])
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS
      );
      lval = (__typeof__(lval)) _res;
   } while (0)

#define CALL_FN_W_WWWW(lval, orig, arg1,arg2,arg3,arg4)
   do {
      volatile OrigFn        _orig = (orig);
      volatile unsigned long _argvec[3+4];
      volatile unsigned long _res;
      /* _argvec[0] holds current r2 across the call */
      _argvec[1]   = (unsigned long)_orig.r2;
      _argvec[2]   = (unsigned long)_orig.nraddr;
      _argvec[2+1] = (unsigned long)arg1;
      _argvec[2+2] = (unsigned long)arg2;
      _argvec[2+3] = (unsigned long)arg3;
      _argvec[2+4] = (unsigned long)arg4;
      __asm__ volatile(
         "mr 11,%1\n\t"
         "std 2,-16(11)\n\t"  /* save tocptr */
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */
         "ld   3, 8(11)\n\t"  /* arg1
### 提示词
```
这是目录为v8/src/third_party/valgrind/valgrind.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/third_party/valgrind/valgrind.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```c
, "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_WWWW(lval, orig, arg1,arg2,arg3,arg4)           \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[5];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)arg1;                           \
      _argvec[2] = (unsigned long)arg2;                           \
      _argvec[3] = (unsigned long)arg3;                           \
      _argvec[4] = (unsigned long)arg4;                           \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "lwz 3,4(11)\n\t"   /* arg1->r3 */                       \
         "lwz 4,8(11)\n\t"                                        \
         "lwz 5,12(11)\n\t"                                       \
         "lwz 6,16(11)\n\t"  /* arg4->r6 */                       \
         "lwz 11,0(11)\n\t"  /* target->r11 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr %0,3"                                                \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_5W(lval, orig, arg1,arg2,arg3,arg4,arg5)        \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[6];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)arg1;                           \
      _argvec[2] = (unsigned long)arg2;                           \
      _argvec[3] = (unsigned long)arg3;                           \
      _argvec[4] = (unsigned long)arg4;                           \
      _argvec[5] = (unsigned long)arg5;                           \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "lwz 3,4(11)\n\t"   /* arg1->r3 */                       \
         "lwz 4,8(11)\n\t"                                        \
         "lwz 5,12(11)\n\t"                                       \
         "lwz 6,16(11)\n\t"  /* arg4->r6 */                       \
         "lwz 7,20(11)\n\t"                                       \
         "lwz 11,0(11)\n\t"  /* target->r11 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr %0,3"                                                \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_6W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6)   \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[7];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)arg1;                           \
      _argvec[2] = (unsigned long)arg2;                           \
      _argvec[3] = (unsigned long)arg3;                           \
      _argvec[4] = (unsigned long)arg4;                           \
      _argvec[5] = (unsigned long)arg5;                           \
      _argvec[6] = (unsigned long)arg6;                           \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "lwz 3,4(11)\n\t"   /* arg1->r3 */                       \
         "lwz 4,8(11)\n\t"                                        \
         "lwz 5,12(11)\n\t"                                       \
         "lwz 6,16(11)\n\t"  /* arg4->r6 */                       \
         "lwz 7,20(11)\n\t"                                       \
         "lwz 8,24(11)\n\t"                                       \
         "lwz 11,0(11)\n\t"  /* target->r11 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr %0,3"                                                \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_7W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7)                            \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[8];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)arg1;                           \
      _argvec[2] = (unsigned long)arg2;                           \
      _argvec[3] = (unsigned long)arg3;                           \
      _argvec[4] = (unsigned long)arg4;                           \
      _argvec[5] = (unsigned long)arg5;                           \
      _argvec[6] = (unsigned long)arg6;                           \
      _argvec[7] = (unsigned long)arg7;                           \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "lwz 3,4(11)\n\t"   /* arg1->r3 */                       \
         "lwz 4,8(11)\n\t"                                        \
         "lwz 5,12(11)\n\t"                                       \
         "lwz 6,16(11)\n\t"  /* arg4->r6 */                       \
         "lwz 7,20(11)\n\t"                                       \
         "lwz 8,24(11)\n\t"                                       \
         "lwz 9,28(11)\n\t"                                       \
         "lwz 11,0(11)\n\t"  /* target->r11 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr %0,3"                                                \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_8W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7,arg8)                       \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[9];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)arg1;                           \
      _argvec[2] = (unsigned long)arg2;                           \
      _argvec[3] = (unsigned long)arg3;                           \
      _argvec[4] = (unsigned long)arg4;                           \
      _argvec[5] = (unsigned long)arg5;                           \
      _argvec[6] = (unsigned long)arg6;                           \
      _argvec[7] = (unsigned long)arg7;                           \
      _argvec[8] = (unsigned long)arg8;                           \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "lwz 3,4(11)\n\t"   /* arg1->r3 */                       \
         "lwz 4,8(11)\n\t"                                        \
         "lwz 5,12(11)\n\t"                                       \
         "lwz 6,16(11)\n\t"  /* arg4->r6 */                       \
         "lwz 7,20(11)\n\t"                                       \
         "lwz 8,24(11)\n\t"                                       \
         "lwz 9,28(11)\n\t"                                       \
         "lwz 10,32(11)\n\t" /* arg8->r10 */                      \
         "lwz 11,0(11)\n\t"  /* target->r11 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr %0,3"                                                \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_9W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7,arg8,arg9)                  \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[10];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)arg1;                           \
      _argvec[2] = (unsigned long)arg2;                           \
      _argvec[3] = (unsigned long)arg3;                           \
      _argvec[4] = (unsigned long)arg4;                           \
      _argvec[5] = (unsigned long)arg5;                           \
      _argvec[6] = (unsigned long)arg6;                           \
      _argvec[7] = (unsigned long)arg7;                           \
      _argvec[8] = (unsigned long)arg8;                           \
      _argvec[9] = (unsigned long)arg9;                           \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "addi 1,1,-16\n\t"                                       \
         /* arg9 */                                               \
         "lwz 3,36(11)\n\t"                                       \
         "stw 3,8(1)\n\t"                                         \
         /* args1-8 */                                            \
         "lwz 3,4(11)\n\t"   /* arg1->r3 */                       \
         "lwz 4,8(11)\n\t"                                        \
         "lwz 5,12(11)\n\t"                                       \
         "lwz 6,16(11)\n\t"  /* arg4->r6 */                       \
         "lwz 7,20(11)\n\t"                                       \
         "lwz 8,24(11)\n\t"                                       \
         "lwz 9,28(11)\n\t"                                       \
         "lwz 10,32(11)\n\t" /* arg8->r10 */                      \
         "lwz 11,0(11)\n\t"  /* target->r11 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "addi 1,1,16\n\t"                                        \
         "mr %0,3"                                                \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_10W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,  \
                                  arg7,arg8,arg9,arg10)           \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[11];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)arg1;                           \
      _argvec[2] = (unsigned long)arg2;                           \
      _argvec[3] = (unsigned long)arg3;                           \
      _argvec[4] = (unsigned long)arg4;                           \
      _argvec[5] = (unsigned long)arg5;                           \
      _argvec[6] = (unsigned long)arg6;                           \
      _argvec[7] = (unsigned long)arg7;                           \
      _argvec[8] = (unsigned long)arg8;                           \
      _argvec[9] = (unsigned long)arg9;                           \
      _argvec[10] = (unsigned long)arg10;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "addi 1,1,-16\n\t"                                       \
         /* arg10 */                                              \
         "lwz 3,40(11)\n\t"                                       \
         "stw 3,12(1)\n\t"                                        \
         /* arg9 */                                               \
         "lwz 3,36(11)\n\t"                                       \
         "stw 3,8(1)\n\t"                                         \
         /* args1-8 */                                            \
         "lwz 3,4(11)\n\t"   /* arg1->r3 */                       \
         "lwz 4,8(11)\n\t"                                        \
         "lwz 5,12(11)\n\t"                                       \
         "lwz 6,16(11)\n\t"  /* arg4->r6 */                       \
         "lwz 7,20(11)\n\t"                                       \
         "lwz 8,24(11)\n\t"                                       \
         "lwz 9,28(11)\n\t"                                       \
         "lwz 10,32(11)\n\t" /* arg8->r10 */                      \
         "lwz 11,0(11)\n\t"  /* target->r11 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "addi 1,1,16\n\t"                                        \
         "mr %0,3"                                                \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_11W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,  \
                                  arg7,arg8,arg9,arg10,arg11)     \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[12];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)arg1;                           \
      _argvec[2] = (unsigned long)arg2;                           \
      _argvec[3] = (unsigned long)arg3;                           \
      _argvec[4] = (unsigned long)arg4;                           \
      _argvec[5] = (unsigned long)arg5;                           \
      _argvec[6] = (unsigned long)arg6;                           \
      _argvec[7] = (unsigned long)arg7;                           \
      _argvec[8] = (unsigned long)arg8;                           \
      _argvec[9] = (unsigned long)arg9;                           \
      _argvec[10] = (unsigned long)arg10;                         \
      _argvec[11] = (unsigned long)arg11;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "addi 1,1,-32\n\t"                                       \
         /* arg11 */                                              \
         "lwz 3,44(11)\n\t"                                       \
         "stw 3,16(1)\n\t"                                        \
         /* arg10 */                                              \
         "lwz 3,40(11)\n\t"                                       \
         "stw 3,12(1)\n\t"                                        \
         /* arg9 */                                               \
         "lwz 3,36(11)\n\t"                                       \
         "stw 3,8(1)\n\t"                                         \
         /* args1-8 */                                            \
         "lwz 3,4(11)\n\t"   /* arg1->r3 */                       \
         "lwz 4,8(11)\n\t"                                        \
         "lwz 5,12(11)\n\t"                                       \
         "lwz 6,16(11)\n\t"  /* arg4->r6 */                       \
         "lwz 7,20(11)\n\t"                                       \
         "lwz 8,24(11)\n\t"                                       \
         "lwz 9,28(11)\n\t"                                       \
         "lwz 10,32(11)\n\t" /* arg8->r10 */                      \
         "lwz 11,0(11)\n\t"  /* target->r11 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "addi 1,1,32\n\t"                                        \
         "mr %0,3"                                                \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_12W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,  \
                                arg7,arg8,arg9,arg10,arg11,arg12) \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[13];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)arg1;                           \
      _argvec[2] = (unsigned long)arg2;                           \
      _argvec[3] = (unsigned long)arg3;                           \
      _argvec[4] = (unsigned long)arg4;                           \
      _argvec[5] = (unsigned long)arg5;                           \
      _argvec[6] = (unsigned long)arg6;                           \
      _argvec[7] = (unsigned long)arg7;                           \
      _argvec[8] = (unsigned long)arg8;                           \
      _argvec[9] = (unsigned long)arg9;                           \
      _argvec[10] = (unsigned long)arg10;                         \
      _argvec[11] = (unsigned long)arg11;                         \
      _argvec[12] = (unsigned long)arg12;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "addi 1,1,-32\n\t"                                       \
         /* arg12 */                                              \
         "lwz 3,48(11)\n\t"                                       \
         "stw 3,20(1)\n\t"                                        \
         /* arg11 */                                              \
         "lwz 3,44(11)\n\t"                                       \
         "stw 3,16(1)\n\t"                                        \
         /* arg10 */                                              \
         "lwz 3,40(11)\n\t"                                       \
         "stw 3,12(1)\n\t"                                        \
         /* arg9 */                                               \
         "lwz 3,36(11)\n\t"                                       \
         "stw 3,8(1)\n\t"                                         \
         /* args1-8 */                                            \
         "lwz 3,4(11)\n\t"   /* arg1->r3 */                       \
         "lwz 4,8(11)\n\t"                                        \
         "lwz 5,12(11)\n\t"                                       \
         "lwz 6,16(11)\n\t"  /* arg4->r6 */                       \
         "lwz 7,20(11)\n\t"                                       \
         "lwz 8,24(11)\n\t"                                       \
         "lwz 9,28(11)\n\t"                                       \
         "lwz 10,32(11)\n\t" /* arg8->r10 */                      \
         "lwz 11,0(11)\n\t"  /* target->r11 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "addi 1,1,32\n\t"                                        \
         "mr %0,3"                                                \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#endif /* PLAT_ppc32_linux */

/* ------------------------ ppc64-linux ------------------------ */

#if defined(PLAT_ppc64_linux)

/* ARGREGS: r3 r4 r5 r6 r7 r8 r9 r10 (the rest on stack somewhere) */

/* These regs are trashed by the hidden call. */
#define __CALLER_SAVED_REGS                                       \
   "lr", "ctr", "xer",                                            \
   "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7",        \
   "r0", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",   \
   "r11", "r12", "r13"

/* These CALL_FN_ macros assume that on ppc64-linux, sizeof(unsigned
   long) == 8. */

#define CALL_FN_W_v(lval, orig)                                   \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+0];                        \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1] = (unsigned long)_orig.r2;                       \
      _argvec[2] = (unsigned long)_orig.nraddr;                   \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)" /* restore tocptr */                      \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_W(lval, orig, arg1)                             \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+1];                        \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)" /* restore tocptr */                      \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_WW(lval, orig, arg1,arg2)                       \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+2];                        \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)" /* restore tocptr */                      \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_WWW(lval, orig, arg1,arg2,arg3)                 \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+3];                        \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      _argvec[2+3] = (unsigned long)arg3;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld   5, 24(11)\n\t" /* arg3->r5 */                      \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)" /* restore tocptr */                      \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_WWWW(lval, orig, arg1,arg2,arg3,arg4)           \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+4];                        \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      _argvec[2+3] = (unsigned long)arg3;                         \
      _argvec[2+4] = (unsigned long)arg4;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld   5, 24(11)\n\t" /* arg3->r5 */                      \
         "ld   6, 32(11)\n\t" /* arg4->r6 */                      \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)" /* restore tocptr */                      \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_5W(lval, orig, arg1,arg2,arg3,arg4,arg5)        \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+5];                        \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      _argvec[2+3] = (unsi
```