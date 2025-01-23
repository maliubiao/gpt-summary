Response:
My thought process for analyzing the provided C++ code snippet and generating the summary goes through these stages:

1. **Understanding the Goal:** The request asks for a functional summary of the C++ code, specifically from the perspective of a Frida dynamic instrumentation user. It also asks for connections to reverse engineering, low-level concepts, logical reasoning, common errors, and debugging context.

2. **Initial Code Scan - High-Level Structure:**  I first quickly scanned the code to identify the major components and data structures. Key things that jumped out:
    * `#include` statements indicating dependencies (V8, GLib).
    * `struct` definitions (e.g., `GumV8ArgsParseScope`, `GumCpuContextWrapper`).
    * A large function `_gum_v8_args_parse`.
    * Many other functions with names starting with `_gum_v8_`.
    * Use of V8-specific types like `Local<Value>`, `Isolate`, `Context`, `String`.
    * Use of GLib types like `GArray`, `GBytes`, `GSList`.

3. **Focusing on the Core Functionality - `_gum_v8_args_parse`:** This function immediately stood out due to its complexity and its name suggesting argument parsing. The `format` string and `va_list` confirmed this. I analyzed the `switch` statement within the loop, noting the various format specifiers (`i`, `u`, `q`, `Q`, `s`, `S`, `p`, `X`, `B`, `C`, `F`, etc.). Each specifier corresponds to handling a different data type from the JavaScript side. This is a central piece of how Frida interacts with JavaScript.

4. **Identifying Key Data Structures:** The `GumV8ArgsParseScope` struct is crucial for managing memory allocated during argument parsing. The use of `GSList` for `strings`, `arrays`, `bytes`, and `match_patterns` indicates that this scope is designed to hold temporary allocations that need to be freed. The `commit()` method suggests a mechanism for either persisting or discarding these allocations.

5. **Recognizing the V8 Bridge:** The extensive use of V8 types clearly indicates this code acts as a bridge between Frida's C++ core and the V8 JavaScript engine. Functions like `_gum_v8_string_new_ascii`, `_gum_v8_array_buffer_new_take`, `_gum_v8_bytes_get`, `_gum_v8_int64_new`, etc., are responsible for converting between V8 JavaScript values and their C++ counterparts.

6. **Connecting to Frida Concepts:**  I started connecting the code to Frida's purpose: dynamic instrumentation. The ability to parse arguments from JavaScript is fundamental to calling Frida functions from scripts. The presence of `GumCpuContext` suggests interaction with CPU state, a core feature of instrumentation.

7. **Relating to Reverse Engineering:** I considered how the functionality of this code would be used in reverse engineering scenarios. The ability to pass data (integers, strings, pointers, byte arrays) between JavaScript and native code enables powerful inspection and manipulation of a target process. The `GumMatchPattern` suggests pattern-based searching, common in reverse engineering.

8. **Identifying Low-Level Concepts:** The manipulation of raw memory (`ArrayBuffer`, `GBytes`), native pointers, and CPU context directly relates to low-level system programming concepts. The mention of Linux and Android kernels in the prompt reinforced the need to look for these connections.

9. **Inferring Logical Reasoning and Potential Errors:** The `_gum_v8_args_parse` function has implicit logic for type checking and handling optional arguments. I considered potential errors like type mismatches or missing required arguments, which are common when users write Frida scripts.

10. **Considering the Debugging Context:** The prompt asked how a user might reach this code. This led me to think about the typical workflow of writing and running a Frida script that calls a native function, triggering the argument parsing logic in this file.

11. **Structuring the Summary:** Finally, I organized the identified functionalities into a clear and concise summary, addressing the specific points raised in the prompt (core function, reverse engineering, low-level aspects, logical reasoning, user errors, debugging). I used bullet points to improve readability.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual functions. I realized the importance of emphasizing the overall purpose of *bridging* V8 and C++.
* I made sure to translate the technical details into user-centric explanations. For example, instead of just saying "parses V8 values," I explained *why* this is important for a Frida user (passing arguments to native functions).
* I ensured that the examples provided were concrete and illustrative, showing how each feature relates to reverse engineering or low-level concepts.
* I double-checked that I addressed all the specific points raised in the prompt, including the examples for user errors and the debugging scenario.
```cpp
/*
 * Copyright (C) 2016-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8value.h"

#include <string.h>
#include <string>

#define GUM_MAX_SEND_ARRAY_LENGTH (1024 * 1024)

using namespace v8;

// ... (rest of the code)
```

This C++ source code file, `gumv8value.cpp`, is a crucial part of Frida's internals, specifically focusing on the interaction between Frida's core C++ code (Gum) and the V8 JavaScript engine. It provides the functionality to translate and handle values between these two environments.

Here's a breakdown of its key functionalities:

**Core Functionality: Bridging V8 JavaScript Values and Gum C++ Types**

The primary goal of this file is to enable seamless communication between JavaScript code running within Frida and the underlying C++ components of Frida (Gum). This involves:

* **Parsing JavaScript Arguments for C++ Functions (`_gum_v8_args_parse`):** This is a central function that takes a JavaScript function's arguments and a format string as input. It then extracts and converts these arguments into corresponding C++ types based on the format specifiers. This is essential for calling native C++ functions from JavaScript hooks in Frida.

* **Converting C++ Values to JavaScript Values:**  While not explicitly shown in detail in this excerpt, the file contains functions (like `_gum_v8_string_new_ascii`, `_gum_v8_int64_new`, `_gum_v8_native_pointer_new`) responsible for creating V8 JavaScript values from C++ data. This allows Frida to return results and data from native code back to the JavaScript environment.

* **Handling Various Data Types:** The code provides specific logic for handling a wide range of data types, including:
    * Integers (signed and unsigned, various sizes)
    * Floating-point numbers
    * Booleans
    * Native pointers
    * External pointers
    * Strings (including handling of nullability)
    * Memory ranges
    * Page protection flags
    * Generic JavaScript `Value` and `Object` types
    * Arrays
    * Functions (callbacks) and native function pointers
    * Byte arrays (`GBytes`)
    * CPU Context objects (`GumCpuContext`)
    * Match Patterns (`GumMatchPattern`)

* **Memory Management:** The `GumV8ArgsParseScope` struct is a helper class to manage the lifetime of memory allocated during argument parsing. It ensures that temporary allocations (like duplicated strings, `GArray`, `GBytes`) are properly freed, even if parsing fails.

* **Error Handling:** The code includes functions for throwing JavaScript exceptions (`_gum_v8_throw`, `_gum_v8_throw_ascii`, `_gum_v8_throw_native`) when errors occur during value conversion or argument parsing.

**Relation to Reverse Engineering:**

This file is fundamental to many reverse engineering tasks performed with Frida:

* **Interacting with Native Functions:** When you hook a native function using Frida, you often need to read or modify its arguments. `_gum_v8_args_parse` is the mechanism that allows you to access these arguments from your JavaScript hook, converting them into usable C++ types within Frida's core. For example, if you are hooking a function that takes a pointer to a string, this code handles converting the JavaScript representation of that pointer into a usable `gchar*` in C++.

    **Example:**  Suppose you are hooking the `open` system call on Linux. The signature is roughly `int open(const char *pathname, int flags, ...)`. In your Frida script, you would access the `pathname` argument. Frida uses the logic in `gumv8value.cpp` to convert the JavaScript string representing the path into a C-style string that the `open` function expects.

* **Passing Data to Native Functions:** Conversely, you might want to call a native function from your Frida script and provide arguments. This file provides the tools to convert JavaScript values into the appropriate C++ types for the function call.

    **Example:** You might want to call a custom function in the target process that takes an integer and a pointer to a buffer. You would use Frida's API to call this function, and `gumv8value.cpp` handles packaging the JavaScript number and ArrayBuffer into the correct C++ integer and memory pointer.

* **Inspecting and Modifying Memory:** Functions that deal with `GBytes` and memory ranges (`GumMemoryRange`) are crucial for reading and writing arbitrary memory in the target process.

    **Example:** If you want to read the contents of a data structure in memory, you might get a pointer to it and a size. You can then use Frida's `Memory.readByteArray` (or similar) which internally utilizes this file's functions to convert the JavaScript representation of the memory range into a byte array you can inspect.

**Relation to Binary Underlying, Linux, Android Kernel & Framework:**

* **Native Pointers and Memory Addresses:** The code extensively deals with native pointers (`gpointer`) and memory addresses. This is fundamental to interacting with the raw memory and code of a process running on any operating system, including Linux and Android.

* **System Calls and Kernel Interaction:** While this specific file doesn't directly make system calls, it's a vital part of the infrastructure that *enables* Frida to interact with the kernel. When Frida hooks system calls or kernel functions, the arguments and return values often involve low-level data types that this file knows how to handle.

* **Android Framework Interaction:** On Android, Frida is often used to hook functions within the Android framework (e.g., in `libart.so` for hooking Java methods or in native libraries). This file is essential for converting data between the JavaScript environment and the native representations used within the Android runtime.

* **CPU Context (`GumCpuContext`):** The handling of `GumCpuContext` is directly related to inspecting and manipulating the CPU's registers and state. This is a core concept in debugging and reverse engineering at the assembly level.

    **Example:** When an exception occurs in the target process, Frida can capture the CPU context at the time of the exception. This file provides the mechanism to represent and access this CPU context (registers, stack pointer, instruction pointer, etc.) in a structured way within the JavaScript environment.

**Logical Reasoning (Assumptions and Conversions):**

The `_gum_v8_args_parse` function embodies logical reasoning based on the format string:

* **Input:**  A JavaScript `arguments` object and a format string like `"isp"` (integer, string, pointer).
* **Assumption:** The JavaScript arguments are provided in the order and with types expected by the format string.
* **Conversion Logic:** The `switch` statement iterates through the format string. For each character:
    * It checks the corresponding JavaScript argument's type (e.g., `IsNumber()`, `IsString()`).
    * If the type matches the expectation, it converts the JavaScript value to the corresponding C++ type using helper functions (e.g., `_gum_v8_int_get`, `_gum_v8_string_get`).
    * If the type doesn't match, it throws a JavaScript error.
* **Output:** Populated C++ variables (passed by reference via `va_arg`).

**Example of Logical Reasoning:**

Let's say the format string is `"i"` and the first argument in JavaScript is `"123"`.

1. The code checks if the format specifier is `'i'`.
2. It checks `arg->IsNumber()`. This would be false because the JavaScript value is a string.
3. It calls `_gum_v8_throw_ascii_literal` to throw an error like "expected an integer".

If the JavaScript argument was the number `123`, the logic would proceed:

1. The code checks if the format specifier is `'i'`.
2. It checks `arg->IsNumber()`. This would be true.
3. It calls `_gum_v8_int_get` to convert the JavaScript number to a `gint`.
4. The `gint` variable passed to `va_arg` would be populated with the value `123`.

**User or Programming Common Usage Errors:**

* **Type Mismatches:** Providing a JavaScript argument of the wrong type for the expected format specifier.

    **Example:**  A C++ function expects an integer (`'i'`), but the JavaScript code passes a string `"hello"`. This will lead to an error like "expected an integer".

* **Missing Arguments:** Not providing enough JavaScript arguments to match the required specifiers in the format string (before the `|` for optional arguments).

    **Example:** The format string is `"is"` (integer, string), but the JavaScript function is called with only one argument. This will result in a "missing argument" error.

* **Incorrect Pointer Types:** Trying to interpret a JavaScript number as a pointer without proper conversion or when the number doesn't represent a valid memory address.

    **Example:**  A C++ function expects a pointer (`'p'`), and the JavaScript code passes the number `1000`. While it might parse as a pointer, dereferencing it could lead to a crash if address `1000` is not a valid memory region.

* **Incorrect String Encoding:**  Assuming a specific encoding for strings when the actual encoding might be different.

* **Buffer Overflows (related to `'B'`):** When passing byte arrays (`GBytes`), not ensuring that the JavaScript array or ArrayBuffer has the expected size.

**How User Operations Reach This Code (Debugging Clues):**

1. **Writing a Frida Script:** A user starts by writing a Frida script in JavaScript.
2. **Hooking a Native Function:** The script uses Frida's `Interceptor.attach()` to hook a native function.
3. **Accessing Function Arguments:** Inside the hook handler, the script accesses the arguments of the intercepted function (e.g., `args[0]`, `args[1]`).
4. **Frida's Internal Processing:** When the hooked function is called in the target process, Frida's core logic (written in C++) intercepts the call.
5. **Argument Parsing:** Frida needs to make the arguments accessible to the JavaScript hook. This is where the code in `gumv8value.cpp`, specifically `_gum_v8_args_parse`, comes into play. Frida has information about the expected types of the arguments (either from manually specified signatures or through introspection).
6. **Conversion:** `_gum_v8_args_parse` uses the format string (implicitly or explicitly defined) to convert the raw argument data into V8 JavaScript values that are then passed to the JavaScript hook handler.
7. **JavaScript Hook Execution:** The JavaScript hook receives the converted arguments and can then inspect or modify them.

Alternatively, a user might be:

1. **Calling a Native Function from JavaScript:** Using Frida's `NativeFunction` API to directly call a native function from the JavaScript side.
2. **Providing Arguments:** The user provides JavaScript values as arguments to the `NativeFunction` call.
3. **Argument Conversion:**  Again, `gumv8value.cpp` is used to convert these JavaScript values into the C++ types expected by the target native function.

**Summary of Functions in Part 1:**

This first part of the `gumv8value.cpp` file primarily focuses on:

* **Argument parsing from JavaScript to C++ (`_gum_v8_args_parse`)**: This is the central mechanism for receiving data from the JavaScript side of Frida and making it usable in the C++ core.
* **Helper structures for argument parsing (`GumV8ArgsParseScope`)**:  Manages the lifetime of temporary allocations during argument processing.
* **Basic data type conversion functions**:  Provides the foundation for converting fundamental types like integers, booleans, and strings between V8 and C++.
* **Management of native and kernel resources**: Introduces the concepts and structures for tracking native memory allocations and kernel resources managed by Frida.

The code lays the groundwork for more complex value handling and interaction between JavaScript and the native world within the Frida framework. The functions and structures defined here are crucial for enabling Frida's dynamic instrumentation capabilities.

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8value.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2016-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8value.h"

#include <string.h>
#include <string>

#define GUM_MAX_SEND_ARRAY_LENGTH (1024 * 1024)

using namespace v8;

struct GumV8ArgsParseScope
{
  GumV8ArgsParseScope ()
    : committed (FALSE),
      strings (NULL),
      arrays (NULL),
      bytes (NULL),
      match_patterns (NULL)
  {
  }

  ~GumV8ArgsParseScope ()
  {
    if (!committed)
    {
      g_slist_foreach (strings, (GFunc) g_free, NULL);
      g_slist_foreach (arrays, (GFunc) g_array_unref, NULL);
      g_slist_foreach (bytes, (GFunc) g_bytes_unref, NULL);
      g_slist_foreach (match_patterns, (GFunc) gum_match_pattern_unref, NULL);
    }

    g_slist_free (strings);
    g_slist_free (arrays);
    g_slist_free (bytes);
    g_slist_free (match_patterns);
  }

  void
  commit ()
  {
    committed = TRUE;
  }

  gchar *
  strdup (const gchar * s)
  {
    auto result = g_strdup (s);
    strings = g_slist_prepend (strings, result);
    return result;
  }

  void
  add (GArray * a)
  {
    arrays = g_slist_prepend (arrays, a);
  }

  void
  add (GBytes * b)
  {
    bytes = g_slist_prepend (bytes, b);
  }

  void
  add (GumMatchPattern * p)
  {
    match_patterns = g_slist_prepend (match_patterns, p);
  }

  gboolean committed;
  GSList * strings;
  GSList * arrays;
  GSList * bytes;
  GSList * match_patterns;
};

struct GumCpuContextWrapper
{
  Global<Object> * instance;
  GumCpuContext * cpu_context;
};

static void gum_delete_heap_allocation (void * data, size_t length,
    void * deleter_data);

static void gum_v8_native_resource_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeResource> & info);
static void gum_v8_kernel_resource_on_weak_notify (
    const WeakCallbackInfo<GumV8KernelResource> & info);

static const gchar * gum_exception_type_to_string (GumExceptionType type);

static void gum_cpu_context_on_weak_notify (
    const WeakCallbackInfo<GumCpuContextWrapper> & info);

gboolean
_gum_v8_args_parse (const GumV8Args * args,
                    const gchar * format,
                    ...)
{
  auto info = args->info;
  auto core = args->core;
  auto isolate = info->GetIsolate ();
  auto context = isolate->GetCurrentContext ();
  GumV8ArgsParseScope scope;
  va_list ap;
  int arg_index, arg_count = info->Length ();
  const gchar * t;
  gboolean is_required;

  va_start (ap, format);

  arg_index = 0;
  is_required = TRUE;
  for (t = format; *t != '\0'; t++)
  {
    if (*t == '|')
    {
      is_required = FALSE;
      continue;
    }

    Local<Value> arg;

    if (arg_index < arg_count)
        arg = (*info)[arg_index];

    if (arg_index >= arg_count || arg->IsUndefined ())
    {
      if (is_required)
      {
        _gum_v8_throw_ascii_literal (isolate, "missing argument");
        return FALSE;
      }
      else
      {
        break;
      }
    }

    switch (*t)
    {
      case 'i':
      {
        gint i;

        if (!_gum_v8_int_get (arg, &i, core))
          return FALSE;

        *va_arg (ap, gint *) = (gint) i;

        break;
      }
      case 'u':
      {
        guint u;

        if (!_gum_v8_uint_get (arg, &u, core))
          return FALSE;

        *va_arg (ap, guint *) = u;

        break;
      }
      case 'q':
      {
        gint64 i;

        gboolean is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (!_gum_v8_int64_parse (arg, &i, core))
            return FALSE;
        }
        else
        {
          if (!_gum_v8_int64_get (arg, &i, core))
            return FALSE;
        }

        *va_arg (ap, gint64 *) = i;

        break;
      }
      case 'Q':
      {
        guint64 u;

        gboolean is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (!_gum_v8_uint64_parse (arg, &u, core))
            return FALSE;
        }
        else
        {
          if (!_gum_v8_uint64_get (arg, &u, core))
            return FALSE;
        }

        *va_arg (ap, guint64 *) = u;

        break;
      }
      case 'z':
      {
        gssize value;

        if (!_gum_v8_ssize_get (arg, &value, core))
          return FALSE;

        *va_arg (ap, gssize *) = value;

        break;
      }
      case 'Z':
      {
        gsize value;

        if (!_gum_v8_size_get (arg, &value, core))
          return FALSE;

        *va_arg (ap, gsize *) = value;

        break;
      }
      case 'n':
      {
        if (!arg->IsNumber ())
        {
          _gum_v8_throw_ascii_literal (isolate, "expected a number");
          return FALSE;
        }

        *va_arg (ap, gdouble *) = arg.As<Number> ()->Value ();

        break;
      }
      case 't':
      {
        if (!arg->IsBoolean ())
        {
          _gum_v8_throw_ascii_literal (isolate, "expected a boolean");
          return FALSE;
        }

        *va_arg (ap, gboolean *) = arg.As<Boolean> ()->Value ();

        break;
      }
      case 'p':
      {
        gpointer ptr;

        gboolean is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (!_gum_v8_native_pointer_parse (arg, &ptr, core))
            return FALSE;
        }
        else
        {
          if (!_gum_v8_native_pointer_get (arg, &ptr, core))
            return FALSE;
        }

        *va_arg (ap, gpointer *) = ptr;

        break;
      }
      case 'X':
      {
        if (!arg->IsExternal ())
        {
          _gum_v8_throw_ascii_literal (isolate, "expected an external pointer");
          return FALSE;
        }

        *va_arg (ap, gpointer *) = arg.As<External> ()->Value ();

        break;
      }
      case 's':
      {
        gchar * str;

        gboolean is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && arg->IsNull ())
        {
          str = NULL;
        }
        else if (arg->IsString ())
        {
          String::Utf8Value arg_utf8 (isolate, arg);
          str = scope.strdup (*arg_utf8);
        }
        else
        {
          _gum_v8_throw_ascii_literal (isolate, "expected a string");
          return FALSE;
        }

        *va_arg (ap, gchar **) = str;

        break;
      }
      case 'S':
      {
        if (!arg->IsString ())
        {
          _gum_v8_throw_ascii_literal (isolate, "expected a string");
          return FALSE;
        }

        String::Utf8Value arg_utf8 (isolate, arg);
        *va_arg (ap, std::string *) = *arg_utf8;

        break;
      }
      case 'r':
      {
        auto range = va_arg (ap, GumMemoryRange *);

        if (!_gum_v8_memory_range_get (arg, range, core))
          return FALSE;

        break;
      }
      case 'R':
      {
        auto ranges = _gum_v8_memory_ranges_get (arg, core);
        if (ranges == NULL)
          return FALSE;

        scope.add (ranges);

        *va_arg (ap, GArray **) = ranges;

        break;
      }
      case 'm':
      {
        GumPageProtection prot;

        if (!_gum_v8_page_protection_get (arg, &prot, core))
          return FALSE;

        *va_arg (ap, GumPageProtection *) = prot;

        break;
      }
      case 'V':
      {
        *va_arg (ap, Local<Value> *) = arg;

        break;
      }
      case 'O':
      {
        gboolean is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && arg->IsNull ())
        {
          *va_arg (ap, Local<Object> *) = Local<Object> ();
        }
        else if (arg->IsObject ())
        {
          *va_arg (ap, Local<Object> *) = arg.As<Object> ();
        }
        else
        {
          _gum_v8_throw_ascii_literal (isolate, "expected an object");
          return FALSE;
        }

        break;
      }
      case 'A':
      {
        gboolean is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (arg->IsArray ())
        {
          *va_arg (ap, Local<Array> *) = arg.As<Array> ();
        }
        else if (is_nullable && arg->IsNull ())
        {
          *va_arg (ap, Local<Array> *) = Local<Array> ();
        }
        else
        {
          _gum_v8_throw_ascii_literal (isolate, "expected an array");
          return FALSE;
        }

        break;
      }
      case 'F':
      {
        gboolean accepts_pointer = t[1] == '*';
        if (accepts_pointer)
          t++;

        gboolean is_expecting_object = t[1] == '{';
        if (is_expecting_object)
          t += 2;

        if (is_expecting_object)
        {
          if (!arg->IsObject ())
          {
            _gum_v8_throw_ascii_literal (isolate,
                "expected an object containing callbacks");
            return FALSE;
          }
          Local<Object> callbacks = arg.As<Object> ();

          const gchar * end, * t_end;

          do
          {
            gchar name[64];

            const gchar * next = strchr (t, ',');
            end = strchr (t, '}');
            t_end = (next != NULL && next < end) ? next : end;
            gsize length = t_end - t;
            strncpy (name, t, length);

            gboolean is_optional = name[length - 1] == '?';
            if (is_optional)
              name[length - 1] = '\0';
            else
              name[length] = '\0';

            Local<Function> func_js;
            gpointer func_c;

            Local<Value> value;
            if (!callbacks->Get (context,
                _gum_v8_string_new_ascii (isolate, name)).ToLocal (&value))
            {
              return FALSE;
            }
            if (value->IsFunction ())
            {
              func_js = value.As<Function> ();
              func_c = NULL;
            }
            else if (is_optional && value->IsUndefined ())
            {
              func_c = NULL;
            }
            else
            {
              auto native_pointer = Local<FunctionTemplate>::New (isolate,
                  *core->native_pointer);
              if (accepts_pointer && native_pointer->HasInstance (value))
              {
                func_c = GUMJS_NATIVE_POINTER_VALUE (value.As<Object> ());
              }
              else
              {
                _gum_v8_throw_ascii_literal (isolate,
                    "expected a callback value");
                return FALSE;
              }
            }

            *va_arg (ap, Local<Function> *) = func_js;
            if (accepts_pointer)
              *va_arg (ap, gpointer *) = func_c;

            t = t_end + 1;
          }
          while (t_end != end);

          t--;
        }
        else
        {
          gboolean is_nullable = t[1] == '?';
          if (is_nullable)
            t++;

          Local<Function> func_js;
          gpointer func_c;

          if (arg->IsFunction ())
          {
            func_js = arg.As<Function> ();
            func_c = NULL;
          }
          else if (is_nullable && arg->IsNull ())
          {
            func_c = NULL;
          }
          else
          {
            auto native_pointer = Local<FunctionTemplate>::New (isolate,
                *core->native_pointer);
            if (accepts_pointer && native_pointer->HasInstance (arg))
            {
              func_c = GUMJS_NATIVE_POINTER_VALUE (arg.As<Object> ());
            }
            else
            {
              _gum_v8_throw_ascii_literal (isolate,
                  "expected a function");
              return FALSE;
            }
          }

          *va_arg (ap, Local<Function> *) = func_js;
          if (accepts_pointer)
            *va_arg (ap, gpointer *) = func_c;
        }

        break;
      }
      case 'B':
      {
        GBytes * bytes;

        gboolean is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        gboolean is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && arg->IsNull ())
        {
          bytes = NULL;
        }
        else
        {
          if (is_fuzzy)
            bytes = _gum_v8_bytes_parse (arg, core);
          else
            bytes = _gum_v8_bytes_get (arg, core);
          if (bytes == NULL)
            return FALSE;

          scope.add (bytes);
        }

        *va_arg (ap, GBytes **) = bytes;

        break;
      }
      case 'C':
      {
        GumCpuContext * cpu_context;

        gboolean is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && arg->IsNull ())
        {
          cpu_context = NULL;
        }
        else if (!_gum_v8_cpu_context_get (arg, &cpu_context, core))
        {
          _gum_v8_throw_ascii_literal (isolate, "expected a CpuContext object");
          return FALSE;
        }

        *va_arg (ap, GumCpuContext **) = cpu_context;

        break;
      }
      case 'M':
      {
        GumMatchPattern * pattern;

        if (arg->IsString ())
        {
          String::Utf8Value arg_utf8 (isolate, arg);

          pattern = gum_match_pattern_new_from_string (*arg_utf8);
          if (pattern == NULL)
          {
            _gum_v8_throw_ascii_literal (isolate, "invalid match pattern");
            return FALSE;
          }
        }
        else
        {
          auto match_pattern = Local<FunctionTemplate>::New (core->isolate,
              *core->match_pattern);
          if (!match_pattern->HasInstance (arg))
          {
            _gum_v8_throw_ascii_literal (isolate,
                "expected either a pattern string or a MatchPattern object");
            return FALSE;
          }

          pattern = (GumMatchPattern *) arg.As<Object> ()
              ->GetInternalField (0).As<External> ()->Value ();

          gum_match_pattern_ref (pattern);
        }

        scope.add (pattern);

        *va_arg (ap, GumMatchPattern **) = pattern;

        break;
      }
      default:
        g_assert_not_reached ();
    }

    arg_index++;
  }

  va_end (ap);

  scope.commit ();

  return TRUE;
}

Local<String>
_gum_v8_string_new_ascii (Isolate * isolate,
                          const gchar * str)
{
  return String::NewFromOneByte (isolate, (const uint8_t *) str,
      NewStringType::kNormal).ToLocalChecked ();
}

Local<ArrayBuffer>
_gum_v8_array_buffer_new_take (Isolate * isolate,
                               gpointer data,
                               gsize size)
{
  return ArrayBuffer::New (isolate, ArrayBuffer::NewBackingStore (data, size,
      gum_delete_heap_allocation, data));
}

static void
gum_delete_heap_allocation (void * data,
                            size_t length,
                            void * deleter_data)
{
  g_free (deleter_data);
}

GBytes *
_gum_v8_bytes_get (Local<Value> value,
                   GumV8Core * core)
{
  auto result = _gum_v8_bytes_try_get (value, core);
  if (result == NULL)
  {
    _gum_v8_throw_ascii_literal (core->isolate, "unsupported data value");
    return NULL;
  }

  return result;
}

GBytes *
_gum_v8_bytes_parse (Local<Value> value,
                     GumV8Core * core)
{
  if (value->IsString ())
  {
    String::Utf8Value value_as_utf8 (core->isolate, value);
    auto value_as_string = *value_as_utf8;
    return g_bytes_new (value_as_string, strlen (value_as_string));
  }

  return _gum_v8_bytes_get (value, core);
}

GBytes *
_gum_v8_bytes_try_get (Local<Value> value,
                       GumV8Core * core)
{
  if (value->IsArrayBuffer ())
  {
    auto store = value.As<ArrayBuffer> ()->GetBackingStore ();
    return g_bytes_new (store->Data (), store->ByteLength ());
  }

  if (value->IsArrayBufferView ())
  {
    auto view = value.As<ArrayBufferView> ();

    auto data_length = view->ByteLength ();
    auto data = g_malloc (data_length);
    view->CopyContents (data, data_length);

    return g_bytes_new_take (data, data_length);
  }

  if (value->IsArray ())
  {
    auto array = value.As<Array> ();

    gsize data_length = array->Length ();
    if (data_length > GUM_MAX_SEND_ARRAY_LENGTH)
      return NULL;

    auto context = core->isolate->GetCurrentContext ();

    auto data = (guint8 *) g_malloc (data_length);
    gboolean data_valid = TRUE;

    for (gsize i = 0; i != data_length && data_valid; i++)
    {
      gboolean element_valid = FALSE;

      Local<Value> element_value;
      if (array->Get (context, i).ToLocal (&element_value))
      {
        auto element = element_value->Uint32Value (context);
        if (element.IsJust ())
        {
          data[i] = element.FromJust ();
          element_valid = TRUE;
        }
      }

      if (!element_valid)
        data_valid = FALSE;
    }

    if (!data_valid)
    {
      g_free (data);
      return NULL;
    }

    return g_bytes_new_take (data, data_length);
  }

  return NULL;
}

GumV8NativeResource *
_gum_v8_native_resource_new (gpointer data,
                             gsize size,
                             GDestroyNotify notify,
                             GumV8Core * core)
{
  auto resource = g_slice_new (GumV8NativeResource);
  resource->instance = new Global<Object> (core->isolate,
      _gum_v8_native_pointer_new (data, core));
  resource->instance->SetWeak (resource, gum_v8_native_resource_on_weak_notify,
      WeakCallbackType::kParameter);
  resource->data = data;
  resource->size = size;
  resource->notify = notify;
  resource->core = core;

  core->isolate->AdjustAmountOfExternalAllocatedMemory (size);

  g_hash_table_add (core->native_resources, resource);

  return resource;
}

void
_gum_v8_native_resource_free (GumV8NativeResource * resource)
{
  resource->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -((gssize) resource->size));

  delete resource->instance;
  if (resource->notify != NULL)
    resource->notify (resource->data);
  g_slice_free (GumV8NativeResource, resource);
}

static void
gum_v8_native_resource_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeResource> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->core->native_resources, self);
}

GumV8KernelResource *
_gum_v8_kernel_resource_new (GumAddress data,
                             gsize size,
                             GumV8KernelDestroyNotify notify,
                             GumV8Core * core)
{
  auto resource = g_slice_new (GumV8KernelResource);
  resource->instance = new Global<Object> (core->isolate,
      _gum_v8_uint64_new (data, core));
  resource->instance->SetWeak (resource, gum_v8_kernel_resource_on_weak_notify,
      WeakCallbackType::kParameter);
  resource->data = data;
  resource->size = size;
  resource->notify = notify;
  resource->core = core;

  core->isolate->AdjustAmountOfExternalAllocatedMemory (size);

  g_hash_table_add (core->kernel_resources, resource);

  return resource;
}

void
_gum_v8_kernel_resource_free (GumV8KernelResource * resource)
{
  resource->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -((gssize) resource->size));

  delete resource->instance;
  if (resource->notify != NULL)
    resource->notify (resource->data);
  g_slice_free (GumV8KernelResource, resource);
}

static void
gum_v8_kernel_resource_on_weak_notify (
    const WeakCallbackInfo<GumV8KernelResource> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->core->kernel_resources, self);
}

gboolean
_gum_v8_int_get (Local<Value> value,
                 gint * i,
                 GumV8Core * core)
{
  if (!value->IsNumber ())
  {
    _gum_v8_throw_ascii_literal (core->isolate, "expected an integer");
    return FALSE;
  }

  double number = value.As<Number> ()->Value ();

  *i = (gint) number;
  return TRUE;
}

gboolean
_gum_v8_uint_get (Local<Value> value,
                  guint * u,
                  GumV8Core * core)
{
  if (!value->IsNumber ())
  {
    _gum_v8_throw_ascii_literal (core->isolate, "expected an unsigned integer");
    return FALSE;
  }

  double number = value.As<Number> ()->Value ();
  if (number < 0)
  {
    _gum_v8_throw_ascii_literal (core->isolate, "expected an unsigned integer");
    return FALSE;
  }

  *u = (guint) number;
  return TRUE;
}

Local<Object>
_gum_v8_int64_new (gint64 value,
                   GumV8Core * core)
{
  auto int64_value (Local<Object>::New (core->isolate, *core->int64_value));
  auto int64_object (int64_value->Clone ());
  _gum_v8_int64_set_value (int64_object, value, core->isolate);
  return int64_object;
}

gboolean
_gum_v8_int64_get (Local<Value> value,
                   gint64 * i,
                   GumV8Core * core)
{
  auto isolate = core->isolate;

  if (value->IsNumber ())
  {
    *i = value->IntegerValue (isolate->GetCurrentContext ()).ToChecked ();
    return TRUE;
  }

  auto int64 (Local<FunctionTemplate>::New (isolate, *core->int64));
  if (!int64->HasInstance (value))
  {
    _gum_v8_throw_ascii_literal (isolate, "expected an integer");
    return FALSE;
  }

  *i = _gum_v8_int64_get_value (value.As<Object> ());
  return TRUE;
}

gboolean
_gum_v8_int64_parse (Local<Value> value,
                     gint64 * i,
                     GumV8Core * core)
{
  if (value->IsString ())
  {
    auto isolate = core->isolate;

    String::Utf8Value value_as_utf8 (isolate, value);
    auto value_as_string = *value_as_utf8;
    gchar * end;
    if (g_str_has_prefix (value_as_string, "0x"))
    {
      *i = g_ascii_strtoll (value_as_string + 2, &end, 16);
      if (end == value_as_string + 2)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid hexadecimal string");
        return FALSE;
      }
    }
    else
    {
      *i = g_ascii_strtoll (value_as_string, &end, 10);
      if (end == value_as_string)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid hexadecimal string");
        return FALSE;
      }
    }

    return TRUE;
  }

  return _gum_v8_int64_get (value, i, core);
}

Local<Object>
_gum_v8_uint64_new (guint64 value,
                    GumV8Core * core)
{
  auto uint64_value (Local<Object>::New (core->isolate, *core->uint64_value));
  auto uint64_object (uint64_value->Clone ());
  _gum_v8_uint64_set_value (uint64_object, value, core->isolate);
  return uint64_object;
}

gint64
_gum_v8_int64_get_value (Local<Object> object)
{
  return object->GetInternalField (0).As<BigInt> ()->Int64Value ();
}

void
_gum_v8_int64_set_value (Local<Object> object,
                         gint64 value,
                         Isolate * isolate)
{
  object->SetInternalField (0, BigInt::New (isolate, value));
}

gboolean
_gum_v8_uint64_get (Local<Value> value,
                    guint64 * u,
                    GumV8Core * core)
{
  auto isolate = core->isolate;

  if (value->IsNumber ())
  {
    double v = value->NumberValue (isolate->GetCurrentContext ()).ToChecked ();
    if (v >= 0)
    {
      *u = (guint64) v;
      return TRUE;
    }
  }
  else
  {
    auto uint64 (Local<FunctionTemplate>::New (isolate, *core->uint64));
    if (uint64->HasInstance (value))
    {
      *u = _gum_v8_uint64_get_value (value.As<Object> ());
      return TRUE;
    }
  }

  _gum_v8_throw_ascii_literal (isolate, "expected an unsigned integer");
  return FALSE;
}

gboolean
_gum_v8_uint64_parse (Local<Value> value,
                      guint64 * u,
                      GumV8Core * core)
{
  if (value->IsString ())
  {
    auto isolate = core->isolate;

    String::Utf8Value value_as_utf8 (isolate, value);
    auto value_as_string = *value_as_utf8;
    gchar * end;
    if (g_str_has_prefix (value_as_string, "0x"))
    {
      *u = g_ascii_strtoull (value_as_string + 2, &end, 16);
      if (end == value_as_string + 2)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid hexadecimal string");
        return FALSE;
      }
    }
    else
    {
      *u = g_ascii_strtoull (value_as_string, &end, 10);
      if (end == value_as_string)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid hexadecimal string");
        return FALSE;
      }
    }

    return TRUE;
  }

  return _gum_v8_uint64_get (value, u, core);
}

guint64
_gum_v8_uint64_get_value (Local<Object> object)
{
  return object->GetInternalField (0).As<BigInt> ()->Uint64Value ();
}

void
_gum_v8_uint64_set_value (Local<Object> object,
                          guint64 value,
                          Isolate * isolate)
{
  object->SetInternalField (0, BigInt::NewFromUnsigned (isolate, value));
}

gboolean
_gum_v8_size_get (Local<Value> value,
                  gsize * size,
                  GumV8Core * core)
{
  auto isolate = core->isolate;

  if (value->IsNumber ())
  {
    double v = value->NumberValue (isolate->GetCurrentContext ()).ToChecked ();
    if (v >= 0)
    {
      *size = (gsize) v;
      return TRUE;
    }
  }
  else
  {
    auto uint64 (Local<FunctionTemplate>::New (isolate, *core->uint64));
    if (uint64->HasInstance (value))
    {
      *size = (gsize) _gum_v8_uint64_get_value (value.As<Object> ());
      return TRUE;
    }

    auto int64 (Local<FunctionTemplate>::New (isolate, *core->int64));
    if (int64->HasInstance (value))
    {
      auto int64_value = _gum_v8_int64_get_value (value.As<Object> ());
      if (int64_value >= 0)
      {
        *size = (gsize) int64_value;
        return TRUE;
      }
    }
  }

  _gum_v8_throw_ascii_literal (isolate, "expected an unsigned integer");
  return FALSE;
}

gboolean
_gum_v8_ssize_get (Local<Value> value,
                   gssize * size,
                   GumV8Core * core)
{
  auto isolate = core->isolate;

  if (value->IsNumber ())
  {
    *size = (gsize) value->IntegerValue (isolate->GetCurrentContext ())
        .ToChecked ();
    return TRUE;
  }
  else
  {
    Local<FunctionTemplate> int64 (Local<FunctionTemplate>::New (
        isolate, *core->int64));
    if (int64->HasInstance (value))
    {
      *size = (gssize) _gum_v8_int64_get_value (value.As<Object> ());
      return TRUE;
    }

    Local<FunctionTemplate> uint64 (Local<FunctionTemplate>::New (isolate,
        *core->uint64));
    if (uint64->HasInstance (value))
    {
      *size = (gssize) _gum_v8_uint64_get_value (value.As<Object> ());
      return TRUE;
    }
  }

  _gum_v8_throw_ascii_literal (isolate, "expected an integer");
  return FALSE;
}

Local<String>
_gum_v8_enum_new (Isolate * isolate,
                  gint value,
                  GType type)
{
  auto enum_class = (GEnumClass *) g_type_class_ref (type);

  GEnumValue * enum_value = g_enum_get_value (enum_class, value);
  g_assert (enum_value != NULL);

  auto result = String::NewFromOneByte (isolate,
      (const uint8_t *) enum_value->value_nick,
      NewStringType::kNormal).ToLocalChecked ();

  g_type_class_unref (enum_class);

  return result;
}

Local<Object>
_gum_v8_native_pointer_new (gpointer address,
                            GumV8Core * core)
{
  auto native_pointer_value (Local<Object>::New (core->isolate,
      *core->native_pointer_value));
  auto native_pointer_object (native_pointer_value->Clone ());
  native_pointer_object->SetInternalField (0,
      BigInt::NewFromUnsigned (core->isolate, GPOINTER_TO_SIZE (address)));
  return native_pointer_object;
}

gboolean
_gum_v8_native_pointer_get (Local<Value> value,
                            gpointer * ptr,
                            GumV8Core * core)
{
  auto isolate = core->isolate;
  gboolean success = FALSE;

  auto native_pointer = Local<FunctionTemplate>::New (isolate,
      *core->native_pointer);
  if (native_pointer->HasInstance (value))
  {
    *ptr = GUMJS_NATIVE_POINTER_VALUE (value.As<Object> ());
    success = TRUE;
  }
  else
  {
    auto context = isolate->GetCurrentContext ();

    /* Cannot use isObject() here as that returns false for proxies */
    MaybeLocal<Object> maybe_obj;
    {
      TryCatch trycatch (isolate);
      maybe_obj = value->ToObject (context);
      trycatch.Reset ();
    }

    Local<Object> obj;
    if (maybe_obj.ToLocal (&obj))
    {
      auto handle_key (Local<String>::New (isolate, *core->handle_key));
      if (obj->Has (context, handle_key).FromJust ())
      {
        auto handle = obj->Get (context, handle_key).ToLocalChecked ();
        if (native_pointer->HasInstance (handle))
        {
          *ptr = GUMJS_NATIVE_POINTER_VALUE (handle.As<Object> ());
          success = TRUE;
        }
      }
    }
  }

  if (!success)
  {
    _gum_v8_throw_ascii_literal (isolate, "expected a pointer");
    return FALSE;
  }

  return TRUE;
}

gboolean
_gum_v8_native_pointer_parse (Local<Value> value,
                              gpointer * ptr,
                              GumV8Core * core)
{
  auto isolate = core->isolate;

  if (value->IsString ())
  {
    String::Utf8Value ptr_as_utf8 (isolate, value);
    auto ptr_as_string = *ptr_as_utf8;
    gchar * endptr;
    if (g_str_has_prefix (ptr_as_string, "0x"))
    {
      *ptr = GSIZE_TO_POINTER (
          g_ascii_strtoull (ptr_as_string + 2, &endptr, 16));
      if (endptr == ptr_as_string + 2)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid hexadecimal string");
        return FALSE;
      }
    }
    else
    {
      *ptr = GSIZE_TO_POINTER (g_ascii_strtoull (ptr_as_string, &endptr, 10));
      if (endptr == ptr_as_string)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid decimal string");
        return FALSE;
      }
    }

    return TRUE;
  }
  else if (value->IsNumber ())
  {
    double number = value.As<Number> ()->Value ();

    if (number < 0)
    {
      union
      {
        gpointer p;
        gint64 i;
      } v;

      v.i = (gint64) number;

      *ptr = v.p;
      return TRUE;
    }

    *ptr = GSIZE_TO_POINTER ((guint64) number);
    return TRUE;
  }
  else
  {
    auto uint64 (Local<FunctionTemplate>::New (isolate, *core->uint64));
    if (uint64->HasInstance (value))
    {
      *ptr = GSIZE_TO_POINTER (_gum_v8_uint64_get_value (value.As<Object> ()));
      return TRUE;
    }

    auto int64 (Local<FunctionTemplate>::New (isolate, *core->int64));
    if (int64->HasInstance (value))
    {
      *ptr = GSIZE_TO_POINTER (_gum_v8_int64_get_value (value.As<Object> ()));
      return TRUE;
    }
  }

  return _gum_v8_native_pointer_get (value, ptr, core);
}

void
_gum_v8_throw (Isolate * isolate,
               const gchar * format,
               ...)
{
  va_list args;
  va_start (args, format);

  auto message = g_strdup_vprintf (format, args);
  _gum_v8_throw_literal (isolate, message);
  g_free (message);

  va_end (args);
}

void
_gum_v8_throw_literal (Isolate * isolate,
                       const gchar * message)
{
  isolate->ThrowException (Exception::Error (
      String::NewFromUtf8 (isolate, message).ToLocalChecked ()));
}

void
_gum_v8_throw_ascii (Isolate * isolate,
                     const gchar * format,
                     ...)
{
  va_list args;
  va_start (args, format);

  auto message = g_strdup_vprintf (format, args);
  _gum_v8_throw_ascii_literal (isolate, message);
  g_free (message);

  va_end (args);
}

void
_gum_v8_throw_ascii_literal (Isolate * isolate,
                             const gchar * message)
{
  isolate->ThrowException (Exception::Error (
      _gum_v8_string_new_ascii (isolate, message)));
}

void
_gum_v8_throw_native (GumExceptionDetails * details,
                      GumV8Core * core)
{
  Local<Object> ex, context;
  _gum_v8_parse_exception_details (details, ex, context, core);
  _gum_v8_cpu_context_free_later (new Global<Object> (core->isolate, context),
      core);
  core->isolate->ThrowException (ex);
}

gboolean
_gum_v8_maybe_throw (Isolate * isolate,
                     GError ** error)
{
  auto value = _gum_v8_error_new_take_error (isolate, error);
  if (value->IsNull ())
    return FALSE;
  isolate->ThrowException (value);
  return TRUE;
}

static const gchar *
gum_exception_type_to_string (GumExceptionType type)
{
  switch (type)
  {
    case GUM_EXCEPTION_ABORT: return "abort";
    case GUM_EXCEPTION_ACCESS_VIOLATION: return "access-violation";
    case GUM_EXCEPTION_GUARD_PAGE: return "guard-page";
    case GUM_EXCEPTION_ILLEGAL_INSTRUCTION: return "illegal-instruction";
    case GUM_EXCEPTION_STACK_OVERFLOW: return "stack-overflow";
    case GUM_EXCEPTION_ARITHMETIC: return "arithmetic";
    case GUM_EXCEPTION_BREAKPOINT: return "breakpoint";
    case GUM_EXCEPTION_SINGLE_STEP: return "single-step";
    case GUM_EXCEPTION_SYSTEM: return "system";
    default:
      break;
  }

  g_assert_not_reached ();
}

Local<Object>
_gum_v8_cpu_context_new_immutable (const GumCpuContext * cpu_context,
                                   GumV8Core * core)
{
  auto isolate = core->isolate;
  auto cpu_context_value (Local<Object>::New (isolate,
      *core->cpu_context_value));
  auto cpu_context_objec
```