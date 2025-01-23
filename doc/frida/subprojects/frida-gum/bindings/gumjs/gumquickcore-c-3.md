Response:
The user wants a summary of the C code provided, focusing on its functionality within the Frida dynamic instrumentation tool. I need to identify the key operations and data structures, and explain how they relate to reverse engineering, low-level details, and potential user errors.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the Core Purpose:** The filename `gumquickcore.c` and the context of Frida suggest this code deals with core functionalities, likely related to interacting with JavaScript within the Frida environment. The repeated use of `GUMJS_DEFINE_FUNCTION` and the presence of "native pointer", "array buffer", "native function", and "native callback" hint at the core features being about bridging native code (C) and JavaScript.

2. **Analyze Key Data Structures:**  Look for `struct` definitions or typedefs. The code prominently features `GumQuickNativePointer`, `GumQuickNativeResource`, `GumQuickKernelResource`, `GumQuickFFIFunction`, and `GumQuickNativeCallback`. These are the fundamental data types the code manipulates. The names themselves are quite descriptive, suggesting they represent native memory addresses, resources, and ways to call native functions from JavaScript.

3. **Examine Function Definitions:**  Go through the `GUMJS_DEFINE_FUNCTION` macros. These are the entry points for JavaScript interaction. Categorize them based on the noun in their name (e.g., `gumjs_native_pointer_*`, `gumjs_array_buffer_*`, `gumjs_native_function_*`).

4. **Focus on `GumQuickNativePointer`:**  The code defines various operations on `GumQuickNativePointer`:
    * **Binary Operations:** `add`, `sub`, `and`, `or`, `xor`, `shr`, `shl`. These directly manipulate memory addresses. This is a crucial aspect for reverse engineering, allowing users to calculate and work with memory locations.
    * **Unary Operations:** `not`. Another basic bitwise operation on memory addresses.
    * **Pointer Authentication (PTRAUTH):** `sign`, `strip`, `blend`. These are architecture-specific features (likely ARM) for securing pointers.
    * **Comparison:** `compare`. Essential for determining the relative order of memory addresses.
    * **Conversion:** `to_int32`, `to_uint32`, `to_string`, `to_json`, `to_match_pattern`. Provides ways to represent the pointer value in different formats. `to_match_pattern` is particularly interesting for reverse engineering as it creates a byte-level representation useful for searching memory.

5. **Examine `GumQuickArrayBuffer`:** The `wrap` and `unwrap` functions handle the conversion between JavaScript `ArrayBuffer` objects and raw memory pointers. This is a fundamental mechanism for accessing and manipulating memory content directly from JavaScript.

6. **Analyze `GumQuickNativeResource` and `GumQuickKernelResource`:** These seem to manage native and kernel resources, providing a way to tie native resources to their JavaScript counterparts and handle cleanup.

7. **Deconstruct `GumQuickFFIFunction` (Native and System Functions):** This is about calling native C functions from JavaScript. The code handles function construction, finalization, and invocation. It deals with function arguments, return types, and calling conventions (ABI). The distinction between "native" and "system" functions likely relates to how errors are handled (plain vs. detailed return values).

8. **Investigate `GumQuickNativeCallback`:**  This enables the reverse: calling JavaScript functions from native C code. It involves creating a native function pointer that, when called, executes the associated JavaScript function.

9. **Identify Interactions with Underlying Systems:** Look for platform-specific `#ifdef` directives (e.g., `HAVE_PTRAUTH`, `HAVE_ANDROID`). The use of `gpointer`, `gsize`, `ffi_type`, and `ffi_call` clearly indicates interaction with GLib and libffi, which are essential for low-level operations and dynamic function calls.

10. **Infer Use Cases and Reverse Engineering Relevance:** Connect the functionalities to common reverse engineering tasks:
    * **Memory Manipulation:**  Pointer arithmetic and bitwise operations are core to understanding memory layouts and data structures.
    * **Function Hooking/Interception:**  The `GumQuickFFIFunction` and `GumQuickNativeCallback` are crucial for intercepting and modifying the behavior of native functions.
    * **Data Inspection:**  Accessing memory through `ArrayBuffer` and converting pointers to different formats allows for examining the contents of memory.
    * **Understanding Pointer Authentication:** The PTRAUTH functions are essential when dealing with architectures that use these security features.

11. **Consider Potential User Errors:** Think about how a user might misuse these features:
    * Incorrect pointer arithmetic leading to invalid memory access.
    * Mismatched function signatures when using FFI, causing crashes or unexpected behavior.
    * Incorrectly handling resource lifetimes, leading to leaks.
    * Providing invalid ABI strings or options.

12. **Trace User Actions:** Imagine the steps a user takes to reach this code:
    * Writing a Frida script in JavaScript.
    * Using Frida's `NativePointer`, `ArrayBuffer`, `NativeFunction`, or `NativeCallback` classes.
    * Performing operations like pointer arithmetic, creating function hooks, or accessing memory.
    * Frida's JavaScript engine then calls into the native code, eventually reaching the functions defined in this file.

13. **Synthesize a Summary:** Combine all the observations into a concise description of the file's functionality, highlighting its role in bridging JavaScript and native code within Frida, and its significance for dynamic instrumentation and reverse engineering. Emphasize the capabilities related to memory manipulation, function calls, and resource management.

By following these steps, it's possible to dissect the provided C code and generate a comprehensive explanation of its functions and relevance within the Frida ecosystem, addressing all the user's specific requirements.
```c
""", &rhs_ptr)) \
        return JS_EXCEPTION; \
      \
      lhs_bits = GPOINTER_TO_SIZE (lhs_ptr); \
      rhs_bits = GPOINTER_TO_SIZE (rhs_ptr); \
      \
      result = GSIZE_TO_POINTER (lhs_bits op rhs_bits); \
      \
      return _gum_quick_native_pointer_new (ctx, result, core); \
    }

GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (add, +)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (sub, -)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (and, &)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (or,  |)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (xor, ^)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (shr, >>)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (shl, <<)

#define GUM_DEFINE_NATIVE_POINTER_UNARY_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_##name) \
    { \
      GumQuickNativePointer * self; \
      gpointer result; \
      \
      if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      result = GSIZE_TO_POINTER (op GPOINTER_TO_SIZE (self->value)); \
      \
      return _gum_quick_native_pointer_new (ctx, result, core); \
    }

GUM_DEFINE_NATIVE_POINTER_UNARY_OP_IMPL (not, ~)

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_sign)
{
#ifdef HAVE_PTRAUTH
  GumQuickNativePointer * self;
  gpointer value;
  const gchar * key;
  gpointer data;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  value = self->value;

  key = "ia";
  data = NULL;
  if (!_gum_quick_args_parse (args, "|sp~", &key, &data))
    return JS_EXCEPTION;

  if (strcmp (key, "ia") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asia, data);
  else if (strcmp (key, "ib") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asib, data);
  else if (strcmp (key, "da") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asda, data);
  else if (strcmp (key, "db") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asdb, data);
  else
    return _gum_quick_throw_literal (ctx, "invalid key");

  return _gum_quick_native_pointer_new (ctx, value, core);
#else
  return JS_DupValue (ctx, this_val);
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_strip)
{
#ifdef HAVE_PTRAUTH
  GumQuickNativePointer * self;
  gpointer value;
  const gchar * key;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  value = self->value;

  key = "ia";
  if (!_gum_quick_args_parse (args, "|s", &key))
    return JS_EXCEPTION;

  if (strcmp (key, "ia") == 0)
    value = ptrauth_strip (value, ptrauth_key_asia);
  else if (strcmp (key, "ib") == 0)
    value = ptrauth_strip (value, ptrauth_key_asib);
  else if (strcmp (key, "da") == 0)
    value = ptrauth_strip (value, ptrauth_key_asda);
  else if (strcmp (key, "db") == 0)
    value = ptrauth_strip (value, ptrauth_key_asdb);
  else
    return _gum_quick_throw_literal (ctx, "invalid key");

  return _gum_quick_native_pointer_new (ctx, value, core);
#elif defined (HAVE_ANDROID) && defined (HAVE_ARM64)
  GumQuickNativePointer * self;
  gpointer value_without_top_byte;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  /* https://source.android.com/devices/tech/debug/tagged-pointers */
  value_without_top_byte = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (self->value) & G_GUINT64_CONSTANT (0x00ffffffffffffff));

  if (value_without_top_byte == self->value)
    return JS_DupValue (ctx, this_val);

  return _gum_quick_native_pointer_new (ctx, value_without_top_byte, core);
#else
  return JS_DupValue (ctx, this_val);
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_blend)
{
#ifdef HAVE_PTRAUTH
  GumQuickNativePointer * self;
  gpointer value;
  guint small_integer;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  value = self->value;

  if (!_gum_quick_args_parse (args, "u", &small_integer))
    return JS_EXCEPTION;

  value = GSIZE_TO_POINTER (ptrauth_blend_discriminator (value, small_integer));

  return _gum_quick_native_pointer_new (ctx, value, core);
#else
  return JS_DupValue (ctx, this_val);
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_compare)
{
  GumQuickNativePointer * self;
  gpointer lhs_ptr, rhs_ptr;
  gsize lhs_bits, rhs_bits;
  gint result;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  lhs_ptr = self->value;

  if (!_gum_quick_args_parse (args, "p~", &rhs_ptr))
    return JS_EXCEPTION;

  lhs_bits = GPOINTER_TO_SIZE (lhs_ptr);
  rhs_bits = GPOINTER_TO_SIZE (rhs_ptr);

  result = (lhs_bits == rhs_bits) ? 0 : ((lhs_bits < rhs_bits) ? -1 : 1);

  return JS_NewInt32 (ctx, result);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_int32)
{
  GumQuickNativePointer * self;
  gint32 result;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  result = (gint32) GPOINTER_TO_SIZE (self->value);

  return JS_NewInt32 (ctx, result);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_uint32)
{
  GumQuickNativePointer * self;
  guint32 result;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  result = (guint32) GPOINTER_TO_SIZE (self->value);

  return JS_NewUint32 (ctx, result);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_string)
{
  GumQuickNativePointer * self;
  gint radix = 0;
  gboolean radix_specified;
  gsize ptr_bits;
  gchar str[32];

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "|u", &radix))
    return JS_EXCEPTION;

  radix_specified = radix != 0;
  if (!radix_specified)
    radix = 16;
  else if (radix != 10 && radix != 16)
    return _gum_quick_throw_literal (ctx, "unsupported radix");

  ptr_bits = GPOINTER_TO_SIZE (self->value);

  if (radix == 10)
  {
    sprintf (str, "%" G_GSIZE_MODIFIER "u", ptr_bits);
  }
  else
  {
    if (radix_specified)
      sprintf (str, "%" G_GSIZE_MODIFIER "x", ptr_bits);
    else
      sprintf (str, "0x%" G_GSIZE_MODIFIER "x", ptr_bits);
  }

  return JS_NewString (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_json)
{
  GumQuickNativePointer * self;
  gchar str[32];

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  sprintf (str, "0x%" G_GSIZE_MODIFIER "x", GPOINTER_TO_SIZE (self->value));

  return JS_NewString (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_match_pattern)
{
  GumQuickNativePointer * self;
  gsize ptr_bits;
  gchar str[24];
  gint src, dst;
  const gint num_bits = GLIB_SIZEOF_VOID_P * 8;
  const gchar nibble_to_char[] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f'
  };

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  ptr_bits = GPOINTER_TO_SIZE (self->value);

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  for (src = 0, dst = 0; src != num_bits; src += 8)
#else
  for (src = num_bits - 8, dst = 0; src >= 0; src -= 8)
#endif
  {
    if (dst != 0)
      str[dst++] = ' ';
    str[dst++] = nibble_to_char[(ptr_bits >> (src + 4)) & 0xf];
    str[dst++] = nibble_to_char[(ptr_bits >> (src + 0)) & 0xf];
  }
  str[dst] = '\0';

  return JS_NewString (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_array_buffer_wrap)
{
  gpointer address;
  gsize size;

  if (!_gum_quick_args_parse (args, "pZ", &address, &size))
    return JS_EXCEPTION;

  return JS_NewArrayBuffer (ctx, address, size, NULL, NULL, FALSE);
}

GUMJS_DEFINE_FUNCTION (gumjs_array_buffer_unwrap)
{
  uint8_t * address;
  size_t size;

  address = JS_GetArrayBuffer (ctx, &size, this_val);
  if (address == NULL)
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx, address, core);
}

GUMJS_DEFINE_FINALIZER (gumjs_native_resource_finalize)
{
  GumQuickNativeResource * r;

  r = JS_GetOpaque (val, core->native_resource_class);
  if (r == NULL)
    return;

  if (r->notify != NULL)
    r->notify (r->native_pointer.value);

  g_slice_free (GumQuickNativeResource, r);
}

GUMJS_DEFINE_FINALIZER (gumjs_kernel_resource_finalize)
{
  GumQuickKernelResource * r;

  r = JS_GetOpaque (val, core->kernel_resource_class);
  if (r == NULL)
    return;

  if (r->notify != NULL)
    r->notify (r->u64.value);

  g_slice_free (GumQuickKernelResource, r);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_function_construct)
{
  JSValue wrapper = JS_NULL;
  GumQuickFFIFunctionParams p = GUM_QUICK_FFI_FUNCTION_PARAMS_EMPTY;
  JSValue proto;
  GumQuickFFIFunction * func;

  if (!gum_quick_ffi_function_params_init (&p, GUM_QUICK_RETURN_PLAIN, args))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->native_function_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  func = gumjs_ffi_function_new (ctx, &p, core);
  if (func == NULL)
    goto propagate_exception;

  JS_SetOpaque (wrapper, func);

  gum_quick_ffi_function_params_destroy (&p);

  return wrapper;

propagate_exception:
  {
    JS_FreeValue (ctx, wrapper);
    gum_quick_ffi_function_params_destroy (&p);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_native_function_finalize)
{
  GumQuickFFIFunction * f;

  f = JS_GetOpaque (val, core->native_function_class);
  if (f == NULL)
    return;

  gum_quick_ffi_function_finalize (f);
}

GUMJS_DEFINE_CALL_HANDLER (gumjs_native_function_invoke)
{
  return gumjs_ffi_function_invoke (ctx, func_obj, core->native_function_class,
      args, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_call)
{
  return gumjs_ffi_function_call (ctx, this_val, core->native_function_class,
      args, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_apply)
{
  return gumjs_ffi_function_apply (ctx, this_val, core->native_function_class,
      args, core);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_system_function_construct)
{
  JSValue wrapper = JS_NULL;
  GumQuickFFIFunctionParams p = GUM_QUICK_FFI_FUNCTION_PARAMS_EMPTY;
  JSValue proto;
  GumQuickFFIFunction * func;

  if (!gum_quick_ffi_function_params_init (&p, GUM_QUICK_RETURN_DETAILED, args))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->system_function_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  func = gumjs_ffi_function_new (ctx, &p, core);
  if (func == NULL)
    goto propagate_exception;

  JS_SetOpaque (wrapper, func);

  gum_quick_ffi_function_params_destroy (&p);

  return wrapper;

propagate_exception:
  {
    JS_FreeValue (ctx, wrapper);
    gum_quick_ffi_function_params_destroy (&p);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_system_function_finalize)
{
  GumQuickFFIFunction * f;

  f = JS_GetOpaque (val, core->system_function_class);
  if (f == NULL)
    return;

  gum_quick_ffi_function_finalize (f);
}

GUMJS_DEFINE_CALL_HANDLER (gumjs_system_function_invoke)
{
  return gumjs_ffi_function_invoke (ctx, func_obj, core->system_function_class,
      args, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_system_function_call)
{
  return gumjs_ffi_function_call (ctx, this_val, core->system_function_class,
      args, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_system_function_apply)
{
  return gumjs_ffi_function_apply (ctx, this_val, core->system_function_class,
      args, core);
}

static GumQuickFFIFunction *
gumjs_ffi_function_new (JSContext * ctx,
                        const GumQuickFFIFunctionParams * params,
                        GumQuickCore * core)
{
  GumQuickFFIFunction * func;
  GumQuickNativePointer * ptr;
  ffi_type * rtype;
  JSValue val = JS_UNDEFINED;
  guint nargs_fixed, nargs_total, length, i;
  gboolean is_variadic;
  ffi_abi abi;

  func = g_slice_new0 (GumQuickFFIFunction);
  ptr = &func->native_pointer;
  ptr->value = GUM_FUNCPTR_TO_POINTER (params->implementation);
  func->implementation = params->implementation;
  func->scheduling = params->scheduling;
  func->exceptions = params->exceptions;
  func->traps = params->traps;
  func->return_shape = params->return_shape;

  if (!gum_quick_ffi_type_get (ctx, params->return_type, core, &rtype,
      &func->data))
    goto invalid_return_type;

  if (!_gum_quick_array_get_length (ctx, params->argument_types, core, &length))
    goto invalid_argument_array;

  nargs_fixed = nargs_total = length;
  is_variadic = FALSE;

  func->atypes = g_new (ffi_type *, nargs_total);

  for (i = 0; i != nargs_total; i++)
  {
    gboolean is_marker;

    val = JS_GetPropertyUint32 (ctx, params->argument_types, i);
    if (JS_IsException (val))
      goto invalid_argument_array;

    if (JS_IsString (val))
    {
      const char * str = JS_ToCString (ctx, val);
      is_marker = strcmp (str, "...") == 0;
      JS_FreeCString (ctx, str);
    }
    else
    {
      is_marker = FALSE;
    }

    if (is_marker)
    {
      if (i == 0 || is_variadic)
        goto unexpected_marker;

      nargs_fixed = i;
      is_variadic = TRUE;
    }
    else
    {
      ffi_type ** atype;

      atype = &func->atypes[is_variadic ? i - 1 : i];

      if (!gum_quick_ffi_type_get (ctx, val, core, atype, &func->data))
        goto invalid_argument_type;

      if (is_variadic)
        *atype = gum_ffi_maybe_promote_variadic (*atype);
    }

    JS_FreeValue (ctx, val);
    val = JS_UNDEFINED;
  }

  if (is_variadic)
    nargs_total--;

  if (params->abi_name != NULL)
  {
    if (!gum_quick_ffi_abi_get (ctx, params->abi_name, &abi))
      goto invalid_abi;
  }
  else
  {
    abi = FFI_DEFAULT_ABI;
  }

  if (is_variadic)
  {
    if (ffi_prep_cif_var (&func->cif, abi, (guint) nargs_fixed,
        (guint) nargs_total, rtype, func->atypes) != FFI_OK)
      goto compilation_failed;
  }
  else
  {
    if (ffi_prep_cif (&func->cif, abi, (guint) nargs_total, rtype,
        func->atypes) != FFI_OK)
      goto compilation_failed;
  }

  func->is_variadic = nargs_fixed < nargs_total;
  func->nargs_fixed = nargs_fixed;
  func->abi = abi;

  for (i = 0; i != nargs_total; i++)
  {
    ffi_type * t = func->atypes[i];

    func->arglist_size = GUM_ALIGN_SIZE (func->arglist_size, t->alignment);
    func->arglist_size += t->size;
  }

  return func;

invalid_return_type:
invalid_argument_array:
invalid_argument_type:
invalid_abi:
  {
    JS_FreeValue (ctx, val);
    gum_quick_ffi_function_finalize (func);

    return NULL;
  }
unexpected_marker:
  {
    JS_FreeValue (ctx, val);
    gum_quick_ffi_function_finalize (func);

    _gum_quick_throw_literal (ctx, "only one variadic marker may be specified, "
        "and can not be the first argument");
    return NULL;
  }
compilation_failed:
  {
    gum_quick_ffi_function_finalize (func);

    _gum_quick_throw_literal (ctx, "failed to compile function call interface");
    return NULL;
  }
}

static void
gum_quick_ffi_function_finalize (GumQuickFFIFunction * func)
{
  while (func->data != NULL)
  {
    GSList * head = func->data;
    g_free (head->data);
    func->data = g_slist_delete_link (func->data, head);
  }
  g_free (func->atypes);

  g_slice_free (GumQuickFFIFunction, func);
}

static JSValue
gum_quick_ffi_function_invoke (GumQuickFFIFunction * self,
                               JSContext * ctx,
                               GCallback implementation,
                               guint argc,
                               JSValueConst * argv,
                               GumQuickCore * core)
{
  JSValue result;
  ffi_cif * cif;
  guint nargs, nargs_fixed;
  gboolean is_variadic;
  ffi_type * rtype;
  ffi_type ** atypes;
  gsize rsize, ralign;
  GumFFIValue * rvalue;
  void ** avalue;
  guint8 * avalues;
  ffi_cif tmp_cif;
  GumFFIValue tmp_value = { 0, };
  GumQuickSchedulingBehavior scheduling;
  GumQuickExceptionsBehavior exceptions;
  GumQuickCodeTraps traps;
  GumQuickReturnValueShape return_shape;
  GumExceptorScope exceptor_scope;
  GumInvocationState invocation_state;
  gint system_error;

  cif = &self->cif;
  nargs = cif->nargs;
  nargs_fixed = self->nargs_fixed;
  is_variadic = self->is_variadic;

  if ((is_variadic && argc < nargs_fixed) || (!is_variadic && argc != nargs))
    return _gum_quick_throw_literal (ctx, "bad argument count");

  rtype = cif->rtype;
  atypes = cif->arg_types;
  rsize = MAX (rtype->size, sizeof (gsize));
  ralign = MAX (rtype->alignment, sizeof (gsize));
  rvalue = g_alloca (rsize + ralign - 1);
  rvalue = GUM_ALIGN_POINTER (GumFFIValue *, rvalue, ralign);

  if (argc > 0)
  {
    gsize arglist_size, arglist_alignment, offset, i;

    avalue = g_newa (void *, MAX (nargs, argc));

    arglist_size = self->arglist_size;
    if (is_variadic && argc > nargs)
    {
      gsize type_idx;

      atypes = g_newa (ffi_type *, argc);

      memcpy (atypes, cif->arg_types, nargs * sizeof (void *));
      for (i = nargs, type_idx = nargs_fixed; i != argc; i++)
      {
        ffi_type * t = cif->arg_types[type_idx];

        atypes[i] = t;
        arglist_size = GUM_ALIGN_SIZE (arglist_size, t->alignment);
        arglist_size += t->size;

        if (++type_idx >= nargs)
          type_idx = nargs_fixed;
      }

      cif = &tmp_cif;
      if (ffi_prep_cif_var (cif, self->abi, (guint) nargs_fixed,
          (guint) argc, rtype, atypes) != FFI_OK)
      {
        return _gum_quick_throw_literal (ctx,
            "failed to compile function call interface");
      }
    }

    arglist_alignment = atypes[0]->alignment;
    avalues = g_alloca (arglist_size + arglist_alignment - 1);
    avalues = GUM_ALIGN_POINTER (guint8 *, avalues, arglist_alignment);

    /* Prefill with zero to clear high bits of values smaller than a pointer. */
    memset (avalues, 0, arglist_size);

    offset = 0;
    for (i = 0; i != argc; i++)
    {
      ffi_type * t;
      GumFFIValue * v;

      t = atypes[i];
      offset = GUM_ALIGN_SIZE (offset, t->alignment);
      v = (GumFFIValue *) (avalues + offset);

      if (!gum_quick_value_to_ffi (ctx, argv[i], t, core, v))
        return JS_EXCEPTION;
      avalue[i] = v;

      offset += t->size;
    }

    while (i < nargs)
      avalue[i++] = &tmp_value;
  }
  else
  {
    avalue = NULL;
  }

  scheduling = self->scheduling;
  exceptions = self->exceptions;
  traps = self->traps;
  return_shape = self->return_shape;
  system_error = -1;

  {
    GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
    GumInterceptor * interceptor = (core->interceptor != NULL)
        ? core->interceptor->interceptor
        : NULL;
    gboolean interceptor_was_ignoring_us = FALSE;
    GumStalker * stalker = NULL;

    if (exceptions == GUM_QUICK_EXCEPTIONS_PROPAGATE ||
        gum_exceptor_try (core->exceptor, &exceptor_scope))
    {
      if (exceptions == GUM_QUICK_EXCEPTIONS_STEAL)
        gum_interceptor_save (&invocation_state);

      if (scheduling == GUM_QUICK_SCHEDULING_COOPERATIVE)
      {
        _gum_quick_scope_suspend (&scope);

        if (traps != GUM_QUICK_CODE_TRAPS_NONE && interceptor != NULL)
        {
          interceptor_
### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickcore.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
", &rhs_ptr)) \
        return JS_EXCEPTION; \
      \
      lhs_bits = GPOINTER_TO_SIZE (lhs_ptr); \
      rhs_bits = GPOINTER_TO_SIZE (rhs_ptr); \
      \
      result = GSIZE_TO_POINTER (lhs_bits op rhs_bits); \
      \
      return _gum_quick_native_pointer_new (ctx, result, core); \
    }

GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (add, +)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (sub, -)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (and, &)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (or,  |)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (xor, ^)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (shr, >>)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (shl, <<)

#define GUM_DEFINE_NATIVE_POINTER_UNARY_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_##name) \
    { \
      GumQuickNativePointer * self; \
      gpointer result; \
      \
      if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      result = GSIZE_TO_POINTER (op GPOINTER_TO_SIZE (self->value)); \
      \
      return _gum_quick_native_pointer_new (ctx, result, core); \
    }

GUM_DEFINE_NATIVE_POINTER_UNARY_OP_IMPL (not, ~)

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_sign)
{
#ifdef HAVE_PTRAUTH
  GumQuickNativePointer * self;
  gpointer value;
  const gchar * key;
  gpointer data;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  value = self->value;

  key = "ia";
  data = NULL;
  if (!_gum_quick_args_parse (args, "|sp~", &key, &data))
    return JS_EXCEPTION;

  if (strcmp (key, "ia") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asia, data);
  else if (strcmp (key, "ib") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asib, data);
  else if (strcmp (key, "da") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asda, data);
  else if (strcmp (key, "db") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asdb, data);
  else
    return _gum_quick_throw_literal (ctx, "invalid key");

  return _gum_quick_native_pointer_new (ctx, value, core);
#else
  return JS_DupValue (ctx, this_val);
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_strip)
{
#ifdef HAVE_PTRAUTH
  GumQuickNativePointer * self;
  gpointer value;
  const gchar * key;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  value = self->value;

  key = "ia";
  if (!_gum_quick_args_parse (args, "|s", &key))
    return JS_EXCEPTION;

  if (strcmp (key, "ia") == 0)
    value = ptrauth_strip (value, ptrauth_key_asia);
  else if (strcmp (key, "ib") == 0)
    value = ptrauth_strip (value, ptrauth_key_asib);
  else if (strcmp (key, "da") == 0)
    value = ptrauth_strip (value, ptrauth_key_asda);
  else if (strcmp (key, "db") == 0)
    value = ptrauth_strip (value, ptrauth_key_asdb);
  else
    return _gum_quick_throw_literal (ctx, "invalid key");

  return _gum_quick_native_pointer_new (ctx, value, core);
#elif defined (HAVE_ANDROID) && defined (HAVE_ARM64)
  GumQuickNativePointer * self;
  gpointer value_without_top_byte;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  /* https://source.android.com/devices/tech/debug/tagged-pointers */
  value_without_top_byte = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (self->value) & G_GUINT64_CONSTANT (0x00ffffffffffffff));

  if (value_without_top_byte == self->value)
    return JS_DupValue (ctx, this_val);

  return _gum_quick_native_pointer_new (ctx, value_without_top_byte, core);
#else
  return JS_DupValue (ctx, this_val);
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_blend)
{
#ifdef HAVE_PTRAUTH
  GumQuickNativePointer * self;
  gpointer value;
  guint small_integer;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  value = self->value;

  if (!_gum_quick_args_parse (args, "u", &small_integer))
    return JS_EXCEPTION;

  value = GSIZE_TO_POINTER (ptrauth_blend_discriminator (value, small_integer));

  return _gum_quick_native_pointer_new (ctx, value, core);
#else
  return JS_DupValue (ctx, this_val);
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_compare)
{
  GumQuickNativePointer * self;
  gpointer lhs_ptr, rhs_ptr;
  gsize lhs_bits, rhs_bits;
  gint result;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  lhs_ptr = self->value;

  if (!_gum_quick_args_parse (args, "p~", &rhs_ptr))
    return JS_EXCEPTION;

  lhs_bits = GPOINTER_TO_SIZE (lhs_ptr);
  rhs_bits = GPOINTER_TO_SIZE (rhs_ptr);

  result = (lhs_bits == rhs_bits) ? 0 : ((lhs_bits < rhs_bits) ? -1 : 1);

  return JS_NewInt32 (ctx, result);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_int32)
{
  GumQuickNativePointer * self;
  gint32 result;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  result = (gint32) GPOINTER_TO_SIZE (self->value);

  return JS_NewInt32 (ctx, result);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_uint32)
{
  GumQuickNativePointer * self;
  guint32 result;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  result = (guint32) GPOINTER_TO_SIZE (self->value);

  return JS_NewUint32 (ctx, result);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_string)
{
  GumQuickNativePointer * self;
  gint radix = 0;
  gboolean radix_specified;
  gsize ptr_bits;
  gchar str[32];

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "|u", &radix))
    return JS_EXCEPTION;

  radix_specified = radix != 0;
  if (!radix_specified)
    radix = 16;
  else if (radix != 10 && radix != 16)
    return _gum_quick_throw_literal (ctx, "unsupported radix");

  ptr_bits = GPOINTER_TO_SIZE (self->value);

  if (radix == 10)
  {
    sprintf (str, "%" G_GSIZE_MODIFIER "u", ptr_bits);
  }
  else
  {
    if (radix_specified)
      sprintf (str, "%" G_GSIZE_MODIFIER "x", ptr_bits);
    else
      sprintf (str, "0x%" G_GSIZE_MODIFIER "x", ptr_bits);
  }

  return JS_NewString (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_json)
{
  GumQuickNativePointer * self;
  gchar str[32];

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  sprintf (str, "0x%" G_GSIZE_MODIFIER "x", GPOINTER_TO_SIZE (self->value));

  return JS_NewString (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_match_pattern)
{
  GumQuickNativePointer * self;
  gsize ptr_bits;
  gchar str[24];
  gint src, dst;
  const gint num_bits = GLIB_SIZEOF_VOID_P * 8;
  const gchar nibble_to_char[] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f'
  };

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  ptr_bits = GPOINTER_TO_SIZE (self->value);

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  for (src = 0, dst = 0; src != num_bits; src += 8)
#else
  for (src = num_bits - 8, dst = 0; src >= 0; src -= 8)
#endif
  {
    if (dst != 0)
      str[dst++] = ' ';
    str[dst++] = nibble_to_char[(ptr_bits >> (src + 4)) & 0xf];
    str[dst++] = nibble_to_char[(ptr_bits >> (src + 0)) & 0xf];
  }
  str[dst] = '\0';

  return JS_NewString (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_array_buffer_wrap)
{
  gpointer address;
  gsize size;

  if (!_gum_quick_args_parse (args, "pZ", &address, &size))
    return JS_EXCEPTION;

  return JS_NewArrayBuffer (ctx, address, size, NULL, NULL, FALSE);
}

GUMJS_DEFINE_FUNCTION (gumjs_array_buffer_unwrap)
{
  uint8_t * address;
  size_t size;

  address = JS_GetArrayBuffer (ctx, &size, this_val);
  if (address == NULL)
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx, address, core);
}

GUMJS_DEFINE_FINALIZER (gumjs_native_resource_finalize)
{
  GumQuickNativeResource * r;

  r = JS_GetOpaque (val, core->native_resource_class);
  if (r == NULL)
    return;

  if (r->notify != NULL)
    r->notify (r->native_pointer.value);

  g_slice_free (GumQuickNativeResource, r);
}

GUMJS_DEFINE_FINALIZER (gumjs_kernel_resource_finalize)
{
  GumQuickKernelResource * r;

  r = JS_GetOpaque (val, core->kernel_resource_class);
  if (r == NULL)
    return;

  if (r->notify != NULL)
    r->notify (r->u64.value);

  g_slice_free (GumQuickKernelResource, r);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_function_construct)
{
  JSValue wrapper = JS_NULL;
  GumQuickFFIFunctionParams p = GUM_QUICK_FFI_FUNCTION_PARAMS_EMPTY;
  JSValue proto;
  GumQuickFFIFunction * func;

  if (!gum_quick_ffi_function_params_init (&p, GUM_QUICK_RETURN_PLAIN, args))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->native_function_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  func = gumjs_ffi_function_new (ctx, &p, core);
  if (func == NULL)
    goto propagate_exception;

  JS_SetOpaque (wrapper, func);

  gum_quick_ffi_function_params_destroy (&p);

  return wrapper;

propagate_exception:
  {
    JS_FreeValue (ctx, wrapper);
    gum_quick_ffi_function_params_destroy (&p);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_native_function_finalize)
{
  GumQuickFFIFunction * f;

  f = JS_GetOpaque (val, core->native_function_class);
  if (f == NULL)
    return;

  gum_quick_ffi_function_finalize (f);
}

GUMJS_DEFINE_CALL_HANDLER (gumjs_native_function_invoke)
{
  return gumjs_ffi_function_invoke (ctx, func_obj, core->native_function_class,
      args, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_call)
{
  return gumjs_ffi_function_call (ctx, this_val, core->native_function_class,
      args, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_apply)
{
  return gumjs_ffi_function_apply (ctx, this_val, core->native_function_class,
      args, core);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_system_function_construct)
{
  JSValue wrapper = JS_NULL;
  GumQuickFFIFunctionParams p = GUM_QUICK_FFI_FUNCTION_PARAMS_EMPTY;
  JSValue proto;
  GumQuickFFIFunction * func;

  if (!gum_quick_ffi_function_params_init (&p, GUM_QUICK_RETURN_DETAILED, args))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->system_function_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  func = gumjs_ffi_function_new (ctx, &p, core);
  if (func == NULL)
    goto propagate_exception;

  JS_SetOpaque (wrapper, func);

  gum_quick_ffi_function_params_destroy (&p);

  return wrapper;

propagate_exception:
  {
    JS_FreeValue (ctx, wrapper);
    gum_quick_ffi_function_params_destroy (&p);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_system_function_finalize)
{
  GumQuickFFIFunction * f;

  f = JS_GetOpaque (val, core->system_function_class);
  if (f == NULL)
    return;

  gum_quick_ffi_function_finalize (f);
}

GUMJS_DEFINE_CALL_HANDLER (gumjs_system_function_invoke)
{
  return gumjs_ffi_function_invoke (ctx, func_obj, core->system_function_class,
      args, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_system_function_call)
{
  return gumjs_ffi_function_call (ctx, this_val, core->system_function_class,
      args, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_system_function_apply)
{
  return gumjs_ffi_function_apply (ctx, this_val, core->system_function_class,
      args, core);
}

static GumQuickFFIFunction *
gumjs_ffi_function_new (JSContext * ctx,
                        const GumQuickFFIFunctionParams * params,
                        GumQuickCore * core)
{
  GumQuickFFIFunction * func;
  GumQuickNativePointer * ptr;
  ffi_type * rtype;
  JSValue val = JS_UNDEFINED;
  guint nargs_fixed, nargs_total, length, i;
  gboolean is_variadic;
  ffi_abi abi;

  func = g_slice_new0 (GumQuickFFIFunction);
  ptr = &func->native_pointer;
  ptr->value = GUM_FUNCPTR_TO_POINTER (params->implementation);
  func->implementation = params->implementation;
  func->scheduling = params->scheduling;
  func->exceptions = params->exceptions;
  func->traps = params->traps;
  func->return_shape = params->return_shape;

  if (!gum_quick_ffi_type_get (ctx, params->return_type, core, &rtype,
      &func->data))
    goto invalid_return_type;

  if (!_gum_quick_array_get_length (ctx, params->argument_types, core, &length))
    goto invalid_argument_array;

  nargs_fixed = nargs_total = length;
  is_variadic = FALSE;

  func->atypes = g_new (ffi_type *, nargs_total);

  for (i = 0; i != nargs_total; i++)
  {
    gboolean is_marker;

    val = JS_GetPropertyUint32 (ctx, params->argument_types, i);
    if (JS_IsException (val))
      goto invalid_argument_array;

    if (JS_IsString (val))
    {
      const char * str = JS_ToCString (ctx, val);
      is_marker = strcmp (str, "...") == 0;
      JS_FreeCString (ctx, str);
    }
    else
    {
      is_marker = FALSE;
    }

    if (is_marker)
    {
      if (i == 0 || is_variadic)
        goto unexpected_marker;

      nargs_fixed = i;
      is_variadic = TRUE;
    }
    else
    {
      ffi_type ** atype;

      atype = &func->atypes[is_variadic ? i - 1 : i];

      if (!gum_quick_ffi_type_get (ctx, val, core, atype, &func->data))
        goto invalid_argument_type;

      if (is_variadic)
        *atype = gum_ffi_maybe_promote_variadic (*atype);
    }

    JS_FreeValue (ctx, val);
    val = JS_UNDEFINED;
  }

  if (is_variadic)
    nargs_total--;

  if (params->abi_name != NULL)
  {
    if (!gum_quick_ffi_abi_get (ctx, params->abi_name, &abi))
      goto invalid_abi;
  }
  else
  {
    abi = FFI_DEFAULT_ABI;
  }

  if (is_variadic)
  {
    if (ffi_prep_cif_var (&func->cif, abi, (guint) nargs_fixed,
        (guint) nargs_total, rtype, func->atypes) != FFI_OK)
      goto compilation_failed;
  }
  else
  {
    if (ffi_prep_cif (&func->cif, abi, (guint) nargs_total, rtype,
        func->atypes) != FFI_OK)
      goto compilation_failed;
  }

  func->is_variadic = nargs_fixed < nargs_total;
  func->nargs_fixed = nargs_fixed;
  func->abi = abi;

  for (i = 0; i != nargs_total; i++)
  {
    ffi_type * t = func->atypes[i];

    func->arglist_size = GUM_ALIGN_SIZE (func->arglist_size, t->alignment);
    func->arglist_size += t->size;
  }

  return func;

invalid_return_type:
invalid_argument_array:
invalid_argument_type:
invalid_abi:
  {
    JS_FreeValue (ctx, val);
    gum_quick_ffi_function_finalize (func);

    return NULL;
  }
unexpected_marker:
  {
    JS_FreeValue (ctx, val);
    gum_quick_ffi_function_finalize (func);

    _gum_quick_throw_literal (ctx, "only one variadic marker may be specified, "
        "and can not be the first argument");
    return NULL;
  }
compilation_failed:
  {
    gum_quick_ffi_function_finalize (func);

    _gum_quick_throw_literal (ctx, "failed to compile function call interface");
    return NULL;
  }
}

static void
gum_quick_ffi_function_finalize (GumQuickFFIFunction * func)
{
  while (func->data != NULL)
  {
    GSList * head = func->data;
    g_free (head->data);
    func->data = g_slist_delete_link (func->data, head);
  }
  g_free (func->atypes);

  g_slice_free (GumQuickFFIFunction, func);
}

static JSValue
gum_quick_ffi_function_invoke (GumQuickFFIFunction * self,
                               JSContext * ctx,
                               GCallback implementation,
                               guint argc,
                               JSValueConst * argv,
                               GumQuickCore * core)
{
  JSValue result;
  ffi_cif * cif;
  guint nargs, nargs_fixed;
  gboolean is_variadic;
  ffi_type * rtype;
  ffi_type ** atypes;
  gsize rsize, ralign;
  GumFFIValue * rvalue;
  void ** avalue;
  guint8 * avalues;
  ffi_cif tmp_cif;
  GumFFIValue tmp_value = { 0, };
  GumQuickSchedulingBehavior scheduling;
  GumQuickExceptionsBehavior exceptions;
  GumQuickCodeTraps traps;
  GumQuickReturnValueShape return_shape;
  GumExceptorScope exceptor_scope;
  GumInvocationState invocation_state;
  gint system_error;

  cif = &self->cif;
  nargs = cif->nargs;
  nargs_fixed = self->nargs_fixed;
  is_variadic = self->is_variadic;

  if ((is_variadic && argc < nargs_fixed) || (!is_variadic && argc != nargs))
    return _gum_quick_throw_literal (ctx, "bad argument count");

  rtype = cif->rtype;
  atypes = cif->arg_types;
  rsize = MAX (rtype->size, sizeof (gsize));
  ralign = MAX (rtype->alignment, sizeof (gsize));
  rvalue = g_alloca (rsize + ralign - 1);
  rvalue = GUM_ALIGN_POINTER (GumFFIValue *, rvalue, ralign);

  if (argc > 0)
  {
    gsize arglist_size, arglist_alignment, offset, i;

    avalue = g_newa (void *, MAX (nargs, argc));

    arglist_size = self->arglist_size;
    if (is_variadic && argc > nargs)
    {
      gsize type_idx;

      atypes = g_newa (ffi_type *, argc);

      memcpy (atypes, cif->arg_types, nargs * sizeof (void *));
      for (i = nargs, type_idx = nargs_fixed; i != argc; i++)
      {
        ffi_type * t = cif->arg_types[type_idx];

        atypes[i] = t;
        arglist_size = GUM_ALIGN_SIZE (arglist_size, t->alignment);
        arglist_size += t->size;

        if (++type_idx >= nargs)
          type_idx = nargs_fixed;
      }

      cif = &tmp_cif;
      if (ffi_prep_cif_var (cif, self->abi, (guint) nargs_fixed,
          (guint) argc, rtype, atypes) != FFI_OK)
      {
        return _gum_quick_throw_literal (ctx,
            "failed to compile function call interface");
      }
    }

    arglist_alignment = atypes[0]->alignment;
    avalues = g_alloca (arglist_size + arglist_alignment - 1);
    avalues = GUM_ALIGN_POINTER (guint8 *, avalues, arglist_alignment);

    /* Prefill with zero to clear high bits of values smaller than a pointer. */
    memset (avalues, 0, arglist_size);

    offset = 0;
    for (i = 0; i != argc; i++)
    {
      ffi_type * t;
      GumFFIValue * v;

      t = atypes[i];
      offset = GUM_ALIGN_SIZE (offset, t->alignment);
      v = (GumFFIValue *) (avalues + offset);

      if (!gum_quick_value_to_ffi (ctx, argv[i], t, core, v))
        return JS_EXCEPTION;
      avalue[i] = v;

      offset += t->size;
    }

    while (i < nargs)
      avalue[i++] = &tmp_value;
  }
  else
  {
    avalue = NULL;
  }

  scheduling = self->scheduling;
  exceptions = self->exceptions;
  traps = self->traps;
  return_shape = self->return_shape;
  system_error = -1;

  {
    GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
    GumInterceptor * interceptor = (core->interceptor != NULL)
        ? core->interceptor->interceptor
        : NULL;
    gboolean interceptor_was_ignoring_us = FALSE;
    GumStalker * stalker = NULL;

    if (exceptions == GUM_QUICK_EXCEPTIONS_PROPAGATE ||
        gum_exceptor_try (core->exceptor, &exceptor_scope))
    {
      if (exceptions == GUM_QUICK_EXCEPTIONS_STEAL)
        gum_interceptor_save (&invocation_state);

      if (scheduling == GUM_QUICK_SCHEDULING_COOPERATIVE)
      {
        _gum_quick_scope_suspend (&scope);

        if (traps != GUM_QUICK_CODE_TRAPS_NONE && interceptor != NULL)
        {
          interceptor_was_ignoring_us =
              gum_interceptor_maybe_unignore_current_thread (interceptor);
        }
      }

      if (traps == GUM_QUICK_CODE_TRAPS_ALL)
      {
        _gum_quick_stalker_process_pending (core->stalker,
            scope.previous_scope);

        stalker = _gum_quick_stalker_get (core->stalker);
        gum_stalker_activate (stalker,
            GUM_FUNCPTR_TO_POINTER (implementation));
      }
      else if (traps == GUM_QUICK_CODE_TRAPS_NONE && interceptor != NULL)
      {
        gum_interceptor_ignore_current_thread (interceptor);
      }

      ffi_call (cif, implementation, rvalue, avalue);

      g_clear_pointer (&stalker, gum_stalker_deactivate);

      if (return_shape == GUM_QUICK_RETURN_DETAILED)
        system_error = gum_thread_get_system_error ();
    }

    g_clear_pointer (&stalker, gum_stalker_deactivate);

    if (traps == GUM_QUICK_CODE_TRAPS_NONE && interceptor != NULL)
      gum_interceptor_unignore_current_thread (interceptor);

    if (scheduling == GUM_QUICK_SCHEDULING_COOPERATIVE)
    {
      if (traps != GUM_QUICK_CODE_TRAPS_NONE && interceptor_was_ignoring_us)
        gum_interceptor_ignore_current_thread (interceptor);

      _gum_quick_scope_resume (&scope);
    }
  }

  if (exceptions == GUM_QUICK_EXCEPTIONS_STEAL &&
      gum_exceptor_catch (core->exceptor, &exceptor_scope))
  {
    gum_interceptor_restore (&invocation_state);

    return _gum_quick_throw_native (ctx, &exceptor_scope.exception, core);
  }

  result = gum_quick_value_from_ffi (ctx, rvalue, rtype, core);

  if (return_shape == GUM_QUICK_RETURN_DETAILED)
  {
    JSValue d = JS_NewObject (ctx);
    JS_DefinePropertyValue (ctx, d,
        GUM_QUICK_CORE_ATOM (core, value),
        result,
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, d,
        GUM_QUICK_CORE_ATOM (core, system_error),
        JS_NewInt32 (ctx, system_error),
        JS_PROP_C_W_E);
    return d;
  }
  else
  {
    return result;
  }
}

static JSValue
gumjs_ffi_function_invoke (JSContext * ctx,
                           JSValueConst func_obj,
                           JSClassID klass,
                           GumQuickArgs * args,
                           GumQuickCore * core)
{
  GumQuickFFIFunction * self;

  if (!_gum_quick_unwrap (ctx, func_obj, klass, core, (gpointer *) &self))
    return JS_EXCEPTION;

  return gum_quick_ffi_function_invoke (self, ctx, self->implementation,
      args->count, args->elements, core);
}

static JSValue
gumjs_ffi_function_call (JSContext * ctx,
                         JSValueConst func_obj,
                         JSClassID klass,
                         GumQuickArgs * args,
                         GumQuickCore * core)
{
  const int argc = args->count;
  JSValueConst * argv = args->elements;
  JSValue receiver;
  GumQuickFFIFunction * func;
  GCallback impl;

  if (argc == 0 || JS_IsNull (argv[0]) || JS_IsUndefined (argv[0]))
  {
    receiver = JS_NULL;
  }
  else if (JS_IsObject (argv[0]))
  {
    receiver = argv[0];
  }
  else
  {
    return _gum_quick_throw_literal (ctx, "invalid receiver");
  }

  if (!gumjs_ffi_function_get (ctx, func_obj, receiver, klass, core, &func,
      &impl))
  {
    return JS_EXCEPTION;
  }

  return gum_quick_ffi_function_invoke (func, ctx, impl, MAX (argc - 1, 0),
      argv + 1, core);
}

static JSValue
gumjs_ffi_function_apply (JSContext * ctx,
                          JSValueConst func_obj,
                          JSClassID klass,
                          GumQuickArgs * args,
                          GumQuickCore * core)
{
  JSValueConst * argv = args->elements;
  JSValue receiver;
  GumQuickFFIFunction * func;
  GCallback impl;
  guint n, i;
  JSValue * values;

  if (JS_IsNull (argv[0]) || JS_IsUndefined (argv[0]))
  {
    receiver = JS_NULL;
  }
  else if (JS_IsObject (argv[0]))
  {
    receiver = argv[0];
  }
  else
  {
    return _gum_quick_throw_literal (ctx, "invalid receiver");
  }

  if (!gumjs_ffi_function_get (ctx, func_obj, receiver, klass, core, &func,
      &impl))
  {
    return JS_EXCEPTION;
  }

  if (JS_IsNull (argv[1]) || JS_IsUndefined (argv[1]))
  {
    return gum_quick_ffi_function_invoke (func, ctx, impl, 0, NULL, core);
  }
  else
  {
    JSValueConst elements = argv[1];
    JSValue result;

    if (!_gum_quick_array_get_length (ctx, elements, core, &n))
      return JS_EXCEPTION;

    values = g_newa (JSValue, n);

    for (i = 0; i != n; i++)
    {
      values[i] = JS_GetPropertyUint32 (ctx, elements, i);
      if (JS_IsException (values[i]))
        goto invalid_argument_value;
    }

    result = gum_quick_ffi_function_invoke (func, ctx, impl, n, values, core);

    for (i = 0; i != n; i++)
      JS_FreeValue (ctx, values[i]);

    return result;
  }

invalid_argument_value:
  {
    n = i;
    for (i = 0; i != n; i++)
      JS_FreeValue (ctx, values[i]);

    return JS_EXCEPTION;
  }
}

static gboolean
gumjs_ffi_function_get (JSContext * ctx,
                        JSValueConst func_obj,
                        JSValueConst receiver,
                        JSClassID klass,
                        GumQuickCore * core,
                        GumQuickFFIFunction ** func,
                        GCallback * implementation)
{
  GumQuickFFIFunction * f;

  if (_gum_quick_try_unwrap (func_obj, klass, core, (gpointer *) &f))
  {
    *func = f;

    if (!JS_IsNull (receiver))
    {
      gpointer impl;
      if (!_gum_quick_native_pointer_get (ctx, receiver, core, &impl))
        return FALSE;
      *implementation = GUM_POINTER_TO_FUNCPTR (GCallback, impl);
    }
    else
    {
      *implementation = f->implementation;
    }
  }
  else
  {
    if (!_gum_quick_unwrap (ctx, receiver, klass, core, (gpointer *) &f))
      return FALSE;

    *func = f;
    *implementation = f->implementation;
  }

  return TRUE;
}

static gboolean
gum_quick_ffi_function_params_init (GumQuickFFIFunctionParams * params,
                                    GumQuickReturnValueShape return_shape,
                                    GumQuickArgs * args)
{
  JSContext * ctx = args->ctx;
  JSValueConst abi_or_options;
  JSValue val;

  params->ctx = ctx;

  abi_or_options = JS_UNDEFINED;
  if (!_gum_quick_args_parse (args, "pVA|V", &params->implementation,
      &params->return_type, &params->argument_types, &abi_or_options))
  {
    return FALSE;
  }
  params->abi_name = NULL;
  params->scheduling = GUM_QUICK_SCHEDULING_COOPERATIVE;
  params->exceptions = GUM_QUICK_EXCEPTIONS_STEAL;
  params->traps = GUM_QUICK_CODE_TRAPS_DEFAULT;
  params->return_shape = return_shape;

  if (JS_IsString (abi_or_options))
  {
    JSValueConst abi = abi_or_options;

    params->abi_name = JS_ToCString (ctx, abi);
  }
  else if (JS_IsObject (abi_or_options))
  {
    JSValueConst options = abi_or_options;
    GumQuickCore * core = args->core;

    val = JS_GetProperty (ctx, options, GUM_QUICK_CORE_ATOM (core, abi));
    if (JS_IsException (val))
      goto invalid_value;
    if (!JS_IsUndefined (val))
    {
      params->abi_name = JS_ToCString (ctx, val);
      if (params->abi_name == NULL)
        goto invalid_value;
      JS_FreeValue (ctx, val);
    }

    val = JS_GetProperty (ctx, options, GUM_QUICK_CORE_ATOM (core, scheduling));
    if (JS_IsException (val))
      goto invalid_value;
    if (!JS_IsUndefined (val))
    {
      if (!gum_quick_scheduling_behavior_get (ctx, val, &params->scheduling))
        goto invalid_value;
      JS_FreeValue (ctx, val);
    }

    val = JS_GetProperty (ctx, options, GUM_QUICK_CORE_ATOM (core, exceptions));
    if (JS_IsException (val))
      goto invalid_value;
    if (!JS_IsUndefined (val))
    {
      if (!gum_quick_exceptions_behavior_get (ctx, val, &params->exceptions))
        goto invalid_value;
      JS_FreeValue (ctx, val);
    }

    val = JS_GetProperty (ctx, options, GUM_QUICK_CORE_ATOM (core, traps));
    if (JS_IsException (val))
      goto invalid_value;
    if (!JS_IsUndefined (val))
    {
      if (!gum_quick_code_traps_get (ctx, val, &params->traps))
        goto invalid_value;
      JS_FreeValue (ctx, val);
    }
  }
  else if (!JS_IsUndefined (abi_or_options))
  {
    _gum_quick_throw_literal (ctx,
        "expected string or object containing options");
    return FALSE;
  }

  return TRUE;

invalid_value:
  {
    JS_FreeValue (ctx, val);
    JS_FreeCString (ctx, params->abi_name);

    return FALSE;
  }
}

static void
gum_quick_ffi_function_params_destroy (GumQuickFFIFunctionParams * params)
{
  JSContext * ctx = params->ctx;

  JS_FreeCString (ctx, params->abi_name);
}

static gboolean
gum_quick_scheduling_behavior_get (JSContext * ctx,
                                   JSValueConst val,
                                   GumQuickSchedulingBehavior * behavior)
{
  const char * str;

  str = JS_ToCString (ctx, val);
  if (str == NULL)
    return FALSE;

  if (strcmp (str, "cooperative") == 0)
    *behavior = GUM_QUICK_SCHEDULING_COOPERATIVE;
  else if (strcmp (str, "exclusive") == 0)
    *behavior = GUM_QUICK_SCHEDULING_EXCLUSIVE;
  else
    goto invalid_value;

  JS_FreeCString (ctx, str);

  return TRUE;

invalid_value:
  {
    JS_FreeCString (ctx, str);

    _gum_quick_throw_literal (ctx, "invalid scheduling behavior value");
    return FALSE;
  }
}

static gboolean
gum_quick_exceptions_behavior_get (JSContext * ctx,
                                   JSValueConst val,
                                   GumQuickExceptionsBehavior * behavior)
{
  const char * str;

  str = JS_ToCString (ctx, val);
  if (str == NULL)
    return FALSE;

  if (strcmp (str, "steal") == 0)
    *behavior = GUM_QUICK_EXCEPTIONS_STEAL;
  else if (strcmp (str, "propagate") == 0)
    *behavior = GUM_QUICK_EXCEPTIONS_PROPAGATE;
  else
    goto invalid_value;

  JS_FreeCString (ctx, str);

  return TRUE;

invalid_value:
  {
    JS_FreeCString (ctx, str);

    _gum_quick_throw_literal (ctx, "invalid exceptions behavior value");
    return FALSE;
  }
}

static gboolean
gum_quick_code_traps_get (JSContext * ctx,
                          JSValueConst val,
                          GumQuickCodeTraps * traps)
{
  const char * str;

  str = JS_ToCString (ctx, val);
  if (str == NULL)
    return FALSE;

  if (strcmp (str, "default") == 0)
    *traps = GUM_QUICK_CODE_TRAPS_DEFAULT;
  else if (strcmp (str, "none") == 0)
    *traps = GUM_QUICK_CODE_TRAPS_NONE;
  else if (strcmp (str, "all") == 0)
    *traps = GUM_QUICK_CODE_TRAPS_ALL;
  else
    goto invalid_value;

  JS_FreeCString (ctx, str);

  return TRUE;

invalid_value:
  {
    JS_FreeCString (ctx, str);

    _gum_quick_throw_literal (ctx, "invalid code traps value");
    return FALSE;
  }
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_callback_construct)
{
  JSValue wrapper = JS_NULL;
  JSValue func, rtype_value, atypes_array, proto;
  gchar * abi_str = NULL;
  GumQuickNativeCallback * cb = NULL;
  GumQuickNativePointer * ptr;
  ffi_type * rtype;
  guint nargs, i;
  JSValue val = JS_NULL;
  ffi_abi abi;

  if (!_gum_quick_args_parse (args, "FVA|s", &func, &rtype_value, &atypes_array,
      &abi_str))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->native_callback_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  cb = g_slice_new0 (GumQuickNativeCallback);
  ptr = &cb->native_pointer;
  cb->wrapper = wrapper;
  cb->func = func;
  cb->core = core;

  if (!gum_quick_ffi_type_get (ctx, rtype_value, core, &rtype, &cb->data))
    goto propagate_exception;

  if (!_gum_quick_array_get_length (ctx, atypes_array, core, &nargs))
    goto propagate_exception;

  cb->atypes = g_new (ffi_type *, nargs);

  for (i = 0; i != nargs; i++)
  {
    ffi_type ** atype;

    val = JS_GetPropertyUint32 (ctx, atypes_array, i);
    if (JS_IsException (val))
      goto propagate_exception;

    atype = &cb->atypes[i];

    if (!gum_quick_ffi_type_get (ctx, val, core, atype, &cb->data))
      goto propagate_exception;

    JS_FreeValue (ctx, val);
    val = JS_NULL;
  }

  if (abi_str != NULL)
  {
    if (!gum_quick_ffi_abi_get (ctx, abi_str, &abi))
      goto propagate_exception;
  }
  else
  {
    abi = FFI_DEFAULT_ABI;
  }

  cb->closure = ffi_closure_alloc (sizeof (ffi_closure), &ptr->value);
  if (cb->closure == NULL)
    goto alloc_failed;

  if (ffi_prep_cif (&cb->cif, abi, (guint) nargs, rtype, cb->atypes) != FFI_OK)
    goto compilation_failed;

  if (ffi_prep_closure_loc (cb->closure, &cb->cif,
      gum_quick_native_callback_invoke, cb, ptr->value) != FFI_OK)
    goto prepare_failed;

  JS_SetOpaque (wrapper, cb);
  JS_DefinePropertyValue (ctx, wrapper,
      GUM_QUICK_CORE_ATOM (core, resource),
      JS_DupValue (ctx, func),
      0);

  return wrapper;

alloc_failed:
  {
    _gum_quick_throw_literal (ctx, "failed to allocate closure");
    goto propagate_exception;
  }
compilation_failed:
  {
    _gum_quick_throw_literal (ctx, "failed to compile function call interface");
    goto propagate_exception;
  }
prepare_failed:
  {
    _gum_quick_throw_literal (ctx, "failed to prepare closure");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeValue (ctx, val);
    if (cb != NULL)
      gum_quick_native_callback_finalize (cb);
    JS_FreeValue (ctx, wrapper);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_native_callback_finalize)
{
  GumQuickNativeCallback * c;

  c = JS_GetOpaque (val, core->native_callback_class);
  if (c == NULL)
    return;

  gum_quick_native_c
```