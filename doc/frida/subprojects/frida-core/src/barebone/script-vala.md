Response:
### 功能归纳

`BareboneScript` 类是 Frida 动态插桩工具的核心部分，主要负责与底层操作系统、调试器（如 GDB）以及 JavaScript 引擎（QuickJS）的交互。以下是该类的核心功能归纳：

1. **JavaScript 引擎集成**：
   - 使用 QuickJS 作为 JavaScript 引擎，负责解析和执行 JavaScript 代码。
   - 提供了 JavaScript 与底层系统交互的接口，允许 JavaScript 代码调用底层函数、读取内存、设置断点等。

2. **调试器集成**：
   - 与 GDB 调试器集成，提供了对目标进程的调试功能，如设置断点、读取寄存器、读写内存等。
   - 支持通过 JavaScript 代码控制 GDB 调试器的行为，如继续执行、停止、重启等。

3. **内存操作**：
   - 提供了内存分配、内存扫描等功能，允许 JavaScript 代码直接操作目标进程的内存。
   - 支持读取和写入内存中的各种数据类型，如指针、整数、浮点数等。

4. **进程和线程管理**：
   - 提供了对目标进程和线程的管理功能，如枚举进程的内存范围、读取线程的寄存器等。
   - 支持通过 JavaScript 代码控制线程的执行，如单步执行、读取和写入寄存器等。

5. **拦截器（Interceptor）**：
   - 提供了函数拦截功能，允许 JavaScript 代码在目标函数执行前后插入自定义逻辑。
   - 支持设置断点、监听函数调用、修改函数参数和返回值等。

6. **文件操作**：
   - 提供了文件读写功能，允许 JavaScript 代码读取和写入目标进程的文件。

7. **信号处理**：
   - 支持处理目标进程的信号，如 SIGINT、SIGTERM 等。

8. **回调机制**：
   - 提供了回调机制，允许 JavaScript 代码注册回调函数，在特定事件发生时执行。

9. **模块加载**：
   - 支持加载和执行 JavaScript 模块，允许将复杂的逻辑拆分为多个模块。

10. **异常处理**：
    - 提供了异常处理机制，能够捕获 JavaScript 执行过程中的异常，并将其传递给上层处理。

### 二进制底层与 Linux 内核相关功能

1. **内存操作**：
   - 通过 GDB 调试器，可以直接读取和写入目标进程的内存。例如，`on_gdb_read_pointer` 和 `on_gdb_write_pointer` 函数分别用于读取和写入指针类型的数据。
   - 内存扫描功能（`on_memory_scan` 和 `on_memory_scan_sync`）可以扫描目标进程的内存，查找特定的字节模式。

2. **寄存器操作**：
   - 通过 `on_gdb_thread_read_registers` 和 `on_gdb_thread_write_register` 函数，可以读取和写入目标线程的寄存器。这在调试过程中非常有用，例如修改寄存器的值以改变程序的执行流程。

3. **断点设置**：
   - 通过 `on_gdb_add_breakpoint` 函数，可以在目标进程的特定地址设置断点。当程序执行到断点时，调试器会暂停执行，并触发相应的回调函数。

4. **信号处理**：
   - 通过 `on_gdb_get_exception` 函数，可以获取目标进程的异常信号（如 SIGSEGV），并对其进行处理。

### LLDB 指令或 LLDB Python 脚本示例

假设我们想要复刻 `BareboneScript` 中的内存读取功能，可以使用 LLDB 的 Python 脚本来实现类似的功能。以下是一个示例脚本，用于读取目标进程的内存：

```python
import lldb

def read_memory(process, address, size):
    error = lldb.SBError()
    data = process.ReadMemory(address, size, error)
    if error.Success():
        return data
    else:
        print(f"Failed to read memory: {error}")
        return None

def main():
    # 获取当前调试目标
    target = lldb.debugger.GetSelectedTarget()
    process = target.GetProcess()

    # 读取内存地址 0x1000 处的 4 字节数据
    address = 0x1000
    size = 4
    data = read_memory(process, address, size)
    if data:
        print(f"Memory at 0x{address:x}: {data.hex()}")

if __name__ == "__main__":
    main()
```

### 假设输入与输出

假设我们有一个目标进程，其内存地址 `0x1000` 处的值为 `0xdeadbeef`。使用上述 LLDB 脚本读取该地址的内存，输出如下：

```
Memory at 0x1000: efbeadde
```

### 用户常见的使用错误

1. **内存地址错误**：
   - 用户可能会提供一个无效的内存地址，导致内存读取失败。例如，尝试读取未分配的内存地址会导致段错误（Segmentation Fault）。

2. **数据类型不匹配**：
   - 用户可能会尝试读取或写入错误的数据类型。例如，尝试将一个浮点数写入一个指针类型的变量，导致数据损坏。

3. **断点设置错误**：
   - 用户可能会在错误的地址设置断点，导致程序无法正常执行。例如，在代码段之外的地址设置断点会导致程序崩溃。

### 用户操作如何一步步到达这里

1. **启动 Frida**：
   - 用户启动 Frida，并选择要调试的目标进程。

2. **加载脚本**：
   - 用户加载一个 JavaScript 脚本，该脚本通过 Frida 的 API 与目标进程交互。

3. **设置断点**：
   - 用户在脚本中调用 `Interceptor.attach` 函数，设置断点并监听函数调用。

4. **执行脚本**：
   - 用户执行脚本，Frida 在目标进程中注入代码，并开始监听断点。

5. **触发断点**：
   - 当目标进程执行到断点时，Frida 会暂停进程，并调用用户注册的回调函数。

6. **调试与修改**：
   - 用户在回调函数中读取寄存器、修改内存、继续执行等操作，逐步调试目标进程。

### 总结

`BareboneScript` 类是 Frida 动态插桩工具的核心部分，负责与底层操作系统、调试器和 JavaScript 引擎的交互。它提供了丰富的功能，允许用户通过 JavaScript 代码直接操作目标进程的内存、寄存器、线程等，并支持设置断点、拦截函数调用等高级调试功能。通过 LLDB 的 Python 脚本，用户可以复刻部分功能，如内存读取和断点设置。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/barebone/script.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
namespace Frida {
	private class BareboneScript : Object {
		public signal void message (string json, Bytes? data);

		public AgentScriptId id {
			get;
			construct;
		}

		public Barebone.Services services {
			get;
			construct;
		}

		private GDB.Client gdb;

		private QuickJS.Runtime rt;
		private QuickJS.Context ctx;

		private QuickJS.Atom address_key;
		private QuickJS.Atom base_key;
		private QuickJS.Atom breakpoint_key;
		private QuickJS.Atom coalesce_key;
		private QuickJS.Atom dependencies_key;
		private QuickJS.Atom handle_key;
		private QuickJS.Atom invoke_key;
		private QuickJS.Atom length_key;
		private QuickJS.Atom line_number_key;
		private QuickJS.Atom message_key;
		private QuickJS.Atom on_complete_key;
		private QuickJS.Atom on_enter_key;
		private QuickJS.Atom on_error_key;
		private QuickJS.Atom on_leave_key;
		private QuickJS.Atom on_match_key;
		private QuickJS.Atom protection_key;
		private QuickJS.Atom prototype_key;
		private QuickJS.Atom signum_key;
		private QuickJS.Atom size_key;
		private QuickJS.Atom thread_key;
		private QuickJS.Atom type_key;
		private QuickJS.Atom v_key;

		private Gee.Queue<QuickJS.Value?> tick_callbacks = new Gee.ArrayQueue<QuickJS.Value?> ();

		private Barebone.Allocation? cached_landing_zone; // TODO: Deallocate on teardown.

		private Gee.Set<Barebone.Callback> native_callbacks = new Gee.HashSet<Barebone.Callback> ();

		private static QuickJS.ClassID cpu_context_class;
		private static QuickJS.ClassExoticMethods cpu_context_exotic_methods;

		private static QuickJS.ClassID invocation_listener_class;
		private Gee.Set<Barebone.InvocationListener> invocation_listeners = new Gee.HashSet<Barebone.InvocationListener> ();
		private static QuickJS.ClassID invocation_context_class;
		private static QuickJS.ClassID invocation_args_class;
		private static QuickJS.ClassExoticMethods invocation_args_exotic_methods;
		private static QuickJS.ClassID invocation_retval_class;

		private static QuickJS.ClassID rust_module_class;
		private Gee.Set<Barebone.RustModule> rust_modules = new Gee.HashSet<Barebone.RustModule> ();

		private static QuickJS.ClassID gdb_thread_class;

		private static QuickJS.ClassID gdb_breakpoint_class;
		private Gee.Map<GDB.Breakpoint, QuickJS.Value?> gdb_breakpoints = new Gee.HashMap<GDB.Breakpoint, QuickJS.Value?> ();

		private QuickJS.Value global = QuickJS.Undefined;
		private QuickJS.Value runtime_obj = QuickJS.Undefined;
		private QuickJS.Value dispatch_exception_func = QuickJS.Undefined;
		private QuickJS.Value dispatch_message_func = QuickJS.Undefined;
		private QuickJS.Value ptr_func = QuickJS.Undefined;
		private QuickJS.Value int64_func = QuickJS.Undefined;
		private QuickJS.Value uint64_func = QuickJS.Undefined;

		private Gee.ArrayList<QuickJS.Value?> entrypoints = new Gee.ArrayList<QuickJS.Value?> ();
		private Gee.Map<string, Asset> assets = new Gee.HashMap<string, Asset> ();

		private Cancellable io_cancellable = new Cancellable ();

		private const uint64 MAX_ASSET_SIZE = 100 * 1024 * 1024;
		private const uint32 MAX_JS_BYTE_ARRAY_LENGTH = 100 * 1024 * 1024;

		public static BareboneScript create (AgentScriptId id, string source, Barebone.Services services) throws Error {
			var script = new BareboneScript (id, services);

			unowned string runtime_js = (string) Frida.Data.Barebone.get_script_runtime_js_blob ().data;
			script.add_program (runtime_js, "/_frida.js");
			script.add_program (source, "/agent.js");

			return script;
		}

		private BareboneScript (AgentScriptId id, Barebone.Services services) {
			Object (id: id, services: services);
		}

		static construct {
			cpu_context_exotic_methods.get_own_property = on_cpu_context_get_own_property;
			cpu_context_exotic_methods.get_own_property_names = on_cpu_context_get_own_property_names;
			cpu_context_exotic_methods.has_property = on_cpu_context_has_property;
			cpu_context_exotic_methods.get_property = on_cpu_context_get_property;
			cpu_context_exotic_methods.set_property = on_cpu_context_set_property;

			invocation_args_exotic_methods.get_property = on_invocation_args_get_property;
			invocation_args_exotic_methods.set_property = on_invocation_args_set_property;
		}

		construct {
			gdb = services.machine.gdb;

			rt = QuickJS.Runtime.make ();
			rt.set_opaque (this);

			ctx = QuickJS.Context.make (rt);
			ctx.set_opaque (this);

			address_key = ctx.make_atom ("address");
			base_key = ctx.make_atom ("base");
			breakpoint_key = ctx.make_atom ("breakpoint");
			coalesce_key = ctx.make_atom ("coalesce");
			dependencies_key = ctx.make_atom ("dependencies");
			handle_key = ctx.make_atom ("handle");
			invoke_key = ctx.make_atom ("_invoke");
			length_key = ctx.make_atom ("length");
			line_number_key = ctx.make_atom ("lineNumber");
			message_key = ctx.make_atom ("message");
			on_complete_key = ctx.make_atom ("onComplete");
			on_enter_key = ctx.make_atom ("onEnter");
			on_error_key = ctx.make_atom ("onError");
			on_leave_key = ctx.make_atom ("onLeave");
			on_match_key = ctx.make_atom ("onMatch");
			protection_key = ctx.make_atom ("protection");
			prototype_key = ctx.make_atom ("prototype");
			signum_key = ctx.make_atom ("signum");
			size_key = ctx.make_atom ("size");
			thread_key = ctx.make_atom ("thread");
			type_key = ctx.make_atom ("type");
			v_key = ctx.make_atom ("$v");

			global = ctx.get_global_object ();
			add_cfunc (global, "_send", on_send, 2);
			add_cfunc (global, "_invoke", on_invoke, 1);
			add_cfunc (global, "_installNativeCallback", on_install_native_callback, 3);

			var script_obj = ctx.make_object ();
			add_cfunc (script_obj, "evaluate", on_evaluate, 2);
			add_cfunc (script_obj, "nextTick", on_next_tick, 1);
			global.set_property_str (ctx, "Script", script_obj);

			QuickJS.ClassDef cc;
			cc.class_name = "CpuContext";
			cc.finalizer = on_cpu_context_finalize;
			cc.exotic = &cpu_context_exotic_methods;
			rt.make_class (QuickJS.make_class_id (ref cpu_context_class), cc);

			var memory_obj = ctx.make_object ();
			add_cfunc (memory_obj, "alloc", on_memory_alloc, 1);
			add_cfunc (memory_obj, "scan", on_memory_scan, 4);
			add_cfunc (memory_obj, "scanSync", on_memory_scan_sync, 3);
			global.set_property_str (ctx, "Memory", memory_obj);

			var process_obj = ctx.make_object ();
			process_obj.set_property_str (ctx, "arch", ctx.make_string (gdb.arch.to_nick ()));
			process_obj.set_property_str (ctx, "pageSize", ctx.make_uint32 ((uint32) services.allocator.page_size));
			process_obj.set_property_str (ctx, "pointerSize", ctx.make_uint32 (gdb.pointer_size));
			add_cfunc (process_obj, "enumerateRanges", on_process_enumerate_ranges, 1);
			global.set_property_str (ctx, "Process", process_obj);

			var file_obj = ctx.make_object ();
			add_cfunc (file_obj, "readAllBytes", on_file_read_all_bytes, 1);
			add_cfunc (file_obj, "readAllText", on_file_read_all_text, 1);
			add_cfunc (file_obj, "writeAllBytes", on_file_write_all_bytes, 2);
			add_cfunc (file_obj, "writeAllText", on_file_write_all_text, 2);
			global.set_property_str (ctx, "File", file_obj);

			var interceptor_obj = ctx.make_object ();
			add_property (interceptor_obj, "breakpointKind", on_interceptor_get_breakpoint_kind,
				on_interceptor_set_breakpoint_kind);
			add_cfunc (interceptor_obj, "attach", on_interceptor_attach, 2);
			global.set_property_str (ctx, "Interceptor", interceptor_obj);

			QuickJS.ClassDef il;
			il.class_name = "InvocationListener";
			rt.make_class (QuickJS.make_class_id (ref invocation_listener_class), il);
			var il_proto = ctx.make_object ();
			add_cfunc (il_proto, "detach", on_invocation_listener_detach, 0);
			ctx.set_class_proto (invocation_listener_class, il_proto);

			QuickJS.ClassDef ic;
			ic.class_name = "InvocationContext";
			rt.make_class (QuickJS.make_class_id (ref invocation_context_class), ic);
			var ic_proto = ctx.make_object ();
			add_getter (ic_proto, "returnAddress", on_invocation_context_get_return_address);
			add_getter (ic_proto, "context", on_invocation_context_get_context);
			ic_proto.set_property_str (ctx, "errno", ctx.make_int32 (-1));
			add_getter (ic_proto, "threadId", on_invocation_context_get_thread_id);
			add_getter (ic_proto, "depth", on_invocation_context_get_depth);
			ctx.set_class_proto (invocation_context_class, ic_proto);

			QuickJS.ClassDef ia;
			ia.class_name = "InvocationArguments";
			ia.exotic = &invocation_args_exotic_methods;
			rt.make_class (QuickJS.make_class_id (ref invocation_args_class), ia);

			QuickJS.ClassDef ir;
			ir.class_name = "InvocationReturnValue";
			rt.make_class (QuickJS.make_class_id (ref invocation_retval_class), ir);

			QuickJS.ClassDef rm;
			rm.class_name = "RustModule";
			rm.finalizer = on_rust_module_finalize;
			rt.make_class (QuickJS.make_class_id (ref rust_module_class), rm);
			var rm_proto = ctx.make_object ();
			add_cfunc (rm_proto, "dispose", on_rust_module_dispose, 0);
			ctx.set_class_proto (rust_module_class, rm_proto);
			var rm_ctor = ctx.make_cfunction2 (on_rust_module_construct, rm.class_name, 3, constructor, 0);
			rm_ctor.set_constructor (ctx, rm_proto);
			global.set_property_str (ctx, "RustModule", rm_ctor);

			var gdb_obj = ctx.make_object ();
			add_getter (gdb_obj, "state", on_gdb_get_state);
			add_getter (gdb_obj, "exception", on_gdb_get_exception);
			add_cfunc (gdb_obj, "continue", on_gdb_continue, 0);
			add_cfunc (gdb_obj, "stop", on_gdb_stop, 0);
			add_cfunc (gdb_obj, "restart", on_gdb_restart, 0);
			add_cfunc (gdb_obj, "readPointer", on_gdb_read_pointer, 1);
			add_cfunc (gdb_obj, "writePointer", on_gdb_write_pointer, 2);
			add_cfunc (gdb_obj, "readS8", on_gdb_read_s8, 1);
			add_cfunc (gdb_obj, "writeS8", on_gdb_write_s8, 2);
			add_cfunc (gdb_obj, "readU8", on_gdb_read_u8, 1);
			add_cfunc (gdb_obj, "writeU8", on_gdb_write_u8, 2);
			add_cfunc (gdb_obj, "readS16", on_gdb_read_s16, 1);
			add_cfunc (gdb_obj, "writeS16", on_gdb_write_s16, 2);
			add_cfunc (gdb_obj, "readU16", on_gdb_read_u16, 1);
			add_cfunc (gdb_obj, "writeU16", on_gdb_write_u16, 2);
			add_cfunc (gdb_obj, "readS32", on_gdb_read_s32, 1);
			add_cfunc (gdb_obj, "writeS32", on_gdb_write_s32, 2);
			add_cfunc (gdb_obj, "readU32", on_gdb_read_u32, 1);
			add_cfunc (gdb_obj, "writeU32", on_gdb_write_u32, 2);
			add_cfunc (gdb_obj, "readS64", on_gdb_read_s64, 1);
			add_cfunc (gdb_obj, "writeS64", on_gdb_write_s64, 2);
			add_cfunc (gdb_obj, "readU64", on_gdb_read_u64, 1);
			add_cfunc (gdb_obj, "writeU64", on_gdb_write_u64, 2);
			add_cfunc (gdb_obj, "readFloat", on_gdb_read_float, 1);
			add_cfunc (gdb_obj, "writeFloat", on_gdb_write_float, 2);
			add_cfunc (gdb_obj, "readDouble", on_gdb_read_double, 1);
			add_cfunc (gdb_obj, "writeDouble", on_gdb_write_double, 2);
			add_cfunc (gdb_obj, "readByteArray", on_gdb_read_byte_array, 2);
			add_cfunc (gdb_obj, "writeByteArray", on_gdb_write_byte_array, 2);
			add_cfunc (gdb_obj, "readCString", on_gdb_read_c_string, 2);
			add_cfunc (gdb_obj, "readUtf8String", on_gdb_read_utf8_string, 2);
			add_cfunc (gdb_obj, "writeUtf8String", on_gdb_write_utf8_string, 2);
			add_cfunc (gdb_obj, "addBreakpoint", on_gdb_add_breakpoint, 3);
			add_cfunc (gdb_obj, "runRemoteCommand", on_gdb_run_remote_command, 1);
			add_cfunc (gdb_obj, "execute", on_gdb_execute, 1);
			add_cfunc (gdb_obj, "query", on_gdb_query, 1);
			global.set_property_str (ctx, "$gdb", gdb_obj);

			QuickJS.ClassDef th;
			th.class_name = "GDBThread";
			th.finalizer = on_gdb_thread_finalize;
			rt.make_class (QuickJS.make_class_id (ref gdb_thread_class), th);
			var th_proto = ctx.make_object ();
			add_getter (th_proto, "id", on_gdb_thread_get_id);
			add_getter (th_proto, "name", on_gdb_thread_get_name);
			add_cfunc (th_proto, "step", on_gdb_thread_step, 0);
			add_cfunc (th_proto, "stepAndContinue", on_gdb_thread_step_and_continue, 0);
			add_cfunc (th_proto, "readRegisters", on_gdb_thread_read_registers, 0);
			add_cfunc (th_proto, "readRegister", on_gdb_thread_read_register, 1);
			add_cfunc (th_proto, "writeRegister", on_gdb_thread_write_register, 2);
			ctx.set_class_proto (gdb_thread_class, th_proto);

			QuickJS.ClassDef bp;
			bp.class_name = "GDBBreakpoint";
			bp.finalizer = on_gdb_breakpoint_finalize;
			rt.make_class (QuickJS.make_class_id (ref gdb_breakpoint_class), bp);
			var bp_proto = ctx.make_object ();
			add_getter (bp_proto, "kind", on_gdb_breakpoint_get_kind);
			add_getter (bp_proto, "address", on_gdb_breakpoint_get_address);
			add_getter (bp_proto, "size", on_gdb_breakpoint_get_size);
			add_cfunc (bp_proto, "enable", on_gdb_breakpoint_enable, 0);
			add_cfunc (bp_proto, "disable", on_gdb_breakpoint_disable, 0);
			add_cfunc (bp_proto, "remove", on_gdb_breakpoint_remove, 0);
			ctx.set_class_proto (gdb_breakpoint_class, bp_proto);
		}

		private void add_cfunc (QuickJS.Value ns, string name, QuickJS.CFunction func, int arity) {
			ns.set_property_str (ctx, name, ctx.make_cfunction (func, name, arity));
		}

		private void add_getter (QuickJS.Value ns, string name, QuickJS.CFunction func) {
			add_property (ns, name, func, null);
		}

		private void add_property (QuickJS.Value ns, string name, QuickJS.CFunction getter_func, QuickJS.CFunction? setter_func) {
			QuickJS.Atom prop = ctx.make_atom (name);
			var val = QuickJS.Undefined;

			QuickJS.PropertyFlags flags = HAS_GET | HAS_ENUMERABLE | ENUMERABLE;
			var getter = ctx.make_cfunction (getter_func, name, 0);

			QuickJS.Value setter = QuickJS.Undefined;
			if (setter_func != null) {
				flags |= HAS_SET;
				setter = ctx.make_cfunction (setter_func, name, 1);
			}

			ns.define_property (ctx, prop, val, getter, setter, flags);

			ctx.free_value (setter);
			ctx.free_value (getter);
			ctx.free_atom (prop);
		}

		~BareboneScript () {
			rust_modules.clear ();
			native_callbacks.clear ();

			QuickJS.Value[] values = {
				global,
				runtime_obj,
				dispatch_exception_func,
				dispatch_message_func,
				ptr_func,
				int64_func,
				uint64_func,
			};
			foreach (var val in values)
				ctx.free_value (val);

			QuickJS.Atom atoms[] = {
				address_key,
				base_key,
				breakpoint_key,
				coalesce_key,
				dependencies_key,
				handle_key,
				invoke_key,
				length_key,
				line_number_key,
				message_key,
				on_complete_key,
				on_enter_key,
				on_error_key,
				on_leave_key,
				on_match_key,
				protection_key,
				signum_key,
				size_key,
				thread_key,
				type_key,
				v_key,
			};
			foreach (var atom in atoms)
				ctx.free_atom (atom);

			ctx = null;
			rt = null;
		}

		public async void destroy (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			var interceptor = services.interceptor;
			foreach (var listener in invocation_listeners.to_array ()) {
				try {
					yield interceptor.detach (listener, cancellable);
				} catch (Error e) {
				}
			}
			invocation_listeners.clear ();

			var source = new IdleSource ();
			source.set_callback (destroy.callback);
			source.attach (MainContext.get_thread_default ());
			yield;
		}

		public void load () {
			foreach (QuickJS.Value? entrypoint in entrypoints) {
				var result = ctx.eval_function (entrypoint);
				if (result.is_exception ())
					catch_and_emit ();
				ctx.free_value (result);

				if (runtime_obj.is_undefined ()) {
					runtime_obj = global.get_property_str (ctx, "$rt");
					if (!runtime_obj.is_undefined ()) {
						dispatch_exception_func = runtime_obj.get_property_str (ctx, "dispatchException");
						assert (!dispatch_exception_func.is_undefined ());

						dispatch_message_func = runtime_obj.get_property_str (ctx, "dispatchMessage");
						assert (!dispatch_message_func.is_undefined ());

						var native_pointer_instance = global.get_property_str (ctx, "NULL");
						assert (!native_pointer_instance.is_undefined ());
						var native_pointer_proto = native_pointer_instance.get_prototype (ctx);

						var ir_proto = ctx.make_object_proto (native_pointer_proto);
						add_cfunc (ir_proto, "replace", on_invocation_retval_replace, 1);
						ctx.set_class_proto (invocation_retval_class, ir_proto);

						ctx.free_value (native_pointer_proto);
						ctx.free_value (native_pointer_instance);

						ptr_func = global.get_property_str (ctx, "ptr");
						assert (!ptr_func.is_undefined ());

						int64_func = global.get_property_str (ctx, "int64");
						assert (!int64_func.is_undefined ());

						uint64_func = global.get_property_str (ctx, "uint64");
						assert (!uint64_func.is_undefined ());
					}
				}
			}

			perform_pending_io ();
		}

		public void post (string json, Bytes? data) {
			var json_val = ctx.make_string (json);
			var data_val = (data != null) ? ctx.make_array_buffer (data.get_data ()) : QuickJS.Null;
			invoke_void (dispatch_message_func, { json_val, data_val }, runtime_obj);
			ctx.free_value (data_val);
			ctx.free_value (json_val);

			perform_pending_io ();
		}

		private void add_program (string source, string name) throws Error {
			unowned string package_marker = "📦\n";
			unowned string delimiter_marker = "\n✄\n";
			unowned string alias_marker = "↻ ";

			if (source.has_prefix (package_marker)) {
				rt.set_module_loader_func (normalize_module_name, load_module);

				string pending = source[package_marker.length:];
				while (true) {
					string[] pkg_tokens = pending.split (delimiter_marker, 2);
					if (pkg_tokens.length != 2)
						throw_malformed_package ();

					unowned string header = pkg_tokens[0];
					unowned string raw_assets = pkg_tokens[1];

					uint assets_offset = 0;
					uint assets_size = raw_assets.length;

					Asset? entrypoint = null;

					string[] header_lines = header.split ("\n");
					Asset? current_asset = null;
					for (uint i = 0; i != header_lines.length && assets_offset != assets_size; i++) {
						unowned string header_line = header_lines[i];

						if (header_line.has_prefix (alias_marker)) {
							if (current_asset == null)
								throw_malformed_package ();
							string alias = header_line[alias_marker.length:];
							assets[alias] = current_asset;
							continue;
						}

						unowned string assets_cursor = (string *) raw_assets + assets_offset;
						if (i != 0) {
							if (!assets_cursor.has_prefix (delimiter_marker))
								throw_malformed_package ();
							assets_offset += delimiter_marker.length;
						}

						string[] tokens = header_line.split (" ", 2);
						if (tokens.length != 2)
							throw_malformed_package ();

						uint64 size = uint64.parse (tokens[0]);
						if (size == 0 || size > MAX_ASSET_SIZE || size > assets_size - assets_offset)
							throw_malformed_package ();

						unowned string asset_name = tokens[1];
						string asset_data = raw_assets[assets_offset:assets_offset + (uint) size];

						var asset = new Asset (asset_name, (owned) asset_data);
						assets[asset_name] = asset;
						current_asset = asset;

						if (entrypoint == null && asset_name.has_suffix (".js"))
							entrypoint = asset;

						assets_offset += (uint) size;
					}

					if (entrypoint == null)
						throw_malformed_package ();

					var val = compile_module (entrypoint);
					entrypoints.add (val);

					string rest = raw_assets[assets_offset:];
					if (rest.has_prefix (delimiter_marker))
						pending = rest[delimiter_marker.length:];
					else if (rest.length == 0)
						break;
					else
						throw_malformed_package ();
				}
			} else {
				var val = compile_script (source, name);
				entrypoints.add (val);
			}
		}

		[NoReturn]
		private static void throw_malformed_package () throws Error {
			throw new Error.INVALID_ARGUMENT ("Malformed package");
		}

		private string * normalize_module_name (QuickJS.Context ctx, string base_name, string name) {
			if (name[0] != '.') {
				Asset? asset = assets[name];
				if (asset != null)
					return ctx.strdup (asset.name);
				return ctx.strdup (name);
			}

			var result = new StringBuilder ();

			int offset = base_name.last_index_of_char ('/');
			if (offset != -1)
				result.append (base_name[:offset]);

			string * cursor = name;
			while (true) {
				if (cursor->has_prefix ("./")) {
					cursor += 2;
				} else if (cursor->has_prefix ("../")) {
					if (result.len == 0)
						break;

					int last_slash_offset = result.str.last_index_of_char ('/');

					string * rest;
					if (last_slash_offset != -1)
						rest = (string *) result.str + last_slash_offset + 1;
					else
						rest = result.str;
					if (rest == "." || rest == "..")
						break;

					result.truncate ((last_slash_offset != -1) ? last_slash_offset : 0);

					cursor += 3;
				} else {
					break;
				}
			}

			result
				.append_c ('/')
				.append (cursor);

			return ctx.strdup (result.str);
		}

		private unowned QuickJS.ModuleDef? load_module (QuickJS.Context ctx, string module_name) {
			QuickJS.Value val;
			try {
				Asset? asset = assets[module_name];
				if (asset == null)
					throw new Error.INVALID_ARGUMENT ("Could not load module '%s'", module_name);

				val = compile_module (asset);
			} catch (Error e) {
				throw_js_error (error_message_to_js (e.message));
				return null;
			}

			unowned QuickJS.ModuleDef mod = (QuickJS.ModuleDef) val.get_ptr ();
			ctx.free_value (val);

			return mod;
		}

		private QuickJS.Value compile_module (Asset asset) throws Error {
			var val = ctx.eval (asset.data, asset.data.length, asset.name,
				QuickJS.EvalType.MODULE |
				QuickJS.EvalFlag.STRICT |
				QuickJS.EvalFlag.COMPILE_ONLY);

			if (val.is_exception ()) {
				JSError e = catch_js_error ();
				throw new Error.INVALID_ARGUMENT ("Could not parse '%s' line %u: %s", asset.name, e.line, e.message);
			}

			return val;
		}

		private QuickJS.Value compile_script (string source, string name) throws Error {
			var val = ctx.eval (source, source.length, name,
				QuickJS.EvalType.GLOBAL |
				QuickJS.EvalFlag.STRICT |
				QuickJS.EvalFlag.COMPILE_ONLY);

			if (val.is_exception ()) {
				JSError e = catch_js_error ();
				throw new Error.INVALID_ARGUMENT ("Script(line %u): %s", e.line, e.message);
			}

			return val;
		}

		private static QuickJS.Value on_send (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			string message;
			if (!script->unparse_string (argv[0], out message))
				return QuickJS.Exception;

			Bytes? data = null;
			if (!argv[1].is_undefined () && !argv[1].is_null () && !script->unparse_bytes (argv[1], out data))
				return QuickJS.Exception;

			script->message (message, data);

			return QuickJS.Undefined;
		}

		private static QuickJS.Value on_invoke (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			uint64 impl;
			if (!script->unparse_uint64 (argv[0], out impl))
				return QuickJS.Exception;

			uint64[] args = {};
			for (uint i = 1; i != argv.length; i++) {
				uint64 v;
				if (!script->unparse_uint64 (argv[i], out v))
					return QuickJS.Exception;
				args += v;
			}

			var promise = new Promise<uint64?> ();
			script->do_invoke.begin (impl, args, promise);

			uint64? retval = script->process_events_until_ready (promise);
			if (retval == null)
				return QuickJS.Exception;

			return ctx.make_biguint64 (retval);
		}

		private async void do_invoke (uint64 impl, uint64[] args, Promise<uint64?> promise) {
			try {
				if (cached_landing_zone == null)
					cached_landing_zone = yield services.allocator.allocate (4, 1, io_cancellable);

				uint64 retval = yield services.machine.invoke (impl, args, cached_landing_zone.virtual_address,
					io_cancellable);

				promise.resolve (retval);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_install_native_callback (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			uint64 code;
			if (!script->unparse_uint64 (argv[0], out code))
				return QuickJS.Exception;

			QuickJS.Value wrapper, method;
			var scope = new ValueScope (script);
			wrapper = scope.retain (argv[1]);
			if (!scope.unparse_callback (wrapper, script->invoke_key, out method))
				return QuickJS.Exception;

			uint arity;
			if (!script->unparse_uint (argv[2], out arity))
				return QuickJS.Exception;

			var handler = new NativeCallbackHandler (script, wrapper, method, arity, scope);

			var promise = new Promise<Barebone.Callback> ();
			script->do_install_native_callback.begin (code, handler, promise);

			Barebone.Callback? callback = script->process_events_until_ready (promise);
			if (callback == null)
				return QuickJS.Exception;

			script->native_callbacks.add (callback);

			return QuickJS.Undefined;
		}

		private async void do_install_native_callback (uint64 code, Barebone.CallbackHandler handler,
				Promise<Barebone.Callback> promise) {
			try {
				var callback = yield new Barebone.Callback (code, handler, services.machine, io_cancellable);

				promise.resolve (callback);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private class NativeCallbackHandler : Object, Barebone.CallbackHandler {
			public uint arity {
				get { return _arity; }
			}

			private weak BareboneScript script;
			private QuickJS.Value wrapper;
			private QuickJS.Value method;
			private uint _arity;

			private ValueScope scope;

			public NativeCallbackHandler (BareboneScript script, QuickJS.Value wrapper, QuickJS.Value method, uint arity,
					ValueScope scope) {
				this.script = script;
				this.wrapper = wrapper;
				this.method = method;
				this._arity = arity;

				this.scope = scope;
			}

			public async uint64 handle_invocation (uint64[] args, Barebone.CallFrame frame, Cancellable? cancellable)
					throws Error, IOError {
				var scope = new ValueScope (script);
				unowned QuickJS.Context ctx = scope.ctx;

				var js_args = scope.take (ctx.make_array ());
				for (uint32 i = 0; i != args.length; i++)
					js_args.set_property_uint32 (ctx, i, ctx.make_biguint64 (args[i]));

				var return_address = scope.take (script.make_native_pointer (frame.return_address));

				var context = scope.take (script.make_cpu_context (frame.registers));

				var js_retval = script.invoke (method, { js_args, return_address, context }, wrapper);
				if (js_retval.is_exception ())
					return 0;
				scope.take (js_retval);

				uint64 retval;
				if (!script.unparse_uint64 (js_retval, out retval)) {
					script.catch_and_emit ();
					return 0;
				}

				return retval;
			}
		}

		private static QuickJS.Value on_evaluate (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			string name;
			if (!script->unparse_string (argv[0], out name))
				return QuickJS.Exception;

			string source;
			if (!script->unparse_string (argv[1], out source))
				return QuickJS.Exception;

			var func = ctx.eval (source, source.length, name,
				QuickJS.EvalType.GLOBAL |
				QuickJS.EvalFlag.STRICT |
				QuickJS.EvalFlag.COMPILE_ONLY);

			if (func.is_exception ()) {
				JSError e = script->catch_js_error ();
				script->throw_js_error ("could not parse '%s' line %u: %s".printf (name, e.line, e.message));
				return QuickJS.Exception;
			}

			return ctx.eval_function (func);
		}

		private static QuickJS.Value on_next_tick (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			var callback = argv[0];
			if (!callback.is_function (ctx)) {
				script->throw_js_error ("expected a function");
				return QuickJS.Exception;
			}

			script->tick_callbacks.offer (ctx.dup_value (callback));

			return QuickJS.Undefined;
		}

		private QuickJS.Value make_native_pointer (uint64 val) {
			var jsval = ctx.make_biguint64 (val);
			var result = ptr_func.call (ctx, QuickJS.Undefined, { jsval });
			ctx.free_value (jsval);
			return result;
		}

		private QuickJS.Value make_int64 (int64 val) {
			var jsval = ctx.make_bigint64 (val);
			var result = int64_func.call (ctx, QuickJS.Undefined, { jsval });
			ctx.free_value (jsval);
			return result;
		}

		private QuickJS.Value make_uint64 (uint64 val) {
			var jsval = ctx.make_biguint64 (val);
			var result = uint64_func.call (ctx, QuickJS.Undefined, { jsval });
			ctx.free_value (jsval);
			return result;
		}

		private QuickJS.Value make_array_buffer_take (owned uint8[] contents) {
			return ctx.make_array_buffer_with_free_func ((owned) contents, free_array_buffer, false);
		}

		private static void free_array_buffer (QuickJS.Runtime rt, void * ptr) {
			free (ptr);
		}

		private QuickJS.Value make_cpu_context (Gee.Map<string, Variant> regs) {
			var wrapper = ctx.make_object_class (cpu_context_class);
			wrapper.set_opaque (regs.ref ());
			return wrapper;
		}

		private static void on_cpu_context_finalize (QuickJS.Runtime rt, QuickJS.Value val) {
			Gee.Map<string, Variant> * map = val.get_opaque (cpu_context_class);
			map->unref ();
		}

		private static int on_cpu_context_get_own_property (QuickJS.Context ctx, QuickJS.PropertyDescriptor desc, QuickJS.Value obj,
				QuickJS.Atom prop) {
			BareboneScript * script = ctx.get_opaque ();

			var val = script->read_cpu_context_field (obj, prop);
			if (val.is_undefined ())
				return 0;

			desc.flags = ENUMERABLE;
			desc.value = val;
			desc.getter = QuickJS.Undefined;
			desc.setter = QuickJS.Undefined;
			return 1;
		}

		private static int on_cpu_context_get_own_property_names (QuickJS.Context ctx, out QuickJS.PropertyEnum * tab,
				out uint32 len, QuickJS.Value obj) {
			Gee.Map<string, Variant> * map = obj.get_opaque (cpu_context_class);

			var keys = map->keys;
			int n = keys.size;
			tab = ctx.malloc (n * sizeof (QuickJS.PropertyEnum));
			len = n;

			int i = 0;
			foreach (var key in keys) {
				QuickJS.PropertyEnum * p = tab + i;
				p->is_enumerable = true;
				p->atom = ctx.make_atom (key);
				i++;
			}

			return 0;
		}

		private static int on_cpu_context_has_property (QuickJS.Context ctx, QuickJS.Value obj, QuickJS.Atom atom) {
			Gee.Map<string, Variant> * map = obj.get_opaque (cpu_context_class);

			string * name = atom.to_cstring (ctx);
			int result = map->has_key (name) ? 1 : 0;
			ctx.free_cstring (name);

			return result;
		}

		private static QuickJS.Value on_cpu_context_get_property (QuickJS.Context ctx, QuickJS.Value obj, QuickJS.Atom atom,
				QuickJS.Value receiver) {
			BareboneScript * script = ctx.get_opaque ();

			return script->read_cpu_context_field (obj, atom);
		}

		private static int on_cpu_context_set_property (QuickJS.Context ctx, QuickJS.Value obj, QuickJS.Atom atom,
				QuickJS.Value val, QuickJS.Value receiver, QuickJS.PropertyFlags flags) {
			BareboneScript * script = ctx.get_opaque ();

			return script->write_cpu_context_field (obj, atom, val) ? 0 : -1;
		}

		private QuickJS.Value read_cpu_context_field (QuickJS.Value obj, QuickJS.Atom atom) {
			Gee.Map<string, Variant> * map = obj.get_opaque (cpu_context_class);

			QuickJS.Value result = QuickJS.Undefined;

			string * name = atom.to_cstring (ctx);

			Variant? val = map->get (name);
			if (val != null) {
				if (val.is_of_type (VariantType.UINT64)) {
					result = make_native_pointer (val.get_uint64 ());
				} else if (val.is_of_type (VariantType.UINT32)) {
					result = ctx.make_uint32 (val.get_uint32 ());
				} else {
					unowned uint8[] data = (uint8[]) val.get_data ();
					result = ctx.make_array_buffer (data[:val.get_size ()]);
				}
			}

			ctx.free_cstring (name);

			return result;
		}

		private bool write_cpu_context_field (QuickJS.Value obj, QuickJS.Atom atom, QuickJS.Value val) {
			Gee.Map<string, Variant> * map = obj.get_opaque (cpu_context_class);

			string * name = atom.to_cstring (ctx);
			try {
				Variant? existing_val = map->get (name);
				if (existing_val == null) {
					throw_js_error ("invalid register name");
					return false;
				}

				Variant new_val;
				if (existing_val.is_of_type (VariantType.UINT64)) {
					uint64 raw_val;
					if (!unparse_uint64 (val, out raw_val))
						return false;
					new_val = raw_val;
				} else if (existing_val.is_of_type (VariantType.UINT32)) {
					uint32 raw_val;
					if (!unparse_uint32 (val, out raw_val))
						return false;
					new_val = raw_val;
				} else {
					Bytes raw_val;
					if (!unparse_bytes (val, out raw_val))
						return false;
					new_val = Variant.new_from_data (new VariantType ("ay"), raw_val.get_data (), true,
						(owned) raw_val);
				}

				map->set (name, new_val);
				map->set_data ("dirty", true);
			} finally {
				ctx.free_cstring (name);
			}

			return true;
		}

		private static QuickJS.Value on_memory_alloc (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			uint size;
			if (!script->unparse_uint (argv[0], out size))
				retu
```