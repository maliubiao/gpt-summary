Response:
### 功能概述

`frida-core/src/fruity/lldb.vala` 文件是 Frida 工具中用于与 LLDB 调试器进行交互的核心模块。它主要负责通过 LLDB 调试器与目标进程进行通信，执行调试操作，如启动进程、附加到进程、读取内存、枚举线程和模块等。以下是该文件的主要功能：

1. **进程管理**：
   - 启动进程 (`launch`)：通过 LLDB 启动一个新的进程，并设置环境变量、架构、ASLR 等选项。
   - 附加到进程 (`attach_by_name`, `attach_by_pid`)：通过进程名或进程 ID 附加到正在运行的进程。

2. **线程管理**：
   - 枚举线程 (`enumerate_threads`)：获取目标进程中所有线程的信息，包括线程 ID 和线程名。
   - 保存和恢复线程寄存器状态 (`save_register_state`, `restore_register_state`)：保存和恢复线程的寄存器状态，用于调试和恢复执行。

3. **模块管理**：
   - 枚举模块 (`enumerate_modules`)：获取目标进程中加载的所有模块（动态库）的信息，包括模块的加载地址、路径、段信息等。

4. **内存操作**：
   - 读取内存 (`read_byte_array`)：从目标进程的指定地址读取内存数据。
   - 分配和释放内存 (`allocate`, `deallocate`)：在目标进程中分配和释放内存。

5. **调试信息获取**：
   - 获取进程信息 (`get_process_info`)：获取目标进程的详细信息，如进程 ID、父进程 ID、CPU 类型、指针大小、字节序等。
   - 获取 Apple Dyld 字段 (`get_apple_dyld_fields`)：获取与 Apple 动态链接器 (dyld) 相关的字段信息。

6. **异常处理**：
   - 解析停止信号 (`parse_stop`)：解析目标进程停止时的信号和异常信息，生成调试上下文。

### 二进制底层与 Linux 内核相关

该文件主要涉及 macOS 和 iOS 系统的底层调试功能，特别是与 Mach-O 二进制格式和 dyld 动态链接器的交互。以下是一些与二进制底层和 Linux 内核相关的示例：

- **Mach-O 二进制格式**：文件中的 `DarwinCpuType` 和 `DarwinCpuSubtype` 枚举类定义了 macOS 和 iOS 系统支持的 CPU 架构类型（如 x86、ARM64 等），这些信息在调试过程中用于确定目标进程的架构。
- **dyld 动态链接器**：`get_apple_dyld_fields` 方法用于获取 dyld 相关的字段信息，这些信息在调试过程中用于确定动态库的加载地址和初始化状态。

### LLDB 指令与 Python 脚本示例

以下是一些 LLDB 指令和 Python 脚本示例，用于复刻源代码中实现的调试功能：

1. **启动进程**：
   - LLDB 指令：
     ```bash
     lldb -- /path/to/executable arg1 arg2
     ```
   - Python 脚本：
     ```python
     import lldb

     debugger = lldb.SBDebugger.Create()
     target = debugger.CreateTarget("/path/to/executable")
     process = target.LaunchSimple(["arg1", "arg2"], None, None)
     ```

2. **附加到进程**：
   - LLDB 指令：
     ```bash
     lldb -p <pid>
     ```
   - Python 脚本：
     ```python
     import lldb

     debugger = lldb.SBDebugger.Create()
     target = debugger.CreateTarget("")
     process = target.AttachToProcessWithID(lldb.SBListener(), <pid>)
     ```

3. **读取内存**：
   - LLDB 指令：
     ```bash
     memory read 0x12345678
     ```
   - Python 脚本：
     ```python
     import lldb

     debugger = lldb.SBDebugger.Create()
     target = debugger.CreateTarget("/path/to/executable")
     process = target.LaunchSimple(None, None, None)
     error = lldb.SBError()
     memory = process.ReadMemory(0x12345678, 16, error)
     ```

4. **枚举线程**：
   - LLDB 指令：
     ```bash
     thread list
     ```
   - Python 脚本：
     ```python
     import lldb

     debugger = lldb.SBDebugger.Create()
     target = debugger.CreateTarget("/path/to/executable")
     process = target.LaunchSimple(None, None, None)
     for thread in process:
         print(f"Thread ID: {thread.GetThreadID()}, Name: {thread.GetName()}")
     ```

### 假设输入与输出

1. **启动进程**：
   - 输入：`argv = ["/path/to/executable", "arg1", "arg2"]`
   - 输出：成功启动进程并返回 `Process` 对象，包含进程的 PID 和其他信息。

2. **附加到进程**：
   - 输入：`name = "executable"` 或 `pid = 1234`
   - 输出：成功附加到进程并返回 `Process` 对象。

3. **读取内存**：
   - 输入：`address = 0x12345678`, `size = 16`
   - 输出：返回从指定地址读取的 16 字节数据。

### 用户常见使用错误

1. **进程启动失败**：
   - 错误示例：用户提供的可执行文件路径错误或参数不正确。
   - 解决方法：检查路径和参数是否正确，确保可执行文件存在且可执行。

2. **附加到进程失败**：
   - 错误示例：用户提供的进程名或 PID 不存在。
   - 解决方法：确保进程正在运行，并使用正确的进程名或 PID。

3. **内存读取失败**：
   - 错误示例：用户提供的地址无效或超出进程的地址空间。
   - 解决方法：检查地址是否有效，并确保进程已启动或附加。

### 用户操作步骤

1. **启动调试会话**：
   - 用户通过 Frida 或 LLDB 启动目标进程或附加到正在运行的进程。
   
2. **执行调试操作**：
   - 用户通过 Frida 提供的 API 或 LLDB 指令执行调试操作，如读取内存、枚举线程、保存寄存器状态等。

3. **处理异常**：
   - 当目标进程发生异常时，Frida 或 LLDB 会捕获异常并生成调试上下文，用户可以根据上下文信息进行调试。

4. **恢复执行**：
   - 用户可以通过恢复寄存器状态或修改内存内容来恢复目标进程的执行。

通过以上步骤，用户可以逐步深入调试目标进程，定位和解决问题。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/fruity/lldb.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```
[CCode (gir_namespace = "FridaLLDB", gir_version = "1.0")]
namespace Frida.LLDB {
	public class Client : GDB.Client {
		public Process? process {
			get {
				return _process;
			}
		}

		private Process? _process;
		private uint64 ptrauth_removal_mask;
		private AppleDyldFields? cached_dyld_fields;

		public enum CachePolicy {
			ALLOW_CACHE,
			BYPASS_CACHE
		}

		private Client (IOStream stream) {
			Object (stream: stream);
		}

		public static new async Client open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var client = new Client (stream);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return client;
		}

		protected override async void detect_vendor_features (Cancellable? cancellable) throws Error, IOError {
		}

		protected override async void enable_extensions (Cancellable? cancellable) throws Error, IOError {
			yield execute_simple ("QThreadSuffixSupported", cancellable);
			yield execute_simple ("QListThreadsInStopReply", cancellable);
			yield execute_simple ("QSetDetachOnError:0", cancellable);
		}

		public async Process launch (string[] argv, LaunchOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			if (options != null) {
				foreach (var env in options.env)
					yield execute_simple ("QEnvironment:" + env, cancellable);

				var arch = options.arch;
				if (arch != null)
					yield execute_simple ("QLaunchArch:" + arch, cancellable);

				if (options.aslr == DISABLE)
					yield execute_simple ("QSetDisableASLR:1", cancellable);
			}

			var set_args_command = make_packet_builder_sized (256)
				.append_c ('A');
			uint arg_index = 0;
			foreach (var arg in argv) {
				if (arg_index > 0)
					set_args_command.append_c (',');

				uint length = arg.length;
				uint hex_length = length * 2;
				set_args_command
					.append_uint (hex_length)
					.append_c (',')
					.append_uint (arg_index)
					.append_c (',');

				for (int byte_index = 0; byte_index != length; byte_index++)
					set_args_command.append_hexbyte (arg[byte_index]);

				arg_index++;
			}
			yield execute (set_args_command.build (), cancellable);

			yield execute_simple ("qLaunchSuccess", cancellable);

			var process = yield probe_target (cancellable);

			var dyld_fields = yield get_apple_dyld_fields (ALLOW_CACHE, cancellable);
			bool libsystem_initialized = yield read_bool (dyld_fields.libsystem_initialized, cancellable);

			process.observed_state = libsystem_initialized
				? Process.ObservedState.ALREADY_RUNNING
				: Process.ObservedState.FRESHLY_CREATED;

			return process;
		}

		public async Process attach_by_name (string name, Cancellable? cancellable = null) throws Error, IOError {
			var request = make_packet_builder_sized (64)
				.append ("vAttachName;");

			int length = name.length;
			for (int i = 0; i != length; i++)
				request.append_hexbyte (name[i]);

			return yield perform_attach (request, cancellable);
		}

		public async Process attach_by_pid (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			var request = make_packet_builder_sized (32)
				.append ("vAttach;")
				.append_process_id (pid);

			return yield perform_attach (request, cancellable);
		}

		private async Process perform_attach (PacketBuilder request, Cancellable? cancellable) throws Error, IOError {
			var response = yield query_with_predicate (request.build (), try_match_attach_response, cancellable);

			if (response.payload[0] == 'E')
				throw new Error.INVALID_ARGUMENT ("Unable to attach to the specified process");

			var process = yield probe_target (cancellable);

			try_handle_notification (response);

			return process;
		}

		private static ResponseAction try_match_attach_response (Packet packet) {
			switch (packet.payload[0]) {
				case NOTIFICATION_TYPE_STOP:
				case NOTIFICATION_TYPE_STOP_WITH_PROPERTIES:
				case 'E':
					return COMPLETE;
				default:
					return KEEP_TRYING;
			}
		}

		private async Process probe_target (Cancellable? cancellable) throws Error, IOError {
			yield load_target_properties (cancellable);

			_process = yield get_process_info (cancellable);
			pointer_size = _process.pointer_size;
			byte_order = _process.byte_order;

			ptrauth_removal_mask = (_process.cpu_type == ARM64) ? 0x0000007fffffffffULL : 0xffffffffffffffffULL;

			return _process;
		}

		public async void enumerate_threads (FoundThreadFunc func, Cancellable? cancellable = null) throws Error, IOError {
			var response = yield query_simple ("jThreadsInfo", cancellable);

			Json.Reader reader;
			try {
				reader = new Json.Reader (Json.from_string (response.payload));
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("Invalid response");
			}

			int thread_count = reader.count_elements ();
			if (thread_count == -1)
				throw new Error.PROTOCOL ("Invalid response");

			int thread_index;
			for (thread_index = 0; thread_index != thread_count; thread_index++) {
				reader.read_element (thread_index);

				reader.read_member ("tid");
				int64 numeric_tid = reader.get_int_value ();
				if (numeric_tid == 0)
					break;
				string tid = ("%" + int64.FORMAT_MODIFIER + "x").printf (numeric_tid);
				reader.end_member ();

				string? name = null;
				if (reader.read_member ("name"))
					name = reader.get_string_value ();
				reader.end_member ();

				var thread = new Thread (tid, name, this);
				bool carry_on = func (thread);
				if (!carry_on)
					return;

				reader.end_element ();
			}
			if (thread_index != thread_count)
				throw new Error.PROTOCOL ("Invalid response");
		}

		public delegate bool FoundThreadFunc (Thread thread);

		public async void enumerate_modules (FoundModuleFunc func, Cancellable? cancellable = null) throws Error, IOError {
			var response = yield query_simple ("jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true}", cancellable);

			Json.Reader reader;
			try {
				reader = new Json.Reader (Json.from_string (response.payload));
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("Invalid response");
			}

			reader.read_member ("images");

			int module_count = reader.count_elements ();
			if (module_count == -1)
				throw new Error.PROTOCOL ("Invalid response");

			int module_index;
			for (module_index = 0; module_index != module_count; module_index++) {
				reader.read_element (module_index);

				reader.read_member ("load_address");
				uint64 load_address = (uint64) reader.get_int_value ();
				if (load_address == 0)
					break;
				reader.end_member ();

				reader.read_member ("pathname");
				string pathname = reader.get_string_value ();
				if (pathname == null)
					break;
				reader.end_member ();

				reader.read_member ("segments");
				int segment_count = reader.count_elements ();
				if (segment_count == -1)
					break;
				var segments = new Gee.ArrayList<Module.Segment> ();
				int segment_index;
				for (segment_index = 0; segment_index != segment_count; segment_index++) {
					reader.read_element (segment_index);

					var segment = new Module.Segment ();

					reader.read_member ("name");
					segment.name = reader.get_string_value ();
					reader.end_member ();

					reader.read_member ("vmaddr");
					segment.vmaddr = (uint64) reader.get_int_value ();
					reader.end_member ();

					reader.read_member ("vmsize");
					segment.vmsize = (uint64) reader.get_int_value ();
					reader.end_member ();

					reader.read_member ("fileoff");
					segment.fileoff = (uint64) reader.get_int_value ();
					reader.end_member ();

					reader.read_member ("filesize");
					segment.filesize = (uint64) reader.get_int_value ();
					reader.end_member ();

					segments.add (segment);

					reader.end_element ();
				}
				if (segment_index != segment_count)
					break;
				reader.end_member ();

				var module = new Module (load_address, pathname, segments);
				bool carry_on = func (module);
				if (!carry_on)
					return;

				reader.end_element ();
			}
			if (module_index != module_count)
				throw new Error.PROTOCOL ("Invalid response");

			reader.end_member ();
		}

		public delegate bool FoundModuleFunc (Module module);

		public override async Bytes read_byte_array (uint64 address, size_t size, Cancellable? cancellable = null)
				throws Error, IOError {
			var request = make_packet_builder_sized (16)
				.append_c ('x')
				.append_address (address)
				.append_c (',')
				.append_size (size)
				.build ();
			var response = yield query (request, cancellable);

			var result = response.payload_bytes;
			if (result.get_size () != size) {
				throw new Error.INVALID_ARGUMENT (
					"Unable to read from 0x%" + uint64.FORMAT_MODIFIER + "x: invalid address", address);
			}

			return result;
		}

		public async uint64 allocate (size_t size, string protection, Cancellable? cancellable = null) throws Error, IOError {
			var request = make_packet_builder_sized (16)
				.append ("_M")
				.append_size (size)
				.append_c (',')
				.append (protection)
				.build ();
			var response = yield query (request, cancellable);

			return GDB.Protocol.parse_address (response.payload);
		}

		public async void deallocate (uint64 address, Cancellable? cancellable = null) throws Error, IOError {
			var command = make_packet_builder_sized (16)
				.append ("_m")
				.append_address (address)
				.build ();
			yield execute (command, cancellable);
		}

		public async AppleDyldFields get_apple_dyld_fields (CachePolicy cache_policy = ALLOW_CACHE, Cancellable? cancellable = null)
				throws Error, IOError {
			if (cache_policy == ALLOW_CACHE && cached_dyld_fields != null)
				return cached_dyld_fields;

			var response = yield query_simple ("qShlibInfoAddr", cancellable);

			var info_address = GDB.Protocol.parse_address (response.payload);
			var pointer_size = _process.pointer_size;

			uint64 notification_callback = info_address + 4 + 4 + pointer_size;
			uint64 libsystem_initialized = notification_callback + pointer_size + 1;
			uint64 dyld_load_address = notification_callback + (2 * pointer_size);

			cached_dyld_fields = new AppleDyldFields (info_address, notification_callback, libsystem_initialized, dyld_load_address);

			return cached_dyld_fields;
		}

		public uint64 strip_code_address (uint64 address) {
			return address & ptrauth_removal_mask;
		}

		private async Process get_process_info (Cancellable? cancellable = null) throws Error, IOError {
			var response = yield query_simple ("qProcessInfo", cancellable);

			var raw_info = GDB.Client.PropertyDictionary.parse (response.payload);

			var info = new Process ();
			info.pid = raw_info.get_uint ("pid");
			info.parent_pid = raw_info.get_uint ("parent-pid");
			info.real_uid = raw_info.get_uint ("real-uid");
			info.real_gid = raw_info.get_uint ("real-gid");
			info.effective_uid = raw_info.get_uint ("effective-uid");
			info.effective_gid = raw_info.get_uint ("effective-gid");
			info.cpu_type = (DarwinCpuType) raw_info.get_uint ("cputype");
			info.cpu_subtype = (DarwinCpuSubtype) raw_info.get_uint ("cpusubtype");
			info.pointer_size = raw_info.get_uint ("ptrsize");
			info.os_type = raw_info.get_string ("ostype");
			info.vendor = raw_info.get_string ("vendor");
			info.byte_order = (raw_info.get_string ("endian") == "little")
				? ByteOrder.LITTLE_ENDIAN
				: ByteOrder.BIG_ENDIAN;

			return info;
		}

		protected override async void parse_stop (uint signum, GDB.Client.PropertyDictionary properties,
				out GDB.Exception exception, out GDB.Breakpoint? breakpoint) throws Error, IOError {
			var sig = (Signal) signum;

			MachExceptionType metype = NONE;
			var medata = new Gee.ArrayList<uint64?> ();
			if (properties.has ("metype")) {
				metype = (MachExceptionType) properties.get_uint ("metype");
				if (properties.has ("medata")) {
					var mecount = properties.get_uint ("mecount");
					if (mecount == 1) {
						medata.add (properties.get_uint64 ("medata"));
					} else {
						medata.add_all (properties.get_uint64_array ("medata"));
					}
				}
			}

			string? thread_name = null;
			if (properties.has ("hexname")) {
				thread_name = GDB.Protocol.parse_hex_encoded_utf8_string (properties.get_string ("hexname"));
			}

			var thread = new Thread (properties.get_string ("thread"), thread_name, this);

			var thread_ids = properties.get_string_array ("threads");
			var thread_pcs = properties.get_uint64_array ("thread-pcs");

			var active_thread_index = thread_ids.index_of (thread.id);
			if (active_thread_index == -1)
				throw new Error.PROTOCOL ("Invalid stop packet");

			uint64 pc = thread_pcs[active_thread_index];

			breakpoint = (sig == SIGTRAP) ? breakpoints[pc] : null;

			var context = new Gee.HashMap<string, uint64?> ();
			var pointer_size = _process.pointer_size;
			var byte_order = _process.byte_order;
			properties.foreach (entry => {
				string key = entry.key;
				if (key.length != 2)
					return true;

				uint64 register_index;
				try {
					uint64.from_string (key, out register_index, 16);
				} catch (NumberParserError e) {
					return true;
				}

				GDB.Client.Register reg;
				try {
					reg = get_register_by_index ((uint) register_index);
				} catch (Error e) {
					return true;
				}

				if (reg.bitsize != pointer_size * 8)
					return true;

				uint64 val;
				try {
					val = GDB.Protocol.parse_pointer_value (entry.value, pointer_size, byte_order);
				} catch (Error e) {
					return true;
				}

				context[reg.name] = val;

				return true;
			});

			exception = new Exception (signum, metype, medata, breakpoint, thread, context);
		}
	}

	public class LaunchOptions : Object {
		public string[] env {
			get;
			set;
			default = {};
		}

		public string? arch {
			get;
			set;
		}

		public ASLR aslr {
			get;
			set;
			default = AUTO;
		}
	}

	public class Process : Object {
		public uint pid {
			get;
			set;
		}

		public uint parent_pid {
			get;
			set;
		}

		public uint real_uid {
			get;
			set;
		}

		public uint real_gid {
			get;
			set;
		}

		public uint effective_uid {
			get;
			set;
		}

		public uint effective_gid {
			get;
			set;
		}

		public DarwinCpuType cpu_type {
			get;
			set;
		}

		public DarwinCpuSubtype cpu_subtype {
			get;
			set;
		}

		public uint pointer_size {
			get;
			set;
		}

		public string os_type {
			get;
			set;
		}

		public string vendor {
			get;
			set;
		}

		public ByteOrder byte_order {
			get;
			set;
		}

		public ObservedState observed_state {
			get;
			set;
			default = ALREADY_RUNNING;
		}

		public enum ObservedState {
			FRESHLY_CREATED,
			ALREADY_RUNNING
		}
	}

	public enum ASLR {
		AUTO,
		DISABLE;

		public static ASLR from_nick (string nick) throws Frida.Error {
			return Marshal.enum_from_nick<ASLR> (nick);
		}
	}

	public enum DarwinCpuArchType {
		ABI64		= 0x01000000,
		ABI64_32	= 0x02000000,
	}

	public enum DarwinCpuType {
		X86		= 7,
		X86_64		= 7 | DarwinCpuArchType.ABI64,
		ARM		= 12,
		ARM64		= 12 | DarwinCpuArchType.ABI64,
		ARM64_32	= 12 | DarwinCpuArchType.ABI64_32,
	}

	public enum DarwinCpuSubtype {
		ARM64E		= 2,
	}

	public class Thread : GDB.Thread {
		private const uint PAGE_SIZE = 16384U;
		private const uint32 THREAD_MAGIC = 0x54485244U;

		public Thread (string id, string? name, Client client) {
			Object (
				id: id,
				name: name,
				client: client
			);
		}

		public async Snapshot save_register_state (Cancellable? cancellable = null) throws Error, IOError {
			var request = client.make_packet_builder_sized (48)
				.append ("QSaveRegisterState;thread:")
				.append (id)
				.append_c (';')
				.build ();

			var response = yield client.query (request, cancellable);

			return new Snapshot (GDB.Protocol.parse_uint (response.payload, 10));
		}

		public async void restore_register_state (Snapshot snapshot, Cancellable? cancellable = null) throws Error, IOError {
			var command = client.make_packet_builder_sized (48)
				.append ("QRestoreRegisterState:")
				.append_uint (snapshot.handle)
				.append (";thread:")
				.append (id)
				.append_c (';')
				.build ();

			yield client.execute (command, cancellable);
		}

		public async Gee.ArrayList<Frame> generate_backtrace (StackBounds? stack = null, Cancellable? cancellable = null) throws Error, IOError {
			var result = new Gee.ArrayList<Frame> ();

			var lldb = (Client) client;

			var sp = yield read_register ("sp", cancellable);
			var lr = lldb.strip_code_address (yield read_register ("lr", cancellable));
			var fp = yield read_register ("fp", cancellable);

			result.add (new Frame (lr, sp));

			uint64 current = fp;

			if (stack == null)
				stack = yield find_stack_bounds (sp, cancellable);

			while (current >= stack.bottom && current < stack.top && frame_pointer_is_aligned (current)) {
				var frame = yield client.read_buffer (current, 16, cancellable);

				uint64 next = frame.read_pointer (0);
				uint64 return_address = lldb.strip_code_address (frame.read_pointer (8));

				if (next == 0 || return_address == 0)
					break;
				result.add (new Frame (return_address, current));

				if (next <= current)
					break;
				current = next;
			}

			return result;
		}

		private static bool frame_pointer_is_aligned (uint64 fp) {
			return (fp & 1) == 0;
		}

		private async StackBounds find_stack_bounds (uint64 sp, Cancellable? cancellable) {
			uint64 start_page = round_down_to_page_boundary (sp);
			uint64 end_page = start_page + (1024 * PAGE_SIZE);

			uint64 cur_region = (start_page + 4095) & ~4095ULL;
			while (cur_region != end_page) {
				Buffer chunk;
				try {
					chunk = yield client.read_buffer (cur_region, 4, cancellable);
				} catch (GLib.Error e) {
					return StackBounds (sp, round_down_to_page_boundary (cur_region));
				}

				if (chunk.read_uint32 (0) == THREAD_MAGIC)
					return StackBounds (sp, cur_region);

				cur_region += 4096;
			}

			return StackBounds (sp, cur_region);
		}

		private static uint64 round_down_to_page_boundary (uint64 address) {
			return address & ~((uint64) (PAGE_SIZE - 1));
		}

		public class Snapshot {
			public uint handle {
				get;
				private set;
			}

			internal Snapshot (uint handle) {
				this.handle = handle;
			}
		}

		public class Frame {
			public uint64 address {
				get;
				private set;
			}

			public uint64 stack_location {
				get;
				private set;
			}

			public Frame (uint64 address, uint64 stack_location) {
				this.address = address;
				this.stack_location = stack_location;
			}
		}

		public struct StackBounds {
			public uint64 bottom;
			public uint64 top;

			public StackBounds (uint64 bottom, uint64 top) {
				this.bottom = bottom;
				this.top = top;
			}
		}
	}

	public class Module : Object {
		public uint64 load_address {
			get;
			construct;
		}

		public string pathname {
			get;
			construct;
		}

		public Gee.ArrayList<Segment> segments {
			get;
			construct;
		}

		public Module (uint64 load_address, string pathname, owned Gee.ArrayList<Segment> segments) {
			Object (
				load_address: load_address,
				pathname: pathname,
				segments: segments
			);
		}

		public class Segment {
			public string name;

			public uint64 vmaddr;
			public uint64 vmsize;

			public uint64 fileoff;
			public uint64 filesize;
		}
	}

	public class Exception : GDB.Exception {
		public MachExceptionType metype {
			get;
			construct;
		}

		public Gee.ArrayList<uint64?> medata {
			get;
			construct;
		}

		public Gee.HashMap<string, uint64?> context {
			get;
			construct;
		}

		public Exception (Signal signum, MachExceptionType metype, Gee.ArrayList<uint64?> medata, GDB.Breakpoint? breakpoint,
				Thread thread, Gee.HashMap<string, uint64?> context) {
			Object (
				signum: signum,
				metype: metype,
				medata: medata,
				breakpoint: breakpoint,
				thread: thread,
				context: context
			);
		}

		public override string to_string () {
			var result = new StringBuilder.sized (128);

			var sig = (Signal) signum;

			result
				.append (sig.to_name ())
				.append (", ")
				.append (metype.to_name ())
				.append (", [ ");

			uint i = 0;
			foreach (uint64 val in medata) {
				if (i != 0)
					result.append (", ");

				result.append_printf ("0x%" + uint64.FORMAT_MODIFIER + "x", val);

				i++;
			}

			result.append (" ]\n\nREGISTERS:");

			var sorted_register_names = context.keys.order_by ((a, b) => {
					var sa = score_register (a);
					var sb = score_register (b);
					if (sa != sb)
						return sa - sb;

					return strcmp (a, b);
				});
			uint offset = 0;
			while (sorted_register_names.next ()) {
				string name = sorted_register_names.get ();
				uint64 val = context[name];

				if (offset % 4 == 0)
					result.append ("\n   ");
				else
					result.append ("  ");

				result.append_printf ("%3s: 0x%016" + uint64.FORMAT_MODIFIER + "x", name, val);

				offset++;
			}

			return result.str;
		}

		private static int score_register (string name) {
			if (name[0] == 'x')
				return name.length;

			return 10;
		}
	}

	public enum Signal {
		SIGHUP = 1,
		SIGINT,
		SIGQUIT,
		SIGILL,
		SIGTRAP,
		SIGABRT,
		SIGEMT,
		SIGFPE,
		SIGKILL,
		SIGBUS,
		SIGSEGV,
		SIGSYS,
		SIGPIPE,
		SIGALRM,
		SIGTERM,
		SIGURG,
		SIGSTOP,
		SIGTSTP,
		SIGCONT,
		SIGCHLD,
		SIGTTIN,
		SIGTTOU,
		SIGIO,
		SIGXCPU,
		SIGXFSZ,
		SIGVTALRM,
		SIGPROF,
		SIGWINCH,
		SIGINFO,
		SIGUSR1,
		SIGUSR2,
		TARGET_EXC_BAD_ACCESS = 0x91,
		TARGET_EXC_BAD_INSTRUCTION,
		TARGET_EXC_ARITHMETIC,
		TARGET_EXC_EMULATION,
		TARGET_EXC_SOFTWARE,
		TARGET_EXC_BREAKPOINT;

		public static Signal from_nick (string nick) throws Frida.Error {
			return Marshal.enum_from_nick<Signal> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Signal> (this);
		}

		public string to_name () {
			return to_nick ().ascii_up ().replace ("-", "_");
		}
	}

	public enum MachExceptionType {
		NONE,
		EXC_BAD_ACCESS,
		EXC_BAD_INSTRUCTION,
		EXC_ARITHMETIC,
		EXC_EMULATION,
		EXC_SOFTWARE,
		EXC_BREAKPOINT,
		EXC_SYSCALL,
		EXC_MACH_SYSCALL,
		EXC_RPC_ALERT,
		EXC_CRASH,
		EXC_RESOURCE,
		EXC_GUARD,
		EXC_CORPSE_NOTIFY;

		public static MachExceptionType from_nick (string nick) throws Frida.Error {
			return Marshal.enum_from_nick<MachExceptionType> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<MachExceptionType> (this);
		}

		public string to_name () {
			return to_nick ().ascii_up ().replace ("-", "_");
		}
	}

	public class AppleDyldFields : Object {
		public uint64 all_image_info {
			get;
			construct;
		}

		public uint64 notification_callback {
			get;
			construct;
		}

		public uint64 libsystem_initialized {
			get;
			construct;
		}

		public uint64 dyld_load_address {
			get;
			construct;
		}

		public AppleDyldFields (uint64 all_image_info, uint64 notification_callback, uint64 libsystem_initialized,
				uint64 dyld_load_address) {
			Object (
				all_image_info: all_image_info,
				notification_callback: notification_callback,
				libsystem_initialized: libsystem_initialized,
				dyld_load_address: dyld_load_address
			);
		}
	}
}
```