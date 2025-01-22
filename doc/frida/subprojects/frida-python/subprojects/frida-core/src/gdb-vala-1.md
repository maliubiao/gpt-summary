Response:
### 功能归纳

该文件是 Frida 动态插桩工具中与 GDB 调试协议相关的实现部分，主要用于与 GDB 调试器进行通信，处理调试过程中的各种操作。以下是该文件的主要功能：

1. **GDB 协议处理**：
   - 实现了 GDB 协议的解析和生成，包括寄存器读取、写入、断点设置、单步执行等操作。
   - 支持多种架构（如 x86、x64、ARM、ARM64、MIPS 等）的寄存器操作。

2. **寄存器操作**：
   - 提供了读取和写入寄存器的功能，支持不同位宽的寄存器（如 32 位、64 位）。
   - 通过 GDB 协议与目标进程通信，获取或修改寄存器的值。

3. **断点管理**：
   - 支持设置、启用、禁用和删除断点。
   - 断点类型包括软件断点、硬件断点、读写断点等。

4. **线程管理**：
   - 提供了线程的单步执行、寄存器读取和写入等功能。
   - 支持多线程调试，能够针对特定线程进行操作。

5. **异常处理**：
   - 捕获和处理调试过程中的异常（如信号、断点触发等）。
   - 提供异常信息的解析和展示。

6. **协议解析与生成**：
   - 实现了 GDB 协议的解析器，能够解析从 GDB 服务器接收到的数据包。
   - 生成符合 GDB 协议的数据包，发送给 GDB 服务器。

7. **架构支持**：
   - 支持多种 CPU 架构的调试，包括 x86、x64、ARM、ARM64、MIPS 等。
   - 根据目标架构的不同，自动调整寄存器操作和断点设置的方式。

8. **调试器客户端**：
   - 实现了与 GDB 服务器的通信逻辑，包括数据包的发送、接收和处理。
   - 提供了高层次的调试接口，供上层工具调用。

### 二进制底层与 Linux 内核相关

- **寄存器操作**：该文件涉及到底层的寄存器操作，特别是在调试过程中读取和写入寄存器的值。例如，在 Linux 内核调试中，可以通过读取 `RIP` 寄存器来获取当前指令的地址，或者通过修改 `RSP` 寄存器来调整栈指针。
  
- **断点设置**：断点的设置涉及到 CPU 的调试寄存器（如 `DR0`-`DR7`），特别是在硬件断点的实现中，调试器会直接操作这些寄存器来设置断点。

- **异常处理**：在 Linux 内核中，调试器会捕获和处理各种异常信号（如 `SIGTRAP`、`SIGSEGV` 等），这些信号通常与调试事件相关，如断点触发、内存访问错误等。

### LLDB 指令或 Python 脚本示例

以下是一个使用 LLDB Python 脚本的示例，展示了如何通过 LLDB 实现类似的调试功能（如读取寄存器、设置断点等）：

```python
import lldb

# 初始化 LLDB 调试器
debugger = lldb.SBDebugger.Create()
debugger.SetAsync(False)
target = debugger.CreateTarget("a.out")

# 启动进程
process = target.LaunchSimple(None, None, os.getcwd())

# 获取第一个线程
thread = process.GetThreadAtIndex(0)

# 读取寄存器的值
frame = thread.GetFrameAtIndex(0)
register_value = frame.FindRegister("rip")
print(f"RIP register value: {register_value.GetValue()}")

# 设置断点
breakpoint = target.BreakpointCreateByAddress(0x100000)
print(f"Breakpoint set at address: {breakpoint.GetLocationAtIndex(0).GetAddress()}")

# 继续执行
process.Continue()
```

### 假设输入与输出

- **输入**：用户通过 Frida 工具调用 `read_register` 方法，传入寄存器名称 `rip`。
- **输出**：返回当前线程的 `RIP` 寄存器的值，例如 `0x100000`。

### 常见使用错误

1. **寄存器名称错误**：
   - 用户可能输入了不存在的寄存器名称，导致调试器无法找到对应的寄存器。
   - 例如，在 x86 架构下输入 `xmm0`，而该寄存器在 x86 架构下不存在。

2. **断点设置失败**：
   - 用户可能尝试在不合法的内存地址上设置断点，导致断点设置失败。
   - 例如，尝试在只读内存区域设置写断点。

3. **多线程竞争**：
   - 在多线程环境下，用户可能在某个线程中修改了寄存器的值，而另一个线程正在使用该寄存器，导致不可预期的行为。

### 用户操作步骤

1. **启动调试器**：用户通过 Frida 工具启动调试会话，连接到目标进程。
2. **设置断点**：用户通过 Frida 的 API 在目标进程的某个地址上设置断点。
3. **运行程序**：目标进程运行，触发断点，调试器捕获到断点事件。
4. **读取寄存器**：用户通过 Frida 的 API 读取当前线程的寄存器值。
5. **单步执行**：用户通过 Frida 的 API 让目标进程单步执行一条指令。
6. **继续执行**：用户通过 Frida 的 API 让目标进程继续执行，直到下一个断点或程序结束。

通过这些步骤，用户可以逐步调试目标进程，分析其运行状态和行为。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/gdb.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共2部分，请归纳一下它的功能

"""
printf ("%x", register_id);
				return this;
			}

			public unowned PacketBuilder append_register_value (uint64 val) {
				return append_address (val);
			}

			public unowned PacketBuilder append_hexbyte (uint8 byte) {
				buffer.append_c (Protocol.NIBBLE_TO_HEX_CHAR[byte >> 4]);
				buffer.append_c (Protocol.NIBBLE_TO_HEX_CHAR[byte & 0xf]);
				return this;
			}

			public Bytes build () {
				buffer.append_c (CHECKSUM_CHARACTER);

				if (checksum_type == PROPER) {
					buffer.append_printf ("%02x", compute_checksum (buffer.str, 1, buffer.len - 2));
				} else {
					buffer.append ("00");
				}

				return StringBuilder.free_to_bytes ((owned) buffer);
			}
		}

		private class StopObserverEntry {
			public SourceFunc? func;

			public StopObserverEntry (owned SourceFunc func) {
				this.func = (owned) func;
			}
		}

		public delegate ResponseAction ResponsePredicate (Packet packet);

		public enum ResponseAction {
			COMPLETE,
			ABSORB,
			KEEP_TRYING
		}

		private class PendingResponse {
			public ResponsePredicate? predicate;

			public Packet? response {
				get;
				private set;
			}

			public GLib.Error? error {
				get;
				private set;
			}

			private SourceFunc? handler;

			public PendingResponse (owned ResponsePredicate predicate, owned SourceFunc handler) {
				this.predicate = (owned) predicate;
				this.handler = (owned) handler;
			}

			public void complete_with_response (Packet response) {
				this.response = response;
				invoke_handler_in_idle ();
			}

			public void complete_with_error (GLib.Error error) {
				this.error = error;
				invoke_handler_in_idle ();
			}

			private void invoke_handler_in_idle () {
				var source = new IdleSource ();
				source.set_callback (() => {
					if (handler != null) {
						handler ();
						handler = null;
					}
					return Source.REMOVE;
				});
				source.attach (MainContext.get_thread_default ());
			}
		}

		protected class PropertyDictionary {
			private Gee.HashMap<string, string> properties = new Gee.HashMap<string, string> ();

			public static PropertyDictionary parse (string raw_properties) throws Error {
				var dictionary = new PropertyDictionary ();

				var properties = dictionary.properties;

				var pairs = raw_properties.split (";");
				foreach (var pair in pairs) {
					if (pair.length == 0)
						continue;

					var tokens = pair.split (":", 2);
					if (tokens.length != 2)
						throw new Error.PROTOCOL ("Invalid property dictionary pair");
					unowned string key = tokens[0];
					unowned string val = tokens[1];

					if (!properties.has_key (key)) {
						properties[key] = val;
					} else {
						properties[key] = properties[key] + "," + val;
					}
				}

				return dictionary;
			}

			public void foreach (Gee.ForallFunc<Gee.Map.Entry<string, string>> f) {
				properties.foreach (f);
			}

			public bool has (string name) {
				return properties.has_key (name);
			}

			public string get_string (string name) throws Error {
				var val = properties[name];
				if (val == null)
					throw new Error.PROTOCOL ("Property '%s' not found", name);
				return val;
			}

			public uint get_uint (string name) throws Error {
				return Protocol.parse_uint (get_string (name), 16);
			}

			public uint64 get_uint64 (string name) throws Error {
				return Protocol.parse_uint64 (get_string (name), 16);
			}

			public Gee.ArrayList<string> get_string_array (string name) throws Error {
				var result = new Gee.ArrayList<string> ();
				result.add_all_array (get_string (name).split (","));
				return result;
			}

			public Gee.ArrayList<uint> get_uint_array (string name) throws Error {
				var result = new Gee.ArrayList<uint> ();

				foreach (var element in get_string (name).split (","))
					result.add (Protocol.parse_uint (element, 16));

				return result;
			}

			public Gee.ArrayList<uint64?> get_uint64_array (string name) throws Error {
				var result = new Gee.ArrayList<uint64?> ();

				foreach (var element in get_string (name).split (","))
					result.add (Protocol.parse_uint64 (element, 16));

				return result;
			}
		}

		protected class Register {
			public string name {
				get;
				private set;
			}

			public string? altname {
				get;
				private set;
			}

			public uint id {
				get;
				private set;
			}

			public uint bitsize {
				get;
				private set;
			}

			public Register (string name, string? altname, uint id, uint bitsize) {
				this.name = name;
				this.altname = altname;
				this.id = id;
				this.bitsize = bitsize;
			}
		}

		protected class TargetSpec {
			public TargetArch arch;
			public Gee.List<Register> registers;

			public TargetSpec (TargetArch arch, Gee.List<Register> registers) {
				this.arch = arch;
				this.registers = registers;
			}
		}

		private class FeatureDocument {
			public TargetArch arch = UNKNOWN;

			public Gee.List<Register> registers = new Gee.ArrayList<Register> ();
			public uint next_regnum;

			public Gee.List<string> includes = new Gee.ArrayList<string> ();

			public static FeatureDocument from_xml (string xml, uint next_regnum) throws Error {
				var doc = new FeatureDocument (next_regnum);

				var parser = new Parser (doc);
				parser.parse (xml);

				return doc;
			}

			private FeatureDocument (uint next_regnum) {
				this.next_regnum = next_regnum;
			}

			private class Parser {
				private FeatureDocument doc;

				private bool in_architecture = false;

				private const MarkupParser CALLBACKS = {
					on_start_element,
					on_end_element,
					on_text_element,
					null,
					null
				};

				public Parser (FeatureDocument doc) {
					this.doc = doc;
				}

				public void parse (string xml) throws Error {
					try {
						var context = new MarkupParseContext (CALLBACKS, 0, this, null);
						context.parse (xml, -1);
					} catch (MarkupError e) {
						throw new Error.PROTOCOL ("%s", e.message);
					}
				}

				private void on_start_element (MarkupParseContext context, string element_name, string[] attribute_names,
						string[] attribute_values) throws MarkupError {
					if (element_name == "reg") {
						on_reg_element (attribute_names, attribute_values);
						return;
					}

					if (element_name == "feature") {
						on_feature_element (attribute_names, attribute_values);
						return;
					}

					if (element_name == "architecture") {
						in_architecture = true;
						return;
					}

					if (element_name == "xi:include") {
						on_include_element (attribute_names, attribute_values);
						return;
					}
				}

				private void on_end_element (MarkupParseContext context, string element_name) throws MarkupError {
					in_architecture = false;
				}

				private void on_text_element (MarkupParseContext context, string text, size_t text_len) throws MarkupError {
					if (in_architecture)
						doc.arch = parse_gdb_arch (text);
				}

				private void on_feature_element (string[] attribute_names, string[] attribute_values) {
					uint i = 0;
					foreach (unowned string attribute_name in attribute_names) {
						unowned string val = attribute_values[i];

						if (attribute_name == "name") {
							if (val.has_prefix ("com.apple.debugserver."))
								doc.arch = parse_lldb_arch (val[22:]);
							return;
						}

						i++;
					}
				}

				private void on_reg_element (string[] attribute_names, string[] attribute_values) {
					string? name = null;
					string? altname = null;
					int regnum = -1;
					int bitsize = -1;
					uint i = 0;
					foreach (unowned string attribute_name in attribute_names) {
						unowned string val = attribute_values[i];

						if (attribute_name == "name")
							name = val.down ();
						else if (attribute_name == "altname")
							altname = val.down ();
						else if (attribute_name == "regnum")
							regnum = int.parse (val);
						else if (attribute_name == "bitsize")
							bitsize = int.parse (val);

						i++;
					}
					if (name == null)
						return;
					if (regnum == -1)
						regnum = (int) doc.next_regnum++;
					else
						doc.next_regnum = regnum + 1;

					doc.registers.add (new Register (name, altname, regnum, bitsize));
				}

				private void on_include_element (string[] attribute_names, string[] attribute_values) {
					uint i = 0;
					foreach (unowned string attribute_name in attribute_names) {
						unowned string val = attribute_values[i];

						if (attribute_name == "href") {
							doc.includes.add (val);
							return;
						}
					}
				}

				private static TargetArch parse_gdb_arch (string name) {
					switch (name) {
						case "i386":		return IA32;
						case "i386:x86-64":	return X64;
						case "arm":		return ARM;
						case "aarch64":		return ARM64;
						case "mips":		return MIPS;
						default:		return UNKNOWN;
					}
				}

				private static TargetArch parse_lldb_arch (string name) {
					if (name == "i386")
						return IA32;

					if (name.has_prefix ("x86_64"))
						return X64;

					if (name.has_prefix ("arm64"))
						return ARM64;

					if (name.has_prefix ("arm"))
						return ARM;

					return UNKNOWN;
				}
			}
		}
	}

	public enum TargetArch {
		UNKNOWN,
		IA32,
		X64,
		ARM,
		ARM64,
		MIPS;

		public static TargetArch from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<TargetArch> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<TargetArch> (this);
		}
	}

	public class Thread : Object {
		public string id {
			get;
			construct;
		}

		public string? name {
			get;
			construct;
		}

		public weak Client client {
			get;
			construct;
		}

		public Thread (string id, string? name, Client client) {
			Object (
				id: id,
				name: name,
				client: client
			);
		}

		public async void step (Cancellable? cancellable = null) throws Error, IOError {
			yield client._step_thread (this, cancellable);
		}

		public void step_and_continue () throws Error {
			client._step_thread_and_continue (this);
		}

		public async Gee.Map<string, Variant> read_registers (Cancellable? cancellable = null) throws Error, IOError {
			var response = yield client.query_simple ("g", cancellable);

			var result = new Gee.HashMap<string, Variant> ();

			unowned string payload = response.payload;
			uint encoded_size = payload.length;

			uint hex_chars_per_byte = 2;
			uint bits_per_byte = 8;

			uint offset = 0;
			uint size = encoded_size / hex_chars_per_byte;
			uint pointer_size = client.pointer_size;
			ByteOrder byte_order = client.byte_order;
			for (uint i = 0; offset != size; i++) {
				GDB.Client.Register reg = client.get_register_by_index (i);

				uint reg_size = reg.bitsize / bits_per_byte;
				uint end_offset = offset + reg_size;
				if (end_offset > size)
					throw new Error.PROTOCOL ("Truncated register value");

				string raw_val = payload[offset * hex_chars_per_byte:end_offset * hex_chars_per_byte];

				try {
					if (reg_size == pointer_size) {
						result[reg.name] = GDB.Protocol.parse_pointer_value (raw_val, pointer_size, byte_order);
					} else if (reg_size < pointer_size) {
						result[reg.name] = (uint32) GDB.Protocol.parse_integer_value (raw_val, byte_order);
					} else {
						Bytes bytes = Protocol.parse_hex_bytes (raw_val);
						result[reg.name] = Variant.new_from_data (new VariantType ("ay"), bytes.get_data (), true, bytes);
					}
				} catch (Error e) {
					throw new Error.PROTOCOL ("Unexpected register value encoding");
				}

				offset = end_offset;
			}
			return result;
		}

		public async void write_registers (Gee.Map<string, Variant> regs, Cancellable? cancellable = null) throws Error, IOError {
			var builder = client.make_packet_builder_sized (2048)
				.append_c ('G');

			int n = int.min (regs.size, client.get_registers ().size);
			ByteOrder byte_order = client.byte_order;
			for (int i = 0; i != n; i++) {
				GDB.Client.Register reg = client.get_register_by_index (i);
				Variant? val = regs[reg.name];
				if (val == null)
					throw new Error.INVALID_ARGUMENT ("Missing %s", reg.name);

				if (val.is_of_type (VariantType.UINT64)) {
					builder.append (Protocol.unparse_integer_value (val.get_uint64 (), sizeof (uint64), byte_order));
				} else if (val.is_of_type (VariantType.UINT32)) {
					builder.append (Protocol.unparse_integer_value (val.get_uint64 (), sizeof (uint32), byte_order));
				} else {
					builder.append (Protocol.unparse_hex_bytes (val.get_data_as_bytes ()));
				}
			}

			yield client.execute (builder.build (), cancellable);
		}

		public async uint64 read_register (string name, Cancellable? cancellable = null) throws Error, IOError {
			var reg = client.get_register_by_name (name);

			var request = client.make_packet_builder_sized (32)
				.append_c ('p')
				.append_register_id (reg.id)
				.append (";thread:")
				.append (id)
				.append_c (';')
				.build ();

			var response = yield client.query (request, cancellable);

			return Protocol.parse_pointer_value (response.payload, client.pointer_size, client.byte_order);
		}

		public async void write_register (string name, uint64 val, Cancellable? cancellable = null) throws Error, IOError {
			var reg = client.get_register_by_name (name);

			var command = client.make_packet_builder_sized (48)
				.append_c ('P')
				.append_register_id (reg.id)
				.append_c ('=')
				.append (Protocol.unparse_integer_value (val, client.pointer_size, client.byte_order))
				.append (";thread:")
				.append (id)
				.append_c (';')
				.build ();

			yield client.execute (command, cancellable);
		}
	}

	public class Exception : Object {
		public uint signum {
			get;
			construct;
		}

		public Breakpoint? breakpoint {
			get;
			construct;
		}

		public Thread thread {
			get;
			construct;
		}

		public Exception (uint signum, Breakpoint? breakpoint, Thread thread) {
			Object (
				signum: signum,
				breakpoint: breakpoint,
				thread: thread
			);
		}

		public virtual string to_string () {
			return "signum=%u".printf (signum);
		}
	}

	public class Breakpoint : Object {
		public signal void removed ();

		public Kind kind {
			get;
			construct;
		}

		public uint64 address {
			get;
			construct;
		}

		public size_t size {
			get;
			construct;
		}

		public weak Client client {
			get;
			construct;
		}

		public enum Kind {
			SOFT,
			HARD,
			WRITE,
			READ,
			ACCESS;

			public static Kind from_nick (string nick) throws Error {
				return Marshal.enum_from_nick<Kind> (nick);
			}

			public string to_nick () {
				return Marshal.enum_to_nick<Kind> (this);
			}
		}

		private enum State {
			DISABLED,
			ENABLED
		}

		private State state = DISABLED;

		public Breakpoint (Kind kind, uint64 address, size_t size, Client client) {
			Object (
				kind: kind,
				address: address,
				size: size,
				client: client
			);
		}

		public async void enable (Cancellable? cancellable = null) throws Error, IOError {
			if (state != DISABLED)
				throw new Error.INVALID_OPERATION ("Already enabled");

			var command = client.make_packet_builder_sized (16)
				.append ("Z%u,".printf (kind))
				.append_address (address)
				.append_c (',')
				.append_size (size)
				.build ();

			yield client.execute (command, cancellable);

			state = ENABLED;
		}

		public async void disable (Cancellable? cancellable = null) throws Error, IOError {
			if (state != ENABLED)
				throw new Error.INVALID_OPERATION ("Already disabled");

			var command = client.make_packet_builder_sized (16)
				.append ("z%u,".printf (kind))
				.append_address (address)
				.append_c (',')
				.append_size (size)
				.build ();

			yield client.execute (command, cancellable);

			state = DISABLED;
		}

		public async void remove (Cancellable? cancellable = null) throws Error, IOError {
			if (state == ENABLED)
				yield disable (cancellable);

			removed ();
		}
	}

	namespace Protocol {
#if HAVE_FRUITY_BACKEND
		internal uint64 parse_address (string raw_val) throws Error {
			return parse_uint64 (raw_val, 16);
		}
#endif

		internal uint parse_uint (string raw_val, uint radix) throws Error {
			uint64 val;

			try {
				uint64.from_string (raw_val, out val, radix, uint.MIN, uint.MAX);
			} catch (NumberParserError e) {
				throw new Error.PROTOCOL ("Invalid response: %s", e.message);
			}

			return (uint) val;
		}

		internal uint64 parse_uint64 (string raw_val, uint radix) throws Error {
			uint64 val;

			try {
				uint64.from_string (raw_val, out val, radix);
			} catch (NumberParserError e) {
				throw new Error.PROTOCOL ("Invalid response: %s", e.message);
			}

			return val;
		}

		internal uint64 parse_pointer_value (string raw_val, uint pointer_size, ByteOrder byte_order) throws Error {
			if (raw_val.length != pointer_size * 2)
				throw new Error.PROTOCOL ("Invalid pointer value: %s", raw_val);

			return parse_integer_value (raw_val, byte_order);
		}

		internal uint64 parse_integer_value (string raw_val, ByteOrder byte_order) throws Error {
			int length = raw_val.length;
			if (length % 2 != 0)
				throw new Error.PROTOCOL ("Invalid integer value: %s", raw_val);

			int start_offset, end_offset, step;
			if (byte_order == BIG_ENDIAN) {
				start_offset = 0;
				end_offset = length;
				step = 2;
			} else {
				start_offset = length - 2;
				end_offset = -2;
				step = -2;
			}

			uint64 val = 0;

			for (int hex_offset = start_offset; hex_offset != end_offset; hex_offset += step) {
				uint8 byte = parse_hex_byte (raw_val[hex_offset + 0], raw_val[hex_offset + 1]);
				val = (val << 8) | byte;
			}

			return val;
		}

		internal string unparse_integer_value (uint64 val, size_t size, ByteOrder byte_order) {
			char * result = malloc ((size * 2) + 1);

			int start_byte_offset, end_byte_offset, byte_step;
			if (byte_order == LITTLE_ENDIAN) {
				start_byte_offset = 0;
				end_byte_offset = (int) size;
				byte_step = 1;
			} else {
				start_byte_offset = (int) size - 1;
				end_byte_offset = -1;
				byte_step = -1;
			}

			int hex_offset = 0;
			for (int byte_offset = start_byte_offset;
					byte_offset != end_byte_offset;
					byte_offset += byte_step, hex_offset += 2) {
				uint8 byte = (uint8) ((val >> (byte_offset * 8)) & 0xff);
				result[hex_offset + 0] = NIBBLE_TO_HEX_CHAR[byte >> 4];
				result[hex_offset + 1] = NIBBLE_TO_HEX_CHAR[byte & 0xf];
			}
			result[hex_offset] = '\0';

			return (string) (owned) result;
		}

		internal static string parse_hex_encoded_utf8_string (string hex_str) throws Error {
			Bytes bytes = parse_hex_bytes (hex_str);
			unowned string str = (string) bytes.get_data ();
			return str.make_valid ((ssize_t) bytes.get_size ());
		}

		internal static Bytes parse_hex_bytes (string hex_bytes) throws Error {
			int size = hex_bytes.length / 2;
			uint8[] data = new uint8[size];

			for (int byte_offset = 0, hex_offset = 0; byte_offset != size; byte_offset++, hex_offset += 2) {
				data[byte_offset] = parse_hex_byte (hex_bytes[hex_offset + 0], hex_bytes[hex_offset + 1]);
			}

			return new Bytes.take ((owned) data);
		}

		internal static string unparse_hex_bytes (Bytes bytes) throws Error {
			unowned uint8[] data = bytes.get_data ();
			uint size = data.length;

			char * result = malloc ((size * 2) + 1);
			int hex_offset = 0;
			for (int byte_offset = 0; byte_offset != size; byte_offset++, hex_offset += 2) {
				uint8 byte = data[byte_offset];
				result[hex_offset + 0] = NIBBLE_TO_HEX_CHAR[byte >> 4];
				result[hex_offset + 1] = NIBBLE_TO_HEX_CHAR[byte & 0xf];
			}
			result[hex_offset] = '\0';

			return (string) (owned) result;
		}

		internal uint8 parse_hex_byte (char upper_ch, char lower_ch) throws Error {
			int8 upper = HEX_CHAR_TO_NIBBLE[upper_ch];
			int8 lower = HEX_CHAR_TO_NIBBLE[lower_ch];
			if (upper == -1 || lower == -1)
				throw new Error.PROTOCOL ("Invalid hex byte");
			return (upper << 4) | lower;
		}

		internal const int8[] HEX_CHAR_TO_NIBBLE = {
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
		};

		internal const char[] NIBBLE_TO_HEX_CHAR = {
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
		};
	}
}

"""


```