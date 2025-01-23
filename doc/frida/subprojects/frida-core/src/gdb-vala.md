Response:
### 功能归纳

`frida-core/src/gdb.vala` 文件是 Frida 动态插桩工具中与 GDB（GNU 调试器）协议交互的核心模块。它实现了一个 GDB 客户端，用于与目标进程进行调试交互。以下是该文件的主要功能：

1. **GDB 协议通信**：
   - 实现了 GDB 协议的客户端，支持与目标进程的通信。
   - 处理 GDB 协议的报文（packet）格式，包括报文的构建、发送、接收和解析。
   - 支持 GDB 协议的 ACK/NACK 机制，确保通信的可靠性。

2. **调试控制**：
   - 提供了对目标进程的调试控制功能，如继续执行（`continue`）、单步执行（`step`）、停止（`stop`）、重启（`restart`）等。
   - 支持多线程调试，可以针对特定线程执行调试操作。

3. **内存读写**：
   - 提供了对目标进程内存的读写功能，支持读取和写入字节数组、指针、布尔值等数据类型。
   - 支持分段读取和写入大块内存数据，以适应 GDB 协议的最大报文大小限制。

4. **断点管理**：
   - 支持在目标进程中设置和删除断点（`breakpoint`）。
   - 断点触发时，能够捕获异常并处理断点相关的调试信息。

5. **寄存器操作**：
   - 支持读取和写入目标进程的寄存器。
   - 根据目标架构（如 x86、ARM 等）自动推断寄存器的大小和字节序。

6. **异常处理**：
   - 捕获目标进程的异常（如断点触发、信号等），并生成相应的异常对象。
   - 支持在异常发生时暂停目标进程，并允许用户继续执行或单步调试。

7. **目标进程信息获取**：
   - 获取目标进程的架构信息（如 x86、ARM 等）。
   - 获取目标进程的寄存器列表及其属性。

8. **异步操作**：
   - 使用 GLib 的异步机制（`async`/`yield`）实现非阻塞的调试操作。
   - 支持通过 `Cancellable` 取消正在进行的调试操作。

9. **扩展功能**：
   - 支持 GDB 协议的扩展功能，如 `QStartNoAckMode`（无 ACK 模式）和 `qEcho`（回显功能）。
   - 支持特定厂商的扩展功能，如 Corellium 和 QEMU 的特殊内存模式。

### 二进制底层与 Linux 内核相关功能

1. **内存读写**：
   - 通过 GDB 协议直接读写目标进程的内存，适用于调试内核模块或用户空间程序。
   - 例如，读取目标进程的某个内存地址的内容：
     ```vala
     var bytes = yield client.read_byte_array(0x7ffffee000, 16);
     ```

2. **寄存器操作**：
   - 支持读取和写入目标进程的寄存器，适用于调试内核或用户空间程序。
   - 例如，读取目标进程的 `rip` 寄存器（x86_64 架构）：
     ```vala
     uint64 rip = yield thread.read_register("rip");
     ```

3. **断点管理**：
   - 在目标进程的特定地址设置断点，适用于调试内核或用户空间程序。
   - 例如，在地址 `0x7ffffee000` 设置断点：
     ```vala
     var breakpoint = yield client.add_breakpoint(Breakpoint.Kind.SOFTWARE, 0x7ffffee000, 1);
     ```

### LLDB 指令或 LLDB Python 脚本示例

假设你想用 LLDB 实现类似的内存读取功能，可以使用以下 LLDB Python 脚本：

```python
import lldb

def read_memory(process, address, size):
    error = lldb.SBError()
    memory = process.ReadMemory(address, size, error)
    if error.Success():
        return memory
    else:
        raise Exception(f"Failed to read memory: {error}")

# 示例：读取目标进程的 0x7ffffee000 地址的 16 字节内容
target = lldb.debugger.GetSelectedTarget()
process = target.GetProcess()
memory = read_memory(process, 0x7ffffee000, 16)
print(memory)
```

### 假设输入与输出

1. **输入**：读取目标进程的内存地址 `0x7ffffee000`，长度为 16 字节。
   - **输出**：返回该地址的 16 字节内容，如 `b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"`。

2. **输入**：在目标进程的 `0x7ffffee000` 地址设置断点。
   - **输出**：断点设置成功，目标进程在该地址暂停执行。

### 用户常见使用错误

1. **未正确初始化 GDB 客户端**：
   - 用户可能忘记调用 `Client.open` 方法初始化 GDB 客户端，导致后续操作失败。
   - 示例错误：`Error: Unable to perform query; connection is closed`。

2. **未处理异步操作的结果**：
   - 用户可能忘记使用 `yield` 或 `await` 等待异步操作完成，导致程序逻辑错误。
   - 示例错误：`Error: Invalid operation when not STOPPED`。

3. **内存地址无效**：
   - 用户可能尝试读取或写入无效的内存地址，导致调试失败。
   - 示例错误：`Error: Unable to read from 0x7ffffee000: invalid address`。

### 用户操作步骤

1. **初始化 GDB 客户端**：
   - 用户通过 `Client.open` 方法初始化 GDB 客户端，连接到目标进程。

2. **设置断点**：
   - 用户在目标进程的特定地址设置断点，等待断点触发。

3. **捕获异常**：
   - 断点触发时，GDB 客户端捕获异常并暂停目标进程。

4. **读取内存或寄存器**：
   - 用户在暂停状态下读取目标进程的内存或寄存器内容。

5. **继续执行**：
   - 用户继续执行目标进程，直到下一个断点或程序结束。

### 调试线索

1. **断点触发**：
   - 当目标进程执行到断点地址时，GDB 客户端会捕获 `SIGTRAP` 信号，并暂停目标进程。

2. **内存读取**：
   - 用户通过 `read_byte_array` 方法读取目标进程的内存内容，调试器会返回该地址的数据。

3. **寄存器读取**：
   - 用户通过 `read_register` 方法读取目标进程的寄存器内容，调试器会返回寄存器的值。

### 总结

`frida-core/src/gdb.vala` 文件实现了 Frida 工具中与 GDB 协议交互的核心功能，支持对目标进程的调试控制、内存读写、断点管理、寄存器操作等。通过该模块，用户可以方便地进行动态插桩和调试操作。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/gdb.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
[CCode (gir_namespace = "FridaGDB", gir_version = "1.0")]
namespace Frida.GDB {
	public class Client : Object, AsyncInitable {
		public signal void closed ();
		public signal void console_output (Bytes bytes);

		public IOStream stream {
			get;
			construct;
		}

		public TargetArch arch {
			get;
			set;
			default = UNKNOWN;
		}

		public uint pointer_size {
			get;
			set;
			default = (uint) sizeof (void *);
		}

		public ByteOrder byte_order {
			get;
			set;
			default = HOST;
		}

		public State state {
			get {
				return _state;
			}
		}

		public Exception? exception {
			get {
				return _exception;
			}
		}

		public Gee.Set<string> features {
			get {
				return supported_features;
			}
		}

		private DataInputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		private State _state = STOPPED;
		private Exception? _exception;
		private Exception? breakpoint_exception;
		private Gee.List<StopObserverEntry> on_stop = new Gee.ArrayList<StopObserverEntry> ();
		private size_t max_packet_size = 1024;
		private AckMode ack_mode = SEND_ACKS;
		private Gee.Queue<Bytes> pending_writes = new Gee.ArrayQueue<Bytes> ();
		private Promise<uint>? write_request;
		private Gee.Queue<PendingResponse> pending_responses = new Gee.ArrayQueue<PendingResponse> ();

		protected Gee.Set<string> supported_features = new Gee.HashSet<string> ();
		protected Gee.List<Register>? registers;
		protected Gee.Map<string, Register>? register_by_name;
		protected Gee.Map<uint64?, Breakpoint> breakpoints = new Gee.HashMap<uint64?, Breakpoint> (
			(n) => { return int64_hash ((int64?) n); },
			(a, b) => { return int64_equal ((int64?) a, (int64?) b); }
		);

		public enum State {
			STOPPED,
			RUNNING,
			STOPPING,
			CLOSED;

			public string to_nick () {
				return Marshal.enum_to_nick<State> (this);
			}
		}

		private enum MessageHandling {
			SEND_ACKS,
			SKIP_ACKS
		}

		private enum AckMode {
			SEND_ACKS,
			SKIP_ACKS
		}

		public enum ChecksumType {
			PROPER,
			ZEROED
		}

		protected const char NOTIFICATION_TYPE_EXIT_STATUS = 'W';
		protected const char NOTIFICATION_TYPE_EXIT_SIGNAL = 'X';
		protected const char NOTIFICATION_TYPE_STOP = 'S';
		protected const char NOTIFICATION_TYPE_STOP_WITH_PROPERTIES = 'T';
		protected const char NOTIFICATION_TYPE_OUTPUT = 'O';

		private const char STOP_CHARACTER = 0x03;
		private const string ACK_NOTIFICATION = "+";
		private const string NACK_NOTIFICATION = "-";
		private const string PACKET_MARKER = "$";
		private const char PACKET_CHARACTER = '$';
		private const string CHECKSUM_MARKER = "#";
		private const char CHECKSUM_CHARACTER = '#';
		private const char ESCAPE_CHARACTER = '}';
		private const uint8 ESCAPE_KEY = 0x20;
		private const char REPEAT_CHARACTER = '*';
		private const uint8 REPEAT_BASE = 0x20;
		private const uint8 REPEAT_BIAS = 3;

		private enum UnixSignal {
			SIGTRAP = 5,
		}

		private Client (IOStream stream) {
			Object (stream: stream);
		}

		public static async Client open (IOStream stream, Cancellable? cancellable = null)
				throws Error, IOError {
			var client = new Client (stream);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return client;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			try {
				input = new DataInputStream (stream.get_input_stream ());
				output = stream.get_output_stream ();

				process_incoming_packets.begin ();
				write_string (ACK_NOTIFICATION);

				string supported_response = yield query_property ("Supported", cancellable);
				supported_features.add_all_array (supported_response.split (";"));

				foreach (string feature in supported_features) {
					if (feature.has_prefix ("PacketSize=")) {
						max_packet_size = (size_t) uint64.parse (feature[11:], 16);
						break;
					}
				}

				if ("QStartNoAckMode+" in supported_features || "qEcho+" in supported_features) {
					yield execute_simple ("QStartNoAckMode", cancellable);
					ack_mode = SKIP_ACKS;
				}

				yield detect_vendor_features (cancellable);

				yield enable_extensions (cancellable);

				string attached_response = yield query_property ("Attached", cancellable);
				if (attached_response == "1") {
					yield load_target_properties (cancellable);
					if (_exception == null) {
						request_stop_info ();
						yield wait_until_stopped (cancellable);
					}
				}
			} catch (GLib.Error e) {
				io_cancellable.cancel ();

				throw new Error.PROTOCOL ("%s", e.message);
			}

			return true;
		}

		protected virtual async void detect_vendor_features (Cancellable? cancellable) throws Error, IOError {
			try {
				string info = yield run_remote_command ("info", cancellable);
				if ("Corellium" in info)
					supported_features.add ("corellium");
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
			}

			try {
				string response = yield query_property ("qemu.PhyMemMode", cancellable);
				if (response.length == 1)
					supported_features.add ("qemu-phy-mem-mode");
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
			}
		}

		protected virtual async void enable_extensions (Cancellable? cancellable) throws Error, IOError {
		}

		private void change_state (State new_state, Exception? new_exception = null) {
			bool state_differs = new_state != _state;
			if (state_differs)
				_state = new_state;

			bool exception_differs = new_exception != _exception;
			if (exception_differs)
				_exception = new_exception;

			if (state_differs)
				notify_property ("state");

			if (exception_differs)
				notify_property ("exception");
		}

		private void clear_current_exception () {
			if (_exception == null)
				return;

			_exception = null;
			notify_property ("exception");
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			if (state == CLOSED)
				return;

			io_cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (close.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield stream.close_async (Priority.DEFAULT, cancellable);
			} catch (IOError e) {
			}
		}

		public async void continue (Cancellable? cancellable = null) throws Error, IOError {
			check_stopped ();

			var exception = breakpoint_exception;
			if (exception != null) {
				breakpoint_exception = null;

				var breakpoint = exception.breakpoint;
				yield breakpoint.disable (cancellable);
				yield exception.thread.step (cancellable);
				yield breakpoint.enable (cancellable);

				check_stopped ();
			}

			change_state (RUNNING);

			var command = make_packet_builder_sized (1)
				.append_c ('c')
				.build ();
			write_bytes (command);
		}

		public async void continue_specific_threads (Gee.Iterable<Thread> threads, Cancellable? cancellable = null)
				throws Error, IOError {
			check_stopped ();

			change_state (RUNNING);

			var command = make_packet_builder_sized (1)
				.append ("vCont");
			foreach (var thread in threads) {
				command
					.append (";c:")
					.append (thread.id);
			}
			write_bytes (command.build ());
		}

		public async Exception continue_until_exception (Cancellable? cancellable = null) throws Error, IOError {
			check_stopped ();

			clear_current_exception ();

			if (breakpoint_exception != null)
				yield continue (cancellable);

			if (_exception != null)
				return _exception;

			bool waiting = false;

			var stop_observer = new StopObserverEntry (() => {
				if (waiting)
					continue_until_exception.callback ();
				return false;
			});
			on_stop.add (stop_observer);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				if (waiting)
					continue_until_exception.callback ();
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			try {
				if (state == STOPPED)
					yield continue (cancellable);

				if (state != STOPPED) {
					waiting = true;
					yield;
					waiting = false;
				}
			} finally {
				cancel_source.destroy ();

				on_stop.remove (stop_observer);
			}

			if (_exception == null)
				throw new Error.TRANSPORT ("Connection closed while waiting for exception");

			return _exception;
		}

		public async void stop (Cancellable? cancellable = null) throws Error, IOError {
			if (state == STOPPED)
				return;

			if (state == CLOSED)
				throw new Error.INVALID_OPERATION ("Unable to stop; connection is closed");

			if (state == RUNNING) {
				change_state (STOPPING);

				write_bytes (new Bytes ({ STOP_CHARACTER }));
			}

			yield wait_until_stopped (cancellable);
		}

		private async void wait_until_stopped (Cancellable? cancellable) throws Error, IOError {
			var stop_observer = new StopObserverEntry (() => {
				wait_until_stopped.callback ();
				return false;
			});
			on_stop.add (stop_observer);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				wait_until_stopped.callback ();
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			yield;

			cancel_source.destroy ();

			on_stop.remove (stop_observer);

			if (state == CLOSED)
				throw new Error.TRANSPORT ("Connection closed while waiting for target to stop");
		}

		public async void detach (Cancellable? cancellable = null) throws Error, IOError {
			yield stop (cancellable);

			yield execute_simple ("D", cancellable);
		}

		public void restart () throws Error {
			check_stopped ();

			var command = make_packet_builder_sized (5)
				.append ("R")
				.build ();
			write_bytes (command);
		}

		public async void kill (Cancellable? cancellable = null) throws Error, IOError {
			yield stop (cancellable);

			var kill_response = yield query_simple ("k", cancellable);
			if (kill_response.payload != "X09")
				throw new Error.INVALID_OPERATION ("Unable to kill existing process");

			change_state (STOPPING);
		}

		public async void _step_thread (Thread thread, Cancellable? cancellable) throws Error, IOError {
			check_stopped ();

			change_state (RUNNING);

			var command = make_packet_builder_sized (16)
				.append ("vCont;s:")
				.append (thread.id)
				.build ();
			write_bytes (command);

			yield wait_until_stopped (cancellable);
		}

		public void _step_thread_and_continue (Thread thread) throws Error {
			check_stopped ();

			change_state (RUNNING);

			var command = make_packet_builder_sized (16)
				.append ("vCont;s:")
				.append (thread.id)
				.append (";c")
				.build ();
			write_bytes (command);
		}

		public virtual async Bytes read_byte_array (uint64 address, size_t size, Cancellable? cancellable = null)
				throws Error, IOError {
			var result = new uint8[size];

			size_t offset = 0;
			size_t max_bytes_per_packet = (max_packet_size - Packet.OVERHEAD) / 2;
			do {
				size_t chunk_size = size_t.min (size - offset, max_bytes_per_packet);

				var request = make_packet_builder_sized (16)
					.append_c ('m')
					.append_address (address + offset)
					.append_c (',')
					.append_size (chunk_size)
					.build ();
				var response = yield query (request, cancellable);

				Bytes chunk = Protocol.parse_hex_bytes (response.payload);
				if (chunk.get_size () != chunk_size) {
					throw new Error.INVALID_ARGUMENT (
						"Unable to read from 0x%" + uint64.FORMAT_MODIFIER + "x: invalid address", address);
				}

				Memory.copy ((uint8 *) result + offset, chunk.get_data (), chunk_size);

				offset += chunk_size;
			} while (offset != size);

			return new Bytes.take ((owned) result);
		}

		public async void write_byte_array (uint64 address, Bytes bytes, Cancellable? cancellable = null)
				throws Error, IOError {
			size_t max_bytes_per_packet = (max_packet_size - 1 - 16 - 1 - 8 - 1 - Packet.OVERHEAD) / 2;

			var data = bytes.get_data ();
			size_t offset = 0;
			size_t remaining = bytes.length;

			var builder = make_packet_builder_sized (32 + (remaining * 2));

			while (remaining != 0) {
				uint64 slice_address = address + offset;
				size_t slice_size = size_t.min (remaining, max_bytes_per_packet);

				builder
					.append_c ('M')
					.append_address (slice_address)
					.append_c (',')
					.append_size (slice_size)
					.append_c (':');

				for (size_t i = 0; i != slice_size; i++) {
					uint8 byte = data[offset + i];
					builder.append_hexbyte (byte);
				}

				yield execute (builder.build (), cancellable);

				builder.reset ();

				offset += slice_size;
				remaining -= slice_size;
			}
		}

		public async uint64 read_pointer (uint64 address, Cancellable? cancellable = null) throws Error, IOError {
			var buffer = yield read_buffer (address, pointer_size, cancellable);
			return buffer.read_pointer (0);
		}

		public async void write_pointer (uint64 address, uint64 val, Cancellable? cancellable = null) throws Error, IOError {
			var buffer = make_buffer_builder ()
				.append_pointer (val)
				.build ();
			yield write_byte_array (address, buffer, cancellable);
		}

		public async bool read_bool (uint64 address, Cancellable? cancellable = null) throws Error, IOError {
			var data = yield read_byte_array (address, 1);
			return data.get (0) != 0 ? true : false;
		}

		public async void write_bool (uint64 address, bool val, Cancellable? cancellable = null) throws Error, IOError {
			yield write_byte_array (address, new Bytes ({ val ? 1 : 0 }), cancellable);
		}

		public BufferBuilder make_buffer_builder () {
			return new BufferBuilder (byte_order, pointer_size);
		}

		public Buffer make_buffer (Bytes bytes) {
			return new Buffer (bytes, byte_order, pointer_size);
		}

		public async Buffer read_buffer (uint64 address, size_t size, Cancellable? cancellable = null) throws Error, IOError {
			var bytes = yield read_byte_array (address, size, cancellable);
			return make_buffer (bytes);
		}

		public async Breakpoint add_breakpoint (Breakpoint.Kind kind, uint64 address, size_t size, Cancellable? cancellable = null)
				throws Error, IOError {
			check_stopped ();

			var breakpoint = new Breakpoint (kind, address, size, this);
			yield breakpoint.enable (cancellable);
			breakpoints[address] = breakpoint;

			breakpoint.removed.connect (on_breakpoint_removed);

			return breakpoint;
		}

		private void on_breakpoint_removed (Breakpoint breakpoint) {
			breakpoints.unset (breakpoint.address);

			var exception = breakpoint_exception;
			if (exception != null && exception.breakpoint == breakpoint)
				breakpoint_exception = null;
		}

		public async string run_remote_command (string command, Cancellable? cancellable = null) throws Error, IOError {
			int n = command.length;
			var builder = make_packet_builder_sized (10 + (n * 2))
				.append ("qRcmd,");
			for (int i = 0; i != n; i++)
				builder.append_hexbyte (command[i]);

			var output = new Gee.ArrayList<Packet> ();
			Packet response = yield query_with_predicate (builder.build (), packet => {
				unowned string payload = packet.payload;
				if (payload.has_prefix ("OK") || payload[0] == 'E')
					return COMPLETE;
				if (payload[0] == NOTIFICATION_TYPE_OUTPUT) {
					output.add (packet);
					return ABSORB;
				}
				return KEEP_TRYING;
			}, cancellable);
			check_execute_response (response);

			var result = new StringBuilder ();
			foreach (Packet p in output)
				result.append (Protocol.parse_hex_encoded_utf8_string (p.payload[1:]));
			return result.str;
		}

		protected async void load_target_properties (Cancellable? cancellable = null) throws Error, IOError {
			TargetSpec spec = yield query_target_spec (cancellable);

			arch = spec.arch;
			pointer_size = infer_pointer_size_from_arch (spec.arch);
			byte_order = infer_byte_order_from_arch (spec.arch);

			registers = spec.registers;

			register_by_name = new Gee.HashMap<string, Register> ();
			foreach (var reg in registers) {
				register_by_name[reg.name] = reg;
				string? altname = reg.altname;
				if (altname != null)
					register_by_name[altname] = reg;
			}
		}

		protected void request_stop_info () {
			var command = make_packet_builder_sized (5)
				.append_c ('?')
				.build ();
			write_bytes (command);
		}

		private async TargetSpec query_target_spec (Cancellable? cancellable) throws Error, IOError {
			uint next_regnum = 0;
			FeatureDocument? target = null;
			try {
				target = yield fetch_feature_document ("target.xml", next_regnum, cancellable);
			} catch (Error e) {
				if (e is Error.NOT_SUPPORTED)
					return new TargetSpec (UNKNOWN, new Gee.ArrayList<Register> ());
				throw e;
			}
			next_regnum = target.next_regnum;

			var pending = new Gee.ArrayQueue<string> ();
			var processed = new Gee.HashSet<string> ();

			pending.add_all (target.includes);

			string? href;
			while ((href = pending.poll ()) != null) {
				if (href in processed)
					continue;

				FeatureDocument child = yield fetch_feature_document (href, next_regnum, cancellable);
				next_regnum = child.next_regnum;
				target.registers.add_all (child.registers);

				pending.add_all (child.includes);
				processed.add (href);
			}

			target.registers.sort ((reg_a, reg_b) => {
				uint a = reg_a.id;
				uint b = reg_b.id;
				if (a < b)
					return -1;
				if (a > b)
					return 1;
				return 0;
			});

			return new TargetSpec (target.arch, target.registers);
		}

		private async FeatureDocument fetch_feature_document (string name, uint next_regnum, Cancellable? cancellable)
				throws Error, IOError {
			var xml = new StringBuilder.sized (4096);

			uint offset = 0;
			char status = 'l';
			do {
				var response = yield query_simple ("qXfer:features:read:%s:%x,1ffff".printf (name, offset), cancellable);

				string payload = response.payload;
				if (payload.length == 0)
					throw new Error.NOT_SUPPORTED ("Feature query not supported by the remote stub");
				if (payload[0] == 'E')
					throw new Error.INVALID_ARGUMENT ("Feature document '%s' not found", name);

				status = payload[0];

				string * chunk = (string *) payload + 1;
				xml.append (chunk);
				offset += chunk->length;
			} while (status == 'm');

			return FeatureDocument.from_xml (xml.str, next_regnum);
		}

		private static uint infer_pointer_size_from_arch (TargetArch arch) {
			switch (arch) {
				case UNKNOWN:
					return (uint) sizeof (void *);
				case IA32:
				case ARM:
				case MIPS:
					return 4;
				case X64:
				case ARM64:
					return 8;
			}

			assert_not_reached ();
		}

		private static ByteOrder infer_byte_order_from_arch (TargetArch arch) {
			switch (arch) {
				case UNKNOWN:
					return HOST;
				case IA32:
				case X64:
				case ARM:
				case ARM64:
					return LITTLE_ENDIAN;
				case MIPS:
					return BIG_ENDIAN;
			}

			assert_not_reached ();
		}

		internal Gee.List<Register>? get_registers () {
			return registers;
		}

		internal Register get_register_by_name (string name) throws Error {
			Register? reg = register_by_name[name];
			if (reg == null)
				throw new Error.INVALID_ARGUMENT ("Invalid register name: %s", name);
			return reg;
		}

		internal Register get_register_by_index (uint index) throws Error {
			if (index >= registers.size)
				throw new Error.INVALID_ARGUMENT ("Invalid register index: %u", index);
			return registers[(int) index];
		}

		private void check_stopped () throws Error {
			if (state != STOPPED) {
				throw new Error.INVALID_OPERATION ("Invalid operation when not STOPPED, current state is %s",
					state.to_nick ().up ());
			}
		}

		public async void execute_simple (string command, Cancellable? cancellable) throws Error, IOError {
			var raw_command = make_packet_builder_sized (command.length + 15 & (size_t) ~15)
				.append (command)
				.build ();
			yield execute (raw_command, cancellable);
		}

		public async void execute (Bytes command, Cancellable? cancellable) throws Error, IOError {
			Packet response = yield query (command, cancellable);
			check_execute_response (response);
		}

		private static void check_execute_response (Packet packet) throws Error {
			unowned string response = packet.payload;
			if (response[0] == 'E') {
				string reason = response[1:response.length];
				if (reason == "Locked")
					throw new Error.INVALID_OPERATION ("Device is locked");
				else
					throw new Error.NOT_SUPPORTED ("%s", reason);
			}

			if (response != "OK")
				throw new Error.PROTOCOL ("Unexpected response: %s", response);
		}

		public async Packet query_simple (string request, Cancellable? cancellable) throws Error, IOError {
			var raw_request = make_packet_builder_sized (request.length + 15 & (size_t) ~15)
				.append (request)
				.build ();
			return yield query (raw_request, cancellable);
		}

		public async string query_property (string name, Cancellable? cancellable) throws Error, IOError {
			Packet response = yield query_simple ("q" + name, cancellable);

			unowned string val = response.payload;
			string ack = "q%s:".printf (name);
			if (val.has_prefix (ack))
				return val[ack.length:];
			return val;
		}

		public async Packet query (Bytes request, Cancellable? cancellable) throws Error, IOError {
			return yield query_with_predicate (request, null, cancellable);
		}

		public async Packet query_with_predicate (Bytes request, owned ResponsePredicate? predicate, Cancellable? cancellable)
				throws Error, IOError {
			if (state == CLOSED)
				throw new Error.INVALID_OPERATION ("Unable to perform query; connection is closed");

			var pending = new PendingResponse ((owned) predicate, query_with_predicate.callback);
			pending_responses.offer (pending);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				pending.complete_with_error (new IOError.CANCELLED ("Operation was cancelled"));
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			write_bytes (request);

			yield;

			cancel_source.destroy ();

			cancellable.set_error_if_cancelled ();

			var response = pending.response;
			if (response == null)
				throw_api_error (pending.error);

			return response;
		}

		private async void process_incoming_packets () {
			while (true) {
				try {
					var packet = yield read_packet ();

					dispatch_packet (packet);
				} catch (GLib.Error error) {
					change_state (CLOSED);

					foreach (var pending_response in pending_responses)
						pending_response.complete_with_error (error);
					pending_responses.clear ();

					foreach (var observer in on_stop.to_array ())
						observer.func ();

					closed ();

					return;
				}
			}
		}

		private async void process_pending_writes () {
			write_request = new Promise<uint> ();
			size_t total_bytes_written = 0;
			try {
				while (!pending_writes.is_empty) {
					Bytes current = pending_writes.peek ();

					size_t bytes_written;
					try {
						yield output.write_all_async (current.get_data (), Priority.DEFAULT, io_cancellable,
							out bytes_written);
						total_bytes_written += bytes_written;
					} catch (GLib.Error e) {
						return;
					}

					pending_writes.poll ();
				}
			} finally {
				write_request.resolve ((uint) total_bytes_written);
				write_request = null;
			}
		}

		private void dispatch_packet (Packet packet) throws Error {
			if (try_handle_specific_response (packet))
				return;

			if (try_handle_notification (packet))
				return;

			handle_wildcard_response (packet);
		}

		private bool try_handle_specific_response (Packet packet) throws Error {
			ResponseAction action = KEEP_TRYING;
			PendingResponse? pr = pending_responses.first_match (pr => {
				if (pr.predicate == null)
					return false;
				action = pr.predicate (packet);
				return action != KEEP_TRYING;
			});
			if (pr == null)
				return false;

			if (action == ABSORB)
				return true;

			pending_responses.remove (pr);

			pr.complete_with_response (packet);
			return true;
		}

		private void handle_wildcard_response (Packet response) throws Error {
			PendingResponse? pr = pending_responses.first_match (pr => pr.predicate == null);
			if (pr == null)
				throw new Error.PROTOCOL ("Unexpected response");
			pending_responses.remove (pr);

			pr.complete_with_response (response);
		}

		protected bool try_handle_notification (Packet packet) throws Error {
			if (state == CLOSED)
				throw new Error.INVALID_OPERATION ("Unable to handle notification; connection is closed");

			unowned string payload = packet.payload;
			if (payload == "OK")
				return false;

			unowned string data = (string) ((char *) payload + 1);
			switch (payload[0]) {
				case NOTIFICATION_TYPE_EXIT_STATUS:
				case NOTIFICATION_TYPE_EXIT_SIGNAL:
					handle_exit (data);
					return true;
				case NOTIFICATION_TYPE_STOP:
				case NOTIFICATION_TYPE_STOP_WITH_PROPERTIES:
					handle_stop.begin (data);
					return true;
				case NOTIFICATION_TYPE_OUTPUT:
					handle_output (data);
					return true;
				default:
					return false;
			}
		}

		private void handle_exit (string data) throws Error {
			change_state (STOPPED);
			foreach (var observer in on_stop.to_array ())
				observer.func ();
		}

		private async void handle_stop (string data) throws Error, IOError {
			if (data.length < 2)
				throw new Error.PROTOCOL ("Invalid stop packet");

			uint64 raw_signum;
			try {
				uint64.from_string (data[0:2], out raw_signum, 16);
			} catch (NumberParserError e) {
				throw new Error.PROTOCOL ("Invalid stop packet: %s", e.message);
			}
			var signum = (uint) raw_signum;

			unowned string rest = (string) ((char *) data + 2);
			var properties = PropertyDictionary.parse (rest);

			Exception exception;
			Breakpoint? breakpoint;
			yield parse_stop (signum, properties, out exception, out breakpoint);

			breakpoint_exception = (breakpoint != null) ? exception : null;
			change_state (STOPPED, exception);
			foreach (var observer in on_stop.to_array ())
				observer.func ();
		}

		protected virtual async void parse_stop (uint signum, PropertyDictionary properties, out Exception exception,
				out Breakpoint? breakpoint) throws Error, IOError {
			string thread_id;
			if (properties.has ("thread")) {
				thread_id = properties.get_string ("thread");
			} else {
				Packet thread_id_response = yield query_simple ("qC", io_cancellable);
				unowned string payload = thread_id_response.payload;
				if (payload.length < 3)
					throw new Error.PROTOCOL ("Invalid thread ID response");
				thread_id = payload[2:];
			}

			string? name = null;
			Packet info_response = yield query_simple ("qThreadExtraInfo," + thread_id, io_cancellable);
			unowned string payload = info_response.payload;
			if (payload.length > 0)
				name = Protocol.parse_hex_encoded_utf8_string (payload);

			Thread thread = new Thread (thread_id, name, this);

			if (signum == UnixSignal.SIGTRAP) {
				string pc_reg_name;
				switch (arch) {
					case IA32:
						pc_reg_name = "eip";
						break;
					case X64:
						pc_reg_name = "rip";
						break;
					default:
						pc_reg_name = "pc";
						break;
				}
				uint64 pc = yield thread.read_register (pc_reg_name, io_cancellable);

				breakpoint = breakpoints[pc];
			} else {
				breakpoint = null;
			}

			exception = new Exception (signum, breakpoint, thread);
		}

		private void handle_output (string hex_bytes) throws Error {
			var bytes = Protocol.parse_hex_bytes (hex_bytes);
			console_output (bytes);
		}

		public PacketBuilder make_packet_builder_sized (size_t capacity) {
			var checksum_type = (ack_mode == SEND_ACKS) ? ChecksumType.PROPER : ChecksumType.ZEROED;
			return new PacketBuilder (capacity, checksum_type);
		}

		private async Packet read_packet () throws Error, IOError {
			string? header = null;
			do {
				header = yield read_string (1);
			} while (header == ACK_NOTIFICATION || header == NACK_NOTIFICATION);

			string? body;
			size_t body_size;
			try {
				body = yield input.read_upto_async (CHECKSUM_MARKER, 1, Priority.DEFAULT, io_cancellable, out body_size);
			} catch (IOError e) {
				if (e is IOError.CANCELLED)
					throw e;
				throw new Error.TRANSPORT ("%s", e.message);
			}
			if (body == null)
				body = "";

			string trailer = yield read_string (3);

			var packet = depacketize (header, body, body_size, trailer);

			if (ack_mode == SEND_ACKS) {
				write_string (ACK_NOTIFICATION);
				var req = write_request.future;
				yield req.wait_async (io_cancellable);
			}

			return packet;
		}

		private async string read_string (uint length) throws Error, IOError {
			var buf = new uint8[length + 1];
			buf[length] = 0;

			size_t bytes_read;
			try {
				yield input.read_all_async (buf[0:length], Priority.DEFAULT, io_cancellable, out bytes_read);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
				throw new Error.TRANSPORT ("%s", e.message);
			}

			if (bytes_read == 0)
				throw new Error.TRANSPORT ("Connection closed");

			return (string) buf;
		}

		private void write_string (string str) {
			unowned uint8[] buf = (uint8[]) str;
			write_bytes (new Bytes (buf[0:str.length]));
		}

		private void write_bytes (Bytes bytes) {
			pending_writes.offer (bytes);
			if (pending_writes.size == 1)
				process_pending_writes.begin ();
		}

		private static Packet depacketize (string header, string data, size_t data_size, string trailer) throws Error {
			var result = new StringBuilder.sized (data_size);

			for (size_t offset = 0; offset != data_size; offset++) {
				char ch = data[(long) offset];
				if (ch == ESCAPE_CHARACTER) {
					if (offset == data_size - 1)
						throw new Error.PROTOCOL ("Invalid packet");
					uint8 escaped_byte = data[(long) (++offset)];
					result.append_c ((char) (escaped_byte ^ ESCAPE_KEY));
				} else if (ch == REPEAT_CHARACTER) {
					if (offset == 0 || offset == data_size - 1)
						throw new Error.PROTOCOL ("Invalid packet");
					char char_to_repeat = data[(long) (offset - 1)];
					uint8 repeat_count = (uint8) data[(long) (++offset)] - REPEAT_BASE + REPEAT_BIAS;
					for (uint8 repeat_index = 0; repeat_index != repeat_count; repeat_index++)
						result.append_c (char_to_repeat);
				} else {
					result.append_c (ch);
				}
			}

			return new Packet.from_bytes (StringBuilder.free_to_bytes ((owned) result));
		}

		private static uint8 compute_checksum (string data, long offset, long length) {
			uint8 sum = 0;

			long end_index = offset + length;
			for (long i = offset; i != end_index; i++)
				sum += (uint8) data[i];

			return sum;
		}

		public class Packet {
			public const size_t OVERHEAD = 1 + 1 + 2;

			public string payload {
				get;
				private set;
			}

			public Bytes payload_bytes {
				get;
				private set;
			}

			public Packet.from_bytes (Bytes payload_bytes) {
				this.payload = (string) payload_bytes.get_data ();
				this.payload_bytes = payload_bytes;
			}
		}

		public class PacketBuilder {
			private StringBuilder? buffer;
			private size_t initial_capacity;
			private ChecksumType checksum_type;

			public PacketBuilder (size_t capacity, ChecksumType checksum_type) {
				this.initial_capacity = capacity + Packet.OVERHEAD;
				this.checksum_type = checksum_type;

				reset ();
			}

			public void reset () {
				if (buffer == null)
					buffer = new StringBuilder.sized (initial_capacity);
				else
					buffer.truncate ();

				buffer.append_c (PACKET_CHARACTER);
			}

			public unowned PacketBuilder append (string val) {
				long length = val.length;
				for (long i = 0; i != length; i++)
					append_c (val[i]);
				return this;
			}

			public unowned PacketBuilder append_c (char c) {
				switch (c) {
					case PACKET_CHARACTER:
					case CHECKSUM_CHARACTER:
					case ESCAPE_CHARACTER:
					case REPEAT_CHARACTER:
						buffer.append_c (ESCAPE_CHARACTER);
						buffer.append_c ((char) ((uint8) c ^ ESCAPE_KEY));
						break;
					default:
						buffer.append_c (c);
						break;
				}
				return this;
			}

			public unowned PacketBuilder append_escaped (string val) {
				buffer.append (val);
				return this;
			}

			public unowned PacketBuilder append_c_escaped (char c) {
				buffer.append_c (c);
				return this;
			}

			public unowned PacketBuilder append_address (uint64 address) {
				buffer.append_printf ("%" + uint64.FORMAT_MODIFIER + "x", address);
				return this;
			}

			public unowned PacketBuilder append_size (size_t size) {
				buffer.append_printf ("%" + size_t.FORMAT_MODIFIER + "x", size);
				return this;
			}

			public unowned PacketBuilder append_uint (uint val) {
				buffer.append_printf ("%u", val);
				return this;
			}

			public unowned PacketBuilder append_process_id (uint process_id) {
				buffer.append_printf ("%x", process_id);
				return this;
			}

			public unowned PacketBuilder append_register_id (uint register_id) {
				buffer.append_
```