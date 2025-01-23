Response:
### 功能归纳

`gdb.vala` 文件是 Frida 动态插桩工具中用于与 GDB（GNU 调试器）进行通信的核心模块。它实现了一个 GDB 客户端，能够与 GDB 服务器进行交互，执行调试操作，并处理调试过程中的各种事件。以下是该文件的主要功能归纳：

1. **GDB 客户端实现**：
   - 该文件实现了一个 GDB 客户端，能够通过 `IOStream` 与 GDB 服务器进行通信。
   - 支持异步操作，允许在调试过程中执行非阻塞的 I/O 操作。

2. **调试状态管理**：
   - 管理调试器的状态（如 `STOPPED`, `RUNNING`, `STOPPING`, `CLOSED`），并根据状态变化触发相应的事件。
   - 支持断点、单步执行、继续执行等调试操作。

3. **断点管理**：
   - 支持添加、启用、禁用断点，并处理断点触发时的异常。
   - 通过 `Breakpoint` 类管理断点的生命周期，并在断点触发时通知客户端。

4. **内存读写操作**：
   - 提供对目标进程内存的读写操作，支持读取和写入字节数组、指针、布尔值等数据类型。
   - 支持分块读取和写入大块内存数据，以适应 GDB 协议的限制。

5. **寄存器操作**：
   - 支持读取和写入目标进程的寄存器。
   - 通过 `Register` 类管理寄存器的信息，并提供按名称或索引访问寄存器的功能。

6. **GDB 协议处理**：
   - 实现 GDB 协议的解析和封装，处理 GDB 服务器发送的响应和通知。
   - 支持处理 GDB 协议中的各种通知类型，如退出状态、停止信号、输出等。

7. **多线程支持**：
   - 支持对多线程程序的调试，能够继续执行特定线程或单步执行特定线程。

8. **错误处理**：
   - 提供详细的错误处理机制，能够捕获并处理调试过程中出现的异常和错误。

### 二进制底层与 Linux 内核相关功能

1. **内存读写**：
   - 通过 GDB 协议，`gdb.vala` 能够直接读取和写入目标进程的内存。这在调试过程中非常有用，尤其是在分析二进制文件或进行逆向工程时。
   - 例如，`read_byte_array` 和 `write_byte_array` 方法允许用户读取和写入目标进程的任意内存地址。

2. **寄存器操作**：
   - 通过 `read_register` 和 `write_register` 方法，用户可以读取和修改目标进程的寄存器状态。这在分析程序执行流程、调试崩溃或异常时非常有用。

3. **断点管理**：
   - 断点是调试器的核心功能之一。`gdb.vala` 支持在指定内存地址设置断点，并在断点触发时暂停目标进程的执行。
   - 例如，`add_breakpoint` 方法允许用户在指定地址设置断点，并在断点触发时捕获异常。

### LLDB 指令或 LLDB Python 脚本示例

假设我们想要使用 LLDB 来复刻 `gdb.vala` 中的内存读取功能，以下是一个 LLDB Python 脚本示例：

```python
import lldb

def read_memory(process, address, size):
    error = lldb.SBError()
    memory = process.ReadMemory(address, size, error)
    if error.Success():
        return memory
    else:
        print(f"Failed to read memory: {error}")
        return None

def main():
    debugger = lldb.SBDebugger.Create()
    target = debugger.CreateTarget("path_to_your_binary")
    if not target:
        print("Failed to create target")
        return

    process = target.LaunchSimple(None, None, os.getcwd())
    if not process:
        print("Failed to launch process")
        return

    address = 0x1000000  # 替换为你想要读取的内存地址
    size = 16  # 读取的字节数
    memory = read_memory(process, address, size)
    if memory:
        print(f"Memory at 0x{address:x}: {memory.hex()}")

if __name__ == "__main__":
    main()
```

### 假设输入与输出

假设我们有一个目标进程，其内存地址 `0x1000000` 处存储了以下数据：`0x01 0x02 0x03 0x04`。

- **输入**：读取地址 `0x1000000` 处的 4 个字节。
- **输出**：`0x01 0x02 0x03 0x04`。

### 用户常见错误

1. **未正确设置断点**：
   - 用户可能会在错误的地址设置断点，导致断点无法触发或触发在错误的位置。
   - 例如，用户可能在未加载的库中设置断点，导致断点无效。

2. **内存访问越界**：
   - 用户可能会尝试读取或写入无效的内存地址，导致调试器崩溃或目标进程崩溃。
   - 例如，用户可能会尝试读取未分配的内存区域，导致访问冲突。

3. **未正确处理调试器状态**：
   - 用户可能会在调试器未停止时尝试执行某些操作（如读取寄存器或内存），导致操作失败。
   - 例如，用户可能会在目标进程运行时尝试读取寄存器，导致操作失败。

### 用户操作如何一步步到达这里

1. **启动调试器**：
   - 用户启动 Frida 并连接到目标进程。
   - Frida 通过 `gdb.vala` 与 GDB 服务器建立连接。

2. **设置断点**：
   - 用户通过 Frida 的 API 在目标进程的某个地址设置断点。
   - `gdb.vala` 通过 GDB 协议向 GDB 服务器发送断点设置请求。

3. **目标进程触发断点**：
   - 目标进程执行到断点地址时，GDB 服务器通知 `gdb.vala`。
   - `gdb.vala` 处理断点触发事件，并通知用户。

4. **读取内存或寄存器**：
   - 用户在断点触发后，通过 Frida 的 API 读取目标进程的内存或寄存器。
   - `gdb.vala` 通过 GDB 协议向 GDB 服务器发送内存或寄存器读取请求，并将结果返回给用户。

5. **继续执行**：
   - 用户在分析完断点处的状态后，继续执行目标进程。
   - `gdb.vala` 通过 GDB 协议向 GDB 服务器发送继续执行请求。

通过以上步骤，用户可以逐步调试目标进程，并分析其执行状态。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/gdb.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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