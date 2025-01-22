Response:
### 功能归纳

`session.vala` 文件是 Frida 动态插桩工具的核心部分，主要负责会话管理、错误处理、进程信息查询、脚本选项配置等功能。以下是该文件的主要功能归纳：

1. **错误处理**：
   - `throw_api_error` 和 `throw_dbus_error` 函数用于处理 API 和 DBus 相关的错误，并将错误转换为 Frida 自定义的错误类型。
   - 错误类型包括 `PERMISSION_DENIED`、`ADDRESS_IN_USE`、`TIMED_OUT`、`NOT_SUPPORTED`、`PROTOCOL` 和 `TRANSPORT` 等。

2. **进程和应用信息管理**：
   - `HostApplicationInfo` 和 `HostProcessInfo` 结构体用于存储主机上运行的应用程序和进程的信息，包括进程 ID (PID)、名称、标识符等。
   - `FrontmostQueryOptions`、`ApplicationQueryOptions` 和 `ProcessQueryOptions` 类用于配置查询选项，如查询范围 (`scope`) 和选择的进程 ID 或应用标识符。

3. **会话选项配置**：
   - `SessionOptions` 类用于配置会话选项，如会话的持久化超时 (`persist_timeout`)、模拟代理路径 (`emulated_agent_path`) 等。
   - `ScriptOptions` 和 `SnapshotOptions` 类用于配置脚本和快照的选项，如脚本名称、运行时环境 (`runtime`)、快照传输方式 (`snapshot_transport`) 等。

4. **进程生成和子进程管理**：
   - `HostSpawnOptions` 结构体用于配置生成新进程的选项，如命令行参数 (`argv`)、环境变量 (`envp`)、工作目录 (`cwd`) 等。
   - `HostChildInfo` 结构体用于存储子进程的信息，包括子进程的 PID、父进程的 PID、子进程的起源 (`origin`) 等。

5. **崩溃信息管理**：
   - `CrashInfo` 结构体用于存储崩溃信息，包括崩溃的进程 ID、进程名称、崩溃摘要 (`summary`) 和崩溃报告 (`report`) 等。

6. **代理会话和脚本管理**：
   - `AgentSessionId` 和 `AgentScriptId` 结构体用于标识代理会话和脚本。
   - `PortalMembershipId` 结构体用于标识门户成员资格。

7. **网络和通信配置**：
   - `PeerOptions` 类用于配置对等节点的选项，如 STUN 服务器地址、中继服务器 (`relays`) 等。
   - `Relay` 类用于表示中继服务器的配置，包括地址、用户名、密码和中继类型 (`RelayKind`)。

8. **系统参数获取**：
   - `compute_system_parameters` 函数用于获取系统参数，如操作系统类型、平台、架构、主机名等。

### 二进制底层与 Linux 内核相关

1. **进程生成与管理**：
   - `HostSpawnOptions` 结构体中的 `argv` 和 `envp` 参数直接对应于 Linux 系统调用 `execve` 的参数，用于生成新进程。
   - `HostChildInfo` 结构体中的 `origin` 字段表示子进程的生成方式（如 `FORK`、`EXEC`、`SPAWN`），这些方式与 Linux 内核中的进程生成机制相关。

2. **系统参数获取**：
   - `compute_system_parameters` 函数通过读取系统文件（如 `/etc/os-release`）或调用系统 API（如 `_query_windows_version`）来获取操作系统信息。这些操作涉及到底层的系统调用和文件读取。

### LLDB 调试示例

假设我们想要调试 `throw_api_error` 函数，可以使用以下 LLDB 命令或 Python 脚本来设置断点并观察错误处理过程：

#### LLDB 命令示例

```bash
# 启动 LLDB 并附加到目标进程
lldb -p <pid>

# 设置断点
b session.vala:throw_api_error

# 运行程序
run

# 当断点触发时，打印错误信息
po e
```

#### LLDB Python 脚本示例

```python
import lldb

def set_breakpoint(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    breakpoint = target.BreakpointCreateByLocation("session.vala", 123)  # 假设 throw_api_error 在 123 行
    print(f"Breakpoint set at {breakpoint.GetNumLocations()} locations")

# 注册命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_script.set_breakpoint breakpoint_throw_api_error')
```

### 假设输入与输出

1. **错误处理**：
   - 输入：`throw_api_error(new Frida.Error.PERMISSION_DENIED("Permission denied"))`
   - 输出：抛出 `Frida.Error.PERMISSION_DENIED` 异常。

2. **进程信息查询**：
   - 输入：`HostProcessInfo(1234, "example_process", new HashTable<string, Variant>())`
   - 输出：返回一个包含 PID 为 1234、名称为 "example_process" 的进程信息结构体。

### 用户常见错误

1. **错误类型不匹配**：
   - 用户可能会尝试传递错误的错误类型给 `throw_api_error` 或 `throw_dbus_error`，导致断言失败或未处理的异常。
   - 示例：`throw_api_error(new GLib.Error("Invalid error type"))` 会导致断言失败。

2. **进程生成参数错误**：
   - 用户在配置 `HostSpawnOptions` 时，可能会传递无效的命令行参数或环境变量，导致进程生成失败。
   - 示例：`HostSpawnOptions { argv = { "invalid_command" } }` 会导致进程生成失败。

### 用户操作路径

1. **启动 Frida 会话**：
   - 用户通过 Frida CLI 或 API 启动一个会话，配置 `SessionOptions` 和 `ScriptOptions`。

2. **查询进程信息**：
   - 用户使用 `ApplicationQueryOptions` 或 `ProcessQueryOptions` 查询当前运行的进程或应用信息。

3. **生成新进程**：
   - 用户配置 `HostSpawnOptions` 并生成一个新进程，Frida 会通过 `HostChildInfo` 跟踪该进程。

4. **处理错误**：
   - 如果在上述操作中发生错误，Frida 会调用 `throw_api_error` 或 `throw_dbus_error` 处理错误，并抛出相应的异常。

通过这些步骤，用户可以逐步深入到 Frida 的核心功能，并在调试过程中跟踪错误和进程信息。
Prompt: 
```
这是目录为frida/subprojects/frida-core/lib/base/session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共2部分，请归纳一下它的功能

"""
D_OPERATION,
		PERMISSION_DENIED,
		ADDRESS_IN_USE,
		TIMED_OUT,
		NOT_SUPPORTED,
		PROTOCOL,
		TRANSPORT
	}

	[NoReturn]
	public static void throw_api_error (GLib.Error e) throws Frida.Error, IOError {
		if (e is Frida.Error)
			throw (Frida.Error) e;

		if (e is IOError.CANCELLED)
			throw (IOError) e;

		assert_not_reached ();
	}

	[NoReturn]
	public static void throw_dbus_error (GLib.Error e) throws Frida.Error, IOError {
		DBusError.strip_remote_error (e);

		if (e is Frida.Error)
			throw (Frida.Error) e;

		if (e is IOError.CANCELLED)
			throw (IOError) e;

		if (e is DBusError.UNKNOWN_METHOD) {
			throw new Frida.Error.PROTOCOL ("Unable to communicate with remote frida-server; " +
				"please ensure that major versions match and that the remote Frida has the " +
				"feature you are trying to use");
		}

		throw new Frida.Error.TRANSPORT ("%s", e.message);
	}

	public struct HostApplicationInfo {
		public string identifier;
		public string name;
		public uint pid;
		public HashTable<string, Variant> parameters;

		public HostApplicationInfo (string identifier, string name, uint pid, owned HashTable<string, Variant> parameters) {
			this.identifier = identifier;
			this.name = name;
			this.pid = pid;
			this.parameters = parameters;
		}

		public HostApplicationInfo.empty () {
			this.identifier = "";
			this.name = "";
			this.pid = 0;
			this.parameters = make_parameters_dict ();
		}
	}

	public struct HostProcessInfo {
		public uint pid;
		public string name;
		public HashTable<string, Variant> parameters;

		public HostProcessInfo (uint pid, string name, owned HashTable<string, Variant> parameters) {
			this.pid = pid;
			this.name = name;
			this.parameters = parameters;
		}
	}

	public class FrontmostQueryOptions : Object {
		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (scope != MINIMAL)
				dict["scope"] = new Variant.string (scope.to_nick ());

			return dict;
		}

		public static FrontmostQueryOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new FrontmostQueryOptions ();

			Variant? scope = dict["scope"];
			if (scope != null) {
				if (!scope.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'scope' option must be a string");
				options.scope = Scope.from_nick (scope.get_string ());
			}

			return options;
		}
	}

	public class ApplicationQueryOptions : Object {
		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}

		private Gee.List<string> identifiers = new Gee.ArrayList<string> ();

		public void select_identifier (string identifier) {
			identifiers.add (identifier);
		}

		public bool has_selected_identifiers () {
			return !identifiers.is_empty;
		}

		public void enumerate_selected_identifiers (Func<string> func) {
			foreach (var identifier in identifiers)
				func (identifier);
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (!identifiers.is_empty)
				dict["identifiers"] = identifiers.to_array ();

			if (scope != MINIMAL)
				dict["scope"] = new Variant.string (scope.to_nick ());

			return dict;
		}

		public static ApplicationQueryOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new ApplicationQueryOptions ();

			Variant? identifiers = dict["identifiers"];
			if (identifiers != null) {
				if (!identifiers.is_of_type (VariantType.STRING_ARRAY))
					throw new Error.INVALID_ARGUMENT ("The 'identifiers' option must be a string array");
				var iter = identifiers.iterator ();
				Variant? val;
				while ((val = iter.next_value ()) != null)
					options.select_identifier (val.get_string ());
			}

			Variant? scope = dict["scope"];
			if (scope != null) {
				if (!scope.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'scope' option must be a string");
				options.scope = Scope.from_nick (scope.get_string ());
			}

			return options;
		}
	}

	public class ProcessQueryOptions : Object {
		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}

		private Gee.List<uint> pids = new Gee.ArrayList<uint> ();

		public void select_pid (uint pid) {
			pids.add (pid);
		}

		public bool has_selected_pids () {
			return !pids.is_empty;
		}

		public void enumerate_selected_pids (Func<uint> func) {
			foreach (var pid in pids)
				func (pid);
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (!pids.is_empty)
				dict["pids"] = pids.to_array ();

			if (scope != MINIMAL)
				dict["scope"] = new Variant.string (scope.to_nick ());

			return dict;
		}

		public static ProcessQueryOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new ProcessQueryOptions ();

			Variant? pids = dict["pids"];
			if (pids != null) {
				if (!pids.is_of_type (new VariantType.array (VariantType.UINT32)))
					throw new Error.INVALID_ARGUMENT ("The 'pids' option must be a uint32 array");
				var iter = pids.iterator ();
				Variant? val;
				while ((val = iter.next_value ()) != null)
					options.select_pid (val.get_uint32 ());
			}

			Variant? scope = dict["scope"];
			if (scope != null) {
				if (!scope.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'scope' option must be a string");
				options.scope = Scope.from_nick (scope.get_string ());
			}

			return options;
		}
	}

	public enum Scope {
		MINIMAL,
		METADATA,
		FULL;

		public static Scope from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<Scope> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Scope> (this);
		}
	}

	public struct HostSpawnOptions {
		public bool has_argv;
		public string[] argv;

		public bool has_envp;
		public string[] envp;

		public bool has_env;
		public string[] env;

		public string cwd;

		public Stdio stdio;

		public HashTable<string, Variant> aux;

		public HostSpawnOptions () {
			this.argv = {};
			this.envp = {};
			this.env = {};
			this.cwd = "";
			this.stdio = INHERIT;
			this.aux = make_parameters_dict ();
		}

		public string[] compute_argv (string path) {
			return has_argv ? argv : new string[] { path };
		}

		public string[] compute_envp () {
			var base_env = has_envp ? envp : Environ.get ();
			if (!has_env)
				return base_env;

			var names = new Gee.ArrayList<string> ();
			var values = new Gee.HashMap<string, string> ();
			parse_envp (base_env, names, values);

			var overridden_names = new Gee.ArrayList<string> ();
			var overridden_values = new Gee.HashMap<string, string> ();
			parse_envp (env, overridden_names, overridden_values);

			foreach (var name in overridden_names) {
				if (!values.has_key (name))
					names.add (name);
				values[name] = overridden_values[name];
			}

			var result = new string[names.size];
			var i = 0;
			foreach (var name in names) {
				result[i] = name.concat ("=", values[name]);
				i++;
			}
			return result;
		}

		private static void parse_envp (string[] envp, Gee.ArrayList<string> names, Gee.HashMap<string, string> values) {
			foreach (var pair in envp) {
				var tokens = pair.split ("=", 2);
				if (tokens.length == 1)
					continue;
				var name = tokens[0];
				var val = tokens[1];
				names.add (name);
				values[name] = val;
			}
		}
	}

	public class SessionOptions : Object {
		public Realm realm {
			get;
			set;
			default = NATIVE;
		}

		public uint persist_timeout {
			get;
			set;
			default = 0;
		}

		public string? emulated_agent_path {
			get;
			set;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (realm != NATIVE)
				dict["realm"] = new Variant.string (realm.to_nick ());

			if (persist_timeout != 0)
				dict["persist-timeout"] = new Variant.uint32 (persist_timeout);

			if (emulated_agent_path != null)
				dict["emulated-agent-path"] = new Variant.string (emulated_agent_path);

			return dict;
		}

		public static SessionOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new SessionOptions ();

			Variant? realm = dict["realm"];
			if (realm != null) {
				if (!realm.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'realm' option must be a string");
				options.realm = Realm.from_nick (realm.get_string ());
			}

			Variant? persist_timeout = dict["persist-timeout"];
			if (persist_timeout != null) {
				if (!persist_timeout.is_of_type (VariantType.UINT32))
					throw new Error.INVALID_ARGUMENT ("The 'persist-timeout' option must be a uint32");
				options.persist_timeout = persist_timeout.get_uint32 ();
			}

			Variant? path = dict["emulated-agent-path"];
			if (path != null) {
				if (!path.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'emulated-agent-path' option must be a string");
				options.emulated_agent_path = path.get_string ();
			}

			return options;
		}
	}

	public enum Stdio {
		INHERIT,
		PIPE;

		public static Stdio from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<Stdio> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Stdio> (this);
		}
	}

	public struct HostSpawnInfo {
		public uint pid;
		public string identifier;

		public HostSpawnInfo (uint pid, string identifier) {
			this.pid = pid;
			this.identifier = identifier;
		}
	}

	public struct HostChildId {
		public uint handle;

		public HostChildId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (HostChildId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (HostChildId? a, HostChildId? b) {
			return a.handle == b.handle;
		}
	}

	public struct HostChildInfo {
		public uint pid;
		public uint parent_pid;

		public ChildOrigin origin;

		public string identifier;
		public string path;

		public bool has_argv;
		public string[] argv;

		public bool has_envp;
		public string[] envp;

		public HostChildInfo (uint pid, uint parent_pid, ChildOrigin origin) {
			this.pid = pid;
			this.parent_pid = parent_pid;
			this.origin = origin;
			this.identifier = "";
			this.path = "";
			this.argv = {};
			this.envp = {};
		}
	}

	public enum ChildOrigin {
		FORK,
		EXEC,
		SPAWN;

		public static ChildOrigin from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<ChildOrigin> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<ChildOrigin> (this);
		}
	}

	public struct CrashInfo {
		public uint pid;
		public string process_name;

		public string summary;
		public string report;

		public HashTable<string, Variant> parameters;

		public CrashInfo (uint pid, string process_name, string summary, string report,
				HashTable<string, Variant>? parameters = null) {
			this.pid = pid;
			this.process_name = process_name;

			this.summary = summary;
			this.report = report;

			this.parameters = (parameters != null) ? parameters : make_parameters_dict ();
		}

		public CrashInfo.empty () {
			this.pid = 0;
			this.process_name = "";
			this.summary = "";
			this.report = "";
			this.parameters = make_parameters_dict ();
		}
	}

	public struct AgentSessionId {
		public string handle;

		public AgentSessionId (string handle) {
			this.handle = handle;
		}

		public AgentSessionId.generate () {
			this.handle = Uuid.string_random ().replace ("-", "");
		}

		public static uint hash (AgentSessionId? id) {
			return id.handle.hash ();
		}

		public static bool equal (AgentSessionId? a, AgentSessionId? b) {
			return a.handle == b.handle;
		}
	}

	public struct AgentScriptId {
		public uint handle;

		public AgentScriptId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (AgentScriptId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (AgentScriptId? a, AgentScriptId? b) {
			return a.handle == b.handle;
		}
	}

	public class ScriptOptions : Object {
		public string? name {
			get;
			set;
		}

		public Bytes? snapshot {
			get;
			set;
		}

		public SnapshotTransport snapshot_transport {
			get;
			set;
			default = INLINE;
		}

		public ScriptRuntime runtime {
			get;
			set;
			default = DEFAULT;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (name != null)
				dict["name"] = new Variant.string (name);

			if (snapshot != null) {
				if (snapshot_transport == SHARED_MEMORY) {
					unowned uint8[]? data = snapshot.get_data ();
					dict["snapshot-memory-range"] = new Variant ("(tu)", (uint64) data, (uint) data.length);
				} else {
					dict["snapshot"] = Variant.new_from_data (new VariantType ("ay"), snapshot.get_data (), true, snapshot);
				}
			}

			if (runtime != DEFAULT)
				dict["runtime"] = new Variant.string (runtime.to_nick ());

			return dict;
		}

		public static ScriptOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new ScriptOptions ();

			Variant? name = dict["name"];
			if (name != null) {
				if (!name.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'name' option must be a string");
				options.name = name.get_string ();
			}

			Variant? snapshot = dict["snapshot"];
			if (snapshot != null) {
				if (!snapshot.is_of_type (new VariantType ("ay")))
					throw new Error.INVALID_ARGUMENT ("The 'snapshot' option must be a byte array");
				options.snapshot = snapshot.get_data_as_bytes ();
			} else {
				Variant? range = dict["snapshot-memory-range"];
				if (range != null) {
					if (!range.is_of_type (new VariantType ("(tu)")))
						throw new Error.INVALID_ARGUMENT ("The 'snapshot-memory-range' option must be a tuple");

					uint64 base_address;
					uint size;
					range.get ("(tu)", out base_address, out size);
					unowned uint8[]? data = ((uint8[]) (void *) base_address)[:size];

					options.snapshot = new Bytes.static (data);
				}
			}

			Variant? runtime = dict["runtime"];
			if (runtime != null) {
				if (!runtime.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'runtime' option must be a string");
				options.runtime = ScriptRuntime.from_nick (runtime.get_string ());
			}

			return options;
		}
	}

	public enum SnapshotTransport {
		INLINE,
		SHARED_MEMORY
	}

	public class SnapshotOptions : Object {
		public string? warmup_script {
			get;
			set;
		}

		public ScriptRuntime runtime {
			get;
			set;
			default = DEFAULT;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (warmup_script != null)
				dict["warmup-script"] = new Variant.string (warmup_script);

			if (runtime != DEFAULT)
				dict["runtime"] = new Variant.string (runtime.to_nick ());

			return dict;
		}

		public static SnapshotOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new SnapshotOptions ();

			Variant? warmup_script = dict["warmup-script"];
			if (warmup_script != null) {
				if (!warmup_script.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'warmup-script' option must be a string");
				options.warmup_script = warmup_script.get_string ();
			}

			Variant? runtime = dict["runtime"];
			if (runtime != null) {
				if (!runtime.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'runtime' option must be a string");
				options.runtime = ScriptRuntime.from_nick (runtime.get_string ());
			}

			return options;
		}
	}

	public enum ScriptRuntime {
		DEFAULT,
		QJS,
		V8;

		public static ScriptRuntime from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<ScriptRuntime> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<ScriptRuntime> (this);
		}
	}

	public struct PortalMembershipId {
		public uint handle;

		public PortalMembershipId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (PortalMembershipId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (PortalMembershipId? a, PortalMembershipId? b) {
			return a.handle == b.handle;
		}
	}

	public class PortalOptions : Object {
		public TlsCertificate? certificate {
			get;
			set;
		}

		public string? token {
			get;
			set;
		}

		public string[]? acl {
			get;
			set;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (certificate != null)
				dict["certificate"] = new Variant.string (certificate.certificate_pem);

			if (token != null)
				dict["token"] = new Variant.string (token);

			if (acl != null)
				dict["acl"] = new Variant.strv (acl);

			return dict;
		}

		public static PortalOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new PortalOptions ();

			Variant? cert_pem = dict["certificate"];
			if (cert_pem != null) {
				if (!cert_pem.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'certificate' option must be a string");
				try {
					options.certificate = new TlsCertificate.from_pem (cert_pem.get_string (), -1);
				} catch (GLib.Error e) {
					throw new Error.INVALID_ARGUMENT ("%s", e.message);
				}
			}

			Variant? token = dict["token"];
			if (token != null) {
				if (!token.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'token' option must be a string");
				options.token = token.get_string ();
			}

			Variant? acl = dict["acl"];
			if (acl != null) {
				if (!acl.is_of_type (VariantType.STRING_ARRAY))
					throw new Error.INVALID_ARGUMENT ("The 'acl' option must be a string array");
				options.acl = acl.get_strv ();
			}

			return options;
		}
	}

	public class PeerOptions : Object {
		public string? stun_server {
			get;
			set;
		}

		private Gee.List<Relay> relays = new Gee.ArrayList<Relay> ();

		public void clear_relays () {
			relays.clear ();
		}

		public void add_relay (Relay relay) {
			relays.add (relay);
		}

		public void enumerate_relays (Func<Relay> func) {
			foreach (var relay in relays)
				func (relay);
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (stun_server != null)
				dict["stun-server"] = new Variant.string (stun_server);

			if (!relays.is_empty) {
				var builder = new VariantBuilder (new VariantType.array (Relay.get_variant_type ()));
				foreach (var relay in relays)
					builder.add_value (relay.to_variant ());
				dict["relays"] = builder.end ();
			}

			return dict;
		}

		public static PeerOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new PeerOptions ();

			Variant? stun_server = dict["stun-server"];
			if (stun_server != null) {
				if (!stun_server.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'stun-server' option must be a string");
				options.stun_server = stun_server.get_string ();
			}

			Variant? relays_val = dict["relays"];
			if (relays_val != null) {
				if (!relays_val.is_of_type (new VariantType.array (Relay.get_variant_type ())))
					throw new Error.INVALID_ARGUMENT ("The 'relays' option must be an array of tuples");
				var iter = relays_val.iterator ();
				Variant? val;
				while ((val = iter.next_value ()) != null)
					options.add_relay (Relay.from_variant (val));
			}

			return options;
		}
	}

	public class Relay : Object {
		public string address {
			get;
			construct;
		}

		public string username {
			get;
			construct;
		}

		public string password {
			get;
			construct;
		}

		public RelayKind kind {
			get;
			construct;
		}

		public Relay (string address, string username, string password, RelayKind kind) {
			Object (
				address: address,
				username: username,
				password: password,
				kind: kind
			);
		}

		internal static VariantType get_variant_type () {
			return new VariantType ("(sssu)");
		}

		internal Variant to_variant () {
			return new Variant ("(sssu)", address, username, password, (uint) kind);
		}

		internal static Relay from_variant (Variant val) {
			string address, username, password;
			uint kind;
			val.get ("(sssu)", out address, out username, out password, out kind);

			return new Relay (address, username, password, (RelayKind) kind);
		}
	}

	public enum RelayKind {
		TURN_UDP,
		TURN_TCP,
		TURN_TLS
	}

	public HashTable<string, Variant> make_parameters_dict () {
		return new HashTable<string, Variant> (str_hash, str_equal);
	}

	public HashTable<string, Variant> compute_system_parameters () {
		var parameters = new HashTable<string, Variant> (str_hash, str_equal);

		var os = new HashTable<string, Variant> (str_hash, str_equal);
		string id;
#if WINDOWS
		id = "windows";
#elif MACOS
		id = "macos";
#elif LINUX && !ANDROID
		id = "linux";
#elif IOS
		id = "ios";
#elif WATCHOS
		id = "watchos";
#elif TVOS
		id = "tvos";
#elif ANDROID
		id = "android";
#elif FREEBSD
		id = "freebsd";
#elif QNX
		id = "qnx";
#else
		id = FIXME;
#endif
		os["id"] = id;
#if WINDOWS
		os["name"] = "Windows";
		os["version"] = _query_windows_version ();
#elif DARWIN
		try {
			string plist;
			FileUtils.get_contents ("/System/Library/CoreServices/SystemVersion.plist", out plist);

			MatchInfo info;
			if (/<key>ProductName<\/key>.*?<string>(.+?)<\/string>/s.match (plist, 0, out info)) {
				os["name"] = info.fetch (1);
			}
			if (/<key>ProductVersion<\/key>.*?<string>(.+?)<\/string>/s.match (plist, 0, out info)) {
				os["version"] = info.fetch (1);
			}
		} catch (FileError e) {
		}
#elif LINUX && !ANDROID
		try {
			string details;
			FileUtils.get_contents ("/etc/os-release", out details);

			MatchInfo info;
			if (/^ID=(.+)$/m.match (details, 0, out info)) {
				os["id"] = Shell.unquote (info.fetch (1));
			}
			if (/^NAME=(.+)$/m.match (details, 0, out info)) {
				os["name"] = Shell.unquote (info.fetch (1));
			}
			if (/^VERSION_ID=(.+)$/m.match (details, 0, out info)) {
				os["version"] = Shell.unquote (info.fetch (1));
			}
		} catch (GLib.Error e) {
		}
#elif ANDROID
		os["name"] = "Android";
		os["version"] = _query_android_system_property ("ro.build.version.release");
#elif QNX
		os["name"] = "QNX";
#endif
		parameters["os"] = os;

		string platform;
#if WINDOWS
		platform = "windows";
#elif DARWIN
		platform = "darwin";
#elif LINUX
		platform = "linux";
#elif FREEBSD
		platform = "freebsd";
#elif QNX
		platform = "qnx";
#else
		platform = FIXME;
#endif
		parameters["platform"] = platform;

		string arch;
#if X86
		arch = "ia32";
#elif X86_64
		arch = "x64";
#elif ARM
		arch = "arm";
#elif ARM64
		arch = "arm64";
#elif MIPS
		arch = "mips";
#else
		arch = FIXME;
#endif
		parameters["arch"] = arch;

		parameters["access"] = "full";

#if WINDOWS
		parameters["name"] = _query_windows_computer_name ();
#elif IOS
		import_mg_property (parameters, "name", "UserAssignedDeviceName");
		import_mg_property (parameters, "udid", "UniqueDeviceID");

		add_interfaces (parameters);
#elif ANDROID
		parameters["api-level"] = int64.parse (_query_android_system_property ("ro.build.version.sdk"));
#else
		parameters["name"] = Environment.get_host_name ();
#endif

		return parameters;
	}

#if WINDOWS
	public extern string _query_windows_version ();
	public extern string _query_windows_computer_name ();
#elif IOS
	private void import_mg_property (HashTable<string, Variant> parameters, string key, string query) {
		string? val = try_resolve_mg_property (query);
		if (val != null)
			parameters[key] = val;
	}

	private void add_interfaces (HashTable<string, Variant> parameters) {
		var ifaces = new VariantBuilder (new VariantType.array (VariantType.VARDICT));

		maybe_add_network_interface (ifaces, "ethernet", "EthernetMacAddress");
		maybe_add_network_interface (ifaces, "wifi", "WifiAddress");
		maybe_add_network_interface (ifaces, "bluetooth", "BluetoothAddress");

		string? phone = try_resolve_mg_property ("PhoneNumber");
		if (phone != null) {
			ifaces.open (VariantType.VARDICT);
			ifaces.add ("{sv}", "type", new Variant.string ("cellular"));
			ifaces.add ("{sv}", "phone-number", new Variant.string (phone));
			ifaces.close ();
		}

		parameters["interfaces"] = ifaces.end ();
	}

	private void maybe_add_network_interface (VariantBuilder ifaces, string type, string query) {
		string? address = try_resolve_mg_property (query);
		if (address == null)
			return;
		ifaces.open (VariantType.VARDICT);
		ifaces.add ("{sv}", "type", new Variant.string (type));
		ifaces.add ("{sv}", "address", new Variant.string (address));
		ifaces.close ();
	}

	private string? try_resolve_mg_property (string query) {
		var answer = _query_mobile_gestalt (query);
		if (answer == null || !answer.is_of_type (VariantType.STRING))
			return null;

		string val = answer.get_string ();
		if (val.length == 0)
			return null;

		return val;
	}

	public extern Variant? _query_mobile_gestalt (string query);
#elif ANDROID
	public extern string _query_android_system_property (string name);
#endif

	namespace ServerGuid {
		public const string HOST_SESSION_SERVICE = "6769746875622e636f6d2f6672696461";
	}

	namespace ObjectPath {
		public const string HOST_SESSION = "/re/frida/HostSession";
		public const string AGENT_SESSION_PROVIDER = "/re/frida/AgentSessionProvider";
		public const string AGENT_SESSION = "/re/frida/AgentSession";
		public const string AGENT_CONTROLLER = "/re/frida/AgentController";
		public const string AGENT_MESSAGE_SINK = "/re/frida/AgentMessageSink";
		public const string CHILD_SESSION = "/re/frida/ChildSession";
		public const string TRANSPORT_BROKER = "/re/frida/TransportBroker";
		public const string PORTAL_SESSION = "/re/frida/PortalSession";
		public const string BUS_SESSION = "/re/frida/BusSession";
		public const string AUTHENTICATION_SERVICE = "/re/frida/AuthenticationService";

		public static string for_agent_session (AgentSessionId id) {
			return AGENT_SESSION + "/" + id.handle;
		}

		public static string for_agent_message_sink (AgentSessionId id) {
			return AGENT_MESSAGE_SINK + "/" + id.handle;
		}
	}

	namespace Marshal {
		public static T enum_from_nick<T> (string nick) throws Error {
			var klass = (EnumClass) typeof (T).class_ref ();
			var v = klass.get_value_by_nick (nick);
			if (v == null)
				throw new Error.INVALID_ARGUMENT ("Invalid %s", klass.get_type ().name ());
			return (T) v.value;
		}

		public static string enum_to_nick<T> (int val) {
			var klass = (EnumClass) typeof (T).class_ref ();
			return klass.get_value (val).value_nick;
		}
	}

	namespace Numeric {
		public uint int64_hash (int64? val) {
			uint64 v = (uint64) val.abs ();
			return (uint) ((v >> 32) ^ (v & 0xffffffffU));
		}

		public bool int64_equal (int64? val_a, int64? val_b) {
			int64 a = val_a;
			int64 b = val_b;
			return a == b;
		}

		public uint uint64_hash (uint64? val) {
			uint64 v = val;
			return (uint) ((v >> 32) ^ (v & 0xffffffffU));
		}

		public bool uint64_equal (uint64? val_a, uint64? val_b) {
			uint64 a = val_a;
			uint64 b = val_b;
			return a == b;
		}
	}
}

"""


```