import core.sys.windows.windows;
import core.sys.windows.winbase;
import core.sys.windows.windef;
import core.sys.windows.winnt;
import std.string : toStringz;
import std.exception : enforce;
import std.conv : to;

extern(Windows) {
    LONG NtReadVirtualMemory(
        HANDLE ProcessHandle,
        const(void)* BaseAddress,
        void* Buffer,
        ULONG NumberOfBytesToRead,
        ULONG* NumberOfBytesRead
    );

    LONG NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        void* BaseAddress,
        const(void)* Buffer,
        ULONG NumberOfBytesToWrite,
        ULONG* NumberOfBytesWritten
    );
}

class AdvancedMemory {
    private:
        HANDLE hProcess = null;

    public:
        this(string processName) {
            DWORD pid = getPIDByName(processName);
            enforce(pid != 0, "Failed to find process PID");
            this.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            enforce(this.hProcess !is null, "Failed to open process with PID: " ~ pid.to!string);
        }

        ~this() {
            if (this.hProcess !is null) {
                CloseHandle(this.hProcess);
            }
        }

        private DWORD getPIDByName(string processName) {
            DWORD[1024] processes;
            uint cbNeeded;

            if (!EnumProcesses(processes.ptr, processes.length * DWORD.sizeof, &cbNeeded))
                return 0;

            foreach (i; 0..cbNeeded / DWORD.sizeof) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
                if (hProcess !is null) {
                    char[1024] processNameBuffer;
                    if (EnumProcessModules(hProcess, cast(HMODULE*)processes.ptr, DWORD.sizeof, &cbNeeded)) {
                        GetModuleBaseNameA(hProcess, processes.ptr[0], processNameBuffer.ptr, processNameBuffer.length);
                        if (processNameBuffer.to!string.split(".")[0].toLowercase() == processName.split(".")[0].toLowercase()) {
                            CloseHandle(hProcess);
                            return processes[i];
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
            return 0;
        }

        void writeProcessMemory(T)(size_t address, T value) {
            enforce(this.hProcess !is null, "No process handle");
            ULONG bytesWritten;
            enforce(
                NtWriteVirtualMemory(
                    this.hProcess,
                    cast(void*)address,
                    &value,
                    T.sizeof,
                    &bytesWritten
                ) == 0, "Failed to write memory"
            );
        }

        T readProcessMemory(T)(size_t address) {
            enforce(this.hProcess !is null, "No process handle");
            T value;
            ULONG bytesRead;
            enforce(
                NtReadVirtualMemory(
                    this.hProcess,
                    cast(void*)address,
                    &value,
                    T.sizeof,
                    &bytesRead
                ) == 0, "Failed to read memory"
            );
            return value;
        }
}

void main() {
    auto mem = new AdvancedMemory("notepad.exe");
    int newValue = 12345;
    mem.writeProcessMemory!int(0x7FF6345A0000, newValue);
    int readValue = mem.readProcessMemory!int(0x7FF6345A0000);
    writeln("Read value: ", readValue);
}
