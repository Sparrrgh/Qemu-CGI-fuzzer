use std::{env, path::PathBuf, process, str};

use libafl::{
    common::{nautilus::grammartec::context::Context, HasMetadata},
    executors::ExitKind,
    generators::NautilusContext,
    inputs::{NautilusInput, UsesInput},
    observers::ObserversTuple,
};
use libafl_qemu::{
    arch::mips::{Regs, SYS_creat, SYS_exit, SYS_exit_group, SYS_open, SYS_read},
    emu::{EmulatorHooks, EmulatorModules},
    modules::{EmulatorModule, EmulatorModuleTuple, StdAddressFilter},
    GuestAddr, Hook, Qemu, SyscallHookResult,
};

use crate::fuzzer::grammar;

// There isn't a specified max POST body size, but it seems the maximum allowed is around 2GB
const MAX_BODY_SIZE: usize = 2147483648; // 2**31 bytes = 2GB

/// wrapper around general purpose register resets, mimics AFL_QEMU_PERSISTENT_GPR
///   ref: https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md#24-resetting-the-register-state
/// The actual SnapshotModule I think is better
#[derive(Default, Debug)]
pub struct QemuGPResetHelper {
    /// vector of values representing each registers saved value
    register_state: Vec<u32>,
    cwd: PathBuf,
    address_filter: StdAddressFilter,
}

/// implement the EmulatorModule trait for QemuGPRegisterHelper
impl<S> EmulatorModule<S> for QemuGPResetHelper
where
    S: HasMetadata + UsesInput<Input = NautilusInput>,
{
    type ModuleAddressFilter = StdAddressFilter;

    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        &self.address_filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        &mut self.address_filter
    }
    /// prepare helper for fuzz case; called before every fuzz case
    fn pre_exec<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        self.restore(emulator_modules.qemu());
    }

    // [APPLICATION SPECIFIC]
    // restore PWD after execution
    fn post_exec<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
        env::set_current_dir(&self.cwd).unwrap();
    }
}

/// QemuGPRegisterHelper implementation
impl QemuGPResetHelper {
    /// given an `Emulator`, save off all known register values
    pub fn new(qemu: &Qemu) -> Self {
        let register_state = (0..qemu.num_regs())
            .map(|reg_idx| qemu.read_reg(reg_idx).unwrap_or(0))
            .collect::<Vec<u32>>();

        let cwd = env::current_dir().unwrap();
        let address_filter = StdAddressFilter::default();

        Self {
            register_state,
            cwd,
            address_filter,
        }
    }

    /// restore emulator's registers to previously saved values
    /// this doesn't restore the memory used for the enviroment variables
    /// it SHOULDN'T taint future inputs, because of the nullbyte at the end of each env string
    pub fn restore(&self, qemu: Qemu) {
        self.register_state
            .iter()
            .enumerate()
            .for_each(|(reg_idx, reg_val)| {
                if let Err(_e) = qemu.write_reg(reg_idx as i32, *reg_val) {
                    println!("[ERR] Couldn't set register {reg_idx}, skipping...")
                }
            })
    }
}

///  Helper used to feed input to stdin
#[derive(Debug)]
pub struct QemuFakeStdinHelper {
    /// Bytes to write in stdin
    bytes: Vec<u8>,
    /// Cloned context to use
    context: NautilusContext,
    address_filter: StdAddressFilter,
}

impl QemuFakeStdinHelper {
    /// Initialize the helper with the context provided
    pub fn new(ctx: Context) -> Self {
        let bytes = Vec::<u8>::new();
        let context = NautilusContext { ctx };
        let address_filter: StdAddressFilter = StdAddressFilter::default();
        Self {
            context,
            bytes,
            address_filter,
        }
    }
}

impl<S> EmulatorModule<S> for QemuFakeStdinHelper
where
    S: HasMetadata + UsesInput<Input = NautilusInput> + Unpin,
{
    type ModuleAddressFilter = StdAddressFilter;

    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        &self.address_filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        &mut self.address_filter
    }

    fn pre_qemu_init<ET>(&self, emulator_hooks: &mut EmulatorHooks<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
        S: UsesInput,
    {
        emulator_hooks.syscalls(Hook::Function(syscall_hook::<ET, S>));
    }

    /// prepare helper for fuzz case; called before every fuzz case
    fn pre_exec<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        input: &NautilusInput,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        let mut output_vec = vec![];
        // I trim for large inputs
        // [TODO] Is there a way to outright refuse the fuzzcase?
        let buf: &[u8] = if !grammar::unparse_bounded_from_rule(
            &self.context,
            input,
            &mut output_vec,
            MAX_BODY_SIZE,
            "BODY",
        ) {
            &output_vec[0..MAX_BODY_SIZE]
        } else {
            &output_vec[..]
        };

        self.bytes.clear();
        self.bytes.extend_from_slice(buf);
    }
}

/// from man syscall
///   arch/ABI    instruction           syscall #  retval
///   mips        syscall               v0          v0
///
///   arch/ABI      arg1  arg2  arg3  arg4  arg5  arg6  arg7
///   mips/o32      a0    a1    a2    a3    -     -     -
///
/// hook signature where ... are add'l u64's
///   fn(&Emulator, &mut QT, &mut S, sys_num: i32, u64, ...) -> SyscallHookResult
#[allow(clippy::too_many_arguments)]
fn syscall_hook<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    syscall: i32, // syscall number
    a0: u32,      // registers ...
    a1: u32,
    a2: u32,
    _: u32,
    _: u32,
    _: u32,
    _: u32,
    _: u32,
) -> SyscallHookResult
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput<Input = NautilusInput> + Unpin,
{
    // [TODO] Hook open so it doesn't read from root!
    // Maybe it's better to simply use chroot?
    let syscall = syscall as i64;
    let qemu = emulator_modules.qemu();
    match syscall {
        // since calls to exit are verboten, hook the relevant syscalls and abort instead
        SYS_exit | SYS_exit_group => {
            process::abort();
        }
        // Don't let the fuzzer create or open files outside of the `/build` folder
        SYS_open | SYS_creat => {
            let path_addr = qemu.read_reg(Regs::A0).unwrap();
            let mut path = [0; 256];
            unsafe {
                qemu.read_mem(path_addr, &mut path);
            }

            if path[0] == b'/' {
                if !path.starts_with(b"/proc") {
                    let null_terminated_path = if let Some(pos) = path.iter().position(|&x| x == 0) {
                        &path[..pos] // Return the slice up to the null byte
                    } else {
                        &path[..] // Return the entire array if no null byte is found
                    };

                    let cwd = env::current_dir()
                        .unwrap()
                        .into_os_string()
                        .into_string()
                        .unwrap();
                    let new_root = cwd.strip_suffix("/usr/www/cgi-bin").unwrap();
                    let path_utf8 = str::from_utf8(null_terminated_path).unwrap();
                    let new_path = format!("{new_root}{path_utf8}");
                    unsafe {
                        qemu.write_mem(path_addr, &mut new_path.as_bytes());
                    }
                }
            }
            SyscallHookResult::new(None)
        }
        // If stdin
        sysnum if (sysnum == SYS_read && a0 == 0) => {
            let fs_helper = emulator_modules
                .modules_mut()
                .match_first_type_mut::<QemuFakeStdinHelper>()
                .unwrap();

            let current_len = fs_helper.bytes.len();

            let offset: usize = if a2 == 0 {
                // ask for nothing, get nothing
                0
            } else if a2 as usize <= current_len {
                // normal non-negative read that's less than the current mutated buffer's total
                // length
                a2.try_into().unwrap()
            } else {
                // length requested is more than what our buffer holds, so we can read up to the
                // end of the buffer
                current_len
            };

            // draining iterator that removes the specified range from the vector
            // and returns the removed items.
            //
            // when the iterator is dropped, all elements in the range are removed
            // from the vector
            let drained = fs_helper.bytes.drain(..offset).as_slice().to_owned();

            unsafe {
                // write the requested number of bytes to the buffer sent to the read syscall
                qemu.write_mem(a1.try_into().unwrap(), &drained);
            }

            SyscallHookResult::new(Some(drained.len() as GuestAddr))
        }
        _ => SyscallHookResult::new(None), // all other syscalls pass through unaltered
    }
}
