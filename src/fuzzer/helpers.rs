use std::{env, path::PathBuf, process, str};

use grammartec::context::Context;
use libafl::{
    executors::ExitKind,
    generators::NautilusContext,
    prelude::{NautilusInput, UsesInput},
    state::HasMetadata,
};
use libafl_qemu::{
    mips::Regs, Emulator, QemuHelper, QemuHelperTuple, QemuHooks, SYS_creat, SYS_exit,
    SYS_exit_group, SYS_open, SYS_read, SyscallHookResult,
};

use crate::fuzzer::grammar;

// There isn't a specified max POST body size, but it seems the maximum allowed is around 2GB
const MAX_BODY_SIZE: usize = 2147483648; // 2**31 bytes = 2GB

/// wrapper around general purpose register resets, mimics AFL_QEMU_PERSISTENT_GPR
///   ref: https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md#24-resetting-the-register-state
#[derive(Default, Debug)]
pub struct QemuGPResetHelper {
    /// vector of values representing each registers saved value
    register_state: Vec<u64>,
    cwd: PathBuf,
}

/// implement the QemuHelper trait for QemuGPRegisterHelper
impl<S> QemuHelper<S> for QemuGPResetHelper
where
    S: HasMetadata + UsesInput<Input = NautilusInput>,
{
    /// prepare helper for fuzz case; called before every fuzz case
    fn pre_exec(&mut self, emulator: &Emulator, _input: &S::Input) {
        self.restore(emulator);
    }

    // [APPLICATION SPECIFIC]
    // restore PWD after execution
    fn post_exec<OT>(
        &mut self,
        _emulator: &Emulator,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) {
        env::set_current_dir(&self.cwd).unwrap();
    }
}

/// QemuGPRegisterHelper implementation
impl QemuGPResetHelper {
    /// given an `Emulator`, save off all known register values
    pub fn new(emulator: &Emulator) -> Self {
        let register_state = (0..emulator.num_regs())
            .map(|reg_idx| emulator.read_reg(reg_idx).unwrap_or(0))
            .collect::<Vec<u64>>();

        let cwd = env::current_dir().unwrap();

        Self {
            register_state,
            cwd,
        }
    }

    /// restore emulator's registers to previously saved values
    /// this doesn't restore the memory used for the enviroment variables
    /// it SHOULDN'T taint future inputs, because of the nullbyte at the end of each env string
    pub fn restore(&self, emulator: &Emulator) {
        self.register_state
            .iter()
            .enumerate()
            .for_each(|(reg_idx, reg_val)| {
                if let Err(e) = emulator.write_reg(reg_idx as i32, *reg_val) {
                    println!("[ERR] Couldn't set register {reg_idx} ({e}), skipping...")
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
}

impl QemuFakeStdinHelper {
    /// Initialize the helper with the context provided
    pub fn new(ctx: Context) -> Self {
        let bytes = Vec::<u8>::new();
        let context = NautilusContext { ctx };
        Self { context, bytes }
    }
}

impl<S> QemuHelper<S> for QemuFakeStdinHelper
where
    S: HasMetadata + UsesInput<Input = NautilusInput>,
{
    fn init_hooks<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
    where
        QT: QemuHelperTuple<S>,
        S: UsesInput,
    {
        hooks.syscalls(syscall_hook::<QT, S>);
    }

    /// prepare helper for fuzz case; called before every fuzz case
    fn pre_exec(&mut self, _emulator: &Emulator, input: &NautilusInput) {
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
pub fn syscall_hook<QT, S>(
    hooks: &mut QemuHooks<QT, S>, // our instantiated QemuHooks
    _state: Option<&mut S>,
    syscall: i32, // syscall number
    a0: u64,      // registers ...
    a1: u64,
    a2: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> SyscallHookResult
where
    QT: QemuHelperTuple<S>,
    S: UsesInput<Input = NautilusInput>,
{
    // [TODO] Hook open so it doesn't read from root!
    // Maybe it's better to simply use chroot?
    let syscall = syscall as i64;
    match syscall {
        // since calls to exit are verboten, hook the relevant syscalls and abort instead
        SYS_exit | SYS_exit_group => {
            process::abort();
        }
        // Don't let the fuzzer create or open files outside of the `/build` folder
        SYS_open | SYS_creat => {
            let path_addr = hooks.emulator().read_reg(Regs::A0).unwrap();
            let mut path = [0; 256];
            unsafe {
                hooks.emulator().read_mem(path_addr, &mut path);
            }

            if path[0] == b'/' {
                if !path.starts_with(b"/proc") {
                    let cwd = env::current_dir()
                        .unwrap()
                        .into_os_string()
                        .into_string()
                        .unwrap();
                    let new_root = cwd.strip_suffix("/usr/www/cgi-bin").unwrap();
                    let path_utf8 = str::from_utf8(&path).unwrap();
                    let new_path = format!("{new_root}{path_utf8}");
                    unsafe {
                        hooks
                            .emulator()
                            .write_mem(path_addr, &mut new_path.as_bytes());
                    }
                }
            }
            SyscallHookResult::new(None)
        }
        // If stdin
        sysnum if (sysnum == SYS_read && a0 == 0) => {
            let fs_helper = hooks
                .helpers_mut()
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
                hooks.emulator().write_mem(a1.try_into().unwrap(), &drained);
            }

            SyscallHookResult::new(Some(drained.len() as u64))
        }
        _ => SyscallHookResult::new(None), // all other syscalls pass through unaltered
    }
}
