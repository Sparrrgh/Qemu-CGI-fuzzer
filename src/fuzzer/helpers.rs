use std::process;

use grammartec::context::Context;
use libafl::{
    generators::NautilusContext,
    prelude::{NautilusInput, UsesInput},
    state::HasMetadata,
};
use libafl_qemu::{
    Emulator, QemuHelper, QemuHelperTuple, QemuHooks, SYS_exit, SYS_exit_group, SYS_read,
    SyscallHookResult,
};

use crate::fuzzer::grammar;
// [TODO] Find max body size
const MAX_BODY_SIZE: usize = 256;

/// wrapper around general purpose register resets, mimics AFL_QEMU_PERSISTENT_GPR
///   ref: https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md#24-resetting-the-register-state
#[derive(Default, Debug)]
pub struct QemuGPRegisterHelper {
    /// vector of values representing each registers saved value
    register_state: Vec<u64>,
}

/// implement the QemuHelper trait for QemuGPRegisterHelper
impl<S> QemuHelper<S> for QemuGPRegisterHelper
where
    S: HasMetadata + UsesInput<Input = NautilusInput>,
{
    /// prepare helper for fuzz case; called before every fuzz case
    fn pre_exec(&mut self, emulator: &Emulator, _input: &S::Input) {
        self.restore(emulator);
    }
}

/// QemuGPRegisterHelper implementation
impl QemuGPRegisterHelper {
    /// given an `Emulator`, save off all known register values
    pub fn new(emulator: &Emulator) -> Self {
        let register_state = (0..emulator.num_regs())
            .map(|reg_idx| emulator.read_reg(reg_idx).unwrap_or(0))
            .collect::<Vec<u64>>();

        Self { register_state }
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
        // I don't need a clone here, but...
        let mut modified_input = input.clone();
        let buf: &[u8] = if !grammar::unparse_bounded_from_rule(
            &self.context,
            &mut modified_input,
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
    let syscall = syscall as i64;
    if syscall == SYS_exit || syscall == SYS_exit_group {
        // since calls to exit are verboten, hook the relevant syscalls and abort instead
        process::abort();
    } else if syscall == SYS_read {
        // man read:
        //
        //   ssize_t read(int fd, void *buf, size_t count);
        //
        //   On  success, the number of bytes read is returned (zero indicates end of file)
        //   On error, -1 is returned, and errno is set appropriately.

        // If stdin
        if a0 == 0 {
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
        // Drain<u8> dropped here, our buffer now has only what remains of the original u8's
        } else {
            SyscallHookResult::new(None) // all other syscalls pass through unaltered
        }
    } else {
        SyscallHookResult::new(None) // all other syscalls pass through unaltered
    }
}
