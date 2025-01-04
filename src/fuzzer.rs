use core::ptr::addr_of_mut;
use std::{env, fs, path::PathBuf, time::Duration};

use libafl::{
    common::HasMetadata,
    corpus::{Corpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    executors::ExitKind,
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    monitors::MultiMonitor,
    mutators::StdScheduledMutator,
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error,
};
// Nautilus imports
use libafl::{
    feedbacks::{NautilusChunksMetadata, NautilusFeedback},
    generators::NautilusGenerator,
    inputs::NautilusInput,
    mutators::{NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator},
};
use libafl_bolts::{
    cli, current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    arch::mips::Regs, elf::EasyElf, Emulator, EmulatorHooks, GuestAddr, MmapPerms, Qemu,
    QemuExecutor,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};

// Own imports
pub mod grammar;

mod helpers;
use helpers::{QemuFakeStdinHelper, QemuGPResetHelper};

/// Assuming the pagesize is 4kb on the device
const MAX_ENV_SIZE: usize = 131072; // PAGESIZE*32 | 128 kb

pub fn fuzz() -> Result<(), Error> {
    // parse the following:
    //   solutions dir
    //   input corpus dirs
    //   cores
    //   timeout
    //   verbosity
    //   broker port
    //   stdout file3
    let mut fuzzer_options = cli::parse_args();

    //
    // Component: Corpus
    //

    // corpus that will be evolved in memory, during fuzzing; metadata saved in json
    let input_corpus = OnDiskCorpus::new(fuzzer_options.output.join("queue"))?;

    // corpus in which we store solutions on disk so we can get them after stopping the fuzzer
    let solutions_corpus = OnDiskCorpus::new(fuzzer_options.output.clone())?;

    //
    // Component: Emulator
    //

    env::remove_var("LD_LIBRARY_PATH");

    let mut env: Vec<(String, String)> = env::vars().collect();

    // create an Emulator which provides the methods necessary to interact with the emulated target
    // let emu = libafl_qemu::init_with_asan(&mut fuzzer_options.qemu_args, &mut env);
    let qemu = Qemu::init(&mut fuzzer_options.qemu_args)?;

    // load our fuzz target from disk, the resulting `EasyElf` is used to do symbol lookups on  the
    // binary. It handles address resolution in the case of PIE as well.
    let mut buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut buffer)?;

    // Get the executable name, and load the nautilus context
    let bin_name = qemu.binary_path().rsplit_once('/').unwrap().1;
    let context = grammar::get_cgi_context(50, bin_name.to_string());

    // find the function of interest from the loaded elf. since we're not interested in parsing
    // command line stuff every time, we'll run until main, and then set our entrypoint to be past
    // the getopt stuff by adding a static offset found by looking at the disassembly. This is the
    // same concept as using AFL_ENTRYPOINT.

    // let main_ptr = elf.resolve_symbol("main", emu.load_addr()).unwrap();
    // [APPLICATION SPECIFIC]
    // [TODO] Cannot find main in webproc?!
    // After module is registered
    let main_ptr = 0x004018d0 as GuestAddr;

    // point at which we want to stop execution, i.e. after the vulnerable function
    // [APPLICATION SPECIFIC]
    // Before module is unregistered
    let ret_addr = 0x004022c0 as GuestAddr;

    // set a breakpoint on the function of interest and emulate execution until we arrive there
    qemu.set_breakpoint(main_ptr);
    unsafe { qemu.run() };
    qemu.remove_breakpoint(main_ptr);

    // Reserve space for the enviroment variables set by the harness
    let my_envp = qemu
        .map_private(0, MAX_ENV_SIZE, MmapPerms::ReadWrite)
        .unwrap();
    // let cwd = env::current_dir()?.into_os_string().into_string().unwrap();
    // let env_start = format!("LD_PRELOAD={cwd}/build/libqasan.so\0_=./build/qemu_mips_cgi\0");
    let env_start = format!("_=./build/qemu_mips_cgi\0");

    // Prepare some of the indexes to later use in the harness
    let env_start_indexes = [0]
        .into_iter()
        .chain(
            env_start
                .bytes()
                .enumerate()
                .filter(|(_, b)| *b == 0)
                .map(|(index, _)| (index + 1) as u32),
        )
        .collect::<Vec<u32>>();

    // Write the start of the env once, at the start of the reserved space
    unsafe {
        qemu.write_mem(my_envp, env_start.as_bytes());
    }

    // reset breakpoint from start of the function to the place we want to stop, registers will
    // all be saved off in `QemuGPRegisterHelper::pre_exec`
    qemu.set_breakpoint(ret_addr);

    //
    // Component: Harness
    //

    let mut harness =
        |_emulator: &mut Emulator<_, _, _, _, _>, _state: &mut _, input: &NautilusInput| {
            let mut buf = vec![];
            let my_envp_write = my_envp + env_start.len() as GuestAddr;
            // Skip large inputs
            if !grammar::unparse_bounded_from_rule(
                &context,
                input,
                &mut buf,
                MAX_ENV_SIZE - env_start.len(),
                "ENV",
            ) {
                return ExitKind::Ok;
            }

            // At the start of the main `a2` contains the pointer to the start of env array
            let start_array: GuestAddr = GuestAddr::from_be(qemu.read_reg(Regs::A2).unwrap());
            // println!("Start of array is at {start_array:#X}");

            // Build my env array
            // First search for each nullbyte in the env
            // Then use the start of each string to create a pointer to it
            // Checking the index using nullbytes is not really smart, it might mutate and throw me way off
            let my_env_array_buf = &buf
                .iter()
                .enumerate()
                .filter(|(_, &b)| b == 0)
                .map(|(index, _)| (index + env_start.len() + 1) as u32)
                .chain(env_start_indexes.clone())
                .flat_map(|offset| GuestAddr::to_be_bytes(my_envp + offset))
                .chain(GuestAddr::to_be_bytes(0))
                .collect::<Vec<u8>>()[..];

            // Writing this in the process stack can corrupt some stuff if I inject a lot of different variables
            // I could write a check on the first execution so that I verify how many envs I can actually write
            unsafe { qemu.write_mem(start_array, my_env_array_buf) };

            unsafe {
                qemu.write_mem(my_envp_write, &buf);
                qemu.run();
            };

            ExitKind::Ok
        };

    //
    // Component: Client Runner
    //

    let mut run_client = |state: Option<_>, mut mgr, _core_id| {
        //
        // Component: Observer
        //

        // Create an observation channel using the coverage map.
        //
        // the `libafl_qemu::edges` module re-exports the same `EDGES_MAP` and `MAX_EDGES_NUM`
        // from `libafl_targets`, meaning we're using the sancov backend for coverage
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        // Create an observation channel to keep track of the execution time and previous runtime
        let time_observer = TimeObserver::new("time");

        //
        // Component: Feedback
        //

        // A Feedback, in most cases, processes the information reported by one or more observers to
        // decide if the execution is interesting. This one is composed of two Feedbacks using a
        // logical OR.
        //
        // Due to the fact that TimeFeedback can never classify a testcase as interesting on its own,
        // we need to use it alongside some other Feedback that has the ability to perform said
        // classification. These two feedbacks are combined to create a boolean formula, i.e. if the
        // input triggered a new code path, OR, false.
        let mut feedback = feedback_or!(
            // New maximization map feedback (attempts to maximize the map contents) linked to the
            // edges observer and the feedback state. This one will track indexes, but will not track
            // novelties, i.e. new_tracking(... true, false).
            MaxMapFeedback::new(&edges_observer),
            // Time feedback, this one does not need a feedback state, nor does it ever return true for
            // is_interesting, However, it does keep track of testcase execution time by way of its
            // TimeObserver
            TimeFeedback::new(&time_observer),
            // Nautilus Feedback
            NautilusFeedback::new(&context)
        );

        // A feedback, when used as an Objective, determines if an input should be added to the
        // corpus or not. In the case below, we're saying that in order for a testcase's input to
        // be added to the corpus, it must:
        //
        //   1: be a crash
        //        AND
        //   2: have produced new edge coverage
        //
        // The feedback_and_fast macro combines the two feedbacks with a fast AND operation, which
        // means only enough feedback functions will be called to know whether or not the objective
        // has been met, i.e. short-circuiting logic.
        //
        // this is essentially the same crash deduplication strategy used by afl++
        let mut objective =
            feedback_and_fast!(CrashFeedback::new(), MaxMapFeedback::new(&edges_observer));

        //
        // Component: State
        //

        // Creates a new State, taking ownership of all of the individual components during fuzzing.
        //
        // On the initial pass, state will be None, and the `unwrap_or_else` will populate our
        // initial settings.
        //
        // On each successive execution, the state from the prior run that was saved
        // off in shared memory will be passed into the closure. The code below handles the
        // initial None value by providing a default StdState. After the first restart, we'll
        // simply unwrap the Some(StdState) passed in to the closure
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // random number generator with a time-based seed
                StdRand::with_seed(current_nanos()),
                // input corpus
                input_corpus.clone(),
                // solutions corpus
                solutions_corpus.clone(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        // Save metadata in tmpfs
        if state
            .metadata_map()
            .get::<NautilusChunksMetadata>()
            .is_none()
        {
            state.add_metadata(NautilusChunksMetadata::new("/dev/shm/".into()));
        }

        //
        // Component: Scheduler
        //

        // A minimization + queue policy to get test cases from the corpus
        //
        // IndexesLenTimeMinimizerCorpusScheduler is a MinimizerCorpusScheduler with a
        // LenTimeMulFavFactor that prioritizes quick and small Testcases that exercise all the
        // entries registered in the MapIndexesMetadata
        //
        // a QueueCorpusScheduler walks the corpus in a queue-like fashion
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

        //
        // Component: Fuzzer
        //

        // A fuzzer with feedback, objectives, and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        //
        // Component: Executor
        //

        // Modules for qemu
        let modules = {
            tuple_list!(
                // QemuEdgeCoverageHelper::new(QemuInstrumentationFilter::None),
                QemuGPResetHelper::new(&qemu),
                // There isn't really an alternative to this, since context has to be a static borrow
                QemuFakeStdinHelper::new(context.ctx.clone()),
                // QemuAsanHelper::new(
                //     QemuInstrumentationFilter::None,
                //     QemuAsanOptions::DetectLeaks
                // ),
            )
        };

        let emulator = Emulator::empty().qemu(qemu).modules(modules).build()?;

        // Create an in-process executor backed by QEMU. The QemuExecutor wraps the
        // `InProcessExecutor`, all of the `QemuHelper`s and the `Emulator` (in addition to the
        // normal wrapped components). This gives us an executor that will execute a bunch of testcases
        // within the same process, eliminating a lot of the overhead associated with a fork/exec or
        // forkserver execution model.
        //
        // additionally, each of the helpers and the emulator will be accessible at other points
        // of execution, easing emulator/input interaction/modification

        let timeout = Duration::from_secs(5);

        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )?;

        let mut generator = NautilusGenerator::new(&context);

        // In case the corpus is empty (i.e. on first run), generate an initial corpus
        // corpus
        if state.corpus().count() < 1 {
            state
                .generate_initial_inputs_forced(
                    &mut fuzzer,
                    &mut executor,
                    &mut generator,
                    &mut mgr,
                    50,
                )
                .unwrap_or_else(|_| {
                    println!("Failed generate initial corpus");
                    std::process::exit(0);
                });
        }
        //
        // Component: Mutator
        //

        // Setup a mutational stage
        let mutator = StdScheduledMutator::with_max_stack_pow(
            tuple_list!(
                NautilusRandomMutator::new(&context),
                NautilusRandomMutator::new(&context),
                NautilusRandomMutator::new(&context),
                NautilusRandomMutator::new(&context),
                NautilusRandomMutator::new(&context),
                NautilusRecursionMutator::new(&context),
                NautilusRecursionMutator::new(&context),
                NautilusSpliceMutator::new(&context),
                NautilusSpliceMutator::new(&context),
            ),
            2,
        );
        //
        // Component: Stage
        //
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    //
    // Component: Monitor
    //

    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .broker_port(fuzzer_options.broker_port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&fuzzer_options.cores)
        .stdout_file(Some(fuzzer_options.stdout.as_str()))
        .build()
        .launch()
    {
        Ok(()) => Ok(()),
        Err(Error::ShuttingDown) => {
            println!("Fuzzing stopped by user. Good bye.");
            Ok(())
        }
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
