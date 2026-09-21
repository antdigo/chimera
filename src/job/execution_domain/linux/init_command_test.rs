use super::*;
use crate::job::execution_domain::linux::hardening::hardening_test::native_child;

#[test]
#[ignore = "disposable Linux namespace; escaped foreground process-group regression"]
fn cancellation_kills_live_leader_even_after_it_joins_another_group() {
    if !native_child(
        "job::execution_domain::linux::init::command::command_test::cancellation_kills_live_leader_even_after_it_joins_another_group",
    ) {
        return;
    }
    unsafe { libc::setpgid(0, 0) };
    let parent_group = unsafe { libc::getpgrp() };
    assert_eq!(parent_group, unsafe { libc::getpid() });
    let (read, write) = pipe().unwrap();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            if libc::setpgid(0, 0) != 0 || libc::setpgid(0, parent_group) != 0 {
                libc::_exit(90);
            }
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
            libc::write(write.as_raw_fd(), b"r".as_ptr().cast(), 1);
            loop {
                libc::pause();
            }
        }
    }
    drop(write);
    let mut file = std::fs::File::from(read);
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if file.read(&mut [0u8; 1]).unwrap_or(0) == 1 {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    let mut command = RunningCommand {
        id: 1,
        pid: Some(pid),
        group: pid,
        stdout: None,
        stderr: None,
        deadline: Instant::now() + Duration::from_secs(30),
        termination: Some((CommandOutcome::Cancelled, Instant::now())),
        reaped: None,
        drain_deadline: None,
    };
    assert!(command.tick().unwrap().is_none());
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut status = 0;
    let mut reaped = false;
    while Instant::now() < deadline {
        if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
            reaped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    if !reaped {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
    }
    assert!(
        reaped,
        "cancel missed its live foreground leader after setpgid"
    );
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    command.exited(status);
    assert_eq!(command.tick().unwrap(), Some(CommandOutcome::Cancelled));
}
