{
  // For SSH, just because you are allowed to have SYS_ADMIN doesn't mean you
  // can do other related dangerous syscalls!
  BlockSyadminSyscalls: {
    action: 'SCMP_ACT_ALLOW',
    includes: {
      caps: [
        'CAP_SYS_ADMIN',
      ],
    },
    names: [
      'bpf',
      'clone',
      'fanotify_init',
      'fsconfig',
      'fsmount',
      'fsopen',
      'fspick',
      'lookup_dcookie',
      'mount',
      'move_mount',
      'name_to_handle_at',
      'open_tree',
      'perf_event_open',
      'quotactl',
      'setdomainname',
      'sethostname',
      'setns',
      'syslog',
      'umount',
      'umount2',
      'unshare',
    ],
  },
  // For Perf-Enabled Profiles, we need to actually allow bpf and perf, if they are SYS_ADMIN
  AllowPerfAndBPF: {
    action: 'SCMP_ACT_ALLOW',
    names: [
      'bpf',
      'perf_event_open',
    ],
  },
  // Fuse containers need to be allowed to actually run these syscalls
  AllowFuseRelatedSyscalls: {
    action: 'SCMP_ACT_ALLOW',
    names: [
      'clone',
      'fsconfig',
      'fsmount',
      'fsopen',
      'fspick',
      'keyctl',
      'mount',
      'move_mount',
      'umount',
      'umount2',
      'unshare',
    ],
  },
}
