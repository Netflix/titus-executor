local stock = import 'stock.docker.json';
local titus = import 'titus.libsonnet';

local original_syscalls = stock.syscalls;
local new_syscalls = [titus.AllowPerfAndBPF] + [titus.BlockSyadminSyscalls] + [titus.ForceAllowSyscalls] + original_syscalls;

local new = stock {
  syscalls: new_syscalls,
};
new
