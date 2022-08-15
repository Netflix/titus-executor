local stock = import 'stock.docker.json';
local titus = import 'titus.libsonnet';

local original_syscalls = stock.syscalls;
local new_syscalls = [titus.AllowImageBuildingSyscalls] + [titus.BlockSyadminSyscalls] + [titus.AllowClone3] + original_syscalls;

local new = stock {
  syscalls: new_syscalls,
};
new
