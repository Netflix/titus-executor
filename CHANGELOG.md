# Change Log

## [20180516.3](https://github.com/Netflix/titus-executor/tree/20180516.3) (2018-06-21)
[Full Changelog](https://github.com/Netflix/titus-executor/compare/20180516.2...20180516.3)

**Merged pull requests:**

- Change Environment to New Netflix Style [\#144](https://github.com/Netflix/titus-executor/pull/144) ([sargun](https://github.com/sargun))
- Fix MTU configuration [\#143](https://github.com/Netflix/titus-executor/pull/143) ([sargun](https://github.com/sargun))
- Jumbo frame support [\#142](https://github.com/Netflix/titus-executor/pull/142) ([sargun](https://github.com/sargun))
- Simpilify allocate done code [\#141](https://github.com/Netflix/titus-executor/pull/141) ([sargun](https://github.com/sargun))
- Add logging around allocation command termination [\#140](https://github.com/Netflix/titus-executor/pull/140) ([sargun](https://github.com/sargun))
- initial \(very simple\) PR template [\#139](https://github.com/Netflix/titus-executor/pull/139) ([fabiokung](https://github.com/fabiokung))

## [20180516.2](https://github.com/Netflix/titus-executor/tree/20180516.2) (2018-06-07)
[Full Changelog](https://github.com/Netflix/titus-executor/compare/20180516.0...20180516.2)

**Closed issues:**

- Make Generic Cancel Launch Test [\#117](https://github.com/Netflix/titus-executor/issues/117)

**Merged pull requests:**

- Sched batch [\#137](https://github.com/Netflix/titus-executor/pull/137) ([sargun](https://github.com/sargun))
- Allow adjusting Ip refresh timeout [\#136](https://github.com/Netflix/titus-executor/pull/136) ([sargun](https://github.com/sargun))
- Bump emergency shutdown window to 1 hour [\#135](https://github.com/Netflix/titus-executor/pull/135) ([sargun](https://github.com/sargun))
- Wait to send kill [\#134](https://github.com/Netflix/titus-executor/pull/134) ([sargun](https://github.com/sargun))
- Add gox to CI builder image [\#133](https://github.com/Netflix/titus-executor/pull/133) ([sargun](https://github.com/sargun))
- Remove Launchguard [\#132](https://github.com/Netflix/titus-executor/pull/132) ([sargun](https://github.com/sargun))
- Introduce OOM settings for containers [\#131](https://github.com/Netflix/titus-executor/pull/131) ([sargun](https://github.com/sargun))
- Bump titus proto definitions [\#130](https://github.com/Netflix/titus-executor/pull/130) ([sargun](https://github.com/sargun))
- Fix terminate timeout test [\#129](https://github.com/Netflix/titus-executor/pull/129) ([sargun](https://github.com/sargun))
- Bump the version of the Docker client image in Circle CI [\#128](https://github.com/Netflix/titus-executor/pull/128) ([sargun](https://github.com/sargun))
- Import executor/runtime/docker so it gets code coverage [\#127](https://github.com/Netflix/titus-executor/pull/127) ([sargun](https://github.com/sargun))

## [20180516.0](https://github.com/Netflix/titus-executor/tree/20180516.0) (2018-05-16)
[Full Changelog](https://github.com/Netflix/titus-executor/compare/20180516.1...20180516.0)

## [20180516.1](https://github.com/Netflix/titus-executor/tree/20180516.1) (2018-05-16)
[Full Changelog](https://github.com/Netflix/titus-executor/compare/20180119.0...20180516.1)

## [20180119.0](https://github.com/Netflix/titus-executor/tree/20180119.0) (2018-05-16)
[Full Changelog](https://github.com/Netflix/titus-executor/compare/20171231.0...20180119.0)

**Closed issues:**

- \[Q\] Can not compile titus-executor [\#93](https://github.com/Netflix/titus-executor/issues/93)
- Configure the Circle CI builder to only build the builder image sometimes [\#92](https://github.com/Netflix/titus-executor/issues/92)
- Make it so that the launchguard can be disabled / bypassed based on protobuf [\#31](https://github.com/Netflix/titus-executor/issues/31)
- Replace the configuration system with Viper [\#21](https://github.com/Netflix/titus-executor/issues/21)

**Merged pull requests:**

- Add logging to docker container setup process [\#124](https://github.com/Netflix/titus-executor/pull/124) ([sargun](https://github.com/sargun))
- Generate metatron credentials with IP address [\#122](https://github.com/Netflix/titus-executor/pull/122) ([sargun](https://github.com/sargun))
- Terminate during prepare [\#119](https://github.com/Netflix/titus-executor/pull/119) ([sargun](https://github.com/sargun))
- Add iputils-ping to ubuntu image [\#115](https://github.com/Netflix/titus-executor/pull/115) ([sargun](https://github.com/sargun))
- Move around test images [\#114](https://github.com/Netflix/titus-executor/pull/114) ([sargun](https://github.com/sargun))
- Add httpie to ubuntu docker image [\#113](https://github.com/Netflix/titus-executor/pull/113) ([sargun](https://github.com/sargun))
- Also push latest tag [\#112](https://github.com/Netflix/titus-executor/pull/112) ([sargun](https://github.com/sargun))
- Allow for custom registry [\#111](https://github.com/Netflix/titus-executor/pull/111) ([sargun](https://github.com/sargun))
- Remove argument asking whether or not to start web server [\#110](https://github.com/Netflix/titus-executor/pull/110) ([sargun](https://github.com/sargun))
- Change the executor state machine [\#109](https://github.com/Netflix/titus-executor/pull/109) ([sargun](https://github.com/sargun))
- Update titus-api-definitinitions to frozen-agent-version-20180508.0 [\#107](https://github.com/Netflix/titus-executor/pull/107) ([sargun](https://github.com/sargun))
- Friendlier metatron [\#106](https://github.com/Netflix/titus-executor/pull/106) ([sargun](https://github.com/sargun))
- Remove tmpfs at /run [\#105](https://github.com/Netflix/titus-executor/pull/105) ([sargun](https://github.com/sargun))
- darion: Use http.ServeContent for serving log data [\#102](https://github.com/Netflix/titus-executor/pull/102) ([cHYzZQo](https://github.com/cHYzZQo))
- Build PTY test image [\#101](https://github.com/Netflix/titus-executor/pull/101) ([sargun](https://github.com/sargun))
- Dynamically generate JOB IDs for standalone tests [\#99](https://github.com/Netflix/titus-executor/pull/99) ([sargun](https://github.com/sargun))
- Remove dependency on titus-bootstrap [\#98](https://github.com/Netflix/titus-executor/pull/98) ([sargun](https://github.com/sargun))
- Update build / make instructions [\#97](https://github.com/Netflix/titus-executor/pull/97) ([sargun](https://github.com/sargun))
- Remove all mentions of junit [\#96](https://github.com/Netflix/titus-executor/pull/96) ([sargun](https://github.com/sargun))
- Build docker images in Circle CI [\#95](https://github.com/Netflix/titus-executor/pull/95) ([sargun](https://github.com/sargun))
- containers get a tmpfs at /run by default [\#94](https://github.com/Netflix/titus-executor/pull/94) ([fabiokung](https://github.com/fabiokung))
- Nested containers \[WIP\] [\#91](https://github.com/Netflix/titus-executor/pull/91) ([sargun](https://github.com/sargun))
- Fix typo in readme [\#90](https://github.com/Netflix/titus-executor/pull/90) ([epickrram](https://github.com/epickrram))
- Update README.md [\#89](https://github.com/Netflix/titus-executor/pull/89) ([corindwyer](https://github.com/corindwyer))
- Enable IPv6 in the container [\#88](https://github.com/Netflix/titus-executor/pull/88) ([sargun](https://github.com/sargun))
- make the realtime sched policy for tini optional [\#87](https://github.com/Netflix/titus-executor/pull/87) ([fabiokung](https://github.com/fabiokung))
- Add circle CI config to build builder [\#85](https://github.com/Netflix/titus-executor/pull/85) ([sargun](https://github.com/sargun))
- Lazily initialize gpuinfo [\#83](https://github.com/Netflix/titus-executor/pull/83) ([sargun](https://github.com/sargun))
- Properly build tarball for distribution [\#81](https://github.com/Netflix/titus-executor/pull/81) ([sargun](https://github.com/sargun))
- make task to publish a titus-agent image to dockerhub [\#80](https://github.com/Netflix/titus-executor/pull/80) ([fabiokung](https://github.com/fabiokung))
- Fix nvidia Device Iterator Code [\#79](https://github.com/Netflix/titus-executor/pull/79) ([sargun](https://github.com/sargun))
- Remove Gradle [\#78](https://github.com/Netflix/titus-executor/pull/78) ([sargun](https://github.com/sargun))
- Red [\#77](https://github.com/Netflix/titus-executor/pull/77) ([sargun](https://github.com/sargun))
- Simplify protobuf management [\#76](https://github.com/Netflix/titus-executor/pull/76) ([sargun](https://github.com/sargun))
- Set TITUS\_NUM\_NETWORK\_BANDWIDTH to the network bandwidth available [\#75](https://github.com/Netflix/titus-executor/pull/75) ([sargun](https://github.com/sargun))
- Add cgroup cleanup code [\#74](https://github.com/Netflix/titus-executor/pull/74) ([sargun](https://github.com/sargun))
- Set bandwidth correctly for numbers greater than 2Gbps  [\#73](https://github.com/Netflix/titus-executor/pull/73) ([sargun](https://github.com/sargun))
- Refactor GC algorithm [\#72](https://github.com/Netflix/titus-executor/pull/72) ([sargun](https://github.com/sargun))
- Add mechanism to debug allocation in VPC driver [\#71](https://github.com/Netflix/titus-executor/pull/71) ([sargun](https://github.com/sargun))
- Deal with corrupted ipv4 addresses from the metadata service [\#70](https://github.com/Netflix/titus-executor/pull/70) ([sargun](https://github.com/sargun))
- Handle Launchguard while Simultaneous doing v2 / v3 engine [\#69](https://github.com/Netflix/titus-executor/pull/69) ([sargun](https://github.com/sargun))
- Fix the interface count that's exposed to the titus scheduler [\#67](https://github.com/Netflix/titus-executor/pull/67) ([sargun](https://github.com/sargun))
- Add a mechanism to generate the resource sets configuration [\#66](https://github.com/Netflix/titus-executor/pull/66) ([sargun](https://github.com/sargun))
- Multi executor [\#65](https://github.com/Netflix/titus-executor/pull/65) ([sargun](https://github.com/sargun))
- Set pid limit on container [\#64](https://github.com/Netflix/titus-executor/pull/64) ([sargun](https://github.com/sargun))
- Add more VPC debugging code [\#63](https://github.com/Netflix/titus-executor/pull/63) ([sargun](https://github.com/sargun))
- Upgrade tini to include tini handoff [\#61](https://github.com/Netflix/titus-executor/pull/61) ([sargun](https://github.com/sargun))
- Update R4.16xlarge bandwidth [\#60](https://github.com/Netflix/titus-executor/pull/60) ([sargun](https://github.com/sargun))
- Put the security convergence timeout behind an FP [\#59](https://github.com/Netflix/titus-executor/pull/59) ([sargun](https://github.com/sargun))
- Update m4.16xl max network throughput [\#58](https://github.com/Netflix/titus-executor/pull/58) ([sargun](https://github.com/sargun))
- Make fslocker \(unlock\) idempotent, and unlock allocation lock during GC earlier [\#57](https://github.com/Netflix/titus-executor/pull/57) ([sargun](https://github.com/sargun))
- Pass through logging from titus-vpc-tool [\#56](https://github.com/Netflix/titus-executor/pull/56) ([sargun](https://github.com/sargun))
- More vpc logging [\#55](https://github.com/Netflix/titus-executor/pull/55) ([sargun](https://github.com/sargun))
- Use random interface names to avoid concurrency issues [\#54](https://github.com/Netflix/titus-executor/pull/54) ([sargun](https://github.com/sargun))
- Add more VPC logging [\#53](https://github.com/Netflix/titus-executor/pull/53) ([sargun](https://github.com/sargun))
- Start refactoring the executor to further split up Docker and runtime… [\#52](https://github.com/Netflix/titus-executor/pull/52) ([sargun](https://github.com/sargun))
- Sync github.com/vishvananda/netlink with origin/master [\#51](https://github.com/Netflix/titus-executor/pull/51) ([sargun](https://github.com/sargun))
- Retry making directory to avoid race condition with simultaneous dire… [\#50](https://github.com/Netflix/titus-executor/pull/50) ([sargun](https://github.com/sargun))
- Make mark phase of global GC more tolerant to eventual consistency [\#49](https://github.com/Netflix/titus-executor/pull/49) ([sargun](https://github.com/sargun))
- Make VPC error logging better [\#48](https://github.com/Netflix/titus-executor/pull/48) ([sargun](https://github.com/sargun))
- Update fq codel quantum [\#46](https://github.com/Netflix/titus-executor/pull/46) ([sargun](https://github.com/sargun))
- Allow user to set mime types on log file upload via xattr [\#45](https://github.com/Netflix/titus-executor/pull/45) ([sargun](https://github.com/sargun))
- Make packet dropping less aggressive on titus-vpc-tool [\#44](https://github.com/Netflix/titus-executor/pull/44) ([sargun](https://github.com/sargun))
- Restore existing launchguard behaviour and wait for allocation to be … [\#43](https://github.com/Netflix/titus-executor/pull/43) ([sargun](https://github.com/sargun))
- Cleanup Launchguard test [\#41](https://github.com/Netflix/titus-executor/pull/41) ([sargun](https://github.com/sargun))
- Launchguard server [\#40](https://github.com/Netflix/titus-executor/pull/40) ([sargun](https://github.com/sargun))
- Make nvidia code ready for multi-executor [\#39](https://github.com/Netflix/titus-executor/pull/39) ([sargun](https://github.com/sargun))
- Add mechanism to disable journald logging when executing titus-vpc-tool [\#38](https://github.com/Netflix/titus-executor/pull/38) ([sargun](https://github.com/sargun))
- Bump trap image to exit in 2 minutes, not just 30s [\#37](https://github.com/Netflix/titus-executor/pull/37) ([sargun](https://github.com/sargun))
- Add Global GC mechanism [\#36](https://github.com/Netflix/titus-executor/pull/36) ([sargun](https://github.com/sargun))
- Fix container hostname setting [\#35](https://github.com/Netflix/titus-executor/pull/35) ([sargun](https://github.com/sargun))
- Add better error messages to testLaunchAfterKill [\#34](https://github.com/Netflix/titus-executor/pull/34) ([sargun](https://github.com/sargun))
- Add initial code to disable launchguard [\#33](https://github.com/Netflix/titus-executor/pull/33) ([sargun](https://github.com/sargun))
- Add agent protobuf with disable launchguard [\#32](https://github.com/Netflix/titus-executor/pull/32) ([sargun](https://github.com/sargun))
- Disable atlas agent during testing [\#30](https://github.com/Netflix/titus-executor/pull/30) ([sargun](https://github.com/sargun))
- Bump golang.org/x/sys/unix [\#28](https://github.com/Netflix/titus-executor/pull/28) ([sargun](https://github.com/sargun))
- Bump protodefs [\#27](https://github.com/Netflix/titus-executor/pull/27) ([sargun](https://github.com/sargun))
- no entrypoint or command during container.Create should yield FAILED [\#26](https://github.com/Netflix/titus-executor/pull/26) ([fabiokung](https://github.com/fabiokung))
- Networking [\#25](https://github.com/Netflix/titus-executor/pull/25) ([sargun](https://github.com/sargun))

## [20171231.0](https://github.com/Netflix/titus-executor/tree/20171231.0) (2018-01-08)
[Full Changelog](https://github.com/Netflix/titus-executor/compare/20171031.1...20171231.0)

**Merged pull requests:**

- Do not run go vet independently of gometalinter [\#24](https://github.com/Netflix/titus-executor/pull/24) ([sargun](https://github.com/sargun))
- Use fmt.Fprint where possible, instead of fmt.Fprintf [\#23](https://github.com/Netflix/titus-executor/pull/23) ([sargun](https://github.com/sargun))
- Fix build [\#20](https://github.com/Netflix/titus-executor/pull/20) ([sargun](https://github.com/sargun))
- Fix renewal of IAM credentials [\#18](https://github.com/Netflix/titus-executor/pull/18) ([sargun](https://github.com/sargun))

## [20171031.1](https://github.com/Netflix/titus-executor/tree/20171031.1) (2017-11-17)
[Full Changelog](https://github.com/Netflix/titus-executor/compare/20171031.0...20171031.1)

**Merged pull requests:**

- Fix metadata proxy credential caching behaviour [\#17](https://github.com/Netflix/titus-executor/pull/17) ([sargun](https://github.com/sargun))
- Fail on no entrypoint, don't crash [\#16](https://github.com/Netflix/titus-executor/pull/16) ([sargun](https://github.com/sargun))
- Update quitelite-client-go [\#15](https://github.com/Netflix/titus-executor/pull/15) ([sargun](https://github.com/sargun))
- try to determine EC2 region [\#14](https://github.com/Netflix/titus-executor/pull/14) ([sargun](https://github.com/sargun))
- Warn on non-fatal errors while getting routes [\#13](https://github.com/Netflix/titus-executor/pull/13) ([sargun](https://github.com/sargun))
- Add build instructions [\#12](https://github.com/Netflix/titus-executor/pull/12) ([sargun](https://github.com/sargun))
- Add configuration capability to systemd units [\#11](https://github.com/Netflix/titus-executor/pull/11) ([sargun](https://github.com/sargun))
- Handle if LIBPROCESS\_IP or LIBPROCESS\_PORT is not set [\#10](https://github.com/Netflix/titus-executor/pull/10) ([sargun](https://github.com/sargun))
- Build debugging [\#9](https://github.com/Netflix/titus-executor/pull/9) ([sargun](https://github.com/sargun))
- Remove extra env [\#8](https://github.com/Netflix/titus-executor/pull/8) ([sargun](https://github.com/sargun))
- Unnumbered address [\#7](https://github.com/Netflix/titus-executor/pull/7) ([sargun](https://github.com/sargun))
- Fix the redirect behaviour around the IAM endpoints for the metdata p… [\#6](https://github.com/Netflix/titus-executor/pull/6) ([sargun](https://github.com/sargun))
- Add provides -dev for all non-master builds [\#5](https://github.com/Netflix/titus-executor/pull/5) ([sargun](https://github.com/sargun))

## [20171031.0](https://github.com/Netflix/titus-executor/tree/20171031.0) (2017-10-31)
[Full Changelog](https://github.com/Netflix/titus-executor/compare/1.0...20171031.0)

**Merged pull requests:**

- Add buildkite pipeline config to repo [\#4](https://github.com/Netflix/titus-executor/pull/4) ([sargun](https://github.com/sargun))
- Run more tests simultaneously [\#3](https://github.com/Netflix/titus-executor/pull/3) ([sargun](https://github.com/sargun))
- Buildkite [\#2](https://github.com/Netflix/titus-executor/pull/2) ([sargun](https://github.com/sargun))

## [1.0](https://github.com/Netflix/titus-executor/tree/1.0) (2017-10-26)


\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*