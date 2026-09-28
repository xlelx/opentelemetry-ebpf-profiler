# Upstream PR 1829 exact-revision benchmark

- Baseline: upstream `main` at `a85d8675` using tracepoint + `finish_task_switch` kprobe
- Candidate: PR head `eb1a2e91` using tracepoint-only off-CPU profiling
- Host: `qa-mydev--0f5c1ce1741c0d7c4.northwest.stripe.io` (16-vCPU ARM64)
- Workload: `stress-ng` on all CPUs at 50% target load
- Design: three randomized repetitions of every revision × threshold combination
- Window: 15s warmup + 60s measurement
- Thresholds: 0, 0.01, 0.05, 0.1, 0.25, 0.5, 1
- Baseline binary SHA-256: `d7b79a1fcd50ff1f28ffb914bf7413ed14bd621cfb851167508b2bed42f9312a`
- Candidate binary SHA-256: `54b9c00913cee00e5308b9f842409da2a72d2a0ed309b30e29c6796bf63b4d28`

## Result

Across positive thresholds, the tracepoint-only candidate used
32.4%–79.2% less direct off-CPU BPF core time.
After normalizing total off-CPU BPF runtime by the observed system-wide context-switch count,
it used 29.7%–76.3% fewer nanoseconds per context switch.

The context-switch count is an observed system-wide outcome, not controlled work. Raw counts and
runqueue histogram buckets are included for transparency but are not used to claim a latency improvement.
The full workbook contains every raw BPF program, perf, cgroup, and runqlat measurement.
