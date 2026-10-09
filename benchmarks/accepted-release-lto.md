# Accepted release LTO experiment (historical, 2026-10-08)

Full LTO and one codegen unit preserve request accounting and latency sampling.
Fixed hfast; WSL2 Ryzen 3950X; client CPU8, server CPU0, one worker each,
16 connections, 64 streams, 13-byte response, batch-linger 1, timeout 2s.
Release locked builds; alternating 10-second runs after warmup.
HTTP/2 A/A: CV 1.62%, median absolute pair 1.83%, maximum 3.80%, zero errors.
Initial three pairs: 5,481,158 -> 5,721,218 rps (+4.38%);
pairs +2.58%, +4.38%, +8.21%.
Independent five-pair confirmation: 5,361,916 -> 5,724,379 (+6.76%);
pairs +6.47%, +11.12%, +6.14%, +6.18%, +0.82%. Zero errors.
HTTP/3 confirmation: 2,583,149 -> 2,697,457 (+4.43%);
pairs +4.01%, +2.54%, +4.43%, +5.49%, +8.17%, zero errors.
Historical correctness includes default suites and 51 release interoperability tests.
2026-10-09 c38 revalidation: 301 unit + 51 integration tests pass; two ignored.
These are historical client-limited results, not fresh c38 gains or server maxima.
Full experiment history and raw reports remain in local OPTIMIZATION.md and
optimization-results/. No HTTP/1.1 improvement established.
