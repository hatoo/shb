# Accepted HPACK prefix experiment (historical, 2026-10-08)

Inline the validated integer prefix and outline the unchanged continuation loop.
Same fixed-server client-limited workload and build as accepted-release-lto.md.
Relative to full-LTO client, three initial HTTP/2 pairs:
5,456,319 -> 5,707,217 rps (+4.60%); +2.23%, +1.87%, +4.60%.
Independent five-pair confirmation: 5,401,050 -> 5,730,774 (+6.10%);
pairs +5.32%, +6.10%, +3.60%, +5.72%, +7.09%. Zero errors.
Default tests, 51 release integrations and independent body/backpressure checks passed.
2026-10-09 c38 revalidation: 301 unit + 51 integrations pass; two ignored.
These historical series cannot be multiplied to estimate combined improvement.
Direct historical original-to-final results: HTTP/2 +6.50%, HTTP/3 +5.59%.
No fresh throughput comparison claimed during c38.
