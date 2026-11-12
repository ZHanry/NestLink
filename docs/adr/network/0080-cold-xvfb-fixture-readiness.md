# 0080 — Bound cold Xvfb readiness before resident acceptance

Source `9340894226589e8c4566c76e029de41492fd2de4`, Rust-core run
[43232680889](https://github.com/ZHanry/NestLink/actions/runs/43232680889),
failed the first original resident case before constructing its business
fixture. The early Linux artifact `13952371284`, SHA-256
`6dfc1693af4a4c503193e77a427118587b8845cf2e327022a74327c33d716bed`,
records `original Xvfb display deadline`; the other six cases passed. The
previous main run `43222192043` had the same first-case construction failure.
The exact cause inside the hosted X server has not been established.

The fixture had allowed only five seconds for an independently spawned Xvfb
to publish its real display number. Give this infrastructure initialization
a finite fifteen-second bound, log elapsed readiness time and child PID, and
on timeout log the actual child status. Keep a single spawn, the original
authenticated displayfd readiness, exclusive platform ownership, cancellation
and physical process reaping. There is no retry or prewarmed replacement.

This explicitly changes the Xvfb setup timeout from five to fifteen seconds.
It does not change the product, resident service lifetime, authorization,
pixel/file assertions, renewal budgets, cleanup bounds or the browser's
steady media observation. A setup failure still fails the test. New exact-source
hosted executions of both the original resident suite and constructor ownership
tests are required before release; earlier failed runs remain evidence.
