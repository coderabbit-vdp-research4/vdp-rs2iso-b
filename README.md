# vdp-rs2iso-b

Authorized CodeRabbit VDP research fixture (own account `coderabbit-vdp-research4`, own repos only).
Purpose: F-RUNNERSINKS-02 task 2 — test whether two concurrent review-tool-runner jobs share any
mutable location (filesystem, process namespace, environment, credential material, egress identity).

The module in `mdx/` executes at review time via a markdownlint `customRules` entry and: writes a
run-specific marker (`ISO_<time36>_<rand36>`) to candidate shared locations (/tmp, /dev/shm,
/var/tmp, $HOME) and to fixed shared files there; polls those locations for ~30 seconds for any
marker that is not its own (i.e. a sibling job's); and reports only markers, hashes and counts.
It does not use any credential, does not touch the network except the OAST collector, and reads no
content belonging to any other account.
