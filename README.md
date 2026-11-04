# bugnet-run

The in-sandbox command runner and its frame format.

Run `make test`, `make lint` and `make build`. `make build` also writes static Linux binaries to
`dist/bugnet-run-linux-amd64` and `dist/bugnet-run-linux-arm64`.

`attach --job <id> --out <n> --err <n>` follows a job from the given offsets. With `--tail <n>` it
sends each second only the newest `n` bytes of each output, writing a `skip` frame whose `o` and
`e` name the offsets the output goes on from; the skipped bytes stay in the job's files.
