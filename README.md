# layerghost

Find secrets that a Dockerfile *deletes* but the image still ships.

`RUN rm id_rsa` does not remove anything from an image. It adds a whiteout on top of the layer that
holds the file, and anyone who pulls the image can extract the earlier layer. The same goes for build
args (`docker history` shows them), `ENV` credentials, and builder stages that get copied wholesale
into the runtime image. `layerghost` statically replays a Dockerfile layer by layer and tells you
which secret bytes survive into the image you actually ship.

Offline, stdlib-only Python 3.8+, no Docker daemon needed.

## What's novel

Most Dockerfile linters look at one instruction at a time. `layerghost` keeps a per-stage model of
the filesystem across layers, so it can reason about *lifetimes*:

- **Cross-layer ghosts.** A file added in one layer (`COPY`, `ADD`, or a `RUN` that writes it with `>`,
  `-o`, `tee`, `cp`, `ssh-keygen -f`) and removed in a later layer is flagged. Create, use, and delete
  inside a single `RUN` is recognized as safe.
- **Stage-aware severity.** It knows which stages ship. A ghost in a throwaway builder stage is `low`;
  the same ghost in the final stage, or in a stage the final one is built `FROM`, is `high`.
  `--target` picks the stage you actually build.
- **Carry tracking through `COPY --from`.** If the builder still holds `.npmrc` or `.env` when the
  runtime stage does `COPY --from=builder /src /app`, it reports the secret at its new path. If the
  builder deleted it inside the same `RUN`, it stays quiet.
- **Build-context awareness.** Point `--context` at the build directory (default is the Dockerfile's
  folder) and `COPY . .` expands to the real files, filtered by `.dockerignore`, so an un-ignored
  `.env` or `certs/server.key` shows up by name.
- **Secret mounts are clean.** `RUN --mount=type=secret` and `--mount=type=ssh` never touch a layer
  and are not flagged.

## Rules

| Rule  | What it catches |
|-------|-----------------|
| LG001 | Secret file added in one layer and removed in a later one (bytes still in the image) |
| LG002 | Secret-named `ARG` expanded in a `RUN` (recorded in build history), or given a literal default |
| LG003 | Secret-named `ENV` baked into image config |
| LG004 | Secret file still present in the final filesystem (e.g. from `COPY . .`) |
| LG005 | Secret file carried out of a builder stage by `COPY --from` |

Use `--bloat` to also report non-secret files deleted in later layers (wasted image size, `info`).

## Install

```bash
pip install git+https://github.com/rashedhasan090/layerghost
# or, from a checkout
python -m layerghost path/to/Dockerfile
```

## Usage

```bash
layerghost Dockerfile                         # text report
layerghost Dockerfile --context . --target prod
layerghost Dockerfile --format json           # machine-readable
layerghost Dockerfile --format md             # paste into a PR comment
layerghost Dockerfile --fail-on high          # exit 1 in CI if anything high
```

## Demo

`examples/ctx/` is a tiny build context with a fake `id_rsa`, `.env`, and `.npmrc` and this Dockerfile:

```dockerfile
ARG NPM_TOKEN
FROM node:20 AS builder
WORKDIR /src
ARG NPM_TOKEN
COPY .npmrc ./
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" >> .npmrc && npm ci
COPY id_rsa /root/.ssh/id_rsa
RUN git clone git@github.com:acme/private-lib.git && rm -f /root/.ssh/id_rsa
COPY . .
RUN npm run build

FROM node:20-slim AS runtime
ENV SENTRY_AUTH_TOKEN=sk_live_example_not_real
WORKDIR /app
COPY --from=builder /src /app
RUN rm -f /app/.npmrc
RUN --mount=type=secret,id=gh_token GH=$(cat /run/secrets/gh_token) ./fetch-assets.sh
CMD ["node", "dist/server.js"]
```

```
$ python -m layerghost examples/ctx/Dockerfile
examples/ctx/Dockerfile: 2 stage(s), final=runtime, 6 finding(s)
  [HIGH  ] LG003 line 13 stage runtime  ENV SENTRY_AUTH_TOKEN
  [HIGH  ] LG001 line 15 stage runtime  /app/.npmrc
           COPY --from=builder (it was added to /src/.npmrc at line 9) puts /app/.npmrc in a layer
           at line 15; the RUN rm at line 16 only hides it, the bytes stay in the final image
  [HIGH  ] LG005 line 15 stage runtime  /app/.env
  [HIGH  ] LG005 line 15 stage runtime  /app/id_rsa
  [LOW   ] LG002 line 6 stage builder  ARG NPM_TOKEN
  [LOW   ] LG001 line 7 stage builder  /root/.ssh/id_rsa
```

The full output with fixes is in [`examples/report.txt`](examples/report.txt). Notice what it does
*not* flag: the secret mount on line 17, and the builder's `id_rsa` ghost is only `low` because the
builder's layers never ship. The real leak is that `COPY . .` dragged `id_rsa` and `.env` from the
build context into `/src`, and `COPY --from=builder /src` carried them into production.

## Tests

```bash
python -m unittest discover -s tests
```

## Limits

This is static analysis. Shell parsing is heuristic (redirects, `-o`, `tee`, `cp`, `rm`), variables in
paths are not expanded, and `ADD` of remote URLs or archives is not unpacked. It flags what the
Dockerfile says, so pair it with an image scanner when you need ground truth on a built image.

## License

MIT
