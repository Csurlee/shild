# Third-party code

This project's own code (`plugins/Shild/`, `plugins/WebPanel/`, `plugins/GitHubWatch/`,
`plugins/Weather/`, `plugins/SpamGuard/` except where noted below, `shildml/`, `scripts/`, and
`install.sh`) is original work, licensed under this repository's own [`LICENSE`](LICENSE) (MIT).

The following files/directories are vendored from other projects, under their own separate
licenses. Each file's own header carries the authoritative license text — this is a summary index,
not a substitute for reading it. In every case, the vendor's own required copyright notice and
license text remain intact in the file itself, as their licenses require.

| Path | License | Copyright | Source |
|---|---|---|---|
| `plugins/UndernetX/` | BSD-3-Clause | © 2017 Ken Spencer, © 2020 oddluck | [oddluck/limnoria-plugins](https://github.com/oddluck/limnoria-plugins) |
| `plugins/ChannelStats/` | BSD-3-Clause | © 2002-2021 Jeremiah Fincher, James McCoy, Valentin Lorentz | Bundled with [Limnoria](https://github.com/progval/Limnoria), patched here (see file headers for what changed) |
| `plugins/Misc/` | BSD-3-Clause | © 2002-2022 Jeremiah Fincher, James McCoy, Valentin Lorentz | Bundled with [Limnoria](https://github.com/progval/Limnoria), patched here (see file headers for what changed) |
| `plugins/SpamGuard/mojibake.py` | MIT | © 2013-2018 Robyn Speer | [rspeer/python-ftfy](https://github.com/rspeer/python-ftfy), via [Libera-Chat/ozone](https://github.com/Libera-Chat/ozone) |

`ChannelStats` and `Misc` are patched, not verbatim -- each file's own header/docstring notes what
was changed from the upstream Limnoria version. `UndernetX` is a mix: the original vendored
login/auth machinery is unmodified, with newer additions (credential command, manual X commands,
reply correlation) clearly marked by a `# shild-py additions` comment in each affected file.

This project also depends on, but does not vendor or redistribute, [Limnoria](https://github.com/progval/Limnoria)
itself (BSD-3-Clause) -- it's installed as an ordinary pip dependency (see `pyproject.toml`), never
copied into this repository.
