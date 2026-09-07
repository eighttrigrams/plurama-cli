.PHONY: test dist install uninstall clean

# Where `dist` writes. **A directory, not a file** — which is the one place this
# diverges from `us-vs-them/Makefile`, whose `DIST` names the single script it
# builds. There are three here, and the private deploy script wants them side by
# side in a staging directory it then bakes credentials into, so
# `make dist DIST=$STAGE` is the call that matters and it has to be able to name
# a place rather than a file.
#
# The filenames inside it are the command names, not the source names:
# `plurama-cli`, not `plurama_cli.clj`. That is deliberate — `plurama_cli.clj`
# reads its own name off `babashka.file` to write its help, so what the file is
# called is user-visible, and a staged artifact called `plurama_cli.clj` would
# make the tool announce itself as a filename.
DIST ?= target

# ---------------------------------------------------------------------------
# Why there is a build here at all.
#
# `cookbook_seal.clj` is the encryption envelope, and it is one namespace shared
# by `plurama_cli.clj` and `cookbook_tui.clj` rather than ~150 lines copied into
# each — its own docstring argues that at length, and the short version is that
# two copies of an envelope drifting costs a Recipe nobody can open, and a
# fixture cannot police a copy inlined into a `-main` script.
#
# The cost of that decision is exactly this file. `bb.edn` puts the seal on the
# classpath for a checkout, so from here nothing has to be done. But `bbin`
# installs a *single file*, and a lone `plurama_cli.clj` on a PATH cannot find
# `cookbook_seal.clj` anywhere — babashka refuses to start with
#
#     Could not locate cookbook_seal.bb, cookbook_seal.clj or cookbook_seal.cljc
#
# which is loud, immediate, and was for a while what `make deploy-cli` did. The
# seal's docstring names the fix: concatenate the namespace before each script
# that requires it, "which is exactly what it already does for `us-vs-them`".
# `bb uberscript` *is* that concatenation, so this is the same target that repo
# has, and the flattened script is a thing you can copy — onto a PATH, into a
# container, over an ssh connection — rather than something that only runs where
# this directory happens to sit.

# ---------------------------------------------------------------------------
# `-e (require ...)` rather than `-m`, and this is not a style choice.
#
# `us-vs-them` builds with `-m et.uvt.cli`, which makes `uberscript` append
# `(apply et.uvt.cli/-main *command-line-args*)` to the end of the collected
# file. That is right there, because `cli.clj` has a `-main` and nothing else.
#
# All three scripts here end instead in the self-invoking guard
#
#     (when (= *file* (System/getProperty "babashka.file"))
#       (apply -main *command-line-args*))
#
# which is what lets `bb plurama_cli.clj treina /describe` work from a checkout
# while the same file stays requirable by a test suite. **In an uberscript
# `*file*` *is* `babashka.file`** — both are the path of the collected script —
# so the guard fires, and a `-m` build then calls `-main` a *second* time from
# the appended form.
#
# `plurama_cli.clj` gets away with that by accident: every branch of its `-main`
# ends in `System/exit`, so the process is gone before the second call. The other
# two do not. A `-m` build of `cookbook_tui.clj` prints `bye`, returns from
# `-main`, and **starts the TUI again** — measured, not reasoned: `q` twice
# gives two `bye`s from a `-m` build and one from this one. A `-m` build of the
# walker would print its help twice.
#
# So the entry point stays the guard the sources already have, and `-e` is how
# `uberscript` is told which namespaces to collect without also being told to
# call anything. Do not "simplify" this to `-m`; the tests that would catch it
# are the ones nobody runs against a built artifact.
#
# $(1) namespace, $(2) output path
define flatten
@mkdir -p $(dir $(2))
bb --classpath . uberscript $(2).tmp -e "(require '[$(1)])"
@printf '#!/usr/bin/env bb\n' | cat - $(2).tmp > $(2)
@rm -f $(2).tmp
@chmod +x $(2)
endef

# The deploy script substitutes a base64 credential blob into the built artifact
# **after** this runs, by finding the literal string below. So the flattening
# must carry it through untouched, and that is a property of `bb uberscript`
# rather than of anything here — it happens to emit the string form verbatim
# today. Asserted rather than trusted: if a future babashka ever normalised
# string literals, the deploy script would silently install a binary with no
# credentials and every call would fall back to a `credentials.edn` that is not
# there. Exactly one, because two would mean the source grew a second marker and
# the deploy script's `awk` only replaces what it finds.
#
# $(1) built artifact
define assert-marker
@n=$$(grep -c '__BAKED_CREDENTIALS__' $(1)) ; \
 test "$$n" = 1 || { \
   echo "$(1): expected exactly one __BAKED_CREDENTIALS__ marker, found $$n." >&2 ; \
   echo "The deploy script bakes credentials by substituting that literal;" >&2 ; \
   echo "without it the installed binary has no credentials at all." >&2 ; \
   exit 1 ; }
endef

# ---------------------------------------------------------------------------
# The three artifacts.
#
# Two of them are installed on a PATH by the private
# `deploy-plurama-cli-cookbook-tui-and-us-vs-them-cli.sh`, which builds them
# here and then bakes a credential blob into each. `plurama-cli` is baked three
# times over, from this one artifact: the full map, a restricted map for the
# devboxes, and the proxy's.
#
# The third, `cookbook-seal-migrate`, is **not** installed, and the README says
# why: "it is not a thing anybody runs twice." It is built anyway, for one
# reason — it requires the seal like the other two, so it has the same problem,
# and it is the one irreversible operation in the project. It runs against a
# database *file*, which means it runs wherever that file is, and needing a
# checkout (plus `bb.edn`, plus a working directory) at that moment is a
# constraint that buys nothing. A single script you can `scp` next to the
# backup you are about to seal is the better shape. The deploy script names what
# it installs, so an extra file in the staging directory costs nothing.
#
# Note for whoever ships it: its `--help` still says `bb cookbook_seal_migrate.clj
# … DATABASE`, because that is the invocation the README documents. The built
# artifact is invoked by its own name. Left alone rather than fixed here, since
# the walker's text is a closed step.
dist: $(DIST)/plurama-cli $(DIST)/cookbook-tui $(DIST)/cookbook-seal-migrate

$(DIST)/plurama-cli: plurama_cli.clj cookbook_seal.clj
	$(call flatten,plurama-cli,$@)
	$(call assert-marker,$@)

$(DIST)/cookbook-tui: cookbook_tui.clj cookbook_seal.clj
	$(call flatten,cookbook-tui,$@)
	$(call assert-marker,$@)

# No marker here: the walker takes no credentials. Its key comes from the
# environment or a file at run time, and it refuses to run without one.
$(DIST)/cookbook-seal-migrate: cookbook_seal_migrate.clj cookbook_seal.clj
	$(call flatten,cookbook-seal-migrate,$@)

# ---------------------------------------------------------------------------
# Installing from here installs the tools **unbaked**, which is a real thing to
# want and not the usual thing.
#
# It is the README's public install path — the one that used to read `bbin
# install https://raw.githubusercontent.com/…/plurama_cli.clj` and has been
# broken since the seal landed, because that URL is one file and the tool is now
# two. Installed this way the binaries carry the literal marker, so
# `decode-baked` answers `nil` and they read
# `~/.config/plurama-cli/credentials.edn` instead. That file is a plaintext
# password store; treat it accordingly.
#
# The owner's install is the private deploy script, which builds these same
# artifacts and bakes the credentials out of `secrets.yaml` into them. If you
# have that script, use it; this target will quietly give you a binary with no
# passwords in it.
#
# Installing the built script rather than the project, deliberately, for the
# reason `us-vs-them/Makefile` gives: `bbin install .` puts a *loader* on your
# PATH that shells back into this directory, which is convenient while you are
# working here and useless the moment the tool has to run anywhere else. The
# cost is that it is a snapshot — edit the source and run this again.
install: dist
	bbin install $(DIST)/plurama-cli --as plurama-cli
	bbin install $(DIST)/cookbook-tui --as cookbook-tui

uninstall:
	bbin uninstall plurama-cli
	bbin uninstall cookbook-tui

# ---------------------------------------------------------------------------
# The suites live in `bb.edn`, which is also where what each of them needs is
# written down — a sibling cookbook checkout for the shared test vectors, and
# `sqlite3` on PATH for the walker. This is here so that the Makefile is one
# door rather than half of one.
test:
	bb test

# Only the files this builds, never `$(DIST)` itself. `DIST` is a directory and
# it is routinely pointed somewhere else — a `rm -rf` of an overridden staging
# path is a footgun waiting for the one time it names a directory with something
# else in it.
clean:
	rm -f $(DIST)/plurama-cli $(DIST)/cookbook-tui $(DIST)/cookbook-seal-migrate
	rm -f $(DIST)/plurama-cli.tmp $(DIST)/cookbook-tui.tmp $(DIST)/cookbook-seal-migrate.tmp
