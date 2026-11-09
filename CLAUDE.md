# Instructions for Claude

## Keep the documentation up to date with every change

Every change to this repository must update all the documentation it affects,
in the same commit or pull request. A change is not finished until its
documentation is. Before you finish, check each of these and update what the
change touches:

- `README.md`: features, installation steps, examples, configuration,
  tutorials, module overview and caveats. Code examples must still compile
  against the new code, and version numbers in examples must name the current
  release.
- `CHANGELOG.md`: describe the change under the next version.
- Haddock in `src`.
- Module headers and declaration comments: add Haddock for every new
  declaration, and fix comments that the change made wrong.

If a change needs no documentation update, say so explicitly when you report
the change, with the reason.

## How to write documentation here

Documentation explains the purpose and spirit of the code, not only its
behaviour. For every module and every significant type or function, say what
problem it solves and why it is designed the way it is, including the trade-offs
and the alternatives it rejects. A reader should come away knowing when to use
it and when not to. Keep to the structure the README already has, and put new
material in the section where a reader would look for it.

## Line length

Every line of code must be shorter than 120 columns. This covers Haskell
source, tests, `package.yaml` and cabal files, CI workflows, scripts, and the
code examples in the documentation. Break long expressions, type signatures
and import lists over several lines rather than letting them run on.

- **Long strings:** split them over several lines in the least cluttered way
  that works. Pick the form that leaves the fewest quotes, backslashes and
  operators on the page:
  - `unwords [...]` or `unlines [...]` for messages and prose, one piece per
    line;
  - string gaps for text that has to stay a single literal, with a backslash
    at the end of one line and another at the start of the next:

    ```haskell
    msg =
      "The first part of a long message, \
      \and the rest of it."
    ```

  - `<>` only when neither of those reads better.
- **Long constants:** split them too, even when they have no natural break,
  such as hexadecimal test vectors, keys, hashes and base64 data. Cut them into
  pieces of equal width so that they line up, and join them with string gaps
  or `mconcat`.
- **Exceptions:** sometimes a line cannot be split because of a limitation of
  the language or of a tool, for example a generated file such as
  `stack.yaml.lock`, a URL or other value that a tool reads only on one line,
  or a format with no way to continue a line. Leave such lines long, but keep
  them rare, and add a comment explaining why where the format allows one.

## Embedded scripts

Put multi-line scripts in their own files whenever possible, rather than
embedding them in other files: for example, move a long `run:` block of a
GitHub Actions workflow into a script under `scripts/` and call it from the
workflow. A script in its own file can be read, linted and run on its own.

When a script has to stay embedded, lay it out to be read: one command per
line, indentation that shows its structure, a comment for any step that is not
obvious, and no long chains of commands joined with `&&` or `;` on one line.

## Checks

Build the documentation with `stack haddock --no-haddock-deps` and make sure it
has no warnings about broken markup. CI builds it too, both with the OS
libraries and with `stack --nix`.

List the lines of 120 columns or more with
`git ls-files '*.hs' '*.yaml' '*.cabal' '*.md' | xargs grep -n '.\{120,\}'`,
and fix every one that is code and is not one of the exceptions above.
