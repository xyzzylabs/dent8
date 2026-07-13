# dent8 paper (arXiv-ready LaTeX)

`dent8.tex` is the LaTeX version of the technical whitepaper — the same content published on
the docs site ([Understanding dent8 → Whitepaper](https://xyzzylabs.github.io/dent8/whitepaper/),
source in [`docs/whitepaper.md`](../docs/whitepaper.md)), formatted as a single-column arXiv
article. The docs page is the human-editable source of truth for the prose; this file mirrors
it for a citable PDF / arXiv preprint.

## Build

No external bibliography processor is needed — the references are an embedded
`thebibliography`, so two LaTeX passes resolve them:

```sh
latexmk -pdf dent8.tex     # or: pdflatex dent8.tex && pdflatex dent8.tex
```

Needs a standard TeX Live (`texlive-latex-recommended` + `texlive-fonts-recommended` is
enough). CI compiles it on every change to `paper/**` and uploads the PDF as a build artifact
— see [`.github/workflows/paper.yml`](../.github/workflows/paper.yml); grab `dent8-paper-pdf`
from the run if you don't have LaTeX locally.

## arXiv

This is prepared as an arXiv submission (single `.tex`, self-contained bibliography, standard
packages) but **not submitted**. To submit, upload `dent8.tex` to arXiv (category `cs.CR`, with
`cs.AI` as a cross-list, is the natural fit) — arXiv compiles the source itself. Keep the prose
in sync with `docs/whitepaper.md`.
