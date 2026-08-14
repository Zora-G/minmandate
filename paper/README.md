# MinMandate preprint package

This directory is a self-contained LaTeX source package for the combined,
two-column MinMandate preprint. It does not depend on files outside this
directory. The entry point uses the official AAAI template's `preprint` option,
which retains the template layout while suppressing its copyright and
publication marks.

## Contents

- `minmandate_preprint.tex`: main preprint source (paper and appendices).
- `aaai2027.sty` and `aaai2027.bst`: unmodified official template files.
- `references.bib`: combined bibliography.
- `figures/`: the five PDF figures used by the source.
- `minmandate_preprint.pdf`: compiled preprint.

## Build

Run from this directory:

```bash
latexmk -pdf -interaction=nonstopmode -halt-on-error minmandate_preprint.tex
```

To remove auxiliary build files while retaining the PDF:

```bash
latexmk -c minmandate_preprint.tex
```

For an arXiv source upload, upload the contents of this directory and select
`minmandate_preprint.tex` as the main TeX file.

## Author metadata

The TeX source lists the confirmed authors in this order: Ge Gao, Haining Yu,
Zhichao Liu, Dongyang Zhan, Yuanxiao Zhu, and Zhongyun Hua. The author block
uses the shared institutional affiliation Harbin Institute of Technology,
China. Following the convention used in the authors' related papers, the first
page lists only Haining Yu's corresponding-author address,
`yuhaining@hit.edu.cn`, in a bottom-left footnote.
