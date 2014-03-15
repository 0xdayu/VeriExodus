TEX = report


LATEX = pdflatex
SPELL = aspell
BIBTEX = bibtex
SOURCES = $(wildcard *.tex) $(wildcard *.bib)

default: pdf

pdf: $(SOURCES)
	$(LATEX) $(TEX); $(BIBTEX) $(TEX); $(LATEX) $(TEX); $(LATEX) $(TEX)

view:
	$(LATEX) $(TEX)
	acroread $(TEX).pdf

osx:
	$(LATEX) $(TEX)
	open $(TEX).pdf

html:
	latex2html -split 0 -show_section_numbers -local_icons -no_navigation $(TEX)

check:
	@echo "Passing the check will cause make to report Error 1."
	$(LATEX) $(TEX)  | grep -i undefined
	

clean:
	$(RM) -f *.aux *.blg *.dvi *.log *.toc *.lof *.lot *.cb *.bbl $(TEX).ps $(TEX).pdf *~
