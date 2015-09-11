DOT=dot
INKSCAPE=inkscape
SRCDIR=src
IMGDIR=images

DOTFILES = $(wildcard $(SRCDIR)/*dot)
DOTPNGFILES = $(DOTFILES:$(SRCDIR)/%.dot=$(IMGDIR)/%.png)

all: $(DOTPNGFILES)

# make png files from dot files
$(DOTPNGFILES): $(IMGDIR)/%.png: $(SRCDIR)/%.dot
	$(DOT) -Tpng $< > $@ || ( rm $@ && false )

# make icon-sized png files from warning.svg and error.svg
ICONSVGFILES = $(SRCDIR)/warning.svg $(SRCDIR)/error.svg
ICONPNGFILES = $(ICONSVGFILES:$(SRCDIR)/%.svg=$(IMGDIR)/%.png)
ICONWIDTH = 35

icons: $(ICONPNGFILES)

$(ICONPNGFILES): $(IMGDIR)/%.png: $(SRCDIR)/%.svg
	$(INKSCAPE) -z -w $(ICONWIDTH) -e $@ $<

.PHONY: clean

clean:
	rm -rf $(DOTPNGFILES)
	rm -rf $(ICONPNGFILES)
