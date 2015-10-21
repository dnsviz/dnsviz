DOT=dot
#INKSCAPE=inkscape
INKSCAPE=/Applications/Inkscape.app/Contents/Resources/bin/inkscape
#SRCDIR=src
SRCDIR=/Users/cdeccio/dnsviz/doc/src
#IMGDIR=images
IMGDIR=/Users/cdeccio/dnsviz/doc/images

DOTFILES = $(wildcard $(SRCDIR)/*dot)
DOTPNGFILES = $(DOTFILES:$(SRCDIR)/%.dot=$(IMGDIR)/%.png)

all: $(DOTPNGFILES)

# make png files from dot files
$(DOTPNGFILES): $(IMGDIR)/%.png: $(SRCDIR)/%.dot
	$(DOT) -Tpng $< > $@ || ( rm $@ && false )

# make icon-sized png files from warning.svg and error.svg
ICONSVGFILES = $(SRCDIR)/warning.svg $(SRCDIR)/error.svg
ICONPNGFILES = $(ICONSVGFILES:$(SRCDIR)/%.svg=$(IMGDIR)/%.png)
ICONWIDTH = 25

icons: $(ICONPNGFILES)

$(ICONPNGFILES): $(IMGDIR)/%.png: $(SRCDIR)/%.svg
	$(INKSCAPE) -z -w $(ICONWIDTH) -e $@ $<

.PHONY: clean

clean:
	rm -rf $(DOTPNGFILES)
	rm -rf $(ICONPNGFILES)
