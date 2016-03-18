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
ICONWIDTH = 25

icons: $(ICONPNGFILES)

$(ICONPNGFILES): $(IMGDIR)/%.png: $(SRCDIR)/%.svg
	$(INKSCAPE) -z -w $(ICONWIDTH) -e $@ $<

# make banner png 220x100 file from logo.svg
LOGOSVGFILE = $(SRCDIR)/logo.svg
LOGOBANNERPNGFILE = $(IMGDIR)/logo-220x100.png
LOGOBANNERVIEWBOX = 58 43 381 173
LOGOBANNERHEIGHT = 100

# make square icon png 60x60 file from logo.svg
LOGOICONPNGFILE = $(IMGDIR)/logo-60x60.png
LOGOICONVIEWBOX = 335 43 103 103
LOGOICONHEIGHT = 50

# make square favico png 16x16 file from logo.svg
LOGOFAVICONPNGFILE = $(IMGDIR)/logo-16x16.png
LOGOFAVICONVIEWBOX = 335 43 103 103
LOGOFAVICONHEIGHT = 16

logo: $(LOGOBANNERPNGFILE) $(LOGOICONPNGFILE) $(LOGOFAVICONPNGFILE)

$(LOGOBANNERPNGFILE): $(LOGOSVGFILE)
	cat $< | sed 's/viewBox="0 0 504 252"/viewBox="$(LOGOBANNERVIEWBOX)"/' | $(INKSCAPE) -z -h $(LOGOBANNERHEIGHT) -e $@ /dev/stdin

$(LOGOICONPNGFILE): $(LOGOSVGFILE)
	cat $< | sed 's/viewBox="0 0 504 252"/viewBox="$(LOGOICONVIEWBOX)"/' | $(INKSCAPE) -z -h $(LOGOICONHEIGHT) -e $@ /dev/stdin

$(LOGOFAVICONPNGFILE): $(LOGOSVGFILE)
	cat $< | sed 's/viewBox="0 0 504 252"/viewBox="$(LOGOFAVICONVIEWBOX)"/' | $(INKSCAPE) -z -h $(LOGOFAVICONHEIGHT) -e $@ /dev/stdin

.PHONY: clean

clean:
	rm -rf $(DOTPNGFILES)
	rm -rf $(ICONPNGFILES)
	rm -rf $(LOGOBANNERPNGFILE) $(LOGOICONPNGFILE) $(LOGOFAVICONPNGFILE)
