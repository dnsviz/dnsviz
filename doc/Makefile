DOT=dot
DOTDIR=dot
IMGDIR=images

DOTFILES = $(wildcard $(DOTDIR)/*dot)
PNGFILES = $(DOTFILES:$(DOTDIR)/%.dot=$(IMGDIR)/%.png)

all: $(PNGFILES)

$(PNGFILES): $(IMGDIR)/%.png: $(DOTDIR)/%.dot
	$(DOT) -Tpng $< > $@ || ( rm $@ && false )

.PHONY: clean

clean:
	rm -rf $(PNGFILES)
