DOT=dot
SRCDIR=src
IMGDIR=images

DOTFILES = $(wildcard $(SRCDIR)/*dot)
DOTPNGFILES = $(DOTFILES:$(SRCDIR)/%.dot=$(IMGDIR)/%.png)

all: $(DOTPNGFILES)

# make png files from dot files
$(DOTPNGFILES): $(IMGDIR)/%.png: $(SRCDIR)/%.dot
	$(DOT) -Tpng $< > $@ || ( rm $@ && false )

.PHONY: clean

clean:
	rm -rf $(DOTPNGFILES)
