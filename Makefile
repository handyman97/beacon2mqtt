#
PREFIX	?= /usr/local
TOP_DIR	= $(shell readlink -f .)
SUBDIRS	= src data helpers

all clean veryclean install::
		for d in $(SUBDIRS); do PREFIX=$(PREFIX) $(MAKE) -C $$d $@ || exit 1; done
clean::;	rm -f *~

tar::	clean
	cwd=$(shell basename $$PWD); \
	filename=$${cwd}-$(shell date +%y%m%d).tar.xz; \
	cd ..; test -f $$filename ||\
	tar cvJf $$filename --exclude=obsolete --exclude=_build --exclude=node_modules $$cwd

#
rsync-to-%:	clean
	dest=src/2022/$(shell basename $$PWD);\
	rsync -avzop --exclude=node_modules --exclude=_build \
	$(TOP_DIR)/ $*:$$dest
