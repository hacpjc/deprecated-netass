pack := json-c-0.13.1.tar.gz
tar_arg := -zxvf

pack-dir := json-c-0.13.1
inst-dir := $(CURDIR)/.inst

.PHONY: all
all:: build_pack

.PHONY: build_pack
build_pack: $(pack-dir)/Makefile
	$(MAKE) -C $(pack-dir)
	$(MAKE) -C $(pack-dir) install

option := --disable-shared --enable-static
$(pack-dir)/Makefile: $(pack-dir)
	( cd $(pack-dir) && ./configure --prefix=$(inst-dir) $(if $(TC_PFX),--host=`$(TC_CC) -dumpmachine`) $(option) || exit 255; )

$(pack-dir):
	tar -C . $(tar_arg) $(pack) 
	@test -d $@
	@touch $@

.PHONY: clean distclean
clean distclean::
	rm -rvf $(inst-dir)
	rm -rvf $(pack-dir)

ifeq ($(inst-dir),)
$(error Invalid symbol inst-dir)
endif

ifeq ($(DIR_STAGE_LIB),)
$(error Invalid symbol DIR_STAGE_LIB)
endif

ifeq ($(DIR_STAGE_INC),)
$(error Invalid symbol DIR_STAGE_INC)
endif

.PHONY: install
install::
	@test -d $(inst-dir)
	@mkdir -vp $(DIR_STAGE_LIB)
	cp -arvf $(inst-dir)/lib/* $(DIR_STAGE_LIB)
	@mkdir -vp $(DIR_STAGE_INC)
	cp -arvf $(inst-dir)/include/* $(DIR_STAGE_INC)

#
# general
#
.PHONY: all
all::

.PHONY: clean
clean::

.PHONY: distclean
distclean::

.PHONY: install
install::

.PHONY: release
relase::

