
include $(CURDIR)/Makefile.inc

subdir := $(subdir-y)

.PHONY: all clean distclean 
all:: 
	@$(foreach d,$(subdir),$(MAKE) -C $(d) $@ && $(MAKE) -C $(d) install || exit 255;)

clean distclean::
	@$(foreach d,$(subdir),$(MAKE) -C $(d) $@ || exit 255;)

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

