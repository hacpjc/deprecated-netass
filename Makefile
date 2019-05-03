
#
# global
#
export EXTRA_CFLAGS=-g -I$(CURDIR)/stage/include -Wno-format
export EXTRA_LDFLAGS=-L$(CURDIR)/stage/lib

export DIR_ROOT := $(CURDIR)
export DIR_STAGE := $(DIR_ROOT)/stage
export DIR_STAGE_INC := $(DIR_STAGE)/include
export DIR_STAGE_LIB := $(DIR_STAGE)/lib
export DIR_STAGE_BIN := $(DIR_STAGE)/bin
export DIR_PACK := $(DIR_ROOT)/pack
export DIR_PACK_INC := $(DIR_ROOT)/include
export DIR_PACK_LIB := $(DIR_ROOT)/lib
export DIR_PACK_BIN := $(DIR_ROOT)/bin

export TC_PFX :=
export TC_CC := $(TC_PFX)gcc
export TC_STRIP := $(TC_PFX)strip


#
# default make target
#
.PHONY: all
all::

#
# subdir
#

#
# CMD_MAKE_ALL_DIR_NOSP
# Run make on specified directory list. Every directory path must not contain a space.
# 1: The directories to run "make"
# 2: The command/target to run at Makefile.
#
CMD_MAKE_ALL_DIR_NOSP = if [ ! "$(1)" = "" ]; then for d in $(1); do if [ ! -d "$$d" ]; then echo " * ERROR: $$d is not a directory" && exit -1; fi; echo "...Enter dir: $$d" && $(MAKE) -C $$d $(2) || exit -1; done; fi;

#
# subdir_target_tpl: All subdir targets should be the same with this
# 
define subdir_target_tpl
$(1)-dir-y += $(1)

.PHONY: $(1)
$(1): $(1)_all $(1)_install

.PHONY: $(1)_all
$(1)_all:
	@$$(call CMD_MAKE_ALL_DIR_NOSP,$$($(1)-dir-y),all)

.PHONY: $(1)_clean
$(1)_clean:
	@$$(call CMD_MAKE_ALL_DIR_NOSP,$$($(1)-dir-y),clean) 

.PHONY: $(1)_install
$(1)_install::
	@$$(call CMD_MAKE_ALL_DIR_NOSP,$$($(1)-dir-y),install) 

.PHONY: $(1)_distclean
$(1)_distclean::
	@$$(call CMD_MAKE_ALL_DIR_NOSP,$$($(1)-dir-y),distclean) 

.PHONY: $(1)_release
$(1)_release::
	@$$(call CMD_MAKE_ALL_DIR_NOSP,$$($(1)-dir-y),release)

# Run build + install export files into pack.
.PHONY: all
all:: $(1)

.PHONY: clean
clean:: $(1)_clean

.PHONY: distclean
distclean:: $(1)_distclean

.PHONY: install
install:: $(1)_install

.PHONY: release
release:: $(1)_release

endef # subdir_target_tpl

subdir-y :=
subdir-y += import
subdir-y += src
$(foreach d,$(subdir-y),$(eval $(call subdir_target_tpl,$(notdir $(d)))))

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


#
# stage
#
.PHONY: distclean
distclean:: stage_distclean

.PHONY: stage_distclean
stage_distclean:
	@rm -rf $(DIR_STAGE)

