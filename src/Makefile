include $(CURDIR)/Makefile.inc

obj := $(obj-y)
src := $(patsubst %.o,%.c,$(obj))
exec := netass

EXTRA_CFLAGS += -I$(CURDIR) -Iinclude -std=gnu99 -D_GNU_SOURCE
EXTRA_LDFLAGS += -ljson-c -lpcap -lpthread

CFLAGS += $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)


ifeq ($(TC_CC),)
$(warning ...Apply TC_CC = $(CC))
TC_CC := $(CC)
endif

define CMD_CC
echo -e "\t\033[0;31mCC\033[0m $(1)" && $(TC_CC) -o $(1) -c $(2) $(3) 
endef

define CMD_LD
echo -e "\t\033[0;31mLD\033[0m $(1)" && $(TC_CC) -o $(1) $(2) $(3)
endef

.PHONY: all
all:: $(exec)

$(exec): $(obj)
	@$(call CMD_LD,$@,$^,$(LDFLAGS))

%.o: %.c
	@$(call CMD_CC,$@,$^,$(CFLAGS))

.PHONY: clean distclean
clean distclean::
	@$(if $(obj),rm -vf $(obj) $(exec)) 

#
# Define general rules here
#
.PHONY: all
all::

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

