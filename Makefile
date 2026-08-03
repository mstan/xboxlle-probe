XBE_TITLE = xboxlle-probe
GEN_XISO = $(XBE_TITLE).iso
SRCS = $(CURDIR)/src/main.c
NXDK_NET = y

ifeq ($(strip $(NXDK_DIR)),)
$(error NXDK_DIR is not set. Clone nxdk recursively, export NXDK_DIR, and activate nxdk/bin/activate)
endif

include $(NXDK_DIR)/Makefile
