ifneq ($(PCAP_LIBS),)
TARGET		:= radsniff
else
TARGET		:=
endif

SOURCES		:= radsniff.c collectd.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS) $(PCAP_LIBS) $(COLLECTDC_LIBS)
TGT_LDFLAGS     := $(LDFLAGS) $(PCAP_LDFLAGS) $(COLLECTDC_LDFLAGS)
