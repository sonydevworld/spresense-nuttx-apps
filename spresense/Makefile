
preconfig:
	$(Q) cp Kconfig.org Kconfig
	$(Q) $(MAKE) -C $(APPDIR)/.. TOPDIR=$(TOPDIR) APPDIR=$(APPDIR) $@

distclean:
	rm -rf Kconfig
	$(Q) $(MAKE) -C $(APPDIR)/.. TOPDIR=$(TOPDIR) APPDIR=$(APPDIR) $@

%:
	$(Q) $(MAKE) -C $(APPDIR)/.. TOPDIR=$(TOPDIR) APPDIR=$(APPDIR) $@
