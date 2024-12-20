ACLOCAL_AMFLAGS = -I m4 --install

SOURCEDIR=src
SOURCES := $(shell find $(SOURCEDIR) -name '*.c')
OBJS = $(patsubst src/%.c,obj/%.o,$(SOURCES))

CFLAGS+=-Wall -Wno-unused-but-set-variable

all: bin/$(PACKAGE)

bin/$(PACKAGE): $(SOURCES)
	mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(SOURCES)

check:
	bin/$(PACKAGE) 2>&1 &
	bin/$(PACKAGE) -h override 2>&1 &
	ping -c 1 $(shell cat /etc/hostname).local # Ok, doesn't actually test anything
	##ping -c 1 override.local # test the override feature
	killall $(PACKAGE)

clean-local:
	rm -rf bin/$(PACKAGE) ./$(PACKAGE)/* ./dist/

install-exec-local:
	install -m 0755 $(@D)/bin/$(PACKAGE) $(TARGET_DIR)/usr/sbin/$(PACKAGE)

deb: bin/$(PACKAGE)
	rm -rf ./$(PACKAGE)/
	mkdir -p dist $(PACKAGE)/DEBIAN

	mkdir -p $(PACKAGE)/usr/sbin
	cp -v bin/$(PACKAGE) $(PACKAGE)/usr/sbin/
	mkdir -p $(PACKAGE)/etc/systemd/system
	cp -v $(PACKAGE).service $(PACKAGE)/etc/systemd/system/
	mkdir -p $(PACKAGE)/usr/share/man/man1
	cat $(PACKAGE).1 | gzip > $(PACKAGE)/usr/share/man/man1/$(PACKAGE).1.gz

	cd $(PACKAGE); find . -type f -exec md5sum {} + | cut -c 1-33,38- > DEBIAN/md5sums

	echo "Package: $(PACKAGE)" > $(PACKAGE)/DEBIAN/control
	echo "Version: $(PACKAGE_VERSION)" >> $(PACKAGE)/DEBIAN/control
	echo "Section: base" >> $(PACKAGE)/DEBIAN/control
	echo "Priority: optional" >> $(PACKAGE)/DEBIAN/control
	echo "Architecture: $(shell dpkg --print-architecture)" >> $(PACKAGE)/DEBIAN/control
	echo "Maintainer: Maintainer <$(PACKAGE_BUGREPORT)>" >> $(PACKAGE)/DEBIAN/control
	echo "Description: Bare bones MDNS server" >> $(PACKAGE)/DEBIAN/control
	echo "#!/bin/sh" > $(PACKAGE)/DEBIAN/postinst
	echo "set -e" >> $(PACKAGE)/DEBIAN/postinst
	echo 'case "$$1" in' >> $(PACKAGE)/DEBIAN/postinst
	echo "  abort-upgrade|abort-remove|abort-deconfigure|configure)" >> $(PACKAGE)/DEBIAN/postinst
	echo "    systemctl daemon-reload;systemctl enable $(PACKAGE).service; service $(PACKAGE) restart" >> $(PACKAGE)/DEBIAN/postinst
	echo "    ;;" >> $(PACKAGE)/DEBIAN/postinst
	echo "  triggered)" >> $(PACKAGE)/DEBIAN/postinst
	echo "    systemctl daemon-reload; service $(PACKAGE) restart" >> $(PACKAGE)/DEBIAN/postinst
	echo "    ;;" >> $(PACKAGE)/DEBIAN/postinst
	echo "  *)" >> $(PACKAGE)/DEBIAN/postinst
	echo "    ;;" >> $(PACKAGE)/DEBIAN/postinst
	echo "esac" >> $(PACKAGE)/DEBIAN/postinst
	echo "exit 0" >> $(PACKAGE)/DEBIAN/postinst
	chmod 775 $(PACKAGE)/DEBIAN/postinst

	echo "#!/bin/sh" > $(PACKAGE)/DEBIAN/prerm
	echo "set -e" >> $(PACKAGE)/DEBIAN/prerm
	echo 'case "$$1" in' >> $(PACKAGE)/DEBIAN/prerm
	echo "  remove|remove-in-favour|deconfigure|deconfigure-in-favour)" >> $(PACKAGE)/DEBIAN/prerm
	echo "    systemctl daemon-reload;systemctl disable $(PACKAGE).service; service $(PACKAGE) stop" >> $(PACKAGE)/DEBIAN/prerm
	echo "    ;;" >> $(PACKAGE)/DEBIAN/prerm
	echo "  upgrade|failed-upgrade)" >> $(PACKAGE)/DEBIAN/prerm
	echo "    service $(PACKAGE) stop" >> $(PACKAGE)/DEBIAN/prerm
	echo "    ;;" >> $(PACKAGE)/DEBIAN/prerm
	echo "  *)" >> $(PACKAGE)/DEBIAN/prerm
	echo "    ;;" >> $(PACKAGE)/DEBIAN/prerm
	echo "esac" >> $(PACKAGE)/DEBIAN/prerm
	echo "exit 0" >> $(PACKAGE)/DEBIAN/postinst
	chmod 775 $(PACKAGE)/DEBIAN/prerm

	dpkg-deb --build $(PACKAGE) ./dist


## For manual installation override
## mkdir -p $(PACKAGE)/etc/systemd/system/multi-user.target.wants/
## cd $(PACKAGE)/etc/systemd/system/multi-user.target.wants && ln -s ../$(PACKAGE).service . || true