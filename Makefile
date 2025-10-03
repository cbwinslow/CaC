.PHONY: all install package clean
all: package

install:
	sudo bash cbw-cac-installer.sh

package:
	@rm -f cbw-cac-release.zip
	zip -r cbw-cac-release.zip . -x '*.git*' -x '*.DS_Store'

clean:
	rm -f cbw-cac-release.zip
