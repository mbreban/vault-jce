
VERSION := 1.0

.PHONY: default
default: help

.PHONY: help
help:
	@echo 'Management commands for vault-jce:'
	@echo
	@echo 'Usage:'
	@echo '    make build           Compile the project.'
	@echo '    make test            Run tests.'
	@echo '    make clean           Clean the directory tree.'
	@echo

.PHONY: build
build:
	@echo "building $(VERSION)"
	./gradlew lib:shadowJar

.PHONY: clean
clean:
	./gradlew clean

.PHONY: test
test:
	./gradlew test
