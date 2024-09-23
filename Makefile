
VERSION := 1.0
GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_DIRTY := $(shell test -n "`git status --porcelain`" && echo "+CHANGES" || true)
BUILD_DATE := $(shell date '+%Y-%m-%d-%H:%M:%S')
IMAGE_NAME := vault-jce

.PHONY: default
default: help

.PHONY: help
help:
	@echo 'Management commands for vault-jce:'
	@echo
	@echo 'Usage:'
	@echo '    make build           Compile the project.'
	@echo '    make package         Build final docker image.'
	@echo '    make tag             Tag image created by package with latest, git commit and version.'
	@echo '    make test            Run tests.'
	@echo '    make push            Push tagged images to registry.'
	@echo '    make clean           Clean the directory tree.'
	@echo

.PHONY: build
build:
	@echo "building $(BIN_NAME) $(VERSION)"
	./gradlew lib:shadowJar

.PHONY: package
package:
	@echo "building image $(VERSION) $(GIT_COMMIT)"
	docker build --rm --build-arg VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) -t $(IMAGE_NAME):local .

.PHONY: tag
tag: 
	@echo "Tagging: latest $(VERSION) $(GIT_COMMIT)"
	docker tag $(IMAGE_NAME):local $(IMAGE_NAME):$(GIT_COMMIT)
	docker tag $(IMAGE_NAME):local $(IMAGE_NAME):$(VERSION)
	docker tag $(IMAGE_NAME):local $(IMAGE_NAME):latest

.PHONY: push
push: tag
	@echo "Pushing docker image to registry: latest $(VERSION) $(GIT_COMMIT)"
	docker push $(IMAGE_NAME):$(GIT_COMMIT)
	docker push $(IMAGE_NAME):$(VERSION)
	docker push $(IMAGE_NAME):latest

.PHONY: clean
clean:
	./gradlew clean

.PHONY: test
test:
	./gradlew test
