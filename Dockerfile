ARG ANDROID_BUILD_TOOLS_VERSION=29.0.3
ARG ANDROID_SDK_ROOT="/home/gradle/android-sdk"

FROM gradle:8.7-jdk17 AS build-stage

ADD . /java/src/vault-jce
WORKDIR /java/src/vault-jce/

RUN ./gradlew lib:shadowJar

### ANDROID

ARG ANDROID_BUILD_TOOLS_VERSION
ARG ANDROID_SDK_ROOT

ENV SDK_URL="https://dl.google.com/android/repository/commandlinetools-linux-6514223_latest.zip" \
    COMMANDLINETOOLS=commandlinetools-linux-11076708_latest.zip \
    ANDROID_HOME=$ANDROID_SDK_ROOT \
    ANDROID_SDK_ROOT=$ANDROID_SDK_ROOT \
    CMD_LINE_TOOL_HOME="$ANDROID_SDK_ROOT/cmdline-tools" \
    ANDROID_BUILD_TOOLS_VERSION=${ANDROID_BUILD_TOOLS_VERSION}

# Download Android SDK
ADD --checksum=sha256:2d2d50857e4eb553af5a6dc3ad507a17adf43d115264b1afc116f95c92e5e258 https://dl.google.com/android/repository/${COMMANDLINETOOLS} /

RUN mkdir "$ANDROID_SDK_ROOT" "$CMD_LINE_TOOL_HOME" .android \
 && cd "$ANDROID_SDK_ROOT" \
 && unzip /${COMMANDLINETOOLS} \
 && rm /${COMMANDLINETOOLS} \
 && yes | $CMD_LINE_TOOL_HOME/bin/sdkmanager --sdk_root=$ANDROID_SDK_ROOT --licenses

# Install Android Build Tool and Libraries
RUN $CMD_LINE_TOOL_HOME/bin/sdkmanager --sdk_root=$ANDROID_SDK_ROOT --update

# https://developer.android.com/tools#tools-build
RUN $CMD_LINE_TOOL_HOME/bin/sdkmanager --sdk_root=$ANDROID_SDK_ROOT \
    "build-tools;${ANDROID_BUILD_TOOLS_VERSION}"

### OPENJDK

FROM openjdk:17

ARG GIT_COMMIT
ARG VERSION
LABEL GIT_COMMIT=$GIT_COMMIT
LABEL VERSION=$VERSION

RUN microdnf install findutils

ARG ANDROID_BUILD_TOOLS_VERSION
ARG ANDROID_SDK_ROOT

COPY --from=build-stage $ANDROID_SDK_ROOT/build-tools/$ANDROID_BUILD_TOOLS_VERSION/apksigner $ANDROID_SDK_ROOT/build-tools/$ANDROID_BUILD_TOOLS_VERSION/apksigner
COPY --from=build-stage $ANDROID_SDK_ROOT/build-tools/$ANDROID_BUILD_TOOLS_VERSION/lib/apksigner.jar $ANDROID_SDK_ROOT/build-tools/$ANDROID_BUILD_TOOLS_VERSION/lib/apksigner.jar

COPY --from=build-stage /java/src/vault-jce/etc/apksigner $ANDROID_SDK_ROOT/build-tools/$ANDROID_BUILD_TOOLS_VERSION/apksigner
COPY --from=build-stage /java/src/vault-jce/lib/build/libs/lib-all.jar $ANDROID_SDK_ROOT/build-tools/$ANDROID_BUILD_TOOLS_VERSION/lib/vault-jce.jar

ENV PATH="$ANDROID_SDK_ROOT/build-tools/$ANDROID_BUILD_TOOLS_VERSION:${PATH}"

RUN adduser --disabled-password --gecos "" apksigner
USER apksigner

CMD ["$ANDROID_SDK_ROOT/build-tools/$ANDROID_BUILD_TOOLS_VERSION/apksigner"]
