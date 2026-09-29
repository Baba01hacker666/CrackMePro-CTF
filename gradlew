#!/bin/sh
# Gradle wrapper stub: prefers local gradle, else downloads Gradle 8.7.
# CI (.github/workflows/build.yml) installs Gradle directly, so this is for local dev.
set -e
if command -v gradle >/dev/null 2>&1; then exec gradle "$@"; fi
GVER=8.11
GZ=/tmp/gradle-$GVER-bin.zip
if [ ! -f "$GZ" ]; then echo "Downloading Gradle $GVER..."; curl -sL "https://services.gradle.org/distributions/gradle-$GVER-bin.zip" -o "$GZ"; fi
D=/tmp/gradle-$GVER
if [ ! -d "$D" ]; then mkdir -p "$D"; unzip -q "$GZ" -d /tmp; mv /tmp/gradle-$GVER "$D"; fi
exec "$D/bin/gradle" "$@"
