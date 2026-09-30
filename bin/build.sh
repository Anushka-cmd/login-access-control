#!/usr/bin/env bash
# Compiles the application into build/classes.
# Requires: JDK 17+, and mariadb-java-client (or mysql-connector-j) on MARIADB_JAR.
set -euo pipefail
cd "$(dirname "$0")/.."

MARIADB_JAR="${MARIADB_JAR:-/usr/share/java/mariadb-java-client.jar}"
if [ ! -f "$MARIADB_JAR" ]; then
  echo "JDBC driver not found at $MARIADB_JAR"
  echo "Install it (e.g. 'apt-get install libmariadb-java') or set MARIADB_JAR=/path/to/driver.jar"
  exit 1
fi

mkdir -p build/classes
find src/main/java -name "*.java" > /tmp/lacms_sources.txt
javac -d build/classes -cp "$MARIADB_JAR" @/tmp/lacms_sources.txt
echo "Build OK -> build/classes"
