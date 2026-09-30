#!/usr/bin/env bash
# Compiles and runs the JUnit test suite against a real database.
# The integration tests TRUNCATE the users/login_history/audit_log tables
# before each test, so point LACMS_DB_URL at a dev/test database, never prod.
set -euo pipefail
cd "$(dirname "$0")/.."

MARIADB_JAR="${MARIADB_JAR:-/usr/share/java/mariadb-java-client.jar}"
JUNIT_JAR="${JUNIT_JAR:-/usr/share/java/junit4.jar}"
HAMCREST_JAR="${HAMCREST_JAR:-/usr/share/java/hamcrest-core.jar}"
for jar in "$MARIADB_JAR" "$JUNIT_JAR" "$HAMCREST_JAR"; do
  if [ ! -f "$jar" ]; then
    echo "Missing dependency: $jar"
    echo "On Debian/Ubuntu: apt-get install libmariadb-java junit4"
    exit 1
  fi
done

CP_LIBS="$MARIADB_JAR:$JUNIT_JAR:$HAMCREST_JAR"

mkdir -p build/classes build/test-classes
find src/main/java -name "*.java" > /tmp/lacms_sources_main.txt
javac -d build/classes -cp "$CP_LIBS" @/tmp/lacms_sources_main.txt

find src/test/java -name "*.java" > /tmp/lacms_sources_test.txt
javac -d build/test-classes -cp "build/classes:$CP_LIBS" @/tmp/lacms_sources_test.txt

java -cp "build/classes:build/test-classes:$CP_LIBS" org.junit.runner.JUnitCore \
    com.lacms.PasswordUtilTest \
    com.lacms.InputValidatorTest \
    com.lacms.AccessControlIntegrationTest
