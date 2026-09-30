#!/usr/bin/env bash
# Runs the console application.
# Configure the database connection with environment variables:
#   LACMS_DB_URL       e.g. jdbc:mysql://127.0.0.1:3306/access_control_db
#   LACMS_DB_USER       e.g. lacms_app
#   LACMS_DB_PASSWORD   the password you set in db/schema.sql
set -euo pipefail
cd "$(dirname "$0")/.."

MARIADB_JAR="${MARIADB_JAR:-/usr/share/java/mariadb-java-client.jar}"
if [ ! -f "build/classes/com/lacms/Main.class" ]; then
  echo "Not built yet. Running bin/build.sh first..."
  MARIADB_JAR="$MARIADB_JAR" bin/build.sh
fi

java -cp "build/classes:$MARIADB_JAR" com.lacms.Main
