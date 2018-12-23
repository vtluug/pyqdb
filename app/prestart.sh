#!/usr/bin/env bash
# -*- coding: utf-8 -*-

python - <<EOF
import os
import sql

DB_PATH = "{}/quotes.db".format(os.path.dirname(os.path.realpath(__file__)))

# Don't overwrite already existing db
if not os.path.exists(DB_PATH):
    sql.init_db()
EOF
