#
#	Unit tests validating the SQL 'nas' table clients
#

#
#	Test name
#
TEST  := test.sql_nas_table
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

$(eval $(call TEST_BOOTSTRAP))

#
#	Config settings
#
SQL_NASTABLE_BUILD_DIR  := $(BUILD_DIR)/tests/sql_nastable
SQL_NASTABLE_RADIUS_LOG := $(SQL_NASTABLE_BUILD_DIR)/radiusd.log
SQL_NASTABLE_GDB_LOG    := $(SQL_NASTABLE_BUILD_DIR)/gdb.log
SQL_NASTABLE_DB         := $(SQL_NASTABLE_BUILD_DIR)/sql_nastable.db

# Used by src/tests/sql_nas_table/config/radiusd.conf
export SQL_NASTABLE_DB

#
#  Generic rules to start / stop the radius service.
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,radiusd,$(OUTPUT)))

sql_nastable_bootstrap:
	$(Q)rm -f $(SQL_NASTABLE_DB)
	$(Q)mkdir -p $(SQL_NASTABLE_BUILD_DIR)
	$(Q)sqlite3 $(SQL_NASTABLE_DB) < ./raddb/mods-config/sql/main/sqlite/schema.sql
	$(Q)sqlite3 $(SQL_NASTABLE_DB) < ./src/tests/sql_nas_table/clients.sql

#
#	Run the radclient commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/% | $(TEST).radiusd_kill sql_nastable_bootstrap $(TEST).radiusd_start
	$(Q)echo "SQL_NASTABLE-TEST"
	$(Q)mkdir -p $(dir $@)
	$(Q)[ -f $(dir $@)/radiusd.pid ] || exit 1
	$(Q)if ! $(TESTBIN)/radclient $(ARGV) -f src/tests/sql_nas_table/auth.txt -D share/ 127.0.0.1:$(PORT) auth $(SECRET) 1> /dev/null 2>&1; then \
		echo "FAILED";                                              \
		rm -f $(BUILD_DIR)/tests/test.sql_nas_table;		    \
		$(MAKE) --no-print-directory test.sql_nas_table.radiusd_kill;   \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "SQL_NASTABLE: $(TESTBIN)/radclient $(ARGV) -f $< -xF -d src/tests/sql_nas_table/config -D share/ 127.0.0.1:$(PORT) auth $(SECRET)"; \
		exit 1;                                                     \
	fi

	$(Q)touch $@

$(TEST): 
	$(Q)$(MAKE) --no-print-directory $@.radiusd_stop
	@touch $(BUILD_DIR)/tests/$@
