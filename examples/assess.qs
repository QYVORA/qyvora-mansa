# assess.qs — a runnable example of the shared QYVORA scripting engine driving
# mansa's authorized wireless assessment pipeline.
#
#     mansa script run examples/assess.qs
#
# mansa is offline here: the deterministic simulation needs no radio and no
# authorization. Live assessment requires --authorized and an in-scope target.

# Use the offline deterministic simulation (the default with no target set).
set assess.sim -> "true"

# Run the full wireless assessment pipeline. Module ids such as "mansa.scan"
# run the pipeline only up to and including that stage.
run assess

# Read live properties from the completed run via $(...).
echo -> "session   = $(session.id)"
echo -> "target    = $(session.target)"
echo -> "aps       = $(result.access_points)"
echo -> "stations  = $(result.stations)"
echo -> "findings  = $(result.findings)"
echo -> "risk      = $(result.risk_score)/100 ($(result.risk_level))"

# Show capability metadata and write a JSON session report.
show mansa.findings
report -> "mansa-report.json"

echo -> "done"
