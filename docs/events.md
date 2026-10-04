# Structured events

Mansa emits schema-versioned JSONL events through the existing event writer.
The event envelope includes schema version, timestamp, execution ID,
framework, level, event name, and structured data. The shared TUI consumes
these records; it does not parse the human-readable terminal output.

Use `--events stdout`, `--events stderr`, or a file path to select the event
stream. Event names and the machine-readable capability registry are maintained
in `internal/events` and `internal/capabilities`. WLAN capture emits AP/client
discovery and update events, channel/interface lifecycle events, and observed
EAPOL/PMKID metadata. BLE scan emits device discovery/update events. Offline
capture analysis persists authentication observations and emits them as
structured records.

Operation runs emit a lifecycle: one started event, then exactly one of
completed, cancelled, or refused. Every operation event carries the operation
id, module, class, domain, risk, target, authorization state, simulation flag,
and execution id, so a run can be reconstructed from the stream alone.

| Event                     | When                                            |
|---------------------------|-------------------------------------------------|
| `validation.started`      | a validation module begins                      |
| `validation.completed`    | it finished, findings and evidence attached     |
| `active_test.started`     | an active test begins                           |
| `active_test.completed`   | it finished                                     |
| `exploit.started`         | an exploitation module begins                   |
| `exploit.completed`       | it finished                                     |
| `operation.refused`       | a gate refused the run, or the run failed       |
| `operation.cancelled`     | the run's context ended before completion       |

A refused run still emits an event. A gate that blocks a run silently is a
run nobody can audit.

Contract conformance against the sibling qyvora-common runner and a final
cross-command event audit remain to be performed.
