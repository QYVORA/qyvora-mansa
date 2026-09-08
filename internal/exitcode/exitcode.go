// Package exitcode defines the shared QYVORA process exit-code contract.
//
//	0   success
//	1   runtime failure
//	2   usage error
//	130 interrupted (128 + SIGINT)
package exitcode

const (
	Success     = 0
	Runtime     = 1
	Usage       = 2
	Interrupted = 130
)
