package k8s.policy

import rego.v1

deny contains msg if {
	input.kind == "Pod"
	container := input.spec.containers[_]
	not container.livenessProbe

	msg := sprintf("liveness Probe is not present,Conformity Check Failed for container %s", [container.name])
}
