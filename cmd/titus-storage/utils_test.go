package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestMountCmds(t *testing.T) {
	POD := `
{
 
            "spec": {
                "containers": [
                    {
                        "image": "titan-registry.main.us-east-1.dyntest.netflix.net:7002/titusops/echoservice@sha256:60d5cdeea0de265fe7b5fe40fe23a90e1001181312d226d0e688b0f75045109e",
                        "imagePullPolicy": "IfNotPresent",
                        "name": "7d3a38db-18c8-41f3-be8b-1225abfb1fd5",
                        "resources": {
                            "limits": {
                                "cpu": "1",
                                "ephemeral-storage": "10000Mi",
                                "memory": "512Mi",
                                "nvidia.com/gpu": "0",
                                "titus/network": "128M"
                            },
                            "requests": {
                                "cpu": "1",
                                "ephemeral-storage": "10000Mi",
                                "memory": "512Mi",
                                "nvidia.com/gpu": "0",
                                "titus/network": "128M"
                            }
                        },
                        "terminationMessagePath": "/dev/termination-log",
                        "terminationMessagePolicy": "File",
                        "volumeMounts": [
                            {
                                "mountPath": "/mnt/ceph-vol1",
                                "name": "ceph-vol1"
                            }
                        ]
                    },
                    {
                        "args": [
                            "nginx",
                            "-g",
                            "daemon off;"
                        ],
                        "image": "registry.us-east-1.streamingtest.titus.netflix.net:7002/nginx@sha256:926b086e1234b6ae9a11589c4cece66b267890d24d1da388c96dd8795b2ffcfb",
                        "imagePullPolicy": "IfNotPresent",
                        "name": "nginx",
                        "resources": {},
                        "terminationMessagePath": "/dev/termination-log",
                        "terminationMessagePolicy": "File"
                    },
                    {
                        "args": [
                            "sleep",
                            "infinity"
                        ],
                        "image": "registry.us-east-1.streamingtest.titus.netflix.net:7002/nginx@sha256:926b086e1234b6ae9a11589c4cece66b267890d24d1da388c96dd8795b2ffcfb",
                        "imagePullPolicy": "IfNotPresent",
                        "name": "php",
                        "resources": {},
                        "terminationMessagePath": "/dev/termination-log",
                        "terminationMessagePolicy": "File"
                    }
                ],
                "dnsPolicy": "Default",
                "enableServiceLinks": true,
                "nodeName": "i-0c65243de356167a3",
                "preemptionPolicy": "PreemptLowerPriority",
                "priority": 0,
                "restartPolicy": "Never",
                "schedulerName": "titus-kube-scheduler",
                "securityContext": {},
                "terminationGracePeriodSeconds": 600,
                "tolerations": [
                    {
                        "effect": "NoSchedule",
                        "key": "virtual-kubelet.io/provider",
                        "operator": "Equal",
                        "value": "titus"
                    },
                    {
                        "effect": "NoSchedule",
                        "key": "node.titus.netflix.com/scheduler",
                        "operator": "Equal",
                        "value": "kubeScheduler"
                    },
                    {
                        "effect": "NoSchedule",
                        "key": "node.titus.netflix.com/decommissioning",
                        "operator": "Exists"
                    },
                    {
                        "effect": "NoSchedule",
                        "key": "node.titus.netflix.com/tier",
                        "operator": "Equal",
                        "value": "flex"
                    },
                    {
                        "effect": "NoExecute",
                        "key": "node.kubernetes.io/not-ready",
                        "operator": "Exists",
                        "tolerationSeconds": 300
                    },
                    {
                        "effect": "NoExecute",
                        "key": "node.kubernetes.io/unreachable",
                        "operator": "Exists",
                        "tolerationSeconds": 300
                    }
                ],
                "topologySpreadConstraints": [
                    {
                        "labelSelector": {
                            "matchLabels": {
                                "v3.job.titus.netflix.com/job-id": "da22fc70-6ed8-4e32-9954-ee8d8eca6fe4"
                            }
                        },
                        "maxSkew": 1,
                        "topologyKey": "node.titus.netflix.com/id",
                        "whenUnsatisfiable": "ScheduleAnyway"
                    }
                ],
                "volumes": [
                    {
                        "cephfs": {
                            "monitors": [
                                "1.2.3.4"
                            ],
                            "path": "/",
                            "secretFile": "secret==",
                            "user": "admin"
                        },
                        "name": "ceph-vol1"
                    }
                ]
            },
            "status": {
                "conditions": [
                    {
                        "lastProbeTime": null,
                        "lastTransitionTime": "2021-11-10T00:23:51Z",
                        "status": "True",
                        "type": "PodScheduled"
                    }
                ],
                "containerStatuses": [
                    {
                        "containerID": "f2176558875d00f3b43ebb8c000231d28065e904c23359c254dc7b5a7b20196f",
                        "image": "titan-registry.main.us-east-1.dyntest.netflix.net:7002/titusops/echoservice@sha256:60d5cdeea0de265fe7b5fe40fe23a90e1001181312d226d0e688b0f75045109e",
                        "imageID": "",
                        "lastState": {},
                        "name": "7d3a38db-18c8-41f3-be8b-1225abfb1fd5",
                        "ready": true,
                        "restartCount": 0,
                        "state": {
                            "running": {
                                "startedAt": "2021-11-10T00:23:55Z"
                            }
                        }
                    },
                    {
                        "containerID": "0b00481f357cf55abfaea5edcbff6d5e4131c9660f762a5c6198a6b8fe59ad86",
                        "image": "registry.us-east-1.streamingtest.titus.netflix.net:7002/nginx@sha256:926b086e1234b6ae9a11589c4cece66b267890d24d1da388c96dd8795b2ffcfb",
                        "imageID": "",
                        "lastState": {},
                        "name": "nginx",
                        "ready": true,
                        "restartCount": 0,
                        "started": true,
                        "state": {
                            "running": {
                                "startedAt": "2021-11-10T00:23:55Z"
                            }
                        }
                    },
                    {
                        "containerID": "ec185650f1418f420bd99f4729d96137226d4ffaf5e7a424b58959cf143df707",
                        "image": "registry.us-east-1.streamingtest.titus.netflix.net:7002/nginx@sha256:926b086e1234b6ae9a11589c4cece66b267890d24d1da388c96dd8795b2ffcfb",
                        "imageID": "",
                        "lastState": {},
                        "name": "php",
                        "ready": true,
                        "restartCount": 0,
                        "started": true,
                        "state": {
                            "running": {
                                "startedAt": "2021-11-10T00:23:55Z"
                            }
                        }
                    }
                ],
                "message": "main container is now running",
                "phase": "Running",
                "podIP": "1.2.3.4",
                "podIPs": [
                    {
                        "ip": "1.2.3.4"
                    }
                ],
                "qosClass": "Burstable",
                "reason": "TASK_RUNNING"
            }
      
}

`

	var pod corev1.Pod
	json.Unmarshal([]byte(POD), &pod)
	containers := containersUsingVolume("ceph-vol1", &pod)
	assert.Equal(t, 1, len(containers))
	assert.Equal(t, "/mnt/ceph-vol1", containers[0].mountPath)

}
