module github.com/Netflix/titus-kube-common

go 1.13

replace (
	k8s.io/api => k8s.io/kubernetes/staging/src/k8s.io/api v0.0.0-20200118001809-59603c6e503c
	k8s.io/apimachinery => k8s.io/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20200118001809-59603c6e503c
)

require (
	github.com/Netflix/titus-controllers-api v0.0.6
	github.com/go-logr/logr v0.1.0
	github.com/google/uuid v1.1.1
	github.com/hashicorp/go-multierror v1.0.0
	github.com/stretchr/testify v1.6.1
	gotest.tools v2.2.0+incompatible
	k8s.io/api v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/utils v0.0.0-20201104234853-8146046b121e
	sigs.k8s.io/controller-runtime v0.5.0
)
