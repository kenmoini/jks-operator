package controller

import (
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var globalLog = logf.Log
var secretInjectorLog = logf.Log.WithName("jks-operator-cjks-secret-injector")
var configMapInjectorLog = logf.Log.WithName("jks-operator-cjks-configmap-injector")
