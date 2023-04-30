# auto-instrument foobar

## make local docker image for auto-instrumentation agent

```sh
# from repository root

# make docker image called otel-go-agent:local
make docker-build IMG=otel-go-agent:local
# make sure you have it locally
docker images | grep otel-go-agent
```

## setup

```sh
# from example-foobar directory

# build the foobar docker image
docker-compose build

# deploy the foobar namespace and services in k8s
kubectl apply -f foobar-instrumented.yaml

# deploy the collector
kubectl apply -f otel-collector.yaml

# make sure everything is up and running
kubectl -n foobar get pods

# follow logs for foobar app
kubectl -n foobar logs deployments/foobar-app --follow
```

## test

`curl localhost:6001/foobar -d "lol"`

## cleanup

```sh
kubectl delete namespace foobar
```
