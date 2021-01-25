#!/bin/bash

DOCKER_ID=$1

docker_cp () {
  output="$1"

  echo "cp $1 from docker $DOCKER_ID to local $output"
  set -x
  rm -rf $output/*
  docker cp "$DOCKER_ID:$1/." "$output/"
  set +x
}

generate_env () {
  echo Generate ENV to $1
  docker exec $DOCKER_ID env \
      | grep -e ^CORE -e ^FABRIC -e ^ORDER \
      | sed 's#/host/var#/var#' \
      > $1
}

docker_cp /var/hyperledger
docker_cp /etc/hyperledger
generate_env docker.env

docker stop $DOCKER_ID
