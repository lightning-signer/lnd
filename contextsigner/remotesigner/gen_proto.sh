#!/bin/sh

echo "Generating remotesigner gRPC client protos"

PROTOS="remotesigner.proto"

# For each of the sub-servers, we then generate their protos, but a restricted
# set as they don't yet require REST proxies, or swagger docs.
for file in $PROTOS; do
  DIRECTORY=$(dirname "${file}")
  echo "Generating protos from ${file}, into ${DIRECTORY}"

  # Generate the protos.
  protoc -I/usr/local/include -I. \
    --go_out=plugins=grpc,paths=source_relative:. \
    "${file}"
done
