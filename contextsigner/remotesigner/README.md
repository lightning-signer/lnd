
Install the protobuf go plugin:

    go get github.com/golang/protobuf/protoc-gen-go

Generate the stubs:

    cd lnd/lnwallet/contextsigner/remotesigner
    ./gen_proto.sh

Run all the tests:

    make itest timeout=240m |& tee itest.log

Run a single test:

    make itest timeout=240m \
        icase=basic_funding_flow/carol_commit=legacy,dave_commit=legacy
