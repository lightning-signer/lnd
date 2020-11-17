
Install the protobuf go plugin:

    go get github.com/golang/protobuf/protoc-gen-go

Generate the stubs:

    cd lnd/lnwallet/contextsigner/remotesigner
    ./gen_proto.sh

Run all the integration tests:

    make itest timeout=240m |& tee itest.log

Run a single integration test:

    make itest timeout=240m \
        icase=basic_funding_flow/carol_commit=legacy,dave_commit=legacy

Run a single unit test:

    go test -v -count=1 \
        -run TestCustomShutdownScript/User_set_script \
        github.com/lightningnetwork/lnd/peer
