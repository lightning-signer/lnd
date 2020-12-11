
Install the protobuf go plugin:

    go get github.com/golang/protobuf/protoc-gen-go

Generate the stubs:

    cd lnd/lnwallet/contextsigner/remotesigner
    ./gen_proto.sh

Run all the integration tests:

    make itest timeout=240m |& tee itest.log

    go test  -v -count=1 \
        ./lntest/itest \
        -tags="dev autopilotrpc chainrpc invoicesrpc routerrpc signrpc verrpc walletrpc watchtowerrpc wtclientrpc rpctest btcd" \
        -test.timeout=240m \
        -logoutput \
        -goroutinedump

Run a single integration test:

    make itest timeout=240m \
        icase=basic_funding_flow/carol_commit=legacy,dave_commit=legacy

Run a single unit test:

    go test -v -count=1 \
        -run TestCustomShutdownScript/User_set_script \
        github.com/lightningnetwork/lnd/peer

Run all integration tests when individual tests fail:

```
diff --git a/lntest/itest/lnd_test.go b/lntest/itest/lnd_test.go
index bcb76d16..890ee084 100644
--- a/lntest/itest/lnd_test.go
+++ b/lntest/itest/lnd_test.go
@@ -14192,7 +14192,7 @@ func TestLightningNetworkDaemon(t *testing.T) {
 			// failure.
 			t.Logf("Failure time: %v",
 				time.Now().Format("2006-01-02 15:04:05.000"))
-			break
+			// break
 		}
 	}
 }
```
