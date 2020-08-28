
Run all the tests:

    make itest timeout=240m |& tee itest.log

Run a single test:

    make itest timeout=240m \
        icase=basic_funding_flow/carol_commit=legacy,dave_commit=legacy
