# Test fixtures

Demo configuration files used by `docker-compose.test-matrix.yaml` to bring up
Kafka and Redpanda variants for `scripts/test-all-variants.sh`.

The JAAS credentials in `kafka_server_jaas.conf` (`admin / admin-secret`) and
the Redpanda bootstrap user are **placeholders for local container fixtures**.
They are not used anywhere except in the test matrix and have no relationship
to any real cluster.

If you fork this repo and reuse these files, change the credentials.
