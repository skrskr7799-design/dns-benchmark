# DNS Benchmark

Self-hosted DNS resolver benchmark for trusted LANs. No authentication; do not expose publicly.

## CasaOS

Create the persistent directory before importing compose.yaml:

```sh
sudo mkdir -p /DATA/AppData/dns-benchmark
sudo chown 10001:10001 /DATA/AppData/dns-benchmark
```

Open port 8099. Cold mode creates new sessions; warm mode attempts session reuse and excludes one initial query. Address resolution is outside timed samples. IPv4 is default. Protocol behavior needs live verification. History is preserved in SQLite.
