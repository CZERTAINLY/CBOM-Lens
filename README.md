# CBOM-Lens

CLI tool, which scans a filesystem, containers and open ports and detects

 * certificates
 * secrets
 * opened ports

Generates BOM in CycloneDX 1.6 JSON format.

# Usage

You may want to generate a X509 certificate in order to have some cryptography
material in a current directory.

```sh
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```

# Filesystem scan

```yaml
version: 0

service:
    mode: manual
    verbose: false
    log: stderr
    dir: .

filesystem:
    enabled: true
    paths: []
```

This configuration snippet searches for certificates and secrets inside local directory.


```sh
$ ./cbom-lens run --config cbom-lens.yaml
{"time":"2025-10-10T14:14:04.632066182+02:00","level":"WARN","msg":"command has no timeout","path":"usr/bin/cbom-lens","cbom-lens":{"cmd":"run","pid":2488398}}
{"time":"2025-10-10T14:14:05.410539638+02:00","level":"INFO","msg":"bom saved","path":"cbom-lens-2025-10-10-02:14:05.json","cbom-lens":{"cmd":"run","pid":2488398}}
```

# Container scan

cbom-lens can scan images stored inside Docker(podman). Those searches for
certificates and secrets exactly like filesystem scan do. Docker host can be
specified via environment variable.

The docker host can be specified via environment variable such as `${DOCKER_HOST}`.


```yaml
version: 0

service:
    mode: manual
    verbose: false
    log: stderr
    dir: .

containers:
    -
        enabled: false
        host: ${DOCKER_HOST}
        images:
            - docker.io/library/alpine:3.22.1
```

```sh
$ time ./cbom-lens run --config cbom-lens.yaml
{"time":"2025-10-11T11:38:54.207199641+02:00","level":"WARN","msg":"command has no timeout","path":"usr/bin/cbom-lens","cbom-lens":{"cmd":"run","pid":2610219}}
{"time":"2025-10-11T11:39:41.257456265+02:00","level":"INFO","msg":"bom saved","path":"cbom-lens-2025-10-11-11-39-41.json","cbom-lens":{"cmd":"run","pid":2610219}}

real    0m47.083s
user    1m33.919s
sys     0m0.442s
```

# Port scan

Port scan is performed via nmap, which must be installed on a target machine
too. It tries to detect TLS and SSH.

```yaml
ports:
    enabled: true
    ipv4: true
    ipv6: false
```

```sh
$ time ./cbom-lens run --config cbom-lens.yaml
{"time":"2025-10-11T11:46:39.889049897+02:00","level":"WARN","msg":"command has no timeout","path":"usr/bin/cbom-lens","cbom-lens":{"cmd":"run","pid":2614823}}
{"time":"2025-10-11T11:46:57.244593739+02:00","level":"INFO","msg":"bom saved","path":"cbom-lens-2025-10-11-11-46-57.json","cbom-lens":{"cmd":"run","pid":2614823}}

real    0m17.389s
user    0m0.838s
sys     0m2.538s
```

# Save and upload the result

By default, cbom-lens prints the BOM to standard output. The `dir` directive
changes this behavior, saving the files as `cbom-lens-$date.json` in the specified
directory. The `.` means the current working directory.

```yaml
service:
    mode: manual
    dir: .
```

The following setup is needed to upload to a [CBOM-Repository](https://github.com/CZERTAINLY/CBOM-Repository)

```yaml
service:
    mode: manual
    repository:
      base_url: "http://localhost:8080"
```

Both the `dir` and the `repository` can be combined in a single configuration
file. cbom-lens will attempt both methods and log an error if either one fails.

```yaml
service:
    mode: manual
    dir: .
    repository:
      base_url: "http://localhost:8080"
```

# Modes of operation

## Manual

This particular mode is the simplest one. Simply run `cbom-lens run` and the
command will run the scan, upload results and finish. Use it in case
scans are going to be orchestrated by other system.

```yaml
service:
    mode: manual
```

## Timer

More advanced is a timer mode. It uses a standard `cron` 5 field syntax. All interpretation and scheduling is done in the machine's local time zone (`time.Local`).

```yaml
version: 0
service:
    mode: timer
    schedule:
      cron: "* * * * *"
```

[github.com/robfig/cron/](https://pkg.go.dev/github.com/robfig/cron/) library
is used under the hood, so the format supported is defined by this library.

### CRON Expression Format

A cron expression represents a set of times, using 5 space-separated fields.

	Field name   | Mandatory? | Allowed values  | Allowed special characters
	----------   | ---------- | --------------  | --------------------------
	Minutes      | Yes        | 0-59            | * / , -
	Hours        | Yes        | 0-23            | * / , -
	Day of month | Yes        | 1-31            | * / , - ?
	Month        | Yes        | 1-12 or JAN-DEC | * / , -
	Day of week  | Yes        | 0-6 or SUN-SAT  | * / , - ?

Month and Day-of-week field values are case insensitive.  "SUN", "Sun", and
"sun" are equally accepted.

The specific interpretation of the format is based on the Cron Wikipedia page:
[https://en.wikipedia.org/wiki/Cron](https://en.wikipedia.org/wiki/Cron)

### Special Characters

#### Asterisk ( * )

The asterisk indicates that the cron expression will match for all values of the
field; e.g., using an asterisk in the 5th field (month) would indicate every
month.

#### Slash ( / )

Slashes are used to describe increments of ranges. For example 3-59/15 in the
1st field (minutes) would indicate the 3rd minute of the hour and every 15
minutes thereafter. The form "*\/..." is equivalent to the form "first-last/...",
that is, an increment over the largest possible range of the field.  The form
"N/..." is accepted as meaning "N-MAX/...", that is, starting at N, use the
increment until the end of that specific range.  It does not wrap around.

#### Comma ( , )

Commas are used to separate items of a list. For example, using "MON,WED,FRI" in
the 5th field (day of week) would mean Mondays, Wednesdays and Fridays.

#### Hyphen ( - )

Hyphens are used to define ranges. For example, 9-17 would indicate every
hour between 9am and 5pm inclusive.

#### Question mark ( ? )

Question mark may be used instead of '*' for leaving either day-of-month or
day-of-week blank.

#### Predefined schedules

You may use one of several pre-defined schedules in place of a cron expression.

	Entry                  | Description                                | Equivalent To
	-----                  | -----------                                | -------------
	@yearly (or @annually) | Run once a year, midnight, Jan. 1st        | 0 0 1 1 *
	@monthly               | Run once a month, midnight, first of month | 0 0 1 * *
	@weekly                | Run once a week, midnight between Sat/Sun  | 0 0 * * 0
	@daily (or @midnight)  | Run once a day, midnight                   | 0 0 * * *
	@hourly                | Run once an hour, beginning of hour        | 0 * * * *

#### Intervals

You may also schedule a job to execute at fixed intervals, starting at the time it's added
or cron is run. This is supported by formatting the cron spec like this:

    @every <duration>

where "duration" is a string accepted by time.ParseDuration
(http://golang.org/pkg/time/#ParseDuration).

For example, "@every 1h30m10s" would indicate a schedule that activates after
1 hour, 30 minutes, 10 seconds, and then every interval after that.

Note: The interval does not take the job runtime into account.  For example,
if a job takes 3 minutes to run, and it is scheduled to run every 5 minutes,
it will have only 2 minutes of idle time between each run.

### ISO 8601 Duration

It is possible to specify the syntax based on ISO-8601 duration and
[java.time.Duration](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/time/Duration.html#parse(java.lang.CharSequence)).

Format is `PnDTnHnMn` and day is exactly 24 hours. Fraction numbers are allowed
`P0.5D` and decimal point can be a point or comma. Fractional part can be up to 9
digits long. Negative numbers are possible too `PT1H-7M`.

```yaml
version: 0
service:
    mode: timer
    schedule:
      # 1 day 2 hours 3 minutes 4 s
      duration: "P1DT2H3M4S"
```

## CZERTAINLY discovery

```yaml
version: 0
service:
    mode: "discovery"
    repository:
        base_url: https://example.com/repo
    server:
        # where should cbom-lens bind to - can be ip:port
        addr: :8080
        # public address from which is cbom-lens accessible
        # to CZERTAINLY
        base_url: https://cbom-lens.example.net/api
    core:
        # base address of CZERTAINLY Core API
        base_url: https://core-demo.example.net/api
```

In this mode cbom-lens is fully managed by CZERTAINLY via discovery
protocol. In this mode using a `repository` is more than recommended, as CZERTAINLY Core is expected to pull BOMs from there.

# Developers

Following section is intended for developers

## Architecture

`cbom-lens` is a single binary with two cooperating modes triggered by `run`.

Supervisor (default when running `cbom-lens run`):
1. Parses the `service:` configuration and initializes runtime (logging, repository, mode).
2. Sets up resources per selected mode.
3. Spawns a scan as a separate subprocess (`cbom-lens _scan`).
4. Enforces single-scan execution (queues/rejects concurrent scans) and waits for completion.
5. Collects results and outputs them (print/store/upload) per configuration.

Scan (invoked internally as `cbom-lens _scan`):
- Performs the actual scanning work.
- Uses the same base configuration, focusing on scan-related fields.
- Returns detections/results to the supervisor for further handling.

Supervisor and scan communicate over stdin/stdout for portability across all supported platforms. The supervisor sends scan configuration via stdin; the scan writes results to stdout and errors to stderr.

## The detector interface

The filesystem/container detectors are based around `scan.Detector` interface. In order to implement new scanning method, the `Detect` method is what is needed to be implemented. For details open the file and follow the comments of an interface.

```go
//internal/model/detection.go
import cdx "github.com/CycloneDX/cyclonedx-go"
type Detection struct {
	Path         string
	Components   []cdx.Component
	Dependencies []cdx.Dependency
}
// internal/scan/scan.go
type Detector interface {
	Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error)
}
```

Existing detectors (gitleaks and x509) are initialized in `main.go` and passed down to the cbom-lens in `_scan` subcommand

```go
// cmd/cbom-lens/main.go
func init() {
	// user configuration
	d, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	userConfigPath = filepath.Join(d, "cbom-lens")

	// configure default detectors
	// secrets:
	leaks, err := gitleaks.NewDetector()
	if err != nil {
		panic(err)
	}

	// certificates:
	detectors = []scan.Detector{
		x509.Detector{},
		leaks,
	}
}
// func do Scan
	lens, err := NewLens(ctx, detectors, config)
```

## Config file format specification

See [docs/config.cue] for a specification and (manual-config.yaml)[docs/manual-config.yaml] for an example config.

There are two main objects

1. Supervisor + _scan config in `#Config` (presented by `model.Config`)
2. _scan only subset in `#Scan` (presented by `model.Scan`)

The split allows code to:
- Treat long‑lived supervisor settings as immutable while permitting hot reload of just scan parameters.
- Reuse the same CUE and Go validation fragments for both full and subset configs.
- Minimize data passed over the HTTP API (only `#Scan` fields) while retaining a canonical persisted `#Config`.
- Decouple operational concerns (service mode, repository) from per‑scan tunables (paths, containers, ports).
- Simplify testing (small #Scan fixtures) and enable merging (#Config baseline + #Scan override) without redefining schema.

## Fast unit test execution

Some tests (e.g. nmap scans or walk.Images enumerating all Docker images) can run for a long time. Use go test -short during local development for faster feedback. GitHub Actions runs the full test suite on each PR.

## Integration tests

Are placed in a `cbom-lens_test.go` in a project root. It is a normal Go test, which starts the `cbom-lens-ci` binary in a specified directory. It expects the binary is built via

```sh
go build -race -cover -covermode=atomic -o cbom-lens-ci ./cmd/cbom-lens/
```

Data for the cbom-lens under the test are stored in a temporary directory, which is deleted after test ends. In order to keep the content for further examination, the `test.keepdir` can be used. This will keep the temporary directory on disk.

```sh
go test -v -test.keepdir
```

# Cryptographic Bill Of Materials (CBOM)

The produced CBOM file conforms [CycloneDX BOM 1.6](https://cyclonedx.org/schema/bom-1.6.schema.json). cbom-lens can identify and correlate identical cryptographic materials across multiple sources and by generating a stable `bom-ref` for each component. This identifier is derived by hashing the component’s content (SHA-256 by default).

There are two exceptions

The generated CBOM file conforms to the CycloneDX BOM 1.6

1. **Private keys** - where hash would leak the private key itself. In this case the hash of a corresponding public key is used.

```json
[
  {"bom-ref": "crypto/key/rsa-4096@sha256:f1ac7a3953323b932aade7e47c045d7981e4602fe465883d21f77051cf3c2dbc"},
  {"bom-ref": "crypto/private_key/rsa-4096@sha256:f1ac7a3953323b932aade7e47c045d7981e4602fe465883d21f77051cf3c2dbc",
    }
]
```

2. **Algorithms** - the algorithm (SHA-256, RSA-4096, ...) component itself does not have "inherent" content to hash. So hash of a its CycloneDX JSON representation is used, ensuring the different algorithms or same algorithm with different BOM properties will receive unique reference.

When computing this hash, cbom-lens excludes the bom-ref and evidence fields to avoid circular dependencies.

A stable, content-based `bom-ref` enables cbom-lens to reliably identify the same cryptographic materials across diverse sources, providing a complete and unified view of an organization’s cryptographic assets.

```json
{
  "bom-ref": "crypto/algorithm/rsa-4096@sha256:2cc0b015108f202753b120182f3c437db4d5bf6e668b019a1f9099f5709e167f",
  "type": "cryptographic-asset",
  "name": "RSA-4096",
  "evidence": {
    "occurrences": [
      {
	"location": "testing/cert.pem"
      },
      {
	"location": "testing/key.pem"
      }
    ]
  }
}
```

# Post Quantum Cryptography

cbom-lens, as any tool written in Go, supports only algorithms, which are
present in a standard library, which PQC are, as of Go 1.25, not. There is
however a support for detecting such algorithms in place and `ml-ds` family can
be detected.

A better support is needed.

```json
    {
      "bom-ref": "crypto/algorithm/ml-dsa-65@sha256:f8c9a2448272eebee3bf9c777bff35d1f84d59166534cc848eed418f3fbc08a3",
      "type": "cryptographic-asset",
      "name": "ML-DSA-65",
      "properties": [
        {
          "name": "czertainly:component:algorithm:pqc:private_key_size",
          "value": "4032"
        },
        {
          "name": "czertainly:component:algorithm:pqc:public_key_size",
          "value": "1952"
        },
        {
          "name": "czertainly:component:algorithm:pqc:signature_size",
          "value": "3309"
        }
      ],
      "evidence": {
        "occurrences": [
          {
            "location": "testing/pqc.pem"
          }
        ]
      },
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "ae",
          "parameterSetIdentifier": "65",
          "executionEnvironment": "software-plain-ram",
          "certificationLevel": [
            "none"
          ],
          "cryptoFunctions": [
            "sign"
          ],
          "classicalSecurityLevel": 192,
          "nistQuantumSecurityLevel": 3
        },
        "oid": "2.16.840.1.101.3.4.3.18"
      }
    },
```
