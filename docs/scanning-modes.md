# Scanning Modes & Scheduling

CBOM-Lens can run in three modes, controlled by `service.mode`:

- `manual`
- `timer`
- `discovery`

This document explains each mode and how to configure schedules using cron expressions and ISO-8601 durations.

For configuration basics, see the [Configuration guide](configuration.md). For integration details, see [CZERTAINLY & CBOM-Repository integration](integration-czertainly.md).

---

## 1. Manual mode

In **manual** mode, CBOM-Lens runs a single scan and exits.

```yaml
service:
  mode: manual
```

Typical use cases:

- Ad-hoc scans on a workstation or server.
- CI pipelines (e.g., scan before deployment).
- External schedulers (system cron, Kubernetes CronJob, etc.) controlling when scans start.

In this mode there is no internal scheduler; each `cbom-lens run` triggers exactly one scan.

---

## 2. Timer mode

In **timer** mode, CBOM-Lens runs as a long-lived process and triggers scans on a schedule. The schedule is configured via `service.schedule`.

```yaml
service:
  mode: timer
  schedule:
    cron: "0 * * * *"  # every hour
```

or

```yaml
service:
  mode: timer
  schedule:
    duration: "PT15M"  # every 15 minutes
```

### 2.1 Cron expressions

CBOM-Lens uses the [github.com/robfig/cron](https://pkg.go.dev/github.com/robfig/cron/) library to interpret cron expressions.

A cron expression has 5 space-separated fields:

| Field name   | Mandatory? | Allowed values  | Allowed special characters |
|--------------|------------|-----------------|----------------------------|
| Minutes      | Yes        | 0-59            | * / , -                    |
| Hours        | Yes        | 0-23            | * / , -                    |
| Day of month | Yes        | 1-31            | * / , - ?                  |
| Month        | Yes        | 1-12 or JAN-DEC | * / , -                    |
| Day of week  | Yes        | 0-6 or SUN-SAT  | * / , - ?                  |

Month and day-of-week values are case insensitive (e.g., `SUN`, `Sun`, `sun`).

#### Special characters

- **Asterisk (\*)** – match all values of the field. Example: `*` in the month field means "every month".
- **Slash (/)** – increments of ranges. Example: `3-59/15` in the minutes field means "the 3rd minute of the hour and every 15 minutes thereafter". `*/N` is shorthand for "from first to last, every N".
- **Comma (,)** – list of values. Example: `MON,WED,FRI` in day-of-week means Mondays, Wednesdays, and Fridays.
- **Hyphen (-)** – ranges. Example: `9-17` in the hours field means every hour from 9:00 to 17:00 inclusive.
- **Question mark (?)** – may be used instead of `*` in day-of-month or day-of-week when that field is not relevant.

#### Predefined schedules

You may use one of the predefined macros:

| Entry                      | Description                                | Equivalent to |
|----------------------------|--------------------------------------------|---------------|
| `@yearly` (or `@annually`) | Run once a year, midnight, Jan. 1st        | `0 0 1 1 *`   |
| `@monthly`                 | Run once a month, midnight, first of month | `0 0 1 * *`   |
| `@weekly`                  | Run once a week, midnight between Sat/Sun  | `0 0 * * 0`   |
| `@daily` (or `@midnight`)  | Run once a day, midnight                   | `0 0 * * *`   |
| `@hourly`                  | Run once an hour, beginning of hour        | `0 * * * *`   |

### 2.2 ISO-8601 duration

Instead of cron, you can define a fixed interval using an ISO-8601 duration string:

```yaml
service:
  mode: timer
  schedule:
    duration: "P1DT2H3M4S"  # 1 day, 2 hours, 3 minutes, 4 seconds
```

Format: `PnDTnHnMnS`, where:

- `P` introduces the period.
- `nD` – days (each day is exactly 24 hours).
- `T` introduces the time part.
- `nH` – hours.
- `nM` – minutes.
- `nS` – seconds.

Details:

- Fractional numbers are allowed (e.g., `P0.5D`).
- Decimal point can be a dot or comma.
- Fractional parts can be up to 9 digits long.
- Negative values are possible (e.g., `PT1H-7M`); see implementation details in the referenced `time.Duration` handling.

The interval does **not** account for job runtime. For example, if a job is scheduled every 5 minutes and takes 3 minutes to run, there will be approximately 2 minutes idle time between runs.

---

## 3. Discovery mode

In **discovery** mode, CBOM-Lens runs as a service that is fully managed by CZERTAINLY via a discovery protocol.

Example configuration:

```yaml
version: 0
service:
  mode: discovery
  repository:
    base_url: https://example.com/repo
  server:
    # where CBOM-Lens should bind to; can be ip:port
    addr: :8080
    # public address where CBOM-Lens is accessible to CZERTAINLY
    base_url: https://cbom-lens.example.net/api
  core:
    # base address of CZERTAINLY Core API
    base_url: https://core-demo.example.net/api
```

Key points:

- CBOM-Lens exposes an HTTP API (`service.server.addr`, `service.server.base_url`).
- CZERTAINLY Core connects to CBOM-Lens using this API to orchestrate scans.
- A CBOM-Repository (`service.repository.base_url`) is strongly recommended, as CZERTAINLY Core typically pulls BOMs from there.

For a deeper integration overview, see `integration-czertainly.md`.

---

## 4. Mode comparison

| Mode        | Scheduling                       | Lifetime         | Typical use cases                       |
|-------------|----------------------------------|------------------|-----------------------------------------|
| `manual`    | external (none inside CBOM-Lens) | one-shot process | ad-hoc scans, CI jobs                   |
| `timer`     | internal (cron or duration)      | long-lived       | periodic scans on a host                |
| `discovery` | external (CZERTAINLY Core)       | long-lived       | fully managed discovery with CZERTAINLY |

Choose the mode that best matches how you want CBOM-Lens to be orchestrated.

---

## 5. Next steps

- For configuration examples: see the [Configuration guide](configuration.md).
- For CZERTAINLY and repository integration: see [CZERTAINLY & CBOM-Repository integration](integration-czertainly.md).
- For operational aspects and troubleshooting: see [Operations](operations.md).
