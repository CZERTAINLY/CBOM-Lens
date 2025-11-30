package config
// SCHEMA DEFINITION
#Config

// Seeker top-level configuration object.
#Config: {
version: 0
filesystem?: #Filesystem
containers?: #Containers
ports?: #Ports
service: #Service
}

// ScanConfig is a subset of a top level configuration which will be passed in a discovery mode by core.
#ScanConfig: {
version: 0
filesystem?: #Filesystem
containers?: #Containers
ports?: #Ports
service?: #ServiceFields
}

// Set of filesystem scanning settings; when disabled no filesystem paths are processed.
// If paths unset, current working directory is assumed.
#Filesystem: {
  enabled?: *false | bool
  paths?: [...string]
}

// List of container daemon configurations to inspect (Docker/Podman).
#Containers: {
  enabled?: bool | *false
  config: [...#ContainerConfig]
}

// Supported container daemon types.
#ContainerDaemon: ("" | "docker" | "podman")

// Configuration for a single container daemon integration.
// name: optional identifier (defaults to daemon type if absent).
// type: daemon implementation, defaults to docker.
// host: path or endpoint for the daemon (e.g. unix:///var/run/docker.sock). Can be specified as environment variable, like ${DOCKER_HOST}
// images: explicit image names/patterns to include (empty => discover all).
#ContainerConfig: {
  name?: string
  type?: #ContainerDaemon
  host: string
  images?: [...string]
}

// Local port scanning module configuration.
// enabled: when false this entry is ignored.
// binary: optional path to nmap binary, $PATH is used by default
// ports: comma/range expression (e.g. "22,80,443,8000-8100") default full range.
// ipv4 / ipv6: protocol selection flags. Both default to true.
#Ports: {
  enabled?: bool | *false
  binary?: string
  ports?: string | *"1-65535"
  ipv4?: bool | *true
  ipv6?: bool | *true
}

// Schedule can be a cron 5 fields format, or macro like @yearly or a @every <duration>, which is string accepted by https://golang.org/pkg/time/#ParseDuration
// or duration in ISO 8601 format
#Schedule:
  { cron?:  #CronExpr } |
  { duration?: #ISODuration }

// Seeker service configuration.
#Service: {
  #ServiceFields
  mode: *"manual" | "timer" | "discovery"
  schedule?: null | #Schedule
  if mode == "timer" { schedule: #Schedule }
  dir?: string
  repository?: #Repository
  seeker?: null | #SeekerServer
  core?: null | #Core
  if mode == "discovery" { 
    seeker: #SeekerServer
    core: #Core
  }
}

// OutputFields specify common output for a scanner
// verbose: extra logging output when true.
// log: destination ("stderr","stdout","discard" or file path).
// dir: local results directory.
// repository: remote repository configuration.
#ServiceFields: {
  verbose?: bool | *false
  log?: *"stderr" | "stdout" | "discard" | string
}

#Repository: {
  base_url: #URL
}

#SeekerServer: {
  addr: string
  base_url: #URL
  state_file: string | *"./seeker-state-file"
}

#Core: {
  base_url: #URL
}

// Common fields

#CronExpr: string & =~"^(@(yearly|annually|monthly|weekly|daily|midnight|hourly)|@every.*|(?:\\S+\\s+){4}\\S+)$" & !=""
#ISODuration: string &
    =~"^P(?:\\d+W|(?:\\d+Y)?(?:\\d+M)?(?:\\d+D)?(?:T(?:\\d+H)?(?:\\d+M)?(?:\\d+S)?)?)$" & !=""
#URL: string & =~"^https?://.+"
