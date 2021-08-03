# CICFlowMeter Mk.6
The repo is forked from [here](https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter) 
but is completely different in code structure.

## New Features
1. A refactor to original code including
    1. Applying OOP (Object-Oriented Programming)
    2. Extendable features (packet level and flow level)
    
2. A complete Maven Repo
3. Extendable commandline config thanks to [JLightConfig](https://github.com/Tomahawkd/JLightConfig)
4. Remove live capture and GUI (currently focus on feature extraction)
5. Introduce TCP Reassembler for analysing application layer protocol (e.g., HTTP)

## Prerequisite
1. Java 8
2. Maven
3. jnetpcap native library

## Build
1. Clone the code
2. `mvn package`
3. Find Jar in `./bin`
4. don't forget `-Djava.library.path=<path to jnetpcap native library>`

Note: 
1. The repo is only tested on Windows platform.
2. The native library is acquired from the forked repo.
3. For more information about jnetpcap, please follow the [link](https://sourceforge.net/projects/jnetpcap/).


## Commandline Help
```
Usage: <main class> [options] Pcap file or directory.
  Options:
    -a, --act_time
      Setting timeout interval for an activity.
      Default: 5000000
    -c, --continue
      Indicate the files in input dir are continuous.
      Default: false
    --debug
      Show debug output (sets logLevel to DEBUG)
      Default: false
    -f, --flow_time
      Setting timeout interval for a flow.
      Default: 120000000
    -h, --help
      Prints usage for all the existing commands.
    -m, --mode
      Mode selection.
      Default: DEFAULT
      Possible Values: [DEFAULT, SAMPLING, FULL, ONLINE]
    -n, --no
      Ignores specific feature (use as -no <feature1>,<feature2>)
      Default: []
    --noassemble
      Disable TCP Reassembing
      Default: false
    -1, --one_file
      Output only one file.
      Default: false
    --quiet
      No output (sets logLevel to NONE)
      Default: false
  * -o, -output
      Output directory.
```