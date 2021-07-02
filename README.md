# CICFlowMeter Mk.6
The repo is forked from [here](https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter) 
but is completely different.

## New Features
1. A refactor to original code including
    1. Applying OOP (Object-Oriented Programming)
    2. Extendable features (packet level and flow level)
    
2. A complete Maven Repo
3. Extendable commandline config thanks to [JLightConfig](https://github.com/Tomahawkd/JLightConfig)
4. Remove live capture and GUI (currently focus on feature extraction)

## Prerequisite
1. Java 8
2. Maven
3. `-Djava.library.path=./jnetpcap`

## Install
1. Clone the code
2. `mvn package`
3. Find Jar in `./bin`