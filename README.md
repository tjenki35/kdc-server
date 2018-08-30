# KDC Server/Client in Java #

## Building/Compilation: ##

A makefile is provided with this project. 

```bash 
make       # default build 
make clean # removes class files
```
**note: The project will build into the src folder

## Simulation: ##

This simulation follows the process up setting two clients up with the KDC and having them establish a secure connection with each other. </br>

2. Run the following (in separate terminals)

```bash
java Simulation.KeyServer                 # Starts the KDC
java Simulation.BClient                   # Starts client B (which authenticates with the KDC). 
java Simulation.AClient                   # Starts client A which will authenticate w/ the keyserver and then request to communicate with B </br>
```

### Additional Options ###

The clients/server support either the extended or original Needham-Schroder KDC protocols. EBC/CBC cipher modes are supported. </br> 
When the options are not specified, the clients will run -OR -ECB. </br>

**note: By default AClient will run using ECB and the Original protocol
```bash
java Simulation.AClient -EX -ECB          # Run client in extended mode, using EBC
java Simulation.AClient -OR -CBC          # Run client in original mode, using CBC
java Simulation.AClient -EX -CBC          # Run client in extended mode, using CBC
```

**note: The code uses port 3030 for the KDC server and port 5050 for Bobs listening port (this is hard coded, but not hard to change)

## ExtendedNeedham–Schroeder protocol Diagram ##
**note: The original scheme using ECB is vulnerable to a reflection attack

![screenshot](https://github.com/tjenki35/kdc-server/blob/master/extended.png?raw=true)
