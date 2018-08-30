# KDC Server/Client in Java #

## Building/Compilation: ##

A makefile is provided with this project. 

```bash 
make       # default build 
make clean # removes class file 
```
**note: Once the project is built go into the src folder

## Simulation: ##

This simulation follows the process up setting two clients up with the KDC and having them establish a secure connection with each other. </br>

2. Run the following (in separate terminals)

```bash
java Simulation.KeyServer                 # to start the KDC
java Simulation.BClient                   # to start client B and have him authenticate with the KDC
java Simulation.AClient                   # to start client A which will authenticate w/ the keyserver and then start the protocol
```

### Additional Options ###

**By default AClient will run using ECB and the Original protocol
```bash
java Simulation.AClient -EX -ECB #where ex stands for Extended, ECB
java Simulation.AClient -OR -CBC (**where ex stands for Original, CBC)
java Simulation.AClient -EX -CBC
```

**note that the code uses port 3030 for the KDC server and port 5050 for Bobs listening port (this is hard coded, but not hard to change)
