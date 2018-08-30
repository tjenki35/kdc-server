To build this project use the make file:
make # will just use the default option
make clean # will remove all of the class files in src

Once the project is built go into the src folder

run (in separate terminals)
$java Simulation.KeyServer #to start the KDC
$java Simulation.BClient # to start "Bob" and have him authenticate with the KDC
$java Simulation.AClient # to start "Alice" which will authenticate w/ the keyserver and then start the protocol

#by default AClient will run using ECB and the Original protocol
#to change this behaviour use
$java Simulation.AClient -EX -ECB #where ex stands for Extended, ECB
$java Simulation.AClient -OR -CBC #where ex stands for Original, CBC
$java Simulation.AClient -EX -CBC #etc

#if the KeyServer is running and BClient is running in listening mode (which it will always do after authentication)
#AND if Alice authenticated using ECB and OR options
#then running the following command will initiate an exploit

$java Simulation.Trudy

**note that the code uses port 3030 for the KDC server and port 5050 for Bobs listening port (this is hard coded, but not hard to change)
